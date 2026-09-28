%% NTCP2 socket-layer tests. Two routers on one node communicate over real TCP
%% through RouterInfo, the per-connection process, and the data phase. The
%% cases also assert process isolation: killing one connection leaves the
%% listener and sibling connections alive.
%%
%% Listeners bind at port 0, and the application lifecycle and case-scoped
%% timeout settings are isolated per testcase.

-module(i2p_ntcp2_conn_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    transport_bytes_are_counted/1,
    shared_helpers_roundtrip/1,
    listener_binds_loopback_by_default/1,
    connection_limit_rejects_new_child/1,
    keepalive_refreshes_quiet_session/1,
    handshake_and_frames_roundtrip/1,
    multiple_frames_ordered/1,
    idle_reap/1,
    peer_close_kills_conn/1,
    isolation/1
]).

-define(APP, i2per).
-define(TIMEOUT, 10000).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        shared_helpers_roundtrip,
        listener_binds_loopback_by_default,
        connection_limit_rejects_new_child,
        keepalive_refreshes_quiet_session,
        handshake_and_frames_roundtrip,
        transport_bytes_are_counted,
        multiple_frames_ordered,
        idle_reap,
        peer_close_kills_conn,
        isolation
    ].

init_per_testcase(transport_bytes_are_counted, Config) ->
    %% The measurement window in this case must contain only the frames it sends
    %% itself. An NTCP2 keepalive is a payload that goes through the very same
    %% `send_payload/3`, so it would be charged and would break the equality
    %% between the two directions. The default interval is 60s and the case
    %% finishes in milliseconds, so it never fires in practice — but "never fires
    %% in practice" is the same hope the SSU2 case was rebuilt to remove, so the
    %% precondition is pinned here instead. The env is read when the connection
    %% arms its timer, which is after this returns.
    {ok, _} = application:ensure_all_started(?APP),
    ok = application:set_env(?APP, ntcp2_keepalive_interval_ms, 600_000),
    Config;
init_per_testcase(idle_reap, Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    ok = application:set_env(?APP, idle_timeout_ms, 300),
    Config;
init_per_testcase(shared_helpers_roundtrip, Config) ->
    Config;
init_per_testcase(_Case, Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    Config.

end_per_testcase(transport_bytes_are_counted, _Config) ->
    ok = application:unset_env(?APP, ntcp2_keepalive_interval_ms),
    application:stop(?APP),
    ok;
end_per_testcase(idle_reap, _Config) ->
    ok = application:unset_env(?APP, idle_timeout_ms),
    application:stop(?APP),
    ok;
end_per_testcase(shared_helpers_roundtrip, _Config) ->
    ok;
end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    ok.

%% --------------------------------------------------------------------------
%% Shared CT helpers prove out: temp data dir, free port, event-driven await,
%% and a wait_msg that drains non-matching mail (the fresh-per-case mailbox).
%% --------------------------------------------------------------------------

shared_helpers_roundtrip(Config) ->
    %% temp_data_dir is a writable directory inside the case's priv_dir.
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Private = proplists:get_value(priv_dir, Config),
    true = lists:prefix(Private, Dir),
    Probe = filename:join(Dir, "probe.bin"),
    ok = file:write_file(Probe, <<"ok">>),
    {ok, <<"ok">>} = file:read_file(Probe),
    %% free_port returns a reserved (then released) ephemeral port.
    Port = i2p_ct_helpers:free_port(),
    true = Port > 0 andalso Port =< 16#FFFF,
    %% await/2 returns ok once the predicate holds.
    ok = i2p_ct_helpers:await(fun() -> true end, 1000),
    %% wait_msg/2 skips unrelated mail and returns the matched value.
    Self = self(),
    Self ! {unrelated, a},
    Self ! {unrelated, b},
    Self ! done,
    done =
        i2p_ct_helpers:wait_msg(
            fun
                ({unrelated, _}) -> false;
                (done) -> {true, done}
            end,
            1000
        ),
    ok.

listener_binds_loopback_by_default(_Config) ->
    {Bob, _Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        {127, 0, 0, 1} = i2p_ntcp2_listener:address(Listener)
    after
        ok = i2p_ntcp2_listener:stop(Listener)
    end.

connection_limit_rejects_new_child(_Config) ->
    application:set_env(?APP, max_ntcp2_connections, 0),
    try
        {error, connection_limit} =
            i2p_ntcp2_sup:start_connection(
                i2p_ntcp2_sup:conn_child(#{role => alice})
            )
    after
        application:unset_env(?APP, max_ntcp2_connections)
    end.

keepalive_refreshes_quiet_session(_Config) ->
    application:set_env(?APP, ntcp2_keepalive_interval_ms, 50),
    application:set_env(?APP, idle_timeout_ms, 5000),
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        {ok, CA} = i2p_ntcp2_conn:connect(ri_at(listen_port(Listener), Bob), Alice, #{}),
        _CB = await_ready(),
        Payload = receive_frame(CA),
        {ok, [#{type := 0, data := <<_Now:32/big>>}]} =
            i2p_framing:decode_blocks(Payload),
        true = is_process_alive(CA)
    after
        i2p_ntcp2_listener:stop(Listener),
        application:unset_env(?APP, ntcp2_keepalive_interval_ms),
        application:unset_env(?APP, idle_timeout_ms)
    end.

%% --------------------------------------------------------------------------
%% End-to-end over real TCP
%% --------------------------------------------------------------------------

handshake_and_frames_roundtrip(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        BobRI = ri_at(listen_port(Listener), Bob),
        {ok, CA} = i2p_ntcp2_conn:connect(BobRI, Alice, #{}),
        CB = await_ready(),
        true = is_process_alive(CA),
        true = is_process_alive(CB),
        %% Alice -> Bob, then Bob -> Alice, on two distinct direction keys.
        Block = i2p_framing:encode_block(3, <<16#04, 16#34, 16#5a, 16#89>>),
        ok = i2p_ntcp2_conn:send(CA, Block),
        PayloadAB = receive_frame(CB),
        {ok, [#{type := 3, data := <<16#04, 16#34, 16#5a, 16#89>>}]} =
            i2p_framing:decode_blocks(PayloadAB),
        ok = i2p_ntcp2_conn:send(CB, <<"pong">>),
        <<"pong">> = receive_frame(CA),
        ok = i2p_ntcp2_conn:stop(CA),
        ok = i2p_ntcp2_conn:stop(CB)
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

%% Bytes counted at the transport boundary.
%%
%% The counter's claim is that it reports what crossed the socket, once per
%% direction, per frame. Two exact assertions establish that, and neither hard-codes
%% the framing:
%%
%%   - the sender's outbound total and the receiver's inbound total move by the
%%     *same* amount. A second counting site on either path, or a double charge
%%     for one frame, breaks that equality. This is what "one choke point" means
%%     when stated as a test rather than as a claim.
%%   - the per-frame overhead is identical for two different payload sizes. A
%%     counter tracking packets would charge a constant whatever the size; one
%%     tracking payload only would charge no overhead. This pins it to
%%     bytes-plus-fixed-framing, and names the overhead without the test needing
%%     to know what it is — so a framing change does not fail a test that was
%%     only ever about the accounting.
%%
%% Handshake traffic has already moved both counters by the time the pair is
%% established, so every measurement is read after that point rather than from
%% zero.
transport_bytes_are_counted(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        {ok, CA} = i2p_ntcp2_conn:connect(ri_at(listen_port(Listener), Bob), Alice, #{}),
        CB = await_ready(),

        #{ntcp2_bytes_out := Out0, ntcp2_bytes_in := In0} = i2p_stats:snapshot(),

        Probe = <<"probe">>,
        ok = i2p_ntcp2_conn:send(CA, Probe),
        <<Probe/binary>> = receive_frame(CB),
        Out1 = ntcp2_bytes_out(),
        In1 = ntcp2_bytes_in(),
        First = Out1 - Out0,
        First = In1 - In0,
        %% Framing is included, so this is strictly more than the payload. Were
        %% it ever equal, the counter would have quietly become a payload counter
        %% and the documented meaning would no longer hold.
        true = (First > byte_size(Probe)),

        Body = crypto:strong_rand_bytes(777),
        ok = i2p_ntcp2_conn:send(CA, Body),
        <<Body/binary>> = receive_frame(CB),
        Second = ntcp2_bytes_out() - Out1,
        Second = ntcp2_bytes_in() - In1,
        true = (First - byte_size(Probe) =:= Second - byte_size(Body)),

        %% And the figures are reachable under the names a consumer reads them
        %% by, rather than only from inside the connection process. The read API
        %% reports whatever the registry declares, so this is the same names the
        %% view will carry; `m:i2p_read_api_SUITE` covers the view end to end,
        %% and this suite has no reason to boot the parts the view reads.
        Counters = i2p_stats:snapshot(),
        true = (Out1 + Second =:= maps:get(ntcp2_bytes_out, Counters)),
        true = (In1 + Second =:= maps:get(ntcp2_bytes_in, Counters))
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

ntcp2_bytes_out() ->
    maps:get(ntcp2_bytes_out, i2p_stats:snapshot()).

ntcp2_bytes_in() ->
    maps:get(ntcp2_bytes_in, i2p_stats:snapshot()).

%% Multiple frames in one direction stay ordered across the stream.
multiple_frames_ordered(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        {ok, CA} = i2p_ntcp2_conn:connect(ri_at(listen_port(Listener), Bob), Alice, #{}),
        CB = await_ready(),
        ok = i2p_ntcp2_conn:send(CA, <<"1">>),
        ok = i2p_ntcp2_conn:send(CA, <<"2">>),
        ok = i2p_ntcp2_conn:send(CA, <<"3">>),
        <<"1">> = receive_frame(CB),
        <<"2">> = receive_frame(CB),
        <<"3">> = receive_frame(CB),
        i2p_ntcp2_conn:stop(CA),
        i2p_ntcp2_conn:stop(CB)
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

%% Data-phase idle reap: with a short idle timeout, a connection that receives
%% no inbound frames reaps itself. Both ends are awaited; at least one must
%% exit `{idle_timeout, no_activity}` (the self-reap under test), while the
%% peer whose socket the reaper closed first may surface `closed` instead of
%% firing its own idle timer.
idle_reap(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        BobRI = ri_at(listen_port(Listener), Bob),
        {ok, CA} = i2p_ntcp2_conn:connect(BobRI, Alice, #{}),
        CB = await_ready(),
        true = is_process_alive(CA),
        true = is_process_alive(CB),
        expect_idle_exit([CA, CB])
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

%% --------------------------------------------------------------------------
%% Let it crash: peer socket close ends the connection process
%% --------------------------------------------------------------------------

peer_close_kills_conn(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        {ok, CA} = i2p_ntcp2_conn:connect(ri_at(listen_port(Listener), Bob), Alice, #{}),
        CB = await_ready(),
        MRef = erlang:monitor(process, CB),
        %% The far end (Alice) closes the TCP connection.
        i2p_ntcp2_conn:stop(CA),
        receive
            {'DOWN', MRef, process, CB, _} -> ok
        after ?TIMEOUT ->
            error(cb_survived_peer_close)
        end
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

%% --------------------------------------------------------------------------
%% Isolation: killing one connection process leaves listener + siblings alive
%% --------------------------------------------------------------------------

isolation(_Config) ->
    {Bob, Alice1} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        BobRI = ri_at(listen_port(Listener), Bob),
        {ok, C1} = i2p_ntcp2_conn:connect(BobRI, Alice1, #{}),
        Bob1 = await_ready(),
        {ok, C2} = i2p_ntcp2_conn:connect(BobRI, pair2(), #{}),
        Bob2 = await_ready(),
        {ok, C3} = i2p_ntcp2_conn:connect(BobRI, pair2(), #{}),
        Bob3 = await_ready(),
        %% Kill one responder connection outright and wait for its death: the
        %% isolation holds only once the runtime has fully processed the signal.
        %% (The killed connection's peer observes the socket close and exits;
        %% that peer-close behavior is separate from the isolation property.)
        KillMRef = erlang:monitor(process, Bob1),
        erlang:exit(Bob1, kill),
        receive
            {'DOWN', KillMRef, process, Bob1, killed} -> ok
        after ?TIMEOUT ->
            error(exit_signal_not_processed)
        end,
        false = is_process_alive(Bob1),
        true = is_process_alive(Listener),
        true = is_process_alive(C2),
        true = is_process_alive(C3),
        true = is_process_alive(Bob2),
        true = is_process_alive(Bob3),
        %% The listener still accepts new connections after the kill.
        {ok, C4} = i2p_ntcp2_conn:connect(BobRI, pair2(), #{}),
        Bob4 = await_ready(),
        true = is_process_alive(Bob4),
        ok = i2p_ntcp2_conn:send(C4, <<"still alive">>),
        <<"still alive">> = receive_frame(Bob4),
        [i2p_ntcp2_conn:stop(C) || C <- [C1, C2, C3, C4]],
        [i2p_ntcp2_conn:stop(B) || B <- [Bob2, Bob3, Bob4]]
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

%% --------------------------------------------------------------------------
%% Connection-suite helpers
%% --------------------------------------------------------------------------

%% A router node: identity, static keypair, hash, IV, and a signed RouterInfo.
%% The RouterInfo is built with a placeholder port and rebound to the real
%% listener port via ri_at/2.
router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        iv => IV,
        seed => Seed,
        identity => Identity
    }.

%% A complete local-keys map for the conn/listener API, with the signed
%% RouterInfo announcing NTCP2 on Port.
local(#{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N, Port) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, 1_800_000_000, [Addr], Opts, Seed),
    N#{hash => i2p_router_info:hash(RI), ri => RI}.

%% Two distinct router nodes. The placeholder port 4668 is replaced by the real
%% bound listener port via ri_at/2 before connecting.
pair() ->
    {local(router(), 4668), local(router(), 4668)}.

pair2() ->
    local(router(), 4668).

%% Re-sign Bob's RouterInfo announcing the actual bound listener port.
ri_at(Port, #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed}) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, 1_800_000_000, [Addr], Opts, Seed).

listen_port(Listener) ->
    i2p_ntcp2_listener:port(Listener).

%% The next {ntcp2_ready, Conn, RemoteRI} (Bob conns and Alice conns announce
%% to us with the peer's decoded RouterInfo).
await_ready() ->
    receive
        {ntcp2_ready, Conn, _RemoteRI} -> Conn
    after ?TIMEOUT ->
        error(no_connection_ready)
    end.

receive_frame(Conn) ->
    receive
        {ntcp2_frame, Conn, Payload} -> Payload
    after ?TIMEOUT ->
        error(frame_timeout)
    end.

%% Assert every pid exits within the window, and that idle reaping fired on at
%% least one of them. The first end whose idle timer fires exits
%% `{idle_timeout, no_activity}` and its process death closes the TCP socket,
%% so the other end's `recv` surfaces `{error, closed}` and that conn exits
%% `closed` before its own idle timer is ever evaluated. Both are valid reaping
%% outcomes for an idle pair; the self-reap is what this test proves. All
%% monitors are armed before any is awaited so the two ends' exits (which may
%% be microseconds apart) cannot be missed as a `noproc` DOWN.
expect_idle_exit(Pids) ->
    Refs = [{erlang:monitor(process, Pid), Pid} || Pid <- Pids],
    Reasons = lists:map(
        fun({MRef, Pid}) ->
            receive
                {'DOWN', MRef, process, Pid, Reason} -> Reason
            after ?TIMEOUT ->
                erlang:error({not_idle_reaped, Pid})
            end
        end,
        Refs
    ),
    true = lists:member({idle_timeout, no_activity}, Reasons),
    lists:foreach(
        fun
            ({idle_timeout, no_activity}) -> ok;
            (closed) -> ok;
            (Other) -> erlang:error({unexpected_exit, Other})
        end,
        Reasons
    ).
