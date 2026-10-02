%% NTCP2 socket-layer tests. Two routers on one node communicate over real TCP
%% through RouterInfo, the per-connection process, and the data phase. The
%% cases also assert process isolation: killing one connection leaves the
%% listener and sibling connections alive, and a connection that stops draining
%% its mailbox does not stop anyone waiting on it.
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
    isolation/1,
    send_does_not_wait_on_the_connection/1,
    a_peer_that_stops_reading_ends_the_connection/1,
    an_inbound_burst_does_not_delay_a_send/1,
    a_batch_of_inbound_connections_is_not_accepted_one_per_second/1
]).

-define(APP, i2per).
-define(TIMEOUT, 10000).

%% How many frames the socket-stall case's feeder may push, and how long the case
%% then waits for the connection to end. Both are hang guards on an OTP and kernel
%% implementation detail, not claims about this module: how much undrained data a
%% socket absorbs before it refuses more belongs to the kernel and the inet
%% driver, and was measured on this tree at 45 frames of 60 kB. The frames are
%% 60 kB so that a generous budget is a short run — the measured stall is under
%% 50 frames, so 500 leaves an order of magnitude of headroom for a kernel with
%% larger buffers. Reaching either bound fails the case rather than passing it.
-define(MAX_FILL_FRAMES, 500).
-define(STALL_BUDGET_MS, 20000).

%% How many inbound connections the accept case opens at once, and the budget the
%% whole batch has to land inside. Six is the number the defect was measured with
%% (6.06 s to drain, one per second); the bound is a *batch* bound, so the floor
%% the defect sets is (6 - 1) = 5 s against a 2 s budget, and the case still
%% fails on the last of the six rather than passing on the five that were fast.
%% Reaching the budget fails the case rather than passing it.
-define(ACCEPT_BATCH, 6).
-define(ACCEPT_BUDGET_MS, 2000).

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
        isolation,
        send_does_not_wait_on_the_connection,
        a_peer_that_stops_reading_ends_the_connection,
        an_inbound_burst_does_not_delay_a_send,
        a_batch_of_inbound_connections_is_not_accepted_one_per_second
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
init_per_testcase(a_peer_that_stops_reading_ends_the_connection, Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    %% Short enough that the case finishes on a loaded machine, long enough that
    %% an ordinary frame never reaches it. The stall is a deadline by
    %% construction — that is the whole point of the option — so the value is
    %% asserted through the outcome it produces rather than through elapsed time.
    ok = application:set_env(?APP, ntcp2_send_timeout_ms, 250),
    %% A small send buffer, so the queue the driver can fill before it refuses is
    %% small. Read once, when the connection enters the data phase, which is after
    %% this returns. This is the one production option the case leans on, and it
    %% is the same lever an operator would use to bound what one non-reading peer
    %% costs — reaching the stall needs a small budget, not a private mechanism.
    ok = application:set_env(?APP, ntcp2_sndbuf, 4096),
    %% The bus is the instrument this fact is recorded on, so the case reads it
    %% from there. The handler is the tree's own collector rather than a channel
    %% added for the test, so what is asserted is the announcement a subscriber
    %% would actually receive. `gen_event:add_handler/3` answers `ok` for a
    %% handler that installs cleanly, so this is matched rather than ignored: a
    %% collector that did not attach would make the assertion below vacuous.
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
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
end_per_testcase(a_peer_that_stops_reading_ends_the_connection, _Config) ->
    ok = gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
    ok = application:unset_env(?APP, ntcp2_send_timeout_ms),
    ok = application:unset_env(?APP, ntcp2_sndbuf),
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
        {_CB, _} = await_ready(),
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
        {CB, _} = await_ready(),
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
        {CB, _} = await_ready(),

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
        {CB, _} = await_ready(),
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
        {CB, _} = await_ready(),
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
        {CB, _} = await_ready(),
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
        {Bob1, _} = await_ready(),
        {ok, C2} = i2p_ntcp2_conn:connect(BobRI, pair2(), #{}),
        {Bob2, _} = await_ready(),
        {ok, C3} = i2p_ntcp2_conn:connect(BobRI, pair2(), #{}),
        {Bob3, _} = await_ready(),
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
        {Bob4, _} = await_ready(),
        true = is_process_alive(Bob4),
        ok = i2p_ntcp2_conn:send(C4, <<"still alive">>),
        <<"still alive">> = receive_frame(Bob4),
        [i2p_ntcp2_conn:stop(C) || C <- [C1, C2, C3, C4]],
        [i2p_ntcp2_conn:stop(B) || B <- [Bob2, Bob3, Bob4]]
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

%% --------------------------------------------------------------------------
%% The send path never makes its caller wait
%% --------------------------------------------------------------------------

%% The send hands the frame over and returns, whatever the connection is doing.
%%
%% Two pids, two ways a send could wait, and one property: `f:send/2` returns.
%%
%% A live pid that never drains its mailbox is the stall the peer manager cares
%% about — that is what a connection looks like while it is blocked in a socket
%% write against a shut window, or busy with a burst of AEAD. A *dead* pid is the
%% second, narrower wait the old send had: it monitored nothing, so a connection
%% that died between the caller's liveness check and its own message was a caller
%% that never came back. Both are plain pids rather than real connections,
%% because what is under test is the shape of the call and not the handshake; the
%% stall that needs a real socket is the next case, and the one that needs a real
%% peer *manager* is `i2p_peer_transport_SUITE`'s.
%%
%% Nothing here can pass by luck. There is no sleep and no poll: a send that
%% waited would not return at all, so reaching the assertion *is* the result, and
%% the `after` clause is what would have caught the old behaviour.
send_does_not_wait_on_the_connection(_Config) ->
    Mute = spawn(fun() -> mute() end),
    try
        ok = i2p_ntcp2_conn:send(Mute, <<"one">>),
        ok = i2p_ntcp2_conn:send(Mute, <<"two">>),
        ok = i2p_ntcp2_conn:send(i2p_ct_helpers:dead_pid(), <<"three">>),
        true = is_process_alive(Mute)
    after
        exit(Mute, kill)
    end.

%% A live process that is alive, has a mailbox, and never reads it.
mute() ->
    receive
        stop -> ok
    end.

%% A peer that stops reading ends the connection, with a name.
%%
%% The stall is real, not simulated: the far end completes a real NTCP2 handshake
%% and then never reads its socket again (`f:i2p_ct_helpers:silent_ntcp2_peer/1`
%% says why that is built rather than suspended). This end's window shuts, its
%% socket eventually refuses a frame, and because the data phase is
%% `{delay_send, true}` with a `send_timeout` the refusal arrives as
%% `{error, timeout}` in bounded time instead of an indefinite wait — and the
%% connection ends with a reason that says which of the two it was.
%%
%% How many frames that takes is not asserted, because it is not a property of
%% this module — it is however much undrained data the socket and the inet driver
%% absorb first, measured on this tree at 45 frames of 60 kB with the kernel's
%% own buffering. So the case drives the socket until the connection ends and
%% asserts the outcome, which is the part this module owns. `?MAX_FILL_FRAMES` is
%% a guard against a hang, and reaching it fails the case rather than passing it.
a_peer_that_stops_reading_ends_the_connection(_Config) ->
    {Bob, Alice} = pair(),
    {LSock, Port, _Peer} = i2p_ct_helpers:silent_ntcp2_peer(Bob),
    try
        {ok, CA} = i2p_ntcp2_conn:connect(ri_at(Port, Bob), Alice, #{}),
        ok = await_silent_peer(),
        %% The hash the announcement carries is over the router *identity*, which
        %% `ri_at/2` does not change — only the addresses it publishes do. So the
        %% placeholder-port RouterInfo in `Bob` is the same identity the
        %% connection saw, and no second ready message has to be picked apart.
        RemoteHash = i2p_router_info:hash(maps:get(ri, Bob)),
        MRef = erlang:monitor(process, CA),
        {send_stalled, socket_blocked} = fill_until_stalled(CA, MRef),
        ok = await_stall_event(RemoteHash)
    after
        gen_tcp:close(LSock)
    end.

%% The peer announces itself once its handshake is done, and that announcement is
%% the barrier saying it has stopped reading. Waiting on a timer instead would
%% race the handshake: frames sent before the peer parks would be drained, and
%% the socket would never fill. The dialer's own ready announcement shares the
%% mailbox, so it is drained rather than left to confuse a later assertion.
await_silent_peer() ->
    receive
        {silent_ntcp2_peer, _Peer} -> ok;
        {ntcp2_ready, _Conn, _RemoteRI} -> await_silent_peer()
    after ?TIMEOUT ->
        error(peer_never_went_silent)
    end.

%% Drive frames at the connection until it ends, and return why.
%%
%% The feeding is a separate process on purpose. A loop in the case itself would
%% enqueue a fixed number of frames and then give up while the connection was
%% still working through them — which is a race dressed up as a bound, and is
%% what the first version of this case did: it reported that the socket had
%% absorbed 30 MB when it had absorbed none, because the frames were still in the
%% connection's mailbox. One feeder and one barrier is the honest shape.
%%
%% The reason the case asserts rather than the count of frames is the same point
%% from the other side: how much undrained data a socket absorbs before it
%% refuses more belongs to the kernel and the inet driver, not to this module.
%% `?MAX_FILL_FRAMES` bounds only how long the feeder may run.
fill_until_stalled(Conn, MRef) ->
    Block = i2p_framing:encode_block(3, crypto:strong_rand_bytes(60_000)),
    %% Not linked: the case kills it when the connection is gone, and a killed
    %% process's exit signal would take down anything linked to it.
    Feeder = spawn(fun() -> feed(Conn, Block, ?MAX_FILL_FRAMES) end),
    try
        await_exit(MRef)
    after
        exit(Feeder, kill)
    end.

%% A legal frame each time, so a connection that died on a malformed one would be
%% a different bug with a different exit reason, and the case can tell them apart
%% rather than passing on either.
feed(_Conn, _Block, 0) ->
    ok;
feed(Conn, Block, N) ->
    ok = i2p_ntcp2_conn:send(Conn, Block),
    feed(Conn, Block, N - 1).

%% A barrier, not a deadline: the connection's exit is a real event, and this
%% receive is what turns "it ended" into a reason to assert on. The `after` is a
%% hang guard — reaching it fails the case rather than passing it, and says the
%% socket never refused a frame, which is the property that would be missing.
await_exit(MRef) ->
    receive
        {'DOWN', MRef, process, _Conn, Reason} -> Reason
    after ?STALL_BUDGET_MS ->
        erlang:error(socket_never_refused_a_frame)
    end.

%% The bus announcement, which is the whole report (ADR 0002: a fact is recorded
%% once, on one instrument). Read through the suite's own event collector, so
%% this asserts the fact a subscriber would read rather than a private channel
%% added for the test — and the peer manager is deliberately *not* asked, because
%% it does not repeat the reason and a test that read it from there would pass
%% against a tree that had stopped announcing.
await_stall_event(RemoteHash) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({peer_send_stalled, Hash, socket_blocked}) when Hash =:= RemoteHash -> {true, ok};
            (_) -> false
        end,
        ?TIMEOUT
    ).

%% --------------------------------------------------------------------------
%% Head-of-line, and the bound it rests on
%% --------------------------------------------------------------------------

%% A burst of inbound traffic does not hold up an outbound frame.
%%
%% A send is serviced in mailbox order, so it waits behind whatever is already
%% queued — and the bound on that is `{active, once}`: the socket is re-armed
%% only after the message in hand has been processed, so the queue holds one
%% inbound message and not a backlog of them. This case puts that to the only
%% test that matters: Bob floods, and Alice's frame still arrives, in order,
%% behind the flood rather than after it.
%%
%% The order assertion is what makes it a test rather than a hope. Ten frames are
%% sent into the middle of the burst and must come back in the order they were
%% sent; the framing state is what orders them, and the only way that could fail
%% is if the burst were being allowed to interleave with them.
an_inbound_burst_does_not_delay_a_send(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        {ok, CA} = i2p_ntcp2_conn:connect(ri_at(listen_port(Listener), Bob), Alice, #{}),
        {CB, _} = await_ready(),
        Filler = i2p_framing:encode_block(254, crypto:strong_rand_bytes(4000)),
        Probes = lists:seq(1, 10),
        Flooder = spawn(fun() -> flood(CB, Filler, 200) end),
        [ok = i2p_ntcp2_conn:send(CB, <<Probe>>) || Probe <- Probes],
        true = is_pid(Flooder),
        assert_ordered(probes_seen(), Probes),
        ok = i2p_ntcp2_conn:stop(CA),
        ok = i2p_ntcp2_conn:stop(CB)
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

flood(_Conn, _Filler, 0) ->
    ok;
flood(Conn, Filler, N) ->
    ok = i2p_ntcp2_conn:send(Conn, Filler),
    flood(Conn, Filler, N - 1).

%% Drain this process's frames, keeping the ones that are a single byte. The
%% flood's filler is 4000 bytes, so the two cannot be confused and nothing has to
%% be decoded to tell them apart. The `after` is a hang guard: the assertions
%% downstream ask for all ten probes, so a probe that never arrived fails the
%% case rather than shortening the list.
probes_seen() ->
    probes_seen([]).

probes_seen(Acc) ->
    receive
        {ntcp2_frame, _Conn, Payload} -> probes_seen(probe_byte(Payload, Acc))
    after ?TIMEOUT ->
        lists:reverse(Acc)
    end.

probe_byte(<<Probe>>, Acc) -> [Probe | Acc];
probe_byte(_Filler, Acc) -> Acc.

%% Every probe arrived, in the order it was sent. The `[]` clause is where the
%% extra ones would show up, and `tl/1` is where a missing or reordered one
%% does — neither can pass by luck, because the list comes from a drain of mail
%% that has already arrived.
assert_ordered(Seen, Want) ->
    case Want of
        [] ->
            [];
        [Head | Rest] ->
            [Head | _] = Seen,
            assert_ordered(tl(Seen), Rest)
    end.

%% --------------------------------------------------------------------------
%% The accept path
%% --------------------------------------------------------------------------

%% A batch of inbound connections is accepted as a batch
%%
%% The defect: the accept loop polled its control messages on a **one-second**
%% receive timeout and only called `f:gen_tcp:accept/2` when that timeout expired,
%% so it took at most one inbound connection per second no matter how many were
%% waiting. Six simultaneous connections took 6.06 s to drain, read from the
%% kernel's accept queue — the rate was exactly the timeout, not a load effect.
%% That is the rate a router's peer set grows at, and the rate it rebuilds one
%% after a restart.
%%
%% The bound is a batch, asserted as one. Six dials are fired at the same instant
%% and all six announcements have to arrive inside ?ACCEPT_BUDGET_MS, so a
%% regression that admitted five immediately and the sixth a second later fails on
%% the sixth rather than passing on the five. Against the defect the floor is
%% (N-1) seconds — the last of N cannot be accepted before the Nth tick — so with
%% N = 6 that is 5 s against a 2 s bound, and the bound is not a tolerance that
%% happens to sit above the real behaviour: it is a third of what the defect
%% needed.
%%
%% What the batch is made of, and why: six **real** NTCP2 dials rather than six
%% raw TCP connects. A raw connect would prove the kernel completed a handshake,
%% which is not the claim; the claim is that a Bob connection process was spawned
%% per accepted socket, so each dial goes through the real handshake and its
%% responder's `{ntcp2_ready, ...}` announcement is the evidence that an accept
%% happened and the handover survived. Both sides of the same accept are counted:
%% `dialed` is `f:i2p_ntcp2_conn:connect/3` returning (the accept let the dialer
%% through), `accepted` is the responder announcing to this process as the
%% listener's owner (a Bob process exists only because the socket was accepted).
%%
%% The control-message assertion is the part of the ticket that is easy to lose
%% while fixing the throttle, so it is here rather than in a case of its own. The
%% asker is a separate process that asks while the batch is in flight, which is
%% the only moment the question means anything: a fix that moved the accept back
%% into the process that answers control messages would leave it blocked. It
%% cannot pass slowly — `f:port/1` answers or raises after its own bound, so a
%% control path stuck behind the accept surfaces here as a wrong answer rather
%% than as a late one.
a_batch_of_inbound_connections_is_not_accepted_one_per_second(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        Port = listen_port(Listener),
        BobRI = ri_at(Port, Bob),
        Deadline = erlang:monotonic_time(millisecond) + ?ACCEPT_BUDGET_MS,
        Asker = ask_port(self(), Listener),
        Dialers = [dial_inbound(BobRI, Alice, self()) || _ <- lists:seq(1, ?ACCEPT_BATCH)],
        ?ACCEPT_BATCH = length(Dialers),
        {Dialed, Accepted} = collect_batch(?ACCEPT_BATCH, Deadline, [], []),
        ?ACCEPT_BATCH = length(Dialed),
        ?ACCEPT_BATCH = length(Accepted),
        %% Six *distinct* connections, from both sides. A count alone would be
        %% satisfied by one connection counted twice, which is what a bug in the
        %% responder's announcement would look like.
        ?ACCEPT_BATCH = length(lists:usort(Dialed)),
        ?ACCEPT_BATCH = length(lists:usort(Accepted)),
        {asked, Port} = take_asked(Asker, Deadline),
        [true = is_process_alive(Conn) || Conn <- Dialed ++ Accepted],
        [ok = i2p_ntcp2_conn:stop(Conn) || Conn <- Dialed ++ Accepted]
    after
        i2p_ntcp2_listener:stop(Listener)
    end,
    %% A control question asked of a listener that is gone has a defined answer
    %% instead of an open wait. What is asserted here is the shape; that the wait
    %% is *bounded* is the function's own `after`, and a regression to an
    %% unbounded one is caught by this case's timetrap rather than by this
    %% assertion — which is also why there is no timing claim here to be wrong
    %% about.
    Answer = answered(fun() -> i2p_ntcp2_listener:port(Listener) end),
    {'EXIT', {{listener_unanswered, Listener, port}, _}} = Answer,
    %% `ok` last, and not as tidiness: Common Test reads a case that *returns*
    %% `{'EXIT', Reason}` as a case that failed with `Reason`, so ending on the
    %% assertion above reports the very failure the assertion is about. This cost
    %% an hour and a half to find.
    ok.

%% The answer to a question nobody will answer, as a value rather than a raise.
%% Kept as a function so the case reads as an assertion about a term; an inline
%% `catch` in a match is the same thing spelled less legibly.
answered(Fun) ->
    try Fun() of
        Answer -> {answered, Answer}
    catch
        _Class:Reason:Stack -> {'EXIT', {Reason, Stack}}
    end.

%% One dial, in its own process, so all ?ACCEPT_BATCH of them reach the listen
%% socket at the same moment rather than as a queue of sequential handshakes. A
%% sequential loop would measure the accept rate with a peer already established
%% between each pair, which is not the condition the defect was measured under.
%%
%% The dialer owns its own connection — `f:i2p_ntcp2_conn:connect/3` defaults the
%% owner to the caller — which is what puts the dialer's own announcement where
%% `connect/3` consumes it and leaves the *responder's* announcement arriving
%% here, as the listener's owner. `f:await_ready/0` relies on the same fact for a
%% single connection. `Parent` is only where the dialer reports its own result.
dial_inbound(BobRI, Alice, Parent) ->
    spawn(fun() ->
        case i2p_ntcp2_conn:connect(BobRI, Alice, #{}) of
            {ok, Conn} -> Parent ! {dialed, Conn};
            {error, Reason} -> Parent ! {dial_failed, Reason}
        end
    end).

%% The asker, with the parent captured by the caller rather than read inside the
%% spawned fun — `self()` there is the asker, and an answer sent to the asker is
%% an answer nobody is waiting for.
ask_port(Parent, Listener) ->
    spawn(fun() ->
        Port =
            try
                i2p_ntcp2_listener:port(Listener)
            catch
                error:Reason -> {raised, Reason}
            end,
        Parent ! {asked, Port}
    end).

%% Both halves of the batch against one deadline, so the bound is on the batch
%% rather than per connection — a bound per connection would let the sixth wait
%% five seconds behind five fast ones and still pass.
%%
%% The two counts share the budget and each has to reach ?ACCEPT_BATCH, so a run
%% where the responder announcements all arrive first still waits for the dials'
%% own answers rather than declaring itself finished on one side.
%%
%% A failed dial is reported rather than left to run out the deadline, because
%% "the sixth never arrived" and "the sixth was refused" are different faults and
%% only one of them is a throttle.
collect_batch(N, Deadline, Dialed, Accepted) ->
    case {length(Dialed), length(Accepted)} of
        {N, N} ->
            {Dialed, Accepted};
        _ ->
            collect_batch_next(N, Deadline, Dialed, Accepted)
    end.

collect_batch_next(N, Deadline, Dialed, Accepted) ->
    receive
        {dialed, Conn} ->
            collect_batch(N, Deadline, [Conn | Dialed], Accepted);
        {ntcp2_ready, Conn, _RemoteRI} ->
            collect_batch(N, Deadline, Dialed, [Conn | Accepted]);
        {dial_failed, Reason} ->
            erlang:error({dial_failed, Reason})
    after remaining_ms(Deadline) ->
        erlang:error(
            {accept_batch_incomplete, [
                {dialed, Dialed},
                {accepted, Accepted}
            ]}
        )
    end.

%% The asked answer, or the same failure as the batch: a control message that has
%% not come back by the time the batch did is part of the same defect.
take_asked(Asker, Deadline) ->
    receive
        {asked, Answer} ->
            {asked, Answer}
    after remaining_ms(Deadline) ->
        erlang:error({control_message_unanswered, Asker})
    end.

remaining_ms(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

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
%%
%% This is always the *responder*, not whichever of the two got there first: the
%% dialer's own announcement is consumed inside `f:i2p_ntcp2_conn:connect/3`,
%% which waits for exactly its own connection's ready message, so the only one
%% left in this process's mailbox is the responder's. The pairing below leans on
%% that rather than racing for it.
await_ready() ->
    receive
        {ntcp2_ready, Conn, RemoteRI} ->
            {Conn, RemoteRI}
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
