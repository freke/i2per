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
    a_batch_of_inbound_connections_is_not_accepted_one_per_second/1,
    stop_reports_only_after_the_accept_path_has_stopped/1,
    wedged_accept_path_is_reported_rather_than_claimed_stopped/1,
    a_session_is_alive_and_speaking_at_frame_70000/1
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

%% The shutdown group's one figure that is not obvious. ?STOP_QUEUE is how many
%% connections sit in the kernel's accept queue while the acceptor is suspended --
%% enough that the accept path is plainly able to produce a responder, not one
%% that might.
%%
%% The bound on this case's own wait is ?TIMEOUT, the suite-wide one, and it is
%% *not* what decides whether `f:stop/1` is honest: that is `?STOP_TIMEOUT_MS` in
%% the module under test, which is a third of it, so this case can only ever be red
%% for a reason the module owns.
-define(STOP_QUEUE, 4).

%% --------------------------------------------------------------------------
%% The message counter crossing 2^16
%% --------------------------------------------------------------------------
%%
%% How many frames each direction is flooded with, and the hang guard around it.
%%
%% ?FRAMES_PER_DIRECTION is **70000**, and the round number is the point rather
%% than a convenience. The boundary this case exists to cross is `2^16`, and a
%% figure like 65537 is *past* it but does not look it: a reader has to decompose
%% it (2^16 + 1) and read the case's comment to learn that the number means
%% anything at all. 70000 states the claim on its own — this session is alive
%% and speaking ~4500 frames beyond the boundary — so the figure is readable in
%% the case name, in this constant, and in the failure message, which is what
%% makes the case's intent legible without its prose.
%%
%% **65537 is the minimum that distinguishes the defect from a fix, and 70000
%% keeps that property rather than trading it.** Message number 65536 is the one
%% that raised, so any count at or above 65537 asks the connection to send the
%% frame that killed it; 70000 is such a count, so the case still goes red
%% against the old bound. It is written as the literal rather than computed from
%% `2^16`, so the case and its reason cannot drift together.
%%
%% **What 70000 does not buy, stated so nobody credits it with catching it.** A
%% second increment site in the data phase would walk the counter twice as fast,
%% and no figure in this range notices: at 65537 frames a doubled counter
%% reaches 131074 and at 70000 it reaches 140000, both comfortably inside
%% `2^64 - 2`. This case is about the boundary the counter *had*, not about the
%% rate it increments at.
%%
%% ?FRAME_BUDGET_MS is a **hang guard, not a tolerance and not an assertion about
%% elapsed time**: reaching it fails the case and names which direction stalled
%% and how far it got. The flood is ~1.5 MB each way over loopback (70k frames
%% of a 4-byte payload) and measures **1.6s** on the machine this was written
%% on, so 20s is an order of magnitude
%% above it and about 4x the ~5s the whole smoke tier's CT costs scale to on a CI
%% runner. It is set **below** the suite's 30s timetrap on purpose, so the guard
%% is what fires and the failure is an error term naming the stall rather than a
%% CT kill that says only that time ran out.
-define(FRAMES_PER_DIRECTION, 70000).
-define(FRAME_BUDGET_MS, 20000).

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
        a_batch_of_inbound_connections_is_not_accepted_one_per_second,
        stop_reports_only_after_the_accept_path_has_stopped,
        wedged_accept_path_is_reported_rather_than_claimed_stopped,
        a_session_is_alive_and_speaking_at_frame_70000
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
init_per_testcase(a_session_is_alive_and_speaking_at_frame_70000, Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    %% The flood's whole claim is a frame count, so nothing else may spend a
    %% message number. A keepalive is a payload through the very same
    %% `send_payload/4`, so one firing would consume a counter value the case
    %% does not know about and put the boundary a frame earlier than the case
    %% believes — which is a weaker test, not a stronger one. The default is 60s
    %% and the case finishes well inside that, but "never fires in practice" is
    %% the same hope `transport_bytes_are_counted` already stopped relying on, so
    %% the precondition is pinned here instead. Read when a connection arms its
    %% timer, which is after this returns.
    ok = application:set_env(?APP, ntcp2_keepalive_interval_ms, 600_000),
    Config;
init_per_testcase(shared_helpers_roundtrip, Config) ->
    Config;
init_per_testcase(_Case, Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    Config.

end_per_testcase(a_session_is_alive_and_speaking_at_frame_70000, _Config) ->
    ok = application:unset_env(?APP, ntcp2_keepalive_interval_ms),
    application:stop(?APP),
    ok;
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
%% The shutdown contract
%% --------------------------------------------------------------------------

%% `f:i2p_ntcp2_listener:stop/1` reports that the listener stopped, and the report
%% is only worth having if it is true when it arrives.
%%
%% **The defect.** The reply was sent first and `exit(normal)` second, and the
%% listening socket closed as a consequence of the process exiting -- so between
%% the two, the answer had arrived and the socket was still open. A connection
%% already sitting in the kernel's accept queue could still be taken by
%% `m:i2p_tcp_acceptor`, and `f:i2p_ntcp2_listener:start_bob/3` could still run: a
%% `f:supervisor:start_child/2` starting a responder that **dials out to a peer**,
%% after a caller had been told nothing further would happen. That last clause is
%% what separates this listener from SAM's, where the same ordering handed out a
%% session and could hit `max_sam_sessions`. Closing the socket explicitly before
%% answering fixes the ordering; waiting for the acceptor's `'DOWN'` is what makes
%% it true for a connection the acceptor had already taken, which a socket close
%% cannot reach.
%%
%% **What this case proves, and what it does not.** The `false = is_process_alive(Acceptor)`
%% is the claim: the acceptor's exit is ordered before the reply, so by the time
%% this process reads the reply the acceptor is gone, and the assertion is a
%% barrier rather than a wait -- everything before the reply has already happened.
%% The acceptor is the only process that calls `f:start_bob/3`, so a dead acceptor
%% is not a weaker version of "no responder will start" but the whole of it. The
%% `econnrefused` below is the same fact seen from the socket: nothing can be
%% accepted at all once the reply is in hand.
%%
%% It is a positive case and it is **not** what kills the defect. Under the old
%% ordering the acceptor also died quickly, just not before the reply -- so this
%% case would usually have passed. `f:wedged_accept_path_is_reported_rather_than_claimed_stopped/1`
%% is the one that rejects the old code, and this case is here because the
%% guarantee is worth stating positively as well as negatively.
stop_reports_only_after_the_accept_path_has_stopped(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    Acceptor = acceptor_of(Listener),
    Port = listen_port(Listener),
    %% One real inbound connection first, so "the accept path is finished" is not
    %% vacuously true of a listener that never accepted anything.
    {ok, CA} = i2p_ntcp2_conn:connect(ri_at(Port, Bob), Alice, #{}),
    {CB, _} = await_ready(),
    try
        Stopper = ask_stop(self(), Listener),
        ok = take_stop_reply(Stopper),
        false = is_process_alive(Acceptor),
        %% Closing the listener stops future accepts and nothing else: the two
        %% established connections are children of the same supervisor and are
        %% untouched by the shutdown. Asserted because "stopped" is easy to
        %% over-read as "gone", and this module doc promises it is not.
        true = is_process_alive(CA),
        true = is_process_alive(CB),
        {error, econnrefused} = connect_ntcp(Port)
    after
        [ok = i2p_ntcp2_conn:stop(Conn) || Conn <- [CA, CB]],
        i2p_ntcp2_listener:stop(Listener)
    end,
    ok.

%% The same guarantee from the other side: a stop that cannot confirm is reported
%% as a stop that could not confirm.
%%
%% **Why the acceptor is suspended rather than the case waiting.** Closing the
%% listening socket ends an acceptor blocked in `f:gen_tcp:accept/1` -- that is what
%% `{error, closed}` means -- so a case that merely queued connections and called
%% `f:stop/1` would see the acceptor finish and could not tell an ordered reply
%% from a lucky one. `f:erlang:suspend_process/1` holds the accept path still:
%% while it is suspended the listener has no way to learn that its acceptor is
%% done, so it cannot honestly answer, and `f:stop/1` must say so rather than
%% report `ok`.
%%
%% **`f:sys:suspend/1` does not work here**, for the reason
%% `f:i2p_sam_SUITE:wedged_accept_path_is_reported_rather_than_claimed_stopped/1`
%% records: `f:gen_tcp:accept/1` is a *selective* receive for `{inet_async, _, _}`,
%% so a `{system, _, _}` message never matches it and the call times out.
%% `f:erlang:suspend_process/1` is scheduler-level and does not care what the
%% process is waiting for: it simply is not scheduled, which is the property the
%% case needs -- the accept path can neither make progress nor be asked whether it
%% has. Scheduling is all that is taken away.
%%
%% **This is the case that rejects the old code**, and the two outcomes are three
%% orders of magnitude apart rather than merely different: the old `f:stop/1`
%% returned `ok` in microseconds because it answered before doing anything, and
%% this one waits out `?ACCEPTOR_EXIT_TIMEOUT_MS` and raises. Nothing here is a
%% race, and nothing here is a tolerance that happens to clear the real behaviour.
%%
%% **The queued connections are what make the refusal correct rather than merely
%% cautious.** They are completed by the kernel and sitting in the accept queue, so
%% "the accept path can still produce a responder" is true at the moment
%% `f:stop/1` is called -- the listener is refusing to answer a question it cannot
%% yet answer, not inventing a failure. They are closed in the `after`, because a
%% client holding a socket into the next case is exactly the kind of cross-case
%% leak that turns one failure into several.
wedged_accept_path_is_reported_rather_than_claimed_stopped(_Config) ->
    {Bob, _Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    Acceptor = acceptor_of(Listener),
    Port = listen_port(Listener),
    %% Nothing has been accepted yet, so "no responder was started" below is a
    %% count against zero rather than against a baseline this case chose.
    0 = i2p_ntcp2_sup:connection_count(),
    ok = suspend(Acceptor),
    Clients = queue_connections(Port, ?STOP_QUEUE),
    %% Armed before the stop, and read in the `after`. The acceptor's exit is the
    %% barrier that makes the count below a reading rather than a race: a monitor
    %% set on an already-dead process answers immediately, so there is no race here
    %% either.
    MRef = erlang:monitor(process, Acceptor),
    try
        %% Read through `f:answered/1` rather than `?assertError` for the reason
        %% the accept-batch case at the end of this module gives for the same
        %% helper: a raise is a term to match here, not a control-flow event to
        %% catch, and matching it keeps this file's style of bare matches.
        {'EXIT', {{accept_path_did_not_stop, Listener}, _}} =
            answered(fun() -> i2p_ntcp2_listener:stop(Listener) end)
    after
        %% The acceptor is resumed before the clients are closed, so the socket
        %% close reached a live accept loop rather than a frozen one -- and the
        %% announcement is in its mailbox, so it exits `normal` at the top of the
        %% loop without taking a single queued connection.
        ok = resume(Acceptor),
        normal = await_down(MRef, Acceptor),
        0 = i2p_ntcp2_sup:connection_count(),
        none = responder_announced(),
        [gen_tcp:close(C) || C <- Clients]
    end,
    ok.

%% The listener's only other linked *process* is its acceptor;
%% `f:proc_lib:start_link/3` in `f:init/3` may or may not leave it linked to the
%% supervisor that started it, and `f:i2p_tcp_acceptor:start_link/2` links the
%% acceptor to it either way. The listening socket is linked too and is not a
%% process, so it is filtered out rather than assumed away -- and the supervisor is
%% filtered rather than subtracted, so this does not depend on which release
%% `f:proc_lib` left the link in place.
%%
%% Matching on *exactly one other process* rather than searching for the acceptor
%% is deliberate. The module's whole shutdown argument rests on there being one
%% acceptor to wait for, so a listener that grew a second linked process would make
%% `f:shutdown/5` wait on the wrong one -- and a case that went looking for an
%% acceptor by module name would find one anyway, and hide that.
acceptor_of(Listener) ->
    Sup = whereis(i2p_ntcp2_sup),
    {links, Links} = erlang:process_info(Listener, links),
    [Acceptor] = [Pid || Pid <- Links, is_pid(Pid), Pid =/= Sup],
    Acceptor.

%% Matched rather than discarded: a suspension that did not take would leave the
%% case asserting against a live accept loop, which is the old code's behaviour,
%% and the case would then pass for the wrong reason.
suspend(Pid) ->
    true = erlang:suspend_process(Pid),
    ok.

resume(Pid) ->
    true = erlang:resume_process(Pid),
    ok.

await_down(MRef, Pid) ->
    receive
        {'DOWN', MRef, process, Pid, Reason} -> Reason
    after ?TIMEOUT ->
        erlang:error({acceptor_never_exited, Pid})
    end.

%% Whether a responder announced itself to this process, read at the instant the
%% acceptor is known to be gone.
%%
%% **The `after 0` is a fact and not a wait**, which is what makes it a barrier
%% rather than a tolerance: the acceptor that is the only caller of
%% `f:start_bob/3` has been observed to exit, so nothing can announce later, and
%% this case's baseline was zero connections, so there is no responder that
%% announced earlier and might announce late. Both halves are what remove the
%% word "yet" from that sentence.
responder_announced() ->
    receive
        {ntcp2_ready, Conn, _RemoteRI} -> {announced, Conn}
    after 0 ->
        none
    end.

%% Connect without reading, and hold. Nothing is read because nothing should ever
%% arrive: these clients exist to sit in the accept queue, and a client that sent a
%% byte would be answered by a responder -- which is the thing the case is about,
%% so a reply here would be a failure rather than a convenience.
queue_connections(Port, N) ->
    [Sock || {ok, Sock} <- [connect_ntcp(Port) || _ <- lists:seq(1, N)]].

connect_ntcp(Port) ->
    gen_tcp:connect("127.0.0.1", Port, [binary, {packet, raw}, {active, false}], 5000).

%% `Parent` is captured by the caller rather than read inside the fun: `self()`
%% there is the stopper, and a reply sent to the stopper is a reply nobody is
%% waiting for. Spawned rather than called directly so the case's own process is
%% free to observe the mailbox while `f:stop/1` runs inside it.
ask_stop(Parent, Listener) ->
    spawn(fun() -> Parent ! {stop_reply, i2p_ntcp2_listener:stop(Listener)} end).

take_stop_reply(Stopper) ->
    receive
        {stop_reply, Reply} -> Reply
    after ?TIMEOUT ->
        erlang:error({stop_never_answered, Stopper})
    end.

%% --------------------------------------------------------------------------
%% The message counter crosses 2^16, and the session is still speaking
%% --------------------------------------------------------------------------

%% A session is alive and speaking at frame 70000, in each direction
%%
%% **The claim is liveness at a named frame**, not merely survival past a number
%% nobody wrote down. See #GY414M9: this case and the fix it guards assert
%% different things on purpose. The fix's case asks *how* the router gets past
%% the boundary; this one asks only that it gets there and is still talking. A
%% session cap at 65535 would satisfy both, and a silent counter reset satisfies
%% only this one — which is the reason it is worth having separately rather than
%% folded into the fix's coverage.
%%
%% **The defect.** `i2p_crypto:es_nonce/1` took `0..65535`, so message number
%% 65536 fell into a clause that was not there and the connection process died
%% with a `function_clause` raised out of a crypto helper. The send direction
%% seeds `msg => 0` when the data phase starts and increments per frame; the
%% receive direction is the inbound side of the same counter and feeds the same
%% function. A session died on exactly the 65536th frame, and **it did not look
%% like a crash on the wire** — the peer manager saw a disconnect and backed
%% off, so from outside a healthy router looked like one that had dropped a peer.
%% See #R8WNYK3.
%%
%% **Both directions in one case, because they are one defect.** The ticket asks
%% for the receive path to be covered by the same case rather than assumed from
%% the send path, and that is because they really are the same counter: fixing
%% one without the other leaves half the bug live and this case stays green. So
%% the pair is flooded in both directions at once and each is counted separately.
%%
%% **What is asserted, and why each part says more than the one before it.**
%% Per direction, every frame arrived carrying the sequence number it was sent
%% with. So the flood is not merely counted — a count is satisfied by one frame
%% counted many times, or by a duplicated one — and not merely ordered, which is
%% what a TCP byte stream gives you for free; ordering is asserted because the
%% framing state is this module's, and a reordering or re-numbering bug there is
%% invisible at the socket. Reading frame N is also the barrier: it cannot arrive
%% before the N-1 before it, so having read it says the sender wrote all
%% ?FRAMES_PER_DIRECTION and therefore ran its counter past 65536 without dying.
%%
%% Then the pair is still alive **and still carrying traffic** — one more frame
%% each way after the flood. A connection that stopped at the boundary without
%% dying would satisfy every count above; only using the session afterwards shows
%% it survived rather than merely did not crash.
%%
%% **The flood runs in its own processes**, one per direction, for the reason
%% `f:fill_until_stalled/2` records: a loop in the case itself would enqueue its
%% frames and return while the connection was still working through them, which
%% is a race dressed up as a bound. Here the case's own receive loop *is* the
%% drain, so feeder and reader run concurrently by construction — the case cannot
%% read a frame the feeder has not already put on the wire.
%%
%% **Neither direction waits for the other.** Both are drained from one mailbox,
%% because this process owns both connections and one `f:receive/2` pattern
%% matches either. A case that drained one direction to exhaustion before looking
%% at the other would stall the side it was not reading.
a_session_is_alive_and_speaking_at_frame_70000(_Config) ->
    {Bob, Alice} = pair(),
    {ok, Listener} = i2p_ntcp2_listener:listen(0, Bob, self()),
    try
        {ok, CA} = i2p_ntcp2_conn:connect(ri_at(listen_port(Listener), Bob), Alice, #{}),
        {CB, _} = await_ready(),
        %% Armed before either flood starts, so a connection that died inside one
        %% cannot be missed as a `noproc` DOWN. The DOWN is what turns "the last
        %% frame never arrived" into "the connection died" instead of a bare
        %% timeout.
        MRefA = erlang:monitor(process, CA),
        MRefB = erlang:monitor(process, CB),
        Conns = #{CA => 1, CB => 1},
        Feeders = [
            spawn(fun() -> feed_numbered(Conn, 1, ?FRAMES_PER_DIRECTION) end)
         || Conn <- [CA, CB]
        ],
        try
            Done = drain_numbered(Conns, 2 * ?FRAMES_PER_DIRECTION),
            %% Each direction's figure is ?FRAMES_PER_DIRECTION + 1, because
            %% `Seen` is the *next* sequence number expected rather than a count
            %% of the frames read, so the count is one less.
            #{CA := PastA, CB := PastB} = Done,
            ?FRAMES_PER_DIRECTION = PastA - 1,
            ?FRAMES_PER_DIRECTION = PastB - 1,
            %% **The liveness assertion, stated at the named frame rather than
            %% left to the reader to infer.** `alive_at_frame/3` names 70000 in its
            %% own failure term, so a red run says which frame the session failed
            %% to reach rather than reporting a bare `false` against a
            %% `is_process_alive/1` call whose expected value is nowhere in the
            %% message. This is the criterion #GY414M9 asks for, and it is why
            %% this is a named function rather than two inline assertions: the
            %% intent has to survive into the failure message, and an inline
            %% `true = is_process_alive(CA)` does not carry it.
            ok = alive_at_frame(CA, ?FRAMES_PER_DIRECTION, send),
            ok = alive_at_frame(CB, ?FRAMES_PER_DIRECTION, recv),
            %% A DOWN is read as a fact rather than waited for, and that is sound
            %% here rather than merely convenient: both the frame announcements
            %% and the monitor DOWN come from the connection, and the runtime
            %% orders one sender's signals. So a connection that exited cannot
            %% have its DOWN still in flight once the case has read the last
            %% frame it sent. The DOWN is checked too because it says *why*,
            %% which is the difference between a boundary failure and an ordinary
            %% drop — `alive_at_frame/3` above only says that it is not alive.
            [false = down(MRef) || MRef <- [MRefA, MRefB]],
            ok = i2p_ntcp2_conn:send(CA, <<"past the boundary">>),
            ok = i2p_ntcp2_conn:send(CB, <<"and back again">>),
            <<"past the boundary">> = receive_frame(CB),
            <<"and back again">> = receive_frame(CA)
        after
            [exit(Feeder, kill) || Feeder <- Feeders]
        end
    after
        i2p_ntcp2_listener:stop(Listener)
    end.

%% Hand over `Left` frames numbered from `Seq`, one per `f:send/2` call, so every
%% frame is its own message number and the reader can tell arrival order from
%% arrival count. A batched send would be a single frame carrying many payloads
%% and would walk the counter once, which is the opposite of what this case is
%% about.
%%
%% **The countdown is what makes the count exact.** The first version of this ran
%% `feed_numbered(Conn, Seq, Last)` with `Last =< Seq` as the base clause, which
%% stops one short of its own argument: it sent frames 1..?FRAMES_PER_DIRECTION - 1
%% and so never sent the frame carrying message number 65536 — the one the whole
%% case exists to send. The case then drained 2 x 65536 frames and waited out its
%% budget looking for a frame that had never been asked for, which reads exactly
%% like the defect it was written to reject. Counting down what is left to send
%% has no off-by-one to hide in.
%%
%% Counting **up** in the payload is what lets one expected-next figure per
%% direction stand for both properties: a frame that arrives out of order fails
%% against it, and a frame that never arrives leaves the flood short of its total.
feed_numbered(_Conn, _Seq, 0) ->
    ok;
feed_numbered(Conn, Seq, Left) ->
    ok = i2p_ntcp2_conn:send(Conn, <<Seq:32/little>>),
    feed_numbered(Conn, Seq + 1, Left - 1).

%% Drain both directions at once until every frame has arrived, and report how
%% far each got.
%%
%% The base clause is checked **before** the receive, because the last frame
%% counted has already arrived by the time `Remaining` reaches zero — a receive
%% first would block on a frame that is never coming, which is a hang dressed as
%% a wait.
%%
%% The progress figure is per connection rather than one total, so a direction
%% that stalled reports its own count instead of hiding behind the other. A
%% connection that dies mid-flood ends the drain with its exit reason, which is
%% the difference between "the boundary killed it" and "the drain gave up".
drain_numbered(Conns, 0) ->
    Conns;
drain_numbered(Conns, Remaining) ->
    receive
        {ntcp2_frame, Conn, <<Seq:32/little>>} when is_map_key(Conn, Conns) ->
            case maps:get(Conn, Conns) of
                Seq ->
                    drain_numbered(Conns#{Conn := Seq + 1}, Remaining - 1);
                Expected ->
                    erlang:error({frame_out_of_order, Conn, {expected, Expected}, {got, Seq}})
            end;
        {ntcp2_frame, Conn, Payload} ->
            erlang:error({unexpected_frame, Conn, Payload});
        {'DOWN', _MRef, process, Conn, Reason} ->
            erlang:error({connection_died_mid_flood, Conn, Reason})
    after ?FRAME_BUDGET_MS ->
        erlang:error({flood_stalled, {frames_read, maps:map(fun(_C, Seen) -> Seen - 1 end, Conns)}})
    end.

%% The assertion this ticket exists for: **this connection is alive, having
%% spoken `Frame` frames in `Dir`.**
%%
%% The named frame is in the failure term on purpose. `true =
%% is_process_alive(Conn)` is a perfectly good assertion whose failure says only
%% `false` — a reader has to go and find which connection, in which direction,
%% at which frame it gave up. Here the frame is the claim, so the frame is what
%% the failure reports:
%%
%%     {session_not_alive_at_frame, Pid, send, 70000}
%%
%% `Dir` is `send` for the connection whose counter walked as it wrote the flood
%% and `recv` for the one whose counter walked as it read the other end's. Both
%% are asserted, because they are two counters on one connection and a fix that
%% touched only one of them leaves the other to die here.
alive_at_frame(Conn, Frame, Dir) ->
    case is_process_alive(Conn) of
        true ->
            ok;
        false ->
            erlang:error({session_not_alive_at_frame, Conn, Dir, Frame})
    end.

%% A monitor that has already fired, read as a fact rather than waited for. The
%% caller's comment is why the `after 0` cannot miss one: the DOWN and the frames
%% come from the same process, so it is ordered after every frame that process
%% sent. Waiting for a DOWN here would hang the case rather than fail it.
down(MRef) ->
    receive
        {'DOWN', MRef, process, _Pid, _Reason} -> true
    after 0 ->
        false
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
