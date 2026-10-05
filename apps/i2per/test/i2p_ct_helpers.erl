%% Shared Common Test support helpers for the i2per suites:
%%
%% - a per-test-case data directory, isolated under the CT priv dir;
%% - an ephemeral port reservation for suites that bind their own listeners;
%% - an event-driven wait/poll that never sleeps a fixed total — each test that
%%   needs a condition to become true polls with a backoff until a deadline,
%%   and a receive wrapper skips (drains) non-matching messages, so a leftover
%%   message from a previous case cannot poison a later assertion;
%% - signed RouterInfo fixtures, so a suite that needs routers in the NetDb
%%   builds them here instead of keeping its own copy of the keygen;
%% - the SU3 signing keypair, generated once per run and shared, because RSA
%%   keygen at the size `m:i2p_su3` requires is the single most expensive thing
%%   a unit run does;
%% - the SSU2 frame capture, which is a `logger` handler rather than a
%%   registered-name sink and is read with a barrier.
%%
%% Test code is not rendered by ExDoc (docs are generated from the `default`
%% profile ebin dirs), so this module carries only header comments.

-module(i2p_ct_helpers).

-export([
    temp_data_dir/1,
    free_port/0,
    stop_app/0,
    await/1,
    await/2,
    wait_msg/2,
    %% Run a self-scheduling `gen_server` callback in a process that is discarded
    %% afterwards. See `f:in_throwaway/1` for the measurement that makes it
    %% necessary and the one thing it does not solve.
    in_throwaway/1,
    events_from/1,
    log_events_from/1,
    project_root/0,
    log_lines_from/1,
    render_log_event/1,
    floodfill_router_info/2,
    db_store_block/3,
    %% One SU3 signing identity for the whole run. See `su3_keypair/0`.
    su3_keypair/0,
    %% A second, distinct identity, for the tests that assert a container is
    %% rejected because it was signed by the wrong key.
    su3_other_keypair/0,
    dead_pid/0,
    silent_ntcp2_peer/1,
    start_ssu2_trace/0,
    stop_ssu2_trace/0,
    dump_ssu2_trace/0,
    %% The bare collector, for a case that wants frames without the whole
    %% start/stop lifecycle. Same process, no level change, no auto-restore.
    start_frame_collector/0,
    stop_frame_collector/1
]).

-define(SU3_KEYPAIR, su3_keypair).
-define(SU3_OTHER_KEYPAIR, su3_other_keypair).

-define(SSU2_TRACE_MAX, 512).

%% The collector's registered name, and the marker it watches for.
%%
%% A frame is identified by the `label` `m:i2p_log:debug/2` attaches, so the
%% collector takes every log line `logger` offers it and keeps only the ones
%% carrying a label. That is what makes this a frame capture rather than a
%% second copy of everything the tree logs: the boot lines and the supervisor
%% reports go past it.
-define(SSU2_FRAMES, i2p_ct_ssu2_frames).

%% The label the dump's own barrier frame carries. Named once because three
%% clauses have to recognise the same shape -- log it, look for it, filter it
%% out of the answer -- and a label spelled three times is a label that can be
%% spelled three ways.
-define(FRAME_BARRIER, '__frame_barrier__').

%% How long a dump waits for its own barrier. A hang guard, not a
%% synchronisation, for the reason `f:log_events_from/1` gives: the barrier
%% decides, not the clock. Crossing it does not raise here -- see
%% `f:dump_ssu2_trace/0` for why this path reports rather than fails.
-define(FRAME_BARRIER_TIMEOUT_MS, 2000).

%% How long to wait for a barrier event to come back from the bus. A hang guard,
%% not a synchronisation -- see `f:events_from/1`. Crossing it raises.
-define(BUS_DELIVERY_TIMEOUT_MS, 5000).

%% The same for the log-capture path. A hang guard, not a synchronisation: the
%% barrier decides, not the clock. See `f:log_lines_from/1`.
-define(LOG_DELIVERY_TIMEOUT_MS, 5000).

%% The repository root, found by walking up from this module's beam until the
%% source tree is in sight.
%%
%% Lives here because three test modules now need it and each had its own copy:
%% `i2p_events_vocabulary_tests`, `i2p_log_checklist_tests`, and the release-profile
%% cases in `i2p_log_tests`. A per-module copy is harmless until one of them is
%% wrong, and then two of the three are wrong in different ways -- and the copies
%% are only ever exercised by the case that needs them, so the drift is invisible.
%%
%% Walking up from the beam rather than reading the CWD, because rebar3 does not
%% promise a working directory and a test that depends on one fails on someone's
%% machine and not yours.
-spec project_root() -> file:filename_all().
project_root() ->
    climb(filename:dirname(code:which(?MODULE)), 8).

climb(_Dir, 0) ->
    erlang:error({project_root_not_found_from, code:which(?MODULE)});
climb(Dir, Fuel) ->
    case filelib:is_regular(filename:join([Dir, "apps", "i2per", "src", "i2p_log.erl"])) of
        true -> Dir;
        false -> climb(filename:dirname(Dir), Fuel - 1)
    end.

%% A directory that exists and is writable for the current test case, created
%% beneath the CT priv dir. Store it in Config as `{temp_data_dir, Dir}` and
%% pass Config back in on every call so each case gets a fresh, isolated one.
-spec temp_data_dir(Config) -> string() when Config :: proplists:proplist().
temp_data_dir(Config) ->
    Dir = filename:join(private_dir(Config), "data"),
    ok = filelib:ensure_dir(filename:join(Dir, "_")),
    Dir.

private_dir(Config) ->
    case proplists:get_value(priv_dir, Config) of
        undefined ->
            Base = filename:join(ct:log_dir(), "priv_" ++ os:getpid()),
            ok = filelib:ensure_dir(filename:join(Base, "_")),
            Base;
        Priv ->
            Priv
    end.

%% Reserve an ephemeral TCP port. The port is released on return; the caller
%% must bind it immediately (typical for test listeners) — this is a race-free
%% convenience, not a lease.
-spec free_port() -> inet:port_number().
free_port() ->
    {ok, Sock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Sock),
    ok = gen_tcp:close(Sock),
    Port.

%% Stop the i2per application and wait for the name to actually be free.
%% `application:stop/1` returns before the children have unlinked, so a suite
%% that starts a registered process straight afterwards can collide with the
%% outgoing one and fail every later suite with `already_started`. Suites that
%% need a process of their own should start only that process, not the
%% application — see the header note.
-spec stop_app() -> ok.
stop_app() ->
    _ = application:stop(i2per),
    wait_stopped(i2per, 5000).

wait_stopped(_App, 0) ->
    timeout;
wait_stopped(App, Budget) ->
    case lists:keymember(App, 1, application:which_applications()) of
        true ->
            timer:sleep(20),
            wait_stopped(App, Budget - 20);
        false ->
            ok
    end.

%% A signed, floodfill-capable RouterInfo. `TimestampMs` is the publish
%% timestamp and is the caller's to choose, because the NetDb's acceptance
%% window is what several tests are about: `f:i2p_netdb:valid_window/2` rejects
%% anything published more than 27 hours before `Now`, and anything more than
%% 2 minutes after it. `Host` is a documentation-range address, so a fixture
%% never names a real host.
-spec floodfill_router_info(integer(), binary()) -> i2p_router_info:router_info().
floodfill_router_info(TimestampMs, Host) ->
    {SPub, Seed} = i2p_crypto:ed25519_keygen(),
    {CPub, _} = i2p_crypto:x25519_keygen(),
    Identity = i2p_keys:from_keys(CPub, SPub),
    Addr = i2p_router_info:ntcp2_address(
        Host, 4668, crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(16)
    ),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => <<"Of">>
    },
    i2p_router_info:build(Identity, TimestampMs, [Addr], Opts, Seed).

%% A DatabaseStore I2NP message shaped the way `m:i2p_ssu2_conn:forward_block/2`
%% hands one to the peer manager: `{i2np, Type, MsgId, ShortExp, Body}`, with
%% the I2NP header already stripped. Type 0 wraps the RouterInfo in the
%% DatabaseStore data field; any other type is sent as opaque bytes, which is
%% the point — the manager must refuse to push on an entry it never parsed
%% rather than re-encode what it was handed.
-spec db_store_block(byte(), i2p_crypto:hash(), i2p_router_info:router_info() | binary()) ->
    {i2np, byte(), non_neg_integer(), non_neg_integer(), binary()}.

%% The SU3 signing keypair every reseed-shaped test signs with, generated once
%% per run.
%%
%% **The key is RSA-4096 because `m:i2p_su3` accepts nothing else.** The decoder
%% rejects any signature type other than `16#0006` and any signature length other
%% than 512 bytes, and 512 bytes is a 4096-bit modulus, so a smaller key produces a
%% container this router itself declares malformed. Do not shrink it to save the
%% time: the cost is real and the fix is the sharing below, not a smaller key.
%%
%% Shared rather than memoised per module, because four suites and unit modules
%% each carried their own copy of the same four lines of `persistent_term`
%% bookkeeping. They agreed on one identity by coincidence, and they paid for one
%% RSA-4096 keygen each. EUnit and Common Test are separate OS processes, so this
%% removes the duplicate within a run and never across the two.
-spec su3_keypair() -> {tuple(), map()}.
su3_keypair() ->
    memorise(?SU3_KEYPAIR).

%% A second identity, distinct from `su3_keypair/0`, for the cases that assert a
%% container is refused because it was signed by a key the trust store does not
%% hold. Memoised for the same reason and with the same cost, which is why it
%% exists rather than being generated per call.
-spec su3_other_keypair() -> {tuple(), map()}.
su3_other_keypair() ->
    memorise(?SU3_OTHER_KEYPAIR).

memorise(Key) ->
    case persistent_term:get({?MODULE, Key}, undefined) of
        undefined ->
            Value = make_su3_keypair(),
            persistent_term:put({?MODULE, Key}, Value),
            Value;
        Value ->
            Value
    end.

make_su3_keypair() ->
    Priv = public_key:generate_key({rsa, 4096, 65537}),
    #{cert := Cert} = public_key:pkix_test_root_cert("i2per-su3-test", [{key, Priv}]),
    {Priv, Cert}.

%% A pid that has already exited, for exercising a teardown path without
%% taking the test process down with it. A store the peer manager cannot parse
%% makes it stop the connection, so a test that wants to check that path must not
%% pass itself as the connection.
-spec dead_pid() -> pid().
dead_pid() ->
    Pid = spawn(fun() -> ok end),
    MRef = erlang:monitor(process, Pid),
    receive
        {'DOWN', MRef, process, Pid, _} -> Pid
    end.

%% A TCP listener that speaks the NTCP2 handshake and then stops reading.
%%
%% This is the "peer that has stopped reading" fault, built rather than
%% simulated, because every way of simulating it from outside a live connection
%% is worse: the only handle on a running responder is
%% `f:erlang:suspend_process/1`, which deadlocks the node's code server as soon
%% as the suspended process is anywhere near a module load, and
%% `f:sys:suspend/1` does not work at all, because a connection process is a
%% plain receive loop and answers no system messages. Doing the responder half of
%% the handshake here is about thirty lines, suspends nothing, and leaves nothing
%% behind for a later case to trip over.
%%
%% Input: the responder's `m:i2p_ntcp2_conn:local_keys/0`.
%% Output: `{LSock, Port, Pid}` — the listening socket (the caller closes it),
%% the bound port to publish in a RouterInfo, and the peer process. The peer
%% announces `{silent_ntcp2_peer, self()}` to the calling process once the
%% handshake is complete, and from then on never reads its socket.
-spec silent_ntcp2_peer(map()) -> {gen_tcp:socket(), inet:port_number(), pid()}.
silent_ntcp2_peer(Keys) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Parent = self(),
    Pid = spawn(fun() -> silent_ntcp2_accept(LSock, Keys, Parent) end),
    {LSock, Port, Pid}.

silent_ntcp2_accept(LSock, Keys, Parent) ->
    {ok, Sock} = gen_tcp:accept(LSock, 10000),
    ok = silent_ntcp2_handshake(Sock, Keys),
    Parent ! {silent_ntcp2_peer, self()},
    %% Parked, not blocked: the process holds the socket and never touches it
    %% again. A zero-length read would answer immediately and is therefore not a
    %% way to "wait" here -- the whole point is that this process does nothing.
    silent_ntcp2_idle(Sock).

%% The responder's half of the XK handshake, using the library's own stream
%% readers so the fixture cannot drift from what a real responder does.
silent_ntcp2_handshake(Sock, #{static_priv := Priv, static_pub := Pub, hash := Hash, iv := IV}) ->
    S0 = i2p_ntcp2:bob_init(Priv, Pub, Hash, IV),
    Recv = fun
        (0) -> {ok, <<>>};
        (N) -> gen_tcp:recv(Sock, N, 10000)
    end,
    {ok, _Opts1, S1} = i2p_ntcp2:receive_msg1_stream(S0, Recv),
    {ok, Msg2, S2} = i2p_ntcp2:create_msg2(
        S1, silent_ntcp2_eph(), crypto:strong_rand_bytes(8), now_s()
    ),
    ok = gen_tcp:send(Sock, Msg2),
    {ok, _Payload, _S3} = i2p_ntcp2:receive_msg3_stream(S2, Recv),
    ok.

silent_ntcp2_eph() ->
    {Priv, _} = i2p_crypto:x25519_keygen(),
    Priv.

now_s() ->
    erlang:system_time(second).

%% The socket stays open on purpose: closing it would be a different fault (a peer
%% that went away, which the connection already handles as `{tcp_closed, _}`), and
%% this fixture exists to produce the one where the peer is present and silent.
silent_ntcp2_idle(Sock) ->
    receive
        {read, From} ->
            {ok, Data} = gen_tcp:recv(Sock, 0, 1000),
            From ! {read, Data},
            silent_ntcp2_idle(Sock)
    end.

db_store_block(0, Key, RI) when is_map(RI) ->
    db_store_block(0, Key, i2p_i2np:router_info_data(i2p_router_info:to_binary(RI)));
db_store_block(Type, Key, Data) when is_binary(Data) ->
    #{body := Body} = i2p_i2np:db_store(Key, Type, 0, undefined, Data),
    {i2np, 1, 7, 0, Body}.

%% %%%%% Running a callback where its side effects die with it %%%%% %%%
%%
%% **The whole unit tier runs in ONE process, and that is the fact this helper
%% exists to work around.** Measured, not assumed: `rebar3 eunit --module=a,b,c`
%% passes the module list to a single `f:eunit:test/1` call, and eunit reuses one
%% worker across it. Two probe modules run through the real gate reported the same
%% pid -- `<0.535.0>` -- for every test in both. Three *separate*
%% `f:eunit:test/1` calls give three different pids, so the sharing is a property
%% of the call, not of eunit: it is the justfile's one `--module=` flag that
%% creates the shared worker. Common Test is the opposite and needs none of this --
%% every testcase gets a fresh process and mailbox, which is why the rule below is
%% about the eunit layer only.
%%
%% So a `gen_server` callback called directly in a test schedules into the worker,
%% and the worker outlives the test. `m:i2per_status_state:handle_info(poll, _)`
%% re-arms itself every five seconds, so a drain is not a fix: the timer that will
%% produce the next message is still armed, and waiting long enough to be
%% conclusive is slower than the whole suite. **A dead process takes its timers
%% with it**, which is the only thing that is actually true here --
%% `f:handle_info/2` is written for a process whose lifetime is the gen_server's,
%% and the test is not that.
%%
%% Shared rather than copied per module, because there is already one caller whose
%% reasoning is worth not losing (`i2per_status_state_tests`) and a second copy of
%% a helper this particular -- whose own failure mode is a leaked `'DOWN'` -- is
%% how the two start to differ.
%%
%% **What this does not solve.** `erlang:process_info(Pid, timers)` raises `badarg`
%% at OTP 28, so a process's armed timers cannot be enumerated and there is no
%% runtime census of them; only a trace on `erlang:send_after/3` can see them, and
%% that needs the trace installed before the tier starts, which `rebar3 eunit` does
%% not offer a hook for. The tree-wide check is therefore static --
%% `i2p_shared_worker_tests` reads the eunit modules and fails on a direct call --
%% and this helper is the escape hatch that rule points at.
%%
%% Both bounds answer, and they are different conditions: `callback_timeout` is a
%% callback that never returned, `callback_would_not_die` is one that returned and
%% then stayed alive. The second is the one that matters, because the `'DOWN'`
%% flush is what keeps this helper from being the leak it prevents.
-spec in_throwaway(fun(() -> Result)) -> Result.
in_throwaway(Fun) ->
    Parent = self(),
    Ref = make_ref(),
    {Pid, MRef} = spawn_monitor(fun() -> Parent ! {Ref, catch Fun()} end),
    Reply =
        receive
            {Ref, Result} -> Result
        after 5000 ->
            exit({callback_timeout, Pid})
        end,
    %% Wait for the process to be gone before returning. It is already dead --
    %% it answered and exited -- but the `'DOWN'` is still in this mailbox, and
    %% leaving it there is the same class of leak this helper exists to stop.
    receive
        {'DOWN', MRef, process, _Pid, _Reason} -> ok
    after 5000 ->
        exit({callback_would_not_die, Pid})
    end,
    Reply.

%% Poll `Fun` (a zero-arity predicate) until it returns true or the default
%% 10-second deadline passes, then fail with error(timeout). No fixed sleeps.
-spec await(fun(() -> boolean())) -> ok.
await(Fun) ->
    await(Fun, 10000).

-spec await(fun(() -> boolean()), non_neg_integer()) -> ok.
await(Fun, Timeout) when is_function(Fun, 0) ->
    await_loop(Fun, erlang:monotonic_time(millisecond) + Timeout).

await_loop(Fun, Deadline) ->
    case Fun() of
        true ->
            ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    await_timeout(Fun);
                false ->
                    timer:sleep(25),
                    await_loop(Fun, Deadline)
            end
    end.

%% Cold-path diagnostic for an await deadline miss, mirroring
%% `wait_msg_timeout/1`: classify the miss as predicate-late (the condition
%% became true just after the deadline -- a scheduling tail) versus missing
%% (it never became true, so the chain that should have set it stalled or
%% dropped), snapshot the mailbox, and dump the SSU2 trace when a collector is
%% registered. Without this an await timeout reports only `{timeout, ...}` and
%% cannot be told apart from a genuine production stall.
await_timeout(Fun) ->
    ct:pal(
        "await timeout; post-deadline predicate = ~0p~nmailbox = ~0p",
        [late_predicate(Fun), mailbox_summary(mailbox_snapshot(), 30)]
    ),
    case dump_ssu2_trace() of
        [] ->
            ok;
        Buffer ->
            ct:pal("ssu2 frames (~p):~n~0p", [length(Buffer), Buffer])
    end,
    error(timeout).

%% Re-check the predicate once, after the deadline, so the log distinguishes a
%% late condition from a missing one. The try keeps a throwing predicate from
%% masking the original timeout with an unrelated crash; this is a diagnostic
%% path only and never changes the outcome, which is always error(timeout).
late_predicate(Fun) ->
    try Fun() of
        true -> predicate_late;
        false -> missing
    catch
        _Class:_Reason -> predicate_raised
    end.

mailbox_snapshot() ->
    case process_info(self(), messages) of
        {messages, Msgs} when is_list(Msgs) -> Msgs;
        _ -> []
    end.

%% Receive until a message matches `Pred` (a unary fun returning `{true, Value}`
%% or false). Non-matching messages are drained while the wait continues. Fails
%% with error(timeout) on the deadline.
-spec wait_msg(fun((term()) -> false | {true, term()}), non_neg_integer()) -> term().
wait_msg(Pred, Timeout) when is_function(Pred, 1) ->
    wait_msg_loop(Pred, erlang:monotonic_time(millisecond) + Timeout).

wait_msg_loop(Pred, Deadline) ->
    Now = erlang:monotonic_time(millisecond),
    case Now >= Deadline of
        true ->
            wait_msg_timeout(Pred);
        false ->
            receive
                Msg ->
                    case Pred(Msg) of
                        {true, Value} -> Value;
                        false -> wait_msg_loop(Pred, Deadline)
                    end
            after erlang:max(0, Deadline - Now) ->
                wait_msg_timeout(Pred)
            end
    end.

%% Cold-path diagnostic for a deadline miss: drain the mailbox once more and
%% classify whether the awaited value was present a hair late (mailbox-late is a
%% scheduling tail) or genuinely absent (the delivering process never forwarded
%% it because of a datagram loss or stalled chain). Log a compact snapshot in
%% either case. This follows the `observe_for_result/1` pattern in
%% `i2p_ssu2_peertest_SUITE`.
wait_msg_timeout(Pred) ->
    Mail = mailbox_snapshot(),
    Late = late_scan(Pred),
    ct:pal(
        "wait_msg timeout; post-deadline scan = ~0p~nmailbox (pre-drain) = ~0p",
        [Late, mailbox_summary(Mail, 30)]
    ),
    case dump_ssu2_trace() of
        [] ->
            ok;
        Buffer ->
            ct:pal("ssu2 frames (~p):~n~0p", [length(Buffer), Buffer])
    end,
    error(timeout).

late_scan(Pred) ->
    receive
        Msg ->
            case Pred(Msg) of
                {true, Value} -> {mailbox_late, Value};
                false -> late_scan(Pred)
            end
    after 0 ->
        missing
    end.

mailbox_summary(undefined, _N) ->
    [];
mailbox_summary(Msgs, N) ->
    lists:sublist([summ_msg(M) || M <- Msgs], N).

summ_msg({ssu2_data, P, Blocks}) ->
    {ssu2_data, P, [summ_block(B) || B <- Blocks]};
summ_msg({ssu2_closed, P, Reason}) ->
    {ssu2_closed, P, Reason};
summ_msg({ssu2_ready, P, _Keys, RI}) ->
    {ssu2_ready, P, byte_size(RI)};
summ_msg({udp, S, _IP, _Port, Datagram}) ->
    {udp, S, byte_size(Datagram)};
summ_msg({ssu2_packet, Datagram}) ->
    {ssu2_packet, byte_size(Datagram)};
summ_msg({peertest_result, Result}) ->
    {peertest_result, Result};
summ_msg({'DOWN', _MRef, process, P, Info}) ->
    {down, P, Info};
summ_msg(M) when is_atom(M) ->
    M;
summ_msg(M) when is_tuple(M), tuple_size(M) > 0 ->
    {tuple, element(1, M), tuple_size(M)};
summ_msg(M) when is_tuple(M) ->
    {tuple, 0};
summ_msg(M) when is_binary(M) ->
    {binary, byte_size(M)};
summ_msg(_M) ->
    term.

summ_block({i2np, Type, MsgId, _ShortExp, Body}) ->
    {i2np, Type, MsgId, byte_size(Body)};
summ_block({first_fragment, Type, MsgId, _ShortExp, Body}) ->
    {first_fragment, Type, MsgId, byte_size(Body)};
summ_block({follow_on_fragment, FragNum, IsLast, MsgId, Body}) ->
    {follow_on_fragment, FragNum, IsLast, MsgId, byte_size(Body)};
summ_block({peertest, N, _Code, _Flags, _Hash, _Ver, _Nonce, _Ts, _Port, _Ip, _Sig}) ->
    {peertest, N};
summ_block({router_info, Flag, RIData}) ->
    {router_info, Flag, byte_size(RIData)};
summ_block({path_challenge, Data}) ->
    {path_challenge, byte_size(Data)};
summ_block({path_response, Data}) ->
    {path_response, byte_size(Data)};
summ_block(B) when is_tuple(B) ->
    {block, element(1, B), tuple_size(B)};
summ_block(B) ->
    {block, B}.

%% ------------------------------------------------------------------
%% SSU2 frame capture
%%
%% The SSU2 session, its listener, the relay coordinator and the PeerTest
%% coordinator each record a frame per thing on the wire through
%% `m:i2p_log:debug/2`. At the `notice` default there are none, so a suite
%% that wants them turns the level to `debug`, attaches a `logger` handler
%% that keeps the labelled ones, and dumps what it collected when a case
%% fails. Used by the four SSU2 suites' per-case lifecycle, and read from
%% `f:await/1` and `f:wait_msg/2` on a timeout so a stalled test carries its
%% own frames.
%%
%% **This used to be a registered name and its own enable/disable.** It is a
%% `logger` handler now, which is the whole point of the move: the per-packet
%% detail obeys `log_level` like everything else, so there is no second
%% verbosity control that cannot be governed from a config key.

-spec start_ssu2_trace() -> ok.
start_ssu2_trace() ->
    ok = stop_collector(),
    ok = i2p_log:set_level(debug),
    _Collector = start_frame_collector(),
    ok.

%% The collector on its own, with the handler attached.
%%
%% Split out because a case that wants to assert on frames has to arrange the
%% level itself: `f:start_ssu2_trace/0` changes the running node's verbosity and
%% restores it in `f:stop_ssu2_trace/0`, which is right for a suite's
%% per-case lifecycle and wrong for a test that is about the level. The
%% collector takes frames from whatever level is in force, so a case that sets
%% `debug` and stops there sees the same frames.
-spec start_frame_collector() -> pid().
start_frame_collector() ->
    Collector = spawn(fun() -> frame_collector({[], current_level(), undefined}) end),
    true = register(?SSU2_FRAMES, Collector),
    {ok, HandlerId} = i2p_log_tests_collector:start(Collector),
    Collector ! {handler, HandlerId},
    Collector.

%% Detach the handler, put the level back, and stop the collector -- in that
%% order, and all three synchronous.
-spec stop_frame_collector(pid()) -> ok.
stop_frame_collector(Collector) ->
    stop_collector_at(Collector).

%% Dump whatever the case collected, then tear down.
%%
%% The handler goes first because it is the only thing still delivering lines
%% into the collector, and the level goes back last because restoring it while
%% frames were still arriving would change what a concurrent case could see.
%% The level is the caller's to have: the four suites call this from
%% `end_per_testcase`, and a case left at `debug` makes every case after it log
%% verbosely, which is the same leak the boot-line cases in `i2p_log_tests`
%% guard against with `f:with_level/1`.
-spec stop_ssu2_trace() -> ok.
stop_ssu2_trace() ->
    Frames = dump_ssu2_trace(),
    case Frames of
        [] ->
            ok;
        _ ->
            ct:pal("ssu2 frames (final, ~p):~n~0p", [length(Frames), Frames])
    end,
    stop_collector().

stop_collector() ->
    case whereis(?SSU2_FRAMES) of
        Collector when is_pid(Collector) -> stop_collector_at(Collector);
        _NotRunning -> ok
    end.

%% Synchronous teardown, and the reason for the monitor: `logger:remove_handler/1`
%% returns once the handler is gone, so after it there can be no line still in
%% flight, and the `'DOWN'` proves the collector has finished with what it had.
%%
%% A collector left running would keep taking the next case's frames and answer
%% its barrier, so a dump in a later case would report frames from a case that
%% had already finished. `unregister` first so nothing can address it in between.
stop_collector_at(Collector) ->
    unregister(?SSU2_FRAMES),
    Ref = erlang:monitor(process, Collector),
    Collector ! teardown,
    receive
        {'DOWN', Ref, process, Collector, _Reason} -> ok
    after 1000 ->
        erlang:demonitor(Ref, [flush]),
        ok
    end.

%% The level to put back, read from `logger` rather than from `f:i2p_log:level/0`.
%% Asking the module would be circular: this set it, so its answer is what it
%% decided, not what the node is running at.
current_level() ->
    maps:get(level, logger:get_primary_config()).

%% The captured frames, oldest first, as `{Label, Context, Mfa}` triples.
%%
%% **A barrier, not a drain.** The collector answers a dump only once it has
%% seen the marker logged *after* the work under inspection, and `logger` walks
%% its handler list in order for each event -- so the marker's arrival proves
%% every frame logged before it has already been delivered. The previous shape
%% asked the collector for a snapshot over a message channel with a 1000ms
%% `after`, which is a deadline: on a loaded machine the frames it had not yet
%% processed were simply absent from a buffer that read as complete. That is
%% the one failure mode a diagnostic cannot have, because the whole point of
%% dumping is that someone is trying to work out what did not arrive.
%%
%% **It reports rather than raises when the barrier does not come.** Every
%% caller is already on a failure path -- `f:await/1` and `f:wait_msg/2` are
%% about to raise `timeout` -- so raising here would replace the real diagnosis
%% with one about the diagnostic. A missing barrier is itself reported in the
%% returned value rather than thrown.
-spec dump_ssu2_trace() -> [tuple()].
dump_ssu2_trace() ->
    case whereis(?SSU2_FRAMES) of
        Collector when is_pid(Collector) ->
            Ref = make_ref(),
            %% A frame, so it passes whatever filter the collector applies, and
            %% distinguishable from a real one by its shape.
            ok = i2p_log:debug({?FRAME_BARRIER, Ref}, []),
            Collector ! {dump, self(), Ref},
            receive
                {dump_result, Ref, Frames} ->
                    Frames;
                {dump_result, Ref, barrier_missed, Frames} ->
                    ct:pal("ssu2 frame capture: barrier never arrived; ~p frames so far", [
                        length(Frames)
                    ]),
                    Frames
            after ?FRAME_BARRIER_TIMEOUT_MS ->
                ct:pal("ssu2 frame capture: timed out waiting for the collector"),
                []
            end;
        _NotRunning ->
            []
    end.

%% Keeps the last ?SSU2_TRACE_MAX labelled events, newest first internally,
%% plus the level to put back and the handler to detach.
%%
%% Two jobs, and the split is why it is not simply `f:events_from/1`: a
%% *barrier* is a one-shot question with a one-shot answer, while this is asked
%% on a timeout after arbitrary work, and the answer has to be whatever has
%% accumulated since the suite started rather than since a marked instant.
frame_collector({Frames, Before, HandlerId}) ->
    receive
        {log_line, Event} ->
            frame_collector({keep(frame(Event), Frames), Before, HandlerId});
        {dump, From, Ref} ->
            From ! dump_answer(Ref, Frames),
            frame_collector({Frames, Before, HandlerId});
        {handler, Id} ->
            frame_collector({Frames, Before, Id});
        teardown ->
            %% The handler first, so no line is in flight when the level moves,
            %% then the level, then stop. Any failure here is the caller's
            %% `end_per_testcase` to report rather than this process's.
            i2p_log_tests_collector:stop({ok, HandlerId}),
            i2p_log:set_level(Before),
            ok
    end.

%% The answer, and whether the barrier was seen.
%%
%% Two shapes because a buffer that reads as complete when it is not is the one
%% failure a diagnostic cannot have: someone reading a dump is trying to work
%% out what did not arrive, and a silently short answer would send them looking
%% for a packet that was simply not collected yet. The caller reports the miss
%% rather than raising, because it is already about to raise the real failure.
dump_answer(Ref, Frames) ->
    case lists:member(Ref, barrier_refs(Frames)) of
        true -> {dump_result, Ref, lists:reverse(drop_barriers(Frames))};
        false -> {dump_result, Ref, barrier_missed, lists:reverse(drop_barriers(Frames))}
    end.

%% The barrier is machinery, not a frame, so it does not appear in what a reader
%% is shown. It stays in the buffer until a dump, because that is how its
%% arrival is known.
drop_barriers(Frames) ->
    [F || F = {{?FRAME_BARRIER, _Ref}, _Context, _Mfa} <- Frames].

%% A frame, or dropped. The `label` key is what `m:i2p_log:debug/2` attaches
%% and nothing else in the tree does, so its presence is the whole filter.
%%
%% Reported rather than silently dropped when the shape is unrecognised: a
%% `logger` event that is neither a format call nor a progress report is not
%% something this collector can tell from a frame, and a capture that quietly
%% loses an event shape is a capture nobody can trust when they are reading it
%% to work out what went wrong.
-spec keep(term(), [term()]) -> [term()].
keep(Frame, Frames) when Frame =/= skip ->
    lists:sublist([Frame | Frames], ?SSU2_TRACE_MAX);
keep(skip, Frames) ->
    Frames.

frame(#{meta := #{label := Label, context := Context}, mfa := Mfa}) ->
    {Label, Context, Mfa};
frame(_Other) ->
    skip.

barrier_refs(Frames) ->
    [Ref || {{?FRAME_BARRIER, Ref}, _Context, _Mfa} <- Frames].

%%%%%%%%% Observing the event bus %%%%%%%%%

%% Run `Fun`, then return every event the bus delivered while it ran.
%%
%% Used for positive and negative assertions alike, and the negative case is why
%% this exists rather than a drain with a zero timeout.
%%
%% Two things about the bus are easy to get wrong, and both were got wrong here
%% first:
%%
%% 1. **`i2p_events:notify/1` returning is not a delivery barrier.** `gen_event`
%%    answers the notify call as soon as the event is queued and dispatches it to
%%    the handlers afterwards, in its own process. A caller that has just announced
%%    something has learned nothing about whether a handler has seen it.
%%
%% 2. **Waiting for a barrier must not consume the events being collected.**
%%    `f:wait_msg/2` drops everything that does not match, so using it to wait for
%%    the barrier would throw away the very events under assertion.
%%
%% So the barrier is a *known* event announced after `Fun` has returned, and the
%% wait accumulates rather than discards: once the barrier arrives, every event
%% announced before it has been delivered, because the manager walks its handler
%% list in order for each one. That makes the absence of an event a real absence
%% rather than a race that happened to pass -- and it works for the negative
%% assertions too, which no deadline can do honestly.
-spec events_from(fun(() -> any())) -> [tuple()].
events_from(Fun) ->
    Owned = start_bus(),
    try
        ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
        _ = Fun(),
        Barrier = {config_changed, {bus_barrier, make_ref()}, 1},
        ok = i2p_events:notify(Barrier),
        {Before, After} = collect_until(Barrier, []),
        lists:reverse(Before) ++ After
    after
        _ = gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
        stop_bus(Owned)
    end.

%% The log-capture counterpart of `f:events_from/1`: run `Fun`, then barrier on a
%% line logged after it, and return every line collected up to that barrier.
%%
%% **Why a marker line is a barrier, and a wait is not.** `logger:log/3` hands the
%% event to the `logger` server and returns; the handler is a separate process and
%% will see it whenever it gets round to it. A zero-timeout drain afterwards is a
%% race that passes on an idle machine, exactly as `i2p_events:notify/1` returning
%% is not a delivery guarantee. The marker is logged *after* the work, the handler
%% processes its mailbox in order, so the marker's arrival is proof that every
%% line emitted before it has already been delivered. Crossing the timeout raises
%% rather than returning a short answer, because a partial list would read as a
%% complete one.
%%
%% Output: the rendered log lines, oldest first, without the marker itself.
-spec log_lines_from(fun(() -> term())) -> [string()].
log_lines_from(Fun) ->
    [render_log_event(Event) || Event <- log_events_from(Fun)].

-doc """
The log events `Fun` produced, oldest first, each still carrying its level.

Same barrier as `f:log_lines_from/1` and the same guarantee; this variant keeps
`logger`'s own `#{level := _, msg := _}` instead of rendering it, so a case can
assert *what level* a line was recorded at rather than only what it says.

ADR 0002 requires the three boot lines at `notice`, and asserting their text alone
does not enforce it: the fact name in `f:i2p_log:emit/3` selects the level and
nothing else, so recording the started-as line under a `warning` fact produces the
identical text at a different level, and every text assertion still passes.
""".
-spec log_events_from(fun(() -> term())) -> [logger:log_event()].
log_events_from(Fun) ->
    {ok, Id} = i2p_log_tests_collector:start(self()),
    try
        _ = Fun(),
        Barrier = lists:flatten(io_lib:format("~p", [{i2p_log_barrier, make_ref()}])),
        logger:notice("~s", [Barrier]),
        log_events_until(Barrier, [])
    after
        i2p_log_tests_collector:stop({ok, Id})
    end.

-spec log_events_until(string(), [logger:log_event()]) -> [logger:log_event()].
log_events_until(Barrier, Acc) ->
    receive
        {log_line, Event} ->
            case render_log_event(Event) of
                Barrier ->
                    lists:reverse(Acc);
                _Line ->
                    log_events_until(Barrier, [Event | Acc])
            end
    after ?LOG_DELIVERY_TIMEOUT_MS ->
        erlang:error({log_barrier_never_arrived, lists:reverse(Acc)})
    end.

%% Render one captured log event the way `logger`'s own formatter would, so a test
%% asserts on the text an operator reads rather than on the pre-format term.
%%
%% Two shapes arrive, not one. A log call carries `{Format, Args}`. A *progress
%% report* -- `supervisor` reporting a started child -- carries `{report, Report}`,
%% and reaching this at all is a real consequence of a router running at `info`,
%% which is exactly one of the configurations a boot-line test asks about. Rendering
%% it with `io_lib:format/2` treats the atom `report` as a format string and raises
%% `badarg`, so it gets its own clause.
-spec render_log_event(map()) -> string().
render_log_event(#{msg := {report, Report}}) ->
    lists:flatten(io_lib:format("~p", [Report]));
render_log_event(#{msg := {Format, Args}}) when
    (is_list(Format) orelse is_binary(Format)) andalso is_list(Args)
->
    lists:flatten(io_lib:format(Format, Args));
render_log_event(Event) ->
    %% Anything else is rendered whole rather than guessed at, so a new event shape
    %% shows up in a failing assertion instead of raising inside the barrier.
    lists:flatten(io_lib:format("~p", [Event])).

%% Everything the bus delivered up to and including `Barrier`, and separately
%% anything already queued behind it.
%%
%% A barrier that never arrives is raised, not returned. Waiting five seconds and
%% then carrying on would turn a broken bus into a test that passes for the wrong
%% reason, which is the one outcome worse than a failure.
collect_until(Barrier, Acc) ->
    receive
        Barrier ->
            {Acc, drain_events([])};
        Event ->
            collect_until(Barrier, [Event | Acc])
    after ?BUS_DELIVERY_TIMEOUT_MS ->
        erlang:error({bus_barrier_not_delivered, Barrier})
    end.

drain_events(Acc) ->
    receive
        Event -> drain_events([Event | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.

%% The manager normally belongs to the router application and is started by its
%% supervisor. A case that drives a callback directly may run with no application
%% up, so one is started here -- and stopped again only when this function was what
%% started it, so no case leaves the bus down for the rest of the run. Unlinked,
%% because a test process dying must not take the bus with it.
start_bus() ->
    case whereis(i2p_events) of
        undefined ->
            {ok, Pid} = i2p_events:start_link(),
            unlink(Pid),
            Pid;
        _Existing ->
            none
    end.

stop_bus(none) -> ok;
stop_bus(Pid) -> gen_event:stop(Pid).
