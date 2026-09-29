%% Shared Common Test support helpers for the i2per suites:
%%
%% - a per-test-case data directory, isolated under the CT priv dir;
%% - an ephemeral port reservation for suites that bind their own listeners;
%% - an event-driven wait/poll that never sleeps a fixed total — each test that
%%   needs a condition to become true polls with a backoff until a deadline,
%%   and a receive wrapper skips (drains) non-matching messages, so a leftover
%%   message from a previous case cannot poison a later assertion;
%% - signed RouterInfo fixtures, so a suite that needs routers in the NetDb
%%   builds them here instead of keeping its own copy of the keygen.
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
    events_from/1,
    log_events_from/1,
    project_root/0,
    log_lines_from/1,
    render_log_event/1,
    floodfill_router_info/2,
    db_store_block/3,
    dead_pid/0,
    start_ssu2_trace/0,
    stop_ssu2_trace/0,
    dump_ssu2_trace/0
]).

-define(SSU2_TRACE_MAX, 512).

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
db_store_block(0, Key, RI) when is_map(RI) ->
    db_store_block(0, Key, i2p_i2np:router_info_data(i2p_router_info:to_binary(RI)));
db_store_block(Type, Key, Data) when is_binary(Data) ->
    #{body := Body} = i2p_i2np:db_store(Key, Type, 0, undefined, Data),
    {i2np, 1, 7, 0, Body}.

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
            ct:pal("ssu2 trace (~p events):~n~0p", [length(Buffer), Buffer])
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
            ct:pal("ssu2 trace (~p events):~n~0p", [length(Buffer), Buffer])
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
%% SSU2 on-wire trace collector
%%
%% Register a collector under `i2p_ssu2_trace_sink`; the SSU2 session,
%% listener and PeerTest coordinator emit to it whenever it is registered.
%% The collector keeps the last ?SSU2_TRACE_MAX events and can hand them
%% back on demand. Used by the peertest suite's init_per_suite/end_per_suite
%% and dumped from wait_msg_timeout so a stalled test carries its own trace.

start_ssu2_trace() ->
    case whereis(i2p_ssu2_trace_sink) of
        Collector when is_pid(Collector) ->
            Collector;
        _NotRegistered ->
            Collector = spawn(fun() -> ssu2_trace_collector([]) end),
            true = register(i2p_ssu2_trace_sink, Collector),
            Collector
    end.

stop_ssu2_trace() ->
    Buffer = dump_ssu2_trace(),
    case Buffer of
        [] ->
            ok;
        _ ->
            ct:pal("ssu2 trace (final, ~p events):~n~0p", [length(Buffer), Buffer])
    end,
    i2p_ssu2_trace:disable().

dump_ssu2_trace() ->
    case i2p_ssu2_trace:sink() of
        Collector when is_pid(Collector) ->
            Collector ! {ssu2_trace_dump, self()},
            receive
                {ssu2_trace_dump_result, Buffer} -> Buffer
            after 1000 ->
                []
            end;
        _ ->
            []
    end.

ssu2_trace_collector(Events) ->
    receive
        {ssu2_trace, MonotonicMs, Pid, Label, Details} ->
            Event = {MonotonicMs, Pid, Label, Details},
            ssu2_trace_collector(lists:sublist([Event | Events], ?SSU2_TRACE_MAX));
        {ssu2_trace_dump, From} ->
            From ! {ssu2_trace_dump_result, lists:reverse(Events)},
            ssu2_trace_collector(Events);
        stop ->
            ok
    end.

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
