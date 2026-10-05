-module(i2p_events_tests).

-moduledoc """
Tests for the `m:i2p_events` bus: manager lifecycle under the real router
application, end-to-end delivery into a subscriber handler, and the bound on the
manager's heap.

The emit sites themselves (tunnel builds, LeaseSet publication, SAM session
lifecycle) are exercised implicitly by every tunnel/SAM e2e suite — a bad
notification there would crash those processes and fail those suites.
""".

-include_lib("eunit/include/eunit.hrl").

%% How long a flood waits for the bound to fire, and for the handler to report
%% itself entered. A hang guard, not a synchronisation: the barriers are the
%% received messages and the `'DOWN'`, which the runtime orders.
-define(FLOOD_DEADLINE_MS, 30000).

%% eunit's per-testcase timeout for the flood case, which is what cancelled it
%% first at the default 5s while the case was still legitimately waiting.
%%
%% **Loose on purpose, and the reason is a test defect rather than a slow
%% machine.** The case queues ~240,000 events and waits on real barriers; eunit's
%% default fired mid-wait, which reports as a failure of the property when it is a
%% failure of the clock. The hang guards above are what actually decide, so this is
%% only the outer bound -- tight enough to stop a true hang, loose enough not to
%% reintroduce the flake it replaced.
-define(FLOOD_TESTCASE_TIMEOUT_SECONDS, 120).

%% Collecting gen_event handler: forwards every event to the test process.
collector_test() ->
    %% The assertion below matches the exact event this test sends. Other
    %% eunit tests must not leave stray messages in the shared worker's
    %% mailbox, or this partition would see them first.
    {ok, _} = application:ensure_all_started(i2per),
    ?assert(is_pid(whereis(i2p_events))),
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
    try
        Hash = crypto:strong_rand_bytes(32),
        ok = i2p_events:notify({leaseset_published, Hash}),
        ?assertEqual({leaseset_published, Hash}, collect())
    after
        gen_event:delete_handler(i2p_events, i2p_events_tests_collector, [])
    end.

notify_without_manager_test() ->
    %% Best-effort contract: notify/1 returns ok even when the manager is
    %% absent. Genuine absence requires stopping the app (the manager is the
    %% first sup child and normally up), so stop it, hit the fallthrough, then
    %% restore so the rest of the run sees the router up again.
    _ = application:stop(i2per),
    try
        ?assertEqual(undefined, whereis(i2p_events)),
        ?assertEqual(ok, i2p_events:notify({config_changed, transit_max_tunnels, 5}))
    after
        catch application:ensure_all_started(i2per)
    end.

manager_callbacks_test() ->
    %% The manager ships with no built-in handlers, so its own gen_event
    %% callbacks are never reached through the live bus (events fan out to
    %% subscriber handlers). The callbacks are still part of the behaviour
    %% surface and exported; exercise them directly.
    ?assertEqual({ok, []}, i2p_events:init([])),
    ?assertEqual({ok, []}, i2p_events:handle_event(some_event, [])),
    ?assertEqual({ok, {error, unsupported}, []}, i2p_events:handle_call(query, [])),
    ?assertEqual({ok, []}, i2p_events:handle_info(irrelevant, [])),
    ?assertEqual(ok, i2p_events:terminate(any, [])),
    ?assertEqual({ok, []}, i2p_events:code_change(0, [], [])).

%%% %%%%% The bound on the manager's heap %%%%% %%%

%% The bound is in force on the running bus, not merely present in the source.
%%
%% **This case exists because the obvious implementation is inert.** `max_heap_size`
%% in `m:i2per_sup`'s child spec is silently ignored at OTP 28.5 / stdlib 7.3.0.2:
%% the manager reported `#{size => 0}` and survived a 93,609,153-word heap. A case
%% that only read the constant would stay green through that. Asserting on the
%% live process's own `max_heap_size` is what distinguishes "the option reached
%% the manager" from "a number is written down somewhere".
manager_reports_its_bound_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    {max_heap_size, #{size := Size}} = process_info(whereis(i2p_events), max_heap_size),
    ?assertEqual(i2p_events:max_heap_words(), Size).

%% A backlog past the bound **kills** the bus rather than letting it keep growing.
%%
%% **The GC is forced, and that is the honest shape of the property.** A case that
%% just queued events and waited for a `'DOWN'` failed, and the reason is the
%% finding this ticket turned on: `max_heap_size` is evaluated **at garbage
%% collection**, and a manager parked inside `handle_event/2` performs none —
%% measured, `minor_gcs` delta **0** while the mailbox grew to 14,400,089 words
%% (1.2M messages) under a 300,000-word bound, still alive. So a wedged bus does
%% not hit the bound by itself.
%%
%% The bound is still load-bearing, and this is where it bites: the moment the
%% manager does collect, the backlog is fatal. `erlang:garbage_collect/1` is the
%% BIF that makes that happen, so the case asserts the mechanism rather than
%% asserting a coincidence of scheduler timing — which is what the unwaited
%% version was doing, and why it was a flake waiting to be born.
%%
%% **The wedge is asserted, not assumed.** A backlog only accumulates because the
%% manager is not reading its mailbox, so the case proves the manager is inside
%% `handle_event/2` before flooding; otherwise it would pass for the wrong reason.
bus_past_the_bound_is_killed_rather_than_left_growing_test_() ->
    {timeout, ?FLOOD_TESTCASE_TIMEOUT_SECONDS, fun bus_past_the_bound_is_killed/0}.

bus_past_the_bound_is_killed() ->
    {ok, _} = application:ensure_all_started(i2per),
    Bus = whereis(i2p_events),
    ok = gen_event:add_handler(i2p_events, i2p_test_wedged_handler, [self()]),
    try
        Down = erlang:monitor(process, Bus),
        %% One announce drives the manager into `handle_event/2`, which is what
        %% wedges it. Adding a handler does not call it -- `gen_event` only runs
        %% `f:init/1` at add time -- so without this event the manager is healthy,
        %% drains the flood as it arrives, and the case would pass having proved
        %% nothing about a backlog.
        ok = i2p_events:notify({leaseset_published, crypto:strong_rand_bytes(32)}),
        _Handler = await_handler(Bus, Down),
        Flooders = flood_past_the_bound(),
        try
            ok = backlogged_past_the_bound(Bus),
            %% The one line that makes the bound decisive: the manager collects, so
            %% the bound is evaluated, so the backlog is fatal.
            true = erlang:garbage_collect(Bus),
            receive
                {'DOWN', Down, process, Bus, Reason} ->
                    ?assertEqual(killed, Reason)
            after ?FLOOD_DEADLINE_MS ->
                erlang:error(bus_survived_a_collected_backlog)
            end
        after
            erlang:demonitor(Down, [flush]),
            [catch exit(P, kill) || P <- Flooders]
        end
    after
        ensure_bus_back()
    end.

%% Queue far past the bound and report the manager's own view of the damage.
%%
%% **Asserted rather than assumed, because the flood is asynchronous.** The
%% producers are spawned and this returns the moment they are running, not the
%% moment the last message has landed, so a case that trusted that moment would be
%% asserting on a partially-queued mailbox — the same unsoundness as asserting on
%% an incomplete call list. `f:backlogged_past_the_bound/1` is the barrier.
backlogged_past_the_bound(Bus) ->
    i2p_ct_helpers:await(
        fun() -> element(2, process_info(Bus, message_queue_len)) > queued_events_needed() end,
        ?FLOOD_DEADLINE_MS
    ).

%% How many queued events put the manager past `f:max_heap_words/0`.
%%
%% From the measured cost of one queued event -- ~12.33 words, see
%% `m:i2p_events` -- the bound is crossed at roughly 24,000. Rounded up to 30,000
%% so the assertion is about the backlog being real rather than about arithmetic
%% landing on exactly the boundary.
queued_events_needed() ->
    30000.

%% The flood: eight producers, well past `f:queued_events_needed/0`. `notify/1` is a
%% cast, so a producer never blocks and all of them finish regardless.
flood_past_the_bound() ->
    Hashes = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 8)],
    [
        spawn(fun() -> [i2p_events:notify({leaseset_published, H}) || _ <- lists:seq(1, 30000)] end)
     || H <- Hashes
    ].

%% Wait until the handler reports it has been entered, which is the proof the
%% manager is parked inside `handle_event/2`.
%%
%% **The `'DOWN'` clause is here so a bus that dies before the wedge is reported
%% as what it is** — a bound that fired on ordinary traffic — rather than as a
%% handler that never arrived, which would send a reader looking at the wrong thing.
await_handler(Bus, Down) ->
    receive
        {wedged_handler, entered, Pid} ->
            Pid;
        {wedged_handler, added, _Pid} ->
            await_handler(Bus, Down);
        {'DOWN', Down, process, Bus, Reason} ->
            erlang:error({bus_died_before_wedging, Reason})
    after ?FLOOD_DEADLINE_MS ->
        erlang:error({handler_never_entered, Bus})
    end.

%% The bus is `permanent`, so the supervisor restarts it — but with zero handlers,
%% and nothing re-attaches. That silent detach is the documented cost of the bound,
%% so the rest of the eunit tier gets a working bus back rather than a frozen one.
ensure_bus_back() ->
    case whereis(i2p_events) of
        undefined ->
            _ = application:stop(i2per),
            {ok, _} = application:ensure_all_started(i2per);
        _ ->
            ok
    end.

%%% %%%%% Internal helpers %%%%% %%%

collect() ->
    %% The event fans out over the i2p_events gen_event bus asynchronously; a
    %% fixed window races the scheduler. Drain non-matching messages (incl.
    %% boot-time normal exits) and wait on a deadline instead.
    i2p_ct_helpers:wait_msg(
        fun(Ev) ->
            case Ev of
                {'EXIT', _, _} -> false;
                Event -> {true, Event}
            end
        end,
        5000
    ).
