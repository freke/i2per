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

%% eunit's outer per-testcase bound for the wedged-subscribe case.
%%
%% **Generous on purpose, and for the same reason as above.** The case is waiting
%% for `f:subscribe/1` to answer, and an implementation that fails to bound its
%% wait will not answer at all -- so a tight bound here would report the very
%% failure under test as a timeout, which is the failure mode this file already
%% had to be repaired for once. The hang guards inside the case decide; this only
%% stops a true hang from taking the tier with it.
-define(WEDGED_TESTCASE_TIMEOUT_SECONDS, 30).

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

%%% %%%%% The published entry point %%%%% %%%
%%
%% #WGV1SZ7. The two production subscribers each knew three internal facts --
%% the registered name, the forwarder module, and that the argument is a pid --
%% and they disagreed about the first. `f:subscribe/1` and `f:unsubscribe/1` are
%% the published entry point that holds all three, so nothing outside the core
%% calls `gen_event:*` and replacing the manager becomes an internal refactor
%% rather than a contract break.

%% The wait is bounded. This is the property the entry point exists to have, and
%% it is the one #G61Y2QZ's mechanism does not supply.
%%
%% `gen_event:add_handler/3` is `rpc/2`, which is `gen:call(M, self(), Cmd,
%% infinity)` (`gen_event.erl:1576`) -- there is no timeout to pass and none to
%% choose. Measured against a manager wedged inside `handle_event/2`: all three
%% of `add_handler/3`, `delete_handler/3` and `stop/1` **blocked**, still running
%% at a 3 s deadline and never answering, while the same call against a healthy
%% manager answered `ok` in **273 µs**. So the wait is not slow, it has no end --
%% and `catch` does not rescue it, because there is no exit to catch.
%%
%% **The reach is the whole router, not the bus.** `m:i2per_sup` lists
%% `events_child()` first and `reachability_child()` fifth, so a bus wedged when
%% `m:i2p_ssu2_reachability:f:init/1` subscribes blocks the supervisor's own
%% `init/1` and the router never finishes booting.
%%
%% The case is a barrier, not a deadline: it waits for the reply, and a reply is
%% the only thing that can make it pass. An implementation that returned
%% `{error, wedged}` without ever having asked the bus would pass this and mean
%% nothing, so the healthy control below is what makes the wedge row evidence.
subscribe_returns_when_the_bus_is_wedged_test_() ->
    {timeout, ?WEDGED_TESTCASE_TIMEOUT_SECONDS, fun subscribe_returns_when_the_bus_is_wedged/0}.

subscribe_returns_when_the_bus_is_wedged() ->
    {ok, _} = application:ensure_all_started(i2per),
    Bus = whereis(i2p_events),
    Down = erlang:monitor(process, Bus),
    ok = gen_event:add_handler(Bus, i2p_test_wedged_handler, [self()]),
    %% Bound **before** the `try`, because a variable bound inside it is unsafe
    %% in the `after` that has to release it. `i2p_test_wedged_handler` announces
    %% its own pid from `init/1` for exactly this reason -- its module doc says
    %% so -- so the pid is available as soon as the handler is attached.
    Handler = await_wedged_added(Bus, Down),
    try
        %% The wedge, established as a barrier rather than assumed: adding a
        %% handler does not call it, so without an event the manager is healthy
        %% and this case would pass having proved nothing.
        ok = i2p_events:notify({leaseset_published, crypto:strong_rand_bytes(32)}),
        _Wedged = await_wedged(Bus, Down),
        %% The assertion. A wedged bus answers `wedged`, and answering is the
        %% whole property: the reply is what a caller could not get from
        %% `gen_event` on its own.
        ?assertEqual({error, wedged}, i2p_events:subscribe(self())),
        ?assertEqual({error, wedged}, i2p_events:unsubscribe(self()))
    after
        %% The monitor is dropped **first**, and it has to be. The bus is
        %% `permanent` and a later case in this tier stops the application --
        %% `f:absent_bus_is_answered_not_fatal_test/0` does, to reach the
        %% `no_bus` branch -- which would deliver this undemonitored
        %% `{'DOWN', _, process, Bus, shutdown}` into the shared worker's
        %% mailbox, where it would be read by whichever case drains next. That is
        %% precisely the leak class #SG93V0P is about, and the leak would appear
        %% in a module that never mentions the bus.
        erlang:demonitor(Down, [flush]),
        %% Released, then **removed** -- both, and in that order.
        %%
        %% Released rather than killed because `i2p_test_wedged_handler` blocks
        %% on a message precisely so a case can let it go; killing the bus would
        %% restart it with zero handlers, which is the documented cost of the heap
        %% bound and not something this case should pay on every run.
        %%
        %% Removed because releasing only lets the current `handle_event/2` return
        %% -- it leaves the handler attached, and the next event puts the bus right
        %% back in `handle_event/2`. A cleanup that notified anything to confirm the
        %% bus was healthy would therefore have re-wedged it.
        %%
        %% **This call is also the barrier that drains the bus.** The
        %% `subscribe/1` and `unsubscribe/1` abandoned at the bound are still
        %% queued ahead of it, and `gen_event` carries them out as it drains: the
        %% abandoned `subscribe` adds a forwarder for this collector. So the reply
        %% to this delete is the point at which both have been applied, and the
        %% unsubscribe after it removes the one that was.
        Handler ! release,
        ok = gen_event:delete_handler(Bus, i2p_test_wedged_handler, [self()]),
        ok = i2p_events:unsubscribe(self())
    end.

%% Wait for the wedged handler to attach, and return the pid the `after` clause
%% will release. Its `init/1` announces the pid before the handler can be entered,
%% so this is available before the wedge exists.
%%
%% **The `'DOWN'` clause is here so a bus that dies is reported as what it is** --
%% the heap bound firing on ordinary traffic -- rather than as a handler that
%% never attached, which would point the reader at the wrong thing.
await_wedged_added(Bus, Down) ->
    receive
        {wedged_handler, added, Pid} ->
            Pid;
        {'DOWN', Down, process, Bus, Reason} ->
            erlang:error({bus_died_before_wedging, Reason})
    after ?FLOOD_DEADLINE_MS ->
        erlang:error({handler_never_attached, Bus})
    end.

%% Wait until the wedged handler reports it has been entered, which is the proof
%% the manager is parked inside `handle_event/2`.
await_wedged(Bus, Down) ->
    receive
        {wedged_handler, entered, Pid} ->
            Pid;
        {'DOWN', Down, process, Bus, Reason} ->
            erlang:error({bus_died_before_wedging, Reason})
    after ?FLOOD_DEADLINE_MS ->
        erlang:error({handler_never_entered, Bus})
    end.

%% Subscribing twice delivers each event **once**.
%%
%% **Why this needs a case at all:** `gen_event` never dedups.
%% `server_add_handler` (`gen_event.erl:1819`) prepends to the handler list
%% unconditionally, and `gen_event:delete_handler/3` removes exactly one. So a
%% second `add_handler/3` is not a no-op, it is a second handler. Measured: two
%% forwarders, and one announced event arriving **twice**.
%%
%% That state is reachable rather than theoretical. `f:subscribe/1` gives up at
%% `?SUBSCRIBE_BOUND_MS`, and `gen_event` adds the handler *before* it replies --
%% so a subscribe abandoned at the bound is still carried out when the bus
%% drains. `m:i2per_status_state` resubscribes on every `{nodeup, RouterNode}`,
%% which is a path to arriving at the same bus twice.
%%
%% **And a duplicate is the worst shape of loss here, because it is invisible.**
%% Events are *counted*, not dropped: `m:i2per_status_state:f:bump/2` folds each
%% one it receives, so a doubled subscription makes every figure on the page read
%% 2x with nothing anywhere reporting an error. A dropped event is at least a
%% missing number.
%%
%% The sentinel is the barrier, and it is what makes this an assertion rather
%% than a deadline. `gen_event` delivers to its handlers in order, so every copy
%% of every earlier event is already in this mailbox by the time the sentinel
%% arrives. Counting up to it is exact -- no sleep, no tolerance, and no
%% dependence on how fast the bus happens to be.
%% Both refusals are answerable rather than fatal, and neither is a rare shape.
%%
%% **A bus that is not running** is the state a subscriber finds when it attaches
%% before the router is up -- and `m:i2per_status_state` is documented to expect
%% exactly that, since its whole purpose is to serve a router that may be absent.
%% **`unsubscribe/1` with nothing attached** is what every caller's shutdown path
%% does, and it cannot know whether it was ever subscribed. `f:unsubscribe/1`
%% collapses that to `ok`, so no caller has to handle a distinction it has no use
%% for.
%%
%% Both are asserted through the published entry point rather than through
%% `gen_event`, because the point is what a *subscriber* is told.
absent_bus_is_answered_not_fatal_test() ->
    %% Genuine absence requires stopping the app: the manager is the first sup
    %% child, so it is otherwise always up and `whereis/1` alone would not prove
    %% the branch was taken. Restore afterwards so the rest of the tier sees the
    %% router up again.
    _ = application:stop(i2per),
    try
        ?assertEqual(undefined, whereis(i2p_events)),
        ?assertEqual({error, no_bus}, i2p_events:subscribe(self())),
        ?assertEqual({error, no_bus}, i2p_events:unsubscribe(self()))
    after
        catch application:ensure_all_started(i2per)
    end.

%% Unsubscribing when nothing is attached is `ok`, not an error.
%%
%% **`gen_event:delete_handler/3` answers `{error, module_not_found}`** for this
%% (`gen_event.erl:1848`), which is a correct answer to a question the caller did
%% not ask. Passing it on would mean every shutdown path had to distinguish
%% "I was subscribed and have now detached" from "I was never subscribed", and
%% neither is actionable there -- so it is collapsed at the boundary.
unsubscribe_with_nothing_attached_is_ok_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    ?assertEqual(ok, i2p_events:unsubscribe(self())).

%% How many events to announce before the sentinel.
%%
%% **Three, and the number is the point rather than an arbitrary choice.** A
%% duplicated subscription delivers 6, so the assertion separates 3 from 6
%% outright -- no arithmetic near a boundary, and no tolerance to hide behind.
-define(ANNOUNCED, 3).

subscribe_twice_delivers_each_event_once_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    ?assertEqual(ok, i2p_events:subscribe(self())),
    ?assertEqual(ok, i2p_events:subscribe(self())),
    try
        ?assertEqual(?ANNOUNCED, announce_then_count(?ANNOUNCED))
    after
        ok = i2p_events:unsubscribe(self())
    end.

%% Announce `N` distinguishable events, then one sentinel, and report how many
%% arrived before the sentinel.
announce_then_count(N) ->
    [
        ok = i2p_events:notify({leaseset_published, crypto:strong_rand_bytes(32)})
     || _ <- lists:seq(1, N)
    ],
    ok = i2p_events:notify({config_changed, sentinel, reached}),
    count_until_sentinel(0).

count_until_sentinel(Seen) ->
    receive
        {event, {config_changed, sentinel, reached}} ->
            Seen;
        {event, _Earlier} ->
            count_until_sentinel(Seen + 1)
    after ?FLOOD_DEADLINE_MS ->
        erlang:error(sentinel_never_arrived)
    end.

%% The subscriber's whole capability: attach, and have events arrive.
%%
%% **`{event, _}` and not the bare event, and that is the contract being pinned
%% here.** `f:subscribe/1` attaches the router's shipped forwarder, which wraps
%% every event; the collector in `f:collector_test/0` above is a different
%% handler that forwards the bare event. A subscriber that reached for
%% `gen_event:add_handler/3` directly and installed its own handler would see the
%% unwrapped shape, so the wrapped one is what the published entry point owes
%% it -- and it is the shape a remote subscriber gets over distribution too.
subscribe_attaches_a_collector_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    ?assertEqual(ok, i2p_events:subscribe(self())),
    try
        Hash = crypto:strong_rand_bytes(32),
        ok = i2p_events:notify({leaseset_published, Hash}),
        ?assertEqual({event, {leaseset_published, Hash}}, collect())
    after
        ok = i2p_events:unsubscribe(self())
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
