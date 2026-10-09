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
%% a death, rather than as a handler that never attached, which would point the
%% reader at the wrong thing.
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
    %% **None of these are reached by a live bus**, and the module says why: the
    %% manager is `f:gen_event`'s own module, because no `f:gen_event:start_link/2`
    %% form both registers the name and names a callback module. Exercised directly
    %% all the same -- they are exported and documented, and a reader comparing them
    %% with `f:gen_event`'s defaults should find them spelled out somewhere.
    %%
    %% What this case deliberately does **not** assert is that the manager calls them.
    %% It did once, in a comment that gave the wrong reason, and a case that calls a
    %% function directly passes either way -- which is how six dead callbacks read as
    %% tested for as long as they did.
    ?assertEqual({ok, []}, i2p_events:init([])),
    ?assertEqual({ok, []}, i2p_events:handle_event(some_event, [])),
    ?assertEqual({ok, {error, unsupported}, []}, i2p_events:handle_call(query, [])),
    ?assertEqual({ok, []}, i2p_events:handle_info(irrelevant, [])),
    ?assertEqual(ok, i2p_events:terminate(any, [])),
    ?assertEqual({ok, []}, i2p_events:code_change(0, [], [])).

%% The registry exists, and it exists because the sampler owns it.
%%
%% **This case exists because it very nearly did not, twice.** The manager cannot own
%% the table -- `f:init/1` never runs, see the module note -- so the sampler does, and
%% the first version of that used `ets:new(Name, Opts)` without `named_table`, which
%% on OTP 28 creates a table whose \`ets:info(Name, _)\` is \`undefined\`. The registry
%% was then permanently empty and every case below passed against it for the wrong
%% reason.
%%
%% So this asserts the table is reachable **by name**, which is the property both bugs
%% broke and the only one the rest of the module depends on, and then that a
%% subscription lands in it.
the_registry_is_reachable_by_name_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    ?assertNotEqual(undefined, ets:info(i2p_events_subscribers, name)),
    Collector = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ok = i2p_events:subscribe(Collector),
    try
        ?assert(lists:member(Collector, i2p_events:subscribers()))
    after
        ok = i2p_events:unsubscribe(Collector)
    end.

%% One sampler, not one per bus start.
%%
%% **The failure it guards against is real and pre-dates the registry.** The sampler
%% used to be a `spawn_link` from `f:start_link/0`, which runs in the *supervisor* --
%% so it survived every bus restart, and `f:start_link/0` also ran again on each
%% restart and started a second one. Two loops wrote the same \`persistent_term\` gauge
%% every 5s, one of them publishing a depth for a manager pid that no longer existed.
%% The registry made it worse rather than better: two samplers cannot own one named
%% table, so the second \`ets:new\` would have failed the bus start.
one_sampler_survives_a_bus_restart_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    Bus = whereis(i2p_events),
    First = whereis(i2p_events_sampler),
    ?assertNotEqual(undefined, First),
    %% Restart the bus the way the supervisor does. Killed from a throwaway process
    %% because `exit/2` from the test process would take the test with it.
    _ = spawn(fun() -> exit(Bus, kill) end),
    %% The predicate asks for a *different* bus pid: `is_process_alive` on the old one
    %% can never become true again, which is a test that would time out rather than
    %% fail.
    ok = i2p_ct_helpers:await(
        fun() ->
            Current = whereis(i2p_events),
            Current =/= undefined andalso
                Current =/= Bus andalso
                is_process_alive(Current) andalso
                whereis(i2p_events_sampler) =/= undefined andalso
                whereis(i2p_events_sampler) =/= First
        end,
        ?FLOOD_DEADLINE_MS
    ),
    %% One sampler, and it is the new one -- a second would have taken the name.
    ?assert(is_process_alive(whereis(i2p_events_sampler))),
    %% And the registry came back with the bus rather than carrying stale rows across
    %% a restart that detached every subscriber.
    ?assertEqual([], i2p_events:subscribers()).

%%% %%%%% The backlog gauge %%%%% %%%

%% The manager carries no heap bound, and that is asserted rather than left to the
%% source.
%%
%% **A case that only read the source would have caught the removal but not the
%% reason for it.** The bound was removed because measurement showed it could not
%% fire for the case it was adopted for (a wedged handler never collects, so
%% `max_heap_size` is never evaluated) and did fire on ordinary load instead (two
%% producers killed a healthy manager at a queue depth of 487). `m:i2p_events`
%% carries both measurements. What this case pins is the shape the removal leaves
%% behind: no limit, and a gauge that reports the backlog instead.
manager_carries_no_heap_bound_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    {max_heap_size, Limit} = process_info(whereis(i2p_events), max_heap_size),
    %% `#{size := 0}` is how the runtime reports "no limit", and it is the same
    %% value a child-spec key that was silently ignored produced -- so this
    %% distinguishes "no bound by decision" from "no bound by accident", which
    %% are the two states that look identical from the source.
    ?assertEqual(0, maps:get(size, Limit, 0)).

%% The backlog gauge reports the manager's queue depth, and reports it while the
%% manager is wedged.
%%
%% **The wedge is asserted, not assumed.** Without it this case would pass against a
%% perfectly healthy bus reading 0, which is the same answer for the wrong reason --
%% so the handler is entered and the queue is grown past the threshold before the
%% reading is taken.
%%
%% **This is the property the bound could not provide, and it is what makes the
%% removal safe.** Every `f:gen_event` call is an rpc to the manager, so the
%% management API is unavailable exactly when an operator needs a reading --
%% `gen_event:which_handlers/1` and `gen_event:sync_notify/2` were both measured not
%% answering after 1500ms against a manager parked in `handle_event/2`.
%% `process_info/2` is a different kind of call: measured answering in **0us** at
%% every sample while the depth grew past 2.8 million. The gauge is built on the call
%% that survives the fault, which is the whole reason it can report one.
backlog_gauge_reports_a_wedged_manager_test_() ->
    {timeout, ?FLOOD_TESTCASE_TIMEOUT_SECONDS, fun backlog_gauge_reports_a_wedged_manager/0}.

backlog_gauge_reports_a_wedged_manager() ->
    {ok, _} = application:ensure_all_started(i2per),
    Bus = whereis(i2p_events),
    Down = erlang:monitor(process, Bus),
    ok = gen_event:add_handler(Bus, i2p_test_wedged_handler, [self()]),
    %% **The handler's pid is stashed in the process dictionary rather than bound
    %% to a variable, because it has to survive into the `after` clause.** Erlang
    %% cannot rebind across `try`, and a variable bound inside the body is not
    %% visible to the `after`. The dictionary is the one mutable thing a test
    %% process has, and this is what it is for.
    put(wedged_handler, undefined),
    try
        %% One announce drives the manager into `handle_event/2`, which is what
        %% wedges it. Adding a handler does not call it.
        ok = i2p_events:notify({leaseset_published, crypto:strong_rand_bytes(32)}),
        put(wedged_handler, await_wedged(Bus, Down)),
        _Flooders = [spawn(fun() -> flood_announcements(20000) end) || _ <- lists:seq(1, 4)],
        ok = await_backlogged(Bus, ?FLOOD_DEADLINE_MS),
        %% The reading the operator would get. Taken through the public entry point
        %% rather than by reading the queue directly, because the gauge is what the
        %% read API carries and the two could disagree.
        Depth = i2p_events:sample_backlog(),
        ?assert(Depth > queued_events_needed()),
        ?assertEqual(Depth, maps:get(bus_backlog, i2p_stats:gauges())),
        %% And it is carried in the read API under `gauges`, beside the counters
        %% rather than inside them. `view/0` itself is not called here: it reaches
        %% `m:i2p_tunnel_srv` through a `gen_server:call`, which this module does not
        %% start, and the wedge under test is exactly the condition under which a
        %% caller must not be made to wait on the bus. `m:i2p_read_api_SUITE` asserts
        %% `view/0`'s keys against `view_keys/0` on a whole router, and this asserts
        %% the gauge the read API would carry.
        ?assert(lists:member(gauges, i2p_status_data:view_keys()))
    after
        %% **Release the handler, or the bus stays wedged for the rest of the tier.**
        %% The eunit tier runs every module in one shared worker, so a manager left
        %% parked in `handle_event/2` makes every later `f:gen_event` call in *any*
        %% module hang -- which is how a defect in this case's cleanup showed up as a
        %% timeout in `m:i2p_log_tests`, a module that never mentions the bus.
        erase(wedged_handler),
        discard_wedged_bus(Bus, Down),
        ensure_bus_back()
    end.

%% Kill a wedged bus and wait for it to actually be gone.
%%
%% **Killing rather than releasing, and the released handler is why.** Releasing lets
%% the handler return -- and it is *still attached*, so the next queued event wedges
%% it again. The flood behind it is what remains, so the manager re-wedges before it
%% ever reaches the queue's end and the bus never drains. A case that waited for a
%% drain that cannot happen was a 40s timeout pretending to be a cleanup step.
%%
%% `f:ensure_bus_back/0` then restarts it, which is also the honest outcome: the
%% bus has been wedged on purpose, and a fresh one comes back with no handlers -- the
%% same silent detach the removed heap bound used to cause. Waiting on the `'DOWN'`
%% is what makes this deterministic rather than a race with the next case.
discard_wedged_bus(Bus, Down) ->
    exit(Bus, kill),
    receive
        {'DOWN', Down, process, Bus, killed} ->
            ok;
        {'DOWN', Down, process, Bus, Reason} ->
            erlang:error({bus_died_with_an_unexpected_reason, Reason})
    after ?FLOOD_DEADLINE_MS ->
        erlang:error(bus_survived_being_killed)
    end.

%% Announce `N` events.
%%
%% **`catch` is not defensive coding here, it is the expected outcome.** The manager
%% is wedged, so `f:gen_event:notify/2` is a cast to a live process and does not
%% raise; the `catch` covers the window in which it dies under us and the name is
%% gone. A producer that outlived the bus would otherwise crash and take the case's
%% own error report with it.
flood_announcements(N) ->
    Hash = crypto:strong_rand_bytes(32),
    _ =
        catch [
            catch i2p_events:notify({leaseset_published, Hash})
         || _ <- lists:seq(1, N)
        ],
    ok.

%% Wait until the manager's queue is deeper than `queued_events_needed/0`.
%%
%% **A barrier, not a deadline.** `f:i2p_ct_helpers:await/2` polls a state predicate
%% until a bound, which the standing preference treats as a barrier in disguise, so
%% this is one: the assertion is about a depth that exists, and the depth is the
%% evidence rather than a sleep that hopes it arrived.
await_backlogged(Bus, Deadline) ->
    i2p_ct_helpers:await(
        fun() -> depth_of(Bus) > queued_events_needed() end,
        Deadline
    ).

depth_of(Bus) ->
    element(2, process_info(Bus, message_queue_len)).

%% How deep the queue has to be for the reading to be evidence rather than noise.
%%
%% Rounded up from the measured ~12.33 words per queued event so the assertion is
%% about the backlog being real rather than about arithmetic landing on a boundary.
queued_events_needed() ->
    30000.

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

%% %%%%% %%% The far-side reading %%%%% %%%

%% With nobody on another node there is nothing to be far of, and the reading is `0`.
%%
%% **No ambient subscriber is assumed, and that is a correction rather than caution.**
%% An earlier version asserted the registry was non-empty here, on the reasoning that
%% `m:i2p_ssu2_reachability` subscribes in its `init/1`. It does -- but the
%% wedged-manager case above kills the bus, and a restarted manager comes back with
%% zero handlers and nothing re-attaches (#G61Y2QZ). So by the time this case runs the
%% registry is legitimately empty, and the assertion was asserting an accident of
%% ordering.
%%
%% What replaces it is the premise the reading actually rests on, checked directly:
%% every subscriber the tier can have is on this node, because the eunit node is
%% `nonode@nohost` and nothing here attaches across a boundary.
no_remote_subscriber_means_a_depth_of_zero_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    ?assert(lists:all(fun(P) -> node(P) =:= node() end, i2p_events:subscribers())),
    ?assertEqual(0, i2p_events:sample_far_backlog()).

%% A local subscriber is registered and then skipped. The two halves are the claim:
%% a local collector's queue grows the *router's own* memory, which is a different
%% fault with a different fix, and folding it into a reading named for the far side
%% would change what the number means.
a_local_subscriber_is_registered_but_not_measured_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    Collector = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ok = i2p_events:subscribe(Collector),
    try
        ?assert(lists:member(Collector, i2p_events:subscribers())),
        ?assertEqual(0, i2p_events:sample_far_backlog())
    after
        ok = i2p_events:unsubscribe(Collector)
    end.

%% The registry is written where the handler is added and removed, so it cannot
%% drift from what the bus is actually carrying. Asserted through the published
%% entry points rather than by reaching into the table: the far-side sweep only ever
%% finds a collector because `f:subscribe/1` put it there, so a registry that
%% drifted from what subscribing does would leave the sweep measuring nothing.
subscribe_registers_and_unsubscribe_forgets_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    Collector = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ?assertNot(lists:member(Collector, i2p_events:subscribers())),
    ok = i2p_events:subscribe(Collector),
    ?assert(lists:member(Collector, i2p_events:subscribers())),
    ok = i2p_events:unsubscribe(Collector),
    ?assertNot(lists:member(Collector, i2p_events:subscribers())).

%% Subscribing twice is one row, not two. A `set` makes that true by construction
%% and the case says so, because a duplicate would have the sweep ask about the same
%% pid twice and the registry would then be a list of subscriptions rather than of
%% subscribers.
subscribe_twice_registers_one_subscriber_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    Collector = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ok = i2p_events:subscribe(Collector),
    ok = i2p_events:subscribe(Collector),
    try
        ?assertEqual(1, count_registered(Collector))
    after
        ok = i2p_events:unsubscribe(Collector)
    end.

%% The reading is offered, never pushed. `m:i2p_stats` is an observer of the core and
%% not part of it, so nothing in this module may hand it a figure on a timer -- and
%% with no collector asking, the far-side reading costs the router nothing at all.
%%
%% The near side is asserted to be *absent* rather than zero: `m:i2p_stats:gauges/0`
%% reports a gauge it has never seen as absent, which is the distinction from
%% "measured, and zero", so a `bus_far_backlog` key appearing at all would mean the
%% core had started pushing.
far_backlog_is_offered_and_not_pushed_test() ->
    {ok, _} = application:ensure_all_started(i2per),
    Near = i2p_events:sample_backlog(),
    ?assertEqual(0, i2p_events:sample_far_backlog()),
    Gauges = i2p_stats:gauges(),
    ?assertEqual(Near, maps:get(bus_backlog, Gauges)),
    ?assertNot(maps:is_key(bus_far_backlog, Gauges)),
    %% And the key the read API would carry is the same one the near side uses.
    ?assert(lists:member(gauges, i2p_status_data:view_keys())).

count_registered(Collector) ->
    length([P || P <- i2p_events:subscribers(), P =:= Collector]).

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
