-module(i2p_events_forward_tests).

-moduledoc """
Tests for the `m:i2p_events_forward` remote-subscriber forwarder: every bus
event arrives as `{event, Event}` at the collector pid, a forwarder whose
collector has died takes itself off the bus, and the remaining gen_event
callbacks behave sanely.

**The self-removal case is the one that is attached, not called.** It goes
through `gen_event:add_handler/3` against a real manager and reads the handler
list back, so it is a statement about the bus rather than about a function's
return value -- see `a_dead_collector_takes_its_forwarder_with_it_test/0` for why
that distinction is the whole point (#DN82Z7J).
""".

-include_lib("eunit/include/eunit.hrl").

%% How long to wait for the bus to notice a collector is gone. A hang guard, not
%% a synchronisation: what the case waits for is the handler list changing, which
%% is the assertion.
-define(GONE_MS, 5000).

forwarding_test() ->
    %% Standalone gen_event manager with the forwarder as its only handler.
    {ok, Mgr} = gen_event:start_link(),
    try
        ok = gen_event:add_handler(Mgr, i2p_events_forward, [self()]),
        ok = gen_event:notify(Mgr, {sample, 42}),
        receive
            {event, {sample, 42}} -> ok
        after 5000 -> erlang:error(event_not_forwarded)
        end,
        %% handle_call on the handler: the unsupported-query shape returns ok
        %% (OTP 28 gen_event:call takes the handler module as second arg).
        ?assertEqual(ok, gen_event:call(Mgr, i2p_events_forward, query)),
        %% handle_info: a stray message to the manager must not crash it.
        %% Prove survival event-driven (no fixed sleep): notify again after
        %% the stray message and await that event.
        Mgr ! stray_message,
        ok = gen_event:notify(Mgr, {sample, 43}),
        receive
            {event, {sample, 43}} -> ok
        after 5000 -> erlang:error(manager_died_after_stray_message)
        end,
        ?assert(is_process_alive(Mgr))
    after
        ok = gen_event:stop(Mgr)
    end.

%% %%%%% %%% The self-removal %%%%% %%%

%% A forwarder whose collector has died is not on the bus, and that is the whole
%% of #DN82Z7J: a dead pid is not an error to send to, so nothing used to raise,
%% `gen_event` removed a handler only for a delete, a stop or a crash, and the
%% bus accumulated one forwarder per subscriber restart for the life of the
%% router.
%%
%% **This case fails on the code it was written for.** Before the monitor, the
%% handler was still on the list here -- and the three lines after the assertion
%% are what made that a leak rather than a curiosity: the forwarder stayed
%% attached, so every subsequent announcement was dispatched to it, and the cost
%% was on the bus (measured 8,951 us for 20,000 announcements with one dead
%% forwarder attached, linear in the dead count).
%%
%% **Read through the handler list rather than through a message.** A test that
%% announced an event and waited for nothing to arrive would be waiting for an
%% absence, which is exactly as true of a forwarder that is attached to a pid
%% that happens to be quiet. `which_handlers/1` is the bus's own answer to "is
%% this still attached", and it is what the router's cost is paid on.
a_dead_collector_takes_its_forwarder_with_it_test() ->
    {ok, Mgr} = gen_event:start_link(),
    Collector = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ok = gen_event:add_handler(Mgr, {i2p_events_forward, Collector}, [Collector]),
    %% The handler is really there first, so a case that could not see the
    %% removal at all is reported as "the removal was never observable" rather
    %% than as a pass.
    ?assertEqual(1, length(gen_event:which_handlers(Mgr))),
    exit(Collector, kill),
    ok = await_gone(Mgr),
    ?assertEqual([], gen_event:which_handlers(Mgr)),
    %% And the bus is unharmed by it: a handler removing itself is not a handler
    %% crashing, so the manager has to still be dispatching afterwards.
    ok = gen_event:notify(Mgr, {sample, after_the_death}),
    ?assert(is_process_alive(Mgr)),
    ok = gen_event:stop(Mgr).

%% Five subscribers that attach and die, against one manager. The shape the leak
%% actually took: a status service restarting on its own node, over and over.
%%
%% **Counted, not asserted non-empty.** On the old code this read 5; on the fixed
%% code it reads 0. A case that only subscribed once would catch a forwarder that
%% fails to remove itself, and would *not* catch one that removes the first and
%% leaves the rest -- which is the shape a loop over a registry would take.
repeated_deaths_do_not_accumulate_test() ->
    {ok, Mgr} = gen_event:start_link(),
    try
        [attach_and_kill(Mgr) || _ <- lists:seq(1, 5)],
        ok = await_gone(Mgr),
        ?assertEqual([], gen_event:which_handlers(Mgr))
    after
        ok = gen_event:stop(Mgr)
    end.

%% A forwarder must not take itself off on *another* collector's death.
%%
%% **`gen_event` hands every unrecognised message to every handler**
%% (`gen_event:handle_msg/3`, `gen_event.erl:1690-1692`), so the DOWN for
%% collector B arrives at the handler carrying collector A as faithfully as its
%% own. A handler that matched on the monitor alone -- or on the message shape
%% alone -- would delete itself on the first neighbour to die, and a bus that
%% silently drops live subscribers under load is worse than the leak it replaced.
one_collectors_death_does_not_take_another_with_it_test() ->
    {ok, Mgr} = gen_event:start_link(),
    Doomed = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    %% **The survivor is the test process**, because the half of this claim a
    %% handler list cannot see is that the survivor still *receives* -- and a
    %% forwarder carrying to a collector that quietly discards what it is sent
    %% would make the assertion unobservable rather than true. It also means this
    %% case's own mailbox is the far side, so a collector p id is not needed.
    Survivor = self(),
    ok = gen_event:add_handler(Mgr, {i2p_events_forward, Doomed}, [Doomed]),
    ok = gen_event:add_handler(Mgr, {i2p_events_forward, Survivor}, [Survivor]),
    exit(Doomed, kill),
    ok = await_handlers(Mgr, [{i2p_events_forward, Survivor}]),
    ok = gen_event:notify(Mgr, {sample, still_here}),
    receive
        {event, {sample, still_here}} -> ok
    after 5000 -> erlang:error(surviving_forwarder_went_silent)
    end,
    ok = gen_event:stop(Mgr).

%% Subscribing to a pid that is already dead is not a special case: the monitor
%% is installed, the DOWN is delivered at once, and the handler takes itself off
%% before it has carried an event.
%%
%% **This is the window a restart actually lands in**, and it is why the
%% subscription is not refused at `add_handler/3` time -- refusing it would mean
%% deciding what a refusal means for a caller that only wants an answer.
a_collector_that_died_before_the_subscribe_is_not_carried_test() ->
    {ok, Mgr} = gen_event:start_link(),
    Collector = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    exit(Collector, kill),
    ok = gen_event:add_handler(Mgr, {i2p_events_forward, Collector}, [Collector]),
    ok = await_gone(Mgr),
    ?assertEqual([], gen_event:which_handlers(Mgr)),
    ok = gen_event:stop(Mgr).

attach_and_kill(Mgr) ->
    Collector = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ok = gen_event:add_handler(Mgr, {i2p_events_forward, Collector}, [Collector]),
    exit(Collector, kill),
    ok.

%% Wait until the manager holds exactly `Expected`.
%%
%% **A barrier, not a deadline.** The removal is asynchronous -- the DOWN is a
%% message the manager has to pick up -- so the case has to wait for the state
%% that is being asserted rather than sleep long enough to probably have got it.
%% `f:await/2` is the tree's own spelling of that, and a bus that never notices
%% fails here rather than passing.
%%
%% **Written against a whole handler list rather than a count**, because "the
%% doomed one is gone" and "nothing is left" are different claims and only the
%% second one holds for most of these cases. `one_collectors_death...` needs the
%% survivor *named*, which is the half of it that would catch a handler matching a
%% DOWN that was not its own.
await_handlers(Mgr, Expected) ->
    ok = i2p_ct_helpers:await(
        fun() -> gen_event:which_handlers(Mgr) =:= Expected end, ?GONE_MS
    ).

await_gone(Mgr) ->
    await_handlers(Mgr, []).

callbacks_test() ->
    %% init, code_change and terminate exercised directly against the *current*
    %% state shape. This case says the callbacks do not raise and that the state
    %% carries the collector and its monitor; it deliberately does **not** claim
    %% the callbacks are reached, because calling a function directly passes
    %% whether or not anything calls it -- which is how #N722YKK's six dead
    %% callbacks in `m:i2p_events` came to read as covered. What is reached is
    %% asserted above, attached, through the bus.
    {ok, State} = i2p_events_forward:init([self()]),
    ?assertMatch({_, MRef} when is_reference(MRef), State),
    ?assertEqual(self(), element(1, State)),
    ?assertEqual({ok, State}, i2p_events_forward:code_change(0, State, [])),
    ?assertEqual(ok, i2p_events_forward:terminate(any, State)).
