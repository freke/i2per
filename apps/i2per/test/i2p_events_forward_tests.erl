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
