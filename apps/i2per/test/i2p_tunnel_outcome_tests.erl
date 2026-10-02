-module(i2p_tunnel_outcome_tests).

-moduledoc """
Tests for the tunnel lifecycle tally, and for the coupling that makes it
trustworthy.

The interesting property is not arithmetic. It is that the counter and the bus
event cannot disagree, which is why every announcement goes through this module
rather than through the bus directly. A second, hand-maintained tally beside
six call sites would be free to drift and silent when it did, and the drift would
be invisible in the read API — the figure would simply be wrong.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%% The registry and the derivation must agree %%%%% %%%

%% The direction from the event to the counter it charges has exactly one
%% definition, and the registry of what exists has another. They are tied
%% together here in both directions: a mapping without a registered counter would
%% raise on a production send, and a registered counter without a mapping would
%% never move. Both are failures this catches before a tunnel is built.
registry_covers_every_derived_name_test() ->
    Derived = i2p_tunnel_outcome:counter_names(),
    Registered = i2p_stats:counters(),
    Missing = Derived -- Registered,
    ?assertEqual([], Missing).

%% And the reverse, restricted to the prefix this module owns. A `tunnels_*`
%% counter in the registry that nothing can charge is a dead counter: it would
%% appear in the read API as a permanent zero, which a consumer cannot tell from
%% "measured, and zero".
registry_has_no_unchargeable_tunnel_counter_test() ->
    Tunnels = [N || N <- i2p_stats:counters(), is_atom(N), tunnel_name(N)],
    ?assertEqual(lists:sort(i2p_tunnel_outcome:counter_names()), lists:sort(Tunnels)).

tunnel_name(Name) ->
    lists:prefix("tunnels_", atom_to_list(Name)).

%% Every event in the outcome vocabulary maps to a counter, and each counter
%% corresponds to exactly one event. Together with the two tests above this makes
%% the mapping and the registry a closed set: nothing can be counted that has no
%% counter, and nothing can be registered that nothing counts.
outcome_vocabulary_and_counters_are_in_bijection_test() ->
    Events = all_events(),
    Names = [i2p_tunnel_outcome:counter_name(E) || E <- Events],
    ?assertEqual(length(Events), length(lists:usort(Events))),
    ?assertEqual(length(Names), length(lists:usort(Names))),
    ?assertEqual(lists:sort(Names), i2p_tunnel_outcome:counter_names()).

%% %%%%% %%% Announcing and counting are one act %%%%% %%%

built_charges_and_announces_test() ->
    with_bus_and_counters(fun() ->
        Before = i2p_stats:snapshot(),
        ok = i2p_tunnel_outcome:built(outbound, 3),
        ?assertEqual(
            maps:get(tunnels_built_outbound, Before) + 1,
            maps:get(tunnels_built_outbound, i2p_stats:snapshot())
        ),
        ?assertMatch({tunnel_built, outbound, 3}, next_event())
    end).

failed_charges_the_reason_specific_counter_test() ->
    with_bus_and_counters(fun() ->
        Before = i2p_stats:snapshot(),
        %% Rejected twice, invalid once, so the two totals differ. One of each
        %% would prove nothing: both counters would read 1, which is exactly what a
        %% single collapsed "failed" figure would also show. Unequal totals are the
        %% evidence that the reasons are kept apart, and that one of them did not
        %% quietly stop moving.
        ok = i2p_tunnel_outcome:failed(outbound, rejected),
        ok = i2p_tunnel_outcome:failed(outbound, rejected),
        ok = i2p_tunnel_outcome:failed(outbound, invalid),
        After = i2p_stats:snapshot(),
        ?assertEqual(
            maps:get(tunnels_failed_outbound_rejected, Before) + 2,
            maps:get(tunnels_failed_outbound_rejected, After)
        ),
        ?assertEqual(
            maps:get(tunnels_failed_outbound_invalid, Before) + 1,
            maps:get(tunnels_failed_outbound_invalid, After)
        ),
        ?assertMatch({tunnel_failed, outbound, rejected}, next_event()),
        ?assertMatch({tunnel_failed, outbound, rejected}, next_event()),
        ?assertMatch({tunnel_failed, outbound, invalid}, next_event())
    end).

expired_charges_and_announces_test() ->
    with_bus_and_counters(fun() ->
        Before = i2p_stats:snapshot(),
        ok = i2p_tunnel_outcome:expired(inbound),
        ?assertEqual(
            maps:get(tunnels_expired_inbound, Before) + 1,
            maps:get(tunnels_expired_inbound, i2p_stats:snapshot())
        ),
        ?assertMatch({tunnel_expired, inbound}, next_event())
    end).

%% The state change is announced even when the counter home is not there. The
%% charge happens first and is a no-op in that case, and the announcement still
%% goes out — a subscriber must not lose an outcome because the router is not
%% measuring.
an_outcome_is_announced_while_the_counter_home_is_absent_test() ->
    ok = drain(),
    ok = start(i2p_events),
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
    ?assertEqual(undefined, whereis(i2p_stats)),
    try
        ok = i2p_tunnel_outcome:built(outbound, 1),
        ?assertMatch({tunnel_built, outbound, 1}, next_event())
    after
        _ = gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
        ok = stop(i2p_events)
    end.

%% %%%%% %%% Internal helpers %%%%% %%%

all_events() ->
    [{tunnel_built, D, 3} || D <- [inbound, outbound]] ++
        [{tunnel_failed, D, W} || D <- [inbound, outbound], W <- [rejected, invalid]] ++
        [{tunnel_expired, D} || D <- [inbound, outbound]].

%% The bus and the counter home, both started bare and unlinked to a supervisor,
%% so this module can take the counter home away again and have it stay away.
with_bus_and_counters(Fun) ->
    ok = drain(),
    ok = stop(i2p_stats),
    ok = start(i2p_events),
    ok = start(i2p_stats),
    %% The handler goes on before any outcome is announced, so an event that was
    %% sent is an event that arrives: no deadline and no polling.
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
    try
        Fun()
    after
        _ = gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
        ok = stop(i2p_stats),
        ok = stop(i2p_events)
    end.

%% EUnit runs every case in one process, and the collector forwards into that
%% process's mailbox. Without this a case that fails part-way leaves its events
%% behind, and the next case reads them instead of its own — which turns one
%% failure into a cascade and hides the real cause. Each case starts empty.
drain() ->
    receive
        _ -> drain()
    after 0 ->
        ok
    end.

start(Module) ->
    case whereis(Module) of
        undefined ->
            {ok, Pid} = Module:start_link(),
            true = unlink(Pid),
            ok;
        _ ->
            ok
    end.

stop(Module) ->
    case whereis(Module) of
        undefined ->
            ok;
        Pid ->
            MRef = erlang:monitor(process, Pid),
            _ = gen_server:stop(Pid),
            receive
                {'DOWN', MRef, process, Pid, _} -> ok
            after 5000 -> ok
            end
    end.

%% The next event the bus delivered to this process. A bare receive: the handler
%% was added before the outcome was announced, so its arrival is ordered by the
%% bus and cannot race.
next_event() ->
    receive
        Event -> Event
    end.
