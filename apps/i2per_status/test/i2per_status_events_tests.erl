-module(i2per_status_events_tests).

-moduledoc """
The contract between the router's event bus and this service's counters.

The old `bump/2` matched six shapes and dropped the rest through a catch-all,
which is how `reachability` and `peertest_result` came to be published over
distribution and thrown away. Nothing in the build failed, and the test that
covered the catch-all asserted the drop was correct.

Two things are checked here, and the second is the one that matters:

1. **The documented key set is well formed** and covers every tag the bus's event
   type admits, so the list this module publishes is not quietly behind.

2. **Folding is total**, so the property above is structural rather than a
   list to maintain. `bump/2` derives the counter from the event's own tag, so an
   event the bus adds in future is counted without any change here. That is
   checked by folding an event shape that does not exist and requiring it to be
   counted *and* flagged.

The ticket asked for a test that "enumerates the event type's shapes". That is
not possible at runtime in Erlang — a type is not data — so the guarantee is
structural instead, which is stronger: it cannot fall behind the type at all.
What can still drift is the *documented* vocabulary, so that is pinned too.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%%%% The documented key set %%%%% %%%%%

%% Every shape the bus's event type admits, as exemplars. Written here rather than
%% derived, because a type is not data and this is the list the documented key set
%% is checked against. It is one exemplar per tag, and every tag in the type has
%% one; adding a tag to the bus without adding it here is caught by
%% `every_shape_in_the_type_vocabulary_is_covered` below only if that check
%% consults the module's own list -- which it does, so what is really being
%% protected is the module's list, not this one.
bus_event_shapes() ->
    [
        {peer_connected, crypto:strong_rand_bytes(32)},
        {peer_disconnected, crypto:strong_rand_bytes(32)},
        {peer_connect_failed, crypto:strong_rand_bytes(32), {handshake, timeout}, 8},
        {ssu2_dial_parked, crypto:strong_rand_bytes(32), {handshake_timeout, session_request}},
        {peer_send_stalled, crypto:strong_rand_bytes(32), socket_blocked},
        {tunnel_built, outbound, 3},
        {tunnel_failed, inbound, invalid},
        {tunnel_expired, inbound},
        {transit_denied, 400, capacity},
        {leaseset_published, crypto:strong_rand_bytes(32)},
        {leaseset_publish_failed, crypto:strong_rand_bytes(32), no_floodfill_targets},
        {sam_session_created, <<"sid">>, stream},
        {sam_session_closed, <<"sid">>},
        {peertest_result, ipv4, ok},
        {reachability, ssu2, firewalled},
        {ssu2_block_unhandled, some_block_kind},
        {db_store_not_stored, unparseable_router_info_data},
        {lookup_failed, crypto:strong_rand_bytes(32), lease, no_answer},
        {config_changed, some_key, some_value}
    ].

%% Every tag the bus's event type admits appears in `f:known_event_keys/0`, either
%% as a plain tag or as the head of a broken-out variant. This is the check that a
%% new event added to the bus cannot go uncounted: if the tag is not in the
%% documented set, it is flagged, and the flag is exactly the "we did not expect
%% this" signal the ticket asked for.
every_shape_in_the_type_vocabulary_is_covered_test() ->
    Keys = i2per_status_state:known_event_keys(),
    %% Every exemplar's key is one the module says it knows.
    lists:foreach(
        fun(Event) ->
            ?assert(lists:member(fold_key(Event), Keys))
        end,
        bus_event_shapes()
    ),
    %% The reverse, by *tag* rather than by key. Comparing keys would be wrong: the
    %% module documents every `reachability` verdict and every `peertest_result`
    %% combination, while this list carries one exemplar per tag, so a key-wise
    %% comparison would report the extra combinations as dead entries. What must
    %% hold is that every documented key belongs to a tag the bus emits, and that
    %% every tag the bus emits is documented. The individual combinations are
    %% covered by the per-verdict cases below.
    DocumentedTags = lists:usort([key_tag(K) || K <- Keys]),
    EmittedTags = lists:usort([element(1, E) || E <- bus_event_shapes()]),
    %% Parenthesised deliberately: `--` is right-associative in Erlang, so the
    %% unparenthesised chain reads as `DocumentedTags -- (EmittedTags -- [...])`
    %% and never subtracts what was intended.
    ?assertEqual([], (DocumentedTags -- EmittedTags) -- [unrecognised_event]),
    ?assertEqual([], EmittedTags -- DocumentedTags).

%% The shapes the old catch-all dropped, by name, so this case fails if one is ever
%% dropped again rather than passing because the list happened to grow. The last
%% four joined them in #FBRVSBE and #902G3ZN: `peer_connect_failed`,
%% `transit_denied`, `leaseset_publish_failed` and `lookup_failed` were not in the bus
%% at all, so a router that could not reach a peer, would not carry a tunnel, could
%% not publish a client's LeaseSet, or could not answer a lookup said nothing
%% anywhere.
the_eleven_previously_dropped_shapes_are_counted_test() ->
    PreviouslyDropped = [
        {peer_connected, crypto:strong_rand_bytes(32)},
        {peer_disconnected, crypto:strong_rand_bytes(32)},
        {peertest_result, ipv4, firewalled},
        {reachability, ssu2, reachable},
        {ssu2_block_unhandled, peer_test},
        {db_store_not_stored, expired},
        {config_changed, transit_max_tunnels, 50},
        {peer_connect_failed, crypto:strong_rand_bytes(32), timeout, 16},
        {transit_denied, 401, build_budget_drained},
        {leaseset_publish_failed, crypto:strong_rand_bytes(32), local_store_rejected},
        {lookup_failed, crypto:strong_rand_bytes(32), lease, no_answer}
    ],
    lists:foreach(
        fun(Event) ->
            Counters = fold(Event),
            ?assertEqual(1, maps:get(fold_key(Event), Counters))
        end,
        PreviouslyDropped
    ).

%% %%%%% %%%%% The verdict, not just a total %%%%% %%%%%

%% A total of `reachability` events would say only that something happened. The
%% thing an operator needs is the verdict, so it is broken out.
reachability_is_counted_per_verdict_test() ->
    lists:foreach(
        fun(Verdict) ->
            Counters = fold({reachability, ssu2, Verdict}),
            ?assertEqual(1, maps:get({reachability, Verdict}, Counters))
        end,
        [reachable, firewalled, unknown]
    ).

%% And the three verdicts are separate counters rather than one figure, so a reader
%% can see which way it went.
reachability_verdicts_are_separate_counters_test() ->
    Counters = lists:foldl(
        fun(Verdict, Acc) -> fold({reachability, ssu2, Verdict}, Acc) end,
        empty(),
        [reachable, reachable, firewalled]
    ),
    ?assertEqual(2, maps:get({reachability, reachable}, Counters)),
    ?assertEqual(1, maps:get({reachability, firewalled}, Counters)),
    ?assertEqual(0, maps:get({reachability, unknown}, Counters)).

peertest_result_is_counted_per_type_and_result_test() ->
    Counters = fold({peertest_result, ipv4, ok}),
    ?assertEqual(1, maps:get({peertest_result, ipv4, ok}, Counters)),
    ?assertEqual(0, maps:get({peertest_result, ipv6, ok}, Counters)).

%% %%%%% %%%%% The verdict, kept current %%%%% %%%%%

%% Counting reachability events gives a history; the snapshot also carries the
%% latest verdict, which is the number that says whether anyone can reach this
%% router right now. The two are separate because the counters cannot supply it.
reachability_verdict_is_tracked_test() ->
    State0 = state(),
    ?assertEqual(undefined, verdict_of(State0)),
    State1 = deliver({reachability, ssu2, firewalled}, State0),
    ?assertEqual(firewalled, verdict_of(State1)),
    State2 = deliver({reachability, ssu2, reachable}, State1),
    ?assertEqual(reachable, verdict_of(State2)),
    %% A later event of another shape leaves the verdict alone: the router's
    %% aggregate decision changes only when the router says so.
    State3 = deliver({tunnel_built, outbound, 3}, State2),
    ?assertEqual(reachable, verdict_of(State3)).

%% %%%%% %%%%% Folding is total %%%%% %%%%%

%% The structural guarantee. An event shape that does not exist is counted under
%% its own tag and flagged, so a future bus event is recorded rather than dropped,
%% and this service needs no change to keep counting it.
folding_is_total_test() ->
    Counters = fold({an_event_from_the_future, 1, 2}),
    ?assertEqual(1, maps:get(an_event_from_the_future, Counters)),
    ?assertEqual(1, maps:get(unrecognised_event, Counters)).

%% Every key starts at zero, so a consumer can read any of them without a default
%% and can tell "nothing has happened" from "this key does not exist".
every_known_key_starts_at_zero_test() ->
    ?assertEqual(
        maps:from_list([{K, 0} || K <- i2per_status_state:known_event_keys()]),
        empty()
    ).

%% Folding one event changes exactly one counter, or two when the event is
%% unrecognised. A fold that disturbed another key would mean the derivation is
%% not a function of the event alone.
folding_touches_only_the_derived_key_test() ->
    Before = empty(),
    After = fold({tunnel_built, outbound, 3}, Before),
    Changed = [K || K <- maps:keys(After), maps:get(K, After) =/= maps:get(K, Before)],
    ?assertEqual([tunnel_built], Changed).

%% %%%%% %%%%% Internal helpers %%%%% %%%%%

%% Fold one event into a fresh counter set, through the real state machine, so the
%% path under test is the one the bus drives rather than a copy of the arithmetic.
fold(Event) -> fold(Event, empty()).

state() ->
    #{
        router_node => 'router@somewhere',
        subscribed => true,
        online => true,
        view => #{},
        events => empty(),
        last_reachability => undefined,
        previous => undefined,
        derived => undefined
    }.

deliver(Event, State) ->
    {noreply, State1} = i2per_status_state:handle_info({event, Event}, State),
    State1.

verdict_of(State) -> maps:get(last_reachability, State, undefined).

fold(Event, Start) ->
    maps:get(events, deliver(Event, (state())#{events => Start})).

empty() ->
    maps:from_list([{K, 0} || K <- i2per_status_state:known_event_keys()]).

%% The counter one exemplar event is counted under. Mirrors `f:key_for/1`, which is
%% not exported; the two variant shapes are the only ones that differ from the tag,
%% and the totality case above covers the general behaviour.
%% The tag a documented counter key belongs to. A plain tag is its own name; a
%% broken-out variant key is a tuple headed by its tag.
key_tag(Key) when is_atom(Key) -> Key;
key_tag(Key) when is_tuple(Key) -> element(1, Key).

fold_key({reachability, _, Verdict}) -> {reachability, Verdict};
fold_key({peertest_result, A, R}) -> {peertest_result, A, R};
fold_key(Event) -> element(1, Event).
