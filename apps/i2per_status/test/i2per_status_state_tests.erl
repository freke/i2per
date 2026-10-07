-module(i2per_status_state_tests).

-moduledoc """
Unit tests for the `m:i2per_status_state` gen_server callbacks: realtime event
counters, node-up/down handling, fallback polling to offline, and the
not-implemented/irrelevant fallthrough clauses.

The callbacks are exercised directly with crafted state maps (they are
exported parts of the gen_server behaviour surface); the live server against a
router is covered end-to-end in `m:i2per_status_tests`.
""".

-include_lib("eunit/include/eunit.hrl").

-define(DEAD_NODE, 'i2per_status_unit@host-invalid').

dead_state() ->
    #{
        router_node => ?DEAD_NODE,
        subscribed => false,
        online => false,
        view => #{},
        events => zero_counters()
    }.

%% Feed one event through handle_info and return the counter map.
counts_for(Event) ->
    State = dead_state(),
    {noreply, State1} = i2per_status_state:handle_info({event, Event}, State),
    maps:get(events, State1).

%% Check one key was bumped to N and everything else stayed at 0.
only_bumped(BumpedKey, N, Counters) ->
    ?assertEqual(N, maps:get(BumpedKey, Counters)),
    maps:fold(
        fun
            (K, _, Acc) when K =:= BumpedKey -> Acc;
            (_, 0, Acc) -> Acc;
            (K, V, _) -> erlang:error({unexpected_bump, K, V})
        end,
        ok,
        Counters
    ).

tunnel_built_counts_test() ->
    only_bumped(tunnel_built, 1, counts_for({tunnel_built, outbound, 3})).

tunnel_failed_counts_test() ->
    only_bumped(tunnel_failed, 1, counts_for({tunnel_failed, inbound, rejected})).

tunnel_expired_counts_test() ->
    only_bumped(tunnel_expired, 1, counts_for({tunnel_expired, outbound})).

leaseset_published_counts_test() ->
    only_bumped(
        leaseset_published, 1, counts_for({leaseset_published, crypto:strong_rand_bytes(32)})
    ).

sam_session_created_counts_test() ->
    only_bumped(sam_session_created, 1, counts_for({sam_session_created, <<"sid">>, stream})).

sam_session_closed_counts_test() ->
    only_bumped(sam_session_closed, 1, counts_for({sam_session_closed, <<"sid">>})).

previously_dropped_event_is_counted_test() ->
    %% This case used to be `unknown_event_ignored_test` and asserted that
    %% `{peer_connected, _}` was *dropped*. That was the defect, written down as
    %% intended behaviour: a peer connecting was an event nobody counted, and the
    %% test said so.
    %%
    %% `peer_connected` is a tag this service knows about -- it is one of the seven
    %% the old catch-all threw away -- so it is counted and *not* flagged.
    C = counts_for({peer_connected, crypto:strong_rand_bytes(32)}),
    ?assertEqual(1, maps:get(peer_connected, C)),
    ?assertEqual(0, maps:get(unrecognised_event, C)).

%% A tag this service has never heard of is counted under its own name *and*
%% flagged, so it is visible as an unrecognised arrival rather than blending into
%% the keys the service does know. Without the flag a future bus event would be
%% recorded and nobody would notice it was not one of the ones being displayed.
unrecognised_event_is_counted_and_flagged_test() ->
    C = counts_for({some_future_event, 1}),
    ?assertEqual(1, maps:get(some_future_event, C)),
    ?assertEqual(1, maps:get(unrecognised_event, C)),
    %% And it is not mistaken for one of the known keys.
    ?assertEqual(0, maps:get(tunnel_expired, C)).

counters_accumulate_across_events_test() ->
    State0 = dead_state(),
    {noreply, State1} =
        i2per_status_state:handle_info({event, {tunnel_failed, inbound, invalid}}, State0),
    {noreply, State2} =
        i2per_status_state:handle_info({event, {tunnel_failed, inbound, invalid}}, State1),
    Counters = maps:get(events, State2),
    ?assertEqual(2, maps:get(tunnel_failed, Counters)).

handle_call_unsupported_test() ->
    {reply, {error, not_implemented}, State} =
        i2per_status_state:handle_call(bogus, undefined, dead_state()),
    ?assertEqual(maps:get(events, dead_state()), maps:get(events, State)).

handle_cast_fallthrough_test() ->
    State = dead_state(),
    {noreply, State} = i2per_status_state:handle_cast(whatever, State).

%% These three run the callback through `m:i2p_ct_helpers:in_throwaway/1`, which
%% owns the reasoning: under eunit the caller is a worker shared by every module in
%% the tier, and `f:handle_info(poll, ...)` re-arms itself into it. A local copy of
%% that helper used to live here; it moved to `m:i2p_ct_helpers` when
%% `i2p_addressbook_subs_tests` needed the same thing, because two copies of a
%% helper whose own failure mode is a leaked `'DOWN'` is how they start to differ.
nodeup_resubscribes_test() ->
    State0 = dead_state(),
    {noreply, State} = i2p_ct_helpers:in_throwaway(fun() ->
        i2per_status_state:handle_info({nodeup, ?DEAD_NODE}, State0)
    end),
    %% subscribe/1 to an unreachable node collapses to false.
    ?assertEqual(false, maps:get(subscribed, State)).

nodedown_marks_offline_test() ->
    State0 = dead_state(),
    {noreply, State} = i2p_ct_helpers:in_throwaway(fun() ->
        i2per_status_state:handle_info({nodedown, ?DEAD_NODE}, State0)
    end),
    ?assertEqual(false, maps:get(online, State)),
    ?assertEqual(#{}, maps:get(view, State)).

irrelevant_info_fallthrough_test() ->
    State = dead_state(),
    {noreply, State} = i2per_status_state:handle_info(irrelevant, State).

poll_to_unreachable_goes_offline_test() ->
    %% Previously-online router disappears: next poll must flip the view to
    %% offline_view() instead of keeping the stale snapshot.
    State0 = (dead_state())#{online => true, view => #{stale => 1}},
    {noreply, State} = i2p_ct_helpers:in_throwaway(fun() ->
        i2per_status_state:handle_info(poll, State0)
    end),
    ?assertEqual(false, maps:get(online, State)),
    ?assertEqual(#{}, maps:get(view, State)).

terminate_and_code_change_test() ->
    State = dead_state(),
    ?assertEqual(ok, i2per_status_state:terminate(any, State)),
    ?assertEqual({ok, State}, i2per_status_state:code_change(0, State, [])).

%% The zero map is whatever the module says it is, read from the module rather
%% than restated here -- a hand-written copy of the key set in the test is exactly
%% the second description that drifts.
zero_counters() ->
    maps:from_list([{Key, 0} || Key <- i2per_status_state:known_event_keys()]).
