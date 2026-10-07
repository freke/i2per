%% The acceptance criterion for a soak is not that its checks are present. It is
%% that they **fail when their invariant is violated** — because a check nobody
%% has seen fail is a comment with a function around it, and the whole reason
%% the first version of this harness family was discarded is that its three bugs
%% produced confident wrong answers rather than errors.
%%
%% The classification cases here drive the *real* exported functions with inputs
%% that violate the invariant, and assert the answer that matters. Two of them
%% are the reason this module exists:
%%
%%  * **`traffic_proportional` has to be reachable.** A verdict built only on the
%%    phase series cannot produce it — there is no phase in which memory was
%%    given back — so an earlier version of this classification had three
%%    reachable answers out of four and would never have distinguished
%%    proportional retention from anything else.
%%  * **A phase series that never rose must not be reported as `plateau`.** A
%%    plateau means "filled up and finished", which is a claim about growth that
%%    stopped. Reporting it for a run that moved nothing would turn "I measured
%%    nothing" into "I measured a bounded fill", which is the exact substitution
%%    of a conclusion for an observation this harness family exists to prevent.
-module(i2p_soak_tunnel_tests).

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%% %%% The verdict %%%%% %%%

%% Nothing moved, so there is no finding to classify. **Not** `plateau`: a
%% plateau asserts that something grew and then stopped, and nothing grew here.
a_flat_run_is_inconclusive_and_not_a_plateau_test() ->
    ?assertEqual(inconclusive, retention(phases([100, 100, 100]))).

%% One rising step and one flat step is a fill that finished.
a_fill_that_stopped_is_a_plateau_test() ->
    ?assertEqual(plateau, retention(phases([100, 300, 300]))).

%% Every step positive: the structure kept what it was given and kept taking more.
growth_every_phase_is_traffic_independent_test() ->
    ?assertEqual(traffic_independent, retention(phases([100, 300, 900]))).

%% The answer a phase series alone cannot give: memory rose under load and came
%% back in the quiet window. `loaded_words` above `retained_words` is the only
%% evidence of a return, so a verdict ignoring those readings cannot reach it.
memory_returned_in_the_quiet_window_is_traffic_proportional_test() ->
    ?assertEqual(traffic_proportional, retention(phases_releasing([100, 300, 900]))).

%% A run that only ever released memory has no retention to attribute, so it is
%% inconclusive rather than claiming a structure gave back what it never took.
a_run_that_only_released_is_inconclusive_test() ->
    ?assertEqual(inconclusive, retention(phases_releasing([100, 100, 100]))).

%% The verdict cannot name a leak, and the prose it hands a reader denies it
%% rather than accusing. The word "leak" is in the note to deny it, so asserting
%% its absence would assert the opposite of the intent.
verdict_carries_no_leak_field_and_says_so_test() ->
    #{retention := R, note := Note} = i2p_soak_tunnel:verdict(phases([100, 300, 900])),
    ?assertEqual(traffic_independent, R),
    ?assertNotEqual(nomatch, string:find(Note, <<"not a leak">>)),
    ?assertNotEqual(nomatch, string:find(Note, <<"slope">>)).

no_phases_is_inconclusive_test() ->
    ?assertEqual(inconclusive, maps:get(retention, i2p_soak_tunnel:verdict([]))).

%% One phase has no slope to difference against, so it reports none rather than
%% inventing one. The run itself refuses fewer than two (see the floor in
%% `f:minimum_phases/0`), and this pins the classifier agreeing with that.
a_single_phase_has_no_slope_test() ->
    ?assertEqual(0, maps:get(slope_words, i2p_soak_tunnel:verdict(phases([100])))).

%% %%%%% %%% %%% The traffic assertion %%%%% %%%

%% This is the ticket's first acceptance criterion, and it exists because the run
%% that motivated the ticket reported flat retention with **every tunnel counter
%% at zero**. A harness that cannot say so will do it again.
a_run_that_built_no_tunnels_fails_test() ->
    Quiet = phases_offering([100, 100, 100], nothing(#{built_inbound => 0, built_outbound => 0})),
    Failures = i2p_soak_tunnel:failures(all_ok(), Quiet, {"", 0}),
    ?assert(has_failure(Failures, "no inbound tunnel build")).

a_run_that_built_no_outbound_fails_test() ->
    Quiet = phases_offering([100, 100, 100], nothing(#{built_outbound => 0})),
    ?assert(
        has_failure(
            i2p_soak_tunnel:failures(all_ok(), Quiet, {"", 0}),
            "no outbound tunnel build"
        )
    ).

a_run_that_carried_no_transit_fails_test() ->
    Quiet = phases_offering([100, 100, 100], nothing(#{transit_frames => 0})),
    ?assert(
        has_failure(
            i2p_soak_tunnel:failures(all_ok(), Quiet, {"", 0}),
            "no transit frame"
        )
    ).

%% A phase that moved nothing is named by number, because "the run was slow" and
%% "phase 3 silently did nothing" are different problems and the reader needs
%% to know which.
a_phase_that_moved_nothing_is_named_test() ->
    Idle = [
        phase(1, 100, #{}, maps:merge(default_offered(), #{requested => 0})),
        phase(2, 100, #{}, default_offered())
    ],
    ?assert(has_failure(i2p_soak_tunnel:failures(all_ok(), Idle, {"", 0}), "phase 1")).

%% A run that built in both directions and carried transit passes, so the
%% assertion is not simply refusing everything.
a_run_that_built_both_ways_and_carried_transit_passes_test() ->
    Busy = phases([100, 300, 900]),
    ?assertEqual([], i2p_soak_tunnel:failures(all_ok(), Busy, {"", 0})).

%% No phases at all is reported as such rather than as a clean bill of health.
no_phases_fails_rather_than_reporting_clean_test() ->
    ?assertNotEqual([], i2p_soak_tunnel:failures(all_ok(), [], {"", 0})).

%% The other three things `ok` folds in.
a_refused_rate_fails_the_run_test() ->
    Busy = phases([100, 300, 900]),
    ?assert(
        has_failure(
            i2p_soak_tunnel:failures(all_ok(), Busy, {"offered rate 1000000 is out of bounds", 0}),
            "1000000"
        )
    ).

a_dirty_node_fails_the_run_test() ->
    Busy = phases([100, 300, 900]),
    ?assert(has_failure(i2p_soak_tunnel:failures(all_ok(), Busy, {"", 7}), "7 processes")).

a_failed_self_check_fails_the_run_test() ->
    Busy = phases([100, 300, 900]),
    Checks = [#{name => census_not_empty, ok => false, evidence => "the census was empty"}],
    ?assertEqual(["the census was empty"], i2p_soak_tunnel:failures(Checks, Busy, {"", 0})).

%% %%%%% %%% %%% Summing, and the floor on phases %%%%% %%%

%% Totals are summed, so the traffic figure beside the phase series is the work
%% the whole run produced rather than the last phase's share of it.
offered_totals_are_summed_across_phases_test() ->
    Phases = [
        phase(1, 100, #{}, nothing(#{built_inbound => 3, transit_frames => 3})),
        phase(2, 200, #{}, nothing(#{built_inbound => 4, transit_frames => 4}))
    ],
    Total = i2p_soak_tunnel:total_offered(Phases),
    ?assertEqual(7, maps:get(built_inbound, Total)),
    ?assertEqual(7, maps:get(transit_frames, Total)).

%% The floor exists because one phase has one slope, and "did the slope continue"
%% is the question. Two is the fewest phases that can answer it.
the_verdict_needs_at_least_two_phases_test() ->
    ?assertEqual(2, i2p_soak_tunnel:minimum_phases()).

%% %%%%% %%% %%% Helpers %%%%% %%%

retention(Phases) ->
    maps:get(retention, i2p_soak_tunnel:verdict(Phases)).

%% A phase series whose retained heap is the given words, and whose load window
%% left the heap **exactly where it found it** — the ordinary case for a
%% structure that keeps what it was given, and therefore the one that must not
%% be classified `traffic_proportional`.
phases(Words) ->
    [phase(N, Word, #{loaded_words => Word}, default_offered()) || {N, Word} <- zip(Words)].

%% The same, but each phase's quiet window **returned** what the load took: the
%% reading at the end of the load window is above the one after it. That
%% difference is the only evidence of a return, so it is what separates
%% proportional retention from everything else.
phases_releasing(Words) ->
    [
        phase(N, Word, #{loaded_words => Word + 400}, default_offered())
     || {N, Word} <- zip(Words)
    ].

%% A phase series that offered a specific amount of traffic, so the traffic
%% assertion is what is under test rather than the classifier.
phases_offering(Words, Offered) ->
    [phase(N, Word, #{loaded_words => Word}, Offered) || {N, Word} <- zip(Words)].

zip(Words) ->
    lists:zip(lists:seq(1, length(Words)), Words).

phase(N, Retained, Fields, Offered) ->
    maps:merge(
        #{
            index => N,
            retained_words => Retained,
            ets_bytes => 1024,
            pools => #{
                outbound => 1,
                inbound => 1,
                transit => 1,
                exploratory_outbound => 0,
                exploratory_inbound => 0,
                pending_outbound => 0,
                pending_inbound => 0
            },
            mailbox_slope => [],
            counters => #{}
        },
        maps:merge(Fields, #{offered => Offered})
    ).

%% Traffic that actually happened, so the traffic assertion is satisfied unless
%% a case overrides one field to zero.
default_offered() ->
    #{
        requested => 20,
        built_inbound => 10,
        built_outbound => 9,
        transit_frames => 9
    }.

%% Zero out one figure and leave the rest, so a case asserts about that figure
%% alone rather than tripping over the others.
nothing(Overrides) ->
    maps:merge(default_offered(), Overrides).

all_ok() ->
    [
        #{name => census_not_empty, ok => true, evidence => "45 processes"},
        #{name => known_bad_mailbox_reported_as_growth, ok => true, evidence => "5000"},
        #{name => seeded_leak_flagged, ok => true, evidence => "4 MB"}
    ].

has_failure(Failures, Fragment) ->
    lists:any(fun(F) -> string:find(F, Fragment) =/= nomatch end, Failures).
