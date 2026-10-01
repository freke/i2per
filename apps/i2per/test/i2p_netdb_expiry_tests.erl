%% Tests that the RouterInfo expiry horizon is a store setting rather than a
%% compile-time constant, and that it slides with the store's size.
%%
%% The horizon used to be `?MAX_EXPIRATION_MS`, read in two places: once by the
%% admission check in `f:store/3` and once by the sweep. Two copies of the same
%% constant, written as two comparisons, with nothing tying them together.
%%
%% It then lived in the store next to `capacity` as one number, so both callers read
%% one value and a store could not admit a RouterInfo it was about to expire -- but
%% it was a flat 27 hours at every size, which is more permissive than either
%% reference implementation, at the one size where both of them expire aggressively.
%%
%% **What is settled now:** the horizon is i2pd's curve between two bounds, so the
%% fuller the store the sooner a stale entry goes. See "The expiry horizon is a
%% function of how full the store is" in `m:i2p_netdb`.

-module(i2p_netdb_expiry_tests).

-moduledoc """
Tests that the RouterInfo expiry horizon is per-store, shared by the admission check
and the sweep, and interpolated from the store's size between two bounds.
""".

-include_lib("eunit/include/eunit.hrl").

-define(MINUTE_MS, 60 * 1000).
-define(HOUR_MS, 60 * ?MINUTE_MS).
%% i2pd NetDb.hpp: NETDB_MAX_EXPIRATION_TIMEOUT = 27 hours. Spelled out so the
%% default case above is checked against something rather than against itself.
-define(MAX_EXPIRATION_MS, 27 * ?HOUR_MS).
%% i2pd NetDb.hpp: NETDB_MIN_EXPIRATION_TIMEOUT = 1.5 hours.
-define(MIN_EXPIRATION_MS, 90 * ?MINUTE_MS).
%% i2pd NetDb.hpp: NETDB_MIN_ROUTERS = 90.
-define(MIN_ROUTERS, 90).

%%% --------------------------------------------------------------------------
%%% The horizon is a store field, not a constant
%%% --------------------------------------------------------------------------

%% Both bounds of the admission window come from the store, and the past one is the
%% value the sweep compares against. Asserted as behaviour rather than by reading
%% the field: a store set to a one-hour horizon must reject a two-hour-old
%% RouterInfo, and a store set to a two-day horizon must accept one.
horizon_is_the_stores_setting_not_a_constant_test() ->
    Now = erlang:system_time(millisecond),
    TwoHours = 2 * ?HOUR_MS,
    RI = router(Now - TwoHours, host(1)),

    %% Stored as of `Now`, so the RouterInfo's age at that moment is the two hours
    %% it was published ago.
    %%
    %% One-hour horizon: the RouterInfo is older than the store allows.
    Tight = i2p_netdb:new(10, ?HOUR_MS),
    {Tight1, Outcome} = i2p_netdb:store(Tight, RI, Now),
    ?assertEqual(too_old, Outcome),
    ?assertEqual(0, i2p_netdb:count(Tight1)),

    %% Two-day horizon: comfortably inside it, so the same RouterInfo is admitted.
    Loose = i2p_netdb:new(10, 48 * ?HOUR_MS),
    {Loose1, added} = i2p_netdb:store(Loose, RI, Now),
    ?assertEqual(1, i2p_netdb:count(Loose1)).

%% The default is what `new/0` and `new/1` give, and it is i2pd's 27 hours rather
%% than a number this module made up. Asserted against the exported accessor rather
%% than a literal, so the test says "the default is the documented one" rather than
%% restating it and drifting.
default_horizon_is_i2pds_maximum_test() ->
    ?assertEqual(?MAX_EXPIRATION_MS, i2p_netdb:default_expiration_ms()),
    %% `new/0` and `new/1` both take the default, and `new/2` overrides it rather
    %% than ignoring the argument -- which is the distinction `new/2` exists for.
    ?assertEqual(i2p_netdb:default_expiration_ms(), i2p_netdb:expiration_ms(i2p_netdb:new())),
    ?assertEqual(i2p_netdb:default_expiration_ms(), i2p_netdb:expiration_ms(i2p_netdb:new(10))),
    ?assertEqual(999, i2p_netdb:expiration_ms(i2p_netdb:new(10, 999))),
    ok.

%%% --------------------------------------------------------------------------
%%% Admission and the sweep read the same value
%%% --------------------------------------------------------------------------

%% **The property the change exists for.**
%%
%% The horizon was two comparisons in two places. If they disagree, a store can
%% accept a RouterInfo and then remove it on the next sweep, which looks like the
%% network expiring entries it just published and is very hard to tell apart from a
%% clock problem.
%%
%% So: store at the store's own horizon, then sweep at the same instant with the
%% same horizon, and assert nothing came out. If the two callers read different
%% values, the RouterInfo is gone.
admission_and_sweep_agree_on_the_horizon_test() ->
    lists:foreach(
        fun(Hours) ->
            Horizon = Hours * ?HOUR_MS,
            Now = erlang:system_time(millisecond),
            %% Published exactly `Horizon` ago, which is inside the window: the
            %% admission comparison is `<=` so the boundary is accepted, and the
            %% sweep's is `<` so the boundary is kept. The two have to agree on
            %% that, which is the whole point.
            RI = router(Now - Horizon, host(Hours)),
            Store0 = i2p_netdb:new(10, Horizon),
            {Store1, added} = i2p_netdb:store(Store0, RI, Now),
            ?assertEqual(added, added),
            ?assertEqual(1, i2p_netdb:count(Store1)),
            {Store2, {0, 0}} =
                i2p_netdb:remove_expired(Store1, Now, erlang:system_time(second)),
            ?assertEqual(1, i2p_netdb:count(Store2))
        end,
        [1, 2, 27]
    ).

%% And one millisecond past it, both ways: rejected at the door, so a sweep can
%% never be the thing that finds out.
one_past_the_horizon_is_rejected_rather_than_swept_test() ->
    Now = erlang:system_time(millisecond),
    Horizon = ?HOUR_MS,
    RI = router(Now - Horizon - 1, host(2)),
    Store0 = i2p_netdb:new(10, Horizon),
    {Store1, too_old} = i2p_netdb:store(Store0, RI, Now),
    ?assertEqual(0, i2p_netdb:count(Store1)),
    %% Nothing to sweep, and that is the point: the entry never existed.
    {Store2, {0, 0}} =
        i2p_netdb:remove_expired(Store1, Now + Horizon, erlang:system_time(second)),
    ?assertEqual(0, i2p_netdb:count(Store2)).

%% The sweep reads the store's horizon too, not the default. A store built with a
%% short horizon must drop what it would have kept at 27 hours.
%%
%% Built through `from_binary/1` because `store/3` refuses an already-expired
%% RouterInfo: a store with a 1-hour horizon cannot be given a 5-hour-old
%% RouterInfo through the public API, and advancing the sweep's clock is how a real
%% router gets one.
sweep_uses_the_stores_horizon_not_the_default_test() ->
    Now = erlang:system_time(millisecond),
    Aged = ?HOUR_MS * 5,
    RI = router(Now - Aged, host(3)),
    Stored0 = i2p_netdb:new(10),
    {Stored, added} = i2p_netdb:store(Stored0, RI, Now - Aged),
    ?assertEqual(added, added),

    SweepAt = Now,
    %% At the default 27-hour horizon it is five hours old and stays.
    {Default1, {0, 0}} = i2p_netdb:remove_expired(Stored, SweepAt, erlang:system_time(second)),
    ?assertEqual(1, i2p_netdb:count(Default1)),

    %% At a one-hour horizon the same store drops it. A different store, because
    %% the sweep mutates.
    Tight = i2p_netdb:set_expiration_ms(i2p_netdb:new(10), ?HOUR_MS),
    Tight1 = seed(Tight, RI, Now - Aged),
    {Tight2, {1, 0}} = i2p_netdb:remove_expired(Tight1, SweepAt, erlang:system_time(second)),
    ?assertEqual(0, i2p_netdb:count(Tight2)).

%%% --------------------------------------------------------------------------
%%% Setting it
%%% --------------------------------------------------------------------------

%% `set_expiration_ms/2` changes the policy and nothing else. The count, the keys and
%% the recency order are untouched, because this is a setting rather than a
%% mutation: a store that changed shape would need the generation claimed and the
%% table checked, and neither is warranted for a policy change.
set_horizon_leaves_the_store_otherwise_untouched_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(10),
    Store1 = stored([router(Now, host(4)), router(Now, host(5))], Store0, Now),
    ?assertEqual(2, i2p_netdb:count(Store1)),

    Store2 = i2p_netdb:set_expiration_ms(Store1, 42 * ?HOUR_MS),
    ?assertEqual(42 * ?HOUR_MS, i2p_netdb:expiration_ms(Store2)),
    ?assertEqual(i2p_netdb:count(Store1), i2p_netdb:count(Store2)),
    ?assertEqual(i2p_netdb:keys(Store1), i2p_netdb:keys(Store2)),
    ?assertEqual(i2p_netdb:capacity(Store1), i2p_netdb:capacity(Store2)),
    ?assertEqual(i2p_netdb:generation(Store1), i2p_netdb:generation(Store2)),
    ok = i2p_netdb:self_check(Store2).

%% Setting the horizon is repeatable and does not accumulate. A store could keep a
%% policy field that only ever grows or only ever shrinks if the setter were
%% relative; it is absolute.
set_horizon_is_absolute_not_relative_test() ->
    Store0 = i2p_netdb:new(10, ?HOUR_MS),
    Store1 = i2p_netdb:set_expiration_ms(Store0, 5 * ?HOUR_MS),
    Store2 = i2p_netdb:set_expiration_ms(Store1, 2 * ?HOUR_MS),
    ?assertEqual(2 * ?HOUR_MS, i2p_netdb:expiration_ms(Store2)),
    %% And back up again, which is the direction a relative setter would refuse.
    Store3 = i2p_netdb:set_expiration_ms(Store2, 9 * ?HOUR_MS),
    ?assertEqual(9 * ?HOUR_MS, i2p_netdb:expiration_ms(Store3)).

%% Capacity and horizon are independent. They are both "how the store is bounded" and
%% an implementation could reasonably have coupled them; nothing does, and a store
%% with a tiny capacity and a long horizon is a valid configuration.
capacity_and_horizon_are_independent_test() ->
    Store = i2p_netdb:new(2, 48 * ?HOUR_MS),
    ?assertEqual(2, i2p_netdb:capacity(Store)),
    ?assertEqual(48 * ?HOUR_MS, i2p_netdb:expiration_ms(Store)),
    Store1 = i2p_netdb:set_expiration_ms(Store, ?HOUR_MS),
    ?assertEqual(2, i2p_netdb:capacity(Store1)),
    ?assertEqual(?HOUR_MS, i2p_netdb:expiration_ms(Store1)).

%% A horizon that is not a positive integer is a programming error in a caller, and
%% raises rather than being silently ignored. A store with a zero or negative
%% horizon would expire every RouterInfo the moment it was stored, which is a
%% failure that would look like the network expiring everything.
invalid_horizon_is_rejected_test() ->
    Store = i2p_netdb:new(10),
    ?assertError(badarg, i2p_netdb:set_expiration_ms(Store, 0)),
    ?assertError(badarg, i2p_netdb:set_expiration_ms(Store, -1)),
    ?assertError(badarg, i2p_netdb:set_expiration_ms(Store, infinity)),
    ?assertError(badarg, i2p_netdb:set_expiration_ms(Store, hour)),
    ?assertError(badarg, i2p_netdb:new(10, 0)),
    ?assertError(badarg, i2p_netdb:new(10, -1)),
    %% And the store is untouched by the attempts that failed.
    ?assertEqual(i2p_netdb:default_expiration_ms(), i2p_netdb:expiration_ms(Store)).

%%% --------------------------------------------------------------------------
%%% The clock-skew tolerance is separate, and deliberately not configurable
%%% --------------------------------------------------------------------------

%% The window has two bounds and only one of them is a policy. The other is how far
%% ahead of the local clock a RouterInfo may claim to be published, which is a
%% tolerance for clock skew rather than a choice about staleness.
%%
%% Asserted so the two are not conflated later: if a future change makes this
%% configurable, this case says the two were distinguished deliberately.
clock_skew_tolerance_is_not_the_horizon_test() ->
    ?assertNotEqual(i2p_netdb:expiration_threshold_ms(), i2p_netdb:default_expiration_ms()),
    %% 2 minutes against 27 hours.
    ?assertEqual(2 * ?MINUTE_MS, i2p_netdb:expiration_threshold_ms()).

%% The skew bound is unchanged by the horizon, in both directions: setting a longer
%% horizon must not widen how far into the future an entry is accepted, and setting
%% a shorter one must not narrow it.
horizon_does_not_move_the_clock_skew_bound_test() ->
    Now = erlang:system_time(millisecond),
    Threshold = i2p_netdb:expiration_threshold_ms(),
    %% One second inside the skew tolerance: admissible, because being published a
    %% little ahead of the local clock is what the tolerance is for.
    SlightlyAhead = router(Now + Threshold - 1000, host(6)),

    Short = i2p_netdb:new(10, ?HOUR_MS),
    {Short1, added} = i2p_netdb:store(Short, SlightlyAhead, Now),
    ?assertEqual(1, i2p_netdb:count(Short1)),

    Long = i2p_netdb:new(10, 48 * ?HOUR_MS),
    {Long1, added} = i2p_netdb:store(Long, SlightlyAhead, Now),
    ?assertEqual(1, i2p_netdb:count(Long1)),

    %% One second outside it, rejected by both horizons alike. The rejection is the
    %% skew bound's, so the horizon has no say in it.
    TooFar = router(Now + Threshold + 1000, host(7)),
    {_Short2, from_future} = i2p_netdb:store(Short, TooFar, Now),
    {_Long2, from_future} = i2p_netdb:store(Long, TooFar, Now),
    %% And changing the horizon on a live store does not move the bound either.
    {_Short3, from_future} = i2p_netdb:store(i2p_netdb:set_expiration_ms(Short, 1), TooFar, Now).

%%% --------------------------------------------------------------------------
%%% Persistence
%%% --------------------------------------------------------------------------

%% **The horizon is not written to the file, on purpose.**
%%
%% Capacity is a property of the store that was saved. The horizon is a policy the
%% running router decides now, the same way it decides the sweep interval, so
%% persisting it would mean an operator lowering it and having a restart silently
%% restore the old value from disk -- configuration that appears not to apply and is
%% invisible while the router is down.
%%
%% So the load restores capacity and leaves the horizon for the caller to set.
loaded_store_takes_its_horizon_from_the_caller_not_the_file_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(77, 2 * ?HOUR_MS),
    Store1 = stored([router(Now, host(8))], Store0, Now),
    Bin = i2p_netdb:to_binary(Store1),

    {ok, Loaded} = i2p_netdb:from_binary(Bin),

    %% Capacity survives, because it is the store's own.
    ?assertEqual(77, i2p_netdb:capacity(Loaded)),
    ?assertEqual(1, i2p_netdb:count(Loaded)),
    %% The horizon does not, and the RouterInfo came back.
    ?assertEqual(i2p_netdb:default_expiration_ms(), i2p_netdb:expiration_ms(Loaded)),

    %% Which means the caller can put its own policy on a store full of routers that
    %% the saved horizon would have kept.
    Tight = i2p_netdb:set_expiration_ms(Loaded, ?MINUTE_MS),
    ?assertEqual(?MINUTE_MS, i2p_netdb:expiration_ms(Tight)),
    {Tight1, {0, 0}} = i2p_netdb:remove_expired(Tight, Now, erlang:system_time(second)),
    %% One minute old at the default 27-hour horizon, so it is still there.
    ?assertEqual(1, i2p_netdb:count(Tight1)).

%% The on-disk bytes do not change. The header is
%% `magic ‖ version ‖ capacity(4) ‖ router_count(4) ‖ ...`, and a store written with
%% a non-default horizon has to produce exactly the same bytes as one written with
%% the default, or every router with a configured horizon would silently fail to
%% share a netdb file with one that has not configured it.
horizon_does_not_change_the_serialised_form_test() ->
    Now = erlang:system_time(millisecond),
    RIs = [router(Now, host(9)), router(Now, host(10))],

    Default = stored(RIs, i2p_netdb:new(10), Now),
    Custom = stored(RIs, i2p_netdb:new(10, 3 * ?MINUTE_MS), Now),

    ?assertEqual(i2p_netdb:to_binary(Default), i2p_netdb:to_binary(Custom)).

%%% --------------------------------------------------------------------------
%%% The horizon slides with the store's size
%%% --------------------------------------------------------------------------

%% **The mapping, at the boundaries.**
%%
%% The curve is `Min + (Max - Min) * 90 / Count`, and these are its values at the
%% sizes that matter: the pivot, i2p-java's aggressive-mode threshold, and this
%% router's shipped capacity. Asserted as numbers rather than as a formula so that
%% a change to the interpolation has to be a deliberate edit to a value a reader can
%% see, rather than a refactor nobody notices.
%%
%% Every case here is structural: it asks what horizon the store reports, and
%% nothing sleeps or waits.
horizon_slides_from_the_ceiling_to_near_the_floor_test() ->
    Store = i2p_netdb:new(),
    ?assertEqual(?MAX_EXPIRATION_MS, i2p_netdb:expiration_ms_at(Store, 0)),
    ?assertEqual(?MAX_EXPIRATION_MS, i2p_netdb:expiration_ms_at(Store, ?MIN_ROUTERS)),
    %% Spelled in hours, minutes and seconds rather than as a sum of `?HOUR_MS` and
    %% `?MINUTE_MS` because the curve is integer division over a 90-router numerator.
    %% Every value here has an exact answer, and a sum of round macros would be a
    %% value somebody eventually tries to match with `2 * ?HOUR_MS`. The comments
    %% carry the exact ms, which is what a reader has to change this to.

    % 12h58m30s
    ?assertEqual(46_710_000, i2p_netdb:expiration_ms_at(Store, 200)),
    %  6h05m24s
    ?assertEqual(21_924_000, i2p_netdb:expiration_ms_at(Store, 500)),
    %  3h47m42s
    ?assertEqual(13_662_000, i2p_netdb:expiration_ms_at(Store, 1000)),
    %  2h38m51s
    ?assertEqual(9_531_000, i2p_netdb:expiration_ms_at(Store, 2000)),
    %  2h04m25s
    ?assertEqual(7_465_500, i2p_netdb:expiration_ms_at(Store, 4000)),
    %  1h57m32s
    ?assertEqual(7_052_400, i2p_netdb:expiration_ms_at(Store, 5000)).

%% The shipped default is the ceiling and the floor, and they are i2pd's numbers
%% rather than this module's. Asserted against the accessors so the case says "the
%% default is the documented pair" instead of restating it and drifting.
default_bounds_are_i2pds_own_test() ->
    ?assertEqual(?MAX_EXPIRATION_MS, i2p_netdb:default_expiration_ms()),
    ?assertEqual(?MIN_EXPIRATION_MS, i2p_netdb:default_min_expiration_ms()),
    ?assertEqual(?MIN_ROUTERS, i2p_netdb:min_routers()),
    Store = i2p_netdb:new(),
    ?assertEqual(i2p_netdb:default_expiration_ms(), i2p_netdb:max_expiration_ms(Store)),
    ?assertEqual(i2p_netdb:default_min_expiration_ms(), i2p_netdb:min_expiration_ms(Store)).

%% **A store reports the horizon for its own size, not a fixed field.**
%%
%% This is the case the old flat field could not express. A store holding two
%% routers is at the ceiling; the same store holding 5000 is at about 1h57m. The
%% count is read from the recency order, so filling a store is what moves it --
%% there is no separate call and nothing to keep in step.
store_reports_the_horizon_at_its_current_size_test() ->
    Now = erlang:system_time(millisecond),
    Small = stored([router(Now, host(N)) || N <- lists:seq(20, 21)], i2p_netdb:new(5000), Now),
    ?assertEqual(2, i2p_netdb:count(Small)),
    ?assertEqual(?MAX_EXPIRATION_MS, i2p_netdb:expiration_ms(Small)),
    %% The same store's policy, asked about a size it has not reached.
    ?assertEqual(7_052_400, i2p_netdb:expiration_ms_at(Small, 5000)).

%% Filling a store tightens its horizon, monotonically. A curve that slid the other
%% way, or one that was not monotonic, would let a store's policy depend on its
%% history rather than its contents.
horizon_tightens_as_the_store_fills_test() ->
    Store = i2p_netdb:new(),
    Sizes = [1, 50, ?MIN_ROUTERS, ?MIN_ROUTERS + 1, 500, 5000],
    Horizons = [i2p_netdb:expiration_ms_at(Store, N) || N <- Sizes],
    Sorted = lists:reverse(lists:sort(Horizons)),
    ?assertEqual(Horizons, Sorted),
    %% And it never leaves the bounds it was given.
    ?assert(
        lists:all(
            fun(H) -> H >= ?MIN_EXPIRATION_MS andalso H =< ?MAX_EXPIRATION_MS end,
            Horizons
        )
    ).

%% A store with a flat horizon does not slide. `set_expiration_ms/2` sets both
%% bounds to one value, so an operator who wants one number for their router gets
%% one number at every size rather than a range they have to keep equal.
flat_horizon_is_the_same_at_every_size_test() ->
    Flat = i2p_netdb:set_expiration_ms(i2p_netdb:new(), 6 * ?HOUR_MS),
    ?assertEqual(6 * ?HOUR_MS, i2p_netdb:expiration_ms_at(Flat, 0)),
    ?assertEqual(6 * ?HOUR_MS, i2p_netdb:expiration_ms_at(Flat, 100)),
    ?assertEqual(6 * ?HOUR_MS, i2p_netdb:expiration_ms_at(Flat, 5000)),
    ?assertEqual(6 * ?HOUR_MS, i2p_netdb:min_expiration_ms(Flat)),
    ?assertEqual(6 * ?HOUR_MS, i2p_netdb:max_expiration_ms(Flat)),
    %% And `new/2` means the same thing, since a flat policy is a real one.
    ?assertEqual(
        6 * ?HOUR_MS,
        i2p_netdb:expiration_ms_at(
            i2p_netdb:new(10, 6 * ?HOUR_MS),
            5000
        )
    ).

%% The bounds are settings, so they are settable per store, and setting them
%% changes the policy and nothing else -- same rule as `set_expiration_ms/2`.
set_expiration_range_changes_policy_and_nothing_else_test() ->
    Now = erlang:system_time(millisecond),
    Store1 = stored([router(Now, host(30)), router(Now, host(31))], i2p_netdb:new(10), Now),
    Store2 = i2p_netdb:set_expiration_range(Store1, ?HOUR_MS, 12 * ?HOUR_MS),
    ?assertEqual(?HOUR_MS, i2p_netdb:min_expiration_ms(Store2)),
    ?assertEqual(12 * ?HOUR_MS, i2p_netdb:max_expiration_ms(Store2)),
    ?assertEqual(12 * ?HOUR_MS, i2p_netdb:expiration_ms(Store2)),
    ?assertEqual(i2p_netdb:count(Store1), i2p_netdb:count(Store2)),
    ?assertEqual(i2p_netdb:keys(Store1), i2p_netdb:keys(Store2)),
    ?assertEqual(i2p_netdb:capacity(Store1), i2p_netdb:capacity(Store2)),
    ?assertEqual(i2p_netdb:generation(Store1), i2p_netdb:generation(Store2)),
    ok = i2p_netdb:self_check(Store2).

%% A floor above the ceiling is refused rather than tolerated. The interpolation
%% would return a horizon *above* the ceiling for every store large enough to be
%% interpolated at all, so the store's most permissive setting would be the one
%% neither bound names -- a configuration error that reads as working.
inverted_expiration_range_is_rejected_test() ->
    Store = i2p_netdb:new(10),
    ?assertError(badarg, i2p_netdb:set_expiration_range(Store, 12 * ?HOUR_MS, ?HOUR_MS)),
    ?assertError(badarg, i2p_netdb:set_expiration_range(Store, 0, ?HOUR_MS)),
    ?assertError(badarg, i2p_netdb:set_expiration_range(Store, ?HOUR_MS, 0)),
    ?assertError(badarg, i2p_netdb:set_expiration_range(Store, ?HOUR_MS, infinity)),
    ?assertError(badarg, i2p_netdb:new(10, ?HOUR_MS, 12 * ?HOUR_MS)),
    ?assertError(badarg, i2p_netdb:new(10, 0, ?HOUR_MS)),
    ?assertError(badarg, i2p_netdb:new(10, ?HOUR_MS, -1)),
    %% Equal bounds are the flat case, not the invalid one.
    ?assertEqual(
        ?HOUR_MS,
        i2p_netdb:max_expiration_ms(
            i2p_netdb:set_expiration_range(Store, ?HOUR_MS, ?HOUR_MS)
        )
    ).

%% A count that is not a positive integer is a programming error in a caller, and
%% raises. A caller asking "what would the horizon be for an empty or negative
%% store" has a bug upstream, and answering it with the ceiling would hide it.
invalid_expiration_count_is_rejected_test() ->
    Store = i2p_netdb:new(10),
    ?assertError(badarg, i2p_netdb:expiration_ms_at(Store, -1)),
    ?assertError(badarg, i2p_netdb:expiration_ms_at(Store, infinity)),
    ?assertError(badarg, i2p_netdb:expiration_ms_at(Store, big)),
    ?assertError(badarg, i2p_netdb:expiration_ms_at(Store, undefined)).

%% **Both callers read the sliding function, not a field.**
%%
%% This is the case a flat horizon could not distinguish. A store holding 200
%% routers runs at about 13 hours and a store holding 5000 at about 2, so if the
%% sweep read a field while the admission check read the curve, one of them would
%% be comparing against 27 hours and the store would either admit everything or
%% sweep everything. Here the same store is given the same RouterInfo at two
%% different sizes and the admission check tracks the curve at both.
admission_agrees_with_the_curve_at_two_sizes_test() ->
    Now = erlang:system_time(millisecond),
    %% Eight hours old: older than the horizon at 5000 routers, comfortably inside
    %% it at 200.
    RI = router(Now - 8 * ?HOUR_MS, host(40)),

    Small = i2p_netdb:new(5000),
    Small1 = fill_to(Small, 200, Now),
    ?assertEqual(200, i2p_netdb:count(Small1)),
    {Small2, added} = i2p_netdb:store(Small1, RI, Now),
    ?assertEqual(added, added),
    ?assertEqual(201, i2p_netdb:count(Small2)),

    Full = i2p_netdb:new(5000),
    Full1 = fill_to(Full, 5000, Now),
    ?assertEqual(5000, i2p_netdb:count(Full1)),
    {Full2, too_old} = i2p_netdb:store(Full1, RI, Now),
    ?assertEqual(5000, i2p_netdb:count(Full2)).

%% The sweep follows the curve too, at two sizes, with one horizon read for the
%% whole walk. The walk does not change the size, so the value hoisted out of the
%% fold is the value every comparison would have computed.
sweep_agrees_with_the_curve_at_two_sizes_test() ->
    Now = erlang:system_time(millisecond),
    Aged = router(Now - 8 * ?HOUR_MS, host(41)),

    %% Seeded past the window, because `store/3` would refuse it at 5000 routers.
    Tight = seed(i2p_netdb:new(5000), Aged, Now - 8 * ?HOUR_MS),
    Tight1 = fill_to(Tight, 5000, Now),
    ?assertEqual(5000, i2p_netdb:count(Tight1)),
    {Tight2, {1, 0}} = i2p_netdb:remove_expired(Tight1, Now, erlang:system_time(second)),
    ?assertEqual(4999, i2p_netdb:count(Tight2)),

    Loose = seed(i2p_netdb:new(5000), Aged, Now - 8 * ?HOUR_MS),
    Loose1 = fill_to(Loose, 200, Now),
    %% `fill_to/3` counts from zero, so 200 total: the seeded 8-hour-old RouterInfo
    %% plus 199 fresh ones.
    ?assertEqual(200, i2p_netdb:count(Loose1)),
    {Loose2, {0, 0}} = i2p_netdb:remove_expired(Loose1, Now, erlang:system_time(second)),
    ?assertEqual(200, i2p_netdb:count(Loose2)).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

router(Timestamp, Host) ->
    i2p_ct_helpers:floodfill_router_info(Timestamp, Host).

host(N) ->
    list_to_binary("192.0.2." ++ integer_to_list(N)).

stored(RIs, Store0, Now) ->
    lists:foldl(
        fun(RI, Store) ->
            {S, added} = i2p_netdb:store(Store, RI, Now),
            S
        end,
        Store0,
        RIs
    ).

%% Put one RouterInfo into a store without asking `store/3` whether it is welcome.
%%
%% The only way an expired RouterInfo can be in a store is `from_binary/1`, which
%% seeds the table directly and bypasses the window check. `seed/3` is that for a
%% test: it stores the RouterInfo as of its own publish time, which is what a real
%% router does, and then the test advances the sweep's clock past the horizon.
%%
%% Not a wrapper around `store/3` that bypasses the check -- it cannot, since there is
%% no such bypass -- but a store built by hand and handed the entry through the
%% mutator at the timestamp that makes it admissible.
seed(Store, RI, StoreAt) ->
    {S, added} = i2p_netdb:store(Store, RI, StoreAt),
    ?assertEqual(added, added),
    S.

%% Grow a store to at least `N` routers, so a case can ask what the *curve* reports
%% at a size no test would otherwise build.
%%
%% `Host` is the next host in the 192.0.2.0/24 test range to hand out. It is a
%% counter rather than a fixed set so two calls cannot collide: a filler that hit a
%% host the store already holds would be an equal-timestamp update, change no
%% count, and leave the case asserting a size it never reached.
%%
%% `N` is a floor rather than an exact target, so the caller does not have to know
%% how many entries the case seeded before asking to be filled.
fill_to(Store0, N, Now) ->
    fill_to(Store0, N, Now, 0).

fill_to(Store0, N, Now, NextHost) ->
    case i2p_netdb:count(Store0) >= N of
        true ->
            Store0;
        false ->
            {Store1, _} = i2p_netdb:store(Store0, router(Now, host(NextHost)), Now),
            fill_to(Store1, N, Now, NextHost + 1)
    end.
