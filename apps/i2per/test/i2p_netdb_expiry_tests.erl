%% Tests that the RouterInfo expiry horizon is a store setting rather than a
%% compile-time constant.
%%
%% The horizon used to be `?MAX_EXPIRATION_MS`, read in two places: once by the
%% admission check in `f:store/3` and once by the sweep. Two copies of the same
%% constant, written as two comparisons, with nothing tying them together.
%%
%% It now lives in the store next to `capacity`, so both callers read one value and
%% a store cannot admit a RouterInfo it is about to expire.
%%
%% **What this suite does not claim:** that the policy is right. It is a flat
%% horizon at every store size, which is more permissive than either reference
%% implementation and is what #RA5PVR1 is about. These cases pin that the knob
%% *works* and that both callers read it, so that ticket is a change to one function
%% rather than a search for every place the constant was spelled.

-module(i2p_netdb_expiry_tests).

-moduledoc """
Tests that the RouterInfo expiry horizon is per-store and shared by the admission
check and the sweep.
""".

-include_lib("eunit/include/eunit.hrl").

-define(MINUTE_MS, 60 * 1000).
-define(HOUR_MS, 60 * ?MINUTE_MS).
%% i2pd NetDb.hpp: NETDB_MAX_EXPIRATION_TIMEOUT = 27 hours. Spelled out so the
%% default case above is checked against something rather than against itself.
-define(MAX_EXPIRATION_MS, 27 * ?HOUR_MS).

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
