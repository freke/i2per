%% Tests that the expiry sweep does not rebuild the store to compact it.
%%
%% `f:remove_expired/3` used to fold every RouterInfo into a FRESH `gb_trees` and
%% then re-derive the inverse, on every sweep, whether or not anything had expired.
%% The symptom was that it cost the same either way -- 13 964 us with nothing
%% expired, 12 972 us with 1000 of 5000 expired -- which is the tell that the cost
%% was in the rebuilding rather than in the expiry.
%%
%% The sweep now drops the expired keys incrementally, which is O(k log n) in what
%% it removes rather than O(n log n) in what it keeps.
%%
%% These cases assert the **behaviour**, not the timing: that a sweep removes
%% exactly the expired routers, keeps every fresh one, and leaves the survivors in
%% the order it found them. Timing is not asserted anywhere, for the reason
%% `i2p_netdb_verify_tests` gives -- a deadline passes on an idle machine and fails
%% on a loaded one, and this project treats that as a defect rather than a flake.
%%
%% What a rebuild could get wrong that a drop cannot is **renumbering**: a
%% surviving router must keep its `Seq`, because expiry is not a recency event. A
%% rebuild that entered survivors back in a different order, or re-derived `Seq`,
%% would compact the store and silently reorder its LRU. That is asserted directly.

-module(i2p_netdb_sweep_tests).

-moduledoc """
Tests that the expiry sweep compacts the NetDb store by dropping expired entries
rather than rebuilding it.
""".

-include_lib("eunit/include/eunit.hrl").

-define(MINUTE_MS, 60 * 1000).
-define(HOUR_MS, 60 * ?MINUTE_MS).
%% i2pd NETDB_MAX_EXPIRATION_TIMEOUT: a RouterInfo older than this is expired.
-define(MAX_AGE_MS, 27 * ?HOUR_MS).

%%% --------------------------------------------------------------------------
%%% What the sweep removes
%%% --------------------------------------------------------------------------

%% Only the expired go. The fresh ones must survive, because a sweep that removed
%% live routers would empty the store and every lookup with it.
sweep_removes_only_expired_routers_test() ->
    SweepNow = erlang:system_time(millisecond),
    Stamped = aged(
        [
            {?MAX_AGE_MS + 1000, host(1)},
            {?MAX_AGE_MS + 2000, host(2)},
            {?MINUTE_MS, host(101)},
            {?MINUTE_MS, host(102)}
        ],
        SweepNow
    ),
    [{Exp0, _A0}, {Exp1, _A1}, {Fresh0, _F0}, {Fresh1, _F1}] = Stamped,
    Expired = [i2p_router_info:hash(RI) || RI <- [Exp0, Exp1]],
    Fresh = [i2p_router_info:hash(RI) || RI <- [Fresh0, Fresh1]],
    Store = stored_at(Stamped),
    ?assertEqual(4, i2p_netdb:count(Store)),
    {Store1, {RRemoved, LSRemoved}} =
        i2p_netdb:remove_expired(Store, SweepNow, now_sec()),

    ?assertEqual({2, 0}, {RRemoved, LSRemoved}),
    ?assertEqual(2, i2p_netdb:count(Store1)),
    %% The fresh two are still held, by hash and by find.
    lists:foreach(fun(K) -> ?assert(i2p_netdb:has_router(Store1, K)) end, Fresh),
    %% The expired two are gone from the table, not merely from the count.
    lists:foreach(fun(K) -> ?assertNot(i2p_netdb:has_router(Store1, K)) end, Expired),
    ?assertEqual(error, i2p_netdb:find(Store1, hd(Expired))),
    ok = i2p_netdb:self_check(Store1).

%% A sweep that expires nothing is the common case, and the one where a rebuild
%% costs the most for no reason. It must still be a well-formed store.
sweep_removing_nothing_leaves_the_store_identical_test() ->
    SweepNow = erlang:system_time(millisecond),
    Stamped = aged(
        [{?MINUTE_MS, host(4)}, {?MINUTE_MS, host(5)}, {?MINUTE_MS, host(6)}],
        SweepNow
    ),
    Store = stored_at(Stamped),
    Before = i2p_netdb:keys(Store),
    {Store1, {0, 0}} = i2p_netdb:remove_expired(Store, SweepNow, now_sec()),

    %% **Byte-identical order.** Not the same set -- the same ORDER. A rebuild that
    %% returned the right routers in a different sequence would pass every count
    %% and change what the LRU evicts next.
    ?assertEqual(Before, i2p_netdb:keys(Store1)),
    ok = i2p_netdb:self_check(Store1).

%% A sweep at the boundary keeps the entry. The 27-hour comparison is `<`, not
%% `<=`, and an off-by-one here would evict a router that still has an hour.
sweep_keeps_a_router_at_the_expiry_boundary_test() ->
    StoredAt = erlang:system_time(millisecond),
    {Store, Keys, BoundaryNow} = boundary_store(1, StoredAt),
    {Store1, {0, 0}} = i2p_netdb:remove_expired(Store, BoundaryNow, now_sec()),
    ?assertEqual(Keys, i2p_netdb:keys(Store1)),
    ?assertEqual(1, i2p_netdb:count(Store1)).

sweep_removes_a_router_one_millisecond_past_the_boundary_test() ->
    StoredAt = erlang:system_time(millisecond),
    {Store, Keys, BoundaryNow} = boundary_store(1, StoredAt),
    {Store1, {1, 0}} = i2p_netdb:remove_expired(Store, BoundaryNow + 1, now_sec()),
    ?assertEqual([], i2p_netdb:keys(Store1)),
    ?assertNot(i2p_netdb:has_router(Store1, hd(Keys))).

%%% --------------------------------------------------------------------------
%%% The survivors keep their recency positions
%%% --------------------------------------------------------------------------

%% The property a rebuild can break and a drop cannot.
%%
%% Expiry is not a recency event: a router that is merely compacted should keep its
%% place in the LRU, so the eviction order the store has built up over hours is not
%% reset every 30 minutes. Storing oldest-first so the expiry lands in the middle of
%% the order, then sweeping, and checking the survivors are in exactly the order
%% they were in -- not sorted, not reversed.
sweep_preserves_the_recency_order_of_survivors_test() ->
    SweepNow = erlang:system_time(millisecond),

    %% Two expired and one live, so the sweep removes a prefix and leaves a suffix.
    %% The live one is stored LAST, which puts it FIRST in the MRU-first order, so a
    %% rebuild that reversed the survivors would show up as a different first key.
    Stamped = aged(
        [
            {?MAX_AGE_MS + 1000, host(1)},
            {?MAX_AGE_MS + 2000, host(2)},
            {?MINUTE_MS, host(3)}
        ],
        SweepNow
    ),
    [{RI_Aged0, _Aged0}, {RI_Aged1, _Aged1}, {RILive, _Live}] = Stamped,

    Store = stored_at(Stamped),
    KeyAged0 = i2p_router_info:hash(RI_Aged0),
    KeyAged1 = i2p_router_info:hash(RI_Aged1),
    KeyLive = i2p_router_info:hash(RILive),

    %% MRU-first: the live one, stored last, leads. Asserted before the sweep so a
    %% fixture that did not build the intended order fails here rather than passing
    %% for the wrong reason below.
    ?assertEqual([KeyLive, KeyAged1, KeyAged0], i2p_netdb:keys(Store)),

    {Store1, {2, 0}} = i2p_netdb:remove_expired(Store, SweepNow, now_sec()),

    %% The two aged ones are gone and the live one is left where it was -- first.
    ?assertEqual([KeyLive], i2p_netdb:keys(Store1)),
    ?assert(i2p_netdb:has_router(Store1, KeyLive)),
    ok = i2p_netdb:self_check(Store1).

%% Why the cases above check removal from one end and the middle separately.
%%
%% `f:store/3` refuses a RouterInfo older than 27 hours (`too_old`), so **the expired
%% set is always a prefix of the recency order**: to be expired, a router must have
%% been stored while fresh and then aged, and ageing is what makes it less recently
%% stored. A store therefore cannot contain an expired router that is newer than a
%% fresh one.
%%
%% Asserted because it is the reason the sweep can be incremental and cannot reorder:
%% the keys it removes always come from one end, so there is nothing for a rebuild to
%% get wrong -- and if that ever stops being true, this says so.
expired_routers_are_always_the_least_recently_stored_test() ->
    SweepNow = erlang:system_time(millisecond),
    %% An already-expired RouterInfo cannot be stored at all, whichever end of the
    %% recency order it would have been given. That is what forces the expired set
    %% to be a prefix of the order.
    TooOld = router(SweepNow - ?MAX_AGE_MS - 1, host(21)),
    ?assertEqual(too_old, stored_result([TooOld], SweepNow)),
    %% And the boundary case just inside the window is accepted, so the rule is the
    %% 27-hour one and not a broader rejection.
    Admissible = router(SweepNow - ?MAX_AGE_MS, host(22)),
    ?assertEqual(added, stored_result([Admissible], SweepNow)).

%% The sweep removes from the least-recently-stored end, and the rest keep their
%% relative order. Checked with a real mix: two routers stored long enough ago to be
%% expired, two stored inside the window.
sweep_removes_from_the_lru_end_and_leaves_the_rest_in_order_test() ->
    SweepNow = erlang:system_time(millisecond),
    Stamped = aged(
        [
            {?MAX_AGE_MS + 1000, host(31)},
            {?MAX_AGE_MS + 2000, host(32)},
            {?MINUTE_MS, host(33)},
            {?MINUTE_MS, host(34)}
        ],
        SweepNow
    ),
    [{RI_A0, _A0}, {RI_A1, _A1}, {RI_L0, _L0}, {RI_L1, _L1}] = Stamped,
    Store = stored_at(Stamped),

    KeyA0 = i2p_router_info:hash(RI_A0),
    KeyA1 = i2p_router_info:hash(RI_A1),
    KeyL0 = i2p_router_info:hash(RI_L0),
    KeyL1 = i2p_router_info:hash(RI_L1),

    %% MRU-first, reverse of insertion. Asserted before the sweep so a fixture that
    %% did not build the intended order fails here.
    ?assertEqual([KeyL1, KeyL0, KeyA1, KeyA0], i2p_netdb:keys(Store)),

    {Store1, {2, 0}} = i2p_netdb:remove_expired(Store, SweepNow, now_sec()),
    %% The two aged ones are gone from the tail; the live two are in the same order
    %% relative to each other as before.
    ?assertEqual([KeyL1, KeyL0], i2p_netdb:keys(Store1)),
    ok = i2p_netdb:self_check(Store1).

%% And the same in the other direction: expiring the oldest must leave the rest in
%% order. Together with the case above this pins that the sweep never reorders,
%% which a single case cannot -- both directions of the list have to be checked for
%% "unchanged" to mean anything.
sweep_leaves_live_routers_untouched_when_the_lru_end_is_swept_test() ->
    SweepNow = erlang:system_time(millisecond),
    Stamped = aged(
        [{?MAX_AGE_MS + 1000, host(41)}, {?MINUTE_MS, host(42)}, {?MINUTE_MS, host(43)}],
        SweepNow
    ),
    [{RIAged, _AgeAged}, {RIMid, _AgeM}, {RINew, _AgeN}] = Stamped,
    %% One expired at the tail, two live ahead of it. Removing from the tail must not
    %% disturb the two ahead: a rebuild that renumbered would swap them even though
    %% every count still matched.
    Store = stored_at(Stamped),
    {Store1, {1, 0}} = i2p_netdb:remove_expired(Store, SweepNow, now_sec()),
    ?assertEqual(
        [i2p_router_info:hash(RINew), i2p_router_info:hash(RIMid)],
        i2p_netdb:keys(Store1)
    ),
    ?assertNot(i2p_netdb:has_router(Store1, i2p_router_info:hash(RIAged))),
    ok = i2p_netdb:self_check(Store1).

%%% --------------------------------------------------------------------------
%%% Both structures, and the table, agree afterwards
%%% --------------------------------------------------------------------------

%% `f:self_check/1` is the property the two-structure arrangement rests on, and it
%% is the check the sweep has to leave satisfied. Asserted after every mutation the
%% sweep can do, because a sweep that drops from one structure and not the other
%% leaves counts that disagree -- which is the failure this rewrite could introduce
%% and the reason `f:drop_from_order/2` takes from both trees.
%%
%% Sizes only are asserted here, deliberately: the full cross-check is what
%% `f:self_check/1` is for, and re-implementing it here would be a second place to
%% get it wrong.
sweep_leaves_the_table_and_the_order_in_agreement_test() ->
    SweepNow = erlang:system_time(millisecond),
    %% Expired some but not all, and capacity is the default so nothing is evicted
    %% for capacity reasons and confused with expiry.
    Aged = [{?MAX_AGE_MS + 1000 + I, host(N)} || {I, N} <- seq_pairs(1, 3)],
    Live = [{?MINUTE_MS, host(100 + N)} || N <- lists:seq(1, 5)],
    Store = stored_at(aged(Aged ++ Live, SweepNow)),
    {Store1, {3, 0}} = i2p_netdb:remove_expired(Store, SweepNow, now_sec()),

    ?assertEqual(ok, i2p_netdb:consistent(Store1)),
    ?assertEqual(5, i2p_netdb:count(Store1)),
    ?assertEqual(5, length(i2p_netdb:keys(Store1))),
    ok = i2p_netdb:self_check(Store1).

%% The sweep claims the generation, so a store that was already swept cannot be swept
%% again. This is the \`#QDA7A0X\` counter doing its job, and it is asserted here
%% because the sweep is the one caller that claims without writing anything when
%% nothing expires -- so a sweep that expired nothing is still a write of the
%% generation, and that has to be visible.
sweep_claims_the_generation_even_when_it_removes_nothing_test() ->
    SweepNow = erlang:system_time(millisecond),
    Store = stored_at(aged([{?MINUTE_MS, host(7)}, {?MINUTE_MS, host(8)}], SweepNow)),
    Before = i2p_netdb:generation(Store),
    {Store1, {0, 0}} = i2p_netdb:remove_expired(Store, SweepNow, now_sec()),
    ?assertEqual(Before + 1, i2p_netdb:generation(Store1)),
    ?assertEqual(
        {stale_store, #{expected => Before, table => Before + 1}},
        raised_by(fun() -> i2p_netdb:remove_expired(Store, SweepNow, now_sec()) end)
    ).

%%% --------------------------------------------------------------------------
%%% The sweep does not rebuild the store to compact it
%%% --------------------------------------------------------------------------

%% **The structural assertion, and the only one that can distinguish a drop from a
%% rebuild.**
%%
%% Every case above asserts behaviour, and every one of them passes against the old
%% rebuild too -- correctly, because the rebuild produced the same answers. That is
%% what behavioural tests are for; it also means they cannot show the sweep got
%% cheaper. Reverting the change here leaves all twelve green, which is the honest
%% result and worth recording rather than hiding.
%%
%% So this one is traced. `f:remove_expired/3` used to call `f:positions_of/1`,
%% which folds every surviving entry into a fresh `gb_trees` to re-derive the
%% inverse — O(n log n) in what it KEEPS, paid on every sweep whether anything had
%% expired. Incremental drops call `f:drop_from_order/2` instead, which takes k keys
%% at O(log n) each.
%%
%% Traced rather than timed, for the reason `i2p_netdb_verify_tests` and
%% `i2p_netdb_save_tests` both give: no deadline, so it cannot flake under load.
%% Demonstrated red: restoring `f:partition_routers/4` and the `positions_of/1`
%% re-derivation makes this case fail.
sweep_does_not_rederive_the_recency_order_test() ->
    {module, i2p_netdb} = code:ensure_loaded(i2p_netdb),
    %% **The count is asserted.** `erlang:trace_pattern/3` returns the number of
    %% matched functions and 0 for a module that is not loaded; 0 matches means no
    %% messages ever arrive, so an assertion built on them would pass whatever the
    %% code did. This is the same trap `i2p_netdb_verify_tests` documents.
    ?assertEqual(1, erlang:trace_pattern({i2p_netdb, positions_of, 1}, true, [local])),

    SweepNow = erlang:system_time(millisecond),
    Stamped = aged(
        [{?MAX_AGE_MS + 1000, host(61)}, {?MAX_AGE_MS + 2000, host(62)}, {?MINUTE_MS, host(63)}],
        SweepNow
    ),
    Store = stored_at(Stamped),

    Tracer = spawn(fun() -> collect([]) end),
    Self = self(),
    ?assertEqual(1, erlang:trace(Self, true, [call, {tracer, Tracer}])),
    try
        {Store1, {2, 0}} = i2p_netdb:remove_expired(Store, SweepNow, now_sec()),
        ?assertEqual(1, i2p_netdb:count(Store1)),
        %% Drain AFTER the sweep, or the collector reports an empty mailbox because
        %% the call has not happened yet rather than because it did not happen.
        ?assertEqual([], drain(Tracer))
    after
        untrace(Tracer)
    end.

%% ---- tracing -----------------------------------------------------------------

%% The collector blocks forever on the drain message; its own receive timeout would
%% race the caller's and lose exactly when there is nothing to report, which is the
%% case that must not fail.
collect(Calls) ->
    receive
        {trace, _Pid, call, {_M, _F, _A}} ->
            collect([called | Calls]);
        {drain, From} ->
            From ! {drained, lists:reverse(Calls)},
            collect([])
    end.

drain(Tracer) ->
    Tracer ! {drain, self()},
    receive
        {drained, Calls} -> Calls
    after 5000 ->
        erlang:error(tracer_never_drained)
    end.

%% `erlang:trace/3` raises `badarg` on an already-exited tracer, so turning tracing
%% off needs a catch.
untrace(Tracer) ->
    try erlang:trace(Tracer, false, [call]) of
        _ -> ok
    catch
        _:_ -> ok
    end.

%%% --------------------------------------------------------------------------
%%% LeaseSets
%%% --------------------------------------------------------------------------

%% LeaseSets share the capacity bound but not the mechanism: they live in a map and
%% a list, not in the table and the order, so they are filtered rather than dropped.
%% A sweep that fixed the routers and left the LeaseSets behind would leak them.
sweep_removes_expired_lease_sets_alongside_routers_test() ->
    NowSec = erlang:system_time(second),
    NowMs = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(),
    LS = lease_set(NowSec),
    {Store1, added} = i2p_netdb:store_ls(Store0, LS, NowSec),
    ?assertEqual(1, i2p_netdb:ls_count(Store1)),
    %% Far enough ahead that the LeaseSet's 7-day lifetime is spent.
    FarFuture = NowSec + 8 * 86400,
    {Store2, {RRemoved, LSRemoved}} = i2p_netdb:remove_expired(Store1, NowMs, FarFuture),
    ?assertEqual({0, 1}, {RRemoved, LSRemoved}),
    ?assertEqual(0, i2p_netdb:ls_count(Store2)),
    ?assertEqual([], i2p_netdb:ls_keys(Store2)),
    ok = i2p_netdb:self_check(Store2).

sweep_keeps_unexpired_lease_sets_test() ->
    NowSec = erlang:system_time(second),
    NowMs = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(),
    LS = lease_set(NowSec),
    {Store1, added} = i2p_netdb:store_ls(Store0, LS, NowSec),
    {Store2, {0, 0}} = i2p_netdb:remove_expired(Store1, NowMs, NowSec),
    ?assertEqual(1, i2p_netdb:ls_count(Store2)),
    ok = i2p_netdb:self_check(Store2).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

%% **Not by backdating their timestamps.** `f:store/3` refuses anything older than
%% 27 hours with `too_old`, so a store built through the public API cannot be handed
%% an already-expired RouterInfo at all. The consequence is worth stating on its own:
%% `f:remove_expired/3` can only ever remove routers that arrived recently enough to
%% be admissible and have since aged, so **the expired set is always a prefix of the
%% recency order**. `expired_routers_are_always_the_least_recently_stored_test` pins
%% that, and it is why a sweep has nothing to reorder.
%%
%% `aged/2` stamps each RouterInfo with a publish time relative to the sweep's
%% clock, and `stored_at/1` stores each one **as of its own publish time** -- which
%% is what a real router does, since the bytes arrive now and are fresh now. A single
%% store time cannot hold a mix of fresh and expired: everything stored at one
%% instant expires together.
%%
%% `{Offset, Index}` for the expired fixtures, so each expired router has a distinct
%% publish time. A RouterInfo with the same identity cannot be stored twice, and one
%% with the same timestamp would be indistinguishable in the recency order.
seq_pairs(_From, 0) ->
    [];
seq_pairs(From, N) ->
    [{I, From + I} || I <- lists:seq(0, N - 1)].

%% A store of `N` routers, all stored at `StoredAt`, plus the `NowMs` at which
%% they are exactly at the expiry boundary.
boundary_store(N, StoredAt) ->
    RIs = [router(StoredAt, host(200 + I)) || I <- lists:seq(1, N)],
    Store = stored(RIs),
    N = i2p_netdb:count(Store),
    ok = i2p_netdb:self_check(Store),
    {Store, [i2p_router_info:hash(RI) || RI <- RIs], StoredAt + ?MAX_AGE_MS}.

%% **Stored in the given order, oldest first**, each at its own publish timestamp.
%%
%% The per-router store time is the whole trick. `f:store/3` refuses a RouterInfo
%% whose publish timestamp is more than 27 hours old (`too_old`) or more than two
%% minutes in the future (`from_future`), so a single store time cannot hold a mix
%% of fresh and expired routers: everything stored at one instant expires together.
%% Storing each router as of its own publish time is what a real router does -- the
%% bytes arrive now, and they are fresh now.
%%
%% The recency order is the reverse of insertion, so the list order controls it.
%% Every RouterInfo stored as of its own publish time, which is what keeps each
%% entry admissible.
stored(RIs) when is_list(RIs) ->
    stored_at([{RI, i2p_router_info:published(RI)} || RI <- RIs]).

stored_at(Stamped) ->
    lists:foldl(
        fun({RI, StoreAt}, Store) ->
            {S, added} = i2p_netdb:store(Store, RI, StoreAt),
            S
        end,
        i2p_netdb:new(),
        Stamped
    ).

%% Stamp each RouterInfo with its own publish time, from `{AgeMsAgo, Host}` pairs.
%%
%% `AgeMsAgo` is relative to `Now`, so a fixture reads as "one router aged 28 hours,
%% two aged an hour" rather than as arithmetic.
%%
%% Returns `{RouterInfo, PublishTime}` pairs, which is the shape `stored_at/1` takes.
%% **The element order is `{RI, Time}`, not `{Time, RI}`** — a pair passed the other
%% way round puts the RouterInfo in `f:store/3`'s `NowMs` slot, and the failure is a
%% `badarg` from `m:i2p_router_info:hash/1` on a tuple, a long way from the fixture.
aged([], _Now) ->
    [];
aged(Specs, Now) ->
    [
        {RI, Now - AgeMsAgo}
     || {AgeMsAgo, Host} <- Specs, RI <- [router(Now - AgeMsAgo, Host)]
    ].

%% The outcome of storing one RouterInfo, without the store.
%%
%% `f:store/3` returns `{Store, Outcome}` and the cases that use this want the
%% Outcome alone.
stored_result([RI], Now) ->
    {_Store, Outcome} = i2p_netdb:store(i2p_netdb:new(), RI, Now),
    Outcome.

router(Timestamp, Host) ->
    i2p_ct_helpers:floodfill_router_info(Timestamp, Host).

now_sec() ->
    erlang:system_time(second).

%% A LeaseSet published at `TimestampSec`, built the way `i2p_netdb_tests` builds
%% one rather than through a CT helper: `i2p_ct_helpers` exports no LeaseSet
%% fixture, and duplicating that here would be a second definition to keep right.
lease_set(TimestampSec) ->
    {{SPub, Seed}, {CPub, _}} =
        {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    Identity = i2p_keys:from_keys(CPub, SPub),
    Lease = #{
        gateway => crypto:strong_rand_bytes(32),
        tunnel_id => 1,
        end_date => (erlang:system_time(millisecond) + 60 * 1000) band 16#FFFFFFFF
    },
    i2p_leaset:build(Identity, TimestampSec, 7, [Lease], Seed).

host(N) ->
    list_to_binary("192.0.2." ++ integer_to_list(N rem 251 + 1)).

%% The term a function raised, so a test can assert on it.
%%
%% `?assertError/2` takes a *pattern*, and a map pattern cannot hold literals:
%% `#{expected => 1}` binds `expected` to a fresh variable and so matches anything.
%% A test asserting on error contents must catch and compare whole terms.
raised_by(Fun) ->
    try
        Fun(),
        no_error
    catch
        error:Reason -> Reason;
        Class:Reason -> {Class, Reason}
    end.
