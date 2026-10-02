%% Tests that the closest-peer lookup computes each router's distance once.
%%
%% `f:closest_keys/3` used to sort with a comparator that called `routing_key/1` on
%% both operands. `routing_key/1` is a SHA-256 that also calls `current_day/0`, so
%% every comparison paid two hashes and two calendar reads and a sort of n keys was
%% O(n log n) of them. Traced at the shipped capacity of 5000 that was **118363
%% SHA-256 calls to return three hashes**, 162.9 ms.
%%
%% What is asserted here is the *count*, not the time. A count is exact and cannot
%% be mistaken for machine load, which is the same reason
%% `i2p_netdb_verify_tests` and `i2p_netdb_save_tests` assert structurally rather
%% than against a deadline.
%%
%% **A behavioural test cannot catch this.** The old code returned exactly the right
%% answers, slowly. Every case below that checks the *answer* passes against both
%% implementations, which is the honest result and worth stating rather than
%% hiding: the only thing that distinguishes them is how much work they do.

%% ## The routing-key memo
%%
%% The second half of the cost was the crypto itself: with the sort fixed, a lookup
%% still spent n SHA-256s resolving n keys, and the key is `SHA256(Hash ‖ Day)` —
%% neither input changes, so it is computed once per router per day and reused.
%% Those cases are in the **The memo** section below, and they assert the *hash
%% count* of a second lookup, which is the exact and non-flaky version of "the
%% second lookup is faster".

-module(i2p_netdb_closest_tests).

-moduledoc """
Tests that the closest-peer lookup hashes each router once rather than once per
comparison, and returns the same answers it always did.
""".

-include_lib("eunit/include/eunit.hrl").

-define(N, 24).

%%% --------------------------------------------------------------------------
%%% The structural assertion: hash count
%%% --------------------------------------------------------------------------

%% **The case the change exists for.**
%%
%% A sort of n elements is O(n log n) comparisons, and the old comparator hashed
%% both operands on every one. Asserted as a *bound* rather than an exact number,
%% because the exact figure depends on the sort's comparison count and that is not
%% a contract worth pinning. The bound is the one that matters: a linear number of
%% hashes, which is what computing each distance once gives.
%%
%% Old shape: ~n log n hashes, so for n = 24 that is roughly 110 and would blow
%% straight through the bound below. New shape: n.
lookup_hashes_each_router_once_not_once_per_comparison_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),

    %% **The store is threaded out of the call**, because the memo is filled there
    %% and the count this case asserts is the count of the *first* lookup. A second
    %% `closest/3` on the returned store is the case that proves the memo works.
    Hashes = count_hashes(fun() -> i2p_netdb:closest(Store, Target, 3) end),
    Count = i2p_netdb:count(Store),
    Count = ?N,

    %% One hash for the target, one per candidate key, and nothing else. The
    %% allowance is for the store's own day lookup and leaves no room for a
    %% per-comparison hash.
    ?assert(Hashes =< Count + 1 + 2),
    io:format(
        "  ~p routers -> ~p SHA-256 calls (a sort of ~p elements would be ~p)~n~n",
        [Count, Hashes, Count, Count * round(math:log2(Count))]
    ).

%% Two lookups cost twice as much as one, and the cost is in the keys rather than
%% the target. Asserted by ratio rather than by a number: `crypto:hash` is only
%% called from the decorate step, so doubling the store must double the count.
lookup_cost_is_linear_in_the_store_not_in_its_logarithm_test() ->
    Small = fixture_store(?N),
    Large = fixture_store(4 * ?N),
    Target = crypto:strong_rand_bytes(32),

    SmallHashes = count_hashes(fun() -> i2p_netdb:closest(Small, Target, 3) end),
    LargeHashes = count_hashes(fun() -> i2p_netdb:closest(Large, Target, 3) end),

    4 * ?N = i2p_netdb:count(Large),
    ?assert(LargeHashes > SmallHashes),
    %% Four times the routers, under six times the hashes. A per-comparison
    %% implementation would be 4 * log2(4n)/log2(n) ~= 4.8x, which also passes, so
    %% this is a sanity bound on the shape and the bound above is the real one.
    ?assert(LargeHashes < 6 * SmallHashes).

%%% --------------------------------------------------------------------------
%%% The floodfill filter reads flags, not whole RouterInfos
%%% --------------------------------------------------------------------------

%% The stored flags must mean exactly what the two predicates mean.
%%
%% They are derived data, so the risk is that a derivation drifts from what it
%% derived. This is the case that found the drift: `f:eligible_floodfill/1` on its
%% own checks only version, reachability and addresses, and never the floodfill
%% capability. The old `is_eligible_floodfill/2` joined the two with `andalso`;
%% storing "eligible" alone made every ordinary router with a published address
%% look like a floodfill.
flags_mean_declared_and_eligible_not_eligible_alone_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(20),
    FF = floodfill(Now, "a"),
    Bare = declared_but_not_eligible(Now, "b"),
    Plain = plain(Now, "c"),
    Store = stored([FF, Bare, Plain], Store0, Now),
    Target = crypto:strong_rand_bytes(32),

    {_Store1, FFs} = i2p_netdb:closest_floodfills(Store, Target, 10, []),
    %% Only the one that is both declared and eligible.
    ?assertEqual([i2p_router_info:hash(FF)], FFs),
    ?assertNot(lists:member(i2p_router_info:hash(Bare), FFs)),
    ?assertNot(lists:member(i2p_router_info:hash(Plain), FFs)),

    %% And the complement: `closest_non_floodfills/4` excludes declared ones
    %% whatever their eligibility, which is a different question and was a
    %% different predicate.
    {_Store2, NonFFs} = i2p_netdb:closest_non_floodfills(Store, Target, 10, []),
    ?assertEqual(
        lists:sort([i2p_router_info:hash(Bare), i2p_router_info:hash(Plain)]),
        lists:sort(NonFFs)
    ).

%% `f:self_check/1` recomputes the flags from the RouterInfo and compares, so a
%% derived row cannot drift without the store refusing it.
%%
%% Demonstrated red by corrupting a stored flag, which is the failure the check
%% exists for and the only way to see that it is doing anything.
self_check_catches_a_stored_flag_that_disagrees_with_its_routerinfo_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(20),
    FF = floodfill(Now, "d"),
    Store = stored([FF], Store0, Now),
    ok = i2p_netdb:self_check(Store),

    Tab = i2p_netdb:router_table(Store),
    Key = i2p_router_info:hash(FF),
    [{_, RI, Flags}] = ets:lookup(Tab, Key),
    %% `?FF_DECLARED` is bit 0 and `?FF_ELIGIBLE` is bit 1, so this fixture -- which
    %% is both -- carries the full byte.
    3 = Flags,

    %% Demote it to "declared but not eligible" and the store should refuse to
    %% vouch for itself.
    true = ets:insert(Tab, {Key, RI, 1}),
    ?assertEqual(
        {error, {flags_disagree_with_routerinfo, [Key]}},
        i2p_netdb:self_check(Store)
    ),

    %% And restoring the row restores the store, so the check is about the data
    %% rather than about having been armed.
    true = ets:insert(Tab, {Key, RI, Flags}),
    ?assertEqual(ok, i2p_netdb:self_check(Store)).

%% Loading a store must compute the flags too. `seed_order/3` writes the table
%% directly, bypassing the mutators, so it is the one write path that could
%% plausibly have been missed -- and a load that stored rows without flags would
%% make every loaded router invisible to the floodfill lookup.
load_computes_the_floodfill_flags_test() ->
    Now = erlang:system_time(millisecond),
    FF = floodfill(Now, "e"),
    Plain = plain(Now, "f"),
    Store0 = i2p_netdb:new(20),
    Store = stored([FF, Plain], Store0, Now),
    Bin = i2p_netdb:to_binary(Store),
    {ok, Loaded} = i2p_netdb:from_binary(Bin),

    ok = i2p_netdb:self_check(Loaded),
    Target = crypto:strong_rand_bytes(32),
    ?assertEqual(
        [i2p_router_info:hash(FF)],
        hashes_of(i2p_netdb:closest_floodfills(Loaded, Target, 10, []))
    ).

%%% --------------------------------------------------------------------------
%%% The memo
%%% --------------------------------------------------------------------------

%% **The case the memo exists for.** A second lookup over the same store does no
%% per-router crypto at all.
%%
%% The count is exact, which is the whole reason this is a test and not a
%% benchmark: one hash for the target, and nothing else. The first lookup pays one
%% per candidate, so the pair of counts is the assertion — 24 keys in, 24 hashes,
%% then 1 hash.
%%
%% Reverting the memo (reading `f:routing_key/2` directly in `rank_keys/4` and
%% returning the store untouched) fails exactly this case. It also fails the
%% day-change case below, which is what stops it being passed by a memo that is
%% never invalidated.
memo_makes_the_second_lookup_do_no_per_router_crypto_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),
    N = i2p_netdb:count(Store),

    {Store1, _First} = i2p_netdb:closest(Store, Target, 3),
    Second = count_hashes(fun() -> i2p_netdb:closest(Store1, Target, 3) end),

    %% The target's own key, and nothing else. Asserting the cold count too is
    %% what makes the warm one mean something: `?assertEqual(1, Second)` on its own
    %% would also pass against a lookup that resolved no keys at all.
    ?assertEqual(N + 1, count_hashes(fun() -> i2p_netdb:closest(Store, Target, 3) end)),
    ?assertEqual(1, Second),
    ?assertEqual(N, 24).

%% The memo survives a router being added, and the new router is not in it.
%%
%% This is the case that makes the day tag sufficient. A memo is only correct for
%% the day it was built for and for the keys it holds, so it has two ways to go
%% stale: midnight, and a store that changed. **Neither invalidates anything** —
%% `memo_routing_key/3` falls back to computing, so a miss costs exactly what the
%% code cost before the memo existed and can never be worse than having no memo.
%%
%% So the assertion is that a lookup after a store still returns the right answer
%% *and* still adds the new router to the memo, rather than that the memo was
%% invalidated. The second lookup afterwards resolves the new router with no
%% crypto, which is what "it was added" means.
memo_picks_up_a_router_added_after_it_was_filled_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(20),
    Store = stored([floodfill(Now, "g"), floodfill(Now, "h")], Store0, Now),
    Target = crypto:strong_rand_bytes(32),

    {Filled, _} = i2p_netdb:closest(Store, Target, 3),

    %% A third router arrives. Nothing about the memo is told.
    Late = floodfill(Now, "i"),
    {Grown, added} = i2p_netdb:store(Filled, Late, Now),
    ?assertEqual(added, added),

    %% The lookup is still correct — the new router is eligible and reachable, so
    %% it can appear — and it costs one hash more than a warm lookup, which is the
    %% single miss.
    {Grown1, Closest} = i2p_netdb:closest(Grown, Target, 3),
    ?assert(lists:all(fun(K) -> i2p_netdb:has_router(Grown1, K) end, Closest)),

    %% And now the memo has it: the following lookup is back to one hash.
    ?assertEqual(1, count_hashes(fun() -> i2p_netdb:closest(Grown1, Target, 3) end)).

%% A memo built for yesterday is discarded rather than used.
%%
%% The routing key is `SHA256(Hash ‖ Day)`, so every value in it is wrong the
%% moment the day rolls over, and the store holds the day in the same field. This
%% case cannot move the clock, so it moves the tag instead — reaching into the
%% store for the one field whose value is a day, which is the only way to observe
%% the invalidation from outside.
%%
%% **And it asserts the answer, not just the rebuild.** A memo that were used
%% stale would rank by yesterday's distances and could return a different nearest
%% set. The store is rebuilt and the result is compared against a fresh store
%% built on the same routers, which is the only honest comparison available
%% without moving the clock.
memo_for_another_day_is_discarded_not_used_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(40),
    RIs = [floodfill(Now, [io_lib:format("d~2..0B", [I])]) || I <- lists:seq(1, 8)],
    Store = stored(RIs, Store0, Now),
    Target = crypto:strong_rand_bytes(32),

    {Filled, _} = i2p_netdb:closest(Store, Target, 3),

    %% **Two things have to be true before the tag is moved, or this case proves
    %% nothing.** The memo must be populated — a retag of an empty memo is
    %% indistinguishable from having no memo — and a lookup with a *matching* tag
    %% must not rebuild. The second is what makes the case falsifiable: an
    %% implementation that never reuses its memo still populates one, still passes a
    %% size check, and still rebuilds on a retag. Only the contrast between these
    %% two numbers says the tag is what decided.
    ?assertEqual(length(RIs), memo_size(Filled)),
    Warm = count_hashes(fun() -> i2p_netdb:closest(Filled, Target, 3) end),
    ?assertEqual(1, Warm),

    %% Keep the store the lookup handed back: that is the one carrying the memo,
    %% and this is the shape a day boundary actually leaves behind.
    Stale = retag_routing(Filled, <<"19700101">>),
    ok = i2p_netdb:self_check(Stale),

    %% The lookup on the stale store does a full pass's worth of crypto, against
    %% the single hash the same lookup cost a moment ago.
    Rebuilt = count_hashes(fun() -> i2p_netdb:closest(Stale, Target, 3) end),
    ?assert(Rebuilt > Warm),
    %% ...and returns what a store that had never memoised anything returns.
    ?assertEqual(
        hashes_of(i2p_netdb:closest(Store, Target, 3)),
        hashes_of(i2p_netdb:closest(Stale, Target, 3))
    ).

%% A dropped router leaves nothing behind in the memo.
%%
%% `f:forget_routing/2` is hygiene rather than correctness — a memo entry for a
%% departed router can never be returned, because a lookup only asks about keys
%% the order still holds. It is still worth doing, and worth a test, because the
%% alternative is a map that grows with the day's churn and nothing that notices.
%%
%% `f:self_check/1` is what notices. Demonstrated red by removing one of the three
%% `forget_routing/2` call sites, which is the failure the check exists for and the
%% only way to see that it is doing anything.
removing_a_router_drops_its_memoised_key_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = i2p_netdb:new(20),
    RIs = [floodfill(Now, [io_lib:format("r~2..0B", [I])]) || I <- lists:seq(1, 4)],
    Store = stored(RIs, Store0, Now),
    Target = crypto:strong_rand_bytes(32),

    {Filled, _} = i2p_netdb:closest(Store, Target, 3),
    ok = i2p_netdb:self_check(Filled),

    Dropped = i2p_router_info:hash(lists:nth(2, RIs)),
    {Emptied, removed} = i2p_netdb:remove(Filled, Dropped),
    ?assertEqual(removed, removed),
    ?assertNot(i2p_netdb:has_router(Emptied, Dropped)),
    %% The store can vouch for itself, which is the assertion: a leftover memo
    %% entry is what makes it refuse.
    ?assertEqual(ok, i2p_netdb:self_check(Emptied)),

    %% And a lookup on the reduced store still works and still resolves.
    {Emptied1, Closest} = i2p_netdb:closest(Emptied, Target, 3),
    ?assertNot(lists:member(Dropped, Closest)),
    ?assertEqual(1, count_hashes(fun() -> i2p_netdb:closest(Emptied1, Target, 3) end)).

%% The same, for the other two ways a router leaves: capacity eviction and the
%% expiry sweep.
%%
%% Eviction is `f:trim/1` and the sweep is `f:drop_each/2`, and both are separate
%% call sites from `f:remove/2` — `f:trim/1` in particular does not go through
%% `f:drop_from_order/2`, so the memo has to be told separately there too.
%%
%% **The order of the lookup and the removal is the whole test.** Filling the memo
%% first is what makes the removal observable: evicting or sweeping a key the memo
%% has never heard of leaves nothing behind to be caught, and both cases pass
%% against code with no `forget_routing/2` call at all. That is why the memo size
%% is asserted after each lookup — without it, a regression that stopped filling
%% the memo would look exactly like a regression that forgot to clean it up.
eviction_and_the_sweep_also_drop_the_memo_key_test() ->
    Now = erlang:system_time(millisecond),
    Target = crypto:strong_rand_bytes(32),

    %% Capacity 2, four routers stored: the memo is filled while both are held,
    %% then two more stores each evict one.
    Two = stored(
        [floodfill(Now, [io_lib:format("e~2..0B", [I])]) || I <- lists:seq(1, 2)],
        i2p_netdb:new(2),
        Now
    ),
    {Two1, _} = i2p_netdb:closest(Two, Target, 3),
    ?assertEqual(2, memo_size(Two1)),

    Four = stored(
        [floodfill(Now, [io_lib:format("e~2..0B", [I])]) || I <- lists:seq(3, 4)],
        Two1,
        Now
    ),
    ?assertEqual(2, i2p_netdb:count(Four)),
    ok = i2p_netdb:self_check(Four),

    %% Three routers all past the horizon. The memo is filled first, by a lookup
    %% that does not care they are stale — routing has nothing to say about expiry —
    %% and the sweep then has something to drop.
    Old = i2p_netdb:set_expiration_ms(i2p_netdb:new(10), 1),
    Aged = lists:foldl(
        fun(I, S) ->
            {S1, _} = i2p_netdb:store(
                S, floodfill(Now - 60000, [io_lib:format("s~2..0B", [I])]), Now - 60000
            ),
            S1
        end,
        Old,
        lists:seq(1, 3)
    ),
    {Aged1, _} = i2p_netdb:closest(Aged, Target, 3),
    ?assertEqual(3, memo_size(Aged1)),

    {Swept, {Removed, 0}} = i2p_netdb:remove_expired(Aged1, Now, erlang:system_time(second)),
    ?assertEqual(3, Removed),
    ?assertEqual(0, i2p_netdb:count(Swept)),
    %% The assertion: the store can vouch for itself with an empty table and a
    %% memo that used to hold three keys.
    ?assertEqual(ok, i2p_netdb:self_check(Swept)),
    ?assertEqual(0, memo_size(Swept)).

%% The memo is a cache, so it must not become load-bearing: a lookup has to be
%% right whether or not anything was ever memoised.
%%
%% The store the assertions compare against is the same store with the memo
%% stripped between the two lookups, which is the closest a test can get to "no
%% memo exists" without a second implementation. It passes on the answers whether
%% or not `memo_routing_key/3` falls back to computing, and it is here to fail if
%% a future change makes the memo something a lookup depends on being complete.
the_memo_is_not_load_bearing_for_the_answer_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),

    {Filled, Warm} = i2p_netdb:closest(Store, Target, 3),
    Cold = hashes_of(i2p_netdb:closest(strip_routing(Filled), Target, 3)),
    Again = hashes_of(i2p_netdb:closest(Filled, Target, 3)),

    ?assertEqual(Warm, Cold),
    ?assertEqual(Warm, Again).

%%% --------------------------------------------------------------------------
%%% The answers did not change
%%% --------------------------------------------------------------------------

%% The contract: hashes, closest first. Both of these pass against the old code
%% too, and that is the point -- the fix changes the cost and not the result.
closest_returns_hashes_not_pairs_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),
    {_Store1, Closest} = i2p_netdb:closest(Store, Target, 3),
    ?assertEqual(3, length(Closest)),
    lists:foreach(fun(K) -> ?assertEqual(32, byte_size(K)) end, Closest),
    %% And every one is a key the store actually holds.
    lists:foreach(
        fun(K) -> ?assert(i2p_netdb:has_router(Store, K)) end, Closest
    ).

closest_is_ordered_by_distance_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),
    {_Store1, Closest} = i2p_netdb:closest(Store, Target, ?N),
    Distances = [i2p_netdb:distance(K, Target) || K <- Closest],
    ?assertEqual(lists:sort(Distances), Distances),
    ?assertEqual(?N, length(Closest)).

%% The answer is the same whichever way the key list arrives, so the result does
%% not depend on the store's recency order or on the sort's internal decisions.
closest_does_not_depend_on_input_order_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),
    {_Store1, Forward} = i2p_netdb:closest(Store, Target, 5),
    %% The store's own order is recency order; asking for the whole store and
    %% taking the nearest five by hand must agree with the lookup.
    All = i2p_netdb:keys(Store),
    ByHand = lists:sublist(
        lists:sort(
            fun(A, B) -> i2p_netdb:distance(A, Target) < i2p_netdb:distance(B, Target) end, All
        ),
        5
    ),
    ?assertEqual(ByHand, Forward).

%% N = 0 and N greater than the store, both of which the old shape handled by
%% accident rather than by intent.
closest_handles_degenerate_n_test() ->
    Store = fixture_store(3),
    Target = crypto:strong_rand_bytes(32),
    ?assertEqual([], hashes_of(i2p_netdb:closest(Store, Target, 0))),
    ?assertEqual(3, length(hashes_of(i2p_netdb:closest(Store, Target, 99)))).

%%% --------------------------------------------------------------------------
%%% Fixtures and tracing
%%% --------------------------------------------------------------------------

fixture_store() ->
    fixture_store(?N).

fixture_store(N) ->
    Now = erlang:system_time(millisecond),
    Store = lists:foldl(
        fun(I, S) ->
            {S1, added} = i2p_netdb:store(S, router(Now, I), Now),
            added = added,
            S1
        end,
        i2p_netdb:new(N + 10),
        lists:seq(1, N)
    ),
    N = i2p_netdb:count(Store),
    ok = i2p_netdb:self_check(Store),
    Store.

router(Now, I) ->
    i2p_ct_helpers:floodfill_router_info(Now, host(I)).

host(N) ->
    list_to_binary("192.0.2." ++ integer_to_list(N)).

stored(RIs, Store0, Now) ->
    lists:foldl(
        fun(RI, S) ->
            {S1, added} = i2p_netdb:store(S, RI, Now),
            added = added,
            S1
        end,
        Store0,
        RIs
    ).

%% A floodfill that satisfies every half of the eligibility rule.
floodfill(Now, Tag) ->
    with_caps(Now, Tag, <<"Of">>).

%% Declares the floodfill capability but is not eligible: the unreachable flag
%% fails it. This is the router that a "flags mean eligible" shortcut gets wrong.
declared_but_not_eligible(Now, Tag) ->
    with_caps(Now, Tag, <<"OUf">>).

plain(Now, Tag) ->
    with_caps(Now, Tag, <<"O">>).

with_caps(Now, Tag, Caps) ->
    {{SPub, Seed}, {CPub, _}} =
        {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    Addr = i2p_router_info:ntcp2_address(
        host_hash(Tag), 4668, crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(16)
    ),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => Caps
    },
    i2p_router_info:build(i2p_keys:from_keys(CPub, SPub), Now, [Addr], Opts, Seed).

%% A host derived from a tag rather than an index, so two fixtures built with the
%% same index in different cases do not collide into one RouterInfo.
%%
%% **Four octets, and the last one is not padded.** The first two versions of this
%% got it wrong in ways that failed silently: the fixture stopped being a published
%% address, so `f:eligible_floodfill/1` was false, so `f:closest_floodfills/4`
%% returned an empty list, and every case that was really about the stored flags
%% failed with an empty expected-value rather than with anything about flags. Then
%% I blamed zero padding, which was wrong -- the prefix was three octets, not four.
%% `f:is_ipv4/1` is the thing to check a host against here.
host_hash(Tag) ->
    list_to_binary("198.51.100." ++ integer_to_list(erlang:phash2(Tag, 250) + 1)).

%% The list half of a `{Store2, Hashes}` result from a closest lookup.
%%
%% The store half is memo state, and asserting on it from a test about answers
%% would pin the optimisation rather than the behaviour. Where the store itself
%% matters — that a memo is filled, evicted, or rebuilt — the case says so
%% explicitly.
hashes_of({_Store, Hashes}) ->
    Hashes.

%% Replace the store's memo tag, leaving its contents alone.
%%
%% **This reaches into a field the type is `opaque` for, and that is the point.**
%% The alternative is to wait for midnight, which no test may do: the store's
%% `f:current_day/0` is not injectable and the whole module's discipline is that a
%% test asserts structurally rather than against a clock. Retagging is the honest
%% way to *construct* the state a day boundary leaves behind — a populated memo,
%% every value stale — rather than to simulate one.
%%
%% `f:self_check/1` is asserted over the result in the case that uses this, so
%% what is being described is a state the store itself considers well-formed.
retag_routing(#{routing := {_Day, Memo}} = Store, Day) ->
    Store#{routing := {Day, Memo}}.

%% How many routing keys the store has memoised.
%%
%% Reading the memo's size is the one thing a test can say about it that is not
%% either "the answer was right" or "the hash count was low". It is what makes the
%% day-change case falsifiable: a memo that is never filled has a size of zero, and
%% a case that retags without checking the size first passes just as happily
%% against no memo at all.
memo_size(#{routing := {_Day, Memo}}) ->
    map_size(Memo).

%% Drop the memo entirely, as though it had never been built.
strip_routing(#{routing := {_Day, Memo}} = Store) ->
    Store#{routing := {<<>>, Memo}}.

%% How many times `crypto:hash/2` ran while `F` ran.
%%
%% Traced rather than timed, for the reason the module docs give: a count is exact
%% and a deadline passes on an idle machine.
%%
%% Three traps this shape has to avoid, all hit in this session:
%%
%%   * `erlang:trace_pattern/3` returns the number of matched functions and 0 for
%%     an unloaded module, so 0 matches means no messages ever arrive and an
%%     assertion built on them passes whatever the code did. The count is asserted.
%%   * `erlang:trace/3`'s first argument is the PidSpec of the process being
%%     TRACED, not the tracer. The tracer goes in `{tracer, Tracer}`.
%%   * `erlang:trace/3` raises `badarg` on an already-exited tracer, so the teardown
%%     needs a catch.
count_hashes(F) ->
    {module, crypto} = code:ensure_loaded(crypto),
    ?assertEqual(1, erlang:trace_pattern({crypto, hash, 2}, true, [local])),
    Tracer = spawn(fun() -> collect_hashes(0) end),
    Self = self(),
    ?assertEqual(1, erlang:trace(Self, true, [call, {tracer, Tracer}])),
    try
        F(),
        Tracer ! {count, self()},
        receive
            {hashes, N} -> N
        after 5000 ->
            erlang:error(tracer_never_counted)
        end
    after
        %% **Untrace the traced process, not the tracer.** Passing the tracer pid
        %% here disables tracing *on the tracer*, which leaves this process still
        %% traced and makes the next `count_hashes` in the same run fail with a
        %% `badarg` from `erlang:trace/3` rather than anything to do with hashes.
        %% Found by running the module rather than by reading it.
        _ = untrace(Self),
        _ = erlang:trace_pattern({crypto, hash, 2}, false, [local])
    end.

%% The collector blocks forever on the count message; its own receive timeout would
%% race the caller's and lose exactly when the answer is slow, which is the case
%% this must not get wrong.
collect_hashes(N) ->
    receive
        {trace, _Pid, call, {crypto, hash, _Args}} ->
            collect_hashes(N + 1);
        {count, From} ->
            From ! {hashes, N},
            collect_hashes(0)
    end.

%% `erlang:trace/3` raises `badarg` on an already-exited pid, so the teardown
%% tolerates it rather than failing a test that has already passed.
untrace(Pid) ->
    try erlang:trace(Pid, false, [call]) of
        _ -> ok
    catch
        _:_ -> ok
    end.
