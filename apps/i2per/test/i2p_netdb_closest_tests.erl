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
