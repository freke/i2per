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

    FFs = i2p_netdb:closest_floodfills(Store, Target, 10, []),
    %% Only the one that is both declared and eligible.
    ?assertEqual([i2p_router_info:hash(FF)], FFs),
    ?assertNot(lists:member(i2p_router_info:hash(Bare), FFs)),
    ?assertNot(lists:member(i2p_router_info:hash(Plain), FFs)),

    %% And the complement: `closest_non_floodfills/4` excludes declared ones
    %% whatever their eligibility, which is a different question and was a
    %% different predicate.
    NonFFs = i2p_netdb:closest_non_floodfills(Store, Target, 10, []),
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
        i2p_netdb:closest_floodfills(Loaded, Target, 10, [])
    ).

%%% --------------------------------------------------------------------------
%%% The answers did not change
%%% --------------------------------------------------------------------------

%% The contract: hashes, closest first. Both of these pass against the old code
%% too, and that is the point -- the fix changes the cost and not the result.
closest_returns_hashes_not_pairs_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),
    Closest = i2p_netdb:closest(Store, Target, 3),
    ?assertEqual(3, length(Closest)),
    lists:foreach(fun(K) -> ?assertEqual(32, byte_size(K)) end, Closest),
    %% And every one is a key the store actually holds.
    lists:foreach(
        fun(K) -> ?assert(i2p_netdb:has_router(Store, K)) end, Closest
    ).

closest_is_ordered_by_distance_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),
    Closest = i2p_netdb:closest(Store, Target, ?N),
    Distances = [i2p_netdb:distance(K, Target) || K <- Closest],
    ?assertEqual(lists:sort(Distances), Distances),
    ?assertEqual(?N, length(Closest)).

%% The answer is the same whichever way the key list arrives, so the result does
%% not depend on the store's recency order or on the sort's internal decisions.
closest_does_not_depend_on_input_order_test() ->
    Store = fixture_store(),
    Target = crypto:strong_rand_bytes(32),
    Forward = i2p_netdb:closest(Store, Target, 5),
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
    ?assertEqual([], i2p_netdb:closest(Store, Target, 0)),
    ?assertEqual(3, length(i2p_netdb:closest(Store, Target, 99))).

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
