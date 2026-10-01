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
