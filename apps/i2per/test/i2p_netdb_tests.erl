%% Unit tests for the NetDb store and DHT helpers.
%%
%% Store semantics (added/updated/older/future/too-old), LRU capacity
%% eviction, day-scoped routing keys, XOR distance and closest selection, and
%% floodfill eligibility — pinned against i2pd's NetDb/RouterInfo behavior.
%% RouterInfo fixtures are real signed RouterInfos built by the test helpers;
%% each carries its key material so tests can re-sign with a new timestamp,
%% version or caps.

-module(i2p_netdb_tests).

-include_lib("eunit/include/eunit.hrl").

-define(EXPIRE_FUTURE_MS, 2 * 60 * 1000).
-define(EXPIRE_OLD_MS, 27 * 60 * 60 * 1000).

%%% --------------------------------------------------------------------------
%%% Routing keys and XOR distance
%%% --------------------------------------------------------------------------

%% CreateRoutingKey = SHA-256(ident ‖ yyyymmdd), exactly 40 bytes hashed.
routing_key_matches_sha256_test() ->
    Key = rand_hash(),
    Day = <<"20260814">>,
    ?assertEqual(crypto:hash(sha256, <<Key/binary, Day/binary>>), i2p_netdb:routing_key(Key, Day)),
    ?assertEqual(32, byte_size(i2p_netdb:routing_key(Key, Day))).

routing_key_changes_with_day_test() ->
    Key = rand_hash(),
    ?assertNotEqual(
        i2p_netdb:routing_key(Key, <<"20260814">>), i2p_netdb:routing_key(Key, <<"20260815">>)
    ).

routing_key_requires_32_bytes_test() ->
    ?assertError(badarg, i2p_netdb:routing_key(rand_hash(31), <<"20260814">>)),
    ?assertError(badarg, i2p_netdb:routing_key(rand_hash(), <<"2026081">>)).

distance_is_xor_and_symmetric_test() ->
    K1 = rand_hash(),
    K2 = rand_hash(),
    D = i2p_netdb:distance(K1, K2),
    ?assertEqual(32, byte_size(D)),
    ?assertEqual(D, i2p_netdb:distance(K2, K1)),
    ?assertEqual(crypto:exor(i2p_netdb:routing_key(K1), i2p_netdb:routing_key(K2)), D),
    ?assertEqual(<<0:256>>, i2p_netdb:distance(K1, K1)),
    ?assertNotEqual(<<0:256>>, i2p_netdb:distance(K1, K2)).

closest_returns_distance_sorted_test() ->
    Store0 = i2p_netdb:new(),
    Target = rand_hash(),
    {Store, Keys} = store_n(Store0, 5, now_ms()),
    {_Store1, Closest} = i2p_netdb:closest(Store, Target, 3),
    Expected = lists:sublist(
        lists:sort(
            fun(A, B) -> i2p_netdb:distance(A, Target) < i2p_netdb:distance(B, Target) end, Keys
        ),
        3
    ),
    ?assertEqual(Expected, Closest),
    ?assertEqual(3, length(Closest)),
    {_Store2, []} = i2p_netdb:closest(Store, Target, 0).

%%% --------------------------------------------------------------------------
%%% Store semantics
%%% --------------------------------------------------------------------------

store_add_and_find_test() ->
    Store0 = i2p_netdb:new(),
    {RI1, _} = fixture_router(),
    {RI2, _} = fixture_router(),
    {Store1, added} = i2p_netdb:store(Store0, RI1, now_ms()),
    {Store2, added} = i2p_netdb:store(Store1, RI2, now_ms()),
    ?assertEqual(2, i2p_netdb:count(Store2)),
    ?assertEqual({ok, RI1}, i2p_netdb:find(Store2, i2p_router_info:hash(RI1))),
    ?assertEqual({ok, RI2}, i2p_netdb:find(Store2, i2p_router_info:hash(RI2))),
    ?assertEqual(error, i2p_netdb:find(Store2, rand_hash())).

store_update_replaces_newer_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI1, Seed} = fixture_router(Now),
    Key = i2p_router_info:hash(RI1),
    {Store1, added} = i2p_netdb:store(Store0, RI1, Now),
    %% a strictly newer RouterInfo for the same identity replaces it
    RI2 = rebuild(RI1, Seed, Now + 1000, <<"0.9.74">>, <<"Of">>),
    ?assertEqual(Key, i2p_router_info:hash(RI2)),
    {Store2, updated} = i2p_netdb:store(Store1, RI2, Now),
    ?assertEqual({ok, RI2}, i2p_netdb:find(Store2, Key)),
    ?assertEqual(1, i2p_netdb:count(Store2)).

store_older_keeps_existing_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI1, Seed} = fixture_router(Now),
    Key = i2p_router_info:hash(RI1),
    {Store1, added} = i2p_netdb:store(Store0, RI1, Now),
    Older = rebuild(RI1, Seed, Now - 1000, <<"0.9.74">>, <<"Of">>),
    {Store2, older} = i2p_netdb:store(Store1, Older, Now),
    ?assertEqual({ok, RI1}, i2p_netdb:find(Store2, Key)),
    %% an equal timestamp is also 'older' (i2pd: strictly newer wins)
    Equal = rebuild(RI1, Seed, i2p_router_info:published(RI1), <<"0.9.74">>, <<"Of">>),
    {Store3, older} = i2p_netdb:store(Store2, Equal, Now),
    ?assertEqual({ok, RI1}, i2p_netdb:find(Store3, Key)).

store_from_future_rejected_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI, _} = fixture_router(Now + ?EXPIRE_FUTURE_MS + 1),
    Key = i2p_router_info:hash(RI),
    {Store1, from_future} = i2p_netdb:store(Store0, RI, Now),
    ?assertEqual(0, i2p_netdb:count(Store1)),
    ?assertEqual(error, i2p_netdb:find(Store1, Key)).

store_too_old_rejected_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI, _} = fixture_router(Now - (?EXPIRE_OLD_MS + 60 * 60 * 1000)),
    Key = i2p_router_info:hash(RI),
    {Store1, too_old} = i2p_netdb:store(Store0, RI, Now),
    ?assertEqual(0, i2p_netdb:count(Store1)),
    ?assertEqual(error, i2p_netdb:find(Store1, Key)).

%% Exactly at the window edges the store accepts (i2pd uses strict < / >).
store_window_edge_accepted_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {RIFuture, _} = fixture_router(Now + ?EXPIRE_FUTURE_MS),
    {Store1, added} = i2p_netdb:store(Store0, RIFuture, Now),
    {RIOld, _} = fixture_router(Now - ?EXPIRE_OLD_MS),
    {Store2, added} = i2p_netdb:store(Store1, RIOld, Now),
    ?assertEqual(2, i2p_netdb:count(Store2)).

lru_evicts_oldest_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(2),
    {RA, _} = fixture_router(Now),
    {RB, _} = fixture_router(Now),
    {RC, _} = fixture_router(Now),
    ?assertNotEqual(i2p_router_info:hash(RA), i2p_router_info:hash(RB)),
    ?assertNotEqual(i2p_router_info:hash(RB), i2p_router_info:hash(RC)),
    {Store1, added} = i2p_netdb:store(Store0, RA, Now),
    {Store2, added} = i2p_netdb:store(Store1, RB, Now),
    %% storing C pushes the oldest (A) out
    {Store3, added} = i2p_netdb:store(Store2, RC, Now),
    ?assertEqual(2, i2p_netdb:count(Store3)),
    ?assertEqual(error, i2p_netdb:find(Store3, i2p_router_info:hash(RA))),
    ?assertEqual({ok, RB}, i2p_netdb:find(Store3, i2p_router_info:hash(RB))),
    ?assertEqual({ok, RC}, i2p_netdb:find(Store3, i2p_router_info:hash(RC))).

store_binary_roundtrip_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI, _} = fixture_router(Now),
    Bin = i2p_router_info:to_binary(RI),
    {ok, Store1, added} = i2p_netdb:store_binary(Store0, Bin, Now),
    ?assertEqual({ok, RI}, i2p_netdb:find(Store1, i2p_router_info:hash(RI))),
    ?assertEqual({error, too_short}, i2p_netdb:store_binary(Store0, rand_hash(), Now)),
    %% A structurally valid RouterInfo with a corrupted signature.
    BodySize = byte_size(Bin) - 64,
    <<Body:BodySize/binary, Sig:64/binary>> = Bin,
    CorruptSig = <<(binary:first(Sig) bxor 16#FF):8, (binary:part(Sig, 1, 63))/binary>>,
    BadBin = <<Body/binary, CorruptSig/binary>>,
    ?assertEqual({error, bad_signature}, i2p_netdb:store_binary(Store0, BadBin, Now)).

remove_test() ->
    Store0 = i2p_netdb:new(),
    {RI, _} = fixture_router(),
    {Store1, added} = i2p_netdb:store(Store0, RI, now_ms()),
    Key = i2p_router_info:hash(RI),
    {Store2, removed} = i2p_netdb:remove(Store1, Key),
    {Store3, not_found} = i2p_netdb:remove(Store2, Key),
    ?assertEqual(0, i2p_netdb:count(Store3)).

%%% --------------------------------------------------------------------------
%%% LeaseSet store
%%% --------------------------------------------------------------------------

ls_store_add_and_find_test() ->
    Now = now_sec(),
    Store0 = i2p_netdb:new(),
    {LS1, _} = fixture_ls(Now),
    {LS2, _} = fixture_ls(Now),
    {Store1, added} = i2p_netdb:store_ls(Store0, LS1, Now),
    {Store2, added} = i2p_netdb:store_ls(Store1, LS2, Now),
    ?assertEqual(2, i2p_netdb:ls_count(Store2)),
    ?assertEqual({ok, LS1}, i2p_netdb:find_ls(Store2, i2p_leaset:hash(LS1))),
    ?assertEqual({ok, LS2}, i2p_netdb:find_ls(Store2, i2p_leaset:hash(LS2))),
    ?assertEqual(error, i2p_netdb:find_ls(Store2, rand_hash())),
    ?assertEqual([i2p_leaset:hash(LS2), i2p_leaset:hash(LS1)], i2p_netdb:ls_keys(Store2)).

ls_store_update_replaces_newer_test() ->
    Now = now_sec(),
    Store0 = i2p_netdb:new(),
    {LS1, SeedKey} = fixture_ls(Now),
    Key = i2p_leaset:hash(LS1),
    {Store1, added} = i2p_netdb:store_ls(Store0, LS1, Now),
    %% a strictly newer LeaseSet for the same destination replaces it
    LS2 = rebuild_ls(LS1, SeedKey, Now + 1),
    ?assertEqual(Key, i2p_leaset:hash(LS2)),
    {Store2, updated} = i2p_netdb:store_ls(Store1, LS2, Now),
    ?assertEqual({ok, LS2}, i2p_netdb:find_ls(Store2, Key)),
    ?assertEqual(1, i2p_netdb:ls_count(Store2)).

ls_store_older_keeps_existing_test() ->
    Now = now_sec(),
    Store0 = i2p_netdb:new(),
    {LS1, SeedKey} = fixture_ls(Now),
    Key = i2p_leaset:hash(LS1),
    {Store1, added} = i2p_netdb:store_ls(Store0, LS1, Now),
    Older = rebuild_ls(LS1, SeedKey, Now - 1),
    {Store2, older} = i2p_netdb:store_ls(Store1, Older, Now),
    ?assertEqual({ok, LS1}, i2p_netdb:find_ls(Store2, Key)),
    %% an equal publish time is also 'older'
    Equal = rebuild_ls(LS1, SeedKey, i2p_leaset:published(LS1)),
    {Store3, older} = i2p_netdb:store_ls(Store2, Equal, Now),
    ?assertEqual({ok, LS1}, i2p_netdb:find_ls(Store3, Key)).

ls_store_from_future_rejected_test() ->
    Now = now_sec(),
    Store0 = i2p_netdb:new(),
    {LS, _} = fixture_ls(Now + 2 * 60 + 1),
    {Store1, from_future} = i2p_netdb:store_ls(Store0, LS, Now),
    ?assertEqual(0, i2p_netdb:ls_count(Store1)),
    ?assertEqual(error, i2p_netdb:find_ls(Store1, i2p_leaset:hash(LS))).

ls_store_expired_rejected_test() ->
    Now = now_sec(),
    Store0 = i2p_netdb:new(),
    %% published a full lifetime (7 days) + the 12-minute threshold + 1 s ago
    {LS, _} = fixture_ls(Now - (7 * 86400 + 12 * 60 + 1)),
    {Store1, expired} = i2p_netdb:store_ls(Store0, LS, Now),
    ?assertEqual(0, i2p_netdb:ls_count(Store1)),
    ?assertEqual(error, i2p_netdb:find_ls(Store1, i2p_leaset:hash(LS))),
    %% exactly at the lifetime + threshold edge the store still accepts
    {Edge, _} = fixture_ls(Now - (7 * 86400 + 12 * 60)),
    {Store2, added} = i2p_netdb:store_ls(Store1, Edge, Now),
    ?assertEqual(1, i2p_netdb:ls_count(Store2)).

ls_lru_evicts_oldest_test() ->
    Now = now_sec(),
    Store0 = i2p_netdb:new(2),
    {LA, _} = fixture_ls(Now),
    {LB, _} = fixture_ls(Now),
    {LC, _} = fixture_ls(Now),
    {Store1, added} = i2p_netdb:store_ls(Store0, LA, Now),
    {Store2, added} = i2p_netdb:store_ls(Store1, LB, Now),
    {Store3, added} = i2p_netdb:store_ls(Store2, LC, Now),
    ?assertEqual(2, i2p_netdb:ls_count(Store3)),
    ?assertEqual(error, i2p_netdb:find_ls(Store3, i2p_leaset:hash(LA))),
    ?assertEqual({ok, LB}, i2p_netdb:find_ls(Store3, i2p_leaset:hash(LB))),
    ?assertEqual({ok, LC}, i2p_netdb:find_ls(Store3, i2p_leaset:hash(LC))).

ls_store_binary_roundtrip_test() ->
    Now = now_sec(),
    Store0 = i2p_netdb:new(),
    {LS, _} = fixture_ls(Now),
    Bin = i2p_leaset:to_binary(LS),
    {ok, Store1, added} = i2p_netdb:store_ls_binary(Store0, Bin, Now),
    ?assertEqual({ok, LS}, i2p_netdb:find_ls(Store1, i2p_leaset:hash(LS))),
    ?assertEqual({error, too_short}, i2p_netdb:store_ls_binary(Store0, rand_hash(), Now)),
    %% a structurally valid LeaseSet with a corrupted signature
    BodySize = byte_size(Bin) - 64,
    <<Body:BodySize/binary, Sig:64/binary>> = Bin,
    CorruptSig = <<(binary:first(Sig) bxor 16#FF):8, (binary:part(Sig, 1, 63))/binary>>,
    BadBin = <<Body/binary, CorruptSig/binary>>,
    ?assertEqual({error, bad_signature}, i2p_netdb:store_ls_binary(Store0, BadBin, Now)).

%%% --------------------------------------------------------------------------
%%% Floodfill predicates
%%% --------------------------------------------------------------------------

version_number_test() ->
    ?assertEqual(974, version_number_of(<<"0.9.74">>)),
    ?assertEqual(962, version_number_of(<<"0.9.62">>)),
    ?assertEqual(9680, version_number_of(<<"0.9.68-0">>)),
    ?assertEqual(0, version_number_of(<<>>)),
    ?assertEqual(0, version_number_of(<<"rolling">>)).

declared_floodfill_test() ->
    ?assert(declared_floodfill_of(<<"Of">>)),
    ?assert(declared_floodfill_of(<<"f">>)),
    ?assertNot(declared_floodfill_of(<<"O">>)),
    ?assertNot(declared_floodfill_of(<<"">>)).

eligible_floodfill_version_gate_test() ->
    Now = now_ms(),
    {FF, Seed} = fixture_floodfill(Now),
    ?assert(i2p_netdb:eligible_floodfill(FF)),
    %% old version not eligible (i2pd NETDB_MIN_FLOODFILL_VERSION = 0.9.62)
    Old = rebuild(FF, Seed, Now, <<"0.9.50">>, <<"Of">>),
    ?assertNot(i2p_netdb:eligible_floodfill(Old)),
    %% boundary 0.9.62 is eligible
    Edge = rebuild(FF, Seed, Now, <<"0.9.62">>, <<"Of">>),
    ?assert(i2p_netdb:eligible_floodfill(Edge)).

eligible_floodfill_caps_gate_test() ->
    Now = now_ms(),
    {FF, Seed} = fixture_floodfill(Now),
    ?assert(i2p_netdb:eligible_floodfill(FF)),
    %% router caps U (unreachable) or H (hidden) disqualify (i2pd IsPublished)
    Unreachable = rebuild(FF, Seed, Now, <<"0.9.74">>, <<"UOf">>),
    ?assertNot(i2p_netdb:eligible_floodfill(Unreachable)),
    Hidden = rebuild(FF, Seed, Now, <<"0.9.74">>, <<"Hf">>),
    ?assertNot(i2p_netdb:eligible_floodfill(Hidden)).

eligible_floodfill_declared_but_unpublished_rejected_test() ->
    Now = now_ms(),
    %% caps declare floodfill but the router has no NTCP2 address at all —
    %% the caps alone don't qualify it.
    {RI, _} = fixture_bare_floodfill(Now),
    ?assert(i2p_netdb:declared_floodfill(RI)),
    ?assertNot(i2p_netdb:eligible_floodfill(RI)).

eligible_floodfill_nonpublished_ntcp2_rejected_test() ->
    Now = now_ms(),
    {RI, _} = fixture_nonpublished_floodfill(Now),
    ?assert(i2p_netdb:declared_floodfill(RI)),
    ?assertNot(i2p_netdb:eligible_floodfill(RI)).

closest_floodfills_filters_by_eligibility_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {FF1, _} = fixture_floodfill(Now),
    {FF2, _} = fixture_floodfill(Now),
    {Plain, _} = fixture_router(Now),
    {Store1, added} = i2p_netdb:store(Store0, FF1, Now),
    {Store2, added} = i2p_netdb:store(Store1, FF2, Now),
    {Store3, added} = i2p_netdb:store(Store2, Plain, Now),
    Target = i2p_router_info:hash(FF1),
    {Store4, FFs} = i2p_netdb:closest_floodfills(Store3, Target, 5, []),
    ?assertEqual(2, length(FFs)),
    ?assert(lists:member(i2p_router_info:hash(FF1), FFs)),
    ?assert(lists:member(i2p_router_info:hash(FF2), FFs)),
    ?assertNot(lists:member(i2p_router_info:hash(Plain), FFs)),
    %% **A lookup that resolved nothing returns the store exactly as it was.**
    %% `Store4` already carries a memo tagged with today, so naming every candidate
    %% as excluded leaves `f:memorize/3` with nothing to record and nothing to
    %% re-tag, and it must not rewrite the store to say "I memoised nothing".
    %% Asserting the store rather than only the answer is the point: the answer is
    %% `[]` either way, so it cannot tell this from a store that was needlessly
    %% rewritten.
    ?assertEqual(
        {Store4, []},
        i2p_netdb:closest_floodfills(
            Store4, Target, 5, [i2p_router_info:hash(FF1), i2p_router_info:hash(FF2)]
        )
    ).

closest_non_floodfills_excludes_declared_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {FF, _} = fixture_floodfill(Now),
    {P1, _} = fixture_router(Now),
    {P2, _} = fixture_router(Now),
    {Store1, added} = i2p_netdb:store(Store0, FF, Now),
    {Store2, added} = i2p_netdb:store(Store1, P1, Now),
    {Store3, added} = i2p_netdb:store(Store2, P2, Now),
    Target = i2p_router_info:hash(FF),
    {_Store4, NonFF} = i2p_netdb:closest_non_floodfills(Store3, Target, 5, []),
    ?assertEqual(2, length(NonFF)),
    ?assertNot(lists:member(i2p_router_info:hash(FF), NonFF)),
    ?assert(lists:member(i2p_router_info:hash(P1), NonFF)),
    ?assert(lists:member(i2p_router_info:hash(P2), NonFF)).

%%% --------------------------------------------------------------------------
%%% Persistence: to_binary / from_binary round-trip
%%% --------------------------------------------------------------------------

binary_roundtrip_preserves_count_and_find_test() ->
    Now = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI1, _} = fixture_router(Now),
    {RI2, _} = fixture_floodfill(Now),
    {Store1, added} = i2p_netdb:store(Store0, RI1, Now),
    {Store2, added} = i2p_netdb:store(Store1, RI2, Now),
    Bin = i2p_netdb:to_binary(Store2),
    {ok, Restored} = i2p_netdb:from_binary(Bin),
    ?assertEqual(2, i2p_netdb:count(Restored)),
    ?assertEqual(i2p_netdb:capacity(Store2), i2p_netdb:capacity(Restored)),
    ?assertEqual({ok, RI1}, i2p_netdb:find(Restored, i2p_router_info:hash(RI1))),
    ?assertEqual({ok, RI2}, i2p_netdb:find(Restored, i2p_router_info:hash(RI2))),
    ?assertEqual(i2p_netdb:keys(Store2), i2p_netdb:keys(Restored)).

binary_roundtrip_lease_sets_test() ->
    NowSec = now_sec(),
    Store0 = i2p_netdb:new(),
    {LS, _} = fixture_ls(NowSec),
    {Store1, added} = i2p_netdb:store_ls(Store0, LS, NowSec),
    Bin = i2p_netdb:to_binary(Store1),
    {ok, Restored} = i2p_netdb:from_binary(Bin),
    ?assertEqual(1, i2p_netdb:ls_count(Restored)),
    ?assertEqual({ok, LS}, i2p_netdb:find_ls(Restored, i2p_leaset:hash(LS))).

%% Compared by content, not by `=:=`. The store carries the tid of its own ETS
%% table, and a round trip builds a fresh store with a fresh table, so the two
%% values can never be the same term. What must survive a round trip is what the
%% store *holds* -- which is what these two assertions say.
binary_roundtrip_empty_store_test() ->
    Store = i2p_netdb:new(),
    Bin = i2p_netdb:to_binary(Store),
    {ok, Restored} = i2p_netdb:from_binary(Bin),
    ?assertEqual(0, i2p_netdb:count(Restored)),
    ?assertEqual([], i2p_netdb:keys(Restored)),
    ?assertEqual(i2p_netdb:capacity(Store), i2p_netdb:capacity(Restored)),
    ?assertEqual(ok, i2p_netdb:self_check(Restored)).

binary_from_bad_magic_test() ->
    ?assertMatch({error, bad_magic}, i2p_netdb:from_binary(<<"BADMGIC">>)).

binary_from_truncated_test() ->
    ?assertMatch({error, _}, i2p_netdb:from_binary(<<"I2PNETDB", 1:8, 0:32>>)).

%%% --------------------------------------------------------------------------
%%% Expiry: remove_expired
%%% --------------------------------------------------------------------------

remove_expired_drops_old_routers_test() ->
    NowMs = now_ms(),
    Store0 = i2p_netdb:new(),
    %% store fresh, then check expiry at a future time when it's old
    {Fresh, _} = fixture_router(NowMs),
    {S1, added} = i2p_netdb:store(Store0, Fresh, NowMs),
    ?assertEqual(1, i2p_netdb:count(S1)),
    FutureMs = NowMs + (27 * 60 * 60 * 1000 + 1),
    {S2, {1, 0}} = i2p_netdb:remove_expired(S1, FutureMs, now_sec()),
    ?assertEqual(0, i2p_netdb:count(S2)),
    ?assertEqual(error, i2p_netdb:find(S2, i2p_router_info:hash(Fresh))).

remove_expired_at_boundary_keeps_router_test() ->
    NowMs = now_ms(),
    Store0 = i2p_netdb:new(),
    %% store fresh, then check expiry at exactly 27h (boundary: still valid)
    {RI, _} = fixture_router(NowMs),
    {S1, added} = i2p_netdb:store(Store0, RI, NowMs),
    BoundaryMs = NowMs + (27 * 60 * 60 * 1000),
    {S2, {0, 0}} = i2p_netdb:remove_expired(S1, BoundaryMs, now_sec()),
    ?assertEqual(1, i2p_netdb:count(S2)).

remove_expired_drops_expired_ls_test() ->
    NowSec = now_sec(),
    Store0 = i2p_netdb:new(),
    %% store fresh, then check expiry at a far-future time
    {LS, _} = fixture_ls(NowSec),
    {S1, added} = i2p_netdb:store_ls(Store0, LS, NowSec),
    %% far future: LS will be expired (published + 7d + threshold < FarFutureSec)
    FarFutureSec = NowSec + 7 * 86400 + 12 * 60 + 1,
    {S2, {0, 1}} = i2p_netdb:remove_expired(S1, now_ms(), FarFutureSec),
    ?assertEqual(0, i2p_netdb:ls_count(S2)).

remove_expired_keeps_fresh_ls_test() ->
    NowSec = now_sec(),
    Store0 = i2p_netdb:new(),
    {LS, _} = fixture_ls(NowSec),
    {S1, added} = i2p_netdb:store_ls(Store0, LS, NowSec),
    {S2, {0, 0}} = i2p_netdb:remove_expired(S1, now_ms(), NowSec),
    ?assertEqual(1, i2p_netdb:ls_count(S2)).

%%% --------------------------------------------------------------------------
%%% Generation: a store that mutates its table in place is only half a value
%%% --------------------------------------------------------------------------

%% Every test below drops a mutator's return value on purpose -- the one caller
%% mistake this store has no defence against -- and then asks whether the store
%% notices. `m:i2p_netdb` detects it with the generation counter the table carries
%% under `'$generation'`, so these assert both halves: that the counter is the
%% thing that fires, and that the store is *left usable* when it does.

generation_starts_at_zero_and_advances_per_mutation_test() ->
    NowMs = now_ms(),
    Store0 = i2p_netdb:new(),
    ?assertEqual(0, i2p_netdb:generation(Store0)),
    {RI, _} = fixture_router(NowMs),
    {Store1, added} = i2p_netdb:store(Store0, RI, NowMs),
    ?assertEqual(1, i2p_netdb:generation(Store1)),
    %% A rejected store writes nothing, so it must not advance the counter.
    %% Advancing it anyway would make the generation a call count rather than a
    %% record of table writes, and a caller would be told the table moved when it
    %% did not.
    {Store2, older} = i2p_netdb:store(Store1, RI, NowMs),
    ?assertEqual(1, i2p_netdb:generation(Store2)),
    {Store3, not_found} = i2p_netdb:remove(Store2, rand_hash()),
    ?assertEqual(1, i2p_netdb:generation(Store3)).

%% The promote case the ticket names. Storing a *newer* RouterInfo for a router
%% already held inserts a row and moves its position in the order, and the
%% returned store is what carries the new position. Drop it and the table holds
%% the newer RouterInfo while the caller's store still has the old position.
dropping_a_promote_result_is_caught_before_the_next_store_test() ->
    NowMs = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI, Seed} = fixture_router(NowMs),
    Key = i2p_router_info:hash(RI),
    {Store1, added} = i2p_netdb:store(Store0, RI, NowMs),
    ?assertEqual(1, i2p_netdb:generation(Store1)),

    %% A strictly newer RouterInfo for the same identity: this is the promote
    %% path, `f:promote/2` moving `Key` to most-recent.
    Newer = rebuild(RI, Seed, NowMs + 1000, <<"0.9.74">>, <<"4">>),
    ?assertEqual(Key, i2p_router_info:hash(Newer)),
    {_, updated} = i2p_netdb:store(Store1, Newer, NowMs),

    %% Both size checks pass on the stale store. `f:consistent/1` compares three
    %% sizes, and the mutation inserted one row and evicted one, so they agree;
    %% `f:self_check/1` agrees too because the order is internally consistent --
    %% it is just the *old* order. A size check cannot catch this, which is why
    %% the fix is a counter rather than a better count.
    ?assertEqual(ok, i2p_netdb:consistent(Store1)),
    ?assertEqual(ok, i2p_netdb:self_check(Store1)),

    %% The next *accepted* mutation is where the damage would happen, so it is
    %% where the claim fires. A fresh router rather than `Newer` again, because
    %% re-storing `Newer` is rejected before it reaches the table (the table
    %% already holds the newer publish time) and so claims nothing -- which is
    %% the behaviour asserted above.
    {Third, _Seed3} = fixture_router(NowMs),
    ?assertEqual(
        {stale_store, #{expected => 1, table => 2}},
        raised_by(fun() -> i2p_netdb:store(Store1, Third, NowMs) end)
    ),

    %% The point of firing *before* the write: nothing further was written, so no
    %% second row was inserted and no router was evicted on the way to the error.
    %% The table still holds exactly the one router the last good store describes.
    ?assertEqual(ok, i2p_netdb:self_check(Store1)),
    ?assertEqual(1, i2p_netdb:count(Store1)),
    ?assert(i2p_netdb:has_router(Store1, Key)),
    ?assertMatch({ok, _}, i2p_netdb:find(Store1, Key)).

%% At capacity the eviction makes the damage visible to a human. Storing a router
%% we already hold, at capacity, promotes it and evicts the oldest. Drop the
%% result and the table has evicted a router the caller's order still holds --
%% so the next store evicts *again* against an order that is one eviction behind,
%% and the router just stored is the one that goes.
dropping_a_result_at_capacity_does_not_evict_the_router_just_stored_test() ->
    NowMs = now_ms(),
    Store0 = i2p_netdb:new(2),
    {A, SeedA} = fixture_router(NowMs),
    {B, _SeedB} = fixture_router(NowMs),
    KeyA = i2p_router_info:hash(A),
    KeyB = i2p_router_info:hash(B),
    {S1, added} = i2p_netdb:store(Store0, A, NowMs),
    {S2, added} = i2p_netdb:store(S1, B, NowMs),
    ?assertEqual(2, i2p_netdb:count(S2)),

    %% Re-store A with a newer timestamp. At capacity this promotes A and evicts
    %% B, so *which* router survives is decided entirely by the returned store:
    %% the table on its own cannot say which router is now least recent.
    NewerA = rebuild(A, SeedA, NowMs + 1000, <<"0.9.74">>, <<"4">>),
    {_, updated} = i2p_netdb:store(S2, NewerA, NowMs),

    %% This is the failure the ticket describes. Carried on against the stale S2,
    %% the promote cannot find A's old position -- the table moved it -- and
    %% `trim/1` evicts whatever the order still calls oldest. Without the
    %% generation counter A, the router just re-stored, is the eviction victim.
    {C, _SeedC} = fixture_router(NowMs),
    ?assertEqual(
        {stale_store, #{expected => 2, table => 3}},
        raised_by(fun() -> i2p_netdb:store(S2, C, NowMs) end)
    ),

    %% At the moment the claim fired, nothing had been evicted: the mutation that
    %% would have chosen a victim never reached the table. A is still held.
    ?assert(i2p_netdb:has_router(S2, KeyA)),
    ?assert(i2p_netdb:has_router(S2, KeyB)).

%% The sweep writes the table, so it claims too -- and it claims before it walks,
%% not at the first delete, because it cannot know whether it will delete anything
%% until it has read the whole order.
remove_expired_claims_the_generation_before_deleting_test() ->
    NowMs = now_ms(),
    Store0 = i2p_netdb:new(),
    {RI, _} = fixture_router(NowMs),
    {Store1, added} = i2p_netdb:store(Store0, RI, NowMs),
    FutureMs = NowMs + (27 * 60 * 60 * 1000 + 1),
    %% One claim for the sweep: the store is expired, so the table is written and
    %% the generation advances by exactly one.
    {Store2, {1, 0}} = i2p_netdb:remove_expired(Store1, FutureMs, now_sec()),
    ?assertEqual(2, i2p_netdb:generation(Store2)),
    ?assertEqual(0, i2p_netdb:count(Store2)),
    %% A sweep that removes nothing still advances it, which is the trade the
    %% claim-before-the-walk makes. Asserted because it is a behaviour a reader
    %% of the code might otherwise assume is a bug.
    {Store3, {0, 0}} = i2p_netdb:remove_expired(Store2, NowMs, now_sec()),
    ?assertEqual(3, i2p_netdb:generation(Store3)),
    ?assertEqual(
        {stale_store, #{expected => 1, table => 3}},
        raised_by(fun() -> i2p_netdb:remove_expired(Store1, FutureMs, now_sec()) end)
    ).

%% The generation is not just a guard. It is what makes a snapshot taken by
%% another process safe to take at all, which is what lets the periodic save run
%% off the read path: read the generation, serialise, read it again, and a change
%% means the bytes describe no store that ever existed.
generation_identifies_an_unchanged_store_for_a_cross_process_snapshot_test() ->
    NowMs = now_ms(),
    Store0 = i2p_netdb:new(3),
    {Store, _Keys} = store_n(Store0, 3, NowMs),
    Before = i2p_netdb:generation(Store),
    %% Nothing wrote the table, so a snapshot taken around it is stable: read the
    %% generation, serialise, read it again, and an equal value means the bytes
    %% describe a store that actually existed.
    _Bin = i2p_netdb:to_binary(Store),
    ?assertEqual(Before, i2p_netdb:generation(Store)),
    {RI, _Seed} = fixture_router(NowMs + 1000),
    {Store2, added} = i2p_netdb:store(Store, RI, NowMs + 1000),
    _Bin2 = i2p_netdb:to_binary(Store2),
    ?assertNotEqual(Before, i2p_netdb:generation(Store2)).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

now_ms() ->
    erlang:system_time(millisecond).

now_sec() ->
    erlang:system_time(second).

rand_hash() ->
    rand_hash(32).

rand_hash(N) ->
    crypto:strong_rand_bytes(N).

%% The term a mutation raised, so a test can assert on it.
%%
%% `?assertError/2` takes a *pattern*, and Erlang map patterns cannot hold
%% literals -- `#{expected => 1, table => 2}` is a binding expression, not a
%% match, so it can never match. A test that needs to assert the values inside
%% the error has to catch it and compare whole terms, which is what this is for.
raised_by(Fun) ->
    try
        Fun(),
        no_error
    catch
        error:Reason -> Reason;
        Class:Reason -> {Class, Reason}
    end.

%% {RouterInfo, SeedKey} where SeedKey = {{SPub, Seed}, {CPub, _}} lets tests
%% rebuild the same identity with a different timestamp/version/caps.
fixture_router() ->
    fixture_router(now_ms()).

fixture_router(Timestamp) ->
    SeedKey = new_seed_key(),
    {build_from(SeedKey, Timestamp, <<"0.9.74">>, <<"4">>, <<"192.0.2.10">>), SeedKey}.

fixture_floodfill(Timestamp) ->
    SeedKey = new_seed_key(),
    {build_from(SeedKey, Timestamp, <<"0.9.74">>, <<"Of">>, <<"192.0.2.10">>), SeedKey}.

%% Declared floodfill (caps 'f') but no NTCP2 address at all — caps alone
%% don't qualify it.
fixture_bare_floodfill(Timestamp) ->
    SeedKey = new_seed_key(),
    {{SPub, Seed}, {CPub, _}} = SeedKey,
    Identity = i2p_keys:from_keys(CPub, SPub),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => <<"f">>
    },
    RI = i2p_router_info:build(Identity, Timestamp, [], Opts, Seed),
    {RI, SeedKey}.

fixture_nonpublished_floodfill(Timestamp) ->
    SeedKey = new_seed_key(),
    {{SPub, Seed}, {CPub, _}} = SeedKey,
    Identity = i2p_keys:from_keys(CPub, SPub),
    Addr = i2p_router_info:ntcp2_nonpublished_address(ipv4, rand_hash()),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => <<"f">>
    },
    RI = i2p_router_info:build(Identity, Timestamp, [Addr], Opts, Seed),
    {RI, SeedKey}.

new_seed_key() ->
    {{SPub, Seed}, {CPub, _}} = {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    {{SPub, Seed}, {CPub, rand_hash()}}.

build_from(SeedKey, Timestamp, Version, Caps, Host) ->
    {{SPub, Seed}, {CPub, _}} = SeedKey,
    Identity = i2p_keys:from_keys(CPub, SPub),
    Addr = i2p_router_info:ntcp2_address(Host, 4668, rand_hash(), rand_hash(16)),
    Opts = maps:merge(
        #{<<"netId">> => <<"2">>, <<"router.version">> => Version},
        caps_map(Caps)
    ),
    i2p_router_info:build(Identity, Timestamp, [Addr], Opts, Seed).

%% Re-sign a fixture's identity with a new timestamp/version/caps. The
%% RouterInfo's identity and the seed key come from the same fixture, so the
%% rebuilt RouterInfo keeps the same hash.
rebuild(RI, SeedKey, Timestamp, Version, Caps) ->
    Identity = i2p_router_info:identity(RI),
    {{_SPub, Seed}, _CPub} = SeedKey,
    Addr = i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, rand_hash(), rand_hash(16)),
    Opts = maps:merge(
        #{<<"netId">> => <<"2">>, <<"router.version">> => Version},
        caps_map(Caps)
    ),
    i2p_router_info:build(Identity, Timestamp, [Addr], Opts, Seed).

%% {LeaseSet, SeedKey} — the SeedKey signs the same destination identity, so a
%% rebuilt LeaseSet keeps the same hash.
fixture_ls(TimestampSec) ->
    SeedKey = new_seed_key(),
    build_ls(SeedKey, TimestampSec).

build_ls(SeedKey, TimestampSec) ->
    {{SPub, Seed}, {CPub, _}} = SeedKey,
    Identity = i2p_keys:from_keys(CPub, SPub),
    Lease = #{
        gateway => rand_hash(),
        tunnel_id => 1,
        end_date => (now_ms() + 60 * 1000) band 16#FFFFFFFF
    },
    {i2p_leaset:build(Identity, TimestampSec, 7, [Lease], Seed), SeedKey}.

%% Re-sign a fixture LeaseSet with a new publish time (same destination hash).
rebuild_ls(LS, SeedKey, TimestampSec) ->
    Identity = i2p_leaset:identity(LS),
    {{_SPub, Seed}, _CPub} = SeedKey,
    i2p_leaset:build(Identity, TimestampSec, 7, i2p_leaset:leases(LS), Seed).

caps_map(undefined) ->
    #{};
caps_map(Caps) ->
    #{<<"caps">> => Caps}.

version_number_of(Version) ->
    i2p_netdb:version_number(rebuild_fresh_version(Version)).

rebuild_fresh_version(Version) ->
    SeedKey = new_seed_key(),
    build_from(SeedKey, now_ms(), Version, <<"4">>, <<"192.0.2.10">>).

declared_floodfill_of(Caps) ->
    SeedKey = new_seed_key(),
    RI = build_from(SeedKey, now_ms(), <<"0.9.74">>, Caps, <<"192.0.2.10">>),
    i2p_netdb:declared_floodfill(RI).

%% Store N freshly built routers, returning the store and their hashes.
store_n(Store, N, Now) ->
    store_n(Store, N, Now, []).

store_n(Store, 0, _Now, Acc) ->
    {Store, lists:reverse(Acc)};
store_n(Store, N, Now, Acc) ->
    {RI, _} = fixture_router(Now),
    Key = i2p_router_info:hash(RI),
    {Store1, added} = i2p_netdb:store(Store, RI, Now),
    store_n(Store1, N - 1, Now, [Key | Acc]).
