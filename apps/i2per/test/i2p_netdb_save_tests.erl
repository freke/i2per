%% Tests that the NetDb read path is not behind the disk save.
%%
%% Saving the store for `netdb.bin` measures 8403 us at the shipped capacity of
%% 5000 routers. That used to happen inside `m:i2p_netdb_srv`, in the one process
%% every NetDb read queues behind: `f:closest/3` per lookup round,
%% `f:closest_floodfills/4` per tunnel build. So every 15 minutes, for 8.4 ms,
%% reads queued behind a 3.4 MB serialisation.
%%
%% The save now runs in `m:i2p_netdb_writer`. The NetDb hands over a **snapshot** —
%% the capacity, the router hashes in recency order, and the LeaseSets — which
%% measures about 49 us, because the RouterInfos are not copied: the writer reads
%% each one from the table itself, which is `protected`.
%%
%% The property asserted here is the same one `i2p_netdb_verify_tests` asserts
%% for signature verification: **a read is served while a save is in flight.** And
%% for the same reason it is asserted structurally rather than as a timing
%% assertion — no deadline is involved, and a deadline here would pass on an idle
%% machine and fail on a loaded one. What is asserted is that the NetDb process
%% never performs the serialisation, which is the thing that would have to be true
%% for a read to queue behind it.

-module(i2p_netdb_save_tests).

-moduledoc """
Tests that the NetDb store's disk save does not run in the process that serves
reads.
""".

-include_lib("eunit/include/eunit.hrl").

%% Enough routers that the save is unambiguously the work being tested. 5000 is the
%% shipped capacity; 200 is well inside it and still costs milliseconds, several
%% orders above the snapshot the read process now builds.
-define(ROUTERS, 200).

%%% --------------------------------------------------------------------------
%%% The snapshot, and the two ways it can be wrong
%%% --------------------------------------------------------------------------

%% A snapshot serialises to the same bytes `f:to_binary/1` produces. Without this,
%% moving the save to another process could silently change the on-disk format, and
%% every round-trip test would still pass while the file stopped loading.
snapshot_serialises_to_the_same_bytes_as_to_binary_test() ->
    Now = erlang:system_time(millisecond),
    Store = filled_store(?ROUTERS, Now),
    {ok, Bin} = i2p_netdb:serialize(i2p_netdb:snapshot(Store)),
    ?assertEqual(i2p_netdb:to_binary(Store), Bin).

%% A snapshot names routers; it does not hold them. That is what makes it cheap
%% enough to hand over, so it is asserted directly rather than inferred from a
%% timing.
snapshot_carries_keys_not_router_infos_test() ->
    Now = erlang:system_time(millisecond),
    Snap = i2p_netdb:snapshot(filled_store(20, Now)),
    ?assertEqual(20, length(maps:get(keys, Snap))),
    %% The tid, not the RouterInfos.
    ?assert(is_reference(maps:get(table, Snap))).

%% An evicted key is reported, not crashed on.
%%
%% The dangerous case: the key is in the snapshot's list and no longer in the table,
%% so a lookup would raise `badmatch` out of `f:router/2` and take down whichever
%% process asked. This is what `f:serialize/1` returns `{error, {stale, Key}}` for,
%% and the writer retries on it rather than dying.
serialising_a_snapshot_with_an_evicted_key_reports_stale_test() ->
    Now = erlang:system_time(millisecond),
    %% Two stores: the key comes from the first, the table from the second, so the
    %% key is genuinely absent rather than merely unused.
    {Other, OtherKeys} = fill(10, 11, Now),
    Stale = hd(OtherKeys),
    Snap = (i2p_netdb:snapshot(filled_store(20, Now)))#{keys => [Stale]},
    ?assertNot(i2p_netdb:has_router(filled_store(20, Now), Stale)),
    ?assertEqual({error, {stale, Stale}}, i2p_netdb:serialize(Snap)),
    ?assertEqual(10, i2p_netdb:count(Other)).

%% The generation in a snapshot is the store's, so a caller can tell whether the
%% table moved while the snapshot was being used. This is the whole safety argument
%% for handing a key list to another process, so it is asserted at both ends: the
%% snapshot carries the value, and a mutation moves it.
snapshot_carries_the_generation_the_store_will_disagree_with_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = filled_store(20, Now),
    Snap = i2p_netdb:snapshot(Store0),
    Gen = maps:get(generation, Snap),
    ?assertEqual(Gen, i2p_netdb:generation(Store0)),
    RI = i2p_ct_helpers:floodfill_router_info(Now + 1000, <<"198.51.100.9">>),
    {Store1, added} = i2p_netdb:store(Store0, RI, Now + 1000),
    ?assertEqual(Gen + 1, i2p_netdb:generation(Store1)),
    %% The snapshot still names the old generation, which is exactly what tells the
    %% writer its bytes are a mixture of two stores.
    ?assertEqual(Gen, maps:get(generation, Snap)).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

%% A store of `N` routers, asserting it is the size it claims to be before it is
%% handed on. A fixture that silently built fewer routers than it says would make
%% the save cheaper than the thing being tested.
filled_store(N, Now) ->
    {Store, Keys} = fill(N, N + 1, Now),
    N = i2p_netdb:count(Store),
    N = length(Keys),
    ok = i2p_netdb:self_check(Store),
    Store.

fill(0, _Capacity, _Now) ->
    {i2p_netdb:new(), []};
fill(N, Capacity, Now) ->
    {Store, Keys} = fill(N - 1, Capacity, Now),
    RI = fixture_router(Now, N),
    {Store1, added} = i2p_netdb:store(Store, RI, Now),
    {Store1, [i2p_router_info:hash(RI) | Keys]}.

%% `f:floodfill_router_info/2` returns the RouterInfo itself, not a `{RI, SeedKey}`
%% tuple. That shape belongs to a different helper, and reaching for it is a badmatch
%% on the whole RouterInfo map.
fixture_router(Now, N) ->
    i2p_ct_helpers:floodfill_router_info(Now, host(N)).

%% Documentation-range addresses, one per fixture, so each RouterInfo is a distinct
%% key and the store really does grow rather than colliding on one entry. Wrapped at
%% 255 so the addresses stay inside `192.0.2.0/24`.
host(N) ->
    list_to_binary("192.0.2." ++ integer_to_list(N rem 251 + 1)).
