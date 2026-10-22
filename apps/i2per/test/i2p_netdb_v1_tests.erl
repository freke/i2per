-module(i2p_netdb_v1_tests).

-include_lib("eunit/include/eunit.hrl").

%% Unit tests for v1 LeaseSet storage in the NetDb.

netdb_v1_store_and_find_test() ->
    Store0 = i2p_netdb:new(),
    Bin = build_v1(),
    {ok, Store1, added} = i2p_netdb:store_ls_v1_binary(Store0, Bin, now_sec()),
    Key = v1_key(Bin),
    ?assertMatch({ok, _}, i2p_netdb:find_ls_v1(Store1, Key)),
    ?assertEqual(error, i2p_netdb:find_ls_v1(Store0, Key)).

netdb_v1_expired_not_stored_test() ->
    Store0 = i2p_netdb:new(),
    Bin = build_v1_expired(),
    ?assertMatch({ok, _, expired}, i2p_netdb:store_ls_v1_binary(Store0, Bin, now_sec())).

now_sec() ->
    erlang:system_time(second).

build_v1() ->
    build_v1(erlang:system_time(millisecond) + 60000).

build_v1_expired() ->
    build_v1(erlang:system_time(millisecond) - 60000).

build_v1(EndDate) ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    DestBin = i2p_keys:to_binary(Identity),
    EncKey = crypto:strong_rand_bytes(256),
    SignPub = i2p_keys:signing_key(Identity),
    Gateway = crypto:strong_rand_bytes(32),
    TunnelID = 42,
    Lease = <<Gateway/binary, TunnelID:32/big, EndDate:64/big>>,
    Num = 1,
    SignedData = <<DestBin/binary, EncKey/binary, SignPub/binary, Num:8, Lease/binary>>,
    Sig = i2p_crypto:ed25519_sign(SignedData, Seed),
    <<SignedData/binary, Sig/binary>>.

v1_key(Bin) ->
    {ok, LS} = i2p_leaset_v1:decode(Bin),
    i2p_leaset_v1:hash(LS).

new_seed_key() ->
    {{SPub, Seed}, {CPub, _}} = {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    {{SPub, Seed}, {CPub, crypto:strong_rand_bytes(32)}}.

identity_seed({{SPub, Seed}, {CPub, _}}) ->
    {i2p_keys:from_keys(CPub, SPub), Seed}.