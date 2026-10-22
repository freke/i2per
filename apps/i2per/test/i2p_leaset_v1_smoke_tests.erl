-module(i2p_leaset_v1_smoke_tests).
-include_lib("eunit/include/eunit.hrl").

smoke_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    %% Build a v1 LeaseSet by hand: dest + 256-byte enc key + signing key + num + lease + sig
    DestBin = i2p_keys:to_binary(Identity),
    EncKey = crypto:strong_rand_bytes(256),
    SignPub = i2p_keys:signing_key(Identity),
    SignKeyBin = SignPub,
    Gateway = crypto:strong_rand_bytes(32),
    TunnelID = 42,
    EndDate = erlang:system_time(millisecond) + 60000,
    Lease = <<Gateway/binary, TunnelID:32/big, EndDate:64/big>>,
    Num = 1,
    LeasesBin = Lease,
    SignedData = <<DestBin/binary, EncKey/binary, SignKeyBin/binary, Num:8, LeasesBin/binary>>,
    Sig = i2p_crypto:ed25519_sign(SignedData, Seed),
    Bin = <<SignedData/binary, Sig/binary>>,
    {ok, LS} = i2p_leaset_v1:decode(Bin),
    ?assertEqual(i2p_keys:hash(Identity), i2p_leaset_v1:hash(LS)),
    ?assertEqual(1, length(i2p_leaset_v1:leases(LS))),
    ?assertEqual(Bin, i2p_leaset_v1:to_binary(LS)),
    ?assertEqual(1, i2p_leaset_v1:store_type()),
    ok.

new_seed_key() ->
    {{SPub, Seed}, {CPub, _}} = {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    {{SPub, Seed}, {CPub, rand_hash()}}.

identity_seed({{SPub, Seed}, {CPub, _}}) ->
    {i2p_keys:from_keys(CPub, SPub), Seed}.

rand_hash() ->
    crypto:strong_rand_bytes(32).
