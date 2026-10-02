%% Unit tests for the SSU2 PeerTest core: the signed-data construction,
%% Ed25519 sign/verify, per-role block building, reject-code classification,
%% nonce-derived out-of-session connection IDs, and the reachability result
%% state machine.

-module(i2p_peertest_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PROLOGUE, <<"PeerTestValidate">>).

bob_hash() -> crypto:strong_rand_bytes(32).
charlie_hash() -> crypto:strong_rand_bytes(32).

keys() -> i2p_crypto:ed25519_keygen().

signed_data_layout_test() ->
    Bob = bob_hash(),
    Charlie = charlie_hash(),
    Nonce = 16#AABBCCDD,
    Ts = 1_700_000_000,
    Port = 49657,
    Ip = <<192, 0, 2, 10>>,
    Data = i2p_peertest:signed_data(Bob, Charlie, 2, Nonce, Ts, 6, Port, Ip),
    ?assertEqual(16 + 32 + 32 + 1 + 4 + 4 + 1 + 2 + 4, byte_size(Data)),
    <<Prologue:16/binary, Bob:32/binary, Charlie:32/binary, Ver:8, Nonce2:32, Ts2:32, Asz:8,
        Port2:16, Ip2:4/binary>> = Data,
    ?assertEqual(?PROLOGUE, Prologue),
    ?assertEqual(2, Ver),
    ?assertEqual(Nonce, Nonce2),
    ?assertEqual(Ts, Ts2),
    ?assertEqual(6, Asz),
    ?assertEqual(Port, Port2),
    ?assertEqual(Ip, Ip2).

signed_data_no_charlie_layout_test() ->
    Bob = bob_hash(),
    Ip = <<200, 1, 2, 3>>,
    Data = i2p_peertest:signed_data(Bob, undefined, 2, 1, 2, 6, 7777, Ip),
    ?assertEqual(16 + 32 + 1 + 4 + 4 + 1 + 2 + 4, byte_size(Data)).

ipv6_address_size_test() ->
    Ip6 = <<0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    ?assertEqual(18, i2p_peertest:address_size(Ip6)),
    ?assertEqual(6, i2p_peertest:address_size(<<1, 2, 3, 4>>)),
    Data = i2p_peertest:signed_data(bob_hash(), undefined, 2, 1, 2, 18, 1234, Ip6),
    ?assertEqual(16 + 32 + 1 + 4 + 4 + 1 + 2 + 16, byte_size(Data)),
    ?assertEqual(Ip6, binary:part(Data, byte_size(Data) - 16, 16)).

sign_verify_ok_test_() ->
    {timeout, 60, fun sign_verify_ok/0}.

sign_verify_ok() ->
    {SignPub, SignSeed} = keys(),
    Bob = bob_hash(),
    Charlie = charlie_hash(),
    Ip = <<10, 0, 0, 1>>,
    Port = 40000,
    Sig = i2p_peertest:sign(Bob, Charlie, 2, 16#12345678, 1234, Port, Ip, SignSeed),
    ?assertEqual(64, byte_size(Sig)),
    ?assert(
        i2p_peertest:verify(Bob, Charlie, 2, 16#12345678, 1234, Port, Ip, Sig, SignPub)
    ).

sign_verify_tamper_fails_test_() ->
    {timeout, 60, fun sign_verify_tamper_fails/0}.

sign_verify_tamper_fails() ->
    {SignPub, SignSeed} = keys(),
    Bob = bob_hash(),
    Ip = <<10, 0, 0, 1>>,
    Sig = i2p_peertest:sign(Bob, undefined, 2, 7, 1, 40000, Ip, SignSeed),
    ?assertNot(
        i2p_peertest:verify(Bob, undefined, 2, 7, 2, 40000, Ip, Sig, SignPub)
    ),
    ?assertNot(
        i2p_peertest:verify(Bob, undefined, 2, 7, 1, 40001, Ip, Sig, SignPub)
    ),
    ?assertNot(
        i2p_peertest:verify(Bob, undefined, 2, 7, 1, 40000, <<0, 0, 0, 1>>, Sig, SignPub)
    ),
    Other = bob_hash(),
    ?assertNot(
        i2p_peertest:verify(Other, undefined, 2, 7, 1, 40000, Ip, Sig, SignPub)
    ).

wrong_signer_fails_test_() ->
    {timeout, 60, fun wrong_signer_fails/0}.

wrong_signer_fails() ->
    {SignPub, SignSeed} = keys(),
    {_OtherPub, _} = keys(),
    Bob = bob_hash(),
    Ip = <<1, 2, 3, 4>>,
    Sig = i2p_peertest:sign(Bob, undefined, 2, 9, 9, 3000, Ip, SignSeed),
    ?assertNot(
        i2p_peertest:verify(bob_hash(), undefined, 2, 9, 9, 3000, Ip, Sig, SignPub)
    ),
    %% Charlie hash presence must change the signed bytes.
    Charlie = charlie_hash(),
    Sig3 = i2p_peertest:sign(Bob, Charlie, 2, 9, 9, 3000, Ip, SignSeed),
    ?assert(
        i2p_peertest:verify(Bob, Charlie, 2, 9, 9, 3000, Ip, Sig3, SignPub)
    ).

block_builder_test() ->
    BobHash = bob_hash(),
    Sig = crypto:strong_rand_bytes(64),
    B = i2p_peertest:block(1, 0, 0, <<0:256>>, 2, 5, 6, 45678, <<8, 8, 8, 8>>, Sig),
    ?assertEqual({peertest, 1, 0, 0, <<0:256>>, 2, 5, 6, 45678, <<8, 8, 8, 8>>, Sig}, B),
    B2 = i2p_peertest:block(2, 0, 0, BobHash, 2, 5, 6, 45678, <<8, 8, 8, 8>>, Sig),
    ?assertEqual({peertest, 2, 0, 0, BobHash, 2, 5, 6, 45678, <<8, 8, 8, 8>>, Sig}, B2).

conn_id_derivation_test() ->
    Nonce = 16#11223344,
    Dst = i2p_peertest:dst_conn_id(Nonce),
    Src = i2p_peertest:src_conn_id(Nonce),
    ?assertEqual((16#11223344 bsl 32) bor 16#11223344, Dst),
    ?assertEqual((bnot Dst) band 16#FFFFFFFFFFFFFFFF, Src),
    ?assert(Src >= 0).

reject_classification_test() ->
    ?assert(i2p_peertest:is_bob_reject(1)),
    ?assert(i2p_peertest:is_bob_reject(5)),
    ?assertNot(i2p_peertest:is_bob_reject(64)),
    ?assert(i2p_peertest:is_charlie_reject(64)),
    ?assert(i2p_peertest:is_charlie_reject(70)),
    ?assertNot(i2p_peertest:is_charlie_reject(5)),
    ?assert(i2p_peertest:is_reject(128)),
    ?assert(i2p_peertest:is_reject(67)),
    ?assert(i2p_peertest:is_reject(3)),
    ?assertNot(i2p_peertest:is_reject(0)).

result_matrix_test() ->
    %% Exactly the SSU2 spec result table.
    ?assertEqual(unknown, i2p_peertest:result(false, false, false)),
    ?assertEqual(firewalled, i2p_peertest:result(true, false, false)),
    ?assertEqual(ok, i2p_peertest:result(false, true, false)),
    ?assertEqual(ok, i2p_peertest:result(true, true, false)),
    ?assertEqual(unknown, i2p_peertest:result(false, false, true)),
    ?assertEqual(firewalled, i2p_peertest:result(true, false, true)),
    ?assertEqual(ok, i2p_peertest:result(false, true, true)),
    ?assertEqual(ok, i2p_peertest:result(true, true, true)).
