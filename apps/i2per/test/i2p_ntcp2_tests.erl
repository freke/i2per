%% Known-answer and structural tests for the NTCP2 Noise XK handshake
%% (Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256).
%%
%% The tests pin the protocol structure, Alice/Bob symmetry (both sides must
%% derive identical data-phase keys), and the rejection paths.

-module(i2p_ntcp2_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PROTOCOL_NAME, <<"Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256">>).

%%% --------------------------------------------------------------------------
%%% Full handshake round-trips
%%% --------------------------------------------------------------------------

roundtrip_empty_padding_test() ->
    {KeysA, KeysB} = handshake(0, 0),
    assert_same_keys(KeysA, KeysB).

roundtrip_padding_test() ->
    {KeysA, KeysB} = handshake(64, 37),
    assert_same_keys(KeysA, KeysB).

roundtrip_max_reasonable_padding_test() ->
    {KeysA, KeysB} = handshake(256, 128),
    assert_same_keys(KeysA, KeysB).

%% Both sides recover the same messages and derive the same keys.
handshake(PadLen1, PadLen2) ->
    {AlicePub, AlicePriv} = alice_static(),
    {BobPub, BobPriv} = bob_static(),
    BobHash = bob_hash(),
    BobIV = bob_iv(),
    S0A = i2p_ntcp2:alice_init(BobPub, BobHash, BobIV, AlicePriv, AlicePub),
    S0B = i2p_ntcp2:bob_init(BobPriv, BobPub, BobHash, BobIV),
    Pad1 = crypto:strong_rand_bytes(PadLen1),
    TsA = 1_700_000_000,
    Payload = routerinfo_payload(),
    Opts1 = #{padlen => PadLen1, m3p2len => byte_size(Payload) + 16, ts => TsA},
    {ok, Msg1, S1A} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts1, Pad1),
    ?assertEqual(64 + PadLen1, byte_size(Msg1)),
    {ok, #{padlen := PadLen1, m3p2len := M3P2Len, ts := TsA}, S1B} =
        i2p_ntcp2:receive_msg1(S0B, Msg1),
    ?assertEqual(byte_size(Payload) + 16, M3P2Len),
    Pad2 = crypto:strong_rand_bytes(PadLen2),
    TsB = 1_700_000_010,
    {ok, Msg2, S2B} = i2p_ntcp2:create_msg2(S1B, eph_b(), Pad2, TsB),
    ?assertEqual(64 + PadLen2, byte_size(Msg2)),
    {ok, #{padlen := PadLen2, ts := TsB}, S2A} =
        i2p_ntcp2:receive_msg2(S1A, Msg2),
    {ok, Msg3, S3A} = i2p_ntcp2:create_msg3(S2A, Payload),
    ?assertEqual(48 + byte_size(Payload) + 16, byte_size(Msg3)),
    {ok, Payload, S3B} = i2p_ntcp2:receive_msg3(S2B, Msg3),
    {i2p_ntcp2:data_phase_keys(S3A), i2p_ntcp2:data_phase_keys(S3B)}.

assert_same_keys(KeysA, KeysB) ->
    ?assertEqual(KeysA, KeysB),
    #{k_ab := KAb, k_ba := KBa} = KeysA,
    ?assertEqual(32, byte_size(KAb)),
    ?assertEqual(32, byte_size(KBa)),
    ?assertNotEqual(KAb, KBa).

%%% --------------------------------------------------------------------------
%%% Determinism and wire structure
%%% --------------------------------------------------------------------------

create_msg1_deterministic_test() ->
    {AlicePub, AlicePriv} = alice_static(),
    {BobPub, _BobPriv} = bob_static(),
    BobHash = bob_hash(),
    BobIV = bob_iv(),
    S0A = i2p_ntcp2:alice_init(BobPub, BobHash, BobIV, AlicePriv, AlicePub),
    Opts = #{padlen => 0, m3p2len => 48, ts => 1_700_000_000},
    {ok, Msg1, _} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts, <<>>),
    {ok, Msg1b, _} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts, <<>>),
    ?assertEqual(Msg1, Msg1b),
    %% A different ephemeral changes the AES block (and everything after it).
    {ok, Msg1c, _} = i2p_ntcp2:create_msg1(S0A, eph_c(), Opts, <<>>),
    ?assertNotEqual(binary:part(Msg1, 0, 32), binary:part(Msg1c, 0, 32)).

initialize_structure_test() ->
    %% ck = SHA256("Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"), then
    %% h = mixhash(sha256(ck), rs) — both precomputed, not derived at runtime.
    {_BobPub, BobPriv} = bob_static(),
    BobPub = i2p_crypto:x25519_public_key(BobPriv),
    {Ck, H} = i2p_ntcp2:initialize(BobPub),
    ?assertEqual(
        <<16#72E842C545E18080D39C4493BB91D7EDF228981771218C1F624E206F28D32F71:256>>,
        Ck
    ),
    ?assertEqual(i2p_crypto:mixhash(crypto:hash(sha256, Ck), BobPub), H),
    %% precomputation is identical for Alice (Bob's key) and Bob (his own)
    {AlicePub, AlicePriv} = alice_static(),
    SA = i2p_ntcp2:alice_init(
        i2p_crypto:x25519_public_key(BobPriv), bob_hash(), bob_iv(), AlicePriv, AlicePub
    ),
    SB = i2p_ntcp2:bob_init(BobPriv, i2p_crypto:x25519_public_key(BobPriv), bob_hash(), bob_iv()),
    ?assertEqual(maps:get(ck, SA), maps:get(ck, SB)),
    ?assertEqual(maps:get(h, SA), maps:get(h, SB)),
    ?assertEqual(48, byte_size(?PROTOCOL_NAME)).

%%% --------------------------------------------------------------------------
%%% Rejection paths
%%% --------------------------------------------------------------------------

msg1_tamper_rejected_test() ->
    {_S0A, S0B, Msg1, _} = start_handshake(<<>>, #{padlen => 0}),
    Bad = flip_byte(Msg1, 0),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Bad)),
    Bad2 = flip_byte(Msg1, 40),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Bad2)).

msg2_tamper_rejected_test() ->
    {S0A, _S0B, _Msg1, S1B} = start_handshake(<<>>, #{padlen => 0}),
    {ok, Msg2, _} = i2p_ntcp2:create_msg2(S1B, eph_b(), <<>>, 1_700_000_000),
    ?assertEqual(error, i2p_ntcp2:receive_msg2(S0A, flip_byte(Msg2, 0))),
    ?assertEqual(error, i2p_ntcp2:receive_msg2(S0A, flip_byte(Msg2, 33))).

msg3_tamper_rejected_test() ->
    Payload = routerinfo_payload(),
    {S0A, _S0B, _Msg1, S1B} =
        start_handshake(<<>>, #{padlen => 0, m3p2len => byte_size(Payload) + 16}),
    {ok, Msg2, S2B} = i2p_ntcp2:create_msg2(S1B, eph_b(), <<>>, 1_700_000_000),
    {ok, _, S2A} = i2p_ntcp2:receive_msg2(S0A, Msg2),
    {ok, Msg3, _} = i2p_ntcp2:create_msg3(S2A, Payload),
    ?assertEqual(error, i2p_ntcp2:receive_msg3(S2B, flip_byte(Msg3, 0))),
    ?assertEqual(error, i2p_ntcp2:receive_msg3(S2B, flip_byte(Msg3, 60))).

padding_length_mismatch_rejected_test() ->
    S0B = bob_state(),
    %% padding present but padlen declared 0 (extra 16 bytes follow the frame)
    Msg1 = msg1_only(crypto:strong_rand_bytes(16), #{padlen => 0}),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Msg1)),
    %% padding declared but missing
    Msg1b = msg1_only(<<>>, #{padlen => 16}),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Msg1b)).

m3p2len_too_small_rejected_test() ->
    S0B = bob_state(),
    Msg1 = msg1_only(<<>>, #{padlen => 0, m3p2len => 18}),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Msg1)).

high_bit_x_rejected_test() ->
    %% Set the high bit of the decrypted X: requests an unsupported ML-KEM
    %% upgrade. AES is deterministic, so encrypting a crafted key with the
    %% known hash/IV and observing the failure is enough.
    {AlicePub, AlicePriv} = alice_static(),
    {BobPub, BobPriv} = bob_static(),
    BobHash = bob_hash(),
    BobIV = bob_iv(),
    S0A = i2p_ntcp2:alice_init(BobPub, BobHash, BobIV, AlicePriv, AlicePub),
    S0B = i2p_ntcp2:bob_init(BobPriv, BobPub, BobHash, BobIV),
    Opts = #{padlen => 0, m3p2len => 48, ts => 1_700_000_000},
    {ok, Msg1, _} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts, <<>>),
    HighX = i2p_crypto:aes256cbc_encrypt(
        BobHash,
        BobIV,
        <<0:248, 1:8>>
    ),
    HighMsg = <<HighX/binary, (binary:part(Msg1, 32, 32))/binary>>,
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, HighMsg)).

wrong_static_key_rejected_test() ->
    %% Alice uses a wrong responder static key: her es DH diverges and Bob's
    %% AEAD authentication must fail.
    {AlicePub, AlicePriv} = alice_static(),
    {BobPriv, BobPub} = bob_static(),
    {_OtherPub, OtherPriv} = other_static(),
    WrongPub = i2p_crypto:x25519_public_key(OtherPriv),
    BobHash = bob_hash(),
    BobIV = bob_iv(),
    S0A = i2p_ntcp2:alice_init(WrongPub, BobHash, BobIV, AlicePriv, AlicePub),
    S0B = i2p_ntcp2:bob_init(BobPriv, BobPub, BobHash, BobIV),
    Opts = #{padlen => 0, m3p2len => 48, ts => 1_700_000_000},
    {ok, Msg1, _} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts, <<>>),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Msg1)).

wrong_hash_rejected_test() ->
    %% A wrong responder hash/IV (published values vs actual) fails the AES
    %% deobfuscation and everything downstream.
    {AlicePub, AlicePriv} = alice_static(),
    {BobPriv, BobPub} = bob_static(),
    WrongHash = crypto:hash(sha256, <<"someone-else">>),
    WrongIV = crypto:strong_rand_bytes(16),
    S0A = i2p_ntcp2:alice_init(BobPub, WrongHash, WrongIV, AlicePriv, AlicePub),
    S0B = i2p_ntcp2:bob_init(BobPriv, BobPub, bob_hash(), bob_iv()),
    Opts = #{padlen => 0, m3p2len => 48, ts => 1_700_000_000},
    {ok, Msg1, _} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts, <<>>),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Msg1)).

payload_length_mismatch_test() ->
    {S0A, _S0B, _Msg1, S1B} = start_handshake(<<>>, #{padlen => 0}),
    {ok, Msg2, _S2B} = i2p_ntcp2:create_msg2(S1B, eph_b(), <<>>, 1_700_000_000),
    {ok, _, S2A} = i2p_ntcp2:receive_msg2(S0A, Msg2),
    %% m3p2len in msg1 was 48; pass a payload of the wrong size
    ?assertEqual(error, i2p_ntcp2:create_msg3(S2A, crypto:strong_rand_bytes(64))),
    ?assertEqual(error, i2p_ntcp2:create_msg3(S2A, routerinfo_payload())).

msg3_short_rejected_test() ->
    {_S0A, _S0B, _Msg1, S1B} = start_handshake(<<>>, #{padlen => 0}),
    {ok, _Msg2, S2B} = i2p_ntcp2:create_msg2(S1B, eph_b(), <<>>, 1_700_000_000),
    ?assertEqual(error, i2p_ntcp2:receive_msg3(S2B, crypto:strong_rand_bytes(40))).

%%% --------------------------------------------------------------------------
%%% Helpers
%%% --------------------------------------------------------------------------

%% Build msg1 (create only, no receive): returns {Msg1, S1A}.
msg1_only(Pad, Opts) ->
    {AlicePub, AlicePriv} = alice_static(),
    {BobPub, _BobPriv} = bob_static(),
    S0A = i2p_ntcp2:alice_init(BobPub, bob_hash(), bob_iv(), AlicePriv, AlicePub),
    Opts1 = maps:merge(#{padlen => byte_size(Pad), m3p2len => 48, ts => 1_700_000_000}, Opts),
    {ok, Msg1, _S1A} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts1, Pad),
    Msg1.

bob_state() ->
    {BobPub, BobPriv} = bob_static(),
    i2p_ntcp2:bob_init(BobPriv, BobPub, bob_hash(), bob_iv()).

%% Run msg1 create + receive with the given padding/options, returning the
%% states needed by callers.
start_handshake(Pad, Opts) ->
    {AlicePub, AlicePriv} = alice_static(),
    {BobPub, BobPriv} = bob_static(),
    BobHash = bob_hash(),
    BobIV = bob_iv(),
    S0A = i2p_ntcp2:alice_init(BobPub, BobHash, BobIV, AlicePriv, AlicePub),
    S0B = i2p_ntcp2:bob_init(BobPriv, BobPub, BobHash, BobIV),
    Opts1 = maps:merge(#{padlen => byte_size(Pad), m3p2len => 48, ts => 1_700_000_000}, Opts),
    {ok, Msg1, S1A} = i2p_ntcp2:create_msg1(S0A, eph_a(), Opts1, Pad),
    {ok, _Options, S1B} = i2p_ntcp2:receive_msg1(S0B, Msg1),
    {S1A, S0B, Msg1, S1B}.

routerinfo_payload() ->
    RI = <<0:256, 16#434F4E46:32>>,
    Block = i2p_framing:encode_block(2, <<0:8, RI/binary>>),
    <<Block/binary, (i2p_framing:pad_block(8))/binary>>.

flip_byte(Bin, Index) ->
    <<Pre:Index/binary, B:8, Post/binary>> = Bin,
    <<Pre/binary, (B bxor 16#FF):8, Post/binary>>.

alice_static() ->
    Priv = <<16#416C6963650000000000000000000000000000000000000000000000000001:256>>,
    {i2p_crypto:x25519_public_key(Priv), Priv}.

bob_static() ->
    Priv = <<16#426F6200000000000000000000000000000000000000000000000000000002:256>>,
    {i2p_crypto:x25519_public_key(Priv), Priv}.

other_static() ->
    Priv = <<16#4F746865720000000000000000000000000000000000000000000000000003:256>>,
    {i2p_crypto:x25519_public_key(Priv), Priv}.

bob_hash() ->
    crypto:hash(sha256, <<"bob-router-identity">>).

bob_iv() ->
    <<16#0B0BB0B00B0BB0B00B0BB0B00B0BB0B0:128>>.

eph_a() ->
    <<16#65657068656D6572616C2D616C6963650000000000000000000000000000:256>>.

eph_b() ->
    <<16#65657068656D6572616C2D626F620000000000000000000000000000000000:256>>.

eph_c() ->
    <<16#65657068656D6572616C2D636861726C696500000000000000000000000000:256>>.
