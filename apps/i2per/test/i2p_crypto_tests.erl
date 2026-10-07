-module(i2p_crypto_tests).

%% Known-answer and structural tests for the cryptographic layer.
%%
%% Sources for the KATs:
%%   - Ed25519: RFC 8032 section 7.1, TEST 1..3 (pure Ed25519)
%%   - X25519:  RFC 7748 sections 6.1 (Diffie-Hellman) and 5.2 (test
%%              vectors, including the iteration test up to 1000 steps;
%%              the 1,000,000-step result is also verified in OTP:
%%              7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424)
%%   - HKDF:    RFC 5869 appendix A, test cases 1..3 (SHA-256)
%%   - AEAD:    RFC 7539 section 2.8.2
%%   - Elligator2: reference Elligator2.java vectors (encode(false),
%%                 encode(true), decode), plus round-trip properties
%%   - Ratchet KDFs: determinism and structural properties (per
%%                 i2p_crypto moduledoc)

-include_lib("eunit/include/eunit.hrl").

hx(Hex) -> binary:decode_hex(Hex).

%%% --------------------------------------------------------------------------
%%% Ed25519 (RFC 8032)
%%% --------------------------------------------------------------------------

ed25519_rfc8032_test() ->
    Vectors = [
        {<<"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60">>,
            <<"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a">>, <<>>, <<
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            >>},
        {<<"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb">>,
            <<"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c">>, <<"72">>, <<
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            >>},
        {<<"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7">>,
            <<"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025">>, <<"af82">>, <<
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            >>}
    ],
    lists:foreach(
        fun({SeedHex, PubHex, MsgHex, SigHex}) ->
            Seed = hx(SeedHex),
            Pub = hx(PubHex),
            Msg = hx(MsgHex),
            Sig = hx(SigHex),
            ?assertEqual(Sig, i2p_crypto:ed25519_sign(Msg, Seed)),
            ?assert(i2p_crypto:ed25519_verify(Msg, Sig, Pub)),
            ?assertNot(i2p_crypto:ed25519_verify(<<Msg/binary, 0>>, Sig, Pub))
        end,
        Vectors
    ),
    ok.

ed25519_keygen_test() ->
    {Pub, Seed} = i2p_crypto:ed25519_keygen(),
    ?assertEqual(32, byte_size(Pub)),
    ?assertEqual(32, byte_size(Seed)),
    Data = crypto:strong_rand_bytes(32),
    Sig = i2p_crypto:ed25519_sign(Data, Seed),
    ?assertEqual(64, byte_size(Sig)),
    ?assert(i2p_crypto:ed25519_verify(Data, Sig, Pub)),
    ?assertNot(i2p_crypto:ed25519_verify(<<Data/binary, 0>>, Sig, Pub)).

%%% --------------------------------------------------------------------------
%%% X25519 (RFC 7748)
%%% --------------------------------------------------------------------------

x25519_rfc7748_6_1_test() ->
    APriv = hx(<<"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a">>),
    APub = hx(<<"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a">>),
    BPriv = hx(<<"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb">>),
    BPub = hx(<<"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f">>),
    Shared = hx(<<"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742">>),
    ?assertEqual(APub, i2p_crypto:x25519_public_key(APriv)),
    ?assertEqual(BPub, i2p_crypto:x25519_public_key(BPriv)),
    ?assertEqual(Shared, i2p_crypto:x25519_dh(APriv, BPub)),
    ?assertEqual(Shared, i2p_crypto:x25519_dh(BPriv, APub)).

x25519_rfc7748_5_2_test() ->
    %% Section 5.2 single-shot test vectors. The u-coordinate of the
    %% second vector ends in 0x93; the RFC requires masking its top bit.
    S1 = hx(<<"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4">>),
    U1 = hx(<<"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c">>),
    V1 = hx(<<"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552">>),
    S2 = hx(<<"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d">>),
    U2 = hx(<<"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493">>),
    V2 = hx(<<"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957">>),
    ?assertEqual(V1, i2p_crypto:x25519_dh(S1, U1)),
    ?assertEqual(V2, i2p_crypto:x25519_dh(S2, U2)).

x25519_iteration_test() ->
    %% RFC 7748 section 5.2 iteration test: start with k = u = 9 (base
    %% point encoding); each step sets k to X25519(k, u) and u to the old k.
    K0 = <<9, 0:248>>,
    ?assertEqual(
        hx(<<"422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079">>),
        i2p_crypto:x25519_dh(K0, K0)
    ),
    ?assertEqual(
        hx(<<"684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51">>),
        iterate(K0, K0, 1, 1000)
    ).

x25519_keygen_test() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    ?assertEqual(32, byte_size(Pub)),
    ?assertEqual(32, byte_size(Priv)),
    ?assertEqual(Pub, i2p_crypto:x25519_public_key(Priv)),
    {BPub, BPriv} = i2p_crypto:x25519_keygen(),
    S1 = i2p_crypto:x25519_dh(Priv, BPub),
    S2 = i2p_crypto:x25519_dh(BPriv, Pub),
    ?assertEqual(32, byte_size(S1)),
    ?assertEqual(S1, S2),
    ?assertNotEqual(<<0:256>>, S1).

x25519_small_order_test() ->
    %% OTP's crypto rejects an all-zero (small order) peer public key
    %% with an error instead of returning an all-zero shared secret.
    {_, Priv} = i2p_crypto:x25519_keygen(),
    ?assertError({error, _, _}, i2p_crypto:x25519_dh(Priv, <<0:256>>)).

%%% --------------------------------------------------------------------------
%%% Elligator2 (reference Elligator2.java vectors)
%%% --------------------------------------------------------------------------

elligator2_java_vectors_test() ->
    Test1 = hx(<<"33951964003c940878063ccfd0348af42150ca16d2646f2c5856e8338377d880">>),
    Test2 = hx(<<"e73507d38bae63992b3f57aac48c0abc14509589288457995a2b4ca3490aa207">>),
    ExpectFalse = hx(<<"2820b6b241e0f68a6c4a7fee3d978228ef3ae45533cd410aa91a415331d8612d">>),
    ExpectTrue = hx(<<"3cfb87c46c0b4575ca8175e0ed1c0ae9dae79db78df86997c4847b9f20b27718">>),
    ExpectDec = hx(<<"1e8afffed6bf53fe271ad572473262ded8faec68e5e67ef45ebb82eeba52604f">>),
    ?assertEqual({ok, ExpectFalse}, i2p_crypto:elligator2_encode(Test1, false)),
    ?assertEqual({ok, ExpectTrue}, i2p_crypto:elligator2_encode(Test1, true)),
    ?assertEqual({ok, ExpectDec}, i2p_crypto:elligator2_decode(Test2)),
    %% Round-trip on the reference representatives: TEST1 has bit 255 set
    %% (top byte 0x80), so as an integer it exceeds the field prime; the
    %% reference implementation operates on the raw 256-bit value and its
    %% decode does not invert its own encode for this out-of-field vector.
    %% Both decodes agree with the reference Elligator2.java output.
    ?assertEqual(
        {ok, hx(<<"46951964003c940878063ccfd0348af42150ca16d2646f2c5856e8338377d800">>)},
        i2p_crypto:elligator2_decode(ExpectFalse)
    ),
    ?assertEqual(
        {ok, hx(<<"46951964003c940878063ccfd0348af42150ca16d2646f2c5856e8338377d800">>)},
        i2p_crypto:elligator2_decode(ExpectTrue)
    ).

elligator2_roundtrip_test() ->
    lists:foreach(
        fun(_) ->
            case i2p_crypto:x25519_keygen_elg2() of
                {Pub, _Priv, Repr} ->
                    ?assertEqual({ok, Pub}, i2p_crypto:elligator2_decode(Repr))
            end
        end,
        lists:seq(1, 20)
    ),
    ok.

elligator2_high_bits_test() ->
    %% The two high bits of byte 31 are ignored by decode and chosen by
    %% the wire-form encoder; a representative with any high bits decodes
    %% to the same key as its masked form.
    %% TEST1 with bit 255 cleared so it is a valid in-field X25519 key
    %% (top bit set, as in the raw vector, would make x >= p).
    Pub = hx(<<"33951964003c940878063ccfd0348af42150ca16d2646f2c5856e8338377d800">>),
    {ok, R0} = i2p_crypto:elligator2_encode(Pub, false, 0),
    ?assertEqual({ok, Pub}, i2p_crypto:elligator2_decode(R0)),
    {ok, Rff} = i2p_crypto:elligator2_encode(Pub, false, 16#ff),
    ?assertEqual({ok, Pub}, i2p_crypto:elligator2_decode(Rff)),
    <<Rest:31/binary, Last>> = Rff,
    ?assertEqual(R0, <<Rest/binary, (Last band 16#3f)>>),
    ok.

elligator2_properties_test() ->
    %% For any key, either both alternative encodings fail (the key's
    %% v-coordinate is a quadratic non-residue) or every successful
    %% encoding decodes back to the key; the two encodings are distinct.
    lists:foreach(
        fun(_) ->
            {Pub, _} = i2p_crypto:x25519_keygen(),
            E1 = i2p_crypto:elligator2_encode(Pub, true),
            E2 = i2p_crypto:elligator2_encode(Pub, false),
            case {E1, E2} of
                {error, error} ->
                    ok;
                {error, {ok, R}} ->
                    ?assertEqual({ok, Pub}, i2p_crypto:elligator2_decode(R));
                {{ok, R}, error} ->
                    ?assertEqual({ok, Pub}, i2p_crypto:elligator2_decode(R));
                {{ok, R1}, {ok, R2}} ->
                    ?assertNotEqual(R1, R2),
                    ?assertEqual({ok, Pub}, i2p_crypto:elligator2_decode(R1)),
                    ?assertEqual({ok, Pub}, i2p_crypto:elligator2_decode(R2))
            end
        end,
        lists:seq(1, 20)
    ),
    ok.

%%% --------------------------------------------------------------------------
%%% HKDF-SHA256 (RFC 5869)
%%% --------------------------------------------------------------------------

hkdf_rfc5869_test() ->
    %% Test case 1
    IKM1 = binary:copy(<<16#0b>>, 22),
    Salt1 = hx(<<"000102030405060708090a0b0c">>),
    Info1 = hx(<<"f0f1f2f3f4f5f6f7f8f9">>),
    ?assertEqual(
        hx(<<
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        >>),
        i2p_crypto:hkdf_sha256(Salt1, IKM1, Info1, 42)
    ),
    %% Test case 2 (longer inputs/outputs)
    IKM2 = list_to_binary(lists:seq(0, 79)),
    Salt2 = list_to_binary(lists:seq(16#60, 16#af)),
    Info2 = list_to_binary(lists:seq(16#b0, 16#ff)),
    ?assertEqual(
        hx(<<
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        >>),
        i2p_crypto:hkdf_sha256(Salt2, IKM2, Info2, 82)
    ),
    %% Test case 3 (zero-length salt and info; empty salt == 32 zero bytes)
    IKM3 = binary:copy(<<16#0b>>, 22),
    ?assertEqual(
        hx(<<
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        >>),
        i2p_crypto:hkdf_sha256(<<>>, IKM3, <<>>, 42)
    ).

%%% --------------------------------------------------------------------------
%%% ChaCha20-Poly1305 (RFC 7539)
%%% --------------------------------------------------------------------------

aead_rfc7539_test() ->
    Key = hx(<<"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f">>),
    Nonce = hx(<<"070000004041424344454647">>),
    Plain = <<
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it."
    >>,
    AAD = hx(<<"50515253c0c1c2c3c4c5c6c7">>),
    Cipher = hx(<<
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692"
        "ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4"
        "def08e4b7a9de576d26586cec64b6116"
    >>),
    Tag = hx(<<"1ae10b594f09e26a7e902ecbd0600691">>),
    ?assertEqual(114, byte_size(Plain)),
    ?assertEqual({Cipher, Tag}, i2p_crypto:chacha20_poly1305_encrypt(Key, Nonce, Plain, AAD)),
    ?assertEqual(Plain, i2p_crypto:chacha20_poly1305_decrypt(Key, Nonce, Cipher, Tag, AAD)),
    ?assertEqual(
        {ok, Plain},
        i2p_crypto:chacha20_poly1305_open(Key, Nonce, <<Cipher/binary, Tag/binary>>, AAD)
    ).

aead_tamper_test() ->
    Key = hx(<<"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f">>),
    Nonce = hx(<<"070000004041424344454647">>),
    Plain = <<
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it."
    >>,
    AAD = hx(<<"50515253c0c1c2c3c4c5c6c7">>),
    {Cipher, Tag} = i2p_crypto:chacha20_poly1305_encrypt(Key, Nonce, Plain, AAD),
    <<_:15/binary, Last>> = Tag,
    BadTag = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (Last bxor 1)>>,
    ?assertEqual(error, i2p_crypto:chacha20_poly1305_decrypt(Key, Nonce, Cipher, BadTag, AAD)),
    ?assertEqual(
        error, i2p_crypto:chacha20_poly1305_open(Key, Nonce, <<Cipher/binary, BadTag/binary>>, AAD)
    ),
    ?assertEqual(error, i2p_crypto:chacha20_poly1305_open(Key, Nonce, <<1, 2, 3>>, AAD)).

aead_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    Data = crypto:strong_rand_bytes(100),
    ?assertEqual(
        {ok, Data},
        i2p_crypto:chacha20_poly1305_open(
            Key,
            i2p_crypto:zero_nonce(),
            i2p_crypto:chacha20_poly1305_seal(Key, i2p_crypto:zero_nonce(), Data, <<"ad">>),
            <<"ad">>
        )
    ),
    ?assertEqual(
        {ok, Data},
        i2p_crypto:chacha20_poly1305_open(
            Key,
            i2p_crypto:es_nonce(1234),
            i2p_crypto:chacha20_poly1305_seal(Key, i2p_crypto:es_nonce(1234), Data, <<>>),
            <<>>
        )
    ).

nonce_test() ->
    ?assertEqual(<<0:96>>, i2p_crypto:zero_nonce()),
    ?assertEqual(<<0:96>>, i2p_crypto:es_nonce(0)),
    ?assertEqual(<<0:32, 1:64/little-unsigned>>, i2p_crypto:es_nonce(1)),
    ?assertEqual(<<0:32, 16#ffff:64/little-unsigned>>, i2p_crypto:es_nonce(65535)),
    ?assertError(function_clause, i2p_crypto:es_nonce(-1)).

%% The counter is 64 bits, and the boundary that matters is the specification's
%% rather than 2^16.
%%
%% This bound used to be `0..65535`, on a doc claim that the session "must
%% ratchet thereafter" — which NTCP2 does not have and does not need. The guard
%% was the entire defect: a live data phase walks the counter once per frame in
%% each direction, so a connection died on the 65536th frame in *both*
%% directions with a `function_clause` raised out of a crypto helper, and from
%% outside read as a peer that had dropped. See #R8WNYK3.
%%
%% Three things are pinned here, and the middle one is the one a narrower test
%% would have missed:
%%
%%   - the top of the specification's range is accepted, and 2^64 - 1 — the one
%%     value the spec says must never be sent — is refused;
%%   - **65536 does not collide with 0.** The reason the old bound was defended
%%     as keystream reuse was that the nonce "is 8 bytes little-endian, so 65536
%%     and 0 collide". They do not: the field is 8 bytes, so the only value that
%%     collides with `es_nonce(0)` is 2^64, which is not representable and
%%     cannot be produced by an incrementing counter. Nonce reuse needs the
%%     counter to *repeat*, and a strictly monotonic one over a 64-bit field does
%%     not repeat. This asserts it on the bytes rather than arguing it in prose;
%%   - the encoding is little-endian all the way up, not only for small numbers.
%%     65536 is `16#010000`, so its low-order half is 1: byte 2 of the counter
%%     carries it and byte 6 carries 0. A big-endian encoding would put the 1 in
%%     byte 6 instead, which is what makes this discriminate rather than merely
%%     pass.
%%
%% 2^64 - 2 is written out once, here and nowhere else in the test: these are
%% the numbers the specification states, and a bound that moved should arrive as
%% a reviewable diff rather than as a retuned constant.
es_nonce_spans_the_specification_range_test() ->
    Top = 16#FFFFFFFFFFFFFFFE,
    ?assertEqual(<<0:32, Top:64/little-unsigned>>, i2p_crypto:es_nonce(Top)),
    ?assertError(function_clause, i2p_crypto:es_nonce(Top + 1)),
    ?assertError(function_clause, i2p_crypto:es_nonce(1 bsl 64)).

es_nonce_does_not_repeat_across_65536_test() ->
    N0 = i2p_crypto:es_nonce(0),
    N65535 = i2p_crypto:es_nonce(65535),
    N65536 = i2p_crypto:es_nonce(65536),
    %% The claim the old 65535 bound rested on, stated as bytes.
    ?assertNotEqual(N0, N65536),
    ?assertNotEqual(N65535, N65536),
    %% Little-endian at the boundary: 65536 = 16#010000, so `<<0:32, 0:8, 0:8,
    %% 1:8, 0:40>>`.
    ?assertEqual(<<0:32, 0:8, 0:8, 1:8, 0:40>>, N65536).

%% A strictly monotonic counter over the field's width cannot repeat, and that is
%% the whole reason widening the bound creates no keystream reuse.
%%
%% Enumerating a 64-bit field is impossible, so this checks the property at the
%% three points where it could plausibly be false: the wrap-adjacent top of the
%% range, the 16-bit boundary the defect was found at, and the very first
%% increment. Each is a distinct nonce, and the top is the largest the function
%% will produce.
es_nonce_is_unique_across_the_range_test() ->
    Points = [0, 1, 65535, 65536, 65537, 16#FFFFFFFFFFFFFFFD, 16#FFFFFFFFFFFFFFFE],
    Nonces = [i2p_crypto:es_nonce(N) || N <- Points],
    ?assertEqual(length(Nonces), length(lists:usort(Nonces))),
    %% and every one is 12 bytes, the size the AEAD calls require
    ?assert(lists:all(fun(Nonce) -> byte_size(Nonce) =:= 12 end, Nonces)).

%%% --------------------------------------------------------------------------
%%% Noise initialization and ratchet KDFs
%%% --------------------------------------------------------------------------

noise_initialize_test() ->
    %% Hardcoded: h = SHA256(protocol_name), ck = h, then h = SHA256(h)
    %% for the null prologue, with the fixed 40-byte protocol name.
    ?assertEqual(
        {
            hx(<<"9ccf852cc93bb9504441e950e01d52322e0d47add1e9a555f755b569ae183b5c">>),
            hx(<<"4caf11ef2c8e36564c53e88885064dbaacbe0054ad178f8079a646827e6ee40c">>)
        },
        i2p_crypto:noise_initialize()
    ).

noise_mix_test() ->
    {H, Ck} = i2p_crypto:noise_initialize(),
    Data = crypto:strong_rand_bytes(64),
    H1 = i2p_crypto:mixhash(H, Data),
    ?assertEqual(H1, i2p_crypto:mixhash(H, Data)),
    ?assertEqual(32, byte_size(H1)),
    ?assertNotEqual(H, H1),
    {Ck1, K} = i2p_crypto:mixkey(Ck, crypto:strong_rand_bytes(32)),
    ?assertEqual(32, byte_size(Ck1)),
    ?assertEqual(32, byte_size(K)).

ratchet_kdf_structure_test() ->
    R0 = crypto:strong_rand_bytes(32),
    K0 = crypto:strong_rand_bytes(32),
    %% dh_initialize builds a complete, deterministic tag set
    T1 = i2p_crypto:dh_initialize(R0, K0),
    ?assertEqual(T1, i2p_crypto:dh_initialize(R0, K0)),
    #{next_root_key := NRK, sess_tag_ck := STC, symm_key_ck := SKC} = T1,
    [?assertEqual(32, byte_size(B)) || B <- [NRK, STC, SKC]],
    ?assertNotEqual(T1, i2p_crypto:dh_initialize(R0, crypto:strong_rand_bytes(32))),
    %% session-tag chain: 8-byte tags, chain key advances
    {Chain, Const} = i2p_crypto:session_tag_chain_init(STC),
    ?assertEqual(32, byte_size(Const)),
    {Chain2, Tag1} = i2p_crypto:session_tag_chain_step(Chain, Const),
    {Chain3, Tag2} = i2p_crypto:session_tag_chain_step(Chain2, Const),
    ?assertEqual(8, byte_size(Tag1)),
    ?assertEqual(8, byte_size(Tag2)),
    ?assertNotEqual(Tag1, Tag2),
    ?assertNotEqual(Chain2, Chain3),
    %% symmetric ratchet: distinct 32-byte keys
    {SC1, SymK1} = i2p_crypto:symmetric_ratchet(SKC),
    {SC2, SymK2} = i2p_crypto:symmetric_ratchet(SC1),
    ?assertNotEqual(SymK1, SymK2),
    ?assertNotEqual(SC1, SC2),
    %% DH ratchet and session-reply tag sets are complete and deterministic
    Tagset = i2p_crypto:dh_ratchet_tagset(K0, NRK),
    ?assertEqual(Tagset, i2p_crypto:dh_ratchet_tagset(K0, NRK)),
    Reply = i2p_crypto:session_reply_tagset(R0),
    ?assertEqual(Reply, i2p_crypto:session_reply_tagset(R0)),
    maps:foreach(fun(_K, V) -> ?assertEqual(32, byte_size(V)) end, Tagset),
    maps:foreach(fun(_K, V) -> ?assertEqual(32, byte_size(V)) end, Reply),
    ok.

%%% --------------------------------------------------------------------------
%%% AES-256-CBC (NTCP2 aesobfse ephemeral obfuscation)
%%% --------------------------------------------------------------------------

aes256cbc_openssl_kat_test() ->
    %% Generated with OpenSSL 3.x `openssl enc -aes-256-cbc -nopad`.
    Key = <<16#4266e2911d58de848da061a0f0c9db2f46cdf735545eafd9a376f13815649015:256>>,
    IV = <<16#1e8834d991073bbd210973d14a391602:128>>,
    Plain = <<16#a9ba31592fdd81e65976f203e96735f889f43906e34f46ec4458610fe49222f4:256>>,
    Cipher = <<
        16#278e1d9a808dba73c1424e5329fc371b6d6d3f14a7b9cec3a2ecc76264b6ec2b:256
    >>,
    ?assertEqual(Cipher, i2p_crypto:aes256cbc_encrypt(Key, IV, Plain)),
    ?assertEqual(Plain, i2p_crypto:aes256cbc_decrypt(Key, IV, Cipher)).

aes256cbc_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(16),
    Data = crypto:strong_rand_bytes(32),
    Cipher = i2p_crypto:aes256cbc_encrypt(Key, IV, Data),
    ?assertEqual(32, byte_size(Cipher)),
    ?assertEqual(Data, i2p_crypto:aes256cbc_decrypt(Key, IV, Cipher)),
    %% determinism
    ?assertEqual(Cipher, i2p_crypto:aes256cbc_encrypt(Key, IV, Data)),
    %% wrong key or IV must not decrypt to the same plaintext
    ?assertNotEqual(
        Data,
        i2p_crypto:aes256cbc_decrypt(crypto:strong_rand_bytes(32), IV, Cipher)
    ),
    ?assertNotEqual(
        Data,
        i2p_crypto:aes256cbc_decrypt(Key, crypto:strong_rand_bytes(16), Cipher)
    ).

aes256cbc_iv_chaining_test() ->
    %% The NTCP2 spec chains the ephemerals as a single CBC plaintext stream:
    %% the last ciphertext block of X becomes the IV for encrypting Y. This
    %% must equal encrypting X || Y in one AES-CBC pass.
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(16),
    X = crypto:strong_rand_bytes(32),
    Y = crypto:strong_rand_bytes(32),
    CX = i2p_crypto:aes256cbc_encrypt(Key, IV, X),
    CY = i2p_crypto:aes256cbc_encrypt(Key, binary:part(CX, 16, 16), Y),
    CXY = i2p_crypto:aes256cbc_encrypt(Key, IV, <<X/binary, Y/binary>>),
    ?assertEqual(binary:part(CXY, 0, 32), CX),
    ?assertEqual(binary:part(CXY, 32, 32), CY),
    %% decrypting Y with the chained IV recovers Y
    ?assertEqual(Y, i2p_crypto:aes256cbc_decrypt(Key, binary:part(CX, 16, 16), CY)).

%%% --------------------------------------------------------------------------
%%% Noise N pattern (ECIES tunnel build request records)
%%% --------------------------------------------------------------------------

noise_n_initialize_kat_test() ->
    %% h = protocol_name || 0 (32 bytes), ck = h, h = SHA256(h)
    %% protocol_name = "Noise_N_25519_ChaChaPoly_SHA256" (31 bytes + pad)
    ?assertEqual(
        {
            hx(<<"694d52445a27d9adfad29c7632395dc1e4354c69b4f92eac8a1ee46a9ed21554">>),
            hx(<<"4e6f6973655f4e5f32353531395f436861436861506f6c795f53484132353600">>)
        },
        i2p_crypto:noise_n_initialize()
    ).

noise_n_roundtrip_test() ->
    {H0, Ck0} = i2p_crypto:noise_n_initialize(),
    {EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    H1 = i2p_crypto:mixhash(H0, crypto:strong_rand_bytes(16)),
    Plain = crypto:strong_rand_bytes(464),
    {CT, Tag, H2, Ck1} = i2p_crypto:noise_n_encrypt(EphPriv, StaticPub, H1, Ck0, Plain),
    ?assertEqual(464, byte_size(CT)),
    ?assertEqual(16, byte_size(Tag)),
    {ok, Plain2, H3, Ck2} = i2p_crypto:noise_n_decrypt(StaticPriv, EphPub, H1, Ck0, CT, Tag),
    ?assertEqual(Plain, Plain2),
    ?assertEqual(H2, H3),
    ?assertEqual(Ck1, Ck2).

noise_n_determinism_test() ->
    {H0, Ck0} = i2p_crypto:noise_n_initialize(),
    {_EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
    {StaticPub, _StaticPriv} = i2p_crypto:x25519_keygen(),
    H1 = i2p_crypto:mixhash(H0, crypto:strong_rand_bytes(16)),
    Plain = crypto:strong_rand_bytes(464),
    {CT1, Tag1, H1a, Ck1a} = i2p_crypto:noise_n_encrypt(EphPriv, StaticPub, H1, Ck0, Plain),
    {CT2, Tag2, H1b, Ck1b} = i2p_crypto:noise_n_encrypt(EphPriv, StaticPub, H1, Ck0, Plain),
    ?assertEqual(CT1, CT2),
    ?assertEqual(Tag1, Tag2),
    ?assertEqual(H1a, H1b),
    ?assertEqual(Ck1a, Ck1b).

noise_n_tamper_test() ->
    {H0, Ck0} = i2p_crypto:noise_n_initialize(),
    {EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    H1 = i2p_crypto:mixhash(H0, crypto:strong_rand_bytes(16)),
    Plain = crypto:strong_rand_bytes(464),
    {CT, Tag, _H2, _Ck1} = i2p_crypto:noise_n_encrypt(EphPriv, StaticPub, H1, Ck0, Plain),
    %% Flip a bit in the ciphertext
    <<First:120/binary, FirstByte:8, Rest/binary>> = CT,
    BadCT = <<First/binary, (FirstByte bxor 1), Rest/binary>>,
    ?assertEqual(error, i2p_crypto:noise_n_decrypt(StaticPriv, EphPub, H1, Ck0, BadCT, Tag)),
    %% Flip a bit in the tag
    <<TFirst:15/binary, TByte:8>> = Tag,
    BadTag = <<TFirst/binary, (TByte bxor 1)>>,
    ?assertEqual(error, i2p_crypto:noise_n_decrypt(StaticPriv, EphPub, H1, Ck0, CT, BadTag)).

noise_n_h_chain_test() ->
    %% Verify that H advances correctly across two hops, and that the
    %% decryption chain produces the same intermediate H/Ck values.
    {H0, Ck0} = i2p_crypto:noise_n_initialize(),
    TruncHash1 = crypto:strong_rand_bytes(16),
    TruncHash2 = crypto:strong_rand_bytes(16),
    {Eph1Pub, Eph1Priv} = i2p_crypto:x25519_keygen(),
    {_Static1Pub, _Static1Priv} = i2p_crypto:x25519_keygen(),
    {Eph2Pub, Eph2Priv} = i2p_crypto:x25519_keygen(),
    {Static2Pub, Static2Priv} = i2p_crypto:x25519_keygen(),
    %% Hop 1 encrypt
    H1 = i2p_crypto:mixhash(H0, TruncHash1),
    Plain1 = crypto:strong_rand_bytes(464),
    {CT1, Tag1, H1after, Ck1after} = i2p_crypto:noise_n_encrypt(
        Eph1Priv, Static2Pub, H1, Ck0, Plain1
    ),
    %% Hop 2 encrypt (chained from hop 1)
    H2pre = i2p_crypto:mixhash(H1after, TruncHash2),
    Plain2 = crypto:strong_rand_bytes(464),
    {CT2, Tag2, H2after, Ck2after} = i2p_crypto:noise_n_encrypt(
        Eph2Priv, Static2Pub, H2pre, Ck1after, Plain2
    ),
    %% Decrypt hop 1 — must recover same H1after and Ck1after
    {ok, Plain1r, H1dec, Ck1dec} = i2p_crypto:noise_n_decrypt(
        Static2Priv, Eph1Pub, H1, Ck0, CT1, Tag1
    ),
    ?assertEqual(Plain1, Plain1r),
    ?assertEqual(H1after, H1dec),
    ?assertEqual(Ck1after, Ck1dec),
    %% Decrypt hop 2 — chained from hop 1's H/Ck
    H2pre_dec = i2p_crypto:mixhash(H1dec, TruncHash2),
    ?assertEqual(H2pre, H2pre_dec),
    {ok, Plain2r, H2dec, Ck2dec} = i2p_crypto:noise_n_decrypt(
        Static2Priv, Eph2Pub, H2pre_dec, Ck1dec, CT2, Tag2
    ),
    ?assertEqual(Plain2, Plain2r),
    ?assertEqual(H2after, H2dec),
    ?assertEqual(Ck2after, Ck2dec).

noise_n_wrong_key_test() ->
    {H0, Ck0} = i2p_crypto:noise_n_initialize(),
    {EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {_, WrongPriv} = i2p_crypto:x25519_keygen(),
    H1 = i2p_crypto:mixhash(H0, crypto:strong_rand_bytes(16)),
    Plain = crypto:strong_rand_bytes(464),
    {CT, Tag, _, _} = i2p_crypto:noise_n_encrypt(EphPriv, StaticPub, H1, Ck0, Plain),
    %% Decrypt with wrong static key fails
    ?assertEqual(error, i2p_crypto:noise_n_decrypt(WrongPriv, EphPub, H1, Ck0, CT, Tag)),
    %% Decrypt with wrong ephemeral key fails
    {_, WrongEph} = i2p_crypto:x25519_keygen(),
    ?assertEqual(error, i2p_crypto:noise_n_decrypt(StaticPriv, WrongEph, H1, Ck0, CT, Tag)).

%%% --------------------------------------------------------------------------
%%% Raw ChaCha20 stream cipher (tunnel reply record layering)
%%% --------------------------------------------------------------------------

chacha20_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    Data = crypto:strong_rand_bytes(512),
    Cipher = i2p_crypto:chacha20_crypt(Key, IV, Data),
    ?assertEqual(Data, i2p_crypto:chacha20_crypt(Key, IV, Cipher)),
    ?assertEqual(
        Data, i2p_crypto:chacha20_crypt(Key, IV, i2p_crypto:chacha20_crypt(Key, IV, Data))
    ).

chacha20_determinism_test() ->
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    Data = crypto:strong_rand_bytes(256),
    C1 = i2p_crypto:chacha20_crypt(Key, IV, Data),
    C2 = i2p_crypto:chacha20_crypt(Key, IV, Data),
    ?assertEqual(C1, C2).

chacha20_different_iv_test() ->
    Key = crypto:strong_rand_bytes(32),
    IV1 = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
    IV2 = <<0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0>>,
    Data = crypto:strong_rand_bytes(128),
    C1 = i2p_crypto:chacha20_crypt(Key, IV1, Data),
    C2 = i2p_crypto:chacha20_crypt(Key, IV2, Data),
    ?assertNotEqual(C1, C2).

chacha20_position_byte_test() ->
    %% Verify that IV[4] (the record-position byte) selects a different
    %% keystream.  Encrypting with position=0 and position=1 over the same
    %% plaintext must produce different ciphertexts, and decrypting the
    %% position=1 ciphertext with position=0 must NOT recover the plaintext.
    Key = crypto:strong_rand_bytes(32),
    Data = crypto:strong_rand_bytes(192),
    IVPos0 = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
    IVPos1 = <<0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0>>,
    C0 = i2p_crypto:chacha20_crypt(Key, IVPos0, Data),
    C1 = i2p_crypto:chacha20_crypt(Key, IVPos1, Data),
    ?assertNotEqual(C0, C1),
    %% XOR-decryption with wrong position must not recover plaintext
    Wrong = i2p_crypto:chacha20_crypt(Key, IVPos0, C1),
    ?assertNotEqual(Data, Wrong).

%%% --------------------------------------------------------------------------
%%% Helpers
%%% --------------------------------------------------------------------------

%% RFC 7748 section 5.2 iteration: k = X25519(k, u), u = old k.
iterate(K, _U, I, Max) when I > Max ->
    K;
iterate(K, U, I, Max) ->
    iterate(i2p_crypto:x25519_dh(K, U), K, I + 1, Max).
