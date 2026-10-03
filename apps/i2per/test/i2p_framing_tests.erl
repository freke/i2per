-module(i2p_framing_tests).

%% Unit tests for the NTCP2 data-phase framing layer.
%%
%% Coverage:
%%   - data_phase_keys/2: split() + SipHash ask KDF structure, direction
%%     separation, deterministic output
%%   - obfuscate_length/2 / deobfuscate_length/2: round-trip, IV chaining
%%     across frames, out-of-range rejection
%%   - encrypt_frame/4 / decrypt_frame/4: round-trips, tamper rejection,
%%     length mismatch, per-frame nonce derivation
%%   - encode_block/2, pad_block/1, decode_blocks/1: round-trips,
%%     malformed input, padding block type
%%   - encrypt_frame/4's size limits: the largest legal payload, one byte over
%%     it, and the empty payload

-include_lib("eunit/include/eunit.hrl").

%%% --------------------------------------------------------------------------
%%% data_phase_keys/2
%%% --------------------------------------------------------------------------

data_phase_keys_structure_test() ->
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    Keys = i2p_framing:data_phase_keys(Ck, H),
    #{k_ab := KAb, k_ba := KBa, sip_ab := SipAb, sip_ba := SipBa} = Keys,
    ?assertEqual(32, byte_size(KAb)),
    ?assertEqual(32, byte_size(KBa)),
    ?assertEqual(16, byte_size(maps:get(key, SipAb))),
    ?assertEqual(8, byte_size(maps:get(iv, SipAb))),
    ?assertEqual(16, byte_size(maps:get(key, SipBa))),
    ?assertEqual(8, byte_size(maps:get(iv, SipBa))),
    %% the two directions derive distinct material
    ?assertNotEqual(KAb, KBa),
    ?assertNotEqual(SipAb, SipBa),
    %% deterministic
    ?assertEqual(Keys, i2p_framing:data_phase_keys(Ck, H)).

data_phase_keys_directions_test() ->
    %% k_ba must not equal k_ab, and the SipHash IVs must be distinct even
    %% when derived from the same chaining key (both directions share Ck, H).
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    Keys = i2p_framing:data_phase_keys(Ck, H),
    ?assertNotEqual(maps:get(iv, maps:get(sip_ab, Keys)), maps:get(iv, maps:get(sip_ba, Keys))).

%%% --------------------------------------------------------------------------
%%% Length obfuscation
%%% --------------------------------------------------------------------------

length_roundtrip_test() ->
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    #{sip_ab := Sip} = i2p_framing:data_phase_keys(Ck, H),
    Lengths = [16, 100, 1000, 65535],
    lists:foreach(
        fun(Length) ->
            {Obf, Sip1} = i2p_framing:obfuscate_length(Length, Sip),
            ?assertEqual({ok, Length, Sip1}, i2p_framing:deobfuscate_length(Obf, Sip))
        end,
        Lengths
    ).

length_obfuscation_hides_boundaries_test() ->
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    #{sip_ab := Sip0} = i2p_framing:data_phase_keys(Ck, H),
    {Obf1, Sip1} = i2p_framing:obfuscate_length(100, Sip0),
    {Obf2, Sip2} = i2p_framing:obfuscate_length(200, Sip1),
    {Obf3, _Sip3} = i2p_framing:obfuscate_length(300, Sip2),
    %% consecutive lengths are masked with different per-frame masks
    ?assertNotEqual(Obf1 bxor 100, Obf2 bxor 200),
    ?assertNotEqual(Obf2 bxor 200, Obf3 bxor 300),
    %% receiver with the same state recovers them
    {ok, 100, Sip1a} = i2p_framing:deobfuscate_length(Obf1, Sip0),
    {ok, 200, Sip2a} = i2p_framing:deobfuscate_length(Obf2, Sip1a),
    {ok, 300, _Sip3a} = i2p_framing:deobfuscate_length(Obf3, Sip2a),
    ?assertEqual(Sip1, Sip1a),
    ?assertEqual(Sip2, Sip2a).

length_out_of_range_test() ->
    %% The bare first mask deobfuscates to length 0 — out of the 16..65535
    %% frame range, so the receiver must reject it.
    ?assertEqual(error, i2p_framing:deobfuscate_length(16#2462, sip0_reference())).

obfuscation_mask_reference_vector_test() ->
    %% First frame mask pinned to the committed SipHash KAT vector:
    %% hash_le(0..7, 0..15) = 6224939a79f5f593, low 16 bits as (hi bsl 8) bor lo
    %% = 0x2462. Independent oracle — not derived from the code under test.
    Sip0 = sip0_reference(),
    {Obf100, _} = i2p_framing:obfuscate_length(100, Sip0),
    {Obf16, _} = i2p_framing:obfuscate_length(16, Sip0),
    ?assertEqual(16#2406, Obf100),
    ?assertEqual(16#2472, Obf16),
    ?assertMatch({ok, 100, _}, i2p_framing:deobfuscate_length(16#2406, Sip0)).

%%% --------------------------------------------------------------------------
%%% Frame round-trips
%%% --------------------------------------------------------------------------

frame_roundtrip_test() ->
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    #{k_ab := K, sip_ab := Sip} = i2p_framing:data_phase_keys(Ck, H),
    Payload = crypto:strong_rand_bytes(200),
    {Frame, Sip1} = i2p_framing:encrypt_frame(K, 0, Payload, Sip),
    ?assertEqual({ok, Payload, Sip1}, i2p_framing:decrypt_frame(K, 0, Frame, Sip)),
    %% 2-byte length + sealed frame
    ?assertEqual(2 + byte_size(Payload) + 16, byte_size(Frame)).

frame_rejects_wrong_key_test() ->
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    #{k_ab := K, sip_ab := Sip} = i2p_framing:data_phase_keys(Ck, H),
    #{k_ba := KOther} = i2p_framing:data_phase_keys(Ck, H),
    Payload = crypto:strong_rand_bytes(64),
    {Frame, Sip1} = i2p_framing:encrypt_frame(K, 0, Payload, Sip),
    ?assertEqual(error, i2p_framing:decrypt_frame(KOther, 0, Frame, Sip)),
    %% wrong nonce also fails the AEAD
    ?assertEqual(error, i2p_framing:decrypt_frame(K, 1, Frame, Sip1)).

frame_rejects_tamper_test() ->
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    #{k_ab := K, sip_ab := Sip} = i2p_framing:data_phase_keys(Ck, H),
    Payload = crypto:strong_rand_bytes(64),
    {Frame, Sip1} = i2p_framing:encrypt_frame(K, 0, Payload, Sip),
    Tampered = flip_bit(Frame),
    ?assertEqual(error, i2p_framing:decrypt_frame(K, 0, Tampered, Sip)),
    %% truncated frame
    <<_Len:16/big, Sealed/binary>> = Frame,
    Truncated = <<_Len:16/big, (binary:part(Sealed, 0, byte_size(Sealed) - 1))/binary>>,
    ?assertEqual(error, i2p_framing:decrypt_frame(K, 0, Truncated, Sip)),
    %% wrong-length frame (length field says one thing, body another)
    ?assertEqual(error, i2p_framing:decrypt_frame(K, 0, <<0:16/big>>, Sip1)).

frame_multiple_messages_test() ->
    %% frames carry a per-direction message counter in the nonce
    Ck = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    #{k_ab := K, sip_ab := Sip0} = i2p_framing:data_phase_keys(Ck, H),
    P1 = crypto:strong_rand_bytes(10),
    P2 = crypto:strong_rand_bytes(20),
    {F1, Sip1} = i2p_framing:encrypt_frame(K, 0, P1, Sip0),
    {F2, _Sip2} = i2p_framing:encrypt_frame(K, 1, P2, Sip1),
    {ok, P1, Sip1a} = i2p_framing:decrypt_frame(K, 0, F1, Sip0),
    {ok, P2, _} = i2p_framing:decrypt_frame(K, 1, F2, Sip1a),
    ok.

%%% --------------------------------------------------------------------------
%%% Blocks
%%% --------------------------------------------------------------------------

block_roundtrip_test() ->
    Block = i2p_framing:encode_block(3, <<1, 2, 3, 4>>),
    ?assertEqual(<<3, 0, 4, 1, 2, 3, 4>>, Block),
    ?assertEqual({ok, [#{type => 3, data => <<1, 2, 3, 4>>}]}, i2p_framing:decode_blocks(Block)),
    ?assertEqual({ok, []}, i2p_framing:decode_blocks(<<>>)),
    %% padding block
    Pad = i2p_framing:pad_block(8),
    ?assertEqual(<<254, 0, 8>>, binary:part(Pad, 0, 3)),
    {ok, [#{type := 254, data := PadData}]} = i2p_framing:decode_blocks(Pad),
    ?assertEqual(8, byte_size(PadData)).

block_malformed_test() ->
    ?assertEqual(error, i2p_framing:decode_blocks(<<1, 0>>)),
    ?assertEqual(error, i2p_framing:decode_blocks(<<1, 0, 5, 1>>)).

block_multiple_test() ->
    A = i2p_framing:encode_block(3, <<1>>),
    B = i2p_framing:encode_block(2, <<2, 2>>),
    Pad = i2p_framing:pad_block(4),
    {ok, Blocks} = i2p_framing:decode_blocks(<<A/binary, B/binary, Pad/binary>>),
    ?assertEqual(
        [3, 2, 254],
        [maps:get(type, Block) || Block <- Blocks]
    ),
    ?assertEqual(4, byte_size(maps:get(data, lists:last(Blocks)))).

%%% --------------------------------------------------------------------------
%%% The size limits, stated rather than drawn
%%% --------------------------------------------------------------------------
%%
%% `i2p_framing` caps a payload at 65519 bytes and its `encrypt_frame/4` clause
%% raises `{too_large, N}` above that. Nothing tested either number: the
%% generator topped out *at* the limit, so a random draw could not exceed it and
%% would have to hit 65519 exactly to reach it. The rejection clause -- a guard
%% clause, and the easiest line in the file to break -- had no test at all.
%%
%% These three lived in `i2p_framing_prop_tests` until they were moved here,
%% which is where an example-based assertion belongs: they have no generator and
%% no `?FORALL`, so they were neither a property nor in the layer whose header
%% documents what it covers. Moving them is also what lets the property layer's
%% generator stay small -- it no longer has to approximate a boundary.
%%
%% 65519 is written out rather than imported, because these are the numbers the
%% specification states. If `?MAX_PAYLOAD` in `i2p_framing` moves, these fail,
%% and that is the intended outcome: a changed limit is a changed protocol and
%% should arrive as a reviewable diff, not as a quietly retuned generator.

-define(MAX_PAYLOAD, 65519).
-define(FRAME_OVERHEAD, 18).

largest_legal_payload_roundtrips_test() ->
    Key = crypto:strong_rand_bytes(32),
    Sip = zero_sip(),
    Payload = crypto:strong_rand_bytes(?MAX_PAYLOAD),
    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, 0, Payload, Sip),
    ?assertEqual(?MAX_PAYLOAD + ?FRAME_OVERHEAD, byte_size(Frame)),
    ?assertEqual({ok, Payload, Sip1}, i2p_framing:decrypt_frame(Key, 0, Frame, Sip)).

one_byte_over_the_limit_is_refused_test() ->
    Key = crypto:strong_rand_bytes(32),
    Sip = zero_sip(),
    Payload = crypto:strong_rand_bytes(?MAX_PAYLOAD + 1),
    ?assertError({too_large, ?MAX_PAYLOAD + 1}, i2p_framing:encrypt_frame(Key, 0, Payload, Sip)).

empty_payload_roundtrips_test() ->
    Key = crypto:strong_rand_bytes(32),
    Sip = zero_sip(),
    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, 0, <<>>, Sip),
    ?assertEqual(?FRAME_OVERHEAD, byte_size(Frame)),
    ?assertEqual({ok, <<>>, Sip1}, i2p_framing:decrypt_frame(Key, 0, Frame, Sip)).

%%% --------------------------------------------------------------------------
%%% Helpers
%%% --------------------------------------------------------------------------

%% The one sip state the boundary cases share. Zero key and IV rather than a
%% generated one: these cases are about payload *size*, and a fixed state keeps
%% them from failing for an unrelated reason.
zero_sip() ->
    #{key => <<0:128>>, iv => <<0:64>>}.

%% The veorq reference state: key = bytes 0..15, IV = bytes 0..7. Its first
%% mask is the low 16 bits of the committed SipHash KAT vector for len 8
%% ("6224939a79f5f593" -> 0x2462).
sip0_reference() ->
    #{key => list_to_binary(lists:seq(0, 15)), iv => list_to_binary(lists:seq(0, 7))}.

flip_bit(<<B:8, Rest/binary>>) ->
    <<(B bxor 1):8, Rest/binary>>.
