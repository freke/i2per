-module(i2p_framing_prop_tests).

%% Property tests for the NTCP2 data-phase framing layer.
%%
%% Invariants under test:
%%   - obfuscate_length/2 : deobfuscate_length/2 round-trips every valid
%%     length and chains the SipHash state identically on both sides
%%   - the length mask is a pure function of the SipHash state: two lengths
%%     masked against the same state cancel under XOR
%%   - deobfuscate_length/2 never returns an out-of-range length, and its
%%     recovery is the centre-inverse of obfuscate_length/2
%%   - encrypt_frame/4 : decrypt_frame/4 round-trips any payload and message
%%     number, advancing the SipHash state identically on both sides
%%   - data_phase_keys/2 derives distinct, correctly-sized per-direction keys
%%   - encode_block/2 : decode_blocks/1 are inverse over whole block lists

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%% --------------------------------------------------------------------------
%%% Length obfuscation
%%% --------------------------------------------------------------------------

length_roundtrip_prop_test_() ->
    {timeout, 60, fun length_roundtrip_prop/0}.

length_roundtrip_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Sip, Length},
                {sip_state_gen(), integer(16, 65535)},
                begin
                    {Obf, Sip1} = i2p_framing:obfuscate_length(Length, Sip),
                    {ok, Length, Sip1} =:= i2p_framing:deobfuscate_length(Obf, Sip)
                end
            ),
            [{numtests, 200}]
        )
    ).

mask_is_state_function_prop_test_() ->
    {timeout, 60, fun mask_is_state_function_prop/0}.

mask_is_state_function_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Sip, L1, L2},
                {sip_state_gen(), integer(16, 65535), integer(16, 65535)},
                begin
                    {O1, _Sip1} = i2p_framing:obfuscate_length(L1, Sip),
                    {O2, _Sip2} = i2p_framing:obfuscate_length(L2, Sip),
                    O1 bxor L1 =:= O2 bxor L2
                end
            ),
            [{numtests, 200}]
        )
    ).

deobfuscate_centre_inverse_prop_test_() ->
    {timeout, 60, fun deobfuscate_centre_inverse_prop/0}.

deobfuscate_centre_inverse_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Sip, ObfLen},
                {sip_state_gen(), integer(0, 65535)},
                case i2p_framing:deobfuscate_length(ObfLen, Sip) of
                    {ok, Length, Sip1} ->
                        Length >= 16 andalso
                            Length =< 65535 andalso
                            {ObfLen, Sip1} =:= i2p_framing:obfuscate_length(Length, Sip);
                    error ->
                        true
                end
            ),
            [{numtests, 200}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Frame round-trips
%%% --------------------------------------------------------------------------

frame_roundtrip_prop_test_() ->
    {timeout, 60, fun frame_roundtrip_prop/0}.

frame_roundtrip_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Key, Sip, MsgNum, Payload},
                {binary(32), sip_state_gen(), integer(0, 65535), payload_gen()},
                begin
                    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, MsgNum, Payload, Sip),
                    byte_size(Frame) =:= 18 + byte_size(Payload) andalso
                        case i2p_framing:decrypt_frame(Key, MsgNum, Frame, Sip) of
                            {ok, Payload, Sip1} -> true;
                            _ -> false
                        end
                end
            ),
            [{numtests, 100}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Key derivation
%%% --------------------------------------------------------------------------

data_phase_keys_prop_test_() ->
    {timeout, 60, fun data_phase_keys_prop/0}.

data_phase_keys_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Ck, H},
                {binary(32), binary(32)},
                begin
                    #{k_ab := KAb, k_ba := KBa, sip_ab := SipAb, sip_ba := SipBa} =
                        i2p_framing:data_phase_keys(Ck, H),
                    KAb =/= KBa andalso
                        byte_size(KAb) =:= 32 andalso
                        byte_size(KBa) =:= 32 andalso
                        SipAb =/= SipBa andalso
                        byte_size(maps:get(key, SipAb)) =:= 16 andalso
                        byte_size(maps:get(iv, SipAb)) =:= 8 andalso
                        byte_size(maps:get(key, SipBa)) =:= 16 andalso
                        byte_size(maps:get(iv, SipBa)) =:= 8
                end
            ),
            [{numtests, 100}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Blocks
%%% --------------------------------------------------------------------------

%% Bounded by `block_list_gen/0` rather than `list(block_gen())`: `list/1` puts no
%% ceiling on the length, so the cost of this property used to be a draw.
blocks_roundtrip_prop_test_() ->
    {timeout, 60, fun blocks_roundtrip_prop/0}.

blocks_roundtrip_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                Blocks,
                block_list_gen(),
                begin
                    Encoded = iolist_to_binary([
                        i2p_framing:encode_block(Type, Data)
                     || #{type := Type, data := Data} <- Blocks
                    ]),
                    {ok, Blocks} =:= i2p_framing:decode_blocks(Encoded)
                end
            ),
            [{numtests, 100}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Generators
%%% --------------------------------------------------------------------------

%% %%%%% Generators, and why they stop where they do %%%%%
%%
%% `payload_gen` used to be `integer(0, 65519)`, and that was the defect. The
%% property ran 100 draws, each sealing and opening a payload of up to 64 KB, so
%% its cost was decided by a lottery rather than by the property: 0.43s on this
%% project's hardware, and over eunit's default 5s budget on a GitHub runner --
%% which is how `i2p_framing_prop_tests:frame_roundtrip_prop_test` came to fail
%% #RJPXXGX having passed the run before it.
%%
%% **The upper bound was buying nothing.** Round-tripping at 64 KB and at 4 KB are
%% the same code path; what the wide range actually bought was an approximation of
%% the size limit, reached essentially never by uniform draw. So the size limits
%% are now stated -- once, deterministically, at exactly the numbers the source
%% cares about -- and the property generates a size that crosses a packet boundary
%% at a cost that does not dominate the suite.
%%
%% `blocks_roundtrip_prop_test` had the same shape one level up: `list(block_gen())`
%% has no upper bound on its *length*, so a single draw could hand it more blocks
%% than the run had budget for. It is a bounded vector now.

%% Comfortably past the NTCP2 data-packet boundary, so single-frame and
%% multi-packet payloads are both still generated.
-define(PROP_PAYLOAD_MAX, 2048).

%% A block list long enough to exercise encode/decode over several blocks without
%% leaving the cost of the test up to a draw.
-define(PROP_BLOCKS_MAX, 32).

sip_state_gen() ->
    ?LET(
        {Key, IV},
        {binary(16), binary(8)},
        #{key => Key, iv => IV}
    ).

payload_gen() ->
    ?LET(Size, integer(0, ?PROP_PAYLOAD_MAX), binary(Size)).

block_gen() ->
    ?LET(
        {Type, Data},
        {integer(0, 255), ?LET(Size, integer(0, 64), binary(Size))},
        #{type => Type, data => Data}
    ).

block_list_gen() ->
    ?LET(N, integer(0, ?PROP_BLOCKS_MAX), vector(N, block_gen())).

%% The one sip state the boundary cases share. Zero key and IV rather than a
%% generated one: these cases are about payload *size*, and a fixed state keeps
%% them from failing for an unrelated reason.
zero_sip() ->
    #{key => <<0:128>>, iv => <<0:64>>}.

%% %%%%% The size limits, stated rather than drawn %%%%%
%%
%% `i2p_framing` caps a payload at 65519 bytes and its `encrypt_frame/4` clause
%% raises `{too_large, N}` above that. Nothing tested either number: the generator
%% topped out *at* the limit, so a random draw could not exceed it and would have
%% to hit 65519 exactly to reach it. The rejection clause -- a guard clause, and
%% the easiest line in the file to break -- had no test at all.
%%
%% 65519 is written out rather than imported, because these are the numbers the
%% specification states. If `?MAX_PAYLOAD` in `i2p_framing` moves, these fail, and
%% that is the intended outcome: a changed limit is a changed protocol and should
%% arrive as a reviewable diff, not as a quietly retuned generator.

-define(MAX_PAYLOAD, 65519).
-define(FRAME_OVERHEAD, 18).

largest_legal_payload_roundtrips_test_() ->
    {timeout, 60, fun largest_legal_payload_roundtrips/0}.

largest_legal_payload_roundtrips() ->
    Key = crypto:strong_rand_bytes(32),
    Sip = zero_sip(),
    Payload = crypto:strong_rand_bytes(?MAX_PAYLOAD),
    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, 0, Payload, Sip),
    ?assertEqual(?MAX_PAYLOAD + ?FRAME_OVERHEAD, byte_size(Frame)),
    ?assertEqual({ok, Payload, Sip1}, i2p_framing:decrypt_frame(Key, 0, Frame, Sip)).

one_byte_over_the_limit_is_refused_test_() ->
    {timeout, 60, fun one_byte_over_the_limit_is_refused/0}.

one_byte_over_the_limit_is_refused() ->
    Key = crypto:strong_rand_bytes(32),
    Sip = zero_sip(),
    Payload = crypto:strong_rand_bytes(?MAX_PAYLOAD + 1),
    ?assertError({too_large, ?MAX_PAYLOAD + 1}, i2p_framing:encrypt_frame(Key, 0, Payload, Sip)).

empty_payload_roundtrips_test_() ->
    {timeout, 60, fun empty_payload_roundtrips/0}.

empty_payload_roundtrips() ->
    Key = crypto:strong_rand_bytes(32),
    Sip = zero_sip(),
    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, 0, <<>>, Sip),
    ?assertEqual(?FRAME_OVERHEAD, byte_size(Frame)),
    ?assertEqual({ok, <<>>, Sip1}, i2p_framing:decrypt_frame(Key, 0, Frame, Sip)).
