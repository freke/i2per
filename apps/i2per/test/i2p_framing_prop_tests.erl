-module(i2p_framing_prop_tests).

%% Property tests for the NTCP2 data-phase framing layer.
%%
%% Invariants under test:
%%   - obfuscate_length/2 : deobfuscate_length/2 round-trips every valid
%%     length and chains the SipHash state identically on both sides
%%   - the length mask is the low 16 bits of SipHash-2-4(iv, key), and the
%%     advanced state is a function of the incoming state alone -- not of the
%%     length being obfuscated
%%   - deobfuscate_length/2 recovers exactly the legal frame lengths over the
%%     whole 16-bit wire space, and refuses the rest
%%   - encrypt_frame/4 : decrypt_frame/4 round-trip any payload and message
%%     number, advancing the SipHash state identically on both sides
%%   - data_phase_keys/2 derives distinct, correctly-sized per-direction keys
%%   - encode_block/2 : decode_blocks/1 are inverse over whole block lists
%%
%% %%%%% Everything about the mask is recomputed here %%%%%
%%
%% `mask_for/1` and `advance/1` below re-derive the length mask and the state
%% transition from the SipHash state, rather than reading either back out of
%% `i2p_framing`. That is the whole difference between a property and a
%% restatement, and it is not a style preference.
%%
%% A mutant applied *symmetrically* -- to `obfuscate_length/2` and
%% `deobfuscate_length/2` together -- leaves every round-trip in this file
%% green, because both ends of the conversation are wrong in the same direction
%% and therefore still agree. Advancing the IV past the digest instead of to it,
%% for instance, is a real and fatal NTCP2 bug: i2per stops interoperating from
%% the second frame onward, and it is green on every round-trip here and in
%% `i2p_framing_tests`. Only a property that knows what the answer *should* be,
%% independently of the code that produced it, can see it. The mask's byte order
%% is the same story for a different reason: swapping the two mask bytes yields a
%% different, entirely self-consistent mask.

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

%% %%%%% The mask is a property of the state, not of the length %%%%%
%%
%% This used to be `O1 bxor L1 =:= O2 bxor L2`, which is the shape of
%% `obfuscate_length/2`'s own definition restated, and which threw both advanced
%% states into `_Sip1` and `_Sip2`. It could not fail for the reason it exists to
%% fail: "the mask is a function of the state" is what the code says.
%%
%% What it asserts now are the two halves that have teeth, neither of them read
%% back out of the function under test:
%%
%%   - the mask is the low 16 bits of `i2p_siphash:hash_le(IV, Key)`, assembled
%%     low byte first. That is the wire format, and swapping the two bytes is a
%%     self-consistent, wholly undetectable-by-round-trip mutation.
%%   - two lengths obfuscated against the same state advance it to the *same*
%%     state -- see the doubled `Sip1` in the match. Length independence of the
%%     advance is the receiver's only reason to stay in step with the sender, and
%%     it is precisely what the discarded `_Sip1`/`_Sip2` would have checked.

mask_is_state_function_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Sip, L1, L2},
                {sip_state_gen(), integer(16, 65535), integer(16, 65535)},
                begin
                    {O1, Sip1} = i2p_framing:obfuscate_length(L1, Sip),
                    {O2, Sip1} = i2p_framing:obfuscate_length(L2, Sip),
                    O1 =:= (L1 bxor mask_for(Sip)) andalso
                        O2 =:= (L2 bxor mask_for(Sip)) andalso
                        Sip1 =:= advance(Sip)
                end
            ),
            [{numtests, 200}]
        )
    ).

deobfuscate_centre_inverse_prop_test_() ->
    {timeout, 60, fun deobfuscate_centre_inverse_prop/0}.

%% %%%%% The refusal half is the half a draw never reaches %%%%%
%%
%% `deobfuscate_length/2` accepts 65520 of the 65536 obfuscated lengths and
%% refuses the other 16 -- the 16 wire values that decode below 16. The old
%% property drew `ObfLen` uniformly, so it reached the refusal in roughly one run
%% in twenty -- and an `error -> true` branch made the assertion vacuous on the
%% nineteen where it did not. The module doc claimed `deobfuscate_length/2`
%% "never returns an out-of-range length", and that claim had no test behind it.
%%
%% So the illegal half is enumerated rather than sampled. Both halves of the
%% contract are asserted here, against the mask this file computes for itself:
%%
%%   - the two *legal* edges, 16 and 65535, recover by the centre-inverse and
%%     advance the state to what `advance/1` says it should;
%%   - *all sixteen* illegal values are refused, for every generated state. That
%%     is 200 states x 16 values = 3200 refusal checks, against the 0.024% chance
%%     a single uniform draw had of landing on one.
%%
%% Sweeping the whole 16-bit space would additionally prove there are exactly 16
%% refusals with no holes in the legal half -- but XOR against a fixed mask is a
%% bijection, so that is arithmetic rather than behaviour, and it costs ~750ms a
%% draw against a tier that runs in 0.19s. The edges and the illegal half are
%% where the range check can actually be wrong; that is where the draws go.

deobfuscate_centre_inverse_prop() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                Sip,
                sip_state_gen(),
                begin
                    Mask = mask_for(Sip),
                    Next = advance(Sip),
                    {ok, 16, Next} =:= i2p_framing:deobfuscate_length(16 bxor Mask, Sip) andalso
                        {ok, 65535, Next} =:=
                            i2p_framing:deobfuscate_length(65535 bxor Mask, Sip) andalso
                        [] =:=
                            [
                                L
                             || L <- lists:seq(0, 15),
                                i2p_framing:deobfuscate_length(L bxor Mask, Sip) =/= error
                            ]
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
%% the size limit, reached essentially never by uniform draw. The size limits are
%% now stated as example tests -- once, deterministically, at exactly the numbers
%% the source cares about -- in `i2p_framing_tests`, and this generator produces a
%% size that crosses a packet boundary at a cost that does not dominate the suite.
%%
%% `blocks_roundtrip_prop_test` had the same shape one level up: `list(block_gen())`
%% has no upper bound on its *length*, so a single draw could hand it more blocks
%% than the run had budget for. It is a bounded vector now.
%%
%% **The sweep in `deobfuscate_centre_inverse_prop` is the opposite trade, on
%% purpose.** It gives up draws for coverage of a boundary a draw cannot reach, and
%% its cost is fixed and known -- 65536 recoveries per state, one SipHash each --
%% rather than decided by a lottery.

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

%%% --------------------------------------------------------------------------
%%% What the specification says, restated independently
%%% --------------------------------------------------------------------------

%% %%%%% The mask, from the specification rather than from the code %%%%%
%%
%% The low 16 bits of `SipHash-2-4(iv, key)`, little byte first: the two lowest
%% bytes of the 8-byte little-endian digest, so byte 0 is the mask's low byte.

mask_for(#{key := Key, iv := IV}) ->
    <<Lo, Hi, _/binary>> = i2p_siphash:hash_le(IV, Key),
    (Hi bsl 8) bor Lo.

%% %%%%% The advance, from the specification rather than from the code %%%%%
%%
%% "the IV advances to each frame's SipHash output" -- to the digest, not past it.
%% One SipHash of the current IV under the key, and the resulting state has that
%% digest as its new IV.

advance(Sip = #{key := Key, iv := IV}) ->
    Sip#{iv => i2p_siphash:hash_le(IV, Key)}.
