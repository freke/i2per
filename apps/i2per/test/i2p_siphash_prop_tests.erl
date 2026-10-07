-module(i2p_siphash_prop_tests).

%% Property tests for the pure-Erlang SipHash-2-4 implementation.
%%
%% Invariants under test:
%%   - the *_le byte layout is little-endian: an independent LSB-first fold
%%     over the bytes recovers the integer digest, which also pins the output
%%     sizes at 8 and 16 bytes (catches endianness bugs)
%%   - a single-bit change to the data or the key changes both the 64-bit and
%%     the 128-bit digest (bit sensitivity)
%%   - distinct inputs produce distinct 64-bit digests under a fixed key
%%     (collision-immunity shape)
%%
%% %%%%% What is deliberately not here %%%%%
%%
%% There is no property asserting that the digests are in bounds and that the
%% `_le` variants are 8 and 16 bytes. There was one, and it could not fail: an
%% XOR of four masked values is masked, so "the digest is below 2^64" follows
%% from the constructor, and `<<X:64/little-unsigned>>` is 8 bytes by
%% definition. A mismatch would have been a compile error, not a test failure.
%%
%% Worse, it was blind to both ways this module can actually be wrong. Laying the
%% digest out big-endian instead of little leaves it in bounds and 8 bytes long,
%% so that property stayed green while `hash_le_endianness_prop_test` went red
%% and the router masked every frame length with the wrong bytes. And dropping
%% the `b = 0xff` finalisation block yields a wrong digest for every input while
%% staying in bounds and correctly sized -- green on all six properties here,
%% caught only by the reference vectors in `i2p_siphash_tests`.
%%
%% The two endianness properties below are what make the bounds claim testable:
%% `le_decode/3` consumes exactly 8 and exactly 16 bytes and compares the folded
%% integer to `hash/2`, so size and layout fall out of an equality rather than
%% being asserted separately.

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

hash_le_endianness_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Data, Key},
                {var_binary(), binary(16)},
                le_decode(i2p_siphash:hash_le(Data, Key), 0, 0) =:=
                    i2p_siphash:hash(Data, Key)
            ),
            [{numtests, 200}]
        )
    ).

hash_128_le_endianness_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Data, Key},
                {var_binary(), binary(16)},
                begin
                    <<W1Bin:8/binary, W2Bin:8/binary>> =
                        i2p_siphash:hash_128_le(Data, Key),
                    {le_decode(W1Bin, 0, 0), le_decode(W2Bin, 0, 0)} =:=
                        i2p_siphash:hash_128(Data, Key)
                end
            ),
            [{numtests, 200}]
        )
    ).

single_bit_data_sensitivity_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {{Data, ByteIdx}, Key},
                {data_and_index_gen(), binary(16)},
                begin
                    Data2 = flip_bit(Data, ByteIdx, 0),
                    i2p_siphash:hash(Data, Key) =/= i2p_siphash:hash(Data2, Key) andalso
                        i2p_siphash:hash_128(Data, Key) =/= i2p_siphash:hash_128(Data2, Key)
                end
            ),
            [{numtests, 200}]
        )
    ).

single_bit_key_sensitivity_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Data, Key, KeyBit},
                {var_binary(), binary(16), integer(0, 127)},
                begin
                    Key2 = flip_bit(Key, KeyBit div 8, KeyBit rem 8),
                    i2p_siphash:hash(Data, Key) =/= i2p_siphash:hash(Data, Key2) andalso
                        i2p_siphash:hash_128(Data, Key) =/= i2p_siphash:hash_128(Data, Key2)
                end
            ),
            [{numtests, 200}]
        )
    ).

distinct_inputs_distinct_digests_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {L1, L2, D1, D2, Key},
                {integer(0, 256), integer(0, 256), binary(64), binary(64), binary(16)},
                begin
                    A = <<L1:16/big, D1/binary>>,
                    B = <<L2:16/big, D2/binary>>,
                    digest_distinct(A, B, Key, A =:= B)
                end
            ),
            [{numtests, 200}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Helpers
%%% --------------------------------------------------------------------------

digest_distinct(A, B, Key, _Equal) ->
    i2p_siphash:hash(A, Key) =/= i2p_siphash:hash(B, Key).

le_decode(<<Byte, Rest/binary>>, Shift, Acc) ->
    le_decode(Rest, Shift + 8, Acc bor (Byte bsl Shift));
le_decode(<<>>, _Shift, Acc) ->
    Acc.

flip_bit(Bin, ByteIdx, BitIdx) ->
    <<Prefix:ByteIdx/binary, Byte:8, Rest/binary>> = Bin,
    <<Prefix/binary, (Byte bxor (1 bsl BitIdx)):8, Rest/binary>>.

var_binary() ->
    ?LET(Size, integer(0, 300), binary(Size)).

data_and_index_gen() ->
    ?LET(
        Size,
        integer(1, 1024),
        ?LET(
            Bin,
            binary(Size),
            ?LET(Idx, integer(0, Size - 1), {Bin, Idx})
        )
    ).
