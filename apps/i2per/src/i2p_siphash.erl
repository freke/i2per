-module(i2p_siphash).

-moduledoc """
Pure-Erlang SipHash-2-4 (Aumasson & Bernstein).

Used by NTCP2 to obfuscate the 2-byte frame length: `f:obfuscate_length/2`
computes `hash_le(IV, Key)` and masks the length with the low two bytes of the
result.

`Key` is bytes 0..15 of the 32-byte SipHash key material `m:i2p_framing` derives
from the transport chaining key. `IV` starts as bytes 16..23 of that same
material and then becomes **the previous frame's digest** -- `obfuscate_length/2`
sets `iv := Next`, the whole 8-byte `hash_le/2` result, so it chains frame to
frame. Nothing from a frame header on the wire enters it.

Cross-checked against the official reference implementation (veorq/SipHash
siphash.c) and OpenSSL's `openssl mac SIPHASH`; all reference vectors are
committed to `test/i2p_siphash_tests.erl`.

## Variants

- `hash/2` and `hash_le/2` return the standard 64-bit SipHash-2-4.
- `hash_128/2` and `hash_128_le/2` return the 128-bit variant (SipHash-2-4-128):
  word 1 is `v0 ^ v1 ^ v2 ^ v3` after the tail and 4 final rounds, then
  `v1 ^= 0xdd` and 4 more rounds for word 2 (matches the reference
  implementation and OpenSSL, 16-byte output).

## Usage

```erlang
%% 64-bit digest as an unsigned integer
Digest = i2p_siphash:hash(Data, Key).

%% 64-bit digest as an 8-byte little-endian binary
DigestBin = i2p_siphash:hash_le(Data, Key).

%% 128-bit digest as two 64-bit words
{W1, W2} = i2p_siphash:hash_128(Data, Key).

%% 128-bit digest as a 16-byte little-endian binary
Digest128Bin = i2p_siphash:hash_128_le(Data, Key).
```

## Validation

The reference vectors cover every tail length 0..7, the 8-byte block boundary,
and multiple blocks (input lengths 0..65), so the implementation is exercised
across all tail lengths and block boundaries.
""".

-export([hash/2, hash_le/2, hash_128/2, hash_128_le/2]).
-export_type([siphash_key/0, data/0, digest64/0, digest128/0]).

-doc "A 16-byte SipHash key.".
-type siphash_key() :: <<_:128>>.

-doc "The bytes to hash.".
-type data() :: binary().

-doc "The 64-bit SipHash-2-4 digest as an unsigned integer.".
-type digest64() :: non_neg_integer().

-doc "The 128-bit SipHash-2-4 digest as two 64-bit words, word 1 then word 2.".
-type digest128() :: {non_neg_integer(), non_neg_integer()}.

-define(MASK, 16#FFFFFFFFFFFFFFFF).

-doc """
SipHash-2-4 of `Data` with the 16-byte `Key`, as an integer.

Input: `Data` — the bytes to hash; `Key` — a 16-byte key.
Output: the 64-bit digest as an unsigned integer.
""".
-spec hash(data(), siphash_key()) -> digest64().
hash(Data, <<K0:64/little-unsigned, K1:64/little-unsigned>>) when is_binary(Data) ->
    {V0, V1, V2, V3} = core(Data, K0, K1, 0),
    {V0f, V1f, V2f, V3f} = rounds_4({V0, V1, V2 bxor 16#ff, V3}),
    V0f bxor V1f bxor V2f bxor V3f.

-doc """
SipHash-2-4 of `Data` with the 16-byte `Key`, as little-endian bytes.

Input: `Data` — the bytes to hash; `Key` — a 16-byte key.
Output: the 64-bit digest as an 8-byte little-endian binary.
""".
-spec hash_le(data(), siphash_key()) -> <<_:64>>.
hash_le(Data, Key) ->
    <<(hash(Data, Key)):64/little-unsigned>>.

-doc """
128-bit SipHash-2-4 of `Data` with the 16-byte `Key`.

Input: `Data` — the bytes to hash; `Key` — a 16-byte key.
Output: `{W1, W2}`, the two 64-bit words of the digest as unsigned integers.
""".
-spec hash_128(data(), siphash_key()) -> digest128().
hash_128(Data, <<K0:64/little-unsigned, K1:64/little-unsigned>>) when is_binary(Data) ->
    {V0, V1, V2, V3} = core(Data, K0, K1, 16#ee),
    {V0a, V1a, V2a, V3a} = rounds_4({V0, V1, V2 bxor 16#ee, V3}),
    W1 = V0a bxor V1a bxor V2a bxor V3a,
    {V0d, V1d, V2d, V3d} = rounds_4({V0a, V1a bxor 16#dd, V2a, V3a}),
    W2 = V0d bxor V1d bxor V2d bxor V3d,
    {W1, W2}.

-doc """
128-bit SipHash-2-4 of `Data` with the 16-byte `Key`, as little-endian bytes.

Input: `Data` — the bytes to hash; `Key` — a 16-byte key.
Output: the 128-bit digest as a 16-byte little-endian binary (word 1 followed
by word 2).
""".
-spec hash_128_le(data(), siphash_key()) -> <<_:128>>.
hash_128_le(Data, Key) ->
    {W1, W2} = hash_128(Data, Key),
    <<W1:64/little-unsigned, W2:64/little-unsigned>>.

%%%%%%%
%%% Internal
%%%%%%%

%% Key mixing (with optional v1 marker for the 128-bit variant), compression of
%% full 8-byte blocks, and absorption of the tail block. Returns the state
%% before the finish marker.
core(Data, K0, K1, Marker) ->
    V0 = K0 bxor 16#736f6d6570736575,
    V1 = (K1 bxor 16#646f72616e646f6d) bxor Marker,
    V2 = K0 bxor 16#6c7967656e657261,
    V3 = K1 bxor 16#7465646279746573,
    Len = byte_size(Data),
    St = compress({V0, V1, V2, V3}, Data),
    M = tail_word(Len, Data),
    absorb_tail(St, M).

compress(St, Bin) when byte_size(Bin) < 8 ->
    St;
compress({V0, V1, V2, V3}, <<Block:64/little-unsigned, Rest/binary>>) ->
    V3a = V3 bxor Block,
    {V0a, V1a, V2a, V3b} = round_2_4({V0, V1, V2, V3a}),
    {V0b, V1b, V2b, V3c} = round_2_4({V0a, V1a, V2a, V3b}),
    V0c = V0b bxor Block,
    compress({V0c, V1b, V2b, V3c}, Rest).

%% The trailing (0..7 byte) partial block packed little-endian with the total
%% byte length in bits 56..63.
tail_word(Len, Data) ->
    Rem = Len band 7,
    Off = Len - Rem,
    <<_:Off/binary, Tail:Rem/binary>> = Data,
    build_tail(Tail) bor ((Len band 255) bsl 56).

build_tail(Tail) when byte_size(Tail) < 8 ->
    build_tail_le(Tail, 0, 0).

build_tail_le(<<>>, _Shift, Acc) ->
    Acc;
build_tail_le(<<B, Rest/binary>>, Shift, Acc) ->
    build_tail_le(Rest, Shift + 8, Acc bor (B bsl Shift)).

%% v3 ^= m; 2 rounds; v0 ^= m
absorb_tail({V0, V1, V2, V3}, M) ->
    V3a = V3 bxor M,
    {V0a, V1a, V2a, V3b} = round_2_4({V0, V1, V2, V3a}),
    {V0b, V1b, V2b, V3c} = round_2_4({V0a, V1a, V2a, V3b}),
    V0c = V0b bxor M,
    {V0c, V1b, V2b, V3c}.

round_2_4({V0, V1, V2, V3}) ->
    V0a = (V0 + V1) band ?MASK,
    V1a = rotl(V1, 13) bxor V0a,
    V0b = rotl(V0a, 32),
    V2a = (V2 + V3) band ?MASK,
    V3a = rotl(V3, 16) bxor V2a,
    V0c = (V0b + V3a) band ?MASK,
    V3b = rotl(V3a, 21) bxor V0c,
    V2b = (V2a + V1a) band ?MASK,
    V1b = rotl(V1a, 17) bxor V2b,
    V2c = rotl(V2b, 32),
    {V0c, V1b, V2c, V3b}.

rounds_4(St) ->
    round_2_4(round_2_4(round_2_4(round_2_4(St)))).

rotl(X, N) ->
    ((X bsl N) band ?MASK) bor (X bsr (64 - N)).
