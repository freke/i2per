-module(i2p_framing).

-moduledoc """
NTCP2 data-phase framing: the 2-byte SipHash-obfuscated length and the
ChaChaPoly AEAD frame.

After the Noise handshake completes, traffic moves as authenticated and
encrypted ChaChaPoly "frames", each preceded by a 2-byte big-endian length
that is obfuscated with SipHash-2-4 so that frame boundaries do not leak to a
passive observer (I2P [NTCP2](https://i2p.net/en/docs/specs/ntcp2/), section
"Data phase").

This module implements:

- The data-phase key derivation (`data_phase_keys/2`, the Noise `split()`
  step extended with the Additional Symmetric Key SipHash KDF), producing the
  two direction cipher keys `k_ab`/`k_ba` and the per-direction SipHash key +
  IV.
- The SipHash-2-4 length-obfuscation state machine (`sip_state/0`): for each
  frame the IV advances to the previous frame's SipHash-2-4 output, and the
  mask is the two least-significant bytes of that output.
- Frame encryption/decryption: ChaCha20-Poly1305 (via `m:i2p_crypto`) under a
  direction key with a zero-AD, counter-based nonce. The counter is **64 bits
  wide** — the nonce's whole 8-byte low half — so a direction key is held for the
  life of a connection and the counter is what keeps every nonce under it unique.
  It runs `0..2^64 - 2` and does not repeat; there is no rekey in NTCP2 and none
  is needed. See `f:i2p_crypto:es_nonce/1` for the bound and `m:i2p_ntcp2_conn`
  for the two directions that walk it.
- The nested block format (`t:block/0`): a 1-byte type and 2-byte big-endian
  length, where type 254 is padding (always last) and types 0..4 are
  datetime, options, RouterInfo, I2NP message and termination.

Frame bounds: the obfuscated length decodes to 16-65535 (the AEAD frame,
ciphertext + 16-byte tag); a full frame including the length field is thus
18-65537 bytes with a 0-65519 payload.

## Usage

```erlang
%% Keys after the handshake: chaining key `Ck` and hash `H`
#{k_ab := KAb, k_ba := KBa, sip_ab := SipAb, sip_ba := SipBa} =
    i2p_framing:data_phase_keys(Ck, H),

%% Alice -> Bob, message number 0
{Frame, SipAb1} = i2p_framing:encrypt_frame(KAb, 0, Payload, SipAb),
{ok, Payload, SipBa1} = i2p_framing:decrypt_frame(KBa, 0, Frame, SipBa),

%% Assemble and split blocks
Block = i2p_framing:encode_block(3, ShortI2npMessage),      %% I2NP block
Pad = i2p_framing:padding_block(64),                         %% type 254
{ok, [#{type := 3, data := Msg}, #{type := 254}]} =
    i2p_framing:decode_blocks(<<Block/binary, Pad/binary>>).
```
""".

-export([
    data_phase_keys/2,
    encrypt_frame/4,
    decrypt_frame/4,
    obfuscate_length/2,
    deobfuscate_length/2,
    encode_block/2,
    pad_block/1,
    decode_blocks/1,
    frame_bytes/1
]).
-export_type([
    frame_key/0,
    sip_state/0,
    frame/0,
    block/0,
    direction_keys/0
]).

-doc "A 32-byte ChaCha20-Poly1305 data-phase cipher key.".
-type frame_key() :: i2p_crypto:key().

-doc """
The per-direction SipHash length-obfuscation state.

- `key` — the 16-byte SipHash-2-4 key (the `sipk1` ‖ `sipk2` pair).
- `iv` — the 8-byte IV, updated to each frame's SipHash-2-4 output.
""".
-opaque sip_state() :: #{key := i2p_siphash:siphash_key(), iv := <<_:64>>}.

-doc """
A complete encoded frame: 2-byte obfuscated length followed by the sealed
AEAD frame (ciphertext ‖ 16-byte tag). 18-65537 bytes.
""".
-opaque frame() :: binary().

-doc """
A data-phase block: `{Type, Data}` — `type` is the 1-byte block identifier
(0 datetime, 1 options, 2 RouterInfo, 3 I2NP message, 4 termination, 254
padding) and `data` the block payload (0-65516 bytes).
""".
-type block() :: #{type := byte(), data := binary()}.

-doc """
The keys derived by `data_phase_keys/2`: the two direction cipher keys and
the two SipHash states.
""".
-type direction_keys() :: #{
    k_ab := frame_key(),
    k_ba := frame_key(),
    sip_ab := sip_state(),
    sip_ba := sip_state()
}.

-define(MAX_FRAME_LEN, 65535).
-define(MIN_FRAME_LEN, 16).
-define(MAX_PAYLOAD, 65519).
-define(BLOCK_MAX_DATA, 65516).

-doc """
Derive the data-phase keys (Noise `split()` plus the SipHash ask KDF).

Computes, from the handshake chaining key `Ck` and hash `H`:

`k_ab`, `k_ba` — the ChaCha20-Poly1305 keys for Alice→Bob and Bob→Alice
(respectively), and `sip_ab`, `sip_ba` — the per-direction SipHash states
(16-byte key + 8-byte IV).

Input: `Ck` — the 32-byte chaining key after the handshake; `H` — the 32-byte
hash `h` from the message 3 part 2 KDF (used as the SipHash KDF salt).

Output: a `t:direction_keys/0` map.
""".
-spec data_phase_keys(i2p_crypto:chaining_key(), i2p_crypto:hash()) ->
    direction_keys().
data_phase_keys(Ck, H) ->
    #{k_ab := KAb, k_ba := KBa, sip_ab := SipAb, sip_ba := SipBa} =
        split_siphash(Ck, H),
    #{k_ab => KAb, k_ba => KBa, sip_ab => SipAb, sip_ba => SipBa}.

-doc """
Encrypt `Payload` into a frame for the current message `MsgNum`.

Input: `Key` — the direction cipher key (`k_ab` or `k_ba`); `MsgNum` — the
message number in this direction, starting at 0, bounded by the nonce it feeds
at `0..2^64 - 2` (the counter's whole 8-byte low half, little-endian);
`Payload` — 0-65519 bytes of plaintext; `Sip` — the current SipHash state.

Output: `{Frame, Sip'}` — the encoded frame and the advanced SipHash state
(the length field uses the frame's mask, so `Sip'` must be what the receiver
derives from the same state).

`MsgNum` is not capped at 65535. The counter is the nonce's whole 8-byte low
half, so it is 64 bits wide and a session is not bounded at 2^16 frames; see the
module doc.
""".
-spec encrypt_frame(frame_key(), non_neg_integer(), binary(), sip_state()) ->
    {frame(), sip_state()}.
encrypt_frame(_Key, _MsgNum, Payload, _Sip) when byte_size(Payload) > ?MAX_PAYLOAD ->
    error({too_large, byte_size(Payload)});
encrypt_frame(Key, MsgNum, Payload, Sip) ->
    Sealed = i2p_crypto:chacha20_poly1305_seal(
        Key,
        i2p_crypto:es_nonce(MsgNum),
        Payload,
        <<>>
    ),
    FrameLen = byte_size(Sealed),
    {ObfLen, Sip1} = obfuscate_length(FrameLen, Sip),
    {<<ObfLen:16/big, Sealed/binary>>, Sip1}.

-doc """
Decrypt a frame and verify its MAC.

Input: `Key` — the direction cipher key; `MsgNum` — the message number used
when encrypting; `Frame` — a complete encoded frame (`t:frame/0`); `Sip` — the
SipHash state ahead of this frame.

Output: `{ok, Payload, Sip'}` on success (with the advanced SipHash state),
or the atom `error` on a malformed length, a MAC failure, or a length that
does not match the supplied bytes.
""".
-spec decrypt_frame(frame_key(), non_neg_integer(), frame(), sip_state()) ->
    {ok, binary(), sip_state()} | error.
decrypt_frame(Key, MsgNum, <<ObfLen:16/big, Sealed/binary>>, Sip) ->
    case deobfuscate_length(ObfLen, Sip) of
        {ok, FrameLen, Sip1} when byte_size(Sealed) =:= FrameLen ->
            case
                i2p_crypto:chacha20_poly1305_open(
                    Key,
                    i2p_crypto:es_nonce(MsgNum),
                    Sealed,
                    <<>>
                )
            of
                {ok, Payload} -> {ok, Payload, Sip1};
                error -> error
            end;
        {ok, _FrameLen, _Sip1} ->
            error;
        error ->
            error
    end;
decrypt_frame(_Key, _MsgNum, _Frame, _Sip) ->
    error.

-doc """
Obfuscate a frame length with SipHash-2-4.

`mask = low 16 bits of SipHash-2-4(iv, key)` where `iv` advances to each
frame's SipHash output: `obfuscated = length XOR mask`.

Input: `Length` — the frame length, 16-65535 (sealed AEAD frame size); `Sip` —
the current SipHash state.

Output: `{ObfuscatedLength, Sip'}` — now the length is masked for the wire and
the IV has advanced.
""".
-spec obfuscate_length(16..65535, sip_state()) -> {0..65535, sip_state()}.
obfuscate_length(Length, #{key := Key, iv := IV} = Sip) when
    Length >= ?MIN_FRAME_LEN, Length =< ?MAX_FRAME_LEN
->
    Next = i2p_siphash:hash_le(IV, Key),
    <<MaskLo, MaskHi, _/binary>> = Next,
    Mask = (MaskHi bsl 8) bor MaskLo,
    {Length bxor Mask, Sip#{iv => Next}}.

-doc """
Recover a frame length from its obfuscated form.

Input: `ObfLen` — the 16-bit masked length from the wire; `Sip` — the SipHash
state ahead of this frame.

Output: `{ok, Length, Sip'}` for an in-range frame length, or the atom `error`
for an out-of-range value (an invalid `16..65535` length).
""".
-spec deobfuscate_length(0..65535, sip_state()) -> {ok, 16..65535, sip_state()} | error.
deobfuscate_length(ObfLen, #{key := Key, iv := IV} = Sip) ->
    Next = i2p_siphash:hash_le(IV, Key),
    <<MaskLo, MaskHi, _/binary>> = Next,
    Mask = (MaskHi bsl 8) bor MaskLo,
    Length = ObfLen bxor Mask,
    case Length >= ?MIN_FRAME_LEN andalso Length =< ?MAX_FRAME_LEN of
        true -> {ok, Length, Sip#{iv => Next}};
        false -> error
    end.

-doc """
Encode a data-phase block: 1-byte type, 2-byte big-endian length, payload.

Input: `Type` — the block type (0-255); `Data` — the block payload, at most
65516 bytes.
Output: the encoded block (at least 3 bytes).
""".
-spec encode_block(byte(), binary()) -> <<_:24, _:_*8>>.
encode_block(Type, Data) when
    Type >= 0, Type =< 255, is_binary(Data), byte_size(Data) =< ?BLOCK_MAX_DATA
->
    <<Type:8, (byte_size(Data)):16/big, Data/binary>>.

-doc """
Encode a padding block (type 254) of exactly `Size` bytes of random data.

Padding must always be the last block in a frame, and only one padding block
may appear. Input: `Size` — padding length, 0-65516. Output: the padding block
(at least 3 bytes).
""".
-spec pad_block(0..65516) -> <<_:24, _:_*8>>.
pad_block(Size) when Size >= 0, Size =< ?BLOCK_MAX_DATA ->
    encode_block(254, crypto:strong_rand_bytes(Size)).

-doc """
Expose an encoded frame's bytes to a trusted consumer (e.g. handing it to a
socket). Frames are opaque to keep the length-obfuscation invariant internal to
this module.
""".
-spec frame_bytes(frame()) -> binary().
frame_bytes(Frame) ->
    Frame.

-doc """
Decode zero or more blocks from plaintext.

Input: `Bin` — the concatenated blocks (1-byte type, 2-byte length, data).
Output: `{ok, Blocks}` — the blocks in order (`t:block/0` maps), or the atom
`error` if the stream is malformed (truncated length or data).
""".
-spec decode_blocks(binary()) -> {ok, [block()]} | error.
decode_blocks(<<>>) ->
    {ok, []};
decode_blocks(<<Type:8, Size:16/big, Data:Size/binary, Rest/binary>>) ->
    case decode_blocks(Rest) of
        {ok, More} -> {ok, [#{type => Type, data => Data} | More]};
        error -> error
    end;
decode_blocks(_) ->
    error.

%%%%%%% %%% Internal %%%%%%%

%% The Noise split() for cipher keys, then the SipHash ask KDF for the
%% per-direction SipHash key + IV. Returns a direction_keys() map.
split_siphash(Ck, H) ->
    TempKey = hmac(Ck, <<>>),
    KAb = hmac(TempKey, <<1>>),
    KBa = hmac(TempKey, <<KAb/binary, 2>>),
    AskMaster = hmac(TempKey, <<"ask", 1>>),
    TempKey2 = hmac(AskMaster, <<H/binary, "siphash">>),
    SipMaster = hmac(TempKey2, <<1>>),
    TempKey3 = hmac(SipMaster, <<>>),
    SipAbRaw = hmac(TempKey3, <<1>>),
    SipBaRaw = hmac(TempKey3, <<SipAbRaw/binary, 2>>),
    #{
        k_ab => KAb,
        k_ba => KBa,
        sip_ab => sip_state(sipkeys(SipAbRaw)),
        sip_ba => sip_state(sipkeys(SipBaRaw))
    }.

%% The 32-byte sipkeys output is a 16-byte key (bytes 0..15) + 8-byte IV
%% (bytes 16..23) + 8 unused bytes.
sipkeys(<<Key:16/binary, IV:8/binary, _:8/binary>>) ->
    <<Key/binary, IV/binary>>.

sip_state(<<Key:16/binary, IV:8/binary>>) ->
    #{key => Key, iv => IV}.

hmac(Key, Data) ->
    crypto:mac(hmac, sha256, Key, Data).
