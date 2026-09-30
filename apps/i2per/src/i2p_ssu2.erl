-module(i2p_ssu2).

-moduledoc """
SSU2 transport codec: packet headers, header obfuscation, the Noise XK
handshake (`SessionRequest`/`SessionCreated`/`SessionConfirmed`), the
symmetric `TokenRequest`/`Retry` exchange, payload blocks — including the
relay family (blocks 7/8/9) and the out-of-session `HolePunch` message (type
11) — and the data phase key derivation.

Implements the SSU2 wire format (geti2p.net/spec/ssu2) as a pure state
machine over complete datagrams — no sockets, no processes. The UDP
listener and per-session processes live in `m:i2p_ssu2_listener` and
`m:i2p_ssu2_conn`; the crypto primitives in `m:i2p_crypto`.

The handshake is the NTCP2-style XK pattern with three additions:

* Headers — and the ephemeral keys X/Y — are obfuscated with ChaCha20
  under keys derived from or equal to the responder's introduction key,
  which is published in the netdb.
* `SessionConfirmed` may be fragmented across up to 15 packets; fragment
  0's header is the AEAD associated data for the reassembled jumbo frame.
* The header carries connection IDs and a session token granted by Bob.

All decoders are fail-closed: malformed input yields the atom `error`, and
AEAD verification failures never produce partial results.

## Usage

```erlang
%% Alice (initiator)
S0 = i2p_ssu2:alice_init(Bpk, Bik, AStaticPriv, AStaticPub),
{ok, SR, S1} = i2p_ssu2:create_session_request(S0, EphPriv, DstId, SrcId,
                                               0, RandNum, [{datetime, Ts}]),
{ok, SCInfo, S2} = i2p_ssu2:receive_session_created(S1, SCPacket),
{ok, [SC], KeysA, _S3} =
    i2p_ssu2:create_session_confirmed(S2, Blocks, 1440),

%% Bob (responder)
B0 = i2p_ssu2:bob_init(BskPriv, Bpk, Bik),
{ok, SRInfo, B1} = i2p_ssu2:receive_session_request(B0, SR),
{ok, SCOut, B2} = i2p_ssu2:create_session_created(B1, BEphPriv, RandNum,
                                                  SCBlocks),
{ok, #{static_key := Apk, blocks := Blocks, keys := KeysB}, B3} =
    i2p_ssu2:receive_session_confirmed(B2, [SC]).
```
""".

-define(PROTOCOL_NAME,
    <<"Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256">>
).
-define(NET_ID, 2).
-define(VERSION, 2).

%% Message types.
-define(TYPE_SESSION_REQUEST, 0).
-define(TYPE_SESSION_CREATED, 1).
-define(TYPE_SESSION_CONFIRMED, 2).
-define(TYPE_DATA, 6).
-define(TYPE_PEER_TEST, 7).
-define(TYPE_RETRY, 9).
-define(TYPE_TOKEN_REQUEST, 10).
-define(TYPE_HOLE_PUNCH, 11).

%% Payload block types.
-define(BLOCK_DATETIME, 0).
-define(BLOCK_OPTIONS, 1).
-define(BLOCK_ROUTER_INFO, 2).
-define(BLOCK_I2NP, 3).
-define(BLOCK_FIRST_FRAGMENT, 4).
-define(BLOCK_FOLLOW_ON_FRAGMENT, 5).
-define(BLOCK_TERMINATION, 6).
-define(BLOCK_RELAY_REQUEST, 7).
-define(BLOCK_RELAY_RESPONSE, 8).
-define(BLOCK_RELAY_INTRO, 9).
-define(BLOCK_PEER_TEST, 10).
-define(BLOCK_ACK, 12).
-define(BLOCK_ADDRESS, 13).
-define(BLOCK_RELAY_TAG_REQUEST, 15).
-define(BLOCK_RELAY_TAG, 16).
-define(BLOCK_NEW_TOKEN, 17).
-define(BLOCK_PATH_CHALLENGE, 18).
-define(BLOCK_PATH_RESPONSE, 19).
-define(BLOCK_FIRST_PACKET_NUMBER, 20).
-define(BLOCK_CONGESTION, 21).
-define(BLOCK_PADDING, 254).

%% Every SSU2 payload must be at least this many bytes: header encryption
%% reads the trailing 24 bytes of a datagram and the last 16 are the MAC.
-define(MIN_PAYLOAD, 8).

%% The minimum total size of a datagram.
-define(MIN_PACKET, 40).

-export([
    initialize/1,
    long_header/5,
    short_header_data/3,
    short_header_confirmed/3,
    header_mask/2,
    seal_long/3,
    open_long/3,
    open_conn_id/3,
    open_header16/3,
    seal_ephemeral/3,
    open_ephemeral/3,
    seal_short/3,
    open_short/3,
    encode_blocks/1,
    decode_blocks/1,
    ensure_min_payload/1,
    alice_init/4,
    create_session_request/7,
    receive_session_created/2,
    create_session_confirmed/3,
    bob_init/3,
    receive_session_request/2,
    create_session_created/4,
    receive_session_confirmed/2,
    encode_token_request/5,
    decode_token_request/2,
    encode_retry/6,
    decode_retry/2,
    encode_peertest/5,
    decode_peertest/2,
    encode_holepunch/5,
    decode_holepunch/2,
    data_keys/1,
    encode_data/6,
    decode_data/4,
    build_ack/2,
    ack_expand/1,
    fragment_i2np/5
]).

-export_type([
    conn_id/0,
    token/0,
    block/0,
    ack_block/0,
    state/0,
    data_keys/0,
    direction/0,
    datagram/0
]).

-doc "A 64-bit connection identifier from the packet header.".
-type conn_id() :: non_neg_integer().

-doc "The 8-byte session token granted by Bob in a Retry.".
-type token() :: non_neg_integer().

-doc "Data phase key direction: `ab` is Alice -> Bob, `ba` is Bob -> Alice.".
-type direction() :: ab | ba.

-doc """
A complete SSU2 datagram: header plus at least the eight-byte minimum
payload.
""".
-type datagram() :: <<_:64, _:_*8>>.

-doc """
One SSU2 payload block. The tuples mirror the specification's block table:

* `{datetime, Secs}` — Unix timestamp, seconds.
* `{options, Data}` — raw options bytes (12 or more).
* `{router_info, FlagByte, RiData}` — flag bit 0 = flood request, bit 1 =
  gzip compressed; `RiData` is the RouterInfo body.
* `{i2np, Type, MsgId, ShortExp, Body}` — complete I2NP message with the
  NTCP2-style 9-byte header.
* `{first_fragment, Type, MsgId, ShortExp, Body}` and
  `{follow_on_fragment, FragNum, IsLast, MsgId, Body}` — I2NP fragments.
* `{ack, AckThrough, Acnt, Ranges}` — packet acknowledgments; `AckThrough`
  is the highest acked packet number, `Acnt` the number of consecutive acks
  immediately below it, and `Ranges` a list of `{NackCount, AckCount}`
  run-length pairs (see `f:build_ack/3`).
* `{termination, ValidPacketsReceived, Reason, AddlData}`.
* `{relay_request, Flag, Nonce, Tag, Ts, Ver, Port, Ip, Sig}` (block 7) —
  Alice's introducer-relay request. `Nonce` is a 4-byte random; `Tag` the
  relay tag (itag) taken from Charlie's RouterInfo; `Port`/`Ip` Alice's
  reachable endpoint; `Sig` the 64-byte Ed25519 signature over prologue
  `"RelayRequestData"`, Bob's and Charlie's hashes and the signed data (see
  `m:i2p_relay`, which builds and verifies it).
* `{relay_response, Flag, Code, Nonce, Ts, Ver, Port, Ip, Sig, Token}` (block
  8) — Charlie's accept/reject back to Alice (also carried inside the
  out-of-session HolePunch message). `Code` is `0` (accept), 1-6 (Bob
  rejects), 64-70 (Charlie rejects) or 128 (catch-all). `Port`/`Ip` are
  Charlie's endpoint, or `Ip = <<>>` when absent (`csz = 0`); `Token` is the
  8-byte session token (the `undefined` atom when absent — only present on
  accept).
* `{relay_intro, Flag, AliceHash, Nonce, Tag, Ts, Ver, Port, Ip, Sig}`
  (block 9) — Bob's introduction of Charlie to Alice. `AliceHash` is Alice's
  32-byte router hash; the remaining fields are forwarded unmodified from her
  RelayRequest, including her signature.
* `{peertest, MsgNum, Code, Flags, RouterHash, Ver, Nonce, Ts, Port, Ip, Sig}`
  — the reachability-probe block (SSU2 spec block 10). `MsgNum` is the
  message number 1-7; `RouterHash` is a 32-byte router hash, present only in
  messages 2 and 4 (all-zeros fake when Bob rejects); `Sig` is the trailing
  signature bytes (Ed25519, 64 bytes), present for messages 1-4 and optional
  for 5-7.
* `{address, Port, IpBin}` — IPv4 (4 bytes) or IPv6 (16 bytes), big endian.
* `relay_tag_request`, `{relay_tag, Tag}`, `{new_token, Expires, Token}`,
  `{path_challenge, Data}`, `{path_response, Data}`,
  `{first_packet_number, Num}`, `{congestion, Flags}`, `{padding, Bytes}`.
""".
-type block() ::
    {datetime, non_neg_integer()}
    | {options, binary()}
    | {router_info, byte(), binary()}
    | {i2np, byte(), non_neg_integer(), non_neg_integer(), binary()}
    | {first_fragment, byte(), non_neg_integer(), non_neg_integer(), binary()}
    | {follow_on_fragment, 1..127, boolean(), non_neg_integer(), binary()}
    | {ack, non_neg_integer(), non_neg_integer(), [{non_neg_integer(), non_neg_integer()}]}
    | {termination, non_neg_integer(), byte(), binary()}
    | {relay_request, byte(), non_neg_integer(), non_neg_integer(), non_neg_integer(), byte(),
        0..65535, binary(), binary()}
    | {relay_response, byte(), byte(), non_neg_integer(), non_neg_integer(), byte(), 0..65535,
        binary(), binary(), undefined | non_neg_integer()}
    | {relay_intro, byte(), binary(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
        byte(), 0..65535, binary(), binary()}
    | {peertest, 1..7, byte(), byte(), binary(), byte(), non_neg_integer(), non_neg_integer(),
        0..65535, binary(), binary()}
    | {address, 0..65535, binary()}
    | relay_tag_request
    | {relay_tag, pos_integer()}
    | {new_token, non_neg_integer(), non_neg_integer()}
    | {path_challenge, binary()}
    | {path_response, binary()}
    | {first_packet_number, non_neg_integer()}
    | {congestion, byte()}
    | {padding, binary()}.

-doc """
An ACK block: `AckThrough` is the highest acked packet number, `Acnt` the
number of consecutive acks immediately below it, and `Ranges` a list of
`{Nack, Ack}` run-length pairs between them (see `f:build_ack/2`).
""".
-type ack_block() ::
    {ack, non_neg_integer(), non_neg_integer(), [{non_neg_integer(), non_neg_integer()}]}.

-doc """
Handshake state for one role of one session. Optional fields appear as the
handshake progresses: ephemeral keys, peer ephemeral keys, derived header
protection keys, and the connection IDs chosen or learned during
`SessionRequest`.
""".
-type state() :: #{
    role := alice | bob,
    ck := i2p_crypto:chaining_key(),
    h := i2p_crypto:hash(),
    k := i2p_crypto:key(),
    bik := i2p_crypto:key(),
    bpk := i2p_crypto:x25519_public_key(),
    eph_priv => i2p_crypto:x25519_private_key(),
    peer_eph => i2p_crypto:x25519_public_key(),
    my_static_priv => i2p_crypto:x25519_private_key(),
    my_static_pub => i2p_crypto:x25519_public_key(),
    sess_create_header_key => i2p_crypto:key(),
    sess_confirm_header_key => i2p_crypto:key(),
    src_conn_id => conn_id(),
    dst_conn_id => conn_id()
}.

-doc """
Data phase keys after `split()`: one ChaChaPoly cipher key plus one header
protection key per direction (`t:direction/0`).
""".
-type data_keys() :: #{
    k_ab := i2p_crypto:key(),
    kh2_ab := i2p_crypto:key(),
    k_ba := i2p_crypto:key(),
    kh2_ba := i2p_crypto:key()
}.

%%%%%%%%% %%% Headers %%%%%%%

-doc """
Build a plaintext long header (32 bytes) — used before a session exists by
`SessionRequest`, `TokenRequest` and `Retry`.

Input: destination and source connection IDs, the random (ignored) packet
number, message type and session token.
Output: the 32-byte header.
""".
-spec long_header(conn_id(), non_neg_integer(), byte(), conn_id(), token()) ->
    <<_:256>>.
long_header(DstConnId, PktNum, Type, SrcConnId, Tok) ->
    <<DstConnId:64, PktNum:32, Type:8, ?VERSION:8, ?NET_ID:8, 0:8, SrcConnId:64, Tok:64>>.

-doc """
Build a plaintext data-phase short header (16 bytes).

Input: destination connection ID, packet number, immediate-ack flag.
Output: the 16-byte header with type 6.
""".
-spec short_header_data(conn_id(), non_neg_integer(), 0 | 1) -> <<_:128>>.
short_header_data(DstConnId, PktNum, ImmediateAck) ->
    <<DstConnId:64, PktNum:32, ?TYPE_DATA:8, ImmediateAck:8, 0:16>>.

-doc """
Build a plaintext SessionConfirmed short header (16 bytes).

Input: destination connection ID, fragment number (0-based) and total
fragment count, each four bits wide.
Output: the 16-byte header with type 2 and packet number zero.
""".
-spec short_header_confirmed(conn_id(), 0..14, 1..15) -> <<_:128>>.
short_header_confirmed(DstConnId, FragNum, FragTotal) ->
    <<DstConnId:64, 0:32, ?TYPE_SESSION_CONFIRMED:8, FragNum:4, FragTotal:4, 0:16>>.

-doc """
Derive the 8-byte XOR mask protecting one header section.

Input: a header protection key and the 12-byte nonce taken from the tail of
the finished datagram.
Output: mask bytes to XOR onto that section.
""".
-spec header_mask(i2p_crypto:key(), i2p_crypto:iv12()) -> <<_:64>>.
header_mask(Key, IV12) ->
    i2p_crypto:chacha20_crypt(Key, IV12, 1, <<0:64>>).

%% The two tail-derived masks for a finished datagram.
masks_for(Packet, KH1, KH2) ->
    Len = byte_size(Packet),
    M1 = header_mask(KH1, binary:part(Packet, Len - 24, 12)),
    M2 = header_mask(KH2, binary:part(Packet, Len - 12, 12)),
    {M1, M2}.

%% Apply or remove the two XOR masks over header bytes 0..15 (symmetric).
mask_parts(Packet, KH1, KH2) ->
    {M1, M2} = masks_for(Packet, KH1, KH2),
    <<First:8/binary, Second:8/binary, Rest/binary>> = Packet,
    <<(crypto:exor(First, M1))/binary, (crypto:exor(Second, M2))/binary, Rest/binary>>.

%% Protect (or restore) the long-header third section, bytes 16..31 (source
%% connection ID and token), with raw ChaCha20 under the intro key, a zero
%% nonce and counter starting at one. Symmetric: one call serves seal and
%% open.
long_header_protect(Packet, KH1, KH2) ->
    {M1, M2} = masks_for(Packet, KH1, KH2),
    <<First:8/binary, Second:8/binary, Third:16/binary, Rest/binary>> = Packet,
    Encrypted = i2p_crypto:chacha20_crypt(KH2, <<0:96>>, 1, Third),
    <<
        (crypto:exor(First, M1))/binary,
        (crypto:exor(Second, M2))/binary,
        Encrypted/binary,
        Rest/binary
    >>.

-doc """
Obfuscate a finished long-header datagram (`TokenRequest`, `Retry`): header
bytes 0..15 are XORed with tail-derived masks, and header bytes 16..31
(source connection ID and token) are encrypted with ChaCha20 under the intro
key with a zero nonce and counter starting at one.

Input: the full datagram with its first 32 bytes still plaintext; both
header protection keys (Bob's intro key for these messages).
Output: the sendable datagram.
""".
-spec seal_long(datagram(), i2p_crypto:key(), i2p_crypto:key()) -> binary().
seal_long(Packet, KH1, KH2) ->
    long_header_protect(Packet, KH1, KH2).

-doc """
Inverse of `f:seal_long/3`: restore the plaintext header.

Input and output as `f:seal_long/3`; `error` when the datagram is too short
to be an SSU2 packet.
""".
-spec open_long(binary(), i2p_crypto:key(), i2p_crypto:key()) ->
    {ok, binary()} | error.
open_long(Packet, KH1, KH2) when byte_size(Packet) >= ?MIN_PACKET ->
    {ok, long_header_protect(Packet, KH1, KH2)};
open_long(_Packet, _KH1, _KH2) ->
    error.

-doc """
Recover only the destination connection id from a datagram — the one field
`m:i2p_ssu2_listener` needs to route almost every datagram it sees.

Bytes 0..7 of both header forms are XORed with the *first* tail-derived mask,
and nothing else in the header is masked with it. So routing by connection id
costs one ChaCha20 pass, where `f:open_long/3` costs three: it also restores
bytes 8..15 under the second mask and decrypts bytes 16..31. The listener
recovered the type byte with `f:open_long/3` for want of a cheaper call, then
threw all but the first eight bytes away.

Exact for both header forms and for both header keys, because the mask is
derived from the datagram's own tail rather than from anything the sender
chose: a datagram whose length is below `?MIN_PACKET` has no tail to derive
from and is rejected, exactly as `f:open_long/3` rejects it.

Input: the datagram and both header protection keys; output: `{ok, ConnId}`
where `ConnId` is the 64-bit big-endian value from header bytes 0..7, or
`error` when the datagram is too short to carry an SSU2 header.
""".
-spec open_conn_id(binary(), i2p_crypto:key(), i2p_crypto:key()) ->
    {ok, conn_id()} | error.
open_conn_id(Packet, KH1, _KH2) when byte_size(Packet) >= ?MIN_PACKET ->
    M1 = header_mask(KH1, binary:part(Packet, byte_size(Packet) - 24, 12)),
    <<First:8/binary, _/binary>> = Packet,
    <<ConnId:64/big-unsigned-integer>> = crypto:exor(First, M1),
    {ok, ConnId};
open_conn_id(_Packet, _KH1, _KH2) ->
    error.

-doc """
Recover header bytes 0..15 of a datagram — everything a router needs to tell one
long-header message type from another.

Two ChaCha20 passes, one per tail-derived mask, and **no** third pass: bytes
16..31 are encrypted under the intro key with a zero nonce and stay encrypted.
`f:open_long/3` decrypts those too, because a caller going on to read a source
connection id or a token needs them; a caller that only wants to ask what type a
datagram is does not, and `m:i2p_ssu2_listener` is that caller.

The caveat `f:open_conn_id/3` documents applies here with more force: **the type
byte in this output is only meaningful for a datagram addressed to our own
introduction key out of session.** For an in-session short header, bytes 8..15 are
masked with the *session's* header protection key, so what comes back is noise. It
is exact for both header forms as bytes; it is the *interpretation* that is
narrow.

Input: the datagram and both header protection keys. Output: `{ok, Header}` with
the 16 recovered bytes, or `error` when the datagram is shorter than
`?MIN_PACKET`.
""".
-spec open_header16(binary(), i2p_crypto:key(), i2p_crypto:key()) ->
    {ok, <<_:128>>} | error.
open_header16(Packet, KH1, KH2) when byte_size(Packet) >= ?MIN_PACKET ->
    {M1, M2} = masks_for(Packet, KH1, KH2),
    <<First:8/binary, Second:8/binary, _/binary>> = Packet,
    {ok, <<(crypto:exor(First, M1))/binary, (crypto:exor(Second, M2))/binary>>};
open_header16(_Packet, _KH1, _KH2) ->
    error.

-doc """
Obfuscate a finished `SessionRequest`/`SessionCreated` datagram: header
bytes 0..15 are masked as in `f:seal_long/3`, then bytes 16..63 (source
connection ID, token, and the ephemeral key X/Y) are run through raw
ChaCha20 under `KH2` with a zero nonce and counter starting at one.
""".
-spec seal_ephemeral(datagram(), i2p_crypto:key(), i2p_crypto:key()) -> binary().
seal_ephemeral(Packet, KH1, KH2) when byte_size(Packet) >= 88 ->
    {M1, M2} = masks_for(Packet, KH1, KH2),
    <<First:8/binary, Second:8/binary, Third:48/binary, Tail/binary>> =
        Packet,
    Encrypted = i2p_crypto:chacha20_crypt(KH2, <<0:96>>, 1, Third),
    <<
        (crypto:exor(First, M1))/binary,
        (crypto:exor(Second, M2))/binary,
        Encrypted/binary,
        Tail/binary
    >>.

-doc """
Inverse of `f:seal_ephemeral/3`: restore the plaintext header and ephemeral
key, or `error` when the datagram cannot be a SessionRequest/Created.
""".
-spec open_ephemeral(binary(), i2p_crypto:key(), i2p_crypto:key()) ->
    {ok, binary()} | error.
open_ephemeral(Packet, KH1, KH2) when byte_size(Packet) >= 80 ->
    {M1, M2} = masks_for(Packet, KH1, KH2),
    <<First:8/binary, Second:8/binary, Third:48/binary, Tail/binary>> =
        Packet,
    <<PlainHi:16/binary, PlainEph:32/binary>> =
        i2p_crypto:chacha20_crypt(KH2, <<0:96>>, 1, Third),
    Plain = <<
        (crypto:exor(First, M1))/binary,
        (crypto:exor(Second, M2))/binary,
        PlainHi/binary,
        PlainEph/binary
    >>,
    {ok, <<Plain/binary, Tail/binary>>};
open_ephemeral(_Packet, _KH1, _KH2) ->
    error.

-doc """
Obfuscate a finished short-header datagram (`SessionConfirmed`, data
phase): header bytes 0..15 are XORed with tail-derived masks.
""".
-spec seal_short(datagram(), i2p_crypto:key(), i2p_crypto:key()) -> binary().
seal_short(Packet, KH1, KH2) ->
    mask_parts(Packet, KH1, KH2).

-doc """
Inverse of `f:seal_short/3`; `error` when the datagram is too short.
""".
-spec open_short(binary(), i2p_crypto:key(), i2p_crypto:key()) ->
    {ok, binary()} | error.
open_short(Packet, KH1, KH2) when byte_size(Packet) >= ?MIN_PACKET ->
    {ok, mask_parts(Packet, KH1, KH2)};
open_short(_Packet, _KH1, _KH2) ->
    error.

%%%%%%%%% %%% Payload blocks %%%%%%%

-doc """
Encode payload blocks in order.

Input: a list of `t:block/0` tuples.
Output: the concatenated TLV blocks; padding, if any, must already be last
(the encoder writes blocks in the given order and does not reorder).
""".
-spec encode_blocks([block()]) -> binary().
encode_blocks(Blocks) ->
    <<<<(block_data(Block))/binary>> || Block <- Blocks>>.

%% One encoded block (tag + big-endian 16-bit length + data).
block_data({datetime, Secs}) ->
    tlv(?BLOCK_DATETIME, <<Secs:32>>);
block_data({options, Data}) ->
    tlv(?BLOCK_OPTIONS, Data);
block_data({router_info, Flag, RiData}) ->
    tlv(?BLOCK_ROUTER_INFO, <<Flag:8, 0:4, 1:4, RiData/binary>>);
block_data({i2np, Type, MsgId, ShortExp, Body}) ->
    tlv(?BLOCK_I2NP, <<Type:8, MsgId:32, ShortExp:32, Body/binary>>);
block_data({first_fragment, Type, MsgId, ShortExp, Body}) ->
    tlv(?BLOCK_FIRST_FRAGMENT, <<Type:8, MsgId:32, ShortExp:32, Body/binary>>);
block_data({follow_on_fragment, FragNum, IsLast, MsgId, Body}) ->
    Last =
        case IsLast of
            true -> 1;
            false -> 0
        end,
    tlv(?BLOCK_FOLLOW_ON_FRAGMENT, <<FragNum:7, Last:1, MsgId:32, Body/binary>>);
block_data({ack, AckThrough, Acnt, Ranges}) when is_list(Ranges) ->
    RangeBin = iolist_to_binary([<<Nack:8, Ack:8>> || {Nack, Ack} <- Ranges]),
    tlv(?BLOCK_ACK, <<AckThrough:32, Acnt:8, RangeBin/binary>>);
block_data({termination, ValidPackets, Reason, AddlData}) ->
    tlv(?BLOCK_TERMINATION, <<ValidPackets:64, Reason:8, AddlData/binary>>);
block_data({relay_request, Flag, Nonce, Tag, Ts, Ver, Port, Ip, Sig}) ->
    tlv(
        ?BLOCK_RELAY_REQUEST,
        <<
            Flag:8,
            Nonce:32,
            Tag:32,
            Ts:32,
            Ver:8,
            (relay_asz(byte_size(Ip))):8,
            Port:16,
            Ip/binary,
            Sig/binary
        >>
    );
block_data({relay_response, Flag, Code, Nonce, Ts, Ver, Port, Ip, Sig, Token}) ->
    tlv(
        ?BLOCK_RELAY_RESPONSE,
        <<
            Flag:8,
            Code:8,
            Nonce:32,
            Ts:32,
            Ver:8,
            (relay_asz(byte_size(Ip))):8,
            (relay_endpoint(Port, Ip))/binary,
            Sig/binary,
            (relay_token(Token))/binary
        >>
    );
block_data({relay_intro, Flag, AliceHash, Nonce, Tag, Ts, Ver, Port, Ip, Sig}) ->
    tlv(
        ?BLOCK_RELAY_INTRO,
        <<
            Flag:8,
            AliceHash/binary,
            Nonce:32,
            Tag:32,
            Ts:32,
            Ver:8,
            (relay_asz(byte_size(Ip))):8,
            Port:16,
            Ip/binary,
            Sig/binary
        >>
    );
block_data({peertest, MsgNum, Code, Flags, RouterHash, Ver, Nonce, Ts, Port, Ip, Sig}) ->
    tlv(
        ?BLOCK_PEER_TEST,
        <<
            MsgNum:8,
            Code:8,
            Flags:8,
            (peertest_hash(MsgNum, RouterHash))/binary,
            Ver:8,
            Nonce:32,
            Ts:32,
            (peertest_asz(byte_size(Ip))):8,
            Port:16,
            Ip/binary,
            Sig/binary
        >>
    );
block_data({address, Port, IpBin}) when byte_size(IpBin) == 4; byte_size(IpBin) == 16 ->
    tlv(?BLOCK_ADDRESS, <<Port:16, IpBin/binary>>);
block_data(relay_tag_request) ->
    tlv(?BLOCK_RELAY_TAG_REQUEST, <<>>);
block_data({relay_tag, Tag}) ->
    tlv(?BLOCK_RELAY_TAG, <<Tag:32>>);
block_data({new_token, Expires, Tok}) ->
    tlv(?BLOCK_NEW_TOKEN, <<Expires:32, Tok:64>>);
block_data({path_challenge, Data}) ->
    tlv(?BLOCK_PATH_CHALLENGE, Data);
block_data({path_response, Data}) ->
    tlv(?BLOCK_PATH_RESPONSE, Data);
block_data({first_packet_number, Num}) ->
    tlv(?BLOCK_FIRST_PACKET_NUMBER, <<Num:32>>);
block_data({congestion, Flags}) ->
    tlv(?BLOCK_CONGESTION, <<Flags:8>>);
block_data({padding, Pad}) ->
    tlv(?BLOCK_PADDING, Pad).

tlv(Type, Data) ->
    <<Type:8, (byte_size(Data)):16, Data/binary>>.

%% The PeerTest router-hash field is carried only in messages 2 and 4 (the
%% Alice hash going Charlie-ward, or the Charlie hash going Alice-ward);
%% messages 1, 3, 5, 6, 7 have no hash field at all.
peertest_hash(MsgNum, RouterHash) when
    (MsgNum == 2 orelse MsgNum == 4), byte_size(RouterHash) == 32
->
    RouterHash;
peertest_hash(_MsgNum, _RouterHash) ->
    <<>>.

%% `asz` is the endpoint size: port (2 bytes) + IP (4 for IPv4, 16 for IPv6).
peertest_asz(4) -> 6;
peertest_asz(16) -> 18.

%% Relay `asz`/`csz` endpoint size. Unlike PeerTest, a RelayResponse may omit
%% the endpoint entirely (`0`): Bob's rejects carry no Charlie address, and
%% some Charlie reject codes likewise.
relay_asz(0) -> 0;
relay_asz(4) -> 6;
relay_asz(16) -> 18.

%% The endpoint bytes of a relay block: `<<>>` when the address is empty
%% (csz 0), else port + IP.
relay_endpoint(_Port, <<>>) ->
    <<>>;
relay_endpoint(Port, Ip) ->
    <<Port:16, Ip/binary>>.

%% The optional RelayResponse token (8 bytes, only on accept). `undefined`
%% encodes as nothing.
relay_token(undefined) ->
    <<>>;
relay_token(Token) ->
    <<Token:64>>.

%% Split a RelayResponse's trailing signature (64-byte Ed25519) from the
%% optional 8-byte token. A token is valid only on accept (code 0); any other
%% trailing bytes fail closed.
relay_response_tail(Flag, Code, Nonce, Ts, Ver, Port, Ip, Sig, <<>>) ->
    {relay_response, Flag, Code, Nonce, Ts, Ver, Port, Ip, Sig, undefined};
relay_response_tail(Flag, 0, Nonce, Ts, Ver, Port, Ip, Sig, <<Token:64>>) ->
    {relay_response, Flag, 0, Nonce, Ts, Ver, Port, Ip, Sig, Token};
relay_response_tail(_Flag, _Code, _Nonce, _Ts, _Ver, _Port, _Ip, _Sig, _Rest) ->
    error.

-doc """
Decode payload blocks.

Input: the decrypted block data of one datagram.
Output: `{ok, [block()]}` — unknown block types are ignored per the
specification's forward-compatibility rule; `error` on truncation or an
impossible length field.
""".
-spec decode_blocks(binary()) -> {ok, [block()]} | error.
decode_blocks(Bin) ->
    walk_blocks(Bin, []).

walk_blocks(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
walk_blocks(<<Type:8, Len:16, Data:Len/binary, Rest/binary>>, Acc) ->
    case decode_block(Type, Data) of
        error -> error;
        ignore -> walk_blocks(Rest, Acc);
        Block -> walk_blocks(Rest, [Block | Acc])
    end;
walk_blocks(_Other, _Acc) ->
    error.

decode_block(?BLOCK_DATETIME, <<Secs:32>>) ->
    {datetime, Secs};
decode_block(?BLOCK_OPTIONS, Data) ->
    {options, Data};
decode_block(?BLOCK_ROUTER_INFO, <<Flag:8, _FragNum:4, _Total:4, RiData/binary>>) ->
    {router_info, Flag, RiData};
decode_block(?BLOCK_I2NP, <<Type:8, MsgId:32, ShortExp:32, Body/binary>>) ->
    {i2np, Type, MsgId, ShortExp, Body};
decode_block(?BLOCK_FIRST_FRAGMENT, <<Type:8, MsgId:32, ShortExp:32, Body/binary>>) ->
    {first_fragment, Type, MsgId, ShortExp, Body};
decode_block(?BLOCK_FOLLOW_ON_FRAGMENT, <<FragNum:7, Last:1, MsgId:32, Body/binary>>) when
    FragNum >= 1
->
    {follow_on_fragment, FragNum, Last =:= 1, MsgId, Body};
decode_block(?BLOCK_TERMINATION, <<ValidPackets:64, Reason:8, AddlData/binary>>) ->
    {termination, ValidPackets, Reason, AddlData};
decode_block(
    ?BLOCK_RELAY_REQUEST,
    <<Flag:8, Nonce:32, Tag:32, Ts:32, Ver:8, Asz:8, Port:16, Ip:(Asz - 2)/binary, Sig/binary>>
) when (Asz == 6 orelse Asz == 18) ->
    {relay_request, Flag, Nonce, Tag, Ts, Ver, Port, Ip, Sig};
decode_block(?BLOCK_RELAY_REQUEST, _Data) ->
    error;
decode_block(
    ?BLOCK_RELAY_RESPONSE,
    <<Flag:8, Code:8, Nonce:32, Ts:32, Ver:8, Csz:8, Port:16, Ip:(Csz - 2)/binary, Sig:64/binary,
        Rest/binary>>
) when (Csz == 6 orelse Csz == 18) ->
    relay_response_tail(Flag, Code, Nonce, Ts, Ver, Port, Ip, Sig, Rest);
decode_block(
    ?BLOCK_RELAY_RESPONSE,
    <<Flag:8, Code:8, Nonce:32, Ts:32, Ver:8, 0:8, Sig:64/binary, Rest/binary>>
) ->
    relay_response_tail(Flag, Code, Nonce, Ts, Ver, 0, <<>>, Sig, Rest);
decode_block(?BLOCK_RELAY_RESPONSE, _Data) ->
    error;
decode_block(
    ?BLOCK_RELAY_INTRO,
    <<Flag:8, AliceHash:32/binary, Nonce:32, Tag:32, Ts:32, Ver:8, Asz:8, Port:16,
        Ip:(Asz - 2)/binary, Sig/binary>>
) when (Asz == 6 orelse Asz == 18) ->
    {relay_intro, Flag, AliceHash, Nonce, Tag, Ts, Ver, Port, Ip, Sig};
decode_block(?BLOCK_RELAY_INTRO, _Data) ->
    error;
decode_block(
    ?BLOCK_PEER_TEST,
    <<MsgNum:8, Code:8, Flags:8, Ver:8, Nonce:32, Ts:32, Asz:8, Port:16, Ip:(Asz - 2)/binary,
        Sig/binary>>
) when
    (MsgNum == 1 orelse MsgNum == 3 orelse MsgNum == 5 orelse MsgNum == 6 orelse
        MsgNum == 7),
    (Asz == 6 orelse Asz == 18)
->
    {peertest, MsgNum, Code, Flags, <<0:256>>, Ver, Nonce, Ts, Port, Ip, Sig};
decode_block(
    ?BLOCK_PEER_TEST,
    <<MsgNum:8, Code:8, Flags:8, Hash:32/binary, Ver:8, Nonce:32, Ts:32, Asz:8, Port:16,
        Ip:(Asz - 2)/binary, Sig/binary>>
) when MsgNum >= 2, MsgNum =< 4, (Asz == 6 orelse Asz == 18) ->
    {peertest, MsgNum, Code, Flags, Hash, Ver, Nonce, Ts, Port, Ip, Sig};
decode_block(?BLOCK_PEER_TEST, _Data) ->
    ignore;
decode_block(?BLOCK_ADDRESS, <<Port:16, IpBin/binary>>) when
    byte_size(IpBin) == 4; byte_size(IpBin) == 16
->
    {address, Port, IpBin};
decode_block(?BLOCK_RELAY_TAG_REQUEST, <<>>) ->
    relay_tag_request;
decode_block(?BLOCK_RELAY_TAG, <<0:32>>) ->
    ignore;
decode_block(?BLOCK_RELAY_TAG, <<Tag:32>>) ->
    {relay_tag, Tag};
decode_block(?BLOCK_NEW_TOKEN, <<Expires:32, Tok:64>>) ->
    {new_token, Expires, Tok};
decode_block(?BLOCK_PATH_CHALLENGE, Data) ->
    {path_challenge, Data};
decode_block(?BLOCK_PATH_RESPONSE, Data) ->
    {path_response, Data};
decode_block(?BLOCK_FIRST_PACKET_NUMBER, <<Num:32>>) ->
    {first_packet_number, Num};
decode_block(?BLOCK_CONGESTION, <<Flags:8>>) ->
    {congestion, Flags};
decode_block(?BLOCK_ACK, <<AckThrough:32, Acnt:8, Ranges/binary>>) ->
    case decode_ack_ranges(Ranges, []) of
        error -> error;
        RangeList -> {ack, AckThrough, Acnt, RangeList}
    end;
decode_block(?BLOCK_PADDING, _Pad) ->
    ignore;
decode_block(_Unknown, _Data) ->
    ignore.

-doc """
Guarantee the minimum payload size by appending a padding block.

Input: any encoded block data.
Output: at least eight bytes of block data — padding is added only when the
input is shorter than the protocol minimum.
""".
-spec ensure_min_payload(binary()) -> binary().
ensure_min_payload(Payload) when byte_size(Payload) >= ?MIN_PAYLOAD ->
    Payload;
ensure_min_payload(Payload) ->
    PadLen = ?MIN_PAYLOAD - byte_size(Payload),
    <<Payload/binary, (tlv(?BLOCK_PADDING, <<0:PadLen/unit:8>>))/binary>>.

%% Walk an ACK block's trailing range bytes into `{Nack, Ack}` run-length
%% pairs. Fail-closed: a fractional range, or one where both counts are zero
%% (the encoding forbids it), yields `error`.
decode_ack_ranges(<<>>, Acc) ->
    lists:reverse(Acc);
decode_ack_ranges(<<Nack:8, Ack:8, Rest/binary>>, Acc) when Nack > 0; Ack > 0 ->
    decode_ack_ranges(Rest, [{Nack, Ack} | Acc]);
decode_ack_ranges(_Malformed, _Acc) ->
    error.

-doc """
Build an `{ack, AckThrough, Acnt, Ranges}` block describing the packet
numbers a session has received.

Input: `Recv` — a `m:i2p_ssu2_recv:window/0`, the session's receive window;
`MaxRanges` — an upper bound on how many `{Nack, Ack}` run-length ranges to emit
(older, lower-numbered packets are dropped first when exceeded, per the spec's
bounded-ackroom rule).

Output: a `t:ack_block/0` ACK block. `AckThrough` is the highest received packet;
`Acnt` the number of consecutive received packets immediately below it; the
ranges express the alternating NACK/ACK runs below that, where each range
starts with a NACK count (the spec encodes the first gap as `nack` bits).

Example (the spec's worked case): for received `[10,9,8,6,5,2,1,0]` with
7,4,3 missing, produces `AckThrough=10, Acnt=2, Ranges=[{1,2},{2,3}]` — i.e.
NACK 7, ACK 6 5, then NACK 4 3, ACK 2 1 0.

The window is `m:i2p_ssu2_recv`'s, not a list of packet numbers, and the
encoding is its `f:build/2`. This exists as the named entry point because the
block is a wire-format concept and belongs to the codec; the walk itself lives
with the window it walks, so there is one implementation of the format rather
than two that must agree. See #7GP4A4K.
""".
-spec build_ack(i2p_ssu2_recv:window(), non_neg_integer()) -> ack_block().
build_ack(Recv, MaxRanges) when is_integer(MaxRanges), MaxRanges >= 0 ->
    i2p_ssu2_recv:build(Recv, MaxRanges).

-doc """
Expand an ACK block back into the concrete acked and nacked packet numbers.

Input: an `{ack, AckThrough, Acnt, Ranges}` block as produced by
`f:build_ack/2` or decoded from the wire.
Output: `{AckedNums, NackedNums}` — the packet numbers explicitly ACKed and
those explicitly NACKed. Numbers below the last range are neither acked nor
nacked (the encoding is open-ended) and are omitted.
""".
-spec ack_expand(block()) -> {[non_neg_integer()], [non_neg_integer()]}.
ack_expand({ack, AckThrough, Acnt, Ranges}) ->
    AckedAcc = down(AckThrough, Acnt + 1),
    {Acked, Nacked} = walk_ack_ranges(Ranges, AckThrough - Acnt - 1, AckedAcc, []),
    {lists:usort(Acked), lists:usort(Nacked)}.

walk_ack_ranges([], _Low, Acked, Nacked) ->
    {Acked, Nacked};
walk_ack_ranges([{Nack, Ack} | Rest], Low, Acked, Nacked) ->
    Nacked1 = down(Low, Nack) ++ Nacked,
    Acked1 = down(Low - Nack, Ack) ++ Acked,
    walk_ack_ranges(Rest, Low - Nack - Ack, Acked1, Nacked1).

%% Numbers `Start`, `Start-1`, ... down to `Start-Count+1` (inclusive), in
%% descending order, clamped at zero. `down(_, 0, _)` yields `[]`.
down(Start, Count) ->
    down(Start, Count, []).

down(_Start, 0, Acc) ->
    Acc;
down(Start, _Count, Acc) when Start < 0 ->
    Acc;
down(Start, Count, Acc) ->
    down(Start - 1, Count - 1, [Start | Acc]).

-doc """
Split a complete I2NP message into SSU2 fragment blocks.

Input: `Type` (8-bit I2NP type), `MsgId` (32-bit), `ShortExp` (32-bit), the
full `Body`, and `MaxBodySize` — the largest body each fragment may carry
(the session derives it from the MTU). The first fragment is type 4, the
rest type 5 with sequential `FragNum` and `IsLast` marking the final one.
Output: a list of `t:block/0` fragment blocks, in order.
""".
-spec fragment_i2np(byte(), non_neg_integer(), non_neg_integer(), binary(), pos_integer()) ->
    [block()].
fragment_i2np(Type, MsgId, ShortExp, Body, MaxBodySize) when
    MaxBodySize >= 1
->
    First = do_fragment_blocks(Type, MsgId, ShortExp, Body, MaxBodySize),
    First.

do_fragment_blocks(Type, MsgId, ShortExp, Body, MaxBodySize) ->
    FirstBody = binary:part(Body, 0, min(byte_size(Body), MaxBodySize)),
    RestSize = byte_size(Body) - byte_size(FirstBody),
    First =
        {first_fragment, Type, MsgId, ShortExp, FirstBody},
    case RestSize of
        0 ->
            [First];
        _ ->
            Follows =
                follow_fragments(
                    MsgId,
                    binary:part(Body, byte_size(FirstBody), RestSize),
                    MaxBodySize,
                    1,
                    []
                ),
            [First | Follows]
    end.

follow_fragments(MsgId, Rest0, MaxBodySize, FragNum, Acc) ->
    Take = min(byte_size(Rest0), MaxBodySize),
    Piece = binary:part(Rest0, 0, Take),
    Rest = binary:part(Rest0, Take, byte_size(Rest0) - Take),
    IsLast = byte_size(Rest) =:= 0,
    Block = {follow_on_fragment, FragNum, IsLast, MsgId, Piece},
    case IsLast of
        true -> lists:reverse([Block | Acc]);
        false -> follow_fragments(MsgId, Rest, MaxBodySize, FragNum + 1, [Block | Acc])
    end.

%%%%%%%%% %%% Handshake %%%%%%%

-doc """
Noise initialization common to both roles (before the `e` step).

`ck = SHA256(protocol_name)`; then the null-prologue MixHash folds in one
more hash before mixing the responder static key, so
`h = SHA256(SHA256(SHA256(protocol_name)) || bpk)`, exactly like NTCP2 but
with the SSU2 protocol name.

Input: `Bpk` — Bob's X25519 static public key from his RouterInfo.
Output: `{Ck, H}`.
""".
-spec initialize(i2p_crypto:x25519_public_key()) ->
    {i2p_crypto:chaining_key(), i2p_crypto:hash()}.
initialize(Bpk) ->
    Ck = crypto:hash(sha256, ?PROTOCOL_NAME),
    {Ck, i2p_crypto:mixhash(crypto:hash(sha256, Ck), Bpk)}.

-doc """
Alice's initial handshake state for a session to Bob.

Input: `Bpk` — Bob's static public key; `Bik` — Bob's introduction key
(published as the `i` option of his SSU2 RouterAddress); Alice's own static
keypair used for the `se` step of SessionConfirmed.
Output: the initial `t:state/0`.
""".
-spec alice_init(
    i2p_crypto:x25519_public_key(),
    i2p_crypto:key(),
    i2p_crypto:x25519_private_key(),
    i2p_crypto:x25519_public_key()
) -> state().
alice_init(Bpk, Bik, MyStaticPriv, MyStaticPub) ->
    {Ck, H} = initialize(Bpk),
    #{
        role => alice,
        ck => Ck,
        h => H,
        k => <<0:256>>,
        bik => Bik,
        bpk => Bpk,
        my_static_priv => MyStaticPriv,
        my_static_pub => MyStaticPub
    }.

-doc """
Bob's initial handshake state for inbound sessions.

Input: Bob's static private/public keypair and his introduction key.
Output: the initial `t:state/0`.
""".
-spec bob_init(
    i2p_crypto:x25519_private_key(),
    i2p_crypto:x25519_public_key(),
    i2p_crypto:key()
) -> state().
bob_init(MyStaticPriv, MyStaticPub, Bik) ->
    {Ck, H} = initialize(MyStaticPub),
    #{
        role => bob,
        ck => Ck,
        h => H,
        k => <<0:256>>,
        bik => Bik,
        bpk => MyStaticPub,
        my_static_priv => MyStaticPriv,
        my_static_pub => MyStaticPub
    }.

-doc """
Alice sends SessionRequest (type 0).

Input: state from `f:alice_init/4`; `EphPriv` — a fresh X25519 ephemeral
private key; the connection IDs Alice chose (`DstConnId` random, must
differ from `SrcConnId`); `Tok` — the token granted in a Retry, or zero;
the random header packet number; payload blocks (DateTime required, Relay
Tag Request optional).
Output: `{ok, Datagram, State'}` with the obfuscated packet, or `error`.
""".
-spec create_session_request(
    state(),
    i2p_crypto:x25519_private_key(),
    conn_id(),
    conn_id(),
    token(),
    non_neg_integer(),
    [block()]
) ->
    {ok, binary(), state()} | error.
create_session_request(
    State = #{bik := Bik, bpk := Bpk},
    EphPriv,
    DstConnId,
    SrcConnId,
    Tok,
    PktNum,
    Blocks
) when DstConnId =/= SrcConnId ->
    Header = long_header(DstConnId, PktNum, ?TYPE_SESSION_REQUEST, SrcConnId, Tok),
    Aepk = i2p_crypto:x25519_public_key(EphPriv),
    H1 = i2p_crypto:mixhash(maps:get(h, State), Header),
    H2 = i2p_crypto:mixhash(H1, Aepk),
    {Ck2, K} = i2p_crypto:mixkey(
        maps:get(ck, State),
        i2p_crypto:x25519_dh(EphPriv, Bpk)
    ),
    Frame = seal_frame(K, H2, ensure_min_payload(encode_blocks(Blocks))),
    KH2Next = sess_create_header_key(Ck2),
    Packet =
        seal_ephemeral(
            <<Header/binary, Aepk/binary, Frame/binary>>,
            Bik,
            Bik
        ),
    State2 = State#{
        ck => Ck2,
        h => i2p_crypto:mixhash(H2, Frame),
        k => K,
        eph_priv => EphPriv,
        sess_create_header_key => KH2Next,
        src_conn_id => SrcConnId,
        dst_conn_id => DstConnId
    },
    {ok, Packet, State2};
create_session_request(
    _State,
    _EphPriv,
    _DstConnId,
    _SrcConnId,
    _Tok,
    _PktNum,
    _Blocks
) ->
    error.

%% AEAD-encrypt a Noise payload frame with the current key and hash:
%% ciphertext || MAC under n=0, ad=h.
seal_frame(Key, Hash, Plaintext) ->
    {CT, MAC} = i2p_crypto:chacha20_poly1305_encrypt(
        Key,
        i2p_crypto:zero_nonce(),
        Plaintext,
        Hash
    ),
    <<CT/binary, MAC/binary>>.

sess_create_header_key(Ck) ->
    i2p_crypto:hkdf_sha256(Ck, <<>>, <<"SessCreateHeader">>, 32).

sess_confirm_header_key(Ck) ->
    i2p_crypto:hkdf_sha256(Ck, <<>>, <<"SessionConfirmed">>, 32).

%% AEAD nonce for counter N: four zero bytes, then little-endian counter.
nonce(N) ->
    <<0:32, N:64/little>>.

%% Parse and validate a long header revealed after de-obfuscation.
parse_long_header(
    <<DstConnId:64, PktNum:32, Type:8, ?VERSION:8, NetId:8, 0:8, SrcConnId:64, Tok:64>>
) when NetId == ?NET_ID, DstConnId =/= SrcConnId ->
    #{
        type => Type,
        pkt_num => PktNum,
        src_conn_id => SrcConnId,
        dst_conn_id => DstConnId,
        token => Tok
    };
parse_long_header(_Other) ->
    error.

%% Split an opened ephemeral datagram into its plaintext header, ephemeral
%% key, encrypted payload and MAC.
split_ephemeral_frame(<<Header:32/binary, EphKey:32/binary, CT/binary>>) ->
    CTSize = byte_size(CT) - 16,
    <<Ciphertext:CTSize/binary, MAC:16/binary>> = CT,
    {Header, EphKey, Ciphertext, MAC};
split_ephemeral_frame(_TooShort) ->
    error.

%% Run the shared "es"/"ee" MixKey chain over a DH result.
mix_dh(State, DHResult) ->
    i2p_crypto:mixkey(maps:get(ck, State), DHResult).

-doc """
Bob receives SessionRequest.

Input: state from `f:bob_init/3` and the received datagram.
Output: `{ok, Info, State'}` where `Info` carries `src_conn_id`,
`dst_conn_id`, `token`, the decrypted Alice ephemeral key `ephemeral`, and
the decoded payload `blocks`; or `error` on any malformed input, wrong
version/net ID, identical connection IDs, or AEAD failure.
""".
-spec receive_session_request(state(), datagram()) ->
    {ok,
        #{
            src_conn_id := conn_id(),
            dst_conn_id := conn_id(),
            token := token(),
            ephemeral := i2p_crypto:x25519_public_key(),
            blocks := [block()]
        },
        state()}
    | error.
receive_session_request(State = #{bik := Bik}, Packet) ->
    case open_ephemeral(Packet, Bik, Bik) of
        {ok, Open} ->
            handle_session_request(State, Open);
        error ->
            error
    end.

handle_session_request(State, Open) ->
    case split_ephemeral_frame(Open) of
        {Header, Aepk, Ciphertext, MAC} ->
            case parse_long_header(Header) of
                #{type := ?TYPE_SESSION_REQUEST} = HdrInfo ->
                    proceed_session_request(
                        State,
                        HdrInfo,
                        Header,
                        Aepk,
                        Ciphertext,
                        MAC
                    );
                _NotASessionRequest ->
                    error
            end;
        _TooShort ->
            error
    end.

proceed_session_request(
    State = #{my_static_priv := MyStaticPriv},
    HdrInfo,
    Header,
    Aepk,
    Ciphertext,
    MAC
) ->
    H1 = i2p_crypto:mixhash(maps:get(h, State), Header),
    H2 = i2p_crypto:mixhash(H1, Aepk),
    %% "es": DH(Bob's static private, Alice's ephemeral public).
    {Ck2, K} = mix_dh(State, i2p_crypto:x25519_dh(MyStaticPriv, Aepk)),
    case
        i2p_crypto:chacha20_poly1305_decrypt(
            K,
            i2p_crypto:zero_nonce(),
            Ciphertext,
            MAC,
            H2
        )
    of
        Payload when is_binary(Payload) ->
            finish_session_request(
                State,
                HdrInfo,
                Aepk,
                H2,
                Ciphertext,
                MAC,
                K,
                Ck2,
                Payload
            );
        error ->
            error
    end.

finish_session_request(
    State,
    HdrInfo,
    Aepk,
    H2,
    Ciphertext,
    MAC,
    K,
    Ck2,
    Payload
) ->
    case decode_blocks(Payload) of
        {ok, Blocks} ->
            #{
                src_conn_id := SrcConnId,
                dst_conn_id := DstConnId,
                token := Tok
            } = HdrInfo,
            Info =
                #{
                    src_conn_id => SrcConnId,
                    dst_conn_id => DstConnId,
                    token => Tok,
                    ephemeral => Aepk,
                    blocks => Blocks
                },
            State2 = State#{
                ck => Ck2,
                h => i2p_crypto:mixhash(H2, <<Ciphertext/binary, MAC/binary>>),
                k => K,
                peer_eph => Aepk,
                sess_create_header_key => sess_create_header_key(Ck2),
                src_conn_id => SrcConnId,
                dst_conn_id => DstConnId
            },
            {ok, Info, State2};
        error ->
            error
    end.

-doc """
Bob sends SessionCreated (type 1) in response to a SessionRequest.

Input: state from `f:receive_session_request/2`; `EphPriv` — Bob's fresh
ephemeral private key; the random header packet number; payload blocks
(DateTime and Address required, Relay Tag / New Token / Options optional).
Output: `{ok, Datagram, State'}` or `error`.
""".
-spec create_session_created(
    state(),
    i2p_crypto:x25519_private_key(),
    non_neg_integer(),
    [block()]
) -> {ok, binary(), state()}.
create_session_created(State = #{bik := Bik}, EphPriv, PktNum, Blocks) ->
    #{src_conn_id := TheirSrc, dst_conn_id := TheirDst} = State,
    Header = long_header(TheirSrc, PktNum, ?TYPE_SESSION_CREATED, TheirDst, 0),
    Bepk = i2p_crypto:x25519_public_key(EphPriv),
    H1 = i2p_crypto:mixhash(maps:get(h, State), Header),
    H2 = i2p_crypto:mixhash(H1, Bepk),
    %% "ee": DH(Bob's ephemeral private, Alice's ephemeral public).
    {Ck2, K} = mix_dh(
        State,
        i2p_crypto:x25519_dh(EphPriv, maps:get(peer_eph, State))
    ),
    Frame = seal_frame(K, H2, ensure_min_payload(encode_blocks(Blocks))),
    Packet = seal_ephemeral(
        <<Header/binary, Bepk/binary, Frame/binary>>,
        Bik,
        maps:get(sess_create_header_key, State)
    ),
    State2 = State#{
        ck => Ck2,
        h => i2p_crypto:mixhash(H2, Frame),
        k => K,
        eph_priv => EphPriv,
        sess_confirm_header_key => sess_confirm_header_key(Ck2)
    },
    {ok, Packet, State2}.

%% Parse and validate an opened SessionCreated header: type 1 and the
%% mirrored connection IDs of the SessionRequest that preceded it.
check_created_header(Header, #{src_conn_id := OurSrc, dst_conn_id := OurDst}) ->
    case parse_long_header(Header) of
        #{type := ?TYPE_SESSION_CREATED, src_conn_id := OurDst, dst_conn_id := OurSrc} =
                HdrInfo ->
            HdrInfo;
        _ ->
            error
    end.

-doc """
Alice receives SessionCreated.

Input: state from `f:create_session_request/7` and the received datagram.
Output: `{ok, Info, State'}` with `src_conn_id`, `dst_conn_id` and decoded
payload `blocks`; `error` on any mismatch — including connection IDs that
do not mirror the SessionRequest — or AEAD failure.
""".
-spec receive_session_created(state(), datagram()) ->
    {ok,
        #{
            src_conn_id := conn_id(),
            dst_conn_id := conn_id(),
            blocks := [block()]
        },
        state()}
    | error.
receive_session_created(State = #{bik := Bik}, Packet) ->
    KH2 = maps:get(sess_create_header_key, State),
    case open_ephemeral(Packet, Bik, KH2) of
        {ok, Open} ->
            case split_ephemeral_frame(Open) of
                {Header, Bepk, Ciphertext, MAC} ->
                    handle_session_created(State, Header, Bepk, Ciphertext, MAC);
                error ->
                    error
            end;
        error ->
            error
    end.

handle_session_created(State, Header, Bepk, Ciphertext, MAC) ->
    case check_created_header(Header, State) of
        #{src_conn_id := SrcConnId, dst_conn_id := DstConnId} ->
            proceed_session_created(State, SrcConnId, DstConnId, Header, Bepk, Ciphertext, MAC);
        error ->
            error
    end.

proceed_session_created(State, SrcConnId, DstConnId, Header, Bepk, Ciphertext, MAC) ->
    H1 = i2p_crypto:mixhash(maps:get(h, State), Header),
    H2 = i2p_crypto:mixhash(H1, Bepk),
    %% "ee": DH(Alice's ephemeral private, Bob's ephemeral public).
    {Ck2, K} = mix_dh(
        State,
        i2p_crypto:x25519_dh(maps:get(eph_priv, State), Bepk)
    ),
    case i2p_crypto:chacha20_poly1305_decrypt(K, i2p_crypto:zero_nonce(), Ciphertext, MAC, H2) of
        Payload when is_binary(Payload) ->
            finish_session_created(
                State, SrcConnId, DstConnId, Bepk, H2, Ciphertext, MAC, K, Ck2, Payload
            );
        error ->
            error
    end.

finish_session_created(State, SrcConnId, DstConnId, Bepk, H2, Ciphertext, MAC, K, Ck2, Payload) ->
    case decode_blocks(Payload) of
        {ok, Blocks} ->
            State2 = State#{
                ck => Ck2,
                h => i2p_crypto:mixhash(H2, <<Ciphertext/binary, MAC/binary>>),
                k => K,
                peer_eph => Bepk,
                sess_confirm_header_key => sess_confirm_header_key(Ck2)
            },
            {ok,
                #{
                    src_conn_id => SrcConnId,
                    dst_conn_id => DstConnId,
                    blocks => Blocks
                },
                State2};
        error ->
            error
    end.

-doc """
Alice sends SessionConfirmed (type 2): her encrypted static key followed by
her RouterInfo and any other blocks, fragmented as needed.

Input: state from `f:receive_session_created/2`; payload blocks — the
RouterInfo block MUST come first; `MaxPacketSize` — the datagram size limit
(1472 for IPv4, 1452 for IPv6 on typical MTUs).
Output: `{ok, [Datagram], DataKeys, State'}` — the fragment datagrams in
order (a single one when everything fits), the data phase keys, and the
final handshake state; `error` when the first block is not a RouterInfo or
more than 15 fragments would be required.
""".
-spec create_session_confirmed(state(), [block()], pos_integer()) ->
    {ok, [binary()], data_keys(), state()} | error.
create_session_confirmed(State = #{my_static_priv := MyStaticPriv}, Blocks, MaxPacketSize) ->
    case {Blocks, encode_blocks(Blocks)} of
        {[{router_info, _Flag, _RI} | _], Payload} ->
            emit_session_confirmed(State, MyStaticPriv, Payload, MaxPacketSize);
        {_, _} ->
            error
    end.

emit_session_confirmed(State, MyStaticPriv, Payload, MaxPacketSize) ->
    Capacity = MaxPacketSize - 16,
    TotalFrames = 64 + byte_size(Payload) + 16,
    FragTotal = (TotalFrames + Capacity - 1) div Capacity,
    begin_fragmenting(State, MyStaticPriv, Payload, Capacity, FragTotal).

%% The protocol allows at most 15 SessionConfirmed fragments.
begin_fragmenting(_State, _Priv, _Payload, _Capacity, FragTotal) when FragTotal > 15 ->
    error;
begin_fragmenting(State, MyStaticPriv, Payload, Capacity, FragTotal) ->
    #{bik := Bik, my_static_pub := Apk} = State,
    DstConnId = maps:get(dst_conn_id, State),
    FragHdr0 = short_header_confirmed(DstConnId, 0, FragTotal),
    H1 = i2p_crypto:mixhash(maps:get(h, State), FragHdr0),
    %% "s": encrypt our static public key with the SessionCreated key, n=1.
    {CT1, MAC1} = i2p_crypto:chacha20_poly1305_encrypt(maps:get(k, State), nonce(1), Apk, H1),
    Frame1 = <<CT1/binary, MAC1/binary>>,
    H2 = i2p_crypto:mixhash(H1, Frame1),
    %% "se": DH(Alice's static private, Bob's ephemeral public).
    {Ck2, K2} = mix_dh(
        State,
        i2p_crypto:x25519_dh(MyStaticPriv, maps:get(peer_eph, State))
    ),
    Frame2 = seal_frame(K2, H2, Payload),
    Keys = data_keys(Ck2),
    AllFrames = <<Frame1/binary, Frame2/binary>>,
    Chunks = split_frames(AllFrames, FragTotal, Capacity),
    Packets = [
        begin
            Hdr = short_header_confirmed(DstConnId, N - 1, FragTotal),
            seal_short(
                <<Hdr/binary, Chunk/binary>>,
                Bik,
                maps:get(sess_confirm_header_key, State)
            )
        end
     || {N, Chunk} <- lists:zip(lists:seq(1, length(Chunks)), Chunks)
    ],
    H3 = i2p_crypto:mixhash(H2, Frame2),
    State2 = State#{ck => Ck2, h => H3, k => K2},
    {ok, Packets, Keys, State2}.

%% Split the jumbo frame into per-packet chunks: every chunk full except
%% the last, which must still carry at least 24 bytes for header
%% encryption to work.
split_frames(Frames, FragTotal, Capacity) ->
    Full = FragTotal - 1,
    LastSize = max(?MIN_PAYLOAD + 16, byte_size(Frames) - Full * Capacity),
    Sizes = lists:duplicate(Full, Capacity) ++ [LastSize],
    split_sizes(Frames, Sizes).

split_sizes(Frames, Sizes) ->
    split_sizes(Frames, Sizes, []).

split_sizes(<<>>, [], Acc) ->
    lists:reverse(Acc);
split_sizes(Frames, [N | Rest], Acc) ->
    <<Chunk:N/binary, Tail/binary>> = Frames,
    split_sizes(Tail, Rest, [Chunk | Acc]).

-doc """
Bob receives SessionConfirmed: one or more fragment datagrams.

Input: state from `f:create_session_created/4`; the fragments in order
(a single datagram when unfragmented).
Output: `{ok, Info, State'}` where `Info` carries `static_key` — Alice's
decrypted X25519 static key, which the caller MUST match against her
RouterInfo — plus the decoded `blocks` and the derived data phase `keys`;
`error` on any framing, AEAD or ordering violation (the first payload
block must be a RouterInfo).
""".
-spec receive_session_confirmed(state(), [binary()]) ->
    {ok,
        #{
            static_key := i2p_crypto:x25519_public_key(),
            blocks := [block()],
            keys := data_keys()
        },
        state()}
    | error.
receive_session_confirmed(State = #{bik := Bik}, Packets) ->
    KH2 = maps:get(sess_confirm_header_key, State),
    case open_all_fragments(Packets, Bik, KH2) of
        {ok, Opened} ->
            assemble_confirmed(State, Opened);
        error ->
            error
    end.

%% De-obfuscate every fragment; keep its plaintext header and frame bytes.
open_all_fragments(Packets, Bik, KH2) ->
    open_all_fragments(Packets, Bik, KH2, []).

open_all_fragments([], _Bik, _KH2, Acc) ->
    {ok, lists:reverse(Acc)};
open_all_fragments([Packet | Rest], Bik, KH2, Acc) ->
    case open_short(Packet, Bik, KH2) of
        {ok, <<Hdr:16/binary, Chunk/binary>>} when byte_size(Chunk) >= 24 ->
            case Hdr of
                <<_DstConnId:64, 0:32, ?TYPE_SESSION_CONFIRMED:8, FragNum:4, FragTotal:4, 0:16>> ->
                    open_all_fragments(
                        Rest,
                        Bik,
                        KH2,
                        [{FragNum, FragTotal, Hdr, Chunk} | Acc]
                    );
                _NotConfirmed ->
                    error
            end;
        _Other ->
            error
    end.

%% Validate that every fragment agrees on the total and the numbers form a
%% complete 0..total-1 sequence; return fragment 0's header and all frame
%% bytes concatenated.
totals_of(Opened) ->
    NumList = lists:sort([N || {N, _T, _H, _C} <- Opened]),
    Totals = lists:usort([T || {_N, T, _H, _C} <- Opened]),
    Complete =
        case Totals of
            [FragTotal] -> NumList == lists:seq(0, FragTotal - 1);
            _OtherTotals -> false
        end,
    case Complete andalso length(Opened) == hd(Totals ++ [0]) of
        true ->
            ByNum = lists:keysort(1, Opened),
            {_Zero, _Total, Hdr0, _Chunk0} = hd(ByNum),
            Frames = <<<<Chunk/binary>> || {_N, _T, _H, Chunk} <- ByNum>>,
            {ok, Hdr0, Frames};
        false ->
            error
    end.

assemble_confirmed(State, Opened) ->
    case totals_of(Opened) of
        {ok, Hdr0, Frames} ->
            proceed_confirmed(State, Hdr0, Frames);
        error ->
            error
    end.

%% The reassembled jumbo carries two AEAD frames: Alice's static key under
%% the SessionCreated key (n=1), then her payload under the post-"se" key.
proceed_confirmed(State, FragHdr0, Frames) ->
    case split_confirmed_frames(Frames) of
        {CT1, MAC1, Ciphertext, MAC} ->
            H1 = i2p_crypto:mixhash(maps:get(h, State), FragHdr0),
            case
                i2p_crypto:chacha20_poly1305_decrypt(
                    maps:get(k, State),
                    nonce(1),
                    CT1,
                    MAC1,
                    H1
                )
            of
                Apk when is_binary(Apk) ->
                    finish_confirmed(
                        State,
                        Apk,
                        H1,
                        <<CT1/binary, MAC1/binary>>,
                        Ciphertext,
                        MAC
                    );
                error ->
                    error
            end;
        error ->
            error
    end.

split_confirmed_frames(<<CT1:32/binary, MAC1:16/binary, CT2/binary>>) ->
    Sz = byte_size(CT2) - 16,
    <<Ciphertext:Sz/binary, MAC:16/binary>> = CT2,
    {CT1, MAC1, Ciphertext, MAC};
split_confirmed_frames(_TooShort) ->
    error.

finish_confirmed(State, Apk, H1, Frame1, Ciphertext, MAC) ->
    %% "se": DH(Bob's ephemeral private, Alice's static public).
    {Ck2, K2} = mix_dh(
        State,
        i2p_crypto:x25519_dh(maps:get(eph_priv, State), Apk)
    ),
    H2 = i2p_crypto:mixhash(H1, Frame1),
    case
        i2p_crypto:chacha20_poly1305_decrypt(
            K2,
            i2p_crypto:zero_nonce(),
            Ciphertext,
            MAC,
            H2
        )
    of
        Payload when is_binary(Payload) ->
            store_confirmed(
                State,
                Apk,
                H2,
                Ciphertext,
                MAC,
                K2,
                Ck2,
                Payload
            );
        error ->
            error
    end.

store_confirmed(State, Apk, H2, Ciphertext, MAC, K2, Ck2, Payload) ->
    case decode_blocks(Payload) of
        {ok, [{router_info, _Flag, _RI} | _] = Blocks} ->
            Keys = data_keys(Ck2),
            State2 = State#{
                ck => Ck2,
                h => i2p_crypto:mixhash(H2, <<Ciphertext/binary, MAC/binary>>),
                k => K2
            },
            {ok, #{static_key => Apk, blocks => Blocks, keys => Keys}, State2};
        {ok, _NotRouterInfoFirst} ->
            error;
        error ->
            error
    end.

%%%%%%%%% %%% TokenRequest / Retry %%%%%%%

-doc """
Alice sends TokenRequest (type 10) when she has no valid token. Symmetric
crypto only — the payload is AEAD-encrypted under Bob's introduction key
with the header as associated data.

Input: Bob's introduction key; the random packet number; Alice's chosen
connection IDs; payload blocks (DateTime required).
Output: the sendable datagram.
""".
-spec encode_token_request(
    i2p_crypto:key(),
    non_neg_integer(),
    conn_id(),
    conn_id(),
    [block()]
) -> {ok, binary()}.
encode_token_request(Bik, PktNum, DstConnId, SrcConnId, Blocks) ->
    encode_symmetric(
        Bik,
        PktNum,
        long_header(DstConnId, PktNum, ?TYPE_TOKEN_REQUEST, SrcConnId, 0),
        Blocks
    ).

-doc """
Bob decodes a TokenRequest.

Input: Bob's introduction key and the received datagram.
Output: `{ok, Info}` with `src_conn_id`, `dst_conn_id`, `pkt_num` and
`blocks`; `error` otherwise.
""".
-spec decode_token_request(i2p_crypto:key(), datagram()) ->
    {ok, #{
        src_conn_id := conn_id(),
        dst_conn_id := conn_id(),
        pkt_num := non_neg_integer(),
        token := token(),
        blocks := [block()]
    }}
    | error.
decode_token_request(Bik, Packet) ->
    decode_symmetric(Bik, ?TYPE_TOKEN_REQUEST, Packet).

-doc """
Bob sends Retry (type 9), granting `Token` for a follow-up SessionRequest —
or zero with a Termination block to reject.

Input: Bob's introduction key; the random packet number; the connection IDs
mirrored from the request; the token; payload blocks (DateTime + Address,
optionally Termination).
Output: the sendable datagram.
""".
-spec encode_retry(
    i2p_crypto:key(),
    non_neg_integer(),
    conn_id(),
    conn_id(),
    token(),
    [block()]
) -> {ok, binary()}.
encode_retry(Bik, PktNum, DstConnId, SrcConnId, Tok, Blocks) ->
    encode_symmetric(
        Bik,
        PktNum,
        long_header(DstConnId, PktNum, ?TYPE_RETRY, SrcConnId, Tok),
        Blocks
    ).

-doc """
Alice decodes a Retry: `{ok, Info}` carrying the granted `token`, mirrored
connection IDs, `pkt_num` and `blocks`; `error` on anything else.
""".
-spec decode_retry(i2p_crypto:key(), binary()) ->
    {ok, #{
        src_conn_id := conn_id(),
        dst_conn_id := conn_id(),
        token := token(),
        pkt_num := non_neg_integer(),
        blocks := [block()]
    }}
    | error.
decode_retry(Bik, Packet) ->
    decode_symmetric(Bik, ?TYPE_RETRY, Packet).

-doc """
Send an out-of-session PeerTest message (type 7, long header).

Messages 5, 6 and 7 of the Alice/Bob/Charlie peer test travel *outside* any
established session, addressed directly to a router's intro key. `Bik` is the
message recipient's introduction key (Alice's for Charlie->Alice messages 5/7,
Charlie's for message 6). The payload is a single PeerTest block (block 10),
AEAD-encrypted under `Bik` with the long header as associated data — the same
symmetric framing as `f:encode_retry/6`.

Input: the recipient introduction key; random packet number; destination and
source connection IDs (these are derived from the peer-test nonce, see the
PeerTest process); the PeerTest payload blocks.
Output: the sendable datagram.
""".
-spec encode_peertest(
    i2p_crypto:key(),
    non_neg_integer(),
    conn_id(),
    conn_id(),
    [block()]
) -> {ok, binary()}.
encode_peertest(Bik, PktNum, DstConnId, SrcConnId, Blocks) ->
    encode_symmetric(
        Bik,
        PktNum,
        long_header(DstConnId, PktNum, ?TYPE_PEER_TEST, SrcConnId, 0),
        Blocks
    ).

-doc """
Decode an out-of-session PeerTest message (type 7).

Input: the recipient introduction key and the received datagram.
Output: `{ok, Info}` with `src_conn_id`, `dst_conn_id`, `pkt_num` and
`blocks`; `error` on anything else.
""".
-spec decode_peertest(i2p_crypto:key(), datagram()) ->
    {ok, #{
        src_conn_id := conn_id(),
        dst_conn_id := conn_id(),
        pkt_num := non_neg_integer(),
        token := token(),
        blocks := [block()]
    }}
    | error.
decode_peertest(Bik, Packet) ->
    decode_symmetric(Bik, ?TYPE_PEER_TEST, Packet).

-doc """
Encode an out-of-session HolePunch message (type 11).

Charlie sends this to Alice in response to a Relay Intro, to open a path for
her SessionRequest. Like PeerTest it wraps its payload blocks in a symmetric
long-header datagram under the recipient's introduction key; the payload is
a DateTime block, an Address block, Charlie's RelayResponse (block 8), and
optional padding.

Input: the recipient (Alice's) introduction key; random packet number;
destination and source connection IDs (derived from the relay nonce, see
`m:i2p_relay`); the HolePunch payload blocks.
Output: the sendable datagram.
""".
-spec encode_holepunch(
    i2p_crypto:key(),
    non_neg_integer(),
    conn_id(),
    conn_id(),
    [block()]
) -> {ok, binary()}.
encode_holepunch(Bik, PktNum, DstConnId, SrcConnId, Blocks) ->
    encode_symmetric(
        Bik,
        PktNum,
        long_header(DstConnId, PktNum, ?TYPE_HOLE_PUNCH, SrcConnId, 0),
        Blocks
    ).

-doc """
Decode an out-of-session HolePunch message (type 11).

Input: the recipient introduction key and the received datagram.
Output: `{ok, Info}` with `src_conn_id`, `dst_conn_id`, `pkt_num` and
`blocks`; `error` on anything else.
""".
-spec decode_holepunch(i2p_crypto:key(), datagram()) ->
    {ok, #{
        src_conn_id := conn_id(),
        dst_conn_id := conn_id(),
        pkt_num := non_neg_integer(),
        token := token(),
        blocks := [block()]
    }}
    | error.
decode_holepunch(Bik, Packet) ->
    decode_symmetric(Bik, ?TYPE_HOLE_PUNCH, Packet).

%% AEAD-seal a symmetric datagram (TokenRequest/Retry): key is Bob's intro
%% key, nonce is the random packet number, AD the plaintext long header.
encode_symmetric(Bik, PktNum, Header, Blocks) ->
    Payload = ensure_min_payload(encode_blocks(Blocks)),
    {CT, MAC} = i2p_crypto:chacha20_poly1305_encrypt(
        Bik,
        nonce(PktNum),
        Payload,
        Header
    ),
    {ok, seal_long(<<Header/binary, CT/binary, MAC/binary>>, Bik, Bik)}.

decode_symmetric(Bik, ExpectedType, Packet) ->
    case open_long(Packet, Bik, Bik) of
        {ok,
            <<DstConnId:64, PktNum:32, ExpectedType:8, ?VERSION:8, ?NET_ID:8, 0:8, SrcConnId:64,
                Tok:64, CTWithMac/binary>>} ->
            Header =
                <<DstConnId:64, PktNum:32, ExpectedType:8, ?VERSION:8, ?NET_ID:8, 0:8, SrcConnId:64,
                    Tok:64>>,
            finish_symmetric(
                Bik,
                Header,
                PktNum,
                Tok,
                SrcConnId,
                DstConnId,
                CTWithMac
            );
        _Other ->
            error
    end.

%% A datagram has to carry a full Poly1305 tag, and this is the one place that
%% fact is enforced. Without the check a datagram between ?MIN_PACKET and 47 bytes
%% leaves fewer than 16 bytes after the 32-byte long header, `Sz` goes negative,
%% and the match raises -- which killed the SSU2 socket owner outright, because
%% this runs on attacker-reachable input with only the public introduction key in
%% the attacker's way. See #YNBT5ZD. A library decides no process's fate: it
%% answers `error`, and the caller decides what that means.
finish_symmetric(_Bik, _Header, _PktNum, _Tok, _SrcConnId, _DstConnId, CTWithMac) when
    byte_size(CTWithMac) < 16
->
    error;
finish_symmetric(Bik, Header, PktNum, Tok, SrcConnId, DstConnId, CTWithMac) ->
    Sz = byte_size(CTWithMac) - 16,
    <<CT:Sz/binary, MAC:16/binary>> = CTWithMac,
    case
        i2p_crypto:chacha20_poly1305_decrypt(
            Bik,
            nonce(PktNum),
            CT,
            MAC,
            Header
        )
    of
        Payload when is_binary(Payload) ->
            case decode_blocks(Payload) of
                {ok, Blocks} ->
                    {ok, #{
                        src_conn_id => SrcConnId,
                        dst_conn_id => DstConnId,
                        pkt_num => PktNum,
                        token => Tok,
                        blocks => Blocks
                    }};
                error ->
                    error
            end;
        error ->
            error
    end.

%%%%%%%%% %%% Data phase %%%%%%%

-doc """
Noise `split()`: derive the data phase keys from the final chaining key.

Input: `Ck` — the chaining key after SessionConfirmed.
Output: per-direction cipher keys `k_ab`/`k_ba` and header protection keys
`kh2_ab`/`kh2_ba`, each direction expanded through
`HKDF(k_dir, ZEROLEN, "HKDFSSU2DataKeys", 64)` as the specification
requires.
""".
-spec data_keys(i2p_crypto:chaining_key()) -> data_keys().
data_keys(Ck) ->
    <<Kab:32/binary, Kba:32/binary>> = i2p_crypto:hkdf_sha256(Ck, <<>>, <<>>, 64),
    <<KDataAb:32/binary, KH2Ab:32/binary>> =
        i2p_crypto:hkdf_sha256(Kab, <<>>, <<"HKDFSSU2DataKeys">>, 64),
    <<KDataBa:32/binary, KH2Ba:32/binary>> =
        i2p_crypto:hkdf_sha256(Kba, <<>>, <<"HKDFSSU2DataKeys">>, 64),
    #{k_ab => KDataAb, kh2_ab => KH2Ab, k_ba => KDataBa, kh2_ba => KH2Ba}.

-doc """
Encode a data-phase datagram (type 6).

Input: keys from `f:data_keys/1`; the sender's direction; the remote peer's
introduction key (header mask 1 uses the *receiver's* intro key); the
packet number (also the AEAD nonce counter); the destination connection ID;
payload blocks.
Output: `{ok, Datagram}`.
""".
-spec encode_data(
    data_keys(),
    direction(),
    i2p_crypto:key(),
    non_neg_integer(),
    conn_id(),
    [block()]
) -> {ok, binary()}.
encode_data(Keys, Dir, RemoteIntroKey, PktNum, DstConnId, Blocks) ->
    Header = short_header_data(DstConnId, PktNum, 0),
    {Key, KH2Own} = dir_keys(Keys, Dir),
    Payload = ensure_min_payload(encode_blocks(Blocks)),
    {CT, MAC} = i2p_crypto:chacha20_poly1305_encrypt(
        Key,
        nonce(PktNum),
        Payload,
        Header
    ),
    Plain = <<Header/binary, CT/binary, MAC/binary>>,
    {ok, seal_data(Plain, RemoteIntroKey, KH2Own)}.

%% Direction key tuple: {cipher key, own header protection key}.
dir_keys(#{k_ab := Kab, kh2_ab := KH2Ab}, ab) ->
    {Kab, KH2Ab};
dir_keys(#{k_ba := Kba, kh2_ba := KH2Ba}, ba) ->
    {Kba, KH2Ba}.

%% Mask a finished data datagram: bytes 0..7 with the receiver's intro key,
%% bytes 8..15 with the sender's data-phase header protection key.
seal_data(Packet, ReceiverIntroKey, KH2Own) ->
    Len = byte_size(Packet),
    M1 = header_mask(ReceiverIntroKey, binary:part(Packet, Len - 24, 12)),
    M2 = header_mask(KH2Own, binary:part(Packet, Len - 12, 12)),
    <<First:8/binary, Second:8/binary, Rest/binary>> = Packet,
    <<(crypto:exor(First, M1))/binary, (crypto:exor(Second, M2))/binary, Rest/binary>>.

%% Inverse of f:seal_data/3 on the receive side.
open_data(Packet, OwnIntroKey, KH2PeerDir) ->
    Len = byte_size(Packet),
    M1 = header_mask(OwnIntroKey, binary:part(Packet, Len - 24, 12)),
    M2 = header_mask(KH2PeerDir, binary:part(Packet, Len - 12, 12)),
    <<First:8/binary, Second:8/binary, Rest/binary>> = Packet,
    <<(crypto:exor(First, M1))/binary, (crypto:exor(Second, M2))/binary, Rest/binary>>.

-doc """
Decode a data-phase datagram.

Input: keys from `f:data_keys/1`; the receiving direction (the sender's is
the opposite); our own introduction key; the received datagram.
Output: `{ok, Info}` with `pkt_num`, the immediate-ack flag and decoded
`blocks`; `error` on AEAD failure or a non-Data message. Replay tracking of
packet numbers is the session layer's job.
""".
-spec decode_data(data_keys(), direction(), i2p_crypto:key(), binary()) ->
    {ok, #{
        pkt_num := non_neg_integer(),
        immediate_ack := boolean(),
        blocks := [block()]
    }}
    | error.
%% On receive, `RecvDir` names the direction of the packets arriving: its
%% cipher key opens the payload and its header protection key undoes mask 2
%% applied by the sender.
decode_data(Keys, RecvDir, OwnIntroKey, Packet) ->
    {KRecv, KH2Sender} = dir_keys(Keys, RecvDir),
    case open_data(Packet, OwnIntroKey, KH2Sender) of
        <<Header:16/binary, CTWithMac/binary>> when
            byte_size(CTWithMac) >=
                16 + ?MIN_PAYLOAD
        ->
            finish_data(KRecv, Header, CTWithMac);
        _TooShort ->
            error
    end.

finish_data(KRecv, Header, CTWithMac) ->
    %% A Data-phase header is fixed-width: destination connection id, packet
    %% number, type, flags, and a zero header-extension length word. A
    %% datagram that fails this shape (wrong headermask or a corrupt frame)
    %% cannot be a valid Data packet — drop it instead of crashing the
    %% session; `data_packet/2` treats `error` as a silent drop.
    case Header of
        <<_DstConnId:64, PktNum:32, Type:8, Flags:8, 0:16>> when Type =:= ?TYPE_DATA ->
            Sz = byte_size(CTWithMac) - 16,
            <<CT:Sz/binary, MAC:16/binary>> = CTWithMac,
            case
                i2p_crypto:chacha20_poly1305_decrypt(
                    KRecv,
                    nonce(PktNum),
                    CT,
                    MAC,
                    Header
                )
            of
                Payload when is_binary(Payload) ->
                    case decode_blocks(Payload) of
                        {ok, Blocks} ->
                            {ok, #{
                                pkt_num => PktNum,
                                immediate_ack => (Flags band 1) == 1,
                                blocks => Blocks
                            }};
                        error ->
                            error
                    end;
                error ->
                    error
            end;
        _ ->
            error
    end.
