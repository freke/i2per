-module(i2p_streaming).

-moduledoc """
I2P streaming protocol packet codec: the TCP-like reliable transport
carried as the payload of end-to-end garlic Data cloves.

A streaming packet is framed entirely by the layers around it — there is no
length field — so one garlic Data clove carries exactly one packet. Wire
format ([streaming spec](https://geti2p.net/en/docs/spec/streaming)):

```
sendStreamId     4 bytes BE
receiveStreamId  4 bytes BE
sequenceNum      4 bytes BE (0 without SYNCHRONIZE = plain ACK)
ackThrough       4 bytes BE (highest in-order sequence ACKed)
nackCount        1 byte  (8 on SYNCHRONIZE: replay-prevention hash form)
nacks            nackCount × 4 bytes BE
resendDelay      1 byte  (seconds; advisory)
flags            2 bytes BE
optionSize       2 bytes BE
optionData       optionSize bytes, in option order: delay ‖ from ‖
                 maxPacketSize ‖ (offlineSignature) ‖ signature
payload          remaining bytes
```

Minimum header size is 22 bytes. Options are emitted iff their flag bit is
set; the signature option covers the entire packet with the signature space
zeroed, so signing encodes once with zeros and again with the real value
(`f:signed/2`).

Only standard X25519 + Ed25519 Destinations (391 bytes) are supported in the
FROM option, matching the project's ECIES-only stance. The
OFFLINE_SIGNATURE option (transient keys) is rejected on decode.

Replay prevention (protocol ≥ 0.9.58, required for interop): a SYNCHRONIZE
sets `nackCount = 8` and carries the recipient's 32-byte destination hash in
the NACKs field — see `f:syn_replay_nacks/1` / `f:replay_hash/1`.

## Usage

```erlang
%% Initiator SYN, signed, carrying Bob's hash for replay prevention
P0 = i2p_streaming:new(0, MyStreamId, 0, 0),
P1 = i2p_streaming:with_flags(P0, ?FLAG_SYNCHRONIZE bor ?FLAG_FROM_INCLUDED
                                  bor ?FLAG_MAX_PACKET_SIZE_INCLUDED
                                  bor ?FLAG_NO_ACK),
Syn = i2p_streaming:signed(
         i2p_streaming:with_nacks(
             i2p_streaming:with_max_packet_size(
                 i2p_streaming:with_from(P1, DestBin),
                 1730),
             i2p_streaming:syn_replay_nacks(BobHash)),
         SignSeed),

%% Receiver side
{ok, Pkt} = i2p_streaming:decode(Syn),
true = i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize()),
{ok, BobHash} = i2p_streaming:replay_hash(Pkt),
true = i2p_streaming:verify(Pkt, SigningPubKey),
Payload = i2p_streaming:payload(Pkt).
```
""".
-export([
    new/4,
    with_send_id/2,
    with_recv_id/2,
    with_seq/2,
    with_seq_num/2,
    with_ack_through/2,
    with_nacks/2,
    with_resend_delay/2,
    with_flags/2,
    with_from/2,
    with_delay_ms/2,
    with_max_packet_size/2,
    with_signature/2,
    with_payload/2,
    with_binary/2,
    with_sig_offset/2,
    has_flag/2,
    encode/1,
    signed/2,
    decode/1,
    verify/2,
    syn_replay_nacks/1,
    replay_hash/1,
    send_id/1,
    recv_id/1,
    seq_num/1,
    ack_through/1,
    nacks/1,
    resend_delay/1,
    flags/1,
    from/1,
    delay_ms/1,
    max_packet_size/1,
    signature/1,
    payload/1,
    binary/1,
    sig_offset/1,
    seq/1,
    flag_synchronize/0,
    flag_close/0,
    flag_reset/0,
    flag_signature_included/0,
    flag_signature_requested/0,
    flag_from_included/0,
    flag_delay_requested/0,
    flag_max_packet_size_included/0,
    flag_profile_interactive/0,
    flag_echo/0,
    flag_no_ack/0
]).
-export_type([packet/0]).

%% Flag bits (bit 15 is MSB; bit N has value 2^N).
-define(FLAG_SYNCHRONIZE, 16#0001).
-define(FLAG_CLOSE, 16#0002).
-define(FLAG_RESET, 16#0004).
-define(FLAG_SIGNATURE_INCLUDED, 16#0008).
-define(FLAG_SIGNATURE_REQUESTED, 16#0010).
-define(FLAG_FROM_INCLUDED, 16#0020).
-define(FLAG_DELAY_REQUESTED, 16#0040).
-define(FLAG_MAX_PACKET_SIZE_INCLUDED, 16#0080).
-define(FLAG_PROFILE_INTERACTIVE, 16#0100).
-define(FLAG_ECHO, 16#0200).
-define(FLAG_NO_ACK, 16#0400).
-define(FLAG_OFFLINE_SIGNATURE, 16#0800).

%% Minimum header: four 4-byte stream/seq fields + nackCount + resendDelay +
%% flags + optionSize.
-define(MIN_HEADER_SIZE, 22).
%% Standard Destination: X25519 public key + padding + Ed25519 signing key +
%% 4-byte key certificate.
-define(DEST_SIZE, 391).
-define(SIG_LEN, 64).
-define(MAX_NACKS, 255).
-define(REPLAY_NACK_COUNT, 8).

-doc """
A decoded or to-be-encoded streaming packet.

Header fields are required; option fields are read and written only when the
matching flag bit is set (`f:has_flag/2`). On `f:decode/1` the original wire
bytes ride along under `binary` together with the `sig_offset`, letting
`f:verify/2` re-zero the signature space without re-parsing.
""".
-type packet() :: #{
    send_id := 0..16#FFFFFFFF,
    recv_id := 0..16#FFFFFFFF,
    seq := 0..16#FFFFFFFF,
    ack_through := 0..16#FFFFFFFF,
    nacks => [0..16#FFFFFFFF],
    resend_delay => 0..255,
    flags => 0..16#FFFF,
    delay_ms => 0..16#FFFF,
    from => binary(),
    max_packet_size => 0..16#FFFF,
    signature => i2p_crypto:ed25519_signature(),
    payload => binary(),
    binary => binary(),
    sig_offset => non_neg_integer()
}.

%%%%%%% %%% Constructors %%%%%%%

-doc """
Build a base packet with empty NACKs, zero resend delay, no flags and no
payload; add option fields and flags on the returned map as needed.
""".
-spec new(SendId, RecvId, Seq, AckThrough) -> packet() when
    SendId :: 0..16#FFFFFFFF,
    RecvId :: 0..16#FFFFFFFF,
    Seq :: 0..16#FFFFFFFF,
    AckThrough :: 0..16#FFFFFFFF.
new(SendId, RecvId, Seq, AckThrough) ->
    #{
        send_id => SendId,
        recv_id => RecvId,
        seq => Seq,
        ack_through => AckThrough,
        nacks => [],
        resend_delay => 0,
        flags => 0,
        payload => <<>>
    }.

-doc """
Set flag bits on a packet, preserving the existing ones.

Input: `Packet` — the packet; `Bits` — flag bitmask to OR in.
Output: the updated packet.
""".
-spec with_flags(packet(), 0..16#FFFF) -> packet().
with_flags(Packet, Bits) ->
    Packet#{flags => (maps:get(flags, Packet, 0) bor Bits) band 16#FFFF}.

-doc "Set the sender's stream ID.".
-spec with_send_id(packet(), 0..16#FFFFFFFF) -> packet().
with_send_id(Packet, V) ->
    Packet#{send_id => V}.

-doc "Set the receiver's stream ID.".
-spec with_recv_id(packet(), 0..16#FFFFFFFF) -> packet().
with_recv_id(Packet, V) ->
    Packet#{recv_id => V}.

-doc "Set the sequence number.".
-spec with_seq(packet(), 0..16#FFFFFFFF) -> packet().
with_seq(Packet, V) ->
    Packet#{seq => V}.

-doc "See `f:with_seq/2`.".
-spec with_seq_num(packet(), 0..16#FFFFFFFF) -> packet().
with_seq_num(Packet, V) ->
    with_seq(Packet, V).

-doc "Set the acknowledged-through sequence number.".
-spec with_ack_through(packet(), 0..16#FFFFFFFF) -> packet().
with_ack_through(Packet, V) ->
    Packet#{ack_through => V}.

-doc "Set the NACK list.".
-spec with_nacks(packet(), [0..16#FFFFFFFF]) -> packet().
with_nacks(Packet, V) ->
    Packet#{nacks => V}.

-doc "Set the advised retransmission delay in seconds.".
-spec with_resend_delay(packet(), 0..255) -> packet().
with_resend_delay(Packet, V) ->
    Packet#{resend_delay => V}.

-doc "Set the FROM option destination.".
-spec with_from(packet(), binary()) -> packet().
with_from(Packet, V) ->
    Packet#{from => V}.

-doc "Set the delay value in milliseconds.".
-spec with_delay_ms(packet(), 0..16#FFFF) -> packet().
with_delay_ms(Packet, V) ->
    Packet#{delay_ms => V}.

-doc "Set the maximum packet size.".
-spec with_max_packet_size(packet(), 0..16#FFFF) -> packet().
with_max_packet_size(Packet, V) ->
    Packet#{max_packet_size => V}.

-doc "Set the signature option.".
-spec with_signature(packet(), i2p_crypto:ed25519_signature()) -> packet().
with_signature(Packet, V) ->
    Packet#{signature => V}.

-doc "Set the payload.".
-spec with_payload(packet(), binary()) -> packet().
with_payload(Packet, V) ->
    Packet#{payload => V}.

-doc "Set the raw wire bytes.".
-spec with_binary(packet(), binary()) -> packet().
with_binary(Packet, V) ->
    Packet#{binary => V}.

-doc "Set the signature offset.".
-spec with_sig_offset(packet(), non_neg_integer()) -> packet().
with_sig_offset(Packet, V) ->
    Packet#{sig_offset => V}.

-doc "Test whether a packet carries the flag bit `Flag`.".
-spec has_flag(packet(), 0..16#FFFF) -> boolean().
has_flag(Packet, Flag) ->
    maps:get(flags, Packet, 0) band Flag =/= 0.

%%%%%%% %%% Encoding %%%%%%%

-doc """
Encode a packet to its wire form.

Option fields are emitted iff their flag bit is set: `delay_ms` under
DELAY_REQUESTED, `from` under FROM_INCLUDED, `max_packet_size` under
MAX_PACKET_SIZE_INCLUDED, `signature` under SIGNATURE_INCLUDED — always in
spec option order (delay, from, maxPacketSize, signature).
""".
-spec encode(packet()) -> binary().
encode(Packet) ->
    #{send_id := SendId, recv_id := RecvId, seq := Seq, ack_through := AckThrough} =
        Packet,
    Nacks = maps:get(nacks, Packet, []),
    NC = length(Nacks),
    true = NC =< ?MAX_NACKS,
    NacksBin = <<<<N:32>> || N <- Nacks>>,
    OptData = encode_options(Packet),
    Header =
        <<
            SendId:32,
            RecvId:32,
            Seq:32,
            AckThrough:32,
            NC:8,
            NacksBin/binary,
            (maps:get(resend_delay, Packet, 0)):8,
            (maps:get(flags, Packet)):16,
            (byte_size(OptData)):16
        >>,
    <<Header/binary, OptData/binary, (maps:get(payload, Packet, <<>>))/binary>>.

%% Option data in spec order: DELAY_REQUESTED (1), FROM_INCLUDED (2),
%% MAX_PACKET_SIZE_INCLUDED (3), SIGNATURE_INCLUDED (5). OFFLINE_SIGNATURE
%% (4) is never emitted.
encode_options(Packet) ->
    Delay = enc_opt(
        maps:get(delay_ms, Packet, undefined),
        has_flag(Packet, ?FLAG_DELAY_REQUESTED)
    ),
    From = enc_opt(
        maps:get(from, Packet, undefined),
        has_flag(Packet, ?FLAG_FROM_INCLUDED)
    ),
    MaxPS = enc_opt(
        maps:get(max_packet_size, Packet, undefined),
        has_flag(Packet, ?FLAG_MAX_PACKET_SIZE_INCLUDED)
    ),
    Signature = enc_opt(
        maps:get(signature, Packet, undefined),
        has_flag(Packet, ?FLAG_SIGNATURE_INCLUDED)
    ),
    <<Delay/binary, From/binary, MaxPS/binary, Signature/binary>>.

enc_opt(_Value, false) ->
    <<>>;
enc_opt(Value, true) when is_binary(Value) ->
    Value;
enc_opt(Value, true) when is_integer(Value), Value >= 0, Value =< 16#FFFF ->
    <<Value:16>>.

-doc """
Sign a packet and return its final wire form.

Sets SIGNATURE_INCLUDED and computes the Ed25519 signature over the entire
encoded packet with the signature space zeroed, per spec.

Input: `Packet` — the packet; `Seed` — the sender Destination's Ed25519
signing seed.
Output: the signed wire bytes.
""".
-spec signed(packet(), i2p_crypto:ed25519_seed()) -> binary().
signed(Packet, Seed) ->
    P1 = with_flags(Packet, ?FLAG_SIGNATURE_INCLUDED),
    Unsigned = encode(P1#{signature => <<0:(?SIG_LEN * 8)>>}),
    Signature = i2p_crypto:ed25519_sign(Unsigned, Seed),
    encode(P1#{signature => Signature}).

%%%%%%% %%% Decoding %%%%%%%

-doc """
Decode a wire packet.

Output: `{ok, Packet}` with the raw bytes and signature offset attached, or
`{error, Reason}` for truncation, out-of-bounds NACK/option regions, option
data left over after the flagged options were parsed, or the unsupported
OFFLINE_SIGNATURE option.
""".
-spec decode(binary()) -> {ok, packet()} | {error, term()}.
decode(<<SendId:32, RecvId:32, Seq:32, AckThrough:32, NC:8, Rest0/binary>> = Bin) when
    NC =< ?MAX_NACKS, byte_size(Rest0) >= NC * 4 + 5
->
    <<NacksBin:(NC * 4)/binary, ResendDelay:8, Flags:16, OptSize:16, Rest1/binary>> = Rest0,
    case Rest1 of
        <<OptData:OptSize/binary, Payload/binary>> ->
            Nacks = [N || <<N:32>> <= NacksBin],
            Acc0 = #{
                send_id => SendId,
                recv_id => RecvId,
                seq => Seq,
                ack_through => AckThrough,
                nacks => Nacks,
                resend_delay => ResendDelay,
                flags => Flags,
                payload => Payload,
                binary => Bin
            },
            parse_options(
                option_steps(),
                Flags,
                OptData,
                0,
                ?MIN_HEADER_SIZE + NC * 4,
                OptSize,
                Acc0
            );
        _ ->
            {error, truncated_options}
    end;
decode(Bin) when is_binary(Bin) ->
    {error, truncated_header};
decode(_Bin) ->
    {error, not_binary}.

%% Option parsers in spec wire order. Each takes the unconsumed option data
%% and returns {ok, FieldKey, Value, Rest} or error.
option_steps() ->
    [
        {?FLAG_DELAY_REQUESTED, fun parse_delay/1, delay_ms},
        {?FLAG_FROM_INCLUDED, fun parse_from/1, from},
        {?FLAG_MAX_PACKET_SIZE_INCLUDED, fun parse_max_packet_size/1, max_packet_size},
        {?FLAG_OFFLINE_SIGNATURE, fun parse_offline_signature/1, offline_sig},
        {?FLAG_SIGNATURE_INCLUDED, fun parse_signature/1, signature}
    ].

parse_options([], _Flags, _OptData, Consumed, _SigBase, OptSize, Acc) when
    Consumed =:= OptSize
->
    {ok, Acc};
parse_options([], _Flags, _OptData, Consumed, _SigBase, OptSize, _Acc) ->
    {error, {option_size_mismatch, Consumed, OptSize}};
parse_options(
    [{Flag, Parser, Key} | Steps],
    Flags,
    OptData,
    Consumed,
    SigBase,
    OptSize,
    Acc
) when Flags band Flag =/= 0 ->
    case Parser(OptData) of
        {ok, Value, Rest} ->
            Eaten = byte_size(OptData) - byte_size(Rest),
            Acc1 =
                case Key of
                    signature ->
                        Acc#{signature => Value, sig_offset => SigBase + Consumed};
                    _ ->
                        Acc#{Key => Value}
                end,
            parse_options(
                Steps,
                Flags,
                Rest,
                Consumed + Eaten,
                SigBase,
                OptSize,
                Acc1
            );
        error ->
            {error, malformed_options}
    end;
parse_options([_Step | Steps], Flags, OptData, Consumed, SigBase, OptSize, Acc) ->
    parse_options(Steps, Flags, OptData, Consumed, SigBase, OptSize, Acc).

parse_delay(<<D:16, Rest/binary>>) -> {ok, D, Rest};
parse_delay(_) -> error.

parse_from(<<From:?DEST_SIZE/binary, Rest/binary>>) -> {ok, From, Rest};
parse_from(_) -> error.

parse_max_packet_size(<<M:16, Rest/binary>>) -> {ok, M, Rest};
parse_max_packet_size(_) -> error.

parse_offline_signature(_OptData) ->
    error.

parse_signature(<<Sig:?SIG_LEN/binary, Rest/binary>>) ->
    {ok, Sig, Rest};
parse_signature(_) ->
    error.

%%%%%%% %%% Verification %%%%%%%

-doc """
Verify a decoded packet's Ed25519 signature.

The signature covers the entire wire form with the signature space zeroed;
this re-zeros the recorded region of the stored bytes and verifies against
the public key.

Input: `Packet` — a packet returned by `f:decode/1`; `PubKey` — the signing
public key of the FROM destination (`i2p_keys:signing_key/1`).
Output: `true` when the signature is valid.
""".
-spec verify(packet(), i2p_crypto:ed25519_public_key()) -> boolean().
verify(#{binary := Bin, sig_offset := Off, signature := Sig}, PubKey) when
    is_binary(Bin), is_integer(Off), byte_size(Sig) =:= ?SIG_LEN
->
    <<Pre:Off/binary, _:(?SIG_LEN)/binary, Post/binary>> = Bin,
    Zeroed = <<Pre/binary, 0:(?SIG_LEN * 8), Post/binary>>,
    i2p_crypto:ed25519_verify(Zeroed, Sig, PubKey);
verify(_Packet, _PubKey) ->
    false.

%%%%%%% %%% Replay prevention %%%%%%%

-doc """
Build the SYNCHRONIZE replay-prevention NACKs for a recipient.

Protocol ≥ 0.9.58: the SYN sets the NACK count to 8 and carries the
recipient's destination hash in the NACKs field.

Input: `DestHash` — the recipient's 32-byte destination hash.
Output: eight 32-bit integers whose concatenation is `DestHash`.
""".
-spec syn_replay_nacks(i2p_crypto:hash()) -> [0..16#FFFFFFFF].
syn_replay_nacks(DestHash) when byte_size(DestHash) =:= ?REPLAY_NACK_COUNT * 4 ->
    [N || <<N:32>> <= DestHash].

-doc """
Extract a SYNCHRONIZE packet's replay-prevention destination hash.

Output: `{ok, DestHash}` when the packet carries exactly eight NACKs (the
replay form); `error` otherwise (a plain pre-0.9.58 SYN has none).
""".
-spec replay_hash(packet()) -> {ok, i2p_crypto:hash()} | error.
replay_hash(Packet) ->
    case maps:get(nacks, Packet, []) of
        Nacks when length(Nacks) =:= ?REPLAY_NACK_COUNT ->
            {ok, <<<<N:32>> || N <- Nacks>>};
        _ ->
            error
    end.

%%%%%%% %%% Accessors %%%%%%%

-doc "The sender's stream ID (0 until the peer's SYN reply assigns one).".
-spec send_id(packet()) -> 0..16#FFFFFFFF.
send_id(Packet) -> maps:get(send_id, Packet).

-doc "The receiver's stream ID as known by the sender.".
-spec recv_id(packet()) -> 0..16#FFFFFFFF.
recv_id(Packet) -> maps:get(recv_id, Packet).

-doc "Sequence number of this packet.".
-spec seq_num(packet()) -> 0..16#FFFFFFFF.
seq_num(Packet) -> maps:get(seq, Packet).

-doc "Highest in-order sequence number being acknowledged.".
-spec ack_through(packet()) -> 0..16#FFFFFFFF.
ack_through(Packet) -> maps:get(ack_through, Packet).

-doc "NACKed sequence numbers (or the SYN replay-prevention words).".
-spec nacks(packet()) -> [0..16#FFFFFFFF].
nacks(Packet) -> maps:get(nacks, Packet, []).

-doc "Advised retransmission delay in seconds.".
-spec resend_delay(packet()) -> 0..255.
resend_delay(Packet) -> maps:get(resend_delay, Packet, 0).

-doc "Raw 16-bit flags bitmask.".
-spec flags(packet()) -> 0..16#FFFF.
flags(Packet) -> maps:get(flags, Packet, 0).

-doc "FROM option: the sender's 391-byte standard Destination, if present.".
-spec from(packet()) -> binary() | undefined.
from(Packet) -> maps:get(from, Packet, undefined).

-doc "DELAY_REQUESTED option value in milliseconds, if present.".
-spec delay_ms(packet()) -> 0..16#FFFF | undefined.
delay_ms(Packet) -> maps:get(delay_ms, Packet, undefined).

-doc """
MAX_PACKET_SIZE_INCLUDED option value, if present.

The packet codec permits this option to be absent. `m:i2p_stream_conn` uses
I2P Java-compatible peer-offer handling: absence means a 1730-byte peer limit,
a positive value below 512 is raised to 512, and an explicit zero is rejected
because it cannot carry payload.
""".
-spec max_packet_size(packet()) -> 0..16#FFFF | undefined.
max_packet_size(Packet) -> maps:get(max_packet_size, Packet, undefined).

-doc "SIGNATURE_INCLUDED option value, if present.".
-spec signature(packet()) -> i2p_crypto:ed25519_signature() | undefined.
signature(Packet) -> maps:get(signature, Packet, undefined).

-doc "The payload bytes following the options region.".
-spec payload(packet()) -> binary().
payload(Packet) -> maps:get(payload, Packet, <<>>).

-doc "The raw wire bytes attached to a decoded packet.".
-spec binary(packet()) -> binary().
binary(Packet) -> maps:get(binary, Packet, <<>>).

-doc "The offset of the signature region in the raw wire bytes.".
-spec sig_offset(packet()) -> non_neg_integer().
sig_offset(Packet) -> maps:get(sig_offset, Packet, 0).

-doc "See `f:seq_num/1`.".
-spec seq(packet()) -> 0..16#FFFFFFFF.
seq(Packet) -> seq_num(Packet).

%%%%%%% %%% Flag constants %%%%%%%

-doc "Flag bit 0: SYNCHRONIZE (TCP SYN).".
-spec flag_synchronize() -> 1.
flag_synchronize() -> ?FLAG_SYNCHRONIZE.

-doc "Flag bit 1: CLOSE (TCP FIN).".
-spec flag_close() -> 2.
flag_close() -> ?FLAG_CLOSE.

-doc "Flag bit 2: RESET (abnormal close).".
-spec flag_reset() -> 4.
flag_reset() -> ?FLAG_RESET.

-doc "Flag bit 3: SIGNATURE_INCLUDED.".
-spec flag_signature_included() -> 8.
flag_signature_included() -> ?FLAG_SIGNATURE_INCLUDED.

-doc "Flag bit 4: SIGNATURE_REQUESTED (unused).".
-spec flag_signature_requested() -> 16.
flag_signature_requested() -> ?FLAG_SIGNATURE_REQUESTED.

-doc "Flag bit 5: FROM_INCLUDED.".
-spec flag_from_included() -> 32.
flag_from_included() -> ?FLAG_FROM_INCLUDED.

-doc "Flag bit 6: DELAY_REQUESTED.".
-spec flag_delay_requested() -> 64.
flag_delay_requested() -> ?FLAG_DELAY_REQUESTED.

-doc "Flag bit 7: MAX_PACKET_SIZE_INCLUDED.".
-spec flag_max_packet_size_included() -> 128.
flag_max_packet_size_included() -> ?FLAG_MAX_PACKET_SIZE_INCLUDED.

-doc "Flag bit 8: PROFILE_INTERACTIVE (ignored).".
-spec flag_profile_interactive() -> 256.
flag_profile_interactive() -> ?FLAG_PROFILE_INTERACTIVE.

-doc "Flag bit 9: ECHO (ping/pong; unused here).".
-spec flag_echo() -> 512.
flag_echo() -> ?FLAG_ECHO.

-doc "Flag bit 10: NO_ACK (set on the initial SYN).".
-spec flag_no_ack() -> 1024.
flag_no_ack() -> ?FLAG_NO_ACK.
