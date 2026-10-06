-module(i2p_stream).

-moduledoc """
A stream reassembler for NTCP2 data-phase frames over TCP.

TCP is a byte stream, not a message stream: a frame may arrive split across
several reads, and several frames may arrive in one read. This module is the
receive side of the data phase — it appends incoming bytes to a buffer, cuts
complete frames by their SipHash-obfuscated 2-byte length, and decrypts and
authenticates each one, threading the SipHash IV and message counter.

`t:stream/0` is opaque and carries everything the cut needs (cipher key,
SipHash state, current message number, residual buffer), so the owning process
holds one value per direction and never re-derives frame boundaries itself.

## The message number, and why receive has to cross 2^16 too

The `msg` field is the inbound half of the connection's per-direction counter,
and it is **64 bits wide** — the whole 8-byte low half of the counter nonce, so
`0..2^64 - 2`. See `m:i2p_crypto:es_nonce/1` for the bound and `m:i2p_ntcp2_conn`
for the send half that has to agree with it.

It is worth being explicit that this is a separate obligation rather than a
mirror of the send side, because they are the same defect seen twice. A session
that *receives* 65536 frames used to fail exactly as one that sent 65536 did, so
a fix applied only to the sender would have left half the bug live — and a test
written only against the send path would have stayed green. The receive path is
therefore covered by the same case as the send path:
`i2p_ntcp2_conn_SUITE`'s `more_than_65536_frames_survive_in_each_direction/1`
floods a live pair past the boundary in both directions at once.

## Usage

```erlang
%% Receive direction: key + SipHash state from the completed handshake.
#{k_ab := KAb, sip_ab := SipAb} = i2p_ntcp2:data_phase_keys(State),
S0 = i2p_stream:new(KAb, SipAb),

%% Every socket read feeds the stream; complete, authenticated payloads come out.
{ok, S1, [Payload]} = i2p_stream:push(S0, <<2 bytes...>>),
{ok, S2, []} = i2p_stream:push(S1, <<...>>),

%% A frame is never left half-consumed: a truncated frame just waits.
{ok, S3, []} = i2p_stream:push(S2, <<2 bytes of a 100-byte frame>>),
```

A malformed length or a MAC failure returns the atom `error` — the caller owns
the process and converts that into a crash, per the project's process
philosophy.
""".

-export([
    new/2,
    push/2,
    size/1
]).
-export_type([stream/0]).

-doc """
A receive-direction data-phase stream: the cipher `key`, the current SipHash
state (`sip`), the residual receive `buf` (bytes that do not yet form a full
frame) and the zero-based message `msg` counter used for the AEAD nonce.
""".
-opaque stream() :: #{
    key := i2p_framing:frame_key(),
    sip := i2p_framing:sip_state(),
    buf := binary(),
    msg := non_neg_integer()
}.

-doc """
Create a fresh stream for one receive direction.

Input: `Key` — the direction cipher key (`k_ab` or `k_ba`); `Sip` — the matching
SipHash state (`sip_ab` or `sip_ba`).
Output: the initial `t:stream/0`.
""".
-spec new(i2p_framing:frame_key(), i2p_framing:sip_state()) -> stream().
new(Key, Sip) ->
    #{key => Key, sip => Sip, buf => <<>>, msg => 0}.

-doc """
Feed bytes into the stream and extract complete, decrypted frames.

Input: `Stream` — the current `t:stream/0`; `Data` — bytes just read from the
socket. Partial frames are buffered until complete; multiple frames in one read
are all cut and returned in order.
Output: `{ok, Stream', Payloads}` with the decrypted payloads in wire order, or
the atom `error` on an out-of-range obfuscated length or a frame MAC failure
(the caller crashes the connection on this).
""".
-spec push(stream(), binary()) -> {ok, stream(), [binary()]} | error.
push(Stream, Data) ->
    #{buf := Buf} = Stream,
    cut(Stream#{buf => <<Buf/binary, Data/binary>>}, []).

-doc "The number of buffered but not-yet-complete bytes.".
-spec size(stream()) -> non_neg_integer().
size(#{buf := Buf}) ->
    byte_size(Buf).

%%%%%%% %%% Internal %%%%%%%

%% Cut frames out of the head of the buffer until fewer than one frame remain.
cut(#{buf := <<>>} = Stream, Acc) ->
    {ok, Stream, lists:reverse(Acc)};
cut(#{buf := <<ObfLen:16/big, _/binary>>, key := Key, sip := Sip, msg := Msg} = Stream, Acc) ->
    case i2p_framing:deobfuscate_length(ObfLen, Sip) of
        {ok, Len, Sip1} ->
            #{buf := Buf} = Stream,
            case byte_size(Buf) >= Len + 2 of
                true ->
                    <<_:2/binary, Sealed:Len/binary, Rest/binary>> = Buf,
                    case
                        i2p_crypto:chacha20_poly1305_open(
                            Key,
                            i2p_crypto:es_nonce(Msg),
                            Sealed,
                            <<>>
                        )
                    of
                        {ok, Payload} ->
                            cut(
                                Stream#{buf => Rest, sip => Sip1, msg => Msg + 1},
                                [Payload | Acc]
                            );
                        error ->
                            error
                    end;
                false ->
                    {ok, Stream, lists:reverse(Acc)}
            end;
        error ->
            error
    end;
%% Keeps the field requirements so a malformed map still crashes on dispatch
%% instead of silently reporting success.
cut(#{buf := _, key := _, sip := _, msg := _} = Stream, Acc) ->
    {ok, Stream, lists:reverse(Acc)}.
