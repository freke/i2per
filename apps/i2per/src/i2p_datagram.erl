-module(i2p_datagram).

-moduledoc """
Repliable (Datagram1) datagram codec: unreliable, authenticated messages
carried as the payload of end-to-end garlic Data cloves, one datagram per
clove — the same framing rule as streaming packets (`m:i2p_streaming`).

Wire format
([datagrams spec](https://geti2p.net/en/docs/specs/datagrams), Datagram1):

```
from       Destination of the sender, 391 bytes for the project's standard
           X25519 + Ed25519 identities
signature  Ed25519 signature over payload, by the sender's signing key,
           64 bytes
payload    application bytes, arbitrary length (practically <= ~11 KB)
```

There is no length field: the layers around the datagram fix its extent.
The signature is verified on decode (`f:decode/2` returns `error` for both
malformed input and failed authentication — callers treat them alike and
drop). Datagram2 replay protection is not implemented in this release.

## Usage

```erlang
{ok, Wire} = i2p_datagram:encode(FromDestBin, SignSeed, <<"ping">>),
%% ... garlic-wrap Wire for the peer and inject into an outbound tunnel ...

{ok, #{from := FromDestBin, payload := <<"ping">>}} = i2p_datagram:decode(Wire).
```
""".

-export([encode/3, decode/1, encode2/4, decode2/2]).

-export_type([datagram/0, datagram2/0]).

-define(DEST_SIZE, 391).
-define(SIG_LEN, 64).

-doc """
A decoded repliable datagram: the sender's 391-byte destination binary and
the application payload (the signature is consumed by authentication).
""".
-type datagram() :: #{
    from := binary(),
    payload := binary()
}.

-doc """
A decoded Datagram2: the sender's 391-byte destination binary, the
application payload, and the 2-byte flags field (version 0x02 in the low
nibble, with the options and offline-signature bits in bits 4 and 5).
""".
-type datagram2() :: #{
    from := binary(),
    payload := binary(),
    flags := char()
}.

-doc """
Encode a repliable datagram signed by the local destination.

Input: `FromDest` — the sender's 391-byte destination binary;
`SignSeed` — the matching Ed25519 private seed; `Payload` — application
bytes.
Output: `{ok, Wire}` — the datagram ready to ride as a garlic Data-clove
payload; `error` when `FromDest` is not a 391-byte destination binary.
""".
-spec encode(binary(), i2p_crypto:ed25519_seed(), binary()) -> {ok, binary()} | error.
encode(FromDest, SignSeed, Payload) when is_binary(Payload) ->
    case FromDest of
        <<_:?DEST_SIZE/binary>> ->
            Signature = i2p_crypto:ed25519_sign(Payload, SignSeed),
            {ok, <<FromDest:?DEST_SIZE/binary, Signature:?SIG_LEN/binary, Payload/binary>>};
        _ ->
            error
    end;
encode(_, _, _) ->
    error.

-doc """
Decode and authenticate a repliable datagram.

Input: `Wire` — the Data-clove payload received out of an inbound tunnel.
Output: `{ok, Datagram}` when the embedded signature verifies against the
embedded sender destination's signing key; `error` when the frame is
malformed, the destination does not parse, or authentication fails — all
three are dropped identically by receivers.
""".
-spec decode(binary()) -> {ok, datagram()} | error.
decode(Wire) when is_binary(Wire) ->
    case Wire of
        <<From:?DEST_SIZE/binary, Signature:?SIG_LEN/binary, Payload/binary>> ->
            case authentic(From, Signature, Payload) of
                true -> {ok, #{from => From, payload => Payload}};
                false -> error
            end;
        _ ->
            error
    end;
decode(_) ->
    error.

-doc """
Encode a Datagram2 (Proposal 163) carrying `Payload` from `FromDest` to the
destination whose 32-byte SHA-256 hash is `TargetDestHash`.

`SignSeed` is the sender's Ed25519 private seed. The signature covers the
32-byte prelude (target destination hash), the 2-byte flags field, and the
payload — options and offline-signature sections are not used by this
release and are omitted (flags = 0x0002, version 0x02, no options, not
offline-signed).

Output: `{ok, Wire}` on success; `error` when `FromDest` is not a
391-byte destination binary, `TargetDestHash` is not a 32-byte hash, or
`Payload` is not a binary.
""".
-spec encode2(binary(), i2p_crypto:ed25519_seed(), binary(), binary()) ->
    {ok, binary()} | error.
encode2(FromDest, SignSeed, TargetDestHash, Payload) when
    is_binary(FromDest), is_binary(TargetDestHash), is_binary(Payload)
->
    case {FromDest, TargetDestHash} of
        {<<_:?DEST_SIZE/binary>>, <<_:32/binary>>} ->
            Flags = 16#0002,
            FlagsBin = <<Flags:16/big>>,
            ToSign = <<TargetDestHash:32/binary, FlagsBin/binary, Payload/binary>>,
            Signature = i2p_crypto:ed25519_sign(ToSign, SignSeed),
            {ok,
                <<FromDest:?DEST_SIZE/binary, FlagsBin/binary, Payload/binary,
                    Signature:?SIG_LEN/binary>>};
        _ ->
            error
    end;
encode2(_, _, _, _) ->
    error.

-doc """
Decode and authenticate a Datagram2.

`Wire` is the Data-clove payload; `TargetDestHash` is the 32-byte SHA-256
hash of this router's destination (the prelude the sender signed over).
Returns `{ok, Datagram}` with `from`, `payload` and `flags` when the frame
is well-formed, carries version 0x02 without options or offline-signature
sections, and the embedded signature verifies against the sender's signing
key; `error` otherwise. Malformed frames, unsupported flag combinations,
unparsable sender destinations, and failed authentication all collapse to
`error`.
""".
-spec decode2(binary(), binary()) -> {ok, datagram2()} | error.
decode2(Wire, TargetDestHash) when
    is_binary(Wire), is_binary(TargetDestHash)
->
    case TargetDestHash of
        <<_:32/binary>> ->
            decode2_body(Wire, TargetDestHash);
        _ ->
            error
    end;
decode2(_, _) ->
    error.

%%%%%%% %%% Internal %%%%%%%

%% The from destination and signature sizes are fixed by decode's segment
%% matching, which narrows the inputs below the general binary() type.
-spec authentic(<<_:3128>>, <<_:512>>, binary()) -> boolean().
authentic(FromDest, Signature, Payload) ->
    case i2p_keys:parse(FromDest) of
        {ok, Identity} ->
            i2p_crypto:ed25519_verify(Payload, Signature, i2p_keys:signing_key(Identity));
        {error, _Reason} ->
            false
    end.

-spec decode2_body(binary(), <<_:256>>) ->
    {ok, #{from := <<_:3128>>, payload := binary(), flags := char()}} | error.
decode2_body(Wire, TargetDestHash) ->
    case Wire of
        <<From:?DEST_SIZE/binary, Flags:16/big, Rest/binary>> when
            byte_size(Rest) >= ?SIG_LEN
        ->
            %% Options (bit 4) and offline signatures (bit 5) are not
            %% implemented in this release (see R85EHTA); reject those.
            case (Flags band 16#0030) of
                0 ->
                    PayloadLen = byte_size(Rest) - ?SIG_LEN,
                    <<Payload:PayloadLen/binary, Signature:?SIG_LEN/binary>> = Rest,
                    case authentic2(From, Signature, TargetDestHash, Flags, Payload) of
                        true ->
                            {ok, #{from => From, payload => Payload, flags => Flags}};
                        false ->
                            error
                    end;
                _ ->
                    error
            end;
        _ ->
            error
    end.

-spec authentic2(<<_:3128>>, <<_:512>>, <<_:256>>, char(), binary()) ->
    boolean().
authentic2(FromDest, Signature, TargetDestHash, Flags, Payload) ->
    case i2p_keys:parse(FromDest) of
        {ok, Identity} ->
            ToSign = <<TargetDestHash:32/binary, Flags:16/big, Payload/binary>>,
            i2p_crypto:ed25519_verify(ToSign, Signature, i2p_keys:signing_key(Identity));
        {error, _Reason} ->
            false
    end.
