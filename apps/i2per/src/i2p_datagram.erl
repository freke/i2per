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

-export([encode/3, decode/1]).

-export_type([datagram/0]).

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
