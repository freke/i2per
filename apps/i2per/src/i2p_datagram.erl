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
The signature is verified on decode (`f:decode/1` returns `error` for both
malformed input and failed authentication — callers treat them alike and
drop). Replay protection is not the codec's job: `m:i2p_datagram_replay`
holds the bounded per-destination window the receive path consults.

Datagram2 ([Proposal 163](https://i2p.net/en/proposals/163-datagram2/))
adds a flags field, an optional options Mapping and an optional
offline-signature section:

```
from      Destination of the sender, 391 bytes
flags     2 bytes: version 0x02 in bits 3-0, bit 4 announces the options
          Mapping, bit 5 the offline-signature section, bits 15-6 reserved
          and zero
options   Mapping (2-byte size, then `key=value;` pairs with 1-byte
          length-prefixed strings) — only when bit 4 is set
offline   expires (4 bytes, seconds since epoch), sigtype (2 bytes), the
          transient signing public key, and the target destination's
          signature over those three fields — only when bit 5 is set
payload   application bytes
signature 64 bytes, over the prelude (the target destination's hash), the
          flags, the options, the offline section and the payload
```

The prelude — the 32-byte hash of the *target* destination — is not on the
wire but is covered by the signature, which is what binds a datagram to the
destination it was addressed to.

An offline-signed datagram is signed by a transient key rather than by the
sender's own. The target's signature over that transient key (the `offsig`)
is what makes the key trustworthy, so a receiver can only accept such a
datagram when it holds the target destination's signing key; without it the
frame is dropped (`f:decode2/2`).

## Usage

```erlang
{ok, Wire} = i2p_datagram:encode(FromDestBin, SignSeed, <<"ping">>),
%% ... garlic-wrap Wire for the peer and inject into an outbound tunnel ...

{ok, #{from := FromDestBin, payload := <<"ping">>}} = i2p_datagram:decode(Wire).
```
""".

-export([encode/3, decode/1, encode2/4, encode2/5, decode2/2, decode2/3]).

-export_type([
    datagram/0,
    datagram2/0,
    datagram2_opts/0,
    offline_block/0,
    offline_sig/0
]).

-define(DEST_SIZE, 391).
-define(SIG_LEN, 64).
%% The Ed25519 public key and signature sizes. They are the only sizes this
%% codec signs with, and the only ones it accepts in an offline section.
-define(ED25519_PUBKEY_LEN, 32).
-define(ED25519_SIG_LEN, 64).
%% Datagram2 flags (2 bytes, big endian): bits 3-0 carry the version (0x02),
%% bit 4 announces the options Mapping, bit 5 the offline-signature section,
%% bits 15-6 are reserved and must be zero.
-define(DG2_VERSION, 16#0002).
-define(DG2_FLAG_OPTIONS, 16#0010).
-define(DG2_FLAG_OFFLINE, 16#0020).
-define(DG2_RESERVED, 16#FFC0).
%% Signature type 7 is EdDSA Ed25519: the only key type this codec signs
%% with, and the only transient key type it accepts.
-define(SIGTYPE_ED25519, 7).
%% A Mapping's strings are length-prefixed with one byte, and the whole
%% mapping is sized with two bytes.
-define(MAPPING_KEY_MAX, 255).
-define(MAPPING_VALUE_MAX, 255).
-define(MAPPING_MAX, 16#FFFF).

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
application payload, the 2-byte flags field (version 0x02 in the low nibble,
with the options and offline-signature bits in bits 4 and 5), and — when the
matching flag bit is set — the options Mapping as `{Key, Value}` pairs and
the offline-signature section.
""".
-type datagram2() :: #{
    from := binary(),
    payload := binary(),
    flags := 0..16#FFFF,
    options => [{binary(), binary()}],
    offline => offline_sig()
}.

-doc """
The offline-signature section of a Datagram2 as it appears on the wire: the
expiry, the transient signature type, the transient signing public key, and
the target destination's signature over those three fields.
""".
-type offline_sig() :: #{
    expires := non_neg_integer(),
    sigtype := 0..16#FFFF,
    pubkey := i2p_crypto:ed25519_public_key(),
    offsig := i2p_crypto:ed25519_signature()
}.

-doc """
Options for `f:encode2/5`: the optional options Mapping (`options`, a list
of `{Key, Value}` binary pairs) and the optional offline-signature section
(`offline`, an `t:offline_block/0`). Each is announced by its flag bit; an
absent key means the section is absent.
""".
-type datagram2_opts() :: #{
    options => [{binary(), binary()}],
    offline => offline_block()
}.

-doc """
The offline-signature section as a *sender* needs it: the four wire fields
plus the transient private seed that signs the payload.

The section is minted by the target destination — its `offsig` is the
target's own signature over `expires`, `sigtype` and `pubkey` — and handed
to the sender out of band; the datagrams spec says the section "can, and
should, be generated offline". A sender cannot mint one: it does not hold
the target's signing key.
""".
-type offline_block() :: #{
    expires := non_neg_integer(),
    sigtype := non_neg_integer(),
    pubkey := i2p_crypto:ed25519_public_key(),
    offsig := i2p_crypto:ed25519_signature(),
    seed := i2p_crypto:ed25519_seed()
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
32-byte prelude (the target destination hash), the 2-byte flags field, the
options and offline sections when they are present, and the payload.

Output: `{ok, Wire}` on success; `error` when `FromDest` is not a
391-byte destination binary, `TargetDestHash` is not a 32-byte hash, or
`Payload` is not a binary.
""".
-spec encode2(binary(), i2p_crypto:ed25519_seed(), binary(), binary()) ->
    {ok, binary()} | error.
encode2(FromDest, SignSeed, TargetDestHash, Payload) ->
    encode2(FromDest, SignSeed, TargetDestHash, Payload, #{}).

-doc """
Encode a Datagram2 with an options Mapping and/or an offline-signature
section.

`Opts` is a map with two optional keys:

- `options` — a list of `{Key, Value}` binary pairs, encoded as a
  [Mapping](https://i2p.net/en/docs/specs/common-structures/) and announced
  by flag bit 4. Keys are sorted (byte order, the spec's advice for signed
  mappings) so the signed bytes are canonical; duplicate keys, strings
  longer than 255 bytes and mappings longer than 65535 bytes are refused.
- `offline` — an `t:offline_block/0`, announced by flag bit 5. The payload is
  then signed by the transient key the block carries instead of by the
  sender's own key, and the block's `offsig` (the target destination's
  signature over `expires`, `sigtype` and `pubkey`) travels in the frame.

A key that is not `options` or `offline` is refused, as is a section that
does not fit the wire.

Output: `{ok, Wire}` on success; `error` when the inputs are malformed.
""".
-spec encode2(binary(), i2p_crypto:ed25519_seed(), binary(), binary(), datagram2_opts()) ->
    {ok, binary()} | error.
encode2(FromDest, SignSeed, TargetDestHash, Payload, Opts) when
    is_binary(FromDest), is_binary(TargetDestHash), is_binary(Payload), is_map(Opts)
->
    case {FromDest, TargetDestHash} of
        {<<_:?DEST_SIZE/binary>>, <<_:32/binary>>} ->
            case sections2(Opts, SignSeed) of
                {ok, Flags, OptionsBin, OfflineBin, SigningSeed} ->
                    FlagsBin = <<Flags:16/big>>,
                    %% The signed bytes are the prelude — the target
                    %% destination's hash, which is not on the wire — followed
                    %% by exactly the bytes that are.
                    Signed = iolist_to_binary([FlagsBin, OptionsBin, OfflineBin, Payload]),
                    ToSign = <<TargetDestHash:32/binary, Signed/binary>>,
                    Signature = i2p_crypto:ed25519_sign(ToSign, SigningSeed),
                    {ok, iolist_to_binary([FromDest, Signed, Signature])};
                error ->
                    error
            end;
        _ ->
            error
    end;
encode2(_, _, _, _, _) ->
    error.

-doc """
Decode and authenticate a Datagram2 without a target destination key.

`Wire` is the Data-clove payload; `TargetDestHash` is the 32-byte SHA-256
hash of this router's destination (the prelude the sender signed over).
Returns `{ok, Datagram}` with `from`, `payload` and `flags` when the frame
is well-formed, carries version 0x02, has no reserved flag bits, and the
embedded signature verifies against the sender's signing key; `error`
otherwise.

An offline-signed frame is always refused here: its `offsig` is the target
destination's signature, and without that destination's signing key there is
nothing to check it against. Use `f:decode2/3` to accept those.
""".
-spec decode2(binary(), binary()) -> {ok, datagram2()} | error.
decode2(Wire, TargetDestHash) ->
    decode2(Wire, TargetDestHash, undefined).

-doc """
Decode and authenticate a Datagram2, with the target destination's signing
key.

`DestSignPubKey` is the 32-byte Ed25519 signing public key of the
destination the datagram was addressed to (`i2p_keys:signing_key/1` of the
session's own identity), or `undefined` when the caller holds no such key.

An offline-signed frame is accepted only when its `offsig` verifies against
`DestSignPubKey` — the signature covers the block's expiry, transient
signature type and transient public key — and the block has not expired; the
payload signature is then checked against the transient public key the block
carries. An ordinary frame is verified against the sender destination's
signing key, exactly as in `f:decode2/2`.

Output: `{ok, Datagram}` when the frame is well-formed and authentic;
`error` otherwise. Malformed frames, unsupported flag combinations,
unparsable sender destinations, failed authentication and expired offline
blocks all collapse to `error`.
""".
-spec decode2(binary(), binary(), binary() | undefined) -> {ok, datagram2()} | error.
decode2(Wire, TargetDestHash, DestSignPubKey) when
    is_binary(Wire), is_binary(TargetDestHash)
->
    case TargetDestHash of
        <<_:32/binary>> ->
            decode2_body(Wire, TargetDestHash, DestSignPubKey);
        _ ->
            error
    end;
decode2(_, _, _) ->
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

%% sections2/2 — turn the encode options into the flag word, the two
%% optional wire sections, and the key that signs the payload.
-spec sections2(map(), i2p_crypto:ed25519_seed()) ->
    {ok, non_neg_integer(), binary(), binary(), i2p_crypto:ed25519_seed()} | error.
sections2(Opts, SignSeed) ->
    case maps:keys(Opts) -- [options, offline] of
        [] ->
            case options_section(maps:get(options, Opts, undefined)) of
                {ok, OptionsBin, OptionsFlag} ->
                    case offline_section(maps:get(offline, Opts, undefined), SignSeed) of
                        {ok, OfflineBin, OfflineFlag, SigningSeed} ->
                            {ok, ?DG2_VERSION bor OptionsFlag bor OfflineFlag, OptionsBin,
                                OfflineBin, SigningSeed};
                        error ->
                            error
                    end;
                error ->
                    error
            end;
        _ ->
            error
    end.

%% options_section/1 — the options Mapping, or nothing when absent.
-spec options_section([{binary(), binary()}] | undefined) ->
    {ok, binary(), non_neg_integer()} | error.
options_section(undefined) ->
    {ok, <<>>, 0};
options_section(Pairs) when is_list(Pairs) ->
    case mapping_encode(Pairs) of
        {ok, Bin} -> {ok, Bin, ?DG2_FLAG_OPTIONS};
        error -> error
    end;
options_section(_) ->
    error.

%% offline_section/2 — the offline-signature section, or nothing when
%% absent. A present section takes over the signing: the payload is signed
%% by the transient key, not by the sender's own.
-spec offline_section(offline_block() | undefined, i2p_crypto:ed25519_seed()) ->
    {ok, binary(), non_neg_integer(), i2p_crypto:ed25519_seed()} | error.
offline_section(undefined, SignSeed) ->
    {ok, <<>>, 0, SignSeed};
offline_section(Block, _SignSeed) when is_map(Block) ->
    case Block of
        #{
            expires := Expires,
            sigtype := SigType,
            pubkey := PubKey,
            offsig := OffSig,
            seed := Seed
        } when
            is_integer(Expires),
            Expires >= 0,
            Expires =< 16#FFFFFFFF,
            is_integer(SigType),
            is_binary(PubKey),
            is_binary(OffSig),
            is_binary(Seed)
        ->
            case sigtype_lengths(SigType) of
                {ok, PubLen, SigLen} when
                    byte_size(PubKey) =:= PubLen, byte_size(OffSig) =:= SigLen
                ->
                    {ok, <<Expires:32/big, SigType:16/big, PubKey/binary, OffSig/binary>>,
                        ?DG2_FLAG_OFFLINE, Seed};
                _ ->
                    error
            end;
        _ ->
            error
    end;
offline_section(_, _) ->
    error.

%% mapping_encode/1 — a Mapping as the common-structures spec defines it: a
%% 2-byte size (the number of bytes that follow) and then `key=value;`
%% pairs with 1-byte length-prefixed strings. The spec sorts mappings that
%% are signed and forbids duplicate keys; both are enforced here so that the
%% signed bytes are canonical and the mapping survives a round trip.
-spec mapping_encode([{binary(), binary()}]) -> {ok, binary()} | error.
mapping_encode(Pairs) ->
    Sorted = lists:keysort(1, Pairs),
    case duplicate_keys(Sorted) of
        true ->
            error;
        false ->
            case mapping_body(Sorted, []) of
                {ok, Body} when byte_size(Body) =< ?MAPPING_MAX ->
                    {ok, <<(byte_size(Body)):16/big, Body/binary>>};
                _ ->
                    error
            end
    end.

-spec duplicate_keys([{binary(), binary()}]) -> boolean().
duplicate_keys([{Key, _}, {Key, _} | _]) ->
    true;
duplicate_keys(_) ->
    false.

-spec mapping_body([{binary(), binary()}], [binary()]) -> {ok, binary()} | error.
mapping_body([], Acc) ->
    {ok, iolist_to_binary(lists:reverse(Acc))};
mapping_body([{Key, Value} | Rest], Acc) when
    is_binary(Key),
    is_binary(Value),
    byte_size(Key) =< ?MAPPING_KEY_MAX,
    byte_size(Value) =< ?MAPPING_VALUE_MAX
->
    Pair = <<(byte_size(Key)):8, Key/binary, $=, (byte_size(Value)):8, Value/binary, $;>>,
    mapping_body(Rest, [Pair | Acc]);
mapping_body(_, _) ->
    error.

%% mapping_decode/1 — the pairs out of a Mapping's body (the bytes after
%% the 2-byte size). A body that does not parse is refused: the caller
%% cannot tell where the payload starts if the options do not parse.
-spec mapping_decode(binary()) -> {ok, [{binary(), binary()}]} | error.
mapping_decode(Body) ->
    mapping_decode(Body, []).

-spec mapping_decode(binary(), [{binary(), binary()}]) ->
    {ok, [{binary(), binary()}]} | error.
mapping_decode(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
mapping_decode(
    <<KeyLen:8, Key:KeyLen/binary, $=, ValLen:8, Val:ValLen/binary, $;, Rest/binary>>, Acc
) ->
    mapping_decode(Rest, [{Key, Val} | Acc]);
mapping_decode(_, _) ->
    error.

%% sigtype_lengths/1 — the public key and signature lengths implied by a
%% signature type. Only Ed25519 (7) is supported; anything else is refused
%% rather than guessed at.
-spec sigtype_lengths(non_neg_integer()) ->
    {ok, ?ED25519_PUBKEY_LEN, ?ED25519_SIG_LEN} | error.
sigtype_lengths(?SIGTYPE_ED25519) ->
    {ok, ?ED25519_PUBKEY_LEN, ?ED25519_SIG_LEN};
sigtype_lengths(SigType) when is_integer(SigType), SigType >= 0 ->
    error.

-spec decode2_body(binary(), <<_:256>>, binary() | undefined) ->
    {ok, datagram2()} | error.
decode2_body(Wire, TargetDestHash, DestSignPubKey) ->
    case Wire of
        <<From:?DEST_SIZE/binary, Flags:16/big, Rest/binary>> when
            byte_size(Rest) >= ?SIG_LEN
        ->
            case flags2_ok(Flags) of
                true ->
                    decode2_sections(From, Flags, Rest, TargetDestHash, DestSignPubKey);
                false ->
                    error
            end;
        _ ->
            error
    end.

%% flags2_ok/1 — the version nibble must be 0x02 and the reserved bits
%% (15-6) must be zero. Bits 4 and 5 announce the sections that follow.
-spec flags2_ok(0..16#FFFF) -> boolean().
flags2_ok(Flags) when Flags >= 0, Flags =< 16#FFFF ->
    (Flags band 16#000F) =:= ?DG2_VERSION andalso (Flags band ?DG2_RESERVED) =:= 0.

-spec decode2_sections(
    <<_:3128>>, 0..16#FFFF, binary(), <<_:256>>, binary() | undefined
) ->
    {ok, datagram2()} | error.
decode2_sections(From, Flags, Rest, TargetDestHash, DestSignPubKey) ->
    HasOptions = (Flags band ?DG2_FLAG_OPTIONS) =/= 0,
    HasOffline = (Flags band ?DG2_FLAG_OFFLINE) =/= 0,
    case options2_section(Rest, HasOptions) of
        {ok, Options, OptionsBin, Rest1} ->
            case offline2_section(Rest1, HasOffline, DestSignPubKey) of
                {ok, Offline, OfflineBin, Rest2} ->
                    case payload2(Rest2) of
                        {ok, Payload, Signature} ->
                            ToSign =
                                <<TargetDestHash:32/binary, Flags:16/big, OptionsBin/binary,
                                    OfflineBin/binary, Payload/binary>>,
                            case authentic2(From, Signature, ToSign, Offline) of
                                true ->
                                    {ok, datagram2_map(From, Flags, Options, Offline, Payload)};
                                false ->
                                    error
                            end;
                        error ->
                            error
                    end;
                error ->
                    error
            end;
        error ->
            error
    end.

%% options2_section/2 — the options Mapping when bit 4 announces it, and
%% the bytes it occupies (the signed section is the wire form, size field
%% included).
-spec options2_section(binary(), boolean()) ->
    {ok, [{binary(), binary()}] | undefined, binary(), binary()} | error.
options2_section(Rest, false) ->
    {ok, undefined, <<>>, Rest};
options2_section(Rest, true) ->
    case Rest of
        <<Size:16/big, Body:Size/binary, Rest1/binary>> ->
            case mapping_decode(Body) of
                {ok, Pairs} -> {ok, Pairs, <<Size:16/big, Body/binary>>, Rest1};
                error -> error
            end;
        _ ->
            error
    end.

%% offline2_section/3 — the offline-signature section when bit 5 announces
%% it. The section is only accepted when the target destination's key
%% vouches for it and the block has not expired.
-spec offline2_section(binary(), boolean(), binary() | undefined) ->
    {ok, offline_sig() | undefined, binary(), binary()} | error.
offline2_section(Rest, false, _DestSignPubKey) ->
    {ok, undefined, <<>>, Rest};
offline2_section(Rest, true, DestSignPubKey) ->
    case Rest of
        <<Expires:32/big, SigType:16/big, Rest1/binary>> ->
            case sigtype_lengths(SigType) of
                {ok, PubLen, SigLen} ->
                    case Rest1 of
                        <<PubKey:PubLen/binary, OffSig:SigLen/binary, Rest2/binary>> ->
                            Section =
                                <<Expires:32/big, SigType:16/big, PubKey/binary, OffSig/binary>>,
                            case offline2_valid(Expires, SigType, PubKey, OffSig, DestSignPubKey) of
                                true ->
                                    {ok,
                                        #{
                                            expires => Expires,
                                            sigtype => SigType,
                                            pubkey => PubKey,
                                            offsig => OffSig
                                        },
                                        Section, Rest2};
                                false ->
                                    error
                            end;
                        _ ->
                            error
                    end;
                error ->
                    error
            end;
        _ ->
            error
    end.

%% offline2_valid/5 — the target destination's signature over the expiry,
%% the transient signature type and the transient public key, plus the
%% expiry itself: a block whose time has passed is refused.
-spec offline2_valid(
    non_neg_integer(), non_neg_integer(), binary(), binary(), binary() | undefined
) ->
    boolean().
offline2_valid(Expires, SigType, PubKey, OffSig, DestSignPubKey) ->
    case DestSignPubKey of
        <<_:?ED25519_PUBKEY_LEN/binary>> ->
            Signed = <<Expires:32/big, SigType:16/big, PubKey/binary>>,
            i2p_crypto:ed25519_verify(Signed, OffSig, DestSignPubKey) andalso
                Expires >= erlang:system_time(second);
        _ ->
            false
    end.

%% payload2/1 — the payload and the signature that closes the frame.
-spec payload2(binary()) -> {ok, binary(), <<_:512>>} | error.
payload2(Rest) when byte_size(Rest) >= ?SIG_LEN ->
    PayloadLen = byte_size(Rest) - ?SIG_LEN,
    case Rest of
        <<Payload:PayloadLen/binary, Signature:?SIG_LEN/binary>> ->
            {ok, Payload, Signature};
        _ ->
            error
    end;
payload2(_) ->
    error.

%% authentic2/4 — an ordinary datagram is signed by the sender
%% destination's key; an offline-signed one by the transient key the block
%% carries.
-spec authentic2(<<_:3128>>, <<_:512>>, binary(), offline_sig() | undefined) -> boolean().
authentic2(FromDest, Signature, ToSign, undefined) ->
    case i2p_keys:parse(FromDest) of
        {ok, Identity} ->
            i2p_crypto:ed25519_verify(ToSign, Signature, i2p_keys:signing_key(Identity));
        {error, _Reason} ->
            false
    end;
authentic2(_FromDest, Signature, ToSign, #{pubkey := PubKey}) ->
    i2p_crypto:ed25519_verify(ToSign, Signature, PubKey).

%% datagram2_map/5 — the decoded frame, with the sections that were
%% present.
-spec datagram2_map(
    <<_:3128>>,
    0..16#FFFF,
    [{binary(), binary()}] | undefined,
    offline_sig() | undefined,
    binary()
) ->
    datagram2().
datagram2_map(From, Flags, undefined, undefined, Payload) ->
    #{from => From, flags => Flags, payload => Payload};
datagram2_map(From, Flags, Options, undefined, Payload) ->
    #{from => From, flags => Flags, options => Options, payload => Payload};
datagram2_map(From, Flags, undefined, Offline, Payload) ->
    #{from => From, flags => Flags, offline => Offline, payload => Payload};
datagram2_map(From, Flags, Options, Offline, Payload) ->
    #{from => From, flags => Flags, options => Options, offline => Offline, payload => Payload}.
