-module(i2p_garlic).

-moduledoc """
Garlic message encryption layer for ECIES-X25519.

Implements the ECIES garlic format used by i2pd: short cloves with embedded
delivery instructions, TLV payload blocks, and router-directed encryption
via the Noise N handshake pattern with a custom protocol name (no null
terminator).

## Wire format

A **router-directed garlic message** is an I2NP Garlic Message (type 11)
whose body contains:

```text
length(4 BE) ‖ ephPub(32) ‖ AEAD(payload, nonce=0, AD=h) ‖ tag(16)
```

The Noise N handshake uses `h = ck = SHA256("Noise_N_25519_ChaChaPoly_SHA256")`
followed by `h = MixHash(h, staticKey)`, which differs from
`f:noise_n_initialize/0` (which appends a null byte to the protocol name).

## Usage

```erlang
%% Wrap cloves for a router
{RouterPub, RouterPriv} = i2p_crypto:x25519_keygen(),
Clove = #{delivery => local, type => 11, msg_id => <<1,2,3,4>>,
          expiration => 1800000000, data => <<"hello">>},
Msg = i2p_garlic:wrap_router([Clove], RouterPub),
%% Msg is an i2np_message() with type=garlic

%% Unwrap on the router side
{ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
{ok, Blocks} = i2p_garlic:unwrap_router(Encrypted, RouterPriv),
Cloves = i2p_garlic:extract_cloves(Blocks).
```
""".

%% TLV type numbers (matching i2pd Garlic.h)
-define(BLOCK_DATETIME, 0).
-define(BLOCK_SESSION_ID, 1).
-define(BLOCK_TERMINATION, 2).
-define(BLOCK_OPTIONS, 3).
-define(BLOCK_NEXT_KEY, 4).
-define(BLOCK_ACK, 8).
-define(BLOCK_ACK_REQUEST, 9).
-define(BLOCK_GARLIC_CLOVE, 11).
-define(BLOCK_PADDING, 254).

-export_type([delivery/0, clove/0, block_type/0, block/0, dispatch_msg/0, ignore_reason/0]).

-export([
    encode_delivery/1,
    decode_delivery/1,
    encode_clove/1,
    decode_clove/1,
    encode_payload/1, encode_payload/2,
    decode_payload/1,
    extract_cloves/1,
    block_datetime/0,
    block_session_id/0,
    block_termination/0,
    block_options/0,
    block_next_key/0,
    block_ack/0,
    block_ack_request/0,
    block_garlic_clove/0,
    block_padding/0,
    clove_message/1,
    wrap_router/2, wrap_router/3,
    unwrap_router/2,
    wrap_existing_session/3,
    unwrap_existing_session/3,
    dispatch_db_message/2
]).

-doc """
Why `f:dispatch_db_message/2` did not handle a message.

Kept apart because the two store cases are opposites from the network's point of
view and must not be collapsed again: `{unsupported_type, T}` means the peer *did*
answer and the record arrived intact, and this router has no parser for what is
inside it — the network is helping and the router cannot read it.
`undecodable_store` means the bytes themselves did not parse, which is a fault on
the wire rather than a gap in this implementation.

`{unsupported_type, T}` is deliberately in the same shape as the corresponding
clause of `m:i2p_peer:store_not_stored_reason/0`, so a store this router declines to
parse carries one vocabulary all the way up instead of being renamed on the way.
""".
-type ignore_reason() ::
    %% The store decoded and named a type with no parser here (types 5 and 7).
    {unsupported_type, byte()}
    | undecodable_store
    | undecodable_lookup
    | undecodable_search_reply
    | not_a_db_message.

-doc "Database message subset accepted by `f:dispatch_db_message/2`.".
-type dispatch_msg() :: #{type := 0..255, body := binary()}.

-doc "Delivery target for a garlic clove.".
-type delivery() ::
    local
    | {destination, binary()}
    | {router, binary()}
    | {tunnel, binary(), non_neg_integer()}.

-doc "A single garlic clove: delivery target, inner I2NP type, msg ID, expiration, and body.".
-type clove() :: #{
    delivery := delivery(),
    type := non_neg_integer(),
    msg_id := binary(),
    expiration := non_neg_integer(),
    data := binary()
}.

-doc "TLV block type tag (atom for known types, `{unknown, N}` for raw).".
-type block_type() ::
    datetime
    | session_id
    | termination
    | options
    | next_key
    | ack
    | ack_request
    | garlic_clove
    | padding
    | {unknown, non_neg_integer()}.

-doc "A decoded TLV payload block.".
-type block() :: #{type := block_type(), data := binary()}.

%%%%%%% Delivery Instructions %%%%%%%

-doc "Encode delivery instructions to binary.".
-spec encode_delivery(delivery()) -> binary().
encode_delivery(local) ->
    <<0:8>>;
encode_delivery({destination, Hash}) when byte_size(Hash) =:= 32 ->
    <<32:8, Hash/binary>>;
encode_delivery({router, Hash}) when byte_size(Hash) =:= 32 ->
    <<64:8, Hash/binary>>;
encode_delivery({tunnel, Hash, TunnelID}) when byte_size(Hash) =:= 32 ->
    <<96:8, Hash/binary, TunnelID:32/big>>.

-doc "Decode delivery instructions, returning `{Delivery, Rest}` or `error`.".
-spec decode_delivery(binary()) -> {delivery(), binary()} | error.
decode_delivery(<<>>) ->
    error;
decode_delivery(<<0:8, Rest/binary>>) ->
    {local, Rest};
decode_delivery(<<32:8, Hash:32/binary, Rest/binary>>) ->
    {{destination, Hash}, Rest};
decode_delivery(<<64:8, Hash:32/binary, Rest/binary>>) ->
    {{router, Hash}, Rest};
decode_delivery(<<96:8, Hash:32/binary, TunnelID:32/big, Rest/binary>>) ->
    {{tunnel, Hash, TunnelID}, Rest};
decode_delivery(_) ->
    error.

%%%%%%% Short ECIES Clove %%%%%%%

-doc "Encode a single ECIES garlic clove to binary.".
-spec encode_clove(clove()) -> binary().
encode_clove(#{
    delivery := Delivery,
    type := Type,
    msg_id := MsgId,
    expiration := Expiration,
    data := Data
}) ->
    Flag = encode_delivery_flag(Delivery),
    DeliveryBin = encode_delivery_payload(Delivery),
    <<Flag:8, DeliveryBin/binary, Type:8, MsgId/binary, Expiration:32/big, Data/binary>>.

-doc "Decode a single ECIES garlic clove from binary.".
-spec decode_clove(binary()) -> {ok, clove()} | error.
decode_clove(<<>>) ->
    error;
decode_clove(Bin) ->
    case decode_clove_fields(Bin) of
        {Delivery, Rest} when byte_size(Rest) >= 9 ->
            <<Type:8, MsgId:4/binary, Expiration:32/big, Data/binary>> = Rest,
            {ok, #{
                delivery => Delivery,
                type => Type,
                msg_id => MsgId,
                expiration => Expiration,
                data => Data
            }};
        _ ->
            error
    end.

%%%%%%% TLV Payload Blocks %%%%%%%

-doc "Encode a payload with cloves and default options (current time).".
-spec encode_payload([clove()]) -> binary().
encode_payload(Cloves) ->
    encode_payload(Cloves, #{}).

-doc "Encode a payload with cloves and options.\n"
"\n"
"Options:\n"
"- `datetime` — explicit timestamp (default: `os:system_time(second)`)\n"
"- `pad_to` — pad payload to this many bytes\n".
-spec encode_payload([clove()], map()) -> binary().
encode_payload(Cloves, Opts) ->
    Now = maps:get(datetime, Opts, os:system_time(second)),
    Blocks0 = [encode_tlv_block(?BLOCK_DATETIME, <<Now:32/big>>)],
    Blocks1 = Blocks0 ++ [encode_clove_block(C) || C <- Cloves],
    PadTo = maps:get(pad_to, Opts, 0),
    Blocks2 = maybe_pad(Blocks1, PadTo),
    iolist_to_binary(Blocks2).

-doc "Decode a TLV payload into a list of blocks.".
-spec decode_payload(binary()) -> {ok, [block()]} | error.
decode_payload(<<>>) ->
    {ok, []};
decode_payload(Bin) ->
    decode_payload_loop(Bin, []).

-doc "Extract garlic cloves from a list of decoded blocks.".
-spec extract_cloves([block()]) -> [clove()].
extract_cloves(Blocks) ->
    [maps:get(clove, B) || #{type := garlic_clove} = B <- Blocks].

%%%%%%% Block Type Constants %%%%%%%

-doc "TLV block type: datetime (0).".
-spec block_datetime() -> datetime.
block_datetime() -> datetime.

-doc "TLV block type: session ID (1).".
-spec block_session_id() -> session_id.
block_session_id() -> session_id.

-doc "TLV block type: termination (2).".
-spec block_termination() -> termination.
block_termination() -> termination.

-doc "TLV block type: options (3).".
-spec block_options() -> options.
block_options() -> options.

-doc "TLV block type: next key (4).".
-spec block_next_key() -> next_key.
block_next_key() -> next_key.

-doc "TLV block type: ack (8).".
-spec block_ack() -> ack.
block_ack() -> ack.

-doc "TLV block type: ack request (9).".
-spec block_ack_request() -> ack_request.
block_ack_request() -> ack_request.

-doc "TLV block type: garlic clove (11).".
-spec block_garlic_clove() -> garlic_clove.
block_garlic_clove() -> garlic_clove.

-doc "TLV block type: padding (254).".
-spec block_padding() -> padding.
block_padding() -> padding.

%%%%%%% Garlic Message Construction %%%%%%%

-doc "Build a short-header I2NP message from a garlic clove's fields.".
-spec clove_message(clove()) -> i2p_i2np:i2np_message().
clove_message(#{
    type := Type,
    msg_id := MsgId,
    expiration := Expiration,
    data := Data
}) ->
    #{type => Type, msg_id => MsgId, expiration => Expiration, body => Data}.

%%%%%%% Router ECIES Wrap/Unwrap %%%%%%%

-doc "Wrap cloves for a router, generating an ephemeral keypair.".
-spec wrap_router([clove()], i2p_crypto:x25519_public_key()) ->
    i2p_i2np:i2np_message().
wrap_router(Cloves, RouterPub) ->
    {_EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
    wrap_router(Cloves, RouterPub, EphPriv).

-doc "Wrap cloves for a router with a deterministic ephemeral private key.".
-spec wrap_router(
    [clove()],
    i2p_crypto:x25519_public_key(),
    i2p_crypto:x25519_private_key()
) ->
    i2p_i2np:i2np_message().
wrap_router(Cloves, RouterPub, EphPriv) ->
    Payload = encode_payload(Cloves),
    {H, Ck} = noise_n_garlic_init(RouterPub),
    {CT, Tag, _H2, _Ck1} = i2p_crypto:noise_n_encrypt(
        EphPriv, RouterPub, H, Ck, Payload
    ),
    EphPub = i2p_crypto:x25519_public_key(EphPriv),
    Encrypted = <<EphPub/binary, CT/binary, Tag/binary>>,
    i2p_i2np:garlic(Encrypted).

-doc "Unwrap a router-directed garlic message.".
-spec unwrap_router(binary(), i2p_crypto:x25519_private_key()) ->
    {ok, [block()]} | error.
unwrap_router(<<EphPub:32/binary, CTAndTag/binary>>, RouterPriv) ->
    CTLen = byte_size(CTAndTag) - 16,
    <<CT:CTLen/binary, Tag:16/binary>> = CTAndTag,
    RouterPub = i2p_crypto:x25519_public_key(RouterPriv),
    {H, Ck} = noise_n_garlic_init(RouterPub),
    case i2p_crypto:noise_n_decrypt(RouterPriv, EphPub, H, Ck, CT, Tag) of
        {ok, Payload, _H2, _Ck1} ->
            decode_payload(Payload);
        error ->
            error
    end;
unwrap_router(_, _) ->
    error.

%%%%%%% %%% Existing Session (RGarlic) %%%%%%%

-doc """
Wrap cloves in an Existing Session (ES) garlic message.

This is the RGarlic form used for outbound tunnel build replies: the wire
format is `length(4) ‖ session tag (8) ‖ AEAD frame`, where the frame is the
garlic TLV payload encrypted with ChaCha20-Poly1305 under `Key`, zero nonce,
and the raw 8-byte tag as associated data (per i2pd
`WrapECIESX25519Message`).

Input: `Cloves` — typically a single clove carrying the OTBRM; `Key` — the
32-byte garlic reply key derived at the OBEP; `Tag` — the 8-byte garlic
reply tag.
Output: a complete type-11 `t:i2p_i2np:i2np_message/0`.
""".
-spec wrap_existing_session([clove()], i2p_crypto:key(), binary()) ->
    i2p_i2np:i2np_message().
wrap_existing_session(Cloves, Key, Tag) when byte_size(Tag) =:= 8 ->
    Payload = encode_payload(Cloves),
    {CT, Mac} = i2p_crypto:chacha20_poly1305_encrypt(Key, <<0:96>>, Payload, Tag),
    Encrypted = <<Tag/binary, CT/binary, Mac/binary>>,
    i2p_i2np:garlic(Encrypted).

-doc """
Unwrap an Existing Session (ES) garlic message body.

The caller supplies the expected 8-byte tag (mismatches are rejected before
decryption) and the garlic reply key. Input is the garlic message DATA —
everything after the 4-byte length prefix.

Output: `{ok, [block()]}` on success, or `error` for a wrong tag, truncated
body, or failed authentication.
""".
-spec unwrap_existing_session(binary(), i2p_crypto:key(), binary()) ->
    {ok, [block()]} | error.
unwrap_existing_session(<<Tag:8/binary, CTAndMac/binary>>, Key, Tag) ->
    MACTagLen = 16,
    case byte_size(CTAndMac) > MACTagLen of
        false ->
            error;
        true ->
            CTLen = byte_size(CTAndMac) - MACTagLen,
            <<CT:CTLen/binary, Mac:16/binary>> = CTAndMac,
            case i2p_crypto:chacha20_poly1305_decrypt(Key, <<0:96>>, CT, Mac, Tag) of
                Payload when is_binary(Payload) ->
                    decode_payload(Payload);
                error ->
                    error
            end
    end;
unwrap_existing_session(_, _, _) ->
    error.

%%%%%%% %%% DB Message Dispatch %%%%%%%

-doc """
Dispatch an I2NP DB message to the appropriate action.

Parses the message body and returns a pure action term describing what the
caller should execute.  The caller (typically `m:i2p_tunnel_srv`) performs the
side effects — this function remains a pure library call.

## Message types handled

- **type 1 (DatabaseStore):** body is decoded via `m:i2p_i2np:decode_db_store/1`.
  `store_type` 0 → `{store, router, Data, NowMs}`; 1 → `{store, lease, Data, NowMs}`.
- **type 2 (DatabaseLookup):** `{lookup, ParsedBody}`.
- **type 3 (DatabaseSearchReply):** `{search_reply, ParsedBody}`.

A DatabaseStore whose `store_type` this router does not implement decodes
successfully and is ignored, with a `warning` naming the type. Both reference
routers can emit types this router has no parser for — 5 (EncryptedLeaseSet)
is live in both, 7 (MetaLeaseSet) is draft — and the decoder reports every byte
on the wire rather than only the types it understands, so a successful decode is
not a promise this router can act on.

Input: `Msg` — an `t:i2p_i2np:i2np_message/0`; `NowMs` — wall-clock
milliseconds since epoch (for timestamping store operations).

Output: `{store, router | lease, Key :: binary(), Data :: binary(), non_neg_integer()} |
{lookup, map()} | {search_reply, map()} | {ignored, t:ignore_reason/0}`.
""".
%% Dispatch one Database-family I2NP message.
%%
%% An unhandled message now says *which* way it was unhandled. It used to be a bare
%% `ignore`, and every caller dropped it identically — so a store of a type this
%% router has no parser for, a store whose body did not decode, and an I2NP message
%% that was never a database message all looked the same, at every layer above. That
%% mattered for lookups in particular: a peer that answered with a record `i2per`
%% cannot read, and a peer that never answered, produced one indistinguishable
%% outcome, so a router could not tell "the network is not helping me" from "the
%% network is helping me with something I cannot read".
-spec dispatch_db_message(dispatch_msg(), integer()) ->
    {store, router | lease, i2p_crypto:hash(), binary(), non_neg_integer()}
    | {lookup, i2p_i2np:db_lookup()}
    | {search_reply, i2p_i2np:db_search_reply()}
    | {ignored, ignore_reason()}.
dispatch_db_message(#{type := 1, body := Body}, NowMs) ->
    case i2p_i2np:decode_db_store(Body) of
        {ok, #{store_type := 0, key := Key, data := Data}} ->
            {store, router, Key, Data, NowMs};
        %% Store types 1 (LeaseSet) and 3 (LeaseSet2) both advertise leases.
        {ok, #{store_type := T, key := Key, data := Data}} when T =:= 1; T =:= 3 ->
            {store, lease, Key, Data, NowMs};
        %% A store type this router has no parser for. Types 5 and 7 decode
        %% successfully, so without this clause they fall off the `case` and
        %% raise `case_clause` — which killed the tunnel manager outright,
        %% because its child spec is `permanent` and the caller has no `try`.
        {ok, #{store_type := T, key := Key}} ->
            %% Log-only, and the reason is worth spelling out because it looks like
            %% it should not be. The `{ignored, {unsupported_type, T}}` returned here
            %% is dropped by `m:i2p_tunnel_relay` without reaching any caller that
            %% announces, so unlike the `m:i2p_peer` store path there is no
            %% `db_store_not_stored` on the bus for a store that arrived inside garlic.
            %% This line is the only record that it happened.
            logger:warning(
                "ignoring netdb store of unimplemented type ~0p for ~s",
                [T, base64:encode(Key)]
            ),
            {ignored, {unsupported_type, T}};
        error ->
            {ignored, undecodable_store}
    end;
dispatch_db_message(#{type := 2, body := Body}, _NowMs) ->
    case i2p_i2np:decode_db_lookup(Body) of
        {ok, Parsed} -> {lookup, Parsed};
        error -> {ignored, undecodable_lookup}
    end;
dispatch_db_message(#{type := 3, body := Body}, _NowMs) ->
    case i2p_i2np:decode_db_search_reply(Body) of
        {ok, Parsed} -> {search_reply, Parsed};
        error -> {ignored, undecodable_search_reply}
    end;
dispatch_db_message(_Msg, _NowMs) ->
    {ignored, not_a_db_message}.

%%%%%%% Internal %%%%%%%

%% Delivery flag bits 6–5
encode_delivery_flag(local) -> 0;
encode_delivery_flag({destination, _}) -> 32;
encode_delivery_flag({router, _}) -> 64;
encode_delivery_flag({tunnel, _, _}) -> 96.

%% Payload bytes after the flag byte (hash and/or tunnel_id)
encode_delivery_payload(local) ->
    <<>>;
encode_delivery_payload({destination, Hash}) ->
    Hash;
encode_delivery_payload({router, Hash}) ->
    Hash;
encode_delivery_payload({tunnel, Hash, TunnelID}) ->
    <<Hash/binary, TunnelID:32/big>>.

%% Decode flag + optional hash/tunnel_id, returning {Delivery, Rest}.
%% The binary patterns enforce the minimum tail lengths (32 or 36 bytes)
%% required by each delivery type.
decode_clove_fields(<<Flag:8, Rest/binary>>) when (Flag bsr 5) band 3 =:= 0 ->
    {local, Rest};
decode_clove_fields(<<Flag:8, Hash:32/binary, After/binary>>) when
    (Flag bsr 5) band 3 =:= 1
->
    {{destination, Hash}, After};
decode_clove_fields(<<Flag:8, Hash:32/binary, After/binary>>) when
    (Flag bsr 5) band 3 =:= 2
->
    {{router, Hash}, After};
decode_clove_fields(<<Flag:8, Hash:32/binary, TunnelID:32/big, After/binary>>) when
    (Flag bsr 5) band 3 =:= 3
->
    {{tunnel, Hash, TunnelID}, After};
decode_clove_fields(_) ->
    error.

%% Encode a TLV block header + data
encode_tlv_block(Type, Data) ->
    Size = byte_size(Data),
    <<Type:8, Size:16/big, Data/binary>>.

%% Wrap a clove in a TLV garlic_clove block
encode_clove_block(Clove) ->
    CloveBin = encode_clove(Clove),
    encode_tlv_block(?BLOCK_GARLIC_CLOVE, CloveBin).

%% Append padding TLV blocks to reach PadTo bytes
maybe_pad(Blocks, PadTo) when PadTo =< 0 ->
    Blocks;
maybe_pad(Blocks, PadTo) ->
    CurSize = iolist_size(Blocks),
    case CurSize >= PadTo of
        true ->
            Blocks;
        false ->
            PadNeed = PadTo - CurSize,
            PadDataSize = max(0, PadNeed - 3),
            PadBlocks = encode_tlv_block(?BLOCK_PADDING, <<0:PadDataSize/unit:8>>),
            Blocks ++ [PadBlocks]
    end.

%% TLV type number to atom
block_type(0) -> datetime;
block_type(1) -> session_id;
block_type(2) -> termination;
block_type(3) -> options;
block_type(4) -> next_key;
block_type(8) -> ack;
block_type(9) -> ack_request;
block_type(11) -> garlic_clove;
block_type(254) -> padding;
block_type(N) -> {unknown, N}.

%% Parse TLV blocks sequentially
decode_payload_loop(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_payload_loop(<<Type:8, Size:16/big, Data:Size/binary, Rest/binary>>, Acc) ->
    Block = decode_tlv_block(block_type(Type), Data),
    decode_payload_loop(Rest, [Block | Acc]);
decode_payload_loop(_, _Acc) ->
    error.

%% Parse a single TLV block into a map
decode_tlv_block(datetime, <<Timestamp:32/big>>) ->
    #{type => datetime, data => <<Timestamp:32/big>>, timestamp => Timestamp};
decode_tlv_block(garlic_clove, Data) ->
    case decode_clove(Data) of
        {ok, Clove} ->
            #{type => garlic_clove, data => Data, clove => Clove};
        error ->
            #{type => garlic_clove, data => Data}
    end;
decode_tlv_block(Type, Data) ->
    #{type => Type, data => Data}.

%% Noise N init for ECIES garlic (no null terminator in protocol name)
noise_n_garlic_init(StaticPub) ->
    H0 = crypto:hash(sha256, <<"Noise_N_25519_ChaChaPoly_SHA256">>),
    H1 = i2p_crypto:mixhash(H0, StaticPub),
    {H1, H0}.
