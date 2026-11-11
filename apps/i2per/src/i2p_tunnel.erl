-module(i2p_tunnel).

%% OTP-28 dialyzer false positive: when gateway/5 is called from inside this
%% module (gateway_loop/7), dialyzer infers its record-producing clause as
%% unreachable and claims the {ok, _, _} match cannot succeed. Runtime
%% behaviour is covered by the multi-fragment gateway tests.
-dialyzer({nowarn_function, gateway_loop/7}).

-moduledoc """
ECIES tunnel build state machine, tunnel message processing, and relay.

Implements the core tunnel operations for ECIES-X25519 tunnels:

- Build request record construction and per-hop processing
- OTBRM reply construction (hop side) and creator-side reply peeling
- Per-hop AES-256-CBC layer encryption/decryption of tunnel messages
- Gateway fragmentation (TunnelGateway delivery instructions + message fragmentation)
- Tunnel data parsing (relay + fragment reassembly)

Everything here is stateless; the running tunnel manager, session table, and
pending build tracking live in `m:i2p_tunnel_srv`. This module provides the
pure crypto and framing operations that the manager calls.

## Usage

```erlang
%% Build a plaintext tunnel request record for a 3-hop outbound tunnel
Rec = i2p_tunnel:build_request_record(RecvID, NextID, NextHash, #{}),

%% Each hop processes the ShortTunnelBuild message addressed to it
{ok, #{role := transit} = HopInfo} =
    i2p_tunnel:process_short_tunnel_build(
        StaticPriv, StaticPub, OurIdHash, Records),

%% The hop seals its reply into its own slot, layers every other slot
%% with ChaCha20(reply_key, iv[slot]), and forwards the modified STB
Records' = i2p_tunnel:apply_build_reply(HopInfo, 0, Records),

%% Creator processes the returned OTBRM: strips relay layers, then
%% AEAD-opens each hop's own record to get the 202-byte reply plaintexts
{ok, ReplyPlaintexts} = i2p_tunnel:process_otbrm(OtbrmRecords, CreatorHops),

%% Gateway fragments an I2NP message into plaintext tunnel frames
{ok, Frame0, State1} =
    i2p_tunnel:gateway(TunnelID, local, undefined, StdMsg, #{}),

%% Inbound gateway applies its single layer; outbound gateways use
%% obgw_prep to pre-apply every hop's inverse layer instead
Wire = i2p_tunnel:encrypt_layer(Frame0, LayerKeys, IVKey),

%% Relay encrypts one layer on the transit side and re-addresses
{ok, ForwardMsg} = i2p_tunnel:process_tunnel_data(WireIn, HopConfig, NextID, MsgID),

%% Inbound endpoint (the creator) undoes every hop's layer
{ok, PlainFrame} = i2p_tunnel:ibep_unwrap(WireIn, HopLayerKeys),

%% Parse the plaintext tunnel data to recover the delivery instructions
{ok, Fragments, FragMap1} = i2p_tunnel:parse_tunnel_data(Payload, IV, FragMap0)
```
""".

-export([
    build_request_record/4,
    process_short_tunnel_build/4,
    apply_build_reply/3,
    process_otbrm/2,
    encrypt_layer/3,
    decrypt_layer/3,
    obgw_prep/2,
    ibep_unwrap/2,
    process_tunnel_data/4,
    parse_tunnel_data/3,
    gateway/5,
    gateway_all/4
]).

-export_type([
    hop_info/0,
    creator_hop/0,
    tunnel_data_state/0,
    layer_keys/0,
    fragment_state/0
]).

%%%%%%% %%% Types %%%%%%%

-doc """
The hop-side configuration produced by processing a build request record
addressed to us (`f:process_short_tunnel_build/4`).

`role` distinguishes a transit/middle hop (`transit`) from the outbound
endpoint (`endpoint`). The data-layer keys (`layer_key`, `iv_key`) come
from the `SMTunnelLayerKey` HKDF; the reply-sealing keys (`reply_key`,
`noise_h`) come from `SMTunnelReplyKey` and the Noise hash at our record.
`t:layer_keys/0` is embedded in this map for the data path.
""".
-type hop_info() :: #{
    role := transit | endpoint,
    record_index := non_neg_integer(),
    recv_tunnel_id := 0..16#FFFFFFFF,
    next_tunnel_id := 0..16#FFFFFFFF,
    next_hash := i2p_crypto:hash(),
    layer_enc_type := byte(),
    is_gateway := boolean(),
    layer_key := i2p_crypto:key(),
    iv_key := i2p_crypto:key(),
    reply_key := i2p_crypto:key(),
    noise_h := i2p_crypto:hash(),
    %% Endpoint-role records only: ExistingSession (RGarlic) wrap material
    %% for the outbound build reply this hop assembles and delivers.
    rgarlic_key => i2p_crypto:key() | undefined,
    rgarlic_tag => binary() | undefined
}.

-doc """
Creator-side per-hop keys, stored between sending a ShortTunnelBuild and
receiving the OTBRM.

Position in the list equals the record position. `reply_key` + `noise_h`
AEAD-open the hop's own reply record; `layer_key` + `iv_key` become the
active tunnel's data-layer keys after the build completes (see
`t:layer_keys/0`).
""".
-type creator_hop() :: #{
    reply_key := i2p_crypto:key(),
    layer_key := i2p_crypto:key(),
    iv_key := i2p_crypto:key(),
    noise_h := i2p_crypto:hash()
}.

-doc """
Per-hop AES-256-CBC tunnel message encryption/decryption keys.
""".
-type layer_keys() :: #{
    layer_key := i2p_crypto:key(),
    iv_key := i2p_crypto:key()
}.

-doc """
The relay-side tunnel data processing result, returned by
`f:process_tunnel_data/3` when the message is forwarded through the tunnel.
""".
-type tunnel_data_state() :: #{
    tunnel_id := 0..16#FFFFFFFF,
    msg_id := i2p_i2np:message_id(),
    next_tunnel_id := 0..16#FFFFFFFF,
    next_hash := i2p_crypto:hash()
}.

-doc """
Gateway fragmentation state, carried across multiple `f:gateway/4` calls.

- `current_msg` — the remaining I2NP message bytes
- `fragment_num` — the current fragment sequence number (0 = first)
- `frag_map` — fragment reassembly map keyed by message ID
""".
-type fragment_state() :: #{
    current_msg => binary(),
    fragment_num => non_neg_integer(),
    frag_map => #{i2p_i2np:message_id() := #{non_neg_integer() := binary()}}
}.

%%%%%%% %%% Tunnel Build Requests %%%%%%%

-doc """
Build a plaintext tunnel request record (154 bytes).

The record is populated with the given tunnel IDs and next router hash.
The creator calls this in a loop, generating fresh random values for the
optional fields on each call.

Input: `RecvTunnelID` — the receive tunnel ID for this hop;
`NextTunnelID` — the next hop's receive tunnel ID;
`NextRouterHash` — the 32-byte SHA-256 of the next router's identity;
`Flags` — `#{gateway => boolean(), endpoint => boolean()}` (default:
both false); `Options` — a `Mapping` binary (default: `<<0, 0>>` empty).
Output: the 154-byte plaintext record.
""".
-spec build_request_record(
    0..16#FFFFFFFF,
    0..16#FFFFFFFF,
    i2p_crypto:hash(),
    #{gateway => boolean(), endpoint => boolean(), options => binary()}
) -> binary().
build_request_record(RecvTunnelID, NextTunnelID, NextRouterHash, Opts) when
    byte_size(NextRouterHash) =:= 32
->
    GW = maps:get(gateway, Opts, false),
    EP = maps:get(endpoint, Opts, false),
    Options = maps:get(options, Opts, <<0, 0>>),
    Flag0 =
        case GW of
            true -> 16#80;
            false -> 0
        end bor
            case EP of
                true -> 16#40;
                false -> 0
            end,
    RequestTime = (erlang:system_time(second) div 60) band 16#FFFFFFFF,
    MsgID = crypto:strong_rand_bytes(4),
    <<RecvTunnelID:32/big, NextTunnelID:32/big, NextRouterHash/binary, Flag0:8, 0:16, 0:8,
        RequestTime:32/big, 600:32/big, MsgID/binary, Options/binary,
        (options_padding(byte_size(Options)))/binary>>.

-doc """
Process a ShortTunnelBuild message on the hop side.

Scans the record list for a prefix match on our truncated identity hash
(`i2p_ecies:find_own_record/2`), decrypts the matching record with the full
Noise N handshake, and interprets the plaintext request. Returns the hop
configuration (transit or endpoint role) carrying data-layer keys,
reply-sealing keys, and forwarding fields.

Per i2pd `TransitTunnelParticipant::HandleShortTunnelBuildMsg`, records that
do not match us, fail decryption, or carry a non-zero layer encryption type
are dropped silently (`error`, no reply record is ever sealed). A transit
record whose next hop is our own hash is likewise dropped.
""".
-spec process_short_tunnel_build(
    i2p_crypto:x25519_private_key(),
    i2p_crypto:x25519_public_key(),
    i2p_crypto:hash(),
    [binary()]
) -> {ok, hop_info()} | error.
process_short_tunnel_build(StaticPriv, StaticPub, OurIdHash, Records) ->
    case i2p_ecies:find_own_record(OurIdHash, Records) of
        error ->
            error;
        {ok, Index} ->
            EncRecord = lists:nth(Index + 1, Records),
            case i2p_ecies:decrypt_build_request_record(StaticPriv, StaticPub, EncRecord) of
                {ok, Plain, Hf, Ck1} ->
                    decode_record(Plain, Ck1, Index, Hf, OurIdHash);
                error ->
                    error
            end
    end.

-doc """
Seal this hop's build reply into a ShortTunnelBuild record list.

Replaces our own slot with the AEAD-encrypted 218-byte reply record
(`i2p_ecies:encrypt_reply_record/4`) and applies the relay layer
ChaCha20(reply_key, nonce[4 ‖ slot]) to every other slot
(`i2p_ecies:encrypt_reply_layer/3`), where the nonce counter is the *target*
slot's position. Both transit hops (forwarding the modified STB) and the
endpoint (assembling the OTBRM) use this same transformation before sending.

Input: `HopInfo` — our config from `f:process_short_tunnel_build/4`;
`RetCode` — 0 for accepted, 30 for rejected (e.g. bandwidth);
`Records` — the incoming 218-byte encrypted records.
Output: the transformed record list ready to forward.
""".
-spec apply_build_reply(hop_info(), 0..255, [binary()]) -> [binary()].
apply_build_reply(
    #{record_index := Idx, reply_key := RK, noise_h := Hf}, RetCode, Records
) ->
    OwnPlain = <<16#00, 16#00, (crypto:strong_rand_bytes(199))/binary, RetCode:8>>,
    {RevRecs, _} =
        lists:foldl(
            fun(Rec, {Acc, J}) ->
                Enc =
                    case J =:= Idx of
                        true -> i2p_ecies:encrypt_reply_record(RK, OwnPlain, Hf, J);
                        false -> i2p_ecies:encrypt_reply_layer(RK, Rec, J)
                    end,
                {[Enc | Acc], J + 1}
            end,
            {[], 0},
            Records
        ),
    lists:reverse(RevRecs).

-doc """
Process an OTBRM reply message (creator side).

Two-phase peel matching the forward-carried reply model:

1. Strip the surviving relay layers: slot J's reply record is concealed
   under exactly the reply keys of the hops that processed it AFTER its own
   hop (positions J+1 .. N-1 — earlier hops' layers cancelled their build-time
   preprocessing counterparts). Apply raw ChaCha20 decryption
   (`i2p_ecies:decrypt_reply_layer/3`) with those later hops' reply keys;
   stream XOR commutes, so application order does not affect the result.
   Each layer's nonce counter is the target slot's position.
2. AEAD-open each hop's own record with its reply key and Noise hash
   (`i2p_ecies:decrypt_reply_record/4`), yielding the 202-byte plaintext
   with the ret code at offset 201.

`Hops` must be in tunnel order (position = list index), as returned by
`m:i2p_ecies`'s `encrypt_build_records/3`. Returns `error` if any record
size is wrong or any AEAD open fails — e.g. when an upstream hop dropped
silently, making the whole build result unusable.
""".
-spec process_otbrm([binary()], [creator_hop()]) -> {ok, [binary()]} | error.
process_otbrm(Records, Hops) when
    length(Records) =:= length(Hops),
    Hops =/= []
->
    %% Stays a case: the scrutinee is a lists:all/2 call, not guard-expressible.
    case
        lists:all(
            fun
                (<<_:218/binary>>) -> true;
                (_) -> false
            end,
            Records
        )
    of
        true ->
            Stripped = strip_relay_layers(Records, Hops),
            open_own_records(Stripped, Hops, 0, []);
        false ->
            error
    end;
process_otbrm(_, _) ->
    error.

%%%%%%% %%% Tunnel Message Encryption/Decryption %%%%%%%

-doc """
Apply one AES-256-CBC encryption layer to a tunnel frame.

This is the operation every tunnel participant performs when forwarding
(per i2pd `TunnelEncryption`, spec "Participant Processing"):

1. `WorkIV = AES-ECB(ivKey, input[4..19])`
2. `output[20..1027] = AES-CBC(layerKey, WorkIV, input[20..1027])`
3. `output[4..19] = AES-ECB(ivKey, WorkIV)` (double-encrypted IV)

The inbound-tunnel gateway uses this same single-layer operation on frames
built by `f:gateway/5`; outbound gateways must instead use `f:obgw_prep/2`.

Input: `TunnelMsg` — a 1028-byte tunnel message (`tunnelID(4) ‖ iv(16) ‖ payload(1008)`);
`LayerKey` — 32-byte AES key; `IVKey` — 32-byte AES key.
Output: the encrypted 1028-byte tunnel message (`tunnelID(4) ‖ encIV(16) ‖ encData(1008)`).
""".
-spec encrypt_layer(<<_:8224>>, <<_:256>>, <<_:256>>) -> <<_:8224>>.
encrypt_layer(<<TunnelID:32/big, Payload:1024/binary>>, LayerKey, IVKey) ->
    <<PlainIV:16/binary, PlainData:1008/binary>> = Payload,
    EncIV = aes_ecb_encrypt(IVKey, PlainIV),
    EncData = i2p_crypto:aes256cbc_encrypt(LayerKey, EncIV, PlainData),
    DoubleEncIV = aes_ecb_encrypt(IVKey, EncIV),
    <<TunnelID:32/big, DoubleEncIV/binary, EncData/binary>>;
encrypt_layer(_, _, _) ->
    error(badarg).

-doc """
Single-hop AES-256-CBC tunnel message decryption.

The exact inverse of `f:encrypt_layer/3` (useful for creator-side frame
construction and tests):

1. `WorkIV = AES-ECB-decrypt(ivKey, input[4..19])`
2. `output[20..1027] = AES-CBC-decrypt(layerKey, WorkIV, input[20..1027])`
3. `output[4..19] = AES-ECB-decrypt(ivKey, WorkIV)` (recover plaintext IV)
""".
-spec decrypt_layer(<<_:8224>>, <<_:256>>, <<_:256>>) -> <<_:8224>>.
decrypt_layer(<<TunnelID:32/big, EncPayload:1024/binary>>, LayerKey, IVKey) ->
    <<EncDoubleIV:16/binary, EncData:1008/binary>> = EncPayload,
    SingleEncIV = aes_ecb_decrypt(IVKey, EncDoubleIV),
    PlainData = i2p_crypto:aes256cbc_decrypt(LayerKey, SingleEncIV, EncData),
    PlainIV = aes_ecb_decrypt(IVKey, SingleEncIV),
    <<TunnelID:32/big, PlainIV:16/binary, PlainData:1008/binary>>;
decrypt_layer(_, _, _) ->
    error(badarg).

-doc """
Pre-encrypt a plaintext tunnel frame at an outbound-tunnel gateway.

Per the tunnel-message spec, transit participants always *encrypt* one layer
as they forward, so the outbound gateway must apply the inverse operation —
an iterative AES-CBC *decryption* with every hop's layer key, endpoint's key
first — so that the plaintext pops out exactly at the endpoint. The IV chain
is likewise derived backwards from the frame's IV so the endpoint receives
the same IV value the gateway's checksum was computed against.

Input: `TunnelMsg` — a plaintext 1028-byte frame
(`tunnelID(4) ‖ randomIV(16) ‖ payload(1008)`) as produced by `f:gateway/5`;
`Hops` — the tunnel's `t:layer_keys/0` in tunnel order (first hop to last).
Output: the wire message to send to the first hop.
""".
-spec obgw_prep(<<_:8224>>, [layer_keys()]) -> <<_:8224>>.
obgw_prep(<<TunnelID:32/big, FinalIV:16/binary, Plain:1008/binary>>, Hops) ->
    {RecvIV, Data} =
        lists:foldl(
            fun(#{layer_key := LK, iv_key := IVK}, {NextIV, Acc}) ->
                WorkIV = aes_ecb_decrypt(IVK, NextIV),
                PrevIV = aes_ecb_decrypt(IVK, WorkIV),
                {PrevIV, i2p_crypto:aes256cbc_decrypt(LK, WorkIV, Acc)}
            end,
            {FinalIV, Plain},
            lists:reverse(Hops)
        ),
    <<TunnelID:32/big, RecvIV/binary, Data/binary>>;
obgw_prep(_, _) ->
    error(badarg).

-doc """
Recover the gateway's plaintext frame at an inbound-tunnel endpoint.

The endpoint of an inbound tunnel is its creator and knows every hop's
keys: it iteratively undoes each hop's participant encryption in reverse
order (AES-ECB-decrypt the IV twice per hop, AES-CBC-decrypt the data once).

Input: `TunnelMsg` — the wire frame received from the nearest hop
(`tunnelID(4) ‖ iv(16) ‖ data(1008)`); `Hops` — the tunnel's
`t:layer_keys/0` in tunnel order (first hop = IBGW to last).
Output: `{ok, PlainFrame}` — the gateway's original plaintext frame ready
for checksum validation and fragment parsing.
""".
-spec ibep_unwrap(<<_:8224>>, [layer_keys()]) -> {ok, <<_:8224>>} | error.
ibep_unwrap(<<TunnelID:32/big, IV:16/binary, Data0:1008/binary>>, Hops) ->
    {Plain, IV0} =
        lists:foldl(
            fun(#{layer_key := LK, iv_key := IVK}, {Data, RecvIV}) ->
                WorkIV = aes_ecb_decrypt(IVK, RecvIV),
                Data1 = i2p_crypto:aes256cbc_decrypt(LK, WorkIV, Data),
                {Data1, aes_ecb_decrypt(IVK, WorkIV)}
            end,
            {Data0, IV},
            lists:reverse(Hops)
        ),
    {ok, <<TunnelID:32/big, IV0/binary, Plain/binary>>};
ibep_unwrap(_, _) ->
    error.

-doc """
Process an incoming tunnel data message on the transit side (relay).

Per the tunnel-message spec every participant *encrypts* one layer as it
forwards: AES-ECB-encrypt the received IV with the IV key to obtain the
working IV, AES-CBC-encrypt the data with the layer key under that working
IV, then ECB-encrypt the working IV again for the outgoing header. The
tunnel ID is replaced with the next hop's receive tunnel ID.

Input: `TunnelMsg` — the incoming 1028-byte tunnel message;
`HopConfig` — the hop config (from `f:process_short_tunnel_build/4`);
`NextTunnelID` — the next hop's receive tunnel ID;
`NextMsgID` — a fresh 4-byte message ID for the forwarded I2NP header.
Output: `{ok, ForwardMsg}` — the tunnel message ready for forwarding to the
next hop (with the next hop's tunnel ID prepended).
""".
-spec process_tunnel_data(binary(), hop_info(), 0..16#FFFFFFFF, i2p_i2np:message_id()) ->
    {ok, binary()} | error.
process_tunnel_data(
    <<_TunnelID:32/big, RecvIV:16/binary, Data:1008/binary>> = _TunnelMsg,
    HopConfig,
    NextTunnelID,
    _NextMsgID
) ->
    #{layer_key := LK, iv_key := IVK} = HopConfig,
    WorkIV = aes_ecb_encrypt(IVK, RecvIV),
    EncData = i2p_crypto:aes256cbc_encrypt(LK, WorkIV, Data),
    NextIV = aes_ecb_encrypt(IVK, WorkIV),
    {ok, <<NextTunnelID:32/big, NextIV/binary, EncData/binary>>};
process_tunnel_data(_, _, _, _) ->
    error.

-doc """
Compute the tunnel data checksum for a plaintext payload.

The checksum is the first 4 bytes of SHA-256(remaining_bytes ‖ IV).
""".
-spec checksum(binary(), binary()) -> <<_:32>>.
checksum(Payload, IV) ->
    Hash = crypto:hash(sha256, <<Payload/binary, IV/binary>>),
    <<Cksum:4/binary, _/binary>> = Hash,
    Cksum.

%%%%%%% %%% Gateway Fragmentation %%%%%%%

-doc """
Fragment an I2NP message into tunnel data delivery instructions.

Produces one or more 1028-byte plaintext tunnel messages. Each message
contains the tunnel ID (4 bytes), a random IV (16 bytes), and the encrypted
payload (1008 bytes).

The plaintext payload layout is:
`checksum(4) ‖ nonzero_padding ‖ 0x00 ‖ delivery_instructions ‖ message_fragment(s)`

The checksum is the first 4 bytes of SHA-256(remaining_bytes ‖ IV).

The `FragmentState` tracks how much of the current message has been sent and
the current fragment sequence number. Pass `#{frag_map => #{}}` to start.

Input: `TunnelID` — the tunnel to deliver into;
`DeliveryType` — `local | tunnel | router`;
`Target` — `undefined` (local), `{TunnelID, Hash}` (tunnel), or `Hash` (router);
`StdMsg` — the raw I2NP message (with standard 16-byte header);
`State` — the `t:fragment_state/0`.
Output: `{ok, TunnelWire, State'}` where `TunnelWire` is the 1028-byte
plaintext tunnel message, or `done` when the message has been fully sent.
""".
-spec gateway(
    0..16#FFFFFFFF,
    local | tunnel | router,
    undefined | {0..16#FFFFFFFF, i2p_crypto:hash()} | i2p_crypto:hash(),
    binary(),
    fragment_state()
) -> {ok, binary(), fragment_state()} | done.
gateway(_TunnelID, _DeliveryType, _Target, <<>>, State) when not is_map_key(current_msg, State) ->
    done;
gateway(_TunnelID, _DeliveryType, _Target, _Msg, #{current_msg := <<>>}) ->
    done;
gateway(TunnelID, DeliveryType, Target, Msg, State) ->
    Remaining = maps:get(current_msg, State, Msg),
    FragNum = maps:get(fragment_num, State, 0),
    MsgID = maps:get(msg_id, State, undefined),
    {ok, PayloadBody, MsgID1, State1} = write_fragment_body(
        DeliveryType, Target, Remaining, FragNum, MsgID
    ),
    IV = crypto:strong_rand_bytes(16),
    Checksum = checksum(PayloadBody, IV),
    EncPayload = <<Checksum/binary, PayloadBody/binary>>,
    {ok, <<TunnelID:32/big, IV/binary, EncPayload/binary>>, State1#{
        fragment_num => FragNum + 1, msg_id => MsgID1
    }}.

-doc """
Fragment an I2NP message into ALL of its plaintext tunnel frames.

Drives `f:gateway/5` to completion: produces one frame per fragment (in
order) plus the terminal fragment state, which callers store so later
messages continue the numbering.

Input: same arguments as `f:gateway/5` minus the running state; `Msg` must
be non-empty.
Output: `{Frames, FragmentState}` — the ordered plaintext frames ready for
per-hop encryption, and the terminal fragmentation state.
""".
-spec gateway_all(
    0..16#FFFFFFFF,
    local | tunnel | router,
    undefined | {0..16#FFFFFFFF, i2p_crypto:hash()} | i2p_crypto:hash(),
    binary()
) -> {[binary()], fragment_state()}.
gateway_all(TunnelID, DeliveryType, Target, Msg) when byte_size(Msg) > 0 ->
    gateway_loop(TunnelID, DeliveryType, Target, Msg, Msg, [], #{
        fragment_num => 0
    }).

%% gateway_loop/7 — accumulate frames while fragments remain. The done
%% arm is a belt-and-braces terminator: the first clause already stops on
%% an empty remainder.
gateway_loop(_TunnelID, _DeliveryType, _Target, <<>>, _Sent, Acc, State) ->
    {lists:reverse(Acc), State};
gateway_loop(TunnelID, DeliveryType, Target, Remaining, _Sent, Acc, State) ->
    case gateway(TunnelID, DeliveryType, Target, Remaining, State#{current_msg => Remaining}) of
        {ok, Frame, State1} ->
            gateway_loop(
                TunnelID,
                DeliveryType,
                Target,
                maps:get(current_msg, State1),
                Remaining,
                [Frame | Acc],
                State1
            );
        done ->
            {lists:reverse(Acc), State}
    end.

-doc """
Parse a decrypted tunnel data payload, extracting delivery instructions
and message fragments.

Input: `Payload` — the 1008-byte plaintext encrypted portion of a tunnel
message (checksum ‖ rest), after decryption and tunnel-ID stripping;
`IV` — the 16-byte plaintext IV from the tunnel message;
`FragMap` — the current fragment reassembly map `#{MsgID => #{FragNum => Data}}`.
Output: `{ok, Fragments, FragMap'}` where `Fragments` is a list of parsed
fragments (each a map), or `error` for an invalid payload or bad checksum.
""".
-spec parse_tunnel_data(binary(), binary(), #{
    i2p_i2np:message_id() := #{non_neg_integer() := binary()}
}) ->
    {ok, [map()], #{i2p_i2np:message_id() := #{non_neg_integer() := binary()}}} | error.
parse_tunnel_data(Payload, IV, FragMap) when
    byte_size(Payload) =:= 1008,
    byte_size(IV) =:= 16
->
    <<Cksum:4/binary, Rest/binary>> = Payload,
    %% Stays a case: Cksum is already bound, so this branch is an equality
    %% test — a head clause here would silently rebind it instead.
    case checksum(Rest, IV) of
        Cksum ->
            case parse_fragments(Rest, FragMap, []) of
                {ok, Fragments, FragMap1} ->
                    {ok, Fragments, FragMap1};
                error ->
                    error
            end;
        _ ->
            error
    end;
parse_tunnel_data(_, _, _) ->
    error.

%%%%%%% %%% Internal %%%%%%%

%% options_padding/1 — random padding after the options Mapping to fill the
%% remaining space in the 154-byte plaintext record (offsets 56..153).
options_padding(OptSize) ->
    PadSize = max(0, 98 - OptSize),
    case PadSize of
        0 -> <<>>;
        _ -> crypto:strong_rand_bytes(PadSize)
    end.

%% aes_ecb_encrypt/2 — AES-256-ECB encrypt a single 16-byte block.
-spec aes_ecb_encrypt(i2p_crypto:key(), binary()) -> <<_:128>>.
aes_ecb_encrypt(Key, <<Block:16/binary>>) ->
    crypto:crypto_one_time(aes_256_ecb, Key, Block, true).

%% aes_ecb_decrypt/2 — AES-256-ECB decrypt a single 16-byte block.
-spec aes_ecb_decrypt(i2p_crypto:key(), binary()) -> <<_:128>>.
aes_ecb_decrypt(Key, <<Block:16/binary>>) ->
    crypto:crypto_one_time(aes_256_ecb, Key, Block, false).

%% decode_record/5 — interpret a decrypted 154-byte request plaintext and
%% build the hop_info map. Applies i2pd's silent-drop checks: non-zero layer
%% encryption type, and a transit record whose next hop is our own hash.
decode_record(Plain, Ck1, Index, Hf, OurIdHash) ->
    <<RecvID:32/big, NextID:32/big, NextHash:32/binary, Flag:8, _MoreFlags:16, EncType:8,
        _ReqTime:32, _ReqExp:32, _MsgID:32/binary, _Rest/binary>> = Plain,
    IsGW = (Flag band 16#80) =/= 0,
    IsEP = (Flag band 16#40) =/= 0,
    case {EncType =:= 0, IsEP orelse NextHash =/= OurIdHash} of
        {true, true} ->
            Keys =
                case IsEP of
                    true -> i2p_ecies:derive_obep_keys(Ck1);
                    false -> i2p_ecies:derive_reply_layer_keys(Ck1)
                end,
            {ok, #{
                role =>
                    case IsEP of
                        true -> endpoint;
                        false -> transit
                    end,
                record_index => Index,
                recv_tunnel_id => RecvID,
                next_tunnel_id => NextID,
                next_hash => NextHash,
                layer_enc_type => EncType,
                is_gateway => IsGW,
                layer_key => maps:get(layer_key, Keys),
                iv_key => maps:get(iv_key, Keys),
                reply_key => maps:get(reply_key, Keys),
                noise_h => Hf,
                rgarlic_key => maps:get(rgarlic_key, Keys, undefined),
                rgarlic_tag => maps:get(rgarlic_tag, Keys, undefined)
            }};
        _ ->
            error
    end.

%% strip_relay_layers/2 — peel each slot's surviving relay layers. Slot J
%% carries the reply keys of hops J+1 .. N-1 (hops after it); earlier hops'
%% layers cancelled their build-time preprocessing counterparts. Stream XOR
%% commutes, so ascending application order is equivalent to any other.
strip_relay_layers(Records, Hops) ->
    lists:map(
        fun({J, Rec}) ->
            LaterKeys = [RK || {K, #{reply_key := RK}} <- indexed(Hops), K > J],
            lists:foldl(
                fun(RK, Acc) -> i2p_ecies:decrypt_reply_layer(RK, Acc, J) end,
                Rec,
                LaterKeys
            )
        end,
        indexed(Records)
    ).

%% open_own_records/4 — AEAD-open every hop's own reply record after all
%% relay layers are stripped. Any failure invalidates the whole build reply.
open_own_records(_Records, [], _K, Acc) ->
    {ok, lists:reverse(Acc)};
open_own_records(Records, [#{reply_key := RK, noise_h := Hf} | Rest], K, Acc) ->
    case i2p_ecies:decrypt_reply_record(RK, lists:nth(K + 1, Records), Hf, K) of
        {ok, Plain} ->
            open_own_records(Records, Rest, K + 1, [Plain | Acc]);
        error ->
            error
    end.

%% indexed/1 — pair each element with its 0-based position.
indexed(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).

%% write_fragment_body/4 — write one tunnel data fragment into a raw payload body
%% (without the 4-byte checksum prefix). The caller adds the checksum.
%% Returns {ok, PayloadBody, MsgID, State'}.
write_fragment_body(DeliveryType, Target, Msg, FragNum, MsgID) ->
    IsFirst = FragNum =:= 0,
    %% Compute base header size (without MsgID) to determine if fragmented
    BaseHeaderSize0 = base_extra_header_size(DeliveryType, IsFirst),
    %% Max data without MsgID: 1003 - flag(1) - base_header - size(2)
    MaxDataNoID = 1003 - 1 - BaseHeaderSize0 - 2,
    IsFragmented = byte_size(Msg) > MaxDataNoID,
    %% Generate MsgID on first fragment if fragmented
    {MsgID1, MsgIDSize} =
        case IsFirst andalso IsFragmented of
            true -> {MsgID =:= undefined andalso crypto:strong_rand_bytes(4), 4};
            false when not IsFirst -> {MsgID, 4};
            false -> {MsgID, 0}
        end,
    MsgID1Actual =
        case MsgID1 of
            false -> MsgID;
            _ -> MsgID1
        end,
    MaxData = MaxDataNoID - MsgIDSize,
    DataSize = min(byte_size(Msg), MaxData),
    FragmentData = binary:part(Msg, 0, DataSize),
    Remaining = binary:part(Msg, DataSize, byte_size(Msg) - DataSize),
    {Flag0, ExtraHeader} = fragment_header(
        DeliveryType, Target, FragNum, IsFirst, IsFragmented, MsgID1Actual
    ),
    Last = Remaining =:= <<>>,
    Flag =
        Flag0 bor
            (case Last of
                true -> 1;
                false -> 0
            end),
    Instructions = <<Flag:8, ExtraHeader/binary, DataSize:16/big, FragmentData/binary>>,
    %% Total payload body (rest after checksum) = 0x00 + padding + instructions = 1004 bytes
    TargetSize = 1003 - byte_size(Instructions),
    Padding = random_nonzero_padding(TargetSize),
    PayloadBody = <<Padding/binary, 0:8, Instructions/binary>>,
    State = #{current_msg => Remaining},
    {ok, PayloadBody, MsgID1Actual, State}.

%% base_extra_header_size/2 — size of non-MsgID header bytes for first fragments.
base_extra_header_size(local, true) -> 0;
base_extra_header_size(local, false) -> 0;
%% hash(32) + tunID(4)
base_extra_header_size(tunnel, true) -> 36;
base_extra_header_size(tunnel, false) -> 0;
%% hash(32)
base_extra_header_size(router, true) -> 32;
base_extra_header_size(router, false) -> 0.

%% fragment_header/6 — build the flag byte and extra header bytes.
%% When Fragmented is true, MsgID (4 bytes) is included in the header.
%% Flag bits: 7=first(0)/follow-on(1), 6-5=delivery(00=local,01=tunnel,10=router),
%%            3=fragmented, 0=last.
%% Returns {Flag, ExtraHeader}.
%% --- LOCAL (delivery type 00 = 0x00) ---
fragment_header(local, undefined, 0, true, false, _MsgID) ->
    {0, <<>>};
fragment_header(local, undefined, 0, true, true, MsgID) ->
    {(1 bsl 3), <<MsgID/binary>>};
fragment_header(local, undefined, FragNum, false, _IsFrag, MsgID) when FragNum > 0 ->
    FragBits = (FragNum band 16#3F) bsl 1,
    {16#80 bor FragBits, <<MsgID/binary>>};
%% --- TUNNEL (delivery type 01 = 0x20) ---
fragment_header(tunnel, {TunID, Hash}, 0, true, false, _MsgID) ->
    {(1 bsl 5), <<TunID:32/big, Hash/binary>>};
fragment_header(tunnel, {TunID, Hash}, 0, true, true, MsgID) ->
    {(1 bsl 5) bor (1 bsl 3), <<TunID:32/big, Hash/binary, MsgID/binary>>};
fragment_header(tunnel, {_TunID, _Hash}, 0, false, _IsFrag, _MsgID) ->
    {(1 bsl 5) bor (1 bsl 3) bor 1, <<>>};
fragment_header(tunnel, {_TunID, _Hash}, FragNum, false, _IsFrag, MsgID) when FragNum > 0 ->
    FragBits = (FragNum band 16#3F) bsl 1,
    {16#80 bor FragBits, <<MsgID/binary>>};
%% --- ROUTER (delivery type 10 = 0x40) ---
fragment_header(router, Hash, 0, true, false, _MsgID) ->
    {(2 bsl 5), <<Hash/binary>>};
fragment_header(router, Hash, 0, true, true, MsgID) ->
    {(2 bsl 5) bor (1 bsl 3), <<Hash/binary, MsgID/binary>>};
fragment_header(router, _Hash, 0, false, _IsFrag, _MsgID) ->
    {(2 bsl 5) bor (1 bsl 3) bor 1, <<>>};
fragment_header(router, _Hash, FragNum, false, _IsFrag, MsgID) when FragNum > 0 ->
    FragBits = (FragNum band 16#3F) bsl 1,
    {16#80 bor FragBits, <<MsgID/binary>>}.

%% parse_fragments/3 — parse the delivery instructions and fragments from the
%% payload body (after checksum). Scans for the 0x00 delimiter, then parses
%% one or more delivery instructions.
parse_fragments(Payload, FragMap, Acc) ->
    case scan_delimiter(Payload) of
        {ok, Instructions} ->
            parse_delivery_instructions(Instructions, FragMap, Acc);
        error ->
            error
    end.

%% scan_delimiter/1 — find the first 0x00 byte in the payload (the delimiter
%% between nonzero padding and the instructions).
scan_delimiter(<<>>) -> error;
scan_delimiter(<<0:8, Rest/binary>>) -> {ok, Rest};
scan_delimiter(<<_:8, Rest/binary>>) -> scan_delimiter(Rest).

%% parse_delivery_instructions/3 — parse one or more fragments from the
%% instructions portion (after the 0x00 delimiter).
parse_delivery_instructions(<<>>, FragMap, Acc) ->
    {ok, lists:reverse(Acc), FragMap};
parse_delivery_instructions(<<Flag:8, Rest/binary>>, FragMap, Acc) ->
    IsFirst = (Flag band 16#80) =:= 0,
    DeliveryType = (Flag bsr 5) band 16#03,
    Fragmented = (Flag band 16#08) =/= 0,
    case IsFirst of
        true ->
            case parse_first_fragment(Flag, DeliveryType, Fragmented, Rest, FragMap) of
                {ok, Fragment, Rem, FragMap1} ->
                    parse_delivery_instructions(Rem, FragMap1, [Fragment | Acc]);
                error ->
                    error
            end;
        false ->
            FragNum = (Flag bsr 1) band 16#3F,
            Last = (Flag band 16#01) =/= 0,
            case Rest of
                <<MsgID:4/binary, _Size:16/big, FragData:_Size/binary, Rem/binary>> ->
                    Fragment = #{
                        type => follow_on,
                        msg_id => MsgID,
                        frag_num => FragNum,
                        last => Last,
                        data => FragData
                    },
                    FragMap1 = add_fragment(FragMap, MsgID, FragNum, FragData, Last),
                    parse_delivery_instructions(Rem, FragMap1, [Fragment | Acc]);
                _ ->
                    error
            end
    end;
parse_delivery_instructions(_, _, _) ->
    error.

%% parse_first_fragment/5 — parse a first-fragment delivery instruction.
%% Returns {ok, Fragment, RemainingBinary, FragMap'}.
parse_first_fragment(Flag, DeliveryType, Fragmented, Rest, FragMap) ->
    Last = (Flag band 16#01) =/= 0,
    case DeliveryType of
        0 ->
            %% LOCAL: flag(1) + msg_id(4 if fragmented) + size(2)
            first_fragment(Rest, FragMap, local, #{}, Last, Fragmented);
        1 ->
            %% TUNNEL: flag(1) + tunnel_id(4) + to_hash(32) + msg_id(4 if frag) + size(2)
            case Rest of
                <<TunID:32/big, ToHash:32/binary, Tail/binary>> ->
                    first_fragment(
                        Tail,
                        FragMap,
                        tunnel,
                        #{tunnel_id => TunID, to_hash => ToHash},
                        Last,
                        Fragmented
                    );
                _ ->
                    error
            end;
        2 ->
            %% ROUTER: flag(1) + to_hash(32) + msg_id(4 if frag) + size(2)
            case Rest of
                <<ToHash:32/binary, Tail/binary>> ->
                    first_fragment(Tail, FragMap, router, #{to_hash => ToHash}, Last, Fragmented);
                _ ->
                    error
            end;
        3 ->
            error
    end.

%% first_fragment/6 — split the msg-id/size-prefixed payload off the tail and
%% build the first-fragment map for any delivery type. A fragmented first
%% fragment carries its message ID on the wire and seeds the reassembly map;
%% an unfragmented one gets a fresh random ID and is complete on arrival.
first_fragment(
    <<MsgID:4/binary, _Size:16/big, FragData:_Size/binary, Rem/binary>>,
    FragMap,
    Delivery,
    Extra,
    FlagLast,
    true
) ->
    Fragment = fragment_map(Delivery, Extra, MsgID, FlagLast, FragData),
    {ok, Fragment, Rem, add_fragment(FragMap, MsgID, 0, FragData, FlagLast)};
first_fragment(
    <<_Size:16/big, FragData:_Size/binary, Rem/binary>>, FragMap, Delivery, Extra, _FlagLast, false
) ->
    MsgID = crypto:strong_rand_bytes(4),
    Fragment = fragment_map(Delivery, Extra, MsgID, true, FragData),
    {ok, Fragment, Rem, FragMap};
first_fragment(_Tail, _FragMap, _Delivery, _Extra, _FlagLast, _FlagFirst) ->
    error.

%% fragment_map/5 — the common first-fragment shape; Extra carries the
%% delivery-specific header fields (tunnel_id/to_hash).
fragment_map(Delivery, Extra, MsgID, Last, Data) ->
    maps:merge(Extra, #{
        type => first,
        delivery => Delivery,
        msg_id => MsgID,
        frag_num => 0,
        last => Last,
        data => Data
    }).

%% add_fragment/4 — add a fragment to the reassembly map.
add_fragment(FragMap, MsgID, FragNum, Data, Last) ->
    MsgFrags = maps:get(MsgID, FragMap, #{}),
    MsgFrags1 = MsgFrags#{FragNum => Data},
    MsgFrags2 =
        case Last of
            true -> MsgFrags1#{last => FragNum};
            false -> MsgFrags1
        end,
    FragMap#{MsgID => MsgFrags2}.

%% random_nonzero_padding/1 — generate random nonzero bytes for padding.
random_nonzero_padding(N) when N =< 0 ->
    <<>>;
random_nonzero_padding(N) ->
    list_to_binary([X bor 1 || <<X:8>> <= crypto:strong_rand_bytes(N)]).
