-module(i2p_relay).

-moduledoc """
Pure signing and codec helpers for SSU2 relay messages.

The module builds RelayRequest, RelayResponse, and RelayIntro blocks, including
the exact Ed25519-signed byte strings, endpoint encoding, reject-code helpers,
and out-of-session connection IDs. `m:i2p_ssu2` uses these helpers for the
wire blocks; see the [Relay](docs/protocol.md#relay) section of the protocol
reference for the message flow and field tables.

## Usage

```erlang
Block = i2p_relay:request_block(2, Nonce, Tag, Timestamp, Port, Ip, Signature).
```
""".

-export([
    prologue_request/0,
    prologue_response/0,
    signed_data_request/8,
    signed_data_response/6,
    sign_request/9,
    sign_response/7,
    verify_request/10,
    verify_response/8,
    request_block/7,
    response_block/8,
    intro_block/8,
    punch_blocks/4,
    dst_conn_id/1,
    src_conn_id/1,
    address_size/1,
    is_bob_reject/1,
    is_charlie_reject/1,
    is_reject/1
]).

-export_type([reject/0]).

-define(RELAY_REQUEST_PROLOGUE, <<"RelayRequestData">>).
-define(RELAY_RESPONSE_PROLOGUE, <<"RelayAgreementOK">>).

-doc """
The relay-request signing prologue.

The 16-byte literal that prefixes every block signed by Alice — her
RelayRequest (block 7) and the RelayIntro (block 9) Bob forwards from it.
""".
-spec prologue_request() -> <<_:128>>.
prologue_request() -> ?RELAY_REQUEST_PROLOGUE.

-doc """
The relay-response signing prologue.

The 16-byte literal that prefixes every RelayResponse (block 8) signed data:
by Charlie (accept or Charlie-side reject) or by Bob (Bob-side reject).
""".
-spec prologue_response() -> <<_:128>>.
prologue_response() -> ?RELAY_RESPONSE_PROLOGUE.

-doc """
Build the exact bytes a RelayRequest signature covers.

Input: `BobHash` — the 32-byte introducer router hash; `CharlieHash` — the
32-byte target router hash; the Alice-chosen 4-byte relay `Nonce`; the `Tag`
(the itag from Charlie's RouterInfo); the Unix `Timestamp`; the SSU version
(`2`); `Port` (0..65535); and Alice's `Ip` bytes (4 or 16).
Output: the byte string
`prologue "RelayRequestData" || BobHash || CharlieHash || nonce || tag || ts ||
ver || asz || port || ip`.
""".
-spec signed_data_request(
    binary(),
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    byte(),
    0..65535,
    binary()
) -> binary().
signed_data_request(BobHash, CharlieHash, Nonce, Tag, Ts, Ver, Port, Ip) ->
    <<?RELAY_REQUEST_PROLOGUE/binary, BobHash/binary, CharlieHash/binary, Nonce:32, Tag:32, Ts:32,
        Ver:8, (2 + byte_size(Ip)):8, Port:16, Ip/binary>>.

-doc """
Build the exact bytes a RelayResponse signature covers.

Input: `BobHash` — the introducer router hash; `Nonce`; the Unix `Timestamp`;
the SSU `Ver`; `Port`; and `Ip` (4 or 16 bytes, or `<<>>` when the endpoint is
absent, `csz 0`).
Output: the byte string
`prologue "RelayAgreementOK" || BobHash || nonce || ts || ver || csz ||
[port || ip]` — the port/IP pair is present only when the endpoint is.
""".
-spec signed_data_response(
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    byte(),
    0..65535,
    binary()
) -> binary().
signed_data_response(BobHash, Nonce, Ts, Ver, Port, Ip) ->
    Csz =
        case Ip of
            <<>> -> 0;
            _ -> 2 + byte_size(Ip)
        end,
    Endpoint =
        case Ip of
            <<>> -> <<>>;
            _ -> <<Port:16, Ip/binary>>
        end,
    <<?RELAY_RESPONSE_PROLOGUE/binary, BobHash/binary, Nonce:32, Ts:32, Ver:8, Csz:8,
        Endpoint/binary>>.

-doc """
Sign a RelayRequest (Alice).

Input: `BobHash` and `CharlieHash` (the signing context — they are not wire
fields); `Ver`; `Nonce`; `Tag`; `Timestamp`; `Port`; Alice's `Ip`; and the
`SignSeed` used to sign.
Output: a 64-byte Ed25519 signature.
""".
-spec sign_request(
    binary(),
    binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_seed()
) -> i2p_crypto:ed25519_signature().
sign_request(BobHash, CharlieHash, Ver, Nonce, Tag, Ts, Port, Ip, SignSeed) ->
    i2p_crypto:ed25519_sign(
        signed_data_request(BobHash, CharlieHash, Nonce, Tag, Ts, Ver, Port, Ip),
        SignSeed
    ).

-doc """
Sign a RelayResponse (Charlie on accept / Charlie-side reject; Bob on a
Bob-side reject).

Input: `BobHash`; `Ver`; `Nonce`; `Timestamp`; `Port` and `Ip` (the Charlie
endpoint, `<<>>` when absent); and the signer's `SignSeed`.
Output: a 64-byte Ed25519 signature.
""".
-spec sign_response(
    binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_seed()
) -> i2p_crypto:ed25519_signature().
sign_response(BobHash, Ver, Nonce, Ts, Port, Ip, SignSeed) ->
    i2p_crypto:ed25519_sign(
        signed_data_response(BobHash, Nonce, Ts, Ver, Port, Ip),
        SignSeed
    ).

-doc """
Verify a RelayRequest / RelayIntro signature (Alice's).

Input: `BobHash`; `CharlieHash`; `Ver`; `Nonce`; `Tag`; `Timestamp`; `Port`;
Alice's `Ip`; the `Signature`; and Alice's Ed25519 `SignPub`.
Output: `true` when the signature verifies against `f:signed_data_request/8`,
`false` otherwise.
""".
-spec verify_request(
    binary(),
    binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_signature(),
    i2p_crypto:ed25519_public_key()
) -> boolean().
verify_request(BobHash, CharlieHash, Ver, Nonce, Tag, Ts, Port, Ip, Signature, SignPub) ->
    i2p_crypto:ed25519_verify(
        signed_data_request(BobHash, CharlieHash, Nonce, Tag, Ts, Ver, Port, Ip),
        Signature,
        SignPub
    ).

-doc """
Verify a RelayResponse signature (Charlie's on accept / Charlie-side reject,
Bob's on a Bob-side reject).

Input: `BobHash`; `Ver`; `Nonce`; `Timestamp`; `Port`; `Ip` (`<<>>` when
absent); the `Signature`; and the signer's Ed25519 `SignPub`.
Output: `true` when the signature verifies against `f:signed_data_response/5`,
`false` otherwise.
""".
-spec verify_response(
    binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_signature(),
    i2p_crypto:ed25519_public_key()
) -> boolean().
verify_response(BobHash, Ver, Nonce, Ts, Port, Ip, Signature, SignPub) ->
    i2p_crypto:ed25519_verify(
        signed_data_response(BobHash, Nonce, Ts, Ver, Port, Ip),
        Signature,
        SignPub
    ).

-doc """
Construct a RelayRequest codec `block()` (block 7) for the given signed data.
""".
-spec request_block(
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    binary()
) -> i2p_ssu2:block().
request_block(Ver, Nonce, Tag, Ts, Port, Ip, Sig) ->
    {relay_request, 0, Nonce, Tag, Ts, Ver, Port, Ip, Sig}.

-doc """
Construct a RelayResponse codec `block()` (block 8) for the given signed data.

`Token` is `undefined` to omit the token (any reject, or an accept with no
granted token).
""".
-spec response_block(
    byte(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    binary(),
    undefined | non_neg_integer()
) -> i2p_ssu2:block().
response_block(Code, Ver, Nonce, Ts, Port, Ip, Sig, Token) ->
    {relay_response, 0, Code, Nonce, Ts, Ver, Port, Ip, Sig, Token}.

-doc """
Construct a RelayIntro codec `block()` (block 9).

`AliceHash` is Alice's 32-byte router hash; the rest is forwarded unmodified
from her RelayRequest, including her signature.
""".
-spec intro_block(
    byte(),
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    binary()
) -> i2p_ssu2:block().
intro_block(Ver, AliceHash, Nonce, Tag, Ts, Port, Ip, Sig) ->
    {relay_intro, 0, AliceHash, Nonce, Tag, Ts, Ver, Port, Ip, Sig}.

-doc """
The payload blocks of a Charlie HolePunch (type 11).

The datagram Charlie sends straight to Alice's asserted endpoint, in the order
the spec lists: a DateTime block, an Address block carrying **Charlie's** own
published endpoint (which is the address Alice then dials), the very
RelayResponse Charlie sent in-session to Bob, and Padding.

The response travels inside the punch as well as alongside it because Alice can
be reached by only one of the two: Bob's relay leg may be what delivered the
intro, and if the punch is what lands then the response has to arrive with it.

Input: the `Timestamp`; Charlie's own `Port` and `Ip`; and the
`relay_response` `t:i2p_ssu2:block/0` to carry.
Output: the block list to seal, AEAD-encrypted under Alice's introduction key by
`m:i2p_ssu2:encode_holepunch/5`.
""".
-spec punch_blocks(non_neg_integer(), 0..65535, binary(), i2p_ssu2:block()) ->
    [i2p_ssu2:block()].
punch_blocks(Ts, Port, Ip, Response) ->
    [{datetime, Ts}, {address, Port, Ip}, Response, {padding, <<0:(8 * 16)>>}].

-doc """
The out-of-session destination connection ID derived from a relay nonce.

Charlie→Alice (HolePunch) and the relay establishment use
`(nonce << 32) | nonce`.
""".
-spec dst_conn_id(non_neg_integer()) -> non_neg_integer().
dst_conn_id(Nonce) ->
    (Nonce bsl 32) bor Nonce.

-doc """
The out-of-session source connection ID derived from a relay nonce — the
bitwise inverse of the destination ID.
""".
-spec src_conn_id(non_neg_integer()) -> non_neg_integer().
src_conn_id(Nonce) ->
    (bnot dst_conn_id(Nonce)) band 16#FFFFFFFFFFFFFFFF.

-doc """
Endpoint address size for a relay block: `0` when the endpoint is absent,
`6` for a 4-byte IPv4 address, `18` for a 16-byte IPv6 address.
""".
-spec address_size(<<>> | <<_:32>> | <<_:128>>) -> 0 | 6 | 18.
address_size(<<>>) -> 0;
address_size(<<_:32>>) -> 6;
address_size(<<_:128>>) -> 18.

-doc """
`true` when `Code` is a RelayResponse reject by Bob (1-6): unspecified,
Charlie banned, limit exceeded, signature failure, relay tag not found, Alice
RouterInfo not found.
""".
-spec is_bob_reject(byte()) -> boolean().
is_bob_reject(Code) when Code >= 1, Code =< 6 -> true;
is_bob_reject(_) -> false.

-doc """
`true` when `Code` is a RelayResponse reject by Charlie (64-70): unspecified,
unsupported address, limit exceeded, signature failure, Alice already
connected, Alice banned, Alice unknown.
""".
-spec is_charlie_reject(byte()) -> boolean().
is_charlie_reject(Code) when Code >= 64, Code =< 70 -> true;
is_charlie_reject(_) -> false.

-doc """
`true` when `Code` is any relay reject (Bob 1-6, Charlie 64-70, or the
catch-all 128).
""".
-spec is_reject(byte()) -> boolean().
is_reject(Code) ->
    is_bob_reject(Code) orelse is_charlie_reject(Code) orelse Code == 128.

-doc """
A reject status code from a RelayResponse block (see `f:is_reject/1`).
""".
-type reject() :: byte().
