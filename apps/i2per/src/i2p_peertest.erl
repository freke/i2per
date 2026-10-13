-module(i2p_peertest).

-moduledoc """
Pure signing and codec helpers for SSU2 PeerTest messages.

PeerTest messages 1 through 7 carry a signed request, response, or reachability
result. This module owns the exact signed byte strings, Ed25519 verification,
connection-ID derivation, and the `peertest` block representation consumed by
`m:i2p_ssu2`. See the [Peer Test](docs/protocol.md#peer-test) section of the
protocol reference for the wire layout and message flow.

## Usage

```erlang
Block = i2p_peertest:block(1, 0, 0, RouterHash, 2, Nonce, Timestamp, Port, Ip, Signature).
```
""".

-export([
    prologue/0,
    signed_data/8,
    sign/8,
    verify/9,
    block/10,
    dst_conn_id/1,
    src_conn_id/1,
    address_size/1,
    is_bob_reject/1,
    is_charlie_reject/1,
    is_reject/1,
    result/3
]).

-export_type([address_type/0, result/0, reject/0, rung/0, reason/0]).

-define(PROLOGUE, <<"PeerTestValidate">>).

-doc """
The peer-test signing prologue.

The 16-byte literal `"PeerTestValidate"` that prefixes every data block signed
by Alice (message 1) or Charlie (message 3), so Ed25519 signatures never
collide across I2P message classes.
""".
-spec prologue() -> <<_:128>>.
prologue() -> ?PROLOGUE.

-doc """
Build the exact bytes an SSU2 PeerTest signature covers.

Input: `BobHash` — the 32-byte introducer router hash; `CharlieHash` — the
32-byte tester hash for messages 3 and 4, or `undefined` for messages 1 and 2;
the SSU version (`2`); the Alice-chosen 4-byte test `Nonce`; the Unix
`Timestamp`; the endpoint address size (`asz`: 6 or 18); `Port` (0..65535); and
the Alice `Ip` bytes (4 or 16).
Output: the byte string
`prologue "PeerTestValidate" || BobHash || CharlieHash? || ver || nonce || ts ||
asz || port || ip`.
""".
-spec signed_data(
    binary(),
    undefined | binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    6 | 18,
    0..65535,
    binary()
) -> binary().
signed_data(BobHash, CharlieHash, Ver, Nonce, Ts, Asz, Port, Ip) ->
    HashPart =
        case CharlieHash of
            undefined -> <<>>;
            _ -> CharlieHash
        end,
    <<?PROLOGUE/binary, BobHash/binary, HashPart/binary, Ver:8, Nonce:32, Ts:32, Asz:8, Port:16,
        Ip/binary>>.

-doc """
Sign a peer-test request (Alice, message 1) or response (Charlie, message 3).

Input: `BobHash`; `CharlieHash` (`undefined` for message 1, Charlie's hash for
message 3); the SSU `Ver`; `Nonce`; `Timestamp`; `Port`; Alice's `Ip`; and the
`SignSeed` used to sign.
Output: a 64-byte Ed25519 signature.
""".
-spec sign(
    binary(),
    undefined | binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_seed()
) -> i2p_crypto:ed25519_signature().
sign(BobHash, CharlieHash, Ver, Nonce, Ts, Port, Ip, SignSeed) ->
    i2p_crypto:ed25519_sign(
        signed_data(BobHash, CharlieHash, Ver, Nonce, Ts, 2 + byte_size(Ip), Port, Ip),
        SignSeed
    ).

-doc """
Verify an SSU2 PeerTest signature.

Input: `BobHash`; `CharlieHash` (`undefined` unless verifying messages 3/4);
`Ver`; `Nonce`; `Timestamp`; `Port`; Alice's `Ip`; the `Signature`; and the
signer's Ed25519 `SignPub`.
Output: `true` when the signature verifies against `f:signed_data/8`, `false`
otherwise.
""".
-spec verify(
    binary(),
    undefined | binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_signature(),
    i2p_crypto:ed25519_public_key()
) -> boolean().
verify(BobHash, CharlieHash, Ver, Nonce, Ts, Port, Ip, Signature, SignPub) ->
    i2p_crypto:ed25519_verify(
        signed_data(BobHash, CharlieHash, Ver, Nonce, Ts, 2 + byte_size(Ip), Port, Ip),
        Signature,
        SignPub
    ).

-doc """
Construct an SSU2 PeerTest payload `block()` (codec form) for any message.
""".
-spec block(
    1..7,
    byte(),
    byte(),
    binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    binary()
) -> i2p_ssu2:block().
block(MsgNum, Code, Flags, RouterHash, Ver, Nonce, Ts, Port, Ip, Sig) ->
    {peertest, MsgNum, Code, Flags, RouterHash, Ver, Nonce, Ts, Port, Ip, Sig}.

-doc """
The out-of-session destination connection ID derived from a test nonce.

For Charlie→Alice messages (5 and 7) the destination ID is
`(nonce << 32) | nonce`.
""".
-spec dst_conn_id(non_neg_integer()) -> non_neg_integer().
dst_conn_id(Nonce) ->
    (Nonce bsl 32) bor Nonce.

-doc """
The out-of-session source connection ID derived from a test nonce — the
bitwise inverse of the destination ID. Alice uses it as her source for the
Alice→Charlie message 6 (and as her expected destination of messages 5/7).
""".
-spec src_conn_id(non_neg_integer()) -> non_neg_integer().
src_conn_id(Nonce) ->
    (bnot dst_conn_id(Nonce)) band 16#FFFFFFFFFFFFFFFF.

-doc """
Endpoint address size for a peer-test: `6` for a 4-byte IPv4 address, `18` for
a 16-byte IPv6 address.
""".
-spec address_size(<<_:32>> | <<_:128>>) -> 6 | 18.
address_size(<<_:32>>) -> 6;
address_size(<<_:128>>) -> 18.

-doc """
`true` when `Code` is a Bob-side reject (1-5).
""".
-spec is_bob_reject(byte()) -> boolean().
is_bob_reject(Code) when Code >= 1, Code =< 5 -> true;
is_bob_reject(_) -> false.

-doc """
`true` when `Code` is a Charlie-side reject (64-70).
""".
-spec is_charlie_reject(byte()) -> boolean().
is_charlie_reject(Code) when Code >= 64, Code =< 70 -> true;
is_charlie_reject(_) -> false.

-doc """
`true` when `Code` is any reject (Bob 1-5, Charlie 64-70, or the catch-all 128).
""".
-spec is_reject(byte()) -> boolean().
is_reject(Code) ->
    is_bob_reject(Code) orelse is_charlie_reject(Code) orelse Code == 128.

-doc """
A tested address type: IPv4 or IPv6.
""".
-type address_type() :: ipv4 | ipv6.

-doc """
A rung of the reachability ladder.

`unknown` (not determined) · `testing` (a test is in flight) · `unreachable`
(no path reaches us) · `introducer_only` (a Charlie completes the punch and
session, but unsolicited inbound fails) · `reachable` (unsolicited inbound
works). Defined in CONTEXT.md; not reopened by the peer-test policy.
""".
-type rung() :: unknown | testing | unreachable | introducer_only | reachable.

-doc """
Where the reachability chain broke, per the peer-test policy's typed reasons.

`own_config` (the operator asserted inbound is impossible, so no test ran) ·
`clock_skew` (the peer's signed timestamp disagrees with ours) ·
`no_charlie_report` (the Charlie never confirmed the test arrived) ·
`punch_not_delivered` (it did confirm, but the unsolicited punch never came) ·
`punch_delivered_no_session` (punch arrived, no session request followed) ·
`session_incomplete` (both happened, the session never established).
""".
-type reason() ::
    own_config
    | clock_skew
    | no_charlie_report
    | punch_not_delivered
    | punch_delivered_no_session
    | session_incomplete.

-doc """
A concluded peer-test outcome: a ladder rung plus, when the chain broke, the
reason naming where. An `undefined` reason means the test succeeded — the
punch landed.
""".
-type result() :: {rung(), reason() | undefined}.

-doc """
A Bob- or Charlie-side peer-test reject status code (see `f:is_reject/1`).
""".
-type reject() :: byte().

-doc """
Resolve the reachability outcome of a concluded test.

Input: whether the in-session message 4 was an `accept` or a `reject`, and
whether the out-of-session messages 5 and 7 (Charlie→Alice) were received.
Waiting a few seconds after message 4 before judging lets an absent message 5
still be detected after the settle window.

Output: `{Rung, Reason}` per the implemented matrix — `reachable` when
Charlie's out-of-session message 5 arrived (unsolicited inbound works),
`{introducer_only, punch_not_delivered}` when the Charlie confirmed in-session
(message 4 accepted) but the unsolicited punch never landed — the
stateful-firewall case (message 7 is the solicited echo of our message 6, so
its arrival without message 5 is still a punch that did not deliver) — and
`{unknown, no_charlie_report}` when the test produced no usable evidence
(nothing arrived, the introducer rejected, or the confirm never came).

The spec is the matrix the clauses enumerate, not the whole of
`t:result/0`: the ladder's wider vocabulary (`testing`, `unreachable`, the
remaining reasons) is what the reachability fold and the event type accept,
and what the relay path's later work populates — not what this function
produces today.
""".
-spec result(accept | reject, boolean(), boolean()) ->
    {unknown, no_charlie_report}
    | {introducer_only, punch_not_delivered}
    | {reachable, undefined}.
result(reject, _S5, _S7) -> {unknown, no_charlie_report};
result(accept, false, false) -> {unknown, no_charlie_report};
result(accept, true, _S7) -> {reachable, undefined};
result(accept, false, true) -> {introducer_only, punch_not_delivered}.
