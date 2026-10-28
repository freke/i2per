-module(i2p_floodfill).

-moduledoc """
Floodfill election, store replication, and DHT observability.

This is a pure library module — no process, no state. It answers questions
about whether this router is a floodfill, which peers should receive a
replicated store, and how to build the forwarding messages. The actual
sending is done by `m:i2p_peer` via `f:m:i2p_peer:send_when_ready/2`.

## Floodfill election

A router declares itself a floodfill by including `f` in its RouterInfo caps
option. This module reads the `i2per` application env `floodfill` flag (boolean,
default `false`) to decide. When enabled, `m:i2p_identity:build_local/4`
includes the `f` cap in our RouterInfo, and this module returns `true`.

## Store replication

When a floodfill receives a DatabaseStore **with a nonzero reply token** (an
announcement from another router), it stores locally and then forwards the entry
to the three closest eligible floodfills in the NetDb — excluding itself and
the originator — with `reply_token = 0` (no DeliveryStatus expected from the
replication targets). This is i2pd's `NetDb::Store` replication path.

The token is not incidental to that condition, it **is** the condition:
`f:flood_requested/1` is the whole of it. A token-free store is a direct
announcement with no distribution asked for, and the references store it and
stop — i2pd's `if (replyToken && context.IsFloodfill () && updated)` at
`libi2pd/NetDb.cpp:925` and Java's
`_facade.floodfillEnabled() && _message.getReplyToken() > 0` at
`HandleFloodfillDatabaseStoreMessageJob.java:486`. Forwarding one anyway tells
the network to hold an entry nobody asked it to hold, and because the forwarded
copy also carries `reply_token = 0`, a mesh of us would hand it on again.

The `f:replication_outbox/5` function computes which peers should receive the
forwarded store and builds the corresponding I2NP messages, without sending
them. The caller (`m:i2p_peer`) iterates the outbox and sends each message via
`f:m:i2p_peer:send_when_ready/2`.

## Usage

```erlang
%% Check if this router is a floodfill.
i2p_floodfill:is_floodfill().

%% Check whether an inbound store asks for a re-flood, and only then compute the
%% outbox for it.
case i2p_floodfill:flood_requested(maps:get(reply_token, Store)) of
    false ->
        ok;
    true ->
        OurHash = i2p_router_info:hash(OurRI),
        Outbox = i2p_floodfill:replication_outbox(0, Key, RIData, OurHash, SenderHash),
        lists:foreach(fun({Target, Msg}) ->
            i2p_peer:send_when_ready(Target, Msg)
        end, Outbox)
end.
```
""".

-export([
    is_floodfill/0,
    capacity_ok/0,
    flood_requested/1,
    replication_outbox/5
]).

-export_type([]).

-doc """
Whether this router is a floodfill.

Reads the `i2per` application env `floodfill` flag, which may be `true`
(force on), `false` (force off, the default) or `auto` (decide from
`f:capacity_ok/0`, which checks the bandwidth class and published address
against i2pd's floodfill requirements).

Output: `true` when floodfill mode is enabled, `false` otherwise.
""".
-spec is_floodfill() -> boolean().
is_floodfill() ->
    case application:get_env(i2per, floodfill) of
        {ok, true} -> true;
        {ok, auto} -> capacity_ok();
        _ -> false
    end.

-doc """
Whether this router has the capacity and published presence i2pd requires
before it will act as a floodfill.

i2pd requires a public (published) NTCP2 address and a bandwidth class of
at least `O` (its default for a floodfill is `X`). A router below that
bandwidth or without a published address is not asked to be a floodfill,
because it cannot serve the NetDb load.

Output: `true` when the configured bandwidth class is `O` or higher and
NTCP2 is published, `false` otherwise.
""".
-spec capacity_ok() -> boolean().
capacity_ok() ->
    Bandwidth = application:get_env(i2per, caps_bandwidth, $L),
    Published = application:get_env(i2per, ntcp2_published, false),
    PublishedOk = (Published =:= true),
    BandwidthOk = lists:member(Bandwidth, [$O, $P, $X]),
    BandwidthOk andalso PublishedOk.

-doc """
Whether a DatabaseStore's reply token asks us to flood the entry on.

This is the whole of the re-flood condition that is not the floodfill role. Both
references gate on it and neither gates on anything else: i2pd's
`if (replyToken && context.IsFloodfill () && updated)` (`libi2pd/NetDb.cpp:925`)
and Java's `_facade.floodfillEnabled() && _message.getReplyToken() > 0`
(`HandleFloodfillDatabaseStoreMessageJob.java:486`).

`16#FFFFFFFF` **is** a request. i2pd skips only the DeliveryStatus reply for that
value (`if (replyToken != 0xFFFFFFFFU)`, `NetDb.cpp:822`) and still floods, so
reading it as a refusal here would flood differently from the implementation the
gate exists to match.

Input: the store's `reply_token`, `0..16#FFFFFFFF`.

Output: `true` for any nonzero token, `false` for zero.
""".
-spec flood_requested(0..16#FFFFFFFF) -> boolean().
flood_requested(0) -> false;
flood_requested(_Token) -> true.

-doc """
Compute the replication outbox for an incoming DatabaseStore.

Given a stored entry, returns a list of `{TargetHash, I2NPMessage}` tuples
representing the DatabaseStore messages to forward to the closest eligible
floodfills. Each message has `reply_token = 0` and `reply = undefined` (no
DeliveryStatus expected from replication targets).

Input: `StoreType` — `0` for RouterInfo, `1` for LeaseSet; `Key` — the 32-byte
hash of the stored object; `Data` — the raw payload bytes (`f:router_info_data/1`
output for a RouterInfo, raw content for a LeaseSet); `OurHash` — our router
hash (to exclude from targets); `SenderHash` — the originator's hash (to
exclude from targets).

Output: a list of `{TargetHash, I2NPMessage}` tuples, typically 0–3 entries.
Empty when no eligible floodfills are reachable or when the caller is not a
floodfill.

The reply token is not an argument here, so **the caller owns the
`f:flood_requested/1` half of the condition** — this function is only ever
reached for a store that asked to be flooded.
""".
-spec replication_outbox(byte(), i2p_crypto:hash(), binary(), i2p_crypto:hash(), i2p_crypto:hash()) ->
    [{i2p_crypto:hash(), i2p_i2np:i2np_message()}].
replication_outbox(StoreType, Key, Data, OurHash, SenderHash) ->
    %% Stays a case: the scrutinee is an is_floodfill() call, not
    %% guard-expressible.
    case is_floodfill() of
        false ->
            [];
        true ->
            Excluded = [OurHash, SenderHash],
            Targets = i2p_netdb_srv:closest_floodfills(Key, 3, Excluded),
            [{T, i2p_i2np:db_store(Key, StoreType, 0, undefined, Data)} || T <- Targets]
    end.
