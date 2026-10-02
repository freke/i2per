-module(i2p_events).

-moduledoc """
Router-wide status event bus (`gen_event` manager).

State changes across the router are announced here so external observers —
notably the separate `i2per_status` web service — can follow them in real
time. Handlers run on the manager's node; subscribers on OTHER nodes install
the router-shipped forwarder `m:i2p_events_forward` instead of their own code:

```erlang
ok = gen_event:add_handler({i2p_events, RouterNode}, i2p_events_forward, [self()]).
receive {event, Event} -> ... end.
```

Emitted events (`t:event/0`):

- `{peer_connected, PeerHash}` / `{peer_disconnected, PeerHash}` /
  `{peer_connect_failed, PeerHash, Reason, BackoffSeconds}` — a connect that
  did not become a connection, with the interval the router will now wait
- `{ssu2_dial_parked, PeerHash, Reason}` — a dial sat on SSU2, gave up, and
  went to NTCP2 instead, with the reason it gave up. Distinct from
  `peer_connect_failed`, which needs *both* legs to fail and so never fires
  for a peer that connected over TCP: a park costs real time and connects
  anyway, so the fact that would report it had no instrument
- `{peer_send_stalled, PeerHash, Reason}` — a peer stopped accepting our sends
- `{tunnel_built, Direction, Hops}` / `{tunnel_failed, Direction, Why}` /
  `{tunnel_expired, Direction}`
- `{transit_denied, ReceiveTunnelId, Reason}` — a transit tunnel this router
  refused to carry, and which of the three reasons applied
- `{leaseset_published, DestHash}` / `{leaseset_publish_failed, DestHash, Reason}`
- `{peertest_result, AddressType, Result}` — one SSU2 peer test concluded
- `{reachability, ssu2, Status}` — the router's inbound reachability decision,
  derived from `peertest_result` events (`firewalled` | `reachable` | `unknown`)
- `{lookup_failed, Key, Kind, Reason}` — a lookup did not produce its record; the
  reason separates a responder that answered with something unreadable from one
  that never answered
- `{sam_session_created, SessionId, Style}` / `{sam_session_closed, SessionId}`
- `{config_changed, Key, Value}`

The three failure events — `peer_connect_failed`, `transit_denied`,
`leaseset_publish_failed` — are the answer to "this router is not working and
nothing says why". Each is announced at the point the thing happens, once per
failure rather than once per packet, and each names what failed and why.

Delivery is best-effort: `f:notify/1` always returns `ok` even when the manager
is not running (emitters must never crash over telemetry). The manager is the
first permanent child of the supervisor tree, so while any emitter runs the
manager is up; discarding rare delivery failures keeps telemetry out of the
data path instead of crashing working connections over it.
""".

-behaviour(gen_event).

-export([start_link/0, notify/1]).

-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2, code_change/3]).

-export_type([event/0, direction/0, lookup_kind/0]).

-doc "Tunnel direction.".
-type direction() :: inbound | outbound.

-doc """
Which kind of record a `lookup_failed` event was about.

`none` for a failure that is not about a particular record — currently only the
lookup service not being running, where there is no key and nothing was asked for.
""".
-type lookup_kind() :: lease | router | none.

-doc "One router status change, as announced on the bus.".
-type event() ::
    {peer_connected, i2p_crypto:hash()}
    | {peer_disconnected, i2p_crypto:hash()}
    %% A connect attempt that did not become a connection, with the reason the
    %% connection process gave (or `unknown`, for a failure with nothing more to
    %% report) and the backoff now in effect, in seconds. The interval is the
    %% load-bearing field: without it a peer being retried in a tight loop and a
    %% peer the router has given up on look identical.
    | {peer_connect_failed, i2p_crypto:hash(), term(), pos_integer()}
    %% A dial waited on SSU2, gave up, and fell back to NTCP2, carrying why.
    %% **Not a peer that could not be connected** — that is `peer_connect_failed`,
    %% and it needs both legs to fail, so it never fires for the peer this event
    %% describes most often: one that answered on TCP and left a UDP stall behind.
    %% The reason is the load-bearing field, because it is the one bit that says
    %% something came back: `{protocol_error, _}` means a datagram arrived and
    %% could not be used, which is proof UDP works that way, while
    %% `{handshake_timeout, _}` and `timeout` are silence. See
    %% `m:i2p_peer:ssu2_park_reason/0`.
    | {ssu2_dial_parked, i2p_crypto:hash(), i2p_peer:ssu2_park_reason()}
    %% A peer that stopped accepting our sends, and why. The counterpart of
    %% `peer_disconnected`, which says the connection is gone without saying
    %% whether it went on its own terms. A session that merely degrades when it
    %% is busy and one that has stopped taking writes are different faults, and
    %% only this one says which.
    | {peer_send_stalled, i2p_crypto:hash(), i2p_ntcp2_conn:send_stalled_reason()}
    | {tunnel_built, direction(), pos_integer()}
    | {tunnel_failed, direction(), rejected | invalid}
    | {tunnel_expired, direction()}
    %% A build record this router refused to carry, with the receive tunnel ID it
    %% was for and which of the three refusal causes applied.
    | {transit_denied, 0..16#FFFFFFFF, i2p_tunnel_relay:transit_denied_reason()}
    | {leaseset_published, i2p_crypto:hash()}
    %% A client LeaseSet that did not reach the network, with the destination and
    %% the reason. The counterpart of `leaseset_published`, which used to be
    %% announced whether or not anything had actually been published.
    | {leaseset_publish_failed, i2p_crypto:hash(),
        i2p_tunnel_publish:leaset_publish_failed_reason()}
    | {sam_session_created, binary(), term()}
    | {sam_session_closed, binary()}
    | {peertest_result, i2p_peertest:address_type(), i2p_peertest:result()}
    | {reachability, ssu2, firewalled | reachable | unknown}
    | {ssu2_block_unhandled, atom()}
    | {db_store_not_stored, i2p_peer:store_not_stored_reason()}
    %% A lookup that did not produce the record it was asked for. The reason is the
    %% whole point: `no_answer` means nobody answered, while `{not_stored, _}` means
    %% a peer *did* answer and this router could not use what it was given. Those are
    %% opposite problems and used to be the same result.
    | {lookup_failed, i2p_crypto:hash() | undefined, lookup_kind(),
        i2p_lookup_srv:lookup_failed_reason()}
    | {config_changed, atom(), term()}.

-doc """
Start the manager.

Registered locally as `i2p_events`; called only by `m:i2per_sup` as the first
child of the tree. Output: the usual `gen_event` start result.
""".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_event:start_link({local, ?MODULE}).

-doc """
Announce a status change.

Input: an event from `t:event/0`. Output: always `ok` — delivery failures are
discarded deliberately (see the module doc).
""".
-spec notify(event()) -> ok.
notify(Event) ->
    ok = i2p_stats:add(events_notified, 1),
    case whereis(?MODULE) of
        undefined ->
            ok;
        _ ->
            _ = gen_event:notify(?MODULE, Event),
            ok
    end.

%% %%%%% %%% gen_event callbacks %%%%% %%%
%% The manager ships without built-in handlers; subscribers attach their own.

init([]) ->
    {ok, []}.

handle_event(_Event, State) ->
    {ok, State}.

handle_call(_Query, State) ->
    {ok, {error, unsupported}, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Arg, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
