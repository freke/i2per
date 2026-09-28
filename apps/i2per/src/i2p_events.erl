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

- `{peer_connected, PeerHash}` / `{peer_disconnected, PeerHash}`
- `{tunnel_built, Direction, Hops}` / `{tunnel_failed, Direction, Why}` /
  `{tunnel_expired, Direction}`
- `{leaseset_published, DestHash}`
- `{peertest_result, AddressType, Result}` — one SSU2 peer test concluded
- `{reachability, ssu2, Status}` — the router's inbound reachability decision,
  derived from `peertest_result` events (`firewalled` | `reachable` | `unknown`)
- `{sam_session_created, SessionId, Style}` / `{sam_session_closed, SessionId}`
- `{config_changed, Key, Value}`

Delivery is best-effort: `f:notify/1` always returns `ok` even when the manager
is not running (emitters must never crash over telemetry). The manager is the
first permanent child of the supervisor tree, so while any emitter runs the
manager is up; discarding rare delivery failures keeps telemetry out of the
data path instead of crashing working connections over it.
""".

-behaviour(gen_event).

-export([start_link/0, notify/1]).

-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2, code_change/3]).

-export_type([event/0, direction/0]).

-doc "Tunnel direction.".
-type direction() :: inbound | outbound.

-doc "One router status change, as announced on the bus.".
-type event() ::
    {peer_connected, i2p_crypto:hash()}
    | {peer_disconnected, i2p_crypto:hash()}
    | {tunnel_built, direction(), pos_integer()}
    | {tunnel_failed, direction(), rejected | invalid}
    | {tunnel_expired, direction()}
    | {leaseset_published, i2p_crypto:hash()}
    | {sam_session_created, binary(), term()}
    | {sam_session_closed, binary()}
    | {peertest_result, i2p_peertest:address_type(), i2p_peertest:result()}
    | {reachability, ssu2, firewalled | reachable | unknown}
    | {ssu2_block_unhandled, atom()}
    | {db_store_not_stored, i2p_peer:store_not_stored_reason()}
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
