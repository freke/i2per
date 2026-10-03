-module(i2p_peer).

-moduledoc """
The peer connection manager: owns the node's connections — NTCP2 and, when the
router operator enables it, SSU2 — both dialed (outbound) and accepted
(inbound, from the boot listeners) — sends and answers I2NP NetDb messages,
populates the local NetDb, and forwards non-DB I2NP messages (garlic, tunnel
data, tunnel gateway, OTBRM) to the tunnel manager (`m:i2p_tunnel_srv`).

This module owns the router's peer connections and NetDb-facing I2NP traffic.
It is a `gen_server` registered locally as `i2p_peer`, a `permanent` child of
`m:i2per_sup`. Each connection is one transport session process spawned under
the matching supervisor (`m:i2p_ntcp2_conn` under `m:i2p_ntcp2_sup`,
`m:i2p_ssu2_conn` under `m:i2p_ssu2_sup`); the peer manager monitors them and
handles their ready, frame, and data messages.

## Transport selection

Outbound dials run in a spawned process and prefer SSU2: when app env
`i2per` -> `ssu2_enabled` is set, the local SSU2 listener is up, and the
remote publishes a usable SSU2 address, the manager attempts the SSU2
handshake there. The handshake blocks until it succeeds or fails; on failure
(SessionCreated timeout, protocol error, or an attempt at a dead SSU2 port)
the dial falls back to NTCP2 without retrying SSU2. When SSU2 is unavailable
(disabled, no listener, or the remote is NTCP2-only) the dial goes straight
to NTCP2. The live transport is surfaced per peer by `f:status/0`.

Inbound sessions arrive from the boot listener as `bob`-role connections. The
ready message carries the dialer's RouterInfo: when the connection's pid does
not match any peer under our own outbound bookkeeping, the manager registers
it as an inbound session (one live session per peer hash — a newer session
replaces the older), learns the dialer's RouterInfo into the NetDb, announces
our own RouterInfo back, and routes its frames like an outbound session. When
no outbound connection is live, `f:send_when_ready/2` messages travel over the
inbound session instead of being queued.

A connection dies on its own (bad peer, closed socket) and the manager only
ever observes that death via a monitor; it then waits out an exponential
backoff before retrying (outbound connections only). Recovery and
reconnection live here, above the connections, never inside them.

The manager connects to seeds, performs exploratory
`m:i2p_i2np:db_lookup/4` round-trips, fills the NetDb from
DatabaseSearchReply and DatabaseStore messages, answers inbound RouterInfo
and LeaseSet2 lookups, sends DeliveryStatus acknowledgements when requested,
and publishes its RouterInfo to the closest floodfills
(`f:publish_floodfills/0`). Every peer connection receives the local
RouterInfo. The periodic refresh timer (`?REFRESH_INTERVAL_SECONDS`) re-signs
and republishes it to the three closest floodfills.

At boot the manager fires a one-shot, bounded floodfill-discovery kick (a
short delay after `init`, `?FLOODFILL_DISCOVERY_KICK_MS` default, overridable
via app env `i2per` -> `floodfill_discovery_delay_ms`). It selects at most
three eligible floodfills and sends exploratory lookups toward them; when the
NetDb has no eligible floodfill yet it falls back to at most three dialable
known seeds. The reseed worker calls `f:discover/0` after its RouterInfos have
traversed the manager, so the same bounded discovery runs after a successful
fresh-client reseed instead of relying on a boot-time race. Incoming
RouterInfos are remembered but are not dialed automatically; this prevents a
75-router reseed bundle from turning into 75 outbound sessions.

Inbound garlic (type 11), tunnel data (type 18), tunnel gateway (type 19), and
OTBRM (type 26) messages are forwarded to `m:i2p_tunnel_srv` when that service
is registered. This routes tunnel build and relay operations through the
current supervisor tree.

## Usage

```erlang
%% Start with the local identity and a seed RouterInfo list. The persistent
%% boot supplies the identity from disk; callers can construct one explicitly.
{ok, _} = i2p_peer:start_link(LocalKeys, SeedRouterInfos),

%% Kick off an exploratory discovery toward one seed.
i2p_peer:lookup(SeedHash, exploratory),

%% Ask a specific peer for its RouterInfo or LeaseSet.
i2p_peer:lookup(PeerHash, routerinfo),
i2p_peer:lookup(PeerHash, leaseset),

%% Ensure our RouterInfo is sent to a peer.
i2p_peer:publish(PeerHash),

%% Publish our RouterInfo to the 3 closest eligible floodfills, asking each
%% for a DeliveryStatus acknowledgement.
i2p_peer:publish_floodfills(),

%% Shut the manager down.
i2p_peer:stop().
```
""".

-behaviour(gen_server).

-export([
    start_link/2,
    learn_ri/1,
    discover/0,
    tunnel_lookup_reply/2,
    reply_via_outbound/3,
    lookup/2,
    publish/1,
    publish_floodfills/0,
    advertise_introducers/1,
    send_when_ready/2,
    status/0,
    dialed/0,
    router_hash/0,
    stop/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-export_type([
    local_keys/0,
    store_outcome/0,
    store_not_stored_reason/0,
    ssu2_park_reason/0
]).

-define(HANDSHAKE_TIMEOUT, 15000).
-define(MAX_BACKOFF_SECONDS, 300).
-define(REFRESH_INTERVAL_SECONDS, 300).
%% How often the bounded structures are swept: `pending_sends` entries past
%% their age, and `peers` entries with no connection and no monitor.
%%
%% **One timer for both, not one each.** A sweep is O(size of the structure) and
%% neither structure grows past its cap, so two timers would buy nothing but a
%% second thing to cancel. It rides the same cadence as the RouterInfo refresh
%% because both are housekeeping rather than work.
-define(SWEEP_INTERVAL_SECONDS, 300).
%% Frames queued for one peer. At the shipped `transit_bandwidth_kbps = 64` with
%% one token per 1028-byte frame this is roughly eight seconds of admitted
%% traffic.
%%
%% **Sized against the reconnection window, not against memory.** A peer in
%% `backoff` retries on a doubling backoff up to `?MAX_BACKOFF_SECONDS`, so a
%% queue that survives about that long loses nothing a peer would have wanted.
%% 64 comfortably exceeds the first few backoff steps while bounding the worst
%% case to roughly 64 KB per peer rather than nothing at all.
-define(MAX_PENDING_SENDS_PER_PEER, 64).
%% How long a queued frame is worth keeping. A relay frame belongs to a tunnel,
%% and a tunnel that has been waiting five minutes is gone, so the frame is
%% worthless to whoever receives it. **This is what reclaims the permanent-stall
%% case** -- a depth cap alone converts unbounded growth into a bounded amount
%% retained for ever, once per peer the router ever learned.
-define(PENDING_SEND_MAX_AGE_MS, 300000).
%% RouterInfos remembered as dialable. Each entry holds a whole RouterInfo, so
%% this is the largest of the three bounded structures per entry.
%%
%% **Well above the number of peers the router will ever hold.** `max_ntcp2_connections`
%% is 64 and `max_ssu2_sessions` is 32, so 500 is several times what can be live
%% at once, which leaves room for backoff entries and for seeds. The cap exists
%% to stop a router that is being fed distinct RouterInfos from retaining them
%% all for the life of the process, not to ration anything it needs.
-define(MAX_KNOWN, 500).
%% Peers retained in `peers`. Generous relative to the connection caps, because
%% a peer in `backoff` is still worth keeping until it has been unreachable
%% longer than the backoff ceiling.
-define(MAX_PEERS, 256).
%% Boot kick delay: after the peer manager comes up (and any reseed pass
%% lands), fire an exploratory lookup at idle seeds so real floodfills enter
%% the NetDb on their own instead of waiting for the first publish cycle.
%% Overridable via app env `i2per` -> `floodfill_discovery_delay_ms` (0 in
%% tests to run it synchronously after init).
-define(FLOODFILL_DISCOVERY_KICK_MS, 1500).

-doc """
The router's local identity keys, shared between the managers. Carried by the
peer manager from boot; `ri` is the current RouterInfo (re-signed on the
refresh cycle), `hash` its NetDb key, `iv` the NTCP2 header IV and `sign_seed`
the Ed25519 seed used to re-sign RouterInfos.
""".
-type local_keys() :: #{
    static_priv := i2p_crypto:x25519_private_key(),
    static_pub := i2p_crypto:x25519_public_key(),
    hash := i2p_crypto:hash(),
    iv := i2p_crypto:aes_iv(),
    port => inet:port_number(),
    sign_seed := i2p_crypto:ed25519_seed(),
    sign_pub => i2p_crypto:ed25519_public_key(),
    ri := i2p_router_info:router_info(),
    intro_key => binary(),
    %% The originally published SSU2 address, kept for restoring reachable
    %% publication after a firewalled (introducer) swap.
    ssu2_addr => i2p_router_info:router_address()
}.

-doc """
Start the peer manager with our identity and seed RouterInfos.

Input: `Local` — `t:local_keys/0`; `Seeds` — parsed RouterInfos to bootstrap
from.
Output: `{ok, Pid}` once the manager process is up (connections are started
lazily on the first `f:lookup/2` / `f:publish/1`).
""".
-spec start_link(local_keys(), [i2p_router_info:router_info()]) ->
    {ok, pid()} | {error, term()}.
start_link(Local, Seeds) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Local, Seeds], []).

-doc """
Send a NetDb DatabaseLookup toward a peer.

Input: `PeerHash` — the peer to ask (and, unless `exploratory`, the key to
search for); `LookupType` — `any | leaseset | routerinfo | exploratory`.
Output: `ok` — the request is queued until the connection is ready.
""".
-spec lookup(i2p_crypto:hash(), any | leaseset | routerinfo | exploratory) -> ok.
lookup(PeerHash, LookupType) ->
    gen_server:cast(?MODULE, {lookup, PeerHash, LookupType}).

-doc """
Ensure our RouterInfo is announced to a peer.

Input: `PeerHash` — the peer to connect to (announcement happens on connect).
Output: `ok` — the connection is (re)established; the RouterInfo is sent when
it becomes ready.
""".
-spec publish(i2p_crypto:hash()) -> ok.
publish(PeerHash) ->
    gen_server:cast(?MODULE, {publish, PeerHash}).

-doc """
Publish our RouterInfo to the three closest eligible floodfills in the NetDb.

Each floodfill receives our RouterInfo in a DatabaseStore with a nonzero reply
token and a direct reply target back to us, so it acknowledges with a
DeliveryStatus. Floodfills that are not connected yet get connected first; the
announcement is sent when their connection becomes ready. Non-floodfill peers
never receive a reply-token store from this call.

Output: `ok` — the work is queued.
""".
-spec publish_floodfills() -> ok.
publish_floodfills() ->
    gen_server:cast(?MODULE, publish_floodfills).

-doc """
Publish this router as firewalled: swap its published SSU2 address for a
non-published introducer address and re-announce, or restore the published
address when `Introducers` is empty.

Input: `Introducers` — up to three `t:i2p_router_info:introducer/0` entries the
router relies on.
Output: `ok` — the swap and re-announce are queued.
""".
-spec advertise_introducers([i2p_router_info:introducer()]) -> ok.
advertise_introducers(Introducers) ->
    gen_server:cast(?MODULE, {advertise_introducers, Introducers}).

-doc """
Inspect the peer manager.

Input: none.
Output: a map of peer hash to `#{status => connecting | connected | backoff,
attempts => non_neg_integer(), transport => ntcp2 | ssu2, last_attempt =>
integer()}` — the status of each connection, how many consecutive connect
attempts it has made, which transport it is on or attempting, and when the
current attempt began.

`transport` is **the attempt, not the entry's creation-time default**. A peer
whose SSU2 dial is parked reports `ssu2`, and only reports `ntcp2` once the
fallback has actually begun, because the dialing process announces each attempt
to this process as it makes it (see `f:attempt_announced/2`).

`last_attempt` is the unix-seconds instant the current attempt began, and it is
what separates a parked dial from a fresh one: `connecting` at `attempts = 0`
is what a healthy dial looks like five milliseconds in, so the age of this field
— not the attempt count — is what says a dial has been stuck.
""".
-spec status() ->
    #{
        i2p_crypto:hash() => #{
            status := connecting | connected | backoff,
            attempts := non_neg_integer(),
            transport := ntcp2 | ssu2,
            last_attempt := integer()
        }
    }.
status() ->
    gen_server:call(?MODULE, status).

-doc """
Our own router identity hash.

Output: the 32-byte SHA-256 hash of this router's RouterInfo identity — the
value other peers use to address us.
""".
-spec router_hash() -> i2p_crypto:hash().
router_hash() ->
    gen_server:call(?MODULE, router_hash).

-doc """
Send an I2NP message to a peer, connecting first if needed.

Input: `PeerHash` — the target peer; `Msg` — a `t:i2p_i2np:i2np_message/0`
to send. If the peer is already connected the message is sent immediately;
otherwise it is queued and sent once the connection becomes ready.

Output: `ok` — the message is queued or sent; errors are not returned because
the send happens asynchronously when the connection opens.
""".
-spec send_when_ready(i2p_crypto:hash(), i2p_i2np:i2np_message()) -> ok.
send_when_ready(PeerHash, Msg) ->
    gen_server:cast(?MODULE, {send_when_ready, PeerHash, Msg}).

-doc """
Learn a RouterInfo from an out-of-band source.

Input: `RI` — the decoded RouterInfo.
Output: `ok` — the info is stored into the NetDb and kept as a connection
candidate; duplicates are ignored. Unlike the DatabaseStore path this does
not dial the peer: a fresh router must not connect to its whole reseed batch
at once.
""".
-spec learn_ri(i2p_router_info:router_info()) -> ok.
learn_ri(RI) ->
    gen_server:cast(?MODULE, {learn_ri, RI}).

-doc """
Start bounded discovery from the current NetDb.

Input: none. Output: `ok`. The peer manager chooses at most three eligible
floodfills and queues exploratory lookups. If the NetDb has no eligible
floodfill yet, it tries up to three known seed routers.
""".
-spec discover() -> ok.
discover() ->
    gen_server:cast(?MODULE, discover).

-doc "Stop the peer manager gracefully.".
-spec stop() -> ok.
stop() ->
    gen_server:cast(?MODULE, stop).

-doc """
Number of peers currently dialed into us (live inbound sessions).

Input: none. Output: the count of distinct peer hashes with an open inbound
session accepted by the boot listeners. Sessions are tracked per peer hash
(`stop_replaced_inbound/3` keeps one live session per hash), so this is the
number of distinct dialers we are currently serving.
""".
-spec dialed() -> non_neg_integer().
dialed() ->
    gen_server:call(?MODULE, dialed).

init([Local, Seeds]) ->
    SeedConfigs = [#{ri => RI, hash => i2p_router_info:hash(RI)} || RI <- Seeds],
    lists:foreach(
        fun(#{hash := Hash}) -> i2p_peer_rep:protect(Hash) end,
        SeedConfigs
    ),
    RefreshRef = erlang:send_after(?REFRESH_INTERVAL_SECONDS * 1000, self(), refresh_routerinfo),
    KickRef = erlang:send_after(discovery_kick_ms(), self(), kick_floodfill_discovery),
    {ok, #{
        local => Local,
        known => maps:from_list([{maps:get(hash, C), C} || C <- SeedConfigs]),
        %% The operator's seed order, kept apart from `known` because it is
        %% meaning, not data. `f:discovery_candidates/1` dials the *first* three
        %% dialable seeds, so a map keyed by hash would silently discard which
        %% seeds the operator ranked highest. This list is the ranking; it is
        %% bounded by the seed count and never grows.
        seed_order => [maps:get(hash, C) || C <- SeedConfigs],
        peers => #{},
        inbound => #{},
        pending => #{},
        pending_sends => #{},
        our_hash => i2p_router_info:hash(maps:get(ri, Local)),
        refresh_ref => RefreshRef,
        discovery_kick_ref => KickRef,
        sweep_ref => erlang:send_after(?SWEEP_INTERVAL_SECONDS * 1000, self(), sweep)
    }}.

handle_call(router_hash, _From, State) ->
    Local = maps:get(local, State),
    {reply, maps:get(hash, Local), State};
handle_call(status, _From, State) ->
    #{peers := Peers} = State,
    Summary = maps:map(
        fun(_Hash, PeerState) ->
            #{
                status => maps:get(status, PeerState),
                attempts => maps:get(attempts, PeerState),
                transport => maps:get(transport, PeerState, ntcp2),
                last_attempt => maps:get(last_attempt, PeerState)
            }
        end,
        Peers
    ),
    {reply, Summary, State};
handle_call(dialed, _From, State) ->
    {reply, map_size(maps:get(inbound, State, #{})), State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({lookup, PeerHash, LookupType}, State) ->
    case peer_status(PeerHash, State) of
        connected ->
            {ok, PeerState} = peer_state(PeerHash, State),
            ConnPid = maps:get(conn, PeerState),
            Transport = maps:get(transport, PeerState, ntcp2),
            send_db_lookup(ConnPid, Transport, maps:get(our_hash, State), PeerHash, LookupType),
            {noreply, State};
        _ ->
            State1 = enqueue_lookup(PeerHash, LookupType, State),
            {noreply, maybe_connect(PeerHash, State1)}
    end;
handle_cast({publish, PeerHash}, State) ->
    {noreply, maybe_connect(PeerHash, State)};
handle_cast(publish_floodfills, State) ->
    {noreply, floodfill_publish(State)};
handle_cast({advertise_introducers, Introducers}, State) ->
    Local = i2p_identity:set_ssu2_introducers(maps:get(local, State), Introducers),
    {noreply, floodfill_publish(State#{local := Local})};
handle_cast({send_when_ready, PeerHash, Msg}, State) ->
    case peer_status(PeerHash, State) of
        connected ->
            {ok, PeerState} = peer_state(PeerHash, State),
            ConnPid = maps:get(conn, PeerState),
            Transport = maps:get(transport, PeerState, ntcp2),
            send_i2np(ConnPid, Transport, Msg),
            {noreply, State};
        _ ->
            %% Prefer a live inbound session to queueing and dialing a peer
            %% that already reached us.
            case inbound_conn(PeerHash, State) of
                {ok, ConnPid, Transport} ->
                    send_i2np(ConnPid, Transport, Msg),
                    {noreply, State};
                error ->
                    State1 = enqueue_send(PeerHash, Msg, State),
                    {noreply, maybe_connect(PeerHash, State1)}
            end
    end;
handle_cast(stop, State) ->
    #{peers := Peers} = State,
    _ = cancel_timer(maps:find(refresh_ref, State)),
    _ = cancel_timer(maps:find(discovery_kick_ref, State)),
    _ = cancel_timer(maps:find(sweep_ref, State)),
    lists:foreach(
        fun({_Hash, #{conn := Conn}}) ->
            case Conn of
                undefined -> ok;
                _ -> stop_conn(Conn)
            end
        end,
        maps:to_list(Peers)
    ),
    lists:foreach(
        fun({ConnPid, _}) -> stop_conn(ConnPid) end,
        maps:to_list(maps:get(inbound, State, #{}))
    ),
    {stop, normal, State};
handle_cast({learn_ri, RI}, State) ->
    {noreply, learn_ri(RI, State)};
handle_cast(discover, State) ->
    {noreply, kick_floodfill_discovery(State)};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({conn_started, PeerHash, ConnPid, Transport}, State) ->
    {noreply, handle_conn_started(PeerHash, ConnPid, Transport, State)};
%% A dial told us which transport it is attempting. Sent by the dialing process
%% before it blocks, so a peer parked in an SSU2 handshake reports `ssu2` rather
%% than the `ntcp2` its entry was seeded with. See `f:attempt_announced/2` for
%% why the dialing process is the one that has to say so.
handle_info({dial_attempt, PeerHash, Transport}, State) ->
    {noreply, handle_dial_attempt(PeerHash, Transport, State)};
%% A connect failure with a reason, and one without. The second shape is what a
%% failure before the connection process exists can only say: `ntcp2_connect/4`
%% reports a supervisor refusal with nothing more to go on, and inventing a reason
%% for it would be worse than admitting there is not one.
handle_info({connect_failed, PeerHash, Reason}, State) ->
    {noreply, handle_connect_failed(PeerHash, Reason, State)};
handle_info({connect_failed, PeerHash}, State) ->
    {noreply, handle_connect_failed(PeerHash, unknown, State)};
handle_info({ntcp2_ready, ConnPid, RemoteRI}, State) ->
    case find_conn_peer(ConnPid, State) of
        {_PeerHash, _PeerState} ->
            {noreply, handle_conn_ready(ConnPid, ntcp2, State)};
        not_found ->
            {noreply, handle_inbound_ready(ConnPid, RemoteRI, ntcp2, State)}
    end;
handle_info({ssu2_ready, ConnPid, _Keys, RemoteRI}, State) ->
    case find_conn_peer(ConnPid, State) of
        {_PeerHash, _PeerState} ->
            {noreply, handle_ssu2_ready(ConnPid, State)};
        not_found when RemoteRI =/= undefined ->
            {noreply, handle_inbound_ready(ConnPid, RemoteRI, ssu2, State)};
        not_found ->
            {noreply, handle_ssu2_unregistered_inbound(ConnPid, State)}
    end;
handle_info({ssu2_data, ConnPid, Blocks}, State) ->
    {noreply, handle_ssu2_data(ConnPid, Blocks, State)};
handle_info({ssu2_closed, ConnPid, _Reason}, State) ->
    {noreply, handle_conn_down_by_pid(ConnPid, State)};
handle_info({ntcp2_frame, ConnPid, Payload}, State) ->
    {noreply, handle_frame(ConnPid, Payload, State)};
handle_info({'DOWN', MonRef, process, _ConnPid, _Reason}, State) ->
    {noreply, handle_conn_down(MonRef, State)};
handle_info({retry_peer, PeerHash}, State) ->
    {noreply, maybe_connect(PeerHash, State)};
handle_info(refresh_routerinfo, State) ->
    State1 = floodfill_publish(State),
    RefreshRef = erlang:send_after(?REFRESH_INTERVAL_SECONDS * 1000, self(), refresh_routerinfo),
    {noreply, State1#{refresh_ref := RefreshRef}};
handle_info(kick_floodfill_discovery, State) ->
    {noreply, kick_floodfill_discovery(State)};
handle_info(sweep, State) ->
    State1 = sweep(State),
    Ref = erlang:send_after(?SWEEP_INTERVAL_SECONDS * 1000, self(), sweep),
    {noreply, State1#{sweep_ref := Ref}};
handle_info(_Msg, State) ->
    {noreply, State}.

%% Sweep the two structures that accumulate. Neither grows past its cap, so this
%% is bounded work, and it is the only thing that reclaims either of them.
%%
%% **`pending_sends` is aged, `peers` is evicted.** Different questions:
%% a queued frame is stale after `?PENDING_SEND_MAX_AGE_MS` because the tunnel
%% it belongs to is gone, whereas a peer entry is stale when it has no
%% connection and no monitor -- it is not being dialled, nothing is holding it,
%% and the backoff that would have retried it has run out.
sweep(State) ->
    NowMs = erlang:system_time(millisecond),
    {Pending1, Expired} = sweep_pending_sends(maps:get(pending_sends, State), NowMs, #{}, 0),
    ok = count_expired(Expired),
    State#{
        pending_sends := Pending1,
        peers => sweep_peers(maps:get(peers, State))
    }.

count_expired(0) -> ok;
count_expired(N) -> i2p_stats:add(pending_sends_expired, N).

sweep_pending_sends(Pending, NowMs, Kept, Expired) ->
    maps:fold(
        fun(PeerHash, Msgs, {Acc, N}) ->
            {KeptMsgs, Stale} = fresh_sends(Msgs, NowMs, []),
            Next =
                case KeptMsgs of
                    [] -> Acc;
                    _ -> maps:put(PeerHash, KeptMsgs, Acc)
                end,
            {Next, N + length(Stale)}
        end,
        {Kept, Expired},
        Pending
    ).

%% Split a peer's queue into the entries still worth sending and the ones past
%% their age.
%%
%% Returns `{Kept, Stale}`, both in queue order.
%%
%% **Walks from the head, keeping the fresh prefix and discarding the rest.**
%% `enqueue_send/3` prepends, so the head is the newest and the tail is the
%% oldest -- which means the entries that aged out are the tail, and a walk that
%% dropped from the head would keep precisely the frames that had waited longest.
%% It stops at the first expired entry rather than filtering, so a queue whose
%% timestamps are out of order is left whole instead of being half-swept on a
%% false reading.
fresh_sends(Msgs, NowMs, Acc) ->
    case Msgs of
        [{at, Ts, _} = M | Rest] when NowMs - Ts =< ?PENDING_SEND_MAX_AGE_MS ->
            fresh_sends(Rest, NowMs, [M | Acc]);
        [] ->
            {lists:reverse(Acc), []};
        _ ->
            {lists:reverse(Acc), Msgs}
    end.

%% Drop peers nothing is holding: no live connection, no monitor, and not
%% mid-dial. Those are the entries `put_peer/3` added and nothing has reclaimed.
%%
%% **`connecting` is never evicted.** A peer in `connecting` has a dial in flight
%% from `maybe_connect_status/3`; evicting it would leave that dial to complete
%% into a `peers` entry that is gone, and `handle_conn_started/4` answers
%% `error` for an unknown peer by stopping the connection. So an in-flight dial
%% would be torn down by its own successful handshake.
%%
%% `?MAX_PEERS` is a backstop rather than the primary mechanism: a peer in
%% `backoff` keeps being retried, so it is only ever unreachable-but-retained,
%% and the count is expected to sit well below the cap. It exists so a router
%% being fed distinct peers cannot grow this map without limit either.
sweep_peers(Peers) when map_size(Peers) =< ?MAX_PEERS ->
    Peers;
sweep_peers(Peers) ->
    Idle = maps:filter(fun(_Hash, Peer) -> idle_peer(Peer) end, Peers),
    case map_size(Idle) of
        0 ->
            %% Every peer is connected, monitored or mid-dial. Nothing is
            %% reclaimable, and the cap is not a licence to drop a live
            %% connection -- so the map is left to exceed the cap and to report
            %% honestly in `status/0` rather than to be truncated here.
            Peers;
        IdleCount ->
            %% Drop at least enough to get back under the cap, and if the idle
            %% peers cannot cover it, all of them. Which peers go is the lowest
            %% hash order, because there is no recency to consult: a peer entry
            %% carries no timestamp, and adding one would mean a write on the
            %% dial path for a bound that is not expected to bite.
            Over = map_size(Peers) - ?MAX_PEERS,
            Evicted = lists:sublist(lists:sort(maps:keys(Idle)), max(Over, IdleCount)),
            ok = count_evicted(length(Evicted)),
            maps:without(Evicted, Peers)
    end.

count_evicted(0) -> ok;
count_evicted(N) -> i2p_stats:add(peers_evicted, N).

idle_peer(Peer) ->
    maps:get(conn, Peer, undefined) =:= undefined andalso
        maps:get(mon, Peer, undefined) =:= undefined andalso
        maps:get(status, Peer, none) =/= connecting.

%%%%%%%%% %%% Internal %%%%%%%

%% Record the transport a dial has committed to, leaving the rest of the entry
%% alone.
%%
%% The `error` clause is the same shape as `f:handle_conn_started/4`'s, and for
%% the same reason: the dialing process is an unlinked spawn, so a message from
%% one is input from outside this process even though it is not a socket. It is
%% in practice unreachable — the entry is written before the spawn returns, and
%% an attempt is only announced once per dial — but the failure mode for being
%% wrong about that is a crash in the process every send path runs through, so
%% it degrades to ignoring the announcement instead. Losing one transport report
%% is a smaller fault than losing the peer manager.
handle_dial_attempt(PeerHash, Transport, State) ->
    case peer_state(PeerHash, State) of
        {ok, PeerState} ->
            put_peer(PeerHash, PeerState#{transport := Transport}, State);
        error ->
            State
    end.

handle_conn_started(PeerHash, ConnPid, Transport, State) ->
    case peer_state(PeerHash, State) of
        {ok, PeerState} ->
            MonRef = erlang:monitor(process, ConnPid),
            Updated = PeerState#{conn := ConnPid, mon := MonRef, transport := Transport},
            put_peer(PeerHash, Updated, State);
        error ->
            stop_conn(ConnPid),
            State
    end.

%% An SSU2 outbound (Alice) session reported `{ssu2_ready, ...}`: the
%% handshake completed, so mark the peer connected and flush queued work — the
%% SSU2 analogue of `f:handle_conn_ready/3` (which stays NTCP2-only because
%% only NTCP2's ready message carries the remote RouterInfo used to learn an
%% inbound peer).
handle_ssu2_ready(ConnPid, State) ->
    case find_conn_peer(ConnPid, State) of
        {PeerHash, PeerState} ->
            Updated = PeerState#{status := connected, attempts := 0, backoff := 0},
            State1 = put_peer(PeerHash, Updated, State),
            i2p_events:notify({peer_connected, PeerHash}),
            i2p_peer_rep:connected(PeerHash),
            State2 = send_pending(ConnPid, ssu2, PeerHash, State1),
            State3 = send_pending_sends(ConnPid, ssu2, PeerHash, State2),
            Local = maps:get(local, State3),
            case maps:get(ff_publish, PeerState, false) of
                true ->
                    State4 = clear_ff_publish(PeerHash, State3),
                    send_our_router_info(ConnPid, ssu2, Local, floodfill),
                    State4;
                false ->
                    send_our_router_info(ConnPid, ssu2, Local, plain),
                    State3
            end;
        not_found ->
            stop_conn(ConnPid),
            State
    end.

%% Route inbound SSU2 Data blocks through the same I2NP handling as NTCP2
%% frames. The SSU2 session delivers whole I2NP messages (already reassembled
%% from fragments) as `{i2np, Type, MsgId, ShortExp, Body}`; NTCP2 delivers raw
%% framing blocks `#{type := 3, data := Data}`. Rebuild the 9-byte short-header
%% wire for each so `handle_frame/3` treats both transports identically.
handle_ssu2_data(ConnPid, Blocks, State) ->
    {Messages, Unhandled} = lists:partition(fun is_i2np_block/1, Blocks),
    Framed = [
        #{type => 3, data => <<Type:8, MsgId:32, ShortExp:32, Body/binary>>}
     || {i2np, Type, MsgId, ShortExp, Body} <- Messages
    ],
    State1 = lists:foldl(
        fun(Block, AccState) -> handle_block(ConnPid, ssu2, Block, AccState) end,
        State,
        Framed
    ),
    lists:foldl(
        fun(Block, AccState) -> note_unhandled_ssu2_block(ConnPid, Block, AccState) end,
        State1,
        Unhandled
    ).

is_i2np_block({i2np, _, _, _, _}) -> true;
is_i2np_block(_) -> false.

%% A non-I2NP SSU2 block reached the peer manager, which has no handler for it.
%% Every shape `m:i2p_ssu2_conn` forwards is meaningful to somebody: the
%% introducer-relay blocks (7/8/9 and the 15/16 tag exchange) and the peer-test
%% blocks (1-4) belong to `m:i2p_relay_coord` and `m:i2p_peertest_coord`, and
%% the RouterInfo and path-challenge blocks are forwarded so the owner can
%% observe an introduction or liveness exchange. Nothing consumes them here, so
%% they are named and counted rather than discarded: silently losing exactly the
%% blocks those coordinators need is how a future implementation ends up looking
%% broken for a reason that lives in this module.
%%
%% Both lines stay, and they are not a duplicate. The event carries the block name
%% alone, which is the dimension a counter wants; the log line adds the *peer*, which
%% the event deliberately does not carry because its cardinality is unbounded. That
%% is the ADR 0002 split rather than a breach of it: the fact is recorded once, and
%% the two lines record different parts of it.
%%
%% The warning is emitted once per peer and kind, because a peer that floods us with
%% these must not turn the log into the flood it is causing. The event is not
%% deduplicated, for the same reason in reverse: a counter wants the total.
note_unhandled_ssu2_block(ConnPid, Block, State) ->
    Name = ssu2_block_name(Block),
    i2p_events:notify({ssu2_block_unhandled, Name}),
    Identity =
        case find_conn_peer(ConnPid, State) of
            {Hash, _PeerState} -> {peer, base64:encode(Hash)};
            not_found -> unknown
        end,
    Key = {Identity, Name},
    Seen = maps:get(unhandled_ssu2_blocks, State, #{}),
    case maps:is_key(Key, Seen) of
        true ->
            State;
        false ->
            i2p_log:emit(
                unhandled_ssu2_block_peer, "unhandled ssu2 ~0p block from ~0p", [Name, Identity]
            ),
            State#{unhandled_ssu2_blocks => Seen#{Key => true}}
    end.

%% The first element is the block's own name for every shape the SSU2 codec
%% produces, so this classifies without repeating `f:i2p_ssu2_conn:block_kind/1`
%% and cannot drift from it.
ssu2_block_name(Block) when is_tuple(Block) -> element(1, Block);
ssu2_block_name(Block) -> Block.

%% Tear down a connection whose session process died or closed, keyed by pid
%% rather than by monitor ref (SSU2 sessions close with `{ssu2_closed, ...}`
%% before any DOWN arrives).
handle_conn_down_by_pid(ConnPid, State) ->
    case find_conn_peer(ConnPid, State) of
        {PeerHash, _PeerState} ->
            i2p_events:notify({peer_disconnected, PeerHash}),
            {State1, _Backoff} = enter_backoff(PeerHash, State),
            State1;
        not_found ->
            case inbound_conn_by_pid(ConnPid, State) of
                {ok, Hash} ->
                    i2p_events:notify({peer_disconnected, Hash}),
                    Inbound = maps:remove(ConnPid, maps:get(inbound, State, #{})),
                    State#{inbound := Inbound};
                error ->
                    State
            end
    end.

%% handle_connect_failed/3 — a connect attempt did not become a connection.
%%
%% The event is announced here, at the one point a connect failure and the backoff
%% it causes are the same decision, and it carries the resulting interval. The
%% interval is the point: a peer being retried in a tight loop and a peer the
%% router has effectively given up on differ only in that number, and without it
%% the two look identical from outside. Reported as one event rather than two
%% because they cannot disagree — the backoff is computed by the very call this
%% makes, so a separate "failed" and a separate "backing off" could only ever be
%% two views of one value.
handle_connect_failed(PeerHash, Reason, State) ->
    case peer_status(PeerHash, State) of
        connecting ->
            {State1, Backoff} = enter_backoff(PeerHash, State),
            ok = i2p_events:notify({peer_connect_failed, PeerHash, Reason, Backoff}),
            State1;
        _ ->
            State
    end.

handle_conn_ready(ConnPid, Transport, State) ->
    case find_conn_peer(ConnPid, State) of
        {PeerHash, PeerState} ->
            Updated = PeerState#{
                status := connected, transport := Transport, attempts := 0, backoff := 0
            },
            State1 = put_peer(PeerHash, Updated, State),
            i2p_events:notify({peer_connected, PeerHash}),
            i2p_peer_rep:connected(PeerHash),
            State2 = send_pending(ConnPid, Transport, PeerHash, State1),
            State3 = send_pending_sends(ConnPid, Transport, PeerHash, State2),
            Local = maps:get(local, State3),
            case maps:get(ff_publish, PeerState, false) of
                true ->
                    State4 = clear_ff_publish(PeerHash, State3),
                    send_our_router_info(ConnPid, Transport, Local, floodfill),
                    State4;
                false ->
                    send_our_router_info(ConnPid, Transport, Local, plain),
                    State3
            end;
        not_found ->
            stop_conn(ConnPid),
            State
    end.

handle_conn_down(MonRef, State) ->
    case find_peer_by_mon(MonRef, State) of
        {PeerHash, _PeerState} ->
            i2p_events:notify({peer_disconnected, PeerHash}),
            {State1, _Backoff} = enter_backoff(PeerHash, State),
            State1;
        not_found ->
            case find_inbound_by_mon(MonRef, State) of
                {ConnPid, Hash} ->
                    i2p_events:notify({peer_disconnected, Hash}),
                    Inbound = maps:remove(ConnPid, maps:get(inbound, State, #{})),
                    State#{inbound := Inbound};
                not_found ->
                    State
            end
    end.

%% An accepted (`bob`-role) connection announced itself. Its RemoteRI names the
%% peer. One live inbound session per peer hash; if the same peer dials us
%% again, the newer session replaces the older.
handle_inbound_ready(ConnPid, RemoteRI, Transport, State) ->
    Hash = i2p_router_info:hash(RemoteRI),
    State1 = stop_replaced_inbound(Hash, ConnPid, State),
    MonRef = erlang:monitor(process, ConnPid),
    Inbound = maps:put(ConnPid, {Hash, MonRef, Transport}, maps:get(inbound, State1, #{})),
    State2 = State1#{inbound := Inbound},
    State3 = learn_ri(RemoteRI, State2),
    send_our_router_info(ConnPid, Transport, maps:get(local, State3), plain),
    i2p_events:notify({peer_connected, Hash}),
    State3.

stop_replaced_inbound(Hash, NewConnPid, State) ->
    Inbound0 = maps:get(inbound, State, #{}),
    Inbound1 = maps:fold(
        fun
            (ConnPid, {H, _, _}, Acc) when H =:= Hash, ConnPid =/= NewConnPid ->
                _ = stop_conn(ConnPid),
                maps:remove(ConnPid, Acc);
            (_, _, Acc) ->
                Acc
        end,
        Inbound0,
        Inbound0
    ),
    State#{inbound := Inbound1}.

inbound_conn(PeerHash, #{inbound := Inbound}) ->
    case
        [
            {ConnPid, T}
         || {ConnPid, {Hash, _, T}} <- maps:to_list(Inbound), Hash =:= PeerHash
        ]
    of
        [{ConnPid, T} | _] -> {ok, ConnPid, T};
        [] -> error
    end.

find_inbound_by_mon(MonRef, #{inbound := Inbound}) ->
    case
        [
            {ConnPid, Hash}
         || {ConnPid, {Hash, M, _}} <- maps:to_list(Inbound), M =:= MonRef
        ]
    of
        [{ConnPid, Hash} | _] -> {ConnPid, Hash};
        [] -> not_found
    end.

inbound_conn_by_pid(ConnPid, #{inbound := Inbound}) ->
    case maps:find(ConnPid, Inbound) of
        {ok, {Hash, _, _}} -> {ok, Hash};
        error -> error
    end.

%% An SSU2 inbound (bob-role) session that announced ready without a remote
%% RouterInfo yet, or one for a peer we do not track; keep it registered so
%% `{ssu2_data, ...}` frames can still be handled. Unknown-peer inbound SSU2
%% is a no-op because the remote hash is required for routing.
handle_ssu2_unregistered_inbound(ConnPid, State) ->
    case maps:get(inbound, State, #{}) of
        Inbound when map_size(Inbound) =:= 0 ->
            MonRef = erlang:monitor(process, ConnPid),
            State#{inbound := maps:put(ConnPid, {undefined, MonRef, ssu2}, Inbound)};
        _ ->
            State
    end.

%% maybe_connect/2 — the connection state machine: never touch a peer that
%% is connecting or connected, dial fresh peers with a config, and retry
%% backed-off peers once their backoff elapsed. Each status gets its own
%% clause. An explicit `live_network = false` profile permits only the local
%% self-seed, so a persisted NetDb cannot turn an offline boot into a live
%% join.
maybe_connect(PeerHash, State) ->
    case network_allowed(PeerHash, State) of
        false -> State;
        true -> maybe_connect_status(peer_status(PeerHash, State), PeerHash, State)
    end.

network_allowed(PeerHash, State) ->
    case application:get_env(i2per, live_network) of
        {ok, false} -> PeerHash =:= maps:get(our_hash, State);
        _ -> true
    end.

%% maybe_connect_status/3 — one clause per peer status.
maybe_connect_status(none, PeerHash, State) ->
    case find_peer_config(PeerHash, State) of
        undefined ->
            State;
        PeerConfig ->
            spawn(fun() -> init_connect(PeerHash, PeerConfig, maps:get(local, State)) end),
            PeerState = #{
                config => PeerConfig,
                conn => undefined,
                mon => undefined,
                transport => ntcp2,
                backoff => 0,
                attempts => 0,
                last_attempt => erlang:system_time(second),
                status => connecting
            },
            put_peer(PeerHash, PeerState, State)
    end;
maybe_connect_status(connecting, _PeerHash, State) ->
    State;
maybe_connect_status(connected, _PeerHash, State) ->
    State;
maybe_connect_status(backoff, PeerHash, State) ->
    case backoff_elapsed(PeerHash, State) of
        true ->
            {ok, PeerState} = peer_state(PeerHash, State),
            spawn(fun() ->
                init_connect(PeerHash, maps:get(config, PeerState), maps:get(local, State))
            end),
            Now = erlang:system_time(second),
            Updated = PeerState#{status := connecting, last_attempt := Now},
            put_peer(PeerHash, Updated, State);
        false ->
            State
    end.

init_connect(PeerHash, #{ri := RemoteRI}, Local) ->
    Owner = whereis(?MODULE),
    case ssu2_connect(PeerHash, RemoteRI, Local) of
        ok ->
            ok;
        {fallback, Reason} ->
            ok = park_reported(PeerHash, Reason),
            ntcp2_connect(PeerHash, RemoteRI, Local, Owner)
    end.

%% The park report, split by whether anything was parked at all. Two clauses
%% rather than a guard inside one, because the two cases are different facts and
%% the split is itself the assertion: `not_attempted` reaches neither the bus nor
%% the counter, so a counter named for parks cannot be moved by a dial that
%% skipped the transport without waiting.
%%
%% Announced from the dialing process rather than by the peer manager, and that
%% is the point rather than an accident: the handshake blocks in this process, so
%% the manager has nothing to report until the dial returns — which, for a dead
%% UDP port, is after the whole stall this ticket exists to make visible.
%% `f:notify/1` discards delivery failures and `f:add/2` is an atomic on shared
%% memory, so both are safe from here and neither can crash a working dial.
park_reported(_PeerHash, not_attempted) ->
    ok;
park_reported(PeerHash, Reason) ->
    ok = i2p_stats:add(ssu2_dials_parked, 1),
    ok = i2p_events:notify({ssu2_dial_parked, PeerHash, Reason}).

%% Tell the manager which transport this dial is about to attempt, before it
%% blocks on the attempt.
%%
%% Announced from the dialing process rather than decided in the manager, because
%% the manager cannot know the answer: the choice between the two transports is
%% made *here*, from `f:i2p_identity:ssu2_enabled/0`, whether the SSU2 listener
%% exists, and what the remote publishes -- none of which the manager re-reads,
%% and the first of which an operator can change.
%%
%% Without it the entry keeps the `ntcp2` it was seeded with when the peer was
%% created, so a peer parked in an SSU2 handshake reports a transport it is not
%% on -- and the park is up to 10s direct, or 60s through an introducer, so the
%% lie is the visible state for the whole of it rather than an instant.
%%
%% Sent before the blocking call and by the same process that later sends
%% `conn_started`, so it reaches the manager first: signal order between one
%% sender and one receiver is guaranteed by the runtime.
attempt_announced(PeerHash, Transport) ->
    Manager = whereis(?MODULE),
    true = is_pid(Manager),
    Manager ! {dial_attempt, PeerHash, Transport},
    ok.

%% Outbound SSU2 dial (Alice role). Bypassed — returning `{fallback,
%% not_attempted}` — unless SSU2 is enabled at boot, this router's SSU2 listener
%% is up, and the remote publishes a usable SSU2 address. The blocking handshake
%% runs in this spawned process; on success it hands the session to the peer
%% manager and reports it as connected (as NTCP2 does), and on any failure
%% returns `{fallback, Reason}` naming why, so the caller can fall back to NTCP2
%% and still say what the park was. Return shape is `ok | {fallback,
%% t:ssu2_park_reason/0}`; deliberately unspecced like the rest of this dial path,
%% because a spec here narrows `local_keys/0` into `f:init_connect/3` and then
%% reads as a contract violation on the NTCP2 fallback, which passes the whole
%% local map. The reason vocabulary itself is checked where it is observable --
%% in `t:i2p_events:event/0`, at the `f:notify/1` call site.
ssu2_connect(PeerHash, RemoteRI, Local) ->
    case
        i2p_identity:ssu2_enabled() andalso
            erlang:whereis(i2p_ssu2_listener) =/= undefined andalso
            i2p_router_info:ssu2_address_options(RemoteRI) =/= error
    of
        false ->
            {fallback, not_attempted};
        true ->
            ok = attempt_announced(PeerHash, ssu2),
            ssu2_connect_ready(PeerHash, RemoteRI, Local)
    end.

ssu2_connect_ready(PeerHash, RemoteRI, Local) ->
    {ok, RemoteOpts} = i2p_router_info:ssu2_address_options(RemoteRI),
    case maps:get(published, RemoteOpts) of
        false ->
            %% Firewalled remote: there is no dialable host/port, only her
            %% introducers. Reach her indirectly through the relay machinery
            %% (relay blocks 7/8 + token redirect); on any failure fall back
            %% to NTCP2 exactly as the direct dial path does, carrying the
            %% reason out with it.
            indirect_ssu2_connect(PeerHash, RemoteRI, RemoteOpts, Local);
        true ->
            %% Published claims a dialable SSU2 address; narrow the full
            %% address-options map down to the concrete remote_opts() the conn
            %% dial requires. Should the published address somehow lack a
            %% concrete host/port, treat the remote as firewalled (route
            %% through her introducers) rather than crash the dial.
            case dialable_remote_opts(RemoteOpts) of
                {ok, DialRemoteOpts} ->
                    direct_ssu2_connect(PeerHash, DialRemoteOpts, Local);
                error ->
                    indirect_ssu2_connect(PeerHash, RemoteRI, RemoteOpts, Local)
            end
    end.

%% Outbound SSU2 dial (Alice role) to a router publishing a dialable SSU2
%% address. The blocking handshake runs in this spawned process; on success it
%% hands the session to the peer manager and reports it as connected (as NTCP2
%% does) and on any failure falls back to NTCP2, carrying the session's own exit
%% reason rather than discarding it.
direct_ssu2_connect(PeerHash, RemoteOpts, Local) ->
    LocalKeys = #{
        static_priv => maps:get(static_priv, Local),
        static_pub => maps:get(static_pub, Local),
        intro_key => maps:get(intro_key, Local),
        sign_seed => maps:get(sign_seed, Local),
        sign_pub => maps:get(sign_pub, Local),
        hash => maps:get(hash, Local),
        ri => maps:get(ri, Local)
    },
    OurRI = maps:get(ri, Local),
    RIBlock = i2p_router_info:to_binary(OurRI),
    Listener = whereis(i2p_ssu2_listener),
    case i2p_ssu2_conn:connect(LocalKeys, RemoteOpts, RIBlock, Listener) of
        {ok, ConnPid, Keys} ->
            Manager = whereis(?MODULE),
            true = is_pid(Manager),
            %% The handshake ran in this spawned process (caller of
            %% `f:i2p_ssu2_conn:connect/5`), which owns the session and is about
            %% to exit. Hand the session to the peer manager so its data
            %% messages (`{ssu2_data, ...}`) reach it, then relay the ready
            %% (echoing what the session already sent to this process) so the
            %% manager can flush pending work and mark the peer connected.
            ok = i2p_ssu2_conn:set_owner(ConnPid, Manager),
            Manager ! {conn_started, PeerHash, ConnPid, ssu2},
            Manager ! {ssu2_ready, ConnPid, Keys, undefined},
            ok;
        {error, Reason} ->
            {fallback, Reason}
    end.

%% Narrow a full firewalled-shaped address-options map (as produced by
%% `f:i2p_router_info:ssu2_address_options/1`, whose host/port are
%% `undefined` for firewalled remotes and which carries `published` /
%% `introducers` bookkeeping on top) down to the concrete dialable
%% `remote_opts()` map the conn dial requires — host/port as concrete
%% values and only the five keys its success typing accepts. Returns
%% `{ok, DialableOpts}` when the published SSU2 address is really a
%% concrete host/port, `error` otherwise (firewalled remote).
-spec dialable_remote_opts(map()) -> {ok, i2p_ssu2_conn:remote_opts()} | error.
dialable_remote_opts(RemoteOpts) ->
    Host = maps:get(host, RemoteOpts, undefined),
    Port = maps:get(port, RemoteOpts, undefined),
    case is_binary(Host) andalso is_integer(Port) andalso Port >= 1 andalso Port =< 65535 of
        true ->
            {ok, #{
                host => Host,
                port => Port,
                intro_key => maps:get(intro_key, RemoteOpts),
                peer_test => maps:get(peer_test, RemoteOpts),
                static_key => maps:get(static_key, RemoteOpts)
            }};
        false ->
            error
    end.

%% Outbound dial to a firewalled remote (no dialable SSU2 address) through one
%% of her introducers: RelayRequest (block 7) in the introducer session, the
%% RelayResponse (block 8) with her endpoint + token, then a redirect dial to
%% her, carrying the token. On success the redirect session is handed to the
%% peer manager exactly like a direct dial's, and the introducer leg (its
%% relay served) is closed. Any failure falls back to NTCP2, naming the reason.
indirect_ssu2_connect(PeerHash, RemoteRI, RemoteOpts, Local) ->
    case pick_introducer(RemoteOpts, RemoteRI, Local) of
        {error, Reason} ->
            {fallback, Reason};
        {ok, BobOpts, Relay} ->
            case dialable_remote_opts(BobOpts) of
                {ok, DialBobOpts} ->
                    LocalKeys = #{
                        static_priv => maps:get(static_priv, Local),
                        static_pub => maps:get(static_pub, Local),
                        intro_key => maps:get(intro_key, Local),
                        sign_seed => maps:get(sign_seed, Local),
                        sign_pub => maps:get(sign_pub, Local),
                        hash => maps:get(hash, Local),
                        ri => maps:get(ri, Local)
                    },
                    OurRI = maps:get(ri, Local),
                    RIBlock = i2p_router_info:to_binary(OurRI),
                    Listener = whereis(i2p_ssu2_listener),
                    case
                        i2p_ssu2_conn:connect_via_introducer(
                            LocalKeys, DialBobOpts, RIBlock, Listener, Relay
                        )
                    of
                        {ok, BobPid, CharliePid, Keys} ->
                            Manager = whereis(?MODULE),
                            true = is_pid(Manager),
                            ok = i2p_ssu2_conn:set_owner(CharliePid, Manager),
                            Manager ! {conn_started, PeerHash, CharliePid, ssu2},
                            Manager ! {ssu2_ready, CharliePid, Keys, undefined},
                            %% The introducer leg already served its purpose: the
                            %% token redirect to Charlie is live, so close it
                            %% gracefully (Bob drops the tagged/relay state).
                            i2p_ssu2_conn:terminate_session(BobPid, 0),
                            ok;
                        {error, Reason} ->
                            {fallback, Reason}
                    end
            end
    end.

%% Pick the first introducer of a firewalled remote whose RouterInfo the NetDb
%% holds and that publishes a dialable SSU2 address; builds the relay material
%% for `f:i2p_ssu2_conn:connect_via_introducer/5` around it.
pick_introducer(Introducers, RemoteRI, Local) when is_map(Introducers) ->
    pick_introducer(maps:get(introducers, Introducers), RemoteRI, Local);
pick_introducer([Intro | Rest], RemoteRI, Local) ->
    case i2p_netdb_srv:find(maps:get(hash, Intro)) of
        {ok, BobRI} ->
            case i2p_router_info:ssu2_address_options(BobRI) of
                {ok, BobOpts} ->
                    case maps:get(published, BobOpts, false) of
                        true ->
                            {OurPort, OurIp} = our_endpoint(Local),
                            Relay =
                                #{
                                    bob_hash => maps:get(hash, Intro),
                                    charlie_hash => i2p_router_info:hash(RemoteRI),
                                    charlie_ri => RemoteRI,
                                    tag => maps:get(tag, Intro),
                                    our_port => OurPort,
                                    our_ip => OurIp,
                                    sign_seed => maps:get(sign_seed, Local)
                                },
                            {ok, BobOpts, Relay};
                        false ->
                            pick_introducer(Rest, RemoteRI, Local)
                    end;
                _ ->
                    pick_introducer(Rest, RemoteRI, Local)
            end;
        not_found ->
            pick_introducer(Rest, RemoteRI, Local)
    end;
pick_introducer([], _RemoteRI, _Local) ->
    {error, no_introducer}.

%% The endpoint we assert reachable in a RelayRequest — what Charlie's
%% HolePunch targets. It is our originally-published SSU2 address (the
%% `ssu2_addr` local-key entry kept by `f:i2p_identity:set_ssu2_introducers/2`);
%% without one we assert no endpoint at all.
our_endpoint(Local) ->
    case maps:get(ssu2_addr, Local, undefined) of
        undefined ->
            {0, <<>>};
        Addr ->
            Opts = maps:get(options, Addr),
            case {maps:get(host, Opts, undefined), maps:get(port, Opts, undefined)} of
                {undefined, _} ->
                    {0, <<>>};
                {_Host, undefined} ->
                    {0, <<>>};
                {Host, Port} ->
                    case inet:parse_address(binary_to_list(Host)) of
                        {ok, IP} ->
                            {Port, iolist_to_binary(tuple_to_list(IP))};
                        _ ->
                            {0, <<>>}
                    end
            end
    end.

ntcp2_connect(PeerHash, RemoteRI, Local, Owner) ->
    %% The fallback announces itself too, and not as a detail: without it a peer
    %% whose SSU2 leg parked would keep reporting `ssu2` for the whole NTCP2 dial
    %% that followed, which is the same lie one transport later.
    ok = attempt_announced(PeerHash, ntcp2),
    Args = #{
        role => alice,
        remote_ri => RemoteRI,
        local => Local,
        owner => Owner,
        handshake_timeout => ?HANDSHAKE_TIMEOUT
    },
    case i2p_ntcp2_sup:start_connection(i2p_ntcp2_sup:conn_child(Args)) of
        {ok, ConnPid} ->
            Owner ! {conn_started, PeerHash, ConnPid, ntcp2};
        {ok, ConnPid, _} ->
            Owner ! {conn_started, PeerHash, ConnPid, ntcp2};
        {error, Reason} ->
            Owner ! {connect_failed, PeerHash, {supervisor, Reason}}
    end.

handle_frame(ConnPid, Payload, State) ->
    case i2p_framing:decode_blocks(Payload) of
        {ok, Blocks} ->
            lists:foldl(
                fun(Block, AccState) -> handle_block(ConnPid, ntcp2, Block, AccState) end,
                State,
                Blocks
            );
        error ->
            stop_conn(ConnPid),
            State
    end.

handle_block(ConnPid, Transport, #{type := 3, data := Data}, State) ->
    case i2p_i2np:decode(Data) of
        {ok, #{type := 1, body := Body, msg_id := MsgID}} ->
            handle_db_store(ConnPid, MsgID, Body, State);
        {ok, #{type := 2, body := Body}} ->
            handle_db_lookup(ConnPid, Transport, Body, State);
        {ok, #{type := 3, body := Body}} ->
            handle_db_search_reply(ConnPid, Transport, Body, State);
        {ok, #{type := 10}} ->
            State;
        {ok, #{type := Type} = Msg} when
            Type =:= 11;
            Type =:= 18;
            Type =:= 19;
            Type =:= 25;
            Type =:= 26
        ->
            forward_to_tunnel(ConnPid, Msg, State),
            State;
        {ok, _} ->
            State;
        error ->
            stop_conn(ConnPid),
            State
    end;
handle_block(_ConnPid, _Transport, _Block, State) ->
    State.

-doc """
Why a DatabaseStore was not kept, as carried on the `i2p_events` bus.

`{unsupported_type, Type}` is a store type that decodes but is not implemented
(ELS2 and MetaLeaseSet today). `{refused_with_reason, Outcome}` is the NetDb's
own verdict in its own vocabulary — `older`, `from_future`, `too_old`,
`expired`. A bare `{Reason}` is a decode failure from the NetDb, and
`unparseable_router_info_data` is ours, for a type 0 store whose data field is
not a RouterInfo.

This is the reason vocabulary the telemetry work needs at the store recording
point. It is deliberately not flattened into a single atom: "we do not implement
this type" and "the NetDb thought it was too old" call for different responses,
and a counter that cannot tell them apart cannot answer the question it was
built to answer.
""".
-type store_not_stored_reason() ::
    {unsupported_type, byte()}
    | {refused_with_reason, older | from_future | too_old | expired}
    | {atom()}
    | unparseable_router_info_data.

-doc """
Why the SSU2 leg of an outbound dial was given up on.

**The point of the vocabulary is one bit: did something come back.** A
`{protocol_error, _}` means a datagram arrived and could not be used, which is
*proof that UDP works in that direction*; `{handshake_timeout, _}` and `timeout`
mean silence. Per dial those cannot be told apart from anything else — silence is
over-determined, because our UDP may be blocked, the peer may be down, or a
middlebox may be eating it. Across peers they can: SSU2 timing out for every peer
while NTCP2 succeeds for every peer means the common cause is ours, and that is the
one an operator can act on, since "your UDP is blocked" is a configuration fact
and "peer X is UDP-dead" is not actionable at all. So the reason is kept, and this
is the vocabulary it is kept in.

The inner terms of the session-exit reasons are `m:i2p_ssu2_conn`'s own, verbatim
and untranslated. Re-describing them here would be a second vocabulary for
conditions that module already names, and a second one to keep in step with it.

`not_attempted` is the one reason that is **not a park**: SSU2 was not available to
try, so nothing waited, nothing was slow, and nothing is counted. It is a named
value rather than a bare `fallback` because a dial that skipped the transport and a
dial that was given up on by it are different facts even when neither is reported,
and collapsing them is how the reason came to be discarded in the first place.
See #1Q4JREN.
""".
-type ssu2_park_reason() ::
    not_attempted
    %% `m:i2p_ssu2_conn`'s handshake ran out of retransmits, naming the phase.
    | {handshake_timeout, atom()}
    %% A datagram arrived and could not be used. Proof UDP works that way.
    | {protocol_error, atom()}
    %% The introducer leg: the introducer refused the relay, its response
    %% signature did not verify, or it refused to admit the session.
    | {relay_rejected, non_neg_integer()}
    | {relay_bad_response_sig, binary()}
    | {session_admission_failed, term()}
    %% The session's supervisor refused to start it, and the wait the conn module
    %% imposes on it expired.
    | {session_start_failed, term()}
    | timeout
    %% A firewalled remote whose introducers the NetDb could not supply with a
    %% dialable address. The relay never ran, so this is silence with a cause we
    %% do know.
    | no_introducer
    %% Anything else the session died of, verbatim: `normal`, `shutdown`,
    %% `{idle_timeout, _}`, a crash. Open deliberately rather than a closed set,
    %% because these are the module's exits rather than this module's branches,
    %% and a closed list here would be an enumeration that goes stale silently.
    | term().

-doc """
What became of a decoded DatabaseStore.

`stored` is the only outcome that licenses floodfill replication, because
replication is the side effect that tells the rest of the network to hold an
entry. A type we do not implement and an entry the NetDb refused are both
`not_stored`, and pushing either onward would be us asking three other routers
to serve something we never held. See `t:store_not_stored_reason/0` for the
reason a `not_stored` carries.
""".
-type store_outcome() :: stored | not_stored.

%% `store_entry/4` returns `{Outcome, State}` where a `not_stored` outcome
%% carries its reason in a three-tuple, so the reason travels with the decision
%% rather than needing a second return value that only one branch populates.
-spec store_entry(byte(), binary(), pid() | undefined, term()) ->
    {stored, term()} | {not_stored, store_not_stored_reason(), term()}.

%% `f:handle_db_store/4` decided what became of an entry and then ignored its
%% own decision, replicating unconditionally on a path that had already
%% determined the entry was unusable. Two consequences, both of which this
%% function is the only defence against:
%%
%%  - a store type we do not implement (ELS2, MetaLeaseSet) was handed to
%%    `f:i2p_floodfill:replication_outbox/5` with its original type byte, so
%%    three other routers were asked to serve an entry we never parsed;
%%  - an entry the NetDb's clock window refused was pushed on the same way.
%%
%% On top of that, the per-type handlers replicated through `f:replicate_if_new/6`
%% *and* the caller replicated again, so every entry we did store went out
%% twice. The duplication of delivery is its own harm: the second copy reaches
%% the same three floodfills, each of which stores it and re-broadcasts in turn.
%%
%% So: replicate once, on `stored`, and report everything else with its reason
%% so an operator can tell a refusal from a corruption and neither from silence.
handle_db_store(ConnPid, MsgID, Body, State) ->
    case i2p_i2np:decode_db_store(Body) of
        {ok, #{key := Key, store_type := StoreType, data := Data} = Store} ->
            reply_to_store(Store, MsgID, State),
            Result = store_entry(StoreType, Data, ConnPid, State),
            replicate_stored(StoreType, Key, Data, Result, ConnPid);
        error ->
            %% A DatabaseStore we cannot even parse came from a peer that is
            %% not speaking the protocol. Nothing is replicated and nothing is
            %% stored, so there is no entry to report a reason for.
            stop_conn(ConnPid),
            State
    end.

%% Route a decoded DatabaseStore by type and report what became of it, as
%% `{Outcome, State}` with the reason carried inside a `not_stored` outcome. Type
%% 0 is a RouterInfo, 1 a LeaseSet, 3 a local LeaseSet; 5 (ELS2) and 7
%% (MetaLeaseSet) decode but are not implemented, and neither is anything a
%% future type brings.
store_entry(0, Data, ConnPid, State) ->
    store_ri_entry(Data, ConnPid, State);
store_entry(StoreType, Data, _ConnPid, State) when StoreType =:= 1; StoreType =:= 3 ->
    store_ls_entry(Data, State);
store_entry(StoreType, _Data, _ConnPid, State) ->
    {not_stored, {unsupported_type, StoreType}, State}.

store_ri_entry(Data, _ConnPid, State) ->
    case i2p_i2np:parse_router_info_data(Data) of
        {ok, RIBytes} ->
            NowMs = erlang:system_time(millisecond),
            case i2p_netdb_srv:store_binary(RIBytes, NowMs) of
                {ok, Outcome} ->
                    netdb_outcome(Outcome, remember_ri_entry(RIBytes, State));
                {error, Reason} ->
                    {not_stored, {Reason}, State}
            end;
        error ->
            {not_stored, unparseable_router_info_data, State}
    end.

store_ls_entry(Data, State) ->
    case i2p_netdb_srv:store_ls_binary(Data, erlang:system_time(second)) of
        {ok, Outcome} ->
            netdb_outcome(Outcome, State);
        {error, Reason} ->
            {not_stored, {Reason}, State}
    end.

%% The NetDb's own verdict, in its own vocabulary. `added` and `updated` mean we
%% hold the entry; every other outcome — `older`, `from_future`, `too_old`,
%% `expired` — means we do not, and must not forward it. An `older` outcome is
%% worth a second thought: the key *is* in the store, but a copy we already had,
%% so forwarding the bytes we were just handed would push a stale one.
netdb_outcome(Outcome, State) when Outcome =:= added; Outcome =:= updated -> {stored, State};
netdb_outcome(Outcome, State) -> {not_stored, {refused_with_reason, Outcome}, State}.

%% Only `stored` licenses replication, and it licenses exactly one. Everything
%% else is reported, because an entry that arrived and was not kept is the fact
%% an operator needs: silently dropping it is indistinguishable from a peer that
%% never sent anything.
replicate_stored(StoreType, Key, Data, {stored, State}, ConnPid) ->
    _ = maybe_replicate(StoreType, Key, Data, ConnPid, State),
    State;
replicate_stored(_StoreType, _Key, _Data, {not_stored, Reason, State}, _ConnPid) ->
    %% The announcement is the whole report (ADR 0002: each fact is recorded once,
    %% on one instrument). This used to also call `f:report_not_stored/1`, which
    %% logged the same reason at `debug` -- invisible under the shipped `notice`
    %% default, so it bought nothing for a subscriber-less router either -- and at
    %% `warning` for an unparseable RouterInfo, where the prominence was the only
    %% addition and `unparseable_router_info_data` is already a distinct reason a
    %% consumer can count apart from `{unsupported_type, T}`. Both lines are gone.
    i2p_events:notify({db_store_not_stored, Reason}),
    State.

%% A DatabaseStore with a nonzero (and not 0xFFFFFFFF) reply token asks for a
%% DeliveryStatus acknowledgement. i2pd replies unconditionally, before any
%% storeability check; direct replies use tunnel ID 0 when no reply tunnel is
%% configured.
reply_to_store(#{reply_token := 0}, _MsgID, _State) ->
    ok;
reply_to_store(#{reply_token := 16#FFFFFFFF}, _MsgID, _State) ->
    ok;
reply_to_store(#{reply_token := _, reply := {0, Gateway}}, MsgID, State) ->
    case find_peer_by_hash(Gateway, State) of
        {ok, TargetConn, TargetTransport} ->
            send_i2np(
                TargetConn,
                TargetTransport,
                i2p_i2np:delivery_status(MsgID, erlang:system_time(millisecond))
            );
        error ->
            ok
    end;
reply_to_store(#{reply_token := _, reply := _}, _MsgID, _State) ->
    ok.

handle_db_lookup(ConnPid, Transport, Body, State) ->
    case i2p_i2np:decode_db_lookup(Body) of
        {ok, Parsed} ->
            case maps:get(delivery, Parsed) of
                #{tunnel_id := _ReplyTid} ->
                    %% The asker wants the answer inside its inbound tunnel
                    %% through the exploratory outbound pool.
                    OurHash = maps:get(our_hash, State),
                    tunnel_lookup_reply(Parsed, OurHash),
                    State;
                undefined ->
                    answer_over_conn(ConnPid, Transport, Parsed, State),
                    State
            end;
        error ->
            stop_conn(ConnPid),
            State
    end.

answer_over_conn(ConnPid, Transport, #{key := Key, type := Type, excluded := Excluded}, State) ->
    case lookup_reply(Type, Key, Excluded) of
        {store_ri, RI} ->
            send_store(ConnPid, Transport, Key, RI, 0, undefined);
        {store_ls, LS} ->
            send_ls_store(ConnPid, Transport, Key, LS);
        {search, PeerHashes} ->
            send_search_reply(ConnPid, Transport, Key, PeerHashes, State)
    end,
    ok.

%% lookup_reply/3 — what we would answer a DatabaseLookup with: a RouterInfo
%% store, a LeaseSet store, or a search reply naming closer routers.
lookup_reply(routerinfo, Key, Excluded) ->
    case i2p_netdb_srv:find(Key) of
        {ok, RI} -> {store_ri, RI};
        not_found -> {search, i2p_netdb_srv:closest(Key, 4) -- Excluded}
    end;
lookup_reply(leaseset, Key, Excluded) ->
    case i2p_netdb_srv:find_ls(Key) of
        {ok, LS} -> {store_ls, LS};
        not_found -> {search, i2p_netdb_srv:closest(Key, 4) -- Excluded}
    end;
lookup_reply(_AnyOrExploratory, Key, Excluded) ->
    {search, i2p_netdb_srv:closest(Key, 4) -- Excluded}.

-doc """
Answer a tunnel-replied DatabaseLookup.

Input: `Parsed` - the decoded `t:i2p_i2np:db_lookup/0`; `OurHash` - this
router's identity hash (the search-reply sender field).
Output: `ok` - the DatabaseStore or DatabaseSearchReply is injected into the
requester's inbound tunnel (`{tunnel, From, ReplyTid}` delivery) through one
of our outbound tunnels; when none is active the reply is dropped and the
requester's retry picks another responder.

**Two ways to drop, and both answer `ok`.** Having no outbound tunnel at all is
the one the caller can see, and it is handled here. The other is the tunnel
going away *between* choosing it and sending on it -- a second lookup, which can
answer `error` after a successful pick -- counted as
`lookup_replies_dropped_no_tunnel` in `m:i2p_stats`. Neither is this router's
fault and neither is worth failing a lookup over, so this function is total by
design rather than by luck; see #MCVQ6D6 for why that used to be an assertion.
""".
-spec tunnel_lookup_reply(i2p_i2np:db_lookup(), i2p_crypto:hash()) -> ok.
tunnel_lookup_reply(
    #{key := Key, from := FromHash, type := Type, excluded := Excluded} = Parsed, OurHash
) ->
    #{tunnel_id := ReplyTid} = maps:get(delivery, Parsed),
    Msg =
        case lookup_reply(Type, Key, Excluded) of
            {store_ri, RI} ->
                Data = i2p_i2np:router_info_data(i2p_router_info:to_binary(RI)),
                i2p_i2np:db_store(Key, 0, 0, undefined, Data);
            {store_ls, LS} ->
                i2p_i2np:db_store(
                    Key, i2p_leaset:store_type(), 0, undefined, i2p_leaset:to_binary(LS)
                );
            {search, PeerHashes} ->
                i2p_i2np:db_search_reply(Key, PeerHashes, OurHash)
        end,
    case i2p_tunnel_srv:pick_lookup_outbound() of
        {ok, OutTid, _Entry} ->
            %% Builders stamp epoch-second expirations; the standard header
            %% wants a relative millisecond lifetime.
            Wire =
                i2p_i2np:encode_std(#{
                    type => maps:get(type, Msg),
                    msg_id => maps:get(msg_id, Msg),
                    expiration_ms => 60_000,
                    body => maps:get(body, Msg)
                }),
            reply_via_outbound(OutTid, {tunnel, FromHash, ReplyTid}, Wire);
        error ->
            ok
    end.

%% The send above answers `error` when the tunnel is gone, and the two calls it
%% takes are separate: `pick_lookup_outbound/0` reads the pool, then
%% `send_via_outbound/3` re-resolves the id through `find_outbound/2`. A tunnel
%% retired by `pool_tick` in that window makes the second answer `error`, which
%% the `ok =` turned into a `badmatch` in the process every send path goes
%% through. The `error ->` branch one line below the assert is the same
%% condition handled for the pick; the send needed the same answer.
%%
%% **Not a counter here, and the reason is that the reply is not ours.** The
%% client-side twin of this loss is `client_messages_dropped_no_tunnel`
%% (#G9HZK8F), and merging the two would be the same category error as calling
%% that one `frames`: a lost client send is a client waiting on its own traffic,
%% and a lost lookup reply is *another router* waiting on an answer we had. The
%% operator acts on those differently -- one is our user's experience, the other
%% is our usefulness to the network -- so they are two counters.
%%
%% Exported for the same reason `f:tunnel_lookup_reply/2` is: it is the named
%% unit of the fix, and the race that reaches it cannot be built through the
%% public surface -- a pick returns a pool *key* and the send re-resolves that
%% same key, so only a concurrent removal separates them. Calling this directly
%% is the only way to put a red case on the line that changed, rather than a
%% green one on the drop path beside it.
-spec reply_via_outbound(0..16#FFFFFFFF, i2p_tunnel_srv:send_delivery(), binary()) -> ok.
reply_via_outbound(OutTid, Delivery, Wire) ->
    case i2p_tunnel_srv:send_via_outbound(OutTid, Delivery, Wire) of
        ok -> ok;
        error -> i2p_stats:add(lookup_replies_dropped_no_tunnel, 1)
    end.

handle_db_search_reply(ConnPid, Transport, Body, State) ->
    case i2p_i2np:decode_db_search_reply(Body) of
        {ok, #{peers := PeerHashes}} ->
            FromHash = maps:get(our_hash, State),
            lists:foreach(
                fun(PeerHash) ->
                    send_db_lookup(ConnPid, Transport, FromHash, PeerHash, routerinfo)
                end,
                PeerHashes
            ),
            State;
        error ->
            State
    end.

send_db_lookup(ConnPid, Transport, FromHash, Key, LookupType) ->
    Flags = lookup_type_to_flag(LookupType),
    LookupKey =
        case LookupType of
            exploratory -> FromHash;
            _ -> Key
        end,
    Msg = i2p_i2np:db_lookup(LookupKey, FromHash, Flags, []),
    send_i2np(ConnPid, Transport, Msg).

lookup_type_to_flag(any) -> i2p_i2np:lookup_type_any();
lookup_type_to_flag(leaseset) -> i2p_i2np:lookup_type_leaseset();
lookup_type_to_flag(routerinfo) -> i2p_i2np:lookup_type_routerinfo();
lookup_type_to_flag(exploratory) -> i2p_i2np:lookup_type_exploratory().

send_store(ConnPid, Transport, Key, RI, Token, Reply) ->
    Data = i2p_i2np:router_info_data(i2p_router_info:to_binary(RI)),
    send_i2np(ConnPid, Transport, i2p_i2np:db_store(Key, 0, Token, Reply, Data)).

%% Floodfill replication: forward a stored entry to the 3 closest eligible
%% floodfills (excluding self and the sender).
%%
%% The caller is what makes this safe: `f:replicate_stored/6` reaches here only
%% on a `stored` outcome, so the `added`/`updated` filter this comment used to
%% describe now lives in one place, at the point where the decision is made,
%% rather than in a helper every caller had to remember to use.
maybe_replicate(StoreType, Key, Data, ConnPid, State) ->
    case i2p_floodfill:is_floodfill() of
        false ->
            ok;
        true ->
            OurHash = maps:get(our_hash, State),
            SenderHash = sender_hash(ConnPid, State),
            Outbox = i2p_floodfill:replication_outbox(StoreType, Key, Data, OurHash, SenderHash),
            lists:foreach(
                fun({Target, Msg}) ->
                    i2p_peer:send_when_ready(Target, Msg)
                end,
                Outbox
            ),
            ok
    end.

%% A RouterInfo the NetDb accepted, which also means we should be willing to
%% dial it. `remember_ri/2` is the same list the seed set lives in.
remember_ri_entry(RIBytes, State) ->
    case i2p_router_info:decode(RIBytes) of
        {ok, RI} -> remember_ri(RI, State);
        {error, _} -> State
    end.

sender_hash(ConnPid, State) ->
    case conn_peer_hash(ConnPid, State) of
        {Hash, _} -> Hash;
        not_found -> maps:get(our_hash, State)
    end.

send_ls_store(ConnPid, Transport, Key, LS) ->
    Data = i2p_leaset:to_binary(LS),
    send_i2np(
        ConnPid, Transport, i2p_i2np:db_store(Key, i2p_leaset:store_type(), 0, undefined, Data)
    ).

send_search_reply(ConnPid, Transport, Key, PeerHashes, State) ->
    Msg = i2p_i2np:db_search_reply(Key, PeerHashes, maps:get(our_hash, State)),
    send_i2np(ConnPid, Transport, Msg).

%% The two announcement modes: `plain` is the token-free self-announce sent to
%% every peer we connect to; `floodfill` asks the floodfill for a
%% DeliveryStatus acknowledgement back to us (direct reply, tunnel ID 0).
send_our_router_info(ConnPid, Transport, Local, Mode) ->
    OurRI = maps:get(ri, Local),
    Hash = i2p_router_info:hash(OurRI),
    case Mode of
        plain -> send_store(ConnPid, Transport, Hash, OurRI, 0, undefined);
        floodfill -> send_store(ConnPid, Transport, Hash, OurRI, ff_reply_token(), {0, Hash})
    end.

%% i2pd forbids the 0xFFFFFFFF "ignore" reply token; any other nonzero value
%% requests the acknowledgement.
ff_reply_token() ->
    <<Token:32/big>> = crypto:strong_rand_bytes(4),
    case Token of
        16#FFFFFFFF -> 1;
        _ -> Token
    end.

%% The boot floodfill-discovery kick chooses a small bounded set of
%% eligible floodfills and fire exploratory lookups. Reseed completion calls
%% this again after its RouterInfos have reached the peer manager. If the
%% NetDb has no eligible floodfill yet, fall back to at most three known seeds
%% so a small or unusual bundle can still make progress.
kick_floodfill_discovery(State) ->
    Candidates0 = discovery_candidates(State),
    Candidates =
        case application:get_env(i2per, live_network) of
            {ok, false} ->
                OurHash = maps:get(our_hash, State),
                [Hash || Hash <- Candidates0, Hash =:= OurHash];
            _ ->
                Candidates0
        end,
    lists:foreach(
        fun(Hash) ->
            case peer_status(Hash, State) of
                none -> i2p_peer:lookup(Hash, exploratory);
                _ -> ok
            end
        end,
        Candidates
    ),
    State.

discovery_candidates(#{our_hash := OurHash, known := Known, seed_order := Seeds}) ->
    Floodfills = i2p_netdb_srv:closest_floodfills(OurHash, 3, [OurHash]),
    case Floodfills of
        [] ->
            %% **`seed_order`, not `known`.** This is the fallback for a router
            %% with no eligible floodfill in its NetDb, and the operator ranked
            %% these seeds by putting them in that order. Iterating the map
            %% instead would pick three at random, so `seed_order` is the
            %% ranking and `known` is only consulted for the RouterInfo.
            lists:sublist(
                [Hash || Hash <- Seeds, dialable_in_known(Hash, Known)], 3
            );
        _ ->
            Floodfills
    end.

dialable_in_known(Hash, Known) ->
    case maps:find(Hash, Known) of
        {ok, #{ri := RI}} -> dialable_ri(RI);
        error -> false
    end.

dialable_ri(RI) ->
    case i2p_router_info:ntcp2_connector(RI) of
        {ok, _} ->
            true;
        _ ->
            i2p_identity:ssu2_enabled() andalso
                i2p_router_info:ssu2_address_options(RI) =/= error
    end.

%% App-env override for the boot kick delay; falls back to the default.
%% Stays a case: reads application env, which is not guard-legal.
discovery_kick_ms() ->
    case application:get_env(i2per, floodfill_discovery_delay_ms) of
        {ok, Ms} when is_integer(Ms), Ms >= 0 -> Ms;
        _ -> ?FLOODFILL_DISCOVERY_KICK_MS
    end.

%% Cancel a pending timer found by maps:find/2; a missing key stays `ok`.
cancel_timer({ok, Ref}) ->
    erlang:cancel_timer(Ref);
cancel_timer(error) ->
    ok.

floodfill_publish(State) ->
    case application:get_env(i2per, live_network) of
        {ok, false} ->
            State;
        _ ->
            %% Re-sign the RouterInfo with a fresh publish timestamp before
            %% announcing, so peer netDbs never age our RouterInfo out (they drop
            %% RouterInfos older than ~27 h). The router hash is unchanged.
            Local = i2p_identity:rebuild_router_info(maps:get(local, State)),
            State1 = State#{local := Local},
            OurHash = maps:get(our_hash, State1),
            FFs = i2p_netdb_srv:closest_floodfills(OurHash, 3, [OurHash]),
            lists:foldl(fun(FFHash, Acc) -> publish_to_ff(FFHash, Acc) end, State1, FFs)
    end.

publish_to_ff(FFHash, State) ->
    case peer_status(FFHash, State) of
        connected ->
            {ok, PeerState} = peer_state(FFHash, State),
            ConnPid = maps:get(conn, PeerState),
            Transport = maps:get(transport, PeerState, ntcp2),
            send_our_router_info(ConnPid, Transport, maps:get(local, State), floodfill),
            State;
        _ ->
            %% Connect first so the peer entry exists, then flag the
            %% announce-on-ready so the first RouterInfo this floodfill sees
            %% carries the reply token (never a token-free self-announce).
            State1 = connect_to_hash(FFHash, State),
            mark_ff_publish(FFHash, State1)
    end.

%% Connect to a hash whose RouterInfo is in the NetDb (a floodfill discovered
%% through exploration), reusing the announce-on-ready path.
connect_to_hash(Hash, State) ->
    case i2p_netdb_srv:find(Hash) of
        {ok, RI} -> connect_to(RI, State);
        not_found -> State
    end.

mark_ff_publish(PeerHash, State) ->
    case peer_state(PeerHash, State) of
        {ok, PeerState} -> put_peer(PeerHash, PeerState#{ff_publish => true}, State);
        error -> State
    end.

clear_ff_publish(PeerHash, State) ->
    {ok, PeerState} = peer_state(PeerHash, State),
    put_peer(PeerHash, maps:remove(ff_publish, PeerState), State).

send_pending(ConnPid, Transport, PeerHash, State) ->
    case maps:find(PeerHash, maps:get(pending, State)) of
        {ok, LookupTypes} ->
            FromHash = maps:get(our_hash, State),
            lists:foreach(
                fun(LookupType) ->
                    send_db_lookup(ConnPid, Transport, FromHash, PeerHash, LookupType)
                end,
                LookupTypes
            ),
            State#{pending := maps:remove(PeerHash, maps:get(pending, State))};
        error ->
            State
    end.

enqueue_lookup(PeerHash, LookupType, State) ->
    Pending = maps:get(pending, State),
    Existing = maps:get(PeerHash, Pending, []),
    case lists:member(LookupType, Existing) of
        true ->
            State;
        false ->
            State#{pending := maps:put(PeerHash, [LookupType | Existing], Pending)}
    end.

%% Send one complete I2NP message over the peer's transport. NTCP2 takes a
%% pre-encoded `i2p_framing` block; SSU2 takes the message split into its
%% type/msg-id/body components (the SSU2 session re-adds the 9-byte short
%% header inside its own I2NP block).
%%
%% Neither transport's send makes this process wait, and that is the property
%% this function is shaped around rather than a detail of it. This is a single
%% `gen_server` through which every inbound message from every connection
%% passes, so a send that blocked on one connection stopped I2NP for all of
%% them. Both entries are casts now (`f:i2p_ntcp2_conn:send/2`,
%% `f:i2p_ssu2_conn:send_i2np/4`), and a send to a connection that cannot take
%% it is lost rather than waited on — which the monitor on every connection
%% already turns into a disconnect and a backoff, the same recovery a failed
%% connect gets. Nothing here branches on the result, because there is none.
send_i2np(ConnPid, Transport, I2NPMsg) ->
    %% Stays a case: is_process_alive/1 is a BIF but not guard-legal.
    case is_process_alive(ConnPid) of
        true ->
            case Transport of
                ntcp2 ->
                    Wire = i2p_i2np:encode(I2NPMsg),
                    Block = i2p_framing:encode_block(3, Wire),
                    ok = i2p_ntcp2_conn:send(ConnPid, Block);
                ssu2 ->
                    #{type := Type, msg_id := <<MsgId:32>>, body := Body} = I2NPMsg,
                    ok = i2p_ssu2_conn:send_i2np(ConnPid, Type, MsgId, Body)
            end;
        false ->
            ok
    end.

%% Transport-agnostic teardown for a peer/inbound connection. Asks the
%% session to close gracefully, but never blocks: an owner that ignores the
%% close request (the other transport) is torn down with a normal shutdown
%% exit after a short grace period.
stop_conn(ConnPid) ->
    Ref = make_ref(),
    Mon = erlang:monitor(process, ConnPid),
    ConnPid ! {stop, self(), Ref},
    receive
        {stopped, Ref} ->
            erlang:demonitor(Mon, [flush]),
            ok;
        {'DOWN', Mon, process, ConnPid, _} ->
            ok
    after 500 ->
        erlang:demonitor(Mon, [flush]),
        _ = catch exit(ConnPid, shutdown),
        ok
    end.

%% learn_ri/2 — record an out-of-band RouterInfo (reseed) without dialling it.
%%
%% The NetDb can refuse a RouterInfo, and that outcome used to be discarded
%% here, so a refused reseed was indistinguishable from an accepted one:
%% remember_ri/2 added it to the known list either way and nothing was logged.
%% A silently failing reseed then looked exactly like a working one, and the
%% only symptom was a NetDb that never reached min_routers.
%%
%% Outcomes split in two. `older` means an equal-or-newer copy is already
%% stored, so the RouterInfo IS in the NetDb and remembering it is correct. The
%% clock rejections, `from_future` and `too_old`, mean it is not, so log those
%% and leave it out of the known list rather than treating it as dialable.
learn_ri(RI, State) ->
    case i2p_netdb_srv:store(RI, erlang:system_time(millisecond)) of
        Outcome when Outcome =:= added; Outcome =:= updated; Outcome =:= older ->
            remember_ri(RI, State);
        Refused ->
            %% Log-only. An out-of-band RouterInfo nobody asked for is not a
            %% DatabaseStore on a pending lookup, so there is no lookup to fail and
            %% nothing for `db_store_not_stored` to be about.
            i2p_log:emit(
                netdb_refused_routerinfo,
                "netdb refused RouterInfo ~0p: ~0p",
                [i2p_router_info:hash(RI), Refused]
            ),
            State
    end.

%% A RouterInfo the NetDb accepted, which also means we should be willing to
%% dial it. `remember_ri/2` is the same structure the seed set lives in.
%%
%% **Bounded, and keyed by hash.** Two reasons, and the second is the one that
%% made it a map rather than a capped list:
%%
%% - every distinct RouterInfo the router accepts was retained for the life of
%%   the process, at roughly the size of a RouterInfo each. Nothing ever
%%   removed one, so this grew without limit on a router that is being fed
%%   distinct RouterInfos;
%% - and because it was a *list*, `known_hash/2` was `lists:any/2` over all of
%%   it, on the dial path, per accepted RouterInfo and per dial decision. A cap
%%   alone would have bounded the growth and left an O(n) scan behind.
%%
%% An existing entry is *not* re-inserted on a repeat RouterInfo, so a peer we
%% already know does not get its place in the cap refreshed by a duplicate.
remember_ri(RI, State = #{known := Known}) ->
    Hash = i2p_router_info:hash(RI),
    case maps:is_key(Hash, Known) of
        true ->
            State;
        false ->
            Known1 = trim_known(maps:put(Hash, #{ri => RI, hash => Hash}, Known)),
            State#{known := Known1}
    end.

%% Enforce `?MAX_KNOWN` by dropping the stalest RouterInfo.
%%
%% **By publish time, which is the thing the entry actually stores.** A
%% RouterInfo is republished rather than mutated, so its `published` field is
%% both how fresh the knowledge is and the same measure `m:i2p_netdb` expires
%% its own entries by. Evicting the stalest here keeps the two structures
%% answering the same question the same way, and it needs no extra field and no
%% second order to maintain.
%%
%% Not least-recently-dialed. That would need an order touched on the dial path,
%% which is the path this change exists to keep cheap.
trim_known(Known) when map_size(Known) =< ?MAX_KNOWN ->
    Known;
trim_known(Known) ->
    ok = i2p_stats:add(known_evicted, 1),
    maps:remove(oldest_known(Known), Known).

%% The hash whose RouterInfo carries the earliest publish time.
%%
%% **A scan, and said so rather than hidden.** O(n) at the cap, run once per
%% insert *past* the cap, so it amortises to nothing for a router sitting at its
%% cap. An ordered map would make it O(1) and cost a structure maintained on the
%% dial path; at ?MAX_KNOWN = 500 the scan is not what matters here, and if it
%% ever becomes what matters that is a change to make against a measurement.
oldest_known(Known) ->
    Oldest = maps:fold(
        fun(Hash, #{ri := RI}, Acc) ->
            case Acc of
                undefined ->
                    {Hash, i2p_router_info:published(RI)};
                {_H, Ts} ->
                    case i2p_router_info:published(RI) < Ts of
                        true -> {Hash, i2p_router_info:published(RI)};
                        false -> Acc
                    end
            end
        end,
        undefined,
        Known
    ),
    element(1, Oldest).

find_peer_config(Hash, #{known := Known, peers := Peers}) ->
    case maps:find(Hash, Known) of
        {ok, Config} ->
            Config;
        error ->
            case maps:find(Hash, Peers) of
                {ok, #{config := Config}} -> Config;
                error -> undefined
            end
    end.

connect_to(RI, State) ->
    Hash = i2p_router_info:hash(RI),
    case peer_status(Hash, State) of
        none ->
            case dialable_ri(RI) of
                true ->
                    %% `remember_ri/2` rather than a bare insert, so the entry goes
                    %% through the `?MAX_KNOWN` bound like every other one. It was
                    %% a raw `maps:put` shape once the list became a map, and a
                    %% second write path around the bound is how a cap stops being
                    %% a cap.
                    State1 = remember_ri(RI, State),
                    maybe_connect(Hash, State1);
                false ->
                    State
            end;
        _ ->
            State
    end.

peer_state(Hash, #{peers := Peers}) ->
    maps:find(Hash, Peers).

peer_status(Hash, State) ->
    case peer_state(Hash, State) of
        {ok, #{status := Status}} -> Status;
        error -> none
    end.

backoff_elapsed(PeerHash, State) ->
    {ok, #{backoff := Backoff, last_attempt := Last}} = peer_state(PeerHash, State),
    erlang:system_time(second) - Last >= Backoff.

put_peer(Hash, PeerState, #{peers := Peers} = State) ->
    State#{peers := maps:put(Hash, PeerState, Peers)}.

enter_backoff(PeerHash, State) ->
    {ok, PeerState} = peer_state(PeerHash, State),
    Attempts = maps:get(attempts, PeerState),
    Backoff = calculate_backoff(Attempts),
    Now = erlang:system_time(second),
    Updated = PeerState#{
        conn := undefined,
        mon := undefined,
        status := backoff,
        backoff := Backoff,
        attempts := Attempts + 1,
        last_attempt := Now
    },
    i2p_peer_rep:connect_failed(PeerHash),
    _ = erlang:send_after(Backoff * 1000, self(), {retry_peer, PeerHash}),
    %% The interval is returned as well as stored. It is the only figure that
    %% distinguishes a peer being retried aggressively from one the router has
    %% written off, and `f:handle_connect_failed/3` announces it. The other two
    %% callers of this function are connection *drops*, not connect failures, and
    %% are left to `peer_disconnected`.
    {put_peer(PeerHash, Updated, State), Backoff}.

calculate_backoff(Attempts) ->
    min(?MAX_BACKOFF_SECONDS, trunc(math:pow(2, Attempts))).

find_conn_peer(ConnPid, #{peers := Peers}) ->
    case
        [
            Hash
         || {Hash, PeerState} <- maps:to_list(Peers),
            maps:get(conn, PeerState, undefined) =:= ConnPid
        ]
    of
        [Hash | _] -> {Hash, maps:get(Hash, Peers)};
        [] -> not_found
    end.

%% Resolve a connection pid to its peer hash, whether the connection was dialed
%% outbound or accepted inbound. Outbound connections carry their full peer
%% state; inbound ones return an empty state (no backoff bookkeeping).
conn_peer_hash(ConnPid, State) ->
    case find_conn_peer(ConnPid, State) of
        {Hash, PeerState} ->
            {Hash, PeerState};
        not_found ->
            case maps:find(ConnPid, maps:get(inbound, State, #{})) of
                {ok, {Hash, _, _}} -> {Hash, #{}};
                error -> not_found
            end
    end.

find_peer_by_hash(Hash, #{peers := Peers}) ->
    case maps:find(Hash, Peers) of
        {ok, #{conn := Conn, transport := Transport}} when Conn =/= undefined ->
            {ok, Conn, Transport};
        _ ->
            error
    end.

find_peer_by_mon(MonRef, #{peers := Peers}) ->
    case
        [
            Hash
         || {Hash, PeerState} <- maps:to_list(Peers), maps:get(mon, PeerState, undefined) =:= MonRef
        ]
    of
        [Hash | _] -> {Hash, maps:get(Hash, Peers)};
        [] -> not_found
    end.

%% Forward a non-DB I2NP message to the tunnel manager if it is registered.
forward_to_tunnel(ConnPid, Msg, #{our_hash := OurHash} = _State) ->
    PeerHash =
        case conn_peer_hash(ConnPid, _State) of
            {Hash, _} -> Hash;
            not_found -> OurHash
        end,
    case erlang:whereis(i2p_tunnel_srv) of
        Pid when is_pid(Pid) ->
            gen_server:cast(Pid, {i2np, ConnPid, PeerHash, Msg});
        undefined ->
            ok
    end.

%% Queue a message to be sent once the peer connection becomes ready.
%%
%% **Bounded in depth, dropping the OLDEST.** Two properties, and the ordering is
%% the one that is easy to get backwards:
%%
%% - `enqueue_send/3` prepends, so the head is the newest and the tail is the
%%   oldest. A relay frame belongs to a tunnel, and a frame that has waited is
%%   worth less than one that has not, so a full queue sheds its tail. Taking
%%   the head instead would keep the frame that has been waiting longest and
%%   deliver it in preference to a fresh one.
%% - The cap is what stops a peer that never connects from accumulating; the age
%%   in `f:sweep/1` is what stops the *capped* queue from being held for ever.
%%   Neither alone is enough: a cap alone converts unbounded growth into a
%%   bounded 64 KB per peer retained permanently, which is still a leak across
%%   every dead peer the router ever learned.
%%
%% A refused frame is counted. A frame dropped for want of queue space is a
%% different operator fact from one dropped for want of a route
%% (`transit_frames_dropped_no_route` on #W46KMT8), and a queue that is silently
%% truncating is exactly the kind of thing this board has twice found.
enqueue_send(PeerHash, Msg, #{pending_sends := Pending} = State) ->
    Existing = maps:get(PeerHash, Pending, []),
    %% Stamped on the way in, because the age sweep has to distinguish a frame
    %% queued a moment ago from one queued five minutes ago and the queue itself
    %% carries no other time.
    Stamped = {at, erlang:system_time(millisecond), Msg},
    case length(Existing) >= ?MAX_PENDING_SENDS_PER_PEER of
        true ->
            ok = i2p_stats:add(pending_sends_dropped_depth, 1),
            Trimmed = lists:sublist(Existing, ?MAX_PENDING_SENDS_PER_PEER - 1),
            State#{
                pending_sends := maps:put(
                    PeerHash, [Stamped | Trimmed], Pending
                )
            };
        false ->
            State#{pending_sends := maps:put(PeerHash, [Stamped | Existing], Pending)}
    end;
enqueue_send(PeerHash, Msg, State) ->
    enqueue_send(PeerHash, Msg, State#{pending_sends => #{}}).

%% Flush queued messages to a newly connected peer.
send_pending_sends(ConnPid, Transport, PeerHash, #{pending_sends := Pending} = State) ->
    case maps:find(PeerHash, Pending) of
        {ok, Msgs} ->
            %% Unwraps the `{at, _, _}` stamp and reverses, so a peer receives
            %% its frames in the order they were queued rather than the order
            %% they were enqueued.
            lists:foreach(
                fun({_at, _Ts, Msg}) -> send_i2np(ConnPid, Transport, Msg) end,
                lists:reverse(Msgs)
            ),
            State#{pending_sends := maps:remove(PeerHash, Pending)};
        error ->
            State
    end;
send_pending_sends(_ConnPid, _Transport, _PeerHash, State) ->
    State.
