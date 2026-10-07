-module(i2p_tunnel_srv).

-moduledoc """
Tunnel participation manager: builds outbound and inbound ECIES tunnels,
serves transit tunnels for other routers, processes OTBRM replies, injects
TunnelGateway payloads at inbound gateways, and delivers tunnel data to
local endpoints.

This GenServer owns the tunnel state machine for ECIES
`t:i2per/long i2p-spec/tunnel-creation-ecies` in every role: creator, transit participant, inbound gateway (IBGW), and local
inbound endpoint. It is a `permanent` child of `m:i2per_sup`. The role logic
itself lives in three pure helper modules over the same state map:

- `m:i2p_tunnel_build` — creator-side outbound/inbound builds and OTBRM
  processing.
- `m:i2p_tunnel_relay` — message routing: transit hops, inbound gateway,
  local endpoint dispatch, garlic clove handling.
- `m:i2p_tunnel_publish` — client LeaseSet publication, pool targets and
  per-session length demands, selection helpers, expiry sweep.

## Outbound builds (creator role)

On `f:build_outbound/0`, `m:i2p_tunnel_build` picks 3 hops from the NetDb,
generates fresh tunnel IDs, encrypts per-record build request records via
`m:i2p_ecies`, wraps them in a garlic message via `m:i2p_garlic`, and sends
the STB (type 25) to the first hop via `m:i2p_peer`. The OTBRM (type 26) is
matched by its I2NP message ID; reply layers are peeled via
`m:i2p_tunnel:process_otbrm/2` and an all-zero ret-code set activates the
tunnel for gateway use.

## Inbound builds (creator role)

On `f:build_inbound/0` the record topology points back at us: hops are
ordered farthest-first, the farthest slot carries the inbound-gateway flag
(IBGW), and the nearest slot's next-router is our own hash — so the sealed
STB travels `IBGW → … → us`. A fourth "fake" record (our truncated hash
prefix, Noise-N encrypted to our own static key, per spec) hides the fact
that the next hop is the originator. When the modified type-25 message
returns, we peel the real slots' reply layers, validate our fake record by
opening it, and activate the tunnel keyed by our endpoint receive ID.

Outbound builds use an active inbound tunnel as their reply path. The reply
is delivered through that inbound gateway and activates the outbound tunnel
when every ret code is zero.
## Transit tunnels (hop role)

Incoming type-25 messages are processed with
`i2p_tunnel:process_short_tunnel_build/4`. Accepted records create a transit
entry keyed by receive tunnel ID; rejected ones (capacity or duplicate ID)
seal ret code 30. Either way the modified record list is forwarded FORWARD
to the record's next hop with the same message ID — replies ride forward to
the build path's last recipient. Type-18 tunnel data on our transit tunnels
is encrypted one layer inward (`f:i2p_tunnel:process_tunnel_data/4`).
Endpoint (OBEP-for-others) roles assemble an OTBRM and deliver it down the
reply path named in the accepted record (RGarlic or direct).

## Inbound gateway role

A transit entry created from a gateway-flagged record serves as an inbound
gateway: type-19 TunnelGateway messages arriving on its receive ID are
fragmented into plaintext frames (`m:i2p_tunnel:gateway/5`), encrypted one
layer, and forwarded as TunnelData toward the creator.

## Outbound gateway role

As the creator of an active outbound tunnel we are its outbound gateway: a
standard-header I2NP message is fragmented into plaintext frames
(`m:i2p_tunnel:gateway_all/4`), every hop's inverse layer is pre-applied
(`m:i2p_tunnel:obgw_prep/2`), and each frame goes to the first hop as
type-18 TunnelData. After each participant hop adds its own layer on
forward, the plaintext pops out at the remote endpoint. The fragment
delivery instructions carried in the frames decide where the far end routes
the payload — `{tunnel, GatewayHash, TunnelID}` names a remote inbound
tunnel's gateway, which is how client streams reach a lease.

**The manager reads the map; the process that plays the role does the work.**
There are two entry points, and they differ only in which process runs the
crypto:

- **A client send takes the role itself.** `f:outbound_injection/1` reads the
  tunnel map and returns the first hop plus this tunnel's layer keys;
  `f:inject/3` then runs the whole sequence in the calling connection's own
  process. Two client sends no longer serialise inside one mailbox, and
  neither is gated by transit frames for other routers or by a tunnel build.
- **A lookup send stays here.** `m:i2p_lookup_srv` and
  `m:i2p_peer:reply_via_outbound/3` are singletons rather than connections —
  and `m:i2p_peer` is the process every send path in the router goes through,
  the worst possible host for a per-connection workload. They use
  `f:send_via_outbound/3`, which is the same role played in the manager.

`f:inject/3` is the one implementation; `f:send_via_outbound/3` calls it. So
the wire output cannot drift between the two, and a change to the framing
lands in both.

## Local inbound endpoint

Tunnel data arriving on one of OUR active inbound tunnels' receive IDs is
unwrapped layer-by-layer (`f:i2p_tunnel:ibep_unwrap/2`), checksummed, and
parsed; complete messages are dispatched locally (garlic cloves go through
the same clove dispatcher as direct garlic). Garlic that our router key
cannot open is offered to the registered SAM sessions: the destination
whose ECIES private key opens it receives the payload as
`{stream_data, Payload}` — the end-to-end client path.

Transit entries expire after the transit lifetime; the periodic sweep also
bounds table growth and expires local tunnels after their lifetime.

## Tunnel pool

When app env `i2per` -> `tunnel_pool` carries a targets map
(`#{outbound => N, inbound := M}`), a periodic tick tops the pools up to
those counts: it counts active plus pending builds per direction and queues
at most one build per direction per tick until the target is met. Outbound
builds name an active inbound tunnel as their reply path, so the pool
bootstraps inbound first exactly like manual builds. Without the env the
manager only builds on explicit `f:build_outbound/0` / `f:build_inbound/0`.

## Exploratory pool

NetDb lookups and their tunnel-delivered replies run over a short-hops
`exploratory` / `exploratory_in` pool instead of the client tunnels, so
tunnel gossip never competes with client traffic for lease/capacity slots.
The same `tunnel_pool` env map optionally declares `exploratory => N`
(the size, default 2 when present) and `exploratory_hops => H` (1..3,
default 2); without the `exploratory` key the pool stays off. When
configured, the tick keeps `N` active-or-pending tunnels per exploratory
direction at `H` hops. Reply paths stay inside the exploratory pool. Lookups
pick `f:pick_lookup_inbound/0` / `f:pick_lookup_outbound/0`, which prefer
the exploratory pools and fall back to the client pools while they
bootstrap.

SAM sessions can additionally demand tunnel lengths:
`f:set_lengths/3` records a session's `inbound.length` / `outbound.length`
options, and the same tick keeps at least one active or pending tunnel of
each demanded hop count per direction while the session lives (monitored —
the demand dies with the session). `f:pick_outbound/1`, `f:pick_inbound/1`
and `f:publish_lease_set/3` prefer tunnels of a requested length and fall
back to any.

## Client LeaseSet publication

SAM destinations need a LeaseSet2 so remote peers can find their inbound
tunnels. `f:publish_lease_set/2` records the destination and immediately
attempts publication: the freshest active inbound tunnel becomes the lease
(gateway hash + receive ID, valid until shortly before tunnel expiry), the
signed LeaseSet2 is stored locally and pushed to the closest floodfills.
Destinations recorded before any tunnel existed are retried by the periodic
tick, which also republishes aging leases as tunnels rotate. The `/3` form
pins the lease to the session's demanded inbound length when such tunnels
exist.

## Usage

```erlang
%% Build an outbound 3-hop tunnel
ok = i2p_tunnel_srv:build_outbound(),

%% Build an inbound 3-hop tunnel (we are the endpoint)
ok = i2p_tunnel_srv:build_inbound(),

%% Inspect pending builds, active tunnels, and transit load
#{pending := Pending, tunnels := Tunnels, transit := Transit} =
    i2p_tunnel_srv:status(),

%% Shut the manager down
ok = i2p_tunnel_srv:stop().
```
""".
-behaviour(gen_server).

-export([
    start_link/1,
    build_outbound/0,
    build_inbound/0,
    set_lengths/3,
    pick_outbound/0,
    pick_outbound/1,
    pick_inbound/0,
    pick_inbound/1,
    pick_exploratory_out/0,
    pick_exploratory_in/0,
    pick_lookup_outbound/0,
    pick_lookup_inbound/0,
    outbound_injection/1,
    inject/3,
    send_via_outbound/3,
    publish_lease_set/2,
    publish_lease_set/3,
    status/0,
    demands/0,
    stop/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-export_type([
    tunnel_srv_state/0,
    send_delivery/0,
    outbound_injection/0,
    pending_build/0,
    pending_inbound/0,
    tunnel_entry/0,
    inbound_entry/0,
    transit_entry/0,
    published_lease/0,
    length_demand/0
]).

-define(NUM_HOPS, 3).
-define(SWEEP_INTERVAL_MS, 60000).
-define(POOL_TICK_MS, 30000).

-doc """
Tunnel manager state: our identity keys, pending builds (outbound and
inbound), active tunnels we created, transit tunnels we serve for other
routers, local inbound tunnels we terminate, the short-hop exploratory pools
(lookup pools), and the token buckets pacing transit relay bandwidth and
tunnel-build acceptance (`none` = unlimited).
""".
-type tunnel_srv_state() :: #{
    local := i2p_peer:local_keys(),
    pending := #{i2p_i2np:message_id() := pending_build()},
    pending_in := #{i2p_i2np:message_id() := pending_inbound()},
    tunnels := #{0..16#FFFFFFFF := tunnel_entry()},
    inbound := #{0..16#FFFFFFFF := inbound_entry()},
    transit := #{0..16#FFFFFFFF := transit_entry()},
    exploratory := #{0..16#FFFFFFFF := tunnel_entry()},
    exploratory_in := #{0..16#FFFFFFFF := inbound_entry()},
    published => #{i2p_crypto:hash() := published_lease()},
    demands => #{pid() => length_demand()},
    demand_mons => #{pid() => reference()},
    next_tunnel_id := non_neg_integer(),
    transit_bucket := i2p_token_bucket:bucket() | none,
    build_bucket := i2p_token_bucket:bucket() | none
}.

-doc """
Per-session tunnel-length demand registered from SAM SESSION CREATE options:
the hop counts the session wants for its inbound and outbound tunnels.
""".
-type length_demand() :: #{in_len := 1..?NUM_HOPS, out_len := 1..?NUM_HOPS}.

-doc """
A client destination whose LeaseSet2 this router publishes: the identity and
signing seed needed to rebuild it, and when the current lease expires
(seconds since epoch; 0 while publication is still pending).
""".
-type published_lease() :: #{
    dest := i2p_keys:identity(),
    seed := i2p_crypto:ed25519_seed(),
    until_sec := non_neg_integer(),
    in_len => pos_integer()
}.

-doc "A pending outbound tunnel build awaiting its OTBRM reply.".
-type pending_build() :: #{
    tunnel_ids := [0..16#FFFFFFFF],
    router_hashes := [i2p_crypto:hash()],
    hop_keys := [i2p_ecies:hop_build_keys()],
    timer_ref := reference(),
    pool := i2p_tunnel_build:pool()
}.

-doc "A pending inbound tunnel build awaiting our own STB to come back.".
-type pending_inbound() :: #{
    tunnel_ids := [0..16#FFFFFFFF],
    router_hashes := [i2p_crypto:hash()],
    hop_keys := [i2p_ecies:hop_build_keys()],
    timer_ref := reference(),
    pool := i2p_tunnel_build:pool()
}.

-doc "An active outbound tunnel entry with per-hop data-layer keys.".
-type tunnel_entry() :: #{
    tunnel_ids := [0..16#FFFFFFFF],
    router_hashes := [i2p_crypto:hash()],
    layers := [i2p_tunnel:layer_keys()],
    built_at := non_neg_integer()
}.

-doc """
An active local inbound tunnel entry: the remote hops in data-path order,
their layer keys (we unwrap every layer as the endpoint), and the fragment
reassembly map for messages still crossing the tunnel.
""".
-type inbound_entry() :: #{
    tunnel_ids := [0..16#FFFFFFFF],
    router_hashes := [i2p_crypto:hash()],
    layers := [i2p_tunnel:layer_keys()],
    frag_map := #{i2p_i2np:message_id() := #{non_neg_integer() := binary()}},
    built_at := non_neg_integer()
}.

-doc """
A transit tunnel we serve for another router's tunnel path. Gateway-role
entries (`is_gateway = true` in the hop info) additionally carry the
fragmentation state used when injecting TunnelGateway payloads.
""".
-type transit_entry() :: #{
    info := i2p_tunnel:hop_info(),
    created_at := non_neg_integer(),
    gw_state => map()
}.

-doc """
Where a reassembled outbound-tunnel payload goes at the far end:
`local` terminates at the remote OBEP's router, `{router, Hash}` pushes to
that router, and `{tunnel, GatewayHash, TunnelID}` injects into the named
inbound tunnel (the client-stream path to a remote lease).
""".
-type send_delivery() ::
    local
    | {router, i2p_crypto:hash()}
    | {tunnel, i2p_crypto:hash(), 0..16#FFFFFFFF}.

-doc """
Everything a caller needs to inject one I2NP message into one of our outbound
tunnels, and nothing it does not: the tunnel's ID, its first hop, and its
per-hop inverse layer keys. Obtained from `f:outbound_injection/1`, consumed by
`f:inject/3`.

**An unfinished send, deliberately.** `{ok, Injection}` says the tunnel was
active at the moment the injection was taken; it does not say the message
reached the first hop, because it has not been fragmented yet. A caller that
reads it as a completed send is wrong — and the gap is the point. Running the
framing and the inverse-layer crypto in the caller's own process is what keeps
a client send out of the manager's mailbox, so the answer has to arrive before
the work rather than after it.

`tunnel_id` is carried rather than echoed by the caller so that the ID the
frames are stamped with cannot drift from the ID the layer keys belong to.
""".
-type outbound_injection() :: #{
    tunnel_id := 0..16#FFFFFFFF,
    hop1 := i2p_crypto:hash(),
    layers := [i2p_tunnel:layer_keys()]
}.

%%%%%%% %%% Public API %%%%%%%

-doc """
Start the tunnel manager with our local identity keys.

Input: `Local` — `t:i2p_peer:local_keys/0`.
Output: `{ok, Pid}` once the manager is registered locally as
`i2p_tunnel_srv`.
""".
-spec start_link(i2p_peer:local_keys()) -> {ok, pid()} | {error, term()}.
start_link(Local) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Local], []).

-doc """
Initiate an outbound 3-hop ECIES tunnel build.

Picks 3 hops from the NetDb closest to our own hash, generates fresh
tunnel IDs, encrypts one Noise N session per record, wraps them in a garlic
message, and sends the STB (type 25) to the first hop.

Output: `ok` — the build is queued and the STB is sent asynchronously.
A build timeout timer is started; if the OTBRM reply does not arrive
in time, the build is cancelled.
""".
-spec build_outbound() -> ok.
build_outbound() ->
    gen_server:cast(?MODULE, build_outbound).

-doc """
Initiate an inbound 3-hop ECIES tunnel build (we are the endpoint).

Picks 3 hops from the NetDb, generates fresh tunnel IDs, and builds records
so that the sealed STB returns to us over the wire: the farthest hop is
flagged as the inbound gateway, each hop's next pointer leads toward us,
and a fourth fake record addressed to ourselves conceals that the path
terminates at its originator. The STB is sent directly to the IBGW.

Output: `ok` — the build is queued. A build timeout timer is started;
if our modified type-25 message does not return in time, the build is
cancelled.
""".
-spec build_inbound() -> ok.
build_inbound() ->
    gen_server:cast(?MODULE, build_inbound).

-doc """
Register a SAM session's tunnel-length demand: the pool tick keeps at
least one active or pending tunnel per direction at the demanded hop count
while the session lives. The demand is monitor-tracked and disappears with
the session process.

Input: `Pid` — the session process; `InLen`/`OutLen` — hop counts, 1..3.
Output: `ok` once recorded.
""".
-spec set_lengths(pid(), 1..?NUM_HOPS, 1..?NUM_HOPS) -> ok.
set_lengths(Pid, InLen, OutLen) ->
    gen_server:call(?MODULE, {set_lengths, Pid, InLen, OutLen}).

-doc """
Pick one active outbound tunnel at random for sending.

Output: `{ok, TunnelID, Entry}` where `TunnelID` is the first hop's receive
ID (the address tunnel frames are sent to) and `Entry` carries the hop
hashes and data-layer keys; `error` when no outbound tunnel is active.
""".
-spec pick_outbound() -> {ok, 0..16#FFFFFFFF, tunnel_entry()} | error.
pick_outbound() ->
    gen_server:call(?MODULE, pick_outbound).

-doc """
Pick one active outbound tunnel at random, preferring the requested hop
count.

Output: like `f:pick_outbound/0`; tunnels whose `router_hashes` length
equals `Len` are preferred, falling back to any active outbound tunnel.
""".
-spec pick_outbound(pos_integer()) -> {ok, 0..16#FFFFFFFF, tunnel_entry()} | error.
pick_outbound(Len) ->
    gen_server:call(?MODULE, {pick_outbound, Len}).

-doc """
Pick one active local inbound tunnel at random.

Output: `{ok, TunnelID, Entry}` where `TunnelID` is our endpoint receive ID
(the address remote senders name in leases) and `Entry` carries the hop
hashes (gateway first) and layer keys; `error` when none is active.
""".
-spec pick_inbound() -> {ok, 0..16#FFFFFFFF, inbound_entry()} | error.
pick_inbound() ->
    gen_server:call(?MODULE, pick_inbound).

-doc """
Pick one active local inbound tunnel at random, preferring the requested hop
count.

Output: like `f:pick_inbound/0`; tunnels whose `router_hashes` length
equals `Len` are preferred, falling back to any active inbound tunnel.
""".
-spec pick_inbound(pos_integer()) -> {ok, 0..16#FFFFFFFF, inbound_entry()} | error.
pick_inbound(Len) ->
    gen_server:call(?MODULE, {pick_inbound, Len}).

-doc """
Pick one active exploratory outbound tunnel at random (lookup pool).

Output: `{ok, TunnelID, Entry}` for the short-hop `exploratory` map;
`error` when none is active.
""".
-spec pick_exploratory_out() -> {ok, 0..16#FFFFFFFF, tunnel_entry()} | error.
pick_exploratory_out() ->
    gen_server:call(?MODULE, pick_exploratory_out).

-doc """
Pick one active exploratory inbound tunnel at random (lookup pool).

Output: `{ok, TunnelID, Entry}` for the short-hop `exploratory_in` map;
`error` when none is active.
""".
-spec pick_exploratory_in() -> {ok, 0..16#FFFFFFFF, inbound_entry()} | error.
pick_exploratory_in() ->
    gen_server:call(?MODULE, pick_exploratory_in).

-doc """
Pick an outbound tunnel for a NetDb lookup delivery.

Prefers the exploratory pool so tunnel gossip stays off client tunnels;
falls back to the client pool while the exploratory pool is still building.
""".
-spec pick_lookup_outbound() -> {ok, 0..16#FFFFFFFF, tunnel_entry()} | error.
pick_lookup_outbound() ->
    gen_server:call(?MODULE, pick_lookup_outbound).

-doc """
Pick an inbound tunnel to receive DatabaseLookup replies.

Prefers the exploratory pool, falling back to the client pool while the
exploratory pool is still building.
""".
-spec pick_lookup_inbound() -> {ok, 0..16#FFFFFFFF, inbound_entry()} | error.
pick_lookup_inbound() ->
    gen_server:call(?MODULE, pick_lookup_inbound).

-doc """
Take out an injection into one of our active outbound tunnels, leaving the
work to the caller.

This is the client send path, and the split is the point: the manager reads
its own map and answers, and the caller's process does the framing and the
inverse-layer crypto. Two client sends therefore no longer serialise inside
the manager, and neither is gated by the transit frames and tunnel builds it
also handles.

`Delivery` and `StdMsg` are deliberately **not** arguments. Nothing about
taking the injection depends on them, so passing them would suggest the
manager had done something with them by the time it answers.

Input: `TunnelID` — the tunnel's first-hop receive ID (as returned by
`f:pick_outbound/0`).
Output: `{ok, t:outbound_injection/0}` to be handed to `f:inject/3`, or
`error` when no outbound tunnel with that ID is active. **`error` is the
answer at the moment it was taken**, and the tunnel can be retired
immediately afterwards — the caller owns what happens next, including
counting a message it could not inject.
""".
-spec outbound_injection(0..16#FFFFFFFF) -> {ok, outbound_injection()} | error.
outbound_injection(TunnelID) ->
    gen_server:call(?MODULE, {outbound_injection, TunnelID}).

-doc """
Play the outbound-gateway role for one message, in the calling process.

Fragments `StdMsg` into plaintext frames carrying the far-end delivery
instructions (`m:i2p_tunnel:gateway_all/4`), pre-applies every hop's inverse
layer so plaintext emerges at the remote endpoint after each participant hop
re-encrypts its own layer (`m:i2p_tunnel:obgw_prep/2`), and hands each frame
to the first hop as type-18 TunnelData
(`m:i2p_tunnel_relay:send_tunnel_data/2`).

Input: `Injection` — from `f:outbound_injection/1`; `Delivery` — where the
far end routes the reassembled payload (`t:send_delivery/0`); `StdMsg` — the
full standard 16-byte-header I2NP message, typically a garlic message.
Output: `ok` once every frame is handed to the peer manager. Fragment
numbering restarts per message — follow-on frames carry their own message ID,
so reassembly at the far end is unaffected.

**The `ok` means "every frame was handed over", not "the message arrived".**
Frames for a hop this router has no RouterInfo for are dropped and counted as
`transit_frames_dropped_no_route` by the peer manager, which owns
reconnection; there is no delivery acknowledgement to return here.
""".
-spec inject(outbound_injection(), send_delivery(), binary()) -> ok.
inject(#{tunnel_id := TunnelID, hop1 := Hop1Hash, layers := Layers}, Delivery, StdMsg) ->
    Frames = outbound_frames(TunnelID, Delivery, StdMsg, Layers),
    lists:foreach(
        fun(Frame) -> i2p_tunnel_relay:send_tunnel_data(Hop1Hash, Frame) end,
        Frames
    ).

-doc """
Inject a standard-header I2NP message into one of our active outbound
tunnels (we act as its outbound gateway), **in the manager**.

The lookup path: `m:i2p_lookup_srv` and `m:i2p_peer:reply_via_outbound/3`
are singletons rather than connections, so there is no per-connection worker
to hand the work to — and `m:i2p_peer` is the process every send path in the
router goes through, which is the worst possible host for it. A client send
has a connection behind it and uses `f:outbound_injection/1` plus
`f:inject/3` instead; both run the same code.

Input: `TunnelID` — the tunnel's first-hop receive ID (as returned by
`f:pick_outbound/0`); `Delivery` — where the far end routes the reassembled
payload (`t:send_delivery/0`; use `{tunnel, GatewayHash, TunnelID}` to
reach a remote lease); `StdMsg` — the full standard 16-byte-header I2NP
message, typically a garlic message.

Output: `ok` once every frame is handed to the peer manager; `error` when
no outbound tunnel with that ID is active.
""".
-spec send_via_outbound(0..16#FFFFFFFF, send_delivery(), binary()) -> ok | error.
send_via_outbound(TunnelID, Delivery, StdMsg) ->
    gen_server:call(?MODULE, {send_via_outbound, TunnelID, Delivery, StdMsg}).

-doc """
Publish a LeaseSet2 for a SAM destination (fire-and-forget).

The destination is recorded and publication is attempted immediately: the
freshest active inbound tunnel becomes its lease, the signed LeaseSet2 goes
into the local NetDb and to the closest floodfills. When no inbound tunnel
is active yet the periodic tick retries until one exists.

Input: `Dest` — the client destination identity; `Seed` — its Ed25519
signing seed (the SAM session's `sign_priv`).
Output: `ok` once the request is queued.
""".
-spec publish_lease_set(i2p_keys:identity(), i2p_crypto:ed25519_seed()) -> ok.
publish_lease_set(Dest, Seed) ->
    gen_server:cast(?MODULE, {publish_lease_set, Dest, Seed}).

-doc """
Publish a LeaseSet2 for a SAM destination that requested a specific inbound
tunnel length.

Like `f:publish_lease_set/2`, but the published lease prefers an active
inbound tunnel with exactly `InLen` remote hops (falling back to any) —
both at first publication and on later refreshes.

Input: `Dest` — the client destination identity; `Seed` — its Ed25519
signing seed; `InLen` — the session's demanded inbound hop count.
Output: `ok` once the request is queued.
""".
-spec publish_lease_set(i2p_keys:identity(), i2p_crypto:ed25519_seed(), pos_integer()) -> ok.
publish_lease_set(Dest, Seed, InLen) ->
    gen_server:cast(?MODULE, {publish_lease_set, Dest, Seed, InLen}).

-doc """
Inspect the tunnel manager state.

Output: a map with `pending` (outbound builds awaiting OTBRM), `pending_in`
(inbound builds awaiting their returning STB), `tunnels` (active outbound
tunnels), `inbound` (active local inbound tunnels), and `transit` (tunnels
we serve for other routers).
""".
-spec status() ->
    #{
        pending := #{i2p_i2np:message_id() := pending_build()},
        pending_in := #{i2p_i2np:message_id() := pending_inbound()},
        tunnels := #{0..16#FFFFFFFF := tunnel_entry()},
        inbound := #{0..16#FFFFFFFF := inbound_entry()},
        transit := #{0..16#FFFFFFFF := transit_entry()},
        exploratory := #{0..16#FFFFFFFF := tunnel_entry()},
        exploratory_in := #{0..16#FFFFFFFF := inbound_entry()}
    }.
status() ->
    gen_server:call(?MODULE, status).

-doc """
Return the tunnel-length demands registered by SAM sessions.

Each entry maps an owning session process to the `in_len`/`out_len` hop counts
it requested via SESSION CREATE length options. An entry disappears with the
session process (the demand is monitor-tracked).
""".
-spec demands() -> #{pid() => length_demand()}.
demands() ->
    gen_server:call(?MODULE, demands).

-doc "Stop the tunnel manager gracefully.".
-spec stop() -> ok.
stop() ->
    gen_server:cast(?MODULE, stop).

%%%%%%% %%% gen_server callbacks %%%%%%%

init([Local]) ->
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), sweep),
    erlang:send_after(?POOL_TICK_MS, self(), pool_tick),
    {ok, #{
        local => Local,
        pending => #{},
        pending_in => #{},
        tunnels => #{},
        inbound => #{},
        transit => #{},
        exploratory => #{},
        exploratory_in => #{},
        published => #{},
        demands => #{},
        demand_mons => #{},
        next_tunnel_id => i2p_tunnel_build:generate_tunnel_id_base(),
        transit_bucket => init_bucket(transit_bandwidth_kbps, 1024),
        build_bucket => init_bucket(tunnel_build_rate, 1)
    }}.

handle_call(status, _From, State) ->
    {reply,
        maps:with(
            [pending, pending_in, tunnels, inbound, transit, exploratory, exploratory_in], State
        ),
        State};
handle_call(demands, _From, #{demands := Demands} = State) ->
    {reply, Demands, State};
handle_call({set_lengths, Pid, InLen, OutLen}, _From, State) ->
    {reply, ok, i2p_tunnel_publish:store_demand(Pid, InLen, OutLen, State)};
handle_call(pick_outbound, _From, #{tunnels := Tunnels} = State) ->
    {reply, i2p_tunnel_publish:random_entry(Tunnels), State};
handle_call({pick_outbound, Len}, _From, #{tunnels := Tunnels} = State) ->
    {reply, i2p_tunnel_publish:preferred_entry(Tunnels, Len), State};
handle_call(pick_inbound, _From, #{inbound := Inbound} = State) ->
    {reply, i2p_tunnel_publish:random_entry(Inbound), State};
handle_call({pick_inbound, Len}, _From, #{inbound := Inbound} = State) ->
    {reply, i2p_tunnel_publish:preferred_entry(Inbound, Len), State};
handle_call(pick_exploratory_out, _From, #{exploratory := Exploratory} = State) ->
    {reply, i2p_tunnel_publish:random_entry(Exploratory), State};
handle_call(pick_exploratory_in, _From, #{exploratory_in := ExploratoryIn} = State) ->
    {reply, i2p_tunnel_publish:random_entry(ExploratoryIn), State};
handle_call(pick_lookup_outbound, _From, #{exploratory := Exploratory, tunnels := Tunnels} = State) ->
    {reply, fallback_pick(Exploratory, Tunnels), State};
handle_call(
    pick_lookup_inbound, _From, #{exploratory_in := ExploratoryIn, inbound := Inbound} = State
) ->
    {reply, fallback_pick(ExploratoryIn, Inbound), State};
handle_call({outbound_injection, TunID}, _From, State) ->
    {reply, injection_for(TunID, find_outbound(State, TunID)), State};
handle_call({send_via_outbound, TunID, Delivery, StdMsg}, _From, State) ->
    {reply, send_over(injection_for(TunID, find_outbound(State, TunID)), Delivery, StdMsg), State};
handle_call(Request, _From, _State) ->
    %% Raising, and not a plausible reply. This used to answer `ok` to anything
    %% it did not recognise, which made a request-shape change that missed a
    %% caller *silently succeed* — the same defect class as the two
    %% false-claim tickets on this board, and a live landmine under exactly
    %% that change. A `permanent` child crashing is the loud outcome; the
    %% alternative was a caller believing a send happened.
    exit({i2p_tunnel_srv, unhandled_call, Request}).

handle_cast(build_outbound, State) ->
    {noreply, i2p_tunnel_build:do_build_outbound(State)};
handle_cast(build_inbound, State) ->
    {noreply, i2p_tunnel_build:do_build_inbound(State)};
handle_cast({publish_lease_set, Dest, Seed}, State) ->
    DestHash = i2p_keys:hash(Dest),
    {noreply, i2p_tunnel_publish:publish_into(Dest, Seed, DestHash, ?NUM_HOPS, State)};
handle_cast({publish_lease_set, Dest, Seed, InLen}, State) ->
    DestHash = i2p_keys:hash(Dest),
    {noreply, i2p_tunnel_publish:publish_into(Dest, Seed, DestHash, InLen, State)};
handle_cast(stop, #{pending := Pending, pending_in := PendingIn} = State) ->
    maps:foreach(
        fun(_MsgID, #{timer_ref := Ref}) -> erlang:cancel_timer(Ref) end,
        Pending
    ),
    maps:foreach(
        fun(_MsgID, #{timer_ref := Ref}) -> erlang:cancel_timer(Ref) end,
        PendingIn
    ),
    {stop, normal, State};
handle_cast({i2np, ConnPid, PeerHash, Msg}, State) ->
    {noreply, i2p_tunnel_relay:handle_routed_i2np(ConnPid, PeerHash, Msg, State)};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({build_timeout, MsgID}, #{pending := Pending, pending_in := PendingIn} = State) ->
    State1 = State#{
        pending := maps:remove(MsgID, Pending),
        pending_in := maps:remove(MsgID, PendingIn)
    },
    case maps:is_key(MsgID, Pending) orelse maps:is_key(MsgID, PendingIn) of
        true -> {noreply, State1};
        false -> {noreply, State}
    end;
handle_info(sweep, State) ->
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), sweep),
    {noreply, i2p_tunnel_publish:do_sweep(State)};
handle_info(pool_tick, State) ->
    erlang:send_after(?POOL_TICK_MS, self(), pool_tick),
    {noreply, i2p_tunnel_publish:do_pool_tick(State)};
handle_info({i2np, ConnPid, PeerHash, Msg}, State) ->
    {noreply, i2p_tunnel_relay:handle_routed_i2np(ConnPid, PeerHash, Msg, State)};
handle_info({'DOWN', _Mon, process, Pid, _Reason}, #{demand_mons := Mons} = State) ->
    case maps:is_key(Pid, Mons) of
        true -> {noreply, i2p_tunnel_publish:drop_demand(Pid, State)};
        false -> {noreply, State}
    end;
handle_info(_Msg, State) ->
    {noreply, State}.

%%%%%%% %%% Internal %%%%%%%

%% fallback_pick/2 — pick from the preferred tunnel map, or the fallback map
%% when the preferred one is empty (lookup pool preference).
-spec fallback_pick(
    #{0..16#FFFFFFFF := V}, #{0..16#FFFFFFFF := V}
) -> {ok, 0..16#FFFFFFFF, V} | error.
fallback_pick(Preferred, Fallback) ->
    case map_size(Preferred) of
        0 -> i2p_tunnel_publish:random_entry(Fallback);
        _ -> i2p_tunnel_publish:random_entry(Preferred)
    end.

%% find_outbound/2 — resolve a first-hop TunnelID across the client and
%% exploratory outbound maps so send_via_outbound works for both pools.
-spec find_outbound(i2p_tunnel_srv:tunnel_srv_state(), 0..16#FFFFFFFF) ->
    {ok, i2p_tunnel_srv:tunnel_entry()} | error.
find_outbound(#{tunnels := Tunnels, exploratory := Exploratory}, TunID) ->
    case maps:find(TunID, Tunnels) of
        {ok, _} = Ok -> Ok;
        error -> maps:find(TunID, Exploratory)
    end.

%% injection_for/2 — narrow a resolved entry to what the outbound-gateway role
%% actually reads: the first hop, and this tunnel's inverse layer keys. The
%% tunnel ID rides along so the caller cannot stamp frames with an ID the keys
%% do not belong to.
%%
%% **Reads the map and nothing else.** No framing, no crypto, no per-frame
%% send — that is the whole reason `f:inject/3` exists, and anything added to
%% this clause puts a client send's work back on the manager's clock.
-spec injection_for(0..16#FFFFFFFF, {ok, tunnel_entry()} | error) ->
    {ok, outbound_injection()} | error.
injection_for(TunnelID, {ok, #{router_hashes := [Hop1 | _], layers := Layers}}) ->
    {ok, #{tunnel_id => TunnelID, hop1 => Hop1, layers => Layers}};
injection_for(_TunnelID, error) ->
    error.

%% send_over/3 — the outbound-gateway role played in this process, for the
%% lookup paths that stay here. One caller by decision rather than by
%% accident: `m:i2p_lookup_srv` and `m:i2p_peer` are singletons, so there is no
%% per-connection worker to hand the work to.
-spec send_over({ok, outbound_injection()} | error, send_delivery(), binary()) ->
    ok | error.
send_over({ok, Injection}, Delivery, StdMsg) ->
    inject(Injection, Delivery, StdMsg);
send_over(error, _Delivery, _StdMsg) ->
    error.

%% outbound_frames/4 — build the wire frames for a creator injection into
%% one of our own outbound tunnels: fragment into plaintext frames carrying
%% the far-end delivery instructions, then pre-apply every hop's inverse
%% layer so plaintext emerges at the remote endpoint after each participant
%% hop re-encrypts its own layer.
%%
%% dialyzer: nowarn because i2p_tunnel:gateway_loop/7's inferred success
%% typing collapses onto its initial accumulator state, which makes Frames
%% look empty here; the roundtrip tests exercise the real behaviour.
-dialyzer({nowarn_function, outbound_frames/4}).
outbound_frames(TunID, Delivery, StdMsg, Layers) ->
    {Type, Target} = frag_delivery(Delivery),
    {Frames, _GwState} = i2p_tunnel:gateway_all(TunID, Type, Target, StdMsg),
    [i2p_tunnel:obgw_prep(Frame, Layers) || Frame <- Frames].

%% frag_delivery/1 — convert a t:send_delivery/0 term to the
%% f:i2p_tunnel:gateway/5 argument pair.
frag_delivery(local) ->
    {local, undefined};
frag_delivery({router, Hash}) ->
    {router, Hash};
frag_delivery({tunnel, GatewayHash, TunID}) ->
    {tunnel, {TunID, GatewayHash}}.

%% init_bucket/2 — build the token bucket pacing one of the two limited
%% work streams from its config key, or `none` when the key is unset. The
%% key's integer value is the rate in naturally-sized units (kilobytes per
%% second for relay bandwidth, builds per second for build pacing);
%% `TokensPerUnit` rescales to tokens per second. Burst capacity is four
%% seconds' worth of tokens, so the token bucket never stalls a burst of
%% less than four seconds' (unlimited uses) — and `none` stays unlimited.
init_bucket(Key, TokensPerUnit) ->
    case application:get_env(i2per, Key) of
        {ok, V} when is_integer(V), V > 0 ->
            i2p_token_bucket:new(V * TokensPerUnit, V * TokensPerUnit * 4);
        _ ->
            none
    end.
