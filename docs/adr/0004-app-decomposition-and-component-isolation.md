# 0004. App decomposition and component isolation

- Status: accepted
- Date: 2026-10-25
- Decided while refining the operator-surface and scaling model for 0.8.0

## Context

ADR 0001 settled that the core is data-only and presentation apps connect over the
Erlang network. That decision left open two questions that this ADR resolves:

1. **Which components become separate OTP applications?** The naive answer ("everything")
   collides with node-local data (ETS, `persistent_term`, sockets) and with the fact that
   some components need runtime hot start/stop while others tolerate a restart.
2. **How are components isolated inside the core?** The core's `i2per_sup` is a flat
   `one_for_one` supervisor with ~15–20 direct children. Components are isolated at the
   process level (a crash restarts only itself) but not at the supervision or enable/disable
   level.

A third question emerged from comparing `i2per_proxy` with i2pd's built-in proxy:
`i2per_proxy` and `i2per_tun` reach the core over the SAM wire protocol on TCP, which
contradicts ADR 0001's "Erlang network" rule and caps concurrency at one SAM session per
client flow. Companion apps should call core Erlang functions directly.

## Decision

### Tier 1 — separate OTP applications, location-transparent

These are optional, long-running services with hot start/stop value that communicate
over Erlang distribution (`gen_server` calls / `erpc`). They can run on any node.

| App | Owns | Status |
|---|---|---|
| `i2per_status` | Status web + versioned read API | Shipped |
| `i2per_proxy` | HTTP/SOCKS/BOB/I2PControl | Shipped (SAM-based; refactor to Erlang calls is E1CHFWF) |
| `i2per_tun` | TUN interface | Shipped (SAM-based; refactor to Erlang calls is E1CHFWF) |
| `i2per_sam` | SAM bridge (TCP 7656) | Candidate (extract from core; pairs with E1CHFWF) |
| `i2per_server_tunnels` | Server tunnel TCP listeners | Candidate |

SAM is the language-agnostic external interface. Making it a companion app means every
deployment that serves non-Erlang clients must start it alongside the core. That is an
acceptable contract (same as `i2per_status`), but it must be documented as
"always deployed alongside core" when SAM is needed.

### Tier 2 — separate OTP applications, node-local, co-located with core

These pass the "optional + long-running + hot start/stop" test but depend on VM-local
primitives (`persistent_term`, ETS, sockets). They are separate apps for isolation and
independent lifecycle, but **must run on the same node as the core**. They are not
location-transparent.

| App | Owns | Why node-local |
|---|---|---|
| `i2per_counters` | Counter refs + `persistent_term` state | `persistent_term` is VM-scoped |
| Transports (`i2per_ntcp2`, `i2per_ssu2`) | Transport supervisors + listeners | Packets arrive at a specific NIC; socket I/O is node-local |

Transports are **not** distributed across nodes. The data path cannot tolerate
distribution latency. They are separate apps for isolation (crash in NTCP2 does not
take down SSU2 or the core) and for optional code loading (don't include in the
release if unused), but they run on the core's node.

### Stays in core (not apps)

These are either required, one-shot, router-behavior toggles, or hot-path-coupled:

- **Required infrastructure:** config, event bus, NetDb, peer manager, tunnel manager,
  identity, reachability, counters (until extracted).
- **Router behavior (optional, hot-switchable children):** floodfill participation,
  transit participation, coordinators (relay/peertest), reseed, UPnP, addressbook
  (subscribe + publish), subs.
- **One-shot:** reseed, UPnP (config process with periodic renewal).

### Tier 1 apps must not use SAM

Companion apps are Erlang applications. They reach the core over the **Erlang network**
(`gen_server` calls to registered names, `erpc`), never over the SAM wire protocol on
TCP. SAM exists for non-Erlang clients. This is the rule ADR 0001 intended and that
`i2per_proxy` and `i2per_tun` currently violate (tracked as E1CHFWF).

### Component isolation within the core

`i2per_sup` becomes a config-driven registry of per-domain supervisors:

- `i2p_core_sup` (one_for_one): counters, events, config_srv, peer_rep, reachability
- `i2p_netdb_sup` (rest_for_one): netdb_srv → netdb_writer
- `i2p_identity_sup` (one_for_one): identity
- `i2p_peer_sup` (rest_for_one): peer_rep → peer → lookup_srv
- `i2p_tunnel_sup` (one_for_one): tunnel_srv, server_tunnels
- `i2p_transport_sup` (one_for_one): ntcp2_sup, ssu2_sup
- `i2p_client_sup` (one_for_one): sam_sup, addressbook, subs, addressbook_pub
- `i2p_optional_sup` (one_for_one): coordinators, upnp, reseed (when enabled)

`i2per_sup` stays `one_for_one`. Cross-group dependencies are handled by start order
in `init/1`. Within a group, `rest_for_one` handles dependent restarts. Enable/disable
uses `supervisor:start_child` / `terminate_child` / `delete_child` — the same pattern
already used for coordinators and UPnP. No manager process.

### Transport modularity

Transports are isolated via an `i2p_transport` behaviour + registry, not via separate
apps or a manager. Adding a transport = implement the behaviour + add an atom to config.
Identity, peer, and reachability iterate over registered transports instead of naming
them. This makes transports pluggable without core edits, while keeping them in-process
for data-path performance.

### Location transparency

Tier 1 apps are location-transparent: they use registered names and `gen_server`/`erpc`
calls that work identically on the same node or a remote node. The operator decides
topology.

Tier 2 apps and core components are **not** location-transparent: they depend on
VM-local primitives (persistent_term, ETS, sockets, dirty schedulers). They must be
co-located with the core. They can be separate apps for isolation, but not distributed.

Mnesia was considered and rejected: it cannot replicate `persistent_term`, sockets, or
dirty schedulers, and its transaction overhead is unacceptable on packet paths. The
node-local constraint is physical, not a database choice.

## Consequences

What this buys:

- **Clear app boundary**: Tier 1 apps are portable, location-transparent services.
  Tier 2 apps are isolated but co-located. Core components are supervisor-isolated.
- **No SAM in companion apps**: proxy/tun use Erlang calls, not SAM TCP. Concurrency
  is no longer capped at `max_sam_sessions` per flow.
- **Pluggable transports**: new transports are a module + config entry.
- **Hot enable/disable**: every component can be toggled at runtime via supervisor APIs,
  without a manager process.
- **Crash isolation**: a crash in one domain (NetDb, peer, transport) restarts only
  that domain's supervisor, not the whole core.

What it costs, stated honestly:

- **E1CHFWF is large**: making `i2p_sam_session` socket-agnostic and rewriting proxy/tun
  to use Erlang calls is a significant refactor of the client path. It touches the
  hottest companion-app code.
- **Transport refactor is deep**: identity, peer, reachability all need to iterate over
  a registry instead of naming transports. This is ~5 module edits, but they're
  load-bearing.
- **Tier 2 apps add deployment complexity**: operators must ensure counters and transports
  run on the same node as core. This is documented but not enforced by the code.
- **SAM as a companion app** adds a deployment dependency: external (non-Erlang) clients
  need it running. An operator who only uses Erlang companion apps can skip it.

## Alternatives considered

**Everything as separate apps (original user proposal).** Rejected for Tier 2: node-local
primitives (persistent_term, ETS, sockets) cannot be distributed. The data path
requires in-process access.

**Mnesia for distributed state.** Rejected: cannot replicate persistent_term, sockets, or
dirty schedulers. Transaction overhead unacceptable on packet paths. Operational
complexity (split-brain, schema migration) adds risk without solving the constraint.

**Manager process for component lifecycle.** Rejected: the supervisor tree already
provides `start_child`/`terminate_child`/`delete_child`. A manager is a single point of
failure and adds a process that must itself be supervised. The coordinator/UPnP pattern
proves the supervisor-tree approach works.

**Transports as separate apps.** Rejected: data-path latency (every packet would be a
remote call if distributed) and deep coupling to core internals (identity, peer,
reachability). Isolation is better achieved via behaviour + registry within the core.

**SAM stays in core.** Considered and partially accepted: SAM is the language-agnostic
external interface and may stay in core for deployments that need it. But it passes all
four criteria for a Tier 1 app (optional, long-running, hot start/stop, Erlang-comm).
The decision is left to the operator: run SAM in core (always available) or as a
companion app (isolated, independently deployable). Both are valid.

## Related

- ADR 0001: data-only core with presentation apps (this ADR extends it).
- ADR 0002: logging floor (unchanged).
- ADR 0003: shared gateway handler (unchanged).
- E1CHFWF: companion apps use Erlang, not SAM.
- MHTKCS4: component grouping in `i2per_sup`.
- Z2DRRT5: transport modularity (behaviour + registry).
