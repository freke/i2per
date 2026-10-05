# i2per glossary

Terms this project has fixed, and the ones most easily confused. Definitions
only; design rationale lives in [docs/adr](docs/adr).

## Architecture

**Core** — the router itself: transports, tunnels, the network database, and the
client-facing APIs. It exposes its state through Erlang APIs and does nothing
else. A core has no user interface of any kind.

**Presentation app** — a separate application that connects to a core over the
Erlang network and supplies a human or programmatic interface: a web page, a
terminal UI, or an external API other software consumes. A presentation app
never becomes part of a core. It may run on the core's own node or on a
different one, and the operator decides which.

**Deployment** — turning a core into a running service: which applications ship
in the artifact, what cookie and distribution policy are set, and how the
operator provisions the host. Deployment is not the core's concern.

## Network roles

**Alice** — the router that wants a connection to someone it cannot reach
directly.

**Bob** — the router Alice wants to reach.

**Charlie** — a router that introduces Alice to Bob by relaying a signed
introduction. Both Alice and Bob need a session with the Charlie first, so
being a Charlie is only meaningful to routers you are already connected to.

**Peer test** — two routers exchanging a signed timestamp over an existing
session to establish whether each can receive unsolicited datagrams. The
mechanism behind measured reachability.

**Measured reachability** — reachability established by an actual peer test, as
opposed to *configured* reachability, which is an operator assertion that no
test has yet contradicted.

Reachability is a ladder, not a boolean:

- **unknown** — not yet determined
- **testing** — a test is in flight
- **unreachable** — no path reaches this router
- **introducer-only** — a Charlie completes the hole punch and the session, but
  unsolicited inbound never arrives, so a Charlie is always needed
- **reachable** — unsolicited inbound arrives

It is reported with a separate **reason**, naming where the chain broke:
**own-config** (the operator asserted inbound is impossible, so no test ran) ·
**clock-skew** (the peer's signed timestamp disagrees with ours) ·
**no-charlie-report** (the Charlie never confirmed the test arrived) ·
**punch-not-delivered** (it did confirm, but the unsolicited punch never came) ·
**punch-delivered-no-session** (punch arrived, no session request followed) ·
**session-incomplete** (both happened, the session never established).

The reasons exist because the distinction is what makes a failure diagnosable.
*Punch-not-delivered* is the important one: a stateful firewall usually permits
traffic on a session that is already established while silently dropping
unsolicited inbound, so the test succeeds on the live session and the punch
never lands. That is a firewall rule, not a routing fault, and without the
reason it is indistinguishable from a router that cannot be reached at all.

**Firewalled mode** — the state of publishing an introducer address instead of a
dialable one, so peers reach this router through a Charlie. Entering it is
cheap and reversible; leaving it is not, because a router that wrongly believes
itself reachable never gets introduced at all. So the two directions are not
symmetric.

**Network credibility** — how the live network treats this router: whether peers
can introduce it to others, and whether it can determine their reachability.

**Floodfill** — a router that stores network database entries on behalf of the
network, and is eligible to answer lookups for them.

**Reseed** — the signed bundle of network database entries a router fetches when
it starts empty.

## Transports

**Transport** — a way for two routers to carry a session: SSU2 over UDP, or
NTCP2 over TCP. A router publishes one address per transport it serves.

**Transport availability** — whether this router serves a transport: whether it
binds a listener for it and publishes an address for it. Nothing about whether
peers can reach it that way, which is a different term.

**Transport preference** — which transport this router reaches for first when
dialing. Independent of availability: a router may serve both transports and
still dial one of them first.

The two are separate because what this router offers and what the network
reports back are different facts. A router that publishes an address and sits
behind a stateful firewall is available and unreachable at the same time — the
firewall permits traffic on a session it has already established while dropping
unsolicited inbound. So availability is a statement about this router's own
configuration, and whether peers can reach it is **reachability**, which is
measured rather than declared. See **measured reachability**.

Neither term is a judgement about which transport is better. The network runs
both because one is UDP and one is TCP, so neither covers every network. A
preference is therefore a statement about this router's own network — which is
why it belongs to the operator, and why it is fixed when the router starts.

## Tunnels

**Tunnel** — a chain of hops that carries messages on behalf of a client.

**Transit tunnel** — a tunnel that passes through this router on its way
somewhere else, carrying traffic for other routers. Relaying transit is a
service this router provides to the network.

**Inbound tunnel** — a tunnel whose endpoint is this router, used to receive.

**Outbound tunnel** — a tunnel this router originates, used to send.

**Exploratory tunnel** — a short-lived tunnel used to reach a network database
server for a lookup, rather than for carrying a client's traffic.

**Gateway roles** — where a hop sits in a tunnel. An *inbound gateway* accepts
tunnel data and forwards it inward; an *outbound gateway* injects it onward; an
*outbound endpoint* is the final hop of someone else's tunnel.

## Data

**LeaseSet** — a client's published statement of which tunnels can reach it.
*LeaseSet2* is the current format; earlier peers may publish the older form.

**Destination** — a client's identity: a public key plus a signature key, and the
hash that names it.

**TCSR** — tunnel creation success rate: the share of tunnel build attempts that
succeeded. Cumulative here, counted since the router started.

**Status view** — a single snapshot of a core's state, fetched in one call by a
presentation app. A public contract: consumers other than the core depend on it,
so its shape changes only additively within a version.

## Observability

**The bus** — the router-wide channel on which state changes are announced so
something outside the core can follow them in real time. The core announces; it
never interprets and never renders.

**Announce** — to put one state change on the bus. Cheap, best-effort, and never
allowed to fail the work that reported the change.

**Subscriber** — something that receives announced events. May be in the core or
in a separate presentation app on another node.

**Notified** — that an event was put on the bus. Counted. Says what the router
*did*, not what anyone received.

**Delivered** — that an event reached a subscriber. **Not counted anywhere**, and
knowing why is load-bearing: delivery happens inside the process that fans events
out, so a count of it would have to be maintained by the thing most likely to
fail. Notified and delivered are therefore different figures and are not
interchangeable — a rising notified count says nothing about receipt.

The log is the **witness** where the bus is the instrument: a fact on the bus is
not also written to the log except at a level that is off by default. That is the
distinction, and it is a discipline rather than a preference — see ADR 0002.
