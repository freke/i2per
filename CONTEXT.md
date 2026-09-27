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

**Network credibility** — how the live network treats this router: whether peers
can introduce it to others, and whether it can determine their reachability.

**Floodfill** — a router that stores network database entries on behalf of the
network, and is eligible to answer lookups for them.

**Reseed** — the signed bundle of network database entries a router fetches when
it starts empty.

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
