# 0003. The gateway handler is shared; the process that plays it owns the work

- Status: accepted
- Date: 2026-10-03
- Decided while resolving the 0.2.0 map's client-send boundary

## Context

`i2p_tunnel_srv` is one `gen_server`, a `permanent` child of the top supervisor,
and twelve workload kinds share its mailbox: transit relay frames, inbound-gateway
injections, garlic and STB from peers, outbound and inbound tunnel builds, LeaseSet
publication, pool top-up, the expiry sweep, build timeouts, session-demand
monitors, and the client send.

The client send arrived through `send_via_outbound/3`, a `gen_server:call` whose
handler did the caller's framing and every hop's inverse-layer crypto inline — in
the same process that was relaying transit for other routers.

Two things were wrong with that, and they are different things. A client send's
latency depended on how much transit the router happened to be carrying, and two
clients serialised behind each other. And more fundamentally: `i2p_tunnel_srv` was
performing per-connection work inside a shared singleton, which is the opposite of
what the rest of the router already does for its connections.

The rest of the router had the right shape. One process per NTCP2 connection, one
per SSU2 session, one per SAM session, each a `temporary` child of a per-transport
`one_for_one` dynamic supervisor, with `i2p_tcp_acceptor` starting the child and
then handing the socket over with `gen_tcp:controlling_process/2`. The tunnel work
was the exception, and nothing recorded that it was one.

## Decision

**The gateway handler is shared; the process that plays it owns the work.**

Inbound and outbound gateway work runs the same code — `i2p_tunnel:gateway_all/4`
and `obgw_prep/2`, which is where the role logic already lives, as
`i2p_tunnel_srv`'s own module doc states. The handler is never forked per
direction. But **per-connection work does not run in a shared singleton**: a
long-lasting connection gets its own worker, with the socket handed to it, and that
worker plays the role for its own traffic. The client send's framing and
inverse-layer crypto moves out of `i2p_tunnel_srv` into the calling connection's
worker.

A process that produces independent workers needs a **dynamic supervisor**, so that
how a worker is created is one decision in one place rather than at each call site.

**`send_via_outbound/3` returns `ok | error`, and the caller decides what to do
about it.** The error is returned — not turned into an event, and not deleted.

**Work with no connection behind it stays with the process that owns the state.**
Lookup requests and replies, through `i2p_lookup_srv` and
`i2p_peer:reply_via_outbound/3`, are not connections, so they stay in the tunnel
manager. `i2p_peer` is the process every send path in the router goes through,
which makes it the worst possible host. Revisit that only on counter evidence, and
then with a pool of workers rather than a guess.

## Consequences

What this buys:

- A client send costs the tunnel manager nothing, so it cannot be delayed by
  transit for other routers or by another client's send.
- The arrangement matches what the router already does for its connections, so
  there is one rule rather than two.
- Because the handler is shared, nothing is duplicated. The inbound gateway case
  keeps running in the manager, because a remote peer initiates it and there is no
  local caller to hand work to.
- The manager keeps what it is actually for: owning the pool and the build state.

What it costs, stated honestly:

- **The outbound gateway role is now played by six call sites' processes** while
  the inbound case stays in the manager, so the one role has two homes.
  `i2p_tunnel` holding the logic is what keeps them consistent.
- **This is safe only because a feature is unimplemented.**
  `docs/protocol.md:1001` records that data-phase extraction for foreign outbound
  tunnels is not implemented, which is the only reason every outbound injection has
  a local caller. Whoever implements it inherits a role spread across six
  processes, and will have to move it back or add a seventh. That sentence, and the
  `send_via_outbound/3` reference at `:1014-1020`, are load-bearing.
- **The tunnel path is still one process.** Only the client send moved. The
  per-connection workers still hand their transit and gateway work to
  `i2p_tunnel_srv`. That remains `QPJWWS4`'s question and is deliberately left in
  Backlog, because pool-state ownership and the status-snapshot contract are still
  open, and sharding the pool changes how the snapshot is assembled.
- Two tests encode the old arrangement and change with it:
  `i2p_tunnel_srv_SUITE.erl:1702` asserts the manager did the crypto, and
  `i2p_peer_tests.erl:1281` stubs the `gen_call` request shape.

## Alternatives considered

**`gen_server:cast`, with the result turned into an event.** Rejected: a cast has no
return value, so it cannot honour the rule that the error is returned to the caller.
It also satisfies the original acceptance criterion — that a client send does not
wait on unrelated tunnel work — literally and completely, while leaving the work in
the same mailbox. Two clients still serialise inside the manager, and a client's
latency still scales with transit volume. It stops the caller waiting without moving
the bottleneck.

**Validate synchronously, then cast the work.** Rejected: its `error` is read before
the work, so it is *staler* than today's. The tunnel can be retired between the
check and the work, so it reports a failure that may not have happened and stays
silent about one that did. Today's `error` is read by `find_outbound/2` at the
moment of injection.

**Delete the `ok | error` return and keep only the counters.** Rejected: no caller
appeared to read it — two turned `error` into a counter and returned `ok`, one
discarded it — but the counter is for the operator and the return is for the
programmer. Different audiences, both kept. The counter is also the wrong
instrument for a per-send decision: `i2p_stats.erl` argues that a route whose
tunnel has gone fails every subsequent send until the route is re-resolved, so
these are per-message rates on live paths rather than incidents.

**Move the crypto into `i2p_lookup_srv` and `i2p_peer` as well.** Rejected: neither
is a connection, so the rule does not reach them, and `i2p_peer` has already had its
blast radius bounded once. Adding per-injection crypto to the process every send
path in the router goes through would re-couple exactly what that ticket unblocked.

**A pool of workers for the manager's injection path.** Not rejected — deferred. It
is the right answer *if* the counters show the manager is a bottleneck, and deciding
it now would be a guess in place of a measurement. That is the whole point of
building the counters first.
