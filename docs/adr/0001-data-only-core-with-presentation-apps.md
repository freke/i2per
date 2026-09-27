# 0001. The core is data-only; presentation apps connect over the Erlang network

- Status: accepted
- Date: 2026-09-27
- Decided while resolving the 0.2.0 map's telemetry contract

## Context

i2pd and i2p-java both ship a built-in HTTP monitor. i2per 0.1.0 grew one too,
`i2per_status`, and it did not work: it was excluded from the release artifact,
the release shipped with distribution disabled so nothing could connect to it,
and the page itself was a seven-row unstyled table with no refresh.

Alongside that, the router had no observability at all. No byte counters, no
uptime, no timestamps, and two `logger:` calls across sixty modules. There was
nothing for a status page to display, so improving the page was not the obvious
first move.

That raised a prior question: who should be responsible for presenting a
router's state? The map took the view that the answer shaped everything else, so
it was settled first.

## Decision

Three coupled boundaries.

**The core is data-only.** The `i2per` application never has a GUI or a TUI and
never serves HTTP. It exposes state through Erlang APIs only.

**A presentation app is a separate OTP application** that connects to a core
node over the Erlang network and supplies a GUI, a TUI, or an external API that
other software consumes. `i2per_status` is the first of these. It may run on the
core's own node, where it needs no distribution at all, or on a separate node
that the operator wires up. Either way the operator decides.

**Deployment is a separate repository** and not part of the core. Which
applications the release artifact contains, the shipped cookie and distribution
policy, and the operator provisioning step all belong there. The core's shipped
defaults leave distribution unconfigured rather than forcing it off, and the
release build stops failing on distribution or cookie policy — those checks were
a deployment concern living in the wrong repository.

One consequence worth stating separately: because a presentation app is a
third-party consumer of the core's state, that state is a public contract. It
changes additively within a version, carries a version identifier, and its key
set is pinned by a test.

## Consequences

What this buys:

- The core has no HTTP surface to secure, patch, or keep current. Every
  interface a user might want is a separate application that can be replaced
  without touching the router.
- A core remains useful when every presentation app is broken or absent, which
  is the property that makes the 3am case survivable.
- The status surface can be rewritten — a different language, a real TUI, a
  third-party app someone else writes — without a router change.
- The read API is a stated contract, so consumers can rely on it instead of
  pattern-matching on a snapshot that was never meant to be public.

What it costs, stated honestly:

- **A stock release cannot be observed out of the box.** With distribution left
  unconfigured and the status app not necessarily in the artifact, a router that
  has just been installed has no view of itself. This is a real regression
  against i2pd, where the monitor always works, and it is the strongest argument
  against this decision. It is accepted because the alternative is a permanent
  HTTP surface in the core.
- **Someone has to write the presentation app.** The core's usefulness to a
  human now depends on work outside this repository.
- **A future reader will consider this a mistake.** Both reference routers have
  a built-in monitor, and the omission will look like an oversight rather than a
  decision. This is why the decision is written down at all.

## Alternatives considered

**Keep the HTTP monitor in the core.** Rejected: it makes the router responsible
for a web server's security posture, patching, and interface stability
indefinitely, and it forecloses every other kind of interface.

**Make the status app the only supported interface.** Rejected: it is one
interface, and putting all presentation effort behind a single app recreates the
coupling this decision removes.

**Leave distribution disabled by default and document the opt-in.** Rejected as
the default, because it makes the unobservable case the default case. The
operator still configures it; the core just does not assert a policy.
