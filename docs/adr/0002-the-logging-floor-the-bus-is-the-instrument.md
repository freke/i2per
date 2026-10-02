# 0002. The logging floor: the bus is the instrument, the log is the witness

- Status: accepted
- Date: 2026-09-29
- Decided while resolving the 0.2.0 map's logging floor ([SEW8DCM])

## Context

The map's second 0.2.0 claim asks for a logging floor: all eight standard levels
with a written discipline, `notice` as the default, a hot `log_level` key, a
configurable formatter, and a 3am checklist of what must be recorded for a fault
to be diagnosable without reading the source.

The tree had almost none of that. Eight `logger:` calls across seventy modules —
seven `warning` and one `debug`, none of the other six levels. No logger
configuration in `config/`. No `log_level` key in either the ini whitelist or the
runtime key set. And `i2per_sup` logged nothing at all, so a boot was completely
silent.

What changed the shape of the question is the four tickets that preceded it. Those
built the event bus out to seventeen shapes, and the checklist the map asks for is
now *mostly already carried by events*: a peer that will not connect, a lookup that
got no answer, a lookup that got an answer it could not read, a transit tunnel
refused, a LeaseSet that did not reach the network, and the reachability verdict
are all announced, with reasons. The logging floor is therefore not the primary
instrument for those facts. It is the record that exists when nobody is watching.

That framing matters because the obvious move — log every event too — is wrong, and
wrong in a way that costs more the bigger the router gets.

## Decision

**Each fact is recorded once, on one instrument.** A fact that is on the event bus
is not also written to the log, except at a level that is off by default. A fact
that has no possible subscriber is written to the log. The two sets barely overlap,
and the checklist below is where the overlap is stated explicitly rather than
guessed at.

**A small `i2p_log` module in the core owns the floor**, not scattered `logger:`
calls. The map asks for a written discipline, and a discipline held across seventy
modules is prose that drifts. The module owns three things and nothing else: the
level to apply, the discipline, and the checklist as data.

The module is thin — a level setter and a declared list — and it is worth having
for exactly one reason: without it the checklist has no addressable home. In the
ADR it would be prose, and in a test module it would be invisible to the code that
has to satisfy it. Declared in `i2p_log`, both the code and the test read the same
list, and there is exactly one place in the tree that can apply a level. A wrapper
that only forwarded to `logger` would not be worth its indirection; this one is
narrowly more than that.

**The checklist is data and it is enforced.** `i2p_log` declares the required
facts and the level each is recorded at. A test asserts every declared fact is
emitted somewhere in the tree, the same way `i2p_events_vocabulary_tests` asserts
that every announced tag is in the event type. This is what makes "diagnosable" a
property the build checks rather than a claim a release makes.

**All eight levels, `notice` by default, and `log_level` is a hot key.** It goes in
`i2p_config_srv`'s runtime set — the level is exactly the thing you want at 3am
without a restart — *and* in the ini whitelist, because that loader is fail-closed
and would refuse to boot on a key it does not recognise.

**Stdout, and no shipped file handler.** A foreground release is already rotated by
whatever supervises it, and where the log goes, how large it may get and who prunes
it are deployment decisions in the deployment repository. `config/sys.config` ships
the default and documents the file handler as a commented alternative.

**`i2p_ssu2_trace` folds into `debug`.** It is a second observability mechanism
with its own registered-name lifecycle, its own enable and disable, and no level at
all. Keeping it means a second thing whose verbosity nobody can govern. Folding it
makes the per-packet SSU2 detail obey `log_level` and removes a bespoke mechanism.

## The 3am checklist

Each row is a symptom an operator would actually report, the facts that must be
available, and where they live.

| Symptom | Facts required | Carried by |
|---|---|---|
| "It won't connect to any peers" | peer hash, why the connect failed, the backoff interval now in force | `peer_connect_failed` |
| "Traffic to one peer has stopped" | the peer, and that it stopped accepting our writes rather than simply closing | `peer_send_stalled` |
| "My client can't reach anything" | the key, and whether **anyone** answered at all | `lookup_failed` |
| "Nobody can reach me" | the current verdict, and how often it has changed | `reachability` |
| "I'm not carrying anyone's tunnels" | the receive tunnel ID and which of the three causes | `transit_denied` |
| "My LeaseSet isn't published" | the destination and which of the three reasons | `leaseset_publish_failed` |
| "A peer's store is being refused" | the reason the NetDb gave, and the kind of record | `db_store_not_stored` |
| **"The config isn't what I set"** | the configuration **in force** — not the file — at boot and on every hot change | **nothing. A gap.** |
| **"It started and I don't know with what"** | version, listen host and port, data directory, whether live participation is on, seed count, distribution posture | **nothing. A gap.** |
| **"The status page shows nothing"** | that the event bus came up and that the read API is answering, before anyone has attached to either | **nothing. A gap.** |

The three gaps are the ticket's real output, and they share a cause: **all three
happen before a subscriber could exist, or outside anything that reports.** No
amount of instrumentation at those points helps, because at those points there is
nothing to instrument *with*. They are the logging floor's actual job for 0.2.0,
and they are three lines at `notice` rather than a framework.

The first row is also where the existing levels are wrong today:
`i2p_peer.erl` logs `netdb store not stored: ~0p` at **`debug`**, so under the
map's own default the fact is invisible — while the same condition emits
`db_store_not_stored` on the bus. A router with no subscriber attached currently
cannot report that a peer sent it something it could not use.

**One row added after acceptance.** `peer_send_stalled` joined the table when the
NTCP2 send path stopped waiting on a connection ([G4TF5RT]) and a peer that had
stopped taking writes became a nameable outcome rather than an indefinite hang.
It is a new row and not a change to the decision: the bus was already the right
instrument for a peer-path fault with a reason attached, and the alternative the
table rules out — logging the same fact a subscriber would also read — is the one
thing this ADR exists to prevent. What the row buys is the difference between
"that peer disconnected" and "that peer stopped accepting our writes", which are
different faults with different fixes and were the same event.

## Consequences

What this buys:

- The checklist is a build artifact. A fact that is declared and then never emitted
  fails `just check`, which is the only thing that makes a checklist more than a
  wish.
- An operator who installs the release and attaches nothing still gets a record of
  what the router decided it was doing, and can change the verbosity without a
  restart.
- The `notice` default is defensible rather than arbitrary: it is the level at
  which the three gaps above are recorded and at which a fault worth waking for
  appears.
- One fewer bespoke observability mechanism.

What it costs, stated honestly:

- **A fault that only manifests while a subscriber is attached is in the bus and
  nowhere else.** That is deliberate, and it is the decision most likely to be
  re-litigated by someone who cannot find a lookup failure in a log file. The
  counter-argument has to be made somewhere, and this is it: the alternative is
  every event in the log, and `lookup_failed` on a router that cannot reach the
  network is one line per lookup.
- **A second observability mechanism dies.** Anyone relying on
  `i2p_ssu2_trace_sink` outside the test tree loses it. Nothing in production does,
  and the test helper is the only registrant.
- **The floor is a floor, not a ceiling.** A deployment that wants a file handler
  configures one; the core neither ships nor forbids it.

## Alternatives considered

**Direct `logger:` calls plus a shipped handler config.** Rejected: it answers the
*configuration* half of the question well and the *discipline* half not at all. The
map asks for eight levels with a written discipline, and a discipline expressed as
prose next to seventy call sites is one nobody applies twice. It is also what
produced the current state — a `debug` line carrying a fact the checklist needs.

**Log every event as well as announcing it.** Rejected: it is the duplication this
project exists to refuse, applied to the highest-volume stream in the router, and
it makes the log unreadable exactly when it is needed. See "each fact is recorded
once, on one instrument".

**A file handler with rotation shipped in the release.** Rejected as a deployment
decision in the wrong repository, per ADR 0001. The default is stdout; a foreground
release is rotated by its supervisor, and a size cap chosen here would be a guess
about hardware the core has never seen.

**Keep `i2p_ssu2_trace` as a separate mechanism with its own enable flag.** Rejected:
two mechanisms means two verbosity controls, and the one that cannot be governed
from a config key is the one that floods.
