# Changelog

All notable changes to i2per are recorded here. Versions follow the OTP
applications' own `{vsn, ...}`; the release tag is `v` + that version, and
CI refuses a tag that disagrees.

## [0.5.0] — 2026-10-19

**The performance release.** 0.4.0 hardened the dial and hot path; 0.5.0 adds
throughput management: SSU2 estimates RTT and runs window-based congestion
control instead of a fixed resend timer. No wire-format or configuration-key
changes, so a 0.4.0 `data_dir` is read unchanged.

### Changed

- **SSU2 congestion control and RTT.** SSU2 now estimates RTT and runs
  window-based congestion control, so a router manages its own throughput
  instead of relying on a fixed resend timer (#RC68AGE).
- **Hermetic protocol gate.** The SSU2 data phase is captured from a real i2pd
  and committed, then replayed on every push (#3TC871W).
- **Observability.** `i2p_status_data:view/0` now reports aggregate SSU2 RTT
  and congestion window (view version 5), and the status page surfaces them
  (#3HWTDQV).
- **Scope.** 0.5.0 anchors on RC68AGE alone; NetDb-driven Charlie selection
  is deferred to 0.6.0 unless it lands small (#01T1WWE). The i2pd interop
  suite stays a local diagnostic, not a required CI gate (#HD80K76).

### Fixed

- **Send queue fairness.** A full SSU2 send queue now drops its oldest queued
  packet (rather than the newest) and announces/logs the drop instead of
  discarding silently (#7NRF872).
- **Status page coverage.** The four SSU2 rows are tested and the `n/a`
  metric list updated with them (#DQ40YW8).
- **Documentation truth.** `config/sys.config` no longer claims the hot
  transport flip is an unbuilt ticket, and `docs/parity.md` marks the
  streaming protocol done (#EAZB4CS).
- **Cleanup.** Dead `rtt`/`rtt_ms`/`srtt`/`cwnd` accessors, an unused
  listener registration path, and two orphaned test helpers are removed
  (#WDJ7NV1).
- **Test reliability.** The NTCP2 70k-frame flood hang guard is widened
  (#SM1MJN0).

## [Unreleased]

_(nothing yet)_

## [0.4.0] — 2026-10-18

**The hardening release.** 0.3.0 added protocol surface; 0.4.0 pays for it:
every dial is bounded, the SSU2 hot path is cheaper, and the dead weight is
gone. No wire-format or configuration-key changes, so a 0.3.0 `data_dir` is
read unchanged.

### Changed

- **Dial convergence and routing.** The three dial parks (transit, peer-test,
  tunnel-build) are each bounded by a single derived number rather than a
  configuration knob (#SV6S264). The dial transport preference can now be
  flipped at runtime without disturbing in-flight dials or established
  connections; only the boot-time availability half stays boot-only (#0JJ375C).
  The two coordinators' supervision shape and enable key are settled (#33KNKEC).
  `connect_via_introducer/5` gained coverage, and the three defects it found
  (requester leg wiring, Charlie's granted token, RouterInfo retention on the
  redirect) are fixed (#98GAVQK). The re-flood is gated on a nonzero
  DatabaseStore reply token in `i2p_peer` as well as in both references and
  `docs/protocol.md` (#EPQVQA7). Bob now rejects a SessionRequest whose token
  it has not granted, answering with a Retry that grants a fresh one, so a
  granted relay token actually authorises the dial (#BFKFGY0). A token'd
  DatabaseStore is answered with a DeliveryStatus carrying the reply token
  instead of the store's own message id (#9TN7XF2).
- **Hot path cost.** Dirty-scheduler crypto flags are shipped (#VXRH456).
  Per-datagram syscall and log allocation in the SSU2 hot path is removed
  (#XZTYAVX). An SSU2 session no longer retains a RouterInfo it is not using
  (#ER0J6KM). Undecryptable garlic stops scanning destinations at the first
  open instead of paying a full ECIES open per candidate (#YN2RZNN). The
  floodfill lookup walks a floodfill-only index instead of scanning and
  sorting the whole store (#13EY2MQ).
- **Simplification.** The unused Noise XX ratchet and ElG2 surface is removed
  (#SHX43XC). `i2p_sam_proxy` no longer ships as a documented feature
  (#EK2KTKP). `i2p_streaming`'s field accessors are read through and written
  around, closing parity's "streaming protocol: partial" row (#C252TF7).
- **Test gate.** The eunit layer's shared-state cases are isolated, so
  `counters_are_unique_test` and `add_is_a_no_op_while_the_owner_is_absent_test`
  can no longer be order-dependent (#PJZZFKR).
- **Doc truth.** `docs/parity.md` no longer bills the Charlie hole punch as
  1.0.0 material; 0.3.0 shipped it (#SMD2V01).

### Fixed

- RouterRequestStatus (I2NP type 20) is confirmed absent from i2pd, Java I2P
  and the I2NP spec; the slot it vacated is taken by #EPQVQA7 (#GF37P50,
  no code change).

## [0.3.0] — 2026-10-13

**The Charlie role is implemented.** `i2p_relay_coord` now answers a RelayIntro
on the tagged session as Charlie: it verifies Alice's RelayRequest signature
with the router signing key her own forwarded RouterInfo publishes, checks her
asserted endpoint for being punchable, and on accept signs a RelayResponse with
its own key and answers twice — in-session to the introducer, and again inside
the out-of-session HolePunch (type 11) sent straight to her asserted endpoint.
A refusal is answered in-session only, with no punch, and carries Charlie's own
reject code (70 Alice unknown, 67 signature failure, 65 endpoint not punchable,
66 the punch budget is spent).

Two bounds the reference implementations do not have: the punch is rate-limited
by a per-session token bucket (a burst of 4, then one per second), and the
endpoint predicate refuses loopback, private, link-local literals and privileged
ports. Neither i2pd nor i2p-java rate-limits a punch this way.

Supporting changes: `m:i2p_addr_policy` is the one predicate for "is this
address on the public internet", shared by the boot validation (which had its
own copy) and the punch gate. `m:i2p_peer` forwards a RouterInfo to both
coordinators, which is the one shape that is not exclusively owned — the
peer-test coordinator needs it for a message 1 and the relay coordinator for a
RelayIntro.

### Fixed

**A review of the Charlie role found several interop and cleanup defects before
the release.** Charlie's RelayResponse is now signed over the introducer's hash
rather than this router's own hash, which is the hash Alice signed against.
The out-of-session HolePunch now carries a usable endpoint: IPv4 addresses stay
4 bytes, IPv6 addresses stay 16 bytes, and the punch path stops converting
through a string form that could never be parsed. The address policy also
rejects IPv4-mapped and IPv4-compatible IPv6 literals instead of treating the
surrounding zeros as a public address.

A session that dies by monitor `DOWN` now runs the same coordinator cleanup and
relay-tag removal as a session that closes with an explicit SSU2 termination,
so dead introducers no longer accumulate in the coordinator's session table.
The identity rebuild and SSU2 introducer swap recompute the measured capability
caps instead of carrying the previous verdict into a new RouterInfo. An
`unknown` peer-test result no longer resets a promotion streak, and repeated
promotion or demotion transitions no longer re-fire the same coarse change.

The SSU2 listener no longer crashes when a peer-asserted endpoint cannot be
sent to. The bus registry row is written before the forwarder is attached, and
the forwarder demonitors its collector on termination. The release profile now
builds the `0.3.0` relx release.

### Added

**Every bus-carried fact now has a record that outlives the bus.** ADR 0002 has
said since acceptance that a fact on the event bus may also be written to the log
"except at a level that is off by default", and the tree delivered that clause
nowhere: seven facts were announced and not recorded anywhere else. Each of the
seven now writes a `debug` line beside its `notify/1` site — ten sites, because
`lookup_failed` and `leaseset_publish_failed` are each announced from more than
one place — carrying the key, the reason and whatever else the announcement did.

This is what makes the bus's bound survivable. A bound that kills the manager
destroys the bus's copy of every fact it was carrying, and with no second copy a
fact is lost at exactly the moment somebody goes looking for the reason. The
level is the control rather than a gate: `debug` is off under the shipped
`notice` default, so `lookup_failed` on a router that cannot reach the network
is still not a line per lookup.

`i2p_log_checklist_tests` pins both directions, and neither was checkable before:
every `bus` row has such a record, and no `log` row has one — a shadow under a
fact already recorded at a level an operator sees is the duplication ADR 0002
exists to prevent, and nothing switches it off for whoever is reading `debug`
afterwards.

ADR 0002 also now states its one real overlap explicitly, which it had left to be
guessed at: `unhandled_ssu2_block_peer` is on both instruments above `debug`,
because `i2per_status` is never started by the router and the log is therefore the
only instrument that exists for a subscriber-less node. That is the opposite
arrangement from the seven bus rows — log-first rather than bus-first — which is
why the check pins the asymmetry rather than a general rule. Whether it should
collapse to bus-only stays open on #HPH59JN.

### Added

**The far side of the bus is now readable.** A subscriber on another node that
falls behind grows without limit, and nothing on this router could see it: there
was no cap to set and, as it turned out, no reading either.
`m:i2p_events:sample_far_backlog/0` reads every remote subscriber's queue depth
and answers with the deepest. It is a read, not a published figure — the core
does not hand data to a stats process it does not control — so with nobody asking,
it costs the router nothing.

The far side cannot be bounded, and that is now measured rather than assumed
(#RWTMGJ9, OTP 28.5): `process_info/2` against a remote pid raises `badarg` for
every item, the distribution exposes no queue depth through `system_info`,
`statistics`, `port_info` or `memory`, and `{async_dist, false}` does not supply
one — under a 300,000-event flood against a collector that never drains, the far
mailbox took **all 300,000** while a non-`async_dist` relay never parked. The
runtime applies no back-pressure to a process that is not consuming. Bounding it
would mean credit/ack flow control, which changes the delivery contract for every
subscriber; reported is what shipped.

The registry the reading walks is the bus's own state, written where the handler
is added and removed, so it cannot drift from what the bus is carrying. It is
pruned when a collector is found gone, which is the only thing that keeps it from
growing across status-service restarts — `m:i2per_status_state` never unsubscribes.

### Fixed

**Six `gen_event` callbacks in `m:i2p_events` were exported, documented and never
executed.** The manager was started with the bare `{local, ?MODULE}` form, which
`gen_event:start_link/2` does not read as a `{Module, Args}` pair, so `gen_event`
substituted its own module and the manager ran its callbacks. Measured: such a
manager reports `current_function = {gen_event, fetch_msg, 6}`, and an `init/1`
that prints is never entered. There is no form on this OTP that both registers the
name and names a callback module — `{Mod, Args}`, `{local, Name, Mod}`,
`{global, Name, Mod}` and `{via, Mod, Name, Args}` each exit `badarg` — so the
registry lives with the sampler instead, which is a process the module does start.

`manager_callbacks_test` had asserted all six by direct call, under a comment
giving the wrong reason for their being unreachable. A case that calls a function
directly passes whether or not anything calls it, which is how dead callbacks read
as covered. **All six are now deleted, and so is the case** — together with the
`-behaviour(gen_event)` declaration, which asserted the same arrangement and which
dialyzer read as one. `m:i2p_events` is a publisher and a registry owner, not a
manager, and the module says so with the measurement rather than with six functions
that cannot run.

Two further measurements settled it rather than the taste of it. `gen_event`'s own
`init_it/6` still takes the manager's module and arguments and discards both
(`init_it(Starter, Parent, Name0, _Mod, _Args, Options)`), so the manager-module
concept is vestigial upstream rather than merely unexposed from `start_link/2`. And
`gen_event:call/3,4` dispatch to a named **handler**, never to the manager module, so
`handle_call/2`'s `{error, unsupported}` was a reply to a question no caller could
ask.

**The backlog sampler survived a bus restart and was started a second time.**
`start_link/0` runs in the supervisor, so its `spawn_link` linked the sampler to
the supervisor — not to the bus — and every restart both kept the old sampler
alive and started another. Two loops wrote the same gauge every 5s, one of them
publishing a depth for a manager pid that no longer existed, which `depth/0`
answers as `0`: a restarted bus reported "no backlog" from a process watching
nothing. The sampler now monitors the manager and exits with it, and a restart
stops any predecessor synchronously before creating the registry.

**`ets:new(Name, Opts)` without `named_table` produces a table that is unreachable
by name.** Measured on OTP 28.5: `ets:info(Name, size)` answers `undefined` and
`named_table` is `false`, while `ets:info(Tid, name)` cheerfully reports the atom.
The table works, holds rows, and cannot be reached by the name every other
function uses — a silent failure that reads as an empty registry.

### Fixed

**A dead subscriber's forwarder stays on the bus forever.** `i2p_events_forward`
sent each event to the collector and returned `{ok, State}` — and a send to a
dead pid is not an error, so a collector that died raised nothing. `gen_event`
removes a handler for a delete, a stop or a crash, and none of the three fired:
every subscriber restart left one more forwarder attached, and every event was
dispatched to all of them. Measured: five attach-and-die cycles left six
handlers, and one dead forwarder cost 8,951 µs across 20,000 announcements,
linear in the dead count.

The forwarder now takes itself off. It monitors its collector from `init/1` —
inside the manager, so the `'DOWN'` is owned there — and returns
`remove_handler`, which is `gen_event`'s own silent self-removal. The `'DOWN'`
reaches it because \`gen_event:fetch_msg/6\` receives with a catch-all and
\`gen_event:handle_msg/3\` hands every unrecognised message to every handler's
`handle_info/2`, so a monitor a handler made is a message the handler is
handed. That was worth measuring rather than assuming: the natural reading is
that a stray message accumulates in the manager's mailbox, and it does not.

**Every way a collector can go is covered**, on OTP 28.5 / ERTS 16.4.0.6: the
process killed locally, the process killed on another node, and the far node
stopped outright — which is the deployment that leaks in production, since
`i2per_status_state` runs on its own node and never unsubscribes. In every case
the handler is gone and the bus still answers.

**It is done inside the manager, and that is the point.** The obvious
alternatives — a watcher process per subscription, or the subsampler reaping —
both remove the handler with `gen_event:delete_handler/3`, which is an rpc with
no timeout and so stops working precisely when the bus is wedged, which is when
a pile-up matters. A handler removing itself needs no rpc and cannot be blocked
by one.

**The subscriber registry now drops the dead pid too**, which it did not: the
row outlived the handler, and `i2per_status_state` restarting on its own node
grew it once per restart. The subsampler — the process that already owns that
table, and already exists to hold bus state no `gen_event` call can reach — takes
a monitor per registered row and drops it when the pid goes. A monitor rather
than an liveness probe, because the alternative for a *remote* pid is the `erpc`
round trip the far-side sweep already makes, once per subscriber per tick,
forever. Two processes, one fact: the manager answers "should the bus keep
calling this pid", the subsampler answers "is it still listed".

**A failed NTCP2 handshake reported `{error, normal}` instead of why it failed.**
The connection process announces `{connect_failed, PeerHash, {handshake, Reason}}`
to its owner and then exits `normal` — normally, because an unreachable peer is a
dial outcome and a crash report per candidate would bury bounded discovery's log.
But `f:i2p_ntcp2_conn:connect/3` reports its result from the monitor's `DOWN`,
and an `exit(normal)` carries `normal`: the exit reason of a process that ended
cleanly, which says nothing about a handshake. The reason was being delivered and
then thrown away — it sat unread in the caller's own mailbox.

`f:await_connection/2` now reads that announcement before the `DOWN` it precedes
(the same process sends it and then exits, and signals from one process to
another are ordered), so `f:connect/3` returns the handshake's own reason:
`{error, {handshake, {connect_failed, econnrefused}}}` for a dead port rather
than `{error, normal}`. A caller that passed a different `owner` is not the
announcement's recipient and still learns only that the connection ended — that
is the documented remainder of the contract, and the pid that was told why is
the pid that asked for the dial.

## [0.2.1] — 2026-10-07

**A patch release, because the defect was a silent one.**

0.2.0 shipped and was correct in behaviour except for one thing an operator
could not see: a reseed could quietly put fewer RouterInfos into the NetDb
than the bundle it had just fetched and verified, and nothing said so. There
are no other changes on this tag.

### Fixed

- **A reseed could silently take fewer RouterInfos out of a bundle than the
  bundle held.** The entry-name filter asked `filename:extension/1`, which
  reads `/` as a directory separator, so an entry whose name put one before
  the `.dat` suffix reported no extension and the RouterInfo behind it was
  dropped — with nothing logged, leaving a NetDb a router short and a
  reseed that reported success. A RouterInfo was lost about once in 128
  reseeds and was the cause of a red release gate about one run in seventeen
  (#Q6NKB9P). The suffix is now matched off the end of the name, and an
  entry the reseed client still cannot take is recorded as the new
  `reseed_routerinfo_skipped` log fact instead of vanishing.

### Upgrading

The wire formats, the configuration keys, the read API's key set and the
artifact's layout are all unchanged from 0.2.0, so an upgrade is the new
tarball and nothing else. A `data_dir` written by 0.2.0 is read by 0.2.1
unchanged. See the README's [upgrade
note](https://github.com/freke/i2per/blob/main/README.md#known-issues-and-limitations):
path migration is still not supported, so upgrading means installing a new
tarball.

## [0.2.0] — 2026-10-07

Promotes [`v0.2.0-rc1`](https://github.com/freke/i2per/releases/tag/v0.2.0-rc1)
unchanged in behaviour: the tag carries the same tree plus this version bump and
the 0.2.0 documentation pass. The change list below is the release's; the
release candidate is the same release before the version was final.

## [0.2.0-rc1] — 2026-10-07

**Operable: a release an operator who did not write it can run, and see.**

### Added

- **Versioned public read API over the event bus.** `i2p_counters` holds the
  counters and node uptime; the read API serves them under
  `i2p_status_data:view/0`, including a `bus_backlog` gauge sampled with
  `process_info/2` so a wedged bus is observable from outside the bus.
- **The telemetry contract.** Tunnel build/fail tallies, per-transport
  byte counts (NTCP2 and SSU2), transit relay bytes, and three new events —
  `peer_connect_failed`, `transit_denied`, `leaseset_publish_failed` —
  plus `lookup_failed` carrying the reason an answer did not arrive.
- **A logging floor.** `i2p_log` owns the router's level and hot key; a
  shipped `logger` default in `config/sys.config`; the three boot gaps
  closed; the 3am checklist is a build-time gate (#9ZZRQQN), so a missing
  required fact fails the build rather than the night shift.
- **The status page derives, not stores.** Rates and the tunnel success
  ratio come from differencing counters at read time.
- **CI produces the release.** Tagging `v*` builds the relx tarball and its
  provenance MANIFEST and attaches them to the GitHub release; the
  documentation site is published to GitHub Pages from the same tag, with
  `source_ref` and version taken from the tag being built.

### Fixed

- An SSU2 session's replay window grew without bound (#7GP4A4K).
- One wedged NTCP2 connection could block the peer manager forever (#G4TF5RT).
- The NTCP2 listener, and separately the SAM listener, accepted one
  inbound connection per second (#ZYQ227K, #EP6SRK1).
- The SSU2 listener did per-connection work in the shared socket owner (#YNBT5ZD).
- An NTCP2 session died at frame 65536: the data-phase message counter is
  now 64 bits (#R8WNYK3).
- `i2p_garlic` crashed the tunnel manager on a store type 5 or 7
  `DatabaseStore` (#XNBSG6A); a floodfill re-broadcast a LeaseSet it
  could not parse (#JDQ8E3Q).
- The tunnel path blocked on a NetDb call for every 1028-byte frame (#W46KMT8);
  client sends blocked on the tunnel manager's call (#G9HZK8F); NetDb ran
  signature verification and disk IO inline (#PPW41Y4).
- Admission for the three client-facing connection kinds took a node-wide
  distributed lock (#41D5PFF); streaming had no cap at all (#GS6VKZ8).
- The event bus could be parked by one slow subscriber node — the manager
  now spawns with `{async_dist, true}` — and `notify/1` could crash its
  emitter on a killed manager (#ZYNNQKQ). The backlog is reported, not
  silently grown; the `max_heap_size` bound was removed after measurement
  showed it could not fire for the case it was adopted for (#VH7Z0KJ).
- A stuck dial stranded its peer in `connecting` for the process's life
  (#8V1Z06A); the dial path discarded the SSU2 failure reason, so a park
  was invisible (#1Q4JREN); the read API flattened `connecting` into
  `other` (#X7BP9G1).
- An unhandled SSU2 block was announced once per peer and counted every
  time; the counter now carries the total (#HPH59JN's flood criterion).
- ~30 smaller fixes recorded on the board, from a PropEr generator that set
  its own cost by lottery (#RJPXXGX) to a compat CI job that had never run
  (#60S5R8T).

### Changed

- `just check` runs dialyzer; the docs step fails on warnings rather than
  printing them.
- `i2p_events:subscribe/1` / `unsubscribe/1` are the published entry point;
  nothing outside the core calls `gen_event:*` directly.
- The dial transport preference is three values — no UDP / enable UDP /
  prefer UDP (#75YRPJ7).
- The RouterInfo expiry horizon slides with store size (#RA5PVR1); the
  closest-peer lookup no longer rehashes per comparison (#8YGZFB8); the
  floodfill lookup no longer hashes per candidate, via a day-tagged routing-key
  memo (#8YGZFB8).

### Known issues

- The event bus's far side is unbounded: a subscriber node that does not
  drain its distribution socket grows without limit, and OTP 28 offers no
  expressible cap from the router side (#RWTMGJ9). `bus_backlog` will
  read zero there because the manager never parks.
- Seven bus-carried facts have no log record yet; taking the log to
  production level is deferred (#ADQ3WVM).
