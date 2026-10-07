# Changelog

All notable changes to i2per are recorded here. Versions follow the OTP
applications' own `{vsn, ...}`; the release tag is `v` + that version, and
CI refuses a tag that disagrees.

## [Unreleased]

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

- **Versioned public read API over the event bus.** `i2p_stats` holds the
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
  floodfill lookup walks an index instead of scanning (#13EY2MQ).

### Known issues

- The event bus's far side is unbounded: a subscriber node that does not
  drain its distribution socket grows without limit, and OTP 28 offers no
  expressible cap from the router side (#RWTMGJ9). `bus_backlog` will
  read zero there because the manager never parks.
- Seven bus-carried facts have no log record yet; taking the log to
  production level is deferred (#ADQ3WVM).
