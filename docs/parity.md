# Parity with i2pd: the frozen 1.0.0 target

This file pins "parity with i2pd" to a dated snapshot so the target cannot
move silently. 1.0.0 is full functionality measured against what i2pd can do
**today**; new crypto, messages or protocol appearing in a later i2pd release
are not in scope and do not change 1.0.0. See `3M0RBXX` for the decision and
`8AA3BVK` for the map that records it.

## Snapshot

- **i2pd version:** 3.0.0
- **Date taken:** 2026-10-21 (snapshot bumped on i2pd 3.0.0 release; interop
  suite re-run pending, see `94S9H7K`)
- **i2per release at snapshot:** 0.6.0
- **Source of the capability list:** i2pd 3.0.0 release notes plus the
  capabilities exercised by `scripts/interop_i2pd.sh` and
  `docs/protocol.md`.
- **Previous snapshot:** 2.61.0 (2026-10-07). Per the header, capabilities new in
  3.0.0 do not change 1.0.0 unless explicitly absorbed (see "1.0.0 material").

Rows are one verdict, not prose: **done** (implemented and exercised),
**partial** (implemented partially / bounded / off by default), or **absent**
(not implemented).

## Capabilities

| Capability | Verdict | Notes |
|---|---|---|
| NTCP2 transport (incl. data phase) | done | `apps/i2per` NTCP2; see `docs/protocol.md` |
| NTCP1 (legacy) | absent | excluded by maintainer decision |
| SSU2 transport (handshake + data phase) | done | session establishment verified in interop; data phase replayed hermetically from committed i2pd vectors |
| SSU2 path migration | absent | excluded; blocks 18/19 stay keepalive-echo |
| SSU2 congestion control / RTT | done | window-based congestion control and RTT estimation (`RC68AGE`) |
| SSU1 (legacy) | absent | excluded by maintainer decision |
| ECIES encryption / garlic | done | LeaseSet2, garlic clove handling |
| ElGamal / AES legacy crypto | absent | excluded by maintainer decision |
| Static-key (NTCP1) crypto | absent | legacy, excluded |
| Tunnel creation v0.1 (ECIES) | done | 3-hop outbound and inbound |
| Tunnel build v2 (variable tunnels) | done | hop cap raised to 7 (i2pd parity); default build stays 3 hops |
| Transit tunnel participation | partial | available, bounded, off by default |
| Inbound gateway role | done | |
| Outbound gateway role | done | client send runs in caller process (ADR 0003) |
| Streaming protocol | done | implemented; field accessors read through and written around (#C252TF7); i2pd 3.0.0 new UDP tunnels window/ack policy |
| NetDb (lookup / store) | done | RI and LeaseSet lookups; i2pd 3.0.0 faster lookups, rejects LS type 1 from ECIES sessions, rejects ipv4-mapped ipv6 in RI |
| Floodfill participation | partial | available, off by default |
| LeaseSet v2 | done | |
| LeaseSet v1 | absent | 1.0.0 material (see `0.2.0` map) |
| Encrypted / Meta LeaseSets | absent | 1.0.0 material; i2pd 3.0.0 adds offline keys for encrypted LeaseSets |
| SAM v3 | done | `i2p_sam_srv`; i2pd 3.0.0 ships SAM 3.3 — extensions (offline keys, multi-dest) are 1.0.0 candidates |
| I2CP | absent | excluded by maintainer decision |
| Datagram2 | done | codec (`encode2`/`decode2`, signature over target hash) + bounded per-destination replay window + SAM `STYLE=DATAGRAM2` / `DATAGRAM2 SEND` with `DATAGRAM2 RECEIVED`; options Mapping and offline signatures deferred (R85EHTA) |
| Addressbook (subscribe) | done | |
| Addressbook (publish) | absent | deferred |
| Multi-destination client tunnels | absent | i2pd 3.0.0; operator surface, undecided |
| Torrents tunnels (RPC/magnets/PEX/DHT/datagram trackers) | absent | i2pd 3.0.0; out of scope for 1.0.0 |
| Post-quantum (ML-KEM) NTCP2 | absent | i2pd 2.59+; new crypto, out of scope per header |
| Charlie / introducer role | done | in-session RelayResponse and out-of-session HolePunch (type 11), rate-limited and endpoint-checked (`A740VAB`) |
| Automatic NetDb-driven Charlie selection | done | SSU2 + peer_test + public address candidates; uniform random; one Charlie per cycle; per-Alice 60s rate limit; code-2 reject on failure |
| Peer testing | done | measured reachability ladder |
| Measured reachability | done | see `CD7ZBVH` |
| TUN interface | done (separate app) | `i2per_tun` companion app (ADR 0001) |
| SOCKS / HTTP proxy / BOB / I2PControl | done (separate app) | `i2per_proxy` companion app; i2pd 3.0.0 adds `LocalDestinationInfo` to I2PControl |
| In-built status monitor | partial | separate presentation app (`i2per_status`) |
| UPnP / NAT traversal service | absent | one-shot indirect dial only |

## 1.0.0 material explicitly listed

- LeaseSet v1, EncryptedLeaseSet, MetaLeaseSet (offline keys now in i2pd 3.0.0).
- SOCKS / HTTP proxy / BOB / I2PControl console (delivered as `i2per_proxy`).
- TUN interface (delivered as `i2per_tun`).
- SAM 3.3 extensions (offline keys, multi-destination) — candidate from i2pd 3.0.0.
- Datagram2 replay protection (correctness gap, see `NTWZWTC`).

## New in i2pd 3.0.0 — out of scope for 1.0.0 (post-snapshot)

- Torrents tunnels with RPC, magnets, PEX, DHT, datagram trackers.
- Multi-destination client tunnels.
- Post-quantum (ML-KEM) NTCP2/SSU2 crypto.
- New UDP tunnels window and ack policy.

## Freshness

A goal with no recorded date leaks. This file is refreshed whenever i2pd
publishes a release that changes the capability surface; the maintainer opens a
follow-up ticket at that point so the refresh is scheduled rather than hoped for.

## Recapturing the committed vectors

`apps/i2per/test/fixtures/i2pd_ssu2_data_phase.term` holds SSU2 data-phase
datagrams captured from i2pd 2.61.0 — the version pinned above — and
`apps/i2per/test/fixtures/i2pd_ntcp2_handshake.term` holds an NTCP2 XK handshake
and the data phase that followed it. `i2p_ssu2_vectors_SUITE` and
`i2p_ntcp2_vectors_SUITE` replay them in the hermetic gate. The captures are
tied to this snapshot, so they are refreshed on the same cadence as this file:

```sh
I2PD_BIN=/path/to/i2pd just capture-vectors
```

It needs an i2pd binary and no network. Both captures come out of one throwaway
router, so the driver takes SSU2 first and NTCP2 second against the same
instance. Five things about it are not obvious and each cost a capture to find:

- **`reservedrange` must be `false`.** i2pd admits an inbound SSU2 datagram only
  when `!IsInReservedRange(addr)` (`SSU2.cpp:775`), which that flag turns on,
  and its reserved list covers 127/8 and 100.64/10 among others
  (`util.cpp:793`). With the flag left at its default every packet from a
  loopback capture is dropped with "incoming packet received from invalid or
  banned endpoint" and the handshake never starts.
- **`reseed.file`, not `reseed.urls`.** Pointed at a local SU3, i2pd reads it,
  finds every RouterInfo stale, and starts transports immediately. Pointed at
  servers, it retries for `RESEED_GIVEUP_TIMEOUT` (180 s, `Reseed.cpp:26`)
  before giving up. An empty NetDb costs the capture nothing either way: SSU2
  answers a SessionRequest without peers.
- **`ntcp2.published` must be `true`.** The NTCP2 acceptor is created inside a
  loop over the router's own addresses and only for an address where
  `IsPublishedNTCP2()` holds (`NTCP2.cpp:1763`). With `ntcp2.published = false`
  no such address is written, the loop skips every entry, and i2pd binds no
  TCP port at all — the connect that follows fails with `econnrefused` while
  the log looks healthy.
- **Wait on `NTCP2: Start listening v4 TCP port`, and only that line.** i2pd
  also logs `Transports: Accepting incoming connections at port <n>`
  (`Transports.cpp:1608`) for SSU2, and that line appears whether or not NTCP2
  is up. Treating it as evidence of a listener is a false positive that hides
  the case above; the driver greps the acceptor's own line instead.
- **One of our packets is dropped on purpose.** An ACK over a contiguous run of
  packet numbers has an empty range list, and the NACK ranges are the part that
  exercises ACK accounting. The capture swallows one packet so i2pd emits them.

Review the regenerated diff rather than taking it on trust: the ACK accounting
the suite asserts is only meaningful if the capture still contains the loss, and
`a_dropped_packet_stays_a_nack_range` is what fails if a re-capture stopped
producing it.

The SSU2 capture is **not deterministic in packet count**: how many datagrams
i2pd sends before it goes quiet depends on its own timers, so `just
capture-vectors` rewrites `i2pd_ssu2_data_phase.term` with a different number of
packets from run to run. That is fine for a local recapture, but it means the
committed SSU2 fixture must not be regenerated as a side effect of a run where
only the NTCP2 side changed — restore it (`jj restore
apps/i2per/test/fixtures/i2pd_ssu2_data_phase.term`) rather than committing a
noise diff. The NTCP2 fixture's *handshake* bytes are deterministic given the
pinned keys; its `ba_frames` count is subject to the same timer drift.
