# Parity with i2pd: the frozen 1.0.0 target

This file pins "parity with i2pd" to a dated snapshot so the target cannot
move silently. 1.0.0 is full functionality measured against what i2pd can do
**today**; new crypto, messages or protocol appearing in a later i2pd release
are not in scope and do not change 1.0.0. See `3M0RBXX` for the decision and
`8AA3BVK` for the map that records it.

## Snapshot

- **i2pd version:** 2.61.0
- **Date taken:** 2026-10-07
- **i2per release at snapshot:** 0.9.0
- **Source of the capability list:** i2pd 2.61.0 release notes plus the
  capabilities exercised by `scripts/interop_i2pd.sh` and
  `docs/protocol.md`.
- **Previous snapshot:** none — 2.61.0 is the baseline for 1.0.0. Per the header,
  capabilities appearing in a later i2pd release do not change 1.0.0 unless
  explicitly absorbed (see "1.0.0 material").

Rows are one verdict, not prose: **done** (implemented and exercised),
**partial** (implemented partially / bounded / off by default), or **absent**
(not implemented).

## Capabilities

| Capability | Verdict | Notes |
|---|---|---|
| NTCP2 transport (incl. data phase) | done | `apps/i2per` NTCP2; see `docs/protocol.md`; tests: `i2p_ntcp2_tests`, `i2p_ntcp2_conn_SUITE`, `i2p_ntcp2_vectors_SUITE` |
| NTCP1 (legacy) | absent | excluded by maintainer decision |
| SSU2 transport (handshake + data phase) | done | session establishment verified in interop; data phase replayed hermetically from committed i2pd vectors; tests: `i2p_ssu2_tests`, `i2p_ssu2_handshake_SUITE`, `i2p_ssu2_e2e_SUITE`, `i2p_ssu2_vectors_SUITE` |
| SSU2 path migration | absent | excluded; blocks 18/19 stay keepalive-echo |
| SSU2 congestion control / RTT | done | window-based congestion control and RTT estimation (`RC68AGE`); tests: `i2p_ssu2_cc_SUITE`, `i2p_ssu2_cc_tests` |
| SSU1 (legacy) | absent | excluded by maintainer decision |
| ECIES encryption / garlic | done | LeaseSet2, garlic clove handling; tests: `i2p_ecies_tests`, `i2p_garlic_tests` |
| ElGamal / AES legacy crypto | absent | excluded by maintainer decision |
| Static-key (NTCP1) crypto | absent | legacy, excluded |
| Tunnel creation v0.1 (ECIES) | done | 3-hop outbound and inbound; tests: `i2p_tunnel_tests`, `i2p_tunnel_srv_SUITE` |
| Tunnel build v2 (variable tunnels) | done | hop cap raised to 7 (i2pd parity, `NUM_HOPS`/`MAX_HOPS`); default build stays 3 hops; tests: `i2p_tunnel_tests` |
| Transit tunnel participation | partial | available, bounded (transit_max_tunnels default 10, transit_bandwidth_kbps default 64; 0 disables); on by default with a small cap; tests: `i2p_tunnel_srv_SUITE` |
| Inbound gateway role | done | tests: `i2p_tunnel_srv_SUITE` |
| Outbound gateway role | done | client send runs in caller process (ADR 0003) |
| Streaming protocol | done | implemented; field accessors read through and written around (#C252TF7); tests: `i2p_streaming_tests`, `i2p_stream_tests`, `i2p_stream_conn_SUITE` |
| NetDb (lookup / store) | done | RI and LeaseSet lookups; tests: `i2p_netdb_tests`, `i2p_lookup_srv_SUITE` |
| Floodfill participation | partial | available, off by default (floodfill env: true/false/auto; auto uses capacity_ok gate: bandwidth class O+ and published NTCP2); tests: `i2p_floodfill_tests`, `i2p_floodfill_SUITE` |
| LeaseSet v2 | done | tests: `i2p_leaset_tests` |
| LeaseSet v1 | partial | receive, store and serve (store type 1); publishing not supported (X25519 + Ed25519 forces LeaseSet2); tests: `i2p_leaset_v1_smoke_tests`, `i2p_netdb_v1_tests` |
| Encrypted / Meta LeaseSets | partial | type 5 (EncryptedLeaseSet) and type 7 (MetaLeaseSet) stored and served verbatim, capacity- and age-bounded by a fixed 24 h insertion ceiling (`?RAW_LS_MAX_AGE_SEC` in `i2p_netdb`); no lease-validity expiry is decoded (the record's published/expires fields are not parsed), so the ceiling is the expiry; type 7 is not re-broadcast; publishing not supported; tests: `i2p_netdb_raw_tests` |
| SAM v3 | done | `i2p_sam_srv`; tests: `i2p_sam_SUITE`, `i2p_sam_api_SUITE` |
| I2CP | absent | excluded by maintainer decision |
| Datagram2 | done | codec (`encode2`/`decode2`, signature over target hash) + options Mapping (flag bit 4) + offline signatures (flag bit 5, checked against the destination's own signing key) + bounded per-destination replay window + SAM `STYLE=DATAGRAM2` / `DATAGRAM2 SEND` with `DATAGRAM2 RECEIVED`; tests: `i2p_datagram_tests`, `i2p_datagram_replay_tests`, `i2p_sam_datagram_SUITE` |
| Addressbook (subscribe) | done | tests: `i2p_addressbook_SUITE`, `i2p_addressbook_subs_tests` |
| Addressbook (publish) | done | dump merged book to configured hosts_file (i2pd addressbook.hostsfile parity), atomic rewrite, counters/events; serve via operator eepsite/server tunnel; tests: `i2p_addressbook_SUITE` |
| Post-quantum (ML-KEM) NTCP2 | absent | i2pd 2.59+; new crypto, out of scope per header |
| Charlie / introducer role | done | in-session RelayResponse and out-of-session HolePunch (type 11), rate-limited and endpoint-checked (`A740VAB`); tests: `i2p_relay_tests`, `i2p_ssu2_relay_SUITE` |
| Automatic NetDb-driven Charlie selection | done | SSU2 + peer_test + public address candidates; uniform random; one Charlie per cycle; per-Alice 60s rate limit; code-2 reject on failure; tests: `i2p_ssu2_peertest_SUITE` |
| Peer testing | done | measured reachability ladder; tests: `i2p_peertest_tests`, `i2p_ssu2_peertest_SUITE` |
| Measured reachability | done | see `CD7ZBVH`; tests: `i2p_ssu2_reachability_SUITE` |
| TUN interface | partial (separate app) | `i2per_tun` companion app (ADR 0001), shape (a) flow translator (SAM STREAM + RAW/DATAGRAM helpers); the packet data path is out of 1.0.0 scope - it writes raw stream payload into the packet-oriented TUN device (no TCP termination / IP synthesis; see `T57SS4F`); tests: `i2per_tun_*_tests` |
| SOCKS / HTTP proxy / BOB / I2PControl | partial (separate app) | SOCKS and HTTP proxy implemented and shipped as `i2per_proxy`; BOB protocol and I2PControl not implemented (I2PControl is 3.x work, see `TZFYB9R`); tests: `i2per_proxy_*_tests` |
| In-built status monitor | done (separate app) | `i2per_status` presentation app; held fields rendered (peers/tunnels/netdb/config/SAM), derived rates and reachability ladder; absent: graceful shutdown, non-SAM service rows, peer-test error reasons; tests: `i2per_status_*_tests` |
| UPnP / NAT traversal service | done (separate app) | `i2p_upnp_srv` (off by default, hot-switchable); SSDP discovery, SOAP port mapping with renewal; tests: `i2p_upnp_srv_tests` |

## 1.0.0 material explicitly listed

None as of 0.9.0: operator console shipped as a companion app; `i2per_tun` ships as a companion app but its packet data path is out of 1.0.0 scope (flow translator writes raw stream payload to a packet-oriented device; no TCP termination / IP synthesis - see `T57SS4F`); LeaseSet v1 / EncryptedLeaseSet / MetaLeaseSet partials are bounded by design (publishing not supported) and tracked in their rows above; BOB / I2PControl and the TUN packet data path are out of 1.0.0 scope.

## Freshness

A goal with no recorded date leaks. This file is refreshed whenever i2pd
publishes a release that changes the capability surface; the maintainer opens a
follow-up ticket at that point so the refresh is scheduled rather than hoped for.

## Recapturing the committed vectors

`apps/i2per/test/fixtures/i2pd_ssu2_data_phase.term` holds SSU2 data-phase
datagrams captured from i2pd 2.61.0 — the version this capture covers for the
2.61.0 snapshot above — and
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
