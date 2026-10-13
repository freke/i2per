# Parity with i2pd: the frozen 1.0.0 target

This file pins "parity with i2pd" to a dated snapshot so the target cannot
move silently. 1.0.0 is full functionality measured against what i2pd can do
**today**; new crypto, messages or protocol appearing in a later i2pd release
are not in scope and do not change 1.0.0. See `3M0RBXX` for the decision and
`8AA3BVK` for the map that records it.

## Snapshot

- **i2pd version:** 2.61.0
- **Date taken:** 2026-10-07 (interop suite run, see `ENFW64W`)
- **i2per release at snapshot:** 0.3.0
- **Source of the capability list:** i2pd 2.61.0 release notes plus the
  capabilities exercised by `scripts/interop_i2pd.sh` and
  `docs/protocol.md`.

Rows are one verdict, not prose: **done** (implemented and exercised),
**partial** (implemented partially / bounded / off by default), or **absent**
(not implemented).

## Capabilities

| Capability | Verdict | Notes |
|---|---|---|
| NTCP2 transport (incl. data phase) | done | `apps/i2per` NTCP2; see `docs/protocol.md` |
| NTCP1 (legacy) | absent | excluded by maintainer decision |
| SSU2 transport (handshake + data phase) | done | session establishment verified in interop |
| SSU2 path migration | absent | excluded; blocks 18/19 stay keepalive-echo |
| SSU2 congestion control / RTT | absent | 1.0.0 material (`RC68AGE`) |
| SSU1 (legacy) | absent | excluded by maintainer decision |
| ECIES encryption / garlic | done | LeaseSet2, garlic clove handling |
| ElGamal / AES legacy crypto | absent | excluded by maintainer decision |
| Static-key (NTCP1) crypto | absent | legacy, excluded |
| Tunnel creation v0.1 (ECIES) | done | 3-hop outbound and inbound |
| Tunnel build v2 (variable tunnels) | absent | 1.0.0 material |
| Transit tunnel participation | partial | available, bounded, off by default |
| Inbound gateway role | done | |
| Outbound gateway role | done | client send runs in caller process (ADR 0003) |
| Streaming protocol | partial | implemented; field accessors being hardened |
| NetDb (lookup / store) | done | RI and LeaseSet lookups |
| Floodfill participation | partial | available, off by default |
| LeaseSet v2 | done | |
| LeaseSet v1 | absent | 1.0.0 material (see `0.2.0` map) |
| Encrypted / Meta LeaseSets | absent | 1.0.0 material |
| SAM v3 | done | `i2p_sam_srv` |
| I2CP | absent | excluded by maintainer decision |
| Datagram2 | absent | correctness gap, deferred |
| Addressbook (subscribe) | done | |
| Addressbook (publish) | absent | deferred |
| Charlie / introducer role | partial | in-session half implemented; hole-punch half is 1.0.0 material |
| Automatic NetDb-driven Charlie selection | absent | 1.0.0 material |
| Peer testing | done | measured reachability ladder |
| Measured reachability | done | see `CD7ZBVH` |
| TUN interface | absent | excluded by maintainer decision |
| SOCKS / HTTP proxy / BOB / I2PControl | absent | operator surface, undecided |
| In-built status monitor | partial | separate presentation app (`i2per_status`) |
| UPnP / NAT traversal service | absent | one-shot indirect dial only |

## 1.0.0 material explicitly listed

- `RC68AGE` — SSU2 congestion control and RTT estimation.
- Tunnel build v2 with NetDb-driven Charlie selection.
- Hole punching as a Charlie (out-of-session half).
- LeaseSet v1, EncryptedLeaseSet, MetaLeaseSet.
- SOCKS / HTTP proxy / BOB / I2PControl console.
- TUN interface.
- Automatic NetDb-driven Charlie selection.

## Freshness

A goal with no recorded date leaks. This file is refreshed whenever i2pd
publishes a release that changes the capability surface; the maintainer opens a
follow-up ticket at that point so the refresh is scheduled rather than hoped for.