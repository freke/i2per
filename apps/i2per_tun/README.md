# i2per_tun — fd spike (epiq D3750BZ)

A Rust NIF that owns a Linux TUN device and hands read readiness to the
BEAM via `enif_select`, so no scheduler ever blocks on the device. It is the
fd-ownership probe for the `i2per_tun` ticket: the shape of the app above it
(flow translator vs point-to-point tunnel) is decided by the shape spikes
that build on this.

Decisions this spike implements (recorded on the ticket, 2026-10-23): Rust
NIF rather than C or a port program — Rust panics are caught at the NIF
boundary and surface as `{error, nif_panic}`; Linux `/dev/net/tun` only for
0.8.0; SAM v3 over TCP is the seam the production app will reach.

## Layout

- `native/i2per_tun_nif/` — the crate. `open/1`, `read/1`, `write/2`,
  `arm/2`, `stop/1`, plus `version/0` as a load probe.
- `src/i2per_tun_tun.erl` — the NIF facade (opaque device resource).
- `src/i2per_tun_dev.erl` — gen_server that owns one device: open, arm,
  drain to `eagain`, re-arm.
- `scripts/build-i2per-tun-nif.sh` — cargo build + copy to `priv/`; skips
  when cargo is absent (OTP-compat job), fails when cargo fails.

## Running it for real (privileged, by hand)

The automated tests are hermetic and run unprivileged. The real-device case
needs CAP_NET_ADMIN and is exercised by hand:

```console
$ sudo -E rebar3 shell
1> application:ensure_all_started(i2per_tun).
{ok,[i2per_tun]}
2> logger:set_primary_config(level, debug).
ok
3> os:cmd("ip addr add 10.113.0.1 peer 10.113.0.2 dev i2per0").
4> os:cmd("ip link set i2per0 up").
```

then, from another terminal on the same host:

```console
$ ping -c 2 10.113.0.2
```

The ICMP echo requests are routed into the TUN device; the spike's drain
loop logs one debug line per packet (`at => i2per_tun_dev, bytes => 84`,
for a ping). Nothing is written back yet — this spike proves fd ownership
and the select loop, not a datapath.
