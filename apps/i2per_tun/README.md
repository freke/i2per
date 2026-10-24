# i2per_tun — TUN companion app (epiq D3750BZ)

Companion app (ADR 0001): owns a Linux TUN device and bridges host TCP flows
to the router's SAM v3 listener. The core stays data-only; this app reaches it
over SAM on TCP, never through core modules.

## What ships today

- `i2per_tun_tun` — Rust NIF facade over `/dev/net/tun` (CAP_NET_ADMIN).
- `i2per_tun_dev` — gen_server owning one device: open, arm, drain to `eagain`,
  re-arm; maintains per-flow packet counts and spawns a held SAM STREAM session
  for each new TCP flow whose destination IP is in the static map; exposes
  `stats/0` (packets/bytes/sessions), `flows/0`, `sessions/0`.
- `i2per_tun_sam` — SAM v3 client conversation (HELLO, SESSION CREATE,
  NAMING LOOKUP, STREAM CONNECT, plus RAW/DATAGRAM helpers) with pure parsers.
- `i2per_tun_config` — static IP -> destination map plus SAM host/port and
  listen port defaults.
- `i2per_tun_flow` — one TCP flow -> one SAM STREAM session, then
  bidirectional relay.
- `i2per_tun_listener` — host-facing TCP listener; one worker per accepted
  connection running `i2per_tun_flow:run/4`.

## Concurrency ceiling

One SAM session per concurrent TCP flow, so `max_sam_sessions` (default 32) is
this app's ceiling. Document a TUN profile with a higher value for busy hosts.
The SAM listener is loopback-only by default; remote-node operation is an
operator `listen_host` decision.

## Platform

Linux `/dev/net/tun` only for 0.8.0; macOS utun and Windows Wintun out of
scope.

## Running it for real (privileged, by hand)

The automated tests are hermetic and run unprivileged. The real-device case
needs CAP_NET_ADMIN:

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
for a ping) and, for a TCP flow whose destination IP is in the static map,
opens and holds a SAM STREAM session to that destination. IP packets are still
not written back to the device — this proves fd ownership, the select loop and
session spawning, not a full datapath.
```