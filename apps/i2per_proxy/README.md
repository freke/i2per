# i2per_proxy — SOCKS and HTTP proxy companion app

Companion app (ADR 0001): exposes the router's I2P destinations to ordinary
TCP clients as a SOCKS5 (and SOCKS4a) proxy and an HTTP proxy. The core stays
data-only; this app reaches it over SAM on TCP, never through core modules.

## What ships today

- `i2per_proxy_http` — HTTP proxy: accepts `GET`/`POST`/`HEAD`, extracts the
  target host, opens a SAM STREAM session, forwards the request, relays the
  response.
- `i2per_proxy_socks` — SOCKS5 CONNECT (no authentication, domain-name and
  IPv4 targets) plus SOCKS4a CONNECT, then bidirectional relay.
- `i2per_proxy_listener` — one listener per protocol (HTTP, SOCKS), binding the
  configured port.
- `i2per_proxy_config` — `listen_host`, `socks_port` (default 4447),
  `http_port` (default 4444), `sam_host`, `sam_port` (default 7656).
- `i2per_proxy_relay` — bidirectional byte relay with a timeout.
- `i2per_proxy_sam` — SAM v3 client conversation (HELLO, SESSION CREATE,
  NAMING LOOKUP, STREAM CONNECT).

## Concurrency

One SAM session per concurrent client flow, so the SAM bridge's capacity is
this app's ceiling. `listen_host` defaults to loopback; remote operation is an
operator decision.

## Platform

Any platform with TCP. No privileged steps; the automated tests are hermetic.

## Running it

```console
$ rebar3 shell
1> application:ensure_all_started(i2per_proxy).
{ok,[i2per_proxy]}
```

Then point a browser or `curl` at `http://127.0.0.1:4444` (HTTP proxy) or
configure a SOCKS5 client for `127.0.0.1:4447`.

## Out of scope (this cut)

BOB protocol, I2PControl JSON-RPC, operator console web UI, HTTPS CONNECT
tunneling, SOCKS authentication methods.
