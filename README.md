# i2per

`i2per` is an Erlang/OTP implementation of an I2P router with a SAM v3 client
bridge. This repository contains the 0.1.0 release. It implements the modern
X25519 and Ed25519 protocol surface, including NTCP2, SSU2, ECIES tunnel
creation, LeaseSet2, the I2P streaming protocol, and bounded tunnel relay
participation.

The project interoperates with I2P routers. It does not bundle code from
`i2pd` or `i2p-java`; the repository's `NOTICE` file records the attribution.

> **Status: proof of concept.** The 0.1.0 in this tree is a development snapshot,
> not a published release.
>
> CI is here as of this tree's HEAD: a smoke tier on **every push** answering
> "does the router still come up and work", and on `main` a pinned gate running
> everything (`just test` and `just dialyzer`) plus a warnings-relaxed job asking
> whether another OTP can build and run it. The read API is versioned and its key
> set is checked across the core/consumer boundary, not only inside each
> application. What 0.1.0 does **not** yet have is the external i2pd
> interoperability suite as a required gate — that is deferred to 0.3.0, the
> first release to make protocol claims, because a gate that cannot tell a real
> failure from a known-broken prerequisite is worse than no gate. See
> [ADR 0001](https://github.com/freke/i2per/blob/main/docs/adr/0001-data-only-core-with-presentation-apps.md)
> and [ADR 0002](https://github.com/freke/i2per/blob/main/docs/adr/0002-the-logging-floor-the-bus-is-the-instrument.md)
> for the reasoning.

## Included in 0.1.0

- **Transports:** NTCP2 and SSU2, with one supervised process per connection
  and per-session isolation.
- **Identity and cryptography:** RouterIdentity and Destination keys,
  Ed25519 signatures, X25519 key agreement, HKDF, ChaCha20-Poly1305, and
  SipHash-2-4.
- **Network database:** RouterInfo validation and storage, floodfill helpers,
  LeaseSet2 handling, SU3 reseeding, and remote lookups through tunnels.
- **Tunnels:** ShortTunnelBuild and OTBRM, ECIES build records, layered tunnel
  messages, inbound and outbound gateway roles, pool maintenance, and LeaseSet
  publication.
- **Client APIs:** SAM v3 `STREAM`, `DATAGRAM`, `RAW`, `NAMING LOOKUP`, and
  `STREAM FORWARD`, with the signed and reliable I2P streaming protocol.
- **Services:** server tunnels for local TCP services, a strict INI
  configuration loader, a runtime configuration service, an event bus, and
  the standalone `i2per_status` web service.
- **Operations:** offline-safe release defaults, reseed certificate anchors,
  and relx packaging.

The default profile is a local client. It does not contact the live network,
publish a floodfill RouterInfo, or accept public transit unless an operator
explicitly enables those choices.

## Source

```sh
git clone https://github.com/freke/i2per.git
cd i2per
```

## Requirements

The toolchain this tree is built and gated against:

- Erlang/OTP 28 (erts 16.4.0.6)
- `rebar3` 3.27
- `just` 1.58
- `erlfmt` 1.8

`just check` runs `erlfmt`, which is not part of a stock Erlang install, and
`rebar.config` compiles with `warnings_as_errors` — so a different OTP version
can fail on warnings this one does not produce. Use the pinned environment
instead of assembling the toolchain by hand:

```sh
devenv shell
```

## Developer mode

Start an interactive Erlang shell with the `i2per` OTP application already
booted:

```sh
just shell
```

Wait for `===> Booted i2per`, then run these checks at the Erlang prompt:

```erlang
application:ensure_all_started(i2per).
true = is_pid(whereis(i2per_sup)).
{ok, "0.1.0"} = application:get_key(i2per, vsn).
```

The successful results are `{ok,[i2per]}`, `true`, and `ok`. Leave the shell
with `q().`.

This is an offline, in-memory application boot. It does not set `data_dir` or
`seeds`, so the persistent peer and tunnel services are not started. Use the
packaged release section below when you need a full router process.

## Build and verify

From the repository root, inside the devenv shell:

```sh
just smoke-test   # the push tier: lint, unit tests, most of the CT suites
just test         # everything: lint, docs, all eunit, all CT, coverage
just proper       # the property tests alone (also inside `just test`)
just dialyzer     # static analysis
just live-smoke   # boot a throwaway router and print its network observables
just doc          # regenerate the local ExDoc site in doc/
```

### The three test layers

The tree separates tests by *what is under test*, and the recipes are named
after that:

| recipe | runs | when |
| --- | --- | --- |
| `just proper` | 2 modules, 11 properties over generated inputs | `main`, and on request |
| `just smoke-test` | lint, 958 unit cases, 211 of 224 CT cases | **every push** |
| `just test` | lint, docs, dialyzer, all 969 eunit, all 224 CT | `main` |

Measured at **91s** for `just smoke-test` and **205s** for `just test` on a
developer machine. The smoke tier is under five minutes on a GitHub runner.

**What the smoke tier skips, and why.** Two CT suites:
`i2p_peer_transport_SUITE` (protocol-mandated connect timeouts) and
`i2p_ssu2_e2e_SUITE` (22,000 real datagrams through a live session). Together
they are more than the whole five-minute budget, for failures that are about
waiting rather than behaviour. `just test` runs both.

**Why properties are not in the smoke tier**, given they take 0.23s: a property
test finds its counterexample from a *random* input, so a failure on a push is a
bug report that arrives before anyone can reproduce it — and re-rolling the seed
is the tempting response to a red that keeps flickering.

The tier boundaries are derived from the tree by `scripts/ct-suites.sh` (CT) and
`scripts/eunit-modules.sh` (eunit/PropEr), so a new suite is in tomorrow's smoke
run by default rather than by an edit someone has to remember.

`just test` and `just dialyzer` are the release gates. `just check` is an alias
for `just test`. `doc/` is generated output and is not committed. The repository
test suite is part of the release quality process.

## Run the packaged release

Build a release artifact with:

```sh
just release
```

The build writes a relx tarball and a provenance manifest to `dist/`. The release
script refuses a dirty working copy unless
`I2PER_ALLOW_DIRTY_RELEASE=1` is set for a diagnostic build. When the local
Erlang runtime is linked against Nix, the script builds inside a Debian 13
container so the bundled ERTS and NIFs match the target system.

After extracting the tarball, start the router from that directory with its
shipped defaults:

```sh
bin/i2per foreground
```

The default profile stores router state under `./data`, keeps Erlang
distribution local and disabled, and listens for I2P traffic on loopback. It
does not enable reseeding or live network participation. A deployment that
needs operator RPC must provide its own node name, cookie, and distribution
settings.

## Configuration

The router reads `i2per.conf` from the working directory. Set the
application setting `i2per.config_file` to use another path. A second file,
`tunnels.conf`, declares server tunnels. Unknown keys, unknown sections, and
duplicate entries stop boot rather than being silently ignored.

Example `i2per.conf`:

```ini
host = 127.0.0.1
listen_host = 127.0.0.1
port = 9150
live_network = false
ntcp2_published = false
transit_max_tunnels = 10
transit_bandwidth_kbps = 64
tunnel_build_rate = 1
max_ntcp2_connections = 64
max_sam_sessions = 32
max_ssu2_sessions = 32

[tunnel_pool]
outbound = 3
inbound = 3

[reseed]
enabled = false
min_routers = 50
```

### UDP transport

How this router uses UDP (SSU2) is one application-environment key, not an
`i2per.conf` entry, and it is not settable through `i2p_config_srv`:

```erlang
%% sys.config, or: application:set_env(i2per, ssu2, prefer_udp).
{ssu2, no_udp}.
```

| value | serves UDP | dials UDP first |
|---|---|---|
| `no_udp` (default) | no | no |
| `enable_udp` | yes | no |
| `prefer_udp` | yes | yes |

Serving UDP and preferring it are separate choices, so `enable_udp` binds the
listener and publishes the address in the RouterInfo while outbound dials still
go to NTCP2 first. The fourth combination — serve nothing, dial UDP — is not
offered, since there would be no address to dial.

**The choice is boot-time and there is no runtime escape.** The listener is bound
and the RouterInfo address published from the value read at start; changing the
key while the router runs changes nothing, and a restart is the only way to
change it. The running setting is on the boot's `config in force` line. Choosing
`prefer_udp` on a UDP-blocked network therefore has no way back but a reboot, so
it is worth deciding deliberately. The configuration value read at boot is
rejected if it is not one of the three, rather than falling back to the default.

The deprecated boolean `ssu2_enabled` is still read when `ssu2` is unset, and
means what it always meant: `true` is `prefer_udp`, `false` is `no_udp`. Setting
both is not a contradiction the router resolves by guessing — `ssu2` wins.

Addressbook subscriptions are configured through `sys.config` or the
application environment, not the INI file. Each entry names an I2P host and
its destination:

```erlang
application:set_env(i2per, addressbook, #{
    subscriptions => [
        #{host => <<"stats.i2p">>, dest_b64 => <<"DESTINATION_BASE64">>}
    ]
}).
```

Values already present in `sys.config` or the application environment take
precedence over values in `i2per.conf`. In particular, edit the release's
`releases/0.1.0/sys.config` to change the shipped `./data` directory. A
persistent boot requires `data_dir` and `seeds` in the application environment.
The release profile sets `live_network = false` and `ntcp2_published = false`;
changing either value is an explicit operator decision.

For live participation, configure trusted reseed sources, set
`live_network = true`, choose `listen_host` deliberately, and keep
`ntcp2_published = false` until the advertised address and firewall have been
verified. Enabling live network access can cause the router to contact remote
I2P services and make its identity visible to them.

### Server tunnels

`tunnels.conf` uses one section per local service:

```ini
[eepsite]
type = server
host = 127.0.0.1
port = 8081
```

Each service gets persistent destination keys under
`<data_dir>/<name>.keys`. The section name identifies the server tunnel. SAM
`STREAM FORWARD` is a separate client mechanism configured by destination and
local host/port, not by this section name.

### Runtime configuration

`i2p_config_srv` exposes validated configuration to a connected operator
node:

```erlang
i2p_config_srv:get(transit_max_tunnels).
i2p_config_srv:get_all().
i2p_config_srv:set(transit_bandwidth_kbps, 512).
i2p_config_srv:set(host, <<"10.0.0.9">>).
```

Most runtime keys apply immediately. `transit_bandwidth_kbps` and
`tunnel_build_rate` are read when the tunnel manager starts, so restart that
service before relying on their new values. Listener and identity changes
answer `{ok, pending_restart}` and take effect after the relevant service
restarts. The service never writes configuration files. Persist accepted values
in the active configuration source before restarting; packaged-release values
already present in `sys.config` must be changed there.

### Events

Router state changes are announced on the `i2p_events` `gen_event` manager.
Events include peer connection changes, tunnel builds and failures, LeaseSet
publication, SAM session lifecycle, configuration changes, and SSU2 reachability
results. A handler on another connected node can receive them with:

```erlang
ok = gen_event:add_handler({i2p_events, RouterNode}, i2p_events_forward, [self()]).
receive
    {event, Event} -> Event
end.
```

## Status service

`i2per_status` is a separate OTP application and is never started by the
router. It is included in the repository but not in the production relx
artifact. From a node connected to the router node, start it explicitly:

```erlang
application:set_env(i2per_status, router_node, 'i2per@host').
application:set_env(i2per_status, port, 7662).
application:ensure_all_started(i2per_status).
```

It serves `GET /` and `GET /status.json`. It uses the router event bus for
realtime updates and polls the router when the event connection is unavailable.
The listener defaults to loopback; set `listen_host` explicitly before exposing
it beyond the local machine.

`i2per_status` settings:

| Setting | Default | What it does |
| --- | --- | --- |
| `router_node` | this node | the router's node, reached over Erlang distribution |
| `port` | `7662` | the HTTP listen port |
| `listen_host` | loopback | the HTTP listen address; set it before exposing the page beyond this machine |
| `poll_ms` | `5000` | how often the router is polled when the event connection is unavailable. It is the window the derived rates and ratios are differenced over, so it sets their resolution. Shorten it for hermetic tests or a denser soak series. |

## Interoperability and live checks

The normal `just check` gate is hermetic. To run the explicit interop suite
against a real i2pd instance:

```sh
I2PD_BIN=/path/to/i2pd scripts/interop_i2pd.sh
```

This starts a local i2pd, runs the NTCP2 and SSU2 interoperability cases, and
removes the temporary instances. It contacts an external service and is never
part of the normal gate. `just live-smoke` is an offline self-check. Use
`just live-smoke --live` only when joining the real I2P network is intended.

## Release limitations

The 0.1.0 release does not implement NTCP1, SSU1, I2CP, the legacy ElGamal/AES
crypto formats, Datagram2, or a TUN interface. Path migration and advanced
congestion control are outside the current SSU2 data path. Floodfill and
transit participation are available as bounded features, but they are not
enabled by the shipped default profile. Automatic NetDb-driven Charlie selection
and the complete firewalled HolePunch path are not implemented. In-place relup
upgrades are not supported in 0.1.0; upgrading means installing a new tarball.

## Documentation

- [Protocol reference](docs/protocol.md) documents the wire formats implemented
  by this release.
- [Documentation standards](docs/documentation.md) defines the EEP-48 and
  ExDoc requirements for source changes.

## License

i2per is available under the BSD 3-Clause License. The repository's `LICENSE`
and `NOTICE` files contain the license terms and i2pd interoperability
attribution.
