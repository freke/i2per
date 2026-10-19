# i2per

`i2per` is an Erlang/OTP implementation of an I2P router with a SAM v3 client
bridge. This repository contains the 0.5.0 release. It implements the modern
X25519 and Ed25519 protocol surface, including NTCP2, SSU2, ECIES tunnel
creation, LeaseSet2, the I2P streaming protocol, and bounded tunnel relay
participation.

The project interoperates with I2P routers. It does not bundle code from
`i2pd` or `i2p-java`; the repository's `NOTICE` file records the attribution.

> **Status: 0.5.0 is in preparation.** The release page
> (<https://github.com/freke/i2per/releases>) will carry the relx tarball and its
> provenance MANIFEST, built by CI from the tag rather than by a person
> remembering to run `just release`. The documentation site is published from the
> same tag at <https://freke.github.io/i2per/>. `CHANGELOG.md` records what
> changed, including the known issues an operator should know about.
>
> 0.5.0 is the performance release: SSU2 gains RTT estimation and window-based
> congestion control, so a router manages its own throughput instead of relying
> on a fixed resend timer. It also captures the SSU2 data-phase vectors from a
> real i2pd and surfaces RTT and congestion state in `i2p_status_data:view/0`.
> No wire-format or configuration-key changes, so a 0.4.0 `data_dir` is read
> unchanged. The external i2pd interoperability suite remains a local
> diagnostic; it is not a required CI gate.
> See [ADR 0001](https://github.com/freke/i2per/blob/main/docs/adr/0001-data-only-core-with-presentation-apps.md),
> [ADR 0002](https://github.com/freke/i2per/blob/main/docs/adr/0002-the-logging-floor-the-bus-is-the-instrument.md)
> and the [changelog](CHANGELOG.md) for the reasoning.

## Included in 0.2.1

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
  configuration loader, a runtime configuration service, an event bus with a
  published `subscribe/1` / `unsubscribe/1` entry point, and the standalone
  `i2per_status` web service.
- **Observability:** a versioned read API (`i2p_status_data:view/0`) over
  counters, gauges and node uptime; the telemetry contract (per-transport bytes,
  transit relay bytes, tunnel build/fail tallies, and
  the `peer_connect_failed` / `transit_denied` / `leaseset_publish_failed`
  / `lookup_failed` events); and a logging floor whose 3am checklist is
  executable rather than prose.
- **Operations:** offline-safe release defaults, reseed certificate anchors,
  and relx packaging with a provenance MANIFEST.

## Included in 0.3.0

- **Charlie relay role:** answer RelayIntro requests as a Charlie, verify the
  request against Alice's RouterInfo, and reply in-session or in a HolePunch to
  her asserted endpoint.
- **Measured reachability:** peer testing feeds a typed ladder from `unknown`
  to `reachable`, with hysteresis and the measured verdict reflected in the
  published RouterInfo caps.
- **Hermetic protocol gate:** the SSU2 data phase is captured from a real i2pd
  and committed, then replayed on every push by `i2p_ssu2_vectors_SUITE`, so
  the ACK accounting is checked against another router's bytes rather than
  against our own encoder — without running an i2p server in the pipeline.
  `scripts/capture_i2pd_vectors.sh` takes the capture; the gate never runs it.
- **Bus hardening:** the event bus records every fact it carries, survives a
  subscriber death, and measures the far-side backlog instead of assuming it
  cannot grow.
- **Release hardening:** dead sessions clean up coordinator state, the SSU2
  listener survives unreachable peer-asserted endpoints, and the relx release
  builds the `0.3.0` tarball.

## Included in 0.4.0

- **Dial convergence:** the three dial parks (transit, peer-test, tunnel-build)
  are each bounded by a single derived number; the dial transport preference can
  be flipped at runtime without disturbing in-flight dials; coordinators'
  supervision shape and enable key are settled; `connect_via_introducer/5` is
  covered and its defects fixed; the re-flood is gated on a nonzero reply token;
  Bob validates the granted relay token; a token'd DatabaseStore is answered
  with the reply token.
- **Hot path cost:** dirty-scheduler crypto flags; per-datagram syscall and log
  allocation removed in SSU2; sessions drop the retained RouterInfo; undecryptable
  garlic stops at the first open; the floodfill lookup walks a floodfill-only
  index.
- **Simplification:** unused Noise XX ratchet and ElG2 removed; `i2p_sam_proxy`
  no longer ships as a feature; streaming accessors read through and written
  around.
- **Test gate:** eunit shared-state cases isolated.
- **Doc truth:** parity.md no longer bills the Charlie hole punch as 1.0.0.

## Included in 0.5.0

- **SSU2 congestion control and RTT:** SSU2 estimates RTT and runs window-based
  congestion control, so a router manages its own throughput instead of relying
  on a fixed resend timer.
- **Hermetic protocol gate:** the SSU2 data phase is captured from a real i2pd
  and committed, then replayed on every push by `i2p_ssu2_vectors_SUITE`.
- **Observability:** `i2p_status_data:view/0` (view version 5) reports aggregate
  SSU2 RTT and congestion window, and the status page surfaces them.
- **Scope:** 0.5.0 anchors on RC68AGE alone; NetDb-driven Charlie selection is
  deferred to 0.6.0.

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
instead of assembling the toolchain by hand.

**The pinned environment loads itself.** `.envrc` puts it in every shell you open
in this directory, including your editor's, a REPL and anything an agent runs:

```sh
git clone https://github.com/freke/i2per && cd i2per
direnv allow      # once per checkout, and deliberately not automatic
```

That prompt is direnv's, and it is a security boundary rather than a papercut:
running an `.envrc` executes shell code from the checkout, so direnv refuses
until you have read it. Approve it once and every later shell is already
correct.

**Editing `.envrc` asks again.** direnv trusts a specific revision of the file,
not the path, so any change to it re-blocks every open shell — and the symptom is
`rebar3: command not found` in a shell that worked a minute ago. Run `direnv
allow` again after editing it.

For a shell that does not have direnv — a script, or CI:

```sh
devenv shell -- <command>
```

Note the `--`. `devenv shell` without it starts an interactive subshell, which is
why an editor or a REPL opened from inside one still has no toolchain.

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
%% The version string moves with each release; it is the app's own {vsn, ...}.
{ok, "0.5.0"} = application:get_key(i2per, vsn).
```

The successful results are `{ok,[i2per]}`, `true`, and `ok`. Leave the shell
with `q().`.

This is an offline, in-memory application boot. It does not set `data_dir` or
`seeds`, so the persistent peer and tunnel services are not started. Use the
packaged release section below when you need a full router process.

## Build and verify

From the repository root — where the pinned environment is already on `PATH`:

```sh
just smoke-test   # the push tier: lint, unit tests, most of the CT suites
just test         # everything: lint, docs, all eunit, all CT, coverage
just check        # the release gate: `just test` plus dialyzer
just proper       # the property tests alone (also inside `just test`)
just dialyzer     # static analysis alone (also inside `just check`)
just live-smoke   # boot a throwaway router and print its network observables
just doc          # regenerate the local ExDoc site in doc/
```

### The three test layers

The tree separates tests by *what is under test*, and the recipes are named
after that:

| recipe | runs | when |
| --- | --- | --- |
| `just proper` | the property modules, over generated inputs | `main`, and on request |
| `just smoke-test` | lint, every unit module, every CT suite but the slow two | **every push** |
| `just test` | lint, docs, dialyzer, every eunit module, every CT suite | `main` |

Case totals are not written down here on purpose: `rebar3` prints the number of
tests each run executed, and a figure kept in prose is a second copy of it that
no run checks.

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

`just check` is the release gate: `erlfmt`, the generated docs, dialyzer, and
every test. It is an alias for `just test` plus `just dialyzer`, and dialyzer is
run before the tests because it reads source and does not depend on which suites
ran — so a type error fails the gate in ~49s rather than after the ~4 minutes of
eunit and CT. Dialyzer is separately runnable because the `compat` CI job invokes
it on its own. `doc/` is generated output and is not committed. The repository
test suite is part of the release quality process.

## Run the packaged release

To install a published release, download the tarball and its `.manifest` from
the [release page](https://github.com/freke/i2per/releases), then check the
recorded hash against the artifact:

```sh
tar xzf i2per-<vsn>-<rev>.tar.gz
grep '^sha256:' i2per-<vsn>-<rev>.tar.gz.manifest
sha256sum i2per-<vsn>-<rev>.tar.gz
cd i2per-<vsn>-<rev> && bin/i2per foreground
```

The manifest also records the source commit, the source tree hash, the OTP it
was built against, and the build date, so a deployment can say exactly which
build it is running.

To build one locally:

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
max_stream_connections = 128

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

**Availability is boot-time; the dial preference is hot.** The listener is bound
and the RouterInfo address published from the value read at start, so serving
UDP (whether this router publishes an SSU2 address at all) is fixed for the
life of the process and a restart is the only way to change it. The *dial*
preference -- which transport this router reaches for first -- is not: it can be
flipped at runtime with `i2p_config_srv:set(ssu2_preferred, true | false)`
without disturbing in-flight dials or established connections, and the new value
is what `f:i2p_identity:ssu2_preferred/0` reports and what the status view
shows. The running boot-time setting is on the boot's `config in force` line.
Choosing `prefer_udp` on a UDP-blocked network therefore no longer needs a
reboot to undo, but the availability half still does, so it is worth deciding
deliberately. The configuration value read at boot is rejected if it is not one
of the three, rather than falling back to the default.

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
`releases/<vsn>/sys.config` to change the shipped `./data` directory (the
directory is named after the release, so it carries the version — `0.5.0` for
this release). A
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
results. `i2p_events:subscribe/1` is the published entry point — a local or a
remote collector attaches the same way, and nothing outside the core calls
`gen_event:*` directly:

```erlang
ok = i2p_events:subscribe(self()).
receive
    {event, Event} -> Event
end.
```

Delivery is best-effort and never propagates a delivery failure to the
emitter. The backlog depth behind a wedged handler is published as the
`bus_backlog` gauge in the read API; a depth that does not fall is what
identifies the fault.

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

The normal `just check` gate is hermetic, but it is not self-referential: some
of what it checks is replayed from a real i2pd. `apps/i2per/test/fixtures/
i2pd_ssu2_data_phase.term` holds SSU2 data-phase datagrams — a real peer's ACK
blocks, its RouterInfo, its I2NP messages — together with the session keys that
make them readable, and `i2p_ssu2_vectors_SUITE` replays them with no i2pd and
no network. To recapture against a different i2pd:

```sh
I2PD_BIN=/path/to/i2pd just capture-vectors
```

The capture needs an i2pd binary and nothing else: it boots a throwaway router
with an empty NetDb, records one SSU2 session, and rewrites the fixture. It is
run by hand, on purpose, for the same reason the interop suite below is — a
fixture regenerated on every push would be a fixture nobody reads.

To run the explicit interop suite against a real i2pd instance:

```sh
I2PD_BIN=/path/to/i2pd scripts/interop_i2pd.sh
```

This starts a local i2pd, runs the NTCP2 and SSU2 interoperability cases, and
removes the temporary instances. It contacts an external service and is never
part of the normal gate. `just live-smoke` is an offline self-check. Use
`just live-smoke --live` only when joining the real I2P network is intended.

## Release limitations

The 0.5.0 release does not implement NTCP1, SSU1, I2CP, the legacy ElGamal/AES
crypto formats, Datagram2, or a TUN interface. SSU2 path migration and automatic
NetDb-driven Charlie selection are outside this release. Floodfill and transit
participation are available as bounded features, but they are not enabled by
the shipped default profile. Automatic NetDb-driven Charlie selection is not
implemented: the Charlie role itself is (a tagged session answers a RelayIntro,
verifies the requester's signature and punches), so a peer that already holds a
tag from i2per can select it. In-place relup upgrades are not supported;
upgrading means installing a new tarball. 0.5.0 keeps the 0.4.0 dial and hot
path surface and adds SSU2 RTT estimation and window-based congestion control,
hermetic SSU2 vectors, and status-page visibility; a `data_dir` written by
0.4.0 is read unchanged.

`CHANGELOG.md` lists the known issues for this release: the event bus's far
side is unbounded if a subscriber node stops draining (OTP 28 offers no cap
from the router side), and SSU2 congestion control and RTT are 1.0.0 material.

The 1.0.0 target is frozen in [`docs/parity.md`](docs/parity.md), which pins a
dated i2pd capability snapshot so "parity with i2pd" cannot drift as i2pd moves.

## Documentation

- The published documentation site for the current release is
  <https://freke.github.io/i2per/>, built and published by CI from the release
  tag. `just doc` regenerates it locally into `doc/`.
- [Changelog](CHANGELOG.md) records what changed in each release, with ticket
  references and the known issues.
- [Protocol reference](docs/protocol.md) documents the wire formats implemented
  by this release.
- [Documentation standards](docs/documentation.md) defines the EEP-48 and
  ExDoc requirements for source changes.
- ADRs under `docs/adr/` record the decisions this release line rests on.

## License

i2per is available under the BSD 3-Clause License. The repository's `LICENSE`
and `NOTICE` files contain the license terms and i2pd interoperability
attribution.
