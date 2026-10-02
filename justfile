# i2per Justfile

# Default task: list recipes
default:
    @just --list

# Compile the project
compile:
    rebar3 compile

# Run unit tests with coverage
test: eunit ct

eunit:
    rebar3 as test eunit --cover

# The fast tier: the whole unit layer, plus the CT suites chosen to catch the
# breakages a unit test cannot see. Named for what it is rather than `smoke`,
# which is already the live-network probe further down and means something else.
# **Measured 2026-10-02 at ~54s** -- eunit 13s plus 41s for 100 CT cases --
# against ~221s for `just check`. About 4x, for 45% of the CT cases and 100% of
# the eunit ones.
#
# The gate already stops at its first failure, so a red `just check` reports in
# seconds rather than after CT. This recipe is for the other case: a *green* run
# you have to wait four minutes to learn about.
#
# **What is chosen, and why these.** Each suite earns its place by covering
# something eunit structurally cannot: `i2p_boot_SUITE` starts the real
# supervision tree, `i2p_config_srv_SUITE` and `i2p_read_api_SUITE` cover the
# configuration and the 0.2.0 read contract, `i2p_tunnel_srv_SUITE` is the tunnel
# path end to end, and the two transport suites mean a change that breaks NTCP2
# *or* SSU2 cannot pass this. `i2p_ssu2_handshake_SUITE` is the cheap SSU2 proxy:
# the fuller `i2p_ssu2_e2e_SUITE` costs 26s on its own and pushed the tier to 98s.
#
# **What it does not cover, stated rather than implied.** No SAM suite, so the
# client-facing path is unchecked here (`i2p_sam_SUITE` alone is 31s). No
# streaming, addressbook, reseed, netdb-srv, or peer-lifecycle suites. A change
# confined to those can pass this and still be caught by the full gate -- which
# is the point of having both, not a reason to trust this one alone.
#
# No `--cover`: this is for turnaround, and the aggregate report is
# `just coverage`'s business. `--sname` for the same reason as `ct` below.
#
# The fast tier: all 940 eunit cases plus 100 CT ones, in about 55s
check-fast:
    rebar3 as test eunit
    rebar3 ct --suite=apps/i2per/test/i2p_boot_SUITE,apps/i2per/test/i2p_config_srv_SUITE,apps/i2per/test/i2p_read_api_SUITE,apps/i2per/test/i2p_tunnel_srv_SUITE,apps/i2per/test/i2p_ntcp2_conn_SUITE,apps/i2per/test/i2p_ssu2_handshake_SUITE --sname i2per_ct

# Run the full suite (eunit + ct) with coverage and render the merged report
coverage:
    rebar3 as test do eunit --cover, ct --cover --sname i2per_ct
    rebar3 cover

# Run Common Test suites (--sname gives the whole CT node a fixed dist name so
# apps/i2per_status/test/i2per_status_SUITE.erl can spawn a `peer` router;
# --cover so `just check` still produces the ct.coverdata half of the aggregate)
ct:
    rebar3 ct --cover --sname i2per_ct

# Run one CT suite
ct-suite name:
    rebar3 ct --suite=apps/i2per/test/{{name}} --sname i2per_ct

# Run one EUnit module
eunit-module name:
    rebar3 as test eunit --module={{name}}

# Repeat one CT suite n times (flake hunting)
repeat suite n:
    rebar3 ct --suite=apps/i2per/test/{{suite}} --repeat={{n}} --sname i2per_ct

# Run the external i2pd interoperability suite. This is an explicit opt-in and
# is not part of the hermetic check gate.
interop:
    scripts/interop_i2pd.sh

# Run SipHash micro-benchmark (pure-Erlang NTCP2 frame-length obfuscation)
bench-siphash:
    escript bench/bench_siphash.escript

# Live-network smoke: boot a throwaway router and emit the network observables
# (peers / dialed / netdb_router_info_growth / transit_relayed_tunnels) as JSON.
# Hermetic by default (self-seed, offline); pass --live for a real join from a
# routable host. Not part of check.
smoke flags="":
    escript scripts/live_smoke.escript {{flags}}

# Build the prod relx release tarball + MANIFEST into dist/ (run via devenv;
# requires rebar3/erl on PATH — see scripts/build-release.sh)
release:
    bash scripts/build-release.sh

# Run static analysis
dialyzer:
    rebar3 dialyzer

# Format the code with erlfmt
format:
    erlfmt -w apps/*/src/*.erl apps/*/test/*.erl

# Lint the code (check formatting)
lint:
    erlfmt -c apps/*/src/*.erl apps/*/test/*.erl

# Generate the umbrella ExDoc site into `doc/` (also run by `check`)
doc:
    bash scripts/gen-docs.sh

# Open Erlang shell with the application started
shell:
    rebar3 shell

# Clean build artifacts
clean:
    rebar3 clean
    rm -rf *dump

# Show jujutsu status
status:
    jj status

# Create a new commit with jj
commit message:
    jj commit -m "{{message}}"

# Run all quality checks
check: lint doc test
