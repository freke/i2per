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

# %%%%% The PR tier %%%%%
#
# What a pull request runs. **Measured 2026-10-02 at ~55s** -- eunit 13s plus
# 41s for 100 CT cases -- against ~221s for `just check`.
#
# The gate stops at its first failure, so a *red* run already reports in seconds.
# This recipe is for the other case: a green run you would otherwise wait ten
# minutes to learn about.
#
# **Lint is in it, `doc` is not.** Formatting costs ~1s and is a thing a PR gets
# wrong; the ExDoc build is a few seconds of work nobody is waiting on, and `main`
# builds it.
#
# **This is not the gate, and it is not named as if it were.** 6 of 25 CT suites,
# so a PR touching SAM, streaming, addressbook, reseed, netdb-srv or a
# peer-lifecycle suite can go green and break `main`. That is the price of a
# one-minute signal, paid deliberately rather than by accident; `main` runs
# everything. Why these six, and exactly what is given up, is argued in
# `scripts/ct-suites.sh` next to the list itself.
#
# No `--cover`: this is for turnaround, and the aggregate report is
# `just coverage`'s business. `--sname` for the same reason as `ct` below.
#
# The PR tier: all 940 eunit cases plus 100 CT ones, in about 55s
check-fast: lint
    rebar3 as test eunit
    rebar3 ct --sname i2per_ct --suite="$(bash scripts/ct-suites.sh fast)"

# Run the full suite (eunit + ct) with coverage and render the merged report
coverage:
    rebar3 as test do eunit --cover, ct --cover --sname i2per_ct
    rebar3 cover

# Run Common Test suites (--sname gives the whole CT node a fixed dist name so
# apps/i2per_status/test/i2per_status_SUITE.erl can spawn a `peer` router;
# --cover so `just check` still produces the ct.coverdata half of the aggregate)
ct:
    rebar3 ct --cover --sname i2per_ct

# %%%%% The slow tier %%%%%
#
# `i2p_ssu2_e2e_SUITE`'s receive-window case drives 22,000 real encrypted
# datagrams through a live session pair: 15s here, and the suite measured
# **5m52s** alone on a GitHub runner -- about 14x slower than the rest of CT,
# which is only ~2.5x slower. Nine testcases out of 223 were taking six of the
# gate's 8m21s of CT, in *both* jobs, so one suite was setting the critical path
# for the whole pipeline.
#
# It is here so it can be run *alone* when it is the thing being worked on. CI
# does not: `main` runs all 223 and a pull request runs the six above.
#
# **No `--cover`.** Coverdata is per-`rebar3 ct`-process and this is a
# single-suite run for development, not an aggregate. Measured at 2s of 43s --
# worth dropping, not worth a report nobody reads.

# The slow suites alone. For working on the receive window, not for CI.
ct-slow:
    rebar3 ct --sname i2per_ct --suite="$(bash scripts/ct-suites.sh slow)"

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
