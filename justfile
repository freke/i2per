# i2per Justfile

# Default task: list recipes
default:
    @just --list

# Compile the project
compile:
    rebar3 compile

# %%%%% The three test layers %%%%%
#
# The tree separates by what is being tested, and the recipes are named after
# that rather than after a CI tier:
#
#   proper       properties over generated inputs   -- `*_prop_tests.erl`
#   smoke-test   the whole router, every push        -- unit + most of CT
#   test         everything, no time limit           -- `main`, and locally
#
# The layer boundary is `scripts/eunit-modules.sh` for eunit/PropEr and
# `scripts/ct-suites.sh` for CT. Neither list lives here, because a list in two
# places drifts and a drifted list is a gate that quietly stops running
# something.

# %%%%% proper: property-based, on main and on request %%%%%
#
# 2 modules, 11 properties, **measured at 0.19s**. They are not in the smoke tier
# for a reason that is not their runtime: they are the layer whose value is
# statistical, so a fixed-seed failure is not reproducible by re-running the
# suite, and a random input found on a push is a bug report that arrives before
# anyone can reproduce it. They run on `main`, where a red is investigated rather
# than re-rolled, and locally by name.
#
# The count fell from 16 because five of them could not fail: `just proper`
# running 11 properties that each reject a plausible mutant is worth more than
# 16 where one is a restatement of the code it calls. #M3VTQBV is what removed
# them, and the mutants it used are in that ticket's `Solution:` comment.
#
# `just test` includes them, so "run everything" means everything.
#
# Run the property tests (2 modules, 11 properties).
proper:
    rebar3 as test eunit --module="$(bash scripts/eunit-modules.sh prop)"

# %%%%% smoke-test: every push, under five minutes %%%%%
#
# lint + the 961 unit cases + **215 of the 233 CT cases** across 23 of the 25
# suites. Measured at **~92s here** (79s CT, 10s eunit, 3s lint).
#
# **This is a partition of the tree, not a hand-picked list.** Every suite except
# the two in `slow` runs. A new suite is in tomorrow's smoke run unless someone
# deliberately puts it in `slow`, which inverts the usual failure: with a named
# list, the edit that adds a suite is the moment someone decides it does not
# matter yet.
#
# What it covers: boot, both transports, the tunnel path, SAM, streaming, the
# address book, reseed, the NetDb server, the peer lifecycle, and the read API.
# What it does not, stated rather than implied: `i2p_peer_transport_SUITE`
# (protocol-mandated connect timeouts) and `i2p_ssu2_e2e_SUITE` (22,000 real
# datagrams through a live session). Together 50s here, ~125s on a runner -- more
# than the whole budget, for two suites whose failures are about waiting rather
# than behaviour. A push that breaks one goes green here and red on `main`.
#
# Dialyzer is deliberately **not** here. It analyses source, not tests, so its
# answer does not depend on which suites ran, and 49s of a 5-minute budget is
# better spent on tests. It runs on every push in the `compat` job's shadow.
#
# The push tier: lint, the unit tests, and most of the CT suites.
smoke-test: lint
    rebar3 as test eunit --module="$(bash scripts/eunit-modules.sh unit)"
    rebar3 ct --sname i2per_ct --suite="$(bash scripts/ct-suites.sh smoke)"

# %%%%% test: everything, no time limit %%%%%
#
# lint + doc + all 972 eunit (961 unit + 11 property) + all 233 CT + the merged
# coverage report. Measured at **~4 minutes here**; `main` runs it unattended.
#
# **`--cover` on both halves, because `just cover` is the only thing that reads
# the aggregate.** Coverdata is per-`rebar3` process, so the eunit half and the CT
# half have to be produced by one run of each in the same profile to merge.
#
# Run everything: lint, docs, all eunit, all PropEr, all CT, coverage.
test: lint doc
    rebar3 as test do eunit --cover, ct --cover --sname i2per_ct
    rebar3 cover

# %%%%% The slow tier %%%%%
#
# The two suites too slow for every push: `i2p_ssu2_e2e_SUITE`, whose
# receive-window case drives 22,000 real encrypted datagrams through a live
# session pair, and `i2p_peer_transport_SUITE`, a cluster of connection-timeout
# and backoff cases. Both are protocol-mandated waiting rather than behaviour, and
# together they are ~50s here and ~125s on a runner.
#
# **For working on them, not for CI.** `main` runs them as part of `just test`;
# the point of this recipe is to run one of them alone while changing it, so a
# 20-minute feedback loop does not come from re-running 23 other suites.
#
# **No `--cover`.** Coverdata is per-`rebar3 ct`-process and this is a
# single-tier run for development, not an aggregate.

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
#
# Run the i2pd interoperability suite against a live router.
interop:
    scripts/interop_i2pd.sh

# Run SipHash micro-benchmark (pure-Erlang NTCP2 frame-length obfuscation)
bench-siphash:
    escript bench/bench_siphash.escript

# Live-network smoke: boot a throwaway router and emit the network observables
# (peers / dialed / netdb_router_info_growth / transit_relayed_tunnels) as JSON.
# Hermetic by default (self-seed, offline); pass --live for a real join from a
# routable host.
#
# **Named `live-smoke`, not `smoke`.** `smoke` reads as "the quick test tier",
# and this is the opposite: it boots a real router, and with `--live` it joins
# the real network. Two recipes where the quicker-sounding one is the dangerous
# one is how somebody runs the wrong thing in CI. Not part of `test`.
#
# Boot a throwaway router and print its network observables as JSON.
live-smoke flags="":
    escript scripts/live_smoke.escript {{flags}}

# Build the prod relx release tarball + MANIFEST into dist/ (run via devenv;
# requires rebar3/erl on PATH — see scripts/build-release.sh)
#
# Build the relx release tarball into dist/.
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

# %%%%% clean: derived state, and evidence %%%%%
#
# Two recipes, because `_build` holds two kinds of thing and only one of them is
# junk. Compiled beams are derived -- the next `just test` makes them again in
# seconds. A CT run directory is evidence: it is what you read when a suite
# fails, and `ct.latest.log` and `all_runs.html` are rewritten from whatever run
# dirs are still there. So `clean` drops the beams and the dead runs and keeps the
# last one; `clean-all` drops the lot.
#
# **`clean` reaches into the test profile, because `rebar3 clean` does not.**
# With no `--profile`, `rebar_prv_clean` hands `default` to `rebar_prv_as` and
# cleans that profile only -- so on its own it deleted 4 KB of symlinks here and
# left every test-profile beam in place. Both profiles are named explicitly,
# because a recipe called `clean` that leaves the next compile nothing to do is
# not what anyone typing it means. Deps are not named (`--all` would take them
# too): they cost a fetch, not a compile, and they are not ours.
#
# **The old runs are pruned, not all of them.** 460 `ct_run.*` directories, 7.5 GB
# here at ~90 MB each, and neither rebar3 nor CT ever deletes one, so they are the
# largest thing in the tree by an order of magnitude. The newest survives: it is
# the run being read right now, and the one the log index points at. The index's
# links to the pruned runs dangle until the next `rebar3 ct` rewrites it.
#
# **What neither recipe touches.** `dist/` -- a release tarball costs a container
# build to produce and may be about to be published. `data/` -- a router identity
# and a server-tunnel private key, so removing it means a reseed and a new
# identity, not a rebuild. `.devenv` -- that is the toolchain, not this project's
# output, and it costs more to rebuild than everything these two recipes delete.

# Drop the beams and the dead CT runs, keeping the newest run and the coverage.
clean:
    rebar3 clean
    rebar3 as test clean
    ls -dt _build/test/logs/ct_run.* 2>/dev/null | tail -n +2 | xargs rm -rf
    rm -rf *dump

# Drop everything derived: `_build` whole -- beams, every CT run, the coverdata,
# the PLT -- plus the generated ExDoc site and any crash dump. `just compile` and
# `just doc` bring the tree back; `just dialyzer` rebuilds the PLT, which is the
# slow part of the rebuild and the reason this is not the everyday recipe.
# Wipe every derived thing: `_build`, the generated docs, and any crash dump.
clean-all:
    rm -rf _build
    rm -rf doc
    rm -rf *dump

# %%%%% gh: authenticate, once %%%%%
#
# The only `gh` command a human runs. Everything after it is agent-driven and
# has no tty.
#
# **`TERM` is pinned for this one command.** gh asks the terminal for its
# background colour (OSC 11) when it styles output; a terminal that answers
# leaks the reply into the tty input queue, where it surfaces as junk at the
# prompt and swallows the keystrokes typed next. muesli/termenv skips the query
# when TERM begins with "screen", "tmux" or "dumb", and keeps 256-colour output
# for anything containing "256color", which "dumb" would not. So this is the same
# value the old `gh()` wrapper in devenv.nix used -- scoped to the one command
# that is interactive, rather than to every `gh` in every shell.
#
# **That scoping is the fix, not a narrowing.** The wrapper was a shell function
# exported with `export -f`, which cannot survive direnv: `direnv export` drops
# it, and zsh has no `export -f` at all, so `type gh` reported the bare binary in
# every zsh session. An env var on the one interactive command has no such
# problem -- there is no shell function to lose in the handoff.
#
# Nothing else needs the pin. The agents' `gh` calls are non-interactive with no
# tty, so there is no terminal to query and no input queue to corrupt.
#
# The token lands in ~/.config/gh/hosts.yml, so this is once per machine.
#
# Authenticate gh against github.com.
gh-login flags="":
    TERM=screen-256color gh auth login {{flags}}
    gh auth status

# Show jujutsu status
status:
    jj status

# Create a new commit with jj
commit message:
    jj commit -m "{{message}}"

# Run all quality checks: formatting, generated documentation, and every test.
#
# **An alias for `test`, kept because the release notes, the ADRs and the README
# all say `just check`.** Renaming it would mean editing every one of those for
# no gain, and two names for one command is cheaper than a stale reference to a
# name that no longer exists. `test` is the primary spelling because that is what
# the recipe *does*.
# Run all quality checks: formatting, docs, and every test.
check: lint doc test
