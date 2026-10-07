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
#
# %%%%% And two things deliberately outside all three %%%%%
#
# **`live-smoke` and `soak` are diagnostics, not tiers.** Neither is in
# `smoke-test`, `test` or `check`, and the reason is a stability claim neither
# can support: `live-smoke` boots a real router and with `--live` joins the real
# network, and `soak` reports on a bounded window of a router's own growth. A
# tier is a claim about what is *known good*; a window in which nothing grew that
# we can see is not that, and promoting either into the gate would make a green
# run assert a stability the window cannot reach. They are run by name, on
# purpose -- and `soak` exiting non-zero when its instrument cannot demonstrate it
# detects a known fault is a reason to run it, not a reason to make it a gate.

# %%%%% proper: property-based, on main and on request %%%%%
#
# Sub-second in practice, and deliberately **not in the smoke tier** for a
# reason that is not their runtime: they are the layer whose value is
# statistical, so a fixed-seed failure is not reproducible by re-running the
# suite, and a random input found on a push is a bug report that arrives before
# anyone can reproduce it. They run on `main`, where a red is investigated rather
# than re-rolled, and locally by name.
#
# This tier shrank because five properties could not fail: a property module set
# where each one rejects a plausible mutant is worth more than a larger set where
# one is a restatement of the code it calls. #M3VTQBV is what removed them, and
# the mutants it used are in that ticket's `Solution:` comment. **How many there
# are now is a property of the tree, not a fact to record here** — `rebar3` prints
# the total on every run, and `bash scripts/eunit-modules.sh prop` prints the
# module list, so a number in this comment would be a second copy that no run
# checks. #STMC7NC removed them.
#
# `just test` includes them, so "run everything" means everything.
#
# Run the property modules `scripts/eunit-modules.sh prop` finds.
proper:
    rebar3 as test eunit --module="$(bash scripts/eunit-modules.sh prop)"

# %%%%% smoke-test: every push, under five minutes %%%%%
#
# lint + every unit module + **every CT suite except the two in `slow`**.
# Measured at **~92s here** (79s CT, 10s eunit, 3s lint) — a wall-clock claim
# about the budget, not a count, and the one number here that cannot be derived
# by a script. `rebar3` prints the case totals it actually ran.
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
# The push tier: lint, the unit tests, and every CT suite but the slow two.
smoke-test: lint
    rebar3 as test eunit --module="$(bash scripts/eunit-modules.sh unit)"
    rebar3 ct --sname i2per_ct --suite="$(bash scripts/ct-suites.sh smoke)"

# %%%%% test: everything, no time limit %%%%%
#
# lint + doc + **every** eunit module, unit and property + **every** CT suite +
# the merged coverage report. Measured at **~4 minutes here**; `main` runs it
# unattended. The case totals are printed by `rebar3` on every run, which is why
# none of them is written down here.
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

# %%%%% soak: bounded load, and a verdict about what the numbers support %%%%%
#
# Like `live-smoke`, and for the same reason, this is a diagnostic and not a tier:
# it is not in `smoke-test`, `test` or `check`, and the reason is in the tier note
# at the top of this file.
#
# **Every parameter is named and bounded, and none has a default chosen for you.**
# `--rate` outside 1..20000 is refused rather than clamped, because a clamped
# rate would let you believe you asked for a million events a second and got the
# ceiling. An unbounded generator measures the generator: the first version of
# this harness offered bursts separated by `erlang:yield/0`, drove refc binaries
# to 11 GB in under ten seconds, and reported a number that had nothing to do with
# the router.
#
# What it reports, and what each part is for:
#
#   self_checks  Three faults are seeded into the node and the harness has to
#                notice each one. A run whose instrument cannot demonstrate it
#                detects a known fault has measured nothing, so a failed check
#                fails the run -- non-zero exit -- rather than annotating it.
#   verdict      traffic_proportional, traffic_independent, or inconclusive.
#                It cannot say "leak": two snapshots cannot show a structure is
#                unbounded, and a slope is a slope. It classifies on **retained
#                memory**, not reductions -- reductions are monotonic, so a
#                reduction-based classifier can never reach its negative branch
#                and would answer `traffic_independent` every single run.
#   fixture_delta  Processes left behind by the reconnect cycle. 0 is the only
#                passing answer. `restart => temporary` children are never reaped
#                by their supervisor, so a reconnect that opens a fresh child
#                without stopping the old one leaks the subtree -- measured here at
#                2 processes per cycle.
#
# What it does **not** exercise is stated in `m:i2p_soak`'s module doc rather
# than implied: not the tunnel or transit paths under real load (#KF1MX96), not
# live-network behaviour without `--live`, and not crash recovery.
#
# **The knobs are top-level `:=` variables, not recipe parameters**, because just
# cannot override a recipe parameter from the command line -- `just soak
# rate=2000` silently passes the literal string `rate=2000` as a positional
# argument, and the run then dies in the parser. Variables *before* the recipe name
# are the spelling that works, and it is worth the extra lines to have a knob that
# is actually a knob:
#
#   just soak
#   just soak_rate=2000 soak_window=60000 soak
#
# Extra escript flags go through `flags=` as **one quoted argument**. `just soak
# --live` fails (`justfile does not contain recipe --live`), and `--` is not a
# passthrough here either; what works is:
#
#   just soak "--live"
#
# Soak a throwaway router: `just soak`, or `just soak_rate=2000 soak`.
soak flags="":
    escript scripts/soak.escript --window {{soak_window}} --quiet {{soak_quiet}} --rate {{soak_rate}} --burst {{soak_burst}} --cycles {{soak_cycles}} --port {{soak_port}} {{flags}}

# %%%%% soak-tunnel: the tunnel and transit paths, that #KF1MX96 opened %%%%%
#
# The counterpart to `just soak`. The existing soak reported flat retention in a
# run where **every tunnel counter read zero**; this one builds real inbound and
# outbound tunnels and relays real transit frames, and refuses to pass when those
# counters do not move. Same discipline: a diagnostic, not a tier; every knob
# named and bounded; refused rather than clamped when out of bounds.
#
#   just soak-tunnel
#   just soak_tunnel_window=60000 soak_tunnel_phases=4 soak-tunnel
soak-tunnel flags="":
    escript scripts/soak_tunnels.escript --warm {{soak_tunnel_warm}} --window {{soak_tunnel_window}} --quiet {{soak_tunnel_quiet}} --phases {{soak_tunnel_phases}} --rate {{soak_tunnel_rate}} --burst {{soak_tunnel_burst}} --hops {{soak_tunnel_hops}} --port {{soak_tunnel_port}} --top {{soak_tunnel_top}} {{flags}}

# The tunnel soak's parameters, as overridable variables.
soak_tunnel_warm := "10000"
soak_tunnel_window := "10000"
soak_tunnel_quiet := "4000"
soak_tunnel_phases := "3"
soak_tunnel_rate := "50"
soak_tunnel_burst := "10"
soak_tunnel_hops := "3"
soak_tunnel_port := "39447"
soak_tunnel_top := "5"

# The soak's parameters, as overridable variables. Named for the escript's flags
# and kept next to the recipe so the two cannot drift.
soak_window := "15000"
soak_quiet := "5000"
soak_rate := "500"
soak_burst := "50"
soak_cycles := "5"
soak_port := "39446"

# Build the prod relx release tarball + MANIFEST into dist/ (run via devenv;
# requires rebar3/erl on PATH — see scripts/build-release.sh)
#
# Build the relx release tarball into dist/.
release:
    bash scripts/build-release.sh

# %%%%% dialyzer: static analysis, and a release gate %%%%%
#
# **In `just check` as well as runnable alone**, because it used to be reachable
# only by name while the README, the release notes and the map's Notes all listed
# it as a gate. A check named `check` that skips one of the three static checks is
# a gate whose coverage a reader has to guess at. See the note on `check` for why
# it is ordered before `test`.
#
# **The `warnings` list is deliberately narrow** — `unmatched_returns`,
# `error_handling`, `underspecs` — and **not** `unknown`. `unknown` is what the
# core's cross-application calls would trip on any time a dependency is not in the
# PLT, so the gate would fail on a well-typed call rather than on a defect, and a
# gate that reports a lie is worse than an absent one. `plt_extra_apps` is what
# keeps a real dependency analysable instead.
#
# Run static analysis (~49s here, cached against the PLT after the first run).
dialyzer:
    rebar3 dialyzer

# Format the code with erlfmt
format:
    erlfmt -w apps/*/src/*.erl apps/*/test/*.erl

# Lint the code (check formatting)
lint:
    erlfmt -c apps/*/src/*.erl apps/*/test/*.erl

# Generate the umbrella ExDoc site into `doc/` (also run by `check`).
#
# **This step can fail, and it used not to.** `scripts/gen-docs.sh` passes ExDoc
# `--warnings-as-errors`; ExDoc otherwise prints a `warning:` per dead
# documentation reference and still exits 0, so this recipe once reported four
# of them and returned success — a gate reporting a defect in its own subject.
# #STMC7NC is what made it a gate.
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

# Run all quality checks: formatting, generated docs, dialyzer, and every test.
#
# **An alias for `test` plus `dialyzer`, kept because the release notes, the ADRs
# and the README all say `just check`.** Renaming it would mean editing every one
# of those for no gain, and two names for one command is cheaper than a stale
# reference to a name that no longer exists. `test` is the primary spelling
# because that is what the recipe *does*.
#
# **Dialyzer is here, and it used not to be.** `check` was `lint doc test` and
# `test` was `lint doc` + eunit + CT, so nothing reachable from `check` invoked
# dialyzer at all -- a recipe named `check` that skipped one of the three static
# checks, while the README and the release notes listed it as a gate. The cost of
# naming it was that a `plt_extra_apps` entry could be deleted and `check` would
# stay green while dialyzer went red: the PLT is built from this project's own
# applications, so a dep the core calls into becomes an unknown function, and only
# the analysis says so.
#
# **Ordered before `test` deliberately.** Dialyzer reads source and does not depend
# on which suites ran, so it can answer first and fail a run before the ~4 minutes
# of eunit and CT spend themselves on a build that was never going to be analysed
# anyway. It costs ~49s here against `test`'s ~4 minutes.
#
# Run all quality checks: formatting, docs, dialyzer, and every test.
check: lint doc dialyzer test
