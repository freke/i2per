#!/usr/bin/env bash
# Print the CT suites in one tier, comma-separated, for `rebar3 ct --suite=`.
#
#   smoke   every push: as much of the router as fits a five-minute CI budget.
#           Deliberately a *partition of the tree*, not a hand-picked list, so a
#           new suite is in tomorrow's smoke run by default.
#   rest   every suite except the slow ones. Main only.
#   slow   the slow ones, alone. For working on them, not for CI.
#   all    every suite, no partition, no time limit. Main only.
#
# One script rather than a list in the justfile *and* a list in the workflow,
# because the two would drift and a drifting partition is a gate that quietly
# stops running something.
#
# **Derived from the tree, not enumerated.** `smoke`, `rest` and `all` are
# whatever is in a `test/` directory now, so a suite added tomorrow is in
# tomorrow's `smoke` without anyone editing this file. Only `slow` is an explicit
# list, because naming what is *too slow for every push* is a decision that
# should be reviewable.

# %%%%% Nothing here may need i2pd %%%%%
#
# `apps/i2per/interop/i2p_i2pd_interop_SUITE` matches `*_SUITE.erl` and is NOT
# here. It is excluded twice over, deliberately:
#
#   1. by the `apps -path '*/test/*_SUITE.erl'` scope below -- rebar3 discovers
#      suites in `test/` directories only, so it has never run this suite either;
#   2. by `assert_hermetic` below, which fails if any tier ever names it.
#
# That suite boots a **live i2pd** and talks to a routable network. The gate is
# hermetic and stays that way: it runs no external router, needs no network, and
# cannot be made to hang on someone else's daemon. For the interoperability check
# run `just interop` locally -- deliberately not a CI job, and deliberately not a
# `workflow_dispatch` one either, because a suite that needs the network is a
# suite whose failure means nothing when the network is what broke.

set -euo pipefail

cd "$(dirname "$0")/.."

# %%%%% The push tier: `smoke` %%%%%
#
# **Every suite except `slow`.** The reasoning is the opposite of a hand-picked
# list: a named list has to be edited every time a suite is added, and the edit
# is the moment someone decides the new suite does not matter yet. Deriving the
# tier from the tree inverts that -- a new suite is *in* the smoke run unless
# someone deliberately puts it in `slow`.
#
# What that buys is coverage of the whole router: boot, both transports, the
# tunnel path, SAM, streaming, the address book, reseed, the NetDb server and the
# peer lifecycle all run on every push. Measured **~44s** of CT time here, which
# is ~110s on a runner against the 5-minute budget -- see the note in
# `.github/workflows/gate.yml` for the arithmetic and the margin.
#
# **What it does not run, stated rather than implied.** The two `slow` suites:
# `i2p_peer_transport_SUITE` (protocol-mandated connect timeouts and backoff) and
# `i2p_ssu2_e2e_SUITE` (22,000 real encrypted datagrams through a live session
# pair). Together they are 50s here and ~125s on a runner -- more than the whole
# budget, for two suites whose failures are about waiting rather than about
# behaviour. A push that breaks one of them goes green here and red on `main`.
# That is the price of a five-minute signal, and it is paid deliberately.

# `i2p_ssu2_e2e_SUITE`'s receive-window case drives 22,000 real encrypted
# datagrams through a live session pair. `i2p_peer_transport_SUITE` is a cluster
# of connection-timeout and backoff cases: protocol-mandated waits, several of
# them over ten seconds each.
#
# **This is the only explicit list in the file**, and it is explicit because
# "too slow to run on every push" is a judgement about wall-clock budget rather
# than about what the code is, and a judgement like that belongs somewhere a
# reader can argue with. `assert_present` below fails if a name here is not in
# the tree, so a suite renamed or deleted cannot leave this quietly naming
# nothing.
read -r -d '' SLOW <<'EOF' || true
apps/i2per/test/i2p_ssu2_e2e
apps/i2per/test/i2p_peer_transport
EOF

# Canonical form `find` yields -- `_SUITE.erl` already stripped -- so the lists
# above can be matched against the tree directly.
suites() {
    find apps -path '*/test/*_SUITE.erl' \
        | sed 's|_SUITE\.erl$||' \
        | sort
}

# Every tier is hermetic. A widened glob would otherwise put a live-network suite
# into the gate silently, and it would only be noticed the first time CI hung.
#
# Canonical paths in, `--suite=`-ready paths out. Args are folded to a string
# first: `sed` and `paste` read stdin, so passing the list as arguments and
# piping nothing emits a single empty suite.
emit() {
    local body
    body=$(printf '%s\n' "$@")

    if printf '%s\n' "$body" | grep -qiE 'interop|i2pd'; then
        echo "ct-suites.sh: refusing to emit a suite that needs a live i2pd:" >&2
        printf '%s\n' "$body" | grep -iE 'interop|i2pd' | sed 's|^|  |' >&2
        echo "  The gate runs no external router. Take it out of the tier." >&2
        exit 1
    fi

    printf '%s\n' "$body" | sed 's|$|_SUITE|' | paste -sd, -
}

# A named suite must exist, or the tier would quietly run one suite fewer than it
# claims -- which is how a suite goes untested without anyone noticing.
assert_present() {
    local tree="$1" name="$2"
    if ! printf '%s\n' "$tree" | grep -qxF "$name"; then
        echo "ct-suites.sh: suite not found in the tree: $name" >&2
        exit 1
    fi
}

tree=$(suites)

# Everything that is not slow. The one derived partition, so `smoke`, `rest` and
# any future name for it cannot disagree.
not_slow() {
    printf '%s\n' "$tree" | grep -vxF "$SLOW" || true
}

assert_slow_present() {
    local suite
    while IFS= read -r suite; do
        assert_present "$tree" "$suite"
    done <<<"$SLOW"
}

case "${1:-all}" in
    smoke|rest)
        assert_slow_present
        body=$(not_slow)
        if [ -z "$body" ]; then
            echo "ct-suites.sh: '$1' is empty -- is the whole tree the slow tier?" >&2
            exit 1
        fi
        emit $body
        ;;
    slow)
        assert_slow_present
        emit $SLOW
        ;;
    all)
        emit $tree
        ;;
    *)
        echo "usage: ct-suites.sh [smoke|rest|slow|all]" >&2
        exit 2
        ;;
esac