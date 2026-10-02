#!/usr/bin/env bash
# Print the CT suites in one tier, comma-separated, for `rebar3 ct --suite=`.
#
#   fast   the PR tier: the few suites that catch what eunit cannot
#   rest   every suite except the slow ones. Main only.
#   slow   the slow ones, alone. Main only.
#   all    every suite, no partition. Main only.
#
# One script rather than a list in the justfile *and* a list in the workflow,
# because the two would drift and a drifting partition is a gate that quietly
# stops running something.
#
# **Derived from the tree, not enumerated.** `rest` and `all` are whatever is in
# a `test/` directory now, so a suite added tomorrow is in tomorrow's `rest`
# without anyone editing this file. Only `fast` and `slow` are explicit lists,
# because choosing what runs on every PR is a decision and should be reviewable.

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

# The PR tier. Each suite earns its place by covering something eunit
# structurally cannot: the real supervision tree, configuration, the 0.2.0 read
# contract, the tunnel path end to end, and NTCP2 *or* SSU2, so a change breaking
# either transport cannot pass a PR.
#
# **What this tier does not run, so it is not mistaken for the gate.** No SAM, so
# the client-facing path is unchecked on a PR. No streaming, addressbook, reseed,
# netdb-srv, or peer-lifecycle suites. And not `i2p_ssu2_e2e_SUITE`. A PR that
# breaks one of those merges green and turns main red -- which is what a
# one-minute signal costs. Chosen deliberately, not arrived at by accident: the
# alternative was a ten-minute PR signal, which is the same gate arriving later.
#
# **`i2p_ssu2_handshake_SUITE` is in both `fast` and `slow`, deliberately.** It is
# the cheap SSU2 check -- the handshake, without the 22,000-datagram receive-window
# case -- so it is exactly what a PR needs and exactly what must not cost a PR its
# ten minutes. Since `fast` runs only on pull requests and `slow` only on `main`,
# no run ever executes it twice. `fast` is therefore a subset of `all`, but *not* of
# `rest`, and anything checking the partition should check that rather than assume
# a tier nesting.
read -r -d '' FAST <<'EOF' || true
apps/i2per/test/i2p_boot
apps/i2per/test/i2p_config_srv
apps/i2per/test/i2p_ntcp2_conn
apps/i2per/test/i2p_read_api
apps/i2per/test/i2p_ssu2_handshake
apps/i2per/test/i2p_tunnel_srv
EOF

# `i2p_ssu2_e2e_SUITE`'s receive-window case drives 22,000 real encrypted
# datagrams through a live session pair. Measured **8m18s** on a runner, alone --
# more than every other CT suite put together. Main only.
read -r -d '' SLOW <<'EOF' || true
apps/i2per/test/i2p_ssu2_e2e
apps/i2per/test/i2p_ssu2_handshake
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

case "${1:-all}" in
    fast)
        while IFS= read -r suite; do
            assert_present "$tree" "$suite"
        done <<<"$FAST"
        emit $FAST
        ;;
    slow)
        while IFS= read -r suite; do
            assert_present "$tree" "$suite"
        done <<<"$SLOW"
        emit $SLOW
        ;;
    rest)
        while IFS= read -r suite; do
            assert_present "$tree" "$suite"
        done <<<"$SLOW"
        rest=$(printf '%s\n' "$tree" | grep -vxF "$SLOW" || true)
        if [ -z "$rest" ]; then
            echo "ct-suites.sh: 'rest' is empty -- is the whole tree the slow tier?" >&2
            exit 1
        fi
        emit $rest
        ;;
    all)
        emit $tree
        ;;
    *)
        echo "usage: ct-suites.sh [fast|rest|slow|all]" >&2
        exit 2
        ;;
esac