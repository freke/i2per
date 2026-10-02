#!/usr/bin/env bash
# Print the EUnit/PropEr module split, for `rebar3 eunit --module=`.
#
#   unit    every `*_tests.erl` that is NOT a property module. The fast layer.
#   prop    every `*_prop_tests.erl`. The slow layer: randomised, and run only
#           on `main` or when someone asks for it by name.
#   all     both, which is what the tree contains.
#
# One script rather than a list in the justfile *and* a list in the workflow,
# because two copies of a partition drift, and a drifted partition is a gate
# that quietly stops running something. This is the same argument as
# `scripts/ct-suites.sh` next to it, for the same layer it covers.
#
# %%%%% Why the split is by filename, not by content %%%%%
#
# A property test and a unit test differ in *how many inputs they run*, not in
# what they call -- both call one function and assert on what comes back. So
# there is nothing in the source to classify on; the convention has to live in
# the name, and `_prop_tests` is it. A property module that does not match the
# convention silently becomes part of the fast tier, which is why `check_prop`
# asserts the naming rather than trusting it: see the guard below.
#
# %%%%% Nothing here needs i2pd %%%%%
#
# These are all in-process. `apps/i2per/interop/` holds the live-router suite
# and matches neither pattern, so it cannot reach here.

set -euo pipefail

cd "$(dirname "$0")/.."

# Every eunit-discoverable test module, as a bare module name.
#
# `find`, not a glob, so a suite added tomorrow is in tomorrow's list without
# anyone editing this file. `sort` for a stable order, which keeps the emitted
# string deterministic and the diff of two runs readable.
#
# **The basename, not the path.** `rebar3 eunit --module=` resolves against the
# compiled code path and answers "not found in project" for a path; `ct-suites.sh`
# emits paths because `--suite=` wants them. Two neighbouring scripts emitting two
# different forms is deliberate, and this note is here so it does not read as an
# inconsistency to be tidied away.
#
# **Only the extension is stripped, not the `_tests` suffix.** Stripping `_tests`
# as well would turn `i2p_ecies_prop_tests` into `i2p_ecies_prop` -- a module
# that does not exist, and whose name no longer says which layer it is in.
modules() {
    find apps -path '*/test/*_tests.erl' \
        | xargs -n1 basename \
        | sed 's|\.erl$||' \
        | sort -u
}

# Property modules, by the `_prop_tests` convention.
props() {
    modules | grep '_prop_tests$'
}

# Everything that is not a property module.
units() {
    modules | grep -v '_prop_tests$'
}

emit() {
    local body
    body=$(printf '%s\n' "$@")
    [ -n "$body" ] || {
        echo "eunit-modules.sh: empty module set -- is the tree missing tests?" >&2
        exit 1
    }
    # Guard the convention: a property test in a module not named `_prop_tests`
    # would run in the fast tier with randomised inputs and a fixed numtests,
    # which is the failure mode the split exists to prevent. A file that says
    # `proper:` but is not named for it is reported rather than guessed at.
    #
    # Both sides are bare module names, which is what `modules/0` yields and what
    # the grep produces after the same basename-and-extension strip.
    local unlabelled
    unlabelled=$(
        comm -13 \
            <(props | sort) \
            <(grep -rl 'proper:' apps --include='*_tests.erl' 2>/dev/null \
                | xargs -n1 basename | sed 's|\.erl$||' | sort -u) \
            || true
    )
    if [ -n "$unlabelled" ]; then
        echo "eunit-modules.sh: modules calling proper: but not named *_prop_tests:" >&2
        printf '%s\n' "$unlabelled" | sed 's|^|  |' >&2
        echo "  Rename them, or they run in the fast tier as fixed-seed unit tests." >&2
        exit 1
    fi
    printf '%s\n' "$body" | paste -sd, -
}

case "${1:-unit}" in
    unit) emit $(units) ;;
    prop) emit $(props) ;;
    all)  emit $(modules) ;;
    *)
        echo "usage: eunit-modules.sh [unit|prop|all]" >&2
        exit 2
        ;;
esac