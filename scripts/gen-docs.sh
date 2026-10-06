#!/usr/bin/env bash
# Build the i2per umbrella ExDoc site into the repo-root `doc/`.
#
# ExDoc renders one merged site covering BOTH OTP apps in this umbrella
# (the `i2per` core router and the standalone `i2per_status` web service),
# plus the README and the docs/ extras, with mermaid diagrams wired in via
# `docs/docs.exs`. Run through `just doc`.
#
# Requires: rebar3 (for compile + the bundled ExDoc escript via rebar3_ex_doc).
#
# %%%%% Why `--warnings-as-errors` is here %%%%%
#
# ExDoc prints a `warning:` for every documentation reference that resolves to
# nothing — a `t:foo/0` that is not a type, an `m:bar` that is not a module —
# and **still exits 0**. A docs step whose whole job is to catch malformed
# documentation attributes therefore reported four of them and returned success,
# which is the same failure the tree calls out everywhere else: a gate that
# cannot fail is not a gate. The flag turns ExDoc's own warning stream into a
# non-zero exit, so the docs build fails on a dead cross-reference.
#
# It is a flag on the ExDoc invocation rather than a grep over its output
# because ExDoc already knows which of its messages are warnings; re-deriving
# that from text would be a second, worse copy of the same judgement.
#
# **The site's own extras are checked too**, not only the module docs, since the
# README and `docs/` extras go through the same autolinker.

set -euo pipefail

# Repo root: parent of the directory holding this script.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROJECT_NAME="i2per"
VERSION="0.1.0"
EBI_I2PER="${EBI_I2PER:-_build/default/lib/i2per/ebin}"
EBI_STATUS="${EBI_STATUS:-_build/default/lib/i2per_status/ebin}"
CONFIG="docs/docs.exs"
OUT="doc"

# Locate the ExDoc escript that rebar3_ex_doc bundles (one per OTP release).
# Mirror the plugin's compatibility fallback: pick the highest available
# `ex_doc_otp_*` (the plugin accepts up to 3 OTP versions back).
find_exdoc() {
    local found
    found="$(find _build -type f -path '*/plugins/rebar3_ex_doc/priv/ex_doc_otp_*' -print 2>/dev/null | sort -V | tail -n1 || true)"
    if [[ -z "$found" ]]; then
        echo "ExDoc escript not found (rebar3_ex_doc plugin priv). Run 'rebar3 plugins upgrade rebar3_ex_doc'." >&2
        exit 1
    fi
    echo "$found"
}

# Make sure both apps are compiled so their .beam files are present.
rebar3 compile >/dev/null

EX_DOC="$(find_exdoc)"
echo "Using ExDoc escript: $EX_DOC"
echo "Generating umbrella docs -> $OUT (${PROJECT_NAME} ${VERSION})"

"$EX_DOC" "$PROJECT_NAME" "$VERSION" "$EBI_I2PER" "$EBI_STATUS" \
    --proglang erlang \
    --config "$CONFIG" \
    --warnings-as-errors \
    --output "$OUT"

echo "Docs written to $OUT/"
