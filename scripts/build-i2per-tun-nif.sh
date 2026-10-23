#!/usr/bin/env bash
# Build the i2per_tun Rust NIF into the app's priv/ directory.
#
#   scripts/build-i2per-tun-nif.sh
#
# Called as a rebar3 compile pre_hook of apps/i2per_tun (see that
# rebar.config). Cargo and `erl` must be on PATH: rustler_sys's build.rs reads
# the local OTP headers through `erl`, which is what pins the NIF ABI to the
# Erlang installation it is built against.
#
# **A missing cargo skips, a failing cargo fails.** The OTP-compat job in
# `.github/workflows/gate.yml` compiles the tree with setup-beam and no
# devenv, so it has no cargo; the Erlang tree must stay compilable without
# the NIF. But a cargo that exists and fails is a broken NIF, and a silently
# absent NIF surfaces as a load failure far from its cause — so that path is
# a hard error.
set -euo pipefail

cd "$(dirname "$0")/.."

CRATE=apps/i2per_tun/native/i2per_tun_nif
SO="$CRATE/target/release/libi2per_tun_nif.so"
DEST=apps/i2per_tun/priv

if ! command -v cargo >/dev/null 2>&1; then
    echo "build-i2per-tun-nif.sh: cargo not on PATH — skipping the i2per_tun NIF (Erlang-only compiles stay green; running the app needs the NIF)"
    exit 0
fi

cargo build --release --manifest-path "$CRATE/Cargo.toml"

if [ ! -f "$SO" ]; then
    echo "build-i2per-tun-nif.sh: cargo produced no $SO" >&2
    exit 1
fi

mkdir -p "$DEST"
cp "$SO" "$DEST/i2per_tun_nif.so"
