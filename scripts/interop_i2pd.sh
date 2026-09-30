#!/usr/bin/env bash
# Run the gated NTCP2 + SSU2 interop Common Test suite against a real i2pd.
#
# Boots a throwaway i2pd 2.61.0 (nixpkgs) with NTCP2 and SSU2 enabled on
# 127.0.0.1, waits for its RouterInfo / keys / listeners, then runs the
# interop suite (apps/i2per/interop/i2p_i2pd_interop_SUITE.erl) against it and
# cleans up.
#
# It also boots a *second*, isolated i2pd on NTCP2 only (I2P_RESPONDER_PORT,
# default 39233) to play the initiator against our responder: the suite pushes
# our floodfill RouterInfo to it as Alice, drops the session, and i2pd dials
# us back (RouterInfo publication / NetDb profiling / floodfill lookups). That
# second instance gets a fresh, uncached datadir with reseed suppressed, so it
# is fully offline.
#
# Requires: an i2pd binary. Set I2PD_BIN if it is not on PATH (nix build
# nixpkgs#i2pd -o ./i2pd-out; I2PD_BIN=./i2pd-out/bin/i2pd).
#
# The first instance reseeds its network database over HTTPS on a fresh
# datadir, which can make the first boot slow or fail offline, so the script
# caches its netDb between runs (I2P_NETDB_CACHE, default /tmp/i2per-interop-netdb)
# and seeds the throwaway datadir from it. With >= 25 routers cached, i2pd
# skips reseed entirely and starts in ~2 s, network-independent. First ever run
# with no cache still needs a live network for the reseed.
#
# The interop suite verifies our pure-Erlang NTCP2 XK handshake against the
# real responder: msg1 -> msg2 -> msg3, then a data-phase frame i2pd must
# decrypt and MAC-verify. The primary i2pd is configured as a firewalled
# client (`reservedrange = true`, `ntcp2.published = false`) so the test
# exercises the real non-published RouterInfo shape. The second responder
# instance remains published because it must accept our loopback floodfill
# RouterInfo and dial us back.
#
# This suite is excluded from `just check` because it does not live in an app's
# test/ directory, which is the only place rebar3 auto-discovers suites from;
# the `--suite` here names it explicitly, and missing env vars fail the cases
# loudly instead of passing trivially.

set -euo pipefail

I2PD_BIN="${I2PD_BIN:-$(command -v i2pd || true)}"
if [[ -z "${I2PD_BIN}" ]]; then
    echo "i2pd not found: set I2PD_BIN to the i2pd binary" >&2
    exit 1
fi

PORT="${I2P_INTEROP_PORT:-39223}"
SSU2_PORT="${I2P_INTEROP_SSU2_PORT:-39224}"
RESP_PORT="${I2P_RESPONDER_PORT:-39233}"
DATA="$(mktemp -d /tmp/i2per-interop-XXXXXX)"
RESP_DATA="$(mktemp -d /tmp/i2per-interop-resp-XXXXXX)"
CACHE="${I2P_NETDB_CACHE:-/tmp/i2per-interop-netdb}"
CONF="${DATA}/i2pd.conf"
LOG="${DATA}/i2pd.log"
RESP_CONF="${RESP_DATA}/i2pd.conf"
RESP_LOG="${RESP_DATA}/i2pd.log"

# Seed the fresh datadir's netDb so i2pd skips the (network-bound) reseed.
if [[ -d "${CACHE}/netDb" ]] && find "${CACHE}/netDb" -name '*.dat' 2>/dev/null | grep -q .; then
    mkdir -p "${DATA}/netDb"
    cp -r "${CACHE}/netDb/." "${DATA}/netDb/"
fi

cat >"${CONF}" <<EOF
log = stdout
loglevel = info
datadir = ${DATA}
port = ${PORT}
host = 127.0.0.1
ipv6 = false
netid = 2
reservedrange = true
ntcp2.enabled = true
ntcp2.port = ${PORT}
ntcp2.published = false
ntcp2.version = 2
ssu2.enabled = true
ssu2.port = ${SSU2_PORT}
ssu2.published = true
http.enabled = false
httpproxy.enabled = false
socksproxy.enabled = false
upnp.enabled = false
sam.enabled = false
bob.enabled = false
EOF

# The responder i2pd: NTCP2 only, SSU2 off so every dial reaches our pump over
# the deterministic transport. The bogus reseed URL fails instantly and, with
# reseed.threshold = 0, i2pd never bootstraps from the network — it comes up
# empty and harmless offline (it retries the localhost URL a few times before
# giving up and starting transports, ~3 min, hence the generous wait below).
cat >"${RESP_CONF}" <<EOF
log = stdout
loglevel = info
datadir = ${RESP_DATA}
port = ${RESP_PORT}
host = 127.0.0.1
ipv6 = false
netid = 2
reservedrange = false
ntcp2.enabled = true
ntcp2.port = ${RESP_PORT}
ntcp2.published = true
ntcp2.version = 2
ssu2.enabled = false
reseed.threshold = 0
reseed.urls = http://127.0.0.1:9/seed.su3
http.enabled = false
httpproxy.enabled = false
socksproxy.enabled = false
upnp.enabled = false
sam.enabled = false
bob.enabled = false
EOF

cleanup() {
    # Preserve the (grown) netDb for the next run, then kill both our i2pd
    # instances by their datadirs to avoid touching any other instance. The
    # responder datadir is deliberately disposable — it must stay isolate.
    if [[ -d "${DATA}/netDb" ]]; then
        mkdir -p "${CACHE}"
        rm -rf "${CACHE}.old"
        [[ -d "${CACHE}/netDb" ]] && mv "${CACHE}/netDb" "${CACHE}.old"
        cp -r "${DATA}/netDb" "${CACHE}/netDb" 2>/dev/null || {
            [[ -d "${CACHE}.old" ]] && mv "${CACHE}.old" "${CACHE}/netDb"
        }
        rm -rf "${CACHE}.old"
    fi
    pkill -f "${DATA}" 2>/dev/null || true
    pkill -f "${RESP_DATA}" 2>/dev/null || true
}
trap cleanup EXIT

"${I2PD_BIN}" --datadir "${DATA}" --conf "${CONF}" >"${LOG}" 2>&1 &
"${I2PD_BIN}" --datadir "${RESP_DATA}" --conf "${RESP_CONF}" >"${RESP_LOG}" 2>&1 &

echo "i2pd: ${I2PD_BIN} (ntcp2 tcp ${PORT}, ssu2 udp ${SSU2_PORT})"
echo "datadir: ${DATA}"
echo "log: ${LOG}"
echo "responder i2pd: (ntcp2 tcp ${RESP_PORT}, ssu2 off)"
echo "responder datadir: ${RESP_DATA}"
echo "responder log: ${RESP_LOG}"

# Wait for the RouterInfo, keys, and both listeners (signalled in the log by
# "Start listening"). Do not probe the TCP port directly: a bare connect looks
# like a broken SessionRequest and makes i2pd drop our real connection.
for _attempt in $(seq 1 240); do
    if [[ -f "${DATA}/router.info" && -f "${DATA}/ntcp2.keys" && -f "${DATA}/ssu2.keys" ]] \
        && { grep -q "Start listening v4 TCP port ${PORT}" "${LOG}" \
            || grep -q "Accepting incoming connections at port ${PORT}" "${LOG}"; } \
        && grep -q "Start listening on 0.0.0.0:${SSU2_PORT}" "${LOG}"; then
        break
    fi
    if ! kill -0 "$(pgrep -f "${DATA}" | head -1)" 2>/dev/null; then
        echo "i2pd exited early:" >&2
        tail -20 "${LOG}" >&2
        exit 1
    fi
    sleep 0.5
done

if ! { grep -q "Start listening v4 TCP port ${PORT}" "${LOG}" \
    || grep -q "Accepting incoming connections at port ${PORT}" "${LOG}"; } \
    || ! grep -q "Start listening on 0.0.0.0:${SSU2_PORT}" "${LOG}"; then
    echo "i2pd did not start NTCP2/SSU2 on ports ${PORT}/${SSU2_PORT} in time:" >&2
    tail -20 "${LOG}" >&2
    exit 1
fi

# The responder instance comes up slower: it retries the dead reseed URL before
# starting transports. Give it up to 5 minutes — it warms up in parallel.
for _attempt in $(seq 1 600); do
    if [[ -f "${RESP_DATA}/router.info" && -f "${RESP_DATA}/ntcp2.keys" ]] \
        && { grep -q "Start listening v4 TCP port ${RESP_PORT}" "${RESP_LOG}" \
            || grep -q "Accepting incoming connections at port ${RESP_PORT}" "${RESP_LOG}"; }; then
        break
    fi
    if ! kill -0 "$(pgrep -f "${RESP_DATA}" | head -1)" 2>/dev/null; then
        echo "responder i2pd exited early:" >&2
        tail -20 "${RESP_LOG}" >&2
        exit 1
    fi
    sleep 0.5
done

if ! { grep -q "Start listening v4 TCP port ${RESP_PORT}" "${RESP_LOG}" \
    || grep -q "Accepting incoming connections at port ${RESP_PORT}" "${RESP_LOG}"; }; then
    echo "responder i2pd did not start NTCP2 on port ${RESP_PORT} in time:" >&2
    tail -20 "${RESP_LOG}" >&2
    exit 1
fi

I2P_INTEROP="${DATA}" I2P_INTEROP_PORT="${PORT}" I2P_INTEROP_SSU2_PORT="${SSU2_PORT}" \
    I2P_INTEROP_RESPONDER="${RESP_DATA}" I2P_RESPONDER_PORT="${RESP_PORT}" \
    rebar3 ct --suite apps/i2per/interop/i2p_i2pd_interop_SUITE.erl
