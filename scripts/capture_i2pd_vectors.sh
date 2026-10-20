#!/usr/bin/env bash
# Capture SSU2 and NTCP2 wire vectors from a real i2pd into committed fixtures.
#
# This is the *capture* half of the hermetic protocol gate: it runs a throwaway
# i2pd, records the bytes it puts on the wire, and writes them to
# apps/i2per/test/fixtures/. Two suites then replay those bytes in `just check`
# with no i2pd anywhere — `apps/i2per/test/i2p_ssu2_vectors_SUITE.erl` for the
# SSU2 data phase and `apps/i2per/test/i2p_ntcp2_vectors_SUITE.erl` for the
# NTCP2 XK handshake and the data phase that follows it. The gate never runs
# this script — see scripts/ct-suites.sh, which refuses to emit any suite whose
# name mentions i2pd.
#
# Requires an i2pd binary. Set I2PD_BIN if it is not on PATH
# (nix build nixpkgs#i2pd -o ./i2pd-out; I2PD_BIN=./i2pd-out/bin/i2pd).
#
# Fully offline and deterministic:
#
#   * `reservedrange = false`. i2pd gates every inbound SSU2 datagram on
#     `!IsInReservedRange(addr)` (SSU2.cpp:775), which the default
#     `reservedrange = true` turns on, and its reserved list covers 127/8 and
#     100.64/10 (util.cpp:793). With the flag left on, i2pd drops every packet
#     from a loopback session with "incoming packet received from invalid or
#     banned endpoint" and the handshake never starts — which is what made the
#     SSU2 leg of scripts/interop_i2pd.sh unrunnable, since that script leaves
#     the flag set.
#   * No NetDb, and no waiting for one. `reseed.file` points i2pd at a local SU3
#     rather than at servers: without it i2pd retries the reseed every 30 s for
#     RESEED_GIVEUP_TIMEOUT (180 s, Reseed.cpp:26) before it gives up and starts
#     transports, which is the entire slow part of a capture. With it, i2pd
#     reads the file, finds every RouterInfo in it stale, and moves straight on
#     — SSU2 does not need peers to answer a SessionRequest, so an empty NetDb
#     costs the capture nothing. The file is the repo's own
#     `live_reseed.su3`, so the capture needs no network and no certificates.
#
# The reseed wait is gone, so the poll below resolves in seconds.

set -euo pipefail

I2PD_BIN="${I2PD_BIN:-$(command -v i2pd || true)}"
if [[ -z "${I2PD_BIN}" ]]; then
    echo "i2pd not found: set I2PD_BIN to the i2pd binary" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/apps/i2per/test/fixtures/i2pd_ssu2_data_phase.term"
NTCP2_OUT="${ROOT}/apps/i2per/test/fixtures/i2pd_ntcp2_handshake.term"
SEED="${ROOT}/apps/i2per/test/fixtures/live_reseed.su3"

# Off the I2P defaults and off the interop script's ports, so a capture never
# collides with a router or an interop run on the same machine.
NTCP2_PORT="${I2P_CAPTURE_NTCP2_PORT:-39523}"
SSU2_PORT="${I2P_CAPTURE_SSU2_PORT:-39524}"

DATA="$(mktemp -d /tmp/i2per-capture-XXXXXX)"
CONF="${DATA}/i2pd.conf"
LOG="${DATA}/i2pd.log"
cp "${SEED}" "${DATA}/i2pseeds.su3"

I2PD_PID=""

# Kill the i2pd *this* run started, by pid, and wait for it to be gone.
#
# The obvious alternative -- `pkill -f "${DATA}"` -- matches on the datadir
# appearing in the command line, which reads as equivalent and is not: the trap
# runs at EXIT, the port is released when the process actually dies, and a
# pattern match that loses the race leaves a listener holding the UDP port. The
# next run then fails to bind, i2pd logs "Address already in use" and never
# brings SSU2 up, and the capture dies on a port that a dead run left behind.
# Waiting for the pid is what makes two captures in a row reliable.
cleanup() {
    if [[ -n "${I2PD_PID}" ]] && kill -0 "${I2PD_PID}" 2>/dev/null; then
        kill "${I2PD_PID}" 2>/dev/null || true
        wait "${I2PD_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

cat >"${CONF}" <<EOF
log = stdout
loglevel = info
datadir = ${DATA}
port = ${NTCP2_PORT}
host = 127.0.0.1
ipv6 = false
netid = 2
reservedrange = false
ntcp2.enabled = true
ntcp2.port = ${NTCP2_PORT}
ntcp2.published = true
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
reseed.threshold = 0
reseed.verify = false
reseed.file = ${DATA}/i2pseeds.su3
reseed.urls =
EOF

echo "i2pd: ${I2PD_BIN}"
echo "datadir: ${DATA}"
echo "log: ${LOG}"

# Refuse to start on a port something else already holds. i2pd does not fail on
# this -- it logs "Failed to bind ... Address already in use", carries on with
# endpoint 0.0.0.0:0, and never prints the listening line, so the failure
# surfaces two minutes later as "did not start SSU2 in time" with nothing in the
# log pointing at the cause. Say it up front instead.
for _port in "${NTCP2_PORT}" "${SSU2_PORT}"; do
    if ss -Hlnt "sport = :${_port}" 2>/dev/null | grep -q . \
        || ss -Hlun "sport = :${_port}" 2>/dev/null | grep -q .; then
        echo "port ${_port} is already in use; set I2P_CAPTURE_NTCP2_PORT /" \
            "I2P_CAPTURE_SSU2_PORT to a free pair" >&2
        exit 1
    fi
done

"${I2PD_BIN}" --datadir "${DATA}" --conf "${CONF}" >"${LOG}" 2>&1 &
I2PD_PID=$!

# Poll for the listeners. i2pd binds 0.0.0.0 for SSU2, so "listening on
# 0.0.0.0" is the log line, not a probe of the loopback port: a bare connect to
# a UDP SSU2 port is indistinguishable from noise to i2pd and would only add to
# the log. NTCP2 is waited on the same way, by its own line — a bare TCP connect
# that sends nothing is a peer that opened a session and abandoned it, and
# scripts/interop_i2pd.sh found the same thing.
#
# The NTCP2 line must be the acceptor's own "NTCP2: Start listening v4 TCP
# port", and *only* that line. Transports.cpp:1608 also logs "Accepting
# incoming connections at port <port>" for the SSU2 transport, so accepting
# that as evidence of NTCP2 was a false positive: it is emitted whether or not
# NTCP2 is up, and NTCP2's acceptor is gated on a *published* NTCP2 address
# (NTCP2.cpp:1763, `address->IsPublishedNTCP2 () && address->port`). With
# `ntcp2.published = false` i2pd writes no address to the RouterInfo, the loop
# skips every address, no acceptor is created, and the wait passed on the SSU2
# line alone while the capture then died on a refused TCP connect. Hence
# `ntcp2.published = true` above, and the single unambiguous line here.
for _attempt in $(seq 1 240); do
    if [[ -f "${DATA}/router.info" && -f "${DATA}/ssu2.keys" && -f "${DATA}/ntcp2.keys" ]] \
        && grep -q "Start listening on 0.0.0.0:${SSU2_PORT}" "${LOG}" \
        && grep -q "NTCP2: Start listening v4 TCP port ${NTCP2_PORT}" "${LOG}"; then
        break
    fi
    if ! kill -0 "${I2PD_PID}" 2>/dev/null; then
        echo "i2pd exited early:" >&2
        tail -20 "${LOG}" >&2
        exit 1
    fi
    sleep 0.5
done

if ! grep -q "Start listening on 0.0.0.0:${SSU2_PORT}" "${LOG}"; then
    echo "i2pd did not start SSU2 on ${SSU2_PORT} in time:" >&2
    tail -20 "${LOG}" >&2
    exit 1
fi

if ! grep -q "NTCP2: Start listening v4 TCP port ${NTCP2_PORT}" "${LOG}"; then
    echo "i2pd did not start NTCP2 on ${NTCP2_PORT} in time:" >&2
    tail -20 "${LOG}" >&2
    exit 1
fi

# The capture records which i2pd it came from, so a fixture refreshed against a
# bumped i2pd says so in the file itself rather than only in the commit message.
I2PD_VERSION="$("${I2PD_BIN}" --version 2>&1 | head -1 | awk '{print $3}')"
export I2PD_VERSION

cd "${ROOT}"
rebar3 compile >/dev/null
escript scripts/capture_ssu2_vectors.escript "${DATA}" "${SSU2_PORT}" "${OUT}"

# NTCP2 runs second, against the same router: the two captures are independent
# sessions to independent transports, and one throwaway i2pd is enough for both
# as long as the listeners are up — which is what the wait above checks.
escript scripts/capture_ntcp2_vectors.escript "${DATA}" "${NTCP2_PORT}" "${NTCP2_OUT}"

echo "wrote ${OUT} (i2pd ${I2PD_VERSION})"
echo "wrote ${NTCP2_OUT} (i2pd ${I2PD_VERSION})"
