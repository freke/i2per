#!/usr/bin/env bash
# Run the scheduler-flag latency matrix for #VXRH456.
#
# One VM per run: the scheduling flags are emulator flags, handed to the VM
# through ERL_FLAGS (escript honours it and reports the online scheduler and
# dirty-scheduler counts in its output, which is what verifies the flags took).
# Repetitions are INTERLEAVED across configurations so drift in machine state
# reads as drift rather than as a flag making a difference.
#
#   scripts/bench_sched_latency.sh                 # the full matrix
#   REPS=1 RATE=0 scripts/bench_sched_latency.sh   # just the quiet floor
#
# Env: REPS (default 3), RATE (default 500), WARM_MS (default 1500),
# WINDOW_MS (default 3000), OUT (default /tmp/sched-latency-matrix.txt).

set -u
cd "$(dirname "$0")/.."

REPS=${REPS:-3}
RATE=${RATE:-500}
WARM_MS=${WARM_MS:-1500}
WINDOW_MS=${WINDOW_MS:-3000}
OUT=${OUT:-/tmp/sched-latency-matrix.txt}

# label|"+S value"|sbwt value|sbwtdcpu value  (empty means "do not set it")
CONFIGS=(
    "true-default|||"
    "s1-default|1||"
    "s1-none|1|none|none"
    "s1-very-short|1|very_short|very_short"
    "s1-short|1|short|short"
    "s1-medium|1|medium|medium"
    "s1-long|1|long|long"
    "s1-very-long|1|very_long|very_long"
    "s2-default|2||"
    "s2-none|2|none|none"
    "s2-very-short|2|very_short|very_short"
    "s2-medium|2|medium|medium"
    "s2-long|2|long|long"
    "s16-default|16||"
    "s16-none|16|none|none"
    "s16-very-short|16|very_short|very_short"
    "s16-medium|16|medium|medium"
    "s16-long|16|long|long"
)

: >"$OUT"
for rep in $(seq 1 "$REPS"); do
    for entry in "${CONFIGS[@]}"; do
        IFS='|' read -r label s sbwt sbwtdcpu <<<"$entry"
        flags=""
        [ -n "$s" ] && flags="$flags+S $s"
        [ -n "$sbwt" ] && flags="$flags +sbwt $sbwt"
        [ -n "$sbwtdcpu" ] && flags="$flags +sbwtdcpu $sbwtdcpu"
        ERL_FLAGS="$flags" escript bench/bench_sched_latency.escript \
            --label "rep$rep $label" --rate "$RATE" \
            --warm-ms "$WARM_MS" --window-ms "$WINDOW_MS" 2>/dev/null >>"$OUT"
    done
done

cat "$OUT"
