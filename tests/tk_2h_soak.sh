#!/usr/bin/env bash
# Time-bounded TreeKEM membership-churn soak on the testnet.
# Drives tests/e2e_treekem_membership.py for SOAK_DURATION_SECS (default 2h),
# then stops the harness with an escalating signal sequence (SIGINT for clean
# tunnel teardown, then TERM/KILL if it doesn't respond) and tallies results.
#
# Iterations are capped well above what 2h can reach so the wall-clock bound
# (not the iteration count) ends the run; if the killer ever fails, the cap
# still terminates it rather than running indefinitely.
set -uo pipefail
cd "$(dirname "$0")/.."

DUR="${SOAK_DURATION_SECS:-7200}"   # 2 hours
ANCHOR="${SOAK_ANCHOR:-nyc}"
MEMBER="${SOAK_MEMBER:-sfo}"
ITERS="${SOAK_ITERS:-150}"          # ~2h at ~50-90s/iter; hard upper bound
STAMP="$(date +%Y%m%dT%H%M%SZ)"
OUT="proofs/treekem-2h-soak-${STAMP}"
mkdir -p "$OUT"
LOG="$OUT/soak.log"

echo "soak start=$STAMP dur=${DUR}s anchor=$ANCHOR member=$MEMBER iters_cap=$ITERS out=$OUT"
python3 tests/e2e_treekem_membership.py \
    --anchor "$ANCHOR" --member "$MEMBER" \
    --iterations "$ITERS" --settle-secs 90 > "$LOG" 2>&1 &
PYPID=$!

# Wall-clock killer: clean SIGINT first (tunnel teardown in the harness finally),
# escalate to TERM/KILL if the process ignores it, then sweep stray tunnels.
(
    sleep "$DUR"
    echo "--- reached ${DUR}s wall-clock; stopping harness ---" >> "$LOG"
    kill -INT "$PYPID" 2>/dev/null
    sleep 30; kill -0 "$PYPID" 2>/dev/null && kill -TERM "$PYPID" 2>/dev/null
    sleep 5;  kill -0 "$PYPID" 2>/dev/null && kill -KILL "$PYPID" 2>/dev/null
    pkill -KILL -f "e2e_treekem_membership.py" 2>/dev/null
    pkill -f "ssh -N.*13600" 2>/dev/null
) &
KILLER=$!

wait "$PYPID" 2>/dev/null
kill "$KILLER" 2>/dev/null

PASS=$(grep -c "iter .* PASS" "$LOG" 2>/dev/null || echo 0)
FAIL=$(grep -c "iter .* FAIL" "$LOG" 2>/dev/null || echo 0)
{
    echo "=== TreeKEM 2h membership-churn soak summary ==="
    echo "start=$STAMP anchor=$ANCHOR member=$MEMBER"
    echo "iterations PASS=$PASS FAIL=$FAIL"
    echo "--- failures by step ---"
    grep -aoE "FAIL @[a-z_]+" "$LOG" 2>/dev/null | sort | uniq -c
    echo "--- FAIL lines ---"
    grep "iter .* FAIL" "$LOG" 2>/dev/null | tail -40
} | tee "$OUT/SUMMARY.txt"
echo "SOAK_DONE pass=$PASS fail=$FAIL out=$OUT"
