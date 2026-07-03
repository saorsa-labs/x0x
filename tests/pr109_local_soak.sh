#!/usr/bin/env bash
# Improvised local 2h soak for PR #109 (feat/agent-verify).
#
# PR #109 adds POST /agent/verify + `x0x agent verify` — a stateless,
# purely-additive endpoint with no background tasks and no gossip/network/CRDT
# impact. The endpoint's own behaviour is fully covered by 21 daemon-backed
# integration tests + the CLI unit tests (all green pre-soak). This soak is the
# launch-readiness *stability* check: it loops the two LOCAL dogfood suites
# against the freshly-built release x0xd from this branch until
# SOAK_DURATION_SECS elapses, proving a daemon built from feat/agent-verify
# stays healthy under sustained restart churn (no panics, no FD/port leaks,
# 100% iteration pass rate).
#
# Mirrors tests/pr99_local_soak.sh (the established per-PR local-soak pattern).
#
# Green bar: 100% iteration pass rate, zero daemon panics, no late-clustering
# failures (port/FD-leak signal), no per-iteration duration blow-out.
set -uo pipefail
cd "$(dirname "$0")/.."

DUR="${SOAK_DURATION_SECS:-7200}"          # 2 hours
SETTLE="${SOAK_SETTLE_SECS:-2}"            # gap between iterations (port release)
MAX_CONSEC_FAIL="${SOAK_MAX_CONSEC_FAIL:-3}"  # fail-fast on a broken build
STAMP="$(date +%Y%m%dT%H%M%SZ)"
OUT="proofs/agent-verify/pr109-soak-${STAMP}"
mkdir -p "$OUT"
RESULTS="$OUT/results.csv"
LOG="$OUT/soak.log"
SUMMARY="$OUT/summary.json"

X0XD="${X0XD:-$PWD/target/release/x0xd}"
export X0XD
if [ ! -x "$X0XD" ]; then
    echo "x0xd not built at $X0XD" | tee -a "$LOG"
    exit 2
fi

echo "iter,ts_utc,suite,rc,elapsed_s" > "$RESULTS"
echo "PR#109 local soak start=$STAMP dur=${DUR}s x0xd=$X0XD head=$(git rev-parse --short HEAD)" | tee -a "$LOG"

t0=$(date +%s)
deadline=$((t0 + DUR))
iter=0
pass=0
fail=0
consec_fail=0
declare -a FAILED_ITERS=()

run_suite() {
    # $1 = label, $2... = command
    local label="$1"; shift
    local s e rc
    s=$(date +%s)
    "$@" >>"$OUT/${label}.last.log" 2>&1
    rc=$?
    e=$(($(date +%s) - s))
    echo "$iter,$(date -u +%Y-%m-%dT%H:%M:%SZ),$label,$rc,$e" >> "$RESULTS"
    if [ "$rc" -ne 0 ]; then
        echo "[iter $iter] $label FAIL rc=$rc (${e}s)" | tee -a "$LOG"
        # preserve the failing run's log
        cp "$OUT/${label}.last.log" "$OUT/${label}.iter${iter}.fail.log" 2>/dev/null || true
    fi
    return $rc
}

while [ "$(date +%s)" -lt "$deadline" ]; do
    iter=$((iter + 1))
    iter_ok=1

    run_suite "dogfood_local"  bash tests/e2e_dogfood_local.sh  || iter_ok=0
    run_suite "dogfood_groups" bash tests/e2e_dogfood_groups.sh || iter_ok=0

    if [ "$iter_ok" -eq 1 ]; then
        pass=$((pass + 1))
        consec_fail=0
    else
        fail=$((fail + 1))
        FAILED_ITERS+=("$iter")
        consec_fail=$((consec_fail + 1))
        if [ "$consec_fail" -ge "$MAX_CONSEC_FAIL" ]; then
            echo "FAIL-FAST: $consec_fail consecutive failed iterations — aborting soak" | tee -a "$LOG"
            break
        fi
    fi

    if [ "$((iter % 20))" -eq 0 ]; then
        echo "[progress] iter=$iter pass=$pass fail=$fail elapsed=$(($(date +%s) - t0))s" | tee -a "$LOG"
    fi
    sleep "$SETTLE"
done

# Panic/abort scan across any preserved logs.
PANICS=$(grep -rlE "panic|thread '.*' panicked|fatal runtime|SIGABRT" "$OUT"/*.log 2>/dev/null | wc -l | tr -d ' ')

elapsed=$(($(date +%s) - t0))
rate="n/a"
if [ "$((pass + fail))" -gt 0 ]; then
    rate=$(awk "BEGIN{printf \"%.1f\", 100*$pass/($pass+$fail)}")
fi

{
  echo "{"
  echo "  \"pr\": 109,"
  echo "  \"head\": \"$(git rev-parse HEAD)\","
  echo "  \"start_utc\": \"$STAMP\","
  echo "  \"elapsed_secs\": $elapsed,"
  echo "  \"iterations\": $iter,"
  echo "  \"pass\": $pass,"
  echo "  \"fail\": $fail,"
  echo "  \"pass_rate_pct\": \"$rate\","
  echo "  \"failed_iters\": \"${FAILED_ITERS[*]:-}\","
  echo "  \"panic_logs\": $PANICS,"
  echo "  \"green\": $([ "$fail" -eq 0 ] && [ "$PANICS" -eq 0 ] && echo true || echo false)"
  echo "}"
} | tee "$SUMMARY" | tee -a "$LOG"

echo "SOAK DONE: iters=$iter pass=$pass fail=$fail rate=${rate}% panics=$PANICS elapsed=${elapsed}s out=$OUT" | tee -a "$LOG"
