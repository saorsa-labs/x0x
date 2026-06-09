#!/usr/bin/env bash
# Improvised local 2h soak for PR #99 (codex/x0x-gui-full-dogfood).
#
# Loops the two LOCAL dogfood suites against the freshly-built release x0xd
# until SOAK_DURATION_SECS elapses, exercising the PR's local-discovery path
# (dogfood_local boots with --no-hard-coded-bootstrap → empty-bootstrap →
# allow_local_discovery_addresses scope) and named-group leave + DM/pubsub
# stability (dogfood_groups), under sustained restart churn.
#
# NOT covered here (no local harness exists): TreeKEM secure-group self-leave
# (testnet-only) and browser base64 upload (GUI) — both covered by the 146/146
# unit+integration slice instead.
#
# Green bar: 100% iteration pass rate, zero daemon panics, no late-clustering
# failures (port/FD-leak signal), no per-iteration duration blow-out.
set -uo pipefail
cd "$(dirname "$0")/.."

DUR="${SOAK_DURATION_SECS:-7200}"          # 2 hours
SETTLE="${SOAK_SETTLE_SECS:-2}"            # gap between iterations (port release)
MAX_CONSEC_FAIL="${SOAK_MAX_CONSEC_FAIL:-3}"  # fail-fast on a broken build
STAMP="$(date +%Y%m%dT%H%M%SZ)"
OUT="proofs/x0x-gui-full-dogfood/pr99-soak-${STAMP}"
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
echo "PR#99 local soak start=$STAMP dur=${DUR}s x0xd=$X0XD head=$(git rev-parse --short HEAD)" | tee -a "$LOG"

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
  echo "  \"pr\": 99,"
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
