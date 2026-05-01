#!/usr/bin/env bash
# Top-level proof runner — orchestrates every E2E surface for a release.
#
# Produces a single machine-readable proof-report.json in
# proofs/<timestamp>/ that rolls up per-phase status.
#
# Phases (each opt-out-able via flags):
#   --rust-tests         cargo nextest (all workspace tests)
#   --comprehensive      tests/e2e_comprehensive.sh (local 3-daemon)
#   --stress             tests/e2e_stress_gossip.sh
#   --chrome             tests/e2e_gui_chrome.mjs
#   --dioxus             tests/e2e_communitas_dioxus.sh
#   --xcuitest           xcodebuild UI tests (macOS only)
#   --dogfood-local      tests/e2e_dogfood_local.sh
#   --dogfood-groups     tests/e2e_dogfood_groups.sh
#   --vps                tests/e2e_vps.sh (requires tokens)
#   --vps-mesh           tests/e2e_vps_mesh.py (requires deployed runners)
#   --vps-groups         tests/e2e_vps_groups.py (requires deployed runners)
#   --lan                tests/e2e_lan.sh (requires Mac Studios)
#   --all                everything above
#
# Usage:
#   tests/e2e_proof_runner.sh --all
#   tests/e2e_proof_runner.sh --rust-tests --comprehensive --stress --chrome

set -euo pipefail

PROOF_DIR="proofs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$PROOF_DIR"
REPORT="$PROOF_DIR/proof-report.json"
LOG="$PROOF_DIR/runner.log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

RUN_RUST=0 RUN_COMP=0 RUN_STRESS=0 RUN_CHROME=0
RUN_DIOXUS=0 RUN_XCUI=0 RUN_DOGFOOD_LOCAL=0 RUN_DOGFOOD_GROUPS=0
RUN_VPS=0 RUN_VPS_MESH=0 RUN_VPS_GROUPS=0 RUN_LAN=0

if [ $# -eq 0 ]; then
    echo "usage: $0 [--all] [--rust-tests] [--comprehensive] [--dogfood-local] [--dogfood-groups] [--stress] [--chrome] [--dioxus] [--xcuitest] [--vps] [--vps-mesh] [--vps-groups] [--lan]"
    exit 2
fi

while (( "$#" )); do
    case "$1" in
        --all) RUN_RUST=1; RUN_COMP=1; RUN_DOGFOOD_LOCAL=1; RUN_DOGFOOD_GROUPS=1; RUN_STRESS=1; RUN_CHROME=1; RUN_DIOXUS=1; RUN_XCUI=1; RUN_VPS=1; RUN_VPS_MESH=1; RUN_VPS_GROUPS=1; RUN_LAN=1 ;;
        --rust-tests) RUN_RUST=1 ;;
        --comprehensive) RUN_COMP=1 ;;
        --dogfood-local) RUN_DOGFOOD_LOCAL=1 ;;
        --dogfood-groups) RUN_DOGFOOD_GROUPS=1 ;;
        --stress) RUN_STRESS=1 ;;
        --chrome) RUN_CHROME=1 ;;
        --dioxus) RUN_DIOXUS=1 ;;
        --xcuitest) RUN_XCUI=1 ;;
        --vps) RUN_VPS=1 ;;
        --vps-mesh) RUN_VPS_MESH=1 ;;
        --vps-groups) RUN_VPS_GROUPS=1 ;;
        --lan) RUN_LAN=1 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
    shift
done

declare -A PHASE_STATUS
declare -A PHASE_DETAIL

run_phase() {
    local name="$1" ; shift
    log "=== $name ==="
    local phase_dir="$PROOF_DIR/$name"
    mkdir -p "$phase_dir"
    local ec=0
    if "$@" > "$phase_dir/stdout.log" 2> "$phase_dir/stderr.log"; then
        PHASE_STATUS["$name"]="pass"
    else
        ec=$?
        PHASE_STATUS["$name"]="fail"
        PHASE_DETAIL["$name"]="exit=$ec"
    fi
    log "$name: ${PHASE_STATUS[$name]}${PHASE_DETAIL[$name]:+ (${PHASE_DETAIL[$name]})}"
}

[ "$RUN_RUST" = 1 ] && run_phase rust-tests \
    cargo nextest run --all-features --workspace

[ "$RUN_COMP" = 1 ] && [ -x tests/e2e_comprehensive.sh ] && run_phase comprehensive \
    bash tests/e2e_comprehensive.sh

[ "$RUN_DOGFOOD_LOCAL" = 1 ] && [ -x tests/e2e_dogfood_local.sh ] && run_phase dogfood-local \
    bash tests/e2e_dogfood_local.sh

[ "$RUN_DOGFOOD_GROUPS" = 1 ] && [ -x tests/e2e_dogfood_groups.sh ] && run_phase dogfood-groups \
    bash tests/e2e_dogfood_groups.sh

[ "$RUN_STRESS" = 1 ] && run_phase stress \
    bash tests/e2e_stress_gossip.sh --nodes 3 --messages 500 \
        --proof-dir "$PROOF_DIR/stress"

[ "$RUN_CHROME" = 1 ] && run_phase chrome \
    node tests/e2e_gui_chrome.mjs --proof-dir "$PROOF_DIR/chrome"

[ "$RUN_DIOXUS" = 1 ] && run_phase dioxus \
    bash tests/e2e_communitas_dioxus.sh "$PROOF_DIR/dioxus"

[ "$RUN_XCUI" = 1 ] && [ "$(uname)" = "Darwin" ] && run_phase xcuitest \
    sh -c 'cd ../communitas/communitas-apple && \
        xcodebuild -scheme Communitas -destination "platform=macOS" \
        -only-testing:CommunitasUITests -resultBundlePath '"$PROOF_DIR/xcuitest/xcresult"' test'

[ "$RUN_VPS" = 1 ] && [ -x tests/e2e_vps.sh ] && run_phase vps \
    bash tests/e2e_vps.sh

[ "$RUN_VPS_MESH" = 1 ] && [ -x tests/e2e_vps_mesh.py ] && run_phase vps-mesh \
    python3 tests/e2e_vps_mesh.py

[ "$RUN_VPS_GROUPS" = 1 ] && [ -x tests/e2e_vps_groups.py ] && run_phase vps-groups \
    python3 tests/e2e_vps_groups.py

[ "$RUN_LAN" = 1 ] && [ -x tests/e2e_lan.sh ] && run_phase lan \
    bash tests/e2e_lan.sh

# Roll up JSON.
{
    printf '{"started_at":"%s","proof_dir":"%s","phases":{' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROOF_DIR"
    first=1
    for k in "${!PHASE_STATUS[@]}"; do
        [ $first -eq 1 ] && first=0 || printf ','
        printf '"%s":{"status":"%s"' "$k" "${PHASE_STATUS[$k]}"
        [ -n "${PHASE_DETAIL[$k]:-}" ] && printf ',"detail":"%s"' "${PHASE_DETAIL[$k]}"
        printf '}'
    done
    printf '}}\n'
} > "$REPORT"

log "Proof report → $REPORT"

fails=0
for v in "${PHASE_STATUS[@]}"; do
    [ "$v" = "fail" ] && ((fails++)) || true
done
exit $((fails > 0 ? 1 : 0))
