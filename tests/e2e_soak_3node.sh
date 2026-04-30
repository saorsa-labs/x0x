#!/usr/bin/env bash
# 3-node VPS soak — 8-hour validation that the saorsa-gossip-pubsub
# cache fix (MAX_CACHE_SIZE 10000 → 2048, CACHE_TTL_SECS 300 → 60) holds
# under sustained publisher load on the live mesh.
#
# All VPS API calls go via SSH because port 12600 is bound to 127.0.0.1
# only on the VPS (firewall + locally-listening API by design).
#
# Roster:
#   nyc      — publisher
#   helsinki — publisher (was OOM-killed pre-fix on 4 GiB box)
#   sfo      — subscriber-only
# All 3 + the other 3 mesh peers stay subscribed; we just don't pump load
# from the other 3.
#
# Workload:
#   nyc + helsinki publish MSG_RATE msgs/s × MSG_SIZE bytes to topic T
#   sfo subscribes to T
#
# Acceptance:
#   - Every node stays <2 GiB RSS (auto-abort if any exceeds)
#   - decode_to_delivery_drops == 0 on every node throughout
#   - Mesh stays at ≥4 peers per node (5 ideal) throughout
#
# Usage:
#   tests/e2e_soak_3node.sh [--duration-hr 8] [--msg-rate 50] [--msg-size 4096]
#                           [--sample-interval-sec 60] [--proof-dir <path>]

set -euo pipefail

DURATION_HR=8
MSG_RATE=50
MSG_SIZE=4096
SAMPLE_INTERVAL_SEC=60
PROOF_DIR=""
ABORT_RSS_KB=$((2 * 1024 * 1024))  # 2 GiB

while (( "$#" )); do
    case "$1" in
        --duration-hr) DURATION_HR="$2"; shift 2 ;;
        --msg-rate) MSG_RATE="$2"; shift 2 ;;
        --msg-size) MSG_SIZE="$2"; shift 2 ;;
        --sample-interval-sec) SAMPLE_INTERVAL_SEC="$2"; shift 2 ;;
        --proof-dir) PROOF_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [ -z "$PROOF_DIR" ]; then
    PROOF_DIR="proofs/soak-3node-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$PROOF_DIR" "$PROOF_DIR/diag"
LOG="$PROOF_DIR/soak.log"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

TOKEN_FILE="$(dirname "${BASH_SOURCE[0]}")/.vps-tokens.env"
if [ ! -f "$TOKEN_FILE" ]; then
    log "FAIL: $TOKEN_FILE not found — run tests/e2e_deploy.sh first"
    exit 2
fi
# shellcheck disable=SC1090
source "$TOKEN_FILE"

TOPIC="soak-3node-$$"
log "Soak config: duration=${DURATION_HR}h rate=${MSG_RATE}msg/s size=${MSG_SIZE}B"
log "  topic=$TOPIC sample-interval=${SAMPLE_INTERVAL_SEC}s"
log "  abort-rss=$((ABORT_RSS_KB / 1024 / 1024))GiB"
log "  proof=$PROOF_DIR"

declare -A IP=([nyc]="$NYC_IP" [sfo]="$SFO_IP" [helsinki]="$HELSINKI_IP")
declare -A TK=([nyc]="$NYC_TK" [sfo]="$SFO_TK" [helsinki]="$HELSINKI_TK")
PUBLISHERS=(nyc helsinki)
ALL_NODES=(nyc sfo helsinki)
# SSH options:
#   ConnectTimeout=10        give up if TCP handshake doesn't complete in 10 s
#   ServerAliveInterval=10   send a keepalive every 10 s …
#   ServerAliveCountMax=2    … and disconnect after 2 missed replies (≈30 s)
# Without ServerAlive, a network blip during a sample loop can wedge the SSH
# session indefinitely; the soak harness on 2026-04-30 hung at uptime=7h24m
# this way and stopped sampling for the final 36 min of the 8 h run.
SSH="ssh -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=2 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none"

# Outer wall-clock cap on every SSH command so a stuck session can never
# block the sample loop. 30 s is generous for any single sample call.
ssh_run() {
    local target="$1"; shift
    timeout 30 $SSH "$target" "$@"
}

# ─────────────────────────────────────────────────────────────────────────
# Helpers (all API calls go via SSH-tunneled curl on the box itself)
# ─────────────────────────────────────────────────────────────────────────
api_get() {
    local node="$1" path="$2"
    ssh_run root@"${IP[$node]}" \
        "curl -sS -m 10 -H 'authorization: Bearer ${TK[$node]}' http://127.0.0.1:12600${path}" 2>/dev/null
}

api_post() {
    local node="$1" path="$2" body="$3"
    ssh_run root@"${IP[$node]}" \
        "curl -sS -m 10 -X POST -H 'authorization: Bearer ${TK[$node]}' -H 'content-type: application/json' -d '${body}' http://127.0.0.1:12600${path}" 2>/dev/null
}

remote_rss_kb() {
    # pidof matches the binary basename only (avoids self-match the way
    # pgrep -f does over SSH because the command line itself contains the
    # pattern).
    ssh_run root@"${IP[$1]}" 'PID=$(pidof x0xd); awk "/VmRSS/{print \$2}" /proc/$PID/status' 2>/dev/null
}

remote_cpu_pct() {
    ssh_run root@"${IP[$1]}" 'ps -o %cpu= -p $(pidof x0xd)' 2>/dev/null | tr -d ' \n'
}

# ─────────────────────────────────────────────────────────────────────────
# Pre-flight
# ─────────────────────────────────────────────────────────────────────────
log "Pre-flight: confirming all 3 nodes reachable + healthy"
for n in "${ALL_NODES[@]}"; do
    H=$(api_get "$n" /health)
    if echo "$H" | grep -q '"ok":true'; then
        log "  $n: healthy"
    else
        log "FAIL $n: $H"
        exit 1
    fi
done

log "Subscribing all 3 nodes to $TOPIC"
for n in "${ALL_NODES[@]}"; do
    api_post "$n" /subscribe "{\"topic\":\"$TOPIC\"}" > "$PROOF_DIR/$n-subscribe.json" || true
done

for n in "${ALL_NODES[@]}"; do
    api_get "$n" /diagnostics/gossip > "$PROOF_DIR/$n-gossip-pre.json" || true
    api_get "$n" /peers > "$PROOF_DIR/$n-peers-pre.json" || true
done

# ─────────────────────────────────────────────────────────────────────────
# Sampler in background
# ─────────────────────────────────────────────────────────────────────────
RSS_CSV="$PROOF_DIR/rss.csv"
echo "ts_iso,uptime_s,nyc_rss_kb,nyc_cpu,sfo_rss_kb,sfo_cpu,helsinki_rss_kb,helsinki_cpu" > "$RSS_CSV"

START=$(date +%s)
END=$((START + DURATION_HR * 3600))
ABORT_FLAG="$PROOF_DIR/.abort"
rm -f "$ABORT_FLAG"

(
    sample_idx=0
    while [ ! -f "$ABORT_FLAG" ] && [ "$(date +%s)" -lt "$END" ]; do
        NOW=$(date +%s)
        UP=$((NOW - START))
        # Parallel SSH for the 3 nodes.
        declare -A R=()
        declare -A C=()
        for n in "${ALL_NODES[@]}"; do
            R[$n]=$(remote_rss_kb "$n" || echo 0)
            C[$n]=$(remote_cpu_pct "$n" || echo 0)
        done
        # Strip non-digits from R values (handle empty/error returns gracefully).
        for n in "${ALL_NODES[@]}"; do
            R[$n]=$(echo "${R[$n]:-0}" | tr -d '\n ' | grep -oE '^[0-9]+' || echo 0)
            R[$n]=${R[$n]:-0}
        done
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$UP,${R[nyc]},${C[nyc]:-0},${R[sfo]},${C[sfo]:-0},${R[helsinki]},${C[helsinki]:-0}" >> "$RSS_CSV"

        # Diagnostic snapshot every 5th sample (= every 5 min at 60s intervals).
        if (( sample_idx % 5 == 0 )); then
            for n in "${ALL_NODES[@]}"; do
                D="$PROOF_DIR/diag/$n"; mkdir -p "$D"
                api_get "$n" /diagnostics/gossip > "$D/gossip-${UP}.json" 2>/dev/null || true
                api_get "$n" /peers > "$D/peers-${UP}.json" 2>/dev/null || true
            done
        fi

        # Auto-abort gate.
        for n in "${ALL_NODES[@]}"; do
            if [ "${R[$n]}" -gt "$ABORT_RSS_KB" ]; then
                echo "$n exceeded ${ABORT_RSS_KB} KB at uptime ${UP}s (rss=${R[$n]} KB = $((R[$n] / 1024)) MB)" > "$ABORT_FLAG"
                break
            fi
        done

        log "uptime=${UP}s nyc=$((R[nyc] / 1024))MB sfo=$((R[sfo] / 1024))MB helsinki=$((R[helsinki] / 1024))MB"
        sample_idx=$((sample_idx + 1))
        sleep "$SAMPLE_INTERVAL_SEC"
    done
) &
SAMPLER_PID=$!

# ─────────────────────────────────────────────────────────────────────────
# Publisher loops — one per publisher, running ON the VPS via SSH.
# Each publisher loops a curl against its own loopback API. We capture the
# remote PID so cleanup can kill them at end-of-soak (or auto-abort).
# ─────────────────────────────────────────────────────────────────────────
SLEEP_SEC=$(awk -v r="$MSG_RATE" 'BEGIN { printf "%.4f", 1.0 / r }')
PAYLOAD_RAW=$(printf '%*s' "$MSG_SIZE" | tr ' ' 'x')
PAYLOAD_B64=$(printf '%s' "$PAYLOAD_RAW" | base64 | tr -d '\n')
BODY="{\"topic\":\"$TOPIC\",\"payload\":\"$PAYLOAD_B64\"}"
REMOTE_STOP_FILE="/tmp/.soak-stop-${TOPIC}"
REMOTE_COUNT_FILE="/tmp/soak-pub-${TOPIC}.count"
REMOTE_LOG_FILE="/tmp/soak-pub-${TOPIC}.log"

declare -A REMOTE_PUB_PIDS=()
for pn in "${PUBLISHERS[@]}"; do
    log "Starting publisher loop on $pn (rate=${MSG_RATE}/s)"
    # Build the remote inner script as a single quoted string. The OUTER
    # bash on the VPS evaluates this; we substitute $BODY, $SLEEP_SEC, the
    # token, and the topic into the literal text before sending. The inner
    # `bash -c` then runs the publish loop forever until the topic-scoped
    # stop file is touched. Quoting note: REMOTE_INNER uses single quotes around the
    # outer bash -c argument, so literal $count and $! won't be expanded
    # locally; nohup keeps the loop running after the SSH session exits.
    REMOTE_INNER=$(cat <<EOF
rm -f '${REMOTE_STOP_FILE}' '${REMOTE_COUNT_FILE}' '${REMOTE_LOG_FILE}'
nohup bash -c 'count=0; while [ ! -f '"'"'${REMOTE_STOP_FILE}'"'"' ]; do curl -sS -m 5 -X POST -H "authorization: Bearer ${TK[$pn]}" -H "content-type: application/json" -d '"'"'${BODY}'"'"' http://127.0.0.1:12600/publish >/dev/null 2>&1 || true; count=\$((count+1)); echo \$count > '"'"'${REMOTE_COUNT_FILE}'"'"'; sleep ${SLEEP_SEC}; done' > '${REMOTE_LOG_FILE}' 2>&1 &
echo \$!
EOF
)
    REMOTE_PUB_PIDS[$pn]=$(ssh_run root@"${IP[$pn]}" "$REMOTE_INNER" 2>/dev/null | tail -1 | tr -d '\n ')
    log "  $pn remote publisher PID: ${REMOTE_PUB_PIDS[$pn]}"
done

cleanup() {
    log "Shutting down publishers + sampler"
    # Stop remote publishers (touch stop flag + kill).
    for pn in "${PUBLISHERS[@]}"; do
        ssh_run root@"${IP[$pn]}" "touch '${REMOTE_STOP_FILE}'; kill ${REMOTE_PUB_PIDS[$pn]} 2>/dev/null || true; sleep 1; pkill -f 'curl.*${TOPIC}' 2>/dev/null || true" >/dev/null 2>&1 || true
        # Capture final publish count.
        ssh_run root@"${IP[$pn]}" "cat '${REMOTE_COUNT_FILE}' 2>/dev/null || true" > "$PROOF_DIR/$pn-publish-count.txt" 2>/dev/null || true
    done
    kill "$SAMPLER_PID" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true

    # Final stats.
    for n in "${ALL_NODES[@]}"; do
        api_get "$n" /diagnostics/gossip > "$PROOF_DIR/$n-gossip-post.json" 2>/dev/null || true
        api_get "$n" /peers > "$PROOF_DIR/$n-peers-post.json" 2>/dev/null || true
    done

    if [ -f "$ABORT_FLAG" ]; then
        log "FAIL: aborted — $(cat "$ABORT_FLAG")"
        return 1
    fi

    fails=0
    for n in "${ALL_NODES[@]}"; do
        D=$(jq -r '.stats.decode_to_delivery_drops // 0' "$PROOF_DIR/$n-gossip-post.json" 2>/dev/null || echo 0)
        if [ "$D" != 0 ]; then
            log "FAIL $n: decode_to_delivery_drops=$D"
            fails=$((fails+1))
        fi
    done

    log "Final RSS curve (every 30 min):"
    awk -F, 'NR==1 || (NR > 1 && ($2 == 0 || $2 % 1800 == 0))' "$RSS_CSV" | tee -a "$LOG"

    [ $fails -eq 0 ] && log "PASS — soak completed cleanly" && return 0 || return 1
}
trap 'cleanup; exit $?' EXIT

# Main wait — sampler decides when to abort.
while [ "$(date +%s)" -lt "$END" ] && [ ! -f "$ABORT_FLAG" ]; do
    sleep 30
done

log "Soak window ended — running cleanup"
