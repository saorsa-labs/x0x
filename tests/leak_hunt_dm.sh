#!/usr/bin/env bash
# Hunt step 4 — local 2-daemon DM ping-pong repro under dhat.
#
# Mirrors the fleet test-runner traffic shape (DM matrix): two isolated
# x0xd daemons peered on loopback, alternating /direct/send at MSG_RATE
# msg/s total for DURATION_MIN minutes, RSS sampled every 30s, then an
# optional idle phase to separate retained growth from working set.
# Graceful shutdown emits dhat-heap-<pid>.json when the binary is the
# profile-heap build.
#
# Usage:
#   tests/leak_hunt_dm.sh \
#       [--duration-min 30] [--idle-min 5] [--msg-rate 10] [--msg-size 3072] \
#       [--proof-dir proofs/leak-dm-<ts>]
#
# dhat-instrumented build:
#   cargo build --bin x0xd --features profile-heap
#   X0XD_BIN=target/debug/x0xd tests/leak_hunt_dm.sh

set -euo pipefail

DURATION_MIN=30
IDLE_MIN=5
MSG_RATE=10
MSG_SIZE=3072
PROOF_DIR=""
GRACE_SEC=300

while (( "$#" )); do
    case "$1" in
        --duration-min) DURATION_MIN="$2"; shift 2;;
        --idle-min) IDLE_MIN="$2"; shift 2;;
        --msg-rate) MSG_RATE="$2"; shift 2;;
        --msg-size) MSG_SIZE="$2"; shift 2;;
        --proof-dir) PROOF_DIR="$2"; shift 2;;
        --grace-sec) GRACE_SEC="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

if [ -z "$PROOF_DIR" ]; then
    PROOF_DIR="proofs/leak-dm-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$PROOF_DIR/logs"

LOG="$PROOF_DIR/run.log"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

BIN="${X0XD_BIN:-target/debug/x0xd}"
if [ ! -x "$BIN" ]; then
    echo "missing $BIN — run: cargo build --bin x0xd"; exit 2
fi

log "Config: duration=${DURATION_MIN}min idle=${IDLE_MIN}min rate=${MSG_RATE}msg/s size=${MSG_SIZE}B"
log "Binary: $BIN"

PIDS=()
APIS=()
TOKENS=()
AGENTS=()

cleanup() {
    log "Stopping daemons (graceful — needed for dhat-heap dump emission)"
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -INT "$pid" 2>/dev/null || true
    done
    log "Waiting up to ${GRACE_SEC}s for graceful shutdown + dhat flush"
    for s in $(seq 1 "${GRACE_SEC}"); do
        alive=0
        for pid in "${PIDS[@]:-}"; do
            [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && alive=$((alive+1))
        done
        [ "$alive" -eq 0 ] && break
        sleep 1
    done
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -KILL "$pid" 2>/dev/null || true
    done
    log "dhat dumps in proof dir:"
    ls -la "$PROOF_DIR"/dhat-heap-*.json 2>&1 | tee -a "$LOG" || true
}
trap cleanup EXIT

# Launch 2 daemons with config-file peering: bob bootstraps to alice.
# alice: bind 13401 api 13301; bob: bind 13402 api 13302.
for i in 1 2; do
    NAME=$([ "$i" = 1 ] && echo alice || echo bob)
    BIND=$((13400 + i))
    API=$((13300 + i))
    NODE_DIR="$PROOF_DIR/node-$i"
    mkdir -p "$NODE_DIR/data" "$NODE_DIR/logs"
    BOOTSTRAP=""
    [ "$i" = 2 ] && BOOTSTRAP='bootstrap_peers = ["127.0.0.1:13401"]'
    cat > "$NODE_DIR/config.toml" <<EOF
instance_name = "leak-dm-$NAME"
data_dir = "$(cd "$NODE_DIR" && pwd)/data"
bind_address = "127.0.0.1:$BIND"
api_address = "127.0.0.1:$API"
log_level = "warn"
$BOOTSTRAP
[update]
enabled = false
EOF
    log "Launching $NAME bind=$BIND api=$API"
    DHAT_OUT_DIR="$(cd "$PROOF_DIR" && pwd)" \
        "$BIN" --config "$NODE_DIR/config.toml" --skip-update-check \
        > "$NODE_DIR/logs/stdout.log" 2> "$NODE_DIR/logs/stderr.log" &
    PIDS+=($!)
    APIS+=("$API")
done

log "Waiting for daemons to report healthy"
for i in 1 2; do
    PORT=$((13300 + i))
    ready=""
    for _ in $(seq 1 60); do
        if curl -sf --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    if [ -z "$ready" ]; then
        log "FATAL: node-$i never became healthy"; exit 1
    fi
done
log "Both daemons healthy"

for i in 1 2; do
    NODE_DIR="$PROOF_DIR/node-$i"
    TOKEN_FILE="$NODE_DIR/data/api-token"
    if [ -f "$TOKEN_FILE" ]; then
        TOKENS+=("$(cat "$TOKEN_FILE")")
    else
        log "warn: no token at $TOKEN_FILE"
        TOKENS+=("")
    fi
done

api() {
    local idx="$1" method="$2" path="$3" body="${4:-}"
    local port="${APIS[$((idx - 1))]}"
    local token="${TOKENS[$((idx - 1))]}"
    local args=(-sS -X "$method" "http://127.0.0.1:${port}${path}")
    [ -n "$token" ] && args+=(-H "authorization: Bearer $token")
    [ -n "$body" ] && args+=(-H "content-type: application/json" -d "$body")
    curl "${args[@]}"
}

# Resolve agent ids.
mkdir -p "$PROOF_DIR/logs/node-1" "$PROOF_DIR/logs/node-2"
for i in 1 2; do
    INFO=$(api "$i" GET /agent || true)
    echo "$INFO" > "$PROOF_DIR/logs/node-$i/agent.json"
    AID=$(printf '%s' "$INFO" | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get("agent_id") or d.get("id") or d.get("agent", {}).get("agent_id") or "")
except Exception:
    print("")
')
    AGENTS+=("$AID")
    log "node-$i agent_id: ${AID:-UNRESOLVED}"
done
if [ -z "${AGENTS[0]}" ] || [ -z "${AGENTS[1]}" ]; then
    log "FATAL: could not resolve agent ids"; exit 1
fi

# Pre-run diagnostics snapshot.
for i in 1 2; do
    api "$i" GET /diagnostics/dm > "$PROOF_DIR/logs/node-$i/dm-pre.json" || true
done

# RSS sampler.
RSS_CSV="$PROOF_DIR/rss.csv"
echo "ts_iso,uptime_s,node1_rss_kb,node2_rss_kb" > "$RSS_CSV"
START=$(date +%s)
(
    while true; do
        NOW=$(date +%s)
        R1=$(ps -o rss= -p "${PIDS[0]}" 2>/dev/null | tr -d ' ' || echo NA)
        R2=$(ps -o rss= -p "${PIDS[1]}" 2>/dev/null | tr -d ' ' || echo NA)
        echo "$(date -u +%H:%M:%S),$((NOW - START)),${R1:-NA},${R2:-NA}" >> "$RSS_CSV"
        sleep 30
    done
) &
SAMPLER_PID=$!

PAYLOAD_RAW=$(printf '%*s' "$MSG_SIZE" | tr ' ' 'x')
PAYLOAD_B64=$(printf '%s' "$PAYLOAD_RAW" | base64 | tr -d '\n')

SLEEP_SEC=$(awk -v r="$MSG_RATE" 'BEGIN { printf "%.4f", 2.0 / r }')
END=$((START + DURATION_MIN * 60))
COUNT=0
ERRS=0
log "DM ping-pong — total rate=${MSG_RATE}/s, ending at $(date -u -r $END '+%H:%M:%S' 2>/dev/null || date -u --date="@$END" '+%H:%M:%S')"

while [ "$(date +%s)" -lt "$END" ]; do
    # alice -> bob
    OUT=$(api 1 POST /direct/send "{\"agent_id\":\"${AGENTS[1]}\",\"payload\":\"$PAYLOAD_B64\"}" 2>&1) || ERRS=$((ERRS+1))
    case "$OUT" in *'"ok":true'*) ;; *) ERRS=$((ERRS+1));; esac
    sleep "$SLEEP_SEC"
    # bob -> alice
    OUT=$(api 2 POST /direct/send "{\"agent_id\":\"${AGENTS[0]}\",\"payload\":\"$PAYLOAD_B64\"}" 2>&1) || ERRS=$((ERRS+1))
    case "$OUT" in *'"ok":true'*) ;; *) ERRS=$((ERRS+1));; esac
    COUNT=$((COUNT+2))
    sleep "$SLEEP_SEC"
done

log "Sent $COUNT DMs ($ERRS errors) over ${DURATION_MIN}min"

# Post-run diagnostics.
for i in 1 2; do
    api "$i" GET /diagnostics/dm > "$PROOF_DIR/logs/node-$i/dm-post.json" || true
done

if (( IDLE_MIN > 0 )); then
    log "Idle phase ${IDLE_MIN}min — retained vs working-set check"
    sleep $((IDLE_MIN * 60))
fi

kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true

# Summary.
F1=$(awk -F, 'NR==2{print $3}' "$RSS_CSV"); L1=$(awk -F, 'END{print $3}' "$RSS_CSV")
F2=$(awk -F, 'NR==2{print $4}' "$RSS_CSV"); L2=$(awk -F, 'END{print $4}' "$RSS_CSV")
log "alice RSS first=${F1}KB ($((F1/1024))MB) last=${L1}KB ($((L1/1024))MB) delta=$(((L1-F1)/1024))MB"
log "bob   RSS first=${F2}KB ($((F2/1024))MB) last=${L2}KB ($((L2/1024))MB) delta=$(((L2-F2)/1024))MB"
log "Proof dir: $PROOF_DIR"
