#!/usr/bin/env bash
# Stress test the x0x gossip pipeline against drop-detection counters.
#
# Launches N daemons on loopback, subscribes to a test topic on each,
# publishes M messages from one daemon, then waits for delivery. The
# /diagnostics/gossip endpoint proves zero drops between publish and
# subscriber delivery.
#
# Usage:
#   tests/e2e_stress_gossip.sh [--nodes 3] [--messages 1000] \
#       [--topic gossip-stress] [--proof-dir proofs/stress-<ts>] [--slow-subscriber]

set -euo pipefail

NODES=3
MESSAGES=1000
TOPIC="gossip-stress-$$"
PROOF_DIR=""
SLOW_SUBSCRIBER=0
# Minimum per-subscriber delivery fraction (0.0 - 1.0). Default 1.0 = every
# subscriber must deliver >= MESSAGES. Relax only when you are deliberately
# measuring under-saturation (e.g. deliberate overload).
MIN_DELIVERY_RATIO="${MIN_DELIVERY_RATIO:-1.0}"

while (( "$#" )); do
    case "$1" in
        --nodes) NODES="$2"; shift 2 ;;
        --messages) MESSAGES="$2"; shift 2 ;;
        --topic) TOPIC="$2"; shift 2 ;;
        --proof-dir) PROOF_DIR="$2"; shift 2 ;;
        --min-delivery-ratio) MIN_DELIVERY_RATIO="$2"; shift 2 ;;
        --slow-subscriber) SLOW_SUBSCRIBER=1; shift ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [ -z "$PROOF_DIR" ]; then
    PROOF_DIR="proofs/stress-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$PROOF_DIR/logs"
LOG="$PROOF_DIR/stress.log"
REPORT="$PROOF_DIR/stress-report.json"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "Stress config: NODES=$NODES MESSAGES=$MESSAGES TOPIC=$TOPIC SLOW_SUBSCRIBER=$SLOW_SUBSCRIBER"
log "Proof dir: $PROOF_DIR"

BIN="${X0XD_BIN:-target/debug/x0xd}"
CLI="${X0X_BIN:-target/debug/x0x}"

if [ ! -x "$BIN" ] || [ ! -x "$CLI" ]; then
    log "Building x0xd + x0x binaries..."
    cargo build --bin x0xd --bin x0x
fi

PIDS=()
SLOW_PIDS=()
TOKENS=()
PORTS=()
cleanup() {
    log "Cleaning up slow subscribers + daemons..."
    for pid in "${SLOW_PIDS[@]}" "${PIDS[@]}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    wait "${SLOW_PIDS[@]}" "${PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT

# Spin up N isolated daemons. Each gets its own identity dir, log file,
# api port, and X0X_LOG_DIR so logs are per-daemon.
for i in $(seq 1 "$NODES"); do
    INSTANCE="stress-$i"
    ID_DIR="$PROOF_DIR/node-$i"
    mkdir -p "$ID_DIR"
    export X0X_IDENTITY_DIR="$ID_DIR"
    export X0X_LOG_DIR="$PROOF_DIR/logs/node-$i"
    mkdir -p "$X0X_LOG_DIR"
    PORT=$((12700 + i))

    log "Launching daemon $i on port $PORT"
    "$BIN" \
        --name "$INSTANCE" \
        --api-port "$PORT" \
        --no-hard-coded-bootstrap \
        > "$PROOF_DIR/logs/node-$i/stdout.log" \
        2> "$PROOF_DIR/logs/node-$i/stderr.log" &
    PIDS+=($!)
    PORTS+=("$PORT")
done

SETTLE_SECS="${SETTLE_SECS:-20}"
log "Waiting ${SETTLE_SECS}s for daemons to bind + discover each other..."
sleep "$SETTLE_SECS"

# Read the auto-generated API tokens. With `--name <instance>`, x0xd writes
# the token to `<dirs::data_dir()>/x0x-<instance>/api-token`. On macOS that
# is `~/Library/Application Support/x0x-<instance>/api-token`; on Linux it
# is `~/.local/share/x0x-<instance>/api-token`.
if [ "$(uname)" = "Darwin" ]; then
    DATA_BASE="$HOME/Library/Application Support"
else
    DATA_BASE="$HOME/.local/share"
fi
for i in $(seq 1 "$NODES"); do
    TOKEN_FILE="$DATA_BASE/x0x-stress-$i/api-token"
    if [ -f "$TOKEN_FILE" ]; then
        TOKENS+=("$(cat "$TOKEN_FILE")")
    else
        log "warn: no api-token at $TOKEN_FILE — skipping token auth for node $i"
        TOKENS+=("")
    fi
done

api() {
    local idx="$1" method="$2" path="$3" body="${4:-}"
    local port="${PORTS[$((idx - 1))]}"
    local token="${TOKENS[$((idx - 1))]}"
    local args=(-sS -X "$method" "http://127.0.0.1:${port}${path}")
    [ -n "$token" ] && args+=(-H "authorization: Bearer $token")
    [ -n "$body" ] && args+=(-H "content-type: application/json" -d "$body")
    curl "${args[@]}"
}

# Subscribe every node to the topic.
for i in $(seq 1 "$NODES"); do
    api "$i" POST /subscribe "{\"topic\":\"$TOPIC\"}" > "$PROOF_DIR/logs/node-$i/subscribe.json" || true
done

if (( SLOW_SUBSCRIBER == 1 )); then
    slow_idx=2
    if (( NODES < 2 )); then
        slow_idx=1
    fi
    slow_port="${PORTS[$((slow_idx - 1))]}"
    slow_token="${TOKENS[$((slow_idx - 1))]}"
    log "Starting slow SSE subscriber on node-$slow_idx (intentionally reads one event/sec)"
    python3 - "$slow_port" "$slow_token" > "$PROOF_DIR/logs/node-$slow_idx/slow-subscriber.log" 2>&1 <<'PY' &
import sys
import time
import urllib.request

port = sys.argv[1]
token = sys.argv[2]
req = urllib.request.Request(f"http://127.0.0.1:{port}/events")
if token:
    req.add_header("authorization", f"Bearer {token}")
with urllib.request.urlopen(req, timeout=30) as resp:
    while True:
        line = resp.readline()
        if not line:
            break
        # Deliberately lag the SSE response stream. x0xd should isolate this
        # behind tokio::broadcast lag/drop semantics instead of pinning PubSub.
        time.sleep(1.0)
PY
    SLOW_PIDS+=($!)
    sleep 1
fi

log "Subscriptions installed; snapshotting pre-publish gossip stats"
for i in $(seq 1 "$NODES"); do
    api "$i" GET /diagnostics/gossip > "$PROOF_DIR/logs/node-$i/gossip-pre.json" || true
done

# Publisher = node 1. Fire $MESSAGES messages. Payload is base64-encoded
# per the x0xd /publish contract. PUBLISH_DELAY_MS pauses between each
# publish to let the mesh drain — default 0 for stress, 20ms for fair
# delivery-ratio measurement.
PUBLISH_DELAY_MS="${PUBLISH_DELAY_MS:-0}"
log "Publishing $MESSAGES messages from node 1 to topic $TOPIC (delay ${PUBLISH_DELAY_MS}ms)"
start_ts=$(date +%s)
for n in $(seq 1 "$MESSAGES"); do
    PAYLOAD=$(printf 'msg-%d' "$n" | base64 | tr -d '\n')
    api 1 POST /publish \
        "{\"topic\":\"$TOPIC\",\"payload\":\"$PAYLOAD\"}" >/dev/null 2>&1 || true
    if (( PUBLISH_DELAY_MS > 0 )); then
        python3 -c "import time; time.sleep(${PUBLISH_DELAY_MS}/1000.0)" 2>/dev/null || sleep 0.02
    fi
done
end_ts=$(date +%s)
elapsed=$((end_ts - start_ts))
log "Published $MESSAGES msgs in ${elapsed}s ($(( MESSAGES / (elapsed > 0 ? elapsed : 1) )) msgs/s)"

log "Sleeping 5s for delivery to drain..."
sleep 5

# Snapshot post-publish gossip stats.
declare -a POST_PUB=()
declare -a POST_DELIV=()
declare -a POST_DROPS=()
declare -a POST_SLOW=()
for i in $(seq 1 "$NODES"); do
    api "$i" GET /diagnostics/gossip > "$PROOF_DIR/logs/node-$i/gossip-post.json" || true
    PUB=$(jq -r '.stats.publish_total // 0' "$PROOF_DIR/logs/node-$i/gossip-post.json" 2>/dev/null || echo 0)
    DEL=$(jq -r '.stats.delivered_to_subscriber // 0' "$PROOF_DIR/logs/node-$i/gossip-post.json" 2>/dev/null || echo 0)
    DROPS=$(jq -r '.stats.decode_to_delivery_drops // 0' "$PROOF_DIR/logs/node-$i/gossip-post.json" 2>/dev/null || echo 0)
    SLOW=$(jq -r '.stats.slow_subscriber_dropped // 0' "$PROOF_DIR/logs/node-$i/gossip-post.json" 2>/dev/null || echo 0)
    POST_PUB+=("$PUB")
    POST_DELIV+=("$DEL")
    POST_DROPS+=("$DROPS")
    POST_SLOW+=("$SLOW")
    log "node-$i: publish=$PUB delivered=$DEL drops=$DROPS slow_subscriber_dropped=$SLOW"
done

# Report JSON.
{
    printf '{"nodes":%s,"messages":%s,"topic":"%s","elapsed_seconds":%s,"slow_subscriber":%s,"per_node":[' \
        "$NODES" "$MESSAGES" "$TOPIC" "$elapsed" "$SLOW_SUBSCRIBER"
    for i in $(seq 1 "$NODES"); do
        [ $i -gt 1 ] && printf ','
        printf '{"idx":%s,"publish_total":%s,"delivered_to_subscriber":%s,"decode_to_delivery_drops":%s,"slow_subscriber_dropped":%s}' \
            "$i" "${POST_PUB[$((i - 1))]}" "${POST_DELIV[$((i - 1))]}" "${POST_DROPS[$((i - 1))]}" "${POST_SLOW[$((i - 1))]}"
    done
    printf ']}\n'
} > "$REPORT"

log "Stress report → $REPORT"

# Acceptance gates:
#   1. Publisher `publish_total` >= MESSAGES.
#   2. Every subscriber's `delivered_to_subscriber` >= MESSAGES * MIN_DELIVERY_RATIO.
#   3. `decode_to_delivery_drops` == 0 on every node (pipeline integrity).
#
# MIN_DELIVERY_RATIO defaults to 1.0 so runs that fail end-to-end delivery
# surface as failures, not silent under-delivery like earlier proof
# artefacts (e.g. proofs/stress-20260420-085405/stress-report.json where
# subscribers only delivered 106/200 yet the run exited 0).
PUB1=${POST_PUB[0]}
FAIL=0
if (( PUB1 < MESSAGES )); then
    log "FAIL: publisher only recorded $PUB1 of $MESSAGES publishes"
    FAIL=1
fi
# Subscriber-side threshold: every NON-publisher node must deliver
# MESSAGES * MIN_DELIVERY_RATIO (integer floor). The publisher's own
# `delivered_to_subscriber` includes self-subscription echo + internal
# traffic and is not held to this bar.
THRESHOLD=$(awk -v m="$MESSAGES" -v r="$MIN_DELIVERY_RATIO" \
    'BEGIN { printf "%d\n", int(m * r) }')
log "Subscriber acceptance threshold: $THRESHOLD (MIN_DELIVERY_RATIO=$MIN_DELIVERY_RATIO)"
for i in $(seq 2 "$NODES"); do
    DEL="${POST_DELIV[$((i - 1))]}"
    if (( DEL < THRESHOLD )); then
        log "FAIL: node-$i delivered $DEL < $THRESHOLD (target $MESSAGES)"
        FAIL=1
    fi
done
for i in $(seq 1 "$NODES"); do
    if [ "${POST_DROPS[$((i - 1))]}" != "0" ]; then
        log "FAIL: node-$i reports ${POST_DROPS[$((i - 1))]} decode→delivery drops"
        FAIL=1
    fi
done

exit $FAIL
