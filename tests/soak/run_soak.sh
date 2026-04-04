#!/usr/bin/env bash
# x0x soak test orchestrator
#
# Starts 3 agents, runs k6 soak tests, monitors memory/connections,
# verifies state consistency after the run.
#
# Usage:
#   bash tests/soak/run_soak.sh                    # default 1hr
#   bash tests/soak/run_soak.sh --duration 5m      # quick soak
#   bash tests/soak/run_soak.sh --duration 1h --script mixed_workload.js
#
# Prerequisites:
#   - cargo build --release --bin x0xd --bin x0x
#   - k6 installed (zb install k6 or brew install k6)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)"
DURATION="1h"
K6_SCRIPT="mixed_workload.js"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --script)   K6_SCRIPT="$2"; shift 2 ;;
        *)          echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$RESULTS_DIR"
echo "=== x0x Soak Test ==="
echo "Duration: $DURATION"
echo "Script:   $K6_SCRIPT"
echo "Results:  $RESULTS_DIR"
echo ""

# ── Check prerequisites ─────────────────────────────────────────────────

BINARY="$PROJECT_DIR/target/release/x0xd"
if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: x0xd not found. Run: cargo build --release --bin x0xd"
    exit 1
fi

if ! command -v k6 &>/dev/null; then
    echo "ERROR: k6 not found. Install: zb install k6"
    exit 1
fi

# ── Start 3 agents ──────────────────────────────────────────────────────

TMPDIR=$(mktemp -d)
PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$TMPDIR"
    echo "Done."
}
trap cleanup EXIT

start_agent() {
    local name="$1"
    local api_port="$2"
    local bind_port="$3"
    local bootstrap="$4"

    local config="$TMPDIR/$name.toml"
    local data_dir="$TMPDIR/$name-data"
    mkdir -p "$data_dir"

    cat > "$config" <<TOML
api_address = "127.0.0.1:$api_port"
bind_address = "0.0.0.0:$bind_port"
data_dir = "$data_dir"
log_level = "warn"
$bootstrap
TOML

    "$BINARY" --config "$config" --name "$name" &
    local pid=$!
    PIDS+=("$pid")

    # Wait for health
    local deadline=$((SECONDS + 30))
    while ! curl -sf "http://127.0.0.1:$api_port/health" >/dev/null 2>&1; do
        if [[ $SECONDS -ge $deadline ]]; then
            echo "ERROR: $name failed to start within 30s"
            exit 1
        fi
        sleep 0.5
    done

    # Read API token
    local token_file="$data_dir/api-token"
    if [[ -f "$token_file" ]]; then
        cat "$token_file"
    else
        echo ""
    fi
}

# Rolling start: nodes need ~15s between launches to allow QUIC listeners
# to bind and the gossip mesh to stabilise. Starting simultaneously causes
# connection races and mesh instability.
ROLLING_DELAY=15

echo "Starting alice (port 19101)..."
ALICE_TOKEN=$(start_agent "soak-alice" 19101 19001 "")
echo "Waiting ${ROLLING_DELAY}s for alice to stabilise..."
sleep "$ROLLING_DELAY"

echo "Starting bob (port 19102, bootstraps to alice)..."
BOB_TOKEN=$(start_agent "soak-bob" 19102 19002 'bootstrap_peers = ["127.0.0.1:19001"]')
echo "Waiting ${ROLLING_DELAY}s for bob to join mesh..."
sleep "$ROLLING_DELAY"

echo "Starting charlie (port 19103, bootstraps to alice)..."
CHARLIE_TOKEN=$(start_agent "soak-charlie" 19103 19003 'bootstrap_peers = ["127.0.0.1:19001"]')
echo "Waiting 5s for mesh to settle..."
sleep 5

echo "All agents running. Verifying mesh connectivity..."

# Enforce mesh: each node must see at least one peer.
# A disconnected cluster makes soak results meaningless.
for port in 19101 19102 19103; do
    TOKEN_VAR="ALICE_TOKEN"
    [[ $port == 19102 ]] && TOKEN_VAR="BOB_TOKEN"
    [[ $port == 19103 ]] && TOKEN_VAR="CHARLIE_TOKEN"
    TOKEN="${!TOKEN_VAR}"

    MESH_DEADLINE=$((SECONDS + 30))
    while true; do
        PEERS=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$port/peers" 2>/dev/null || echo '[]')
        PEER_COUNT=$(echo "$PEERS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get('peers',d.get('connected',[]))))" 2>/dev/null || echo "0")
        if [[ "$PEER_COUNT" -gt 0 ]]; then
            echo "  :$port sees $PEER_COUNT peer(s)"
            break
        fi
        if [[ $SECONDS -ge $MESH_DEADLINE ]]; then
            echo "ERROR: node on :$port has zero peers after 30s — mesh is disconnected"
            echo "Soak test requires a connected cluster. Aborting."
            exit 1
        fi
        sleep 1
    done
done
echo "Mesh verified — all 3 nodes connected."
echo ""

# ── Record initial state ────────────────────────────────────────────────

record_rss() {
    local label="$1"
    for pid in "${PIDS[@]}"; do
        local rss=$(ps -o rss= -p "$pid" 2>/dev/null || echo "0")
        echo "$label,$pid,$rss" >> "$RESULTS_DIR/memory.csv"
    done
}

echo "timestamp,pid,rss_kb" > "$RESULTS_DIR/memory.csv"
record_rss "initial"

INITIAL_RSS=()
for pid in "${PIDS[@]}"; do
    rss=$(ps -o rss= -p "$pid" 2>/dev/null || echo "0")
    INITIAL_RSS+=("$rss")
done

echo "Initial RSS (KB): ${INITIAL_RSS[*]}"

# ── Start memory sampling (background) ──────────────────────────────────

(
    while true; do
        sleep 60
        record_rss "$(date +%s)"
    done
) &
SAMPLER_PID=$!

# ── Run k6 ──────────────────────────────────────────────────────────────

echo ""
echo "=== Running k6: $K6_SCRIPT for $DURATION ==="
echo ""

k6 run \
    --env "X0X_API=http://127.0.0.1:19101" \
    --env "X0X_TOKEN=$ALICE_TOKEN" \
    --env "DURATION=$DURATION" \
    --summary-export "$RESULTS_DIR/k6-summary.json" \
    "$SCRIPT_DIR/k6/$K6_SCRIPT" \
    2>&1 | tee "$RESULTS_DIR/k6-output.txt"

K6_EXIT=$?

# Stop memory sampler
kill "$SAMPLER_PID" 2>/dev/null || true

# ── Record final state ──────────────────────────────────────────────────

record_rss "final"

echo ""
echo "=== Post-Soak Verification ==="

PASS=0
FAIL=0

check() {
    local name="$1"
    local result="$2"
    if [[ "$result" == "ok" ]]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name — $result"
        FAIL=$((FAIL + 1))
    fi
}

# ── Memory leak detection ───────────────────────────────────────────────

for i in "${!PIDS[@]}"; do
    pid="${PIDS[$i]}"
    initial="${INITIAL_RSS[$i]}"
    final=$(ps -o rss= -p "$pid" 2>/dev/null || echo "0")
    final=$(echo "$final" | tr -d ' ')
    initial=$(echo "$initial" | tr -d ' ')

    if [[ "$initial" -gt 0 && "$final" -gt 0 ]]; then
        ratio=$((final * 100 / initial))
        if [[ $ratio -le 300 ]]; then
            check "Memory PID $pid (${ratio}% of initial)" "ok"
        else
            check "Memory PID $pid (${ratio}% of initial, limit 300%)" "grew too much"
        fi
    fi
done

# ── WebSocket session leak detection ────────────────────────────────────

WS_SESSIONS=$(curl -sf -H "Authorization: Bearer $ALICE_TOKEN" "http://127.0.0.1:19101/ws/sessions" 2>/dev/null || echo '{"sessions":[]}')
SESSION_COUNT=$(echo "$WS_SESSIONS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('sessions',d.get('active',[]))))" 2>/dev/null || echo "0")
if [[ "$SESSION_COUNT" -eq 0 ]]; then
    check "No leaked WS sessions" "ok"
else
    check "No leaked WS sessions ($SESSION_COUNT remaining)" "leaked"
fi

# ── Health check all agents ─────────────────────────────────────────────

for port in 19101 19102 19103; do
    if curl -sf "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
        check "Agent on :$port healthy" "ok"
    else
        check "Agent on :$port healthy" "unreachable"
    fi
done

# ── k6 exit code ────────────────────────────────────────────────────────

if [[ "$K6_EXIT" -eq 0 ]]; then
    check "k6 thresholds met" "ok"
else
    check "k6 thresholds met" "thresholds exceeded (exit $K6_EXIT)"
fi

# ── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Results: $RESULTS_DIR"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "SOAK TEST FAILED"
    exit 1
else
    echo "SOAK TEST PASSED"
fi
