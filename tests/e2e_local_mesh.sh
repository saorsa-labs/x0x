#!/usr/bin/env bash
# Local 3-node smoke test for the mesh-relay harness.
#
# Boots alice/bob/charlie x0xd daemons + a runner per daemon, then runs
# tests/e2e_vps_mesh.py against alice with --no-tunnel. Proves the
# command/result protocol without needing the live VPS fleet.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
X0XD="${X0XD:-$ROOT/target/release/x0xd}"
RUNNER="$ROOT/tests/runners/x0x_test_runner.py"

if [ ! -x "$X0XD" ]; then
    echo "x0xd not built at $X0XD — run: cargo build --release --bin x0xd" >&2
    exit 2
fi

NODES=(alice bob charlie)
declare -A API_PORTS=([alice]=23700 [bob]=23701 [charlie]=23702)
declare -A DATA_DIRS
declare -a DAEMON_PIDS RUNNER_PIDS

WORK_DIR=$(mktemp -d -t x0x-mesh-local.XXXXXX)
echo "work_dir=$WORK_DIR"

cleanup() {
    for p in "${RUNNER_PIDS[@]:-}"; do
        kill -9 "$p" 2>/dev/null || true
    done
    for p in "${DAEMON_PIDS[@]:-}"; do
        kill -TERM "$p" 2>/dev/null || true
    done
    sleep 1
    for p in "${DAEMON_PIDS[@]:-}"; do
        kill -9 "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT

token_path() {
    local node="$1"
    echo "$HOME/Library/Application Support/x0x-$node/api-token"
}

# Boot daemons.
for node in "${NODES[@]}"; do
    DATA_DIRS[$node]="$WORK_DIR/$node"
    mkdir -p "${DATA_DIRS[$node]}"
    "$X0XD" \
        --name "$node" \
        --api-port "${API_PORTS[$node]}" \
        --no-hard-coded-bootstrap \
        > "$WORK_DIR/$node.x0xd.log" 2>&1 &
    DAEMON_PIDS+=("$!")
    echo "started daemon $node pid=$! port=${API_PORTS[$node]}"
done

echo "waiting for daemons to bind /health..."
for node in "${NODES[@]}"; do
    port="${API_PORTS[$node]}"
    until curl -sf -m 2 "http://127.0.0.1:$port/health" > /dev/null 2>&1; do
        sleep 1
    done
done

# Cards exchange so the agents know each other's machine_ids.
declare -A TOKENS AIDS CARDS
for node in "${NODES[@]}"; do
    tk_file="$(token_path "$node")"
    until [ -s "$tk_file" ]; do sleep 1; done
    TOKENS[$node]="$(cat "$tk_file")"
    port="${API_PORTS[$node]}"
    AIDS[$node]="$(curl -sf -H "Authorization: Bearer ${TOKENS[$node]}" \
        "http://127.0.0.1:$port/agent" \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['agent_id'])")"
    CARDS[$node]="$(curl -sf -H "Authorization: Bearer ${TOKENS[$node]}" \
        "http://127.0.0.1:$port/agent/card")"
    echo "$node aid=${AIDS[$node]:0:16}…"
done

for src in "${NODES[@]}"; do
    for dst in "${NODES[@]}"; do
        [ "$src" = "$dst" ] && continue
        curl -sf -X POST \
            -H "Authorization: Bearer ${TOKENS[$src]}" \
            -H "Content-Type: application/json" \
            -d "${CARDS[$dst]}" \
            "http://127.0.0.1:${API_PORTS[$src]}/agent/card/import" \
            > /dev/null
    done
done
echo "card exchange complete"

# Connect everyone to alice for the demo.
for src in bob charlie; do
    curl -sf -X POST \
        -H "Authorization: Bearer ${TOKENS[$src]}" \
        -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"${AIDS[alice]}\"}" \
        "http://127.0.0.1:${API_PORTS[$src]}/connect" > /dev/null || true
done
curl -sf -X POST \
    -H "Authorization: Bearer ${TOKENS[alice]}" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"${AIDS[bob]}\"}" \
    "http://127.0.0.1:${API_PORTS[alice]}/connect" > /dev/null || true
curl -sf -X POST \
    -H "Authorization: Bearer ${TOKENS[alice]}" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"${AIDS[charlie]}\"}" \
    "http://127.0.0.1:${API_PORTS[alice]}/connect" > /dev/null || true

sleep 2

# Boot one runner per daemon.
for node in "${NODES[@]}"; do
    NODE_NAME="$node" \
    X0X_API_BASE="http://127.0.0.1:${API_PORTS[$node]}" \
    X0X_API_TOKEN="${TOKENS[$node]}" \
        python3 "$RUNNER" \
        > "$WORK_DIR/$node.runner.log" 2>&1 &
    RUNNER_PIDS+=("$!")
    echo "started runner $node pid=$!"
done

sleep 3

echo "==== running mesh harness ===="
python3 "$ROOT/tests/e2e_vps_mesh.py" \
    --no-tunnel \
    --anchor alice \
    --api-base "http://127.0.0.1:${API_PORTS[alice]}" \
    --api-token "${TOKENS[alice]}" \
    --nodes "${NODES[@]}" \
    --discover-secs 15 \
    --settle-secs 30
RC=$?
echo "==== mesh harness exit=$RC ===="

if [ $RC -ne 0 ]; then
    for node in "${NODES[@]}"; do
        echo "--- runner log: $node (last 20) ---"
        tail -20 "$WORK_DIR/$node.runner.log"
    done
fi

exit $RC
