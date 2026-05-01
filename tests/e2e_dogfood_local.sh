#!/usr/bin/env bash
# Phase-D fast 2-instance dogfood smoke (~30 s wall-clock target).
#
# Boots alice + bob locally, exchanges agent cards, starts the Phase-A
# runner on bob's daemon, then drives every assertion through DMs from
# alice (the anchor) to bob via tests/e2e_dogfood_local.py.
#
# Designed as a pre-commit-friendly smoke: no SSH, no VPS, no curl-out.
# All test assertions exercise x0x's own protocol surface.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
X0XD="${X0XD:-$ROOT/target/release/x0xd}"
RUNNER="$ROOT/tests/runners/x0x_test_runner.py"
ORCHESTRATOR="$ROOT/tests/e2e_dogfood_local.py"
BUDGET_SECS="${PHASE_D_BUDGET_SECS:-60}"

if [ ! -x "$X0XD" ]; then
    echo "x0xd not built at $X0XD — run: cargo build --release --bin x0xd" >&2
    exit 2
fi

NODES=(alice bob)
declare -A API_PORTS=([alice]=25700 [bob]=25701)
declare -a DAEMON_PIDS=()
declare -a RUNNER_PIDS=()

WORK_DIR=$(mktemp -d -t x0x-dogfood-local.XXXXXX)
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
    echo "$HOME/Library/Application Support/x0x-$1/api-token"
}

t0=$(date +%s)

# 1. Boot daemons.
for node in "${NODES[@]}"; do
    "$X0XD" \
        --name "$node" \
        --api-port "${API_PORTS[$node]}" \
        --no-hard-coded-bootstrap \
        > "$WORK_DIR/$node.x0xd.log" 2>&1 &
    DAEMON_PIDS+=("$!")
done
echo "spawned daemons in $(($(date +%s) - t0))s"

for node in "${NODES[@]}"; do
    until curl -sf -m 2 "http://127.0.0.1:${API_PORTS[$node]}/health" \
        > /dev/null 2>&1; do
        sleep 1
    done
done
echo "daemons healthy in $(($(date +%s) - t0))s"

# 2. Tokens, agent ids, cards.
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

curl -sf -X POST \
    -H "Authorization: Bearer ${TOKENS[alice]}" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"${AIDS[bob]}\"}" \
    "http://127.0.0.1:${API_PORTS[alice]}/connect" > /dev/null || true
sleep 1

# 3. Boot bob's runner. Alice doesn't need a runner — she's the
# orchestrator and uses the local-API short-circuit for her own actions.
NODE_NAME=bob \
X0X_API_BASE="http://127.0.0.1:${API_PORTS[bob]}" \
X0X_API_TOKEN="${TOKENS[bob]}" \
    python3 "$RUNNER" > "$WORK_DIR/bob.runner.log" 2>&1 &
RUNNER_PIDS+=("$!")

sleep 2
echo "ready in $(($(date +%s) - t0))s — invoking orchestrator"

# 4. Drive every assertion via DMs.
python3 "$ORCHESTRATOR" \
    --api-base "http://127.0.0.1:${API_PORTS[alice]}" \
    --api-token "${TOKENS[alice]}" \
    --anchor alice \
    --peer-name bob \
    --peer-aid "${AIDS[bob]}" \
    --cmd-timeout 15 \
    --budget-secs "$BUDGET_SECS" \
    --report "$WORK_DIR/dogfood-local.json"
RC=$?

elapsed=$(($(date +%s) - t0))
echo "==== Phase-D smoke exit=$RC total wall-clock=${elapsed}s ===="

if [ $RC -ne 0 ]; then
    echo "--- bob runner log (last 20) ---"
    tail -20 "$WORK_DIR/bob.runner.log"
fi

exit $RC
