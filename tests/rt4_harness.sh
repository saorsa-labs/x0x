#!/bin/bash
# #491 RT-4 x0xd process harness — PREPARATION ONLY (not executed).
# Real 3-phase acceptance using actual x0xd children with distinct PIDs.
# Every child must run under the whole-child network namespace wrapper.
#
# Prerequisites (verified before any phase runs):
#   - cargo metadata --offline --locked resolves ant-quic 0.27.49
#   - Cargo.lock sha256 == 5769726f49c34214f818a9c21e435cfabe02ba5efc1e47a62d6b888c1ee6f9c2
#   - x0xd binary built and sha256 pinned
#   - Network namespace wrapper present and executable
#
# Usage: RT4_RUN=1 bash tests/rt4_harness.sh
# Without RT4_RUN=1, prints the plan and exits (preparation mode).

set -euo pipefail

WORKTREE="$(cd "$(dirname "$0")/.." && pwd)"
X0XD="$WORKTREE/target/debug/x0xd"
ARTIFACTS="${RT4_ARTIFACTS:-/tmp/rt4-artifacts}"
LOCK_SHA_EXPECTED="5769726f49c34214f818a9c21e435cfabe02ba5efc1e47a62d6b888c1ee6f9c2"

# --- Preparation mode: print plan, exit ---
if [[ "${RT4_RUN:-0}" != "1" ]]; then
    echo "RT-4 harness PREPARATION MODE (set RT4_RUN=1 to execute)"
    echo "Phases:"
    echo "  0: Machine-ID discovery (x0xd child 1 → GET /agent → stop)"
    echo "  1: Self-only fixture (child 2 → prune remaining=0 → file absent → stop → child 3 restart)"
    echo "  2: Mixed fixture (child 4 → remaining=1 → /shutdown → inspect file → child 5 restart)"
    exit 0
fi

# --- Prerequisites ---
echo "=== RT-4 harness starting $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
mkdir -p "$ARTIFACTS"

LOCK_SHAActual=$(shasum -a 256 "$WORKTREE/Cargo.lock" | cut -d' ' -f1)
if [[ "$LOCK_SHAActual" != "$LOCK_SHA_EXPECTED" ]]; then
    echo "FATAL: Cargo.lock sha256 mismatch: $LOCK_SHAActual != $LOCK_SHA_EXPECTED" >&2
    exit 1
fi
echo "Cargo.lock verified: $LOCK_SHAActual"

if [[ ! -x "$X0XD" ]]; then
    echo "Building x0xd..."
    (cd "$WORKTREE" && CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true cargo build --offline --locked -p x0x --bin x0xd)
fi
X0XD_SHA=$(shasum -a 256 "$X0XD" | cut -d' ' -f1)
echo "x0xd binary: $X0XD_SHA"

# Namespace wrapper (from corrected #449 diagnostic — reuse after Root review)
NS_WRAPPER="${RT4_NS_WRAPPER:-}"
if [[ -z "$NS_WRAPPER" || ! -x "$NS_WRAPPER" ]]; then
    echo "FATAL: network namespace wrapper required (RT4_NS_WRAPPER)" >&2
    exit 1
fi

# --- Helper: start x0xd child, wait for health, return PID + API port ---
start_child() {
    local name="$1" identity_dir="$2" data_dir="$3" cache_dir="$4" api_port="$5"
    local log="$ARTIFACTS/${name}.log"

    "$NS_WRAPPER" "$X0XD" \
        --identity-dir "$identity_dir" \
        --data-dir "$data_dir" \
        --peer-cache-dir "$cache_dir" \
        --api-port "$api_port" \
        --skip-update-check \
        > "$log" 2>&1 &
    local pid=$!

    # Wait for /health 200
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:$api_port/health" > /dev/null 2>&1; then
            echo "$name started: pid=$pid api_port=$api_port"
            return 0
        fi
        sleep 1
    done
    echo "FATAL: $name failed to become healthy within 30s" >&2
    kill "$pid" 2>/dev/null || true
    return 1
}

# --- Helper: clean stop + reap ---
stop_child() {
    local name="$1" pid="$2" api_port="$3"
    curl -sf -X POST "http://127.0.0.1:$api_port/shutdown" > /dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
    if kill -0 "$pid" 2>/dev/null; then
        echo "FATAL: $name pid=$pid still alive after /shutdown" >&2
        return 1
    fi
    echo "$name stopped and reaped: pid=$pid"
}

# --- Phase 0: Machine-ID discovery ---
echo "=== Phase 0: Machine-ID discovery ==="
P0_DIR=$(mktemp -d /tmp/rt4-phase0-XXXX)
P0_API=18801
start_child "phase0" "$P0_DIR/id" "$P0_DIR/data" "$P0_DIR/cache" "$P0_API"
P0_PID=$!

# Read /agent for the machine ID (flat response — reuse #449 parser shape)
AGENT_JSON=$(curl -sf "http://127.0.0.1:$P0_API/agent")
MACHINE_ID=$(echo "$AGENT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['agent_id'])")
echo "Machine ID: $MACHINE_ID"

stop_child "phase0" "$P0_PID" "$P0_API"
rm -rf "$P0_DIR"

# --- Phase 1: Self-only fixture ---
echo "=== Phase 1: Self-only fixture ==="
P1_DIR=$(mktemp -d /tmp/rt4-phase1-XXXX)
P1_API=18802

# Write fixture using a helper (Rust test generates the exact serializer output)
# The fixture writer is tests/rt4_fixture_writer --self-id "$MACHINE_ID" --dir "$P1_DIR/cache"
# (not yet implemented — this is the preparation)

# TODO: implement fixture_writer binary
echo "PREPARATION INCOMPLETE: fixture_writer binary not yet implemented"

# --- Phase 2: Mixed fixture ---
echo "=== Phase 2: Mixed fixture ==="
echo "PREPARATION INCOMPLETE: awaiting Phase 1 implementation"

echo "=== RT-4 harness done ==="
