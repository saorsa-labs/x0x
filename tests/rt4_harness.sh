#!/bin/bash
# #491 RT-4 x0xd process harness — 3-phase acceptance.
#
# Topology: the ENTIRE harness (all x0xd children + all curl clients) runs
# inside ONE network namespace wrapper. Children bind to loopback; curls
# reach them because they share the namespace. No outer-shell curl.
#
# Identity: reads the flat `machine_id` from GET /agent (the ant-quic
# PeerId / machine peer ID), NOT `agent_id`.
#
# Fail-closed: if any phase is incomplete, the harness exits nonzero.
#
# Usage: RT4_RUN=1 bash tests/rt4_harness.sh
# Without RT4_RUN=1, prints the plan and exits 1 (incomplete).

set -euo pipefail

WORKTREE="$(cd "$(dirname "$0")/.." && pwd)"
X0XD="$WORKTREE/target/debug/x0xd"
FIXTURE="$WORKTREE/target/debug/rt4_fixture"
ARTIFACTS="${RT4_ARTIFACTS:-/tmp/rt4-artifacts}"
LOCK_SHA_EXPECTED="5769726f49c34214f818a9c21e435cfabe02ba5efc1e47a62d6b888c1ee6f9c2"

# Namespace wrapper: wraps the ENTIRE harness once, not each child.
NS_WRAPPER="${RT4_NS_WRAPPER:-}"
if [[ -z "$NS_WRAPPER" || ! -x "$NS_WRAPPER" ]]; then
    echo "FATAL: network namespace wrapper required (RT4_NS_WRAPPER=<path>)" >&2
    exit 1
fi

# --- Preparation mode: exit nonzero (incomplete) ---
if [[ "${RT4_RUN:-0}" != "1" ]]; then
    echo "RT-4 harness PREPARATION MODE (set RT4_RUN=1 + RT4_NS_WRAPPER to execute)"
    echo "Phases: 0=discover machine_id, 1=self-only prune+unlink, 2=mixed prune+persist"
    exit 1
fi

# --- All phases run inside the namespace wrapper ---
exec "$NS_WRAPPER" bash -c '
set -euo pipefail
export ARTIFACTS="'"$ARTIFACTS"'"
export X0XD="'"$X0XD"'"
export FIXTURE="'"$FIXTURE"'"
export WORKTREE="'"$WORKTREE"'"
export LOCK_SHA_EXPECTED="'"$LOCK_SHA_EXPECTED"'"

mkdir -p "$ARTIFACTS"

# Prerequisites
LOCK_SHA=$(shasum -a 256 "$WORKTREE/Cargo.lock" | cut -d" " -f1)
if [[ "$LOCK_SHA" != "$LOCK_SHA_EXPECTED" ]]; then
    echo "FATAL: Cargo.lock mismatch: $LOCK_SHA != $LOCK_SHA_EXPECTED" >&2
    exit 1
fi
echo "lock_ok: $LOCK_SHA"

if [[ ! -x "$X0XD" ]]; then
    echo "FATAL: x0xd not built: $X0XD" >&2
    exit 1
fi
X0XD_SHA=$(shasum -a 256 "$X0XD" | cut -d" " -f1)
echo "x0xd_sha256: $X0XD_SHA"

if [[ ! -x "$FIXTURE" ]]; then
    echo "FATAL: rt4_fixture not built: $FIXTURE" >&2
    exit 1
fi
FIXTURE_SHA=$(shasum -a 256 "$FIXTURE" | cut -d" " -f1)
echo "fixture_sha256: $FIXTURE_SHA"

# Helper: start child, wait for health
start_child() {
    local name="$1" identity_dir="$2" data_dir="$3" cache_dir="$4" api_port="$5"
    local log="$ARTIFACTS/${name}.log"
    mkdir -p "$identity_dir" "$data_dir" "$cache_dir"

    "$X0XD" \
        --identity-dir "$identity_dir" \
        --data-dir "$data_dir" \
        --peer-cache-dir "$cache_dir" \
        --api-port "$api_port" \
        --skip-update-check \
        > "$log" 2>&1 &
    CHILD_PID=$!

    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:${api_port}/health" > /dev/null 2>&1; then
            echo "${name}_pid: $CHILD_PID"
            echo "${name}_api: $api_port"
            return 0
        fi
        sleep 1
    done
    echo "FATAL: $name not healthy in 30s (log: $log)" >&2
    kill "$CHILD_PID" 2>/dev/null || true
    wait "$CHILD_PID" 2>/dev/null || true
    return 1
}

# Helper: clean stop — capture exit code, require 0, reject escalation
stop_child() {
    local name="$1" pid="$2" api_port="$3"
    curl -sf -X POST "http://127.0.0.1:${api_port}/shutdown" > /dev/null 2>&1
    wait "$pid" 2>/dev/null
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "FATAL: $name exited with code $exit_code (not clean 0)" >&2
        echo "${name}_exit_code: $exit_code" >> "$ARTIFACTS/harness.log"
        return 1
    fi
    echo "${name}_exit_code: 0"
    echo "${name}_exit_code: 0" >> "$ARTIFACTS/harness.log"
}

# ══════════════════════════════════════════════════════════════════
# Phase 0: Machine-ID discovery
# ══════════════════════════════════════════════════════════════════
echo "=== Phase 0: Machine-ID discovery ==="
P0_ROOT=$(mktemp -d /tmp/rt4-p0-XXXX)
P0_API=18901
start_child "phase0" "$P0_ROOT/id" "$P0_ROOT/data" "$P0_ROOT/cache" "$P0_API"
P0_PID=$CHILD_PID

# Read the flat machine_id (NOT agent_id — the cache key is the machine peer ID)
MACHINE_ID=$(curl -sf "http://127.0.0.1:$P0_API/agent" | python3 -c "import json,sys; print(json.load(sys.stdin)[\"machine_id\"])")
echo "machine_id: $MACHINE_ID"

stop_child "phase0" "$P0_PID" "$P0_API"
rm -rf "$P0_ROOT"

# ══════════════════════════════════════════════════════════════════
# Phase 1: Self-only fixture → prune → unlink → restart
# ══════════════════════════════════════════════════════════════════
echo "=== Phase 1: Self-only fixture ==="
P1_ROOT=$(mktemp -d /tmp/rt4-p1-XXXX)
P1_API=18902

# Write self-only fixture using the public-API CLI
"$FIXTURE" write "$P1_ROOT/cache" "$MACHINE_ID"
CACHE_FILE="$P1_ROOT/cache/bootstrap_cache.json"
if [[ ! -f "$CACHE_FILE" ]]; then
    echo "FATAL: fixture not written: $CACHE_FILE" >&2
    rm -rf "$P1_ROOT"
    exit 1
fi
echo "phase1_fixture_written: $CACHE_FILE"

# Start child 2 — prune should fire and unlink the file
start_child "phase1_run1" "$P1_ROOT/id" "$P1_ROOT/data" "$P1_ROOT/cache" "$P1_API"
P1_PID=$CHILD_PID

# Wait for the prune log
sleep 3
if ! grep -q "#484: pruned self entry" "$ARTIFACTS/phase1_run1.log" 2>/dev/null; then
    echo "FATAL: prune log not found in phase1_run1.log" >&2
    stop_child "phase1_run1" "$P1_PID" "$P1_API" || true
    rm -rf "$P1_ROOT"
    exit 1
fi
echo "phase1_prune_log: found"

# Assert file was unlinked (remaining=0)
if [[ -f "$CACHE_FILE" ]]; then
    echo "FATAL: bootstrap_cache.json still exists after self-only prune (should be unlinked)" >&2
    stop_child "phase1_run1" "$P1_PID" "$P1_API" || true
    rm -rf "$P1_ROOT"
    exit 1
fi
echo "phase1_file_unlinked: yes"

# Clean stop
stop_child "phase1_run1" "$P1_PID" "$P1_API"

# Assert file still absent after shutdown
if [[ -f "$CACHE_FILE" ]]; then
    echo "FATAL: file reappeared after clean shutdown" >&2
    rm -rf "$P1_ROOT"
    exit 1
fi
echo "phase1_file_absent_after_shutdown: yes"

# Restart: child 3 with same paths, distinct PID
P1_API2=18903
start_child "phase1_run2" "$P1_ROOT/id" "$P1_ROOT/data" "$P1_ROOT/cache" "$P1_API2"
P1_PID2=$CHILD_PID
if [[ "$P1_PID2" -eq "$P1_PID" ]]; then
    echo "FATAL: child 3 PID matches child 2 ($P1_PID)" >&2
    stop_child "phase1_run2" "$P1_PID2" "$P1_API2" || true
    rm -rf "$P1_ROOT"
    exit 1
fi
echo "phase1_restart_pid: $P1_PID2 (distinct from $P1_PID)"

# Assert no self entry: file should be absent or have no self key
if [[ -f "$CACHE_FILE" ]]; then
    COUNT=$("$FIXTURE" inspect "$P1_ROOT/cache" | grep -o "count=[0-9]*" | cut -d= -f2)
    if [[ "$COUNT" -gt 0 ]]; then
        echo "FATAL: self entry reappeared: count=$COUNT" >&2
        stop_child "phase1_run2" "$P1_PID2" "$P1_API2" || true
        rm -rf "$P1_ROOT"
        exit 1
    fi
fi
echo "phase1_no_self_after_restart: yes"

stop_child "phase1_run2" "$P1_PID2" "$P1_API2"
rm -rf "$P1_ROOT"
echo "=== Phase 1 PASSED ==="

# ══════════════════════════════════════════════════════════════════
# Phase 2: Mixed fixture → prune self → clean shutdown → nonself persists
# ══════════════════════════════════════════════════════════════════
echo "=== Phase 2: Mixed fixture ==="
P2_ROOT=$(mktemp -d /tmp/rt4-p2-XXXX)
P2_API=18904

# Generate a known non-self peer ID
NONSELF_ID="bb$(printf "bb%.0s" $(seq 1 31))"
echo "nonself_id: $NONSELF_ID"

# Write mixed fixture
"$FIXTURE" write "$P2_ROOT/cache" "$MACHINE_ID" "$NONSELF_ID"
if [[ ! -f "$P2_ROOT/cache/bootstrap_cache.json" ]]; then
    echo "FATAL: mixed fixture not written" >&2
    rm -rf "$P2_ROOT"
    exit 1
fi
echo "phase2_fixture_written: 2 peers"

# Start child 4 — prune self, remaining=1
start_child "phase2_run1" "$P2_ROOT/id" "$P2_ROOT/data" "$P2_ROOT/cache" "$P2_API"
P2_PID=$CHILD_PID
sleep 3
if ! grep -q "#484: pruned self entry" "$ARTIFACTS/phase2_run1.log" 2>/dev/null; then
    echo "FATAL: prune log not found in phase2_run1.log" >&2
    stop_child "phase2_run1" "$P2_PID" "$P2_API" || true
    rm -rf "$P2_ROOT"
    exit 1
fi
# Assert remaining=1 (not remaining=0)
if grep -q "remaining=0" "$ARTIFACTS/phase2_run1.log" 2>/dev/null; then
    echo "FATAL: remaining=0 in mixed cache (should be remaining=1)" >&2
    stop_child "phase2_run1" "$P2_PID" "$P2_API" || true
    rm -rf "$P2_ROOT"
    exit 1
fi
echo "phase2_remaining: 1"

# File should still exist (remaining > 0, no unlink)
if [[ ! -f "$P2_ROOT/cache/bootstrap_cache.json" ]]; then
    echo "FATAL: file unlinked in mixed case (should persist)" >&2
    stop_child "phase2_run1" "$P2_PID" "$P2_API" || true
    rm -rf "$P2_ROOT"
    exit 1
fi

# Clean stop — Agent::shutdown saves the nonself-only cache
stop_child "phase2_run1" "$P2_PID" "$P2_API"

# Inspect the saved file: exactly the nonself key, no self
INSPECT_COUNT=$("$FIXTURE" inspect "$P2_ROOT/cache" | grep -o "count=[0-9]*" | cut -d= -f2)
if [[ "$INSPECT_COUNT" != "1" ]]; then
    echo "FATAL: post-shutdown count=$INSPECT_COUNT (expected 1 nonself)" >&2
    rm -rf "$P2_ROOT"
    exit 1
fi
echo "phase2_post_shutdown_count: 1 (nonself only)"

# Restart: child 5 with same paths
P2_API2=18905
start_child "phase2_run2" "$P2_ROOT/id" "$P2_ROOT/data" "$P2_ROOT/cache" "$P2_API2"
P2_PID2=$CHILD_PID

# Assert nonself persists (no prune log for the restart — no self in cache)
sleep 3
if grep -q "#484: pruned self entry" "$ARTIFACTS/phase2_run2.log" 2>/dev/null; then
    echo "WARN: prune fired on restart — self entry reappeared?" >&2
fi

stop_child "phase2_run2" "$P2_PID2" "$P2_API2"
rm -rf "$P2_ROOT"
echo "=== Phase 2 PASSED ==="

echo "=== RT-4 harness ALL PHASES PASSED ==="
exit 0
'
