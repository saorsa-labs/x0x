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
ARTIFACTS="${RT4_ARTIFACTS:-}"
LOCK_SHA_EXPECTED="5769726f49c34214f818a9c21e435cfabe02ba5efc1e47a62d6b888c1ee6f9c2"

# Namespace wrapper: wraps the ENTIRE harness once, not each child.
NS_WRAPPER="${RT4_NS_WRAPPER:-}"
NS_WRAPPER_SHA_EXPECTED="2a0c2521c19d5054b6e77c995e1604e9e9e174208157bb4331b5b38783aedced"
if [[ -z "$NS_WRAPPER" || ! -x "$NS_WRAPPER" ]]; then
    echo "FATAL: network namespace wrapper required (RT4_NS_WRAPPER=<path>)" >&2
    exit 1
fi
NS_WRAPPER_SHA=$(shasum -a 256 "$NS_WRAPPER" | cut -d" " -f1)
if [[ "$NS_WRAPPER_SHA" != "$NS_WRAPPER_SHA_EXPECTED" ]]; then
    echo "FATAL: namespace wrapper hash mismatch: $NS_WRAPPER_SHA != $NS_WRAPPER_SHA_EXPECTED" >&2
    exit 1
fi

# --- Preparation mode: exit nonzero (incomplete) ---
if [[ "${RT4_RUN:-0}" != "1" ]]; then
    echo "RT-4 harness PREPARATION MODE (set RT4_RUN=1 + RT4_NS_WRAPPER to execute)"
    echo "Phases: 0=discover machine_id, 1=self-only prune+unlink, 2=mixed prune+persist"
    exit 1
fi

if [[ -z "$ARTIFACTS" || "$ARTIFACTS" != /* || "$ARTIFACTS" == "/tmp" || "$ARTIFACTS" == /tmp/* ]]; then
    echo "FATAL: RT4_ARTIFACTS must be an absolute path outside /tmp (for example RUNNER_TEMP)" >&2
    exit 1
fi
mkdir -p "$ARTIFACTS"

# --- All phases run inside the namespace wrapper ---
WRAPPER_OUTPUT="$ARTIFACTS/namespace-wrapper.log"
set +e
"$NS_WRAPPER" bash -c '
set -euo pipefail
export ARTIFACTS="$1"
export X0XD="$2"
export FIXTURE="$3"
export WORKTREE="$4"
export LOCK_SHA_EXPECTED="$5"
export NS_WRAPPER_SHA="$6"

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
{
    echo "lock_sha256: $LOCK_SHA"
    echo "x0xd_sha256: $X0XD_SHA"
    echo "fixture_sha256: $FIXTURE_SHA"
    echo "namespace_wrapper_sha256: $NS_WRAPPER_SHA"
} > "$ARTIFACTS/harness.log"

# The machine identity must survive all three phases. Runtime data/cache roots
# are disposable per phase, but the identity directory is shared deliberately.
IDENTITY_ROOT=$(mktemp -d /tmp/rt4-identity-XXXX)
SHARED_IDENTITY="$IDENTITY_ROOT/id"
mkdir -p "$SHARED_IDENTITY"
CHILD_PID=""
API_TOKEN=""

cleanup() {
    if [[ -n "${CHILD_PID:-}" ]]; then
        kill -TERM "$CHILD_PID" 2>/dev/null || true
        if ! wait_child_bounded "$CHILD_PID"; then
            kill -KILL "$CHILD_PID" 2>/dev/null || true
            wait_child_bounded "$CHILD_PID" || true
        fi
        CHILD_PID=""
    fi
    for root in "${IDENTITY_ROOT:-}" "${P0_ROOT:-}" "${P1_ROOT:-}" "${P2_ROOT:-}"; do
        if [[ -n "$root" ]]; then
            rm -rf "$root"
        fi
    done
}
trap cleanup EXIT

# Helper: start child, wait for health
start_child() {
    local name="$1" identity_dir="$2" data_dir="$3" cache_dir="$4" api_port="$5"
    local log="$ARTIFACTS/${name}.log"
    mkdir -p "$identity_dir" "$data_dir" "$cache_dir"

    if [[ "$cache_dir" != "$data_dir/peers" ]]; then
        echo "FATAL: cache dir must be daemon data_dir/peers: $cache_dir" >&2
        return 1
    fi

    local config="$data_dir/rt4-config.toml"
    cat > "$config" <<EOF
identity_dir = "$identity_dir"
data_dir = "$data_dir"
bind_address = "127.0.0.1:0"
api_address = "127.0.0.1:$api_port"
bootstrap_peers = []
port_mapping_enabled = false
network_id = "x0x.rt4"
log_level = "info"
[update]
enabled = false
EOF

    "$X0XD" \
        --config "$config" \
        --skip-update-check \
        > "$log" 2>&1 &
    CHILD_PID=$!

    for i in $(seq 1 30); do
        if [[ -s "$data_dir/api-token" ]]; then
            API_TOKEN=$(cat "$data_dir/api-token")
        fi
        if [[ -n "$API_TOKEN" ]] && \
           curl --connect-timeout 1 --max-time 2 -sf \
             -H "Authorization: Bearer $API_TOKEN" \
             "http://127.0.0.1:${api_port}/health" > /dev/null 2>&1; then
            echo "${name}_pid: $CHILD_PID"
            echo "${name}_api: $api_port"
            return 0
        fi
        sleep 1
    done
    echo "FATAL: $name not healthy in 30s (log: $log)" >&2
    kill -TERM "$CHILD_PID" 2>/dev/null || true
    if ! wait_child_bounded "$CHILD_PID"; then
        kill -KILL "$CHILD_PID" 2>/dev/null || true
        wait_child_bounded "$CHILD_PID" || true
    fi
    CHILD_PID=""
    return 1
}

# Helper: bounded wait that still captures the actual process exit status.
wait_child_bounded() {
    local pid="$1" i state
    for i in $(seq 1 30); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null
            return $?
        fi
        state=$(ps -o stat= -p "$pid" 2>/dev/null || true)
        if [[ "$state" == Z* ]]; then
            wait "$pid" 2>/dev/null
            return $?
        fi
        sleep 1
    done
    return 124
}

# Helper: clean stop — bounded shutdown, capture exit code, reject escalation
stop_child() {
    local name="$1" pid="$2" api_port="$3"
    local shutdown_code=0 exit_code=124 escalation=0
    curl --connect-timeout 1 --max-time 5 -sf \
        -H "Authorization: Bearer $API_TOKEN" \
        -X POST "http://127.0.0.1:${api_port}/shutdown" > /dev/null 2>&1 || shutdown_code=$?
    if wait_child_bounded "$pid"; then
        exit_code=0
    else
        exit_code=$?
    fi
    if [[ "$exit_code" -eq 124 ]]; then
        escalation=1
        kill -TERM "$pid" 2>/dev/null || true
        if wait_child_bounded "$pid"; then
            exit_code=0
        else
            exit_code=$?
        fi
    fi
    if [[ "$exit_code" -eq 124 ]]; then
        kill -KILL "$pid" 2>/dev/null || true
        if wait_child_bounded "$pid"; then
            exit_code=0
        else
            exit_code=$?
        fi
    fi
    CHILD_PID=""
    if [[ "$shutdown_code" -ne 0 || "$exit_code" -ne 0 || "$escalation" -ne 0 ]]; then
        echo "FATAL: $name shutdown=$shutdown_code exit=$exit_code escalation=$escalation" >&2
        echo "${name}_shutdown_code: $shutdown_code" >> "$ARTIFACTS/harness.log"
        echo "${name}_exit_code: $exit_code" >> "$ARTIFACTS/harness.log"
        echo "${name}_escalation: $escalation" >> "$ARTIFACTS/harness.log"
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
start_child "phase0" "$SHARED_IDENTITY" "$P0_ROOT/data" "$P0_ROOT/data/peers" "$P0_API"
P0_PID=$CHILD_PID

# Read the flat machine_id (NOT agent_id — the cache key is the machine peer ID)
query_machine_id() {
    local api_port="$1" expected="$2" name="$3" observed
    observed=$(curl --connect-timeout 1 --max-time 5 -sf \
        -H "Authorization: Bearer $API_TOKEN" \
        "http://127.0.0.1:$api_port/agent" | \
        python3 -c "import json,sys; print(json.load(sys.stdin)[\"machine_id\"])")
    if [[ -z "$observed" ]]; then
        echo "FATAL: $name returned an empty machine_id" >&2
        return 1
    fi
    if [[ -n "$expected" && "$observed" != "$expected" ]]; then
        echo "FATAL: $name machine_id changed: $observed != $expected" >&2
        return 1
    fi
    echo "$name machine_id: $observed"
    echo "$name machine_id: $observed" >> "$ARTIFACTS/harness.log"
    MACHINE_ID="$observed"
}

query_machine_id "$P0_API" "" "phase0"
echo "machine_id: $MACHINE_ID"

stop_child "phase0" "$P0_PID" "$P0_API"
rm -rf "$P0_ROOT"
P0_ROOT=""

# ══════════════════════════════════════════════════════════════════
# Phase 1: Self-only fixture → prune → unlink → restart
# ══════════════════════════════════════════════════════════════════
echo "=== Phase 1: Self-only fixture ==="
P1_ROOT=$(mktemp -d /tmp/rt4-p1-XXXX)
P1_API=18902
P1_CACHE="$P1_ROOT/data/peers"

# Write self-only fixture using the public-API CLI
"$FIXTURE" write "$P1_CACHE" "$MACHINE_ID"
CACHE_FILE="$P1_CACHE/bootstrap_cache.json"
if [[ ! -f "$CACHE_FILE" ]]; then
    echo "FATAL: fixture not written: $CACHE_FILE" >&2
    rm -rf "$P1_ROOT"
    exit 1
fi
echo "phase1_fixture_written: $CACHE_FILE"
if ! INSPECT=$("$FIXTURE" inspect "$P1_CACHE" "$MACHINE_ID" -); then
    echo "FATAL: self-only fixture did not load with the discovered machine ID" >&2
    exit 1
fi
if [[ "$INSPECT" != *"count=1"* || "$INSPECT" != *"contains_expected=1"* || "$INSPECT" != *"contains_forbidden=0"* ]]; then
    echo "FATAL: self-only fixture load oracle failed: $INSPECT" >&2
    exit 1
fi

# Start child 2 — prune should fire and unlink the file
start_child "phase1_run1" "$SHARED_IDENTITY" "$P1_ROOT/data" "$P1_CACHE" "$P1_API"
P1_PID=$CHILD_PID
query_machine_id "$P1_API" "$MACHINE_ID" "phase1_run1"

# Wait for the prune log
sleep 3
if ! grep -Eq "#484: pruned self entry.*remaining=0|remaining=0.*#484: pruned self entry" "$ARTIFACTS/phase1_run1.log" 2>/dev/null; then
    echo "FATAL: exact remaining=0 prune log not found in phase1_run1.log" >&2
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
start_child "phase1_run2" "$SHARED_IDENTITY" "$P1_ROOT/data" "$P1_CACHE" "$P1_API2"
P1_PID2=$CHILD_PID
query_machine_id "$P1_API2" "$MACHINE_ID" "phase1_run2"
if [[ "$P1_PID2" -eq "$P1_PID" ]]; then
    echo "FATAL: child 3 PID matches child 2 ($P1_PID)" >&2
    stop_child "phase1_run2" "$P1_PID2" "$P1_API2" || true
    rm -rf "$P1_ROOT"
    exit 1
fi
echo "phase1_restart_pid: $P1_PID2 (distinct from $P1_PID)"

# Assert no self entry: file should be absent or have no self key
if [[ -f "$CACHE_FILE" ]]; then
    if ! INSPECT=$("$FIXTURE" inspect "$P1_CACHE" - "$MACHINE_ID"); then
        echo "FATAL: self entry reappeared in phase1 restart" >&2
        stop_child "phase1_run2" "$P1_PID2" "$P1_API2" || true
        rm -rf "$P1_ROOT"
        exit 1
    fi
    if [[ "$INSPECT" != *"count=0"* ]]; then
        echo "FATAL: self-only cache reappeared with peers: $INSPECT" >&2
        stop_child "phase1_run2" "$P1_PID2" "$P1_API2" || true
        rm -rf "$P1_ROOT"
        exit 1
    fi
fi
echo "phase1_no_self_after_restart: yes"

stop_child "phase1_run2" "$P1_PID2" "$P1_API2"
rm -rf "$P1_ROOT"
P1_ROOT=""
echo "=== Phase 1 PASSED ==="

# ══════════════════════════════════════════════════════════════════
# Phase 2: Mixed fixture → prune self → clean shutdown → nonself persists
# ══════════════════════════════════════════════════════════════════
echo "=== Phase 2: Mixed fixture ==="
P2_ROOT=$(mktemp -d /tmp/rt4-p2-XXXX)
P2_API=18904
P2_CACHE="$P2_ROOT/data/peers"

# Generate a known non-self peer ID
NONSELF_ID="bb$(printf "bb%.0s" $(seq 1 31))"
echo "nonself_id: $NONSELF_ID"

# Write mixed fixture
"$FIXTURE" write "$P2_CACHE" "$MACHINE_ID" "$NONSELF_ID"
if [[ ! -f "$P2_CACHE/bootstrap_cache.json" ]]; then
    echo "FATAL: mixed fixture not written" >&2
    rm -rf "$P2_ROOT"
    exit 1
fi
echo "phase2_fixture_written: 2 peers"
for expected_id in "$MACHINE_ID" "$NONSELF_ID"; do
    if ! INSPECT=$("$FIXTURE" inspect "$P2_CACHE" "$expected_id" -); then
        echo "FATAL: mixed fixture did not load expected peer $expected_id" >&2
        exit 1
    fi
    if [[ "$INSPECT" != *"count=2"* || "$INSPECT" != *"contains_expected=1"* ]]; then
        echo "FATAL: mixed fixture load oracle failed for $expected_id: $INSPECT" >&2
        exit 1
    fi
done

# Start child 4 — prune self, remaining=1
start_child "phase2_run1" "$SHARED_IDENTITY" "$P2_ROOT/data" "$P2_CACHE" "$P2_API"
P2_PID=$CHILD_PID
query_machine_id "$P2_API" "$MACHINE_ID" "phase2_run1"
sleep 3
if ! grep -Eq "#484: pruned self entry.*remaining=1|remaining=1.*#484: pruned self entry" "$ARTIFACTS/phase2_run1.log" 2>/dev/null; then
    echo "FATAL: exact remaining=1 prune log not found in phase2_run1.log" >&2
    stop_child "phase2_run1" "$P2_PID" "$P2_API" || true
    rm -rf "$P2_ROOT"
    exit 1
fi
echo "phase2_remaining: 1"

# File should still exist (remaining > 0, no unlink)
if [[ ! -f "$P2_CACHE/bootstrap_cache.json" ]]; then
    echo "FATAL: file unlinked in mixed case (should persist)" >&2
    stop_child "phase2_run1" "$P2_PID" "$P2_API" || true
    rm -rf "$P2_ROOT"
    exit 1
fi

# Clean stop — Agent::shutdown saves the nonself-only cache
stop_child "phase2_run1" "$P2_PID" "$P2_API"

# Inspect the saved file: exactly the nonself key, no self
if ! INSPECT=$("$FIXTURE" inspect "$P2_CACHE" "$NONSELF_ID" "$MACHINE_ID"); then
    echo "FATAL: post-shutdown cache identity check failed: $INSPECT" >&2
    rm -rf "$P2_ROOT"
    exit 1
fi
if [[ "$INSPECT" != *"count=1"* || "$INSPECT" != *"contains_expected=1"* || "$INSPECT" != *"contains_forbidden=0"* ]]; then
    echo "FATAL: post-shutdown cache is not exactly nonself-only: $INSPECT" >&2
    rm -rf "$P2_ROOT"
    exit 1
fi
echo "phase2_post_shutdown_count: 1 (nonself only)"

# Restart: child 5 with same paths
P2_API2=18905
start_child "phase2_run2" "$SHARED_IDENTITY" "$P2_ROOT/data" "$P2_CACHE" "$P2_API2"
P2_PID2=$CHILD_PID
query_machine_id "$P2_API2" "$MACHINE_ID" "phase2_run2"

# Assert nonself persists (no prune log for the restart — no self in cache)
sleep 3
if grep -q "#484: pruned self entry" "$ARTIFACTS/phase2_run2.log" 2>/dev/null; then
    echo "FATAL: prune fired on restart — self entry reappeared" >&2
    stop_child "phase2_run2" "$P2_PID2" "$P2_API2" || true
    rm -rf "$P2_ROOT"
    exit 1
fi
if ! INSPECT=$("$FIXTURE" inspect "$P2_CACHE" "$NONSELF_ID" "$MACHINE_ID"); then
    echo "FATAL: restart cache identity check failed: $INSPECT" >&2
    stop_child "phase2_run2" "$P2_PID2" "$P2_API2" || true
    rm -rf "$P2_ROOT"
    exit 1
fi
if [[ "$INSPECT" != *"count=1"* || "$INSPECT" != *"contains_expected=1"* || "$INSPECT" != *"contains_forbidden=0"* ]]; then
    echo "FATAL: restart cache is not exactly nonself-only: $INSPECT" >&2
    stop_child "phase2_run2" "$P2_PID2" "$P2_API2" || true
    rm -rf "$P2_ROOT"
    exit 1
fi

stop_child "phase2_run2" "$P2_PID2" "$P2_API2"
rm -rf "$P2_ROOT"
P2_ROOT=""
echo "=== Phase 2 PASSED ==="

echo "=== RT-4 harness ALL PHASES PASSED ==="
exit 0
' _ "$ARTIFACTS" "$X0XD" "$FIXTURE" "$WORKTREE" "$LOCK_SHA_EXPECTED" "$NS_WRAPPER_SHA" >"$WRAPPER_OUTPUT" 2>&1
WRAPPER_EXIT=$?
set -e
echo "namespace_wrapper_exit: $WRAPPER_EXIT" >> "$WRAPPER_OUTPUT"
if [[ "$WRAPPER_EXIT" -ne 0 ]]; then
    echo "FATAL: namespace-wrapped RT4 harness exited $WRAPPER_EXIT" >&2
    exit 1
fi

EVIDENCE_DIR=$(python3 -c "import sys; lines=[line.strip() for line in open(sys.argv[1]) if line.startswith('Isolation evidence: ')]; print(lines[-1].split(': ', 1)[1] if lines else '')" "$WRAPPER_OUTPUT")
if [[ -z "$EVIDENCE_DIR" || ! -f "$EVIDENCE_DIR/admission.json" || ! -f "$EVIDENCE_DIR/exit.json" || ! -f "$EVIDENCE_DIR/supervisor.json" ]]; then
    echo "FATAL: namespace wrapper receipts are missing" >&2
    exit 1
fi
if ! python3 - "$EVIDENCE_DIR" "$WRAPPER_EXIT" <<'PY'
import json
import sys
from pathlib import Path

evidence = Path(sys.argv[1])
wrapper_exit = int(sys.argv[2])
admission = json.loads((evidence / "admission.json").read_text())
wrapped_exit = json.loads((evidence / "exit.json").read_text())
supervisor = json.loads((evidence / "supervisor.json").read_text())

def validate_admission(state):
    if not state.get("namespace"):
        return False
    links = state.get("links")
    if (not isinstance(links, list) or len(links) != 1
            or not isinstance(links[0], dict) or links[0].get("ifname") != "lo"):
        return False
    routes = state.get("routes")
    if not isinstance(routes, dict) or set(routes) != {"-4", "-6"}:
        return False
    if any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
           for rows in routes.values()):
        return False
    return not any(
        row.get("dev") != "lo" or row.get("dst") == "default" or "gateway" in row
        for rows in routes.values()
        for row in rows
    )

valid_loopback_route = {
    "namespace": "private",
    "links": [{"ifname": "lo"}],
    "routes": {"-4": [{"dst": "127.0.0.0/8", "dev": "lo"}], "-6": []},
}
invalid_routes = (
    {"dev": "eth0", "dst": "10.0.0.0/8"},
    {"dev": "lo", "dst": "default"},
    {"dev": "lo", "dst": "127.0.0.0/8", "gateway": "127.0.0.1"},
)
if not validate_admission(valid_loopback_route):
    raise SystemExit("loopback route control was rejected")
if any(validate_admission({**valid_loopback_route, "routes": {"-4": [route], "-6": []}})
       for route in invalid_routes):
    raise SystemExit("foreign/default/gateway route control was accepted")
if wrapper_exit != 0 or wrapped_exit.get("exit") != 0:
    raise SystemExit("wrapper or wrapped command was nonzero")
if supervisor.get("reason") is not None or supervisor.get("child_exit") != 0:
    raise SystemExit("supervisor did not report a clean zero exit")
if supervisor.get("child_reaped") is not True:
    raise SystemExit("supervisor did not report reaping its child")
if not validate_admission(admission):
    raise SystemExit("admission receipt is not loopback-only")
PY
then
    echo "FATAL: namespace wrapper receipts failed validation" >&2
    exit 1
fi
