#!/usr/bin/env bash
# Local two-daemon end-to-end test for Tier-1 x0x exec.
#
# The test proves the SSH-free exec path over signed/encrypted gossip DMs:
#   - exact (AgentId, MachineId) ACL pair is loaded at daemon startup
#   - allowlisted argv succeeds
#   - non-allowlisted argv returns structured denial
#   - stdout caps truncate while the child is drained
#   - diagnostics and JSONL audit record the run/deny/warning/exit path
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
X0XD="${X0XD:-}"
if [ -z "$X0XD" ]; then
    if [ -x "$ROOT/target/release/x0xd" ] && { [ ! -x "$ROOT/target/debug/x0xd" ] || [ "$ROOT/target/release/x0xd" -nt "$ROOT/target/debug/x0xd" ]; }; then
        X0XD="$ROOT/target/release/x0xd"
    else
        X0XD="$ROOT/target/debug/x0xd"
    fi
fi

if [ ! -x "$X0XD" ]; then
    echo "x0xd not built at $X0XD — run: cargo build --bin x0xd" >&2
    exit 2
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 2; }
}
need_cmd curl
need_cmd python3

WORK_DIR="$(mktemp -d -t x0x-exec-e2e.XXXXXX)"
BASE_OFFSET=$(( ($$ % 1000) * 10 ))
API_ALICE=$((23750 + BASE_OFFSET))
API_BOB=$((23751 + BASE_OFFSET))
QUIC_ALICE=$((24750 + BASE_OFFSET))
QUIC_BOB=$((24751 + BASE_OFFSET))
ALICE_NAME="execalice$$"
BOB_NAME="execbob$$"
ALICE_DATA="$WORK_DIR/alice-data"
BOB_DATA="$WORK_DIR/bob-data"
ALICE_CFG="$WORK_DIR/alice.toml"
BOB_CFG="$WORK_DIR/bob.toml"
ALICE_ACL="$WORK_DIR/alice-exec-acl.toml"
BOB_ACL="$WORK_DIR/bob-exec-acl.toml"
ALICE_AUDIT="$WORK_DIR/alice-exec.jsonl"
BOB_AUDIT="$WORK_DIR/bob-exec.jsonl"
declare -a DAEMON_PIDS=()

cat > "$ALICE_CFG" <<EOF_CFG
bind_address = "[::]:$QUIC_ALICE"
api_address = "127.0.0.1:$API_ALICE"
data_dir = "$ALICE_DATA"
bootstrap_peers = ["127.0.0.1:$QUIC_BOB"]
log_level = "info"
rendezvous_enabled = false
heartbeat_interval_secs = 2
identity_ttl_secs = 30
presence_beacon_interval_secs = 2
presence_event_poll_interval_secs = 2
presence_offline_timeout_secs = 10
directory_digest_interval_secs = 2
group_card_republish_interval_secs = 0
[update]
enabled = false
EOF_CFG

cat > "$BOB_CFG" <<EOF_CFG
bind_address = "[::]:$QUIC_BOB"
api_address = "127.0.0.1:$API_BOB"
data_dir = "$BOB_DATA"
bootstrap_peers = ["127.0.0.1:$QUIC_ALICE"]
log_level = "info"
rendezvous_enabled = false
heartbeat_interval_secs = 2
identity_ttl_secs = 30
presence_beacon_interval_secs = 2
presence_event_poll_interval_secs = 2
presence_offline_timeout_secs = 10
directory_digest_interval_secs = 2
group_card_republish_interval_secs = 0
[update]
enabled = false
EOF_CFG

cleanup() {
    for p in "${DAEMON_PIDS[@]:-}"; do
        kill -TERM "$p" 2>/dev/null || true
    done
    sleep 1
    for p in "${DAEMON_PIDS[@]:-}"; do
        kill -KILL "$p" 2>/dev/null || true
    done
    if [ "${KEEP_X0X_EXEC_E2E:-0}" != "1" ]; then
        rm -rf "$HOME/.x0x-$ALICE_NAME" "$HOME/.x0x-$BOB_NAME" 2>/dev/null || true
        rm -rf "$WORK_DIR"
    else
        echo "kept work_dir=$WORK_DIR" >&2
        echo "kept identity dirs: $HOME/.x0x-$ALICE_NAME $HOME/.x0x-$BOB_NAME" >&2
    fi
}
trap cleanup EXIT

start_daemons() {
    local with_acl="$1"
    DAEMON_PIDS=()
    if [ "$with_acl" = "yes" ]; then
        "$X0XD" --config "$ALICE_CFG" --name "$ALICE_NAME" --exec-acl "$ALICE_ACL" --skip-update-check \
            > "$WORK_DIR/alice.x0xd.log" 2>&1 &
        DAEMON_PIDS+=("$!")
        "$X0XD" --config "$BOB_CFG" --name "$BOB_NAME" --exec-acl "$BOB_ACL" --skip-update-check \
            > "$WORK_DIR/bob.x0xd.log" 2>&1 &
        DAEMON_PIDS+=("$!")
    else
        "$X0XD" --config "$ALICE_CFG" --name "$ALICE_NAME" --skip-update-check \
            > "$WORK_DIR/alice.x0xd.log" 2>&1 &
        DAEMON_PIDS+=("$!")
        "$X0XD" --config "$BOB_CFG" --name "$BOB_NAME" --skip-update-check \
            > "$WORK_DIR/bob.x0xd.log" 2>&1 &
        DAEMON_PIDS+=("$!")
    fi
}

stop_daemons() {
    for p in "${DAEMON_PIDS[@]:-}"; do
        kill -TERM "$p" 2>/dev/null || true
    done
    sleep 1
    for p in "${DAEMON_PIDS[@]:-}"; do
        kill -KILL "$p" 2>/dev/null || true
    done
    DAEMON_PIDS=()
}

wait_health() {
    local port="$1" name="$2"
    for _ in $(seq 1 60); do
        if curl -sf -m 2 "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "daemon $name did not become healthy" >&2
    tail -80 "$WORK_DIR/$name.x0xd.log" >&2 || true
    return 1
}

api_get() {
    local port="$1" token="$2" path="$3"
    curl -sf -m 10 -H "Authorization: Bearer $token" "http://127.0.0.1:$port$path"
}

api_post() {
    local port="$1" token="$2" path="$3" body="$4"
    curl -sf -m 20 \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "http://127.0.0.1:$port$path"
}

api_post_raw() {
    local port="$1" token="$2" path="$3" body="$4"
    curl -sS -m 30 \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "http://127.0.0.1:$port$path"
}

json_field() {
    local field="$1"
    python3 -c "import sys,json; print(json.load(sys.stdin)['$field'])"
}

json_card_link() {
    python3 -c 'import sys,json; print(json.load(sys.stdin)["link"])'
}

stdin_b64() {
    python3 - <<'PY'
import base64
payload = b"abcdefghijklmnopqrstuvwxyz0123456789"
print(base64.b64encode(payload).decode())
PY
}

check_success_response() {
    python3 -c 'import base64,json,sys; r=json.load(sys.stdin); assert r.get("ok") is True, r; assert r.get("denial_reason") is None, r; out=base64.b64decode(r["stdout_b64"]).decode(); assert out == "ok\n", out; assert r.get("code") == 0, r; assert r.get("truncated") is False, r; print(r["request_id"])'
}

check_denial_response() {
    python3 -c 'import json,sys; r=json.load(sys.stdin); assert r.get("ok") is True, r; assert r.get("denial_reason") == "argv_not_allowed", r; print(r["request_id"])'
}

check_truncation_response() {
    python3 -c 'import base64,json,sys; r=json.load(sys.stdin); assert r.get("ok") is True, r; assert r.get("denial_reason") is None, r; assert r.get("truncated") is True, r; assert r.get("stdout_bytes_total", 0) >= 36, r; out=base64.b64decode(r["stdout_b64"]); assert len(out) == 8, (len(out), r); warnings=set(r.get("warnings") or []); assert "stdout_approaching_cap" in warnings, warnings; assert "stdout_cap_hit" in warnings, warnings; print(r["request_id"])'
}

retry_exec_check() {
    local label="$1" body="$2" checker="$3" resp req_id
    for i in $(seq 1 90); do
        resp="$(api_post_raw "$API_ALICE" "$ALICE_TK" /exec/run "$body" 2>/dev/null || true)"
        if [ -n "$resp" ]; then
            req_id="$(printf '%s' "$resp" | $checker 2>/dev/null || true)"
            if [ -n "$req_id" ]; then
                echo "$label request_id=$req_id"
                return 0
            fi
        fi
        echo "waiting for exec $label ($i/90): ${resp:-<no response>}" >&2
        sleep 1
    done
    echo "exec $label failed after retries" >&2
    echo "last response: ${resp:-<none>}" >&2
    return 1
}

check_bob_diagnostics() {
    python3 -c 'import json,sys; r=json.load(sys.stdin); assert r.get("ok") is True, r; assert r.get("enabled") is True, r; t=r["totals"]; assert t.get("requests_received", 0) >= 3, t; assert t.get("requests_denied", 0) >= 1, t; assert t.get("denial_breakdown", {}).get("argv_not_allowed", 0) >= 1, t; assert t.get("cap_breaches", {}).get("stdout", 0) >= 1, t; assert t.get("cap_warnings", {}).get("stdout_cap_hit", 0) >= 1, t'
}

check_audit_log() {
    python3 - "$BOB_AUDIT" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    events = [json.loads(line) for line in fh if line.strip()]
assert any(e.get("event") == "request" for e in events), events
assert any(e.get("event") == "denial" and e.get("reason") == "argv_not_allowed" for e in events), events
assert any(e.get("event") == "warning" and e.get("kind") == "stdout_cap_hit" for e in events), events
assert any(e.get("event") == "exit" and e.get("truncated") is True for e in events), events
PY
}

echo "work_dir=$WORK_DIR"
echo "starting initial daemons to mint stable identities"
start_daemons no
wait_health "$API_ALICE" alice
wait_health "$API_BOB" bob
ALICE_TK="$(cat "$ALICE_DATA/api-token")"
BOB_TK="$(cat "$BOB_DATA/api-token")"
ALICE_INFO="$(api_get "$API_ALICE" "$ALICE_TK" /agent)"
BOB_INFO="$(api_get "$API_BOB" "$BOB_TK" /agent)"
ALICE_AID="$(printf '%s' "$ALICE_INFO" | json_field agent_id)"
ALICE_MID="$(printf '%s' "$ALICE_INFO" | json_field machine_id)"
BOB_AID="$(printf '%s' "$BOB_INFO" | json_field agent_id)"
BOB_MID="$(printf '%s' "$BOB_INFO" | json_field machine_id)"
echo "alice aid=${ALICE_AID:0:16} mid=${ALICE_MID:0:16}"
echo "bob   aid=${BOB_AID:0:16} mid=${BOB_MID:0:16}"
stop_daemons

cat > "$BOB_ACL" <<EOF_ACL
[exec]
enabled = true
max_stdout_bytes = 8
max_stderr_bytes = 4096
max_stdin_bytes = 1024
max_duration_secs = 5
max_concurrent_per_agent = 1
max_concurrent_total = 2
warn_stdout_bytes = 4
warn_stderr_bytes = 2048
warn_duration_secs = 3
audit_log_path = "$BOB_AUDIT"

[[exec.allow]]
description = "alice local e2e"
agent_id = "$ALICE_AID"
machine_id = "$ALICE_MID"

[[exec.allow.commands]]
argv = ["/bin/echo", "ok"]

[[exec.allow.commands]]
argv = ["/bin/cat"]
EOF_ACL

cat > "$ALICE_ACL" <<EOF_ACL
[exec]
enabled = true
max_stdout_bytes = 4096
max_stderr_bytes = 4096
max_stdin_bytes = 1024
max_duration_secs = 5
max_concurrent_per_agent = 1
max_concurrent_total = 2
warn_stdout_bytes = 2048
warn_stderr_bytes = 2048
warn_duration_secs = 3
audit_log_path = "$ALICE_AUDIT"

[[exec.allow]]
description = "bob local e2e"
agent_id = "$BOB_AID"
machine_id = "$BOB_MID"

[[exec.allow.commands]]
argv = ["/bin/echo", "reverse-ok"]
EOF_ACL

echo "restarting daemons with explicit exec ACLs"
start_daemons yes
wait_health "$API_ALICE" alice
wait_health "$API_BOB" bob
ALICE_TK="$(cat "$ALICE_DATA/api-token")"
BOB_TK="$(cat "$BOB_DATA/api-token")"

ALICE_CARD="$(api_get "$API_ALICE" "$ALICE_TK" /agent/card | json_card_link)"
BOB_CARD="$(api_get "$API_BOB" "$BOB_TK" /agent/card | json_card_link)"
api_post "$API_ALICE" "$ALICE_TK" /agent/card/import "{\"card\":\"$BOB_CARD\",\"trust_level\":\"Trusted\"}" >/dev/null
api_post "$API_BOB" "$BOB_TK" /agent/card/import "{\"card\":\"$ALICE_CARD\",\"trust_level\":\"Trusted\"}" >/dev/null
# Connection attempts are best-effort; gossip DM delivery is the required exec substrate.
api_post "$API_ALICE" "$ALICE_TK" /agents/connect "{\"agent_id\":\"$BOB_AID\"}" >/dev/null 2>&1 || true
api_post "$API_BOB" "$BOB_TK" /agents/connect "{\"agent_id\":\"$ALICE_AID\"}" >/dev/null 2>&1 || true

SUCCESS_BODY="{\"agent_id\":\"$BOB_AID\",\"argv\":[\"/bin/echo\",\"ok\"],\"timeout_ms\":5000}"
retry_exec_check success "$SUCCESS_BODY" check_success_response || exit 1

DENY_BODY="{\"agent_id\":\"$BOB_AID\",\"argv\":[\"/bin/echo\",\"not-allowed\"],\"timeout_ms\":5000}"
retry_exec_check denial "$DENY_BODY" check_denial_response || exit 1

STDIN_B64="$(stdin_b64)"
TRUNC_BODY="{\"agent_id\":\"$BOB_AID\",\"argv\":[\"/bin/cat\"],\"stdin_b64\":\"$STDIN_B64\",\"timeout_ms\":5000}"
retry_exec_check truncation "$TRUNC_BODY" check_truncation_response || exit 1

api_get "$API_BOB" "$BOB_TK" /exec/sessions >/dev/null 2>&1 || true
api_get "$API_BOB" "$BOB_TK" /diagnostics/exec | check_bob_diagnostics || exit 1
check_audit_log || exit 1

echo "Tier-1 exec E2E passed"
exit 0
