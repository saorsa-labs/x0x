#!/bin/bash
# Wrapper that boots temp x0xd daemons, runs the Chrome harness against them,
# and cleans up. Mirrors tests/harness/src/daemon.rs shape so the harness
# behaves identically locally and in CI.

set -euo pipefail

BIN="${X0XD_BIN:-$(dirname "$0")/../target/release/x0xd}"
if [ ! -x "$BIN" ]; then
    echo "x0xd not found at $BIN — build with cargo build --release --bin x0xd" >&2
    exit 2
fi

DATA_DIR=$(mktemp -d -t x0x-gui-chrome.XXXXXX)
SECONDARY_DATA_DIR=$(mktemp -d -t x0x-gui-chrome-peer.XXXXXX)
PROOF_DIR="${PROOF_DIR:-$(dirname "$0")/../proofs/gui-parity-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$PROOF_DIR"

cleanup() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if [ -n "${SECONDARY_DAEMON_PID:-}" ]; then
        kill -TERM "$SECONDARY_DAEMON_PID" 2>/dev/null || true
        wait "$SECONDARY_DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR" "$SECONDARY_DATA_DIR" || true
}
trap cleanup EXIT

write_config() {
    local dir="$1"
    local instance="$2"
    cat > "$dir/config.toml" <<EOF
bind_address = "127.0.0.1:0"
api_address = "127.0.0.1:0"
data_dir = "$dir"
log_level = "info"
bootstrap_peers = []
instance_name = "$instance"

[update]
enabled = false
EOF
}

wait_ready() {
    local dir="$1"
    local label="$2"
    local deadline=$((SECONDS + 60))
    until [ -s "$dir/api.port" ] && [ -s "$dir/api-token" ]; do
        if [ $SECONDS -gt $deadline ]; then
            echo "[harness] timeout waiting for $label api.port / api-token" >&2
            echo "[harness] $label daemon log:" >&2
            cat "$dir/x0xd.log" >&2 || true
            exit 3
        fi
        sleep 1
    done
}

wait_health() {
    local addr="$1"
    local token="$2"
    local dir="$3"
    local label="$4"
    local deadline=$((SECONDS + 30))
    until curl -fsS -m 2 -H "Authorization: Bearer $token" "http://$addr/health" >/dev/null; do
        if [ $SECONDS -gt $deadline ]; then
            echo "[harness] timeout waiting for $label /health" >&2
            cat "$dir/x0xd.log" >&2 || true
            exit 4
        fi
        sleep 1
    done
}

write_config "$DATA_DIR" "gui-chrome-harness"
write_config "$SECONDARY_DATA_DIR" "gui-chrome-harness-peer"

# Disable App Nap on macOS by using caffeinate when available — the daemons
# must keep their event loops hot for the API to be reachable.
NICE_PREFIX=""
if command -v caffeinate >/dev/null 2>&1; then
    NICE_PREFIX="caffeinate -i"
fi

$NICE_PREFIX "$BIN" \
    --config "$DATA_DIR/config.toml" \
    --skip-update-check \
    >"$DATA_DIR/x0xd.log" 2>&1 &
DAEMON_PID=$!

$NICE_PREFIX "$BIN" \
    --config "$SECONDARY_DATA_DIR/config.toml" \
    --skip-update-check \
    >"$SECONDARY_DATA_DIR/x0xd.log" 2>&1 &
SECONDARY_DAEMON_PID=$!

echo "[harness] daemon pid=$DAEMON_PID data_dir=$DATA_DIR" >&2
echo "[harness] secondary daemon pid=$SECONDARY_DAEMON_PID data_dir=$SECONDARY_DATA_DIR" >&2

wait_ready "$DATA_DIR" "primary"
wait_ready "$SECONDARY_DATA_DIR" "secondary"

ADDR=$(cat "$DATA_DIR/api.port")
TOKEN=$(cat "$DATA_DIR/api-token")
SECONDARY_ADDR=$(cat "$SECONDARY_DATA_DIR/api.port")
SECONDARY_TOKEN=$(cat "$SECONDARY_DATA_DIR/api-token")

echo "[harness] daemon ready: addr=$ADDR" >&2
echo "[harness] secondary daemon ready: addr=$SECONDARY_ADDR" >&2

# Probe /health once before we hand off to the Node harness so binding
# regressions surface in the wrapper rather than as surprising network errors
# inside Playwright.
wait_health "$ADDR" "$TOKEN" "$DATA_DIR" "primary"
wait_health "$SECONDARY_ADDR" "$SECONDARY_TOKEN" "$SECONDARY_DATA_DIR" "secondary"

echo "[harness] /health green — running Node harness" >&2

set +e
X0X_API_BASE="http://$ADDR" \
X0X_API_TOKEN="$TOKEN" \
X0X_SECONDARY_API_BASE="http://$SECONDARY_ADDR" \
X0X_SECONDARY_API_TOKEN="$SECONDARY_TOKEN" \
node "$(dirname "$0")/e2e_gui_chrome.mjs" --proof-dir "$PROOF_DIR"
RC=$?
set -e

# Snapshot daemon logs for the proof bundle even when the Node harness fails.
cp "$DATA_DIR/x0xd.log" "$PROOF_DIR/x0xd.log" 2>/dev/null || true
cp "$SECONDARY_DATA_DIR/x0xd.log" "$PROOF_DIR/x0xd-secondary.log" 2>/dev/null || true

echo "[harness] exit=$RC proof=$PROOF_DIR" >&2
exit $RC
