#!/bin/bash
# Wrapper that boots a temp x0xd, runs the Chrome harness against it,
# and cleans up. Mirrors tests/harness/src/daemon.rs shape so the
# harness behaves identically locally and in CI.

set -euo pipefail

BIN="${X0XD_BIN:-$(dirname "$0")/../target/release/x0xd}"
if [ ! -x "$BIN" ]; then
    echo "x0xd not found at $BIN — build with cargo build --release --bin x0xd" >&2
    exit 2
fi

DATA_DIR=$(mktemp -d -t x0x-gui-chrome.XXXXXX)
PROOF_DIR="${PROOF_DIR:-$(dirname "$0")/../proofs/gui-parity-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$PROOF_DIR"

cleanup() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR" || true
}
trap cleanup EXIT

cat > "$DATA_DIR/config.toml" <<EOF
bind_address = "127.0.0.1:0"
api_address = "127.0.0.1:0"
data_dir = "$DATA_DIR"
log_level = "info"
bootstrap_peers = []
instance_name = "gui-chrome-harness"
EOF

# Disable App Nap on macOS by using caffeinate when available — the
# daemon must keep its event loop hot for the API to be reachable.
NICE_PREFIX=""
if command -v caffeinate >/dev/null 2>&1; then
    NICE_PREFIX="caffeinate -i"
fi

$NICE_PREFIX "$BIN" \
    --config "$DATA_DIR/config.toml" \
    --skip-update-check \
    >"$DATA_DIR/x0xd.log" 2>&1 &
DAEMON_PID=$!

echo "[harness] daemon pid=$DAEMON_PID data_dir=$DATA_DIR" >&2

deadline=$((SECONDS + 60))
until [ -s "$DATA_DIR/api.port" ] && [ -s "$DATA_DIR/api-token" ]; do
    if [ $SECONDS -gt $deadline ]; then
        echo "[harness] timeout waiting for api.port / api-token" >&2
        echo "[harness] daemon log:" >&2
        cat "$DATA_DIR/x0xd.log" >&2 || true
        exit 3
    fi
    sleep 1
done

ADDR=$(cat "$DATA_DIR/api.port")
TOKEN=$(cat "$DATA_DIR/api-token")

echo "[harness] daemon ready: addr=$ADDR" >&2

# Probe /health once before we hand off to the Node harness so any
# binding regression surfaces in the wrapper rather than as a
# surprising network error inside Playwright.
deadline=$((SECONDS + 30))
until curl -fsS -m 2 -H "Authorization: Bearer $TOKEN" "http://$ADDR/health" >/dev/null; do
    if [ $SECONDS -gt $deadline ]; then
        echo "[harness] timeout waiting for /health" >&2
        cat "$DATA_DIR/x0xd.log" >&2 || true
        exit 4
    fi
    sleep 1
done

echo "[harness] /health green — running Node harness" >&2

X0X_API_BASE="http://$ADDR" \
X0X_API_TOKEN="$TOKEN" \
node "$(dirname "$0")/e2e_gui_chrome.mjs" --proof-dir "$PROOF_DIR"
RC=$?

# Snapshot the daemon log for the proof bundle.
cp "$DATA_DIR/x0xd.log" "$PROOF_DIR/x0xd.log" 2>/dev/null || true

echo "[harness] exit=$RC proof=$PROOF_DIR" >&2
exit $RC
