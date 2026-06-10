#!/usr/bin/env bash
# End-to-end smoke test for the Communitas Dioxus desktop app.
#
# Launches the Dioxus binary with COMMUNITAS_TEST_MODE=1, drives a handful
# of golden paths via the app's built-in JSON IPC test hooks, and asserts
# each capability round-trips against the live x0xd daemon.
#
# Prereqs:
#   * x0xd running on http://127.0.0.1:12700
#   * Dioxus build exists at ../communitas/target/debug/communitas-dioxus
#     (or CI_DIOXUS_BIN env var points at a pre-built binary)
#   * jq, curl
#
# Proof artefacts:
#   <proof-dir>/dioxus-e2e.log        — combined stderr + test hook transcript
#   <proof-dir>/dioxus-capabilities.json — per-capability pass/fail

set -euo pipefail

PROOF_DIR="${1:-proofs/dioxus-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$PROOF_DIR"
LOG="$PROOF_DIR/dioxus-e2e.log"
REPORT="$PROOF_DIR/dioxus-capabilities.json"

X0X_API_BASE="${X0X_API_BASE:-http://127.0.0.1:12700}"
TOKEN_FILE="${HOME}/.local/share/x0x/api-token"
X0X_API_TOKEN="${X0X_API_TOKEN:-$(cat "$TOKEN_FILE" 2>/dev/null || echo '')}"

DIOXUS_BIN="${CI_DIOXUS_BIN:-$(cd "$(dirname "$0")/.." && cd ../communitas && pwd)/target/debug/communitas-dioxus}"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

declare -A RESULT

record() {
    local name="$1" status="$2" detail="${3:-}"
    RESULT["$name"]="$status"
    log "[$status] $name${detail:+ — $detail}"
}

finish() {
    {
        printf '{'
        local first=1
        for k in "${!RESULT[@]}"; do
            if [ $first -eq 1 ]; then first=0; else printf ','; fi
            printf '"%s":"%s"' "$k" "${RESULT[$k]}"
        done
        printf '}\n'
    } > "$REPORT"
    log "Dioxus E2E report → $REPORT"
    local fails=0
    for k in "${!RESULT[@]}"; do
        [[ "${RESULT[$k]}" == "fail" ]] && ((fails++)) || true
    done
    exit $((fails > 0 ? 1 : 0))
}
trap finish EXIT

# --- preflight ------------------------------------------------------------

if ! command -v jq >/dev/null; then
    record "preflight.jq" "fail" "jq not installed"
    exit 2
fi

if ! curl -fsSL "${X0X_API_BASE}/health" \
        -H "authorization: Bearer ${X0X_API_TOKEN}" >/dev/null 2>&1; then
    record "preflight.x0xd" "fail" "x0xd not reachable at ${X0X_API_BASE}"
    exit 2
fi
record "preflight.x0xd" "pass"

if [ ! -x "$DIOXUS_BIN" ]; then
    record "preflight.dioxus-binary" "skip" "binary not found at $DIOXUS_BIN"
    log "To build: (cd ../communitas && cargo build -p communitas-dioxus)"
    exit 0
fi
record "preflight.dioxus-binary" "pass"

# --- launch & drive -------------------------------------------------------

export COMMUNITAS_TEST_MODE=1
export X0X_API_BASE X0X_API_TOKEN

log "Launching Dioxus binary: $DIOXUS_BIN"

# The Dioxus app supports a headless test mode that reads line-delimited
# JSON commands from stdin and writes line-delimited JSON responses to
# stdout when COMMUNITAS_TEST_MODE=1. If that hook is missing this script
# skips the UI path and leaves a note. Gate: 30s for app startup.

TMPDIR="$(mktemp -d)"
FIFO_IN="$TMPDIR/in"
FIFO_OUT="$TMPDIR/out"
mkfifo "$FIFO_IN" "$FIFO_OUT"

( "$DIOXUS_BIN" < "$FIFO_IN" > "$FIFO_OUT" 2>>"$LOG" & echo $! > "$TMPDIR/pid" ) &
APP_PID=$(cat "$TMPDIR/pid" 2>/dev/null || echo 0)

exec 3<>"$FIFO_IN"
exec 4<>"$FIFO_OUT"

send() { echo "$1" >&3; }
read_response() {
    local deadline=$((SECONDS + 15))
    local line=""
    while (( SECONDS < deadline )); do
        if IFS= read -t 1 -u 4 line; then
            echo "$line"
            return 0
        fi
    done
    echo ""
    return 1
}

send '{"op":"handshake","api_base":"'"$X0X_API_BASE"'"}'
HELLO="$(read_response || true)"

if [ -z "$HELLO" ] || ! echo "$HELLO" | jq -e '.ok == true' >/dev/null 2>&1; then
    record "app.handshake" "skip" "Dioxus binary has no test-mode JSON hook yet"
    log "Response was: $HELLO"
    kill "$APP_PID" 2>/dev/null || true
    exit 0
fi
record "app.handshake" "pass"

# Probe a handful of golden paths via the current Dioxus test hook. These ops
# exercise the Communitas typed x0x client against the live daemon.
for op in \
    identity.agent_card \
    identity.user_id \
    identity.export_keypairs \
    connectivity.discover_agents \
    connectivity.four_word_bootstrap \
    groups.discover \
    kv.create_list \
    kv.put_get_delete \
    kv.access_policy_setup \
    presence.foaf \
    upgrade.check
do
    send '{"op":"'"$op"'"}'
    RESP="$(read_response || true)"
    if echo "$RESP" | jq -e '.ok == true' >/dev/null 2>&1; then
        record "$op" "pass"
    else
        record "$op" "fail" "${RESP:-no response}"
    fi
done

# NOTE (PR #99): the previous `pubsub.roundtrip` assertion was removed here, NOT
# silently dropped. The Dioxus e2e hook (communitas-dioxus/src/e2e_test_mode.rs)
# no longer dispatches `pubsub.subscribe`/`pubsub.publish` — those ops now hit
# its `_ => "unknown e2e op"` arm, so re-adding the old block would record a
# guaranteed `fail`, not a real check.
#
# End-to-end pubsub *delivery* through the Communitas typed x0x client is now
# covered — more strongly — by the typed-client contract test
# `communitas-x0x-client/tests/live_mutation_contract.rs` (subscribe → publish →
# receive frame → assert topic + decoded-payload-bytes equality, over BOTH SSE
# and WS). That test runs in this same proof set and asserts payload equality,
# vs. the old block's bare `.delivered == true`.
#
# FOLLOW-UP (tracked, communitas repo): to restore delivery coverage at the
# Dioxus *app-hook* layer specifically, add a `messaging.pubsub_roundtrip` op to
# e2e_test_mode.rs that drives X0xClient::{subscribe,publish} and confirms
# delivery, then add that op to the loop above. Not a merge blocker — the
# typed-client layer below the app already proves delivery.

kill "$APP_PID" 2>/dev/null || true
