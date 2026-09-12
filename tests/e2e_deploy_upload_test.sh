#!/usr/bin/env bash
# =============================================================================
# tests/e2e_deploy_upload_test.sh — unit tests for the upload retry,
# remote size-verification, and straggler re-push logic added in #682.
#
# Sources tests/lib/deploy_upload.sh — the same library that e2e_deploy.sh
# sources and calls — and drives its two exported functions
# (x0x_upload_binary, x0x_scan_and_repush_stragglers) with a fake SSH
# command injected via X0X_DEPLOY_SSH_CMD.
#
# Three paths verified:
#   RETRY    — SSH upload fails on attempts 1–2; succeeds on attempt 3.
#   VERIFY   — SSH upload "succeeds" but the remote stat returns the wrong
#               size on the first attempt; the correct size on attempt 2.
#   STRAGGLER — After the main loop the health endpoint returns the wrong
#               version for one node; x0x_scan_and_repush_stragglers detects
#               it, re-uploads, and restarts it; FAILED_NODES stays empty.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── TAP bookkeeping ──────────────────────────────────────────────────────────
PASS=0; FAIL=0

pass() { PASS=$((PASS+1)); printf 'ok %d - %s\n' "$((PASS+FAIL))" "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'not ok %d - %s\n' "$((PASS+FAIL))" "$*"; }

# ── Shared temp directory ────────────────────────────────────────────────────
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Fake binary — content does not matter; only the byte count is checked.
BINARY="$TMP/x0xd"
printf 'FAKEBIN' > "$BINARY"
LOCAL_SIZE=$(stat -f %z "$BINARY" 2>/dev/null || stat -c %s "$BINARY")
MAX_UPLOAD_ATTEMPTS=3

# ── Fake SSH builder ─────────────────────────────────────────────────────────
# Writes $TMP/fake_ssh.sh.  Behaviour is controlled by two env vars the
# caller exports before invoking:
#   X0X_FAKE_STATE_DIR  — per-test scratch dir for call-count files
#   X0X_FAKE_SCENARIO   — retry | verify_size | straggler
#   X0X_FAKE_LOCAL_SIZE — local binary size (for stat replies)
#
# X0X_DEPLOY_SSH_CMD is set to this path so that e2e_deploy.sh's own
# SSH-override hook (and the library's $SSH variable) resolves to it.
FAKE_SSH="$TMP/fake_ssh.sh"
cat > "$FAKE_SSH" << 'ENDFAKE'
#!/usr/bin/env bash
# Parses: [ssh-opts…] root@HOST 'COMMAND'
host=""
cmd=""
for arg in "$@"; do
    case "$arg" in
        root@*) host="${arg#root@}" ;;
        *)      [ -n "$host" ] && [ -z "$cmd" ] && cmd="$arg" ;;
    esac
done

STATE_DIR="${X0X_FAKE_STATE_DIR:?X0X_FAKE_STATE_DIR not set}"
SCENARIO="${X0X_FAKE_SCENARIO:?X0X_FAKE_SCENARIO not set}"
FAKE_SIZE="${X0X_FAKE_LOCAL_SIZE:?X0X_FAKE_LOCAL_SIZE not set}"

# Connectivity probe
if [ "$cmd" = "true" ]; then exit 0; fi

# Upload (gunzip stream)
if printf '%s' "$cmd" | grep -q 'gunzip -c > /tmp/x0xd.codex'; then
    cnt_file="$STATE_DIR/upload_cnt_${host//[^a-zA-Z0-9]/_}"
    cnt=$(cat "$cnt_file" 2>/dev/null || echo 0)
    cnt=$((cnt + 1))
    printf '%s' "$cnt" > "$cnt_file"
    cat > /dev/null   # drain stdin so the gzip writer does not block
    case "$SCENARIO" in
        retry)
            [ "$cnt" -le 2 ] && exit 1 || exit 0 ;;
        *)
            exit 0 ;;
    esac
fi

# Remote stat for byte-count verification
if printf '%s' "$cmd" | grep -q 'stat -c %s /tmp/x0xd.codex'; then
    cnt_file="$STATE_DIR/upload_cnt_${host//[^a-zA-Z0-9]/_}"
    cnt=$(cat "$cnt_file" 2>/dev/null || echo 0)
    case "$SCENARIO" in
        verify_size)
            # Wrong size on first upload; correct thereafter
            [ "$cnt" -le 1 ] && echo "99999" || echo "$FAKE_SIZE" ;;
        *)
            echo "$FAKE_SIZE" ;;
    esac
    exit 0
fi

# Health endpoint (via inline curl command)
if printf '%s' "$cmd" | grep -q '/health'; then
    case "$SCENARIO" in
        straggler)
            repushed="$STATE_DIR/repushed_${host//[^a-zA-Z0-9]/_}"
            if [ "$host" = "192.0.2.1" ] && [ ! -f "$repushed" ]; then
                printf '{"ok":true,"version":"0.0.0"}\n'
            else
                printf '{"ok":true,"version":"1.2.3"}\n'
            fi ;;
        *)
            printf '{"ok":true,"version":"1.2.3"}\n' ;;
    esac
    exit 0
fi

# API token read
if printf '%s' "$cmd" | grep -q 'api-token'; then
    echo "test-token-stub"
    exit 0
fi

# install + systemctl restart — mark node as successfully re-pushed
if printf '%s' "$cmd" | grep -q 'install -m 755'; then
    touch "$STATE_DIR/repushed_${host//[^a-zA-Z0-9]/_}"
    exit 0
fi

exit 0
ENDFAKE
chmod +x "$FAKE_SSH"

# Export the hook used by e2e_deploy.sh (and inherited by the library via SSH=)
export X0X_DEPLOY_SSH_CMD="$FAKE_SSH"

# Source the library — same file e2e_deploy.sh sources.
# shellcheck source=lib/deploy_upload.sh
source "$SCRIPT_DIR/lib/deploy_upload.sh"

# Honour the X0X_DEPLOY_SSH_CMD hook: the deploy script applies it to SSH;
# we do the same here so the library functions see the fake command.
SSH="$X0X_DEPLOY_SSH_CMD"

# =============================================================================
# TEST 1: RETRY — x0x_upload_binary retries until attempt 3 succeeds
# =============================================================================
{
    STATE="$TMP/state_retry"; mkdir -p "$STATE"
    export X0X_FAKE_STATE_DIR="$STATE"
    export X0X_FAKE_SCENARIO="retry"
    export X0X_FAKE_LOCAL_SIZE="$LOCAL_SIZE"

    if x0x_upload_binary "10.0.0.1" > /dev/null 2>&1; then
        cnt=$(cat "$STATE/upload_cnt_10_0_0_1" 2>/dev/null || echo "0")
        if [ "$cnt" -eq 3 ]; then
            pass "RETRY: x0x_upload_binary succeeded on attempt 3 ($cnt SSH calls)"
        else
            fail "RETRY: upload succeeded but used $cnt attempt(s) instead of 3"
        fi
    else
        fail "RETRY: x0x_upload_binary did not succeed within $MAX_UPLOAD_ATTEMPTS attempts"
    fi
}

# =============================================================================
# TEST 2: VERIFY — size mismatch on attempt 1 triggers a retry; attempt 2 ok
# =============================================================================
{
    STATE="$TMP/state_verify"; mkdir -p "$STATE"
    export X0X_FAKE_STATE_DIR="$STATE"
    export X0X_FAKE_SCENARIO="verify_size"
    export X0X_FAKE_LOCAL_SIZE="$LOCAL_SIZE"

    if x0x_upload_binary "10.0.0.2" > /dev/null 2>&1; then
        cnt=$(cat "$STATE/upload_cnt_10_0_0_2" 2>/dev/null || echo "0")
        if [ "$cnt" -eq 2 ]; then
            pass "VERIFY: size mismatch triggered retry; verified on attempt 2 ($cnt SSH calls)"
        else
            fail "VERIFY: expected 2 upload calls (mismatch+retry), got $cnt"
        fi
    else
        fail "VERIFY: x0x_upload_binary did not succeed within $MAX_UPLOAD_ATTEMPTS attempts"
    fi
}

# =============================================================================
# TEST 3: STRAGGLER — x0x_scan_and_repush_stragglers detects a node on the
#         wrong version, re-uploads it, and leaves FAILED_NODES empty.
# =============================================================================
{
    STATE="$TMP/state_straggler"; mkdir -p "$STATE"
    export X0X_FAKE_STATE_DIR="$STATE"
    export X0X_FAKE_SCENARIO="straggler"
    export X0X_FAKE_LOCAL_SIZE="$LOCAL_SIZE"

    # Set the globals that x0x_scan_and_repush_stragglers reads.
    # 192.0.2.1 is the straggler; 192.0.2.2 is already on the right version.
    declare -a NODE_NAMES=("stale" "fresh")
    declare -A NODE_IPS=([stale]="192.0.2.1" [fresh]="192.0.2.2")
    VERSION="1.2.3"
    X0X_API_PORT="13600"
    X0X_BINARY_PATH="/opt/x0x/x0xd-testnet"
    X0X_SERVICE="x0xd-testnet.service"
    RUNNER_AGENT_DATA_DIR="/root/.local/share/x0x-testnet"
    FAILED_NODES=()

    x0x_scan_and_repush_stragglers > /dev/null 2>&1

    repushed_file="$STATE/repushed_192_0_2_1"
    if [ "${#FAILED_NODES[@]}" -eq 0 ] && [ -f "$repushed_file" ]; then
        pass "STRAGGLER: x0x_scan_and_repush_stragglers re-pushed stale node; FAILED_NODES empty"
    elif [ "${#FAILED_NODES[@]}" -gt 0 ]; then
        fail "STRAGGLER: FAILED_NODES non-empty after straggler pass (${FAILED_NODES[*]})"
    else
        fail "STRAGGLER: stale node was not re-pushed (install marker missing at $repushed_file)"
    fi
}

# ── Summary ──────────────────────────────────────────────────────────────────
printf '\n1..%d\n' "$((PASS+FAIL))"
if [ "$FAIL" -gt 0 ]; then
    printf '# %d test(s) failed\n' "$FAIL" >&2
    exit 1
fi
printf '# All %d test(s) passed\n' "$PASS"
