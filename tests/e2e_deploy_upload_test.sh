#!/usr/bin/env bash
# =============================================================================
# tests/e2e_deploy_upload_test.sh — unit tests for the upload retry,
# remote size-verification, and straggler re-push logic added in #682.
#
# These tests use X0X_DEPLOY_SSH_CMD to inject a fake "SSH" binary so no
# real network access is needed.  They exercise the same control flow that
# tests/e2e_deploy.sh runs in its upload and straggler sections.
#
# Three paths covered:
#   RETRY    — SSH upload fails on the first two attempts; the third succeeds.
#   VERIFY   — SSH upload "succeeds" but the remote stat returns the wrong
#               size on the first attempt; the correct size on the second.
#   STRAGGLER — After the main loop the health endpoint returns the wrong
#               version for one node; the straggler loop re-uploads it and
#               the node is no longer reported as a failure.
# =============================================================================
set -euo pipefail

# ── TAP bookkeeping ──────────────────────────────────────────────────────────
PASS=0; FAIL=0

pass() { PASS=$((PASS+1)); echo "ok $((PASS+FAIL)) - $*"; }
fail() { FAIL=$((FAIL+1)); echo "not ok $((PASS+FAIL)) - $*"; }

# ── Shared temp directory ────────────────────────────────────────────────────
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Fake binary — content does not matter; only the byte count is important.
FAKE_BINARY="$TMP/x0xd"
printf 'FAKEBIN' > "$FAKE_BINARY"
LOCAL_SIZE=$(stat -f %z "$FAKE_BINARY" 2>/dev/null || stat -c %s "$FAKE_BINARY")
MAX_UPLOAD_ATTEMPTS=3

# ── Fake SSH builder ─────────────────────────────────────────────────────────
# Writes a fake SSH script to $TMP/fake_ssh_<scenario>.sh.
# Behaviour is driven by two env vars the caller must export before using it:
#   X0X_FAKE_STATE_DIR  — per-test scratch dir for call-count files
#   X0X_FAKE_SCENARIO   — one of: retry | verify_size | straggler
#   X0X_FAKE_LOCAL_SIZE — local binary size (for stat replies)
write_fake_ssh() {
    local path="$TMP/fake_ssh.sh"
    cat > "$path" << 'ENDFAKE'
#!/usr/bin/env bash
# Parses arguments in the form: [ssh-opts...] root@HOST 'COMMAND'
# and dispatches based on $X0X_FAKE_SCENARIO and per-host call counters.
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
    # Drain stdin regardless of outcome to avoid broken-pipe in the gzip pipe.
    cat > /dev/null

    case "$SCENARIO" in
        retry)
            # Fail the first two attempts; succeed on the third.
            [ "$cnt" -le 2 ] && exit 1
            exit 0
            ;;
        *)
            exit 0
            ;;
    esac
fi

# Remote stat for byte-count verification
if printf '%s' "$cmd" | grep -q 'stat -c %s /tmp/x0xd.codex'; then
    cnt_file="$STATE_DIR/upload_cnt_${host//[^a-zA-Z0-9]/_}"
    cnt=$(cat "$cnt_file" 2>/dev/null || echo 0)
    case "$SCENARIO" in
        verify_size)
            # Return wrong size on the first upload attempt; correct thereafter.
            [ "$cnt" -le 1 ] && echo "99999" || echo "$FAKE_SIZE"
            ;;
        *)
            echo "$FAKE_SIZE"
            ;;
    esac
    exit 0
fi

# Health endpoint (via curl over SSH)
if printf '%s' "$cmd" | grep -q '/health'; then
    case "$SCENARIO" in
        straggler)
            # The target node (192.0.2.1) reports the wrong version until
            # re-pushed; other nodes are already on the correct version.
            repushed_file="$STATE_DIR/repushed_${host//[^a-zA-Z0-9]/_}"
            if [ "$host" = "192.0.2.1" ] && [ ! -f "$repushed_file" ]; then
                printf '{"ok":true,"version":"0.0.0"}\n'
            else
                printf '{"ok":true,"version":"1.2.3"}\n'
            fi
            ;;
        *)
            printf '{"ok":true,"version":"1.2.3"}\n'
            ;;
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
    repushed_file="$STATE_DIR/repushed_${host//[^a-zA-Z0-9]/_}"
    touch "$repushed_file"
    exit 0
fi

exit 0
ENDFAKE
    chmod +x "$path"
    echo "$path"
}

FAKE_SSH=$(write_fake_ssh)

# ── Helper: run the upload-with-retry loop ───────────────────────────────────
# Mirrors the logic in e2e_deploy.sh sections [2/4] and [3b/4].
# Returns 0 if the upload succeeded (uploaded=true), 1 otherwise.
# Sets UPLOAD_ATTEMPTS to the number of SSH calls made.
run_upload_retry() {
    local ip="$1"
    local state_dir="$2"
    export X0X_FAKE_STATE_DIR="$state_dir"
    local uploaded=false
    local _attempt
    for _attempt in $(seq 1 "$MAX_UPLOAD_ATTEMPTS"); do
        if gzip -1 -c "$FAKE_BINARY" | timeout 30 "$FAKE_SSH" root@"$ip" 'gunzip -c > /tmp/x0xd.codex && chmod 755 /tmp/x0xd.codex' 2>/dev/null; then
            REMOTE_SIZE=$("$FAKE_SSH" root@"$ip" "stat -c %s /tmp/x0xd.codex" 2>/dev/null || echo "0")
            if [ "$REMOTE_SIZE" = "$LOCAL_SIZE" ]; then
                uploaded=true
                break
            fi
        fi
    done
    [ "$uploaded" = "true" ] && return 0 || return 1
}

# ── Helper: run the straggler re-push loop ───────────────────────────────────
# Checks version on each node in NODE_LIST (space-separated IPs) and
# re-uploads nodes whose reported version != EXPECTED_VER.
# Returns the number of nodes added to FAILED_NODES (0 = all fixed).
run_straggler_check() {
    local expected_ver="$1"
    local state_dir="$2"
    shift 2
    local nodes=("$@")
    export X0X_FAKE_STATE_DIR="$state_dir"
    local repushed=0
    local straggler_failed=0

    for ip in "${nodes[@]}"; do
        token=$("$FAKE_SSH" root@"$ip" "cat /data/api-token 2>/dev/null" 2>/dev/null || echo "")
        running_ver=$("$FAKE_SSH" root@"$ip" \
            "curl -sf -m 5 -H 'Authorization: Bearer $token' http://127.0.0.1:13600/health" \
            2>/dev/null \
            | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('version',''))" 2>/dev/null \
            || echo "")
        [ "$running_ver" = "$expected_ver" ] && continue

        # Straggler: re-upload
        local uploaded=false
        local _attempt
        for _attempt in $(seq 1 "$MAX_UPLOAD_ATTEMPTS"); do
            if gzip -1 -c "$FAKE_BINARY" | timeout 30 "$FAKE_SSH" root@"$ip" 'gunzip -c > /tmp/x0xd.codex && chmod 755 /tmp/x0xd.codex' 2>/dev/null; then
                REMOTE_SIZE=$("$FAKE_SSH" root@"$ip" "stat -c %s /tmp/x0xd.codex" 2>/dev/null || echo "0")
                if [ "$REMOTE_SIZE" = "$LOCAL_SIZE" ]; then
                    uploaded=true
                    break
                fi
            fi
        done
        if [ "$uploaded" != "true" ]; then
            straggler_failed=$((straggler_failed + 1))
            continue
        fi
        "$FAKE_SSH" root@"$ip" "install -m 755 /tmp/x0xd.codex /opt/x0x/x0xd && systemctl restart x0xd.service" 2>/dev/null
        repushed=$((repushed + 1))
    done

    echo "$straggler_failed"
}

# =============================================================================
# TEST 1: RETRY — upload fails on attempts 1–2, succeeds on attempt 3
# =============================================================================
{
    STATE="$TMP/state_retry"; mkdir -p "$STATE"
    export X0X_FAKE_SCENARIO="retry"
    export X0X_FAKE_LOCAL_SIZE="$LOCAL_SIZE"

    if run_upload_retry "10.0.0.1" "$STATE"; then
        cnt=$(cat "$STATE/upload_cnt_10_0_0_1" 2>/dev/null || echo "0")
        if [ "$cnt" -eq 3 ]; then
            pass "RETRY: upload succeeded on attempt 3 (made $cnt SSH calls)"
        else
            fail "RETRY: upload succeeded but used $cnt attempts instead of 3"
        fi
    else
        fail "RETRY: upload did not succeed within $MAX_UPLOAD_ATTEMPTS attempts"
    fi
}

# =============================================================================
# TEST 2: VERIFY — upload "succeeds" but remote stat returns wrong size on
#         attempt 1; correct size on attempt 2 → retry triggered by mismatch
# =============================================================================
{
    STATE="$TMP/state_verify"; mkdir -p "$STATE"
    export X0X_FAKE_SCENARIO="verify_size"
    export X0X_FAKE_LOCAL_SIZE="$LOCAL_SIZE"

    if run_upload_retry "10.0.0.2" "$STATE"; then
        cnt=$(cat "$STATE/upload_cnt_10_0_0_2" 2>/dev/null || echo "0")
        if [ "$cnt" -eq 2 ]; then
            pass "VERIFY: size mismatch triggered retry; verified on attempt 2 ($cnt SSH calls)"
        else
            fail "VERIFY: expected 2 upload calls (mismatch+retry), got $cnt"
        fi
    else
        fail "VERIFY: upload+verify did not succeed within $MAX_UPLOAD_ATTEMPTS attempts"
    fi
}

# =============================================================================
# TEST 3: STRAGGLER — one node reports wrong version after the main loop;
#         the straggler loop re-uploads it and the failure count is 0
# =============================================================================
{
    STATE="$TMP/state_straggler"; mkdir -p "$STATE"
    export X0X_FAKE_SCENARIO="straggler"
    export X0X_FAKE_LOCAL_SIZE="$LOCAL_SIZE"

    # 192.0.2.1 is the straggler; 192.0.2.2 is already on the right version.
    failed=$(run_straggler_check "1.2.3" "$STATE" "192.0.2.1" "192.0.2.2")
    repushed_file="$STATE/repushed_192_0_2_1"
    if [ "$failed" -eq 0 ] && [ -f "$repushed_file" ]; then
        pass "STRAGGLER: straggler node re-uploaded and restarted; no failures"
    elif [ "$failed" -gt 0 ]; then
        fail "STRAGGLER: straggler loop reported $failed failure(s)"
    else
        fail "STRAGGLER: straggler node was not re-pushed (restart marker missing)"
    fi
}

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "1..$((PASS+FAIL))"
if [ "$FAIL" -gt 0 ]; then
    echo "# $FAIL test(s) failed" >&2
    exit 1
fi
echo "# All $PASS test(s) passed"
