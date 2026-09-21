#!/usr/bin/env bash
# Offline boundary tests for tests/e2e_deploy.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DEPLOY="$SCRIPT_DIR/e2e_deploy.sh"
PASS=0
FAIL=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass() { PASS=$((PASS + 1)); printf 'ok %d - %s\n' "$((PASS + FAIL))" "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'not ok %d - %s\n' "$((PASS + FAIL))" "$*"; }

make_fixture() {
    local root="$1"
    mkdir -p "$root/tests/lib" "$root/bin" "$root/target/x86_64-unknown-linux-gnu/release"
    cp "$SOURCE_DEPLOY" "$root/tests/e2e_deploy.sh"
    cat > "$root/Cargo.toml" <<'EOF'
[package]
name = "deploy-boundary-fixture"
version = "9.8.7"
EOF
    cat > "$root/tests/x0x-network.sh" <<'EOF'
x0x_network_select() {
    X0X_NETWORK=test
    X0X_API_PORT=13600
    X0X_GOSSIP_PORT=23600
    X0X_SERVICE=x0xd-testnet.service
    X0X_BINARY_PATH=/opt/x0x/x0xd-testnet
    X0X_TOKEN_FILE="${BASH_SOURCE[0]%/*}/tokens.env"
    X0X_TOKEN_VAR_PREFIX=TEST
    X0X_FILTERED_ARGS=()
}
EOF
    cat > "$root/tests/lib/deploy_upload.sh" <<'EOF'
x0x_upload_binary() {
    printf 'upload %s\n' "$1" >> "$X0X_FAKE_REMOTE_LOG"
}
x0x_scan_and_repush_stragglers() {
    STRAGGLERS_REPUSHED=0
}
EOF
    cat > "$root/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf 'build-line-one\nbuild-line-two\nbuild-line-three\nbuild-line-four\nbuild-line-five\nbuild-line-six\n'
if [ "${FAKE_BUILD_STATUS:-0}" -ne 0 ]; then
    exit "$FAKE_BUILD_STATUS"
fi
mkdir -p target/x86_64-unknown-linux-gnu/release
printf 'fresh-binary' > target/x86_64-unknown-linux-gnu/release/x0xd
EOF
    cat > "$root/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat > "$root/bin/fake-ssh" <<'EOF'
#!/usr/bin/env bash
host=""
cmd=""
for arg in "$@"; do
    case "$arg" in
        root@*) host="${arg#root@}" ;;
        *) [ -n "$host" ] && [ -z "$cmd" ] && cmd="$arg" ;;
    esac
done
printf '%s|%s\n' "$host" "$cmd" >> "$X0X_FAKE_REMOTE_LOG"
case "$cmd" in
    true) exit 0 ;;
    *"systemctl is-active"*) echo active ;;
    *"cat /root/.local/share/x0x-testnet/api-token"*) echo "super-secret-token-material" ;;
    *"/health"*) printf '{"ok":true,"version":"9.8.7"}\n' ;;
    *"/network/status"*) printf '{"connected_peers":5}\n' ;;
esac
exit 0
EOF
    chmod +x "$root/tests/e2e_deploy.sh" "$root/bin/cargo" "$root/bin/sleep" "$root/bin/fake-ssh"
}

# A native build failure must win even when a stale binary exists, print the
# complete captured output, and perform no remote action.
{
    ROOT="$TMP/fail"; make_fixture "$ROOT"
    printf 'stale-binary' > "$ROOT/target/x86_64-unknown-linux-gnu/release/x0xd"
    : > "$ROOT/remote.log"
    set +e
    OUTPUT=$(cd "$ROOT" && PATH="$ROOT/bin:$PATH" FAKE_BUILD_STATUS=37 \
        X0X_FAKE_REMOTE_LOG="$ROOT/remote.log" \
        X0X_DEPLOY_SSH_CMD="$ROOT/bin/fake-ssh" \
        bash tests/e2e_deploy.sh 2>&1)
    STATUS=$?
    set -e
    if [ "$STATUS" -eq 37 ] \
        && grep -q 'build-line-one' <<<"$OUTPUT" \
        && grep -q 'build-line-six' <<<"$OUTPUT" \
        && [ ! -s "$ROOT/remote.log" ]; then
        pass "failed zigbuild preserves native exit, prints full output, and never deploys stale binary"
    else
        fail "failed zigbuild boundary (status=$STATUS remote_bytes=$(wc -c < "$ROOT/remote.log"))"
    fi
}

# The opt-out must skip only host-global log policy. Binary deployment,
# restart, verification, and token collection still proceed without leaking
# token bytes to stdout/stderr.
{
    ROOT="$TMP/success"; make_fixture "$ROOT"
    : > "$ROOT/remote.log"
    set +e
    OUTPUT=$(cd "$ROOT" && PATH="$ROOT/bin:$PATH" FAKE_BUILD_STATUS=0 \
        CONFIGURE_LOG_CAPS=0 DEPLOY_RUNNER=0 \
        X0X_FAKE_REMOTE_LOG="$ROOT/remote.log" \
        X0X_DEPLOY_SSH_CMD="$ROOT/bin/fake-ssh" \
        bash tests/e2e_deploy.sh 2>&1)
    STATUS=$?
    set -e
    if [ "$STATUS" -eq 0 ] \
        && grep -q 'build-line-six' <<<"$OUTPUT" \
        && ! grep -q 'build-line-one' <<<"$OUTPUT" \
        && grep -q 'Log-cap configuration skipped' <<<"$OUTPUT" \
        && grep -q 'API token obtained' <<<"$OUTPUT" \
        && ! grep -q 'super-secret-tok' <<<"$OUTPUT" \
        && ! grep -q 'super-secret-token-material' <<<"$OUTPUT" \
        && grep -q 'install -m 755' "$ROOT/remote.log" \
        && grep -q 'systemctl restart' "$ROOT/remote.log" \
        && grep -q 'TEST_NYC_TK="super-secret-token-material"' "$ROOT/tests/tokens.env" \
        && ! grep -qE 'journald\.conf|x0x-logcap|cron\.hourly' "$ROOT/remote.log"; then
        pass "successful testnet deploy skips global log policy and emits no token bytes"
    else
        fail "successful opt-out boundary (status=$STATUS)"
    fi
}

# Omission preserves the existing host-global log-cap behavior.
{
    ROOT="$TMP/default"; make_fixture "$ROOT"
    printf 'existing-binary' > "$ROOT/target/x86_64-unknown-linux-gnu/release/x0xd"
    : > "$ROOT/remote.log"
    set +e
    OUTPUT=$(cd "$ROOT" && PATH="$ROOT/bin:$PATH" SKIP_BUILD=1 DEPLOY_RUNNER=0 \
        X0X_FAKE_REMOTE_LOG="$ROOT/remote.log" \
        X0X_DEPLOY_SSH_CMD="$ROOT/bin/fake-ssh" \
        bash tests/e2e_deploy.sh 2>&1)
    STATUS=$?
    set -e
    if [ "$STATUS" -eq 0 ] \
        && grep -q 'Enforcing log budget' <<<"$OUTPUT" \
        && grep -qE 'journald\.conf|x0x-logcap|cron\.hourly' "$ROOT/remote.log"; then
        pass "default deployment still configures the existing global log policy"
    else
        fail "default log-policy behavior (status=$STATUS)"
    fi
}

# Invalid values fail before connectivity, upload, or any other remote call.
{
    ROOT="$TMP/invalid"; make_fixture "$ROOT"
    : > "$ROOT/remote.log"
    set +e
    OUTPUT=$(cd "$ROOT" && PATH="$ROOT/bin:$PATH" CONFIGURE_LOG_CAPS=maybe \
        X0X_FAKE_REMOTE_LOG="$ROOT/remote.log" \
        X0X_DEPLOY_SSH_CMD="$ROOT/bin/fake-ssh" \
        bash tests/e2e_deploy.sh 2>&1)
    STATUS=$?
    set -e
    if [ "$STATUS" -eq 2 ] && grep -q 'must be 0 or 1' <<<"$OUTPUT" && [ ! -s "$ROOT/remote.log" ]; then
        pass "invalid CONFIGURE_LOG_CAPS fails before remote action"
    else
        fail "invalid option boundary (status=$STATUS)"
    fi
}

printf '\n1..%d\n' "$((PASS + FAIL))"
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
