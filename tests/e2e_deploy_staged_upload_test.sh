#!/usr/bin/env bash
# Inert execution of the real staged-copy command; no SSH, install path, or
# daemon on the host is touched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'ok %d - %s\n' "$((PASS + FAIL))" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'not ok %d - %s\n' "$((PASS + FAIL))" "$1"; }

BINARY="$TMP/local-x0xd"
printf 'reviewed-artifact-fixture' > "$BINARY"
EXPECTED=$(shasum -a 256 "$BINARY" | cut -d ' ' -f1)
RUN_ID=stage-787-c5e78290-20260922
X0X_DEPLOY_STAGED_RUN_ID="$RUN_ID"
X0X_DEPLOY_STAGED_SHA256="$EXPECTED"
X0X_NETWORK=test
MAX_UPLOAD_ATTEMPTS=3
SSH="$TMP/fake-ssh"
export X0X_FAKE_STAGE="$TMP/stage" X0X_FAKE_DEST="$TMP/x0xd.codex"
export X0X_FAKE_RUN_ID="$RUN_ID" X0X_FAKE_TRACE="$TMP/ssh-calls"

cat > "$SSH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" = root@192.0.2.42 ]] || exit 90
cmd="$2"
[[ "$cmd" = *"/tmp/x0x-artifact-stage-$X0X_FAKE_RUN_ID"* ]] || exit 91
printf 'staged-command\n' >> "$X0X_FAKE_TRACE"
cmd="${cmd//\/tmp\/x0x-artifact-stage-$X0X_FAKE_RUN_ID/$X0X_FAKE_STAGE}"
cmd="${cmd//\/tmp\/x0xd.codex/$X0X_FAKE_DEST}"
bash -c "$cmd"
EOF
chmod +x "$SSH"

# shellcheck source=lib/deploy_upload.sh
source "$SCRIPT_DIR/lib/deploy_upload.sh"

make_stage() {
    rm -rf "$X0X_FAKE_STAGE" "$X0X_FAKE_DEST"
    mkdir -p "$X0X_FAKE_STAGE/artifact"
    printf %s "$RUN_ID" > "$X0X_FAKE_STAGE/.x0x-stage-owner"
    cp "$BINARY" "$X0X_FAKE_STAGE/artifact/x0xd"
}

make_stage
if x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = true ] \
    && cmp -s "$BINARY" "$X0X_FAKE_DEST"; then
    pass 'staged command copies verified bytes to the scratch destination'
else
    fail 'valid stage should copy and verify'
fi

make_stage
printf 'wrong-source' > "$X0X_FAKE_STAGE/artifact/x0xd"
if ! x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = false ] && [ ! -e "$X0X_FAKE_DEST" ]; then
    pass 'wrong stage SHA refuses without upload fallback'
else
    fail 'wrong stage SHA was accepted or touched destination'
fi

make_stage
printf 'different-owner' > "$X0X_FAKE_STAGE/.x0x-stage-owner"
if ! x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = false ] && [ ! -e "$X0X_FAKE_DEST" ]; then
    pass 'wrong owner marker refuses before copy'
else
    fail 'wrong owner marker was accepted or touched destination'
fi

make_stage
rm -rf "$X0X_FAKE_STAGE"
if ! x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = false ] && [ ! -e "$X0X_FAKE_DEST" ]; then
    pass 'missing stage refuses without upload fallback'
else
    fail 'missing stage was accepted or touched destination'
fi

make_stage
rm "$X0X_FAKE_STAGE/artifact/x0xd"
ln -s "$BINARY" "$X0X_FAKE_STAGE/artifact/x0xd"
if ! x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = false ] && [ ! -e "$X0X_FAKE_DEST" ]; then
    pass 'symlink source refuses before copy'
else
    fail 'symlink source was accepted or touched destination'
fi

make_stage
X0X_NETWORK=prod
before=$(wc -l < "$X0X_FAKE_TRACE")
if ! x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = false ] \
    && [ "$(wc -l < "$X0X_FAKE_TRACE")" -eq "$before" ]; then
    pass 'production refuses locally before any remote command'
else
    fail 'production was accepted or attempted remote action'
fi
X0X_NETWORK=test

X0X_DEPLOY_STAGED_SHA256=""
before=$(wc -l < "$X0X_FAKE_TRACE")
if ! x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = false ] \
    && [ "$(wc -l < "$X0X_FAKE_TRACE")" -eq "$before" ]; then
    pass 'partial staged opt-in refuses locally'
else
    fail 'partial staged opt-in was accepted or attempted remote action'
fi
X0X_DEPLOY_STAGED_SHA256="$EXPECTED"

X0X_DEPLOY_STAGED_SHA256="$(printf '%064d' 0)"
before=$(wc -l < "$X0X_FAKE_TRACE")
if ! x0x_upload_binary 192.0.2.42 >/dev/null 2>&1 \
    && [ "$uploaded" = false ] \
    && [ "$(wc -l < "$X0X_FAKE_TRACE")" -eq "$before" ]; then
    pass 'expected SHA must match local binary before remote command'
else
    fail 'local SHA mismatch was accepted or attempted remote action'
fi

printf '\n1..%d\n' "$((PASS + FAIL))"
[ "$FAIL" -eq 0 ] || exit 1
printf '# All %d tests passed\n' "$PASS"
