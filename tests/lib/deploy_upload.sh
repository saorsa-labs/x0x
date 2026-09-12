# shellcheck shell=bash
# =============================================================================
# tests/lib/deploy_upload.sh — bounded upload, size-verify, and straggler
# re-push helpers for e2e_deploy.sh.
#
# Sourced by:
#   tests/e2e_deploy.sh              — the real deploy script
#   tests/e2e_deploy_upload_test.sh  — the unit test suite
#
# Required globals (set by the caller before invoking either function):
#   SSH              — SSH command string; honour X0X_DEPLOY_SSH_CMD if set
#   BINARY           — absolute path to the local binary
#   LOCAL_SIZE       — byte count of $BINARY (stat -f %z / -c %s)
#   MAX_UPLOAD_ATTEMPTS — maximum upload attempts per node (default 3)
#
# Additional globals consumed by x0x_scan_and_repush_stragglers:
#   NODE_NAMES          — indexed array of node names
#   NODE_IPS            — associative array: name → IP
#   VERSION             — expected running version string
#   X0X_API_PORT        — remote API port for /health
#   X0X_BINARY_PATH     — remote binary install path
#   X0X_SERVICE         — systemd service name
#   RUNNER_AGENT_DATA_DIR — remote path holding the api-token file
#   FAILED_NODES        — indexed array; failed nodes are appended here
#
# Colour codes (GREEN, YELLOW, RED, CYAN, NC) are used when set; callers that
# do not define them get plain output.
# =============================================================================

# x0x_upload_binary IP
#
# Streams $BINARY to /tmp/x0xd.codex on the remote and verifies the received
# byte count against $LOCAL_SIZE.  Each attempt is hard-capped at 900 s via
# `timeout`.  Tries up to $MAX_UPLOAD_ATTEMPTS times.
#
# Sets the caller's 'uploaded' variable to 'true' on success.
# Returns 0 on success, 1 on total failure (caller decides what to do next).
x0x_upload_binary() {
    local _ip="$1"
    uploaded=false
    local _attempt _remote
    for _attempt in $(seq 1 "$MAX_UPLOAD_ATTEMPTS"); do
        printf '    Uploading binary (attempt %s/%s)... ' "$_attempt" "$MAX_UPLOAD_ATTEMPTS"
        # shellcheck disable=SC2086  # intentional word-split on $SSH
        if gzip -1 -c "$BINARY" | timeout 900 $SSH root@"$_ip" \
                'gunzip -c > /tmp/x0xd.codex && chmod 755 /tmp/x0xd.codex' 2>/dev/null; then
            # shellcheck disable=SC2086
            _remote=$($SSH root@"$_ip" "stat -c %s /tmp/x0xd.codex" 2>/dev/null || echo "0")
            if [ "$_remote" = "$LOCAL_SIZE" ]; then
                printf '%sdone%s\n' "${GREEN:-}" "${NC:-}"
                uploaded=true
                break
            else
                printf '%ssize mismatch (local=%s remote=%s)%s\n' \
                    "${YELLOW:-}" "$LOCAL_SIZE" "$_remote" "${NC:-}"
            fi
        else
            printf '%sfailed%s\n' "${YELLOW:-}" "${NC:-}"
        fi
    done
    [ "$uploaded" = "true" ]
}

# x0x_scan_and_repush_stragglers
#
# Checks every node in NODE_NAMES that is not already in FAILED_NODES.
# Queries its /health endpoint; any node whose reported version != $VERSION
# is re-uploaded (via x0x_upload_binary) and restarted.
# Failed re-pushes are appended to FAILED_NODES.
x0x_scan_and_repush_stragglers() {
    local _node _ip _already _fn _token _running _straggler_nodes
    _straggler_nodes=()
    STRAGGLERS_REPUSHED=0

    for _node in "${NODE_NAMES[@]}"; do
        _ip="${NODE_IPS[$_node]}"
        _already=false
        for _fn in "${FAILED_NODES[@]+"${FAILED_NODES[@]}"}"; do
            [ "$_fn" = "$_node" ] && { _already=true; break; }
        done
        [ "$_already" = "true" ] && continue

        # shellcheck disable=SC2086
        _token=$($SSH root@"$_ip" \
            "cat $RUNNER_AGENT_DATA_DIR/api-token 2>/dev/null" 2>/dev/null || echo "")
        # shellcheck disable=SC2086
        _running=$($SSH root@"$_ip" \
            "curl -sf -m 5 -H 'Authorization: Bearer $_token' \
             http://127.0.0.1:$X0X_API_PORT/health" 2>/dev/null \
            | python3 -c \
                "import sys,json;d=json.load(sys.stdin);print(d.get('version',''))" \
              2>/dev/null \
            || echo "")

        if [ "$_running" != "$VERSION" ]; then
            _straggler_nodes+=("$_node")
            printf '  %sstraggler%s: %s running '\''%s'\'' expected '\''%s'\''\n' \
                "${YELLOW:-}" "${NC:-}" "$_node" "${_running:-unknown}" "$VERSION"
        fi
    done

    [ "${#_straggler_nodes[@]}" -eq 0 ] && { STRAGGLERS_REPUSHED=0; return 0; }

    STRAGGLERS_REPUSHED=${#_straggler_nodes[@]}
    printf '  Re-uploading %d straggler(s): %s\n' \
        "${#_straggler_nodes[@]}" "${_straggler_nodes[*]}"

    for _node in "${_straggler_nodes[@]}"; do
        _ip="${NODE_IPS[$_node]}"
        printf '\n  %s%s%s (%s) [straggler re-push]:\n' \
            "${CYAN:-}" "$_node" "${NC:-}" "$_ip"

        x0x_upload_binary "$_ip"
        if [ "$uploaded" != "true" ]; then
            printf '    %sstraggler re-upload failed%s\n' "${RED:-}" "${NC:-}"
            FAILED_NODES+=("$_node")
            continue
        fi

        printf '    Restarting %s (straggler)... ' "$X0X_SERVICE"
        # shellcheck disable=SC2086
        if $SSH root@"$_ip" "
            install -m 755 /tmp/x0xd.codex '$X0X_BINARY_PATH' && \
            rm -f /tmp/x0xd.codex
            systemctl restart '$X0X_SERVICE'
        " 2>/dev/null; then
            printf '%sdone%s\n' "${GREEN:-}" "${NC:-}"
        else
            printf '%sfailed%s\n' "${RED:-}" "${NC:-}"
            FAILED_NODES+=("$_node")
        fi
    done
}
