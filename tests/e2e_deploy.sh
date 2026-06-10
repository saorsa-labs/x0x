#!/usr/bin/env bash
# =============================================================================
# x0x Build, Deploy & Verify Bootstrap Nodes
#
# Cross-compiles for Linux, deploys to all 6 VPS nodes, verifies health + mesh.
# Writes API tokens to tests/.vps-tokens-<network>.env.
#
# DEFAULT NETWORK = TESTNET. Pass --network prod to target the production
# fleet (REAL USERS) — that path prints a loud red banner and waits 5 s for
# Ctrl-C before any action.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_DIR/target/x86_64-unknown-linux-gnu/release/x0xd"
RUNNER_SCRIPT="$SCRIPT_DIR/runners/x0x_test_runner.py"
RUNNER_UNIT="$SCRIPT_DIR/runners/x0x-test-runner.service"

# Network selector — sets X0X_NETWORK, X0X_API_PORT, X0X_SERVICE,
# X0X_TOKEN_FILE, X0X_TOKEN_VAR_PREFIX. Banner + 5 s hold for prod.
# Consumes the --network flag from "$@" and leaves the rest in
# X0X_FILTERED_ARGS.
# shellcheck source=/dev/null
source "$SCRIPT_DIR/x0x-network.sh"
x0x_network_select "$@"
set -- "${X0X_FILTERED_ARGS[@]+"${X0X_FILTERED_ARGS[@]}"}"

TOKEN_FILE="$X0X_TOKEN_FILE"
# Per-network runner identity: testnet runs alongside prod, must not collide.
if [ "$X0X_NETWORK" = "prod" ]; then
    RUNNER_UNIT_NAME="x0x-test-runner.service"
    RUNNER_ENV_FILE="/etc/x0x-test-runner.env"
    RUNNER_AGENT_DATA_DIR="/root/.local/share/x0x"
else
    RUNNER_UNIT_NAME="x0x-test-runner-testnet.service"
    RUNNER_ENV_FILE="/etc/x0x-test-runner-testnet.env"
    RUNNER_AGENT_DATA_DIR="/root/.local/share/x0x-testnet"
fi
DEPLOY_RUNNER="${DEPLOY_RUNNER:-1}"
MESH_VERIFY="${MESH_VERIFY:-0}"
MESH_ANCHOR="${MESH_ANCHOR:-nyc}"
MESH_DISCOVER_SECS="${MESH_DISCOVER_SECS:-45}"
MESH_SETTLE_SECS="${MESH_SETTLE_SECS:-45}"
VERSION="$(grep '^version = ' "$PROJECT_DIR/Cargo.toml" | head -1 | cut -d '"' -f2)"
SSH="ssh -C -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes"

# CLI overrides (--mesh-verify / --skip-mesh-verify)
for arg in "$@"; do
    case "$arg" in
        --mesh-verify) MESH_VERIFY=1 ;;
        --skip-mesh-verify) MESH_VERIFY=0 ;;
        --mesh-anchor=*) MESH_ANCHOR="${arg#*=}" ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0

check() {
    local n="$1" ok="$2"; TOTAL=$((TOTAL+1))
    if [ "$ok" = "true" ]; then PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n"
    else FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n"; fi
}

# ── Node definitions ────────────────────────────────────────────────────
declare -a NODE_NAMES=(nyc sfo helsinki nuremberg singapore sydney)
declare -A NODE_IPS=(
    [nyc]="142.93.199.50"
    [sfo]="147.182.234.192"
    [helsinki]="65.21.157.229"
    [nuremberg]="116.203.101.172"
    [singapore]="152.42.210.67"
    [sydney]="170.64.176.102"
)

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   x0x v$VERSION — Build, Deploy & Verify Bootstrap Nodes${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

# ═════════════════════════════════════════════════════════════════════════
# 1. BUILD
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[1/4] Cross-compile for Linux x86_64${NC}"

if [ "${SKIP_BUILD:-}" = "1" ] && [ -f "$BINARY" ]; then
    echo -e "  ${YELLOW}Skipping build (SKIP_BUILD=1), using existing binary${NC}"
else
    cd "$PROJECT_DIR"
    echo "  Building x0xd for x86_64-unknown-linux-gnu..."
    cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd 2>&1 | tail -5
    if [ ! -f "$BINARY" ]; then
        echo -e "  ${RED}Build failed — binary not found at $BINARY${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}Build complete${NC}: $(ls -lh "$BINARY" | awk '{print $5}')"
fi

# ═════════════════════════════════════════════════════════════════════════
# 2. DEPLOY TO ALL 6 NODES
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[2/4] Deploy to 6 VPS bootstrap nodes${NC}"

FAILED_NODES=()
for node in "${NODE_NAMES[@]}"; do
    ip="${NODE_IPS[$node]}"
    echo -e "\n  ${CYAN}$node${NC} ($ip):"

    # Check SSH connectivity
    if ! $SSH root@"$ip" 'true' 2>/dev/null; then
        echo -e "    ${RED}SSH connection failed${NC}"
        FAILED_NODES+=("$node")
        continue
    fi

    # Stream to a temp path and install atomically. These hosts accept SSH
    # command execution reliably, but SFTP/scp in-place replacement can fail.
    echo -n "    Uploading binary... "
    if cat "$BINARY" | $SSH root@"$ip" 'cat > /tmp/x0xd.codex && chmod 755 /tmp/x0xd.codex' 2>/dev/null; then
        echo -e "${GREEN}done${NC}"
    else
        echo -e "${RED}failed${NC}"
        FAILED_NODES+=("$node")
        continue
    fi

    # Install atomically to the network's OWN binary path and restart. Prod and
    # testnet use SEPARATE paths ($X0X_BINARY_PATH: /opt/x0x/x0xd for prod,
    # /opt/x0x/x0xd-testnet for test) so prod's self-upgrade can never overwrite
    # a freshly-deployed testnet binary (and vice versa). For the testnet we also
    # idempotently repoint the unit's ExecStart at the testnet path (migrating
    # hosts whose x0xd-testnet.service still references the old shared path) and
    # daemon-reload only when the unit actually changed.
    echo -n "    Restarting $X0X_SERVICE (bin $X0X_BINARY_PATH)... "
    if $SSH root@"$ip" "
        install -m 755 /tmp/x0xd.codex '$X0X_BINARY_PATH' && rm -f /tmp/x0xd.codex
        if [ '$X0X_NETWORK' != 'prod' ]; then
            unit=\$(systemctl show -p FragmentPath --value '$X0X_SERVICE')
            if [ -n \"\$unit\" ] && grep -qE '^ExecStart=/opt/x0x/x0xd ' \"\$unit\"; then
                sed -i 's#^ExecStart=/opt/x0x/x0xd #ExecStart=$X0X_BINARY_PATH #' \"\$unit\"
                systemctl daemon-reload
            fi
        fi
        systemctl restart '$X0X_SERVICE'
    " 2>/dev/null; then
        echo -e "${GREEN}done${NC}"
    else
        echo -e "${RED}failed${NC}"
        FAILED_NODES+=("$node")
        continue
    fi

    # Enforce a hard log budget so verbose daemon output can never fill the
    # disk (a runaway /var/log/syslog at ~14-18 GB/day once truncated a binary
    # mid-deploy and contaminated a soak). journald capped at 1G; rsyslog's
    # syslog/messages rotated at maxsize 200M x5 compressed; logrotate run
    # hourly (stock cadence is daily — too slow for busy bootstrap nodes).
    # Idempotent: safe to re-run every deploy. x0xd itself now logs per-packet
    # recv/send at DEBUG (not INFO), so steady-state volume is already low.
    echo -n "    Enforcing log budget (<5G)... "
    if $SSH root@"$ip" '
        mkdir -p /etc/systemd/journald.conf.d
        printf "[Journal]\nSystemMaxUse=1G\nSystemMaxFileSize=200M\n" > /etc/systemd/journald.conf.d/99-x0x-cap.conf
        systemctl restart systemd-journald 2>/dev/null || true
        if [ -f /etc/logrotate.d/rsyslog ] && [ ! -f /etc/logrotate.d/rsyslog.x0x-bak ]; then
            mv /etc/logrotate.d/rsyslog /etc/logrotate.d/rsyslog.x0x-bak
        fi
        cat > /etc/logrotate.d/x0x-logcap <<"LRCONF"
/var/log/syslog
/var/log/messages
/var/log/kern.log
/var/log/auth.log
/var/log/daemon.log
/var/log/user.log
/var/log/debug
{
    su root adm
    rotate 5
    maxsize 200M
    missingok
    notifempty
    nocreate
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog 2>/dev/null || true
    endpostrotate
}
LRCONF
        printf "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf 2>/dev/null || true\n" > /etc/cron.hourly/x0x-logrotate
        chmod 0755 /etc/cron.hourly/x0x-logrotate
        /usr/sbin/logrotate -f /etc/logrotate.conf >/dev/null 2>&1 || true
    ' 2>/dev/null; then
        echo -e "${GREEN}done${NC}"
    else
        echo -e "${YELLOW}log-cap setup failed (continuing)${NC}"
    fi

    # Mesh test runner — single Python script + systemd unit + env file.
    # The runner subscribes to the test-control gossip topic so the Mac
    # harness can drive matrix tests through one SSH tunnel instead of
    # one SSH per assertion.
    if [ "$DEPLOY_RUNNER" = "1" ] && [ -f "$RUNNER_SCRIPT" ] && [ -f "$RUNNER_UNIT" ]; then
        echo -n "    Installing mesh test runner... "
        # Per-network unit + env file so prod and testnet runners coexist.
        # The Python script at /usr/local/bin/x0x-test-runner.py is shared;
        # the systemd unit uses EnvironmentFile= for the network-specific
        # endpoint + api-token path.
        REMOTE_UNIT_PATH="/etc/systemd/system/$RUNNER_UNIT_NAME"
        if cat "$RUNNER_SCRIPT" \
            | $SSH root@"$ip" 'cat > /tmp/x0x-test-runner.py.codex && chmod 755 /tmp/x0x-test-runner.py.codex' 2>/dev/null \
           && sed "s|EnvironmentFile=.*|EnvironmentFile=$RUNNER_ENV_FILE|" "$RUNNER_UNIT" \
            | $SSH root@"$ip" "cat > /tmp/$RUNNER_UNIT_NAME.codex" 2>/dev/null \
           && $SSH root@"$ip" "
                set -e
                install -m 755 /tmp/x0x-test-runner.py.codex /usr/local/bin/x0x-test-runner.py
                install -m 644 /tmp/$RUNNER_UNIT_NAME.codex $REMOTE_UNIT_PATH
                rm -f /tmp/x0x-test-runner.py.codex /tmp/$RUNNER_UNIT_NAME.codex
                cat > $RUNNER_ENV_FILE <<EOF
NODE_NAME=$node
X0X_API_BASE=http://127.0.0.1:$X0X_API_PORT
X0X_API_TOKEN=$RUNNER_AGENT_DATA_DIR/api-token
LOG_LEVEL=INFO
EOF
                systemctl daemon-reload
                systemctl enable --quiet $RUNNER_UNIT_NAME
                systemctl restart $RUNNER_UNIT_NAME
            " 2>/dev/null; then
            echo -e "${GREEN}done${NC}"
        else
            echo -e "${YELLOW}runner install failed (continuing)${NC}"
        fi
    fi

    # Rolling restart: 15s between nodes to avoid simultaneous bootstrap storm
    # (see rolling_start_requirement memory). Skip on the last node.
    if [ "$node" != "${NODE_NAMES[-1]}" ]; then
        echo "    Rolling delay 15s before next node..."
        sleep 15
    fi
done

if [ ${#FAILED_NODES[@]} -gt 0 ]; then
    echo -e "\n  ${RED}Deployment failed on: ${FAILED_NODES[*]}${NC}"
fi

# ═════════════════════════════════════════════════════════════════════════
# 3. WAIT FOR MESH FORMATION
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[3/4] Waiting 30s for mesh formation...${NC}"
sleep 30

# ═════════════════════════════════════════════════════════════════════════
# 4. VERIFY HEALTH, VERSION, MESH & COLLECT TOKENS
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[4/4] Verify health, version, mesh & collect tokens${NC}"

# Clear token file
echo "# x0x ${X0X_NETWORK^^} API tokens (UDP $X0X_GOSSIP_PORT / TCP $X0X_API_PORT)" > "$TOKEN_FILE"
echo "# Auto-generated by e2e_deploy.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$TOKEN_FILE"
echo "# Variable prefix: ${X0X_TOKEN_VAR_PREFIX}_<NODE>_<IP|TK>. Do NOT mix with the other network's tokens." >> "$TOKEN_FILE"
echo "" >> "$TOKEN_FILE"

for node in "${NODE_NAMES[@]}"; do
    ip="${NODE_IPS[$node]}"
    echo -e "\n  ${CYAN}$node${NC} ($ip):"

    # Check service status
    STATUS=$($SSH root@"$ip" "systemctl is-active $X0X_SERVICE" 2>/dev/null || echo "failed")
    check "$node service active" "$([ "$STATUS" = "active" ] && echo true || echo false)"

    if [ "$STATUS" != "active" ]; then
        echo "    Service not active, showing logs:"
        $SSH root@"$ip" "journalctl -u $X0X_SERVICE -n 10 --no-pager" 2>/dev/null || true
        continue
    fi

    # Read API token from the network-specific data dir
    TOKEN=$($SSH root@"$ip" "cat $RUNNER_AGENT_DATA_DIR/api-token 2>/dev/null" || echo "")
    if [ -n "$TOKEN" ]; then
        NODE_UPPER=$(echo "$node" | tr '[:lower:]' '[:upper:]')
        echo "${X0X_TOKEN_VAR_PREFIX}_${NODE_UPPER}_IP=\"$ip\"" >> "$TOKEN_FILE"
        echo "${X0X_TOKEN_VAR_PREFIX}_${NODE_UPPER}_TK=\"$TOKEN\"" >> "$TOKEN_FILE"
        echo "    Token: ${TOKEN:0:16}..."
    else
        echo -e "    ${RED}Could not read API token${NC}"
    fi

    # Health check
    HEALTH=$($SSH root@"$ip" "curl -sf -m 5 -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$X0X_API_PORT/health" 2>/dev/null || echo '{"error":"failed"}')
    check "$node health ok" "$(echo "$HEALTH" | grep -q '"ok":true\|"ok": true' && echo true || echo false)"

    # Version check
    HAS_VERSION=$(echo "$HEALTH" | python3 -c "import sys,json;d=json.load(sys.stdin);print('$VERSION' in str(d))" 2>/dev/null || echo "False")
    check "$node version $VERSION" "$([ "$HAS_VERSION" = "True" ] && echo true || echo false)"

    # Peer count
    NET=$($SSH root@"$ip" "curl -sf -m 5 -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$X0X_API_PORT/network/status" 2>/dev/null || echo '{}')
    PEERS=$(echo "$NET" | python3 -c "import sys,json;print(json.load(sys.stdin).get('connected_peers',0))" 2>/dev/null || echo "0")
    check "$node has peers (got $PEERS)" "$([ "$PEERS" -ge 1 ] 2>/dev/null && echo true || echo false)"
    echo "    Connected peers: $PEERS"
done

# ═════════════════════════════════════════════════════════════════════════
# OPTIONAL: MESH-DRIVEN VERIFICATION (--mesh-verify or MESH_VERIFY=1)
# ═════════════════════════════════════════════════════════════════════════
# Drives an end-to-end protocol test through the freshly-deployed fleet
# using x0x's own DM + group-message primitives. One SSH tunnel to the
# anchor; everything else flows through the new code on the new daemons,
# which is the strongest "the deploy is good" signal we can get without
# adding a daemon-side test endpoint.
MESH_RC=0
if [ "$MESH_VERIFY" = "1" ] && [ $FAIL -eq 0 ]; then
    echo -e "\n${CYAN}[5/4] Mesh-driven verification (anchor=$MESH_ANCHOR)${NC}"
    echo "  This replaces the per-node SSH+curl status checks with a"
    echo "  single mesh round-trip that exercises DMs + groups."

    # 1. Phase-A all-pairs DM matrix.
    if python3 "$SCRIPT_DIR/e2e_vps_mesh.py" \
        --anchor "$MESH_ANCHOR" \
        --discover-secs "$MESH_DISCOVER_SECS" \
        --settle-secs "$MESH_SETTLE_SECS" \
        --local-port 22720; then
        echo -e "  ${GREEN}PASS${NC} mesh DM matrix"
    else
        rc=$?
        echo -e "  ${YELLOW}FAIL${NC} mesh DM matrix exit=$rc — see log"
        MESH_RC=$rc
    fi

    # 2. Phase-B groups + contacts dogfood.
    if python3 "$SCRIPT_DIR/e2e_vps_groups.py" \
        --anchor "$MESH_ANCHOR" \
        --discover-secs "$MESH_DISCOVER_SECS" \
        --local-port 22721; then
        echo -e "  ${GREEN}PASS${NC} mesh groups + contacts dogfood"
    else
        rc=$?
        echo -e "  ${YELLOW}FAIL${NC} mesh groups + contacts dogfood exit=$rc — see log"
        MESH_RC=$((MESH_RC + rc))
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ] && [ $MESH_RC -eq 0 ]; then
    echo -e "${GREEN}  ALL $TOTAL CHECKS PASSED${NC}"
    if [ "$MESH_VERIFY" = "1" ]; then
        echo -e "  ${GREEN}+ mesh-driven verification clean${NC}"
    fi
    echo -e "  Tokens written to: $TOKEN_FILE"
    echo -e "  Run: bash tests/e2e_vps.sh    (legacy SSH-per-call)"
    echo -e "  Or:  python3 tests/e2e_vps_mesh.py --anchor $MESH_ANCHOR"
else
    if [ $FAIL -gt 0 ]; then
        echo -e "${RED}  $FAIL FAILED / $TOTAL TOTAL${NC} ($PASS passed)"
    fi
    if [ $MESH_RC -ne 0 ]; then
        echo -e "${RED}  Mesh verification non-zero (exit codes summed=$MESH_RC)${NC}"
    fi
fi
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

OVERALL=$FAIL
[ $MESH_RC -ne 0 ] && OVERALL=$((OVERALL + MESH_RC))
exit $OVERALL
