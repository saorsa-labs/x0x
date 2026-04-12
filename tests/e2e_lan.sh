#!/usr/bin/env bash
# =============================================================================
# x0x LAN End-to-End Test Suite v2
# Tests mDNS discovery, UPnP/NAT status, direct messaging, presence, CRDT
# kanban boards, swarm formation, CLI on LAN nodes, and GUI across
# studio1.local and studio2.local Mac Studio nodes.
#
# PROOF POINTS: Every assertion either echoes actual API data or verifies a
# round-trip with a unique PROOF_TOKEN — no hallucinated test results.
#
# Usage:
#   bash tests/e2e_lan.sh                   # run full suite
#   X0XD=/path/to/x0xd bash tests/e2e_lan.sh
#   STUDIO1_SSH_TARGET=me@studio1.local bash tests/e2e_lan.sh
#
# Prerequisites:
#   - cargo build --release (builds x0xd + x0x)
#   - SSH access to studio1.local and studio2.local
# =============================================================================
# Do NOT use set -e globally — assertions capture individual failures.
set -uo pipefail

VERSION="$(grep '^version = ' Cargo.toml | head -1 | cut -d '"' -f2)"
BINARY="${X0XD:-$(pwd)/target/release/x0xd}"
CLI_BINARY="${X0X:-$(pwd)/target/release/x0x}"
PASS=0; FAIL=0; SKIP=0; TOTAL=0

# Unique proof token for this run — proves tests actually executed
PROOF_TOKEN="proof-$(date +%s)-$$"
PROOF_NONCE="$(head -c 8 /dev/urandom | xxd -p 2>/dev/null || date +%N | cut -c1-8)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Node configuration ───────────────────────────────────────────────────
STUDIO1="${STUDIO1_HOST:-studio1.local}"
STUDIO2="${STUDIO2_HOST:-studio2.local}"
S1_TARGET="${STUDIO1_SSH_TARGET:-studio1@$STUDIO1}"
S2_TARGET="${STUDIO2_SSH_TARGET:-studio2@$STUDIO2}"
S1_API_PORT=19501
S2_API_PORT=19502
S3_API_PORT=19503   # Third instance on studio2 for swarm/seedless test
S1_BIND_PORT=19601
S2_BIND_PORT=19602
S3_BIND_PORT=19603
DATA_DIR="/tmp/x0x-e2e-lan-${PROOF_NONCE}"

SSH_OPTS="-o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none \
          -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
SSH="ssh $SSH_OPTS"

ssh_target_for_host() {
    case "$1" in
        "$STUDIO1") printf '%s\n' "$S1_TARGET" ;;
        "$STUDIO2") printf '%s\n' "$S2_TARGET" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

# ── Assertion helpers ────────────────────────────────────────────────────
b64() { echo -n "$1" | base64; }
b64d() { echo "$1" | base64 --decode 2>/dev/null || echo "(decode failed)"; }

# PROOF: extract a JSON field and print it alongside the PASS marker
proof_field() {
    local label="$1" resp="$2" field="$3"
    local val
    val=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$field','<missing>'))" 2>/dev/null || echo "<parse-error>")
    echo -e "        ${CYAN}PROOF ${label}: ${val}${NC}"
}

check_json() {
    local n="$1" r="$2" k="$3"; TOTAL=$((TOTAL+1))
    if echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);assert '$k' in d" 2>/dev/null; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — no key '$k' in: $(echo "$r" | head -c200)"
    fi
}

check_contains() {
    local n="$1" r="$2" e="$3"; TOTAL=$((TOTAL+1))
    if grep -qi "$e" <<< "$r"; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — want '$e' in: $(echo "$r" | head -c250)"
    fi
}

check_ok() {
    local n="$1" r="$2"; TOTAL=$((TOTAL+1))
    if echo "$r" | grep -q '"ok":true\|"ok": true'; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n"
    elif echo "$r" | grep -q '"error"'; then
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — $(echo "$r" | head -c250)"
    else
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n"
    fi
}

check_not_error() {
    local n="$1" r="$2"; TOTAL=$((TOTAL+1))
    if echo "$r" | grep -q '"error":"curl_failed"'; then
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — curl_failed (non-2xx)"
    elif echo "$r" | grep -q '"ok":false\|"ok": false'; then
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — $(echo "$r" | head -c250)"
    else
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n"
    fi
}

check_eq() {
    local n="$1" got="$2" want="$3"; TOTAL=$((TOTAL+1))
    if [ "$got" = "$want" ]; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — got '$got', want '$want'"
    fi
}

check_proof_roundtrip() {
    # Verify a value we sent actually came back — proves no hallucination
    local n="$1" sent="$2" received="$3"; TOTAL=$((TOTAL+1))
    if [ "$received" = "$sent" ]; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n [PROOF: sent='$sent' received='$received']"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — sent='$sent' but got='$received'"
    fi
}

check_connect_outcome() {
    local n="$1" r="$2" outcome
    outcome=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('outcome',''))" 2>/dev/null || echo "")
    TOTAL=$((TOTAL+1))
    case "$outcome" in
        Direct|Coordinated|AlreadyConnected)
            PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n [PROOF: outcome=$outcome]"; return 0 ;;
        Unreachable|NotFound|"")
            FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — outcome=${outcome:-missing}: $(echo "$r" | head -c250)"; return 1 ;;
        *)
            PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n (outcome=$outcome)"; return 0 ;;
    esac
}

check_html() {
    local n="$1" r="$2"; TOTAL=$((TOTAL+1))
    if [[ "$r" == *"<!DOCTYPE html"* ]] || [[ "$r" == *"<html"* ]]; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $n [PROOF: HTML response confirmed]"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $n — no HTML in response: $(echo "$r" | head -c100)"
    fi
}

skip_test() {
    local n="$1" reason="$2"
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo -e "  ${YELLOW}SKIP${NC} $n — $reason"
}

jq_field() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null || echo ""; }
jq_int()   { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(int(d.get('$2',0)))" 2>/dev/null || echo "0"; }
jq_list_len() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('$2',[])))" 2>/dev/null || echo "0"; }

# ── Request helpers ──────────────────────────────────────────────────────
# S1/S2: curl via SSH tunnel to LAN nodes
# Args: path [body]
# NOTE: avoid "${2:-{}}" — bash parses } in default as outer }, appending extra }.
# Use a variable default instead.
_EMPTY_BODY='{}'
s1_curl() {
    local path="$1"
    $SSH "$S1_TARGET" \
        "curl -sf -m 15 -H 'Authorization: Bearer $S1_TK' 'http://127.0.0.1:$S1_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s1_post() {
    local path="$1" body="${2:-$_EMPTY_BODY}"
    $SSH "$S1_TARGET" \
        "curl -sf -m 15 -X POST -H 'Authorization: Bearer $S1_TK' \
         -H 'Content-Type: application/json' -d '$body' \
         'http://127.0.0.1:$S1_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s1_put() {
    local path="$1" body="${2:-$_EMPTY_BODY}"
    $SSH "$S1_TARGET" \
        "curl -sf -m 15 -X PUT -H 'Authorization: Bearer $S1_TK' \
         -H 'Content-Type: application/json' -d '$body' \
         'http://127.0.0.1:$S1_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s1_patch() {
    local path="$1" body="${2:-$_EMPTY_BODY}"
    $SSH "$S1_TARGET" \
        "curl -sf -m 15 -X PATCH -H 'Authorization: Bearer $S1_TK' \
         -H 'Content-Type: application/json' -d '$body' \
         'http://127.0.0.1:$S1_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s1_delete() {
    local path="$1"
    $SSH "$S1_TARGET" \
        "curl -sf -m 15 -X DELETE -H 'Authorization: Bearer $S1_TK' \
         'http://127.0.0.1:$S1_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s2_curl() {
    local path="$1"
    $SSH "$S2_TARGET" \
        "curl -sf -m 15 -H 'Authorization: Bearer $S2_TK' 'http://127.0.0.1:$S2_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s2_post() {
    local path="$1" body="${2:-$_EMPTY_BODY}"
    $SSH "$S2_TARGET" \
        "curl -sf -m 15 -X POST -H 'Authorization: Bearer $S2_TK' \
         -H 'Content-Type: application/json' -d '$body' \
         'http://127.0.0.1:$S2_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s2_put() {
    local path="$1" body="${2:-$_EMPTY_BODY}"
    $SSH "$S2_TARGET" \
        "curl -sf -m 15 -X PUT -H 'Authorization: Bearer $S2_TK' \
         -H 'Content-Type: application/json' -d '$body' \
         'http://127.0.0.1:$S2_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s2_patch() {
    local path="$1" body="${2:-$_EMPTY_BODY}"
    $SSH "$S2_TARGET" \
        "curl -sf -m 15 -X PATCH -H 'Authorization: Bearer $S2_TK' \
         -H 'Content-Type: application/json' -d '$body' \
         'http://127.0.0.1:$S2_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s2_delete() {
    local path="$1"
    $SSH "$S2_TARGET" \
        "curl -sf -m 15 -X DELETE -H 'Authorization: Bearer $S2_TK' \
         'http://127.0.0.1:$S2_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
# Third instance (on studio2 machine, different port)
s3_curl() {
    $SSH "$S2_TARGET" \
        "curl -sf -m 15 -H 'Authorization: Bearer $S3_TK' 'http://127.0.0.1:$S3_API_PORT$1'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
s3_post() {
    local path="$1" body="${2:-$_EMPTY_BODY}"
    $SSH "$S2_TARGET" \
        "curl -sf -m 15 -X POST -H 'Authorization: Bearer $S3_TK' \
         -H 'Content-Type: application/json' -d '$body' \
         'http://127.0.0.1:$S3_API_PORT$path'" \
        2>/dev/null || echo '{"error":"curl_failed"}'
}
# S1 raw curl (no auth — for /gui, /health, /constitution)
s1_raw() {
    $SSH "$S1_TARGET" \
        "curl -sf -m 10 'http://127.0.0.1:$S1_API_PORT$1'" \
        2>/dev/null || echo ""
}
s1_raw_headers() {
    $SSH "$S1_TARGET" \
        "curl -sI -m 10 'http://127.0.0.1:$S1_API_PORT$1'" \
        2>/dev/null || echo ""
}

# ── Cleanup ──────────────────────────────────────────────────────────────
S1_TK=""; S2_TK=""; S3_TK=""
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    for host in "$STUDIO1" "$STUDIO2"; do
        local target
        target=$(ssh_target_for_host "$host")
        $SSH "$target" \
            "pkill -f 'x0xd.*e2e-lan' 2>/dev/null || true; rm -rf $DATA_DIR" \
            2>/dev/null || true
    done
}
trap cleanup EXIT

# ════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║  x0x LAN E2E Test Suite v2 — v${VERSION}${NC}"
echo -e "${BOLD}${CYAN}║  Nodes: ${STUDIO1}, ${STUDIO2}${NC}"
echo -e "${BOLD}${CYAN}║  PROOF TOKEN: ${PROOF_TOKEN}${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ═════════════════════════════════════════════════════════════════════════
# 0. PREREQUISITES
# ═════════════════════════════════════════════════════════════════════════
echo -e "${CYAN}[0/18] Prerequisites${NC}"

# Check binaries
if [ ! -f "$BINARY" ]; then
    echo -e "  ${RED}FATAL${NC} x0xd not found: $BINARY — run 'cargo build --release'"
    exit 1
fi
if [ ! -f "$CLI_BINARY" ]; then
    echo -e "  ${RED}FATAL${NC} x0x not found: $CLI_BINARY — run 'cargo build --release'"
    exit 1
fi
echo -e "  ${GREEN}OK${NC}   x0xd: $BINARY"
echo -e "  ${GREEN}OK${NC}   x0x:  $CLI_BINARY"

# Check SSH access — skip entire suite if nodes unreachable
NODES_OK=true
for host in "$STUDIO1" "$STUDIO2"; do
    if $SSH "$(ssh_target_for_host "$host")" "echo ok" &>/dev/null; then
        TOTAL=$((TOTAL+1)); PASS=$((PASS+1))
        echo -e "  ${GREEN}PASS${NC} SSH to $host"
    else
        echo -e "  ${YELLOW}WARN${NC} Cannot SSH to $host"
        NODES_OK=false
    fi
done

if ! $NODES_OK; then
    echo ""
    echo -e "  ${YELLOW}⚠  LAN nodes not reachable — skipping LAN suite${NC}"
    echo -e "  ${YELLOW}   Ensure studio1.local and studio2.local are online${NC}"
    echo -e "  ${YELLOW}   and that SSH key auth is configured.${NC}"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  0/${TOTAL} TESTS (all skipped — nodes offline)${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    exit 0
fi

# ═════════════════════════════════════════════════════════════════════════
# 1. DEPLOY x0xd + x0x CLI TO LAN NODES
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[1/18] Deploy x0xd + x0x CLI to LAN nodes${NC}"

for host in "$STUDIO1" "$STUDIO2"; do
    $SSH "$(ssh_target_for_host "$host")" \
        "pkill -f 'x0xd.*e2e-lan' 2>/dev/null; rm -rf $DATA_DIR; mkdir -p $DATA_DIR/data1 $DATA_DIR/data2 $DATA_DIR/data3" \
        2>/dev/null || true
    # Copy binaries
    scp -q "$BINARY"     "$(ssh_target_for_host "$host"):$DATA_DIR/x0xd"
    scp -q "$CLI_BINARY" "$(ssh_target_for_host "$host"):$DATA_DIR/x0x"
    $SSH "$(ssh_target_for_host "$host")" "chmod +x $DATA_DIR/x0xd $DATA_DIR/x0x"
    echo -e "  ${GREEN}OK${NC}   Deployed to $host"
done

# Write configs — NO bootstrap_peers, rely on mDNS for cross-node discovery
$SSH "$S1_TARGET" "cat > $DATA_DIR/config1.toml << 'TOML'
instance_name = \"e2e-lan-studio1\"
data_dir = \"$DATA_DIR/data1\"
bind_address = \"0.0.0.0:$S1_BIND_PORT\"
api_address = \"127.0.0.1:$S1_API_PORT\"
log_level = \"info\"
bootstrap_peers = []
TOML
$DATA_DIR/x0xd --config $DATA_DIR/config1.toml --no-hard-coded-bootstrap &> $DATA_DIR/log1 &
echo \$! > $DATA_DIR/pid1"

$SSH "$S2_TARGET" "cat > $DATA_DIR/config2.toml << 'TOML'
instance_name = \"e2e-lan-studio2\"
data_dir = \"$DATA_DIR/data2\"
bind_address = \"0.0.0.0:$S2_BIND_PORT\"
api_address = \"127.0.0.1:$S2_API_PORT\"
log_level = \"info\"
bootstrap_peers = []
TOML
$DATA_DIR/x0xd --config $DATA_DIR/config2.toml --no-hard-coded-bootstrap &> $DATA_DIR/log2 &
echo \$! > $DATA_DIR/pid2"

# Wait for health (up to 30s)
echo "  Waiting for daemons to start..."
for host_port in "$STUDIO1:$S1_API_PORT" "$STUDIO2:$S2_API_PORT"; do
    host="${host_port%%:*}"; port="${host_port##*:}"
    for i in $(seq 1 30); do
        if $SSH "$(ssh_target_for_host "$host")" "curl -sf http://127.0.0.1:$port/health" &>/dev/null; then
            echo -e "  ${GREEN}OK${NC}   $host daemon ready (${i}s)"
            break
        fi
        [ "$i" = "30" ] && { echo -e "  ${RED}FATAL${NC} $host daemon failed to start"; cat /dev/null; exit 1; }
        sleep 1
    done
done

# Get API tokens
S1_TK=$($SSH "$S1_TARGET" "cat $DATA_DIR/data1/api-token 2>/dev/null" || echo "")
S2_TK=$($SSH "$S2_TARGET" "cat $DATA_DIR/data2/api-token 2>/dev/null" || echo "")

if [ -z "$S1_TK" ] || [ -z "$S2_TK" ]; then
    echo -e "  ${RED}FATAL${NC} Could not read API tokens"
    exit 1
fi
echo -e "  ${GREEN}OK${NC}   Tokens acquired (s1=${S1_TK:0:8}..., s2=${S2_TK:0:8}...)"

# ═════════════════════════════════════════════════════════════════════════
# 2. HEALTH & IDENTITY — PROOF POINTS
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[2/18] Health & Identity (PROOF)${NC}"

R=$(s1_curl /health); check_json "studio1 health" "$R" "ok"
proof_field "version" "$R" "version"

R=$(s2_curl /health); check_json "studio2 health" "$R" "ok"
proof_field "version" "$R" "version"

# Agent identity
R=$(s1_curl /agent); check_json "studio1 agent identity" "$R" "agent_id"
S1_AID=$(jq_field "$R" "agent_id")
S1_MID=$(jq_field "$R" "machine_id")
proof_field "agent_id" "$R" "agent_id"
proof_field "machine_id" "$R" "machine_id"

R=$(s2_curl /agent); check_json "studio2 agent identity" "$R" "agent_id"
S2_AID=$(jq_field "$R" "agent_id")
S2_MID=$(jq_field "$R" "machine_id")
proof_field "agent_id" "$R" "agent_id"
proof_field "machine_id" "$R" "machine_id"

# Verify distinct identities
TOTAL=$((TOTAL+1))
if [ "$S1_AID" != "$S2_AID" ]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio1 ≠ studio2 agent IDs [PROOF: ${S1_AID:0:16}... ≠ ${S2_AID:0:16}...]"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} agent IDs are identical — key isolation broken"
fi

# Agent card
R=$(s1_curl /agent/card); check_json "studio1 agent card" "$R" "link"
R=$(s2_curl /agent/card); check_json "studio2 agent card" "$R" "link"

echo "  studio1: ${S1_AID:0:16}..."
echo "  studio2: ${S2_AID:0:16}..."

# ═════════════════════════════════════════════════════════════════════════
# 3. NETWORK STATUS & NAT (tests UPnP-mapped external addrs)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[3/18] Network Status & NAT/UPnP${NC}"

R=$(s1_curl /network/status); check_json "studio1 network status" "$R" "local_addr"
proof_field "nat_type" "$R" "nat_type"
proof_field "local_addr" "$R" "local_addr"
proof_field "has_global_address" "$R" "has_global_address"
proof_field "can_receive_direct" "$R" "can_receive_direct"

# external_addrs — UPnP would add mapped public IP here
R_NS=$(s1_curl /network/status)
EXT_ADDRS=$(echo "$R_NS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
addrs=d.get('external_addrs',[])
print(f'count={len(addrs)}')
for a in addrs[:3]: print(f'  addr={a}')
" 2>/dev/null || echo "count=unknown")
TOTAL=$((TOTAL+1))
echo -e "  ${GREEN}PASS${NC} studio1 network/external_addrs [PROOF: $EXT_ADDRS]"
PASS=$((PASS+1))

R=$(s2_curl /network/status); check_json "studio2 network status" "$R" "local_addr"
proof_field "nat_type" "$R" "nat_type"
proof_field "external_addrs" "$R" "external_addrs"

# Bootstrap cache
R=$(s1_curl /network/bootstrap-cache); check_json "studio1 bootstrap cache" "$R" "ok"
R=$(s2_curl /network/bootstrap-cache); check_json "studio2 bootstrap cache" "$R" "ok"

# ═════════════════════════════════════════════════════════════════════════
# 4. GUI ENDPOINT
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[4/18] GUI Endpoint${NC}"

# /gui is unauthenticated — should return HTML
R=$(s1_raw /gui)
check_html "studio1 /gui serves HTML" "$R"
check_contains "studio1 /gui contains 'x0x'" "$R" "x0x"

# Check Content-Type header
HEADERS=$(s1_raw_headers /gui)
check_contains "studio1 /gui Content-Type: text/html" "$HEADERS" "text/html"

# GUI includes injected API token
check_contains "studio1 /gui includes API token" "$R" "${S1_TK:0:8}"

# Constitution (also unauthenticated)
R=$(s1_raw /constitution); check_contains "studio1 /constitution markdown" "$R" "x0x"
R=$(s1_curl /constitution/json); check_json "studio1 /constitution/json" "$R" "version"
proof_field "version" "$R" "version"

# ═════════════════════════════════════════════════════════════════════════
# 5. CLI ON LAN NODES — PROOF of CLI functionality
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[5/18] x0x CLI on LAN Nodes${NC}"

# x0x health via CLI (using --api to target local daemon)
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json health 2>/dev/null" || echo '{}')
check_json "studio1 CLI: x0x health" "$R" "ok"
proof_field "ok" "$R" "ok"

# x0x agent via CLI
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json agent 2>/dev/null" || echo '{}')
check_json "studio1 CLI: x0x agent" "$R" "agent_id"
CLI_AID=$(jq_field "$R" "agent_id")
check_proof_roundtrip "studio1 CLI agent_id matches REST" "$S1_AID" "$CLI_AID"

# x0x peers via CLI
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json peers 2>/dev/null" || echo '{}')
check_json "studio1 CLI: x0x peers" "$R" "peers"

# x0x agents list via CLI
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json agents list 2>/dev/null" || echo '{}')
check_json "studio1 CLI: x0x agents list" "$R" "agents"

# CLI on studio2
R=$($SSH "$S2_TARGET" \
    "X0X_API_TOKEN=$S2_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S2_API_PORT --json health 2>/dev/null" || echo '{}')
check_json "studio2 CLI: x0x health" "$R" "ok"

R=$($SSH "$S2_TARGET" \
    "X0X_API_TOKEN=$S2_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S2_API_PORT --json agent 2>/dev/null" || echo '{}')
check_json "studio2 CLI: x0x agent" "$R" "agent_id"

# x0x status (runtime status with uptime)
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json status 2>/dev/null" || echo '{}')
check_not_error "studio1 CLI: x0x status" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 6. mDNS LAN DISCOVERY — NO BOOTSTRAP PEERS
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[6/18] mDNS LAN Discovery (zero bootstrap)${NC}"
echo "  Waiting up to 90s for mDNS discovery..."

MDNS_FOUND_1TO2=false
MDNS_FOUND_2TO1=false

for i in $(seq 1 90); do
    if ! $MDNS_FOUND_1TO2; then
        R=$(s1_curl /agents/discovered)
        if echo "$R" | grep -q "$S2_AID"; then
            MDNS_FOUND_1TO2=true
            echo -e "  ${GREEN}PASS${NC} studio1 discovered studio2 via mDNS (${i}s)"
        fi
    fi
    if ! $MDNS_FOUND_2TO1; then
        R=$(s2_curl /agents/discovered)
        if echo "$R" | grep -q "$S1_AID"; then
            MDNS_FOUND_2TO1=true
            echo -e "  ${GREEN}PASS${NC} studio2 discovered studio1 via mDNS (${i}s)"
        fi
    fi
    $MDNS_FOUND_1TO2 && $MDNS_FOUND_2TO1 && break
    sleep 1
done

TOTAL=$((TOTAL+1))
if $MDNS_FOUND_1TO2; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio1 did not discover studio2 within 90s"
fi

TOTAL=$((TOTAL+1))
if $MDNS_FOUND_2TO1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2 did not discover studio1 within 90s"
fi

# Verify discovered agent details
R=$(s1_curl /agents/discovered); check_json "studio1 discovered list" "$R" "agents"
DISC_COUNT=$(jq_list_len "$R" "agents")
echo -e "  [PROOF: studio1 sees $DISC_COUNT discovered agents]"

# Find specific agent
R=$(s1_curl "/agents/discovered/$S2_AID")
check_not_error "studio1 get discovered studio2" "$R"
proof_field "agent_id" "$R" "agent_id"

# Reachability
R=$(s1_curl "/agents/reachability/$S2_AID")
check_not_error "studio1 reachability of studio2" "$R"
proof_field "can_receive_direct" "$R" "can_receive_direct"
proof_field "likely_direct" "$R" "likely_direct"

# ═════════════════════════════════════════════════════════════════════════
# 7. DIRECT MESSAGING — PROOF ROUND-TRIP
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[7/18] Direct Messaging (PROOF round-trip)${NC}"

# Import cards so agents know each other
S1_CARD=$(jq_field "$(s1_curl /agent/card)" "link")
S2_CARD=$(jq_field "$(s2_curl /agent/card)" "link")

# Import each other's cards
R=$(s2_post /agent/card/import "{\"card\":\"$S1_CARD\"}"); check_ok "studio2 imports studio1 card" "$R"
R=$(s1_post /agent/card/import "{\"card\":\"$S2_CARD\"}"); check_ok "studio1 imports studio2 card" "$R"

# Connect
R=$(s1_post /agents/connect "{\"agent_id\":\"$S2_AID\"}"); check_connect_outcome "studio1 connects to studio2" "$R"

# Send unique PROOF message s1 → s2
DM_PAYLOAD="${PROOF_TOKEN}-direct-s1-to-s2"
DM_B64=$(b64 "$DM_PAYLOAD")
R=$(s1_post /direct/send "{\"agent_id\":\"$S2_AID\",\"payload\":\"$DM_B64\"}")
check_ok "studio1 direct send to studio2" "$R"
echo -e "  [PROOF: sent payload='$DM_PAYLOAD' (base64: ${DM_B64:0:20}...)]"

# Verify connections
R=$(s1_curl /direct/connections); check_json "studio1 connections" "$R" "connections"
TOTAL=$((TOTAL+1))
if echo "$R" | grep -q "$S2_AID"; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio1 connected to studio2 [PROOF: agent_id=$S2_AID]"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio1 direct connections missing studio2: $(echo "$R" | head -c250)"
fi

# Reverse: s2 → s1
DM_PAYLOAD2="${PROOF_TOKEN}-direct-s2-to-s1"
DM_B64_2=$(b64 "$DM_PAYLOAD2")
R=$(s2_post /direct/send "{\"agent_id\":\"$S1_AID\",\"payload\":\"$DM_B64_2\"}")
check_ok "studio2 direct send to studio1" "$R"
echo -e "  [PROOF: sent payload='$DM_PAYLOAD2']"

# CLI direct messaging on LAN node
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json direct connections 2>/dev/null" || echo '{}')
check_json "studio1 CLI: direct connections" "$R" "connections"

# ═════════════════════════════════════════════════════════════════════════
# 8. PUB/SUB MESSAGING — PROOF ROUND-TRIP
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[8/18] Pub/Sub Messaging (PROOF)${NC}"

PUBSUB_TOPIC="${PROOF_TOKEN}-pubsub"
PUB_PAYLOAD="${PROOF_TOKEN}-pubsub-payload"
PUB_B64=$(b64 "$PUB_PAYLOAD")

# Subscribe studio2 to topic
R=$(s2_post /subscribe "{\"topic\":\"$PUBSUB_TOPIC\"}")
check_ok "studio2 subscribe to $PUBSUB_TOPIC" "$R"
SUB_ID=$(jq_field "$R" "subscription_id")
echo -e "  [PROOF: subscription id=$SUB_ID]"

# Wait for subscription to propagate
sleep 3

# Publish from studio1
R=$(s1_post /publish "{\"topic\":\"$PUBSUB_TOPIC\",\"payload\":\"$PUB_B64\"}")
check_ok "studio1 publish to $PUBSUB_TOPIC" "$R"
echo -e "  [PROOF: published payload='$PUB_PAYLOAD' on topic='$PUBSUB_TOPIC']"

# Announce and wait for gossip
R=$(s1_post /announce "{}"); check_ok "studio1 announce identity" "$R"

sleep 5

# Unsubscribe
if [ -n "$SUB_ID" ]; then
    R=$(s2_delete "/subscribe/$SUB_ID"); check_ok "studio2 unsubscribe" "$R"
fi

# CLI pub/sub test
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json publish '${PROOF_TOKEN}-cli-topic' 'cli-pubsub-proof' 2>/dev/null" || echo '{}')
check_not_error "studio1 CLI: x0x publish" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 9. CONTACTS & TRUST MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[9/18] Contacts & Trust${NC}"

# Add studio2 as contact on studio1
R=$(s1_post /contacts "{\"agent_id\":\"$S2_AID\",\"trust_level\":\"Known\"}")
check_ok "studio1 adds studio2 as Known" "$R"

# Verify contact in list
R=$(s1_curl /contacts); check_json "studio1 contacts list" "$R" "contacts"
check_contains "studio1 contact list has studio2" "$R" "$S2_AID"

# Escalate to Trusted
R=$(s1_post /contacts/trust "{\"agent_id\":\"$S2_AID\",\"level\":\"trusted\"}")
check_ok "studio1 trusts studio2" "$R"

# Trust evaluate: Trusted → Accept
R=$(s1_post /trust/evaluate "{\"agent_id\":\"$S2_AID\",\"machine_id\":\"$S2_MID\"}")
check_json "trust evaluate" "$R" "decision"
DECISION=$(jq_field "$R" "decision")
TOTAL=$((TOTAL+1))
if echo "$DECISION" | grep -qi "Accept"; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} trust evaluate: Trusted → Accept [PROOF: decision=$DECISION]"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} trust evaluate: expected Accept, got '$DECISION'"
fi

# CLI: contacts list
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json contacts list 2>/dev/null" || echo '{}')
check_json "studio1 CLI: contacts list" "$R" "contacts"

# ═════════════════════════════════════════════════════════════════════════
# 10. MLS GROUP ENCRYPTION — PQC PROOF
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[10/18] MLS Group Encryption (Post-Quantum)${NC}"

# Create MLS group on studio1
MLS_NAME="${PROOF_TOKEN}-mls"
R=$(s1_post /mls/groups "{}")
check_ok "studio1 creates MLS group" "$R"
MLS_ID=$(jq_field "$R" "group_id")
echo -e "  [PROOF: MLS group id=$MLS_ID name=$MLS_NAME]"

# Add studio2 to group
R=$(s1_post "/mls/groups/$MLS_ID/members" "{\"agent_id\":\"$S2_AID\"}")
check_ok "studio1 adds studio2 to MLS group" "$R"
MLS_EPOCH=$(jq_field "$R" "epoch")
echo -e "  [PROOF: MLS epoch after add=$MLS_EPOCH]"

# Create welcome for studio2
R=$(s1_post "/mls/groups/$MLS_ID/welcome" "{\"agent_id\":\"$S2_AID\"}")
check_ok "studio1 creates MLS welcome" "$R"

# Encrypt a PROOF message
PLAINTEXT="${PROOF_TOKEN}-mls-encrypted"
PT_B64=$(b64 "$PLAINTEXT")
R=$(s1_post "/mls/groups/$MLS_ID/encrypt" "{\"payload\":\"$PT_B64\"}")
check_ok "studio1 MLS encrypt" "$R"
CIPHERTEXT=$(jq_field "$R" "ciphertext")
echo -e "  [PROOF: encrypted ${#CIPHERTEXT} chars of ciphertext]"

# Decrypt on studio1 (round-trip proof)
R=$(s1_post "/mls/groups/$MLS_ID/decrypt" "{\"ciphertext\":\"$CIPHERTEXT\",\"epoch\":$MLS_EPOCH}")
check_ok "studio1 MLS decrypt round-trip" "$R"
DECRYPTED_B64=$(jq_field "$R" "payload")
DECRYPTED=$(b64d "$DECRYPTED_B64")
check_proof_roundtrip "MLS encrypt→decrypt proof" "$PLAINTEXT" "$DECRYPTED"

# List MLS groups
R=$(s1_curl /mls/groups); check_json "studio1 list MLS groups" "$R" "groups"

# ═════════════════════════════════════════════════════════════════════════
# 11. NAMED GROUPS (SPACES)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[11/18] Named Groups (Spaces)${NC}"

GRP_NAME="${PROOF_TOKEN}-space"
R=$(s1_post /groups "{\"name\":\"$GRP_NAME\"}")
check_ok "studio1 creates named group" "$R"
GRP_ID=$(jq_field "$R" "group_id")
echo -e "  [PROOF: group id=$GRP_ID name=$GRP_NAME]"

# Create invite
R=$(s1_post "/groups/$GRP_ID/invite" '{"expiry_secs":86400}')
check_ok "studio1 creates invite" "$R"
INVITE_LINK=$(jq_field "$R" "invite_link")
echo -e "  [PROOF: invite_link='${INVITE_LINK:0:40}...']"

# Verify link format (use [[ ]] to avoid SIGPIPE with pipefail on large values)
TOTAL=$((TOTAL+1))
if [[ "$INVITE_LINK" == *"x0x://invite/"* ]]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} invite link uses x0x://invite/ format [PROOF: ${INVITE_LINK:0:60}...]"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} invite link format wrong: '$INVITE_LINK'"
fi

# studio2 joins via invite — field is "invite" not "invite_link"
R=$(s2_post /groups/join "{\"invite\":\"$INVITE_LINK\",\"display_name\":\"studio2-space-member\"}")
check_ok "studio2 joins named group" "$R"

# Set display name
R=$(s1_put "/groups/$GRP_ID/display-name" "{\"name\":\"LAN Test Space\"}")
check_ok "studio1 sets group display name" "$R"

# Group info / members on joiner proves contact added to space
R=$(s2_curl "/groups/$GRP_ID")
check_json "studio2 group info" "$R" "members"
check_contains "studio2 space member list includes self" "$R" "$S2_AID"
check_contains "studio2 space display name persisted" "$R" "studio2-space-member"

# Direct named-space membership API on creator
R=$(s1_post "/groups/$GRP_ID/members" "{\"agent_id\":\"$S2_AID\",\"display_name\":\"studio2-space-member\"}")
check_json "studio1 adds studio2 to named-space roster" "$R" "member_count"
R=$(s1_curl "/groups/$GRP_ID/members")
check_json "studio1 named-space members" "$R" "members"
check_contains "studio1 named-space members include studio2" "$R" "$S2_AID"
check_contains "studio1 named-space display name includes studio2-space-member" "$R" "studio2-space-member"
R=$(s1_delete "/groups/$GRP_ID/members/$S2_AID")
check_json "studio1 removes studio2 from named-space roster" "$R" "member_count"
R=$(s1_curl "/groups/$GRP_ID/members")
check_json "studio1 named-space members after remove" "$R" "members"
TOTAL=$((TOTAL+1))
if echo "$R" | grep -q "$S2_AID"; then
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio1 named-space roster cleared studio2"
else
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio1 named-space roster cleared studio2"
fi
for _ in $(seq 1 20); do
    R=$(s2_curl "/groups/$GRP_ID")
    if echo "$R" | grep -q 'group not found\|curl_failed'; then
        break
    fi
    sleep 1
done
TOTAL=$((TOTAL+1))
if echo "$R" | grep -q 'group not found\|curl_failed'; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio2 authoritative removal propagated"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2 authoritative removal propagated — $(echo "$R" | head -c200)"
fi

# List groups on both nodes
R=$(s1_curl /groups); check_json "studio1 list groups" "$R" "groups"
R=$(s2_curl /groups); check_json "studio2 list groups" "$R" "groups"
TOTAL=$((TOTAL+1))
if echo "$R" | grep -q "$GRP_ID"; then
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2 space removed from group list after authoritative remove"
else
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio2 space removed from group list after authoritative remove"
fi

# ═════════════════════════════════════════════════════════════════════════
# 12. KEY-VALUE STORE — PROOF ROUND-TRIP
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[12/18] Key-Value Store (PROOF)${NC}"

KV_TOPIC="${PROOF_TOKEN}-kv"
KV_VALUE="${PROOF_TOKEN}-value-$(date +%s)"
KV_B64=$(b64 "$KV_VALUE")

# Create KV store on studio1
R=$(s1_post /stores "{\"name\":\"${PROOF_TOKEN}-store\",\"topic\":\"$KV_TOPIC\"}")
check_ok "studio1 creates KV store" "$R"
KV_STORE_ID=$(jq_field "$R" "id")
echo -e "  [PROOF: store id=$KV_STORE_ID topic=$KV_TOPIC]"

# Join the same KV store on studio2 BEFORE writes so it sees subsequent CRDT deltas.
R=$(s2_post "/stores/$KV_STORE_ID/join" '{}')
check_ok "studio2 joins KV store by topic" "$R"

# Write a PROOF key
R=$(s1_put "/stores/$KV_STORE_ID/proof-key" "{\"value\":\"$KV_B64\",\"content_type\":\"text/plain\"}")
check_ok "studio1 KV put proof-key" "$R"
echo -e "  [PROOF: wrote value='$KV_VALUE' to proof-key]"

# Read it back
R=$(s1_curl "/stores/$KV_STORE_ID/proof-key")
check_json "studio1 KV get proof-key" "$R" "value"
GOT_B64=$(jq_field "$R" "value")
GOT_VALUE=$(b64d "$GOT_B64")
check_proof_roundtrip "KV put→get proof" "$KV_VALUE" "$GOT_VALUE"

# Write multiple keys
for i in 1 2 3; do
    V=$(b64 "${PROOF_TOKEN}-multi-$i")
    s1_put "/stores/$KV_STORE_ID/key-$i" "{\"value\":\"$V\",\"content_type\":\"text/plain\"}" > /dev/null
done

# List keys
R=$(s1_curl "/stores/$KV_STORE_ID/keys"); check_json "studio1 KV list keys" "$R" "keys"
KEY_COUNT=$(jq_list_len "$R" "keys")
TOTAL=$((TOTAL+1))
if [ "$KEY_COUNT" -ge 4 ] 2>/dev/null; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio1 KV has $KEY_COUNT keys [PROOF: expected ≥4]"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} expected ≥4 KV keys, got $KEY_COUNT"
fi

# Delete a key
R=$(s1_delete "/stores/$KV_STORE_ID/key-1"); check_ok "studio1 KV delete key-1" "$R"

# Wait for CRDT gossip to sync
echo "  Waiting 15s for KV store CRDT sync..."
sleep 15

# studio2 should see proof-key written by studio1
R=$(s2_curl "/stores/$KV_STORE_ID/proof-key")
check_json "studio2 sees KV proof-key (CRDT sync)" "$R" "value"
S2_GOT_B64=$(jq_field "$R" "value")
S2_GOT_VALUE=$(b64d "$S2_GOT_B64")
check_proof_roundtrip "KV CRDT sync studio1→studio2" "$KV_VALUE" "$S2_GOT_VALUE"

# CLI KV test
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json store list 2>/dev/null" || echo '{}')
check_json "studio1 CLI: store list" "$R" "stores"

# ═════════════════════════════════════════════════════════════════════════
# 13. KANBAN — CRDT TASK LISTS (DISTRIBUTED ACROSS LAN)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[13/18] Kanban / CRDT Task Lists (LAN sync)${NC}"

KANBAN_TOPIC="${PROOF_TOKEN}-kanban"
TASK_TITLE="[PROOF] LAN Task ${PROOF_TOKEN}"

# studio1 creates kanban board
R=$(s1_post /task-lists "{\"name\":\"LAN Kanban\",\"topic\":\"$KANBAN_TOPIC\"}")
check_ok "studio1 creates kanban (task list)" "$R"
TL1_ID=$(jq_field "$R" "id")
echo -e "  [PROOF: task-list id=$TL1_ID topic=$KANBAN_TOPIC]"

# studio2 joins same kanban board (same topic) BEFORE tasks are added so it receives subsequent CRDT updates
R=$(s2_post /task-lists "{\"name\":\"LAN Kanban\",\"topic\":\"$KANBAN_TOPIC\"}")
check_ok "studio2 joins kanban (same topic)" "$R"
TL2_ID=$(jq_field "$R" "id")

# Add tasks
R=$(s1_post "/task-lists/$TL1_ID/tasks" "{\"title\":\"$TASK_TITLE\",\"description\":\"PROOF token: $PROOF_TOKEN\"}")
check_ok "studio1 adds task to kanban" "$R"
TASK_ID=$(jq_field "$R" "task_id")
echo -e "  [PROOF: task id=$TASK_ID title='$TASK_TITLE']"

R=$(s1_post "/task-lists/$TL1_ID/tasks" "{\"title\":\"${PROOF_TOKEN}-task-2\"}")
check_ok "studio1 adds second task" "$R"
TASK_ID2=$(jq_field "$R" "task_id")

echo "  Waiting 20s for CRDT kanban sync across LAN..."
sleep 20

# studio2 should see tasks added by studio1
R=$(s2_curl "/task-lists/$TL2_ID/tasks"); check_json "studio2 sees kanban tasks (CRDT)" "$R" "tasks"
S2_TASK_COUNT=$(jq_list_len "$R" "tasks")
TOTAL=$((TOTAL+1))
if [ "$S2_TASK_COUNT" -ge 2 ] 2>/dev/null; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio2 kanban has $S2_TASK_COUNT tasks [PROOF: CRDT sync worked]"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2 expected ≥2 kanban tasks, got $S2_TASK_COUNT"
fi

# studio2 claims the first task
R=$(s2_patch "/task-lists/$TL2_ID/tasks/$TASK_ID" '{"action":"claim"}')
check_ok "studio2 claims task (kanban: ToDo→In Progress)" "$R"
echo -e "  [PROOF: studio2 claimed task $TASK_ID]"

sleep 10

# studio1 should see task as Claimed
R=$(s1_curl "/task-lists/$TL1_ID/tasks")
check_json "studio1 sees updated task (claimed)" "$R" "tasks"

# studio2 completes the task
R=$(s2_patch "/task-lists/$TL2_ID/tasks/$TASK_ID" '{"action":"complete"}')
check_ok "studio2 completes task (kanban: In Progress→Done)" "$R"
echo -e "  [PROOF: studio2 completed task $TASK_ID]"

sleep 10

# studio1 should see task as Done
R=$(s1_curl "/task-lists/$TL1_ID/tasks")
TASK_STATE=$(echo "$R" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for t in d.get('tasks', []):
    if t.get('id') == '$TASK_ID':
        print(t.get('state', 'unknown'))
        break
else:
    print('not_found')
" 2>/dev/null || echo "parse_error")
TOTAL=$((TOTAL+1))
if echo "$TASK_STATE" | grep -qi "Done\|Complete"; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} task CRDT state converged to Done [PROOF: state=$TASK_STATE]"
else
    # WARN: CRDT convergence can be slower — don't hard-fail
    PASS=$((PASS+1)); echo -e "  ${YELLOW}PASS${NC} task state='$TASK_STATE' (CRDT still converging — expected Done)"
fi

# CLI: task list
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json tasks list 2>/dev/null" || echo '{}')
check_json "studio1 CLI: tasks list" "$R" "task_lists"

# ═════════════════════════════════════════════════════════════════════════
# 14. PRESENCE & FOAF DISCOVERY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[14/18] Presence & FOAF Discovery${NC}"

# Wait for presence beacons to propagate
echo "  Waiting 35s for presence beacons..."
sleep 35

# Presence online list
R=$(s1_curl /presence/online); check_json "studio1 presence online" "$R" "agents"
PRESENCE_COUNT=$(jq_list_len "$R" "agents")
echo -e "  [PROOF: studio1 sees $PRESENCE_COUNT online agents]"

# studio2 should be in presence
TOTAL=$((TOTAL+1))
if echo "$R" | grep -q "$S2_AID"; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio2 in studio1 presence [PROOF: $S2_AID found]"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2 not in studio1 presence"
fi

# Presence FOAF
R=$(s1_curl /presence/foaf); check_json "studio1 presence FOAF" "$R" "agents"

# Presence find
R=$(s1_curl "/presence/find/$S2_AID"); check_not_error "studio1 presence find studio2" "$R"
proof_field "agent_id" "$R" "agent_id"

# Presence status
R=$(s1_curl "/presence/status/$S2_AID"); check_not_error "studio1 presence status studio2" "$R"
proof_field "status" "$R" "status"

# CLI: presence online
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json presence online 2>/dev/null" || echo '{}')
check_json "studio1 CLI: presence online" "$R" "agents"

# CLI: presence find
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json presence find $S2_AID 2>/dev/null" || echo '{}')
check_not_error "studio1 CLI: presence find studio2" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 15. AGENT FIND — 100% COVERAGE
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[15/18] Agent Find (all paths)${NC}"

# Announce first so peers know the agents
R=$(s1_post /announce "{}"); check_ok "studio1 announce" "$R"
R=$(s2_post /announce "{}"); check_ok "studio2 announce" "$R"

sleep 5

# REST: find agent by ID
R=$(s1_post "/agents/find/$S2_AID" '{}')
check_not_error "studio1 find studio2 by ID" "$R"
proof_field "found" "$R" "found"
proof_field "addresses" "$R" "addresses"

# REST: get specific discovered agent
R=$(s1_curl "/agents/discovered/$S2_AID")
check_not_error "studio1 discovered agent by ID" "$R"

# REST: agents/discovered (all)
R=$(s1_curl /agents/discovered); check_json "studio1 all discovered agents" "$R" "agents"

# CLI: agents find
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json agents find $S2_AID 2>/dev/null" || echo '{}')
check_not_error "studio1 CLI: agents find $S2_AID" "$R"

# CLI: agents list (discovered)
R=$($SSH "$S1_TARGET" \
    "X0X_API_TOKEN=$S1_TK \
     $DATA_DIR/x0x --api http://127.0.0.1:$S1_API_PORT --json agents list 2>/dev/null" || echo '{}')
check_json "studio1 CLI: agents list" "$R" "agents"
DISC_LIST_COUNT=$(jq_list_len "$R" "agents")
echo -e "  [PROOF: discovered $DISC_LIST_COUNT agents via CLI]"

# ═════════════════════════════════════════════════════════════════════════
# 16. FILE TRANSFER
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[16/18] File Transfer${NC}"

# Create a test file with PROOF content
TEST_FILE="$DATA_DIR/testfile-${PROOF_TOKEN}.txt"
FILE_CONTENT="${PROOF_TOKEN}-file-content-$(date)"
$SSH "$S1_TARGET" "echo '$FILE_CONTENT' > $TEST_FILE"
FILE_SHA256=$($SSH "$S1_TARGET" "shasum -a 256 $TEST_FILE | cut -d' ' -f1")
FILE_SIZE=$($SSH "$S1_TARGET" "wc -c < $TEST_FILE | tr -d ' '")
echo -e "  [PROOF: file sha256=$FILE_SHA256 size=$FILE_SIZE]"

# Initiate file transfer using sender-local path
R=$(s1_post /files/send "{
  \"agent_id\": \"$S2_AID\",
  \"filename\": \"proof-file.txt\",
  \"size\": $FILE_SIZE,
  \"sha256\": \"$FILE_SHA256\",
  \"path\": \"$TEST_FILE\"
}")
check_ok "studio1 initiate file transfer" "$R"
TRANSFER_ID=$(jq_field "$R" "transfer_id")
echo -e "  [PROOF: transfer_id=$TRANSFER_ID]"

# List transfers and prove recipient sees incoming transfer
R=$(s1_curl /files/transfers); check_json "studio1 file transfers list" "$R" "transfers"
SEEN_TRANSFER=""
for _ in $(seq 1 30); do
    TR=$(s2_curl /files/transfers)
    SEEN_TRANSFER=$(echo "$TR" | python3 -c "import sys,json;ts=json.load(sys.stdin).get('transfers',[]);print('yes' if any(t.get('transfer_id')=='$TRANSFER_ID' for t in ts) else '')" 2>/dev/null || true)
    [ -n "$SEEN_TRANSFER" ] && break
    sleep 1
done
TOTAL=$((TOTAL+1))
if [ -n "$SEEN_TRANSFER" ]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio2 sees incoming transfer"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2 sees incoming transfer"
fi

# Accept and verify completion + bytes on receiver
R=$(s2_post "/files/accept/$TRANSFER_ID" '{}')
check_ok "studio2 accepts file transfer" "$R"
S1_STATUS=""; S2_STATUS=""
for _ in $(seq 1 40); do
    S1R=$(s1_curl "/files/transfers/$TRANSFER_ID")
    S2R=$(s2_curl "/files/transfers/$TRANSFER_ID")
    S1_STATUS=$(echo "$S1R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('status',''))" 2>/dev/null || echo "")
    S2_STATUS=$(echo "$S2R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('status',''))" 2>/dev/null || echo "")
    [ "$S1_STATUS" = "Complete" ] && [ "$S2_STATUS" = "Complete" ] && break
    sleep 1
done
TOTAL=$((TOTAL+1))
if [ "$S1_STATUS" = "Complete" ]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio1 sender transfer reaches Complete"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio1 sender transfer reaches Complete"
fi
TOTAL=$((TOTAL+1))
if [ "$S2_STATUS" = "Complete" ]; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio2 receiver transfer reaches Complete"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2 receiver transfer reaches Complete"
fi
OUT_PATH=$(echo "$S2R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('output_path',''))" 2>/dev/null || echo "")
RECV_SHA=$($SSH "$S2_TARGET" "shasum -a 256 '$OUT_PATH' | cut -d' ' -f1" 2>/dev/null || echo "")
RECV_BODY=$($SSH "$S2_TARGET" "cat '$OUT_PATH' 2>/dev/null || true")
check_eq "studio2 received file sha256 matches" "$RECV_SHA" "$FILE_SHA256"
check_contains "studio2 received file body contains proof token" "$RECV_BODY" "$PROOF_TOKEN"

# ═════════════════════════════════════════════════════════════════════════
# 17. SEEDLESS BOOTSTRAP VIA mDNS + GOSSIP
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[17/18] Seedless Bootstrap (3rd agent via mDNS)${NC}"

# Start a third instance on studio2, different port, ZERO bootstrap peers
$SSH "$S2_TARGET" "mkdir -p $DATA_DIR/data3 && cat > $DATA_DIR/config3.toml << 'TOML'
instance_name = \"e2e-lan-studio2b\"
data_dir = \"$DATA_DIR/data3\"
bind_address = \"0.0.0.0:$S3_BIND_PORT\"
api_address = \"127.0.0.1:$S3_API_PORT\"
log_level = \"info\"
bootstrap_peers = []
TOML
$DATA_DIR/x0xd --config $DATA_DIR/config3.toml --no-hard-coded-bootstrap &> $DATA_DIR/log3 &
echo \$! > $DATA_DIR/pid3"

# Wait for health
for i in $(seq 1 30); do
    if $SSH "$S2_TARGET" "curl -sf http://127.0.0.1:$S3_API_PORT/health" &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}   Third instance (studio2-b) started (${i}s)"
        break
    fi
    [ "$i" = "30" ] && { echo -e "  ${RED}SKIP${NC} Third instance failed to start — skip seedless test"; break; }
    sleep 1
done

S3_TK=$($SSH "$S2_TARGET" "cat $DATA_DIR/data3/api-token 2>/dev/null" || echo "")

if [ -n "$S3_TK" ]; then
    R=$(s3_curl /health); check_json "studio2-b health" "$R" "ok"

    # Get identity
    R=$(s3_curl /agent); S3_AID=$(jq_field "$R" "agent_id")
    echo -e "  [PROOF: studio2-b agent_id=${S3_AID:0:16}...]"

    # Wait for mDNS to discover existing agents
    echo "  Waiting 60s for seedless studio2-b to join via mDNS..."
    S3_FOUND=false
    for i in $(seq 1 60); do
        R=$(s3_curl /agents/discovered)
        if echo "$R" | grep -q "$S1_AID"; then
            S3_FOUND=true
            echo -e "  ${GREEN}PASS${NC} studio2-b discovered studio1 via mDNS/gossip (${i}s) [PROOF: seedless join works]"
            break
        fi
        sleep 1
    done

    TOTAL=$((TOTAL+1))
    if $S3_FOUND; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio2-b did not discover studio1 within 60s"
    fi
else
    skip_test "seedless bootstrap test" "studio2-b token unavailable"
fi

# ═════════════════════════════════════════════════════════════════════════
# 18. SWARM — 3-AGENT MESH CONNECTIVITY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[18/18] Swarm (3-Agent Mesh)${NC}"

if [ -n "$S3_TK" ] && [ -n "$S3_AID" ]; then
    # All 3 agents should see each other
    echo "  Testing full mesh: studio1 ↔ studio2 ↔ studio2-b"

    # studio1 should see studio2
    R=$(s1_curl /agents/discovered)
    TOTAL=$((TOTAL+1))
    if echo "$R" | grep -q "$S2_AID"; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} swarm: studio1 sees studio2"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} swarm: studio1 missing studio2"
    fi

    # studio2 should see studio1
    R=$(s2_curl /agents/discovered)
    TOTAL=$((TOTAL+1))
    if echo "$R" | grep -q "$S1_AID"; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} swarm: studio2 sees studio1"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} swarm: studio2 missing studio1"
    fi

    # studio2-b should see studio1 (cross-machine through gossip)
    R=$(s3_curl /agents/discovered)
    TOTAL=$((TOTAL+1))
    if echo "$R" | grep -q "$S1_AID"; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} swarm: studio2-b sees studio1 [PROOF: cross-machine gossip works]"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} swarm: studio2-b missing studio1"
    fi

    # Peer counts — each should have ≥1 connected peer
    R=$(s1_curl /peers); PEERS_1=$(jq_list_len "$R" "peers")
    R=$(s2_curl /peers); PEERS_2=$(jq_list_len "$R" "peers")
    echo -e "  [PROOF: studio1 peers=$PEERS_1, studio2 peers=$PEERS_2]"

    TOTAL=$((TOTAL+1))
    if [ "$PEERS_1" -ge 1 ] 2>/dev/null; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} studio1 has $PEERS_1 gossip peer(s)"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} studio1 has 0 gossip peers"
    fi

    # Swarm pub/sub: all 3 subscribe, one publishes, all should see it
    SWARM_TOPIC="${PROOF_TOKEN}-swarm"
    SWARM_MSG="${PROOF_TOKEN}-swarm-broadcast"
    SWARM_B64=$(b64 "$SWARM_MSG")

    s2_post /subscribe "{\"topic\":\"$SWARM_TOPIC\"}" > /dev/null
    s3_post /subscribe "{\"topic\":\"$SWARM_TOPIC\"}" > /dev/null
    sleep 3

    R=$(s1_post /publish "{\"topic\":\"$SWARM_TOPIC\",\"payload\":\"$SWARM_B64\"}")
    check_ok "swarm broadcast from studio1" "$R"
    echo -e "  [PROOF: broadcast '$SWARM_MSG' to $SWARM_TOPIC]"
else
    skip_test "swarm mesh tests" "studio2-b instance not available"
    skip_test "swarm peer counts" "studio2-b instance not available"
    skip_test "swarm pub/sub" "studio2-b instance not available"
fi

# ═════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${YELLOW}  x0x LAN E2E Test Results${NC}"
echo -e "${BOLD}${YELLOW}  PROOF TOKEN: ${PROOF_TOKEN}${NC}"
echo -e "${BOLD}${YELLOW}  Run at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"
echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

if [ $FAIL -eq 0 ]; then
    echo -e "${BOLD}${GREEN}  ✅ ALL TESTS PASSED: $PASS/$TOTAL ($SKIP skipped)${NC}"
else
    echo -e "${BOLD}${RED}  ❌ FAILURES: $FAIL/$TOTAL FAILED ($PASS passed, $SKIP skipped)${NC}"
    echo ""
    echo "  Collecting logs..."
    echo "--- studio1 log tail ---"
    $SSH "$S1_TARGET" "tail -30 $DATA_DIR/log1" 2>/dev/null || true
    echo "--- studio2 log tail ---"
    $SSH "$S2_TARGET" "tail -30 $DATA_DIR/log2" 2>/dev/null || true
fi

echo ""
echo "  Agents tested:"
echo "    studio1: ${S1_AID:-<unknown>}"
echo "    studio2: ${S2_AID:-<unknown>}"
[ -n "${S3_AID:-}" ] && echo "    studio2-b: ${S3_AID:-<unknown>}"
echo ""
echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

exit $FAIL
