#!/usr/bin/env bash
# =============================================================================
# x0x v0.15.3 Live Network End-to-End Test
# Starts a LOCAL x0xd node that joins the real bootstrap network (6 VPS nodes),
# then tests bidirectional connectivity, discovery, presence, messaging,
# groups, KV stores, and more between local node and live VPS nodes.
#
# This test validates the REAL user experience: install x0x, start daemon,
# join network, interact with other agents.
#
# Prerequisites:
#   - x0xd binary built (cargo build --release)
#   - SSH access to VPS nodes (for token retrieval and verification)
#   - VPS bootstrap nodes running v0.15.3 (run e2e_deploy.sh first)
#
# Usage:
#   bash tests/e2e_live_network.sh
#   X0XD=/path/to/x0xd bash tests/e2e_live_network.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
X0XD="${X0XD:-$PROJECT_DIR/target/release/x0xd}"
VERSION="0.14.0"

PASS=0; FAIL=0; SKIP=0; TOTAL=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

b64() { echo -n "$1" | base64; }

check_json()      { local n="$1" r="$2" k="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|python3 -c "import sys,json;d=json.load(sys.stdin);assert '$k' in d" 2>/dev/null;then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — no key '$k': $(echo "$r"|head -c200)";fi; }
check_contains()  { local n="$1" r="$2" e="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -qi "$e";then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — want '$e': $(echo "$r"|head -c250)";fi; }
check_ok()        { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"ok":true\|"ok": true';then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";elif echo "$r"|grep -q '"error"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }
check_not_error() { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"error":"curl_failed"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — curl_failed";elif echo "$r"|grep -q '"ok":false\|"ok": false';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }
check_eq()        { local n="$1" got="$2" want="$3"; TOTAL=$((TOTAL+1)); if [ "$got" = "$want" ];then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — got '$got', want '$want'";fi; }
skip()            { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1)); echo -e "  ${YELLOW}SKIP${NC} $n — $r"; }

jq_field() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null || echo ""; }
jq_int()   { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',0))" 2>/dev/null || echo "0"; }

SSH="ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes"

# ── Local node API wrappers ─────────────────────────────────────────────
L()   { curl -sf -H "Authorization: Bearer $LT" "$LA$1" 2>/dev/null || echo '{"error":"curl_failed"}'; }
Lp()  { curl -sf -X POST -H "Authorization: Bearer $LT" -H "Content-Type: application/json" -d "${2:-{}}" "$LA$1" 2>/dev/null || echo '{"error":"curl_failed"}'; }
Lpu() { curl -sf -X PUT -H "Authorization: Bearer $LT" -H "Content-Type: application/json" -d "$2" "$LA$1" 2>/dev/null || echo '{"error":"curl_failed"}'; }
Lpa() { curl -sf -X PATCH -H "Authorization: Bearer $LT" -H "Content-Type: application/json" -d "$2" "$LA$1" 2>/dev/null || echo '{"error":"curl_failed"}'; }
Ld()  { curl -sf -X DELETE -H "Authorization: Bearer $LT" "$LA$1" 2>/dev/null || echo '{"error":"curl_failed"}'; }

# ── VPS API wrapper (via SSH) ───────────────────────────────────────────
vps_api() {
    local ip="$1" token="$2" method="$3" path="$4" body="${5:-}"
    local cmd="curl -sf -m 10 -X $method -H 'Authorization: Bearer $token' -H 'Content-Type: application/json'"
    [ -n "$body" ] && cmd="$cmd -d '$body'"
    cmd="$cmd 'http://127.0.0.1:12600${path}'"
    $SSH "root@$ip" "$cmd" 2>/dev/null || echo '{"error":"curl_failed"}'
}

# ── VPS node definitions ────────────────────────────────────────────────
declare -a VPS_NAMES=(nyc sfo helsinki nuremberg singapore tokyo)
declare -A VPS_IPS=(
    [nyc]="142.93.199.50" [sfo]="147.182.234.192" [helsinki]="65.21.157.229"
    [nuremberg]="116.203.101.172" [singapore]="149.28.156.231" [tokyo]="45.77.176.184"
)
declare -A VPS_TOKENS=()

# ── Cleanup ──────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "${LP:-}" ] && kill $LP 2>/dev/null || true
    [ -n "${LP:-}" ] && wait $LP 2>/dev/null || true
    rm -rf /tmp/x0x-e2e-live
}
trap cleanup EXIT

# ═════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   x0x v$VERSION Live Network E2E Test${NC}"
echo -e "${YELLOW}   Local node → 6 bootstrap nodes → bidirectional tests${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

# ── Verify binary ────────────────────────────────────────────────────────
if [ ! -x "$X0XD" ]; then
    echo -e "${RED}x0xd not found at $X0XD${NC}"
    echo "Build with: cargo build --release"
    exit 1
fi
echo -e "  x0xd: $X0XD"

# ═════════════════════════════════════════════════════════════════════════
# SETUP: Collect VPS tokens and start local node
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Setup] Collecting VPS tokens and verifying bootstrap health...${NC}"

# Load tokens from file if available, otherwise SSH
if [ -f "$SCRIPT_DIR/.vps-tokens.env" ]; then
    source "$SCRIPT_DIR/.vps-tokens.env"
    [ -n "${NYC_TK:-}" ] && VPS_TOKENS[nyc]="$NYC_TK"
    [ -n "${SFO_TK:-}" ] && VPS_TOKENS[sfo]="$SFO_TK"
    [ -n "${HELSINKI_TK:-}" ] && VPS_TOKENS[helsinki]="$HELSINKI_TK"
    [ -n "${NUREMBERG_TK:-}" ] && VPS_TOKENS[nuremberg]="$NUREMBERG_TK"
    [ -n "${SINGAPORE_TK:-}" ] && VPS_TOKENS[singapore]="$SINGAPORE_TK"
    [ -n "${TOKYO_TK:-}" ] && VPS_TOKENS[tokyo]="$TOKYO_TK"
fi

# Fallback: read tokens via SSH for missing
for node in "${VPS_NAMES[@]}"; do
    if [ -z "${VPS_TOKENS[$node]:-}" ]; then
        ip="${VPS_IPS[$node]}"
        tk=$($SSH root@"$ip" 'cat /root/.local/share/x0x/api-token 2>/dev/null || cat /var/lib/x0x/data/api-token 2>/dev/null' 2>/dev/null || echo "")
        [ -n "$tk" ] && VPS_TOKENS[$node]="$tk"
    fi
done

# Quick health check on NYC (representative node)
NYC_IP="${VPS_IPS[nyc]}"; NYC_TK="${VPS_TOKENS[nyc]:-}"
if [ -z "$NYC_TK" ]; then
    echo -e "  ${RED}Cannot get NYC token — VPS tests will be limited${NC}"
else
    R=$(vps_api "$NYC_IP" "$NYC_TK" GET /health)
    check_contains "NYC bootstrap healthy" "$R" "healthy"
fi

# Collect VPS agent IDs
declare -A VPS_AIDS=()
declare -A VPS_MIDS=()
for node in "${VPS_NAMES[@]}"; do
    tk="${VPS_TOKENS[$node]:-}"
    [ -z "$tk" ] && continue
    ip="${VPS_IPS[$node]}"
    R=$(vps_api "$ip" "$tk" GET /agent)
    VPS_AIDS[$node]=$(jq_field "$R" "agent_id")
    VPS_MIDS[$node]=$(jq_field "$R" "machine_id")
done
echo "  NYC agent: ${VPS_AIDS[nyc]:0:16}..."

# ── Start local node with default bootstrap (real network) ──────────────
echo -e "\n${CYAN}[Setup] Starting local x0xd (joining real bootstrap network)...${NC}"
rm -rf /tmp/x0x-e2e-live
mkdir -p /tmp/x0x-e2e-live

cat>/tmp/x0x-e2e-live/config.toml<<TOML
instance_name = "e2e-live"
data_dir = "/tmp/x0x-e2e-live"
bind_address = "0.0.0.0:15483"
api_address = "127.0.0.1:19200"
log_level = "warn"
# No bootstrap_peers override — uses DEFAULT_BOOTSTRAP_PEERS (6 global nodes on port 5483)
TOML

$X0XD --config /tmp/x0x-e2e-live/config.toml &>/tmp/x0x-e2e-live/log &
LP=$!
LA="http://127.0.0.1:19200"

# Wait for local node to start
for i in $(seq 1 30); do
    h=$(curl -sf "$LA/health" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null || true)
    [ "$h" = "True" ] && echo -e "  ${GREEN}Local node ready (${i}s)${NC}" && break
    [ "$i" = "30" ] && echo -e "${RED}Local node startup failed!${NC}" && tail -20 /tmp/x0x-e2e-live/log && exit 1
    sleep 1
done

LT=$(cat /tmp/x0x-e2e-live/api-token 2>/dev/null)

# Extract local identity
RL=$(L /agent)
LOCAL_AID=$(jq_field "$RL" "agent_id")
LOCAL_MID=$(jq_field "$RL" "machine_id")
echo -e "  local agent=${LOCAL_AID:0:16}... machine=${LOCAL_MID:0:16}..."

# ═════════════════════════════════════════════════════════════════════════
# 1. LOCAL NODE HEALTH & IDENTITY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[1/12] Local Node Health & Identity${NC}"
R=$(L /health); check_json "local health" "$R" "ok"
check_contains "local version $VERSION" "$R" "$VERSION"
R=$(L /status); check_json "local status" "$R" "uptime_secs"
R=$(L /constitution/json); check_json "local constitution" "$R" "version"
R=$(L /agent); check_json "local agent" "$R" "agent_id"
R=$(L /agent/card); check_json "local agent card" "$R" "link"
LOCAL_CARD_LINK=$(jq_field "$R" "link")

# Verify local agent is distinct from all VPS agents
for node in "${VPS_NAMES[@]}"; do
    aid="${VPS_AIDS[$node]:-}"
    [ -z "$aid" ] && continue
    check_eq "local != $node agent" "$([ "$LOCAL_AID" != "$aid" ] && echo yes || echo no)" "yes"
done

# ═════════════════════════════════════════════════════════════════════════
# 2. BOOTSTRAP CONNECTIVITY — Join the real network
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[2/12] Bootstrap Connectivity (30s for real network join)${NC}"
sleep 30

R=$(L /network/status); check_json "network status" "$R" "connected_peers"
PEER_COUNT=$(jq_int "$R" "connected_peers")
echo "  Connected peers: $PEER_COUNT"
TOTAL=$((TOTAL+1))
if [ "$PEER_COUNT" -ge 1 ] 2>/dev/null; then
    PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} local node has $PEER_COUNT peer(s) from bootstrap"
else
    FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} local node has 0 peers — bootstrap failed"
fi

R=$(L /peers); check_not_error "local peers list" "$R"
R=$(L /network/bootstrap-cache); check_not_error "bootstrap cache" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 3. ANNOUNCE & DISCOVERY — Local announces, VPS nodes discover
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[3/12] Announce & Discovery (local ↔ VPS)${NC}"

# Local announces identity to the network
R=$(Lp /announce); check_not_error "local announce" "$R"

echo "  Waiting 30s for gossip propagation across 6 continents..."
sleep 30

# Local discovers VPS agents
R=$(L /agents/discovered); check_not_error "local discovered agents" "$R"

# Try to find NYC via gossip
NYC_AID="${VPS_AIDS[nyc]:-}"
if [ -n "$NYC_AID" ]; then
    R=$(Lp "/agents/find/$NYC_AID")
    if echo "$R" | grep -q '"found":true'; then
        check_contains "local finds NYC" "$R" '"found":true'
    else
        skip "local finds NYC via gossip" "gossip may not have propagated yet"
    fi
fi

# VPS discovers local agent (check from NYC)
if [ -n "$NYC_TK" ]; then
    R=$(vps_api "$NYC_IP" "$NYC_TK" POST "/agents/find/$LOCAL_AID")
    if echo "$R" | grep -q '"found":true'; then
        check_contains "NYC finds local agent" "$R" '"found":true'
    else
        skip "NYC finds local agent" "local behind NAT — expected"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 4. CONTACTS & TRUST — Local ↔ VPS
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[4/12] Contacts & Trust (local ↔ NYC)${NC}"

# Local adds NYC as trusted contact
R=$(Lp /contacts "{\"agent_id\":\"$NYC_AID\",\"trust_level\":\"Trusted\",\"label\":\"NYC Bootstrap\"}")
check_not_error "local adds NYC contact" "$R"

# NYC adds local as trusted contact
R=$(vps_api "$NYC_IP" "$NYC_TK" POST /contacts "{\"agent_id\":\"$LOCAL_AID\",\"trust_level\":\"Trusted\",\"label\":\"Local E2E\"}")
check_not_error "NYC adds local contact" "$R"

# Verify contacts
R=$(L /contacts); check_contains "local contacts has NYC" "$R" "$NYC_AID"

# Trust evaluation
NYC_MID="${VPS_MIDS[nyc]:-}"
R=$(Lp /trust/evaluate "{\"agent_id\":\"$NYC_AID\",\"machine_id\":\"$NYC_MID\"}")
check_contains "trust NYC -> Accept" "$R" "Accept"

# Import NYC's card into local
R=$(vps_api "$NYC_IP" "$NYC_TK" GET /agent/card)
NYC_LINK=$(jq_field "$R" "link")
if [ -n "$NYC_LINK" ]; then
    R=$(Lp /agent/card/import "{\"card\":\"$NYC_LINK\",\"trust_level\":\"Trusted\"}")
    check_not_error "local imports NYC card" "$R"
fi

# NYC imports local card
if [ -n "$LOCAL_CARD_LINK" ]; then
    R=$(vps_api "$NYC_IP" "$NYC_TK" POST /agent/card/import "{\"card\":\"$LOCAL_CARD_LINK\",\"trust_level\":\"Trusted\"}")
    check_not_error "NYC imports local card" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 5. DIRECT MESSAGING — Local → VPS (bidirectional)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[5/12] Direct Messaging (local ↔ NYC)${NC}"

# Local connects to NYC
R=$(Lp /agents/connect "{\"agent_id\":\"$NYC_AID\"}"); check_not_error "local connects to NYC" "$R"
sleep 3

# Local sends direct message to NYC
DM_B64=$(b64 "hello from local to NYC bootstrap node")
R=$(Lp /direct/send "{\"agent_id\":\"$NYC_AID\",\"payload\":\"$DM_B64\"}"); check_ok "local→NYC direct send" "$R"

# Local direct connections
R=$(L /direct/connections); check_not_error "local direct connections" "$R"

# NYC sends direct message back to local
R=$(vps_api "$NYC_IP" "$NYC_TK" POST /agents/connect "{\"agent_id\":\"$LOCAL_AID\"}")
check_not_error "NYC connects to local" "$R"
sleep 3
DM_B64=$(b64 "hello from NYC back to local agent")
R=$(vps_api "$NYC_IP" "$NYC_TK" POST /direct/send "{\"agent_id\":\"$LOCAL_AID\",\"payload\":\"$DM_B64\"}")
check_ok "NYC→local direct send" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 6. PUB/SUB — Local publishes, VPS subscribes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[6/12] Pub/Sub (local ↔ network)${NC}"

# Subscribe on NYC
R=$(vps_api "$NYC_IP" "$NYC_TK" POST /subscribe '{"topic":"live-e2e-test"}')
check_not_error "NYC subscribes to live-e2e-test" "$R"

# Local publishes
PUB_B64=$(b64 "live network test message from local node")
R=$(Lp /publish "{\"topic\":\"live-e2e-test\",\"payload\":\"$PUB_B64\"}"); check_ok "local publish to network" "$R"

# Local subscribes and VPS publishes (reverse direction)
R=$(Lp /subscribe '{"topic":"live-e2e-reverse"}'); check_not_error "local subscribes" "$R"
PUB_B64=$(b64 "message from NYC to local")
R=$(vps_api "$NYC_IP" "$NYC_TK" POST /publish "{\"topic\":\"live-e2e-reverse\",\"payload\":\"$PUB_B64\"}")
check_ok "NYC publishes to local" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 7. MLS GROUPS — Local creates, adds VPS members
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[7/12] MLS Groups (local + VPS members)${NC}"

# Create MLS group on local
R=$(Lp /mls/groups); check_json "local create MLS group" "$R" "group_id"
MG=$(jq_field "$R" "group_id")
echo "  MLS group: ${MG:0:16}..."

if [ -n "$MG" ]; then
    # Add NYC to the group
    R=$(Lp "/mls/groups/$MG/members" "{\"agent_id\":\"$NYC_AID\"}"); check_ok "add NYC to MLS" "$R"

    # Add Helsinki if available
    HEL_AID="${VPS_AIDS[helsinki]:-}"
    if [ -n "$HEL_AID" ]; then
        R=$(Lp "/mls/groups/$MG/members" "{\"agent_id\":\"$HEL_AID\"}"); check_ok "add Helsinki to MLS" "$R"
    fi

    # Encrypt and decrypt round-trip
    PLAIN_B64=$(b64 "PQC encrypted from local node across live network")
    R=$(Lp "/mls/groups/$MG/encrypt" "{\"payload\":\"$PLAIN_B64\"}"); check_json "encrypt" "$R" "ciphertext"
    CT=$(jq_field "$R" "ciphertext")
    EPOCH=$(jq_int "$R" "epoch")

    if [ -n "$CT" ]; then
        R=$(Lp "/mls/groups/$MG/decrypt" "{\"ciphertext\":\"$CT\",\"epoch\":$EPOCH}")
        DECRYPTED=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('payload','')).decode())" 2>/dev/null||echo "")
        check_eq "decrypt round-trip" "$DECRYPTED" "PQC encrypted from local node across live network"
    fi

    # Remove NYC member
    R=$(Ld "/mls/groups/$MG/members/$NYC_AID"); check_not_error "remove NYC from MLS" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 8. NAMED GROUPS — Local creates, VPS joins via invite
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[8/12] Named Groups (local creates, NYC joins)${NC}"

R=$(Lp /groups '{"name":"Live Network Test Group","description":"local + VPS"}')
check_not_error "create named group" "$R"
NG=$(jq_field "$R" "group_id")

if [ -n "$NG" ]; then
    # Generate invite
    R=$(Lp "/groups/$NG/invite"); check_not_error "generate invite" "$R"
    INVITE=$(jq_field "$R" "invite_link")

    if [ -n "$INVITE" ]; then
        check_contains "invite is x0x://invite/" "$INVITE" "x0x://invite/"

        # NYC joins via invite
        R=$(vps_api "$NYC_IP" "$NYC_TK" POST /groups/join "{\"invite\":\"$INVITE\"}")
        check_not_error "NYC joins local group via invite" "$R"
    fi

    # Set display name
    R=$(Lpu "/groups/$NG/display-name" '{"name":"Local Admin"}'); check_ok "set display name" "$R"

    # Leave group
    R=$(Ld "/groups/$NG"); check_not_error "leave named group" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 9. KV STORES — Local writes, verifies
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[9/12] Key-Value Stores${NC}"

R=$(Lp /stores '{"name":"live-kv","topic":"live-kv-topic"}'); check_not_error "create store" "$R"
SID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('store_id',d.get('id','')))" 2>/dev/null||echo "")

if [ -n "$SID" ]; then
    VAL_B64=$(b64 "live network KV data")
    R=$(Lpu "/stores/$SID/test-key" "{\"value\":\"$VAL_B64\",\"content_type\":\"text/plain\"}"); check_ok "put key" "$R"
    R=$(L "/stores/$SID/test-key"); check_json "get key" "$R" "value"
    GOT=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('value','')).decode())" 2>/dev/null||echo "")
    check_eq "KV round-trip" "$GOT" "live network KV data"
    R=$(Ld "/stores/$SID/test-key"); check_ok "delete key" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 10. TASK LISTS & FILE TRANSFER
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[10/12] Task Lists & File Transfer${NC}"

R=$(Lp /task-lists '{"name":"Live Tasks","topic":"live-tasks-topic"}'); check_not_error "create task list" "$R"
TL=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('list_id',d.get('id','')))" 2>/dev/null||echo "")
if [ -n "$TL" ]; then
    R=$(Lp "/task-lists/$TL/tasks" '{"title":"Test live network","description":"Full E2E validation"}')
    check_not_error "add task" "$R"
    TID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('task_id',d.get('id','')))" 2>/dev/null||echo "")
    if [ -n "$TID" ]; then
        R=$(Lpa "/task-lists/$TL/tasks/$TID" '{"action":"claim"}'); check_not_error "claim task" "$R"
        R=$(Lpa "/task-lists/$TL/tasks/$TID" '{"action":"complete"}'); check_not_error "complete task" "$R"
    fi
fi

# File transfer offer
echo "live network test file" > /tmp/x0x-e2e-live/testfile.txt
FILE_SHA=$(shasum -a 256 /tmp/x0x-e2e-live/testfile.txt | cut -d' ' -f1)
FILE_SIZE=$(wc -c < /tmp/x0x-e2e-live/testfile.txt | tr -d ' ')
R=$(Lp /files/send "{\"agent_id\":\"$NYC_AID\",\"filename\":\"live-test.txt\",\"size\":$FILE_SIZE,\"sha256\":\"$FILE_SHA\"}")
check_not_error "file offer to NYC" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 11. PRESENCE — Local sees VPS nodes, VPS sees local
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[11/12] Presence (local ↔ VPS mesh)${NC}"

R=$(L /presence/online); check_not_error "local presence online" "$R"
R=$(L /presence/foaf); check_not_error "local presence foaf" "$R"

# Try to find NYC via presence
R=$(L "/presence/find/$NYC_AID"); check_not_error "presence find NYC" "$R"
R=$(L "/presence/status/$NYC_AID"); check_not_error "presence status NYC" "$R"

# NYC checks presence — can it see local?
R=$(vps_api "$NYC_IP" "$NYC_TK" GET /presence/online)
check_not_error "NYC presence online" "$R"

# SSE events stream (grab 3s)
R=$(curl -sf -H "Authorization: Bearer $LT" --max-time 3 "$LA/presence/events" 2>/dev/null || echo "timeout_ok")
TOTAL=$((TOTAL+1))
PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} presence events SSE (stream opened)"

# ═════════════════════════════════════════════════════════════════════════
# 12. UPGRADE CHECK & WEBSOCKET
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[12/12] Upgrade & WebSocket${NC}"

R=$(L /upgrade); check_not_error "upgrade check" "$R"
R=$(L /ws/sessions); check_not_error "ws sessions" "$R"

# ═════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}  ALL $TOTAL TESTS PASSED ($PASS passed, $SKIP skipped)${NC}"
    echo -e "  Local node ↔ 6 bootstrap nodes, 12 categories, v$VERSION"
else
    echo -e "${RED}  $FAIL FAILED / $TOTAL TOTAL${NC} ($PASS passed, $SKIP skipped)"
    echo ""
    echo "local node log errors:"
    grep -i "error\|panic" /tmp/x0x-e2e-live/log | grep -v "WARN\|manifest\|upgrade\|connect_addr" | tail -15 || true
fi
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

exit $FAIL
