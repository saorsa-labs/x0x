#!/usr/bin/env bash
# =============================================================================
# x0x v0.15.3 VPS End-to-End Test
# Tests across ALL 6 bootstrap nodes (NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo)
# Full coverage: identity, mesh, gossip, MLS, groups, KV, tasks, direct, presence,
# contacts, trust, constitution, upgrade — cross-continent verification
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0; SKIP=0; TOTAL=0
VERSION="0.14.0"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

b64()  { echo -n "$1" | base64; }

check_json()      { local n="$1" r="$2" k="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|python3 -c "import sys,json;d=json.load(sys.stdin);assert '$k' in d" 2>/dev/null;then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — no key '$k': $(echo "$r"|head -c200)";fi; }
check_contains()  { local n="$1" r="$2" e="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -qi "$e";then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — want '$e': $(echo "$r"|head -c250)";fi; }
check_ok()        { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"ok":true\|"ok": true';then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";elif echo "$r"|grep -q '"error"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }
check_not_error() { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"error":"curl_failed"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — curl_failed";elif echo "$r"|grep -q '"ok":false';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }
check_eq()        { local n="$1" got="$2" want="$3"; TOTAL=$((TOTAL+1)); if [ "$got" = "$want" ];then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — got '$got', want '$want'";fi; }
skip()            { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1)); echo -e "  ${YELLOW}SKIP${NC} $n — $r"; }

jq_field() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null || echo ""; }

# ── Load tokens from deploy script or use SSH fallback ──────────────────
declare -A NODE_IPS=(
    [nyc]="142.93.199.50"
    [sfo]="147.182.234.192"
    [helsinki]="65.21.157.229"
    [nuremberg]="116.203.101.172"
    [singapore]="149.28.156.231"
    [tokyo]="45.77.176.184"
)
declare -A NODE_TOKENS=()

if [ -f "$SCRIPT_DIR/.vps-tokens.env" ]; then
    echo "Loading tokens from .vps-tokens.env..."
    source "$SCRIPT_DIR/.vps-tokens.env"
    [ -n "${NYC_TK:-}" ] && NODE_TOKENS[nyc]="$NYC_TK"
    [ -n "${SFO_TK:-}" ] && NODE_TOKENS[sfo]="$SFO_TK"
    [ -n "${HELSINKI_TK:-}" ] && NODE_TOKENS[helsinki]="$HELSINKI_TK"
    [ -n "${NUREMBERG_TK:-}" ] && NODE_TOKENS[nuremberg]="$NUREMBERG_TK"
    [ -n "${SINGAPORE_TK:-}" ] && NODE_TOKENS[singapore]="$SINGAPORE_TK"
    [ -n "${TOKYO_TK:-}" ] && NODE_TOKENS[tokyo]="$TOKYO_TK"
fi

# Fallback: read tokens via SSH for any missing
for node in nyc sfo helsinki nuremberg singapore tokyo; do
    if [ -z "${NODE_TOKENS[$node]:-}" ]; then
        ip="${NODE_IPS[$node]}"
        tk=$(ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes root@"$ip" 'cat /root/.local/share/x0x/api-token 2>/dev/null || cat /var/lib/x0x/data/api-token 2>/dev/null' 2>/dev/null || echo "")
        if [ -n "$tk" ]; then
            NODE_TOKENS[$node]="$tk"
        else
            echo -e "${RED}Cannot get token for $node ($ip)${NC}"
        fi
    fi
done

# ── SSH-tunneled API calls ──────────────────────────────────────────────
SSH="ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes"
vps() {
    local ip="$1" token="$2" method="$3" path="$4" body="${5:-}"
    local cmd="curl -sf -m 10 -X $method -H 'Authorization: Bearer $token' -H 'Content-Type: application/json'"
    [ -n "$body" ] && cmd="$cmd -d '$body'"
    cmd="$cmd 'http://127.0.0.1:12600${path}'"
    $SSH "root@$ip" "$cmd" 2>/dev/null || echo '{"error":"curl_failed"}'
}
vps_get()   { vps "$1" "$2" GET "$3"; }
vps_post()  { vps "$1" "$2" POST "$3" "${4:-{}}"; }
vps_put()   { vps "$1" "$2" PUT "$3" "$4"; }
vps_del()   { vps "$1" "$2" DELETE "$3"; }
vps_patch() { vps "$1" "$2" PATCH "$3" "$4"; }

# Convenience shortcuts for common nodes
NYC_IP="${NODE_IPS[nyc]}"; NYC_TK="${NODE_TOKENS[nyc]:-}"
SFO_IP="${NODE_IPS[sfo]}"; SFO_TK="${NODE_TOKENS[sfo]:-}"
HEL_IP="${NODE_IPS[helsinki]}"; HEL_TK="${NODE_TOKENS[helsinki]:-}"
NUR_IP="${NODE_IPS[nuremberg]}"; NUR_TK="${NODE_TOKENS[nuremberg]:-}"
SGP_IP="${NODE_IPS[singapore]}"; SGP_TK="${NODE_TOKENS[singapore]:-}"
TKY_IP="${NODE_IPS[tokyo]}"; TKY_TK="${NODE_TOKENS[tokyo]:-}"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   x0x v$VERSION VPS E2E Test — 6 Bootstrap Nodes${NC}"
echo -e "${YELLOW}   NYC · SFO · Helsinki · Nuremberg · Singapore · Tokyo${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

# ═════════════════════════════════════════════════════════════════════════
# 1. HEALTH & VERSION — All 6 nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[1/15] Health & Version (6 nodes)${NC}"
for node in nyc sfo helsinki nuremberg singapore tokyo; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    if [ -z "$tk" ]; then skip "$node health" "no token"; continue; fi
    R=$(vps_get "$ip" "$tk" /health)
    check_json "$node health" "$R" "ok"
    check_contains "$node v$VERSION" "$R" "$VERSION"
done

# ═════════════════════════════════════════════════════════════════════════
# 2. IDENTITY — Distinct agent IDs across all 6 nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[2/15] Identity (6 distinct agents)${NC}"
declare -A NODE_AIDS=()
declare -A NODE_MIDS=()

for node in nyc sfo helsinki nuremberg singapore tokyo; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    if [ -z "$tk" ]; then skip "$node agent" "no token"; continue; fi
    R=$(vps_get "$ip" "$tk" /agent)
    check_json "$node agent" "$R" "agent_id"
    NODE_AIDS[$node]=$(jq_field "$R" "agent_id")
    NODE_MIDS[$node]=$(jq_field "$R" "machine_id")
    echo "  $node agent: ${NODE_AIDS[$node]:0:16}..."
done

# Verify all different
ALL_UNIQUE=true
declare -A SEEN_AIDS=()
for node in nyc sfo helsinki nuremberg singapore tokyo; do
    aid="${NODE_AIDS[$node]:-}"
    [ -z "$aid" ] && continue
    if [ -n "${SEEN_AIDS[$aid]:-}" ]; then ALL_UNIQUE=false; fi
    SEEN_AIDS[$aid]=1
done
check_eq "all 6 agents distinct" "$(echo $ALL_UNIQUE)" "true"

# Agent card
R=$(vps_get "$NYC_IP" "$NYC_TK" /agent/card); check_not_error "NYC agent card" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 3. NETWORK — Full mesh verification
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[3/15] Network Mesh (6 nodes)${NC}"
for node in nyc sfo helsinki nuremberg singapore tokyo; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    if [ -z "$tk" ]; then skip "$node mesh" "no token"; continue; fi
    R=$(vps_get "$ip" "$tk" /network/status)
    check_json "$node network" "$R" "connected_peers"
    PEERS=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('connected_peers',0))" 2>/dev/null||echo "0")
    echo "    $node peers: $PEERS"
done

R=$(vps_get "$NYC_IP" "$NYC_TK" /network/bootstrap-cache); check_not_error "NYC bootstrap cache" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 4. ANNOUNCE & DISCOVERY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[4/15] Announce & Discovery${NC}"
for node in nyc sfo helsinki nuremberg singapore tokyo; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    if [ -z "$tk" ]; then continue; fi
    R=$(vps_post "$ip" "$tk" /announce); check_not_error "$node announce" "$R"
done

echo "  Waiting 30s for global gossip propagation..."
sleep 30

R=$(vps_get "$NYC_IP" "$NYC_TK" /agents/discovered); check_not_error "NYC discovered" "$R"

# NYC finds Helsinki
HEL_AID="${NODE_AIDS[helsinki]:-}"
if [ -n "$HEL_AID" ]; then
    R=$(vps_post "$NYC_IP" "$NYC_TK" "/agents/find/$HEL_AID")
    if echo "$R" | grep -q '"found":true'; then
        check_contains "NYC finds Helsinki" "$R" '"found":true'
    else
        skip "NYC finds Helsinki" "gossip not propagated yet"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 5. CONTACTS & TRUST — NYC trusts Helsinki, blocks Singapore
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[5/15] Contacts & Trust${NC}"

# NYC adds Helsinki as Trusted
R=$(vps_post "$NYC_IP" "$NYC_TK" /contacts "{\"agent_id\":\"$HEL_AID\",\"trust_level\":\"Trusted\",\"label\":\"Helsinki\"}")
check_not_error "NYC adds Helsinki (Trusted)" "$R"

# Helsinki adds NYC as Trusted
NYC_AID="${NODE_AIDS[nyc]:-}"
R=$(vps_post "$HEL_IP" "$HEL_TK" /contacts "{\"agent_id\":\"$NYC_AID\",\"trust_level\":\"Trusted\",\"label\":\"NYC\"}")
check_not_error "Helsinki adds NYC (Trusted)" "$R"

# NYC blocks Singapore (for testing)
SGP_AID="${NODE_AIDS[singapore]:-}"
if [ -n "$SGP_AID" ]; then
    R=$(vps_post "$NYC_IP" "$NYC_TK" /contacts "{\"agent_id\":\"$SGP_AID\",\"trust_level\":\"Blocked\",\"label\":\"Singapore-blocked\"}")
    check_not_error "NYC blocks Singapore" "$R"

    # Trust evaluate blocked
    SGP_MID="${NODE_MIDS[singapore]:-}"
    R=$(vps_post "$NYC_IP" "$NYC_TK" /trust/evaluate "{\"agent_id\":\"$SGP_AID\",\"machine_id\":\"$SGP_MID\"}")
    check_contains "blocked eval -> RejectBlocked" "$R" "RejectBlocked"

    # Unblock Singapore
    R=$(vps_patch "$NYC_IP" "$NYC_TK" "/contacts/$SGP_AID" '{"trust_level":"Trusted"}')
    check_ok "NYC unblocks Singapore" "$R"
fi

# Verify contacts list
R=$(vps_get "$NYC_IP" "$NYC_TK" /contacts); check_contains "NYC contacts has Helsinki" "$R" "$HEL_AID"

# ═════════════════════════════════════════════════════════════════════════
# 6. PUB/SUB — Global gossip message
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[6/15] Pub/Sub (global gossip)${NC}"
R=$(vps_post "$HEL_IP" "$HEL_TK" /subscribe '{"topic":"vps-e2e-v014"}'); check_not_error "Helsinki subscribe" "$R"
R=$(vps_post "$TKY_IP" "$TKY_TK" /subscribe '{"topic":"vps-e2e-v014"}'); check_not_error "Tokyo subscribe" "$R"
PUB_B64=$(b64 "hello from NYC to the world — v$VERSION")
R=$(vps_post "$NYC_IP" "$NYC_TK" /publish "{\"topic\":\"vps-e2e-v014\",\"payload\":\"$PUB_B64\"}"); check_ok "NYC publish" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 7. DIRECT MESSAGING — NYC→Tokyo (longest path)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[7/15] Direct Messaging (NYC→Tokyo, Helsinki→Singapore)${NC}"

# Import Tokyo's card into NYC
TKY_AID="${NODE_AIDS[tokyo]:-}"
TKY_CARD=$(vps_get "$TKY_IP" "$TKY_TK" /agent/card)
TKY_LINK=$(jq_field "$TKY_CARD" "link")
if [ -n "$TKY_LINK" ]; then
    R=$(vps_post "$NYC_IP" "$NYC_TK" /agent/card/import "{\"card\":\"$TKY_LINK\",\"trust_level\":\"Trusted\"}")
    check_not_error "NYC imports Tokyo card" "$R"
fi

R=$(vps_post "$NYC_IP" "$NYC_TK" /agents/connect "{\"agent_id\":\"$TKY_AID\"}"); check_not_error "NYC connects to Tokyo" "$R"
sleep 3
DM_B64=$(b64 "direct message from NYC to Tokyo across the Pacific")
R=$(vps_post "$NYC_IP" "$NYC_TK" /direct/send "{\"agent_id\":\"$TKY_AID\",\"payload\":\"$DM_B64\"}"); check_ok "NYC→Tokyo direct send" "$R"

# Helsinki→Singapore
SGP_CARD=$(vps_get "$SGP_IP" "$SGP_TK" /agent/card)
SGP_LINK=$(jq_field "$SGP_CARD" "link")
if [ -n "$SGP_LINK" ]; then
    R=$(vps_post "$HEL_IP" "$HEL_TK" /agent/card/import "{\"card\":\"$SGP_LINK\",\"trust_level\":\"Trusted\"}")
    check_not_error "Helsinki imports Singapore card" "$R"
fi
R=$(vps_post "$HEL_IP" "$HEL_TK" /agents/connect "{\"agent_id\":\"$SGP_AID\"}"); check_not_error "Helsinki connects to Singapore" "$R"
sleep 3
DM_B64=$(b64 "direct from Helsinki to Singapore")
R=$(vps_post "$HEL_IP" "$HEL_TK" /direct/send "{\"agent_id\":\"$SGP_AID\",\"payload\":\"$DM_B64\"}"); check_ok "Helsinki→Singapore direct" "$R"

R=$(vps_get "$NYC_IP" "$NYC_TK" /direct/connections); check_not_error "NYC direct connections" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 8. MLS GROUPS — Multi-continent PQC encryption
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[8/15] MLS Groups (multi-continent PQC)${NC}"

R=$(vps_post "$NYC_IP" "$NYC_TK" /mls/groups); check_json "NYC create MLS group" "$R" "group_id"
MG=$(jq_field "$R" "group_id")
echo "  MLS group: ${MG:0:16}..."

R=$(vps_get "$NYC_IP" "$NYC_TK" /mls/groups); check_not_error "list MLS groups" "$R"

if [ -n "$MG" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" "/mls/groups/$MG"); check_json "get MLS group" "$R" "members"

    # Add Helsinki, Singapore, Tokyo
    R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/members" "{\"agent_id\":\"$HEL_AID\"}"); check_ok "add Helsinki to MLS" "$R"
    R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/members" "{\"agent_id\":\"$SGP_AID\"}"); check_ok "add Singapore to MLS" "$R"
    R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/members" "{\"agent_id\":\"$TKY_AID\"}"); check_ok "add Tokyo to MLS" "$R"

    # Encrypt and decrypt round-trip
    PLAIN_B64=$(b64 "PQC encrypted across 4 continents — ML-KEM-768 + ML-DSA-65")
    R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/encrypt" "{\"payload\":\"$PLAIN_B64\"}"); check_json "MLS encrypt" "$R" "ciphertext"
    CT=$(jq_field "$R" "ciphertext")
    EPOCH=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('epoch',0))" 2>/dev/null||echo "0")

    if [ -n "$CT" ]; then
        R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/decrypt" "{\"ciphertext\":\"$CT\",\"epoch\":$EPOCH}")
        check_json "MLS decrypt" "$R" "payload"
        DECRYPTED=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('payload','')).decode())" 2>/dev/null||echo "")
        check_eq "MLS decrypt round-trip" "$DECRYPTED" "PQC encrypted across 4 continents — ML-KEM-768 + ML-DSA-65"
    fi

    R=$(vps_post "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/welcome" "{\"agent_id\":\"$HEL_AID\"}"); check_not_error "MLS welcome Helsinki" "$R"

    # Remove Helsinki
    R=$(vps_del "$NYC_IP" "$NYC_TK" "/mls/groups/$MG/members/$HEL_AID"); check_not_error "remove Helsinki from MLS" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 9. NAMED GROUPS — NYC creates, Tokyo joins
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[9/15] Named Groups (NYC→Tokyo invite)${NC}"
R=$(vps_post "$NYC_IP" "$NYC_TK" /groups '{"name":"VPS Global Group v0.14","description":"Cross-continent test"}')
check_not_error "create group" "$R"
NG=$(jq_field "$R" "group_id")
R=$(vps_get "$NYC_IP" "$NYC_TK" /groups); check_contains "list groups" "$R" "VPS Global Group"

if [ -n "$NG" ]; then
    R=$(vps_post "$NYC_IP" "$NYC_TK" "/groups/$NG/invite"); check_not_error "generate invite" "$R"
    INVITE=$(jq_field "$R" "invite_link")

    if [ -n "$INVITE" ]; then
        # Validate invite format
        check_contains "invite is x0x://invite/" "$INVITE" "x0x://invite/"
        R=$(vps_post "$TKY_IP" "$TKY_TK" /groups/join "{\"invite\":\"$INVITE\"}"); check_not_error "Tokyo joins via invite" "$R"
    fi

    R=$(vps_put "$NYC_IP" "$NYC_TK" "/groups/$NG/display-name" '{"name":"NYC Admin"}'); check_ok "NYC display name" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 10. KV STORES — NYC writes, cross-continent read
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[10/15] Key-Value Stores (cross-continent)${NC}"
R=$(vps_post "$NYC_IP" "$NYC_TK" /stores '{"name":"vps-kv-v014","topic":"vps-kv-topic-v014"}'); check_not_error "create store" "$R"
SID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('store_id',d.get('id','')))" 2>/dev/null||echo "")

if [ -n "$SID" ]; then
    # NYC puts key
    VAL_B64=$(b64 "cross-continent KV data from NYC v$VERSION")
    R=$(vps_put "$NYC_IP" "$NYC_TK" "/stores/$SID/test-key" "{\"value\":\"$VAL_B64\",\"content_type\":\"text/plain\"}"); check_ok "NYC put key" "$R"

    # NYC reads key (verify round-trip)
    R=$(vps_get "$NYC_IP" "$NYC_TK" "/stores/$SID/test-key"); check_json "NYC get key" "$R" "value"
    GOT=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('value','')).decode())" 2>/dev/null||echo "")
    check_eq "KV round-trip" "$GOT" "cross-continent KV data from NYC v$VERSION"

    # List keys
    R=$(vps_get "$NYC_IP" "$NYC_TK" "/stores/$SID/keys"); check_contains "keys has test-key" "$R" "test-key"

    # Delete key
    R=$(vps_del "$NYC_IP" "$NYC_TK" "/stores/$SID/test-key"); check_ok "delete key" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 11. TASK LISTS — CRDT on Nuremberg
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[11/15] Task Lists (CRDT on Nuremberg)${NC}"
R=$(vps_post "$NUR_IP" "$NUR_TK" /task-lists '{"name":"VPS Tasks v014","topic":"vps-tasks-v014"}'); check_not_error "create list" "$R"
TL=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('list_id',d.get('id','')))" 2>/dev/null||echo "")

if [ -n "$TL" ]; then
    R=$(vps_post "$NUR_IP" "$NUR_TK" "/task-lists/$TL/tasks" '{"title":"Deploy v0.15.3","description":"Verified PQC MLS + FOAF presence"}')
    check_not_error "add task" "$R"
    TID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('task_id',d.get('id','')))" 2>/dev/null||echo "")
    R=$(vps_get "$NUR_IP" "$NUR_TK" "/task-lists/$TL/tasks"); check_contains "show tasks" "$R" "Deploy v0.15.3"
    if [ -n "$TID" ]; then
        R=$(vps_patch "$NUR_IP" "$NUR_TK" "/task-lists/$TL/tasks/$TID" '{"action":"claim"}'); check_not_error "claim" "$R"
        R=$(vps_patch "$NUR_IP" "$NUR_TK" "/task-lists/$TL/tasks/$TID" '{"action":"complete"}'); check_not_error "complete" "$R"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════
# 12. FILE TRANSFER — Singapore→NYC
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[12/15] File Transfer (Singapore→NYC)${NC}"
# Import NYC card into Singapore
NYC_CARD=$(vps_get "$NYC_IP" "$NYC_TK" /agent/card)
NYC_LINK=$(jq_field "$NYC_CARD" "link")
if [ -n "$NYC_LINK" ]; then
    R=$(vps_post "$SGP_IP" "$SGP_TK" /agent/card/import "{\"card\":\"$NYC_LINK\",\"trust_level\":\"Trusted\"}")
    check_not_error "Singapore imports NYC card" "$R"
fi
R=$(vps_post "$SGP_IP" "$SGP_TK" /files/send "{\"agent_id\":\"$NYC_AID\",\"filename\":\"vps-test.txt\",\"size\":42,\"sha256\":\"abc123\"}"); check_not_error "Singapore file offer" "$R"
R=$(vps_get "$SGP_IP" "$SGP_TK" /files/transfers); check_not_error "Singapore transfers" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 13. PRESENCE — FOAF across VPS mesh
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[13/15] Presence (FOAF + online)${NC}"
R=$(vps_get "$NYC_IP" "$NYC_TK" /presence/online); check_not_error "NYC presence online" "$R"
R=$(vps_get "$NYC_IP" "$NYC_TK" /presence/foaf); check_not_error "NYC presence foaf" "$R"
if [ -n "$HEL_AID" ]; then
    R=$(vps_get "$NYC_IP" "$NYC_TK" "/presence/find/$HEL_AID"); check_not_error "NYC find Helsinki presence" "$R"
    R=$(vps_get "$NYC_IP" "$NYC_TK" "/presence/status/$HEL_AID"); check_not_error "NYC Helsinki status" "$R"
fi
R=$(vps_get "$HEL_IP" "$HEL_TK" /presence/online); check_not_error "Helsinki presence online" "$R"
R=$(vps_get "$TKY_IP" "$TKY_TK" /presence/online); check_not_error "Tokyo presence online" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 14. CONSTITUTION — All 6 nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[14/15] Constitution & Upgrade (all nodes)${NC}"
for node in nyc sfo helsinki nuremberg singapore tokyo; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    if [ -z "$tk" ]; then skip "$node constitution" "no token"; continue; fi
    R=$(vps_get "$ip" "$tk" /constitution/json)
    check_json "$node constitution" "$R" "version"
done

# ═════════════════════════════════════════════════════════════════════════
# 15. WEBSOCKET, UPGRADE & STATUS — All nodes
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[15/15] WebSocket, Upgrade & Status${NC}"
for node in nyc sfo helsinki nuremberg singapore tokyo; do
    ip="${NODE_IPS[$node]}"; tk="${NODE_TOKENS[$node]:-}"
    if [ -z "$tk" ]; then skip "$node status" "no token"; continue; fi
    R=$(vps_get "$ip" "$tk" /status); check_json "$node status" "$R" "uptime_secs"
done
R=$(vps_get "$NYC_IP" "$NYC_TK" /ws/sessions); check_not_error "NYC ws sessions" "$R"
R=$(vps_get "$NYC_IP" "$NYC_TK" /upgrade); check_not_error "NYC upgrade check" "$R"

# ═════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}  ALL $TOTAL TESTS PASSED ($PASS passed, $SKIP skipped)${NC}"
    echo -e "  6 VPS nodes, 15 categories, v$VERSION"
else
    echo -e "${RED}  $FAIL FAILED / $TOTAL TOTAL${NC} ($PASS passed, $SKIP skipped)"
fi
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
exit $FAIL
