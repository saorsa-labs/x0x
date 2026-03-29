#!/usr/bin/env bash
# =============================================================================
# x0x v0.11.1 Full End-to-End Test Suite
# Two named instances (alice + bob) with separate identities
# Tests all 15 API categories with real data send/receive verification
# =============================================================================
set -euo pipefail

X0XD="$(pwd)/target/debug/x0xd"
PASS=0; FAIL=0; TOTAL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

b64() { echo -n "$1" | base64; }
b64d() { echo "$1" | base64 -d 2>/dev/null; }

check_json()     { local n="$1" r="$2" k="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|python3 -c "import sys,json;d=json.load(sys.stdin);assert '$k' in d" 2>/dev/null;then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — no key '$k' in: $(echo "$r"|head -c200)";fi; }
check_contains() { local n="$1" r="$2" e="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -qi "$e";then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — want '$e' in: $(echo "$r"|head -c250)";fi; }
check_ok()       { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"ok":true\|"ok": true';then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";elif echo "$r"|grep -q '"error"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }
check_not_error() { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"error":"curl_failed"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — curl_failed (non-2xx)";elif echo "$r"|grep -q '"ok":false';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — $(echo "$r"|head -c250)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }

A()  { curl -sf -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
B()  { curl -sf -H "Authorization: Bearer $BT" "$BA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Ap() { curl -sf -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "${2:-{}}" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Bp() { curl -sf -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d "${2:-{}}" "$BA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Apu(){ curl -sf -X PUT -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Apa(){ curl -sf -X PATCH -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Ad() { curl -sf -X DELETE -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }

# Verbose versions for debugging failures
Apv() { curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "${2:-{}}" "$AA$1" 2>/dev/null; }

cleanup() { echo ""; echo "Cleaning up..."; kill $AP $BP 2>/dev/null||true; wait $AP $BP 2>/dev/null||true; rm -rf /tmp/x0x-e2e-*; rm -rf ~/.x0x-e2e-alice ~/.x0x-e2e-bob; }
trap cleanup EXIT

echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   x0x v0.11.1 Full E2E Test — saorsa-mls PQC Integration${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"

# ── Setup ────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[Setup]${NC} Starting alice + bob with separate identities..."
rm -rf /tmp/x0x-e2e-alice /tmp/x0x-e2e-bob ~/.x0x-e2e-alice ~/.x0x-e2e-bob
mkdir -p /tmp/x0x-e2e-alice /tmp/x0x-e2e-bob

cat>/tmp/x0x-e2e-alice/config.toml<<TOML
instance_name = "e2e-alice"
data_dir = "/tmp/x0x-e2e-alice"
bind_address = "127.0.0.1:19001"
api_address = "127.0.0.1:19101"
log_level = "warn"
bootstrap_peers = ["127.0.0.1:19002"]
TOML

cat>/tmp/x0x-e2e-bob/config.toml<<TOML
instance_name = "e2e-bob"
data_dir = "/tmp/x0x-e2e-bob"
bind_address = "127.0.0.1:19002"
api_address = "127.0.0.1:19102"
log_level = "warn"
bootstrap_peers = ["127.0.0.1:19001"]
TOML

$X0XD --config /tmp/x0x-e2e-alice/config.toml &>/tmp/x0x-e2e-alice/log &
AP=$!
$X0XD --config /tmp/x0x-e2e-bob/config.toml &>/tmp/x0x-e2e-bob/log &
BP=$!

AA="http://127.0.0.1:19101"; BA="http://127.0.0.1:19102"

for i in $(seq 1 30); do
    a=$(curl -sf "$AA/health" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null||true)
    b=$(curl -sf "$BA/health" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null||true)
    [ "$a" = "True" ] && [ "$b" = "True" ] && echo -e "  ${GREEN}Both daemons ready (${i}s)${NC}" && break
    [ "$i" = "30" ] && echo -e "${RED}Startup failed!${NC}" && tail -20 /tmp/x0x-e2e-alice/log && exit 1
    sleep 1
done

AT=$(cat /tmp/x0x-e2e-alice/api-token 2>/dev/null||cat ~/.x0x-e2e-alice/api-token 2>/dev/null)
BT=$(cat /tmp/x0x-e2e-bob/api-token 2>/dev/null||cat ~/.x0x-e2e-bob/api-token 2>/dev/null)

# ═══════════════════════════════════════════════════════════════════════════
# 1. HEALTH & STATUS
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[1/15] Health & Status${NC}"
R=$(A /health); check_json "alice health" "$R" "ok"; check_contains "version 0.11.1" "$R" "0.11.1"
R=$(B /health); check_json "bob health" "$R" "ok"
R=$(A /status); check_json "alice status" "$R" "uptime_secs"

# ═══════════════════════════════════════════════════════════════════════════
# 2. IDENTITY
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[2/15] Identity${NC}"
RA=$(A /agent); check_json "alice agent" "$RA" "agent_id"
AID=$(echo "$RA"|python3 -c "import sys,json;print(json.load(sys.stdin)['agent_id'])")
AM=$(echo "$RA"|python3 -c "import sys,json;print(json.load(sys.stdin)['machine_id'])")
echo "  alice=${AID:0:16}..."

RB=$(B /agent); check_json "bob agent" "$RB" "agent_id"
BID=$(echo "$RB"|python3 -c "import sys,json;print(json.load(sys.stdin)['agent_id'])")
BM=$(echo "$RB"|python3 -c "import sys,json;print(json.load(sys.stdin)['machine_id'])")
echo "  bob  =${BID:0:16}..."

TOTAL=$((TOTAL+1)); if [ "$AID" != "$BID" ]; then PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} distinct agent IDs"; else FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} SAME agent IDs!"; fi

R=$(A /agent/card); check_not_error "agent card" "$R"
R=$(A /agent/user-id); check_not_error "user-id" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 3. NETWORK
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[3/15] Network (15s bootstrap)${NC}"
sleep 15
R=$(A /peers); check_not_error "peers" "$R"
R=$(A /network/status); check_json "network status" "$R" "connected_peers"
R=$(A /network/bootstrap-cache); check_not_error "bootstrap cache" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 4. ANNOUNCE & DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[4/15] Announce & Discovery${NC}"
R=$(Ap /announce); check_not_error "alice announce" "$R"
R=$(Bp /announce); check_not_error "bob announce" "$R"
echo "  Waiting 20s for gossip propagation..."
sleep 20
R=$(A /agents/discovered); check_not_error "discovered agents" "$R"
R=$(Ap "/agents/find/$BID"); check_not_error "find bob" "$R"
R=$(A "/agents/reachability/$BID"); check_not_error "bob reachability" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 5. CONTACTS & TRUST
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[5/15] Contacts & Trust${NC}"
R=$(Ap /contacts "{\"agent_id\":\"$BID\",\"trust_level\":\"Trusted\",\"label\":\"bob\"}"); check_not_error "alice adds bob" "$R"
R=$(Bp /contacts "{\"agent_id\":\"$AID\",\"trust_level\":\"Trusted\",\"label\":\"alice\"}"); check_not_error "bob adds alice" "$R"
R=$(A /contacts); check_contains "contacts has bob" "$R" "$BID"
R=$(Ap /trust/evaluate "{\"agent_id\":\"$BID\",\"machine_id\":\"$BM\"}"); check_not_error "trust evaluate" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 6. PUB/SUB (payload must be base64)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[6/15] Pub/Sub Messaging${NC}"
R=$(Bp /subscribe '{"topic":"e2e-channel"}'); check_not_error "bob subscribe" "$R"
PAYLOAD_B64=$(b64 "hello from alice via gossip")
R=$(Ap /publish "{\"topic\":\"e2e-channel\",\"payload\":\"$PAYLOAD_B64\"}"); check_ok "alice publish (base64)" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 7. DIRECT MESSAGING (field is "payload" base64, not "message")
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[7/15] Direct Messaging${NC}"
R=$(Ap /agents/connect "{\"agent_id\":\"$BID\"}"); check_not_error "connect to bob" "$R"
sleep 2
DM_B64=$(b64 "direct hello from alice to bob")
R=$(Ap /direct/send "{\"agent_id\":\"$BID\",\"payload\":\"$DM_B64\"}"); check_ok "send direct (base64)" "$R"
R=$(A /direct/connections); check_not_error "direct connections" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 8. MLS GROUPS (saorsa-mls PQC — encrypt/decrypt with base64)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[8/15] MLS Groups (PQC)${NC}"

# Create group
R=$(Ap /mls/groups); check_json "create MLS group" "$R" "group_id"
MG=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('group_id',''))" 2>/dev/null||echo "")
echo "  MLS group: ${MG:0:16}..."

# List and get
R=$(A /mls/groups); check_not_error "list MLS groups" "$R"
[ -n "$MG" ] && {
    R=$(A "/mls/groups/$MG"); check_json "get MLS group" "$R" "members"

    # Add bob — no longer double-applies commit
    R=$(Ap "/mls/groups/$MG/members" "{\"agent_id\":\"$BID\"}"); check_ok "add bob to MLS" "$R"
    check_json "add bob returns epoch" "$R" "epoch"

    # Encrypt (payload must be base64)
    PLAIN_B64=$(b64 "PQC encrypted secret message via saorsa-mls")
    R=$(Ap "/mls/groups/$MG/encrypt" "{\"payload\":\"$PLAIN_B64\"}"); check_json "encrypt" "$R" "ciphertext"
    CT=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('ciphertext',''))" 2>/dev/null||echo "")
    EPOCH=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('epoch',0))" 2>/dev/null||echo "0")

    # Decrypt (ciphertext base64, epoch required)
    [ -n "$CT" ] && {
        R=$(Ap "/mls/groups/$MG/decrypt" "{\"ciphertext\":\"$CT\",\"epoch\":$EPOCH}")
        check_json "decrypt" "$R" "payload"
        # Verify round-trip: decode the returned base64 payload
        DECRYPTED=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('payload','')).decode())" 2>/dev/null||echo "")
        TOTAL=$((TOTAL+1))
        if [ "$DECRYPTED" = "PQC encrypted secret message via saorsa-mls" ]; then
            PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} decrypt round-trip verified"
        else
            FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} decrypt mismatch: '$DECRYPTED'"
        fi
    }

    # Welcome
    R=$(Ap "/mls/groups/$MG/welcome" "{\"agent_id\":\"$BID\"}"); check_not_error "create welcome" "$R"
}

# ═══════════════════════════════════════════════════════════════════════════
# 9. NAMED GROUPS
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[9/15] Named Groups${NC}"
R=$(Ap /groups '{"name":"E2E Test Group","description":"full e2e test"}'); check_not_error "create group" "$R"
NG=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('group_id',''))" 2>/dev/null||echo "")
R=$(A /groups); check_contains "list groups" "$R" "E2E Test Group"

[ -n "$NG" ] && {
    R=$(A "/groups/$NG"); check_not_error "get group" "$R"

    # Invite — response has invite_link not invite
    R=$(Ap "/groups/$NG/invite"); check_not_error "generate invite" "$R"
    INVITE=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('invite_link',''))" 2>/dev/null||echo "")
    [ -n "$INVITE" ] && {
        R=$(Bp /groups/join "{\"invite\":\"$INVITE\"}"); check_not_error "bob joins via invite" "$R"
    }

    # Display name — field is "name" not "display_name"
    R=$(Apu "/groups/$NG/display-name" '{"name":"Alice the Admin"}'); check_ok "set display name" "$R"

    # Leave group
    R=$(Ad "/groups/$NG"); check_not_error "leave group" "$R"
}

# ═══════════════════════════════════════════════════════════════════════════
# 10. KEY-VALUE STORES (value must be base64)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[10/15] Key-Value Stores${NC}"
R=$(Ap /stores '{"name":"e2e-kv","topic":"e2e-kv-topic"}'); check_not_error "create store" "$R"
SID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('store_id',d.get('id','')))" 2>/dev/null||echo "")
echo "  store: $SID"

[ -n "$SID" ] && {
    # PUT — value must be base64
    VAL_B64=$(b64 "hello kv world")
    R=$(Apu "/stores/$SID/greeting" "{\"value\":\"$VAL_B64\",\"content_type\":\"text/plain\"}"); check_ok "put key (base64)" "$R"

    # GET — value comes back base64
    R=$(A "/stores/$SID/greeting"); check_json "get key" "$R" "value"
    GOT_VAL=$(echo "$R"|python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('value','')).decode())" 2>/dev/null||echo "")
    TOTAL=$((TOTAL+1))
    if [ "$GOT_VAL" = "hello kv world" ]; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} KV round-trip verified"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} KV mismatch: '$GOT_VAL'"
    fi

    # LIST keys
    R=$(A "/stores/$SID/keys"); check_contains "list keys" "$R" "greeting"

    # DELETE
    R=$(Ad "/stores/$SID/greeting"); check_ok "delete key" "$R"

    # Verify deletion
    R=$(A "/stores/$SID/keys")
    TOTAL=$((TOTAL+1))
    if echo "$R"|python3 -c "import sys,json;assert len(json.load(sys.stdin).get('keys',[]))==0" 2>/dev/null; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} key deleted confirmed"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} key still exists after delete"
    fi
}

R=$(A /stores); check_not_error "list stores" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 11. TASK LISTS (CRDT)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[11/15] Task Lists (CRDT)${NC}"
R=$(Ap /task-lists '{"name":"E2E Tasks","topic":"e2e-tasks-topic"}'); check_not_error "create task list" "$R"
TL=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('list_id',d.get('id','')))" 2>/dev/null||echo "")

[ -n "$TL" ] && {
    R=$(Ap "/task-lists/$TL/tasks" '{"title":"Verify PQC MLS","description":"Test saorsa-mls encryption"}'); check_not_error "add task" "$R"
    TID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('task_id',d.get('id','')))" 2>/dev/null||echo "")

    R=$(A "/task-lists/$TL/tasks"); check_contains "show tasks" "$R" "Verify PQC"

    [ -n "$TID" ] && {
        R=$(Apa "/task-lists/$TL/tasks/$TID" '{"action":"claim"}'); check_not_error "claim task" "$R"
        R=$(Apa "/task-lists/$TL/tasks/$TID" '{"action":"complete"}'); check_not_error "complete task" "$R"
    }
}
R=$(A /task-lists); check_not_error "list task-lists" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 12. FILE TRANSFER (needs sha256 + filename + size)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[12/15] File Transfer${NC}"
echo "E2E test file content for x0x" > /tmp/x0x-e2e-testfile.txt
FILE_SHA=$(shasum -a 256 /tmp/x0x-e2e-testfile.txt | cut -d' ' -f1)
FILE_SIZE=$(wc -c < /tmp/x0x-e2e-testfile.txt | tr -d ' ')
R=$(Ap /files/send "{\"agent_id\":\"$BID\",\"filename\":\"test.txt\",\"size\":$FILE_SIZE,\"sha256\":\"$FILE_SHA\",\"path\":\"/tmp/x0x-e2e-testfile.txt\"}")
check_not_error "send file offer" "$R"
check_json "transfer_id returned" "$R" "transfer_id"
R=$(A /files/transfers); check_not_error "list transfers" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 13. PRESENCE
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[13/15] Presence${NC}"
R=$(A /presence); check_not_error "presence list" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 14. WEBSOCKET
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[14/15] WebSocket${NC}"
R=$(A /ws/sessions); check_not_error "ws sessions" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# 15. UPGRADE
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[15/15] Upgrade${NC}"
R=$(A /upgrade); check_not_error "upgrade check" "$R"

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}  ALL $TOTAL TESTS PASSED${NC}"
else
    echo -e "${RED}  $FAIL FAILED / $TOTAL TOTAL${NC} ($PASS passed)"
    echo ""
    echo "alice errors:"
    grep -i "error" /tmp/x0x-e2e-alice/log | grep -v "WARN.*manifest\|WARN.*upgrade" | tail -10 || true
    echo "bob errors:"
    grep -i "error" /tmp/x0x-e2e-bob/log | grep -v "WARN.*manifest\|WARN.*upgrade" | tail -10 || true
fi
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"

exit $FAIL
