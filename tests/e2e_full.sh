#!/usr/bin/env bash
# =============================================================================
# x0x v0.11.1 Full End-to-End Test Suite
# Two named instances (alice + bob) with separate identities
# =============================================================================
set -euo pipefail

X0XD="$(pwd)/target/debug/x0xd"
PASS=0; FAIL=0; TOTAL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

check_json()  { local n="$1" r="$2" k="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|python3 -c "import sys,json;d=json.load(sys.stdin);assert '$k' in d or '$k' in d.get('card',{})" 2>/dev/null;then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — key '$k' :: $(echo "$r"|head -c200)";fi; }
check_contains() { local n="$1" r="$2" e="$3"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -qi "$e";then PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";else FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n — want '$e' :: $(echo "$r"|head -c200)";fi; }
check_ok()    { local n="$1" r="$2"; TOTAL=$((TOTAL+1)); if echo "$r"|grep -q '"error"';then FAIL=$((FAIL+1));echo -e "  ${RED}FAIL${NC} $n :: $(echo "$r"|head -c200)";else PASS=$((PASS+1));echo -e "  ${GREEN}PASS${NC} $n";fi; }

A() { curl -sf -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
B() { curl -sf -H "Authorization: Bearer $BT" "$BA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Ap() { curl -sf -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "${2:-{}}" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Bp() { curl -sf -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d "${2:-{}}" "$BA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Apu() { curl -sf -X PUT -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Apa() { curl -sf -X PATCH -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }
Ad() { curl -sf -X DELETE -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null||echo '{"error":"curl_failed"}'; }

cleanup() { echo ""; echo "Cleaning up..."; kill $AP $BP 2>/dev/null||true; wait $AP $BP 2>/dev/null||true; rm -rf /tmp/x0x-e2e-*; }
trap cleanup EXIT

echo -e "${YELLOW}═══ x0x v0.11.1 Full E2E Test ═══${NC}"

# ── Setup ────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[Setup]${NC} Starting alice + bob..."
rm -rf /tmp/x0x-e2e-alice /tmp/x0x-e2e-bob
mkdir -p /tmp/x0x-e2e-alice /tmp/x0x-e2e-bob

cat>/tmp/x0x-e2e-alice/config.toml<<TOML
instance_name = "e2e-alice"
data_dir = "/tmp/x0x-e2e-alice"
bind_address = "127.0.0.1:19001"
api_address = "127.0.0.1:19101"
log_level = "warn"
TOML

cat>/tmp/x0x-e2e-bob/config.toml<<TOML
instance_name = "e2e-bob"
data_dir = "/tmp/x0x-e2e-bob"
bind_address = "127.0.0.1:19002"
api_address = "127.0.0.1:19102"
log_level = "warn"
TOML

$X0XD --config /tmp/x0x-e2e-alice/config.toml &>/tmp/x0x-e2e-alice/log &
AP=$!
$X0XD --config /tmp/x0x-e2e-bob/config.toml &>/tmp/x0x-e2e-bob/log &
BP=$!

AA="http://127.0.0.1:19101"; BA="http://127.0.0.1:19102"

for i in $(seq 1 30); do
    a=$(curl -sf "$AA/health" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null||true)
    b=$(curl -sf "$BA/health" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null||true)
    [ "$a" = "True" ] && [ "$b" = "True" ] && echo -e "  ${GREEN}Ready (${i}s)${NC}" && break
    [ "$i" = "30" ] && echo -e "${RED}Startup failed${NC}" && tail -20 /tmp/x0x-e2e-alice/log && exit 1
    sleep 1
done

AT=$(cat /tmp/x0x-e2e-alice/api-token 2>/dev/null||cat ~/.x0x-e2e-alice/api-token 2>/dev/null)
BT=$(cat /tmp/x0x-e2e-bob/api-token 2>/dev/null||cat ~/.x0x-e2e-bob/api-token 2>/dev/null)

# ── 1. Health ────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1] Health & Status${NC}"
R=$(A /health); check_json "alice health" "$R" "ok"; check_contains "version" "$R" "0.11.1"
R=$(B /health); check_json "bob health" "$R" "ok"
R=$(A /status); check_json "status" "$R" "uptime_secs"

# ── 2. Identity ──────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[2] Identity${NC}"
RA=$(A /agent); check_json "alice agent" "$RA" "agent_id"
AID=$(echo "$RA"|python3 -c "import sys,json;print(json.load(sys.stdin)['agent_id'])" 2>/dev/null)
AM=$(echo "$RA"|python3 -c "import sys,json;print(json.load(sys.stdin)['machine_id'])" 2>/dev/null)
echo "  alice=${AID:0:16}..."

RB=$(B /agent); check_json "bob agent" "$RB" "agent_id"
BID=$(echo "$RB"|python3 -c "import sys,json;print(json.load(sys.stdin)['agent_id'])" 2>/dev/null)
BM=$(echo "$RB"|python3 -c "import sys,json;print(json.load(sys.stdin)['machine_id'])" 2>/dev/null)
echo "  bob  =${BID:0:16}..."

# Verify different identities
TOTAL=$((TOTAL+1))
if [ "$AID" != "$BID" ]; then PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} different agent IDs"; else FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} SAME agent IDs!"; fi

R=$(A /agent/card); check_ok "agent card" "$R"

# ── 3. Network ───────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3] Network (15s bootstrap wait)${NC}"
sleep 15
R=$(A /peers); check_ok "peers" "$R"
R=$(A /network/status); check_json "network status" "$R" "connected_peers"
R=$(A /network/bootstrap-cache); check_ok "bootstrap cache" "$R"

# ── 4. Announce & Discovery ──────────────────────────────────────────────────
echo -e "\n${YELLOW}[4] Announce & Discovery${NC}"
Ap /announce; Bp /announce
echo "  Waiting 20s for gossip propagation..."
sleep 20
R=$(A /agents/discovered); check_ok "discovered agents" "$R"
R=$(Ap "/agents/find/$BID"); check_ok "find bob" "$R"

# ── 5. Contacts ──────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[5] Contacts & Trust${NC}"
R=$(Ap /contacts "{\"agent_id\":\"$BID\",\"trust_level\":\"Trusted\",\"label\":\"bob\"}"); check_ok "alice adds bob" "$R"
R=$(Bp /contacts "{\"agent_id\":\"$AID\",\"trust_level\":\"Trusted\",\"label\":\"alice\"}"); check_ok "bob adds alice" "$R"
R=$(A /contacts); check_contains "contacts has bob" "$R" "$BID"
R=$(Ap /trust/evaluate "{\"agent_id\":\"$BID\",\"machine_id\":\"$BM\"}"); check_ok "trust evaluate" "$R"

# ── 6. Pub/Sub ───────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[6] Pub/Sub${NC}"
R=$(Bp /subscribe '{"topic":"e2e-channel"}'); check_ok "subscribe" "$R"
R=$(Ap /publish '{"topic":"e2e-channel","payload":"hello from alice"}'); check_ok "publish" "$R"

# ── 7. Direct Messaging ─────────────────────────────────────────────────────
echo -e "\n${YELLOW}[7] Direct Messaging${NC}"
R=$(Ap /agents/connect "{\"agent_id\":\"$BID\"}"); check_ok "connect" "$R"
sleep 2
R=$(Ap /direct/send "{\"agent_id\":\"$BID\",\"message\":\"direct hello\"}"); check_ok "send direct" "$R"
R=$(A /direct/connections); check_ok "connections" "$R"

# ── 8. MLS Groups ───────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[8] MLS Groups (PQC)${NC}"
R=$(Ap /mls/groups); check_json "create MLS group" "$R" "group_id"
MG=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('group_id',''))" 2>/dev/null||echo "")
echo "  MLS group: ${MG:0:16}..."

R=$(A /mls/groups); check_ok "list groups" "$R"
[ -n "$MG" ] && {
    R=$(A "/mls/groups/$MG"); check_json "get group" "$R" "members"
    R=$(Ap "/mls/groups/$MG/members" "{\"agent_id\":\"$BID\"}"); check_ok "add bob" "$R"
    R=$(Ap "/mls/groups/$MG/encrypt" '{"payload":"PQC encrypted secret"}'); check_json "encrypt" "$R" "ciphertext"
    CT=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('ciphertext',''))" 2>/dev/null||echo "")
    [ -n "$CT" ] && { R=$(Ap "/mls/groups/$MG/decrypt" "{\"ciphertext\":\"$CT\"}"); check_contains "decrypt" "$R" "PQC encrypted"; }
    R=$(Ap "/mls/groups/$MG/welcome" "{\"agent_id\":\"$BID\"}"); check_ok "welcome" "$R"
}

# ── 9. Named Groups ─────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[9] Named Groups${NC}"
R=$(Ap /groups '{"name":"E2E Group","description":"test"}'); check_ok "create group" "$R"
NG=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('group_id',''))" 2>/dev/null||echo "")
R=$(A /groups); check_contains "list groups" "$R" "E2E Group"
[ -n "$NG" ] && {
    R=$(A "/groups/$NG"); check_ok "get group" "$R"
    R=$(Ap "/groups/$NG/invite"); check_ok "invite" "$R"
    INVITE=$(echo "$R"|python3 -c "import sys,json;print(json.load(sys.stdin).get('invite_link',''))" 2>/dev/null||echo "")
    [ -n "$INVITE" ] && { R=$(Bp /groups/join "{\"invite\":\"$INVITE\"}"); check_ok "bob joins" "$R"; }
    R=$(Apu "/groups/$NG/display-name" '{"display_name":"Alice"}'); check_ok "display name" "$R"
}

# ── 10. KV Stores ───────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[10] Key-Value Stores${NC}"
R=$(Ap /stores '{"name":"e2e-kv","topic":"e2e-kv-t"}'); check_ok "create store" "$R"
SID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('store_id',d.get('id','')))" 2>/dev/null||echo "")
[ -n "$SID" ] && {
    R=$(Apu "/stores/$SID/greeting" '{"value":"hello world","content_type":"text/plain"}'); check_ok "put key" "$R"
    R=$(A "/stores/$SID/greeting"); check_contains "get key" "$R" "hello world"
    R=$(A "/stores/$SID/keys"); check_contains "list keys" "$R" "greeting"
    R=$(Ad "/stores/$SID/greeting"); check_ok "delete key" "$R"
}
R=$(A /stores); check_ok "list stores" "$R"

# ── 11. Task Lists ──────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[11] Task Lists (CRDT)${NC}"
R=$(Ap /task-lists '{"name":"E2E Tasks","topic":"e2e-tasks-t"}'); check_ok "create list" "$R"
TL=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('list_id',d.get('id','')))" 2>/dev/null||echo "")
[ -n "$TL" ] && {
    R=$(Ap "/task-lists/$TL/tasks" '{"title":"Test PQC MLS","description":"Verify encryption"}'); check_ok "add task" "$R"
    TID=$(echo "$R"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('task_id',d.get('id','')))" 2>/dev/null||echo "")
    R=$(A "/task-lists/$TL/tasks"); check_contains "show tasks" "$R" "Test PQC"
    [ -n "$TID" ] && {
        R=$(Apa "/task-lists/$TL/tasks/$TID" '{"action":"claim"}'); check_ok "claim" "$R"
        R=$(Apa "/task-lists/$TL/tasks/$TID" '{"action":"complete"}'); check_ok "complete" "$R"
    }
}
R=$(A /task-lists); check_ok "list task-lists" "$R"

# ── 12. File Transfer ────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[12] File Transfer${NC}"
echo "E2E test $(date)" > /tmp/x0x-e2e-testfile.txt
R=$(Ap /files/send "{\"agent_id\":\"$BID\",\"path\":\"/tmp/x0x-e2e-testfile.txt\"}"); check_ok "send file" "$R"
R=$(A /files/transfers); check_ok "list transfers" "$R"

# ── 13-15. Presence, WS, Upgrade ────────────────────────────────────────────
echo -e "\n${YELLOW}[13-15] Presence, WebSocket, Upgrade${NC}"
R=$(A /presence); check_ok "presence" "$R"
R=$(A /ws/sessions); check_ok "ws sessions" "$R"
R=$(A /upgrade); check_ok "upgrade" "$R"

# ═════════════════════════════════════════════════════════════════════════════
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ]; then echo -e "${GREEN}  ALL $TOTAL TESTS PASSED${NC}"
else echo -e "${RED}  $FAIL FAILED / $TOTAL TOTAL${NC} ($PASS passed)"; fi
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

[ $FAIL -gt 0 ] && { echo ""; echo "alice errors:"; grep -i "error" /tmp/x0x-e2e-alice/log|tail -5||true; echo "bob errors:"; grep -i "error" /tmp/x0x-e2e-bob/log|tail -5||true; }
exit $FAIL
