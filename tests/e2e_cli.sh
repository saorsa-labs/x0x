#!/usr/bin/env bash
# =============================================================================
# x0x CLI End-to-End Test Suite
# Two local instances (alice + bob) tested entirely via `x0x` CLI commands.
# No direct REST/curl calls — validates the CLI works as a real user would.
# =============================================================================
set -euo pipefail

X0XD="${X0XD:-$(pwd)/target/release/x0xd}"
X0X="${X0X:-$(pwd)/target/release/x0x}"
PASS=0; FAIL=0; SKIP=0; TOTAL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# ── Assertion helpers ────────────────────────────────────────────────────
check() {
    local name="$1" ok="$2"
    TOTAL=$((TOTAL+1))
    if [ "$ok" = "true" ]; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $name"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $name"
    fi
}

check_contains() {
    local name="$1" output="$2" expected="$3"
    TOTAL=$((TOTAL+1))
    if echo "$output" | grep -qi "$expected"; then
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $name"
    else
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $name — want '$expected' in: $(echo "$output" | head -c 250)"
    fi
}

check_not_error() {
    local name="$1" output="$2"
    TOTAL=$((TOTAL+1))
    # Check for real errors: "error":"cli_failed", "ok":false, or panic
    # Ignore "error": null (valid JSON field meaning no error)
    if echo "$output" | grep -q '"error":"cli_failed"'; then
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $name — cli_failed"
    elif echo "$output" | grep -q '"ok":false\|"ok": false'; then
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $name — $(echo "$output" | head -c 250)"
    elif echo "$output" | grep -qi "panic"; then
        FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $name — panic detected"
    else
        PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $name"
    fi
}

skip() {
    local name="$1" reason="$2"
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo -e "  ${YELLOW}SKIP${NC} $name — $reason"
}

# ── CLI wrappers (alice on port 19101, bob on port 19102) ────────────────
# Must pass X0X_API_TOKEN since --api overrides address but token comes from data dir
alice() {
    local tok
    tok=$(cat /tmp/x0x-cli-alice/api-token 2>/dev/null || true)
    X0X_API_TOKEN="$tok" "$X0X" --json --api "http://127.0.0.1:19101" "$@" 2>/dev/null || echo '{"error":"cli_failed"}'
}
bob() {
    local tok
    tok=$(cat /tmp/x0x-cli-bob/api-token 2>/dev/null || true)
    X0X_API_TOKEN="$tok" "$X0X" --json --api "http://127.0.0.1:19102" "$@" 2>/dev/null || echo '{"error":"cli_failed"}'
}
# Text mode for human-readable checks
alice_text() {
    local tok
    tok=$(cat /tmp/x0x-cli-alice/api-token 2>/dev/null || true)
    X0X_API_TOKEN="$tok" "$X0X" --api "http://127.0.0.1:19101" "$@" 2>&1 || echo "ERROR"
}
bob_text() {
    local tok
    tok=$(cat /tmp/x0x-cli-bob/api-token 2>/dev/null || true)
    X0X_API_TOKEN="$tok" "$X0X" --api "http://127.0.0.1:19102" "$@" 2>&1 || echo "ERROR"
}

jq_field() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null || echo ""; }

# ── Cleanup ──────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $ALICE_PID $BOB_PID 2>/dev/null || true
    wait $ALICE_PID $BOB_PID 2>/dev/null || true
    rm -rf /tmp/x0x-cli-alice /tmp/x0x-cli-bob /tmp/x0x-cli-testfile.txt
}
trap cleanup EXIT

# ═════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   x0x CLI End-to-End Test Suite${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"

# ── Verify binaries ──────────────────────────────────────────────────────
if [ ! -x "$X0XD" ]; then echo -e "${RED}x0xd not found at $X0XD — run: cargo build --release${NC}"; exit 1; fi
if [ ! -x "$X0X" ];  then echo -e "${RED}x0x not found at $X0X — run: cargo build --release${NC}"; exit 1; fi
echo -e "  x0xd: $X0XD"
echo -e "  x0x:  $X0X"

# ── Setup: start two daemons ─────────────────────────────────────────────
echo -e "\n${CYAN}[Setup] Starting alice + bob daemons...${NC}"
rm -rf /tmp/x0x-cli-alice /tmp/x0x-cli-bob
mkdir -p /tmp/x0x-cli-alice /tmp/x0x-cli-bob

cat > /tmp/x0x-cli-alice/config.toml <<TOML
instance_name = "cli-alice"
data_dir = "/tmp/x0x-cli-alice"
bind_address = "127.0.0.1:19001"
api_address = "127.0.0.1:19101"
log_level = "warn"
bootstrap_peers = ["127.0.0.1:19002"]
TOML

cat > /tmp/x0x-cli-bob/config.toml <<TOML
instance_name = "cli-bob"
data_dir = "/tmp/x0x-cli-bob"
bind_address = "127.0.0.1:19002"
api_address = "127.0.0.1:19102"
log_level = "warn"
bootstrap_peers = ["127.0.0.1:19001"]
TOML

"$X0XD" --config /tmp/x0x-cli-alice/config.toml &>/tmp/x0x-cli-alice/log &
ALICE_PID=$!
"$X0XD" --config /tmp/x0x-cli-bob/config.toml &>/tmp/x0x-cli-bob/log &
BOB_PID=$!

# Wait for both daemons to be ready
for i in $(seq 1 30); do
    a=$(alice health 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null || true)
    b=$(bob health 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null || true)
    if [ "$a" = "True" ] && [ "$b" = "True" ]; then
        echo -e "  ${GREEN}Both daemons ready (${i}s)${NC}"
        break
    fi
    if [ "$i" = "30" ]; then
        echo -e "  ${RED}Startup failed!${NC}"
        cat /tmp/x0x-cli-alice/log | tail -20
        exit 1
    fi
    sleep 1
done

# ═════════════════════════════════════════════════════════════════════════
# 1. HEALTH & STATUS
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[1/13] Health & Status${NC}"
R=$(alice health); check_contains "alice health ok" "$R" '"ok"'
R=$(bob health);   check_contains "bob health ok" "$R" '"ok"'
R=$(alice status); check_contains "alice status" "$R" "uptime_secs"

# ═════════════════════════════════════════════════════════════════════════
# 2. IDENTITY & AGENT CARDS
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[2/14] Identity & Agent Cards${NC}"

R=$(alice agent); check_contains "alice agent" "$R" "agent_id"
ALICE_AID=$(jq_field "$R" "agent_id")
ALICE_MID=$(jq_field "$R" "machine_id")
echo "  alice agent_id=${ALICE_AID:0:16}..."

R=$(bob agent); check_contains "bob agent" "$R" "agent_id"
BOB_AID=$(jq_field "$R" "agent_id")
BOB_MID=$(jq_field "$R" "machine_id")
echo "  bob   agent_id=${BOB_AID:0:16}..."

check "distinct agent IDs" "$([ "$ALICE_AID" != "$BOB_AID" ] && echo true || echo false)"

# Generate cards (CLI positional display_name)
R=$(alice agent card Alice); check_contains "alice card" "$R" "link"
ALICE_CARD=$(jq_field "$R" "link")

R=$(bob agent card Bob); check_contains "bob card" "$R" "link"
BOB_CARD=$(jq_field "$R" "link")

# ── Card identity validation ──────────────────────────────────────────
# Decode alice's card and verify it contains alice's agent_id (not bob's or anyone else's)
ALICE_CARD_AID=$(echo "$ALICE_CARD" | sed 's|x0x://agent/||' | python3 -c "
import sys,json,base64
b64=sys.stdin.read().strip()
# Try URL-safe then standard base64
try:
    d=json.loads(base64.urlsafe_b64decode(b64+'=='))
except:
    d=json.loads(base64.b64decode(b64+'=='))
print(d.get('agent_id',''))
" 2>/dev/null || echo "")
check "alice card contains alice agent_id" "$([ "$ALICE_CARD_AID" = "$ALICE_AID" ] && echo true || echo false)"

# Decode bob's card and verify it contains bob's agent_id
BOB_CARD_AID=$(echo "$BOB_CARD" | sed 's|x0x://agent/||' | python3 -c "
import sys,json,base64
b64=sys.stdin.read().strip()
try:
    d=json.loads(base64.urlsafe_b64decode(b64+'=='))
except:
    d=json.loads(base64.b64decode(b64+'=='))
print(d.get('agent_id',''))
" 2>/dev/null || echo "")
check "bob card contains bob agent_id" "$([ "$BOB_CARD_AID" = "$BOB_AID" ] && echo true || echo false)"

# Verify cards don't contain each other's identity (the Ben bug)
check "alice card does NOT contain bob agent_id" "$([ "$ALICE_CARD_AID" != "$BOB_AID" ] && echo true || echo false)"
check "bob card does NOT contain alice agent_id" "$([ "$BOB_CARD_AID" != "$ALICE_AID" ] && echo true || echo false)"

# Verify display names in cards
ALICE_CARD_NAME=$(echo "$ALICE_CARD" | sed 's|x0x://agent/||' | python3 -c "
import sys,json,base64
b64=sys.stdin.read().strip()
try:
    d=json.loads(base64.urlsafe_b64decode(b64+'=='))
except:
    d=json.loads(base64.b64decode(b64+'=='))
print(d.get('display_name',''))
" 2>/dev/null || echo "")
check "alice card display_name is Alice" "$([ "$ALICE_CARD_NAME" = "Alice" ] && echo true || echo false)"

# Import each other's cards
R=$(alice agent import "$BOB_CARD" --trust trusted); check_not_error "alice imports bob card" "$R"
R=$(bob agent import "$ALICE_CARD" --trust trusted); check_not_error "bob imports alice card" "$R"

# Verify imported contact matches the card's agent_id
R=$(alice contacts list)
check "alice contacts contains bob's card agent_id" "$(echo "$R" | grep -q "$BOB_CARD_AID" && echo true || echo false)"

# ═════════════════════════════════════════════════════════════════════════
# 3. NETWORK & BOOTSTRAP
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[3/13] Network & Bootstrap (15s wait)${NC}"
sleep 15
R=$(alice peers); check_not_error "alice peers" "$R"
R=$(alice network status); check_contains "network status" "$R" "connected_peers"
R=$(alice network cache); check_not_error "bootstrap cache" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 4. ANNOUNCE & DISCOVERY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[4/13] Announce & Discovery${NC}"
R=$(alice announce); check_not_error "alice announce" "$R"
R=$(bob announce);   check_not_error "bob announce" "$R"
echo "  Waiting 20s for gossip propagation..."
sleep 20
R=$(alice agents list); check_not_error "discovered agents" "$R"

# Try to find bob via gossip (may not work on localhost)
R=$(alice agents find "$BOB_AID" 2>/dev/null || echo '{}')
if echo "$R" | grep -q '"found":true'; then
    check_contains "find bob via gossip" "$R" '"found":true'
else
    skip "find bob via gossip" "expected on localhost — card import used instead"
fi

# ═════════════════════════════════════════════════════════════════════════
# 5. CONTACTS & TRUST
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[5/13] Contacts & Trust${NC}"
R=$(alice contacts list); check_contains "alice has bob in contacts" "$R" "$BOB_AID"
R=$(bob contacts list);   check_contains "bob has alice in contacts" "$R" "$ALICE_AID"

R=$(alice trust evaluate "$BOB_AID" "$BOB_MID"); check_not_error "trust evaluate bob" "$R"
R=$(alice trust set "$BOB_AID" trusted); check_not_error "trust set bob trusted" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 6. PUB/SUB MESSAGING
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[6/13] Pub/Sub Messaging${NC}"

# Bob subscribes in background, alice publishes
# (subscribe is a streaming command, so we just test publish works)
R=$(alice publish "e2e-test-topic" "hello from alice via gossip CLI"); check_not_error "alice publish" "$R"
R=$(bob publish "e2e-test-topic" "hello from bob via gossip CLI");     check_not_error "bob publish" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 7. DIRECT MESSAGING
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[7/13] Direct Messaging${NC}"

# Connect alice to bob
R=$(alice direct connect "$BOB_AID"); check_not_error "alice connect to bob" "$R"
sleep 2

# Send direct message
R=$(alice direct send "$BOB_AID" "hey bob, this is a CLI direct message"); check_not_error "alice direct send" "$R"
R=$(alice direct connections); check_not_error "alice direct connections" "$R"

# Bob connects back and sends
R=$(bob direct connect "$ALICE_AID"); check_not_error "bob connect to alice" "$R"
sleep 2
R=$(bob direct send "$ALICE_AID" "hey alice, got your message"); check_not_error "bob direct send" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 8. MLS GROUPS (PQC encryption)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[8/13] MLS Groups (PQC Encryption)${NC}"

R=$(alice groups create); check_contains "create MLS group" "$R" "group_id"
MLS_GID=$(jq_field "$R" "group_id")
echo "  MLS group: ${MLS_GID:0:16}..."

if [ -n "$MLS_GID" ]; then
    R=$(alice groups list); check_not_error "list MLS groups" "$R"
    R=$(alice groups get "$MLS_GID"); check_contains "get MLS group" "$R" "members"

    # Add bob to group
    R=$(alice groups add-member "$MLS_GID" "$BOB_AID"); check_not_error "add bob to MLS" "$R"

    # Encrypt
    R=$(alice groups encrypt "$MLS_GID" "PQC encrypted secret via CLI"); check_contains "encrypt" "$R" "ciphertext"
    CIPHERTEXT=$(jq_field "$R" "ciphertext")
    EPOCH=$(echo "$R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('epoch',0))" 2>/dev/null || echo "0")

    # Decrypt round-trip
    if [ -n "$CIPHERTEXT" ]; then
        R=$(alice groups decrypt "$MLS_GID" "$CIPHERTEXT" --epoch "$EPOCH"); check_contains "decrypt" "$R" "payload"
        DECRYPTED=$(echo "$R" | python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('payload','')).decode())" 2>/dev/null || echo "")
        check "decrypt round-trip matches" "$([ "$DECRYPTED" = "PQC encrypted secret via CLI" ] && echo true || echo false)"
    fi

    # Welcome message
    R=$(alice groups welcome "$MLS_GID" "$BOB_AID"); check_not_error "create welcome" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 9. NAMED GROUPS (spaces)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[9/13] Named Groups (Spaces)${NC}"

R=$(alice group create "CLI Test Space" --description "e2e CLI test space"); check_not_error "create named group" "$R"
NG_ID=$(jq_field "$R" "group_id")
echo "  Named group: ${NG_ID:0:16}..."

if [ -n "$NG_ID" ]; then
    R=$(alice group list); check_contains "list named groups" "$R" "CLI Test Space"
    R=$(alice group info "$NG_ID"); check_not_error "get group info" "$R"

    # Generate invite and validate it
    R=$(alice group invite "$NG_ID"); check_not_error "generate invite" "$R"
    INVITE_LINK=$(jq_field "$R" "invite_link")

    # ── CRITICAL: Space invite link validation (the Ben bug) ──────────
    # Invite links MUST be x0x://invite/, NOT x0x://agent/
    if [ -n "$INVITE_LINK" ]; then
        check "invite is x0x://invite/ (not x0x://agent/)" "$(echo "$INVITE_LINK" | grep -q '^x0x://invite/' && echo true || echo false)"

        # Decode the invite and verify it contains group info, not agent identity
        INVITE_DECODED=$(echo "$INVITE_LINK" | sed 's|x0x://invite/||' | python3 -c "
import sys,json,base64
b64=sys.stdin.read().strip()
try:
    d=json.loads(base64.urlsafe_b64decode(b64+'=='))
except:
    d=json.loads(base64.b64decode(b64+'=='))
print(json.dumps(d))
" 2>/dev/null || echo "{}")
        check "invite has group_name" "$(echo "$INVITE_DECODED" | grep -q 'group_name' && echo true || echo false)"
        check "invite has group_id" "$(echo "$INVITE_DECODED" | grep -q 'group_id' && echo true || echo false)"
        check "invite has invite_secret" "$(echo "$INVITE_DECODED" | grep -q 'invite_secret' && echo true || echo false)"

        # Verify invite group_name matches what we created
        INVITE_GNAME=$(echo "$INVITE_DECODED" | python3 -c "import sys,json;print(json.load(sys.stdin).get('group_name',''))" 2>/dev/null || echo "")
        check "invite group_name matches 'CLI Test Space'" "$([ "$INVITE_GNAME" = "CLI Test Space" ] && echo true || echo false)"

        # Bob joins via invite
        R=$(bob group join "$INVITE_LINK" --display-name "Bob"); check_not_error "bob joins via invite" "$R"
    else
        skip "invite link validation" "no invite_link returned"
        skip "bob joins via invite" "no invite_link returned"
    fi

    # ── Agent card with --include-groups ──────────────────────────────
    # When alice generates a card with groups, the embedded group links
    # should be x0x://invite/ links, not duplicates of alice's card
    R=$(alice agent card Alice --include-groups); check_not_error "card with groups" "$R"
    CARD_WITH_GROUPS=$(jq_field "$R" "link")
    if [ -n "$CARD_WITH_GROUPS" ]; then
        # Decode the card and check embedded group invite links
        CARD_GROUPS=$(echo "$CARD_WITH_GROUPS" | sed 's|x0x://agent/||' | python3 -c "
import sys,json,base64
b64=sys.stdin.read().strip()
try:
    d=json.loads(base64.urlsafe_b64decode(b64+'=='))
except:
    d=json.loads(base64.b64decode(b64+'=='))
groups=d.get('groups',[])
for g in groups:
    print(g.get('invite_link',''))
" 2>/dev/null || echo "")

        if [ -n "$CARD_GROUPS" ]; then
            # Each embedded invite should be x0x://invite/, not x0x://agent/
            ALL_INVITES_OK=true
            while IFS= read -r inv; do
                [ -z "$inv" ] && continue
                if ! echo "$inv" | grep -q '^x0x://invite/'; then
                    ALL_INVITES_OK=false
                    echo -e "    ${RED}BAD embedded link:${NC} $inv"
                fi
            done <<< "$CARD_GROUPS"
            check "card embedded group links are x0x://invite/" "$(echo $ALL_INVITES_OK)"
        else
            skip "card embedded group invite links" "no groups in card (alice may have left)"
        fi

        # The card itself should still contain alice's identity
        CARD_AID=$(echo "$CARD_WITH_GROUPS" | sed 's|x0x://agent/||' | python3 -c "
import sys,json,base64
b64=sys.stdin.read().strip()
try:
    d=json.loads(base64.urlsafe_b64decode(b64+'=='))
except:
    d=json.loads(base64.b64decode(b64+'=='))
print(d.get('agent_id',''))
" 2>/dev/null || echo "")
        check "card-with-groups still has alice's agent_id" "$([ "$CARD_AID" = "$ALICE_AID" ] && echo true || echo false)"
    fi

    # Set display name
    R=$(alice group set-name "$NG_ID" "Alice the Admin"); check_not_error "set display name" "$R"

    # Leave group
    R=$(alice group leave "$NG_ID"); check_not_error "alice leaves group" "$R"
fi

# ═════════════════════════════════════════════════════════════════════════
# 10. KEY-VALUE STORES
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[10/13] Key-Value Stores${NC}"

R=$(alice store create "cli-kv" "cli-kv-topic"); check_not_error "create store" "$R"
STORE_ID=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('store_id',d.get('id','')))" 2>/dev/null || echo "")
echo "  store: $STORE_ID"

if [ -n "$STORE_ID" ]; then
    # Put
    R=$(alice store put "$STORE_ID" "greeting" "hello kv world"); check_not_error "put key" "$R"

    # Get
    R=$(alice store get "$STORE_ID" "greeting"); check_contains "get key" "$R" "value"
    GOT_VAL=$(echo "$R" | python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin).get('value','')).decode())" 2>/dev/null || echo "")
    check "KV round-trip verified" "$([ "$GOT_VAL" = "hello kv world" ] && echo true || echo false)"

    # List keys
    R=$(alice store keys "$STORE_ID"); check_contains "list keys" "$R" "greeting"

    # Remove
    R=$(alice store rm "$STORE_ID" "greeting"); check_not_error "delete key" "$R"

    # Verify deletion
    R=$(alice store keys "$STORE_ID")
    KEYS_EMPTY=$(echo "$R" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('keys',[]))==0)" 2>/dev/null || echo "False")
    check "key deleted confirmed" "$([ "$KEYS_EMPTY" = "True" ] && echo true || echo false)"
fi

R=$(alice store list); check_not_error "list stores" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 11. TASK LISTS (CRDT)
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[11/13] Task Lists (CRDT)${NC}"

R=$(alice tasks create "CLI Tasks" "cli-tasks-topic"); check_not_error "create task list" "$R"
TL_ID=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('list_id',d.get('id','')))" 2>/dev/null || echo "")
echo "  task list: $TL_ID"

if [ -n "$TL_ID" ]; then
    R=$(alice tasks add "$TL_ID" "Test PQC MLS" --description "Verify encryption round-trip"); check_not_error "add task" "$R"
    TASK_ID=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('task_id',d.get('id','')))" 2>/dev/null || echo "")

    R=$(alice tasks show "$TL_ID"); check_contains "show tasks" "$R" "Test PQC"

    if [ -n "$TASK_ID" ]; then
        R=$(alice tasks claim "$TL_ID" "$TASK_ID"); check_not_error "claim task" "$R"
        R=$(alice tasks complete "$TL_ID" "$TASK_ID"); check_not_error "complete task" "$R"
    fi
fi

R=$(alice tasks list); check_not_error "list task lists" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 12. FILE TRANSFER
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[12/13] File Transfer${NC}"

echo "CLI e2e test file content" > /tmp/x0x-cli-testfile.txt
R=$(alice_text send-file "$BOB_AID" /tmp/x0x-cli-testfile.txt); check_not_error "send file offer" "$R"
R=$(alice transfers); check_not_error "list transfers" "$R"

# ═════════════════════════════════════════════════════════════════════════
# 13. PRESENCE & MISC
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[13/13] Presence & Misc${NC}"

R=$(alice presence); check_not_error "presence" "$R"
R=$(alice_text tree); check_contains "command tree" "$R" "direct"

# ═════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}  ALL $TOTAL TESTS PASSED ($PASS passed, $SKIP skipped)${NC}"
else
    echo -e "${RED}  $FAIL FAILED${NC} / $TOTAL TOTAL ($PASS passed, $SKIP skipped)"
    echo ""
    echo "alice log tail:"
    grep -i "error\|panic" /tmp/x0x-cli-alice/log | grep -v "WARN\|manifest\|upgrade" | tail -10 || true
    echo "bob log tail:"
    grep -i "error\|panic" /tmp/x0x-cli-bob/log | grep -v "WARN\|manifest\|upgrade" | tail -10 || true
fi
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"

exit $FAIL
