# ══════════════════════════════════════════════════════════════════════════
# Named Groups Full Model — E2E sections to add to e2e_full_audit.sh
# Append these after section [9] NAMED GROUPS / SPACES (and before [10] TASK LISTS)
# Uses existing helpers: get/post/put/pat/del (Alice), bget/bpst (Bob), cget/cpst (Charlie)
# Alice=AID, Bob=BID, Charlie=CID (already captured by the main script)
# ══════════════════════════════════════════════════════════════════════════

# Start Charlie if not already started — needed for request/approval flow
if [ -z "$CP" ]; then
  start_charlie
  CR=$(cget /agent); CID=$(fld "$CR" "agent_id")
  proof "charlie started: agent_id=${CID:0:24}..."
fi

sec "━━ [9a] NAMED GROUPS — Policy & Preset ━━"

# [9a-1] Create group with explicit private_secure preset
R=$(post /groups "{\"name\":\"priv-sec-$TS\",\"preset\":\"private_secure\"}")
chk "$R" "group_id" "POST /groups preset=private_secure"
GID_PS=$(fld "$R" "group_id")
proof "private_secure group_id=${GID_PS:0:24}..."

# [9a-2] Verify default policy is private_secure
R=$(get /groups/$GID_PS)
DISC=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('policy',{}).get('discoverability',''))" 2>/dev/null)
chkv "$DISC" "hidden" "private_secure discoverability=hidden"
ADM=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('policy',{}).get('admission',''))" 2>/dev/null)
chkv "$ADM" "invite_only" "private_secure admission=invite_only"
CONF=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('policy',{}).get('confidentiality',''))" 2>/dev/null)
chkv "$CONF" "mls_encrypted" "private_secure confidentiality=mls_encrypted"

# [9a-3] Hidden group must NOT be discoverable by non-members
DISC_BOB=$(bget /groups/discover | python3 -c "
import sys,json
d=json.load(sys.stdin)
target='$GID_PS'
matches=[g for g in d.get('groups',[]) if g.get('group_id')==target]
print(len(matches))" 2>/dev/null || echo "err")
chkv "$DISC_BOB" "0" "private_secure NOT in bob's discover"

# [9a-4] PATCH /groups/:id (owner updates name/description)
R=$(pat /groups/$GID_PS '{"description":"updated desc"}')
chk "$R" "ok" "PATCH /groups/:id (update metadata)"

# [9a-5] Clean up
R=$(del /groups/$GID_PS); chk "$R" "ok" "DELETE /groups/:id cleanup private_secure"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [9b] NAMED GROUPS — public_request_secure Full Flow ━━"

# [9b-1] Alice creates public_request_secure group
R=$(post /groups "{\"name\":\"pub-req-$TS\",\"preset\":\"public_request_secure\"}")
chk "$R" "group_id" "POST /groups preset=public_request_secure"
GID_PRS=$(fld "$R" "group_id")
proof "public_request_secure group_id=${GID_PRS:0:24}..."

# [9b-2] Verify policy
R=$(get /groups/$GID_PRS)
DISC=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('policy',{}).get('discoverability',''))" 2>/dev/null)
chkv "$DISC" "public_directory" "public_request_secure discoverability=public_directory"
ADM=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('policy',{}).get('admission',''))" 2>/dev/null)
chkv "$ADM" "request_access" "public_request_secure admission=request_access"

# [9b-3] Alice's own discover shows her group
R=$(get /groups/discover)
COUNT=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
target='$GID_PRS'
print(sum(1 for g in d.get('groups',[]) if g.get('group_id')==target))" 2>/dev/null || echo "0")
chkv "$COUNT" "1" "owner sees public group in /groups/discover"

# [9b-4] Alice fetches group card
R=$(get /groups/cards/$GID_PRS)
chk "$R" "group_id" "GET /groups/cards/:id"
CARD_JSON="$R"
proof "card has $(echo "$CARD_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('member_count',0))" 2>/dev/null) members"

# [9b-5] Bob imports Alice's card
R=$(bpst /groups/cards/import "$CARD_JSON")
chk "$R" "ok" "POST /groups/cards/import (bob)"

# [9b-6] Bob can see group in his discover after import
COUNT=$(bget /groups/discover | python3 -c "
import sys,json
d=json.load(sys.stdin)
target='$GID_PRS'
print(sum(1 for g in d.get('groups',[]) if g.get('group_id')==target))" 2>/dev/null || echo "0")
chkv "$COUNT" "1" "bob sees imported group in discover"

# [9b-7] Bob submits join request
R=$(bpst /groups/$GID_PRS/requests '{"message":"Please let me join"}')
chk "$R" "request_id" "POST /groups/:id/requests (bob submits)"
BOB_REQ_ID=$(fld "$R" "request_id")
proof "bob request_id=${BOB_REQ_ID:0:16}..."

# [9b-8] Wait for gossip propagation, Alice sees pending request
sleep 3
R=$(get /groups/$GID_PRS/requests)
chk "$R" "requests" "GET /groups/:id/requests (alice sees)"
PENDING=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for r in d.get('requests',[]) if r.get('status')=='pending' and r.get('requester_agent_id')=='$BID'))" 2>/dev/null || echo "0")
chkv "$PENDING" "1" "alice sees bob's pending request"

# [9b-9] Alice approves Bob's request
R=$(post /groups/$GID_PRS/requests/$BOB_REQ_ID/approve '{}')
chk "$R" "ok" "POST /groups/:id/requests/:rid/approve"

# [9b-10] Bob is now an active member
sleep 2
R=$(get /groups/$GID_PRS/members)
BOB_ACTIVE=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for m in d.get('members',[]):
    if m.get('agent_id')=='$BID' and m.get('state','active')=='active':
        print('yes'); break
else:
    print('no')" 2>/dev/null)
chkv "$BOB_ACTIVE" "yes" "bob is now active member after approval"

# [9b-11] Charlie submits request, Alice rejects
R=$(cpst /groups/$GID_PRS/requests '{"message":"Also me"}')
chk "$R" "request_id" "POST /groups/:id/requests (charlie submits)"
CHARLIE_REQ_ID=$(fld "$R" "request_id")

sleep 2
R=$(post /groups/$GID_PRS/requests/$CHARLIE_REQ_ID/reject '{}')
chk "$R" "ok" "POST /groups/:id/requests/:rid/reject"

# [9b-12] Charlie is NOT a member
R=$(get /groups/$GID_PRS/members)
CHARLIE_MEMBER=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for m in d.get('members',[]) if m.get('agent_id')=='$CID' and m.get('state','active')=='active'))" 2>/dev/null || echo "err")
chkv "$CHARLIE_MEMBER" "0" "charlie NOT a member after rejection"

# [9b-13] Cancel own request path — Charlie creates a new one, cancels it
R=$(cpst /groups/$GID_PRS/requests '{}')
CREQ2=$(fld "$R" "request_id")
if [ -n "$CREQ2" ]; then
  R=$(curl -sf -m 10 -X DELETE -H "Authorization: Bearer $CT" "$CA/groups/$GID_PRS/requests/$CREQ2" 2>/dev/null || echo '{"error":"curl_fail"}')
  chk "$R" "ok" "DELETE /groups/:id/requests/:rid (cancel own)"
fi

# Cleanup
R=$(del /groups/$GID_PRS); chk "$R" "ok" "DELETE /groups/:id cleanup public_request_secure"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [9c] NAMED GROUPS — Authorization Negative Paths ━━"

# [9c-1] Alice creates a group
R=$(post /groups "{\"name\":\"authz-$TS\"}")
GID_AZ=$(fld "$R" "group_id")
chk "$R" "group_id" "POST /groups for authz test"

# [9c-2] Non-member Bob cannot PATCH policy
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PATCH -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{"preset":"public_open"}' "$BA/groups/$GID_AZ/policy" 2>/dev/null)
chkv "$STATUS" "403" "non-member PATCH policy → 403"

# [9c-3] Add Bob as plain Member
R=$(post /groups/$GID_AZ/members "{\"agent_id\":\"$BID\"}")
chk "$R" "ok" "alice adds bob as member"

# [9c-4] Bob (Member role) still cannot PATCH policy (Owner-only)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PATCH -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{"preset":"public_open"}' "$BA/groups/$GID_AZ/policy" 2>/dev/null)
chkv "$STATUS" "403" "member PATCH policy → 403 (owner-only)"

# [9c-5] Switch group to public_request_secure so we can test approval authz
R=$(pat /groups/$GID_AZ/policy '{"preset":"public_request_secure"}')
chk "$R" "ok" "owner switches to public_request_secure"

# [9c-6] Charlie submits request; Bob (Member, not Admin) cannot approve
R=$(cpst /groups/$GID_AZ/requests '{}')
CREQ_A=$(fld "$R" "request_id")
sleep 2
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{}' "$BA/groups/$GID_AZ/requests/$CREQ_A/approve" 2>/dev/null)
chkv "$STATUS" "403" "member cannot approve request → 403"

# [9c-7] Bob (Member) cannot remove Alice (Owner)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X DELETE -H "Authorization: Bearer $BT" "$BA/groups/$GID_AZ/members/$AID" 2>/dev/null)
chkv "$STATUS" "403" "member cannot remove owner → 403"

# [9c-8] Alice promotes Bob to Admin
R=$(pat /groups/$GID_AZ/members/$BID/role '{"role":"admin"}')
chk "$R" "ok" "PATCH /groups/:id/members/:id/role (promote bob to admin)"

# [9c-9] Bob (Admin) CAN approve Charlie's request now
R=$(curl -sf -m 10 -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{}' "$BA/groups/$GID_AZ/requests/$CREQ_A/approve" 2>/dev/null || echo '{"error":"curl_fail"}')
chk "$R" "ok" "admin CAN approve request"

# [9c-10] Ban Bob, verify banned member cannot submit join request
R=$(del /groups/$GID_AZ/members/$BID)
chk "$R" "ok" "remove bob first"
R=$(post /groups/$GID_AZ/members "{\"agent_id\":\"$BID\"}")  # re-add for ban test
chk "$R" "ok" "re-add bob for ban test"
R=$(post /groups/$GID_AZ/ban/$BID '{}')
chk "$R" "ok" "POST /groups/:id/ban/:id"

sleep 2
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{}' "$BA/groups/$GID_AZ/requests" 2>/dev/null)
chkv "$STATUS" "403" "banned member cannot create join request → 403"

# [9c-11] Unban
R=$(curl -sf -m 10 -X DELETE -H "Authorization: Bearer $AT" "$AA/groups/$GID_AZ/ban/$BID" 2>/dev/null || echo '{"error":"curl_fail"}')
chk "$R" "ok" "DELETE /groups/:id/ban/:id (unban)"

# Cleanup
R=$(del /groups/$GID_AZ); chk "$R" "ok" "DELETE /groups/:id cleanup authz"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [9d] NAMED GROUPS — Ban/Unban + Convergence ━━"

# [9d-1] Create group, invite bob, add him
R=$(post /groups "{\"name\":\"ban-$TS\"}")
GID_BAN=$(fld "$R" "group_id")
INV=$(fld "$(post /groups/$GID_BAN/invite '{}')" "invite_link")
R=$(bpst /groups/join "{\"invite\":\"$INV\"}")
chk "$R" "ok" "bob joins via invite"
R=$(post /groups/$GID_BAN/members "{\"agent_id\":\"$BID\"}")
chk "$R" "ok" "alice adds bob"

# [9d-2] Ban Bob
R=$(post /groups/$GID_BAN/ban/$BID '{}')
chk "$R" "ok" "ban bob"

# [9d-3] Verify state=banned
R=$(get /groups/$GID_BAN/members)
STATE=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for m in d.get('members',[]):
    if m.get('agent_id')=='$BID':
        print(m.get('state','unknown')); break
else:
    print('not_found')" 2>/dev/null)
chkv "$STATE" "banned" "bob state=banned in member list"

# [9d-4] Unban
R=$(curl -sf -m 10 -X DELETE -H "Authorization: Bearer $AT" "$AA/groups/$GID_BAN/ban/$BID" 2>/dev/null || echo '{"error":"curl_fail"}')
chk "$R" "ok" "unban bob"

# [9d-5] Verify state=active
R=$(get /groups/$GID_BAN/members)
STATE=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for m in d.get('members',[]):
    if m.get('agent_id')=='$BID':
        print(m.get('state','unknown')); break
else:
    print('not_found')" 2>/dev/null)
chkv "$STATE" "active" "bob state=active after unban"

# [9d-6] Delete-group convergence — bob's view should lose the group
R=$(del /groups/$GID_BAN); chk "$R" "ok" "alice deletes group"
sleep 3
BR=$(bget /groups/$GID_BAN 2>/dev/null || echo '{"error":"curl_fail"}')
if echo "$BR" | grep -q 'group not found\|curl_fail\|"error"'; then
  ok "delete convergence: bob's view cleared"
else
  fail "delete convergence: bob's view cleared" "$BR"
fi
