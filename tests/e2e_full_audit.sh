#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
X0XD="${X0XD:-$ROOT/target/release/x0xd}"
X0X="${X0X:-$ROOT/target/release/x0x}"
X0X_USER_KEYGEN="${X0X_USER_KEYGEN:-$ROOT/target/release/x0x-user-keygen}"
AA="http://127.0.0.1:19811"
BA="http://127.0.0.1:19812"
CA="http://127.0.0.1:19813"
ADIR="/tmp/x0x-fulltest-alice"
BDIR="/tmp/x0x-fulltest-bob"
CDIR="/tmp/x0x-fulltest-charlie"
TS=$(date +%Y%m%d_%H%M%S)_$$
PROOF_TOKEN="full-audit-$TS"
ENDPOINT_COUNT=$(python3 - <<'PY'
import re, pathlib
text = pathlib.Path('src/api/mod.rs').read_text()
print(len(re.findall(r'path:\s*"', text)))
PY
)

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YEL='\033[0;33m'; NC='\033[0m'
P=0; F=0; S=0
AP=""; BP=""; CP=""
AT=""; BT=""; CT=""
USER_KEY_PATH="/tmp/x0x-fulltest-user.key"

cleanup() {
  [ -n "$AP" ] && kill "$AP" 2>/dev/null || true
  [ -n "$BP" ] && kill "$BP" 2>/dev/null || true
  [ -n "$CP" ] && kill "$CP" 2>/dev/null || true
  wait "$AP" "$BP" "$CP" 2>/dev/null || true
  rm -rf "$ADIR" "$BDIR" "$CDIR"
  rm -f "$USER_KEY_PATH"
}
trap cleanup EXIT

if [ ! -x "$X0XD" ] || [ ! -x "$X0X" ] || [ ! -x "$X0X_USER_KEYGEN" ]; then
  echo "Build first: cargo build --release --bin x0xd --bin x0x --bin x0x-user-keygen" >&2
  exit 1
fi

"$X0X_USER_KEYGEN" "$USER_KEY_PATH" >/dev/null

for port in 19811 19812 19813 19881 19882 19883; do
  lsof -ti tcp:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
done
sleep 1

start_daemon() {
  local dir="$1" name="$2" bind_port="$3" api_port="$4" bootstrap="$5"
  rm -rf "$dir"
  mkdir -p "$dir"
  cat > "$dir/config.toml" <<TOML
instance_name = "$name"
data_dir = "$dir"
bind_address = "127.0.0.1:$bind_port"
api_address = "127.0.0.1:$api_port"
log_level = "warn"
heartbeat_interval_secs = 2
identity_ttl_secs = 6
presence_beacon_interval_secs = 2
presence_event_poll_interval_secs = 1
presence_offline_timeout_secs = 3
user_key_path = "$USER_KEY_PATH"
bootstrap_peers = [$bootstrap]
TOML
  "$X0XD" --config "$dir/config.toml" --skip-update-check >"$dir/log" 2>&1 &
  echo $!
}

wait_health() {
  local url="$1"
  for i in $(seq 1 60); do
    if curl -sf "$url/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_token() {
  local file="$1"
  for i in $(seq 1 60); do
    if [ -s "$file" ]; then
      local token
      token=$(tr -d '[:space:]' < "$file" 2>/dev/null || true)
      if [ ${#token} -ge 32 ]; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

AP=$(start_daemon "$ADIR" fulltest-alice 19881 19811 '"127.0.0.1:19882"')
BP=$(start_daemon "$BDIR" fulltest-bob 19882 19812 '"127.0.0.1:19881"')
wait_health "$AA"
wait_health "$BA"
wait_token "$ADIR/api-token"
wait_token "$BDIR/api-token"
AT=$(tr -d '[:space:]' < "$ADIR/api-token")
BT=$(tr -d '[:space:]' < "$BDIR/api-token")

ok()    { P=$((P+1)); printf "  ${GREEN}✓${NC} %-62s\n" "$1"; }
fail()  { F=$((F+1)); printf "  ${RED}✗${NC} %-56s  %s\n" "$1" "${2:0:120}"; }
skip()  { S=$((S+1)); printf "  ${YEL}~${NC} %-56s  skip:$2\n" "$1"; }
sec()   { printf "\n${CYAN}$1${NC}\n"; }
proof() { printf "  ${YEL}[PROOF]${NC} %s\n" "$1"; }
get()   { curl -sf -m 10 -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
bget()  { curl -sf -m 10 -H "Authorization: Bearer $BT" "$BA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
cget()  { curl -sf -m 10 -H "Authorization: Bearer $CT" "$CA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
post()  { curl -sf -m 10 -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
# post_slow: used for endpoints that do network queries (rendezvous, find, connect) — needs longer timeout
post_slow() { curl -sf -m 30 -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
bpst()  { curl -sf -m 10 -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d "$2" "$BA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
cpst()  { curl -sf -m 10 -X POST -H "Authorization: Bearer $CT" -H "Content-Type: application/json" -d "$2" "$CA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
put()   { curl -sf -m 10 -X PUT  -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
bput()  { curl -sf -m 10 -X PUT  -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d "$2" "$BA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
pat()   { curl -sf -m 10 -X PATCH -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -d "$2" "$AA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
bpat()  { curl -sf -m 10 -X PATCH -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d "$2" "$BA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
del()   { curl -sf -m 10 -X DELETE -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
bdel()  { curl -sf -m 10 -X DELETE -H "Authorization: Bearer $BT" "$BA$1" 2>/dev/null || echo '{"error":"curl_fail"}'; }
# Returns HTTP status code
http_status() { curl -so /dev/null -w "%{http_code}" -m 5 -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null; }
http_status_b() { curl -so /dev/null -w "%{http_code}" -m 5 -H "Authorization: Bearer $BT" "$BA$1" 2>/dev/null; }
http_del() { curl -so /dev/null -w "%{http_code}" -X DELETE -m 5 -H "Authorization: Bearer $AT" "$AA$1" 2>/dev/null; }
ws_connect() { { curl -sf -m 3 -H "Authorization: Bearer $AT" -H "Connection: Upgrade" -H "Upgrade: websocket" \
               -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "$AA$1" 2>/dev/null | strings | head -1; } || true; }
fld()  { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null || echo ""; }
chk()  { local R="$1" K="$2" N="$3"
  if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert '$K' in d" 2>/dev/null; then ok "$N"; else fail "$N" "$R"; fi; }
check_contains() { local N="$1" R="$2" NEEDLE="$3"; [[ "$R" == *"$NEEDLE"* ]] && ok "$N" || fail "$N" "want='$NEEDLE' got='${R:0:120}'"; }
chkv() { [[ "$1" == *"$2"* ]] && ok "$3" || fail "$3" "want='$2' got='${1:0:90}'"; }
json_len() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);v=d.get('$2',[]);print(len(v) if isinstance(v,list) else 0)" 2>/dev/null || echo 0; }
# Named groups currently expose two identifiers during the D.3 transition:
# - local/authority `group_id` on create/list/get routes (legacy MLS key)
# - stable public `group_id` on cards/discovery/imported stubs
# When a test crosses from authority-local control-plane routes into public
# discovery/card/import flows, derive the stable id from the signed card.
stable_group_id_from_local() { fld "$(get /groups/cards/$1)" "group_id"; }
json_path() { echo "$1" | python3 - <<PY 2>/dev/null || true
import json,sys
obj=json.load(sys.stdin)
path='$2'.split('.')
cur=obj
for part in path:
    if part.isdigit():
        cur=cur[int(part)]
    else:
        cur=cur.get(part)
print('' if cur is None else cur)
PY
}
start_sse_capture() {
  local token="$1" url="$2" outfile="$3" max_time="${4:-12}"
  if [[ "$url" == *"/direct/events" || "$url" == */events && "$url" != *"/presence/events" ]]; then
    curl -NsS --max-time "$max_time" "$url?token=$token" >"$outfile" 2>/dev/null &
  else
    curl -NsS --max-time "$max_time" -H "Authorization: Bearer $token" "$url" >"$outfile" 2>/dev/null &
  fi
  echo $!
}
start_charlie() {
  # Idempotent: if charlie already running, just reuse the existing token.
  if [ -n "$CP" ] && kill -0 "$CP" 2>/dev/null && curl -sf "$CA/health" >/dev/null 2>&1; then
    return 0
  fi
  CP=$(start_daemon "$CDIR" fulltest-charlie 19883 19813 '"127.0.0.1:19881"')
  wait_health "$CA"
  wait_token "$CDIR/api-token"
  CT=$(tr -d '[:space:]' < "$CDIR/api-token")
}

AID=$(fld "$(get /agent)" "agent_id")
AMI=$(fld "$(get /agent)" "machine_id")
BID=$(fld "$(bget /agent)" "agent_id")
BMI=$(fld "$(bget /agent)" "machine_id")
ALINK=$(fld "$(get /agent/card)" "link")
BLINK=$(fld "$(bget /agent/card)" "link")
# DISC_ID: first discovered agent that is NOT alice herself (Bob or VPS node)
# Used for GET /agents/discovered/:id and reachability tests — works even if Bob not yet discovered
DISC_ID=$(get /agents/discovered | python3 -c "
import sys,json,os
d=json.load(sys.stdin)
aid='$AID'
agents=[a for a in d.get('agents',[]) if a['agent_id']!=aid]
print(agents[0]['agent_id'] if agents else aid)
" 2>/dev/null || echo "$AID")
DISC_SRC="$([ "$DISC_ID" == "$BID" ] && echo "bob" || echo "vps/other")"

printf "\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}\n"
printf "${CYAN}║    x0x COMPLETE API AUDIT — ${ENDPOINT_COUNT} endpoints + CLI + GUI + WS      ║${NC}\n"
printf "${CYAN}║    Run: $TS                                   ║${NC}\n"
printf "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}\n"
proof "Token: ${PROOF_TOKEN}"
proof "Alice: ${AID:0:24}...  Bob: ${BID:0:24}..."
proof "Machine Alice: ${AMI:0:20}...  Machine Bob: ${BMI:0:20}..."
proof "Disc peer: ${DISC_ID:0:24}... (${DISC_SRC})"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [1] UNAUTHENTICATED (3 endpoints / 7 checks) ━━"
# GET /health
R=$(curl -sf -m 5 "$AA/health" 2>/dev/null || echo '{}')
chk "$R" "ok"  "GET /health"
chkv "$(fld "$R" "version")" "0.17" "GET /health → version 0.17.x"
proof "version=$(fld "$R" "version") peers=$(fld "$R" "peers")"

# GET /constitution
R=$(curl -sf -m 5 "$AA/constitution" 2>/dev/null || echo "")
[[ "$R" == *"x0x"* ]] && ok "GET /constitution (plaintext)" || fail "GET /constitution" "empty"

# GET /constitution/json
R=$(curl -sf -m 5 "$AA/constitution/json" 2>/dev/null || echo '{}')
chk "$R" "version" "GET /constitution/json"
chk "$R" "content" "GET /constitution/json → content"
proof "constitution v=$(fld "$R" "version")"

# GET /gui (unauthenticated)
GUI=$(curl -sf -m 10 "$AA/gui" 2>/dev/null || echo "")
[[ "$GUI" == *"<!DOCTYPE html"* ]] && ok "GET /gui → DOCTYPE html" || fail "GET /gui → DOCTYPE" ""
GUI_CT=$(curl -sI -m 5 "$AA/gui" 2>/dev/null | grep -i "^content-type:" | tr -d '\r')
[[ "$GUI_CT" == *"text/html"* ]] && ok "GET /gui → Content-Type: text/html" || fail "GET /gui → CT" "$GUI_CT"
[[ "$GUI" == *"X0X_TOKEN"* ]] && ok "GET /gui → API token injected in <script>" || fail "GET /gui → token" ""
proof "GUI body=${#GUI}B  CT=$GUI_CT"
GUI_SLASH=$(curl -sf -m 10 "$AA/gui/" 2>/dev/null || echo "")
[[ "$GUI_SLASH" == *"<!DOCTYPE html"* ]] && ok "GET /gui/ → trailing slash alias works" || fail "GET /gui/ alias" ""

sec "━━ [1b] AUTH BOUNDARIES (strong proof) ━━"
UA=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$AA/agent" 2>/dev/null || echo 000)
[[ "$UA" == "401" || "$UA" == "403" ]] && ok "GET /agent requires auth" || fail "GET /agent requires auth" "HTTP $UA"
UGUI=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$AA/gui" 2>/dev/null || echo 000)
[[ "$UGUI" == "200" ]] && ok "GET /gui remains unauthenticated" || fail "GET /gui unauth" "HTTP $UGUI"
UCONS=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$AA/constitution/json" 2>/dev/null || echo 000)
[[ "$UCONS" == "200" ]] && ok "GET /constitution/json remains unauthenticated" || fail "GET /constitution/json unauth" "HTTP $UCONS"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [2] IDENTITY & STATUS (7 endpoints / 11 checks) ━━"
R=$(get /agent);         chk "$R" "agent_id"   "GET /agent"
proof "agent_id=$(fld "$R" "agent_id" | head -c 32)..."
R=$(get /agent/user-id); chk "$R" "ok"          "GET /agent/user-id"
AUSER_ID=$(fld "$R" "user_id")
proof "user_id=${AUSER_ID:-<none>}"
R=$(get /agent/card);    chk "$R" "link"        "GET /agent/card"
proof "link=${ALINK:0:50}..."
R=$(get /introduction);  chk "$R" "agent_id"   "GET /introduction"
proof "intro services=$(echo "$R" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('services',[])))" 2>/dev/null)"
# Introduction with peer context (trust-scoped disclosure)
R=$(get "/introduction?peer=$BID"); chk "$R" "agent_id" "GET /introduction?peer=:id (trust-scoped)"
R=$(post /announce '{"include_user_identity":true,"human_consent":true}');chk "$R" "ok"          "POST /announce (alice)"
R=$(bpst /announce '{"include_user_identity":true,"human_consent":true}');chk "$R" "ok"          "POST /announce (bob)"
R=$(post /agent/card/import "{\"card\":\"$BLINK\",\"trust_level\":\"Trusted\"}"); chk "$R" "ok" "POST /agent/card/import (alice imports bob)"
proof "alice import→agent=$(fld "$R" "agent_id" | head -c 20)..."
R=$(bpst /agent/card/import "{\"card\":\"$ALINK\",\"trust_level\":\"Trusted\"}"); chk "$R" "ok" "POST /agent/card/import (bob imports alice)"
proof "bob import→agent=$(fld "$R" "agent_id" | head -c 20)..."
R=$(get /status);        chk "$R" "ok"          "GET /status"
proof "uptime=$(fld "$R" "uptime_secs")s daemon=$(fld "$R" "version")"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [3] NETWORK & DISCOVERY (10 endpoints / 14 checks) ━━"
R=$(get /peers); chk "$R" "peers" "GET /peers"
proof "peers=$(echo "$R" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('peers',[])))" 2>/dev/null)"
R=$(get /network/status); chk "$R" "ok" "GET /network/status"
proof "nat=$(fld "$R" "nat_type") has_global=$(fld "$R" "has_global_address") peers=$(fld "$R" "connected_peers")"
R=$(get /network/bootstrap-cache); chk "$R" "ok" "GET /network/bootstrap-cache"
R=$(get /agents/discovered); chk "$R" "agents" "GET /agents/discovered"
proof "discovered=$(echo "$R" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('agents',[])))" 2>/dev/null)"
# Use DISC_ID (first non-self discovered peer — may be Bob or VPS node, not just Bob)
R=$(get /agents/discovered/$DISC_ID); chk "$R" "agent" "GET /agents/discovered/:id ($DISC_SRC)"
proof "disc_id=${DISC_ID:0:16}... last_seen=$(echo "$R" | python3 -c "import sys,json;print(json.load(sys.stdin)['agent']['last_seen'])" 2>/dev/null)"
R=$(get /agents/reachability/$DISC_ID); chk "$R" "ok" "GET /agents/reachability/:id ($DISC_SRC)"
# POST /agents/find — rendezvous query, can take up to 30s
R=$(post_slow "/agents/find/$BID" '{}'); chk "$R" "ok" "POST /agents/find/:id"
proof "found=$(fld "$R" "found") addrs=$(echo "$R" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('addresses',[])))" 2>/dev/null)"
if [ -n "$AUSER_ID" ] && [ "$AUSER_ID" != "None" ] && [ "$AUSER_ID" != "null" ]; then
  R=$(get /users/$AUSER_ID/agents); chk "$R" "agents" "GET /users/:uid/agents"
  check_contains "GET /users/:uid/agents includes self" "$R" "$AID"
else
  skip "GET /users/:uid/agents" "no user identity configured for this daemon"
fi
R=$(post_slow /agents/connect "{\"agent_id\":\"$BID\"}")
outcome=$(fld "$R" "outcome")
if [[ "$outcome" == "Direct" || "$outcome" == "Coordinated" || "$outcome" == "AlreadyConnected" ]]; then
  ok "POST /agents/connect"
else
  fail "POST /agents/connect" "$R"
fi
proof "outcome=$outcome"
# GET /upgrade may return 500 if GitHub API is rate-limited; accept any response
UPG_ST=$(http_status /upgrade)
[[ "$UPG_ST" == "200" || "$UPG_ST" == "500" ]] && ok "GET /upgrade → HTTP $UPG_ST (endpoint wired)" || fail "GET /upgrade" "HTTP $UPG_ST"
proof "upgrade HTTP status=$UPG_ST (500=GitHub rate-limited, 200=success)"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [4] PRESENCE (6 endpoints / 7 checks + SSE) ━━"
R=$(get /presence); chk "$R" "agents" "GET /presence (alias)"
R=$(get /presence/online); chk "$R" "agents" "GET /presence/online"
proof "online=$(echo "$R" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('agents',[])))" 2>/dev/null) agents"
R=$(get /presence/foaf); chk "$R" "agents" "GET /presence/foaf"
R=$(get /presence/find/$BID); chk "$R" "ok" "GET /presence/find/:id"
proof "found=$(fld "$R" "found")"
R=$(get /presence/status/$BID); chk "$R" "ok" "GET /presence/status/:id"
# SSE: /presence/events — check 200 response
SSE_ST=$(curl -sI -m 3 -H "Authorization: Bearer $AT" "$AA/presence/events" 2>/dev/null | head -1)
[[ "$SSE_ST" == *"200"* ]] && ok "GET /presence/events → SSE 200" || fail "GET /presence/events" "$SSE_ST"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [5] CONTACTS & TRUST — Full Lifecycle (14 endpoints / 19 checks) ━━"
R=$(get /contacts); chk "$R" "contacts" "GET /contacts"
# Add Bob as Trusted
R=$(post /contacts "{\"agent_id\":\"$BID\",\"trust_level\":\"Trusted\"}"); chk "$R" "ok" "POST /contacts (add)"
R=$(get /contacts/$BID/revocations); chk "$R" "revocations" "GET /contacts/:id/revocations"
R=$(get /contacts/$BID/machines); chk "$R" "machines" "GET /contacts/:id/machines"
# Add machine
R=$(post /contacts/$BID/machines "{\"machine_id\":\"$BMI\"}"); chk "$R" "ok" "POST /contacts/:id/machines"
# PATCH trust
R=$(pat /contacts/$BID "{\"trust_level\":\"Known\"}"); chk "$R" "ok" "PATCH /contacts/:id"
# Pin/unpin machine
R=$(post /contacts/$BID/machines/$BMI/pin '{}'); chk "$R" "ok" "POST /contacts/:id/machines/:mid/pin"
R=$(del /contacts/$BID/machines/$BMI/pin); chk "$R" "ok" "DELETE /contacts/:id/machines/:mid/pin"
# DELETE machine (returns 204 — check status code)
STATUS=$(http_del /contacts/$BID/machines/$BMI)
[[ "$STATUS" == "204" || "$STATUS" == "200" ]] && ok "DELETE /contacts/:id/machines/:mid (HTTP $STATUS)" || fail "DELETE /contacts/:id/machines/:mid" "HTTP $STATUS"
# Quick trust (uses 'level' field)
R=$(post /contacts/trust "{\"agent_id\":\"$BID\",\"level\":\"trusted\"}"); chk "$R" "ok" "POST /contacts/trust (quick)"
# Evaluate
R=$(post /trust/evaluate "{\"agent_id\":\"$BID\",\"machine_id\":\"$BMI\"}"); chk "$R" "decision" "POST /trust/evaluate"
proof "decision=$(fld "$R" "decision")"
# DELETE contact — full lifecycle: add→trust→evaluate→delete→re-add
# Use a dummy contact so Bob stays in the contact store for later tests
DUMMY_CONTACT="b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
R=$(post /contacts "{\"agent_id\":\"$DUMMY_CONTACT\",\"trust_level\":\"Known\"}"); chk "$R" "ok" "POST /contacts (add dummy for delete)"
DEL_STATUS=$(http_del /contacts/$DUMMY_CONTACT)
[[ "$DEL_STATUS" == "204" || "$DEL_STATUS" == "200" ]] && ok "DELETE /contacts/:id (HTTP $DEL_STATUS)" || fail "DELETE /contacts/:id" "HTTP $DEL_STATUS"
proof "contact delete: added dummy → deleted → HTTP $DEL_STATUS"
# Revoke — use a dummy agent_id (not Bob's) since revocation is permanent and cannot be undone
DUMMY_AID="a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
R=$(post /contacts/$DUMMY_AID/revoke '{"reason":"audit test - dummy id"}'); chk "$R" "ok" "POST /contacts/:id/revoke"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [6] GOSSIP PUB/SUB + SSE (receive-side proof) ━━"
TOPIC="x0x.audit.$TS"
PUB_RAW="${PROOF_TOKEN}-gossip"
PUB_B64=$(echo -n "$PUB_RAW" | base64)
R=$(bpst /subscribe "{\"topic\":\"$TOPIC\"}"); chk "$R" "ok" "POST /subscribe"
SUB_ID=$(fld "$R" "subscription_id")
proof "subscription_id=$SUB_ID"
SSE_ST=$(curl -sI -m 3 -H "Authorization: Bearer $BT" "$BA/events" 2>/dev/null | head -1)
[[ "$SSE_ST" == *"200"* ]] && ok "GET /events → SSE 200" || fail "GET /events" "$SSE_ST"
EV_LOG=$(mktemp)
EV_PID=$(start_sse_capture "$BT" "$BA/events" "$EV_LOG" 12)
sleep 1
R=$(post /publish "{\"topic\":\"$TOPIC\",\"payload\":\"$PUB_B64\"}"); chk "$R" "ok" "POST /publish"
sleep 5
kill "$EV_PID" 2>/dev/null || true
wait "$EV_PID" 2>/dev/null || true
if grep -q "$PUB_B64" "$EV_LOG" 2>/dev/null; then
  ok "GET /events receives published payload"
else
  fail "GET /events receives published payload" "$(tr '\n' ' ' < "$EV_LOG" | head -c 220)"
fi
rm -f "$EV_LOG"
R=$(bdel /subscribe/$SUB_ID); chk "$R" "ok" "DELETE /subscribe/:id"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [7] DIRECT MESSAGING + SSE (receive-side proof) ━━"
SSE_ST=$(curl -sI -m 3 -H "Authorization: Bearer $BT" "$BA/direct/events" 2>/dev/null | head -1)
[[ "$SSE_ST" == *"200"* ]] && ok "GET /direct/events → SSE 200" || fail "GET /direct/events" "$SSE_ST"
R=$(post_slow /agents/connect "{\"agent_id\":\"$BID\"}")
outcome=$(fld "$R" "outcome")
if [[ "$outcome" == "Direct" || "$outcome" == "Coordinated" || "$outcome" == "AlreadyConnected" ]]; then ok "alice connects to bob for direct messaging"; else fail "alice connects to bob for direct messaging" "$R"; fi
DM_RAW="${PROOF_TOKEN}-direct-a2b"
DM_B64=$(echo -n "$DM_RAW" | base64)
DM_LOG=$(mktemp)
DM_PID=$(start_sse_capture "$BT" "$BA/direct/events" "$DM_LOG" 12)
sleep 1
R=$(post /direct/send "{\"agent_id\":\"$BID\",\"payload\":\"$DM_B64\"}"); chk "$R" "ok" "POST /direct/send"
sleep 5
kill "$DM_PID" 2>/dev/null || true
wait "$DM_PID" 2>/dev/null || true
if grep -q "$DM_B64" "$DM_LOG" 2>/dev/null && grep -q "$AID" "$DM_LOG" 2>/dev/null; then
  ok "GET /direct/events receives verified alice→bob message"
else
  fail "GET /direct/events receives verified alice→bob message" "$(tr '\n' ' ' < "$DM_LOG" | head -c 240)"
fi
rm -f "$DM_LOG"
R=$(get /direct/connections); chk "$R" "connections" "GET /direct/connections"
check_contains "GET /direct/connections includes bob" "$R" "$BID"
DM2_RAW="${PROOF_TOKEN}-direct-b2a"
DM2_B64=$(echo -n "$DM2_RAW" | base64)
DM2_LOG=$(mktemp)
DM2_PID=$(start_sse_capture "$AT" "$AA/direct/events" "$DM2_LOG" 12)
sleep 1
R=$(bpst /agents/connect "{\"agent_id\":\"$AID\"}")
outcome=$(fld "$R" "outcome")
if [[ "$outcome" == "Direct" || "$outcome" == "Coordinated" || "$outcome" == "AlreadyConnected" ]]; then ok "bob connects to alice for direct messaging"; else fail "bob connects to alice for direct messaging" "$R"; fi
R=$(bpst /direct/send "{\"agent_id\":\"$AID\",\"payload\":\"$DM2_B64\"}"); chk "$R" "ok" "POST /direct/send (bob→alice)"
sleep 5
kill "$DM2_PID" 2>/dev/null || true
wait "$DM2_PID" 2>/dev/null || true
if python3 - <<PY 2>/dev/null
import json
from pathlib import Path
raw = Path("$DM2_LOG").read_text()
for line in raw.splitlines():
    if not line.startswith('data: '):
        continue
    payload = json.loads(line[6:])
    if payload.get('sender') == "$BID" and payload.get('payload') == "$DM2_B64":
        raise SystemExit(0)
raise SystemExit(1)
PY
then
  ok "GET /direct/events receives bob→alice message"
else
  fail "GET /direct/events receives bob→alice message" "$(tr '\n' ' ' < "$DM2_LOG" | head -c 240)"
fi
rm -f "$DM2_LOG"
proof "direct tokens: $DM_RAW / $DM2_RAW"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [8] MLS ENCRYPTION — Post-Quantum ChaCha20 (8 endpoints / 11 checks) ━━"
R=$(post /mls/groups '{}'); chk "$R" "group_id" "POST /mls/groups (create encrypted group)"
MLS_ID=$(fld "$R" "group_id")
proof "mls_id=${MLS_ID:0:24}..."
R=$(get /mls/groups); chk "$R" "groups" "GET /mls/groups"
R=$(get /mls/groups/$MLS_ID); chk "$R" "group_id" "GET /mls/groups/:id"
R=$(post /mls/groups/$MLS_ID/members "{\"agent_id\":\"$BID\"}"); chk "$R" "ok" "POST /mls/groups/:id/members"
PT="proof-mls-$TS"
PT_B64=$(echo -n "$PT" | base64)
R=$(post /mls/groups/$MLS_ID/encrypt "{\"payload\":\"$PT_B64\"}"); chk "$R" "ciphertext" "POST /mls/groups/:id/encrypt"
CT=$(fld "$R" "ciphertext"); EPOCH=$(fld "$R" "epoch")
proof "ct_len=${#CT} epoch=$EPOCH"
R=$(post /mls/groups/$MLS_ID/decrypt "{\"ciphertext\":\"$CT\",\"epoch\":$EPOCH}"); chk "$R" "payload" "POST /mls/groups/:id/decrypt"
DEC=$(fld "$R" "payload")
[[ "$DEC" == "$PT_B64" ]] && ok "  MLS encrypt→decrypt round-trip [PROOF: plaintext matched exactly]" || fail "MLS round-trip" "sent=$PT_B64 got=$DEC"
proof "decrypt='$(echo "$DEC" | base64 -d 2>/dev/null)'"
R=$(post /mls/groups/$MLS_ID/welcome "{\"agent_id\":\"$BID\"}"); chk "$R" "ok" "POST /mls/groups/:id/welcome"
R=$(del /mls/groups/$MLS_ID/members/$BID); chk "$R" "ok" "DELETE /mls/groups/:id/members/:aid"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [9] NAMED GROUPS / SPACES (7 endpoints / 10 checks) ━━"
R=$(post /groups "{\"name\":\"audit-$TS\"}"); chk "$R" "group_id" "POST /groups (create)"
GRP_ID=$(fld "$R" "group_id")
proof "group_id=${GRP_ID:0:24}... chat=$(fld "$R" "chat_topic" | head -c 40)"
R=$(get /groups); chk "$R" "groups" "GET /groups"
R=$(get /groups/$GRP_ID); chk "$R" "group_id" "GET /groups/:id"
R=$(post /groups/$GRP_ID/invite '{"expiry_secs":86400}'); chk "$R" "invite_link" "POST /groups/:id/invite"
INVITE=$(fld "$R" "invite_link")
[[ "$INVITE" == *"x0x://invite/"* ]] && ok "  invite format: x0x://invite/" || fail "invite format" "$INVITE"
proof "invite=${INVITE:0:60}..."
R=$(bpst /groups/join "{\"invite\":\"$INVITE\"}"); chk "$R" "ok" "POST /groups/join (bob joins)"
proof "bob joined: $(fld "$R" "chat_topic" | head -c 40)"
R=$(post /groups/$GRP_ID/members "{\"agent_id\":\"$BID\",\"display_name\":\"AuditBobSpace\"}"); chk "$R" "member_count" "POST /groups/:id/members"
R=$(get /groups/$GRP_ID/members); chk "$R" "members" "GET /groups/:id/members"
check_contains "named-group members include bob" "$R" "$BID"
check_contains "named-group members include bob display name" "$R" "AuditBobSpace"
R=$(del /groups/$GRP_ID/members/$BID); chk "$R" "member_count" "DELETE /groups/:id/members/:agent_id"
R=$(get /groups/$GRP_ID/members); chk "$R" "members" "GET /groups/:id/members after remove"
if echo "$R" | grep -q "$BID"; then fail "named-group members cleared bob" "$R"; else ok "named-group members cleared bob"; fi
for _ in $(seq 1 20); do
  BR=$(bget /groups/$GRP_ID)
  if echo "$BR" | grep -q 'group not found\|curl_fail'; then
    break
  fi
  sleep 1
done
if echo "$BR" | grep -q 'group not found\|curl_fail'; then ok "named-group removal propagated to bob"; else fail "named-group removal propagated to bob" "$BR"; fi
R=$(put /groups/$GRP_ID/display-name '{"name":"AuditSpace"}'); chk "$R" "ok" "PUT /groups/:id/display-name"
proof "display_name=$(fld "$R" "display_name")"
R=$(del /groups/$GRP_ID); chk "$R" "ok" "DELETE /groups/:id (leave)"

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
STABLE_GID_PRS=$(stable_group_id_from_local "$GID_PRS")
proof "public_request_secure stable_group_id=${STABLE_GID_PRS:0:24}..."

# [9b-3] Alice's own discover shows her group by stable public id
R=$(get /groups/discover)
COUNT=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
target='$STABLE_GID_PRS'
print(sum(1 for g in d.get('groups',[]) if g.get('group_id')==target))" 2>/dev/null || echo "0")
[[ "$COUNT" =~ ^[0-9]+$ ]] && [ "$COUNT" -ge 1 ] && ok "owner sees public group in /groups/discover" || fail "owner sees public group in /groups/discover" "want>=1 got='$COUNT'"

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
target='$STABLE_GID_PRS'
print(sum(1 for g in d.get('groups',[]) if g.get('group_id')==target))" 2>/dev/null || echo "0")
chkv "$COUNT" "1" "bob sees imported group in discover"

# [9b-7] Bob submits join request via his imported stable-id stub
R=$(bpst /groups/$STABLE_GID_PRS/requests '{"message":"Please let me join"}')
chk "$R" "request_id" "POST /groups/:id/requests (bob submits)"
BOB_REQ_ID=$(fld "$R" "request_id")
proof "bob request_id=${BOB_REQ_ID:0:16}..."

# [9b-8] Wait for gossip propagation, Alice sees pending request (poll up to 30s)
R=""
PENDING=0
for _ in $(seq 1 30); do
  R=$(get /groups/$GID_PRS/requests)
  PENDING=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for r in d.get('requests',[]) if r.get('status')=='pending' and r.get('requester_agent_id')=='$BID'))" 2>/dev/null || echo "0")
  [ "$PENDING" = "1" ] && break
  sleep 1
done
chk "$R" "requests" "GET /groups/:id/requests (alice sees)"
chkv "$PENDING" "1" "alice sees bob's pending request"

# [9b-9] Alice approves Bob's request
R=$(post /groups/$GID_PRS/requests/$BOB_REQ_ID/approve '{}')
chk "$R" "ok" "POST /groups/:id/requests/:rid/approve"

# [9b-10] Bob is now an active member
BOB_ACTIVE=no
for _ in $(seq 1 20); do
  R=$(get /groups/$GID_PRS/members)
  BOB_ACTIVE=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for m in d.get('members',[]):
    if m.get('agent_id')=='$BID' and m.get('state','active')=='active':
        print('yes'); break
else:
    print('no')" 2>/dev/null)
  [ "$BOB_ACTIVE" = "yes" ] && break
  sleep 1
done
chkv "$BOB_ACTIVE" "yes" "bob is now active member after approval"

# [9b-11] Charlie submits request, Alice rejects
# Charlie also needs to import the card to have a local stub.
R=$(cpst /groups/cards/import "$CARD_JSON")
chk "$R" "ok" "charlie imports card"
R=$(cpst /groups/$STABLE_GID_PRS/requests '{"message":"Also me"}')
chk "$R" "request_id" "POST /groups/:id/requests (charlie submits)"
CHARLIE_REQ_ID=$(fld "$R" "request_id")

# Wait for Alice to observe Charlie's pending request before rejecting.
CHARLIE_PENDING=0
ALICE_CHARLIE_REQ_ID=""
for _ in $(seq 1 30); do
  R=$(get /groups/$GID_PRS/requests)
  CHARLIE_PENDING=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for r in d.get('requests',[]) if r.get('status')=='pending' and r.get('requester_agent_id')=='$CID'))" 2>/dev/null || echo "0")
  ALICE_CHARLIE_REQ_ID=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for r in d.get('requests',[]):
    if r.get('status')=='pending' and r.get('requester_agent_id')=='$CID':
        print(r.get('request_id',''))
        break
" 2>/dev/null || echo "")
  [ "$CHARLIE_PENDING" = "1" ] && [ -n "$ALICE_CHARLIE_REQ_ID" ] && break
  sleep 1
done
R=$(post /groups/$GID_PRS/requests/${ALICE_CHARLIE_REQ_ID:-$CHARLIE_REQ_ID}/reject '{}')
chk "$R" "ok" "POST /groups/:id/requests/:rid/reject"

# [9b-12] Charlie is NOT a member
R=$(get /groups/$GID_PRS/members)
CHARLIE_MEMBER=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for m in d.get('members',[]) if m.get('agent_id')=='$CID' and m.get('state','active')=='active'))" 2>/dev/null || echo "err")
chkv "$CHARLIE_MEMBER" "0" "charlie NOT a member after rejection"

# [9b-13] Cancel own request path — Charlie creates a new one, cancels it
R=$(cpst /groups/$STABLE_GID_PRS/requests '{}')
CREQ2=$(fld "$R" "request_id")
if [ -n "$CREQ2" ]; then
  R=$(curl -sf -m 10 -X DELETE -H "Authorization: Bearer $CT" "$CA/groups/$STABLE_GID_PRS/requests/$CREQ2" 2>/dev/null || echo '{"error":"curl_fail"}')
  chk "$R" "ok" "DELETE /groups/:id/requests/:rid (cancel own)"
fi

# Cleanup
R=$(del /groups/$GID_PRS); chk "$R" "ok" "DELETE /groups/:id cleanup public_request_secure"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [9c] NAMED GROUPS — Authorization Negative Paths ━━"

# [9c-1] Alice creates a public_request_secure group so card flow works
R=$(post /groups "{\"name\":\"authz-$TS\",\"preset\":\"public_request_secure\"}")
GID_AZ=$(fld "$R" "group_id")
chk "$R" "group_id" "POST /groups for authz test"
STABLE_GID_AZ=$(stable_group_id_from_local "$GID_AZ")
proof "authz stable_group_id=${STABLE_GID_AZ:0:24}..."

# [9c-1b] Non-member Bob PATCH policy should be denied (no local card yet)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PATCH -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{"preset":"public_open"}' "$BA/groups/$GID_AZ/policy" 2>/dev/null)
[[ "$STATUS" == "403" || "$STATUS" == "404" ]] && ok "non-member PATCH policy denied ($STATUS)" || fail "non-member PATCH policy denied" "got $STATUS"

# [9c-2] Both Bob and Charlie import the card so they have local stubs
AUTHZ_CARD=$(get /groups/cards/$GID_AZ)
R=$(bpst /groups/cards/import "$AUTHZ_CARD"); chk "$R" "ok" "bob imports authz card"
R=$(cpst /groups/cards/import "$AUTHZ_CARD"); chk "$R" "ok" "charlie imports authz card"

# [9c-3] After import Bob has a stable-id stub but is NOT a member — policy PATCH still denied
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PATCH -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{"preset":"public_open"}' "$BA/groups/$STABLE_GID_AZ/policy" 2>/dev/null)
[[ "$STATUS" == "403" ]] && ok "non-member-after-import PATCH policy → 403" || fail "non-member-after-import PATCH policy denied" "got $STATUS"

# [9c-4] Alice adds Bob as Member
R=$(post /groups/$GID_AZ/members "{\"agent_id\":\"$BID\"}")
chk "$R" "ok" "alice adds bob as member"
sleep 2

# [9c-5] Bob (Member on his own daemon via card import + self-added via metadata) cannot PATCH policy
# Note: Bob's stub still shows Alice as owner only; Bob will not be in his local v2 roster.
# So "member PATCH denied" is correct — 403 from role check, or 404 if stub has no bob entry.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PATCH -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{"preset":"public_open"}' "$BA/groups/$STABLE_GID_AZ/policy" 2>/dev/null)
[[ "$STATUS" == "403" ]] && ok "member PATCH policy denied → 403 (owner-only)" || fail "member PATCH policy denied" "got $STATUS"

# [9c-6] Charlie submits a join request on his own daemon (he has the stable-id stub)
R=$(cpst /groups/$STABLE_GID_AZ/requests '{"message":"authz test"}')
chk "$R" "request_id" "charlie submits join request"
CREQ_A=$(fld "$R" "request_id")
sleep 3  # let gossip propagate the JoinRequestCreated event

# [9c-7] Alice sees charlie's pending request in her daemon
R=$(get /groups/$GID_AZ/requests)
PENDING_C=$(echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for r in d.get('requests',[]) if r.get('status')=='pending' and r.get('requester_agent_id')=='$CID'))" 2>/dev/null || echo "0")
chkv "$PENDING_C" "1" "alice sees charlie's request via gossip"

# [9c-8] Bob (plain Member, not Admin) tries to approve on his own daemon — denied.
# Note: Bob's daemon may not yet have charlie's request locally. 403/404 both acceptable.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{}' "$BA/groups/$STABLE_GID_AZ/requests/$CREQ_A/approve" 2>/dev/null)
[[ "$STATUS" == "403" || "$STATUS" == "404" ]] && ok "member cannot approve request ($STATUS)" || fail "member cannot approve request" "got $STATUS"

# [9c-9] Bob (Member) cannot remove Alice (Owner) on his own daemon
# 400 is returned by the existing creator-protection guard; 403 is the role-based denial.
# Both represent "owner removal via member API is not allowed".
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X DELETE -H "Authorization: Bearer $BT" "$BA/groups/$STABLE_GID_AZ/members/$AID" 2>/dev/null)
[[ "$STATUS" == "403" || "$STATUS" == "400" || "$STATUS" == "404" ]] && ok "member cannot remove owner ($STATUS)" || fail "member cannot remove owner" "got $STATUS"

# [9c-10] Alice promotes Bob to Admin (on Alice's daemon where state is authoritative)
R=$(pat /groups/$GID_AZ/members/$BID/role '{"role":"admin"}')
chk "$R" "ok" "PATCH /groups/:id/members/:id/role (promote bob to admin)"

# [9c-11] Alice approves charlie's request (on her own daemon)
R=$(post /groups/$GID_AZ/requests/$CREQ_A/approve '{}')
chk "$R" "ok" "alice approves charlie's request"

# [9c-12] Alice bans Bob — banned member cannot submit new request
R=$(post /groups/$GID_AZ/ban/$BID '{}')
chk "$R" "ok" "alice bans bob"
# Poll until bob's daemon has seen the ban event (up to 20s)
STATUS=0
for _ in $(seq 1 20); do
  sleep 1
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -d '{"message":"try again"}' "$BA/groups/$STABLE_GID_AZ/requests" 2>/dev/null)
  [[ "$STATUS" == "403" || "$STATUS" == "409" ]] && break
done
[[ "$STATUS" == "403" || "$STATUS" == "409" ]] && ok "banned member cannot create join request ($STATUS)" || fail "banned member cannot request" "got $STATUS"

# [9c-13] Unban
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
# Poll up to 20s for gossip deletion to propagate
BR=""
for _ in $(seq 1 20); do
  sleep 1
  BR=$(bget /groups/$GID_BAN 2>/dev/null || echo '{"error":"curl_fail"}')
  if echo "$BR" | grep -q 'group not found\|curl_fail\|"error"'; then
    break
  fi
done
if echo "$BR" | grep -q 'group not found\|curl_fail\|"error"'; then
  ok "delete convergence: bob's view cleared"
else
  fail "delete convergence: bob's view cleared" "$BR"
fi

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [10] TASK LISTS / KANBAN CRDT (5 endpoints / 8 checks) ━━"
TNAME="audit-$TS"
R=$(post /task-lists "{\"name\":\"$TNAME\",\"topic\":\"x0x.tasks.$TS\"}"); chk "$R" "id" "POST /task-lists (create)"
TL_ID=$(fld "$R" "id")
proof "task-list id=$TL_ID"
R=$(get /task-lists); chk "$R" "task_lists" "GET /task-lists"
TTITLE="proof-task-$TS"
R=$(post /task-lists/$TL_ID/tasks "{\"title\":\"$TTITLE\",\"description\":\"audit-$TS\"}"); chk "$R" "task_id" "POST /task-lists/:id/tasks"
TASK_ID=$(fld "$R" "task_id")
proof "task_id=${TASK_ID:0:24}..."
R=$(get /task-lists/$TL_ID/tasks); chk "$R" "tasks" "GET /task-lists/:id/tasks"
TASK_TITLE=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['tasks'][0]['title'] if d.get('tasks') else '')" 2>/dev/null)
[[ "$TASK_TITLE" == "$TTITLE" ]] && ok "  task title round-trip [PROOF: '$TTITLE']" || fail "task title" "got='$TASK_TITLE'"
R=$(pat /task-lists/$TL_ID/tasks/$TASK_ID "{\"action\":\"claim\",\"agent_id\":\"$AID\"}"); chk "$R" "ok" "PATCH /task-lists/:id/tasks/:tid (claim)"
R=$(pat /task-lists/$TL_ID/tasks/$TASK_ID "{\"action\":\"complete\",\"agent_id\":\"$AID\"}"); chk "$R" "ok" "PATCH /task-lists/:id/tasks/:tid (complete)"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [11] KV STORE CRDT (7 endpoints / 9 checks) ━━"
R=$(post /stores "{\"name\":\"audit-kv-$TS\",\"topic\":\"x0x.kv.$TS\"}"); chk "$R" "id" "POST /stores (create)"
KV_ID=$(fld "$R" "id")
proof "store id=$KV_ID"
R=$(get /stores); chk "$R" "stores" "GET /stores"
KV_VAL="proof-kv-$TS"
KV_B64=$(echo -n "$KV_VAL" | base64)
R=$(put "/stores/$KV_ID/proof-key" "{\"value\":\"$KV_B64\",\"content_type\":\"text/plain\"}"); chk "$R" "ok" "PUT /stores/:id/:key"
R=$(get "/stores/$KV_ID/keys"); chk "$R" "keys" "GET /stores/:id/keys"
R=$(get "/stores/$KV_ID/proof-key"); chk "$R" "value" "GET /stores/:id/:key"
GOT=$(fld "$R" "value")
[[ "$GOT" == "$KV_B64" ]] && ok "  KV round-trip [PROOF: '$KV_VAL' exact match]" || fail "KV round-trip" "sent=$KV_B64 got=$GOT"
R=$(del /stores/$KV_ID/proof-key); chk "$R" "ok" "DELETE /stores/:id/:key"
R=$(post /stores/$KV_ID/join '{}'); chk "$R" "ok" "POST /stores/:id/join"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [12] FILE TRANSFERS — Full Lifecycle (real bytes + accept/reject) ━━"
R=$(post_slow /agents/connect "{\"agent_id\":\"$BID\"}")
outcome=$(fld "$R" "outcome")
[[ "$outcome" == "Direct" || "$outcome" == "Coordinated" || "$outcome" == "AlreadyConnected" ]] && ok "file-transfer reconnect alice→bob" || fail "file-transfer reconnect alice→bob" "$R"
R=$(bpst /agents/connect "{\"agent_id\":\"$AID\"}")
outcome=$(fld "$R" "outcome")
[[ "$outcome" == "Direct" || "$outcome" == "Coordinated" || "$outcome" == "AlreadyConnected" ]] && ok "file-transfer reconnect bob→alice" || fail "file-transfer reconnect bob→alice" "$R"
SEND_PATH="$ADIR/proof-file.txt"
printf '%s\n' "${PROOF_TOKEN}-file-payload" > "$SEND_PATH"
SHA=$(shasum -a 256 "$SEND_PATH" | awk '{print $1}')
SIZE=$(wc -c < "$SEND_PATH" | tr -d ' ')
R=$(post /files/send "{\"agent_id\":\"$BID\",\"filename\":\"proof-file.txt\",\"size\":$SIZE,\"sha256\":\"$SHA\",\"path\":\"$SEND_PATH\"}")
chk "$R" "transfer_id" "POST /files/send"
sleep 2
TFR_ID=$(fld "$R" "transfer_id")
proof "transfer_id=$TFR_ID sha256=$SHA size=$SIZE"
R=$(get /files/transfers); chk "$R" "transfers" "GET /files/transfers"
R=$(get /files/transfers/$TFR_ID); chk "$R" "transfer" "GET /files/transfers/:id"
B_TFR=""
for _ in $(seq 1 40); do
  BR=$(bget /files/transfers)
  B_TFR=$(echo "$BR" | python3 -c "import sys,json;ts=json.load(sys.stdin).get('transfers',[]);print(next((t['transfer_id'] for t in ts if t.get('transfer_id')=='$TFR_ID'),''))" 2>/dev/null || echo "")
  [ -n "$B_TFR" ] && break
  sleep 1
done
[ -n "$B_TFR" ] && ok "recipient sees pending incoming transfer" || fail "recipient sees pending incoming transfer" "$BR"
R=$(bpst /files/accept/$TFR_ID '{}'); chk "$R" "ok" "POST /files/accept/:id"
for _ in $(seq 1 40); do
  AR=$(get /files/transfers/$TFR_ID)
  BR=$(bget /files/transfers/$TFR_ID)
  A_STATUS=$(python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('status',''))" <<<"$AR" 2>/dev/null || echo "")
  B_STATUS=$(python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('status',''))" <<<"$BR" 2>/dev/null || echo "")
  if [ "$A_STATUS" = "Complete" ] && [ "$B_STATUS" = "Complete" ]; then
    break
  fi
  sleep 1
done
[ "$A_STATUS" = "Complete" ] && ok "sender transfer reaches Complete" || fail "sender transfer reaches Complete" "$AR"
[ "$B_STATUS" = "Complete" ] && ok "receiver transfer reaches Complete" || fail "receiver transfer reaches Complete" "$BR"
OUTPUT_PATH=$(python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('output_path',''))" <<<"$BR" 2>/dev/null || echo "")
RECV_SHA=$(shasum -a 256 "$OUTPUT_PATH" | awk '{print $1}' 2>/dev/null || echo "")
RECV_BODY=$(cat "$OUTPUT_PATH" 2>/dev/null || echo "")
[[ "$RECV_SHA" == "$SHA" ]] && ok "received file sha256 matches" || fail "received file sha256 matches" "got=$RECV_SHA want=$SHA path=$OUTPUT_PATH"
check_contains "received file body contains proof token" "$RECV_BODY" "$PROOF_TOKEN"

REJECT_PATH="$ADIR/reject-file.txt"
printf '%s\n' "${PROOF_TOKEN}-reject-file" > "$REJECT_PATH"
REJECT_SHA=$(shasum -a 256 "$REJECT_PATH" | awk '{print $1}')
REJECT_SIZE=$(wc -c < "$REJECT_PATH" | tr -d ' ')
R=$(post /files/send "{\"agent_id\":\"$BID\",\"filename\":\"reject-file.txt\",\"size\":$REJECT_SIZE,\"sha256\":\"$REJECT_SHA\",\"path\":\"$REJECT_PATH\"}")
chk "$R" "transfer_id" "POST /files/send (reject path)"
REJECT_ID=$(fld "$R" "transfer_id")
for _ in $(seq 1 40); do
  BR=$(bget /files/transfers)
  B_REJECT=$(echo "$BR" | python3 -c "import sys,json;ts=json.load(sys.stdin).get('transfers',[]);print(next((t['transfer_id'] for t in ts if t.get('transfer_id')=='$REJECT_ID'),''))" 2>/dev/null || echo "")
  [ -n "$B_REJECT" ] && break
  sleep 1
done
[ -n "$B_REJECT" ] && ok "recipient sees second pending transfer" || fail "recipient sees second pending transfer" "$BR"
R=$(bpst /files/reject/$REJECT_ID '{"reason":"full audit reject proof"}'); chk "$R" "ok" "POST /files/reject/:id"
for _ in $(seq 1 40); do
  AR=$(get /files/transfers/$REJECT_ID)
  A_STATUS=$(python3 -c "import sys,json;print(json.load(sys.stdin).get('transfer',{}).get('status',''))" <<<"$AR" 2>/dev/null || echo "")
  [ "$A_STATUS" = "Rejected" ] && break
  sleep 1
done
[ "$A_STATUS" = "Rejected" ] && ok "sender sees rejected transfer" || fail "sender sees rejected transfer" "$AR"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [13] WEBSOCKET (real WS interaction) ━━"
WS_HOLD_LOG=$(mktemp)
node tests/helpers/ws_probe.mjs hold /ws "$AA" "$AT" 5000 > "$WS_HOLD_LOG" &
WS_HOLD_PID=$!
sleep 1
WS=$(cat "$WS_HOLD_LOG" 2>/dev/null || echo '{}')
chk "$WS" "connected" "GET /ws → real WebSocket connected frame"
WS_AID=$(echo "$WS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('connected',{}).get('agent_id',''))" 2>/dev/null || echo "")
[[ "$WS_AID" == "$AID" ]] && ok "  /ws session agent_id matches REST [PROOF: exact match]" || fail "/ws agent_id" "ws='$WS_AID' rest='$AID'"
R=$(get /ws/sessions); chk "$R" "sessions" "GET /ws/sessions"
SESS_COUNT=$(json_len "$R" "sessions")
[ "$SESS_COUNT" -ge 1 ] && ok "GET /ws/sessions sees active session" || fail "GET /ws/sessions sees active session" "$R"
wait "$WS_HOLD_PID" 2>/dev/null || true
rm -f "$WS_HOLD_LOG"

WS_TOPIC="ws-proof-$TS"
WS_MSG="${PROOF_TOKEN}-ws-pubsub"
WS_PUB=$(node tests/helpers/ws_probe.mjs pubsub "$AA" "$AT" "$WS_TOPIC" "$WS_MSG" 2>/dev/null || echo '{"error":"ws_fail"}')
chk "$WS_PUB" "received" "GET /ws pubsub round-trip"
check_contains "GET /ws pubsub payload matched" "$WS_PUB" "$(printf '%s' "$WS_MSG" | base64)"

WS_D=$(ws_connect /ws/direct)
[[ "$WS_D" == *"connected"* && "$WS_D" == *"session_id"* ]] && ok "GET /ws/direct → connected frame via upgrade probe" || fail "GET /ws/direct upgrade probe" "$WS_D"
R=$(post_slow /agents/connect "{\"agent_id\":\"$BID\"}") >/dev/null
R=$(bpst /agents/connect "{\"agent_id\":\"$AID\"}") >/dev/null
WS_DIRECT_MSG="${PROOF_TOKEN}-ws-direct"
WS_DIRECT_LOG=$(mktemp)
node tests/helpers/ws_probe.mjs direct-receive "$BA" "$BT" 20000 > "$WS_DIRECT_LOG" &
WS_DIRECT_PID=$!
sleep 3
WS_SEND=$(node tests/helpers/ws_probe.mjs send-direct "$AA" "$AT" "$BID" "$WS_DIRECT_MSG" 2>/dev/null || echo '{"error":"ws_fail"}')
chk "$WS_SEND" "pong" "GET /ws send_direct command"
wait "$WS_DIRECT_PID" 2>/dev/null || true
chk "$(cat "$WS_DIRECT_LOG" 2>/dev/null || echo '{}')" "received" "GET /ws/direct receives direct_message frame"
check_contains "GET /ws/direct payload matched" "$(cat "$WS_DIRECT_LOG" 2>/dev/null || echo '{}')" "$(printf '%s' "$WS_DIRECT_MSG" | base64)"
rm -f "$WS_DIRECT_LOG"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [13b] GUI INTERACTION (real browser proof) ━━"
R=$(post_slow /agents/connect "{\"agent_id\":\"$BID\"}") >/dev/null
R=$(bpst /agents/connect "{\"agent_id\":\"$AID\"}") >/dev/null
GUI_DM_RAW="${PROOF_TOKEN}-gui-direct"
GUI_DM_B64=$(printf '%s' "$GUI_DM_RAW" | base64)
GUI_EVT=$(mktemp)
GUI_EVT_PID=$(start_sse_capture "$BT" "$BA/direct/events" "$GUI_EVT" 15)
sleep 1
GUI_PROOF=$(node tests/helpers/gui_proof.mjs send-dm "$AA" "$BLINK" "$BID" "$GUI_DM_RAW" 2>/tmp/x0x-gui-proof.log || echo '{"error":"gui_fail"}')
chk "$GUI_PROOF" "messageVisible" "GUI sends direct message via real browser"
sleep 5
kill "$GUI_EVT_PID" 2>/dev/null || true
wait "$GUI_EVT_PID" 2>/dev/null || true
if python3 - <<PY 2>/dev/null
import json, base64
from pathlib import Path
raw = Path("$GUI_EVT").read_text()
for line in raw.splitlines():
    if not line.startswith('data: '):
        continue
    payload = json.loads(line[6:])
    if payload.get('sender') != "$AID":
        continue
    try:
        msg = json.loads(base64.b64decode(payload.get('payload','')).decode())
    except Exception:
        continue
    if msg.get('text') == "$GUI_DM_RAW":
        raise SystemExit(0)
raise SystemExit(1)
PY
then
  ok "GUI-driven direct send reached bob"
else
  fail "GUI-driven direct send reached bob" "$(tr '\n' ' ' < "$GUI_EVT" | head -c 220)"
fi
rm -f "$GUI_EVT"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [14] CLI COMMANDS — expanded coverage ━━"
export X0X_API_TOKEN="$AT"
CLI="$X0X --api $AA --json"
CLIB="X0X_API_TOKEN=$BT $X0X --api $BA --json"

cli_chk() { local cmd="$1" field="$2"
  R=$($CLI $cmd 2>/dev/null || echo '{"error":"cli_fail"}')
  if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert '$field' in d" 2>/dev/null; then ok "x0x $cmd → $field"; else fail "x0x $cmd" "$R"; fi; }
cli_chk_b() { local cmd="$1" field="$2"
  R=$(eval "$CLIB $cmd" 2>/dev/null || echo '{"error":"cli_fail"}')
  if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert '$field' in d" 2>/dev/null; then ok "bob x0x $cmd → $field"; else fail "bob x0x $cmd" "$R"; fi; }
cli_has() { local cmd="$1" want="$2"
  R=$($CLI $cmd 2>/dev/null || echo "FAIL")
  [[ "$R" == *"$want"* ]] && ok "x0x $cmd → '$want'" || fail "x0x $cmd" "${R:0:80}"; }

# Health / Status
cli_chk "health" "ok"
cli_chk "status" "ok"
# Identity
cli_chk "agent" "agent_id"
cli_chk "agent card" "link"
cli_chk "agent user-id" "ok"
cli_chk "agent introduction" "agent_id"
R=$($CLI agent import "$BLINK" 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x agent import → ok"; else fail "x0x agent import" "$R"; fi
cli_chk "announce" "ok"
# Network
cli_chk "network status" "ok"
cli_chk "network cache" "ok"
cli_chk "peers" "peers"
# Presence
cli_chk "presence online" "agents"
cli_chk "presence foaf" "agents"
cli_chk "presence find $BID" "ok"
cli_chk "presence status $BID" "ok"
# Contacts & trust
cli_chk "contacts list" "contacts"
cli_chk "contacts add --trust trusted $BID" "ok"
R=$($CLI contacts update $BID --trust known 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x contacts update $BID → ok"; else fail "x0x contacts update $BID" "$R"; fi
R=$($CLI contacts revoke $DUMMY_AID --reason 'cli revoke proof' 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x contacts revoke dummy → ok"; else fail "x0x contacts revoke dummy" "$R"; fi
R=$($CLI contacts revocations $DUMMY_AID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'revocations' in d" 2>/dev/null; then ok "x0x contacts revocations dummy → revocations"; else fail "x0x contacts revocations dummy" "$R"; fi
R=$($CLI contacts add --trust known $DUMMY_CONTACT 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x contacts add dummy → ok"; else fail "x0x contacts add dummy" "$R"; fi
R=$($CLI contacts remove $DUMMY_CONTACT 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d or d=={}" 2>/dev/null; then ok "x0x contacts remove dummy → ok"; else fail "x0x contacts remove dummy" "$R"; fi
R=$($CLI trust set $BID trusted 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x trust set $BID trusted → ok"; else fail "x0x trust set $BID trusted" "$R"; fi
cli_chk "trust evaluate $BID $BMI" "decision"
# Machines
R=$($CLI machines list $BID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'machines' in d" 2>/dev/null; then ok "x0x machines list $BID → machines"; else fail "x0x machines list $BID" "$R"; fi
CLI_FAKE_MID="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
R=$($CLI machines add $BID $CLI_FAKE_MID --pin 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x machines add/pin fake machine → ok"; else fail "x0x machines add/pin fake machine" "$R"; fi
R=$($CLI machines unpin $BID $CLI_FAKE_MID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d or d=={}" 2>/dev/null; then ok "x0x machines unpin fake machine → ok"; else fail "x0x machines unpin fake machine" "$R"; fi
R=$($CLI machines remove $BID $CLI_FAKE_MID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d or d=={}" 2>/dev/null; then ok "x0x machines remove fake machine → ok"; else fail "x0x machines remove fake machine" "$R"; fi
# Agents — use DISC_ID (first non-self discovered peer) for get/reachability (works even if Bob not yet visible)
cli_chk "agents list" "agents"
cli_chk "agents get $DISC_ID" "agent"
cli_chk "agents reachability $DISC_ID" "ok"
if [ -n "$AUSER_ID" ] && [ "$AUSER_ID" != "None" ] && [ "$AUSER_ID" != "null" ]; then
  R=$($CLI agents by-user $AUSER_ID 2>/dev/null || echo '{"error":"cli_fail"}')
  if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'agents' in d" 2>/dev/null; then ok "x0x agents by-user $AUSER_ID → agents"; else fail "x0x agents by-user $AUSER_ID" "$R"; fi
else
  skip "x0x agents by-user" "no user identity configured"
fi
# agents find does a slow rendezvous query — use a separate check with longer timeout
R=$($X0X --api $AA --json agents find $BID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x agents find $BID → ok"; else fail "x0x agents find $BID" "$R"; fi
# Direct
R=$($CLI direct connect $BID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'outcome' in d or 'ok' in d" 2>/dev/null; then ok "x0x direct connect $BID → outcome"; else fail "x0x direct connect $BID" "$R"; fi
R=$($CLI direct send $BID cli-direct-proof 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x direct send $BID → ok"; else fail "x0x direct send $BID" "$R"; fi
cli_chk "direct connections" "connections"
# MLS groups
cli_chk "groups list" "groups"
cli_chk "groups create" "group_id"
R=$($CLI groups get $MLS_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'group_id' in d or 'members' in d" 2>/dev/null; then ok "x0x groups get $MLS_ID → group data"; else fail "x0x groups get $MLS_ID" "$R"; fi
R=$($CLI groups add-member $MLS_ID $BID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x groups add-member → ok"; else fail "x0x groups add-member" "$R"; fi
R=$($CLI groups welcome $MLS_ID $BID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x groups welcome → ok"; else fail "x0x groups welcome" "$R"; fi
R=$($CLI groups remove-member $MLS_ID $BID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x groups remove-member → ok"; else fail "x0x groups remove-member" "$R"; fi
# Named groups (spaces)
cli_chk "group list" "groups"
CLI_GROUP_CREATE=$($CLI group create CliAuditSpace --description cli-space 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$CLI_GROUP_CREATE" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'group_id' in d" 2>/dev/null; then ok "x0x group create CliAuditSpace → group_id"; else fail "x0x group create CliAuditSpace" "$CLI_GROUP_CREATE"; fi
CLI_GROUP_ID=$(echo "$CLI_GROUP_CREATE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('group_id',''))" 2>/dev/null || echo '')
R=$($CLI group info $CLI_GROUP_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'group_id' in d" 2>/dev/null; then ok "x0x group info $CLI_GROUP_ID → group_id"; else fail "x0x group info $CLI_GROUP_ID" "$R"; fi
R=$($CLI group add-member $CLI_GROUP_ID $BID --display-name CliBob 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'member_count' in d" 2>/dev/null; then ok "x0x group add-member $CLI_GROUP_ID $BID → member_count"; else fail "x0x group add-member $CLI_GROUP_ID $BID" "$R"; fi
R=$($CLI group members $CLI_GROUP_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'members' in d" 2>/dev/null; then ok "x0x group members $CLI_GROUP_ID → members"; else fail "x0x group members $CLI_GROUP_ID" "$R"; fi
R=$($CLI group remove-member $CLI_GROUP_ID $BID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'member_count' in d" 2>/dev/null; then ok "x0x group remove-member $CLI_GROUP_ID $BID → member_count"; else fail "x0x group remove-member $CLI_GROUP_ID $BID" "$R"; fi
CLI_GROUP_INVITE=$($CLI group invite $CLI_GROUP_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$CLI_GROUP_INVITE" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'invite_link' in d" 2>/dev/null; then ok "x0x group invite $CLI_GROUP_ID → invite_link"; else fail "x0x group invite $CLI_GROUP_ID" "$CLI_GROUP_INVITE"; fi
CLI_GROUP_INVITE_LINK=$(echo "$CLI_GROUP_INVITE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('invite_link',''))" 2>/dev/null || echo '')
R=$(eval "$CLIB group join '$CLI_GROUP_INVITE_LINK' --display-name BobCLI" 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "bob x0x group join invite → ok"; else fail "bob x0x group join invite" "$R"; fi
R=$($CLI group set-name $CLI_GROUP_ID AuditCLI 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x group set-name $CLI_GROUP_ID → ok"; else fail "x0x group set-name $CLI_GROUP_ID" "$R"; fi
# Task lists
cli_chk "tasks list" "task_lists"
R=$($CLI tasks show $TL_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'tasks' in d" 2>/dev/null; then ok "x0x tasks show $TL_ID → tasks"; else fail "x0x tasks show $TL_ID" "$R"; fi
R=$($CLI tasks add $TL_ID cli-added-task --description from-cli 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'task_id' in d" 2>/dev/null; then ok "x0x tasks add $TL_ID → task_id"; else fail "x0x tasks add $TL_ID" "$R"; fi
CLI_TASK_ID=$(echo "$R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('task_id',''))" 2>/dev/null || echo '')
R=$($CLI tasks claim $TL_ID $CLI_TASK_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x tasks claim $CLI_TASK_ID → ok"; else fail "x0x tasks claim $CLI_TASK_ID" "$R"; fi
R=$($CLI tasks complete $TL_ID $CLI_TASK_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x tasks complete $CLI_TASK_ID → ok"; else fail "x0x tasks complete $CLI_TASK_ID" "$R"; fi
# KV store
cli_chk "store list" "stores"
R=$($CLI store create cli-store cli.store.$TS 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'id' in d or 'store_id' in d" 2>/dev/null; then ok "x0x store create → id"; else fail "x0x store create" "$R"; fi
R=$(eval "$CLIB store join $KV_ID" 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "bob x0x store join $KV_ID → ok"; else fail "bob x0x store join $KV_ID" "$R"; fi
R=$($CLI store keys $KV_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'keys' in d" 2>/dev/null; then ok "x0x store keys $KV_ID → keys"; else fail "x0x store keys $KV_ID" "$R"; fi
R=$($CLI store put $KV_ID cli-key cli-value 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x store put cli-key → ok"; else fail "x0x store put cli-key" "$R"; fi
R=$($CLI store get $KV_ID cli-key 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'value' in d" 2>/dev/null; then ok "x0x store get cli-key → value"; else fail "x0x store get cli-key" "$R"; fi
R=$($CLI store rm $KV_ID cli-key 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "x0x store rm cli-key → ok"; else fail "x0x store rm cli-key" "$R"; fi
# File transfers
cli_chk "transfers" "transfers"
R=$($CLI transfer-status $TFR_ID 2>/dev/null || echo '{"error":"cli_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'transfer' in d" 2>/dev/null; then ok "x0x transfer-status $TFR_ID → transfer"; else fail "x0x transfer-status $TFR_ID" "$R"; fi
# Publish
$CLI publish "audit-cli-$TS" "dGVzdA==" 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null \
  && ok "x0x publish → ok" || fail "x0x publish" ""
# WebSocket sessions
cli_chk "ws sessions" "sessions"
# Routes listing
ROUTES_OUT=$($CLI routes 2>/dev/null || echo 'FAIL')
check_contains "x0x routes includes GET /shutdown" "$ROUTES_OUT" "/shutdown"
# Constitution
cli_chk "constitution --json" "version"
# x0x upgrade CLI writes to stderr and may fail on GitHub rate limits; prove it runs.
UPGRADE_OUT=$($X0X upgrade --check 2>&1 || true)
if [[ "$UPGRADE_OUT" == *"Checking for updates"* ]] || [[ "$UPGRADE_OUT" == *"failed to check for updates"* ]] || [[ "$UPGRADE_OUT" == *"up to date"* ]]; then
  ok "x0x upgrade --check executes"
else
  fail "x0x upgrade --check executes" "$UPGRADE_OUT"
fi
# GUI command prints/open URL (just verify no crash)
GUI_CMD_OUT=$($X0X --api $AA gui 2>&1 || true)
check_contains "x0x gui prints GUI URL" "$GUI_CMD_OUT" "/gui"

# Agent ID cross-validation
REST_AID=$(fld "$(get /agent)" "agent_id")
CLI_AID=$($CLI agent 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")
[[ "$REST_AID" == "$CLI_AID" ]] && ok "CLI agent_id == REST agent_id [PROOF: '$REST_AID']" || fail "CLI/REST mismatch" "rest=$REST_AID cli=$CLI_AID"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [15] PRESENCE EVENTS + SHUTDOWN (real lifecycle proof) ━━"
PRES_LOG=$(mktemp)
PRES_PID=$(start_sse_capture "$AT" "$AA/presence/events" "$PRES_LOG" 90)
sleep 1
start_charlie
CR=$(cget /agent); chk "$CR" "agent_id" "charlie agent online for presence proof"
CID=$(fld "$CR" "agent_id")
R=$(cpst /announce '{}'); chk "$R" "ok" "charlie announce for presence proof"
sleep 15
for _ in $(seq 1 10); do
  R=$(get /presence/online)
  echo "$R" | grep -q "$CID" && break
  sleep 1
done
check_contains "presence online includes charlie" "$R" "$CID"
R=$(curl -s -m 10 -X POST -H "Authorization: Bearer $CT" -H "Content-Type: application/json" -d '{}' "$CA/shutdown" 2>/dev/null || echo '{"error":"shutdown_fail"}')
chk "$R" "ok" "POST /shutdown"
for _ in $(seq 1 20); do
  if ! curl -sf "$CA/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
wait "$CP" 2>/dev/null || true
sleep 40
kill "$PRES_PID" 2>/dev/null || true
wait "$PRES_PID" 2>/dev/null || true
if python3 - <<PY 2>/dev/null
import json
from pathlib import Path
raw = Path("$PRES_LOG").read_text()
seen_on = seen_off = False
for line in raw.splitlines():
    if not line.startswith('data: '):
        continue
    payload = json.loads(line[6:])
    if payload.get('agent_id') == "$CID" and payload.get('event') == 'online':
        seen_on = True
    if payload.get('agent_id') == "$CID" and payload.get('event') == 'offline':
        seen_off = True
print(seen_on, seen_off)
raise SystemExit(0 if seen_on and seen_off else 1)
PY
then
  ok "GET /presence/events emits online+offline for charlie"
else
  fail "GET /presence/events emits online+offline for charlie" "$(tr '\n' ' ' < "$PRES_LOG" | head -c 260)"
fi
rm -f "$PRES_LOG"

# ══════════════════════════════════════════════════════════════════════════
sec "━━ [16] SWARM / 3-NODE GOSSIP PROOF ━━"
CP=$(start_daemon "$CDIR" fulltest-charlie 19883 19813 '"127.0.0.1:19881"')
wait_health "$CA"
CT=$(tr -d '[:space:]' < "$CDIR/api-token")
SWARM_TOPIC="swarm.$TS"
SWARM_MSG="${PROOF_TOKEN}-swarm-posted"
SWARM_B64=$(printf '%s' "$SWARM_MSG" | base64)
SWARM_ACK="${PROOF_TOKEN}-swarm-ack-bob"
SWARM_ACK_B64=$(printf '%s' "$SWARM_ACK" | base64)
A_EVT=$(mktemp); B_WS_LOG=$(mktemp); B_EVT=$(mktemp); C_EVT=$(mktemp)
A_EVT_PID=$(start_sse_capture "$AT" "$AA/events" "$A_EVT" 30)
X0X_API_TOKEN="$BT" "$X0X" --api "$BA" --json subscribe "$SWARM_TOPIC" > "$B_WS_LOG" 2>/dev/null &
B_WS_PID=$!
B_EVT_PID=$(start_sse_capture "$BT" "$BA/events" "$B_EVT" 30)
C_EVT_PID=$(start_sse_capture "$CT" "$CA/events" "$C_EVT" 30)
sleep 2
A_SUB=$(post /subscribe "{\"topic\":\"$SWARM_TOPIC\"}")
A_SUB_ID=$(fld "$A_SUB" "subscription_id")
B_SUB=$(bpst /subscribe "{\"topic\":\"$SWARM_TOPIC\"}")
B_SUB_ID=$(fld "$B_SUB" "subscription_id")
C_SUB=$(cpst /subscribe "{\"topic\":\"$SWARM_TOPIC\"}")
C_SUB_ID=$(fld "$C_SUB" "subscription_id")
chk "$A_SUB" "subscription_id" "alice subscribes swarm topic"
chk "$B_SUB" "subscription_id" "bob subscribes swarm topic"
chk "$C_SUB" "subscription_id" "charlie subscribes swarm topic"
sleep 5
for _ in $(seq 1 20); do
  BRP=$(bget /peers)
  BPEERS=$(json_len "$BRP" "peers")
  CR=$(cget /peers)
  CPEERS=$(json_len "$CR" "peers")
  [ "$BPEERS" -ge 1 ] && [ "$CPEERS" -ge 1 ] && break
  sleep 1
done
[ "$BPEERS" -ge 1 ] && ok "bob has gossip peer for swarm" || fail "bob has gossip peer for swarm" "$BRP"
[ "$CPEERS" -ge 1 ] && ok "charlie has gossip peer for swarm" || fail "charlie has gossip peer for swarm" "$CR"
R=$(post /publish "{\"topic\":\"$SWARM_TOPIC\",\"payload\":\"$SWARM_B64\"}"); chk "$R" "ok" "swarm publish from alice"
sleep 1
R=$(post /publish "{\"topic\":\"$SWARM_TOPIC\",\"payload\":\"$SWARM_B64\"}"); chk "$R" "ok" "swarm publish replay from alice"
sleep 1
R=$(post /publish "{\"topic\":\"$SWARM_TOPIC\",\"payload\":\"$SWARM_B64\"}"); chk "$R" "ok" "swarm publish replay #2 from alice"
sleep 1
R=$(bpst /publish "{\"topic\":\"$SWARM_TOPIC\",\"payload\":\"$SWARM_ACK_B64\"}"); chk "$R" "ok" "swarm ack publish from bob"
sleep 6
kill "$A_EVT_PID" "$B_WS_PID" "$B_EVT_PID" "$C_EVT_PID" 2>/dev/null || true
wait "$A_EVT_PID" 2>/dev/null || true
wait "$B_WS_PID" 2>/dev/null || true
wait "$B_EVT_PID" 2>/dev/null || true
wait "$C_EVT_PID" 2>/dev/null || true
if ! grep -q "$SWARM_B64" "$B_WS_LOG" 2>/dev/null && ! grep -q "$SWARM_B64" "$B_EVT" 2>/dev/null; then
  B_WS_RETRY=$(mktemp)
  B_EVT_RETRY=$(mktemp)
  X0X_API_TOKEN="$BT" "$X0X" --api "$BA" --json subscribe "$SWARM_TOPIC" > "$B_WS_RETRY" 2>/dev/null &
  B_WS2_PID=$!
  B_EVT2_PID=$(start_sse_capture "$BT" "$BA/events" "$B_EVT_RETRY" 20)
  sleep 2
  R=$(post /publish "{\"topic\":\"$SWARM_TOPIC\",\"payload\":\"$SWARM_B64\"}")
  chk "$R" "ok" "swarm bob retry publish"
  sleep 5
  kill "$B_WS2_PID" "$B_EVT2_PID" 2>/dev/null || true
  wait "$B_WS2_PID" 2>/dev/null || true
  wait "$B_EVT2_PID" 2>/dev/null || true
  cat "$B_WS_RETRY" >> "$B_WS_LOG"
  cat "$B_EVT_RETRY" >> "$B_EVT"
  rm -f "$B_WS_RETRY" "$B_EVT_RETRY"
fi
if grep -q "$SWARM_B64" "$A_EVT" 2>/dev/null; then ok "swarm event delivered to alice"; else fail "swarm event delivered to alice" "$(tr '\n' ' ' < "$A_EVT" | head -c 180)"; fi
if grep -q "$SWARM_ACK_B64" "$A_EVT" 2>/dev/null; then ok "swarm reply from bob delivered to alice"; else fail "swarm reply from bob delivered to alice" "$(tr '\n' ' ' < "$A_EVT" | head -c 180)"; fi
if grep -q "$SWARM_B64" "$C_EVT" 2>/dev/null; then ok "swarm event delivered to charlie"; else fail "swarm event delivered to charlie" "$(tr '\n' ' ' < "$C_EVT" | head -c 180)"; fi
rm -f "$A_EVT" "$B_WS_LOG" "$B_EVT" "$C_EVT"
R=$(del /subscribe/$A_SUB_ID); chk "$R" "ok" "alice unsubscribe swarm"
R=$(bdel /subscribe/$B_SUB_ID); chk "$R" "ok" "bob unsubscribe swarm"
R=$(curl -s -m 10 -X DELETE -H "Authorization: Bearer $CT" "$CA/subscribe/$C_SUB_ID" 2>/dev/null || echo '{"error":"curl_fail"}')
if echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'ok' in d" 2>/dev/null; then ok "charlie unsubscribe swarm"; else fail "charlie unsubscribe swarm" "$R"; fi

# ══════════════════════════════════════════════════════════════════════════
printf "\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}\n"
printf "${CYAN}║  FINAL RESULTS                                                   ║${NC}\n"
printf "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}\n"
printf "${CYAN}║  ${GREEN}✓ $P PASS${NC}${CYAN}  ·  ${RED}✗ $F FAIL${NC}${CYAN}  ·  ${YEL}~ $S SKIP${NC}${CYAN}                              ║${NC}\n"
printf "${CYAN}║  Total checks: $((P+F+S)) across ${ENDPOINT_COUNT} REST endpoints + CLI + GUI + SSE + WS ║${NC}\n"
printf "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}\n"
exit $F
