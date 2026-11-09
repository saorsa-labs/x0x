#!/usr/bin/env bash
# CI proof of docs/quickstart-two-agents.md: two loopback-only daemons,
# a DM each way over REST, delivery asserted on the RECEIVER's own
# subscription — the /ws/direct WebSocket event stream (never wire-byte
# filters). Keep this script in step with the recipe document: the step
# numbers, config, connect wait and send retry below match the document's
# commands. The recipe is only "CI-verified" while this runs them.
#
# The final leg proves the #894 `GET /onboard` output: a THIRD fresh daemon
# (carol) imports the inviter's signed card from the onboard response and
# DMs the inviter, asserted on the inviter's own subscription.
#
# Isolation: 127.0.0.1 binds, mdns_enabled = false, --no-hard-coded-bootstrap,
# loopback bootstrap_peers, a private plane (network_id = "x0x.quickstart",
# never x0x.prod), and --skip-update-check plus [update] enabled = false so
# no GitHub update check, manifest fetch or fallback poll starts. CI also
# runs it inside scripts/ci/isolated-runtime.py's loopback-only namespace.
#
# Bash 3.2 safe (macOS /bin/bash): no associative arrays.
# Requirements: x0xd (env X0XD or target/{release,debug}/x0xd), curl,
# python3, node >= 22 (global WebSocket).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${X0XD:-}" ]; then
    for cand in "$ROOT/target/release/x0xd" "$ROOT/target/debug/x0xd"; do
        [ -x "$cand" ] && X0XD="$cand" && break
    done
fi
[ -x "${X0XD:-}" ] || { echo "FAIL: x0xd not found (set X0XD or cargo build --bin x0xd)" >&2; exit 2; }

NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
[ "$NODE_MAJOR" -ge 22 ] || { echo "FAIL: node >= 22 required for global WebSocket (found: $(node --version 2>/dev/null || echo none))" >&2; exit 2; }

# Deadlines (seconds) for the steps that wait on the mesh.
CONNECT_DEADLINE=${CONNECT_DEADLINE:-90}
SEND_DEADLINE=${SEND_DEADLINE:-60}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/x0x-onboarding.XXXXXX")
echo "work_dir=$WORK  x0xd=$X0XD"
PIDS=()
cleanup() {
    local rc=$?
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    sleep 1
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true; done
    if [ "$rc" -ne 0 ]; then
        for n in alice bob carol; do
            echo "--- $n daemon log (tail) ---"; tail -40 "$WORK/$n.log" 2>/dev/null || true
            echo "--- $n ws frames ---"; cat "$WORK/$n.ws.ndjson" 2>/dev/null || true
            echo "--- $n ws stderr ---"; cat "$WORK/$n.ws.err" 2>/dev/null || true
        done
    fi
    rm -rf "$WORK"
    exit "$rc"
}
trap cleanup EXIT

# json <python-subscript>: read JSON on stdin, print the selected value.
# Prints nothing (exit 0) when stdin is not JSON, so callers see the raw body.
json() { python3 -c "import sys,json
try: print(json.load(sys.stdin)$1)
except Exception: pass"; }

wait_for() { # wait_for <seconds> <description> <command...>
    local deadline=$1 what=$2; shift 2
    local i=0
    until "$@" > /dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge "$deadline" ]; then
            echo "FAIL: timed out after ${deadline}s waiting for $what" >&2
            return 1
        fi
        sleep 1
    done
}

api_port() { [ "$1" = alice ] && echo 19901 || echo 19902; }
quic_port() { [ "$1" = alice ] && echo 19801 || echo 19802; }

# ── Recipe step 2: two loopback-only daemons ─────────────────────────────
for n in alice bob; do
    peer=$([ "$n" = alice ] && echo bob || echo alice)
    mkdir -p "$WORK/$n"
    cat > "$WORK/$n/config.toml" <<TOML
instance_name = "qs-$n"
network_id = "x0x.quickstart"
data_dir = "$WORK/$n"
identity_dir = "$WORK/$n/identity"
bind_address = "127.0.0.1:$(quic_port "$n")"
api_address = "127.0.0.1:$(api_port "$n")"
mdns_enabled = false
bootstrap_peers = ["127.0.0.1:$(quic_port "$peer")"]
log_level = "warn"

[update]
enabled = false
TOML
    "$X0XD" --config "$WORK/$n/config.toml" --no-hard-coded-bootstrap --skip-update-check \
        > "$WORK/$n.log" 2>&1 &
    PIDS+=("$!")
    disown  # keep job-control kill notices out of the transcript
done
for n in alice bob; do
    wait_for 60 "$n /health" curl -sf -m 2 "http://127.0.0.1:$(api_port "$n")/health"
done
echo "PASS: both daemons answer /health"

# ── Recipe step 3: tokens and agent ids ──────────────────────────────────
for n in alice bob; do
    wait_for 30 "$n api-token" test -s "$WORK/$n/api-token"
done
AA="http://127.0.0.1:19901"; BA="http://127.0.0.1:19902"
AT=$(cat "$WORK/alice/api-token"); BT=$(cat "$WORK/bob/api-token")
AID=$(curl -s -H "Authorization: Bearer $AT" "$AA/agent" | json "['agent_id']")
BID=$(curl -s -H "Authorization: Bearer $BT" "$BA/agent" | json "['agent_id']")
[ -n "$AID" ] && [ -n "$BID" ] || { echo "FAIL: could not read agent ids (alice='$AID' bob='$BID')" >&2; exit 1; }
echo "PASS: identities read (alice=${AID:0:16}… bob=${BID:0:16}…)"

# ── Recipe step 4: connect, retrying until discovery has run ─────────────
# The daemons must first see each other's signed identity announcements
# (the first re-announce comes a few seconds after join). Until then the
# connect answers HTTP 200 with outcome NotFound, so poll with a deadline.
OUTCOME=""; BODY=""
for _ in $(seq 1 "$CONNECT_DEADLINE"); do
    BODY=$(curl -s -m 10 -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"$BID\"}" "$AA/agents/connect" || true)
    OUTCOME=$(printf '%s' "$BODY" | json ".get('outcome','')")
    case "$OUTCOME" in Direct|Coordinated|AlreadyConnected) break ;; esac
    sleep 1
done
case "$OUTCOME" in
    Direct|Coordinated|AlreadyConnected) echo "PASS: alice connected to bob ($OUTCOME)" ;;
    *) echo "FAIL: connect did not succeed within ${CONNECT_DEADLINE}s; last body: $BODY" >&2; exit 1 ;;
esac

# ── Recipe step 5: each receiver's /ws/direct subscription ──────────────
ws_listen() { # ws_listen <name> <api_port> <durable_token>
    local n=$1 port=$2 token=$3 body session
    body=$(curl -s -X POST -H "Authorization: Bearer $token" "http://127.0.0.1:$port/auth/session" || true)
    session=$(printf '%s' "$body" | json "['session_token']")
    [ -n "$session" ] || { echo "FAIL: $n /auth/session gave no session_token: $body" >&2; return 1; }
    node - "$port" "$session" > "$WORK/$n.ws.ndjson" 2> "$WORK/$n.ws.err" <<'JS' &
const [port, token] = process.argv.slice(2);
const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/direct?token=${token}`);
ws.onopen = () => console.log(JSON.stringify({ type: "listener_open" }));
ws.onmessage = (e) => {
    const f = JSON.parse(e.data);
    if (f.type === "direct_message")
        f.decoded = Buffer.from(f.payload, "base64").toString("utf8");
    console.log(JSON.stringify(f));
};
ws.onerror = (e) => { console.error("ws error:", e.message); process.exit(1); };
JS
    PIDS+=("$!")
    disown
    wait_for 15 "$n ws listener open" grep -q listener_open "$WORK/$n.ws.ndjson"
}
ws_listen bob   19902 "$BT"
ws_listen alice 19901 "$AT"
echo "PASS: both /ws/direct listeners connected (session tokens)"

# ── Recipe step 6: DM each way, assert on the receiver's stream ──────────
# send_dm <sender_api> <sender_token> <recipient_id> <text>
# Retries the transient refusals (404 recipient_key_unavailable, 409 key
# not converged, 503 recipient_undiscovered) until SEND_DEADLINE.
send_dm() {
    local api=$1 token=$2 to=$3 payload resp code body i=0
    payload=$(printf '%s' "$4" | base64 | tr -d '\n')
    while :; do
        resp=$(curl -s -m 30 -w '\n%{http_code}' -X POST -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "{\"agent_id\":\"$to\",\"payload\":\"$payload\"}" "$api/direct/send" || true)
        code=${resp##*$'\n'}; body=${resp%$'\n'*}
        if [ "$code" = 200 ] && [ "$(printf '%s' "$body" | json "['ok']")" = True ]; then
            return 0
        fi
        case "$code" in
            404|409|503) ;;
            *) echo "FAIL: /direct/send HTTP $code: $body" >&2; return 1 ;;
        esac
        i=$((i + 1))
        if [ "$i" -ge "$SEND_DEADLINE" ]; then
            echo "FAIL: /direct/send still refused after ${SEND_DEADLINE}s: HTTP $code $body" >&2
            return 1
        fi
        sleep 1
    done
}

# assert_dm <receiver> <text> <expected_sender_id>
assert_dm() {
    local n=$1 text=$2 want=$3 got
    wait_for 30 "$n's ws stream to deliver \"$text\"" grep -qF "$text" "$WORK/$n.ws.ndjson"
    got=$(grep -F "$text" "$WORK/$n.ws.ndjson" | head -1 | json ".get('sender','')")
    [ "$got" = "$want" ] \
        || { echo "FAIL: DM on $n's stream has sender '$got', want '$want'" >&2; return 1; }
}

MSG_AB="hello bob — over x0x $$"
MSG_BA="hey alice, got it $$"

send_dm "$AA" "$AT" "$BID" "$MSG_AB"
assert_dm bob "$MSG_AB" "$AID"
echo "PASS: alice -> bob DM delivered on bob's /ws/direct stream, sender verified"

send_dm "$BA" "$BT" "$AID" "$MSG_BA"
assert_dm alice "$MSG_BA" "$BID"
echo "PASS: bob -> alice reply delivered on alice's /ws/direct stream, sender verified"

# ── #894 leg: GET /onboard output joins a NEW agent to the inviter ───────
# Alice is the inviter. Carol is the fresh agent: a third daemon that knows
# only alice's transport address (the loopback stand-in for "shares a
# network with the inviter"). Carol follows the onboard output — import the
# inviter's signed card, DM the inviter — and the DM must land on ALICE's
# own /ws/direct subscription with carol as the attributed sender.
mkdir -p "$WORK/carol"
cat > "$WORK/carol/config.toml" <<TOML
instance_name = "qs-carol"
network_id = "x0x.quickstart"
data_dir = "$WORK/carol"
identity_dir = "$WORK/carol/identity"
bind_address = "127.0.0.1:19803"
api_address = "127.0.0.1:19903"
mdns_enabled = false
bootstrap_peers = ["127.0.0.1:19801"]
log_level = "warn"

[update]
enabled = false
TOML
"$X0XD" --config "$WORK/carol/config.toml" --no-hard-coded-bootstrap --skip-update-check \
    > "$WORK/carol.log" 2>&1 &
PIDS+=("$!")
disown
wait_for 60 "carol /health" curl -sf -m 2 "http://127.0.0.1:19903/health"
wait_for 30 "carol api-token" test -s "$WORK/carol/api-token"
CA="http://127.0.0.1:19903"
CT=$(cat "$WORK/carol/api-token")
CID=$(curl -s -H "Authorization: Bearer $CT" "$CA/agent" | json "['agent_id']")
[ -n "$CID" ] || { echo "FAIL: could not read carol's agent id" >&2; exit 1; }

# The inviter asks its own daemon for the recipe (default: file delivery).
ONBOARD=$(curl -s -H "Authorization: Bearer $AT" "$AA/onboard")
[ "$(printf '%s' "$ONBOARD" | json "['ok']")" = True ] \
    || { echo "FAIL: GET /onboard refused: $ONBOARD" >&2; exit 1; }
printf '%s' "$ONBOARD" | json "['recipe']" > "$WORK/onboard-recipe.md"
grep -qF "install.sh" "$WORK/onboard-recipe.md" \
    || { echo "FAIL: onboard recipe has no install step" >&2; exit 1; }
grep -qF "x0x direct send $AID" "$WORK/onboard-recipe.md" \
    || { echo "FAIL: onboard recipe does not target the inviter's agent id" >&2; exit 1; }
INVITER_ID=$(printf '%s' "$ONBOARD" | json "['inviter_agent_id']")
[ "$INVITER_ID" = "$AID" ] \
    || { echo "FAIL: onboard inviter_agent_id '$INVITER_ID' != alice '$AID'" >&2; exit 1; }
CARD_LINK=$(printf '%s' "$ONBOARD" | json "['card_link']")
case "$CARD_LINK" in x0x://agent/*) ;; *)
    echo "FAIL: onboard card_link is not an x0x://agent/ link: ${CARD_LINK:0:40}" >&2; exit 1 ;;
esac
echo "PASS: GET /onboard serves the recipe, inviter id and signed card link"

# Carol follows the recipe's import + DM steps (REST spellings of
# `x0x agent import` and `x0x direct send`).
IMPORT=$(curl -s -m 10 -X POST -H "Authorization: Bearer $CT" -H "Content-Type: application/json" \
    -d "{\"card\":\"$CARD_LINK\",\"trust_level\":\"known\"}" "$CA/agent/card/import")
[ "$(printf '%s' "$IMPORT" | json "['ok']")" = True ] \
    || { echo "FAIL: carol could not import the inviter card: $IMPORT" >&2; exit 1; }
echo "PASS: carol imported the inviter's card from the onboard output"

MSG_CA="hello inviter — onboarded $$"
send_dm "$CA" "$CT" "$AID" "$MSG_CA"
assert_dm alice "$MSG_CA" "$CID"
echo "PASS: carol -> alice DM delivered on the inviter's /ws/direct stream, sender verified"

echo "onboarding recipe: ALL PASS"
