#!/usr/bin/env bash
# CI proof of docs/quickstart-two-agents.md: two loopback-only daemons,
# a DM each way over REST, delivery asserted on the RECEIVER's own
# subscription — the /ws/direct WebSocket event stream (never wire-byte
# filters). Keep this script in step with the recipe document; the recipe
# is only "CI-verified" while this runs the same commands.
#
# Network-inert by construction: 127.0.0.1 binds, mdns_enabled = false,
# --no-hard-coded-bootstrap, loopback bootstrap_peers. CI additionally runs
# it inside scripts/ci/isolated-runtime.py's loopback-only namespace.
#
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

WORK=$(mktemp -d -t x0x-onboarding.XXXXXX)
echo "work_dir=$WORK  x0xd=$X0XD"
PIDS=()
cleanup() {
    local rc=$?
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    sleep 1
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    if [ "$rc" -ne 0 ]; then
        for n in alice bob; do
            echo "--- $n daemon log (tail) ---"; tail -40 "$WORK/$n.log" 2>/dev/null || true
            echo "--- $n ws frames ---"; cat "$WORK/$n.ws.ndjson" 2>/dev/null || true
        done
    fi
    rm -rf "$WORK"
    exit "$rc"
}
trap cleanup EXIT

json() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

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

# ── Recipe step 2: two loopback-only daemons ─────────────────────────────
declare -A API=( [alice]=19901 [bob]=19902 )
declare -A QUIC=( [alice]=19801 [bob]=19802 )
for n in alice bob; do
    peer=$([ "$n" = alice ] && echo bob || echo alice)
    mkdir -p "$WORK/$n"
    cat > "$WORK/$n/config.toml" <<TOML
instance_name = "qs-$n"
network_id = "x0x.prod"
data_dir = "$WORK/$n"
identity_dir = "$WORK/$n/identity"
bind_address = "127.0.0.1:${QUIC[$n]}"
api_address = "127.0.0.1:${API[$n]}"
mdns_enabled = false
bootstrap_peers = ["127.0.0.1:${QUIC[$peer]}"]
log_level = "warn"
TOML
    "$X0XD" --config "$WORK/$n/config.toml" --no-hard-coded-bootstrap > "$WORK/$n.log" 2>&1 &
    PIDS+=("$!")
    disown  # keep job-control kill notices out of the transcript
done
for n in alice bob; do
    wait_for 60 "$n /health" curl -sf -m 2 "http://127.0.0.1:${API[$n]}/health"
done
echo "PASS: both daemons answer /health"

# ── Recipe step 3: tokens and agent ids ──────────────────────────────────
for n in alice bob; do
    wait_for 30 "$n api-token" test -s "$WORK/$n/api-token"
done
AA="http://127.0.0.1:${API[alice]}"; BA="http://127.0.0.1:${API[bob]}"
AT=$(cat "$WORK/alice/api-token"); BT=$(cat "$WORK/bob/api-token")
AID=$(curl -sf -H "Authorization: Bearer $AT" "$AA/agent" | json "['agent_id']")
BID=$(curl -sf -H "Authorization: Bearer $BT" "$BA/agent" | json "['agent_id']")
echo "PASS: identities read (alice=${AID:0:16}… bob=${BID:0:16}…)"

# ── Recipe step 4: connect (announce exchange already ran over loopback) ─
OUTCOME=$(curl -sf -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$BID\"}" "$AA/agents/connect" | json ".get('outcome','')")
case "$OUTCOME" in
    Direct|Coordinated|AlreadyConnected) echo "PASS: alice connected to bob ($OUTCOME)" ;;
    *) echo "FAIL: connect outcome=$OUTCOME" >&2; exit 1 ;;
esac

# ── Recipe step 5: each receiver's /ws/direct subscription ──────────────
ws_listen() { # ws_listen <name> <api_port> <durable_token>
    local n=$1 port=$2 token=$3 session
    session=$(curl -sf -X POST -H "Authorization: Bearer $token" "http://127.0.0.1:$port/auth/session" \
        | json "['session_token']")
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
ws_listen bob   "${API[bob]}"   "$BT"
ws_listen alice "${API[alice]}" "$AT"
echo "PASS: both /ws/direct listeners connected (session tokens)"

# ── Recipe step 6: DM each way, assert on the receiver's stream ──────────
send_dm() { # send_dm <sender_api> <sender_token> <recipient_id> <text>
    local body
    body=$(curl -sf -X POST -H "Authorization: Bearer $2" -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"$3\",\"payload\":\"$(printf '%s' "$4" | base64 | tr -d '\n')\"}" "$1/direct/send")
    echo "$body" | json "['ok']" | grep -qx True \
        || { echo "FAIL: /direct/send did not return ok:true: $body" >&2; return 1; }
}
MSG_AB="hello bob — over x0x $$"
MSG_BA="hey alice, got it $$"

send_dm "$AA" "$AT" "$BID" "$MSG_AB"
wait_for 30 "bob's ws stream to deliver alice's DM" grep -qF "$MSG_AB" "$WORK/bob.ws.ndjson"
grep -F "$MSG_AB" "$WORK/bob.ws.ndjson" | head -1 | json ".get('sender','')" | grep -qx "$AID" \
    || { echo "FAIL: DM on bob's stream not attributed to alice" >&2; exit 1; }
echo "PASS: alice -> bob DM delivered on bob's /ws/direct stream, sender verified"

send_dm "$BA" "$BT" "$AID" "$MSG_BA"
wait_for 30 "alice's ws stream to deliver bob's reply" grep -qF "$MSG_BA" "$WORK/alice.ws.ndjson"
echo "PASS: bob -> alice reply delivered on alice's /ws/direct stream"

echo "onboarding recipe: ALL PASS"
