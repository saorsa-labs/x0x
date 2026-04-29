#!/usr/bin/env bash
# =============================================================================
# Regression test for communitas#11 ("MSG-005 drops initial message").
#
# Symptom (pre-fix): when Bob joins a SignedPublic group via invite, the very
# first message Alice sends afterwards is permanently lost — Bob's daemon
# does not subscribe to `x0x.groups.public.<stable_id>` until his first
# `GET /groups/:id/messages` poll, and Plumtree cannot backfill messages on
# a topic that had no subscriber at receive time.
#
# Fix: every site that inserts into `state.named_groups` (create / join /
# import / startup-load) now spawns BOTH the metadata listener AND the
# public-message listener up-front via `ensure_named_group_listeners`.
#
# This script reproduces the original bug deterministically (FAIL pre-fix,
# PASS post-fix) by sweeping the join→first-send delay across several values
# and asserting Bob receives the first message in every trial.
# =============================================================================
set -euo pipefail

X0XD="${X0XD:-$(pwd)/target/release/x0xd}"
DELAYS="${DELAYS:-0 100 500 2000}"
TRIALS="${TRIALS:-5}"
GRACE_MS="${GRACE_MS:-2000}"
ALICE_SETTLE_SECS="${ALICE_SETTLE_SECS:-15}"

WORKDIR="${WORKDIR:-$(mktemp -d -t x0x-first-msg-XXXXXX)}"
mkdir -p "$WORKDIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "${AP:-}" ] && kill "$AP" 2>/dev/null || true
    [ -n "${BP:-}" ] && kill "$BP" 2>/dev/null || true
    sleep 1
    [ -n "${AP:-}" ] && kill -9 "$AP" 2>/dev/null || true
    [ -n "${BP:-}" ] && kill -9 "$BP" 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -x "$X0XD" ]; then
    echo -e "${RED}x0xd not found at $X0XD${NC}"
    echo "Build with: cargo build --release"
    exit 1
fi

echo -e "${YELLOW}=== first-message-after-join regression ===${NC}"
echo "  X0XD:    $X0XD"
echo "  WORKDIR: $WORKDIR"
echo "  DELAYS:  $DELAYS"
echo "  TRIALS:  $TRIALS per delay"

mkdir -p "$WORKDIR/alice" "$WORKDIR/bob"
cat>"$WORKDIR/alice/config.toml"<<TOML
instance_name = "fma-alice"
data_dir = "$WORKDIR/alice"
bind_address = "127.0.0.1:29701"
api_address = "127.0.0.1:29801"
log_level = "warn"
bootstrap_peers = ["127.0.0.1:29702"]
TOML
cat>"$WORKDIR/bob/config.toml"<<TOML
instance_name = "fma-bob"
data_dir = "$WORKDIR/bob"
bind_address = "127.0.0.1:29702"
api_address = "127.0.0.1:29802"
log_level = "warn"
bootstrap_peers = ["127.0.0.1:29701"]
TOML

"$X0XD" --config "$WORKDIR/alice/config.toml" &> "$WORKDIR/alice/log" &
AP=$!
"$X0XD" --config "$WORKDIR/bob/config.toml"   &> "$WORKDIR/bob/log" &
BP=$!

AA="http://127.0.0.1:29801"; BA="http://127.0.0.1:29802"

for i in $(seq 1 30); do
    a=$(curl -sf "$AA/health" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null || true)
    b=$(curl -sf "$BA/health" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null || true)
    [ "$a" = "True" ] && [ "$b" = "True" ] && break
    sleep 1
done

AT=$(cat "$WORKDIR/alice/api-token")
BT=$(cat "$WORKDIR/bob/api-token")
A() { curl -sf -H "Authorization: Bearer $AT" "$AA$1"; }
B() { curl -sf -H "Authorization: Bearer $BT" "$BA$1"; }
Ap() { curl -sf -H "Authorization: Bearer $AT" -H "Content-Type: application/json" -X POST -d "$2" "$AA$1"; }
Bp() { curl -sf -H "Authorization: Bearer $BT" -H "Content-Type: application/json" -X POST -d "$2" "$BA$1"; }

ALICE_LINK=$(A /agent/card | python3 -c "import sys,json;print(json.load(sys.stdin)['link'])")
BOB_LINK=$(B /agent/card | python3 -c "import sys,json;print(json.load(sys.stdin)['link'])")
Ap /agent/card/import "{\"card\":\"$BOB_LINK\",\"trust_level\":\"Trusted\"}" > /dev/null
Bp /agent/card/import "{\"card\":\"$ALICE_LINK\",\"trust_level\":\"Trusted\"}" > /dev/null

echo "Settling mesh for ${ALICE_SETTLE_SECS}s..."
sleep "$ALICE_SETTLE_SECS"
PEERS=$(A /network/status | python3 -c "import sys,json;print(json.load(sys.stdin).get('connected_peers',0))" 2>/dev/null || echo 0)
[ "$PEERS" = "0" ] && { echo -e "${RED}Mesh not formed${NC}"; exit 1; }

for delay in $DELAYS; do
    echo -e "\n${CYAN}--- DELAY ${delay}ms (join → first send) ---${NC}"
    for t in $(seq 1 "$TRIALS"); do
        TOTAL=$((TOTAL+1))
        nonce="fma-d${delay}-t${t}-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"

        create=$(Ap /groups "{\"name\":\"fma-${delay}-${t}\",\"description\":\"\",\"preset\":\"public_open\"}")
        gid=$(echo "$create" | python3 -c "import sys,json;print(json.load(sys.stdin).get('group_id',''))")
        inv=$(Ap "/groups/$gid/invite" '{"ttl_secs":600}')
        link=$(echo "$inv" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('invite_link') or d.get('invite') or '')")
        join=$(Bp /groups/join "{\"invite\":\"$link\",\"display_name\":\"bob\"}")
        bob_gid=$(echo "$join" | python3 -c "import sys,json;print(json.load(sys.stdin).get('group_id',''))")

        if [ "$delay" -gt 0 ]; then
            python3 -c "import time;time.sleep(${delay}/1000.0)"
        fi
        Ap "/groups/$gid/send" "{\"body\":\"hello $nonce\"}" > /dev/null
        python3 -c "import time;time.sleep(${GRACE_MS}/1000.0)"
        saw=$(B "/groups/$bob_gid/messages" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(1 if any('$nonce' in (m.get('body') or '') for m in d.get('messages',[])) else 0)
except Exception:
    print(0)
")
        if [ "$saw" = "1" ]; then
            PASS=$((PASS+1)); printf "  trial %2d: %sOK%s\n" "$t" "$GREEN" "$NC"
        else
            FAIL=$((FAIL+1)); printf "  trial %2d: %sMISS%s gid=%s\n" "$t" "$RED" "$NC" "$gid"
        fi
    done
done

echo -e "\n${YELLOW}=== SUMMARY ===${NC}"
echo "  total=$TOTAL pass=$PASS fail=$FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}REGRESSION: $FAIL/$TOTAL first-message deliveries failed${NC}"
    exit 1
fi
echo -e "${GREEN}OK: every trial received the first message after join${NC}"
