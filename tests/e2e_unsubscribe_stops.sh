#!/usr/bin/env bash
# Proof harness: DELETE /subscribe/:id actually stops delivery.
#
# Regression guard for the unsubscribe-forwarder-leak fix. Before the fix,
# the REST unsubscribe handler only dropped a bookkeeping map entry and left
# the forwarder task running, so an "unsubscribed" stream kept forwarding
# messages to /events forever.
#
# Proof: subscribe → publish A (must arrive on SSE) → unsubscribe →
# publish B (must NOT arrive on SSE). If B arrives, the subscription did not
# stop and the fix has regressed.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
X0XD="${X0XD:-$ROOT/target/debug/x0xd}"
DIR="${DIR:-/tmp/x0x-e2e-unsub}"
API="http://127.0.0.1:19181"
TOPIC="unsub-proof-topic"

[ -x "$X0XD" ] || { echo "FAIL: x0xd binary not found at $X0XD (run: cargo build --bin x0xd)"; exit 1; }

cleanup() {
  [ -n "${SSE_PID:-}" ] && kill "$SSE_PID" 2>/dev/null || true
  [ -n "${DP:-}" ] && kill "$DP" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$DIR"; mkdir -p "$DIR"
cat >"$DIR/config.toml" <<TOML
instance_name = "e2e-unsub"
data_dir = "$DIR"
bind_address = "127.0.0.1:19081"
api_address = "127.0.0.1:19181"
log_level = "warn"
bootstrap_peers = []
TOML

"$X0XD" --config "$DIR/config.toml" --no-hard-coded-bootstrap &>"$DIR/log" &
DP=$!

# Wait for health.
for i in $(seq 1 30); do
  ok=$(curl -sf "$API/health" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok',''))" 2>/dev/null || true)
  [ "$ok" = "True" ] && break
  [ "$i" = "30" ] && { echo "FAIL: daemon did not become healthy"; tail -20 "$DIR/log"; exit 1; }
  sleep 1
done
TOKEN=$(cat "$DIR/api-token" 2>/dev/null || true)
AUTH=(-H "Authorization: Bearer $TOKEN")

# Subscribe.
SUB=$(curl -sf "${AUTH[@]}" -H "Content-Type: application/json" \
  -d "{\"topic\":\"$TOPIC\"}" "$API/subscribe")
SUB_ID=$(echo "$SUB" | python3 -c "import sys,json;print(json.load(sys.stdin)['subscription_id'])")
[ -n "$SUB_ID" ] || { echo "FAIL: no subscription_id from /subscribe ($SUB)"; exit 1; }
echo "subscribed: id=$SUB_ID topic=$TOPIC"

# Tap the SSE stream in the background.
curl -sN "${AUTH[@]}" "$API/events" >"$DIR/sse.log" 2>/dev/null &
SSE_PID=$!
sleep 1  # let the SSE client attach to the broadcast channel

PAY_A=$(printf 'BEFORE-UNSUB-payload' | base64)
PAY_B=$(printf 'AFTER-UNSUB-payload' | base64)

publish() {
  curl -sf "${AUTH[@]}" -H "Content-Type: application/json" \
    -d "{\"topic\":\"$TOPIC\",\"payload\":\"$1\"}" "$API/publish" >/dev/null
}

wait_for() { # pattern timeout_secs -> 0 if found
  local pat="$1" t="$2" i
  for i in $(seq 1 "$t"); do
    grep -q "$pat" "$DIR/sse.log" && return 0
    sleep 1
  done
  return 1
}

# 1) While subscribed, A must arrive.
publish "$PAY_A"
if wait_for "$PAY_A" 5; then
  echo "PASS: message delivered to SSE while subscribed"
else
  echo "FAIL: subscribed stream never received message A (delivery broken, cannot prove fix)"
  tail -20 "$DIR/log"; exit 1
fi

# 2) Unsubscribe.
DEL=$(curl -sf "${AUTH[@]}" -X DELETE "$API/subscribe/$SUB_ID")
echo "unsubscribe response: $DEL"
echo "$DEL" | grep -q '"ok":true' || { echo "FAIL: unsubscribe did not return ok:true"; exit 1; }

# 3) After unsubscribe, B must NOT arrive. Give the forwarder ample time to
#    (mis)deliver if the fix has regressed.
publish "$PAY_B"
if wait_for "$PAY_B" 4; then
  echo "FAIL: message B delivered to SSE AFTER unsubscribe — subscription did not stop"
  exit 1
else
  echo "PASS: no delivery after unsubscribe — subscription stopped"
fi

echo "ALL CHECKS PASSED: unsubscribe stops delivery"
