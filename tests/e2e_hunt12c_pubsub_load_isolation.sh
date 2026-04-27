#!/usr/bin/env bash
# Hunt 12c reproducer: under sustained PubSub publish load, presence
# delivery (Bulk stream) MUST keep working — Step 2 per-stream channel
# split should isolate PubSub stalls from Bulk presence beacons.
#
# Pre-Step-2 expectation: stalled PubSub handler back-pressures the
# shared recv queue, presence_online drifts down on at least one node,
# dispatcher.bulk.timed_out grows.
#
# Post-Step-2 expectation: presence_online stays at N-1 on every node,
# dispatcher.bulk.timed_out stays at 0.
set -euo pipefail

X0XD="${X0XD:-$(pwd)/target/release/x0xd}"
N=4
PUBLISH_RATE_PER_SEC="${PUBLISH_RATE_PER_SEC:-20}"
DURATION_SECS="${DURATION_SECS:-180}"   # 3 minutes
PAYLOAD_BYTES="${PAYLOAD_BYTES:-12000}"  # ~16k including overhead, similar to peer 6a24bdeddd828e1e
TOPIC="hunt12c-load-$$"

if [ ! -x "$X0XD" ]; then
  echo "x0xd not found at $X0XD" >&2
  exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
PROOF_DIR="${PROOF_DIR:-proofs/hunt12c-pubsub-load-$TS}"
BASE="$PROOF_DIR/runtime"
mkdir -p "$BASE"

PIDS=()
TOKENS=()
API_PORTS=()
BIND_PORTS=()
PUBLISH_PID=""
MONITOR_PID=""
FAIL=0

cleanup() {
  if [ -n "${PUBLISH_PID:-}" ]; then kill -TERM "$PUBLISH_PID" 2>/dev/null || true; fi
  if [ -n "${MONITOR_PID:-}" ]; then kill -TERM "$MONITOR_PID" 2>/dev/null || true; fi
  for pid in "${PIDS[@]:-}"; do
    kill -INT "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in "${PIDS[@]:-}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

echo "Hunt 12c PubSub-load isolation reproducer"
echo "Proof: $PROOF_DIR"
echo "N=$N, publish rate=$PUBLISH_RATE_PER_SEC msg/s, payload=$PAYLOAD_BYTES bytes, duration=${DURATION_SECS}s"
echo

# ── Fixed deterministic port ranges (avoids OS port-reuse race) ──
# Bind 19410-19413 (UDP), API 19510-19513 (TCP)
for i in $(seq 0 $((N-1))); do
  BIND_PORTS+=("$((19410 + i))")
  API_PORTS+=("$((19510 + i))")
done

# ── Launch nodes (config schema matches e2e_presence_propagation.sh) ──
for i in $(seq 0 $((N-1))); do
  NAME="node-$((i+1))"
  NODE_DIR="$BASE/$NAME"
  mkdir -p "$NODE_DIR"

  # Bootstrap peers = every other node (skip self)
  PEERS=()
  for j in $(seq 0 $((N-1))); do
    if [ "$j" -ne "$i" ]; then
      PEERS+=("\"127.0.0.1:${BIND_PORTS[$j]}\"")
    fi
  done
  PEER_LIST=$(IFS=,; echo "${PEERS[*]}")

  cat > "$NODE_DIR/config.toml" <<EOF
instance_name = "hunt12c-$((i+1))"
data_dir = "$NODE_DIR"
bind_address = "127.0.0.1:${BIND_PORTS[$i]}"
api_address = "127.0.0.1:${API_PORTS[$i]}"
log_level = "info"
bootstrap_peers = [$PEER_LIST]
heartbeat_interval_secs = 5
identity_ttl_secs = 60
presence_beacon_interval_secs = 5
presence_event_poll_interval_secs = 2
EOF

  NO_COLOR=1 RUST_LOG='warn,x0x=info,saorsa_gossip=warn,ant_quic=warn' \
    "$X0XD" --config "$NODE_DIR/config.toml" --skip-update-check >"$NODE_DIR/stdout.log" 2>&1 &
  PIDS+=($!)
  sleep 0.5
done

echo "Launched $N daemons. Waiting 12s for mesh formation..."
sleep 12

# ── Read tokens ──
for i in $(seq 0 $((N-1))); do
  NODE_DIR="$BASE/node-$((i+1))"
  for _ in 1 2 3 4 5; do
    if [ -s "$NODE_DIR/api-token" ]; then break; fi
    sleep 1
  done
  TOKENS+=("$(cat "$NODE_DIR/api-token" 2>/dev/null)")
done

# ── Subscribe to TOPIC on every node so PubSub fanout actually traverses the mesh ──
for i in $(seq 0 $((N-1))); do
  curl -sf -m 4 -X POST -H "Authorization: Bearer ${TOKENS[$i]}" \
    "http://127.0.0.1:${API_PORTS[$i]}/pubsub/subscribe?topic=$TOPIC" >/dev/null || true
done

# ── Generate publish payload ──
PAYLOAD=$(python3 -c "import sys; sys.stdout.write('A'*$PAYLOAD_BYTES)")
PUBLISH_BODY="$PROOF_DIR/publish-body.json"
python3 -c "import json,sys; print(json.dumps({'payload': 'A'*$PAYLOAD_BYTES}))" > "$PUBLISH_BODY"

# ── Background publisher: hammer node-1 with PAYLOAD at PUBLISH_RATE_PER_SEC msg/s ──
SLEEP_BETWEEN=$(python3 -c "print(1.0/$PUBLISH_RATE_PER_SEC)")
PUB_TOKEN="${TOKENS[0]}"
PUB_API="${API_PORTS[0]}"
(
  end=$(($(date +%s) + DURATION_SECS))
  count=0
  while [ "$(date +%s)" -lt "$end" ]; do
    curl -sf -m 4 -X POST -H "Authorization: Bearer $PUB_TOKEN" -H "Content-Type: application/json" \
      --data @"$PUBLISH_BODY" \
      "http://127.0.0.1:$PUB_API/pubsub/publish?topic=$TOPIC" >/dev/null || true
    count=$((count+1))
    sleep "$SLEEP_BETWEEN"
  done
  echo "$count" > "$PROOF_DIR/publish-count.txt"
) &
PUBLISH_PID=$!
echo "Publisher PID $PUBLISH_PID hammering node-1 at ${PUBLISH_RATE_PER_SEC}/s with ${PAYLOAD_BYTES}B payloads"

# ── Monitor: every 10s sample /presence/online + /diagnostics/gossip on every node ──
CSV="$PROOF_DIR/monitor.csv"
echo "tick_unix,node,presence_online,pubsub_received,pubsub_completed,pubsub_timed_out,membership_timed_out,bulk_received,bulk_completed,bulk_timed_out,bulk_max_ms,recv_pubsub_max,recv_membership_max,recv_bulk_max" > "$CSV"

(
  end=$(($(date +%s) + DURATION_SECS))
  while [ "$(date +%s)" -lt "$end" ]; do
    now=$(date +%s)
    for i in $(seq 0 $((N-1))); do
      NAME="node-$((i+1))"
      ONLINE=$(curl -sf -m 4 -H "Authorization: Bearer ${TOKENS[$i]}" \
        "http://127.0.0.1:${API_PORTS[$i]}/presence/online" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); a=d.get('agents') or d.get('online') or d.get('data') or []; print(len(a) if isinstance(a,list) else 0)" 2>/dev/null || echo 0)
      DIAG=$(curl -sf -m 4 -H "Authorization: Bearer ${TOKENS[$i]}" \
        "http://127.0.0.1:${API_PORTS[$i]}/diagnostics/gossip" 2>/dev/null || echo "{}")
      LINE=$(python3 -c "
import json,sys
d = json.loads(\"\"\"$DIAG\"\"\" or '{}')
disp = d.get('dispatcher') or {}
ps = disp.get('pubsub') or {}
ms = disp.get('membership') or {}
bk = disp.get('bulk') or {}
rd = disp.get('recv_depth') or {}
rd_ps = rd.get('pubsub') or {}
rd_ms = rd.get('membership') or {}
rd_bk = rd.get('bulk') or {}
print(','.join(str(v) for v in [
  ps.get('received', 0), ps.get('completed', 0), ps.get('timed_out', 0),
  ms.get('timed_out', 0),
  bk.get('received', 0), bk.get('completed', 0), bk.get('timed_out', 0), bk.get('max_elapsed_ms', 0),
  rd_ps.get('max', 0), rd_ms.get('max', 0), rd_bk.get('max', 0),
]))
" 2>/dev/null || echo "0,0,0,0,0,0,0,0,0,0,0")
      echo "$now,$NAME,$ONLINE,$LINE" >> "$CSV"
    done
    sleep 10
  done
) &
MONITOR_PID=$!

# ── Wait for both background tasks to finish ──
wait "$PUBLISH_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true

echo
echo "=== Summary ==="
PUB_COUNT=$(cat "$PROOF_DIR/publish-count.txt" 2>/dev/null || echo 0)
echo "Published: $PUB_COUNT messages from node-1"
echo

# Per-node final state
for NAME in node-1 node-2 node-3 node-4; do
  LAST=$(awk -F, -v n=$NAME '$2==n {last=$0} END {print last}' "$CSV")
  echo "  $NAME final: $LAST"
done

# ── Pass criteria ──
echo
echo "=== Pass criteria ==="
MIN_ONLINE_FAIL=0
BULK_TIMED_OUT_FAIL=0
MS_TIMED_OUT_FAIL=0
while IFS=',' read -r tick node online _ps_recv _ps_compl _ps_to ms_to _bk_recv _bk_compl bk_to _bk_max _rd_ps _rd_ms _rd_bk; do
  if [ "$node" = "node" ]; then continue; fi   # header
  if [ "$online" -lt 3 ]; then
    MIN_ONLINE_FAIL=$((MIN_ONLINE_FAIL+1))
  fi
  if [ "$bk_to" -gt 0 ]; then
    BULK_TIMED_OUT_FAIL=$((BULK_TIMED_OUT_FAIL+1))
  fi
  if [ "$ms_to" -gt 0 ]; then
    MS_TIMED_OUT_FAIL=$((MS_TIMED_OUT_FAIL+1))
  fi
done < "$CSV"

echo "  presence_online < N-1=3 ticks:       $MIN_ONLINE_FAIL"
echo "  bulk.timed_out > 0 ticks:            $BULK_TIMED_OUT_FAIL  (Step 2 isolation: must be 0)"
echo "  membership.timed_out > 0 ticks:      $MS_TIMED_OUT_FAIL  (Step 2 isolation: must be 0)"
echo

if [ "$MIN_ONLINE_FAIL" -eq 0 ] && [ "$BULK_TIMED_OUT_FAIL" -eq 0 ] && [ "$MS_TIMED_OUT_FAIL" -eq 0 ]; then
  echo "RESULT: PASS — Hunt 12c isolation holds under sustained PubSub load"
  echo "RESULT: PASS" > "$PROOF_DIR/summary.txt"
  exit 0
else
  echo "RESULT: FAIL — Step 2 did not isolate PubSub stalls from Bulk/Membership"
  echo "RESULT: FAIL" > "$PROOF_DIR/summary.txt"
  echo "  presence_online_fail=$MIN_ONLINE_FAIL bulk_timed_out_fail=$BULK_TIMED_OUT_FAIL membership_timed_out_fail=$MS_TIMED_OUT_FAIL" >> "$PROOF_DIR/summary.txt"
  exit 1
fi
