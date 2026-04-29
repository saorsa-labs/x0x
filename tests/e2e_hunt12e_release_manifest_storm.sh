#!/usr/bin/env bash
# Hunt 12e release-manifest storm isolation test.
#
# Launches a 4-daemon loopback mesh with the normal x0x/release gossip
# listener enabled, then injects a sustained stream of release-manifest-shaped
# payloads on RELEASE_TOPIC. The pass criterion is that the PubSub dispatcher
# never hits its 10s watchdog while the storm runs.
#
# Defaults implement the Hunt 12e validation slice: 4 daemons, 5 minutes.
# Override DURATION_SECS for quick local smoke runs while iterating.
set -euo pipefail

X0XD="${X0XD:-$(pwd)/target/release/x0xd}"
N=4
DURATION_SECS="${DURATION_SECS:-300}"
PUBLISHES_PER_NODE_PER_SEC="${PUBLISHES_PER_NODE_PER_SEC:-1}"
PAYLOAD_PAD_BYTES="${PAYLOAD_PAD_BYTES:-8500}"
TOPIC="x0x/release"

if [ ! -x "$X0XD" ]; then
  echo "x0xd not found at $X0XD" >&2
  echo "Build with: cargo build --release --bin x0xd" >&2
  exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
PROOF_DIR="${PROOF_DIR:-proofs/hunt12e-release-storm-$TS}"
BASE="$PROOF_DIR/runtime"
mkdir -p "$BASE" "$PROOF_DIR/payloads"

PIDS=()
TOKENS=()
API_PORTS=()
BIND_PORTS=()
PUBLISH_PID=""
MONITOR_PID=""

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

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$PROOF_DIR/test.log"; }

log "Hunt 12e release-manifest storm isolation"
log "Proof: $PROOF_DIR"
log "N=$N duration=${DURATION_SECS}s publishes_per_node_per_sec=$PUBLISHES_PER_NODE_PER_SEC pad=${PAYLOAD_PAD_BYTES}B"

for i in $(seq 0 $((N-1))); do
  BIND_PORTS+=("$((19610 + i))")
  API_PORTS+=("$((19710 + i))")
done

for i in $(seq 0 $((N-1))); do
  NAME="node-$((i+1))"
  NODE_DIR="$BASE/$NAME"
  mkdir -p "$NODE_DIR"

  PEERS=()
  for j in $(seq 0 $((N-1))); do
    if [ "$j" -ne "$i" ]; then
      PEERS+=("\"127.0.0.1:${BIND_PORTS[$j]}\"")
    fi
  done
  PEER_LIST=$(IFS=,; echo "${PEERS[*]}")

  cat > "$NODE_DIR/config.toml" <<EOF
instance_name = "hunt12e-$((i+1))"
data_dir = "$NODE_DIR"
bind_address = "127.0.0.1:${BIND_PORTS[$i]}"
api_address = "127.0.0.1:${API_PORTS[$i]}"
log_level = "info"
bootstrap_peers = [$PEER_LIST]
heartbeat_interval_secs = 5
identity_ttl_secs = 60
presence_beacon_interval_secs = 5
presence_event_poll_interval_secs = 2

[update]
enabled = true
gossip_updates = true
fallback_check_interval_minutes = 0
repo = "saorsa-labs/x0x"
EOF

  NO_COLOR=1 RUST_LOG='warn,x0x=info,saorsa_gossip=warn,ant_quic=warn' \
    "$X0XD" --config "$NODE_DIR/config.toml" --skip-update-check >"$NODE_DIR/stdout.log" 2>&1 &
  PIDS+=("$!")
  sleep 0.5
done

log "Launched $N daemons. Waiting for API tokens..."
for i in $(seq 0 $((N-1))); do
  NODE_DIR="$BASE/node-$((i+1))"
  deadline=$((SECONDS + 60))
  until [ -s "$NODE_DIR/api-token" ]; do
    if [ "$SECONDS" -gt "$deadline" ]; then
      log "FAIL: timed out waiting for $NODE_DIR/api-token"
      exit 3
    fi
    sleep 1
  done
  TOKENS+=("$(cat "$NODE_DIR/api-token")")
done

api_get() {
  local idx="$1" path="$2"
  curl -sf -m 5 -H "Authorization: Bearer ${TOKENS[$idx]}" \
    "http://127.0.0.1:${API_PORTS[$idx]}$path"
}

api_post_body() {
  local idx="$1" body_file="$2"
  curl -sf -m 5 -X POST \
    -H "Authorization: Bearer ${TOKENS[$idx]}" \
    -H "Content-Type: application/json" \
    --data @"$body_file" \
    "http://127.0.0.1:${API_PORTS[$idx]}/publish"
}

log "Waiting for mesh formation..."
mesh_deadline=$((SECONDS + 60))
while :; do
  ready=0
  for i in $(seq 0 $((N-1))); do
    peers=$(api_get "$i" /peers 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("peers", [])))' 2>/dev/null || echo 0)
    if [ "$peers" -ge 3 ]; then ready=$((ready+1)); fi
  done
  if [ "$ready" -eq "$N" ]; then break; fi
  if [ "$SECONDS" -gt "$mesh_deadline" ]; then
    log "WARN: mesh did not report 3 peers on every node before storm; continuing to exercise local dispatcher"
    break
  fi
  sleep 2
done

log "Generating release-manifest-shaped payloads"
python3 - "$PROOF_DIR/payloads" "$PAYLOAD_PAD_BYTES" <<'PY'
import base64
import json
import pathlib
import struct
import sys
import time

out = pathlib.Path(sys.argv[1])
pad = int(sys.argv[2])
versions = ["0.19.9", "0.19.10", "0.19.11"]
for idx, version in enumerate(versions):
    assets = []
    for target in [
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ]:
        assets.append({
            "target": target,
            "archive_url": "https://example.com/" + target + "/" + ("a" * (pad // 12)),
            "archive_sha256": "%02x" % (0xA0 + idx) * 32,
            "signature_url": "https://example.com/" + target + ".sig/" + ("b" * (pad // 12)),
        })
    manifest = {
        "schema_version": 1,
        "version": version,
        "timestamp": int(time.time()),
        "assets": assets,
        "skill_url": "https://example.com/SKILL.md/" + ("c" * (pad // 8)),
        "skill_sha256": "ab" * 32,
    }
    manifest_json = json.dumps(manifest, separators=(",", ":")).encode()
    # ML-DSA-65 signatures are large; the exact bytes are intentionally invalid
    # because this harness stresses dispatcher throughput, not release-key trust.
    signature = bytes([0x40 + idx]) * 3309
    payload = struct.pack(">I", len(manifest_json)) + manifest_json + signature
    body = {"topic": "x0x/release", "payload": base64.b64encode(payload).decode()}
    (out / f"manifest-{idx}.json").write_text(json.dumps(body))
PY

CSV="$PROOF_DIR/monitor.csv"
echo "tick_unix,node,pubsub_received,pubsub_completed,pubsub_timed_out,pubsub_max_ms,recv_pubsub_latest,recv_pubsub_max" > "$CSV"

monitor_once() {
  local now="$1"
  for i in $(seq 0 $((N-1))); do
    local name="node-$((i+1))"
    local diag
    diag=$(api_get "$i" /diagnostics/gossip 2>/dev/null || echo '{}')
    python3 -c '
import json
import sys

now, name, csv_path = sys.argv[1:4]
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
disp = d.get("dispatcher") or {}
ps = disp.get("pubsub") or {}
rd = (disp.get("recv_depth") or {}).get("pubsub") or {}
row = [
    now,
    name,
    ps.get("received", -1),
    ps.get("completed", -1),
    ps.get("timed_out", -1),
    ps.get("max_elapsed_ms", -1),
    rd.get("latest", -1),
    rd.get("max", -1),
]
with open(csv_path, "a", encoding="utf-8") as f:
    f.write(",".join(str(v) for v in row) + "\n")
' "$now" "$name" "$CSV" <<<"$diag"
  done
}

log "Snapshotting pre-storm diagnostics"
for i in $(seq 0 $((N-1))); do
  api_get "$i" /diagnostics/gossip > "$BASE/node-$((i+1))/gossip-pre.json" 2>/dev/null || true
done
monitor_once "$(date +%s)"

(
  end=$(( $(date +%s) + DURATION_SECS ))
  count=0
  sleep_between=$(python3 - "$PUBLISHES_PER_NODE_PER_SEC" <<'PY'
import sys
rate = float(sys.argv[1])
print(1.0 / rate if rate > 0 else 1.0)
PY
)
  while [ "$(date +%s)" -lt "$end" ]; do
    for i in $(seq 0 $((N-1))); do
      body="$PROOF_DIR/payloads/manifest-$((count % 3)).json"
      api_post_body "$i" "$body" >/dev/null 2>&1 || true
    done
    count=$((count+1))
    sleep "$sleep_between"
  done
  echo $((count * N)) > "$PROOF_DIR/publish-count.txt"
) &
PUBLISH_PID=$!

(
  end=$(( $(date +%s) + DURATION_SECS ))
  while [ "$(date +%s)" -lt "$end" ]; do
    monitor_once "$(date +%s)"
    sleep 10
  done
) &
MONITOR_PID=$!

log "Storm running (publisher pid=$PUBLISH_PID monitor pid=$MONITOR_PID)"
wait "$PUBLISH_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
monitor_once "$(date +%s)"

log "Snapshotting post-storm diagnostics"
for i in $(seq 0 $((N-1))); do
  api_get "$i" /diagnostics/gossip > "$BASE/node-$((i+1))/gossip-post.json" 2>/dev/null || true
done

published=$(cat "$PROOF_DIR/publish-count.txt" 2>/dev/null || echo 0)
log "Published $published release-topic payloads"

fail_rows=$(awk -F, 'NR > 1 && ($5 != 0) { c++ } END { print c+0 }' "$CSV")
diag_fail_rows=$(awk -F, 'NR > 1 && ($5 < 0) { c++ } END { print c+0 }' "$CSV")
max_timeout=$(awk -F, 'NR > 1 && $5 > m { m=$5 } END { print m+0 }' "$CSV")
max_pubsub_depth=$(awk -F, 'NR > 1 && $8 > m { m=$8 } END { print m+0 }' "$CSV")

{
  echo "# Hunt 12e release-manifest storm"
  echo
  echo "- timestamp: $TS"
  echo "- nodes: $N"
  echo "- duration_secs: $DURATION_SECS"
  echo "- published_payloads: $published"
  echo "- pubsub_timed_out_rows: $fail_rows"
  echo "- diagnostics_failed_rows: $diag_fail_rows"
  echo "- max_pubsub_timed_out: $max_timeout"
  echo "- max_recv_pubsub_depth: $max_pubsub_depth"
} > "$PROOF_DIR/README.md"

log "max pubsub.timed_out=$max_timeout (rows with >0: $fail_rows)"
log "max recv_depth.pubsub=$max_pubsub_depth"

if [ "$fail_rows" -eq 0 ] && [ "$diag_fail_rows" -eq 0 ]; then
  log "RESULT: PASS — PubSub dispatcher watchdog stayed at 0 during release storm"
  echo "RESULT: PASS" > "$PROOF_DIR/summary.txt"
  exit 0
fi

log "RESULT: FAIL — PubSub dispatcher timed out or diagnostics failed during release storm"
echo "RESULT: FAIL" > "$PROOF_DIR/summary.txt"
exit 1
