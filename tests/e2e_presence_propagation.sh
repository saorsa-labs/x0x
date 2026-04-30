#!/usr/bin/env bash
# =============================================================================
# Presence propagation regression harness
#
# Starts a 4-daemon localhost mesh with short heartbeat/beacon intervals and
# asserts that:
#   1. QUIC peers form,
#   2. presence beacons are actually broadcast on Bulk (log peer_count > 0),
#   3. each daemon receives/processes presence beacons, and
#   4. /presence/online sees the other three agents.
# =============================================================================
set -euo pipefail

X0XD="${X0XD:-$(pwd)/target/release/x0xd}"
N="${N:-4}"
if [ "$N" -lt 2 ]; then
  echo "N must be >= 2" >&2
  exit 2
fi

if [ ! -x "$X0XD" ]; then
  echo "x0xd not found at $X0XD" >&2
  echo "Build with: cargo build --release --bin x0xd" >&2
  exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
PROOF_DIR="${PROOF_DIR:-proofs/e2e-presence-propagation-$TS}"
BASE="$PROOF_DIR/runtime"
mkdir -p "$BASE"

PIDS=()
TOKENS=()
API_PORTS=()
BIND_PORTS=()
FAIL=0

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill -INT "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in "${PIDS[@]:-}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done
  wait "${PIDS[@]:-}" 2>/dev/null || true
}
trap cleanup EXIT

json_len() {
  local key="$1"
  python3 -c 'import json,sys; key=sys.argv[1]; print(len(json.load(sys.stdin).get(key, [])))' "$key" 2>/dev/null || echo 0
}

write_config() {
  local i="$1" dir="$2" bind_port="$3" api_port="$4"
  local peers=()
  for j in $(seq 1 "$N"); do
    [ "$j" = "$i" ] && continue
    peers+=("\"127.0.0.1:$((19210 + j))\"")
  done
  local peer_list
  peer_list=$(IFS=,; echo "${peers[*]}")
  cat >"$dir/config.toml" <<TOML
instance_name = "presence-$i"
data_dir = "$dir"
bind_address = "127.0.0.1:$bind_port"
api_address = "127.0.0.1:$api_port"
log_level = "debug"
bootstrap_peers = [$peer_list]
heartbeat_interval_secs = 5
identity_ttl_secs = 60
presence_beacon_interval_secs = 2
presence_event_poll_interval_secs = 1
TOML
}

printf 'Presence propagation proof: %s\n' "$PROOF_DIR"
printf 'Binary: %s\n' "$X0XD"

for i in $(seq 1 "$N"); do
  dir="$BASE/node-$i"
  mkdir -p "$dir"
  bind_port=$((19210 + i))
  api_port=$((19310 + i))
  BIND_PORTS+=("$bind_port")
  API_PORTS+=("$api_port")
  write_config "$i" "$dir" "$bind_port" "$api_port"
  NO_COLOR=1 RUST_LOG='x0x=debug,saorsa_gossip_presence=debug,saorsa_gossip_membership=info,saorsa_gossip=info,ant_quic=warn' \
    "$X0XD" --config "$dir/config.toml" --skip-update-check >"$dir/log" 2>&1 &
  PIDS+=("$!")
  sleep 0.5
done

for i in $(seq 1 "$N"); do
  api_port="${API_PORTS[$((i-1))]}"
  ready=0
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$api_port/health" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    echo "FAIL node-$i health did not become ready" >&2
    tail -80 "$BASE/node-$i/log" >&2 || true
    exit 1
  fi
  TOKENS+=("$(tr -d '\n' < "$BASE/node-$i/api-token")")
done

# Let bootstrap retry, delayed identity re-announcement, and 2-second presence
# beacons converge. This is intentionally shorter than the live 60-second gate.
sleep "${SETTLE_SECS:-30}"

for i in $(seq 1 "$N"); do
  api_port="${API_PORTS[$((i-1))]}"
  token="${TOKENS[$((i-1))]}"
  dir="$BASE/node-$i"

  peers_json=$(curl -sf -H "Authorization: Bearer $token" "http://127.0.0.1:$api_port/peers")
  online_json=$(curl -sf -H "Authorization: Bearer $token" "http://127.0.0.1:$api_port/presence/online")
  printf '%s\n' "$peers_json" >"$dir/peers.json"
  printf '%s\n' "$online_json" >"$dir/presence-online.json"

  peer_count=$(printf '%s' "$peers_json" | json_len peers)
  online_count=$(printf '%s' "$online_json" | json_len agents)
  beacon_count=$(grep -c 'Broadcast presence beacon' "$dir/log" || true)
  handled_count=$(grep -Ec 'Handled presence beacon|Processed presence beacon' "$dir/log" || true)
  positive_peer_broadcasts=$(grep 'Broadcast presence beacon' "$dir/log" | grep -Ec 'peer_count=([1-9]|[1-9][0-9]+)' || true)

  printf 'node-%s peers=%s online=%s beacon_logs=%s handled_logs=%s positive_broadcasts=%s\n' \
    "$i" "$peer_count" "$online_count" "$beacon_count" "$handled_count" "$positive_peer_broadcasts" \
    | tee -a "$PROOF_DIR/summary.txt"

  if [ "$peer_count" -lt $((N - 1)) ]; then
    echo "FAIL node-$i expected at least $((N - 1)) peers" | tee -a "$PROOF_DIR/summary.txt"
    FAIL=1
  fi
  if [ "$online_count" -lt $((N - 1)) ]; then
    echo "FAIL node-$i expected at least $((N - 1)) online agents" | tee -a "$PROOF_DIR/summary.txt"
    FAIL=1
  fi
  if [ "$positive_peer_broadcasts" -lt 1 ]; then
    echo "FAIL node-$i did not log a presence beacon broadcast with peer_count > 0" | tee -a "$PROOF_DIR/summary.txt"
    FAIL=1
  fi
  if [ "$handled_count" -lt 1 ]; then
    echo "FAIL node-$i did not process any incoming presence beacon" | tee -a "$PROOF_DIR/summary.txt"
    FAIL=1
  fi
done

if [ "$FAIL" != 0 ]; then
  echo "Presence propagation regression FAILED — see $PROOF_DIR" >&2
  exit 1
fi

echo "Presence propagation regression PASS — see $PROOF_DIR"
