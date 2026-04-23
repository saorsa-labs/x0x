#!/usr/bin/env bash
# Local x0xd spin repro / hammer harness.
#
# Starts N named x0xd instances on localhost with isolated data dirs,
# rolling startup, shared pubsub load, optional direct-message load,
# optional parallel file transfers, explicit announce traffic, pairwise
# connect/probe exercises, and automatic capture when a process crosses a
# CPU threshold.
#
# Designed for the residual CPU-spin hunt described in NEXT-SESSION-PROMPT.md.
# Works on macOS and Linux (uses sample/lldb on macOS, gdb/perf on Linux when
# available).

set -euo pipefail

NODES=6
RUNTIME_SECS=180
ROLLING_DELAY_SECS=8
SETTLE_DELAY_SECS=5
PUBLISH_INTERVAL_MS=250
ANNOUNCE_INTERVAL_SECS=5
CPU_SPIN_THRESHOLD=140
BASE_API_PORT=21101
BASE_BIND_PORT=21201
HEARTBEAT_SECS=5
PRESENCE_BEACON_SECS=5
PRESENCE_POLL_SECS=2
DIRECTORY_DIGEST_SECS=5
GROUP_CARD_REPUBLISH_SECS=5
TOPIC="spin-debug"
BINARY="${X0XD:-$(pwd)/target/release-profiling/x0xd}"
RESULTS_DIR="${X0X_RESULTS_DIR:-/tmp/x0x-spin-local-$(date +%Y%m%d-%H%M%S)}"
RUST_LOG_DEFAULT='info,x0x=debug,x0x::network=debug,x0xd=debug,saorsa_gossip=info,saorsa_gossip_pubsub=debug,ant_quic=info,ant_quic::high_level::endpoint=debug,ant_quic::nat_traversal_api=debug'
RUST_LOG_VALUE="${RUST_LOG:-$RUST_LOG_DEFAULT}"
STOP_ON_CAPTURE=1
BIND_MODE="dual"   # dual | ipv4 | ipv6
PUBLISHERS_PER_NODE=1
DIRECT_SENDERS_PER_NODE=0
DIRECT_INTERVAL_MS=400
DIRECT_PAYLOAD_BYTES=256
DIRECT_REQUIRE_ACK_MS=0
CONNECT_ALL_PAIRS=0
PROBE_INTERVAL_SECS=0
FILE_TRANSFER_WORKERS_PER_NODE=0
FILE_TRANSFER_SIZE_MIB=1
FILE_TRANSFER_INTERVAL_SECS=3
AUTO_ACCEPT_TRANSFERS=1

usage() {
  cat <<'EOF'
Usage: bash scripts/local-spin-debug.sh [options]

Options:
  --nodes N                        Number of local daemons (default: 6)
  --runtime-secs N                Steady-state runtime after startup (default: 180)
  --rolling-delay-secs N          Delay between node starts (default: 8)
  --settle-delay-secs N           Delay after last node starts (default: 5)
  --publish-interval-ms N         PubSub publish loop interval (default: 250)
  --announce-interval-secs N      Explicit /announce interval (default: 5)
  --cpu-threshold N               Capture when process CPU >= N (default: 140)
  --base-api-port N               First API port (default: 21101)
  --base-bind-port N              First QUIC bind port (default: 21201)
  --heartbeat-secs N              Identity heartbeat interval (default: 5)
  --presence-beacon-secs N        Presence beacon interval (default: 5)
  --presence-poll-secs N          Presence poll interval (default: 2)
  --digest-secs N                 Directory digest interval (default: 5)
  --group-card-republish-secs N   Group-card republish interval (default: 5)
  --topic NAME                    Shared pubsub topic (default: spin-debug)
  --bind-mode MODE                dual|ipv4|ipv6 (default: dual)
  --publishers-per-node N         Concurrent pubsub publish loops/node (default: 1)
  --direct-senders-per-node N     Concurrent direct-send loops/node (default: 0)
  --direct-interval-ms N          Direct-send interval (default: 400)
  --direct-payload-bytes N        Direct-send payload size before base64 (default: 256)
  --direct-require-ack-ms N       Optional require_ack_ms for /direct/send (default: 0)
  --connect-all-pairs             POST /agents/connect for every ordered pair after warmup
  --probe-interval-secs N         Write a probe matrix every N seconds (default: 0 = off)
  --file-transfer-workers-per-node N  Parallel file-offer loops/node (default: 0)
  --file-transfer-size-mib N      Size of each reusable file payload (default: 1)
  --file-transfer-interval-secs N Delay between transfer offers/worker (default: 3)
  --no-auto-accept-transfers      Disable receiver auto-accept loop
  --binary PATH                   x0xd binary (default: target/release-profiling/x0xd)
  --results-dir PATH              Artifact directory
  --keep-running-after-capture    Do not stop after first capture
  --help                          Show this help

Examples:
  bash scripts/local-spin-debug.sh
  bash scripts/local-spin-debug.sh --connect-all-pairs --probe-interval-secs 15
  bash scripts/local-spin-debug.sh --publishers-per-node 2 --direct-senders-per-node 1 \
    --file-transfer-workers-per-node 1 --file-transfer-size-mib 8 --runtime-secs 300
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

sleep_ms() {
  local ms="$1"
  python3 - <<PY >/dev/null 2>&1
import time

time.sleep(max(${ms}, 0) / 1000.0)
PY
}

sleep_secs_fractional() {
  local secs="$1"
  python3 - <<PY >/dev/null 2>&1
import time

time.sleep(max(float(${secs}), 0.0))
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --nodes) NODES="$2"; shift 2 ;;
    --runtime-secs) RUNTIME_SECS="$2"; shift 2 ;;
    --rolling-delay-secs) ROLLING_DELAY_SECS="$2"; shift 2 ;;
    --settle-delay-secs) SETTLE_DELAY_SECS="$2"; shift 2 ;;
    --publish-interval-ms) PUBLISH_INTERVAL_MS="$2"; shift 2 ;;
    --announce-interval-secs) ANNOUNCE_INTERVAL_SECS="$2"; shift 2 ;;
    --cpu-threshold) CPU_SPIN_THRESHOLD="$2"; shift 2 ;;
    --base-api-port) BASE_API_PORT="$2"; shift 2 ;;
    --base-bind-port) BASE_BIND_PORT="$2"; shift 2 ;;
    --heartbeat-secs) HEARTBEAT_SECS="$2"; shift 2 ;;
    --presence-beacon-secs) PRESENCE_BEACON_SECS="$2"; shift 2 ;;
    --presence-poll-secs) PRESENCE_POLL_SECS="$2"; shift 2 ;;
    --digest-secs) DIRECTORY_DIGEST_SECS="$2"; shift 2 ;;
    --group-card-republish-secs) GROUP_CARD_REPUBLISH_SECS="$2"; shift 2 ;;
    --topic) TOPIC="$2"; shift 2 ;;
    --bind-mode) BIND_MODE="$2"; shift 2 ;;
    --publishers-per-node) PUBLISHERS_PER_NODE="$2"; shift 2 ;;
    --direct-senders-per-node) DIRECT_SENDERS_PER_NODE="$2"; shift 2 ;;
    --direct-interval-ms) DIRECT_INTERVAL_MS="$2"; shift 2 ;;
    --direct-payload-bytes) DIRECT_PAYLOAD_BYTES="$2"; shift 2 ;;
    --direct-require-ack-ms) DIRECT_REQUIRE_ACK_MS="$2"; shift 2 ;;
    --connect-all-pairs) CONNECT_ALL_PAIRS=1; shift ;;
    --probe-interval-secs) PROBE_INTERVAL_SECS="$2"; shift 2 ;;
    --file-transfer-workers-per-node) FILE_TRANSFER_WORKERS_PER_NODE="$2"; shift 2 ;;
    --file-transfer-size-mib) FILE_TRANSFER_SIZE_MIB="$2"; shift 2 ;;
    --file-transfer-interval-secs) FILE_TRANSFER_INTERVAL_SECS="$2"; shift 2 ;;
    --no-auto-accept-transfers) AUTO_ACCEPT_TRANSFERS=0; shift ;;
    --binary) BINARY="$2"; shift 2 ;;
    --results-dir) RESULTS_DIR="$2"; shift 2 ;;
    --keep-running-after-capture) STOP_ON_CAPTURE=0; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "error: unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

need_cmd curl
need_cmd jq
need_cmd python3

if [[ ! -x "$BINARY" ]]; then
  echo "error: x0xd binary not found at $BINARY" >&2
  echo "hint: cargo build --profile release-profiling --bin x0xd --bin x0x" >&2
  exit 1
fi

if [[ "$BIND_MODE" != "dual" && "$BIND_MODE" != "ipv4" && "$BIND_MODE" != "ipv6" ]]; then
  echo "error: --bind-mode must be one of: dual, ipv4, ipv6" >&2
  exit 1
fi

mkdir -p "$RESULTS_DIR"
STATUS_LOG="$RESULTS_DIR/status.log"
SUMMARY_JSON="$RESULTS_DIR/summary.json"
: > "$STATUS_LOG"

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$STATUS_LOG"
}

declare -a PIDS=()
declare -a BG_PIDS=()
declare -a API_PORTS=()
declare -a BIND_PORTS=()
declare -a TOKENS=()
declare -a NODE_DIRS=()
declare -a NODE_NAMES=()
declare -a AGENT_IDS=()
declare -a MACHINE_IDS=()
declare -A CAPTURED=()
declare -A FILE_PAYLOAD_PATHS=()
declare -A FILE_PAYLOAD_SHAS=()
declare -A FILE_PAYLOAD_SIZES=()

register_bg_pid() {
  local pid="$1"
  BG_PIDS+=("$pid")
}

cleanup() {
  set +e
  log "cleanup: stopping background workload loops"
  for pid in "${BG_PIDS[@]:-}"; do
    [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true
  done
  log "cleanup: stopping x0xd daemons"
  for pid in "${PIDS[@]:-}"; do
    [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

request_json() {
  local token="$1"
  local method="$2"
  local url="$3"
  local body="${4:-}"
  local tmp status out
  tmp=$(mktemp)
  if [[ -n "$body" ]]; then
    status=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' \
      -d "$body" "$url" 2>/dev/null || echo 000)
  else
    status=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $token" "$url" 2>/dev/null || echo 000)
  fi
  out=$(cat "$tmp" 2>/dev/null || true)
  rm -f "$tmp"
  if [[ "$status" == 2* ]]; then
    printf '%s' "$out"
  elif [[ "$status" == 000 ]]; then
    printf '{"ok":false,"error":"curl_failed"}'
  elif [[ -n "$out" ]]; then
    printf '%s' "$out"
  else
    printf '{"ok":false,"error":"http_%s"}' "$status"
  fi
}

wait_for_health() {
  local api_port="$1"
  local deadline=$((SECONDS + 45))
  while true; do
    if curl -sf "http://127.0.0.1:${api_port}/health" >/dev/null 2>&1; then
      return 0
    fi
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep_secs_fractional 0.5
  done
}

wait_for_token() {
  local token_file="$1"
  local deadline=$((SECONDS + 10))
  while true; do
    if [[ -s "$token_file" ]]; then
      tr -d '[:space:]' < "$token_file"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep_secs_fractional 0.2
  done
}

cpu_value_for_pid() {
  local pid="$1"
  ps -o %cpu= -p "$pid" 2>/dev/null | awk '{print int($1 + 0.5)}' || echo 0
}

peer_count_for_node() {
  local idx="$1"
  local token="${TOKENS[$idx]}"
  local api_port="${API_PORTS[$idx]}"
  request_json "$token" GET "http://127.0.0.1:${api_port}/peers" \
    | jq -r 'if type=="array" then length else (.peers // [] | length) end' 2>/dev/null || echo 0
}

write_config() {
  local idx="$1"
  local node_dir="$2"
  local bind_port="$3"
  local api_port="$4"
  local cfg="$node_dir/config.toml"
  local bootstrap_line='bootstrap_peers = []'

  if (( idx > 0 )); then
    local seed_port="${BIND_PORTS[0]}"
    case "$BIND_MODE" in
      dual)
        bootstrap_line="bootstrap_peers = [\"127.0.0.1:${seed_port}\", \"[::1]:${seed_port}\"]"
        ;;
      ipv6)
        bootstrap_line="bootstrap_peers = [\"[::1]:${seed_port}\"]"
        ;;
      ipv4)
        bootstrap_line="bootstrap_peers = [\"127.0.0.1:${seed_port}\"]"
        ;;
    esac
  fi

  local bind_address
  case "$BIND_MODE" in
    dual) bind_address="[::]:${bind_port}" ;;
    ipv6) bind_address="[::1]:${bind_port}" ;;
    ipv4) bind_address="127.0.0.1:${bind_port}" ;;
  esac

  cat > "$cfg" <<EOF
instance_name = "${NODE_NAMES[$idx]}"
data_dir = "${node_dir}"
bind_address = "${bind_address}"
api_address = "127.0.0.1:${api_port}"
log_level = "info"
heartbeat_interval_secs = ${HEARTBEAT_SECS}
presence_beacon_interval_secs = ${PRESENCE_BEACON_SECS}
presence_event_poll_interval_secs = ${PRESENCE_POLL_SECS}
directory_digest_interval_secs = ${DIRECTORY_DIGEST_SECS}
group_card_republish_interval_secs = ${GROUP_CARD_REPUBLISH_SECS}
${bootstrap_line}
EOF
}

start_node() {
  local idx="$1"
  local node_dir="${NODE_DIRS[$idx]}"
  local api_port="${API_PORTS[$idx]}"
  local bind_port="${BIND_PORTS[$idx]}"
  mkdir -p "$node_dir"
  write_config "$idx" "$node_dir" "$bind_port" "$api_port"

  log "starting ${NODE_NAMES[$idx]} api=:${api_port} quic=:${bind_port}"
  X0X_LOG_DIR="$node_dir/logs" RUST_LOG="$RUST_LOG_VALUE" \
    "$BINARY" --config "$node_dir/config.toml" --name "${NODE_NAMES[$idx]}" \
    >"$node_dir/stdout.log" 2>"$node_dir/stderr.log" &
  local pid=$!
  PIDS[$idx]="$pid"

  if ! wait_for_health "$api_port"; then
    log "startup failed for ${NODE_NAMES[$idx]} — tailing logs"
    tail -50 "$node_dir/stdout.log" "$node_dir/stderr.log" >&2 || true
    exit 1
  fi

  local token
  token=$(wait_for_token "$node_dir/api-token") || {
    log "missing api-token for ${NODE_NAMES[$idx]}"
    exit 1
  }
  TOKENS[$idx]="$token"

  local agent_json agent_id machine_id
  agent_json=$(request_json "$token" GET "http://127.0.0.1:${api_port}/agent")
  printf '%s\n' "$agent_json" > "$node_dir/agent.json"
  agent_id=$(printf '%s' "$agent_json" | jq -r '.agent_id // empty')
  machine_id=$(printf '%s' "$agent_json" | jq -r '.machine_id // empty')
  AGENT_IDS[$idx]="$agent_id"
  MACHINE_IDS[$idx]="$machine_id"
  log "ready ${NODE_NAMES[$idx]} pid=${pid} agent=${agent_id:0:16}... machine=${machine_id:0:16}..."
}

verify_mesh() {
  local deadline=$((SECONDS + 60))
  for idx in $(seq 0 $((NODES - 1))); do
    while true; do
      local peers
      peers=$(peer_count_for_node "$idx")
      if [[ "$peers" =~ ^[0-9]+$ ]] && (( peers > 0 || NODES == 1 )); then
        log "mesh ${NODE_NAMES[$idx]} sees ${peers} peer(s)"
        break
      fi
      if (( SECONDS >= deadline )); then
        log "mesh check failed for ${NODE_NAMES[$idx]} after 60s"
        request_json "${TOKENS[$idx]}" GET "http://127.0.0.1:${API_PORTS[$idx]}/diagnostics/connectivity" \
          > "$RESULTS_DIR/${NODE_NAMES[$idx]}-connectivity-failure.json" || true
        exit 1
      fi
      sleep 1
    done
  done
}

snapshot_connectivity() {
  local phase="$1"
  for idx in $(seq 0 $((NODES - 1))); do
    request_json "${TOKENS[$idx]}" GET "http://127.0.0.1:${API_PORTS[$idx]}/network/status" \
      > "$RESULTS_DIR/${NODE_NAMES[$idx]}-network-${phase}.json" || true
    request_json "${TOKENS[$idx]}" GET "http://127.0.0.1:${API_PORTS[$idx]}/diagnostics/connectivity" \
      > "$RESULTS_DIR/${NODE_NAMES[$idx]}-connectivity-${phase}.json" || true
  done
}

warm_subscriptions() {
  for idx in $(seq 0 $((NODES - 1))); do
    local api_port="${API_PORTS[$idx]}"
    local token="${TOKENS[$idx]}"
    request_json "$token" POST "http://127.0.0.1:${api_port}/subscribe" \
      "{\"topic\":\"${TOPIC}\"}" > "$RESULTS_DIR/${NODE_NAMES[$idx]}-subscribe.json"
    request_json "$token" POST "http://127.0.0.1:${api_port}/announce" '{}' \
      > "$RESULTS_DIR/${NODE_NAMES[$idx]}-announce-warm.json"
  done
}

connect_all_pairs() {
  if (( CONNECT_ALL_PAIRS == 0 || NODES < 2 )); then
    return 0
  fi
  log "connecting all ordered agent pairs"
  mkdir -p "$RESULTS_DIR/connect-pairs"
  for from_idx in $(seq 0 $((NODES - 1))); do
    for to_idx in $(seq 0 $((NODES - 1))); do
      (( from_idx == to_idx )) && continue
      local body resp outcome
      body=$(jq -nc --arg agent_id "${AGENT_IDS[$to_idx]}" '{agent_id:$agent_id}')
      resp=$(request_json "${TOKENS[$from_idx]}" POST "http://127.0.0.1:${API_PORTS[$from_idx]}/agents/connect" "$body")
      printf '%s\n' "$resp" > "$RESULTS_DIR/connect-pairs/${NODE_NAMES[$from_idx]}-to-${NODE_NAMES[$to_idx]}.json"
      outcome=$(printf '%s' "$resp" | jq -r '.outcome // .error // "unknown"' 2>/dev/null || echo unknown)
      log "connect ${NODE_NAMES[$from_idx]} -> ${NODE_NAMES[$to_idx]} = ${outcome}"
    done
  done
}

write_probe_matrix() {
  local label="$1"
  local outfile="$RESULTS_DIR/probe-matrix-${label}-$(date +%Y%m%d-%H%M%S).json"
  {
    printf '['
    local first=1
    for from_idx in $(seq 0 $((NODES - 1))); do
      for to_idx in $(seq 0 $((NODES - 1))); do
        (( from_idx == to_idx )) && continue
        local resp ok rtt
        resp=$(request_json "${TOKENS[$from_idx]}" POST \
          "http://127.0.0.1:${API_PORTS[$from_idx]}/peers/${MACHINE_IDS[$to_idx]}/probe?timeout_ms=1500")
        ok=$(printf '%s' "$resp" | jq -r '.ok // false' 2>/dev/null || echo false)
        rtt=$(printf '%s' "$resp" | jq -r '.rtt_ms // -1' 2>/dev/null || echo -1)
        (( first == 1 )) && first=0 || printf ','
        printf '{"from":"%s","to":"%s","ok":%s,"rtt_ms":%s}' \
          "${NODE_NAMES[$from_idx]}" "${NODE_NAMES[$to_idx]}" "$ok" "$rtt"
      done
    done
    printf ']\n'
  } > "$outfile"
  log "probe matrix written: $outfile"
}

start_probe_loop() {
  if (( PROBE_INTERVAL_SECS <= 0 || NODES < 2 )); then
    return 0
  fi
  (
    while true; do
      write_probe_matrix interval
      sleep "$PROBE_INTERVAL_SECS"
    done
  ) &
  register_bg_pid "$!"
}

start_publishers() {
  if (( PUBLISHERS_PER_NODE <= 0 || NODES < 1 )); then
    return 0
  fi
  log "starting pubsub publishers: ${PUBLISHERS_PER_NODE}/node"
  for idx in $(seq 0 $((NODES - 1))); do
    local api_port="${API_PORTS[$idx]}"
    local token="${TOKENS[$idx]}"
    local node_name="${NODE_NAMES[$idx]}"
    for worker in $(seq 1 "$PUBLISHERS_PER_NODE"); do
      (
        local seq=0 msg payload
        while true; do
          seq=$((seq + 1))
          msg="${node_name}/pub/${worker}/${seq}/$(date +%s%N)"
          payload=$(printf '%s' "$msg" | base64 | tr -d '\n')
          curl -sS -X POST \
            -H "Authorization: Bearer ${token}" \
            -H 'Content-Type: application/json' \
            -d "{\"topic\":\"${TOPIC}\",\"payload\":\"${payload}\"}" \
            "http://127.0.0.1:${api_port}/publish" >/dev/null 2>&1 || true
          sleep_ms "$PUBLISH_INTERVAL_MS"
        done
      ) &
      register_bg_pid "$!"
    done
  done
}

target_idx_for_worker() {
  local from_idx="$1"
  local worker="$2"
  local target=$(((from_idx + worker) % NODES))
  if (( target == from_idx )); then
    target=$(((target + 1) % NODES))
  fi
  printf '%s' "$target"
}

start_announcers() {
  if (( ANNOUNCE_INTERVAL_SECS <= 0 || NODES < 1 )); then
    return 0
  fi
  log "starting explicit announcers (interval=${ANNOUNCE_INTERVAL_SECS}s)"
  for idx in $(seq 0 $((NODES - 1))); do
    local api_port="${API_PORTS[$idx]}"
    local token="${TOKENS[$idx]}"
    (
      while true; do
        curl -sS -X POST \
          -H "Authorization: Bearer ${token}" \
          -H 'Content-Type: application/json' \
          -d '{}' \
          "http://127.0.0.1:${api_port}/announce" >/dev/null 2>&1 || true
        sleep "$ANNOUNCE_INTERVAL_SECS"
      done
    ) &
    register_bg_pid "$!"
  done
}

make_direct_payload_b64() {
  local node_name="$1"
  local worker="$2"
  local seq="$3"
  local size="$4"
  python3 - <<PY
import base64
prefix = f"${node_name}/direct/${worker}/${seq}/".encode()
size = max(int(${size}), len(prefix))
payload = (prefix * ((size // len(prefix)) + 1))[:size]
print(base64.b64encode(payload).decode())
PY
}

start_direct_senders() {
  if (( DIRECT_SENDERS_PER_NODE <= 0 || NODES < 2 )); then
    return 0
  fi
  log "starting direct senders: ${DIRECT_SENDERS_PER_NODE}/node payload=${DIRECT_PAYLOAD_BYTES}B ack_ms=${DIRECT_REQUIRE_ACK_MS}"
  for idx in $(seq 0 $((NODES - 1))); do
    local token="${TOKENS[$idx]}"
    local api_port="${API_PORTS[$idx]}"
    local node_name="${NODE_NAMES[$idx]}"
    for worker in $(seq 1 "$DIRECT_SENDERS_PER_NODE"); do
      local target_idx
      target_idx=$(target_idx_for_worker "$idx" "$worker")
      local target_agent_id="${AGENT_IDS[$target_idx]}"
      (
        local seq=0 payload body
        while true; do
          seq=$((seq + 1))
          payload=$(make_direct_payload_b64 "$node_name" "$worker" "$seq" "$DIRECT_PAYLOAD_BYTES")
          if (( DIRECT_REQUIRE_ACK_MS > 0 )); then
            body=$(jq -nc \
              --arg agent_id "$target_agent_id" \
              --arg payload "$payload" \
              --argjson ack "$DIRECT_REQUIRE_ACK_MS" \
              '{agent_id:$agent_id,payload:$payload,require_ack_ms:$ack}')
          else
            body=$(jq -nc \
              --arg agent_id "$target_agent_id" \
              --arg payload "$payload" \
              '{agent_id:$agent_id,payload:$payload}')
          fi
          request_json "$token" POST "http://127.0.0.1:${api_port}/direct/send" "$body" \
            >> "$RESULTS_DIR/${node_name}-direct-send.log" 2>/dev/null || true
          printf '\n' >> "$RESULTS_DIR/${node_name}-direct-send.log"
          sleep_ms "$DIRECT_INTERVAL_MS"
        done
      ) &
      register_bg_pid "$!"
    done
  done
}

payload_key() {
  printf '%s:%s' "$1" "$2"
}

prepare_file_payloads() {
  if (( FILE_TRANSFER_WORKERS_PER_NODE <= 0 || NODES < 2 )); then
    return 0
  fi
  log "preparing reusable file payloads: ${FILE_TRANSFER_WORKERS_PER_NODE}/node size=${FILE_TRANSFER_SIZE_MIB}MiB"
  for idx in $(seq 0 $((NODES - 1))); do
    for worker in $(seq 1 "$FILE_TRANSFER_WORKERS_PER_NODE"); do
      local key path sha size
      key=$(payload_key "$idx" "$worker")
      path="${NODE_DIRS[$idx]}/payload-w${worker}-${FILE_TRANSFER_SIZE_MIB}MiB.bin"
      python3 - <<PY
import os, pathlib
path = pathlib.Path(${path@Q})
size = int(${FILE_TRANSFER_SIZE_MIB}) * 1024 * 1024
if not path.exists() or path.stat().st_size != size:
    path.write_bytes(os.urandom(size))
PY
      read -r size sha < <(python3 - <<PY
import hashlib, pathlib
path = pathlib.Path(${path@Q})
data = path.read_bytes()
print(len(data), hashlib.sha256(data).hexdigest())
PY
)
      FILE_PAYLOAD_PATHS["$key"]="$path"
      FILE_PAYLOAD_SHAS["$key"]="$sha"
      FILE_PAYLOAD_SIZES["$key"]="$size"
    done
  done
}

start_auto_acceptors() {
  if (( FILE_TRANSFER_WORKERS_PER_NODE <= 0 || NODES < 2 || AUTO_ACCEPT_TRANSFERS == 0 )); then
    return 0
  fi
  log "starting auto-accept loops for incoming file offers"
  for idx in $(seq 0 $((NODES - 1))); do
    local token="${TOKENS[$idx]}"
    local api_port="${API_PORTS[$idx]}"
    local node_name="${NODE_NAMES[$idx]}"
    (
      while true; do
        local resp pending_ids transfer_id
        resp=$(request_json "$token" GET "http://127.0.0.1:${api_port}/files/transfers")
        while IFS= read -r transfer_id; do
          [[ -z "$transfer_id" ]] && continue
          request_json "$token" POST "http://127.0.0.1:${api_port}/files/accept/${transfer_id}" '{}' \
            >> "$RESULTS_DIR/${node_name}-file-accept.log" 2>/dev/null || true
          printf '\n' >> "$RESULTS_DIR/${node_name}-file-accept.log"
        done < <(printf '%s' "$resp" | jq -r '.transfers[]? | select(.direction=="Receiving" and .status=="Pending") | .transfer_id' 2>/dev/null || true)
        sleep 1
      done
    ) &
    register_bg_pid "$!"
  done
}

start_file_senders() {
  if (( FILE_TRANSFER_WORKERS_PER_NODE <= 0 || NODES < 2 )); then
    return 0
  fi
  prepare_file_payloads
  start_auto_acceptors
  log "starting file transfer offer loops: ${FILE_TRANSFER_WORKERS_PER_NODE}/node size=${FILE_TRANSFER_SIZE_MIB}MiB interval=${FILE_TRANSFER_INTERVAL_SECS}s"
  for idx in $(seq 0 $((NODES - 1))); do
    local token="${TOKENS[$idx]}"
    local api_port="${API_PORTS[$idx]}"
    local node_name="${NODE_NAMES[$idx]}"
    for worker in $(seq 1 "$FILE_TRANSFER_WORKERS_PER_NODE"); do
      local target_idx target_agent_id key path sha size target_name
      target_idx=$(target_idx_for_worker "$idx" "$worker")
      target_agent_id="${AGENT_IDS[$target_idx]}"
      target_name="${NODE_NAMES[$target_idx]}"
      key=$(payload_key "$idx" "$worker")
      path="${FILE_PAYLOAD_PATHS[$key]}"
      sha="${FILE_PAYLOAD_SHAS[$key]}"
      size="${FILE_PAYLOAD_SIZES[$key]}"
      (
        local seq=0 body resp
        while true; do
          seq=$((seq + 1))
          body=$(jq -nc \
            --arg agent_id "$target_agent_id" \
            --arg filename "${node_name}-to-${target_name}-w${worker}-seq${seq}.bin" \
            --arg sha256 "$sha" \
            --arg path "$path" \
            --argjson size "$size" \
            '{agent_id:$agent_id,filename:$filename,size:$size,sha256:$sha256,path:$path}')
          resp=$(request_json "$token" POST "http://127.0.0.1:${api_port}/files/send" "$body")
          printf '%s\n' "$resp" >> "$RESULTS_DIR/${node_name}-file-send.log"
          sleep "$FILE_TRANSFER_INTERVAL_SECS"
        done
      ) &
      register_bg_pid "$!"
    done
  done
}

transfer_summary() {
  local pending=0 in_progress=0 complete=0 failed=0 rejected=0
  if (( FILE_TRANSFER_WORKERS_PER_NODE <= 0 )); then
    printf 'transfers=off'
    return 0
  fi
  for idx in $(seq 0 $((NODES - 1))); do
    local resp p i c f r
    resp=$(request_json "${TOKENS[$idx]}" GET "http://127.0.0.1:${API_PORTS[$idx]}/files/transfers")
    p=$(printf '%s' "$resp" | jq '[.transfers[]? | select(.status=="Pending")] | length' 2>/dev/null || echo 0)
    i=$(printf '%s' "$resp" | jq '[.transfers[]? | select(.status=="InProgress")] | length' 2>/dev/null || echo 0)
    c=$(printf '%s' "$resp" | jq '[.transfers[]? | select(.status=="Complete")] | length' 2>/dev/null || echo 0)
    f=$(printf '%s' "$resp" | jq '[.transfers[]? | select(.status=="Failed")] | length' 2>/dev/null || echo 0)
    r=$(printf '%s' "$resp" | jq '[.transfers[]? | select(.status=="Rejected")] | length' 2>/dev/null || echo 0)
    pending=$((pending + p))
    in_progress=$((in_progress + i))
    complete=$((complete + c))
    failed=$((failed + f))
    rejected=$((rejected + r))
  done
  printf 'transfers(pending=%d,in_progress=%d,complete=%d,failed=%d,rejected=%d)' \
    "$pending" "$in_progress" "$complete" "$failed" "$rejected"
}

count_nat_warnings() {
  local total=0
  for idx in $(seq 0 $((NODES - 1))); do
    local count=0
    if compgen -G "${NODE_DIRS[$idx]}/logs/*.log" >/dev/null; then
      count=$(rg -n 'WARN.*ant_quic::nat_traversal_api|ERROR.*ant_quic::nat_traversal_api|NAT traversal failed|No successful punch|Phase Punching failed|UnknownTarget' \
        "${NODE_DIRS[$idx]}/logs"/*.log 2>/dev/null | wc -l | tr -d ' ')
    fi
    total=$((total + count))
  done
  printf '%s' "$total"
}

capture_process() {
  local idx="$1"
  local pid="${PIDS[$idx]}"
  local node_name="${NODE_NAMES[$idx]}"
  local node_dir="${NODE_DIRS[$idx]}"
  local api_port="${API_PORTS[$idx]}"
  local token="${TOKENS[$idx]}"
  local outdir="$RESULTS_DIR/capture-${node_name}-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$outdir"

  log "CAPTURE ${node_name} pid=${pid} cpu=$(cpu_value_for_pid "$pid")% → $outdir"

  request_json "$token" GET "http://127.0.0.1:${api_port}/health" > "$outdir/health.json" || true
  request_json "$token" GET "http://127.0.0.1:${api_port}/peers" > "$outdir/peers.json" || true
  request_json "$token" GET "http://127.0.0.1:${api_port}/network/status" > "$outdir/network-status.json" || true
  request_json "$token" GET "http://127.0.0.1:${api_port}/diagnostics/connectivity" > "$outdir/connectivity.json" || true
  request_json "$token" GET "http://127.0.0.1:${api_port}/diagnostics/gossip" > "$outdir/gossip.json" || true
  request_json "$token" GET "http://127.0.0.1:${api_port}/direct/connections" > "$outdir/direct-connections.json" || true
  request_json "$token" GET "http://127.0.0.1:${api_port}/files/transfers" > "$outdir/file-transfers.json" || true
  cp "$node_dir/config.toml" "$outdir/config.toml" || true
  cp "$node_dir/agent.json" "$outdir/agent.json" || true
  tail -200 "$node_dir/stdout.log" > "$outdir/stdout-tail.log" 2>/dev/null || true
  tail -200 "$node_dir/stderr.log" > "$outdir/stderr-tail.log" 2>/dev/null || true

  if [[ "$(uname -s)" == "Darwin" ]]; then
    top -l 1 -pid "$pid" -stats pid,command,cpu,threads,state,time > "$outdir/top.txt" 2>&1 || true
    if command -v sample >/dev/null 2>&1; then
      sample "$pid" 10 1 -mayDie -file "$outdir/sample.txt" >/dev/null 2>&1 || true
    fi
    if command -v lldb >/dev/null 2>&1; then
      lldb --batch -p "$pid" \
        -o 'thread backtrace all' \
        -o 'detach' \
        -o 'quit' > "$outdir/lldb.txt" 2>&1 || true
    fi
  else
    top -b -n 1 -H -p "$pid" > "$outdir/top.txt" 2>&1 || true
    if command -v gdb >/dev/null 2>&1; then
      gdb -batch -p "$pid" \
        -ex 'set pagination off' \
        -ex 'thread apply all bt 25' > "$outdir/gdb.txt" 2>&1 || true
    fi
    if command -v perf >/dev/null 2>&1; then
      perf record -F 999 -g -p "$pid" --call-graph dwarf -- sleep 10 > "$outdir/perf-record.log" 2>&1 || true
      perf report --stdio --no-children --percent-limit 0.5 > "$outdir/perf-report.txt" 2>&1 || true
    fi
    if [[ -d "/proc/$pid/task" ]]; then
      for task_dir in /proc/$pid/task/*; do
        [[ -d "$task_dir" ]] || continue
        local tid
        tid="$(basename "$task_dir")"
        cat "$task_dir/stack" > "$outdir/kernel-stack-$tid.txt" 2>&1 || true
      done
    fi
  fi

  CAPTURED["$pid"]="$outdir"
}

monitor_loop() {
  local deadline=$((SECONDS + RUNTIME_SECS))
  while (( SECONDS < deadline )); do
    local status_line="status"
    for idx in $(seq 0 $((NODES - 1))); do
      local pid="${PIDS[$idx]}"
      if ! kill -0 "$pid" 2>/dev/null; then
        log "process died unexpectedly: ${NODE_NAMES[$idx]} pid=${pid}"
        exit 1
      fi
      local cpu peers
      cpu=$(cpu_value_for_pid "$pid")
      peers=$(peer_count_for_node "$idx")
      status_line+=" ${NODE_NAMES[$idx]}(pid=${pid},cpu=${cpu}%,peers=${peers})"
      if (( cpu >= CPU_SPIN_THRESHOLD )) && [[ -z "${CAPTURED[$pid]:-}" ]]; then
        capture_process "$idx"
        if (( STOP_ON_CAPTURE == 1 )); then
          log "stop-on-capture enabled; ending run after first capture"
          return 0
        fi
      fi
    done
    if (( FILE_TRANSFER_WORKERS_PER_NODE > 0 )); then
      status_line+=" $(transfer_summary)"
    fi
    if (( PROBE_INTERVAL_SECS > 0 )); then
      status_line+=" nat_warnings=$(count_nat_warnings)"
    fi
    log "$status_line"
    sleep 5
  done
}

for idx in $(seq 0 $((NODES - 1))); do
  NODE_NAMES[$idx]="spin-$((idx + 1))"
  API_PORTS[$idx]=$((BASE_API_PORT + idx))
  BIND_PORTS[$idx]=$((BASE_BIND_PORT + idx))
  NODE_DIRS[$idx]="$RESULTS_DIR/${NODE_NAMES[$idx]}"
done

log "results dir: $RESULTS_DIR"
log "binary: $BINARY"
log "nodes: $NODES | runtime: ${RUNTIME_SECS}s | rolling delay: ${ROLLING_DELAY_SECS}s | bind mode: $BIND_MODE"
log "heartbeat=${HEARTBEAT_SECS}s presence_beacon=${PRESENCE_BEACON_SECS}s digest=${DIRECTORY_DIGEST_SECS}s publish_interval=${PUBLISH_INTERVAL_MS}ms"
log "workload: pub=${PUBLISHERS_PER_NODE}/node direct=${DIRECT_SENDERS_PER_NODE}/node file=${FILE_TRANSFER_WORKERS_PER_NODE}/node connect_all_pairs=${CONNECT_ALL_PAIRS} probe_interval=${PROBE_INTERVAL_SECS}s"

for idx in $(seq 0 $((NODES - 1))); do
  start_node "$idx"
  if (( idx + 1 < NODES )); then
    log "waiting ${ROLLING_DELAY_SECS}s before next node"
    sleep "$ROLLING_DELAY_SECS"
  fi
done

log "waiting ${SETTLE_DELAY_SECS}s for mesh settle"
sleep "$SETTLE_DELAY_SECS"
verify_mesh
snapshot_connectivity pre
warm_subscriptions
connect_all_pairs
if (( PROBE_INTERVAL_SECS > 0 )); then
  write_probe_matrix pre
fi
start_probe_loop
start_publishers
start_announcers
start_direct_senders
start_file_senders
monitor_loop
snapshot_connectivity post
if (( PROBE_INTERVAL_SECS > 0 )); then
  write_probe_matrix post
fi

NAT_WARNING_TOTAL=$(count_nat_warnings)

python3 - <<PY > "$SUMMARY_JSON"
import json
summary = {
    "results_dir": ${RESULTS_DIR@Q},
    "nodes": ${NODES},
    "runtime_secs": ${RUNTIME_SECS},
    "cpu_spin_threshold": ${CPU_SPIN_THRESHOLD},
    "captured": ${#CAPTURED[@]},
    "publishers_per_node": ${PUBLISHERS_PER_NODE},
    "direct_senders_per_node": ${DIRECT_SENDERS_PER_NODE},
    "direct_require_ack_ms": ${DIRECT_REQUIRE_ACK_MS},
    "file_transfer_workers_per_node": ${FILE_TRANSFER_WORKERS_PER_NODE},
    "file_transfer_size_mib": ${FILE_TRANSFER_SIZE_MIB},
    "connect_all_pairs": bool(${CONNECT_ALL_PAIRS}),
    "probe_interval_secs": ${PROBE_INTERVAL_SECS},
    "nat_warning_lines": ${NAT_WARNING_TOTAL},
}
print(json.dumps(summary, indent=2))
PY

log "completed. summary: $SUMMARY_JSON"
if (( ${#CAPTURED[@]} == 0 )); then
  log "no spin captured above ${CPU_SPIN_THRESHOLD}% during this run"
else
  log "captures written under $RESULTS_DIR"
fi
