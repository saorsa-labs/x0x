#!/usr/bin/env bash
# Comprehensive proof run across every measurable dimension:
#
#   - gossip pub/sub throughput (publish_total / delivered_to_subscriber /
#     decode_to_delivery_drops)
#   - direct messaging w/ require_ack_ms peer-liveness RTT
#   - data transfer (file send) bytes/s
#   - NAT traversal (NAT type, can_receive_direct, hole_punch_success_rate,
#     port_mapping_{active,addr})
#   - relay (is_relaying, relay_sessions, relay_bytes_forwarded)
#   - coordinator (is_coordinating, coordination_sessions)
#   - IPv4 / IPv6 mix (external_addrs)
#   - peer lifecycle events (Replaced / Closed{Superseded} counts)
#
# Each daemon gets its own X0X_LOG_DIR with JSON logs, so post-hoc analysis
# can correlate log events with the snapshot deltas.
#
# Usage:
#   tests/e2e_full_measurement.sh [--nodes 5] [--messages 500] \
#       [--proof-dir proofs/full-<ts>]

set -euo pipefail

NODES="${NODES:-5}"
MESSAGES="${MESSAGES:-500}"
TOPIC="measure-$$"
PROOF_DIR=""
# Bind prefer — "v4" = 127.0.0.1, "v6" = ::1, "dual" = ::. We rotate across
# daemons so at least one v4-only and one v6-only is present when `dual` is
# chosen for all (ant-quic defaults to dual-stack but some peers may prefer
# a single family).
BIND_PREFER="dual"

while (( "$#" )); do
    case "$1" in
        --nodes) NODES="$2"; shift 2 ;;
        --messages) MESSAGES="$2"; shift 2 ;;
        --proof-dir) PROOF_DIR="$2"; shift 2 ;;
        --topic) TOPIC="$2"; shift 2 ;;
        --bind-prefer) BIND_PREFER="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

[ -z "$PROOF_DIR" ] && PROOF_DIR="proofs/full-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$PROOF_DIR/logs"
LOG="$PROOF_DIR/measure.log"
REPORT="$PROOF_DIR/measure-report.json"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "Config: NODES=$NODES MESSAGES=$MESSAGES TOPIC=$TOPIC PROOF_DIR=$PROOF_DIR"

BIN="${X0XD_BIN:-target/debug/x0xd}"
CLI="${X0X_BIN:-target/debug/x0x}"
if [ ! -x "$BIN" ] || [ ! -x "$CLI" ]; then
    log "Building x0xd + x0x..."
    cargo build --bin x0xd --bin x0x
fi

# macOS data dir differs from Linux — resolve the token path for each named
# instance here, not inside `api`.
if [ "$(uname)" = "Darwin" ]; then
    DATA_BASE="$HOME/Library/Application Support"
else
    DATA_BASE="$HOME/.local/share"
fi

PIDS=()
PORTS=()
TOKENS=()
cleanup() {
    log "Cleaning up daemons..."
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait "${PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT

# Launch daemons with rotating bind preference. All use --no-hard-coded-bootstrap
# so cross-traffic to the live global mesh doesn't pollute the counters.
for i in $(seq 1 "$NODES"); do
    INSTANCE="measure-$i"
    PORT=$((12800 + i))
    LOG_DIR="$PROOF_DIR/logs/node-$i"
    mkdir -p "$LOG_DIR"

    export X0X_LOG_DIR="$LOG_DIR"
    export X0X_LOG_FORMAT="json"

    log "Launching daemon $i on API port $PORT"
    "$BIN" \
        --name "$INSTANCE" \
        --api-port "$PORT" \
        --no-hard-coded-bootstrap \
        > "$LOG_DIR/stdout.log" \
        2> "$LOG_DIR/stderr.log" &
    PIDS+=($!)
    PORTS+=("$PORT")
done
unset X0X_LOG_DIR X0X_LOG_FORMAT

SETTLE_SECS="${SETTLE_SECS:-20}"
log "Waiting ${SETTLE_SECS}s for daemons to bind + discover each other..."
sleep "$SETTLE_SECS"

for i in $(seq 1 "$NODES"); do
    TOKEN_FILE="$DATA_BASE/x0x-measure-$i/api-token"
    if [ -f "$TOKEN_FILE" ]; then
        TOKENS+=("$(cat "$TOKEN_FILE")")
    else
        log "warn: no api-token at $TOKEN_FILE"
        TOKENS+=("")
    fi
done

api() {
    local idx="$1" method="$2" path="$3" body="${4:-}"
    local port="${PORTS[$((idx - 1))]}"
    local token="${TOKENS[$((idx - 1))]}"
    local args=(-sS -X "$method" "http://127.0.0.1:${port}${path}")
    [ -n "$token" ] && args+=(-H "authorization: Bearer $token")
    [ -n "$body" ] && args+=(-H "content-type: application/json" -d "$body")
    curl "${args[@]}"
}

# --- Snapshot helpers ----------------------------------------------------

snapshot_phase() {
    local phase="$1"
    log "Snapshot: $phase"
    for i in $(seq 1 "$NODES"); do
        local dir="$PROOF_DIR/logs/node-$i"
        api "$i" GET /health          > "$dir/health-$phase.json"           || true
        api "$i" GET /agent           > "$dir/agent-$phase.json"            || true
        api "$i" GET /network/status  > "$dir/network-$phase.json"          || true
        api "$i" GET /diagnostics/connectivity > "$dir/connectivity-$phase.json" || true
        api "$i" GET /diagnostics/gossip > "$dir/gossip-$phase.json"        || true
        api "$i" GET /peers           > "$dir/peers-$phase.json"            || true
    done
}

# --- Phase 1: subscribe every node to the test topic --------------------

snapshot_phase "pre"

log "Installing subscriptions on every node..."
for i in $(seq 1 "$NODES"); do
    api "$i" POST /subscribe "{\"topic\":\"$TOPIC\"}" > /dev/null || true
done

# --- Phase 2: pub/sub throughput ----------------------------------------

log "Publishing $MESSAGES pub/sub messages from node 1 (no delay)"
pub_start=$(date +%s)
for n in $(seq 1 "$MESSAGES"); do
    PAYLOAD=$(printf 'measure-%d' "$n" | base64 | tr -d '\n')
    api 1 POST /publish "{\"topic\":\"$TOPIC\",\"payload\":\"$PAYLOAD\"}" >/dev/null 2>&1 || true
done
pub_end=$(date +%s)
pub_elapsed=$((pub_end - pub_start))
log "Published ${MESSAGES} msgs in ${pub_elapsed}s"
sleep 5

snapshot_phase "mid"

# --- Phase 3: direct messaging with require_ack_ms ----------------------

AGENT_IDS=()
for i in $(seq 1 "$NODES"); do
    AID=$(python3 -c "import json; print(json.load(open('$PROOF_DIR/logs/node-$i/agent-mid.json')).get('agent_id','?'))" 2>/dev/null || echo "?")
    AGENT_IDS+=("$AID")
done

log "DM round-trip from node-1 → node-2 with require_ack_ms=2000"
NODE2_AGENT="${AGENT_IDS[1]}"
DM_PAYLOAD=$(printf 'dm-measure' | base64 | tr -d '\n')
api 1 POST /direct/send \
    "{\"agent_id\":\"$NODE2_AGENT\",\"payload\":\"$DM_PAYLOAD\",\"require_ack_ms\":2000}" \
    > "$PROOF_DIR/logs/node-1/dm-send.json" || true

DM_OK=$(python3 -c "import json; d=json.load(open('$PROOF_DIR/logs/node-1/dm-send.json')); print('ok' if d.get('ok') else 'fail')" 2>/dev/null || echo "fail")
DM_RTT=$(python3 -c "import json; d=json.load(open('$PROOF_DIR/logs/node-1/dm-send.json')); r=d.get('require_ack') or {}; print(r.get('rtt_ms', -1))" 2>/dev/null || echo "-1")
log "DM send: ok=$DM_OK rtt_ms=$DM_RTT"

# --- Phase 4: probe every pair's direct liveness ------------------------

log "Probing every pair's peer liveness (ant-quic probe_peer)..."
{
    printf '['
    FIRST=1
    for i in $(seq 1 "$NODES"); do
        for j in $(seq 1 "$NODES"); do
            [ "$i" = "$j" ] && continue
            MID=$(python3 -c "import json; d=json.load(open('$PROOF_DIR/logs/node-$j/agent-mid.json')); print(d.get('machine_id','?'))" 2>/dev/null || echo "?")
            [ "$MID" = "?" ] && continue
            RESP=$(api "$i" POST "/peers/$MID/probe?timeout_ms=1500" 2>/dev/null || echo '{"ok":false}')
            OK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok'))" 2>/dev/null || echo "False")
            RTT=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('rtt_ms', -1))" 2>/dev/null || echo "-1")
            [ $FIRST -eq 1 ] && FIRST=0 || printf ','
            printf '{"from":%d,"to":%d,"ok":"%s","rtt_ms":%s}' "$i" "$j" "$OK" "$RTT"
        done
    done
    printf ']\n'
} > "$PROOF_DIR/probe-matrix.json"
log "Probe matrix → $PROOF_DIR/probe-matrix.json"

# --- Phase 5: data transfer (file send) ---------------------------------

FILE="$PROOF_DIR/test-payload.bin"
dd if=/dev/urandom of="$FILE" bs=1024 count=256 2>/dev/null
FILE_SIZE=$(stat -f%z "$FILE" 2>/dev/null || stat -c%s "$FILE")
log "File transfer: ${FILE_SIZE} bytes (node-1 → node-2)"

# `x0x send-file` binds to daemon 1 via its api-token env.
export X0X_API_TOKEN="${TOKENS[0]}"
export X0X_API_URL="http://127.0.0.1:${PORTS[0]}"
ft_start_us=$(python3 -c "import time; print(int(time.time()*1_000_000))")
FT_RESP=$("$CLI" --name measure-1 send-file "$NODE2_AGENT" "$FILE" 2>&1 || true)
ft_end_us=$(python3 -c "import time; print(int(time.time()*1_000_000))")
ft_elapsed_us=$((ft_end_us - ft_start_us))
unset X0X_API_TOKEN X0X_API_URL
echo "$FT_RESP" > "$PROOF_DIR/logs/node-1/send-file.txt"
# x0x send-file completes async — post the offer, the bytes flow as
# accept→chunks. We'll treat the offer-send latency as a lower bound.
ft_kbps=$(awk -v b="$FILE_SIZE" -v us="$ft_elapsed_us" 'BEGIN { printf "%.1f", (b * 8 / 1000.0) / (us / 1_000_000.0) }')
log "File transfer offer sent in ${ft_elapsed_us}us (${ft_kbps} kbps initial-RTT-bounded)"

# --- Phase 6: post-run snapshot + report --------------------------------

sleep 5
snapshot_phase "post"

# Build the summary report.
python3 - <<PY > "$REPORT"
import json, os, pathlib

proof = pathlib.Path("$PROOF_DIR")
nodes = int("$NODES")
messages = int("$MESSAGES")

def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None

per_node = []
for i in range(1, nodes + 1):
    d = proof / "logs" / f"node-{i}"
    net   = load(d / "network-post.json") or {}
    conn  = load(d / "connectivity-post.json") or {}
    goss  = load(d / "gossip-post.json") or {}
    peers = load(d / "peers-post.json") or {}
    agent = load(d / "agent-post.json") or {}

    stats = (goss or {}).get("stats", {})
    extern = conn.get("external_addrs", []) or []
    v4 = [a for a in extern if "." in a and ":" in a]
    v6 = [a for a in extern if a.count(":") > 2]

    per_node.append({
        "idx": i,
        "agent_id": agent.get("agent_id"),
        "machine_id": agent.get("machine_id"),
        "port_mapping": {
            "active": conn.get("port_mapping", {}).get("active"),
            "external_addr": conn.get("port_mapping", {}).get("external_addr"),
        },
        "nat_type": conn.get("nat_type"),
        "can_receive_direct": conn.get("can_receive_direct"),
        "has_global_address": conn.get("has_global_address"),
        "external_addrs": {
            "v4": v4,
            "v6": v6,
            "total": len(extern),
        },
        "connections": conn.get("connections", {}),
        "relay": conn.get("relay", {}),
        "coordinator": conn.get("coordinator", {}),
        "avg_rtt_ms": conn.get("avg_rtt_ms"),
        "uptime_s": conn.get("uptime_s"),
        "gossip": {
            "publish_total": stats.get("publish_total"),
            "publish_failed": stats.get("publish_failed"),
            "incoming_total": stats.get("incoming_total"),
            "incoming_decoded": stats.get("incoming_decoded"),
            "incoming_decode_failed": stats.get("incoming_decode_failed"),
            "delivered_to_subscriber": stats.get("delivered_to_subscriber"),
            "subscriber_channel_closed": stats.get("subscriber_channel_closed"),
            "in_flight_decode": stats.get("in_flight_decode"),
            "decode_to_delivery_drops": stats.get("decode_to_delivery_drops"),
        },
        "peer_count": len((peers or {}).get("peers", [])),
    })

# Aggregate pass/fail signals.
failures = []
pub_total = per_node[0]["gossip"]["publish_total"] or 0
if pub_total < messages:
    failures.append(f"publisher publish_total={pub_total} < {messages}")
for n in per_node[1:]:
    delivered = n["gossip"]["delivered_to_subscriber"] or 0
    if delivered < messages:
        failures.append(
            f"node-{n['idx']} delivered_to_subscriber={delivered} < {messages}")
    drops = n["gossip"]["decode_to_delivery_drops"] or 0
    if drops != 0:
        failures.append(f"node-{n['idx']} decode_to_delivery_drops={drops}")

any_relay = any(n.get("relay", {}).get("is_relaying") for n in per_node)
any_v4 = any(n["external_addrs"]["v4"] for n in per_node)
any_v6 = any(n["external_addrs"]["v6"] for n in per_node)

report = {
    "config": {"nodes": nodes, "messages": messages},
    "publish_elapsed_seconds": int("$pub_elapsed"),
    "dm_ok": "$DM_OK",
    "dm_rtt_ms": "$DM_RTT",
    "file_transfer": {
        "bytes": int("$FILE_SIZE"),
        "offer_roundtrip_us": int("$ft_elapsed_us"),
        "initial_kbps": float("$ft_kbps"),
    },
    "any_relay_active": any_relay,
    "any_ipv4_external": any_v4,
    "any_ipv6_external": any_v6,
    "per_node": per_node,
    "failures": failures,
    "passed": len(failures) == 0,
}
print(json.dumps(report, indent=2, default=str))
PY

log "Measurement report → $REPORT"

PASSED=$(python3 -c "import json; print(json.load(open('$REPORT'))['passed'])")
FAIL_COUNT=$(python3 -c "import json; print(len(json.load(open('$REPORT'))['failures']))")
log "PASSED=$PASSED  FAILURES=$FAIL_COUNT"

python3 -c "
import json
d = json.load(open('$REPORT'))
for f in d['failures']:
    print('  FAIL:', f)
" >> "$LOG"

[ "$PASSED" = "True" ] && exit 0 || exit 1
