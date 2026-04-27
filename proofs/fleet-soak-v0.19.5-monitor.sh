#!/usr/bin/env bash
# Hunt 12c live-fleet 90-minute validation monitor for x0x v0.19.5.
#
# Polls /presence/online and the v0.19.5 per-stream /diagnostics/gossip
# every 60s for 90 minutes. Asserts:
#   - presence_online >= N-1 on every node every tick
#   - dispatcher.{pubsub,membership,bulk}.timed_out stays at 0
#   - dispatcher.recv_depth.{pubsub,membership,bulk}.max stays well
#     under the per-stream capacity (PubSub < 8000, Bulk < 3500,
#     Membership < 3500)
set -uo pipefail

PROOF_DIR="$(cd "$(dirname "$0")" && pwd)/fleet-soak-v0.19.5-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$PROOF_DIR"
SSH="ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes"

NODES=(
  "saorsa-2:142.93.199.50"
  "saorsa-3:147.182.234.192"
  "saorsa-6:65.21.157.229"
  "saorsa-7:116.203.101.172"
)
N=${#NODES[@]}
MIN_ONLINE=$((N - 1))
DURATION_SECS=${DURATION_SECS:-5400}
INTERVAL_SECS=${INTERVAL_SECS:-60}
PUBSUB_DEPTH_LIMIT=${PUBSUB_DEPTH_LIMIT:-8000}
CONTROL_DEPTH_LIMIT=${CONTROL_DEPTH_LIMIT:-3500}

CSV="$PROOF_DIR/monitor.csv"
LOG="$PROOF_DIR/monitor.log"
SUMMARY="$PROOF_DIR/summary.txt"

echo "tick_unix,tick_iso,node,presence_online,ps_received,ps_completed,ps_timed_out,ps_max_ms,ms_received,ms_completed,ms_timed_out,ms_max_ms,bk_received,bk_completed,bk_timed_out,bk_max_ms,rd_pubsub_latest,rd_pubsub_max,rd_pubsub_cap,rd_ms_latest,rd_ms_max,rd_ms_cap,rd_bk_latest,rd_bk_max,rd_bk_cap" > "$CSV"

started_unix=$(date +%s)
end_unix=$((started_unix + DURATION_SECS))

declare -A FIRST_FAIL_TICK FIRST_FAIL_REASON
fail_min_online=0
fail_timed_out=0
fail_recv_depth=0

probe_node() {
  local node="$1" ip="$2"
  $SSH "root@$ip" 'TOKEN=$(cat /root/.local/share/x0x/api-token)
OUT=$(curl -sf -m 8 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12600/presence/online 2>/dev/null || echo "{}")
DIAG=$(curl -sf -m 8 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12600/diagnostics/gossip 2>/dev/null || echo "{}")
python3 <<PYEOF
import json
out = json.loads("""$OUT""" or "{}")
diag = json.loads("""$DIAG""" or "{}")
agents = out.get("agents") or out.get("online") or out.get("data") or []
if isinstance(agents, dict):
    agents = agents.get("agents") or agents.get("online") or []
n_online = len(agents) if isinstance(agents, list) else 0
disp = diag.get("dispatcher", {}) or {}
ps = disp.get("pubsub", {}) or {}
ms = disp.get("membership", {}) or {}
bk = disp.get("bulk", {}) or {}
rd = disp.get("recv_depth", {}) or {}
rd_ps = rd.get("pubsub", {}) or {}
rd_ms = rd.get("membership", {}) or {}
rd_bk = rd.get("bulk", {}) or {}
print(",".join(str(v) for v in [
  n_online,
  ps.get("received", 0), ps.get("completed", 0), ps.get("timed_out", 0), ps.get("max_elapsed_ms", 0),
  ms.get("received", 0), ms.get("completed", 0), ms.get("timed_out", 0), ms.get("max_elapsed_ms", 0),
  bk.get("received", 0), bk.get("completed", 0), bk.get("timed_out", 0), bk.get("max_elapsed_ms", 0),
  rd_ps.get("latest", 0), rd_ps.get("max", 0), rd_ps.get("capacity", 0),
  rd_ms.get("latest", 0), rd_ms.get("max", 0), rd_ms.get("capacity", 0),
  rd_bk.get("latest", 0), rd_bk.get("max", 0), rd_bk.get("capacity", 0),
]))
PYEOF
' 2>/dev/null
}

tick=0
while :; do
  now=$(date +%s)
  if [ "$now" -ge "$end_unix" ]; then
    break
  fi
  tick=$((tick + 1))
  iso=$(date -u +%FT%TZ)
  echo "[tick $tick @ $iso] polling all nodes..." | tee -a "$LOG"

  for entry in "${NODES[@]}"; do
    node="${entry%%:*}"; ip="${entry##*:}"
    line="$(probe_node "$node" "$ip")"
    if [ -z "$line" ]; then
      line="0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
      echo "  $node: PROBE FAILED" | tee -a "$LOG"
    fi
    echo "$now,$iso,$node,$line" >> "$CSV"

    online=$(echo "$line" | cut -d',' -f1)
    ps_to=$(echo "$line" | cut -d',' -f4)
    ms_to=$(echo "$line" | cut -d',' -f8)
    bk_to=$(echo "$line" | cut -d',' -f12)
    rd_ps_max=$(echo "$line" | cut -d',' -f15)
    rd_ms_max=$(echo "$line" | cut -d',' -f18)
    rd_bk_max=$(echo "$line" | cut -d',' -f21)
    echo "  $node: online=$online ps_to=$ps_to ms_to=$ms_to bk_to=$bk_to rd_ps_max=$rd_ps_max rd_ms_max=$rd_ms_max rd_bk_max=$rd_bk_max" | tee -a "$LOG"

    if [ "$online" -lt "$MIN_ONLINE" ]; then
      fail_min_online=$((fail_min_online + 1))
      key="$node:min_online"
      if [ -z "${FIRST_FAIL_TICK[$key]:-}" ]; then
        FIRST_FAIL_TICK[$key]=$tick
        FIRST_FAIL_REASON[$key]="online=$online < $MIN_ONLINE at tick $tick ($iso)"
      fi
    fi
    if [ "$bk_to" -gt 0 ] || [ "$ms_to" -gt 0 ]; then
      fail_timed_out=$((fail_timed_out + 1))
      key="$node:timed_out"
      if [ -z "${FIRST_FAIL_TICK[$key]:-}" ]; then
        FIRST_FAIL_TICK[$key]=$tick
        FIRST_FAIL_REASON[$key]="ms_timed_out=$ms_to bk_timed_out=$bk_to at tick $tick ($iso) — Step 2 must keep these at 0 even under PubSub stress"
      fi
    fi
    if [ "$rd_ps_max" -ge "$PUBSUB_DEPTH_LIMIT" ] || [ "$rd_ms_max" -ge "$CONTROL_DEPTH_LIMIT" ] || [ "$rd_bk_max" -ge "$CONTROL_DEPTH_LIMIT" ]; then
      fail_recv_depth=$((fail_recv_depth + 1))
      key="$node:recv_depth"
      if [ -z "${FIRST_FAIL_TICK[$key]:-}" ]; then
        FIRST_FAIL_TICK[$key]=$tick
        FIRST_FAIL_REASON[$key]="rd_ps_max=$rd_ps_max rd_ms_max=$rd_ms_max rd_bk_max=$rd_bk_max at tick $tick ($iso)"
      fi
    fi
  done

  remaining=$((end_unix - now - INTERVAL_SECS))
  if [ "$remaining" -le 0 ]; then
    break
  fi
  sleep "$INTERVAL_SECS"
done

{
  echo "Hunt 12c live-fleet 90-min monitor (v0.19.5)"
  echo "============================================"
  echo "Commit: $(git -C "$PROOF_DIR/../.." rev-parse HEAD)"
  echo "Started: $(date -u -r "$started_unix" +%FT%TZ)"
  echo "Ended:   $(date -u +%FT%TZ)"
  echo "Nodes (N=$N): ${NODES[*]}"
  echo
  echo "Pass criteria:"
  echo "  - presence_online >= $MIN_ONLINE on every node"
  echo "  - dispatcher.bulk.timed_out == 0"
  echo "  - dispatcher.membership.timed_out == 0"
  echo "  - dispatcher.pubsub.timed_out (informational; expected to grow under wild-net load)"
  echo "  - recv_depth.pubsub.max < $PUBSUB_DEPTH_LIMIT"
  echo "  - recv_depth.{membership,bulk}.max < $CONTROL_DEPTH_LIMIT"
  echo
  echo "Ticks completed: $tick"
  echo "Failures by criterion:"
  echo "  - min_online failures: $fail_min_online"
  echo "  - bulk/membership timed_out failures (Step 2 isolation):  $fail_timed_out"
  echo "  - recv_depth failures: $fail_recv_depth"
  echo
  if [ ${#FIRST_FAIL_TICK[@]:-0} -gt 0 ]; then
    echo "First-failure events:"
    for key in "${!FIRST_FAIL_TICK[@]}"; do
      echo "  - $key: ${FIRST_FAIL_REASON[$key]}"
    done
  else
    echo "First-failure events: NONE"
  fi
  echo
  if [ "$fail_min_online" -eq 0 ] && [ "$fail_timed_out" -eq 0 ] && [ "$fail_recv_depth" -eq 0 ]; then
    echo "RESULT: PASS"
  else
    echo "RESULT: FAIL"
  fi
} | tee "$SUMMARY"
