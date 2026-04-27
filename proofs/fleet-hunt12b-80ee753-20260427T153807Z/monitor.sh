#!/usr/bin/env bash
# 90-minute Hunt 12b validation monitor.
#
# Polls /presence/online and /diagnostics/gossip on every node every 60s and
# evaluates success criteria continuously:
#   - presence_online >= N-1 on every node
#   - dispatcher.{pubsub,membership,bulk}.timed_out == 0
#   - dispatcher.recv_depth_max < 8000
set -uo pipefail

PROOF_DIR="$(cd "$(dirname "$0")" && pwd)"
SSH="ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes"

NODES=(
  "saorsa-2:142.93.199.50"
  "saorsa-3:147.182.234.192"
  "saorsa-6:65.21.157.229"
  "saorsa-7:116.203.101.172"
)
N=${#NODES[@]}
MIN_ONLINE=$((N - 1))
DURATION_SECS=${DURATION_SECS:-5400}   # 90 minutes
INTERVAL_SECS=${INTERVAL_SECS:-60}
RECV_DEPTH_LIMIT=${RECV_DEPTH_LIMIT:-8000}

CSV="$PROOF_DIR/monitor.csv"
LOG="$PROOF_DIR/monitor.log"
SUMMARY="$PROOF_DIR/summary.txt"

echo "tick_unix,tick_iso,node,presence_online,pubsub_received,pubsub_completed,pubsub_timed_out,pubsub_max_ms,membership_received,membership_completed,membership_timed_out,membership_max_ms,bulk_received,bulk_completed,bulk_timed_out,bulk_max_ms,recv_depth_latest,recv_depth_max,recv_capacity_latest" > "$CSV"

started_unix=$(date +%s)
end_unix=$((started_unix + DURATION_SECS))

declare -A FIRST_FAIL_TICK FIRST_FAIL_REASON
fail_min_online=0
fail_timed_out=0
fail_recv_depth=0

probe_node() {
  local node="$1" ip="$2"
  $SSH "root@$ip" '
    TOKEN=$(cat /root/.local/share/x0x/api-token 2>/dev/null)
    OUT=$(curl -sf -m 8 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12600/presence/online 2>/dev/null || echo "{}")
    DIAG=$(curl -sf -m 8 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12600/diagnostics/gossip 2>/dev/null || echo "{}")
    python3 - <<PYEOF
import json, sys
out = json.loads("""$OUT""" or "{}")
diag = json.loads("""$DIAG""" or "{}")
agents = out.get("agents") or out.get("online") or out.get("data") or []
if isinstance(agents, dict):
    agents = agents.get("agents") or agents.get("online") or []
n_online = len(agents) if isinstance(agents, list) else 0
d = diag.get("dispatcher", {}) or {}
ps = d.get("pubsub", {}) or {}
ms = d.get("membership", {}) or {}
bk = d.get("bulk", {}) or {}
print(",".join(str(v) for v in [
  n_online,
  ps.get("received", 0), ps.get("completed", 0), ps.get("timed_out", 0), ps.get("max_elapsed_ms", 0),
  ms.get("received", 0), ms.get("completed", 0), ms.get("timed_out", 0), ms.get("max_elapsed_ms", 0),
  bk.get("received", 0), bk.get("completed", 0), bk.get("timed_out", 0), bk.get("max_elapsed_ms", 0),
  d.get("recv_depth_latest", 0), d.get("recv_depth_max", 0), d.get("recv_capacity_latest", 0),
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
      line="0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
      echo "  $node: PROBE FAILED (SSH or curl error)" | tee -a "$LOG"
    fi
    echo "$now,$iso,$node,$line" >> "$CSV"

    online=$(echo "$line" | cut -d',' -f1)
    ps_to=$(echo "$line" | cut -d',' -f4)
    ms_to=$(echo "$line" | cut -d',' -f8)
    bk_to=$(echo "$line" | cut -d',' -f12)
    depth_max=$(echo "$line" | cut -d',' -f15)
    echo "  $node: online=$online ps_timed_out=$ps_to ms_timed_out=$ms_to bk_timed_out=$bk_to recv_depth_max=$depth_max" | tee -a "$LOG"

    if [ "$online" -lt "$MIN_ONLINE" ]; then
      fail_min_online=$((fail_min_online + 1))
      key="$node:min_online"
      if [ -z "${FIRST_FAIL_TICK[$key]:-}" ]; then
        FIRST_FAIL_TICK[$key]=$tick
        FIRST_FAIL_REASON[$key]="online=$online < $MIN_ONLINE at tick $tick ($iso)"
      fi
    fi
    if [ "$ps_to" -gt 0 ] || [ "$ms_to" -gt 0 ] || [ "$bk_to" -gt 0 ]; then
      fail_timed_out=$((fail_timed_out + 1))
      key="$node:timed_out"
      if [ -z "${FIRST_FAIL_TICK[$key]:-}" ]; then
        FIRST_FAIL_TICK[$key]=$tick
        FIRST_FAIL_REASON[$key]="ps_timed_out=$ps_to ms=$ms_to bk=$bk_to at tick $tick ($iso)"
      fi
    fi
    if [ "$depth_max" -ge "$RECV_DEPTH_LIMIT" ]; then
      fail_recv_depth=$((fail_recv_depth + 1))
      key="$node:recv_depth"
      if [ -z "${FIRST_FAIL_TICK[$key]:-}" ]; then
        FIRST_FAIL_TICK[$key]=$tick
        FIRST_FAIL_REASON[$key]="recv_depth_max=$depth_max >= $RECV_DEPTH_LIMIT at tick $tick ($iso)"
      fi
    fi
  done

  remaining=$((end_unix - now - INTERVAL_SECS))
  if [ "$remaining" -le 0 ]; then
    break
  fi
  sleep "$INTERVAL_SECS"
done

# ── Summary ──
{
  echo "Hunt 12b 90-min fleet monitor"
  echo "============================="
  echo "Commit: $(git -C "$PROOF_DIR/../.." rev-parse HEAD)"
  echo "Started: $(date -u -r "$started_unix" +%FT%TZ)"
  echo "Ended:   $(date -u +%FT%TZ)"
  echo "Nodes (N=$N): ${NODES[*]}"
  echo "Success criteria:"
  echo "  - presence_online >= $MIN_ONLINE on every node"
  echo "  - dispatcher.{pubsub,membership,bulk}.timed_out == 0"
  echo "  - dispatcher.recv_depth_max < $RECV_DEPTH_LIMIT"
  echo
  echo "Ticks completed: $tick"
  echo "Failures by criterion:"
  echo "  - min_online failures: $fail_min_online"
  echo "  - timed_out failures:  $fail_timed_out"
  echo "  - recv_depth failures: $fail_recv_depth"
  echo
  if [ ${#FIRST_FAIL_TICK[@]} -gt 0 ]; then
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
