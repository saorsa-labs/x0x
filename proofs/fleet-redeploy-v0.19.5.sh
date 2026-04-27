#!/usr/bin/env bash
# Redeploy x0xd v0.19.5 (Hunt 12c) to all reachable VPS nodes.
set -euo pipefail

PROOF_DIR="proofs/fleet-redeploy-v0.19.5-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$PROOF_DIR"
LOG="$PROOF_DIR/deploy.log"
exec > >(tee -a "$LOG") 2>&1

BINARY="${BINARY:-target/x86_64-unknown-linux-gnu/release/x0xd}"
SSH="ssh -o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

NODES=(
  "saorsa-2:142.93.199.50"
  "saorsa-3:147.182.234.192"
  "saorsa-6:65.21.157.229"
  "saorsa-7:116.203.101.172"
)

echo "Redeploy x0x v0.19.5 (Hunt 12c)"
echo "Tag commit: $(git rev-list -n 1 v0.19.5)"
echo "Binary: $BINARY ($(ls -la "$BINARY" | awk '{print $5,$6,$7,$8}'))"
echo "Targets: ${NODES[*]}"
echo "Started: $(date -u +%FT%TZ)"
echo "==="

for i in "${!NODES[@]}"; do
  entry="${NODES[$i]}"
  node="${entry%%:*}"
  ip="${entry##*:}"
  echo
  echo "--- $node ($ip) ---"

  echo -n "  Uploading binary... "
  cat "$BINARY" | $SSH "root@$ip" "cat > /tmp/x0xd.v0195 && chmod 755 /tmp/x0xd.v0195" && echo "done"

  echo -n "  Installing + restarting x0xd... "
  $SSH "root@$ip" "install -m 755 /tmp/x0xd.v0195 /opt/x0x/x0xd && rm -f /tmp/x0xd.v0195 && systemctl restart x0xd" && echo "done"

  sleep 3
  echo -n "  Post-deploy version: "
  $SSH "root@$ip" "/opt/x0x/x0xd --version 2>/dev/null | head -1"
  echo -n "  Service active: "
  $SSH "root@$ip" "systemctl is-active x0xd"
  echo -n "  /diagnostics/gossip recv_depth shape: "
  $SSH "root@$ip" 'TOKEN=$(cat /root/.local/share/x0x/api-token 2>/dev/null); curl -sf -m 5 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12600/diagnostics/gossip 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); rd=d.get(\"dispatcher\",{}).get(\"recv_depth\",{}); print(\"per-stream\" if all(k in rd for k in (\"pubsub\",\"membership\",\"bulk\")) else \"FLAT/MISSING\")"'

  if [ "$i" -lt $((${#NODES[@]} - 1)) ]; then
    echo "  Rolling delay 15s before next node..."
    sleep 15
  fi
done

echo
echo "==="
echo "Finished: $(date -u +%FT%TZ)"
