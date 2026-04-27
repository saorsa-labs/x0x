#!/usr/bin/env bash
set -euo pipefail

PROOF_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="${BINARY:-target/x86_64-unknown-linux-gnu/release/x0xd}"
SSH="ssh -o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

NODES=(
  "saorsa-2:142.93.199.50"
  "saorsa-3:147.182.234.192"
  "saorsa-6:65.21.157.229"
  "saorsa-7:116.203.101.172"
)

LOG="$PROOF_DIR/deploy.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "Deploy commit: $(git rev-parse HEAD)"
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
  echo -n "  Pre-deploy version: "
  $SSH "root@$ip" "/opt/x0x/x0xd --version 2>/dev/null | head -1" || echo "unknown"

  echo -n "  Uploading binary... "
  cat "$BINARY" | $SSH "root@$ip" "cat > /tmp/x0xd.hunt12b && chmod 755 /tmp/x0xd.hunt12b" && echo "done"

  echo -n "  Installing + restarting x0xd... "
  $SSH "root@$ip" "install -m 755 /tmp/x0xd.hunt12b /opt/x0x/x0xd && rm -f /tmp/x0xd.hunt12b && systemctl restart x0xd" && echo "done"

  echo -n "  Post-deploy version: "
  sleep 3
  $SSH "root@$ip" "/opt/x0x/x0xd --version 2>/dev/null | head -1"

  echo -n "  Service active: "
  $SSH "root@$ip" "systemctl is-active x0xd"

  if [ "$i" -lt $((${#NODES[@]} - 1)) ]; then
    echo "  Rolling delay 15s before next node..."
    sleep 15
  fi
done

echo
echo "==="
echo "Finished: $(date -u +%FT%TZ)"
