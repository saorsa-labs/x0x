#!/usr/bin/env bash
# Harden all 6 saorsa-labs bootstrap nodes:
#   1. systemctl enable x0xd       — auto-start on boot
#   2. clean leaked .x0x-upgrade-* working dirs
#   3. remove legacy /etc/x0x/{bootstrap.toml,x0xd-test.toml}
#   4. remove stale binaries (x0xd-dhat-old, x0xd.backup, x0xd.bak, old x0x CLI)
#
# Idempotent. Safe to re-run. Pass DRY_RUN=1 to only print actions.
set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
SSH="ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

NODES=(
  "saorsa-2:142.93.199.50"
  "saorsa-3:147.182.234.192"
  "saorsa-8:152.42.210.67"
  "saorsa-9:170.64.176.102"
)

PROOF_DIR="proofs/harden-bootstrap-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$PROOF_DIR"
LOG="$PROOF_DIR/harden.log"

echo "Hardening bootstrap fleet (DRY_RUN=$DRY_RUN)" | tee "$LOG"
echo "Timestamp: $(date -u +%FT%TZ)" | tee -a "$LOG"
echo | tee -a "$LOG"

# Remote script — receives DRY_RUN as first positional argument.
# Single-quoted heredoc so all $vars are expanded ON THE REMOTE.
REMOTE_SCRIPT=$(cat <<'EOF'
set -u
DRY="${1:-0}"
do_run() {
  if [ "$DRY" = "1" ]; then
    echo "  DRY: $*"
  else
    eval "$@"
  fi
}

# 1. enable x0xd at boot
ENABLED=$(systemctl is-enabled x0xd 2>/dev/null || echo unknown)
if [ "$ENABLED" != "enabled" ]; then
  echo "  systemctl enable x0xd  (was: $ENABLED)"
  do_run systemctl enable x0xd
else
  echo "  systemctl enable x0xd  (already enabled)"
fi

# 2. clean leaked .x0x-upgrade-* working dirs (any age — they're upgrade scratch dirs that should be cleaned per-upgrade)
LEAK_COUNT=$(find /opt/x0x -maxdepth 1 -name ".x0x-upgrade-*" -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$LEAK_COUNT" -gt 0 ]; then
  echo "  remove $LEAK_COUNT leaked /opt/x0x/.x0x-upgrade-* dirs"
  do_run "find /opt/x0x -maxdepth 1 -name '.x0x-upgrade-*' -type d -exec rm -rf {} +"
fi

# 3. legacy /etc/x0x configs
for f in /etc/x0x/bootstrap.toml /etc/x0x/bootstrap.toml.bak /etc/x0x/x0xd-test.toml; do
  if [ -f "$f" ]; then
    echo "  rm $f  (legacy)"
    do_run "rm -f $f"
  fi
done

# 4. stale binaries — anything in /opt/x0x that is not the live x0xd
for f in /opt/x0x/x0x /opt/x0x/x0xd-dhat-old /opt/x0x/x0xd.backup /opt/x0x/x0xd.bak /opt/x0x/x0xd.codex; do
  if [ -f "$f" ]; then
    SIZE=$(du -h "$f" | cut -f1)
    echo "  rm $f  ($SIZE)"
    do_run "rm -f $f"
  fi
done

# Empty config.toml in /opt/x0x is a leftover from before /etc/x0x existed
if [ -f /opt/x0x/config.toml ] && [ ! -s /opt/x0x/config.toml ]; then
  echo "  rm /opt/x0x/config.toml (empty leftover)"
  do_run "rm -f /opt/x0x/config.toml"
fi

# Empty tests/ subdir
if [ -d /opt/x0x/tests ] && [ -z "$(ls -A /opt/x0x/tests 2>/dev/null)" ]; then
  echo "  rmdir /opt/x0x/tests (empty)"
  do_run "rmdir /opt/x0x/tests"
fi

echo "  --- post-harden state ---"
ENABLED2=$(systemctl is-enabled x0xd 2>/dev/null || echo unknown)
ACTIVE=$(systemctl is-active x0xd 2>/dev/null || echo unknown)
LEAK2=$(find /opt/x0x -maxdepth 1 -name ".x0x-upgrade-*" -type d 2>/dev/null | wc -l | tr -d ' ')
SIZE=$(du -sh /opt/x0x 2>/dev/null | cut -f1)
echo "  enabled=$ENABLED2 active=$ACTIVE upgrade_leak=$LEAK2 /opt/x0x_size=$SIZE"
EOF
)

for entry in "${NODES[@]}"; do
  node="${entry%%:*}"; ip="${entry##*:}"
  echo "=== $node ($ip) ===" | tee -a "$LOG"
  $SSH "root@$ip" "bash -s -- $DRY_RUN" <<<"$REMOTE_SCRIPT" 2>&1 | tee -a "$LOG"
  echo | tee -a "$LOG"
done

echo | tee -a "$LOG"
echo "Done. Proof: $PROOF_DIR" | tee -a "$LOG"
