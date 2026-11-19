#!/usr/bin/env bash
# Aggressive cleanup of non-x0x cruft on the bootstrap fleet.
# These VPSes are dedicated to x0x; everything else is leftover from
# old test/dev iterations and should go.
#
# What this REMOVES:
#   - nginx (stopped + disabled + purged) — exposed on public ports
#   - docker + containerd (stopped + disabled) — heavyweight, orphaned
#   - saorsa-quic-test orphaned processes (killed)
#   - /opt/ant-quic, /opt/ant-quic-test, /opt/communitas-src,
#     /opt/saorsa, /opt/saorsa-gossip, /opt/saorsa-test,
#     /opt/nat-emulation, /opt/containerd
#   - /usr/local/bin/ant-quic{,-test}, saorsa-quic-test, test-agent,
#     x0x-bootstrap, x0x-test
#   - Orphaned systemd units for the above
#
# What this KEEPS:
#   - /opt/x0x — production daemon
#   - /opt/digitalocean — DO provider agent
#   - All system services (sshd, systemd-*, networkd, ufw, etc.)
#   - DO provider agents (do-agent, droplet-agent)
#
# Idempotent. Safe to re-run. DRY_RUN=1 to preview.
set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
SSH="ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

NODES=(
  "saorsa-2:142.93.199.50"
  "saorsa-3:147.182.234.192"
  "saorsa-8:152.42.210.67"
  "saorsa-9:170.64.176.102"
)

PROOF_DIR="proofs/cleanup-non-x0x-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$PROOF_DIR"
LOG="$PROOF_DIR/cleanup.log"

echo "Cleaning non-x0x cruft from bootstrap fleet (DRY_RUN=$DRY_RUN)" | tee "$LOG"
echo "Timestamp: $(date -u +%FT%TZ)" | tee -a "$LOG"
echo | tee -a "$LOG"

REMOTE_SCRIPT=$(cat <<'EOF'
set -u
DRY="${1:-0}"
do_run() {
  if [ "$DRY" = "1" ]; then
    echo "  DRY: $*"
  else
    eval "$@" || echo "  (warning: $* failed, continuing)"
  fi
}

echo "  --- pre-cleanup state ---"
PRE_OPT=$(du -sh /opt/ 2>/dev/null | cut -f1)
PRE_LB=$(ls /usr/local/bin/ 2>/dev/null | wc -l | tr -d ' ')
echo "  /opt size=$PRE_OPT  /usr/local/bin entries=$PRE_LB"

# 1. Kill orphaned saorsa-quic-test processes
QTPIDS=$(pgrep -f saorsa-quic-tes 2>/dev/null || true)
if [ -n "$QTPIDS" ]; then
  echo "  killing orphaned saorsa-quic-tes processes:" $QTPIDS
  do_run "pkill -9 -f saorsa-quic-tes"
fi

# 2. Stop + disable rogue services
for svc in nginx docker containerd; do
  if systemctl is-active "$svc" >/dev/null 2>&1; then
    echo "  systemctl stop+disable $svc"
    do_run "systemctl stop $svc"
    do_run "systemctl disable $svc"
  fi
done

# 3. Mask the rogue services so nothing brings them back
for svc in nginx docker containerd; do
  if systemctl list-unit-files "$svc.service" 2>/dev/null | grep -q "$svc"; then
    echo "  systemctl mask $svc"
    do_run "systemctl mask $svc"
  fi
done

# 4. Purge packages where present (apt)
PURGE_PKGS=""
for pkg in nginx nginx-common nginx-core nginx-full nginx-light docker.io docker-ce containerd containerd.io; do
  if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
    PURGE_PKGS="$PURGE_PKGS $pkg"
  fi
done
if [ -n "$PURGE_PKGS" ]; then
  echo "  apt-get purge -y$PURGE_PKGS"
  do_run "DEBIAN_FRONTEND=noninteractive apt-get purge -y $PURGE_PKGS >/dev/null 2>&1"
  do_run "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y >/dev/null 2>&1"
fi

# 5. Remove non-x0x /opt/ subdirs
for d in /opt/ant-quic /opt/ant-quic-test /opt/communitas-src /opt/saorsa /opt/saorsa-gossip /opt/saorsa-test /opt/nat-emulation /opt/containerd; do
  if [ -e "$d" ]; then
    SIZE=$(du -sh "$d" 2>/dev/null | cut -f1)
    echo "  rm -rf $d  ($SIZE)"
    do_run "rm -rf $d"
  fi
done

# 6. Remove non-x0x /usr/local/bin entries (only the known-bad set, never sweep wholesale)
for f in ant-quic ant-quic-test saorsa-quic-test test-agent x0x-bootstrap x0x-test x0xd-test; do
  if [ -e "/usr/local/bin/$f" ]; then
    echo "  rm /usr/local/bin/$f"
    do_run "rm -f /usr/local/bin/$f"
  fi
done

# 7. Clean orphaned systemd unit files matching non-x0x pattern
for unit in /etc/systemd/system/saorsa-quic-test.service /etc/systemd/system/ant-quic-test.service /etc/systemd/system/x0x-bootstrap.service /etc/systemd/system/test-agent.service /etc/systemd/system/saorsa-test.service /etc/systemd/system/communitas.service; do
  if [ -f "$unit" ]; then
    NAME=$(basename "$unit" .service)
    echo "  remove orphaned systemd unit $unit"
    do_run "systemctl stop $NAME 2>/dev/null"
    do_run "systemctl disable $NAME 2>/dev/null"
    do_run "rm -f $unit"
  fi
done
do_run "systemctl daemon-reload"

# 8. Clean apport/coredump caches (often gigabytes)
for d in /var/crash /var/lib/apport/coredump; do
  if [ -d "$d" ]; then
    SIZE=$(du -sh "$d" 2>/dev/null | cut -f1)
    if [ "$SIZE" != "4.0K" ] && [ -n "$SIZE" ]; then
      echo "  clean $d ($SIZE)"
      do_run "find $d -mindepth 1 -delete 2>/dev/null"
    fi
  fi
done

# 9. Vacuum journald older than 7 days
JOURNAL_SIZE=$(journalctl --disk-usage 2>/dev/null | awk '{print $NF}')
echo "  journald disk usage before vacuum: $JOURNAL_SIZE"
do_run "journalctl --vacuum-time=7d >/dev/null 2>&1"
JOURNAL_AFTER=$(journalctl --disk-usage 2>/dev/null | awk '{print $NF}')
echo "  journald after vacuum: $JOURNAL_AFTER"

echo "  --- post-cleanup state ---"
POST_OPT=$(du -sh /opt/ 2>/dev/null | cut -f1)
POST_LB=$(ls /usr/local/bin/ 2>/dev/null | wc -l | tr -d ' ')
LISTENERS=$(ss -tulnp 2>/dev/null | awk 'NR>1 && $5 !~ /^127\.|^\[::1\]|^.*:22$/' | wc -l | tr -d ' ')
QT_REMAINING=$(pgrep -f saorsa-quic-tes 2>/dev/null | wc -l | tr -d ' ')
X0XD_STATUS=$(systemctl is-active x0xd 2>/dev/null)
X0XD_ENABLED=$(systemctl is-enabled x0xd 2>/dev/null)
echo "  /opt size=$PRE_OPT -> $POST_OPT"
echo "  /usr/local/bin: $PRE_LB -> $POST_LB entries"
echo "  non-loopback non-ssh listeners: $LISTENERS"
echo "  saorsa-quic-tes still running: $QT_REMAINING"
echo "  x0xd: enabled=$X0XD_ENABLED active=$X0XD_STATUS"
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
