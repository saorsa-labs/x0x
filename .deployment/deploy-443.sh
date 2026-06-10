#!/usr/bin/env bash
# =============================================================================
# Deploy the UDP/443 bootstrap listener (ADR-0011) to one or more VPS nodes.
#
# Each bootstrap host already runs x0xd.service on :5483. This stands up a
# SECOND, independent x0xd-443.service bound to [::]:443 (root, privileged
# port), with its own state dir + machine identity, alongside the existing
# listener. No client ever does this — only operator-run bootstrap nodes.
#
# The 443 config is generated FROM the host's live /etc/x0x/x0xd.toml so it
# can never drift from the running :5483 config: only bind_address, data_dir,
# machine_key_path and api_address are overridden.
#
# Usage:
#   ./deploy-443.sh <node|all>        # deploy
#   DRY_RUN=1 ./deploy-443.sh <node>  # print actions only
#   ./deploy-443.sh --verify <node>   # verify an existing 443 listener
#
#   <node> ∈ nyc sfo helsinki nuremberg singapore sydney all
#
# Idempotent. Safe to re-run. Roll ONE node, verify, then the rest.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SRC="$SCRIPT_DIR/systemd/x0xd-443.service"
DRY_RUN="${DRY_RUN:-0}"
SSH="ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

declare -A NODES=(
  ["nyc"]="142.93.199.50"
  ["sfo"]="147.182.234.192"
  ["helsinki"]="65.21.157.229"
  ["nuremberg"]="116.203.101.172"
  ["singapore"]="152.42.210.67"
  ["sydney"]="170.64.176.102"
)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[FAIL]${NC} $*"; }

VERIFY_ONLY=0
if [ "${1:-}" = "--verify" ]; then VERIFY_ONLY=1; shift; fi
TARGET="${1:-}"
if [ -z "$TARGET" ]; then err "usage: $0 [--verify] <node|all>"; exit 2; fi

# Remote script executed on each host. Reads $DRY from arg 1.
# Single-quoted heredoc — all expansion happens ON THE REMOTE.
REMOTE_DEPLOY=$(cat <<'EOF'
set -eu
DRY="${1:-0}"
LIVE=/etc/x0x/config.toml
GEN=/etc/x0x/x0xd-443.toml
DATA_DIR=/var/lib/x0x-443
do_run() { if [ "$DRY" = 1 ]; then echo "  DRY: $*"; else eval "$@"; fi; }

[ -f "$LIVE" ] || { echo "FATAL: live config $LIVE not found"; exit 1; }

# Sanity: confirm the live config is the :5483 listener before cloning it.
if ! grep -Eq '^[[:space:]]*bind_address[[:space:]]*=' "$LIVE"; then
  echo "FATAL: $LIVE has no bind_address line — refusing to clone"; exit 1
fi

# Generate the 443 config: copy the live one, override exactly 4 keys.
# Any key absent from the live file is appended so the override always lands.
TMP=$(mktemp)
override() { # key value(quoted-literal-to-write)
  local key="$1" val="$2"
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$TMP"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$TMP"
  else
    printf '%s = %s\n' "$key" "$val" >> "$TMP"
  fi
}
cp "$LIVE" "$TMP"
override bind_address '"[::]:443"'
override data_dir "\"$DATA_DIR/data\""
override machine_key_path "\"$DATA_DIR/machine.key\""
# Distinct REST API port: x0xd binds api_address with `?` (fatal on conflict),
# and prod x0xd.service already holds 127.0.0.1:12600. The :443 listener needs
# its own port or it cannot start alongside the :5483 instance.
override api_address '"127.0.0.1:12643"'

echo "--- generated $GEN (diff vs live) ---"
diff -u "$LIVE" "$TMP" || true
echo "-------------------------------------"

do_run "mkdir -p $DATA_DIR/data"
if [ "$DRY" = 1 ]; then echo "  DRY: write $GEN"; else cp "$TMP" "$GEN"; fi
rm -f "$TMP"

# Install/refresh the systemd unit (delivered to /tmp by the local driver).
if [ -f /tmp/x0xd-443.service ]; then
  do_run "install -m 644 /tmp/x0xd-443.service /etc/systemd/system/x0xd-443.service"
  do_run "rm -f /tmp/x0xd-443.service"
fi
do_run "systemctl daemon-reload"
do_run "systemctl enable x0xd-443.service"

# Open UDP/443 if a host firewall is active. Cloud firewalls (DO/Hetzner)
# are managed out-of-band and must also allow UDP/443 — verified separately.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  do_run "ufw allow 443/udp"
  echo "  ufw: allowed 443/udp"
else
  echo "  no active ufw host firewall — ensure the CLOUD firewall allows UDP/443"
fi

do_run "systemctl restart x0xd-443.service"
sleep 2
systemctl is-active --quiet x0xd-443.service && echo "  x0xd-443 active" || { echo "FATAL: x0xd-443 not active"; journalctl -u x0xd-443 -n 30 --no-pager; exit 1; }
EOF
)

REMOTE_VERIFY=$(cat <<'EOF'
set -u
echo "--- x0xd-443.service ---"
systemctl is-active x0xd-443.service 2>/dev/null || echo inactive
echo "--- UDP listeners (expect :443 and :5483 bound by x0xd) ---"
ss -ulnp 2>/dev/null | grep -E ':(443|5483)\b' || echo "  (ss found nothing — check process)"
echo "--- recent x0xd-443 log ---"
journalctl -u x0xd-443 -n 8 --no-pager 2>/dev/null || true
EOF
)

deploy_node() {
  local name="$1" ip="${NODES[$1]}"
  echo
  info "=== $name ($ip) ==="
  if [ "$VERIFY_ONLY" = 0 ]; then
    [ -f "$UNIT_SRC" ] || { err "unit file $UNIT_SRC missing"; return 1; }
    if [ "$DRY_RUN" = 0 ]; then
      scp -q -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "$UNIT_SRC" "root@$ip:/tmp/x0xd-443.service" || { err "$name: scp unit failed"; return 1; }
    fi
    # shellcheck disable=SC2029
    if $SSH "root@$ip" "bash -s -- $DRY_RUN" <<<"$REMOTE_DEPLOY"; then
      ok "$name: 443 listener deployed"
    else
      err "$name: deploy failed"; return 1
    fi
  fi
  $SSH "root@$ip" "bash -s" <<<"$REMOTE_VERIFY" || warn "$name: verify probe failed"
}

if [ "$TARGET" = "all" ]; then
  for n in nyc sfo helsinki nuremberg singapore sydney; do deploy_node "$n"; done
else
  [ -n "${NODES[$TARGET]:-}" ] || { err "unknown node: $TARGET"; exit 2; }
  deploy_node "$TARGET"
fi
echo
ok "done"
