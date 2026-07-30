#!/usr/bin/env bash
# =============================================================================
# Authoritative x0xd installer for managed production bootstrap hosts.
#
# Single repository-identified installation path for the production x0xd
# instance (ADR 0026). Installs the tracked systemd/x0xd.service unit and the
# production configuration generated from the tracked config/bootstrap-config.toml
# source to the SAME paths the unit reads, so a fresh host is brought up
# identically to the live fleet.
#
# This replaces the legacy .deployment/deploy.sh — which uploaded
# bootstrap-<node>.toml to /etc/x0x/bootstrap.toml, a path its own installed
# unit never read — and the contradictory top-level .deployment/x0xd.service,
# which read /etc/x0x/x0xd.toml. Both have been retired so the tree no longer
# carries two claimed deployment authorities (ADR 0026, design chapter §1/§6).
#
# The installer does NOT start the service. Starting x0xd is a managed
# transition that requires preflight/postflight over the complete running set
# (design chapter §5); start it explicitly once that is satisfied:
#
#     systemctl start x0xd
#
# Usage (run ON THE TARGET HOST as root):
#   .deployment/install.sh                           # unit + config from tracked sources
#   .deployment/install.sh --binary /path/to/x0xd    # also install the binary
#   .deployment/install.sh --config /path/to/bootstrap-config.toml
#
# Options:
#   --binary PATH   x0xd binary to install at /opt/x0x/x0xd (optional)
#   --unit PATH     override the tracked unit source (default: systemd/x0xd.service)
#   --config PATH   override the tracked config source (default: config/bootstrap-config.toml)
#   -h, --help      show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SRC_DEFAULT="$SCRIPT_DIR/systemd/x0xd.service"
CONFIG_SRC_DEFAULT="$SCRIPT_DIR/config/bootstrap-config.toml"

UNIT_SRC="$UNIT_SRC_DEFAULT"
CONFIG_SRC="$CONFIG_SRC_DEFAULT"
BINARY_SRC="${BINARY:-}"

usage() {
    cat <<'EOF'
Usage: install.sh [options]

Installs the tracked systemd/x0xd.service unit and the production config
(from config/bootstrap-config.toml) to the paths the unit reads.
Run on the target host as root. Does NOT start the service.

Options:
  --binary PATH   x0xd binary to install at /opt/x0x/x0xd (optional)
  --unit PATH     override tracked unit source (default: systemd/x0xd.service)
  --config PATH   override tracked config source (default: config/bootstrap-config.toml)
  -h, --help      show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY_SRC="${2:?--binary requires a path}"; shift 2 ;;
        --unit)   UNIT_SRC="${2:?--unit requires a path}"; shift 2 ;;
        --config) CONFIG_SRC="${2:?--config requires a path}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# Canonical destination paths. systemd/x0xd.service reads /etc/x0x/config.toml,
# so the production config is installed at exactly that path.
UNIT_DST="/etc/systemd/system/x0xd.service"
CONFIG_DST="/etc/x0x/config.toml"
BINARY_DST="/opt/x0x/x0xd"

# --- fail-closed validation of the tracked sources ---------------------------
[ -f "$UNIT_SRC" ]   || { echo "error: unit source not found: $UNIT_SRC" >&2; exit 1; }
[ -f "$CONFIG_SRC" ] || { echo "error: config source not found: $CONFIG_SRC" >&2; exit 1; }

# The installer must write the production config to the same path its selected
# unit reads (design chapter §6 step 2). Refuse to install if they disagree.
unit_config="$(grep -oE -- '--config[= ][^ ]+' "$UNIT_SRC" | head -1 | sed -E 's/^--config[= ]+//')"
if [ -n "$unit_config" ] && [ "$unit_config" != "$CONFIG_DST" ]; then
    echo "error: unit $UNIT_SRC reads '$unit_config' but this installer writes '$CONFIG_DST'" >&2
    echo "       the install path and the unit's --config path must agree" >&2
    exit 1
fi

echo "[install] unit:   $UNIT_SRC -> $UNIT_DST"
echo "[install] config: $CONFIG_SRC -> $CONFIG_DST"
[ -n "$BINARY_SRC" ] && echo "[install] binary: $BINARY_SRC -> $BINARY_DST"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (writes $UNIT_DST, $CONFIG_DST, $BINARY_DST)" >&2
    exit 1
fi

# --- install binary (optional) ----------------------------------------------
if [ -n "$BINARY_SRC" ]; then
    [ -f "$BINARY_SRC" ] || { echo "error: binary not found: $BINARY_SRC" >&2; exit 1; }
    mkdir -p /opt/x0x
    install -m 0755 "$BINARY_SRC" "$BINARY_DST"
fi

# --- install production config to the path the unit reads --------------------
mkdir -p /etc/x0x
install -m 0644 "$CONFIG_SRC" "$CONFIG_DST"

# --- install the tracked systemd unit ---------------------------------------
mkdir -p "$(dirname "$UNIT_DST")"
install -m 0644 "$UNIT_SRC" "$UNIT_DST"

systemctl daemon-reload
systemctl enable x0xd >/dev/null 2>&1 || true

echo "[install] done. unit enabled; service NOT started (managed transition)."
echo "[install] start explicitly:  systemctl start x0xd"
echo "[install] verify:            curl -s http://127.0.0.1:12600/health"
