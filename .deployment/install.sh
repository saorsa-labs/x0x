#!/usr/bin/env bash
# =============================================================================
# Authoritative x0xd installer for managed bootstrap hosts (ADR 0026).
#
# A manifest consumer (design chapter §1a). The instance inventory lives in
# authority-inventory.json; this installer reads the selected instance's record
# and installs its tracked unit + tracked config to the destinations the record
# declares, so a fresh host is brought up identically to the live fleet. It
# holds no inline instance list and no inline destination paths.
#
# Production is the install default (the manifest's single install-default
# instance: entrypoint install.sh, empty selector_args). Select any other
# install-served instance with a stable selector only — `--instance <id>` —
# never a path-valued flag (ec8d50d): the unit, config, and destination values
# are owned by the manifest record, not repeated on the command line.
#
# This replaces the legacy .deployment/deploy.sh — which uploaded
# bootstrap-<node>.toml to /etc/x0x/bootstrap.toml, a path its own installed
# unit never read — and the contradictory top-level .deployment/x0xd.service,
# which read /etc/x0x/x0xd.toml. Both are retired so the tree carries one
# claimed deployment authority (ADR 0026, design chapter §1/§6).
#
# The installer does NOT start the service. Starting x0xd is a managed
# transition that requires preflight/postflight over the complete running set
# (design chapter §5); start it explicitly once that is satisfied:
#
#     systemctl start x0xd
#
# Usage (run ON THE TARGET HOST as root):
#   .deployment/install.sh                           # production instance (default)
#   .deployment/install.sh --instance testnet        # another install-served instance
#   .deployment/install.sh --binary /path/to/x0xd    # also install the binary
#
# Options:
#   --instance ID   stable instance id from the manifest (default: production)
#   --binary PATH   x0xd binary to install at the instance's binary.destination
#   -h, --help      show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/authority-inventory.json"
INSTANCE=""
BINARY_SRC="${BINARY:-}"

usage() {
    cat <<'EOF'
Usage: install.sh [options]

Manifest-driven installer (ADR 0026, chapter §1a). Installs the selected
instance's tracked systemd unit and config (from authority-inventory.json) to
the destinations the manifest record declares. Run on the target host as root.
Does NOT start the service.

Options:
  --instance ID   stable instance id from the manifest (default: production)
  --binary PATH   x0xd binary to install at the instance's binary.destination
  -h, --help      show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --instance) INSTANCE="${2:?--instance requires an id}"; shift 2 ;;
        --binary)   BINARY_SRC="${2:?--binary requires a path}"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

[ -f "$MANIFEST" ] || { echo "error: authority inventory not found: $MANIFEST" >&2; exit 1; }

# Resolve the selected instance's values from the manifest. With no --instance,
# select the install default (entrypoint install.sh, empty selector_args), which
# is production. Emits: id, unit.source, unit.destination, config.source (empty
# for a generated-config instance), config.destination, binary.destination.
read_instance() {
    python3 - "$MANIFEST" "$INSTANCE" <<'PY'
import sys, json
m = json.load(open(sys.argv[1]))
insts = m.get("instances", [])
want = sys.argv[2]
if want:
    rec = next((i for i in insts if i.get("id") == want), None)
    if rec is None:
        print(f"error: instance '{want}' is not in the manifest", file=sys.stderr); sys.exit(1)
else:
    defs = [i for i in insts
            if i.get("installation", {}).get("entrypoint") == "install.sh"
            and not i.get("installation", {}).get("selector_args")]
    if len(defs) != 1:
        print(f"error: manifest must name exactly one install-default instance "
              f"(entrypoint install.sh, empty selector_args); found {len(defs)}", file=sys.stderr)
        sys.exit(1)
    rec = defs[0]
cfg = rec["config"]
print("\t".join([
    rec["id"],
    rec["unit"]["source"],
    rec["unit"]["destination"],
    cfg.get("source", "") or "",
    cfg["destination"],
    rec["binary"]["destination"],
]))
PY
}

IFS=$'\t' read -r INST_ID UNIT_SRC UNIT_DST CONFIG_SRC CONFIG_DST BINARY_DST < <(read_instance)

# install.sh serves tracked-config instances only. A generated-config instance
# (443) has no tracked config source — its config is produced by its generator
# (deploy-443.sh), which is the fleet-contact entry point for that instance.
if [ -z "$CONFIG_SRC" ]; then
    echo "error: instance '$INST_ID' has no tracked config source; its config is generated" >&2
    echo "       (generated-config instances are served by their generator, not install.sh)" >&2
    exit 1
fi

UNIT_SRC_PATH="$SCRIPT_DIR/$UNIT_SRC"
CONFIG_SRC_PATH="$SCRIPT_DIR/$CONFIG_SRC"

# --- fail-closed validation of the tracked sources ---------------------------
[ -f "$UNIT_SRC_PATH" ]   || { echo "error: unit source not found: $UNIT_SRC_PATH" >&2; exit 1; }
[ -f "$CONFIG_SRC_PATH" ] || { echo "error: config source not found: $CONFIG_SRC_PATH" >&2; exit 1; }

# The installer must write the config to the same path its selected unit reads
# (design chapter §6 step 2). Refuse to install if the unit binds no --config
# path at all or if the derived --config disagrees with the manifest destination.
unit_config="$(grep -oE -- '--config[= ][^ ]+' "$UNIT_SRC_PATH" | head -1 | sed -E 's/^--config[= ]+//')"
if [ -z "$unit_config" ]; then
    echo "error: unit $UNIT_SRC ExecStart carries no --config flag" >&2
    echo "       every managed unit must bind its config path (design chapter §6 step 2)" >&2
    exit 1
elif [ "$unit_config" != "$CONFIG_DST" ]; then
    echo "error: unit $UNIT_SRC reads '$unit_config' but the manifest declares '$CONFIG_DST'" >&2
    echo "       the install destination and the unit's --config path must agree" >&2
    exit 1
fi

echo "[install] instance: $INST_ID"
echo "[install] unit:     $UNIT_SRC -> $UNIT_DST"
echo "[install] config:   $CONFIG_SRC -> $CONFIG_DST"
[ -n "$BINARY_SRC" ] && echo "[install] binary:   $BINARY_SRC -> $BINARY_DST"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (writes $UNIT_DST, $CONFIG_DST, $BINARY_DST)" >&2
    exit 1
fi

# --- install binary (optional) ----------------------------------------------
if [ -n "$BINARY_SRC" ]; then
    [ -f "$BINARY_SRC" ] || { echo "error: binary not found: $BINARY_SRC" >&2; exit 1; }
    mkdir -p "$(dirname "$BINARY_DST")"
    install -m 0755 "$BINARY_SRC" "$BINARY_DST"
fi

# --- install the tracked config to the path the unit reads -------------------
mkdir -p "$(dirname "$CONFIG_DST")"
install -m 0644 "$CONFIG_SRC_PATH" "$CONFIG_DST"

# --- install the tracked systemd unit ---------------------------------------
mkdir -p "$(dirname "$UNIT_DST")"
install -m 0644 "$UNIT_SRC_PATH" "$UNIT_DST"

systemctl daemon-reload
# Enable by the service name the installed unit provides (basename minus .service).
svc_name="$(basename "$UNIT_DST" .service)"
systemctl enable "$svc_name" >/dev/null 2>&1 || true

echo "[install] done. unit enabled; service NOT started (managed transition)."
echo "[install] start explicitly:  systemctl start $svc_name"
echo "[install] verify:            curl -s http://127.0.0.1:12600/health"
