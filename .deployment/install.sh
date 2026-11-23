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
#   .deployment/install.sh --launcher /path/to/x0x-launcher  # opt in (#1378)
#   .deployment/install.sh --launcher                # opt in, fetch the signed launcher
#
# Options:
#   --instance ID     stable instance id from the manifest (default: production)
#   --binary PATH     x0xd binary to install at the instance's binary.destination
#   --launcher [PATH] run x0xd through the stable launcher (off by default); with
#                     no PATH, fetch the release's signed x0x-launcher asset for
#                     the installed x0xd's version and verify it with GPG
#   -h, --help        show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Saorsa Labs release signing key (primary fingerprint of SAORSA_PUBLIC_KEY.asc).
# scripts/ci/check-installer-fingerprints.py fails CI if it drifts.
TRUSTED_FPR="CEB3506E7DCB8A2DD2D679E8EDDA4827D89C0F29"
RELEASE_BASE="${X0X_RELEASE_BASE:-https://github.com/saorsa-labs/x0x/releases/download}"
ANCHOR_DIR="${X0X_LAUNCHER_ANCHOR_DIR:-/etc/x0x/launcher}"
MANIFEST="$SCRIPT_DIR/authority-inventory.json"
INSTANCE=""
BINARY_SRC="${BINARY:-}"
LAUNCHER_SRC=""

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
  --launcher [PATH]
                  install this x0x-launcher next to x0xd and add a drop-in
                  that runs x0xd through it (off by default; x0xd must have
                  started once, so its data directory exists). With no PATH,
                  fetch the x0x-launcher-<platform>.tar.gz asset of the
                  installed x0xd's release and verify its GPG signature
                  against the pinned release key (needs curl and gpg). The
                  install also writes the root-owned plan anchor of the
                  install (/etc/x0x/launcher). Without the flag, an earlier
                  launcher drop-in, and this unit's entry in the anchor, are
                  removed.
  -h, --help      show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --instance) INSTANCE="${2:?--instance requires an id}"; shift 2 ;;
        --binary)   BINARY_SRC="${2:?--binary requires a path}"; shift 2 ;;
        --launcher)
            if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then
                LAUNCHER_SRC="$2"; shift 2
            else
                LAUNCHER_SRC="fetch"; shift
            fi ;;
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
LAUNCHER_DST="$(dirname "$BINARY_DST")/x0x-launcher"
[ -n "$LAUNCHER_SRC" ] && echo "[install] launcher: $LAUNCHER_SRC -> $LAUNCHER_DST"

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

# Enable by the service name the installed unit provides (basename minus .service).
svc_name="$(basename "$UNIT_DST" .service)"

# --- fetch the signed launcher (#2012, opt-in) -------------------------------
# The release asset x0x-launcher-<platform>.tar.gz of the installed x0xd's own
# version, its .sha256 and its GPG signature (.asc). The signature must be a
# VALIDSIG of the pinned release key, checked in a throwaway GnuPG home.
fetch_launcher() {
    local version platform tmp archive key_fprs status signers expected actual
    command -v curl >/dev/null 2>&1 || { echo "error: --launcher with no path needs curl" >&2; return 1; }
    command -v gpg >/dev/null 2>&1 || { echo "error: --launcher with no path needs gpg" >&2; return 1; }
    version="$("$BINARY_DST" --version 2>/dev/null | awk '{print $NF; exit}')"
    version="${version#v}"
    case "$version" in
        [0-9]*.[0-9]*.[0-9]*) ;;
        *) echo "error: cannot read the version of $BINARY_DST (got '$version')" >&2; return 1 ;;
    esac
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) platform="linux-x64-gnu" ;;
        Linux-aarch64|Linux-arm64) platform="linux-arm64-gnu" ;;
        *) echo "error: no released x0x-launcher for $(uname -s) $(uname -m)" >&2; return 1 ;;
    esac
    archive="x0x-launcher-$platform.tar.gz"
    tmp="$(mktemp -d)" || { echo "error: mktemp failed" >&2; return 1; }
    if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
        echo "error: mktemp gave no directory" >&2; return 1
    fi
    LAUNCHER_TMP="$tmp"
    echo "[install] fetching $archive for v$version"
    for name in "$archive" "$archive.sha256" "$archive.asc" SAORSA_PUBLIC_KEY.asc; do
        curl -sfL "$RELEASE_BASE/v$version/$name" -o "$tmp/$name" \
            || { echo "error: cannot fetch $RELEASE_BASE/v$version/$name" >&2; return 1; }
    done
    expected="$(awk 'NR == 1 {print tolower($1)}' "$tmp/$archive.sha256")"
    actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
    if [ "${#expected}" -ne 64 ] || [ "$expected" != "$actual" ]; then
        echo "error: $archive does not match its .sha256" >&2; return 1
    fi
    mkdir -m 700 "$tmp/gnupg"
    key_fprs="$(gpg --homedir "$tmp/gnupg" --batch --with-colons --show-keys \
        --fingerprint "$tmp/SAORSA_PUBLIC_KEY.asc" 2>/dev/null | awk -F: '$1 == "fpr" {print toupper($10)}')"
    if ! printf '%s\n' "$key_fprs" | grep -qx "$TRUSTED_FPR"; then
        echo "error: SAORSA_PUBLIC_KEY.asc is not the pinned release key ($TRUSTED_FPR)" >&2; return 1
    fi
    gpg --homedir "$tmp/gnupg" --batch --quiet --import "$tmp/SAORSA_PUBLIC_KEY.asc" >/dev/null 2>&1 \
        || { echo "error: gpg could not import the release key" >&2; return 1; }
    status="$(gpg --homedir "$tmp/gnupg" --batch --status-fd 1 \
        --verify "$tmp/$archive.asc" "$tmp/$archive" 2>/dev/null)" \
        || { echo "error: the GPG signature of $archive is not valid" >&2; return 1; }
    signers="$(printf '%s\n' "$status" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" {print toupper($3); if (NF >= 12) print toupper($12)}')"
    if ! printf '%s\n' "$signers" | grep -qx "$TRUSTED_FPR"; then
        echo "error: $archive was not signed by the pinned release key ($TRUSTED_FPR)" >&2; return 1
    fi
    tar -xzf "$tmp/$archive" -C "$tmp" "x0x-launcher-$platform/x0x-launcher" \
        || { echo "error: $archive holds no x0x-launcher-$platform/x0x-launcher" >&2; return 1; }
    LAUNCHER_SRC="$tmp/x0x-launcher-$platform/x0x-launcher"
    echo "[install] verified $archive (sha256 $actual, GPG $TRUSTED_FPR)"
}

# --- stable launcher drop-in (#1378, opt-in) ---------------------------------
LAUNCHER_DROPIN="$(dirname "$UNIT_DST")/$svc_name.service.d/30-x0x-launcher.conf"
LAUNCHER_TMP=""
trap 'if [ -n "$LAUNCHER_TMP" ]; then rm -rf "$LAUNCHER_TMP"; fi' EXIT
if [ "$LAUNCHER_SRC" = "fetch" ]; then
    if ! fetch_launcher; then
        echo "error: the launcher was not fetched; the launcher, its drop-in and the plan anchor" >&2
        echo "       are unchanged (the unit and config above, and any --binary, are installed)" >&2
        exit 1
    fi
fi
if [ -n "$LAUNCHER_SRC" ]; then
    # The helper installs the launcher, the plan anchor of the install and the
    # drop-in, each atomically. On a failure it leaves no drop-in, so the
    # reload below restores the direct job before the error exit; exit 2 is a
    # refused anchor change that changed nothing (a host journal in flight).
    status=0
    python3 "$SCRIPT_DIR/launcher-dropin.py" \
        --unit "$UNIT_DST" --binary "$BINARY_DST" \
        --launcher-source "$LAUNCHER_SRC" --launcher "$LAUNCHER_DST" \
        --instance "$INST_ID" --dropin "$LAUNCHER_DROPIN" --anchor-dir "$ANCHOR_DIR" || status=$?
    if [ "$status" -eq 2 ]; then
        systemctl daemon-reload
        echo "error: the launcher step changed nothing: the launcher, its drop-in and the plan" >&2
        echo "       anchor are as they were (the unit and config above, and any --binary, are installed)" >&2
        exit 1
    elif [ "$status" -eq 4 ]; then
        systemctl daemon-reload
        echo "error: the launcher step failed part way and its clean-up failed (see above); the" >&2
        echo "       drop-in of $svc_name is left as it was; the unit and config above, and any --binary, are installed" >&2
        exit 1
    elif [ "$status" -ne 0 ]; then
        systemctl daemon-reload
        echo "error: the launcher drop-in is not installed and $INST_ID is out of the plan anchor;" >&2
        echo "       $svc_name runs x0xd directly (the unit and config above, and any --binary, are installed)" >&2
        exit 1
    fi
elif [ -f "$LAUNCHER_DROPIN" ]; then
    if ! python3 "$SCRIPT_DIR/launcher-dropin.py" --remove \
        --binary "$BINARY_DST" --instance "$INST_ID" \
        --dropin "$LAUNCHER_DROPIN" --anchor-dir "$ANCHOR_DIR"; then
        echo "error: the launcher drop-in and the plan anchor are kept (the unit and config" >&2
        echo "       above, and any --binary, are installed)" >&2
        exit 1
    fi
fi

systemctl daemon-reload
if ! systemctl enable "$svc_name" >/dev/null 2>&1; then
    echo "[install] ERROR: systemctl enable $svc_name failed" >&2
    exit 1
fi

echo "[install] done. unit enabled; service NOT started (managed transition)."
echo "[install] start explicitly:  systemctl start $svc_name"
echo "[install] verify:            curl -s http://127.0.0.1:12600/health"
