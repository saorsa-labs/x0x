#!/usr/bin/env bash
# =============================================================================
# Static repository authority check for managed x0xd deployment.
#
# Governing decision: ADR 0026 (Managed x0xd Deployment Has Distinct Roots
# and Closed Resolution), design chapter §3 "Static repository authority
# check". Reconciles the deployment artifacts under .deployment/ against the
# authoritative instance inventory and fails closed on any:
#
#   C1  competing/second production authority (the retired top-level unit);
#   C2  production unit that binds no --config, or whose --config disagrees
#       with the path the installer writes (§6 step 2);
#   C3  declared instance whose tracked unit or config source is missing;
#   C4  discovered unit/config that maps to no declared instance (orphan);
#   C5  two units that resolve the same effective root (duplicate root); or
#   C6  deploy-443.sh cloning a non-authoritative live config (comment/body
#       mismatch).
#
# This is the STATIC check. It reconciles tracked repository artifacts only;
# it performs no fleet contact and is NOT the PID-bound runtime observation of
# design chapter §4. It is reached by `just deploy-check` (part of `just
# check`) and by pull-request CI.
#
# Usage:
#   check-authority.sh              # check the real .deployment/ tree
#   check-authority.sh --root DIR   # check a deployment dir copied to DIR
#   check-authority.sh --self-test  # exercise every disclosed control against
#                                   # temp copies (each must flip the check red)
#
# Exit: 0 compliant / 1 violation or self-test failure / 2 usage error.
# =============================================================================
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
DEPLOYMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="check"

usage() {
    cat <<'EOF'
Usage: check-authority.sh [--root DIR] [--self-test]

Static authority check for managed x0xd deployment (ADR 0026, chapter §3).
  --root DIR     check a deployment directory copied to DIR
  --self-test    exercise every disclosed control against temp copies
  -h, --help     show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --root) DEPLOYMENT_DIR="$(cd "${2:?--root requires a directory}" && pwd)"; shift 2 ;;
        --self-test) MODE="self-test"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# --- authoritative instance inventory ----------------------------------------
# The three managed instances declared by this repository. The 443 instance
# (ADR 0011 dual-listener) has no tracked config source: deploy-443.sh
# generates it from the live production config at install time.
PROD_UNIT="systemd/x0xd.service"
TESTNET_UNIT="systemd/x0xd-testnet.service"
UNIT443="systemd/x0xd-443.service"
PROD_CFG="config/bootstrap-config.toml"
TESTNET_CFG="config/bootstrap-config-testnet.toml"
INSTALLER="install.sh"
GEN443="deploy-443.sh"

# --- parse helpers (read values from the artifacts themselves) ---------------
unit_config_arg() {  # $1 = unit relpath under .deployment -> the --config path
    grep -oE -- '--config[= ][^ ]+' "$DEPLOYMENT_DIR/$1" 2>/dev/null \
        | head -1 | sed -E 's/^--config[= ]+//' || true
}
unit_binary() {  # ExecStart argv0 basename
    local exe
    exe="$(grep -E '^[[:space:]]*ExecStart=' "$DEPLOYMENT_DIR/$1" \
        | head -1 | sed -E 's/^[[:space:]]*ExecStart=//' | awk '{print $1}')"
    basename "$exe"
}
unit_name() {  # --name value, empty if absent
    grep -oE -- '--name [^ ]+' "$DEPLOYMENT_DIR/$1" 2>/dev/null \
        | head -1 | awk '{print $2}' || true
}
installer_unit_default() {  # the installer's tracked --unit source (relpath)
    grep -E '^UNIT_SRC_DEFAULT=' "$DEPLOYMENT_DIR/$INSTALLER" \
        | head -1 \
        | sed -E 's/^UNIT_SRC_DEFAULT="//; s/"$//; s|^\$SCRIPT_DIR/||'
}
installer_config_dst() {  # the path the installer writes the config to
    grep -E '^CONFIG_DST=' "$DEPLOYMENT_DIR/$INSTALLER" \
        | head -1 | sed -E 's/^CONFIG_DST="//; s/"$//'
}
gen443_live_src() {  # the live config path deploy-443.sh clones the 443 config from
    grep -E '^LIVE=' "$DEPLOYMENT_DIR/$GEN443" \
        | head -1 | sed -E 's/^LIVE=//'
}

fail() { echo "FAIL [$1] $2" >&2; exit 1; }

# --- the six controls --------------------------------------------------------
run_check() {
    # C3 — every declared artifact exists on disk.
    local f
    for f in "$PROD_UNIT" "$TESTNET_UNIT" "$UNIT443" "$PROD_CFG" "$TESTNET_CFG"; do
        [ -f "$DEPLOYMENT_DIR/$f" ] \
            || fail C3-missing "declared artifact absent: $f"
    done

    # C1 — one production authority, reached from the install entry point.
    [ -f "$DEPLOYMENT_DIR/$INSTALLER" ] \
        || fail C1-authority "install entry point absent: $INSTALLER"
    local inst_unit
    inst_unit="$(installer_unit_default)"
    [ -n "$inst_unit" ] \
        || fail C1-authority "installer declares no UNIT_SRC_DEFAULT"
    [ "$inst_unit" = "$PROD_UNIT" ] \
        || fail C1-authority "installer --unit default ($inst_unit) is not the production unit ($PROD_UNIT)"

    # C2 — the production unit binds --config and it agrees with the installer.
    local prod_cfg_arg inst_dst
    prod_cfg_arg="$(unit_config_arg "$PROD_UNIT")"
    [ -n "$prod_cfg_arg" ] \
        || fail C2-no-config "production unit $PROD_UNIT ExecStart carries no --config flag (§6 step 2)"
    inst_dst="$(installer_config_dst)"
    [ -n "$inst_dst" ] \
        || fail C2-disagree "installer declares no CONFIG_DST"
    [ "$prod_cfg_arg" = "$inst_dst" ] \
        || fail C2-disagree "production unit reads '$prod_cfg_arg' but installer writes '$inst_dst' (§6 step 2)"

    # C6 — deploy-443.sh clones the authoritative live config path.
    [ -f "$DEPLOYMENT_DIR/$GEN443" ] || fail C6-source "$GEN443 absent"
    local live
    live="$(gen443_live_src)"
    [ -n "$live" ] \
        || fail C6-source "$GEN443 declares no LIVE source"
    [ "$live" = "$prod_cfg_arg" ] \
        || fail C6-source "$GEN443 clones '$live', not the production config path '$prod_cfg_arg' (comment/body mismatch)"

    # C5 — root distinctness: unique (binary, name, config) across declared units.
    declare -A seen cfgseen
    local u b n c key
    for u in "$PROD_UNIT" "$TESTNET_UNIT" "$UNIT443"; do
        b="$(unit_binary "$u")"; n="$(unit_name "$u")"; c="$(unit_config_arg "$u")"
        key="$b|$n|$c"
        if [ -n "${seen[$key]:-}" ]; then
            fail C5-dup-root "units '$u' and '${seen[$key]}' resolve the same root ($key) — duplicate effective root"
        fi
        seen[$key]="$u"
        if [ -n "${cfgseen[$c]:-}" ]; then
            fail C5-dup-root "units '$u' and '${cfgseen[$c]}' read the same config path '$c'"
        fi
        cfgseen[$c]="$u"
    done

    # C4 — every discovered .service and config/*.toml maps to a declared instance.
    local d
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        case "$d" in
            "$PROD_UNIT"|"$TESTNET_UNIT"|"$UNIT443") : ;;
            *) fail C4-orphan "discovered unit '$d' is not a declared managed instance (orphan/competing authority)" ;;
        esac
    done < <(cd "$DEPLOYMENT_DIR" && find . -type f -name '*.service' | sed 's|^\./||' | sort)

    while IFS= read -r d; do
        [ -n "$d" ] || continue
        case "$d" in
            "$PROD_CFG"|"$TESTNET_CFG") : ;;
            *) fail C4-orphan "discovered config '$d' is not a declared config source (orphan alternative)" ;;
        esac
    done < <(cd "$DEPLOYMENT_DIR" && find ./config -type f -name '*.toml' 2>/dev/null | sed 's|^\./||' | sort)

    echo "OK [authority] .deployment reconciles: units {prod,testnet,443}, config sources {prod,testnet}; install↔prod --config agree ('$prod_cfg_arg'); roots distinct; deploy-443 source bound ('$live')."
}

# Portable in-place rewrite: sed -E EXPR FILE > tmp && mv (BSD+GNU safe).
_rewrite() { sed -E "$2" "$1" > "$1.__t" && mv "$1.__t" "$1"; }

# --- self-test: each disclosed control must flip the check red ---------------
run_self_test() {
    local tmp pass=0 failed=0
    tmp="$(mktemp -d)"

    cp -r "$DEPLOYMENT_DIR" "$tmp/base"
    if "$SCRIPT_PATH" --root "$tmp/base" >/dev/null 2>&1; then
        echo "[self-test] baseline (clean copy) compliant ✓"
    else
        echo "[self-test] FAIL: baseline clean copy is non-compliant — the check itself is broken" >&2
        rm -rf "$tmp"
        return 1
    fi

    # Each disclosed control (chapter §3) + the advisory-1 no-flag arm.
    # Mutators run with cwd = a fresh copy of .deployment; _rewrite is the
    # BSD+GNU-safe in-place sed (> tmp && mv), so the self-test is portable
    # across macOS and Linux runners without eval or nested quoting.
    mut_C1()  { printf '[Unit]\nDescription=competing\n\n[Service]\nExecStart=/opt/x0x/x0xd --config /etc/x0x/x0xd.toml\n' > x0xd.service; }
    mut_C2a() { _rewrite install.sh 's|^CONFIG_DST=.*|CONFIG_DST="/etc/x0x/x0xd.toml"|'; }
    mut_C2b() { _rewrite systemd/x0xd.service 's| --config /etc/x0x/config.toml||'; }
    mut_C3()  { rm -f systemd/x0xd-testnet.service; }
    mut_C4()  { printf '[Unit]\nDescription=staging\n\n[Service]\nExecStart=/opt/x0x/x0xd-staging --config /etc/x0x/staging.toml\n' > systemd/x0xd-staging.service; }
    mut_C5()  { _rewrite systemd/x0xd-443.service 's|/etc/x0x/x0xd-443.toml|/etc/x0x/config.toml|'; }
    mut_C6()  { _rewrite deploy-443.sh 's|^LIVE=.*|LIVE=/etc/x0x/x0xd.toml|'; }

    # expect_fail NAME MUTATOR-FN : apply the mutator to a fresh copy, expect red.
    expect_fail() {
        local name="$1" fn="$2" d="$tmp/$1"
        rm -rf "$d"; cp -r "$tmp/base" "$d"
        ( cd "$d" && "$fn" )
        if "$SCRIPT_PATH" --root "$d" >/dev/null 2>&1; then
            echo "[self-test] FAIL: $name — violation NOT caught" >&2
            failed=$((failed + 1))
        else
            echo "[self-test] ok: $name — violation caught ✓"
            pass=$((pass + 1))
        fi
    }

    expect_fail C1-competing-prod-unit       mut_C1
    expect_fail C2-config-disagree           mut_C2a
    expect_fail C2-no-config-flag            mut_C2b
    expect_fail C3-missing-testnet-unit      mut_C3
    expect_fail C4-orphan-alternative        mut_C4
    expect_fail C5-duplicate-root            mut_C5
    expect_fail C6-deploy443-source-mismatch mut_C6

    rm -rf "$tmp"
    echo "[self-test] $pass control(s) fired, $failed failed to fire"
    [ "$failed" -eq 0 ]
}

if [ "$MODE" = "self-test" ]; then
    run_self_test
    exit $?
else
    run_check
    exit $?
fi
