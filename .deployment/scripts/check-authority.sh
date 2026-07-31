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
#   (C7 is reserved for the per-instance reachability control of the
#    inventory-MOVE follow-up; it is not part of this commit.)
#   C8  shell/unit/config syntax error in a tracked deployment artifact
#       (§3:67). Config/unit syntax run under a disclosed platform bound:
#       skipped WITH a printed note where the tool is absent, never silent.
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
# Requires bash ≥4 (associative arrays: declare -A). Stock macOS /bin/bash is
# 3.2 and errors on `declare -A`; fail with a reason rather than a usage error.
if [ -z "${BASH_VERSINFO[0]:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "error: ${BASH_SOURCE[0]} requires bash ≥4 (uses associative arrays); current bash is ${BASH_VERSION:-unknown}." >&2
    echo "       invoke via a modern bash on PATH — the repo gate uses PATH bash; macOS stock /bin/bash is 3.2." >&2
    exit 1
fi

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

# --- syntax-parse helpers (chapter §3:67) ------------------------------------
# TOML via the python stdlib (tomllib, ≥3.11) or the tomli backport.
have_toml_parser() {
    python3 -c "import tomllib" 2>/dev/null || python3 -c "import tomli" 2>/dev/null
}
# toml_parse PATH: silent + exit 0 if it parses; a one-line reason on stdout
# + exit 1 if malformed. Caller MUST gate on have_toml_parser first.
toml_parse() {
    python3 - "$1" <<'PY'
import sys
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
try:
    tomllib.load(open(sys.argv[1], "rb"))
except Exception as e:  # tomllib.TOMLDecodeError and friends
    print(f"toml: {e}")
    sys.exit(1)
PY
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

    # C8 — syntax validity of tracked deployment artifacts (§3:67: "shell/
    # unit/config syntax checks appropriate to the chosen mechanism"). Runs
    # after C3 (existence) and before the semantic greps: a syntactically
    # broken script/unit/config makes C1/C2/C6's value extraction meaningless.
    # Config/unit run under a disclosed platform bound: skipped WITH a printed
    # note where the tool is absent — never silent (§3:67).

    # 8a — shell syntax: bash -n over every tracked .deployment/*.sh.
    # Discovery (mirrors C4): a newly tracked script is checked by default,
    # and this covers the check script itself.
    local s berr
    while IFS= read -r s; do
        [ -n "$s" ] || continue
        if ! berr="$(bash -n "$DEPLOYMENT_DIR/$s" 2>&1)"; then
            fail C8-shell-syntax "script '$s' fails bash -n: $berr"
        fi
    done < <(cd "$DEPLOYMENT_DIR" && find . -type f -name '*.sh' | sed 's|^\./||' | sort)

    # 8b — config syntax: TOML parse of both declared config sources.
    local cfg c8_cfg="verified" terr
    if have_toml_parser; then
        for cfg in "$PROD_CFG" "$TESTNET_CFG"; do
            if ! terr="$(toml_parse "$DEPLOYMENT_DIR/$cfg")"; then
                fail C8-config-syntax "config '$cfg' fails TOML parse: $terr"
            fi
        done
    else
        echo "NOTE [C8] no python TOML parser (tomllib/tomli) — config syntax SKIPPED (disclosed platform bound)" >&2
        c8_cfg="skipped(no parser)"
    fi

    # 8c — unit syntax: systemd-analyze verify over the three declared units.
    local un c8_unit="verified" uerr
    if command -v systemd-analyze >/dev/null 2>&1; then
        for un in "$PROD_UNIT" "$TESTNET_UNIT" "$UNIT443"; do
            if ! uerr="$(systemd-analyze verify "$DEPLOYMENT_DIR/$un" 2>&1)"; then
                fail C8-unit-syntax "unit '$un' fails systemd-analyze verify: $uerr"
            fi
        done
    else
        echo "NOTE [C8] systemd-analyze absent — unit syntax SKIPPED (disclosed platform bound, e.g. macOS dev)" >&2
        c8_unit="skipped(no systemd-analyze)"
    fi

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

    echo "OK [authority] .deployment reconciles: units {prod,testnet,443}, config sources {prod,testnet}; install↔prod --config agree ('$prod_cfg_arg'); roots distinct; deploy-443 source bound ('$live'); syntax shell=verified config=$c8_cfg unit=$c8_unit (§3:67)."
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

    # The §3 controls: C1–C6 (C4 two discovery arms, C2b no-flag arm) + C8
    # syntax (two arms: shell + config). C7 reachability lands with the
    # inventory-MOVE follow-up; unit syntax (8c) has no red arm here because
    # systemd-analyze is absent where self-test runs.
    # Mutators run with cwd = a fresh copy of .deployment; _rewrite is the
    # BSD+GNU-safe in-place sed (> tmp && mv), so the self-test is portable
    # across macOS and Linux runners without eval or nested quoting.
    mut_C1()  { _rewrite install.sh 's|^UNIT_SRC_DEFAULT=.*|UNIT_SRC_DEFAULT="$SCRIPT_DIR/systemd/x0xd-testnet.service"|'; }
    mut_C2a() { _rewrite install.sh 's|^CONFIG_DST=.*|CONFIG_DST="/etc/x0x/x0xd.toml"|'; }
    mut_C2b() { _rewrite systemd/x0xd.service 's| --config /etc/x0x/config.toml||'; }
    mut_C3()  { rm -f systemd/x0xd-testnet.service; }
    mut_C4()  { printf '[Unit]\nDescription=staging\n\n[Service]\nExecStart=/opt/x0x/x0xd-staging --config /etc/x0x/staging.toml\n' > systemd/x0xd-staging.service; }
    mut_C4b() { printf '[Unit]\nDescription=competing\n\n[Service]\nExecStart=/opt/x0x/x0xd --config /etc/x0x/x0xd.toml\n' > x0xd.service; }
    mut_C5()  { _rewrite systemd/x0xd-443.service 's|/etc/x0x/x0xd-443.toml|/etc/x0x/config.toml|'; }
    mut_C6()  { _rewrite deploy-443.sh 's|^LIVE=.*|LIVE=/etc/x0x/x0xd.toml|'; }
    mut_C8a() { printf '\nthen\n' >> install.sh; }                                        # bare keyword → bash -n syntax error
    mut_C8b() { printf '\nbroken = "unterminated\n' >> config/bootstrap-config.toml; }    # unterminated string → TOML parse error

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

    expect_fail C1-installer-default-mismatch mut_C1
    expect_fail C2-config-disagree            mut_C2a
    expect_fail C2-no-config-flag             mut_C2b
    expect_fail C3-missing-testnet-unit       mut_C3
    expect_fail C4-orphan-alternative         mut_C4
    expect_fail C4-competing-prod-unit        mut_C4b
    expect_fail C5-duplicate-root             mut_C5
    expect_fail C6-deploy443-source-mismatch  mut_C6
    expect_fail C8-shell-syntax-error         mut_C8a
    expect_fail C8-config-syntax-error        mut_C8b

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
