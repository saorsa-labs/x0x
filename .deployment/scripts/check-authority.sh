#!/usr/bin/env bash
# =============================================================================
# Static repository authority check for managed x0xd deployment.
#
# Governing decision: ADR 0026 (Managed x0xd Deployment Has Distinct Roots
# and Closed Resolution), design chapter §3 "Static repository authority
# check" (docs/design/managed-x0xd-deployment.md). Reconciles the deployment
# artifacts under .deployment/ against the authoritative instance inventory
# (.deployment/authority-inventory.json, schema chapter §1a) and fails closed
# on any:
#
#   C1  missing/ambiguous production authority: install.sh is absent, or the
#       manifest does not designate exactly one install-default instance
#       (entrypoint install.sh, empty selector_args) equal to production;
#   C2  a unit that binds no --config, or whose --config disagrees with the
#       config destination its manifest record declares (§6 step 2);
#   C3  a manifest-declared source artifact (unit, tracked config, generator,
#       dropin) that is missing on disk;
#   C4  a discovered unit/config that maps to no declared instance (orphan);
#   C5  two units that resolve the same effective root (duplicate root), or
#       two units that read the same config path (duplicate config);
#   C6  deploy-443.sh cloning a non-authoritative live config (its RESOLVED
#       LIVE input must reconcile with the manifest's prod config destination);
#   C7  an instance not reachable from its install entry point by EXECUTION
#       (§3): each entry point is invoked unprivileged — install.sh must reach
#       its root guard (resolved-and-reached), deploy-443.sh --resolve must
#       print values that reconcile with the manifest. A declared entrypoint
#       absent on disk, or a selector that does not bind to its instance, also
#       reds. Evidence class is uniform execution (no reading/exec split);
#   C8  shell/unit/config syntax error in a tracked deployment artifact
#       (§3:67). Unit syntax runs HERMETICALLY under a temp systemd-analyze
#       --root tree (placeholders from each unit's own ExecStart argv0) and
#       under a disclosed platform bound: skipped WITH a printed note where
#       the tool is absent, never silent.
#   C9  a unit whose ExecStart argv0 differs from its manifest binary.destination
#       (§1a: the binary the unit runs is the binary the manifest ships).
#
# The inventory is the single source of truth (§1a). This check, install.sh,
# and deploy-443.sh are consumers: they derive binary/--name/--config/roots
# from the referenced artifacts and reconcile those derived values with the
# manifest in both directions. No consumer retains an inline instance list.
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
Authority inventory: .deployment/authority-inventory.json (chapter §1a).
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

# --- authoritative instance inventory (§1a) ----------------------------------
# The single source of truth is the strict JSON manifest. Consumers derive
# instance values from the referenced artifacts and reconcile with it; they do
# not retain inline instance lists.
MANIFEST="authority-inventory.json"
MANIFEST_DUMP=""
# Non-whitespace field separator for the manifest dump: a tab would collapse the
# empty dropins/input fields (tab is IFS-whitespace), shifting every later field.
readonly _FS=$'\x1f'

# manifest_load PATH: strict-validate the §1a schema and emit one TSV record
# per instance (in manifest order). Columns, tab-separated:
#   1 id | 2 unit.source | 3 unit.destination | 4 dropins("src=dst" space-joined)
#   5 config.kind(source|generator) | 6 config.authority(source path|generator)
#   7 config.destination | 8 input_instances(space) | 9 binary.destination
#   10 installation.entrypoint | 11 selector_args(space)
# python3 is already a dependency (C8b TOML parse via tomllib/tomli); the
# manifest is load-bearing, so its absence fails closed (it is not skippable).
manifest_load() {
    python3 - "$1" <<'PY'
import sys, json
path = sys.argv[1]
try:
    with open(path) as f:
        data = json.load(f)
except Exception as e:
    print(f"FAIL [manifest] cannot load/parse JSON: {e}", file=sys.stderr); sys.exit(1)
def bad(msg):
    print(f"FAIL [manifest] {msg}", file=sys.stderr); sys.exit(1)
if not isinstance(data, dict): bad("top-level object must be a JSON object")
if set(data.keys()) != {"schema_version", "instances"}:
    bad("top-level keys must be exactly {schema_version, instances}")
sv = data["schema_version"]
if not isinstance(sv, int) or sv <= 0: bad("schema_version must be a positive integer")
if sv != 1: bad(f"unsupported schema_version {sv} (this checker knows version 1)")
insts = data["instances"]
if not isinstance(insts, list) or not insts: bad("instances must be a non-empty array")
INST_KEYS = {"id", "unit", "config", "binary", "installation"}
UNIT_KEYS = {"source", "destination", "dropins"}
SRC_KEYS = {"source", "destination"}
GEN_KEYS = {"generator", "input_instances", "destination"}
BIN_KEYS = {"destination"}
II_KEYS = {"entrypoint", "selector_args"}
# ec8d50d: path-valued flags are not conforming selector arguments.
PATH_FLAGS = {"--config", "--unit", "--binary", "--source", "--destination",
              "--config-source", "--unit-source", "--binary-src"}
def is_rel(p):
    if not isinstance(p, str) or not p or p.startswith("/"): return False
    return ".." not in p.split("/")
def is_abs(p):
    # Canonical absolute: leading '/', never bare root, no '.'/'..' components,
    # no empty segments (//), no trailing separator. Guards EVERY destination
    # the manifest governs (unit/config/binary/dropin destinations) against
    # path-escape (e.g. /../sibling) before any consumer concatenates it onto a
    # staging root. A bare leading-slash check would let /../x escape.
    if (not isinstance(p, str) or not p.startswith("/") or p == "/"
            or "//" in p or p.endswith("/")):
        return False
    return all(seg not in (".", "..", "") for seg in p.split("/")[1:])
ids = []
rows = []
for idx, inst in enumerate(insts):
    if not isinstance(inst, dict): bad(f"instance[{idx}] is not an object")
    if set(inst.keys()) != INST_KEYS:
        bad(f"instance[{idx}] keys must be exactly {sorted(INST_KEYS)}")
    iid = inst["id"]
    if not isinstance(iid, str) or not iid: bad(f"instance[{idx}] id missing/empty")
    if iid in ids: bad(f"duplicate instance id {iid!r}")
    ids.append(iid)
    u = inst["unit"]
    if not isinstance(u, dict) or set(u.keys()) != UNIT_KEYS:
        bad(f"{iid}: unit keys must be exactly {sorted(UNIT_KEYS)}")
    if not is_rel(u["source"]): bad(f"{iid}: unit.source must be a .deployment/-relative path")
    if not is_abs(u["destination"]): bad(f"{iid}: unit.destination must be an absolute path")
    if not isinstance(u["dropins"], list): bad(f"{iid}: unit.dropins must be an array")
    dropins = []
    for d in u["dropins"]:
        if not isinstance(d, dict) or set(d.keys()) != {"source", "destination"}:
            bad(f"{iid}: each dropin must be {{source, destination}}")
        if not is_rel(d["source"]): bad(f"{iid}: dropin.source must be .deployment/-relative")
        if not is_abs(d["destination"]): bad(f"{iid}: dropin.destination must be absolute")
        dropins.append(f"{d['source']}={d['destination']}")
    c = inst["config"]
    if not isinstance(c, dict): bad(f"{iid}: config must be an object")
    ckeys = set(c.keys())
    has_src, has_gen = "source" in ckeys, "generator" in ckeys
    if has_src and has_gen: bad(f"{iid}: config has both source and generator (exactly one authority)")
    if not has_src and not has_gen: bad(f"{iid}: config has neither source nor generator (exactly one authority)")
    if has_src:
        if ckeys != SRC_KEYS: bad(f"{iid}: tracked-config keys must be exactly {sorted(SRC_KEYS)}")
        if not is_rel(c["source"]): bad(f"{iid}: config.source must be .deployment/-relative")
        if not is_abs(c["destination"]): bad(f"{iid}: config.destination must be absolute")
        kind, auth, inputs = "source", c["source"], ""
    else:
        if ckeys != GEN_KEYS: bad(f"{iid}: generated-config keys must be exactly {sorted(GEN_KEYS)}")
        if not is_rel(c["generator"]): bad(f"{iid}: config.generator must be .deployment/-relative")
        ii = c["input_instances"]
        if not isinstance(ii, list) or not ii: bad(f"{iid}: config.input_instances must be a non-empty array")
        if not all(isinstance(x, str) and x for x in ii): bad(f"{iid}: config.input_instances must be strings")
        if not is_abs(c["destination"]): bad(f"{iid}: config.destination must be absolute")
        kind, auth, inputs = "generator", c["generator"], " ".join(ii)
    b = inst["binary"]
    if not isinstance(b, dict) or set(b.keys()) != BIN_KEYS:
        bad(f"{iid}: binary keys must be exactly {sorted(BIN_KEYS)}")
    if not is_abs(b["destination"]): bad(f"{iid}: binary.destination must be absolute")
    n = inst["installation"]
    if not isinstance(n, dict) or set(n.keys()) != II_KEYS:
        bad(f"{iid}: installation keys must be exactly {sorted(II_KEYS)}")
    if not is_rel(n["entrypoint"]): bad(f"{iid}: installation.entrypoint must be .deployment/-relative")
    sa = n["selector_args"]
    if not isinstance(sa, list) or not all(isinstance(x, str) for x in sa):
        bad(f"{iid}: selector_args must be an array of strings")
    for tok in sa:
        if tok.startswith("/"): bad(f"{iid}: selector arg {tok!r} is a path value, not a stable selector (ec8d50d)")
        if tok in PATH_FLAGS: bad(f"{iid}: selector arg {tok!r} is a path-bearing flag, not a stable selector (ec8d50d)")
    rows.append((iid, u["source"], u["destination"], " ".join(dropins), kind, auth,
                 c["destination"], inputs, b["destination"], n["entrypoint"], " ".join(sa)))
idset = set(ids)
for r in rows:
    if r[4] == "generator":
        for ref in r[7].split():
            if ref not in idset: bad(f"{r[0]}: config.input_instances references unknown id {ref!r}")
for r in rows:
    print("\x1f".join(r))
PY
}

# --- manifest field accessors (read the validated TSV dump) ------------------
_inst_field() { awk -F"$_FS" -v id="$1" -v f="$2" '$1==id {print $f; exit}' <<<"$MANIFEST_DUMP"; }
inst_unit_src() { _inst_field "$1" 2; }
inst_cfg_kind() { _inst_field "$1" 5; }
inst_cfg_auth() { _inst_field "$1" 6; }
inst_cfg_dst()  { _inst_field "$1" 7; }
inst_inputs()   { _inst_field "$1" 8; }
inst_entry()    { _inst_field "$1" 10; }
inst_selargs()  { _inst_field "$1" 11; }

# --- parse helpers (derive values from the artifacts themselves) -------------
unit_config_arg() {  # --config value on the unit's ExecStart, empty if absent
    # Anchored on ExecStart (like unit_binary) so prose mentions of --config in
    # comments/Description cannot supply the value. §1a: derive from the unit.
    grep -E '^[[:space:]]*ExecStart=' "$DEPLOYMENT_DIR/$1" | head -1 \
        | grep -oE -- '--config[= ][^ ]+' | head -1 | sed -E 's/^--config[= ]+//' || true
}
unit_binary() {  # ExecStart argv0 basename
    local exe
    exe="$(grep -E '^[[:space:]]*ExecStart=' "$DEPLOYMENT_DIR/$1" \
        | head -1 | sed -E 's/^[[:space:]]*ExecStart=//' | awk '{print $1}')"
    basename "$exe"
}
unit_argv0() {  # full ExecStart argv0 path (e.g. /opt/x0x/x0xd), empty if absent
    # Anchored on ExecStart (like unit_binary) so a prose mention in comments or
    # Description cannot supply it. §1a: derive from the unit. Returns the FULL
    # path (unlike unit_binary's basename) so C9 can compare it to binary.destination
    # and C8c can place a placeholder at the resolved --root path.
    grep -E '^[[:space:]]*ExecStart=' "$DEPLOYMENT_DIR/$1" \
        | head -1 | sed -E 's/^[[:space:]]*ExecStart=//' | awk '{print $1}'
}
# is_canonical_abs PATH: 0 iff PATH is absolute and canonical — leading '/',
# never bare root, no '.'/'..' components, no empty segments (//), no trailing
# separator. Guards the C8c staging write: a non-canonical argv0 such as
# /../sibling/marker would, concatenated onto the temp --root tree, write
# OUTSIDE it before C9 runs. Pure parameter expansion (no IFS/globbing state).
is_canonical_abs() {
    local p="$1" rest seg
    [ -n "$p" ] || return 1
    [ "${p:0:1}" = "/" ] || return 1            # absolute
    [ "$p" != "/" ] || return 1                  # never bare root
    [[ "$p" == *//* ]] && return 1               # no duplicate separators
    [ "${p: -1}" != "/" ] || return 1            # no trailing separator
    rest="${p#/}"                                # drop the leading '/'
    while [ -n "$rest" ]; do
        seg="${rest%%/*}"                        # segment up to next '/'
        [ -n "$seg" ] || return 1                # no empty segment (also via //* above)
        [ "$seg" != "." ] && [ "$seg" != ".." ] || return 1
        [ "$rest" = "$seg" ] && rest="" || rest="${rest#*/}"
    done
    return 0
}
unit_name() {  # --name value on the unit's ExecStart, empty if absent
    # Anchored on ExecStart (like unit_binary) so prose mentions of --name in
    # comments/Description cannot supply the value (was reading 'testnet)' off
    # the Description line). §1a: derive from the unit.
    grep -E '^[[:space:]]*ExecStart=' "$DEPLOYMENT_DIR/$1" | head -1 \
        | grep -oE -- '--name [^ ]+' | head -1 | awk '{print $2}' || true
}
# resolve_live SCRIPT: the live config path a generator RESOLVES and would ship
# (the `live=` value from the script's --resolve output). Post-§1a MOVE the
# generator carries no ^LIVE= body literal — LIVE is resolved from the manifest
# and passed positionally — so C6 reconciles what the script RESOLVES, not what
# its body contains (Dario 05fad365: gen_live grepped a line of remote shell as
# a local declaration; the re-point onto the resolve path is mandatory here).
resolve_live() {
    "$DEPLOYMENT_DIR/$1" --resolve 2>/dev/null | sed -nE 's/^live=//p' | head -1 || true
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

# --- the eight controls ------------------------------------------------------
run_check() {
    # Load + strict-validate the authoritative inventory (§1a). Fail closed.
    MANIFEST_DUMP="$(manifest_load "$DEPLOYMENT_DIR/$MANIFEST")" || exit 1
    local prod_id="prod"

    # C3 — every manifest-declared source artifact exists on disk.
    local id usrc ckind cauth d src
    while IFS="$_FS" read -r id usrc _ _ ckind cauth _ _ _ _ _; do
        [ -n "$id" ] || continue
        [ -f "$DEPLOYMENT_DIR/$usrc" ] \
            || fail C3-missing "declared unit.source absent for '$id': $usrc"
        [ -f "$DEPLOYMENT_DIR/$cauth" ] \
            || fail C3-missing "declared config.${ckind} absent for '$id': $cauth"
        for d in $(_inst_field "$id" 4); do
            src="${d%%=*}"
            [ -f "$DEPLOYMENT_DIR/$src" ] \
                || fail C3-missing "declared dropin.source absent for '$id': $src"
        done
    done <<<"$MANIFEST_DUMP"

    # C8 — syntax validity of tracked deployment artifacts (§3:67). Runs after
    # C3 (existence) and before the semantic greps: a syntactically broken
    # script/unit/config makes the value extraction below meaningless.
    # Config/unit run under a disclosed platform bound: skipped WITH a printed
    # note where the tool is absent — never silent (§3:67).

    # 8a — shell syntax: bash -n over every tracked .deployment/*.sh (discovery,
    # mirrors C4: a newly tracked script is checked by default; self-covers this
    # check script).
    local s berr
    while IFS= read -r s; do
        [ -n "$s" ] || continue
        if ! berr="$(bash -n "$DEPLOYMENT_DIR/$s" 2>&1)"; then
            fail C8-shell-syntax "script '$s' fails bash -n: $berr"
        fi
    done < <(cd "$DEPLOYMENT_DIR" && find . -type f -name '*.sh' | sed 's|^\./||' | sort)

    # 8b — config syntax: TOML parse of every tracked config.source.
    local cfg c8_cfg="verified" terr
    if have_toml_parser; then
        while IFS="$_FS" read -r id _ _ _ ckind cauth _ _ _ _ _; do
            [ "$ckind" = source ] || continue
            if ! terr="$(toml_parse "$DEPLOYMENT_DIR/$cauth")"; then
                fail C8-config-syntax "config '$cauth' (instance '$id') fails TOML parse: $terr"
            fi
        done <<<"$MANIFEST_DUMP"
    else
        echo "NOTE [C8] no python TOML parser (tomllib/tomli) — config syntax SKIPPED (disclosed platform bound)" >&2
        c8_cfg="skipped(no parser)"
    fi

    # 8p — path safety: every unit's ExecStart argv0 must be a canonical
    # absolute path before the hermetic C8c staging concatenates it onto the
    # temp --root tree. Platform-independent (pure bash): runs whether or not
    # systemd-analyze exists, so an escaping argv0 (e.g. /../sibling/marker) is
    # refused before ANY mkdir/write — not only on Linux. Independent of C9:
    # C9 compares argv0 to binary.destination; this control validates argv0's
    # shape, so a non-canonical argv0 reds here regardless of the manifest
    # value (and before C9). An empty argv0 is left to C9 (no binary to
    # compare); only a present-but-non-canonical one reds here.
    local _p_argv0
    while IFS="$_FS" read -r id usrc _ _ _ _ _ _ _ _ _; do
        [ -n "$id" ] || continue
        _p_argv0="$(unit_argv0 "$usrc")"
        [ -z "$_p_argv0" ] || is_canonical_abs "$_p_argv0" \
            || fail C8-unit-path "unit '$usrc' (instance '$id') ExecStart argv0 '$_p_argv0' is not a canonical absolute path (path-escape risk before hermetic staging)"
    done <<<"$MANIFEST_DUMP"

    # 8c — unit syntax: systemd-analyze verify over every declared unit.source,
    # run HERMETICALLY under a temporary --root tree so a host without the
    # deployed binary installed does not false-red on the missing ExecStart
    # target. Each unit is staged with an executable placeholder created from
    # the unit's OWN ExecStart argv0 (unit_argv0) — not the manifest
    # binary.destination — so syntax verification stays independent of the C9
    # argv0↔binary.destination authority comparison below (a C9 argv0 drift
    # moves the placeholder too, keeping C8c green). --recursive-errors=no
    # limits non-zero exit to the specified unit's own warnings (isolates absent
    # system deps like network-online.target under the temp root); --man=no
    # skips Documentation= URL man-page checks. Platform-bound: skipped WITH a
    # printed note where systemd-analyze is absent.
    local c8_unit="verified" uerr stage argv0 bin
    if command -v systemd-analyze >/dev/null 2>&1; then
        stage="$(mktemp -d)"
        while IFS="$_FS" read -r id usrc _ _ _ _ _ _ _ _ _; do
            [ -n "$id" ] || continue
            mkdir -p "$stage/etc/systemd/system"
            cp "$DEPLOYMENT_DIR/$usrc" "$stage/etc/systemd/system/"
            argv0="$(unit_argv0 "$usrc")"
            if [ -n "$argv0" ]; then
                mkdir -p "$stage$(dirname "$argv0")"
                printf '#!/bin/sh\nexit 0\n' > "$stage$argv0"
                chmod +x "$stage$argv0"
            fi
        done <<<"$MANIFEST_DUMP"
        if ! uerr="$(systemd-analyze verify --root="$stage" --man=no --recursive-errors=no "$stage"/etc/systemd/system/*.service 2>&1)"; then
            rm -rf "$stage"
            fail C8-unit-syntax "systemd-analyze verify (hermetic --root) failed: $uerr"
        fi
        rm -rf "$stage"
    else
        echo "NOTE [C8] systemd-analyze absent — unit syntax SKIPPED (disclosed platform bound, e.g. macOS dev)" >&2
        c8_unit="skipped(no systemd-analyze)"
    fi

    # C9 — each unit's ExecStart argv0 must equal its manifest binary.destination.
    # Reads BOTH sides: argv0 derived from the unit's ExecStart (unit_argv0),
    # binary.destination from the manifest (field 9). Independent of C8c — C8c
    # builds its placeholder FROM the unit's argv0, so an argv0 drift passes
    # syntax but reds here. Placed after C8 so a syntactically broken unit does
    # not reach this comparison. Sole-catcher: no earlier control reads argv0 or
    # binary.destination (C2 reads --config, not the binary path).
    while IFS="$_FS" read -r id usrc _ _ _ _ _ _ bin _ _; do
        [ -n "$id" ] || continue
        argv0="$(unit_argv0 "$usrc")"
        [ -n "$argv0" ] || fail C9-bin-argv0 "unit '$usrc' (instance '$id') ExecStart has no argv0"
        [ "$argv0" = "$bin" ] \
            || fail C9-bin-argv0 "unit '$usrc' (instance '$id') ExecStart argv0 '$argv0' != manifest binary.destination '$bin'"
    done <<<"$MANIFEST_DUMP"

    # C1 — one production authority, reached as the install default. install.sh
    # exists and the manifest designates exactly one install-default instance
    # (entrypoint install.sh, empty selector_args) and it is production.
    [ -f "$DEPLOYMENT_DIR/install.sh" ] \
        || fail C1-authority "production install entry point absent: install.sh"
    local defaults ndefault def_id
    defaults="$(awk -F"$_FS" '$10=="install.sh" && $11=="" {print $1}' <<<"$MANIFEST_DUMP")"
    ndefault="$(printf '%s\n' "$defaults" | grep -c . || true)"
    [ "$ndefault" -eq 1 ] \
        || fail C1-authority "exactly one install-default instance (entrypoint install.sh, empty selector_args) required; found $ndefault: ${defaults//$'\n'/ }"
    def_id="$(printf '%s\n' "$defaults" | head -1)"
    [ "$def_id" = "$prod_id" ] \
        || fail C1-authority "install-default instance is '$def_id', not the production instance '$prod_id'"

    # C2 — the production unit binds --config and it agrees with the config
    # destination its manifest record declares (§6 step 2: installer writes ==
    # unit reads). Production-specific, matching §6 step 2: the closed scope
    # re-points C2 at the manifest, it does not generalise it to every instance.
    # (A general unit↔config reconcile would intercept the C5 arms, which prove
    # root-distinctness by mutating a non-prod unit's --config; that reconcile
    # is a future control, disclosed here, not this commit's scope.)
    local prod_usrc prod_cdst prod_cfg_arg
    prod_usrc="$(inst_unit_src "$prod_id")"
    prod_cdst="$(inst_cfg_dst "$prod_id")"
    prod_cfg_arg="$(unit_config_arg "$prod_usrc")"
    [ -n "$prod_cfg_arg" ] \
        || fail C2-no-config "production unit $prod_usrc ExecStart carries no --config flag (§6 step 2)"
    [ "$prod_cfg_arg" = "$prod_cdst" ] \
        || fail C2-disagree "production unit $prod_usrc reads '$prod_cfg_arg' but manifest declares '$prod_cdst' (§6 step 2)"

    # C6 — a generated config is cloned from the authoritative live source. The
    # generator's RESOLVED live input (the `live=` value from its --resolve
    # output, not a ^LIVE= body literal — the §1a MOVE deleted that line) must
    # equal the config destination of its declared input instance. C6 SOLELY
    # owns this cross-instance LIVE link (Kimi partition [11]: C7's 443 arm
    # asserts the record's own fields only, never LIVE).
    local live ref ref_cdst
    while IFS="$_FS" read -r id _ _ _ ckind cauth _ inputs _ _ _; do
        [ "$ckind" = generator ] || continue
        live="$(resolve_live "$cauth")"
        [ -n "$live" ] || fail C6-source "$cauth (instance '$id') resolves no live source (--resolve printed no live=)"
        ref="$(awk '{print $1}' <<<"$inputs")"
        ref_cdst="$(inst_cfg_dst "$ref")"
        [ -n "$ref_cdst" ] || fail C6-source "$cauth input_instances references instance '$ref' with no config destination"
        [ "$live" = "$ref_cdst" ] \
            || fail C6-source "$cauth (instance '$id') resolves '$live', not the declared input '$ref' config destination '$ref_cdst'"
    done <<<"$MANIFEST_DUMP"

    # C5 — root distinctness: unique (binary, name, config) and unique config
    # path across declared units. Values are DERIVED from each unit's ExecStart
    # (the daemon's effective root), not copied from the manifest.
    declare -A seen cfgseen
    local b n c key
    while IFS="$_FS" read -r id usrc _ _ _ _ _ _ _ _ _; do
        [ -n "$id" ] || continue
        b="$(unit_binary "$usrc")"; n="$(unit_name "$usrc")"; c="$(unit_config_arg "$usrc")"
        key="$b|$n|$c"
        if [ -n "${seen[$key]:-}" ]; then
            fail C5-dup-root "units '$usrc' and '${seen[$key]}' resolve the same root ($key) — duplicate effective root"
        fi
        seen[$key]="$usrc"
        if [ -n "${cfgseen[$c]:-}" ]; then
            # Distinct tag at the emitting site (not the root-collision tag): a
            # config-only collision is a different condition from a full-root
            # collision. Fixture-drift caveat: this arm binds to :229 only while
            # 443 and testnet differ in binary AND name; if the fixtures ever
            # converge it drifts to the root-collision branch, where this tag
            # fails loudly instead of passing green on the wrong condition.
            fail C5-dup-config "units '$usrc' and '${cfgseen[$c]}' read the same config path '$c'"
        fi
        cfgseen[$c]="$usrc"
    done <<<"$MANIFEST_DUMP"

    # C7 — reachability from the install entry point by EXECUTION (§3). Each
    # instance's entry point is actually invoked (unprivileged) and required to
    # resolve its own record from the manifest and reach the point where
    # privilege (local entry) or fleet contact (fleet entry) would begin. The
    # evidence class is uniform execution — the reading/execution split is gone
    # (Kimi [6]/[11]); the receipt no longer maintains a per-instance class
    # disclosure that no longer discriminates.
    #
    # prod/testnet (local entry install.sh): invoked with the record's literal
    # selector_args; "must run as root" on stderr is the observable of
    # resolved-and-reached — the manifest was read, sources validated, and the
    # install would proceed past privilege (root guard precedes every write). A
    # non-root exit WITHOUT that message failed before resolving (broken
    # manifest path, missing source, wrong id) — the finding-1 defect class an
    # existence check cannot see, and what C7 exists for.
    # 443 (fleet entry deploy-443.sh): its --resolve path prints the values it
    # would ship and exits before deploy_node; the arm reconciles the record's
    # OWN fields (unit.source, unit.destination, GEN) against the manifest. LIVE
    # is NOT asserted here — C6 solely owns the cross-instance LIVE link. Red
    # conditions: resolution failure (C7-resolve-failed — structurally shadowed
    # by C6, which runs --resolve first and reds on an empty live) and
    # printed/manifest disagreement (C7-resolve-disagree — the observable 443-
    # arm sole-catcher: an own-field mutation leaves LIVE correct so C6 passes
    # and C7 runs).
    local entry selargs selid ev_classes="" out rc p_usrc p_udst p_gen
    while IFS="$_FS" read -r id _ _ _ _ _ _ _ _ entry selargs; do
        [ -n "$id" ] || continue
        [ -f "$DEPLOYMENT_DIR/$entry" ] \
            || fail C7-missing-artifact "instance '$id' installation.entrypoint absent on disk: $entry"
        # row self-consistency: a --instance selector must bind to its own id.
        # Execution alone cannot catch this — install.sh --instance <other-id>
        # still reaches the root guard for that other instance.
        if [ -n "$selargs" ]; then
            selid="$(awk '{for (i=1;i<=NF;i++) if ($i=="--instance") {print $(i+1); exit}}' <<<"$selargs")"
            if [ -n "$selid" ] && [ "$selid" != "$id" ]; then
                fail C7-entrypoint-selector "instance '$id' selector references '$selid', not its own id (reachability mismatch)"
            fi
        fi
        if [ "$entry" = "install.sh" ]; then
            # Execute install.sh unprivileged with the record's literal
            # selector_args; require it to reach the root guard.
            rc=0
            # shellcheck disable=SC2086
            if out="$("$DEPLOYMENT_DIR/$entry" $selargs 2>&1)"; then rc=0; else rc=$?; fi
            if [ "$rc" -eq 0 ]; then
                fail C7-unreachable "instance '$id' entry point '$entry' exited 0 unprivileged (expected root-guard refusal)"
            elif printf '%s\n' "$out" | grep -q "must run as root"; then
                ev_classes+=" $id=execution(local:${entry}${selargs:+ $selargs})"
            else
                fail C7-unreachable "instance '$id' entry point '$entry' did not reach the root guard (resolved-and-reached failed); first line: $(printf '%s\n' "$out" | head -1)"
            fi
        else
            # Fleet entry (443): execute the resolve-only path and reconcile
            # the record's OWN fields against the manifest (LIVE excluded — C6).
            rc=0
            if out="$("$DEPLOYMENT_DIR/$entry" --resolve 2>&1)"; then rc=0; else rc=$?; fi
            if [ "$rc" -ne 0 ]; then
                fail C7-resolve-failed "instance '$id' entry point '$entry --resolve' failed (exit $rc); first line: $(printf '%s\n' "$out" | head -1)"
            fi
            p_usrc="$(printf '%s\n' "$out" | sed -nE 's/^unit\.source=//p' | head -1)"
            p_udst="$(printf '%s\n' "$out" | sed -nE 's/^unit\.destination=//p' | head -1)"
            p_gen="$(printf '%s\n' "$out" | sed -nE 's/^gen=//p' | head -1)"
            [ -n "$p_usrc" ] || fail C7-resolve-disagree "instance '$id' --resolve printed no unit.source"
            [ -n "$p_udst" ] || fail C7-resolve-disagree "instance '$id' --resolve printed no unit.destination"
            [ -n "$p_gen" ]  || fail C7-resolve-disagree "instance '$id' --resolve printed no gen"
            [ "$p_usrc" = "$(inst_unit_src "$id")" ] \
                || fail C7-resolve-disagree "instance '$id' --resolve unit.source '$p_usrc' != manifest '$(inst_unit_src "$id")'"
            [ "$p_udst" = "$(_inst_field "$id" 3)" ] \
                || fail C7-resolve-disagree "instance '$id' --resolve unit.destination '$p_udst' != manifest '$(_inst_field "$id" 3)'"
            [ "$p_gen" = "$(inst_cfg_dst "$id")" ] \
                || fail C7-resolve-disagree "instance '$id' --resolve gen '$p_gen' != manifest '$(inst_cfg_dst "$id")'"
            ev_classes+=" $id=execution(resolve:${entry})"
        fi
    done <<<"$MANIFEST_DUMP"

    # C4 — every discovered .service and config/*.toml maps to a declared
    # instance (orphan / competing authority), reconciled in both directions.
    local disc
    while IFS= read -r disc; do
        [ -n "$disc" ] || continue
        awk -F"$_FS" -v p="$disc" '$2==p {f=1} END{exit !f}' <<<"$MANIFEST_DUMP" \
            || fail C4-orphan "discovered unit '$disc' is not a declared managed instance (orphan/competing authority)"
    done < <(cd "$DEPLOYMENT_DIR" && find . -type f -name '*.service' | sed 's|^\./||' | sort)
    while IFS= read -r disc; do
        [ -n "$disc" ] || continue
        awk -F"$_FS" -v p="$disc" '$5=="source" && $6==p {f=1} END{exit !f}' <<<"$MANIFEST_DUMP" \
            || fail C4-orphan "discovered config '$disc' is not a declared config source (orphan alternative)"
    done < <(cd "$DEPLOYMENT_DIR" && find ./config -type f -name '*.toml' 2>/dev/null | sed 's|^\./||' | sort)

    local ids; ids="$(awk -F"$_FS" '{print $1}' <<<"$MANIFEST_DUMP" | paste -sd, -)"
    echo "OK [authority] inventory reconciles ($ids); install↔prod --config agree; roots distinct; deploy-443 LIVE resolved; reachability C7 executed (root-guard + resolve); evidence-class:${ev_classes}; syntax shell=verified config=$c8_cfg unit=$c8_unit; binary argv0↔destination verified (C9) (§3:67)."
}

# Portable in-place rewrite: sed -E EXPR FILE > tmp && mv (BSD+GNU safe). Fails
# closed on a no-op (EXPR changed nothing) so a mutator whose pattern stops
# matching mutates nothing and the arm reds on the detectable no-op rather than
# on whatever else happens to be failing — closes the class, not the instance.
# Preserves the original file mode: sed's redirect creates a 0644 temp, so
# without restoring the mode an executable script (install.sh/deploy-443.sh)
# loses +x and the execution-based C6/C7 arms then fail on permission rather
# than the mutation — a silent attribution bug.
_rewrite() {
    local f="$1" expr="$2" mode
    mode="$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null)"
    sed -E "$expr" "$f" > "$f.__t" || return 1
    if cmp -s "$f" "$f.__t"; then
        rm -f "$f.__t"
        echo "_rewrite: no-op — '$expr' changed nothing in $f" >&2
        return 1
    fi
    mv "$f.__t" "$f"
    [ -n "$mode" ] && chmod "$mode" "$f"
}
# mut_manifest ID FIELD JSON_LITERAL — edit one instance field in the manifest
# (python-scoped by id; sed cannot safely target a single JSON record).
mut_manifest() {
    python3 - "$1" "$2" "$3" authority-inventory.json <<'PY'
import sys, json
iid, field, literal = sys.argv[1], sys.argv[2], sys.argv[3]
path = "authority-inventory.json"
m = json.load(open(path))
for inst in m["instances"]:
    if inst["id"] == iid:
        cur = inst
        parts = field.split(".")
        for p in parts[:-1]:
            cur = cur[p]
        cur[parts[-1]] = json.loads(literal)
        break
json.dump(m, open(path, "w"), indent=2)
PY
}

# --- self-test: each disclosed control must flip the check red ---------------
run_self_test() {
    local tmp pass=0 failed=0
    tmp="$(mktemp -d)"

    cp -r "$DEPLOYMENT_DIR" "$tmp/base"
    # Baseline (clean copy) MUST be compliant — the check itself is broken
    # otherwise. Capture includes stderr so a spurious FAIL tag is visible.
    if "$SCRIPT_PATH" --root "$tmp/base" >/dev/null 2>&1; then
        echo "[self-test] baseline (clean copy) compliant ✓"
    else
        echo "[self-test] FAIL: baseline clean copy is non-compliant — the check itself is broken" >&2
        "$SCRIPT_PATH" --root "$tmp/base" >&2 || true
        rm -rf "$tmp"
        return 1
    fi

    # The §3 controls: C1–C8. Mutators run with cwd = a fresh copy of
    # .deployment; _rewrite is the BSD+GNU-safe in-place sed. Manifest edits use
    # mut_manifest (python-scoped by instance id). C7 reachability, C8c unit
    # syntax, C4c config-orphan and C5b config-only-collision are new arms.
    mut_C1()  { mut_manifest prod installation.selector_args '["--instance", "prod"]'; }   # prod no longer the install default
    mut_C2a() { mut_manifest prod config.destination '"/etc/x0x/wrong.toml"'; }             # manifest dst disagrees with unit --config
    mut_C2b() { _rewrite systemd/x0xd.service 's| --config /etc/x0x/config.toml||'; }       # prod unit ExecStart has no --config
    mut_C3()  { rm -f systemd/x0xd-testnet.service; }                                       # declared unit.source missing
    mut_C4()  { printf '[Unit]\nDescription=staging\n\n[Service]\nExecStart=/opt/x0x/x0xd-staging --config /etc/x0x/staging.toml\n' > systemd/x0xd-staging.service; }
    mut_C4b() { printf '[Unit]\nDescription=competing\n\n[Service]\nExecStart=/opt/x0x/x0xd --config /etc/x0x/x0xd.toml\n' > x0xd.service; }
    mut_C4c() { printf '# orphan config\n' > config/orphan.toml; }                          # discovered config maps to no instance
    mut_C5()  { _rewrite systemd/x0xd-443.service 's|/etc/x0x/x0xd-443.toml|/etc/x0x/config.toml|'; }   # 443 root collides with prod
    mut_C5b() { _rewrite systemd/x0xd-443.service 's|/etc/x0x/x0xd-443.toml|/etc/x0x/config-testnet.toml|'; }  # 443 config collides with testnet
    mut_C6()  { _rewrite deploy-443.sh 's/inputs\[0\]/"testnet"/'; }                          # generator resolves the WRONG input instance for LIVE (testnet not prod) — C6-side sole-catcher
    mut_C7a() { mut_manifest testnet installation.entrypoint '"nonexistent.sh"'; }           # declared entrypoint absent on disk (testnet: avoids breaking C6's 443 self-resolution)
    mut_C7b() { mut_manifest testnet installation.selector_args '["--instance", "prod"]'; } # selector references wrong instance
    mut_C7c() { _rewrite install.sh 's#SCRIPT_DIR/authority-inventory.json"#SCRIPT_DIR/authority-inventory-missing.json"#'; } # install.sh manifest path broken → fails before root guard (execution-only catcher)
    mut_C7d() { _rewrite deploy-443.sh 's#rec\["unit"\]\["destination"\]#"/etc/systemd/system/x0xd-443.service"#'; mut_manifest 443 unit.destination '"/etc/systemd/system/x0xd-443-mut.service"'; } # 443 own-field two-part: hardcode old unit.destination + move manifest value → printed/manifest disagree
    mut_C8a() { printf '\nthen\n' >> install.sh; }                                          # bare keyword → bash -n syntax error
    mut_C8b() { printf '\nbroken = "unterminated\n' >> config/bootstrap-config.toml; }      # unterminated string → TOML parse error
    # 8c — unit syntax. Proven red only where systemd-analyze exists; skipped
    # WITH a printed note where absent (disclosed platform bound). The self-test
    # runs in two contexts — macOS dev (absent) and the ubuntu-latest CI runner
    # (present) — so the arm reports its own status per context.
    mut_C8c() { printf '[Service]\nExecStart=/opt/x0x/x0xd --config "/etc/x0x/config.toml\n' > systemd/x0xd-443.service; }  # unbalanced ExecStart quote → genuine systemd-analyze syntax error (was: bare --config = valid systemd syntax, inert)
    mut_C9a() { _rewrite systemd/x0xd-443.service 's|ExecStart=/opt/x0x/x0xd |ExecStart=/opt/x0x/x0xd-mut |'; }  # unit ExecStart argv0 moved; C8c placeholder follows argv0 (green) → C9 sole-catches (reads unit side)
    mut_C9b() { mut_manifest 443 binary.destination '"/opt/x0x/x0xd-mut-bin"'; }  # manifest binary.destination moved; no earlier control reads field 9 → C9 sole-catches (reads manifest side)
    # 8c-before-C9 fail-fast ordering: a unit with BOTH a C8c syntax error
    # (unbalanced ExecStart quote) AND a C9 argv0 mismatch (argv0 moved off the
    # manifest binary.destination) must fail at C8c (syntax) and never reach C9.
    # Proves the C8c→C9 ordering gates the comparison behind syntax. Like C8c,
    # runtime-provable only where systemd-analyze exists.
    mut_C8c_first() { printf '[Service]\nExecStart=/opt/x0x/x0xd-mut --config "/etc/x0x/config.toml\n' > systemd/x0xd-443.service; }  # unbalanced quote (C8c) + argv0=/opt/x0x/x0xd-mut (C9 mismatch) → C8c must fire first
    # 8p — path safety: an escaping unit ExecStart argv0 (e.g. /../sibling/x)
    # would, concatenated onto the hermetic C8c --root tree, write OUTSIDE the
    # stage before C9 runs. C8-unit-path (pure bash) catches it before ANY
    # staging write — platform-independent (no systemd-analyze needed). The arm
    # ALSO proves the negative: no marker is created outside the temp root.
    mut_C8p() { _rewrite systemd/x0xd-443.service 's|ExecStart=/opt/x0x/x0xd |ExecStart=/../escape-glm/marker |'; }  # argv0 escapes the stage: /../escape-glm/marker → C8-unit-path sole-catches before staging
    # manifest-side: a non-canonical absolute destination (contains '..') is
    # rejected by the strict manifest_load validator (is_abs) before any control.
    mut_C8m() { mut_manifest 443 binary.destination '"/opt/x0x/../escape"'; }  # canonical-absolute rejection: '..' segment → manifest_load fails closed

    # expect_fail NAME MUTATOR-FN [EXPECTED-TAG]: apply the mutator to a fresh
    # copy and expect the check red. When EXPECTED-TAG is given, the check's
    # output (captured with 2>&1 — fail() writes stderr) MUST contain that exact
    # FAIL tag, so attribution is structural, not merely positional (Dario/Kimi
    # disjoint-sole-catcher discipline). Without a tag the arm asserts exit-only
    # and must justify why no tag is assertable.
    expect_fail() {
        local name="$1" fn="$2" tag="${3:-}" d="$tmp/$1"
        rm -rf "$d"; cp -r "$tmp/base" "$d"
        # A mutator that itself fails (e.g. _rewrite no-op: its pattern matched
        # nothing, so the arm would exercise nothing) is a broken arm, not a
        # passing one — report and count it, do not abort under set -e.
        if ! ( cd "$d" && "$fn" ); then
            echo "[self-test] FAIL: $name — mutator failed (no-op _rewrite or error); arm not exercised" >&2
            failed=$((failed + 1)); return
        fi
        # `if cmd; then` form is set-e safe: a red check exits non-zero and
        # must NOT abort the script before we record rc.
        if out="$("$SCRIPT_PATH" --root "$d" 2>&1)"; then rc=0; else rc=$?; fi
        if [ "$rc" -eq 0 ]; then
            echo "[self-test] FAIL: $name — violation NOT caught (exit 0)" >&2
            failed=$((failed + 1)); return
        fi
        if [ -n "$tag" ]; then
            if ! grep -q "FAIL \[$tag\]" <<<"$out"; then
                echo "[self-test] FAIL: $name — red (exit $rc) but expected tag [$tag] absent; emitted:" >&2
                grep 'FAIL \[' <<<"$out" >&2 || true
                failed=$((failed + 1)); return
            fi
        fi
        echo "[self-test] ok: $name — violation caught ✓${tag:+ (tag $tag)}"
        pass=$((pass + 1))
    }

    # Each arm names the tag its condition emits. Tags shared across sibling
    # emit-sites (C1, C3, C4, C6) are asserted but do not by themselves
    # discriminate which site fired — see the per-arm accounting below.
    expect_fail C1-not-install-default           mut_C1   C1-authority
    expect_fail C2-config-disagree               mut_C2a  C2-disagree
    expect_fail C2-no-config-flag                mut_C2b  C2-no-config
    expect_fail C3-missing-testnet-unit          mut_C3   C3-missing
    expect_fail C4-orphan-unit                   mut_C4   C4-orphan
    expect_fail C4-competing-prod-unit           mut_C4b  C4-orphan
    expect_fail C4-orphan-config                 mut_C4c  C4-orphan
    expect_fail C5-duplicate-root                mut_C5   C5-dup-root
    expect_fail C5-duplicate-config              mut_C5b  C5-dup-config
    expect_fail C6-deploy443-source-mismatch     mut_C6   C6-source
    expect_fail C7-missing-entrypoint            mut_C7a  C7-missing-artifact
    expect_fail C7-selector-mismatch             mut_C7b  C7-entrypoint-selector
    expect_fail C7-install-unreachable           mut_C7c  C7-unreachable
    expect_fail C7-443-resolve-disagree          mut_C7d  C7-resolve-disagree
    expect_fail C8-shell-syntax-error            mut_C8a  C8-shell-syntax
    expect_fail C8-config-syntax-error           mut_C8b  C8-config-syntax
    expect_fail C8-manifest-noncanonical      mut_C8m  manifest
    # 8c: platform-bound. Run + assert tag where systemd-analyze exists; else
    # report the arm skipped with its disclosed reason (never silently absent).
    if command -v systemd-analyze >/dev/null 2>&1; then
        expect_fail C8-unit-syntax-error         mut_C8c  C8-unit-syntax
        # Fail-fast ordering: a unit with BOTH a C8c syntax error and a C9
        # argv0 mismatch must fail at C8c (C8-unit-syntax), never reaching C9.
        expect_fail C8c-before-C9-failfast       mut_C8c_first  C8-unit-syntax
        c8c_arm="verified"
    else
        echo "[self-test] skip: C8-unit-syntax-error + C8c-before-C9-failfast — systemd-analyze absent on this host (CI runner proves them red)" >&2
        c8c_arm="skipped(no systemd-analyze)"
    fi
    expect_fail C9-unit-argv0-moved        mut_C9a  C9-bin-argv0
    expect_fail C9-bin-destination-moved   mut_C9b  C9-bin-argv0
    # C8-unit-path proof: an escaping argv0 (/../escape-glm/marker) is caught by
    # C8-unit-path (pure bash, platform-independent) BEFORE C8c's staging
    # mkdir/write. The tag-firing is proven on every host. The no-outside-marker
    # filesystem proof runs only where C8c staging actually executes
    # (systemd-analyze present) — elsewhere C8c is skipped so no escape vector
    # materialises (same disclosed platform bound as the C8c arm above). On Linux
    # TMPDIR is pinned so the would-be escape target (<stage>/../escape-glm/marker,
    # where stage=$work/tmp.X, collapsing to $work/escape-glm/marker) is
    # deterministic; a leftover marker proves the gate failed OPEN.
    {
        local d8p out8p rc8p
        d8p="$tmp/C8-unit-path-escape"; rm -rf "$d8p"; cp -r "$tmp/base" "$d8p"
        if ! ( cd "$d8p" && mut_C8p ); then
            echo "[self-test] FAIL: C8-unit-path-escape — mutator failed (no-op _rewrite)" >&2
            failed=$((failed + 1))
        else
            if out8p="$("$SCRIPT_PATH" --root "$d8p" 2>&1)"; then rc8p=0; else rc8p=$?; fi
            if [ "$rc8p" -eq 0 ] || ! grep -q "FAIL \[C8-unit-path\]" <<<"$out8p"; then
                echo "[self-test] FAIL: C8-unit-path-escape — control did not fire (rc=$rc8p)" >&2
                failed=$((failed + 1))
            elif command -v systemd-analyze >/dev/null 2>&1; then
                # C8c stages here: prove no marker escapes the temp root.
                local work8p marker_parent
                work8p="$(mktemp -d)"; marker_parent="$work8p/escape-glm"
                rm -rf "$marker_parent"
                if TMPDIR="$work8p" "$SCRIPT_PATH" --root "$d8p" >/dev/null 2>&1; then :; fi
                if [ -e "$marker_parent" ]; then
                    echo "[self-test] FAIL: C8-unit-path-escape — marker written OUTSIDE stage (gate failed open)" >&2
                    failed=$((failed + 1))
                else
                    echo "[self-test] ok: C8-unit-path-escape — escaping argv0 rejected (C8-unit-path), no marker outside stage ✓"
                    pass=$((pass + 1))
                fi
                rm -rf "$work8p"
            else
                echo "[self-test] ok: C8-unit-path-escape — escaping argv0 rejected (C8-unit-path) ✓; no-marker proof deferred to CI (C8c staging skipped: systemd-analyze absent)"
                pass=$((pass + 1))
            fi
        fi
    }

    rm -rf "$tmp"
    echo "[self-test] $pass control(s) fired, $failed failed to fire; C8c arm=$c8c_arm"
    echo "[self-test] attribution: single-site={C2-disagree, C2-no-config, C5-dup-root, C5-dup-config, C7-missing-artifact, C7-entrypoint-selector, C7-unreachable, C7-resolve-disagree, C8-shell-syntax, C8-config-syntax, C8-unit-path, C8-unit-syntax, C9-bin-argv0}; shared={C1-authority, C3-missing, C4-orphan, C6-source}; manifest={C8-manifest-noncanonical}; shadowed={C7-resolve-failed ← C6 (both run --resolve, C6 first)}"
    [ "$failed" -eq 0 ]
}

if [ "$MODE" = "self-test" ]; then
    run_self_test
    exit $?
else
    run_check
    exit $?
fi
