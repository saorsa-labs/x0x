#!/usr/bin/env bash
# =============================================================================
# Deploy the UDP/443 bootstrap listener (ADR-0011) to one or more VPS nodes.
#
# Each bootstrap host already runs x0xd.service on :5483. This stands up a
# SECOND, independent x0xd-443.service bound to [::]:443 (root, privileged
# port), with its own state dir + machine identity, alongside the existing
# listener. No client ever does this — only operator-run bootstrap nodes.
#
# A manifest consumer (design chapter §1a). The instance inventory lives in
# authority-inventory.json; this script reads and validates the manifest,
# resolves its own instance record (the unique record whose
# installation.entrypoint is this script with empty selector_args — the 443
# instance), and derives unit source, unit destination, the generated-config
# destination, and the live config it clones from its declared input instance.
# It holds no inline instance list and no inline destination paths: every
# instance-record value flows manifest → local resolution → positional args →
# the remote payload.
#
# The 443 config is generated FROM the production instance's live config
# (resolved from the manifest as input_instances[0]'s config.destination) so it
# can never drift from the running :5483 config: only bind_address, data_dir,
# identity_dir and api_address are overridden.
#
# Usage:
#   ./deploy-443.sh <node|all>        # deploy
#   DRY_RUN=1 ./deploy-443.sh <node>  # print actions only
#   ./deploy-443.sh --verify <node>   # verify an existing 443 listener
#   ./deploy-443.sh --resolve         # print the resolved values this script
#                                    # would ship, then exit (no fleet contact)
#
#   <node> ∈ nyc sfo helsinki nuremberg singapore sydney all
#
# Idempotent. Safe to re-run. Roll ONE node, verify, then the rest.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/authority-inventory.json"
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

# --- manifest resolution (§1a): deploy-443.sh is a consumer ------------------
# Resolve this script's own instance (the unique record whose
# installation.entrypoint is this script with empty selector_args) and derive
# every instance-record value from the manifest. Emits TSV:
#   id \t unit.source \t unit.destination \t gen(config.destination) \t live
# where `live` is input_instances[0]'s config.destination (the live config
# cloned on the host). Holds no inline instance list.
resolve_instance() {
    python3 - "$MANIFEST" "${BASH_SOURCE[0]##*/}" <<'PY'
import sys, json
path, self_entry = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        m = json.load(f)
except Exception as e:
    print(f"error: cannot load manifest {path}: {e}", file=sys.stderr); sys.exit(1)
insts = m.get("instances", [])
defs = [i for i in insts
        if i.get("installation", {}).get("entrypoint") == self_entry
        and not i.get("installation", {}).get("selector_args")]
if len(defs) != 1:
    print(f"error: manifest must name exactly one {self_entry} default instance "
          f"(entrypoint {self_entry}, empty selector_args); found {len(defs)}",
          file=sys.stderr); sys.exit(1)
rec = defs[0]
cfg = rec["config"]
if "source" in cfg:
    print(f"error: instance '{rec['id']}' is a tracked-config instance "
          f"(config.source present); {self_entry} serves generators only",
          file=sys.stderr); sys.exit(1)
for k in ("generator", "input_instances", "destination"):
    if k not in cfg:
        print(f"error: instance '{rec['id']}' config missing '{k}'", file=sys.stderr); sys.exit(1)
gen = cfg["destination"]
inputs = cfg["input_instances"]
live_rec = next((i for i in insts if i.get("id") == inputs[0]), None)
if live_rec is None:
    print(f"error: instance '{rec['id']}' input_instances references unknown id '{inputs[0]}'",
          file=sys.stderr); sys.exit(1)
live = live_rec["config"]["destination"]
print("\t".join([
    rec["id"],
    rec["unit"]["source"],
    rec["unit"]["destination"],
    gen,
    live,
]))
PY
}

IFS=$'\t' read -r INST_ID UNIT_SRC_REL UNIT_DST GEN LIVE < <(resolve_instance)
# Local unit source path (this script ships the unit file to the remote /tmp).
UNIT_SRC="$SCRIPT_DIR/$UNIT_SRC_REL"

# --- argument parsing --------------------------------------------------------
# --resolve is parsed BEFORE the usage/node guard and takes no node argument:
# an arm failing on a usage exit (2) proves nothing about resolution (Dario
# 05fad365 argument-parsing trap).
RESOLVE_ONLY=0
if [ "${1:-}" = "--resolve" ]; then RESOLVE_ONLY=1; shift; fi
VERIFY_ONLY=0
if [ "${1:-}" = "--verify" ]; then VERIFY_ONLY=1; shift; fi

if [ "$RESOLVE_ONLY" = 1 ]; then
    # Print the values this script resolves AND would actually ship to the
    # remote payload (LIVE, GEN, UNIT_DST are the positional args; UNIT_SRC is
    # the local unit file). Exits before deploy_node — no ssh/scp reachable on
    # this path, verifiable by construction (exit precedes the fleet functions)
    # and by execution. A check reconciling this output against the manifest
    # observes the SHIPPING path, never the manifest against itself.
    echo "id=$INST_ID"
    echo "unit.source=$UNIT_SRC_REL"
    echo "unit.destination=$UNIT_DST"
    echo "gen=$GEN"
    echo "live=$LIVE"
    exit 0
fi

TARGET="${1:-}"
if [ -z "$TARGET" ]; then err "usage: $0 [--resolve|--verify] <node|all>"; exit 2; fi

# Remote script executed on each host. Reads its values from positional args:
#   $1 = DRY (0|1), $2 = LIVE (live config path), $3 = GEN (generated config
#   destination), $4 = UNIT_DST (systemd unit destination). No defaults — a
#   missing arg is a fatal contract violation, not a silent fallback. The
#   driver quotes each value (printf %q) so a path containing whitespace
#   arrives as one argument, not two (Dario/Kimi word-split fix).
# Single-quoted heredoc — all expansion happens ON THE REMOTE.
REMOTE_DEPLOY=$(cat <<'EOF'
set -eu
DRY="${1:-0}"
LIVE="${2:?LIVE (live config path) required}"
GEN="${3:?GEN (generated config path) required}"
UNIT_DST="${4:?UNIT_DST (systemd unit destination) required}"
DATA_DIR=/var/lib/x0x-443
do_run() { if [ "$DRY" = 1 ]; then echo "  DRY: $*"; else eval "$@"; fi; }

[ -f "$LIVE" ] || { echo "FATAL: live config $LIVE not found"; exit 1; }

# Sanity: confirm the live config is the :5483 listener before cloning it.
if ! grep -Eq '^[[:space:]]*bind_address[[:space:]]*=' "$LIVE"; then
  echo "FATAL: $LIVE has no bind_address line — refusing to clone"; exit 1
fi

# Generate the 443 config: copy the live one, override exactly 4 keys
# (bind_address, data_dir, identity_dir, api_address).
#
# These four keys are TOP-LEVEL `DaemonConfig` fields (src/server/state.rs:200).
# TOML scoping makes placement load-bearing: a key written after a `[section]`
# header belongs to that section, and `DaemonConfig` carries no
# `deny_unknown_fields`, so a misplaced `data_dir` is parsed, ignored, and
# silently replaced by `default_data_dir()`. Two daemons on one host then
# resolve the same `<data_dir>/history.db`, which ADR-0023's exclusive open
# turns into a restart loop for whichever daemon loses the race (issue #281).
#
# The previous implementation was section-blind in both branches: it appended
# an absent key at EOF (every bootstrap-*.toml ends inside `[update]`, so the
# key landed there) and rewrote an existing key wherever it sat. The generated
# `diff -u` looked correct in both cases — the line really was written, just
# into the wrong scope. Per ADR-0025, the diff is not proof of the observation.
#
# This implementation is section-aware and self-healing: it deletes every
# occurrence of the key anywhere in the file, then re-emits it in the top-level
# block immediately before the first section header (or at EOF when the file
# has no sections, where EOF *is* top level).
TMP=$(mktemp)
override() { # key value(quoted-literal-to-write)
  local key="$1" val="$2"
  awk -v k="$key" -v v="$val" '
    /^[[:space:]]*\[/ && !done       { print k " = " v; done = 1 }
    $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { next }
                                     { print }
    END                              { if (!done) print k " = " v }
  ' "$TMP" > "$TMP.new" && mv "$TMP.new" "$TMP"
}
cp "$LIVE" "$TMP"
override bind_address '"[::]:443"'
override data_dir "\"$DATA_DIR/data\""
# Issue #385: the identity knob is `identity_dir` (top-level `DaemonConfig`).
# `machine_key_path` is NOT a field — it was silently ignored and every :443
# daemon fell back to the prod daemon's ~/.x0x keys, sharing one identity.
override identity_dir "\"$DATA_DIR/identity\""
# Distinct REST API port: x0xd binds api_address with `?` (fatal on conflict),
# and prod x0xd.service already holds 127.0.0.1:12600. The :443 listener needs
# its own port or it cannot start alongside the :5483 instance.
override api_address '"127.0.0.1:12643"'

echo "--- generated $GEN (diff vs live) ---"
diff -u "$LIVE" "$TMP" || true
echo "-------------------------------------"

# Fail closed BEFORE shipping: prove each overridden key is top-level in the
# generated file. The diff above shows only that a line was written, not that
# it is in scope — the exact gap that let issue #281 ship. `awk` finds the
# first section header; every override must appear before it, exactly once.
first_section=$(grep -nE '^[[:space:]]*\[' "$TMP" | head -1 | cut -d: -f1)
: "${first_section:=999999}"
for k in bind_address data_dir identity_dir api_address; do
  hits=$(grep -cE "^[[:space:]]*${k}[[:space:]]*=" "$TMP" || true)
  line=$(grep -nE "^[[:space:]]*${k}[[:space:]]*=" "$TMP" | head -1 | cut -d: -f1)
  if [ "$hits" != "1" ] || [ -z "$line" ] || [ "$line" -ge "$first_section" ]; then
    echo "FATAL: '$k' is not a single top-level key in the generated config"
    echo "       (occurrences=$hits line=${line:-none} first_section=$first_section)."
    echo "       A key at or after the first [section] header is silently ignored"
    echo "       by DaemonConfig and falls back to its default — issue #281."
    rm -f "$TMP"; exit 1
  fi
done
echo "  verified: 4/4 overrides are top-level (pre-[section]) keys"

do_run "mkdir -p $DATA_DIR/data"
if [ "$DRY" = 1 ]; then echo "  DRY: write $GEN"; else cp "$TMP" "$GEN"; fi
rm -f "$TMP"

# Install/refresh the systemd unit (delivered to /tmp by the local driver).
if [ -f /tmp/x0xd-443.service ]; then
  do_run "install -m 644 /tmp/x0xd-443.service $UNIT_DST"
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
    # The command string is re-parsed by the remote shell (the disable
    # acknowledges SC2029). Each positional value is printf-%q-escaped so a
    # path containing whitespace arrives as a single argument, not two.
    if $SSH "root@$ip" "bash -s -- $(printf %q "$DRY_RUN") $(printf %q "$LIVE") $(printf %q "$GEN") $(printf %q "$UNIT_DST")" <<<"$REMOTE_DEPLOY"; then
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
