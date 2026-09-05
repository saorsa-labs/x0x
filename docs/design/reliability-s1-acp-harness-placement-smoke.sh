#!/usr/bin/env bash
# S1 ACP harness placement smoke — offline fixtures (live dual-daemon blocked).
#
# Requires a captured successful GET /owner/placement response, then
# observes an assembled snapshot of owner_machine_id, placement
# {kind,machine_id}, and harness_machine {machine_id, agent_ids}.
# Does not start daemons, touch the mesh, or implement #512 / #507 /
# #508 / #509 product fixes.
#
# Live dual-daemon (G3) is not accepted by this offline-only script.
# Reviewed #512 tip f1418a0 removes the unsafe bypass; authenticated
# identity-ingest regression evidence remains pending. Offline --self-test is the acceptance-oracle proof
# available now. No Ben Mac.
#
# Exit codes (--fixture / --classify-snapshot):
#   0  PASS — pinned to harness ≠ owner and agent_ids contains agent
#             OR pending with no pin/bind and agent absent from a
#             successful lazy-mint ledger capture (G1)
#   1  FAIL — pinned to owner with valid empty binding evidence
#             OR agent bound on a machine that is not the pin
#             (wrong-machine / mode=Acp fail-open never PASS)
#   3  inconclusive — missing/error ledger, malformed or contradictory
#                     evidence, missing placement / ids / other shapes
#
# --self-test exits 0 only when every required fixture matches.
#
# See docs/design/reliability-acp-harness-placement-acceptance.md
# and docs/design/reliability-acceptance-scenarios.md § G.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="${SCRIPT_DIR}/reliability-s1-acp-fixtures"

REQUIRED_FIXTURES=(
  fail-open-wrong-machine-must-not-pass
  fail-pinned-to-owner-empty-agent-ids
  inconclusive-missing-placement
  inconclusive-pending-body-error
  inconclusive-pending-existing-ledger-pin
  inconclusive-pending-http-error
  inconclusive-pending-malformed-bindings
  inconclusive-pending-missing-harness
  inconclusive-pending-missing-ledger
  inconclusive-pending-missing-rows
  inconclusive-pending-owner-pin
  inconclusive-pending-read-only-endpoint
  pass-pending-known-empty-binding
  pass-pending-unknown-harness
  pass-pin-harness-machine
)

usage() {
  cat <<'EOF'
S1 ACP harness placement smoke (offline fixtures).

Live dual-daemon remains unaccepted at reviewed #512 f1418a0 (ingest regression pending).
Offline fixture mode is the acceptance-oracle proof (no daemon, no mesh):

  docs/design/reliability-s1-acp-harness-placement-smoke.sh --self-test
  docs/design/reliability-s1-acp-harness-placement-smoke.sh --fixture pass-pin-harness-machine
  docs/design/reliability-s1-acp-harness-placement-smoke.sh --classify-snapshot snap.json
  docs/design/reliability-s1-acp-harness-placement-smoke.sh --list-fixtures

Exit 0 = PASS, 1 = FAIL, 3 = inconclusive.
--self-test exits 0 only if every required fixture matches its expected code.
EOF
}

MODE="blocked-live"
FIXTURE_NAME=""
SNAPSHOT_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --self-test)
      MODE="self-test"
      shift
      ;;
    --fixture)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        echo "error: --fixture requires a name" >&2
        usage >&2
        exit 3
      fi
      MODE="fixture"
      FIXTURE_NAME="$2"
      shift 2
      ;;
    --classify-snapshot)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        echo "error: --classify-snapshot requires a JSON path" >&2
        usage >&2
        exit 3
      fi
      MODE="snapshot"
      SNAPSHOT_PATH="$2"
      shift 2
      ;;
    --list-fixtures)
      MODE="list"
      shift
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 3
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required to classify placement snapshots" >&2
  exit 3
fi

# Deterministic S1 transform of one observational snapshot.
classify_snapshot() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys

PENDING_KINDS = frozenset({"pending", "unbound", "deferred", "unknown"})


def as_id(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        print("INCONCLUSIVE: identifiers must be strings or null")
        sys.exit(3)
    return value.strip()


def as_kind(value) -> str:
    return as_id(value).lower()


def load_snapshot(path: str) -> dict:
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(3)
    if not raw.strip():
        print(f"error: empty snapshot in {path}", file=sys.stderr)
        sys.exit(3)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: snapshot is not JSON: {exc}", file=sys.stderr)
        sys.exit(3)
    if not isinstance(body, dict):
        print("error: snapshot must be a JSON object", file=sys.stderr)
        sys.exit(3)
    if "snapshot" in body and isinstance(body["snapshot"], dict):
        return body["snapshot"]
    return body


def inconclusive(reason):
    print(f"INCONCLUSIVE: {reason}")
    sys.exit(3)


def agent_ids_of(harness) -> list:
    if harness is None:
        return []
    if not isinstance(harness, dict):
        inconclusive("harness_machine must be an object or explicit null")
    raw = harness.get("agent_ids")
    if not isinstance(raw, list) or any(not isinstance(x, str) or not x.strip() for x in raw):
        inconclusive("harness agent_ids must be an array of nonempty strings")
    if "machine_id" not in harness:
        inconclusive("missing harness machine_id")
    machine_id = as_id(harness["machine_id"])
    if raw and not machine_id:
        inconclusive("bound agents require a known harness machine")
    return [x.strip() for x in raw]


snap = load_snapshot(sys.argv[1])
agent_id = as_id(snap.get("agent_id"))
owner_machine_id = as_id(snap.get("owner_machine_id"))
placement = snap.get("placement")
if "harness_machine" not in snap:
    inconclusive("missing harness observation (use explicit null for observed absence)")
harness = snap["harness_machine"]
harness_machine_id = as_id(harness.get("machine_id") if isinstance(harness, dict) else None)
bound_ids = agent_ids_of(harness)
bound = bool(agent_id and agent_id in bound_ids)

if isinstance(placement, dict):
    kind = as_kind(placement.get("kind"))
    pin_machine = as_id(placement.get("machine_id"))
    alias_pin = as_id(placement.get("pinned_machine"))
    if pin_machine and alias_pin and pin_machine != alias_pin:
        inconclusive("conflicting placement machine identifiers")
    pin_machine = pin_machine or alias_pin
else:
    kind = ""
    pin_machine = ""

print(
    f"agent_id={agent_id or '(none)'} owner_machine_id={owner_machine_id or '(none)'} "
    f"placement.kind={kind or '(missing)'} placement.machine_id={pin_machine or '(none)'} "
    f"harness_machine.machine_id={harness_machine_id or '(none)'} "
    f"agent_ids={bound_ids} bound={bound}"
)

if not agent_id or not owner_machine_id:
    print("INCONCLUSIVE: missing required agent_id or owner_machine_id")
    sys.exit(3)

if not isinstance(placement, dict):
    print("INCONCLUSIVE: missing placement object")
    sys.exit(3)

# A per-agent 404 is not a mint attempt. Retain the actual ledger trigger
# response and compare its rows with the assembled observation before PASS.
capture = snap.get("ledger_capture")
if not isinstance(capture, dict):
    inconclusive("missing GET /owner/placement capture")
if capture.get("method") != "GET" or capture.get("path") != "/owner/placement":
    inconclusive("ledger capture must identify the lazy-mint endpoint")
if type(capture.get("http_status")) is not int or capture["http_status"] != 200:
    inconclusive("ledger mint request did not return HTTP 200")
body = capture.get("body")
if not isinstance(body, dict) or body.get("ok") is not True:
    inconclusive("missing or unsuccessful ledger body")
rows = body.get("placements")
if not isinstance(rows, list) or any(
    not isinstance(row, dict) or not isinstance(row.get("agent_id"), str)
    or not row["agent_id"].strip() for row in rows
):
    inconclusive("missing or malformed ledger placements")
matching = [row for row in rows if row["agent_id"].strip() == agent_id]
if len(matching) > 1:
    inconclusive("duplicate agent placement rows")

if kind in PENDING_KINDS:
    if pin_machine or matching or bound:
        inconclusive("pending contradicts a pin, ledger record, or bound agent")
    print("PASS: successful mint deferred this unbound agent (G1)")
    sys.exit(0)

if kind == "pinned":
    if len(matching) != 1:
        inconclusive("pinned snapshot lacks its ledger record")
    row = matching[0]
    if row.get("kind") != "pinned" or as_id(row.get("pinned_machine")) != pin_machine:
        inconclusive("snapshot pin disagrees with ledger record")
    epoch = placement.get("epoch")
    if type(epoch) is not int or epoch < 0 or type(row.get("epoch")) is not int or row["epoch"] != epoch:
        inconclusive("missing or inconsistent placement epoch")

if kind != "pinned":
    print(f"INCONCLUSIVE: unclassifiable placement kind {kind or '(empty)'}")
    sys.exit(3)

if not pin_machine:
    print("INCONCLUSIVE: pinned placement missing machine_id")
    sys.exit(3)

if (
    pin_machine != owner_machine_id
    and harness_machine_id == pin_machine
    and bound
):
    print("PASS: pinned to harness machine ≠ owner and agent_ids contains agent (G2)")
    sys.exit(0)

if pin_machine == owner_machine_id and not bound:
    print(
        "FAIL: pinned to owner machine with empty/missing agent_ids "
        "(epoch-0 owner pin / harness-ping hole; G1/G2)"
    )
    sys.exit(1)

if bound and harness_machine_id != pin_machine:
    print(
        "FAIL: agent bound on a machine that is not the pin "
        "(wrong-machine bind / mode=Acp fail-open must not PASS; G4/G5)"
    )
    sys.exit(1)

print(
    "INCONCLUSIVE: not a harness-pin PASS, not a pending PASS, "
    "and not an owner-pin or wrong-machine FAIL"
)
sys.exit(3)
PY
}

load_fixture() {
  local name="$1"
  local spec="${FIXTURE_DIR}/${name}.json"
  if [[ ! -f "$spec" ]]; then
    echo "error: fixture not found: $spec" >&2
    exit 3
  fi
  python3 - "$spec" "$tmp_snap" <<'PY'
import json
import sys

spec_path, dest = sys.argv[1], sys.argv[2]
try:
    spec = json.load(open(spec_path, encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    print(f"error: cannot load fixture {spec_path}: {exc}", file=sys.stderr)
    sys.exit(3)
if "expected_exit" not in spec or "snapshot" not in spec:
    print(f"error: fixture {spec_path} must have expected_exit and snapshot", file=sys.stderr)
    sys.exit(3)
try:
    json.dump(spec["snapshot"], open(dest, "w", encoding="utf-8"))
except (OSError, TypeError) as exc:
    print(f"error: cannot write fixture snapshot: {exc}", file=sys.stderr)
    sys.exit(3)
print(spec["expected_exit"])
PY
}

tmp_snap="$(mktemp)"
cleanup() {
  rm -f "$tmp_snap"
}
trap cleanup EXIT

if [[ "$MODE" == "list" ]]; then
  echo "Required fixtures in ${FIXTURE_DIR}:"
  for name in "${REQUIRED_FIXTURES[@]}"; do
    echo "  $name"
  done
  exit 0
fi

if [[ "$MODE" == "blocked-live" ]]; then
  echo "LIVE UNACCEPTED: use retained evidence from the corrected #512 tip and real ingest regression." >&2
  echo "Reviewed #512 head f1418a0 removes the bypass; real identity-ingest regression is pending." >&2
  echo "Offline proof: $0 --self-test   (no daemon, no mesh, no Ben Mac)" >&2
  usage >&2
  exit 3
fi

if [[ "$MODE" == "self-test" ]]; then
  echo "=== S1 fixture self-test (no daemon, no mesh; live dual-daemon blocked) ==="
  failed=0
  for name in "${REQUIRED_FIXTURES[@]}"; do
    expected="$(load_fixture "$name")"
    set +e
    out="$(classify_snapshot "$tmp_snap" 2>&1)"
    actual=$?
    set -e
    if [[ "$actual" -eq "$expected" ]]; then
      verdict="OK"
    else
      verdict="MISMATCH"
      failed=1
    fi
    printf '%-42s expected=%s actual=%s  %s\n' "$name" "$expected" "$actual" "$verdict"
    printf '%s\n' "$out" | sed 's/^/  /'
  done
  if [[ "$failed" -ne 0 ]]; then
    echo "SELF-TEST FAIL: one or more fixtures did not match expected exit"
    exit 1
  fi
  echo "SELF-TEST PASS: all required fixtures matched expected exits"
  exit 0
fi

if [[ "$MODE" == "fixture" ]]; then
  echo "fixture: $FIXTURE_NAME  (offline; no daemon, no mesh)"
  expected="$(load_fixture "$FIXTURE_NAME")"
  echo "expected_exit=$expected"
  set +e
  classify_snapshot "$tmp_snap"
  rc=$?
  set -e
  exit "$rc"
fi

if [[ "$MODE" == "snapshot" ]]; then
  echo "classify-snapshot: $SNAPSHOT_PATH"
  set +e
  classify_snapshot "$SNAPSHOT_PATH"
  rc=$?
  set -e
  exit "$rc"
fi

echo "error: unreachable mode $MODE" >&2
exit 3
