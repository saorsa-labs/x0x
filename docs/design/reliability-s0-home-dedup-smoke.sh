#!/usr/bin/env bash
# S0 Home dedup smoke — local named instances, or offline fixtures.
#
# Observes GET /home on two enrolled instances that share an owner key.
# Does not start daemons, mint keys, touch the mesh, or implement product
# fixes for #507 / #508 / #509.
#
# Live daemon mode (acceptance against a running pair):
#   ALICE_URL      e.g. http://127.0.0.1:12701
#   ALICE_B_URL    e.g. http://127.0.0.1:12702
#   ALICE_TOK      bearer token for alice
#   ALICE_B_TOK    bearer token for alice-device-b
#
# Fixture mode (acceptance-oracle proof; no daemon, no mesh):
#   docs/design/reliability-s0-home-dedup-smoke.sh --fixture <name>
#   docs/design/reliability-s0-home-dedup-smoke.sh --self-test
#
# Exit codes (live and --fixture):
#   0  PASS — both 2xx; A.canonical_id == B.canonical_id
#             local/pre507: canonical = group_id
#             elsewhere / adoption_pending: canonical = canonical_group_id
#             (elsewhere has no group_id; adoption_pending.group_id may be
#             a losing local Home and is not the comparison key)
#   1  FAIL — both 2xx, both authoritative local, different group_ids
#   3  inconclusive — non-2xx, parse/schema errors, missing required id
#                     for that state, contradictory canonicals, unknown
#                     state, or any other unclassifiable pair
#
# --self-test exits 0 only when every required fixture matches its
# expected classifier exit; that is the offline proof, not an S0 PASS.
#
# See docs/design/reliability-acceptance-scenarios.md (S0).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="${SCRIPT_DIR}/reliability-s0-fixtures"

REQUIRED_FIXTURES=(
  pass-same-id
  pass-elsewhere-canonical
  pass-adoption-pending-canonical
  fail-duplicate-local
  inconclusive-b-500-elsewhere
  inconclusive-b-503-same-id
  inconclusive-elsewhere-wrong-id
  inconclusive-adoption-contradictory-canonical
)

usage() {
  cat <<'EOF'
S0 Home dedup smoke (local named instances, or offline fixtures).

Live daemon mode (both instances already running; no mesh):
  ALICE_URL=http://127.0.0.1:12701 \
  ALICE_B_URL=http://127.0.0.1:12702 \
  ALICE_TOK="$(cat /path/to/alice/api-token)" \
  ALICE_B_TOK="$(cat /path/to/alice-device-b/api-token)" \
  docs/design/reliability-s0-home-dedup-smoke.sh

Offline fixture mode (acceptance-oracle proof; no daemon, no mesh):
  docs/design/reliability-s0-home-dedup-smoke.sh --self-test
  docs/design/reliability-s0-home-dedup-smoke.sh --fixture pass-same-id
  docs/design/reliability-s0-home-dedup-smoke.sh --list-fixtures

Exit 0 = PASS, 1 = FAIL (duplicate authoritative Homes), 3 = inconclusive.
--self-test exits 0 only if every required fixture matches its expected code.
EOF
}

MODE="live"
FIXTURE_NAME=""

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
  echo "error: python3 is required to classify GET /home JSON" >&2
  exit 3
fi

# Deterministic S0 transform of two GET /home snapshots.
# Never starts instances or mutates product state.
classify_pair() {
  local status_a="$1"
  local file_a="$2"
  local status_b="$3"
  local file_b="$4"
  python3 - "$status_a" "$file_a" "$status_b" "$file_b" <<'PY'
import json
import sys

# Wire from #507 home.rs @ 413028e:
#   local / pre507: canonical = group_id
#   elsewhere:      canonical = canonical_group_id (no group_id)
#   adoption_pending: canonical = canonical_group_id
#                     (group_id is the losing local Home)


def is_2xx(status: int) -> bool:
    return 200 <= status <= 299


def as_id(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load(status_s: str, path: str):
    try:
        status = int(status_s)
    except ValueError:
        print(f"error: unparseable HTTP status {status_s!r}", file=sys.stderr)
        sys.exit(3)
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(3)
    if not raw.strip():
        print(f"error: empty GET /home body in {path}", file=sys.stderr)
        sys.exit(3)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: GET /home body is not JSON: {exc}", file=sys.stderr)
        print(raw[:400], file=sys.stderr)
        sys.exit(3)
    if not isinstance(body, dict):
        print("error: GET /home body must be a JSON object", file=sys.stderr)
        sys.exit(3)
    return status, body


def snapshot(label: str, status: int, body: dict) -> dict:
    group_id = as_id(body.get("group_id"))
    canonical_field = as_id(body.get("canonical_group_id"))
    snap = {
        "label": label,
        "status": status,
        "state": "(non-2xx)",
        "group_id": group_id,
        "canonical_id": "",
        "authoritative_local": False,
        "ok_http": is_2xx(status),
        "classifiable": False,
    }
    if not snap["ok_http"]:
        return snap
    if "ok" in body and body["ok"] is not True:
        snap["state"] = "(ok!=true)"
        return snap
    raw_state = body.get("state")
    if raw_state is None:
        kind = "pre507_local"
        snap["state"] = "pre507_local"
    else:
        kind = str(raw_state).strip().lower()
        snap["state"] = kind
    if kind in ("local", "pre507_local"):
        if not group_id:
            return snap
        snap["canonical_id"] = group_id
        snap["authoritative_local"] = True
        snap["classifiable"] = True
        return snap
    if kind == "elsewhere":
        if not canonical_field:
            return snap
        snap["canonical_id"] = canonical_field
        snap["authoritative_local"] = False
        snap["classifiable"] = True
        return snap
    if kind == "adoption_pending":
        if not canonical_field:
            return snap
        snap["canonical_id"] = canonical_field
        snap["authoritative_local"] = False
        snap["classifiable"] = True
        return snap
    snap["state"] = f"unknown:{kind}"
    return snap


def emit(snap: dict) -> None:
    print(
        f"{snap['label']}: status={snap['status']} state={snap['state']} "
        f"group_id={snap['group_id'] or '(none)'} "
        f"canonical_id={snap['canonical_id'] or '(none)'} "
        f"authoritative_local={snap['authoritative_local']}"
    )


alice = snapshot("alice", *load(sys.argv[1], sys.argv[2]))
alice_b = snapshot("alice-b", *load(sys.argv[3], sys.argv[4]))
emit(alice)
emit(alice_b)

if not alice["ok_http"] or not alice_b["ok_http"]:
    print(
        "INCONCLUSIVE: non-2xx on at least one side "
        "(never PASS — HTTP errors are not acceptance)"
    )
    sys.exit(3)

if (
    alice["classifiable"]
    and alice_b["classifiable"]
    and alice["canonical_id"]
    and alice_b["canonical_id"]
    and alice["canonical_id"] == alice_b["canonical_id"]
):
    print("PASS: both 2xx with the same canonical Home id")
    sys.exit(0)

if (
    alice["authoritative_local"]
    and alice_b["authoritative_local"]
    and alice["group_id"]
    and alice_b["group_id"]
    and alice["group_id"] != alice_b["group_id"]
):
    print(
        "FAIL: both 2xx authoritative local with different group_ids "
        "(duplicate authoritative Homes; #507 / #449 class)"
    )
    sys.exit(1)

print(
    "INCONCLUSIVE: pair is not same-canonical PASS "
    "and not a duplicate-authoritative FAIL "
    "(missing required id, unknown state, or contradictory canonicals)"
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
  python3 - "$spec" "$tmp_a" "$tmp_b" <<'PY'
import json
import sys

spec_path, dest_a, dest_b = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    spec = json.load(open(spec_path, encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    print(f"error: cannot load fixture {spec_path}: {exc}", file=sys.stderr)
    sys.exit(3)
for key in ("alice_status", "alice_body", "alice_b_status", "alice_b_body", "expected_exit"):
    if key not in spec:
        print(f"error: fixture {spec_path} missing {key}", file=sys.stderr)
        sys.exit(3)
try:
    json.dump(spec["alice_body"], open(dest_a, "w", encoding="utf-8"))
    json.dump(spec["alice_b_body"], open(dest_b, "w", encoding="utf-8"))
except (OSError, TypeError) as exc:
    print(f"error: cannot write fixture bodies: {exc}", file=sys.stderr)
    sys.exit(3)
print(f'{spec["alice_status"]} {spec["alice_b_status"]} {spec["expected_exit"]}')
PY
}

tmp_a="$(mktemp)"
tmp_b=""
cleanup() {
  rm -f "$tmp_a" "$tmp_b"
}
trap cleanup EXIT
tmp_b="$(mktemp)"

if [[ "$MODE" == "list" ]]; then
  echo "Required fixtures in ${FIXTURE_DIR}:"
  for name in "${REQUIRED_FIXTURES[@]}"; do
    echo "  $name"
  done
  exit 0
fi

if [[ "$MODE" == "self-test" ]]; then
  echo "=== S0 fixture self-test (no daemon, no mesh) ==="
  failed=0
  for name in "${REQUIRED_FIXTURES[@]}"; do
    read -r status_a status_b expected < <(load_fixture "$name")
    set +e
    out="$(classify_pair "$status_a" "$tmp_a" "$status_b" "$tmp_b" 2>&1)"
    actual=$?
    set -e
    if [[ "$actual" -eq "$expected" ]]; then
      verdict="OK"
    else
      verdict="MISMATCH"
      failed=1
    fi
    printf '%-46s expected=%s actual=%s  %s\n' "$name" "$expected" "$actual" "$verdict"
    printf '%s\n' "$out" | sed 's/^/  /'
  done
  if [[ "$failed" -ne 0 ]]; then
    echo "SELF-TEST FAIL: one or more fixtures did not match expected exit"
    exit 1
  fi
  echo "SELF-TEST PASS: eight required fixtures matched expected exits"
  exit 0
fi

if [[ "$MODE" == "fixture" ]]; then
  echo "fixture: $FIXTURE_NAME  (offline; no daemon, no mesh)"
  read -r status_a status_b expected < <(load_fixture "$FIXTURE_NAME")
  echo "alice   HTTP $status_a  (fixture)"
  echo "alice-b HTTP $status_b  (fixture)"
  echo "expected_exit=$expected"
  set +e
  classify_pair "$status_a" "$tmp_a" "$status_b" "$tmp_b"
  rc=$?
  set -e
  exit "$rc"
fi

# Live daemon mode.
if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required for live daemon mode" >&2
  exit 3
fi

missing=0
for var in ALICE_URL ALICE_B_URL ALICE_TOK ALICE_B_TOK; do
  if [[ -z "${!var:-}" ]]; then
    echo "error: $var is unset or empty (live mode); use --fixture / --self-test for offline proof" >&2
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  usage >&2
  exit 3
fi

trim_slash() {
  local url="$1"
  echo "${url%/}"
}

# Bearer token goes in a 0600 curl config, not argv.
fetch_home() {
  local url="$1"
  local tok="$2"
  local dest="$3"
  local cfg
  local code
  cfg="$(mktemp)"
  chmod 600 "$cfg"
  printf 'header = "Authorization: Bearer %s"\n' "$tok" >"$cfg"
  printf 'header = "Accept: application/json"\n' >>"$cfg"
  code="$(
    curl -sS \
      --config "$cfg" \
      --connect-timeout 3 \
      --max-time 10 \
      -o "$dest" \
      -w '%{http_code}' \
      "$(trim_slash "$url")/home"
  )" || {
    rm -f "$cfg"
    echo "error: curl failed talking to $url" >&2
    exit 3
  }
  rm -f "$cfg"
  printf '%s' "$code"
}

status_a="$(fetch_home "$ALICE_URL" "$ALICE_TOK" "$tmp_a")"
status_b="$(fetch_home "$ALICE_B_URL" "$ALICE_B_TOK" "$tmp_b")"

echo "alice   HTTP $status_a  GET $(trim_slash "$ALICE_URL")/home"
echo "alice-b HTTP $status_b  GET $(trim_slash "$ALICE_B_URL")/home"

set +e
classify_pair "$status_a" "$tmp_a" "$status_b" "$tmp_b"
rc=$?
set -e
exit "$rc"
