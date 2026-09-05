#!/usr/bin/env bash
# S0 Home dedup smoke — local named instances only.
#
# Observes GET /home on two enrolled instances that share an owner key.
# Does not start daemons, mint keys, touch the mesh, or implement product
# fixes for #507 / #508 / #509.
#
# Required env:
#   ALICE_URL      e.g. http://127.0.0.1:12701
#   ALICE_B_URL    e.g. http://127.0.0.1:12702
#   ALICE_TOK      bearer token for alice
#   ALICE_B_TOK    bearer token for alice-device-b
#
# Exit codes:
#   0  PASS — same group_id, or B reports elsewhere / adoption_pending
#   1  FAIL — both 200 local-ish with different group_ids (duplicate Homes)
#   3  inconclusive — missing env, HTTP/parse failure, or unclassifiable pair
#
# See docs/design/reliability-acceptance-scenarios.md (S0).

set -euo pipefail

usage() {
  cat <<'EOF'
S0 Home dedup smoke (local named instances only).

Usage:
  ALICE_URL=http://127.0.0.1:12701 \
  ALICE_B_URL=http://127.0.0.1:12702 \
  ALICE_TOK="$(cat /path/to/alice/api-token)" \
  ALICE_B_TOK="$(cat /path/to/alice-device-b/api-token)" \
  docs/design/reliability-s0-home-dedup-smoke.sh

Exit 0 = PASS, 1 = FAIL (duplicate authoritative Homes), 3 = inconclusive.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

missing=0
for var in ALICE_URL ALICE_B_URL ALICE_TOK ALICE_B_TOK; do
  if [[ -z "${!var:-}" ]]; then
    echo "error: $var is unset or empty" >&2
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  usage >&2
  exit 3
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 3
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required to classify GET /home JSON" >&2
  exit 3
fi

trim_slash() {
  local url="$1"
  echo "${url%/}"
}

fetch_home() {
  local url="$1"
  local tok="$2"
  local dest="$3"
  local code
  # Write body to dest; print HTTP status on stdout. Transient curl
  # failures are inconclusive (exit 3), not a product FAIL.
  code="$(
    curl -sS \
      --connect-timeout 3 \
      --max-time 10 \
      -o "$dest" \
      -w '%{http_code}' \
      -H "Authorization: Bearer ${tok}" \
      -H "Accept: application/json" \
      "$(trim_slash "$url")/home"
  )" || {
    echo "error: curl failed talking to $url" >&2
    exit 3
  }
  printf '%s' "$code"
}

tmp_a="$(mktemp)"
tmp_b="$(mktemp)"
cleanup() {
  rm -f "$tmp_a" "$tmp_b"
}
trap cleanup EXIT

status_a="$(fetch_home "$ALICE_URL" "$ALICE_TOK" "$tmp_a")"
status_b="$(fetch_home "$ALICE_B_URL" "$ALICE_B_TOK" "$tmp_b")"

echo "alice   HTTP $status_a  GET $(trim_slash "$ALICE_URL")/home"
echo "alice-b HTTP $status_b  GET $(trim_slash "$ALICE_B_URL")/home"

# Classify S0. The python helper is a deterministic transform of two
# GET /home snapshots — it does not start instances or mutate product state.
set +e
python3 - "$status_a" "$tmp_a" "$status_b" "$tmp_b" <<'PY'
import json
import sys

HONEST = {"elsewhere", "adoption_pending"}
LOCALISH = {"", "local", "local-ish", "authoritative"}


def load(status_s, path):
    try:
        status = int(status_s)
    except ValueError:
        print(f"error: unparseable HTTP status {status_s!r}", file=sys.stderr)
        sys.exit(3)
    raw = open(path, encoding="utf-8").read()
    body = None
    if raw.strip():
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"error: GET /home body is not JSON: {exc}", file=sys.stderr)
            print(raw[:400], file=sys.stderr)
            sys.exit(3)
    return status, body


def snapshot(label, status, body):
    if not isinstance(body, dict):
        return {
            "label": label,
            "status": status,
            "group_id": "",
            "resolution": "",
            "honest": False,
            "localish": False,
        }
    group_id = body.get("group_id")
    if group_id is None:
        group_id = ""
    else:
        group_id = str(group_id).strip()
    resolution = body.get("resolution")
    if resolution is None:
        resolution = ""
    else:
        resolution = str(resolution).strip().lower()
    honest = resolution in HONEST
    # Current product (pre-#507) has no resolution field: a 200 with
    # group_id is treated as local-ish / authoritative.
    localish = (
        status == 200
        and bool(group_id)
        and not honest
        and resolution in LOCALISH
    )
    return {
        "label": label,
        "status": status,
        "group_id": group_id,
        "resolution": resolution or "(absent)",
        "honest": honest,
        "localish": localish,
    }


def emit(snap):
    print(
        f"{snap['label']}: status={snap['status']} "
        f"group_id={snap['group_id'] or '(none)'} "
        f"resolution={snap['resolution']}"
    )


a = snapshot("alice", *load(sys.argv[1], sys.argv[2]))
b = snapshot("alice-b", *load(sys.argv[3], sys.argv[4]))
emit(a)
emit(b)

if a["group_id"] and a["group_id"] == b["group_id"]:
    print("PASS: both report the same group_id")
    sys.exit(0)

if b["honest"]:
    print("PASS: alice-b reports honest elsewhere/adoption_pending")
    sys.exit(0)

if a["localish"] and b["localish"] and a["group_id"] != b["group_id"]:
    print(
        "FAIL: both 200 local-ish with different group_ids "
        "(duplicate authoritative Homes; #507 / #449 class)"
    )
    sys.exit(1)

print(
    "INCONCLUSIVE: pair is not same-id PASS, not honest-B PASS, "
    "and not a duplicate-authoritative FAIL "
    "(check tokens, enrollment, and that both daemons are up)"
)
sys.exit(3)
PY
rc=$?
set -e
exit "$rc"
