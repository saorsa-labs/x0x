#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CHECK="$SCRIPT_DIR/health-check.sh"
EXPECTED_VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$SCRIPT_DIR/../Cargo.toml" | sed -n '1p')
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

host=""
for arg in "$@"; do
    case "$arg" in root@*) host=${arg#root@};; esac
done

case "${HEALTH_SCENARIO:-healthy}:$host" in
    mixed:147.182.234.192) printf 'inactive\n{"status":"healthy","version":"%s"}\n{}\n' "$HEALTH_EXPECTED_VERSION" ;;
    mixed:152.42.210.67) exit 255 ;;
    mixed:170.64.176.102) printf 'active\nFAILED\n{}\n' ;;
    missing:142.93.199.50) printf 'active\n{"status":"healthy"}\n{"connected_peers":5}\n' ;;
    wrong:142.93.199.50) printf 'active\n{"status":"healthy","version":"0.0.0"}\n{"connected_peers":5}\n' ;;
    peersmissing:142.93.199.50) printf 'active\n{"status":"healthy","version":"%s"}\n{"status":"connected"}\n' "$HEALTH_EXPECTED_VERSION" ;;
    *) printf 'active\n{"status":"healthy","version":"%s"}\n{"connected_peers":5}\n' "$HEALTH_EXPECTED_VERSION" ;;
esac
EOF
chmod +x "$TMP/ssh"

run_check() {
    local scenario=$1 output_file=$2
    shift 2
    set +e
    PATH="$TMP:$PATH" HEALTH_SCENARIO="$scenario" HEALTH_EXPECTED_VERSION="$EXPECTED_VERSION" \
        bash "$CHECK" "$@" >"$output_file" 2>&1
    RUN_STATUS=$?
    set -e
}

assert_contains() {
    local file=$1 expected=$2
    if ! grep -Fq -- "$expected" "$file"; then
        printf 'missing expected output %q in:\n' "$expected" >&2
        cat "$file" >&2
        exit 1
    fi
}

assert_all_nodes_checked() {
    local file=$1
    for node in nyc sfo singapore sydney; do
        assert_contains "$file" "$node"
    done
}

out="$TMP/all-healthy"
run_check healthy "$out" --extended
[[ $RUN_STATUS -eq 0 ]]
assert_all_nodes_checked "$out"
assert_contains "$out" "Expected version: v$EXPECTED_VERSION"
assert_contains "$out" "Summary: 4/4 nodes healthy"
assert_contains "$out" "peers: 5"

out="$TMP/peersmissing"
run_check peersmissing "$out" --extended
[[ $RUN_STATUS -eq 0 ]]
assert_all_nodes_checked "$out"
assert_contains "$out" "Summary: 4/4 nodes healthy"
assert_contains "$out" "peers: ?"

out="$TMP/mixed"
run_check mixed "$out" --extended
[[ $RUN_STATUS -eq 1 ]]
assert_all_nodes_checked "$out"
assert_contains "$out" "SERVICE inactive"
assert_contains "$out" "SSH FAILED"
assert_contains "$out" "HEALTH FAILED"
assert_contains "$out" "Summary: 1/4 nodes healthy"

for scenario in missing wrong; do
    out="$TMP/$scenario"
    run_check "$scenario" "$out"
    [[ $RUN_STATUS -eq 1 ]]
    assert_all_nodes_checked "$out"
    assert_contains "$out" "Summary: 3/4 nodes healthy"
done
assert_contains "$TMP/missing" "VERSION MISSING"
assert_contains "$TMP/wrong" "VERSION MISMATCH"

printf 'health-check controls: PASS\n'
