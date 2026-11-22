#!/usr/bin/env bash
# =============================================================================
# scripts/ci/test_coverage_gate.sh — deterministic controls for the Coverage
# Gate step (issue #607).
#
# Extracts the ACTUAL `run:` block of "Run line coverage gate" from
# .github/workflows/ci-full.yml and executes it in a temp directory with PATH-stub
# `cargo` / `python3` and a stub scripts/ci/nextest-isolated.sh, exactly as
# GitHub runs it (`bash -e`). Four cases:
#
#   success   — all phases exit 0 → job exits 0, all three phases ran in order
#   test_fail — nextest exits 1  → job exits 1, report AND ratchet still ran
#   rep_fail  — llvm-cov report exits 2 → job exits 2, ratchet still ran
#   rat_fail  — ratchet script exits 3 → job exits 3
#
# Every case also asserts the arguments were preserved verbatim from the
# workflow: --no-fail-fast and the exclusion filter on the test pass,
# --fail-under-lines on the report, --thresholds/--enforce-global on the
# ratchet. If ci-full.yml ever drifts (flag dropped, filter edited), the recorded
# stub arguments no longer match and these controls fail.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CI_YML="$REPO_ROOT/.github/workflows/ci-full.yml"
REAL_PYTHON3="$(command -v python3)"
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf 'ok %d - %s\n' "$((PASS+FAIL))" "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'not ok %d - %s\n' "$((PASS+FAIL))" "$*"; }

# ── Extract the run block of the coverage step (dedent the 10-space body). ──
extract_run_block() {
    awk '
      /^      - name: Run line coverage gate$/ { in_step=1; next }
      in_step && /^      - name: / { exit }
      in_step && /^        run: \|$/ { in_run=1; next }
      in_run {
        if ($0 ~ /^          /) { sub(/^          /, ""); print; next }
        if ($0 ~ /^[[:space:]]*$/) { print; next }
        exit
      }
    ' "$CI_YML"
}

EXCLUSION_FILTER='!binary(x0x_0041_synthetic_kill_restart) & !binary(x0x_0041_prefer_newest_test) & !binary(named_group_join_metadata_event)'

# ── One case: run_case <name> <test_rc> <report_rc> <ratchet_rc> <want_rc> ──
run_case() {
    local name="$1" test_rc="$2" report_rc="$3" ratchet_rc="$4" want_rc="$5"
    local tmp; tmp="$(mktemp -d)"
    local state="$tmp/state"; mkdir -p "$state" "$tmp/scripts/ci" "$tmp/runner" "$tmp/stubbin"
    export X0X_607_STATE="$state"
    export X0X_607_TEST_RC="$test_rc"
    export X0X_607_REPORT_RC="$report_rc"
    export X0X_607_RATCHET_RC="$ratchet_rc"

    # Stub nextest-isolated.sh: records args, one per line, then exits $test_rc.
    cat > "$tmp/scripts/ci/nextest-isolated.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$X0X_607_STATE/nextest.args"
echo nextest >> "$X0X_607_STATE/order.log"
exit "$X0X_607_TEST_RC"
STUB
    chmod +x "$tmp/scripts/ci/nextest-isolated.sh"

    # PATH-stub cargo: dispatch on the llvm-cov subcommand.
    cat > "$tmp/stubbin/cargo" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
    "llvm-cov show-env")
        echo "export X0X_STUB_LLVM_COV_ENV=1"
        exit 0 ;;
    "llvm-cov clean") exit 0 ;;
    "llvm-cov report")
        printf '%s\n' "$@" > "$X0X_607_STATE/report.args"
        echo report >> "$X0X_607_STATE/order.log"
        : > lcov.info
        exit "$X0X_607_REPORT_RC" ;;
esac
echo "stub cargo: unexpected invocation: $*" >&2
exit 99
STUB
    chmod +x "$tmp/stubbin/cargo"

    # PATH-stub python3: intercept only the ratchet script; delegate the rest.
    cat > "$tmp/stubbin/python3" <<STUB
#!/usr/bin/env bash
if [ "\${1:-}" = "scripts/check-coverage-thresholds.py" ]; then
    printf '%s\n' "\$@" > "\$X0X_607_STATE/ratchet.args"
    echo ratchet >> "\$X0X_607_STATE/order.log"
    exit "\$X0X_607_RATCHET_RC"
fi
exec "$REAL_PYTHON3" "\$@"
STUB
    chmod +x "$tmp/stubbin/python3"

    extract_run_block > "$tmp/step.sh"
    # shellcheck disable=SC2116
    RUN_BLOCK_LINES="$(wc -l < "$tmp/step.sh")"
    if [ "$RUN_BLOCK_LINES" -lt 5 ]; then
        fail "$name: extraction produced only $RUN_BLOCK_LINES lines"
        rm -rf "$tmp"; return
    fi

    local got_rc=0
    (
        cd "$tmp"
        export RUNNER_TEMP="$tmp/runner"
        export PATH="$tmp/stubbin:$PATH"
        bash -e "$tmp/step.sh"
    ) || got_rc=$?

    # 1. Exit code preserved.
    if [ "$got_rc" -eq "$want_rc" ]; then
        pass "$name: job exit $got_rc"
    else
        fail "$name: expected exit $want_rc, got $got_rc"
    fi

    # 2. All three phases ran, in order — in EVERY case.
    printf 'nextest\nreport\nratchet\n' > "$state/order.want"
    if cmp -s "$state/order.log" "$state/order.want"; then
        pass "$name: all three phases ran in order (test → report → ratchet)"
    else
        fail "$name: phase order wrong: $(tr '\n' ' ' < "$state/order.log" 2>/dev/null)"
    fi

    # 3. Arguments preserved verbatim from the workflow.
    local ok_args=true
    grep -Fx -- '--no-fail-fast' "$state/nextest.args" >/dev/null || ok_args=false
    grep -Fx -- "$EXCLUSION_FILTER" "$state/nextest.args" >/dev/null || ok_args=false
    grep -Fx -- '--fail-under-lines' "$state/report.args" >/dev/null || ok_args=false
    grep -Fx -- '65.7' "$state/report.args" >/dev/null || ok_args=false
    grep -Fx -- '--enforce-global' "$state/ratchet.args" >/dev/null || ok_args=false
    grep -Fx -- '--thresholds' "$state/ratchet.args" >/dev/null || ok_args=false
    grep -Fx -- 'coverage-thresholds.toml' "$state/ratchet.args" >/dev/null || ok_args=false
    if [ "$ok_args" = true ]; then
        pass "$name: --no-fail-fast, exclusion filter, floor 65.7 and ratchet args preserved"
    else
        fail "$name: argument drift (see $state/*.args)"
    fi

    # 4. The report artifact exists whenever the report ran (always here).
    if [ -e "$tmp/lcov.info" ]; then
        pass "$name: lcov.info produced despite configured failures"
    else
        fail "$name: lcov.info missing"
    fi

    rm -rf "$tmp"
}

run_case success   0 0 0 0
run_case test_fail 1 0 0 1
run_case rep_fail  0 2 0 2
run_case rat_fail  0 0 3 3

printf '\n1..%d\n' "$((PASS+FAIL))"
if [ "$FAIL" -gt 0 ]; then
    echo "# $FAIL control(s) failed" >&2
    exit 1
fi
printf '# All %d control(s) passed\n' "$PASS"
