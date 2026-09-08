#!/usr/bin/env bash
# Sequentially run every integration test binary.
#
# On macOS 26.4 aarch64, `cargo nextest run --all-features --workspace`
# spawns ~50 test binaries in parallel for the list phase; each gets
# stuck at `_dyld_start` for minutes because dyld closure resolution
# serialises catastrophically under that concurrency. Running per-binary
# avoids the mass spawn — each binary's --list then returns in ~6 ms and
# the run phase uses its own (in-process) thread pool. Lib + doc tests
# are run once up front.
#
# Usage: bash tests/run_full_suite.sh [--no-ignored]
# Requires the admitted Linux developer isolation prerequisites.
# Selection is nonignored; --no-ignored is retained as a compatibility no-op.

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for arg in "$@"; do
    case "$arg" in
        --no-ignored) : ;;
    esac
done

PASS=0
FAIL=0
SKIPPED=0
FAILED_BINARIES=()

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# Refuse unsupported hosts before compilation or any test runtime.
if python3 scripts/dev/test-isolated.py check; then
    :
else
    exit "$?"
fi

LOG_PARENT="$ROOT/target/dev-isolation"
if ! mkdir -p "$LOG_PARENT"; then
    log "cannot create full-suite log parent"
    exit 1
fi
if ! LOG_DIR=$(mktemp -d "$LOG_PARENT/full-suite-XXXXXX"); then
    log "cannot create full-suite log directory"
    exit 1
fi
log "Full stage logs (retained): $LOG_DIR"
STAGE_NUMBER=0

run_stage() {
    local label="$1" display_lines="$2"
    shift 2
    STAGE_NUMBER=$((STAGE_NUMBER + 1))
    local logfile
    printf -v logfile '%s/%03d.log' "$LOG_DIR" "$STAGE_NUMBER"
    log "$label log: $logfile"
    if ! : > "$logfile"; then
        log "cannot create stage log: $logfile"
        return 74
    fi
    # tee's separate exit detects writes which fail after the file was opened.
    # Capture both exits before any display command can overwrite PIPESTATUS.
    "$@" 2>&1 | tee "$logfile" > /dev/null
    local exits=("${PIPESTATUS[@]}")
    if [[ ${exits[1]} -ne 0 ]]; then
        log "stage log write failed: $logfile"
        return 74
    fi
    if ! tail -n "$display_lines" "$logfile"; then
        log "cannot display stage log: $logfile"
        return 74
    fi
    return "${exits[0]}"
}

log "Building all tests once (cargo build --tests --all-features)"
if ! run_stage build 5 cargo build --tests --all-features; then
    log "build failed"
    exit 1
fi

log "Running lib + bin tests"
if run_stage lib+bins 3 python3 scripts/dev/test-isolated.py nextest --lib --bins --all-features -- --no-fail-fast; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    FAILED_BINARIES+=("lib+bins")
fi

log "Running doc tests"
if run_stage doc 3 python3 scripts/dev/test-isolated.py doctest; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    FAILED_BINARIES+=("doc")
fi

log "Running each integration test binary sequentially"
for test_file in tests/*.rs; do
    name="$(basename "$test_file" .rs)"
    log "  -> $name"
    if run_stage "$name" 3 python3 scripts/dev/test-isolated.py nextest --test "$name" --all-features -- --no-fail-fast; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_BINARIES+=("$name")
    fi
done

log ""
log "Summary: pass=$PASS fail=$FAIL skipped=$SKIPPED"
if [ ${#FAILED_BINARIES[@]} -gt 0 ]; then
    log "Failed binaries:"
    for b in "${FAILED_BINARIES[@]}"; do
        log "  - $b"
    done
    exit 1
fi
exit 0
