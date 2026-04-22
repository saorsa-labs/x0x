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

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_IGNORED=1
for arg in "$@"; do
    case "$arg" in
        --no-ignored) RUN_IGNORED=0 ;;
    esac
done

PASS=0
FAIL=0
SKIPPED=0
FAILED_BINARIES=()

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

log "Building all tests once (cargo build --tests --all-features)"
if ! cargo build --tests --all-features 2>&1 | tail -5; then
    log "build failed"
    exit 1
fi

log "Running lib + bin tests"
if cargo nextest run --lib --bins --all-features --no-fail-fast 2>&1 | tail -3; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    FAILED_BINARIES+=("lib+bins")
fi

log "Running doc tests"
if cargo test --doc --all-features 2>&1 | tail -3; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    FAILED_BINARIES+=("doc")
fi

log "Running each integration test binary sequentially"
for test_file in tests/*.rs; do
    name="$(basename "$test_file" .rs)"
    log "  -> $name"
    if cargo nextest run --test "$name" --all-features --no-fail-fast 2>&1 | tail -3; then
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
