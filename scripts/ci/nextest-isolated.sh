#!/usr/bin/env bash
# Usage: build flags ... -- nextest runtime flags ... (the separator is required).
set -euo pipefail
build=()
while [[ $# -gt 0 && $1 != -- ]]; do build+=("$1"); shift; done
[[ $# -gt 0 ]] || { echo 'missing build/runtime separator' >&2; exit 2; }
shift
scratch=$(mktemp -d "${RUNNER_TEMP:?}/x0x-archive-XXXXXX")
# archive builds without executing test discovery. Keep original build flags.
cargo nextest archive "${build[@]}" --archive-file "$scratch/tests.tar.zst"
sha256sum Cargo.lock "$scratch/tests.tar.zst" > "$scratch/build.sha256"
git rev-parse HEAD HEAD^{tree} > "$scratch/source.txt"
mkdir -m 700 "$scratch/extract"
python3 scripts/ci/isolated-runtime.py cargo nextest run \
  --archive-file "$scratch/tests.tar.zst" --extract-to "$scratch/extract" "$@"
