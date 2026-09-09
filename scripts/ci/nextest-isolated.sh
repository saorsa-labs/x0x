#!/usr/bin/env bash
# Usage: build flags ... -- nextest runtime flags ... (the separator is required).
set -euo pipefail
build=()
metadata=(--format-version 1)
metadata_locked=false
while [[ $# -gt 0 && $1 != -- ]]; do
  case "$1" in
    --locked)
      if [[ $metadata_locked == false ]]; then
        metadata+=("$1")
        metadata_locked=true
      fi
      shift
      continue ;;
    --all-features|--no-default-features|--offline|--frozen) metadata+=("$1") ;;
    --features|-F|--manifest-path|--config)
      [[ $# -gt 1 && $2 != -- ]] || { echo 'missing build option value' >&2; exit 2; }
      metadata+=("$1" "$2"); build+=("$1" "$2"); shift 2; continue ;;
  esac
  build+=("$1"); shift
done
[[ $# -gt 0 ]] || { echo 'missing build/runtime separator' >&2; exit 2; }
shift
scratch=$(mktemp -d "${RUNNER_TEMP:?}/x0x-metadata-XXXXXX")
# Resolve once. Both binary preparation and reuse consume this exact graph.
cargo metadata "${metadata[@]}" > "$scratch/cargo.json"
sha256sum Cargo.lock > "$scratch/lock.sha256"
# binaries-only builds without executing discovery; no archive/extraction copy.
cargo nextest list "${build[@]}" --locked --cargo-metadata "$scratch/cargo.json" \
  --list-type binaries-only --message-format json > "$scratch/binaries.json"
sha256sum --check "$scratch/lock.sha256"
python3 scripts/ci/nextest-reuse.py record "$scratch"
X0X_CUSTODY_SCRATCH="$scratch" python3 scripts/ci/isolated-runtime.py python3 scripts/ci/nextest-reuse.py run "$scratch" "$@"
