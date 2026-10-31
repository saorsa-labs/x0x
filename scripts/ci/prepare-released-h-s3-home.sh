#!/usr/bin/env bash
# Install the published v0.45.0 and v0.46.1 x0xd before the loopback-only
# test namespace, for the ADR 0109 H-S3-home released-binary gate (#1571).
# Each tarball checksum and each binary checksum is pinned to the release
# asset. v0.46.1 ships build-provenance.json, so its source_head is pinned
# too. v0.45.0 has no provenance file; its pin is the tarball and binary
# checksum, and the tag commit is recorded below for reference.
#
# Output: target/released-pinned/<tag>/x0xd (plus build-provenance.json
# when the release has one).
#
# A macOS developer cannot use the Linux binaries. Set X0X_V045_BIN and
# X0X_V0461_BIN to local x0xd binaries; the test reads them, and this script
# then does nothing.
set -euo pipefail

if [[ -n "${X0X_V045_BIN:-}" && -n "${X0X_V0461_BIN:-}" ]]; then
  exit 0
fi

root=$(git rev-parse --show-toplevel)
base="$root/target/released-pinned"
workroot=$(mktemp -d)
trap 'rm -rf "$workroot"' EXIT

# install <tag> <version> <tarball_sha256> <binary_sha256> <source_head or "">
install() {
  local tag=$1 version=$2 tarball_sha256=$3 binary_sha256=$4 source_head=$5
  local dest="$base/$tag"
  local bin="$dest/x0xd"
  local provenance="$dest/build-provenance.json"

  if [[ -f "$bin" ]]; then
    local actual recorded=""
    actual=$(sha256sum "$bin" | awk '{print $1}')
    if [[ -n "$source_head" && -f "$provenance" ]]; then
      recorded=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("source_head",""))' "$provenance" || true)
    fi
    if [[ "$actual" == "$binary_sha256" && "$recorded" == "$source_head" ]]; then
      return 0
    fi
  fi

  local workdir="$workroot/$tag"
  mkdir -p "$workdir"
  local archive="$workdir/x0x-linux-x64-gnu.tar.gz"
  curl -fsSL --retry 3 -o "$archive" \
    "https://github.com/saorsa-labs/x0x/releases/download/$tag/x0x-linux-x64-gnu.tar.gz"
  echo "$tarball_sha256  $archive" | sha256sum -c -
  tar -xzf "$archive" -C "$workdir"
  local extracted="$workdir/x0x-linux-x64-gnu"
  python3 - "$extracted" "$source_head" "$binary_sha256" <<'PY'
import hashlib, json, os, sys
extracted, source_head, binary_sha = sys.argv[1:]
digest = hashlib.sha256(open(os.path.join(extracted, "x0xd"), "rb").read()).hexdigest()
if digest != binary_sha:
    raise SystemExit("extracted x0xd checksum drifted")
if source_head:
    doc = json.load(open(os.path.join(extracted, "build-provenance.json")))
    if doc.get("source_head") != source_head:
        raise SystemExit(f"source_head {doc.get('source_head')} is not {source_head}")
    rows = {row["file"]: row["sha256"] for row in doc["binaries"]}
    if rows.get("x0xd") != binary_sha:
        raise SystemExit("provenance x0xd checksum drifted")
PY
  mkdir -p "$dest"
  rm -f "$provenance"
  cp "$extracted/x0xd" "$bin"
  if [[ -n "$source_head" ]]; then
    cp "$extracted/build-provenance.json" "$provenance"
  fi
  chmod 755 "$bin"
  local reported
  reported=$("$bin" --version)
  [[ "$reported" == "x0xd $version" ]] || {
    echo "$bin reports '$reported', expected 'x0xd $version'" >&2
    return 1
  }
}

# v0.45.0: tag commit 0988ce46b8e3eddb7389ac45178ee3c73a5b0ef9 (no provenance file).
install v0.45.0 0.45.0 \
  53c25adfee607cb488e55d1f2fcd25491c264f9079ab524d62483b91a7b37feb \
  64f0dbf6eeea4c729cc969f4f100302340699671eae1ae3be38b9c2bc880131a \
  ""
# v0.46.1: tag commit 10fe0dd19df1b87ec9b28165dcdb5391ba5897da.
install v0.46.1 0.46.1 \
  00d0347c0aee1a09b65772623e1d037d194f64f72380f6b25723241955467d2b \
  ca0d641b41f1b636e120ce188bd86c0468788679b4736e2b924c683be0a23708 \
  10fe0dd19df1b87ec9b28165dcdb5391ba5897da
