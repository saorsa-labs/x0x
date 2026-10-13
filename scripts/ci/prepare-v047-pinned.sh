#!/usr/bin/env bash
# Install the published v0.47.0 x0xd before the loopback-only test namespace.
# Commit 57ca3866a816f73cd7df55024c15d3ad8f0f29db is the v0.47.0 release.
# The tarball checksum and the binary checksum are pinned to that release asset.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tag=57ca3866a816f73cd7df55024c15d3ad8f0f29db
tarball_sha256=e0f244ea0e0983b7cbdb8fb211f2c3414c1b9b7e83348dca7bf748142f1b4e4a
binary_sha256=652ff80327a3f4c04f71980b5e5c30decc0cd003ccfb6df0c7c11e3432188cfa
dest="$root/target/v047-pinned"
bin="$dest/x0xd"
provenance="$dest/build-provenance.json"

if [[ -f "$bin" && -f "$provenance" ]]; then
  recorded=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("source_head",""))' "$provenance" || true)
  actual=$(sha256sum "$bin" | awk '{print $1}')
  if [[ "$recorded" == "$tag" && "$actual" == "$binary_sha256" ]]; then
    exit 0
  fi
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
archive="$workdir/x0x-linux-x64-gnu.tar.gz"
curl -fsSL --retry 3 -o "$archive" \
  https://github.com/saorsa-labs/x0x/releases/download/v0.47.0/x0x-linux-x64-gnu.tar.gz
echo "$tarball_sha256  $archive" | sha256sum -c -
tar -xzf "$archive" -C "$workdir"
extracted="$workdir/x0x-linux-x64-gnu"
python3 - "$extracted/build-provenance.json" "$extracted/x0xd" "$tag" "$binary_sha256" <<'PY'
import hashlib, json, sys
provenance_path, binary_path, tag, binary_sha = sys.argv[1:]
doc = json.load(open(provenance_path))
if doc.get("source_head") != tag:
    raise SystemExit(f"source_head {doc.get('source_head')} is not {tag}")
rows = {row["file"]: row["sha256"] for row in doc["binaries"]}
if rows.get("x0xd") != binary_sha:
    raise SystemExit("provenance x0xd checksum drifted")
digest = hashlib.sha256(open(binary_path, "rb").read()).hexdigest()
if digest != binary_sha:
    raise SystemExit("extracted x0xd checksum drifted")
PY
mkdir -p "$dest"
cp "$extracted/x0xd" "$bin"
cp "$extracted/build-provenance.json" "$provenance"
chmod 755 "$bin"
version=$("$bin" --version)
[[ "$version" == "x0xd 0.47.0" ]]
