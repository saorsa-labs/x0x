#!/usr/bin/env bash
#
# Bump the project version in EVERY file the release `version_sync` gate
# checks, in one shot, so a release can never fail because one copy was
# forgotten (the recurring SKILL.md drift that broke the 0.22.1 and 0.23.0
# tags). The version lives in three hand-maintained places — Cargo.toml's
# [package] version, SKILL.md's frontmatter, and the static agent card — all
# MUST agree with the release tag. Always bump via this script (or `just bump-version`) instead of
# hand-editing these files.
#
# Usage: scripts/bump-version.sh <X.Y.Z>
#
# After running: add a `## [vX.Y.Z]` section to CHANGELOG.md, commit, and tag
# `vX.Y.Z`. The release workflow's validate gate will then pass.

set -euo pipefail

VERSION="${1:-}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 <X.Y.Z>  (got: '${VERSION}')" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Precompute and validate every replacement before writing any version file.
# This prevents invalid input from leaving a partial bump; it is not a
# multi-file transaction against write failures or process interruption.
python3 - "$VERSION" <<'PYTHON'
import json
import re
import sys
from pathlib import Path

version = sys.argv[1]
path = Path(".well-known/agent.json")
text = path.read_bytes().decode("utf-8")
card = json.loads(text)
if not isinstance(card, dict) or not isinstance(card.get("version"), str):
    raise SystemExit("Agent card must have a top-level string version")

# Walk only the top-level object with the JSON decoder, so whitespace and
# nested version fields do not matter. Replace the value's exact source span
# to preserve every unrelated byte, including the card's existing formatting.
decoder = json.JSONDecoder()

def skip_space(pos):
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos

pos = skip_space(0) + 1  # validated top-level opening brace
spans = []
while text[skip_space(pos)] != "}":
    key, pos = decoder.raw_decode(text, skip_space(pos))
    start = skip_space(skip_space(pos) + 1)  # validated colon
    _, end = decoder.raw_decode(text, start)
    if key == "version":
        spans.append((start, end))
    pos = skip_space(end)
    if text[pos] == "}":
        break
    pos += 1  # validated comma
if len(spans) != 1:
    raise SystemExit("Agent card must have exactly one top-level version")
start, end = spans[0]
updated = text[:start] + json.dumps(version) + text[end:]
card["version"] = version
if json.loads(updated) != card:
    raise SystemExit("Cannot safely update agent card top-level version")

replacements = {path: updated}
for filename, pattern, replacement in [
    ("Cargo.toml", r'(?m)^version = "[^"\n]*"', f'version = "{version}"'),
    ("SKILL.md", r'(?m)^version:\s[^\n]*', f'version: {version}'),
]:
    path = Path(filename)
    updated, count = re.subn(
        pattern, lambda _: replacement, path.read_bytes().decode("utf-8"), count=1
    )
    if count != 1:
        raise SystemExit(f"Cannot safely update version in {filename}")
    replacements[path] = updated

for path, updated in replacements.items():
    path.write_bytes(updated.encode("utf-8"))
PYTHON

echo "Bumped to $VERSION:"
grep -m1 '^version = ' Cargo.toml | sed 's/^/  Cargo.toml  /'
grep -m1 '^version:'   SKILL.md   | sed 's/^/  SKILL.md    /'
python3 -c 'import json; print("  agent.json  version:", json.load(open(".well-known/agent.json"))["version"])'

# Prove all three are now in sync (and consistent with a vX.Y.Z tag) using the
# same validator the release workflow runs — fail loudly if anything drifted.
if [[ -f .github/scripts/validate_release_metadata.py ]]; then
    echo
    echo "Verifying with the release version_sync gate..."
    python3 .github/scripts/validate_release_metadata.py --mode release_tag --tag "v$VERSION"
    echo "  version_sync OK"
fi

echo
echo "Next: add a '## [v$VERSION]' section to CHANGELOG.md, then commit and tag v$VERSION."
