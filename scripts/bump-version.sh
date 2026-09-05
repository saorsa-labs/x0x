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

# Cargo.toml: the [package] version is the first line-anchored `version = "..."`.
perl -i -pe 'if (!$done && /^version = "/) { s/^version = ".*"/version = "'"$VERSION"'"/; $done = 1 }' Cargo.toml

# SKILL.md frontmatter: the first `version: ...` line.
perl -i -pe 'if (!$done && /^version:\s/) { s/^version:.*/version: '"$VERSION"'/; $done = 1 }' SKILL.md

# Update only the card's top-level version, preserving protocol versions and formatting.
python3 - "$VERSION" <<'PYTHON'
import json
import re
import sys
from pathlib import Path

path = Path(".well-known/agent.json")
text = path.read_text()
card = json.loads(text)
updated, count = re.subn(r'(?m)^(  "version": )"[^"\n]*"',
                         lambda match: match[1] + json.dumps(sys.argv[1]), text, count=1)
card["version"] = sys.argv[1]
if count != 1 or json.loads(updated) != card:
    raise SystemExit("Cannot safely update agent card top-level version")
path.write_text(updated)
PYTHON

echo "Bumped to $VERSION:"
grep -m1 '^version = ' Cargo.toml | sed 's/^/  Cargo.toml  /'
grep -m1 '^version:'   SKILL.md   | sed 's/^/  SKILL.md    /'
grep -m1 '^  "version":' .well-known/agent.json | sed 's/^/  agent.json  /'

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
