#!/usr/bin/env bash
#
# Bump the project version in EVERY file the release `version_sync` gate
# checks, in one shot, so a release can never fail because one copy was
# forgotten (the recurring SKILL.md drift that broke the 0.22.1 and 0.23.0
# tags). The version lives in two hand-maintained places — Cargo.toml's
# [package] version and SKILL.md's frontmatter — and they MUST agree with the
# release tag. Always bump via this script (or `just bump-version`) instead of
# hand-editing either file.
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

echo "Bumped to $VERSION:"
grep -m1 '^version = ' Cargo.toml | sed 's/^/  Cargo.toml  /'
grep -m1 '^version:'   SKILL.md   | sed 's/^/  SKILL.md    /'

# Prove the two are now in sync (and consistent with a vX.Y.Z tag) using the
# same validator the release workflow runs — fail loudly if anything drifted.
if [[ -f .github/scripts/validate_release_metadata.py ]]; then
    echo
    echo "Verifying with the release version_sync gate..."
    python3 .github/scripts/validate_release_metadata.py --mode release_tag --tag "v$VERSION"
    echo "  version_sync OK"
fi

echo
echo "Next: add a '## [v$VERSION]' section to CHANGELOG.md, then commit and tag v$VERSION."
