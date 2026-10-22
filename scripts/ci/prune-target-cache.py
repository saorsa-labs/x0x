#!/usr/bin/env python3
"""Reduce a Cargo target directory to third-party build output before a cache save.

The Test Suite job builds about 115 workspace test binaries. They change on
every PR, so a cache of them is never reused, but they fill most of the hosted
runner disk. The cache archive is then written to the same disk and the save
fails with 'No space left on device' (refs #1543).

This keeps only `<target>/debug/{build,deps,.fingerprint}` entries that do not
belong to a workspace package or target. Usage: prune-target-cache.py [TARGET]
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

PROFILE = 'debug'
KEEP_DIRS = ('build', 'deps', '.fingerprint')


def workspace_stems(metadata):
    """Return every name under which Cargo stores a workspace artifact."""
    stems = set()
    for package in metadata['packages']:
        names = [package['name']] + [t['name'] for t in package['targets']]
        for name in names:
            stems.add(name)
            stems.add(name.replace('-', '_'))
    return stems


def is_workspace_artifact(name, stems):
    """Cargo names artifacts `[lib]<stem>-<hash>[.ext]`; the hash has no '-'."""
    candidates = [name]
    if name.startswith('lib'):
        candidates.append(name[3:])
    for candidate in candidates:
        stem, separator, _ = candidate.rpartition('-')
        if separator and stem in stems:
            return True
    return False


def remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def prune(target, stems):
    """Prune `target` in place; return the number of entries removed."""
    removed = 0
    profile = target / PROFILE
    for entry in target.iterdir():
        if entry.name not in (PROFILE, 'CACHEDIR.TAG'):
            remove(entry)
            removed += 1
    if not profile.is_dir():
        return removed
    for entry in profile.iterdir():
        if entry.name not in KEEP_DIRS:
            remove(entry)
            removed += 1
            continue
        for child in entry.iterdir():
            if is_workspace_artifact(child.name, stems):
                remove(child)
                removed += 1
    return removed


def main(argv):
    target = Path(argv[1] if len(argv) > 1 else 'target')
    if not target.is_dir():
        print(f'{target}: no target directory, nothing to prune')
        return 0
    metadata = json.loads(subprocess.run(
        ['cargo', 'metadata', '--no-deps', '--format-version', '1'],
        check=True, capture_output=True, text=True).stdout)
    removed = prune(target, workspace_stems(metadata))
    print(f'{target}: removed {removed} workspace or non-dependency entries')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
