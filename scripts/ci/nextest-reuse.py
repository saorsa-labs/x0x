#!/usr/bin/env python3
"""Record/verify binary-only build custody; execution occurs only in the namespace."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def inputs(scratch):
    metadata = json.loads((scratch / 'binaries.json').read_text())
    target = Path(metadata['rust-build-meta']['target-directory'])
    paths = {Path(binary['binary-path']) for binary in metadata['rust-binaries'].values()}
    if not paths:
        raise RuntimeError('binary-only build produced no test binaries')
    for binaries in metadata['rust-build-meta']['non-test-binaries'].values():
        paths.update(target / binary['path'] for binary in binaries)
    paths.update([scratch / 'binaries.json', scratch / 'cargo.json', Path.cwd() / 'Cargo.lock'])
    return sorted(str(path.resolve(strict=True)) for path in paths)


def record(scratch):
    receipt = {
        'files': {path: digest(path) for path in inputs(scratch)},
        'source': subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], text=True).splitlines(),
    }
    (scratch / 'custody.json').write_text(json.dumps(receipt, indent=2) + '\n')


def verify(scratch):
    receipt = json.loads((scratch / 'custody.json').read_text())
    if inputs(scratch) != sorted(receipt['files']):
        raise RuntimeError('build input set changed')
    for path, expected in receipt['files'].items():
        if digest(path) != expected:
            raise RuntimeError(f'build input changed: {path}')
    if subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], text=True).splitlines() != receipt['source']:
        raise RuntimeError('source checkout changed')


def main():
    mode, directory, *arguments = sys.argv[1:]
    scratch = Path(directory).resolve(strict=True)
    if mode == 'record':
        if arguments:
            raise RuntimeError('record accepts no runtime arguments')
        record(scratch)
    elif mode == 'run':
        # The caller is isolated-runtime.py. Require its admitted environment
        # before invoking nextest discovery; no host fallback or compilation.
        status = Path('/proc/self/status').read_text()
        if 'NoNewPrivs:\t1' not in status or os.geteuid() == 0:
            raise RuntimeError('nextest reuse requires admitted unprivileged runtime')
        verify(scratch)
        os.execvp('cargo', ['cargo', 'nextest', 'run', '--binaries-metadata',
            str(scratch / 'binaries.json'), '--cargo-metadata', str(scratch / 'cargo.json'), *arguments])
    else:
        raise RuntimeError(f'unknown mode: {mode}')


if __name__ == '__main__':
    main()
