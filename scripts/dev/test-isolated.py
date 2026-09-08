#!/usr/bin/env python3
"""Developer test entrypoints using the existing Linux isolation boundary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

NAMESPACE_TOOLS = (
    '/usr/bin/sudo', '/usr/bin/unshare', '/usr/bin/setpriv',
    '/usr/sbin/ip', '/usr/bin/mount', '/usr/bin/python3', '/usr/bin/true',
)
MARKER = 'x0x.developer-coverage/1'
COVERAGE_SCRIPT = '''set -euo pipefail
source "$1"
shift
count=$1
shift
build=("${@:1:count}")
shift "$count"
bash scripts/ci/nextest-isolated.sh "${build[@]}" --
cargo llvm-cov report "$@"
'''


def run(command, root, env, capture=False):
    return subprocess.run(command, cwd=root, env=env, check=True,
                          text=True, stdout=subprocess.PIPE if capture else None)


def split_arguments(arguments):
    if '--' not in arguments:
        raise ValueError('expected build arguments -- runtime/report arguments')
    separator = arguments.index('--')
    return arguments[:separator], arguments[separator + 1:]


def scratch_parent(root):
    parent = root / 'target' / 'dev-isolation'
    # The existing wrapper mounts a private /tmp. Custody must stay visible.
    if root.is_relative_to(Path('/tmp').resolve()):
        raise ValueError('workspace must be outside /tmp for isolation custody')
    if parent.resolve() != parent or (root / 'target').is_symlink():
        raise ValueError('developer scratch path must not traverse symlinks')
    return parent


def preflight(root, env, coverage=False):
    if sys.platform != 'linux' or os.getuid() == 0:
        raise ValueError('requires unprivileged Linux with passwordless sudo; no host fallback')
    scratch_parent(root)
    for tool in NAMESPACE_TOOLS:
        if not os.path.isfile(tool) or not os.access(tool, os.X_OK):
            raise ValueError(f'missing namespace prerequisite: {tool}')
    for tool in ('cargo', 'bash', 'python3', 'sha256sum', 'mktemp'):
        if shutil.which(tool) is None:
            raise ValueError(f'missing developer prerequisite: {tool}')
    run(['/usr/bin/sudo', '-n', '--', '/usr/bin/true'], root, env)
    run(['cargo', 'nextest', '--version'], root, env)
    if coverage:
        run(['cargo', 'llvm-cov', '--version'], root, env)


def clean_coverage(root, argument):
    """Remove only a completed, explicitly named developer coverage target."""
    parent = scratch_parent(root)
    candidate = Path(argument).absolute()
    if candidate.resolve() != candidate or candidate.parent != parent:
        raise ValueError('coverage run must be a canonical direct child of target/dev-isolation')
    if not candidate.name.startswith('run-') or candidate.stat().st_uid != os.getuid():
        raise ValueError('coverage run is not owned by this user')
    marker = candidate / 'coverage-owner.json'
    if marker.is_symlink():
        raise ValueError('coverage ownership marker must not be a symlink')
    record = json.loads(marker.read_text())
    expected = dict(schema=MARKER, workspace=str(root), run=str(candidate), active=False)
    if record != expected:
        raise ValueError('coverage ownership marker disagrees or run is still active')
    target = candidate / 'coverage-target'
    if target.is_symlink() or target.resolve() != target:
        raise ValueError('coverage target must not be a symlink')
    # Preserve custody and environment; reports inside this target are removed.
    # Never clean ambient Cargo caches.
    if target.exists():
        shutil.rmtree(target)
    print(f'Cleaned owned coverage target: {target}')


def mirror_report(report, destination):
    """Replace the shared editor mirror with one complete private report."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.lcov-', suffix='.tmp',
                                         dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            with report.open('rb') as source:
                shutil.copyfileobj(source, output)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(arguments=None, root=None):
    args = list(sys.argv[1:] if arguments is None else arguments)
    root = (Path(__file__).resolve().parents[2] if root is None else root).resolve()
    if not args:
        raise ValueError('usage: test-isolated.py nextest|voice|coverage|coverage-lcov|coverage-check|check|coverage-clean ...')
    mode, args = args[0], args[1:]
    if mode == 'coverage-clean':
        if len(args) != 1:
            raise ValueError('coverage-clean requires one explicitly named run directory')
        clean_coverage(root, args[0])
        return 0
    if mode not in ('nextest', 'voice', 'coverage', 'coverage-lcov', 'coverage-check', 'check'):
        raise ValueError(f'unknown mode: {mode}')
    build, runtime = split_arguments(args) if mode in ('nextest', 'coverage') else ([], [])
    if mode in ('voice', 'check', 'coverage-lcov', 'coverage-check') and args:
        raise ValueError(f'{mode} does not accept extra arguments')
    env = os.environ.copy()
    env.pop('X0X_CUSTODY_SCRATCH', None)
    env.pop('X0X_ISOLATION_ROLE', None)
    preflight(root, env, coverage=mode in ('coverage', 'coverage-lcov', 'coverage-check'))
    if mode == 'check':
        return 0
    parent = scratch_parent(root)
    parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    env['RUNNER_TEMP'] = str(scratch)
    print(f'Developer isolation evidence (retained): {scratch}', flush=True)
    wrapper = ['bash', 'scripts/ci/nextest-isolated.sh']
    if mode == 'nextest':
        run([*wrapper, *build, '--', *runtime], root, env)
    elif mode == 'voice':
        run(['cargo', 'test', '--all-features', '--test', 'voice_datagram_e2e', '--no-run'], root, env)
        env['X0X_ISOLATION_ROLE'] = 'selection'
        run(['python3', 'scripts/ci/isolated-runtime.py', 'python3',
             'scripts/ci/voice-datagram-selection.py'], root, env)
        env['X0X_ISOLATION_ROLE'] = 'acceptance'
        run([*wrapper, '--all-features', '--test', 'voice_datagram_e2e', '--',
             '--run-ignored', 'ignored-only', '--test-threads', '1'], root, env)
    else:
        target = scratch / 'coverage-target'
        env['CARGO_TARGET_DIR'] = str(target)
        env['CARGO_LLVM_COV_TARGET_DIR'] = str(target)
        env.pop('CARGO_LLVM_COV_BUILD_DIR', None)
        owner = dict(schema=MARKER, workspace=str(root), run=str(scratch), active=True)
        marker = scratch / 'coverage-owner.json'
        marker.write_text(json.dumps(owner) + '\n')
        try:
            report = None
            if mode in ('coverage-lcov', 'coverage-check'):
                build = ['--all-features', '--workspace']
                report = target / 'reports' / 'lcov.info'
                report.parent.mkdir(parents=True)
                runtime = ['--package', '*', '--lcov', '--output-path', str(report)]
                if mode == 'coverage-check':
                    runtime += ['--fail-under-lines', '48']
                print(f'Run-owned coverage report: {report}', flush=True)
            instrument = run(['cargo', 'llvm-cov', 'show-env', '--sh'], root, env, capture=True)
            exports = scratch / 'coverage-env.sh'
            exports.write_text(instrument.stdout)
            # A fresh owned target has no stale profiles to clean. As in CI,
            # instrumentation, isolated execution and reporting share one env.
            run(['bash', '-c', COVERAGE_SCRIPT, 'dev-coverage', str(exports),
                 str(len(build)), *build, *runtime], root, env)
            if report is not None:
                if mode == 'coverage-check':
                    run(['python3', 'scripts/check-coverage-thresholds.py', '--lcov', str(report),
                         '--thresholds', 'coverage-thresholds.toml', '--enforce-global'], root, env)
                mirror_report(report, root / 'lcov.info')
                print('Shared editor mirror: lcov.info (last writer wins; not run evidence)', flush=True)
        except BaseException:
            # A failed/killed shell may have live descendants. Only successful
            # completion unlocks cleanup; preserve active custody on failure.
            raise
        else:
            owner['active'] = False
            marker.write_text(json.dumps(owner) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode if error.returncode > 0 else 128 - error.returncode)
    except (ValueError, OSError) as error:
        print(f'REFUSING developer test entrypoint: {error}', file=sys.stderr)
        sys.exit(2)
