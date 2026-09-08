#!/usr/bin/env python3
"""Disposable fixed A/B route. NEVER MERGE; no release or acceptance credit."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time
import tomllib

from suite574_collect import Invalid, TARGET, TEST, MAX_BYTES, account, interrupted_prefix, require

LOCK = '83fc5316716b6240ffa470daa77d3e6a7ea9ed09baf6631320d472514e38b32f'
BRANCH = 'refs/heads/codex/574-suite-diagnostic'
TARGET_FILTER = 'package(=x0x) & binary(=x0x) & kind(=lib) & test(=' + TEST + ')'
FILTERS = {'single': TARGET_FILTER, 'suite': '!binary(x0x_0041_synthetic_kill_restart)'}


def digest(path):
    require(path.is_file() and not path.is_symlink(), 'FILE_INVALID')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES, 'FILE_INVALID')
    return json.loads(path.read_text())


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def module(name):
    return runpy.run_path(str(Path(__file__).with_name(name)))


def source(guard=True):
    head = command('git', 'rev-parse', 'HEAD')
    if guard:
        require(re.fullmatch('[0-9a-f]{40}', os.environ['EXPECTED_COMMIT']) is not None, 'SOURCE')
        require(head == os.environ['EXPECTED_COMMIT'] == os.environ['GITHUB_SHA'], 'SOURCE')
        require(os.environ['GITHUB_REF'] == BRANCH, 'SOURCE')
    require(not command('git', 'status', '--porcelain'), 'SOURCE')
    files = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')[:-1]
    return {'head': head, 'tree': command('git', 'rev-parse', 'HEAD^{tree}'),
            'files': {f: digest(Path(f)) for f in files}}


def verify(root):
    require(source(False) == read(root / 'source.json'), 'SOURCE')
    require(digest(Path('Cargo.lock')) == LOCK, 'LOCK')


def report_config(original, path):
    """Change reporting only; compare parsed settings, including override order."""
    require('"' not in str(path) and '\n' not in str(path), 'CONFIG')
    extra = ('\n[profile.default.junit]\npath=' + json.dumps(str(path)) +
             '\nstore-success-output=false\nstore-failure-output=true\nreport-skipped="all"\n' +
             '\n[[profile.default.overrides]]\nfilter=' + json.dumps(TARGET_FILTER) +
             '\njunit.store-success-output=true\n')
    baseline = tomllib.loads(original)
    require('junit' not in baseline['profile']['default'], 'CONFIG')
    parsed = tomllib.loads(original + extra)
    compared = copy.deepcopy(parsed)
    del compared['profile']['default']['junit']
    override = compared['profile']['default']['overrides'].pop()
    require(override == {'filter': TARGET_FILTER, 'junit': {'store-success-output': True}}, 'CONFIG')
    require(compared == baseline, 'CONFIG')
    return original + extra


def prep(root):
    require(not Path('Cargo.lock').exists() and not Path('target').exists(), 'DIRTY_BUILD')
    write(root / 'source.json', source())
    require(digest(Path('ci/lifecycle574/Cargo.lock.fixture')) == LOCK, 'LOCK')
    Path('Cargo.lock').write_bytes(Path('ci/lifecycle574/Cargo.lock.fixture').read_bytes())
    for role in FILTERS:
        leg = root / role
        leg.mkdir()
        (leg / 'evidence').mkdir()
        (leg / 'report.toml').write_text(report_config(Path('.config/nextest.toml').read_text(), leg / 'junit.xml'))


def tool_and_runner_facts():
    rust = command('rustc', '--version')
    nextest = command('cargo', 'nextest', '--version')
    require(rust.startswith('rustc 1.95.0 ') and nextest.startswith('cargo-nextest 0.9.143 '), 'TOOL_VERSION')
    cpu = Path('/sys/fs/cgroup/cpu.max')
    quota = cpu.read_text().strip().split() if cpu.exists() else None
    if quota is not None:
        require(len(quota) == 2 and (quota[0] == 'max' or quota[0].isdigit()) and quota[1].isdigit(), 'RUNNER')
        quota = {'quota': None if quota[0] == 'max' else int(quota[0]), 'period': int(quota[1])}
    image = os.environ.get('ImageVersion')
    require(image is None or re.fullmatch('[0-9.]{1,40}', image), 'RUNNER')
    return {'rust': '1.95.0', 'nextest': '0.9.143', 'rust_version_sha256': hashlib.sha256(rust.encode()).hexdigest(),
            'nextest_version_sha256': hashlib.sha256(nextest.encode()).hexdigest(), 'image_version': image,
            'cpu_count': os.cpu_count(), 'affinity_count': len(os.sched_getaffinity(0)), 'cpu_quota': quota,
            'build_jobs': 2, 'incremental': False, 'coverage': False}


def closed_runner(facts):
    keys = {'rust', 'nextest', 'rust_version_sha256', 'nextest_version_sha256',
            'image_version', 'cpu_count', 'affinity_count', 'cpu_quota',
            'build_jobs', 'incremental', 'coverage'}
    require(isinstance(facts, dict) and set(facts) == keys, 'RUNNER')
    require(facts['rust'] == '1.95.0' and facts['nextest'] == '0.9.143', 'RUNNER')
    for key in ('rust_version_sha256', 'nextest_version_sha256'):
        require(isinstance(facts[key], str) and re.fullmatch('[0-9a-f]{64}', facts[key]), 'RUNNER')
    image = facts['image_version']
    require(image is None or isinstance(image, str) and re.fullmatch('[0-9.]{1,40}', image), 'RUNNER')
    for key in ('cpu_count', 'affinity_count'):
        require(type(facts[key]) is int and 1 <= facts[key] <= 65536, 'RUNNER')
    require(type(facts['build_jobs']) is int and facts['build_jobs'] == 2 and
            facts['incremental'] is False and facts['coverage'] is False, 'RUNNER')
    quota = facts['cpu_quota']
    if quota is not None:
        require(isinstance(quota, dict) and set(quota) == {'quota', 'period'}, 'RUNNER')
        require(type(quota['period']) is int and 1 <= quota['period'] <= 10**12, 'RUNNER')
        require(quota['quota'] is None or type(quota['quota']) is int and 1 <= quota['quota'] <= 10**12, 'RUNNER')
    return facts


def build(root):
    verify(root)
    facts = closed_runner(tool_and_runner_facts())
    require(not any(os.environ.get(k) for k in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'LLVM_PROFILE_FILE', 'CARGO_LLVM_COV')), 'BUILD_ENV')
    directory = Path(tempfile.mkdtemp(prefix='x0x-metadata-', dir=root))
    for name, argv in [('cargo.json', ['cargo', 'metadata', '--format-version', '1', '--all-features', '--locked', '--offline']),
                       ('binaries.json', ['cargo', 'nextest', '--user-config-file', 'none', 'list', '--all-features', '--workspace', '--locked', '--offline', '--cargo-metadata', str(directory/'cargo.json'), '--list-type', 'binaries-only', '--message-format', 'json'])]:
        with (directory/name).open('wb') as output:
            subprocess.run(argv, stdout=output, check=True)
    (directory/'lock.sha256').write_text(LOCK + '  Cargo.lock\n')
    module('nextest-reuse.py')['record'](directory)
    binaries = read(directory/'binaries.json')['rust-binaries']
    require(binaries and all(Path(b['binary-path']).resolve().is_relative_to(Path('target').resolve()) for b in binaries.values()), 'BINARY_SET')
    require(sum(b['kind']=='lib' and b['binary-name']=='x0x' for b in binaries.values()) == 1, 'TARGET_BINARY')
    write(root/'build.json', {'scratch': str(directory), 'facts': facts, 'binary_count': len(binaries)})
    verify(root)


def bind_discovery(listing, binary_metadata, cargo_metadata):
    """Every discovered binary must be from the one recorded build set."""
    binaries = binary_metadata['rust-binaries']
    suites = listing['rust-suites']
    require(set(suites) == set(binaries), 'DISCOVERY_BINARY_SET')
    packages = {p['id']: p['name'] for p in cargo_metadata['packages']}
    for bid, suite in suites.items():
        built = binaries[bid]
        require(built['binary-id'] == bid == suite['binary-id'], 'DISCOVERY_BINARY_ID')
        for key in ('binary-name', 'package-id', 'kind', 'build-platform'):
            require(suite[key] == built[key], 'DISCOVERY_BINARY_FIELDS')
        require(Path(suite['binary-path']).resolve() == Path(built['binary-path']).resolve(), 'DISCOVERY_BINARY_PATH')
        require(suite['package-name'] == packages[built['package-id']], 'DISCOVERY_PACKAGE')


def isolated(root, role):
    require(role in FILTERS, 'ROLE')
    require(os.geteuid() != 0 and 'NoNewPrivs:\t1' in Path('/proc/self/status').read_text(), 'ISOLATION')
    verify(root)
    scratch = Path(read(root/'build.json')['scratch'])
    reuse = module('nextest-reuse.py')
    reuse['verify'](scratch)
    leg = root/role
    require((leg/'report.toml').read_text() == report_config(Path('.config/nextest.toml').read_text(), leg/'junit.xml'), 'CONFIG')
    require(not (leg/'junit.xml').exists(), 'STALE_REPORT')
    common = ['--config-file', str(leg/'report.toml'), '--user-config-file', 'none',
              '--binaries-metadata', str(scratch/'binaries.json'), '--cargo-metadata', str(scratch/'cargo.json'), '-E', FILTERS[role]]
    with (leg/'selection.json').open('xb') as out, (leg/'selection.stderr').open('xb') as err:
        subprocess.run(['cargo', 'nextest', 'list', *common, '--message-format', 'json'], stdout=out, stderr=err, check=True)
    # Explicit default ignored policy; no scheduler/test-thread overrides.
    with (leg/'nextest.jsonl').open('xb') as out, (leg/'nextest.stderr').open('xb') as err:
        result = subprocess.run(['cargo', 'nextest', 'run', *common, '--run-ignored', 'default', '--retries', '0', '--fail-fast',
                                 '--no-tests', 'fail', '--message-format', 'libtest-json-plus', '--message-format-version', '0.1'],
                                stdout=out, stderr=err, env={**os.environ, 'NEXTEST_EXPERIMENTAL_LIBTEST_JSON': '1'})
    reuse['verify'](scratch)
    verify(root)
    return result.returncode


def leg_receipt(root, role):
    leg = root/role
    result = {'role': role, 'errors': [], 'general_acceptance': False}
    errors = result['errors']
    try:
        verify(root)
        scratch = Path(read(root/'build.json')['scratch'])
        module('nextest-reuse.py')['verify'](scratch)
        c = module('isolation-custody-collect.py')
        build_record = c['custody_record'](scratch, os.environ['GITHUB_SHA'], 'x0x', Path.cwd())
        candidates = list((leg/'evidence').glob('x0x-isolation-*'))
        require(len(candidates) == 1 and not candidates[0].is_symlink(), 'ISOLATION_COUNT')
        run = c['isolation_record'](candidates[0], False, ['single', 'suite'], Path.cwd())
        result['custody'] = {'build': build_record, 'isolation': run}
        require(run['role'] == {'role': role, 'scratch': scratch.name}, 'CUSTODY_BINDING')
        # Cancellation has intentionally different exit conventions: supervisor
        # deadline=124/cancel=125, caller signal=128+signal, child may be negative,
        # and admitted()/the outer caller may not have written their receipts.
        supervisor = run['supervisor']
        interrupted = (supervisor['reason'] is not None or
                       supervisor['child_reaped'] is not True or supervisor['child_exit'] < 0)
        if interrupted:
            result['interrupted'] = True
        exit_code = None
        try:
            outer = read(leg/'runtime.json')
            require(isinstance(outer, dict) and set(outer) == {'exit'} and
                    type(outer['exit']) is int and -255 <= outer['exit'] <= 255, 'OUTER_EXIT')
            exit_code = outer['exit']
        except Exception:
            if not interrupted:
                raise
            errors.append('OUTER_EXIT_UNAVAILABLE')
        result['exit_observations'] = {'wrapper': exit_code, 'admitted': run['exit'],
                                       'supervisor_child': supervisor['child_exit']}
        if exit_code is not None:
            result['process_exit'] = exit_code
        if interrupted:
            raise Invalid('INTERRUPTED')
        # Equality belongs exclusively to a normally completed, reaped run.
        require(exit_code is not None and exit_code == run['exit'] == supervisor['child_exit'], 'EXIT_BINDING')
    except Exception:
        errors.append('CUSTODY_OR_SOURCE')
    try:
        raw = leg/'junit.xml'
        require(raw.is_file() and not raw.is_symlink() and raw.stat().st_size <= MAX_BYTES)
        js = leg/'nextest.jsonl'
        require(js.is_file() and not js.is_symlink() and js.stat().st_size <= MAX_BYTES)
        listing = read(leg/'selection.json')
        bind_discovery(listing, read(scratch/'binaries.json'), read(scratch/'cargo.json'))
        require(not result.get('interrupted'), 'INTERRUPTED')
        result['accounting'] = account(listing, js.read_text(), raw.read_bytes(), result['process_exit'])
        if role == 'single':
            require(result['accounting']['selected'] == 1, 'SINGLE_SELECTION')
        result['report_hashes'] = {p.name: digest(p) for p in (raw, js, leg/'selection.json')}
    except Exception as error:
        errors.append('ACCOUNTING_BOUND_EXCEEDED' if isinstance(error, Invalid) and
                      error.args == ('NUMBER_BOUND',) else 'ACCOUNTING_INVALID')
        if result.get('interrupted'):
            try:
                listing = read(leg/'selection.json')
                bind_discovery(listing, read(scratch/'binaries.json'), read(scratch/'cargo.json'))
                raw = leg/'nextest.jsonl'
                require(raw.is_file() and not raw.is_symlink() and raw.stat().st_size <= MAX_BYTES)
                result['interrupted_prefix'] = interrupted_prefix(listing, raw.read_text())
            except Exception:
                errors.append('INTERRUPTED_PREFIX_UNAVAILABLE')
    result['valid'] = not errors
    return result


def pair(root):
    verify(root)
    for role in FILTERS:
        # No role can execute twice, even after a failed prior invocation.
        with (root/role/'started').open('x') as stream:
            stream.write(role)
        require(float(os.environ['S574_DEADLINE']) - time.monotonic() >= 1850, 'DEADLINE')
        verify(root)
        scratch = Path(read(root/'build.json')['scratch'])
        module('nextest-reuse.py')['verify'](scratch)
        argv = ['python3', 'scripts/ci/isolated-runtime.py', 'python3', '-B', 'scripts/ci/suite574.py', 'isolated', str(root), role]
        leg = root/role
        with (leg/'wrapper.stdout').open('xb') as out, (leg/'wrapper.stderr').open('xb') as err:
            result = subprocess.run(argv, stdout=out, stderr=err, env={**os.environ,
                'RUNNER_TEMP': str(leg/'evidence'), 'X0X_RUNTIME_TIMEOUT_SECONDS': '1800',
                'X0X_ISOLATION_ROLE': role, 'X0X_CUSTODY_SCRATCH': str(scratch)})
        write(leg/'runtime.json', {'exit': result.returncode})
        receipt = leg_receipt(root, role)
        write(leg/'closed.json', receipt)
        # Continue after ordinary test failure; never after invalid custody/accounting.
        if not receipt['valid']:
            return 125
    return 0 if all(read(root/r/'closed.json')['process_exit'] == 0 for r in FILTERS) else 100


def collect(root, output):
    c = module('isolation-custody-collect.py')
    c['exclusive_output'](output)
    result = {'schema': 1, 'scope': 'suite_diagnostic_only', 'general_acceptance': False, 'legs': [], 'errors': []}
    try:
        verify(root)
        src = read(root/'source.json')
        result['source'] = {'head': src['head'], 'tree': src['tree'], 'manifest_sha256': digest(root/'source.json'), 'lock_sha256': LOCK}
        result['runner'] = closed_runner(read(root/'build.json')['facts'])
    except Exception:
        result['errors'].append('SOURCE_OR_BUILD')
    for role in FILTERS:
        result['legs'].append(leg_receipt(root, role))
    result['evidence_valid'] = not result['errors'] and all(r['valid'] for r in result['legs'])
    result['comparison_complete'] = result['evidence_valid'] and all(r['accounting']['target_status'] != 'unrun' for r in result['legs'])
    result['diagnostic_tests_passed'] = result['comparison_complete'] and all(r['accounting']['target_status'] == 'ok' for r in result['legs'])
    c['assert_no_leak'](result)
    path = output/'suite-diagnostic.json'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(result, stream, sort_keys=True)
        stream.write('\n')
    require(list(output.iterdir()) == [path], 'OUTPUT_EXTRA')
    c['mark_upload_eligible']()
    print(json.dumps({k: result[k] for k in ('evidence_valid', 'comparison_complete', 'diagnostic_tests_passed', 'general_acceptance')}))
    return 0 if result['evidence_valid'] else 125


def main():
    mode, path, *args = sys.argv[1:]
    root = Path(path).resolve(strict=True)
    if mode == 'prep' and not args: prep(root); return 0
    if mode == 'build' and not args: build(root); return 0
    if mode == 'pair' and not args: return pair(root)
    if mode == 'isolated' and len(args) == 1: return isolated(root, args[0])
    if mode == 'collect' and len(args) == 1: return collect(root, Path(args[0]))
    raise Invalid('MODE')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('suite574: operation rejected', file=sys.stderr)
        raise SystemExit(125)
