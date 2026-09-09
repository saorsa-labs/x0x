#!/usr/bin/env python3
"""One bounded component sequence. Raw evidence is encrypted, never printed."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time

PARENT = '920296961c028d5c2bc61368e2d0ea2e132f601b'
BRANCH = 'refs/heads/codex/501-isolated-evidence'
LOCK = '83fc5316716b6240ffa470daa77d3e6a7ea9ed09baf6631320d472514e38b32f'
RECIPIENT_SHA = '2265bb7ac6df437ea1c6c69f7f856f8603989f4d4b64415c1a3a17c333d570c8'
SELECTORS = tuple('legacy_bus_interop_tests::' + x for x in (
    'bus_only_interop_default_positive_and_optout_negative',
    'optout_sender_bus_fallback_reaches_bus_only_receiver',
    'optout_receiver_still_receives_modern_targeted_dm',
    'default_keeps_bus_subscription_and_optout_does_not',
    'paired_controlled_load_bus_eager_attempts_default_vs_optout'))
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
CANCELLED = False


class Rejected(Exception):
    """Only constant codes may cross the private/public boundary."""


def require(ok, code):
    if not ok:
        raise Rejected(code)


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def regular(path, root, limit=MAX_FILE):
    path, root = Path(path), Path(root).resolve(strict=True)
    require(path.is_absolute(), 'PATH_ABSOLUTE')
    require(path.resolve(strict=True).is_relative_to(root), 'PATH_ESCAPE')
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'PATH_SYMLINK')
        if part == root:
            break
    require(stat.S_ISREG(path.stat().st_mode), 'PATH_NOT_FILE')
    require(path.stat().st_size <= limit, 'FILE_TOO_LARGE')
    return path


def write_json(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')


def runtime_argv(selector):
    require(selector in SELECTORS, 'SELECTOR')
    return ['bash', 'scripts/ci/nextest-isolated.sh', '--offline', '--locked',
            '--all-features', '--package', 'x0x', '--lib', '--', '--profile', 'default',
            '--retries', '0', '--fail-fast', '--no-tests', 'fail', '--success-output',
            'immediate', '--failure-output', 'immediate', '-E',
            'package(=x0x) & binary(=x0x) & kind(=lib) & test(=' + selector + ')']


def parse_report(raw, selector, binary_id='x0x'):
    """Strip reporter framing only; payload cannot create an unindented separator."""
    text = raw.decode('utf-8', errors='strict')
    require('\x1b' not in text, 'ANSI_OUTPUT')
    lines = text.splitlines(keepends=True)
    cuts = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == '────────────']
    require(len(cuts) == 2, 'REPORT_FRAME')
    first, last = cuts
    reporter, stderr, spans = [], [], []
    channel = None
    seen = set()
    for i in range(first + 1, last):
        line = lines[i]
        marker = re.fullmatch(r'  (stdout|stderr) ───\r?\n?', line)
        if marker:
            channel = marker.group(1)
            require(channel not in seen, 'OUTPUT_DUPLICATE_CHANNEL')
            seen.add(channel)
        elif channel is None:
            reporter.append(line)
        elif line.startswith('    ') or not line.strip():
            if channel == 'stderr':
                stderr.append(line[4:] if line.startswith('    ') else line)
                spans.append(i + 1)
        elif line.startswith('  Cancelling due to test failure:'):
            pass
        else:
            raise Rejected('OUTPUT_FRAME')
    frame = ''.join(reporter)
    require(len(re.findall(r'^ Nextest run ID [0-9a-f-]+ with nextest profile: default$', frame, re.M)) == 1, 'RUN_HEADER')
    starts = re.findall(r'^    Starting (\d+) tests? across (\d+) binar(?:y|ies)(?: \([^\n]*\))?$', frame, re.M)
    require(starts == [('1', '1')], 'SELECTION_COUNT')
    rows = re.findall(r'^        (PASS|FAIL|TIMEOUT|LEAK|EXECFAIL|SKIP) \[\s*[0-9.]+s\] \((\d+)/(\d+)\) (\S+) (\S+)$', frame, re.M)
    require(len(rows) == 1, 'TERMINAL_COUNT')
    status, ordinal, total, binary, name = rows[0]
    require((ordinal, total, binary, name) == ('1', '1', binary_id, selector), 'TERMINAL_IDENTITY')
    # Failed recap lines after Summary are not a second execution.
    tail = ''.join(lines[last + 1:])
    summaries = re.findall(r'^     Summary \[\s*[0-9.]+s\] (\d+) tests? run: ([^\n]+)$', tail, re.M)
    require(len(summaries) == 1 and summaries[0][0] == '1', 'SUMMARY_COUNT')
    summary = re.fullmatch(r'1 passed(?: \((\d+) slow\))?(?:, \d+ skipped)?', summaries[0][1])
    require(status == 'PASS' and summary is not None, 'TEST_FAILED')
    require(summary.group(1) is None or int(summary.group(1)) == 1, 'SUMMARY_SLOW_COUNT')
    require(not re.search(r'^        (?:PASS|FAIL|TIMEOUT|LEAK|EXECFAIL|SKIP) ', tail, re.M), 'UNEXPECTED_RECAP')
    return {'selected': 1, 'ran': 1, 'passed': 1, 'failed': 0}, ''.join(stderr).encode(), spans


def parse_terminal(raw, selector):
    return parse_report(raw, selector)[0]


def run_private(argv, cwd, env, directory, name, timeout):
    """Own/reap the outer group; inner root supervisor retains its own custody."""
    started = time.monotonic()
    with (directory / (name + '.stdout')).open('xb') as out, (directory / (name + '.stderr')).open('xb') as err:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        reason = None
        try:
            while child.poll() is None:
                if (CANCELLED and name == 'runtime') or time.monotonic() - started >= timeout:
                    reason = 'signal' if CANCELLED and name == 'runtime' else 'deadline'
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    break
                time.sleep(0.1)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            else:
                child.wait()
    result = {'argv': argv, 'cwd': str(cwd), 'exit': child.returncode, 'reason': reason,
              'outer_pid': child.pid, 'outer_reaped': True, 'elapsed_seconds': time.monotonic() - started,
              'stdout_sha256': digest(directory / (name + '.stdout')),
              'stderr_sha256': digest(directory / (name + '.stderr'))}
    write_json(directory / (name + '.json'), result)
    return result


def source_map(workspace, expected_sha):
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=workspace, stderr=subprocess.DEVNULL)
    require(git('rev-parse', 'HEAD').decode().strip() == expected_sha, 'SOURCE_HEAD')
    require(git('show', '-s', '--format=%P', 'HEAD').decode().split() == [PARENT], 'SOURCE_PARENT')
    require(not git('status', '--porcelain').strip(), 'SOURCE_DIRTY')
    require(git('rev-parse', PARENT + '^{tree}').decode().strip() == '71f9e06f5f73cf414ac88eb75ed9d7563d20c943', 'PARENT_TREE')
    require(set(git('diff', '--name-only', PARENT, 'HEAD').decode().splitlines()) == {'.github/workflows/issue501-component.yml', 'scripts/ci/issue501-component-evidence.py', 'scripts/ci/nextest-isolated.sh', 'scripts/ci/test_nextest_isolated.py'}, 'CONTRIBUTION_SCOPE')
    entries = {}
    for row in git('ls-tree', '-rz', '--full-tree', 'HEAD').split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t'); mode, kind, blob = meta.decode().split()
        name = name.decode(); p = regular(workspace / name, workspace)
        require(kind == 'blob' and mode in ('100644', '100755'), 'SOURCE_KIND')
        require(('100755' if p.stat().st_mode & 0o111 else '100644') == mode, 'SOURCE_MODE')
        content = p.read_bytes()
        require(hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == blob, 'SOURCE_BLOB')
        entries[name] = {'sha256': hashlib.sha256(content).hexdigest(), 'mode': mode, 'blob': blob}
    require(digest(workspace / 'Cargo.lock') == LOCK, 'LOCK_DRIFT')
    return {'head': expected_sha, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(), 'parents': [PARENT], 'files': entries, 'lock_sha256': LOCK}


def validate_reuse(workspace, root, source):
    scratches = sorted(root.glob('x0x-metadata-*'))
    require(len(scratches) == 1 and scratches[0].is_dir() and not scratches[0].is_symlink(), 'SCRATCH_COUNT')
    scratch = scratches[0]
    custody = json.loads(regular(scratch / 'custody.json', root).read_text())
    require(custody['source'] == [source['head'], source['tree']], 'REUSE_SOURCE')
    require(regular(scratch / 'lock.sha256', root).read_text().split() == [LOCK, 'Cargo.lock'], 'REUSE_LOCK')
    meta = json.loads(regular(scratch / 'binaries.json', root).read_text())
    regular(scratch / 'cargo.json', root)
    target = Path(meta['rust-build-meta']['target-directory'])
    require(target == workspace / 'target', 'TARGET_ROOT')
    binaries = meta['rust-binaries']
    require(len(binaries) == 1, 'BINARY_COUNT')
    binary = next(iter(binaries.values()))
    require(binary['binary-name'] == 'x0x' and binary['kind'] == 'lib', 'BINARY_IDENTITY')
    require(next(iter(binaries)) == 'x0x', 'BINARY_IDENTITY')
    path = Path(binary['binary-path'])
    # Large linked binaries are hashed streaming, not copied into public output.
    regular(path, target, MAX_TOTAL)
    inputs = {str(path.resolve()), str((workspace / 'Cargo.lock').resolve()), str((scratch / 'cargo.json').resolve()), str((scratch / 'binaries.json').resolve())}
    for values in meta['rust-build-meta']['non-test-binaries'].values():
        for item in values:
            p = target / item['path']; regular(p, target, MAX_TOTAL)
            inputs.add(str(p.resolve()))
    require(set(custody['files']) == inputs, 'REUSE_INPUT_SET')
    for p, sha in custody['files'].items():
        require(digest(p) == sha, 'REUSE_INPUT_HASH')
    return {'scratch': scratch.name, 'binary_sha256': digest(path), 'binary_id': next(iter(binaries)), 'input_hashes': custody['files']}


def validate_closed(receipt, source, reuse):
    require(receipt.get('valid') is True and receipt.get('status') == 'complete', 'CUSTODY_INVALID')
    runs, builds = receipt['isolation_runs'], receipt['build_custody']
    require(len(runs) == len(builds) == 1, 'CUSTODY_COUNT')
    run, build = runs[0], builds[0]
    require(run['role'] == {'role': 'acceptance', 'scratch': reuse['scratch']}, 'CUSTODY_BINDING')
    require(build['source_head'] == source['head'] and build['source_tree'] == source['tree'] and build['lock_sha256'] == LOCK, 'CUSTODY_SOURCE')
    require(run['supervisor']['reason'] is None and run['supervisor']['child_exit'] == 0 and run['supervisor']['child_reaped'] is True, 'CHILD_NOT_COMPLETE')
    require(type(run['exit']) is int and run['exit'] == 0, 'ADMITTED_EXIT')
    a = run['admission']
    require(a['interfaces'] == ['lo'] and a['no_new_privs'] == 1 and all(a[k] is True for k in ('namespace_changed', 'all_routes_dev_lo', 'no_default_route', 'no_gateway_route', 'unprivileged_uid', 'capability_sets_empty')), 'ADMISSION_FACTS')
    return {'child_exit': 0, 'child_reaped': True, 'namespace_admitted': True}


def execute_sequence(execute):
    results = []
    stopped = False
    for index, selector in enumerate(SELECTORS, 1):
        if stopped:
            results.append({'ordinal': index, 'selector': selector, 'status': 'UNRUN'})
            continue
        result = execute(index, selector)
        results.append(result)
        stopped = result['status'] != 'PASS'
    return results


def safe_measurement(value):
    require(value['derivation'] == 'CONSISTENT', 'DERIVATION_NOT_CONSISTENT')
    result = {}
    for arm in ('D5', 'O5'):
        row = value['arms'][arm]
        for field in ('elapsed_seconds', 'bus_eager_attempt_bytes', 'bus_eager_attempt_KiB_per_s', 'relay_delta'):
            x = row[field]
            require(type(x) in (int, float) and math.isfinite(x) and x >= 0, 'DERIVATION_NUMBER')
            result[arm + '_' + field] = x
    return result


def validate_derivation(result, derived, binary_sha, raw_sha):
    require(result['reason'] is None and type(result['exit']) is int and result['exit'] in (0, 1), 'DERIVATION_INCOMPLETE')
    require(isinstance(derived, dict), 'DERIVATION_RESULT')
    require(derived.get('binary_sha256') == binary_sha and derived.get('build_lock_sha256') == LOCK
            and derived.get('retained_lock_sha256') == LOCK and derived.get('raw_sha256') == raw_sha, 'DERIVATION_BINDING')
    failures = derived.get('oracle_failures')
    tags = ('D5_EAGER_ORACLE', 'O5_EAGER_ORACLE', 'D5_RELAY_CHANGED', 'O5_RELAY_CHANGED')
    require(type(failures) is list and len(failures) <= len(tags)
            and all(type(x) is str and x in tags for x in failures)
            and len(set(failures)) == len(failures), 'DERIVATION_RESULT')
    if result['exit'] == 1:
        require(derived.get('derivation') == 'FAIL' and bool(failures), 'DERIVATION_RESULT')
        raise Rejected('DERIVATION_ORACLE_FAIL')
    require(derived.get('derivation') == 'CONSISTENT' and not failures, 'DERIVATION_RESULT')
    return safe_measurement(derived)


def failure_status(item, error):
    oracle = isinstance(error, Rejected) and str(error) in ('RUNTIME_FAILED', 'TEST_FAILED', 'DERIVATION_ORACLE_FAIL')
    return 'FAIL' if item.get('wrapper_exit', 0) != 0 or oracle else 'INCOMPLETE'


def public_results(results):
    allowed = {'ordinal', 'selector', 'status', 'wrapper_exit', 'outer_reaped', 'binary_sha256',
               'selected', 'ran', 'passed', 'failed', 'child_exit', 'child_reaped', 'namespace_admitted', 'code'}
    require(len(results) == 5, 'RESULT_COUNT')
    for index, item in enumerate(results, 1):
        require(set(item) <= allowed and item.get('ordinal') == index and item.get('selector') == SELECTORS[index - 1], 'PUBLIC_RESULT_SCHEMA')
        require(item.get('status') in ('PASS', 'FAIL', 'INCOMPLETE', 'UNRUN'), 'PUBLIC_STATUS')
        for key, value in item.items():
            if key in ('ordinal', 'wrapper_exit', 'selected', 'ran', 'passed', 'failed', 'child_exit'):
                require(type(value) is int and -255 <= value <= 255, 'PUBLIC_NUMBER')
            elif key in ('outer_reaped', 'child_reaped', 'namespace_admitted'):
                require(type(value) is bool, 'PUBLIC_BOOLEAN')
            elif key == 'binary_sha256':
                require(re.fullmatch('[0-9a-f]{64}', value) is not None, 'PUBLIC_HASH')
            elif key == 'code':
                require(re.fullmatch('[A-Z_]{1,50}', value) is not None, 'PUBLIC_CODE')
    return results


def seal(private, output, recipient, run, env, source, results, measurement, age_identity):
    results = public_results(results)
    require(digest(recipient) == RECIPIENT_SHA, 'RECIPIENT_PIN')
    age_path, age_sha = age_identity
    require(digest(age_path) == age_sha, 'AGE_CHANGED')
    files = {}
    total = 0
    for path in sorted(private.rglob('*')):
        require(not path.is_symlink(), 'ARCHIVE_SYMLINK')
        if path.is_dir():
            continue
        regular(path, private); total += path.stat().st_size
        require(total <= MAX_TOTAL, 'ARCHIVE_BOUND')
        files[str(path.relative_to(private))] = digest(path)
    write_json(private / 'plaintext-manifest.json', files)
    archive = output.parent / 'private-evidence.tar'
    with tarfile.open(archive, 'x') as tar:
        for path in sorted(private.rglob('*')):
            if path.is_file():
                tar.add(path, arcname=str(path.relative_to(private)), recursive=False)
    cipher = output / 'evidence.tar.age'
    result = run([str(age_path), '-R', str(recipient), '-o', str(cipher), str(archive)], private, env, private, 'seal', 120)
    require(result['exit'] == 0 and result['reason'] is None and cipher.is_file() and cipher.stat().st_size > 0, 'SEAL_FAILED')
    with cipher.open('rb') as f:
        require(f.read(22).startswith(b'age-encryption.org/v1'), 'SEAL_HEADER')
    public = {'schema': 'x0x.issue501-component/1', 'source_commit': source['head'], 'source_tree': source['tree'],
              'source_map_sha256': digest(private / 'source-before.json'), 'run_id': os.environ['GITHUB_RUN_ID'],
              'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'job': 'component',
              'results': results, 'measurement': measurement,
              'plaintext_manifest_sha256': digest(private / 'plaintext-manifest.json'),
              'plaintext_archive_sha256': digest(archive), 'cipher_sha256': digest(cipher),
              'seal_exit': 0, 'age_binary_sha256': age_sha, 'recipient_sha256': RECIPIENT_SHA, 'private_readback': 'PENDING', 'scope': 'component send attempts; no wire/field/final acceptance'}
    write_json(output / 'receipt.json', public)
    return public


def verify_readback(archive, cipher, receipt):
    """After owner-side decryption: hashes only, never runtime acceptance."""
    require(digest(archive) == receipt['plaintext_archive_sha256'] and digest(cipher) == receipt['cipher_sha256'], 'READBACK_ARCHIVE_HASH')
    with tarfile.open(archive, 'r:') as tar:
        members = tar.getmembers()
        require(len(members) <= 10000 and sum(x.size for x in members) <= MAX_TOTAL, 'READBACK_BOUND')
        require(len({x.name for x in members}) == len(members), 'READBACK_DUPLICATE')
        for member in members:
            path = Path(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts and member.size <= MAX_FILE, 'READBACK_PATH')
        payload = {m.name: tar.extractfile(m).read() for m in members}
    manifest_bytes = payload.pop('plaintext-manifest.json')
    require(hashlib.sha256(manifest_bytes).hexdigest() == receipt['plaintext_manifest_sha256'], 'READBACK_MANIFEST_HASH')
    manifest = json.loads(manifest_bytes)
    require(set(payload) == set(manifest), 'READBACK_FILE_SET')
    require(all(hashlib.sha256(b).hexdigest() == manifest[n] for n, b in payload.items()), 'READBACK_FILE_HASH')
    require(hashlib.sha256(payload['source-before.json']).hexdigest() == receipt['source_map_sha256'], 'READBACK_SOURCE_HASH')
    source = json.loads(payload['source-before.json'])
    require(source['head'] == receipt['source_commit'] and source['tree'] == receipt['source_tree'], 'READBACK_SOURCE')
    return 'HASH_READBACK_VERIFIED_NOT_RUNTIME_ACCEPTANCE'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-root', type=Path, required=True)
    args = parser.parse_args()
    workspace = Path.cwd().resolve()
    require(os.environ.get('GITHUB_REPOSITORY') == 'saorsa-labs/x0x' and os.environ.get('GITHUB_REF') == BRANCH and os.environ.get('GITHUB_EVENT_NAME') == 'push', 'EVENT_GUARD')
    sha = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'EVENT_SHA')
    require(all(re.fullmatch('[1-9][0-9]*', os.environ.get(k, '')) for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'RUN_ID')
    root = args.output_root
    require(root.is_absolute() and not root.exists() and not root.is_symlink(), 'ROOT_EXCLUSIVE')
    root.mkdir(mode=0o700); private = root / 'private'; private.mkdir(mode=0o700); output = root / 'public'; output.mkdir()
    env = os.environ.copy(); env.update(CARGO_TERM_COLOR='never', RUSTUP_TOOLCHAIN='1.95.0', CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(workspace / 'target'))
    recipient = workspace / 'scripts/ci/issue501-recipient.txt'
    require(digest(recipient) == RECIPIENT_SHA, 'RECIPIENT_PIN')
    require(not (workspace / 'target').exists(), 'TARGET_NOT_FRESH')
    source = source_map(workspace, sha); write_json(private / 'source-before.json', source)
    # Retain the exact downloaded tool archives and private preparation logs.
    prep = Path(os.environ['RUNNER_TEMP']) / 'issue501-preparation'
    retained = private / 'preparation'; retained.mkdir()
    for name in ('apt-update.log', 'apt-install.log', 'rustup.log', 'cargo-fetch.log', 'nextest.tar.gz', 'age.tar.gz'):
        shutil.copyfile(regular(prep / name, prep), retained / name)
    require(digest(retained / 'nextest.tar.gz') == '66786b9abe23920d022a182d1416b1bbc8130dd4872a9553d76985a1708dcd1e', 'NEXTEST_ASSET')
    require(digest(retained / 'age.tar.gz') == 'cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10', 'AGE_ASSET')
    for name in ('age', 'cargo-nextest'):
        require(Path(shutil.which(name)).resolve() == (prep / 'bin' / name).resolve(), 'TOOL_PATH')
    # Missing/incompatible encryption must prevent any real selector.
    version = run_private(['age', '--version'], workspace, env, private, 'age-version', 15)
    require(version['exit'] == 0 and (private / 'age-version.stdout').read_text().strip() in ('1.3.2', 'v1.3.2'), 'AGE_VERSION')
    probe = private / 'seal-probe.txt'; probe.write_text('issue501 retention preflight\n')
    probe_result = run_private(['age', '-R', str(recipient), '-o', str(private / 'seal-probe.age'), str(probe)], workspace, env, private, 'seal-probe', 15)
    require(probe_result['exit'] == 0 and (private / 'seal-probe.age').is_file(), 'SEAL_PREFLIGHT')
    for name, argv, expected in [('rustc', ['rustc', '--version'], 'rustc 1.95.0'), ('nextest', ['cargo', 'nextest', '--version'], 'cargo-nextest 0.9.143')]:
        r = run_private(argv, workspace, env, private, name + '-version', 30)
        require(r['exit'] == 0 and (private / (name + '-version.stdout')).read_text().startswith(expected), 'TOOL_VERSION')
    write_json(private / 'tool-hashes.json', {name: digest(shutil.which(name)) for name in ('age', 'cargo-nextest', 'rustc', 'cargo')})
    age_identity = (Path(shutil.which('age')).resolve(), digest(shutil.which('age')))
    deadline = time.monotonic() + 2700
    measurement = None

    def execute(index, selector):
        nonlocal measurement
        folder = private / ('selector-' + str(index)); folder.mkdir(); rt = folder / 'runner-temp'; rt.mkdir()
        e = env.copy(); e.update(RUNNER_TEMP=str(rt), X0X_ISOLATION_ROLE='acceptance', X0X_RUNTIME_TIMEOUT_SECONDS='300')
        item = {'ordinal': index, 'selector': selector, 'status': 'INCOMPLETE'}
        try:
            require(not CANCELLED and time.monotonic() < deadline, 'OUTER_STOP')
            require(source_map(workspace, sha) == source, 'SOURCE_DRIFT')
            shutil.copyfile(workspace / 'Cargo.lock', folder / 'Cargo.lock.before')
            result = run_private(runtime_argv(selector), workspace, e, folder, 'runtime', min(900, deadline - time.monotonic()))
            item.update(wrapper_exit=result['exit'], outer_reaped=result['outer_reaped'])
            e.update(X0X_CUSTODY_EXPECT='success' if result['exit'] == 0 and result['reason'] is None else 'failure', X0X_CUSTODY_ROLES='acceptance', X0X_CUSTODY_TARGET='x0x', X0X_CUSTODY_MIN_RUNS='1')
            collector = run_private(['python3', 'scripts/ci/isolation-custody-collect.py', str(folder / 'closed')], workspace, e, folder, 'collector', 60)
            shutil.copyfile(workspace / 'Cargo.lock', folder / 'Cargo.lock.after')
            require(source_map(workspace, sha) == source, 'SOURCE_DRIFT')
            require((folder / 'Cargo.lock.before').read_bytes() == (folder / 'Cargo.lock.after').read_bytes(), 'LOCK_DRIFT')
            reuse = validate_reuse(workspace, rt, source); write_json(folder / 'verified-reuse.json', reuse)
            item['binary_sha256'] = reuse['binary_sha256']
            require(result['exit'] == 0 and result['reason'] is None, 'RUNTIME_FAILED')
            accounting, test_stderr, spans = parse_report((folder / 'runtime.stderr').read_bytes(), selector)
            item.update(accounting)
            (folder / 'test.stderr').write_bytes(test_stderr)
            write_json(folder / 'stderr-extraction.json', {'source_sha256': digest(folder / 'runtime.stderr'), 'extracted_sha256': digest(folder / 'test.stderr'), 'source_lines_one_based': spans, 'transform': 'remove exactly one reporter four-space prefix; preserve content/newlines', 'selector': selector, 'binary': 'x0x'})
            require(collector['exit'] == 0 and collector['reason'] is None, 'COLLECTOR_FAILED')
            closed = json.loads((folder / 'closed/custody-receipt.json').read_text())
            item.update(validate_closed(closed, source, reuse))
            if index == 5:
                d = run_private(['python3', 'scripts/ci/derive-legacy-bus-attempts.py', '--raw', str(folder / 'test.stderr'), '--lock', str(folder / 'Cargo.lock.before')], workspace, e, folder, 'derive', 60)
                derived = json.loads((folder / 'derive.stdout').read_text())
                measurement = validate_derivation(d, derived, reuse['binary_sha256'], digest(folder / 'test.stderr'))
            item['status'] = 'PASS'
        except (Rejected, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
            item['status'] = failure_status(item, error)
            item['code'] = str(error) if isinstance(error, Rejected) else 'MALFORMED_OR_IO'
        return item

    results = execute_sequence(execute)
    try:
        after = source_map(workspace, sha)
        require(after == source, 'SOURCE_DRIFT')
        write_json(private / 'source-after.json', after)
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        write_json(private / 'source-after-error.json', {'code': 'POST_SOURCE_INVALID'})
        for item in results:
            if item['status'] == 'PASS':
                item['status'] = 'INCOMPLETE'
                item['code'] = 'POST_SOURCE_INVALID'
    seal(private, output, recipient, run_private, env, source, results, measurement, age_identity)
    # Only exact encrypted+closed paths are eligible; failure still uploads retained evidence.
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write('sealed=true\n')
    return 0 if all(x['status'] == 'PASS' for x in results) else 1


def interrupted(_number, _frame):
    global CANCELLED
    CANCELLED = True


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(main())
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('issue501 evidence incomplete; no raw output disclosed')
        raise SystemExit(2)
