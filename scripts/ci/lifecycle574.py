#!/usr/bin/env python3
"""Disposable diagnostic runner/closed collector. Never release or general acceptance."""
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

TEST = 'server::routes::named_groups::tests::hs_f2_membership_cluster::integration_treekem_home_rename_restart_single_announce_end_to_end'
QUALIFIED = 'x0x::x0x$' + TEST
FILTER = 'test(=' + TEST + ')'
LOCK = '83fc5316716b6240ffa470daa77d3e6a7ea9ed09baf6631320d472514e38b32f'
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')
MAX_RAW = 16 * 1024 * 1024
REASONS = 'Superseded ReaderExit PeerShutdown Banned LifecycleCleanup NoReader LivenessTimeout ApplicationClosed ConnectionClosed TimedOut Reset TransportError LocallyClosed VersionMismatch CidsExhausted Unknown'.split()
MARKERS = {'before_old_shutdown', 'before_new_dial', 'reconnected', 'readiness_returned', 'collector_join_error'}


def require(condition):
    if not condition:
        raise ValueError('invalid diagnostic evidence')


def digest(path):
    require(path.is_file() and not path.is_symlink())
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_RAW)
    return json.loads(path.read_text())


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def guard(expected, event, head, dirty):
    require(isinstance(expected, str) and HEX40.fullmatch(expected))
    require(expected == event == head and not dirty)


def source_snapshot():
    guard(os.environ['EXPECTED_COMMIT'], os.environ['GITHUB_SHA'], git('rev-parse', 'HEAD'), git('status', '--porcelain'))
    paths = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')[:-1]
    require(paths and all(not Path(path).is_symlink() for path in paths))
    return {'head': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'files': {name: digest(Path(name)) for name in paths}}


def verify_source(root):
    old = read(root / 'source.json')
    require(source_snapshot() == old)
    require(digest(Path('Cargo.lock')) == LOCK)
    return old


def selection(value, test=TEST):
    suites = value['rust-suites']
    require(set(suites) == {'x0x'})
    suite = suites['x0x']
    require(suite['kind'] == 'lib' and suite['binary-name'] == suite['package-name'] == 'x0x')
    require(suite['status'] == 'listed')
    selected = [(name, row) for name, row in suite['testcases'].items()
                if row['filter-match']['status'] == 'matches']
    require(len(selected) == 1 and selected[0][0] == test)
    require(selected[0][1]['ignored'] is False and selected[0][1]['kind'] == 'test')
    return {'matched': 1, 'target': 'x0x', 'kind': 'lib', 'exact_test': True, 'ignored': False}


def nextest(lines, qualified=QUALIFIED):
    events = []
    for line in lines:
        if not line.strip():
            continue
        value = json.loads(line)
        require(isinstance(value, dict))
        kind, event = value.get('type'), value.get('event')
        if kind == 'suite':
            require(value.get('nextest') == {'crate': 'x0x', 'test_binary': 'x0x', 'kind': 'lib'})
            require(event in {'started', 'ok', 'failed'})
        else:
            require(kind == 'test' and value.get('name') == qualified)
            require(event in {'started', 'ok', 'failed'})
        events.append((kind, event, value))
    require(len(events) == 4)
    require([item[:2] for item in events[:2]] == [('suite', 'started'), ('test', 'started')])
    terminal = events[2][1]
    require(events[2][:2] == ('test', terminal) and terminal in {'ok', 'failed'})
    require(events[3][:2] == ('suite', terminal))
    first, last = events[0][2], events[3][2]
    for key in ('passed', 'failed', 'ignored', 'measured', 'filtered_out'):
        require(type(last.get(key)) is int and last[key] >= 0)
    require(type(first.get('test_count')) is int)
    require(last['passed'] == int(terminal == 'ok') and last['failed'] == int(terminal == 'failed'))
    require(last['measured'] == 0 and first['test_count'] == 1 + last['ignored'])
    # Pinned nextest includes filtered ignored cases in suite_test_count; the
    # structured-list exact match and sole started/terminal pair are binding.
    return {'started': 1, 'terminal': terminal, 'suite_count': first['test_count'],
            'ignored_accounting': last['ignored'], 'filtered_out': last['filtered_out']}


def trace_rows(text):
    rows, summary = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith('DIAG lifecycle574'):
            continue
        require(summary is None)
        m = re.fullmatch(r'DIAG lifecycle574 seq=(\d+) elapsed_us=(\d+) side=(Owner|Joiner) (.+)', line)
        if m:
            seq, elapsed, side, detail = m.groups()
            require(len(rows) < 256 and int(seq) == len(rows) + 1)
            require(int(elapsed) <= 30 * 60 * 1_000_000)
            require(not rows or int(elapsed) >= rows[-1]['elapsed_us'])
            row = {'sequence': int(seq), 'elapsed_us': int(elapsed), 'side': side}
            if detail.startswith('lifecycle='):
                event = detail.removeprefix('lifecycle=')
                fields = re.fullmatch(r'(Established|ReaderExited) \{ generation: (\d+) \}', event)
                replaced = re.fullmatch(r'Replaced \{ old_generation: (\d+), new_generation: (\d+) \}', event)
                closed = re.fullmatch(r'(Closing|Closed) \{ generation: (\d+), reason: (' + '|'.join(REASONS) + r') \}', event)
                require(fields or replaced or closed)
                if fields: row.update(event=fields[1], generation=int(fields[2]))
                if replaced: row.update(event='Replaced', old_generation=int(replaced[1]), new_generation=int(replaced[2]))
                if closed: row.update(event=closed[1], generation=int(closed[2]), reason=closed[3])
            elif detail in {'stream_closed', 'stream_unavailable', 'capture_event_limit', 'capture_deadline'}:
                row['event'] = detail
            elif re.fullmatch(r'lagged=\d+', detail):
                row.update(event='lagged', count=int(detail.split('=')[1]))
            elif re.fullmatch(r'marker=[a-z_]+', detail):
                marker = detail.split('=')[1]; require(marker in MARKERS)
                row.update(event='marker', marker=marker)
            elif re.fullmatch(r'publish_attempted=(None|Some\(\d+\))', detail):
                val = detail.split('=')[1]
                row.update(event='publish', attempted=None if val == 'None' else int(val[5:-1]))
            else:
                snap = re.fullmatch(r'transport_send_ready=(None|Some\(\((true|false), (true|false)\)\)) admission=unavailable', detail)
                require(snap)
                row.update(event='snapshot', transport=None if snap[1] == 'None' else snap[2] == 'true',
                           send_ready=None if snap[1] == 'None' else snap[3] == 'true', admission='unavailable')
            require(all(type(v) is not int or 0 <= v < 2**64 for v in row.values()))
            rows.append(row)
            continue
        stop = re.fullmatch(r'DIAG lifecycle574 stop=(collectors_joined|abort_requested_on_drop) total=(\d+) overflow=(\d+) foreign=(\[\d+, \d+\]) lagged=(\[\d+, \d+\]) stream_closed=(\[(?:true|false), (?:true|false)\]) pending_at_stop=(\[\d+, \d+\]) collectors_dropped=(\[(?:true|false), (?:true|false)\]) acceptance=not_evaluated', line)
        require(stop)
        summary = dict(stop=stop[1], total=int(stop[2]), overflow=int(stop[3]),
                       foreign=json.loads(stop[4]), lagged=json.loads(stop[5]),
                       stream_closed=json.loads(stop[6]), pending_at_stop=json.loads(stop[7]),
                       collectors_dropped=json.loads(stop[8]))
        require(summary['total'] == len(rows) + summary['overflow'])
        for name in ('total', 'overflow', 'foreign', 'lagged', 'pending_at_stop'):
            values = summary[name] if isinstance(summary[name], list) else [summary[name]]
            require(all(type(v) is int and 0 <= v < 2**64 for v in values))
    require(summary is not None)
    gaps = (summary['overflow'] > 0 or any(summary['lagged']) or any(summary['pending_at_stop'])
            or summary['stop'] != 'collectors_joined' or not all(summary['collectors_dropped'])
            or any(r['event'] in {'stream_unavailable', 'capture_event_limit', 'capture_deadline'} for r in rows))
    return {'rows': rows, 'summary': summary, 'evidence_gaps': bool(gaps), 'general_acceptance': False}


def binding(custody):
    require(custody['observed_roles'] == ['diagnostic'])
    require(len(custody['isolation_runs']) == len(custody['build_custody']) == 1)
    run, build = custody['isolation_runs'][0], custody['build_custody'][0]
    require(run['role']['role'] == 'diagnostic' and run['role']['scratch'] == build['scratch'])
    require(build['target'] == 'x0x' and len(build['target_binaries']) == 1)


def reuse():
    return runpy.run_path(str(Path(__file__).with_name('nextest-reuse.py')))


def scratch(root):
    value = read(root / 'build.json')
    return Path(value['scratch'])


def prep(root):
    require(not Path('Cargo.lock').exists() and not Path('target').exists())
    value = source_snapshot()
    require(digest(Path('ci/lifecycle574/Cargo.lock.fixture')) == LOCK)
    Path('Cargo.lock').write_bytes(Path('ci/lifecycle574/Cargo.lock.fixture').read_bytes())
    write(root / 'source.json', value)


def build_record(root):
    verify_source(root)
    directory = Path(tempfile.mkdtemp(prefix='x0x-metadata-', dir=os.environ['RUNNER_TEMP']))
    for name, argv in [('cargo.json', ['cargo', 'metadata', '--format-version', '1', '--all-features', '--locked', '--offline']),
                       ('binaries.json', ['cargo', 'nextest', 'list', '--all-features', '--lib', '--locked', '--offline', '--cargo-metadata', str(directory / 'cargo.json'), '--list-type', 'binaries-only', '--message-format', 'json'])]:
        with (directory / name).open('wb') as output:
            subprocess.run(argv, stdout=output, check=True)
    (directory / 'lock.sha256').write_text(LOCK + '  Cargo.lock\n')
    reuse()['record'](directory)
    meta = read(directory / 'binaries.json')['rust-binaries']
    require(len(meta) == 1)
    binary = next(iter(meta.values()))
    require(binary['kind'] == 'lib' and binary['binary-name'] == 'x0x')
    path = Path(binary['binary-path'])
    require(path.resolve().is_relative_to(Path('target').resolve()))
    write(root / 'build.json', {'scratch': str(directory), 'binary_sha256': digest(path)})
    verify_source(root)


def isolated(root):
    require(os.geteuid() != 0 and 'NoNewPrivs:\t1' in Path('/proc/self/status').read_text())
    directory = scratch(root)
    reuse()['verify'](directory)
    common = ['--binaries-metadata', str(directory / 'binaries.json'), '--cargo-metadata', str(directory / 'cargo.json'), '--run-ignored', 'all', '-E', FILTER]
    with (root / 'selection-raw.json').open('wb') as output, (root / 'selection.stderr').open('wb') as error:
        subprocess.run(['cargo', 'nextest', 'list', *common, '--message-format', 'json'], stdout=output, stderr=error, check=True)
    write(root / 'selection.json', selection(read(root / 'selection-raw.json')))
    reuse()['verify'](directory)
    argv = ['python3', 'scripts/ci/nextest-reuse.py', 'run', str(directory), '--run-ignored', 'all', '-E', FILTER,
            '--retries', '0', '--test-threads', '1', '--no-tests', 'fail', '--message-format', 'libtest-json-plus',
            '--message-format-version', '0.1', '--success-output', 'immediate', '--failure-output', 'immediate']
    with (root / 'nextest.log').open('wb') as output, (root / 'nextest.stderr').open('wb') as error:
        result = subprocess.run(argv, stdout=output, stderr=error, env={**os.environ, 'NEXTEST_EXPERIMENTAL_LIBTEST_JSON': '1'})
    reuse()['verify'](directory)
    return result.returncode


def runtime(root):
    require(float(os.environ['L574_DEADLINE']) - time.monotonic() >= 495)
    verify_source(root)
    directory = scratch(root)
    reuse()['verify'](directory)
    argv = ['python3', 'scripts/ci/isolated-runtime.py', 'python3', 'scripts/ci/lifecycle574.py', 'isolated', str(root)]
    with (root / 'wrapper.log').open('wb') as output, (root / 'wrapper.stderr').open('wb') as error:
        result = subprocess.run(argv, stdout=output, stderr=error, env={**os.environ,
            'X0X_RUNTIME_TIMEOUT_SECONDS': '300', 'X0X_ISOLATION_ROLE': 'diagnostic', 'X0X_CUSTODY_SCRATCH': str(directory)})
    write(root / 'runtime.json', {'exit': result.returncode})
    verify_source(root)
    reuse()['verify'](directory)
    return result.returncode


def collect(root, output):
    c = runpy.run_path(str(Path(__file__).with_name('isolation-custody-collect.py')))
    c['exclusive_output'](output)
    errors = []
    result = {'schema': 1, 'scope': 'diagnostic_only', 'general_acceptance': False}
    try:
        source = verify_source(root)
        directory = scratch(root)
        reuse()['verify'](directory)
        build = read(root / 'build.json')
        require(HEX64.fullmatch(build['binary_sha256']))
        result['source'] = {'head': source['head'], 'tree': source['tree'], 'file_count': len(source['files']),
            'source_manifest_sha256': digest(root / 'source.json'), 'lock_sha256': LOCK,
            'binary_sha256': build['binary_sha256'], 'unchanged': True}
    except Exception:
        errors.append('SOURCE_OR_BUILD')
    try:
        selected = read(root / 'selection.json')
        require(selected == {'matched': 1, 'target': 'x0x', 'kind': 'lib', 'exact_test': True, 'ignored': False})
        result['selection'] = selected
        log = root / 'nextest.log'; require(log.stat().st_size <= MAX_RAW and not log.is_symlink())
        result['nextest'] = nextest(log.read_text().splitlines())
        run = read(root / 'runtime.json'); require(set(run) == {'exit'} and type(run['exit']) is int and 0 <= run['exit'] <= 255)
        require((run['exit'] == 0) == (result['nextest']['terminal'] == 'ok'))
        result['runtime_exit'] = run['exit']
    except Exception:
        errors.append('SELECTION_OR_TERMINAL')
    try:
        log = root / 'nextest.stderr'; require(log.stat().st_size <= MAX_RAW and not log.is_symlink())
        result['trace'] = trace_rows(log.read_text())
    except Exception:
        errors.append('TRACE')
    try:
        expect = 'success' if result.get('runtime_exit') == 0 else 'failure'
        custody = c['collect'](Path(os.environ['RUNNER_TEMP']), expect, os.environ['GITHUB_SHA'], Path.cwd(), ['diagnostic'], 'x0x', 1)
        c['assert_no_leak'](custody)
        result['custody'] = custody
        binding(custody)
        expected_errors = [] if result.get('runtime_exit') == 0 else [{'stage': 'isolation', 'code': 'EXIT_NONZERO', 'where': ''}]
        require(custody['errors'] == expected_errors)
        build = custody['build_custody'][0]
        require(build['source_head'] == result['source']['head'] and build['source_tree'] == result['source']['tree'])
        require(build['lock_sha256'] == LOCK)
        require(build['inputs'][build['target_binaries'][0]] == result['source']['binary_sha256'])
        # R3 admits nonzero runtime exits as valid failed-run evidence; still
        # explicitly reconcile command, supervisor and wrapper exits here.
        run = custody['isolation_runs'][0]
        require(run['exit'] == result['runtime_exit'] == run['supervisor']['child_exit'])
        require(run['supervisor']['reason'] is None and run['supervisor']['child_reaped'] is True)
    except Exception:
        errors.append('CUSTODY_OR_BINDING')
    result['errors'] = errors
    result['evidence_valid'] = not errors
    result['diagnostic_test_passed'] = not errors and result.get('runtime_exit') == 0
    c['assert_no_leak'](result)
    descriptor = os.open(output / 'diagnostic.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream: json.dump(result, stream, sort_keys=True); stream.write('\n')
    c['mark_upload_eligible']()
    print(json.dumps({'evidence_valid': not errors, 'errors': errors, 'general_acceptance': False}))
    return 0 if not errors else 1


def main():
    mode, path, *extra = sys.argv[1:]
    root = Path(path).resolve(strict=True)
    require(root.is_dir())
    if mode == 'prep': prep(root); return 0
    if mode == 'build': build_record(root); return 0
    if mode == 'isolated': return isolated(root)
    if mode == 'runtime': return runtime(root)
    if mode == 'collect' and len(extra) == 1: return collect(root, Path(extra[0]))
    raise ValueError('invalid mode')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # Raw exception text may include paths or hostile test content.
        print('lifecycle574: operation rejected', file=sys.stderr)
        raise SystemExit(125)
