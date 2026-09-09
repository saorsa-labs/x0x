#!/usr/bin/env python3
"""One #287 matched comparator; private evidence only, no host runtime fallback."""
import argparse
from contextlib import contextmanager
import math
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import tarfile
import time

PARENT = '1c23fdaef443b17e0a9f55d7f34f45d1393d227e'
ORIGINAL_PARENT = 'd18172e82b28eff753a8d88dc0a12df47141ed96'
PARENT_TREE = '58bd36d3b81ad07051fe6e08b3f81ff95a3a1183'
OBSERVABILITY_PATHS = frozenset({'.github/workflows/issue287-matched-reader.yml',
    'scripts/ci/issue287-matched-reader-evidence.py',
    'scripts/ci/test_issue287_matched_reader_evidence.py'})
BRANCH = 'refs/heads/codex/287-isolated-evidence'
LOCK = '83fc5316716b6240ffa470daa77d3e6a7ea9ed09baf6631320d472514e38b32f'
RECIPIENT_SHA = '2265bb7ac6df437ea1c6c69f7f856f8603989f4d4b64415c1a3a17c333d570c8'
SELECTOR = 'ws_backpressure_matched_reader_acceptance'
# Root's retained actual 0.9.143 integration producer proves package::target
# framing and same-build x0xd metadata. Real build bytes still pass the interlock.
# Neither environment nor CLI can override this exact source-controlled identity.
PRODUCER_BINARY_ID = 'x0x::ws_integration'
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
CAPTURE_TOTAL = 1024 * 1024 * 1024
JSON_LIMIT = 8 * 1024 * 1024
MAX_MEMBERS = 10000
CANCELLED = False
PUBLICATION_ACTIVE = False
RECEIPT_LIMIT = 64 * 1024
# Only fixed evidence-retention tasks may start/finish after execution cancellation.
EVIDENCE_TASKS = frozenset({'collector', 'collect-worker', 'archive-worker', 'seal', 'seal-metadata-worker'})

class PublicationCancelled(Exception):
    """One-shot local unwind during parent receipt publication only."""


class Rejected(Exception):
    """Only constant codes may cross the private/public boundary."""


def require(ok, code):
    if not ok:
        raise Rejected(code)


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write_json(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')


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


def terminate_owned(child, deadline):
    """Reserve TERM grace inside the caller's deadline, then reap our child only."""
    if child.poll() is not None:
        child.wait()
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=max(0, min(20, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # No false reap claim: the OS may delay final wait even after SIGKILL.
        # The workflow limit is a further envelope, not proof of kernel progress.
        child.wait()


def run_private(argv, cwd, env, directory, name, timeout, deadline=None):
    """Cancel execution, but retain bounded owned evidence without clearing fact."""
    cleanup = name in EVIDENCE_TASKS
    require(not CANCELLED or cleanup, 'EXECUTION_CANCELLED')
    started = time.monotonic()
    deadline = started + timeout + 20 if deadline is None else deadline
    with (directory / (name + '.stdout')).open('xb') as out, (directory / (name + '.stderr')).open('xb') as err:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        reason = None
        try:
            while child.poll() is None:
                if (CANCELLED and not cleanup) or time.monotonic() - started >= timeout:
                    reason = 'signal' if CANCELLED and not cleanup else 'deadline'
                    terminate_owned(child, deadline)
                    break
                time.sleep(0.1)
        finally:
            terminate_owned(child, deadline)
    result = {'argv': argv, 'cwd': str(cwd), 'exit': child.returncode, 'reason': reason,
              'outer_pid': child.pid, 'outer_reaped': True, 'elapsed_seconds': time.monotonic() - started,
              'stdout_sha256': digest(directory / (name + '.stdout')),
              'stderr_sha256': digest(directory / (name + '.stderr'))}
    write_json(directory / (name + '.json'), result)
    return result


COMMIT_LIMIT = 64 * 1024
COMMIT_HEADER_LIMIT = 8 * 1024


def verify_parent_header(raw):
    """Read the real commit header, including at a depth-two shallow boundary."""
    require(type(raw) is bytes and len(raw) <= COMMIT_LIMIT, 'PARENT_OBJECT_BOUND')
    header, separator, _message = raw.partition(b'\n\n')
    require(bool(separator) and len(header) <= COMMIT_HEADER_LIMIT, 'PARENT_HEADER_BOUND')
    parents = []
    for line in header.split(b'\n'):
        if line.startswith(b'parent'):
            require(re.fullmatch(rb'parent [0-9a-f]{40}', line) is not None, 'PARENT_HEADER')
            parents.append(line[7:])
    require(parents == [ORIGINAL_PARENT.encode('ascii')], 'PARENT_ANCESTRY')


def read_parent_commit(workspace, deadline=None):
    """Fixed Git object only; bounded pipe reads and owned cleanup, no fetch."""
    end = time.monotonic() + 30
    if deadline is not None:
        end = min(end, deadline)
    # Keep the existing twenty-second TERM allowance inside both bounds.
    work_end = end - 20
    require(time.monotonic() < work_end, 'PHASE_DEADLINE')
    child = subprocess.Popen(['git', 'cat-file', 'commit', PARENT], cwd=workspace,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    data = bytearray()
    try:
        os.set_blocking(child.stdout.fileno(), False)
        while True:
            left = work_end - time.monotonic()
            require(left > 0, 'PARENT_READ_DEADLINE')
            ready, _, _ = select.select([child.stdout], [], [], left)
            require(bool(ready), 'PARENT_READ_DEADLINE')
            try:
                chunk = os.read(child.stdout.fileno(), min(4096, COMMIT_LIMIT + 1 - len(data)))
            except BlockingIOError:
                continue
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= COMMIT_LIMIT, 'PARENT_OBJECT_BOUND')
        code = child.wait(timeout=max(0, work_end - time.monotonic()))
        require(code == 0, 'PARENT_READ_FAILED')
        return bytes(data)
    finally:
        try:
            child.stdout.close()
        finally:
            # Final OS reap may outlast a deadline; no false hard-bound claim.
            terminate_owned(child, end)


def source_map(workspace, expected_sha, deadline=None):
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=workspace, stderr=subprocess.DEVNULL,
                                       timeout=remaining(deadline, 30) if deadline is not None else 30)
    require(git('rev-parse', 'HEAD').decode().strip() == expected_sha, 'SOURCE_HEAD')
    require(git('show', '-s', '--format=%P', 'HEAD').decode().split() == [PARENT], 'SOURCE_PARENT')
    require(not git('status', '--porcelain').strip(), 'SOURCE_DIRTY')
    require(git('rev-parse', PARENT + '^{tree}').decode().strip() == PARENT_TREE, 'PARENT_TREE')
    require(set(git('diff', '--name-only', PARENT, 'HEAD').decode().splitlines()) == OBSERVABILITY_PATHS, 'CONTRIBUTION_SCOPE')
    verify_parent_header(read_parent_commit(workspace, deadline))
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


def interrupted(_number, _frame):
    global CANCELLED, PUBLICATION_ACTIVE
    CANCELLED = True
    if PUBLICATION_ACTIVE:
        # Disarm before raising: subsequent signals can set the fact but cannot
        # repeatedly interrupt the single bounded negative-publication attempt.
        PUBLICATION_ACTIVE = False
        raise PublicationCancelled()


BUILD_OBSERVATION_LIMIT = 32 * 1024
BUILD_NUMBER_LIMIT = (1 << 53) - 1
BUILD_CODES = frozenset({'PATH_ESCAPE', 'PATH_SYMLINK', 'PATH_KIND_OR_LINK',
    'FILE_OWNER_OR_SIZE', 'FILE_RACE', 'FILE_CHANGED', 'JSON_DUPLICATE', 'JSON_NUMBER',
    'TARGET_ROOT', 'BUILD_ROOT', 'PACKAGE_ROOT', 'BINARY_COUNT', 'BINARY_IDENTITY',
    'DAEMON_PACKAGE', 'DAEMON_METADATA', 'DAEMON_PATH', 'DAEMON_SYMLINK',
    'DAEMON_ALTERNATE', 'BUILD_SOURCE', 'BUILD_INPUT_SET', 'BUILD_INPUT_HASH', 'BUILD_DRIFT'})
BUILD_STAGES = frozenset({'not_started', 'metadata_read', 'metadata_json', 'cargo_read',
    'cargo_json', 'target', 'workspace', 'packages', 'binary_map', 'binary_count',
    'binary_entry', 'binary_identity', 'test_path', 'non_test_map', 'inputs',
    'non_test_iteration', 'non_test_path', 'input_insert', 'daemon_name', 'daemon_package',
    'daemon_append', 'daemon_count', 'daemon_select', 'daemon_path', 'fallback_paths',
    'daemon_digest', 'fallback_symlink', 'fallback_exists', 'fallback_resolve',
    'fallback_digest', 'custody_read', 'custody_json', 'custody_source', 'input_set',
    'input_hash', 'test_digest', 'return_value', 'regular_resolve_root',
    'regular_containment', 'regular_symlink', 'regular_stat', 'regular_kind_link',
    'regular_owner_size', 'read_before_stat', 'read_open', 'read_fdopen', 'read_open_stat',
    'read_identity', 'read_bytes', 'read_after_stat', 'read_close', 'read_stability'})
BUILD_FACTS = ('absolute', 'contained', 'ancestor_symlink', 'stat_kind', 'nlink',
    'size', 'limit', 'owner_matches', 'before_open_equal', 'after_read_equal',
    'read_within_limit', 'symlink', 'exists', 'resolved_equal', 'digest_equal')
BUILD_ROLES = frozenset({'unknown', 'test_binary', 'non_test_binary', 'daemon',
    'cargo_metadata', 'binary_metadata', 'custody', 'lock', 'fallback', 'input'})


def build_error(error):
    if isinstance(error, Rejected):
        code = error.args[0] if error.args and type(error.args[0]) is str else None
        return {'category': 'rejected', 'code': code if code in BUILD_CODES else 'UNRECOGNIZED_REJECTION'}
    if isinstance(error, OSError):
        names = {errno.ENOENT: 'ENOENT', errno.EACCES: 'EACCES', errno.EPERM: 'EPERM',
                 errno.ELOOP: 'ELOOP', errno.ENOTDIR: 'ENOTDIR', errno.EIO: 'EIO',
                 errno.ENOSPC: 'ENOSPC'}
        return {'category': 'filesystem', 'errno': names.get(error.errno, 'OTHER')}
    for kind, name in ((ValueError, 'json_or_value'), (KeyError, 'missing_key'),
                       (TypeError, 'wrong_type'), (subprocess.SubprocessError, 'subprocess')):
        if isinstance(error, kind):
            return {'category': name}
    return {'category': 'other'}


def observe(observer, method, *args):
    """Telemetry errors cannot change a checked operation or swallow cancellation."""
    if observer is not None:
        try:
            getattr(observer, method)(*args)
        except PublicationCancelled:
            raise
        except Exception:
            observer.unavailable = True


def operation(observer, stage, action):
    observe(observer, 'stage', stage)
    return action()


def fact(observer, name, value):
    observe(observer, 'fact', name, value)
    return value


class BuildObservation:
    """Two local invocation records; no filesystem access or global registration."""
    def __init__(self, origin):
        self.origin = origin
        self.unavailable = False
        self.state = 'not_started'
        self.current_stage = 'not_started'
        self.started_ms = self.finished_ms = None
        self.error = None
        self.facts_truncated = False
        self.current = self.new_role('unknown', 0)
        self.roles = {}

    @staticmethod
    def number(value):
        return value if type(value) is int and 0 <= value <= BUILD_NUMBER_LIMIT else 'overflow'

    @staticmethod
    def new_role(role, ordinal):
        return {'role': role, 'ordinal': ordinal, 'facts': dict.fromkeys(BUILD_FACTS, 'unobserved')}

    def stamp(self):
        elapsed = time.monotonic() - self.origin
        if not 0 <= elapsed <= BUILD_NUMBER_LIMIT / 1000:
            self.unavailable = True
            return 'unobserved'
        return int(elapsed * 1000)

    def start(self):
        if self.state == 'not_started':
            self.state, self.started_ms = 'in_progress', self.stamp()

    def stage(self, stage):
        if self.state == 'in_progress':
            self.current_stage = stage if stage in BUILD_STAGES else 'not_started'

    def role(self, role, ordinal=0):
        if self.state != 'in_progress':
            return
        role = role if role in BUILD_ROLES else 'unknown'
        ordinal = self.number(ordinal)
        key = (role, ordinal)
        # Fixed roles plus16 metadata slots. Overflow keeps the currently checked
        # operand, but does not retain an unbounded history or stop verification.
        metadata_role = role in ('non_test_binary', 'input')
        bounded = not metadata_role or (type(ordinal) is int and ordinal < 16)
        if metadata_role and key not in self.roles:
            bounded = bounded and sum(k[0] in ('non_test_binary', 'input') for k in self.roles) < 16
        if role == 'fallback':
            bounded = type(ordinal) is int and ordinal < 4
        if not bounded:
            self.facts_truncated = True
            self.current = self.new_role(role, ordinal)
        else:
            self.current = self.roles.setdefault(key, self.new_role(role, ordinal))

    def fact(self, name, value):
        if self.state != 'in_progress' or name not in BUILD_FACTS:
            return
        if name in ('nlink', 'size', 'limit'):
            value = self.number(value)
        elif name == 'stat_kind':
            value = value if value in ('regular', 'directory', 'symlink', 'other') else 'unobserved'
        elif type(value) is not bool:
            value = 'unobserved'
        self.current['facts'][name] = value

    def stat(self, info, limit):
        kind = {stat.S_IFREG: 'regular', stat.S_IFDIR: 'directory', stat.S_IFLNK: 'symlink'}.get(stat.S_IFMT(info.st_mode), 'other')
        for key, value in (('stat_kind', kind), ('nlink', info.st_nlink), ('size', info.st_size), ('limit', limit)):
            self.fact(key, value)

    def finish(self, error=None):
        if self.state == 'in_progress':
            self.error = build_error(error) if error is not None else None
            self.state = 'rejected' if error is not None else 'verified'
            self.finished_ms = self.stamp()

    def value(self, compact=False):
        return {'state': self.state, 'stage': self.current_stage, 'started_ms': self.started_ms,
                'finished_ms': self.finished_ms, 'current': self.current, 'error': self.error,
                'unavailable': self.unavailable, 'facts_truncated': self.facts_truncated or compact,
                'observations': [] if compact else list(self.roles.values())}


class BuildVerification:
    def __init__(self, source, origin):
        self.source = {key: source[key] for key in ('head', 'tree')}
        self.before = BuildObservation(origin)
        self.after = BuildObservation(origin)
        self.write = {'state': 'not_started', 'error': None}
        self.equality = {'state': 'not_started', 'error': None}

    def value(self):
        def shape(compact):
            return {'schema': 'x0x.issue287-build-verification/1', 'source': self.source,
                    'clock': 'milliseconds_since_driver_entry', 'before_runtime': self.before.value(compact),
                    'after_runtime': self.after.value(compact), 'verified_receipt_write': self.write,
                    'after_runtime_equality': self.equality}
        try:
            value = shape(False)
            if len(json.dumps(value, sort_keys=True).encode()) > BUILD_OBSERVATION_LIMIT:
                value = shape(True)
            if len(json.dumps(value, sort_keys=True).encode()) > BUILD_OBSERVATION_LIMIT:
                raise ValueError('bounded observer projection unavailable')
            return value
        except PublicationCancelled:
            raise
        except Exception:
            # Internal values below are fixed enums/bounded numbers, not exception
            # text. Preserve the first classified failure even if projection fails.
            def unavailable(o):
                return {'state': o.state, 'stage': o.current_stage, 'error': o.error,
                        'current': {'role': o.current['role'], 'ordinal': o.current['ordinal']},
                        'unavailable': True, 'facts_truncated': True}
            return {'schema': 'x0x.issue287-build-verification/1', 'source': self.source,
                    'clock': 'milliseconds_since_driver_entry', 'before_runtime': unavailable(self.before),
                    'after_runtime': unavailable(self.after), 'verified_receipt_write': self.write,
                    'after_runtime_equality': self.equality}


def verification_action(slot, action):
    """Write/equality errors remain separate from a successful verifier."""
    slot['state'] = 'started'
    try:
        value = action()
    except PublicationCancelled:
        raise
    except Exception as error:
        slot.update(state='rejected', error=build_error(error))
        raise
    slot['state'] = 'completed'
    return value


def regular(path, root, limit=MAX_FILE, observer=None):
    path, root = operation(observer, 'regular_resolve_root', lambda: (Path(path), Path(root).resolve(strict=True)))
    observe(observer, 'stage', 'regular_containment')
    require(fact(observer, 'absolute', path.is_absolute()) and
            fact(observer, 'contained', path.resolve(strict=True).is_relative_to(root)), 'PATH_ESCAPE')
    for part in (path, *path.parents):
        observe(observer, 'stage', 'regular_symlink')
        require(not fact(observer, 'ancestor_symlink', part.is_symlink()), 'PATH_SYMLINK')
        if part == root:
            break
    info = operation(observer, 'regular_stat', path.stat)
    observe(observer, 'stat', info, limit)
    observe(observer, 'stage', 'regular_kind_link')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'PATH_KIND_OR_LINK')
    observe(observer, 'stage', 'regular_owner_size')
    require(fact(observer, 'owner_matches', info.st_uid == os.getuid()) and info.st_size <= limit, 'FILE_OWNER_OR_SIZE')
    return path


def read_owned(path, root, limit=MAX_FILE, observer=None):
    path = regular(path, root, limit, observer)
    before = operation(observer, 'read_before_stat', path.stat)
    fd = operation(observer, 'read_open', lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW))
    observe(observer, 'stage', 'read_fdopen')
    with os.fdopen(fd, 'rb') as f:
        opened = operation(observer, 'read_open_stat', lambda: os.fstat(f.fileno()))
        observe(observer, 'stage', 'read_identity')
        require(fact(observer, 'before_open_equal', (before.st_dev, before.st_ino, before.st_size) ==
                (opened.st_dev, opened.st_ino, opened.st_size)), 'FILE_RACE')
        data = operation(observer, 'read_bytes', lambda: f.read(limit + 1))
        after = operation(observer, 'read_after_stat', lambda: os.fstat(f.fileno()))
        observe(observer, 'stage', 'read_close')
    observe(observer, 'stage', 'read_stability')
    require(fact(observer, 'read_within_limit', len(data) <= limit) and
            fact(observer, 'after_read_equal', (opened.st_size, opened.st_mtime_ns) ==
            (after.st_size, after.st_mtime_ns)), 'FILE_CHANGED')
    return data


def object_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'JSON_DUPLICATE')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'JSON_NUMBER'))


def runtime_arguments():
    return ['--profile', 'default', '--run-ignored', 'ignored-only', '--retries', '0',
            '--fail-fast', '--no-tests', 'fail', '--success-output', 'immediate',
            '--failure-output', 'immediate', '-E',
            'package(=x0x) & binary(=ws_integration) & kind(=test) & test(=' + SELECTOR + ')']


def producer_admission():
    require(PRODUCER_BINARY_ID == 'x0x::ws_integration', 'PRODUCER_CONTRACT_UNVERIFIED')


def validate_build(workspace, scratch, source, observer=None):
    observe(observer, 'start')
    try:
        value = validate_build_inputs(workspace, scratch, source, observer)
    except PublicationCancelled:
        raise
    except Exception as error:
        # Observe then re-raise the same exception; existing caller catch sets
        # still determine propagation and the actual nonpass verdict.
        observe(observer, 'finish', error)
        raise
    observe(observer, 'finish')
    return value


def build_description(workspace, scratch, observer=None):
    observe(observer, 'role', 'binary_metadata')
    data = operation(observer, 'metadata_read', lambda: read_owned(scratch / 'binaries.json', scratch, JSON_LIMIT, observer))
    meta = operation(observer, 'metadata_json', lambda: object_json(data))
    del data
    observe(observer, 'role', 'cargo_metadata')
    data = operation(observer, 'cargo_read', lambda: read_owned(scratch / 'cargo.json', scratch, JSON_LIMIT, observer))
    cargo = operation(observer, 'cargo_json', lambda: object_json(data))
    del data
    observe(observer, 'role', 'binary_metadata')
    observe(observer, 'stage', 'target')
    target = workspace / 'target'
    require(Path(meta['rust-build-meta']['target-directory']) == target, 'TARGET_ROOT')
    observe(observer, 'role', 'cargo_metadata')
    observe(observer, 'stage', 'workspace')
    require(Path(cargo['workspace_root']) == workspace and Path(cargo['target_directory']) == target, 'BUILD_ROOT')
    observe(observer, 'stage', 'packages')
    packages = [p for p in cargo['packages'] if p['name'] == 'x0x' and Path(p['manifest_path']) == workspace / 'Cargo.toml']
    require(len(packages) == 1, 'PACKAGE_ROOT')
    observe(observer, 'role', 'binary_metadata')
    observe(observer, 'stage', 'binary_map')
    binaries = meta['rust-binaries']
    observe(observer, 'stage', 'binary_count')
    require(len(binaries) == 1, 'BINARY_COUNT')
    observe(observer, 'stage', 'binary_entry')
    binary_id, binary = next(iter(binaries.items()))
    observe(observer, 'stage', 'binary_identity')
    require(binary_id == PRODUCER_BINARY_ID and binary['binary-id'] == PRODUCER_BINARY_ID and binary['binary-name'] == 'ws_integration'
            and binary['kind'] == 'test' and binary['package-id'] == packages[0]['id'], 'BINARY_IDENTITY')
    return meta, cargo, packages, binary_id, binary, target


def validate_build_inputs(workspace, scratch, source, observer):
    meta, _cargo, packages, binary_id, binary, target = build_description(workspace, scratch, observer)
    observe(observer, 'role', 'test_binary')
    test = operation(observer, 'test_path', lambda: regular(Path(binary['binary-path']), target, MAX_TOTAL, observer))
    observe(observer, 'role', 'binary_metadata')
    observe(observer, 'stage', 'non_test_map')
    non_test = meta['rust-build-meta']['non-test-binaries']
    observe(observer, 'stage', 'inputs')
    inputs = {str(test), str(workspace / 'Cargo.lock'), str(scratch / 'cargo.json'), str(scratch / 'binaries.json')}
    daemons = []
    # Bounded private role association only; actual input set/iteration unchanged.
    roles = {str(test): ('test_binary', 0), str(workspace / 'Cargo.lock'): ('lock', 0),
             str(scratch / 'cargo.json'): ('cargo_metadata', 0), str(scratch / 'binaries.json'): ('binary_metadata', 0)} if observer is not None else {}
    ordinal = 0
    observe(observer, 'stage', 'non_test_iteration')
    for package, values in non_test.items():
        for row in values:
            observe(observer, 'role', 'non_test_binary', ordinal)
            path = operation(observer, 'non_test_path', lambda: regular(target / row['path'], target, MAX_TOTAL, observer))
            observe(observer, 'stage', 'input_insert')
            inputs.add(str(path))
            if observer is not None and ordinal < 16:
                roles.setdefault(str(path), ('non_test_binary', ordinal))
            observe(observer, 'stage', 'daemon_name')
            if row.get('name') == 'x0xd':
                observe(observer, 'stage', 'daemon_package')
                require(package == packages[0]['id'] and row['kind'] == 'bin-exe', 'DAEMON_PACKAGE')
                observe(observer, 'stage', 'daemon_append')
                daemons.append(path)
            ordinal = min(ordinal + 1, BUILD_NUMBER_LIMIT)
            observe(observer, 'role', 'binary_metadata')
            observe(observer, 'stage', 'non_test_iteration')
    observe(observer, 'role', 'binary_metadata')
    observe(observer, 'stage', 'daemon_count')
    require(len(daemons) == 1, 'DAEMON_METADATA')
    observe(observer, 'stage', 'daemon_select')
    daemon = daemons[0]
    observe(observer, 'role', 'daemon')
    # Cargo's integration-test CARGO_BIN_EXE_x0xd must denote this executable.
    # Fresh target + complete metadata disallows an inherited release fallback.
    observe(observer, 'stage', 'daemon_path')
    require(daemon == target / 'debug/x0xd', 'DAEMON_PATH')
    observe(observer, 'stage', 'fallback_paths')
    candidates = [workspace / 'target/release/x0xd', workspace / '../../target/release/x0xd',
                  workspace / 'target/debug/x0xd', workspace / '../../target/debug/x0xd']
    daemon_sha = operation(observer, 'daemon_digest', lambda: digest(daemon))
    for ordinal, candidate in enumerate(candidates):
        observe(observer, 'role', 'fallback', ordinal)
        observe(observer, 'stage', 'fallback_symlink')
        require(not fact(observer, 'symlink', candidate.is_symlink()), 'DAEMON_SYMLINK')
        observe(observer, 'stage', 'fallback_exists')
        if fact(observer, 'exists', candidate.exists()):
            observe(observer, 'stage', 'fallback_resolve')
            require(fact(observer, 'resolved_equal', candidate.resolve() == daemon) and
                    fact(observer, 'digest_equal', operation(observer, 'fallback_digest', lambda: digest(candidate)) == daemon_sha), 'DAEMON_ALTERNATE')
    observe(observer, 'role', 'custody')
    data = operation(observer, 'custody_read', lambda: read_owned(scratch / 'custody.json', scratch, JSON_LIMIT, observer))
    custody = operation(observer, 'custody_json', lambda: object_json(data))
    del data
    observe(observer, 'stage', 'custody_source')
    require(custody['source'] == [source['head'], source['tree']], 'BUILD_SOURCE')
    observe(observer, 'stage', 'input_set')
    require(set(custody['files']) == inputs, 'BUILD_INPUT_SET')
    def checked_hash(p, sha, ordinal):
        observe(observer, 'role', *roles.get(p, ('input', min(ordinal, BUILD_NUMBER_LIMIT))))
        return fact(observer, 'digest_equal', operation(observer, 'input_hash', lambda: digest(Path(p))) == sha)
    observe(observer, 'stage', 'input_hash')
    require(all(checked_hash(p, sha, i) for i, (p, sha) in enumerate(custody['files'].items())), 'BUILD_INPUT_HASH')
    observe(observer, 'role', 'test_binary')
    observe(observer, 'stage', 'return_value')
    return {'scratch': scratch.name, 'binary_id': binary_id,
            'binary_sha256': operation(observer, 'test_digest', lambda: digest(test)),
            'daemon_path': str(daemon), 'daemon_sha256': daemon_sha, 'input_hashes': custody['files']}


# These are detachment limits only. Archive/capture MAX_TOTAL stays unchanged.
DETACH_NAMES = ('gui-coverage', 'x0x', 'x0x-keygen', 'x0x-user-keygen', 'x0xd', 'x0xd-forge-injector')
DETACH_FILE_LIMIT = 2 * 1024 * 1024 * 1024
DETACH_TOTAL_LIMIT = 6 * DETACH_FILE_LIMIT
DETACH_RECEIPT_LIMIT = 32 * 1024
DETACH_CHUNK = 1024 * 1024
DETACH_CODES = frozenset({'DETACH_DEADLINE', 'DETACH_FILE', 'DETACH_MODE', 'DETACH_DIRECTORY',
    'DETACH_PATH', 'DETACH_DIRECTORY_CHANGED', 'DETACH_SHORT_READ', 'DETACH_GROWTH',
    'DETACH_INPUT_CHANGED', 'DETACH_SET', 'DETACH_CAPACITY', 'DETACH_METADATA_CHANGED',
    'DETACH_CUSTODY', 'DETACH_PACKAGE', 'DETACH_KIND', 'DETACH_ACTION', 'DETACH_SHORT_WRITE',
    'DETACH_COPY_CHANGED', 'DETACH_DESTINATION', 'DETACH_TEMP_CHANGED', 'DETACH_INSTALL_CHANGED',
    'DETACH_RECEIPT_BOUND', 'DETACH_PROGRESS_CHANGED', 'DETACH_PROGRESS_EXISTS', 'DETACH_RESPONSE', 'DETACH_REQUEST'})


def detach_budget(deadline):
    require(type(deadline) in (float, int) and math.isfinite(deadline), 'DETACH_DEADLINE')
    require(not CANCELLED and time.monotonic() < deadline, 'DETACH_DEADLINE')


def detach_state(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def detach_file(info, single=False, executable=True):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            0 <= info.st_size <= DETACH_FILE_LIMIT and info.st_nlink >= 1 and
            (not single or info.st_nlink == 1), 'DETACH_FILE')
    mode = stat.S_IMODE(info.st_mode)
    require(not mode & 0o7000 and (not executable or bool(mode & 0o111)), 'DETACH_MODE')


def detach_directory(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            not stat.S_IMODE(info.st_mode) & 0o022, 'DETACH_DIRECTORY')


@contextmanager
def detach_parent(target, relative):
    """Open every component without following links; hold owned target/parent FDs."""
    require(target.is_absolute() and '..' not in target.parts and
            not relative.is_absolute() and relative.parts and
            all(x not in ('.', '..', '') for x in relative.parts), 'DETACH_PATH')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    anchor = os.open('/', flags)
    parent = None
    try:
        for part in target.parts[1:]:
            child = os.open(part, flags, dir_fd=anchor)
            os.close(anchor); anchor = child
        detach_directory(anchor)
        parent = os.dup(anchor)
        for part in relative.parts[:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent); parent = child
            detach_directory(parent)
        yield anchor, parent, relative.name
    finally:
        if parent is not None:
            os.close(parent)
        os.close(anchor)


def detach_attached(target, relative, anchor, parent):
    # Reopen the actual named directories. This is observed drift detection under
    # exclusive ownership, not a CAS against an arbitrary concurrent same-UID writer.
    with detach_parent(target, relative) as (current_anchor, current_parent, _name):
        require(all((os.fstat(a).st_dev, os.fstat(a).st_ino) ==
                    (os.fstat(b).st_dev, os.fstat(b).st_ino)
                    for a, b in ((anchor, current_anchor), (parent, current_parent))), 'DETACH_DIRECTORY_CHANGED')


def detach_hash_fd(fd, size, deadline):
    detach_budget(deadline)
    os.lseek(fd, 0, os.SEEK_SET)
    hashed = hashlib.sha256()
    remaining_bytes = size
    while remaining_bytes:
        detach_budget(deadline)
        chunk = os.read(fd, min(DETACH_CHUNK, remaining_bytes))
        require(bool(chunk), 'DETACH_SHORT_READ')
        hashed.update(chunk)
        remaining_bytes -= len(chunk)
    require(os.read(fd, 1) == b'', 'DETACH_GROWTH')
    detach_budget(deadline)
    return hashed.hexdigest()


def inspect_detach_input(target, relative, expected, deadline, single=False, executable=True, record=None):
    detach_budget(deadline)
    with detach_parent(target, relative) as (anchor, parent, name):
        if record is not None:
            record['stage'] = 'stat'
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if record is not None:
            record.update(source_state=detach_state(before), size=before.st_size, nlink=before.st_nlink,
                          mode=stat.S_IMODE(before.st_mode), stage='kind_owner_mode')
        detach_file(before, single, executable)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            require(detach_state(opened) == detach_state(before), 'DETACH_INPUT_CHANGED')
            if record is not None:
                record['stage'] = 'input_hash'
            observed_sha = detach_hash_fd(fd, opened.st_size, deadline)
            if record is not None:
                record['source_sha256'] = observed_sha
            require(observed_sha == expected, 'BUILD_INPUT_HASH')
            require(detach_state(os.fstat(fd)) == detach_state(opened) and
                    detach_state(os.stat(name, dir_fd=parent, follow_symlinks=False)) == detach_state(opened),
                    'DETACH_INPUT_CHANGED')
            detach_attached(target, relative, anchor, parent)
            return detach_state(opened)
        finally:
            os.close(fd)


def detach_capacity(rows):
    require(len(rows) == 6 and {r['name'] for r in rows} == set(DETACH_NAMES) and
            len({r['path'] for r in rows}) == 6, 'DETACH_SET')
    total = 0
    for row in rows:
        require(type(row['size']) is int and 0 <= row['size'] <= DETACH_FILE_LIMIT and
                type(row['nlink']) is int and row['nlink'] >= 1, 'DETACH_CAPACITY')
        if row['nlink'] > 1:
            total += row['size']
    require(total <= DETACH_TOTAL_LIMIT, 'DETACH_CAPACITY')
    return total


def plan_detachment(workspace, scratch, source, deadline, on_plan=None):
    """Structural build binding shared with final validation; never runtime admission."""
    detach_budget(deadline)
    meta, cargo, packages, _binary_id, binary, target = build_description(workspace, scratch)
    metadata = {name: read_owned(scratch / name, scratch, JSON_LIMIT)
                for name in ('binaries.json', 'cargo.json', 'custody.json')}
    # The structural reader and retained request must refer to the same metadata.
    require(object_json(metadata['binaries.json']) == meta and object_json(metadata['cargo.json']) == cargo,
            'DETACH_METADATA_CHANGED')
    custody = object_json(metadata['custody.json'])
    require(set(custody) == {'source', 'files'} and custody['source'] == [source['head'], source['tree']], 'BUILD_SOURCE')
    require(isinstance(custody['files'], dict) and all(type(p) is str and type(h) is str and
            re.fullmatch('[0-9a-f]{64}', h) for p, h in custody['files'].items()), 'DETACH_CUSTODY')
    test = regular(Path(binary['binary-path']), target, DETACH_FILE_LIMIT)
    require(test == test.resolve() and '..' not in test.parts, 'DETACH_PATH')
    values = meta['rust-build-meta']['non-test-binaries']
    require(set(values) == {packages[0]['id']} and type(values[packages[0]['id']]) is list, 'DETACH_PACKAGE')
    entries = values[packages[0]['id']]
    require(len(entries) == 6 and {r['name'] for r in entries} == set(DETACH_NAMES), 'DETACH_SET')
    paths = []
    for row in entries:
        require(row['kind'] == 'bin-exe' and type(row['path']) is str, 'DETACH_KIND')
        relative = Path(row['path'])
        require(not relative.is_absolute() and relative.parts and
                row['path'] == relative.as_posix() and '..' not in relative.parts, 'DETACH_PATH')
        path = target / relative
        require(path != test, 'DETACH_PATH')
        if row['name'] == 'x0xd':
            require(relative.as_posix() == 'debug/x0xd', 'DAEMON_PATH')
        paths.append(str(path))
    require(len(set(paths)) == 6, 'DETACH_SET')
    inputs = {str(test), str(workspace / 'Cargo.lock'), str(scratch / 'cargo.json'),
              str(scratch / 'binaries.json'), *paths}
    require(set(custody['files']) == inputs, 'BUILD_INPUT_SET')
    for name in ('binaries.json', 'cargo.json'):
        require(hashlib.sha256(metadata[name]).hexdigest() == custody['files'][str(scratch / name)], 'BUILD_INPUT_HASH')
    lock = read_owned(workspace / 'Cargo.lock', workspace, JSON_LIMIT)
    require(hashlib.sha256(lock).hexdigest() == LOCK == custody['files'][str(workspace / 'Cargo.lock')], 'LOCK_DRIFT')
    inspect_detach_input(target, test.relative_to(target), custody['files'][str(test)], deadline,
                         single=True, executable=False)
    rows = []
    for ordinal, (entry, path) in enumerate(zip(entries, paths)):
        rows.append({'ordinal': ordinal, 'name': entry['name'], 'path': path,
                     'expected_sha256': custody['files'][path], 'size': None, 'nlink': None,
                     'mode': None, 'source_state': None, 'source_sha256': None,
                     'action': None, 'stage': 'unobserved', 'copy_sha256': None,
                     'destination_sha256': None, 'installed_sha256': None, 'alias_identity': 'unknown'})
    if on_plan is not None:
        on_plan(rows)
    for row in rows:
        inspect_detach_input(target, Path(row['path']).relative_to(target), row['expected_sha256'], deadline,
                             record=row)
        row.update(action='detach' if row['nlink'] > 1 else 'untouched', stage='planned')
        if on_plan is not None:
            on_plan(rows)
    total = detach_capacity(rows)
    # Preserve byte identity of all preflight inputs; final validation is still owed.
    pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in metadata.items()}
    for name, expected in pins.items():
        require(hashlib.sha256(read_owned(scratch / name, scratch, JSON_LIMIT)).hexdigest() == expected,
                'DETACH_METADATA_CHANGED')
    return rows, total, pins


def detach_one(target, row, deadline):
    relative = Path(row['path']).relative_to(target)
    with detach_parent(target, relative) as (anchor, parent, name):
        original = os.stat(name, dir_fd=parent, follow_symlinks=False)
        detach_file(original)
        require(detach_state(original) == row['source_state'], 'DETACH_INPUT_CHANGED')
        source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        temporary = '.issue287-detach-' + str(row['ordinal']) + '.pending'
        destination_fd = None
        try:
            require(detach_state(os.fstat(source_fd)) == row['source_state'], 'DETACH_INPUT_CHANGED')
            detach_budget(deadline)
            if row['action'] == 'untouched':
                row['installed_sha256'] = detach_hash_fd(source_fd, row['size'], deadline)
                require(row['installed_sha256'] == row['expected_sha256'] and
                        detach_state(os.fstat(source_fd)) == row['source_state'] and
                        detach_state(os.stat(name, dir_fd=parent, follow_symlinks=False)) == row['source_state'],
                        'DETACH_INPUT_CHANGED')
                detach_attached(target, relative, anchor, parent)
                row['stage'] = 'verified_untouched'
                return
            require(row['action'] == 'detach' and original.st_nlink > 1, 'DETACH_ACTION')
            destination_fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=parent)
            row['stage'] = 'copying'
            hashed = hashlib.sha256()
            left = row['size']
            while left:
                detach_budget(deadline)
                chunk = os.read(source_fd, min(DETACH_CHUNK, left))
                require(bool(chunk), 'DETACH_SHORT_READ')
                hashed.update(chunk); left -= len(chunk)
                view = memoryview(chunk)
                while view:
                    detach_budget(deadline)
                    count = os.write(destination_fd, view)
                    require(count > 0, 'DETACH_SHORT_WRITE')
                    view = view[count:]
            require(os.read(source_fd, 1) == b'', 'DETACH_GROWTH')
            row['copy_sha256'] = hashed.hexdigest()
            require(row['copy_sha256'] == row['expected_sha256'] and
                    detach_state(os.fstat(source_fd)) == row['source_state'], 'DETACH_COPY_CHANGED')
            dest = os.fstat(destination_fd)
            detach_file(dest, single=True, executable=False)
            require(dest.st_size == row['size'], 'DETACH_DESTINATION')
            row['destination_sha256'] = detach_hash_fd(destination_fd, row['size'], deadline)
            require(row['destination_sha256'] == row['expected_sha256'] and
                    detach_state(os.fstat(destination_fd)) == detach_state(dest), 'DETACH_DESTINATION')
            os.fchmod(destination_fd, row['mode'])
            dest = os.fstat(destination_fd)
            detach_file(dest, single=True)
            require(detach_state(os.stat(temporary, dir_fd=parent, follow_symlinks=False)) == detach_state(dest),
                    'DETACH_TEMP_CHANGED')
            detach_attached(target, relative, anchor, parent)
            require(detach_state(os.stat(name, dir_fd=parent, follow_symlinks=False)) == row['source_state'] and
                    detach_state(os.fstat(source_fd)) == row['source_state'], 'DETACH_INPUT_CHANGED')
            detach_budget(deadline)
            row['stage'] = 'installing'
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            installed = os.stat(name, dir_fd=parent, follow_symlinks=False)
            detach_file(installed, single=True)
            require((installed.st_dev, installed.st_ino, stat.S_IMODE(installed.st_mode), installed.st_size) ==
                    (dest.st_dev, dest.st_ino, row['mode'], row['size']), 'DETACH_INSTALL_CHANGED')
            row['installed_sha256'] = detach_hash_fd(destination_fd, row['size'], deadline)
            require(row['installed_sha256'] == row['expected_sha256'] and
                    detach_state(os.fstat(destination_fd)) == detach_state(installed) and
                    detach_state(os.stat(name, dir_fd=parent, follow_symlinks=False)) == detach_state(installed),
                    'DETACH_INSTALL_CHANGED')
            detach_attached(target, relative, anchor, parent)
            row['stage'] = 'verified_detached'
        finally:
            try:
                if destination_fd is not None:
                    # Clean only this positively identified one-link temporary.
                    # A renamed, extra-linked or substituted entry is left untouched.
                    try:
                        info = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        held = os.fstat(destination_fd)
                        if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and \
                                (info.st_dev, info.st_ino) == (held.st_dev, held.st_ino):
                            os.unlink(temporary, dir_fd=parent)
            finally:
                if destination_fd is not None:
                    os.close(destination_fd)
                os.close(source_fd)


def detach_progress(private, value):
    path, temporary = private / 'detach-progress.json', private / 'detach-progress.pending.json'
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    require(len(raw) <= DETACH_RECEIPT_LIMIT and len(value['records']) <= 6, 'DETACH_RECEIPT_BOUND')
    if path.exists() or path.is_symlink():
        old = object_json(read_owned(path, private, DETACH_RECEIPT_LIMIT))
        require(old['schema'] == value['schema'] and old['request_sha256'] == value['request_sha256'], 'DETACH_PROGRESS_CHANGED')
    with temporary.open('xb') as stream:
        stream.write(raw)
    require(read_owned(temporary, private, DETACH_RECEIPT_LIMIT) == raw, 'DETACH_PROGRESS_CHANGED')
    os.replace(temporary, path)
    require(read_owned(path, private, DETACH_RECEIPT_LIMIT) == raw, 'DETACH_PROGRESS_CHANGED')


def execute_detachment(workspace, scratch, source, private, deadline, request_sha):
    report = {'schema': 'x0x.issue287-detachment/1', 'request_sha256': request_sha,
              'source': [source['head'], source['tree']], 'state': 'planning', 'planned_bytes': None,
              'metadata_sha256': None, 'records': [], 'error': None}
    require(not (private / 'detach-progress.json').exists() and
            not (private / 'detach-progress.json').is_symlink(), 'DETACH_PROGRESS_EXISTS')
    detach_progress(private, report)
    try:
        def planning(rows):
            report['records'] = rows
            detach_progress(private, report)
        rows, total, pins = plan_detachment(workspace, scratch, source, deadline, planning)
        report.update(records=rows, planned_bytes=total, metadata_sha256=pins, state='prepared')
        detach_progress(private, report)
        for row in rows:
            detach_budget(deadline)
            detach_one(workspace / 'target', row, deadline)
            detach_progress(private, report)
        for name, expected in pins.items():
            require(hashlib.sha256(read_owned(scratch / name, scratch, JSON_LIMIT)).hexdigest() == expected,
                    'DETACH_METADATA_CHANGED')
        report['state'] = 'completed'
        detach_progress(private, report)
    except (Rejected, OSError, ValueError, KeyError, TypeError) as error:
        report['state'] = 'failed'
        report['error'] = build_error(error)
        if isinstance(error, Rejected) and error.args and error.args[0] in DETACH_CODES:
            report['error'] = {'category': 'rejected', 'code': error.args[0]}
        # Preserve the actual stage and partial facts; never manufacture admission.
        detach_progress(private, report)
        raise
    return {'report_sha256': digest(private / 'detach-progress.json')}


def prepare_verified_build(workspace, scratch, source, private, env, deadline, observer=None):
    completed = run_worker('detach', {'workspace': str(workspace), 'scratch': str(scratch),
                           'source': source, 'deadline': deadline - 20}, private, env, deadline, 1200)
    require(set(completed) == {'schema', 'request_sha256', 'report_sha256'}, 'DETACH_RESPONSE')
    raw = read_owned(private / 'detach-progress.json', private, DETACH_RECEIPT_LIMIT)
    require(hashlib.sha256(raw).hexdigest() == completed['report_sha256'], 'DETACH_RESPONSE')
    report = object_json(raw)
    require(set(report) == {'schema', 'request_sha256', 'source', 'state', 'planned_bytes',
            'metadata_sha256', 'records', 'error'} and report['schema'] == 'x0x.issue287-detachment/1' and
            report['request_sha256'] == completed['request_sha256'] and report['source'] == [source['head'], source['tree']]
            and report['state'] == 'completed' and report['error'] is None, 'DETACH_RESPONSE')
    require(type(report['planned_bytes']) is int and report['planned_bytes'] == detach_capacity(report['records']), 'DETACH_RESPONSE')
    require(set(report['metadata_sha256']) == {'binaries.json', 'cargo.json', 'custody.json'}, 'DETACH_RESPONSE')
    for name, expected in report['metadata_sha256'].items():
        require(hashlib.sha256(read_owned(scratch / name, scratch, JSON_LIMIT)).hexdigest() == expected, 'DETACH_METADATA_CHANGED')
    # No exception to runtime admission: unchanged strict one-link/source/input/
    # daemon checks must all succeed, and namespace reuse still verifies again.
    detach_budget(deadline)
    reuse = validate_build(workspace, scratch, source, observer)
    meta = object_json(read_owned(scratch / 'binaries.json', scratch, JSON_LIMIT))
    entries = [entry for rows in meta['rust-build-meta']['non-test-binaries'].values() for entry in rows]
    require(len(entries) == 6, 'DETACH_RESPONSE')
    for ordinal, row in enumerate(report['records']):
        require(set(row) == {'ordinal', 'name', 'path', 'expected_sha256', 'size', 'nlink', 'mode', 'source_state',
                'action', 'stage', 'source_sha256', 'copy_sha256', 'destination_sha256', 'installed_sha256', 'alias_identity'}, 'DETACH_RESPONSE')
        require(type(row['ordinal']) is int and row['ordinal'] == ordinal and row['alias_identity'] == 'unknown' and
                row['name'] == entries[ordinal]['name'] and row['path'] == str(workspace / 'target' / entries[ordinal]['path']) and
                row['expected_sha256'] == reuse['input_hashes'][row['path']] == row['installed_sha256'] == row['source_sha256'], 'DETACH_RESPONSE')
        state = row['source_state']
        require(type(state) is list and len(state) == 8 and all(type(x) is int for x in state) and
                state[2] == os.getuid() and state[4:6] == [row['nlink'], row['size']] and
                stat.S_ISREG(state[3]) and row['mode'] == stat.S_IMODE(state[3]) and
                not row['mode'] & 0o7000 and bool(row['mode'] & 0o111), 'DETACH_RESPONSE')
        if row['nlink'] > 1:
            require(row['action'] == 'detach' and row['stage'] == 'verified_detached' and
                    row['copy_sha256'] == row['destination_sha256'] == row['expected_sha256'], 'DETACH_RESPONSE')
        else:
            require(row['action'] == 'untouched' and row['stage'] == 'verified_untouched' and
                    row['copy_sha256'] is None and row['destination_sha256'] is None, 'DETACH_RESPONSE')
    return reuse


KINDS = {'inputs', 'checkpoint', 'workload', 'counters', 'wave', 'children', 'wire_close', 'draining_final_counters'}


def collect_capture(workspace, destination, on_record=None):
    parent = workspace / 'target/issue287-captures'
    require(parent.is_dir() and not parent.is_symlink(), 'CAPTURE_MISSING')
    children = list(parent.iterdir())
    require(parent.stat().st_uid == os.getuid(), 'CAPTURE_OWNER')
    require(len(children) == 1 and re.fullmatch('[0-9a-f]{32}', children[0].name), 'CAPTURE_COUNT')
    root = children[0]
    require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == os.getuid()
            and stat.S_IMODE(root.stat().st_mode) == 0o700, 'CAPTURE_OWNER')
    destination.mkdir(mode=0o700)
    records, retained, incomplete = [], {}, []
    total = 0
    # Never traverse a data/identity directory or read its key/config files.
    allowed = [root / 'Cargo.lock']
    for path in root.iterdir():
        if path.name == 'Cargo.lock':
            continue
        if path.name in ('stalled', 'draining'):
            require(path.is_dir() and not path.is_symlink() and path.stat().st_uid == os.getuid(), 'ARM_DIRECTORY')
            for item in path.iterdir():
                if item.name in ('spawn.json', 'cleanup.json', 'daemon.stdout', 'daemon.stderr'):
                    allowed.append(item)
                else:
                    incomplete.append('UNEXPECTED_ARM_ENTRY')
            continue
        match = re.fullmatch(r'(\d{6})-([a-z_]+)\.json', path.name)
        require(match is not None and match[2] in KINDS, 'CAPTURE_MEMBER')
        allowed.append(path)
    require(len(allowed) <= MAX_MEMBERS, 'CAPTURE_MEMBERS')
    for path in sorted(allowed, key=lambda p: (p.name != 'Cargo.lock', str(p))):
        data = read_owned(path, root, JSON_LIMIT if path.suffix == '.json' else MAX_FILE)
        total += len(data)
        require(total <= CAPTURE_TOTAL, 'CAPTURE_BOUND')
        relative = str(path.relative_to(root))
        out = destination / relative
        out.parent.mkdir(mode=0o700, exist_ok=True)
        with out.open('xb') as f:
            f.write(data)
        retained[relative] = hashlib.sha256(data).hexdigest()
        if path.parent == root and path.suffix == '.json':
            value = object_json(data)
            require(set(value) == {'schema', 'nonce', 'kind', 'data'} and
                    value['schema'] == 'x0x.issue287-local/1' and value['nonce'] == root.name,
                    'CAPTURE_NONCE_SCHEMA')
            match = re.fullmatch(r'(\d{6})-([a-z_]+)\.json', path.name)
            require(value['kind'] == match[2], 'CAPTURE_KIND')
            records.append((int(match[1]), value))
            if on_record is not None:
                on_record(root.name, relative, value)
    records.sort()
    require([n for n, _ in records] == list(range(len(records))), 'CAPTURE_SEQUENCE')
    return root.name, [v for _, v in records], retained, incomplete



LATCH_NAMES = ('tests/ws_integration.rs', 'tests/harness/src/daemon.rs',
               'tests/harness/src/ws_backpressure_diagnostic.rs')


def fail_latch_value(private, request_sha, source, binary_sha, nonce, input_name, checkpoint_name):
    """Revalidate only fixed retained inputs and one explicit-Fail checkpoint."""
    require(re.fullmatch('[0-9a-f]{32}', nonce) is not None, 'FAIL_LATCH_NONCE')
    require(re.fullmatch(r'\d{6}-inputs\.json', input_name) is not None and
            re.fullmatch(r'\d{6}-checkpoint\.json', checkpoint_name) is not None, 'FAIL_LATCH_PATH')
    directory = private / 'capture'
    inputs_raw = read_owned(directory / input_name, private, JSON_LIMIT)
    checkpoint_raw = read_owned(directory / checkpoint_name, private, JSON_LIMIT)
    inputs, checkpoint = object_json(inputs_raw), object_json(checkpoint_raw)
    for record, kind in ((inputs, 'inputs'), (checkpoint, 'checkpoint')):
        require(set(record) == {'schema', 'nonce', 'kind', 'data'} and
                record['schema'] == 'x0x.issue287-local/1' and record['nonce'] == nonce and
                record['kind'] == kind, 'FAIL_LATCH_RECORD')
    expected_sources = {n: source['files'][n]['sha256'] for n in LATCH_NAMES}
    data = inputs['data']
    require(data['selector'] == SELECTOR and data['test_binary_sha256'] == binary_sha and
            re.fullmatch('[0-9a-f]{64}', binary_sha) is not None and
            data['actual_lock_sha256'] == LOCK and
            hashlib.sha256(read_owned(directory / 'Cargo.lock', private)).hexdigest() == LOCK and
            data['source_files'] == expected_sources, 'FAIL_LATCH_INPUTS')
    require(any(p['class'] == 'Fail' for p in checkpoint['data']['trace']['problems']), 'FAIL_LATCH_ORACLE')
    return {'schema': 'x0x.issue287-fail-latch/1', 'collect_request_sha256': request_sha,
            'nonce': nonce, 'inputs': input_name, 'inputs_sha256': hashlib.sha256(inputs_raw).hexdigest(),
            'checkpoint': checkpoint_name, 'checkpoint_sha256': hashlib.sha256(checkpoint_raw).hexdigest(),
            'source_files': expected_sources, 'test_binary_sha256': binary_sha, 'lock_sha256': LOCK}


def save_fail_latch(private, value):
    # Atomic publication without replacing an existing/stale latch. A crash can
    # leave the uncommitted temp, which is never accepted as a latch.
    temporary, final = private / 'fail-latch.pending.json', private / 'fail-latch.json'
    write_json(temporary, value)
    try:
        os.link(temporary, final)
    finally:
        temporary.unlink()


def validate_fail_latch(private, request_sha, source, binary_sha, latch):
    require(request_sha is not None, 'FAIL_LATCH_REQUEST')
    request_raw = read_owned(private / 'collect-request.json', private, JSON_LIMIT)
    require(hashlib.sha256(request_raw).hexdigest() == request_sha, 'FAIL_LATCH_REQUEST')
    request = object_json(request_raw)
    require(set(request) == {'schema', 'mode', 'private', 'payload'} and
            request['schema'] == 'x0x.issue287-worker-input/1' and request['mode'] == 'collect' and
            request['private'] == str(private), 'FAIL_LATCH_REQUEST')
    payload = request['payload']
    require(set(payload) == {'workspace', 'source', 'reuse', 'runtime_exit', 'runtime_reason'} and
            payload['source'] == source and payload['reuse']['binary_sha256'] == binary_sha,
            'FAIL_LATCH_REQUEST')
    expected = fail_latch_value(private, request_sha, source, binary_sha,
                               latch['nonce'], latch['inputs'], latch['checkpoint'])
    require(latch == expected, 'FAIL_LATCH_BINDING')


def recover_interrupted_fail_latch(private, request_sha, source, binary_sha):
    """Only the exact two-link interrupted publication pair, after collect reap."""
    pending, final = private / 'fail-latch.pending.json', private / 'fail-latch.json'
    if not pending.exists() and not pending.is_symlink():
        return
    if not final.exists() and not final.is_symlink():
        # An unpublished partial temp is private audit data, never a FAIL latch.
        return
    require(private == private.resolve() and private.is_dir() and
            private.stat().st_uid == os.getuid(), 'FAIL_LATCH_PAIR_OWNER')
    def stable(st):
        return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    states = [p.lstat() for p in (pending, final)]
    require(all(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
                st.st_nlink == 2 and 0 < st.st_size <= JSON_LIMIT for st in states) and
            (states[0].st_dev, states[0].st_ino) == (states[1].st_dev, states[1].st_ino), 'FAIL_LATCH_PAIR')
    with os.fdopen(os.open(final, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_size) ==
                (states[1].st_dev, states[1].st_ino, 2, states[1].st_size), 'FAIL_LATCH_PAIR_CHANGED')
        raw = stream.read(JSON_LIMIT + 1)
        require(len(raw) == opened.st_size and stable(os.fstat(stream.fileno())) == stable(opened),
                'FAIL_LATCH_PAIR_CHANGED')
    # No unlink until the full source/request/binary/nonce/checkpoint/lock binding
    # is proven. This exception never relaxes regular/read_owned for other files.
    validate_fail_latch(private, request_sha, source, binary_sha, object_json(raw))
    require([stable(p.lstat()) for p in (pending, final)] == [stable(st) for st in states], 'FAIL_LATCH_PAIR_CHANGED')
    pending.unlink()
    current = final.lstat()
    require(current.st_nlink == 1 and (current.st_dev, current.st_ino) ==
            (opened.st_dev, opened.st_ino), 'FAIL_LATCH_PAIR_CHANGED')


def verify_fail_latch(private, request_sha, source, binary_sha):
    final = private / 'fail-latch.json'
    if not final.exists() and not final.is_symlink():
        return False
    latch = object_json(read_owned(final, private, JSON_LIMIT))
    validate_fail_latch(private, request_sha, source, binary_sha, latch)
    return True


def local_validation(records, directory, source, reuse):
    by_kind = {kind: [r['data'] for r in records if r['kind'] == kind] for kind in KINDS}
    require(len(by_kind['inputs']) == len(by_kind['workload']) == 1, 'INPUT_COUNT')
    data = by_kind['inputs'][0]
    require(data['selector'] == SELECTOR and data['test_binary_sha256'] == reuse['binary_sha256']
            and data['actual_lock_sha256'] == LOCK and digest(directory / 'Cargo.lock') == LOCK, 'INPUT_BINDING')
    names = ('tests/ws_integration.rs', 'tests/harness/src/daemon.rs', 'tests/harness/src/ws_backpressure_diagnostic.rs')
    require(data['source_files'] == {n: source['files'][n]['sha256'] for n in names}, 'LOCAL_SOURCE')
    checkpoints = by_kind['checkpoint']
    require(bool(checkpoints), 'CHECKPOINT_MISSING')
    # Preserve established FAIL even if final capture/cleanup is absent.
    if any(p['class'] == 'Fail' for c in checkpoints for p in c['trace']['problems']):
        return 'FAIL'
    require(records[-1]['kind'] == 'checkpoint', 'FINAL_CHECKPOINT')
    final = checkpoints[-1]
    status = final['local_status']
    require(status in ('FAIL', 'INCOMPLETE', 'INCONCLUSIVE', 'LOCAL_ORACLES_PASS'), 'LOCAL_STATUS')
    if status != 'LOCAL_ORACLES_PASS':
        return status
    trace = final['trace']
    require(not trace['problems'] and trace['cleanup_complete'] is True, 'LOCAL_PROBLEMS')
    require(trace['phases'] == ['setup_entered', 'setup_complete', 'stalled_fill_entered',
        'stalled_saturation_established', 'stalled_oracles_complete', 'matched_replay_admitted',
        'both_local_oracles_complete'], 'PHASES')
    require(type(final['elapsed_ms']) is int and final['elapsed_ms'] <= 570000, 'CLEANUP_BUDGET')
    n, n2 = trace['waves']
    require(type(n) is int and 0 < n <= 4096 and n == n2, 'WAVE_COUNTS')
    workload = by_kind['workload'][0]
    require(workload['payload_bytes'] == 16384 and workload['concurrency'] == 64
            and workload['request_timeout_ms'] == 10000 and workload['wave_algorithm'] == 'all full bodies then counters'
            and workload['network_planes'] == 'distinct per arm', 'WORKLOAD')
    require(re.fullmatch('[0-9a-f]{64}', workload['payload_base64_sha256']) is not None, 'PAYLOAD_HASH')
    for arm in ('stalled', 'draining'):
        waves = [w for w in by_kind['wave'] if w['arm'] == arm]
        require([w['ordinal'] for w in waves] == list(range(n)), 'WAVE_ORDER')
        for wave in waves:
            require(wave['capture_complete'] is True and len(wave['requests']) == 64, 'WAVE_CAPTURE')
            for i, row in enumerate(wave['requests']):
                require(row['ordinal'] == i and row['state'] == 'Complete' and row['status'] == 200, 'HTTP_OUTCOME')
                times = [row[k] for k in ('entered_ms', 'headers_ms', 'eof_ms')]
                require(all(type(x) is int and x >= 0 for x in times) and times == sorted(times)
                        and times[-1] <= 540000 and type(row['body_bytes']) is int
                        and 0 <= row['body_bytes'] <= 65536
                        and re.fullmatch('[0-9a-f]{64}', row['body_sha256']) is not None, 'HTTP_BODY')
        counters = [c['counters'] for c in by_kind['counters'] if c['arm'] == arm]
        require(len(counters) >= 2 and all(c['capture_complete'] is True for c in counters), 'COUNTER_CAPTURE')
        if arm == 'stalled':
            require(counters[-1]['dropped'] > counters[0]['dropped'] and counters[-1]['closes'] == counters[0]['closes'] + 1, 'STALLED_COUNTERS')
        else:
            require(all(c['dropped'] == counters[0]['dropped'] and c['closes'] == counters[0]['closes'] for c in counters), 'DRAINING_COUNTERS')
            require(len(by_kind['draining_final_counters']) == 1, 'DRAINING_FINAL')
            last = by_kind['draining_final_counters'][0]
            require(last['ws_outbound_dropped'] == counters[0]['dropped'] and last['ws_slow_consumer_closes'] == counters[0]['closes'], 'DRAINING_FINAL')
    require(len(by_kind['wire_close']) == 1 and by_kind['wire_close'][0]['arm'] == 'stalled'
            and by_kind['wire_close'][0]['close_code'] == 1013, 'WIRE_CLOSE')
    reader = final['reader']
    require(reader['started'] is True and reader['frames'] == n * 64 and reader['unexpected'] == 0
            and reader['error'] is None and type(reader['last_frame_ms']) is int, 'READER_ORACLE')
    cleanups = final['cleanup_observations']
    require(len(cleanups) == 2, 'CHILD_COUNT')
    pids = []
    for arm, cleanup in zip(('stalled', 'draining'), cleanups):
        spawn = object_json(read_owned(directory / arm / 'spawn.json', directory, JSON_LIMIT))
        saved = object_json(read_owned(directory / arm / 'cleanup.json', directory, JSON_LIMIT))
        require(spawn['schema'] == 'x0x.issue287-daemon/1' and spawn['binary_path'] == reuse['daemon_path']
                and spawn['binary_sha256'] == reuse['daemon_sha256'], 'SPAWN_BUILD')
        require(type(spawn['pid']) is int and spawn['pid'] > 0 and cleanup['pid'] == spawn['pid'], 'CHILD_PID')
        pids.append(spawn['pid'])
        require(cleanup['reaped'] is True and cleanup['deliberate_termination'] is True
                and cleanup['capture_complete'] is True and cleanup['identity_removed'] is True
                and not cleanup['errors'] and isinstance(cleanup['exit'], str), 'CHILD_CLEANUP')
        require(saved == {k: cleanup[k] for k in ('pid', 'reaped', 'deliberate_termination', 'exit')}, 'CHILD_RECEIPT')
    require(len(set(pids)) == 2, 'CHILD_DUPLICATE')
    require(bool(by_kind['children']), 'SURVIVAL_MISSING')
    for row in by_kind['children']:
        require(len(row['children']) == 2 and {c['pid'] for c in row['children']} == set(pids)
                and all(c['alive'] is True for c in row['children']), 'CHILD_SURVIVAL')
    # Session/health and exact reader cutoff are source-asserted phase facts;
    # their raw responses/cutoff are not emitted by this fixed Rust producer.
    return 'LOCAL_ORACLES_PASS'


def adjudicate(local, terminal_ok, custody_ok, incomplete):
    if local == 'FAIL':
        return 'FAIL'
    if incomplete or not custody_ok:
        return 'INCOMPLETE'
    if local in ('INCOMPLETE', 'INCONCLUSIVE'):
        return local
    return 'PASS' if local == 'LOCAL_ORACLES_PASS' and terminal_ok else 'INCOMPLETE'


def finish_result(result, terminal_ok, custody_ok, gaps, framework_failed):
    """Framework FAIL is not a local oracle verdict: all local nonpass asserts."""
    if framework_failed:
        result.update(selected=1, ran=1, passed=0, failed=1, framework_status='FAIL')
    elif terminal_ok:
        result['framework_status'] = 'PASS'
    else:
        result['framework_status'] = 'UNVERIFIED'
    result['status'] = adjudicate(result['local_status'], terminal_ok, custody_ok, gaps)
    return result


def remaining(deadline, cap, reserve=0):
    value = min(cap, deadline - time.monotonic() - reserve)
    require(value > 0, 'PHASE_DEADLINE')
    return value


def run_bounded(argv, cwd, env, directory, name, cap, deadline):
    return run_private(argv, cwd, env, directory, name, remaining(deadline, cap, reserve=20), deadline=deadline)


def worker_result(path, root, request_sha):
    result = object_json(read_owned(path, root, JSON_LIMIT))
    require(isinstance(result, dict) and result.get('schema') == 'x0x.issue287-worker/1'
            and result.get('request_sha256') == request_sha, 'WORKER_BINDING')
    return result


def run_worker(mode, payload, private, env, deadline, cap, request_pins=None):
    request = private / (mode + '-request.json')
    response = private / (mode + '-response.json')
    write_json(request, {'schema': 'x0x.issue287-worker-input/1', 'mode': mode,
                         'private': str(private), 'payload': payload})
    if request_pins is not None:
        request_pins[mode] = digest(request)
    argv = ['python3', str(Path(__file__).resolve()), '--worker', mode,
            '--request', str(request), '--response', str(response)]
    process = run_bounded(argv, Path.cwd(), env, private, mode + '-worker', cap, deadline)
    require(process['outer_reaped'] is True and process['reason'] is None and process['exit'] == 0,
            'WORKER_NONPASS')
    return worker_result(response, private, digest(request))


def prepare_archive(private, archive):
    # These files belong to the currently active archive worker and cannot be
    # stable inputs to its own archive. Its result is retained in the public hashes.
    excluded = {'archive-worker.stdout', 'archive-worker.stderr', 'archive-worker.json',
                'archive-response.json', 'plaintext-manifest.json'}
    files, total = {}, 0
    for path in sorted(private.rglob('*')):
        require(not path.is_symlink(), 'ARCHIVE_SYMLINK')
        if path.is_dir():
            continue
        name = str(path.relative_to(private))
        if name in excluded:
            continue
        regular(path, private)
        total += path.stat().st_size
        require(total <= MAX_TOTAL and len(files) < MAX_MEMBERS, 'ARCHIVE_BOUND')
        files[name] = digest(path)
    write_json(private / 'plaintext-manifest.json', files)
    with tarfile.open(archive, 'x', format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files | {'plaintext-manifest.json': ''}):
            path = regular(private / name, private)
            tar.add(path, arcname=name, recursive=False)
            if name in files:
                require(digest(path) == files[name], 'ARCHIVE_INPUT_CHANGED')
    return {'archive_sha256': digest(archive), 'manifest_sha256': digest(private / 'plaintext-manifest.json'),
            'source_map_sha256': digest(private / 'source-before.json')}


def receipt_value(source, result, age_sha, archive_meta, cipher_sha):
    require(set(result) == {'status', 'local_status', 'selected', 'ran', 'passed', 'failed',
            'namespace_admitted', 'outer_reaped', 'test_binary_sha256', 'daemon_binary_sha256', 'framework_status'}, 'PUBLIC_SCHEMA')
    require(result['status'] in ('PASS', 'FAIL', 'INCOMPLETE', 'INCONCLUSIVE') and result['local_status'] in
            ('UNVERIFIED', 'LOCAL_ORACLES_PASS', 'FAIL', 'INCOMPLETE', 'INCONCLUSIVE'), 'PUBLIC_STATUS')
    require(result['framework_status'] in ('PASS', 'FAIL', 'UNVERIFIED'), 'PUBLIC_FRAMEWORK')
    require(all(type(result[k]) is int and result[k] in (0, 1) for k in ('selected', 'ran', 'passed', 'failed')), 'PUBLIC_COUNT')
    require(all(type(result[k]) is bool for k in ('namespace_admitted', 'outer_reaped')), 'PUBLIC_BOOL')
    require(all(result[k] is None or re.fullmatch('[0-9a-f]{64}', result[k]) for k in
                ('test_binary_sha256', 'daemon_binary_sha256')), 'PUBLIC_HASH')
    receipt = {'schema': 'x0x.issue287-outer/1', 'source_commit': source['head'], 'source_tree': source['tree'],
               'parent_commit': PARENT, 'source_map_sha256': archive_meta['source_map_sha256'],
               'lock_sha256': LOCK, 'selector': SELECTOR, 'run_id': os.environ['GITHUB_RUN_ID'],
               'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'job': 'component', **result,
               'plaintext_manifest_sha256': archive_meta['manifest_sha256'],
               'plaintext_archive_sha256': archive_meta['archive_sha256'], 'cipher_sha256': cipher_sha,
               'age_binary_sha256': age_sha, 'recipient_sha256': RECIPIENT_SHA,
               'private_readback': 'PENDING', 'scope': 'local comparator plus external custody; not final Tester acceptance'}
    require(re.fullmatch('[0-9a-f]{64}', cipher_sha) is not None, 'CIPHER_HASH')
    return receipt



def prepare_receipt_candidate(private, output, source, result, age_sha, archive_meta):
    cipher = regular(output / 'evidence.tar.age', output, MAX_TOTAL)
    with cipher.open('rb') as f:
        require(f.read(22).startswith(b'age-encryption.org/v1'), 'SEAL_HEADER')
    cipher_sha = digest(cipher)
    candidate = receipt_value(source, result, age_sha, archive_meta, cipher_sha)
    write_json(private / 'receipt-candidate.json', candidate)
    return {'candidate_sha256': digest(private / 'receipt-candidate.json'), 'cipher_sha256': cipher_sha}


def finalize_receipt(private, output, candidate, result, deadline):
    """Finite main-thread publication; metadata worker never writes publicly."""
    global PUBLICATION_ACTIVE
    signals = {signal.SIGTERM, signal.SIGINT}
    require(not (signal.pthread_sigmask(signal.SIG_BLOCK, set()) & signals), 'PUBLICATION_SIGNALS_BLOCKED')
    public = output / 'receipt.json'
    initial_temp = private / 'receipt-publication.pending.json'
    cancelled_temp = private / 'receipt-cancelled.pending.json'
    require(all(not p.exists() and not p.is_symlink() for p in (public, initial_temp, cancelled_temp)),
            'PUBLICATION_EXCLUSIVE')
    initial = dict(candidate)
    def publish(value, temporary, replacing=False):
        remaining(deadline, 120)
        encoded = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        require(len(encoded) <= RECEIPT_LIMIT, 'RECEIPT_BOUND')
        with temporary.open('xb') as f:
            f.write(encoded)
        require(read_owned(temporary, private, RECEIPT_LIMIT) == encoded, 'PUBLICATION_TEMP')
        if replacing and public.exists():
            require(object_json(read_owned(public, output, RECEIPT_LIMIT)) == initial, 'PUBLICATION_CHANGED')
        else:
            require(not public.exists() and not public.is_symlink(), 'PUBLICATION_EXCLUSIVE')
        os.replace(temporary, public)
        require(read_owned(public, output, RECEIPT_LIMIT) == encoded, 'PUBLICATION_READBACK')
        remaining(deadline, 120)
        return value
    try:
        PUBLICATION_ACTIVE = True
        if CANCELLED or signal.sigpending() & signals:
            interrupted(None, None)
        published = publish(initial, initial_temp)
        if CANCELLED or signal.sigpending() & signals:
            interrupted(None, None)
        # Publication boundary: exact small-file readback is complete. Handler
        # delivery before this assignment cancels; later signals keep exit1 but
        # need not retroactively rewrite completed evidence. No signal is masked.
        PUBLICATION_ACTIVE = False
    except PublicationCancelled:
        PUBLICATION_ACTIVE = False
        cancelled = dict(candidate)
        if cancelled['status'] != 'FAIL':
            cancelled['status'] = 'INCOMPLETE'
        published = publish(cancelled, cancelled_temp, replacing=True)
    finally:
        PUBLICATION_ACTIVE = False
    result['status'] = published['status']
    return published


def seal_packet(private, output, recipient, env, source, result, age, step_deadline, collect_request_sha=None):
    seal_deadline = min(step_deadline, time.monotonic() + 120)
    require(digest(recipient) == RECIPIENT_SHA and digest(age[0]) == age[1], 'SEAL_TOOL')
    prepared = run_worker('archive', {'collect_request_sha256': collect_request_sha, 'source': source,
                         'test_binary_sha256': result['test_binary_sha256']}, private, env, seal_deadline, 120)
    require(set(prepared) == {'schema', 'request_sha256', 'archive_sha256', 'manifest_sha256', 'source_map_sha256', 'verified_local_fail'}, 'ARCHIVE_RESULT')
    require(type(prepared['verified_local_fail']) is bool, 'ARCHIVE_RESULT')
    if prepared['verified_local_fail']:
        result.update(local_status='FAIL', status='FAIL')
    elif CANCELLED and result['status'] != 'FAIL':
        result['status'] = 'INCOMPLETE'
    archive_meta = {k: prepared[k] for k in ('archive_sha256', 'manifest_sha256', 'source_map_sha256')}
    require(all(re.fullmatch('[0-9a-f]{64}', x) for x in archive_meta.values()), 'ARCHIVE_HASH')
    archive = output.parent / 'private-evidence.tar'
    cipher = output / 'evidence.tar.age'
    sealed = run_bounded([str(age[0]), '-R', str(recipient), '-o', str(cipher), str(archive)],
                         private, env, private, 'seal', 120, seal_deadline)
    require(sealed['exit'] == 0 and sealed['reason'] is None and sealed['outer_reaped'] is True,
            'SEAL_FAILED')
    # Hashing potentially large ciphertext is also watched; the worker executes
    # no encryption/tool child and cannot outlive an unreaped parent watchdog.
    if CANCELLED and result['status'] != 'FAIL':
        result['status'] = 'INCOMPLETE'
    completed = run_worker('seal-metadata', {'source': source, 'result': result, 'age_sha256': age[1],
                         'archive': archive_meta}, private, env, seal_deadline, 120)
    require(set(completed) == {'schema', 'request_sha256', 'candidate_sha256', 'cipher_sha256'}, 'SEAL_RECEIPT')
    raw = read_owned(private / 'receipt-candidate.json', private, RECEIPT_LIMIT)
    require(hashlib.sha256(raw).hexdigest() == completed['candidate_sha256'], 'SEAL_RECEIPT')
    candidate = object_json(raw)
    require(candidate == receipt_value(source, result, age[1], archive_meta, completed['cipher_sha256']),
            'SEAL_CANDIDATE')
    return finalize_receipt(private, output, candidate, result, seal_deadline)


def execute_worker(mode, request, response):
    # File-only worker modes. No Cargo, daemon, age, namespace or subprocess call.
    require(mode in ('collect', 'archive', 'seal-metadata', 'detach'), 'WORKER_MODE')
    private = request.parent
    require(private.is_absolute() and private == private.resolve() and private.stat().st_uid == os.getuid(), 'WORKER_OWNER')
    require(request == private / (mode + '-request.json') and response == private / (mode + '-response.json'), 'WORKER_PATH')
    data = object_json(read_owned(request, private, JSON_LIMIT))
    require(set(data) == {'schema', 'mode', 'private', 'payload'} and data['schema'] == 'x0x.issue287-worker-input/1'
            and data['mode'] == mode and data['private'] == str(private), 'WORKER_INPUT')
    payload = data['payload']
    value = {'schema': 'x0x.issue287-worker/1', 'request_sha256': digest(request)}
    if mode == 'detach':
        require(set(payload) == {'workspace', 'scratch', 'source', 'deadline'}, 'DETACH_REQUEST')
        workspace, scratch = Path(payload['workspace']), Path(payload['scratch'])
        require(workspace.is_absolute() and workspace == workspace.resolve() and
                scratch == private / 'runner-temp/x0x-metadata-issue287', 'DETACH_REQUEST')
        value.update(execute_detachment(workspace, scratch, payload['source'], private,
                     payload['deadline'], value['request_sha256']))
    elif mode == 'collect':
        require(set(payload) == {'workspace', 'source', 'reuse', 'runtime_exit', 'runtime_reason'}, 'COLLECT_INPUT')
        workspace = Path(payload['workspace'])
        require(workspace.is_absolute() and workspace == workspace.resolve(), 'COLLECT_WORKSPACE')
        destination = private / 'capture'
        local, gaps = 'UNVERIFIED', []
        input_name, latched = None, False
        def copied_record(nonce, name, record):
            nonlocal input_name, latched
            if record['kind'] == 'inputs':
                require(input_name is None, 'INPUT_COUNT')
                input_name = name
            if record['kind'] == 'checkpoint' and not latched and input_name is not None and any(
                    p['class'] == 'Fail' for p in record['data']['trace']['problems']):
                latch = fail_latch_value(private, value['request_sha256'], payload['source'],
                                        payload['reuse']['binary_sha256'], nonce, input_name, name)
                save_fail_latch(private, latch)
                latched = True
        try:
            nonce, records, captured, capture_gaps = collect_capture(workspace, destination, copied_record)
            write_json(private / 'capture-manifest.json', {'nonce': nonce, 'files': captured,
                'source_asserted_not_raw_recalculated': ['exact_reader_15s_cutoff', 'final_health_and_session_presence']})
            gaps.extend(capture_gaps)
            local = local_validation(records, destination, payload['source'], payload['reuse'])
        except (Rejected, OSError, ValueError, KeyError, TypeError):
            gaps.append('CAPTURE_INCOMPLETE')
        if observed_failure(destination):
            local = 'FAIL'
        terminal_ok, framework_failed = False, False
        counts = {'selected': 0, 'ran': 0, 'passed': 0, 'failed': 0}
        try:
            raw = read_owned(private / 'runtime.stderr', private)
            framework_failed = terminal_failure(raw, payload['reuse']['binary_id'])
            counts, _, _ = parse_report(raw, SELECTOR, payload['reuse']['binary_id'])
            terminal_ok = payload['runtime_exit'] == 0 and payload['runtime_reason'] is None
        except (Rejected, OSError, ValueError, KeyError, TypeError):
            gaps.append('TERMINAL_NONPASS_OR_INCOMPLETE')
        value.update(local_status=local, gaps=gaps, terminal_ok=terminal_ok,
                     framework_failed=framework_failed, counts=counts)
    elif mode == 'archive':
        require(set(payload) == {'collect_request_sha256', 'source', 'test_binary_sha256'}, 'ARCHIVE_INPUT')
        recover_interrupted_fail_latch(private, payload['collect_request_sha256'], payload['source'],
                                       payload['test_binary_sha256'])
        verified = verify_fail_latch(private, payload['collect_request_sha256'], payload['source'],
                                     payload['test_binary_sha256'])
        write_json(private / 'fail-latch-verification.json', {'verified_local_fail': verified,
                   'collect_request_sha256': payload['collect_request_sha256']})
        value.update(prepare_archive(private, private.parent / 'private-evidence.tar'), verified_local_fail=verified)
    else:
        require(set(payload) == {'source', 'result', 'age_sha256', 'archive'}, 'SEAL_INPUT')
        value.update(prepare_receipt_candidate(private, private.parent / 'public', payload['source'],
                     payload['result'], payload['age_sha256'], payload['archive']))
    write_json(response, value)
    return 0


def terminal_failure(raw, binary_id):
    """Retain a bound nonpass terminal even if a later summary is incomplete."""
    try:
        lines = raw.decode('utf-8', errors='strict').splitlines()
        cuts = [i for i, line in enumerate(lines) if line == '────────────']
        if not cuts:
            return False
        rows = []
        for line in lines[cuts[0] + 1:]:
            if line == '────────────' or re.fullmatch(r'  (stdout|stderr) ───', line):
                break
            rows.append(line)
        body = '\n'.join(rows)
        starts = re.findall(r'^    Starting (\d+) tests? across (\d+) binar(?:y|ies)(?: \([^\n]*\))?$', body, re.M)
        terminals = re.findall(r'^        (FAIL|TIMEOUT|LEAK|EXECFAIL) \[\s*[0-9.]+s\] \(1/1\) (\S+) (\S+)$', body, re.M)
        return starts == [('1', '1')] and len(terminals) == 1 and terminals[0][1:] == (binary_id, SELECTOR)
    except (UnicodeError, TypeError):
        return False


def observed_failure(directory):
    """Do not let a later capture error erase an already retained oracle failure."""
    if not directory.exists():
        return False
    for path in sorted(directory.glob('*.json')):
        try:
            v = object_json(read_owned(path, directory, JSON_LIMIT))
            if v.get('schema') != 'x0x.issue287-local/1':
                continue
            d = v['data']
            if v['kind'] == 'checkpoint':
                if any(p.get('class') == 'Fail' for p in d['trace']['problems']):
                    return True
                if any(c.get('deliberate_termination') is False for c in d['cleanup_observations']):
                    return True
            if v['kind'] == 'children' and any(c.get('alive') is False for c in d['children']):
                return True
            if v['kind'] == 'wave' and any(r.get('status') not in (None, 200) or r.get('state') in
                    ('RequestError', 'BodyError', 'Timeout', 'Non200') for r in d['requests']):
                return True
        except (Rejected, OSError, KeyError, TypeError, ValueError):
            continue
    return False


def main():
    step_deadline = time.monotonic() + 49 * 60
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-root', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    workspace = Path.cwd()
    require(workspace == workspace.resolve() and not workspace.is_relative_to('/tmp')
            and os.geteuid() != 0, 'WORKSPACE_OWNER')
    require(os.environ.get('GITHUB_REPOSITORY') == 'saorsa-labs/x0x' and
            os.environ.get('GITHUB_EVENT_NAME') == 'push' and os.environ.get('GITHUB_REF') == BRANCH, 'EVENT_GUARD')
    sha = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'EVENT_SHA')
    require(all(re.fullmatch('[1-9][0-9]*', os.environ.get(k, '')) for k in
                ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'RUN_ID')
    producer_admission()  # No runtime, build or permission fallback on an unknown contract.
    root = args.output_root
    require(root.is_absolute() and not root.exists() and not root.is_symlink()
            and root.parent == root.parent.resolve() and not root.is_relative_to('/tmp'), 'ROOT_EXCLUSIVE')
    root.mkdir(mode=0o700)
    private, output = root / 'private', root / 'public'
    private.mkdir(mode=0o700); output.mkdir(mode=0o700)
    require(not (workspace / 'target').exists() and not (workspace / 'target').is_symlink(), 'TARGET_FRESH')
    source = source_map(workspace, sha, step_deadline)
    write_json(private / 'source-before.json', source)
    env = os.environ.copy()
    env.update(CARGO_TERM_COLOR='never', RUSTUP_TOOLCHAIN='1.95.0', CARGO_BUILD_JOBS='2',
               CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(workspace / 'target'))
    recipient = workspace / 'scripts/ci/issue287-recipient.txt'
    require(digest(recipient) == RECIPIENT_SHA, 'RECIPIENT_PIN')
    prep = Path(os.environ['RUNNER_TEMP']) / 'issue287-preparation'
    retained = private / 'preparation'; retained.mkdir(mode=0o700)
    for name in ('apt-update.log', 'apt-install.log', 'rustup.log', 'cargo-fetch.log', 'nextest.tar.gz', 'age.tar.gz'):
        data = read_owned(prep / name, prep)
        with (retained / name).open('xb') as f:
            f.write(data)
    require(digest(retained / 'nextest.tar.gz') == '66786b9abe23920d022a182d1416b1bbc8130dd4872a9553d76985a1708dcd1e', 'NEXTEST_ASSET')
    require(digest(retained / 'age.tar.gz') == 'cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10', 'AGE_ASSET')
    for tool in ('cargo-nextest', 'age'):
        require(shutil.which(tool) is not None and Path(shutil.which(tool)).resolve() ==
                (prep / 'bin' / tool).resolve(), 'TOOL_PATH')
    age = (Path(shutil.which('age')).resolve(), digest(shutil.which('age')))
    for name, argv, prefix in [('age-version', ['age', '--version'], 'v1.3.2'),
                               ('nextest-version', ['cargo', 'nextest', '--version'], 'cargo-nextest 0.9.143'),
                               ('rustc-version', ['rustc', '--version'], 'rustc 1.95.0')]:
        r = run_bounded(argv, workspace, env, private, name, 30, step_deadline)
        require(r['exit'] == 0 and r['reason'] is None, 'TOOL_VERSION')
        text = (private / (name + '.stdout')).read_text().strip()
        require(text.startswith(prefix) or (name == 'age-version' and text == '1.3.2'), 'TOOL_VERSION')
    probe = private / 'seal-probe.txt'; probe.write_text('issue287 retention preflight\n')
    r = run_bounded([str(age[0]), '-R', str(recipient), '-o', str(private / 'seal-probe.age'), str(probe)], workspace, env, private, 'seal-probe', 15, step_deadline)
    require(r['exit'] == 0 and r['reason'] is None and (private / 'seal-probe.age').is_file(), 'SEAL_PREFLIGHT')
    rt = private / 'runner-temp'; rt.mkdir(mode=0o700)
    scratch = rt / 'x0x-metadata-issue287'; scratch.mkdir(mode=0o700)
    env.update(RUNNER_TEMP=str(rt), X0X_ISOLATION_ROLE='acceptance',
               X0X_CUSTODY_SCRATCH=str(scratch), X0X_RUNTIME_TIMEOUT_SECONDS='1200')
    result = {'status': 'INCOMPLETE', 'local_status': 'UNVERIFIED', 'selected': 0,
              'ran': 0, 'passed': 0, 'failed': 0, 'namespace_admitted': False, 'outer_reaped': False,
              'test_binary_sha256': None, 'daemon_binary_sha256': None, 'framework_status': 'UNVERIFIED'}
    runtime, reuse = None, None
    build_verification = BuildVerification(source, step_deadline - 49 * 60)
    request_pins = {}
    complete, terminal_ok, gaps = False, False, []
    framework_failed = False
    deadline = step_deadline
    build_deadline = min(step_deadline, time.monotonic() + 1200)
    try:
        def build(name, argv):
            require(not CANCELLED and time.monotonic() < build_deadline, 'BUILD_DEADLINE')
            r = run_bounded(argv, workspace, env, private, name, 1200, build_deadline)
            require(r['exit'] == 0 and r['reason'] is None, 'BUILD_FAILED')
            require(source_map(workspace, sha, step_deadline) == source, 'SOURCE_DRIFT')
            return private / (name + '.stdout')
        metadata = build('metadata', ['cargo', 'metadata', '--offline', '--locked', '--all-features', '--format-version', '1'])
        shutil.copyfile(metadata, scratch / 'cargo.json')
        binaries = build('binaries', ['cargo', 'nextest', 'list', '--offline', '--locked', '--all-features',
            '--package', 'x0x', '--test', 'ws_integration', '--cargo-metadata', str(scratch / 'cargo.json'),
            '--list-type', 'binaries-only', '--message-format', 'json'])
        shutil.copyfile(binaries, scratch / 'binaries.json')
        (scratch / 'lock.sha256').write_text(LOCK + '  Cargo.lock\n')
        build('record', ['python3', 'scripts/ci/nextest-reuse.py', 'record', str(scratch)])
        reuse = prepare_verified_build(workspace, scratch, source, private, env, build_deadline, build_verification.before)
        verification_action(build_verification.write,
                            lambda: write_json(private / 'verified-build-before.json', reuse))
        result.update(test_binary_sha256=reuse['binary_sha256'], daemon_binary_sha256=reuse['daemon_sha256'])
        require(not (workspace / 'target/issue287-captures').exists(), 'CAPTURE_NOT_FRESH')
        require(not CANCELLED and time.monotonic() + 1230 <= deadline, 'RUNTIME_ADMISSION_DEADLINE')
        runtime = run_bounded(['python3', 'scripts/ci/isolated-runtime.py', 'python3',
            'scripts/ci/nextest-reuse.py', 'run', str(scratch), *runtime_arguments()],
            workspace, env, private, 'runtime', 1230, min(step_deadline, time.monotonic() + 1230))
        result['outer_reaped'] = runtime['outer_reaped']
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        gaps.append('BUILD_OR_RUNTIME_INCOMPLETE')
    # Once a runtime was launched, retain its custody even when it failed.
    if runtime is not None:
        collect_deadline = min(step_deadline, time.monotonic() + 120)
        try:
            env.update(X0X_CUSTODY_EXPECT='success' if runtime['exit'] == 0 and runtime['reason'] is None else 'failure',
                       X0X_CUSTODY_ROLES='acceptance', X0X_CUSTODY_TARGET='ws_integration', X0X_CUSTODY_MIN_RUNS='1')
            collected = run_bounded(['python3', 'scripts/ci/isolation-custody-collect.py', str(private / 'closed')],
                                    workspace, env, private, 'collector', 120, collect_deadline)
            require(collected['exit'] == 0 and collected['reason'] is None, 'COLLECTOR_FAILED')
            closed = object_json(read_owned(private / 'closed/custody-receipt.json', private, JSON_LIMIT))
            validate_closed(closed, source, reuse)
            complete = True
            result['namespace_admitted'] = True
        except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            gaps.append('CUSTODY_INCOMPLETE')
        try:
            captured = run_worker('collect', {'workspace': str(workspace), 'source': source, 'reuse': reuse,
                                  'runtime_exit': runtime['exit'], 'runtime_reason': runtime['reason']},
                                  private, env, collect_deadline, 120, request_pins)
            require(set(captured) == {'schema', 'request_sha256', 'local_status', 'gaps', 'terminal_ok', 'framework_failed', 'counts'} and
                    captured['local_status'] in ('UNVERIFIED', 'LOCAL_ORACLES_PASS', 'FAIL', 'INCOMPLETE', 'INCONCLUSIVE'), 'COLLECT_RESULT')
            require(isinstance(captured['gaps'], list) and all(x in ('CAPTURE_INCOMPLETE', 'UNEXPECTED_ARM_ENTRY', 'TERMINAL_NONPASS_OR_INCOMPLETE')
                    for x in captured['gaps']), 'COLLECT_RESULT')
            require(type(captured['terminal_ok']) is bool and type(captured['framework_failed']) is bool, 'COLLECT_RESULT')
            require(set(captured['counts']) == {'selected', 'ran', 'passed', 'failed'} and all(type(x) is int and x in (0, 1) for x in captured['counts'].values()), 'COLLECT_RESULT')
            result['local_status'] = captured['local_status']
            result.update(captured['counts'])
            terminal_ok, framework_failed = captured['terminal_ok'], captured['framework_failed']
            gaps.extend(captured['gaps'])
        except (Rejected, OSError, ValueError, KeyError, TypeError):
            # Partial capture files remain private. A missing/timeout worker result
            # cannot manufacture a local oracle status from framework failure.
            gaps.append('CAPTURE_WORKER_INCOMPLETE')
        try:
            checked = validate_build(workspace, scratch, source, build_verification.after)
            verification_action(build_verification.equality, lambda: require(checked == reuse, 'BUILD_DRIFT'))
        except (Rejected, OSError, ValueError, KeyError, TypeError):
            gaps.append('BUILD_DRIFT')
    try:
        after = source_map(workspace, sha, step_deadline)
        require(after == source, 'SOURCE_DRIFT')
        write_json(private / 'source-after.json', after)
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        gaps.append('SOURCE_DRIFT')
    if CANCELLED:
        gaps.append('EXECUTION_CANCELLED')
    finish_result(result, terminal_ok, complete, gaps, framework_failed)
    write_json(private / 'adjudication.json', {'result': result, 'gaps': gaps,
               'build_verification': build_verification.value()})
    seal_packet(private, output, recipient, env, source, result, age, step_deadline, request_pins.get('collect'))
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write('sealed=true\n')
    return 0 if result['status'] == 'PASS' and not CANCELLED else 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if len(__import__('sys').argv) > 1 and __import__('sys').argv[1] == '--worker':
            worker = argparse.ArgumentParser()
            worker.add_argument('--worker', choices=('collect', 'archive', 'seal-metadata', 'detach'), required=True)
            worker.add_argument('--request', type=Path, required=True)
            worker.add_argument('--response', type=Path, required=True)
            args = worker.parse_args()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            os.umask(0o077)
            raise SystemExit(execute_worker(args.worker, args.request, args.response))
        raise SystemExit(main())
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('issue287 evidence incomplete; raw output withheld')
        raise SystemExit(2)
