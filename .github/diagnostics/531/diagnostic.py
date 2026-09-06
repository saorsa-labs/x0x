"""One-run #531 coordinator. Preparation is separate from fenced execution."""
import hashlib
import contextlib
import errno
import stat
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
BASE = 'e16ba97a9d65022251e67ecc17f6e23d4b75699e'
CI_HEAD = 'da1fbd930c94cf2ac6f29992cbb269cea0e840d9'
CI_TREE = '637b7237d07d528f2db17dd4ec76e529f71e05e4'
LOCK = '6c21e6e693b0465c17d00031e9b2dc65e9ffe0c8dae1b4b3fcc6d8baf0cd0b72'
TEST = 'member_banned_lost_initial_volley_recovers_via_bounded_resend'
FILTER = f'test(={TEST})'
LOGS = ('provenance.json', 'build.jsonl', 'build.stderr', 'archive.stdout', 'archive.stderr',
        'build.tar.zst', 'Cargo.lock', 'diagnostic.patch', 'binaries.json', 'namespace.json',
        'firewall-before.json', 'firewall-after-probes.json', 'firewall-final.json',
        'probes.stdout', 'probes.stderr', 'capabilities.txt', 'list.json', 'list.stderr',
        'fixture.stdout', 'fixture.stderr', 'sockets.jsonl', 'receipt.json', 'worker-receipt.json',
        'build.exit', 'archive.exit', 'probes.exit')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def output(args):
    return subprocess.check_output(args, text=True, cwd=SOURCE).strip()


def capture(args, evidence, name, **kwargs):
    with (evidence/f'{name}.stdout').open('w') as out, (evidence/f'{name}.stderr').open('w') as err:
        result = subprocess.run(args, cwd=SOURCE, stdout=out, stderr=err, **kwargs)
    (evidence/f'{name}.exit').write_text(str(result.returncode)+'\n')
    if result.returncode:
        raise RuntimeError(f'{name} exited {result.returncode}; evidence retained')


def prepare(evidence):
    evidence.mkdir(mode=0o700)  # No accidental reuse/retry of a prior run.
    subprocess.run(['git', 'fetch', 'origin', CI_HEAD], cwd=SOURCE, check=True)
    assert output(['git', 'rev-parse', CI_HEAD+'^{tree}']) == CI_TREE
    # Original CI and local baseline runtime/tests/manifests must agree.
    subprocess.run(['git', 'diff', '--exit-code', BASE, CI_HEAD, '--', 'src', 'tests',
                    'Cargo.toml', '.config/nextest.toml'], cwd=SOURCE, check=True)
    subprocess.run(['git', 'diff', '--exit-code', BASE, 'HEAD', '--', 'src', 'Cargo.toml',
                    '.config/nextest.toml'], cwd=SOURCE, check=True)
    assert digest(HERE/'Cargo.lock.pinned') == LOCK
    shutil.copyfile(HERE/'Cargo.lock.pinned', SOURCE/'Cargo.lock')
    shutil.copyfile(SOURCE/'Cargo.lock', evidence/'Cargo.lock')
    rust = output(['rustc', '-Vv'])
    nextest = output(['cargo-nextest', 'nextest', '--version'])
    assert 'release: 1.98.1\n' in rust and 'host: x86_64-unknown-linux-gnu' in rust, rust
    assert 'cargo-nextest 0.9.143 ' in nextest, nextest
    (evidence/'provenance.json').write_text(json.dumps({
        'head': output(['git', 'rev-parse', 'HEAD']), 'tree': output(['git', 'rev-parse', 'HEAD^{tree}']),
        'base': BASE, 'ci_head': CI_HEAD, 'ci_tree': CI_TREE, 'rustc': rust, 'nextest': nextest,
        'kernel': output(['uname', '-a']), 'os': Path('/etc/os-release').read_text(),
        'image': {k: os.environ.get(k) for k in ('ImageOS', 'ImageVersion', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')},
        'lock': LOCK, 'rustflags': os.environ.get('RUSTFLAGS'),
        'incremental': os.environ.get('CARGO_INCREMENTAL')}, indent=2))
    patch = subprocess.check_output(['git', 'diff', '--unified=0', BASE, 'HEAD', '--', 'tests'], cwd=SOURCE)
    assert patch == (HERE/'test-observation.patch').read_bytes(), 'unreviewed test-source drift'
    (evidence/'diagnostic.patch').write_bytes(patch)
    subprocess.run(['cargo', 'fetch', '--locked'], cwd=SOURCE, check=True)
    capture(['cargo', 'test', '--locked', '--offline', '--all-features', '--test',
             'named_group_integration', '--no-run', '--message-format=json'], evidence, 'build')
    (evidence/'build.stdout').rename(evidence/'build.jsonl')
    binaries = {}
    for line in (evidence/'build.jsonl').read_text().splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row.get('executable'):
            name = row['target']['name']
            if name in ('x0xd', 'named_group_integration'):
                binaries[name] = {'path': row['executable'], 'sha256': digest(row['executable']),
                                  'profile': row['profile']}
    assert set(binaries) == {'x0xd', 'named_group_integration'}, binaries
    assert all(x['profile']['opt_level'] == '0' for x in binaries.values())
    capture(['cargo', 'nextest', 'archive', '--locked', '--offline', '--all-features', '--test',
             'named_group_integration', '--archive-file', str(evidence/'build.tar.zst')], evidence, 'archive')
    binaries['archive_sha256'] = digest(evidence/'build.tar.zst')
    (evidence/'binaries.json').write_text(json.dumps(binaries, indent=2))


def valid_socket(line):
    fields = line.split()
    if len(fields) < 6:
        return False
    proto, state, local, remote = fields[0], fields[1], fields[4], fields[5]
    def endpoint(value):
        address, port = value.rsplit(':', 1)
        return address.strip('[]'), port
    try:
        la, lp = endpoint(local)
        ra, rp = endpoint(remote)
    except ValueError:
        return False
    loops, apis, quics = {'127.0.0.1', '::1'}, {'29381', '29382'}, {'29481', '29482'}
    wild = {'0.0.0.0', '::', '*'}
    if proto == 'udp':
        return la in loops|wild and lp in quics and (
            (ra in wild and rp == '*') or (ra in loops and rp in quics))
    if proto == 'tcp':
        if state == 'LISTEN':
            return la == '127.0.0.1' and lp in apis and ra in wild and rp == '*'
        return la in loops and ra in loops and (lp in apis or rp in apis)
    return False


def selected_test(listing):
    selected = []
    for suite in listing.get('rust-suites', {}).values():
        for name, case in suite.get('testcases', {}).items():
            if case.get('filter-match', {}).get('status') == 'matches':
                selected.append(name)
    return selected == [TEST]


def drop_count(rules):
    count = 0
    for item in rules['nftables']:
        expressions = item.get('rule', {}).get('expr', [])
        if any('drop' in x for x in expressions):
            count += sum(x.get('counter', {}).get('packets', 0) for x in expressions)
    return count


def worker(evidence, nextest):
    status = Path('/proc/self/status').read_text()
    (evidence/'capabilities.txt').write_text(status)
    for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'):
        assert int(re.search(rf'^{name}:\s*(\w+)', status, re.M)[1], 16) == 0, name
    assert re.search(r'^NoNewPrivs:\s*1$', status, re.M)
    binaries = json.loads((evidence/'binaries.json').read_text())
    for name in ('x0xd', 'named_group_integration'):
        assert digest(binaries[name]['path']) == binaries[name]['sha256'], name
    assert digest(evidence/'build.tar.zst') == binaries['archive_sha256']
    run = evidence/'private-data'
    run.mkdir(mode=0o700)
    for name in ('tmp', 'logs', 'app-logs'):
        (run/name).mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(run/'tmp'),
           'X0X_HOME': '/tmp/x0x-nextest-home', 'X0X_TEST_LOG_DIR': str(run/'logs'),
           'X0X_LOG_DIR': str(run/'app-logs'), 'X0XD_TEST_BINARY': binaries['x0xd']['path'],
           'DHAT_OUT_DIR': str(run), 'NO_PROXY': '*', 'no_proxy': '*',
           'RUST_LOG': 'warn,treekem.trace=debug,x0x::server=debug,ant_quic::p2p_endpoint=info'}
    archive = ['--archive-file', str(evidence/'build.tar.zst'), '--workspace-remap', str(SOURCE)]
    with (evidence/'list.json').open('w') as out, (evidence/'list.stderr').open('w') as err:
        result = subprocess.run([nextest, 'nextest', 'list', *archive, '--extract-to', str(run/'list-extract'),
                                 '--run-ignored', 'ignored-only', '-E', FILTER, '--message-format', 'json'],
                                cwd=SOURCE, env=env, stdout=out, stderr=err, close_fds=True)
    assert result.returncode == 0 and selected_test(json.loads((evidence/'list.json').read_text()))
    extracted = list((run/'list-extract').rglob(Path(binaries['named_group_integration']['path']).name))
    assert len(extracted) == 1 and digest(extracted[0]) == binaries['named_group_integration']['sha256']
    # One admission only; never catch a failure by relaunching this command.
    command = [nextest, 'nextest', 'run', *archive, '--extract-to', str(run/'run-extract'),
               '--run-ignored', 'ignored-only', '--retries', '0', '-E', FILTER, '--no-capture']
    with (evidence/'fixture.stdout').open('w') as out, (evidence/'fixture.stderr').open('w') as err:
        result = subprocess.run(command, cwd=SOURCE, env=env, stdout=out, stderr=err, close_fds=True)
    final = {'exit': result.returncode, 'command': command,
             'daemon_sha256_after': digest(binaries['x0xd']['path']), 'lock_sha256_after': digest(SOURCE/'Cargo.lock')}
    (evidence/'worker-receipt.json').write_text(json.dumps(final, indent=2))
    daemon_logs = list((run/'logs').glob('pair-*.start.log'))
    final['mdns_skip_log_count'] = sum('Skipping first-party mDNS for a loopback-only endpoint' in path.read_text() for path in daemon_logs)
    (evidence/'worker-receipt.json').write_text(json.dumps(final, indent=2))
    if result.returncode == 0:
        assert len(daemon_logs) == 2 and final['mdns_skip_log_count'] == 2, 'missing mDNS suppression evidence'
    assert final['daemon_sha256_after'] == binaries['x0xd']['sha256'] and final['lock_sha256_after'] == LOCK
    return result.returncode


def supervise(evidence, uid, gid, nextest):
    assert os.getuid() == 0 and os.getpid() == 1, 'supervisor must own new PID namespace'
    privilege = ['setpriv', '--reuid', uid, '--regid', gid, '--clear-groups', '--bounding-set=-all',
                 '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']
    # No untrusted inherited environment or descriptors enter the controls/product.
    env = {'PATH': '/usr/bin:/bin'}
    capture([*privilege, sys.executable, str(HERE/'probes.py')], evidence, 'probes', env=env, close_fds=True)
    firewall = output(['nft', '--json', 'list', 'ruleset'])
    (evidence/'firewall-after-probes.json').write_text(firewall)
    assert drop_count(json.loads(firewall)) > drop_count(json.loads((evidence/'firewall-before.json').read_text()))
    # Witness sockets all closed; TIME-WAIT is harmless and independently tuple checked.
    initial = output(['ss', '-H', '-tunap'])
    assert all(valid_socket(line) for line in initial.splitlines()), initial
    process = subprocess.Popen([*privilege, sys.executable, str(HERE/'diagnostic.py'), 'worker', str(evidence), nextest],
                               env=env, cwd=SOURCE, close_fds=True, start_new_session=True)
    violation, started = None, time.monotonic()
    with (evidence/'sockets.jsonl').open('w') as log:
        while process.poll() is None:
            snapshot = output(['ss', '-H', '-tunap'])
            record = {'elapsed': time.monotonic()-started, 'sockets': snapshot}
            log.write(json.dumps(record)+'\n'); log.flush()
            if not all(valid_socket(line) for line in snapshot.splitlines()):
                violation = record
                os.killpg(process.pid, signal.SIGTERM)
                break
            time.sleep(.2)
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        code = process.wait()
    remaining = output(['ss', '-H', '-tunap'])
    if any(line.split()[1] != 'TIME-WAIT' for line in remaining.splitlines()):
        violation = {'remaining_after_worker_exit': remaining}
    (evidence/'firewall-final.json').write_text(output(['nft', '--json', 'list', 'ruleset']))
    (evidence/'receipt.json').write_text(json.dumps({'exit': code, 'violation': violation,
                                                  'seconds': time.monotonic()-started, 'postrun_sockets': remaining}, indent=2))
    # Exiting namespace PID1 also kills any descendants not reaped by nextest.
    return code if not violation else 1


def copy_evidence_file(root_fd, upload_fd, relative):
    """Open every ancestor without following symlinks; create output exclusively."""
    with contextlib.ExitStack() as stack:
        directory = root_fd
        try:
            for part in relative.parts[:-1]:
                directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory)
                stack.callback(os.close, directory)
            source_fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            stack.callback(os.close, source_fd)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT):
                return False
            raise
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            return False
        target_fd = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=upload_fd)
        stack.callback(os.close, target_fd)
        with os.fdopen(os.dup(source_fd), 'rb') as source, os.fdopen(os.dup(target_fd), 'wb') as target:
            shutil.copyfileobj(source, target)
    return True


def collect(evidence):
    evidence.mkdir(exist_ok=True)
    copied = []
    with contextlib.ExitStack() as stack:
        root_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, root_fd)
        # Existing paths, including directory symlinks, fail closed before copying.
        os.mkdir('upload', mode=0o700, dir_fd=root_fd)
        upload_fd = os.open('upload', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        stack.callback(os.close, upload_fd)
        for name in LOGS:
            if copy_evidence_file(root_fd, upload_fd, Path(name)):
                copied.append(name)
        logs = evidence/'private-data'/'logs'
        if not (evidence/'private-data').is_symlink() and not logs.is_symlink():
            for path in logs.glob('pair-*.start.log'):
                if copy_evidence_file(root_fd, upload_fd, path.relative_to(evidence)):
                    copied.append(path.name)
        # Explicit filenames only: never traverse identity/data/token trees.
        collection_fd = os.open('collection.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=upload_fd)
        with os.fdopen(collection_fd, 'w') as stream:
            json.dump({'copied': copied, 'product_receipt_present': 'worker-receipt.json' in copied},
                      stream, indent=2)


if __name__ == '__main__':
    mode, evidence = sys.argv[1], Path(sys.argv[2]).resolve()
    if mode == 'prepare':
        prepare(evidence)
    elif mode == 'supervise':
        raise SystemExit(supervise(evidence, *sys.argv[3:]))
    elif mode == 'worker':
        raise SystemExit(worker(evidence, sys.argv[3]))
    elif mode == 'collect':
        collect(evidence)
    else:
        raise SystemExit('unknown mode')
