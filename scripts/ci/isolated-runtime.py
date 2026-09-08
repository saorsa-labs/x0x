#!/usr/bin/env python3
"""Run CI tests in a fresh Linux network/PID/mount namespace, never host fallback."""
import json
import os
from pathlib import Path
import shutil
import select
import signal
import time
import subprocess
import sys
import tempfile

# Preserve toolchain/instrumentation, not proxy credentials or host agent sockets.
ENV_KEYS = (
    'PATH', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'CARGO_TARGET_DIR',
    'CARGO_TERM_COLOR', 'RUST_BACKTRACE', 'RUSTFLAGS', 'RUSTDOCFLAGS',
    'CARGO_ENCODED_RUSTFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC', 'RUSTDOC',
    'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'LLVM_PROFILE_FILE',
    'CARGO_INCREMENTAL', 'CARGO_LLVM_COV', 'CARGO_LLVM_COV_TARGET_DIR', 'CARGO_LLVM_COV_BUILD_DIR',
    'LLVM_COV', 'LLVM_PROFDATA',
)


def checked(*args):
    return subprocess.check_output(args, text=True).strip()


def namespace_state(parent):
    current = os.readlink('/proc/self/ns/net')
    if current == parent:
        raise RuntimeError('network namespace did not change')
    links = json.loads(checked('/usr/sbin/ip', '-j', 'link'))
    if [link['ifname'] for link in links] != ['lo']:
        raise RuntimeError(f'foreign interfaces: {links}')
    routes = {family: json.loads(checked('/usr/sbin/ip', family, '-j', 'route',
                                       'show', 'table', 'all'))
              for family in ('-4', '-6')}
    if any(row.get('dev') != 'lo' or row.get('dst') == 'default' or 'gateway' in row
           for rows in routes.values() for row in rows):
        raise RuntimeError(f'foreign route: {routes}')
    return dict(namespace=current, links=links, routes=routes)


def admitted(config):
    state = namespace_state(config['parent_netns'])
    state['namespace_changed'] = True
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if os.getuid() != config['uid'] or os.geteuid() == 0 or os.getgroups():
        raise RuntimeError('runtime did not drop to the unprivileged owner')
    for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        if int(status[key].strip(), 16):
            raise RuntimeError(f'{key} is not empty')
    if status['NoNewPrivs'].strip() != '1':
        raise RuntimeError('no_new_privs is not set')
    state.update(uid=os.getuid(), gid=os.getgid(), capabilities={
        key: status[key].strip() for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')},
        no_new_privs=1)
    (Path(config['evidence']) / 'admission.json').write_text(json.dumps(state, indent=2) + '\n')
    if config.get('role'):
        (Path(config['evidence']) / 'role.json').write_text(json.dumps({
            'role': config['role'], 'scratch': config.get('scratch')
        }) + '\n')
    result = subprocess.run(config['command'], env=config['env'], close_fds=True)
    (Path(config['evidence']) / 'exit.json').write_text(json.dumps({'exit': result.returncode}) + '\n')
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def setup(config_file):
    config = json.loads(Path(config_file).read_text())
    if os.getuid() != 0:
        raise RuntimeError('namespace setup requires root')
    namespace_state(config['parent_netns'])
    subprocess.run(['/usr/bin/mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=1777,nosuid,nodev',
                    'tmpfs', '/tmp'], check=True)
    for name in ('/tmp/x0x-nextest-home', '/tmp/x0x-runtime-home', '/tmp/x0x-runtime-tmp'):
        Path(name).mkdir(mode=0o700)
        os.chown(name, config['uid'], config['gid'])
    subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], check=True)
    namespace_state(config['parent_netns'])
    os.execv('/usr/bin/setpriv', [
        'setpriv', f"--reuid={config['uid']}", f"--regid={config['gid']}", '--clear-groups',
        '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
        '/usr/bin/python3', str(Path(__file__).resolve()), '--admitted', config_file])


def supervise(config_file):
    """Root monitor: caller pipe EOF, deadline or signals cancel our child only."""
    config = json.loads(Path(config_file).read_text())
    if os.getuid() != 0:
        raise RuntimeError('supervisor requires root')
    cancelled = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda number, _frame: cancelled.append(number))
    child = subprocess.Popen([
        '/usr/bin/unshare', '--net', '--mount', '--pid', '--fork', '--kill-child',
        '--mount-proc', '/usr/bin/python3', str(Path(__file__).resolve()),
        '--setup', config_file], stdin=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    started = time.monotonic()
    reason = None
    try:
        while child.poll() is None:
            if cancelled:
                reason = 'signal'
                break
            if time.monotonic() - started >= config['timeout_seconds']:
                reason = 'deadline'
                break
            if select.select([sys.stdin], [], [], 0.1)[0] and not os.read(0, 1):
                reason = 'caller-pipe-closed'
                break
    finally:
        # poll() may reap an already-exited leader. Never signal it afterward.
        # While unreaped, its PID/session identity cannot be reused. Namespace
        # init inherits this session; killing init removes all its descendants.
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        else:
            child.wait()
        receipt = Path(config['evidence']) / 'supervisor.json'
        receipt.write_text(json.dumps(dict(reason=reason, child_pid=child.pid,
            child_exit=child.returncode, child_reaped=True,
            seconds=time.monotonic() - started)) + '\n')
        os.chown(receipt, config['uid'], config['gid'])
    if reason == 'deadline':
        return 124
    if reason is not None:
        return 125
    return child.returncode if child.returncode >= 0 else 128 - child.returncode


def caller(config_file):
    """Own sudo's lifetime; pipe EOF also covers uncatchable caller SIGKILL."""
    interrupted = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda number, _frame: interrupted.append(number))
    child = subprocess.Popen([
        '/usr/bin/sudo', '-n', '/usr/bin/python3', str(Path(__file__).resolve()),
        '--supervise', str(config_file)], stdin=subprocess.PIPE, close_fds=True)
    try:
        while child.poll() is None:
            if interrupted:
                break
            time.sleep(0.1)
    finally:
        child.stdin.close()
        # The privileged monitor owns escalation; do not signal root/reused PIDs.
        child.wait(timeout=15)
    return 128 + interrupted[0] if interrupted else child.returncode


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--supervise':
        return supervise(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == '--setup':
        setup(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == '--admitted':
        return admitted(json.loads(Path(sys.argv[2]).read_text()))
    if sys.platform != 'linux' or os.getuid() == 0:
        raise RuntimeError('requires a Linux unprivileged runner with sudo for namespace setup')
    command = sys.argv[1:]
    if not command:
        raise RuntimeError('a command is required')
    for tool in ('/usr/bin/sudo', '/usr/bin/unshare', '/usr/bin/setpriv', '/usr/sbin/ip', '/usr/bin/mount'):
        if not Path(tool).is_file():
            raise RuntimeError(f'missing namespace prerequisite: {tool}')
    # Resolve once before changing HOME/PATH; no shell evaluation of test arguments.
    command[0] = shutil.which(command[0]) or command[0]
    env = {key: os.environ[key] for key in ENV_KEYS if key in os.environ}
    env.setdefault('CARGO_HOME', str(Path.home() / '.cargo'))
    env.setdefault('RUSTUP_HOME', str(Path.home() / '.rustup'))
    env.update(HOME='/tmp/x0x-runtime-home', X0X_HOME='/tmp/x0x-runtime-home',
               TMPDIR='/tmp/x0x-runtime-tmp', CARGO_NET_OFFLINE='true', RUST_MIN_STACK='16777216')
    evidence = Path(tempfile.mkdtemp(prefix='x0x-isolation-', dir=os.environ['RUNNER_TEMP'])).resolve()
    if evidence.is_relative_to('/tmp'):
        raise RuntimeError('RUNNER_TEMP must remain visible outside private /tmp')
    role = os.environ.get('X0X_ISOLATION_ROLE')
    scratch = os.environ.get('X0X_CUSTODY_SCRATCH')
    config = dict(command=command, env=env, uid=os.getuid(), gid=os.getgid(),
                  parent_netns=os.readlink('/proc/self/ns/net'), evidence=str(evidence),
                  timeout_seconds=int(os.environ.get('X0X_RUNTIME_TIMEOUT_SECONDS', '21600')))
    if role:
        config.update(role=role, scratch=Path(scratch).name if scratch else None)
    if not 1 <= config['timeout_seconds'] <= 21600:
        raise RuntimeError('runtime deadline must be1..21600 seconds')
    config_file = evidence / 'runtime.json'
    config_file.write_text(json.dumps(config, indent=2) + '\n')
    print(f'Isolation evidence: {evidence}', flush=True)
    return caller(config_file)


if __name__ == '__main__':
    sys.exit(main())
