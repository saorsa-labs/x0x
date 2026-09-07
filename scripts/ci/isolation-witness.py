#!/usr/bin/env python3
"""Synthetic-only Linux admission control. Never starts a product binary."""
import errno
import json
import os
from pathlib import Path
import socket
import signal
import tempfile
import time
import subprocess
import sys


def loopback(family, address):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(family, kind) as server, socket.socket(family, kind) as client:
            server.bind((address, 0))
            server.settimeout(2)
            client.settimeout(2)
            if kind == socket.SOCK_STREAM:
                server.listen(1)
                client.connect(server.getsockname())
                with server.accept()[0] as accepted:
                    accepted.settimeout(2)
                    client.sendall(b'owned-loopback')
                    assert accepted.recv(64) == b'owned-loopback'
                    accepted.sendall(b'reply')
                    assert client.recv(64) == b'reply'
            else:
                client.sendto(b'owned-loopback', server.getsockname())
                payload, peer = server.recvfrom(64)
                assert payload == b'owned-loopback'
                server.sendto(b'reply', peer)
                assert client.recv(64) == b'reply'


def inside(host_ports, expected_namespace=None):
    current = os.readlink('/proc/self/ns/net')
    if expected_namespace is not None:
        assert current == expected_namespace
    for family, address, external in ((socket.AF_INET, '127.0.0.1', '192.0.2.1'),
                                      (socket.AF_INET6, '::1', '2001:db8::1')):
        loopback(family, address)
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(family, kind) as client:
                client.settimeout(1)
                try:
                    if kind == socket.SOCK_STREAM:
                        client.connect((external, 9))
                    else:
                        client.sendto(b'no-route', (external, 9))
                except OSError as error:
                    assert error.errno == errno.ENETUNREACH, error
                else:
                    raise AssertionError('documentation-address egress unexpectedly succeeded')
            port = host_ports[f'{family}:{kind}']
            with socket.socket(family, kind) as client:
                client.settimeout(1)
                if kind == socket.SOCK_STREAM:
                    try:
                        client.connect((address, port))
                    except OSError as error:
                        assert error.errno == errno.ECONNREFUSED, error
                    else:
                        raise AssertionError('host namespace TCP endpoint reached')
                else:
                    client.sendto(b'host-must-not-receive', (address, port))
    # No CAP_SYS_ADMIN to create/rejoin a namespace after dropping privileges.
    denied = subprocess.run(['/usr/bin/unshare', '--net', '/bin/true'], capture_output=True)
    assert denied.returncode != 0
    print(json.dumps({'namespace': current, 'loopback_v4_v6_tcp_udp': 'pass',
                      'nonloopback_v4_v6_tcp_udp': 'unreachable', 'unprivileged_unshare': 'denied'}), flush=True)
    return current


def wait_for(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError('bounded synthetic control did not complete')


def held_writer(fifo, ready, grandchild=False):
    if grandchild:
        descriptor = int(fifo)
        Path(ready).write_text('grandchild ready')
    else:
        descriptor = os.open(fifo, os.O_WRONLY)
        subprocess.Popen([sys.executable, __file__, '--grandchild', str(descriptor), ready],
                         pass_fds=(descriptor,))
    # Both processes retain the FIFO writer for their whole lifetime. EOF in
    # the host witness proves both are gone; neither voluntarily closes it.
    while True:
        time.sleep(60)


def cancellation(signum):
    scratch = Path(tempfile.mkdtemp(prefix='x0x-cancel-witness-', dir=os.environ['RUNNER_TEMP']))
    fifo = scratch / 'alive.fifo'
    ready = scratch / 'ready'
    os.mkfifo(fifo, 0o600)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    wrapper = Path(__file__).with_name('isolated-runtime.py')
    with (scratch / 'wrapper.stdout').open('w') as output, (scratch / 'wrapper.stderr').open('w') as error:
        child = subprocess.Popen([sys.executable, str(wrapper), sys.executable,
            str(Path(__file__).resolve()), '--held-writer', str(fifo), str(ready)],
            stdout=output, stderr=error)
        try:
            wait_for(ready.exists, 15)
            # The expected EAGAIN proves live writer(s), rather than vacuous EOF.
            try:
                os.read(reader, 1)
            except BlockingIOError:
                pass
            else:
                raise AssertionError('child/grandchild lifetime witness has no writer')
            assert child.poll() is None
            child.send_signal(signum)
            child.wait(timeout=20)
            def all_writers_gone():
                try:
                    return os.read(reader, 1) == b''
                except BlockingIOError:
                    return False
            wait_for(all_writers_gone, 15)
            prefix = 'Isolation evidence: '
            lines = (scratch / 'wrapper.stdout').read_text().splitlines()
            evidence = Path(next(line[len(prefix):] for line in lines if line.startswith(prefix)))
            wait_for((evidence / 'supervisor.json').exists, 10)
            receipt = json.loads((evidence / 'supervisor.json').read_text())
            assert receipt['child_reaped'] and receipt['reason'] == 'caller-pipe-closed', receipt
            print(json.dumps({'cancel_signal': signum, 'wrapper_exit': child.returncode,
                'descendant_writers_closed': True, 'supervisor': receipt}), flush=True)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=20)
            os.close(reader)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('--held-writer', '--grandchild'):
        held_writer(sys.argv[2], sys.argv[3], sys.argv[1] == '--grandchild')
    if len(sys.argv) > 1:
        ports = json.loads(sys.argv[2])
        if sys.argv[1] == '--child':
            inside(ports, sys.argv[3])
        else:
            current = inside(ports)
            subprocess.run([sys.executable, __file__, '--child', sys.argv[2], current], check=True)
        return
    if sys.platform != 'linux':
        raise RuntimeError('Linux-only synthetic control; do not substitute host execution')
    sockets = []
    try:
        ports = {}
        for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                listener = socket.socket(family, kind)
                sockets.append(listener)
                listener.bind((address, 0))
                listener.settimeout(0.1)
                if kind == socket.SOCK_STREAM:
                    listener.listen(4)
                ports[f'{family}:{kind}'] = listener.getsockname()[1]
        subprocess.run([sys.executable, str(Path(__file__).with_name('isolated-runtime.py')),
                        sys.executable, str(Path(__file__).resolve()), '--inside', json.dumps(ports)], check=True, timeout=60)
        for listener in sockets:
            try:
                if listener.type == socket.SOCK_STREAM:
                    connection, _ = listener.accept()
                    connection.close()
                else:
                    listener.recv(256)
            except TimeoutError:
                continue
            raise AssertionError('host witness received cross-namespace traffic')
        # Wrapper must propagate an admitted command's failure, never return green.
        failure = subprocess.run([sys.executable, str(Path(__file__).with_name('isolated-runtime.py')),
                                  '/bin/sh', '-c', 'exit 23'], timeout=20)
        assert failure.returncode == 23, failure.returncode
        cancellation(signal.SIGTERM)
        cancellation(signal.SIGKILL)
        deadline = subprocess.run([sys.executable, str(Path(__file__).with_name('isolated-runtime.py')),
            '/bin/sleep', '60'], env={**os.environ, 'X0X_RUNTIME_TIMEOUT_SECONDS': '1'}, timeout=20)
        assert deadline.returncode == 124, deadline.returncode
        print('PASS: network/inheritance, host zero delivery, exit23, TERM/KILL descendant cleanup', flush=True)
    finally:
        for listener in sockets:
            listener.close()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main()
    else:
        receipt_dir = Path(tempfile.mkdtemp(prefix='x0x-witness-total-', dir=os.environ['RUNNER_TEMP']))
        started = time.monotonic()
        def expired(_number, _frame):
            raise TimeoutError('240s total synthetic witness bound exceeded')
        signal.signal(signal.SIGALRM, expired)
        signal.alarm(240)
        try:
            main()
        except BaseException as error:
            signal.alarm(0)
            # An interrupted subprocess.run kills/reaps its retained caller;
            # allow its EOF-driven privileged monitor's bounded cleanup to
            # finish writing evidence before the failed step uploads receipts.
            time.sleep(10)
            (receipt_dir / 'result.json').write_text(json.dumps({
                'outcome': 'failed', 'error': repr(error),
                'seconds': time.monotonic() - started}) + '\n')
            raise
        else:
            signal.alarm(0)
            (receipt_dir / 'result.json').write_text(json.dumps({
                'outcome': 'passed', 'seconds': time.monotonic() - started}) + '\n')
