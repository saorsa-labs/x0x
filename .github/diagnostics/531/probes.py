"""Synthetic namespace controls only. No product or public endpoint requests."""
import json
import socket
import subprocess
import sys
import threading

PAYLOAD = b'531-synthetic-only'


def client(family):
    af, host = (socket.AF_INET, '127.0.0.1') if family == '4' else (socket.AF_INET6, '::1')
    result = {'positive': [], 'forbidden_errors': []}
    for port in (29381, 29382):
        with socket.socket(af, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((host, port))
            sock.sendall(PAYLOAD)
            result['positive'].append(sock.recv(128) == PAYLOAD)
    with socket.socket(af, socket.SOCK_DGRAM) as sock:
        if af == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.settimeout(3)
        sock.bind(('0.0.0.0' if family == '4' else '::', 29482))
        result['wildcard_bind'] = sock.getsockname()
        sock.sendto(PAYLOAD, (host, 29481))
        result['positive'].append(sock.recvfrom(128)[0] == PAYLOAD)
        sock.sendto(b'reply-received', (host, 29481))
        # A successful UDP send syscall is NOT proof of delivery under DROP.
        sock.sendto(PAYLOAD, (host, 29483))
    with socket.socket(af, socket.SOCK_STREAM) as sock:
        sock.settimeout(.5)
        try:
            sock.connect((host, 29383))
            raise AssertionError('forbidden TCP connected')
        except OSError as error:
            result['forbidden_errors'].append(type(error).__name__)
    # Connect only: no payload sent to multicast or nonloopback addresses.
    for address, port in [('224.0.0.251', 5353), ('192.0.2.1', 29481)]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.connect((address, port))
                raise AssertionError('nonloopback route unexpectedly available')
            except OSError as error:
                result['forbidden_errors'].append(error.errno)
    assert all(result['positive']), result
    return result


def family_control(family):
    af, host = (socket.AF_INET, '127.0.0.1') if family == '4' else (socket.AF_INET6, '::1')
    sockets = []
    for kind, port in [(socket.SOCK_STREAM, 29381), (socket.SOCK_STREAM, 29382),
                       (socket.SOCK_DGRAM, 29481), (socket.SOCK_STREAM, 29383),
                       (socket.SOCK_DGRAM, 29483)]:
        sock = socket.socket(af, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        address = ('0.0.0.0' if family == '4' else '::') if kind == socket.SOCK_DGRAM else host
        sock.bind((address, port))
        sock.settimeout(4)
        if kind == socket.SOCK_STREAM:
            sock.listen()
        sockets.append(sock)
    observations, errors = [], []

    def serve():
        try:
            for sock in sockets[:2]:
                conn, _ = sock.accept()
                with conn:
                    body = conn.recv(128)
                    observations.append(body == PAYLOAD)
                    conn.sendall(body)
            body, peer = sockets[2].recvfrom(128)
            observations.append(body == PAYLOAD)
            sockets[2].sendto(body, peer)
            observations.append(sockets[2].recvfrom(128)[0] == b'reply-received')
        except Exception as error:
            errors.append(repr(error))

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        child = subprocess.run([sys.executable, __file__, 'client', family],
                               capture_output=True, text=True, timeout=15, close_fds=True)
        worker.join(5)
        counters = {'tcp': 0, 'udp': 0}
        for sock, kind in zip(sockets[3:], ('tcp', 'udp')):
            sock.settimeout(.2)
            try:
                if kind == 'tcp':
                    conn, _ = sock.accept()
                    conn.close()
                else:
                    sock.recvfrom(128)
                counters[kind] += 1
            except socket.timeout:
                pass
        result = {'family': family, 'child_exit': child.returncode, 'child_stdout': child.stdout,
                  'child_stderr': child.stderr, 'server_positive': observations,
                  'server_errors': errors, 'forbidden_counters': counters}
        assert child.returncode == 0 and observations == [True]*4 and not errors, result
        assert counters == {'tcp': 0, 'udp': 0}, result
        return result
    finally:
        for sock in sockets:
            sock.close()
        worker.join(5)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        print(json.dumps(client(sys.argv[2])))
    else:
        print(json.dumps([family_control('4'), family_control('6')]))
