#!/usr/bin/env python3
"""Clean-path 2-daemon TreeKEM membership validation (no SSH, no VPS).

Boots alice (anchor) + bob (member) locally with distinct identities, exchanges
agent cards, connects them, then drives e2e_treekem_membership.run_iteration.
Proves the JoinResult Result-variant fix end-to-end on a clean transport.
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

import os as _os
ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from e2e_treekem_membership import X0xClient, run_iteration  # noqa: E402

X0XD = os.path.join(ROOT, "target/release/x0xd")
PORTS = {"alice": 25710, "bob": 25711}
LOGDIR = "/tmp"
RUST_LOG = "x0xd=debug,x0x=info,saorsa_gossip=info,ant_quic=warn"


def token_path(name):
    return os.path.expanduser(
        f"~/Library/Application Support/x0x-{name}/api-token")


def http(method, port, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, r.read().decode()


def main():
    procs = {}
    env = dict(os.environ, RUST_LOG=RUST_LOG)
    for name, port in PORTS.items():
        log = open(f"{LOGDIR}/tk-{name}.log", "w")
        procs[name] = subprocess.Popen(
            [X0XD, "--name", name, "--api-port", str(port),
             "--no-hard-coded-bootstrap"],
            stdout=log, stderr=subprocess.STDOUT, env=env)
    try:
        # health
        deadline = time.time() + 30
        for name, port in PORTS.items():
            while time.time() < deadline:
                try:
                    http("GET", port, "/health", "")
                    break
                except Exception:
                    time.sleep(0.5)
        # tokens
        tok = {}
        for name in PORTS:
            tp = token_path(name)
            while not (os.path.exists(tp) and os.path.getsize(tp) > 0):
                time.sleep(0.3)
            tok[name] = open(tp).read().strip()
        # agent ids + card links (import expects the x0x://agent/... link string)
        aid, link = {}, {}
        for name, port in PORTS.items():
            _, b = http("GET", port, "/agent", tok[name])
            aid[name] = json.loads(b)["agent_id"]
            _, c = http("GET", port, "/agent/card", tok[name])
            link[name] = json.loads(c)["link"]
        # mutual card import
        for src in PORTS:
            for dst in PORTS:
                if src == dst:
                    continue
                http("POST", PORTS[src], "/agent/card/import",
                     tok[src], {"card": link[dst], "trust_level": "known"})
        # connect alice -> bob
        http("POST", PORTS["alice"], "/agents/connect", tok["alice"],
             {"agent_id": aid["bob"]})
        time.sleep(2)

        anchor = X0xClient(f"http://127.0.0.1:{PORTS['alice']}", tok["alice"])
        member = X0xClient(f"http://127.0.0.1:{PORTS['bob']}", tok["bob"])

        # sanity: base DM anchor->member
        try:
            st, _ = http("POST", PORTS["alice"], "/direct/send", tok["alice"],
                         {"agent_id": aid["bob"],
                          "payload": base64.b64encode(b"ping").decode()})
            print(f"base DM alice->bob: {st}", flush=True)
        except Exception as e:
            print(f"base DM alice->bob FAILED: {e}", flush=True)

        iters = int(os.environ.get("X0X_TK_ITERS", "1"))
        passed = 0
        for i in range(1, iters + 1):
            r = run_iteration(anchor, member, aid["bob"], settle_secs=90.0, idx=i)
            status = "PASS" if r.ok else f"FAIL@{r.step}:{r.detail!r}"
            print(f"ITER {i}/{iters} {status} timings={r.timings}", flush=True)
            if r.ok:
                passed += 1
        print(f"RESULT ok={passed == iters} passed={passed}/{iters}", flush=True)
        return 0 if passed == iters else 1
    finally:
        for p in procs.values():
            p.terminate()
        time.sleep(1)
        for p in procs.values():
            p.kill()


if __name__ == "__main__":
    sys.exit(main())
