#!/usr/bin/env python3
"""Tests for announce_promoted_release.py against a fake x0xd."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("announce_promoted_release.py")

# A stand-in for x0xd: it reads the config the script writes, writes the API
# token, answers /health with a peer count, and answers each
# POST /upgrade/announce with the next scripted reply.
FAKE_X0XD = textwrap.dedent(
    r'''
    import http.server, json, os, re, sys
    from pathlib import Path

    args = sys.argv[1:]
    assert "--skip-update-check" in args, args
    config = Path(args[args.index("--config") + 1]).read_text()
    assert re.search(r"^\[update\]\nenabled = false$", config, re.M), config
    assert "mdns_enabled = false" in config, config
    port = int(re.search(r'api_address = "127\.0\.0\.1:(\d+)"', config).group(1))
    data_dir = Path(re.search(r'data_dir = "([^"]+)"', config).group(1))
    (data_dir / "api-token").write_text("test-token\n")
    scenario = json.loads(Path(os.environ["FAKE_SCENARIO"]).read_text())
    calls = Path(os.environ["FAKE_CALLS"])

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/health":
                self.reply(200, {"ok": True, "peers": scenario["peers"]})
            else:
                self.reply(404, {"ok": False})

        def do_POST(self):
            if self.path != "/upgrade/announce":
                return self.reply(404, {"ok": False})
            assert self.headers["Authorization"] == "Bearer test-token"
            replies = scenario["announce"]
            n = len(calls.read_text().splitlines()) if calls.exists() else 0
            with calls.open("a") as f:
                f.write("announce\n")
            status, body = replies[min(n, len(replies) - 1)]
            self.reply(status, body)

    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
    '''
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ok(result: str, version: str):
    return [200, {"ok": True, "result": result, "version": version, "current_version": "1.2.3"}]


def refused(result: str):
    return [502, {"ok": False, "result": result, "current_version": "1.2.3", "error": "x"}]


class AnnounceTests(unittest.TestCase):
    def run_script(self, peers: int, announce: list) -> tuple[int, str, int]:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            fake = tmp / "x0xd"
            fake.write_text(f"#!{sys.executable}\n{FAKE_X0XD}")
            fake.chmod(0o755)
            scenario = tmp / "scenario.json"
            scenario.write_text(json.dumps({"peers": peers, "announce": announce}))
            calls = tmp / "calls"
            env = dict(
                os.environ,
                FAKE_SCENARIO=str(scenario),
                FAKE_CALLS=str(calls),
                ANNOUNCE_API_PORT=str(free_port()),
                ANNOUNCE_START_WAIT="20",
                ANNOUNCE_PEER_WAIT="3",
                ANNOUNCE_SETTLE="0",
                ANNOUNCE_LINGER="0",
                ANNOUNCE_RETRY_WAIT="0",
                ANNOUNCE_ATTEMPTS="3",
            )
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--x0xd", str(fake), "--version", "1.2.3",
                 "--work-dir", str(tmp / "work")],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            n = len(calls.read_text().splitlines()) if calls.exists() else 0
            return proc.returncode, proc.stdout + proc.stderr, n

    def test_announced_with_the_promoted_version_succeeds(self):
        code, out, calls = self.run_script(3, [ok("announced", "1.2.3")])
        self.assertEqual((code, calls), (0, 1), out)
        self.assertIn("announced on the x0x network", out)

    def test_an_earlier_version_is_not_success_and_is_retried(self):
        code, out, calls = self.run_script(
            3, [ok("already_announced", "1.2.2"), ok("announced", "1.2.3")]
        )
        self.assertEqual((code, calls), (0, 2), out)

    def test_an_earlier_version_on_every_attempt_fails(self):
        code, out, calls = self.run_script(3, [ok("already_announced", "1.2.2")])
        self.assertEqual((code, calls), (1, 3), out)
        self.assertIn("x0x upgrade --announce", out)

    def test_retryable_refusals_are_retried(self):
        code, out, calls = self.run_script(
            3, [refused("fetch_failed"), ok("nothing_newer", "1.2.2"), ok("announced", "1.2.3")]
        )
        self.assertEqual((code, calls), (0, 3), out)

    def test_verification_failure_fails_at_once(self):
        code, out, calls = self.run_script(3, [refused("verification_failed")])
        self.assertEqual((code, calls), (1, 1), out)

    def test_a_binary_without_the_route_skips_cleanly(self):
        code, out, calls = self.run_script(3, [[404, {"ok": False}]])
        self.assertEqual((code, calls), (0, 1), out)
        self.assertIn("no POST /upgrade/announce route", out)

    def test_no_peers_fails_without_announcing(self):
        code, out, calls = self.run_script(0, [ok("announced", "1.2.3")])
        self.assertEqual((code, calls), (1, 0), out)
        self.assertIn("found no peers", out)


if __name__ == "__main__":
    unittest.main()
