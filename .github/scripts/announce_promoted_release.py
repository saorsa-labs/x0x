#!/usr/bin/env python3
"""Announce a promoted release on the x0x network from a short-lived node (#1169 PR 2).

Starts the promoted release's own x0xd with a fresh identity and self-update
off, waits for it to join the network, calls `POST /upgrade/announce`, and
checks that the answer names the promoted version. The route answers
`already_announced` from a time-keyed record before it fetches anything, so
that answer can carry an earlier version: the version in the body is
compared, never the result alone.

Exit status: 0 when the promoted version was announced, or when the binary has
no announce route (a release older than #1169 PR 1); 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ANNOUNCED = {"announced", "already_announced"}
# Answers that a later attempt can change: GitHub's latest release may still
# point at the previous release just after promotion, the fetch can hit a
# rate limit, and a publish can time out.
RETRYABLE = {"fetch_failed", "nothing_newer", "publish_failed"}


def report(level: str, message: str) -> None:
    """Print a workflow annotation and add the outcome to the job summary."""
    print(f"::{level}::{message}", flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"{message}\n")


def env_seconds(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def request(url: str, token: str | None = None, method: str = "GET", timeout: float = 10):
    """Return (status, parsed JSON or None); status 0 means no answer."""
    req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    except (urllib.error.URLError, OSError):
        return 0, None
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, None


def write_config(work: Path, api_port: int) -> Path:
    config = work / "config.toml"
    config.write_text(
        f'instance_name = "release-announce"\n'
        'network_id = "x0x.prod"\n'
        f'data_dir = "{work}"\n'
        f'identity_dir = "{work / "identity"}"\n'
        f'api_address = "127.0.0.1:{api_port}"\n'
        "mdns_enabled = false\n"
        'log_level = "info"\n'
        "\n[update]\n"
        "enabled = false\n"
    )
    return config


def wait_for(predicate, deadline_s: float, poll_s: float):
    deadline = time.monotonic() + deadline_s
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            return None
        time.sleep(poll_s)


def judge(status: int, body, expected: str) -> str:
    """Classify one announce answer: 'ok', 'absent', 'retry' or 'fail'."""
    if status == 404:
        return "absent"
    if not isinstance(body, dict):
        return "retry" if status in (0, 502, 503) else "fail"
    result = body.get("result")
    if result in ANNOUNCED:
        return "ok" if body.get("version") == expected else "retry"
    if result in RETRYABLE:
        return "retry"
    return "fail"


def announce(api: str, token: str, expected: str) -> int:
    attempts = int(os.environ.get("ANNOUNCE_ATTEMPTS", 3))
    retry_wait = env_seconds("ANNOUNCE_RETRY_WAIT", 305)
    for attempt in range(1, attempts + 1):
        status, body = request(f"{api}/upgrade/announce", token, method="POST", timeout=60)
        print(f"attempt {attempt}: HTTP {status} {json.dumps(body)}", flush=True)
        verdict = judge(status, body, expected)
        if verdict == "ok":
            report("notice", f"Release {expected} announced on the x0x network ({body['result']}).")
            return 0
        if verdict == "absent":
            report(
                "notice",
                "This release's x0xd has no POST /upgrade/announce route "
                "(older than #1169 PR 1); nothing announced.",
            )
            return 0
        if verdict == "fail":
            break
        if attempt < attempts:
            # A successful announce of another version is refused for the
            # 300 s rebroadcast interval; wait past it before trying again.
            print(f"retrying in {retry_wait:.0f} s", flush=True)
            time.sleep(retry_wait)
    report(
        "error",
        f"Release {expected} was not announced. Run `x0x upgrade --announce` "
        "on a node that can reach the network.",
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--x0xd", required=True, type=Path)
    parser.add_argument("--version", required=True, help="promoted version, without the v")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()

    work = args.work_dir or Path(tempfile.mkdtemp(prefix="x0x-announce-"))
    work.mkdir(parents=True, exist_ok=True)
    api_port = int(os.environ.get("ANNOUNCE_API_PORT", 12600))
    config = write_config(work, api_port)
    api = f"http://127.0.0.1:{api_port}"
    log_path = work / "x0xd.log"

    with open(log_path, "wb") as log:
        daemon = subprocess.Popen(
            [str(args.x0xd), "--config", str(config), "--skip-update-check"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    code = 1
    try:
        health = wait_for(
            lambda: request(f"{api}/health")[1], env_seconds("ANNOUNCE_START_WAIT", 60), 1
        )
        token_file = work / "api-token"
        token = wait_for(
            lambda: token_file.exists() and token_file.read_text().strip(),
            env_seconds("ANNOUNCE_START_WAIT", 60),
            1,
        )
        if not health or not token:
            report("error", "x0xd did not start.")
            return 1
        # `send_ready_peers` counts peers this node can publish to; `peers`
        # can include connections that are not yet usable for gossip.
        peers = wait_for(
            lambda: (request(f"{api}/health")[1] or {}).get("send_ready_peers", 0) or None,
            env_seconds("ANNOUNCE_PEER_WAIT", 180),
            2,
        )
        if not peers:
            report(
                "error",
                "The announce node found no send-ready peers (hosted runners may not reach "
                "the network over UDP). Run `x0x upgrade --announce` on a node that can.",
            )
            return 1
        print(f"{peers} send-ready peer(s)", flush=True)
        # Topic membership follows the first connections by a few seconds.
        time.sleep(env_seconds("ANNOUNCE_SETTLE", 20))
        code = announce(api, token, args.version)
        if code == 0:
            # Peers that heard only a lazy announcement pull the payload
            # from this node, so it stays up a little longer.
            time.sleep(env_seconds("ANNOUNCE_LINGER", 60))
        return code
    finally:
        daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(timeout=30)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
        if code != 0:
            tail = log_path.read_bytes()[-8000:].decode(errors="replace")
            print("---- x0xd log (tail) ----\n" + tail)


if __name__ == "__main__":
    sys.exit(main())
