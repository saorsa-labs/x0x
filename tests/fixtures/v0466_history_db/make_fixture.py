#!/usr/bin/env python3
"""Write the ADR 0116 slice F history fixture with a released x0xd.

Runs ONE x0xd under a loopback-only macOS sandbox with a scratch HOME,
seeds durable-history rows through the daemon's own local REST API, stops
it with SIGTERM and copies the resulting `history.db`. See PROVENANCE.md.

    python3 make_fixture.py --x0xd <path/to/x0xd> --sandbox <loopback-only.sb> \
        --work <scratch dir> --out <path/to/history.db> [--summary <rows.json>]

The daemon binds 127.0.0.1 only, with no bootstrap peers, mDNS, port mapping,
rendezvous, peer cache or update check. Nothing here downloads anything.
"""

import argparse
import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_PORT = 19707
BIND_PORT = 19587
TOPICS = ["fixture.chat", "fixture.notes"]


def config_toml(data_dir: str) -> str:
    return f"""api_address = "127.0.0.1:{API_PORT}"
bind_address = "127.0.0.1:{BIND_PORT}"
data_dir = "{data_dir}"
identity_dir = "{data_dir}/identity"
log_level = "info"
bootstrap_peers = []
mdns_enabled = false
port_mapping_enabled = false
rendezvous_enabled = false

[history]
enabled = true
record_topics = {json.dumps(TOPICS)}

[update]
enabled = false
"""


class Api:
    def __init__(self, token: str):
        self.base = f"http://127.0.0.1:{API_PORT}"
        self.token = token

    def call(self, method: str, path: str, body=None, raw=False):
        data = None
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None:
            data = body if raw else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode()
                return resp.status, (json.loads(text) if text.strip() else {})
        except urllib.error.HTTPError as err:
            text = err.read().decode()
            return err.code, (json.loads(text) if text.strip().startswith("{") else {"raw": text})

    def ok(self, method: str, path: str, body=None, raw=False):
        status, value = self.call(method, path, body, raw)
        if not 200 <= status < 300:
            raise SystemExit(f"{method} {path} -> {status}: {value}")
        return value


def field(value: dict, name: str):
    if name in value:
        return value[name]
    return value.get("data", {}).get(name)


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def wait_health(deadline_s: float = 60.0):
    url = f"http://127.0.0.1:{API_PORT}/health"
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.5)
    raise SystemExit("x0xd never became healthy")


def seed(api: Api) -> dict:
    me = field(api.ok("GET", "/agent"), "agent_id")
    # Topic rows: this daemon subscribes to its own topics and publishes.
    for topic in TOPICS:
        api.ok("POST", "/subscribe", {"topic": topic})
    time.sleep(1)
    published = [
        ("fixture.chat", "chat one: the quick brown fox"),
        ("fixture.chat", "chat two: lazy dog jumps"),
        ("fixture.chat", "chat three: retained topic text"),
        ("fixture.notes", "note one: searchable fixture note"),
        ("fixture.notes", "note two: another fixture note"),
    ]
    for topic, text in published:
        api.ok("POST", "/publish", {"topic": topic, "payload": b64(text)})
    # Outbound DM rows: a DM to this daemon's own agent id (loopback path).
    for text in ["dm one: hello self", "dm two: durable direct message", "dm three: last"]:
        api.ok("POST", "/direct/send", {"agent_id": me, "payload": b64(text)})
    # Group public messages (signed artifact, canonical projection).
    public = field(api.ok("POST", "/groups", {"name": "fixture-public", "preset": "public_open"}), "group_id")
    for text in ["group one: public fixture message", "group two: canonical id row", "group three: final"]:
        api.ok("POST", f"/groups/{urllib.parse.quote(public, safe='')}/send", {"body": text})
    # MLS group plaintext (no artifact, no canonical projection).
    secure = field(api.ok("POST", "/groups", {"name": "fixture-secure"}), "group_id")
    for text in ["secure one: mls plaintext", "secure two: mls plaintext"]:
        api.ok("POST", f"/groups/{urllib.parse.quote(secure, safe='')}/secure/encrypt", {"payload_b64": b64(text)})
    # Replaceable rows: an agent card (DM scope) and a group card (group scope).
    link = field(api.ok("GET", "/agent/card"), "link")
    api.ok("POST", "/agent/card/import", {"card": link})
    card = api.ok("GET", f"/groups/cards/{urllib.parse.quote(public, safe='')}")
    api.ok("POST", "/groups/cards/import", json.dumps(card).encode(), raw=True)
    return {"agent_id": me, "public_group": public, "secure_group": secure}


def settle(api: Api) -> dict:
    last = None
    for _ in range(60):
        stats = api.ok("GET", "/history/stats")
        if stats == last:
            return stats
        last = stats
        time.sleep(1)
    return last


def summarize(api: Api) -> list:
    scopes = api.ok("GET", "/history/scopes?limit=100").get("scopes", [])
    rows = []
    for entry in scopes:
        scope = entry.get("scope")
        listing = api.ok("GET", "/history?" + urllib.parse.urlencode({"scope": scope, "limit": 100}))
        for record in listing.get("records", []):
            rows.append({k: record.get(k) for k in ("scope", "msg_id", "content_type", "direction", "provenance", "replace_key")})
    return sorted(rows, key=lambda r: (r["scope"] or "", r["msg_id"] or ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--x0xd", required=True)
    ap.add_argument("--sandbox", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--summary")
    args = ap.parse_args()

    work = os.path.abspath(args.work)
    data_dir, home = os.path.join(work, "data"), os.path.join(work, "home")
    for path in (data_dir, home):
        os.makedirs(path, exist_ok=False)
    config = os.path.join(work, "x0xd.toml")
    with open(config, "w") as fh:
        fh.write(config_toml(data_dir))
    log = open(os.path.join(work, "x0xd.log"), "w")
    env = {"PATH": "/usr/bin:/bin", "HOME": home}
    cmd = ["sandbox-exec", "-f", args.sandbox, args.x0xd, "--config", config,
           "--no-hard-coded-bootstrap", "--disable-peer-cache", "--skip-update-check"]
    print("run:", " ".join(cmd), flush=True)
    daemon = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_health()
        token = open(os.path.join(data_dir, "api-token")).read().strip()
        api = Api(token)
        ids = seed(api)
        stats = settle(api)
        rows = summarize(api)
        summary = {"ids": ids, "stats": stats, "rows": rows}
        print(json.dumps({"ids": ids, "rows": len(rows), "stats": stats}, indent=1), flush=True)
        if args.summary:
            with open(args.summary, "w") as fh:
                json.dump(summary, fh, indent=1, sort_keys=True)
    finally:
        daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(timeout=60)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
    print("x0xd exit code:", daemon.returncode, flush=True)
    db = os.path.join(data_dir, "history.db")
    for suffix in ("-wal", "-shm", "-journal"):
        side = db + suffix
        if os.path.exists(side) and os.path.getsize(side) > 0:
            raise SystemExit(f"{side} is not empty after shutdown")
    shutil.copyfile(db, args.out)
    print("copied", db, "->", args.out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
