#!/usr/bin/env python3
"""ADR 0116 slice F: the scripted local downgrade proof (see PROVENANCE.md).

Upgrade the released v0.46.6 fixture, trim it, open it with the released
v0.46.6 x0xd, then upgrade again. Every daemon runs under a loopback-only
macOS sandbox with a scratch HOME; nothing is downloaded.

  S1 upgrade:   the NEW x0xd opens the fixture, `POST /history/retain` trims
                it under ADR 0116 rules, and the rules suppress a DM and an
                ephemeral topic message.
  S2 downgrade: the RELEASED v0.46.6 x0xd opens the trimmed file with the
                same config. It serves every retained row, has no
                `/history/policy` or `/history/retain`, and records exactly
                what the new rules suppress: explicit loss of new-policy
                enforcement.
  S3 upgrade:   the NEW x0xd opens it again. Every row is still there; the
                trim enforces the budgets again.
  S4 newer:     a schema-5 copy is refused by both binaries; the file is
                hashed before and after.

After S1, S2 and S3 the file is checked by the Rust verifier
(`--verify`, run with `X0X_F_VERIFY_DB=<db>`): schema 4, the v0.46.6 schema
objects, FTS integrity, canonical consistency.

    python3 downgrade_proof.py --new-x0xd <x0xd> --old-x0xd <v0.46.6 x0xd> \
        --sandbox <loopback-only.sb> --fixture history.db --work <scratch> \
        --verify '<command that runs verify_history_db_from_env>'
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_PORT = 19708
BIND_PORT = 19588
RECORD_TOPICS = ["fixture.chat", "fixture.notes", "fixture.quiet"]


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
record_topics = {json.dumps(RECORD_TOPICS)}
dm_recording = "ephemeral"

[[history.class_limits]]
class = "replaceable"
max_bytes = 1

[[history.topic_rules]]
prefix = "fixture.chat"
max_bytes = 31

[[history.topic_rules]]
prefix = "fixture.quiet"
recording = "ephemeral"

[update]
enabled = false
"""


class Daemon:
    def __init__(self, binary, sandbox, work, label):
        self.binary, self.sandbox, self.work, self.label = binary, sandbox, work, label
        self.data_dir = os.path.join(work, "data")
        self.home = os.path.join(work, "home")
        self.config = os.path.join(work, "x0xd.toml")
        self.proc = None
        self.token = None

    def start(self, expect_healthy=True):
        os.makedirs(self.home, exist_ok=True)
        with open(self.config, "w") as fh:
            fh.write(config_toml(self.data_dir))
        log = open(os.path.join(self.work, f"x0xd-{self.label}.log"), "w")
        cmd = ["sandbox-exec", "-f", self.sandbox, self.binary, "--config", self.config,
               "--no-hard-coded-bootstrap", "--disable-peer-cache", "--skip-update-check"]
        env = {"PATH": "/usr/bin:/bin", "HOME": self.home}
        self.proc = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
        end = time.time() + 60
        while time.time() < end:
            if self.proc.poll() is not None:
                if expect_healthy:
                    raise SystemExit(f"[{self.label}] x0xd exited {self.proc.returncode} at start")
                return self.proc.returncode
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{API_PORT}/health", timeout=2) as r:
                    if r.status == 200:
                        self.token = open(os.path.join(self.data_dir, "api-token")).read().strip()
                        if not expect_healthy:
                            raise SystemExit(f"[{self.label}] x0xd started on a newer schema")
                        return 0
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(0.5)
        raise SystemExit(f"[{self.label}] x0xd never became healthy")

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        db = os.path.join(self.data_dir, "history.db")
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db + suffix) and os.path.getsize(db + suffix) > 0:
                raise SystemExit(f"[{self.label}] {db}{suffix} not empty after shutdown")
        return self.proc.returncode

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {self.token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"http://127.0.0.1:{API_PORT}{path}", data=data,
                                     method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode()
                return resp.status, (json.loads(text) if text.strip() else {})
        except urllib.error.HTTPError as err:
            text = err.read().decode()
            try:
                return err.code, json.loads(text)
            except ValueError:
                return err.code, {"raw": text}

    def ok(self, method, path, body=None):
        status, value = self.call(method, path, body)
        if not 200 <= status < 300:
            raise SystemExit(f"[{self.label}] {method} {path} -> {status}: {value}")
        return value


def b64(text):
    return base64.b64encode(text.encode()).decode()


def field(value, name):
    return value[name] if name in value else value.get("data", {}).get(name)


def scope_rows(d, scope):
    query = urllib.parse.urlencode({"scope": scope, "limit": 100})
    return d.ok("GET", f"/history?{query}").get("records", [])


def stats(d):
    return d.ok("GET", "/history/stats")["stats"]


def settle(d):
    last = None
    for _ in range(30):
        now = stats(d)
        if now == last:
            return now
        last = now
        time.sleep(1)
    return last


def write_suppressible(d, me, tag):
    """A DM and an ephemeral-topic message, which ADR 0116 rules suppress."""
    d.ok("POST", "/direct/send", {"agent_id": me, "payload": b64(f"dm written by {tag}")})
    d.ok("POST", "/subscribe", {"topic": "fixture.quiet"})
    time.sleep(1)
    d.ok("POST", "/publish", {"topic": "fixture.quiet", "payload": b64(f"quiet written by {tag}")})


def check(cond, message, log):
    log.append(("PASS" if cond else "FAIL") + ": " + message)
    print(log[-1], flush=True)
    if not cond:
        raise SystemExit(message)


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def verify(command, db, log):
    env = dict(os.environ, X0X_F_VERIFY_DB=db)
    out = subprocess.run(command, shell=True, env=env, capture_output=True, text=True)
    line = next((l for l in out.stdout.splitlines() if "X0X_F_VERIFY " in l), None)
    check(out.returncode == 0 and line is not None,
          f"Rust verifier on {os.path.basename(os.path.dirname(os.path.dirname(db)))}: "
          f"schema 4, v0.46.6 schema objects, FTS integrity, canonical consistency",
          log)
    facts = json.loads(line.split("X0X_F_VERIFY ", 1)[1])
    print(json.dumps(facts, indent=1), flush=True)
    return facts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-x0xd", required=True)
    ap.add_argument("--old-x0xd", required=True)
    ap.add_argument("--sandbox", required=True)
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--verify", required=True)
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=False)
    log, facts = [], {}
    run = os.path.join(work, "run")
    os.makedirs(os.path.join(run, "data"))
    db = os.path.join(run, "data", "history.db")
    shutil.copyfile(args.fixture, db)
    check(sha256(db) == sha256(args.fixture), "S0: the run starts from the released fixture", log)

    # S1: upgrade, trim, new rules suppress writes.
    new = Daemon(args.new_x0xd, args.sandbox, run, "S1-new")
    new.start()
    me = field(new.ok("GET", "/agent"), "agent_id")
    check(stats(new)["rows"] == 15, "S1: the new x0xd serves all 15 released rows", log)
    status, policy = new.call("GET", "/history/policy")
    check(status == 200, "S1: GET /history/policy is served", log)
    report = new.ok("POST", "/history/retain", {})
    print("S1 retain:", json.dumps(report), flush=True)
    check(report["deleted"] == 4 and report["state"] == "complete",
          "S1: the trim deletes the two oldest chat rows and both cards, then is complete", log)
    write_suppressible(new, me, "the new x0xd")
    time.sleep(2)
    check(scope_rows(new, f"dm:{me}") == [] and scope_rows(new, "topic:fixture.quiet") == [],
          "S1: dm_recording = ephemeral and the ephemeral topic rule store nothing", log)
    s1 = settle(new)
    check(s1["rows"] == 11, "S1: 11 rows after the trim", log)
    check(new.stop() == 0, "S1: the new x0xd stops cleanly", log)
    facts["S1"] = verify(args.verify, db, log)

    # S2: downgrade to the released binary with the same config.
    old = Daemon(args.old_x0xd, args.sandbox, run, "S2-old")
    old.start()
    check(stats(old)["rows"] == 11, "S2: v0.46.6 opens the trimmed file and serves its 11 rows", log)
    hits = old.ok("GET", "/history/search?" + urllib.parse.urlencode({"q": "retained"})).get("records", [])
    check(len(hits) == 1, "S2: v0.46.6 full-text search serves the retained chat row", log)
    check(old.call("GET", "/history/policy")[0] == 404, "S2: v0.46.6 has no /history/policy", log)
    check(old.call("POST", "/history/retain", {})[0] in (404, 405), "S2: v0.46.6 has no /history/retain", log)
    write_suppressible(old, me, "v0.46.6")
    old.ok("POST", "/subscribe", {"topic": "fixture.chat"})
    time.sleep(1)
    old.ok("POST", "/publish", {"topic": "fixture.chat", "payload": b64("chat four: v0.46.6 over budget")})
    old.ok("POST", "/publish", {"topic": "fixture.chat", "payload": b64("chat five: also over budget")})
    time.sleep(2)
    s2 = settle(old)
    check(len(scope_rows(old, f"dm:{me}")) == 1 and len(scope_rows(old, "topic:fixture.quiet")) == 1,
          "S2: v0.46.6 records the DM and the ephemeral-topic message the new rules suppress", log)
    check(len(scope_rows(old, "topic:fixture.chat")) == 3,
          "S2: v0.46.6 does not apply the 31-byte topic budget", log)
    check(s2["rows"] == 15, "S2: 15 rows after the downgrade writes", log)
    check(old.stop() == 0, "S2: v0.46.6 stops cleanly", log)
    facts["S2"] = verify(args.verify, db, log)

    # S3: upgrade again.
    new = Daemon(args.new_x0xd, args.sandbox, run, "S3-new")
    new.start()
    check(stats(new)["rows"] == 15, "S3: the new x0xd opens it again and serves all 15 rows", log)
    report = new.ok("POST", "/history/retain", {})
    print("S3 retain:", json.dumps(report), flush=True)
    chat = scope_rows(new, "topic:fixture.chat")
    chat_bytes = sum(len(base64.b64decode(r.get("payload_b64") or r.get("payload") or "")) for r in chat)
    check(report["deleted_by_phase"]["topic_budgets"] >= 1 and chat_bytes <= 31,
          f"S3: the topic budget is enforced again ({len(chat)} chat rows, {chat_bytes} bytes)", log)
    check(len(scope_rows(new, f"dm:{me}")) == 1 and len(scope_rows(new, "topic:fixture.quiet")) == 1,
          "S3: rows v0.46.6 recorded stay (recording rules are not retroactive)", log)
    s3 = settle(new)
    check(new.stop() == 0, "S3: the new x0xd stops cleanly", log)
    facts["S3"] = verify(args.verify, db, log)

    # S4: a schema-5 copy, refused by both binaries.
    for label, binary in (("S4-new", args.new_x0xd), ("S4-old", args.old_x0xd)):
        dir5 = os.path.join(work, label)
        os.makedirs(os.path.join(dir5, "data"))
        db5 = os.path.join(dir5, "data", "history.db")
        shutil.copyfile(db, db5)
        conn = sqlite3.connect(db5)
        conn.execute("UPDATE schema_version SET version = 5")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        before = sha256(db5)
        code = Daemon(binary, args.sandbox, dir5, label).start(expect_healthy=False)
        after = sha256(db5)
        text = open(os.path.join(dir5, f"x0xd-{label}.log")).read()
        check(code != 0 and "newer than this binary" in text,
              f"{label}: x0xd refuses schema 5 at start (exit {code})", log)
        facts[label] = {"exit": code, "sha256_before": before, "sha256_after": after,
                        "unchanged": before == after}
        print(f"{label}: file unchanged = {before == after}", flush=True)

    with open(os.path.join(work, "proof.json"), "w") as fh:
        json.dump({"log": log, "facts": facts, "stats": {"S1": s1, "S2": s2, "S3": s3}}, fh,
                  indent=1, sort_keys=True)
    print("\n".join(log))
    return 0


if __name__ == "__main__":
    sys.exit(main())
