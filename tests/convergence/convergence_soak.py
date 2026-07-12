#!/usr/bin/env python3
"""Three-node local convergence soak harness for x0xd.

Repeatable, in-repo version of the ad-hoc three-machine convergence test
that exposed the v0.30.1 defects (restart recovery, claim semantics,
signed-store non-owner writes). Spins N local x0xd instances with isolated
data dirs that bootstrap only to each other, then drives five phases with
independent gates and per-primitive (TaskList vs KV) arrival timing:

  1. cold-join          task+key created on node1 BEFORE peers join
  2. live-propagation   mutation after all peers joined and converged
  3. restart-recovery   node N stopped, creator mutates, node restarted;
                        state must be visible WITHOUT explicit rejoin
  4. concurrent-claims  two peers claim the same task simultaneously
  5. signed-store non-owner write  joiner PUTs to creator's Signed store

GET /diagnostics/gossip is snapshotted on every node before and after each
phase so pubsub admission-counter growth (dropped_critical_hard_error,
cooling) is attributable per phase.

Known-gap phases (current main, pre-fix): restart auto-recovery, structured
claim fields (claimed_by/claimed_at/version), and non-owner PUT returning
200 instead of 403. Without --expect-fixed these are reported as
"known-gap" and do not fail the run; --expect-fixed turns them into hard
gates for verifying the fixes.

Stdlib only (urllib, never curl — curl is intercepted in some environments).

Usage:
  python3 tests/convergence/convergence_soak.py                 # 1 run
  python3 tests/convergence/convergence_soak.py --runs 10       # soak
  python3 tests/convergence/convergence_soak.py --expect-fixed  # post-fix
"""

import argparse
import base64
import concurrent.futures
import json
import os
import pathlib
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_OUT = pathlib.Path(__file__).resolve().parent / "out"

KNOWN_GAP_NOTES = {
    "restart_auto_recovery": (
        "task-list/store subscriptions are not restored after daemon "
        "restart (server handle maps start empty)"
    ),
    "structured_claim_fields": (
        "claim ownership is only encoded in the formatted `state` string; "
        "no claimed_by/claimed_at/version fields"
    ),
    "nonowner_put_rejected": (
        "non-owner PUT to a Signed store returns local 200 and forks "
        "locally instead of being rejected with 403"
    ),
}


# ──────────────────────────────────────────────────────────────────────────
# HTTP helpers (urllib only)
# ──────────────────────────────────────────────────────────────────────────

def http_request(base, path, method="GET", body=None, token=None, timeout=10):
    """Return {'status': int, 'body': parsed-json-or-text}. Raises OSError
    (incl. URLError/ConnectionError) when the daemon is unreachable."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode(errors="replace")
    return {"status": status, "body": parsed}


# ──────────────────────────────────────────────────────────────────────────
# Node lifecycle
# ──────────────────────────────────────────────────────────────────────────

class Node:
    def __init__(self, name, api_port, quic_port, root_dir, x0xd, log_level):
        self.name = name
        self.api_port = api_port
        self.quic_port = quic_port
        self.base = f"http://127.0.0.1:{api_port}"
        self.dir = root_dir / name
        self.data_dir = self.dir / "data"
        self.config_path = self.dir / "config.toml"
        self.log_path = self.dir / "daemon.log"
        self.x0xd = x0xd
        self.log_level = log_level
        self.proc = None
        self.token = None

    def write_config(self, bootstrap_quic_ports):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        peers = ", ".join(f'"127.0.0.1:{p}"' for p in bootstrap_quic_ports)
        self.config_path.write_text(
            f'instance_name = "{self.name}"\n'
            f'data_dir = "{self.data_dir}"\n'
            f'api_address = "127.0.0.1:{self.api_port}"\n'
            f'bind_address = "127.0.0.1:{self.quic_port}"\n'
            f'log_level = "{self.log_level}"\n'
            # Explicit list (possibly empty) overrides the hardcoded global
            # bootstrap network, keeping the cluster fully isolated. Do NOT
            # pass --no-hard-coded-bootstrap: it clears config peers too.
            f'bootstrap_peers = [{peers}]\n'
        )

    def start(self):
        log = open(self.log_path, "a")
        self.proc = subprocess.Popen(
            [str(self.x0xd), "--config", str(self.config_path),
             "--skip-update-check"],
            stdout=log, stderr=subprocess.STDOUT,
            cwd=str(self.dir),
        )
        log.close()

    def wait_ready(self, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"{self.name}: x0xd exited rc={self.proc.returncode} "
                    f"(see {self.log_path})")
            try:
                r = http_request(self.base, "/health", timeout=2)
                if r["status"] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError(f"{self.name}: /health not up in {timeout}s")
        token_file = self.data_dir / "api-token"
        while time.monotonic() < deadline:
            if token_file.exists() and token_file.stat().st_size > 0:
                self.token = token_file.read_text().strip()
                return
            time.sleep(0.3)
        raise RuntimeError(f"{self.name}: api-token not written in {timeout}s")

    def req(self, method, path, body=None, auth=True, timeout=10):
        return http_request(self.base, path, method=method, body=body,
                            token=self.token if auth else None,
                            timeout=timeout)

    def stop(self, grace=8):
        if self.proc is None or self.proc.poll() is not None:
            self.proc = None
            return
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc = None

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None


# ──────────────────────────────────────────────────────────────────────────
# Diagnostics snapshots / deltas
# ──────────────────────────────────────────────────────────────────────────

def gossip_snapshot(nodes):
    snap = {}
    for n in nodes:
        if not n.running:
            snap[n.name] = None
            continue
        try:
            r = n.req("GET", "/diagnostics/gossip")
            snap[n.name] = r["body"] if r["status"] == 200 else None
        except OSError:
            snap[n.name] = None
    return snap


def admission_counters(snapshot_body):
    if not isinstance(snapshot_body, dict):
        return {}
    adm = (snapshot_body.get("pubsub_stages") or {}).get("admission") or {}
    return {k: v for k, v in adm.items() if isinstance(v, (int, float))}


def admission_delta(before, after):
    deltas = {}
    for name in set(before) | set(after):
        b = admission_counters(before.get(name))
        a = admission_counters(after.get(name))
        if not b and not a:
            deltas[name] = None
            continue
        deltas[name] = {k: a.get(k, 0) - b.get(k, 0)
                        for k in sorted(set(a) | set(b))
                        if a.get(k, 0) - b.get(k, 0) != 0}
    return deltas


# ──────────────────────────────────────────────────────────────────────────
# Convergence sampling — per-primitive arrival times
# ──────────────────────────────────────────────────────────────────────────

def sample_until(checks, gate_secs, interval):
    """checks: {metric_name: callable() -> bool}. Samples every `interval`
    seconds until every check has passed once or `gate_secs` elapses.
    Returns {metric_name: arrival_secs_or_None} (arrival measured from the
    first sample loop start)."""
    start = time.monotonic()
    arrivals = {k: None for k in checks}
    while True:
        elapsed = time.monotonic() - start
        for key, fn in checks.items():
            if arrivals[key] is not None:
                continue
            try:
                if fn():
                    arrivals[key] = round(time.monotonic() - start, 2)
            except OSError:
                pass
        if all(v is not None for v in arrivals.values()):
            return arrivals
        if elapsed >= gate_secs:
            return arrivals
        time.sleep(interval)


def task_visible(node, topic, task_id):
    r = node.req("GET", f"/task-lists/{topic}/tasks")
    if r["status"] != 200 or not isinstance(r["body"], dict):
        return False
    return any(t.get("id") == task_id for t in r["body"].get("tasks", []))


def key_visible(node, store, key):
    r = node.req("GET", f"/stores/{store}/{key}")
    return r["status"] == 200 and isinstance(r["body"], dict) \
        and r["body"].get("ok", True)


def get_task(node, topic, task_id):
    r = node.req("GET", f"/task-lists/{topic}/tasks")
    if r["status"] != 200 or not isinstance(r["body"], dict):
        return None
    for t in r["body"].get("tasks", []):
        if t.get("id") == task_id:
            return t
    return None


def b64(value):
    return base64.b64encode(value.encode()).decode()


# ──────────────────────────────────────────────────────────────────────────
# Single run
# ──────────────────────────────────────────────────────────────────────────

class Run:
    def __init__(self, idx, args, run_dir):
        self.idx = idx
        self.args = args
        self.run_dir = run_dir
        tag = f"{int(time.time())}-r{idx}"
        self.topic = f"x0x.convergence.soak.{tag}"
        self.store = f"x0x-convergence-store-{tag}"
        self.nodes = []
        self.report = {
            "run": idx,
            "topic": self.topic,
            "store": self.store,
            "started_unix": time.time(),
            "phases": {},
            "diagnostics_deltas": {},
            "pass": None,
        }
        self.hard_failures = []
        self.known_gaps = []

    # -- helpers -----------------------------------------------------------

    def creator(self):
        return self.nodes[0]

    def phase(self, name):
        """Context manager: snapshots /diagnostics/gossip on all nodes
        before and after the phase body, records the admission delta."""
        run = self

        class _Ctx:
            def __enter__(self):
                self.before = gossip_snapshot(run.nodes)
                self.t0 = time.monotonic()
                return self

            def __exit__(self, exc_type, exc, tb):
                after = gossip_snapshot(run.nodes)
                run.report["diagnostics_deltas"][name] = {
                    "elapsed_secs": round(time.monotonic() - self.t0, 1),
                    "admission_delta": admission_delta(self.before, after),
                    "hard_error_after": {
                        n: admission_counters(after.get(n)).get(
                            "dropped_critical_hard_error")
                        for n in after
                    },
                }
                return False

        return _Ctx()

    def gate(self, phase, ok, detail=None):
        entry = self.report["phases"].setdefault(phase, {})
        entry["pass"] = bool(ok)
        if detail is not None:
            entry.update(detail)
        if not ok:
            self.hard_failures.append(phase)
        return ok

    def known_gap_gate(self, phase, gap_key, fixed, observed):
        """A gate that is a hard requirement only under --expect-fixed.
        `fixed` True means the post-fix behavior was observed."""
        entry = self.report["phases"].setdefault(phase, {})
        entry["observed"] = observed
        if fixed:
            entry["status"] = "fixed"
            entry["pass"] = True
        elif self.args.expect_fixed:
            entry["status"] = "fail"
            entry["pass"] = False
            self.hard_failures.append(phase)
        else:
            entry["status"] = "known-gap"
            entry["pass"] = True  # tolerated pre-fix
            entry["known_gap"] = KNOWN_GAP_NOTES[gap_key]
            self.known_gaps.append(phase)
        return entry["pass"]

    # -- topology ----------------------------------------------------------

    def start_cluster_creator_only(self):
        a = self.args
        for i in range(a.nodes):
            node = Node(
                name=f"conv{i + 1}",
                api_port=a.api_base + i,
                quic_port=a.quic_base + i,
                root_dir=self.run_dir,
                x0xd=a.x0xd,
                log_level=a.log_level,
            )
            # node1 bootstraps to nobody; every other node only to node1.
            node.write_config([] if i == 0 else [a.quic_base])
            self.nodes.append(node)
        creator = self.nodes[0]
        log(f"run {self.idx}: starting {creator.name} "
            f"(api={creator.api_port}, quic={creator.quic_port})")
        creator.start()
        creator.wait_ready()

    def start_peer(self, node):
        log(f"run {self.idx}: starting {node.name} "
            f"(api={node.api_port}, quic={node.quic_port})")
        node.start()
        node.wait_ready()

    # -- phases ------------------------------------------------------------

    def phase_cold_join(self):
        a, creator = self.args, self.creator()
        # Creator state BEFORE any peer exists.
        tl = creator.req("POST", "/task-lists",
                         {"name": "convergence soak", "topic": self.topic})
        task = creator.req("POST", f"/task-lists/{self.topic}/tasks",
                           {"title": "prejoin-task",
                            "description": "must cold-start replicate"})
        st = creator.req("POST", "/stores",
                         {"name": "convergence manifests",
                          "topic": self.store})
        put = creator.req("PUT", f"/stores/{self.store}/prejoin",
                          {"value": b64("prejoin-value"),
                           "content_type": "text/plain"})
        if not all(r["status"] in (200, 201)
                   for r in (tl, task, st, put)):
            raise RuntimeError(
                f"creator setup failed: tl={tl} task={task} st={st} put={put}")
        self.pre_task_id = task["body"]["task_id"]

        per_node = {}
        with self.phase("cold_join"):
            for node in self.nodes[1:]:
                # Rolling start: known requirement — space daemon launches.
                log(f"run {self.idx}: rolling-start wait "
                    f"{a.stagger_secs}s before {node.name}")
                time.sleep(a.stagger_secs)
                self.start_peer(node)
                join_tl = node.req("POST", "/task-lists",
                                   {"name": "convergence soak",
                                    "topic": self.topic})
                join_st = node.req("POST", f"/stores/{self.store}/join")
                arrivals = sample_until(
                    {
                        "task": lambda n=node: task_visible(
                            n, self.topic, self.pre_task_id),
                        "kv": lambda n=node: key_visible(
                            n, self.store, "prejoin"),
                    },
                    gate_secs=a.cold_gate, interval=a.poll_interval)
                per_node[node.name] = {
                    "join_status": {"task_list": join_tl["status"],
                                    "store": join_st["status"]},
                    "task_secs": arrivals["task"],
                    "kv_secs": arrivals["kv"],
                }
        ok = all(v["task_secs"] is not None and v["kv_secs"] is not None
                 for v in per_node.values())
        self.gate("cold_join", ok,
                  {"gate_secs": a.cold_gate, "per_node": per_node})
        log(f"run {self.idx}: cold_join {'PASS' if ok else 'FAIL'} "
            f"{json.dumps(per_node)}")

    def phase_live_propagation(self):
        a, creator = self.args, self.creator()
        with self.phase("live_propagation"):
            task = creator.req("POST", f"/task-lists/{self.topic}/tasks",
                               {"title": "live-task",
                                "description": "created after all joined"})
            live_tid = task["body"]["task_id"]
            creator.req("PUT", f"/stores/{self.store}/live",
                        {"value": b64("live-value"),
                         "content_type": "text/plain"})
            checks = {}
            for node in self.nodes[1:]:
                checks[f"{node.name}.task"] = (
                    lambda n=node: task_visible(n, self.topic, live_tid))
                checks[f"{node.name}.kv"] = (
                    lambda n=node: key_visible(n, self.store, "live"))
            arrivals = sample_until(checks, gate_secs=a.live_gate,
                                    interval=a.poll_interval)
        self.live_task_id = live_tid
        ok = all(v is not None for v in arrivals.values())
        self.gate("live_propagation", ok,
                  {"gate_secs": a.live_gate, "arrivals_secs": arrivals})
        log(f"run {self.idx}: live_propagation {'PASS' if ok else 'FAIL'} "
            f"{json.dumps(arrivals)}")

    def phase_restart_recovery(self):
        a, creator = self.args, self.creator()
        victim = self.nodes[-1]
        with self.phase("restart_recovery"):
            log(f"run {self.idx}: stopping {victim.name}")
            victim.stop()
            time.sleep(3)
            task = creator.req("POST", f"/task-lists/{self.topic}/tasks",
                               {"title": "offline-recovery",
                                "description": "created while peer was down"})
            off_tid = task["body"]["task_id"]
            creator.req("PUT", f"/stores/{self.store}/offline",
                        {"value": b64("offline-value"),
                         "content_type": "text/plain"})
            log(f"run {self.idx}: restarting {victim.name}")
            victim.start()
            victim.wait_ready()
            # No explicit rejoin — this is exactly what the fix must provide.
            arrivals = sample_until(
                {
                    "task": lambda: task_visible(victim, self.topic, off_tid),
                    "kv": lambda: key_visible(victim, self.store, "offline"),
                },
                gate_secs=a.restart_gate, interval=a.poll_interval)
            auto = (arrivals["task"] is not None
                    and arrivals["kv"] is not None)

            rejoin = None
            if not auto:
                # Explicit rejoin (followup.py pattern) so later phases can
                # run; its own convergence is a hard gate either way.
                t0 = time.monotonic()
                victim.req("POST", "/task-lists",
                           {"name": "convergence soak", "topic": self.topic})
                victim.req("POST", f"/stores/{self.store}/join")
                r = sample_until(
                    {
                        "task": lambda: task_visible(
                            victim, self.topic, off_tid),
                        "kv": lambda: key_visible(
                            victim, self.store, "offline"),
                    },
                    gate_secs=a.cold_gate, interval=a.poll_interval)
                rejoin = {
                    "task_secs": r["task"], "kv_secs": r["kv"],
                    "total_secs": round(time.monotonic() - t0, 2),
                }
        observed = {
            "node": victim.name,
            "auto_recovery_arrivals_secs": arrivals,
            "auto_recovery_gate_secs": a.restart_gate,
            "explicit_rejoin": rejoin,
        }
        self.known_gap_gate("restart_recovery", "restart_auto_recovery",
                            fixed=auto, observed=observed)
        if not auto:
            # Eventual convergence via explicit rejoin is ALWAYS a hard gate
            # (acceptance criterion: 100% eventual offline-rejoin).
            ok = (rejoin is not None and rejoin["task_secs"] is not None
                  and rejoin["kv_secs"] is not None)
            self.gate("restart_recovery_eventual", ok,
                      {"explicit_rejoin": rejoin})
        status = self.report["phases"]["restart_recovery"]["status"]
        log(f"run {self.idx}: restart_recovery {status} "
            f"{json.dumps(observed)}")

    def phase_concurrent_claims(self):
        a, creator = self.args, self.creator()
        claimants = self.nodes[1:3]
        with self.phase("concurrent_claims"):
            task = creator.req("POST", f"/task-lists/{self.topic}/tasks",
                               {"title": "claim-target",
                                "description": "two peers claim this"})
            tid = task["body"]["task_id"]
            vis = sample_until(
                {n.name: (lambda n=n: task_visible(n, self.topic, tid))
                 for n in claimants},
                gate_secs=a.live_gate, interval=a.poll_interval)
            if any(v is None for v in vis.values()):
                self.gate("concurrent_claims", False,
                          {"error": "task never visible on claimants",
                           "visibility_secs": vis})
                log(f"run {self.idx}: concurrent_claims FAIL (visibility)")
                return

            barrier = threading.Barrier(len(claimants))

            def do_claim(node):
                barrier.wait(timeout=10)
                return node.req(
                    "PATCH", f"/task-lists/{self.topic}/tasks/{tid}",
                    {"action": "claim"})

            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=len(claimants)) as ex:
                futs = {n.name: ex.submit(do_claim, n) for n in claimants}
                responses = {k: f.result() for k, f in futs.items()}

            t0 = time.monotonic()
            winner, converge_secs, final_tasks = None, None, {}
            while time.monotonic() - t0 < a.claim_gate:
                final_tasks = {n.name: get_task(n, self.topic, tid)
                               for n in self.nodes}
                states = [t.get("state") if t else None
                          for t in final_tasks.values()]
                if (None not in states and len(set(states)) == 1
                        and str(states[0]).startswith("claimed")):
                    converge_secs = round(time.monotonic() - t0, 2)
                    winner = states[0]
                    break
                time.sleep(a.poll_interval)

        structured = {}
        for name, t in final_tasks.items():
            structured[name] = (
                {k: t.get(k) for k in
                 ("claimed_by", "claimed_at", "version") if k in t}
                if isinstance(t, dict) else None)
        has_structured = all(
            isinstance(s, dict) and "claimed_by" in s
            for s in structured.values())

        converged = converge_secs is not None
        self.gate("concurrent_claims", converged, {
            "gate_secs": a.claim_gate,
            "visibility_secs": vis,
            "claim_responses": {k: {"status": v["status"], "body": v["body"]}
                                for k, v in responses.items()},
            "both_accepted_200": all(
                v["status"] == 200 for v in responses.values()),
            "converge_secs": converge_secs,
            "winner_state": winner,
        })
        self.known_gap_gate(
            "concurrent_claims_structured_fields", "structured_claim_fields",
            fixed=has_structured,
            observed={"structured_fields": structured})
        log(f"run {self.idx}: concurrent_claims "
            f"{'PASS' if converged else 'FAIL'} winner={winner!r} "
            f"converge={converge_secs}s structured={has_structured}")

    def phase_signed_store_nonowner(self):
        a, creator = self.args, self.creator()
        writer = self.nodes[1]
        with self.phase("signed_store_nonowner_write"):
            put = writer.req("PUT", f"/stores/{self.store}/unauthorized",
                             {"value": b64("intruder-value"),
                              "content_type": "text/plain"})
            local = writer.req("GET", f"/stores/{self.store}/unauthorized")
            # Observe the fork window: the key must never become visible on
            # the creator (owner-side inbound enforcement).
            deadline = time.monotonic() + a.fork_window
            propagated = False
            while time.monotonic() < deadline:
                if key_visible(creator, self.store, "unauthorized"):
                    propagated = True
                    break
                time.sleep(a.poll_interval)
        rejected = put["status"] == 403
        local_fork = local["status"] == 200
        observed = {
            "writer": writer.name,
            "put_status": put["status"],
            "put_body": put["body"],
            "writer_local_read_status": local["status"],
            "local_fork": local_fork,
            "propagated_to_owner": propagated,
            "fork_window_secs": a.fork_window,
        }
        fixed = rejected and not local_fork and not propagated
        self.known_gap_gate("signed_store_nonowner_write",
                            "nonowner_put_rejected", fixed=fixed,
                            observed=observed)
        # Propagation to the owner would be a NEW defect (inbound
        # enforcement regression) — hard gate regardless of mode.
        self.gate("signed_store_no_owner_propagation", not propagated,
                  {"propagated_to_owner": propagated})
        status = self.report["phases"]["signed_store_nonowner_write"]["status"]
        log(f"run {self.idx}: signed_store_nonowner_write {status} "
            f"put={put['status']} local_fork={local_fork} "
            f"propagated={propagated}")

    # -- driver ------------------------------------------------------------

    def execute(self):
        try:
            self.start_cluster_creator_only()
            self.phase_cold_join()
            self.phase_live_propagation()
            self.phase_restart_recovery()
            self.phase_concurrent_claims()
            self.phase_signed_store_nonowner()
        finally:
            for n in self.nodes:
                try:
                    n.stop()
                except Exception:
                    pass
        self.report["finished_unix"] = time.time()
        self.report["hard_failures"] = self.hard_failures
        self.report["known_gaps"] = self.known_gaps
        self.report["pass"] = not self.hard_failures
        return self.report


# ──────────────────────────────────────────────────────────────────────────
# Soak orchestration + summary
# ──────────────────────────────────────────────────────────────────────────

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def check_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def latency_series(runs):
    """Collect named latency samples across runs."""
    series = {}

    def add(key, value):
        if value is not None:
            series.setdefault(key, []).append(value)

    for r in runs:
        p = r["phases"]
        for node, v in p.get("cold_join", {}).get("per_node", {}).items():
            add("cold_join.task", v["task_secs"])
            add("cold_join.kv", v["kv_secs"])
        for key, v in p.get("live_propagation", {}) \
                .get("arrivals_secs", {}).items():
            prim = key.rsplit(".", 1)[-1]
            add(f"live_propagation.{prim}", v)
        rr = p.get("restart_recovery", {}).get("observed", {})
        auto = rr.get("auto_recovery_arrivals_secs") or {}
        add("restart.auto.task", auto.get("task"))
        add("restart.auto.kv", auto.get("kv"))
        rj = rr.get("explicit_rejoin") or {}
        add("restart.rejoin.task", rj.get("task_secs"))
        add("restart.rejoin.kv", rj.get("kv_secs"))
        add("claims.converge", p.get("concurrent_claims", {})
            .get("converge_secs"))
    return series


def pctl(sorted_vals, q):
    if not sorted_vals:
        return None
    k = max(0, min(len(sorted_vals) - 1,
                   round(q * (len(sorted_vals) - 1))))
    return sorted_vals[k]


def summarize(runs, args):
    lines = []
    total = len(runs)
    passed = sum(1 for r in runs if r["pass"])
    lines.append("")
    lines.append("=" * 72)
    lines.append(f"CONVERGENCE SOAK SUMMARY — {total} run(s), "
                 f"{args.nodes} nodes, mode="
                 f"{'expect-fixed' if args.expect_fixed else 'known-gap'}")
    lines.append("=" * 72)
    lines.append(f"runs passed: {passed}/{total}")

    # Gate pass rates
    lines.append("")
    lines.append(f"{'phase':<42}{'pass':>6}{'gap':>6}{'fail':>6}")
    phase_names = []
    for r in runs:
        for name in r["phases"]:
            if name not in phase_names:
                phase_names.append(name)
    for name in phase_names:
        n_pass = n_gap = n_fail = 0
        for r in runs:
            e = r["phases"].get(name)
            if e is None:
                continue
            status = e.get("status")
            if status == "known-gap":
                n_gap += 1
            elif e.get("pass"):
                n_pass += 1
            else:
                n_fail += 1
        lines.append(f"{name:<42}{n_pass:>6}{n_gap:>6}{n_fail:>6}")

    # Latency table
    series = latency_series(runs)
    lines.append("")
    lines.append(f"{'latency (secs)':<28}{'n':>4}{'min':>8}{'median':>8}"
                 f"{'p95':>8}{'max':>8}")
    for key in sorted(series):
        vals = sorted(series[key])
        lines.append(
            f"{key:<28}{len(vals):>4}{vals[0]:>8.1f}"
            f"{statistics.median(vals):>8.1f}"
            f"{pctl(vals, 0.95):>8.1f}{vals[-1]:>8.1f}")

    # Diagnostics: hard-error growth per phase (summed across runs+nodes)
    lines.append("")
    lines.append("dropped_critical_hard_error growth per phase "
                 "(sum across runs and nodes):")
    growth = {}
    for r in runs:
        for phase, d in r.get("diagnostics_deltas", {}).items():
            for node, delta in (d.get("admission_delta") or {}).items():
                if delta:
                    growth[phase] = growth.get(phase, 0) + delta.get(
                        "dropped_critical_hard_error", 0)
                else:
                    growth.setdefault(phase, 0)
    for phase, g in growth.items():
        lines.append(f"  {phase:<40}{g:>6}")

    # Known gaps observed
    gaps = {}
    for r in runs:
        for name, e in r["phases"].items():
            if e.get("status") == "known-gap":
                gaps[name] = e.get("known_gap", "")
    if gaps:
        lines.append("")
        lines.append("known gaps observed (tolerated; use --expect-fixed to "
                     "gate on them):")
        for name, note in gaps.items():
            lines.append(f"  - {name}: {note}")

    lines.append("")
    lines.append(f"OVERALL: {'PASS' if passed == total else 'FAIL'}")
    return "\n".join(lines)


def parse_args():
    p = argparse.ArgumentParser(
        description="x0x three-node convergence soak harness")
    p.add_argument("--nodes", type=int, default=3,
                   help="number of local x0xd instances (default 3, min 3)")
    p.add_argument("--runs", type=int, default=1,
                   help="repeat the full scenario N times (default 1)")
    p.add_argument("--x0xd", default=None,
                   help="path to x0xd binary (default: $X0XD_TEST_BINARY "
                        "or target/release/x0xd)")
    p.add_argument("--api-base", type=int, default=27810,
                   help="first API port; node i uses api-base+i")
    p.add_argument("--quic-base", type=int, default=27910,
                   help="first QUIC port; node i uses quic-base+i")
    p.add_argument("--stagger-secs", type=float, default=15.0,
                   help="rolling-start delay between node launches "
                        "(default 15, a known network requirement)")
    p.add_argument("--poll-interval", type=float, default=1.5,
                   help="convergence sampling interval in seconds")
    p.add_argument("--cold-gate", type=float, default=120.0,
                   help="cold-join convergence gate per node (secs)")
    p.add_argument("--live-gate", type=float, default=60.0,
                   help="live-propagation gate (secs)")
    p.add_argument("--restart-gate", type=float, default=90.0,
                   help="restart auto-recovery gate (secs)")
    p.add_argument("--claim-gate", type=float, default=60.0,
                   help="concurrent-claim convergence gate (secs)")
    p.add_argument("--fork-window", type=float, default=20.0,
                   help="observation window for non-owner write "
                        "propagation (secs)")
    p.add_argument("--expect-fixed", action="store_true",
                   help="turn known-gap expectations into hard gates "
                        "(use to verify the fixes)")
    p.add_argument("--log-level", default="info",
                   help="daemon log_level (default info)")
    p.add_argument("--out-dir", default=str(DEFAULT_OUT),
                   help="output root for logs and reports")
    p.add_argument("--keep-data", action="store_true",
                   help="keep node data dirs after passing runs")
    args = p.parse_args()
    if args.nodes < 3:
        p.error("--nodes must be >= 3 (claims need two non-creator peers)")
    if args.x0xd is None:
        args.x0xd = os.environ.get(
            "X0XD_TEST_BINARY", str(REPO_ROOT / "target/release/x0xd"))
    args.x0xd = pathlib.Path(args.x0xd)
    return args


def main():
    args = parse_args()
    if not args.x0xd.is_file():
        log(f"ERROR: x0xd not found at {args.x0xd} — build with "
            f"`cargo build --release --bin x0xd` or set X0XD_TEST_BINARY")
        return 2
    for i in range(args.nodes):
        if not check_port_free(args.api_base + i):
            log(f"ERROR: API port {args.api_base + i} already in use")
            return 2

    out_root = pathlib.Path(args.out_dir) / time.strftime("%Y%m%d-%H%M%S")
    out_root.mkdir(parents=True, exist_ok=True)
    log(f"output: {out_root}")
    log(f"x0xd: {args.x0xd}")

    runs = []
    try:
        for i in range(1, args.runs + 1):
            run_dir = out_root / f"run-{i}"
            run_dir.mkdir(parents=True, exist_ok=True)
            log(f"=== run {i}/{args.runs} ===")
            run = Run(i, args, run_dir)
            try:
                report = run.execute()
            except Exception as e:  # harness/daemon failure: fail loud
                for n in run.nodes:
                    try:
                        n.stop()
                    except Exception:
                        pass
                report = run.report
                report["pass"] = False
                report["error"] = f"{type(e).__name__}: {e}"
                report["hard_failures"] = run.hard_failures + ["exception"]
                log(f"run {i}: EXCEPTION {e}")
            runs.append(report)
            (run_dir / "report.json").write_text(
                json.dumps(report, indent=2))
            # Fresh data dirs per run: keep logs+configs, drop key/state data
            # unless asked to keep it (or the run failed — keep for debug).
            if report["pass"] and not args.keep_data:
                for n in run.nodes:
                    shutil.rmtree(n.data_dir, ignore_errors=True)
            time.sleep(2)  # let UDP/TCP ports drain between runs
    finally:
        report_path = out_root / "report.json"
        report_path.write_text(json.dumps({
            "args": {k: str(v) if isinstance(v, pathlib.Path) else v
                     for k, v in vars(args).items()},
            "runs": runs,
        }, indent=2))
        summary = summarize(runs, args) if runs else "(no runs completed)"
        (out_root / "summary.txt").write_text(summary + "\n")
        print(summary)
        log(f"report: {report_path}")

    return 0 if runs and all(r["pass"] for r in runs) else 1


if __name__ == "__main__":
    sys.exit(main())
