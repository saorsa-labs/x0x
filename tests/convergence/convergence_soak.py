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
  4. concurrent-claims  two peers claim the same task simultaneously; the
                       oracle uses fence_token (LOCAL fence, not
                       distributed exclusion), requires structured
                       claimed_by/claimed_at/version, attributes the
                       deterministic OR-Set winner to a real claimant, and
                       asserts no commit response misrepresents advisory
                       local commit as exclusive ownership
  5. signed-store non-owner write  joiner PUTs to creator's Signed store;
                       plus an ownership-binding oracle (owner == creator,
                       no first-self-claim takeover by the joiner)

GET /diagnostics/gossip is snapshotted on every node before and after each
phase so pubsub admission-counter growth (dropped_critical_hard_error,
cooling) is attributable per phase. Same-host topology (per-node AgentId via
GET /agent, PeerId via GET /diagnostics/connectivity, addresses, bootstrap
siblings) is recorded once the cluster is up for claim-winner / store-owner
attribution.

Claim semantics are ADVISORY: fence_token fences locally only — two
replicas at the same version can both commit, and the single deterministic
winner is resolved at convergence (claimed_by). No response may imply
distributed atomic exclusion the protocol cannot provide.

Known-gap phases (current main, pre-fix): restart auto-recovery, structured
claim fields, claim CAS local-fence, claim exclusivity honesty, non-owner
PUT rejected, and store owner binding. Without --expect-fixed these are
reported as "known-gap" and do not fail the run; --expect-fixed turns them
into hard gates for verifying the fixes.

Beyond the soak, the release ORACLE records and (under --expect-fixed) verifies
binary/source PROVENANCE — current+legacy SHA-256 and --version, Git HEAD +
dirty-tree fingerprint + source cutoff, and the actual peer set / reconnect
path — refusing a binary older than the reviewed sources or a legacy binary
that is not exactly v0.30.1 (file existence is not authentication). Additional
prerequisite gates run once per invocation and cover threats the single-version
soak cannot: mixed-version skew (needs a real v0.30.1 --legacy-binary, else
UNSUPPORTED — never faked), the hostile OwnerAnnounce injection (in-repo via
public REST), owner-offline checkpoint/delete recovery, and forged first-seen
task admission (driven by the in-repo x0xd-forge-injector, which publishes an
unattested first-seen TaskItem over real gossip; absent injector ⇒ UNSUPPORTED).
In-soak gates also cover malformed/pre-restart fence rejection
and named new-port reconnect. Under --expect-fixed UNSUPPORTED or unproven
phases FAIL the run, and critical hard-error growth / mDNS contamination are
hard gates. `just convergence-release` is the authoritative recipe (--expect-fixed
+ authenticated v0.30.1 legacy + 10/10); `convergence-soak-quick` stays as a
one-run smoke.

Stdlib only (urllib, never curl — curl is intercepted in some environments).

Usage:
  python3 tests/convergence/convergence_soak.py                 # 1 run
  python3 tests/convergence/convergence_soak.py --runs 10       # soak
  python3 tests/convergence/convergence_soak.py --expect-fixed  # post-fix
  python3 tests/convergence/convergence_soak.py --help          # all gates
"""

import argparse
import base64
import hashlib
import re
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
    "nonowner_put_rejected": (
        "non-owner PUT to a Signed store returns local 200 and forks "
        "locally instead of being rejected with 403"
    ),
    # ── Strengthened oracles (convergence blockers) ───────────────────────
    # These were tolerated under the old string-only `state` oracle. The
    # harness now asserts them as structured-field contracts; pre-fix they
    # surface as known-gap so a regression is loud rather than invisible.
    "claim_structured_fields": (
        "claimed_by/claimed_at/version absent on a claimed task — the "
        "deterministic OR-Set winner is not observable without parsing the "
        "formatted `state` string"
    ),
    "claim_cas_local_fence": (
        "PATCH with a stale fence_token still mutates — the local fence "
        "guard does not fence (fence_token is advisory/local, not exclusive)"
    ),
    "claim_exclusivity_honesty": (
        "a claim commit response misrepresents advisory local CRDT commit as "
        "exclusive ownership (e.g. an exclusive 'won/winner/owner' field, or "
        "committed != \"local\") — the protocol cannot provide distributed "
        "atomic exclusion"
    ),
    "store_owner_binding": (
        "the store's authoritative owner is not exposed/bound to the "
        "creator, so a first-self-claim takeover by a joiner is not "
        "detectable at the API"
    ),
    "fence_malformed": (
        "a malformed fence_token (non-token / overflow) collapses to "
        "'absent' and mutates unconditionally instead of being rejected "
        "with 400/409 — present-but-invalid must be distinct from absent"
    ),
    "fence_pre_restart": (
        "a fence_token captured before a daemon restart is still accepted "
        "after restart — the fence epoch is wall-clock/zero, not a durable "
        "incarnation nonce, so a pre-restart token is not invalidated"
    ),
    "named_new_port_reconnect": (
        "a killed named peer restarted on a forced different QUIC port with "
        "the same MachineId does not proactively reconnect / recover CRDT "
        "state without a manual rejoin"
    ),
}

# Gates that cannot run because an external prerequisite is missing. These are
# NOT tolerated defects (known-gap) — they are explicitly UNSUPPORTED until the
# named prerequisite is supplied, so CI/users know exactly what to provide
# rather than the harness silently skipping them.
#
# Note: malicious_owner_announce is NO LONGER a prerequisite gate — it runs
# in-repo via public REST create/join APIs (a rogue daemon self-claims the
# same store topic; its sync loop publishes a genuine OwnerAnnounce). Only
# mixed_version_skew remains prerequisite-gated (needs a real legacy binary).
UNSUPPORTED_PREREQ_NOTES = {
    "mixed_version_skew": (
        "requires a legacy x0xd binary (v0.30.1) to run alongside the "
        "current build; set X0XD_LEGACY_BINARY (or --legacy-binary) to a "
        "path to that release's x0xd. Without it the mixed-version "
        "load-bearing (legacy-owner + current-anchored-joiner) and degraded "
        "directions cannot be exercised — do NOT fake it by downgrading "
        "protocol fields on the current binary, which would not reproduce "
        "the real skew."
    ),
    "forged_first_seen_task": (
        "requires the in-repo x0xd-forge-injector binary to publish an "
        "unattested first-seen TaskItem (Claimed{victim,ts:1}, no "
        "attestation) over the real live-sync gossip path. The convergence "
        "harness speaks REST only and a legitimate daemon always self-"
        "attests, so the injector crafts the wire bytes via "
        "x0x::crdt::forge_unattested_delta_bytes and publishes them through "
        "the daemon's /publish API. Build it with `cargo build --release "
        "--bin x0xd-forge-injector` (the release recipe provisions it). The "
        "other variants (malformed-sig, attacker-key, wrong-agent, "
        "wrong-scope) are proven at the store/CRDT regression layer"
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

    def reconfigure_port(self, new_quic_port, bootstrap_quic_ports):
        """Rewrite the config to bind a FORCED DIFFERENT QUIC port, keeping
        the same data_dir (⇒ same MachineId/identity/PeerId) and the same
        API port. Used by the named-new-port reconnect gate: the cached old
        endpoint is invalid, so reconnection must use a refreshed candidate
        address and recover CRDT state without a manual rejoin."""
        self.quic_port = new_quic_port
        self.write_config(bootstrap_quic_ports)

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
# Release-oracle provenance + exact-value + peer-set helpers
# ──────────────────────────────────────────────────────────────────────────
#
# The independent review established that the prior oracle attested a release
# from PATHS alone (binary path, no digest/version), accepted a "legacy"
# binary by file existence, checked KV convergence by PRESENCE (not exact
# bytes/hash), and never recorded the actual peer set or reconnect path. The
# helpers below close each of those false positives: the oracle now records
# binary SHA-256 + --version, Git HEAD + dirty-tree fingerprint + source
# cutoff, exact decoded KV values/hashes, and the real connected peer set.

# Source files the independent review pinned as the security/correctness
# surface. The release binary MUST be no older than the newest of these — a
# binary built before the last edit to a reviewed file is stale and the
# oracle refuses to attest it (refuse a binary older than reviewed sources).
REVIEWED_SOURCES = [
    "src/kv/store.rs", "src/kv/entry.rs",
    "src/crdt/provenance.rs", "src/crdt/task_item.rs",
    "src/crdt/task_list.rs", "src/crdt/delta.rs", "src/crdt/sync.rs",
    "src/server/crdt_subscriptions.rs", "src/server/routes/tasks.rs",
    "src/server/mod.rs", "src/lib.rs", "src/network.rs",
    "src/bin/x0xd.rs",
]
LEGACY_REQUIRED_VERSION = "0.30.1"


def sha256_file(path):
    """Streaming SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def binary_version(x0xd):
    """Run `x0xd --version` and return the stripped stdout (e.g.
    'x0xd 0.30.1'), or None on failure. Never raises."""
    try:
        out = subprocess.run(
            [str(x0xd), "--version"],
            capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def parse_version(version_str):
    """Extract the dotted 'major.minor.patch' from a 'x0xd 0.30.1'-style
    string, or None."""
    if not isinstance(version_str, str):
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", version_str)
    return m.group(1) if m else None


def git_provenance():
    """Capture HEAD, HEAD^{tree}, branch, dirty flag, a dirty-tree
    fingerprint (source cutoff beyond the commit), and the HEAD commit
    timestamp. Best-effort; missing git → None fields."""
    def run(*cmd):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=10, cwd=str(REPO_ROOT))
            return out.stdout.strip() if out.returncode == 0 else None
        except Exception:
            return None
    head = run("git", "rev-parse", "HEAD")
    head_tree = run("git", "rev-parse", "HEAD^{tree}")
    branch = run("git", "rev-parse", "--abbrev-ref", "HEAD")
    diff = run("git", "diff", "HEAD") or ""
    status = run("git", "status", "--porcelain") or ""
    dirty = bool(diff or status)
    dirty_tree_hash = hashlib.sha256(
        (diff + "\n" + status).encode()).hexdigest() if dirty else None
    commit_unix = None
    iso = run("git", "show", "-s", "--format=%ct", "HEAD")
    if iso:
        try:
            commit_unix = int(iso)
        except ValueError:
            commit_unix = None
    return {
        "head": head, "head_tree": head_tree, "branch": branch,
        "dirty": dirty, "dirty_tree_hash": dirty_tree_hash,
        "commit_unix": commit_unix,
    }


def record_and_verify_provenance(args):
    """Record binary/source provenance and REFUSE to attest a release from a
    stale binary or a non-v0.30.1 legacy. Returns (provenance, errors).
    `errors` non-empty ⇒ the oracle cannot certify this tree; under
    --expect-fixed the caller fails the run (release authority). Without
    --expect-fixed the errors are recorded as warnings so the one-run smoke
    stays available."""
    errors = []
    cur = {"path": str(args.x0xd)}
    try:
        cur["sha256"] = sha256_file(args.x0xd)
    except Exception as e:
        cur["sha256"] = None
        errors.append(f"current binary unreadable: {e}")
    cur["version_raw"] = binary_version(args.x0xd)
    cur["version"] = parse_version(cur["version_raw"])
    try:
        cur["mtime_unix"] = int(args.x0xd.stat().st_mtime)
    except Exception:
        cur["mtime_unix"] = None
    # Stale-binary floor: binary mtime must be >= the newest reviewed source.
    newest_src = 0
    for rel in REVIEWED_SOURCES:
        try:
            newest_src = max(newest_src, int((REPO_ROOT / rel).stat().st_mtime))
        except Exception:
            pass
    cur["newest_reviewed_source_mtime_unix"] = newest_src or None
    if cur["mtime_unix"] and newest_src and cur["mtime_unix"] < newest_src:
        errors.append(
            f"current binary mtime ({cur['mtime_unix']}) predates the newest "
            f"reviewed source ({newest_src}); rebuild "
            f"`cargo build --release --bin x0xd` before attesting a release")
    if not cur["version"]:
        errors.append("current binary reports no parseable --version")
    legacy = None
    if args.legacy_binary:
        legacy = {"path": str(args.legacy_binary)}
        try:
            legacy["sha256"] = sha256_file(args.legacy_binary)
        except Exception as e:
            legacy["sha256"] = None
            errors.append(f"legacy binary unreadable: {e}")
        legacy["version_raw"] = binary_version(args.legacy_binary)
        legacy["version"] = parse_version(legacy["version_raw"])
        if legacy["version"] != LEGACY_REQUIRED_VERSION:
            errors.append(
                f"legacy binary must be exactly v{LEGACY_REQUIRED_VERSION} "
                f"(got {legacy['version_raw']!r}); file existence alone is "
                f"not authentication — supply an authenticated v0.30.1 x0xd")
    forge = {"path": str(args.forge_injector)}
    if pathlib.Path(args.forge_injector).is_file():
        try:
            forge["sha256"] = sha256_file(args.forge_injector)
        except Exception:
            forge["sha256"] = None
        forge["version"] = binary_version(args.forge_injector)
    else:
        forge["sha256"] = None
        forge["version"] = None
    return {
        "current_binary": cur, "legacy_binary": legacy,
        "forge_injector": forge,
        "git": git_provenance(),
        "review_cutoff_sources": REVIEWED_SOURCES,
        "legacy_required_version": LEGACY_REQUIRED_VERSION,
    }, errors


def key_record(node, store, key):
    """Full GET /stores/:id/:key body, or None if absent/unreadable."""
    r = node.req("GET", f"/stores/{store}/{key}")
    if r["status"] == 200 and isinstance(r["body"], dict) \
            and r["body"].get("ok") is not False:
        return r["body"]
    return None


def key_value_bytes(node, store, key):
    """Decoded value bytes for `key`, or None. Closes the presence-only KV
    false positive: convergence is asserted on EXACT decoded bytes."""
    rec = key_record(node, store, key)
    if rec is None:
        return None
    raw = rec.get("value")
    if not isinstance(raw, str):
        return None
    try:
        return base64.b64decode(raw)
    except Exception:
        return None


def key_value_matches(node, store, key, expected_plain):
    """True iff `key` is present with EXACT decoded value == expected_plain."""
    got = key_value_bytes(node, store, key)
    return got is not None and got == expected_plain.encode()


def key_content_hash(node, store, key):
    """Owner-signed content_hash (blake3) for `key`, or None."""
    rec = key_record(node, store, key)
    if rec is None:
        return None
    h = rec.get("content_hash")
    return h if isinstance(h, str) else None


def connectivity_snapshot(node):
    """GET /diagnostics/connectivity body, or None."""
    try:
        r = node.req("GET", "/diagnostics/connectivity")
    except OSError:
        return None
    if r["status"] == 200 and isinstance(r["body"], dict):
        return r["body"]
    return None


def node_connected_peer_ids(node):
    """Actual connected peer set (hex PeerIds) from per_peer_transport rows.
    This is the real mesh edges, not the configured bootstrap list."""
    snap = connectivity_snapshot(node)
    if not snap:
        return set()
    ids = set()
    for row in snap.get("per_peer_transport", []) or []:
        if isinstance(row, dict) and row.get("peer_id") and \
                row.get("connected") is not False:
            ids.add(row["peer_id"])
    return ids


def node_connection_pool(node):
    """Connection-pool counters (active_connections, lru_evictions_total,
    establish_failures_total) used for reconnect/eviction attribution."""
    snap = connectivity_snapshot(node)
    if not snap:
        return None
    cp = snap.get("connection_pool")
    return cp if isinstance(cp, dict) else None


# ──────────────────────────────────────────────────────────────────────────
# Identity / topology / store-metadata probes (read-only)
# ──────────────────────────────────────────────────────────────────────────

def node_agent_id(node):
    """Local agent id (hex) via GET /agent. Read-only, no side effects.
    The server's ApiResponse flattens its data payload, so `agent_id` is a
    top-level key (not nested under `data`). Cached on the node after first
    lookup."""
    if getattr(node, "agent_id", None):
        return node.agent_id
    r = node.req("GET", "/agent")
    if r["status"] == 200 and isinstance(r["body"], dict):
        aid = r["body"].get("agent_id")
        if isinstance(aid, str) and aid:
            node.agent_id = aid
            return aid
    return None


def node_peer_id(node):
    """Local QUIC peer id (hex) via GET /diagnostics/connectivity. Read-only.
    Cached on the node after first lookup."""
    if getattr(node, "peer_id", None):
        return node.peer_id
    try:
        r = node.req("GET", "/diagnostics/connectivity")
    except OSError:
        return None
    if r["status"] == 200 and isinstance(r["body"], dict):
        pid = r["body"].get("peer_id")
        if isinstance(pid, str) and pid:
            node.peer_id = pid
            return pid
    return None


def node_mdns(node):
    """Local mDNS discovery state via GET /diagnostics/connectivity.
    Returns {browsing, advertising, discovered_peers} or None. Same call as
    node_peer_id; cached on the node. discovered_peers > 0 on an isolated
    same-host cluster signals mesh contamination (stray x0xd daemons on the
    host advertising via mDNS)."""
    if getattr(node, "mdns", None) is not None:
        return node.mdns
    try:
        r = node.req("GET", "/diagnostics/connectivity")
    except OSError:
        return None
    mdns = None
    if r["status"] == 200 and isinstance(r["body"], dict):
        mdns = r["body"].get("mdns")
    if isinstance(mdns, dict):
        node.mdns = mdns
        return mdns
    return None


def store_meta(node, store):
    """Best-effort store metadata for `store`.

    Captures {owner, policy, version, ownership_status}. The finalized
    contract exposes these on GET /stores list entries (and a possible
    GET /stores/:id detail). Probes defensively so the oracle works whether
    the field lands on the list entry or a detail route; any field not yet
    exposed is None and `exposed` is False (the caller treats a missing field
    as a known-gap, not a failure).

    ownership_status is "anchored" (owner cryptographically bound at
    construction), "unknown" (no anchor — read-only), or "conflict" (anchored
    owner differs from an announced owner)."""
    meta = {"owner": None, "policy": None, "version": None,
            "ownership_status": None, "exposed": False}
    # Prefer the list endpoint (always present); fall back to a detail route.
    candidates = []
    r = node.req("GET", "/stores")
    if r["status"] == 200 and isinstance(r["body"], dict):
        for entry in r["body"].get("stores", []):
            if isinstance(entry, dict) and (entry.get("id") == store
                    or entry.get("topic") == store):
                candidates.append(entry)
                break
    if not candidates:
        rd = node.req("GET", f"/stores/{store}")
        if rd["status"] == 200 and isinstance(rd["body"], dict):
            candidates.append(rd["body"])
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        for k in ("owner", "policy", "version", "ownership_status"):
            if entry.get(k) is not None:
                meta[k] = entry.get(k)
                meta["exposed"] = True
    return meta


def task_list_version(node, topic):
    """Current task-list revision (u64) from GET /task-lists/:id/tasks, or
    None if absent. Reported for observability; the fencing input is the
    opaque `fence_token` (see task_list_fence), not this revision."""
    r = node.req("GET", f"/task-lists/{topic}/tasks")
    if r["status"] == 200 and isinstance(r["body"], dict):
        v = r["body"].get("version")
        if isinstance(v, int):
            return v
    return None


def task_list_fence(node, topic):
    """Opaque local-replica fence token (string) from GET /task-lists/:id/tasks,
    or None if absent. Echo this verbatim as `fence_token` on a subsequent
    PATCH; if it does not match the daemon's current (epoch, revision) the
    mutation is rejected with 409 and nothing changes. This is LOCAL fencing
    (two daemons at the same token both accept), NOT distributed CAS."""
    r = node.req("GET", f"/task-lists/{topic}/tasks")
    if r["status"] == 200 and isinstance(r["body"], dict):
        tok = r["body"].get("fence_token")
        if isinstance(tok, str) and tok:
            return tok
    return None


# Claim-oracle helpers. Claims are ADVISORY (CRDT OR-Set): the deterministic
# winner is resolved at convergence and read from `claimed_by`; no response
# may imply distributed atomic exclusion the protocol cannot provide.

def claimed_by_of(task):
    """Hex AgentId of the deterministic claim winner, or None."""
    if isinstance(task, dict):
        cb = task.get("claimed_by")
        if isinstance(cb, str) and cb:
            return cb
    return None


def claimed_at_of(task):
    """Unix-ms timestamp of the winning claim, or None."""
    if isinstance(task, dict):
        ca = task.get("claimed_at")
        if isinstance(ca, int) and ca > 0:
            return ca
    return None


def state_str_of(task):
    """Legacy formatted state string (empty|claimed:<hex>|done:<hex>)."""
    if isinstance(task, dict):
        s = task.get("state")
        return str(s) if s is not None else None
    return None


# A response LEAKS when it positively asserts exclusive ownership the
# advisory CRDT cannot guarantee. A top-level NEGATION is honest, not a leak:
# the finalized contract carries `exclusive:false`. Provisional/local fields
# (resolution.locally_winning, resolution.current_winner, pending_convergence)
# are explicitly non-final and nested, so they are not leaks either.
_POSITIVE_EXCLUSIVITY_KEYS = frozenset({
    "won", "winner", "owner", "acquired", "granted", "locked", "primary",
})


def claims_exclusivity(body):
    """True iff the body POSITIVELY asserts exclusive ownership the advisory
    CRDT cannot guarantee. `exclusive:false` (a negation) is HONEST and is
    NOT reported as a leak."""
    if not isinstance(body, dict):
        return False
    if body.get("exclusive") is True:
        return True
    for k in _POSITIVE_EXCLUSIVITY_KEYS:
        if k in body and body.get(k):
            return True
    return False


def honesty_fields_ok(body):
    """Check the finalized contract's POSITIVE honesty signals. Each is
    optional (the response may predate the field), but when PRESENT it must
    be honest. Returns (ok, details).

    Contract (PATCH commit 200): committed=="local"; exclusive==false (if
    present); execution.authorization=="advisory" (if present);
    cas.scope=="local_replica" (if present); resolution.pending_convergence
    ==true (if present)."""
    if not isinstance(body, dict):
        return True, {}
    details = {}
    if "exclusive" in body:
        details["exclusive_is_false"] = body.get("exclusive") is False
    res = body.get("resolution")
    if isinstance(res, dict) and "pending_convergence" in res:
        details["pending_convergence_is_true"] = \
            res.get("pending_convergence") is True
    cas = body.get("cas")
    if isinstance(cas, dict) and "scope" in cas:
        details["cas_scope_is_local_replica"] = \
            cas.get("scope") == "local_replica"
    ex = body.get("execution")
    if isinstance(ex, dict) and "authorization" in ex:
        details["authorization_is_advisory"] = \
            ex.get("authorization") == "advisory"
    ok = all(details.values()) if details else True
    return ok, details


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
            "topology": {},          # per-node agent_id/peer_id/paths/siblings
            "unsupported": [],       # gates skipped for a missing prerequisite
            "pass": None,
        }
        self.hard_failures = []
        self.known_gaps = []
        self.unsupported_gates = []

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

    def unsupported_gate(self, phase, prereq_key, detail=None):
        """Record a gate that cannot run because an external prerequisite is
        missing (e.g. a legacy binary). Never a hard failure and never a
        tolerated defect — the gate is explicitly UNSUPPORTED and the exact
        prerequisite is reported so it can be supplied. Distinct from
        known-gap (a real defect we tolerate) and from a hard failure."""
        entry = self.report["phases"].setdefault(phase, {})
        entry["status"] = "unsupported"
        entry["pass"] = True  # does not fail the run; reported separately
        entry["unsupported"] = UNSUPPORTED_PREREQ_NOTES[prereq_key]
        if detail is not None:
            entry.update(detail)
        self.unsupported_gates.append(phase)
        self.report["unsupported"].append(phase)
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

    def _record_topology(self):
        """Capture each node's agent_id, peer_id, addresses, data dir, and
        bootstrap siblings once the whole cluster is up. Same-host topology
        (who-is-who and who bootstraps to whom) is needed to attribute the
        deterministic claim winner and to reproduce same-host fan-out. The
        PeerId is the QUIC identity (`GET /diagnostics/connectivity`); the
        AgentId (`GET /agent`) is what `claimed_by`/store `owner` resolve to.
        """
        a = self.args
        creator = self.nodes[0]
        creator_pid = node_peer_id(creator)
        mesh_peers = []
        for i, node in enumerate(self.nodes):
            # node1 bootstraps to nobody; every other node lists only node1.
            targets = ([{"quic_addr": f"127.0.0.1:{a.quic_base}",
                         "peer_id": creator_pid,
                         "agent_id": node_agent_id(creator)}]
                       if i > 0 else [])
            mdns = node_mdns(node) or {}
            disc = mdns.get("discovered_peers")
            if isinstance(disc, int):
                mesh_peers.append(disc)
        self.report["topology"][node.name] = {
            "api_addr": node.base,
            "quic_addr": f"127.0.0.1:{node.quic_port}",
            "data_dir": str(node.data_dir),
            "agent_id": node_agent_id(node),
            "peer_id": node_peer_id(node),
            "bootstrap_siblings": targets,
            "mdns": mdns,
            # Actual mesh edges (connected PeerIds) + pool counters, so the
            # report records the REAL peer set and reconnect/eviction path —
            # not just the configured bootstrap list.
            "connected_peer_ids": sorted(node_connected_peer_ids(node)),
            "connection_pool": node_connection_pool(node),
        }
        # Surface same-host mDNS mesh contamination: bootstrap_peers isolates
        # QUIC, not mDNS, so stray x0xd daemons on the host can appear as
        # discovered peers. Non-zero on an isolated cluster ⇒ contamination
        # (the convergence assertions still hold via unique topics, but this
        # makes the environmental assumption observable, not silent).
        self.report["mesh_contamination"] = {
            "max_mdns_discovered_peers": max(mesh_peers) if mesh_peers else None,
            "contaminated": bool(mesh_peers and max(mesh_peers) > 0),
        }

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
        # Discover the creator's AgentId now so peer store joins can pin it
        # as expected_owner — the cryptographic/out-of-band owner binding that
        # anchors the joiner to the creator at join time (no first-self-claim).
        self.creator_aid = node_agent_id(creator)

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
                join_st = node.req("POST", f"/stores/{self.store}/join",
                                   ({"expected_owner": self.creator_aid}
                                    if self.creator_aid else {}))
                arrivals = sample_until(
                    {
                        "task": lambda n=node: task_visible(
                            n, self.topic, self.pre_task_id),
                        "kv": lambda n=node: key_value_matches(
                            n, self.store, "prejoin", "prejoin-value"),
                    },
                    gate_secs=a.cold_gate, interval=a.poll_interval)
                per_node[node.name] = {
                    "join_status": {"task_list": join_tl["status"],
                                    "store": join_st["status"]},
                    "store_join_body": join_st.get("body"),
                    "task_secs": arrivals["task"],
                    "kv_secs": arrivals["kv"],
                }
        ok = all(v["task_secs"] is not None and v["kv_secs"] is not None
                 for v in per_node.values())
        self.gate("cold_join", ok,
                  {"gate_secs": a.cold_gate, "per_node": per_node})
        log(f"run {self.idx}: cold_join {'PASS' if ok else 'FAIL'} "
            f"{json.dumps(per_node)}")
        # All nodes are up now — capture same-host topology (agent_id,
        # peer_id, addresses, bootstrap siblings) for the report and for
        # claim-winner / store-owner attribution in later phases.
        self._record_topology()

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
                    lambda n=node: key_value_matches(
                        n, self.store, "live", "live-value"))
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
            pre_restart_fence = task_list_fence(victim, self.topic)
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
                    "kv": lambda: key_value_matches(
                        victim, self.store, "offline", "offline-value"),
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
                        "kv": lambda: key_value_matches(
                            victim, self.store, "offline", "offline-value"),
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

        if victim.running:
            prf = self._fence_pre_restart_rejected(victim, pre_restart_fence)
            self.known_gap_gate("fence_pre_restart_rejected",
                                "fence_pre_restart", fixed=prf["fenced"],
                                observed=prf)

    def phase_concurrent_claims(self):
        a, creator = self.args, self.creator()
        claimants = self.nodes[1:3]
        # Resolve claimant AgentIds so the deterministic winner is
        # attributable to a real claimant (not a phantom/too-short id).
        claimant_aids = {n.name: node_agent_id(n) for n in claimants}
        known_aids = {v for v in claimant_aids.values() if v}
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

            # Each claimant reads its OWN local fence_token (right after the
            # barrier, minimizing the window for a background delta to advance
            # it) and echoes it as fence_token. fence_token is a LOCAL fence:
            # two replicas each at their own current token BOTH commit — that
            # is the advisory property. Do NOT read one replica's token and
            # reuse it for the other: cross-replica skew can spuriously 409
            # the second and mask the contract.
            used_tokens = {}

            barrier = threading.Barrier(len(claimants))

            def do_claim(node):
                barrier.wait(timeout=10)
                f_local = task_list_fence(node, self.topic)
                used_tokens[node.name] = f_local
                return node.req(
                    "PATCH", f"/task-lists/{self.topic}/tasks/{tid}",
                    {"action": "claim", "fence_token": f_local})

            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=len(claimants)) as ex:
                futs = {n.name: ex.submit(do_claim, n) for n in claimants}
                responses = {k: f.result() for k, f in futs.items()}

            # Converge: all nodes agree on the deterministic winner. Prefer
            # the structured `claimed_by`; fall back to the legacy `state`
            # string only when structured fields are entirely absent, so the
            # hard convergence gate still fires pre-fix.
            t0 = time.monotonic()
            winner_aid, converge_secs, final_tasks = None, None, {}
            while time.monotonic() - t0 < a.claim_gate:
                final_tasks = {n.name: get_task(n, self.topic, tid)
                               for n in self.nodes}
                aids = [claimed_by_of(t) for t in final_tasks.values()]
                states = [state_str_of(t) for t in final_tasks.values()]
                present = all(final_tasks.values())
                if present and len(set(aids)) == 1 and aids[0] is not None:
                    winner_aid = aids[0]
                    converge_secs = round(time.monotonic() - t0, 2)
                    break
                if (present and all(x is None for x in aids)
                        and len(set(states)) == 1
                        and (states[0] or "").startswith("claimed")):
                    converge_secs = round(time.monotonic() - t0, 2)
                    break
                time.sleep(a.poll_interval)

        # ── Structured-field oracle (claimed_by / claimed_at / version) ─────
        structured = {}
        for name, t in final_tasks.items():
            if isinstance(t, dict):
                structured[name] = {
                    "claimed_by": claimed_by_of(t),
                    "claimed_at": claimed_at_of(t),
                    "state": state_str_of(t),
                }
            else:
                structured[name] = None
        has_structured = all(
            isinstance(s, dict) and s.get("claimed_by") is not None
            and s.get("claimed_at") is not None
            for s in structured.values())
        # The deterministic winner must be one of the claimants (hex AgentId
        # present in the topology). Skipped if agent ids were undiscoverable.
        winner_attributable = (winner_aid is None or not known_aids
                               or winner_aid in known_aids)

        converged = converge_secs is not None
        self.gate("concurrent_claims", converged and winner_attributable, {
            "gate_secs": a.claim_gate,
            "visibility_secs": vis,
            "fence_tokens_used": used_tokens,
            "claimant_agent_ids": claimant_aids,
            "claim_responses": {k: {"status": v["status"], "body": v["body"]}
                                for k, v in responses.items()},
            "converge_secs": converge_secs,
            "winner_agent_id": winner_aid,
            "winner_attributable": winner_attributable,
        })
        # Advisory race gate: each claimant used its OWN local version, so
        # BOTH must commit (200) — two replicas at their own current version
        # both pass the local fence. A 409 here would mean the fence fired
        # on cross-replica skew, which masks the advisory contract.
        both_committed = all(
            v["status"] == 200 for v in responses.values())
        self.known_gap_gate(
            "concurrent_claims_advisory_both_commit",
            "claim_cas_local_fence", fixed=both_committed,
            observed={"fence_tokens_used": used_tokens,
                      "claim_statuses": {k: v["status"]
                                         for k, v in responses.items()},
                      "both_committed": both_committed})
        # No commit response may POSITIVELY claim exclusivity the advisory
        # CRDT cannot provide (a top-level negation like exclusive:false is
        # honest, not a leak); every 200 commit must be labeled "local"; and
        # any present honesty signal (exclusive/execution/cas/resolution)
        # must be correct.
        exclusivity_leak = {
            k: claims_exclusivity(v.get("body"))
            for k, v in responses.items()
        }
        local_labeled = {
            k: (isinstance(v.get("body"), dict)
                and v["body"].get("committed") == "local")
            for k, v in responses.items() if v["status"] == 200
        }
        honesty_fields = {}
        for k, v in responses.items():
            if v["status"] == 200:
                ok, det = honesty_fields_ok(v.get("body"))
                honesty_fields[k] = {"ok": ok, "details": det}
        honest = (not any(exclusivity_leak.values())
                  and all(local_labeled.values())
                  and all(h["ok"] for h in honesty_fields.values()))
        self.known_gap_gate(
            "concurrent_claims_honest_semantics", "claim_exclusivity_honesty",
            fixed=honest,
            observed={"exclusivity_leak": exclusivity_leak,
                      "local_labeled": local_labeled,
                      "honesty_fields": honesty_fields})
        self.known_gap_gate(
            "concurrent_claims_structured_fields", "claim_structured_fields",
            fixed=has_structured and winner_attributable,
            observed={"structured_fields": structured,
                      "winner_agent_id": winner_aid,
                      "claimant_agent_ids": claimant_aids})

        # ── CAS local-fence oracle (single replica) ────────────────────────
        # On ONE replica, a stale fence_token must NOT mutate. This is
        # the honest local fence; it is NOT distributed exclusion (two
        # replicas at the same version can both commit — see above).
        cas = self._claim_cas_local_fence(creator)
        self.known_gap_gate(
            "concurrent_claims_cas_fence", "claim_cas_local_fence",
            fixed=cas["fenced"], observed=cas)

        # ── Malformed fence-token oracle ──────────────────────────────────
        # A supplied-but-MALFORMED fence_token must be rejected (non-200)
        # WITHOUT mutating the list — present-but-invalid must NOT collapse
        # to 'absent' (unconditional mutation).
        mal = self._fence_malformed_rejected(creator)
        self.known_gap_gate("fence_malformed_rejected", "fence_malformed",
                            fixed=mal["fenced"], observed=mal)

        # ── Remote-invalidation CAS oracle ─────────────────────────────────
        # The local fence must also reject a claim whose fence_token a
        # SINCE-MERGED REMOTE delta has invalidated — not only local
        # mutations. A remote peer mutates the shared list; once that delta
        # merges into the local replica (version advances), a local claim
        # guarded by the pre-merge version MUST be rejected (non-mutation).
        rinv = self._claim_remote_invalidation(creator, self.nodes[1])
        self.known_gap_gate(
            "concurrent_claims_remote_invalidation",
            "claim_cas_local_fence", fixed=rinv["fenced"], observed=rinv)

        log(f"run {self.idx}: concurrent_claims "
            f"{'PASS' if converged else 'FAIL'} winner={winner_aid!r} "
            f"converge={converge_secs}s structured={has_structured} "
            f"both_committed={both_committed} cas_fenced={cas['fenced']} "
            f"remote_inv_fenced={rinv['fenced']}")

    def _claim_cas_local_fence(self, node):
        """Single-replica fence oracle on a fresh task.

        Sequence on ONE node: read the opaque fence_token F0, claim echoing
        fence_token=F0 (commits, token advances to F1), then claim again with
        the now-stale fence_token=F0. The stale attempt MUST NOT mutate (token
        stays F1) and MUST return a non-200 conflict echoing the current
        fence_token. We assert the *behavior* (non-mutation + token echo),
        never the literal error string. fence_token is a LOCAL fence (epoch,
        revision): two daemons at the same token both accept — not a
        distributed CAS, and a token captured before a restart never matches
        post-restart (epoch differs), closing the restart-ABA window.
        """
        task = node.req("POST", f"/task-lists/{self.topic}/tasks",
                        {"title": "cas-target",
                         "description": "fence_token local fence"})
        if task["status"] not in (200, 201) or not isinstance(
                task.get("body"), dict):
            return {"fenced": False, "error": "cas task create failed",
                    "create_response": task}
        tid = task["body"].get("task_id")
        f0 = task_list_fence(node, self.topic)
        commit = node.req("PATCH", f"/task-lists/{self.topic}/tasks/{tid}",
                          {"action": "claim", "fence_token": f0})
        # The commit response carries the new fence_token; fall back to a GET.
        f1 = None
        if isinstance(commit.get("body"), dict):
            f1 = commit["body"].get("fence_token")
        if not isinstance(f1, str):
            f1 = task_list_fence(node, self.topic)
        stale = node.req("PATCH", f"/task-lists/{self.topic}/tasks/{tid}",
                         {"action": "claim", "fence_token": f0})
        f2 = task_list_fence(node, self.topic)
        echoed = None
        if isinstance(stale.get("body"), dict):
            echoed = stale["body"].get("fence_token")
        committed_ok = (commit["status"] == 200 and isinstance(f0, str)
                        and isinstance(f1, str) and f1 != f0)
        # Honest fence: stale attempt did not advance the token, was not a
        # 200 commit, and (if exposed) echoed the unchanged current token.
        stale_non_mutating = (isinstance(f1, str) and isinstance(f2, str)
                              and f2 == f1 and stale["status"] != 200)
        echoed_ok = (echoed is None or echoed == f1)
        return {
            "fenced": committed_ok and stale_non_mutating and echoed_ok,
            "task_id": tid,
            "fence_before": f0, "fence_after_commit": f1,
            "fence_after_stale": f2,
            "commit_status": commit["status"],
            "stale_status": stale["status"],
            "stale_echoed_fence_token": echoed,
            "stale_body": stale["body"],
            "note": ("fence_token fences locally only; two replicas at the "
                     "same token can both commit"),
        }

    def _fence_malformed_rejected(self, node):
        """Malformed fence-token rejection oracle.

        A supplied-but-MALFORMED fence_token (u64 overflow, non-token
        string) must be rejected (non-200) WITHOUT mutating the task list —
        present-but-invalid must NOT collapse to 'absent'. Asserts behavior
        (non-200 + fence unchanged across every attempt), never the literal
        error string or status code."""
        task = node.req("POST", f"/task-lists/{self.topic}/tasks",
                        {"title": "malformed-fence-target",
                         "description": "malformed token must reject, "
                         "not mutate"})
        if task["status"] not in (200, 201) or not isinstance(
                task.get("body"), dict):
            return {"fenced": False,
                    "error": "malformed-fence task create failed",
                    "create_response": task}
        tid = task["body"].get("task_id")
        # 2^64 (u64 overflow) and a non-token string are unambiguously
        # malformed — neither is 'absent'.
        malformed = ["18446744073709551616", "!!!not-a-real-token!!!"]
        rejected_all = True
        non_mutating = True
        attempts = []
        for tok in malformed:
            f_before = task_list_fence(node, self.topic)
            r = node.req("PATCH", f"/task-lists/{self.topic}/tasks/{tid}",
                         {"action": "claim", "fence_token": tok})
            f_after = task_list_fence(node, self.topic)
            attempts.append({
                "token_repr": tok, "status": r["status"],
                "fence_changed": (f_before != f_after),
            })
            if r["status"] == 200:
                rejected_all = False
            if f_before != f_after:
                non_mutating = False
        return {"fenced": rejected_all and non_mutating,
                "task_id": tid, "attempts": attempts}

    def _fence_pre_restart_rejected(self, node, pre_restart_fence):
        """Pre-restart fence-token rejection oracle.

        A fence_token captured BEFORE a daemon restart must NOT be accepted
        after the restart: the fence epoch is a fresh incarnation, so the old
        token is invalid. Post-restart the node creates a task and PATCHes it
        with the captured pre-restart token — it MUST be rejected (non-200,
        non-mutating). Closes the restart-ABA window the wall-clock epoch
        left open."""
        if not isinstance(pre_restart_fence, str) or not pre_restart_fence:
            return {"fenced": False, "error": "no pre-restart fence captured"}
        task = node.req("POST", f"/task-lists/{self.topic}/tasks",
                        {"title": "pre-restart-fence-target",
                         "description": "stale pre-restart token must reject"})
        if task["status"] not in (200, 201) or not isinstance(
                task.get("body"), dict):
            return {"fenced": False,
                    "error": "pre-restart task create failed",
                    "create_response": task}
        tid = task["body"].get("task_id")
        f_before = task_list_fence(node, self.topic)
        stale = node.req("PATCH", f"/task-lists/{self.topic}/tasks/{tid}",
                         {"action": "claim",
                          "fence_token": pre_restart_fence})
        f_after = task_list_fence(node, self.topic)
        echoed = None
        if isinstance(stale.get("body"), dict):
            echoed = stale["body"].get("fence_token")
        non_mutating = (isinstance(f_before, str) and isinstance(f_after, str)
                        and f_after == f_before)
        rejected = stale["status"] != 200
        echoed_ok = (echoed is None or echoed == f_before)
        return {
            "fenced": rejected and non_mutating and echoed_ok,
            "task_id": tid,
            "pre_restart_fence": pre_restart_fence,
            "post_restart_fence_before": f_before,
            "fence_after_stale": f_after,
            "stale_status": stale["status"],
            "stale_echoed_fence_token": echoed,
            "stale_body": stale["body"],
        }

    def _claim_remote_invalidation(self, local, remote):
        """Remote-invalidation fence oracle.

        A local claim guarded by a fence_token that a SINCE-MERGED REMOTE
        delta has invalidated MUST NOT mutate. The fence must observe merged
        remote state, not only local mutations. Sequence:
          1. local creates a claim target task T and reads fence_token F_before;
          2. remote peer adds a different task (delta published);
          3. wait for that delta to merge into local (token changes);
          4. local claims T with fence_token=F_before → must be rejected.
        Asserts non-mutation + current fence_token echo, never the literal
        error string.
        """
        a = self.args
        task = local.req("POST", f"/task-lists/{self.topic}/tasks",
                         {"title": "rinv-target",
                          "description": "remote invalidation target"})
        if task["status"] not in (200, 201) or not isinstance(
                task.get("body"), dict):
            return {"fenced": False, "error": "rinv task create failed",
                    "create_response": task}
        tid = task["body"].get("task_id")
        f_before = task_list_fence(local, self.topic)
        # Remote mutation on the shared list.
        rtask = remote.req("POST", f"/task-lists/{self.topic}/tasks",
                           {"title": "rinv-remote-delta",
                            "description": "merged delta advances version"})
        if rtask["status"] not in (200, 201):
            return {"fenced": False, "error": "remote task create failed",
                    "fence_before": f_before, "remote_response": rtask}
        # Wait for the NAMED remote mutation to be visible on local AND to
        # advance the fence. Requiring the specific task to be visible (not
        # just any fence change) closes the idempotent-churn false positive:
        # bare revision churn from a redelivered/no-op delta must NOT satisfy
        # this gate — only the named remote mutation does.
        rtid = rtask["body"].get("task_id") if isinstance(
            rtask.get("body"), dict) else None
        t0 = time.monotonic()
        f_merged = f_before
        named_visible = False
        while time.monotonic() - t0 < a.live_gate:
            f_merged = task_list_fence(local, self.topic)
            named_visible = (rtid is not None
                             and task_visible(local, self.topic, rtid))
            if named_visible and f_merged is not None \
                    and f_merged != f_before:
                break
            time.sleep(a.poll_interval)
        merged = (named_visible and f_merged is not None
                  and f_merged != f_before)
        if not merged:
            return {"fenced": False, "error": "named remote mutation never "
                    "merged (visible + fence advance)",
                    "named_remote_task_id": rtid,
                    "named_remote_visible": named_visible,
                    "fence_before": f_before, "fence_merged": f_merged}
        # Local claim guarded by the pre-merge token must be rejected.
        stale = local.req("PATCH", f"/task-lists/{self.topic}/tasks/{tid}",
                          {"action": "claim", "fence_token": f_before})
        f_after = task_list_fence(local, self.topic)
        echoed = None
        if isinstance(stale.get("body"), dict):
            echoed = stale["body"].get("fence_token")
        stale_non_mutating = (f_after == f_merged and stale["status"] != 200)
        echoed_ok = (echoed is None or echoed == f_merged)
        return {
            "fenced": stale_non_mutating and echoed_ok,
            "task_id": tid,
            "named_remote_task_id": rtid,
            "named_remote_visible": named_visible,
            "fence_before": f_before, "fence_merged": f_merged,
            "fence_after_stale": f_after,
            "stale_status": stale["status"],
            "stale_echoed_fence_token": echoed,
            "stale_body": stale["body"],
            "note": ("local fence rejects a token invalidated by a merged "
                     "remote delta"),
        }

    def phase_signed_store_nonowner(self):
        a, creator = self.args, self.creator()
        writer = self.nodes[1]
        creator_aid = node_agent_id(creator)
        writer_aid = node_agent_id(writer)
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
                if key_value_matches(creator, self.store, "unauthorized",
                                     "intruder-value"):
                    propagated = True
                    break
                time.sleep(a.poll_interval)
        rejected = put["status"] == 403
        local_fork = local["status"] == 200
        observed = {
            "writer": writer.name,
            "creator_agent_id": creator_aid,
            "writer_agent_id": writer_aid,
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

        # ── Ownership-binding oracle — HARD gate (finalized contract) ──────
        # Ownership is set ONLY at construction; the soak joiner pins
        # expected_owner=creator at join, so it anchors to the creator
        # IMMEDIATELY (no async race, no first-self-claim possible). Both the
        # creator and the joiner must be "anchored" with owner == creator.
        owner_creator = store_meta(creator, self.store)
        owner_writer = store_meta(writer, self.store)
        owner_exposed = owner_creator["exposed"] and owner_writer["exposed"]
        binding_ok = True
        if creator_aid:
            # Creator created this Signed store ⇒ owner == creator, anchored.
            binding_ok = binding_ok and owner_creator["owner"] == creator_aid
            if owner_creator["ownership_status"] is not None:
                binding_ok = binding_ok and (
                    owner_creator["ownership_status"] == "anchored")
        if writer_aid:
            # Joiner pinned expected_owner=creator ⇒ anchored to creator,
            # NEVER self-claimed. owner != writer; status "anchored";
            # owner == creator. A forged OwnerAnnounce cannot flip this.
            wo, wst = owner_writer["owner"], owner_writer["ownership_status"]
            binding_ok = binding_ok and wo != writer_aid
            if wst is not None:
                binding_ok = binding_ok and wst == "anchored"
            if wo is not None:
                binding_ok = binding_ok and wo == creator_aid
        self.gate("signed_store_owner_binding",
                  owner_exposed and binding_ok,
                  {"owner_field_exposed": owner_exposed,
                   "store_meta_creator": owner_creator,
                   "store_meta_writer": owner_writer,
                   "creator_agent_id": creator_aid,
                   "writer_agent_id": writer_aid,
                   "binding_ok": binding_ok,
                   "note": ("hard gate: owner/policy/version/ownership_status "
                            "exposed; join anchors to creator via "
                            "expected_owner. Deep forged-OwnerAnnounce "
                            "injection is the malicious_owner_announce gate")})
        # Propagation to the owner would be a NEW defect (inbound
        # enforcement regression) — hard gate regardless of mode.
        self.gate("signed_store_no_owner_propagation", not propagated,
                  {"propagated_to_owner": propagated})
        status = self.report["phases"]["signed_store_nonowner_write"]["status"]
        log(f"run {self.idx}: signed_store_nonowner_write {status} "
            f"put={put['status']} local_fork={local_fork} "
            f"propagated={propagated} owner_exposed={owner_exposed}")

    def phase_named_new_port_reconnect(self):
        """Named-node new-port reconnect gate (P1 proactive reconnect).

        Stop a running peer and restart it on a FORCED DIFFERENT QUIC port
        (same data_dir ⇒ same MachineId/PeerId), bootstrapping to the still-
        running creator, with NO manual rejoin. Require:
          (a) same identity — post-restart PeerId == pre-restart PeerId;
          (b) transport-path reconnect — the restarted node's ACTUAL
              connected peer set (per_peer_transport, not the cached
              identical endpoint — the port changed) includes the creator's
              PeerId;
          (c) CRDT recovery — a task created while the peer was down becomes
              visible on the restarted node WITHOUT an explicit rejoin.
        """
        a, creator = self.args, self.creator()
        victim = self.nodes[-1]
        creator_pid = node_peer_id(creator)
        victim_pid_before = node_peer_id(victim)
        peers_before = sorted(node_connected_peer_ids(victim))
        old_port = victim.quic_port
        new_port = a.quic_base + 200 + self.idx  # well clear, per-run
        with self.phase("named_new_port_reconnect"):
            log(f"run {self.idx}: stopping {victim.name} for new-port "
                f"restart")
            victim.stop()
            time.sleep(2)
            # Creator mutates while the peer is DOWN.
            task = creator.req("POST", f"/task-lists/{self.topic}/tasks",
                               {"title": "newport-task",
                                "description": "created while peer down; "
                                "no manual rejoin"})
            np_tid = task["body"].get("task_id") if isinstance(
                task.get("body"), dict) else None
            # Restart on a FORCED different port, same data_dir (same
            # MachineId), bootstrapping to the creator only.
            victim.reconfigure_port(new_port, [creator.quic_port])
            log(f"run {self.idx}: restarting {victim.name} on new quic "
                f"port {new_port} (was {old_port})")
            victim.start()
            victim.wait_ready()
            # Wait for transport reconnect to the creator AND CRDT recovery
            # of the down-window task, with no explicit rejoin.
            t0 = time.monotonic()
            reconnected = False
            recovered = False
            while time.monotonic() - t0 < a.restart_gate:
                if creator_pid and creator_pid in \
                        node_connected_peer_ids(victim):
                    reconnected = True
                if np_tid and task_visible(victim, self.topic, np_tid):
                    recovered = True
                if reconnected and recovered:
                    break
                time.sleep(a.poll_interval)
        # Read post-restart PeerId FRESH (node_peer_id caches); this verifies
        # the daemon actually reports the same identity on the new port.
        victim_pid_after = (connectivity_snapshot(victim) or {}).get("peer_id")
        peers_after = sorted(node_connected_peer_ids(victim))
        same_identity = (bool(victim_pid_before) and bool(victim_pid_after)
                         and victim_pid_before == victim_pid_after)
        observed = {
            "node": victim.name,
            "creator_peer_id": creator_pid,
            "victim_peer_id_before": victim_pid_before,
            "victim_peer_id_after": victim_pid_after,
            "same_identity": same_identity,
            "old_quic_port": old_port,
            "new_quic_port": new_port,
            "connected_peers_before": peers_before,
            "connected_peers_after": peers_after,
            "reconnected_to_creator": reconnected,
            "down_window_task_id": np_tid,
            "crdt_recovered_without_rejoin": recovered,
            "gate_secs": a.restart_gate,
        }
        fixed = same_identity and reconnected and recovered
        self.known_gap_gate("named_new_port_reconnect",
                            "named_new_port_reconnect", fixed=fixed,
                            observed=observed)
        log(f"run {self.idx}: named_new_port_reconnect "
            f"{'fixed' if fixed else 'gap'} same_id={same_identity} "
            f"reconnected={reconnected} recovered={recovered}")

    # -- driver ------------------------------------------------------------

    def execute(self):
        try:
            self.start_cluster_creator_only()
            self.phase_cold_join()
            self.phase_live_propagation()
            self.phase_restart_recovery()
            self.phase_concurrent_claims()
            self.phase_signed_store_nonowner()
            self.phase_named_new_port_reconnect()
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
# Prerequisite-gated security/skew gates
# ──────────────────────────────────────────────────────────────────────────
#
# These gates cover threats the single-version same-host soak CANNOT: real
# protocol version skew (needs a legacy binary) and forged OwnerAnnounce
# injection (needs a gossip-level harness, not a REST backdoor). Each runs for
# real when its prerequisite binary is supplied, otherwise it reports
# UNSUPPORTED with the exact missing prerequisite — never silently skipped and
# never faked by degrading the current binary.

def _spawn_isolated_node(name, api_port, quic_port, root_dir, x0xd,
                        log_level, bootstrap_quic_ports):
    """Build, configure, and start a single isolated node, returning it once
    /health is up and the api token is written. Used by the prerequisite
    gates which need bespoke topologies/binaries outside the soak Run."""
    node = Node(name, api_port, quic_port, root_dir, x0xd, log_level)
    node.write_config(bootstrap_quic_ports)
    log(f"starting {name} (api={api_port}, quic={quic_port}, "
        f"binary={x0xd})")
    node.start()
    node.wait_ready()
    return node


def run_mixed_version_gate(args, out_dir):
    """Mixed-version (current + legacy v0.30.1) interop gate — BOTH directions.

    LOAD-BEARING (legacy v0.30.1 owner + current anchored joiner): the real
    legacy owner creates+writes; the current joiner pins expected_owner and
    must recover historical + live values. This is the convergence-with-anchor
    case — the load-bearing direction for ownership/version skew.
    DEGRADED (current owner + legacy joiner): OwnerAnnounce-additive / safe
    interop characterization.

    Both need a REAL legacy binary (X0XD_LEGACY_BINARY); the skew is NEVER
    faked by degrading the current binary. --expect-fixed requires BOTH.
    Returns a list of two gate dicts.
    """
    legacy = args.legacy_binary
    if not legacy or not pathlib.Path(legacy).is_file():
        note = UNSUPPORTED_PREREQ_NOTES["mixed_version_skew"]
        lb = {"name": "mixed_version_skew_load_bearing",
              "status": "unsupported", "unsupported": note,
              "legacy_binary": str(legacy) if legacy else None}
        dg = {"name": "mixed_version_skew_degraded",
              "status": "unsupported", "unsupported": note,
              "legacy_binary": str(legacy) if legacy else None}
        log("mixed_version_skew: UNSUPPORTED (both directions) — set "
            "X0XD_LEGACY_BINARY (or --legacy-binary) to a v0.30.1 x0xd")
        return [lb, dg]
    legacy = pathlib.Path(legacy)
    # File existence is NOT authentication: the legacy binary must be EXACTLY
    # v0.30.1. A wrong-version "legacy" is a hard FAIL of both directions —
    # not UNSUPPORTED (the prerequisite was supplied, just wrong), and never a
    # silent green. The release-oracle provenance check enforces the same.
    lver = parse_version(binary_version(legacy))
    if lver != LEGACY_REQUIRED_VERSION:
        err = (f"legacy binary is v{lver}, must be exactly "
               f"v{LEGACY_REQUIRED_VERSION}; file existence alone is not "
               f"authentication — supply an authenticated v0.30.1 x0xd")
        log(f"mixed_version_skew: FAIL — {err}")
        return [
            {"name": "mixed_version_skew_load_bearing", "status": "fail",
             "error": err, "legacy_version": lver,
             "legacy_binary": str(legacy)},
            {"name": "mixed_version_skew_degraded", "status": "fail",
             "error": err, "legacy_version": lver,
             "legacy_binary": str(legacy)},
        ]
    return [_mixed_version_load_bearing(args, out_dir, legacy),
            _mixed_version_degraded(args, out_dir, legacy)]


def _mixed_version_load_bearing(args, out_dir, legacy):
    """LOAD-BEARING direction: legacy v0.30.1 owner + current anchored joiner
    (ONLINE-owner convergence across version skew).

    The legacy owner (ONLINE) creates the Signed store and writes a historical
    key; the current-binary joiner pins expected_owner=<legacy owner AgentId>
    at join and MUST recover both the historical key and a live key the owner
    writes after join. The historical key recovers via the owner's republished
    full_delta, whose sender-auth passes BECAUSE the owner is the sender — so
    this proves online-owner convergence-with-anchor across skew (blueprint §6
    row-1), NOT offline-owner relay recovery.

    Scope (do NOT over-claim): offline-owner relay recovery (owner DOWN, a
    replica relays a cached owner-signed checkpoint) is NOT exercised here —
    it is store-layer-only (checkpoint T11) and defended by content-root
    verification (a relayed value whose recomputed root != the owner-signed
    checkpoint is rejected). The impossible no-anchor-against-v0.30.1-owner
    case (§6 row-2 / T3) is likewise NOT asserted here — covered at the
    store/unit layer and documented as impossible; the harness does not
    fake-cover either.
    """
    gate = {"name": "mixed_version_skew_load_bearing"}
    mv_dir = out_dir / "mv-load-bearing"
    mv_dir.mkdir(parents=True, exist_ok=True)
    store = f"x0x-convergence-mv-lb-{int(time.time())}"
    nodes = []
    try:
        # Legacy binary = OWNER/creator; current binary = anchored joiner.
        owner = _spawn_isolated_node(
            "mv-lb-owner", args.api_base + 10, args.quic_base + 10,
            mv_dir, legacy, args.log_level, [])
        nodes.append(owner)
        time.sleep(args.stagger_secs)
        joiner = _spawn_isolated_node(
            "mv-lb-joiner", args.api_base + 11, args.quic_base + 11,
            mv_dir, args.x0xd, args.log_level, [args.quic_base + 10])
        nodes.append(joiner)

        # Legacy owner creates the store and writes a HISTORICAL key.
        owner.req("POST", "/stores",
                  {"name": "mv lb manifests", "topic": store})
        owner.req("PUT", f"/stores/{store}/historical",
                  {"value": b64("owner-historical"),
                   "content_type": "text/plain"})
        owner_aid = node_agent_id(owner)  # v0.30.1 /agent shape
        # Current joiner pins expected_owner = legacy owner; must anchor.
        joiner.req("POST", f"/stores/{store}/join",
                   ({"expected_owner": owner_aid} if owner_aid else {}))
        # Historical recovery: joiner recovers the pre-join key with EXACT
        # decoded bytes (presence alone is not convergence).
        hist = sample_until(
            {"key": lambda: key_value_matches(
                joiner, store, "historical", "owner-historical")},
            gate_secs=args.cold_gate, interval=args.poll_interval)
        hist_hash = key_content_hash(joiner, store, "historical")
        # Live recovery: owner writes AFTER join; joiner must see it too,
        # again with EXACT decoded bytes + owner-signed content_hash.
        owner.req("PUT", f"/stores/{store}/live",
                  {"value": b64("owner-live"),
                   "content_type": "text/plain"})
        live = sample_until(
            {"key": lambda: key_value_matches(
                joiner, store, "live", "owner-live")},
            gate_secs=args.live_gate, interval=args.poll_interval)
        live_hash = key_content_hash(joiner, store, "live")
        jm = store_meta(joiner, store)
        anchored = (jm["ownership_status"] == "anchored"
                    and (owner_aid is None or jm["owner"] == owner_aid))
        owner_alive = (owner.running
                       and owner.req("GET", "/health")["status"] == 200)
        gate.update({
            "status": ("pass" if hist["key"] is not None
                       and live["key"] is not None and anchored and owner_alive
                       else "fail"),
            "historical_content_hash": hist_hash,
            "live_content_hash": live_hash,
            "store": store,
            "owner_agent_id": owner_aid,
            "historical_recovery_secs": hist["key"],
            "live_recovery_secs": live["key"],
            "joiner_anchored": anchored,
            "joiner_store_meta": jm,
            "legacy_owner_alive": owner_alive,
            "owner_binary": str(legacy),
            "joiner_binary": str(args.x0xd),
            "scope": ("online_owner_convergence_across_skew; historical "
                      "key recovers via owner-republished full_delta "
                      "(sender-auth: owner IS sender). offline-owner relay "
                      "recovery is store-layer (checkpoint T11) + "
                      "content_root verification, NOT daemon-gated"),
        })
        log(f"mixed_version_skew_load_bearing: {gate['status']} "
            f"hist={hist['key']}s live={live['key']}s anchored={anchored}")
    except Exception as e:
        gate["status"] = "fail"
        gate["error"] = f"{type(e).__name__}: {e}"
        log(f"mixed_version_skew_load_bearing: EXCEPTION {e}")
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
    return gate


def _mixed_version_degraded(args, out_dir, legacy):
    """DEGRADED direction: current owner + legacy v0.30.1 joiner.

    Characterization coverage (less load-bearing): OwnerAnnounce is ADDITIVE —
    the legacy joiner that cannot decode the new variant skips it without
    crashing — and the owner's key replicates. The legacy version predates
    expected_owner, so its join sends no anchor; we record the observed PUT
    status rather than asserting a specific code.
    """
    gate = {"name": "mixed_version_skew_degraded"}
    mv_dir = out_dir / "mv-degraded"
    mv_dir.mkdir(parents=True, exist_ok=True)
    store = f"x0x-convergence-mv-dg-{int(time.time())}"
    nodes = []
    try:
        # Current binary = owner/creator; legacy binary = joiner.
        owner = _spawn_isolated_node(
            "mv-dg-owner", args.api_base + 12, args.quic_base + 12,
            mv_dir, args.x0xd, args.log_level, [])
        nodes.append(owner)
        time.sleep(args.stagger_secs)
        joiner = _spawn_isolated_node(
            "mv-dg-joiner", args.api_base + 13, args.quic_base + 13,
            mv_dir, legacy, args.log_level, [args.quic_base + 12])
        nodes.append(joiner)

        owner.req("POST", "/stores",
                  {"name": "mv dg manifests", "topic": store})
        owner.req("PUT", f"/stores/{store}/owned",
                  {"value": b64("owner-value"),
                   "content_type": "text/plain"})
        joiner.req("POST", f"/stores/{store}/join")
        arrivals = sample_until(
            {"key": lambda: key_value_matches(
                joiner, store, "owned", "owner-value")},
            gate_secs=args.cold_gate, interval=args.poll_interval)
        owned_hash = key_content_hash(joiner, store, "owned")
        legacy_alive = (joiner.running
                        and joiner.req("GET", "/health")["status"] == 200)
        # The legacy joiner (non-owner; it predates expected_owner) attempts a
        # write. Safe DEGRADED interop means this NON-OWNER write must NOT
        # propagate to the current owner — inbound enforcement holds even
        # against a legacy peer. PASS requires NO unauthorized propagation.
        jput = joiner.req("PUT", f"/stores/{store}/from-legacy",
                          {"value": b64("legacy-write"),
                           "content_type": "text/plain"})
        jlocal = joiner.req("GET", f"/stores/{store}/from-legacy")
        propagated = False
        deadline = time.monotonic() + args.fork_window
        while time.monotonic() < deadline:
            if key_value_matches(owner, store, "from-legacy",
                                 "legacy-write"):
                propagated = True
                break
            time.sleep(args.poll_interval)
        # Owner state must stay EXACT: it keeps its own key (exact bytes) and
        # never acquires the legacy non-owner write.
        owner_kept_owned = key_value_matches(owner, store, "owned",
                                             "owner-value")
        owner_clean = not key_value_bytes(owner, store, "from-legacy")
        gate.update({
            "status": ("pass" if arrivals["key"] is not None and legacy_alive
                       and not propagated and owner_kept_owned and owner_clean
                       else "fail"),
            "store": store,
            "interop_key_secs": arrivals["key"],
            "owned_content_hash": owned_hash,
            "legacy_joiner_alive": legacy_alive,
            "legacy_joiner_put_status": jput["status"],
            "legacy_local_fork": jlocal["status"] == 200,
            "legacy_write_propagated_to_owner": propagated,
            "owner_kept_owned_exact": owner_kept_owned,
            "owner_clean_of_legacy_write": owner_clean,
            "owner_binary": str(args.x0xd),
            "legacy_binary": str(legacy),
            "scope": ("degraded interop: owner's key replicates to the legacy "
                      "joiner with EXACT bytes; the legacy non-owner write "
                      "must NOT propagate to the owner (no unauthorized "
                      "propagation) and owner state stays exact"),
        })
        log(f"mixed_version_skew_degraded: {gate['status']} "
            f"interop={arrivals['key']}s legacy_alive={legacy_alive} "
            f"propagated={propagated}")
    except Exception as e:
        gate["status"] = "fail"
        gate["error"] = f"{type(e).__name__}: {e}"
        log(f"mixed_version_skew_degraded: EXCEPTION {e}")
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
    return gate


def run_malicious_owner_announce_gate(args, out_dir):
    """Hostile OwnerAnnounce injection gate (in-repo, no external binary).

    A rogue daemon self-claims ownership of the SAME store topic: creating the
    store locally makes it the owner of its own replica (store_id =
    for_topic_owner(topic, rogue)), so its background sync loop publishes a
    GENUINE OwnerAnnounce{owner: rogue} on the shared <topic>/state-sync side
    channel in response to the joiner's StateRequest — signed by the rogue, so
    sender == claimed owner and it passes the pub/sub sender check. It races
    this self-claim against the legitimate owner.

    The anchored joiner (joined with expected_owner=legit) MUST stay bound to
    the legit owner and NEVER flip to the rogue: ownership is set only at
    construction, so learn_ownership() rejects the conflicting announce. The
    rogue's deltas are also rejected (different store_id). This is driven
    ENTIRELY via public REST create/join APIs — no fake write-path backdoor,
    no crate-private injection, no bincode crafting.
    """
    gate = {"name": "malicious_owner_announce"}
    mv_dir = out_dir / "malicious-announce"
    mv_dir.mkdir(parents=True, exist_ok=True)
    store = f"x0x-convergence-mal-{int(time.time())}"
    nodes = []
    try:
        legit = _spawn_isolated_node(
            "mal-legit", args.api_base + 20, args.quic_base + 20,
            mv_dir, args.x0xd, args.log_level, [])
        nodes.append(legit)
        time.sleep(args.stagger_secs)
        # Rogue bootstraps to legit and is started BEFORE the joiner so its
        # sync loop is registered and ready to race its self-claim.
        rogue = _spawn_isolated_node(
            "mal-rogue", args.api_base + 21, args.quic_base + 21,
            mv_dir, args.x0xd, args.log_level, [args.quic_base + 20])
        nodes.append(rogue)

        legit_aid = node_agent_id(legit)
        rogue_aid = node_agent_id(rogue)
        # Legit owner creates the store and writes a key.
        legit.req("POST", "/stores", {"name": "mal legit", "topic": store})
        legit.req("PUT", f"/stores/{store}/legit-key",
                  {"value": b64("legit-value"),
                   "content_type": "text/plain"})
        # Rogue SELF-CLAIMS the same topic: creating it locally makes the
        # rogue the owner of its replica, so its sync loop will publish a
        # genuine OwnerAnnounce{owner: rogue} on <store>/state-sync.
        rogue.req("POST", "/stores", {"name": "mal rogue", "topic": store})
        rogue.req("PUT", f"/stores/{store}/rogue-key",
                  {"value": b64("rogue-value"),
                   "content_type": "text/plain"})
        time.sleep(args.stagger_secs)
        # Joiner anchors to the legit owner (expected_owner).
        joiner = _spawn_isolated_node(
            "mal-joiner", args.api_base + 22, args.quic_base + 22,
            mv_dir, args.x0xd, args.log_level, [args.quic_base + 20])
        nodes.append(joiner)
        joiner.req("POST", f"/stores/{store}/join",
                   ({"expected_owner": legit_aid} if legit_aid else {}))
        # Wait for convergence: the joiner recovers the legit key with EXACT
        # decoded bytes (legit delta merges; same store_id).
        arrivals = sample_until(
            {"legit_key": lambda: key_value_matches(
                joiner, store, "legit-key", "legit-value")},
            gate_secs=args.cold_gate, interval=args.poll_interval)
        # POSITIVE ATTACK RECEIPT: poll for the conflict the rogue
        # OwnerAnnounce{owner:rogue} produces against the legit anchor. PASS
        # must PROVE the rogue identity was seen and rejected — not merely
        # that the joiner stayed anchored (anchored-alone permits the false
        # positive where the rogue announce never arrived).
        conflict_observed = False
        deadline = time.monotonic() + args.fork_window
        while time.monotonic() < deadline:
            jmc = store_meta(joiner, store)
            if jmc["ownership_status"] == "conflict" and \
                    (legit_aid is None or jmc["owner"] == legit_aid):
                conflict_observed = True
                break
            time.sleep(args.poll_interval)
        jm = store_meta(joiner, store)
        # Stable legit owner: the anchor holds across the attack — owner is
        # legit, NEVER the rogue.
        owner_stable = (
            (legit_aid is None or jm["owner"] == legit_aid)
            and (rogue_aid is None or jm["owner"] != rogue_aid))
        # The rogue's key (different store_id) must never appear on the
        # joiner — exact bytes, not mere presence.
        rogue_key_leaked = key_value_matches(joiner, store, "rogue-key",
                                             "rogue-value")
        # POST-ATTACK legit write: after the attack the legit owner can still
        # write and the joiner recovers it — proving the anchor is not wedged
        # by the rejected conflict.
        legit.req("PUT", f"/stores/{store}/post-attack",
                  {"value": b64("legit-after-attack"),
                   "content_type": "text/plain"})
        post_attack = sample_until(
            {"key": lambda: key_value_matches(
                joiner, store, "post-attack", "legit-after-attack")},
            gate_secs=args.live_gate, interval=args.poll_interval)
        post_attack_recovered = post_attack["key"] is not None
        gate.update({
            "status": ("pass" if conflict_observed and owner_stable
                       and not rogue_key_leaked
                       and arrivals["legit_key"] is not None
                       and post_attack_recovered else "fail"),
            "store": store,
            "legit_agent_id": legit_aid,
            "rogue_agent_id": rogue_aid,
            "joiner_store_meta": jm,
            "conflict_with_rogue_observed": conflict_observed,
            "owner_stable_to_legit": owner_stable,
            "legit_key_recovery_secs": arrivals["legit_key"],
            "rogue_key_leaked_to_joiner": rogue_key_leaked,
            "post_attack_key_recovery_secs": post_attack["key"],
            "note": ("rogue self-claimed the same topic; its sync loop "
                     "published a genuine OwnerAnnounce{owner:rogue}; PASS "
                     "requires a POSITIVE conflict with the rogue identity, "
                     "a stable legit owner, NO rogue content, and a legit "
                     "post-attack write the joiner recovers"),
        })
        log(f"malicious_owner_announce: {gate['status']} "
            f"conflict={conflict_observed} owner_stable={owner_stable} "
            f"legit_key={arrivals['legit_key']}s "
            f"rogue_leaked={rogue_key_leaked} "
            f"post_attack={post_attack['key']}s")
    except Exception as e:
        gate["status"] = "fail"
        gate["error"] = f"{type(e).__name__}: {e}"
        log(f"malicious_owner_announce: EXCEPTION {e}")
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
    return gate


def run_forged_first_seen_gate(args, out_dir):
    """First-seen forged/unattested TaskItem admission gate (in-repo injector).

    A hostile gossip publisher ships a first-seen TaskItem carrying a
    Claimed/Done element with NO matching attestation (or a malformed/
    attacker-key/wrong-agent/wrong-scope attestation) over the live task-list
    sync path (topic → decode_delta::<TaskListDelta> → merge_delta → admit()).
    The fail-closed admission routine MUST purge it, leaving
    current_state()==Empty: the forged task never appears, the list
    version/fence does not churn, and a legitimate post-attack claim still
    resolves. Driven by the in-repo `x0xd-forge-injector` binary (built by
    `just convergence-release`), which crafts the unattested delta and
    publishes it over REAL gossip via the daemon's /publish wire API — never
    faked via REST. A missing injector is a hard setup failure (the recipe
    builds it); UNSUPPORTED without it, FAIL under --expect-fixed.
    """
    gate = {"name": "forged_first_seen_task"}
    inj = getattr(args, "forge_injector", None)
    if not inj or not pathlib.Path(inj).is_file():
        note = UNSUPPORTED_PREREQ_NOTES["forged_first_seen_task"]
        log("forged_first_seen_task: UNSUPPORTED — in-repo injector absent "
            f"at {inj}; build `cargo build --release --bin x0xd-forge-injector` "
            "(the release recipe provisions it)")
        gate.update({"status": "unsupported", "unsupported": note,
                     "injector": str(inj) if inj else None})
        return gate
    inj = pathlib.Path(inj)
    fg_dir = out_dir / "forged-first-seen"
    fg_dir.mkdir(parents=True, exist_ok=True)
    topic = f"x0x.convergence.forged.{int(time.time())}"
    nodes = []

    def list_ids(node):
        r = node.req("GET", f"/task-lists/{topic}/tasks")
        if r["status"] != 200 or not isinstance(r["body"], dict):
            return set()
        return {t.get("id") for t in r["body"].get("tasks", [])
                if isinstance(t, dict)}

    try:
        creator = _spawn_isolated_node(
            "forged-creator", args.api_base + 40, args.quic_base + 40,
            fg_dir, args.x0xd, args.log_level, [])
        nodes.append(creator)
        time.sleep(args.stagger_secs)
        receiver = _spawn_isolated_node(
            "forged-receiver", args.api_base + 41, args.quic_base + 41,
            fg_dir, args.x0xd, args.log_level, [args.quic_base + 40])
        nodes.append(receiver)
        creator.req("POST", "/task-lists",
                    {"name": "forged admission", "topic": topic})
        legit = creator.req("POST", f"/task-lists/{topic}/tasks",
                            {"title": "legit-baseline",
                             "description": "must survive the forged delta"})
        legit_tid = legit["body"].get("task_id") if isinstance(
            legit.get("body"), dict) else None
        # The receiver MUST join the task list (subscribe to the topic) or it
        # receives neither the legit task nor the forged delta — which would
        # make the security check vacuous (sees nothing) and the liveness check
        # fail. Join uses the same POST /task-lists as the core cold-join phase.
        receiver.req("POST", "/task-lists",
                     {"name": "forged admission", "topic": topic})
        # Baseline convergence; snapshot receiver list state BEFORE attack.
        sample_until({"t": lambda: task_visible(receiver, topic, legit_tid)},
                     gate_secs=args.cold_gate, interval=args.poll_interval)
        ids_before = list_ids(receiver)
        ver_before = task_list_version(receiver, topic)
        fence_before = task_list_fence(receiver, topic)
        # Hostile injection: publish an unattested first-seen TaskItem over
        # real gossip via the daemon's /publish wire API.
        cmd = [str(inj), "--daemon", creator.base, "--token", creator.token,
               "--topic", topic, "--variant", "missing_att"]
        log(f"forged_first_seen_task: injector {cmd}")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=60)
        published = False
        try:
            outj = json.loads(proc.stdout) if proc.stdout.strip() else {}
            published = bool(outj.get("published"))
        except ValueError:
            outj = {"raw": proc.stdout}
        # Let the forged delta propagate. The security property is NO CLAIM
        # HIJACK: the forged Claimed{victim,ts:1} must NOT make any task
        # claimed-by the victim. admit() may either reject the whole forged
        # task (absent) OR purge the element leaving an Empty task — both are
        # acceptable; the FORBIDDEN outcome is claimed_by == victim.
        forged_tid = outj.get("forged_task_id") if isinstance(outj, dict) else None
        victim_hex = outj.get("victim_agent") if isinstance(outj, dict) else None
        time.sleep(args.fork_window)
        ft = get_task(receiver, topic, forged_tid) if forged_tid else None
        ft_claimed_by = claimed_by_of(ft) if ft else None
        claim_hijacked = (ft is not None and victim_hex is not None
                          and ft_claimed_by == victim_hex)
        # Forged task absent, OR present but unclaimed (Empty — element purged).
        forged_absent_or_empty = (ft is None or ft_claimed_by is None)
        ver_after = task_list_version(receiver, topic)
        fence_after = task_list_fence(receiver, topic)
        # Legit post-attack claim must still resolve (admission not wedged).
        claim = creator.req("PATCH", f"/task-lists/{topic}/tasks/{legit_tid}",
                            {"action": "claim",
                             "fence_token": task_list_fence(creator, topic)})
        claim_resolved = sample_until(
            {"c": lambda: claimed_by_of(
                get_task(receiver, topic, legit_tid)) is not None},
            gate_secs=args.live_gate, interval=args.poll_interval)["c"] \
            is not None
        gate.update({
            "status": ("pass" if published and not claim_hijacked
                       and forged_absent_or_empty and claim_resolved
                       else "fail"),
            "store": topic,
            "injector": str(inj),
            "injector_sha256": sha256_file(inj),
            "injector_version": binary_version(inj),
            "injector_rc": proc.returncode,
            "injector_output": outj,
            "forged_task_id": forged_tid,
            "victim_agent": victim_hex,
            "forged_task_on_receiver": ft is not None,
            "forged_task_claimed_by": ft_claimed_by,
            "claim_hijacked": claim_hijacked,
            "forged_absent_or_empty": forged_absent_or_empty,
            "version_before": ver_before, "version_after": ver_after,
            "fence_before": fence_before, "fence_after": fence_after,
            "post_attack_claim_status": claim["status"],
            "post_attack_claim_resolved": claim_resolved,
            "scope": ("hostile injector published an unattested first-seen "
                     "TaskItem over real gossip; admit() must purge the forged "
                     "Claimed element so no task is claimed-by the victim "
                     "(task absent OR Empty) and a legit post-attack claim "
                     "still resolves"),
        })
        log(f"forged_first_seen_task: {gate['status']} "
            f"published={published} hijacked={claim_hijacked} "
            f"absent_or_empty={forged_absent_or_empty} "
            f"claim_resolved={claim_resolved}")
    except Exception as e:
        gate["status"] = "fail"
        gate["error"] = f"{type(e).__name__}: {e}"
        log(f"forged_first_seen_task: EXCEPTION {e}")
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
    return gate


def run_owner_offline_checkpoint_gate(args, out_dir):
    """Owner-offline checkpoint recovery + delete/tamper-integrity gate (P0).

    Exercises the checkpoint-recovery contract end to end via REST:
      1. owner multi-writes k1, k2; the anchored relay matches EXACT bytes;
      2. owner updates k1; relay matches the EXACT new bytes (k2 unchanged);
      3. owner deletes k2; relay drops it (delete recovery — replicas must
         NOT retain deleted keys);
      4. owner deletes k1 → EMPTY; relay shows both absent (the empty-
         checkpoint early-return defect);
      5. owner writes a final key; relay matches exact;
      6. owner STOPPED; a fresh anchored joiner bootstraps ONLY to the relay
         (not the owner) and recovers the EXACT final state — final key
         exact, k1/k2 ABSENT (no resurrection). Owner-offline relay recovery
         with content integrity.
    All current-binary. FAIL ⇒ run fails (P0).
    """
    gate = {"name": "owner_offline_checkpoint_recovery"}
    cp_dir = out_dir / "checkpoint-recovery"
    cp_dir.mkdir(parents=True, exist_ok=True)
    store = f"x0x-convergence-cp-{int(time.time())}"
    nodes = []
    try:
        owner = _spawn_isolated_node(
            "cp-owner", args.api_base + 30, args.quic_base + 30,
            cp_dir, args.x0xd, args.log_level, [])
        nodes.append(owner)
        time.sleep(args.stagger_secs)
        relay = _spawn_isolated_node(
            "cp-relay", args.api_base + 31, args.quic_base + 31,
            cp_dir, args.x0xd, args.log_level, [args.quic_base + 30])
        nodes.append(relay)
        owner_aid = node_agent_id(owner)
        owner.req("POST", "/stores",
                  {"name": "cp manifests", "topic": store})
        relay.req("POST", f"/stores/{store}/join",
                  ({"expected_owner": owner_aid} if owner_aid else {}))

        def owner_put(key, plain):
            owner.req("PUT", f"/stores/{store}/{key}",
                      {"value": b64(plain), "content_type": "text/plain"})

        def relay_exact(key, plain):
            return sample_until(
                {"k": lambda k=key, p=plain: key_value_matches(
                    relay, store, k, p)},
                gate_secs=args.cold_gate, interval=args.poll_interval)["k"]

        # 1. multi-write
        owner_put("k1", "alpha")
        owner_put("k2", "beta")
        m1 = relay_exact("k1", "alpha")
        m2 = relay_exact("k2", "beta")
        # 2. update k1 (mutate value); k2 must stay exact
        owner_put("k1", "alpha-2")
        m3 = relay_exact("k1", "alpha-2")
        k2_still = key_value_matches(relay, store, "k2", "beta")
        # 3. delete k2; relay must drop it (delete recovery). Wait for the
        # delete delta to propagate — settling on k1 would NOT detect the
        # removal (k1 is unchanged by deleting k2).
        owner.req("DELETE", f"/stores/{store}/k2")
        k2_gone = False
        deadline = time.monotonic() + args.cold_gate
        while time.monotonic() < deadline:
            if key_value_bytes(relay, store, "k2") is None:
                k2_gone = True
                break
            time.sleep(args.poll_interval)
        # 4. delete k1 → empty (empty-checkpoint early-return case)
        owner.req("DELETE", f"/stores/{store}/k1")
        deadline = time.monotonic() + args.fork_window
        empty_ok = False
        while time.monotonic() < deadline:
            if key_value_bytes(relay, store, "k1") is None and \
                    key_value_bytes(relay, store, "k2") is None:
                empty_ok = True
                break
            time.sleep(args.poll_interval)
        # 5. final key
        owner_put("k_final", "final")
        mf = relay_exact("k_final", "final")
        final_hash = key_content_hash(relay, store, "k_final")
        # 6. owner OFFLINE; fresh anchored joiner via RELAY only
        owner.stop()
        time.sleep(2)
        joiner = _spawn_isolated_node(
            "cp-joiner", args.api_base + 32, args.quic_base + 32,
            cp_dir, args.x0xd, args.log_level, [args.quic_base + 31])
        nodes.append(joiner)
        joiner.req("POST", f"/stores/{store}/join",
                   ({"expected_owner": owner_aid} if owner_aid else {}))
        jf = sample_until(
            {"k": lambda: key_value_matches(
                joiner, store, "k_final", "final")},
            gate_secs=args.cold_gate, interval=args.poll_interval)["k"]
        time.sleep(args.fork_window)  # window for any resurrection to show
        j_final_exact = key_value_matches(joiner, store, "k_final", "final")
        j_k1_absent = key_value_bytes(joiner, store, "k1") is None
        j_k2_absent = key_value_bytes(joiner, store, "k2") is None
        gate.update({
            "status": ("pass" if all([
                m1 is not None, m2 is not None, m3 is not None, k2_still,
                k2_gone, empty_ok, mf is not None, jf is not None,
                j_final_exact, j_k1_absent, j_k2_absent]) else "fail"),
            "store": store,
            "owner_agent_id": owner_aid,
            "multi_write_k1_secs": m1, "multi_write_k2_secs": m2,
            "update_k1_secs": m3, "k2_still_after_update": k2_still,
            "delete_k2_propagated": k2_gone,
            "delete_to_empty_propagated": empty_ok,
            "final_key_secs": mf, "final_content_hash": final_hash,
            "owner_offline_joiner_final_secs": jf,
            "joiner_final_exact": j_final_exact,
            "joiner_k1_absent_no_resurrection": j_k1_absent,
            "joiner_k2_absent_no_resurrection": j_k2_absent,
            "owner_binary": str(args.x0xd),
            "scope": ("multi-write + update + delete + delete-to-empty with "
                      "exact-byte replica match each step; owner OFFLINE, "
                      "fresh anchored joiner via relay-only recovers exact "
                      "final state with no key resurrection"),
        })
        log(f"owner_offline_checkpoint_recovery: {gate['status']} "
            f"multi={m1}/{m2}s update={m3}s del_k2={k2_gone} "
            f"empty={empty_ok} offline_joiner={jf}s "
            f"final_exact={j_final_exact} "
            f"no_resurrect={j_k1_absent and j_k2_absent}")
    except Exception as e:
        gate["status"] = "fail"
        gate["error"] = f"{type(e).__name__}: {e}"
        log(f"owner_offline_checkpoint_recovery: EXCEPTION {e}")
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
    return gate


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


def summarize(runs, args, prereq_gates=None, provenance=None,
              release_env=None):
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

    # Gate pass rates (pass / known-gap / unsupported / fail)
    lines.append("")
    lines.append(f"{'phase':<42}{'pass':>6}{'gap':>6}{'unsupp':>8}{'fail':>6}")
    phase_names = []
    for r in runs:
        for name in r["phases"]:
            if name not in phase_names:
                phase_names.append(name)
    for name in phase_names:
        n_pass = n_gap = n_unsupp = n_fail = 0
        for r in runs:
            e = r["phases"].get(name)
            if e is None:
                continue
            status = e.get("status")
            if status == "known-gap":
                n_gap += 1
            elif status == "unsupported":
                n_unsupp += 1
            elif e.get("pass"):
                n_pass += 1
            else:
                n_fail += 1
        lines.append(
            f"{name:<42}{n_pass:>6}{n_gap:>6}{n_unsupp:>8}{n_fail:>6}")

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
    # Same-host topology (one run is representative): who-is-who for
    # claim-winner / store-owner attribution.
    topo = next((r.get("topology") for r in runs
                 if r.get("topology")), {})
    if topo:
        lines.append("")
        lines.append("same-host topology (agent_id[:8] / peer_id[:8]):")
        for name, t in topo.items():
            aid = (t.get("agent_id") or "?")[:8]
            pid = (t.get("peer_id") or "?")[:8]
            sib = ",".join((s.get("peer_id") or "?")[:8]
                           for s in (t.get("bootstrap_siblings") or [])) or "-"
            lines.append(f"  {name:<8} agent={aid} peer={pid} "
                         f"quic={t.get('quic_addr')} siblings={sib}")
        # mDNS mesh contamination (environmental): non-zero discovered_peers
        # on an isolated cluster ⇒ stray x0xd daemons on the host.
        mc = next((r.get("mesh_contamination") for r in runs
                   if r.get("mesh_contamination")), {})
        if mc:
            tag = "CONTAMINATED" if mc.get("contaminated") else "clean"
            lines.append(f"  mesh(mDNS): {tag} "
                         f"(max_discovered_peers="
                         f"{mc.get('max_mdns_discovered_peers')})")

    # Release-oracle provenance: binary digests/versions + git source cutoff
    # + release-environment gates (hard-error growth / mDNS contamination).
    if provenance:
        lines.append("")
        lines.append("provenance (binary + source cutoff):")
        cb = provenance.get("current_binary") or {}
        lines.append(f"  current: v{cb.get('version')} "
                     f"sha256={(cb.get('sha256') or '?')[:16]}… "
                     f"mtime={cb.get('mtime_unix')}")
        lb = provenance.get("legacy_binary")
        if lb:
            lines.append(f"  legacy:  v{lb.get('version')} "
                         f"sha256={(lb.get('sha256') or '?')[:16]}… "
                         f"(required v{provenance.get('legacy_required_version')})")
        else:
            lines.append("  legacy:  (none — mixed-version UNSUPPORTED)")
        g = provenance.get("git") or {}
        lines.append(f"  git:     head={(g.get('head') or '?')[:12]} "
                     f"dirty={g.get('dirty')} "
                     f"tree_hash={(g.get('dirty_tree_hash') or '-')[:16]}…")
        if release_env:
            he = "GROWTH" if release_env.get(
                "dropped_critical_hard_error_growth") else "clean"
            mc = "CONTAMINATED" if release_env.get(
                "mdns_contaminated") else "clean"
            lines.append(f"  env:     hard_error={he} mdns={mc}")

    # Prerequisite-gated security/skew gates: pass / fail / UNSUPPORTED.
    if prereq_gates:
        lines.append("")
        lines.append("prerequisite gates (mixed-version / malicious announce "
                     "/ checkpoint-recovery / forged-first-seen):")
        for g in prereq_gates:
            st = g.get("status")
            tag = {"unsupported": "UNSUPPORTED",
                   "pass": "PASS", "fail": "FAIL"}.get(st, st)
            lines.append(f"  {g.get('name'):<32}{tag}")
            if st == "unsupported":
                lines.append(f"    → {g.get('unsupported', '')}")
                if args.expect_fixed:
                    lines.append("      [expect-fixed] UNSUPPORTED required "
                                 "prerequisite FAILS the run — supply the "
                                 "named binary to exercise this gate")
            elif st == "fail":
                lines.append(f"    → error: {g.get('error', '(see report)')}")

    lines.append("")
    soak_pass = (passed == total)
    if prereq_gates:
        if args.expect_fixed:
            prereq_pass = all(g.get("status") not in ("fail", "unsupported")
                              for g in prereq_gates)
        else:
            prereq_pass = all(g.get("status") != "fail"
                              for g in prereq_gates)
    else:
        prereq_pass = True
    overall = soak_pass and prereq_pass
    tag = "PASS" if overall else "FAIL"
    if soak_pass and not prereq_pass:
        tag += " (soak gates green; prerequisite gate(s) missing/failed)"
    lines.append(f"OVERALL: {tag}")
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
    p.add_argument("--legacy-binary", default=None,
                   help="path to a legacy (v0.30.1) x0xd binary for the "
                        "mixed-version skew gate (or $X0XD_LEGACY_BINARY). "
                        "If absent the gate reports UNSUPPORTED rather than "
                        "faking the skew")
    p.add_argument("--forge-injector", default=None,
                   help="path to the in-repo x0xd-forge-injector binary for "
                        "the forged-first-seen gate (default: "
                        "target/release/x0xd-forge-injector, built by the "
                        "release recipe). Optional $X0XD_FORGE_INJECTOR "
                        "override; absent ⇒ the gate is UNSUPPORTED")
    args = p.parse_args()
    if args.nodes < 3:
        p.error("--nodes must be >= 3 (claims need two non-creator peers)")
    if args.x0xd is None:
        args.x0xd = os.environ.get(
            "X0XD_TEST_BINARY", str(REPO_ROOT / "target/release/x0xd"))
    args.x0xd = pathlib.Path(args.x0xd)
    if args.legacy_binary is None:
        args.legacy_binary = os.environ.get("X0XD_LEGACY_BINARY")
    if args.legacy_binary:
        args.legacy_binary = pathlib.Path(args.legacy_binary)
    if args.forge_injector is None:
        args.forge_injector = os.environ.get(
            "X0XD_FORGE_INJECTOR",
            str(REPO_ROOT / "target/release/x0xd-forge-injector"))
    args.forge_injector = pathlib.Path(args.forge_injector)
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

    # Release-oracle provenance: record binary SHA-256 + --version, Git HEAD
    # + dirty-tree fingerprint + source cutoff, and REFUSE to attest a release
    # from a stale binary or a non-v0.30.1 legacy. Under --expect-fixed a
    # provenance refusal fails fast (release authority); without it the
    # errors are warnings so the one-run smoke stays available.
    provenance, prov_errors = record_and_verify_provenance(args)
    for e in prov_errors:
        log(f"PROVENANCE REFUSAL: {e}")
    if prov_errors and args.expect_fixed:
        refuse_root = pathlib.Path(args.out_dir) / time.strftime(
            "%Y%m%d-%H%M%S")
        refuse_root.mkdir(parents=True, exist_ok=True)
        (refuse_root / "report.json").write_text(json.dumps({
            "args": {k: str(v) if isinstance(v, pathlib.Path) else v
                     for k, v in vars(args).items()},
            "provenance": provenance, "provenance_errors": prov_errors,
            "refused": True,
        }, indent=2))
        log("REFUSING release under --expect-fixed: rebuild "
            "`cargo build --release --bin x0xd` and supply an authenticated "
            "v0.30.1 legacy binary, then re-run.")
        return 1

    out_root = pathlib.Path(args.out_dir) / time.strftime("%Y%m%d-%H%M%S")
    out_root.mkdir(parents=True, exist_ok=True)
    log(f"output: {out_root}")
    log(f"x0xd: {args.x0xd}")

    runs = []
    prereq_gates = []
    hard_error_growth = False
    contaminated = False
    release_env = {}
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

        # Release-environment gates computed from the per-run diagnostics:
        # any dropped_critical_hard_error growth, and mDNS mesh contamination.
        hard_error_growth = any(
            delta.get("dropped_critical_hard_error", 0)
            for r in runs
            for d in r.get("diagnostics_deltas", {}).values()
            for delta in (d.get("admission_delta") or {}).values()
            if isinstance(delta, dict))
        contaminated = any(
            r.get("mesh_contamination", {}).get("contaminated")
            for r in runs)
        release_env = {
            "dropped_critical_hard_error_growth": hard_error_growth,
            "mdns_contaminated": contaminated,
        }

        # Prerequisite-gated security/skew gates run ONCE per invocation
        # (they do not depend on soak repetition and use isolated ports).
        log("=== prerequisite gates (mixed-version / malicious announce) ===")
        prereq_gates.extend(run_mixed_version_gate(args, out_root))
        prereq_gates.append(run_malicious_owner_announce_gate(args, out_root))
        prereq_gates.append(run_owner_offline_checkpoint_gate(args, out_root))
        prereq_gates.append(run_forged_first_seen_gate(args, out_root))
    finally:
        report_path = out_root / "report.json"
        report_path.write_text(json.dumps({
            "args": {k: str(v) if isinstance(v, pathlib.Path) else v
                     for k, v in vars(args).items()},
            "provenance": provenance,
            "provenance_errors": prov_errors,
            "release_environment": release_env,
            "runs": runs,
            "prerequisite_gates": prereq_gates,
        }, indent=2))
        summary = summarize(runs, args, prereq_gates, provenance,
                            release_env) if runs \
            else "(no runs completed)"
        (out_root / "summary.txt").write_text(summary + "\n")
        print(summary)
        log(f"report: {report_path}")

    soak_ok = runs and all(r["pass"] for r in runs)
    # A gate that ran and FAILED is always a failure. Under --expect-fixed an
    # UNSUPPORTED gate (mixed-version without a legacy binary, or the
    # forged-first-seen gossip-harness gap) is ALSO a failure: the release
    # recipe demands every phase be exercised, never silently skipped. A
    # provenance refusal (stale binary / wrong legacy version) already failed
    # fast above under --expect-fixed.
    if args.expect_fixed:
        prereq_ok = all(g.get("status") not in ("fail", "unsupported")
                        for g in prereq_gates)
    else:
        prereq_ok = all(g.get("status") != "fail" for g in prereq_gates)
    # Release-environment gates: critical hard-error growth and mDNS mesh
    # contamination are HARD gates under --expect-fixed (a release must run
    # clean); reported but non-blocking in the one-run smoke.
    if args.expect_fixed:
        release_env_ok = (not hard_error_growth) and (not contaminated)
    else:
        release_env_ok = True
    return 0 if (soak_ok and prereq_ok and release_env_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
