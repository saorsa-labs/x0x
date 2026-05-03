#!/usr/bin/env python3
"""x0x launch-readiness harness — X0X-0015.

Runs scenarios against the live VPS bootstrap mesh (or a single anchor)
and produces a go/no-go report against documented launch SLOs:

  proofs/launch-readiness-<run-id>/
    summary.md          # human verdict per scenario, gate result
    summary.csv         # one row per scenario
    diagnostics/
      <scenario>/
        <node>-pre.json
        <node>-post.json
    runs/
      <scenario>/<node>/*.log

Scenarios are functions registered in SCENARIOS. Default safe set (no
operator-disrupting actions) is `baseline,fanout_burst`. Destructive
scenarios (`restart_storm`, `partition_recovery`) require explicit
opt-in flags.

Usage::

    python3 tests/launch_readiness.py --gate limited-production
    python3 tests/launch_readiness.py --gate broad-launch \\
        --scenarios baseline,fanout_burst,restart_storm \\
        --allow-restart-storm
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

LOG = logging.getLogger("launch_readiness")

NODES_DEFAULT: List[str] = [
    "nyc",
    "sfo",
    "helsinki",
    "nuremberg",
    "singapore",
    "sydney",
]

# ── SLO gates ──────────────────────────────────────────────────────────
# Two named gates. Limited-production is the bar a node must clear before
# being recommended to early adopters; broad-launch is the bar before a
# fleet-wide marketing push. Numbers are "delta over the scenario window"
# unless suffixed _total or _ratio.
GATES: Dict[str, Dict[str, float]] = {
    "limited-production": {
        # Per-node deltas for one scenario window (~5-10 min).
        "max_dispatcher_timed_out_delta": 5,
        "max_recv_pump_dropped_full_delta": 0,
        "max_per_peer_timeout_delta": 200,
        "max_suppressed_peers_steady": 200,
        "min_phase_a_pairs": 30,
        "max_recovery_secs": 90,
    },
    "broad-launch": {
        "max_dispatcher_timed_out_delta": 0,
        "max_recv_pump_dropped_full_delta": 0,
        "max_per_peer_timeout_to_dispatcher_completed_ratio": 0.25,
        "max_suppressed_peers_steady": 100,
        "min_phase_a_pairs": 30,
        "max_recovery_secs": 30,
    },
}


# ── Token loading ──────────────────────────────────────────────────────
def load_tokens(path: Path) -> Dict[str, Tuple[str, str]]:
    """Parse tests/.vps-tokens.env → {node: (ip, token)}."""
    if not path.is_file():
        raise FileNotFoundError(f"token file not found: {path}")
    ips: Dict[str, str] = {}
    toks: Dict[str, str] = {}
    pattern = re.compile(r'^([A-Z]+)_(IP|TK)="?([^"]+)"?\s*$')
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = pattern.match(line)
        if not m:
            continue
        node = m.group(1).lower()
        if m.group(2) == "IP":
            ips[node] = m.group(3)
        else:
            toks[node] = m.group(3)
    return {n: (ip, toks[n]) for n, ip in ips.items() if n in toks}


# ── Diagnostics fetcher ────────────────────────────────────────────────
def fetch_diagnostics(node: str, ip: str, token: str, timeout: int = 12) -> Dict[str, Any]:
    """Fetch /diagnostics/gossip via SSH (avoids opening per-node tunnels)."""
    cmd = (
        f"curl -s --max-time {timeout} "
        f"-H 'Authorization: Bearer {token}' "
        f"http://127.0.0.1:12600/diagnostics/gossip"
    )
    proc = subprocess.run(
        [
            "ssh",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout={timeout}",
            f"root@{ip}",
            cmd,
        ],
        capture_output=True,
        timeout=timeout + 10,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"ssh+curl failed for {node}: rc={proc.returncode} "
            f"stderr={proc.stderr.decode('utf-8', errors='replace').strip()}"
        )
    body = proc.stdout.decode("utf-8", errors="replace").strip()
    if not body:
        raise RuntimeError(f"empty diagnostics body from {node}")
    return json.loads(body)


def fetch_diagnostics_local(base_url: str, token: str, timeout: int = 12) -> Dict[str, Any]:
    """Fetch /diagnostics/gossip from a local URL (no SSH)."""
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/diagnostics/gossip",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


# ── Counter extractors ────────────────────────────────────────────────
def extract_counters(diag: Dict[str, Any]) -> Dict[str, int]:
    """Pull the SLO-relevant scalars out of /diagnostics/gossip."""
    disp = diag.get("dispatcher", {}).get("pubsub", {})
    rp = diag.get("recv_pump", {}).get("pubsub", {})
    ps = diag.get("pubsub_stages", {})
    sp = ps.get("suppressed_peers", []) or []
    scores = ps.get("peer_scores", []) or []
    return {
        "dispatcher_completed": int(disp.get("completed", 0)),
        "dispatcher_timed_out": int(disp.get("timed_out", 0)),
        "recv_pump_dropped_full": int(rp.get("dropped_full", 0)),
        "recv_pump_latest_depth": int(rp.get("latest_depth", 0)),
        "recv_pump_max_depth": int(rp.get("max_depth", 0)),
        "recv_pump_produced_total": int(rp.get("produced_total", 0)),
        "recv_pump_dequeued_total": int(rp.get("dequeued_total", 0)),
        "per_peer_timeout_count": int(ps.get("republish_per_peer_timeout", 0)),
        "suppressed_peers_size": len(sp),
        "outbound_budget_exhausted": int(ps.get("outbound_budget_exhausted", 0)),
        "pubsub_workers": int(diag.get("dispatcher", {}).get("pubsub_workers", 0)),
        "peer_scores_eager_eligible": sum(1 for r in scores if r.get("eager_eligible")),
        "peer_scores_lazy": sum(1 for r in scores if r.get("role") == "lazy"),
        "peer_scores_excluded": sum(1 for r in scores if r.get("role") == "excluded"),
    }


def diff_counters(pre: Dict[str, int], post: Dict[str, int]) -> Dict[str, int]:
    """Per-key delta. Missing keys default to 0."""
    keys = set(pre) | set(post)
    return {k: int(post.get(k, 0)) - int(pre.get(k, 0)) for k in keys}


def per_peer_timeout_ratio(delta: Dict[str, int]) -> float:
    """Timeouts normalized by dispatcher completions in the same window."""
    per_peer_timeouts = max(0, int(delta.get("per_peer_timeout_count", 0)))
    dispatcher_completed = max(0, int(delta.get("dispatcher_completed", 0)))
    if per_peer_timeouts == 0:
        return 0.0
    if dispatcher_completed == 0:
        return float("inf")
    return per_peer_timeouts / dispatcher_completed


def dropped_full_ratio(delta: Dict[str, int]) -> float:
    """Recv-pump drops normalized by produced frames in the same window."""
    dropped = max(0, int(delta.get("recv_pump_dropped_full", 0)))
    produced = max(0, int(delta.get("recv_pump_produced_total", 0)))
    if dropped == 0:
        return 0.0
    if produced == 0:
        return float("inf")
    return dropped / produced


# ── Scenario plugin pattern ───────────────────────────────────────────
@dataclass
class ScenarioContext:
    args: argparse.Namespace
    proof_dir: Path
    nodes: Dict[str, Tuple[str, str]]  # {node: (ip, token)}
    anchor: str
    repo_root: Path


@dataclass
class ScenarioResult:
    name: str
    duration_secs: float
    extra_metrics: Dict[str, Any] = field(default_factory=dict)
    fail_reason: Optional[str] = None  # set if scenario itself errored


ScenarioFn = Callable[[ScenarioContext], ScenarioResult]


# ── Scenarios ─────────────────────────────────────────────────────────
def scenario_baseline(ctx: ScenarioContext) -> ScenarioResult:
    """Run Phase A 30/30 once and capture the diagnostics envelope."""
    t0 = time.time()
    cmd = [
        sys.executable,
        str(ctx.repo_root / "tests" / "e2e_vps_mesh.py"),
        "--anchor", ctx.anchor,
        "--discover-secs", "30",
        "--settle-secs", "60",
    ]
    log_path = ctx.proof_dir / "runs" / "baseline" / "phase-a.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    LOG.info("baseline: running %s", " ".join(shlex.quote(c) for c in cmd))
    proc = subprocess.run(cmd, capture_output=True, timeout=600, cwd=ctx.repo_root)
    log_path.write_bytes(proc.stdout + b"\n--- stderr ---\n" + proc.stderr)
    pairs_received = 0
    pairs_sent = 0
    # e2e_vps_mesh.py emits results via logging → stderr; scan both streams
    # to be robust to either sink.
    combined = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", errors="replace")
    for line in combined.splitlines():
        m = re.search(r"Sent:\s+(\d+)\s*/\s*(\d+)", line)
        if m:
            pairs_sent = int(m.group(1))
        m = re.search(r"Received:\s+(\d+)\s*/\s*(\d+)", line)
        if m:
            pairs_received = int(m.group(1))
    elapsed = time.time() - t0
    return ScenarioResult(
        name="baseline",
        duration_secs=elapsed,
        extra_metrics={
            "phase_a_sent": pairs_sent,
            "phase_a_received": pairs_received,
            "phase_a_exit_code": proc.returncode,
        },
        fail_reason=None if proc.returncode == 0 else f"phase A exit code {proc.returncode}",
    )


def scenario_fanout_burst(ctx: ScenarioContext) -> ScenarioResult:
    """Anchor publishes N messages on a unique topic and watches drops."""
    burst = ctx.args.burst_messages
    payload_bytes = ctx.args.burst_payload_bytes
    delay_ms = ctx.args.burst_delay_ms
    topic = f"x0x.launch.fanout.{int(time.time())}"
    ip, token = ctx.nodes[ctx.anchor]

    payload = ("X" * payload_bytes).encode("utf-8")
    payload_b64 = base64.b64encode(payload).decode("ascii")

    LOG.info(
        "fanout_burst: anchor=%s topic=%s burst=%d payload=%dB delay=%dms",
        ctx.anchor, topic, burst, payload_bytes, delay_ms,
    )

    # Build a remote shell loop that publishes N times via the local API.
    # All requests stay on the anchor — no tunnel needed for the burst.
    publish_cmd = (
        "for i in $(seq 1 {burst}); do "
        "curl -s -X POST -H 'Authorization: Bearer {token}' "
        "-H 'Content-Type: application/json' "
        "-d '{{\"topic\":\"{topic}\",\"payload\":\"{payload}\"}}' "
        "http://127.0.0.1:12600/publish >/dev/null; "
        "{sleep}"
        "done"
    ).format(
        burst=burst,
        token=token,
        topic=topic,
        payload=payload_b64,
        sleep=(f"sleep {delay_ms / 1000.0}; " if delay_ms > 0 else ""),
    )

    t0 = time.time()
    proc = subprocess.run(
        [
            "ssh",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            f"root@{ip}",
            publish_cmd,
        ],
        capture_output=True,
        timeout=max(120, int(burst * (delay_ms / 1000.0)) + 60),
    )
    burst_secs = time.time() - t0

    # Settle 30s for fanout/replies.
    time.sleep(30)
    elapsed = time.time() - t0
    return ScenarioResult(
        name="fanout_burst",
        duration_secs=elapsed,
        extra_metrics={
            "burst_messages": burst,
            "burst_payload_bytes": payload_bytes,
            "burst_delay_ms": delay_ms,
            "burst_publish_secs": round(burst_secs, 3),
            "burst_publish_exit_code": proc.returncode,
        },
        fail_reason=None if proc.returncode == 0 else f"burst publish exit code {proc.returncode}",
    )


def scenario_restart_storm(ctx: ScenarioContext) -> ScenarioResult:
    """Restart x0xd on N runner nodes simultaneously and measure recovery.

    Destructive — requires --allow-restart-storm. Excludes the anchor so
    the harness keeps a control plane.
    """
    if not ctx.args.allow_restart_storm:
        return ScenarioResult(
            name="restart_storm",
            duration_secs=0.0,
            fail_reason="skipped: pass --allow-restart-storm to enable",
        )
    targets = [n for n in ctx.nodes if n != ctx.anchor][: ctx.args.restart_count]
    LOG.warning("restart_storm: restarting x0xd on %s", targets)
    t0 = time.time()
    procs = [
        subprocess.Popen(
            [
                "ssh",
                "-o", "ControlMaster=no",
                "-o", "ControlPath=none",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                f"root@{ctx.nodes[n][0]}",
                "systemctl restart x0xd",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for n in targets
    ]
    for p in procs:
        p.wait(timeout=60)
    issued_secs = time.time() - t0

    # Poll /health on each restarted node until it answers (or 120s).
    recovery: Dict[str, float] = {}
    deadline = time.time() + 120
    for n in targets:
        ip, token = ctx.nodes[n]
        rec_t0 = time.time()
        while time.time() < deadline:
            try:
                check = subprocess.run(
                    [
                        "ssh",
                        "-o", "ControlMaster=no",
                        "-o", "ControlPath=none",
                        "-o", "BatchMode=yes",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "ConnectTimeout=5",
                        f"root@{ip}",
                        f"curl -sf -H 'Authorization: Bearer {token}' "
                        f"http://127.0.0.1:12600/health",
                    ],
                    capture_output=True,
                    timeout=10,
                )
                if check.returncode == 0:
                    recovery[n] = time.time() - rec_t0
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            recovery[n] = -1.0  # timeout

    # Re-mesh settle window.
    time.sleep(30)
    elapsed = time.time() - t0
    return ScenarioResult(
        name="restart_storm",
        duration_secs=elapsed,
        extra_metrics={
            "restart_count": len(targets),
            "restart_targets": ",".join(targets),
            "issued_secs": round(issued_secs, 3),
            "recovery_secs_per_node": {k: round(v, 1) for k, v in recovery.items()},
            "max_recovery_secs": max(recovery.values()) if recovery else 0,
        },
        fail_reason=None if all(v >= 0 for v in recovery.values()) else "one or more nodes failed to recover within 120s",
    )


SCENARIOS: Dict[str, ScenarioFn] = {
    "baseline": scenario_baseline,
    "fanout_burst": scenario_fanout_burst,
    "restart_storm": scenario_restart_storm,
}


# ── SLO evaluation ────────────────────────────────────────────────────
def evaluate_slos(
    gate: str,
    deltas_per_node: Dict[str, Dict[str, int]],
    posts_per_node: Dict[str, Dict[str, int]],
    scenario: ScenarioResult,
) -> Tuple[bool, List[str]]:
    """Apply gate thresholds. Returns (pass, [violations])."""
    g = GATES[gate]
    violations: List[str] = []

    for node, d in deltas_per_node.items():
        if d.get("dispatcher_timed_out", 0) > g["max_dispatcher_timed_out_delta"]:
            violations.append(
                f"{node}: dispatcher_timed_out delta {d['dispatcher_timed_out']} "
                f"> gate {g['max_dispatcher_timed_out_delta']}"
            )
        if d.get("recv_pump_dropped_full", 0) > g["max_recv_pump_dropped_full_delta"]:
            violations.append(
                f"{node}: recv_pump.dropped_full delta {d['recv_pump_dropped_full']} "
                f"> gate {g['max_recv_pump_dropped_full_delta']}"
            )
        if (
            "max_per_peer_timeout_delta" in g
            and d.get("per_peer_timeout_count", 0) > g["max_per_peer_timeout_delta"]
        ):
            violations.append(
                f"{node}: per_peer_timeout delta {d['per_peer_timeout_count']} "
                f"> gate {g['max_per_peer_timeout_delta']}"
            )
        if "max_per_peer_timeout_to_dispatcher_completed_ratio" in g:
            ratio = per_peer_timeout_ratio(d)
            max_ratio = g["max_per_peer_timeout_to_dispatcher_completed_ratio"]
            if ratio > max_ratio:
                ratio_str = "inf" if ratio == float("inf") else f"{ratio:.3f}"
                violations.append(
                    f"{node}: per_peer_timeout/dispatcher_completed ratio "
                    f"{ratio_str} > gate {max_ratio:.3f} "
                    f"({d.get('per_peer_timeout_count', 0)} / "
                    f"{d.get('dispatcher_completed', 0)})"
                )

    for node, post in posts_per_node.items():
        if post.get("suppressed_peers_size", 0) > g["max_suppressed_peers_steady"]:
            violations.append(
                f"{node}: suppressed_peers steady {post['suppressed_peers_size']} "
                f"> gate {g['max_suppressed_peers_steady']}"
            )

    if scenario.name == "baseline":
        rcv = scenario.extra_metrics.get("phase_a_received", 0)
        if rcv < g["min_phase_a_pairs"]:
            violations.append(
                f"phase A received {rcv} < gate {g['min_phase_a_pairs']}"
            )

    if scenario.name == "restart_storm":
        max_rec = scenario.extra_metrics.get("max_recovery_secs", 0)
        if max_rec > g["max_recovery_secs"]:
            violations.append(
                f"restart recovery {max_rec}s > gate {g['max_recovery_secs']}s"
            )

    return (len(violations) == 0, violations)


# ── Output writers ────────────────────────────────────────────────────
def write_summary_md(
    proof_dir: Path,
    gate: str,
    results: List[Tuple[ScenarioResult, Dict[str, Dict[str, int]], bool, List[str]]],
) -> None:
    lines = [
        "# x0x launch-readiness report",
        "",
        f"- Gate: **{gate}**",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
        "## SLO thresholds",
        "",
        "| Metric | Threshold |",
        "|---|---|",
    ]
    for k, v in GATES[gate].items():
        lines.append(f"| {k} | {v} |")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    overall_pass = all(passed for _, _, passed, _ in results)
    verdict = "GO" if overall_pass else "NO-GO"
    lines.append(f"### Overall verdict: **{verdict}**")
    lines.append("")
    for sr, deltas, passed, violations in results:
        lines.append(f"#### {sr.name} — {'PASS' if passed else 'FAIL'}")
        lines.append("")
        if sr.fail_reason:
            lines.append(f"- fail_reason: `{sr.fail_reason}`")
        lines.append(f"- duration: {sr.duration_secs:.1f}s")
        for k, v in sr.extra_metrics.items():
            lines.append(f"- {k}: `{v}`")
        if violations:
            lines.append("- violations:")
            for v in violations:
                lines.append(f"  - {v}")
        lines.append("")
        lines.append("Per-node deltas (key counters):")
        lines.append("")
        lines.append(
            "| node | disp_to | drop_full | drop_ratio | pp_to | pp_to/completed | depth_post | suppressed_post | workers_post |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
        for node in sorted(deltas):
            d = deltas[node]
            posts = d.get("_post", {})
            pp_ratio = per_peer_timeout_ratio(d)
            pp_ratio_str = "inf" if pp_ratio == float("inf") else f"{pp_ratio:.3f}"
            drop_ratio = dropped_full_ratio(d)
            drop_ratio_str = "inf" if drop_ratio == float("inf") else f"{drop_ratio:.6f}"
            lines.append(
                f"| {node} | {d.get('dispatcher_timed_out', 0)} | "
                f"{d.get('recv_pump_dropped_full', 0)} | "
                f"{drop_ratio_str} | "
                f"{d.get('per_peer_timeout_count', 0)} | "
                f"{pp_ratio_str} | "
                f"{posts.get('recv_pump_latest_depth', 0)} | "
                f"{posts.get('suppressed_peers_size', 0)} | "
                f"{posts.get('pubsub_workers', 0)} |"
            )
        lines.append("")
    (proof_dir / "summary.md").write_text("\n".join(lines))


def write_summary_csv(
    proof_dir: Path,
    results: List[Tuple[ScenarioResult, Dict[str, Dict[str, int]], bool, List[str]]],
) -> None:
    with (proof_dir / "summary.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "scenario", "node", "passed", "fail_reason",
            "dispatcher_timed_out_delta", "recv_pump_dropped_full_delta",
            "per_peer_timeout_delta", "suppressed_peers_post",
            "pubsub_workers_post", "violations_count",
            "per_peer_timeout_to_completed_ratio", "recv_pump_drop_full_ratio",
            "recv_pump_latest_depth_post",
        ])
        for sr, deltas, passed, violations in results:
            for node, d in deltas.items():
                posts = d.get("_post", {})
                pp_ratio = per_peer_timeout_ratio(d)
                drop_ratio = dropped_full_ratio(d)
                w.writerow([
                    sr.name, node,
                    "PASS" if passed else "FAIL",
                    sr.fail_reason or "",
                    d.get("dispatcher_timed_out", 0),
                    d.get("recv_pump_dropped_full", 0),
                    d.get("per_peer_timeout_count", 0),
                    posts.get("suppressed_peers_size", 0),
                    posts.get("pubsub_workers", 0),
                    len(violations),
                    "inf" if pp_ratio == float("inf") else f"{pp_ratio:.6f}",
                    "inf" if drop_ratio == float("inf") else f"{drop_ratio:.6f}",
                    posts.get("recv_pump_latest_depth", 0),
                ])


# ── Main ──────────────────────────────────────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor", default="nyc", choices=NODES_DEFAULT)
    parser.add_argument("--gate", default="limited-production",
                        choices=sorted(GATES.keys()))
    parser.add_argument("--scenarios", default="baseline,fanout_burst",
                        help="comma-separated scenario list (default: %(default)s)")
    parser.add_argument("--tokens-file", default="tests/.vps-tokens.env")
    parser.add_argument("--proof-dir", default=None,
                        help="output dir (default: proofs/launch-readiness-<ts>)")
    parser.add_argument("--burst-messages", type=int, default=200,
                        help="fanout_burst: messages to publish (default 200)")
    parser.add_argument("--burst-payload-bytes", type=int, default=4096,
                        help="fanout_burst: payload size (default 4096)")
    parser.add_argument("--burst-delay-ms", type=int, default=10,
                        help="fanout_burst: ms between publishes (default 10)")
    parser.add_argument("--allow-restart-storm", action="store_true",
                        help="enable destructive restart_storm scenario")
    parser.add_argument("--restart-count", type=int, default=2,
                        help="restart_storm: number of nodes (default 2)")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    repo_root = Path(__file__).resolve().parents[1]
    tokens_path = (repo_root / args.tokens_file).resolve()
    nodes = load_tokens(tokens_path)
    if args.anchor not in nodes:
        LOG.error("anchor %s not in tokens file", args.anchor)
        return 2

    selected = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    for s in selected:
        if s not in SCENARIOS:
            LOG.error("unknown scenario: %s (known: %s)", s, sorted(SCENARIOS))
            return 2

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    proof_dir = Path(args.proof_dir) if args.proof_dir else (
        repo_root / "proofs" / f"launch-readiness-{ts}"
    )
    proof_dir.mkdir(parents=True, exist_ok=True)
    (proof_dir / "diagnostics").mkdir(exist_ok=True)
    (proof_dir / "runs").mkdir(exist_ok=True)
    LOG.info("proof_dir: %s", proof_dir)

    ctx = ScenarioContext(
        args=args, proof_dir=proof_dir, nodes=nodes,
        anchor=args.anchor, repo_root=repo_root,
    )

    results: List[Tuple[ScenarioResult, Dict[str, Dict[str, int]], bool, List[str]]] = []

    for sname in selected:
        LOG.info("=== scenario: %s ===", sname)
        scen_diag_dir = proof_dir / "diagnostics" / sname
        scen_diag_dir.mkdir(exist_ok=True)
        # Pre-snapshot.
        pre_counters: Dict[str, Dict[str, int]] = {}
        for node, (ip, token) in nodes.items():
            try:
                diag = fetch_diagnostics(node, ip, token)
                (scen_diag_dir / f"{node}-pre.json").write_text(json.dumps(diag, indent=2))
                pre_counters[node] = extract_counters(diag)
            except Exception as e:
                LOG.warning("pre-snapshot %s failed: %s", node, e)
                pre_counters[node] = {}

        sr = SCENARIOS[sname](ctx)

        # Post-snapshot.
        post_counters: Dict[str, Dict[str, int]] = {}
        for node, (ip, token) in nodes.items():
            try:
                diag = fetch_diagnostics(node, ip, token)
                (scen_diag_dir / f"{node}-post.json").write_text(json.dumps(diag, indent=2))
                post_counters[node] = extract_counters(diag)
            except Exception as e:
                LOG.warning("post-snapshot %s failed: %s", node, e)
                post_counters[node] = {}

        deltas: Dict[str, Dict[str, int]] = {}
        for node in nodes:
            d = diff_counters(pre_counters.get(node, {}), post_counters.get(node, {}))
            d["_post"] = post_counters.get(node, {})  # smuggle for reports
            deltas[node] = d

        passed, violations = evaluate_slos(args.gate, deltas, post_counters, sr)
        if sr.fail_reason and "skipped" not in sr.fail_reason:
            passed = False
            violations.insert(0, f"scenario errored: {sr.fail_reason}")

        LOG.info("scenario %s → %s (%d violations)", sname,
                 "PASS" if passed else "FAIL", len(violations))
        for v in violations:
            LOG.info("  violation: %s", v)
        results.append((sr, deltas, passed, violations))

    write_summary_md(proof_dir, args.gate, results)
    write_summary_csv(proof_dir, results)

    overall = all(p for _, _, p, _ in results)
    LOG.info("=== verdict: %s ===", "GO" if overall else "NO-GO")
    LOG.info("report: %s", proof_dir / "summary.md")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
