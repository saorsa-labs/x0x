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
scenarios (`restart_storm`, `high_rtt_peer`, `partition_recovery`)
require explicit opt-in flags.

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

PARTITION_RULE_COMMENT = "x0x-partition-recovery"

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
        # Per-window strict gate. launch_readiness.py is the
        # *investigation-trigger* layer: every threshold is "any event in
        # a single 15-min window = NO-GO for this window". Aggregate
        # multi-burn-rate certification lives in launch_soak.py's
        # `dispatcher_noise_policy` + `tolerated_dispatcher_windows`
        # logic, which evaluates totals/rates across an entire soak.
        # See `docs/launch-gates/broad-launch.md` for the full two-layer
        # model.
        "max_dispatcher_timed_out_delta": 0,
        "max_recv_pump_dropped_full_delta": 0,
        "max_per_peer_timeout_to_dispatcher_completed_ratio": 0.25,
        "max_suppressed_peers_to_known_peer_topic_pairs_ratio": 0.12,
        "min_phase_a_pairs": 30,
        "max_recovery_secs": 30,
        # X0X-0039 + X0X-0063 acceptance: cluster-wide data_tx saturation
        # must be zero. X0X-0063's 50_000 capacity made this gate clean
        # in all subsequent soaks; keeping it strict because any
        # saturation event signals a real back-pressure regression.
        "max_data_tx_high_water_count_delta": 0,
    },
}


# ── Network endpoints (rebound at runtime by --network flag) ────────────
# Defaults to testnet to keep accidental runs off prod. main() overrides
# these by reading tests/x0x_network.py.
X0X_API_PORT: int = 13600
X0X_GOSSIP_PORT: int = 6483


# ── Token loading ──────────────────────────────────────────────────────
def load_tokens(path: Path, var_prefix: str = "") -> Dict[str, Tuple[str, str]]:
    """Parse a tokens file → {node: (ip, token)}.

    `var_prefix` (e.g. "PROD" or "TEST") narrows parsing to that network's
    variables so a single combined file can never be misread. Empty string
    accepts the legacy unprefixed format.
    """
    if not path.is_file():
        raise FileNotFoundError(f"token file not found: {path}")
    ips: Dict[str, str] = {}
    toks: Dict[str, str] = {}
    if var_prefix:
        pattern = re.compile(
            r'^' + re.escape(var_prefix) + r'_([A-Z]+)_(IP|TK)="?([^"]+)"?\s*$'
        )
    else:
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


AUTH_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+")


def redact_auth_tokens(text: str) -> str:
    """Redact bearer tokens before command strings reach proof logs."""
    return AUTH_BEARER_RE.sub("Bearer [REDACTED]", text)


def fetch_diagnostics(node: str, ip: str, token: str, timeout: int = 12) -> Dict[str, Any]:
    """Fetch /diagnostics/gossip via SSH (avoids opening per-node tunnels)."""
    return fetch_remote_json(node, ip, token, "/diagnostics/gossip", timeout)


def fetch_ack_diagnostics(node: str, ip: str, token: str, timeout: int = 12) -> Dict[str, Any]:
    """Fetch /diagnostics/ack via SSH."""
    return fetch_remote_json(node, ip, token, "/diagnostics/ack", timeout)


def fetch_connectivity_diagnostics(
    node: str, ip: str, token: str, timeout: int = 12
) -> Dict[str, Any]:
    """Fetch /diagnostics/connectivity via SSH (X0X-0039 / X0X-0043 surfaces)."""
    return fetch_remote_json(node, ip, token, "/diagnostics/connectivity", timeout)


def fetch_diagnostics_local(base_url: str, token: str, timeout: int = 12) -> Dict[str, Any]:
    """Fetch /diagnostics/gossip from a local URL (no SSH)."""
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/diagnostics/gossip",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def fetch_connectivity_diagnostics_local(
    base_url: str, token: str, timeout: int = 12
) -> Dict[str, Any]:
    """Fetch /diagnostics/connectivity from a local URL (no SSH)."""
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/diagnostics/connectivity",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def ssh_run(ip: str, remote_cmd: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run a shell command on one VPS with isolated SSH control state."""
    return subprocess.run(
        [
            "ssh",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout={min(timeout, 10)}",
            f"root@{ip}",
            remote_cmd,
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 10,
    )


def ssh_checked(ip: str, remote_cmd: str, timeout: int = 30) -> str:
    """Run a remote command and raise with stderr context on failure."""
    try:
        proc = ssh_run(ip, remote_cmd, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(
            f"ssh command timed out after {timeout}s: {redact_auth_tokens(remote_cmd)}"
        ) from e
    if proc.returncode != 0:
        raise RuntimeError(
            f"ssh command failed rc={proc.returncode}: {redact_auth_tokens(remote_cmd)}; "
            f"stderr={redact_auth_tokens(proc.stderr.strip())}"
        )
    return proc.stdout.strip()


def fetch_remote_json(
    node: str,
    ip: str,
    token: str,
    path: str,
    timeout: int = 12,
) -> Dict[str, Any]:
    """Fetch an authenticated local x0xd JSON endpoint through SSH."""
    header = shlex.quote(f"Authorization: Bearer {token}")
    url = shlex.quote(f"http://127.0.0.1:{X0X_API_PORT}/{path.lstrip('/')}")
    cmd = f"curl -s --max-time {timeout} -H {header} {url}"
    body = ssh_checked(ip, cmd, timeout=timeout + 10)
    if not body:
        raise RuntimeError(f"empty JSON body from {node} {path}")
    return json.loads(body)


def fetch_agent_info(node: str, ip: str, token: str) -> Dict[str, Any]:
    """Return /agent data regardless of ApiResponse wrapping shape."""
    body = fetch_remote_json(node, ip, token, "/agent")
    data = body.get("data", body)
    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected /agent body from {node}: {body}")
    return data


def detect_default_iface(ip: str) -> str:
    """Detect the egress interface used for Internet-bound traffic."""
    cmd = "ip route get 1.1.1.1 | awk '{for (i=1; i<=NF; i++) if ($i==\"dev\") {print $(i+1); exit}}'"
    iface = ssh_checked(ip, cmd, timeout=15).strip()
    if not iface:
        raise RuntimeError("could not detect default network interface")
    return iface


def netem_apply_command(
    iface: str,
    delay_ms: int,
    jitter_ms: int,
    distribution: str,
) -> str:
    """Remote shell command that installs a root netem qdisc."""
    q_iface = shlex.quote(iface)
    q_dist = shlex.quote(distribution)
    return (
        f"tc qdisc del dev {q_iface} root 2>/dev/null || true; "
        f"tc qdisc add dev {q_iface} root netem delay "
        f"{int(delay_ms)}ms {int(jitter_ms)}ms distribution {q_dist}"
    )


def netem_cleanup_command(iface: str) -> str:
    """Remote shell command that removes the root qdisc if present."""
    q_iface = shlex.quote(iface)
    return f"tc qdisc del dev {q_iface} root 2>/dev/null || true"


def netem_verify_clean_command(iface: str) -> str:
    """Remote shell command that succeeds iff no netem qdisc remains."""
    q_iface = shlex.quote(iface)
    return f"! tc qdisc show dev {q_iface} | grep -q netem"


def iptables_rule_args(peer_ip: str, udp_port: int) -> List[str]:
    """The INPUT rule body used for partition-recovery tests."""
    return [
        "-p", "udp",
        "--sport", str(int(udp_port)),
        "-s", peer_ip,
        "-m", "comment",
        "--comment", PARTITION_RULE_COMMENT,
        "-j", "DROP",
    ]


def _shell_join(args: List[str]) -> str:
    return " ".join(shlex.quote(a) for a in args)


def iptables_apply_command(peer_ip: str, udp_port: int) -> str:
    """Remote shell command that inserts the partition DROP rule."""
    return f"iptables -I INPUT 1 {_shell_join(iptables_rule_args(peer_ip, udp_port))}"


def iptables_cleanup_command(peer_ip: str, udp_port: int) -> str:
    """Remote shell command that removes every matching partition rule."""
    args = _shell_join(iptables_rule_args(peer_ip, udp_port))
    return f"while iptables -C INPUT {args} 2>/dev/null; do iptables -D INPUT {args}; done"


def iptables_verify_clean_command(peer_ip: str, udp_port: int) -> str:
    """Remote shell command that succeeds iff the partition rule is absent."""
    return f"! iptables -C INPUT {_shell_join(iptables_rule_args(peer_ip, udp_port))} 2>/dev/null"


def suppressed_topic_counts(ps: Dict[str, Any]) -> Dict[str, int]:
    """Return per-topic suppressed-peer counts from new or legacy diagnostics."""
    raw_by_topic = ps.get("suppressed_peers_by_topic")
    counts: Dict[str, int] = {}
    if isinstance(raw_by_topic, dict):
        for topic, peers in raw_by_topic.items():
            if isinstance(peers, list):
                counts[str(topic)] = len({str(peer) for peer in peers})
            elif isinstance(peers, int):
                counts[str(topic)] = max(0, int(peers))

    if counts:
        return counts

    rows = ps.get("suppressed_peers", []) or []
    grouped: Dict[str, set[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        topic = row.get("topic")
        peer_id = row.get("peer_id")
        if topic is None or peer_id is None:
            continue
        grouped.setdefault(str(topic), set()).add(str(peer_id))
    return {topic: len(peers) for topic, peers in grouped.items()}


def format_top_suppressed_topics(ps: Dict[str, Any], limit: int = 3) -> str:
    """Compact `topic:count` list for CSV/Markdown summaries."""
    counts = suppressed_topic_counts(ps)
    if not counts:
        return ""
    items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return ";".join(f"{topic}:{count}" for topic, count in items)


def peer_score_topic_count(ps: Dict[str, Any]) -> int:
    """Count topics with peer-score rows from new or legacy diagnostics."""
    by_topic = ps.get("peer_scores_by_topic")
    if isinstance(by_topic, dict):
        return len(by_topic)
    rows = ps.get("peer_scores", []) or []
    topics = {
        str(row.get("topic"))
        for row in rows
        if isinstance(row, dict) and row.get("topic") is not None
    }
    return len(topics)


# ── Counter extractors ────────────────────────────────────────────────
def extract_counters(diag: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the SLO-relevant scalars out of /diagnostics/gossip."""
    disp = diag.get("dispatcher", {}).get("pubsub", {})
    rp = diag.get("recv_pump", {}).get("pubsub", {})
    ps = diag.get("pubsub_stages", {})
    ps = ps if isinstance(ps, dict) else {}
    kinds = ps.get("message_kinds", {}) or {}
    sp = ps.get("suppressed_peers", []) or []
    scores = ps.get("peer_scores", []) or []
    topic_caches = ps.get("topic_caches", []) or []
    topic_suppression = suppressed_topic_counts(ps)
    cache_stats = [
        row.get("cache", {}) or {}
        for row in topic_caches
        if isinstance(row, dict)
    ]
    return {
        "dispatcher_completed": int(disp.get("completed", 0)),
        "dispatcher_timed_out": int(disp.get("timed_out", 0)),
        "recv_pump_dropped_full": int(rp.get("dropped_full", 0)),
        "recv_pump_latest_depth": int(rp.get("latest_depth", 0)),
        "recv_pump_max_depth": int(rp.get("max_depth", 0)),
        "recv_pump_produced_total": int(rp.get("produced_total", 0)),
        "recv_pump_dequeued_total": int(rp.get("dequeued_total", 0)),
        "per_peer_timeout_count": int(ps.get("republish_per_peer_timeout", 0)),
        "message_kind_anti_entropy": int(kinds.get("anti_entropy", 0)),
        "message_kind_eager": int(kinds.get("eager", 0)),
        "message_kind_ihave": int(kinds.get("ihave", 0)),
        "message_kind_iwant": int(kinds.get("iwant", 0)),
        "suppressed_peers_size": len(sp),
        "outbound_budget_exhausted": int(ps.get("outbound_budget_exhausted", 0)),
        "pubsub_workers": int(diag.get("dispatcher", {}).get("pubsub_workers", 0)),
        "peer_scores_total": len(scores),
        "peer_scores_eager_eligible": sum(1 for r in scores if r.get("eager_eligible")),
        "peer_scores_lazy": sum(1 for r in scores if r.get("role") == "lazy"),
        "peer_scores_excluded": sum(1 for r in scores if r.get("role") == "excluded"),
        "peer_scores_topics_total": peer_score_topic_count(ps),
        "suppressed_topics_total": len(topic_suppression),
        "suppressed_topic_top_count": max(topic_suppression.values(), default=0),
        "suppressed_topics_top3": format_top_suppressed_topics(ps),
        "pubsub_cache_topics": len(cache_stats),
        "pubsub_cache_msg_count": sum(int(c.get("msg_count", 0)) for c in cache_stats),
        "pubsub_cache_total_bytes": sum(int(c.get("total_bytes", 0)) for c in cache_stats),
        "pubsub_cache_oldest_age_secs_max": max(
            (int(c.get("oldest_age_secs", 0)) for c in cache_stats),
            default=0,
        ),
        "pubsub_cache_evicted_by_age": sum(int(c.get("evicted_by_age", 0)) for c in cache_stats),
        "pubsub_cache_evicted_by_bytes": sum(
            int(c.get("evicted_by_bytes", 0)) for c in cache_stats
        ),
        "pubsub_cache_evicted_by_count": sum(
            int(c.get("evicted_by_count", 0)) for c in cache_stats
        ),
    }


MONOTONIC_COUNTER_FIELDS = {
    "dispatcher_completed",
    "dispatcher_timed_out",
    "recv_pump_dropped_full",
    "recv_pump_produced_total",
    "per_peer_timeout_count",
    "data_tx_high_water_count",
    "gso_bundle_send_total",
    "gso_bundle_partial_send",
    "pubsub_cache_evicted_by_age",
    "pubsub_cache_evicted_by_bytes",
    "pubsub_cache_evicted_by_count",
}

CONNECTIVITY_SCALAR_FIELDS = {
    "data_tx_depth",
    "data_tx_capacity",
    "data_tx_high_water_count",
    "gso_bundle_send_total",
    "gso_bundle_partial_send",
    "transport_peer_count",
    "transport_connected_count",
    "transport_rtt_ms_max",
    "transport_packet_loss_ppm_max",
}

NON_DELTA_FIELDS = {
    "suppressed_topics_top3",
    "transport_peers_top3",
}


def transport_rows(diag: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return per-peer transport rows when the connectivity endpoint exposes them."""
    rows = diag.get("per_peer_transport", []) or []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _packet_loss_ppm(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return max(0, int(float(value) * 1_000_000))
    except (TypeError, ValueError):
        return None


def format_transport_peers(rows: List[Dict[str, Any]], limit: int = 3) -> str:
    """Compact peer transport ranking for CSV/Markdown summaries."""
    if not rows:
        return ""

    def _rank(row: Dict[str, Any]) -> Tuple[int, int, str]:
        loss = _packet_loss_ppm(row.get("packet_loss_rate")) or 0
        rtt = _optional_int(row.get("rtt_ms")) or 0
        return (-loss, -rtt, str(row.get("peer_id", "")))

    parts: List[str] = []
    for row in sorted(rows, key=_rank)[:limit]:
        peer = str(row.get("peer_id", "?"))[:12]
        rtt = _optional_int(row.get("rtt_ms"))
        loss = _packet_loss_ppm(row.get("packet_loss_rate"))
        idle = _optional_int(row.get("idle_for_ms"))
        fields = [
            f"rtt={rtt}ms" if rtt is not None else "rtt=?",
            f"loss={loss}ppm" if loss is not None else "loss=?",
        ]
        if idle is not None:
            fields.append(f"idle={idle}ms")
        parts.append(f"{peer}({','.join(fields)})")
    return ";".join(parts)


def extract_connectivity_scalars(diag: Dict[str, Any]) -> Dict[str, Any]:
    """Pull X0X-0039/X0X-0043 scalars out of /diagnostics/connectivity.

    Missing/null values stay distinct from zero so gate evaluation can
    fail closed when the connectivity endpoint or a required block is
    unavailable.
    """
    data_tx_raw = diag.get("data_tx")
    gso_raw = diag.get("gso")
    data_tx = data_tx_raw if isinstance(data_tx_raw, dict) else {}
    gso = gso_raw if isinstance(gso_raw, dict) else {}
    has_transport_block = isinstance(diag.get("per_peer_transport"), list)
    transports = transport_rows(diag)
    rtts = [
        value for value in (_optional_int(row.get("rtt_ms")) for row in transports)
        if value is not None
    ]
    losses = [
        value
        for value in (_packet_loss_ppm(row.get("packet_loss_rate")) for row in transports)
        if value is not None
    ]

    return {
        "data_tx_depth": _optional_int(data_tx.get("data_tx_depth")),
        "data_tx_capacity": _optional_int(data_tx.get("data_tx_capacity")),
        "data_tx_high_water_count": _optional_int(data_tx.get("data_tx_high_water_count")),
        "gso_bundle_send_total": _optional_int(gso.get("bundle_send_total")),
        "gso_bundle_partial_send": _optional_int(gso.get("bundle_partial_send")),
        "transport_peer_count": len(transports) if has_transport_block else None,
        "transport_connected_count": (
            sum(1 for row in transports if row.get("connected"))
            if has_transport_block
            else None
        ),
        "transport_rtt_ms_max": max(rtts, default=0) if has_transport_block else None,
        "transport_packet_loss_ppm_max": max(losses, default=0) if has_transport_block else None,
        "transport_peers_top3": format_transport_peers(transports),
    }


def diff_counters(pre: Dict[str, Any], post: Dict[str, Any]) -> Dict[str, Any]:
    """Per-key delta. Monotonic counters are clamped across resets/gaps."""
    keys = (set(pre) | set(post)) - NON_DELTA_FIELDS

    def _delta(key: str) -> Optional[int]:
        if key in CONNECTIVITY_SCALAR_FIELDS:
            if key not in pre or key not in post:
                return None
            pre_value = pre.get(key)
            post_value = post.get(key)
            if pre_value is None or post_value is None:
                return None
        else:
            pre_value = pre.get(key, 0)
            post_value = post.get(key, 0)
        return int(post_value) - int(pre_value)

    deltas = {k: _delta(k) for k in keys}
    for key in MONOTONIC_COUNTER_FIELDS:
        if key in deltas and deltas[key] is not None:
            deltas[key] = max(0, deltas[key])
    return deltas


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


def suppressed_peers_ratio(post: Dict[str, int]) -> float:
    """Suppressed peer-topic entries normalized by known peer-topic scores."""
    suppressed = max(0, int(post.get("suppressed_peers_size", 0)))
    known_pairs = max(
        0,
        int(post.get("known_peer_topic_pairs", 0)),
        int(post.get("peer_scores_total", 0)),
    )
    if suppressed == 0:
        return 0.0
    if known_pairs == 0:
        return float("inf")
    return suppressed / known_pairs


def scalar_for_report(value: Any) -> str:
    """Render optional diagnostics scalars in proof artifacts."""
    if value is None:
        return "MISSING"
    return str(value)


def bool_for_report(value: Any) -> str:
    """Render proof booleans consistently for CSV/Markdown outputs."""
    return "true" if bool(value) else "false"


def peer_id_matches(observed: Any, target_peer_id: str) -> bool:
    """Match full machine IDs against the short peer IDs in diagnostics."""
    observed_s = str(observed or "")
    if not observed_s or not target_peer_id:
        return False
    return (
        observed_s == target_peer_id
        or observed_s.startswith(target_peer_id)
        or target_peer_id.startswith(observed_s)
    )


def summarize_peer_view(diag: Dict[str, Any], target_peer_id: str) -> Dict[str, Any]:
    """Summarize peer-score and suppression diagnostics for one target peer."""
    ps = diag.get("pubsub_stages", {})
    scores = [
        r for r in (ps.get("peer_scores", []) or [])
        if peer_id_matches(r.get("peer_id"), target_peer_id)
    ]
    suppressed = [
        r for r in (ps.get("suppressed_peers", []) or [])
        if peer_id_matches(r.get("peer_id"), target_peer_id)
    ]
    role_counts: Dict[str, int] = {}
    for row in scores:
        role = str(row.get("role", "unknown"))
        role_counts[role] = role_counts.get(role, 0) + 1

    score_values = [
        float(row.get("score", 0.0))
        for row in scores
        if isinstance(row.get("score", 0.0), (int, float))
    ]
    health_values = [
        float(row.get("send_health", 0.0))
        for row in scores
        if isinstance(row.get("send_health", 0.0), (int, float))
    ]

    return {
        "score_entries": len(scores),
        "suppressed_entries": len(suppressed),
        "suppressed_states": sorted({str(r.get("state", "unknown")) for r in suppressed}),
        "suppressed_topics": sorted({str(r.get("topic")) for r in suppressed if r.get("topic")}),
        "roles": role_counts,
        "eager_eligible": sum(1 for r in scores if r.get("eager_eligible")),
        "score_min": min(score_values) if score_values else None,
        "score_avg": (sum(score_values) / len(score_values)) if score_values else None,
        "score_max": max(score_values) if score_values else None,
        "send_health_avg": (sum(health_values) / len(health_values)) if health_values else None,
        "outbound_send_timeouts": sum(float(r.get("outbound_send_timeouts", 0.0)) for r in scores),
        "cooling_events": sum(float(r.get("cooling_events", 0.0)) for r in scores),
        "topics": sorted({str(r.get("topic")) for r in scores if r.get("topic")}),
    }


def summarize_peer_across_nodes(
    ctx: ScenarioContext,
    target_peer_id: str,
    label: str,
) -> Dict[str, Any]:
    """Fetch diagnostics from all nodes and summarize their view of target."""
    observers: Dict[str, Any] = {}
    for node, (ip, token) in ctx.nodes.items():
        try:
            diag = fetch_diagnostics(node, ip, token)
            observers[node] = summarize_peer_view(diag, target_peer_id)
        except Exception as exc:
            observers[node] = {"error": str(exc)}
    return {
        "label": label,
        "unix": int(time.time()),
        "target_peer_id": target_peer_id,
        "observers": observers,
    }


def total_suppressed(snapshot: Dict[str, Any], exclude_node: Optional[str] = None) -> int:
    total = 0
    for node, view in snapshot.get("observers", {}).items():
        if node == exclude_node or not isinstance(view, dict):
            continue
        total += int(view.get("suppressed_entries", 0) or 0)
    return total


def total_lazy_or_excluded(snapshot: Dict[str, Any], exclude_node: Optional[str] = None) -> int:
    total = 0
    for node, view in snapshot.get("observers", {}).items():
        if node == exclude_node or not isinstance(view, dict):
            continue
        roles = view.get("roles", {}) or {}
        total += int(roles.get("lazy", 0) or 0)
        total += int(roles.get("excluded", 0) or 0)
    return total


def min_score(snapshot: Dict[str, Any], exclude_node: Optional[str] = None) -> Optional[float]:
    values: List[float] = []
    for node, view in snapshot.get("observers", {}).items():
        if node == exclude_node or not isinstance(view, dict):
            continue
        value = view.get("score_min")
        if isinstance(value, (int, float)):
            values.append(float(value))
    return min(values) if values else None


def target_cooling_delta_summary(
    start: Dict[str, Any],
    mid: Dict[str, Any],
    exclude_node: Optional[str] = None,
) -> Dict[str, Any]:
    """Detect new target-peer cooling activity in a noisy baseline.

    The live high_rtt_peer run can begin while unrelated suppressions are
    draining. This helper looks only at the target peer as seen by each
    observer and fires on positive per-observer deltas instead of aggregate
    cluster counts.
    """

    observers: Dict[str, Any] = {}
    cooling_event_observers: List[str] = []
    timeout_observers: List[str] = []
    new_suppression_observers: List[str] = []

    start_observers = start.get("observers", {}) or {}
    mid_observers = mid.get("observers", {}) or {}
    for node in sorted(set(start_observers) | set(mid_observers)):
        if node == exclude_node:
            continue
        start_view = start_observers.get(node, {}) or {}
        mid_view = mid_observers.get(node, {}) or {}
        if not isinstance(start_view, dict) or not isinstance(mid_view, dict):
            continue
        if "error" in start_view or "error" in mid_view:
            observers[node] = {
                "error": start_view.get("error") or mid_view.get("error")
            }
            continue

        cooling_delta = max(
            0.0,
            float(mid_view.get("cooling_events", 0.0) or 0.0)
            - float(start_view.get("cooling_events", 0.0) or 0.0),
        )
        timeout_delta = max(
            0.0,
            float(mid_view.get("outbound_send_timeouts", 0.0) or 0.0)
            - float(start_view.get("outbound_send_timeouts", 0.0) or 0.0),
        )
        start_suppressed_topics = {
            str(topic) for topic in (start_view.get("suppressed_topics", []) or [])
        }
        mid_suppressed_topics = {
            str(topic) for topic in (mid_view.get("suppressed_topics", []) or [])
        }
        new_suppressed_topics = sorted(mid_suppressed_topics - start_suppressed_topics)
        first_suppression = (
            int(start_view.get("suppressed_entries", 0) or 0) == 0
            and int(mid_view.get("suppressed_entries", 0) or 0) > 0
        )
        new_suppression = bool(new_suppressed_topics) or first_suppression

        if cooling_delta > 0:
            cooling_event_observers.append(node)
        if timeout_delta > 0:
            timeout_observers.append(node)
        if new_suppression:
            new_suppression_observers.append(node)

        observers[node] = {
            "cooling_events_delta": cooling_delta,
            "outbound_send_timeouts_delta": timeout_delta,
            "new_suppressed_topics": new_suppressed_topics,
            "first_suppression": first_suppression,
            "new_suppression": new_suppression,
        }

    cooling_observed = bool(
        cooling_event_observers or timeout_observers or new_suppression_observers
    )
    return {
        "cooling_observed": cooling_observed,
        "cooling_event_observers": cooling_event_observers,
        "outbound_send_timeout_observers": timeout_observers,
        "new_suppression_observers": new_suppression_observers,
        "observers": observers,
    }


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


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
        "http://127.0.0.1:{api_port}/publish >/dev/null; "
        "{sleep}"
        "done"
    ).format(
        burst=burst,
        token=token,
        topic=topic,
        payload=payload_b64,
        sleep=(f"sleep {delay_ms / 1000.0}; " if delay_ms > 0 else ""),
        api_port=X0X_API_PORT,
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
                        f"http://127.0.0.1:{X0X_API_PORT}/health",
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


def scenario_high_rtt_peer(ctx: ScenarioContext) -> ScenarioResult:
    """Inject netem delay on one non-anchor node and observe cooling."""
    t0 = time.time()
    if not ctx.args.allow_netem:
        return ScenarioResult(
            name="high_rtt_peer",
            duration_secs=0.0,
            fail_reason="skipped: pass --allow-netem to enable",
        )
    target = ctx.args.target_node
    if not target:
        return ScenarioResult(
            name="high_rtt_peer",
            duration_secs=0.0,
            fail_reason="--target-node is required with --allow-netem",
        )
    if target == ctx.anchor:
        return ScenarioResult(
            name="high_rtt_peer",
            duration_secs=0.0,
            fail_reason="--target-node must be a non-anchor node",
        )
    if target not in ctx.nodes:
        return ScenarioResult(
            name="high_rtt_peer",
            duration_secs=0.0,
            fail_reason=f"unknown --target-node {target}",
        )

    target_ip, target_token = ctx.nodes[target]
    scenario_dir = ctx.proof_dir / "scenarios" / "high_rtt_peer"
    trajectory_path = scenario_dir / "peer-score-trajectory.json"
    iface = ctx.args.netem_iface or detect_default_iface(target_ip)
    agent_info = fetch_agent_info(target, target_ip, target_token)
    target_machine_id = str(agent_info.get("machine_id", ""))
    target_peer_id = target_machine_id[:16]
    if not target_peer_id:
        return ScenarioResult(
            name="high_rtt_peer",
            duration_secs=time.time() - t0,
            fail_reason=f"{target} /agent response missing machine_id",
        )

    window_secs = max(1, int(ctx.args.netem_secs))
    heal_secs = max(0, int(ctx.args.netem_heal_secs))
    half_secs = max(1, window_secs // 2)
    applied = False
    interrupted = False
    cleanup_ok = False
    scenario_error: Optional[str] = None
    trajectory: Dict[str, Any] = {
        "target_node": target,
        "target_ip": target_ip,
        "target_machine_id": target_machine_id,
        "target_peer_id": target_peer_id,
        "iface": iface,
        "delay_ms": int(ctx.args.netem_delay_ms),
        "jitter_ms": int(ctx.args.netem_jitter_ms),
        "distribution": ctx.args.netem_distribution,
        "window_secs": window_secs,
        "heal_secs": heal_secs,
        "samples": [],
    }

    def sample(label: str) -> None:
        LOG.info("high_rtt_peer: sampling %s", label)
        trajectory["samples"].append(summarize_peer_across_nodes(ctx, target_peer_id, label))
        write_json(trajectory_path, trajectory)

    LOG.warning(
        "high_rtt_peer: applying netem to %s iface=%s delay=%sms jitter=%sms",
        target, iface, ctx.args.netem_delay_ms, ctx.args.netem_jitter_ms,
    )
    try:
        sample("start")
        ssh_checked(
            target_ip,
            netem_apply_command(
                iface,
                int(ctx.args.netem_delay_ms),
                int(ctx.args.netem_jitter_ms),
                ctx.args.netem_distribution,
            ),
            timeout=30,
        )
        applied = True
        time.sleep(half_secs)
        sample("mid")
        time.sleep(max(0, window_secs - half_secs))
    except KeyboardInterrupt:
        interrupted = True
        LOG.warning("high_rtt_peer interrupted; cleaning netem before returning")
    except Exception as exc:
        scenario_error = str(exc)
        trajectory["error"] = str(exc)
        LOG.warning("high_rtt_peer failed before cleanup: %s", exc)
    finally:
        if applied:
            cleanup = ssh_run(target_ip, netem_cleanup_command(iface), timeout=30)
            verify = ssh_run(target_ip, netem_verify_clean_command(iface), timeout=15)
            cleanup_ok = cleanup.returncode == 0 and verify.returncode == 0
            trajectory["cleanup"] = {
                "cleanup_rc": cleanup.returncode,
                "cleanup_stderr": cleanup.stderr.strip(),
                "verify_rc": verify.returncode,
                "verify_stderr": verify.stderr.strip(),
                "clean": cleanup_ok,
            }
        else:
            cleanup_ok = True
            trajectory["cleanup"] = {"clean": True, "note": "netem was not applied"}

    if not interrupted and cleanup_ok and heal_secs > 0:
        time.sleep(heal_secs)
    sample("end")

    samples = trajectory["samples"]
    start_sample = samples[0] if samples else {}
    mid_sample = samples[1] if len(samples) > 1 else samples[-1] if samples else {}
    end_sample = samples[-1] if samples else {}
    start_suppressed = total_suppressed(start_sample, exclude_node=target)
    mid_suppressed = total_suppressed(mid_sample, exclude_node=target)
    end_suppressed = total_suppressed(end_sample, exclude_node=target)
    start_demoted = total_lazy_or_excluded(start_sample, exclude_node=target)
    mid_demoted = total_lazy_or_excluded(mid_sample, exclude_node=target)
    start_min_score = min_score(start_sample, exclude_node=target)
    mid_min_score = min_score(mid_sample, exclude_node=target)
    score_dropped = (
        start_min_score is not None
        and mid_min_score is not None
        and mid_min_score < start_min_score - 0.05
    )
    cooling_delta_summary = target_cooling_delta_summary(
        start_sample,
        mid_sample,
        exclude_node=target,
    )
    cooling_observed = bool(cooling_delta_summary["cooling_observed"])
    recovered = end_suppressed <= max(start_suppressed, 1)
    trajectory["summary"] = {
        "start_suppressed": start_suppressed,
        "mid_suppressed": mid_suppressed,
        "end_suppressed": end_suppressed,
        "start_lazy_or_excluded": start_demoted,
        "mid_lazy_or_excluded": mid_demoted,
        "start_min_score": start_min_score,
        "mid_min_score": mid_min_score,
        "legacy_score_dropped": score_dropped,
        "target_cooling_deltas": cooling_delta_summary,
        "cooling_observed": cooling_observed,
        "recovered": recovered,
    }
    write_json(trajectory_path, trajectory)

    fail_reason = None
    if interrupted:
        fail_reason = "interrupted after netem cleanup"
    elif not cleanup_ok:
        fail_reason = f"netem cleanup failed on {target}"
    elif scenario_error:
        fail_reason = scenario_error
    elif not cooling_observed:
        fail_reason = "cooling signal was not observed for target peer"
    elif not recovered:
        fail_reason = "suppressed_peers for target peer did not drain after netem heal window"

    return ScenarioResult(
        name="high_rtt_peer",
        duration_secs=time.time() - t0,
        extra_metrics={
            "target_node": target,
            "netem_iface": iface,
            "netem_delay_ms": int(ctx.args.netem_delay_ms),
            "netem_jitter_ms": int(ctx.args.netem_jitter_ms),
            "netem_window_secs": window_secs,
            "netem_heal_secs": heal_secs,
            "cooling_observed": cooling_observed,
            "suppression_recovered": recovered,
            "trajectory_path": str(trajectory_path),
            "dispatcher_timeout_exempt_nodes": target,
            "suppression_ratio_exempt_nodes": target,
        },
        fail_reason=fail_reason,
    )


def parse_partition_pair(pair: str, anchor: str, nodes: Dict[str, Tuple[str, str]]) -> Tuple[str, str]:
    parts = [p.strip() for p in pair.split(",") if p.strip()]
    if len(parts) != 2:
        raise ValueError("--partition-pair must be two node names, e.g. sfo,sydney")
    a, b = parts
    if a == b:
        raise ValueError("--partition-pair nodes must be distinct")
    if a == anchor or b == anchor:
        raise ValueError("--partition-pair must not include the anchor")
    missing = [n for n in (a, b) if n not in nodes]
    if missing:
        raise ValueError(f"unknown partition node(s): {','.join(missing)}")
    return a, b


def anti_entropy_count(diag: Dict[str, Any]) -> int:
    return int(
        diag.get("pubsub_stages", {})
        .get("message_kinds", {})
        .get("anti_entropy", 0)
    )


def suppressed_count_for_peer(diag: Dict[str, Any], peer_id: str) -> int:
    return int(summarize_peer_view(diag, peer_id).get("suppressed_entries", 0) or 0)


def scenario_partition_recovery(ctx: ScenarioContext) -> ScenarioResult:
    """Partition two non-anchor nodes with iptables, then prove heal."""
    t0 = time.time()
    if not ctx.args.allow_iptables:
        return ScenarioResult(
            name="partition_recovery",
            duration_secs=0.0,
            fail_reason="skipped: pass --allow-iptables to enable",
        )
    try:
        a, b = parse_partition_pair(ctx.args.partition_pair, ctx.anchor, ctx.nodes)
    except ValueError as exc:
        return ScenarioResult(
            name="partition_recovery",
            duration_secs=0.0,
            fail_reason=str(exc),
        )

    scenario_dir = ctx.proof_dir / "scenarios" / "partition_recovery"
    recovery_path = scenario_dir / "recovery.json"
    a_ip, a_token = ctx.nodes[a]
    b_ip, b_token = ctx.nodes[b]
    a_info = fetch_agent_info(a, a_ip, a_token)
    b_info = fetch_agent_info(b, b_ip, b_token)
    a_peer_id = str(a_info.get("machine_id", ""))[:16]
    b_peer_id = str(b_info.get("machine_id", ""))[:16]
    if not a_peer_id or not b_peer_id:
        return ScenarioResult(
            name="partition_recovery",
            duration_secs=time.time() - t0,
            fail_reason="partition pair /agent response missing machine_id",
        )

    block_secs = max(1, int(ctx.args.block_secs))
    heal_secs = max(1, int(ctx.args.heal_secs))
    poll_secs = max(1, int(ctx.args.recovery_poll_secs))
    port = int(ctx.args.partition_udp_port)
    applied: List[Tuple[str, str, str]] = []
    interrupted = False
    cleanup_ok = False
    scenario_error: Optional[str] = None
    proof: Dict[str, Any] = {
        "pair": [a, b],
        "peer_ids": {a: a_peer_id, b: b_peer_id},
        "peer_ips": {a: a_ip, b: b_ip},
        "udp_port": port,
        "block_secs": block_secs,
        "heal_secs": heal_secs,
        "poll_secs": poll_secs,
        "samples": [],
    }

    def pair_sample(label: str) -> Dict[str, Any]:
        LOG.info("partition_recovery: sampling %s", label)
        a_diag = fetch_diagnostics(a, a_ip, a_token)
        b_diag = fetch_diagnostics(b, b_ip, b_token)
        sample = {
            "label": label,
            "unix": int(time.time()),
            a: {
                "anti_entropy": anti_entropy_count(a_diag),
                "suppressed_for_peer": suppressed_count_for_peer(a_diag, b_peer_id),
            },
            b: {
                "anti_entropy": anti_entropy_count(b_diag),
                "suppressed_for_peer": suppressed_count_for_peer(b_diag, a_peer_id),
            },
        }
        proof["samples"].append(sample)
        write_json(recovery_path, proof)
        return sample

    LOG.warning("partition_recovery: blocking UDP/%d between %s and %s", port, a, b)
    try:
        start = pair_sample("start")
        ssh_checked(a_ip, iptables_apply_command(b_ip, port), timeout=20)
        applied.append((a, a_ip, b_ip))
        ssh_checked(b_ip, iptables_apply_command(a_ip, port), timeout=20)
        applied.append((b, b_ip, a_ip))
        time.sleep(block_secs)
        blocked = pair_sample("blocked")
    except KeyboardInterrupt:
        interrupted = True
        LOG.warning("partition_recovery interrupted; cleaning iptables before returning")
        start = proof["samples"][0] if proof["samples"] else {}
        blocked = proof["samples"][-1] if proof["samples"] else {}
    except Exception as exc:
        scenario_error = str(exc)
        proof["error"] = str(exc)
        LOG.warning("partition_recovery failed before cleanup: %s", exc)
        start = proof["samples"][0] if proof["samples"] else {}
        blocked = proof["samples"][-1] if proof["samples"] else {}
    finally:
        cleanup_results = []
        for node, ip, peer_ip in applied:
            cleanup = ssh_run(ip, iptables_cleanup_command(peer_ip, port), timeout=20)
            verify = ssh_run(ip, iptables_verify_clean_command(peer_ip, port), timeout=15)
            cleanup_results.append({
                "node": node,
                "peer_ip": peer_ip,
                "cleanup_rc": cleanup.returncode,
                "cleanup_stderr": cleanup.stderr.strip(),
                "verify_rc": verify.returncode,
                "verify_stderr": verify.stderr.strip(),
                "clean": cleanup.returncode == 0 and verify.returncode == 0,
            })
        cleanup_ok = all(r["clean"] for r in cleanup_results) if cleanup_results else True
        proof["cleanup"] = cleanup_results
        write_json(recovery_path, proof)

    recovered_at: Optional[int] = None
    end = proof["samples"][-1] if proof["samples"] else {}
    if not interrupted and cleanup_ok:
        deadline = time.time() + heal_secs
        baseline_a = int(start.get(a, {}).get("suppressed_for_peer", 0) or 0)
        baseline_b = int(start.get(b, {}).get("suppressed_for_peer", 0) or 0)
        while True:
            end = pair_sample("heal")
            recovered = (
                int(end.get(a, {}).get("suppressed_for_peer", 0) or 0) <= baseline_a
                and int(end.get(b, {}).get("suppressed_for_peer", 0) or 0) <= baseline_b
            )
            if recovered:
                recovered_at = int(time.time() - t0)
                break
            if time.time() >= deadline:
                break
            time.sleep(min(poll_secs, max(0.0, deadline - time.time())))

    start_a_ae = int(start.get(a, {}).get("anti_entropy", 0) or 0)
    start_b_ae = int(start.get(b, {}).get("anti_entropy", 0) or 0)
    end_a_ae = int(end.get(a, {}).get("anti_entropy", start_a_ae) or start_a_ae)
    end_b_ae = int(end.get(b, {}).get("anti_entropy", start_b_ae) or start_b_ae)
    anti_entropy_delta = {
        a: max(0, end_a_ae - start_a_ae),
        b: max(0, end_b_ae - start_b_ae),
    }
    proof["summary"] = {
        "anti_entropy_delta": anti_entropy_delta,
        "recovered_at_secs": recovered_at,
        "cleanup_ok": cleanup_ok,
    }
    write_json(recovery_path, proof)

    fail_reason = None
    if interrupted:
        fail_reason = "interrupted after iptables cleanup"
    elif not cleanup_ok:
        fail_reason = "iptables cleanup verification failed"
    elif scenario_error:
        fail_reason = scenario_error
    elif recovered_at is None:
        fail_reason = "partition pair did not return to baseline suppression within heal window"
    elif anti_entropy_delta[a] == 0 and anti_entropy_delta[b] == 0:
        fail_reason = "no anti_entropy traffic observed during partition/heal window"

    return ScenarioResult(
        name="partition_recovery",
        duration_secs=time.time() - t0,
        extra_metrics={
            "partition_pair": f"{a},{b}",
            "block_secs": block_secs,
            "heal_secs": heal_secs,
            "recovered_at_secs": recovered_at if recovered_at is not None else -1,
            "anti_entropy_delta": anti_entropy_delta,
            "recovery_path": str(recovery_path),
            "dispatcher_timeout_exempt_nodes": f"{a},{b}",
        },
        fail_reason=fail_reason,
    )


SCENARIOS: Dict[str, ScenarioFn] = {
    "baseline": scenario_baseline,
    "fanout_burst": scenario_fanout_burst,
    "restart_storm": scenario_restart_storm,
    "high_rtt_peer": scenario_high_rtt_peer,
    "partition_recovery": scenario_partition_recovery,
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
    dispatcher_exempt_nodes = {
        n.strip()
        for n in str(scenario.extra_metrics.get("dispatcher_timeout_exempt_nodes", "")).split(",")
        if n.strip()
    }
    suppression_ratio_exempt_nodes = {
        n.strip()
        for n in str(scenario.extra_metrics.get("suppression_ratio_exempt_nodes", "")).split(",")
        if n.strip()
    }

    for node, d in deltas_per_node.items():
        if (
            node not in dispatcher_exempt_nodes
            and d.get("dispatcher_timed_out", 0) > g["max_dispatcher_timed_out_delta"]
        ):
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
        # X0X-0039 acceptance: data_tx must not saturate cluster-wide.
        if "max_data_tx_high_water_count_delta" in g:
            high_water_delta = d.get("data_tx_high_water_count")
            if high_water_delta is None:
                violations.append(
                    f"{node}: data_tx_high_water_count_delta unmeasurable: "
                    "/diagnostics/connectivity unreachable or missing data_tx"
                )
            elif high_water_delta > g["max_data_tx_high_water_count_delta"]:
                violations.append(
                    f"{node}: data_tx saturation delta "
                    f"{high_water_delta} > "
                    f"gate {g['max_data_tx_high_water_count_delta']}"
                )

    for node, post in posts_per_node.items():
        if (
            "max_suppressed_peers_steady" in g
            and post.get("suppressed_peers_size", 0) > g["max_suppressed_peers_steady"]
        ):
            violations.append(
                f"{node}: suppressed_peers steady {post['suppressed_peers_size']} "
                f"> gate {g['max_suppressed_peers_steady']}"
            )
        if (
            "max_suppressed_peers_to_known_peer_topic_pairs_ratio" in g
            and node not in suppression_ratio_exempt_nodes
        ):
            ratio = suppressed_peers_ratio(post)
            max_ratio = g["max_suppressed_peers_to_known_peer_topic_pairs_ratio"]
            if ratio > max_ratio:
                ratio_str = "inf" if ratio == float("inf") else f"{ratio:.3f}"
                violations.append(
                    f"{node}: suppressed_peers/known_peer_topic_pairs ratio "
                    f"{ratio_str} > gate {max_ratio:.3f} "
                    f"({post.get('suppressed_peers_size', 0)} / "
                    f"{post.get('known_peer_topic_pairs', post.get('peer_scores_total', 0))})"
                )

    if scenario.name == "baseline":
        rcv = scenario.extra_metrics.get("phase_a_received", 0)
        if rcv < g["min_phase_a_pairs"]:
            violations.append(
                f"phase A received {rcv} < gate {g['min_phase_a_pairs']}"
            )
        sent = scenario.extra_metrics.get("phase_a_sent", 0)
        if sent < g["min_phase_a_pairs"]:
            violations.append(
                f"phase A sent {sent} < gate {g['min_phase_a_pairs']}"
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
            "| node | disp_to | drop_full | drop_ratio | pp_to | pp_to/completed | depth_post | suppressed_post | suppressed_topics | suppressed/known | known_pairs | workers_post |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for node in sorted(deltas):
            d = deltas[node]
            posts = d.get("_post", {})
            pp_ratio = per_peer_timeout_ratio(d)
            pp_ratio_str = "inf" if pp_ratio == float("inf") else f"{pp_ratio:.3f}"
            drop_ratio = dropped_full_ratio(d)
            drop_ratio_str = "inf" if drop_ratio == float("inf") else f"{drop_ratio:.6f}"
            suppressed_ratio = suppressed_peers_ratio(posts)
            suppressed_ratio_str = (
                "inf" if suppressed_ratio == float("inf") else f"{suppressed_ratio:.3f}"
            )
            lines.append(
                f"| {node} | {d.get('dispatcher_timed_out', 0)} | "
                f"{d.get('recv_pump_dropped_full', 0)} | "
                f"{drop_ratio_str} | "
                f"{d.get('per_peer_timeout_count', 0)} | "
                f"{pp_ratio_str} | "
                f"{posts.get('recv_pump_latest_depth', 0)} | "
                f"{posts.get('suppressed_peers_size', 0)} | "
                f"{posts.get('suppressed_topics_total', 0)} | "
                f"{suppressed_ratio_str} | "
                f"{posts.get('known_peer_topic_pairs', posts.get('peer_scores_total', 0))} | "
                f"{posts.get('pubsub_workers', 0)} |"
            )
        lines.append("")

        # X0X-0039 / X0X-0043 — per-scenario connectivity diagnostics summary.
        # data_tx_* gates broad-launch (hard fail). gso_* are recorded but
        # do not fail the gate today (Quinn #2627 GSO-tail-drop hypothesis
        # under test; bundles never form in current build).
        lines.append("## Diagnostics (X0X-0039 data_tx, X0X-0043 GSO)")
        lines.append("")
        lines.append(
            "| node | conn_pre | conn_post | data_tx_depth_post | data_tx_capacity_post | "
            "data_tx_high_water Δ | gso_bundle_send_total Δ | "
            "gso_bundle_partial_send Δ |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
        for node in sorted(deltas):
            d = deltas[node]
            posts = d.get("_post", {})
            lines.append(
                f"| {node} | "
                f"{bool_for_report(d.get('diagnostics_connectivity_pre_fetched', False))} | "
                f"{bool_for_report(d.get('diagnostics_connectivity_post_fetched', False))} | "
                f"{scalar_for_report(posts.get('data_tx_depth'))} | "
                f"{scalar_for_report(posts.get('data_tx_capacity'))} | "
                f"{scalar_for_report(d.get('data_tx_high_water_count'))} | "
                f"{scalar_for_report(d.get('gso_bundle_send_total'))} | "
                f"{scalar_for_report(d.get('gso_bundle_partial_send'))} |"
            )
        lines.append("")

        lines.append("## Diagnostics (X0X-0075 suppression/transport)")
        lines.append("")
        lines.append(
            "| node | top_suppressed_topics | peer_score_topics | transport_peers | "
            "transport_connected | max_rtt_ms | max_loss_ppm | transport_top |"
        )
        lines.append("|---|---|---:|---:|---:|---:|---:|---|")
        for node in sorted(deltas):
            d = deltas[node]
            posts = d.get("_post", {})
            lines.append(
                f"| {node} | "
                f"{posts.get('suppressed_topics_top3', '') or '-'} | "
                f"{posts.get('peer_scores_topics_total', 0)} | "
                f"{scalar_for_report(posts.get('transport_peer_count'))} | "
                f"{scalar_for_report(posts.get('transport_connected_count'))} | "
                f"{scalar_for_report(posts.get('transport_rtt_ms_max'))} | "
                f"{scalar_for_report(posts.get('transport_packet_loss_ppm_max'))} | "
                f"{posts.get('transport_peers_top3', '') or '-'} |"
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
            "recv_pump_latest_depth_post", "suppressed_peers_to_known_ratio",
            "known_peer_topic_pairs_post",
            "suppressed_topics_post", "suppressed_topic_top_count_post",
            "suppressed_topics_top3_post", "peer_score_topics_post",
            # X0X-0039 / X0X-0043 connectivity diagnostics scalars.
            "diagnostics_connectivity_pre_fetched",
            "diagnostics_connectivity_post_fetched",
            "data_tx_depth_post", "data_tx_capacity_post",
            "data_tx_high_water_count_delta",
            "gso_bundle_send_total_delta", "gso_bundle_partial_send_delta",
            # X0X-0075 per-peer transport diagnostics.
            "transport_peer_count_post", "transport_connected_count_post",
            "transport_rtt_ms_max_post", "transport_packet_loss_ppm_max_post",
            "transport_peers_top3_post",
        ])
        for sr, deltas, passed, violations in results:
            for node, d in deltas.items():
                posts = d.get("_post", {})
                pp_ratio = per_peer_timeout_ratio(d)
                drop_ratio = dropped_full_ratio(d)
                suppressed_ratio = suppressed_peers_ratio(posts)
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
                    "inf" if suppressed_ratio == float("inf") else f"{suppressed_ratio:.6f}",
                    posts.get("known_peer_topic_pairs", posts.get("peer_scores_total", 0)),
                    posts.get("suppressed_topics_total", 0),
                    posts.get("suppressed_topic_top_count", 0),
                    posts.get("suppressed_topics_top3", ""),
                    posts.get("peer_scores_topics_total", 0),
                    bool_for_report(d.get("diagnostics_connectivity_pre_fetched", False)),
                    bool_for_report(d.get("diagnostics_connectivity_post_fetched", False)),
                    scalar_for_report(posts.get("data_tx_depth")),
                    scalar_for_report(posts.get("data_tx_capacity")),
                    scalar_for_report(d.get("data_tx_high_water_count")),
                    scalar_for_report(d.get("gso_bundle_send_total")),
                    scalar_for_report(d.get("gso_bundle_partial_send")),
                    scalar_for_report(posts.get("transport_peer_count")),
                    scalar_for_report(posts.get("transport_connected_count")),
                    scalar_for_report(posts.get("transport_rtt_ms_max")),
                    scalar_for_report(posts.get("transport_packet_loss_ppm_max")),
                    posts.get("transport_peers_top3", ""),
                ])


# ── Main ──────────────────────────────────────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor", default="nyc", choices=NODES_DEFAULT)
    parser.add_argument("--gate", default="limited-production",
                        choices=sorted(GATES.keys()))
    parser.add_argument("--scenarios", default="baseline,fanout_burst",
                        help="comma-separated scenario list (default: %(default)s)")
    # Network selection — defaults to testnet. Pass --network prod for the
    # production fleet (REAL USERS); that path prints a loud banner and
    # holds 5s before any action. See tests/x0x_network.py.
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from x0x_network import (
        NETWORKS as _X0X_NETWORKS,
        select_network as _x0x_select,
        banner as _x0x_banner,
    )
    parser.add_argument("--network", choices=["test", "prod"], default="test",
                        help="Which fleet to target. Default 'test' (isolated testnet "
                             "on UDP 6483/TCP 13600). Pass 'prod' to target the "
                             "production fleet (5483/12600 — REAL USERS, 5s Ctrl-C "
                             "window before action).")
    parser.add_argument("--tokens-file", default=None,
                        help="override tokens file (default: derived from --network)")
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
    parser.add_argument("--allow-netem", action="store_true",
                        help="enable destructive high_rtt_peer netem scenario")
    parser.add_argument("--target-node", choices=NODES_DEFAULT, default=None,
                        help="high_rtt_peer: explicit non-anchor node to slow")
    parser.add_argument("--netem-iface", default=None,
                        help="high_rtt_peer: interface to shape (default: detected)")
    parser.add_argument("--netem-secs", type=int, default=180,
                        help="high_rtt_peer: netem active window (default 180)")
    parser.add_argument("--netem-heal-secs", type=int, default=150,
                        help="high_rtt_peer: post-cleanup recovery window (default 150)")
    parser.add_argument("--netem-delay-ms", type=int, default=1500,
                        help="high_rtt_peer: netem delay in ms (default 1500)")
    parser.add_argument("--netem-jitter-ms", type=int, default=200,
                        help="high_rtt_peer: netem jitter in ms (default 200)")
    parser.add_argument("--netem-distribution", default="normal",
                        help="high_rtt_peer: netem delay distribution (default normal)")
    parser.add_argument("--allow-iptables", action="store_true",
                        help="enable destructive partition_recovery iptables scenario")
    parser.add_argument("--partition-pair", default="sfo,sydney",
                        help="partition_recovery: non-anchor pair a,b (default sfo,sydney)")
    parser.add_argument("--block-secs", type=int, default=60,
                        help="partition_recovery: partition duration (default 60)")
    parser.add_argument("--heal-secs", type=int, default=90,
                        help="partition_recovery: heal wait duration (default 90)")
    parser.add_argument("--recovery-poll-secs", type=int, default=10,
                        help="partition_recovery: recovery polling interval (default 10)")
    parser.add_argument("--partition-udp-port", type=int, default=None,
                        help="partition_recovery: UDP source port to block (default: network gossip port — 5483 prod, 6483 test)")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    repo_root = Path(__file__).resolve().parents[1]
    # Network selection happens BEFORE any tokens / endpoint work so the
    # banner (and the 5s prod Ctrl-C window) fire before SSH or curl.
    _net = _x0x_select(args)
    _x0x_banner(_net)
    # Patch the module-level API port + gossip port that the rest of this
    # file uses (the hot-path f-strings reference X0X_API_PORT / X0X_GOSSIP).
    global X0X_API_PORT, X0X_GOSSIP_PORT
    X0X_API_PORT = _net.api_port
    X0X_GOSSIP_PORT = _net.gossip_port
    if args.tokens_file is None:
        tokens_path = _net.token_file
    else:
        tokens_path = (repo_root / args.tokens_file).resolve()
    nodes = load_tokens(tokens_path, var_prefix=_net.var_prefix)
    # Phase A is an all-directed-pairs DM matrix over the active node set, so
    # the expected pair count is n*(n-1), not a fixed 30. Derive the gate from
    # the live token set so excluding a node (e.g. a degraded APAC host) scales
    # the bar correctly instead of failing every window by construction. With
    # the full 6-node bootstrap matrix this is 30 (unchanged); a 5-node set is
    # 20. This corrects the denominator for the actual matrix size — it is not
    # a relaxation of the per-pair delivery requirement.
    expected_phase_a_pairs = len(nodes) * (len(nodes) - 1)
    GATES[args.gate]["min_phase_a_pairs"] = expected_phase_a_pairs
    LOG.info(
        "phase A gate scaled to %d directed pairs for %d-node set: %s",
        expected_phase_a_pairs, len(nodes), ",".join(sorted(nodes)),
    )
    if args.partition_udp_port is None:
        args.partition_udp_port = _net.gossip_port
    if args.anchor not in nodes:
        LOG.error("anchor %s not in tokens file %s (network=%s, expected prefix=%s)",
                  args.anchor, tokens_path, _net.name, _net.var_prefix)
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
        scen_ack_diag_dir = proof_dir / "diagnostics_ack" / sname
        scen_ack_diag_dir.mkdir(parents=True, exist_ok=True)
        scen_conn_diag_dir = proof_dir / "diagnostics_connectivity" / sname
        scen_conn_diag_dir.mkdir(parents=True, exist_ok=True)
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
            try:
                ack_diag = fetch_ack_diagnostics(node, ip, token)
                (scen_ack_diag_dir / f"{node}-pre.json").write_text(
                    json.dumps(ack_diag, indent=2)
                )
            except Exception as e:
                LOG.warning("pre ACK snapshot %s failed: %s", node, e)
            try:
                conn_diag = fetch_connectivity_diagnostics(node, ip, token)
                (scen_conn_diag_dir / f"{node}-pre.json").write_text(
                    json.dumps(conn_diag, indent=2)
                )
                pre_counters[node].update(extract_connectivity_scalars(conn_diag))
                pre_counters[node]["diagnostics_connectivity_pre_fetched"] = True
            except Exception as e:
                LOG.warning("pre connectivity snapshot %s failed: %s", node, e)
                pre_counters[node]["diagnostics_connectivity_pre_fetched"] = False

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
            try:
                ack_diag = fetch_ack_diagnostics(node, ip, token)
                (scen_ack_diag_dir / f"{node}-post.json").write_text(
                    json.dumps(ack_diag, indent=2)
                )
            except Exception as e:
                LOG.warning("post ACK snapshot %s failed: %s", node, e)
            try:
                conn_diag = fetch_connectivity_diagnostics(node, ip, token)
                (scen_conn_diag_dir / f"{node}-post.json").write_text(
                    json.dumps(conn_diag, indent=2)
                )
                post_counters[node].update(extract_connectivity_scalars(conn_diag))
                post_counters[node]["diagnostics_connectivity_post_fetched"] = True
            except Exception as e:
                LOG.warning("post connectivity snapshot %s failed: %s", node, e)
                post_counters[node]["diagnostics_connectivity_post_fetched"] = False

        deltas: Dict[str, Dict[str, int]] = {}
        for node in nodes:
            pre = pre_counters.get(node, {})
            post = post_counters.get(node, {})
            known_pairs = max(
                int(pre.get("peer_scores_total", 0)),
                int(post.get("peer_scores_total", 0)),
            )
            pre["known_peer_topic_pairs"] = known_pairs
            post["known_peer_topic_pairs"] = known_pairs
            d = diff_counters(pre_counters.get(node, {}), post_counters.get(node, {}))
            d["diagnostics_connectivity_pre_fetched"] = pre.get(
                "diagnostics_connectivity_pre_fetched", False
            )
            d["diagnostics_connectivity_post_fetched"] = post.get(
                "diagnostics_connectivity_post_fetched", False
            )
            d["_post"] = post  # smuggle for reports
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
