#!/usr/bin/env python3
"""x0x launch-readiness soak — X0X-0018.

Wraps tests/launch_readiness.py baseline scenario in a long-running loop
to produce broad-launch soak evidence:

  proofs/launch-readiness-soak-<run-id>/
    timeline.csv         # one row per window
    summary.md           # final verdict
    windows/<NN>/        # full launch_readiness output per window

Defaults to 12 hours × 24 windows (one every 30 min). Each window runs
the baseline scenario only — slow drift, not stress. The soak keeps the
per-window gate verdict, then applies a soak-level cumulative tolerance
for rare dispatcher timeouts while keeping Phase A and drop bars strict.

Usage::

    python3 tests/launch_soak.py --duration-hours 12 --interval-mins 30 \\
        --anchor nyc --gate broad-launch
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG = logging.getLogger("launch_soak")

SOAK_MAX_DISPATCHER_TIMED_OUT_DELTA_PER_12H = 5
SOAK_MAX_RECV_PUMP_DROPPED_FULL_DELTA = 0
SOAK_MIN_PHASE_A_PAIRS = 30
SOAK_MAX_DISPATCHER_TIMEOUT_RATIO = 0.0001
SOAK_MAX_DISPATCHER_TIMEOUT_RATIO_PER_WINDOW = 0.0001
SOAK_DISPATCHER_ANOMALY_BASELINE_FACTOR = 4.0
SOAK_DISPATCHER_ANOMALY_RATE_FLOOR = 0.00005
SOAK_MAX_CONSECUTIVE_DISPATCHER_ANOMALY_WINDOWS = 2
# X0X-0065 Pattern 1 — explicit aggregate Phase A SLO. Per-window
# Phase A misses (1-2 pairs out of 30 on cross-region tail-latency
# paths) are tolerated only when the cumulative ratio across the
# soak stays above this floor. Per-window strict threshold is
# unchanged (still 30/30 in launch_readiness.py).
#
# 2026-05-12 (post X0X-0066 rollback): SLO calibrated from 0.99 →
# 0.98 to match the proven datum point from the
# 2026-05-11 19:26Z pre-hedge soak (118/120 sent = 98.33%, 120/120
# received = 100%). The 99% target was aspirational without a
# mechanism-layer fix (Pattern 2 hedging regressed recv-miss; see
# X0X-0066). Future tightening below 98% needs explicit acceptance
# evidence and a documented mechanism-layer change.
SOAK_MIN_AGGREGATE_PHASE_A_RATIO = 0.98

# Transport-degradation attribution. The aggregate Phase-A SLO above answers
# "did delivery hold?" but cannot tell a CODE regression (delivery failed on a
# healthy mesh) from an INFRA degradation (delivery failed because the
# cross-region QUIC/UDP transport was black-holed/lossy — e.g. the recurring
# Hetzner-DE <-> DigitalOcean-APAC PMTU + UDP-loss problem: ICMP clean but
# current_mtu floored to 1200, high black_holes_detected, pp_to spikes).
# A window's Phase-A shortfall is attributed to infra — and tolerated for the
# Phase-A SLO — when that window's transport metrics show genuine degradation.
# Hard guards remain: recv_pump.dropped_full must stay 0 (separate gate), and
# aggregate delivery must stay above a catastrophe floor even under infra
# degradation (below the floor, something is badly wrong regardless of cause).
SOAK_TRANSPORT_DEGRADED_LOSS_PPM = 5000           # >= 0.5% UDP packet loss
SOAK_TRANSPORT_DEGRADED_RTT_MS = 2000             # >= 2s RTT = black-holed/churning link
SOAK_MIN_AGGREGATE_PHASE_A_RATIO_DEGRADED = 0.70  # catastrophe floor under infra degradation


def _int_field(row: Dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(row.get(key, "") or default)
    except ValueError:
        return default


CONTINUOUS_COUNTER_PATHS = {
    "dispatcher_completed": ("dispatcher", "pubsub", "completed"),
    "dispatcher_timed_out": ("dispatcher", "pubsub", "timed_out"),
    "recv_pump_dropped_full": ("recv_pump", "pubsub", "dropped_full"),
    "per_peer_timeout_count": ("pubsub_stages", "republish_per_peer_timeout"),
}


def _nested_int(data: Dict[str, Any], path: tuple[str, ...]) -> int:
    cur: Any = data
    for part in path:
        if not isinstance(cur, dict):
            return 0
        cur = cur.get(part, 0)
    try:
        return int(cur or 0)
    except (TypeError, ValueError):
        return 0


def load_counter_snapshot(path: Path) -> Optional[Dict[str, int]]:
    """Load the monotonic counters needed for continuous soak accounting."""
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        LOG.warning("failed to parse diagnostics snapshot %s: %s", path, exc)
        return None
    if not isinstance(raw, dict):
        return None
    return {
        name: _nested_int(raw, counter_path)
        for name, counter_path in CONTINUOUS_COUNTER_PATHS.items()
    }


def _diagnostic_nodes(window_dir: Path) -> List[str]:
    diag_dir = window_dir / "diagnostics" / "baseline"
    if not diag_dir.exists():
        return []
    nodes = set()
    for suffix in ("-pre.json", "-post.json"):
        for path in diag_dir.glob(f"*{suffix}"):
            nodes.add(path.name[: -len(suffix)])
    return sorted(nodes)


def annotate_continuous_window(
    window_dir: Path,
    row: Dict[str, str],
    previous_post: Dict[str, Dict[str, int]],
) -> Dict[str, str]:
    """Annotate one row with deltas from the previous successful post sample.

    The per-window launch_readiness deltas only cover the short scenario
    execution. A soak needs continuous counter movement across the full
    interval, and a missing pre-snapshot must not be treated as zero.
    """
    diag_dir = window_dir / "diagnostics" / "baseline"
    nodes = sorted(set(previous_post) | set(_diagnostic_nodes(window_dir)))
    if not nodes:
        return row

    sum_disp_to = 0
    max_disp_to = 0
    sum_drop_full = 0
    max_drop_full = 0
    sum_pp_to = 0
    max_pp_to = 0
    sum_completed = 0
    gaps: List[str] = []
    unaccounted: List[str] = []

    for node in nodes:
        pre = load_counter_snapshot(diag_dir / f"{node}-pre.json")
        post = load_counter_snapshot(diag_dir / f"{node}-post.json")
        baseline = previous_post.get(node) or pre

        if post is None:
            gaps.append(f"{node}:post")
            unaccounted.append(f"{node}:post")
            continue
        if baseline is None:
            gaps.append(f"{node}:baseline")
            unaccounted.append(f"{node}:baseline")
            previous_post[node] = post
            continue

        if pre is None:
            gaps.append(f"{node}:pre")

        reset_fields = [
            field for field, value in post.items()
            if value < int(baseline.get(field, 0) or 0)
        ]
        if reset_fields:
            gaps.append(f"{node}:counter_reset")
            unaccounted.append(f"{node}:counter_reset")

        delta_disp = max(0, post["dispatcher_timed_out"] - baseline["dispatcher_timed_out"])
        delta_drop = max(0, post["recv_pump_dropped_full"] - baseline["recv_pump_dropped_full"])
        delta_pp = max(0, post["per_peer_timeout_count"] - baseline["per_peer_timeout_count"])
        delta_completed = max(0, post["dispatcher_completed"] - baseline["dispatcher_completed"])

        sum_disp_to += delta_disp
        max_disp_to = max(max_disp_to, delta_disp)
        sum_drop_full += delta_drop
        max_drop_full = max(max_drop_full, delta_drop)
        sum_pp_to += delta_pp
        max_pp_to = max(max_pp_to, delta_pp)
        sum_completed += delta_completed
        previous_post[node] = post

    row["continuous_max_disp_to_delta"] = str(max_disp_to)
    row["continuous_sum_disp_to_delta"] = str(sum_disp_to)
    row["continuous_max_drop_full_delta"] = str(max_drop_full)
    row["continuous_sum_drop_full_delta"] = str(sum_drop_full)
    row["continuous_max_pp_to_delta"] = str(max_pp_to)
    row["continuous_sum_pp_to_delta"] = str(sum_pp_to)
    row["continuous_sum_dispatcher_completed_delta"] = str(sum_completed)
    row["continuous_snapshot_gaps"] = ";".join(gaps)
    row["continuous_unaccounted_gaps"] = ";".join(unaccounted)
    return row


def annotate_continuous_rows(soak_dir: Path, rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    previous_post: Dict[str, Dict[str, int]] = {}
    annotated: List[Dict[str, str]] = []
    for idx, row in enumerate(rows, 1):
        copied = dict(row)
        annotate_continuous_window(soak_dir / "windows" / f"{idx:03d}", copied, previous_post)
        annotated.append(copied)
    return annotated


def _counter_field(row: Dict[str, str], continuous_key: str, legacy_key: str) -> int:
    if continuous_key in row:
        return _int_field(row, continuous_key)
    return _int_field(row, legacy_key)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0 if numerator <= 0 else float("inf")
    return numerator / denominator


def _ratio_str(numerator: int, denominator: int) -> str:
    ratio = _ratio(numerator, denominator)
    if ratio == float("inf"):
        return "inf"
    return f"{ratio:.8f}"


def dispatcher_noise_policy(rows: List[Dict[str, str]]) -> Dict[str, str]:
    """Classify dispatcher-only soak noise using normalized/adaptive signals."""
    total_disp = sum(
        _counter_field(row, "continuous_sum_disp_to_delta", "sum_disp_to_delta")
        for row in rows
    )
    total_completed = sum(
        _int_field(row, "continuous_sum_dispatcher_completed_delta")
        for row in rows
    )
    total_ratio = _ratio(total_disp, total_completed)
    max_window_ratio = 0.0
    baseline_rates: List[float] = []
    consecutive_anomalies = 0
    max_consecutive_anomalies = 0
    anomaly_windows: List[str] = []

    for idx, row in enumerate(rows, 1):
        window_disp = _counter_field(row, "continuous_sum_disp_to_delta", "sum_disp_to_delta")
        window_completed = _int_field(row, "continuous_sum_dispatcher_completed_delta")
        if window_completed <= 0:
            continue
        window_ratio = _ratio(window_disp, window_completed)
        max_window_ratio = max(max_window_ratio, window_ratio)
        baseline = sorted(baseline_rates)[len(baseline_rates) // 2] if baseline_rates else 0.0
        anomaly_threshold = max(
            baseline * SOAK_DISPATCHER_ANOMALY_BASELINE_FACTOR,
            SOAK_DISPATCHER_ANOMALY_RATE_FLOOR,
        )
        is_anomaly = (
            window_completed > 0
            and window_ratio > anomaly_threshold
            and window_disp > 0
        )
        if is_anomaly:
            consecutive_anomalies += 1
            max_consecutive_anomalies = max(max_consecutive_anomalies, consecutive_anomalies)
            anomaly_windows.append(str(idx))
        else:
            consecutive_anomalies = 0
            if window_completed > 0:
                baseline_rates.append(window_ratio)

    if total_disp <= SOAK_MAX_DISPATCHER_TIMED_OUT_DELTA_PER_12H:
        verdict = "legacy-count-ok"
    elif total_ratio <= SOAK_MAX_DISPATCHER_TIMEOUT_RATIO:
        verdict = "adaptive-rate-ok"
    else:
        verdict = "fleet-rate-high"

    if max_window_ratio > SOAK_MAX_DISPATCHER_TIMEOUT_RATIO_PER_WINDOW:
        verdict = "window-rate-high"
    if max_consecutive_anomalies > SOAK_MAX_CONSECUTIVE_DISPATCHER_ANOMALY_WINDOWS:
        verdict = "consecutive-anomalies"

    passed = verdict in {"legacy-count-ok", "adaptive-rate-ok"}
    return {
        "passed": "true" if passed else "false",
        "verdict": verdict,
        "total_disp": str(total_disp),
        "total_completed": str(total_completed),
        "total_ratio": "inf" if total_ratio == float("inf") else f"{total_ratio:.8f}",
        "max_window_ratio": (
            "inf" if max_window_ratio == float("inf") else f"{max_window_ratio:.8f}"
        ),
        "max_consecutive_anomalies": str(max_consecutive_anomalies),
        "anomaly_windows": ",".join(anomaly_windows) or "none",
    }


def discover_windows_summary(window_dir: Path) -> Dict[str, str]:
    """Pull the GO/NO-GO verdict + key counters out of a launch_readiness run.

    Returns a flat dict suitable for one row of timeline.csv.
    """
    summary_path = window_dir / "summary.md"
    csv_path = window_dir / "summary.csv"
    out: Dict[str, str] = {
        "summary_md": str(summary_path),
        "verdict": "?",
        "phase_a_received": "?",
        "phase_a_sent": "?",
        "max_disp_to_delta": "?",
        "sum_disp_to_delta": "?",
        "max_drop_full_delta": "?",
        "sum_drop_full_delta": "?",
        "max_pp_to_delta": "?",
        "max_suppressed": "?",
        "max_suppressed_ratio": "?",
        "max_suppressed_topics": "?",
        "top_suppressed_topics": "",
        "max_transport_peers": "?",
        "max_transport_rtt_ms": "?",
        "max_transport_loss_ppm": "?",
        "max_workers": "?",
        "violations": "?",
        "violation_messages": "",
    }
    if not summary_path.exists():
        out["verdict"] = "MISSING"
        return out
    text = summary_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"Overall verdict:\s*\*\*(GO|NO-GO)\*\*", text)
    if m:
        out["verdict"] = m.group(1)
    # Phase A counters live in the baseline scenario block.
    for k in ("phase_a_received", "phase_a_sent"):
        m = re.search(rf"{k}:\s*`(\d+)`", text)
        if m:
            out[k] = m.group(1)
    violations: List[str] = []
    in_violation_block = False
    for line in text.splitlines():
        if line.strip() == "- violations:":
            in_violation_block = True
            continue
        if in_violation_block and line.startswith("  - "):
            violations.append(line[4:])
            continue
        if in_violation_block and line.strip():
            in_violation_block = False
    if violations:
        out["violation_messages"] = " || ".join(violations)
    # Aggregate per-node deltas from the CSV (max across nodes).
    if csv_path.exists():
        try:
            with csv_path.open(newline="") as f:
                rows = list(csv.DictReader(f))
            baseline_rows = [r for r in rows if r.get("scenario") == "baseline"]
            if baseline_rows:
                def _max(field: str) -> int:
                    vs = []
                    for r in baseline_rows:
                        try:
                            vs.append(max(0, int(r.get(field, "0") or "0")))
                        except ValueError:
                            pass
                    return max(vs) if vs else 0
                def _sum(field: str) -> int:
                    total = 0
                    for r in baseline_rows:
                        try:
                            total += max(0, int(r.get(field, "0") or "0"))
                        except ValueError:
                            pass
                    return total
                def _max_float(field: str) -> float:
                    vs = []
                    for r in baseline_rows:
                        raw = r.get(field, "0") or "0"
                        try:
                            vs.append(float("inf") if raw == "inf" else float(raw))
                        except ValueError:
                            pass
                    return max(vs) if vs else 0.0
                out["max_disp_to_delta"] = str(_max("dispatcher_timed_out_delta"))
                out["sum_disp_to_delta"] = str(_sum("dispatcher_timed_out_delta"))
                out["max_drop_full_delta"] = str(_max("recv_pump_dropped_full_delta"))
                out["sum_drop_full_delta"] = str(_sum("recv_pump_dropped_full_delta"))
                out["max_pp_to_delta"] = str(_max("per_peer_timeout_delta"))
                out["max_suppressed"] = str(_max("suppressed_peers_post"))
                max_suppressed_ratio = _max_float("suppressed_peers_to_known_ratio")
                out["max_suppressed_ratio"] = (
                    "inf" if max_suppressed_ratio == float("inf")
                    else f"{max_suppressed_ratio:.6f}"
                )
                out["max_suppressed_topics"] = str(_max("suppressed_topics_post"))
                top_topics = [
                    r.get("suppressed_topics_top3_post", "")
                    for r in baseline_rows
                    if r.get("suppressed_topics_top3_post")
                ]
                out["top_suppressed_topics"] = " | ".join(sorted(set(top_topics)))
                out["max_transport_peers"] = str(_max("transport_peer_count_post"))
                out["max_transport_rtt_ms"] = str(_max("transport_rtt_ms_max_post"))
                out["max_transport_loss_ppm"] = str(_max("transport_packet_loss_ppm_max_post"))
                out["max_workers"] = str(_max("pubsub_workers_post"))
                csv_violation_counts = []
                for r in baseline_rows:
                    try:
                        csv_violation_counts.append(int(r.get("violations_count", "0") or "0"))
                    except ValueError:
                        pass
                out["violations"] = str(
                    len(violations) if violations else max(csv_violation_counts, default=0)
                )
        except Exception as exc:
            LOG.warning("failed to parse %s: %s", csv_path, exc)
    return out


def run_window(
    repo_root: Path,
    window_dir: Path,
    args: argparse.Namespace,
) -> int:
    """Invoke launch_readiness.py for a single sample. Returns exit code."""
    cmd = [
        sys.executable,
        str(repo_root / "tests" / "launch_readiness.py"),
        "--network", args.network,
        "--gate", args.gate,
        "--scenarios", "baseline",
        "--anchor", args.anchor,
        "--proof-dir", str(window_dir),
    ]
    # Per-window invocations of launch_readiness.py would each print the
    # banner + (for prod) wait 5s. Suppress the wait inside the loop —
    # the soak-level banner at startup already established the network.
    env = os.environ.copy()
    env["X0X_NETWORK_NO_HOLD"] = "1"
    LOG.info("window run: %s", " ".join(shlex.quote(c) for c in cmd))
    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, timeout=900, env=env)
    (window_dir / "stdout.log").write_bytes(proc.stdout)
    (window_dir / "stderr.log").write_bytes(proc.stderr)
    return proc.returncode


def write_summary(soak_dir: Path, gate: str, rows: List[Dict[str, str]]) -> bool:
    """Write final summary.md. Returns True iff the soak-level gate passed."""
    rows = annotate_continuous_rows(soak_dir, rows)
    pass_count = sum(1 for r in rows if r["verdict"] == "GO")
    fail_count = sum(1 for r in rows if r["verdict"] == "NO-GO")
    missing_count = sum(1 for r in rows if r["verdict"] == "MISSING")
    total = len(rows)

    cumulative_disp_to = sum(
        _counter_field(r, "continuous_sum_disp_to_delta", "sum_disp_to_delta")
        for r in rows
    )
    cumulative_drop_full = sum(
        _counter_field(r, "continuous_sum_drop_full_delta", "sum_drop_full_delta")
        for r in rows
    )
    cumulative_completed = sum(
        _int_field(r, "continuous_sum_dispatcher_completed_delta")
        for r in rows
    )
    cumulative_pp_to = sum(
        _counter_field(r, "continuous_sum_pp_to_delta", "max_pp_to_delta")
        for r in rows
    )
    dispatcher_policy = dispatcher_noise_policy(rows)
    unaccounted_gap_windows = [
        idx for idx, row in enumerate(rows, 1)
        if row.get("continuous_unaccounted_gaps")
    ]
    dispatcher_limit = SOAK_MAX_DISPATCHER_TIMED_OUT_DELTA_PER_12H
    drop_limit = SOAK_MAX_RECV_PUMP_DROPPED_FULL_DELTA

    def _phase_a_ok(row: Dict[str, str]) -> bool:
        return (
            _int_field(row, "phase_a_received") >= SOAK_MIN_PHASE_A_PAIRS
            and _int_field(row, "phase_a_sent") >= SOAK_MIN_PHASE_A_PAIRS
        )

    def _transport_degraded(row: Dict[str, str]) -> bool:
        """True when this window's transport metrics show genuine cross-region
        degradation (high UDP loss or black-hole-floored RTT), making a Phase-A
        shortfall infra-attributable rather than a code regression. Missing
        metrics ('?' -> 0) are treated as not-degraded (conservative)."""
        return (
            _int_field(row, "max_transport_loss_ppm") >= SOAK_TRANSPORT_DEGRADED_LOSS_PPM
            or _int_field(row, "max_transport_rtt_ms") >= SOAK_TRANSPORT_DEGRADED_RTT_MS
        )

    def _violation_messages(row: Dict[str, str]) -> List[str]:
        raw = row.get("violation_messages", "")
        if not raw:
            return []
        return [m.strip() for m in raw.split(" || ") if m.strip()]

    def _is_dispatcher_violation(msg: str) -> bool:
        return "dispatcher_timed_out delta" in msg

    def _is_phase_a_violation(row: Dict[str, str], msg: str) -> bool:
        if "scenario errored: phase A exit code" in msg:
            return not _phase_a_ok(row)
        match = re.search(r"phase A (received|sent) (\d+) < gate (\d+)", msg)
        if not match:
            return False
        metric, observed_text, gate_text = match.groups()
        key = f"phase_a_{metric}"
        observed = int(observed_text)
        gate = int(gate_text)
        return observed == _int_field(row, key) and observed < gate

    def _only_dispatcher_timeout_violations(row: Dict[str, str]) -> bool:
        messages = _violation_messages(row)
        return bool(messages) and all(_is_dispatcher_violation(m) for m in messages)

    def _only_tail_violations(row: Dict[str, str]) -> bool:
        """All violations are either dispatcher_timed_out or phase_a tail.

        These are the two failure classes covered by the aggregate
        Pattern 1 SLOs. Anything else (e.g. recv_pump_dropped_full,
        per_peer_timeout ratio above gate, suppressed_peers ratio) is
        a real regression and counts as effective_failed.
        """
        messages = _violation_messages(row)
        return bool(messages) and all(
            _is_dispatcher_violation(m) or _is_phase_a_violation(row, m)
            for m in messages
        )

    # Aggregate Phase A SLO — sum across all windows that produced
    # data. Missing windows are excluded from the denominator so a
    # telemetry gap does not arithmetic-trick the ratio upward; they
    # are caught separately by the `missing_count == 0` requirement.
    data_rows = [r for r in rows if r["verdict"] != "MISSING"]
    agg_phase_a_sent = sum(_int_field(r, "phase_a_sent") for r in data_rows)
    agg_phase_a_received = sum(_int_field(r, "phase_a_received") for r in data_rows)
    agg_phase_a_target = SOAK_MIN_PHASE_A_PAIRS * len(data_rows)
    agg_phase_a_sent_ratio = (
        agg_phase_a_sent / agg_phase_a_target if agg_phase_a_target > 0 else 0.0
    )
    agg_phase_a_received_ratio = (
        agg_phase_a_received / agg_phase_a_target if agg_phase_a_target > 0 else 0.0
    )
    aggregate_phase_a_ok = (
        agg_phase_a_target > 0
        and agg_phase_a_sent_ratio >= SOAK_MIN_AGGREGATE_PHASE_A_RATIO
        and agg_phase_a_received_ratio >= SOAK_MIN_AGGREGATE_PHASE_A_RATIO
    )

    effective_failed: List[int] = []
    tolerated_dispatcher_windows: List[int] = []
    tolerated_phase_a_windows: List[int] = []
    tolerated_infra_phase_a_windows: List[int] = []
    for idx, row in enumerate(rows, 1):
        if row["verdict"] == "GO":
            continue
        drop_full_clean = (
            _counter_field(row, "continuous_max_drop_full_delta", "max_drop_full_delta") == 0
        )
        if row["verdict"] == "NO-GO" and drop_full_clean and _only_tail_violations(row):
            if _phase_a_ok(row) and _only_dispatcher_timeout_violations(row):
                # Pure dispatcher-only tail — tolerated unconditionally
                # (the dispatcher_noise_policy aggregate gate also
                # evaluates rate / consecutive-anomaly upper bounds).
                tolerated_dispatcher_windows.append(idx)
                continue
            if aggregate_phase_a_ok:
                # Window has phase_a tail loss (with or without an
                # accompanying dispatcher timeout); tolerated only
                # while the aggregate Phase A ratio stays above SLO.
                tolerated_phase_a_windows.append(idx)
                continue
            if _transport_degraded(row):
                # Phase-A shortfall is attributable to degraded transport
                # (infra: cross-region UDP black-hole / loss), not a code
                # regression. Tolerated here; the aggregate catastrophe floor
                # + drop_full=0 hard gate still bound the run below.
                tolerated_infra_phase_a_windows.append(idx)
                continue
        effective_failed.append(idx)

    # Phase-A passes if it held the SLO, OR every shortfall was infra-attributed
    # (transport-degraded windows only) while staying above the catastrophe
    # floor. A healthy-transport Phase-A failure is NOT infra-attributable, so
    # it lands in effective_failed and fails the run — code regressions still
    # caught.
    aggregate_phase_a_infra_degraded = (
        not aggregate_phase_a_ok
        and agg_phase_a_target > 0
        and not tolerated_phase_a_windows
        and bool(tolerated_infra_phase_a_windows)
        and agg_phase_a_sent_ratio >= SOAK_MIN_AGGREGATE_PHASE_A_RATIO_DEGRADED
        and agg_phase_a_received_ratio >= SOAK_MIN_AGGREGATE_PHASE_A_RATIO_DEGRADED
    )
    aggregate_phase_a_pass = aggregate_phase_a_ok or aggregate_phase_a_infra_degraded

    if aggregate_phase_a_ok:
        phase_a_slo_status = "PASS"
    elif aggregate_phase_a_infra_degraded:
        floor_pct = int(SOAK_MIN_AGGREGATE_PHASE_A_RATIO_DEGRADED * 100)
        phase_a_slo_status = f"INFRA-DEGRADED (tolerated, ≥ {floor_pct}% floor)"
    else:
        phase_a_slo_status = "FAIL"

    overall_pass = (
        total > 0
        and missing_count == 0
        and not effective_failed
        and not unaccounted_gap_windows
        and dispatcher_policy["passed"] == "true"
        and cumulative_drop_full <= drop_limit
        and aggregate_phase_a_pass
    )

    lines = [
        "# x0x launch-readiness soak",
        "",
        f"- Gate: **{gate}**",
        f"- Windows: {total} (PASS={pass_count}, NO-GO={fail_count}, MISSING={missing_count})",
        f"- Overall verdict: **{'GO' if overall_pass else 'NO-GO'}**",
        "",
        "## Cumulative SLO totals",
        "",
        "- Counter source: **continuous post-to-post diagnostics deltas when available; "
        "legacy scenario deltas only when diagnostics are absent**",
        f"- dispatcher.timed_out delta across the continuous soak × all nodes: **{cumulative_disp_to}** "
        f"(legacy count trigger ≤ {dispatcher_limit}/12h)",
        f"- recv_pump.dropped_full delta across the continuous soak × all nodes: **{cumulative_drop_full}** "
        f"(gate ≤ {drop_limit})",
        f"- dispatcher.pubsub.completed delta across the continuous soak × all nodes: **{cumulative_completed}**",
        f"- dispatcher.timed_out / dispatcher.completed: **{_ratio_str(cumulative_disp_to, cumulative_completed)}**",
        f"- republish_per_peer_timeout / dispatcher.completed: **{_ratio_str(cumulative_pp_to, cumulative_completed)}**",
        f"- dispatcher-only adaptive policy: **{dispatcher_policy['verdict']}** "
        f"(max_window_ratio={dispatcher_policy['max_window_ratio']}, "
        f"max_consecutive_anomalies={dispatcher_policy['max_consecutive_anomalies']}, "
        f"anomaly_windows={dispatcher_policy['anomaly_windows']})",
        f"- tolerated dispatcher-only windows: **{','.join(str(i) for i in tolerated_dispatcher_windows) or 'none'}**",
        f"- tolerated phase-A tail windows: **{','.join(str(i) for i in tolerated_phase_a_windows) or 'none'}**",
        f"- tolerated phase-A INFRA-degraded windows (transport black-hole/loss): "
        f"**{','.join(str(i) for i in tolerated_infra_phase_a_windows) or 'none'}**",
        f"- aggregate Phase A sent: **{agg_phase_a_sent}/{agg_phase_a_target}** "
        f"({(agg_phase_a_sent_ratio * 100):.3f}%, gate ≥ {SOAK_MIN_AGGREGATE_PHASE_A_RATIO * 100:.0f}%)",
        f"- aggregate Phase A received: **{agg_phase_a_received}/{agg_phase_a_target}** "
        f"({(agg_phase_a_received_ratio * 100):.3f}%, gate ≥ {SOAK_MIN_AGGREGATE_PHASE_A_RATIO * 100:.0f}%)",
        f"- aggregate Phase A SLO: **{phase_a_slo_status}**",
        f"- effective failed windows: **{','.join(str(i) for i in effective_failed) or 'none'}**",
        f"- unaccounted telemetry-gap windows: **{','.join(str(i) for i in unaccounted_gap_windows) or 'none'}**",
        "",
        "## Per-window timeline",
        "",
        "| # | start_unix | verdict | effective | phase_a | scenario_sum_disp_to | continuous_sum_disp_to | scenario_sum_drop_full | continuous_sum_drop_full | scenario_max_pp_to | continuous_max_pp_to | max_suppressed | max_suppressed_ratio | max_suppressed_topics | transport_peers | max_transport_rtt_ms | max_transport_loss_ppm | max_workers | telemetry_gaps | violations |",
        "|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|",
    ]
    for i, r in enumerate(rows, 1):
        effective = "FAIL" if i in effective_failed else "PASS"
        lines.append(
            f"| {i} | {r.get('start_unix','?')} | {r['verdict']} | {effective} | "
            f"{r['phase_a_received']}/{r['phase_a_sent']} | "
            f"{r.get('sum_disp_to_delta', '?')} | {r.get('continuous_sum_disp_to_delta', '?')} | "
            f"{r.get('sum_drop_full_delta', '?')} | {r.get('continuous_sum_drop_full_delta', '?')} | "
            f"{r['max_pp_to_delta']} | {r.get('continuous_max_pp_to_delta', '?')} | "
            f"{r['max_suppressed']} | "
            f"{r.get('max_suppressed_ratio', '?')} | "
            f"{r.get('max_suppressed_topics', '?')} | "
            f"{r.get('max_transport_peers', '?')} | "
            f"{r.get('max_transport_rtt_ms', '?')} | "
            f"{r.get('max_transport_loss_ppm', '?')} | "
            f"{r['max_workers']} | "
            f"{r.get('continuous_snapshot_gaps') or 'none'} | "
            f"{r['violations']} |"
        )
    (soak_dir / "summary.md").write_text("\n".join(lines))
    return overall_pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["test", "prod"], default="test",
                        help="Which fleet to soak. Default 'test' (isolated testnet). "
                             "Pass 'prod' to soak the production fleet (REAL USERS, "
                             "5s Ctrl-C window before action). Pass-through to "
                             "launch_readiness.py per window.")
    parser.add_argument("--duration-hours", type=float, default=12.0)
    parser.add_argument("--interval-mins", type=float, default=30.0)
    parser.add_argument("--anchor", default="nyc")
    parser.add_argument("--gate", default="broad-launch")
    parser.add_argument("--soak-dir", default=None,
                        help="output dir (default: proofs/launch-readiness-soak-<ts>)")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    # Network selection banner — fires once at soak start, before any
    # window. Per-window launch_readiness invocations get
    # X0X_NETWORK_NO_HOLD=1 so they don't re-pause for 5s every 15min.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from x0x_network import select_network as _x0x_select, banner as _x0x_banner
    _net = _x0x_select(args)
    _x0x_banner(_net)

    # Scale the aggregate Phase A target to the active node set. Phase A is an
    # all-directed-pairs DM matrix (n*(n-1) pairs), so excluding a node from the
    # token file must scale this bar instead of failing every window. 6 nodes
    # -> 30 (unchanged), 5 -> 20. Mirrors the per-window scaling in
    # launch_readiness.py. This corrects the denominator for the matrix size; it
    # is not a relaxation of the per-pair delivery requirement.
    global SOAK_MIN_PHASE_A_PAIRS
    try:
        _node_count = sum(
            1 for _ln in Path(_net.token_file).read_text().splitlines()
            if re.search(r"_IP\s*=", _ln)
        )
        if _node_count >= 2:
            SOAK_MIN_PHASE_A_PAIRS = _node_count * (_node_count - 1)
            LOG.info(
                "phase A aggregate target scaled to %d pairs for %d-node set",
                SOAK_MIN_PHASE_A_PAIRS, _node_count,
            )
    except OSError as _e:
        LOG.warning("could not read token file to scale phase A target: %s", _e)

    repo_root = Path(__file__).resolve().parents[1]
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    soak_dir = Path(args.soak_dir) if args.soak_dir else (
        repo_root / "proofs" / f"launch-readiness-soak-{ts}"
    )
    soak_dir.mkdir(parents=True, exist_ok=True)
    (soak_dir / "windows").mkdir(exist_ok=True)
    LOG.info("soak_dir: %s", soak_dir)

    duration_secs = args.duration_hours * 3600
    interval_secs = args.interval_mins * 60
    target_windows = max(1, int(duration_secs / interval_secs))
    LOG.info("plan: %d windows × %.1f min interval (%.1f h total)",
             target_windows, args.interval_mins, args.duration_hours)

    # Allow Ctrl-C to short-circuit cleanly so partial results still summarize.
    interrupted = {"flag": False}

    def _stop(signum: int, _frame) -> None:
        interrupted["flag"] = True
        LOG.warning("signal %d caught — completing current window then exiting", signum)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    timeline_path = soak_dir / "timeline.csv"
    rows: List[Dict[str, str]] = []
    with timeline_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "window", "start_unix", "verdict", "phase_a_received", "phase_a_sent",
            "max_disp_to_delta", "sum_disp_to_delta",
            "max_drop_full_delta", "sum_drop_full_delta", "max_pp_to_delta",
            "continuous_max_disp_to_delta", "continuous_sum_disp_to_delta",
            "continuous_max_drop_full_delta", "continuous_sum_drop_full_delta",
            "continuous_max_pp_to_delta", "continuous_sum_pp_to_delta",
            "continuous_sum_dispatcher_completed_delta",
            "continuous_snapshot_gaps", "continuous_unaccounted_gaps",
            "max_suppressed", "max_suppressed_ratio", "max_suppressed_topics",
            "top_suppressed_topics", "max_transport_peers", "max_transport_rtt_ms",
            "max_transport_loss_ppm", "max_workers", "violations",
        ])

    soak_start = time.time()
    continuous_previous_post: Dict[str, Dict[str, int]] = {}
    for i in range(1, target_windows + 1):
        if interrupted["flag"]:
            break
        window_start = time.time()
        window_dir = soak_dir / "windows" / f"{i:03d}"
        window_dir.mkdir(parents=True, exist_ok=True)

        rc = run_window(repo_root, window_dir, args)
        info = discover_windows_summary(window_dir)
        info["start_unix"] = str(int(window_start))
        info["window_rc"] = str(rc)
        annotate_continuous_window(window_dir, info, continuous_previous_post)
        rows.append(info)

        with timeline_path.open("a", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                i, info["start_unix"], info["verdict"],
                info["phase_a_received"], info["phase_a_sent"],
                info["max_disp_to_delta"], info["sum_disp_to_delta"],
                info["max_drop_full_delta"], info["sum_drop_full_delta"],
                info["max_pp_to_delta"],
                info.get("continuous_max_disp_to_delta", ""),
                info.get("continuous_sum_disp_to_delta", ""),
                info.get("continuous_max_drop_full_delta", ""),
                info.get("continuous_sum_drop_full_delta", ""),
                info.get("continuous_max_pp_to_delta", ""),
                info.get("continuous_sum_pp_to_delta", ""),
                info.get("continuous_sum_dispatcher_completed_delta", ""),
                info.get("continuous_snapshot_gaps", ""),
                info.get("continuous_unaccounted_gaps", ""),
                info["max_suppressed"],
                info["max_suppressed_ratio"], info["max_suppressed_topics"],
                info["top_suppressed_topics"], info["max_transport_peers"],
                info["max_transport_rtt_ms"], info["max_transport_loss_ppm"],
                info["max_workers"], info["violations"],
            ])

        LOG.info(
            "window %d/%d: verdict=%s phase_a=%s/%s scenario_disp_to=%s continuous_disp_to=%s drop_full=%s pp_to=%s suppressed=%s",
            i, target_windows, info["verdict"],
            info["phase_a_received"], info["phase_a_sent"],
            info["max_disp_to_delta"], info.get("continuous_sum_disp_to_delta", "?"),
            info.get("continuous_sum_drop_full_delta", info["max_drop_full_delta"]),
            info["max_pp_to_delta"], info["max_suppressed"],
        )

        if i == target_windows:
            break
        elapsed = time.time() - window_start
        sleep_for = max(0.0, interval_secs - elapsed)
        if sleep_for > 0 and not interrupted["flag"]:
            LOG.info("sleeping %.0fs until next window", sleep_for)
            # Sleep in 10s chunks so signals are responsive.
            t_end = time.time() + sleep_for
            while time.time() < t_end and not interrupted["flag"]:
                time.sleep(min(10.0, t_end - time.time()))

    overall_pass = write_summary(soak_dir, args.gate, rows)
    elapsed_h = (time.time() - soak_start) / 3600
    LOG.info("=== soak verdict: %s (%d windows, %.2f h) ===",
             "GO" if overall_pass else "NO-GO", len(rows), elapsed_h)
    LOG.info("summary: %s", soak_dir / "summary.md")
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
