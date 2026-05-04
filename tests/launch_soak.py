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
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

LOG = logging.getLogger("launch_soak")

SOAK_MAX_DISPATCHER_TIMED_OUT_DELTA_PER_12H = 5
SOAK_MAX_RECV_PUMP_DROPPED_FULL_DELTA = 0
SOAK_MIN_PHASE_A_PAIRS = 30


def _int_field(row: Dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(row.get(key, "") or default)
    except ValueError:
        return default


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
                            vs.append(int(r.get(field, "0") or "0"))
                        except ValueError:
                            pass
                    return max(vs) if vs else 0
                def _sum(field: str) -> int:
                    total = 0
                    for r in baseline_rows:
                        try:
                            total += int(r.get(field, "0") or "0")
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
                out["max_workers"] = str(_max("pubsub_workers_post"))
                out["violations"] = str(sum(int(r.get("violations_count", "0")) for r in baseline_rows))
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
        "--gate", args.gate,
        "--scenarios", "baseline",
        "--anchor", args.anchor,
        "--proof-dir", str(window_dir),
    ]
    LOG.info("window run: %s", " ".join(shlex.quote(c) for c in cmd))
    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, timeout=900)
    (window_dir / "stdout.log").write_bytes(proc.stdout)
    (window_dir / "stderr.log").write_bytes(proc.stderr)
    return proc.returncode


def write_summary(soak_dir: Path, gate: str, rows: List[Dict[str, str]]) -> bool:
    """Write final summary.md. Returns True iff the soak-level gate passed."""
    pass_count = sum(1 for r in rows if r["verdict"] == "GO")
    fail_count = sum(1 for r in rows if r["verdict"] == "NO-GO")
    missing_count = sum(1 for r in rows if r["verdict"] == "MISSING")
    total = len(rows)

    cumulative_disp_to = sum(
        _int_field(r, "sum_disp_to_delta", _int_field(r, "max_disp_to_delta"))
        for r in rows
    )
    cumulative_drop_full = sum(
        _int_field(r, "sum_drop_full_delta", _int_field(r, "max_drop_full_delta"))
        for r in rows
    )
    dispatcher_limit = SOAK_MAX_DISPATCHER_TIMED_OUT_DELTA_PER_12H
    drop_limit = SOAK_MAX_RECV_PUMP_DROPPED_FULL_DELTA

    def _phase_a_ok(row: Dict[str, str]) -> bool:
        return (
            _int_field(row, "phase_a_received") >= SOAK_MIN_PHASE_A_PAIRS
            and _int_field(row, "phase_a_sent") >= SOAK_MIN_PHASE_A_PAIRS
        )

    def _only_dispatcher_timeout_violations(row: Dict[str, str]) -> bool:
        raw = row.get("violation_messages", "")
        if not raw:
            return False
        messages = [m.strip() for m in raw.split(" || ") if m.strip()]
        return bool(messages) and all("dispatcher_timed_out delta" in m for m in messages)

    effective_failed: List[int] = []
    tolerated_dispatcher_windows: List[int] = []
    for idx, row in enumerate(rows, 1):
        if row["verdict"] == "GO":
            continue
        if (
            row["verdict"] == "NO-GO"
            and _phase_a_ok(row)
            and _int_field(row, "max_drop_full_delta") == 0
            and _only_dispatcher_timeout_violations(row)
        ):
            tolerated_dispatcher_windows.append(idx)
            continue
        effective_failed.append(idx)

    overall_pass = (
        total > 0
        and missing_count == 0
        and not effective_failed
        and cumulative_disp_to <= dispatcher_limit
        and cumulative_drop_full <= drop_limit
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
        f"- dispatcher.timed_out delta across all windows × all nodes: **{cumulative_disp_to}** "
        f"(gate ≤ {dispatcher_limit}/12h)",
        f"- recv_pump.dropped_full delta across all windows × all nodes: **{cumulative_drop_full}** "
        f"(gate ≤ {drop_limit})",
        f"- tolerated dispatcher-only windows: **{','.join(str(i) for i in tolerated_dispatcher_windows) or 'none'}**",
        f"- effective failed windows: **{','.join(str(i) for i in effective_failed) or 'none'}**",
        "",
        "## Per-window timeline",
        "",
        "| # | start_unix | verdict | effective | phase_a | max_disp_to | sum_disp_to | max_drop_full | sum_drop_full | max_pp_to | max_suppressed | max_suppressed_ratio | max_workers | violations |",
        "|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for i, r in enumerate(rows, 1):
        effective = "FAIL" if i in effective_failed else "PASS"
        lines.append(
            f"| {i} | {r.get('start_unix','?')} | {r['verdict']} | {effective} | "
            f"{r['phase_a_received']}/{r['phase_a_sent']} | "
            f"{r['max_disp_to_delta']} | {r.get('sum_disp_to_delta', '?')} | "
            f"{r['max_drop_full_delta']} | {r.get('sum_drop_full_delta', '?')} | "
            f"{r['max_pp_to_delta']} | {r['max_suppressed']} | "
            f"{r.get('max_suppressed_ratio', '?')} | {r['max_workers']} | "
            f"{r['violations']} |"
        )
    (soak_dir / "summary.md").write_text("\n".join(lines))
    return overall_pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
            "max_suppressed", "max_suppressed_ratio", "max_workers", "violations",
        ])

    soak_start = time.time()
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
        rows.append(info)

        with timeline_path.open("a", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                i, info["start_unix"], info["verdict"],
                info["phase_a_received"], info["phase_a_sent"],
                info["max_disp_to_delta"], info["sum_disp_to_delta"],
                info["max_drop_full_delta"], info["sum_drop_full_delta"],
                info["max_pp_to_delta"], info["max_suppressed"],
                info["max_suppressed_ratio"], info["max_workers"], info["violations"],
            ])

        LOG.info(
            "window %d/%d: verdict=%s phase_a=%s/%s disp_to=%s drop_full=%s pp_to=%s suppressed=%s",
            i, target_windows, info["verdict"],
            info["phase_a_received"], info["phase_a_sent"],
            info["max_disp_to_delta"], info["max_drop_full_delta"],
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
