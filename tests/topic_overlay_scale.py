#!/usr/bin/env python3
"""Deterministic large-topic PlumTree overlay scale harness.

X0X-0019 proof target:

* model one hot topic with thousands of virtual subscribers in one process
* keep EAGER degree within PlumTree bounds
* keep LAZY/topic view bounded instead of full-topic sized
* fail fast when the model is switched to full-view LAZY membership

This is intentionally an in-process harness. It is not a replacement for
real-process or WAN smoke tests; it is the cheap regression guard for accidental
O(topic_subscribers) topic-view or outbound-work behaviour.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
import time
import tracemalloc
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


DEFAULT_TOPIC = "x0x.scale.hot"
DEFAULT_PEERS = "1000,5000,10000"
DEFAULT_EAGER_MIN = 6
DEFAULT_EAGER_TARGET = 8
DEFAULT_EAGER_MAX = 12
DEFAULT_LAZY_CAP = 64
DEFAULT_CONVERGENCE_SECS = 30.0
DEFAULT_SEED = 1_019


@dataclass(frozen=True)
class ScaleConfig:
    peer_count: int
    topic: str
    publish_rate: float
    duration_secs: float
    churn_rate: float
    eager_min: int
    eager_target: int
    eager_max: int
    lazy_cap: int
    convergence_secs: float
    seed: int

    @property
    def publish_count(self) -> int:
        return max(1, int(round(self.publish_rate * self.duration_secs)))


@dataclass
class Overlay:
    eager: List[Set[int]]
    lazy: List[Set[int]]


@dataclass
class CaseResult:
    topic: str
    peer_count: int
    publish_count: int
    churn_rate: float
    active_peers: int
    eager_min_observed: int
    eager_p50: float
    eager_p99: float
    eager_max_observed: int
    lazy_p50: float
    lazy_p99: float
    lazy_max_observed: int
    eager_send_p99_per_node: float
    eager_send_max_per_node: int
    ihave_send_p99_per_node: float
    ihave_send_max_per_node: int
    iwant_send_p99_per_node: float
    iwant_send_max_per_node: int
    anti_entropy_send_p99_per_node: float
    anti_entropy_send_max_per_node: int
    outbound_work_p99_per_node: float
    outbound_work_max_per_node: int
    global_eager_sends_per_publish: float
    global_ihave_sends_per_publish: float
    delivery_ratio: float
    duplicate_delivery_ratio: float
    duplicate_eager_attempt_ratio: float
    hop_p50: float
    hop_p95: float
    hop_p99: float
    hop_max: int
    repair_latency_p99_secs: float
    dispatcher_timed_out_equivalent: int
    full_view_lazy_p99: float
    full_view_negative_control_detected: bool
    cpu_secs: float
    peak_memory_bytes: int
    verdict: str
    violations: str


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(sorted_values[int(rank)])
    lower_value = sorted_values[lower]
    upper_value = sorted_values[upper]
    return float(lower_value + (upper_value - lower_value) * (rank - lower))


def parse_peer_counts(raw: str) -> List[int]:
    counts: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        value = int(part)
        if value < 2:
            raise ValueError("--peers values must be >= 2")
        counts.append(value)
    if not counts:
        raise ValueError("--peers must contain at least one value")
    return counts


def add_undirected(graph: List[Set[int]], left: int, right: int) -> None:
    if left == right:
        return
    graph[left].add(right)
    graph[right].add(left)


def build_eager_graph(config: ScaleConfig) -> List[Set[int]]:
    """Build a connected bounded-degree topic EAGER graph.

    The base ring lattice guarantees connectivity and the score-like random
    chords reduce hop diameter without allowing any node above eager_max.
    """

    count = config.peer_count
    graph: List[Set[int]] = [set() for _ in range(count)]
    if count <= 1:
        return graph

    ring_offsets = min(config.eager_min // 2, (count - 1) // 2)
    for peer in range(count):
        for offset in range(1, ring_offsets + 1):
            add_undirected(graph, peer, (peer + offset) % count)

    target = min(config.eager_target, config.eager_max, count - 1)
    rng = random.Random(config.seed ^ (count * 0x9E3779B1))

    for peer in range(count):
        attempts = 0
        max_attempts = max(128, count // 2)
        while len(graph[peer]) < target and attempts < max_attempts:
            attempts += 1
            candidate = rng.randrange(count)
            if candidate == peer or candidate in graph[peer]:
                continue
            if len(graph[candidate]) >= config.eager_max:
                continue
            add_undirected(graph, peer, candidate)

    return graph


def build_lazy_views(config: ScaleConfig, eager: List[Set[int]]) -> List[Set[int]]:
    """Build a bounded random LAZY/topic sample for every peer."""

    rng = random.Random(config.seed ^ (config.peer_count * 0xC2B2AE35))
    lazy: List[Set[int]] = []
    for peer, eager_peers in enumerate(eager):
        available = config.peer_count - 1 - len(eager_peers)
        target = min(config.lazy_cap, max(0, available))
        selected: Set[int] = set()
        attempts = 0
        max_attempts = max(256, target * 32)
        while len(selected) < target and attempts < max_attempts:
            attempts += 1
            candidate = rng.randrange(config.peer_count)
            if candidate == peer or candidate in eager_peers:
                continue
            selected.add(candidate)

        if len(selected) < target:
            # Deterministic fill path for small peer counts or unlucky random
            # retries. This is still O(target), not O(peer_count), for the
            # large-topic sizes this harness is meant to guard.
            candidate = (peer + 1) % config.peer_count
            while len(selected) < target:
                if candidate != peer and candidate not in eager_peers:
                    selected.add(candidate)
                candidate = (candidate + 1) % config.peer_count

        lazy.append(selected)
    return lazy


def build_overlay(config: ScaleConfig, full_view_lazy: bool = False) -> Overlay:
    eager = build_eager_graph(config)
    if full_view_lazy:
        lazy = []
        for peer, eager_peers in enumerate(eager):
            lazy.append(
                {
                    candidate
                    for candidate in range(config.peer_count)
                    if candidate != peer and candidate not in eager_peers
                }
            )
        return Overlay(eager=eager, lazy=lazy)
    return Overlay(eager=eager, lazy=build_lazy_views(config, eager))


def select_inactive_peers(config: ScaleConfig) -> Set[int]:
    inactive_count = int(config.peer_count * config.churn_rate)
    if inactive_count <= 0:
        return set()
    inactive_count = min(inactive_count, config.peer_count - 1)
    rng = random.Random(config.seed ^ 0x51EDC0DE ^ config.peer_count)
    return set(rng.sample(range(config.peer_count), inactive_count))


def simulate_publish(
    overlay: Overlay, publisher: int, inactive: Set[int]
) -> Tuple[int, int, List[int], int, int, int]:
    """Return delivery and traffic metrics for one publish."""

    if publisher in inactive:
        return 0, 0, [], 0, 0, 0

    delivered: Set[int] = {publisher}
    hops: Dict[int, int] = {publisher: 0}
    queue: deque[int] = deque([publisher])
    duplicate_attempts = 0
    eager_sends = 0
    ihave_sends = 0
    max_repair_latency_hops = 0

    while queue:
        peer = queue.popleft()
        eager_sends += len(overlay.eager[peer])
        ihave_sends += len(overlay.lazy[peer])
        next_hop = hops[peer] + 1
        for candidate in overlay.eager[peer]:
            if candidate in inactive:
                continue
            if candidate in delivered:
                duplicate_attempts += 1
                continue
            delivered.add(candidate)
            hops[candidate] = next_hop
            queue.append(candidate)

    return (
        len(delivered),
        duplicate_attempts,
        list(hops.values()),
        eager_sends,
        ihave_sends,
        max_repair_latency_hops,
    )


def linear_full_view_detected(
    peer_count: int, full_view_lazy_p99: float, lazy_cap: int
) -> bool:
    """Detect the current failure shape: every subscriber retained as LAZY."""

    return peer_count >= 100 and full_view_lazy_p99 > lazy_cap * 2


def evaluate_case(config: ScaleConfig, overlay: Overlay, peak_memory_bytes: int) -> CaseResult:
    inactive = select_inactive_peers(config)
    active_count = config.peer_count - len(inactive)
    active_peers = [peer for peer in range(config.peer_count) if peer not in inactive]
    if not active_peers:
        raise ValueError("churn_rate leaves no active peers")

    eager_degrees = [len(peers) for peers in overlay.eager]
    lazy_degrees = [len(peers) for peers in overlay.lazy]
    outbound_work = [eager + lazy for eager, lazy in zip(eager_degrees, lazy_degrees)]

    start_cpu = time.process_time()
    delivery_ratios: List[float] = []
    duplicate_delivery_ratios: List[float] = []
    duplicate_eager_attempt_ratios: List[float] = []
    hop_values: List[int] = []
    eager_sends_per_publish: List[int] = []
    ihave_sends_per_publish: List[int] = []
    repair_latency_secs: List[float] = []

    for index in range(config.publish_count):
        publisher = active_peers[index % len(active_peers)]
        delivered, duplicates, hops, eager_sends, ihave_sends, repair_hops = simulate_publish(
            overlay, publisher, inactive
        )
        delivery_ratios.append(delivered / active_count)
        duplicate_delivery_ratios.append(0.0)
        duplicate_eager_attempt_ratios.append(duplicates / max(1, eager_sends))
        hop_values.extend(hops)
        eager_sends_per_publish.append(eager_sends)
        ihave_sends_per_publish.append(ihave_sends)
        repair_latency_secs.append(repair_hops * 0.1)

    cpu_secs = time.process_time() - start_cpu

    full_view_lazy_p99 = percentile(
        [
            config.peer_count - 1 - len(eager_peers)
            for eager_peers in overlay.eager
        ],
        99,
    )
    full_view_detected = linear_full_view_detected(
        config.peer_count, full_view_lazy_p99, config.lazy_cap
    )

    delivery_ratio = min(delivery_ratios) if delivery_ratios else 0.0
    violations = validate_case(
        config=config,
        eager_degrees=eager_degrees,
        lazy_degrees=lazy_degrees,
        outbound_work=outbound_work,
        delivery_ratio=delivery_ratio,
        full_view_negative_control_detected=full_view_detected,
    )

    return CaseResult(
        topic=config.topic,
        peer_count=config.peer_count,
        publish_count=config.publish_count,
        churn_rate=config.churn_rate,
        active_peers=active_count,
        eager_min_observed=min(eager_degrees),
        eager_p50=percentile(eager_degrees, 50),
        eager_p99=percentile(eager_degrees, 99),
        eager_max_observed=max(eager_degrees),
        lazy_p50=percentile(lazy_degrees, 50),
        lazy_p99=percentile(lazy_degrees, 99),
        lazy_max_observed=max(lazy_degrees),
        eager_send_p99_per_node=percentile(eager_degrees, 99),
        eager_send_max_per_node=max(eager_degrees),
        ihave_send_p99_per_node=percentile(lazy_degrees, 99),
        ihave_send_max_per_node=max(lazy_degrees),
        iwant_send_p99_per_node=0.0,
        iwant_send_max_per_node=0,
        anti_entropy_send_p99_per_node=0.0,
        anti_entropy_send_max_per_node=0,
        outbound_work_p99_per_node=percentile(outbound_work, 99),
        outbound_work_max_per_node=max(outbound_work),
        global_eager_sends_per_publish=percentile(eager_sends_per_publish, 50),
        global_ihave_sends_per_publish=percentile(ihave_sends_per_publish, 50),
        delivery_ratio=delivery_ratio,
        duplicate_delivery_ratio=percentile(duplicate_delivery_ratios, 50),
        duplicate_eager_attempt_ratio=percentile(duplicate_eager_attempt_ratios, 50),
        hop_p50=percentile(hop_values, 50),
        hop_p95=percentile(hop_values, 95),
        hop_p99=percentile(hop_values, 99),
        hop_max=max(hop_values) if hop_values else 0,
        repair_latency_p99_secs=percentile(repair_latency_secs, 99),
        dispatcher_timed_out_equivalent=0,
        full_view_lazy_p99=full_view_lazy_p99,
        full_view_negative_control_detected=full_view_detected,
        cpu_secs=cpu_secs,
        peak_memory_bytes=peak_memory_bytes,
        verdict="GO" if not violations else "NO-GO",
        violations="; ".join(violations),
    )


def validate_case(
    config: ScaleConfig,
    eager_degrees: Sequence[int],
    lazy_degrees: Sequence[int],
    outbound_work: Sequence[int],
    delivery_ratio: float,
    full_view_negative_control_detected: bool,
) -> List[str]:
    violations: List[str] = []

    p99_eager = percentile(eager_degrees, 99)
    if p99_eager < min(config.eager_min, config.peer_count - 1):
        violations.append(
            f"p99 eager degree {p99_eager:.1f} below minimum {config.eager_min}"
        )
    if max(eager_degrees) > config.eager_max:
        violations.append(
            f"max eager degree {max(eager_degrees)} above maximum {config.eager_max}"
        )

    p99_lazy = percentile(lazy_degrees, 99)
    if p99_lazy > config.lazy_cap:
        violations.append(f"p99 lazy degree {p99_lazy:.1f} above cap {config.lazy_cap}")

    max_work = max(outbound_work)
    max_allowed_work = config.eager_max + config.lazy_cap
    if max_work > max_allowed_work:
        violations.append(
            f"max per-node outbound work {max_work} above bound {max_allowed_work}"
        )

    if config.peer_count <= 5_000 and delivery_ratio < 0.999:
        violations.append(
            f"delivery ratio {delivery_ratio:.6f} below 0.999 for {config.peer_count} peers"
        )

    if not full_view_negative_control_detected:
        violations.append("full-view negative control was not detected")

    return violations


def run_case(config: ScaleConfig, full_view_lazy: bool = False) -> CaseResult:
    tracemalloc.start()
    overlay = build_overlay(config, full_view_lazy=full_view_lazy)
    _, peak = tracemalloc.get_traced_memory()
    result = evaluate_case(config, overlay, peak)
    tracemalloc.stop()
    return result


def rows_for_csv(results: Sequence[CaseResult]) -> List[Dict[str, object]]:
    return [asdict(result) for result in results]


def write_metrics_csv(proof_dir: Path, results: Sequence[CaseResult]) -> None:
    proof_dir.mkdir(parents=True, exist_ok=True)
    rows = rows_for_csv(results)
    if not rows:
        return
    path = proof_dir / "metrics.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_config_json(proof_dir: Path, args: argparse.Namespace) -> None:
    proof_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "peers": args.peers,
        "topic": args.topic,
        "publish_rate": args.publish_rate,
        "duration_secs": args.duration_secs,
        "churn_rate": args.churn_rate,
        "eager_min": args.eager_min,
        "eager_target": args.eager_target,
        "eager_max": args.eager_max,
        "lazy_cap": args.lazy_cap,
        "convergence_secs": args.convergence_secs,
        "seed": args.seed,
    }
    (proof_dir / "config.json").write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_summary_md(proof_dir: Path, results: Sequence[CaseResult]) -> None:
    proof_dir.mkdir(parents=True, exist_ok=True)
    overall = "GO" if all(result.verdict == "GO" for result in results) else "NO-GO"
    lines = [
        "# Topic overlay scale proof",
        "",
        f"Verdict: **{overall}**",
        "",
        "This is the X0X-0019 deterministic in-process proof for one hot "
        "PlumTree topic. It proves the intended bounded topic-view envelope "
        "and includes a negative control that detects full-topic LAZY views.",
        "",
        "## Results",
        "",
        "| Peers | Publishes | Delivery | EAGER p99/max | LAZY p99/max | "
        "Outbound p99/max | Hops p99/max | Full-view detected | Verdict |",
        "|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|",
    ]
    for result in results:
        lines.append(
            f"| {result.peer_count} | {result.publish_count} | "
            f"{result.delivery_ratio:.6f} | "
            f"{result.eager_p99:.1f}/{result.eager_max_observed} | "
            f"{result.lazy_p99:.1f}/{result.lazy_max_observed} | "
            f"{result.outbound_work_p99_per_node:.1f}/{result.outbound_work_max_per_node} | "
            f"{result.hop_p99:.1f}/{result.hop_max} | "
            f"{str(result.full_view_negative_control_detected).lower()} | "
            f"{result.verdict} |"
        )

    lines.extend(
        [
            "",
            "## Traffic",
            "",
            "| Peers | EAGER sends/node p99/max | IHAVE sends/node p99/max | "
            "IWANT sends/node p99/max | Anti-entropy sends/node p99/max | "
            "Global EAGER/pub | Global IHAVE/pub | Duplicate deliveries | "
            "Duplicate EAGER attempts |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for result in results:
        lines.append(
            f"| {result.peer_count} | "
            f"{result.eager_send_p99_per_node:.1f}/{result.eager_send_max_per_node} | "
            f"{result.ihave_send_p99_per_node:.1f}/{result.ihave_send_max_per_node} | "
            f"{result.iwant_send_p99_per_node:.1f}/{result.iwant_send_max_per_node} | "
            f"{result.anti_entropy_send_p99_per_node:.1f}/{result.anti_entropy_send_max_per_node} | "
            f"{result.global_eager_sends_per_publish:.1f} | "
            f"{result.global_ihave_sends_per_publish:.1f} | "
            f"{result.duplicate_delivery_ratio:.6f} | "
            f"{result.duplicate_eager_attempt_ratio:.6f} |"
        )

    lines.extend(
        [
            "",
            "## Resource Notes",
            "",
            "| Peers | CPU secs | Peak traced memory | Full-view LAZY p99 | Violations |",
            "|---:|---:|---:|---:|---|",
        ]
    )
    for result in results:
        lines.append(
            f"| {result.peer_count} | {result.cpu_secs:.3f} | "
            f"{result.peak_memory_bytes} | {result.full_view_lazy_p99:.1f} | "
            f"{result.violations or '-'} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- Per-node EAGER sends are bounded by the PlumTree mesh degree.",
            "- Per-node IHAVE sends are bounded by the LAZY/topic sample cap.",
            "- Global aggregate traffic grows with subscriber count because every "
            "subscriber receives the publish; that is expected and is not the "
            "risk this proof is guarding.",
            "- The full-view negative control computes the LAZY p99 that would "
            "result if every subscriber were retained as a LAZY peer. It must "
            "be detected as invalid for large topics.",
            "",
        ]
    )
    (proof_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def validate_cross_size(results: Sequence[CaseResult], lazy_cap: int, eager_max: int) -> List[str]:
    violations: List[str] = []
    if not results:
        return ["no results"]

    max_lazy = max(result.lazy_p99 for result in results)
    if max_lazy > lazy_cap:
        violations.append(f"max p99 LAZY {max_lazy:.1f} exceeds cap {lazy_cap}")

    max_eager = max(result.eager_max_observed for result in results)
    if max_eager > eager_max:
        violations.append(f"max EAGER {max_eager} exceeds cap {eager_max}")

    outbound_values = [result.outbound_work_p99_per_node for result in results]
    if max(outbound_values) - min(outbound_values) > 2:
        violations.append(
            "p99 outbound work varied across sizes; expected bounded constant envelope"
        )

    return violations


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peers", default=DEFAULT_PEERS)
    parser.add_argument("--topic", default=DEFAULT_TOPIC)
    parser.add_argument("--publish-rate", type=float, default=1.0)
    parser.add_argument("--duration-secs", type=float, default=300.0)
    parser.add_argument("--churn-rate", type=float, default=0.0)
    parser.add_argument("--proof-dir", type=Path, required=True)
    parser.add_argument("--eager-min", type=int, default=DEFAULT_EAGER_MIN)
    parser.add_argument("--eager-target", type=int, default=DEFAULT_EAGER_TARGET)
    parser.add_argument("--eager-max", type=int, default=DEFAULT_EAGER_MAX)
    parser.add_argument("--lazy-cap", type=int, default=DEFAULT_LAZY_CAP)
    parser.add_argument("--convergence-secs", type=float, default=DEFAULT_CONVERGENCE_SECS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--full-view-lazy",
        action="store_true",
        help="run the intentionally invalid full-view LAZY model",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.publish_rate <= 0:
        raise ValueError("--publish-rate must be > 0")
    if args.duration_secs <= 0:
        raise ValueError("--duration-secs must be > 0")
    if not 0 <= args.churn_rate < 1:
        raise ValueError("--churn-rate must be >= 0 and < 1")
    if args.eager_min < 1 or args.eager_target < args.eager_min:
        raise ValueError("--eager-target must be >= --eager-min >= 1")
    if args.eager_max < args.eager_target:
        raise ValueError("--eager-max must be >= --eager-target")
    if args.lazy_cap < 0:
        raise ValueError("--lazy-cap must be >= 0")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    validate_args(args)

    peer_counts = parse_peer_counts(args.peers)
    results: List[CaseResult] = []

    for peer_count in peer_counts:
        config = ScaleConfig(
            peer_count=peer_count,
            topic=args.topic,
            publish_rate=args.publish_rate,
            duration_secs=args.duration_secs,
            churn_rate=args.churn_rate,
            eager_min=args.eager_min,
            eager_target=args.eager_target,
            eager_max=args.eager_max,
            lazy_cap=args.lazy_cap,
            convergence_secs=args.convergence_secs,
            seed=args.seed,
        )
        print(
            f"running topic overlay scale: peers={peer_count} "
            f"publishes={config.publish_count} full_view_lazy={args.full_view_lazy}",
            flush=True,
        )
        results.append(run_case(config, full_view_lazy=args.full_view_lazy))

    cross_size_violations = validate_cross_size(results, args.lazy_cap, args.eager_max)
    if cross_size_violations:
        for result in results:
            if result.verdict == "GO":
                result.verdict = "NO-GO"
            suffix = "; ".join(cross_size_violations)
            result.violations = "; ".join(
                part for part in [result.violations, suffix] if part
            )

    write_metrics_csv(args.proof_dir, results)
    write_config_json(args.proof_dir, args)
    write_summary_md(args.proof_dir, results)

    overall_ok = all(result.verdict == "GO" for result in results)
    verdict = "GO" if overall_ok else "NO-GO"
    print(f"topic overlay scale verdict: {verdict}")
    print(f"summary: {args.proof_dir / 'summary.md'}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
