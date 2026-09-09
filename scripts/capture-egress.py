#!/usr/bin/env python3
"""Capture a validated Leaf gossip-egress window for issue #504.

Implements the measurement recipe in `docs/design/504-leaf-egress-budget.md`
section 5. Every remaining #504 slice (byte shedding, announce consume-only,
the #501 DM-bus default) is gated on this capture, because the design doc
deliberately does not claim which named topic owns the reported
1.54 GB / 97,744 eager messages. You cannot budget what you cannot attribute.

The script snapshots `x0x diagnostics gossip|transport --json` and
`x0x health --json` at t0 and t1, enforces the section 5.4 acceptance rules,
and ranks per-topic EAGER byte *deltas* (never cumulative t1 totals).

Usage:
    python3 -m venv .venv
    .venv/bin/python -m pip install blake3
    .venv/bin/python scripts/capture-egress.py [--window-secs N] [TOPIC ...]

Extra positional TOPIC arguments name node-specific topics (identity/machine/
user shards) so their hex8 keys resolve instead of showing `unknown-hex`.
Pass a DM inbox by its human-readable `x0x/dm/v1/inbox/<64-hex>` name.

If the daemon requires auth, export X0X_API_TOKEN before running.
Reject and restart the whole window on any raised error; a partial window is
not evidence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

try:
    from blake3 import blake3
except ImportError:  # pragma: no cover - operator environment guard
    sys.exit("Missing dependency: pip install blake3")

# Fixed system topics from docs/design/504-leaf-egress-budget.md section 5.3.
FIXED_TOPICS = """
x0x.identity.announce.v2
x0x.machine.announce.v2
x0x.machine.announce.v3
x0x.user.announce.v2
x0x.revocation.v1
x0x.revocation.v2
x0x.move.activation.v1
x0x/dm/v1/bus
x0x/caps/v1
x0x/caps/v2/digest
x0x/caps/v1/request/targeted-v2
x0x/caps/v1/response/targeted-v2
x0x/announce/v2/blob
x0x.discovery.groups
x0x.groups.public.v1
x0x/announce/v3/blob
x0x/release
""".split()

DM_INBOX_PREFIX = "x0x/dm/v1/inbox/"

# section 5.3: counters whose deltas must be reported for the window.
PARTICIPATION_KEYS = (
    "epidemic_forward_bytes",
    "epidemic_forward_msgs",
    "relay_bytes",
    "relay_msgs",
    "unsubscribed_refused_frames",
    "passthrough_refresh_runs",
)


def topic_hex8(name: str) -> str:
    """Return the 16-hex-character `TopicId` prefix used by `outbound_by_topic`.

    saorsa-gossip derives `TopicId` as BLAKE3 of the exact UTF-8 topic string.
    DM inbox names are the exception: `inbox_topic_name` already embeds the
    full 32-byte topic hex, so it must be sliced rather than rehashed.
    """
    if name.startswith(DM_INBOX_PREFIX):
        raw_hex = name[len(DM_INBOX_PREFIX) :]
        if len(raw_hex) != 64 or len(bytes.fromhex(raw_hex)) != 32:
            raise ValueError(f"Inbox name must end in its full 32-byte topic hex: {name}")
        return raw_hex[:16].lower()
    return blake3(name.encode("utf-8")).hexdigest()[:16]


def snapshot(label: str, out_dir: Path) -> dict:
    """Capture one endpoint sample, preserving every raw response on disk."""
    result: dict = {}
    for name, args in (
        ("gossip", ["diagnostics", "gossip"]),
        ("transport", ["diagnostics", "transport"]),
        ("health", ["health"]),
    ):
        # --json is mandatory: the CLI defaults to Text and a .json filename
        # does not change the output format.
        raw = subprocess.check_output(["x0x", *args, "--json"], encoding="utf-8")
        obj = json.loads(raw)  # Reject errors/Text output rather than treating as zero.
        if obj.get("ok") is False:
            raise RuntimeError(f"{name} failed: {obj}")
        (out_dir / f"{name}-{label}.json").write_text(raw, encoding="utf-8")
        result[name] = obj.get("data", obj)
    result["epoch"] = time.time()
    result["monotonic"] = time.monotonic()
    (out_dir / f"{label}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def checked_delta(before: int, after: int, label: str) -> int:
    """Delta that refuses to silently absorb a counter reset.

    A daemon restart can grow counters past t0 again, so a nonnegative delta
    alone does not prove continuity; the caller also compares uptime with
    elapsed time.
    """
    if after < before:
        raise RuntimeError(f"Counter reset: {label}; reject/restart window")
    return after - before


def validate_window(a: dict, b: dict, dt: float) -> None:
    """Enforce the section 5.4 acceptance rules for the *measurement*."""
    uptime_delta = b["health"]["uptime_secs"] - a["health"]["uptime_secs"]
    if dt < 300 or abs(uptime_delta - dt) > 5:
        raise RuntimeError("Restart or invalid timing: reject/restart window")
    for sample in (a, b):
        p = sample["gossip"]["participation"]
        if (
            p["mode"] != "leaf"
            or p["reason"] != "default_leaf"
            or p["passthrough_refresh_runs"] != 0
            or sample["health"]["peers"] == 0
        ):
            raise RuntimeError("Not a usable default Leaf window")


def report_participation(a: dict, b: dict, dt: float) -> None:
    for key in PARTICIPATION_KEYS:
        delta = checked_delta(
            a["gossip"]["participation"][key], b["gossip"]["participation"][key], key
        )
        if key.endswith("_bytes"):
            print(f"{key}: {delta / dt / 1024:.2f} KiB/s; {delta / dt * 60 / 1e6:.2f} MB/min")
        else:
            print(f"{key}: {delta}")


def report_topics(a: dict, b: dict, dt: float, names: dict[str, str]) -> None:
    """Rank topics by Δeager.bytes — the attribution #504 is missing."""
    old = a["gossip"]["pubsub_stages"]["outbound_by_topic"]
    new = b["gossip"]["pubsub_stages"]["outbound_by_topic"]
    rows = []
    for topic in old.keys() | new.keys():
        before, after = old.get(topic, {}), new.get(topic, {})
        if topic in old and topic not in new:
            raise RuntimeError("Topic counters disappeared: reject/restart window")
        for kind in before.keys() | after.keys():
            for metric in ("bytes", "msgs"):
                checked_delta(
                    before.get(kind, {}).get(metric, 0),
                    after.get(kind, {}).get(metric, 0),
                    f"{topic}/{kind}/{metric}",
                )
        delta = checked_delta(
            before.get("eager", {}).get("bytes", 0),
            after.get("eager", {}).get("bytes", 0),
            topic,
        )
        rows.append((delta, topic, names.get(topic, "unknown-hex")))
    for delta, topic, name in sorted(rows, reverse=True)[:8]:
        print(f"{delta:12d} bytes  {delta / dt / 1024:9.2f} KiB/s  {topic}  {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--window-secs",
        type=int,
        default=1200,
        help="idle window length; must be >= 300 to be acceptable (default: 1200)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("."),
        help="evidence directory for the raw JSON responses (default: cwd)",
    )
    parser.add_argument("topics", nargs="*", help="extra node-specific topic names")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    names = {topic_hex8(t): t for t in FIXED_TOPICS + args.topics}
    (args.out_dir / "topic-names.json").write_text(json.dumps(names, indent=2), encoding="utf-8")

    a = snapshot("t0", args.out_dir)
    # Idle: no publishes or extra subscriptions during this interval.
    time.sleep(args.window_secs)
    b = snapshot("t1", args.out_dir)

    dt = b["monotonic"] - a["monotonic"]
    validate_window(a, b, dt)
    report_participation(a, b, dt)
    report_topics(a, b, dt, names)
    print(f"\nWindow accepted: dt={dt:.0f}s; evidence in {args.out_dir.resolve()}")


if __name__ == "__main__":
    main()
