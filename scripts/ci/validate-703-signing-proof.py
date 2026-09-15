#!/usr/bin/env python3
"""Validate the unchanged #703 100k slow-subscriber proof."""

import json
import sys
from pathlib import Path


def validate(proof: object) -> None:
    if not isinstance(proof, dict):
        raise ValueError("proof must be an object")
    exact = {
        "messages": 100_000,
        "publish_total": 100_000,
        "fast_received": 100_000,
        # Fast receiver plus the unread slow subscriber's 10k buffer.
        "delivered_to_subscriber": 110_000,
        "decode_to_delivery_drops": 0,
    }
    for key, expected in exact.items():
        if type(proof.get(key)) is not int or proof.get(key) != expected:
            raise ValueError(f"{key} must be {expected}, got {proof.get(key)!r}")
    for key in ("slow_subscriber_dropped", "subscriber_channel_closed"):
        value = proof.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{key} must be a positive integer, got {value!r}")


def self_test() -> None:
    good = {
        "messages": 100_000,
        "publish_total": 100_000,
        "fast_received": 100_000,
        "delivered_to_subscriber": 110_000,
        "slow_subscriber_dropped": 1,
        "subscriber_channel_closed": 1,
        "decode_to_delivery_drops": 0,
    }
    validate(good)
    for key, bad in (
        ("messages", 99_999),
        ("publish_total", 99_999),
        ("fast_received", 99_999),
        ("delivered_to_subscriber", None),
        ("delivered_to_subscriber", True),
        ("delivered_to_subscriber", 110_000.0),
        ("delivered_to_subscriber", "110000"),
        ("delivered_to_subscriber", 100_000),
        ("delivered_to_subscriber", 120_000),
        ("delivered_to_subscriber", 109_999),
        ("delivered_to_subscriber", 110_001),
        ("delivered_to_subscriber", 99_999),
        ("decode_to_delivery_drops", 1),
        ("decode_to_delivery_drops", False),
        ("messages", 100_000.0),
        ("slow_subscriber_dropped", 0),
        ("subscriber_channel_closed", False),
    ):
        candidate = dict(good)
        candidate[key] = bad
        try:
            validate(candidate)
        except ValueError:
            continue
        raise AssertionError(f"invalid {key} proof was accepted")
    for missing in (
        "messages",
        "publish_total",
        "fast_received",
        "delivered_to_subscriber",
        "slow_subscriber_dropped",
        "subscriber_channel_closed",
        "decode_to_delivery_drops",
    ):
        candidate = dict(good)
        del candidate[missing]
        try:
            validate(candidate)
        except ValueError:
            continue
        raise AssertionError(f"proof missing {missing} was accepted")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("#703 proof validator self-test passed")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate-703-signing-proof.py PROOF.json")
    path = Path(sys.argv[1]).resolve(strict=True)
    validate(json.loads(path.read_text()))
    print(f"#703 100k proof accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
