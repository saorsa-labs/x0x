#!/usr/bin/env python3
"""Structured selection proof for the issue #277 datagram-lane acceptance suite.

The whole suite is `#[ignore]`d, so a plain `cargo test` reports it green
without executing a single test, and a missing `required-features` entry
would compile the file away to an empty, passing binary. Both failures
are invisible in human-readable output, so this asserts against nextest's
structured JSON list: real test names, and the `ignored` flag that
decides whether `--run-ignored ignored-only` selects them at all.

Runs inside the issue #417 namespace (see `isolated-runtime.py`), which
is why discovery is `--offline --locked` against binaries already built
outside it.
"""
import json
import subprocess
import sys

BINARY_ID = "x0x::voice_datagram_e2e"

# The #277 acceptance oracles: deterministic jitter-counter phases.
REQUIRED_COUNTER_ORACLES = {
    "jitter_counters_stay_zero_on_in_order_datagram_schedule",
    "scheduled_reorder_counts_exactly_one_reordered_frame",
    "duplicate_arriving_while_buffered_counts_as_duplicate_not_late",
    "frame_arriving_after_gap_and_playout_counts_as_late",
}

# The ADR-0042 posture these oracles sit alongside and must not replace:
# lane negotiation, routing, loss resilience, flood defence, advert
# authenticity, churn fallback.
REQUIRED_ADR0042 = {
    "datagram_lane_delivers_decodable_audio_on_loopback",
    "datagram_lane_survives_injected_loss_and_reorder",
    "datagram_flood_rate_limited_and_lane_recovers",
    "spoofed_or_replayed_advert_cannot_flip_lane",
    "connection_churn_falls_back_to_reliable",
    "sequential_startup_still_negotiates_datagram_lane",
}

REQUIRED = REQUIRED_COUNTER_ORACLES | REQUIRED_ADR0042


def main():
    listing = json.loads(subprocess.check_output([
        "cargo", "nextest", "list", "--offline", "--locked", "--all-features",
        "--test", "voice_datagram_e2e", "--run-ignored", "all",
        "--message-format", "json", "--list-type", "full",
    ], text=True))

    suites = listing.get("rust-suites", {})
    suite = suites.get(BINARY_ID)
    if suite is None:
        raise SystemExit(
            f"{BINARY_ID} was not discovered; the acceptance suite is not "
            f"selected by this build. Discovered suites: {sorted(suites)}"
        )

    cases = suite.get("testcases", {})
    missing = sorted(REQUIRED - set(cases))
    if missing:
        raise SystemExit(f"acceptance tests missing from the suite: {missing}")

    # Every case must be ignored, or `--run-ignored ignored-only` silently
    # skips it in the acceptance run below.
    not_ignored = sorted(n for n, c in cases.items() if not c.get("ignored"))
    if not_ignored:
        raise SystemExit(
            "these tests are not #[ignore]d, so `--run-ignored ignored-only` "
            f"would not select them: {not_ignored}"
        )

    unmatched = sorted(
        n for n, c in cases.items()
        if c.get("filter-match", {}).get("status") != "matches"
    )
    if unmatched:
        raise SystemExit(f"tests not selected by the filter: {unmatched}")

    manifest = {
        "binary-id": BINARY_ID,
        "binary-path": suite.get("binary-path"),
        "test-count": listing.get("test-count"),
        "tests": sorted(cases),
        "counter-oracles": sorted(REQUIRED_COUNTER_ORACLES),
        "adr-0042": sorted(REQUIRED_ADR0042),
        "all-ignored": True,
    }
    json.dump(manifest, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
