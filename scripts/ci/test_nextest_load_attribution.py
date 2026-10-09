#!/usr/bin/env python3
"""#702: the nextest load-attribution check rejects the old claim and accepts the fix."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "nextest_load_attribution",
    Path(__file__).with_name("check-nextest-load-attribution.py"),
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

STALE = """
# Issue #316: the trigger is ambient suite load starving their timing windows
[[profile.default.overrides]]
filter = "test(direct_send_with_require_ack_round_trips_to_live_peer)"
threads-required = 4

# ADR 0030 slice 3: the trigger here is ambient load from the ungrouped tests starving
# the dial's timing window.
[[profile.default.overrides]]
filter = "binary(gossip_plane_isolation)"
threads-required = 4

# Issue #510
[test-groups.membership-cluster]
max-threads = 2
"""

FIXED = """
# Issue #316. The ambient-load attribution is unverified (#702).
[[profile.default.overrides]]
filter = "test(direct_send_with_require_ack_round_trips_to_live_peer)"
threads-required = 4

# ADR 0030 slice 3. The ambient-load attribution is unverified (#702).
[[profile.default.overrides]]
filter = "binary(gossip_plane_isolation)"
threads-required = 4

# Issue #510. The ambient-load attribution is unverified (#702).
[test-groups.membership-cluster]
max-threads = 2
"""


class LoadAttributionCheck(unittest.TestCase):
    def test_stale_claim_fails(self) -> None:
        errors = CHECK.attribution_errors(STALE)
        self.assertTrue(any("the trigger is ambient suite load" in err for err in errors), errors)
        self.assertTrue(any("the trigger here is ambient load" in err for err in errors), errors)
        self.assertTrue(any("starving the dial's timing window" in err for err in errors), errors)
        self.assertTrue(any(err.startswith("#316:") for err in errors), errors)
        self.assertTrue(any(err.startswith("#510:") for err in errors), errors)

    def test_qualified_comments_pass(self) -> None:
        self.assertEqual(CHECK.attribution_errors(FIXED), [])

    def test_reinserted_claim_fails(self) -> None:
        tainted = FIXED.replace(
            "Issue #316. The ambient-load attribution is unverified (#702).",
            "Issue #316. The ambient-load attribution is unverified (#702). "
            "the trigger is ambient suite load starving their timing windows",
        )
        errors = CHECK.attribution_errors(tainted)
        self.assertTrue(any("the trigger is ambient suite load" in err for err in errors), errors)

    def test_live_config_passes(self) -> None:
        text = (ROOT / ".config" / "nextest.toml").read_text(encoding="utf-8")
        self.assertEqual(CHECK.attribution_errors(text), [])


if __name__ == "__main__":
    unittest.main()
