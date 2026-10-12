#!/usr/bin/env python3
"""#1283: daemon-mesh binaries stay in the quic-localhost serial group.

The groups job's issue #321 acceptance selector runs three daemon-mesh tests
from `delegation_spaces` in one nextest invocation. nextest runs each test as
its own process, so the binary's in-process suite lock cannot serialise them;
without a `quic-localhost` group override all three pairs form simultaneously
inside the single loopback network namespace the isolated runtime grants the
invocation. Run 37898362740 (issue #1283) lost two of those three meshes.
This test pins the override so the serialization cannot be silently dropped.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".config" / "nextest.toml"

# Daemon-mesh binaries that a CI selector runs with more than one test per
# nextest invocation. Single-test selectors gain nothing from the group, so
# they are deliberately absent (see the module docstring in the config).
SERIALIZED_MESH_BINARIES = ("delegation_spaces",)


def overrides(text: str):
    """Yield (filter_expression, settings_lines) per profile override block."""
    block = re.compile(
        r"\[\[profile\.default\.overrides\]\]\n((?:[^\[]|\[(?!\[))*)", re.S)
    for match in block.finditer(text):
        body = match.group(1)
        filter_line = re.search(r'^filter\s*=\s*"(.*)"\s*$', body, re.M)
        if filter_line:
            yield filter_line.group(1), body


class MeshSerialization(unittest.TestCase):
    def test_mesh_binaries_are_in_the_quic_localhost_group(self) -> None:
        text = CONFIG.read_text(encoding="utf-8")
        for binary in SERIALIZED_MESH_BINARIES:
            wanted = f"binary({binary})"
            hits = [body for expression, body in overrides(text)
                    if wanted in expression and "quic-localhost" in body]
            with self.subTest(binary=binary):
                self.assertTrue(
                    hits,
                    f".config/nextest.toml must map {wanted} to the "
                    "quic-localhost test-group (#1283); the daemon-mesh "
                    "selector would otherwise run its pairs concurrently "
                    "in one loopback namespace",
                )

    def test_quic_localhost_group_still_serialises(self) -> None:
        text = CONFIG.read_text(encoding="utf-8")
        self.assertRegex(
            text,
            r"\[test-groups\.quic-localhost\]\s*\nmax-threads\s*=\s*1\b",
        )


if __name__ == "__main__":
    unittest.main()
