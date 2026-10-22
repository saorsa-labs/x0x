#!/usr/bin/env python3
"""Unit tests for scripts/ci/prune-target-cache.py (Test Suite cache size, refs #1543)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'prune_target_cache', Path(__file__).with_name('prune-target-cache.py'))
PRUNE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRUNE)

METADATA = {'packages': [
    {'name': 'x0x', 'targets': [{'name': 'x0x'}, {'name': 'gui-coverage'},
                                {'name': 'identity_test'}]},
    {'name': 'x0x-test-harness', 'targets': [{'name': 'x0x_test_harness'}]},
]}

KEPT = [
    'debug/deps/libsaorsa_pqc-0a1b2c.rlib',
    'debug/deps/libc-0a1b2c.d',
    'debug/deps/liblibc-0a1b2c.rlib',
    'debug/build/ant-quic-0a1b2c/output',
    'debug/.fingerprint/tokio-0a1b2c/lib-tokio',
    'CACHEDIR.TAG',
]
REMOVED = [
    'debug/deps/x0x-0a1b2c',
    'debug/deps/x0x-0a1b2c.d',
    'debug/deps/libx0x-0a1b2c.rlib',
    'debug/deps/gui_coverage-0a1b2c',
    'debug/deps/identity_test-0a1b2c',
    'debug/deps/libx0x_test_harness-0a1b2c.rmeta',
    'debug/.fingerprint/x0x-test-harness-0a1b2c/lib',
    'debug/build/x0x-0a1b2c/output',
    'debug/incremental/x0x-0a1b2c/s-1/dep-graph.bin',
    'debug/x0xd',
    'debug/.cargo-lock',
    'nextest/default/junit.xml',
    'dev-isolation/run-1/receipt.json',
    'release/x0xd',
]


class PruneTargetCacheTest(unittest.TestCase):
    def test_keeps_only_third_party_build_output(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            for relative in KEPT + REMOVED:
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('x')
            PRUNE.prune(target, PRUNE.workspace_stems(METADATA))
            for relative in KEPT:
                self.assertTrue((target / relative).exists(), relative)
            for relative in REMOVED:
                self.assertFalse((target / relative).exists(), relative)

    def test_missing_profile_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / 'nextest').mkdir()
            self.assertEqual(PRUNE.prune(target, set()), 1)
            self.assertEqual(list(target.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
