#!/usr/bin/env python3
"""Offline custody controls. No product executable, socket or namespace is run."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('reuse', Path(__file__).with_name('nextest-reuse.py'))
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.old_cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.old_cwd)
        self.addCleanup(self.temporary.cleanup)
        self.graph = patch.object(reuse.subprocess, 'check_output', return_value='source-head\nsource-tree\n')
        self.graph.start()
        self.addCleanup(self.graph.stop)
        (self.root / 'test-binary').write_bytes(b'disposable test executable bytes')
        (self.root / 'daemon').write_bytes(b'disposable non-test executable bytes')
        (self.root / 'Cargo.lock').write_text('resolved lock')
        (self.root / 'cargo.json').write_text('{"resolve":"same graph"}')
        (self.root / 'binaries.json').write_text(json.dumps({
            'rust-binaries': {'fixture': {'binary-path': str(self.root / 'test-binary')}},
            'rust-build-meta': {'target-directory': str(self.root),
                'non-test-binaries': {'fixture': [{'path': 'daemon'}]}},
        }))
        reuse.record(self.root)

    def test_exact_inputs_pass(self):
        reuse.verify(self.root)

    def test_test_binary_change_refused(self):
        (self.root / 'test-binary').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'build input changed'):
            reuse.verify(self.root)

    def test_non_test_binary_change_refused(self):
        (self.root / 'daemon').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'build input changed'):
            reuse.verify(self.root)

    def test_feature_graph_change_refused(self):
        (self.root / 'cargo.json').write_text('{"resolve":"different graph"}')
        with self.assertRaisesRegex(RuntimeError, 'build input changed'):
            reuse.verify(self.root)

    def test_lock_change_refused(self):
        (self.root / 'Cargo.lock').write_text('different lock')
        with self.assertRaisesRegex(RuntimeError, 'build input changed'):
            reuse.verify(self.root)

    def test_binary_set_change_refused(self):
        value = json.loads((self.root / 'binaries.json').read_text())
        value['rust-build-meta']['non-test-binaries'] = {}
        (self.root / 'binaries.json').write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, 'input set changed'):
            reuse.verify(self.root)

    def test_source_revision_change_refused(self):
        with patch.object(reuse.subprocess, 'check_output', return_value='other-head\nother-tree\n'):
            with self.assertRaisesRegex(RuntimeError, 'source checkout changed'):
                reuse.verify(self.root)

    def test_empty_binary_list_refused(self):
        value = json.loads((self.root / 'binaries.json').read_text())
        value['rust-binaries'] = {}
        (self.root / 'binaries.json').write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, 'no test binaries'):
            reuse.record(self.root)


if __name__ == '__main__':
    unittest.main()
