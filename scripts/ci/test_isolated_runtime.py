#!/usr/bin/env python3
"""Inert fixture-retention controls: no Cargo, namespaces, sudo or sockets."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'runtime', Path(__file__).with_name('isolated-runtime.py'))
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class FixtureDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'private-tmp'
        self.source.mkdir()
        self.fixture = self.source / 'x0x-test-bob'
        self.fixture.mkdir()
        self.evidence = self.root / 'x0x-isolation-run123'
        self.evidence.mkdir()
        self.output = self.root / 'x0x-fixture-diagnostics-run123'
        self.config = dict(evidence=str(self.evidence), env={'TMPDIR': str(self.source)},
                           retain_fixture_diagnostics=True)
        # Any unexpected process launch is a test failure, including Cargo.
        spy = patch.object(runtime.subprocess, 'run', side_effect=AssertionError('no processes'))
        spy.start()
        self.addCleanup(spy.stop)

    def collect(self, code=101):
        runtime.retain_fixture_diagnostics(self.config, code)
        return json.loads((self.output / 'manifest.json').read_text())

    def test_copy_survives_source_removal_and_leaves_evidence_unchanged(self):
        (self.evidence / 'exit.json').write_text('{"exit": 101}\n')
        before = {p.name: p.read_bytes() for p in self.evidence.iterdir()}
        (self.fixture / 'daemon.stderr.log').write_text('retiring encrypted store\n')
        nested = self.fixture / '.state'
        nested.mkdir()
        (nested / 'group.bin').write_bytes(b'\x00\x01\xff')
        unrelated = self.source / 'other-app'
        unrelated.mkdir()
        (unrelated / 'secret').write_text('do not copy')
        manifest = self.collect()
        shutil.rmtree(self.source)
        self.assertEqual((self.output / 'x0x-test-bob/daemon.stderr.log').read_text(),
                         'retiring encrypted store\n')
        self.assertEqual((self.output / 'x0x-test-bob/.state/group.bin').read_bytes(), b'\x00\x01\xff')
        self.assertFalse((self.output / 'other-app').exists())
        self.assertEqual(manifest['evidence'], self.evidence.name)
        self.assertEqual(manifest['exit'], 101)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.evidence.iterdir()})

    def test_key_files_and_api_token_are_never_copied(self):
        identity = self.fixture / 'identity'
        identity.mkdir()
        (identity / 'agent.key').write_bytes(b'AGENT-SECRET')
        (identity / 'machine.key').write_bytes(b'MACHINE-SECRET')
        (identity / 'other.bin').write_bytes(b'IDENTITY-DIR-SECRET')
        (self.fixture / 'user.key').write_bytes(b'USER-SECRET')
        (self.fixture / 'api-token').write_text('TOKEN-SECRET')
        (self.fixture / 'named_groups.json').write_text('{"epoch": 2}')
        (self.fixture / 'daemon.stderr.log').write_text('log line\n')
        manifest = self.collect()
        rows = {row['path']: row for row in manifest['entries']}
        for path, size in (('x0x-test-bob/identity/agent.key', 12),
                           ('x0x-test-bob/identity/machine.key', 14),
                           ('x0x-test-bob/identity/other.bin', 19),
                           ('x0x-test-bob/user.key', 11),
                           ('x0x-test-bob/api-token', 12)):
            self.assertEqual(rows[path]['status'], 'skipped-secret')
            self.assertEqual(rows[path]['source_bytes'], size)
            self.assertFalse((self.output / path).exists())
        uploaded = b''.join(p.read_bytes() for p in self.output.rglob('*') if p.is_file())
        self.assertNotIn(b'SECRET', uploaded)
        self.assertEqual((self.output / 'x0x-test-bob/named_groups.json').read_text(), '{"epoch": 2}')
        self.assertEqual((self.output / 'x0x-test-bob/daemon.stderr.log').read_text(), 'log line\n')

    def test_success_and_non_opted_in_failure_do_not_copy(self):
        runtime.retain_fixture_diagnostics(self.config, 0)
        self.assertFalse(self.output.exists())
        self.config.pop('retain_fixture_diagnostics')
        runtime.retain_fixture_diagnostics(self.config, 101)
        self.assertFalse(self.output.exists())

    def test_symlink_files_directories_and_fifo_are_not_copied(self):
        external = self.root / 'external'
        external.mkdir()
        (external / 'secret').write_text('not fixture data')
        (self.source / 'x0x-test-link').symlink_to(external, target_is_directory=True)
        (self.fixture / 'directory-link').symlink_to(external, target_is_directory=True)
        (self.fixture / 'file-link').symlink_to(external / 'secret')
        os.mkfifo(self.fixture / 'fifo')
        manifest = self.collect()
        self.assertEqual(manifest['bytes'], 0)
        self.assertEqual(list(self.output.iterdir()), [self.output / 'manifest.json'])
        self.assertIn('skipped-nonregular', [row['status'] for row in manifest['entries']])

    def test_source_symlink_is_not_followed(self):
        shutil.rmtree(self.source)
        self.source.symlink_to(self.root, target_is_directory=True)
        runtime.retain_fixture_diagnostics(self.config, 101)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_destination_symlink_is_not_followed(self):
        external = self.root / 'external'
        external.mkdir()
        self.output.symlink_to(external, target_is_directory=True)
        runtime.retain_fixture_diagnostics(self.config, 101)
        self.assertEqual(list(external.iterdir()), [])

    def test_file_tail_and_total_byte_caps(self):
        size = 4 * 1024 * 1024
        for index in range(9):
            with (self.fixture / f'{index}.log').open('wb') as stream:
                stream.truncate(size + 10)
                stream.seek(size)
                stream.write(b'final-tail')
        manifest = self.collect()
        self.assertEqual(manifest['bytes'], 32 * 1024 * 1024)
        self.assertTrue(manifest['limit_reached'])
        copies = [row for row in manifest['entries'] if row['status'] == 'copied']
        self.assertEqual(len(copies), 8)
        for row in copies:
            self.assertEqual(row['offset'], 10)
            self.assertEqual(row['copied_bytes'], size)
            self.assertTrue((self.output / row['path']).read_bytes().endswith(b'final-tail'))

    def test_entry_limit_bounds_empty_files(self):
        for index in range(1030):
            (self.fixture / f'{index:04}').touch()
        manifest = self.collect()
        self.assertEqual(len(manifest['entries']), 1024)
        self.assertTrue(manifest['limit_reached'])

    def test_missing_source_is_best_effort(self):
        shutil.rmtree(self.source)
        runtime.retain_fixture_diagnostics(self.config, 101)
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_admitted_copies_after_command_and_preserves_exit(self):
        # Exercise real admitted() sequencing with inert admission/process spies.
        self.config.update(uid=1001, gid=1001, parent_netns='parent', command=['inert'])
        status = '\n'.join(f'{key}:\t0000000000000000' for key in
                           ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) + '\nNoNewPrivs:\t1\n'
        original_read = Path.read_text

        def read(path, *args, **kwargs):
            return status if str(path) == '/proc/self/status' else original_read(path, *args, **kwargs)

        def command(*args, **kwargs):
            self.assertFalse(self.output.exists())
            (self.fixture / 'daemon.stderr.log').write_text('command failed\n')
            return subprocess.CompletedProcess(args[0], -9)

        with patch.object(runtime, 'namespace_state', return_value={}), \
             patch.object(runtime.os, 'getuid', return_value=1001), \
             patch.object(runtime.os, 'geteuid', return_value=1001), \
             patch.object(runtime.os, 'getgroups', return_value=[]), \
             patch.object(Path, 'read_text', read), \
             patch.object(runtime.subprocess, 'run', side_effect=command) as run:
            self.assertEqual(runtime.admitted(self.config), 137)
        run.assert_called_once_with(['inert'], env=self.config['env'], close_fds=True)
        self.assertEqual(json.loads((self.evidence / 'exit.json').read_text()), {'exit': -9})
        self.assertEqual((self.output / 'x0x-test-bob/daemon.stderr.log').read_text(), 'command failed\n')

    def test_collection_error_does_not_replace_command_failure(self):
        self.config.update(uid=1001, gid=1001, parent_netns='parent', command=['inert'])
        # The helper itself absorbs filesystem failures; its return cannot
        # replace the command's return code in admitted().
        with patch.object(runtime.os, 'open', side_effect=PermissionError('denied')):
            self.assertIsNone(runtime.retain_fixture_diagnostics(self.config, 101))

    def test_workflow_opts_in_only_kv_and_uploads_only_on_failure(self):
        workflow = Path(__file__).parents[2] / '.github/workflows/integration.yml'
        text = workflow.read_text()
        kv = text.split('  encrypted-kv-transport:\n', 1)[1].split('  gossip-key-cache-transport:\n', 1)[0]
        self.assertEqual(text.count("X0X_RETAIN_FIXTURE_DIAGNOSTICS: '1'"), 1)
        self.assertIn("X0X_RETAIN_FIXTURE_DIAGNOSTICS: '1'", kv)
        self.assertIn('name: Upload retained fixture diagnostics\n        if: failure()\n'
                      '        uses: actions/upload-artifact@v5', kv)
        self.assertIn('path: ${{ runner.temp }}/x0x-fixture-diagnostics-*', kv)


if __name__ == '__main__':
    unittest.main()
