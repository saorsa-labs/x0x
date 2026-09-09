#!/usr/bin/env python3
"""Inert shell/collector routing controls; no build, daemon or namespace run."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from test_isolation_custody_collect import ADMISSION, HEAD, SUPERVISOR, TREE

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = Path(os.environ.get('ISSUE321_WORKFLOW', ROOT / '.github/workflows/integration.yml'))
CASES = (
    ('history', 'history-restart', 'named_group_e_live'),
    ('point', 'history-point', 'history_point_lookup_wiring'),
    ('delegation', 'delegation', 'delegation_spaces'),
    ('moderated', 'moderated', 'named_group_e_live'),
)


class Routing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.runner = self.root / 'runner'
        self.workspace = self.root / 'workspace'
        self.runner.mkdir(); self.workspace.mkdir()
        self.blocks = re.split(r'^      - ', WORKFLOW.read_text(), flags=re.MULTILINE)
        # The preceding normal group suite leaves unrelated, untyped evidence
        # at the runner root. Scanning this instead of a selector must fail.
        self.producer(self.runner, 'named_group_integration', typed=False)
        for _, suffix, target in CASES:
            directory = self.runner / ('issue321-' + suffix)
            directory.mkdir()
            self.producer(directory, target)

    def producer(self, directory, target, typed=True):
        scratch = directory / 'x0x-metadata-inert'
        evidence = directory / 'x0x-isolation-inert'
        scratch.mkdir(); evidence.mkdir()
        binary = self.workspace / ('target/debug/deps/' + target + '-12345678')
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b'inert, never executed\n'); binary.chmod(0o755)
        files = [self.workspace / 'Cargo.lock', scratch / 'binaries.json', scratch / 'cargo.json']
        for path in files: path.write_text('{}\n')
        (scratch / 'custody.json').write_text(json.dumps({
            'files': {str(p): 'a' * 64 for p in [*files, binary]}, 'source': [HEAD, TREE]}))
        (scratch / 'lock.sha256').write_text('a' * 64 + '  Cargo.lock\n')
        for name, data in [('admission', ADMISSION), ('supervisor', SUPERVISOR), ('exit', {'exit': 0})]:
            (evidence / (name + '.json')).write_text(json.dumps(data))
        if typed:
            (evidence / 'role.json').write_text(json.dumps({'role': 'acceptance', 'scratch': scratch.name}))

    def invoke(self, key):
        block = next(b for b in self.blocks if '\n        id: collect_issue321_' + key + '\n' in b)
        command = re.search(r'^        run: (.+)$', block, re.MULTILINE).group(1)
        environment = dict(os.environ, RUNNER_TEMP=str(self.runner), GITHUB_SHA=HEAD,
                           GITHUB_WORKSPACE=str(self.workspace), PYTHONDONTWRITEBYTECODE='1')
        # Model the observed Actions boundary: reserved RUNNER_/GITHUB_ values
        # come from the runner, not step-env overrides. Task variables survive.
        for name, value in re.findall(r'^          ([A-Z0-9_]+): (.+)$', block, re.MULTILINE):
            if not name.startswith(('RUNNER_', 'GITHUB_')):
                environment[name] = value.strip("'").replace('${{ runner.temp }}', str(self.runner))
        output = self.root / ('outputs-' + key)
        environment['GITHUB_OUTPUT'] = str(output)
        result = subprocess.run(['bash', '-e', '-c', command], cwd=ROOT, env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result, output

    def test_four_actual_collector_commands_keep_selector_custody_separate(self):
        results = [self.invoke(key)[0] for key, _, _ in CASES]
        self.assertEqual([r.returncode for r in results], [0] * 4,
                         '\n'.join(r.stdout for r in results))
        for key, suffix, target in CASES:
            directory = self.runner / ('issue321-' + suffix)
            receipt = json.loads((directory / 'safe/custody-receipt.json').read_text())
            self.assertTrue(receipt['valid'])
            self.assertEqual(receipt['target'], target)
            self.assertEqual(receipt['observed_roles'], ['acceptance'])
            self.assertEqual(receipt['build_custody_count'], 1)
            self.assertEqual(receipt['isolation_run_count'], 1)
            self.assertEqual((self.root / ('outputs-' + key)).read_text(), 'receipt_eligible=true\n')
        self.assertFalse((self.runner / 'safe').exists())

    def test_producer_collector_and_upload_paths_agree(self):
        text = WORKFLOW.read_text()
        for key, suffix, _ in CASES:
            path = '${{ runner.temp }}/issue321-' + suffix
            self.assertIn('root="$RUNNER_TEMP/issue321-' + suffix + '"', text)
            upload = next(b for b in self.blocks if '\n          path: ' + path in b)
            self.assertIn('          path: ' + path + '/safe/custody-receipt.json\n', upload)
            self.assertIn('          if-no-files-found: error\n', upload)
            self.assertIn('steps.collect_issue321_' + key + '.outputs.receipt_eligible', upload)

    def test_wrong_acceptance_binding_still_fails(self):
        path = self.runner / 'issue321-history-restart/x0x-isolation-inert/role.json'
        path.write_text(json.dumps({'role': 'acceptance', 'scratch': 'x0x-metadata-other'}))
        result, _ = self.invoke('history')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ACCEPTANCE_BINDING', result.stdout)

    def test_existing_output_is_refused_without_upload_eligibility(self):
        (self.runner / 'issue321-history-restart/safe').mkdir()
        result, output = self.invoke('history')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('OUTPUT_NOT_EXCLUSIVE', result.stdout)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
