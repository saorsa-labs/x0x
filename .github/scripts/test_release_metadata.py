#!/usr/bin/env python3
"""Offline regressions for the static release card/version contract."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = Path('.github/scripts/validate_release_metadata.py')
CARD = Path('.well-known/agent.json')


class ReleaseCardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in [VALIDATOR, CARD, Path('Cargo.toml'), Path('SKILL.md'),
                     Path('scripts/bump-version.sh')]:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.policy = json.loads((ROOT / '.github/release-metadata-policy.json').read_text())
        self.policy['rules'] = {'version_sync': self.policy['rules']['version_sync']}
        (self.root / '.github/release-metadata-policy.json').write_text(json.dumps(self.policy))
        spec = importlib.util.spec_from_file_location('validator_fixture', self.root / VALIDATOR)
        self.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.validator)
        self.version = self.validator.extract_cargo_version('Cargo.toml')

    def validate(self, tag=None, card=None):
        command = ['python3', str(self.root / VALIDATOR), '--mode', 'release_tag',
                   '--tag', 'v' + (tag or self.version)]
        if card:
            command += ['--agent-card', str(card)]
        return subprocess.run(command, cwd=self.root, capture_output=True, text=True)

    def test_current_source_and_staged_asset_match_tag(self):
        staged = self.root / 'release-files/agent.json'
        staged.parent.mkdir()
        shutil.copyfile(self.root / CARD, staged)
        result = self.validate(card=staged)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_stale_source_and_staged_asset_are_blocking(self):
        for staged in [False, True]:
            with self.subTest(staged=staged):
                (self.root / CARD).write_text((ROOT / CARD).read_text())
                target = self.root / ('staged-agent.json' if staged else CARD)
                card = json.loads((ROOT / CARD).read_text())
                card['version'] = '0.10.0'
                target.write_text(json.dumps(card))
                result = self.validate(card=target if staged else None)
                self.assertEqual(result.returncode, 1)
                self.assertIn('Agent card version', result.stdout)

    def test_card_only_pr_change_runs_blocking_rule(self):
        rule = self.policy['rules']['version_sync']
        self.assertTrue(self.validator.should_run_rule(
            rule, 'pull_request', [str(CARD)], self.policy))
        self.assertEqual(rule['level'], 'blocking')

    def test_bump_preserves_every_other_card_byte_and_checks_new_tag(self):
        before = (self.root / CARD).read_text()
        result = subprocess.run(['bash', 'scripts/bump-version.sh', '9.8.7'],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / CARD).read_text(), before.replace(
            '"version": "' + self.version + '"', '"version": "9.8.7"', 1))
        self.assertEqual(self.validate(tag='9.8.7').returncode, 0)
        self.assertEqual(self.validate(tag='9.8.6').returncode, 1)

    def test_bump_accepts_reformatted_json_and_preserves_other_bytes(self):
        card = json.loads((ROOT / CARD).read_text())
        # Put another version before the top-level field to catch accidental
        # first-match replacement in nested objects.
        card = {'metadata': {'version': 'keep-me'}, **card}
        for indent, newline in [(None, '\n'), (4, '\n'), ('\t', '\n'), (2, '\r\n')]:
            with self.subTest(indent=indent, newline=newline):
                before = json.dumps(card, indent=indent).replace('\n', newline)
                (self.root / CARD).write_bytes(before.encode('utf-8'))
                result = subprocess.run(['bash', 'scripts/bump-version.sh', '9.8.7'],
                                        cwd=self.root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((self.root / CARD).read_bytes().decode('utf-8'), before.replace(
                    '"version": "' + self.version + '"', '"version": "9.8.7"', 1))
                self.assertEqual(self.validate(tag='9.8.7').returncode, 0)

    def test_invalid_card_leaves_every_version_file_unchanged(self):
        valid = json.loads((ROOT / CARD).read_text())
        missing_version = dict(valid)
        del missing_version['version']
        for card_text in ['{broken json', json.dumps(missing_version),
                          json.dumps({**valid, 'version': 17}),
                          '{"version": "0.1.0", "version": "0.2.0"}']:
            with self.subTest(card_text=card_text):
                for name in ['Cargo.toml', 'SKILL.md']:
                    shutil.copyfile(ROOT / name, self.root / name)
                (self.root / CARD).write_text(card_text)
                paths = [Path('Cargo.toml'), Path('SKILL.md'), CARD]
                before = {path: (self.root / path).read_bytes() for path in paths}
                result = subprocess.run(['bash', 'scripts/bump-version.sh', '9.8.7'],
                                        cwd=self.root, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual({path: (self.root / path).read_bytes() for path in paths},
                                 before, 'validation failure must not partially bump versions')

    def test_unmatched_version_file_leaves_inputs_unchanged(self):
        for broken in ['Cargo.toml', 'SKILL.md']:
            with self.subTest(broken=broken):
                for name in ['Cargo.toml', 'SKILL.md']:
                    shutil.copyfile(ROOT / name, self.root / name)
                (self.root / broken).write_text('no version field here\n')
                paths = [Path('Cargo.toml'), Path('SKILL.md'), CARD]
                before = {path: (self.root / path).read_bytes() for path in paths}
                result = subprocess.run(['bash', 'scripts/bump-version.sh', '9.8.7'],
                                        cwd=self.root, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual({path: (self.root / path).read_bytes() for path in paths},
                                 before)


if __name__ == '__main__':
    unittest.main()
