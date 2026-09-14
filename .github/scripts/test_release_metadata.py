#!/usr/bin/env python3
"""Offline regressions for the static release card/version contract."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = Path('.github/scripts/validate_release_metadata.py')
WORKFLOW = Path('.github/workflows/release.yml')
CARD = Path('.well-known/agent.json')


class ReleaseCardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in [VALIDATOR, WORKFLOW, CARD, Path('Cargo.toml'), Path('SKILL.md'),
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

    def run_validator(self, tag, ref=None, card=None):
        command = ['python3', str(self.root / VALIDATOR), '--mode', 'release_tag',
                   '--tag', tag]
        if ref:
            command += ['--ref', ref]
        if card:
            command += ['--agent-card', str(card)]
        return subprocess.run(command, cwd=self.root, capture_output=True, text=True)

    def validate(self, tag=None, card=None):
        return self.run_validator('v' + (tag or self.version), card=card)

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

    def test_staged_card_mismatched_against_tag_is_blocking(self):
        # WHY (#514): the published asset must be inspected against the
        # release TAG, not merely against the source tree — a staged card
        # that drifted from the tagged release has to block publishing even
        # when the source files themselves are consistent with the tag.
        staged = self.root / 'release-files/agent.json'
        staged.parent.mkdir()
        card = json.loads((ROOT / CARD).read_text())
        card['version'] = '0.10.0'
        staged.write_text(json.dumps(card))
        result = self.validate(card=staged)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            f"Agent card version '0.10.0' does not match release tag v{self.version}",
            result.stdout,
            result.stdout + result.stderr,
        )

    def test_tag_argument_is_rejected_outside_release_tag_mode(self):
        # WHY (#514 audit lesson): a silently ignored --tag makes a
        # tag-mismatch gate look like a pass — misuse must fail loudly.
        result = subprocess.run(
            ['python3', str(self.root / VALIDATOR), '--mode', 'push_main',
             '--tag', 'v' + self.version],
            cwd=self.root, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--tag is only valid in release_tag mode', result.stderr)

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

    def test_valid_tag_ref_passes(self):
        result = self.run_validator('v' + self.version,
                                    ref=f'refs/tags/v{self.version}')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_branch_dispatch_is_refused_before_other_checks(self):
        # WHY: dispatching Release on a branch used to validate in push_main
        # mode and only die after the platform builds, when VERSION derivation
        # hit a non-semver GITHUB_REF_NAME. The ref gate must refuse first,
        # with one clear message and no tag-derived noise.
        for ref_name, ref in [('main', 'refs/heads/main'),
                              ('codex/release-dispatch-guard',
                               'refs/heads/codex/release-dispatch-guard')]:
            with self.subTest(ref=ref):
                result = self.run_validator(ref_name, ref=ref)
                self.assertEqual(result.returncode, 1,
                                 result.stdout + result.stderr)
                self.assertIn(
                    'Release must target a valid release tag ref refs/tags/vX.Y.Z',
                    result.stderr)
                self.assertNotIn('Running version_sync', result.stdout)
                self.assertNotIn('does not match release tag', result.stdout)

    def test_malformed_tag_refs_are_refused(self):
        cases = [
            ('v1.2', 'refs/tags/v1.2'),
            ('v1.2.3.4', 'refs/tags/v1.2.3.4'),
            ('v1.2.3+', 'refs/tags/v1.2.3+'),
            ('1.2.3', 'refs/tags/1.2.3'),
            ('main', 'refs/tags/main'),
        ]
        for tag, ref in cases:
            with self.subTest(ref=ref):
                result = self.run_validator(tag, ref=ref)
                self.assertEqual(result.returncode, 1,
                                 result.stdout + result.stderr)
                self.assertIn('Release must target a valid release tag ref',
                              result.stderr)

    def test_tag_ref_disagreement_is_refused(self):
        # A --tag that does not name the validated ref would let a caller
        # vouch for metadata the run is not actually building from.
        result = self.run_validator('v' + self.version, ref='refs/tags/v0.42.0')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("does not name the release ref 'refs/tags/v0.42.0'",
                      result.stderr)

    def test_valid_ref_shape_but_mismatched_metadata_fails(self):
        # Prerelease-shaped tags are valid refs; they must still fail on the
        # metadata-mismatch rules rather than the ref-form gate.
        result = self.run_validator('v999.0.0-rc.1', ref='refs/tags/v999.0.0-rc.1')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('does not match release tag v999.0.0-rc.1', result.stdout)
        self.assertNotIn('Release must target', result.stderr)

    def test_ref_argument_is_rejected_outside_release_tag_mode(self):
        # Mirror of the --tag guard: a silently ignored --ref would make the
        # release-ref gate look like a pass — misuse must fail loudly.
        result = subprocess.run(
            ['python3', str(self.root / VALIDATOR), '--mode', 'push_main',
             '--ref', 'refs/heads/main'],
            cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('--ref is only valid in release_tag mode', result.stderr)

    def run_release_validate_step(self, ref, ref_name):
        # Execute the exact shell command the Release workflow's first job
        # runs, extracted from the real workflow file, under a simulated ref.
        run_block = self.validator.extract_step_run_block(
            str(WORKFLOW), 'Validate release metadata')
        env = dict(os.environ, GITHUB_REF=ref, GITHUB_REF_NAME=ref_name)
        return subprocess.run(['bash', '-c', run_block], cwd=self.root,
                              capture_output=True, text=True, env=env)

    def test_workflow_validate_step_accepts_matching_tag(self):
        result = self.run_release_validate_step(
            f'refs/tags/v{self.version}', f'v{self.version}')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_workflow_validate_step_refuses_branch_dispatch(self):
        result = self.run_release_validate_step('refs/heads/main', 'main')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Release must target a valid release tag ref refs/tags/vX.Y.Z',
                      result.stderr)

    def test_every_side_effect_job_is_gated_on_metadata_validation(self):
        # Rejection must land before any build/publish side effect: every
        # downstream job has to hang (directly or transitively) off the
        # first validation job, and no call site may fall back to push_main.
        text = (ROOT / WORKFLOW).read_text()
        self.assertNotIn(
            '--mode push_main', text,
            'release.yml must not validate any release run in push_main mode')
        self.assertGreaterEqual(
            text.count('--ref "${GITHUB_REF}"'), 2,
            'both validator call sites must pass the actual full ref')
        needs = {}
        current = None
        for line in text.splitlines():
            stripped = line.strip()
            if line.startswith('  ') and not line.startswith('   ') \
                    and stripped.endswith(':'):
                current = stripped[:-1]
                needs[current] = ''
            elif current and stripped.startswith('needs:'):
                needs[current] = stripped[len('needs:'):].strip()
        expected = {
            'require-green-ci': ['validate-release-metadata'],
            'build-release': ['validate-release-metadata', 'require-green-ci'],
            'sign-release': ['build-release'],
            'create-release': ['build-release', 'sign-release'],
            'publish-clawhub': ['create-release'],
            'publish-crates': ['create-release'],
        }
        for job, dependencies in expected.items():
            with self.subTest(job=job):
                self.assertIn(job, needs, f'{job} is missing from release.yml')
                for dependency in dependencies:
                    self.assertIn(
                        dependency, needs[job],
                        f'{job} must need {dependency} so an invalid ref '
                        'cannot reach it')


if __name__ == '__main__':
    unittest.main()
