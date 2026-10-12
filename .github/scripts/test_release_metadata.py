#!/usr/bin/env python3
"""Offline regressions for the static release card/version contract."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = Path('.github/scripts/validate_release_metadata.py')
WORKFLOW = Path('.github/workflows/release.yml')
PROMOTED_WORKFLOW = Path('.github/workflows/publish-promoted-release.yml')
CARD = Path('.well-known/agent.json')

EXPECTED_RELEASE_JOB_NEEDS = {
    'require-green-ci': ['validate-release-metadata'],
    'resolve-release-lock': ['validate-release-metadata', 'require-green-ci'],
    'prepare-m2-signing-controls': [
        'validate-release-metadata', 'require-green-ci', 'resolve-release-lock'],
    'build-release': [
        'validate-release-metadata', 'require-green-ci', 'resolve-release-lock',
        'prepare-m2-signing-controls'],
    'sign-release': ['build-release'],
    'create-release': ['build-release', 'sign-release'],
}

EXPECTED_PROMOTED_JOB_NEEDS = {
    'publish-clawhub': ['validate-promoted-release'],
    'publish-crates': ['validate-promoted-release'],
}


# Jobs that sign, create, or publish a release, or read signing/publish
# secrets. Each must run in the tag-restricted `release` environment.
EXPECTED_RELEASE_ENVIRONMENT_JOBS = ['build-release', 'sign-release', 'create-release']
EXPECTED_PROMOTED_ENVIRONMENT_JOBS = ['publish-clawhub', 'publish-crates']


def parse_workflow_environments(text):
    """Map each job id to its job-level `environment:` value (or None)."""
    environments = {}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if line.startswith('  ') and not line.startswith('   ') \
                and stripped.endswith(':'):
            current = stripped[:-1]
            environments[current] = None
        elif current and line.startswith('    environment:') \
                and not line.startswith('     '):
            environments[current] = stripped[len('environment:'):].strip()
    return environments


def environment_violations(text, expected, workflow_name):
    environments = parse_workflow_environments(text)
    return [f'{job} in {workflow_name} must declare environment: release '
            f'(declared: {environments.get(job)!r})'
            for job in expected if environments.get(job) != 'release']


def parse_workflow_needs(text):
    """Map each release.yml job id to its exact `needs` job ids.

    Covers the two shapes this workflow uses — scalar (`needs: job`) and
    inline list (`needs: [a, b]`) — without a YAML dependency. Ids are
    compared as whole names, never substrings, so a suffixed id such as
    `validate-release-metadata-typo` cannot satisfy a check for
    `validate-release-metadata`.
    """
    needs = {}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if line.startswith('  ') and not line.startswith('   ') \
                and stripped.endswith(':'):
            current = stripped[:-1]
            needs[current] = []
        elif current and stripped.startswith('needs:'):
            value = stripped[len('needs:'):].strip()
            if value.startswith('[') and value.endswith(']'):
                needs[current] = [item.strip() for item in value[1:-1].split(',')
                                  if item.strip()]
            else:
                needs[current] = [value] if value else []
    return needs


def job_needs_violations(text, expected, workflow_name):
    """Return exact-name gating violations for one workflow's jobs."""
    needs = parse_workflow_needs(text)
    violations = []
    # Check every declared edge, including jobs not yet in the expected map.
    # Otherwise a new job can hide a misspelled dependency from this guard.
    for job, dependencies in needs.items():
        for dependency in dependencies:
            if dependency not in needs:
                violations.append(
                    f'{job} needs unknown job {dependency!r} in {workflow_name}')
    for job, dependencies in expected.items():
        if job not in needs:
            violations.append(f'{job} is missing from {workflow_name}')
            continue
        for dependency in dependencies:
            if dependency not in needs[job]:
                violations.append(
                    f'{job} must need {dependency} (declared: {needs[job]}) '
                    'so an invalid ref cannot reach it')
    return violations


def release_job_needs_violations(text):
    return job_needs_violations(
        text, EXPECTED_RELEASE_JOB_NEEDS, 'release.yml')


def promoted_job_needs_violations(text):
    return job_needs_violations(
        text, EXPECTED_PROMOTED_JOB_NEEDS,
        'publish-promoted-release.yml')


class ReleaseCardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in [VALIDATOR, WORKFLOW, PROMOTED_WORKFLOW, CARD,
                     Path('Cargo.toml'), Path('SKILL.md'),
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

    def set_fixture_version(self, version):
        # Rewrite the fixture's three version sources (from the pristine repo
        # copies) so metadata agrees with `version`; a refusal can then only
        # come from the tag gate, not from a metadata mismatch.
        for name, old in (('Cargo.toml', f'version = "{self.version}"'),
                          ('SKILL.md', f'version: {self.version}'),
                          (str(CARD), f'"version": "{self.version}"')):
            text = (ROOT / name).read_text()
            self.assertIn(old, text)
            (self.root / name).write_text(
                text.replace(old, old.replace(self.version, version), 1))

    def test_prerelease_and_build_tags_are_refused_even_when_metadata_matches(self):
        # WHY (charter N3): a release enters the daemon auto-update feed and
        # is published to crates.io and ClawHub. Prerelease/build tags used
        # to clear the ref gate, so one would have shipped as soon as
        # Cargo.toml/SKILL.md/agent.json carried the same suffix. Only exact
        # vMAJOR.MINOR.PATCH may release: refused before any rule runs, with
        # or without --ref, even when every version file agrees with the tag.
        tags = [
            'v0.46.0-rc.1',
            'v0.46.0-alpha',
            'v0.46.0+build',
            'v0.46.0-rc.1+build.5',
            'v1.2.3-0.3.7',
            'v1.2.3-x.7.z.92',
            'v1.2.3+001',
        ]
        for tag in tags:
            self.set_fixture_version(tag[1:])
            for ref in (f'refs/tags/{tag}', None):
                with self.subTest(tag=tag, ref=ref):
                    result = self.run_validator(tag, ref=ref)
                    self.assertEqual(result.returncode, 1,
                                     result.stdout + result.stderr)
                    self.assertIn(
                        'Release must target a valid release tag ref'
                        if ref else
                        'Release tag must be exactly vMAJOR.MINOR.PATCH',
                        result.stderr)
                    self.assertNotIn('Running version_sync', result.stdout)

        # Control: the same fixture rewrite to a plain version releases, so
        # the refusals above are the tag gate and not broken metadata.
        self.set_fixture_version('0.46.0')
        for ref in ('refs/tags/v0.46.0', None):
            with self.subTest(control=ref):
                result = self.run_validator('v0.46.0', ref=ref)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)

    def test_strict_semver_violations_are_refused(self):
        # The old pattern accepted these: `[0-9A-Za-z.-]+` allowed empty
        # dot-separated identifiers, `\d` allowed non-ASCII digits and
        # leading zeros in the core, and `$` matched before a trailing
        # newline. Strict SemVer 2.0.0 must refuse them all.
        refs = [
            'refs/tags/v1.2.3-01',          # numeric prerelease leading zero
            'refs/tags/v1.2.3-rc.01',
            'refs/tags/v1.2.3-rc..1',       # empty prerelease identifier
            'refs/tags/v1.2.3-.rc',
            'refs/tags/v1.2.3-rc.',
            'refs/tags/v1.2.3-',
            'refs/tags/v1.2.3+build..1',    # empty build identifier
            'refs/tags/v1.2.3+.',
            'refs/tags/v1.2.3+build.',
            'refs/tags/v01.2.3',            # numeric core leading zeros
            'refs/tags/v1.02.3',
            'refs/tags/v1.2.03',
            'refs/tags/v١.٢.٣',              # non-ASCII digits in the core
            'refs/tags/v1.2.3\n',           # full-string: trailing newline
            'refs/tags/v1.2.3 extra',
        ]
        for ref in refs:
            with self.subTest(ref=ref.rstrip('\n')):
                result = self.run_validator(ref.rstrip('\n'), ref=ref)
                self.assertEqual(result.returncode, 1,
                                 result.stdout + result.stderr)
                self.assertIn('Release must target a valid release tag ref',
                              result.stderr)

    def test_workflow_validate_step_enforces_strict_semver_shapes(self):
        # The Release workflow's first job passes the real GITHUB_REF to
        # the validator: a plain vX.Y.Z clears the ref gate (failing only on
        # the metadata mismatch); prerelease/build tags and illegal shapes
        # are refused with the ref-gate message before any side effect.
        legal = self.run_release_validate_step('refs/tags/v1.2.3', 'v1.2.3')
        self.assertEqual(legal.returncode, 1, legal.stdout + legal.stderr)
        self.assertNotIn('Release must target a valid release tag ref',
                         legal.stderr)
        self.assertIn('does not match release tag', legal.stdout)

        for ref in ['refs/tags/v0.46.0-rc.1', 'refs/tags/v0.46.0-alpha',
                    'refs/tags/v0.46.0+build',
                    'refs/tags/v1.2.3-rc.1+build.001',
                    'refs/tags/v1.2.3-01', 'refs/tags/v1.2.3-rc..1',
                    'refs/tags/v1.2.3+build.', 'refs/tags/v1.2.3\n',
                    'refs/tags/v1.2.3-rc.1+build.001 extra']:
            with self.subTest(ref=ref.rstrip('\n')):
                result = self.run_release_validate_step(
                    ref, ref[len('refs/tags/'):].rstrip('\n'))
                self.assertEqual(result.returncode, 1,
                                 result.stdout + result.stderr)
                self.assertIn(
                    'Release must target a valid release tag ref refs/tags/vX.Y.Z',
                    result.stderr)

    def test_tag_ref_disagreement_is_refused(self):
        # A --tag that does not name the validated ref would let a caller
        # vouch for metadata the run is not actually building from.
        result = self.run_validator('v' + self.version, ref='refs/tags/v0.42.0')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("does not name the release ref 'refs/tags/v0.42.0'",
                      result.stderr)

    def test_valid_ref_shape_but_mismatched_metadata_fails(self):
        # A well-formed release tag must still fail on the metadata-mismatch
        # rules rather than the ref-form gate.
        result = self.run_validator('v999.0.0', ref='refs/tags/v999.0.0')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('does not match release tag v999.0.0', result.stdout)
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
        for violation in release_job_needs_violations(text):
            with self.subTest(violation=violation):
                self.fail(violation)

        promoted = (ROOT / PROMOTED_WORKFLOW).read_text()
        self.assertIn('types: [published]', promoted)
        self.assertIn('RELEASE_TAG: ${{ github.event.release.tag_name }}', promoted)
        self.assertIn('RELEASE_DRAFT: ${{ github.event.release.draft }}', promoted)
        self.assertIn('RELEASE_PRERELEASE: ${{ github.event.release.prerelease }}', promoted)
        self.assertIn('ref: ${{ github.event.release.tag_name }}', promoted)
        self.assertIn('[ "$RELEASE_DRAFT" = "false" ]', promoted)
        self.assertIn('[ "$RELEASE_PRERELEASE" = "false" ]', promoted)
        self.assertIn('--mode release_tag --tag "$RELEASE_TAG" --ref "refs/tags/$RELEASE_TAG"', promoted)
        for violation in promoted_job_needs_violations(promoted):
            with self.subTest(violation=violation):
                self.fail(violation)

        promoted_gate = self.validator.extract_step_run_block(
            str(PROMOTED_WORKFLOW),
            'Require the published event to match the tagged source')
        base_env = dict(os.environ, RELEASE_TAG=f'v{self.version}',
                        RELEASE_DRAFT='false', RELEASE_PRERELEASE='false')
        accepted = subprocess.run(
            ['bash', '-c', promoted_gate], cwd=self.root,
            capture_output=True, text=True, env=base_env)
        self.assertEqual(accepted.returncode, 0,
                         accepted.stdout + accepted.stderr)
        for overrides in (
                {'RELEASE_DRAFT': 'true'},
                {'RELEASE_PRERELEASE': 'true'},
                {'RELEASE_TAG': 'v999.0.0'},
                # A prerelease tag published without GitHub's prerelease
                # flag must still be refused by the tag gate.
                {'RELEASE_TAG': f'v{self.version}-rc.1'}):
            with self.subTest(overrides=overrides):
                refused = subprocess.run(
                    ['bash', '-c', promoted_gate], cwd=self.root,
                    capture_output=True, text=True,
                    env={**base_env, **overrides})
                self.assertNotEqual(refused.returncode, 0)

        self.assertEqual(
            self.validator.extract_release_unix_bins(str(ROOT / WORKFLOW)),
            ['x0xd', 'x0x'])
        self.assertEqual(
            self.validator.extract_release_windows_bins(str(ROOT / WORKFLOW)),
            ['x0xd.exe', 'x0x.exe'])
        workflow_text = (ROOT / WORKFLOW).read_text()
        packaging_tampers = (
            ('for bin in x0xd x0x; do', 'for bin in x0xd; do'),
            ('for bin in x0xd x0x; do', 'for bin in x0x; do'),
            ('foreach ($bin in @("x0xd.exe", "x0x.exe"))',
             'foreach ($bin in @("x0xd.exe"))'),
            ('foreach ($bin in @("x0xd.exe", "x0x.exe"))',
             'foreach ($bin in @("x0x.exe"))'),
        )
        rule = {
            'level': 'blocking',
            'inputs': [str(ROOT / 'SKILL.md'), str(ROOT / 'scripts/install.sh'), ''],
            'expected_bins': {
                'unix': ['x0xd', 'x0x'],
                'windows': ['x0xd.exe', 'x0x.exe'],
            },
        }
        for declaration, replacement in packaging_tampers:
            with self.subTest(omitted_packaged_binary=replacement):
                before, separator, after = workflow_text.rpartition(declaration)
                self.assertEqual(separator, declaration)
                fixture = self.root / ('tampered-' + str(len(replacement)) + '.yml')
                fixture.write_text(before + replacement + after)
                rule['inputs'][2] = str(fixture)
                state = self.validator.ValidationState()
                self.validator.validate_openclaw_bins(rule, state)
                self.assertTrue(state.failures, 'omitted packaged binary must block')

        for declaration, extractor in (
                ('for bin in x0xd x0x; do', self.validator.extract_release_unix_bins),
                ('foreach ($bin in @("x0xd.exe", "x0x.exe"))',
                 self.validator.extract_release_windows_bins)):
            before, separator, after = workflow_text.rpartition(declaration)
            self.assertEqual(separator, declaration)
            fixture = self.root / ('unknown-' + str(len(declaration)) + '.yml')
            fixture.write_text(before + after)
            with self.assertRaises(ValueError):
                extractor(str(fixture))

    def test_suffixed_dependency_name_fails_the_gate_check(self):
        # Negative control: the old substring check (assertIn(dependency,
        # raw_needs_string)) passed when a job declared
        # `validate-release-metadata-typo`, falsely proving the gate.
        # Exact id comparison must flag both scalar and inline-list forms.
        text = (ROOT / WORKFLOW).read_text()
        tampers = [
            ('needs: validate-release-metadata',
             'needs: validate-release-metadata-typo'),
            ('needs: [validate-release-metadata, require-green-ci]',
             'needs: [validate-release-metadata-typo, require-green-ci]'),
            ('needs: [validate-release-metadata, require-green-ci, resolve-release-lock]',
             'needs: [validate-release-metadata-typo, require-green-ci, resolve-release-lock]'),
        ]
        for original, tampered in tampers:
            with self.subTest(tampered=tampered):
                self.assertIn(original, text)
                self.assertTrue(
                    release_job_needs_violations(text.replace(original, tampered, 1)),
                    f'suffixed dependency {tampered!r} must be flagged')

        promoted = (ROOT / PROMOTED_WORKFLOW).read_text()
        self.assertTrue(promoted_job_needs_violations(
            promoted.replace(
                'needs: validate-promoted-release',
                'needs: validate-promoted-release-typo', 1)))

    def test_tar_packaging_has_exact_custody_members_and_fails_missing_inputs(self):
        block = self.validator.extract_step_run_block(
            str(WORKFLOW), 'Package (tar.gz)')
        platform = 'macos-arm64'
        block = block.replace('${{ matrix.platform }}', platform)
        required = ('x0xd', 'x0x', 'Cargo.lock', 'build-provenance.json')

        def run_case(missing=None):
            case = self.root / ('package-' + (missing or 'complete').replace('.', '-'))
            case.mkdir()
            runner_temp = case / 'runner-temp'
            custody = runner_temp / f'release-{platform}-custody'
            custody.mkdir(parents=True)
            for name in required:
                if name != missing:
                    path = custody / name
                    path.write_bytes((name + '\n').encode())
                    if hasattr(os, 'setxattr'):
                        try:
                            os.setxattr(path, 'user.x0x-test', b'owned')
                        except OSError:
                            pass
            env = dict(os.environ, RUNNER_TEMP=str(runner_temp),
                       GITHUB_ENV=str(case / 'github-env'))
            result = subprocess.run(
                ['bash', '-c', 'set -euo pipefail\n' + block], cwd=case,
                capture_output=True, text=True, env=env)
            return case, result

        case, result = run_case()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tarfile.open(case / f'x0x-{platform}.tar.gz', 'r:gz') as archive:
            self.assertEqual(
                set(archive.getnames()),
                {f'x0x-{platform}',
                 *(f'x0x-{platform}/{name}' for name in required)})
        for missing in required:
            with self.subTest(missing=missing):
                _, failed = run_case(missing)
                self.assertNotEqual(failed.returncode, 0)


class ReleaseEnvironmentAndLockTests(unittest.TestCase):
    LOCK_GUARD_STEP = 'Require committed, current Cargo.lock'

    def test_signing_and_publish_jobs_run_in_release_environment(self):
        # WHY (charter N6): signing keys and publish tokens must only be
        # reachable from the tag-restricted `release` environment, so a
        # rewired job or a branch run cannot sign or publish.
        release = (ROOT / WORKFLOW).read_text()
        promoted = (ROOT / PROMOTED_WORKFLOW).read_text()
        for violation in (
                environment_violations(release, EXPECTED_RELEASE_ENVIRONMENT_JOBS,
                                       'release.yml')
                + environment_violations(promoted, EXPECTED_PROMOTED_ENVIRONMENT_JOBS,
                                         'publish-promoted-release.yml')):
            with self.subTest(violation=violation):
                self.fail(violation)

        # Negative control: dropping one declaration must be flagged.
        tampered = release.replace('    environment: release\n', '', 1)
        self.assertTrue(environment_violations(
            tampered, EXPECTED_RELEASE_ENVIRONMENT_JOBS, 'release.yml'))

        # The environment admits only v* tag refs. release.yml runs on tag
        # pushes (a dispatch is refused off-tag by its first job) and the
        # promotion workflow only on `release: published`, whose GITHUB_REF
        # is refs/tags/<tag_name>. A branch/workflow_run trigger here would
        # be rejected by the environment policy.
        self.assertIn("  push:\n    tags:\n      - 'v*'\n", release)
        self.assertNotIn('workflow_run', release)
        self.assertIn('on:\n  release:\n    types: [published]\n', promoted)
        self.assertNotIn('workflow_run', promoted)

    def test_release_never_regenerates_the_lock(self):
        # WHY (charter D04/D05): the release must ship the Cargo.lock CI
        # tested on the tagged commit. A `cargo generate-lockfile` in the
        # release re-resolved against the live registry at tag time (and
        # dirtied the tracked lock, which custody then refuses).
        release = (ROOT / WORKFLOW).read_text()
        for forbidden in ('generate-lockfile', 'cargo update'):
            self.assertFalse(forbidden in release,
                             f'release.yml must not run `{forbidden}`')
        job = release[release.index('\n  resolve-release-lock:\n'):
                      release.index('\n  build-release:\n')]
        self.assertLess(job.index(f'- name: {self.LOCK_GUARD_STEP}'),
                        job.index('release_artifact_custody.py resolve'))

    @unittest.skipUnless(shutil.which('cargo') and shutil.which('git'),
                         'cargo and git are required to exercise the lock guard')
    def test_lock_guard_refuses_missing_untracked_and_stale_locks(self):
        spec = importlib.util.spec_from_file_location('validator_guard', ROOT / VALIDATOR)
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        guard = validator.extract_step_run_block(str(ROOT / WORKFLOW), self.LOCK_GUARD_STEP)

        def fixture(temp):
            repo = Path(temp)
            for crate in ('app', 'dep'):
                (repo / crate / 'src').mkdir(parents=True)
                (repo / crate / 'src' / 'lib.rs').write_text('')
            (repo / 'dep' / 'Cargo.toml').write_text(
                '[package]\nname = "dep"\nversion = "0.1.0"\nedition = "2021"\n')
            (repo / 'app' / 'Cargo.toml').write_text(
                '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n')
            (repo / 'Cargo.toml').write_text('[workspace]\nmembers = ["app"]\n'
                                             'resolver = "2"\n')
            for command in (['git', 'init', '-q'],
                            ['cargo', 'generate-lockfile', '--offline']):
                subprocess.run(command, cwd=repo, check=True, capture_output=True)
            return repo

        def run(repo):
            return subprocess.run(['bash', '-c', guard], cwd=repo, capture_output=True,
                                  text=True, env=dict(os.environ, GITHUB_SHA='fixture'))

        def track(repo):
            subprocess.run(['git', 'add', '-A'], cwd=repo, check=True)

        with tempfile.TemporaryDirectory() as temp:
            repo = fixture(temp)
            untracked = run(repo)
            self.assertNotEqual(untracked.returncode, 0)
            self.assertIn('Cargo.lock is not committed', untracked.stdout)

            track(repo)
            self.assertEqual(run(repo).returncode, 0, run(repo).stdout)

            # Stale: Cargo.toml gains a dependency the committed lock lacks.
            manifest = repo / 'app' / 'Cargo.toml'
            manifest.write_text(manifest.read_text()
                                + '\n[dependencies]\ndep = { path = "../dep" }\n')
            stale = run(repo)
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn('Committed Cargo.lock is stale', stale.stdout)

            (repo / 'Cargo.lock').unlink()
            missing = run(repo)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn('Cargo.lock is not committed', missing.stdout)


if __name__ == '__main__':
    unittest.main()
