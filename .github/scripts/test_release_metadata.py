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
    'build-release': [
        'validate-release-metadata', 'require-green-ci', 'resolve-release-lock'],
    'sign-release': ['build-release'],
    'create-release': ['build-release', 'sign-release'],
}

EXPECTED_PROMOTED_JOB_NEEDS = {
    'publish-clawhub': ['validate-promoted-release'],
    'publish-crates': ['validate-promoted-release'],
}


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

    def test_strict_semver_prerelease_build_shapes_pass_ref_gate(self):
        # SemVer 2.0.0 (semver.org): prerelease identifiers split by '.',
        # each numeric-without-leading-zero or alphanumeric; build
        # identifiers may be numeric WITH leading zeros. Every legal
        # shape must clear the ref gate (and only then fail here on the
        # metadata mismatch against this fixture's 0.45.0 files).
        refs = [
            'refs/tags/v1.2.3-rc.1',
            'refs/tags/v1.2.3-0.3.7',
            'refs/tags/v1.2.3-x.7.z.92',
            'refs/tags/v1.2.3-0a.1-b',
            'refs/tags/v1.2.3+build.001',
            'refs/tags/v1.2.3+001',
            'refs/tags/v1.2.3-rc.1+build.5',
        ]
        for ref in refs:
            with self.subTest(ref=ref):
                result = self.run_validator(ref[len('refs/tags/'):], ref=ref)
                self.assertEqual(result.returncode, 1,
                                 result.stdout + result.stderr)
                self.assertNotIn('Release must target a valid release tag ref',
                                 result.stderr)
                self.assertIn('Release tag version:', result.stdout)

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
        # the validator: legal prerelease/build metadata clears the ref
        # gate (failing only on the metadata mismatch), illegal shapes
        # are refused with the ref-gate message before any side effect.
        legal = self.run_release_validate_step(
            'refs/tags/v1.2.3-rc.1+build.001', 'v1.2.3-rc.1+build.001')
        self.assertEqual(legal.returncode, 1, legal.stdout + legal.stderr)
        self.assertNotIn('Release must target a valid release tag ref',
                         legal.stderr)
        self.assertIn('does not match release tag', legal.stdout)

        for ref in ['refs/tags/v1.2.3-01', 'refs/tags/v1.2.3-rc..1',
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
                {'RELEASE_TAG': 'v999.0.0'}):
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


if __name__ == '__main__':
    unittest.main()
