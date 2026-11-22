#!/usr/bin/env python3
"""Pin the train/* bundle-PR skip in the PR workflows.

A job may skip only a PR that meets all three terms of RUN_UNLESS_TRAIN_BUNDLE:
a `train/*` head branch, a head repository that is this repository, and an
author in the bundle-author list. A branch name alone must never stand in for
CI. Each workflow defines the condition once as the YAML anchor
`&run-unless-train-bundle` and every other job uses `*run-unless-train-bundle`;
a workflow with one job writes the condition in place (an unused anchor is an
actionlint error).

The check reads workflow text only. It needs no YAML library and starts nothing.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
FILES = (
    'ci.yml', 'build.yml', 'integration.yml', 'security.yml',
    'release-custody-check.yml', 'python-client-example.yml',
    'adr-governance.yml',
)

# The bundle-author list. Change it here and in the seven anchors together.
BUNDLE_AUTHORS = '["dirvine"]'
RUN_UNLESS_TRAIN_BUNDLE = (
    "${{ !(github.event_name == 'pull_request'"
    " && startsWith(github.head_ref, 'train/')"
    " && github.event.pull_request.head.repo.full_name == github.repository"
    " && contains(fromJSON('" + BUNDLE_AUTHORS + "'), github.event.pull_request.user.login)) }}"
)
ANCHOR = '    if: &run-unless-train-bundle ' + RUN_UNLESS_TRAIN_BUNDLE
ALIAS = '    if: *run-unless-train-bundle'
PLAIN = '    if: ' + RUN_UNLESS_TRAIN_BUNDLE

# Jobs that never run on a pull request keep their own condition.
OTHER_CONDITIONS = {
    ('build.yml', 'build-matrix'): "github.event_name != 'pull_request'",
    ('integration.yml', 'integration-timing'): "github.event_name == 'schedule'",
    ('integration.yml', 'soak'): "github.event_name == 'schedule'",
}

REQUIRED_TERMS = (
    "startsWith(github.head_ref, 'train/')",
    'github.event.pull_request.head.repo.full_name == github.repository',
    'github.event.pull_request.user.login',
)


def jobs(text):
    """Map job id to the job's text, from the top-level `jobs:` key."""
    body = text[text.index('\njobs:\n') + len('\njobs:\n'):]
    parts = re.split(r'^  ([\w-]+):\n', body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2]))


def violations(name, text):
    found = []
    for line in text.splitlines():
        if line.lstrip().startswith('#') or 'train/' not in line:
            continue
        if line not in (ANCHOR, PLAIN):
            found.append(f'{name}: train/ skip differs from the pinned condition: {line.strip()}')
    lines = text.splitlines()
    if lines.count(ANCHOR) != (1 if ALIAS in lines else 0):
        found.append(f'{name}: needs one &run-unless-train-bundle anchor exactly when a job uses the alias')
    for job, body in jobs(text).items():
        conditions = [line for line in body.splitlines() if line.startswith('    if:')]
        other = OTHER_CONDITIONS.get((name, job))
        if other is not None:
            if conditions != ['    if: ' + other]:
                found.append(f'{name}: {job} must keep `if: {other}`')
        elif conditions not in ([ANCHOR], [ALIAS], [PLAIN]):
            found.append(f'{name}: {job} lacks the run-unless-train-bundle condition')
    return found


def workflow_violations():
    found = []
    for name in FILES:
        found.extend(violations(name, (WORKFLOWS / name).read_text()))
    return found


class TrainBundleSkip(unittest.TestCase):
    def test_pinned_condition_has_all_three_terms(self):
        for term in REQUIRED_TERMS:
            self.assertIn(term, RUN_UNLESS_TRAIN_BUNDLE)
        self.assertTrue(RUN_UNLESS_TRAIN_BUNDLE.startswith("${{ !(github.event_name == 'pull_request' && "))

    def test_workflows_carry_the_pinned_condition(self):
        self.assertEqual(workflow_violations(), [])

    def test_weakened_or_missing_conditions_fail(self):
        text = (WORKFLOWS / 'ci.yml').read_text()
        same_repo = ' && github.event.pull_request.head.repo.full_name == github.repository'
        author = " && contains(fromJSON('" + BUNDLE_AUTHORS + "'), github.event.pull_request.user.login)"
        broken = {
            'no same-repo term': text.replace(same_repo, '', 1),
            'no author term': text.replace(author, '', 1),
            'other author': text.replace('"dirvine"', '"dirvine", "someone"', 1),
            'branch name only': text.replace(ALIAS, "    if: ${{ !startsWith(github.head_ref, 'train/') }}", 1),
            'job without condition': text.replace(ALIAS + '\n', '', 1),
            'second anchor': text.replace(ALIAS, ANCHOR, 1),
        }
        for label, tampered in broken.items():
            with self.subTest(label):
                self.assertNotEqual(tampered, text)
                self.assertTrue(violations('ci.yml', tampered))


if __name__ == '__main__':
    sys.exit(unittest.main())
