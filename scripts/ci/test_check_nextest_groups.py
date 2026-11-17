#!/usr/bin/env python3
"""Unit tests for scripts/ci/check-nextest-groups.py."""
import importlib.util
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('check_nextest_groups', HERE / 'check-nextest-groups.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def errors(text):
    return CHECK.check(tomllib.loads(text))


class CheckNextestGroups(unittest.TestCase):
    def test_repository_config_passes(self):
        with CHECK.CONFIG.open('rb') as handle:
            self.assertEqual(CHECK.check(tomllib.load(handle)), [])

    def test_paired_overrides_with_one_weight_pass(self):
        self.assertEqual(errors('''
[[profile.default.overrides]]
filter = "test(a)"
test-group = "g"
threads-required = 4
[[profile.default.overrides]]
filter = "test(b)"
test-group = "g"
threads-required = 4
[[profile.default.overrides]]
filter = "test(c)"
slow-timeout = "60s"
'''), [])

    def test_mixed_weights_in_one_group_fail(self):
        found = errors('''
[[profile.default.overrides]]
filter = "test(a)"
test-group = "g"
threads-required = 4
[[profile.default.overrides]]
filter = "test(b)"
test-group = "g"
threads-required = 1
''')
        self.assertEqual(len(found), 1)
        self.assertIn("mixes threads-required", found[0])

    def test_mixed_weights_across_profiles_fail(self):
        found = errors('''
[[profile.default.overrides]]
filter = "test(a)"
test-group = "g"
threads-required = 4
[[profile.ci.overrides]]
filter = "test(b)"
test-group = "g"
threads-required = 2
''')
        self.assertEqual(len(found), 1)

    def test_weight_only_override_fails(self):
        # It may match a grouped test and give it another weight.
        found = errors('''
[[profile.default.overrides]]
filter = "test(a)"
test-group = "g"
threads-required = 1
[[profile.default.overrides]]
filter = "test(a)"
threads-required = 4
''')
        self.assertEqual(len(found), 1)
        self.assertIn("sets only one", found[0])

    def test_group_only_override_fails(self):
        # Its weight would come from another override that matches.
        found = errors('''
[[profile.default.overrides]]
filter = "test(a)"
test-group = "g"
''')
        self.assertEqual(len(found), 1)
        self.assertIn("sets only one", found[0])


if __name__ == '__main__':
    unittest.main()
