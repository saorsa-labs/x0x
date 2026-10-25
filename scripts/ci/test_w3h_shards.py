#!/usr/bin/env python3
"""The W3-H shard plan covers every case once and keeps S3/S4 on their own shards."""
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'w3h_shards', Path(__file__).with_name('w3h-shards.py'))
SHARDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARDS)


class ShardPlanTest(unittest.TestCase):
    def setUp(self):
        self.names = SHARDS.discover()

    def test_this_tree_discovers_the_long_and_s4_anchors(self):
        # These cases are part of the D196 gate. Discovery must see them
        # so their shard cannot disappear. S3 cases may be absent.
        self.assertGreaterEqual(len(self.names), 100)
        self.assertTrue(any(name.startswith('w3h_1357_') for name in self.names))
        self.assertIn('w3h_1023_control_holders_never_return_fail_closed', self.names)

    def test_every_case_is_in_exactly_one_shard(self):
        assigned = SHARDS.assign(self.names)
        seen = [name for cases in assigned.values() for name in cases]
        self.assertEqual(sorted(seen), self.names)
        self.assertEqual(len(seen), len(set(seen)))

    def test_filter_matches_the_same_cases_as_the_assignment(self):
        import re
        assigned = SHARDS.assign(self.names)
        for group, cases in assigned.items():
            expr = SHARDS.filter_expr(group)
            if group == 'rest':
                excluded = [re.compile(rf'(^|::){prefix}') for _g, prefix in SHARDS.GROUPS]
                matched = [
                    name for name in self.names
                    if not any(pattern.search(name) for pattern in excluded)
                ]
            else:
                prefix = dict(SHARDS.GROUPS)[group]
                pattern = re.compile(rf'(^|::){prefix}')
                matched = [name for name in self.names if pattern.search(name)]
            self.assertEqual(matched, cases, expr)

    def test_s3_and_s4_prefixes_do_not_fall_through_to_rest(self):
        self.assertEqual(SHARDS.group_of('w3h_1356_future_case'), 's3')
        self.assertEqual(SHARDS.group_of('w3h_1357_future_case'), 's4')
        self.assertEqual(SHARDS.group_of('w3h_1023_future_case'), 'long-1023')
        self.assertEqual(SHARDS.group_of('w3h_future_case'), 'rest')

    def test_matrix_omits_an_empty_s3_shard_and_keeps_the_others(self):
        self.assertEqual(
            SHARDS.matrix(['w3h_1023_a', 'w3h_1357_b', 'w3h_other'])['group'],
            ['long-1023', 's4', 'rest'])
        self.assertEqual(
            SHARDS.matrix([
                'w3h_1023_a', 'w3h_1357_b',
                'w3h_1356_red_s3_manual_reseat_recovers_forked_node', 'w3h_other',
            ])['group'],
            ['long-1023', 's4', 's3', 'rest'])

    def test_cli_matrix_is_compact_json(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(SHARDS.main(['--matrix']), 0)
        text = stdout.getvalue().strip()
        self.assertNotIn('\n', text)
        self.assertEqual(json.loads(text), SHARDS.matrix(self.names))


if __name__ == '__main__':
    unittest.main()
