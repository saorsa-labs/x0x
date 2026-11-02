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

        def matches(pattern, name):
            return re.search(rf'(^|::){pattern}', name) is not None

        assigned = SHARDS.assign(self.names)
        names = [group for group, _pattern in SHARDS.GROUPS]
        for group, cases in assigned.items():
            expr = SHARDS.filter_expr(group)
            if group == 'rest':
                earlier, own = SHARDS.GROUPS, None
            else:
                earlier = SHARDS.GROUPS[:names.index(group)]
                own = dict(SHARDS.GROUPS)[group]
            matched = [
                name for name in self.names
                if (own is None or matches(own, name))
                and not any(matches(pattern, name) for _g, pattern in earlier)
            ]
            self.assertEqual(matched, cases, expr)

    def test_each_owner_axis_row_has_its_own_shard(self):
        # One rerun of each H-S3-c/c2 row is the longest S3 case, so each
        # row runs its 20 reruns on its own runner.
        rows = {
            's3-c': 'w3h_1356_red_s3_c_promoted_admin_reseats_owner_axis_node',
            's3-c2': 'w3h_1356_red_s3_c2_reseat_retires_marker_and_gap',
        }
        assigned = SHARDS.assign(self.names)
        for group, name in rows.items():
            self.assertEqual(assigned.get(group), [name])
        self.assertEqual(SHARDS.group_of(
            'w3h_1356_red_s3_c_promoted_admin_reseats_owner_axis_node_more'), 's3')
        self.assertFalse(set(rows.values()) & set(assigned.get('s3', [])))

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
