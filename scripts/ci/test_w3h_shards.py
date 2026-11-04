#!/usr/bin/env python3
"""The W3-H shard plan covers every case once and keeps S3/S4 on their own shards."""
import importlib.util
import io
import json
import tempfile
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
        # One rerun of each H-S3-c/c2/c3/d8/d3 row is the longest S3 case,
        # so each row runs its 20 reruns on its own runner(s).
        rows = {
            's3-c': 'w3h_1356_red_s3_c_promoted_admin_reseats_owner_axis_node',
            's3-c2': 'w3h_1356_red_s3_c2_reseat_retires_marker_and_gap',
            's3-c3': 'w3h_1356_control_s3_c3_owner_reseats_owner_axis_node',
            's3-d8': 'w3h_1356_control_s3_d8_removal_basis_reseats_owner_axis_node',
            's3-d3': 'w3h_1356_control_s3_d3_authorisation_refusals_typed',
            's3-1661': 'w3h_1356_red_1661_welcome_lost_after_readmission_ends_typed',
        }
        assigned = SHARDS.assign(self.names)
        for group, name in rows.items():
            self.assertEqual(assigned.get(group), [name])
        self.assertEqual(SHARDS.group_of(
            'w3h_1356_red_s3_c_promoted_admin_reseats_owner_axis_node_more'), 's3')
        self.assertFalse(set(rows.values()) & set(assigned.get('s3', [])))

    def test_rm4_variants_share_their_own_shard(self):
        # The H-S3-rm4 variants run the H-S3-c prefix, so they stay out of
        # `s3` and share one split shard.
        assigned = SHARDS.assign(self.names)
        rm4 = [name for name in self.names if name.startswith('w3h_1356_control_s3_rm4_')]
        self.assertTrue(rm4)
        self.assertEqual(sorted(assigned.get('s3-rm4', [])), sorted(rm4))
        self.assertFalse(set(rm4) & set(assigned.get('s3', [])))

    def test_split_parts_run_the_full_rerun_count_together(self):
        # D196: the gate counts exactly RUNS receipts per case, so the
        # parts of a split group add up to RUNS and run the same filter.
        self.assertEqual(SHARDS.RUNS, 20)
        for group, parts in SHARDS.PARTS.items():
            entries = [f'{group}.{k}' for k in range(1, parts + 1)]
            self.assertEqual(sum(SHARDS.stress_count(e) for e in entries), SHARDS.RUNS)
            for entry in entries:
                self.assertEqual(SHARDS.filter_expr(entry), SHARDS.filter_expr(group))
            with self.assertRaises(SystemExit):
                SHARDS.stress_count(group)
            with self.assertRaises(SystemExit):
                SHARDS.stress_count(f'{group}.{parts + 1}')
        self.assertEqual(SHARDS.stress_count('s3'), 20)
        self.assertEqual(SHARDS.stress_count('rest'), 20)
        with self.assertRaises(SystemExit):
            SHARDS.stress_count('s3.1')
        with self.assertRaises(SystemExit):
            SHARDS.stress_count('no-such-group')

    def test_matrix_lists_a_split_group_as_its_parts(self):
        groups = SHARDS.matrix(
            ['w3h_1356_control_s3_d3_authorisation_refusals_typed', 'w3h_other'])['group']
        self.assertEqual(groups, ['s3-d3.1', 's3-d3.2', 's3-d3.3', 's3-d3.4', 'rest'])

    def test_tag_traces_keeps_the_case_and_makes_parts_distinct(self):
        case = 'w3h_1356_control_s3_d3_authorisation_refusals_typed'
        files = [f'{case}-4242.trace', f'{case}-4242.receipt.json',
                 f'{case}-4242.kv', 'notes.txt']
        with tempfile.TemporaryDirectory() as directory:
            for name in files:
                (Path(directory) / name).write_text('x')
            self.assertEqual(SHARDS.tag_traces('s3-d3.2', directory), 3)
            names = sorted(path.name for path in Path(directory).iterdir())
            self.assertEqual(names, sorted([
                f'{case}-p2_4242.trace', f'{case}-p2_4242.receipt.json',
                f'{case}-p2_4242.kv', 'notes.txt']))
            for name in (n for n in names if n != 'notes.txt'):
                stem = name[:-len('.receipt.json')] if name.endswith('.receipt.json') \
                    else name.rpartition('.')[0]
                self.assertEqual(stem.rpartition('-')[0], case)
            self.assertEqual(SHARDS.tag_traces('s3', directory), 0)

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
