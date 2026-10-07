#!/usr/bin/env python3
"""Unit tests for scripts/ci/w3h-trace-check.py (the W3-H determinism gate)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'w3h_trace_check', Path(__file__).with_name('w3h-trace-check.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

TRACE = '# w3h canonical trace v1 seed=0x1\n[marks]\n  @0us case c entropy=controlled\n'


class TraceCheckTest(unittest.TestCase):
    def write(self, directory, name, text):
        Path(directory, name).write_text(text)

    def test_identical_traces_pass(self):
        with tempfile.TemporaryDirectory() as d:
            for pid in range(3):
                self.write(d, f'w3h_case-{pid}.trace', TRACE)
            self.assertEqual(CHECK.check(d, 3, ['w3h_case']), [])

    def test_divergent_traces_are_reported_not_blocking(self):
        # D196: the gate is verdict-stable; trace identity is reported.
        with tempfile.TemporaryDirectory() as d:
            self.write(d, 'w3h_case-1.trace', TRACE)
            self.write(d, 'w3h_case-2.trace', TRACE.replace('@0us', '@5us'))
            self.assertEqual(CHECK.check(d, 2, ['w3h_case']), [])

    def test_divergent_trace_fails_with_strict_traces(self):
        with tempfile.TemporaryDirectory() as d:
            self.write(d, 'w3h_case-1.trace', TRACE)
            self.write(d, 'w3h_case-2.trace', TRACE.replace('@0us', '@5us'))
            problems = CHECK.check(d, 2, [], strict_traces=True)
            self.assertEqual(len(problems), 1)
            self.assertIn('2 distinct traces', problems[0])
            self.assertIn('first divergence', problems[0])
            self.assertIn('@5us', problems[0])

    def test_appendix_is_not_compared(self):
        with tempfile.TemporaryDirectory() as d:
            for pid, stop in enumerate(('@9us', '@12us')):
                self.write(d, f'w3h_case-{pid}.trace',
                           f'{TRACE}{CHECK.APPENDIX}\n  {stop} teardown verified\n')
            self.assertEqual(CHECK.check(d, 2, ['w3h_case']), [])

    def test_divergence_before_the_appendix_still_fails(self):
        with tempfile.TemporaryDirectory() as d:
            tail = f'{CHECK.APPENDIX}\n  @9us teardown verified\n'
            self.write(d, 'w3h_case-1.trace', TRACE + tail)
            self.write(d, 'w3h_case-2.trace', TRACE.replace('@0us', '@5us') + tail)
            problems = CHECK.check(d, 2, [], strict_traces=True)
            self.assertEqual(len(problems), 1)
            self.assertIn('@5us', problems[0])

    def test_wrong_run_count_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.write(d, 'w3h_case-1.trace', TRACE)
            self.assertIn('w3h_case: 1 traces, expected 20', CHECK.check(d, 20, []))

    def test_uncontrolled_entropy_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.write(d, 'w3h_case-1.trace', TRACE.replace('controlled', 'uncontrolled'))
            self.assertTrue(any('not controlled' in p for p in CHECK.check(d, 1, [])))

    def test_empty_directory_fails_without_requirements(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(CHECK.main([d, '--runs', '20']), 1)
            self.assertTrue(any('nothing was checked' in p for p in CHECK.check(d, 20, [])))

    def test_missing_required_case_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn('w3h_missing: no trace written', CHECK.check(d, 1, ['w3h_missing']))

    def receipt(self, d, pid, verdict, stages=None, case='w3h_red', ok=True):
        import json
        if stages is None:
            stages = ('setup_done', 'evidence', 'request_delivered', 'final')
            if verdict == 'RED':
                stages = ('setup_done', 'evidence', 'request_delivered', 'cause', 'final')
        body = {'schema': 'w3h.receipt/1', 'case': case, 'verdict': verdict,
                'stages': [self.stage(stage, verdict, ok) for stage in stages]}
        self.write(d, f'{case}-{pid}.receipt.json', json.dumps(body))

    @staticmethod
    def stage(kind, verdict, ok):
        if kind in ('evidence', 'request_delivered', 'cause'):
            return {'stage': kind, 'name': kind, 'ok': ok}
        if kind == 'final':
            return {'stage': kind, 'name': 'final', 'passed': verdict == 'GREEN'}
        return {'stage': kind}

    def test_expected_red_receipts_pass(self):
        with tempfile.TemporaryDirectory() as d:
            for pid in range(2):
                self.receipt(d, pid, 'RED')
            self.assertEqual(CHECK.check_receipts(d, 2, ['w3h_red=RED']), [])

    def test_infra_receipt_is_not_red(self):
        with tempfile.TemporaryDirectory() as d:
            self.receipt(d, 1, 'RED')
            self.receipt(d, 2, 'INFRA')
            problems = CHECK.check_receipts(d, 2, ['w3h_red=RED'])
            self.assertTrue(any('verdict INFRA' in p for p in problems), problems)

    def test_expected_green_receipts_pass(self):
        with tempfile.TemporaryDirectory() as d:
            for pid in range(2):
                self.receipt(d, pid, 'GREEN', case='w3h_ctl')
            self.assertEqual(CHECK.check_receipts(d, 2, ['w3h_ctl=GREEN']), [])

    def test_verdicts_that_differ_across_reruns_fail(self):
        with tempfile.TemporaryDirectory() as d:
            self.receipt(d, 1, 'GREEN', case='w3h_ctl')
            self.receipt(d, 2, 'INFRA', case='w3h_ctl', stages=('setup_done',))
            problems = CHECK.check_receipts(d, 2, ['w3h_ctl=GREEN'])
            self.assertTrue(any('verdicts differ across reruns' in p for p in problems), problems)

    def test_green_receipt_needs_every_precondition(self):
        with tempfile.TemporaryDirectory() as d:
            self.receipt(d, 1, 'GREEN', case='w3h_ctl',
                         stages=('setup_done', 'request_delivered', 'final'))
            problems = CHECK.check_receipts(d, 1, ['w3h_ctl=GREEN'])
            self.assertTrue(any("lacks stages ['evidence']" in p for p in problems), problems)

    def test_false_evidence_stage_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.receipt(d, 1, 'GREEN', case='w3h_ctl', ok=False)
            problems = CHECK.check_receipts(d, 1, ['w3h_ctl=GREEN'])
            self.assertTrue(any('false evidence stage' in p for p in problems), problems)

    def test_red_receipt_missing_cause_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.receipt(d, 1, 'RED', stages=('setup_done', 'evidence', 'request_delivered', 'final'))
            problems = CHECK.check_receipts(d, 1, ['w3h_red=RED'])
            self.assertTrue(any("lacks stages ['cause']" in p for p in problems), problems)


if __name__ == '__main__':
    unittest.main()
