#!/usr/bin/env python3
"""Synthetic closed receipts only: no Git, Cargo, Agent or namespace execution."""
import copy
import importlib.util
import json
import io
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('convergence_custody', Path(__file__).with_name('issue442-convergence-custody.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class Custody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='issue442-custody-inert-')
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.head, self.tree, self.binary = 'a' * 40, 'b' * 40, 'c' * 64
        self.nonce = C.prepare(self.workspace, self.head, [self.head, self.tree])
        self.root = self.workspace / 'ci-evidence/issue442'
        self.build = dict(source_head=self.head, source_tree=self.tree, target_binaries=['target/debug/deps/x0x-0123456789abcdef'], inputs={'target/debug/deps/x0x-0123456789abcdef': self.binary})
        self.custody = dict(valid=True, build_custody=[self.build], isolation_runs=[])
        self.value = self.complete_value()
        self.write()

    def complete_value(self):
        topology = {name: dict(agent_id=str(i) * 64, machine_id=str(i + 3) * 64) for i, name in enumerate(('s', 'r', 'd'), 1)}
        phases, sent, received = {}, [], []
        for i, name in enumerate(C.PHASES):
            positive = name != 'downgrade'
            rid = str(i + 1) * 32
            phases[name] = dict(request_id=rid, outcome='observed', delivery_count=int(positive), extra_count=0, unrelated_count=0, window_ms=300, forwarded_before=i, forwarded_after=i + int(positive), refused_before=0, refused_after=int(not positive), extension_present=name != 'legacy', baseline_present=name != 'legacy')
            event = dict(request_id=rid, sender=topology['s']['agent_id'], destination=topology['d']['agent_id'], digest_present=name == 'bound', hop=topology['s']['machine_id'], prefix=topology['s']['agent_id'], sent_wire=None, classification=dict(kind='forward', destination=topology['d']['agent_id']) if positive else dict(kind='refuse', reason='missing_inner_digest'))
            received.append(event)
            if positive:
                wire = copy.deepcopy(event)
                wire.update(hop=topology['r']['agent_id'], sent_wire=dict(length=100, sha256='d' * 64), classification=None)
                sent.append(wire)
        return dict(schema='x0x.issue442-phases/1', run_nonce=self.nonce, source_head=self.head, source_tree=self.tree, selector=C.SELECTOR, binary_sha256=self.binary, status='completed', checkpoint='cleanup', topology=topology, preconditions=dict(zip(C.PRE, (True, True, True, False, True, False))), phases=phases, service_observation=dict(overflow=False, poisoned=False, events=[dict(kind='pending_skip'), dict(kind='enqueue', requester=topology['s']['agent_id'], carrier='critical', payload_sha256='e' * 64, accepted=True), dict(kind='consumed'), dict(kind='pending_skip')]), relay_observations={name: dict(overflow=False, poisoned=False, decode_failed=False, events=events) for name, events in [('s', sent), ('r', received), ('d', [])]})

    def write(self):
        claim = dict(schema='x0x.issue442-claim/1', run_nonce=self.nonce, selector=C.SELECTOR, binary_sha256=self.binary)
        (self.root / 'claim.json').write_text(json.dumps(claim))
        # Rust's serde_json maps sort keys; validation must not depend on JSON ordering.
        (self.root / 'phases.json').write_text(json.dumps(self.value, sort_keys=True))

    def result(self, expect='success'):
        return C.compose(self.root, self.nonce, self.custody, expect, self.head)

    def test_complete_and_binary_correlated(self):
        result = self.result()
        self.assertTrue(result['valid'])
        self.assertEqual(result['phase_status'], 'completed')
        C.BASE.assert_no_leak(result)
        self.assertNotIn(str(self.workspace), json.dumps(result))

    def test_enqueue_observation_may_follow_consumption(self):
        # try_send publishes before its caller records success; do not order
        # observational events as though the producer held the receiver lock.
        enqueue = self.value['service_observation']['events'][1]
        self.value['service_observation']['events'] = [dict(kind='consumed'), dict(kind='pending_skip'), enqueue]
        self.write()
        self.assertTrue(self.result()['valid'])

    def test_prepare_is_exclusive_and_event_bound(self):
        with self.assertRaises(C.Rejected):
            C.prepare(self.workspace, self.head, [self.head, self.tree])
        other = self.workspace / 'fresh'
        other.mkdir()
        with self.assertRaises(C.Rejected):
            C.prepare(other, 'f' * 40, [self.head, self.tree])
        self.assertFalse((other / 'ci-evidence').exists())

    def test_partial_failure_retains_facts_without_success(self):
        self.value.update(status='partial', checkpoint='legacy')
        self.value['phases']['bound'] = None
        self.value['phases']['downgrade'] = None
        self.write()
        self.custody['valid'] = False
        self.custody['isolation_runs'] = [dict(exit=100, supervisor=dict(child_reaped=True))]
        result = self.result('failure')
        self.assertFalse(result['valid'])
        self.assertEqual(result['phase_status'], 'partial')
        self.assertEqual(result['phases']['phases']['legacy']['delivery_count'], 1)
        self.assertEqual(result['custody']['isolation_runs'][0]['exit'], 100)
        self.assertIn(dict(stage='test', code='TEST_NOT_SUCCESS'), result['errors'])

    def test_started_and_absent_are_not_green(self):
        self.value.update(status='started', checkpoint='entry', topology=None, service_observation=None)
        self.value['phases'] = dict.fromkeys(C.PHASES)
        self.value['preconditions'] = dict.fromkeys(C.PRE)
        self.value['relay_observations'] = dict.fromkeys(('s', 'r', 'd'))
        self.write()
        self.assertFalse(self.result()['valid'])
        self.assertEqual(self.result('failure')['phase_status'], 'partial')
        (self.root / 'phases.json').unlink()
        self.assertEqual(self.result()['phase_status'], 'absent')

    def test_nonce_source_and_binary_mismatches(self):
        for field, wrong in [('run_nonce', 'f' * 32), ('source_head', 'f' * 40), ('source_tree', 'f' * 40), ('binary_sha256', 'f' * 64)]:
            with self.subTest(field=field):
                saved = self.value[field]
                self.value[field] = wrong
                self.write()
                self.assertFalse(self.result()['valid'])
                self.value[field] = saved
        self.write()
        self.build['inputs'][self.build['target_binaries'][0]] = 'f' * 64
        self.assertFalse(self.result()['valid'])

    def test_unhealthy_or_contradictory_completed_phases_refused(self):
        original = copy.deepcopy(self.value)
        mutations = [lambda v: v['service_observation'].update(overflow=True), lambda v: v['relay_observations']['r'].update(poisoned=True), lambda v: v['relay_observations']['s'].update(decode_failed=True), lambda v: v['phases']['downgrade'].update(delivery_count=1), lambda v: v['phases']['bound'].update(forwarded_after=1), lambda v: v['phases']['bound'].update(baseline_present=False), lambda v: v['relay_observations']['r']['events'][2].update(classification=dict(kind='refuse', reason='stale')), lambda v: v['phases']['bound'].update(request_id=v['phases']['legacy']['request_id'])]
        for mutation in mutations:
            self.value = copy.deepcopy(original)
            mutation(self.value)
            self.write()
            self.assertFalse(self.result()['valid'])

    def test_schema_types_bounds_and_unknown_fields(self):
        original = copy.deepcopy(self.value)
        mutations = [lambda v: v.update(payload='secret'), lambda v: v['phases']['legacy'].update(delivery_count=True), lambda v: v['phases']['legacy'].update(extra_count=-1), lambda v: v['service_observation'].update(events=[dict(kind='pending_skip')] * 17), lambda v: v['relay_observations']['s']['events'][0]['sent_wire'].update(sha256='/home/private'), lambda v: v['phases']['legacy'].update(delivery_count=1 << 64)]
        for mutation in mutations:
            self.value = copy.deepcopy(original)
            mutation(self.value)
            self.write()
            self.assertEqual(self.result()['phase_status'], 'rejected')
        # Reject both the old field alone and a loose alias alongside classification.
        self.value = copy.deepcopy(original)
        self.write()
        self.assertTrue(self.result()['valid'])
        for keep_classification in (False, True):
            with self.subTest(keep_classification=keep_classification):
                self.value = copy.deepcopy(original)
                event = self.value['relay_observations']['r']['events'][0]
                event['disposition'] = event['classification']
                if not keep_classification:
                    del event['classification']
                self.write()
                result = self.result()
                self.assertEqual(result['phase_status'], 'rejected')
                self.assertIn(dict(stage='phase', code='INPUT_SCHEMA'), result['errors'])
        (self.root / 'phases.json').write_text(' ' * (65536 + 1))
        self.assertFalse(self.result()['valid'])
        (self.root / 'phases.json').write_text('{"schema":1,"schema":2}')
        self.assertFalse(self.result()['valid'])

    def test_symlink_foreign_files_and_stale_output(self):
        (self.root / 'phases.json').unlink()
        (self.root / 'phases.json').symlink_to(self.root / 'descriptor.json')
        self.assertEqual(self.result()['phase_status'], 'rejected')
        (self.root / 'phases.json').unlink()
        self.write()
        (self.root / 'foreign').write_text('not copied')
        self.assertEqual(self.result()['phase_status'], 'rejected')
        output = self.workspace / 'output'
        C.BASE.exclusive_output(output)
        with self.assertRaises(C.BASE.Rejected):
            C.BASE.exclusive_output(output)

    def test_complete_phase_cannot_hide_missing_custody_or_failed_test(self):
        self.custody['valid'] = False
        self.assertFalse(self.result()['valid'])
        self.custody['valid'] = True
        self.assertFalse(self.result('failure')['valid'])
        self.assertFalse(self.result('cancelled')['valid'])
        self.assertFalse(C.compose(self.root, None, self.custody, 'success', self.head)['valid'])

    def test_output_failure_never_marks_eligible(self):
        output = self.workspace / 'new-output'
        C.BASE.exclusive_output(output)
        with patch.object(C.BASE.os, 'open', side_effect=OSError('inert write failure')):
            with self.assertRaises(OSError):
                C.BASE.write_receipt(output, self.result())
        self.assertEqual(list(output.iterdir()), [])

    def real_inputs(self):
        runner_temp = tempfile.TemporaryDirectory(prefix='issue442-runner-inert-')
        self.addCleanup(runner_temp.cleanup)
        runner = Path(runner_temp.name).resolve()
        self.assertFalse(runner.is_relative_to(self.workspace))
        metadata = runner / 'x0x-metadata-inert'
        isolated = runner / 'x0x-isolation-inert'
        metadata.mkdir()
        isolated.mkdir()
        binary = self.workspace / 'target/debug/deps/x0x-0123456789abcdef'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'never executed')
        binary.chmod(0o700)
        files = {str(binary): self.binary}
        for path, digest in [(self.workspace / 'Cargo.lock', 'd' * 64), (metadata / 'cargo.json', 'e' * 64), (metadata / 'binaries.json', 'f' * 64)]:
            path.write_text('{}')
            files[str(path)] = digest
        (metadata / 'custody.json').write_text(json.dumps(dict(source=[self.head, self.tree], files=files)))
        (metadata / 'lock.sha256').write_text('d' * 64 + '  Cargo.lock\n')
        (isolated / 'role.json').write_text(json.dumps(dict(role='acceptance', scratch=metadata.name)))
        (isolated / 'admission.json').write_text(json.dumps(dict(namespace='net:[12345]', namespace_changed=True, links=[dict(ifname='lo')], routes={'-4': [], '-6': []}, uid=1001, gid=1001, capabilities={k: '0' * 16 for k in C.BASE.CAPABILITY_KEYS}, no_new_privs=1)))
        (isolated / 'supervisor.json').write_text(json.dumps(dict(reason=None, child_pid=1234, child_exit=0, child_reaped=True, seconds=1.0)))
        (isolated / 'exit.json').write_text(json.dumps(dict(exit=0)))
        return runner, metadata, isolated

    def test_actual_collector_entrypoint_retains_closed_artifact(self):
        runner, _, _ = self.real_inputs()
        output = self.workspace / 'github-output'
        env = dict(GITHUB_WORKSPACE=str(self.workspace), GITHUB_SHA=self.head, RUNNER_TEMP=str(runner), X0X_CUSTODY_EXPECT='success', X0X_ISSUE442_NONCE=self.nonce, GITHUB_OUTPUT=str(output))
        with patch.dict(os.environ, env, clear=True), patch.object(C.sys, 'argv', ['collector', 'collect']), patch.object(C.subprocess, 'check_output', side_effect=AssertionError('no Git/commands in collect')), redirect_stdout(io.StringIO()):
            self.assertEqual(C.main(), 0)
        result = json.loads((runner / 'x0x-issue442-receipt/custody-receipt.json').read_text())
        self.assertTrue(result['valid'])
        self.assertTrue(result['custody']['isolation_runs'][0]['supervisor']['child_reaped'])
        self.assertEqual(result['custody']['build_custody'][0]['lock_sha256'], 'd' * 64)
        self.assertEqual(output.read_text(), 'receipt_eligible=true\n')
        self.assertNotIn(str(self.workspace), json.dumps(result))

    def test_actual_base_missing_exit_lock_and_role_fail_closed(self):
        runner, metadata, isolated = self.real_inputs()
        baseline = C.BASE.collect(runner, 'success', self.head, self.workspace, ['acceptance'], 'x0x', 1)
        self.assertTrue(baseline['valid'])
        self.assertTrue(C.compose(self.root, self.nonce, baseline, 'success', self.head)['valid'])
        self.assertEqual(set(baseline['build_custody'][0]['inputs']), {'Cargo.lock', 'binaries.json', 'cargo.json', 'target/debug/deps/x0x-0123456789abcdef'})
        changes = [(metadata / 'lock.sha256', 'e' * 64 + '  Cargo.lock\n'), (isolated / 'exit.json', None), (isolated / 'supervisor.json', json.dumps(dict(reason=None, child_pid=1234, child_exit=0, child_reaped=False, seconds=1))), (isolated / 'role.json', json.dumps(dict(role='other', scratch=metadata.name)))]
        for path, replacement in changes:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                if replacement is None:
                    path.unlink()
                else:
                    path.write_text(replacement)
                custody = C.BASE.collect(runner, 'success', self.head, self.workspace, ['acceptance'], 'x0x', 1)
                result = C.compose(self.root, self.nonce, custody, 'success', self.head)
                self.assertFalse(result['valid'])
                self.assertFalse(result['custody']['valid'])
                path.write_bytes(original)
                restored = C.BASE.collect(runner, 'success', self.head, self.workspace, ['acceptance'], 'x0x', 1)
                self.assertTrue(restored['valid'])
                self.assertTrue(C.compose(self.root, self.nonce, restored, 'success', self.head)['valid'])
        (isolated / 'exit.json').write_text(json.dumps(dict(exit=100)))
        custody = C.BASE.collect(runner, 'failure', self.head, self.workspace, ['acceptance'], 'x0x', 1)
        result = C.compose(self.root, self.nonce, custody, 'failure', self.head)
        self.assertFalse(result['valid'])
        self.assertEqual(result['custody']['isolation_runs'][0]['exit'], 100)
        self.assertIsNotNone(result['phases'])

    def test_workflow_keeps_command_and_closed_upload(self):
        workflow = Path(__file__).resolve().parents[2].joinpath('.github/workflows/ci.yml').read_text()
        job = workflow[workflow.index('  test:'):workflow.index('  coverage:')]
        self.assertIn("run: bash scripts/ci/nextest-isolated.sh --all-features --workspace -- -E '!binary(x0x_0041_synthetic_kill_restart)'", job)
        self.assertIn('X0X_ISOLATION_ROLE: acceptance', job)
        self.assertIn('X0X_CUSTODY_EXPECT: ${{ steps.tests.outcome }}', job)
        self.assertIn("if: always() && steps.collect_convergence.outputs.receipt_eligible == 'true'", job)
        self.assertIn('path: ${{ runner.temp }}/x0x-issue442-receipt/custody-receipt.json', job)
        self.assertNotIn('continue-on-error', job)
        self.assertNotIn('unittest discover', workflow)


if __name__ == '__main__':
    unittest.main()
