#!/usr/bin/env python3
"""Inert controls only: parsing/routing, never an x0x constructor or socket."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import suite574 as route
import suite574_collect as collector

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT/'ci/suite574/producer-0143.json').read_text())['cases']


def parsed(case):
    return collector.account(case['listing'], case['jsonl'], case['xml'].encode(), case['exit'], tuple(case['target']))


class ProducerContract(unittest.TestCase):
    def test_exact_producer_kind_scoping(self):
        c = CASES['kind']
        r = parsed(c)
        self.assertEqual((r['executed'], r['passed'], r['failed']), (2, 2, 0))
        self.assertEqual(r['target_trace_state'], 'complete')
        self.assertFalse(r['general_acceptance'])
        root = ET.fromstring(c['xml'])
        lib = [e for e in root.findall('./testsuite/testcase') if e.attrib['classname']=='inert-kind-contract' and e.attrib['name']=='tests::same_name'][0]
        other = [e for e in root.findall('./testsuite/testcase') if e.attrib['classname']=='inert-kind-contract::peer' and e.attrib['name']=='tests::same_name'][0]
        self.assertIsNotNone(lib.find('system-out'))
        self.assertIsNone(other.find('system-out'))

    def test_mixed_suite_fragments_not_execution_counts(self):
        r = parsed(CASES['mixed'])
        self.assertEqual((r['selected'], r['executed'], r['passed'], r['failed']), (6, 6, 4, 2))
        self.assertEqual(r['synthetic_ignored_starts'], 2)

    def test_failfast_unstarted_target_is_unrun(self):
        r = parsed(CASES['failfast'])
        self.assertEqual((r['selected'], r['executed'], r['unrun']), (6, 2, 4))
        self.assertEqual(r['target_status'], 'unrun')
        self.assertIsNone(r['trace'])

    def test_same_name_scoped_success(self):
        self.assertEqual(parsed(CASES['scoped'])['passed'], 2)

    def test_foreign_binary_output_is_never_target_trace(self):
        c = copy.deepcopy(CASES['kind']); root = ET.fromstring(c['xml'])
        case = [e for e in root.findall('./testsuite/testcase') if e.attrib['classname'].endswith('::peer') and e.attrib['name']=='tests::same_name'][0]
        ET.SubElement(case, 'system-out').text='DIAG lifecycle574 seq=1 elapsed_us=1 side=Joiner marker=reconnected\nSECRET_FOREIGN_IDENTITY'
        ET.SubElement(case, 'system-err').text='(stdout and stderr are combined)'
        c['xml']=ET.tostring(root,encoding='unicode');r=parsed(c)
        self.assertNotIn('SECRET',json.dumps(r));self.assertEqual(r['trace']['rows'][0]['side'],'Owner')

    def test_duplicate_xml_case(self):
        c=copy.deepcopy(CASES['kind']);r=ET.fromstring(c['xml']);r[0].append(copy.deepcopy(r[0][-1]));c['xml']=ET.tostring(r,encoding='unicode')
        with self.assertRaises(ValueError):parsed(c)

    def test_wrong_binary_classname(self):
        c=copy.deepcopy(CASES['kind']);r=ET.fromstring(c['xml']);r[0][-1].set('classname','inert-kind-contract::peer');c['xml']=ET.tostring(r,encoding='unicode')
        with self.assertRaises(ValueError):parsed(c)

    def test_conflicting_status(self):
        c=copy.deepcopy(CASES['kind']);events=[json.loads(l) for l in c['jsonl'].splitlines()]
        for e in events:
            if e.get('type')=='test' and e.get('event')=='ok':e['event']='failed';break
        c['jsonl']='\n'.join(json.dumps(e) for e in events)
        with self.assertRaises(ValueError):parsed(c)

    def test_timeout_classification_requires_matching_json(self):
        c = copy.deepcopy(CASES['mixed'])
        root = ET.fromstring(c['xml'])
        failed = next(e for e in root.findall('./testsuite/testcase') if e.find('failure') is not None)
        failed.find('failure').set('type', 'test timeout')
        c['xml'] = ET.tostring(root, encoding='unicode')
        with self.assertRaises(ValueError): parsed(c)
        events = [json.loads(line) for line in c['jsonl'].splitlines()]
        binary = next(v for k, v in c['listing']['rust-suites'].items() if k == failed.attrib['classname'])
        name = binary['package-name']+'::'+binary['binary-name']+'$'+failed.attrib['name']
        for event in events:
            if event.get('name') == name and event.get('event') == 'failed':
                event['reason'] = 'time limit exceeded'
        c['jsonl'] = '\n'.join(json.dumps(e) for e in events)
        self.assertEqual(parsed(c)['failure_kinds']['timeout'], 1)

    def test_abort_classification_retained_without_raw_detail(self):
        c = copy.deepcopy(CASES['mixed']); root = ET.fromstring(c['xml'])
        next(e for e in root.iter('failure')).set('type', 'test abort')
        c['xml'] = ET.tostring(root, encoding='unicode')
        self.assertEqual(parsed(c)['failure_kinds']['abort'], 1)

    def test_discovery_count_disagreement_refused(self):
        c = copy.deepcopy(CASES['kind']); c['listing']['test-count'] += 1
        with self.assertRaises(ValueError): parsed(c)

    def test_duplicate_ignored_terminal_refused(self):
        c = copy.deepcopy(CASES['mixed'])
        events = [json.loads(line) for line in c['jsonl'].splitlines()]
        events.append(next(e for e in events if e.get('type') == 'test' and e.get('event') == 'ignored'))
        c['jsonl'] = '\n'.join(json.dumps(e) for e in events)
        with self.assertRaises(ValueError): parsed(c)

    def test_interrupted_prefix_retains_real_started_missing_terminal(self):
        c = CASES['kind']; lines = c['jsonl'].splitlines()
        cutoff = next(i for i, line in enumerate(lines) if json.loads(line).get('event') == 'ok' and json.loads(line).get('type') == 'test')
        prefix = '\n'.join(lines[:cutoff]) + '\n{"type":'
        result = collector.interrupted_prefix(c['listing'], prefix)
        self.assertGreater(result['started_without_terminal'], 0)
        self.assertTrue(result['truncated_last_line'])
        self.assertFalse(result['accounting_valid'])
        self.assertFalse(result['general_acceptance'])
        self.assertNotIn('unrun', json.dumps(result))

    def test_interrupted_prefix_rejects_foreign_identity(self):
        with self.assertRaises(ValueError):
            collector.interrupted_prefix(CASES['kind']['listing'], '{"type":"test","event":"started","name":"foreign"}')

    def test_time_bound_is_explicit_without_widening(self):
        with self.assertRaisesRegex(collector.Invalid, '^NUMBER_BOUND$'):
            collector.number(1901)
        self.assertEqual(collector.number(1900), 1900)

    def test_truncated_xml(self):
        c=copy.deepcopy(CASES['kind']);c['xml']=c['xml'][:-20]
        with self.assertRaises(ET.ParseError):parsed(c)

    def test_truncated_json(self):
        c=copy.deepcopy(CASES['kind']);c['jsonl']=c['jsonl'][:-20]
        with self.assertRaises(ValueError):parsed(c)

    def test_missing_started_test_terminal(self):
        c=copy.deepcopy(CASES['kind']);es=[json.loads(l) for l in c['jsonl'].splitlines()];es=[e for e in es if not(e.get('type')=='test' and e.get('event')=='ok')];c['jsonl']='\n'.join(json.dumps(e) for e in es)
        with self.assertRaises(ValueError):parsed(c)

    def test_duplicate_json_start(self):
        c=copy.deepcopy(CASES['kind']);es=[json.loads(l) for l in c['jsonl'].splitlines()];e=next(e for e in es if e.get('type')=='test' and e.get('event')=='started');es.append(e);c['jsonl']='\n'.join(json.dumps(e) for e in es)
        with self.assertRaises(ValueError):parsed(c)

    def test_interrupted_process_not_false_acceptance(self):
        c=copy.deepcopy(CASES['kind']);c['exit']=143
        with self.assertRaises(ValueError):parsed(c)

    def test_zero_exit_conflicts_with_failure(self):
        c=copy.deepcopy(CASES['mixed']);c['exit']=0
        with self.assertRaises(ValueError):parsed(c)

    def test_unknown_json_identity(self):
        c=copy.deepcopy(CASES['kind']);c['jsonl']+='{"type":"test","event":"started","name":"secret"}\n'
        with self.assertRaises(ValueError):parsed(c)

    def test_entity_declaration_refused(self):
        c=copy.deepcopy(CASES['kind']);c['xml']='<!DOCTYPE testsuites []>'+c['xml']
        with self.assertRaises(ValueError):parsed(c)

    def test_health_query_rows_refused(self):
        c=copy.deepcopy(CASES['kind']);c['xml']=c['xml'].replace('marker=before_old_shutdown','transport_send_ready=Some((true, true)) admission=unavailable')
        with self.assertRaises(ValueError):parsed(c)

    def test_report_config_preserves_all_original_settings(self):
        original=(ROOT/'.config/nextest.toml').read_text()
        result=route.report_config(original,Path('/tmp/inert/report.xml'))
        self.assertIn('kind(=lib)',result);self.assertIn('package(=x0x)',result)
        self.assertTrue(result.startswith(original))

    def test_existing_junit_cannot_be_overridden_silently(self):
        original=(ROOT/'.config/nextest.toml').read_text()+'\n[profile.default.junit]\npath="other.xml"\n'
        with self.assertRaises(ValueError):route.report_config(original,Path('/tmp/inert/report.xml'))

    def test_registered_route_has_no_release_or_parallel_pair(self):
        text=(ROOT/'.github/workflows/build.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('pull_request:',text)
        self.assertNotIn('matrix:',text);self.assertNotIn('cargo publish',text)
        self.assertIn('66786b9abe23920d022a182d1416b1bbc8130dd4872a9553d76985a1708dcd1e',text)
        self.assertIn('RUSTUP_TOOLCHAIN: 1.95.0',text)
        self.assertIn('steps.collect.outputs.receipt_eligible',text)
        self.assertEqual(list(route.FILTERS),['single','suite'])
        self.assertNotIn('--test-threads', (ROOT/'scripts/ci/suite574.py').read_text())


class DiscoveryBinding(unittest.TestCase):
    def setUp(self):
        self.built = {'rust-binaries': {'pkg': {'binary-id': 'pkg', 'binary-name': 'libname',
            'package-id': 'pkg-id', 'kind': 'lib', 'binary-path': './target/libname-abcd', 'build-platform': 'target'}}}
        self.listed = {'rust-suites': {'pkg': {**self.built['rust-binaries']['pkg'], 'package-name': 'pkg'}}}
        self.cargo = {'packages': [{'id': 'pkg-id', 'name': 'pkg'}]}

    def test_same_built_binary_admitted(self):
        route.bind_discovery(self.listed, self.built, self.cargo)

    def test_foreign_binary_path_refused(self):
        self.listed['rust-suites']['pkg']['binary-path'] = './target/other-abcd'
        with self.assertRaises(ValueError): route.bind_discovery(self.listed, self.built, self.cargo)

    def test_missing_built_binary_refused(self):
        self.built['rust-binaries']['other'] = self.built['rust-binaries']['pkg']
        with self.assertRaises(ValueError): route.bind_discovery(self.listed, self.built, self.cargo)

    def test_changed_kind_refused(self):
        self.listed['rust-suites']['pkg']['kind'] = 'test'
        with self.assertRaises(ValueError): route.bind_discovery(self.listed, self.built, self.cargo)

    def test_package_name_bound_to_cargo(self):
        self.listed['rust-suites']['pkg']['package-name'] = 'other'
        with self.assertRaises(ValueError): route.bind_discovery(self.listed, self.built, self.cargo)


class RouteBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scratch = self.root / 'x0x-metadata-inert'
        self.scratch.mkdir()
        route.write(self.scratch/'binaries.json', {})
        route.write(self.scratch/'cargo.json', {})
        route.write(self.root/'build.json', {'scratch': str(self.scratch)})
        for role in route.FILTERS:
            (self.root/role/'evidence'/'x0x-isolation-inert').mkdir(parents=True)
        self.run = {'role': {'role': 'single', 'scratch': self.scratch.name}, 'exit': 0,
                    'supervisor': {'child_exit': 0, 'child_reaped': True, 'reason': None}}
        self.modules = {
            'nextest-reuse.py': {'verify': lambda path: None},
            'isolation-custody-collect.py': {'custody_record': lambda *args: {},
                                           'isolation_record': lambda *args: self.run}}
        for role in route.FILTERS:
            leg = self.root/role
            case = CASES['kind']
            (leg/'junit.xml').write_text(case['xml'])
            (leg/'nextest.jsonl').write_text(case['jsonl'])
            route.write(leg/'selection.json', case['listing'])
            route.write(leg/'runtime.json', {'exit': 0})
        self.enter = []
        for patch in [mock.patch.object(route, 'verify', return_value=None),
                      mock.patch.object(route, 'bind_discovery', return_value=None),
                      mock.patch.object(route, 'module', side_effect=lambda name: self.modules[name]),
                      mock.patch.dict(os.environ, {'GITHUB_SHA': 'a'*40})]:
            patch.start(); self.addCleanup(patch.stop)
        # The actual producer is parsed in ProducerContract above. Here isolate
        # routing decisions from the fixture's different test identity/count.
        patch = mock.patch.object(route, 'account', return_value={'selected': 1})
        patch.start(); self.addCleanup(patch.stop)

    def test_matching_role_source_exit_can_pass_glue(self):
        self.assertTrue(route.leg_receipt(self.root, 'single')['valid'])

    def test_wrong_role_refused(self):
        self.run['role']['role'] = 'suite'
        self.assertFalse(route.leg_receipt(self.root, 'single')['valid'])

    def test_wrong_build_custody_refused(self):
        self.run['role']['scratch'] = 'x0x-metadata-other'
        self.assertFalse(route.leg_receipt(self.root, 'single')['valid'])

    def test_exit_disagreement_refused(self):
        self.run['supervisor']['child_exit'] = 100
        self.assertFalse(route.leg_receipt(self.root, 'single')['valid'])

    def test_unreaped_child_is_interrupted(self):
        self.run['supervisor']['child_reaped'] = False
        result = route.leg_receipt(self.root, 'single')
        self.assertFalse(result['valid']); self.assertTrue(result['interrupted'])

    def test_external_deadline_is_interrupted(self):
        self.run['supervisor']['reason'] = 'deadline'
        result = route.leg_receipt(self.root, 'single')
        self.assertFalse(result['valid']); self.assertTrue(result['interrupted'])

    def test_multiple_isolation_receipts_refused(self):
        (self.root/'single/evidence/x0x-isolation-other').mkdir()
        self.assertFalse(route.leg_receipt(self.root, 'single')['valid'])

    def test_wrong_single_selection_refused(self):
        with mock.patch.object(route, 'account', return_value={'selected': 2}):
            self.assertFalse(route.leg_receipt(self.root, 'single')['valid'])

    def test_accounting_bound_retains_closed_category(self):
        with mock.patch.object(route, 'account', side_effect=collector.Invalid('NUMBER_BOUND')):
            result = route.leg_receipt(self.root, 'single')
            self.assertFalse(result['valid'])
            self.assertIn('ACCOUNTING_BOUND_EXCEEDED', result['errors'])

    def test_private_runner_fields_cannot_leak(self):
        with self.assertRaises(ValueError):
            route.closed_runner({'secret': 'raw peer identity'})

    def test_exhausted_deadline_never_launches(self):
        with mock.patch.dict(os.environ, {'S574_DEADLINE': '0'}), mock.patch.object(route.subprocess, 'run') as run:
            with self.assertRaises(ValueError): route.pair(self.root)
            run.assert_not_called()

    def test_fixed_pair_continues_ordinary_failure_once(self):
        for role in route.FILTERS: (self.root/role/'runtime.json').unlink()
        receipts = [{'valid': True, 'process_exit': 100}, {'valid': True, 'process_exit': 0}]
        with mock.patch.dict(os.environ, {'S574_DEADLINE': '999999999999'}), \
             mock.patch.object(route.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run, \
             mock.patch.object(route, 'leg_receipt', side_effect=receipts):
            self.assertEqual(route.pair(self.root), 100)
            self.assertEqual([c.args[0][-1] for c in run.call_args_list], ['single', 'suite'])
            self.assertTrue(all('-B' in c.args[0] for c in run.call_args_list))
            with self.assertRaises(FileExistsError): route.pair(self.root)
            self.assertEqual(run.call_count, 2)

    def test_invalid_first_leg_aborts_second(self):
        (self.root/'single/runtime.json').unlink()
        with mock.patch.dict(os.environ, {'S574_DEADLINE': '999999999999'}), \
             mock.patch.object(route.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run, \
             mock.patch.object(route, 'leg_receipt', return_value={'valid': False}):
            self.assertEqual(route.pair(self.root), 125)
            self.assertEqual(run.call_count, 1)


class ActualInterruptionReceipts(unittest.TestCase):
    """Use the real closed isolation parser with producer-shaped private files.

    Source/build verification and process launch remain inert mocks; this does
    not execute the Linux supervisor or claim a real signal/namespace run.
    """
    def setUp(self):
        import test_isolation_custody_collect as custody_fixtures
        self.h = RouteBinding('test_matching_role_source_exit_can_pass_glue')
        self.h.setUp(); self.addCleanup(self.h.doCleanups)
        self.leg = self.h.root/'single'
        self.evidence = self.leg/'evidence/x0x-isolation-inert'
        actual = route.runpy.run_path(str(ROOT/'scripts/ci/isolation-custody-collect.py'))
        self.h.modules['isolation-custody-collect.py']['isolation_record'] = actual['isolation_record']
        self.admission = copy.deepcopy(custody_fixtures.ADMISSION)
        self.supervisor = copy.deepcopy(custody_fixtures.SUPERVISOR)
        self.supervisor.update(reason='deadline', child_exit=-15, child_reaped=True)
        route.write(self.evidence/'role.json', {'role': 'single', 'scratch': self.h.scratch.name})
        self.save('admission.json', self.admission)
        self.save('supervisor.json', self.supervisor)
        (self.leg/'runtime.json').write_text(json.dumps({'exit': 124}))
        (self.leg/'junit.xml').unlink()
        case = CASES['kind']; lines = case['jsonl'].splitlines()
        cutoff = next(i for i, line in enumerate(lines) if json.loads(line).get('type') == 'test' and json.loads(line).get('event') == 'ok')
        (self.leg/'nextest.jsonl').write_text('\n'.join(lines[:cutoff])+'\n{"type":')

    def save(self, name, value):
        (self.evidence/name).write_text(json.dumps(value))

    def receipt(self):
        return route.leg_receipt(self.h.root, 'single')

    def assert_partial(self, result):
        self.assertFalse(result['valid'])
        self.assertTrue(result['interrupted'])
        self.assertGreater(result['interrupted_prefix']['started_without_terminal'], 0)
        self.assertFalse(result['interrupted_prefix']['accounting_valid'])
        self.assertNotIn('accounting', result)
        self.assertFalse(result['general_acceptance'])

    def test_deadline124_negative_child_missing_admitted_exit(self):
        result = self.receipt(); self.assert_partial(result)
        self.assertEqual(result['exit_observations'], {'wrapper': 124, 'admitted': None, 'supervisor_child': -15})

    def test_signal125_negative_child_missing_admitted_exit(self):
        self.supervisor['reason'] = 'signal'; self.save('supervisor.json', self.supervisor)
        (self.leg/'runtime.json').write_text('{"exit":125}')
        self.assert_partial(self.receipt())

    def test_caller143_and_pipe_closure_keep_distinct_exits(self):
        self.supervisor['reason'] = 'caller-pipe-closed'; self.save('supervisor.json', self.supervisor)
        (self.leg/'runtime.json').write_text('{"exit":143}')
        result = self.receipt(); self.assert_partial(result)
        self.assertEqual(result['exit_observations']['wrapper'], 143)

    def test_missing_outer_exit_preserves_supervisor_and_prefix(self):
        (self.leg/'runtime.json').unlink()
        result = self.receipt(); self.assert_partial(result)
        self.assertIn('OUTER_EXIT_UNAVAILABLE', result['errors'])
        self.assertIsNone(result['exit_observations']['wrapper'])
        self.assertNotIn('process_exit', result)

    def test_malformed_outer_exit_never_becomes_zero(self):
        (self.leg/'runtime.json').write_text('{"exit":false}')
        result = self.receipt(); self.assert_partial(result)
        self.assertIsNone(result['exit_observations']['wrapper'])

    def test_admitted_exit_can_survive_but_differ(self):
        self.save('exit.json', {'exit': -15})
        result = self.receipt(); self.assert_partial(result)
        self.assertEqual(result['exit_observations']['admitted'], -15)

    def test_negative_child_without_supervisor_reason_is_incomplete(self):
        self.supervisor['reason'] = None; self.save('supervisor.json', self.supervisor)
        (self.leg/'runtime.json').write_text('{"exit":143}')
        self.assert_partial(self.receipt())

    def test_bad_namespace_prevents_prefix_attribution(self):
        self.admission['namespace_changed'] = False; self.save('admission.json', self.admission)
        result = self.receipt()
        self.assertFalse(result['valid']); self.assertNotIn('interrupted_prefix', result)

    def test_malformed_supervisor_prevents_prefix_attribution(self):
        self.supervisor['child_exit'] = False; self.save('supervisor.json', self.supervisor)
        result = self.receipt()
        self.assertFalse(result['valid']); self.assertNotIn('interrupted_prefix', result)

    def test_normal_completion_still_requires_admitted_exit(self):
        self.supervisor.update(reason=None, child_exit=0); self.save('supervisor.json', self.supervisor)
        (self.leg/'runtime.json').write_text('{"exit":0}')
        result = self.receipt()
        self.assertFalse(result['valid']); self.assertNotIn('interrupted_prefix', result)

    def test_actual_interrupted_receipt_stops_pair_before_b(self):
        (self.leg/'runtime.json').unlink()
        with mock.patch.dict(os.environ, {'S574_DEADLINE': '999999999999'}), \
             mock.patch.object(route.subprocess, 'run', return_value=mock.Mock(returncode=124)) as run:
            self.assertEqual(route.pair(self.h.root), 125)
            self.assertEqual(run.call_count, 1)
            self.assertFalse((self.h.root/'suite/started').exists())
            self.assert_partial(route.read(self.leg/'closed.json'))


if __name__=='__main__':
    unittest.main()
