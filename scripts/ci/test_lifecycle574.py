#!/usr/bin/env python3
"""Inert source guards, pinned producer formats and closed upload controls."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('lifecycle574', HERE / 'lifecycle574.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)
C = __import__('runpy').run_path(str(HERE / 'isolation-custody-collect.py'))
HEAD, TREE = 'a' * 40, 'b' * 40
PREFIX = 'DIAG lifecycle574 '
SUMMARY = PREFIX + 'stop=collectors_joined total=1 overflow=0 foreign=[0, 0] lagged=[0, 0] stream_closed=[false, false] pending_at_stop=[0, 0] collectors_dropped=[true, true] acceptance=not_evaluated'
TRACE = PREFIX + 'seq=1 elapsed_us=1 side=Owner marker=before_old_shutdown\n' + SUMMARY


def producer(terminal='ok', qualified=m.QUALIFIED):
    meta = {'crate': 'x0x', 'test_binary': 'x0x', 'kind': 'lib'}
    # Exact observed0.9.126 shape: one selected nonignored case but two
    # filtered ignored cases contribute to suite counts, not execution.
    return [json.dumps(v) for v in [
        {'type': 'suite', 'event': 'started', 'test_count': 3, 'nextest': meta},
        {'type': 'test', 'event': 'started', 'name': qualified},
        {'type': 'test', 'event': terminal, 'name': qualified, 'exec_time': 0.01},
        {'type': 'suite', 'event': terminal, 'passed': int(terminal == 'ok'),
         'failed': int(terminal == 'failed'), 'ignored': 2, 'measured': 0,
         'filtered_out': 2787, 'exec_time': 0.01, 'nextest': meta}]]


def selected():
    return {'rust-suites': {'x0x': {'kind': 'lib', 'binary-name': 'x0x',
        'package-name': 'x0x', 'status': 'listed', 'testcases': {
            m.TEST: {'kind': 'test', 'ignored': False, 'filter-match': {'status': 'matches'}},
            'other': {'kind': 'test', 'ignored': True, 'filter-match': {'status': 'mismatch'}}}}}}


class Guards(unittest.TestCase):
    def test_exact_sha_guard_rejects_ref_drift_dirty_and_injection(self):
        m.guard(HEAD, HEAD, HEAD, '')
        for args in [(HEAD, TREE, HEAD, ''), (HEAD, HEAD, HEAD, ' M src/x.rs'),
                     ('main', 'main', 'main', ''), ('$(id)', HEAD, HEAD, ''),
                     ('A'*40, 'A'*40, 'A'*40, '')]:
            with self.assertRaises(ValueError): m.guard(*args)

    def test_source_and_lock_drift_fail_actual_recheck(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);old=Path.cwd();os.chdir(root)
            try:
                (root/'input.rs').write_text('frozen')
                (root/'Cargo.lock').write_bytes((HERE.parents[1]/'ci/lifecycle574/Cargo.lock.fixture').read_bytes())
                answers={('rev-parse','HEAD'):HEAD,('rev-parse','HEAD^{tree}'):TREE,('status','--porcelain'):''}
                with patch.object(m,'git',side_effect=lambda *args:answers[args]),patch.object(m.subprocess,'check_output',return_value=b'input.rs\0'),patch.dict(os.environ,{'EXPECTED_COMMIT':HEAD,'GITHUB_SHA':HEAD}):
                    m.write(root/'source.json',m.source_snapshot())
                    m.verify_source(root)
                    (root/'input.rs').write_text('changed')
                    with self.assertRaises(ValueError):m.verify_source(root)
                    (root/'input.rs').write_text('frozen');(root/'Cargo.lock').write_text('different lock')
                    with self.assertRaises(ValueError):m.verify_source(root)
            finally:os.chdir(old)

    def test_isolated_guard_rejects_root_before_any_test_launcher(self):
        with patch.object(m.os,'geteuid',return_value=0),patch.object(m.subprocess,'run') as launch:
            with self.assertRaises(ValueError):m.isolated(Path('/unused'))
            launch.assert_not_called()

    def test_exact_single_lib_selector_not_empty_other_extra_or_ignored(self):
        self.assertEqual(m.selection(selected())['matched'], 1)
        for change in ('empty', 'extra', 'ignored', 'target'):
            value = selected(); suite = value['rust-suites']['x0x']
            if change == 'empty': suite['testcases'][m.TEST]['filter-match']['status'] = 'mismatch'
            if change == 'extra': suite['testcases']['other']['filter-match']['status'] = 'matches'
            if change == 'ignored': suite['testcases'][m.TEST]['ignored'] = True
            if change == 'target': suite['kind'] = 'test'
            with self.assertRaises(ValueError): m.selection(value)

    def test_pinned_nextest_one_terminal_positive_failure_and_false_selection(self):
        self.assertEqual(m.nextest(producer())['terminal'], 'ok')
        self.assertEqual(m.nextest(producer('failed'))['terminal'], 'failed')
        for lines in [[], producer()[:-1], producer()+producer(), producer(qualified='other'),
                      producer()[:2]+producer()[1:], ['not json'], producer('ignored')]:
            with self.assertRaises((ValueError, KeyError)): m.nextest(lines)
        wrong = producer(); v=json.loads(wrong[-1]);v['passed']=True;wrong[-1]=json.dumps(v)
        with self.assertRaises(ValueError): m.nextest(wrong)

    def test_closed_trace_preserves_generations_reasons_and_rejects_raw(self):
        details = ['lifecycle=Established { generation: 1 }',
                   'lifecycle=Replaced { old_generation: 1, new_generation: 2 }',
                   'lifecycle=Closing { generation: 1, reason: Superseded }',
                   'lifecycle=Closed { generation: 1, reason: Superseded }',
                   'lifecycle=ReaderExited { generation: 1 }',
                   'transport_send_ready=Some((true, false)) admission=unavailable',
                   'transport_send_ready=None admission=unavailable', 'publish_attempted=Some(0)', 'lagged=2']
        text='\n'.join(PREFIX+f'seq={i} elapsed_us={i} side=Joiner {value}' for i,value in enumerate(details,1))
        receipt=m.trace_rows(text+'\n'+SUMMARY.replace('total=1 ', 'total=9 ').replace('lagged=[0, 0]', 'lagged=[0, 2]'))
        self.assertEqual(receipt['rows'][3]['generation'],1)
        self.assertEqual(receipt['rows'][3]['reason'],'Superseded')
        self.assertTrue(receipt['evidence_gaps'])
        for text in [TRACE+'\n'+SUMMARY, TRACE.replace('seq=1','seq=2'), TRACE.replace('elapsed_us=1','elapsed_us=999999999999999'),
                     TRACE.replace('marker=before_old_shutdown','peer=ghp_SECRET'),
                     TRACE.replace('marker=before_old_shutdown','lifecycle=Closed { generation: 1, reason: /Users/private }'),
                     TRACE.replace('total=1 ', 'total=2 '), TRACE.replace('admission=unavailable','admission=admitted')+'\n'+PREFIX+'junk']:
            with self.assertRaises(ValueError): m.trace_rows(text)

    def test_gap_flags_never_general_acceptance(self):
        for token, replacement in [('overflow=0','overflow=1'),('lagged=[0, 0]','lagged=[1, 0]'),
                                   ('pending_at_stop=[0, 0]','pending_at_stop=[0, 1]'),
                                   ('stop=collectors_joined','stop=abort_requested_on_drop'),
                                   ('collectors_dropped=[true, true]','collectors_dropped=[true, false]')]:
            text=TRACE.replace(token,replacement)
            if token=='overflow=0':text=text.replace('total=1','total=2')
            value=m.trace_rows(text);self.assertTrue(value['evidence_gaps']);self.assertFalse(value['general_acceptance'])

    def test_real_inert_producer_fixture_contract(self):
        # Same shape captured from actual pinned nextest inert control run.
        lines=(HERE.parents[1]/'ci/lifecycle574/inert-nextest.jsonl').read_text().splitlines()
        name=json.loads(lines[1])['name']
        self.assertEqual(m.nextest(lines, name)['started'],1)
        self.assertEqual(m.selection(selected())['kind'],'lib')

    def test_workflow_has_only_guarded_manual_diagnostic_and_exact_upload(self):
        text=(HERE.parents[1]/'.github/workflows/build.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('pull_request:',text);self.assertNotIn('  push:',text)
        self.assertNotIn('release:',text);self.assertNotIn('build-matrix:',text)
        self.assertIn('expected_commit:',text);self.assertIn('refs/heads/codex/574-lifecycle-diagnostic',text)
        self.assertIn("steps.collect.outputs.receipt_eligible == 'true'",text)
        self.assertIn('path: ${{ env.L574_SAFE }}/diagnostic.json',text)
        source=(HERE/'lifecycle574.py').read_text()
        self.assertIn("'--retries', '0'",source);self.assertIn("'--no-tests', 'fail'",source)
        self.assertNotIn('peer_admission(',source)


class ProducerCollector(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.workspace=Path(self.tmp.name)/'workspace';self.workspace.mkdir()
        self.runner=Path(self.tmp.name)/'runner';self.runner.mkdir()
        self.root=self.runner/'raw';self.root.mkdir();self.out=self.root/'safe'
        self.meta=self.runner/'x0x-metadata-abc';self.meta.mkdir()
        self.iso=self.runner/'x0x-isolation-abc';self.iso.mkdir()
        self.binary=self.workspace/'target/debug/deps/x0x-12345678';self.binary.parent.mkdir(parents=True);self.binary.write_bytes(b'inert executable');self.binary.chmod(0o755)
        lock=HERE.parents[1]/'ci/lifecycle574/Cargo.lock.fixture';(self.workspace/'Cargo.lock').write_bytes(lock.read_bytes())
        self.source={'head':HEAD,'tree':TREE,'files':{'dummy':'c'*64}}
        self.put(self.root/'source.json',self.source)
        self.put(self.root/'build.json',{'scratch':str(self.meta),'binary_sha256':m.digest(self.binary)})
        self.put(self.meta/'cargo.json',{});self.put(self.meta/'binaries.json',{})
        paths=[self.workspace/'Cargo.lock',self.meta/'cargo.json',self.meta/'binaries.json',self.binary]
        self.put(self.meta/'custody.json',{'files':{str(p):m.digest(p) for p in paths},'source':[HEAD,TREE]})
        (self.meta/'lock.sha256').write_text(m.LOCK+'  Cargo.lock\n')
        self.put(self.iso/'role.json',{'role':'diagnostic','scratch':self.meta.name})
        self.put(self.iso/'admission.json',{'namespace':'net:[42]','namespace_changed':True,'links':[{'ifname':'lo'}],
            'routes':{'-4':[{'dev':'lo','dst':'127.0.0.0/8'}],'-6':[]},'uid':1001,'gid':1001,
            'capabilities':{k:'0000000000000000' for k in C['CAPABILITY_KEYS']},'no_new_privs':1})
        self.put(self.iso/'supervisor.json',{'reason':None,'child_pid':42,'child_exit':0,'child_reaped':True,'seconds':20.1})
        self.put(self.iso/'exit.json',{'exit':0});self.put(self.root/'runtime.json',{'exit':0})
        self.put(self.root/'selection.json',m.selection(selected()))
        (self.root/'nextest.log').write_text('\n'.join(producer()))
        (self.root/'nextest.stderr').write_text('private unrelated /Users/raw ghp_SECRET\n'+TRACE)
        self.outputs=self.runner/'github-output'

    def put(self,path,value):path.write_text(json.dumps(value))

    def call(self):
        old=Path.cwd();os.chdir(self.workspace)
        try:
            # Source/graph guards are separately tested; use actual R3 consumer
            # against producer-shaped files/target permissions/scratch below.
            with patch.object(m,'verify_source',return_value=self.source),patch.object(m,'reuse',return_value={'verify':lambda _:None}),patch.dict(os.environ,{'RUNNER_TEMP':str(self.runner),'GITHUB_SHA':HEAD,'GITHUB_OUTPUT':str(self.outputs)}):
                return m.collect(self.root,self.out)
        finally:os.chdir(old)

    def test_success_one_lib_role_and_no_raw_upload(self):
        self.assertEqual(self.call(),0)
        value=json.loads((self.out/'diagnostic.json').read_text())
        self.assertTrue(value['evidence_valid']);self.assertTrue(value['diagnostic_test_passed'])
        self.assertFalse(value['general_acceptance']);self.assertEqual(value['custody']['observed_roles'],['diagnostic'])
        self.assertEqual(self.outputs.read_text(),'receipt_eligible=true\n')
        self.assertEqual(list(p.name for p in self.out.iterdir()),['diagnostic.json'])
        text=(self.out/'diagnostic.json').read_text();self.assertNotIn('SECRET',text);self.assertNotIn('/Users/',text)

    def test_failed_test_retains_valid_evidence_without_pass_credit(self):
        for p in [self.root/'runtime.json',self.iso/'exit.json']:self.put(p,{'exit':100})
        p=self.iso/'supervisor.json';v=m.read(p);v['child_exit']=100;self.put(p,v)
        (self.root/'nextest.log').write_text('\n'.join(producer('failed')))
        self.assertEqual(self.call(),0)
        value=m.read(self.out/'diagnostic.json');self.assertTrue(value['evidence_valid']);self.assertFalse(value['diagnostic_test_passed'])

    def test_wrong_scratch_is_refused_even_for_diagnostic_role(self):
        self.put(self.iso/'role.json',{'role':'diagnostic','scratch':'x0x-metadata-other'})
        self.assertEqual(self.call(),1);self.assertIn('CUSTODY_OR_BINDING',m.read(self.out/'diagnostic.json')['errors'])
        self.assertTrue(self.outputs.exists())

    def test_cancel_or_unreaped_is_not_valid_failed_evidence(self):
        p=self.iso/'supervisor.json';v=m.read(p);v['reason']='deadline';v['child_reaped']=False;self.put(p,v)
        self.assertEqual(self.call(),1)

    def test_output_exists_or_symlink_never_sets_upload_eligible(self):
        self.out.symlink_to(self.root)
        with self.assertRaises(Exception):self.call()
        self.assertFalse(self.outputs.exists())

    def test_existing_regular_output_is_never_upload_eligible(self):
        self.out.mkdir();(self.out/'diagnostic.json').write_text('stale-secret')
        with self.assertRaises(Exception):self.call()
        self.assertFalse(self.outputs.exists())
        self.assertEqual((self.out/'diagnostic.json').read_text(),'stale-secret')

    def test_malformed_trace_is_withheld_and_partial_closed_receipt_retained(self):
        (self.root/'nextest.stderr').write_text(PREFIX+'peer=ghp_SECRET')
        self.assertEqual(self.call(),1)
        text=(self.out/'diagnostic.json').read_text();self.assertNotIn('SECRET',text);self.assertNotIn('trace',json.loads(text))

    def test_binary_digest_mismatch_and_source_failure_are_not_credited(self):
        self.put(self.root/'build.json',{'scratch':str(self.meta),'binary_sha256':'d'*64})
        self.assertEqual(self.call(),1)


if __name__=='__main__':unittest.main()
