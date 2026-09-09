#!/usr/bin/env python3
"""Constructor-free reporter/custody/retention controls; no x0x runtime."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('evidence', Path(__file__).with_name('issue501-component-evidence.py'))
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
S = e.SELECTORS[0]


def frame(status='PASS', selector=S, binary='x0x', payload='private identity sentinel'):
    return (f'────────────\n Nextest run ID 01234567-abcd with nextest profile: default\n'
            f'    Starting 1 test across 1 binary (2 tests skipped)\n'
            f'        {status} [   0.011s] (1/1) {binary} {selector}\n'
            '  stdout ───\n\n    running 1 test\n    test result: ok.\n'
            f'  stderr ───\n    {payload}\n'
            f'    Starting 1 test across 1 binary (9 tests skipped)\n'
            f'        PASS [   0.001s] (1/1) {binary} {selector}\n'
            f'        FAIL [   0.002s] (1/1) {binary} {selector}\n'
            '     Summary [   0.003s] 1 test run: 1 passed, 9 skipped\n\n'
            '────────────\n     Summary [   0.012s] 1 test run: '
            + ('1 passed, 2 skipped\n' if status == 'PASS' else '0 passed, 1 failed, 2 skipped\n')) .encode()


def results():
    return [{'ordinal': i, 'selector': s, 'status': 'UNRUN'} for i, s in enumerate(e.SELECTORS, 1)]


class Controls(unittest.TestCase):
    def test_exact_five_argv_no_retry_or_unfenced_discovery(self):
        for s in e.SELECTORS:
            a = e.runtime_argv(s)
            self.assertEqual(a[:2], ['bash', 'scripts/ci/nextest-isolated.sh'])
            self.assertEqual(a[a.index('--retries') + 1], '0')
            self.assertEqual(a[-1], 'package(=x0x) & binary(=x0x) & kind(=lib) & test(=' + s + ')')
            self.assertIn('--success-output', a)
        with self.assertRaises(e.Rejected): e.runtime_argv('foreign')

    def test_immediate_frames_exclude_fake_payload_rows_and_extract_exact_bytes(self):
        count, stderr, lines = e.parse_report(frame(), S)
        self.assertEqual(count, dict(selected=1, ran=1, passed=1, failed=0))
        self.assertTrue(stderr.startswith(b'private identity sentinel\n'))
        self.assertIn(b'    FAIL ', stderr)
        self.assertTrue(lines)

    def test_actual_failure_with_recap_cannot_become_pass(self):
        raw = frame('FAIL') + f'        FAIL [   0.011s] (1/1) x0x {S}\nerror: test run failed\n'.encode()
        with self.assertRaisesRegex(e.Rejected, 'TEST_FAILED'): e.parse_report(raw, S)

    def test_wrong_binary_same_name(self):
        with self.assertRaisesRegex(e.Rejected, 'TERMINAL_IDENTITY'): e.parse_report(frame(binary='x0x::other'), S)

    def test_wrong_test_same_binary(self):
        with self.assertRaisesRegex(e.Rejected, 'TERMINAL_IDENTITY'): e.parse_report(frame(selector='foreign'), S)

    def test_zero_selection(self):
        with self.assertRaises(e.Rejected): e.parse_report(frame().replace(b'Starting 1 test', b'Starting 0 test', 1), S)

    def test_missing_duplicate_real_terminal(self):
        row = f'        PASS [   0.011s] (1/1) x0x {S}\n'.encode()
        for replacement in (b'', row + row):
            with self.assertRaisesRegex(e.Rejected, 'TERMINAL_COUNT'): e.parse_report(frame().replace(row, replacement, 1), S)

    def test_truncation_and_conflicting_summary(self):
        for raw in (frame().rsplit('────────────'.encode(), 1)[0], frame().replace(b'1 passed, 2 skipped', b'0 passed, 1 failed')):
            with self.assertRaises(e.Rejected): e.parse_report(raw, S)

    def test_single_slow_success_summary_is_valid(self):
        # Actual nextest143 Suite grammar: 3552 passed (8 slow), 300 skipped.
        # This exact-selector route admits only one executed/passed/slow test.
        for summary in (b'1 passed (1 slow), 2 skipped', b'1 passed (1 slow)'):
            raw=frame().replace(b'1 passed, 2 skipped',summary)
            self.assertEqual(e.parse_report(raw,S)[0]['passed'],1)

    def test_slow_summary_cannot_hide_failed_or_excess_counts(self):
        for summary in (b'1 passed (0 slow), 2 skipped', b'1 passed (2 slow), 2 skipped',
                        b'1 passed (8 slow), 300 skipped', b'2 passed (1 slow), 2 skipped',
                        b'0 passed (1 slow), 1 failed', b'1 passed (1 slow), 1 failed',
                        b'1 passed (1 slow), 1 unrun', b'1 passed (1 slow) (1 slow)'):
            with self.assertRaises(e.Rejected):e.parse_report(frame().replace(b'1 passed, 2 skipped',summary),S)

    def test_duplicate_output_channel_and_indented_separator(self):
        with self.assertRaises(e.Rejected): e.parse_report(frame().replace(b'  stderr ', b'  stdout '), S)
        self.assertEqual(e.parse_report(frame(payload='────────────'), S)[0]['passed'], 1)

    def test_stop_first_failure_remainder_unrun(self):
        calls = []
        def execute(i, s):
            calls.append(i); return {'ordinal': i, 'selector': s, 'status': 'PASS' if i == 1 else 'FAIL'}
        r = e.execute_sequence(execute)
        self.assertEqual(calls, [1, 2]); self.assertEqual([x['status'] for x in r], ['PASS', 'FAIL', 'UNRUN', 'UNRUN', 'UNRUN'])

    def test_incomplete_also_stops(self):
        self.assertEqual([x['status'] for x in e.execute_sequence(lambda i, s: {'ordinal': i, 'selector': s, 'status': 'INCOMPLETE'})], ['INCOMPLETE'] + ['UNRUN'] * 4)

    def test_closed_custody_reaping_source_lock_admission(self):
        source = {'head': 'a' * 40, 'tree': 'b' * 40}; reuse = {'scratch': 'x0x-metadata-one'}
        a = dict(interfaces=['lo'], no_new_privs=1, **{k: True for k in ('namespace_changed', 'all_routes_dev_lo', 'no_default_route', 'no_gateway_route', 'unprivileged_uid', 'capability_sets_empty')})
        good = {'valid': True, 'status': 'complete', 'isolation_runs': [{'role': {'role': 'acceptance', 'scratch': reuse['scratch']}, 'supervisor': {'reason': None, 'child_exit': 0, 'child_reaped': True}, 'exit': 0, 'admission': a}], 'build_custody': [{'source_head': source['head'], 'source_tree': source['tree'], 'lock_sha256': e.LOCK}]}
        self.assertTrue(e.validate_closed(good, source, reuse)['child_reaped'])
        for mutate in (lambda x: x['isolation_runs'][0]['supervisor'].update(child_reaped=False), lambda x: x['build_custody'][0].update(lock_sha256='0'*64), lambda x: x['build_custody'][0].update(source_tree='c'*40), lambda x: x['isolation_runs'][0]['admission'].update(interfaces=['lo','eth0']), lambda x: x['isolation_runs'][0].update(exit=-15)):
            bad = copy.deepcopy(good); mutate(bad)
            with self.assertRaises(e.Rejected): e.validate_closed(bad, source, reuse)

    def test_reject_symlinks_crossroot_and_oversize(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve(); file = root/'a'; file.write_text('data'); link=root/'link'; link.symlink_to(file)
            self.assertEqual(e.regular(file, root), file)
            for path, scope, limit in [(link,root,100), (file,root/'other',100), (file,root,1)]:
                if not scope.exists(): scope.mkdir()
                with self.assertRaises(e.Rejected): e.regular(path,scope,limit)

    def test_actual_reuse_input_hashes_and_binary_identity(self):
        with tempfile.TemporaryDirectory() as t:
            ws=Path(t).resolve()/'ws';ws.mkdir();target=ws/'target';target.mkdir();rt=Path(t).resolve()/'runner';rt.mkdir();scratch=rt/'x0x-metadata-one';scratch.mkdir()
            (ws/'Cargo.lock').write_bytes(Path(__file__).with_name('issue501-component.lock').read_bytes())
            binary=target/'x0x-inert';binary.write_bytes(b'inert binary bytes, never executed')
            metadata={'rust-build-meta':{'target-directory':str(target),'non-test-binaries':{}},'rust-binaries':{'x0x':{'binary-name':'x0x','kind':'lib','binary-path':str(binary)}}}
            (scratch/'binaries.json').write_text(json.dumps(metadata));(scratch/'cargo.json').write_text('{}');(scratch/'lock.sha256').write_text(e.LOCK+'  Cargo.lock\n')
            source={'head':'a'*40,'tree':'b'*40}
            paths=[binary,ws/'Cargo.lock',scratch/'binaries.json',scratch/'cargo.json']
            custody={'files':{str(p):e.digest(p) for p in paths},'source':[source['head'],source['tree']]}
            (scratch/'custody.json').write_text(json.dumps(custody))
            self.assertEqual(e.validate_reuse(ws,rt,source)['binary_sha256'],e.digest(binary))
            binary.write_bytes(b'changed binary')
            with self.assertRaisesRegex(e.Rejected,'REUSE_INPUT_HASH'):e.validate_reuse(ws,rt,source)
            binary.write_bytes(b'inert binary bytes, never executed')
            with self.assertRaisesRegex(e.Rejected,'REUSE_SOURCE'):e.validate_reuse(ws,rt,{'head':'c'*40,'tree':'b'*40})
            (rt/'x0x-metadata-stale').mkdir()
            with self.assertRaisesRegex(e.Rejected,'SCRATCH_COUNT'):e.validate_reuse(ws,rt,source)

    def test_public_schema_rejects_identity_and_wrong_types(self):
        for field,value in [('private_peer','SENTINEL'), ('code','peer:secret'), ('binary_sha256','SENTINEL'), ('wrapper_exit',True)]:
            r=results();r[0][field]=value
            with self.assertRaises(e.Rejected): e.public_results(r)

    def test_measurement_projection_keeps_only_numbers(self):
        raw={'derivation':'CONSISTENT','secret':'SENTINEL','arms':{x:dict(elapsed_seconds=2,bus_eager_attempt_bytes=3,bus_eager_attempt_KiB_per_s=1,relay_delta=0,secret='SENTINEL') for x in ('D5','O5')}}
        self.assertNotIn('SENTINEL',json.dumps(e.safe_measurement(raw)))
        raw['arms']['D5']['elapsed_seconds']=float('nan')
        with self.assertRaises(e.Rejected):e.safe_measurement(raw)

    def test_real_inert_child_output_exit_reaping(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t).resolve()
            r=e.run_private([sys.executable,'-c','import sys; print("PRIVATE_SENTINEL",file=sys.stderr); sys.exit(7)'],p,os.environ.copy(),p,'inert',10)
            self.assertEqual(r['exit'],7);self.assertTrue(r['outer_reaped']);self.assertEqual((p/'inert.stderr').read_text(),'PRIVATE_SENTINEL\n')

    def test_validated_derivation_preserves_real_oracle_failure(self):
        derived={'derivation':'CONSISTENT','oracle_failures':[], 'binary_sha256':'b'*64,
                 'build_lock_sha256':e.LOCK,'retained_lock_sha256':e.LOCK,'raw_sha256':'a'*64,
                 'arms':{x:dict(elapsed_seconds=2,bus_eager_attempt_bytes=3,bus_eager_attempt_KiB_per_s=1,relay_delta=0) for x in ('D5','O5')}}
        self.assertEqual(len(e.validate_derivation({'exit':0,'reason':None},derived,'b'*64,'a'*64)),8)
        for tag in ('D5_EAGER_ORACLE','O5_EAGER_ORACLE','D5_RELAY_CHANGED','O5_RELAY_CHANGED'):
            bad=copy.deepcopy(derived);bad.update(derivation='FAIL',oracle_failures=[tag])
            with self.assertRaisesRegex(e.Rejected,'^DERIVATION_ORACLE_FAIL$') as caught:
                e.validate_derivation({'exit':1,'reason':None},bad,'b'*64,'a'*64)
            self.assertEqual(e.failure_status({'wrapper_exit':0},caught.exception),'FAIL')

    def test_exit_one_without_bound_oracle_evidence_is_incomplete(self):
        good={'derivation':'FAIL','oracle_failures':['O5_EAGER_ORACLE'],'binary_sha256':'b'*64,
              'build_lock_sha256':e.LOCK,'retained_lock_sha256':e.LOCK,'raw_sha256':'a'*64}
        cases=[]
        for field,value in [('binary_sha256','c'*64),('build_lock_sha256','c'*64),('retained_lock_sha256','c'*64),('raw_sha256','c'*64),
                            ('derivation','CONSISTENT'),('oracle_failures',[]),('oracle_failures',['unknown']),
                            ('oracle_failures',['O5_EAGER_ORACLE']*2),('oracle_failures',[True])]:
            row=copy.deepcopy(good);row[field]=value;cases.append(({'exit':1,'reason':None},row))
        for result in ({'exit':2,'reason':None},{'exit':1,'reason':'deadline'},{'exit':True,'reason':None},{'exit':0,'reason':None}):
            cases.append((result,good))
        cases.append(({'exit':1,'reason':None},[]))
        for result,row in cases:
            with self.assertRaises(e.Rejected) as caught:e.validate_derivation(result,row,'b'*64,'a'*64)
            self.assertNotEqual(str(caught.exception),'DERIVATION_ORACLE_FAIL')
            self.assertEqual(e.failure_status({'wrapper_exit':0},caught.exception),'INCOMPLETE')

    def test_actual_inert_deadline_reaps(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t).resolve();r=e.run_private([sys.executable,'-c','import time; time.sleep(30)'],p,os.environ.copy(),p,'inert',0.01)
            self.assertEqual(r['reason'],'deadline');self.assertTrue(r['outer_reaped']);self.assertNotEqual(r['exit'],0)

    def test_seal_success_keeps_private_archive_and_closed_public(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ,GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1'):
            root=Path(t).resolve();private=root/'private';private.mkdir();out=root/'public';out.mkdir();recipient=root/'recipient';recipient.write_bytes(Path(__file__).with_name('issue501-recipient.txt').read_bytes()); age=root/'age';age.write_bytes(b'inert encryptor stub')
            (private/'source-before.json').write_text(json.dumps(dict(head='a'*40,tree='b'*40)));(private/'raw').write_text('PRIVATE_SENTINEL')
            def encrypt(argv,*unused):
                Path(argv[argv.index('-o')+1]).write_bytes(b'age-encryption.org/v1\nENCRYPTED_STUB')
                return {'exit':0,'reason':None}
            key=recipient.read_bytes();recipient.write_text('wrong recipient')
            with self.assertRaisesRegex(e.Rejected,'RECIPIENT_PIN'):e.seal(private,out,recipient,encrypt,{},dict(head='a'*40,tree='b'*40),results(),None,(age,e.digest(age)))
            recipient.write_bytes(key);age_sha=e.digest(age);age.write_bytes(b'changed tool')
            with self.assertRaisesRegex(e.Rejected,'AGE_CHANGED'):e.seal(private,out,recipient,encrypt,{},dict(head='a'*40,tree='b'*40),results(),None,(age,age_sha))
            age.write_bytes(b'inert encryptor stub')
            result=e.seal(private,out,recipient,encrypt,{},dict(head='a'*40,tree='b'*40),results(),None,(age,e.digest(age)))
            self.assertNotIn('PRIVATE_SENTINEL',(out/'receipt.json').read_text())
            self.assertEqual(set(p.name for p in out.iterdir()),{'receipt.json','evidence.tar.age'})
            with tarfile.open(root/'private-evidence.tar') as tar:self.assertEqual(tar.extractfile('raw').read(),b'PRIVATE_SENTINEL')
            self.assertEqual(result['cipher_sha256'],e.digest(out/'evidence.tar.age'))
            self.assertEqual(result['private_readback'],'PENDING')
            self.assertEqual(e.verify_readback(root/'private-evidence.tar',out/'evidence.tar.age',result),'HASH_READBACK_VERIFIED_NOT_RUNTIME_ACCEPTANCE')
            (out/'evidence.tar.age').write_bytes(b'tampered')
            with self.assertRaisesRegex(e.Rejected,'READBACK_ARCHIVE_HASH'):e.verify_readback(root/'private-evidence.tar',out/'evidence.tar.age',result)

    def test_seal_failure_never_creates_eligible_receipt(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();private=root/'private';private.mkdir();out=root/'public';out.mkdir();age=root/'age';age.write_bytes(b'inert stub');(root/'recipient').write_bytes(Path(__file__).with_name('issue501-recipient.txt').read_bytes())
            with self.assertRaises(e.Rejected):e.seal(private,out,root/'recipient',lambda *a:{'exit':1,'reason':None},{},dict(head='a'*40,tree='b'*40),results(),None,(age,e.digest(age)))
            self.assertFalse((out/'receipt.json').exists())


if __name__ == '__main__':
    unittest.main()
