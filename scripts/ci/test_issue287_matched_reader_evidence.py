#!/usr/bin/env python3
"""Constructor-free controls. Imports only; fake binaries are data, never executed."""
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('evidence287', Path(__file__).with_name('issue287-matched-reader-evidence.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def fixture(directory):
    source = {'head': 'a' * 40, 'tree': 'b' * 40, 'files': {n: {'sha256': 'c' * 64} for n in
        ('tests/ws_integration.rs', 'tests/harness/src/daemon.rs', 'tests/harness/src/ws_backpressure_diagnostic.rs')}}
    # The real retained lock is harmless dependency text, not a key or binary.
    lock = Path(__file__).with_name('issue287-matched-reader.lock').read_bytes()
    (directory / 'Cargo.lock').write_bytes(lock)
    reuse = {'binary_sha256': 'd' * 64, 'daemon_sha256': 'e' * 64, 'daemon_path': '/fixture/target/debug/x0xd'}
    records = []
    def add(kind, data):
        records.append({'schema': 'x0x.issue287-local/1', 'nonce': 'f' * 32, 'kind': kind, 'data': data})
    add('inputs', {'selector': M.SELECTOR, 'test_binary_sha256': reuse['binary_sha256'],
                  'actual_lock_sha256': M.LOCK, 'source_files': {n: v['sha256'] for n, v in source['files'].items()}})
    add('workload', {'payload_bytes': 16384, 'concurrency': 64, 'request_timeout_ms': 10000,
                    'payload_base64_sha256': '1' * 64, 'wave_algorithm': 'all full bodies then counters',
                    'network_planes': 'distinct per arm'})
    children = []
    for arm, pid in [('stalled', 50), ('draining', 51)]:
        add('counters', {'arm': arm, 'counters': {'dropped': 0, 'closes': 0, 'capture_complete': True}})
        add('wave', {'arm': arm, 'ordinal': 0, 'capture_complete': True, 'requests': [
            {'ordinal': i, 'state': 'Complete', 'status': 200, 'entered_ms': 100,
             'headers_ms': 101, 'eof_ms': 102, 'body_bytes': 2, 'body_sha256': '2' * 64} for i in range(64)]})
        add('counters', {'arm': arm, 'counters': {'dropped': int(arm == 'stalled'),
             'closes': int(arm == 'stalled'), 'capture_complete': True}})
        cleanup = {'pid': pid, 'reaped': True, 'deliberate_termination': True, 'exit': 'signal: 9',
                   'capture_complete': True, 'identity_removed': True, 'errors': []}
        children.append(cleanup)
        write(directory / arm / 'spawn.json', {'schema': 'x0x.issue287-daemon/1', 'pid': pid,
              'binary_path': reuse['daemon_path'], 'binary_sha256': reuse['daemon_sha256']})
        write(directory / arm / 'cleanup.json', {k: cleanup[k] for k in ('pid', 'reaped', 'deliberate_termination', 'exit')})
    add('children', {'children': [{'pid': c['pid'], 'alive': True, 'exit': None} for c in children]})
    add('wire_close', {'arm': 'stalled', 'close_code': 1013, 'elapsed_ms': 200})
    add('draining_final_counters', {'ws_outbound_dropped': 0, 'ws_slow_consumer_closes': 0})
    add('checkpoint', {'elapsed_ms': 1000, 'trace': {'problems': [], 'cleanup_complete': True,
        'waves': [1, 1], 'phases': ['setup_entered', 'setup_complete', 'stalled_fill_entered',
        'stalled_saturation_established', 'stalled_oracles_complete', 'matched_replay_admitted', 'both_local_oracles_complete']},
        'local_status': 'LOCAL_ORACLES_PASS', 'reader': {'started': True, 'frames': 64,
        'last_frame_ms': 300, 'unexpected': 0, 'error': None, 'stopped': False}, 'cleanup_observations': children})
    return records, source, reuse


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='issue287-inert-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.records, self.source, self.reuse = fixture(self.root)

    def validate(self):
        return M.local_validation(self.records, self.root, self.source, self.reuse)

    def row(self, kind):
        return next(x['data'] for x in self.records if x['kind'] == kind)

    def test_actual_validator_accepts_complete_scalar_fixture(self):
        self.assertEqual(self.validate(), 'LOCAL_ORACLES_PASS')

    def test_all_64_full_body_outcomes_required(self):
        self.assertEqual(self.validate(), 'LOCAL_ORACLES_PASS')
        self.row('wave')['requests'].pop()
        with self.assertRaises(M.Rejected): self.validate()

    def test_headers_without_eof_cannot_pass(self):
        self.row('wave')['requests'][3]['state'] = 'Headers'
        with self.assertRaises(M.Rejected): self.validate()

    def test_body_error_cannot_pass(self):
        self.row('wave')['requests'][3]['state'] = 'BodyError'
        with self.assertRaises(M.Rejected): self.validate()

    def test_1013_required_not_transport_error(self):
        self.row('wire_close')['close_code'] = None
        self.row('wire_close')['transport_error'] = True
        with self.assertRaises(M.Rejected): self.validate()

    def test_exact_matched_count_required(self):
        self.row('checkpoint')['reader']['frames'] = 63
        with self.assertRaises(M.Rejected): self.validate()

    def test_daemon_hash_must_match_build(self):
        path = self.root / 'draining/spawn.json'
        value = json.loads(path.read_text()); value['binary_sha256'] = '9' * 64; write(path, value)
        with self.assertRaises(M.Rejected): self.validate()

    def test_foreign_source_lock_rejected(self):
        self.row('inputs')['actual_lock_sha256'] = '9' * 64
        with self.assertRaises(M.Rejected): self.validate()

    def test_missing_cleanup_not_pass(self):
        (self.root / 'draining/cleanup.json').unlink()
        with self.assertRaises(OSError): self.validate()

    def test_observed_failure_precedes_missing_final_capture(self):
        self.row('checkpoint')['trace']['problems'] = [{'class': 'Fail', 'code': 'OWN_DAEMON_EXIT'}]
        self.records.append({'kind': 'children', 'data': {}})
        self.assertEqual(self.validate(), 'FAIL')
        self.assertEqual(M.adjudicate('FAIL', False, False, ['capture']), 'FAIL')

    def test_premise_and_missing_custody_distinct(self):
        self.assertEqual(M.adjudicate('INCONCLUSIVE', False, True, []), 'INCONCLUSIVE')
        self.assertEqual(M.adjudicate('LOCAL_ORACLES_PASS', True, False, []), 'INCOMPLETE')

    def test_no_environment_override_for_wrong_producer_literal(self):
        with patch.dict(os.environ, {'PRODUCER_BINARY_ID': 'x0x::ws_integration'}), patch.object(M, 'PRODUCER_BINARY_ID', 'foreign'):
            with self.assertRaisesRegex(M.Rejected, 'PRODUCER_CONTRACT_UNVERIFIED'): M.producer_admission()

    def test_one_literal_selector_no_retry_or_timeout_override(self):
        args = M.runtime_arguments()
        self.assertEqual(args[args.index('--retries') + 1], '0')
        self.assertEqual(args[args.index('--run-ignored') + 1], 'ignored-only')
        self.assertEqual(args[-1], 'package(=x0x) & binary(=ws_integration) & kind(=test) & test(=ws_backpressure_matched_reader_acceptance)')
        self.assertNotIn('--slow-timeout', args)

    def test_reporter_contract_sample_is_only_synthetic(self):
        raw = ('────────────\n Nextest run ID aaaa-bbbb with nextest profile: default\n'
               '    Starting 1 test across 1 binary\n'
               '        PASS [ 1.000s] (1/1) x0x::ws_integration ' + M.SELECTOR + '\n'
               '  stderr ───\n    FAIL fake untrusted payload\n────────────\n'
               '     Summary [ 1.001s] 1 test run: 1 passed\n').encode()
        counts, payload, _ = M.parse_report(raw, M.SELECTOR, 'x0x::ws_integration')
        self.assertEqual(counts['passed'], 1)
        self.assertIn(b'FAIL fake', payload)
        with self.assertRaises(M.Rejected): M.parse_report(raw.replace(b'Starting 1', b'Starting 0'), M.SELECTOR, 'x0x::ws_integration')

    def test_reporter_wrong_identity_rejected(self):
        with self.assertRaises(M.Rejected): M.parse_report(b'PASS whatever\n', M.SELECTOR, 'foreign')

    def test_json_duplicate_rejected(self):
        with self.assertRaises(M.Rejected): M.object_json(b'{"a":1,"a":2}')

    def test_file_symlink_hardlink_and_cap_rejected(self):
        target = self.root / 'target'; target.write_bytes(b'abc')
        link = self.root / 'alias'; link.symlink_to(target)
        with self.assertRaises(M.Rejected): M.read_owned(link, self.root)
        hard = self.root / 'hard'; os.link(target, hard)
        with self.assertRaises(M.Rejected): M.read_owned(hard, self.root)
        hard.unlink()
        with self.assertRaises(M.Rejected): M.read_owned(target, self.root, 2)

    def test_capture_nonce_and_unexpected_data_not_read(self):
        workspace = self.root / 'workspace'; capture = workspace / 'target/issue287-captures' / ('f' * 32)
        capture.mkdir(parents=True, mode=0o700)
        (capture / 'Cargo.lock').write_bytes(Path(__file__).with_name('issue287-matched-reader.lock').read_bytes())
        write(capture / '000000-inputs.json', {'schema': 'x0x.issue287-local/1', 'nonce': 'f' * 32, 'kind': 'inputs', 'data': {}})
        arm = capture / 'stalled'; arm.mkdir(); data = arm / 'data-secret'; data.mkdir()
        (data / 'key').write_text('do not read')
        with patch.object(M, 'read_owned', wraps=M.read_owned) as read:
            _, _, _, gaps = M.collect_capture(workspace, self.root / 'collected')
            self.assertIn('UNEXPECTED_ARM_ENTRY', gaps)
            self.assertFalse(any('data-secret' in str(call.args[0]) for call in read.call_args_list))

    def test_capture_duplicate_nonce_refused(self):
        p = self.root / 'target/issue287-captures'; p.mkdir(parents=True)
        (p / ('a' * 32)).mkdir(); (p / ('b' * 32)).mkdir()
        with self.assertRaises(M.Rejected): M.collect_capture(self.root, self.root / 'collected')

    def test_missing_receipt_does_not_erase_saved_failure(self):
        write(self.root / '000000-checkpoint.json', {'schema': 'x0x.issue287-local/1', 'kind': 'checkpoint',
              'data': {'trace': {'problems': [{'class': 'Fail'}]}, 'cleanup_observations': []}})
        self.assertTrue(M.observed_failure(self.root))


    def build_inputs(self):
        workspace = self.root / 'work/repo'; workspace.mkdir(parents=True)
        target = workspace / 'target'; binary = target / 'debug/deps/ws_integration-deadbeef'
        binary.parent.mkdir(parents=True); binary.write_bytes(b'fake test data only')
        daemon = target / 'debug/x0xd'; daemon.write_bytes(b'fake daemon data only')
        lock = workspace / 'Cargo.lock'; lock.write_bytes(Path(__file__).with_name('issue287-matched-reader.lock').read_bytes())
        scratch = self.root / 'x0x-metadata-inert'; scratch.mkdir()
        package = 'path+fixture#x0x@0.1.0'
        meta = {'rust-build-meta': {'target-directory': str(target), 'non-test-binaries': {
            package: [{'name': 'x0xd', 'kind': 'bin-exe', 'path': 'debug/x0xd'}]}},
            'rust-binaries': {'x0x::ws_integration': {'binary-id': 'x0x::ws_integration', 'binary-name': 'ws_integration', 'kind': 'test',
                'package-id': package, 'binary-path': str(binary)}}}
        write(scratch / 'binaries.json', meta)
        write(scratch / 'cargo.json', {'workspace_root': str(workspace), 'target_directory': str(target),
              'packages': [{'name': 'x0x', 'id': package, 'manifest_path': str(workspace / 'Cargo.toml')}]})
        paths = [binary, daemon, lock, scratch / 'binaries.json', scratch / 'cargo.json']
        write(scratch / 'custody.json', {'source': ['a' * 40, 'b' * 40], 'files': {str(p): M.digest(p) for p in paths}})
        return workspace, scratch, {'head': 'a' * 40, 'tree': 'b' * 40}

    def test_build_interlock_actual_validator_synthetic_metadata(self):
        w, scratch, source = self.build_inputs()
        with patch.object(M, 'PRODUCER_BINARY_ID', 'x0x::ws_integration'):
            result = M.validate_build(w, scratch, source)
        self.assertEqual(result['daemon_sha256'], M.digest(w / 'target/debug/x0xd'))

    def test_build_interlock_rejects_changed_binary_before_runtime(self):
        w, scratch, source = self.build_inputs()
        (w / 'target/debug/x0xd').write_bytes(b'changed')
        with patch.object(M, 'PRODUCER_BINARY_ID', 'x0x::ws_integration'):
            with self.assertRaises(M.Rejected): M.validate_build(w, scratch, source)

    def test_build_interlock_rejects_release_fallback(self):
        w, scratch, source = self.build_inputs()
        release = w / 'target/release/x0xd'; release.parent.mkdir(); release.write_bytes(b'foreign')
        with patch.object(M, 'PRODUCER_BINARY_ID', 'x0x::ws_integration'):
            with self.assertRaisesRegex(M.Rejected, 'DAEMON_ALTERNATE'): M.validate_build(w, scratch, source)

    def test_build_interlock_rejects_foreign_parent(self):
        w, scratch, source = self.build_inputs(); source['head'] = 'f' * 40
        with patch.object(M, 'PRODUCER_BINARY_ID', 'x0x::ws_integration'):
            with self.assertRaisesRegex(M.Rejected, 'BUILD_SOURCE'): M.validate_build(w, scratch, source)

    def test_bound_failure_terminal_survives_missing_summary(self):
        raw = ('────────────\n    Starting 1 test across 1 binary\n'
               '        FAIL [ 1.0s] (1/1) x0x::ws_integration ' + M.SELECTOR + '\n').encode()
        self.assertTrue(M.terminal_failure(raw, 'x0x::ws_integration'))
        self.assertFalse(M.terminal_failure(raw.replace(b'        FAIL', b'    payload FAIL'), 'x0x::ws_integration'))
        self.assertFalse(M.terminal_failure(raw, 'foreign'))

    def test_actual_outer_owner_cancel_uses_only_fake_child(self):
        class Fake:
            pid = 123456
            returncode = None
            def poll(self): return self.returncode
            def wait(self, timeout=None):
                self.returncode = -15
                return self.returncode
        child = Fake()
        def spawn(*args, **kwargs):
            M.CANCELLED = True
            return child
        with patch.object(M.subprocess, 'Popen', side_effect=spawn) as spawned, \
             patch.object(M.os, 'killpg') as killed, patch.object(M, 'CANCELLED', False):
            result = M.run_private(['inert-only'], self.root, {}, self.root, 'runtime', 10)
        self.assertEqual(result['exit'], -15)
        self.assertTrue(result['outer_reaped'])
        self.assertEqual(result['reason'], 'signal')
        spawned.assert_called_once()
        killed.assert_called_once_with(child.pid, M.signal.SIGTERM)

    def test_same_uid_read_checks_foreign_owner(self):
        path = self.root / 'owned'; path.write_text('harmless')
        with patch.object(M.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaisesRegex(M.Rejected, 'FILE_OWNER_OR_SIZE'): M.read_owned(path, self.root)



    def seal_inputs(self):
        private = self.root / 'seal-private'; private.mkdir()
        output = self.root / 'public'; output.mkdir()
        write(private / 'source-before.json', {'head': 'a' * 40, 'tree': 'b' * 40})
        age = self.root / 'fake-age'; age.write_bytes(b'inert fake tool never executed')
        recipient = Path(__file__).with_name('issue287-recipient.txt')
        result = {'status': 'INCOMPLETE', 'local_status': 'UNVERIFIED', 'selected': 0,
                  'ran': 0, 'passed': 0, 'failed': 0, 'namespace_admitted': False,
                  'outer_reaped': True, 'test_binary_sha256': None, 'daemon_binary_sha256': None, 'framework_status': 'UNVERIFIED'}
        return private, output, recipient, {'head': 'a' * 40, 'tree': 'b' * 40}, result, (age, M.digest(age))

    def fake_seal(self, argv, *_args, **_kwargs):
        if '--worker' in argv:
            M.execute_worker(argv[argv.index('--worker') + 1], Path(argv[argv.index('--request') + 1]), Path(argv[argv.index('--response') + 1]))
        else:
            Path(argv[argv.index('-o') + 1]).write_bytes(b'age-encryption.org/v1\ninert-not-real-ciphertext')
        return {'exit': 0, 'reason': None, 'outer_reaped': True}

    def test_seal_and_hash_readback_are_not_acceptance(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        with patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual(receipt['private_readback'], 'PENDING')
        self.assertEqual(receipt['status'], 'INCOMPLETE')
        self.assertEqual(M.verify_readback(out.parent / 'private-evidence.tar', out / 'evidence.tar.age', receipt),
                         'HASH_READBACK_VERIFIED_NOT_RUNTIME_ACCEPTANCE')

    def test_failed_seal_never_creates_public_receipt(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        def failed_age(argv, *args, **kwargs):
            if '--worker' in argv:
                return self.fake_seal(argv, *args, **kwargs)
            return {'exit': 1, 'reason': None, 'outer_reaped': True}
        with patch.object(M, 'run_private', side_effect=failed_age):
            with self.assertRaisesRegex(M.Rejected, 'SEAL_FAILED'):
                M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertFalse((out / 'receipt.json').exists())

    def test_public_schema_rejects_raw_error_path(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        result['raw_error'] = '/private/harmless-inert-token'
        with patch.object(M, 'run_private', side_effect=self.fake_seal):
            with self.assertRaisesRegex(M.Rejected, 'PUBLIC_SCHEMA'):
                M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertFalse((out / 'receipt.json').exists())

    def test_readback_rejects_changed_archive(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        with patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        with (out.parent / 'private-evidence.tar').open('ab') as f: f.write(b'changed')
        with self.assertRaises(M.Rejected): M.verify_readback(out.parent / 'private-evidence.tar', out / 'evidence.tar.age', receipt)



    def test_integrated_incomplete_plus_framework_fail_stays_local_incomplete(self):
        result = {'local_status': 'INCOMPLETE'}
        M.finish_result(result, False, False, ['CUSTODY_INCOMPLETE'], True)
        self.assertEqual(result['local_status'], 'INCOMPLETE')
        self.assertEqual(result['framework_status'], 'FAIL')
        self.assertEqual(result['failed'], 1)
        self.assertEqual(result['status'], 'INCOMPLETE')

    def test_integrated_inconclusive_plus_framework_fail_preserves_premise(self):
        result = {'local_status': 'INCONCLUSIVE'}
        M.finish_result(result, False, True, [], True)
        self.assertEqual(result['local_status'], 'INCONCLUSIVE')
        self.assertEqual(result['framework_status'], 'FAIL')
        self.assertEqual(result['status'], 'INCONCLUSIVE')

    def test_integrated_local_fail_survives_later_custody_gap(self):
        result = {'local_status': 'FAIL'}
        M.finish_result(result, False, False, ['CAPTURE_INCOMPLETE'], False)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['local_status'], 'FAIL')
        self.assertEqual(result['framework_status'], 'UNVERIFIED')

    def test_integrated_missing_capture_does_not_invent_local_oracle(self):
        result = {'local_status': 'UNVERIFIED'}
        M.finish_result(result, False, False, ['CAPTURE_INCOMPLETE'], True)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['local_status'], 'UNVERIFIED')
        self.assertEqual(result['framework_status'], 'FAIL')
        self.assertEqual((result['selected'], result['ran'], result['failed']), (1, 1, 1))

    def test_exact_verified_producer_ignores_foreign_environment(self):
        with patch.dict(os.environ, {'PRODUCER_BINARY_ID': 'foreign'}):
            M.producer_admission()



    def test_actual_phase_budget_passes_only_remaining_time(self):
        with patch.object(M.time, 'monotonic', return_value=60), \
             patch.object(M, 'run_private', return_value={'exit': 0}) as run:
            M.run_bounded(['fake'], self.root, {}, self.root, 'collect-worker', 120, 100)
        self.assertEqual(run.call_args.args[-1], 20)
        self.assertEqual(run.call_args.kwargs['deadline'], 100)

    def test_expired_global_budget_starts_no_worker(self):
        with patch.object(M.time, 'monotonic', return_value=100), \
             patch.object(M, 'run_private') as run:
            with self.assertRaisesRegex(M.Rejected, 'PHASE_DEADLINE'):
                M.run_bounded(['fake'], self.root, {}, self.root, 'archive-worker', 120, 100)
        run.assert_not_called()

    def test_collection_timeout_has_no_fabricated_worker_verdict(self):
        private = self.root / 'private'; private.mkdir()
        with patch.object(M, 'run_private', return_value={'exit': -9, 'reason': 'deadline', 'outer_reaped': True}), \
             patch.object(M, 'worker_result') as read:
            with self.assertRaisesRegex(M.Rejected, 'WORKER_NONPASS'):
                M.run_worker('collect', {}, private, {}, M.time.monotonic() + 120, 120)
        read.assert_not_called()
        self.assertFalse((private / 'collect-response.json').exists())

    def test_archive_crash_stops_before_any_age_execution(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        with patch.object(M, 'run_private', return_value={'exit': 2, 'reason': None, 'outer_reaped': True}) as run:
            with self.assertRaisesRegex(M.Rejected, 'WORKER_NONPASS'):
                M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual(run.call_count, 1)
        self.assertIn('--worker', run.call_args.args[0])
        self.assertFalse((out / 'receipt.json').exists())

    def test_archive_timeout_is_nonpass_and_not_a_new_budget(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        with patch.object(M, 'run_private', return_value={'exit': -9, 'reason': 'deadline', 'outer_reaped': True}) as run:
            with self.assertRaisesRegex(M.Rejected, 'WORKER_NONPASS'):
                M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 25)
        self.assertLessEqual(run.call_args.args[-1], 5)
        self.assertEqual(run.call_count, 1)

    def test_shared_seal_budget_expiry_after_archive_prevents_age(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        clock = [0]
        def archived(argv, *args, **kwargs):
            value = self.fake_seal(argv, *args, **kwargs)
            clock[0] = 121
            return value
        with patch.object(M.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(M, 'run_private', side_effect=archived) as run:
            with self.assertRaisesRegex(M.Rejected, 'PHASE_DEADLINE'):
                M.seal_packet(private, out, recipient, {}, source, result, age, 1000)
        self.assertEqual(run.call_count, 1)
        self.assertFalse((out / 'evidence.tar.age').exists())

    def test_cancelled_file_worker_is_allowed_and_reaped_without_signal(self):
        class Fake:
            pid = 234567
            returncode = None
            polls = 0
            def poll(self):
                self.polls += 1
                if self.polls >= 2: self.returncode = 0
                return self.returncode
            def wait(self, timeout=None): return self.returncode
        child = Fake()
        with patch.object(M.subprocess, 'Popen', return_value=child), \
             patch.object(M.os, 'killpg') as killed, patch.object(M.time, 'sleep'), \
             patch.object(M, 'CANCELLED', True):
            result = M.run_private(['file-worker-not-executed'], self.root, {}, self.root, 'collect-worker', 120)
            self.assertTrue(M.CANCELLED)
        self.assertIsNone(result['reason'])
        self.assertTrue(result['outer_reaped'])
        killed.assert_not_called()

    def test_file_worker_rejects_unknown_mode_without_subprocess(self):
        with patch.object(M.subprocess, 'Popen') as execute:
            with self.assertRaisesRegex(M.Rejected, 'WORKER_MODE'):
                M.execute_worker('runtime', self.root / 'request.json', self.root / 'response.json')
        execute.assert_not_called()

    def test_cancelled_execution_never_starts_another_child(self):
        with patch.object(M, 'CANCELLED', True), patch.object(M.subprocess, 'Popen') as spawn:
            for name in ('runtime', 'metadata', 'binaries', 'record', 'seal-probe', 'age-version', 'unknown'):
                with self.assertRaisesRegex(M.Rejected, 'EXECUTION_CANCELLED'):
                    M.run_private(['not-executed'], self.root, {}, self.root, name, 10)
        spawn.assert_not_called()

    def test_allowed_evidence_tasks_still_obey_timeout(self):
        class Fake:
            pid = 222222
            returncode = None
            def poll(self): return self.returncode
            def wait(self, timeout=None):
                self.returncode = -15
                return self.returncode
        child = Fake()
        clock = iter([0, 10, 10, 10])
        with patch.object(M, 'CANCELLED', True), patch.object(M.time, 'monotonic', side_effect=lambda: next(clock)), \
             patch.object(M.subprocess, 'Popen', return_value=child), patch.object(M.os, 'killpg') as kill:
            result = M.run_private(['fake'], self.root, {}, self.root, 'archive-worker', 10, deadline=30)
        self.assertEqual(result['reason'], 'deadline')
        self.assertEqual(result['exit'], -15)
        kill.assert_called_once_with(child.pid, M.signal.SIGTERM)

    def test_termination_grace_uses_only_remaining_deadline(self):
        class Fake:
            pid = 333333
            returncode = None
            waits = []
            def poll(self): return self.returncode
            def wait(self, timeout=None):
                self.waits.append(timeout)
                if timeout is not None: raise M.subprocess.TimeoutExpired('fake', timeout)
                self.returncode = -9
                return self.returncode
        child = Fake()
        with patch.object(M.time, 'monotonic', return_value=98), patch.object(M.os, 'killpg') as kill:
            M.terminate_owned(child, 100)
        self.assertEqual(child.waits, [2, None])
        self.assertEqual([c.args[1] for c in kill.call_args_list], [M.signal.SIGTERM, M.signal.SIGKILL])

    def test_already_reaped_child_is_never_signalled(self):
        class Fake:
            pid = 333333
            def poll(self): return 0
            def wait(self): return 0
        with patch.object(M.os, 'killpg') as kill:
            M.terminate_owned(Fake(), 0)
        kill.assert_not_called()

    def latch_inputs(self, private):
        workspace = self.root / 'latch-workspace'
        capture = workspace / 'target/issue287-captures' / ('f' * 32)
        capture.mkdir(parents=True, mode=0o700)
        records, source, reuse = fixture(capture)
        records[-1]['data']['local_status'] = 'FAIL'
        records[-1]['data']['trace']['problems'] = [{'class': 'Fail', 'code': 'OWN_DAEMON_EXIT'}]
        for i, record in enumerate(records):
            write(capture / (f'{i:06d}-' + record['kind'] + '.json'), record)
        reuse['binary_id'] = 'x0x::ws_integration'
        payload = {'workspace': str(workspace), 'source': source, 'reuse': reuse,
                   'runtime_exit': 100, 'runtime_reason': None}
        write(private / 'collect-request.json', {'schema': 'x0x.issue287-worker-input/1', 'mode': 'collect',
              'private': str(private), 'payload': payload})
        (private / 'runtime.stderr').write_bytes(b'no invented terminal')
        return capture, source, reuse, M.digest(private / 'collect-request.json')

    def produce_latch_then_simulate_crash(self, private):
        capture, source, reuse, request_sha = self.latch_inputs(private)
        actual = M.collect_capture
        def interrupted_copy(workspace, destination, callback):
            def copied(nonce, name, record):
                callback(nonce, name, record)
                if record['kind'] == 'checkpoint': raise KeyboardInterrupt('inert worker crash')
            return actual(workspace, destination, copied)
        with patch.object(M, 'collect_capture', side_effect=interrupted_copy):
            with self.assertRaises(KeyboardInterrupt):
                M.execute_worker('collect', private / 'collect-request.json', private / 'collect-response.json')
        self.assertFalse((private / 'collect-response.json').exists())
        return source, reuse, request_sha

    def test_actual_sealing_retains_bound_fail_after_collection_crash_and_cancellation(self):
        private, out, recipient, _, result, age = self.seal_inputs()
        source, reuse, request_sha = self.produce_latch_then_simulate_crash(private)
        result.update(test_binary_sha256=reuse['binary_sha256'], daemon_binary_sha256=reuse['daemon_sha256'])
        with patch.object(M, 'run_private', side_effect=self.fake_seal), patch.object(M, 'CANCELLED', True), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120, request_sha)
            self.assertTrue(M.CANCELLED)
        self.assertEqual((receipt['status'], receipt['local_status']), ('FAIL', 'FAIL'))
        self.assertEqual(receipt['framework_status'], 'UNVERIFIED')
        self.assertTrue(json.loads((private / 'fail-latch-verification.json').read_text())['verified_local_fail'])

    def test_latch_rejects_mismatched_nonce_request_checkpoint_source_and_binary(self):
        private = self.root / 'private'; private.mkdir()
        source, reuse, request_sha = self.produce_latch_then_simulate_crash(private)
        latch_path = private / 'fail-latch.json'; original = json.loads(latch_path.read_text())
        self.assertTrue(M.verify_fail_latch(private, request_sha, source, reuse['binary_sha256']))
        for key, value in [('nonce', 'a' * 32), ('collect_request_sha256', 'a' * 64),
                           ('checkpoint_sha256', 'b' * 64), ('source_files', {}),
                           ('test_binary_sha256', 'f' * 64), ('extra', True)]:
            bad = dict(original); bad[key] = value; write(latch_path, bad)
            with self.assertRaises(M.Rejected): M.verify_fail_latch(private, request_sha, source, reuse['binary_sha256'])
        write(latch_path, original)
        with self.assertRaises(M.Rejected): M.verify_fail_latch(private, 'a' * 64, source, reuse['binary_sha256'])
        path = private / 'capture' / original['checkpoint']; value = json.loads(path.read_text())
        value['data']['trace']['problems'] = []; write(path, value)
        with self.assertRaises(M.Rejected): M.verify_fail_latch(private, request_sha, source, reuse['binary_sha256'])

    def test_framework_fail_local_incomplete_cannot_create_latch(self):
        private = self.root / 'private'; private.mkdir()
        capture, source, reuse, request_sha = self.latch_inputs(private)
        checkpoint = next(capture.glob('*-checkpoint.json'))
        value = json.loads(checkpoint.read_text())
        value['data']['trace']['problems'] = [{'class': 'Incomplete', 'code': 'CAPTURE'}]
        value['data']['local_status'] = 'INCOMPLETE'; write(checkpoint, value)
        (private / 'runtime.stderr').write_bytes(('────────────\n    Starting 1 test across 1 binary\n'
            '        FAIL [ 1.0s] (1/1) x0x::ws_integration ' + M.SELECTOR + '\n').encode())
        M.execute_worker('collect', private / 'collect-request.json', private / 'collect-response.json')
        response = json.loads((private / 'collect-response.json').read_text())
        self.assertEqual(response['local_status'], 'INCOMPLETE')
        self.assertTrue(response['framework_failed'])
        self.assertFalse((private / 'fail-latch.json').exists())
        self.assertFalse(M.verify_fail_latch(private, request_sha, source, reuse['binary_sha256']))

    def test_existing_latch_is_never_overwritten(self):
        private = self.root / 'private'; private.mkdir()
        write(private / 'fail-latch.json', {'stale': True})
        before = (private / 'fail-latch.json').read_bytes()
        with self.assertRaises(FileExistsError): M.save_fail_latch(private, {'new': True})
        self.assertEqual((private / 'fail-latch.json').read_bytes(), before)
        self.assertFalse((private / 'fail-latch.pending.json').exists())

    def test_cancellation_cannot_seal_a_pass(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        result.update(status='PASS', local_status='LOCAL_ORACLES_PASS')
        with patch.object(M, 'CANCELLED', True), patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual(receipt['status'], 'INCOMPLETE')


    def publication_inputs(self):
        values = self.seal_inputs()
        values[4].update(status='PASS', local_status='LOCAL_ORACLES_PASS', selected=1,
                         ran=1, passed=1, namespace_admitted=True, framework_status='PASS')
        return values

    def test_cancellation_during_metadata_stays_private_until_parent_nonpass_publication(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        def late(argv, *args, **kwargs):
            if '--worker' in argv and argv[argv.index('--worker') + 1] == 'seal-metadata':
                M.interrupted(None, None)
            answer = self.fake_seal(argv, *args, **kwargs)
            if '--worker' in argv and argv[argv.index('--worker') + 1] == 'seal-metadata':
                self.assertFalse((out / 'receipt.json').exists())
                self.assertEqual(json.loads((private / 'receipt-candidate.json').read_text())['status'], 'PASS')
            return answer
        with patch.object(M, 'CANCELLED', False), patch.object(M, 'run_private', side_effect=late), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
            self.assertTrue(M.CANCELLED)
        self.assertEqual((receipt['status'], result['status']), ('INCOMPLETE', 'INCOMPLETE'))

    def test_cancellation_after_metadata_completion_is_observed(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        def late(argv, *args, **kwargs):
            answer = self.fake_seal(argv, *args, **kwargs)
            if '--worker' in argv and argv[argv.index('--worker') + 1] == 'seal-metadata':
                M.interrupted(None, None)
            return answer
        with patch.object(M, 'CANCELLED', False), patch.object(M, 'run_private', side_effect=late), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual(receipt['status'], 'INCOMPLETE')

    def test_partial_publication_temp_cancel_uses_one_distinct_negative_file(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        original_open = Path.open
        class Partial:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def write(self, data):
                self.stream.write(data[:8])
                M.interrupted(None, None)
                raise AssertionError('one-shot interruption must unwind')
        def opened(path, *args, **kwargs):
            stream = original_open(path, *args, **kwargs)
            return Partial(stream) if path.name == 'receipt-publication.pending.json' and args == ('xb',) else stream
        with patch.object(M, 'CANCELLED', False), patch.object(Path, 'open', opened), \
             patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual(receipt['status'], 'INCOMPLETE')
        self.assertEqual((private / 'receipt-publication.pending.json').stat().st_size, 8)
        self.assertFalse((private / 'receipt-cancelled.pending.json').exists())

    def test_cancel_at_readback_and_again_during_negative_write_cannot_reinterrupt(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        read = M.read_owned; injected = []
        def observed(path, *args, **kwargs):
            value = read(path, *args, **kwargs)
            if path == out / 'receipt.json' and not injected:
                injected.append('initial-readback'); M.interrupted(None, None)
            if path == private / 'receipt-cancelled.pending.json':
                injected.append('negative-write'); M.interrupted(None, None)
            return value
        with patch.object(M, 'CANCELLED', False), patch.object(M, 'read_owned', side_effect=observed), \
             patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual(receipt['status'], 'INCOMPLETE')
        self.assertEqual(injected, ['initial-readback', 'negative-write'])
        self.assertFalse(M.PUBLICATION_ACTIVE)

    def test_pending_signal_is_preserved_at_publication_boundary(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        with patch.object(M, 'CANCELLED', False), patch.object(M.signal, 'sigpending', return_value={M.signal.SIGTERM}), \
             patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
            self.assertTrue(M.CANCELLED)
        self.assertEqual(receipt['status'], 'INCOMPLETE')

    def test_signal_after_complete_publication_does_not_rewrite_evidence(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        with patch.object(M, 'CANCELLED', False), patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
            before = (out / 'receipt.json').read_bytes()
            self.assertFalse(M.PUBLICATION_ACTIVE)
            M.interrupted(None, None)
            self.assertTrue(M.CANCELLED)
            self.assertEqual(1, 0 if result['status'] == 'PASS' and not M.CANCELLED else 1)
            self.assertEqual((out / 'receipt.json').read_bytes(), before)
        self.assertEqual(receipt['status'], 'PASS')

    def test_small_finalization_failure_does_not_report_success(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        replace = M.os.replace
        def broken(source_path, target_path):
            if target_path == out / 'receipt.json': raise OSError('inert publication failure')
            return replace(source_path, target_path)
        with patch.object(M, 'run_private', side_effect=self.fake_seal), patch.object(M.os, 'replace', side_effect=broken), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            with self.assertRaises(OSError):
                M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertFalse((out / 'receipt.json').exists())
        self.assertFalse(M.PUBLICATION_ACTIVE)

    def test_parent_does_not_repeat_cipher_hashing(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        with patch.object(M, 'digest', wraps=M.digest) as hashed, patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual(sum(Path(c.args[0]) == out / 'evidence.tar.age' for c in hashed.call_args_list), 1)

    def produce_interrupted_link_pair(self, private):
        _, source, reuse, request_sha = self.latch_inputs(private)
        unlink = Path.unlink
        def interrupted_unlink(path, *args, **kwargs):
            if path == private / 'fail-latch.pending.json': raise KeyboardInterrupt('inert link-before-unlink kill')
            return unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', interrupted_unlink):
            with self.assertRaises(KeyboardInterrupt):
                M.execute_worker('collect', private / 'collect-request.json', private / 'collect-response.json')
        self.assertEqual((private / 'fail-latch.json').stat().st_nlink, 2)
        return source, reuse, request_sha

    def test_actual_archive_recovers_only_bound_interrupted_latch_pair(self):
        private, out, recipient, _, result, age = self.seal_inputs()
        source, reuse, request_sha = self.produce_interrupted_link_pair(private)
        result.update(test_binary_sha256=reuse['binary_sha256'], daemon_binary_sha256=reuse['daemon_sha256'])
        with self.assertRaises(M.Rejected): M.read_owned(private / 'fail-latch.json', private)
        with patch.object(M, 'run_private', side_effect=self.fake_seal), patch.object(M, 'CANCELLED', True), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120, request_sha)
        self.assertEqual((receipt['local_status'], receipt['status']), ('FAIL', 'FAIL'))
        self.assertFalse((private / 'fail-latch.pending.json').exists())
        self.assertEqual((private / 'fail-latch.json').stat().st_nlink, 1)
        self.assertTrue(M.verify_fail_latch(private, request_sha, source, reuse['binary_sha256']))

    def test_latch_pair_recovery_rejects_extra_link(self):
        private = self.root / 'private'; private.mkdir()
        source, reuse, request_sha = self.produce_interrupted_link_pair(private)
        os.link(private / 'fail-latch.json', private / 'extra-link')
        with self.assertRaisesRegex(M.Rejected, 'FAIL_LATCH_PAIR'):
            M.recover_interrupted_fail_latch(private, request_sha, source, reuse['binary_sha256'])
        self.assertTrue((private / 'fail-latch.pending.json').exists())
        self.assertEqual((private / 'fail-latch.json').stat().st_nlink, 3)

    def test_latch_pair_recovery_rejects_different_inode(self):
        private = self.root / 'private'; private.mkdir()
        source, reuse, request_sha = self.produce_interrupted_link_pair(private)
        (private / 'fail-latch.pending.json').unlink()
        write(private / 'fail-latch.pending.json', {'unrelated': True})
        with self.assertRaisesRegex(M.Rejected, 'FAIL_LATCH_PAIR'):
            M.recover_interrupted_fail_latch(private, request_sha, source, reuse['binary_sha256'])
        self.assertTrue((private / 'fail-latch.pending.json').exists())

    def test_latch_pair_binding_is_checked_before_unlink(self):
        private = self.root / 'private'; private.mkdir()
        source, reuse, request_sha = self.produce_interrupted_link_pair(private)
        latch = private / 'fail-latch.json'; value = json.loads(latch.read_text())
        value['nonce'] = 'a' * 32; write(latch, value)
        with self.assertRaises(M.Rejected):
            M.recover_interrupted_fail_latch(private, request_sha, source, reuse['binary_sha256'])
        self.assertEqual(latch.stat().st_nlink, 2)
        self.assertTrue((private / 'fail-latch.pending.json').exists())


    def test_known_fail_survives_cancellation_during_metadata(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        result.update(status='FAIL', local_status='FAIL')
        def late(argv, *args, **kwargs):
            answer = self.fake_seal(argv, *args, **kwargs)
            if '--worker' in argv and argv[argv.index('--worker') + 1] == 'seal-metadata':
                M.interrupted(None, None)
            return answer
        with patch.object(M, 'CANCELLED', False), patch.object(M, 'run_private', side_effect=late), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual((receipt['status'], receipt['local_status'], result['status']), ('FAIL', 'FAIL', 'FAIL'))

    def test_known_fail_survives_cancellation_during_final_readback(self):
        private, out, recipient, source, result, age = self.publication_inputs()
        result.update(status='FAIL', local_status='FAIL')
        read = M.read_owned; injected = []
        def observed(path, *args, **kwargs):
            value = read(path, *args, **kwargs)
            if path == out / 'receipt.json' and not injected:
                injected.append(True); M.interrupted(None, None)
            return value
        with patch.object(M, 'CANCELLED', False), patch.object(M, 'read_owned', side_effect=observed), \
             patch.object(M, 'run_private', side_effect=self.fake_seal), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertEqual((receipt['status'], receipt['local_status'], result['status']), ('FAIL', 'FAIL', 'FAIL'))



    def observation(self):
        return M.BuildObservation(M.time.monotonic())

    def observation_error(self, observer, action, error=M.Rejected):
        with self.assertRaises(error) as caught:
            action()
        self.assertEqual(observer.state, 'rejected')
        return caught.exception

    def fs_trace(self, action):
        calls = []
        def wrapper(label, original):
            def invoke(*args, **kwargs):
                calls.append((label, args, kwargs))
                return original(*args, **kwargs)
            return invoke
        with ExitStack() as stack:
            for owner, names in ((Path, ('resolve', 'is_absolute', 'is_symlink', 'stat', 'exists', 'open')),
                                 (M.os, ('open', 'fstat', 'getuid')), (M, ('digest',))):
                for name in names:
                    stack.enter_context(patch.object(owner, name, wrapper(name, getattr(owner, name))))
            result = action()
        return result, calls

    def test_build_observer_preserves_real_file_call_order_and_return(self):
        w, scratch, source = self.build_inputs()
        original, before = self.fs_trace(lambda: M.validate_build(w, scratch, source))
        o = self.observation()
        result, after = self.fs_trace(lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(result, original)
        self.assertEqual(after, before, 'recording must not add, repeat or reorder filesystem operations')
        self.assertEqual(o.state, 'verified')
        self.assertEqual(o.roles[('test_binary', 0)]['facts']['nlink'], 1)
        self.assertEqual(o.roles[('binary_metadata', 0)]['facts']['before_open_equal'], True)
        self.assertEqual(o.roles[('cargo_metadata', 0)]['facts']['after_read_equal'], True)
        self.assertLessEqual(len(json.dumps(M.BuildVerification(source, M.time.monotonic()).value()).encode()), 32768)

    def test_build_observer_two_links_reject_actual_guard_without_later_probe(self):
        w, scratch, source = self.build_inputs()
        binary = w / 'target/debug/deps/ws_integration-deadbeef'
        os.link(binary, self.root / 'second-link')
        def rejected(observer):
            with self.assertRaisesRegex(M.Rejected, 'PATH_KIND_OR_LINK'):
                M.validate_build(w, scratch, source, observer)
        _, before = self.fs_trace(lambda: rejected(None))
        o = self.observation(); _, after = self.fs_trace(lambda: rejected(o))
        self.assertEqual(after, before)
        self.assertEqual(o.current_stage, 'regular_kind_link')
        self.assertEqual(o.current['facts']['nlink'], 2)
        self.assertEqual(o.current['facts']['owner_matches'], 'unobserved')
        self.assertEqual(o.error, {'category': 'rejected', 'code': 'PATH_KIND_OR_LINK'})
        self.assertNotIn(('daemon', 0), o.roles)

    def test_build_observer_missing_stat_is_unobserved_not_zero(self):
        w, scratch, source = self.build_inputs()
        (w / 'target/debug/deps/ws_integration-deadbeef').unlink()
        o = self.observation()
        self.observation_error(o, lambda: M.validate_build(w, scratch, source, o), FileNotFoundError)
        self.assertEqual(o.current_stage, 'regular_containment')
        self.assertTrue(o.current['facts']['absolute'])
        self.assertEqual(o.current['facts']['contained'], 'unobserved')
        self.assertEqual(o.current['facts']['nlink'], 'unobserved')
        self.assertEqual(o.error, {'category': 'filesystem', 'errno': 'ENOENT'})

    def test_build_observer_symlink_escape_and_size_keep_first_predicate(self):
        w, scratch, source = self.build_inputs()
        binary = w / 'target/debug/deps/ws_integration-deadbeef'
        original = binary.read_bytes(); binary.unlink()
        outside = self.root / 'outside'; outside.write_bytes(original); binary.symlink_to(outside)
        o = self.observation()
        self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(o.error['code'], 'PATH_ESCAPE')
        self.assertEqual(o.current['facts']['ancestor_symlink'], 'unobserved')
        binary.unlink(); inside = binary.with_name('inside'); inside.write_bytes(original); binary.symlink_to(inside)
        o = self.observation()
        self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(o.error['code'], 'PATH_SYMLINK'); self.assertTrue(o.current['facts']['ancestor_symlink'])
        binary.unlink(); binary.write_bytes(original)
        with patch.object(M, 'MAX_TOTAL', 1):
            o = self.observation()
            self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(o.error['code'], 'FILE_OWNER_OR_SIZE')
        self.assertEqual(o.current['facts']['size'], len(original))
        self.assertEqual(o.current['facts']['limit'], 1)
        self.assertTrue(o.current['facts']['owner_matches'])

    def test_build_observer_owner_mismatch_records_only_boolean(self):
        w, scratch, source = self.build_inputs(); uid = os.getuid()
        o = self.observation()
        with patch.object(M.os, 'getuid', return_value=uid + 1):
            self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertFalse(o.current['facts']['owner_matches'])
        self.assertEqual(o.current_stage, 'regular_owner_size')
        self.assertNotIn('uid', json.dumps(o.value()))

    def test_build_observer_fixed_fallbacks_and_short_circuit(self):
        w, scratch, source = self.build_inputs(); o = self.observation()
        M.validate_build(w, scratch, source, o)
        for i in (0, 1, 3):
            self.assertFalse(o.roles[('fallback', i)]['facts']['exists'])
            self.assertEqual(o.roles[('fallback', i)]['facts']['resolved_equal'], 'unobserved')
        self.assertTrue(o.roles[('fallback', 2)]['facts']['resolved_equal'])
        self.assertTrue(o.roles[('fallback', 2)]['facts']['digest_equal'])
        for index, path in ((0, w / 'target/release/x0xd'), (1, w / '../../target/release/x0xd'),
                            (3, w / '../../target/debug/x0xd')):
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'foreign bytes not executed')
            o = self.observation()
            with patch.object(M, 'digest', wraps=M.digest) as hashed:
                self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
            self.assertEqual(o.error['code'], 'DAEMON_ALTERNATE')
            self.assertEqual(o.current['role'], 'fallback'); self.assertEqual(o.current['ordinal'], index)
            self.assertFalse(o.current['facts']['resolved_equal'])
            self.assertEqual(o.current['facts']['digest_equal'], 'unobserved')
            self.assertNotIn(path, [call.args[0] for call in hashed.call_args_list])
            self.assertNotIn(('fallback', index + 1), o.roles)
            path.unlink()

    def test_build_observer_fallback_symlink_and_digest_mismatch(self):
        w, scratch, source = self.build_inputs(); daemon = w / 'target/debug/x0xd'
        path = w / 'target/release/x0xd'; path.parent.mkdir(); path.symlink_to(daemon)
        o = self.observation(); self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(o.error['code'], 'DAEMON_SYMLINK')
        self.assertTrue(o.current['facts']['symlink']); self.assertEqual(o.current['facts']['exists'], 'unobserved')
        path.unlink(); original = M.digest; calls = 0
        def changed(p):
            nonlocal calls
            if p == daemon:
                calls += 1
                if calls == 2: return '0' * 64
            return original(p)
        o = self.observation()
        with patch.object(M, 'digest', side_effect=changed):
            self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(o.current_stage, 'fallback_digest')
        self.assertTrue(o.current['facts']['resolved_equal']); self.assertFalse(o.current['facts']['digest_equal'])
        self.assertEqual(calls, 2)

    def test_build_observer_schema_hash_and_decode_failures_keep_distinct_stages(self):
        w, scratch, source = self.build_inputs()
        metadata = scratch / 'binaries.json'; saved = metadata.read_bytes()
        metadata.write_text('{secret-like-malformed')
        o = self.observation(); self.observation_error(o, lambda: M.validate_build(w, scratch, source, o), ValueError)
        self.assertEqual((o.current_stage, o.error), ('metadata_json', {'category': 'json_or_value'}))
        metadata.write_text('{}')
        o = self.observation(); self.observation_error(o, lambda: M.validate_build(w, scratch, source, o), KeyError)
        self.assertEqual((o.current_stage, o.error), ('target', {'category': 'missing_key'}))
        metadata.write_bytes(saved)
        custody = scratch / 'custody.json'; c = json.loads(custody.read_text()); original = copy.deepcopy(c)
        c['files']['foreign-secret-path'] = '0' * 64; write(custody, c)
        o = self.observation(); self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual((o.current_stage, o.error['code']), ('input_set', 'BUILD_INPUT_SET'))
        first = next(iter(original['files'])); original['files'][first] = '0' * 64; write(custody, original)
        o = self.observation(); self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual((o.current_stage, o.error['code']), ('input_hash', 'BUILD_INPUT_HASH'))
        self.assertFalse(o.current['facts']['digest_equal'])
        self.assertNotIn('secret', json.dumps(o.value()))

    def test_build_observer_open_and_read_race_use_existing_stats_only(self):
        w, scratch, source = self.build_inputs(); original = M.os.fstat; calls = 0
        def changed(fd):
            nonlocal calls
            calls += 1; value = original(fd)
            from types import SimpleNamespace
            if calls == 1:
                return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino + 1, st_size=value.st_size)
            return value
        o = self.observation()
        with patch.object(M.os, 'fstat', side_effect=changed):
            self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(calls, 1); self.assertFalse(o.current['facts']['before_open_equal'])
        self.assertEqual(o.current['facts']['after_read_equal'], 'unobserved')
        self.assertEqual(o.error['code'], 'FILE_RACE')
        calls = 0
        def changed_after(fd):
            nonlocal calls
            calls += 1; value = original(fd)
            from types import SimpleNamespace
            if calls == 2:
                return SimpleNamespace(st_size=value.st_size, st_mtime_ns=value.st_mtime_ns + 1)
            return value
        o = self.observation()
        with patch.object(M.os, 'fstat', side_effect=changed_after):
            self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(calls, 2); self.assertTrue(o.current['facts']['before_open_equal'])
        self.assertFalse(o.current['facts']['after_read_equal']); self.assertEqual(o.error['code'], 'FILE_CHANGED')

    def test_build_observer_preserves_first_failure_and_unavailable_recording(self):
        w, scratch, source = self.build_inputs(); o = self.observation()
        error = KeyError('SECRET_KEY_DO_NOT_RECORD')
        with patch.object(M, 'object_json', side_effect=error), patch.object(o, 'fact', side_effect=RuntimeError('SECRET_TELEMETRY')):
            caught = self.observation_error(o, lambda: M.validate_build(w, scratch, source, o), KeyError)
        self.assertIs(caught, error); self.assertTrue(o.unavailable)
        prior = copy.deepcopy(o.value())
        M.observe(o, 'finish', ValueError('later')); M.observe(o, 'stage', 'target'); M.observe(o, 'role', 'daemon')
        self.assertEqual(o.value(), prior)
        self.assertNotIn('SECRET', json.dumps(o.value()))
        o = self.observation()
        with patch.object(o, 'fact', side_effect=RuntimeError('observer unavailable')):
            self.assertEqual(M.validate_build(w, scratch, source, o)['binary_id'], M.PRODUCER_BINARY_ID)
        self.assertTrue(o.unavailable); self.assertEqual(o.state, 'verified')

    def test_build_observer_never_swallows_cancellation(self):
        w, scratch, source = self.build_inputs(); o = self.observation()
        with patch.object(M, 'object_json', side_effect=M.PublicationCancelled):
            with self.assertRaises(M.PublicationCancelled): M.validate_build(w, scratch, source, o)
        self.assertEqual(o.state, 'in_progress')
        with patch.object(o, 'fact', side_effect=M.PublicationCancelled):
            with self.assertRaises(M.PublicationCancelled): M.observe(o, 'fact', 'absolute', True)

    def test_build_observer_receipt_write_and_post_equality_are_separate(self):
        w, scratch, source = self.build_inputs(); v = M.BuildVerification(source, M.time.monotonic())
        reuse = M.validate_build(w, scratch, source, v.before)
        err = OSError(M.errno.ENOSPC, 'SECRET_PATH')
        def fail(): raise err
        with self.assertRaises(OSError) as caught: M.verification_action(v.write, fail)
        self.assertIs(caught.exception, err); self.assertEqual(v.before.state, 'verified')
        self.assertEqual(v.after.state, 'not_started'); self.assertEqual(v.write['error']['errno'], 'ENOSPC')
        checked = M.validate_build(w, scratch, source, v.after)
        self.assertEqual(checked, reuse)
        with self.assertRaisesRegex(M.Rejected, 'BUILD_DRIFT'):
            M.verification_action(v.equality, lambda: M.require(checked == {}, 'BUILD_DRIFT'))
        self.assertEqual(v.after.state, 'verified'); self.assertEqual(v.equality['error']['code'], 'BUILD_DRIFT')
        self.assertNotIn('SECRET', json.dumps(v.value()))

    def test_build_observer_role_cap_does_not_truncate_actual_input_verification(self):
        w, scratch, source = self.build_inputs(); meta_path = scratch / 'binaries.json'
        meta = json.loads(meta_path.read_text()); rows = next(iter(meta['rust-build-meta']['non-test-binaries'].values()))
        extra = []
        for i in range(20):
            path = w / f'target/debug/inert-{i}'; path.write_bytes(b'data never executed'); extra.append(path)
            rows.append({'name': f'inert-{i}', 'kind': 'bin-exe', 'path': f'debug/inert-{i}'})
        write(meta_path, meta)
        c = json.loads((scratch / 'custody.json').read_text())
        c['files'][str(meta_path)] = M.digest(meta_path)
        c['files'].update({str(p): M.digest(p) for p in extra}); write(scratch / 'custody.json', c)
        o = self.observation(); M.validate_build(w, scratch, source, o)
        self.assertEqual(o.state, 'verified'); self.assertTrue(o.facts_truncated)
        self.assertLessEqual(sum(k[0] in ('input', 'non_test_binary') for k in o.roles), 16)
        c['files'][str(extra[-1])] = '0' * 64; write(scratch / 'custody.json', c)
        o = self.observation(); self.observation_error(o, lambda: M.validate_build(w, scratch, source, o))
        self.assertEqual(o.error['code'], 'BUILD_INPUT_HASH'); self.assertEqual(o.current['role'], 'input')
        self.assertFalse(o.current['facts']['digest_equal'])

    def test_build_observer_closed_error_numeric_and_serialized_bounds(self):
        v = M.BuildVerification({'head': 'a' * 40, 'tree': 'b' * 40}, M.time.monotonic())
        for o in (v.before, v.after):
            o.start()
            for role in ('non_test_binary', 'input'):
                for i in range(100):
                    o.role(role, i)
                    for fact in ('size', 'nlink', 'limit'): o.fact(fact, 10 ** 100)
            o.stage('SECRET_STAGE'); o.fact('SECRET_FIELD', 'SECRET_VALUE')
            o.finish(M.Rejected('SECRET_REJECTION'))
        raw = json.dumps(v.value()).encode()
        self.assertLessEqual(len(raw), 32768); self.assertNotIn(b'SECRET', raw)
        self.assertIn(b'UNRECOGNIZED_REJECTION', raw); self.assertIn(b'overflow', raw)
        for error in (KeyError('SECRET'), ValueError('SECRET'), TypeError('SECRET'), RuntimeError('SECRET'), OSError(999999, 'SECRET')):
            self.assertNotIn('SECRET', json.dumps(M.build_error(error)))
        with patch.object(v.before, 'value', side_effect=ValueError('SECRET_PROJECTION')):
            fallback = v.value()
        self.assertTrue(fallback['before_runtime']['unavailable'])
        self.assertEqual(fallback['before_runtime']['error'], v.before.error)
        self.assertLess(len(json.dumps(fallback).encode()), 32768)
        self.assertNotIn('SECRET', json.dumps(fallback))

    def test_build_observer_private_adjudication_archived_public_schema_unchanged(self):
        private, out, recipient, source, result, age = self.seal_inputs()
        v = M.BuildVerification(source, M.time.monotonic()); v.before.start(); v.before.finish(M.Rejected('PATH_KIND_OR_LINK'))
        write(private / 'adjudication.json', {'result': result, 'gaps': [], 'build_verification': v.value()})
        with patch.object(M, 'run_private', side_effect=self.fake_seal), patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}):
            receipt = M.seal_packet(private, out, recipient, {}, source, result, age, M.time.monotonic() + 120)
        self.assertNotIn('build_verification', json.dumps(receipt))
        manifest = json.loads((private / 'plaintext-manifest.json').read_text())
        self.assertEqual(manifest['adjudication.json'], M.digest(private / 'adjudication.json'))
        with M.tarfile.open(out.parent / 'private-evidence.tar') as archive:
            row = json.loads(archive.extractfile('adjudication.json').read())
        self.assertEqual(row['build_verification']['before_runtime']['error']['code'], 'PATH_KIND_OR_LINK')

    def parent_object(self, parents=None):
        parents = [M.ORIGINAL_PARENT] if parents is None else parents
        return ('tree ' + 'b' * 40 + '\n' + ''.join('parent ' + p + '\n' for p in parents) +
                'author Inert <inert@example.invalid> 0 +0000\n\nmessage\n').encode()

    def test_parent_header_uses_raw_shallow_boundary_not_traversal(self):
        M.verify_parent_header(self.parent_object())
        for raw in (self.parent_object([]), self.parent_object(['f' * 40]),
                    self.parent_object([M.ORIGINAL_PARENT, M.ORIGINAL_PARENT]), self.parent_object(['malformed']),
                    self.parent_object([]) + b'parent ' + M.ORIGINAL_PARENT.encode() + b'\n',
                    self.parent_object().replace(b'parent ', b'parent  ', 1),
                    self.parent_object().replace(b'\n\n', b'\nparent\tmalformed\n\n', 1)):
            with self.assertRaises(M.Rejected): M.verify_parent_header(raw)
        with self.assertRaisesRegex(M.Rejected, 'PARENT_OBJECT_BOUND'): M.verify_parent_header(b'x' * (M.COMMIT_LIMIT + 1))
        with self.assertRaisesRegex(M.Rejected, 'PARENT_HEADER_BOUND'):
            M.verify_parent_header(b'x' * (M.COMMIT_HEADER_LIMIT + 1) + b'\n\n')

    def test_parent_read_bounded_pipe_and_owned_cleanup_only_fake_process(self):
        from types import SimpleNamespace
        class Fake:
            pid = 999999
            returncode = None
            stdout = SimpleNamespace(fileno=lambda: 98, close=lambda: None)
            def poll(self): return self.returncode
            def wait(self, timeout=None): self.returncode = 0; return 0
        raw = self.parent_object(); child = Fake(); chunks = [raw, b'']
        with patch.object(M.subprocess, 'Popen', return_value=child) as spawn, patch.object(M.os, 'set_blocking'), \
             patch.object(M.select, 'select', return_value=([child.stdout], [], [])), \
             patch.object(M.os, 'read', side_effect=lambda _fd, count: chunks.pop(0)) as read, \
             patch.object(M.os, 'killpg') as kill:
            self.assertEqual(M.read_parent_commit(self.root, M.time.monotonic() + 30), raw)
        self.assertEqual(spawn.call_args.args[0], ['git', 'cat-file', 'commit', M.PARENT])
        self.assertTrue(all(c.args[1] <= 4096 for c in read.call_args_list)); kill.assert_not_called()
        for mode in ('overflow', 'timeout', 'cancel'):
            child = Fake(); child.returncode = None
            def fake_read(_fd, count):
                if mode == 'cancel': raise M.PublicationCancelled()
                return b'x' * count
            with patch.object(M.subprocess, 'Popen', return_value=child), patch.object(M.os, 'set_blocking'), \
                 patch.object(M.select, 'select', return_value=([] if mode == 'timeout' else [child.stdout], [], [])), \
                 patch.object(M.os, 'read', side_effect=fake_read), patch.object(M.os, 'killpg') as kill:
                with self.assertRaises(M.PublicationCancelled if mode == 'cancel' else M.Rejected):
                    M.read_parent_commit(self.root, M.time.monotonic() + 30)
            kill.assert_called_once_with(child.pid, M.signal.SIGTERM)
            self.assertEqual(child.returncode, 0)

    def test_successor_guard_exact_three_paths_tree_and_parent(self):
        sha = 'e' * 40
        responses = {('rev-parse', 'HEAD'): sha.encode(), ('show', '-s', '--format=%P', 'HEAD'): M.PARENT.encode(),
                     ('status', '--porcelain'): b'', ('rev-parse', M.PARENT + '^{tree}'): M.PARENT_TREE.encode(),
                     ('diff', '--name-only', M.PARENT, 'HEAD'): '\n'.join(sorted(M.OBSERVABILITY_PATHS)).encode(),
                     ('ls-tree', '-rz', '--full-tree', 'HEAD'): b'', ('rev-parse', 'HEAD^{tree}'): b'a' * 40}
        def run(raw=None):
            with patch.object(M.subprocess, 'check_output', side_effect=lambda args, **kw: responses[tuple(args[1:])]), \
                 patch.object(M, 'read_parent_commit', return_value=self.parent_object() if raw is None else raw), patch.object(M, 'digest', return_value=M.LOCK):
                return M.source_map(self.root, sha)
        self.assertEqual(run()['parents'], [M.PARENT])
        with self.assertRaisesRegex(M.Rejected, 'PARENT_ANCESTRY'): run(self.parent_object(['f' * 40]))
        for key, value, code in ((('show', '-s', '--format=%P', 'HEAD'), M.ORIGINAL_PARENT.encode(), 'SOURCE_PARENT'),
                                 (('rev-parse', M.PARENT + '^{tree}'), b'0' * 40, 'PARENT_TREE'),
                                 (('diff', '--name-only', M.PARENT, 'HEAD'), b'extra\n' + responses[('diff', '--name-only', M.PARENT, 'HEAD')], 'CONTRIBUTION_SCOPE')):
            saved = responses[key]; responses[key] = value
            with self.assertRaisesRegex(M.Rejected, code): run()
            responses[key] = saved

    def test_parent_read_eof_nonzero_and_wait_timeout_do_not_lose_reap(self):
        from types import SimpleNamespace
        class Fake:
            pid = 999999
            returncode = None
            stdout = SimpleNamespace(fileno=lambda: 98, close=lambda: None)
            def __init__(self, stalled): self.stalled, self.waits = stalled, []
            def poll(self): return self.returncode
            def wait(self, timeout=None):
                self.waits.append(timeout)
                if self.stalled and len(self.waits) == 1:
                    raise M.subprocess.TimeoutExpired('inert-only', timeout)
                self.returncode = 1
                return 1
        for stalled in (False, True):
            child = Fake(stalled)
            with patch.object(M.subprocess, 'Popen', return_value=child), patch.object(M.os, 'set_blocking'), \
                 patch.object(M.select, 'select', return_value=([child.stdout], [], [])), \
                 patch.object(M.os, 'read', return_value=b''), patch.object(M.os, 'killpg') as kill, \
                 patch.object(M.time, 'monotonic', return_value=100):
                with self.assertRaises(M.subprocess.TimeoutExpired if stalled else M.Rejected):
                    M.read_parent_commit(self.root, 130)
            self.assertEqual(child.returncode, 1)
            self.assertEqual(child.waits[0], 10)
            if stalled:
                kill.assert_called_once_with(child.pid, M.signal.SIGTERM)
                self.assertEqual(child.waits[1], 20)
            else:
                kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
