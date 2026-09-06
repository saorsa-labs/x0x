import importlib.util
import errno
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('diagnostic', Path(__file__).with_name('diagnostic.py'))
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


probe_spec = importlib.util.spec_from_file_location('probes', Path(__file__).with_name('probes.py'))
probes = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probes)


class ForbiddenUdpControls(unittest.TestCase):
    def test_permission_denial_is_recorded(self):
        for number in (errno.EPERM, errno.EACCES):
            with self.subTest(errno=number):
                sock = MagicMock()
                sock.sendto.side_effect = OSError(number, 'fixture denied')
                self.assertEqual(probes.forbidden_udp_send(sock, ('127.0.0.1', 29483)),
                                 {'outcome': 'denied', 'errno': number})
                sock.sendto.assert_called_once_with(probes.PAYLOAD, ('127.0.0.1', 29483))

    def test_successful_send_is_recorded_without_claiming_delivery(self):
        sock = MagicMock()
        self.assertEqual(probes.forbidden_udp_send(sock, ('::1', 29483)),
                         {'outcome': 'sent', 'errno': None})
        sock.sendto.assert_called_once_with(probes.PAYLOAD, ('::1', 29483))

    def test_unexpected_send_error_fails(self):
        sock = MagicMock()
        sock.sendto.side_effect = OSError(errno.ENETUNREACH, 'fixture wrong route')
        with self.assertRaises(OSError) as raised:
            probes.forbidden_udp_send(sock, ('127.0.0.1', 29483))
        self.assertEqual(raised.exception.errno, errno.ENETUNREACH)

    def family_with_delivery(self, delivered):
        # Exercise actual family_control counter collection, with no real sockets.
        sockets = [MagicMock() for _ in range(5)]
        for sock in sockets[:2]:
            connection = MagicMock()
            connection.__enter__.return_value = connection
            connection.recv.return_value = probes.PAYLOAD
            sock.accept.return_value = (connection, ('127.0.0.1', 44000))
        sockets[2].recvfrom.side_effect = [(probes.PAYLOAD, ('127.0.0.1', 29482)),
                                         (b'reply-received', ('127.0.0.1', 29482))]
        sockets[3].accept.side_effect = probes.socket.timeout()
        if delivered:
            sockets[4].recvfrom.return_value = (probes.PAYLOAD, ('127.0.0.1', 29482))
        else:
            sockets[4].recvfrom.side_effect = probes.socket.timeout()
        child = subprocess.CompletedProcess([], 0, stdout='fixture', stderr='')
        with patch.object(probes.socket, 'socket', side_effect=sockets), \
                patch.object(probes.subprocess, 'run', return_value=child):
            return probes.family_control('4')

    def test_zero_delivery_family_control_passes(self):
        result = self.family_with_delivery(False)
        self.assertEqual(result['forbidden_counters'], {'tcp': 0, 'udp': 0})
        self.assertEqual(result['server_positive'], [True]*4)

    def test_received_forbidden_packet_fails_actual_family_control(self):
        with self.assertRaisesRegex(AssertionError, "'udp': 1"):
            self.family_with_delivery(True)


class SourceCustodyControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.source/'tests').mkdir()
        (self.source/'tests'/'sample.rs').write_text('original\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')
        (self.source/'tests'/'sample.rs').write_text('reviewed\n')
        self.commit()
        self.expected = self.git('rev-parse', 'HEAD:tests')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.source, text=True).strip()

    def commit(self):
        self.git('add', 'tests')
        self.git('-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture')

    def test_identical_source_accepts_different_diff_presentation(self):
        short = self.git('-c', 'core.abbrev=7', 'diff', '--unified=0', self.base, 'HEAD', '--', 'tests')
        long = self.git('-c', 'core.abbrev=12', 'diff', '--unified=0', self.base, 'HEAD', '--', 'tests')
        self.assertNotEqual(short, long)  # Old byte-comparison oracle rejects this same tree.
        self.git('config', 'core.abbrev', '12')
        diag.verify_test_source(self.source, self.expected)

    def test_committed_byte_drift_rejected(self):
        (self.source/'tests'/'sample.rs').write_text('unreviewed\n')
        self.commit()
        with self.assertRaisesRegex(AssertionError, 'committed'):
            diag.verify_test_source(self.source, self.expected)

    def test_added_test_path_rejected(self):
        (self.source/'tests'/'extra.rs').write_text('unreviewed\n')
        self.commit()
        with self.assertRaisesRegex(AssertionError, 'committed'):
            diag.verify_test_source(self.source, self.expected)

    def test_removed_test_path_rejected(self):
        (self.source/'tests'/'sample.rs').unlink()
        (self.source/'tests'/'other.rs').write_text('reviewed\n')
        self.commit()
        with self.assertRaisesRegex(AssertionError, 'committed'):
            diag.verify_test_source(self.source, self.expected)

    def test_working_tree_drift_rejected(self):
        (self.source/'tests'/'sample.rs').write_text('unreviewed\n')
        with self.assertRaisesRegex(AssertionError, 'working'):
            diag.verify_test_source(self.source, self.expected)

    def test_staged_test_source_rejected(self):
        (self.source/'tests'/'sample.rs').write_text('unreviewed\n')
        self.git('add', 'tests')
        with self.assertRaisesRegex(AssertionError, 'working'):
            diag.verify_test_source(self.source, self.expected)

    def test_untracked_test_source_rejected(self):
        (self.source/'tests'/'extra.rs').write_text('unreviewed\n')
        with self.assertRaisesRegex(AssertionError, 'working'):
            diag.verify_test_source(self.source, self.expected)


class DiagnosticControls(unittest.TestCase):
    def test_expected_sockets(self):
        for line in (
            'tcp LISTEN 0 128 127.0.0.1:29381 0.0.0.0:* users:fixture',
            'tcp ESTAB 0 0 127.0.0.1:44001 127.0.0.1:29382',
            'tcp ESTAB 0 0 127.0.0.1:29382 127.0.0.1:44001',
            'udp UNCONN 0 0 0.0.0.0:29481 0.0.0.0:*',
            'udp UNCONN 0 0 [::]:29482 [::]:*',
        ):
            self.assertTrue(diag.valid_socket(line), line)

    def test_foreign_and_malformed_sockets_stop_admission(self):
        for line in (
            'tcp LISTEN 0 128 0.0.0.0:29381 0.0.0.0:*',
            'tcp ESTAB 0 0 127.0.0.1:44001 127.0.0.1:12700',
            'tcp ESTAB 0 0 127.0.0.1:29381 192.0.2.1:44001',
            'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*',
            'udp ESTAB 0 0 127.0.0.1:29481 127.0.0.1:59949',
            'udp UNCONN 0 0 192.0.2.1:29481 0.0.0.0:*', 'unparsed',
        ):
            self.assertFalse(diag.valid_socket(line), line)

    def test_exactly_one_matching_case_required(self):
        case = {'filter-match': {'status': 'matches'}}
        good = {'rust-suites': {'suite': {'testcases': {diag.TEST: case}}}}
        self.assertTrue(diag.selected_test(good))
        self.assertFalse(diag.selected_test({}))
        self.assertFalse(diag.selected_test({'rust-suites': {'suite': {'testcases': {'wrong': case}}}}))
        good['rust-suites']['other'] = {'testcases': {diag.TEST: case}}
        self.assertFalse(diag.selected_test(good))

    def test_only_drop_counters_count_for_fence_witness(self):
        rules = {'nftables': [
            {'rule': {'expr': [{'counter': {'packets': 20}}, {'accept': None}]}},
            {'rule': {'expr': [{'counter': {'packets': 3}}, {'drop': None}]}}]}
        self.assertEqual(diag.drop_count(rules), 3)

    def test_collector_excludes_raw_state_tokens_and_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            evidence = Path(root)
            raw = evidence/'private-data'
            logs = raw/'logs'
            logs.mkdir(parents=True)
            (raw/'api-token').write_text('fixture-secret')
            (raw/'machine.key').write_text('fixture-secret')
            (logs/'pair-alice.start.log').write_text('safe-log')
            (evidence/'receipt.json').write_text('{}')
            (evidence/'fixture.stdout').symlink_to(raw/'api-token')
            diag.collect(evidence)
            names = {p.name for p in (evidence/'upload').iterdir()}
            self.assertEqual(names, {'receipt.json', 'pair-alice.start.log', 'collection.json'})
            self.assertNotIn('fixture-secret', ''.join(p.read_text() for p in (evidence/'upload').iterdir()))


    def test_symlinked_log_directory_cannot_export_external_files(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            evidence, outside = base/'evidence', base/'outside'
            evidence.mkdir(); outside.mkdir()
            (outside/'pair-alice.start.log').write_text('external-secret')
            (evidence/'private-data').mkdir()
            (evidence/'private-data'/'logs').symlink_to(outside, target_is_directory=True)
            diag.collect(evidence)
            self.assertFalse((evidence/'upload'/'pair-alice.start.log').exists())

    def test_symlinked_data_ancestor_cannot_export_external_files(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            evidence, outside = base/'evidence', base/'outside'
            evidence.mkdir(); (outside/'logs').mkdir(parents=True)
            (outside/'logs'/'pair-alice.start.log').write_text('external-secret')
            (evidence/'private-data').symlink_to(outside, target_is_directory=True)
            diag.collect(evidence)
            self.assertFalse((evidence/'upload'/'pair-alice.start.log').exists())

    def test_symlinked_upload_directory_refused(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            evidence, outside = base/'evidence', base/'outside'
            evidence.mkdir(); outside.mkdir()
            (evidence/'receipt.json').write_text('{}')
            (evidence/'upload').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                diag.collect(evidence)
            self.assertEqual(list(outside.iterdir()), [])

    def test_preexisting_upload_destination_cannot_overwrite_external_file(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            evidence = base/'evidence'
            (evidence/'upload').mkdir(parents=True)
            external = base/'sentinel'
            external.write_text('preserve-me')
            (evidence/'receipt.json').write_text('{}')
            (evidence/'upload'/'receipt.json').symlink_to(external)
            with self.assertRaises(FileExistsError):
                diag.collect(evidence)
            self.assertEqual(external.read_text(), 'preserve-me')


    def test_workflow_never_uploads_after_rejected_collection(self):
        import yaml
        workflow = yaml.safe_load((Path(__file__).resolve().parents[2]/'workflows'/'build.yml').read_text())
        steps = workflow['jobs']['diagnostic']['steps']
        collect = next(step for step in steps if step.get('name') == 'Assemble explicit evidence whitelist')
        upload = next(step for step in steps if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(collect['if'], 'always()')  # Salvage a failed fixture's diagnostics.
        # Evaluate the actual workflow predicate's supported conjunction terms.
        # Removing the collection gate makes all negative outcomes incorrectly admit upload.
        def admitted(outcome):
            terms = {
                'always()': True,
                "steps.collect.outcome == 'success'": outcome == 'success',
            }
            return all(terms[term.strip()] for term in upload['if'].split('&&'))
        for outcome in ('failure', 'cancelled', 'skipped'):
            self.assertFalse(admitted(outcome), outcome)
        self.assertTrue(admitted('success'))
        self.assertEqual(collect.get('id'), 'collect')


    def test_artifact_path_is_bound_from_runner_environment_at_step_runtime(self):
        import subprocess
        import yaml
        workflow = yaml.safe_load((Path(__file__).resolve().parents[2]/'workflows'/'build.yml').read_text())
        job = workflow['jobs']['diagnostic']
        self.assertNotIn('DIAG_ARTIFACTS', job['env'])
        self.assertFalse(any('runner.' in str(value) for value in job['env'].values()))
        binding = next(step for step in job['steps'] if step.get('name') == 'Bind isolated evidence path')
        self.assertEqual(binding['shell'], 'bash')
        self.assertNotIn('${{', binding['run'])
        with tempfile.TemporaryDirectory(prefix='531 path with spaces ') as root:
            env_file = Path(root)/'github-env'
            result = subprocess.run(['bash', '-eu', '-c', binding['run']],
                                    env={'PATH': '/usr/bin:/bin', 'RUNNER_TEMP': root,
                                         'GITHUB_ENV': str(env_file)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(env_file.read_text(), f'DIAG_ARTIFACTS={root}/x0x-531-evidence\n')
        # This proves shell binding and catches the previous unsupported location;
        # it does not claim to emulate GitHub's expression-context validator.
        upload = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/x0x-531-evidence/upload/')


if __name__ == '__main__':
    unittest.main()
