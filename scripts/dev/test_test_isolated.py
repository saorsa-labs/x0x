#!/usr/bin/env python3
"""Inert entrypoint controls: stub commands, no Cargo or namespace execution."""
import importlib.util
import json
import os
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('developer_launcher', Path(__file__).with_name('test-isolated.py'))
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)
REPOSITORY = Path(__file__).resolve().parents[2]


class Routes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='x0x-dev-stub-', dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.calls = []
        self.fail = None
        self.failure_code = 23
        self.interrupt = False
        self.report_bytes = None
        self.before_threshold = None
        self.real_threshold = False
        self.addCleanup(patch.stopall)
        patch.object(launcher.sys, 'platform', 'linux').start()
        patch.object(launcher.os, 'getuid', return_value=self.root.stat().st_uid).start()
        patch.object(launcher.os.path, 'isfile', return_value=True).start()
        patch.object(launcher.os, 'access', return_value=True).start()
        patch.object(launcher.shutil, 'which', side_effect=lambda name: '/stub/' + name).start()
        patch.object(launcher, 'run', side_effect=self.stub).start()

    def stub(self, command, root, env, capture=False):
        self.calls.append((list(command), root, dict(env)))
        if self.interrupt and command[:2] == ['bash', '-c']:
            raise KeyboardInterrupt()
        if self.fail and self.fail(command):
            raise subprocess.CalledProcessError(self.failure_code, command)
        if command[:2] == ['bash', '-c'] and '--output-path' in command and self.report_bytes is not None:
            output = Path(command[command.index('--output-path') + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(self.report_bytes)
        if command[:2] == ['python3', 'scripts/check-coverage-thresholds.py']:
            if self.before_threshold is not None:
                callback, self.before_threshold = self.before_threshold, None
                callback()
            if self.real_threshold:
                return subprocess.run(['python3', str(REPOSITORY / command[1]), *command[2:]],
                                      cwd=root, env=env, check=True, capture_output=True, text=True)
        return subprocess.CompletedProcess(command, 0, stdout='export CARGO_LLVM_COV=1\n')

    def invoke(self, *args):
        return launcher.main(list(args), self.root)

    def test_exact_build_runtime_and_emulated_arguments(self):
        build = ['-p', 'x0x', '--all-features', '--test', 'kv_append_only_rest']
        runtime = ['--no-fail-fast', '-E', 'test(a b)', '--', '--ignored']
        self.invoke('nextest', *build, '--', *runtime)
        self.assertEqual(self.calls[-1][0], ['bash', 'scripts/ci/nextest-isolated.sh', *build, '--', *runtime])
        self.assertTrue(all(call[0][:3] != ['cargo', 'nextest', 'run'] for call in self.calls))

    def test_unique_retained_scratch_preserves_normal_target(self):
        with patch.dict(os.environ, {'CARGO_TARGET_DIR': '/sentinel-existing-target', 'RUNNER_TEMP': '/tmp/ambient'}):
            self.invoke('nextest', '--all-features', '--workspace', '--')
            first = self.calls[-1][2]
            self.invoke('nextest', '--all-features', '--workspace', '--')
            second = self.calls[-1][2]
        self.assertNotEqual(first['RUNNER_TEMP'], second['RUNNER_TEMP'])
        for env in (first, second):
            self.assertEqual(env['CARGO_TARGET_DIR'], '/sentinel-existing-target')
            self.assertTrue(Path(env['RUNNER_TEMP']).is_relative_to(self.root / 'target/dev-isolation'))
            self.assertTrue(Path(env['RUNNER_TEMP']).is_dir())

    def test_unsupported_hosts_and_root_refuse_before_commands(self):
        for platform, uid in [('darwin', 501), ('win32', 501), ('linux', 0)]:
            with self.subTest(platform=platform, uid=uid), patch.object(launcher.sys, 'platform', platform), patch.object(launcher.os, 'getuid', return_value=uid):
                with self.assertRaises(ValueError):
                    self.invoke('voice')
        self.assertEqual(self.calls, [])
        self.assertFalse((self.root / 'target').exists())

    def test_missing_namespace_tool_refuses_before_commands(self):
        for missing in launcher.NAMESPACE_TOOLS:
            with self.subTest(missing=missing), patch.object(launcher.os.path, 'isfile', side_effect=lambda name: name != missing):
                with self.assertRaises(ValueError):
                    self.invoke('nextest', '--')
        self.assertEqual(self.calls, [])

    def test_missing_cargo_or_permission_has_no_runtime_fallback(self):
        with patch.object(launcher.shutil, 'which', return_value=None):
            with self.assertRaises(ValueError):
                self.invoke('voice')
        self.assertEqual(self.calls, [])
        self.fail = lambda command: command[0] == '/usr/bin/sudo'
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('voice')
        self.assertEqual(len(self.calls), 1)

    def test_missing_nextest_and_failed_wrapper_propagate(self):
        for predicate in [lambda c: c[:3] == ['cargo', 'nextest', '--version'], lambda c: c[0] == 'bash']:
            self.calls.clear()
            self.fail = predicate
            with self.assertRaises(subprocess.CalledProcessError) as error:
                self.invoke('nextest', '--')
            self.assertEqual(error.exception.returncode, 23)
            self.assertTrue(predicate(self.calls[-1][0]))

    def test_missing_separator_private_tmp_and_symlink_refuse(self):
        with self.assertRaises(ValueError):
            self.invoke('nextest', '--workspace')
        with self.assertRaises(ValueError):
            launcher.main(['nextest', '--'], Path('/tmp/x0x-never-created'))
        external = self.root / 'external'
        external.mkdir()
        (self.root / 'target').symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.invoke('nextest', '--')
        self.assertEqual(self.calls, [])
        self.assertEqual(list(external.iterdir()), [])

    def test_voice_prepares_then_wraps_selection_and_execution(self):
        self.invoke('voice')
        operations = self.calls[2:]
        self.assertEqual(operations[0][0], ['cargo', 'test', '--all-features', '--test', 'voice_datagram_e2e', '--no-run'])
        self.assertEqual(operations[1][0], ['python3', 'scripts/ci/isolated-runtime.py', 'python3', 'scripts/ci/voice-datagram-selection.py'])
        self.assertEqual(operations[1][2]['X0X_ISOLATION_ROLE'], 'selection')
        self.assertEqual(operations[2][0], ['bash', 'scripts/ci/nextest-isolated.sh', '--all-features', '--test', 'voice_datagram_e2e', '--', '--run-ignored', 'ignored-only', '--test-threads', '1'])
        self.assertEqual(operations[2][2]['X0X_ISOLATION_ROLE'], 'acceptance')

    def test_empty_or_failed_voice_selection_cannot_start_runtime(self):
        self.fail = lambda c: 'scripts/ci/voice-datagram-selection.py' in c
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('voice')
        self.assertFalse(any(c[0][0] == 'bash' for c in self.calls))

    def test_coverage_owns_fresh_target_and_preserves_report_arguments(self):
        self.invoke('coverage', '--all-features', '--workspace', '--', '--package', '*', '--lcov', '--output-path', 'space name.info', '--fail-under-lines', '48')
        command, _, env = self.calls[-1]
        scratch = Path(env['RUNNER_TEMP'])
        self.assertEqual(env['CARGO_TARGET_DIR'], str(scratch / 'coverage-target'))
        self.assertEqual(env['CARGO_LLVM_COV_TARGET_DIR'], env['CARGO_TARGET_DIR'])
        self.assertEqual(command[5:], ['2', '--all-features', '--workspace', '--package', '*', '--lcov', '--output-path', 'space name.info', '--fail-under-lines', '48'])
        self.assertFalse((scratch / 'coverage-target').exists())  # Stubs never build targets.
        self.assertFalse(json.loads((scratch / 'coverage-owner.json').read_text())['active'])
        self.assertFalse(any('clean' in c[0] for c in self.calls))

    def test_interrupted_coverage_remains_active_and_uncleanable(self):
        self.interrupt = True
        with self.assertRaises(KeyboardInterrupt):
            self.invoke('coverage', '--workspace', '--', '--summary-only')
        scratch = Path(self.calls[-1][2]['RUNNER_TEMP'])
        self.assertTrue(json.loads((scratch / 'coverage-owner.json').read_text())['active'])
        with patch.object(launcher.shutil, 'rmtree') as remove:
            with self.assertRaises(ValueError):
                launcher.clean_coverage(self.root, str(scratch))
            remove.assert_not_called()

    def test_failed_or_killed_coverage_shell_does_not_unlock_cleanup(self):
        self.fail = lambda command: command[:2] == ['bash', '-c']
        for code in (23, -15):
            with self.subTest(returncode=code):
                self.failure_code = code
                with self.assertRaises(subprocess.CalledProcessError) as error:
                    self.invoke('coverage', '--workspace', '--', '--summary-only')
                self.assertEqual(error.exception.returncode, code)
                scratch = Path(self.calls[-1][2]['RUNNER_TEMP'])
                self.assertTrue(json.loads((scratch / 'coverage-owner.json').read_text())['active'])
                with patch.object(launcher.shutil, 'rmtree') as remove:
                    with self.assertRaises(ValueError):
                        launcher.clean_coverage(self.root, str(scratch))
                    remove.assert_not_called()

    def test_cleanup_requires_canonical_completed_marker_and_owned_child(self):
        self.invoke('coverage', '--workspace', '--', '--html')
        scratch = Path(self.calls[-1][2]['RUNNER_TEMP'])
        target = scratch / 'coverage-target'
        target.mkdir()  # Empty inert directory, never a Cargo target build.
        marker = scratch / 'coverage-owner.json'
        good = json.loads(marker.read_text())
        with patch.object(launcher.shutil, 'rmtree') as remove:
            launcher.clean_coverage(self.root, str(scratch))
            remove.assert_called_once_with(target)
            remove.reset_mock()
            for wrong in [{**good, 'workspace': '/elsewhere'}, {**good, 'active': True}, {**good, 'schema': 'foreign'}]:
                marker.write_text(json.dumps(wrong))
                with self.assertRaises(ValueError):
                    launcher.clean_coverage(self.root, str(scratch))
            marker.write_text(json.dumps(good))
            with self.assertRaises(ValueError):
                launcher.clean_coverage(self.root, str(self.root))
            alias = scratch.parent / 'run-alias'
            alias.symlink_to(scratch, target_is_directory=True)
            with self.assertRaises(ValueError):
                launcher.clean_coverage(self.root, str(alias))
            remove.assert_not_called()

    def test_cleanup_refuses_foreign_owner_and_target_or_marker_symlinks(self):
        self.invoke('coverage', '--workspace', '--', '--html')
        scratch = Path(self.calls[-1][2]['RUNNER_TEMP'])
        target = scratch / 'coverage-target'
        marker = scratch / 'coverage-owner.json'
        outside = self.root / 'untouched'
        outside.mkdir()
        target.symlink_to(outside, target_is_directory=True)
        with patch.object(launcher.shutil, 'rmtree') as remove:
            with self.assertRaises(ValueError):
                launcher.clean_coverage(self.root, str(scratch))
            target.unlink()  # Only a disposable test symlink, never a cache.
            original = scratch / 'original-marker.json'
            marker.rename(original)
            marker.symlink_to(original)
            with self.assertRaises(ValueError):
                launcher.clean_coverage(self.root, str(scratch))
            with patch.object(launcher.os, 'getuid', return_value=scratch.stat().st_uid + 1):
                with self.assertRaises(ValueError):
                    launcher.clean_coverage(self.root, str(scratch))
            remove.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_check_and_quick_check_inherit_routed_test_recipe(self):
        just = subprocess.run(['just', '--dry-run', 'check', 'quick-check'], cwd=REPOSITORY, capture_output=True, text=True, check=True)
        self.assertIn('scripts/dev/test-isolated.py nextest --all-features --workspace --', just.stderr)
        self.assertNotIn('cargo nextest run', just.stderr)

    def test_coverage_recipes_select_workspace_only_before_report_separator(self):
        for recipe in ('coverage', 'coverage-summary'):
            with self.subTest(recipe=recipe):
                result = subprocess.run(['just', '--dry-run', recipe], cwd=REPOSITORY, capture_output=True, text=True, check=True)
                command = next(shlex.split(line) for line in result.stderr.splitlines()
                               if line.startswith('python3 scripts/dev/test-isolated.py coverage '))
                build, report = launcher.split_arguments(command[3:])
                self.assertEqual(build, ['--all-features', '--workspace'])
                self.assertEqual(report[:2], ['--package', '*'])
                self.assertNotIn('--workspace', report)
                self.assertNotIn('--all-features', report)

    def test_recipe_flags_and_coverage_threshold_are_preserved(self):
        expected = {
            'test-verbose': 'nextest --all-features --workspace -- --no-capture',
            'test-full': 'nextest --all-features --workspace -- --no-fail-fast',
            'adr-gates-f1': "-- --no-fail-fast --test-threads=1 -E 'test(/(^|::)f1_/)'",
            'adr-gates-f1-live': "--run-ignored all -E 'test(/(^|::)f1_.*_live/)'",
            'test-kv-e2e': '--test kv_append_only_rest -- -- --ignored',
            'test-recovery-e2e': '--test crdt_subscription_persistence -- --run-ignored all',
            'test-voice-datagram-e2e': 'scripts/dev/test-isolated.py voice',
            'coverage': "--workspace -- --package '*' --html",
            'coverage-summary': "--workspace -- --package '*' --summary-only",
            'coverage-lcov': 'scripts/dev/test-isolated.py coverage-lcov',
            'coverage-check': 'scripts/dev/test-isolated.py coverage-check',
        }
        for recipe, fragment in expected.items():
            with self.subTest(recipe=recipe):
                result = subprocess.run(['just', '--dry-run', recipe], cwd=REPOSITORY, capture_output=True, text=True, check=True)
                self.assertIn(fragment, result.stderr)
                self.assertNotIn('cargo nextest run', result.stderr)
        result = subprocess.run(['just', '--dry-run', 'coverage-check'], cwd=REPOSITORY, capture_output=True, text=True, check=True)
        self.assertNotIn('scripts/check-coverage-thresholds.py', result.stderr)
        self.assertNotIn('--output-path lcov.info', result.stderr)


    def test_private_modes_bind_report_helper_and_preserve_both_gates(self):
        self.report_bytes = b'SF:src/example.rs\nLF:100\nLH:80\nend_of_record\n'
        reports = []
        for mode in ('coverage-lcov', 'coverage-check'):
            self.calls.clear()
            self.invoke(mode)
            shell = next(c for c in self.calls if c[0][:2] == ['bash', '-c'])
            command, _, env = shell
            report = Path(command[command.index('--output-path') + 1])
            reports.append(report)
            self.assertEqual(report, Path(env['CARGO_TARGET_DIR']) / 'reports/lcov.info')
            self.assertTrue(report.is_absolute())
            expected = ['2', '--all-features', '--workspace', '--package', '*', '--lcov', '--output-path', str(report)]
            helpers = [c for c in self.calls if c[0][:2] == ['python3', 'scripts/check-coverage-thresholds.py']]
            if mode == 'coverage-check':
                expected += ['--fail-under-lines', '48']
                self.assertEqual(helpers[0][0], ['python3', 'scripts/check-coverage-thresholds.py', '--lcov', str(report), '--thresholds', 'coverage-thresholds.toml', '--enforce-global'])
            else:
                self.assertEqual(helpers, [])
            self.assertEqual(command[5:], expected)
            self.assertEqual((self.root / 'lcov.info').read_bytes(), report.read_bytes())
            self.assertFalse(json.loads((Path(env['RUNNER_TEMP']) / 'coverage-owner.json').read_text())['active'])
        self.assertNotEqual(*reports)
        for mode in ('coverage-lcov', 'coverage-check'):
            with self.assertRaises(ValueError):
                self.invoke(mode, '--output-path', 'elsewhere')

    def test_interleaving_shared_mirror_cannot_change_private_threshold_result(self):
        # Real pure helper, tiny LCOV/TOML inputs; no Cargo or network execution.
        (self.root / 'coverage-thresholds.toml').write_text('[global]\nline_floor = 65.7\n')
        self.real_threshold = True
        for a_hits, b_hits in ((50, 90), (90, 50)):
            with self.subTest(a=a_hits, b=b_hits):
                make = lambda hits: f'SF:src/example.rs\nLF:100\nLH:{hits}\nend_of_record\n'.encode()
                self.report_bytes = make(a_hits)
                legacy_results = []
                def publish_b():
                    self.report_bytes = make(b_hits)
                    self.invoke('coverage-lcov')
                    old = subprocess.run(['python3', str(REPOSITORY / 'scripts/check-coverage-thresholds.py'), '--lcov', 'lcov.info', '--thresholds', 'coverage-thresholds.toml', '--enforce-global'], cwd=self.root, capture_output=True)
                    legacy_results.append(old.returncode)
                self.before_threshold = publish_b
                if a_hits < 65.7:
                    with self.assertRaises(subprocess.CalledProcessError):
                        self.invoke('coverage-check')
                else:
                    self.invoke('coverage-check')
                self.assertEqual(legacy_results, [0 if b_hits > 65.7 else 1])
                # The old shared-path helper gives the opposite answer to A.
                self.assertEqual((self.root / 'lcov.info').read_bytes(), make(b_hits if a_hits < 65.7 else a_hits))

    def test_private_report_failures_keep_marker_active_and_skip_later_steps(self):
        for failure in ('missing', 'helper', 'mirror', 'shell', 'signal', 'interrupt'):
            with self.subTest(failure=failure):
                self.calls.clear()
                self.report_bytes = None if failure == 'missing' else b'report'
                self.failure_code = -15 if failure == 'signal' else 23
                self.interrupt = failure == 'interrupt'
                self.fail = (lambda c: c[:2] == ['python3', 'scripts/check-coverage-thresholds.py']) if failure == 'helper' else ((lambda c: c[:2] == ['bash', '-c']) if failure in ('shell', 'signal') else None)
                with patch.object(launcher, 'mirror_report', side_effect=OSError('mirror fault') if failure == 'mirror' else launcher.mirror_report) as mirror:
                    with self.assertRaises((OSError, subprocess.CalledProcessError, KeyboardInterrupt)):
                        self.invoke('coverage-check')
                    if failure in ('helper', 'shell', 'signal', 'interrupt'):
                        mirror.assert_not_called()
                shell = next(c for c in self.calls if c[0][:2] == ['bash', '-c'])
                scratch = Path(shell[2]['RUNNER_TEMP'])
                self.assertTrue(json.loads((scratch / 'coverage-owner.json').read_text())['active'])
                if failure in ('shell', 'signal', 'interrupt'):
                    self.assertFalse(any(c[0][:2] == ['python3', 'scripts/check-coverage-thresholds.py'] for c in self.calls))
                with patch.object(launcher.shutil, 'rmtree') as remove:
                    with self.assertRaises(ValueError):
                        launcher.clean_coverage(self.root, str(scratch))
                    remove.assert_not_called()

    def test_success_cleanup_removes_private_report_preserves_mirror_and_marker(self):
        self.report_bytes = b'complete private report'
        self.invoke('coverage-lcov')
        scratch = Path(self.calls[-1][2]['RUNNER_TEMP'])
        marker = scratch / 'coverage-owner.json'
        before = marker.read_bytes()
        launcher.clean_coverage(self.root, str(scratch))
        self.assertFalse((scratch / 'coverage-target').exists())
        self.assertEqual(marker.read_bytes(), before)
        self.assertEqual((self.root / 'lcov.info').read_bytes(), self.report_bytes)

    def test_ci_selects_only_known_inert_module_after_just_install(self):
        workflow = (REPOSITORY / '.github/workflows/ci.yml').read_text()
        job = workflow[workflow.index('  deployment-authority:'):]
        install = job.index('uses: taiki-e/install-action@just')
        controls = job.index('python3 scripts/dev/test_test_isolated.py')
        authority = job.index('run: python3 scripts/ci/isolated-runtime.py just deploy-check')
        self.assertLess(install, controls)
        self.assertLess(controls, authority)
        self.assertIn('sys.version_info >= (3, 9)', job[install:controls])
        self.assertNotIn('unittest discover', job[install:authority])


class Mirror(unittest.TestCase):
    def test_atomic_replacement_preserves_symlink_referent_and_other_private_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a, b, destination, outside = (root / name for name in ('a.info', 'b.info', 'lcov.info', 'outside.info'))
            a.write_bytes(b'A' * 1000)
            b.write_bytes(b'B' * 2000)
            outside.write_bytes(b'untouched')
            destination.symlink_to(outside)
            original_replace = os.replace
            observations = []
            def replace(source, target):
                self.assertEqual(source.parent, target.parent)
                self.assertNotEqual(source, target)
                observations.append(source.read_bytes())
                original_replace(source, target)
            with patch.object(launcher.os, 'replace', side_effect=replace):
                launcher.mirror_report(a, destination)
                launcher.mirror_report(b, destination)
            self.assertEqual(observations, [a.read_bytes(), b.read_bytes()])
            self.assertEqual(destination.read_bytes(), b.read_bytes())
            self.assertEqual(outside.read_bytes(), b'untouched')
            self.assertFalse(destination.is_symlink())
            self.assertEqual(list(root.glob('.lcov-*.tmp')), [])
            sentinel = root / '.lcov-foreign.tmp'
            sentinel.write_bytes(b'foreign')
            with patch.object(launcher.os, 'replace', side_effect=OSError('replace failed')):
                with self.assertRaises(OSError):
                    launcher.mirror_report(a, destination)
            self.assertEqual(destination.read_bytes(), b.read_bytes())
            self.assertEqual(list(root.glob('.lcov-*.tmp')), [sentinel])
            self.assertEqual(a.read_bytes(), b'A' * 1000)


class CoverageShell(unittest.TestCase):
    def test_real_fixed_shell_forwards_to_stubs_and_stops_on_failure(self):
        with tempfile.TemporaryDirectory(prefix='x0x-dev-shell-', dir='/var/tmp') as directory:
            root = Path(directory)
            (root / 'scripts/ci').mkdir(parents=True)
            (root / 'bin').mkdir()
            recorder = root / 'record.py'
            recorder.write_text('import json,os,sys\nwith open(os.environ["RECORD"],"a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\nraise SystemExit(int(os.environ.get("WRAPPER_EXIT","0")) if sys.argv[1]=="wrapper" else 0)\n')
            (root / 'scripts/ci/nextest-isolated.sh').write_text('python3 record.py wrapper "$@"\n')
            cargo = root / 'bin/cargo'
            cargo.write_text('#!/bin/sh\nexec python3 record.py cargo "$@"\n')
            cargo.chmod(0o755)
            exports = root / 'env.sh'
            exports.write_text('export CARGO_LLVM_COV=1\n')
            command = ['bash', '-c', launcher.COVERAGE_SCRIPT, 'dev-coverage', str(exports), '2', '--all-features', '--workspace', '--package', '*', '--lcov', '--output-path', 'space name.info', '--fail-under-lines', '48']
            for exit_code in (0, 23):
                record = root / f'record-{exit_code}.jsonl'
                env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'], RECORD=str(record), WRAPPER_EXIT=str(exit_code))
                result = subprocess.run(command, cwd=root, env=env)
                self.assertEqual(result.returncode, exit_code)
                rows = [json.loads(line) for line in record.read_text().splitlines()]
                self.assertEqual(rows[0], ['wrapper', '--all-features', '--workspace', '--'])
                if exit_code == 0:
                    self.assertEqual(rows[1], ['cargo', 'llvm-cov', 'report', '--package', '*', '--lcov', '--output-path', 'space name.info', '--fail-under-lines', '48'])
                else:
                    self.assertEqual(len(rows), 1)


if __name__ == '__main__':
    unittest.main()
