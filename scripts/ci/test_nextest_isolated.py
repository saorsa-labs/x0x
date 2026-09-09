#!/usr/bin/env python3
"""Exercise the actual Bash wrapper with inert spies; never run Cargo or helpers."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest


WRAPPER = Path(__file__).with_name('nextest-isolated.sh')
BUILD = ['--offline', '--locked', '--all-features', '--package', 'x0x', '--lib']
RUNTIME = ['--profile', 'default', '--retries', '0', '--fail-fast', '--no-tests',
           'fail', '--success-output', 'immediate', '--failure-output', 'immediate',
           '-E', 'package(=x0x) & binary(=x0x) & kind(=lib) & '
           'test(=legacy_bus_interop_tests::bus_only_interop_default_positive_and_optout_negative)']

# Executed only by the four task-local commands. No subprocess, imports of the
# named helpers, exec, sockets, or fallback to ambient commands exist here.
SPY = r'''
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

root = Path(os.environ['SPY_ROOT'])
name, args = Path(sys.argv[0]).name, sys.argv[1:]
row = {'command': name, 'argv': args,
       'custody_scratch': os.environ.get('X0X_CUSTODY_SCRATCH')}
phase = ''
output = ''
code = 0
if name == 'mktemp':
    expected = str(root / 'runner-temp' / 'x0x-metadata-XXXXXX')
    assert args == ['-d', expected]
    output = tempfile.mkdtemp(prefix='x0x-metadata-', dir=root / 'runner-temp') + '\n'
    row['created'] = output.strip()
elif name == 'cargo':
    if args[0] == 'metadata':
        phase, output = 'metadata', '{}\n'
    else:
        assert args[:2] == ['nextest', 'list']
        phase, output = 'binaries', '{}\n'
    if args.count('--locked') > 1:
        code = 2
        output = ''
        print("error: the argument '--locked' cannot be used multiple times", file=sys.stderr)
elif name == 'sha256sum':
    lock = root / 'Cargo.lock'
    value = hashlib.sha256(lock.read_bytes()).hexdigest()
    if args == ['Cargo.lock']:
        output = value + '  Cargo.lock\n'
    else:
        assert len(args) == 2 and args[0] == '--check'
        phase = 'lock_check'
        manifest = Path(args[1])
        assert manifest.parent.parent == root / 'runner-temp'
        assert manifest.read_text() == value + '  Cargo.lock\n'
elif name == 'python3':
    if args[0] == 'scripts/ci/nextest-reuse.py':
        assert args[1] == 'record' and len(args) == 3
        phase = 'record'
    else:
        assert args[:4] == ['scripts/ci/isolated-runtime.py', 'python3',
                            'scripts/ci/nextest-reuse.py', 'run']
        phase = 'isolated'
else:
    raise AssertionError('unknown inert spy')
forced = {'metadata': 41, 'binaries': 42, 'lock_check': 43}
if phase and phase == os.environ.get('SPY_FAIL_PHASE'):
    code = forced[phase]
    output = ''
row.update(phase=phase, exit=code)
with (root / 'trace.jsonl').open('a') as trace:
    trace.write(json.dumps(row, sort_keys=True) + '\n')
sys.stdout.write(output)
raise SystemExit(code)
'''


class WrapperControls(unittest.TestCase):
    def invoke(self, arguments, fail_phase=''):
        # Both the scratch directory and cwd are ours. An absent RUNNER_TEMP
        # must never masquerade as the original duplicate-option regression.
        with tempfile.TemporaryDirectory(prefix='nextest-wrapper-inert-') as tmp:
            root = Path(tmp).resolve()
            bindir = root / 'bin'
            bindir.mkdir()
            (root / 'runner-temp').mkdir()
            (root / 'Cargo.lock').write_text('inert lock input\n')
            wrapper = root / 'nextest-isolated.sh'
            source = WRAPPER.read_bytes()
            wrapper.write_bytes(source)
            # Absolute interpreter: the python3 spy cannot recursively invoke
            # itself. PATH has no real Cargo, nextest, or isolation executables.
            spy = '#!' + sys.executable + '\n' + SPY
            for name in ('cargo', 'python3', 'sha256sum', 'mktemp'):
                path = bindir / name
                path.write_text(spy)
                path.chmod(0o700)
            env = {'PATH': str(bindir), 'RUNNER_TEMP': str(root / 'runner-temp'),
                   'SPY_ROOT': str(root), 'SPY_FAIL_PHASE': fail_phase}
            child = subprocess.Popen(['/bin/bash', str(wrapper), *arguments],
                                     cwd=root, env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, start_new_session=True)
            try:
                stdout, stderr = child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate()
                self.fail('inert wrapper exceeded its deadline; not a regression result')
            trace = root / 'trace.jsonl'
            rows = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            observation = {'wrapper_sha256': hashlib.sha256(source).hexdigest(),
                           'argv': arguments, 'pid': child.pid, 'exit': child.returncode,
                           'stdout': stdout.decode(), 'stderr': stderr.decode(), 'calls': rows}
            print('WRAPPER_SPY_OBSERVATION ' + json.dumps(observation, sort_keys=True), file=sys.stderr)
            return observation

    def assert_success(self, observation, build, runtime, metadata_flags):
        self.assertEqual(observation['exit'], 0, observation)
        self.assertEqual(observation['stderr'], '')
        calls = observation['calls']
        self.assertEqual([c['command'] for c in calls],
                         ['mktemp', 'cargo', 'sha256sum', 'cargo', 'sha256sum', 'python3', 'python3'])
        scratch = calls[0]['created']
        self.assertEqual(calls[1]['argv'], ['metadata', '--format-version', '1', *metadata_flags])
        self.assertEqual(calls[2]['argv'], ['Cargo.lock'])
        self.assertEqual(calls[3]['argv'], ['nextest', 'list', *build, '--locked',
                         '--cargo-metadata', scratch + '/cargo.json',
                         '--list-type', 'binaries-only', '--message-format', 'json'])
        self.assertEqual(calls[3]['argv'].count('--locked'), 1)
        self.assertEqual(calls[4]['argv'], ['--check', scratch + '/lock.sha256'])
        self.assertEqual(calls[5]['argv'], ['scripts/ci/nextest-reuse.py', 'record', scratch])
        self.assertEqual(calls[6]['argv'], ['scripts/ci/isolated-runtime.py', 'python3',
                         'scripts/ci/nextest-reuse.py', 'run', scratch, *runtime])
        self.assertEqual(calls[6]['custody_scratch'], scratch)
        self.assertTrue(all(c['custody_scratch'] is None for c in calls[:6]))
        self.assertTrue(all(c['exit'] == 0 for c in calls))

    def test_caller_locked_uses_one_lock_per_phase(self):
        # The original wrapper fails THIS unchanged success assertion at exit2
        # after the spy observes duplicate list --locked, before any helper.
        result = self.invoke([*BUILD, '--', *RUNTIME])
        self.assert_success(result, ['--offline', '--all-features', '--package', 'x0x', '--lib'],
                            RUNTIME, ['--offline', '--locked', '--all-features'])
        self.assertEqual(result['calls'][1]['argv'].count('--locked'), 1)

    def test_omitted_locked_preserves_metadata_behavior(self):
        build = ['--all-features', '--workspace']
        self.assert_success(self.invoke([*build, '--', *RUNTIME]), build, RUNTIME, ['--all-features'])

    def test_repeated_locked_is_canonical(self):
        build = ['--locked', '--offline', '--locked', '--lib', '--locked']
        self.assert_success(self.invoke([*build, '--', *RUNTIME]), ['--offline', '--lib'],
                            RUNTIME, ['--locked', '--offline'])

    def test_offline_frozen_and_no_default_features_unchanged(self):
        build = ['--offline', '--frozen', '--no-default-features', '--lib']
        self.assert_success(self.invoke([*build, '--', *RUNTIME]), build, RUNTIME, build[:3])

    def test_paired_build_values_preserve_spaces_and_order(self):
        pairs = ['--features', 'feature one', '-F', 'feature two', '--manifest-path',
                 'space dir/Cargo.toml', '--config', 'build.target-dir="space target"']
        self.assert_success(self.invoke([*pairs, '--locked', '--', *RUNTIME]), pairs,
                            RUNTIME, [*pairs, '--locked'])

    def test_post_separator_tokens_are_runtime_only(self):
        runtime = ['--locked', '--config', 'literal value', '-E', 'test(=name with spaces)']
        self.assert_success(self.invoke(['--lib', '--', *runtime]), ['--lib'], runtime, [])

    def test_missing_separator_stops_before_any_command(self):
        result = self.invoke(['--locked', '--lib'])
        self.assertEqual(result['exit'], 2)
        self.assertEqual(result['stderr'], 'missing build/runtime separator\n')
        self.assertEqual(result['calls'], [])

    def test_missing_paired_value_stops_before_any_command(self):
        for flag in ('--features', '-F', '--manifest-path', '--config'):
            for suffix in ([], ['--']):
                with self.subTest(flag=flag, suffix=suffix):
                    result = self.invoke([flag, *suffix])
                    self.assertEqual(result['exit'], 2)
                    self.assertEqual(result['stderr'], 'missing build option value\n')
                    self.assertEqual(result['calls'], [])

    def test_metadata_failure_stops_before_binary_preparation(self):
        result = self.invoke([*BUILD, '--', *RUNTIME], 'metadata')
        self.assertEqual(result['exit'], 41)
        self.assertEqual([x['command'] for x in result['calls']], ['mktemp', 'cargo'])

    def test_binary_failure_stops_before_record_or_isolation(self):
        result = self.invoke([*BUILD, '--', *RUNTIME], 'binaries')
        self.assertEqual(result['exit'], 42)
        self.assertEqual([x['command'] for x in result['calls']], ['mktemp', 'cargo', 'sha256sum', 'cargo'])

    def test_lock_check_failure_stops_before_record_or_isolation(self):
        result = self.invoke([*BUILD, '--', *RUNTIME], 'lock_check')
        self.assertEqual(result['exit'], 43)
        self.assertEqual([x['command'] for x in result['calls']],
                         ['mktemp', 'cargo', 'sha256sum', 'cargo', 'sha256sum'])


if __name__ == '__main__':
    unittest.main()
