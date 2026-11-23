#!/usr/bin/env python3
"""Inert controls for scripts/ci/windows-flush-acceptance.ps1 (#1764).

The acceptance script runs only on the hosted Windows runner in ci-full.yml.
It depends on literal strings from the Rust code and the wrapper template.
These controls fail on a PR when one of those strings changes, instead of
only in the nightly Windows run. They read files only.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/ci/windows-flush-acceptance.ps1'
PEER = ROOT / 'scripts/ci/windows-flush-acceptance-peer.ps1'
WORKFLOW = ROOT / '.github/workflows/ci-full.yml'


def read(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


def rust_struct_fields(source, name):
    match = re.search(r'struct ' + name + r' \{(.*?)\n\}', source, re.S)
    if match is None:
        raise AssertionError(f'struct {name} not found')
    return re.findall(r'^\s*(?:pub(?:\([a-z]+\))? )?([a-z_0-9]+):', match.group(1), re.M)


class WindowsFlushAcceptanceControls(unittest.TestCase):
    def setUp(self):
        self.script = SCRIPT.read_text(encoding='utf-8')

    def test_wrapper_markers_match_the_template(self):
        template = read('src/cli/commands/windows-wrapper.ps1')
        for line in ("$x0xWrapperVersion = __X0X_WRAPPER_VERSION__",
                     "$x0xExecutable = '__X0X_EXECUTABLE__'",
                     "$x0xArguments = @(__X0X_ARGUMENTS__)",
                     "$x0xRestartOnExit100 = $true",
                     "$x0xRestartOnExit75 = $true",
                     "$env:X0X_SUPERVISED = '1'",
                     "$env:X0X_WRAPPER = $PSCommandPath"):
            self.assertIn(line, template)
        self.assertIn('if ($x0xExit -ne 100 -and $x0xExit -ne 75) { exit $x0xExit }', template)
        self.assertIn('Start-Sleep -Seconds 5', template)
        # The script expects version 2 and `'a','b'` argument rendering.
        restart = read('src/upgrade/restart.rs')
        self.assertIn('pub(crate) const WINDOWS_WRAPPER_TESTED_VERSION: u32 = 2;', restart)
        self.assertIn("'$x0xWrapperVersion = 2'", self.script)
        daemon = read('src/cli/commands/daemon.rs')
        self.assertIn('.map(|arg| format!("\'{}\'", ps_single_quote_escape(arg)))', daemon)
        self.assertIn('.join(",");', daemon)
        self.assertIn('const WINDOWS_WRAPPER_FILE_NAME: &str = "x0xd-wrapper.ps1";', daemon)
        self.assertIn('const WINDOWS_AUTOSTART_TASK: &str = "x0xd";', daemon)
        self.assertIn("'x0x\\x0xd-wrapper.ps1'", self.script)

    def test_daemon_messages_the_script_matches(self):
        flush = read('src/server/upgrade_flush.rs')
        server = read('src/server/mod.rs')
        self.assertIn('"Acknowledged flush unavailable; supervised apply disabled"', server)
        self.assertIn("'Acknowledged flush unavailable'", self.script)
        for message in ('no prepared host transaction', 'invalid control credential'):
            self.assertIn(f'"{message}"', flush)
            self.assertIn(f"'{message}'", self.script)

    def test_pipe_name_derivation_matches(self):
        flush = read('src/server/upgrade_flush.rs')
        self.assertIn('Sha256::digest(root.to_string_lossy().to_lowercase().as_bytes())', flush)
        self.assertIn('.take(16)', flush)
        self.assertIn(r'format!(r"\\.\pipe\x0x-upgrade-flush-{hex}")', flush)
        self.assertIn('const PIPE_SDDL: &str = "D:P(A;;GA;;;OW)";', flush)
        self.assertIn('let root = data_root.canonicalize()?;', flush)
        self.assertIn("$PipePrefix = 'x0x-upgrade-flush-'", self.script)
        self.assertIn("('\\\\?\\' + (Get-Item $dataDir).FullName).ToLowerInvariant()", self.script)
        self.assertIn('$hash[0..15]', self.script)

    def test_arm_request_fields_match_the_rust_structs(self):
        flush = read('src/server/upgrade_flush.rs')
        journal = read('src/upgrade/journal.rs')
        request = rust_struct_fields(flush, 'Request')
        self.assertEqual(request, ['token', 'transaction_id', 'generation', 'instance_id', 'plan'])
        body = self.script[self.script.index('function New-ArmRequest'):]
        body = body[:body.index('\n}\n')]
        for field in request + rust_struct_fields(journal, 'FrozenPlan') + \
                rust_struct_fields(journal, 'ArtifactPlan'):
            self.assertRegex(body, r'\b' + field + r' = ')

    def test_barrier_tests_named_by_the_script_exist(self):
        journal = read('src/upgrade/journal.rs')
        for name in ('windows_open_for_sync_flushes_a_file_and_a_directory',
                     'windows_record_barrier_support_is_available'):
            self.assertIn(f'fn {name}()', journal)
            self.assertIn(f'{name} ... ok', self.script)
        self.assertIn('mod windows_exec_regressions', journal)

    def test_isolated_config_keeps_the_daemon_off_the_network(self):
        start = self.script.index('network_id = "x0x.acceptance.issue1764"')
        config = self.script[start:self.script.index('"@', start)]
        for line in ('bootstrap_peers = []', 'mdns_enabled = false', 'port_mapping_enabled = false',
                     'rendezvous_enabled = false', 'bind_address = "127.0.0.1:0"',
                     'api_address = "127.0.0.1:0"', '[update]\nenabled = true\n',
                     'gossip_updates = false', 'fallback_check_interval_minutes = 0',
                     'repo = "saorsa-labs/x0x-issue1764-no-such-repo"'):
            self.assertIn(line, config)
        self.assertNotIn('repo = "saorsa-labs/x0x"\n', config)
        # Run 45037951104: `[update] enabled = false` turned the owner off.
        x0xd = read('src/bin/x0xd.rs')
        self.assertIn('let self_update_enabled = config.update_enabled();', x0xd)
        server = read('src/server/mod.rs')
        self.assertIn('let upgrade_flush = if self_update_enabled {', server)
        self.assertIn('&& (config.update.gossip_updates || config.update.fallback_check_interval_minutes > 0)', server)
        self.assertIn('"Startup check: new version available"', read('src/server/routes/upgrade.rs'))
        self.assertIn("'new version available'", self.script)
        # The check must prove the updater ran: its 404 line is required.
        self.assertIn('"Startup update check failed: {e}"', server)
        for needle in ("'Startup update check failed'", "'404 Not Found'", "'x0x-issue1764-no-such-repo'"):
            self.assertIn(f'$logText.Contains({needle})', self.script)

    def test_cleanup_runs_in_finally(self):
        tail = self.script[self.script.index('\n} finally {\n'):]
        tail = tail[:tail.index('\n}\n')]
        self.assertIn('net user $PeerUser /delete', tail)
        self.assertIn('Stop-Process -Id $wrapperProcess.Id', tail)
        self.assertIn('Get-Process -Name x0xd', tail)
        self.assertEqual(self.script.count('net user $PeerUser /delete'), 1)

    def test_peer_never_sends_the_token(self):
        peer = PEER.read_text(encoding='utf-8')
        self.assertNotIn('token', peer.lower().replace('api token', ''))
        self.assertIn('[System.UnauthorizedAccessException]', peer)

    def test_workflow_runs_the_script_and_uploads_evidence(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        job = workflow[workflow.index('  test-windows:'):workflow.index('  coverage:')]
        self.assertIn('runs-on: windows-latest', job)
        self.assertIn('./scripts/ci/windows-flush-acceptance.ps1', job)
        self.assertIn('run: cargo build --bin x0xd --bin x0x', job)
        self.assertIn('name: windows-flush-acceptance', job)
        self.assertIn('path: ${{ runner.temp }}/windows-flush-acceptance/', job)
        self.assertIn("'scripts/ci/windows-flush-acceptance-peer.ps1'", job)
        self.assertNotIn('continue-on-error', job)
        # The evidence dir is uploaded; the instance root with the API token
        # and keys must be a different directory.
        self.assertIn('-Work "$env:RUNNER_TEMP/windows-flush-acceptance-work"', job)
        self.assertIn("$root = Join-Path $Work 'instance'", self.script)
        self.assertNotIn('windows-flush-acceptance', read('.github/workflows/ci.yml').replace(
            'test_windows_flush_acceptance.py', ''))

    def test_dispatch_only_windows_skips_every_other_job(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        self.assertIn("      only:\n", workflow)
        self.assertIn("        default: all\n", workflow)
        self.assertIn("          - windows\n", workflow)
        gate = "github.event_name != 'workflow_dispatch' || inputs.only == 'all'"
        jobs = re.split(r'\n  (?=[a-z0-9_-]+:\n)', workflow[workflow.index('\njobs:\n'):])[1:]
        self.assertGreater(len(jobs), 5)
        for job in jobs:
            name = job.split(':', 1)[0]
            header = job[:job.index('    steps:')] if '    steps:' in job else job
            job_if = [line for line in header.splitlines() if line.startswith('    if: ')]
            if name == 'test-windows':
                self.assertEqual(job_if, [], name)
            else:
                self.assertEqual(len(job_if), 1, name)
                self.assertIn(gate, job_if[0], name)

    def test_cli_runs_on_the_explicit_stack_and_ci_checks_it(self):
        cli = read('src/bin/x0x.rs')
        self.assertNotIn('#[tokio::main]', cli)
        self.assertIn('x0x::server::run_cli_runtime(run_cli)', cli)
        workflow = WORKFLOW.read_text(encoding='utf-8')
        job = workflow[workflow.index('  test-windows:'):workflow.index('  coverage:')]
        debug = job.index('run: ./scripts/ci/windows-cli-stack-check.ps1 -X0x target/debug/x0x.exe')
        release = job.index('run: ./scripts/ci/windows-cli-stack-check.ps1 -X0x target/release/x0x.exe')
        self.assertLess(debug, job.index('./scripts/ci/windows-flush-acceptance.ps1'))
        self.assertLess(job.index('run: cargo build --release --bin x0x'), release)
        self.assertIn("'scripts/ci/windows-cli-stack-check.ps1'", job)
        check = read('scripts/ci/windows-cli-stack-check.ps1')
        self.assertIn('$StackOverflow = -1073741571', check)
        self.assertEqual(-1073741571, 0xC00000FD - (1 << 32))
        for arguments in ("@('--version')", "@('--help')", "@('autostart', '--help')"):
            self.assertIn(arguments, check)


if __name__ == '__main__':
    unittest.main()
