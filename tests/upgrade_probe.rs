#![allow(clippy::unwrap_used, clippy::expect_used)]

//! M2 S2d execution-probe regressions. These commands never start a daemon:
//! `--version` keeps the old daemon's missing-probe case on its early exit path.
//! Never remove that guard when testing a binary that may predate this feature.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

// The process and hold engine is private to upgrade. Exercise its real writer
// and bounded-clock seams without exposing a new library API.
#[cfg(unix)]
#[path = "../src/upgrade/journal.rs"]
mod journal;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/upgrade/probe.rs"]
mod probe;

struct ProbeFixture {
    _root: TempDir,
    application_dirs: Vec<PathBuf>,
    profiles: PathBuf,
}

impl ProbeFixture {
    fn new() -> Self {
        // The nextest wrapper replaces HOME with /tmp/x0x-nextest-home.
        // Use the explicitly owned evidence root or the allowed repo scratch
        // directory, never that synthetic HOME or the system temp directory.
        let evidence = std::env::var_os("X0X_UPGRADE_PROBE_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join(".planning/upgrade-probe-fixtures")
            });
        std::fs::create_dir_all(&evidence).expect("probe evidence directory");
        let root = tempfile::Builder::new()
            .prefix("packaged-probe-")
            .tempdir_in(evidence)
            .expect("private probe fixture");
        let application_dirs = ["cwd", "home", "config", "data", "cache", "tmp", "heap"]
            .into_iter()
            .map(|name| {
                let path = root.path().join(name);
                std::fs::create_dir(&path).expect("empty application directory");
                path
            })
            .collect();
        let profiles = root.path().join("profiles");
        std::fs::create_dir(&profiles).expect("coverage output directory");
        Self {
            _root: root,
            application_dirs,
            profiles,
        }
    }

    fn command(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(&self.application_dirs[0])
            .env("HOME", &self.application_dirs[1])
            .env("X0X_HOME", &self.application_dirs[1])
            .env("USERPROFILE", &self.application_dirs[1])
            .env("XDG_CONFIG_HOME", &self.application_dirs[2])
            .env("APPDATA", &self.application_dirs[2])
            .env("XDG_DATA_HOME", &self.application_dirs[3])
            .env("LOCALAPPDATA", &self.application_dirs[3])
            .env("XDG_CACHE_HOME", &self.application_dirs[4])
            .env("TMPDIR", &self.application_dirs[5])
            .env("TMP", &self.application_dirs[5])
            .env("TEMP", &self.application_dirs[5])
            .env("DHAT_OUT_DIR", &self.application_dirs[6])
            // Instrumentation output belongs to the harness, not application
            // state. The upgrade probe must still bypass the heap profiler.
            .env(
                "LLVM_PROFILE_FILE",
                self.profiles.join("probe-%p-%m.profraw"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn assert_no_application_state(&self) {
        for directory in &self.application_dirs {
            assert_eq!(
                std::fs::read_dir(directory)
                    .expect("application state")
                    .count(),
                0,
                "inert probe created state under {}",
                directory.display()
            );
        }
    }
}

struct ReapedChild(Option<Child>);

impl Drop for ReapedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_inert(mut command: Command) -> Output {
    let mut child = ReapedChild(Some(command.spawn().expect("spawn inert command")));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child
            .0
            .as_mut()
            .unwrap()
            .try_wait()
            .expect("observe inert command")
            .is_some()
        {
            return child
                .0
                .take()
                .unwrap()
                .wait_with_output()
                .expect("collect inert command output");
        }
        assert!(
            Instant::now() < deadline,
            "inert command did not exit within 30 seconds"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_packaged_probe(binary: &str) {
    let fixture = ProbeFixture::new();
    let mut command = fixture.command(Path::new(binary));
    // Main lacks --upgrade-probe. The daemon nevertheless exits at --version,
    // before config, identity, stores, sockets, cleanup, or normal startup.
    command.args(["--upgrade-probe", "--version"]);
    let output = run_inert(command);
    assert!(
        output.status.success(),
        "{binary} probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("upgrade probe must return a structured version/platform response");
    assert_eq!(response["version"], x0x::VERSION);
    assert_eq!(
        response["platform"],
        x0x::upgrade::manifest::current_platform_target().expect("supported binary platform")
    );
    assert!(
        output.stderr.is_empty(),
        "probe initialized logging or profiling: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_no_application_state();
}

#[test]
fn packaged_daemon_upgrade_probe_reports_version_and_platform_without_state() {
    assert_packaged_probe(env!("CARGO_BIN_EXE_x0xd"));
}

#[test]
fn packaged_cli_upgrade_probe_reports_version_and_platform_without_state() {
    assert_packaged_probe(env!("CARGO_BIN_EXE_x0x"));
}

#[test]
fn packaged_version_mode_remains_an_inert_text_control() {
    for binary in [env!("CARGO_BIN_EXE_x0xd"), env!("CARGO_BIN_EXE_x0x")] {
        let fixture = ProbeFixture::new();
        let mut command = fixture.command(Path::new(binary));
        command.arg("--version");
        let output = run_inert(command);
        assert!(
            output.status.success(),
            "{binary} version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(x0x::VERSION));
        assert!(serde_json::from_slice::<serde_json::Value>(&output.stdout).is_err());
        // Existing --version may create a heap profile in all-features builds.
        // It must not create any configuration, identity, or store state.
        for directory in &fixture.application_dirs[..6] {
            assert_eq!(std::fs::read_dir(directory).unwrap().count(), 0);
        }
    }
}

#[cfg(unix)]
mod execution {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;

    use probe::{
        Admission, ProbeCause, ProbeClock, ProbeLaunch, ProbeOptions, ProbePhase, ProbeRefusal,
        ProbeRequest,
    };

    const CANDIDATE_VERSION: &str = "9.9.9";
    const OLD_DAEMON: &[u8] = b"installed daemon must remain unchanged";
    const OLD_CLI: &[u8] = b"installed CLI must remain unchanged";

    struct ExecutionFixture {
        _scratch: ProbeFixture,
        request: ProbeRequest,
        installed_cli: PathBuf,
        launches: PathBuf,
    }

    impl ExecutionFixture {
        fn new() -> Self {
            let scratch = ProbeFixture::new();
            let root = scratch._root.path();
            let install_dir = root.join("install");
            let stage = root.join("stage");
            std::fs::create_dir(&install_dir).unwrap();
            std::fs::create_dir(&stage).unwrap();
            let install = install_dir.join("x0xd");
            let installed_cli = install_dir.join("x0x");
            std::fs::write(&install, OLD_DAEMON).unwrap();
            std::fs::write(&installed_cli, OLD_CLI).unwrap();
            let daemon = stage.join("x0xd");
            let cli = stage.join("x0x");
            let launches = root.join("launched-pids");
            let cwd = scratch.application_dirs[0].clone();
            let launch = ProbeLaunch {
                cwd: cwd.clone(),
                env: vec![
                    (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                    (
                        OsString::from("HOME"),
                        scratch.application_dirs[1].as_os_str().to_owned(),
                    ),
                    (
                        OsString::from("TMPDIR"),
                        scratch.application_dirs[5].as_os_str().to_owned(),
                    ),
                    (
                        OsString::from("PROBE_TEST_LAUNCHES"),
                        launches.as_os_str().to_owned(),
                    ),
                    (OsString::from("PROBE_TEST_CWD"), cwd.into_os_string()),
                ],
            };
            let request = ProbeRequest {
                install,
                version: CANDIDATE_VERSION.to_owned(),
                platform: x0x::upgrade::manifest::current_platform_target()
                    .unwrap()
                    .to_owned(),
                archive_sha256: [7; 32],
                daemon,
                cli,
                launch,
            };
            let fixture = Self {
                _scratch: scratch,
                request,
                installed_cli,
                launches,
            };
            fixture.write_success(&fixture.request.daemon);
            fixture.write_success(&fixture.request.cli);
            fixture
        }

        fn write_script(&self, path: &Path, body: &str) {
            let script = format!(
                "#!/bin/sh\n\
                 test \"$#\" -eq 1 && test \"$1\" = '--upgrade-probe' || exit 96\n\
                 test \"$PWD\" = \"$PROBE_TEST_CWD\" || exit 97\n\
                 printf '%s\\n' \"$$\" >> \"$PROBE_TEST_LAUNCHES\"\n\
                 {body}\n"
            );
            std::fs::write(path, script).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn write_response(&self, path: &Path, version: &str, platform: &str) {
            let response = serde_json::json!({"version": version, "platform": platform});
            self.write_script(path, &format!("printf '%s\\n' '{response}'"));
        }

        fn write_success(&self, path: &Path) {
            self.write_response(path, CANDIDATE_VERSION, &self.request.platform);
        }

        fn options(clock_ms: u64) -> ProbeOptions {
            ProbeOptions {
                clock: ProbeClock {
                    boot_id: "inert-test-boot".to_owned(),
                    monotonic_ms: clock_ms,
                },
                timeout: Duration::from_secs(2),
                fail_write: None,
            }
        }

        fn run(&self, options: &ProbeOptions) -> Result<probe::ProbeReceipt, ProbeRefusal> {
            probe::run_before_swap_with_options(&self.request, &AtomicBool::new(true), options)
        }

        fn launched_pids(&self) -> Vec<u32> {
            match std::fs::read_to_string(&self.launches) {
                Ok(text) => text.lines().map(|line| line.parse().unwrap()).collect(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(error) => panic!("read launch evidence: {error}"),
            }
        }

        fn assert_installed_pair_unchanged(&self) {
            assert_eq!(std::fs::read(&self.request.install).unwrap(), OLD_DAEMON);
            assert_eq!(std::fs::read(&self.installed_cli).unwrap(), OLD_CLI);
        }

        fn assert_child_reaped(pid: u32) {
            let pid = i32::try_from(pid).unwrap();
            // Each PID comes from this fixture's child, whose execution has
            // completed. No signal is sent: kill(pid, 0) checks existence.
            let exists = unsafe { libc::kill(pid, 0) };
            assert_eq!(exists, -1, "probe child {pid} remains alive or unreaped");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }

    #[test]
    fn pair_probe_runs_both_candidates_in_the_frozen_launch_environment() {
        let fixture = ExecutionFixture::new();
        let receipt = fixture.run(&ExecutionFixture::options(1_000)).unwrap();
        let pids = fixture.launched_pids();
        assert_eq!(pids.len(), 2, "daemon and managed CLI must both execute");
        assert_eq!(pids, vec![receipt.daemon_pid, receipt.cli_pid]);
        for pid in pids {
            ExecutionFixture::assert_child_reaped(pid);
        }
        let state = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        assert!(matches!(state.phase, ProbePhase::Passed));
        assert_eq!(state.daemon_sha256, Some(receipt.daemon_sha256));
        assert_eq!(state.cli_sha256, Some(receipt.cli_sha256));
        assert_eq!(state.transaction_id, receipt.transaction_id);
        fixture.assert_installed_pair_unchanged();
        assert_eq!(probe::PROBE_TIMEOUT, Duration::from_secs(90));
    }

    #[test]
    fn either_candidate_failure_is_durably_held_before_a_repeat_attempt() {
        for bad_cli in [false, true] {
            for (body, expected_cause) in [
                ("exit 23".to_owned(), ProbeCause::NonzeroExit),
                (
                    "printf '%s\\n' 'not a JSON response'".to_owned(),
                    ProbeCause::InvalidOutput,
                ),
                (
                    format!(
                        "printf '%s\\n' '{{\"version\":\"0.0.1\",\"platform\":\"{}\"}}'",
                        x0x::upgrade::manifest::current_platform_target().unwrap()
                    ),
                    ProbeCause::VersionMismatch,
                ),
                (
                    format!(
                        "printf '%s\\n' '{{\"version\":\"{CANDIDATE_VERSION}\",\"platform\":\"wrong-platform\"}}'"
                    ),
                    ProbeCause::PlatformMismatch,
                ),
            ] {
                let fixture = ExecutionFixture::new();
                let candidate = if bad_cli {
                    &fixture.request.cli
                } else {
                    &fixture.request.daemon
                };
                fixture.write_script(candidate, &body);
                let result = fixture.run(&ExecutionFixture::options(1_000));
                assert!(matches!(result, Err(ProbeRefusal::Failed { .. })));
                let state = probe::read_state(&fixture.request.install).unwrap().unwrap();
                assert!(matches!(state.phase, ProbePhase::FailedHold));
                assert_eq!(state.cause, Some(expected_cause));
                let launches = fixture.launched_pids();
                assert_eq!(launches.len(), if bad_cli { 2 } else { 1 });
                for pid in &launches {
                    ExecutionFixture::assert_child_reaped(*pid);
                }
                let repeated = fixture.run(&ExecutionFixture::options(2_000));
                assert!(matches!(repeated, Err(ProbeRefusal::Held { .. })));
                assert_eq!(fixture.launched_pids(), launches);
                fixture.assert_installed_pair_unchanged();
            }
        }
    }

    #[test]
    fn an_unloadable_candidate_is_held_without_running_or_replacing_either_binary() {
        let fixture = ExecutionFixture::new();
        std::fs::write(&fixture.request.daemon, b"\x7fELFnot-an-executable").unwrap();
        let result = fixture.run(&ExecutionFixture::options(1_000));
        assert!(matches!(result, Err(ProbeRefusal::Failed { .. })));
        let state = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        assert!(matches!(state.phase, ProbePhase::FailedHold));
        assert_eq!(state.cause, Some(ProbeCause::ExecFailed));
        assert!(fixture.launched_pids().is_empty());
        fixture.assert_installed_pair_unchanged();
    }

    #[test]
    fn timed_out_candidate_is_killed_reaped_and_retried_only_at_the_fixed_bounds() {
        let fixture = ExecutionFixture::new();
        fixture.write_script(&fixture.request.daemon, "while :; do :; done");
        let mut clock_ms = 1_000;
        let mut transaction_ids = std::collections::HashSet::new();
        for (attempt, wait_secs) in [(1, 30 * 60), (2, 60 * 60), (3, 120 * 60)] {
            let mut options = ExecutionFixture::options(clock_ms);
            options.timeout = Duration::from_millis(100);
            let result = fixture.run(&options);
            assert!(matches!(result, Err(ProbeRefusal::Interrupted { .. })));
            let state = probe::read_state(&fixture.request.install)
                .unwrap()
                .unwrap();
            assert!(matches!(state.phase, ProbePhase::InterruptedWait));
            assert_eq!(state.cause, Some(ProbeCause::Timeout));
            assert_eq!(state.attempt, attempt);
            assert!(
                transaction_ids.insert(state.transaction_id),
                "each retry must use a fresh transaction"
            );
            ExecutionFixture::assert_child_reaped(state.last_pid.unwrap());
            assert_eq!(state.retry_remaining_ms, wait_secs * 1_000);
            let due = state.retry_deadline_ms;
            let before_due = ProbeClock {
                boot_id: options.clock.boot_id.clone(),
                monotonic_ms: due - 1,
            };
            assert!(matches!(
                probe::inspect_admission_at(
                    &fixture.request.install,
                    CANDIDATE_VERSION,
                    &before_due
                ),
                Ok(Admission::Waiting { .. })
            ));
            let at_due = ProbeClock {
                monotonic_ms: due,
                ..before_due
            };
            assert!(matches!(
                probe::inspect_admission_at(&fixture.request.install, CANDIDATE_VERSION, &at_due),
                Ok(Admission::Ready)
            ));
            clock_ms = due;
            fixture.assert_installed_pair_unchanged();
        }
        let mut options = ExecutionFixture::options(clock_ms);
        options.timeout = Duration::from_millis(100);
        assert!(fixture.run(&options).is_err());
        let state = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        assert!(matches!(state.phase, ProbePhase::FailedHold));
        assert_eq!(state.cause, Some(ProbeCause::RetriesExhausted));
        assert_eq!(state.attempt, 4);
        for pid in fixture.launched_pids() {
            ExecutionFixture::assert_child_reaped(pid);
        }
        assert!(matches!(
            fixture.run(&ExecutionFixture::options(clock_ms + 1)),
            Err(ProbeRefusal::Held { .. })
        ));
        fixture.assert_installed_pair_unchanged();
    }

    #[test]
    fn reboot_preserves_the_remaining_retry_wait_without_resetting_same_boot_progress() {
        let fixture = ExecutionFixture::new();
        fixture.write_script(&fixture.request.daemon, "while :; do :; done");
        let mut options = ExecutionFixture::options(1_000);
        options.timeout = Duration::from_millis(100);
        assert!(matches!(
            fixture.run(&options),
            Err(ProbeRefusal::Interrupted { .. })
        ));
        let state = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        let before_reboot = ProbeClock {
            boot_id: options.clock.boot_id,
            monotonic_ms: state.retry_deadline_ms - 1_000,
        };
        assert_eq!(
            probe::inspect_admission_at(
                &fixture.request.install,
                CANDIDATE_VERSION,
                &before_reboot
            )
            .unwrap(),
            Admission::Waiting {
                retry_after: Duration::from_secs(1)
            }
        );
        let after_reboot = ProbeClock {
            boot_id: "next-inert-test-boot".to_owned(),
            monotonic_ms: 5,
        };
        assert_eq!(
            probe::inspect_admission_at(&fixture.request.install, CANDIDATE_VERSION, &after_reboot)
                .unwrap(),
            Admission::Waiting {
                retry_after: Duration::from_secs(1)
            }
        );
        let same_boot_later = ProbeClock {
            monotonic_ms: 505,
            ..after_reboot.clone()
        };
        assert_eq!(
            probe::inspect_admission_at(
                &fixture.request.install,
                CANDIDATE_VERSION,
                &same_boot_later
            )
            .unwrap(),
            Admission::Waiting {
                retry_after: Duration::from_millis(500)
            }
        );
        let due = ProbeClock {
            monotonic_ms: 1_005,
            ..after_reboot
        };
        assert_eq!(
            probe::inspect_admission_at(&fixture.request.install, CANDIDATE_VERSION, &due).unwrap(),
            Admission::Ready
        );
        fixture.assert_installed_pair_unchanged();
    }

    #[test]
    fn an_abandoned_running_record_becomes_an_interruption_before_any_new_probe() {
        let fixture = ExecutionFixture::new();
        fixture.run(&ExecutionFixture::options(1_000)).unwrap();
        let mut state = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        // Model a process/host exit after the Running record barrier and
        // before the result barrier. No child is left alive by this fixture.
        state.phase = ProbePhase::Running;
        state.cause = None;
        state.daemon_sha256 = None;
        state.cli_sha256 = None;
        std::fs::write(
            probe::state_path(&fixture.request.install).unwrap(),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        let launches = fixture.launched_pids();
        assert!(matches!(
            probe::inspect_admission_at(
                &fixture.request.install,
                CANDIDATE_VERSION,
                &ExecutionFixture::options(2_000).clock
            ),
            Ok(Admission::Waiting { .. })
        ));
        let recovered = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        assert!(matches!(recovered.phase, ProbePhase::InterruptedWait));
        assert_eq!(recovered.cause, Some(ProbeCause::AbandonedAttempt));
        assert_eq!(recovered.retry_remaining_ms, 30 * 60 * 1_000);
        assert_eq!(fixture.launched_pids(), launches);
        fixture.assert_installed_pair_unchanged();
    }

    #[test]
    fn a_cli_probe_cannot_change_the_already_probed_daemon_bytes() {
        let mut fixture = ExecutionFixture::new();
        fixture.request.launch.env.push((
            OsString::from("PROBE_TEST_TAMPER"),
            fixture.request.daemon.as_os_str().to_owned(),
        ));
        let response = serde_json::json!({
            "version": CANDIDATE_VERSION,
            "platform": fixture.request.platform,
        });
        fixture.write_script(
            &fixture.request.cli,
            &format!(
                "printf '\\n# changed after first probe\\n' >> \"$PROBE_TEST_TAMPER\"\n\
                 printf '%s\\n' '{response}'"
            ),
        );
        assert!(matches!(
            fixture.run(&ExecutionFixture::options(1_000)),
            Err(ProbeRefusal::Failed { .. })
        ));
        let state = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        assert_eq!(state.cause, Some(ProbeCause::CandidateChanged));
        assert!(matches!(state.phase, ProbePhase::FailedHold));
        fixture.assert_installed_pair_unchanged();
    }

    #[test]
    fn corrupt_or_unknown_probe_state_never_authorizes_a_candidate_or_rewrites_evidence() {
        for bytes in [b"{torn".as_slice(), br#"{"schema_version":999}"#] {
            let fixture = ExecutionFixture::new();
            let path = probe::state_path(&fixture.request.install).unwrap();
            std::fs::write(&path, bytes).unwrap();
            assert!(matches!(
                fixture.run(&ExecutionFixture::options(1_000)),
                Err(ProbeRefusal::RecoveryFailed { .. })
            ));
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(fixture.launched_pids().is_empty());
            fixture.assert_installed_pair_unchanged();
        }
    }

    #[test]
    fn cancellation_before_a_probe_creates_no_attempt_or_child() {
        let fixture = ExecutionFixture::new();
        let result = probe::run_before_swap_with_options(
            &fixture.request,
            &AtomicBool::new(false),
            &ExecutionFixture::options(1_000),
        );
        assert!(matches!(result, Err(ProbeRefusal::Cancelled)));
        assert!(probe::read_state(&fixture.request.install)
            .unwrap()
            .is_none());
        assert!(fixture.launched_pids().is_empty());
        fixture.assert_installed_pair_unchanged();
    }

    #[test]
    fn cancellation_during_a_probe_kills_reaps_and_records_an_interruption() {
        use std::sync::atomic::Ordering;

        let fixture = ExecutionFixture::new();
        fixture.write_script(&fixture.request.daemon, "while :; do :; done");
        let alive = AtomicBool::new(true);
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !fixture.launches.exists() {
                    assert!(Instant::now() < deadline, "candidate never started");
                    std::thread::sleep(Duration::from_millis(5));
                }
                alive.store(false, Ordering::Release);
            });
            probe::run_before_swap_with_options(
                &fixture.request,
                &alive,
                &ExecutionFixture::options(1_000),
            )
        });
        assert!(matches!(result, Err(ProbeRefusal::Interrupted { .. })));
        let state = probe::read_state(&fixture.request.install)
            .unwrap()
            .unwrap();
        assert!(matches!(state.phase, ProbePhase::InterruptedWait));
        assert_eq!(state.cause, Some(ProbeCause::Cancelled));
        for pid in fixture.launched_pids() {
            ExecutionFixture::assert_child_reaped(pid);
        }
        fixture.assert_installed_pair_unchanged();
    }

    #[test]
    fn failed_record_barriers_never_return_a_success_receipt() {
        use probe::{RecordWrite, WriteFailure};

        for phase in [
            RecordWrite::Attempt,
            RecordWrite::Outcome,
            RecordWrite::Hold,
        ] {
            for step in [
                journal::BarrierStep::Write,
                journal::BarrierStep::FileSync,
                journal::BarrierStep::Rename,
                journal::BarrierStep::DirectorySync,
            ] {
                let fixture = ExecutionFixture::new();
                if matches!(phase, RecordWrite::Hold) {
                    fixture.write_script(&fixture.request.daemon, "exit 23");
                }
                let mut options = ExecutionFixture::options(1_000);
                options.fail_write = Some(WriteFailure { phase, step });
                let result = fixture.run(&options);
                assert!(
                    matches!(result, Err(ProbeRefusal::RecoveryFailed { .. })),
                    "a failed record barrier must withhold authorization: {result:?}"
                );
                if matches!(phase, RecordWrite::Attempt) {
                    assert!(fixture.launched_pids().is_empty());
                }
                for pid in fixture.launched_pids() {
                    ExecutionFixture::assert_child_reaped(pid);
                }
                fixture.assert_installed_pair_unchanged();
            }
        }
    }

    #[test]
    fn a_newer_release_can_pass_a_failed_hold_but_cannot_clear_recovery_failure() {
        let fixture = ExecutionFixture::new();
        fixture.write_script(&fixture.request.daemon, "exit 23");
        assert!(matches!(
            fixture.run(&ExecutionFixture::options(1_000)),
            Err(ProbeRefusal::Failed { .. })
        ));
        let clock = ExecutionFixture::options(2_000).clock;
        assert!(matches!(
            probe::inspect_admission_at(&fixture.request.install, "9.9.8", &clock),
            Err(ProbeRefusal::Held { .. })
        ));
        assert!(matches!(
            probe::inspect_admission_at(&fixture.request.install, "9.9.10", &clock),
            Ok(Admission::Ready)
        ));

        let recovery = ExecutionFixture::new();
        recovery.write_script(&recovery.request.daemon, "exit 23");
        let mut options = ExecutionFixture::options(1_000);
        options.fail_write = Some(probe::WriteFailure {
            phase: probe::RecordWrite::Hold,
            step: journal::BarrierStep::FileSync,
        });
        assert!(matches!(
            recovery.run(&options),
            Err(ProbeRefusal::RecoveryFailed { .. })
        ));
        assert!(matches!(
            probe::inspect_admission_at(&recovery.request.install, "9.9.10", &clock),
            Err(ProbeRefusal::RecoveryFailed { .. })
        ));
        recovery.assert_installed_pair_unchanged();
    }
}
