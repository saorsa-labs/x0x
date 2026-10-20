#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! S2e pair regressions against real filesystem replacement operations.
//!
//! The RED scaffold calls the released single-binary primitives. The dormant
//! pair engine must satisfy these same assertions before S3a can wire it in.
//! Candidate shell fixtures implement only the inert probe response. No real
//! daemon, service, socket or network starts.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use x0x::upgrade::manifest;

#[path = "../src/upgrade/journal.rs"]
mod journal;
#[path = "../src/upgrade/pair.rs"]
mod pair;
#[allow(dead_code)]
#[path = "../src/upgrade/probe.rs"]
mod probe;

use pair::{
    BinaryInput, CliInput, PairError, PairOptions, PairOutcome, PairPhase, PairRefusal,
    PairRequest, PairRole, PairStep, ProbeBinding, SkillInput,
};

const OLD_DAEMON: &[u8] = b"original daemon 1.2.3";
const OLD_CLI: &[u8] = b"original managed CLI 1.2.0";
const WORKER_ROOT: &str = "X0X_1373_PAIR_WORKER_ROOT";
const WORKER_NAME: &str = "fixture_second_pair_writer";

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn candidate_bytes(second: bool, role: PairRole) -> Vec<u8> {
    let response = serde_json::json!({
        "version": if second { "3.0.0" } else { "2.0.0" },
        "platform": manifest::current_platform_target().unwrap(),
    });
    format!(
        "#!/bin/sh\n\
         # Inert {role:?} candidate fixture.\n\
         test \"$#\" -eq 1 && test \"$1\" = '--upgrade-probe' || exit 96\n\
         printf '%s\\n' '{response}'\n"
    )
    .into_bytes()
}

struct PairFixture {
    root: TempDir,
}

impl PairFixture {
    fn new() -> Self {
        // nextest replaces HOME with /tmp/x0x-nextest-home. Use an explicit
        // owned evidence root or the repository scratch directory instead.
        let evidence = std::env::var_os("X0X_UPGRADE_PAIR_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".planning/upgrade-pair-fixtures")
            });
        std::fs::create_dir_all(&evidence).unwrap();
        let root = tempfile::Builder::new()
            .prefix("pair-")
            .tempdir_in(evidence)
            .unwrap();
        for directory in ["install", "first", "second", "home", "tmp", "profiles"] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
        }
        for (name, bytes) in [("install/x0xd", OLD_DAEMON), ("install/x0x", OLD_CLI)] {
            std::fs::write(root.path().join(name), bytes).unwrap();
        }
        for (stage, second) in [("first", false), ("second", true)] {
            for (name, role) in [("x0xd", PairRole::Daemon), ("x0x", PairRole::Cli)] {
                let path = root.path().join(stage).join(name);
                std::fs::write(&path, candidate_bytes(second, role)).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        Self { root }
    }

    fn request(&self, second: bool) -> PairRequest {
        request_at(self.root.path(), second)
    }

    fn assert_original_pair(&self) {
        assert_eq!(
            std::fs::read(self.root.path().join("install/x0x")).unwrap(),
            OLD_CLI,
            "the managed CLI must restore when the daemon swap fails"
        );
        assert_eq!(
            std::fs::read(self.root.path().join("install/x0xd")).unwrap(),
            OLD_DAEMON,
            "the daemon must retain or restore its original bytes"
        );
    }

    fn assert_no_pair_preparation(&self) {
        self.assert_original_pair();
        for entry in std::fs::read_dir(self.root.path().join("install")).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.contains(".backup-")
                    && !name.contains(".candidate-")
                    && !name.contains(".upgrade-pair"),
                "refused admission prepared transaction material: {name}"
            );
        }
    }

    fn run_second_writer(&self) -> serde_json::Value {
        let result_path = self.root.path().join("second-result.json");
        assert!(!result_path.exists());
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", WORKER_NAME, "--ignored", "--nocapture"])
            .env(WORKER_ROOT, self.root.path())
            .env("HOME", self.root.path().join("home"))
            .env("XDG_CONFIG_HOME", self.root.path().join("home"))
            .env("XDG_DATA_HOME", self.root.path().join("home"))
            .env("XDG_CACHE_HOME", self.root.path().join("home"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("TMP", self.root.path().join("tmp"))
            .env("TEMP", self.root.path().join("tmp"))
            .env(
                "LLVM_PROFILE_FILE",
                self.root.path().join("profiles/worker-%p-%m.profraw"),
            )
            .current_dir(self.root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn inert second writer");
        let mut child = ReapedChild(Some(child));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "second writer did not finish within its bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "second writer fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(
            &std::fs::read(result_path).expect("the exact worker must write its result"),
        )
        .unwrap()
    }
}

fn request_at(root: &Path, second: bool) -> PairRequest {
    let mut request = unprobed_request_at(root, second);
    let CliInput::Managed(cli) = &request.cli else {
        unreachable!("base fixtures have a managed CLI");
    };
    // The probe engine's caller owns this persistent install lock. Release
    // it before the pair engine acquires its own ordered lock set.
    let probe_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("install/x0xd.upgrade.lock"))
        .unwrap();
    probe_lock.lock().unwrap();
    let receipt = probe::run_before_swap_with_options(
        &probe::ProbeRequest {
            install: request.install.clone(),
            version: request.candidate_version.clone(),
            platform: request.probe.platform.clone(),
            archive_sha256: request.archive_sha256,
            daemon: request.daemon.staged.clone(),
            cli: cli.staged.clone(),
            launch: probe::ProbeLaunch {
                cwd: root.to_path_buf(),
                env: vec![
                    (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                    (OsString::from("HOME"), root.join("home").into_os_string()),
                    (OsString::from("TMPDIR"), root.join("tmp").into_os_string()),
                ],
            },
        },
        &AtomicBool::new(true),
        &probe::ProbeOptions {
            clock: probe::ProbeClock {
                boot_id: "inert-pair-fixture".to_owned(),
                monotonic_ms: 1_000,
            },
            timeout: Duration::from_secs(5),
            fail_write: None,
        },
    )
    .expect("both inert candidates must produce durable Passed evidence");
    drop(probe_lock);
    request.probe.transaction_id = receipt.transaction_id;
    request
}

fn unprobed_request_at(root: &Path, second: bool) -> PairRequest {
    let (stage, version) = if second {
        ("second", "3.0.0")
    } else {
        ("first", "2.0.0")
    };
    let daemon_hash = digest(&candidate_bytes(second, PairRole::Daemon));
    let cli_hash = digest(&candidate_bytes(second, PairRole::Cli));
    PairRequest {
        install: root.join("install/x0xd"),
        candidate_version: version.to_owned(),
        manifest_sha256: [if second { 23 } else { 17 }; 32],
        archive_sha256: [if second { 41 } else { 31 }; 32],
        daemon: BinaryInput {
            target: root.join("install/x0xd"),
            staged: root.join(stage).join("x0xd"),
            previous_version: "1.2.3".to_owned(),
            previous_sha256: digest(OLD_DAEMON),
            candidate_sha256: daemon_hash,
        },
        cli: CliInput::Managed(BinaryInput {
            target: root.join("install/x0x"),
            staged: root.join(stage).join("x0x"),
            previous_version: "1.2.0".to_owned(),
            previous_sha256: digest(OLD_CLI),
            candidate_sha256: cli_hash,
        }),
        skill: None,
        probe: ProbeBinding {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            platform: manifest::current_platform_target().unwrap().to_owned(),
            daemon_sha256: daemon_hash,
            cli_sha256: cli_hash,
        },
    }
}

fn options() -> PairOptions {
    PairOptions {
        // A deterministic capacity reading avoids consuming a real GiB and
        // makes this regression independent of the build host's free space.
        available_bytes: Some(4 * 1024 * 1024 * 1024),
        cli_first: false,
        fail_at: None,
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

fn assert_retained_backups(receipt: &pair::PairReceipt) {
    assert_eq!(std::fs::read(&receipt.daemon_backup).unwrap(), OLD_DAEMON);
    assert!(
        receipt
            .daemon_backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(".backup-1.2.3-"),
        "daemon backup must use its own previous version"
    );
    let cli = receipt.cli_backup.as_ref().expect("managed CLI backup");
    assert_eq!(std::fs::read(cli).unwrap(), OLD_CLI);
    assert!(
        cli.file_name()
            .unwrap()
            .to_string_lossy()
            .contains(".backup-1.2.0-"),
        "managed CLI may have a different previous version"
    );
}

fn assert_refused(result: Result<PairOutcome, PairError>, expected: PairRefusal) {
    assert!(
        matches!(&result, Err(PairError::Refused { cause, .. }) if *cause == expected),
        "expected {expected:?}, got {result:?}"
    );
}

fn optional_bytes(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("read {}: {error}", path.display()),
    }
}

fn retained_backup_snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut backups: Vec<_> = std::fs::read_dir(root.join("install"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".backup-")
        })
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    backups.sort_by(|left, right| left.0.cmp(&right.0));
    backups
}

#[test]
fn successful_cli_then_failed_daemon_swap_restores_both_original_binaries() {
    let fixture = PairFixture::new();
    let request = fixture.request(false);
    let mut fault = options();
    fault.cli_first = true;
    fault.fail_at = Some(PairStep::BeforeSwap(PairRole::Daemon));
    let result = pair::execute_pair_with_options(&request, &AtomicBool::new(true), &fault);
    eprintln!("CLI-first swap with failed daemon result: {result:?}");
    // Check bytes before the result variant so RED names the broken pair,
    // rather than merely a missing new result or journal representation.
    fixture.assert_original_pair();
    let PairOutcome::Restored { receipt, reason } =
        result.expect("the healthy old owner must restore the pair")
    else {
        panic!("a failed second swap must report the restored pair");
    };
    assert!(!reason.is_empty());
    assert_eq!(std::fs::read(receipt.daemon_backup).unwrap(), OLD_DAEMON);
    assert_eq!(
        std::fs::read(receipt.cli_backup.expect("managed CLI backup")).unwrap(),
        OLD_CLI,
        "restoration must retain its referenced backup"
    );
}

#[test]
fn second_writer_with_different_candidate_cannot_destroy_first_pair_rollback_bytes() {
    let fixture = PairFixture::new();
    let first = pair::execute_pair_with_options(
        &fixture.request(false),
        &AtomicBool::new(true),
        &options(),
    )
    .expect("first pair must swap successfully");
    let PairOutcome::Swapped(receipt) = first else {
        panic!("first writer must reach the unresolved swapped phase");
    };
    assert_eq!(std::fs::read(&receipt.daemon_backup).unwrap(), OLD_DAEMON);
    assert_eq!(
        std::fs::read(receipt.cli_backup.as_ref().unwrap()).unwrap(),
        OLD_CLI
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0xd")).unwrap(),
        candidate_bytes(false, PairRole::Daemon)
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
        candidate_bytes(false, PairRole::Cli)
    );

    let second = fixture.run_second_writer();
    assert_ne!(
        second["pid"].as_u64().unwrap(),
        u64::from(std::process::id())
    );
    eprintln!("fresh second writer result: {second}");
    // Different incoming bytes deliberately bypass #1447's equal-byte skip.
    // The first receipt must still point to its actual original recovery pair.
    assert_eq!(
        std::fs::read(&receipt.daemon_backup).unwrap(),
        OLD_DAEMON,
        "second writer destroyed the first transaction's daemon rollback bytes"
    );
    assert_eq!(
        std::fs::read(receipt.cli_backup.unwrap()).unwrap(),
        OLD_CLI,
        "second writer destroyed the first transaction's CLI rollback bytes"
    );
    assert_eq!(second["outcome"], "refused");
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0xd")).unwrap(),
        candidate_bytes(false, PairRole::Daemon)
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
        candidate_bytes(false, PairRole::Cli)
    );
}

#[test]
fn missing_or_mismatched_durable_probe_never_prepares_a_pair() {
    for mismatch in [
        "missing",
        "transaction",
        "archive",
        "platform",
        "daemon_hash",
    ] {
        let fixture = PairFixture::new();
        let mut request = if mismatch == "missing" {
            unprobed_request_at(fixture.root.path(), false)
        } else {
            fixture.request(false)
        };
        match mismatch {
            "transaction" => request.probe.transaction_id = uuid::Uuid::new_v4().to_string(),
            "archive" => request.archive_sha256[0] ^= 1,
            "platform" => request.probe.platform = "different-platform".to_owned(),
            "daemon_hash" => request.probe.daemon_sha256[0] ^= 1,
            _ => {}
        }
        assert_refused(
            pair::execute_pair_with_options(&request, &AtomicBool::new(true), &options()),
            PairRefusal::Unresolved,
        );
        fixture.assert_no_pair_preparation();
    }
}

#[test]
fn changed_installed_or_staged_bytes_refuse_before_backup() {
    for staged in [false, true] {
        let fixture = PairFixture::new();
        let request = fixture.request(false);
        let changed = if staged {
            &request.daemon.staged
        } else {
            &request.daemon.target
        };
        std::fs::write(changed, b"unrelated replacement bytes").unwrap();
        assert_refused(
            pair::execute_pair_with_options(&request, &AtomicBool::new(true), &options()),
            if staged {
                PairRefusal::CandidateChanged
            } else {
                PairRefusal::InstalledChanged
            },
        );
        assert_eq!(
            std::fs::read(changed).unwrap(),
            b"unrelated replacement bytes"
        );
        assert_eq!(
            std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
            OLD_CLI
        );
        assert!(!pair::pair_record_path(&request.install).unwrap().exists());
        assert!(!pair::pair_pending_path(&request.install).unwrap().exists());
    }
}

#[test]
fn already_new_bytes_cannot_be_recorded_as_the_previous_recovery_pair() {
    let fixture = PairFixture::new();
    let mut request = fixture.request(false);
    std::fs::write(
        &request.daemon.target,
        candidate_bytes(false, PairRole::Daemon),
    )
    .unwrap();
    request.daemon.previous_sha256 = request.daemon.candidate_sha256;
    let CliInput::Managed(cli) = &mut request.cli else {
        unreachable!();
    };
    std::fs::write(&cli.target, candidate_bytes(false, PairRole::Cli)).unwrap();
    cli.previous_sha256 = cli.candidate_sha256;
    assert_refused(
        pair::execute_pair_with_options(&request, &AtomicBool::new(true), &options()),
        PairRefusal::InstalledChanged,
    );
    assert!(retained_backup_snapshot(fixture.root.path()).is_empty());
    assert!(!pair::pair_record_path(&request.install).unwrap().exists());
    assert_eq!(
        std::fs::read(&request.daemon.target).unwrap(),
        candidate_bytes(false, PairRole::Daemon)
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
        candidate_bytes(false, PairRole::Cli)
    );
}

#[test]
fn insufficient_capacity_and_cancelled_owner_do_not_prepare_or_swap() {
    let fixture = PairFixture::new();
    let request = fixture.request(false);
    let mut tight = options();
    tight.available_bytes = Some(1024 * 1024 * 1024 - 1);
    assert_refused(
        pair::execute_pair_with_options(&request, &AtomicBool::new(true), &tight),
        PairRefusal::InsufficientDisk,
    );
    fixture.assert_no_pair_preparation();
    assert_refused(
        pair::execute_pair_with_options(&request, &AtomicBool::new(false), &options()),
        PairRefusal::Cancelled,
    );
    fixture.assert_no_pair_preparation();
}

#[test]
fn split_cli_is_untouched_and_signed_skill_is_only_staged() {
    let fixture = PairFixture::new();
    let mut request = fixture.request(false);
    let external_cli = fixture.root.path().join("home/package-managed-x0x");
    std::fs::write(&external_cli, b"external CLI must stay unchanged").unwrap();
    request.cli = CliInput::Split {
        path: Some(external_cli.clone()),
        reason: "package-managed CLI; reinstall with its package manager".to_owned(),
    };
    let active_skill = fixture.root.path().join("home/SKILL.md");
    let incoming_skill = fixture.root.path().join("first/SKILL.md");
    std::fs::write(&active_skill, b"prior guide").unwrap();
    std::fs::write(&incoming_skill, b"verified candidate guide").unwrap();
    request.skill = Some(SkillInput {
        target: active_skill.clone(),
        staged: incoming_skill,
        candidate_sha256: digest(b"verified candidate guide"),
    });
    let PairOutcome::Swapped(receipt) =
        pair::execute_pair_with_options(&request, &AtomicBool::new(true), &options()).unwrap()
    else {
        panic!("daemon-only managed transaction must swap");
    };
    assert!(receipt.cli_untouched);
    assert!(receipt
        .cli_untouched_reason
        .as_deref()
        .unwrap()
        .contains("package-managed"));
    assert!(receipt.cli_backup.is_none());
    assert_eq!(
        std::fs::read(external_cli).unwrap(),
        b"external CLI must stay unchanged"
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
        OLD_CLI
    );
    assert_eq!(std::fs::read(active_skill).unwrap(), b"prior guide");
    assert_eq!(
        std::fs::read(receipt.staged_skill.unwrap()).unwrap(),
        b"verified candidate guide"
    );
    let record = pair::read_pair_record(&request.install).unwrap().unwrap();
    assert_eq!(record.phase, PairPhase::Swapped);
    assert!(record.cli_progress.is_none());
}

#[test]
fn every_post_rename_swap_cut_restores_both_members_and_retains_versioned_backups() {
    for cli_first in [false, true] {
        for role in [PairRole::Daemon, PairRole::Cli] {
            for step in [
                PairStep::AfterSwapRename(role),
                PairStep::SwapDirectorySync(role),
                PairStep::BeforeSwapProgress(role),
            ] {
                let fixture = PairFixture::new();
                let request = fixture.request(false);
                let mut fault = options();
                fault.cli_first = cli_first;
                fault.fail_at = Some(step);
                let result =
                    pair::execute_pair_with_options(&request, &AtomicBool::new(true), &fault);
                let PairOutcome::Restored { receipt, .. } =
                    result.unwrap_or_else(|error| panic!("{step:?}: {error}"))
                else {
                    panic!("{step:?} must restore despite unacknowledged rename progress");
                };
                fixture.assert_original_pair();
                assert_retained_backups(&receipt);
                let record = pair::read_pair_record(&request.install).unwrap().unwrap();
                assert_eq!(record.phase, PairPhase::Restored);
                assert!(record.daemon_progress.restored);
                assert!(record.cli_progress.unwrap().restored);
                assert!(!pair::pair_pending_path(&request.install).unwrap().exists());
            }
        }
    }
}

#[test]
fn preparation_file_barriers_refuse_without_replacing_installed_bytes() {
    for role in [PairRole::Daemon, PairRole::Cli] {
        for step in [
            PairStep::BackupFileSync(role),
            PairStep::BackupDirectorySync(role),
            PairStep::CandidateFileSync(role),
            PairStep::CandidateDirectorySync(role),
        ] {
            let fixture = PairFixture::new();
            let request = fixture.request(false);
            let mut fault = options();
            fault.fail_at = Some(step);
            assert!(
                pair::execute_pair_with_options(&request, &AtomicBool::new(true), &fault).is_err(),
                "{step:?} must withhold a swapped receipt"
            );
            fixture.assert_original_pair();
            assert!(!pair::pair_record_path(&request.install).unwrap().exists());
        }
    }
}

#[test]
fn failed_restore_keeps_backups_and_refuses_a_fresh_process_writer() {
    for step in [
        PairStep::BeforeRollbackRecord,
        PairStep::BeforeRestore(PairRole::Cli),
        PairStep::AfterRestoreRename(PairRole::Cli),
        PairStep::RestoreDirectorySync(PairRole::Cli),
        PairStep::BeforeRestoreProgress(PairRole::Cli),
        PairStep::BeforeRestoredRecord,
    ] {
        let fixture = PairFixture::new();
        let request = fixture.request(false);
        let mut fault = options();
        fault.cli_first = true;
        fault.fail_at = Some(PairStep::BeforeSwap(PairRole::Daemon));
        let result =
            pair::execute_pair_with_failures(&request, &AtomicBool::new(true), &fault, &[step]);
        assert!(
            matches!(result, Err(PairError::RecoveryFailed { .. })),
            "{step:?} must require repair: {result:?}"
        );
        let path = pair::pair_record_path(&request.install).unwrap();
        let pending = pair::pair_pending_path(&request.install).unwrap();
        let before = std::fs::read(&path).unwrap();
        let pending_before = std::fs::read(&pending).unwrap();
        let record = pair::read_pair_record(&request.install).unwrap().unwrap();
        assert_eq!(record.phase, PairPhase::RecoveryFailed);
        assert_eq!(
            std::fs::read(&record.plan.daemon.backup).unwrap(),
            OLD_DAEMON
        );
        assert_eq!(
            std::fs::read(&record.plan.cli.as_ref().unwrap().backup).unwrap(),
            OLD_CLI
        );
        let second = fixture.run_second_writer();
        assert_eq!(second["outcome"], "refused");
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert_eq!(std::fs::read(pending).unwrap(), pending_before);
        assert_eq!(
            std::fs::read(&record.plan.daemon.backup).unwrap(),
            OLD_DAEMON
        );
        assert_eq!(
            std::fs::read(&record.plan.cli.as_ref().unwrap().backup).unwrap(),
            OLD_CLI
        );
    }
}

#[test]
fn a_new_transaction_after_restore_preserves_both_earlier_versioned_backups() {
    let fixture = PairFixture::new();
    let mut fault = options();
    fault.cli_first = true;
    fault.fail_at = Some(PairStep::BeforeSwap(PairRole::Daemon));
    let PairOutcome::Restored { receipt: first, .. } =
        pair::execute_pair_with_options(&fixture.request(false), &AtomicBool::new(true), &fault)
            .unwrap()
    else {
        panic!("first transaction must restore");
    };
    let PairOutcome::Swapped(second) =
        pair::execute_pair_with_options(&fixture.request(true), &AtomicBool::new(true), &options())
            .unwrap()
    else {
        panic!("a resolved predecessor permits a fresh transaction");
    };
    assert_ne!(first.transaction_id, second.transaction_id);
    assert_ne!(first.daemon_backup, second.daemon_backup);
    assert_ne!(first.cli_backup, second.cli_backup);
    assert_retained_backups(&first);
    assert_retained_backups(&second);
    let record = pair::read_pair_record(&fixture.root.path().join("install/x0xd"))
        .unwrap()
        .unwrap();
    let previous = record
        .plan
        .previous_record
        .expect("retained resolved record");
    let previous: serde_json::Value =
        serde_json::from_slice(&std::fs::read(previous).unwrap()).unwrap();
    assert_eq!(previous["transaction_id"], first.transaction_id);
}

#[test]
fn every_pair_record_barrier_withholds_unsafe_completion() {
    for phase in [
        PairPhase::Prepared,
        PairPhase::Swapped,
        PairPhase::RollingBack,
        PairPhase::Restored,
    ] {
        for step in [
            journal::BarrierStep::Write,
            journal::BarrierStep::FileSync,
            journal::BarrierStep::Rename,
            journal::BarrierStep::DirectorySync,
        ] {
            let fixture = PairFixture::new();
            let request = fixture.request(false);
            let mut fault = options();
            if matches!(phase, PairPhase::RollingBack | PairPhase::Restored) {
                fault.fail_at = Some(PairStep::BeforeSwap(PairRole::Cli));
            }
            let result = pair::execute_pair_with_record_failure(
                &request,
                &AtomicBool::new(true),
                &fault,
                phase,
                step,
            );
            if phase == PairPhase::Swapped {
                let PairOutcome::Restored { receipt, .. } =
                    result.unwrap_or_else(|error| panic!("{phase:?}/{step:?}: {error}"))
                else {
                    panic!("an unacknowledged swapped record must restore the pair");
                };
                fixture.assert_original_pair();
                assert_retained_backups(&receipt);
                continue;
            }
            assert!(
                matches!(result, Err(PairError::RecoveryFailed { .. })),
                "{phase:?}/{step:?} must preserve uncertainty: {result:?}"
            );
            let path = pair::pair_record_path(&request.install).unwrap();
            let pending = pair::pair_pending_path(&request.install).unwrap();
            let before = optional_bytes(&path);
            let pending_before = std::fs::read(&pending).unwrap();
            let backups = retained_backup_snapshot(fixture.root.path());
            assert_eq!(backups.len(), 2);
            assert!(backups.iter().any(|(_, bytes)| bytes == OLD_DAEMON));
            assert!(backups.iter().any(|(_, bytes)| bytes == OLD_CLI));
            if phase != PairPhase::RollingBack {
                fixture.assert_original_pair();
            }
            let second = fixture.run_second_writer();
            assert_eq!(second["outcome"], "refused");
            assert_eq!(optional_bytes(&path), before);
            assert_eq!(std::fs::read(pending).unwrap(), pending_before);
            assert_eq!(retained_backup_snapshot(fixture.root.path()), backups);
        }
    }
}

#[test]
fn corrupt_or_unknown_pair_evidence_is_preserved_by_a_fresh_writer() {
    for (pending, bytes) in [
        (false, b"{torn".as_slice()),
        (false, br#"{"schema_version":999,"record_kind":"pair"}"#),
        (true, b"{torn".as_slice()),
    ] {
        let fixture = PairFixture::new();
        let request = fixture.request(false);
        let path = if pending {
            pair::pair_pending_path(&request.install).unwrap()
        } else {
            pair::pair_record_path(&request.install).unwrap()
        };
        std::fs::write(&path, bytes).unwrap();
        let second = fixture.run_second_writer();
        assert_eq!(second["outcome"], "refused");
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        fixture.assert_original_pair();
        assert!(retained_backup_snapshot(fixture.root.path()).is_empty());
    }
}

#[test]
fn installed_hash_is_rechecked_after_preparation_without_overwriting_unrelated_bytes() {
    let fixture = PairFixture::new();
    let request = fixture.request(false);
    let daemon = request.daemon.target.clone();
    let result = pair::execute_pair_with_observer(
        &request,
        &AtomicBool::new(true),
        &options(),
        move |step| {
            if step == PairStep::BeforeSwap(PairRole::Daemon) {
                std::fs::write(&daemon, b"unrelated writer after preparation").unwrap();
            }
        },
    );
    assert!(matches!(result, Err(PairError::RecoveryFailed { .. })));
    assert_eq!(
        std::fs::read(&request.daemon.target).unwrap(),
        b"unrelated writer after preparation",
        "neither swap nor rollback may overwrite an unattributed target"
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
        OLD_CLI
    );
    let record = pair::read_pair_record(&request.install).unwrap().unwrap();
    assert_eq!(record.phase, PairPhase::RecoveryFailed);
    assert_eq!(
        std::fs::read(record.plan.daemon.backup).unwrap(),
        OLD_DAEMON
    );
    assert_eq!(
        std::fs::read(record.plan.cli.unwrap().backup).unwrap(),
        OLD_CLI
    );
}

#[test]
fn cancellation_after_first_rename_restores_the_pair_before_returning() {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    let fixture = PairFixture::new();
    let request = fixture.request(false);
    let alive = Arc::new(AtomicBool::new(true));
    let cancel = Arc::clone(&alive);
    let result = pair::execute_pair_with_observer(&request, &alive, &options(), move |step| {
        if step == PairStep::AfterSwapRename(PairRole::Daemon) {
            cancel.store(false, Ordering::Release);
        }
    });
    let PairOutcome::Restored { receipt, reason } = result.unwrap() else {
        panic!("cancellation cannot strand the first replaced member");
    };
    assert!(reason.contains("cancelled"));
    fixture.assert_original_pair();
    assert_retained_backups(&receipt);
    assert_eq!(
        pair::read_pair_record(&request.install)
            .unwrap()
            .unwrap()
            .phase,
        PairPhase::Restored
    );
}

#[test]
#[ignore = "inert fixture, invoked only by the bounded parent regression"]
fn fixture_second_pair_writer() {
    let Some(root) = std::env::var_os(WORKER_ROOT).map(PathBuf::from) else {
        return;
    };
    let result = pair::execute_pair_with_options(
        &request_at(&root, true),
        &AtomicBool::new(true),
        &options(),
    );
    let outcome = match &result {
        Ok(PairOutcome::Swapped(_)) => "swapped",
        Ok(PairOutcome::Restored { .. }) => "restored",
        Ok(PairOutcome::AlreadyCandidate) => "already_candidate",
        Err(pair::PairError::Refused { .. }) => "refused",
        Err(pair::PairError::RecoveryFailed { .. }) => "recovery_failed",
    };
    let receipt = serde_json::json!({
        "pid": std::process::id(),
        "outcome": outcome,
        "detail": format!("{result:?}"),
    });
    std::fs::write(
        root.join("second-result.json"),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
