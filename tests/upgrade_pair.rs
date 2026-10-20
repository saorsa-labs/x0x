#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! S2e pair regressions against real filesystem replacement operations.
//!
//! The RED scaffold calls the released single-binary primitives. The dormant
//! pair engine must satisfy these same assertions before S3a can wire it in.
//! Fixtures contain inert bytes; no daemon, service, socket or network starts.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[path = "../src/upgrade/journal.rs"]
mod journal;
#[path = "../src/upgrade/pair.rs"]
mod pair;

use pair::{
    BinaryInput, CliInput, PairOptions, PairOutcome, PairRequest, PairRole, PairStep, ProbeBinding,
};

const OLD_DAEMON: &[u8] = b"original daemon 1.2.3";
const OLD_CLI: &[u8] = b"original managed CLI 1.2.0";
const FIRST_DAEMON: &[u8] = b"first candidate daemon 2.0.0";
const FIRST_CLI: &[u8] = b"first candidate CLI 2.0.0";
const SECOND_DAEMON: &[u8] = b"different second candidate daemon 3.0.0";
const SECOND_CLI: &[u8] = b"different second candidate CLI 3.0.0";
const WORKER_ROOT: &str = "X0X_1373_PAIR_WORKER_ROOT";
const WORKER_NAME: &str = "fixture_second_pair_writer";

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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
        for (name, bytes) in [
            ("install/x0xd", OLD_DAEMON),
            ("install/x0x", OLD_CLI),
            ("first/x0xd", FIRST_DAEMON),
            ("first/x0x", FIRST_CLI),
            ("second/x0xd", SECOND_DAEMON),
            ("second/x0x", SECOND_CLI),
        ] {
            std::fs::write(root.path().join(name), bytes).unwrap();
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
    let (stage, version, daemon_bytes, cli_bytes, probe_id) = if second {
        (
            "second",
            "3.0.0",
            SECOND_DAEMON,
            SECOND_CLI,
            "00000000-0000-4000-8000-000000000002",
        )
    } else {
        (
            "first",
            "2.0.0",
            FIRST_DAEMON,
            FIRST_CLI,
            "00000000-0000-4000-8000-000000000001",
        )
    };
    PairRequest {
        install: root.join("install/x0xd"),
        candidate_version: version.to_owned(),
        manifest_sha256: [if second { 23 } else { 17 }; 32],
        daemon: BinaryInput {
            target: root.join("install/x0xd"),
            staged: root.join(stage).join("x0xd"),
            previous_version: "1.2.3".to_owned(),
            previous_sha256: digest(OLD_DAEMON),
            candidate_sha256: digest(daemon_bytes),
        },
        cli: CliInput::Managed(BinaryInput {
            target: root.join("install/x0x"),
            staged: root.join(stage).join("x0x"),
            previous_version: "1.2.0".to_owned(),
            previous_sha256: digest(OLD_CLI),
            candidate_sha256: digest(cli_bytes),
        }),
        skill: None,
        probe: ProbeBinding {
            transaction_id: probe_id.to_owned(),
            daemon_sha256: digest(daemon_bytes),
            cli_sha256: digest(cli_bytes),
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
        FIRST_DAEMON
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
        FIRST_CLI
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
        FIRST_DAEMON
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("install/x0x")).unwrap(),
        FIRST_CLI
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
