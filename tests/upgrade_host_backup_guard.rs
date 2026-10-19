#![allow(clippy::unwrap_used, clippy::expect_used)]

//! #1447 host-wide backup guard: two units on one shared target must leave
//! `<target>.backup` holding the original bytes. Uses a libtest self-exec
//! pattern so the race runs in independent processes (not threads).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use semver::Version;
use tempfile::TempDir;
use x0x::upgrade::{UpgradeResult, Upgrader};

const ORIGINAL: &[u8] = b"original-binary-bytes-v1";
const CANDIDATE: &[u8] = b"candidate-binary-bytes-v2";
const FROM: &str = "1.0.0";
const TO: &str = "2.0.0";

const WORKER_ENV: &str = "X0X_1447_HOST_BACKUP_WORKER";
/// Fixture filter name — real test names in this file must not contain it.
const APPLY_WORKER: &str = "fixture_role_host_backup_apply_worker";

fn test_exe() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn wait_until_exists(path: &Path) {
    while !path.exists() {
        std::thread::yield_now();
    }
}

fn backup_path(target: &Path) -> PathBuf {
    target.with_extension("backup")
}

/// Child: wait for the barrier, then `perform_upgrade`, record skip vs replace.
#[test]
fn fixture_role_host_backup_apply_worker() {
    let Ok(dir) = std::env::var(WORKER_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let target = dir.join("target");
    let incoming = dir.join(std::env::var("X0X_1447_INCOMING").unwrap());
    let ready = dir.join(std::env::var("X0X_1447_READY").unwrap());
    let go = dir.join("barrier_go");
    let result = dir.join(std::env::var("X0X_1447_RESULT").unwrap());

    fs::write(&ready, b"ready").unwrap();
    wait_until_exists(&go);

    let upgrader = Upgrader::new(target, Version::parse(FROM).unwrap());
    let outcome = upgrader
        .perform_upgrade(&incoming, &Version::parse(TO).unwrap())
        .expect("perform_upgrade");
    assert!(
        matches!(outcome, UpgradeResult::Success { .. }),
        "disk-already-matches must still be Success, not NoUpgrade: {outcome:?}"
    );

    // Skip leaves the incoming path in place; replace renames it onto the target.
    let kind = if incoming.exists() {
        "skipped"
    } else {
        "replaced"
    };
    fs::write(&result, kind).unwrap();
}

fn spawn_apply_worker(
    dir: &Path,
    incoming_name: &str,
    ready_name: &str,
    result_name: &str,
) -> Child {
    Command::new(test_exe())
        .arg(APPLY_WORKER)
        .env(WORKER_ENV, dir)
        .env("X0X_1447_INCOMING", incoming_name)
        .env("X0X_1447_READY", ready_name)
        .env("X0X_1447_RESULT", result_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn apply worker")
}

fn wait_for_result(path: &Path) -> String {
    wait_until_exists(path);
    loop {
        let text = fs::read_to_string(path).unwrap_or_default();
        if text == "skipped" || text == "replaced" {
            return text;
        }
        std::thread::yield_now();
    }
}

fn assert_backup_and_target(target: &Path) {
    // Unconditional postcondition (Codex nit on #1451): backup keeps original
    // bytes and target holds the candidate. A skip never stands in for this.
    assert_eq!(
        fs::read(backup_path(target)).unwrap(),
        ORIGINAL,
        "backup must hold the original bytes"
    );
    assert_eq!(
        fs::read(target).unwrap(),
        CANDIDATE,
        "target must hold the candidate bytes"
    );
}

/// Two independent processes apply the same candidate onto one shared target,
/// overlapping through a barrier, then a late third attempt.
#[test]
fn two_processes_preserve_original_backup_unconditionally() {
    if std::env::var_os(WORKER_ENV).is_some() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let target = root.join("target");
    write_bytes(&target, ORIGINAL);
    write_bytes(&root.join("incoming_a"), CANDIDATE);
    write_bytes(&root.join("incoming_b"), CANDIDATE);

    let mut child_a = spawn_apply_worker(root, "incoming_a", "ready_a", "result_a");
    let mut child_b = spawn_apply_worker(root, "incoming_b", "ready_b", "result_b");

    wait_until_exists(&root.join("ready_a"));
    wait_until_exists(&root.join("ready_b"));
    fs::write(root.join("barrier_go"), b"go").unwrap();

    let outcome_a = wait_for_result(&root.join("result_a"));
    let outcome_b = wait_for_result(&root.join("result_b"));
    assert!(child_a.wait().unwrap().success());
    assert!(child_b.wait().unwrap().success());

    assert_backup_and_target(&target);

    // Record the skip separately — never as a substitute for the backup check.
    let skips = [&outcome_a, &outcome_b]
        .iter()
        .filter(|s| **s == "skipped")
        .count();
    let replaces = [&outcome_a, &outcome_b]
        .iter()
        .filter(|s| **s == "replaced")
        .count();
    assert_eq!(
        replaces, 1,
        "exactly one process must replace: a={outcome_a} b={outcome_b}"
    );
    assert_eq!(
        skips, 1,
        "exactly one process must skip: a={outcome_a} b={outcome_b}"
    );

    // Late second attempt after replacement (disk already matches).
    write_bytes(&root.join("incoming_late"), CANDIDATE);
    let _ = fs::remove_file(root.join("barrier_go"));
    let mut child_late = spawn_apply_worker(root, "incoming_late", "ready_late", "result_late");
    wait_until_exists(&root.join("ready_late"));
    fs::write(root.join("barrier_go"), b"go").unwrap();
    let late = wait_for_result(&root.join("result_late"));
    assert!(child_late.wait().unwrap().success());
    assert_eq!(late, "skipped", "late attempt must skip backup and replace");
    assert_backup_and_target(&target);
}

/// Two old-running units (both `current_version` older than the candidate)
/// share one on-disk target: both return Success; backup keeps pre-upgrade bytes.
#[test]
fn two_old_processes_one_shared_target_both_succeed() {
    if std::env::var_os(WORKER_ENV).is_some() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let root = dir.path();
    // Workers always use the basename `target` (see fixture).
    let target = root.join("target");
    write_bytes(&target, ORIGINAL);
    write_bytes(&root.join("incoming_a"), CANDIDATE);
    write_bytes(&root.join("incoming_b"), CANDIDATE);

    let mut child_a = spawn_apply_worker(root, "incoming_a", "ready_a", "result_a");
    let mut child_b = spawn_apply_worker(root, "incoming_b", "ready_b", "result_b");
    wait_until_exists(&root.join("ready_a"));
    wait_until_exists(&root.join("ready_b"));
    fs::write(root.join("barrier_go"), b"go").unwrap();

    let a = wait_for_result(&root.join("result_a"));
    let b = wait_for_result(&root.join("result_b"));
    assert!(child_a.wait().unwrap().success());
    assert!(child_b.wait().unwrap().success());
    assert!(
        (a == "replaced" || a == "skipped") && (b == "replaced" || b == "skipped"),
        "both old processes must finish with Success-side outcomes: a={a} b={b}"
    );
    assert_backup_and_target(&target);
}

/// Single-unit apply still backs up and replaces as today.
#[test]
fn single_unit_backs_up_and_replaces() {
    if std::env::var_os(WORKER_ENV).is_some() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let target = dir.path().join("x0xd");
    let incoming = dir.path().join("incoming");
    write_bytes(&target, ORIGINAL);
    write_bytes(&incoming, CANDIDATE);

    let upgrader = Upgrader::new(target.clone(), Version::parse(FROM).unwrap());
    let result = upgrader
        .perform_upgrade(&incoming, &Version::parse(TO).unwrap())
        .unwrap();
    assert!(matches!(result, UpgradeResult::Success { .. }));
    assert_eq!(fs::read(backup_path(&target)).unwrap(), ORIGINAL);
    assert_eq!(fs::read(&target).unwrap(), CANDIDATE);
    assert!(!incoming.exists(), "replace must consume the incoming path");
}

/// Companion CLI beside x0xd uses its own `<target>.upgrade.lock` (same
/// mechanism, distinct lock file per binary path).
#[test]
fn companion_cli_uses_own_lock_file_beside_target() {
    if std::env::var_os(WORKER_ENV).is_some() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let x0xd = dir.path().join("x0xd");
    let x0x = dir.path().join("x0x");
    let incoming_d = dir.path().join("incoming_d");
    let incoming_c = dir.path().join("incoming_c");
    write_bytes(&x0xd, ORIGINAL);
    write_bytes(&x0x, ORIGINAL);
    write_bytes(&incoming_d, CANDIDATE);
    write_bytes(&incoming_c, CANDIDATE);

    Upgrader::new(x0xd.clone(), Version::parse(FROM).unwrap())
        .perform_upgrade(&incoming_d, &Version::parse(TO).unwrap())
        .unwrap();
    Upgrader::new(x0x.clone(), Version::parse(FROM).unwrap())
        .perform_upgrade(&incoming_c, &Version::parse(TO).unwrap())
        .unwrap();

    assert!(
        dir.path().join("x0xd.upgrade.lock").exists(),
        "x0xd must take x0xd.upgrade.lock"
    );
    assert!(
        dir.path().join("x0x.upgrade.lock").exists(),
        "companion x0x must take its own x0x.upgrade.lock"
    );
}
