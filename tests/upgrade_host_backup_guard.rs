#![allow(clippy::unwrap_used, clippy::expect_used)]

//! #1447 host-wide backup guard: two units on one shared target must leave
//! `<target>.backup` holding the original bytes. Uses a libtest self-exec
//! pattern so the race runs in independent processes (not threads).

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

/// Bound for parent waits so a crashed worker fails the test instead of hanging.
const WAIT_DEADLINE: Duration = Duration::from_secs(15);

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

fn backup_path(target: &Path) -> PathBuf {
    target.with_extension("backup")
}

fn host_lock_path(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".upgrade.lock");
    target.with_file_name(name)
}

fn acquire_host_lock(target: &Path) -> File {
    let lock_path = host_lock_path(target);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap_or_else(|e| panic!("open host lock {}: {e}", lock_path.display()));
    file.lock()
        .unwrap_or_else(|e| panic!("take host lock {}: {e}", lock_path.display()));
    file
}

/// Kills and reaps any still-running children on drop (failure or panic).
struct ChildReaper {
    children: Vec<Child>,
}

impl ChildReaper {
    fn new() -> Self {
        Self {
            children: Vec::new(),
        }
    }

    fn push(&mut self, child: Child) -> usize {
        self.children.push(child);
        self.children.len() - 1
    }

    fn get_mut(&mut self, index: usize) -> &mut Child {
        &mut self.children[index]
    }

    fn try_wait_one(&mut self, index: usize) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.children[index].try_wait()
    }

    fn kill_all(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.children.clear();
    }
}

impl Drop for ChildReaper {
    fn drop(&mut self) {
        self.kill_all();
    }
}

fn wait_until_exists(path: &Path, reaper: &mut ChildReaper, label: &str) {
    let deadline = Instant::now() + WAIT_DEADLINE;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        for i in 0..reaper.children.len() {
            if let Ok(Some(status)) = reaper.try_wait_one(i) {
                reaper.kill_all();
                panic!(
                    "{label}: child {i} exited with {status} before {} appeared",
                    path.display()
                );
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    reaper.kill_all();
    panic!(
        "{label}: timed out after {WAIT_DEADLINE:?} waiting for {}",
        path.display()
    );
}

fn wait_for_result(path: &Path, reaper: &mut ChildReaper, label: &str) -> String {
    let deadline = Instant::now() + WAIT_DEADLINE;
    while Instant::now() < deadline {
        if path.exists() {
            let text = fs::read_to_string(path).unwrap_or_default();
            if text == "skipped" || text == "replaced" {
                return text;
            }
        }
        for i in 0..reaper.children.len() {
            if let Ok(Some(status)) = reaper.try_wait_one(i) {
                if !status.success() {
                    reaper.kill_all();
                    panic!(
                        "{label}: child {i} failed with {status} while waiting for result {}",
                        path.display()
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    reaper.kill_all();
    panic!(
        "{label}: timed out after {WAIT_DEADLINE:?} waiting for result {}",
        path.display()
    );
}

fn reap_success(reaper: &mut ChildReaper, index: usize, label: &str) {
    let status = reaper
        .get_mut(index)
        .wait()
        .unwrap_or_else(|e| panic!("{label}: wait child {index}: {e}"));
    assert!(
        status.success(),
        "{label}: child {index} exited with {status}"
    );
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
    // Worker-side barrier wait: bounded so a missing go file fails the child.
    let deadline = Instant::now() + WAIT_DEADLINE;
    while !go.exists() {
        if Instant::now() >= deadline {
            panic!("worker timed out waiting for barrier_go");
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let upgrader = Upgrader::new(target, Version::parse(FROM).unwrap());
    let outcome = upgrader
        .perform_upgrade(&incoming, &Version::parse(TO).unwrap())
        .expect("perform_upgrade");

    // Skip leaves the incoming path in place; replace renames it onto the target.
    // Public perform_upgrade reports Success on an already-matching disk
    // (same observable result as main; #1447 RC5). Replace is also Success.
    let kind = if incoming.exists() {
        assert!(
            matches!(outcome, UpgradeResult::Success { .. }),
            "disk-already-matches must be public Success (main-compatible): {outcome:?}"
        );
        "skipped"
    } else {
        assert!(
            matches!(outcome, UpgradeResult::Success { .. }),
            "replace must be Success: {outcome:?}"
        );
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

    let mut reaper = ChildReaper::new();
    let idx_a = reaper.push(spawn_apply_worker(
        root,
        "incoming_a",
        "ready_a",
        "result_a",
    ));
    let idx_b = reaper.push(spawn_apply_worker(
        root,
        "incoming_b",
        "ready_b",
        "result_b",
    ));

    wait_until_exists(&root.join("ready_a"), &mut reaper, "two_processes ready_a");
    wait_until_exists(&root.join("ready_b"), &mut reaper, "two_processes ready_b");
    fs::write(root.join("barrier_go"), b"go").unwrap();

    let outcome_a = wait_for_result(
        &root.join("result_a"),
        &mut reaper,
        "two_processes result_a",
    );
    let outcome_b = wait_for_result(
        &root.join("result_b"),
        &mut reaper,
        "two_processes result_b",
    );
    reap_success(&mut reaper, idx_a, "two_processes");
    reap_success(&mut reaper, idx_b, "two_processes");

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
    let mut late_reaper = ChildReaper::new();
    let idx_late = late_reaper.push(spawn_apply_worker(
        root,
        "incoming_late",
        "ready_late",
        "result_late",
    ));
    wait_until_exists(
        &root.join("ready_late"),
        &mut late_reaper,
        "two_processes ready_late",
    );
    fs::write(root.join("barrier_go"), b"go").unwrap();
    let late = wait_for_result(
        &root.join("result_late"),
        &mut late_reaper,
        "two_processes result_late",
    );
    reap_success(&mut late_reaper, idx_late, "two_processes late");
    assert_eq!(late, "skipped", "late attempt must skip backup and replace");
    assert_backup_and_target(&target);
}

/// Two old-running units (both `current_version` older than the candidate)
/// share one on-disk target: one replaces, one may skip (both public Success);
/// backup keeps pre-upgrade bytes.
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

    let mut reaper = ChildReaper::new();
    let idx_a = reaper.push(spawn_apply_worker(
        root,
        "incoming_a",
        "ready_a",
        "result_a",
    ));
    let idx_b = reaper.push(spawn_apply_worker(
        root,
        "incoming_b",
        "ready_b",
        "result_b",
    ));
    wait_until_exists(&root.join("ready_a"), &mut reaper, "two_old ready_a");
    wait_until_exists(&root.join("ready_b"), &mut reaper, "two_old ready_b");
    fs::write(root.join("barrier_go"), b"go").unwrap();

    let a = wait_for_result(&root.join("result_a"), &mut reaper, "two_old result_a");
    let b = wait_for_result(&root.join("result_b"), &mut reaper, "two_old result_b");
    reap_success(&mut reaper, idx_a, "two_old");
    reap_success(&mut reaper, idx_b, "two_old");
    assert!(
        (a == "replaced" || a == "skipped") && (b == "replaced" || b == "skipped"),
        "both old processes must finish with Success-side outcomes: a={a} b={b}"
    );
    assert_backup_and_target(&target);
}

/// Parent holds the real host lock: a ready worker must not replace until unlock.
#[test]
fn held_host_lock_excludes_ready_worker_until_released() {
    if std::env::var_os(WORKER_ENV).is_some() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let target = root.join("target");
    write_bytes(&target, ORIGINAL);
    write_bytes(&root.join("incoming_a"), CANDIDATE);

    let host_lock = acquire_host_lock(&target);

    let mut reaper = ChildReaper::new();
    let idx = reaper.push(spawn_apply_worker(
        root,
        "incoming_a",
        "ready_a",
        "result_a",
    ));
    wait_until_exists(&root.join("ready_a"), &mut reaper, "exclusion ready_a");
    fs::write(root.join("barrier_go"), b"go").unwrap();

    // Worker is past the barrier and blocked on File::lock. Give it time to
    // prove it cannot replace while we still hold the lock.
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        fs::read(&target).unwrap(),
        ORIGINAL,
        "worker must not replace the target while the parent holds the host lock"
    );
    assert!(
        !root.join("result_a").exists(),
        "worker must still be waiting on the host lock (no result file yet)"
    );
    if let Ok(Some(status)) = reaper.try_wait_one(idx) {
        reaper.kill_all();
        panic!("worker exited with {status} while parent still held the host lock");
    }

    drop(host_lock);

    let outcome = wait_for_result(&root.join("result_a"), &mut reaper, "exclusion result_a");
    reap_success(&mut reaper, idx, "exclusion");
    assert_eq!(
        outcome, "replaced",
        "worker must replace once the lock is released"
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
