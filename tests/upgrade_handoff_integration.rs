#![allow(clippy::unwrap_used, clippy::expect_used)]

//! #261 integration tests: transactional upgrade handoff.
//!
//! No live GitHub release is used. The "new"/"old" binaries are fixture
//! wrappers around this test binary (a libtest self-exec pattern: the wrapper
//! execs `current_exe()` with a fixture test name and `FIXTURE_*` env), the
//! handoff helper is the real `x0xd` binary (`--upgrade-handoff`), and the
//! handoff JSON is produced by the library's own `UpgradeHandoff` types.
//!
//! Unix-only: the wrappers are `#!/bin/sh` scripts and the pid probes rely on
//! `kill(pid, 0)`.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use x0x::upgrade::restart::{self, RestartMode, UpgradeHandoff};

/// The real daemon binary — used as the handoff helper.
const X0XD_BIN: &str = env!("CARGO_BIN_EXE_x0xd");
/// Fixture test names (libtest filters for the self-exec wrappers). Real test
/// names in this file must never contain these substrings.
const HEALTH_FIXTURE: &str = "fixture_role_health_daemon";
const OLD_SIDE_FIXTURE: &str = "fixture_role_old_side";

const OLD_VERSION: &str = "9.9.7";
const NEW_VERSION: &str = "9.9.9";

const FROM: u64 = 2;
const RELEASE_TIMEOUT_SECS: u64 = 4;
const HEALTH_TIMEOUT_SECS: u64 = 4;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn test_exe() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn assert_quote_free(s: &str) {
    assert!(
        !s.contains('\''),
        "fixture path may not contain a single quote: {s}"
    );
}

fn make_executable(path: &Path) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A fixture "daemon" that serves `GET /health` 200 with `version` until the
/// stop file appears (or the lifetime backstop expires).
fn write_health_wrapper(path: &Path, port: u16, version: &str, stop_file: &Path) {
    let exe = test_exe().to_string_lossy().to_string();
    let stop = stop_file.to_string_lossy().to_string();
    assert_quote_free(&exe);
    assert_quote_free(&stop);
    let script = format!(
        "#!/bin/sh\nFIXTURE_PORT={port} FIXTURE_VERSION={version} \
         FIXTURE_STOP_FILE='{stop}' FIXTURE_LIFETIME_SECS=300 \
         exec '{exe}' {HEALTH_FIXTURE}\n"
    );
    std::fs::write(path, script).unwrap();
    make_executable(path);
}

/// A fixture "new binary" that exits 1 and never binds anything.
fn write_crash_wrapper(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nexit 1\n").unwrap();
    make_executable(path);
}

/// Spawn the "old daemon" process directly: the health fixture holding
/// `port`, self-terminating after `lifetime_secs`.
///
/// A reaper thread owns the child so its pid reads as dead (not zombie) once
/// it exits — in production the old daemon's parent (shell/systemd) does the
/// reaping the helper's pid probe depends on.
fn spawn_old_daemon(port: u16, version: &str, stop_file: &Path, lifetime_secs: u64) -> u32 {
    let stop = stop_file.to_string_lossy().to_string();
    assert_quote_free(&stop);
    let mut child = Command::new(test_exe())
        .arg(HEALTH_FIXTURE)
        .env("FIXTURE_PORT", port.to_string())
        .env("FIXTURE_VERSION", version)
        .env("FIXTURE_STOP_FILE", stop)
        .env("FIXTURE_LIFETIME_SECS", lifetime_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    pid
}

/// A pid that is guaranteed dead: spawn, reap, and reuse its (now free) pid.
fn dead_pid() -> u32 {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .spawn()
        .unwrap();
    let pid = child.id();
    let _ = child.wait();
    pid
}

fn write_handoff(
    data_dir: &Path,
    target: &Path,
    backup: &Path,
    old_pid: u32,
    port: u16,
) -> PathBuf {
    let handoff = UpgradeHandoff {
        from_version: OLD_VERSION.to_string(),
        to_version: NEW_VERSION.to_string(),
        target_path: target.to_path_buf(),
        backup_path: backup.to_path_buf(),
        argv: vec![
            "x0xd".to_string(),
            "--config".to_string(),
            "x.toml".to_string(),
        ],
        cwd: data_dir.to_string_lossy().to_string(),
        env: Default::default(),
        old_pid,
        api_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        started_at: 1_724_000_000,
        mode: RestartMode::TransactionalHandoff,
    };
    let path = data_dir.join(restart::HANDOFF_FILE_NAME);
    handoff.write(&path).unwrap();
    path
}

/// Run the real `x0xd --upgrade-handoff` helper with short test timeouts.
fn run_helper(handoff_path: &Path) -> std::process::ExitStatus {
    Command::new(X0XD_BIN)
        .arg("--upgrade-handoff")
        .arg(handoff_path)
        .env(
            "X0X_UPGRADE_HANDOFF_RELEASE_TIMEOUT_SECS",
            RELEASE_TIMEOUT_SECS.to_string(),
        )
        .env(
            "X0X_UPGRADE_HANDOFF_HEALTH_TIMEOUT_SECS",
            HEALTH_TIMEOUT_SECS.to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
}

/// Minimal HTTP client for the fixture daemon / real daemon `/health`.
fn http_get_health(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    if response.starts_with("HTTP/1.1 200") {
        Some(response)
    } else {
        None
    }
}

fn wait_for_health_version(port: u16, version: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(body) = http_get_health(port) {
            if body.contains(&format!("\"{version}\"")) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

fn wait_for_bind(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if http_get_health(port).is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn stop_daemon(stop_file: &Path) {
    std::fs::write(stop_file, b"stop").unwrap();
}

/// Wait for a path to disappear (the detached helper cleans up just after its
/// own health check — which can trail the test's poll by a beat).
fn wait_for_gone(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    !path.exists()
}

// ---------------------------------------------------------------------------
// Fixture roles (self-exec targets). No-ops under a normal suite run.
// ---------------------------------------------------------------------------

/// Serves `/health` 200 with `FIXTURE_VERSION` until `FIXTURE_STOP_FILE`
/// appears or `FIXTURE_LIFETIME_SECS` elapses. In a normal suite run (no
/// `FIXTURE_PORT` in the environment) this returns immediately.
#[test]
fn fixture_role_health_daemon() {
    let (Ok(port), Ok(version), stop_file, lifetime) = (
        std::env::var("FIXTURE_PORT"),
        std::env::var("FIXTURE_VERSION"),
        std::env::var("FIXTURE_STOP_FILE").ok().map(PathBuf::from),
        std::env::var("FIXTURE_LIFETIME_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300),
    ) else {
        return;
    };
    let port: u16 = port.parse().expect("fixture port");
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("fixture daemon binds API port");
    listener
        .set_nonblocking(true)
        .expect("fixture daemon nonblocking listener");
    let deadline = Instant::now() + Duration::from_secs(lifetime);
    let stop = stop_file
        .as_deref()
        .unwrap_or_else(|| Path::new("/nonexistent"));
    while Instant::now() < deadline && !stop.exists() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let body = format!("{{\"ok\":true,\"data\":{{\"version\":\"{version}\"}}}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                     {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break,
        }
    }
}

/// The old-daemon side of a transactional handoff: binds the API port, then
/// calls `begin_transactional_handoff` (which spawns the real `x0xd` helper
/// from the backup bytes and `_exit`s). Reaching the end of this test is a
/// failure — the handoff must take the process down.
#[test]
fn fixture_role_old_side() {
    let Ok(spec_path) = std::env::var("FIXTURE_HANDOFF_SPEC") else {
        return;
    };
    #[derive(serde::Deserialize)]
    struct Spec {
        port: u16,
        target: PathBuf,
        backup: PathBuf,
        data_dir: PathBuf,
    }
    let spec: Spec = serde_json::from_str(&std::fs::read_to_string(&spec_path).unwrap()).unwrap();
    // Hold the API bind like a real daemon; released when this process exits.
    let _listener = TcpListener::bind(("127.0.0.1", spec.port)).expect("fixture binds API port");
    let handoff = UpgradeHandoff {
        from_version: OLD_VERSION.to_string(),
        to_version: NEW_VERSION.to_string(),
        target_path: spec.target,
        backup_path: spec.backup,
        argv: vec!["x0xd".to_string()],
        cwd: std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        env: Default::default(),
        old_pid: std::process::id(),
        api_addr: format!("127.0.0.1:{}", spec.port).parse().unwrap(),
        started_at: 1_724_000_000,
        mode: RestartMode::TransactionalHandoff,
    };
    let handoff_path = spec.data_dir.join(restart::HANDOFF_FILE_NAME);
    let result = restart::begin_transactional_handoff(handoff, &handoff_path, None);
    panic!("begin_transactional_handoff must not return on success: {result:?}");
}

// ---------------------------------------------------------------------------
// Tests that prove the fix
// ---------------------------------------------------------------------------

/// Design test 3: the new binary exits 1 and never binds. The helper must
/// restore the backup bytes at the target path, respawn the previous binary,
/// and leave `/health` 200 answering the OLD version — no `UPGRADE_FAILED`,
/// handoff file cleaned up, process table not empty.
#[test]
fn handoff_rolls_back_when_new_binary_never_serves() {
    let install = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let port = free_port();

    // The "old daemon": holds the port, dies by itself after FROM seconds.
    let old_stop = install.path().join("stop-old");
    let old_pid = spawn_old_daemon(port, OLD_VERSION, &old_stop, FROM);
    assert!(
        wait_for_bind(port, Duration::from_secs(10)),
        "old daemon must be serving before the handoff"
    );

    let target = install.path().join("x0xd");
    let backup = install.path().join("x0xd.backup");
    write_crash_wrapper(&target);
    let new_stop = install.path().join("stop-restored");
    write_health_wrapper(&backup, port, OLD_VERSION, &new_stop);

    let handoff_path = write_handoff(data.path(), &target, &backup, old_pid, port);
    let status = run_helper(&handoff_path);

    assert!(status.success(), "rollback restart commits: {status:?}");
    assert!(
        !data.path().join(restart::UPGRADE_FAILED_FILE_NAME).exists(),
        "successful rollback must not leave UPGRADE_FAILED"
    );
    assert!(
        !handoff_path.exists(),
        "handoff file must be removed once a process serves /health"
    );
    // Restore moved the backup over the target: the install path now holds
    // the previous binary again.
    assert!(!backup.exists(), "restore consumes the backup file");
    let restored = std::fs::read_to_string(&target).unwrap();
    assert!(
        restored.contains(&format!("FIXTURE_VERSION={OLD_VERSION}")),
        "target must hold the previous binary's bytes"
    );
    assert!(
        wait_for_health_version(port, OLD_VERSION, Duration::from_secs(10)),
        "respawned previous binary must answer /health with the old version"
    );
    // "Process table not empty": the health answer above proves a live
    // process is bound to the port.

    stop_daemon(&new_stop);
}

/// Design test 4: the new binary serves `/health`. The handoff file is
/// removed, the reported version is the target, and the helper exits 0. The
/// backup stays on disk until a later sweep may reclaim it.
#[test]
fn handoff_commits_when_new_binary_serves_health() {
    let install = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let port = free_port();

    let old_stop = install.path().join("stop-old");
    let old_pid = spawn_old_daemon(port, OLD_VERSION, &old_stop, FROM);
    assert!(
        wait_for_bind(port, Duration::from_secs(10)),
        "old daemon must be serving before the handoff"
    );

    let target = install.path().join("x0xd");
    let backup = install.path().join("x0xd.backup");
    let new_stop = install.path().join("stop-new");
    write_health_wrapper(&target, port, NEW_VERSION, &new_stop);
    write_health_wrapper(&backup, port, OLD_VERSION, &old_stop);

    let handoff_path = write_handoff(data.path(), &target, &backup, old_pid, port);
    let status = run_helper(&handoff_path);

    assert!(status.success(), "healthy new binary commits the restart");
    assert!(
        wait_for_health_version(port, NEW_VERSION, Duration::from_secs(10)),
        "the daemon now answering must be the target version"
    );
    assert!(
        !handoff_path.exists(),
        "restart commit deletes the handoff file"
    );
    assert!(
        !data.path().join(restart::UPGRADE_FAILED_FILE_NAME).exists(),
        "no failure artifact on a successful handoff"
    );
    assert!(
        backup.exists(),
        "backup bytes stay on disk until restart commit + later sweep"
    );

    stop_daemon(&new_stop);
}

/// Design test 5: both the new spawn and the rollback spawn fail. The helper
/// must write `UPGRADE_FAILED` (reason, versions, paths) and exit nonzero —
/// never a silent exit 0.
#[test]
fn handoff_writes_upgrade_failed_when_no_respawn_succeeds() {
    let install = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let port = free_port();

    // Old pid already dead; nothing binds the port.
    let target = install.path().join("x0xd");
    let backup = install.path().join("x0xd.backup");
    // Target does not exist: first spawn fails (ENOENT).
    assert!(!target.exists());
    // Backup exists but is not executable: after restore renames it over the
    // target, the rollback spawn fails (EACCES).
    std::fs::write(&backup, b"not an executable - previous binary placeholder").unwrap();

    let handoff_path = write_handoff(data.path(), &target, &backup, dead_pid(), port);
    let status = run_helper(&handoff_path);

    assert!(
        !status.success(),
        "helper must exit nonzero when no respawn succeeded: {status:?}"
    );
    let failed = data.path().join(restart::UPGRADE_FAILED_FILE_NAME);
    let content = std::fs::read_to_string(&failed).unwrap();
    assert!(content.contains("reason:"), "artifact must carry a reason");
    assert!(
        content.contains(&format!("from version: {OLD_VERSION}")),
        "artifact must record the from version: {content}"
    );
    assert!(
        content.contains(&format!("to version: {NEW_VERSION}")),
        "artifact must record the to version: {content}"
    );
    assert!(
        content.contains(&format!("target binary: {}", target.display())),
        "artifact must record the target path: {content}"
    );
    assert!(
        content.contains(&format!("backup binary: {}", backup.display())),
        "artifact must record the backup path: {content}"
    );
    assert!(
        handoff_path.exists(),
        "failed handoff keeps the intent file for diagnosis (UPGRADE_FAILED carries the outcome)"
    );
    // Nothing is serving: the loud artifact is the only acceptable end state.
    assert!(
        !wait_for_bind(port, Duration::from_secs(1)),
        "no process should be bound after a double spawn failure"
    );
}

/// Design I2.4: the old pid hangs past the bound. The helper must abort the
/// new spawn, restore the backup over the target, leave the old process
/// running, and write `UPGRADE_FAILED` — the user stays UP.
#[test]
fn handoff_aborts_when_old_pid_hangs_past_the_bound() {
    let install = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let port = free_port();

    // Old "daemon" holds the port and outlives the release bound.
    let old_stop = install.path().join("stop-old");
    let old_pid = spawn_old_daemon(port, OLD_VERSION, &old_stop, 120);
    assert!(
        wait_for_bind(port, Duration::from_secs(10)),
        "hung old daemon must be serving"
    );

    let target = install.path().join("x0xd");
    let backup = install.path().join("x0xd.backup");
    write_crash_wrapper(&target);
    write_health_wrapper(&backup, port, OLD_VERSION, &old_stop);

    let handoff_path = write_handoff(data.path(), &target, &backup, old_pid, port);
    let status = run_helper(&handoff_path);

    assert!(
        !status.success(),
        "old-pid-hung abort must exit nonzero: {status:?}"
    );
    let failed = data.path().join(restart::UPGRADE_FAILED_FILE_NAME);
    let content = std::fs::read_to_string(&failed).unwrap();
    assert!(
        content.contains("did not exit"),
        "artifact must name the hung old pid: {content}"
    );
    // The old process is left running and still serving.
    assert!(
        wait_for_health_version(port, OLD_VERSION, Duration::from_secs(5)),
        "old process must stay up"
    );
    // Backup restored over the target: the next manual start gets old bytes.
    assert!(!backup.exists());
    let restored = std::fs::read_to_string(&target).unwrap();
    assert!(restored.contains(&format!("FIXTURE_VERSION={OLD_VERSION}")));

    stop_daemon(&old_stop);
}

/// Design I2.1–3 end to end from the old process side: the old daemon writes
/// the handoff file, spawns the REAL `x0xd` helper (from the backup bytes),
/// and exits. The helper then brings up the target and commits on health.
///
/// The backup is a copy of the real `x0xd` binary so the helper runs the
/// genuine `--upgrade-handoff` entrypoint.
#[test]
fn old_process_handoff_spawns_real_helper_and_comes_back_on_target() {
    let install = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    std::fs::create_dir_all(data.path()).unwrap();
    let port = free_port();

    let target = install.path().join("x0xd");
    let backup = install.path().join("x0xd.backup");
    let new_stop = install.path().join("stop-new");
    write_health_wrapper(&target, port, NEW_VERSION, &new_stop);
    std::fs::copy(X0XD_BIN, &backup).unwrap();
    make_executable(&backup);

    #[derive(serde::Serialize)]
    struct Spec {
        port: u16,
        target: PathBuf,
        backup: PathBuf,
        data_dir: PathBuf,
    }
    let spec_path = install.path().join("old-side-spec.json");
    std::fs::write(
        &spec_path,
        serde_json::to_string(&Spec {
            port,
            target: target.clone(),
            backup: backup.clone(),
            data_dir: data.path().to_path_buf(),
        })
        .unwrap(),
    )
    .unwrap();

    let handoff_path = data.path().join(restart::HANDOFF_FILE_NAME);
    let mut old_daemon = Command::new(test_exe())
        .arg(OLD_SIDE_FIXTURE)
        .env("FIXTURE_HANDOFF_SPEC", &spec_path)
        .current_dir(install.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Reap the old process (its parent owns that in production — the shell
    // or systemd); blocking here reaps it the instant it exits, which is what
    // the helper's pid probe needs.
    let old_exit = old_daemon
        .wait()
        .expect("old process must exit after spawning the handoff helper");
    assert!(old_exit.success(), "old process exits 0: {old_exit:?}");

    // Restart commit: the target version serves the same port.
    assert!(
        wait_for_health_version(port, NEW_VERSION, Duration::from_secs(20)),
        "replacement daemon must serve /health with the target version"
    );
    assert!(
        wait_for_gone(&handoff_path, Duration::from_secs(5)),
        "helper deletes the handoff file on commit"
    );
    assert!(
        !data.path().join(restart::UPGRADE_FAILED_FILE_NAME).exists(),
        "no failure artifact on a committed handoff"
    );

    stop_daemon(&new_stop);
}

/// If the helper itself cannot be spawned, the old process must NOT exit
/// (that would be the #261 silent DOWN): it restores the backup, writes
/// `UPGRADE_FAILED`, and keeps running.
#[test]
fn handoff_start_failure_keeps_old_process_alive_and_loud() {
    let install = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();

    let target = install.path().join("x0xd");
    let backup = install.path().join("x0xd.backup");
    // Backup exists but is not executable: the helper (spawned from the
    // backup bytes) cannot start.
    std::fs::write(&backup, b"previous binary (not executable)").unwrap();

    let handoff = UpgradeHandoff {
        from_version: OLD_VERSION.to_string(),
        to_version: NEW_VERSION.to_string(),
        target_path: target.clone(),
        backup_path: backup.clone(),
        argv: vec!["x0xd".to_string()],
        cwd: install.path().to_string_lossy().to_string(),
        env: Default::default(),
        old_pid: std::process::id(),
        api_addr: "127.0.0.1:0".parse().unwrap(),
        started_at: 1_724_000_000,
        mode: RestartMode::TransactionalHandoff,
    };
    let handoff_path = data.path().join(restart::HANDOFF_FILE_NAME);
    let result = restart::begin_transactional_handoff(handoff, &handoff_path, None);

    // Still alive and holding an Err: the silent-DOWN path is closed.
    assert!(
        result.is_err(),
        "helper spawn failure must surface: {result:?}"
    );
    let failed = data.path().join(restart::UPGRADE_FAILED_FILE_NAME);
    let content = std::fs::read_to_string(&failed).unwrap();
    assert!(
        content.contains("helper spawn failed"),
        "artifact must name the helper spawn failure: {content}"
    );
    // Restore moved the (unspawneable) backup over the target: the install
    // path holds the previous bytes again.
    assert!(!backup.exists());
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"previous binary (not executable)"
    );
}
