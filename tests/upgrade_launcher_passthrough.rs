#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Dormant-passthrough checks for the installed launcher binary. These tests
//! spawn only the launcher and a shell-script daemon; they never start a real
//! daemon, bind a socket, or contact the network.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// 75 is EX_TEMPFAIL: the manager restarts the job, as for a direct unit
/// whose daemon cannot exec.
const EXIT_TEMPFAIL: i32 = 75;
/// 64 is EX_USAGE: the unit supplied no daemon to run.
const EXIT_USAGE: i32 = 64;

fn stub_daemon(root: &TempDir) -> PathBuf {
    let daemon = root.path().join("x0xd");
    let log = root.path().join("daemon.log");
    let mut file = std::fs::File::create(&daemon).unwrap();
    writeln!(
        file,
        "#!/bin/sh\nprintf '%s' \"$0 $$ $*\" >{}",
        log.display()
    )
    .unwrap();
    drop(file);
    let mut permissions = std::fs::metadata(&daemon).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&daemon, permissions).unwrap();
    daemon
}

#[test]
fn dormant_launcher_runs_the_daemon_as_the_same_process() {
    let root = tempfile::tempdir().unwrap();
    let daemon = stub_daemon(&root);
    let mut child = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(&daemon)
        .arg("--config")
        .arg("/etc/x0x/config.toml")
        .spawn()
        .unwrap();
    let launcher_pid = child.id();
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}");
    // The shell's own PID is the spawned PID and its argument list is
    // forwarded, which only holds when the launcher exec'd the daemon
    // instead of parenting it.
    assert_eq!(
        std::fs::read_to_string(root.path().join("daemon.log")).unwrap(),
        format!(
            "{} {launcher_pid} --config /etc/x0x/config.toml",
            daemon.display()
        )
    );
}

#[test]
fn launcher_without_daemon_argv_exits_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(EXIT_USAGE));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage"), "{stderr}");
}

#[test]
fn launcher_reports_tempfail_when_the_daemon_cannot_exec() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(root.path().join("absent-daemon"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(EXIT_TEMPFAIL));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot exec"), "{stderr}");
}
