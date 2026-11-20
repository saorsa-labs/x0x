#![cfg(all(unix, feature = "m2-launcher"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Dormant-passthrough checks for the installed launcher binary. These tests
//! spawn only the launcher and a shell-script daemon; they never start a real
//! daemon, bind a socket, or contact the network.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

/// 75 is EX_TEMPFAIL: the manager restarts the job, as for a direct unit
/// whose daemon cannot exec. On macOS a missing daemon is waited for
/// instead (#1379); any other exec error still exits 75.
const EXIT_TEMPFAIL: i32 = 75;
/// 64 is EX_USAGE: the unit supplied no daemon to run.
const EXIT_USAGE: i32 = 64;

/// Write the stub daemon in one step, so the file is closed before any
/// process execs it; a file still open for writing fails with ETXTBSY.
/// The stub reports `$0`, its PID, one bracketed line per argument
/// (`"$@"`, never `$*`, so argument boundaries stay visible), the boot
/// marker variable and the probe variable, then exits with `exit`.
/// The log goes to `daemon.log` beside the stub, named from `$0` inside a
/// quoted expansion, so no path is spliced into the shell code and a
/// `TMPDIR` with spaces or shell metacharacters cannot split it.
fn stub_daemon(root: &TempDir, exit: u8) -> std::path::PathBuf {
    let daemon = root.path().join("x0xd");
    let script = format!(
        "#!/bin/sh\n\
         {{\n\
         \x20 printf '%s\\n' \"$0\"\n\
         \x20 printf '%s\\n' \"$$\"\n\
         \x20 for argument in \"$@\"; do printf '[%s]\\n' \"$argument\"; done\n\
         \x20 printf 'boot-fd=%s\\n' \"${{X0X_M2_BOOT_FD-unset}}\"\n\
         \x20 printf 'probe=%s\\n' \"${{X0X_PASSTHROUGH_PROBE-unset}}\"\n\
         \x20 exit {exit}\n\
         }} >\"${{0%/*}}/daemon.log\"\n",
        exit = exit,
    );
    std::fs::write(&daemon, script).unwrap();
    let mut permissions = std::fs::metadata(&daemon).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&daemon, permissions).unwrap();
    daemon
}

fn read_log(root: &TempDir) -> String {
    String::from_utf8_lossy(&std::fs::read(root.path().join("daemon.log")).unwrap()).into_owned()
}

#[test]
fn dormant_launcher_runs_the_daemon_as_the_same_process() {
    let root = tempfile::tempdir().unwrap();
    let daemon = stub_daemon(&root, 0);
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
    // forwarded, one bracketed line per argument. Both only hold when the
    // launcher exec'd the daemon instead of parenting it.
    assert_eq!(
        read_log(&root),
        format!(
            "{daemon}\n{launcher_pid}\n[--config]\n[/etc/x0x/config.toml]\n\
             boot-fd=unset\nprobe=unset\n",
            daemon = daemon.display()
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
fn relative_daemon_path_exits_usage_at_the_binary_level() {
    let output = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg("x0xd")
        .arg("--config")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(EXIT_USAGE));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("absolute"), "{stderr}");
}

#[cfg(not(target_os = "macos"))]
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

/// Bounds every wait on a launcher that waits for its daemon, so a
/// regression fails the test instead of hanging it.
#[cfg(target_os = "macos")]
const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(20);

/// Start the launcher on a daemon path that does not exist yet and wait
/// for its "is missing" line (#1379: on macOS it waits, launchd would
/// restart an exit).
#[cfg(target_os = "macos")]
fn launcher_waiting_for(daemon: &std::path::Path) -> std::process::Child {
    use std::io::BufRead;
    let mut child = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(daemon)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (lines, read) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr).lines() {
            if lines.send(line.unwrap_or_default()).is_err() {
                break;
            }
        }
    });
    match read.recv_timeout(WAIT_BOUND) {
        Ok(line) if line.contains("is missing") && line.contains("waiting") => child,
        other => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("expected the launcher's wait line, got {other:?}");
        }
    }
}

/// The child's exit status, or a kill and a failure after `WAIT_BOUND`.
#[cfg(target_os = "macos")]
fn exit_within_bound(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + WAIT_BOUND;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the launcher did not exit within {WAIT_BOUND:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn launcher_waits_for_a_missing_daemon_and_then_runs_it() {
    let root = tempfile::tempdir().unwrap();
    let daemon = root.path().join("x0xd");
    let mut child = launcher_waiting_for(&daemon);
    assert!(child.try_wait().unwrap().is_none(), "the launcher exited");
    stub_daemon(&root, 42);
    // The next attempt (after the 1 s pause) execs the daemon, so its own
    // exit status reaches the manager.
    assert_eq!(exit_within_bound(&mut child).code(), Some(42));
}

/// #1379: only a missing daemon is waited for. A daemon that exists but
/// cannot be executed (mode 000, `EACCES`) still exits 75 on macOS.
#[cfg(target_os = "macos")]
#[test]
fn launcher_reports_tempfail_when_an_existing_daemon_cannot_exec() {
    let root = tempfile::tempdir().unwrap();
    let daemon = stub_daemon(&root, 0);
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(&daemon)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let status = exit_within_bound(&mut child);
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert_eq!(status.code(), Some(EXIT_TEMPFAIL), "{stderr}");
    assert!(stderr.contains("cannot exec"), "{stderr}");
}

#[cfg(target_os = "macos")]
#[test]
fn a_stop_ends_the_launchers_wait_for_a_missing_daemon() {
    use std::os::unix::process::ExitStatusExt;
    let root = tempfile::tempdir().unwrap();
    let mut child = launcher_waiting_for(&root.path().join("absent-daemon"));
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    assert_eq!(exit_within_bound(&mut child).signal(), Some(libc::SIGTERM));
}

#[test]
fn the_daemon_exit_code_passes_through() {
    let root = tempfile::tempdir().unwrap();
    let daemon = stub_daemon(&root, 42);
    let status = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(&daemon)
        .status()
        .unwrap();
    // The launcher exec'd the daemon, so the manager sees the daemon's own
    // exit status, not a launcher translation of it.
    assert_eq!(status.code(), Some(42));
}

#[test]
fn the_environment_reaches_the_daemon() {
    let root = tempfile::tempdir().unwrap();
    let daemon = stub_daemon(&root, 0);
    let output = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(&daemon)
        .env("X0X_PASSTHROUGH_PROBE", "reached")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output.status);
    assert!(read_log(&root).contains("probe=reached\n"));
}

/// The launcher owns the fd-3 boot marker. The daemon it starts must not
/// see a stale `X0X_M2_BOOT_FD`, exactly like the restart.rs handoff path.
#[test]
fn dormant_launcher_strips_the_boot_fd_marker() {
    let root = tempfile::tempdir().unwrap();
    let daemon = stub_daemon(&root, 0);
    let output = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(&daemon)
        .env("X0X_M2_BOOT_FD", "3")
        .env("X0X_PASSTHROUGH_PROBE", "kept")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output.status);
    let log = read_log(&root);
    assert!(log.contains("boot-fd=unset\n"), "{log}");
    // Only the boot marker is stripped; the rest of the environment passes.
    assert!(log.contains("probe=kept\n"), "{log}");
}

/// Non-UTF-8 argv must survive the exec as raw OS strings, with argument
/// boundaries intact. The log is compared as bytes, and the stub prints
/// one line per argument, so a `$*`-style merge cannot pass.
#[test]
fn non_utf8_argv_survives_exec_with_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let daemon = stub_daemon(&root, 0);
    let mut child = Command::new(env!("CARGO_BIN_EXE_x0x-launcher"))
        .arg(&daemon)
        .arg(OsString::from_vec(b"--path=\xff/".to_vec()))
        .arg("two words")
        .arg(OsString::from_vec(b"\xfe\xed\xfa\xce".to_vec()))
        .spawn()
        .unwrap();
    let launcher_pid = child.id();
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}");
    let mut expected = Vec::new();
    expected.extend_from_slice(daemon.display().to_string().as_bytes());
    expected.push(b'\n');
    expected.extend_from_slice(launcher_pid.to_string().as_bytes());
    expected.push(b'\n');
    expected.extend_from_slice(b"[--path=\xff/]\n[two words]\n[\xfe\xed\xfa\xce]\n");
    expected.extend_from_slice(b"boot-fd=unset\nprobe=unset\n");
    assert_eq!(
        std::fs::read(root.path().join("daemon.log")).unwrap(),
        expected
    );
}
