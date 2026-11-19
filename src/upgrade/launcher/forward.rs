//! Dormant-mode passthrough for the installed stable launcher.
//!
//! In ADR 0094 §5 the launcher starts and owns the daemon as a child
//! (manager -> launcher -> child readback). That mode is held until
//! `ENABLED = true`. This passthrough is a provisional, dormant interim
//! mode that ADR 0094 does not describe, and it cannot meet that readback.
//! With no launcher-owned trial in flight the launcher has no authority
//! and no child to own, so it becomes the daemon by `exec`: the manager
//! keeps one process with the same signals, exit codes and restart
//! semantics as the previous direct job.
use super::*;
use std::ffi::OsString;

pub(crate) struct DaemonCommand {
    pub(crate) executable: OsString,
    pub(crate) args: Vec<OsString>,
}

/// Split `[launcher, daemon, daemon args...]`. The daemon path must be
/// absolute — the unit supplies it, and a relative path would be searched
/// on `PATH` — and is never defaulted or resolved by this launcher.
pub(crate) fn daemon_argv(argv: &[OsString]) -> io::Result<DaemonCommand> {
    match contract::daemon_argv(argv).map_err(invalid)? {
        [executable, args @ ..] => Ok(DaemonCommand {
            executable: executable.clone(),
            args: args.to_vec(),
        }),
        [] => Err(invalid("usage: x0x-launcher /absolute/daemon-executable")),
    }
}

/// The M2 launcher marks its private fd-3 boot handoff with this variable
/// (#1375). A passthrough daemon has no launcher permit behind fd 3, so it
/// must not inherit a stale marker. The restart.rs handoff path strips the
/// variable for its children; the dormant launcher does the same.
const LAUNCHER_BOOT_FD_ENV: &str = "X0X_M2_BOOT_FD";

/// Replace this process with the daemon. The return value is the `exec`
/// error; on success this function does not return.
///
/// Dormant passthrough only. It is correct while the engine is held
/// (`ENABLED = false`) and no launcher-owned trial can exist. When
/// `ENABLED` turns `true`, the launcher-owned trial path must run instead;
/// `dormant_passthrough_requires_the_held_engine` fails on that flip until
/// the passthrough is re-tied to it.
pub(crate) fn exec_daemon(command: &DaemonCommand) -> io::Error {
    use std::os::unix::process::CommandExt;
    let mut daemon = std::process::Command::new(&command.executable);
    daemon.args(&command.args);
    daemon.env_remove(LAUNCHER_BOOT_FD_ENV);
    daemon.exec()
}

/// First and longest pause between two `exec` attempts on a missing daemon.
const MISSING_FIRST_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
const MISSING_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The `exec` error of a daemon path that does not exist (now).
fn is_missing(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENOTDIR)
}

/// `exec_daemon`, but a daemon path that does not exist is waited for
/// (#1379). launchd restarts a `KeepAlive` job after every exit, so an
/// exit on a missing daemon (a volume not yet mounted, a package being
/// replaced) is a restart every throttle interval for as long as the path
/// is missing. Waiting keeps one quiet process that execs the daemon as
/// soon as the path is back. The pause doubles from 1 s to 60 s. Any other
/// `exec` error, or a stop, returns the error. The passthrough arms no
/// signal handler, so a stop is SIGTERM's default action; `stop` covers a
/// launcher that armed one.
pub(crate) fn exec_daemon_when_present(
    command: &DaemonCommand,
    mut exec: impl FnMut(&DaemonCommand) -> io::Error,
    mut stop: impl FnMut() -> bool,
    mut pause: impl FnMut(std::time::Duration),
) -> io::Error {
    let mut wait = MISSING_FIRST_WAIT;
    let mut reported = false;
    loop {
        let error = exec(command);
        if !is_missing(&error) || stop() {
            return error;
        }
        if !reported {
            eprintln!(
                "x0x-launcher: daemon {} is missing ({error}); waiting for it",
                std::path::Path::new(&command.executable).display()
            );
            reported = true;
        }
        pause(wait);
        wait = (wait * 2).min(MISSING_MAX_WAIT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn missing_daemon() -> DaemonCommand {
        DaemonCommand {
            executable: "/nonexistent/x0xd".into(),
            args: Vec::new(),
        }
    }

    /// #1379: a missing daemon is waited for with a doubling pause up to
    /// 60 s, and exec'd once it is back; launchd sees one process.
    #[test]
    fn a_missing_daemon_is_waited_for_then_execd() {
        let mut attempts = 0;
        let mut pauses = Vec::new();
        let error = exec_daemon_when_present(
            &missing_daemon(),
            |_| {
                attempts += 1;
                if attempts <= 9 {
                    io::Error::from(io::ErrorKind::NotFound)
                } else {
                    io::Error::from(io::ErrorKind::PermissionDenied)
                }
            },
            || false,
            |wait| pauses.push(wait.as_secs()),
        );
        assert_eq!(attempts, 10);
        assert_eq!(pauses, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    /// A path whose parent is not a directory is missing too.
    #[test]
    fn a_daemon_under_a_non_directory_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let command = DaemonCommand {
            executable: file.join("x0xd").into_os_string(),
            args: Vec::new(),
        };
        let mut attempts = 0;
        exec_daemon_when_present(
            &command,
            |command| {
                attempts += 1;
                if attempts == 1 {
                    exec_daemon(command)
                } else {
                    io::Error::from(io::ErrorKind::PermissionDenied)
                }
            },
            || false,
            |_| {},
        );
        assert_eq!(attempts, 2);
    }

    /// Any other exec error returns at once: the manager's restart decides.
    #[test]
    fn other_exec_errors_return_at_once() {
        let mut pauses = 0;
        let error = exec_daemon_when_present(
            &missing_daemon(),
            |_| io::Error::from(io::ErrorKind::PermissionDenied),
            || false,
            |_| pauses += 1,
        );
        assert_eq!((error.kind(), pauses), (io::ErrorKind::PermissionDenied, 0));
    }

    /// A stop ends the wait.
    #[test]
    fn a_stop_ends_the_wait() {
        let mut checks = 0;
        let error = exec_daemon_when_present(
            &missing_daemon(),
            exec_daemon,
            || {
                checks += 1;
                checks == 3
            },
            |_: Duration| {},
        );
        assert_eq!((error.kind(), checks), (io::ErrorKind::NotFound, 3));
    }

    #[test]
    fn daemon_argv_is_forwarded_untouched() {
        let split = daemon_argv(&[
            "/opt/x0x/x0xd".into(),
            "--config".into(),
            "/etc/x0x/config.toml".into(),
        ])
        .unwrap();
        assert_eq!(split.executable, "/opt/x0x/x0xd");
        assert_eq!(split.args.len(), 2);
        assert_eq!(split.args[0], "--config");
        assert_eq!(split.args[1], "/etc/x0x/config.toml");
    }

    #[test]
    fn missing_daemon_argv_is_a_usage_error() {
        assert!(daemon_argv(&[]).is_err());
    }

    #[test]
    fn relative_daemon_argv_is_refused() {
        assert!(daemon_argv(&["x0xd".into(), "--config".into()]).is_err());
    }

    /// The passthrough is only correct while the engine is held. Flipping
    /// `ENABLED` to `true` must wire the launcher-owned trial path ahead of
    /// the passthrough; this test forces that work instead of a silent skip.
    /// The assert is on a const by design, so the lint is allowed here.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn dormant_passthrough_requires_the_held_engine() {
        assert!(
            !ENABLED,
            "ENABLED = true: wire the launcher-owned trial path before the dormant passthrough"
        );
    }

    /// The installed launcher must become the daemon, not parent it. This
    /// test runs in two roles: without the fixture variable it spawns this
    /// same test as the launcher process; with it, the child execs `/bin/sh`
    /// through `exec_daemon`. The shell keeps the spawned PID and forwards
    /// the daemon argument, which only holds when `exec` replaced the
    /// launcher process image.
    #[test]
    fn the_launcher_process_image_is_replaced_by_exec() {
        const NAME: &str =
            "launcher::forward::tests::the_launcher_process_image_is_replaced_by_exec";
        let Some(script) = std::env::var_os("X0X_LAUNCHER_FORWARD_FIXTURE") else {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("exec-marker");
            // The marker path reaches the shell as a variable, never as
            // shell code, so a `TMPDIR` with spaces cannot split it.
            let script = "printf '%s' \"$$ $0\" >\"$X0X_LAUNCHER_FORWARD_MARKER\"";
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(NAME)
                .env("X0X_LAUNCHER_FORWARD_FIXTURE", script)
                .env("X0X_LAUNCHER_FORWARD_MARKER", &marker)
                .env("X0X_LAUNCHER_FORWARD_ARG", "daemon-argument")
                .spawn()
                .unwrap();
            let launcher_pid = child.id();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{}", output.status);
            assert_eq!(
                std::fs::read_to_string(&marker).unwrap(),
                format!("{launcher_pid} daemon-argument")
            );
            return;
        };
        let argument = std::env::var_os("X0X_LAUNCHER_FORWARD_ARG").unwrap_or_default();
        let command = DaemonCommand {
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), script, argument],
        };
        let error = exec_daemon(&command);
        panic!("exec must not return: {error}");
    }
}
