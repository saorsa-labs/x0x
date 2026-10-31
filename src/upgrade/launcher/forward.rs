//! Dormant-mode passthrough for the installed stable launcher.
//!
//! ADR 0094 §5 binds `x0x-launcher` into the unit `ExecStart` before M2
//! activation. With no launcher-owned trial in flight the launcher has no
//! authority and no child to own, so it becomes the daemon by `exec`:
//! the manager keeps one process with the same signals, exit codes and
//! restart semantics as the previous direct job.
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
    match argv.split_first() {
        Some((executable, args)) => {
            if !std::path::Path::new(executable).is_absolute() {
                return Err(invalid(
                    "daemon executable must be absolute: x0x-launcher /absolute/daemon [args]",
                ));
            }
            Ok(DaemonCommand {
                executable: executable.clone(),
                args: args.to_vec(),
            })
        }
        None => Err(invalid(
            "usage: x0x-launcher /absolute/daemon-executable [daemon args]",
        )),
    }
}

/// Replace this process with the daemon. The return value is the `exec`
/// error; on success this function does not return.
pub(crate) fn exec_daemon(command: &DaemonCommand) -> io::Error {
    use std::os::unix::process::CommandExt;
    let mut daemon = std::process::Command::new(&command.executable);
    daemon.args(&command.args);
    daemon.exec()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let script = format!("printf '%s' \"$$ $0\" >{}", marker.display());
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(NAME)
                .env("X0X_LAUNCHER_FORWARD_FIXTURE", script)
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
