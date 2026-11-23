//! The running daemon's own participant entry for the prepare producer
//! (#2012), read from the live process so that the arm handler
//! (`server::upgrade_flush::admit`) accepts it: the executable it compares
//! (`apply::current_binary_path`, canonical), its pid, its process start
//! (`upgrade_flush::process_start`) and the boot (`boot_identity`), each
//! from the same function the handler uses.
//!
//! Library only: the launcher never observes a daemon this way. The apply
//! path calls it only through `producer`, whose gate stays closed while
//! `launcher_contract::LAUNCHER_ENABLED` is false.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use super::journal::{Participant, RestartBinding};

/// Environment variables set for one start only, by the launcher
/// (`X0X_M2_BOOT_FD`) or by the service manager (systemd's per-invocation
/// and socket, notify, watchdog and trigger variables). They are never part
/// of the captured environment: the launcher starts the candidate with the
/// captured one, and an old value would name the previous start (#2012,
/// #2115 review).
pub(crate) const PER_START_ENV: &[&str] = &[
    "X0X_M2_BOOT_FD",
    "INVOCATION_ID",
    "JOURNAL_STREAM",
    "NOTIFY_SOCKET",
    "LISTEN_PID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
    "MAINPID",
    "MANAGERPID",
    "SYSTEMD_EXEC_PID",
    "WATCHDOG_PID",
    "WATCHDOG_USEC",
    "TRIGGER_UNIT",
    "TRIGGER_PATH",
    "TRIGGER_TIMER_REALTIME_USEC",
    "TRIGGER_TIMER_MONOTONIC_USEC",
    "MONITOR_SERVICE_RESULT",
    "MONITOR_EXIT_CODE",
    "MONITOR_EXIT_STATUS",
    "MONITOR_INVOCATION_ID",
    "MONITOR_UNIT",
];

/// The captured environment: `vars` without the per-start variables. A
/// non-UTF-8 variable is refused, since the journal stores text.
pub(crate) fn captured_env(
    vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> io::Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for (key, value) in vars {
        let (Ok(key), Ok(value)) = (key.into_string(), value.into_string()) else {
            return Err(refused("a daemon environment variable is not UTF-8"));
        };
        if !PER_START_ENV.contains(&key.as_str()) {
            env.insert(key, value);
        }
    }
    Ok(env)
}

fn refused(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.into())
}

/// The running daemon as one participant of the plan. `argv[0]` is the
/// executable path (the process's own argv0 may be relative); the rest is
/// the process's arguments. The environment is the process's own, without
/// the per-start launcher variables; the launcher starts the candidate
/// with exactly this environment. A non-UTF-8 argument or variable is
/// refused, since the journal stores text.
pub(crate) fn observe_this_daemon(
    instance_id: &str,
    data_root: &Path,
    identity_root: &Path,
    restart: RestartBinding,
) -> io::Result<Participant> {
    // Canonical, as the arm handler compares it (#2065 review): a daemon
    // started through a symlink is recorded by the file it runs.
    let executable = super::apply::current_binary_path()
        .map_err(io::Error::other)?
        .canonicalize()?;
    let executable_text = executable
        .to_str()
        .ok_or_else(|| refused("the daemon executable path is not UTF-8"))?
        .to_owned();
    let mut argv = vec![executable_text];
    for argument in std::env::args_os().skip(1) {
        argv.push(
            argument
                .into_string()
                .map_err(|_| refused("a daemon argument is not UTF-8"))?,
        );
    }
    let env = captured_env(std::env::vars_os())?;
    Ok(Participant {
        instance_id: instance_id.to_owned(),
        executable,
        data_root: data_root.canonicalize()?,
        identity_root: identity_root.canonicalize()?,
        argv,
        cwd: std::env::current_dir()?.canonicalize()?,
        env,
        restart,
        old_pid: Some(std::process::id()),
        process_start: Some(crate::server::upgrade_flush::process_start()?),
        boot_id: super::shutdown_flush::boot_identity()?,
        was_running: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upgrade::journal::RestartOwner;

    #[test]
    fn this_daemon_is_observed_as_the_arm_handler_checks_it() {
        let dir = tempfile::tempdir().unwrap();
        let restart = RestartBinding {
            mode: RestartOwner::SupervisedExit,
            supervised_exit_code: None,
            supervision_signal: None,
            launchd_verified: None,
            systemd_verified: None,
            launcher: None,
        };
        let observed = observe_this_daemon("alice", dir.path(), dir.path(), restart).unwrap();
        assert_eq!(observed.old_pid, Some(std::process::id()));
        assert_eq!(
            observed.process_start,
            Some(crate::server::upgrade_flush::process_start().unwrap())
        );
        assert_eq!(
            observed.boot_id,
            crate::upgrade::shutdown_flush::boot_identity().unwrap()
        );
        assert_eq!(
            observed.executable,
            crate::upgrade::apply::current_binary_path()
                .unwrap()
                .canonicalize()
                .unwrap()
        );
        assert_eq!(observed.argv[0], observed.executable.to_str().unwrap());
        assert_eq!(observed.data_root, dir.path().canonicalize().unwrap());
        assert!(!observed.env.contains_key("X0X_M2_BOOT_FD"));
    }

    /// #2012: no per-start variable of the launcher or of systemd reaches
    /// the captured environment; every other variable does.
    #[test]
    fn per_start_variables_are_left_out_of_the_captured_environment() {
        let mut vars: Vec<(std::ffi::OsString, std::ffi::OsString)> = PER_START_ENV
            .iter()
            .map(|key| ((*key).into(), "stale".into()))
            .collect();
        vars.push(("X0X_LOG".into(), "info".into()));
        let env = captured_env(vars).unwrap();
        assert_eq!(env.len(), 1, "{:?}", env.keys().collect::<Vec<_>>());
        assert_eq!(env.get("X0X_LOG").map(String::as_str), Some("info"));
        for key in [
            "INVOCATION_ID",
            "JOURNAL_STREAM",
            "NOTIFY_SOCKET",
            "LISTEN_FDS",
            "X0X_M2_BOOT_FD",
        ] {
            assert!(PER_START_ENV.contains(&key), "{key}");
        }
    }
}
