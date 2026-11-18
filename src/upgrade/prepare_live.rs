//! The running daemon's own participant entry for the prepare producer
//! (#2012), read from the live process so that the arm handler
//! (`server::upgrade_flush::admit`) accepts it: the executable it compares
//! (`apply::current_binary_path`), its pid, its process start
//! (`upgrade_flush::process_start`) and the boot (`boot_identity`), each
//! from the same function the handler uses.
//!
//! Library only: the launcher never observes a daemon this way. Dormant:
//! no apply path calls it yet.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use super::journal::{Participant, RestartBinding};

/// Environment variables the launcher sets for one child start; they are
/// never part of the captured environment.
const PER_START_ENV: [&str; 1] = ["X0X_M2_BOOT_FD"];

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
    let executable = super::apply::current_binary_path().map_err(io::Error::other)?;
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
    let mut env = BTreeMap::new();
    for (key, value) in std::env::vars_os() {
        let (Ok(key), Ok(value)) = (key.into_string(), value.into_string()) else {
            return Err(refused("a daemon environment variable is not UTF-8"));
        };
        if !PER_START_ENV.contains(&key.as_str()) {
            env.insert(key, value);
        }
    }
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
            crate::upgrade::apply::current_binary_path().unwrap()
        );
        assert_eq!(observed.argv[0], observed.executable.to_str().unwrap());
        assert_eq!(observed.data_root, dir.path().canonicalize().unwrap());
        assert!(!observed.env.contains_key("X0X_M2_BOOT_FD"));
    }
}
