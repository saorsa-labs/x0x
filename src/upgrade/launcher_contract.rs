//! The stable launcher's contract with the rest of x0x, in one file that
//! both the `x0x` library and the dormant launcher engine compile (the
//! engine includes it by path). One parser, so that a launchd job which the
//! `x0x autostart --repair` classifier or the upgrade-time readback accepts
//! is a job the launcher accepts (#2016 review); and one refusal record, so
//! that `x0x doctor` can show why the launcher will not start the daemon.
//!
//! The argv contract (provisional and dormant, frozen before `ENABLED`):
//!
//! ```text
//! x0x-launcher /abs/x0xd [daemon args...]
//! x0x-launcher --host-root <abs data_root> --instance <id> -- /abs/x0xd [daemon args...]
//! ```
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Basename of the stable launcher executable.
pub const LAUNCHER_BASENAME: &str = "x0x-launcher";

/// Where a trial-form launcher looks for its trial authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialArgs {
    pub host_root: PathBuf,
    pub instance: String,
}

/// A launcher argv (after the launcher's own name) that the launcher
/// accepts: the trial authority it names, if any, and the daemon argv.
#[derive(Debug)]
pub struct LauncherArgv<'a, S> {
    pub trial: Option<TrialArgs>,
    /// The daemon's absolute executable, then its arguments.
    pub daemon: &'a [S],
}

const PLAIN_USAGE: &str = "usage: x0x-launcher /absolute/daemon-executable [daemon args]";
const TRIAL_USAGE: &str = "usage: x0x-launcher --host-root /absolute/data-root --instance ID -- \
                           /absolute/daemon [daemon args]";

/// Parse a launcher argv (after the launcher's own name). The error is the
/// usage message; the launcher exits 64 on it.
pub fn parse_launcher_argv<S: AsRef<OsStr>>(argv: &[S]) -> Result<LauncherArgv<'_, S>, String> {
    if argv.first().map(AsRef::as_ref) != Some(OsStr::new("--host-root")) {
        return Ok(LauncherArgv {
            trial: None,
            daemon: daemon_argv(argv)?,
        });
    }
    let [_, root, flag, instance, separator, rest @ ..] = argv else {
        return Err(TRIAL_USAGE.to_string());
    };
    if flag.as_ref() != "--instance" || separator.as_ref() != "--" {
        return Err(TRIAL_USAGE.to_string());
    }
    let host_root = PathBuf::from(root.as_ref());
    if !host_root.is_absolute() {
        return Err("--host-root must be absolute".to_string());
    }
    let instance = instance
        .as_ref()
        .to_str()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
        // `.` and `..` would name a directory if the id were ever joined to
        // a path; the character set already excludes any separator.
        .filter(|id| *id != "." && *id != "..")
        .ok_or_else(|| "--instance must be 1-128 of [A-Za-z0-9._-], not . or ..".to_string())?
        .to_owned();
    Ok(LauncherArgv {
        trial: Some(TrialArgs {
            host_root,
            instance,
        }),
        daemon: daemon_argv(rest)?,
    })
}

/// The daemon argv: an absolute executable, then its arguments.
pub fn daemon_argv<S: AsRef<OsStr>>(argv: &[S]) -> Result<&[S], String> {
    match argv.first() {
        Some(executable) if Path::new(executable.as_ref()).is_absolute() => Ok(argv),
        Some(_) => {
            Err("daemon executable must be absolute: x0x-launcher /absolute/daemon [args]".into())
        }
        None => Err(PLAIN_USAGE.to_string()),
    }
}

/// The record a trial-form launcher leaves in its host root when it
/// refuses to start the daemon for a reason no restart changes (exit 78,
/// or the macOS hold). The next launcher start removes it. `x0x doctor`
/// reads it while the daemon is unreachable.
pub const REFUSAL_FILE_NAME: &str = "launcher-refusal.json";

/// Upper bound on the refusal record's size when read.
pub const MAX_REFUSAL_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherRefusal {
    pub schema: u32,
    /// Why the launcher refused.
    pub reason: String,
    /// The refusing launcher's pid. On macOS it holds until a stop
    /// (launchd would restart an exit), so a live pid is a holding launcher.
    pub pid: u32,
    /// When it refused, in milliseconds since the Unix epoch.
    pub at_unix_ms: u64,
}

pub const REFUSAL_SCHEMA: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_trial_forms_parse() {
        let plain = parse_launcher_argv(&["/usr/bin/x0xd", "--name", "a"]).unwrap();
        assert!(plain.trial.is_none());
        assert_eq!(plain.daemon, ["/usr/bin/x0xd", "--name", "a"]);
        let trial = parse_launcher_argv(&[
            "--host-root",
            "/var/lib/x0x",
            "--instance",
            "alice",
            "--",
            "/usr/bin/x0xd",
        ])
        .unwrap();
        assert_eq!(
            trial.trial,
            Some(TrialArgs {
                host_root: "/var/lib/x0x".into(),
                instance: "alice".into(),
            })
        );
        assert_eq!(trial.daemon, ["/usr/bin/x0xd"]);
    }

    #[test]
    fn malformed_argv_is_refused() {
        for argv in [
            &[][..],
            &["x0xd"][..],
            &["--host-root", "rel", "--instance", "a", "--", "/x0xd"][..],
            &["--host-root", "/r", "--instance", "..", "--", "/x0xd"][..],
            &["--host-root", "/r", "--instance", "a/b", "--", "/x0xd"][..],
            &["--host-root", "/r", "--instance", "a", "/x0xd"][..],
            &["--host-root", "/r", "--instance", "a", "--"][..],
            &["--host-root", "/r", "--instance", "a", "--", "x0xd"][..],
        ] {
            assert!(parse_launcher_argv(argv).is_err(), "{argv:?}");
        }
    }
}
