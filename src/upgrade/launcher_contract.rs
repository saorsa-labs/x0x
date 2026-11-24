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
//! x0x-launcher --host-root <abs data_root> --instance <id> [--plan-anchor <abs path>] -- /abs/x0xd [daemon args...]
//! ```
//!
//! `--plan-anchor` names the root-owned plan anchor (#2012, B4); a trial
//! needs it, and a trial-form start without it can only pass through.
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Basename of the stable launcher executable.
pub const LAUNCHER_BASENAME: &str = "x0x-launcher";

/// The one switch that keeps the launcher and the prepare producer dormant
/// (#2012). The launcher's engine and the daemon's producer gate both read
/// it, so a build either has both or neither.
pub const LAUNCHER_ENABLED: bool = false;

/// `x0x-launcher --capabilities` (the only argument) prints the
/// capabilities of this launcher, one per line, and exits 0. It starts
/// nothing. A launcher older than this flag exits 64 (usage), since
/// `--capabilities` is not an absolute daemon path.
pub const CAPABILITIES_FLAG: &str = "--capabilities";

/// The capability a launcher answers when it reads the host journal and
/// runs trials (ADR 0094 §5). The producer writes a journal only for a
/// launcher that answers it.
pub const TRIAL_CAPABILITY: &str = "trial-v1";

/// What `--capabilities` prints: nothing while the launcher is dormant.
pub fn capabilities() -> &'static [&'static str] {
    if LAUNCHER_ENABLED {
        &[TRIAL_CAPABILITY]
    } else {
        &[]
    }
}

/// Where a trial-form launcher looks for its trial authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialArgs {
    pub host_root: PathBuf,
    pub instance: String,
    /// The root-owned plan anchor (#2012, B4). Without it the launcher
    /// never gives a trial.
    pub plan_anchor: Option<PathBuf>,
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
const TRIAL_USAGE: &str = "usage: x0x-launcher --host-root /absolute/data-root --instance ID \
                           [--plan-anchor /absolute/anchor] -- /absolute/daemon [daemon args]";

/// Parse a launcher argv (after the launcher's own name). The error is the
/// usage message; the launcher exits 64 on it.
pub fn parse_launcher_argv<S: AsRef<OsStr>>(argv: &[S]) -> Result<LauncherArgv<'_, S>, String> {
    if argv.first().map(AsRef::as_ref) != Some(OsStr::new("--host-root")) {
        return Ok(LauncherArgv {
            trial: None,
            daemon: daemon_argv(argv)?,
        });
    }
    let [_, root, flag, instance, after @ ..] = argv else {
        return Err(TRIAL_USAGE.to_string());
    };
    let (plan_anchor, separator, rest) = match after {
        [anchor_flag, anchor, separator, rest @ ..] if anchor_flag.as_ref() == "--plan-anchor" => {
            let anchor = PathBuf::from(anchor.as_ref());
            if !anchor.is_absolute() {
                return Err("--plan-anchor must be absolute".to_string());
            }
            (Some(anchor), separator, rest)
        }
        [separator, rest @ ..] => (None, separator, rest),
        [] => return Err(TRIAL_USAGE.to_string()),
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
            plan_anchor,
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
    /// The refusing launcher's start time ([`process_start`]). With `pid`
    /// it names one process, so a reused pid is not read as a holding
    /// launcher (#2019 review).
    pub process_start: u64,
    /// When it refused, in milliseconds since the Unix epoch.
    pub at_unix_ms: u64,
}

pub const REFUSAL_SCHEMA: u32 = 1;

/// The first word of a refusal reason when the host journal in the data
/// root belongs to another install pair than this launcher's (#2012): the
/// data root moved to another install, or two installs share it. `x0x
/// doctor` gives the remedy for it.
pub const REFUSAL_OTHER_INSTALL: &str = "other-install-journal";

/// The start time of process `pid`, fixed for the life of the process: on
/// Linux the `starttime` field of `/proc/<pid>/stat` (clock ticks since
/// boot), on macOS the libproc start time in microseconds since the epoch.
/// With the pid and the boot it names one process.
#[cfg(target_os = "linux")]
pub fn process_start(pid: u32) -> std::io::Result<u64> {
    let invalid = |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .ok_or_else(|| invalid("bad process stat"))?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| invalid("missing process start"))?
        .parse()
        .map_err(|_| invalid("bad process start"))
}

/// See the Linux form. A zombie still has its start time.
#[cfg(target_os = "macos")]
pub fn process_start(pid: u32) -> std::io::Result<u64> {
    let invalid = |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
    let raw_pid = i32::try_from(pid).map_err(|_| invalid("pid out of range"))?;
    // SAFETY: proc_bsdinfo holds integers and fixed byte arrays; zero is a
    // valid value for each field.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = i32::try_from(std::mem::size_of_val(&info)).map_err(|_| invalid("size"))?;
    // SAFETY: proc_pidinfo writes at most `size` bytes into the owned,
    // sized `info` buffer and reads only the arguments passed. The nonzero
    // arg asks libproc for zombies too.
    let received = unsafe {
        libc::proc_pidinfo(
            raw_pid,
            libc::PROC_PIDTBSDINFO,
            1,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if received == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if received != size || info.pbi_pid != pid {
        return Err(invalid("incomplete process status"));
    }
    info.pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|micros| micros.checked_add(info.pbi_start_tvusec))
        .ok_or_else(|| invalid("process start overflow"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_start(_pid: u32) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process start time requires Linux or macOS",
    ))
}

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
                plan_anchor: None,
            })
        );
        assert_eq!(trial.daemon, ["/usr/bin/x0xd"]);
        let anchored = parse_launcher_argv(&[
            "--host-root",
            "/var/lib/x0x",
            "--instance",
            "alice",
            "--plan-anchor",
            "/etc/x0x/launcher/x0xd.anchor.json",
            "--",
            "/usr/bin/x0xd",
            "--name",
            "a",
        ])
        .unwrap();
        assert_eq!(
            anchored.trial.and_then(|trial| trial.plan_anchor),
            Some("/etc/x0x/launcher/x0xd.anchor.json".into())
        );
        assert_eq!(anchored.daemon, ["/usr/bin/x0xd", "--name", "a"]);
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
            &[
                "--host-root",
                "/r",
                "--instance",
                "a",
                "--plan-anchor",
                "rel",
                "--",
                "/x0xd",
            ][..],
            &[
                "--host-root",
                "/r",
                "--instance",
                "a",
                "--plan-anchor",
                "/a",
                "/x0xd",
            ][..],
            &[
                "--host-root",
                "/r",
                "--instance",
                "a",
                "--plan-anchor",
                "/a",
                "--",
            ][..],
            &["--host-root", "/r", "--instance", "a", "--plan-anchor"][..],
            &["--host-root", "/r", "--instance", "a"][..],
        ] {
            assert!(parse_launcher_argv(argv).is_err(), "{argv:?}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn process_start_names_one_process() {
        let own = process_start(std::process::id()).unwrap();
        assert_eq!(process_start(std::process::id()).unwrap(), own);
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let other = process_start(child.id()).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(process_start(child.id()).is_err());
        assert!(other >= own);
    }
}
