//! Only this owner starts, signals and waits for its candidate.
use super::*;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{net::UnixStream, process::CommandExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

const BOOT_FD: &str = "X0X_M2_BOOT_FD";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    record: journal::BootRecord,
    parent: Identity,
    root: PathBuf,
    executable: PathBuf,
    sha256: [u8; 32],
    version: String,
    argv: Vec<String>,
    cwd: PathBuf,
}

pub(super) struct Owned {
    child: Child,
    identity: Identity,
    channel: Option<UnixStream>,
    booted: bool,
}

impl Owned {
    pub(super) fn spawn(
        trial: &mut Trial,
        path: &Path,
        participant: &journal::Participant,
        version: &str,
        sha256: [u8; 32],
    ) -> io::Result<Option<Self>> {
        let clock = Clock::now()?;
        if trial.phase != Phase::Booting {
            return Err(invalid("attempt not reserved"));
        }
        let (mut parent, channel) = UnixStream::pair()?;
        let fd = channel.as_raw_fd();
        let mut command = Command::new(&participant.executable);
        command
            .args(participant.argv.iter().skip(1))
            .arg0(
                participant
                    .argv
                    .first()
                    .ok_or_else(|| invalid("missing argv"))?,
            )
            .current_dir(&participant.cwd)
            .env_clear()
            .envs(&participant.env)
            .env(BOOT_FD, "3")
            .stdin(Stdio::null());
        // SAFETY: the child closure only calls async-signal-safe descriptor
        // operations. The owned stream keeps fd valid until spawn completes.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                trial.cause = Some(format!("exec failed: {error}"));
                return Ok(None);
            }
        };
        drop(channel);
        let setup = (|| -> io::Result<Identity> {
            let child_identity = identity(child.id())?;
            trial.child = Some(child_identity.clone());
            trial.save(path)?;
            let permit = Permit {
                record: journal::BootRecord {
                    schema_version: 1,
                    record_kind: "boot".into(),
                    transaction_id: trial.binding.transaction.clone(),
                    generation: trial.binding.generation,
                    instance_id: trial.instance.clone(),
                    attempt: trial.attempts,
                    pid: child_identity.pid,
                    process_start: child_identity.start,
                    boot_id: child_identity.boot.clone(),
                    started_at_ns: clock.ms.saturating_mul(1_000_000),
                    deadline_ns: trial.deadline_ms.saturating_mul(1_000_000),
                },
                parent: identity(std::process::id())?,
                root: participant.data_root.clone(),
                executable: participant.executable.clone(),
                sha256,
                version: version.into(),
                argv: participant.argv.clone(),
                cwd: participant.cwd.clone(),
            };
            parent.set_write_timeout(Some(Duration::from_secs(1)))?;
            let mut bytes = serde_json::to_vec(&permit)?;
            bytes.push(b'\n');
            parent.write_all(&bytes)?;
            parent.set_nonblocking(true)?;
            Ok(child_identity)
        })();
        match setup {
            Ok(identity) => Ok(Some(Self {
                child,
                identity,
                channel: Some(parent),
                booted: false,
            })),
            // A candidate that dies before it takes its permit (EPIPE) or
            // that this OS cannot hold in custody is a failed attempt: the
            // caller charges it and retries. Only a failed reap is final.
            Err(error) => {
                if let Err(reap) = stop_and_reap(&mut child) {
                    let error = invalid(format!("{error}; reap also failed: {reap}"));
                    return Err(trial.recovery_failed(path, error));
                }
                trial.child = None;
                trial.cause = Some(format!("boot setup failed: {error}"));
                Ok(None)
            }
        }
    }

    pub(super) fn poll_boot(&mut self) -> io::Result<bool> {
        if self.booted {
            return Ok(true);
        }
        let mut byte = [0];
        match self
            .channel
            .as_mut()
            .ok_or_else(|| invalid("boot channel missing"))?
            .read(&mut byte)
        {
            Ok(1) if byte == [1] => {
                self.booted = true;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            _ => Err(invalid("candidate did not acknowledge its boot barrier")),
        }
    }

    pub(super) fn exited(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    pub(super) fn restored(p: &journal::Participant) -> io::Result<Self> {
        let mut child = Command::new(&p.executable)
            .arg0(p.argv.first().ok_or_else(|| invalid("missing argv"))?)
            .args(p.argv.iter().skip(1))
            .env_clear()
            .envs(&p.env)
            .env_remove(BOOT_FD)
            .current_dir(&p.cwd)
            .stdin(Stdio::null())
            .spawn()?;
        match identity(child.id()) {
            Ok(identity) => Ok(Self {
                child,
                identity,
                channel: None,
                booted: true,
            }),
            Err(error) => {
                stop_and_reap(&mut child)?;
                Err(error)
            }
        }
    }

    pub(super) fn identity(&self) -> &Identity {
        &self.identity
    }

    pub(super) fn reap(mut self) -> io::Result<Identity> {
        stop_and_reap(&mut self.child)?;
        Ok(self.identity.clone())
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = stop_and_reap(&mut self.child);
    }
}

pub(super) fn stop_and_reap(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    child.kill()?;
    let start = Clock::now()?;
    let until = start.ms.saturating_add(REAP_MS);
    while child.try_wait()?.is_none() {
        let now = Clock::now()?;
        if now.boot != start.boot || now.ms >= until {
            return Err(invalid("recovery-failed: child reap timeout"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// This is before runtime creation, logging, config or store initialization.
pub(crate) fn candidate_boot(version: &str) -> io::Result<()> {
    if std::env::var_os(BOOT_FD).is_none() {
        return Ok(());
    }
    if !super::ENABLED {
        return Err(invalid(format!(
            "{BOOT_FD} is set, but M2 launcher activation is held; \
             unset {BOOT_FD} to start x0xd"
        )));
    }
    candidate_boot_owned(version)
}

pub(crate) fn candidate_boot_owned(version: &str) -> io::Result<()> {
    take_boot_fd()?;
    // SAFETY: the private parent contract transfers descriptor 3 to this
    // process. A bad or closed descriptor fails its first socket operation.
    if unsafe { libc::fcntl(3, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let channel = unsafe { UnixStream::from_raw_fd(3) };
    channel.set_read_timeout(Some(Duration::from_secs(120)))?;
    let mut reader = std::io::BufReader::new(channel);
    let mut bytes = Vec::new();
    std::io::BufRead::read_until(&mut reader.by_ref().take(1024 * 1024), b'\n', &mut bytes)?;
    let permit: Permit = serde_json::from_slice(&bytes)?;
    let current = identity(std::process::id())?;
    // SAFETY: getppid takes no pointers and has no failure mode.
    let parent = identity(unsafe { libc::getppid() } as u32)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let cwd = std::env::current_dir()?;
    let argv = std::env::args_os().collect();
    let sha256 = filesystem::hash(&permit.executable)?;
    let observed = Observed {
        current,
        parent,
        executable,
        cwd,
        argv,
        sha256,
        now_ns: Clock::now()?.ms.saturating_mul(1_000_000),
    };
    check_permit(&permit, &observed, version)?;
    journal::write_record(&permit.root.join(journal::BOOT_FILE_NAME), &permit.record)?;
    reader.get_mut().write_all(&[1])
}

fn take_boot_fd() -> io::Result<()> {
    let value = std::env::var_os(BOOT_FD).ok_or_else(|| invalid("boot descriptor missing"))?;
    // Drop the descriptor variable at once: a re-exec or any later child
    // must not treat an inherited descriptor 3 as its own boot channel.
    std::env::remove_var(BOOT_FD);
    if value != "3" {
        return Err(invalid("invalid private boot descriptor"));
    }
    Ok(())
}

/// What the candidate process sees of itself at boot.
struct Observed {
    current: Identity,
    parent: Identity,
    executable: PathBuf,
    cwd: PathBuf,
    argv: Vec<OsString>,
    sha256: [u8; 32],
    now_ns: u64,
}

fn check_permit(permit: &Permit, observed: &Observed, version: &str) -> io::Result<()> {
    if observed.current.pid != permit.record.pid
        || observed.current.start != permit.record.process_start
        || observed.current.boot != permit.record.boot_id
        || observed.parent != permit.parent
        || observed.executable != permit.executable
        || observed.cwd != permit.cwd
        || observed.argv
            != permit
                .argv
                .iter()
                .map(|arg| OsString::from(arg.as_str()))
                .collect::<Vec<_>>()
        || version != permit.version
        || observed.sha256 != permit.sha256
        || observed.now_ns >= permit.record.deadline_ns
    {
        return Err(invalid("candidate boot does not match launcher authority"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn identity(pid: u32) -> io::Result<Identity> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let start = stat
        .rsplit_once(')')
        .ok_or_else(|| invalid("bad process stat"))?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| invalid("missing process start"))?
        .parse()
        .map_err(invalid)?;
    Ok(Identity {
        pid,
        start,
        boot: Clock::now()?.boot,
    })
}

#[cfg(not(target_os = "linux"))]
pub(super) fn identity(_pid: u32) -> io::Result<Identity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "launcher process custody requires Linux",
    ))
}

pub(super) fn absent(expected: &Identity) -> io::Result<bool> {
    if expected.boot != Clock::now()?.boot {
        return Ok(true);
    }
    match identity(expected.pid) {
        Ok(actual) => Ok(actual != *expected),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn me() -> Identity {
        Identity {
            pid: 41,
            start: 7,
            boot: "boot-1".into(),
        }
    }

    fn permit() -> Permit {
        Permit {
            record: journal::BootRecord {
                schema_version: 1,
                record_kind: "boot".into(),
                transaction_id: "transaction-1".into(),
                generation: 2,
                instance_id: "alice".into(),
                attempt: 1,
                pid: 41,
                process_start: 7,
                boot_id: "boot-1".into(),
                started_at_ns: 1_000_000_000,
                deadline_ns: 9_000_000_000,
            },
            parent: Identity {
                pid: 40,
                start: 5,
                boot: "boot-1".into(),
            },
            root: "/var/lib/x0x".into(),
            executable: "/usr/bin/x0xd".into(),
            sha256: [9; 32],
            version: "0.49.0".into(),
            argv: vec!["x0xd".into(), "--name".into(), "alice".into()],
            cwd: "/var/lib/x0x".into(),
        }
    }

    fn observed() -> Observed {
        Observed {
            current: me(),
            parent: permit().parent,
            executable: "/usr/bin/x0xd".into(),
            cwd: "/var/lib/x0x".into(),
            argv: vec!["x0xd".into(), "--name".into(), "alice".into()],
            sha256: [9; 32],
            now_ns: 2_000_000_000,
        }
    }

    fn refused(edit: impl FnOnce(&mut Observed), version: &str) {
        let mut seen = observed();
        edit(&mut seen);
        let error = check_permit(&permit(), &seen, version).unwrap_err();
        assert_eq!(
            error.to_string(),
            "candidate boot does not match launcher authority"
        );
    }

    #[test]
    fn launcher_child_matching_permit_is_accepted() {
        check_permit(&permit(), &observed(), "0.49.0").unwrap();
    }

    #[test]
    fn launcher_child_each_permit_mismatch_is_refused() {
        refused(|o| o.current.pid = 42, "0.49.0");
        refused(|o| o.current.start = 8, "0.49.0");
        refused(|o| o.current.boot = "boot-2".into(), "0.49.0");
        refused(|o| o.parent.pid = 1, "0.49.0");
        refused(|o| o.parent.start = 6, "0.49.0");
        refused(|o| o.parent.boot = "boot-2".into(), "0.49.0");
        refused(|o| o.executable = "/tmp/x0xd".into(), "0.49.0");
        refused(|o| o.cwd = "/".into(), "0.49.0");
        refused(|o| o.argv.push("--extra".into()), "0.49.0");
        refused(|o| o.argv.truncate(2), "0.49.0");
        refused(|o| o.argv[2] = "bob".into(), "0.49.0");
        refused(|_| {}, "0.48.0");
        refused(|o| o.sha256[0] ^= 1, "0.49.0");
        refused(|o| o.now_ns = 9_000_000_000, "0.49.0");
        refused(|o| o.now_ns = u64::MAX, "0.49.0");
    }

    #[test]
    fn launcher_child_argv_is_compared_as_os_strings() {
        let mut seen = observed();
        seen.argv[2] = OsString::from_vec(b"alice\xff".to_vec());
        let mut lossy = permit();
        lossy.argv[2] = seen.argv[2].to_string_lossy().into_owned();
        assert_eq!(lossy.argv[2], "alice\u{FFFD}");
        assert!(check_permit(&lossy, &seen, "0.49.0").is_err());
    }

    #[test]
    fn launcher_child_boot_fd_env_is_taken_once_and_must_be_3() {
        // The only test that touches X0X_M2_BOOT_FD: env is process-global.
        // While activation is held, x0xd refuses a launcher boot descriptor
        // and the refusal names the variable the operator must remove.
        std::env::set_var(BOOT_FD, "3");
        let held = candidate_boot("0.49.0").unwrap_err().to_string();
        assert!(held.contains("X0X_M2_BOOT_FD"), "{held}");
        assert!(held.contains("activation is held"), "{held}");
        std::env::set_var(BOOT_FD, "4");
        let error = take_boot_fd().unwrap_err();
        assert_eq!(error.to_string(), "invalid private boot descriptor");
        assert!(std::env::var_os(BOOT_FD).is_none());
        std::env::set_var(BOOT_FD, "3");
        take_boot_fd().unwrap();
        assert!(std::env::var_os(BOOT_FD).is_none());
        let error = take_boot_fd().unwrap_err();
        assert_eq!(error.to_string(), "boot descriptor missing");
        candidate_boot("0.49.0").unwrap();
    }

    #[test]
    fn launcher_child_permit_round_trips_and_refuses_unknown_fields() {
        let bytes = serde_json::to_vec(&permit()).unwrap();
        let parsed: Permit = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&parsed).unwrap(), bytes);
        check_permit(&parsed, &observed(), "0.49.0").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["extra"] = true.into();
        assert!(serde_json::from_value::<Permit>(value).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["record"]["extra"] = true.into();
        assert!(serde_json::from_value::<Permit>(value).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["parent"]["extra"] = true.into();
        assert!(serde_json::from_value::<Permit>(value).is_err());
    }

    #[test]
    fn launcher_child_stop_and_reap_kills_a_live_child() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        stop_and_reap(&mut child).unwrap();
        assert!(child.try_wait().unwrap().is_some());
        // A second call sees the reaped child and does not signal again.
        stop_and_reap(&mut child).unwrap();
    }

    #[test]
    fn launcher_child_stop_and_reap_accepts_an_exited_child() {
        let mut child = Command::new("true").spawn().unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
        stop_and_reap(&mut child).unwrap();
        assert_eq!(child.try_wait().unwrap(), Some(status));
    }

    #[test]
    fn launcher_child_absent_after_reboot() {
        let mut other = me();
        other.boot = "not-this-boot".into();
        assert!(absent(&other).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launcher_child_identity_tracks_live_and_reaped_processes() {
        let mine = identity(std::process::id()).unwrap();
        assert!(!absent(&mine).unwrap());
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let theirs = identity(child.id()).unwrap();
        assert!(!absent(&theirs).unwrap());
        let mut stale = theirs.clone();
        stale.start = stale.start.wrapping_add(1);
        assert!(absent(&stale).unwrap());
        stop_and_reap(&mut child).unwrap();
        assert!(absent(&theirs).unwrap());
    }
}
