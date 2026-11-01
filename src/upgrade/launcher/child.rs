//! Only this owner starts, signals and waits for its candidate.
use super::*;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, net::UnixStream, process::CommandExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

const BOOT_FD: &str = "X0X_M2_BOOT_FD";

/// How long a held build waits on a stray descriptor 3 for a launcher
/// permit before starting normally. A real launcher writes the permit
/// immediately after spawn; only silence or garbage follows a stray.
const HELD_PERMIT_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    record: journal::BootRecord,
    parent: Identity,
    root: PathBuf,
    executable: PathBuf,
    sha256: [u8; 32],
    version: String,
    argv: Vec<Vec<u8>>,
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
            let (executable, cwd) =
                captured_spawn_paths(&participant.executable, &participant.cwd)?;
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
                executable,
                sha256,
                version: version.into(),
                argv: participant
                    .argv
                    .iter()
                    .map(|argument| argument.as_bytes().to_vec())
                    .collect(),
                cwd,
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
        return held_boot(version);
    }
    candidate_boot_owned(version)
}

/// ADR 0094 §6: never brick startup while activation is held. No published
/// build carries the launcher, so fd 3 under the marker is an unrelated
/// descriptor unless a launcher channel delivers a permit on it. A stray
/// marker is dropped with one warning line and the daemon starts normally;
/// only a present permit that fails its checks refuses the boot (#1375).
fn held_boot(version: &str) -> io::Result<()> {
    let marker = std::env::var_os(BOOT_FD);
    std::env::remove_var(BOOT_FD);
    held_boot_with(marker.as_deref(), held_channel(), version)
}

/// The held-boot decision, split from the env and descriptor glue so tests
/// can drive it with synthetic descriptors.
fn held_boot_with(
    marker: Option<&std::ffi::OsStr>,
    channel: Result<i32, &'static str>,
    version: &str,
) -> io::Result<()> {
    if marker != Some(std::ffi::OsStr::new("3")) {
        return stray_boot("the marker does not name descriptor 3");
    }
    let channel = match channel {
        Ok(channel) => channel,
        Err(reason) => return stray_boot(reason),
    };
    match held_permit(channel) {
        Some(permit) => {
            let observed = observed_for(&permit)?;
            check_permit(&permit, &observed, version)
        }
        None => stray_boot("no launcher permit arrived on descriptor 3"),
    }
}

/// One warning line, then normal startup.
fn stray_boot(reason: &str) -> io::Result<()> {
    eprintln!("warning: ignoring stray {BOOT_FD} (M2 launcher activation is held): {reason}");
    Ok(())
}

/// Probe descriptor 3 for a launcher channel. The descriptor belongs to
/// whoever opened it and stays theirs: the probe only polls it and receives
/// with per-call `MSG_DONTWAIT`, so it never blocks long and never changes
/// the shared open-file flags.
fn held_channel() -> Result<i32, &'static str> {
    // SAFETY: fcntl and fstat take no pointers this process does not own;
    // every failure mode returns -1 and becomes a stray reason.
    unsafe {
        if libc::fcntl(3, libc::F_GETFD) == -1 {
            return Err("descriptor 3 is not open");
        }
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(3, &mut stat) == -1 {
            return Err("descriptor 3 could not be inspected");
        }
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
            return Err("descriptor 3 is not a socket");
        }
        Ok(3)
    }
}

/// Read one bounded permit line under a poll deadline. Silence, a timeout or
/// bytes that are not a permit all mean stray.
fn held_permit(fd: i32) -> Option<Permit> {
    let deadline = std::time::Instant::now() + HELD_PERMIT_TIMEOUT;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = bytes.iter().position(|&byte| byte == b'\n') {
            bytes.truncate(pos + 1);
            return serde_json::from_slice(&bytes).ok();
        }
        if bytes.len() >= 1024 * 1024 {
            return None;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let wait_ms = (deadline - now).as_millis() as i32;
        // SAFETY: poll reads only the pollfd this loop owns.
        let ready = unsafe { libc::poll(&mut pollfd, 1, wait_ms) };
        if ready != 1 || pollfd.revents & libc::POLLIN == 0 {
            return None;
        }
        // SAFETY: recv with MSG_DONTWAIT writes only into this loop's
        // buffer and never changes the shared descriptor flags.
        let read = unsafe {
            libc::recv(
                fd,
                chunk.as_mut_ptr().cast(),
                chunk.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if read <= 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read as usize]);
    }
}

/// The permit must carry the paths the candidate compares against: its own
/// `current_exe()` is canonicalized, its `current_dir()` is kernel-resolved,
/// and the boot hash opens with `O_NOFOLLOW`. A symlinked install is
/// therefore canonicalized when the participant is captured, instead of
/// being refused by the boot check (#1375).
fn captured_spawn_paths(executable: &Path, cwd: &Path) -> io::Result<(PathBuf, PathBuf)> {
    Ok((executable.canonicalize()?, cwd.canonicalize()?))
}

/// argv is not guaranteed UTF-8, and a String-based collection panics on
/// raw bytes. The permit carries the same OS bytes, so the boot
/// comparison stays exact and can only refuse, never panic (#1375).
fn argv_bytes<I: Iterator<Item = OsString>>(argv: I) -> Vec<Vec<u8>> {
    argv.map(|argument| argument.as_bytes().to_vec()).collect()
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
    let observed = observed_for(&permit)?;
    check_permit(&permit, &observed, version)?;
    journal::write_record(&permit.root.join(journal::BOOT_FILE_NAME), &permit.record)?;
    reader.get_mut().write_all(&[1])
}

/// Everything the boot check compares, captured from this process.
fn observed_for(permit: &Permit) -> io::Result<Observed> {
    Ok(Observed {
        current: identity(std::process::id())?,
        // SAFETY: getppid takes no pointers and has no failure mode.
        parent: identity(unsafe { libc::getppid() } as u32)?,
        executable: std::env::current_exe()?.canonicalize()?,
        cwd: std::env::current_dir()?,
        argv: std::env::args_os().collect(),
        sha256: filesystem::hash(&permit.executable)?,
        now_ns: Clock::now()?.ms.saturating_mul(1_000_000),
    })
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
        || argv_bytes(observed.argv.iter().cloned()) != permit.argv
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
            argv: vec![b"x0xd".to_vec(), b"--name".to_vec(), b"alice".to_vec()],
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
        // The permit carries OS bytes, so the lossy UTF-8 spelling of the
        // same argument is a different byte string and must be refused.
        let mut lossy = permit();
        lossy.argv[2] = seen.argv[2].to_string_lossy().into_owned().into_bytes();
        assert_eq!(
            String::from_utf8(lossy.argv[2].clone()).unwrap(),
            "alice\u{FFFD}"
        );
        assert!(check_permit(&lossy, &seen, "0.49.0").is_err());
    }

    #[test]
    fn launcher_child_boot_fd_env_is_taken_once_and_must_be_3() {
        // The only in-process test that touches X0X_M2_BOOT_FD: env is
        // process-global. The held stray-marker boot itself is covered by
        // the boot_guards re-exec tests, which own their descriptor 3.
        std::env::set_var(BOOT_FD, "4");
        let error = take_boot_fd().unwrap_err();
        assert_eq!(error.to_string(), "invalid private boot descriptor");
        assert!(std::env::var_os(BOOT_FD).is_none());
        std::env::set_var(BOOT_FD, "3");
        take_boot_fd().unwrap();
        assert!(std::env::var_os(BOOT_FD).is_none());
        let error = take_boot_fd().unwrap_err();
        assert_eq!(error.to_string(), "boot descriptor missing");
    }

    #[test]
    fn launcher_child_held_boot_ignores_unreadable_channels() {
        // A marker naming another descriptor never touches fd 3.
        held_boot_with(
            Some(std::ffi::OsStr::new("4")),
            Err("descriptor 3 is not open"),
            "0.49.0",
        )
        .unwrap();
        // Bytes that are not a permit are stray, not a refusal.
        let (mut writer, channel) = UnixStream::pair().unwrap();
        writer.write_all(b"not-a-permit\n").unwrap();
        held_boot_with(
            Some(std::ffi::OsStr::new("3")),
            Ok(channel.as_raw_fd()),
            "0.49.0",
        )
        .unwrap();
        // A socket whose peer is closed without sending is stray too.
        let (_writer, silent) = UnixStream::pair().unwrap();
        drop(_writer);
        held_boot_with(
            Some(std::ffi::OsStr::new("3")),
            Ok(silent.as_raw_fd()),
            "0.49.0",
        )
        .unwrap();
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

/// Boot invariants that hold even while activation is held: the boot
/// marker must not outlive the fd-3 take, argv compares as OS bytes, a
/// symlinked install captures canonical paths, and a stray marker never
/// bricks startup (ADR 0094 §6).
#[cfg(test)]
mod boot_guards {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    const BOOT_ROLE: &str = "X0X_1375_S2_BOOT_FD_ROLE";

    fn fixture_permit() -> Permit {
        Permit {
            record: journal::BootRecord {
                schema_version: 1,
                record_kind: "boot".into(),
                transaction_id: "transaction-1".into(),
                generation: 1,
                instance_id: "alice".into(),
                attempt: 1,
                pid: 1,
                process_start: 1,
                boot_id: "boot-1".into(),
                started_at_ns: 0,
                deadline_ns: u64::MAX,
            },
            parent: Identity {
                pid: 1,
                start: 1,
                boot: "boot-1".into(),
            },
            root: PathBuf::from("/nonexistent-x0x-boot-guard"),
            executable: PathBuf::from("/nonexistent-x0x-boot-guard/x0xd"),
            sha256: [0; 32],
            version: "fixture-version".into(),
            argv: vec![b"x0xd".to_vec()],
            cwd: PathBuf::from("/nonexistent-x0x-boot-guard"),
        }
    }

    #[test]
    fn boot_fd_is_cleared_once_fd_3_is_taken() {
        if std::env::var_os(BOOT_ROLE).is_some() {
            boot_fd_role();
            return;
        }
        let (mut parent, channel) = UnixStream::pair().unwrap();
        let fd = channel.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        // The launcher module is mounted at the bin crate root, so the
        // exact selector carries no `upgrade::` prefix.
        command
            .arg("--exact")
            .arg("launcher::child::boot_guards::boot_fd_is_cleared_once_fd_3_is_taken")
            .env(BOOT_ROLE, "1")
            .env(BOOT_FD, "3")
            .stdin(Stdio::null());
        // SAFETY: the descriptor contract under test is the one
        // `Owned::spawn` installs; the child closure only calls
        // async-signal-safe descriptor operations.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(channel);
        let mut bytes = serde_json::to_vec(&fixture_permit()).unwrap();
        bytes.push(b'\n');
        parent.write_all(&bytes).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "child exited with {status}");
    }

    fn boot_fd_role() {
        // Non-Linux refuses the boot right after the take; Linux refuses it
        // on the fixture identity. Either way the marker must already be
        // gone, or a later self-update child would treat its own unrelated
        // descriptor 3 as a boot channel.
        let _ = candidate_boot_owned("fixture-version");
        if std::env::var_os(BOOT_FD).is_none() {
            std::process::exit(0);
        }
        std::process::exit(42);
    }

    #[test]
    fn held_boot_ignores_a_stray_marker_and_boots_normally() {
        if let Some(role) = std::env::var_os(BOOT_ROLE) {
            match role.to_str() {
                Some("2") => held_stray_role(),
                Some("3") => held_permit_role(),
                _ => boot_fd_role(),
            }
            return;
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(
                "launcher::child::boot_guards::held_boot_ignores_a_stray_marker_and_boots_normally",
            )
            .env(BOOT_ROLE, "2")
            .env(BOOT_FD, "3")
            .stdin(Stdio::null());
        // SAFETY: closing descriptor 3 in the forked child leaves the
        // marker naming nothing — the shape a leaked marker has while the
        // launcher is dormant. The closure only calls async-signal-safe
        // close.
        unsafe {
            command.pre_exec(|| {
                libc::close(3);
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "child exited with {status}");
    }

    fn held_stray_role() {
        // ADR 0094 §6: the held build boots normally instead of refusing,
        // and drops the marker so a later self-update child cannot mistake
        // its own descriptor 3 for a boot channel.
        candidate_boot("fixture-version").unwrap();
        if std::env::var_os(BOOT_FD).is_none() {
            std::process::exit(0);
        }
        std::process::exit(42);
    }

    #[test]
    fn held_boot_refuses_a_present_permit_that_fails_its_checks() {
        if let Some(role) = std::env::var_os(BOOT_ROLE) {
            match role.to_str() {
                Some("2") => held_stray_role(),
                Some("3") => held_permit_role(),
                _ => boot_fd_role(),
            }
            return;
        }
        let (mut parent, channel) = UnixStream::pair().unwrap();
        let fd = channel.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(
                "launcher::child::boot_guards::held_boot_refuses_a_present_permit_that_fails_its_checks",
            )
            .env(BOOT_ROLE, "3")
            .env(BOOT_FD, "3")
            .stdin(Stdio::null());
        // SAFETY: the same descriptor contract `Owned::spawn` installs; the
        // child closure only calls async-signal-safe descriptor operations.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(channel);
        let mut bytes = serde_json::to_vec(&fixture_permit()).unwrap();
        bytes.push(b'\n');
        parent.write_all(&bytes).unwrap();
        drop(parent);
        let status = child.wait().unwrap();
        assert!(status.success(), "child exited with {status}");
    }

    fn held_permit_role() {
        // The fixture permit names a nonexistent executable, so a permit
        // that really arrives cannot pass its checks: the held build keeps
        // the refusal and never acks or writes a boot record.
        match candidate_boot("fixture-version") {
            Err(_) => std::process::exit(0),
            Ok(()) => std::process::exit(43),
        }
    }

    #[test]
    fn argv_bytes_keep_non_utf8_without_panicking() {
        let raw = OsString::from_vec(b"daemon\xff".to_vec());
        // A String-based args() collection panics on these bytes; the byte
        // collection keeps them, so the boot check refuses raw argv instead
        // of dying before logging exists.
        assert_eq!(
            argv_bytes(std::iter::once(raw)),
            vec![b"daemon\xff".to_vec()]
        );
        // The permit carries the same OS bytes, so equal argv passes the
        // boot comparison and only genuinely different argv is refused.
        assert_eq!(
            argv_bytes(std::iter::once(OsString::from("x0xd"))),
            fixture_permit().argv
        );
    }

    #[test]
    fn captured_paths_are_canonical_so_a_symlinked_install_boots() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let real_executable = real_dir.join("x0xd");
        std::fs::write(&real_executable, b"candidate-bytes").unwrap();
        let linked_executable = dir.path().join("linked-x0xd");
        std::os::unix::fs::symlink(&real_executable, &linked_executable).unwrap();
        let linked_cwd = dir.path().join("linked-cwd");
        std::os::unix::fs::symlink(&real_dir, &linked_cwd).unwrap();

        let (executable, cwd) = captured_spawn_paths(&linked_executable, &linked_cwd).unwrap();

        // The candidate compares these against its own canonical
        // current_exe() and kernel-resolved current_dir(), so a
        // Homebrew-style link boots instead of spending all three attempts
        // and rolling back.
        assert_eq!(executable, real_executable.canonicalize().unwrap());
        assert_eq!(cwd, real_dir.canonicalize().unwrap());
        // The O_NOFOLLOW boot hash agrees with the captured path: it opens
        // the real file, never the symlink the plan was captured with.
        assert_eq!(
            filesystem::hash(&executable).unwrap(),
            <[u8; 32]>::from(Sha256::digest(b"candidate-bytes"))
        );
        assert!(filesystem::hash(&linked_executable).is_err());
    }
}
