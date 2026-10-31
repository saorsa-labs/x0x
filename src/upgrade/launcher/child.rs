//! Only this owner starts, signals and waits for its candidate.
use super::*;
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
        let setup = (|| {
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
            Err(error) => {
                stop_and_reap(&mut child)?;
                Err(error)
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
        return Err(invalid("M2 launcher activation is held"));
    }
    candidate_boot_owned(version)
}

pub(crate) fn candidate_boot_owned(version: &str) -> io::Result<()> {
    let value = std::env::var_os(BOOT_FD).ok_or_else(|| invalid("boot descriptor missing"))?;
    // Drop the descriptor variable at once: a re-exec or any later child
    // must not treat an inherited descriptor 3 as its own boot channel.
    std::env::remove_var(BOOT_FD);
    if value != "3" {
        return Err(invalid("invalid private boot descriptor"));
    }
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
    if current.pid != permit.record.pid
        || current.start != permit.record.process_start
        || current.boot != permit.record.boot_id
        || parent != permit.parent
        || std::env::current_exe()?.canonicalize()? != permit.executable
        || std::env::current_dir()? != permit.cwd
        || std::env::args_os().collect::<Vec<std::ffi::OsString>>()
            != permit
                .argv
                .iter()
                .map(|arg| std::ffi::OsString::from(arg.as_str()))
                .collect::<Vec<_>>()
        || version != permit.version
        || filesystem::hash(&permit.executable)? != permit.sha256
        || Clock::now()?.ms.saturating_mul(1_000_000) >= permit.record.deadline_ns
    {
        return Err(invalid("candidate boot does not match launcher authority"));
    }
    journal::write_record(&permit.root.join(journal::BOOT_FILE_NAME), &permit.record)?;
    reader.get_mut().write_all(&[1])
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
