//! The launcher-side issuer (#1378): the launcher argv names the host root
//! and this launcher's participant, and the issuer reads and verifies the
//! prepared host journal there before it gives the main loop a host.
//!
//! The argv contract (provisional and dormant, frozen before `ENABLED`):
//!
//! ```text
//! x0x-launcher /abs/x0xd [daemon args...]
//! x0x-launcher --host-root <abs data_root> --instance <id> -- /abs/x0xd [daemon args...]
//! ```
//!
//! The first form never owns a trial. The writer of the journal is the M2
//! prepare producer (#2012); the launcher only reads it. A journal it cannot
//! verify is an error (the main loop exits 75), never a guess.
use super::*;
use std::ffi::OsString;
use std::fs::File;
use std::os::unix::fs::MetadataExt;

pub(crate) use contract::TrialArgs;

pub(crate) struct LauncherArgs {
    pub(crate) trial: Option<TrialArgs>,
    pub(crate) command: forward::DaemonCommand,
}

/// Parse the launcher argv (after the launcher's own name) with the shared
/// contract parser (`contract::parse_launcher_argv`), which the launchd
/// classifiers also use (#2016 review).
pub(crate) fn launcher_argv(argv: &[OsString]) -> io::Result<LauncherArgs> {
    let parsed = contract::parse_launcher_argv(argv).map_err(invalid)?;
    Ok(LauncherArgs {
        trial: parsed.trial,
        command: forward::daemon_argv(parsed.daemon)?,
    })
}

/// The issuer for a launcher whose argv names a host root and instance.
/// After a start that is a passthrough, `held` holds the daemon install
/// lock the issuer read the records under, for the caller to keep until
/// the `exec` (#2012).
pub(super) struct JournalIssuer<'a> {
    pub(super) args: &'a TrialArgs,
    pub(super) held: std::cell::RefCell<Option<File>>,
}

impl start::Issuer for JournalIssuer<'_> {
    fn issue(&self, command: &forward::DaemonCommand) -> io::Result<Option<start::Issued>> {
        let uid = effective_uid();
        issue_held(
            self.args,
            command,
            uid,
            uid,
            &mut self.held.borrow_mut(),
            false,
        )
    }
}

/// `uid` is the account the root and records must belong to: the
/// launcher's effective uid.
fn issue_as(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    uid: u32,
) -> io::Result<Option<start::Issued>> {
    issue_with(args, command, uid, uid)
}

/// As `issue_as`, with the root's and the journal's expected owners apart,
/// so a test can make only the journal foreign (#2014 review).
fn issue_with(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    root_uid: u32,
    record_uid: u32,
) -> io::Result<Option<start::Issued>> {
    issue_held(args, command, root_uid, record_uid, &mut None, false)
}

/// Read the host journal and the trial record under the daemon install
/// lock (`<daemon>.upgrade.lock`), which the prepare producer holds for
/// every journal change and swap (#2012, #2014 review). Without it a start
/// could read a Prepared journal, the producer could then swap, and the
/// passthrough would `exec` the candidate unsupervised. A passthrough
/// leaves the lock in `held`, so the caller keeps it until the `exec`
/// (the descriptor is close-on-exec). A trial start releases it, since
/// `Host::locked` takes the CLI and daemon locks itself. `retired` is set
/// by `relock` after a start retired its trial: a committed host whose
/// trial for this instance is Committed is then the steady state, and its
/// passthrough keeps the lock as an ordinary one does.
fn issue_held(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    root_uid: u32,
    record_uid: u32,
    held: &mut Option<File>,
    retired: bool,
) -> io::Result<Option<start::Issued>> {
    let root = open_root(&args.host_root, root_uid)?;
    let daemon = daemon_lock(Path::new(&command.executable), DAEMON_LOCK_WAIT)?;
    let Some(record) = read_journal(&root, record_uid)? else {
        no_authority(args, &root)?;
        *held = daemon.map(|(_, lock)| lock);
        return Ok(None);
    };
    let passthrough = if owns_trial(record.phase)? {
        retired && committed_trial(args, &root, record.phase)?
    } else {
        no_authority(args, &root)?;
        true
    };
    if passthrough {
        if let Some((canonical, _)) = &daemon {
            if *canonical != record.plan.daemon.target_path {
                return Err(start::refused(
                    "the launcher's daemon is not the host journal's daemon target",
                ));
            }
        }
        *held = daemon.map(|(_, lock)| lock);
        return Ok(None);
    }
    drop(daemon);
    let participant = record
        .plan
        .participants
        .iter()
        .find(|p| p.instance_id == args.instance)
        .ok_or_else(|| start::refused("instance is not a participant of the host journal"))?;
    // `argv[0]` is the process's argv0, which the launcher sets itself at
    // spawn; the daemon's arguments are the rest (`child::Owned::spawn`).
    let planned = participant.argv.get(1..).unwrap_or_default();
    let args_match = planned.len() == command.args.len()
        && planned
            .iter()
            .zip(&command.args)
            .all(|(planned, given)| given.to_str() == Some(planned.as_str()));
    if participant.data_root != args.host_root
        || participant.executable.as_os_str() != command.executable
        || !args_match
    {
        return Err(start::refused(
            "launcher argv does not match its participant in the host journal",
        ));
    }
    // Canonical install and participant paths (`Host::new`). A plan path
    // that is not canonical stays so on a restart: `Host::new` returns a
    // typed refusal (78). A missing path may appear by itself (a data root
    // on a volume not yet mounted at boot), so it is a failed read (75),
    // as is every other I/O error (#2015 review).
    let host = recovery::Host::new(args.host_root.clone(), record)?;
    Ok(Some(start::Issued {
        host,
        instance: args.instance.clone(),
    }))
}

/// How long a start waits for the daemon install lock before it gives up
/// with a failed read (75): a producer holds it only for one journal change
/// or swap.
const DAEMON_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The daemon install lock, taken, with the daemon's canonical path: the
/// producer and the daemon's routes lock beside the canonical install
/// target, so a unit that names the daemon through a symlink must take the
/// same file (#2118 review). `Ok(None)` when the daemon or its directory
/// does not exist: there is nothing to swap and the producer cannot lock
/// there either, so the start goes on to the missing-daemon wait (#1379)
/// and takes the lock before its `exec` (`relock`). A lock file this
/// account cannot create or open (EACCES, EPERM, EROFS) is a typed
/// refusal: the CLI self-update can take the same lock and swap as another
/// account, root under `sudo` for example, so a passthrough without the
/// lock is not safe. Waiting longer than `wait` is a failed read.
fn daemon_lock(
    executable: &Path,
    wait: std::time::Duration,
) -> io::Result<Option<(PathBuf, File)>> {
    daemon_lock_with(executable, wait, &|path| path.canonicalize())
}

/// `daemon_lock` with the path resolution injected, so a test can move the
/// daemon path while the lock is taken. After the lock is held the path is
/// resolved again: one that now names another file is a retryable error
/// (`Interrupted`, a failed read), since the lock taken is not the daemon's.
fn daemon_lock_with(
    executable: &Path,
    wait: std::time::Duration,
    resolve: &dyn Fn(&Path) -> io::Result<PathBuf>,
) -> io::Result<Option<(PathBuf, File)>> {
    let missing = |e: &io::Error| {
        e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENOTDIR)
    };
    let canonical = match resolve(executable) {
        Ok(canonical) => canonical,
        Err(error) if missing(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let lock = match recovery::lock(&canonical) {
        Ok(lock) => lock,
        Err(error) if missing(&error) => return Ok(None),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EACCES | libc::EPERM | libc::EROFS)
            ) =>
        {
            return Err(start::refused(format!(
                "cannot create or open the install lock beside {} ({error}); let the \
                 launcher's account write that directory, or use the plain launcher form",
                canonical.display()
            )));
        }
        Err(error) => {
            // A symlink, directory or other non-regular file at the lock
            // path stays so: a fixed refusal, as for EACCES above.
            let path = recovery::lock_path(&canonical);
            if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_file()) {
                return Err(start::refused(format!(
                    "the install lock {} is not a regular file ({error})",
                    path.display()
                )));
            }
            return Err(error);
        }
    };
    let deadline = std::time::Instant::now() + wait;
    loop {
        match lock.try_lock() {
            Ok(()) => {
                return match resolve(executable) {
                    Ok(again) if again == canonical => Ok(Some((canonical, lock))),
                    Ok(_) => Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "the daemon path changed while its install lock was taken",
                    )),
                    Err(error) if missing(&error) => Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "the daemon went missing while its install lock was taken",
                    )),
                    Err(error) => Err(error),
                };
            }
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the daemon install lock is still held",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

/// Before a passthrough `exec` of a trial-form start that holds no lock
/// (it found no daemon, or it retired its trial on a committed host): read
/// the records again under the daemon install lock and keep it in `held`
/// (#2118 review). A trial that is in flight, not this instance's retired
/// one, is left to the next start, which owns it: a failed read (75).
pub(super) fn relock(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    held: &mut Option<File>,
) -> io::Result<()> {
    if held.is_some() {
        return Ok(());
    }
    let uid = effective_uid();
    match issue_held(args, command, uid, uid, held, true)? {
        None => Ok(()),
        Some(_) => Err(io::Error::other(
            "a trial is now in flight; the next start owns it",
        )),
    }
}

/// Read the host journal through one descriptor: open it without following
/// a symlink, check owner, mode, type and size on that descriptor, and read
/// from it, so nothing can swap the file between the check and the read
/// (#2014 review). `Ok(None)` only when there is no journal.
fn read_journal(root: &File, uid: u32) -> io::Result<Option<journal::JournalRecord>> {
    use std::io::Read;
    let file = match open_at(root, journal::JOURNAL_FILE_NAME) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(start::refused("host journal is a symlink"));
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    // The record's authority is its owner, mode and place (#2012): only
    // this account wrote it, and only this account can read or change it.
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > journal::MAX_RECORD_BYTES
    {
        return Err(start::refused(
            "host journal must be a regular file of this account with mode 0600",
        ));
    }
    let mut bytes = Vec::new();
    file.take(journal::MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > journal::MAX_RECORD_BYTES {
        return Err(start::refused("host journal exceeds the size limit"));
    }
    match journal::classify_record(&bytes, "journal") {
        journal::RecordRead::Journal(record) => Ok(Some(*record)),
        _ => Err(start::refused(
            "host journal is corrupt or of an unknown schema",
        )),
    }
}

/// No in-flight journal names this launcher. That is an ordinary start
/// only if no unfinished trial of this participant is on disk: a Booting or
/// Authorized trial means a swapped candidate could start unsupervised, so
/// the start is refused instead (#2014 review). A Committed or Restored
/// trial is finished: its daemon is the installed or the restored bytes.
fn no_authority(args: &TrialArgs, root: &File) -> io::Result<()> {
    let bytes = match read_record_at(root, coordinator::TRIAL_FILE_NAME) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        // A symlinked, non-regular or oversized trial record stays so: a
        // fixed refusal, never a passthrough (#2014 review).
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Err(start::refused(format!("trial record is unusable: {error}")));
        }
        Err(error) => return Err(error),
    };
    let trial: Trial =
        serde_json::from_slice(&bytes).map_err(|_| start::refused("trial record is unreadable"))?;
    match trial.phase {
        Phase::Committed | Phase::Restored if trial.instance == args.instance => Ok(()),
        _ => Err(start::refused(
            "an unfinished trial exists without an in-flight host journal",
        )),
    }
}

/// A retired trial: the host is committed and this instance's trial record
/// is Committed. A trial is saved Committed only under the host lock while
/// the journal is HostCommitted (`run::retire`), and only a new producer
/// transaction, under the install lock, moves the journal on.
fn committed_trial(args: &TrialArgs, root: &File, phase: journal::Phase) -> io::Result<bool> {
    if phase != journal::Phase::HostCommitted {
        return Ok(false);
    }
    let bytes = match read_record_at(root, coordinator::TRIAL_FILE_NAME) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let trial: Trial =
        serde_json::from_slice(&bytes).map_err(|_| start::refused("trial record is unreadable"))?;
    Ok(trial.phase == Phase::Committed && trial.instance == args.instance)
}

/// Whether the journal phase gives the launcher trial authority. Before
/// any swap the installed bytes are unchanged and idle or superseded
/// records are history (an ordinary start, unless a trial is unfinished).
/// A daemon swapped without its CLI is a mixed pair the launcher must not
/// start or guess at.
fn owns_trial(phase: journal::Phase) -> io::Result<bool> {
    use journal::Phase::*;
    match phase {
        Staged | Probed | Prepared | Idle | Superseded => Ok(false),
        SwappedDaemon => Err(start::refused(
            "host journal is between the daemon and CLI swap",
        )),
        SwappedCli | HandoffArmed | Booting | HealthCommitted | HostCommitted | RollingBack
        | FailedReleaseHold | Restored | RecoveryFailed => Ok(true),
    }
}

/// The host root must be canonical (no symlink can move it), a directory
/// of this account, and writable by nobody else.
pub(super) fn check_root(root: &Path, uid: u32) -> io::Result<()> {
    open_root(root, uid).map(drop)
}

/// Open the host root once, as a directory, after its checks, so the
/// records are read relative to the checked directory and a rename of the
/// path cannot redirect them (#2014 review). Every ancestor must also be a
/// directory that only root or this account can change: one that another
/// account can write could move the root aside. A sticky ancestor (such as
/// `/tmp`) is allowed, since only the owner of an entry may rename it.
fn open_root(root: &Path, uid: u32) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    if root.canonicalize()? != root {
        return Err(start::refused("--host-root must be canonical"));
    }
    for ancestor in root.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        let writable_by_others = metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || writable_by_others
        {
            return Err(start::refused(format!(
                "--host-root ancestor {} must be a directory that only root or this account \
                 can change",
                ancestor.display()
            )));
        }
    }
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)?;
    let metadata = dir.metadata()?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(start::refused(
            "--host-root must be a directory of this account that no other can write",
        ));
    }
    Ok(dir)
}

/// Open `name` in the checked directory `dir` without following a
/// symlink; a FIFO opens without blocking and then fails the caller's
/// regular-file check.
fn open_at(dir: &File, name: &str) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
    // SAFETY: `dir` is an open directory descriptor for the whole call and
    // `name` is a NUL-terminated string that outlives it. A non-negative
    // result is a new descriptor that nothing else owns.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this function owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// A record in the checked directory: a regular file within the record
/// size limit. A symlink fails with `ELOOP`, anything else that is not a
/// usable record with `InvalidData`.
fn read_record_at(dir: &File, name: &str) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_at(dir, name)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "record is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(journal::MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > journal::MAX_RECORD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "record exceeds the size limit",
        ));
    }
    Ok(bytes)
}

pub(super) fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use testkit::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_plain_form_owns_no_trial() {
        let parsed = launcher_argv(&os(&["/usr/bin/x0xd", "--name", "a"])).unwrap();
        assert!(parsed.trial.is_none());
        assert_eq!(parsed.command.executable, "/usr/bin/x0xd");
        assert_eq!(parsed.command.args, os(&["--name", "a"]));
    }

    #[test]
    fn the_trial_form_names_root_and_instance() {
        let parsed = launcher_argv(&os(&[
            "--host-root",
            "/var/lib/x0x",
            "--instance",
            "alice",
            "--",
            "/usr/bin/x0xd",
            "--name",
            "a",
        ]))
        .unwrap();
        assert_eq!(
            parsed.trial,
            Some(TrialArgs {
                host_root: "/var/lib/x0x".into(),
                instance: "alice".into(),
            })
        );
        assert_eq!(parsed.command.executable, "/usr/bin/x0xd");
        assert_eq!(parsed.command.args, os(&["--name", "a"]));
    }

    #[test]
    fn a_malformed_trial_form_is_refused() {
        for argv in [
            vec!["--host-root"],
            vec!["--host-root", "/r", "--instance", "a", "/usr/bin/x0xd"],
            vec!["--host-root", "/r", "--name", "a", "--", "/usr/bin/x0xd"],
            vec![
                "--host-root",
                "rel",
                "--instance",
                "a",
                "--",
                "/usr/bin/x0xd",
            ],
            vec!["--host-root", "/r", "--instance", "", "--", "/usr/bin/x0xd"],
            vec![
                "--host-root",
                "/r",
                "--instance",
                "a/b",
                "--",
                "/usr/bin/x0xd",
            ],
            vec![
                "--host-root",
                "/r",
                "--instance",
                ".",
                "--",
                "/usr/bin/x0xd",
            ],
            vec![
                "--host-root",
                "/r",
                "--instance",
                "..",
                "--",
                "/usr/bin/x0xd",
            ],
            vec!["--host-root", "/r", "--instance", "a", "--", "x0xd"],
            vec!["--host-root", "/r", "--instance", "a", "--"],
        ] {
            assert!(launcher_argv(&os(&argv)).is_err(), "{argv:?}");
        }
    }

    /// A launcher argv that matches the fixture's participant `alice`.
    fn matching(record: &journal::JournalRecord) -> (TrialArgs, forward::DaemonCommand) {
        let alice = &record.plan.participants[0];
        (
            TrialArgs {
                host_root: alice.data_root.clone(),
                instance: alice.instance_id.clone(),
            },
            forward::DaemonCommand {
                executable: alice.executable.clone().into_os_string(),
                args: alice.argv.iter().skip(1).map(OsString::from).collect(),
            },
        )
    }

    /// The fixture's journal is in alice's data root, the launcher's host
    /// root. Alice gets one daemon argument, so argument checks bite.
    fn rooted(phase: journal::Phase) -> (tempfile::TempDir, PathBuf, journal::JournalRecord) {
        let (dir, root, _host, record) = fixture_with(phase, |record| {
            record.plan.participants[0].argv.push("--name".into());
        });
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, root, record)
    }

    #[test]
    fn a_matching_in_flight_journal_issues_a_host() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let issued = issue_as(&args, &command, effective_uid())
            .unwrap()
            .expect("issued");
        assert_eq!(issued.instance, "alice");
        assert_eq!(issued.host.root(), root);
    }

    /// #2012: a journal the prepare producer writes is one this issuer
    /// issues, and `Host::new` binds; an instance it did not write is a
    /// fixed refusal.
    #[test]
    fn a_journal_from_the_prepare_producer_is_issued() {
        use super::super::prepare::tests as producer;
        let (_dir, root) = producer::root();
        let prepared = producer::prepared_in(&root, producer::input_in(&root));
        let (args, command) = matching(prepared.record());
        let issued = issue_as(&args, &command, effective_uid())
            .unwrap()
            .expect("issued");
        assert_eq!(issued.host.root(), root);
        let other = TrialArgs {
            instance: "bob".into(),
            ..args
        };
        let error = issue_as(&other, &command, effective_uid())
            .err()
            .expect("refused");
        assert!(start::is_refusal(&error), "{error}");
    }

    #[test]
    fn no_journal_or_a_settled_one_is_an_ordinary_start() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        for phase in [
            journal::Phase::Staged,
            journal::Phase::Prepared,
            journal::Phase::Idle,
        ] {
            let mut settled = record.clone();
            settled.phase = phase;
            journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &settled).unwrap();
            assert!(
                issue_as(&args, &command, effective_uid())
                    .unwrap()
                    .is_none(),
                "{phase:?}"
            );
        }
        std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
        assert!(issue_as(&args, &command, effective_uid())
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_half_swapped_pair_is_refused() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedDaemon);
        let (args, command) = matching(&record);
        assert!(issue_as(&args, &command, effective_uid()).is_err());
    }

    /// Every mismatch between the launcher argv and the participant is an
    /// error, never an ordinary start.
    #[test]
    fn a_mismatched_argv_is_refused() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let mut other_instance = args.clone();
        other_instance.instance = "nobody".into();
        assert!(issue_as(&other_instance, &command, effective_uid()).is_err());
        let mut other_exe = forward::DaemonCommand {
            executable: "/usr/bin/other".into(),
            args: command.args.clone(),
        };
        assert!(issue_as(&args, &other_exe, effective_uid()).is_err());
        other_exe.executable = command.executable.clone();
        other_exe.args.push("--extra".into());
        assert!(issue_as(&args, &other_exe, effective_uid()).is_err());
    }

    #[test]
    fn a_writable_or_foreign_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            issue_as(&args, &command, effective_uid()).is_err(),
            "group-readable journal"
        );
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            issue_as(&args, &command, effective_uid()).is_err(),
            "group-writable root"
        );
    }

    /// A symlinked host root could move the journal out from under the
    /// checks; it is refused, even when its target is valid.
    #[test]
    fn a_symlinked_host_root_is_refused() {
        let (dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (mut args, command) = matching(&record);
        let link = dir.path().canonicalize().unwrap().join("link");
        std::os::unix::fs::symlink(&args.host_root, &link).unwrap();
        args.host_root = link;
        assert!(issue_as(&args, &command, effective_uid()).is_err());
    }

    /// End to end: the trial-form argv, the journal issuer and the main
    /// loop. A stop before the first attempt saves the trial Stopped.
    #[test]
    fn the_trial_form_runs_the_issued_trial() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let host = recovery::Host::new(root.clone(), record).unwrap();
        let path = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        trial.phase = Phase::Authorized;
        trial.save(&path).unwrap();
        let exit = start::start_with(
            &JournalIssuer {
                args: &args,
                held: std::cell::RefCell::new(None),
            },
            &command,
            || {},
            Clock::now,
            || true,
            || {},
        );
        assert_eq!(exit, start::Start::Exit(0));
        let on_disk = Trial::load(&path, &host.binding().unwrap(), "alice").unwrap();
        assert_eq!(on_disk.phase, Phase::Stopped);
    }

    fn refused(result: io::Result<Option<start::Issued>>) -> bool {
        match result {
            Err(error) => start::is_refusal(&error),
            Ok(_) => false,
        }
    }

    /// Whether another open of `executable`'s install lock can take it now.
    fn lock_is_free(executable: &std::ffi::OsStr) -> bool {
        recovery::lock(Path::new(executable))
            .unwrap()
            .try_lock()
            .is_ok()
    }

    /// #2012 (#2014 review): a passthrough start keeps the daemon install
    /// lock it read the records under, for the caller to hold until the
    /// `exec`; a trial start releases it for `Host::locked`.
    #[test]
    fn a_passthrough_keeps_the_daemon_lock_and_a_trial_releases_it() {
        let (_dir, _root, record) = rooted(journal::Phase::Prepared);
        let (args, command) = matching(&record);
        let mut held = None;
        let uid = effective_uid();
        assert!(issue_held(&args, &command, uid, uid, &mut held, false)
            .unwrap()
            .is_none());
        assert!(held.is_some());
        assert!(!lock_is_free(&command.executable), "held through the exec");
        drop(held);
        assert!(lock_is_free(&command.executable));

        let (_dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let mut held = None;
        assert!(issue_held(&args, &command, uid, uid, &mut held, false)
            .unwrap()
            .is_some());
        assert!(held.is_none());
        assert!(lock_is_free(&command.executable));
    }

    /// #2012: the records are read under the daemon install lock, so a
    /// start waits while the producer holds it.
    #[test]
    fn a_start_waits_for_the_producers_daemon_lock() {
        let (_dir, _root, record) = rooted(journal::Phase::Prepared);
        let (args, command) = matching(&record);
        let producer = recovery::lock(Path::new(&command.executable)).unwrap();
        producer.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let uid = effective_uid();
            let issued =
                issue_held(&args, &command, uid, uid, &mut None, false).map(|i| i.is_none());
            sender.send(issued.unwrap()).unwrap();
        });
        assert!(receiver
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err());
        drop(producer);
        assert!(receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap());
        waiter.join().unwrap();
    }

    /// #2118 review: a unit that names the daemon through a symlink takes
    /// the producer's lock, the one beside the canonical install target.
    #[test]
    fn a_symlinked_daemon_takes_the_canonical_install_lock() {
        let (dir, _root, record) = rooted(journal::Phase::Prepared);
        let (args, mut command) = matching(&record);
        let link = dir.path().canonicalize().unwrap().join("bin-link");
        std::os::unix::fs::symlink(&record.plan.daemon.target_path, &link).unwrap();
        command.executable = link.into_os_string();
        let producer = recovery::lock(&record.plan.daemon.target_path).unwrap();
        producer.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let uid = effective_uid();
            let mut held = None;
            let issued =
                issue_held(&args, &command, uid, uid, &mut held, false).map(|i| i.is_none());
            sender.send((issued.unwrap(), held.is_some())).unwrap();
        });
        assert!(receiver
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err());
        drop(producer);
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap(),
            (true, true)
        );
        waiter.join().unwrap();
    }

    /// #2118 review: a passthrough whose daemon is not the journal's daemon
    /// target is refused.
    #[test]
    fn a_passthrough_of_another_daemon_than_the_journals_is_refused() {
        let (dir, _root, record) = rooted(journal::Phase::Prepared);
        let (args, mut command) = matching(&record);
        let other = dir.path().canonicalize().unwrap().join("other-x0xd");
        std::fs::write(&other, b"").unwrap();
        command.executable = other.into_os_string();
        assert!(refused(issue_as(&args, &command, effective_uid())));
    }

    /// #2118 review: no daemon (or no daemon directory) means nothing to
    /// swap; the start goes on to the missing-daemon wait without the lock,
    /// and `relock` takes it once the daemon is back.
    #[test]
    fn a_missing_daemon_passes_through_without_the_lock_until_it_is_back() {
        let (dir, _root, record) = rooted(journal::Phase::Prepared);
        let (args, mut command) = matching(&record);
        let target = record.plan.daemon.target_path.clone();
        let base = dir.path().canonicalize().unwrap();
        for missing in [base.join("gone/x0xd"), base.join("absent-x0xd")] {
            command.executable = missing.into_os_string();
            let mut held = None;
            let uid = effective_uid();
            assert!(issue_held(&args, &command, uid, uid, &mut held, false)
                .unwrap()
                .is_none());
            assert!(held.is_none());
        }
        let moved = target.with_extension("away");
        std::fs::rename(&target, &moved).unwrap();
        command.executable = target.clone().into_os_string();
        let mut held = None;
        relock(&args, &command, &mut held).unwrap();
        assert!(held.is_none(), "still missing");
        std::fs::rename(&moved, &target).unwrap();
        relock(&args, &command, &mut held).unwrap();
        assert!(held.is_some(), "locked before the exec");
        assert!(!lock_is_free(&command.executable));
    }

    /// #2118 review: a trial-form passthrough never `exec`s without the
    /// install lock. While the daemon is missing it returns `NotFound` for
    /// the missing-daemon wait instead; once the daemon is back it `exec`s
    /// under the lock, and an `exec` that finds it missing releases it.
    #[test]
    fn a_passthrough_execs_only_under_the_install_lock() {
        let (_dir, _root, record) = rooted(journal::Phase::Prepared);
        let (trial, command) = matching(&record);
        let target = record.plan.daemon.target_path.clone();
        let args = LauncherArgs {
            trial: Some(trial),
            command,
        };
        let moved = target.with_extension("away");
        std::fs::rename(&target, &moved).unwrap();
        let mut held = None;
        let mut execs = 0;
        let error = start::exec_locked_with(true, &args, &mut held, |_| {
            execs += 1;
            io::Error::other("exec")
        });
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(forward::is_missing(&error), "the #1379 wait retries it");
        assert_eq!(execs, 0, "no exec without the lock");
        assert!(held.is_none());

        std::fs::rename(&moved, &target).unwrap();
        let error = start::exec_locked_with(true, &args, &mut held, |command| {
            assert!(!lock_is_free(&command.executable), "exec under the lock");
            io::Error::other("exec")
        });
        assert_eq!(error.to_string(), "exec");
        assert!(held.is_some());

        let error = start::exec_locked_with(true, &args, &mut held, |_| {
            io::Error::from(io::ErrorKind::NotFound)
        });
        assert!(forward::is_missing(&error));
        assert!(held.is_none(), "released for the missing-daemon wait");
        assert!(lock_is_free(&args.command.executable));
    }

    /// #2118 review: a daemon path that names another file once the lock is
    /// held is a retryable error, not the lock of the wrong file.
    #[test]
    fn a_daemon_path_that_moves_while_locking_is_retried() {
        let (dir, _root, record) = rooted(journal::Phase::Prepared);
        let target = record.plan.daemon.target_path.clone();
        let other = dir.path().canonicalize().unwrap().join("other-x0xd");
        let calls = std::cell::Cell::new(0);
        let resolve = |_: &Path| {
            calls.set(calls.get() + 1);
            Ok(if calls.get() == 1 {
                target.clone()
            } else {
                other.clone()
            })
        };
        let error =
            daemon_lock_with(&target, std::time::Duration::from_secs(1), &resolve).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(!start::is_refusal(&error));
        assert_eq!(calls.get(), 2);
    }

    /// #2118 review: a trial that is in flight when the daemon is back is
    /// left to the next start (a failed read, not a passthrough).
    #[test]
    fn relock_leaves_an_in_flight_trial_to_the_next_start() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let mut held = None;
        let error = relock(&args, &command, &mut held).unwrap_err();
        assert!(!start::is_refusal(&error), "{error}");
        assert!(held.is_none());
    }

    /// Save alice's trial record in `phase` under `record`'s host.
    fn save_trial(root: &Path, record: &journal::JournalRecord, phase: Phase) {
        let host = recovery::Host::new(root.to_path_buf(), record.clone()).unwrap();
        let path = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        if phase == Phase::Committed {
            trial.attempts = 1;
        }
        trial.phase = phase;
        trial.save(&path).unwrap();
    }

    /// #2118 review: after a start retired its trial on a committed host,
    /// the passthrough takes the install lock, checks the journal's daemon
    /// target and `exec`s under the lock, not a 75 loop. Another daemon is
    /// still refused, and an unretired trial is still left to the next
    /// start.
    #[test]
    fn a_retired_trial_passthrough_execs_under_the_install_lock() {
        let (dir, root, record) = rooted(journal::Phase::HostCommitted);
        save_trial(&root, &record, Phase::Committed);
        let (trial, command) = matching(&record);
        let mut args = LauncherArgs {
            trial: Some(trial),
            command,
        };
        let mut held = None;
        let mut execs = 0;
        let error = start::exec_locked_with(true, &args, &mut held, |command| {
            execs += 1;
            assert!(!lock_is_free(&command.executable), "exec under the lock");
            io::Error::other("exec")
        });
        assert_eq!(error.to_string(), "exec");
        assert_eq!(execs, 1);
        assert!(held.is_some());

        let other = dir.path().canonicalize().unwrap().join("other-x0xd");
        std::fs::write(&other, b"").unwrap();
        args.command.executable = other.into_os_string();
        let mut held = None;
        let error = start::exec_locked_with(true, &args, &mut held, |_| {
            panic!("no exec of another daemon")
        });
        assert!(start::is_refusal(&error), "{error}");
        assert!(held.is_none());

        let (trial, command) = matching(&record);
        std::fs::remove_file(root.join(coordinator::TRIAL_FILE_NAME)).unwrap();
        save_trial(&root, &record, Phase::Authorized);
        let args = LauncherArgs {
            trial: Some(trial),
            command,
        };
        let error = start::exec_locked_with(true, &args, &mut held, |_| {
            panic!("no exec while a trial is unretired")
        });
        assert!(!start::is_refusal(&error), "{error}");
        assert!(held.is_none());
    }

    /// #2118 review: a typed refusal from the re-read before the `exec` is
    /// final and leaves the refusal record; any other `exec` error is a
    /// failed read (75).
    #[test]
    fn a_refusal_at_the_exec_is_final() {
        let (_dir, root, record) = rooted(journal::Phase::Prepared);
        let (trial, command) = matching(&record);
        let args = LauncherArgs {
            trial: Some(trial),
            command,
        };
        let refusal =
            start::refused("the launcher's daemon is not the host journal's daemon target");
        assert!(matches!(
            start::exec_failed(&args, &refusal),
            start::Start::Final(reason) if reason.contains("daemon target")
        ));
        assert!(root.join(contract::REFUSAL_FILE_NAME).is_file());
        assert_eq!(
            start::exec_failed(&args, &io::Error::from(io::ErrorKind::PermissionDenied)),
            start::Start::Exit(start::EXIT_TEMPFAIL)
        );
    }

    /// #2118 review: a symlink or a directory at the install lock path
    /// stays so; it is a typed refusal, not a 75 loop.
    #[test]
    fn an_install_lock_that_is_not_a_regular_file_is_refused() {
        let (dir, _root, record) = rooted(journal::Phase::Prepared);
        let (args, command) = matching(&record);
        let lock = recovery::lock_path(&record.plan.daemon.target_path);
        let elsewhere = dir.path().canonicalize().unwrap().join("elsewhere.lock");
        std::fs::write(&elsewhere, b"").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &lock).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "symlink"
        );
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "directory"
        );
    }

    /// #2118 review: an install lock this account cannot create is a typed
    /// refusal, since another account may lock and swap there.
    #[test]
    fn an_install_lock_this_account_cannot_create_is_refused() {
        if effective_uid() == 0 {
            return;
        }
        let (dir, _root, record) = rooted(journal::Phase::Prepared);
        let (args, mut command) = matching(&record);
        let bin = dir.path().canonicalize().unwrap().join("ro-bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::write(bin.join("x0xd"), b"").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o555)).unwrap();
        command.executable = bin.join("x0xd").into_os_string();
        let result = issue_as(&args, &command, effective_uid());
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = result.err().expect("refused");
        assert!(start::is_refusal(&error), "{error}");
        assert!(error.to_string().contains("install lock"), "{error}");
    }

    /// #2118 review: the wait for the install lock is bounded and then a
    /// failed read, not a refusal.
    #[test]
    fn the_wait_for_the_install_lock_is_bounded() {
        let (_dir, _root, record) = rooted(journal::Phase::Prepared);
        let target = &record.plan.daemon.target_path;
        let producer = recovery::lock(target).unwrap();
        producer.lock().unwrap();
        let error = daemon_lock(target, std::time::Duration::from_millis(200)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!start::is_refusal(&error));
    }

    /// #2012 (#2014 review): an ancestor of the host root that another
    /// account can write could move the root aside; a sticky one cannot.
    #[test]
    fn an_ancestor_others_can_write_is_refused_unless_sticky() {
        let dir = tempfile::tempdir().unwrap();
        // The temporary directory is itself an ancestor; a umask such as
        // 0002 leaves it group-writable.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let shared = dir.path().canonicalize().unwrap().join("shared");
        let root = shared.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = check_root(&root, effective_uid()).unwrap_err();
        assert!(start::is_refusal(&error), "{error}");
        assert!(error.to_string().contains("ancestor"), "{error}");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
        check_root(&root, effective_uid()).unwrap();
    }

    /// #2012 (#2014 review): the records are read relative to the checked
    /// directory, so a rename of the path after the check cannot redirect
    /// them.
    #[test]
    fn records_are_read_from_the_checked_directory() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let opened = open_root(&root, effective_uid()).unwrap();
        let moved = root.with_file_name("moved-aside");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        let read = read_journal(&opened, effective_uid())
            .unwrap()
            .expect("journal");
        assert_eq!(read.transaction_id, record.transaction_id);
        assert!(root
            .join(journal::JOURNAL_FILE_NAME)
            .symlink_metadata()
            .is_err());
        std::fs::remove_dir(&root).unwrap();
        std::fs::rename(&moved, &root).unwrap();
    }

    fn write_0600(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Save alice's trial through `phases` (the save guard checks each).
    fn trial_through(root: &Path, record: &journal::JournalRecord, phases: &[Phase]) {
        let host = recovery::Host::new(root.to_path_buf(), record.clone()).unwrap();
        let path = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        for phase in phases {
            match phase {
                Phase::Booting | Phase::Provisional => {
                    trial.attempts = 1;
                    trial.ready_since_ms = Some(trial.started_ms);
                    trial.child = Some(Identity {
                        pid: 1,
                        start: 1,
                        boot: trial.boot.clone(),
                    });
                }
                _ => trial.child = None,
            }
            trial.phase = phase.clone();
            trial.save(&path).unwrap();
        }
    }

    /// #2014 review item 2: no in-flight journal (absent, or rewritten to
    /// a settled phase) while an unfinished trial is on disk is a fixed
    /// refusal, never an unsupervised start of a swapped candidate.
    #[test]
    fn an_unfinished_trial_without_an_in_flight_journal_is_refused() {
        for unfinished in [
            &[Phase::Authorized][..],
            &[Phase::Authorized, Phase::Booting][..],
            &[Phase::Authorized, Phase::Stopped][..],
        ] {
            let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
            let (args, command) = matching(&record);
            trial_through(&root, &record, unfinished);
            for phase in [
                journal::Phase::Staged,
                journal::Phase::Prepared,
                journal::Phase::Idle,
            ] {
                let mut settled = record.clone();
                settled.phase = phase;
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &settled).unwrap();
                assert!(
                    refused(issue_as(&args, &command, effective_uid())),
                    "{unfinished:?} {phase:?}"
                );
            }
            std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
            assert!(
                refused(issue_as(&args, &command, effective_uid())),
                "{unfinished:?} no journal"
            );
        }
    }

    /// A Committed trial is finished: an idle or absent journal is an
    /// ordinary start.
    #[test]
    fn a_finished_trial_allows_an_ordinary_start() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        trial_through(
            &root,
            &record,
            &[Phase::Authorized, Phase::Provisional, Phase::Committed],
        );
        let mut idle = record.clone();
        idle.phase = journal::Phase::Idle;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &idle).unwrap();
        assert!(issue_as(&args, &command, effective_uid())
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_corrupt_or_unknown_schema_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        write_0600(&journal, b"{ not json");
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "corrupt"
        );
        let mut value = serde_json::to_value(&record).unwrap();
        value["schema_version"] = 99.into();
        write_0600(&journal, &serde_json::to_vec(&value).unwrap());
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "schema 99"
        );
    }

    #[test]
    fn a_participant_in_another_data_root_is_refused() {
        let (_dir, root, mut record) = rooted(journal::Phase::SwappedCli);
        let other = root.join("other");
        std::fs::create_dir(&other).unwrap();
        record.plan.participants[0].data_root = other;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let (mut args, command) = matching(&record);
        args.host_root = root;
        assert!(refused(issue_as(&args, &command, effective_uid())));
    }

    #[test]
    fn a_symlinked_or_irregular_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        let moved = root.join("elsewhere.json");
        std::fs::rename(&journal, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &journal).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "symlink"
        );
        std::fs::remove_file(&journal).unwrap();
        std::fs::create_dir(&journal).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "directory"
        );
    }

    /// Exactly 0600 and this account: 0400 and a foreign owner are refused.
    #[test]
    fn a_journal_that_is_not_0600_of_this_account_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let journal = root.join(journal::JOURNAL_FILE_NAME);
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(refused(issue_as(&args, &command, effective_uid())), "0400");
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(issue_as(&args, &command, effective_uid())
            .unwrap()
            .is_some());
        // Only the journal is foreign: the root check passes, so the
        // descriptor owner check is the one that refuses (#2014 review).
        let foreign = effective_uid().wrapping_add(1);
        assert!(
            refused(issue_with(&args, &command, effective_uid(), foreign)),
            "foreign journal owner"
        );
    }

    /// Fixed refusals exit 78; a failed read (here a host root that does
    /// not exist) exits 75.
    #[test]
    fn issuer_refusals_exit_78_and_read_errors_75() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedDaemon);
        let (args, command) = matching(&record);
        let exit = |args: &TrialArgs| {
            start::start_with(
                &JournalIssuer {
                    args,
                    held: std::cell::RefCell::new(None),
                },
                &command,
                || {},
                Clock::now,
                || false,
                || {},
            )
        };
        assert!(matches!(exit(&args), start::Start::Final(_)));
        let missing = TrialArgs {
            host_root: root.join("missing"),
            instance: "alice".into(),
        };
        assert_eq!(exit(&missing), start::Start::Exit(start::EXIT_TEMPFAIL));
    }

    /// #2015 review: a plan path that is missing may appear by itself (a
    /// volume not yet mounted at boot), so it is a failed read (75), not a
    /// fixed refusal. A plan path that is not canonical stays so: 78.
    #[test]
    fn a_missing_plan_path_retries_and_a_non_canonical_one_is_refused() {
        let (_dir, root, mut record) = rooted(journal::Phase::SwappedCli);
        record.plan.cli.backup_path = root.join("missing-backup");
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let (args, command) = matching(&record);
        let error = issue_as(&args, &command, effective_uid())
            .err()
            .expect("a missing plan path is an error");
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        assert!(!start::is_refusal(&error), "{error}");

        let real = root.join("real-backup");
        std::fs::write(&real, b"cli").unwrap();
        let link = root.join("linked-backup");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        record.plan.cli.backup_path = link;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        assert!(refused(issue_as(&args, &command, effective_uid())));
    }

    /// #2015 review: only the typed refusal is fixed. An untyped
    /// `io::Error::other` (any future I/O helper) is a failed read.
    #[test]
    fn only_a_typed_refusal_is_fixed() {
        assert!(start::is_refusal(&start::refused("fixed")));
        assert!(!start::is_refusal(&io::Error::other("untyped")));
        assert!(!start::is_refusal(&io::Error::from(
            io::ErrorKind::NotFound
        )));
    }

    /// #2015 review: an oversized trial record with no in-flight journal
    /// is a fixed refusal, never a passthrough.
    #[test]
    fn an_oversized_trial_record_is_a_fixed_refusal() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
        let trial = root.join(coordinator::TRIAL_FILE_NAME);
        let file = std::fs::File::create(&trial).unwrap();
        file.set_len(journal::MAX_RECORD_BYTES + 1).unwrap();
        std::fs::set_permissions(&trial, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(refused(issue_as(&args, &command, effective_uid())));
    }

    /// #2014 review item 4: a symlinked or non-regular trial record with no
    /// in-flight journal is a fixed refusal, never a passthrough.
    #[test]
    fn an_unusable_trial_record_is_a_fixed_refusal() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        std::fs::remove_file(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
        let trial = root.join(coordinator::TRIAL_FILE_NAME);
        let target = root.join("elsewhere.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &trial).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "symlink"
        );
        std::fs::remove_file(&trial).unwrap();
        std::fs::create_dir(&trial).unwrap();
        assert!(
            refused(issue_as(&args, &command, effective_uid())),
            "directory"
        );
    }
}
