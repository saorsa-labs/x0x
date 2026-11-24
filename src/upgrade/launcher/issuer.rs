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
            Owners {
                root: uid,
                record: uid,
                anchor: anchor_owner(),
            },
            &mut self.held.borrow_mut(),
            false,
            &process_data_dir,
        )
    }
}

/// The accounts that must own what the issuer reads: the host root and its
/// records (the launcher's account) and the plan anchor (root).
#[derive(Clone, Copy)]
struct Owners {
    root: u32,
    record: u32,
    anchor: u32,
}

impl Owners {
    /// Root, records and anchor all of `uid` (unprivileged tests).
    #[cfg(test)]
    fn of(uid: u32) -> Self {
        Self {
            root: uid,
            record: uid,
            anchor: uid,
        }
    }
}

/// Root owns a plan anchor (`plan_binding::ANCHOR_OWNER`). Unit tests run
/// unprivileged, so they expect their own account; a test that needs a
/// foreign anchor passes the owner itself (`issue_owned`).
fn anchor_owner() -> u32 {
    anchor_owner_for(cfg!(test))
}

/// The anchor owner outside a unit test is root (pinned by
/// `the_production_anchor_owner_is_root`).
fn anchor_owner_for(unit_test: bool) -> u32 {
    if unit_test {
        effective_uid()
    } else {
        plan_binding::ANCHOR_OWNER
    }
}

/// How the issuer finds the data directory of the daemon in the argv.
type DataDir<'a> = &'a dyn Fn(&forward::DaemonCommand) -> io::Result<PathBuf>;

/// The daemon's data directory, as `x0xd` derives it in this environment.
fn process_data_dir(command: &forward::DaemonCommand) -> io::Result<PathBuf> {
    daemon_root::data_dir(&command.args, &daemon_root::Bases::of_process())
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
    let owners = Owners {
        root: root_uid,
        record: record_uid,
        anchor: anchor_owner(),
    };
    issue_owned(args, command, owners)
}

/// As `issue_with`, with every expected owner given.
fn issue_owned(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    owners: Owners,
) -> io::Result<Option<start::Issued>> {
    let data_dir = |_: &forward::DaemonCommand| Ok(args.host_root.clone());
    issue_held(args, command, owners, &mut None, false, &data_dir)
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
///
/// The host root must be the daemon's own data directory (`data_dir`,
/// #1378): records read from any other directory say nothing about this
/// daemon, so a mismatch could pass through to a candidate swapped in under
/// another journal. It is a typed refusal.
///
/// A trial needs the plan anchor the argv names and the plan binding
/// beside the journal (#2012, B4): see `check_binding`.
fn issue_held(
    args: &TrialArgs,
    command: &forward::DaemonCommand,
    owners: Owners,
    held: &mut Option<File>,
    retired: bool,
    data_dir: DataDir<'_>,
) -> io::Result<Option<start::Issued>> {
    let record_uid = owners.record;
    let root = open_root(&args.host_root, owners.root)?;
    let daemon_data = data_dir(command)?;
    if !daemon_root::names_root(&daemon_data, &args.host_root)? {
        return Err(start::refused(format!(
            "--host-root {} is not the daemon's data directory {}",
            args.host_root.display(),
            daemon_data.display()
        )));
    }
    let daemon = daemon_lock(Path::new(&command.executable), DAEMON_LOCK_WAIT)?;
    let Some(record) = read_journal(&root, record_uid)? else {
        no_authority(args, &root)?;
        *held = daemon.map(|(_, lock)| lock);
        return Ok(None);
    };
    if interrupted_swap(record.phase) {
        // A transaction that stopped before its CLI swap was recorded: its
        // producer is gone (it holds the install locks until it exits, and
        // this start holds the daemon lock). Settle it, then let the next
        // start read the settled journal (#2012).
        no_authority(args, &root)?;
        let anchor = read_checked_anchor(args, owners)?;
        if anchor.anchor().daemon_target != record.plan.daemon.target_path
            || anchor.anchor().cli_target != record.plan.cli.target_path
        {
            return Err(other_install(
                &record,
                &anchor.anchor().daemon_target,
                &anchor.anchor().cli_target,
            ));
        }
        drop(daemon);
        settle_interrupted_swap(&args.host_root, &root, record_uid, &record, owners, &anchor)?;
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "an interrupted update was settled (the previous pair is installed and the host \
             journal is superseded); the next start reads it",
        ));
    }
    let passthrough = if owns_trial(record.phase)? {
        retired && committed_trial(args, &root, record.phase)?
    } else {
        no_authority(args, &root)?;
        true
    };
    if passthrough {
        if let Some((canonical, _)) = &daemon {
            if *canonical != record.plan.daemon.target_path {
                return Err(other_install(
                    &record,
                    canonical,
                    &record.plan.cli.target_path,
                ));
            }
        }
        *held = daemon.map(|(_, lock)| lock);
        return Ok(None);
    }
    // The plan must name the anchored install before any lock file is
    // created at the plan's daemon target (#2171 fourth review): a journal
    // of another install pair, or one written by anything else that runs
    // as this account, cannot make the start create a lock file beside a
    // path the anchor does not approve.
    let anchor = read_checked_anchor(args, owners)?;
    if anchor.anchor().daemon_target != record.plan.daemon.target_path
        || anchor.anchor().cli_target != record.plan.cli.target_path
    {
        return Err(other_install(
            &record,
            &anchor.anchor().daemon_target,
            &anchor.anchor().cli_target,
        ));
    }
    // The journal and its binding are read under the install lock of the
    // journal plan's daemon target (#2171 review). A producer stages, and
    // removes an old transaction's binding, only while it holds that lock
    // and the data root's stage lock: `stage` refuses a plan for another
    // install pair over a journal in this data root, so every stage that
    // can write here while this journal exists takes this same lock. When
    // the lock taken above is not that one (the daemon is missing, or the
    // argv names another file), take it now and read the journal again
    // under it. A lock that cannot be taken is a failed read (75), never a
    // refusal from a torn read.
    let own_lock = daemon
        .as_ref()
        .map(|(canonical, lock)| (canonical.as_path(), lock));
    #[cfg(test)]
    tests::before_plan_lock();
    let plan_lock = plan_daemon_lock(&record.plan.daemon.target_path, own_lock, DAEMON_LOCK_WAIT)?;
    let record = if plan_lock.is_some() {
        match read_journal(&root, record_uid)? {
            Some(again) if serde_json::to_vec(&again)? == serde_json::to_vec(&record)? => again,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "the host journal changed while its install lock was taken",
                ))
            }
        }
    } else {
        record
    };
    #[cfg(test)]
    tests::before_binding_read();
    check_binding(&root, &record, owners, &anchor)?;
    drop(plan_lock);
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

/// A journal phase before `SwappedCli` that is not settled: the producer
/// stopped (crash, power loss or kill) between its Staged write and its
/// SwappedCli write. A daemon swap may have happened without its record
/// (#2012 crash row), and a CLI swap without its record.
fn interrupted_swap(phase: journal::Phase) -> bool {
    use journal::Phase::*;
    matches!(phase, Staged | Probed | Prepared | SwappedDaemon)
}

/// Settle an interrupted swap (#2012): under the host lock (CLI lock, then
/// daemon lock, never one held while waiting for the other, bounded by
/// `DAEMON_LOCK_WAIT`), with the journal read again and byte-identical and
/// its binding checked against the anchor, restore every target that holds
/// the candidate from its backup (which must hold the previous release; the
/// backup stays), then write `Superseded`. A target that holds neither the
/// previous nor the candidate release, or a backup that does not hold the
/// previous release, is a typed refusal (78) and nothing is written. An I/O
/// error is a failed read (75).
fn settle_interrupted_swap(
    host_root: &Path,
    root: &File,
    uid: u32,
    record: &journal::JournalRecord,
    owners: Owners,
    anchor: &plan_binding::Anchored,
) -> io::Result<()> {
    let deadline = std::time::Instant::now() + DAEMON_LOCK_WAIT;
    let _locks = loop {
        let cli = recovery::lock(&record.plan.cli.target_path)?;
        let daemon = recovery::lock(&record.plan.daemon.target_path)?;
        if same_file(file_id(&cli.metadata()?), file_id(&daemon.metadata()?)) {
            return Err(start::refused("install locks alias"));
        }
        // A refused daemon lock drops the CLI lock (both files close) before
        // the wait.
        if cli.try_lock().is_ok() && daemon.try_lock().is_ok() {
            break (cli, daemon);
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the host lock is held by another holder",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    #[cfg(test)]
    tests::before_settle();
    let current = match read_journal(root, uid)? {
        Some(again) if serde_json::to_vec(&again)? == serde_json::to_vec(record)? => again,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the host journal changed while its install lock was taken",
            ))
        }
    };
    check_binding(root, &current, owners, anchor)?;
    let mut next = current.clone();
    for (artifact, progress) in [
        (&current.plan.daemon, &mut next.daemon_progress),
        (&current.plan.cli, &mut next.cli_progress),
    ] {
        let observed = filesystem::hash(&artifact.target_path)?;
        if observed == artifact.previous_sha256 {
            continue;
        }
        if observed != artifact.candidate_sha256 {
            return Err(start::refused(format!(
                "an interrupted update left {} holding neither the previous nor the candidate \
                 release; restore it by hand",
                artifact.target_path.display()
            )));
        }
        if filesystem::hash(&artifact.backup_path)? != artifact.previous_sha256 {
            return Err(start::refused(format!(
                "an interrupted update left {} swapped, but its backup {} does not hold the \
                 previous release; restore it by hand",
                artifact.target_path.display(),
                artifact.backup_path.display()
            )));
        }
        filesystem::restore_one(artifact)?;
        if filesystem::hash(&artifact.target_path)? != artifact.previous_sha256 {
            return Err(io::Error::other("restore hash mismatch"));
        }
        progress.restored = true;
        progress.observed_sha256 = Some(artifact.previous_sha256);
    }
    next.phase = journal::Phase::Superseded;
    next.sequence = next
        .sequence
        .checked_add(1)
        .ok_or_else(|| start::refused("journal sequence exhausted"))?;
    journal::write_record(&host_root.join(journal::JOURNAL_FILE_NAME), &next)
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
                "cannot create or open the install lock {} ({error}); let the launcher's \
                 account write that directory, remove a lock file another account \
                 created there (root under sudo, for example) or give it to this \
                 account, or use the plain launcher form",
                recovery::lock_path(&canonical).display()
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

/// The install lock of the journal plan's daemon target, taken within
/// `wait`, or `None` when `held` (the daemon lock this start already holds,
/// with its daemon's canonical path) is that same lock: the same path, or
/// a lock file that is the same file through another path (a plan target
/// that names the install through a symlinked directory). Taking a second
/// lock on the same file would wait on the start's own lock (#2171 fourth
/// review). The lock file is created beside the target even when the
/// binary itself is missing. Every failure (no directory, no access, a
/// lock held past the wait) is a failed read, so the start is retried; a
/// read under no lock could see a torn journal and binding.
fn plan_daemon_lock(
    target: &Path,
    held: Option<(&Path, &File)>,
    wait: std::time::Duration,
) -> io::Result<Option<File>> {
    let retry = |error: io::Error| {
        io::Error::new(
            io::ErrorKind::Interrupted,
            format!(
                "cannot take the install lock {}: {error}",
                recovery::lock_path(target).display()
            ),
        )
    };
    if held.is_some_and(|(canonical, _)| canonical == target) {
        return Ok(None);
    }
    let lock = recovery::lock(target).map_err(retry)?;
    if let Some((_, held)) = held {
        let (a, b) = (
            held.metadata().map_err(retry)?,
            lock.metadata().map_err(retry)?,
        );
        if same_file(file_id(&a), file_id(&b)) {
            return Ok(None);
        }
    }
    let deadline = std::time::Instant::now() + wait;
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(Some(lock)),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(retry(io::Error::new(io::ErrorKind::TimedOut, "still held")))
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(retry(error)),
        }
    }
}

/// Two files are one file only when both the device and the inode are
/// equal: inode numbers repeat across file systems.
fn same_file(a: (u64, u64), b: (u64, u64)) -> bool {
    a == b
}

/// The (device, inode) pair that names one file.
fn file_id(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
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
    let owners = Owners {
        root: uid,
        record: uid,
        anchor: anchor_owner(),
    };
    match issue_held(args, command, owners, held, true, &process_data_dir)? {
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

/// The plan anchor the argv names (#2012, B4): root's and unchangeable by
/// the launcher's account (`plan_binding::read_anchor`). No `--plan-anchor`,
/// and every failed check, is a typed refusal (78): none of them clears by
/// itself. Only an I/O error while reading is a failed read (75).
fn read_checked_anchor(args: &TrialArgs, owners: Owners) -> io::Result<plan_binding::Anchored> {
    let Some(anchor_path) = &args.plan_anchor else {
        return Err(start::refused(
            "a launcher trial needs --plan-anchor; this unit can only pass through",
        ));
    };
    plan_binding::read_anchor(anchor_path, owners.anchor).map_err(|error| {
        if fixed(&error) {
            start::refused(format!("plan anchor {}: {error}", anchor_path.display()))
        } else {
            error
        }
    })
}

/// The journal's integrity binding (#2012, B4): the plan binding beside the
/// journal must be a 0600 regular file of the launcher's account, read
/// through the checked host root, and it must bind this journal's
/// transaction, generation and plan to `anchor`, whose install the plan
/// names exactly. Every failure is a typed refusal (78); only an I/O error
/// while reading is a failed read (75).
fn check_binding(
    root: &File,
    record: &journal::JournalRecord,
    owners: Owners,
    anchor: &plan_binding::Anchored,
) -> io::Result<()> {
    let name = plan_binding::binding_file_name(&record.transaction_id);
    let bytes = match read_owned_at(root, &name, owners.record) {
        Ok(bytes) => bytes,
        Err(error) if fixed(&error) => {
            return Err(start::refused(format!("plan binding: {error}")));
        }
        Err(error) => return Err(error),
    };
    let binding =
        plan_binding::parse_binding(&bytes).map_err(|error| start::refused(error.to_string()))?;
    anchor
        .verify(&binding, record)
        .map_err(|error| start::refused(error.to_string()))
}

/// The typed refusal for a host journal of another install pair in this
/// data root (`contract::REFUSAL_OTHER_INSTALL`): `x0x doctor` names the
/// remedy for it (docs/upgrade-system.md, "Moving a data root to another
/// install").
fn other_install(record: &journal::JournalRecord, daemon: &Path, cli: &Path) -> io::Error {
    start::refused(format!(
        "{}: the host journal ({:?}, transaction {}) is for the install {} with {}, not {} with {}",
        contract::REFUSAL_OTHER_INSTALL,
        record.phase,
        record.transaction_id,
        record.plan.daemon.target_path.display(),
        record.plan.cli.target_path.display(),
        daemon.display(),
        cli.display()
    ))
}

/// An error no restart changes: a missing, symlinked, foreign or malformed
/// anchor or binding.
fn fixed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::PermissionDenied
    ) || error.raw_os_error() == Some(libc::ELOOP)
}

/// A record of this account in the checked directory: opened once without
/// following a symlink, a regular file of `uid` with mode 0600 within the
/// size limit, checked and read on that descriptor. A failed check is
/// `InvalidData`.
fn read_owned_at(root: &File, name: &str, uid: u32) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_at(root, name)?;
    let metadata = file.metadata()?;
    let unusable =
        |reason: &str| io::Error::new(io::ErrorKind::InvalidData, format!("{name} {reason}"));
    if !metadata.is_file() {
        return Err(unusable("is not a regular file"));
    }
    if metadata.uid() != uid {
        return Err(unusable("is not owned by this account"));
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(unusable("does not have mode 0600"));
    }
    if metadata.len() > plan_binding::MAX_BYTES {
        return Err(unusable("exceeds the size limit"));
    }
    let mut bytes = Vec::new();
    file.take(plan_binding::MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// No in-flight journal names this launcher. That is an ordinary start
/// only if no unfinished trial of this participant is on disk: a Booting or
/// Authorized trial means a swapped candidate could start unsupervised, so
/// the start is refused instead (#2014 review). A Committed or Restored
/// trial is finished: its daemon is the installed or the restored bytes.
fn no_authority(args: &TrialArgs, root: &File) -> io::Result<()> {
    let Some(trial) = read_trial(root)? else {
        return Ok(());
    };
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
    Ok(read_trial(root)?
        .is_some_and(|trial| trial.phase == Phase::Committed && trial.instance == args.instance))
}

/// The trial record in the host root; `None` when there is none. A
/// symlinked, non-regular, oversized or unparseable record stays so: a
/// fixed refusal, never a passthrough (#2014 review).
fn read_trial(root: &File) -> io::Result<Option<Trial>> {
    let bytes = match read_record_at(root, coordinator::TRIAL_FILE_NAME) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Err(start::refused(format!("trial record is unusable: {error}")));
        }
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| start::refused("trial record is unreadable"))
}

/// Whether the journal phase gives the launcher trial authority. Idle and
/// superseded records are history (an ordinary start, unless a trial is
/// unfinished). `issue_held` settles the interrupted phases (Staged to
/// SwappedDaemon) before it asks; they stay here as refusals for any other
/// caller.
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

    thread_local! {
        /// Runs once, on this thread, just before the issuer reads the
        /// plan binding.
        static BEFORE_BINDING_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    thread_local! {
        /// Runs once, on this thread, after the start's first journal read
        /// and before it takes the plan's daemon lock.
        static BEFORE_PLAN_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn before_plan_lock() {
        if let Some(hook) = BEFORE_PLAN_LOCK.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
    }

    pub(super) fn before_settle() {
        if let Some(hook) = BEFORE_SETTLE.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
    }

    thread_local! {
        pub(super) static BEFORE_SETTLE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn before_binding_read() {
        if let Some(hook) = BEFORE_BINDING_READ.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
    }

    #[test]
    fn the_production_anchor_owner_is_root() {
        assert_eq!(anchor_owner_for(false), 0);
        assert_eq!(anchor_owner_for(true), effective_uid());
    }

    /// Stage a new transaction `tx` over the journal in `root` (as the
    /// producer does), with the journal write failing at `failure` if set.
    fn stage_over(
        root: &Path,
        record: &journal::JournalRecord,
        tx: &str,
        failure: Option<journal::BarrierStep>,
    ) -> io::Result<()> {
        use super::super::prepare::{tests as producer, HostLock, Prepared};
        let lock = HostLock::acquire_within(&record.plan, std::time::Duration::from_millis(200))?;
        if let Some(step) = failure {
            producer::fail_journal_write(step);
        }
        let anchor = plan_binding::test_anchored(&record.plan);
        Prepared::stage(&lock, root, tx, record.plan.clone(), &anchor).map(drop)
    }

    /// #2171 review (a), (b): on a committed or restored host, which still
    /// gives its launcher a trial, a new stage that dies after its binding
    /// (a binding-only write, or a journal write that fails at any barrier
    /// step) leaves a startable host: the start issues the current
    /// transaction, or the new journal if it became durable.
    #[test]
    fn a_stage_that_dies_after_its_binding_leaves_a_startable_host() {
        for phase in [journal::Phase::HostCommitted, journal::Phase::Restored] {
            // A binding-only write for the next transaction, then a crash.
            let (_dir, root, record) = rooted(phase);
            let (args, command) = matching(&record);
            let mut next = record.clone();
            next.transaction_id = "tx-next".into();
            let binding = plan_binding::test_anchored(&next.plan)
                .bind(&next.transaction_id, next.generation, &next.plan)
                .unwrap();
            journal::write_auxiliary_record(
                &root.join(plan_binding::binding_file_name("tx-next")),
                &binding,
                plan_binding::validate_binding,
            )
            .unwrap();
            let issued = issue_as(&args, &command, effective_uid());
            assert!(matches!(issued, Ok(Some(_))), "{phase:?}: binding-only");

            // A real stage whose journal write fails at each barrier step.
            for step in [
                journal::BarrierStep::Write,
                journal::BarrierStep::FileSync,
                journal::BarrierStep::Rename,
                journal::BarrierStep::DirectorySync,
            ] {
                let (_dir, root, record) = rooted(phase);
                let (args, command) = matching(&record);
                assert!(stage_over(&root, &record, "tx-next", Some(step)).is_err());
                match issue_as(&args, &command, effective_uid()) {
                    // The journal stayed: the current transaction issues.
                    Ok(Some(issued)) => {
                        // At the directory sync the new journal is already
                        // in place, so only an ordinary start is right.
                        assert!(
                            !matches!(step, journal::BarrierStep::DirectorySync),
                            "{phase:?} {step:?}"
                        );
                        assert_eq!(issued.host.root(), root, "{phase:?} {step:?}")
                    }
                    // The rename landed before the failure: the new Staged
                    // journal is an interrupted transaction over the
                    // installed bytes, which the start settles (#2012).
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        assert!(
                            matches!(step, journal::BarrierStep::DirectorySync),
                            "{phase:?} {step:?}"
                        );
                        assert!(issue_as(&args, &command, effective_uid())
                            .unwrap()
                            .is_none());
                    }
                    Ok(None) => {
                        panic!("{phase:?} {step:?}: a Staged journal is never a passthrough")
                    }
                    Err(error) => panic!("{phase:?} {step:?}: {error}"),
                }
            }
        }
    }

    /// Arm the hook to try `stage` just before the binding read; returns
    /// whether that stage went through.
    fn race_before_binding_read(
        stage: impl FnOnce() -> io::Result<()> + 'static,
    ) -> std::rc::Rc<std::cell::Cell<Option<bool>>> {
        let staged = std::rc::Rc::new(std::cell::Cell::new(None));
        let hook_staged = staged.clone();
        BEFORE_BINDING_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                hook_staged.set(Some(stage().is_ok()));
            }))
        });
        staged
    }

    /// #2171 review 3 (a): a racing stage for another install pair (another
    /// daemon target, so another daemon lock) over this data root is
    /// refused by the producer, so it cannot remove the binding between the
    /// start's two reads.
    #[test]
    fn a_racing_stage_for_another_install_pair_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::HostCommitted);
        let (args, command) = matching(&record);
        let mut other = record.clone();
        let other_daemon = root.join("other-daemon.d");
        std::fs::write(&other_daemon, b"other").unwrap();
        other.plan.daemon.target_path = other_daemon.clone();
        for participant in &mut other.plan.participants {
            participant.executable = other_daemon.clone();
            participant.argv[0] = other_daemon.to_string_lossy().into_owned();
        }
        let staged = race_before_binding_read(move || {
            use super::super::prepare::{HostLock, Prepared};
            let lock =
                HostLock::acquire_within(&other.plan, std::time::Duration::from_millis(200))?;
            let anchor = plan_binding::test_anchored(&other.plan);
            Prepared::stage(&lock, &root, "tx-racer", other.plan.clone(), &anchor).map(drop)
        });
        let issued = issue_as(&args, &command, effective_uid());
        assert_eq!(staged.get(), Some(false), "the other pair's stage ran");
        assert!(matches!(issued, Ok(Some(_))));
    }

    /// #2171 review 3 (b): with the daemon binary missing, the start still
    /// reads the journal and binding under the journal plan's daemon lock,
    /// so a same-pair stage cannot run in between; the missing binary is
    /// then a failed read (75), not a refusal.
    #[test]
    fn a_missing_daemon_still_reads_under_the_plans_lock() {
        let (_dir, root, record) = rooted(journal::Phase::HostCommitted);
        let (args, command) = matching(&record);
        std::fs::remove_file(&record.plan.daemon.target_path).unwrap();
        let (hook_root, hook_record) = (root.clone(), record.clone());
        let staged = race_before_binding_read(move || {
            stage_over(&hook_root, &hook_record, "tx-racer", None)
        });
        let error = issue_as(&args, &command, effective_uid())
            .err()
            .expect("the missing daemon is an error");
        assert_eq!(staged.get(), Some(false), "the racing stage got the lock");
        assert!(!start::is_refusal(&error), "{error}");
        assert!(root
            .join(plan_binding::binding_file_name(&record.transaction_id))
            .exists());
    }

    /// Replace the journal in `root` with `record`, as a writer would.
    fn rewrite(root: &Path, record: &journal::JournalRecord) {
        let path = root.join(journal::JOURNAL_FILE_NAME);
        std::fs::remove_file(&path).unwrap();
        journal::write_record(&path, record).unwrap();
    }

    /// Point `record`'s plan, and every participant, at the daemon `target`.
    fn retarget(record: &mut journal::JournalRecord, target: PathBuf) {
        for participant in &mut record.plan.participants {
            participant.executable = target.clone();
            participant.argv[0] = target.to_string_lossy().into_owned();
        }
        record.plan.daemon.target_path = target;
    }

    /// #2171 fourth review: when the argv names another daemon file than the
    /// journal plan's target, the start reads the binding under the lock of
    /// the PLAN's daemon target, not the argv's: a same-pair stage cannot
    /// run before the binding read.
    #[test]
    fn the_binding_is_read_under_the_plans_lock_not_the_argvs() {
        let (dir, root, record) = rooted(journal::Phase::HostCommitted);
        let (args, mut command) = matching(&record);
        let other = dir.path().canonicalize().unwrap().join("argv-x0xd");
        std::fs::write(&other, b"").unwrap();
        command.executable = other.into_os_string();
        let (hook_root, hook_record) = (root.clone(), record.clone());
        let staged = race_before_binding_read(move || {
            stage_over(&hook_root, &hook_record, "tx-racer", None)
        });
        let _ = issue_as(&args, &command, effective_uid());
        assert_eq!(
            staged.get(),
            Some(false),
            "the racing stage got the plan's lock"
        );
        assert!(root
            .join(plan_binding::binding_file_name(&record.transaction_id))
            .exists());
    }

    /// #2171 fourth review: a journal that changes between the start's
    /// first read and the plan's daemon lock is a failed read (75), both
    /// when a new transaction replaced it and when the same transaction
    /// moved on. The read under the lock is what the start uses.
    #[test]
    fn a_journal_that_changes_before_the_plans_lock_is_a_failed_read() {
        for same_transaction in [false, true] {
            let (_dir, root, record) = rooted(journal::Phase::HostCommitted);
            let (args, command) = matching(&record);
            // No daemon, so the start holds no lock until the plan's.
            std::fs::remove_file(&record.plan.daemon.target_path).unwrap();
            let (hook_root, hook_record) = (root.clone(), record.clone());
            BEFORE_PLAN_LOCK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    if same_transaction {
                        let mut moved = hook_record.clone();
                        moved.sequence += 1;
                        rewrite(&hook_root, &moved);
                    } else {
                        stage_over(&hook_root, &hook_record, "tx-racer", None).unwrap();
                    }
                }))
            });
            let error = issue_as(&args, &command, effective_uid())
                .err()
                .expect("a changed journal is an error");
            let case = format!("same transaction {same_transaction}");
            assert!(!start::is_refusal(&error), "{case}: {error}");
            assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{case}: {error}");
            assert!(
                error.to_string().contains("changed while"),
                "{case}: {error}"
            );
        }
    }

    /// #2171 fourth review: the plan is checked against the root-owned
    /// anchor before any lock file is created at the plan's daemon target.
    /// A journal whose plan names a target the anchor does not approve is a
    /// typed refusal and leaves no lock file there.
    #[test]
    fn no_plan_lock_file_is_created_outside_the_anchored_install() {
        let (dir, root, mut record) = rooted(journal::Phase::HostCommitted);
        let (args, command) = matching(&record);
        let elsewhere = dir.path().canonicalize().unwrap().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        retarget(&mut record, elsewhere.join("x0xd"));
        rewrite(&root, &record);
        let error = issue_as(&args, &command, effective_uid())
            .err()
            .expect("refused");
        assert!(start::is_refusal(&error), "{error}");
        assert!(
            error
                .to_string()
                .starts_with(contract::REFUSAL_OTHER_INSTALL),
            "{error}"
        );
        assert!(!recovery::lock_path(&elsewhere.join("x0xd")).exists());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    /// #2171 fourth review: a plan daemon target that names the argv's
    /// daemon through a symlinked directory has the same lock file. The
    /// start does not wait on its own lock (30 s, then a failed read); it
    /// goes on at once to the checks, here the non-canonical plan path,
    /// which is a typed refusal.
    #[test]
    fn a_plan_target_through_a_symlinked_directory_reuses_the_held_lock() {
        let (dir, root, mut record) = rooted(journal::Phase::HostCommitted);
        let (args, command) = matching(&record);
        let target = record.plan.daemon.target_path.clone();
        let alias = dir.path().canonicalize().unwrap().join("alias");
        std::os::unix::fs::symlink(target.parent().unwrap(), &alias).unwrap();
        retarget(&mut record, alias.join(target.file_name().unwrap()));
        rewrite(&root, &record);
        bind(&root, &record);
        let begun = std::time::Instant::now();
        let result = issue_as(&args, &command, effective_uid());
        assert!(
            begun.elapsed() < std::time::Duration::from_secs(10),
            "the start waited on its own lock"
        );
        assert!(refused(result));
    }

    /// #2186 review: the same-file check needs both halves; the same inode
    /// on another device is another file.
    #[test]
    fn same_file_compares_device_and_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(file_id(&meta), (meta.dev(), meta.ino()));
        assert!(same_file((1, 5), (1, 5)));
        assert!(!same_file((1, 5), (2, 5)));
        assert!(!same_file((1, 5), (1, 6)));
    }

    /// #2171 review 3 (b): a plan lock that cannot be taken (its directory
    /// is gone) is a failed read, never a refusal.
    #[test]
    fn a_plan_lock_that_cannot_be_taken_is_a_failed_read() {
        let error = plan_daemon_lock(
            Path::new("/nonexistent-x0x-dir/x0xd"),
            None,
            std::time::Duration::from_millis(10),
        )
        .expect_err("no directory");
        assert!(!start::is_refusal(&error), "{error}");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    /// #2171 review (c): a stage that tries to run between the start's
    /// journal read and its binding read cannot, because the start holds
    /// the daemon install lock across both; it issues the journal it read.
    #[test]
    fn a_stage_cannot_run_between_the_journal_and_the_binding_read() {
        let (_dir, root, record) = rooted(journal::Phase::HostCommitted);
        let (args, command) = matching(&record);
        let staged = std::rc::Rc::new(std::cell::Cell::new(None));
        let (hook_root, hook_record, hook_staged) = (root.clone(), record.clone(), staged.clone());
        BEFORE_BINDING_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                hook_staged.set(Some(
                    stage_over(&hook_root, &hook_record, "tx-racer", None).is_ok(),
                ));
            }))
        });
        let issued = issue_as(&args, &command, effective_uid());
        assert_eq!(staged.get(), Some(false), "the racing stage got the lock");
        assert!(matches!(issued, Ok(Some(_))));
    }

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
                plan_anchor: None,
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
                plan_anchor: Some(alice.data_root.join(plan_binding::TEST_ANCHOR_NAME)),
            },
            forward::DaemonCommand {
                executable: alice.executable.clone().into_os_string(),
                args: alice.argv.iter().skip(1).map(OsString::from).collect(),
            },
        )
    }

    /// The fixture's journal is in alice's data root, the launcher's host
    /// root. Alice gets daemon arguments, so argument checks bite.
    /// Alice's argv names a config file that sets the host root as her
    /// data directory, so the issuer's data directory check passes in any
    /// environment.
    fn rooted(phase: journal::Phase) -> (tempfile::TempDir, PathBuf, journal::JournalRecord) {
        let (dir, root, _host, record) = fixture_with(phase, |record| {
            let alice = &mut record.plan.participants[0];
            let config = alice.data_root.join("x0xd.toml");
            alice.argv.push("--config".into());
            alice.argv.push(config.to_string_lossy().into_owned());
        });
        set_data_dir(&root, &root);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, root, record)
    }

    /// Point the config file of `rooted`'s alice at `data_dir`.
    fn set_data_dir(root: &Path, data_dir: &Path) {
        std::fs::write(
            root.join("x0xd.toml"),
            format!("data_dir = {:?}\n", data_dir.to_str().unwrap()),
        )
        .unwrap();
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
        // The installer's anchor for the same install (#2012, B4).
        plan_binding::write_test_anchor(&root, &prepared.record().plan);
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

    /// #2012 (B4): a trial needs the plan anchor the argv names. Without
    /// `--plan-anchor` (a unit an older installer wrote) an in-flight
    /// journal is a fixed refusal, never a trial and never a passthrough.
    #[test]
    fn a_trial_needs_its_plan_anchor() {
        let (_dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (mut args, command) = matching(&record);
        args.plan_anchor = None;
        let error = issue_as(&args, &command, effective_uid())
            .err()
            .expect("refused");
        assert!(start::is_refusal(&error), "{error}");
        assert!(error.to_string().contains("--plan-anchor"), "{error}");
    }

    /// #2012 (B4): the anchor must be root's (here: the expected owner),
    /// not writable by group or others, and not a symlink.
    #[test]
    fn a_foreign_writable_or_linked_anchor_is_refused() {
        let (dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (mut args, command) = matching(&record);
        let uid = effective_uid();
        let foreign = Owners {
            anchor: uid + 1,
            ..Owners::of(uid)
        };
        assert!(refused(issue_owned(&args, &command, foreign)), "foreign");
        let anchor = root.join(plan_binding::TEST_ANCHOR_NAME);
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(refused(issue_as(&args, &command, uid)), "writable");
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().canonicalize().unwrap().join("anchor-link");
        std::os::unix::fs::symlink(&anchor, &link).unwrap();
        args.plan_anchor = Some(link);
        assert!(refused(issue_as(&args, &command, uid)), "symlink");
        args.plan_anchor = Some(root.join("no-such-anchor"));
        assert!(refused(issue_as(&args, &command, uid)), "missing");
    }

    /// #2012 (B4): a missing plan binding, or one that is not a 0600 file
    /// of this account, is a fixed refusal.
    #[test]
    fn a_missing_or_loose_plan_binding_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let uid = effective_uid();
        let binding = root.join(plan_binding::binding_file_name(&record.transaction_id));
        let refused_for = |reason: &str| {
            let error = issue_as(&args, &command, uid).err().expect("refused");
            assert!(start::is_refusal(&error), "{error}");
            assert!(
                error.to_string().contains(reason),
                "want {reason:?}: {error}"
            );
        };
        // Each check alone: mode, owner, type, a symlink to a valid
        // binding (only the no-follow open refuses it), missing.
        std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o644)).unwrap();
        refused_for("does not have mode 0600");
        std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(issue_as(&args, &command, uid).unwrap().is_some());
        let dir = open_root(&root, uid).unwrap();
        let error = read_owned_at(
            &dir,
            &plan_binding::binding_file_name(&record.transaction_id),
            uid + 1,
        )
        .expect_err("foreign");
        assert!(
            error.to_string().contains("not owned by this account"),
            "{error}"
        );
        let valid = root.join("valid-binding.json");
        std::fs::rename(&binding, &valid).unwrap();
        std::os::unix::fs::symlink(&valid, &binding).unwrap();
        refused_for("plan binding");
        std::fs::remove_file(&binding).unwrap();
        std::fs::create_dir(&binding).unwrap();
        refused_for("is not a regular file");
        std::fs::remove_dir(&binding).unwrap();
        refused_for("plan binding");
        std::fs::rename(&valid, &binding).unwrap();
        assert!(issue_as(&args, &command, uid).unwrap().is_some());
    }

    /// #2012 (B4): the binding must bind this journal's plan, transaction
    /// and generation to this anchor, and the plan must name exactly the
    /// anchored install.
    #[test]
    fn a_binding_that_does_not_bind_this_journal_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let uid = effective_uid();
        let journal_path = root.join(journal::JOURNAL_FILE_NAME);
        assert!(issue_as(&args, &command, uid).unwrap().is_some());

        // The plan changed after the binding was written.
        let mut changed = record.clone();
        changed.plan.candidate_version = "9.9.10".into();
        journal::write_record(&journal_path, &changed).unwrap();
        assert!(refused(issue_as(&args, &command, uid)), "plan");

        // Another transaction, then another generation.
        let mut other = record.clone();
        other.transaction_id = "another-transaction".into();
        journal::write_record(&journal_path, &other).unwrap();
        assert!(refused(issue_as(&args, &command, uid)), "transaction");
        let mut other = record.clone();
        other.generation = 2;
        journal::write_record(&journal_path, &other).unwrap();
        assert!(refused(issue_as(&args, &command, uid)), "generation");

        // The anchor changed after the binding was written.
        journal::write_record(&journal_path, &record).unwrap();
        assert!(issue_as(&args, &command, uid).unwrap().is_some());
        let anchor = root.join(plan_binding::TEST_ANCHOR_NAME);
        let mut text = std::fs::read_to_string(&anchor).unwrap();
        text.push('\n');
        std::fs::write(&anchor, text).unwrap();
        assert!(refused(issue_as(&args, &command, uid)), "anchor");
    }

    /// #2012 (B4): an anchor for another install pair or another set of
    /// participants refuses the plan, even with a binding made against it.
    #[test]
    fn a_plan_outside_the_anchored_install_is_refused() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let uid = effective_uid();
        let anchor = root.join(plan_binding::TEST_ANCHOR_NAME);
        type Edit = (fn(&mut serde_json::Value), &'static str);
        let edits: [Edit; 4] = [
            (
                |a| a["cli_target"] = "/usr/local/bin/other-x0x".into(),
                contract::REFUSAL_OTHER_INSTALL,
            ),
            (
                |a| a["daemon_target"] = "/usr/local/bin/other-x0xd".into(),
                contract::REFUSAL_OTHER_INSTALL,
            ),
            (
                |a| {
                    a["participants"].as_array_mut().unwrap().push(
                        serde_json::json!({"instance_id": "bob", "data_root": "/var/lib/bob"}),
                    )
                },
                "anchored",
            ),
            (
                |a| a["participants"][0]["data_root"] = "/var/lib/elsewhere".into(),
                "anchored",
            ),
        ];
        for (edit, expected) in edits {
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&anchor).unwrap()).unwrap();
            edit(&mut value);
            std::fs::write(&anchor, serde_json::to_vec(&value).unwrap()).unwrap();
            let anchored = plan_binding::read_test_anchor(&anchor);
            // A binding made against the edited anchor, bypassing the
            // producer's own check.
            let binding = plan_binding::PlanBinding {
                schema: 1,
                record_kind: "plan_binding".into(),
                transaction_id: record.transaction_id.clone(),
                generation: record.generation,
                plan_sha256: plan_binding::plan_sha256(&record.plan).unwrap(),
                anchor_sha256: anchored.sha256(),
            };
            journal::write_auxiliary_record(
                &root.join(plan_binding::binding_file_name(&record.transaction_id)),
                &binding,
                plan_binding::validate_binding,
            )
            .unwrap();
            let error = issue_as(&args, &command, uid).err().expect("refused");
            assert!(start::is_refusal(&error), "{error}");
            assert!(error.to_string().contains(expected), "{error}");
            bind(&root, &record);
        }
    }

    #[test]
    fn no_journal_or_a_settled_one_is_an_ordinary_start() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        for phase in [journal::Phase::Idle, journal::Phase::Superseded] {
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
        // A passthrough needs no anchor and no binding (#2012, B4).
        std::fs::remove_file(root.join(plan_binding::binding_file_name(&record.transaction_id)))
            .unwrap();
        let mut unanchored = args.clone();
        unanchored.plan_anchor = None;
        assert!(issue_as(&unanchored, &command, effective_uid())
            .unwrap()
            .is_none());
    }

    fn journal_at(root: &Path) -> journal::JournalRecord {
        let journal::RecordRead::Journal(record) = journal::read_boot_records(root).journal else {
            panic!("no journal");
        };
        *record
    }

    fn set_phase(root: &Path, record: &journal::JournalRecord, phase: journal::Phase) {
        let mut changed = record.clone();
        changed.phase = phase;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &changed).unwrap();
    }

    /// #2012 (the open crash row of PR 2): the producer swapped the daemon
    /// and stopped before its SwappedDaemon record, so a Prepared journal
    /// lies over candidate bytes. A start restores the previous daemon from
    /// its backup (the backup stays), writes Superseded and asks for the
    /// next start (75); that start is an ordinary one on the previous
    /// release. Red: the pre-#2012 issuer passed through to the candidate.
    #[test]
    fn a_swap_without_its_record_is_restored_and_superseded() {
        for phase in [
            journal::Phase::Staged,
            journal::Phase::Probed,
            journal::Phase::Prepared,
            journal::Phase::SwappedDaemon,
        ] {
            let (_dir, root, record) = rooted(phase);
            let (args, command) = matching(&record);
            let plan = &record.plan;
            // The CLI is still the previous release; the daemon is not.
            std::fs::copy(&plan.cli.backup_path, &plan.cli.target_path).unwrap();
            let error = issue_as(&args, &command, effective_uid())
                .err()
                .expect("settled, not a start");
            assert_eq!(
                error.kind(),
                io::ErrorKind::Interrupted,
                "{phase:?}: {error}"
            );
            assert!(!start::is_refusal(&error), "{error}");
            for artifact in [&plan.daemon, &plan.cli] {
                assert_eq!(
                    filesystem::hash(&artifact.target_path).unwrap(),
                    artifact.previous_sha256,
                    "{phase:?}"
                );
                assert_eq!(
                    filesystem::hash(&artifact.backup_path).unwrap(),
                    artifact.previous_sha256,
                    "the backup stays"
                );
            }
            let settled = journal_at(&root);
            assert_eq!(settled.phase, journal::Phase::Superseded);
            assert_eq!(settled.sequence, record.sequence + 1);
            assert!(settled.daemon_progress.restored && !settled.cli_progress.restored);
            assert!(issue_as(&args, &command, effective_uid())
                .unwrap()
                .is_none());
        }
    }

    /// A daemon and a CLI both swapped without SwappedCli (a crash between
    /// the CLI swap and its record) are both restored.
    #[test]
    fn a_cli_swap_without_its_record_is_restored_too() {
        let (_dir, root, record) = rooted(journal::Phase::SwappedDaemon);
        let (args, command) = matching(&record);
        let error = issue_as(&args, &command, effective_uid()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{error}");
        let settled = journal_at(&root);
        assert_eq!(settled.phase, journal::Phase::Superseded);
        assert!(settled.daemon_progress.restored && settled.cli_progress.restored);
        for artifact in [&record.plan.daemon, &record.plan.cli] {
            assert_eq!(
                filesystem::hash(&artifact.target_path).unwrap(),
                artifact.previous_sha256
            );
        }
    }

    /// An interrupted journal over the previous pair is settled without a
    /// restore, so later applies are not refused for ever.
    #[test]
    fn an_interrupted_journal_over_the_previous_pair_is_superseded() {
        let (_dir, root, record) = rooted(journal::Phase::Prepared);
        let (args, command) = matching(&record);
        for artifact in [&record.plan.daemon, &record.plan.cli] {
            std::fs::copy(&artifact.backup_path, &artifact.target_path).unwrap();
        }
        let error = issue_as(&args, &command, effective_uid()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{error}");
        let settled = journal_at(&root);
        assert_eq!(settled.phase, journal::Phase::Superseded);
        assert!(!settled.daemon_progress.restored && !settled.cli_progress.restored);
    }

    /// Each check before the settle alone refuses it, and nothing changes:
    /// unrelated bytes at a target, a backup that is not the previous
    /// release, no plan anchor, a binding that does not bind the journal,
    /// an unfinished trial. A journal that changes while the host lock is
    /// taken is a failed read (75).
    #[test]
    fn an_interrupted_swap_is_settled_only_when_every_check_passes() {
        type Spoil = fn(&Path, &journal::JournalRecord, &mut TrialArgs);
        let spoils: [(Spoil, &str); 5] = [
            (
                |_, record, _| {
                    std::fs::write(&record.plan.daemon.target_path, b"unrelated").unwrap()
                },
                "neither the previous nor the candidate",
            ),
            (
                |_, record, _| std::fs::write(&record.plan.daemon.backup_path, b"other").unwrap(),
                "does not hold the previous release",
            ),
            (|_, _, args| args.plan_anchor = None, "--plan-anchor"),
            (
                |root, record, _| {
                    std::fs::remove_file(
                        root.join(plan_binding::binding_file_name(&record.transaction_id)),
                    )
                    .unwrap()
                },
                "plan binding",
            ),
            (
                |root, record, _| {
                    let host = recovery::Host::new(root.to_path_buf(), record.clone()).unwrap();
                    let trial = Trial::new(
                        host.binding().unwrap(),
                        "alice".into(),
                        &Clock {
                            boot: "b".into(),
                            ms: 1,
                        },
                    )
                    .unwrap();
                    trial
                        .save(&root.join(coordinator::TRIAL_FILE_NAME))
                        .unwrap();
                },
                "unfinished trial",
            ),
        ];
        for (spoil, reason) in spoils {
            let (_dir, root, record) = rooted(journal::Phase::Prepared);
            let (mut args, command) = matching(&record);
            spoil(&root, &record, &mut args);
            let daemon = std::fs::read(&record.plan.daemon.target_path).unwrap();
            let error = issue_as(&args, &command, effective_uid()).err().unwrap();
            assert!(start::is_refusal(&error), "{reason}: {error}");
            assert!(error.to_string().contains(reason), "{reason}: {error}");
            assert_eq!(
                journal_at(&root).phase,
                journal::Phase::Prepared,
                "{reason}"
            );
            assert_eq!(
                std::fs::read(&record.plan.daemon.target_path).unwrap(),
                daemon
            );
        }
        let (_dir, root, record) = rooted(journal::Phase::Prepared);
        let (args, command) = matching(&record);
        let (again, changed) = (root.clone(), record.clone());
        tests::BEFORE_SETTLE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                set_phase(&again, &changed, journal::Phase::Probed)
            }))
        });
        let error = issue_as(&args, &command, effective_uid()).err().unwrap();
        assert!(!start::is_refusal(&error), "{error}");
        assert_eq!(journal_at(&root).phase, journal::Phase::Probed);
        assert_eq!(
            filesystem::hash(&record.plan.daemon.target_path).unwrap(),
            record.plan.daemon.candidate_sha256,
            "a failed read restores nothing"
        );
    }

    /// The settle takes the host lock: while the CLI lock is held by
    /// another holder (a producer), the start waits and nothing changes.
    #[test]
    fn an_interrupted_swap_waits_for_the_host_lock() {
        let (_dir, root, record) = rooted(journal::Phase::Prepared);
        let (args, command) = matching(&record);
        let cli = recovery::lock(&record.plan.cli.target_path).unwrap();
        cli.lock().unwrap();
        let started = std::time::Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        let held = std::thread::spawn(move || {
            rx.recv().unwrap();
            drop(cli);
        });
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            tx.send(()).unwrap();
        });
        let error = issue_as(&args, &command, effective_uid()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{error}");
        assert!(started.elapsed() >= std::time::Duration::from_millis(350));
        assert_eq!(journal_at(&root).phase, journal::Phase::Superseded);
        held.join().unwrap();
        releaser.join().unwrap();
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

    /// #1378: a host root that is not the daemon's data directory reads
    /// another directory's records. Here it holds no journal, while the
    /// daemon's own directory holds a swapped pair: the start is a typed
    /// refusal (78), not a passthrough to the candidate.
    #[test]
    fn a_host_root_that_is_not_the_daemons_data_directory_is_refused() {
        let (dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (mut args, command) = matching(&record);
        let elsewhere = dir.path().canonicalize().unwrap().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
        args.host_root = elsewhere;
        let uid = effective_uid();
        let error = issue_held(
            &args,
            &command,
            Owners::of(uid),
            &mut None,
            false,
            &process_data_dir,
        )
        .err()
        .expect("refused");
        assert!(start::is_refusal(&error), "{error}");
        assert!(error.to_string().contains("data directory"), "{error}");
        let exit = start::start_with(
            &JournalIssuer {
                args: &args,
                held: std::cell::RefCell::new(None),
            },
            &command,
            || {},
            Clock::now,
            || false,
            || {},
        );
        assert!(matches!(exit, start::Start::Final(_)), "{exit:?}");
        assert!(relock(&args, &command, &mut None).is_err_and(|e| start::is_refusal(&e)));
        assert!(root.join(journal::JOURNAL_FILE_NAME).is_file());
    }

    /// #1378: a daemon data directory that is a symlink to the host root is
    /// not the host root; the link is never followed.
    #[test]
    fn a_daemon_data_directory_that_links_to_the_host_root_is_refused() {
        let (dir, root, record) = rooted(journal::Phase::Idle);
        let (args, command) = matching(&record);
        let link = dir.path().canonicalize().unwrap().join("data-link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        set_data_dir(&root, &link);
        let uid = effective_uid();
        let error = issue_held(
            &args,
            &command,
            Owners::of(uid),
            &mut None,
            false,
            &process_data_dir,
        )
        .err()
        .expect("refused");
        assert!(start::is_refusal(&error), "{error}");
        set_data_dir(&root, &root);
        assert!(issue_held(
            &args,
            &command,
            Owners::of(uid),
            &mut None,
            false,
            &process_data_dir
        )
        .unwrap()
        .is_none());
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
        let (_dir, _root, record) = rooted(journal::Phase::Idle);
        let (args, command) = matching(&record);
        let mut held = None;
        let uid = effective_uid();
        assert!(issue_held(
            &args,
            &command,
            Owners::of(uid),
            &mut held,
            false,
            &process_data_dir
        )
        .unwrap()
        .is_none());
        assert!(held.is_some());
        assert!(!lock_is_free(&command.executable), "held through the exec");
        drop(held);
        assert!(lock_is_free(&command.executable));

        let (_dir, _root, record) = rooted(journal::Phase::SwappedCli);
        let (args, command) = matching(&record);
        let mut held = None;
        assert!(issue_held(
            &args,
            &command,
            Owners::of(uid),
            &mut held,
            false,
            &process_data_dir
        )
        .unwrap()
        .is_some());
        assert!(held.is_none());
        assert!(lock_is_free(&command.executable));
    }

    /// #2012: the records are read under the daemon install lock, so a
    /// start waits while the producer holds it.
    #[test]
    fn a_start_waits_for_the_producers_daemon_lock() {
        let (_dir, _root, record) = rooted(journal::Phase::Idle);
        let (args, command) = matching(&record);
        let producer = recovery::lock(Path::new(&command.executable)).unwrap();
        producer.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let uid = effective_uid();
            let issued = issue_held(
                &args,
                &command,
                Owners::of(uid),
                &mut None,
                false,
                &process_data_dir,
            )
            .map(|i| i.is_none());
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
        let (dir, _root, record) = rooted(journal::Phase::Idle);
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
            let issued = issue_held(
                &args,
                &command,
                Owners::of(uid),
                &mut held,
                false,
                &process_data_dir,
            )
            .map(|i| i.is_none());
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
        let (dir, _root, record) = rooted(journal::Phase::Idle);
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
        let (dir, _root, record) = rooted(journal::Phase::Idle);
        let (args, mut command) = matching(&record);
        let target = record.plan.daemon.target_path.clone();
        let base = dir.path().canonicalize().unwrap();
        for missing in [base.join("gone/x0xd"), base.join("absent-x0xd")] {
            command.executable = missing.into_os_string();
            let mut held = None;
            let uid = effective_uid();
            assert!(issue_held(
                &args,
                &command,
                Owners::of(uid),
                &mut held,
                false,
                &process_data_dir
            )
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
        let (_dir, _root, record) = rooted(journal::Phase::Idle);
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
        let (dir, _root, record) = rooted(journal::Phase::Idle);
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
        assert!(
            error.to_string().contains("trial is now in flight"),
            "{error}"
        );
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
        drop(held);
        assert!(lock_is_free(&args.command.executable));

        let other = dir.path().canonicalize().unwrap().join("other-x0xd");
        std::fs::write(&other, b"").unwrap();
        args.command.executable = other.into_os_string();
        let mut held = None;
        let error = start::exec_locked_with(true, &args, &mut held, |_| {
            panic!("no exec of another daemon")
        });
        assert!(start::is_refusal(&error), "{error}");
        assert!(
            error
                .to_string()
                .starts_with(contract::REFUSAL_OTHER_INSTALL),
            "{error}"
        );
        assert!(held.is_none());

        let (trial, command) = matching(&record);
        std::fs::remove_file(root.join(coordinator::TRIAL_FILE_NAME)).unwrap();
        save_trial(&root, &record, Phase::Authorized);
        let args = LauncherArgs {
            trial: Some(trial),
            command,
        };
        let begun = std::time::Instant::now();
        let error = start::exec_locked_with(true, &args, &mut held, |_| {
            panic!("no exec while a trial is unretired")
        });
        assert!(!start::is_refusal(&error), "{error}");
        assert!(
            error.to_string().contains("trial is now in flight"),
            "{error}"
        );
        assert!(
            begun.elapsed() < std::time::Duration::from_secs(5),
            "no lock wait"
        );
        assert!(held.is_none());
    }

    /// #2118 review: a symlinked or oversized trial record on a committed
    /// host is a typed refusal at the re-read, not a 75 loop.
    #[test]
    fn an_unusable_trial_record_on_a_committed_host_is_refused_at_relock() {
        let (_dir, root, record) = rooted(journal::Phase::HostCommitted);
        let (args, command) = matching(&record);
        let trial = root.join(coordinator::TRIAL_FILE_NAME);
        let target = root.join("elsewhere.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &trial).unwrap();
        let error = relock(&args, &command, &mut None).unwrap_err();
        assert!(start::is_refusal(&error), "symlink: {error}");
        std::fs::remove_file(&trial).unwrap();
        let file = std::fs::File::create(&trial).unwrap();
        file.set_len(journal::MAX_RECORD_BYTES + 1).unwrap();
        std::fs::set_permissions(&trial, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = relock(&args, &command, &mut None).unwrap_err();
        assert!(start::is_refusal(&error), "oversized: {error}");
    }

    /// The bounded wait for the install lock is 30 s (#2118 review).
    #[test]
    fn the_install_lock_wait_is_30_s() {
        assert_eq!(DAEMON_LOCK_WAIT, std::time::Duration::from_secs(30));
    }

    /// #2118 review: a typed refusal from the re-read before the `exec` is
    /// final and leaves the refusal record; any other `exec` error is a
    /// failed read (75).
    #[test]
    fn a_refusal_at_the_exec_is_final() {
        let (_dir, root, record) = rooted(journal::Phase::Idle);
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
        let (dir, _root, record) = rooted(journal::Phase::Idle);
        let (args, command) = matching(&record);
        let lock = recovery::lock_path(&record.plan.daemon.target_path);
        let elsewhere = dir.path().canonicalize().unwrap().join("elsewhere.lock");
        std::fs::write(&elsewhere, b"").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &lock).unwrap();
        let not_regular = |what: &str| {
            let error = issue_as(&args, &command, effective_uid())
                .err()
                .expect("refused");
            assert!(start::is_refusal(&error), "{what}: {error}");
            assert!(
                error.to_string().contains("not a regular file"),
                "{what}: {error}"
            );
        };
        not_regular("symlink");
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        not_regular("directory");
    }

    /// #2118 review: an install lock this account cannot create is a typed
    /// refusal, since another account may lock and swap there.
    #[test]
    fn an_install_lock_this_account_cannot_create_is_refused() {
        if effective_uid() == 0 {
            return;
        }
        let (dir, _root, record) = rooted(journal::Phase::Idle);
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
        let (_dir, _root, record) = rooted(journal::Phase::Idle);
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
        let (_dir, root, record) = rooted(journal::Phase::SwappedCli);
        let (mut args, command) = matching(&record);
        args.plan_anchor = None;
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
            plan_anchor: None,
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
        bind(&root, &record);
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
        bind(&root, &record);
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
