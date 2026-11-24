//! M2 prepare producer (#2012): freeze the host plan and write the
//! prepared host journal (`<data_root>/upgrade-journal.json`) through
//! `Staged` … `SwappedCli`.
//!
//! The readers are the launcher-side issuer and `recovery::Host::new`
//! (#1378), and the arm handler (`server::upgrade_flush::admit`). This
//! module checks what they check before anything is written, so a journal
//! it writes is one they accept: canonical install and participant paths,
//! each participant's executable the plan's daemon, a valid and unique
//! instance id, a live identity for each running participant, and the
//! journal's own validation. The journal is written with
//! `journal::write_record` (mode 0600, owned by the writing account, file
//! and directory fsync, atomic replace) into a data root that the issuer's
//! root check accepts.
//!
//! This file depends only on `journal`, so the launcher's tests include it
//! by path and read what it writes with the launcher's own issuer. The live
//! observation of the running daemon is in `prepare_live` (library only).
//!
//! The apply worker calls it only through `producer`, whose gate stays
//! closed while `launcher_contract::LAUNCHER_ENABLED` is false.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::install_lock::InstallLock;
use super::journal::{self, ArtifactPlan, FrozenPlan, JournalRecord, Participant, Phase};
use super::plan_binding::{self, Anchored};

/// What the apply path knows when it prepares: the release, the two
/// staged artifacts and the participants it observed.
#[derive(Debug, Clone)]
pub(crate) struct PlanInput {
    pub previous_version: String,
    pub candidate_version: String,
    pub manifest_sha256: [u8; 32],
    pub daemon: ArtifactPlan,
    pub cli: ArtifactPlan,
    pub participants: Vec<Participant>,
}

fn refused(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.into())
}

/// `path` resolves to itself. The path must exist.
fn canonical(path: &Path, what: &str) -> io::Result<()> {
    if path.canonicalize()? != path {
        return Err(refused(format!(
            "{what} {} is not canonical",
            path.display()
        )));
    }
    Ok(())
}

/// The launcher's instance rule (`launcher_contract::parse_launcher_argv`):
/// 1-128 of `[A-Za-z0-9._-]`, not `.` or `..`.
fn valid_instance(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && id != "."
        && id != ".."
}

/// Freeze the host plan after the readers' checks (#2012):
/// - the daemon's and the CLI's target and backup paths exist and are
///   canonical (`Host::new`);
/// - each participant has a valid, unique instance id; its executable and
///   `argv[0]` are the plan's daemon target; its data root, identity root
///   and working directory are canonical; a running participant carries
///   its pid and process start (the arm handler compares both);
/// - there is at least one participant;
/// - the journal's own validation accepts a record of the plan.
pub(crate) fn freeze_plan(input: PlanInput) -> io::Result<FrozenPlan> {
    for (name, artifact) in [("daemon", &input.daemon), ("cli", &input.cli)] {
        canonical(&artifact.target_path, &format!("{name} target"))?;
        canonical(&artifact.backup_path, &format!("{name} backup"))?;
    }
    if input.participants.is_empty() {
        return Err(refused("the plan has no participant"));
    }
    let mut instances = BTreeSet::new();
    for participant in &input.participants {
        let id = participant.instance_id.as_str();
        if !valid_instance(id) {
            return Err(refused(format!(
                "instance {id:?} is not 1-128 of [A-Za-z0-9._-], or is . or .."
            )));
        }
        if !instances.insert(id) {
            return Err(refused(format!("instance {id} appears twice")));
        }
        if participant.executable != input.daemon.target_path {
            return Err(refused(format!(
                "participant {id} runs {}, not the plan's daemon {}",
                participant.executable.display(),
                input.daemon.target_path.display()
            )));
        }
        if participant.argv.first().map(Path::new) != Some(input.daemon.target_path.as_path()) {
            return Err(refused(format!(
                "participant {id} argv[0] is not the plan's daemon"
            )));
        }
        canonical(
            &participant.data_root,
            &format!("participant {id} data root"),
        )?;
        canonical(
            &participant.identity_root,
            &format!("participant {id} identity root"),
        )?;
        canonical(
            &participant.cwd,
            &format!("participant {id} working directory"),
        )?;
        if participant.was_running
            && (participant.old_pid.is_none() || participant.process_start.is_none())
        {
            return Err(refused(format!(
                "running participant {id} has no live pid and process start"
            )));
        }
    }
    let plan = FrozenPlan {
        previous_version: input.previous_version,
        candidate_version: input.candidate_version,
        manifest_sha256: input.manifest_sha256,
        daemon: input.daemon,
        cli: input.cli,
        participants: input.participants,
    };
    checked(&record("validation", plan.clone(), Phase::Staged))?;
    Ok(plan)
}

fn unswapped() -> journal::ArtifactProgress {
    journal::ArtifactProgress {
        swapped: false,
        restored: false,
        observed_sha256: None,
    }
}

fn record(transaction_id: &str, plan: FrozenPlan, phase: Phase) -> JournalRecord {
    JournalRecord {
        schema_version: journal::SCHEMA_VERSION,
        record_kind: "journal".into(),
        transaction_id: transaction_id.into(),
        sequence: 1,
        generation: 1,
        plan,
        phase,
        cause: None,
        daemon_progress: unswapped(),
        cli_progress: unswapped(),
    }
}

/// The journal readers' own validation of `record`.
fn checked(record: &JournalRecord) -> io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    match journal::classify_record(&bytes, "journal") {
        journal::RecordRead::Journal(_) => Ok(()),
        journal::RecordRead::Refused(reason) => Err(refused(format!(
            "the journal readers refuse the prepared record: {reason}"
        ))),
        _ => Err(refused("the journal readers refuse the prepared record")),
    }
}

/// A host journal another transaction may replace: a settled one.
fn settled(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::HostCommitted | Phase::Restored | Phase::Idle | Phase::Superseded
    )
}

/// The issuer's root check (`launcher::issuer::check_root`): a canonical
/// directory of this account that no group or other account can write.
#[cfg(unix)]
fn check_root(root: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    canonical(root, "data root")?;
    let metadata = std::fs::symlink_metadata(root)?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(refused(format!(
            "data root {} must be a directory of this account that no other can write",
            root.display()
        )));
    }
    Ok(())
}

/// Remove a leftover binding at the NEW transaction's path that the strict
/// writer would refuse to replace: a symlink (removed as a link; its
/// target is not touched), or any regular file it cannot read as a
/// binding, for whatever reason (corrupt, a later schema, oversized, or a
/// read that fails, such as EACCES or EIO). A valid one stays, for the
/// atomic replace. Only `stage` calls this, under the host lock, for a
/// transaction that no journal names (the current journal's id is
/// refused). Anything else at the path (a directory) is refused and left
/// alone.
fn clear_unusable_binding(path: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let usable = metadata.is_file()
        && journal::read_auxiliary_record(path)
            .and_then(|bytes| plan_binding::validate_binding(&bytes))
            .is_ok();
    if usable {
        return Ok(());
    }
    if !metadata.is_file() && !metadata.file_type().is_symlink() {
        return Err(refused(format!(
            "{} is not a file; remove it by hand",
            path.display()
        )));
    }
    std::fs::remove_file(path)
}

/// Best effort: remove every plan binding file in `data_root` whose name
/// is not in `keep` (a symlink as a link; a directory is left alone).
#[cfg(unix)]
fn remove_bindings_except(data_root: &Path, keep: &[Option<&str>]) {
    let Ok(entries) = std::fs::read_dir(data_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !plan_binding::is_binding_file_name(name) || keep.contains(&Some(name)) {
            continue;
        }
        if entry.file_type().is_ok_and(|kind| !kind.is_dir()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// The stage lock of a data root: `<data_root>/upgrade-stage.lock`.
pub(crate) const STAGE_LOCK_NAME: &str = "upgrade-stage.lock";

/// Take the stage lock of `data_root` (#2171 fourth review): every `stage`
/// holds it from its journal read to its last binding removal, so two
/// stages in one data root never interleave, whatever install pair each
/// is for. Without it, two pairs that stage for the first time in a data
/// root with no journal hold different install locks, and each could
/// remove the other's new binding. It is taken after the host lock and
/// held while nothing else is waited for, so it cannot deadlock.
#[cfg(unix)]
fn stage_lock(data_root: &Path) -> io::Result<InstallLock> {
    InstallLock::take(lock_file(&data_root.join(STAGE_LOCK_NAME))?)
}

/// The new transaction's binding write. A test can make it fail at one
/// barrier step (`tests::fail_binding_write`).
#[cfg(unix)]
fn write_binding(path: &Path, binding: &plan_binding::PlanBinding) -> io::Result<()> {
    #[cfg(test)]
    if let Some(step) = tests::BINDING_FAILURE.with(std::cell::Cell::take) {
        return journal::write_auxiliary_record_with_failure(
            path,
            binding,
            plan_binding::validate_binding,
            step,
        );
    }
    journal::write_auxiliary_record(path, binding, plan_binding::validate_binding)
}

/// The Staged journal write. A test can make it fail at one barrier step
/// (`tests::fail_journal_write`), as a crash or a full disk would.
#[cfg(unix)]
fn write_staged_journal(path: &Path, record: &JournalRecord) -> io::Result<()> {
    #[cfg(test)]
    if let Some(hook) = tests::BEFORE_JOURNAL_WRITE.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
    #[cfg(test)]
    if let Some(step) = tests::JOURNAL_FAILURE.with(std::cell::Cell::take) {
        return journal::write_record_with_failure(path, record, step);
    }
    journal::write_record(path, record)
}

fn sha256_of(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

/// The host lock (#2012 review): the advisory locks on
/// `<cli target>.upgrade.lock`, then `<daemon target>.upgrade.lock`, in the
/// order the pair writer and the launcher's `Host::locked` take them.
/// `journal::write_record` requires it for every transaction change, so
/// `stage` and `advance` take it by type: a caller cannot forget it. It is
/// held until dropped.
pub(crate) struct HostLock {
    cli: PathBuf,
    daemon: PathBuf,
    _locks: [InstallLock; 2],
}

/// `adopt` refused the caller's locks and hands them back, still held.
pub(crate) struct AdoptRefused {
    pub(crate) error: io::Error,
    pub(crate) cli: InstallLock,
    pub(crate) daemon: InstallLock,
}

/// The lock file of an install target: `<target>.upgrade.lock`.
fn lock_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_os_string();
    name.push(".upgrade.lock");
    PathBuf::from(name)
}

/// The lock file of `plan`'s daemon. A test plan whose daemon is the
/// running test binary (the arm handler compares the running executable)
/// keeps that lock in its own temporary directory, beside its CLI target,
/// so parallel tests never share one lock file (#2074 review).
fn daemon_lock_path(plan: &FrozenPlan) -> PathBuf {
    #[cfg(test)]
    if std::env::current_exe()
        .and_then(|exe| exe.canonicalize())
        .is_ok_and(|exe| exe == plan.daemon.target_path)
    {
        let mut name = plan.cli.target_path.as_os_str().to_os_string();
        name.push(".test-daemon.upgrade.lock");
        return PathBuf::from(name);
    }
    lock_path(&plan.daemon.target_path)
}

/// Open (create) one install lock file: no symlink followed, mode 0600,
/// and a regular file.
#[cfg(unix)]
fn lock_file(name: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(name)?;
    if !file.metadata()?.is_file() {
        return Err(refused("invalid install lock"));
    }
    Ok(file)
}

impl HostLock {
    /// Take the host lock for `plan`'s install pair; waits for a holder.
    #[cfg(unix)]
    pub(crate) fn acquire(plan: &FrozenPlan) -> io::Result<Self> {
        let [cli, daemon] = Self::open(plan)?;
        let cli = InstallLock::take(cli)?;
        let daemon = InstallLock::take(daemon)?;
        Ok(Self::held(plan, cli, daemon))
    }

    /// As `acquire`, but give up after `wait` (#2065 review): a caller that
    /// may run while another holder waits on it (the arm handler's
    /// restore, while the arming caller waits for its reply) must not
    /// block for ever. Never holds one lock while it waits for the other.
    #[cfg(unix)]
    pub(crate) fn acquire_within(plan: &FrozenPlan, wait: std::time::Duration) -> io::Result<Self> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            let [cli, daemon] = Self::open(plan)?;
            // A refused daemon lock drops the CLI lock before the wait.
            if let Some(cli) = InstallLock::try_take(cli)? {
                if let Some(daemon) = InstallLock::try_take(daemon)? {
                    return Ok(Self::held(plan, cli, daemon));
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "the host lock is held by another holder",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Adopt the host lock that the caller already holds (#2065 review):
    /// the two install locks the apply path took with
    /// `acquire_host_upgrade_lock`, so taking them again cannot deadlock
    /// the caller. Holding is proven by the `InstallLock` type. Each lock
    /// must be on the lock file of `plan`'s pair (same file), CLI first. A
    /// refusal hands both locks back, still held.
    #[cfg(unix)]
    pub(crate) fn adopt(
        plan: &FrozenPlan,
        cli: InstallLock,
        daemon: InstallLock,
    ) -> Result<Self, AdoptRefused> {
        let checked = (|| {
            use std::os::unix::fs::MetadataExt;
            let [expected_cli, expected_daemon] = Self::open(plan)?;
            for (held, expected) in [
                (cli.file(), &expected_cli),
                (daemon.file(), &expected_daemon),
            ] {
                let (a, b) = (held.metadata()?, expected.metadata()?);
                if a.dev() != b.dev() || a.ino() != b.ino() {
                    return Err(refused("an adopted lock is not this install pair's lock"));
                }
            }
            Ok(())
        })();
        match checked {
            Ok(()) => Ok(Self::held(plan, cli, daemon)),
            Err(error) => Err(AdoptRefused { error, cli, daemon }),
        }
    }

    /// The two install lock files of `plan`'s pair, opened, not locked.
    #[cfg(unix)]
    fn open(plan: &FrozenPlan) -> io::Result<[std::fs::File; 2]> {
        use std::os::unix::fs::MetadataExt;
        let cli = lock_file(&lock_path(&plan.cli.target_path))?;
        let daemon = lock_file(&daemon_lock_path(plan))?;
        let (a, b) = (cli.metadata()?, daemon.metadata()?);
        if a.dev() == b.dev() && a.ino() == b.ino() {
            return Err(refused("install locks alias"));
        }
        Ok([cli, daemon])
    }

    /// The two locked files, CLI first, still held until they are dropped:
    /// the apply worker hands them to the restart owner (#2012).
    pub(crate) fn into_files(self) -> (std::fs::File, std::fs::File) {
        let [cli, daemon] = self._locks;
        (cli.into_file(), daemon.into_file())
    }

    fn held(plan: &FrozenPlan, cli: InstallLock, daemon: InstallLock) -> Self {
        Self {
            cli: plan.cli.target_path.clone(),
            daemon: plan.daemon.target_path.clone(),
            _locks: [cli, daemon],
        }
    }

    /// This lock is the host lock of `plan`'s install pair.
    fn covers(&self, plan: &FrozenPlan) -> io::Result<()> {
        if self.cli != plan.cli.target_path || self.daemon != plan.daemon.target_path {
            return Err(refused("the host lock is for another install pair"));
        }
        Ok(())
    }
}

/// The forward phases the producer writes, in order. `Probed` may be
/// skipped; the two swaps may not.
const FORWARD: [Phase; 5] = [
    Phase::Staged,
    Phase::Probed,
    Phase::Prepared,
    Phase::SwappedDaemon,
    Phase::SwappedCli,
];

/// One prepared host transaction and its journal.
#[derive(Debug)]
pub(crate) struct Prepared {
    path: PathBuf,
    record: JournalRecord,
}

impl Prepared {
    /// Write the journal for `plan` in `data_root`, in `Staged`. The data
    /// root must be one participant's data root and pass the issuer's root
    /// check. An earlier journal is replaced only when it is settled; an
    /// in-flight or unreadable one is refused. The check and the write are
    /// both under `lock`, so of two concurrent runs the second sees the
    /// first's journal in flight and is refused.
    ///
    /// The plan must name exactly the install that `anchor` approves
    /// (#2012, B4). Before the Staged journal it writes this transaction's
    /// plan binding beside it (`plan_binding::binding_file_name`, mode
    /// 0600): the transaction, the generation, the plan digest and the
    /// anchor digest. The binding does not change for the rest of the
    /// transaction.
    ///
    /// Each transaction has its own binding file (#2171 review). A settled
    /// earlier journal (HostCommitted, Restored) still gives its launcher a
    /// trial, so its binding must stay valid until the new journal is
    /// durable: stage never writes or removes the binding the current
    /// journal names before that. A transaction id equal to the current
    /// journal's is refused, since its binding would be the current one.
    /// A settled journal for another install pair is refused too: the
    /// launcher reads this data root under the lock of the journal's own
    /// daemon target, which a stage for another pair would not hold.
    ///
    /// A crash or a failed journal write after the new binding leaves one
    /// of two states, both startable. If it happens before the journal's
    /// rename, the current journal and its binding are as they were, plus
    /// an orphan binding. If it happens after the rename (at the directory
    /// sync), the new Staged journal is in place with its own binding.
    /// Orphans (bindings of neither the current nor the new transaction)
    /// are removed before the new binding is written, and every binding
    /// but the new one after the new journal is written. Each removal is
    /// best effort: when all succeed at most two binding files exist; a
    /// removal that fails leaves a harmless leftover that the next stage
    /// retries.
    #[cfg(unix)]
    pub(crate) fn stage(
        lock: &HostLock,
        data_root: &Path,
        transaction_id: &str,
        plan: FrozenPlan,
        anchor: &Anchored,
    ) -> io::Result<Self> {
        Self::stage_reading_anchor(lock, data_root, transaction_id, plan, || Ok(anchor.clone()))
    }

    /// `stage`, with the anchor read by `read_anchor` while the data
    /// root's stage lock is held (#2012). The installer takes the same lock
    /// around its anchor change and its journal check, so either the
    /// installer sees this transaction's Staged journal and refuses, or
    /// this stage reads the anchor the installer wrote.
    #[cfg(unix)]
    pub(crate) fn stage_reading_anchor(
        lock: &HostLock,
        data_root: &Path,
        transaction_id: &str,
        plan: FrozenPlan,
        read_anchor: impl FnOnce() -> io::Result<Anchored>,
    ) -> io::Result<Self> {
        lock.covers(&plan)?;
        check_root(data_root)?;
        if !plan.participants.iter().any(|p| p.data_root == data_root) {
            return Err(refused(format!(
                "{} is not the data root of a participant",
                data_root.display()
            )));
        }
        if transaction_id.trim().is_empty() {
            return Err(refused("empty transaction id"));
        }
        let _stage = stage_lock(data_root)?;
        let path = data_root.join(journal::JOURNAL_FILE_NAME);
        let mut current = None;
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                let bytes = journal::read_auxiliary_record(&path)?;
                match journal::classify_record(&bytes, "journal") {
                    journal::RecordRead::Journal(earlier) if settled(earlier.phase) => {
                        if earlier.transaction_id == transaction_id {
                            return Err(refused(format!(
                                "transaction {transaction_id} is the current journal's"
                            )));
                        }
                        // The launcher reads this data root's journal and
                        // binding under the lock of the journal's daemon
                        // target; a stage for another pair would hold other
                        // locks and could remove that binding between its
                        // two reads (#2171 review). Refused rather than also
                        // taking the earlier pair's locks: a third and
                        // fourth lock beside the plan's two has no order
                        // every holder agrees on, so it could deadlock.
                        if earlier.plan.daemon.target_path != plan.daemon.target_path
                            || earlier.plan.cli.target_path != plan.cli.target_path
                        {
                            return Err(refused(format!(
                                "the host journal in {} is for another install pair \
                                 ({}, {}); this data root cannot be staged for a different \
                                 install until that journal is removed by hand",
                                data_root.display(),
                                earlier.plan.daemon.target_path.display(),
                                earlier.plan.cli.target_path.display()
                            )));
                        }
                        current = Some(plan_binding::binding_file_name(&earlier.transaction_id));
                    }
                    journal::RecordRead::Journal(earlier) => {
                        return Err(refused(format!(
                            "transaction {} is in flight ({:?})",
                            earlier.transaction_id, earlier.phase
                        )));
                    }
                    _ => return Err(refused("the existing host journal is unreadable")),
                }
            }
        }
        let anchor = read_anchor()?;
        let record = record(transaction_id, plan, Phase::Staged);
        checked(&record)?;
        let binding = anchor
            .bind(&record.transaction_id, record.generation, &record.plan)
            .map_err(|error| refused(error.to_string()))?;
        let name = plan_binding::binding_file_name(&record.transaction_id);
        remove_bindings_except(data_root, &[Some(name.as_str()), current.as_deref()]);
        let binding_path = data_root.join(&name);
        clear_unusable_binding(&binding_path)?;
        write_binding(&binding_path, &binding)?;
        write_staged_journal(&path, &record)?;
        // The new journal is durable: the current one's binding is history.
        remove_bindings_except(data_root, &[Some(name.as_str())]);
        Ok(Self { path, record })
    }

    pub(crate) fn record(&self) -> &JournalRecord {
        &self.record
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Move the journal forward to `phase`, after the step it names is
    /// done. A swap phase is written only after the swapped file is
    /// checked: the target holds the candidate and the backup the previous
    /// release (their planned sha256). Under `lock`, the journal on disk
    /// must still be exactly the one this run last wrote (transaction,
    /// sequence and every field); a journal that changed underneath is
    /// refused and left as it is.
    pub(crate) fn advance(&mut self, lock: &HostLock, phase: Phase) -> io::Result<()> {
        lock.covers(&self.record.plan)?;
        let on_disk = journal::read_auxiliary_record(&self.path)?;
        let unchanged = match journal::classify_record(&on_disk, "journal") {
            journal::RecordRead::Journal(current) => {
                current.transaction_id == self.record.transaction_id
                    && current.sequence == self.record.sequence
                    && serde_json::to_vec(&current).map_err(io::Error::other)?
                        == serde_json::to_vec(&self.record).map_err(io::Error::other)?
            }
            _ => false,
        };
        if !unchanged {
            return Err(refused("the host journal changed since this run wrote it"));
        }
        let position = |phase| FORWARD.iter().position(|p| *p == phase);
        let (Some(from), Some(to)) = (position(self.record.phase), position(phase)) else {
            return Err(refused(format!(
                "{:?} -> {phase:?} is not a prepare step",
                self.record.phase
            )));
        };
        let in_order = to > from
            && match phase {
                Phase::SwappedDaemon => self.record.phase == Phase::Prepared,
                Phase::SwappedCli => self.record.phase == Phase::SwappedDaemon,
                _ => true,
            };
        if !in_order {
            return Err(refused(format!(
                "{:?} -> {phase:?} is out of order",
                self.record.phase
            )));
        }
        let mut next = self.record.clone();
        let artifact = match phase {
            Phase::SwappedDaemon => Some((&next.plan.daemon, "daemon")),
            Phase::SwappedCli => Some((&next.plan.cli, "cli")),
            _ => None,
        };
        if let Some((artifact, name)) = artifact {
            let observed = sha256_of(&artifact.target_path)?;
            if observed != artifact.candidate_sha256
                || sha256_of(&artifact.backup_path)? != artifact.previous_sha256
            {
                return Err(refused(format!(
                    "the {name} swap does not hold the planned candidate and backup"
                )));
            }
            let progress = journal::ArtifactProgress {
                swapped: true,
                restored: false,
                observed_sha256: Some(observed),
            };
            if phase == Phase::SwappedDaemon {
                next.daemon_progress = progress;
            } else {
                next.cli_progress = progress;
            }
        }
        next.phase = phase;
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| refused("journal sequence overflow"))?;
        checked(&next)?;
        journal::write_record(&self.path, &next)?;
        self.record = next;
        Ok(())
    }

    /// Settle a transaction this run is giving up before any trial
    /// (#2012): write `Superseded`, after the caller restored every swapped
    /// artifact (`restored`: daemon, CLI). Allowed from Staged up to and
    /// including SwappedCli, only for the journal this run last wrote. The
    /// launcher passes through a Superseded journal (the previous pair is
    /// installed) and the next stage replaces it.
    pub(crate) fn abandon(&mut self, lock: &HostLock, restored: [bool; 2]) -> io::Result<()> {
        lock.covers(&self.record.plan)?;
        if !FORWARD.contains(&self.record.phase) {
            return Err(refused(format!(
                "a {:?} transaction is not abandoned by its producer",
                self.record.phase
            )));
        }
        let on_disk = journal::read_auxiliary_record(&self.path)?;
        let unchanged = match journal::classify_record(&on_disk, "journal") {
            journal::RecordRead::Journal(current) => {
                serde_json::to_vec(&current).map_err(io::Error::other)?
                    == serde_json::to_vec(&self.record).map_err(io::Error::other)?
            }
            _ => false,
        };
        if !unchanged {
            return Err(refused("the host journal changed since this run wrote it"));
        }
        for (index, artifact) in [&self.record.plan.daemon, &self.record.plan.cli]
            .into_iter()
            .enumerate()
        {
            if sha256_of(&artifact.target_path)? != artifact.previous_sha256 {
                return Err(refused(format!(
                    "the {} target does not hold the previous release; not abandoned",
                    if index == 0 { "daemon" } else { "cli" }
                )));
            }
        }
        let mut next = self.record.clone();
        for (progress, restored) in [&mut next.daemon_progress, &mut next.cli_progress]
            .into_iter()
            .zip(restored)
        {
            if restored {
                progress.restored = true;
            }
        }
        next.phase = Phase::Superseded;
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| refused("journal sequence overflow"))?;
        checked(&next)?;
        journal::write_record(&self.path, &next)?;
        self.record = next;
        Ok(())
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;

    thread_local! {
        /// The barrier step at which this thread's next Staged journal
        /// write fails.
        pub(crate) static JOURNAL_FAILURE: std::cell::Cell<Option<journal::BarrierStep>> =
            const { std::cell::Cell::new(None) };
    }

    thread_local! {
        /// The barrier step at which this thread's next binding write fails.
        pub(crate) static BINDING_FAILURE: std::cell::Cell<Option<journal::BarrierStep>> =
            const { std::cell::Cell::new(None) };
    }

    thread_local! {
        /// Runs once, on this thread, just before the next Staged journal
        /// write, after the new binding is durable.
        pub(crate) static BEFORE_JOURNAL_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Make this thread's next binding write fail at `step`.
    pub(crate) fn fail_binding_write(step: journal::BarrierStep) {
        BINDING_FAILURE.with(|failure| failure.set(Some(step)));
    }

    /// Make this thread's next Staged journal write fail at `step`.
    pub(crate) fn fail_journal_write(step: journal::BarrierStep) {
        JOURNAL_FAILURE.with(|failure| failure.set(Some(step)));
    }
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    /// A canonical 0700 root with the swapped pair in place: target =
    /// candidate, backup = previous.
    pub(crate) fn input_in(root: &Path) -> PlanInput {
        let artifact = |name: &str| {
            let target = root.join(format!("{name}.d"));
            let backup = root.join(format!("{name}.b"));
            std::fs::write(&target, format!("candidate-{name}")).unwrap();
            std::fs::write(&backup, format!("previous-{name}")).unwrap();
            ArtifactPlan {
                previous_sha256: sha256_of(&backup).unwrap(),
                candidate_sha256: sha256_of(&target).unwrap(),
                target_path: target,
                staged_path: root.join(format!("{name}.s")),
                backup_path: backup,
            }
        };
        let daemon = artifact("daemon");
        let cli = artifact("cli");
        let participant = Participant {
            instance_id: "alice".into(),
            executable: daemon.target_path.clone(),
            data_root: root.to_path_buf(),
            identity_root: root.to_path_buf(),
            argv: vec![
                daemon.target_path.to_string_lossy().into_owned(),
                "--name".into(),
                "alice".into(),
            ],
            cwd: root.to_path_buf(),
            env: BTreeMap::new(),
            restart: journal::RestartBinding {
                mode: journal::RestartOwner::SupervisedExit,
                supervised_exit_code: None,
                supervision_signal: None,
                launchd_verified: None,
                systemd_verified: None,
                launcher: None,
            },
            old_pid: Some(std::process::id()),
            process_start: Some(1),
            boot_id: "test-boot".into(),
            was_running: true,
        };
        PlanInput {
            previous_version: "0.0.1".into(),
            candidate_version: "9.9.9".into(),
            manifest_sha256: [7; 32],
            daemon,
            cli,
            participants: vec![participant],
        }
    }

    pub(crate) fn root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, root)
    }

    /// `Prepared::stage` with an anchor for `plan`'s own install (#2012,
    /// B4).
    pub(crate) fn stage(
        lock: &HostLock,
        data_root: &Path,
        transaction_id: &str,
        plan: FrozenPlan,
    ) -> io::Result<Prepared> {
        let anchor = plan_binding::test_anchored(&plan);
        Prepared::stage(lock, data_root, transaction_id, plan, &anchor)
    }

    /// Stage, then move through every forward phase to `SwappedCli`.
    pub(crate) fn prepared_in(root: &Path, input: PlanInput) -> Prepared {
        let plan = freeze_plan(input).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let mut prepared = stage(&lock, root, "tx-2012", plan).unwrap();
        for phase in [
            Phase::Probed,
            Phase::Prepared,
            Phase::SwappedDaemon,
            Phase::SwappedCli,
        ] {
            prepared.advance(&lock, phase).unwrap();
        }
        prepared
    }

    #[test]
    fn a_prepared_journal_is_written_0600_and_reads_back() {
        let (_dir, root) = root();
        let prepared = prepared_in(&root, input_in(&root));
        let path = root.join(journal::JOURNAL_FILE_NAME);
        assert_eq!(prepared.path(), path);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let bytes = std::fs::read(&path).unwrap();
        let journal::RecordRead::Journal(read) = journal::classify_record(&bytes, "journal") else {
            panic!("the prepared journal does not read back");
        };
        assert_eq!(read.phase, Phase::SwappedCli);
        assert_eq!(read.sequence, 5);
        assert!(read.daemon_progress.swapped && read.cli_progress.swapped);
        assert_eq!(
            read.daemon_progress.observed_sha256,
            Some(read.plan.daemon.candidate_sha256)
        );
    }

    /// #2012 (B4): staging writes the plan binding (0600) that binds the
    /// Staged journal to the anchor, and it refuses a plan the anchor does
    /// not name, before it writes anything.
    #[test]
    fn staging_binds_the_plan_to_the_anchor() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let binding_path = root.join(plan_binding::binding_file_name("tx"));
        let journal_path = root.join(journal::JOURNAL_FILE_NAME);

        let mut other_install = plan.clone();
        other_install.participants[0].instance_id = "bob".into();
        let foreign = plan_binding::test_anchored(&other_install);
        assert!(Prepared::stage(&lock, &root, "tx", plan.clone(), &foreign).is_err());
        assert!(!binding_path.exists() && !journal_path.exists());

        let anchor = plan_binding::test_anchored(&plan);
        let prepared = Prepared::stage(&lock, &root, "tx", plan, &anchor).unwrap();
        let mode = std::fs::metadata(&binding_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let binding = plan_binding::parse_binding(&std::fs::read(&binding_path).unwrap()).unwrap();
        anchor.verify(&binding, prepared.record()).unwrap();
        assert!(foreign.verify(&binding, prepared.record()).is_err());
    }

    /// #2171 review: a leftover binding the strict writer would refuse to
    /// replace (corrupt, a later schema, a symlink) is replaced by the next
    /// stage; a symlink's target is not touched.
    #[test]
    fn staging_replaces_an_unusable_leftover_binding() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let path = root.join(plan_binding::binding_file_name("tx"));
        let journal_path = root.join(journal::JOURNAL_FILE_NAME);
        let anchor = plan_binding::test_anchored(&plan);
        let target = root.join("elsewhere.json");
        std::fs::write(&target, b"not mine").unwrap();
        let leftovers: [&dyn Fn(); 3] = [
            &|| std::fs::write(&path, b"{corrupt").unwrap(),
            &|| {
                std::fs::write(
                    &path,
                    br#"{"schema":2,"record_kind":"plan_binding","future":true}"#,
                )
                .unwrap()
            },
            &|| std::os::unix::fs::symlink(&target, &path).unwrap(),
        ];
        for (index, leftover) in leftovers.into_iter().enumerate() {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&journal_path);
            leftover();
            let prepared = Prepared::stage(&lock, &root, "tx", plan.clone(), &anchor)
                .unwrap_or_else(|error| panic!("leftover {index}: {error}"));
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_file(), "leftover {index}");
            let binding = plan_binding::parse_binding(&std::fs::read(&path).unwrap()).unwrap();
            anchor.verify(&binding, prepared.record()).unwrap();
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"not mine");
        // A directory there is not removed.
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&journal_path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(Prepared::stage(&lock, &root, "tx", plan, &anchor).is_err());
        assert!(path.is_dir() && !journal_path.exists());
    }

    /// #2171 review: a stage keeps at most the current and the new
    /// binding while it runs, and only the new one after its journal is
    /// durable. An orphan from an earlier failed stage is removed; a
    /// directory with a binding's name is left alone.
    #[test]
    fn staging_cleans_orphan_bindings_after_a_durable_journal() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let anchor = plan_binding::test_anchored(&plan);
        let bindings = || {
            let mut names: Vec<String> = std::fs::read_dir(&root)
                .unwrap()
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| plan_binding::is_binding_file_name(n))
                .collect();
            names.sort();
            names
        };
        let mut first = Prepared::stage(&lock, &root, "tx-1", plan.clone(), &anchor).unwrap();
        for phase in [Phase::Prepared, Phase::SwappedDaemon, Phase::SwappedCli] {
            first.advance(&lock, phase).unwrap();
        }
        settle(&root, Phase::HostCommitted);
        // An orphan of a stage that failed after its binding.
        fail_journal_write(journal::BarrierStep::Write);
        assert!(Prepared::stage(&lock, &root, "tx-failed", plan.clone(), &anchor).is_err());
        let orphan = plan_binding::binding_file_name("tx-failed");
        assert_eq!(bindings().len(), 2);
        assert!(bindings().contains(&orphan));
        let directory = root.join(plan_binding::binding_file_name("a-directory"));
        std::fs::create_dir(&directory).unwrap();

        Prepared::stage(&lock, &root, "tx-2", plan, &anchor).unwrap();
        let mut expected = vec![
            plan_binding::binding_file_name("tx-2"),
            plan_binding::binding_file_name("a-directory"),
        ];
        expected.sort();
        assert_eq!(bindings(), expected);
        assert!(directory.is_dir());
    }

    /// #2171 review: the binding is written before the journal; a binding
    /// write that fails at any step before its rename writes no journal.
    #[test]
    fn a_failed_binding_write_writes_no_journal() {
        for step in [
            journal::BarrierStep::Write,
            journal::BarrierStep::FileSync,
            journal::BarrierStep::Rename,
        ] {
            let (_dir, root) = root();
            let plan = freeze_plan(input_in(&root)).unwrap();
            let lock = HostLock::acquire(&plan).unwrap();
            let anchor = plan_binding::test_anchored(&plan);
            fail_binding_write(step);
            assert!(Prepared::stage(&lock, &root, "tx", plan, &anchor).is_err());
            assert!(!root.join(journal::JOURNAL_FILE_NAME).exists(), "{step:?}");
        }
    }

    /// The plan of another install pair staged into `root`: the daemon
    /// target, the CLI target or both (`daemon`, `cli`) from a pair in
    /// another directory, the participants `plan`'s.
    fn other_pair(plan: &FrozenPlan, daemon: bool, cli: bool) -> (tempfile::TempDir, FrozenPlan) {
        let (other_dir, other_root) = super::tests::root();
        let fresh = freeze_plan(input_in(&other_root)).unwrap();
        let mut other = plan.clone();
        if daemon {
            other.daemon = fresh.daemon;
        }
        if cli {
            other.cli = fresh.cli;
        }
        for participant in &mut other.participants {
            participant.executable = other.daemon.target_path.clone();
            participant.argv[0] = other.daemon.target_path.to_string_lossy().into_owned();
        }
        (other_dir, other)
    }

    /// #2171 review: over a settled journal for another install pair, a
    /// stage is refused and changes nothing. Each target is compared on
    /// its own: a pair that differs only in the daemon target, or only in
    /// the CLI target, is another pair.
    #[test]
    fn staging_refuses_another_install_pair_over_a_journal() {
        for (daemon, cli) in [(true, false), (false, true), (true, true)] {
            let (_dir, root) = root();
            let plan = freeze_plan(input_in(&root)).unwrap();
            let lock = HostLock::acquire(&plan).unwrap();
            let anchor = plan_binding::test_anchored(&plan);
            Prepared::stage(&lock, &root, "tx-1", plan.clone(), &anchor).unwrap();
            settle(&root, Phase::HostCommitted);
            drop(lock);
            let (_other_dir, other) = other_pair(&plan, daemon, cli);
            let other_lock = HostLock::acquire(&other).unwrap();
            let other_anchor = plan_binding::test_anchored(&other);
            let before = std::fs::read(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
            let error = Prepared::stage(&other_lock, &root, "tx-2", other, &other_anchor)
                .expect_err("refused");
            let case = format!("daemon differs {daemon}, cli differs {cli}");
            assert!(
                error.to_string().contains("another install pair"),
                "{case}: {error}"
            );
            assert_eq!(
                std::fs::read(root.join(journal::JOURNAL_FILE_NAME)).unwrap(),
                before,
                "{case}"
            );
            assert!(root.join(plan_binding::binding_file_name("tx-1")).exists());
            assert!(!root.join(plan_binding::binding_file_name("tx-2")).exists());
        }
    }

    /// #2171 fourth review: two install pairs that stage for the first time
    /// in one data root (no journal yet) hold different install locks. The
    /// data root's stage lock still keeps them apart: the second waits for
    /// the first, then sees its Staged journal in flight and is refused, so
    /// the first journal keeps its binding. Without the stage lock the
    /// second runs inside the first and removes its binding.
    #[test]
    fn first_stages_of_two_pairs_in_one_data_root_never_interleave() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let (_other_dir, other) = other_pair(&plan, true, true);
        let (sender, receiver) = std::sync::mpsc::channel();
        let racer_root = root.clone();
        let racer = std::sync::Arc::new(std::sync::Mutex::new(None));
        let racer_slot = racer.clone();
        BEFORE_JOURNAL_WRITE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let thread = std::thread::spawn(move || {
                    let other_lock = HostLock::acquire(&other).unwrap();
                    let result = stage(&other_lock, &racer_root, "tx-other", other).map(drop);
                    let _ = sender.send(());
                    result
                });
                // Give the racing stage time to run to its end if it can.
                let finished = receiver
                    .recv_timeout(std::time::Duration::from_millis(500))
                    .is_ok();
                *racer_slot.lock().unwrap() = Some((thread, finished));
            }))
        });
        stage(&lock, &root, "tx-first", plan).unwrap();
        let (thread, finished_inside) = racer.lock().unwrap().take().expect("the hook ran");
        let raced = thread.join().unwrap();
        assert!(!finished_inside, "the second stage ran inside the first");
        let error = raced.expect_err("the second stage is refused");
        assert!(error.to_string().contains("in flight"), "{error}");
        let bytes = std::fs::read(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
        let journal::RecordRead::Journal(record) = journal::classify_record(&bytes, "journal")
        else {
            panic!("no journal");
        };
        assert_eq!(record.transaction_id, "tx-first");
        assert!(root
            .join(plan_binding::binding_file_name("tx-first"))
            .exists());
        assert!(!root
            .join(plan_binding::binding_file_name("tx-other"))
            .exists());
    }

    /// #2171 review: a transaction id equal to the current journal's is
    /// refused (its binding is the current one).
    #[test]
    fn staging_refuses_the_current_transaction_id() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let anchor = plan_binding::test_anchored(&plan);
        Prepared::stage(&lock, &root, "tx-1", plan.clone(), &anchor).unwrap();
        settle(&root, Phase::Restored);
        let before = std::fs::read(root.join(plan_binding::binding_file_name("tx-1"))).unwrap();
        assert!(Prepared::stage(&lock, &root, "tx-1", plan.clone(), &anchor).is_err());
        assert_eq!(
            std::fs::read(root.join(plan_binding::binding_file_name("tx-1"))).unwrap(),
            before
        );
        assert!(Prepared::stage(&lock, &root, "tx-2", plan, &anchor).is_ok());
    }

    /// Rewrite the journal in `root` in a settled `phase`, as a launcher's
    /// commit or restore leaves it.
    pub(crate) fn settle(root: &Path, phase: Phase) {
        let path = root.join(journal::JOURNAL_FILE_NAME);
        let bytes = std::fs::read(&path).unwrap();
        let journal::RecordRead::Journal(mut record) = journal::classify_record(&bytes, "journal")
        else {
            panic!("no journal");
        };
        record.phase = phase;
        if phase == Phase::Restored {
            record.cause = Some(journal::Cause {
                class: journal::CauseClass::Failed,
                reason: "fixture".into(),
            });
        }
        std::fs::remove_file(&path).unwrap();
        journal::write_record(&path, &*record).unwrap();
    }

    #[test]
    fn a_non_canonical_path_is_refused() {
        let (_dir, root) = root();
        let link = root.join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        let mut input = input_in(&root);
        input.participants[0].data_root = link.clone();
        assert!(freeze_plan(input).is_err());
        let mut input = input_in(&root);
        input.daemon.backup_path = link.join("daemon.b");
        assert!(freeze_plan(input).is_err());
        let mut input = input_in(&root);
        input.participants[0].cwd = root.join("missing");
        assert!(freeze_plan(input).is_err());
    }

    #[test]
    fn a_wrong_executable_is_refused() {
        let (_dir, root) = root();
        let mut input = input_in(&root);
        input.participants[0].executable = input.cli.target_path.clone();
        assert!(freeze_plan(input).is_err());
        let mut input = input_in(&root);
        input.participants[0].argv[0] = "x0xd".into();
        assert!(freeze_plan(input).is_err());
    }

    #[test]
    fn a_missing_or_duplicate_or_invalid_participant_is_refused() {
        let (_dir, root) = root();
        let mut input = input_in(&root);
        input.participants.clear();
        assert!(freeze_plan(input).is_err());
        let mut input = input_in(&root);
        let twin = input.participants[0].clone();
        input.participants.push(twin);
        assert!(freeze_plan(input).is_err());
        for bad in ["", "..", "a/b", "a b"] {
            let mut input = input_in(&root);
            input.participants[0].instance_id = bad.into();
            assert!(freeze_plan(input).is_err(), "{bad:?}");
        }
        let mut input = input_in(&root);
        input.participants[0].process_start = None;
        assert!(freeze_plan(input).is_err());
    }

    #[test]
    fn staging_needs_a_participant_root_of_this_account_and_its_lock() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let other = root.join("other");
        std::fs::create_dir(&other).unwrap();
        assert!(stage(&lock, &other, "tx", plan.clone()).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(stage(&lock, &root, "tx", plan.clone()).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(stage(&lock, &root, " ", plan.clone()).is_err());
        // The host lock of another install pair does not cover this plan.
        let (_other_dir, other_root) = super::tests::root();
        let other_plan = freeze_plan(input_in(&other_root)).unwrap();
        let other_lock = HostLock::acquire(&other_plan).unwrap();
        assert!(stage(&other_lock, &root, "tx", plan).is_err());
    }

    #[test]
    fn an_in_flight_journal_is_never_replaced() {
        let (_dir, root) = root();
        let prepared = prepared_in(&root, input_in(&root));
        let plan = prepared.record().plan.clone();
        let lock = HostLock::acquire(&plan).unwrap();
        assert!(stage(&lock, &root, "tx-next", plan.clone()).is_err());
        // A settled journal may be replaced.
        let mut settled = prepared.record().clone();
        settled.phase = Phase::HostCommitted;
        settled.sequence += 1;
        journal::write_record(prepared.path(), &settled).unwrap();
        assert!(stage(&lock, &root, "tx-next", plan).is_ok());
    }

    /// #2065 review: two concurrent runs. The second waits for the host
    /// lock, then finds the first's journal in flight and is refused; the
    /// first's journal stands.
    #[test]
    fn a_concurrent_stage_waits_for_the_lock_and_is_refused() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let held = HostLock::acquire(&plan).unwrap();
        let (acquired, waiting) = std::sync::mpsc::channel();
        let (racer_root, racer_plan) = (root.clone(), plan.clone());
        let racer = std::thread::spawn(move || {
            let lock = HostLock::acquire(&racer_plan).unwrap();
            acquired.send(()).unwrap();
            stage(&lock, &racer_root, "tx-racer", racer_plan).map(|_| ())
        });
        let wait = std::time::Duration::from_millis(300);
        assert!(
            waiting.recv_timeout(wait).is_err(),
            "the racer did not wait"
        );
        let first = stage(&held, &root, "tx-first", plan).unwrap();
        drop(held);
        waiting
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(racer.join().unwrap().is_err());
        let bytes = std::fs::read(first.path()).unwrap();
        let journal::RecordRead::Journal(read) = journal::classify_record(&bytes, "journal") else {
            panic!("the journal does not read back");
        };
        assert_eq!(read.transaction_id, "tx-first");
    }

    /// #2065 and #2074 reviews: a caller that already holds the install
    /// locks adopts them instead of taking them again. While they are held
    /// a bounded acquire gives up. Another pair's locks are refused and
    /// handed back still held.
    #[test]
    fn a_held_host_lock_is_adopted_not_taken_again() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let take = |plan: &FrozenPlan| {
            let [cli, daemon] = HostLock::open(plan).unwrap();
            (
                InstallLock::take(cli).unwrap(),
                InstallLock::take(daemon).unwrap(),
            )
        };
        let (cli, daemon) = take(&plan);
        let Ok(adopted) = HostLock::adopt(&plan, cli, daemon) else {
            panic!("adopt the caller's own locks");
        };
        stage(&adopted, &root, "tx", plan.clone()).unwrap();
        let waited = HostLock::acquire_within(&plan, std::time::Duration::from_millis(200));
        assert_eq!(
            waited.err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(adopted);
        assert!(HostLock::acquire_within(&plan, std::time::Duration::from_millis(200)).is_ok());
        // Another pair's locks are not this pair's lock: refused, and
        // handed back still held.
        let (_other_dir, other_root) = super::tests::root();
        let other = freeze_plan(input_in(&other_root)).unwrap();
        let (cli, daemon) = take(&other);
        let Err(refusal) = HostLock::adopt(&plan, cli, daemon) else {
            panic!("another pair's locks were adopted");
        };
        assert_eq!(refusal.error.kind(), io::ErrorKind::InvalidInput);
        let waited = HostLock::acquire_within(&other, std::time::Duration::from_millis(200));
        assert_eq!(
            waited.err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock),
            "a refused adopt must not release the caller's locks"
        );
        drop(refusal);
        assert!(HostLock::acquire_within(&other, std::time::Duration::from_millis(200)).is_ok());
    }

    /// #2065 review: `advance` re-reads the journal under the lock and
    /// refuses one that changed since this run wrote it.
    #[test]
    fn advance_refuses_a_journal_that_changed_underneath() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let mut prepared = stage(&lock, &root, "tx", plan).unwrap();
        let edits: [fn(&mut JournalRecord); 3] = [
            |r: &mut JournalRecord| r.transaction_id = "tx-other".into(),
            |r: &mut JournalRecord| r.phase = Phase::Probed,
            |r: &mut JournalRecord| r.plan.participants[0].boot_id = "other-boot".into(),
        ];
        for edit in edits {
            let mut changed = prepared.record().clone();
            edit(&mut changed);
            changed.sequence += 1;
            journal::write_record(prepared.path(), &changed).unwrap();
            assert!(prepared.advance(&lock, Phase::Prepared).is_err());
            // The changed journal is left as it is.
            let bytes = std::fs::read(prepared.path()).unwrap();
            let journal::RecordRead::Journal(read) = journal::classify_record(&bytes, "journal")
            else {
                panic!("the changed journal does not read back");
            };
            assert_eq!(
                serde_json::to_vec(&read).unwrap(),
                serde_json::to_vec(&changed).unwrap()
            );
            // Put this run's journal back for the next case.
            journal::write_record(prepared.path(), prepared.record()).unwrap();
        }
        prepared.advance(&lock, Phase::Prepared).unwrap();
    }

    #[test]
    fn the_swaps_are_ordered_and_checked() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let mut prepared = stage(&lock, &root, "tx", plan).unwrap();
        // No swap before Prepared, and no CLI swap before the daemon's.
        assert!(prepared.advance(&lock, Phase::SwappedDaemon).is_err());
        prepared.advance(&lock, Phase::Prepared).unwrap();
        assert!(prepared.advance(&lock, Phase::SwappedCli).is_err());
        assert!(prepared.advance(&lock, Phase::Booting).is_err());
        // A daemon target that is not the candidate is not a swap.
        let target = prepared.record().plan.daemon.target_path.clone();
        std::fs::write(&target, b"something else").unwrap();
        assert!(prepared.advance(&lock, Phase::SwappedDaemon).is_err());
        assert_eq!(prepared.record().phase, Phase::Prepared);
        std::fs::write(&target, b"candidate-daemon").unwrap();
        prepared.advance(&lock, Phase::SwappedDaemon).unwrap();
        assert!(prepared.advance(&lock, Phase::Prepared).is_err());
    }

    /// #2012: the producer gives up a transaction only over the previous
    /// pair, from Staged up to SwappedCli, and only the journal it last
    /// wrote. The result is Superseded, which no longer blocks an apply and
    /// opens the host-commit gate. Red: drop the previous-pair check.
    #[test]
    fn an_abandoned_transaction_is_superseded_only_over_the_previous_pair() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let lock = HostLock::acquire(&plan).unwrap();
        let mut prepared = stage(&lock, &root, "tx", plan).unwrap();
        prepared.advance(&lock, Phase::Prepared).unwrap();
        let daemon = prepared.record().plan.daemon.clone();
        std::fs::copy(&daemon.target_path, root.join("candidate")).unwrap();
        std::fs::copy(&daemon.backup_path, &daemon.target_path).unwrap();
        // The daemon now holds the previous release; the CLI target too.
        let cli = prepared.record().plan.cli.clone();
        std::fs::copy(&cli.backup_path, &cli.target_path).unwrap();
        std::fs::write(&daemon.target_path, b"neither").unwrap();
        assert!(prepared.abandon(&lock, [true, false]).is_err());
        assert_eq!(prepared.record().phase, Phase::Prepared);
        std::fs::copy(&daemon.backup_path, &daemon.target_path).unwrap();
        assert!(journal::read_boot_records(&root).blocks_apply());
        assert!(!journal::host_commit_gate_open(&root));
        prepared.abandon(&lock, [true, false]).unwrap();
        assert_eq!(prepared.record().phase, Phase::Superseded);
        assert!(prepared.record().daemon_progress.restored);
        assert!(!journal::read_boot_records(&root).blocks_apply());
        assert!(journal::host_commit_gate_open(&root));
        assert!(
            prepared.abandon(&lock, [true, true]).is_err(),
            "settled already"
        );
    }

    /// #2012: of the journal phases, only Idle and Superseded let a later
    /// apply through (`blocks_apply`); HostCommitted, Idle and Superseded
    /// open the host-commit gate.
    #[test]
    fn only_settled_journals_let_an_apply_through() {
        let (_dir, root) = root();
        prepared_in(&root, input_in(&root));
        for (phase, blocks, gate) in [
            (Phase::Staged, true, false),
            (Phase::SwappedCli, true, false),
            (Phase::HostCommitted, true, true),
            (Phase::Restored, true, false),
            (Phase::RecoveryFailed, true, false),
            (Phase::Idle, false, true),
            (Phase::Superseded, false, true),
        ] {
            settle(&root, phase);
            assert_eq!(
                journal::read_boot_records(&root).blocks_apply(),
                blocks,
                "{phase:?}"
            );
            assert_eq!(journal::host_commit_gate_open(&root), gate, "{phase:?}");
        }
        // A handoff record still blocks, whatever the journal.
        std::fs::write(root.join(journal::HANDOFF_FILE_NAME), b"{").unwrap();
        assert!(journal::read_boot_records(&root).blocks_apply());
    }
}
