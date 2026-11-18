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
//! Dormant: no apply path calls it yet.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::journal::{self, ArtifactPlan, FrozenPlan, JournalRecord, Participant, Phase};

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
    /// in-flight or unreadable one is refused.
    #[cfg(unix)]
    pub(crate) fn stage(
        data_root: &Path,
        transaction_id: &str,
        plan: FrozenPlan,
    ) -> io::Result<Self> {
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
        let path = data_root.join(journal::JOURNAL_FILE_NAME);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                let bytes = journal::read_auxiliary_record(&path)?;
                match journal::classify_record(&bytes, "journal") {
                    journal::RecordRead::Journal(earlier) if settled(earlier.phase) => {}
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
        let record = record(transaction_id, plan, Phase::Staged);
        checked(&record)?;
        journal::write_record(&path, &record)?;
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
    /// release (their planned sha256).
    pub(crate) fn advance(&mut self, phase: Phase) -> io::Result<()> {
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
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;
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

    /// Stage, then move through every forward phase to `SwappedCli`.
    pub(crate) fn prepared_in(root: &Path, input: PlanInput) -> Prepared {
        let plan = freeze_plan(input).unwrap();
        let mut prepared = Prepared::stage(root, "tx-2012", plan).unwrap();
        for phase in [
            Phase::Probed,
            Phase::Prepared,
            Phase::SwappedDaemon,
            Phase::SwappedCli,
        ] {
            prepared.advance(phase).unwrap();
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
    fn staging_needs_a_participant_root_of_this_account() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let other = root.join("other");
        std::fs::create_dir(&other).unwrap();
        assert!(Prepared::stage(&other, "tx", plan.clone()).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(Prepared::stage(&root, "tx", plan.clone()).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Prepared::stage(&root, " ", plan).is_err());
    }

    #[test]
    fn an_in_flight_journal_is_never_replaced() {
        let (_dir, root) = root();
        let prepared = prepared_in(&root, input_in(&root));
        let plan = prepared.record().plan.clone();
        assert!(Prepared::stage(&root, "tx-next", plan.clone()).is_err());
        // A settled journal may be replaced.
        let mut settled = prepared.record().clone();
        settled.phase = Phase::HostCommitted;
        settled.sequence += 1;
        journal::write_record(prepared.path(), &settled).unwrap();
        assert!(Prepared::stage(&root, "tx-next", plan).is_ok());
    }

    #[test]
    fn the_swaps_are_ordered_and_checked() {
        let (_dir, root) = root();
        let plan = freeze_plan(input_in(&root)).unwrap();
        let mut prepared = Prepared::stage(&root, "tx", plan).unwrap();
        // No swap before Prepared, and no CLI swap before the daemon's.
        assert!(prepared.advance(Phase::SwappedDaemon).is_err());
        prepared.advance(Phase::Prepared).unwrap();
        assert!(prepared.advance(Phase::SwappedCli).is_err());
        assert!(prepared.advance(Phase::Booting).is_err());
        // A daemon target that is not the candidate is not a swap.
        let target = prepared.record().plan.daemon.target_path.clone();
        std::fs::write(&target, b"something else").unwrap();
        assert!(prepared.advance(Phase::SwappedDaemon).is_err());
        assert_eq!(prepared.record().phase, Phase::Prepared);
        std::fs::write(&target, b"candidate-daemon").unwrap();
        prepared.advance(Phase::SwappedDaemon).unwrap();
        assert!(prepared.advance(Phase::Prepared).is_err());
    }
}
