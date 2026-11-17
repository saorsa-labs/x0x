//! Post-death restore. The independent frozen plan supplies paths; the
//! on-disk journal must match it. A parsed journal alone grants no authority.
use super::filesystem::{hash, restore_one};
use super::*;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

fn lock(path: &Path) -> io::Result<File> {
    let mut name = path.as_os_str().to_os_string();
    name.push(".upgrade.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(name)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("invalid install lock"));
    }
    Ok(file)
}

pub(super) struct Host {
    root: PathBuf,
    expected: journal::JournalRecord,
}

impl Host {
    pub(super) fn new(root: PathBuf, expected: journal::JournalRecord) -> io::Result<Self> {
        // Only the complete inventory issuer may supply `expected`. S3b has
        // no production issuer: fixture construction cannot activate apply.
        for artifact in [&expected.plan.daemon, &expected.plan.cli] {
            if artifact.target_path.canonicalize()? != artifact.target_path
                || artifact.backup_path.canonicalize()? != artifact.backup_path
            {
                return Err(invalid("non-canonical independently approved install"));
            }
        }
        // `data_root` decides where the flush token is sent and where the
        // candidate boot record lands. The boot check compares the child's
        // resolved executable and cwd with these paths, so all must be
        // canonical, and every participant must run the hashed daemon.
        for participant in &expected.plan.participants {
            if participant.data_root.canonicalize()? != participant.data_root
                || participant.cwd.canonicalize()? != participant.cwd
                || participant.executable != expected.plan.daemon.target_path
            {
                return Err(invalid("non-canonical participant paths"));
            }
        }
        Ok(Self { root, expected })
    }

    /// The directory that holds the host journal. Each participant's
    /// handoff and boot records are in its own `data_root`.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }
    pub(super) fn plan(&self) -> &journal::FrozenPlan {
        &self.expected.plan
    }
    pub(super) fn binding(&self) -> io::Result<Binding> {
        Ok(Binding {
            transaction: self.expected.transaction_id.clone(),
            generation: self.expected.generation,
            plan_sha256: digest(&self.expected.plan)?,
        })
    }

    pub(super) fn locked<T>(
        &self,
        action: impl FnOnce(&mut journal::JournalRecord) -> io::Result<T>,
    ) -> io::Result<T> {
        let cli = lock(&self.expected.plan.cli.target_path)?;
        let daemon = lock(&self.expected.plan.daemon.target_path)?;
        let a = cli.metadata()?;
        let b = daemon.metadata()?;
        if a.dev() == b.dev() && a.ino() == b.ino() {
            return Err(invalid("install locks alias"));
        }
        // Same CLI-then-daemon order as the existing pair writer.
        cli.lock()?;
        daemon.lock()?;
        let journal::RecordRead::Journal(mut record) =
            journal::read_boot_records(&self.root).journal
        else {
            return Err(invalid("host journal unavailable"));
        };
        if record.transaction_id != self.expected.transaction_id
            || record.generation != self.expected.generation
            || digest(&record.plan)? != digest(&self.expected.plan)?
        {
            return Err(invalid("host journal differs from independent plan"));
        }
        action(&mut record)
    }

    fn save(&self, record: &mut journal::JournalRecord) -> io::Result<()> {
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sequence exhausted"))?;
        journal::write_record(&self.root.join(journal::JOURNAL_FILE_NAME), record)
    }

    /// Record that no safe automatic step remains. A committed host is
    /// never changed.
    pub(super) fn mark_recovery_failed(&self) -> io::Result<()> {
        self.locked(|record| {
            if record.phase == journal::Phase::HostCommitted {
                return Err(invalid("a committed host is never marked failed"));
            }
            record.phase = journal::Phase::RecoveryFailed;
            self.save(record)
        })
    }

    /// As `mark_recovery_failed`, for one launcher's failed coordinator pass
    /// (#1991 review): a host that a peer has already restored is also left
    /// alone. Its pair is back, and a RecoveryFailed mark would block every
    /// participant's restored start. Returns the phase found under the lock.
    pub(super) fn mark_unrestored_recovery_failed(&self) -> io::Result<journal::Phase> {
        self.locked(|record| match record.phase {
            journal::Phase::HostCommitted => {
                Err(invalid("a committed host is never marked failed"))
            }
            journal::Phase::Restored => Ok(journal::Phase::Restored),
            found => {
                record.phase = journal::Phase::RecoveryFailed;
                self.save(record)?;
                Ok(found)
            }
        })
    }

    /// Write the host commit (ADR 0094 §3 `host-committed`). Under the host
    /// lock: the transaction must be uncommitted and not rolling back, both
    /// installed files must hash to the candidate pair, and `check` (the
    /// full-set health check) must pass. A refusal changes nothing.
    ///
    /// A file that hashes to other bytes rolls back as Failed. A hash that
    /// cannot be read (an I/O error) is returned as `Err` for the caller to
    /// retry: a transient read error must not hold the release (D189).
    pub(super) fn commit(
        &self,
        check: impl FnOnce() -> io::Result<commit::Commit>,
    ) -> io::Result<commit::Commit> {
        self.locked(|record| {
            if !matches!(
                record.phase,
                journal::Phase::SwappedCli
                    | journal::Phase::HandoffArmed
                    | journal::Phase::Booting
                    | journal::Phase::HealthCommitted
            ) {
                return Err(invalid("host is not in a committable phase"));
            }
            for a in [&self.plan().daemon, &self.plan().cli] {
                // A missing, symlinked, non-regular or oversized installed
                // file will fail every retry: roll back now as Failed. Only
                // a true I/O error is returned for the caller to retry; if
                // it keeps happening, the trial's total deadline rolls back.
                let installed = match hash(&a.target_path) {
                    Ok(installed) => Some(installed),
                    Err(error) if super::filesystem::persistent_hash_error(&error) => None,
                    Err(error) => return Err(error),
                };
                if installed != Some(a.candidate_sha256) {
                    return Ok(commit::Commit::RollBack(cause(
                        journal::CauseClass::Failed,
                        "installed pair is not the candidate pair",
                    )));
                }
            }
            let decision = check()?;
            if decision == commit::Commit::Committed {
                record.phase = journal::Phase::HostCommitted;
                self.save(record)?;
            }
            Ok(decision)
        })
    }

    pub(super) fn verify_candidate(&self) -> io::Result<()> {
        for a in [&self.plan().daemon, &self.plan().cli] {
            if hash(&a.target_path)? != a.candidate_sha256 {
                return Err(invalid("candidate pair changed"));
            }
        }
        Ok(())
    }

    /// Fence the host before the coordinator stops any participant: write
    /// RollingBack and the cause under the host lock. `run::run_trial`
    /// spawns only in SwappedCli or HandoffArmed under the same lock, so no
    /// candidate starts after this returns (A14, #1940 review). Returns the
    /// phase found under the lock. A host that a peer restored, committed or
    /// marked recovery-failed in the meantime is left unchanged.
    ///
    /// `snapshot` runs under the same lock unless the host is final. The
    /// coordinator loads every trial there. A restored child starts only
    /// under this lock with the host `Restored`, and a Restored host never
    /// returns to RollingBack, so when this returns any other phase, every
    /// child in that snapshot is a candidate.
    pub(super) fn fence(
        &self,
        cause: &journal::Cause,
        snapshot: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<journal::Phase> {
        self.locked(|record| {
            let found = record.phase;
            match found {
                journal::Phase::HostCommitted | journal::Phase::RecoveryFailed => return Ok(found),
                journal::Phase::Restored => {}
                _ => {
                    record_cause(record, cause.clone());
                    record.phase = journal::Phase::RollingBack;
                    self.save(record)?;
                }
            }
            snapshot()?;
            Ok(found)
        })
    }

    /// Every running OLD and NEW identity must be absent. The caller cannot
    /// use a success HTTP response, an exit signal or a stale PID as a reap.
    pub(super) fn restore(
        &self,
        trials: &[(PathBuf, Trial)],
        cause: journal::Cause,
    ) -> io::Result<()> {
        self.locked(|record| self.restore_locked(record, trials, cause))
    }

    /// `restore` with the host lock held and `record` read under it. The
    /// coordinator calls it inside its own `locked` section, so the phase
    /// read, the trial marks and the restore are one step.
    pub(super) fn restore_locked(
        &self,
        record: &mut journal::JournalRecord,
        trials: &[(PathBuf, Trial)],
        cause: journal::Cause,
    ) -> io::Result<()> {
        if matches!(
            record.phase,
            journal::Phase::RecoveryFailed | journal::Phase::HostCommitted
        ) {
            return Err(invalid("automatic recovery is forbidden in this phase"));
        }
        for p in &self.plan().participants {
            if p.was_running {
                let old = Identity {
                    pid: p.old_pid.ok_or_else(|| invalid("old pid missing"))?,
                    start: p
                        .process_start
                        .ok_or_else(|| invalid("old start missing"))?,
                    boot: p.boot_id.clone(),
                };
                if !child::absent(&old)? {
                    return Err(invalid("OLD participant still exists"));
                }
                let (_, trial) = trials
                    .iter()
                    .find(|(_, t)| t.instance == p.instance_id)
                    .ok_or_else(|| invalid("participant trial missing"))?;
                if trial.binding != self.binding()? {
                    return Err(invalid("trial binding mismatch"));
                }
                if let Some(identity) = &trial.child {
                    if !child::absent(identity)? {
                        return Err(invalid("candidate still exists"));
                    }
                }
            }
        }
        let result = (|| {
            record_cause(record, cause);
            // A Restored host never returns to RollingBack: restored
            // children may run, and a crash here must not leave a phase
            // that tells the next pass to stop them.
            if record.phase != journal::Phase::Restored {
                record.phase = journal::Phase::RollingBack;
            }
            self.save(record)?;
            // The cause remains in the journal through Restored. An
            // unresolved M2 record already blocks all apply ingress.
            for (index, a) in [self.plan().daemon.clone(), self.plan().cli.clone()]
                .iter()
                .enumerate()
            {
                let observed = hash(&a.target_path)?;
                if observed != a.previous_sha256 && observed != a.candidate_sha256 {
                    return Err(invalid("restore target contains unrelated bytes"));
                }
                if hash(&a.backup_path)? != a.previous_sha256 {
                    return Err(invalid("rollback copy changed"));
                }
                if observed != a.previous_sha256 {
                    restore_one(a)?;
                }
                if hash(&a.target_path)? != a.previous_sha256 {
                    return Err(invalid("restore hash mismatch"));
                }
                let progress = if index == 0 {
                    &mut record.daemon_progress
                } else {
                    &mut record.cli_progress
                };
                progress.restored = true;
                progress.observed_sha256 = Some(a.previous_sha256);
                self.save(record)?;
            }
            record.phase = journal::Phase::Restored;
            self.save(record)
        })();
        if let Err(error) = result {
            record.phase = journal::Phase::RecoveryFailed;
            let _ = self.save(record);
            return Err(error);
        }
        Ok(())
    }
}

/// Merge `cause` into the host record before it moves to RollingBack.
/// ADR 0094 S4: once restoration is complete, the cause is retained.
/// Restored children may already run, so a later cause must not change the
/// hold decision behind them. Before that, the first cause wins, except
/// that a Failed cause replaces an Interrupted one, so the hold is durable
/// before any restored start and a Failed cause is never downgraded.
fn record_cause(record: &mut journal::JournalRecord, cause: journal::Cause) {
    let keep = match &record.cause {
        Some(_) if record.phase == journal::Phase::Restored => true,
        Some(existing) => {
            existing.class == journal::CauseClass::Failed
                || cause.class != journal::CauseClass::Failed
        }
        None => false,
    };
    if !keep {
        record.cause = Some(cause);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::testkit::fixture;
    use super::*;

    fn trial(host: &Host) -> Trial {
        Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap()
    }

    fn cause(class: journal::CauseClass) -> journal::Cause {
        journal::Cause {
            class,
            reason: "fixture cause".into(),
        }
    }

    fn journal_record(root: &Path) -> journal::JournalRecord {
        match journal::read_boot_records(root).journal {
            journal::RecordRead::Journal(record) => *record,
            _ => panic!("journal record missing"),
        }
    }

    #[test]
    fn new_refuses_non_canonical_install_and_participant_paths() {
        let (_dir, root, _host, record) = fixture(journal::Phase::SwappedCli);
        // `Path` equality ignores `.` components, so alias through a symlink.
        let link = root.join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        let aliased = |path: &Path| link.join(path.file_name().unwrap());
        let edits: [&dyn Fn(&mut journal::JournalRecord); 5] = [
            &|r| r.plan.daemon.target_path = aliased(&r.plan.daemon.target_path),
            &|r| r.plan.cli.backup_path = aliased(&r.plan.cli.backup_path),
            &|r| r.plan.participants[0].data_root = link.clone(),
            &|r| r.plan.participants[0].cwd = link.clone(),
            &|r| r.plan.participants[0].executable = r.plan.cli.target_path.clone(),
        ];
        for edit in edits {
            let mut changed = record.clone();
            edit(&mut changed);
            let error = Host::new(root.clone(), changed).err().unwrap().to_string();
            assert!(error.contains("non-canonical"), "{error}");
        }
    }

    #[test]
    fn locked_refuses_a_journal_that_differs_from_the_independent_plan() {
        let (_dir, root, _host, mut other) = fixture(journal::Phase::SwappedCli);
        other.transaction_id = "another-transaction".into();
        let host = Host::new(root, other).unwrap();
        let error = host.locked(|_| Ok(())).unwrap_err().to_string();
        assert!(error.contains("differs"), "{error}");
    }

    #[test]
    fn authorize_refuses_without_host_agreement_and_reap_receipts() {
        for (phase, refusal) in [
            (journal::Phase::Staged, "not ready"),
            (journal::Phase::SwappedCli, "reap receipts"),
        ] {
            let (_dir, root, host, _record) = fixture(phase);
            let path = root.join("trial.json");
            let mut trial = trial(&host);
            trial.save(&path).unwrap();
            let error = super::super::control::authorize(&host, &mut trial, &path, &[])
                .unwrap_err()
                .to_string();
            assert!(error.contains(refusal), "{error}");
            assert_eq!(trial.phase, Phase::Armed);
        }
    }

    #[test]
    fn restore_refuses_in_a_terminal_phase_and_keeps_the_journal() {
        for phase in [
            journal::Phase::RecoveryFailed,
            journal::Phase::HostCommitted,
        ] {
            let (_dir, root, host, _record) = fixture(phase);
            let trials = [(root.join("trial.json"), trial(&host))];
            let error = host
                .restore(&trials, cause(journal::CauseClass::Failed))
                .unwrap_err()
                .to_string();
            assert!(error.contains("forbidden"), "{error}");
            assert_eq!(journal_record(&root).phase, phase);
            assert_eq!(
                filesystem::hash(&host.plan().daemon.target_path).unwrap(),
                host.plan().daemon.candidate_sha256
            );
        }
    }

    /// A damaged rollback copy or unrelated target bytes never replace the
    /// installed file: restore refuses before any byte moves and the journal
    /// marks RecoveryFailed.
    #[test]
    fn restore_refuses_a_changed_rollback_copy_or_unrelated_bytes() {
        for (damaged, refusal) in [(true, "rollback copy changed"), (false, "unrelated bytes")] {
            let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
            let daemon = &host.plan().daemon;
            let file = if damaged {
                &daemon.backup_path
            } else {
                &daemon.target_path
            };
            std::fs::write(file, b"unrelated").unwrap();
            let before = filesystem::hash(&daemon.target_path).unwrap();
            let trials = [(root.join("trial.json"), trial(&host))];
            let error = host
                .restore(&trials, cause(journal::CauseClass::Failed))
                .unwrap_err()
                .to_string();
            assert!(error.contains(refusal), "{error}");
            assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
            assert_eq!(filesystem::hash(&daemon.target_path).unwrap(), before);
        }
    }

    /// Restore moves both files back and keeps its first cause through Restored.
    #[test]
    fn restore_returns_the_previous_pair_and_keeps_the_cause() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trials = [(root.join("trial.json"), trial(&host))];
        host.restore(&trials, cause(journal::CauseClass::Interrupted))
            .unwrap();
        // A second restore from Restored must not overwrite the first
        // cause, not even with a Failed one.
        let later = journal::Cause {
            class: journal::CauseClass::Failed,
            reason: "later restore".into(),
        };
        host.restore(&trials, later).unwrap();
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let kept = record.cause.unwrap();
        assert_eq!(kept.class, journal::CauseClass::Interrupted);
        assert_eq!(kept.reason, "fixture cause");
        for a in [&host.plan().daemon, &host.plan().cli] {
            assert_eq!(filesystem::hash(&a.target_path).unwrap(), a.previous_sha256);
        }
        assert!(record.daemon_progress.restored && record.cli_progress.restored);
    }

    /// A restore that re-enters after a launcher restart keeps a Failed
    /// cause already in the journal (ADR 0094: a held release stays held).
    #[test]
    fn restore_keeps_a_failed_journal_cause() {
        let (_dir, root, _host, mut record) = fixture(journal::Phase::RollingBack);
        record.cause = Some(cause(journal::CauseClass::Failed));
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = Host::new(root.clone(), record).unwrap();
        let trials = [(root.join("trial.json"), trial(&host))];
        let interrupted = journal::Cause {
            class: journal::CauseClass::Interrupted,
            reason: "launcher died during rollback".into(),
        };
        host.restore(&trials, interrupted).unwrap();
        let kept = journal_record(&root).cause.unwrap();
        assert_eq!(kept.class, journal::CauseClass::Failed);
        assert_eq!(kept.reason, "fixture cause");
    }

    /// Before restoration completes, a Failed cause replaces an Interrupted
    /// one, so the failed-release hold is durable before a restored start.
    #[test]
    fn restore_lets_a_failed_cause_replace_an_interrupted_one_before_restored() {
        let (_dir, root, _host, mut record) = fixture(journal::Phase::RollingBack);
        record.cause = Some(cause(journal::CauseClass::Interrupted));
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = Host::new(root.clone(), record).unwrap();
        let trials = [(root.join("trial.json"), trial(&host))];
        let failed = journal::Cause {
            class: journal::CauseClass::Failed,
            reason: "launch attempts exhausted".into(),
        };
        host.restore(&trials, failed).unwrap();
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let kept = record.cause.unwrap();
        assert_eq!(kept.class, journal::CauseClass::Failed);
        assert_eq!(kept.reason, "launch attempts exhausted");
    }

    /// Restore never runs while an OLD or candidate process still exists.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn restore_refuses_while_an_old_or_candidate_process_lives() {
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = child::identity(live.id()).unwrap();
        for old_is_live in [true, false] {
            let (_dir, root, _host, mut record) = fixture(journal::Phase::SwappedCli);
            if old_is_live {
                let p = &mut record.plan.participants[0];
                p.old_pid = Some(identity.pid);
                p.process_start = Some(identity.start);
                p.boot_id = identity.boot.clone();
            }
            journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
            let host = Host::new(root.clone(), record).unwrap();
            let mut candidate = trial(&host);
            candidate.child = (!old_is_live).then(|| identity.clone());
            let error = host
                .restore(
                    &[(root.join("trial.json"), candidate)],
                    cause(journal::CauseClass::Failed),
                )
                .unwrap_err()
                .to_string();
            assert!(error.contains("still exists"), "{error}");
            assert_eq!(journal_record(&root).phase, journal::Phase::SwappedCli);
        }
        live.kill().unwrap();
        live.wait().unwrap();
    }
}
