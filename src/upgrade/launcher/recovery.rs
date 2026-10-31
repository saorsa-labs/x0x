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

    pub(super) fn verify_candidate(&self) -> io::Result<()> {
        for a in [&self.plan().daemon, &self.plan().cli] {
            if hash(&a.target_path)? != a.candidate_sha256 {
                return Err(invalid("candidate pair changed"));
            }
        }
        Ok(())
    }

    /// Every running OLD and NEW identity must be absent. The caller cannot
    /// use a success HTTP response, an exit signal or a stale PID as a reap.
    pub(super) fn restore(
        &self,
        trials: &[(PathBuf, Trial)],
        cause: journal::Cause,
    ) -> io::Result<()> {
        self.locked(|record| {
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
                record.phase = journal::Phase::RollingBack;
                // A recorded Failed cause is never downgraded to Interrupted
                // by a later launcher restart (ADR 0094 S4).
                if !matches!(
                    &record.cause,
                    Some(existing) if existing.class == journal::CauseClass::Failed
                ) {
                    record.cause = Some(cause);
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
        })
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

    /// Restore moves both files back and keeps its cause through Restored.
    #[test]
    fn restore_returns_the_previous_pair_and_keeps_the_cause() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trials = [(root.join("trial.json"), trial(&host))];
        host.restore(&trials, cause(journal::CauseClass::Interrupted))
            .unwrap();
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

    /// Restore never runs while an OLD or candidate process still exists.
    #[cfg(target_os = "linux")]
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
