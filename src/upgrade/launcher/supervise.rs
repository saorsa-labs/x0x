//! The launcher's supervise driver (#1378): one trial, from the first
//! candidate start to a host commit, a stop, or a restored child. It is the
//! production caller of `commit::host_commit`. It is dormant: the launcher
//! calls it only when `ENABLED` is true and the inventory issuer has given
//! it a host.
//!
//! The run loop's readiness is process stability: the candidate acknowledged
//! its boot barrier and stayed alive for `STABLE_MS`. The candidate's own
//! health commit (`upgrade-health.json`, ADR 0094 A14) is the host commit
//! gate, polled here until the full set commits, a rollback is due, or the
//! trial's total deadline passes.
use super::*;
use coordinator::Resolution;

/// How often a provisional trial polls the host commit.
const COMMIT_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// What the supervise driver needs from the candidate it owns. The
/// production type is `child::Owned`; tests use a stand-in.
pub(super) trait Custody {
    fn exited(&mut self) -> io::Result<bool>;
    /// Stop the child if it still runs, then reap it.
    fn reap(self) -> io::Result<()>;
}

impl Custody for child::Owned {
    fn exited(&mut self) -> io::Result<bool> {
        Ok(child::Owned::exited(self)?.is_some())
    }

    fn reap(self) -> io::Result<()> {
        child::Owned::reap(self).map(drop)
    }
}

pub(super) enum Settled<C> {
    /// The host is committed with this candidate running.
    Committed(C),
    /// An intentional stop ended the trial; the next start rolls back.
    Stopped,
    /// This launcher reaped its candidate and ran the coordinator pass.
    Recovered(Resolution),
}

pub(super) enum Supervised {
    Committed(child::Owned),
    Restored(child::Owned),
    Stopped,
    /// No automatic step is allowed (`RecoveryFailed`, or a host a peer
    /// committed while this launcher had no candidate).
    Final(journal::Phase),
}

/// Run one participant's trial with the live clock and process custody.
pub(super) fn supervise(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    mut stop: impl FnMut() -> bool,
) -> io::Result<Supervised> {
    // Readiness is the boot barrier plus `STABLE_MS` alive; the health
    // commit is checked by the host commit below.
    let provisional = match run::run_trial(host, path, trial, Clock::now, |_| Ok(true), &mut stop)?
    {
        run::Outcome::Stopped => return Ok(Supervised::Stopped),
        run::Outcome::Restored(child) => return Ok(Supervised::Restored(child)),
        run::Outcome::Provisional(child) => child,
    };
    let settled = settle_provisional(
        host,
        path,
        trial,
        provisional,
        coordinator::trial_path,
        Clock::now,
        &mut stop,
        coordinator::recover,
        || std::thread::sleep(COMMIT_POLL),
    )?;
    match settled {
        Settled::Committed(child) => Ok(Supervised::Committed(child)),
        Settled::Stopped => Ok(Supervised::Stopped),
        // Every trial is Restored: start this participant's restored child.
        Settled::Recovered(Resolution::Restored(_)) => {
            match run::run_trial(host, path, trial, Clock::now, |_| Ok(true), &mut stop)? {
                run::Outcome::Restored(child) => Ok(Supervised::Restored(child)),
                _ => Err(invalid("restored trial did not start the restored child")),
            }
        }
        Settled::Recovered(Resolution::Final(phase)) => Ok(Supervised::Final(phase)),
        Settled::Recovered(Resolution::Proceed) => {
            Err(invalid("recovery found no cause after a rollback was due"))
        }
    }
}

/// After the run loop returned a provisional candidate: poll the host
/// commit until one of these:
/// - the full set commits, here or by a peer: `Committed`;
/// - an intentional stop: the child is reaped and the trial `Stopped`, as
///   in the run loop;
/// - a rollback is due: the host commit says so, the candidate exited, the
///   trial's total deadline passed, or a peer has begun recovery. The child
///   is reaped first (the coordinator refuses a live child of this
///   process), the cause is saved as this trial's verdict under the host
///   lock, and `recover` runs the coordinator pass over the full set.
///
/// A host commit that returns an I/O error is polled again; one that keeps
/// failing ends at the total deadline, which rolls back as Failed.
#[allow(clippy::too_many_arguments)]
pub(super) fn settle_provisional<C: Custody>(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    mut child: C,
    trial_path: impl Fn(&journal::Participant) -> PathBuf,
    mut now: impl FnMut() -> io::Result<Clock>,
    mut stop: impl FnMut() -> bool,
    recover: impl FnOnce(&recovery::Host) -> io::Result<Resolution>,
    mut pause: impl FnMut(),
) -> io::Result<Settled<C>> {
    if trial.phase != Phase::Provisional {
        return Err(invalid("trial is not provisional"));
    }
    let due = loop {
        if stop() {
            run::record_budget_verdict(trial, now().ok().as_ref());
            if let Err(error) = child.reap() {
                return Err(trial.recovery_failed(path, error));
            }
            trial.child = None;
            trial.phase = Phase::Stopped;
            trial.save(path)?;
            return Ok(Settled::Stopped);
        }
        match host.locked(|record| Ok(record.phase))? {
            journal::Phase::HostCommitted => return Ok(Settled::Committed(child)),
            // A peer's coordinator has fenced the host: join its recovery.
            journal::Phase::RollingBack
            | journal::Phase::Restored
            | journal::Phase::RecoveryFailed => break None,
            _ => {}
        }
        let clock = now()?;
        if let Some(cause) = trial.expired(&clock) {
            break Some(cause);
        }
        if child.exited()? {
            break Some(cause(
                journal::CauseClass::Failed,
                "candidate exited before the host commit",
            ));
        }
        match commit::host_commit(host, &load_trials(host, &trial_path)?) {
            Ok(commit::Commit::Committed) => return Ok(Settled::Committed(child)),
            Ok(commit::Commit::RollBack(cause)) => break Some(cause),
            Ok(commit::Commit::NotYet(_)) | Err(_) => pause(),
        }
    };
    if let Err(error) = child.reap() {
        return Err(trial.recovery_failed(path, error));
    }
    let (binding, instance) = (trial.binding.clone(), trial.instance.clone());
    if let Some(cause) = due {
        // Under the host lock, as a peer's coordinator writes this trial.
        // The first verdict wins (ADR 0094 S4).
        host.locked(|_| {
            let mut current = Trial::load(path, &binding, &instance)?;
            current.verdict.get_or_insert(cause);
            current.save(path)
        })?;
    }
    let resolution = recover(host)?;
    *trial = Trial::load(path, &binding, &instance)?;
    Ok(Settled::Recovered(resolution))
}

/// Every participant's trial on disk. A missing one is left out, so the
/// host commit waits for it.
fn load_trials(
    host: &recovery::Host,
    trial_path: &impl Fn(&journal::Participant) -> PathBuf,
) -> io::Result<Vec<(PathBuf, Trial)>> {
    let binding = host.binding()?;
    let mut trials = Vec::new();
    for p in &host.plan().participants {
        let path = trial_path(p);
        match Trial::load(&path, &binding, &p.instance_id) {
            Ok(trial) => trials.push((path, trial)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(trials)
}

#[cfg(all(test, unix))]
mod tests {
    use super::testkit::fixture;
    use super::*;
    use std::cell::Cell;

    /// A candidate stand-in: `alive` until reaped or told to exit.
    struct Stand {
        exited: bool,
        reaped: std::rc::Rc<Cell<bool>>,
    }

    impl Custody for Stand {
        fn exited(&mut self) -> io::Result<bool> {
            Ok(self.exited)
        }
        fn reap(self) -> io::Result<()> {
            self.reaped.set(true);
            Ok(())
        }
    }

    fn stand(exited: bool) -> (Stand, std::rc::Rc<Cell<bool>>) {
        let reaped = std::rc::Rc::new(Cell::new(false));
        (
            Stand {
                exited,
                reaped: reaped.clone(),
            },
            reaped,
        )
    }

    /// A child identity that is gone on any host.
    fn gone_child() -> Identity {
        Identity {
            pid: 4300,
            start: 1,
            boot: "fixture-boot".into(),
        }
    }

    /// A Provisional trial at `path` whose child is `identity`.
    fn provisional(host: &recovery::Host, path: &Path, identity: Identity) -> Trial {
        let clock = Clock {
            boot: identity.boot.clone(),
            ms: 1_000,
        };
        let mut trial = Trial::new(host.binding().unwrap(), "alice".into(), &clock).unwrap();
        trial.save(path).unwrap();
        trial.phase = Phase::Authorized;
        trial.save(path).unwrap();
        trial.reserve(path, &clock).unwrap();
        trial.child = Some(identity);
        trial.ready_since_ms = Some(clock.ms);
        trial.phase = Phase::Provisional;
        trial.save(path).unwrap();
        trial
    }

    fn at(trial: &Trial, ms: u64) -> impl FnMut() -> io::Result<Clock> {
        let boot = trial.boot.clone();
        move || {
            Ok(Clock {
                boot: boot.clone(),
                ms,
            })
        }
    }

    fn journal_phase(root: &Path) -> journal::Phase {
        match journal::read_boot_records(root).journal {
            journal::RecordRead::Journal(record) => record.phase,
            _ => panic!("journal missing"),
        }
    }

    fn set_journal_phase(root: &Path, phase: journal::Phase) {
        let mut record = match journal::read_boot_records(root).journal {
            journal::RecordRead::Journal(record) => *record,
            _ => panic!("journal missing"),
        };
        record.sequence += 1;
        record.phase = phase;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
    }

    /// Runs `settle_provisional` with a recover stand-in that records the
    /// trial's verdict as it saw it on disk.
    #[allow(clippy::type_complexity)]
    fn settle(
        host: &recovery::Host,
        path: &Path,
        trial: &mut Trial,
        child: Stand,
        ms: u64,
        polls: usize,
    ) -> (
        io::Result<Settled<Stand>>,
        Option<Option<journal::Cause>>,
        usize,
    ) {
        let seen = Cell::new(None);
        let paused = Cell::new(0);
        let clock = at(trial, ms);
        let result = settle_provisional(
            host,
            path,
            trial,
            child,
            |_| path.to_path_buf(),
            clock,
            || paused.get() >= polls,
            |host| {
                let trial = Trial::load(path, &host.binding()?, "alice")?;
                seen.set(Some(trial.verdict));
                Ok(Resolution::Final(journal::Phase::RecoveryFailed))
            },
            || paused.set(paused.get() + 1),
        );
        (result, seen.into_inner(), paused.get())
    }

    /// A host commit that is not due yet polls until the stop, which reaps
    /// the child and leaves the trial Stopped; the host is not committed.
    #[test]
    fn not_yet_polls_until_a_stop_reaps_and_saves_stopped() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = provisional(&host, &path, gone_child());
        let (child, reaped) = stand(false);
        let (result, recovered, polls) = settle(&host, &path, &mut trial, child, 2_000, 3);
        assert!(matches!(result.unwrap(), Settled::Stopped));
        assert!(reaped.get());
        assert_eq!(polls, 3, "no health commit: the driver keeps polling");
        assert!(recovered.is_none());
        assert_eq!(trial.phase, Phase::Stopped);
        assert_eq!(journal_phase(&root), journal::Phase::SwappedCli);
    }

    /// The host commit's rollback cause becomes the trial verdict before
    /// the coordinator pass, and the child is reaped first.
    #[test]
    fn a_host_commit_rollback_saves_the_verdict_and_recovers() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = provisional(&host, &path, gone_child());
        // The CLI changed after the swap: the host commit rolls back.
        std::fs::write(&host.plan().cli.target_path, b"other cli").unwrap();
        let (child, reaped) = stand(false);
        let (result, recovered, _) = settle(&host, &path, &mut trial, child, 2_000, usize::MAX);
        assert!(matches!(
            result.unwrap(),
            Settled::Recovered(Resolution::Final(journal::Phase::RecoveryFailed))
        ));
        assert!(reaped.get());
        let verdict = recovered.expect("recover ran").expect("verdict saved");
        assert_eq!(verdict.class, journal::CauseClass::Failed);
        assert!(verdict.reason.contains("candidate pair"), "{verdict:?}");
    }

    /// A candidate that exits before the host commit rolls back as Failed.
    #[test]
    fn a_candidate_exit_before_the_commit_rolls_back_as_failed() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = provisional(&host, &path, gone_child());
        let (child, reaped) = stand(true);
        let (result, recovered, _) = settle(&host, &path, &mut trial, child, 2_000, usize::MAX);
        assert!(matches!(result.unwrap(), Settled::Recovered(_)));
        assert!(reaped.get());
        let verdict = recovered.unwrap().unwrap();
        assert_eq!(verdict.class, journal::CauseClass::Failed);
        assert!(verdict.reason.contains("exited"), "{verdict:?}");
    }

    /// A health commit that never arrives ends at the total deadline, which
    /// rolls back as Failed.
    #[test]
    fn the_total_deadline_rolls_back_as_failed() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = provisional(&host, &path, gone_child());
        let deadline = trial.deadline_ms;
        let (child, _reaped) = stand(false);
        let (result, recovered, polls) =
            settle(&host, &path, &mut trial, child, deadline, usize::MAX);
        assert!(matches!(result.unwrap(), Settled::Recovered(_)));
        assert_eq!(polls, 0);
        let verdict = recovered.unwrap().unwrap();
        assert_eq!(verdict.reason, "total trial deadline reached");
    }

    /// A peer's coordinator fenced the host: this launcher reaps its child
    /// and joins the pass without a verdict of its own. A host a peer
    /// committed is Committed here too, with the child kept.
    #[test]
    fn a_peer_fence_joins_recovery_and_a_peer_commit_is_committed() {
        for (found, joins) in [
            (journal::Phase::RollingBack, true),
            (journal::Phase::Restored, true),
            (journal::Phase::RecoveryFailed, true),
            (journal::Phase::HostCommitted, false),
        ] {
            let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
            let path = root.join("trial.json");
            let mut trial = provisional(&host, &path, gone_child());
            set_journal_phase(&root, found);
            let (child, reaped) = stand(false);
            let (result, recovered, _) = settle(&host, &path, &mut trial, child, 2_000, usize::MAX);
            match result.unwrap() {
                Settled::Recovered(_) => {
                    assert!(joins, "{found:?}");
                    assert!(reaped.get());
                    assert_eq!(recovered, Some(None), "no verdict of its own");
                }
                Settled::Committed(_) => {
                    assert!(!joins, "{found:?}");
                    assert!(!reaped.get(), "the committed child keeps running");
                }
                Settled::Stopped => panic!("no stop was requested"),
            }
        }
    }

    /// A verdict already on the trial wins over the later cause (ADR 0094
    /// S4: the first verdict is kept).
    #[test]
    fn an_earlier_verdict_is_kept() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = provisional(&host, &path, gone_child());
        trial.verdict = Some(cause(journal::CauseClass::Interrupted, "first"));
        trial.save(&path).unwrap();
        let (child, _reaped) = stand(true);
        let (_result, recovered, _) = settle(&host, &path, &mut trial, child, 2_000, usize::MAX);
        assert_eq!(recovered.unwrap().unwrap().reason, "first");
    }

    /// End to end with the production coordinator pass: a rollback that is
    /// due (here the total deadline) restores the previous pair, holds the release (D190) and
    /// leaves the trial Restored with the Failed verdict.
    #[test]
    fn a_due_rollback_restores_the_pair_through_the_coordinator() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let plan = host.plan();
        let install = plan.daemon.target_path.clone();
        let state = probe::ProbeState {
            schema_version: 1,
            record_kind: "probe".into(),
            install: install.clone(),
            version: plan.candidate_version.clone(),
            platform: "fixture-platform".into(),
            archive_sha256: [1; 32],
            transaction_id: "00000000-0000-4000-8000-000000000001".into(),
            attempt: 1,
            phase: probe::ProbePhase::Passed,
            cause: None,
            last_pid: None,
            boot_id: "fixture-boot".into(),
            retry_remaining_ms: 0,
            retry_deadline_ms: 0,
            daemon_sha256: Some(plan.daemon.candidate_sha256),
            cli_sha256: Some(plan.cli.candidate_sha256),
        };
        journal::write_auxiliary_record(&probe::state_path(&install).unwrap(), &state, |_| Ok(()))
            .unwrap();
        let path = coordinator::trial_path(&plan.participants[0]);
        let mut trial = provisional(&host, &path, gone_child());
        // No health commit before the total deadline: Failed.
        let (child, reaped) = stand(false);
        let clock = at(&trial, trial.deadline_ms);
        let settled = settle_provisional(
            &host,
            &path,
            &mut trial,
            child,
            coordinator::trial_path,
            clock,
            || false,
            coordinator::recover,
            || {},
        )
        .unwrap();
        assert!(reaped.get());
        assert!(
            matches!(
                settled,
                Settled::Recovered(Resolution::Restored(coordinator::After::Hold(_)))
            ),
            "the Failed verdict holds the release"
        );
        for a in [&plan.daemon, &plan.cli] {
            assert_eq!(filesystem::hash(&a.target_path).unwrap(), a.previous_sha256);
        }
        assert_eq!(journal_phase(&root), journal::Phase::Restored);
        assert_eq!(trial.phase, Phase::Restored);
        assert_eq!(
            trial.verdict.as_ref().map(|v| v.class),
            Some(journal::CauseClass::Failed)
        );
    }

    /// A healthy live full set commits the host through the driver, and the
    /// child is handed back unreaped.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_healthy_live_candidate_commits_the_host() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = child::identity(live.id()).unwrap();
        let mut trial = provisional(&host, &path, identity.clone());
        let p = &host.plan().participants[0];
        let record = journal::HealthRecord {
            schema_version: journal::SCHEMA_VERSION,
            record_kind: "health".into(),
            transaction_id: trial.binding.transaction.clone(),
            generation: trial.binding.generation,
            instance_id: p.instance_id.clone(),
            attempt: trial.attempts,
            pid: identity.pid,
            process_start: identity.start,
            boot_id: identity.boot.clone(),
            version: host.plan().candidate_version.clone(),
            data_root: p.data_root.clone(),
            identity_root: p.identity_root.clone(),
            executable_sha256: host.plan().daemon.candidate_sha256,
            stores_initialized: true,
            local_verdict: journal::LocalVerdict::Ok,
            previously_connected: false,
            peer_continuity: false,
        };
        journal::write_auxiliary_record(
            &root.join(journal::HEALTH_FILE_NAME),
            &record,
            journal::validate_health,
        )
        .unwrap();
        let (child, reaped) = stand(false);
        let (result, recovered, _) = {
            // The trial was saved on the identity's boot.
            let trial_boot = identity.boot.clone();
            let seen: Cell<Option<Option<journal::Cause>>> = Cell::new(None);
            let result = settle_provisional(
                &host,
                &path,
                &mut trial,
                child,
                |_| path.clone(),
                || {
                    Ok(Clock {
                        boot: trial_boot.clone(),
                        ms: 2_000,
                    })
                },
                || false,
                |_| {
                    seen.set(Some(None));
                    Ok(Resolution::Proceed)
                },
                || {},
            );
            (result, seen.into_inner(), 0)
        };
        live.kill().unwrap();
        live.wait().unwrap();
        assert!(matches!(result.unwrap(), Settled::Committed(_)));
        assert!(!reaped.get());
        assert!(recovered.is_none());
        assert_eq!(journal_phase(&root), journal::Phase::HostCommitted);
    }
}
