//! S3c host coordinator recovery (ADR 0094 §3, §4; #1376). Dormant like the
//! rest of this module: no production caller yet. The caller holds the
//! independent frozen plan (`Host`), every participant's trial record, and a
//! way to stop and reap a live child of another launcher.
//!
//! One pass reconciles the host after a crash, a stop or a reboot. It never
//! starts a child. It stops and reaps every live participant before a pair
//! restore, restores the pair once for all participants, and leaves each
//! trial `Restored` so each launcher starts only its missing restored child
//! (`run::run_trial`). A `RecoveryFailed` host or trial is final and stays so
//! across restarts.
use super::*;

/// What the host must do after one coordinator pass.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Resolution {
    /// No recovery is needed: the transaction continues as planned.
    Proceed,
    /// The previous pair is installed and every trial is `Restored`. Each
    /// launcher may start its missing restored child. `After` is the D189
    /// decision for the release.
    Restored(After),
    /// No automatic action is allowed (`RecoveryFailed` or `HostCommitted`).
    Final(journal::Phase),
}

/// The D189 decision after a restore.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum After {
    /// A Failed cause, or interrupted retries exhausted: hold the release.
    Hold(journal::Cause),
    /// An Interrupted cause with retries left: stage a fresh transaction
    /// after this delay.
    RetryAfterMs(u64),
}

/// D189: an interrupted attempt retries as a fresh transaction at 30, 60 and
/// 120 minutes (N = 3), then holds with `retries_exhausted`. A Failed cause
/// holds at once. `prior_retries` is the count of fresh retry transactions
/// already staged for this release.
pub(super) fn after_restore(cause: &journal::Cause, prior_retries: u32) -> After {
    if cause.class == journal::CauseClass::Failed {
        return After::Hold(cause.clone());
    }
    match probe::RETRY_DELAYS_MS.get(prior_retries as usize) {
        Some(delay) => After::RetryAfterMs(*delay),
        None => After::Hold(super::cause(
            journal::CauseClass::Failed,
            "retries_exhausted",
        )),
    }
}

/// Reconcile the host once.
///
/// `handoff_present` says whether the transaction's handoff record exists.
/// `stop` must stop and reap the live process with that identity; the pass
/// checks absence itself afterwards and never trusts the callback alone.
pub(super) fn reconcile(
    host: &recovery::Host,
    trials: &mut [(PathBuf, Trial)],
    handoff_present: bool,
    clock: &Clock,
    prior_retries: u32,
    mut stop: impl FnMut(&Identity) -> io::Result<()>,
) -> io::Result<Resolution> {
    let (phase, journal_cause) = host.locked(|record| Ok((record.phase, record.cause.clone())))?;
    // A RecoveryFailed trial or host survives restart and blocks every
    // automatic step (ADR 0094 §4).
    if phase == journal::Phase::RecoveryFailed
        || trials
            .iter()
            .any(|(_, trial)| trial.phase == Phase::RecoveryFailed)
    {
        return Ok(Resolution::Final(journal::Phase::RecoveryFailed));
    }
    if phase == journal::Phase::HostCommitted {
        return Ok(Resolution::Final(phase));
    }
    let binding = host.binding()?;
    if trials.iter().any(|(_, trial)| trial.binding != binding) {
        return Err(invalid("trial binding mismatch"));
    }
    // Partial restore: the pair is back. Keep the cause and mark every
    // trial Restored, so each launcher starts only a missing child.
    if phase == journal::Phase::Restored {
        let cause = journal_cause.ok_or_else(|| invalid("restored host has no cause"))?;
        mark_restored(trials, &cause)?;
        return Ok(Resolution::Restored(after_restore(&cause, prior_retries)));
    }
    let Some(cause) = recovery_cause(host, trials, phase, journal_cause, handoff_present, clock)?
    else {
        return Ok(Resolution::Proceed);
    };
    // Stop and reap every participant before the pair restore. A
    // provisional commit by a healthy participant is invalidated here.
    if let Err(error) = stop_all(host, trials, &mut stop) {
        // Nothing moved, but no safe automatic step remains: record it on
        // the host as well, so the block does not live in trials alone.
        let _ = host.mark_recovery_failed();
        return Err(fail_all(trials, error));
    }
    for (path, trial) in trials.iter_mut() {
        begin_rollback(path, trial, &cause)?;
    }
    if let Err(error) = host.restore(trials, cause) {
        return Err(fail_all(trials, error));
    }
    // `restore` keeps an earlier Failed cause: read back the durable one.
    let kept = host
        .locked(|record| Ok(record.cause.clone()))?
        .ok_or_else(|| invalid("restored host has no cause"))?;
    mark_restored(trials, &kept)?;
    Ok(Resolution::Restored(after_restore(&kept, prior_retries)))
}

/// The cause that requires a pair restore, or `None` to proceed.
fn recovery_cause(
    host: &recovery::Host,
    trials: &[(PathBuf, Trial)],
    phase: journal::Phase,
    journal_cause: Option<journal::Cause>,
    handoff_present: bool,
    clock: &Clock,
) -> io::Result<Option<journal::Cause>> {
    // A Failed verdict anywhere wins: the failed release must be held. An
    // attempt still running is counted but has not failed, so only its
    // budget can decide while it has a child (as `run` does on a stop).
    let verdicts: Vec<journal::Cause> = trials
        .iter()
        .filter_map(|(_, trial)| {
            let exhausted = || {
                trial
                    .child
                    .is_none()
                    .then(|| run::failed_verdict(trial, clock))
                    .flatten()
            };
            trial
                .verdict
                .clone()
                .or_else(exhausted)
                .or_else(|| trial.expired(clock))
        })
        .collect();
    let found = verdicts
        .iter()
        .find(|verdict| verdict.class == journal::CauseClass::Failed)
        .or(verdicts.first())
        .cloned();
    // A coordinator that died during a restore left RollingBack: resume it.
    if phase == journal::Phase::RollingBack {
        return Ok(Some(found.or(journal_cause).unwrap_or_else(|| {
            cause(
                journal::CauseClass::Interrupted,
                "coordinator died during rollback",
            )
        })));
    }
    if found.is_some() {
        return Ok(found);
    }
    // Both swaps may be done with no handoff written and the OLD process
    // gone. The NEW bytes are unarmed: never start them, restore instead.
    let swapped = matches!(
        phase,
        journal::Phase::SwappedDaemon | journal::Phase::SwappedCli
    );
    let unstarted = trials
        .iter()
        .all(|(_, trial)| trial.phase == Phase::Armed && trial.child.is_none());
    if swapped && !handoff_present && unstarted && old_participants_absent(host)? {
        return Ok(Some(cause(
            journal::CauseClass::Interrupted,
            "handoff missing after swap",
        )));
    }
    Ok(None)
}

fn old_identity(p: &journal::Participant) -> io::Result<Option<Identity>> {
    if !p.was_running {
        return Ok(None);
    }
    Ok(Some(Identity {
        pid: p.old_pid.ok_or_else(|| invalid("old pid missing"))?,
        start: p
            .process_start
            .ok_or_else(|| invalid("old start missing"))?,
        boot: p.boot_id.clone(),
    }))
}

fn old_participants_absent(host: &recovery::Host) -> io::Result<bool> {
    for p in &host.plan().participants {
        if let Some(old) = old_identity(p)? {
            if !child::absent(&old)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Stop and reap every live OLD and candidate process, then prove each one
/// is absent. A process that survives its stop leaves no safe restore.
fn stop_all(
    host: &recovery::Host,
    trials: &[(PathBuf, Trial)],
    stop: &mut impl FnMut(&Identity) -> io::Result<()>,
) -> io::Result<()> {
    let mut identities = Vec::new();
    for p in &host.plan().participants {
        identities.extend(old_identity(p)?);
    }
    identities.extend(trials.iter().filter_map(|(_, trial)| trial.child.clone()));
    for identity in &identities {
        if !child::absent(identity)? {
            stop(identity)?;
            if !child::absent(identity)? {
                return Err(invalid("participant survived its stop"));
            }
        }
    }
    Ok(())
}

fn mark_restored(trials: &mut [(PathBuf, Trial)], cause: &journal::Cause) -> io::Result<()> {
    for (path, trial) in trials.iter_mut() {
        if trial.phase == Phase::Restored {
            continue;
        }
        if trial.phase == Phase::RollingBack {
            trial.verdict.get_or_insert_with(|| cause.clone());
        } else {
            begin_rollback(path, trial, cause)?;
        }
        trial.phase = Phase::Restored;
        trial.save(path)?;
    }
    Ok(())
}

/// Keep the first verdict, drop custody of the gone child, save RollingBack.
fn begin_rollback(path: &Path, trial: &mut Trial, cause: &journal::Cause) -> io::Result<()> {
    trial.verdict.get_or_insert_with(|| cause.clone());
    trial.child = None;
    trial.phase = Phase::RollingBack;
    trial.save(path)
}

/// No safe automatic step remains: every trial records RecoveryFailed.
fn fail_all(trials: &mut [(PathBuf, Trial)], error: io::Error) -> io::Error {
    for (path, trial) in trials.iter_mut() {
        let _ = trial.recovery_failed(path, invalid(&error));
    }
    error
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::testkit::{fixture, fixture_with};
    use super::*;

    fn now() -> Clock {
        Clock::now().unwrap()
    }

    fn journal_record(root: &Path) -> journal::JournalRecord {
        match journal::read_boot_records(root).journal {
            journal::RecordRead::Journal(record) => *record,
            _ => panic!("journal record missing"),
        }
    }

    fn assert_previous_pair(host: &recovery::Host) {
        for a in [&host.plan().daemon, &host.plan().cli] {
            assert_eq!(filesystem::hash(&a.target_path).unwrap(), a.previous_sha256);
        }
    }

    fn assert_candidate_pair(host: &recovery::Host) {
        for a in [&host.plan().daemon, &host.plan().cli] {
            assert_eq!(
                filesystem::hash(&a.target_path).unwrap(),
                a.candidate_sha256
            );
        }
    }

    /// One saved trial per participant, in `dir`, at `phase`.
    fn make_trials(
        host: &recovery::Host,
        dir: &Path,
        clock: &Clock,
        phase: Phase,
    ) -> Vec<(PathBuf, Trial)> {
        host.plan()
            .participants
            .iter()
            .map(|p| {
                let path = dir.join(format!("{}.trial.json", p.instance_id));
                let mut trial =
                    Trial::new(host.binding().unwrap(), p.instance_id.clone(), clock).unwrap();
                trial.save(&path).unwrap();
                if phase != Phase::Armed {
                    trial.phase = Phase::Authorized;
                    trial.save(&path).unwrap();
                }
                if matches!(phase, Phase::Booting | Phase::Provisional) {
                    trial.attempts = 1;
                    trial.phase = Phase::Booting;
                    trial.save(&path).unwrap();
                }
                (path, trial)
            })
            .collect()
    }

    fn no_stop(identity: &Identity) -> io::Result<()> {
        panic!("no live process expected, asked to stop {identity:?}")
    }

    fn two_participants(record: &mut journal::JournalRecord) {
        let mut bob = record.plan.participants[0].clone();
        bob.instance_id = "bob".into();
        record.plan.participants.push(bob);
    }

    fn reload(trials: &[(PathBuf, Trial)], host: &recovery::Host) -> Vec<Trial> {
        trials
            .iter()
            .map(|(path, trial)| {
                Trial::load(path, &host.binding().unwrap(), &trial.instance).unwrap()
            })
            .collect()
    }

    /// Case 1: both swaps done, no handoff written, OLD process gone. The
    /// unarmed NEW bytes are not started; the pair is restored.
    #[test]
    fn missing_handoff_restores_the_unarmed_pair() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Armed);

        let resolution = reconcile(&host, &mut trials, false, &clock, 0, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Restored(After::RetryAfterMs(30 * 60_000))
        );
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        assert_eq!(record.cause.unwrap().reason, "handoff missing after swap");
        for trial in reload(&trials, &host) {
            assert_eq!(trial.phase, Phase::Restored);
        }
    }

    /// With the handoff present, an unstarted transaction proceeds.
    #[test]
    fn a_present_handoff_proceeds_without_restore() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Armed);
        let resolution = reconcile(&host, &mut trials, true, &clock, 0, no_stop).unwrap();
        assert_eq!(resolution, Resolution::Proceed);
        assert_candidate_pair(&host);
    }

    /// Case 2: A is healthy (Provisional), B failed before host commit.
    /// A's provisional commit is invalidated, both are reaped, the pair is
    /// restored once, and the Failed cause holds the release.
    #[test]
    fn one_healthy_and_one_failed_participant_restore_together_and_hold() {
        let (_dir, root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);
        // A: provisional with a child from another boot (already gone).
        {
            let (path, a) = &mut trials[0];
            a.attempts = 1;
            a.phase = Phase::Booting;
            a.save(path).unwrap();
            a.child = Some(Identity {
                pid: 4300,
                start: 1,
                boot: a.boot.clone(),
            });
            a.ready_since_ms = Some(clock.ms);
            a.phase = Phase::Provisional;
            a.save(path).unwrap();
            a.child.as_mut().unwrap().boot = "earlier-boot".into();
        }
        // B: its launcher began rollback with a Failed verdict.
        {
            let (path, b) = &mut trials[1];
            b.verdict = Some(cause(
                journal::CauseClass::Failed,
                "launch attempts exhausted",
            ));
            b.phase = Phase::RollingBack;
            b.save(path).unwrap();
        }

        let resolution = reconcile(&host, &mut trials, true, &clock, 0, no_stop).unwrap();
        let held = cause(journal::CauseClass::Failed, "launch attempts exhausted");
        assert_eq!(resolution, Resolution::Restored(After::Hold(held)));
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        assert_eq!(record.cause.unwrap().class, journal::CauseClass::Failed);
        for trial in reload(&trials, &host) {
            assert_eq!(trial.phase, Phase::Restored, "{}", trial.instance);
            assert!(trial.child.is_none());
        }
    }

    /// Case 2 with live processes: the coordinator stops and reaps the
    /// healthy candidate before the pair restore.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_healthy_candidate_is_stopped_and_reaped_before_restore() {
        let (_dir, _root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Booting);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = child::identity(live.id()).unwrap();
        {
            let (path, a) = &mut trials[0];
            a.child = Some(identity.clone());
            a.ready_since_ms = Some(clock.ms);
            a.phase = Phase::Provisional;
            a.save(path).unwrap();
        }
        {
            let (path, b) = &mut trials[1];
            b.verdict = Some(cause(
                journal::CauseClass::Failed,
                "readiness deadline reached",
            ));
            b.phase = Phase::RollingBack;
            b.save(path).unwrap();
        }
        let mut stopped = Vec::new();
        let resolution = reconcile(&host, &mut trials, true, &clock, 0, |target| {
            stopped.push(target.clone());
            live.kill()?;
            live.wait().map(|_| ())
        })
        .unwrap();
        assert!(matches!(resolution, Resolution::Restored(After::Hold(_))));
        assert_eq!(stopped, vec![identity]);
        assert_previous_pair(&host);
    }

    /// A participant that survives its stop leaves no safe restore: no byte
    /// moves and every trial is RecoveryFailed.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_participant_that_survives_its_stop_fails_recovery_without_restore() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Booting);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        {
            let (path, a) = &mut trials[0];
            a.child = Some(child::identity(live.id()).unwrap());
            a.verdict = Some(cause(journal::CauseClass::Failed, "stable health lost"));
            a.save(path).unwrap();
        }
        let error = reconcile(&host, &mut trials, true, &clock, 0, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("survived"), "{error}");
        assert_candidate_pair(&host);
        assert_eq!(trials[0].1.phase, Phase::RecoveryFailed);
        assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
        live.kill().unwrap();
        live.wait().unwrap();
    }

    /// Case 3: a coordinator that died during a restore left the host
    /// RollingBack. The successor resumes the restore and keeps the cause.
    #[test]
    fn a_successor_coordinator_resumes_an_interrupted_restore() {
        let (_dir, root, _host, mut record) = fixture(journal::Phase::RollingBack);
        record.cause = Some(cause(journal::CauseClass::Interrupted, "first coordinator"));
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = recovery::Host::new(root.clone(), record).unwrap();
        // The first coordinator restored the daemon only.
        let daemon = host.plan().daemon.clone();
        filesystem::restore_one(&daemon).unwrap();
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);

        let resolution = reconcile(&host, &mut trials, true, &clock, 1, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Restored(After::RetryAfterMs(60 * 60_000))
        );
        assert_previous_pair(&host);
        let kept = journal_record(&root).cause.unwrap();
        assert_eq!(kept.reason, "first coordinator");
    }

    /// Case 4: the pair was restored but the coordinator died before every
    /// trial was marked. The next pass marks them Restored and moves no byte.
    #[test]
    fn a_partial_restore_marks_every_trial_restored_without_moving_bytes() {
        let (_dir, root, _host, mut record) = fixture(journal::Phase::Restored);
        record.cause = Some(cause(journal::CauseClass::Interrupted, "earlier pass"));
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = recovery::Host::new(root.clone(), record).unwrap();
        for a in [&host.plan().daemon, &host.plan().cli] {
            filesystem::restore_one(a).unwrap();
        }
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);

        let resolution = reconcile(&host, &mut trials, true, &clock, 3, no_stop).unwrap();
        // Interrupted with three retries already used: hold (D189).
        let exhausted = cause(journal::CauseClass::Failed, "retries_exhausted");
        assert_eq!(resolution, Resolution::Restored(After::Hold(exhausted)));
        assert_previous_pair(&host);
        for trial in reload(&trials, &host) {
            assert_eq!(trial.phase, Phase::Restored);
            assert_eq!(trial.verdict.unwrap().reason, "earlier pass");
        }
    }

    /// Case 5: the hold record cannot be made durable. No byte moves, no
    /// restored start is possible, and every trial is RecoveryFailed.
    #[test]
    fn a_hold_write_failure_moves_no_bytes_and_fails_recovery() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores directory permissions
        }
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        // Create the install locks, then make the journal directory read-only.
        host.locked(|_| Ok(())).unwrap();
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);
        trials[0].1.verdict = Some(cause(journal::CauseClass::Failed, "stable health lost"));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = reconcile(&host, &mut trials, true, &clock, 0, no_stop);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert_candidate_pair(&host);
        assert_ne!(journal_record(&root).phase, journal::Phase::Restored);
        for trial in reload(&trials, &host) {
            assert_eq!(trial.phase, Phase::RecoveryFailed);
        }
    }

    /// Case 6: a reboot during the trial records Interrupted, restores the
    /// pair, and keeps the trial's counters.
    #[test]
    fn a_reboot_restores_and_keeps_the_trial_counters() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let earlier = Clock {
            boot: "earlier-boot".into(),
            ms: 1_000,
        };
        let mut trials = make_trials(&host, trial_dir.path(), &earlier, Phase::Booting);
        let clock = now();

        let resolution = reconcile(&host, &mut trials, true, &clock, 0, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Restored(After::RetryAfterMs(30 * 60_000))
        );
        assert_previous_pair(&host);
        let kept = journal_record(&root).cause.unwrap();
        assert_eq!(kept.class, journal::CauseClass::Interrupted);
        for trial in reload(&trials, &host) {
            assert_eq!(trial.phase, Phase::Restored);
            assert_eq!(trial.attempts, 1, "counters never reset");
            assert_eq!(trial.boot, "earlier-boot");
        }
    }

    /// A final attempt that is still running has not failed: the pass
    /// proceeds and stops nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_final_attempt_is_not_treated_as_failed() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Booting);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        {
            let (path, a) = &mut trials[0];
            a.attempts = MAX_ATTEMPTS;
            a.child = Some(child::identity(live.id()).unwrap());
            a.save(path).unwrap();
        }
        let resolution = reconcile(&host, &mut trials, true, &clock, 0, no_stop).unwrap();
        assert_eq!(resolution, Resolution::Proceed);
        assert_candidate_pair(&host);
        live.kill().unwrap();
        live.wait().unwrap();
    }

    /// Nothing is swapped yet in `Prepared`: a missing handoff restores
    /// nothing and charges no retry.
    #[test]
    fn a_prepared_host_without_handoff_proceeds() {
        let (_dir, root, host, _record) = fixture(journal::Phase::Prepared);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Armed);
        let resolution = reconcile(&host, &mut trials, false, &clock, 0, no_stop).unwrap();
        assert_eq!(resolution, Resolution::Proceed);
        assert_eq!(journal_record(&root).phase, journal::Phase::Prepared);
    }

    /// RecoveryFailed survives a restart: a later pass takes no action.
    #[test]
    fn recovery_failed_survives_a_restart_and_blocks_every_action() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);
        let (path, trial) = &mut trials[0];
        let _ = trial.recovery_failed(path, invalid("fixture failure"));
        // A restarted coordinator reloads the durable trial.
        let mut reloaded: Vec<_> = reload(&trials, &host)
            .into_iter()
            .zip(trials.iter().map(|(path, _)| path.clone()))
            .map(|(trial, path)| (path, trial))
            .collect();
        let resolution = reconcile(&host, &mut reloaded, false, &clock, 0, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Final(journal::Phase::RecoveryFailed)
        );
        assert_candidate_pair(&host);

        let (_dir, _root, host, _record) = fixture(journal::Phase::RecoveryFailed);
        let other_dir = tempfile::tempdir().unwrap();
        let mut trials = make_trials(&host, other_dir.path(), &clock, Phase::Armed);
        let resolution = reconcile(&host, &mut trials, false, &clock, 0, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Final(journal::Phase::RecoveryFailed)
        );
    }

    #[test]
    fn d189_retries_three_times_then_holds() {
        let interrupted = cause(journal::CauseClass::Interrupted, "x");
        assert_eq!(
            after_restore(&interrupted, 0),
            After::RetryAfterMs(30 * 60_000)
        );
        assert_eq!(
            after_restore(&interrupted, 1),
            After::RetryAfterMs(60 * 60_000)
        );
        assert_eq!(
            after_restore(&interrupted, 2),
            After::RetryAfterMs(120 * 60_000)
        );
        assert!(
            matches!(after_restore(&interrupted, 3), After::Hold(c) if c.reason == "retries_exhausted")
        );
        let failed = cause(journal::CauseClass::Failed, "y");
        assert_eq!(after_restore(&failed, 0), After::Hold(failed.clone()));
    }
}
