//! S3c host coordinator recovery (ADR 0094 §3, §4; #1376). Dormant like the
//! rest of this module. `recover` is the production pass. The supervise
//! driver calls it after a due rollback, and `run::run_trial` calls it for
//! its own rollback on a host with more than one participant. Both need a
//! `Host` from the complete inventory issuer (#1378), which does not exist
//! yet, so no live path reaches it.
//!
//! One pass reconciles the host after a crash, a stop or a reboot. It never
//! starts a child. It fences the host to RollingBack, so no launcher can
//! start a candidate, then stops and reaps every live participant before a pair
//! restore, restores the pair once for all participants, records the D189 or
//! D190 outcome in the release's probe record, and only then leaves each
//! trial `Restored`, so each launcher starts only its missing restored child
//! (`run::run_trial`). A `RecoveryFailed` host or trial is final and stays so
//! across restarts. Every failure after the pass decides to restore marks
//! the host and every trial `RecoveryFailed`, so no later pass repeats it.
use super::*;

/// What the host must do after one coordinator pass.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Resolution {
    /// No recovery is needed: the transaction continues as planned.
    Proceed,
    /// The previous pair is installed, the outcome is durable in the probe
    /// record and every trial is `Restored`. Each launcher may start its
    /// missing restored child.
    Restored(After),
    /// No automatic action is allowed (`RecoveryFailed` or `HostCommitted`).
    Final(journal::Phase),
}

/// The D189 or D190 outcome after a restore, as the probe record holds it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum After {
    /// A Failed cause, or interrupted retries exhausted: the release is
    /// held (D190).
    Hold(journal::Cause),
    /// An Interrupted cause with retries left: a fresh transaction for the
    /// release may stage after this delay (D189).
    RetryAfterMs(u64),
    /// The hold was already cleared, or a newer release owns the probe
    /// record.
    Resolved,
}

/// Each participant's trial record, beside its data root.
pub(super) const TRIAL_FILE_NAME: &str = "upgrade-trial.json";

pub(super) fn trial_path(participant: &journal::Participant) -> PathBuf {
    participant.data_root.join(TRIAL_FILE_NAME)
}

/// The production pass: trial records at `trial_path`, each running
/// participant's handoff record read from its data root, the live clock,
/// and `child::stop_foreign` for every live participant. `host` must come
/// from the complete inventory issuer (#1378). There is none yet, so no
/// live path calls this while `ENABLED` is false.
///
/// Contract for the caller: it stops and reaps its own child
/// (`child::Owned::reap`) first. `stop_foreign` only signals; a child of
/// this process would stay a zombie that only this process can reap, so
/// the pass refuses one before it acts.
pub(super) fn recover(host: &recovery::Host) -> io::Result<Resolution> {
    let binding = host.binding()?;
    for p in &host.plan().participants {
        let path = trial_path(p);
        match Trial::load(&path, &binding, &p.instance_id) {
            Ok(trial) => {
                if let Some(identity) = &trial.child {
                    if !child::absent(identity)? && child::is_own_child(identity)? {
                        return Err(invalid("own child must be reaped before recover"));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    reconcile(
        host,
        trial_path,
        handoff_present(host)?,
        &Clock::now()?,
        child::stop_foreign,
    )
}

/// Whether every running participant's handoff for this transaction is
/// durable. Only an M2 handoff whose transaction, generation and instance
/// equal the binding counts. A missing record means not armed. Any other
/// record (a legacy handoff, another transaction or generation, another
/// instance, or an unreadable one) refuses the pass: counting it as present
/// would skip the missing-handoff restore and start unarmed NEW bytes.
fn handoff_present(host: &recovery::Host) -> io::Result<bool> {
    let binding = host.binding()?;
    let mut all = true;
    for p in host.plan().participants.iter().filter(|p| p.was_running) {
        match journal::read_boot_records(&p.data_root).handoff {
            journal::RecordRead::Missing => all = false,
            journal::RecordRead::Handoff(record)
                if record.transaction_id == binding.transaction
                    && record.generation == binding.generation
                    && record.instance_id == p.instance_id => {}
            _ => {
                return Err(invalid(
                    "handoff record does not belong to this transaction",
                ))
            }
        }
    }
    Ok(all)
}

/// Reconcile the host once.
///
/// `trial_path` names each participant's trial record. A missing record
/// means that participant's launcher never armed a trial, so it never asked
/// OLD to stop and never started a candidate. `handoff_present` says whether
/// the transaction's handoff record exists. `stop` must stop and reap the
/// live process with that identity; the pass checks absence itself
/// afterwards and never trusts the callback alone.
pub(super) fn reconcile(
    host: &recovery::Host,
    trial_path: impl Fn(&journal::Participant) -> PathBuf,
    handoff_present: bool,
    clock: &Clock,
    mut stop: impl FnMut(&Identity) -> io::Result<()>,
) -> io::Result<Resolution> {
    let (phase, journal_cause) = host.locked(|record| Ok((record.phase, record.cause.clone())))?;
    if phase == journal::Phase::RecoveryFailed {
        return Ok(Resolution::Final(phase));
    }
    let binding = host.binding()?;
    let mut trials = Vec::new();
    let mut unarmed = Vec::new();
    for p in &host.plan().participants {
        let path = trial_path(p);
        match Trial::load(&path, &binding, &p.instance_id) {
            Ok(trial) => trials.push((path, trial)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                unarmed.push((path, p.instance_id.clone()));
            }
            Err(error) => return Err(error),
        }
    }
    // A RecoveryFailed trial or host survives restart and blocks every
    // automatic step (ADR 0094 §4).
    if any_recovery_failed(&trials) {
        return Ok(Resolution::Final(journal::Phase::RecoveryFailed));
    }
    if phase == journal::Phase::HostCommitted {
        return Ok(Resolution::Final(phase));
    }
    // Partial restore: the pair is back. Keep the cause, make the outcome
    // durable, and mark every trial Restored.
    if phase == journal::Phase::Restored {
        let cause = journal_cause.ok_or_else(|| invalid("restored host has no cause"))?;
        arm(&mut trials, unarmed, &binding, clock)
            .map_err(|error| fail(host, &mut trials, error))?;
        return settle(host, &mut trials, &binding, &cause, clock);
    }
    let Some(cause) = recovery_cause(host, &trials, phase, journal_cause, handoff_present, clock)?
    else {
        return Ok(Resolution::Proceed);
    };
    // A participant with no trial record gets an Armed one first, so the
    // restore has custody of every participant and any later failure is
    // durable in a trial even when the host record cannot be written.
    // Without it the restore refuses with "participant trial missing" and
    // every later pass repeats that refusal.
    if let Err(error) = arm(&mut trials, unarmed, &binding, clock) {
        return Err(fail(host, &mut trials, error));
    }
    // Fence the host first: once RollingBack is durable under the host lock,
    // no launcher can spawn a candidate or commit the host. A peer may have
    // spawned after the first load; its child is durable in its trial
    // (spawn saves it under the same lock), so load every trial again,
    // under the fence's lock. A restored child starts only under that lock
    // on a Restored host, so every child in a snapshot taken with the host
    // not Restored is a candidate: the stop below can never reach a
    // restored child, whatever a peer does after the lock is free.
    // A peer may also have committed or restored the host since the first
    // read: the fence leaves such a host alone.
    let fenced = host.fence(&cause, || reload(&mut trials, &binding));
    let found = fenced.map_err(|error| fail(host, &mut trials, error))?;
    if matches!(
        found,
        journal::Phase::HostCommitted | journal::Phase::RecoveryFailed
    ) {
        return Ok(Resolution::Final(found));
    }
    // A trial that a peer marked RecoveryFailed in the meantime is final.
    if any_recovery_failed(&trials) {
        return Ok(Resolution::Final(journal::Phase::RecoveryFailed));
    }
    // A peer finished the restore: as the partial-restore case, no stop.
    if found != journal::Phase::Restored {
        // Stop and reap every participant before the pair restore. A
        // provisional commit by a healthy participant is invalidated here.
        if let Err(error) = stop_all(host, &trials, &mut stop) {
            return Err(fail(host, &mut trials, error));
        }
    }
    settle(host, &mut trials, &binding, &cause, clock)
}

fn any_recovery_failed(trials: &[(PathBuf, Trial)]) -> bool {
    trials
        .iter()
        .any(|(_, trial)| trial.phase == Phase::RecoveryFailed)
}

/// The last step of a pass, in one host lock: read the phase again, then
/// act on it. The lock was free during the stop, so a peer may have
/// finished the restore and a launcher may have started a restored child
/// (#1950 review).
///
/// - `RollingBack`: mark the trials, restore the pair.
/// - `Restored`: a peer restored the pair (or an earlier pass did). Load
///   the trials again; stop nothing and move no byte.
/// - `RecoveryFailed`, or a trial that is: final. A peer marked what it
///   could; this pass writes nothing.
///
/// Then, still under the lock, record the D189 or D190 outcome in the
/// probe record (the hold barrier before any restored start) and mark
/// every trial Restored. A launcher starts a restored child only under
/// this lock, so none starts between the restore and the marks.
fn settle(
    host: &recovery::Host,
    trials: &mut [(PathBuf, Trial)],
    binding: &Binding,
    cause: &journal::Cause,
    clock: &Clock,
) -> io::Result<Resolution> {
    let settled = host.locked(|record| {
        let failed = Resolution::Final(journal::Phase::RecoveryFailed);
        match record.phase {
            journal::Phase::RollingBack => {
                // A peer that failed with the host journal unwritable left
                // the host RollingBack but marked the trials
                // RecoveryFailed: final, write nothing (#1950 review).
                reload(trials, binding)?;
                if any_recovery_failed(trials) {
                    return Ok(failed);
                }
                for (path, trial) in trials.iter_mut() {
                    begin_rollback(path, trial, cause)?;
                }
                host.restore_locked(record, trials, cause.clone())?;
            }
            journal::Phase::Restored => {
                reload(trials, binding)?;
                if any_recovery_failed(trials) {
                    return Ok(failed);
                }
            }
            journal::Phase::RecoveryFailed => return Ok(failed),
            // The fence allows no other phase: refuse and stay failed.
            _ => return Err(invalid("host left RollingBack without a restore")),
        }
        // `restore_locked` and a peer's restore keep an earlier Failed
        // cause: use the durable one.
        let kept = record
            .cause
            .clone()
            .ok_or_else(|| invalid("restored host has no cause"))?;
        let after = record_outcome(host, &kept, clock)?;
        mark_restored(trials, &kept)?;
        Ok(Resolution::Restored(after))
    });
    settled.map_err(|error| fail(host, trials, error))
}

/// Save an Armed trial for each participant that has none.
fn arm(
    trials: &mut Vec<(PathBuf, Trial)>,
    unarmed: Vec<(PathBuf, String)>,
    binding: &Binding,
    clock: &Clock,
) -> io::Result<()> {
    for (path, instance) in unarmed {
        let trial = Trial::new(binding.clone(), instance, clock)?;
        trial.save(&path)?;
        trials.push((path, trial));
    }
    Ok(())
}

/// Load every trial from disk again, under the host lock.
fn reload(trials: &mut [(PathBuf, Trial)], binding: &Binding) -> io::Result<()> {
    for (path, trial) in trials.iter_mut() {
        *trial = Trial::load(path, binding, &trial.instance)?;
    }
    Ok(())
}

fn record_outcome(
    host: &recovery::Host,
    cause: &journal::Cause,
    clock: &Clock,
) -> io::Result<After> {
    let plan = host.plan();
    let outcome = probe::record_apply_outcome(
        &plan.daemon.target_path,
        &plan.candidate_version,
        (plan.daemon.candidate_sha256, plan.cli.candidate_sha256),
        cause.class == journal::CauseClass::Failed,
        &probe::ProbeClock {
            boot_id: clock.boot.clone(),
            monotonic_ms: clock.ms,
        },
    )?;
    Ok(match outcome {
        probe::ApplyOutcome::Held(probe::ProbeCause::RetriesExhausted) => After::Hold(
            super::cause(journal::CauseClass::Failed, "retries_exhausted"),
        ),
        probe::ApplyOutcome::Held(_) => After::Hold(cause.clone()),
        probe::ApplyOutcome::Waiting { retry_after_ms } => After::RetryAfterMs(retry_after_ms),
        probe::ApplyOutcome::Resolved => After::Resolved,
    })
}

/// No safe automatic step remains: the host and every trial record
/// RecoveryFailed, so no later pass repeats the step. A committed host is
/// never changed.
fn fail(host: &recovery::Host, trials: &mut [(PathBuf, Trial)], error: io::Error) -> io::Error {
    let error = match host.mark_recovery_failed() {
        Ok(()) => error,
        // The trials still carry the marker; report both failures.
        Err(mark) => invalid(format!("{error}; host not marked recovery-failed: {mark}")),
    };
    fail_all(trials, error)
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
    use super::super::testkit;
    use super::testkit::write_probe;
    use super::*;

    fn now() -> Clock {
        Clock::now().unwrap()
    }

    /// The shared fixture plus a Passed probe record for the candidate, as
    /// the probe leaves it before the swap.
    fn fixture(
        phase: journal::Phase,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        recovery::Host,
        journal::JournalRecord,
    ) {
        fixture_with(phase, |_| {})
    }

    fn fixture_with(
        phase: journal::Phase,
        edit: impl FnOnce(&mut journal::JournalRecord),
    ) -> (
        tempfile::TempDir,
        PathBuf,
        recovery::Host,
        journal::JournalRecord,
    ) {
        let fixture = testkit::fixture_with(phase, edit);
        write_probe(&fixture.2, 1, probe::ProbePhase::Passed);
        fixture
    }

    fn probe_state(host: &recovery::Host) -> Option<probe::ProbeState> {
        probe::read_state(&host.plan().daemon.target_path).unwrap()
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

    fn path_in(dir: &Path) -> impl Fn(&journal::Participant) -> PathBuf + '_ {
        move |p| dir.join(format!("{}.trial.json", p.instance_id))
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
                let path = path_in(dir)(p);
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

    /// Every participant's trial as saved on disk.
    fn reload(host: &recovery::Host, dir: &Path) -> Vec<Trial> {
        host.plan()
            .participants
            .iter()
            .map(|p| {
                Trial::load(&path_in(dir)(p), &host.binding().unwrap(), &p.instance_id).unwrap()
            })
            .collect()
    }

    /// Case 1: both swaps done, no handoff written, OLD process gone. The
    /// unarmed NEW bytes are not started; the pair is restored and the
    /// first D189 wait is durable in the probe record.
    #[test]
    fn missing_handoff_restores_the_unarmed_pair() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        make_trials(&host, trial_dir.path(), &clock, Phase::Armed);

        let resolution =
            reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Restored(After::RetryAfterMs(30 * 60_000))
        );
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        assert_eq!(record.cause.unwrap().reason, "handoff missing after swap");
        for trial in reload(&host, trial_dir.path()) {
            assert_eq!(trial.phase, Phase::Restored);
        }
        let state = probe_state(&host).unwrap();
        assert_eq!(state.phase, probe::ProbePhase::InterruptedWait);
        assert_eq!(state.cause, Some(probe::ProbeCause::ApplyInterrupted));
    }

    /// Review fix for #1934: with no trial record yet, the pass arms one per
    /// participant and restores. Before the fix `Host::restore` refused with
    /// "participant trial missing" before any mark, so every pass repeated
    /// with no RecoveryFailed and the node stayed down on the unarmed pair.
    #[test]
    fn missing_trial_records_are_armed_and_the_pair_restored() {
        let (_dir, root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();

        let resolution =
            reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Restored(After::RetryAfterMs(30 * 60_000))
        );
        assert_previous_pair(&host);
        assert_eq!(journal_record(&root).phase, journal::Phase::Restored);
        let trials = reload(&host, trial_dir.path());
        assert_eq!(trials.len(), 2);
        for trial in trials {
            assert_eq!(trial.phase, Phase::Restored);
            assert_eq!(trial.attempts, 0);
            assert_eq!(trial.verdict.unwrap().reason, "handoff missing after swap");
        }
        // A second pass finds the restored host and moves nothing.
        let again = reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
        assert_eq!(
            again,
            Resolution::Restored(After::RetryAfterMs(30 * 60_000))
        );
    }

    /// One trial present and one missing: the missing one is armed too.
    #[test]
    fn a_partly_armed_host_restores_with_custody_of_every_participant() {
        let (_dir, _root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Armed);
        std::fs::remove_file(&trials.pop().unwrap().0).unwrap();

        let resolution =
            reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
        assert!(matches!(resolution, Resolution::Restored(_)));
        assert_previous_pair(&host);
        for trial in reload(&host, trial_dir.path()) {
            assert_eq!(trial.phase, Phase::Restored);
        }
    }

    /// A restore that fails after the pass decided to restore marks the host
    /// RecoveryFailed, so a later pass does not repeat it.
    #[test]
    fn a_refused_restore_marks_the_host_recovery_failed() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        // Unrelated bytes in the daemon target: restore must refuse.
        std::fs::write(&host.plan().daemon.target_path, b"unrelated").unwrap();
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();

        let error =
            reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap_err();
        assert!(error.to_string().contains("unrelated"), "{error}");
        assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
        for trial in reload(&host, trial_dir.path()) {
            assert_eq!(trial.phase, Phase::RecoveryFailed);
        }
        let again = reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
        assert_eq!(again, Resolution::Final(journal::Phase::RecoveryFailed));
    }

    /// With the handoff present, an unstarted transaction proceeds.
    #[test]
    fn a_present_handoff_proceeds_without_restore() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        make_trials(&host, trial_dir.path(), &clock, Phase::Armed);
        let resolution =
            reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop).unwrap();
        assert_eq!(resolution, Resolution::Proceed);
        assert_candidate_pair(&host);
        assert_eq!(probe_state(&host).unwrap().phase, probe::ProbePhase::Passed);
    }

    /// Case 2: A is still booting, B failed before host commit. Both trials
    /// roll back, the pair is restored once, and the Failed cause holds the
    /// release (D190) until a local clear.
    #[test]
    fn one_healthy_and_one_failed_participant_restore_together_and_hold() {
        let (_dir, root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);
        // A: booting with no child yet. The live provisional case runs on
        // Linux (`a_live_healthy_candidate_is_stopped_and_reaped_before_restore`).
        {
            let (path, a) = &mut trials[0];
            a.attempts = 1;
            a.phase = Phase::Booting;
            a.save(path).unwrap();
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

        let resolution =
            reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop).unwrap();
        let held = cause(journal::CauseClass::Failed, "launch attempts exhausted");
        assert_eq!(resolution, Resolution::Restored(After::Hold(held)));
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        assert_eq!(record.cause.unwrap().class, journal::CauseClass::Failed);
        for trial in reload(&host, trial_dir.path()) {
            assert_eq!(trial.phase, Phase::Restored, "{}", trial.instance);
            assert!(trial.child.is_none());
        }
        let state = probe_state(&host).unwrap();
        assert_eq!(state.phase, probe::ProbePhase::FailedHold);
        assert_eq!(state.cause, Some(probe::ProbeCause::ApplyFailed));
        // The hold is the D190 failed-release hold: admission refuses the
        // release and a local clear lifts it.
        assert!(matches!(
            probe::inspect_admission(&host.plan().daemon.target_path, "9.9.9"),
            Err(probe::ProbeRefusal::Held { .. })
        ));
        assert!(matches!(
            probe::clear_failed_hold(&host.plan().daemon.target_path, "9.9.9"),
            Ok(probe::HoldClear::Cleared(_))
        ));
        // After the clear, a later pass finds the hold resolved.
        let again = reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop).unwrap();
        assert_eq!(again, Resolution::Restored(After::Resolved));
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
        let resolution = reconcile(&host, path_in(trial_dir.path()), true, &clock, |target| {
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
    /// moves and the host and every trial are RecoveryFailed.
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
        let error =
            reconcile(&host, path_in(trial_dir.path()), true, &clock, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("survived"), "{error}");
        assert_candidate_pair(&host);
        assert_eq!(
            reload(&host, trial_dir.path())[0].phase,
            Phase::RecoveryFailed
        );
        assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
        live.kill().unwrap();
        live.wait().unwrap();
    }

    /// Case 3: a coordinator that died during a restore left the host
    /// RollingBack. The successor resumes the restore and keeps the cause.
    /// The probe record's attempt 2 means one retry was already staged, so
    /// the wait is 60 minutes (D189 count persisted across transactions).
    #[test]
    fn a_successor_coordinator_resumes_an_interrupted_restore() {
        let (_dir, root, _host, mut record) = fixture(journal::Phase::RollingBack);
        record.cause = Some(cause(journal::CauseClass::Interrupted, "first coordinator"));
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = recovery::Host::new(root.clone(), record).unwrap();
        write_probe(&host, 2, probe::ProbePhase::Passed);
        // The first coordinator restored the daemon only.
        let daemon = host.plan().daemon.clone();
        filesystem::restore_one(&daemon).unwrap();
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);

        let resolution =
            reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop).unwrap();
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
    /// Attempt 4 means three retries were used: the release is held.
    #[test]
    fn a_partial_restore_marks_every_trial_restored_without_moving_bytes() {
        let (_dir, root, _host, mut record) = fixture(journal::Phase::Restored);
        record.cause = Some(cause(journal::CauseClass::Interrupted, "earlier pass"));
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = recovery::Host::new(root.clone(), record).unwrap();
        write_probe(&host, 4, probe::ProbePhase::Passed);
        for a in [&host.plan().daemon, &host.plan().cli] {
            filesystem::restore_one(a).unwrap();
        }
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);

        let resolution =
            reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop).unwrap();
        let exhausted = cause(journal::CauseClass::Failed, "retries_exhausted");
        assert_eq!(resolution, Resolution::Restored(After::Hold(exhausted)));
        assert_previous_pair(&host);
        for trial in reload(&host, trial_dir.path()) {
            assert_eq!(trial.phase, Phase::Restored);
            assert_eq!(trial.verdict.unwrap().reason, "earlier pass");
        }
        let state = probe_state(&host).unwrap();
        assert_eq!(state.phase, probe::ProbePhase::FailedHold);
        assert_eq!(state.cause, Some(probe::ProbeCause::RetriesExhausted));
    }

    /// Case 5: the journal cannot be written. No byte moves, no restored
    /// start is possible, and every trial is RecoveryFailed.
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
        trials[0].1.save(&trials[0].0).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert_candidate_pair(&host);
        assert_ne!(journal_record(&root).phase, journal::Phase::Restored);
        for trial in reload(&host, trial_dir.path()) {
            assert_eq!(trial.phase, Phase::RecoveryFailed);
        }
    }

    /// Case 5b: the pair is restored but the outcome cannot be recorded (no
    /// probe record names the candidate). No restored start is allowed: the
    /// host and every trial are RecoveryFailed, and no trial is Restored.
    #[test]
    fn an_unrecordable_outcome_blocks_every_restored_start() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        std::fs::remove_file(probe::state_path(&host.plan().daemon.target_path).unwrap()).unwrap();
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        make_trials(&host, trial_dir.path(), &clock, Phase::Armed);

        let error =
            reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap_err();
        assert!(error.to_string().contains("no probe record"), "{error}");
        assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
        for trial in reload(&host, trial_dir.path()) {
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
        make_trials(&host, trial_dir.path(), &earlier, Phase::Booting);
        let clock = now();

        let resolution =
            reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Restored(After::RetryAfterMs(30 * 60_000))
        );
        assert_previous_pair(&host);
        let kept = journal_record(&root).cause.unwrap();
        assert_eq!(kept.class, journal::CauseClass::Interrupted);
        for trial in reload(&host, trial_dir.path()) {
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
        let resolution =
            reconcile(&host, path_in(trial_dir.path()), true, &clock, no_stop).unwrap();
        assert_eq!(resolution, Resolution::Proceed);
        assert_candidate_pair(&host);
        live.kill().unwrap();
        live.wait().unwrap();
    }

    /// Nothing is swapped yet in `Prepared`: a missing handoff restores
    /// nothing, arms no trial and charges no retry.
    #[test]
    fn a_prepared_host_without_handoff_proceeds() {
        let (_dir, root, host, _record) = fixture(journal::Phase::Prepared);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let resolution =
            reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
        assert_eq!(resolution, Resolution::Proceed);
        assert_eq!(journal_record(&root).phase, journal::Phase::Prepared);
        assert_eq!(std::fs::read_dir(trial_dir.path()).unwrap().count(), 0);
        assert_eq!(probe_state(&host).unwrap().phase, probe::ProbePhase::Passed);
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
        let resolution =
            reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Final(journal::Phase::RecoveryFailed)
        );
        assert_candidate_pair(&host);

        let (_dir, _root, host, _record) = fixture(journal::Phase::RecoveryFailed);
        let other_dir = tempfile::tempdir().unwrap();
        make_trials(&host, other_dir.path(), &clock, Phase::Armed);
        let resolution =
            reconcile(&host, path_in(other_dir.path()), false, &clock, no_stop).unwrap();
        assert_eq!(
            resolution,
            Resolution::Final(journal::Phase::RecoveryFailed)
        );
    }

    /// D189 across transactions: the probe record's attempt carries the
    /// count. Attempts 1..=3 wait 30, 60 and 120 minutes; attempt 4 holds
    /// with `retries_exhausted`.
    #[test]
    fn d189_retries_three_times_then_holds() {
        let expected = [
            After::RetryAfterMs(30 * 60_000),
            After::RetryAfterMs(60 * 60_000),
            After::RetryAfterMs(120 * 60_000),
            After::Hold(cause(journal::CauseClass::Failed, "retries_exhausted")),
        ];
        for (attempt, after) in (1..=4).zip(expected) {
            let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
            write_probe(&host, attempt, probe::ProbePhase::Passed);
            let trial_dir = tempfile::tempdir().unwrap();
            let clock = now();
            let resolution =
                reconcile(&host, path_in(trial_dir.path()), false, &clock, no_stop).unwrap();
            assert_eq!(resolution, Resolution::Restored(after), "attempt {attempt}");
        }
    }

    /// The production pass reads each participant's handoff from its data
    /// root and keeps trials at `trial_path`. With no handoff and no trial
    /// it arms one there and restores.
    #[test]
    fn recover_uses_the_data_root_handoff_and_the_fixed_trial_path() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let resolution = recover(&host).unwrap();
        assert_eq!(
            resolution,
            Resolution::Restored(After::RetryAfterMs(30 * 60_000))
        );
        assert_previous_pair(&host);
        let trial = Trial::load(
            &root.join(TRIAL_FILE_NAME),
            &host.binding().unwrap(),
            "alice",
        )
        .unwrap();
        assert_eq!(trial.phase, Phase::Restored);
    }

    fn legacy_handoff() -> serde_json::Value {
        serde_json::json!({
            "from_version": "0.0.1", "to_version": "9.9.9",
            "target_path": "/owned/bin/x0xd", "backup_path": "/owned/bin/x0xd.backup",
            "argv": ["x0xd"], "cwd": "/owned", "env": {}, "old_pid": 24,
            "api_addr": "127.0.0.1:12700", "started_at": 1_792_500_000u64,
            "mode": "TransactionalHandoff", "launchd_verified": null,
            "systemd_verified": null
        })
    }

    fn m2_handoff(transaction: &str, generation: u64, instance: &str) -> serde_json::Value {
        let mut value = legacy_handoff();
        let object = value.as_object_mut().unwrap();
        object.insert("schema_version".into(), 1.into());
        object.insert("record_kind".into(), "handoff".into());
        object.insert("transaction_id".into(), transaction.into());
        object.insert("generation".into(), generation.into());
        object.insert("instance_id".into(), instance.into());
        value
    }

    /// Review of #1940: only an M2 handoff of this transaction, generation
    /// and instance counts as present. Every other record refuses the pass,
    /// moves no byte and leaves the journal as it was; it never makes an
    /// unarmed swapped host proceed.
    #[test]
    fn recover_refuses_every_handoff_that_does_not_bind_the_transaction() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("unreadable", b"{broken".to_vec()),
            ("legacy", serde_json::to_vec(&legacy_handoff()).unwrap()),
            (
                "other transaction",
                serde_json::to_vec(&m2_handoff("other-transaction", 1, "alice")).unwrap(),
            ),
            (
                "other generation",
                serde_json::to_vec(&m2_handoff("refusal-fixture", 2, "alice")).unwrap(),
            ),
            (
                "other instance",
                serde_json::to_vec(&m2_handoff("refusal-fixture", 1, "bob")).unwrap(),
            ),
        ];
        for (name, bytes) in cases {
            let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
            std::fs::write(root.join(journal::HANDOFF_FILE_NAME), bytes).unwrap();
            // Each fixture is the record kind it names, not a parse error.
            let read = journal::read_boot_records(&root).handoff;
            match name {
                "unreadable" => assert!(matches!(read, journal::RecordRead::Refused(_))),
                "legacy" => assert!(matches!(read, journal::RecordRead::LegacyHandoff(_))),
                _ => assert!(matches!(read, journal::RecordRead::Handoff(_)), "{name}"),
            }
            let error = recover(&host).unwrap_err();
            assert!(error.to_string().contains("handoff"), "{name}: {error}");
            assert_candidate_pair(&host);
            assert_eq!(
                journal_record(&root).phase,
                journal::Phase::SwappedCli,
                "{name}"
            );
        }
    }

    /// The binding handoff counts as present: the armed transaction
    /// proceeds.
    #[test]
    fn recover_counts_the_binding_handoff_as_present() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        std::fs::write(
            root.join(journal::HANDOFF_FILE_NAME),
            serde_json::to_vec(&m2_handoff("refusal-fixture", 1, "alice")).unwrap(),
        )
        .unwrap();
        match journal::read_boot_records(&root).handoff {
            journal::RecordRead::Handoff(_) => {}
            journal::RecordRead::Refused(reason) => panic!("fixture refused: {reason}"),
            _ => panic!("fixture is not an M2 handoff"),
        }
        assert_eq!(recover(&host).unwrap(), Resolution::Proceed);
        assert_candidate_pair(&host);
    }

    /// The caller must reap its own child first: a live child of this
    /// process refuses the pass before any action.
    #[cfg(target_os = "linux")]
    #[test]
    fn recover_refuses_a_live_child_of_this_process() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let clock = now();
        let path = root.join(TRIAL_FILE_NAME);
        let mut trial = Trial::new(host.binding().unwrap(), "alice".into(), &clock).unwrap();
        trial.save(&path).unwrap();
        trial.phase = Phase::Authorized;
        trial.save(&path).unwrap();
        trial.reserve(&path, &clock).unwrap();
        trial.child = Some(child::identity(live.id()).unwrap());
        trial.save(&path).unwrap();
        let error = recover(&host).unwrap_err();
        assert!(error.to_string().contains("own child"), "{error}");
        assert_candidate_pair(&host);
        live.kill().unwrap();
        live.wait().unwrap();
    }

    /// A live candidate of another launcher is stopped through
    /// `child::stop_foreign`; that launcher's reaper collects it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_candidate_of_another_launcher_is_stopped_before_restore() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Booting);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = child::identity(live.id()).unwrap();
        let reaper = std::thread::spawn(move || live.wait().unwrap());
        {
            let (path, a) = &mut trials[0];
            a.child = Some(identity.clone());
            a.verdict = Some(cause(journal::CauseClass::Failed, "peer failed"));
            a.save(path).unwrap();
        }
        let resolution = reconcile(
            &host,
            path_in(trial_dir.path()),
            true,
            &clock,
            child::stop_foreign,
        )
        .unwrap();
        assert!(matches!(resolution, Resolution::Restored(After::Hold(_))));
        assert!(child::absent(&identity).unwrap());
        assert!(!reaper.join().unwrap().success());
        assert_previous_pair(&host);
    }

    /// A peer launcher's protected start, as `run::run_trial` does it:
    /// under the host lock, refuse unless the host phase allows a spawn,
    /// else reserve the attempt and record the child in the trial on disk.
    fn peer_spawn(host: &recovery::Host, path: &Path, instance: &str, child: &Identity) -> bool {
        host.locked(|record| {
            if !run::protected_start_allowed(record.phase) {
                return Ok(false);
            }
            let mut trial = Trial::load(path, &host.binding()?, instance)?;
            trial.reserve(path, &now())?;
            trial.child = Some(child.clone());
            trial.save(path)?;
            Ok(true)
        })
        .unwrap()
    }

    /// Review of #1940: Alice's launcher spawns a candidate after the pass
    /// loaded her trial. The pass must not restore the pair past that
    /// child. On Linux it stops the child and restores. Elsewhere process
    /// custody is unsupported, so the pass fails closed on that child and
    /// moves no byte. Before the fix the pass never saw the child: on Linux
    /// its stale save failed, and in the later window it restored past it.
    #[test]
    fn a_peer_spawn_after_the_first_load_is_never_restored_past() {
        let (_dir, root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);
        {
            let (path, b) = &mut trials[1];
            b.verdict = Some(cause(journal::CauseClass::Failed, "peer failed"));
            b.phase = Phase::RollingBack;
            b.save(path).unwrap();
        }
        let alice = trials[0].0.clone();
        #[cfg(target_os = "linux")]
        let (identity, reaper) = {
            let mut live = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let identity = child::identity(live.id()).unwrap();
            (identity, std::thread::spawn(move || live.wait().unwrap()))
        };
        #[cfg(not(target_os = "linux"))]
        let identity = Identity {
            pid: std::process::id(),
            start: 0,
            boot: clock.boot.clone(),
        };
        let spawned = std::cell::Cell::new(false);
        let paths = path_in(trial_dir.path());
        // Alice's launcher spawns while the pass loads Bob's trial.
        let trial_path = |p: &journal::Participant| {
            if p.instance_id == "bob" && !spawned.replace(true) {
                assert!(peer_spawn(&host, &alice, "alice", &identity));
            }
            paths(p)
        };
        #[cfg(target_os = "linux")]
        {
            let resolution =
                reconcile(&host, trial_path, true, &clock, child::stop_foreign).unwrap();
            assert!(matches!(resolution, Resolution::Restored(After::Hold(_))));
            assert!(child::absent(&identity).unwrap());
            assert!(!reaper.join().unwrap().success());
            assert_previous_pair(&host);
            assert_eq!(journal_record(&root).phase, journal::Phase::Restored);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let error = reconcile(&host, trial_path, true, &clock, no_stop).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
            assert_candidate_pair(&host);
            assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
        }
    }

    /// Review of #1940: the host is fenced before any stop. Bob's launcher
    /// tries a protected start while the pass stops Alice's candidate; the
    /// fence refuses it, so no new candidate runs when the pair is restored.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_peer_spawn_during_the_stop_is_refused_by_the_fence() {
        let (_dir, _root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = child::identity(live.id()).unwrap();
        let reaper = std::thread::spawn(move || live.wait().unwrap());
        {
            let (path, a) = &mut trials[0];
            a.reserve(path, &clock).unwrap();
            a.child = Some(identity.clone());
            a.verdict = Some(cause(journal::CauseClass::Failed, "peer failed"));
            a.save(path).unwrap();
        }
        let bob = trials[1].0.clone();
        let mut spawns = Vec::new();
        let resolution = reconcile(&host, path_in(trial_dir.path()), true, &clock, |target| {
            spawns.push(peer_spawn(&host, &bob, "bob", target));
            child::stop_foreign(target)
        })
        .unwrap();
        assert_eq!(spawns, vec![false], "the fence must refuse the spawn");
        assert!(matches!(resolution, Resolution::Restored(After::Hold(_))));
        assert!(!reaper.join().unwrap().success());
        assert_previous_pair(&host);
    }

    /// Review of #1940: a peer restores or commits the host after the
    /// pass's first read. The fence leaves that host alone: no stop of the
    /// restored child, and no trial on a committed host is marked failed.
    #[test]
    fn a_peer_restore_or_commit_after_the_first_read_is_not_fenced() {
        for found in [journal::Phase::Restored, journal::Phase::HostCommitted] {
            let (_dir, root, host, _record) =
                fixture_with(journal::Phase::SwappedCli, two_participants);
            let trial_dir = tempfile::tempdir().unwrap();
            let clock = now();
            let mut trials = make_trials(&host, trial_dir.path(), &clock, Phase::Authorized);
            let (path, b) = &mut trials[1];
            b.verdict = Some(cause(journal::CauseClass::Failed, "peer failed"));
            b.phase = Phase::RollingBack;
            b.save(path).unwrap();
            let alice = trials[0].0.clone();
            let (paths, done) = (path_in(trial_dir.path()), std::cell::Cell::new(false));
            // The peer finishes while the pass loads Bob's trial; Alice's
            // restored child then runs.
            let trial_path = |p: &journal::Participant| {
                if p.instance_id == "bob" && !done.replace(true) {
                    let mut record = journal_record(&root);
                    record.phase = found;
                    record.cause = Some(cause(journal::CauseClass::Failed, "peer failed"));
                    journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
                    if found == journal::Phase::Restored {
                        for a in [&host.plan().daemon, &host.plan().cli] {
                            filesystem::restore_one(a).unwrap();
                        }
                        let mut a = Trial::load(&alice, &host.binding().unwrap(), "alice").unwrap();
                        a.phase = Phase::Restored;
                        a.verdict = Some(cause(journal::CauseClass::Failed, "peer failed"));
                        a.child = Some(Identity {
                            pid: std::process::id(),
                            start: 0,
                            boot: clock.boot.clone(),
                        });
                        a.save(&alice).unwrap();
                    }
                }
                paths(p)
            };
            let resolution = reconcile(&host, trial_path, true, &clock, no_stop).unwrap();
            assert_eq!(journal_record(&root).phase, found);
            if found == journal::Phase::Restored {
                assert!(matches!(resolution, Resolution::Restored(After::Hold(_))));
                assert_previous_pair(&host);
            } else {
                assert_eq!(resolution, Resolution::Final(found));
            }
            for trial in reload(&host, trial_dir.path()) {
                assert_ne!(trial.phase, Phase::RecoveryFailed, "{}", trial.instance);
            }
        }
    }

    /// Two participants, Alice with a live candidate and a Failed verdict.
    /// Returns the trials, the candidate's identity and its reaper.
    #[cfg(target_os = "linux")]
    #[allow(clippy::type_complexity)]
    fn alice_runs_a_failed_candidate(
        host: &recovery::Host,
        dir: &Path,
        clock: &Clock,
    ) -> (
        Vec<(PathBuf, Trial)>,
        Identity,
        std::thread::JoinHandle<std::process::ExitStatus>,
    ) {
        let mut trials = make_trials(host, dir, clock, Phase::Authorized);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = child::identity(live.id()).unwrap();
        let reaper = std::thread::spawn(move || live.wait().unwrap());
        let (path, a) = &mut trials[0];
        a.reserve(path, clock).unwrap();
        a.child = Some(identity.clone());
        a.verdict = Some(cause(journal::CauseClass::Failed, "peer failed"));
        a.save(path).unwrap();
        (trials, identity, reaper)
    }

    /// Review of #1950: the host lock is free while the pass stops Alice's
    /// candidate. A peer pass finishes the restore in that time and Bob's
    /// launcher starts his restored child, as `run::start_restored` does.
    /// This pass must then act on the phase it reads under the lock, not
    /// the phase it found at the fence: it stops no restored child, moves
    /// no byte and demotes nothing. Before the fix it wrote its stale
    /// RollingBack trials over the restored ones and, when Bob's save
    /// refused, marked the restored host and trials RecoveryFailed.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_peer_restore_during_the_stop_keeps_the_restored_host_and_child() {
        let (_dir, root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let (trials, identity, reaper) =
            alice_runs_a_failed_candidate(&host, trial_dir.path(), &clock);
        let bob = trials[1].0.clone();
        let mut stopped = Vec::new();
        let mut restored_child = None;
        let resolution = reconcile(&host, path_in(trial_dir.path()), true, &clock, |target| {
            stopped.push(target.clone());
            let peer = reconcile(
                &host,
                path_in(trial_dir.path()),
                true,
                &clock,
                child::stop_foreign,
            )?;
            assert!(matches!(peer, Resolution::Restored(After::Hold(_))));
            let mut b = Trial::load(&bob, &host.binding()?, "bob")?;
            assert_eq!(b.phase, Phase::Restored);
            b.restored_starts += 1;
            b.save(&bob)?;
            let child = host.locked(|record| {
                assert_eq!(record.phase, journal::Phase::Restored);
                std::process::Command::new("sleep").arg("30").spawn()
            })?;
            b.child = Some(child::identity(child.id())?);
            b.save(&bob)?;
            restored_child = Some(child);
            Ok(())
        });
        let mut restored_child = restored_child.expect("the peer ran");
        let restored = child::identity(restored_child.id()).unwrap();
        let alive = !child::absent(&restored).unwrap();
        restored_child.kill().unwrap();
        restored_child.wait().unwrap();
        assert!(!reaper.join().unwrap().success());

        assert!(
            matches!(resolution, Ok(Resolution::Restored(After::Hold(_)))),
            "{resolution:?}"
        );
        assert_eq!(stopped, vec![identity], "only the candidate is stopped");
        assert!(alive, "the restored child must keep running");
        assert_previous_pair(&host);
        assert_eq!(journal_record(&root).phase, journal::Phase::Restored);
        let trials = reload(&host, trial_dir.path());
        for trial in &trials {
            assert_eq!(trial.phase, Phase::Restored, "{}", trial.instance);
        }
        assert_eq!(trials[1].child, Some(restored));
        assert_eq!(trials[1].restored_starts, 1);
    }

    /// Review of #1950: a peer marks the host RecoveryFailed while this
    /// pass stops the candidate. The pass reads that under the lock and is
    /// final: it moves no byte and rolls no trial back. Before the fix it
    /// wrote RollingBack to the trial and then failed in the restore.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_peer_recovery_failure_during_the_stop_is_final() {
        let (_dir, root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let (_trials, identity, reaper) =
            alice_runs_a_failed_candidate(&host, trial_dir.path(), &clock);
        let resolution = reconcile(&host, path_in(trial_dir.path()), true, &clock, |target| {
            host.mark_recovery_failed()?;
            child::stop_foreign(target)
        });
        assert!(!reaper.join().unwrap().success());
        assert!(child::absent(&identity).unwrap());
        assert_eq!(
            resolution.unwrap(),
            Resolution::Final(journal::Phase::RecoveryFailed)
        );
        assert_candidate_pair(&host);
        assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
        let phases: Vec<Phase> = reload(&host, trial_dir.path())
            .into_iter()
            .map(|trial| trial.phase)
            .collect();
        assert_eq!(phases, vec![Phase::Booting, Phase::Authorized]);
    }

    /// Review of #1950: a peer pass fails while this pass stops the
    /// candidate, but cannot write the host journal, so the host stays
    /// RollingBack; it marks every trial RecoveryFailed. This pass reloads
    /// the trials under the lock and is final: it overwrites no trial,
    /// moves no byte and writes no Restored. Before the fix it rolled the
    /// trials back over the peer's marks and restored the pair.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_peer_recovery_failure_with_an_unwritable_journal_is_final() {
        let (_dir, root, host, _record) =
            fixture_with(journal::Phase::SwappedCli, two_participants);
        let trial_dir = tempfile::tempdir().unwrap();
        let clock = now();
        let (trials, identity, reaper) =
            alice_runs_a_failed_candidate(&host, trial_dir.path(), &clock);
        let paths: Vec<(PathBuf, String)> = trials
            .iter()
            .map(|(path, trial)| (path.clone(), trial.instance.clone()))
            .collect();
        let resolution = reconcile(&host, path_in(trial_dir.path()), true, &clock, |target| {
            // The peer's `fail` with the host mark refused: trials only.
            host.locked(|_| {
                for (path, instance) in &paths {
                    let mut trial = Trial::load(path, &host.binding()?, instance)?;
                    trial.phase = Phase::RecoveryFailed;
                    trial.save(path)?;
                }
                Ok(())
            })?;
            child::stop_foreign(target)
        });
        assert!(!reaper.join().unwrap().success());
        assert!(child::absent(&identity).unwrap());
        assert_eq!(
            resolution.unwrap(),
            Resolution::Final(journal::Phase::RecoveryFailed)
        );
        assert_candidate_pair(&host);
        assert_eq!(journal_record(&root).phase, journal::Phase::RollingBack);
        for trial in reload(&host, trial_dir.path()) {
            assert_eq!(trial.phase, Phase::RecoveryFailed, "{}", trial.instance);
        }
    }
}
