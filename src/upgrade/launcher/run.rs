use super::*;

pub(super) enum Outcome {
    /// An intentional stop: nothing runs. A Committed trial stays
    /// Committed; any other stopped trial rolls back at the next start.
    Stopped,
    Restored(child::Owned),
    // Ownership remains with this launcher. The S3c host coordinator must
    // still verify all participants before it can commit the host.
    Provisional(child::Owned),
    /// The host is committed and this trial is retired. No child of this
    /// launcher runs: the caller starts the installed (committed) daemon as
    /// an ordinary start.
    Committed,
}

/// `health` must be the candidate's version/root/ownership-bound M1 evidence,
/// never a bare HTTP status. `stop` is an intentional service-manager stop.
pub(super) fn run_trial(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    mut now: impl FnMut() -> io::Result<Clock>,
    mut health: impl FnMut(&Identity) -> io::Result<bool>,
    mut stop: impl FnMut() -> bool,
) -> io::Result<Outcome> {
    let p = host
        .plan()
        .participants
        .iter()
        .find(|p| p.instance_id == trial.instance)
        .ok_or_else(|| invalid("participant missing"))?;
    if !p.was_running {
        return Err(invalid("stopped participant must remain stopped"));
    }
    if trial.phase == Phase::RecoveryFailed {
        return Err(invalid("automatic start is forbidden"));
    }
    if trial.phase == Phase::Committed {
        prior_child_absent(trial)?;
        // As for Restored: a stop starts no daemon (#1981 review).
        if stop() {
            return Ok(Outcome::Stopped);
        }
        // A crash between saving Committed and writing Idle leaves the journal
        // HostCommitted (#2012): retry retire so the journal settles once every
        // participant is Committed (no-op if already Idle).
        match retire(host, path, trial)? {
            Retire::Retired => return Ok(Outcome::Committed),
            Retire::Uncommitted => return Err(uncommitted()),
            Retire::NotCommitted => return Err(invalid("committed trial on uncommitted host")),
        }
    }
    if trial.phase == Phase::Restored {
        // An intentional stop starts no restored child; the trial stays
        // Restored, so the next start starts it (#1968 review).
        if stop() {
            return Ok(Outcome::Stopped);
        }
        // ADR 0094 S4: a restarted launcher starts only a missing restored
        // child. The previous bytes are already installed, so no rollback
        // is repeated.
        if let Some(identity) = &trial.child {
            if !child::absent(identity)? {
                return Err(invalid("prior child still exists"));
            }
        }
        return start_restored(host, path, trial).map(Outcome::Restored);
    }
    // After parent death, the manager must remove the old cgroup. Never
    // overlap a surviving process or reset its attempt/deadline on restart.
    if let Some(identity) = &trial.child {
        if !child::absent(identity)? {
            return Err(invalid("prior child still exists"));
        }
        // The launcher died after the host commit and before it retired
        // the trial: the committed host keeps the candidate. Without this a
        // lost child would roll back, the restore would refuse the
        // committed host, and the trial would end RecoveryFailed.
        match retire(host, path, trial)? {
            Retire::Retired if stop() => return Ok(Outcome::Stopped),
            Retire::Retired => return Ok(Outcome::Committed),
            Retire::Uncommitted => return Err(uncommitted()),
            Retire::NotCommitted => {}
        }
        return rollback(
            host,
            path,
            trial,
            interrupted("launcher lost child custody"),
        );
    }
    match trial.phase {
        Phase::Authorized => {}
        Phase::Booting => {
            return rollback(host, path, trial, interrupted("launcher died during exec"));
        }
        // `restore` is idempotent: resume it. The first verdict is kept.
        Phase::RollingBack => {
            return rollback(
                host,
                path,
                trial,
                interrupted("launcher died during rollback"),
            );
        }
        // An intentional stop ended the trial without a health commit. The
        // candidate is not committed, so restore the previous pair.
        Phase::Stopped => {
            return rollback(
                host,
                path,
                trial,
                interrupted("service stopped during trial"),
            );
        }
        _ => return Err(invalid("no durable start authority")),
    }
    loop {
        // Exhausted attempts or a run-out total budget are Failed. A stop in
        // the same pass records that verdict before it saves Stopped, so the
        // next start rolls back as Failed (rollback keeps a stored verdict)
        // and the failed release is held. The restore still waits for the
        // next start, as for any stop. A changed boot or a regressed clock
        // stays Interrupted: the launcher cannot tell whether the deadline
        // passed before the reboot.
        let clock = now()?;
        let expired = trial.expired(&clock);
        let failed = failed_verdict(trial, &clock);
        if stop() {
            if let Some(cause) = failed {
                trial.verdict.get_or_insert(cause);
            }
            trial.phase = Phase::Stopped;
            trial.save(path)?;
            return Ok(Outcome::Stopped);
        }
        if let Some(cause) = failed.or(expired) {
            return rollback(host, path, trial, cause);
        }
        if clock.ms < trial.next_launch_ms {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        let spawned = host.locked(|record| {
            // Each attempt re-checks the host phase, not only the first.
            if !protected_start_allowed(record.phase) {
                return Err(invalid("host is not ready for protected start"));
            }
            host.verify_candidate()?;
            // The lock wait and the candidate hash can outlast the budget
            // after the loop-head check passed. Read the clock again here,
            // immediately before the reservation. An expired budget is a
            // typed result, not an error, so it rolls back with its cause.
            let clock = now()?;
            if let Some(cause) = trial.expired(&clock) {
                return Ok(Err(cause));
            }
            trial.reserve(path, &clock)?;
            child::Owned::spawn(
                trial,
                path,
                p,
                &host.plan().candidate_version,
                host.plan().daemon.candidate_sha256,
            )
            .map(Ok)
        });
        let mut child = match spawned? {
            // Nothing was reserved or spawned for this attempt.
            Err(cause) => return rollback(host, path, trial, cause),
            Ok(Some(child)) => child,
            // Exec or boot setup failed. The attempt stays charged, unless a
            // stop arrived: a stop can end the child during boot setup, and
            // that exit is not a failed attempt.
            Ok(None) => {
                trial.child = None;
                if stop() {
                    record_budget_verdict(trial, now().ok().as_ref());
                    trial.phase = Phase::Stopped;
                    trial.save(path)?;
                    return Ok(Outcome::Stopped);
                }
                // The spawn recorded the exec failure in memory only.
                let cause = trial.cause.clone();
                let next = match now() {
                    Ok(clock) => clock.ms.saturating_add(GAP_MS),
                    Err(error) => return clock_lost(host, path, trial, cause, error),
                };
                if !requeue(host, path, trial, cause.clone(), next)? {
                    return resume_peer_recovery(host, path, trial, cause, &mut now, &mut stop);
                }
                continue;
            }
        };
        let failure = loop {
            if stop() {
                // A clock error must not leave the child unreaped.
                record_budget_verdict(trial, now().ok().as_ref());
                if let Err(error) = child.reap() {
                    return Err(trial.recovery_failed(path, error));
                }
                trial.child = None;
                trial.phase = Phase::Stopped;
                trial.save(path)?;
                return Ok(Outcome::Stopped);
            }
            let observation = (|| {
                if child.exited()?.is_some() {
                    return Err(invalid("candidate exited before commit"));
                }
                let ready = child.poll_boot()?
                    && health(
                        trial
                            .child
                            .as_ref()
                            .ok_or_else(|| invalid("missing child identity"))?,
                    )?;
                trial.observe_health(path, &now()?, ready)
            })();
            match observation {
                Ok(true) => return Ok(Outcome::Provisional(child)),
                // A stop can end the child before the next poll sees it.
                // Take the stop path then, or the stop-caused exit would be
                // charged as a failed attempt.
                Err(_) if stop() => continue,
                Err(error) => break error,
                Ok(false) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };
        if let Err(error) = child.reap() {
            return Err(trial.recovery_failed(path, error));
        }
        trial.child = None;
        let cause = Some(failure.to_string());
        let next = match now() {
            Ok(clock) => clock.ms.saturating_add(GAP_MS),
            Err(error) => return clock_lost(host, path, trial, cause, error),
        };
        if !requeue(host, path, trial, cause.clone(), next)? {
            return resume_peer_recovery(host, path, trial, cause, &mut now, &mut stop);
        }
    }
}

/// The clock failed after a failed attempt, so the next attempt cannot be
/// scheduled. A used-up attempt count needs no clock: it rolls back as
/// Failed now, so the failed release is held. Otherwise the error is
/// returned with the trial still Booting, and the next start rolls back as
/// lost custody (Interrupted), which is the verdict an earlier attempt
/// gets anyway (#2006 review).
fn clock_lost(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    cause: Option<String>,
    error: io::Error,
) -> io::Result<Outcome> {
    if cause.is_some() {
        trial.cause = cause;
    }
    match exhausted_verdict(trial) {
        Some(verdict) => rollback(host, path, trial, verdict),
        None => Err(error),
    }
}

/// What a retire found. Only an `Err` from `retire` can change on a retry.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Retire {
    /// The trial is saved `Committed`, and `*trial` is that saved trial.
    Retired,
    /// The host is not committed. Nothing was written.
    NotCommitted,
    /// The host is committed but the trial is neither Provisional nor
    /// Committed. `host_commit` refuses such a trial, so this is a broken
    /// host, not a transient state. Nothing was written.
    Uncommitted,
}

pub(super) fn uncommitted() -> io::Error {
    invalid("committed host has an uncommitted trial")
}

/// Retire a provisional trial whose host is committed: under the host lock,
/// a fresh read, saved `Committed`. When that makes every participant's
/// trial Committed, the same locked step settles the host journal to `Idle`
/// (#2012): the transaction is history, the installer may change the
/// launcher and its anchor again, and the next start is an ordinary one.
/// A host already settled to `Idle` by a peer's retire is retired too, for
/// a trial that is already Committed.
pub(super) fn retire(host: &recovery::Host, path: &Path, trial: &mut Trial) -> io::Result<Retire> {
    let (binding, instance) = (trial.binding.clone(), trial.instance.clone());
    let retired = host.locked(|record| {
        let settled = record.phase == journal::Phase::Idle;
        if record.phase != journal::Phase::HostCommitted && !settled {
            return Ok(Err(Retire::NotCommitted));
        }
        let mut current = Trial::load(path, &binding, &instance)?;
        match current.phase {
            Phase::Provisional if !settled => {
                current.phase = Phase::Committed;
                current.save(path)?;
            }
            Phase::Committed => {}
            _ if settled => return Ok(Err(Retire::NotCommitted)),
            _ => return Ok(Err(Retire::Uncommitted)),
        }
        if !settled {
            settle_idle(host, record, &binding)?;
        }
        Ok(Ok(current))
    })?;
    Ok(match retired {
        Ok(current) => {
            *trial = current;
            Retire::Retired
        }
        Err(found) => found,
    })
}

/// Under the host lock with the journal HostCommitted: remove each
/// participant's matching `upgrade-boot.json` and write `Idle` when every
/// running participant's trial record of this transaction is Committed
/// (skipping participants with `!was_running`, matching `commit::host_commit`).
/// Removing the boot record before writing `Idle` ensures a crash or failed
/// unlink leaves the journal `HostCommitted`, so the next start retries
/// `retire` instead of stranding a stale boot record across a later
/// `Superseded` transaction. A running participant's trial that is missing,
/// of another transaction or not yet Committed leaves the journal
/// HostCommitted; that participant's own retire settles it later.
fn settle_idle(
    host: &recovery::Host,
    record: &mut journal::JournalRecord,
    binding: &Binding,
) -> io::Result<()> {
    for participant in &host.plan().participants {
        if !participant.was_running {
            continue;
        }
        let path = coordinator::trial_path(participant);
        match Trial::load(&path, binding, &participant.instance_id) {
            Ok(trial) if trial.phase == Phase::Committed => {}
            _ => return Ok(()),
        }
    }
    for participant in &host.plan().participants {
        remove_matching_boot_record(
            &participant.data_root,
            &record.transaction_id,
            record.generation,
        )?;
    }
    record.phase = journal::Phase::Idle;
    host.save_settled(record)
}

/// Remove `upgrade-boot.json` in `root` when it is a regular file belonging
/// to `(tx_id, generation)`. Missing, symlinked, corrupt, or foreign-tx files
/// are left intact so fail-closed startup checks continue to detect anomalies;
/// an unlink I/O error propagates so `settle_idle` retries on the next start.
fn remove_matching_boot_record(root: &Path, tx_id: &str, generation: u64) -> io::Result<()> {
    let boot_path = root.join(journal::BOOT_FILE_NAME);
    let meta = match std::fs::symlink_metadata(&boot_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if !meta.is_file() {
        return Ok(());
    }
    let Ok(bytes) = journal::read_auxiliary_record(&boot_path) else {
        return Ok(());
    };
    if let journal::RecordRead::Boot(boot) = journal::classify_record(&bytes, "boot") {
        if boot.transaction_id == tx_id && boot.generation == generation {
            match std::fs::remove_file(&boot_path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
    }
    Ok(())
}

/// ADR 0094 S4: never overlap a surviving process of an earlier start.
fn prior_child_absent(trial: &Trial) -> io::Result<()> {
    if let Some(identity) = &trial.child {
        if !child::absent(identity)? {
            return Err(invalid("prior child still exists"));
        }
    }
    Ok(())
}

/// Mark the host and this trial RecoveryFailed after a failed coordinator
/// pass, so no later start repeats it. A committed host is never marked.
/// The trial is re-read first: the pass may have written it.
///
/// A host that a peer has already restored is never marked either (#1991
/// review): its pair is back and the other participants may start. If the
/// peer's pass also marked this trial Restored, this launcher joins it and
/// starts its restored child; otherwise only this trial is final.
fn recovery_failed_final(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    error: io::Error,
) -> io::Result<Outcome> {
    let (error, restored) = match host.mark_unrestored_recovery_failed() {
        Ok(found) => (error, found == journal::Phase::Restored),
        Err(mark) => (
            invalid(format!("{error}; host not marked recovery-failed: {mark}")),
            false,
        ),
    };
    if let Ok(current) = Trial::load(path, &trial.binding, &trial.instance) {
        *trial = current;
    }
    if restored && trial.phase == Phase::Restored {
        return start_restored(host, path, trial).map(Outcome::Restored);
    }
    if trial.phase == Phase::RecoveryFailed {
        return Err(error);
    }
    Err(trial.recovery_failed(path, error))
}

/// Save a failed, reaped attempt `Authorized` for the next one, under the
/// host lock from a fresh read (#1989 review). A peer's coordinator may have
/// fenced the host and moved this trial while the attempt ran. Then the
/// fresh trial is kept, `*trial` becomes it, and this returns false: the
/// caller resumes that recovery and never writes `Authorized` over it.
///
/// The coordinator fences the host before it stops the candidates and
/// marks their trials, so a trial can still be Booting on a host that no
/// longer allows a protected start (#1991 review). Such a trial is not
/// requeued either: the next attempt could not spawn, and the caller joins
/// the recovery instead.
fn requeue(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    cause: Option<String>,
    next_launch_ms: u64,
) -> io::Result<bool> {
    let (binding, instance) = (trial.binding.clone(), trial.instance.clone());
    let (fresh, requeued) = host.locked(|record| {
        let mut current = Trial::load(path, &binding, &instance)?;
        if current.phase != Phase::Booting || !protected_start_allowed(record.phase) {
            return Ok((current, false));
        }
        current.child = None;
        if cause.is_some() {
            current.cause = cause.clone();
        }
        current.phase = Phase::Authorized;
        current.next_launch_ms = next_launch_ms;
        current.save(path)?;
        Ok((current, true))
    })?;
    *trial = fresh;
    Ok(requeued)
}

/// A peer's coordinator moved this trial, or fenced the host, during an
/// attempt. Join what it did: a Restored trial starts its restored child
/// (unless a stop arrived), a RollingBack one resumes the pass, a
/// RecoveryFailed one is final. A trial still Booting on a fenced host
/// (the peer had not marked it yet) runs the coordinator pass itself; the
/// pass joins or finishes the peer's restore and keeps its first cause.
///
/// `cause` is the failure of the attempt that just ended. On a Booting
/// trial that attempt has failed, so a used-up attempt count or total
/// budget gives a Failed verdict, as at the loop head; only otherwise is
/// the verdict Interrupted. The coordinator lets a Failed verdict win, so
/// the failed release is held (#1991 review). A last attempt that a peer's
/// stop ended also counts as Failed: fail-safe, the release is held (A14,
/// 17 Nov 2026). The attempt count needs no clock, so a clock error cannot
/// turn a last-attempt Failed into Interrupted.
fn resume_peer_recovery(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    cause: Option<String>,
    now: &mut impl FnMut() -> io::Result<Clock>,
    stop: &mut impl FnMut() -> bool,
) -> io::Result<Outcome> {
    match trial.phase {
        Phase::Restored if stop() => Ok(Outcome::Stopped),
        Phase::Restored => start_restored(host, path, trial).map(Outcome::Restored),
        Phase::RollingBack => rollback(
            host,
            path,
            trial,
            interrupted("a peer began recovery during an attempt"),
        ),
        Phase::Booting => {
            if cause.is_some() {
                trial.cause = cause;
            }
            let failed = match now() {
                Ok(clock) => failed_verdict(trial, &clock),
                Err(_) => exhausted_verdict(trial),
            };
            let verdict =
                failed.unwrap_or_else(|| interrupted("a peer began recovery during an attempt"));
            rollback(host, path, trial, verdict)
        }
        Phase::RecoveryFailed => Err(invalid("automatic start is forbidden")),
        _ => Err(invalid("trial changed during an attempt")),
    }
}

/// Whether the host phase allows a candidate spawn. Checked under the host
/// lock; the coordinator's RollingBack fence makes it false.
pub(super) fn protected_start_allowed(phase: journal::Phase) -> bool {
    matches!(
        phase,
        journal::Phase::SwappedCli | journal::Phase::HandoffArmed
    )
}

/// The Failed verdict a trial has already reached between attempts, if
/// any: every attempt used and failed, or the total budget run out on this
/// boot. Do not call it while an attempt runs: that attempt is counted but
/// has not failed.
pub(super) fn failed_verdict(trial: &Trial, clock: &Clock) -> Option<journal::Cause> {
    exhausted_verdict(trial).or_else(|| {
        trial
            .expired(clock)
            .filter(|cause| cause.class == journal::CauseClass::Failed)
    })
}

/// The Failed verdict for a used-up attempt count. It needs no clock.
fn exhausted_verdict(trial: &Trial) -> Option<journal::Cause> {
    (trial.attempts >= MAX_ATTEMPTS).then(|| {
        let reason = format!(
            "launch attempts exhausted: {}",
            trial.cause.as_deref().unwrap_or("no health commit")
        );
        cause(journal::CauseClass::Failed, reason)
    })
}

/// On a stop during an attempt, record a Failed verdict only for a run-out
/// total budget. The attempt is counted at reservation but has not failed,
/// so the attempt count must not decide the verdict here.
pub(super) fn record_budget_verdict(trial: &mut Trial, clock: Option<&Clock>) {
    if let Some(cause) = clock
        .and_then(|clock| trial.expired(clock))
        .filter(|cause| cause.class == journal::CauseClass::Failed)
    {
        trial.verdict.get_or_insert(cause);
    }
}

fn interrupted(reason: &str) -> journal::Cause {
    cause(journal::CauseClass::Interrupted, reason)
}

/// Start the previous bytes after restoration (ADR 0094 S4 and the 31 Oct
/// Engineer ruling). Each start is reserved durably first and bounded by
/// `MAX_ATTEMPTS`. A start that fails, or restored bytes that fail
/// verification, leave the trial RecoveryFailed for the operator.
fn start_restored(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
) -> io::Result<child::Owned> {
    if trial.restored_starts >= MAX_ATTEMPTS {
        // The last restored child is gone, as on the start path below. Clear
        // it so the RecoveryFailed save passes `validate_trial` when that
        // child ran on an earlier boot.
        trial.child = None;
        return Err(trial.recovery_failed(path, invalid("restored starts exhausted")));
    }
    trial.restored_starts += 1;
    trial.child = None;
    trial.save(path)?;
    let started = host.locked(|record| {
        if record.phase != journal::Phase::Restored || record.cause.is_none() {
            return Err(invalid("restored start has no durable cause"));
        }
        for a in [&host.plan().daemon, &host.plan().cli] {
            if filesystem::hash(&a.target_path)? != a.previous_sha256 {
                return Err(invalid("restored pair changed"));
            }
        }
        let p = host
            .plan()
            .participants
            .iter()
            .find(|p| p.instance_id == trial.instance)
            .ok_or_else(|| invalid("restored participant missing"))?;
        child::Owned::restored(p)
    });
    let child = started.map_err(|error| trial.recovery_failed(path, error))?;
    trial.child = Some(child.identity().clone());
    trial.save(path)?;
    Ok(child)
}

fn rollback(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    cause: journal::Cause,
) -> io::Result<Outcome> {
    // The first verdict wins: a launcher restart that re-enters rollback
    // must not turn a Failed cause into Interrupted (ADR 0094 S4), and an
    // earlier per-attempt error never classifies the rollback.
    if host.plan().participants.len() > 1 {
        return rollback_through_coordinator(host, path, trial, cause);
    }
    let cause = trial.verdict.get_or_insert(cause).clone();
    trial.phase = Phase::RollingBack;
    trial.save(path)?;
    if let Err(error) = host.restore(&[(path.to_owned(), trial.clone())], cause) {
        return Err(trial.recovery_failed(path, error));
    }
    trial.phase = Phase::Restored;
    trial.save(path)?;
    let restored = start_restored(host, path, trial)?;
    Ok(Outcome::Restored(restored))
}

/// A single launcher cannot restore on behalf of another participant: on
/// a host with more than one, the coordinator pass gathers the full set
/// (#1378 slice 5). Under the host lock, this trial keeps its first verdict
/// (`host_commit` reads trials under the same lock and rolls back on a
/// verdict). Then `coordinator::recover` fences the host, stops every
/// peer's live process, restores the pair once and marks every trial
/// Restored, and this launcher starts its own restored child as on the
/// single-participant path. The caller has no child of its own running:
/// every path here reaped it, or found it absent.
fn rollback_through_coordinator(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    cause: journal::Cause,
) -> io::Result<Outcome> {
    let p = host
        .plan()
        .participants
        .iter()
        .find(|p| p.instance_id == trial.instance)
        .ok_or_else(|| invalid("participant missing"))?;
    // The pass reads every trial at `coordinator::trial_path`.
    if path != coordinator::trial_path(p) {
        return Err(invalid("trial is not at its coordinator path"));
    }
    let (binding, instance) = (trial.binding.clone(), trial.instance.clone());
    *trial = host.locked(|_| {
        let mut current = Trial::load(path, &binding, &instance)?;
        if current.verdict.is_none() {
            current.verdict = Some(cause.clone());
            current.save(path)?;
        }
        Ok(current)
    })?;
    // An error before the fence (a peer trial that does not load, a foreign
    // handoff record, a live own child) would repeat on every restart and
    // leave the host unfinished, so any error here is final, as on the
    // single-participant path (#1989 review). The pass marks the host and
    // every trial itself for an error after its fence.
    let resolution = match coordinator::recover(host) {
        Ok(resolution) => resolution,
        Err(error) => return recovery_failed_final(host, path, trial, error),
    };
    *trial = Trial::load(path, &binding, &instance)?;
    match resolution {
        coordinator::Resolution::Restored(_) => {
            start_restored(host, path, trial).map(Outcome::Restored)
        }
        coordinator::Resolution::Final(phase) => {
            Err(invalid(format!("host recovery is final: {phase:?}")))
        }
        coordinator::Resolution::Proceed => {
            Err(invalid("recovery found no cause after a rollback was due"))
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::testkit::{fixture, fixture_with, write_probe};
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn trial_in(host: &recovery::Host, path: &Path, phase: Phase, attempts: u32) -> Trial {
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        trial.phase = Phase::Authorized;
        trial.save(path).unwrap();
        trial.attempts = attempts;
        trial.phase = phase;
        trial.save(path).unwrap();
        trial
    }

    /// A clock that moves 10 s per read, so deadlines pass without sleeps.
    fn fast_clock(trial: &Trial) -> impl FnMut() -> io::Result<Clock> {
        let boot = trial.boot.clone();
        let mut ms = Clock::now().unwrap().ms;
        move || {
            ms += 10_000;
            Ok(Clock {
                boot: boot.clone(),
                ms,
            })
        }
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

    /// Replace the candidate daemon with an executable that runs but never
    /// acknowledges its boot barrier, and rebind the host to its hash.
    fn executable_candidate(root: &Path, record: journal::JournalRecord) -> recovery::Host {
        candidate_script(root, record, "#!/bin/sh\nexec sleep 30\n")
    }

    /// Replace the candidate daemon with `script` and rebind the host to it.
    fn candidate_script(
        root: &Path,
        mut record: journal::JournalRecord,
        script: &str,
    ) -> recovery::Host {
        let target = &record.plan.daemon.target_path;
        std::fs::write(target, script).unwrap();
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755)).unwrap();
        record.plan.daemon.candidate_sha256 = filesystem::hash(target).unwrap();
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        recovery::Host::new(root.to_owned(), record).unwrap()
    }

    /// Real exec failures against a non-executable candidate: all three
    /// attempts are charged, the previous pair is restored with a Failed
    /// cause, and the restored daemon that cannot start (the fixture's
    /// previous bytes are not executable) leaves the trial RecoveryFailed.
    #[test]
    fn exec_failures_exhaust_attempts_and_restore_previous_bytes() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 0);
        let clock = fast_clock(&trial);
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert!(outcome.is_err());
        assert_eq!(trial.attempts, MAX_ATTEMPTS);
        assert_eq!(trial.phase, Phase::RecoveryFailed);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed);
        assert!(
            cause.reason.contains("launch attempts exhausted")
                && cause.reason.contains("exec failed"),
            "{cause:?}"
        );
    }

    /// A two-participant host: Bob is a second running participant with
    /// his own data root, so each trial has its own coordinator path.
    fn with_bob(record: &mut journal::JournalRecord) {
        let mut bob = record.plan.participants[0].clone();
        bob.instance_id = "bob".into();
        bob.data_root = bob.data_root.join("bob");
        std::fs::create_dir_all(&bob.data_root).unwrap();
        record.plan.participants.push(bob);
    }

    /// #1378 slice 5: on a two-participant host, Alice's own rollback
    /// (here: launch attempts exhausted) goes through the coordinator. The
    /// pass arms Bob's missing trial, restores the pair once for both and
    /// marks both trials Restored with Alice's Failed cause. Before, the
    /// single-trial restore refused a host whose full set it did not hold
    /// and the trial ended RecoveryFailed with the candidate pair in place.
    #[test]
    fn a_two_participant_rollback_restores_through_the_coordinator() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        write_probe(&host, 1, probe::ProbePhase::Passed);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let bob = coordinator::trial_path(&host.plan().participants[1]);
        let mut trial = trial_in(&host, &alice, Phase::Authorized, 0);
        let clock = fast_clock(&trial);
        // The fixture's previous bytes are not executable, so the restored
        // start fails after the restore; the restore itself is the check.
        let outcome = run_trial(&host, &alice, &mut trial, clock, |_| Ok(false), || false);
        assert!(outcome.is_err());
        assert_eq!(trial.attempts, MAX_ATTEMPTS);
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let cause = record.cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("launch attempts exhausted"),
            "{cause:?}"
        );
        let bob = Trial::load(&bob, &trial.binding, "bob").unwrap();
        assert_eq!(bob.phase, Phase::Restored);
        assert_eq!(
            bob.verdict.map(|v| v.class),
            Some(journal::CauseClass::Failed)
        );
    }

    fn set_journal(root: &Path, phase: journal::Phase, cause: Option<journal::Cause>) {
        let mut record = journal_record(root);
        record.sequence += 1;
        record.phase = phase;
        record.cause = cause;
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
    }

    /// #1989 review item 1: an error before the coordinator's fence (here
    /// Bob's trial does not load) is final. The host and Alice's trial are
    /// RecoveryFailed, no byte moved, and a restart does not repeat the
    /// pass.
    #[test]
    fn a_pre_fence_recovery_error_is_final() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        write_probe(&host, 1, probe::ProbePhase::Passed);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let bob = coordinator::trial_path(&host.plan().participants[1]);
        std::fs::write(&bob, b"not a trial record").unwrap();
        let mut trial = trial_in(&host, &alice, Phase::Authorized, 0);
        let clock = fast_clock(&trial);
        let outcome = run_trial(&host, &alice, &mut trial, clock, |_| Ok(false), || false);
        assert!(outcome.is_err());
        assert_eq!(journal_record(&root).phase, journal::Phase::RecoveryFailed);
        let mut again = Trial::load(&alice, &trial.binding, "alice").unwrap();
        assert_eq!(again.phase, Phase::RecoveryFailed);
        assert_eq!(
            filesystem::hash(&host.plan().daemon.target_path).unwrap(),
            host.plan().daemon.candidate_sha256
        );
        let clock = fast_clock(&again);
        let restart = run_trial(&host, &alice, &mut again, clock, |_| Ok(false), || false);
        assert_eq!(
            restart.err().map(|e| e.to_string()).as_deref(),
            Some("automatic start is forbidden")
        );
    }

    /// #1989 review item 2: a peer's coordinator restores the host and
    /// marks this trial Restored while an attempt runs. The failed attempt
    /// is requeued under the host lock from a fresh read, so it never
    /// writes Authorized over Restored; the launcher joins the restore and
    /// tries its restored start at once. (The fixture's pair was not
    /// actually restored, so that start then fails and is RecoveryFailed.)
    #[test]
    fn a_peer_restore_during_an_attempt_is_never_overwritten() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = trial_in(&host, &alice, Phase::Authorized, 0);
        let mut clock = fast_clock(&trial);
        let marked = std::cell::Cell::new(false);
        let binding = trial.binding.clone();
        let peer_clock = || {
            let on_disk = Trial::load(&alice, &binding, "alice").unwrap();
            if on_disk.phase == Phase::Booting && !marked.get() {
                // The peer's pass, as `settle` leaves it.
                let failed = cause(journal::CauseClass::Failed, "peer failed");
                set_journal(&root, journal::Phase::Restored, Some(failed.clone()));
                let mut restored = on_disk;
                restored.verdict = Some(failed);
                restored.phase = Phase::Restored;
                restored.save(&alice).unwrap();
                marked.set(true);
            }
            clock()
        };
        let outcome = run_trial(
            &host,
            &alice,
            &mut trial,
            peer_clock,
            |_| Ok(false),
            || false,
        );
        assert!(marked.get(), "the peer acted during the attempt");
        assert!(outcome.is_err());
        let on_disk = Trial::load(&alice, &trial.binding, "alice").unwrap();
        // The one restored start failed on the fixture's bytes: final.
        assert_eq!(on_disk.phase, Phase::RecoveryFailed, "{on_disk:?}");
        assert_eq!(on_disk.restored_starts, 1, "{on_disk:?}");
        assert_eq!(on_disk.attempts, 1);
        assert_eq!(on_disk.verdict.unwrap().reason, "peer failed");
        assert_eq!(journal_record(&root).phase, journal::Phase::Restored);
    }

    /// #1991 review: a peer's coordinator fences the host (RollingBack)
    /// during Alice's attempt and has not yet marked her trial, which is
    /// still Booting. The failed attempt is not requeued Authorized (the
    /// next attempt could not spawn on a fenced host); Alice joins the
    /// recovery. The pass restores the pair once, keeps the peer's first
    /// Failed cause, marks both trials Restored, and Alice makes one
    /// restored start. Before, the next attempt failed with "host is not
    /// ready for protected start" and the launcher exited.
    #[test]
    fn a_peer_fence_during_an_attempt_joins_the_recovery() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        write_probe(&host, 1, probe::ProbePhase::Passed);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let bob = coordinator::trial_path(&host.plan().participants[1]);
        let mut trial = trial_in(&host, &alice, Phase::Authorized, 0);
        let mut clock = fast_clock(&trial);
        let fenced = std::cell::Cell::new(false);
        let binding = trial.binding.clone();
        let peer_clock = || {
            let on_disk = Trial::load(&alice, &binding, "alice").unwrap();
            if on_disk.phase == Phase::Booting && !fenced.get() {
                // The peer's fence, before its stop and its trial marks.
                let failed = cause(journal::CauseClass::Failed, "peer failed");
                set_journal(&root, journal::Phase::RollingBack, Some(failed));
                fenced.set(true);
            }
            clock()
        };
        let outcome = run_trial(
            &host,
            &alice,
            &mut trial,
            peer_clock,
            |_| Ok(false),
            || false,
        );
        assert!(fenced.get(), "the peer fenced during the attempt");
        // The restored start fails on the fixture's unexecutable bytes.
        let error = outcome.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            !error.contains("host is not ready for protected start"),
            "{error}"
        );
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        assert_eq!(record.cause.unwrap().reason, "peer failed");
        let bob = Trial::load(&bob, &binding, "bob").unwrap();
        assert_eq!(bob.phase, Phase::Restored);
        let on_disk = Trial::load(&alice, &binding, "alice").unwrap();
        assert_eq!(on_disk.attempts, 1, "{on_disk:?}");
        assert_eq!(on_disk.restored_starts, 1, "{on_disk:?}");
        assert_eq!(on_disk.phase, Phase::RecoveryFailed, "{on_disk:?}");
    }

    /// #1991 review (23ce1538): a peer fences the host with an Interrupted
    /// cause during Alice's last allowed attempt, and her trial is still
    /// Booting. That attempt failed, so her verdict is Failed (attempts
    /// exhausted), not Interrupted, and the Failed verdict wins in the
    /// coordinator: the host records Failed and the release is held.
    #[test]
    fn a_peer_fence_on_the_last_attempt_records_failed() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        write_probe(&host, 1, probe::ProbePhase::Passed);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let bob = coordinator::trial_path(&host.plan().participants[1]);
        let mut trial = trial_in(&host, &alice, Phase::Authorized, MAX_ATTEMPTS - 1);
        let mut clock = fast_clock(&trial);
        let fenced = std::cell::Cell::new(false);
        let binding = trial.binding.clone();
        let peer_clock = || {
            let on_disk = Trial::load(&alice, &binding, "alice").unwrap();
            if on_disk.phase == Phase::Booting && !fenced.get() {
                let peer = cause(journal::CauseClass::Interrupted, "peer interrupted");
                set_journal(&root, journal::Phase::RollingBack, Some(peer));
                fenced.set(true);
            }
            clock()
        };
        let outcome = run_trial(
            &host,
            &alice,
            &mut trial,
            peer_clock,
            |_| Ok(false),
            || false,
        );
        assert!(fenced.get(), "the peer fenced during the attempt");
        // The restored start fails on the fixture's unexecutable bytes.
        assert!(outcome.is_err());
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let cause = record.cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("launch attempts exhausted"),
            "{cause:?}"
        );
        let on_disk = Trial::load(&alice, &binding, "alice").unwrap();
        assert_eq!(on_disk.attempts, MAX_ATTEMPTS, "{on_disk:?}");
        assert_eq!(
            on_disk.verdict.map(|v| v.class),
            Some(journal::CauseClass::Failed)
        );
        let bob = Trial::load(&bob, &binding, "bob").unwrap();
        assert_eq!(bob.phase, Phase::Restored);
        assert_eq!(
            bob.verdict.map(|v| v.class),
            Some(journal::CauseClass::Failed)
        );
    }

    /// #2005 review: a peer fences the host with an Interrupted cause
    /// during an earlier (not the last) attempt. The attempt count is not
    /// used up, so the verdict stays Interrupted and the release is not
    /// held as Failed.
    #[test]
    fn a_peer_fence_on_an_earlier_attempt_stays_interrupted() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        write_probe(&host, 1, probe::ProbePhase::Passed);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let bob = coordinator::trial_path(&host.plan().participants[1]);
        let mut trial = trial_in(&host, &alice, Phase::Authorized, 0);
        let mut clock = fast_clock(&trial);
        let fenced = std::cell::Cell::new(false);
        let binding = trial.binding.clone();
        let peer_clock = || {
            let on_disk = Trial::load(&alice, &binding, "alice").unwrap();
            if on_disk.phase == Phase::Booting && !fenced.get() {
                let peer = cause(journal::CauseClass::Interrupted, "peer interrupted");
                set_journal(&root, journal::Phase::RollingBack, Some(peer));
                fenced.set(true);
            }
            clock()
        };
        let outcome = run_trial(
            &host,
            &alice,
            &mut trial,
            peer_clock,
            |_| Ok(false),
            || false,
        );
        assert!(fenced.get(), "the peer fenced during the attempt");
        // The restored start fails on the fixture's unexecutable bytes.
        assert!(outcome.is_err());
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let cause = record.cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Interrupted, "{cause:?}");
        let on_disk = Trial::load(&alice, &binding, "alice").unwrap();
        assert_eq!(on_disk.attempts, 1, "{on_disk:?}");
        assert_eq!(
            on_disk.verdict.map(|v| v.class),
            Some(journal::CauseClass::Interrupted)
        );
        let bob = Trial::load(&bob, &binding, "bob").unwrap();
        assert_eq!(
            bob.verdict.map(|v| v.class),
            Some(journal::CauseClass::Interrupted)
        );
    }

    /// #2005 review: a clock error when a fenced last attempt joins the
    /// recovery does not leave the trial Booting (a restart would roll back
    /// as lost custody, Interrupted). The attempt count needs no clock, so
    /// the verdict is still Failed and the release is held.
    #[test]
    fn a_clock_error_on_a_fenced_last_attempt_still_records_failed() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        write_probe(&host, 1, probe::ProbePhase::Passed);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = trial_in(&host, &alice, Phase::Booting, MAX_ATTEMPTS);
        let peer = cause(journal::CauseClass::Interrupted, "peer interrupted");
        set_journal(&root, journal::Phase::RollingBack, Some(peer));
        let mut broken = || -> io::Result<Clock> { Err(io::Error::other("clock")) };
        let outcome = resume_peer_recovery(
            &host,
            &alice,
            &mut trial,
            Some("candidate exited before commit".into()),
            &mut broken,
            &mut || false,
        );
        // The restored start fails on the fixture's unexecutable bytes.
        assert!(outcome.is_err());
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let cause = record.cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("launch attempts exhausted"),
            "{cause:?}"
        );
        let on_disk = Trial::load(&alice, &trial.binding, "alice").unwrap();
        assert_ne!(on_disk.phase, Phase::Booting, "{on_disk:?}");
    }

    /// #1991 review: a failed coordinator pass on a host that a peer has
    /// already restored never marks the host RecoveryFailed, which would
    /// block every participant's restored start. Here Bob's trial does not
    /// load and Alice's trial was not marked Restored, so only Alice's
    /// trial is final; the host stays Restored.
    #[test]
    fn a_recovery_error_never_fails_a_restored_host() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        write_probe(&host, 1, probe::ProbePhase::Passed);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let bob = coordinator::trial_path(&host.plan().participants[1]);
        let mut trial = trial_in(&host, &alice, Phase::Booting, 1);
        std::fs::write(&bob, b"not a trial record").unwrap();
        let peer = cause(journal::CauseClass::Failed, "peer failed");
        set_journal(&root, journal::Phase::Restored, Some(peer));
        let clock = fast_clock(&trial);
        let outcome = run_trial(&host, &alice, &mut trial, clock, |_| Ok(false), || false);
        assert!(outcome.is_err());
        assert_eq!(journal_record(&root).phase, journal::Phase::Restored);
        let on_disk = Trial::load(&alice, &trial.binding, "alice").unwrap();
        assert_eq!(on_disk.phase, Phase::RecoveryFailed, "{on_disk:?}");
        assert_eq!(on_disk.restored_starts, 0, "{on_disk:?}");
    }

    /// #1991 review: as above, but the peer's pass had marked Alice's trial
    /// Restored by the time her own pass failed. She joins the peer's
    /// restore: the host stays Restored and she makes her restored start.
    #[test]
    fn a_recovery_error_after_a_peer_restore_joins_it() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        let alice = coordinator::trial_path(&host.plan().participants[0]);
        let mut trial = trial_in(&host, &alice, Phase::Booting, 1);
        let peer = cause(journal::CauseClass::Failed, "peer failed");
        set_journal(&root, journal::Phase::Restored, Some(peer.clone()));
        let mut restored = trial.clone();
        restored.verdict = Some(peer);
        restored.phase = Phase::Restored;
        restored.save(&alice).unwrap();
        let outcome = recovery_failed_final(&host, &alice, &mut trial, invalid("pass failed"));
        // The fixture's pair was not really restored: the start is refused
        // after it was reserved.
        assert!(outcome.is_err());
        assert_eq!(journal_record(&root).phase, journal::Phase::Restored);
        let on_disk = Trial::load(&alice, &trial.binding, "alice").unwrap();
        assert_eq!(on_disk.restored_starts, 1, "{on_disk:?}");
    }

    /// #1989 review item 3: crash-resume at run level on a two-participant
    /// host. Alice's launcher saved its verdict, then died either before
    /// the coordinator's fence or after it (host RollingBack). The
    /// restarted `run_trial` resumes the pass: the pair is restored once,
    /// both trials are Restored, and the first verdict is the host cause.
    #[test]
    fn a_restart_resumes_an_interrupted_coordinator_rollback() {
        for fenced in [false, true] {
            let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
            write_probe(&host, 1, probe::ProbePhase::Passed);
            let alice = coordinator::trial_path(&host.plan().participants[0]);
            let bob = coordinator::trial_path(&host.plan().participants[1]);
            let mut trial = trial_in(&host, &alice, Phase::Authorized, MAX_ATTEMPTS);
            let first = cause(journal::CauseClass::Failed, "first failure");
            trial.verdict = Some(first.clone());
            trial.save(&alice).unwrap();
            if fenced {
                set_journal(&root, journal::Phase::RollingBack, Some(first.clone()));
            }
            let mut restarted = Trial::load(&alice, &trial.binding, "alice").unwrap();
            let clock = fast_clock(&restarted);
            // The restored start fails on the fixture's unexecutable bytes.
            let outcome = run_trial(
                &host,
                &alice,
                &mut restarted,
                clock,
                |_| Ok(false),
                || false,
            );
            assert!(outcome.is_err(), "fenced={fenced}");
            assert_previous_pair(&host);
            let record = journal_record(&root);
            assert_eq!(record.phase, journal::Phase::Restored, "fenced={fenced}");
            assert_eq!(record.cause.unwrap().reason, "first failure");
            let bob = Trial::load(&bob, &trial.binding, "bob").unwrap();
            assert_eq!(bob.phase, Phase::Restored, "fenced={fenced}");
            let alice = Trial::load(&alice, &trial.binding, "alice").unwrap();
            assert_eq!(alice.restored_starts, 1, "fenced={fenced}");
            assert_eq!(alice.phase, Phase::RecoveryFailed, "fenced={fenced}");
        }
    }

    /// On a two-participant host the coordinator reads every trial at its
    /// coordinator path; a trial anywhere else is refused before any write
    /// to the host.
    #[test]
    fn a_two_participant_rollback_needs_the_coordinator_path() {
        let (_dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, with_bob);
        let path = root.join("elsewhere.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 0);
        let clock = fast_clock(&trial);
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_eq!(
            outcome.err().map(|e| e.to_string()).as_deref(),
            Some("trial is not at its coordinator path")
        );
        assert_eq!(journal_record(&root).phase, journal::Phase::SwappedCli);
    }

    /// A candidate that starts but whose boot setup fails (no permit
    /// acknowledgement, or no process custody on this OS) is a charged,
    /// failed attempt: the loop retries, never stops with a live Booting
    /// trial that a restart would class as interrupted.
    #[test]
    fn a_boot_setup_failure_is_a_charged_failed_attempt() {
        let (_dir, root, _host, record) = fixture(journal::Phase::SwappedCli);
        let host = executable_candidate(&root, record);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 0);
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_eq!(trial.attempts, MAX_ATTEMPTS);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
    }

    /// An earlier failed attempt does not turn a later interruption into a
    /// Failed hold: attempts remained, so ADR 0094 records an interruption.
    #[test]
    fn an_interruption_after_a_failed_attempt_stays_interrupted() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Booting, 1);
        trial.cause = Some("failed: readiness deadline reached".into());
        trial.save(&path).unwrap();
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Interrupted, "{cause:?}");
    }

    /// A launcher that died inside restore resumes it on the next start.
    #[test]
    fn an_interrupted_rollback_resumes_on_the_next_start() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::RollingBack, MAX_ATTEMPTS);
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let cause = record.cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Interrupted, "{cause:?}");
    }

    /// The first verdict wins: a launcher restart that re-enters rollback
    /// after a Failed verdict keeps Failed, not Interrupted.
    #[test]
    fn a_resumed_rollback_keeps_a_failed_verdict() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::RollingBack, MAX_ATTEMPTS);
        trial.verdict = Some(cause(
            journal::CauseClass::Failed,
            "launch attempts exhausted",
        ));
        trial.save(&path).unwrap();
        let mut trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let record = journal_record(&root);
        assert_eq!(record.phase, journal::Phase::Restored);
        let cause = record.cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("launch attempts exhausted"),
            "{cause:?}"
        );
        let verdict = trial.verdict.unwrap();
        assert_eq!(verdict.class, journal::CauseClass::Failed);
    }

    /// A service stop during the trial never wedges the host: the next
    /// start records an interruption and restores the previous pair.
    /// A launcher start after a reboot, with restored starts exhausted and
    /// the last restored child recorded from the earlier boot, must save
    /// RecoveryFailed to disk, not only in memory.
    #[test]
    fn exhausted_restored_starts_after_a_reboot_save_recovery_failed() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 1);
        trial.verdict = Some(interrupted("candidate exited before commit"));
        trial.phase = Phase::Restored;
        trial.restored_starts = MAX_ATTEMPTS;
        trial.child = Some(Identity {
            pid: 2,
            start: 3,
            boot: format!("{}-earlier", trial.boot),
        });
        trial.save(&path).unwrap();
        let clock = fast_clock(&trial);
        let error = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("restored starts exhausted"), "{error}");
        let saved = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert_eq!(saved.phase, Phase::RecoveryFailed);
        assert!(saved.child.is_none());
    }

    /// A stop that arrives after the last attempt failed does not turn the
    /// Failed verdict into Interrupted.
    #[test]
    fn a_stop_after_the_last_failed_attempt_stays_failed() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, MAX_ATTEMPTS);
        let clock = fast_clock(&trial);
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || true);
        // The stop restores nothing now; it records the Failed verdict.
        assert!(matches!(outcome, Ok(Outcome::Stopped)));
        let mut trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert_eq!(trial.phase, Phase::Stopped);
        assert!(trial.verdict.is_some());
        // The next start rolls back with the stored Failed verdict.
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("launch attempts exhausted"),
            "{cause:?}"
        );
    }

    /// A stop that arrives after the total budget ran out does not turn the
    /// Failed verdict into Interrupted.
    #[test]
    fn a_stop_after_the_total_budget_ran_out_stays_failed() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 1);
        let boot = trial.boot.clone();
        let late = trial.deadline_ms;
        let clock = move || {
            Ok(Clock {
                boot: boot.clone(),
                ms: late,
            })
        };
        let outcome = run_trial(
            &host,
            &path,
            &mut trial,
            clock.clone(),
            |_| Ok(false),
            || true,
        );
        // The stop restores nothing now; it records the Failed verdict.
        assert!(matches!(outcome, Ok(Outcome::Stopped)));
        let mut trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert_eq!(trial.phase, Phase::Stopped);
        assert!(trial.verdict.is_some());
        // The next start rolls back with the stored Failed verdict.
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("total trial deadline reached"),
            "{cause:?}"
        );
    }

    /// A stop that arrives as the last attempt's exec or boot setup fails is
    /// a stop: the next start rolls back as Interrupted, not Failed.
    #[test]
    fn a_stop_as_the_last_spawn_fails_stays_interrupted() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, MAX_ATTEMPTS - 1);
        let clock = fast_clock(&trial);
        let polls = std::cell::Cell::new(0u32);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 1
        };
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), stop);
        assert!(matches!(outcome, Ok(Outcome::Stopped)));
        assert_eq!(trial.attempts, MAX_ATTEMPTS);
        let mut trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert!(trial.verdict.is_none());
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Interrupted, "{cause:?}");
    }

    #[test]
    fn a_stopped_trial_restores_the_previous_pair_on_the_next_start() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Stopped, 1);
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Interrupted, "{cause:?}");
    }

    /// Every attempt re-checks the host journal before it spawns.
    #[test]
    fn no_attempt_starts_unless_the_host_journal_is_ready() {
        let (_dir, root, host, _record) = fixture(journal::Phase::Staged);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 0);
        let clock = fast_clock(&trial);
        let error = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("not ready"), "{error}");
        assert_eq!(trial.attempts, 0);
    }

    /// The budget is read again inside the install lock. The lock wait and
    /// the candidate hash can outlast the deadline after the loop-head check
    /// passed, so no attempt may be charged or spawned on the stale clock.
    #[test]
    fn an_attempt_may_not_spawn_on_a_clock_stale_from_the_lock_wait() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 0);
        let boot = trial.boot.clone();
        let deadline = trial.deadline_ms;
        let mut reads = 0;
        // The first read is the loop head; every later read is past the
        // deadline, as if the lock wait had used up the budget.
        let clock = move || {
            reads += 1;
            let ms = if reads == 1 {
                deadline - 1
            } else {
                deadline + 1
            };
            Ok(Clock {
                boot: boot.clone(),
                ms,
            })
        };
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        // The fixture's previous bytes cannot start, so the restored start
        // fails. The typed rollback cause is what must survive.
        assert!(outcome.is_err());
        assert_eq!(trial.attempts, 0);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("total trial deadline reached"),
            "{cause:?}"
        );
    }

    /// Linux custody: the restored child starts after rollback, a restarted
    /// launcher starts only the missing restored child, and restored starts
    /// stop at the bound with RecoveryFailed.
    /// A stop that arrives while a live candidate is health-checked, after
    /// the total budget ran out, records the Failed verdict before it saves
    /// Stopped. The next start rolls back as Failed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_stop_during_health_checks_after_the_budget_ran_out_stays_failed() {
        let (_dir, root, _host, record) = fixture(journal::Phase::SwappedCli);
        let host = executable_candidate(&root, record);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 0);
        let boot = trial.boot.clone();
        let (early, late) = (trial.started_ms + 1_000, trial.deadline_ms);
        let reads = std::cell::Cell::new(0u32);
        // The outer loop and the reservation read the clock inside the
        // budget; the inner loop's stop reads it after the deadline.
        let clock = || {
            reads.set(reads.get() + 1);
            Ok(Clock {
                boot: boot.clone(),
                ms: if reads.get() <= 2 { early } else { late },
            })
        };
        let polls = std::cell::Cell::new(0u32);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 1
        };
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), stop);
        assert!(matches!(outcome, Ok(Outcome::Stopped)));
        assert_eq!(trial.attempts, 1);
        // The stop came during health checks, not after a failed attempt.
        assert!(trial.cause.is_none());
        let mut trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert_eq!(trial.phase, Phase::Stopped);
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Failed, "{cause:?}");
        assert!(
            cause.reason.contains("total trial deadline reached"),
            "{cause:?}"
        );
    }

    /// A stop during the last attempt, inside the budget, is Interrupted:
    /// that attempt is counted but has not failed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_stop_during_the_last_attempt_is_interrupted() {
        let (_dir, root, _host, record) = fixture(journal::Phase::SwappedCli);
        let host = executable_candidate(&root, record);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, MAX_ATTEMPTS - 1);
        let boot = trial.boot.clone();
        let early = trial.started_ms + 1_000;
        let clock = || {
            Ok(Clock {
                boot: boot.clone(),
                ms: early,
            })
        };
        let polls = std::cell::Cell::new(0u32);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 1
        };
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), stop);
        assert!(matches!(outcome, Ok(Outcome::Stopped)));
        assert_eq!(trial.attempts, MAX_ATTEMPTS);
        let mut trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert!(trial.verdict.is_none());
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        assert_previous_pair(&host);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Interrupted, "{cause:?}");
        assert!(
            cause.reason.contains("service stopped during trial"),
            "{cause:?}"
        );
    }

    /// A stop that ends the last attempt's child before the next poll sees
    /// it is still a stop: the exit is not charged, and the next start
    /// rolls back as Interrupted.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_stop_that_ends_the_last_child_stays_interrupted() {
        let (_dir, root, _host, record) = fixture(journal::Phase::SwappedCli);
        let marker = root.join("stopping");
        // The child outlives boot setup, then ends as a stop would end it.
        let script = format!("#!/bin/sh\nsleep 1\ntouch '{}'\nexit 0\n", marker.display());
        let host = candidate_script(&root, record, &script);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, MAX_ATTEMPTS - 1);
        let boot = trial.boot.clone();
        let early = trial.started_ms + 1_000;
        let clock = || {
            Ok(Clock {
                boot: boot.clone(),
                ms: early,
            })
        };
        // The service manager's stop ends the child, and the launcher sees
        // the stop flag one poll later: the first poll after the marker
        // still reads no stop, so the next observation finds the exit first.
        let seen = std::cell::Cell::new(false);
        let stop = || {
            if !marker.exists() {
                return false;
            }
            seen.replace(true)
        };
        let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), stop);
        assert!(matches!(outcome, Ok(Outcome::Stopped)));
        assert_eq!(trial.attempts, MAX_ATTEMPTS);
        assert!(trial.cause.is_none(), "{:?}", trial.cause);
        let mut trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert!(trial.verdict.is_none());
        let clock = fast_clock(&trial);
        let _ = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
        let cause = journal_record(&root).cause.unwrap();
        assert_eq!(cause.class, journal::CauseClass::Interrupted, "{cause:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn restored_starts_are_reserved_and_bounded() {
        let (_dir, root, _host, mut record) = fixture(journal::Phase::SwappedCli);
        let backup = &record.plan.daemon.backup_path;
        std::fs::write(backup, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(backup, std::fs::Permissions::from_mode(0o755)).unwrap();
        record.plan.daemon.previous_sha256 = filesystem::hash(backup).unwrap();
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = recovery::Host::new(root.clone(), record).unwrap();
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Booting, 1);
        for start in 1..=MAX_ATTEMPTS {
            let clock = fast_clock(&trial);
            let outcome = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false);
            assert!(matches!(outcome, Ok(Outcome::Restored(_))), "start {start}");
            assert_eq!(trial.restored_starts, start);
            assert!(trial.child.is_some());
            // Dropping the outcome kills and reaps the restored child, as
            // a crash would; the next launcher start reloads the record.
            drop(outcome);
            trial = Trial::load(&path, &trial.binding, "alice").unwrap();
        }
        let clock = fast_clock(&trial);
        let error = run_trial(&host, &path, &mut trial, clock, |_| Ok(false), || false)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("restored starts exhausted"), "{error}");
        assert_eq!(trial.phase, Phase::RecoveryFailed);
        assert_eq!(
            Trial::load(&path, &trial.binding, "alice").unwrap().phase,
            Phase::RecoveryFailed
        );
        assert_eq!(
            journal_record(&root).cause.unwrap().class,
            journal::CauseClass::Interrupted
        );
    }

    #[test]
    fn an_intentional_stop_before_the_first_spawn_spends_no_attempt() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = trial_in(&host, &path, Phase::Authorized, 0);
        let clock = Clock::now().unwrap();
        let outcome = run_trial(
            &host,
            &path,
            &mut trial,
            || Ok(clock.clone()),
            |_| Ok(false),
            || true,
        )
        .unwrap();
        assert!(matches!(outcome, Outcome::Stopped));
        assert_eq!(trial.attempts, 0);
        assert_eq!(trial.phase, Phase::Stopped);
    }
}
