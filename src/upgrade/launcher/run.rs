use super::*;

pub(super) enum Outcome {
    Stopped,
    Restored(child::Owned),
    // Ownership remains with this launcher. The S3c host coordinator must
    // still verify all participants before it can commit the host.
    Provisional(child::Owned),
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
    if trial.phase == Phase::Restored {
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
        if stop() {
            trial.phase = Phase::Stopped;
            trial.save(path)?;
            return Ok(Outcome::Stopped);
        }
        let clock = now()?;
        if let Some(cause) = trial.expired(&clock) {
            return rollback(host, path, trial, cause);
        }
        if trial.attempts >= MAX_ATTEMPTS {
            let reason = format!(
                "launch attempts exhausted: {}",
                trial.cause.as_deref().unwrap_or("no health commit")
            );
            return rollback(
                host,
                path,
                trial,
                cause(journal::CauseClass::Failed, reason),
            );
        }
        if clock.ms < trial.next_launch_ms {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        let spawned = host.locked(|record| {
            // Each attempt re-checks the host phase, not only the first.
            if !matches!(
                record.phase,
                journal::Phase::SwappedCli | journal::Phase::HandoffArmed
            ) {
                return Err(invalid("host is not ready for protected start"));
            }
            host.verify_candidate()?;
            trial.reserve(path, &clock)?;
            child::Owned::spawn(
                trial,
                path,
                p,
                &host.plan().candidate_version,
                host.plan().daemon.candidate_sha256,
            )
        });
        let mut child = match spawned? {
            Some(child) => child,
            // Exec or boot setup failed. The attempt stays charged.
            None => {
                trial.child = None;
                trial.phase = Phase::Authorized;
                trial.next_launch_ms = now()?.ms.saturating_add(GAP_MS);
                trial.save(path)?;
                continue;
            }
        };
        let failure = loop {
            if stop() {
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
                Err(error) => break error,
                Ok(false) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };
        if let Err(error) = child.reap() {
            return Err(trial.recovery_failed(path, error));
        }
        trial.child = None;
        trial.cause = Some(failure.to_string());
        trial.phase = Phase::Authorized;
        trial.next_launch_ms = now()?.ms.saturating_add(GAP_MS);
        trial.save(path)?;
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
    let cause = trial.verdict.get_or_insert(cause).clone();
    trial.phase = Phase::RollingBack;
    trial.save(path)?;
    // A single launcher cannot restore on behalf of another participant.
    // Multi-participant rollback must gather the full set through S3c.
    if let Err(error) = host.restore(&[(path.to_owned(), trial.clone())], cause) {
        return Err(trial.recovery_failed(path, error));
    }
    trial.phase = Phase::Restored;
    trial.save(path)?;
    let restored = start_restored(host, path, trial)?;
    Ok(Outcome::Restored(restored))
}

#[cfg(all(test, unix))]
mod tests {
    use super::testkit::fixture;
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
    fn executable_candidate(root: &Path, mut record: journal::JournalRecord) -> recovery::Host {
        let target = &record.plan.daemon.target_path;
        std::fs::write(target, "#!/bin/sh\nexec sleep 30\n").unwrap();
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
            cause.reason.contains("launch attempts exhausted"),
            "{cause:?}"
        );
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
        assert_eq!(journal_record(&root).phase, journal::Phase::Restored);
    }

    /// A service stop during the trial never wedges the host: the next
    /// start records an interruption and restores the previous pair.
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

    /// Linux custody: the restored child starts after rollback, a restarted
    /// launcher starts only the missing restored child, and restored starts
    /// stop at the bound with RecoveryFailed.
    #[cfg(target_os = "linux")]
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
