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
    if trial.phase == Phase::RecoveryFailed || trial.phase == Phase::Stopped {
        return Err(invalid("automatic start is forbidden"));
    }
    if trial.phase == Phase::Restored {
        // ADR 0094 S4: a restarted launcher starts only a missing restored
        // child. The previous bytes are already installed, so no trial
        // budget is spent and no rollback is repeated.
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
            "interrupted: launcher lost child custody",
        );
    }
    if trial.phase != Phase::Authorized {
        if trial.phase == Phase::Booting {
            return rollback(host, path, trial, "interrupted: launcher died during exec");
        }
        return Err(invalid("no durable start authority"));
    }
    loop {
        if stop() {
            trial.phase = Phase::Stopped;
            trial.save(path)?;
            return Ok(Outcome::Stopped);
        }
        let clock = now()?;
        if let Err(error) = trial.check_budget(&clock) {
            return rollback(host, path, trial, &error.to_string());
        }
        if trial.attempts >= MAX_ATTEMPTS {
            let reason = format!(
                "failed: launch attempts exhausted: {}",
                trial.cause.as_deref().unwrap_or("no health commit")
            );
            return rollback(host, path, trial, &reason);
        }
        if clock.ms < trial.next_launch_ms {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        let spawned = host.locked(|_| {
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
                    return Err(reap_failed(path, trial, error));
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
            return Err(reap_failed(path, trial, error));
        }
        trial.child = None;
        trial.cause = Some(failure.to_string());
        trial.phase = Phase::Authorized;
        trial.next_launch_ms = now()?.ms.saturating_add(GAP_MS);
        trial.save(path)?;
    }
}

/// A failed reap leaves an unowned process behind, so the trial must not
/// stay in a live phase that a later start could resume.
fn reap_failed(path: &Path, trial: &mut Trial, error: io::Error) -> io::Error {
    trial.phase = Phase::RecoveryFailed;
    trial.cause = Some(error.to_string());
    // The durable RecoveryFailed marker is the operator signal; a failed
    // marker save must not mask the reap error that caused it.
    let _ = trial.save(path);
    error
}

/// Start the previous bytes after restoration. ADR 0094 S4: the launcher
/// restarts restored bytes as needed, so a spawn failure here is retried
/// by the next launcher start, not converted to RecoveryFailed.
fn start_restored(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
) -> io::Result<child::Owned> {
    host.locked(|record| {
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
        let child = child::Owned::restored(p)?;
        trial.child = Some(child.identity().clone());
        trial.save(path)?;
        Ok(child)
    })
}

fn rollback(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    reason: &str,
) -> io::Result<Outcome> {
    trial.phase = Phase::RollingBack;
    // A launcher restart re-entering rollback must not downgrade a recorded
    // Failed cause to Interrupted, which would reopen backoff and reapply
    // of a known-bad release (ADR 0094 S4 keeps the original cause).
    let reason = retained_cause(trial.cause.as_deref(), reason).into_owned();
    trial.cause = Some(reason.clone());
    trial.save(path)?;
    let cause = journal::Cause {
        class: if reason.starts_with("interrupted:") {
            journal::CauseClass::Interrupted
        } else {
            journal::CauseClass::Failed
        },
        reason,
    };
    // A single launcher cannot restore on behalf of another participant.
    // Multi-participant rollback must gather the full set through S3c.
    if let Err(error) = host.restore(&[(path.to_owned(), trial.clone())], cause) {
        trial.phase = Phase::RecoveryFailed;
        // Fail-closed marker only: the returned error carries the cause.
        let _ = trial.save(path);
        return Err(error);
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

    /// Real exec failures against a non-executable candidate: all three
    /// attempts are charged, the previous bytes are restored, and the
    /// restored daemon that cannot start leaves a retryable error (the
    /// fixture's previous bytes stay mode 0644, so the restored spawn
    /// fails and the phase stays Restored for the next launcher start).
    #[test]
    fn exec_failures_exhaust_attempts_and_restore_previous_bytes() {
        let (dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        trial.phase = Phase::Authorized;
        trial.save(&path).unwrap();
        let boot = trial.boot.clone();
        let mut ms = Clock::now().unwrap().ms;
        let outcome = run_trial(
            &host,
            &path,
            &mut trial,
            || {
                ms += 10_000;
                Ok(Clock {
                    boot: boot.clone(),
                    ms,
                })
            },
            |_| Ok(false),
            || false,
        );
        assert!(outcome.is_err());
        assert_eq!(trial.attempts, MAX_ATTEMPTS);
        assert_eq!(trial.phase, Phase::Restored);
        assert_eq!(
            filesystem::hash(&host.plan().daemon.target_path).unwrap(),
            host.plan().daemon.previous_sha256
        );
        drop(dir);
    }

    #[test]
    fn an_intentional_stop_before_the_first_spawn_spends_no_attempt() {
        let (dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        trial.phase = Phase::Authorized;
        trial.save(&path).unwrap();
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
        drop(dir);
    }
}
