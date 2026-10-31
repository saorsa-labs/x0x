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
                child.reap()?;
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
        child.reap()?;
        trial.child = None;
        trial.cause = Some(failure.to_string());
        trial.phase = Phase::Authorized;
        trial.next_launch_ms = now()?.ms.saturating_add(GAP_MS);
        trial.save(path)?;
    }
}

fn rollback(
    host: &recovery::Host,
    path: &Path,
    trial: &mut Trial,
    reason: &str,
) -> io::Result<Outcome> {
    trial.phase = Phase::RollingBack;
    trial.cause = Some(reason.into());
    trial.save(path)?;
    let cause = journal::Cause {
        class: if reason.starts_with("interrupted:") {
            journal::CauseClass::Interrupted
        } else {
            journal::CauseClass::Failed
        },
        reason: reason.into(),
    };
    // A single launcher cannot restore on behalf of another participant.
    // Multi-participant rollback must gather the full set through S3c.
    if let Err(error) = host.restore(&[(path.to_owned(), trial.clone())], cause) {
        trial.phase = Phase::RecoveryFailed;
        let _ = trial.save(path);
        return Err(error);
    }
    trial.phase = Phase::Restored;
    trial.save(path)?;
    let restored = host.locked(|record| {
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
    })?;
    Ok(Outcome::Restored(restored))
}
