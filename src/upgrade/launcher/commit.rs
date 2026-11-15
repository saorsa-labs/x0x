//! S3d host commit gate (ADR 0094 §3, §4; #1377). Dormant like the rest of
//! this module. HTTP 200 alone is never health: each candidate writes a
//! health commit (`journal::HealthRecord`) that binds the transaction, its
//! child identity and attempt, the version, its roots and the executable
//! hash. The coordinator commits the host only when every running
//! participant is Provisional with a live child and a binding, healthy
//! record, and both installed files hash to the candidate pair.
use super::*;

/// What one candidate's health commit shows.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Health {
    /// A binding record with a healthy local verdict and, if required,
    /// peer continuity (D193).
    Committed,
    /// No record yet, or the candidate is not healthy yet: stores not
    /// initialized or a local M1 verdict that is not `ok`. The trial's own
    /// deadlines decide what happens next.
    NotYet(&'static str),
    /// The record can never commit this candidate.
    Refused(journal::Cause),
}

/// Check one participant's health commit against the plan and its trial.
pub(super) fn instance_health(
    host: &recovery::Host,
    participant: &journal::Participant,
    trial: &Trial,
) -> io::Result<Health> {
    let Some(record) = journal::read_health(&participant.data_root)? else {
        return Ok(Health::NotYet("no health commit"));
    };
    Ok(check_record(host, participant, trial, &record))
}

fn check_record(
    host: &recovery::Host,
    participant: &journal::Participant,
    trial: &Trial,
    record: &journal::HealthRecord,
) -> Health {
    let plan = host.plan();
    let Some(child) = &trial.child else {
        return Health::NotYet("no current candidate");
    };
    // A record from another transaction, attempt or process is stale: the
    // current candidate has not written its own yet.
    if record.transaction_id != trial.binding.transaction
        || record.generation != trial.binding.generation
        || record.instance_id != participant.instance_id
        || record.attempt != trial.attempts
        || record.pid != child.pid
        || record.process_start != child.start
        || record.boot_id != child.boot
    {
        return Health::NotYet("health commit is from another candidate");
    }
    // The current candidate wrote it, but runs the wrong release or roots:
    // it can never be this transaction's healthy candidate.
    if record.version != plan.candidate_version
        || record.executable_sha256 != plan.daemon.candidate_sha256
        || record.data_root != participant.data_root
        || record.identity_root != participant.identity_root
    {
        return Health::Refused(cause(
            journal::CauseClass::Failed,
            "health commit does not match the candidate's version, roots or executable",
        ));
    }
    if !record.stores_initialized {
        return Health::NotYet("stores not initialized");
    }
    if record.local_verdict != journal::LocalVerdict::Ok {
        return Health::NotYet("local M1 verdict is not ok");
    }
    // D193: a host that had a send-ready peer must reach one and keep it
    // through the stable interval; a miss is Interrupted.
    if record.previously_connected && !record.peer_continuity {
        return Health::Refused(cause(
            journal::CauseClass::Interrupted,
            "peer continuity lost",
        ));
    }
    Health::Committed
}

/// Write the host commit when the full set is healthy. `Ok(None)` means
/// committed; `Ok(Some(cause))` means refused with nothing changed. A
/// refusal with no cause class decision (a candidate not healthy yet)
/// is reported as Interrupted `not yet healthy`; the caller keeps waiting
/// within the trial budget and does not roll back on it.
pub(super) fn host_commit(
    host: &recovery::Host,
    trials: &[(PathBuf, Trial)],
) -> io::Result<Option<journal::Cause>> {
    host.commit(|| {
        for p in &host.plan().participants {
            if !p.was_running {
                continue;
            }
            let Some((_, trial)) = trials.iter().find(|(_, t)| t.instance == p.instance_id) else {
                return Ok(Some(not_yet("participant trial missing")));
            };
            if trial.binding != host.binding()? {
                return Err(invalid("trial binding mismatch"));
            }
            if trial.phase != Phase::Provisional {
                return Ok(Some(not_yet("participant is not provisional")));
            }
            match instance_health(host, p, trial)? {
                Health::Committed => {}
                Health::NotYet(reason) => return Ok(Some(not_yet(reason))),
                Health::Refused(cause) => return Ok(Some(cause)),
            }
            // Last: the committed candidate must still be the live child.
            let child = trial
                .child
                .as_ref()
                .ok_or_else(|| invalid("provisional trial has no child"))?;
            if child::absent(child)? {
                return Ok(Some(not_yet("candidate is gone")));
            }
        }
        Ok(None)
    })
}

fn not_yet(reason: &str) -> journal::Cause {
    cause(
        journal::CauseClass::Interrupted,
        format!("not yet healthy: {reason}"),
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::testkit::fixture;
    use super::*;

    fn journal_phase(root: &Path) -> journal::Phase {
        match journal::read_boot_records(root).journal {
            journal::RecordRead::Journal(record) => record.phase,
            _ => panic!("journal missing"),
        }
    }

    /// A Provisional trial whose child is `identity`.
    fn provisional(host: &recovery::Host, root: &Path, identity: Identity) -> (PathBuf, Trial) {
        let clock = Clock {
            boot: identity.boot.clone(),
            ms: 1_000,
        };
        let path = root.join("trial.json");
        let mut trial = Trial::new(host.binding().unwrap(), "alice".into(), &clock).unwrap();
        trial.save(&path).unwrap();
        trial.phase = Phase::Authorized;
        trial.save(&path).unwrap();
        trial.reserve(&path, &clock).unwrap();
        trial.child = Some(identity);
        trial.ready_since_ms = Some(clock.ms);
        trial.phase = Phase::Provisional;
        trial.save(&path).unwrap();
        (path, trial)
    }

    fn healthy_record(host: &recovery::Host, trial: &Trial) -> journal::HealthRecord {
        let p = &host.plan().participants[0];
        let child = trial.child.clone().unwrap();
        journal::HealthRecord {
            schema_version: 1,
            record_kind: "health".into(),
            transaction_id: trial.binding.transaction.clone(),
            generation: trial.binding.generation,
            instance_id: p.instance_id.clone(),
            attempt: trial.attempts,
            pid: child.pid,
            process_start: child.start,
            boot_id: child.boot,
            version: host.plan().candidate_version.clone(),
            data_root: p.data_root.clone(),
            identity_root: p.identity_root.clone(),
            executable_sha256: host.plan().daemon.candidate_sha256,
            stores_initialized: true,
            local_verdict: journal::LocalVerdict::Ok,
            previously_connected: true,
            peer_continuity: true,
        }
    }

    fn write_health(root: &Path, record: &journal::HealthRecord) {
        journal::write_auxiliary_record(
            &root.join(journal::HEALTH_FILE_NAME),
            record,
            journal::validate_health,
        )
        .unwrap();
    }

    fn gone_child() -> Identity {
        Identity {
            pid: 4300,
            start: 1,
            boot: "fixture-boot".into(),
        }
    }

    /// The record checks run before any process check, so they need no
    /// live child.
    #[test]
    fn a_wrong_root_or_release_refuses_and_an_unhealthy_m1_verdict_waits() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let (_path, trial) = provisional(&host, &root, gone_child());
        let p = &host.plan().participants[0];
        let good = healthy_record(&host, &trial);
        assert_eq!(check_record(&host, p, &trial, &good), Health::Committed);

        let mut wrong_roots = good.clone();
        wrong_roots.data_root = PathBuf::from("/var/lib/elsewhere");
        assert!(matches!(
            check_record(&host, p, &trial, &wrong_roots),
            Health::Refused(c) if c.class == journal::CauseClass::Failed
        ));
        let mut wrong_release = good.clone();
        wrong_release.version = "0.0.2".into();
        assert!(matches!(
            check_record(&host, p, &trial, &wrong_release),
            Health::Refused(_)
        ));
        let mut wrong_exe = good.clone();
        wrong_exe.executable_sha256 = [9; 32];
        assert!(matches!(
            check_record(&host, p, &trial, &wrong_exe),
            Health::Refused(_)
        ));
        let mut m1_error = good.clone();
        m1_error.local_verdict = journal::LocalVerdict::Error;
        assert!(matches!(
            check_record(&host, p, &trial, &m1_error),
            Health::NotYet(_)
        ));
        let mut stores = good.clone();
        stores.stores_initialized = false;
        assert!(matches!(
            check_record(&host, p, &trial, &stores),
            Health::NotYet(_)
        ));
        let mut stale = good.clone();
        stale.attempt += 1;
        assert!(matches!(
            check_record(&host, p, &trial, &stale),
            Health::NotYet(_)
        ));
    }

    /// D193: a host that had a send-ready peer and lost it is Interrupted;
    /// a host that never had one commits on local checks alone.
    #[test]
    fn d193_peer_continuity_applies_only_to_a_previously_connected_host() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let (_path, trial) = provisional(&host, &root, gone_child());
        let p = &host.plan().participants[0];
        let mut lost = healthy_record(&host, &trial);
        lost.peer_continuity = false;
        assert!(matches!(
            check_record(&host, p, &trial, &lost),
            Health::Refused(c) if c.class == journal::CauseClass::Interrupted
        ));
        lost.previously_connected = false;
        assert_eq!(check_record(&host, p, &trial, &lost), Health::Committed);
    }

    /// An M1 failure, a wrong root or a missing record never commits the
    /// host, and the journal stays uncommitted.
    #[test]
    fn host_commit_refuses_without_a_healthy_full_set() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trials = vec![provisional(&host, &root, gone_child())];
        let refused = host_commit(&host, &trials).unwrap().unwrap();
        assert!(refused.reason.contains("no health commit"), "{refused:?}");

        let mut record = healthy_record(&host, &trials[0].1);
        record.local_verdict = journal::LocalVerdict::Error;
        write_health(&root, &record);
        let refused = host_commit(&host, &trials).unwrap().unwrap();
        assert!(refused.reason.contains("M1"), "{refused:?}");

        record.local_verdict = journal::LocalVerdict::Ok;
        record.identity_root = PathBuf::from("/var/lib/elsewhere");
        write_health(&root, &record);
        let refused = host_commit(&host, &trials).unwrap().unwrap();
        assert_eq!(refused.class, journal::CauseClass::Failed);
        assert_eq!(journal_phase(&root), journal::Phase::SwappedCli);
    }

    /// The CLI must hash to the candidate before the host commits.
    #[test]
    fn host_commit_refuses_a_changed_cli() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let trials = vec![provisional(&host, &root, gone_child())];
        write_health(&root, &healthy_record(&host, &trials[0].1));
        std::fs::write(&host.plan().cli.target_path, b"other cli").unwrap();
        let refused = host_commit(&host, &trials).unwrap().unwrap();
        assert!(refused.reason.contains("candidate pair"), "{refused:?}");
        assert_eq!(journal_phase(&root), journal::Phase::SwappedCli);
    }

    /// A healthy live candidate with a binding record commits the host.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_healthy_live_full_set_commits_the_host() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = child::identity(live.id()).unwrap();
        let trials = vec![provisional(&host, &root, identity)];
        write_health(&root, &healthy_record(&host, &trials[0].1));
        assert_eq!(host_commit(&host, &trials).unwrap(), None);
        assert_eq!(journal_phase(&root), journal::Phase::HostCommitted);
        assert!(journal::host_commit_gate_open(&root));
        live.kill().unwrap();
        live.wait().unwrap();
    }
}
