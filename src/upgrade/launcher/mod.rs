//! Private, dormant S3b engine. No installer or daemon apply path calls it.
//! The complete inventory issuer and host coordinator remain separate gates.
#![allow(dead_code)]

mod child;
mod filesystem;
#[path = "../journal.rs"]
mod journal;
#[path = "../probe.rs"]
mod probe;
const ENABLED: bool = false;
impl Clock {
    fn now() -> io::Result<Self> {
        let clock = probe::ProbeClock::now()?;
        Ok(Self {
            boot: clock.boot_id,
            ms: clock.monotonic_ms,
        })
    }
}

pub(crate) fn candidate_boot(version: &str) -> io::Result<()> {
    child::candidate_boot(version)
}
pub(crate) fn candidate_boot_for_fixture(version: &str) -> io::Result<()> {
    child::candidate_boot_owned(version)
}
mod control;
mod recovery;
pub(crate) fn fixture_receipt(request: &[u8]) -> io::Result<serde_json::Value> {
    control::fixture_receipt(request)
}
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
};

const TRIAL_MS: u64 = 660_000;
const READY_MS: u64 = 120_000;
const STABLE_MS: u64 = 60_000;
const REAP_MS: u64 = 10_000;
const GAP_MS: u64 = 10_000;
const MAX_ATTEMPTS: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    pid: u32,
    start: u64,
    boot: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    transaction: String,
    generation: u64,
    plan_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Armed,
    Authorized,
    Booting,
    Provisional,
    Stopped,
    RollingBack,
    Restored,
    RecoveryFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trial {
    schema: u32,
    binding: Binding,
    instance: String,
    boot: String,
    started_ms: u64,
    deadline_ms: u64,
    attempts: u32,
    attempt_deadline_ms: u64,
    next_launch_ms: u64,
    ready_since_ms: Option<u64>,
    child: Option<Identity>,
    phase: Phase,
    cause: Option<String>,
}

#[derive(Clone, Debug)]
struct Clock {
    boot: String,
    ms: u64,
}

impl Trial {
    // Called before the first OLD shutdown request, never on each retry.
    fn new(binding: Binding, instance: String, clock: &Clock) -> io::Result<Self> {
        Ok(Self {
            schema: 1,
            binding,
            instance,
            boot: clock.boot.clone(),
            started_ms: clock.ms,
            deadline_ms: clock
                .ms
                .checked_add(TRIAL_MS)
                .ok_or_else(|| invalid("clock overflow"))?,
            attempts: 0,
            attempt_deadline_ms: 0,
            next_launch_ms: clock.ms,
            ready_since_ms: None,
            child: None,
            phase: Phase::Armed,
            cause: None,
        })
    }

    fn check_budget(&self, clock: &Clock) -> io::Result<()> {
        if self.boot != clock.boot || clock.ms < self.started_ms {
            return Err(invalid("interrupted: boot changed or clock regressed"));
        }
        if clock.ms >= self.deadline_ms {
            return Err(invalid("failed: total trial deadline reached"));
        }
        Ok(())
    }

    /// Persist the attempt before exec. A failed spawn consumes this attempt.
    fn reserve(&mut self, path: &Path, clock: &Clock) -> io::Result<()> {
        self.check_budget(clock)?;
        if self.phase != Phase::Authorized
            || self.child.is_some()
            || self.attempts >= MAX_ATTEMPTS
            || clock.ms < self.next_launch_ms
        {
            return Err(invalid("candidate start is not authorized"));
        }
        self.attempts += 1;
        self.attempt_deadline_ms = clock.ms.saturating_add(READY_MS).min(self.deadline_ms);
        self.ready_since_ms = None;
        self.phase = Phase::Booting;
        self.save(path)
    }

    fn observe_health(&mut self, path: &Path, clock: &Clock, healthy: bool) -> io::Result<bool> {
        self.check_budget(clock)?;
        if self.phase != Phase::Booting || self.child.is_none() {
            return Err(invalid("health has no current child"));
        }
        if let Some(since) = self.ready_since_ms {
            if !healthy {
                return Err(invalid("failed: stable health lost"));
            }
            if clock.ms >= since.saturating_add(STABLE_MS) {
                self.phase = Phase::Provisional;
                self.save(path)?;
                return Ok(true);
            }
        } else {
            if clock.ms >= self.attempt_deadline_ms {
                return Err(invalid("failed: readiness deadline reached"));
            }
            if healthy {
                self.ready_since_ms = Some(clock.ms);
                self.save(path)?;
            }
        }
        Ok(false)
    }

    fn save(&self, path: &Path) -> io::Result<()> {
        match journal::read_auxiliary_record(path) {
            Ok(bytes) => {
                validate_trial(&bytes)?;
                let old: Trial = serde_json::from_slice(&bytes)?;
                if old.binding != self.binding
                    || old.instance != self.instance
                    || old.boot != self.boot
                    || old.started_ms != self.started_ms
                    || old.deadline_ms != self.deadline_ms
                    || old.attempts > self.attempts
                    || (matches!(old.phase, Phase::Stopped | Phase::RecoveryFailed)
                        && old.phase != self.phase)
                {
                    return Err(invalid("existing trial cannot be replaced or reset"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        journal::write_auxiliary_record(path, self, validate_trial)
    }

    fn load(path: &Path, binding: &Binding, instance: &str) -> io::Result<Self> {
        let bytes = journal::read_auxiliary_record(path)?;
        validate_trial(&bytes)?;
        let trial: Self = serde_json::from_slice(&bytes)?;
        if &trial.binding != binding || trial.instance != instance {
            return Err(invalid(
                "trial belongs to another transaction or participant",
            ));
        }
        // Re-establish the barrier: readable bytes alone do not prove fsync.
        trial.save(path)?;
        Ok(trial)
    }
}

fn validate_trial(bytes: &[u8]) -> io::Result<()> {
    let trial: Trial = serde_json::from_slice(bytes)?;
    if trial.schema != 1
        || trial.binding.transaction.is_empty()
        || trial.instance.is_empty()
        || trial.boot.is_empty()
        || trial.attempts > MAX_ATTEMPTS
        || trial.started_ms.checked_add(TRIAL_MS) != Some(trial.deadline_ms)
        || (matches!(trial.phase, Phase::Booting | Phase::Provisional) && trial.attempts == 0)
        || (matches!(
            trial.phase,
            Phase::Armed | Phase::Authorized | Phase::Stopped
        ) && trial.child.is_some())
        || (trial.phase == Phase::Provisional
            && (trial.ready_since_ms.is_none() || trial.child.is_none()))
        || trial.child.as_ref().is_some_and(|child| {
            child.pid == 0 || (trial.phase != Phase::Restored && child.boot != trial.boot)
        })
        || trial.attempt_deadline_ms > trial.deadline_ms
    {
        return Err(invalid("invalid launcher trial"));
    }
    Ok(())
}

fn digest(value: &impl Serialize) -> io::Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).into())
}

fn invalid(reason: impl std::fmt::Display) -> io::Error {
    io::Error::other(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, Trial, Clock) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trial.json");
        let clock = Clock {
            boot: "boot-1".into(),
            ms: 1000,
        };
        let binding = Binding {
            transaction: "transaction-1".into(),
            generation: 1,
            plan_sha256: [7; 32],
        };
        let trial = Trial::new(binding, "alice".into(), &clock).unwrap();
        trial.save(&path).unwrap();
        (dir, path, trial, clock)
    }

    #[test]
    fn attempts_survive_reload_and_exec_failure() {
        let (_dir, path, mut trial, clock) = fixture();
        trial.phase = Phase::Authorized;
        trial.reserve(&path, &clock).unwrap();
        // Real failed exec: no candidate code can run a boot counter.
        assert!(std::process::Command::new(path.with_file_name("absent"))
            .spawn()
            .is_err());
        let saved = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert_eq!(saved.attempts, 1);
        assert_eq!(saved.deadline_ms, clock.ms + TRIAL_MS);
        assert_eq!(saved.phase, Phase::Booting);
    }

    #[test]
    fn restart_keeps_original_budget_and_changed_boot_refuses() {
        let (_dir, path, trial, clock) = fixture();
        let saved = Trial::load(&path, &trial.binding, "alice").unwrap();
        assert_eq!(saved.deadline_ms, trial.deadline_ms);
        assert!(saved
            .check_budget(&Clock {
                ms: trial.deadline_ms,
                ..clock.clone()
            })
            .is_err());
        assert!(saved
            .check_budget(&Clock {
                boot: "boot-2".into(),
                ms: 1
            })
            .is_err());
        assert_eq!(
            Trial::load(&path, &trial.binding, "alice")
                .unwrap()
                .deadline_ms,
            trial.deadline_ms
        );
    }

    #[test]
    fn no_authority_no_spawn_and_three_attempts_only() {
        let (_dir, path, mut trial, clock) = fixture();
        assert!(trial.reserve(&path, &clock).is_err());
        for attempt in 1..=MAX_ATTEMPTS {
            trial.phase = Phase::Authorized;
            trial.reserve(&path, &clock).unwrap();
            assert_eq!(
                Trial::load(&path, &trial.binding, "alice")
                    .unwrap()
                    .attempts,
                attempt
            );
        }
        trial.phase = Phase::Authorized;
        assert!(trial.reserve(&path, &clock).is_err());
    }

    #[test]
    fn readiness_and_stable_health_are_both_bounded() {
        let (_dir, path, mut trial, clock) = fixture();
        trial.phase = Phase::Authorized;
        trial.reserve(&path, &clock).unwrap();
        trial.child = Some(Identity {
            pid: 2,
            start: 3,
            boot: clock.boot.clone(),
        });
        let ready = Clock {
            ms: clock.ms + READY_MS - 1,
            ..clock.clone()
        };
        assert!(!trial.observe_health(&path, &ready, true).unwrap());
        assert!(!trial
            .observe_health(
                &path,
                &Clock {
                    ms: ready.ms + STABLE_MS - 1,
                    ..clock.clone()
                },
                true
            )
            .unwrap());
        assert!(trial
            .observe_health(
                &path,
                &Clock {
                    ms: ready.ms + STABLE_MS,
                    ..clock
                },
                true
            )
            .unwrap());
        assert_eq!(
            Trial::load(&path, &trial.binding, "alice").unwrap().phase,
            Phase::Provisional
        );
    }

    #[test]
    fn corrupt_or_wrong_transaction_never_resets_the_budget() {
        let (_dir, path, trial, _) = fixture();
        let mut binding = trial.binding.clone();
        binding.generation += 1;
        assert!(Trial::load(&path, &binding, "alice").is_err());
        assert!(Trial::load(&path, &trial.binding, "bob").is_err());
        std::fs::write(&path, b"{incomplete").unwrap();
        assert!(Trial::load(&path, &trial.binding, "alice").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"{incomplete");
    }

    #[test]
    fn a_fresh_trial_cannot_replace_the_original_deadline() {
        let (_dir, path, trial, mut clock) = fixture();
        clock.ms += 100;
        let replacement =
            Trial::new(trial.binding.clone(), trial.instance.clone(), &clock).unwrap();
        assert!(replacement.save(&path).is_err());
        assert_eq!(
            Trial::load(&path, &trial.binding, "alice")
                .unwrap()
                .deadline_ms,
            trial.deadline_ms
        );
    }
}
