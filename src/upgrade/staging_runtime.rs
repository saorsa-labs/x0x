//! Private admission adapter. Receipt I/O runs under the canonical install lock.
#![cfg(unix)]

use super::{journal, probe, staging, UpgradeError};
use std::{path::Path, time::Duration};

#[cfg(test)]
pub(crate) type Clock =
    std::sync::Arc<dyn Fn() -> std::io::Result<probe::ProbeClock> + Send + Sync>;
#[cfg(test)]
pub(crate) type Observer = std::sync::Arc<dyn Fn(staging::Decision) + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Gate {
    pub request: staging::StagingRequest,
    #[cfg(test)]
    pub clock: Option<Clock>,
    #[cfg(test)]
    pub observed: Option<Observer>,
}

impl Gate {
    pub fn clock(&self) -> std::io::Result<probe::ProbeClock> {
        #[cfg(test)]
        if let Some(clock) = &self.clock {
            return clock();
        }
        probe::ProbeClock::now()
    }

    /// The caller holds the actual install lock; no lock is acquired here.
    pub fn observe_locked(&self, install: &Path) -> Result<staging::Decision, UpgradeError> {
        let clock = self
            .clock()
            .map_err(|error| UpgradeError::Other(error.to_string()))?;
        self.observe_locked_at(install, &clock)
    }

    pub fn observe_locked_at(
        &self,
        install: &Path,
        clock: &probe::ProbeClock,
    ) -> Result<staging::Decision, UpgradeError> {
        let error = |error: std::io::Error| UpgradeError::Other(error.to_string());
        if std::fs::canonicalize(install).map_err(error)? != self.request.install {
            return Err(UpgradeError::Other("staging install changed".into()));
        }
        if journal::read_boot_records(&self.request.data_root).blocks_apply() {
            return Err(UpgradeError::Other(
                "staging refused: unresolved upgrade records; records preserved".into(),
            ));
        }
        match super::pair::read_pair_record(install).map_err(error)? {
            None => {}
            Some(record) if record.phase == super::pair::PairPhase::Restored => {}
            Some(_) => {
                return Err(UpgradeError::Other(
                    "staging refused: unresolved pair record; records preserved".into(),
                ))
            }
        }
        let pending = super::pair::pair_pending_path(install).map_err(error)?;
        match journal::read_auxiliary_record(&pending) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(UpgradeError::Other(
                    "staging refused: unresolved pair intent".into(),
                ))
            }
        }
        let retry = match probe::inspect_admission(install, &self.request.version)
            .map_err(|error| UpgradeError::Other(error.to_string()))?
        {
            probe::Admission::Ready => Duration::ZERO,
            probe::Admission::Waiting { retry_after } => retry_after,
        };
        let decision = staging::observe(&self.request, clock).map_err(error)?;
        let remaining = match decision {
            staging::Decision::Due => retry,
            staging::Decision::Waiting(wait) => wait.max(retry),
        };
        Ok(if remaining.is_zero() {
            staging::Decision::Due
        } else {
            staging::Decision::Waiting(remaining)
        })
    }

    pub fn require_due(&self, install: &Path) -> Result<(), UpgradeError> {
        match self.observe_locked(install)? {
            staging::Decision::Due => Ok(()),
            staging::Decision::Waiting(wait) => Err(UpgradeError::Other(format!(
                "staging is not due; remaining {} seconds",
                wait.as_secs()
            ))),
        }
    }
}
