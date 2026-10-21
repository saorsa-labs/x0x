//! Private admission adapter. Receipt I/O runs under the canonical install lock.
#![cfg(unix)]

use super::{fleet_policy, journal, probe, restart, staging, UpgradeError};
use std::{path::Path, time::Duration};

#[cfg(test)]
pub(crate) type Clock =
    std::sync::Arc<dyn Fn() -> std::io::Result<probe::ProbeClock> + Send + Sync>;
#[cfg(test)]
pub(crate) type Observer = std::sync::Arc<dyn Fn(staging::Decision) + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Gate {
    pub request: staging::StagingRequest,
    /// D185: bypass only the rollout delay, retaining every admission check.
    pub skip_staging_delay: bool,
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
    pub fn observe_locked_at(
        &self,
        install: &Path,
        clock: &probe::ProbeClock,
        identity: &restart::StagingIdentity,
    ) -> Result<staging::Decision, UpgradeError> {
        self.check_install(install)?;
        self.check_data_root(&identity.data_root)?;
        let policy =
            fleet_policy::effective_staging_window(self.request.window_minutes, install, identity)
                .map_err(|error| UpgradeError::Other(error.to_string()))?;
        self.observe_with_policy(install, clock, policy)
    }

    /// Read-only refusal checks before a retry can acknowledge its probe clock.
    /// The caller holds the canonical install lock. A pending rollout delay
    /// does not prevent inspecting the independent mandatory probe retry.
    pub fn check_retry_policy(
        &self,
        install: &Path,
        identity: &restart::StagingIdentity,
    ) -> Result<(), UpgradeError> {
        self.check_install(install)?;
        self.check_data_root(&identity.data_root)?;
        let policy =
            fleet_policy::effective_staging_window(self.request.window_minutes, install, identity)
                .map_err(|error| UpgradeError::Other(error.to_string()))?;
        self.checked_request(install, policy).map(|_| ())
    }

    /// Recheck refusal evidence under the separate probe-preflight lock using
    /// the actual captured restart plan. This does not acknowledge a receipt
    /// or require its delay to be due.
    pub fn check_apply_policy(
        &self,
        install: &Path,
        plan: &restart::RestartPlan,
    ) -> Result<(), UpgradeError> {
        self.checked_request(install, self.apply_policy(install, plan)?)
            .map(|_| ())
    }

    fn apply_policy(
        &self,
        install: &Path,
        plan: &restart::RestartPlan,
    ) -> Result<fleet_policy::WindowPolicy, UpgradeError> {
        self.check_install(install)?;
        self.check_data_root(&plan.data_root)?;
        fleet_policy::effective_window(self.request.window_minutes, install, plan)
            .map_err(|error| UpgradeError::Other(error.to_string()))
    }

    fn check_install(&self, install: &Path) -> Result<(), UpgradeError> {
        if std::fs::canonicalize(install).map_err(|error| UpgradeError::Other(error.to_string()))?
            != self.request.install
        {
            return Err(UpgradeError::Other("staging install changed".into()));
        }
        Ok(())
    }

    fn check_data_root(&self, data_root: &Path) -> Result<(), UpgradeError> {
        if std::fs::canonicalize(data_root)
            .map_err(|error| UpgradeError::Other(error.to_string()))?
            != self.request.data_root
        {
            return Err(UpgradeError::Other("staging data root changed".into()));
        }
        Ok(())
    }

    fn checked_request(
        &self,
        install: &Path,
        policy: fleet_policy::WindowPolicy,
    ) -> Result<staging::StagingRequest, UpgradeError> {
        let error = |error: std::io::Error| UpgradeError::Other(error.to_string());
        self.check_install(install)?;
        let mut request = self.request.clone();
        request.window_minutes = policy.window_minutes;
        // A stale waiter must refuse before any receipt or probe-state write.
        super::staging_selection::check_request(&request).map_err(error)?;
        // This read MUST precede observe: observing even a due receipt writes
        // an acknowledged clock tick. Preserve an older undersized receipt
        // byte-for-byte instead of resetting its first-receipt history.
        if let Some(receipt) = staging::read_receipt(&request).map_err(error)? {
            policy
                .check_receipt_window(receipt.window_minutes)
                .map_err(error)?;
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
        Ok(request)
    }

    fn observe_with_policy(
        &self,
        install: &Path,
        clock: &probe::ProbeClock,
        policy: fleet_policy::WindowPolicy,
    ) -> Result<staging::Decision, UpgradeError> {
        let error = |error: std::io::Error| UpgradeError::Other(error.to_string());
        let request = self.checked_request(install, policy)?;
        let retry = match probe::inspect_admission(install, &self.request.version)
            .map_err(|error| UpgradeError::Other(error.to_string()))?
        {
            probe::Admission::Ready => Duration::ZERO,
            probe::Admission::Waiting { retry_after } => retry_after,
        };
        let decision =
            super::staging_selection::observe_selected(&request, clock).map_err(error)?;
        let remaining = match decision {
            staging::Decision::Due => retry,
            staging::Decision::Waiting(_) if self.skip_staging_delay => retry,
            staging::Decision::Waiting(wait) => wait.max(retry),
        };
        Ok(if remaining.is_zero() {
            staging::Decision::Due
        } else {
            staging::Decision::Waiting(remaining)
        })
    }

    pub fn require_due(
        &self,
        install: &Path,
        plan: &restart::RestartPlan,
    ) -> Result<(), UpgradeError> {
        let policy = self.apply_policy(install, plan)?;
        let clock = self
            .clock()
            .map_err(|error| UpgradeError::Other(error.to_string()))?;
        match self.observe_with_policy(install, &clock, policy)? {
            staging::Decision::Due => Ok(()),
            staging::Decision::Waiting(wait) => Err(UpgradeError::Other(format!(
                "staging is not due; remaining {} seconds",
                wait.as_secs()
            ))),
        }
    }
}
