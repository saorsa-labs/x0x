//! Process-local retry ownership. Durable probe state remains authoritative.

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use tokio::sync::{watch, Mutex};

#[derive(Clone, Debug)]
pub(crate) struct RetryWait {
    pub delay: Duration,
    pub transaction_id: String,
}

type RetryKey = (PathBuf, String);

fn owners() -> &'static StdMutex<HashSet<RetryKey>> {
    static OWNERS: OnceLock<StdMutex<HashSet<RetryKey>>> = OnceLock::new();
    OWNERS.get_or_init(|| StdMutex::new(HashSet::new()))
}

pub(crate) struct RetryOwner(RetryKey);

impl Drop for RetryOwner {
    fn drop(&mut self) {
        if let Ok(mut active) = owners().lock() {
            active.remove(&self.0);
        }
    }
}

/// The supplied install path is independently resolved by the running process.
/// A poisoned ownership map refuses a new waiter; it never permits duplicates.
pub(crate) fn claim_retry(install: PathBuf, version: String) -> Option<RetryOwner> {
    let key = (install, version);
    let mut active = owners().lock().ok()?;
    active.insert(key.clone()).then(|| RetryOwner(key))
}

/// Wait without the apply mutex, then take a fresh staging/probe attempt.
///
/// Every iteration rereads durable state. A stage failure before a new probe
/// transaction does not consume the old expired wait in a tight retry loop.
/// The unchanged transaction returns the last error and leaves later normal
/// update discovery in charge.
pub(crate) async fn run_retry_loop<T, E, Check, CheckFuture, Apply, ApplyFuture>(
    apply_lock: &Arc<Mutex<()>>,
    shutdown: &mut watch::Receiver<bool>,
    mut check: Check,
    mut apply: Apply,
) -> Result<Option<T>, E>
where
    Check: FnMut() -> CheckFuture,
    CheckFuture: Future<Output = Result<Option<RetryWait>, E>>,
    Apply: FnMut() -> ApplyFuture,
    ApplyFuture: Future<Output = Result<T, E>>,
{
    let mut previous_transaction = None;
    let mut last_error = None;
    loop {
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return Ok(None);
        }
        let pending = tokio::select! {
            result = check() => result?,
            _ = shutdown.changed() => return Ok(None),
        };
        let Some(wait) = pending else {
            return last_error.map_or(Ok(None), Err);
        };
        if previous_transaction.as_ref() == Some(&wait.transaction_id) {
            return last_error.map_or(Ok(None), Err);
        }
        // Durable deadlines include host suspend; Tokio's timer may not.
        // Reread periodically so resume or a superseding release cannot leave
        // an obsolete timer asleep for another complete backoff period.
        let poll_interval = Duration::from_secs(30);
        tokio::select! {
            _ = tokio::time::sleep(wait.delay.min(poll_interval)) => {}
            _ = shutdown.changed() => return Ok(None),
        }
        if wait.delay > poll_interval {
            continue;
        }
        let guard = tokio::select! {
            guard = apply_lock.lock() => guard,
            _ = shutdown.changed() => return Ok(None),
        };
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return Ok(None);
        }
        previous_transaction = Some(wait.transaction_id);
        let result = tokio::select! {
            result = apply() => Some(result),
            _ = shutdown.changed() => None,
        };
        drop(guard);
        match result {
            Some(Ok(value)) => return Ok(Some(value)),
            Some(Err(error)) => last_error = Some(error),
            None => return Ok(None),
        }
    }
}
