//! A returned receipt permits the existing supervised restart request only.
//! Reading a file is not proof that its writer finished the durability barrier.
//! Launcher ownership, stop/reap and protected candidate start belong to S3b.

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, LazyLock, Mutex,
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed internal flush budget (engineer ruling, 23 Oct 2026): 30 s. Not
/// operator-configurable; only tests override it through the
/// `*_with_limit` seams. A follow-up issue proposes making it configurable.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);
pub(crate) const RECORD: &str = "upgrade-flush.json";
pub(crate) const ROLLBACK_RECORD: &str = "upgrade-flush-rollback.json";
pub(crate) const HOLD_RECORD: &str = "upgrade-flush-hold.json";
pub(crate) const RETRY_RECORD: &str = "upgrade-flush-producer-retries.json";
/// Refusal the shutdown tail reports when a producer (an HTTP request that
/// missed the drain bound, an aborted grace straggler, a shielded apply past
/// its bound) was still running at the drain bound. A started-flush failure
/// carrying exactly this cause is transient, so it draws the bounded retry
/// budget below instead of an immediate per-release hold (issue #1595,
/// Claude #1565 finding 4). The producer and the classifier share this
/// constant so the marker cannot drift.
pub(crate) const PRODUCERS_UNFINISHED: &str = "shutdown producers remain unfinished";
/// Fixed bounded retries for a started-flush failure caused only by
/// unfinished producers at the drain bound (issue #1595): one slow request
/// at upgrade time must not hold a release forever. After this many
/// producer-drain failures of one release, the per-release hold applies. A
/// constant, not configuration (same ruling as `LIMIT`).
pub(crate) const PRODUCER_DRAIN_RETRIES: u32 = 2;
/// Fixed bounded wait for the flush worker's completion message after a
/// started failure (issue #1595): the caller's `EX_TEMPFAIL` exit gives the
/// worker this long to finish its last durable write, then exits anyway —
/// a stalled worker must never park a daemon that already stopped. The
/// worker's completion send is its final statement, so receiving it proves
/// every write finished. A constant, not configuration.
pub(crate) const WORKER_JOIN_BOUND: Duration = Duration::from_secs(2);
/// Hard ceiling for a test-supplied flush budget; the registration clamp
/// only refuses a zero budget and this ceiling.
#[cfg(test)]
pub(crate) const MAX_LIMIT: Duration = Duration::from_secs(3600);
/// The hook calls `Deadline::commit_stop` as soon as the daemon is committed
/// to stopping behind it. Only that point and beyond count as a started
/// flush for recovery: earlier failures leave the daemon serving and are
/// ordinary refusals (engineer ruling, 23 Oct 2026).
type Hook = Arc<dyn Fn(Deadline, &AtomicBool) -> io::Result<()> + Send + Sync>;

/// Metadata preflight the flush owner registers with the roots its hook
/// walks: it names the first path the flush would refuse, so upgrade
/// admission can surface it before any byte changes (issue #1595).
pub(crate) type Preflight = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

/// Failures distinguish a request that never owned admission from an owned
/// refusal before stop and an owned failure after the stop commit point.
#[derive(Debug)]
pub(crate) enum FlushFailure {
    NotOwned(io::Error),
    Refused(io::Error),
    Started(io::Error),
}

impl FlushFailure {
    pub(crate) fn started(&self) -> bool {
        matches!(self, Self::Started(_))
    }

    fn error(&self) -> &io::Error {
        match self {
            Self::NotOwned(error) | Self::Refused(error) | Self::Started(error) => error,
        }
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> io::ErrorKind {
        self.error().kind()
    }

    fn owned(error: io::Error, started: bool) -> Self {
        if started {
            Self::Started(error)
        } else {
            Self::Refused(error)
        }
    }
}

impl std::fmt::Display for FlushFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error().fmt(formatter)
    }
}

impl From<io::Error> for FlushFailure {
    fn from(error: io::Error) -> Self {
        Self::NotOwned(error)
    }
}

/// The original transaction budget, including time spent suspended.
pub(crate) struct Deadline {
    pub(crate) instant: Instant,
    boot_id: String,
    deadline_ms: u64,
    cancelled: Arc<Mutex<bool>>,
}
impl Deadline {
    pub(crate) fn check(&self) -> io::Result<()> {
        check_clock(&self.boot_id, self.deadline_ms, self.instant)
    }

    /// Serialize the stop commit with timeout cancellation. Once the waiter
    /// classifies a refusal, even a hook paused after its deadline check cannot
    /// stop the daemon. The same lock protects the initial intent publication.
    pub(crate) fn commit_stop(&self, stopped: &AtomicBool) -> io::Result<()> {
        self.before_stop(|| {
            stopped.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn before_stop(&self, operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let cancelled = self
            .cancelled
            .lock()
            .map_err(|_| io::Error::other("flush cancellation poisoned"))?;
        if *cancelled {
            return Err(io::Error::other("shutdown flush cancelled before stop"));
        }
        self.check()?;
        operation()
    }

    #[cfg(test)]
    pub(crate) fn for_test(limit: Duration) -> io::Result<Self> {
        let (boot_id, now) = clock()?;
        Ok(Self {
            instant: Instant::now() + limit,
            boot_id,
            deadline_ms: now.saturating_add(limit.as_millis() as u64),
            cancelled: Arc::new(Mutex::new(false)),
        })
    }

    /// Ceiling for the metadata-only admission preflight (issue #1595): no
    /// fsync runs under it, so the generous bound only stops a walk that is
    /// not making progress. Built on the same suspend-inclusive clock the
    /// flush itself checks.
    pub(crate) fn preflight() -> io::Result<Self> {
        let limit = LIMIT.saturating_mul(4);
        let (boot_id, now) = clock()?;
        Ok(Self {
            instant: Instant::now() + limit,
            boot_id,
            deadline_ms: now.saturating_add(limit.as_millis() as u64),
            cancelled: Arc::new(Mutex::new(false)),
        })
    }
}
static HOOKS: LazyLock<Mutex<HashMap<PathBuf, Arc<Entry>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct Entry {
    root: PathBuf,
    hook: Hook,
    armed: AtomicBool,
    started: AtomicBool,
    shutdown_pending: AtomicBool,
    unused_released: tokio::sync::Notify,
    limit: Duration,
    /// The owner's metadata preflight over the roots the hook walks. `None`
    /// for owners that register no tree walk (tests, bare registrations).
    preflight: Option<Preflight>,
    #[cfg(test)]
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
}
pub(crate) struct Registration {
    entry: Arc<Entry>,
}

impl Registration {
    /// Close admission if normal shutdown won the race. A true result means
    /// a flush owner already armed and still owns the process lifetime.
    pub(crate) fn seal_admission(&self) -> bool {
        let mut hooks = HOOKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.entry.shutdown_pending.store(true, Ordering::Release);
        let armed = self.entry.armed.load(Ordering::Acquire);
        if !armed {
            hooks.retain(|_, entry| !Arc::ptr_eq(entry, &self.entry));
        }
        armed
    }

    /// Wake an ordinary shutdown that yielded to a replacement which never
    /// started acknowledgement. A started flush retains custody after failure.
    pub(crate) async fn wait_for_unused_release(&self) {
        loop {
            let released = self.entry.unused_released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if !self.entry.armed.load(Ordering::Acquire) {
                return;
            }
            released.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn join_workers(&self) {
        let workers = std::mem::take(&mut *self.entry.workers.lock().expect("flush workers"));
        for worker in workers {
            worker.join().expect("shutdown flush worker");
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // A timed-out worker retains its shutdown custody. Do not admit a new
        // operation or let a new registration conceal that unfinished work.
        self.seal_admission();
    }
}

// Production registers the fixed budget and its preflight. The plain,
// explicit-budget and acknowledge variants are the regression macros'
// test seams.
#[cfg(test)]
pub(crate) fn register(root: PathBuf, hook: Hook) -> io::Result<Registration> {
    register_inner(root, hook, LIMIT, None)
}

/// Register with the metadata preflight that admission runs before any
/// upgrade byte changes (issue #1595). The daemon's flush owner uses this
/// to refuse early — naming the offending path — on state its hook could
/// never walk.
pub(crate) fn register_with_preflight(
    root: PathBuf,
    hook: Hook,
    preflight: Preflight,
) -> io::Result<Registration> {
    register_inner(root, hook, LIMIT, Some(preflight))
}

#[cfg(test)]
pub(crate) fn register_with_limit(
    root: PathBuf,
    hook: Hook,
    limit: Duration,
) -> io::Result<Registration> {
    register_inner(root, hook, limit, None)
}

fn register_inner(
    root: PathBuf,
    hook: Hook,
    limit: Duration,
    preflight: Option<Preflight>,
) -> io::Result<Registration> {
    // The clamp bounds only test-supplied budgets; production passes LIMIT.
    #[cfg(test)]
    let limit = limit.max(Duration::from_millis(1)).min(MAX_LIMIT);
    let supplied_root = root.clone();
    let root = std::fs::canonicalize(root)?;
    let mut hooks = HOOKS
        .lock()
        .map_err(|_| io::Error::other("flush registry poisoned"))?;
    if hooks.contains_key(&root) || hooks.contains_key(&supplied_root) {
        return Err(io::Error::other("flush owner already registered"));
    }
    let entry = Arc::new(Entry {
        root: root.clone(),
        hook,
        armed: AtomicBool::new(false),
        started: AtomicBool::new(false),
        shutdown_pending: AtomicBool::new(false),
        unused_released: tokio::sync::Notify::new(),
        limit,
        preflight,
        #[cfg(test)]
        workers: Mutex::new(Vec::new()),
    });
    hooks.insert(root.clone(), Arc::clone(&entry));
    hooks.insert(supplied_root, Arc::clone(&entry));
    Ok(Registration { entry })
}

pub(crate) fn ensure_ready(root: &Path) -> io::Result<()> {
    let supplied_root = root.to_path_buf();
    let root = std::fs::canonicalize(root)?;
    let mut hooks = HOOKS
        .lock()
        .map_err(|_| io::Error::other("flush registry poisoned"))?;
    let entry = hooks
        .get(&root)
        .cloned()
        .ok_or_else(|| io::Error::other("acknowledged shutdown owner unavailable"))?;
    if entry.armed.load(Ordering::Acquire) {
        return Err(io::Error::other("shutdown flush already armed"));
    }
    if hooks
        .get(&supplied_root)
        .is_some_and(|prior| !Arc::ptr_eq(prior, &entry))
    {
        return Err(io::Error::other("shutdown flush data root changed"));
    }
    hooks.insert(supplied_root, Arc::clone(&entry));
    drop(hooks);
    check_previous(&root)?;
    // Admission preflight (issue #1595): an upgrade whose flush could never
    // walk the shutdown state must not change bytes first. The owner's scan
    // names the offending path — an operator's symlink is the known case —
    // so the refusal surfaces before the swap instead of as a started-flush
    // failure after the daemon already stopped.
    if let Some(preflight) = &entry.preflight {
        if let Err(error) = preflight() {
            tracing::error!(
                %error,
                "shutdown state cannot be flushed; the upgrade is refused before any \
                 byte changes; remove the offending path (or relocate the store it \
                 names) so a supervised upgrade can flush"
            );
            return Err(io::Error::other(format!(
                "shutdown state cannot be flushed: {error}"
            )));
        }
    }
    Ok(())
}

/// Carried by the admitted replacement worker and its restart continuation.
/// Before activation this token owns no shutdown action. Activation and normal
/// shutdown's admission seal use the same lock, before any installed byte changes.
#[derive(Clone)]
pub(crate) struct Reservation {
    state: Arc<ReservationState>,
}

struct ReservationState {
    entry: Arc<Entry>,
    active: AtomicBool,
}

impl ReservationState {
    fn release_unused(&self) {
        if !self.active.load(Ordering::Acquire) {
            return;
        }
        let mut hooks = HOOKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Only this reservation's successful activation may release admission.
        // Once acknowledge starts, its worker owns custody even after failure.
        if !self.entry.started.load(Ordering::Acquire) && self.active.swap(false, Ordering::AcqRel)
        {
            self.entry.armed.store(false, Ordering::Release);
            if self.entry.shutdown_pending.load(Ordering::Acquire) {
                // Shutdown already yielded to this reservation. Remove its
                // admission before waking that waiter, without a retry gap.
                hooks.retain(|_, entry| !Arc::ptr_eq(entry, &self.entry));
            }
            drop(hooks);
            self.entry.unused_released.notify_waiters();
        }
    }
}

impl Drop for ReservationState {
    fn drop(&mut self) {
        // Clones share one activation. A parked continuation retains it until
        // it starts acknowledge or the last owner abandons the operation.
        self.release_unused();
    }
}

pub(crate) fn reserve(root: &Path) -> io::Result<Reservation> {
    let hooks = HOOKS
        .lock()
        .map_err(|_| io::Error::other("flush registry poisoned"))?;
    let entry = hooks
        .get(root)
        .cloned()
        .ok_or_else(|| io::Error::other("acknowledged shutdown owner unavailable"))?;
    if entry.armed.load(Ordering::Acquire) {
        return Err(io::Error::other("shutdown flush already armed"));
    }
    Ok(Reservation {
        state: Arc::new(ReservationState {
            entry,
            active: AtomicBool::new(false),
        }),
    })
}

impl Reservation {
    pub(crate) fn release_unused(&self) {
        self.state.release_unused();
    }

    pub(crate) fn activate(&self) -> io::Result<()> {
        let hooks = HOOKS
            .lock()
            .map_err(|_| io::Error::other("flush registry poisoned"))?;
        if !hooks
            .get(&self.state.entry.root)
            .is_some_and(|entry| Arc::ptr_eq(entry, &self.state.entry))
        {
            return Err(io::Error::other("shutdown closed upgrade admission"));
        }
        if self.state.entry.armed.swap(true, Ordering::AcqRel) {
            return Err(io::Error::other("shutdown flush already armed"));
        }
        self.state.active.store(true, Ordering::Release);
        Ok(())
    }
}

fn check_previous(root: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(root.join(ROLLBACK_RECORD)) {
        Ok(_) => {
            return Err(io::Error::other(
                "previous shutdown flush requires recovery",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match super::journal::read_auxiliary_record(&root.join(RECORD)) {
        Ok(bytes) => {
            validate(&bytes)?;
            let prior: Record = serde_json::from_slice(&bytes)?;
            if prior.receipt_id.is_none() {
                return Err(io::Error::other("previous shutdown flush is unresolved"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Startup recovery (engineer ruling 23 Oct 2026): a receipt-less flush
/// record or a rollback marker whose owning process is gone is debris from a
/// failed or interrupted flush. The old owner held the instance data-root
/// lock for its whole flush and never released it while alive, so a daemon
/// running this cleanup after acquiring that lock proves the owner exited.
/// Clear the debris, log the recorded cause, and leave that upgrade failed;
/// a later apply starts fresh instead of being refused forever. A record
/// holding a receipt proves a completed flush and is preserved. The manual
/// fallback (stop the daemon, delete the files) is documented in
/// docs/upgrade-system.md.
///
/// A failed-upgrade hold ([`HOLD_RECORD`]) is never debris: it outlives this
/// cleanup so the held release is not applied again automatically (engineer
/// ruling, 23 Oct 2026).
pub(crate) fn clear_stale_records(root: &Path) {
    log_failed_release_hold(root);
    match std::fs::symlink_metadata(root.join(ROLLBACK_RECORD)) {
        Ok(_) => {
            let reason = super::journal::read_auxiliary_record(&root.join(ROLLBACK_RECORD))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok())
                .and_then(|record| record.rollback_reason);
            tracing::error!(
                reason = reason.as_deref().unwrap_or("unknown"),
                "previous shutdown flush failed; clearing its stale rollback record; \
                 that upgrade is treated as failed"
            );
            if let Err(error) = std::fs::remove_file(root.join(ROLLBACK_RECORD)) {
                tracing::error!(
                    %error,
                    "cannot remove the stale shutdown flush rollback record; \
                     supervised apply stays disabled until it is cleared manually"
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(%error, "cannot inspect the shutdown flush rollback record"),
    }
    match super::journal::read_auxiliary_record(&root.join(RECORD)) {
        Ok(bytes) => {
            let resolved = validate(&bytes)
                .ok()
                .and_then(|()| serde_json::from_slice::<Record>(&bytes).ok())
                .is_some_and(|record| record.receipt_id.is_some());
            if resolved {
                return;
            }
            tracing::error!(
                "previous shutdown flush never returned its receipt; clearing the stale \
                 record; that upgrade is treated as failed"
            );
            if let Err(error) = std::fs::remove_file(root.join(RECORD)) {
                tracing::error!(
                    %error,
                    "cannot remove the stale shutdown flush record; \
                     supervised apply stays disabled until it is cleared manually"
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(%error, "cannot inspect the shutdown flush record"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HoldRecord {
    pub(crate) schema_version: u32,
    pub(crate) record_kind: String,
    pub(crate) held_version: String,
    pub(crate) reason: String,
}

fn validate_hold(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("failed-upgrade hold exceeds size limit"));
    }
    let record: HoldRecord = serde_json::from_slice(bytes)?;
    if record.schema_version != 1
        || record.record_kind != "shutdown_flush_hold"
        || semver::Version::parse(&record.held_version).is_err()
        || record.reason.trim().is_empty()
    {
        return Err(io::Error::other("unknown failed-upgrade hold record"));
    }
    Ok(())
}

/// Persist the per-release failed-upgrade hold (engineer ruling, 23 Oct
/// 2026). A flush that started and failed exits `EX_TEMPFAIL`; without this
/// hold the startup check would re-apply the same release after every
/// restart, an endless exit loop ADR 0094 §4 forbids. The hold is separate
/// from the rollback record exactly because startup stale-record cleanup
/// must not erase it.
pub(crate) fn hold_failed_release(root: &Path, version: &str, reason: &str) -> io::Result<()> {
    let record = HoldRecord {
        schema_version: 1,
        record_kind: "shutdown_flush_hold".into(),
        held_version: version.to_string(),
        reason: reason.to_string(),
    };
    let path = root.join(HOLD_RECORD);
    super::journal::write_auxiliary_record(&path, &record, validate_hold)?;
    tracing::error!(
        held_release = %version,
        hold = %path.display(),
        reason,
        "failed-upgrade hold recorded: release {version} will not be applied again \
         automatically until a newer release appears or the operator removes \
        this hold file (stop the daemon first)"
    );
    Ok(())
}

/// The held release, if any. `Err` means a hold exists but cannot be
/// understood; callers must refuse to apply rather than guess.
pub(crate) fn failed_release_hold(root: &Path) -> io::Result<Option<HoldRecord>> {
    match super::journal::read_auxiliary_record(&root.join(HOLD_RECORD)) {
        Ok(bytes) => {
            validate_hold(&bytes)?;
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The release an apply of `target` must be refused for, if the hold says
/// so. The held release is refused (and so is anything older); a strictly
/// newer release passes, which is how a newer release clears the hold.
pub(crate) fn release_is_held(root: &Path, target: &semver::Version) -> io::Result<Option<String>> {
    let Some(hold) = failed_release_hold(root)? else {
        return Ok(None);
    };
    let held = semver::Version::parse(&hold.held_version)
        .map_err(|error| io::Error::other(format!("invalid held release: {error}")))?;
    if target <= &held {
        Ok(Some(hold.held_version))
    } else {
        Ok(None)
    }
}

/// True when a started-flush failure was caused only by unfinished
/// producers at the drain bound — the exact refusal `finish` reports
/// through the receipt channel. Every other cause (a refused symlink, a
/// stalled fsync, an overrun) keeps the immediate hold.
pub(crate) fn producers_unfinished(error: &io::Error) -> bool {
    error.to_string() == PRODUCERS_UNFINISHED
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetryRecord {
    schema_version: u32,
    record_kind: String,
    retried_version: String,
    failures: u32,
}

fn validate_retry(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other(
            "producer-drain retry record exceeds size limit",
        ));
    }
    let record: RetryRecord = serde_json::from_slice(bytes)?;
    if record.schema_version != 1
        || record.record_kind != "shutdown_flush_producer_retries"
        || semver::Version::parse(&record.retried_version).is_err()
        || record.failures == 0
    {
        return Err(io::Error::other("unknown producer-drain retry record"));
    }
    Ok(())
}

/// Count one more producer-drain failure of `version` and say whether the
/// per-release hold must apply (issue #1595). A failure of a different
/// release resets the count — a release that later applied never carries
/// another release's budget. The count persists across the `EX_TEMPFAIL`
/// restarts that retry the release; it is private durability state, not
/// configuration, and nothing but a producers-only failure reads it.
fn note_producer_drain_failure(root: &Path, version: &str) -> io::Result<bool> {
    let failures = match super::journal::read_auxiliary_record(&root.join(RETRY_RECORD)) {
        Ok(bytes) => {
            validate_retry(&bytes)?;
            let prior: RetryRecord = serde_json::from_slice(&bytes)?;
            if prior.retried_version == version {
                prior.failures.saturating_add(1)
            } else {
                1
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => 1,
        Err(error) => return Err(error),
    };
    let record = RetryRecord {
        schema_version: 1,
        record_kind: "shutdown_flush_producer_retries".into(),
        retried_version: version.to_string(),
        failures,
    };
    super::journal::write_auxiliary_record(&root.join(RETRY_RECORD), &record, validate_retry)?;
    Ok(failures > PRODUCER_DRAIN_RETRIES)
}

/// Apply the failure policy of a started-flush failure (issue #1595): a
/// failure caused only by unfinished producers at the drain bound draws
/// the bounded retry budget — the restart retries the release, no hold —
/// while every other cause, a spent budget, or a count that cannot be
/// persisted holds the release. Returns true when the hold was written.
/// `error` is the failure's cause; it is named in the hold record.
pub(crate) fn hold_or_retry_started_failure(
    root: &Path,
    version: &str,
    failure: &FlushFailure,
) -> bool {
    let error = failure.error();
    if producers_unfinished(error) {
        match note_producer_drain_failure(root, version) {
            Ok(false) => {
                tracing::warn!(
                    held_release = %version,
                    retries = PRODUCER_DRAIN_RETRIES,
                    "started flush failed only because producers missed the drain \
                     bound; the restart retries this release instead of holding it"
                );
                return false;
            }
            Ok(true) => {}
            Err(count_error) => {
                tracing::error!(
                    %count_error,
                    held_release = %version,
                    "cannot persist the producer-drain retry count; holding the release"
                );
            }
        }
    }
    if let Err(hold_error) = hold_failed_release(root, version, &error.to_string()) {
        tracing::error!(
            %hold_error,
            "cannot persist the failed-upgrade hold; the next automatic \
             check may retry this release once more"
        );
    }
    true
}

/// Announce an active hold at startup, loudly; never remove it here.
fn log_failed_release_hold(root: &Path) {
    match failed_release_hold(root) {
        Ok(Some(hold)) => tracing::error!(
            held_release = %hold.held_version,
            hold = %root.join(HOLD_RECORD).display(),
            reason = %hold.reason,
            "failed-upgrade hold is active: release {} will not be applied \
             automatically; remove the hold file (daemon stopped) to clear it",
            hold.held_version
        ),
        Ok(None) => {}
        Err(error) => tracing::error!(
            %error,
            hold = %root.join(HOLD_RECORD).display(),
            "failed-upgrade hold cannot be read; every automatic apply stays \
             refused until the hold file is removed (daemon stopped)"
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub transaction_id: String,
    pub generation: u64,
    pub plan_sha256: [u8; 32],
}

impl Binding {
    pub(crate) fn new(
        transaction_id: String,
        generation: u64,
        plan: &impl Serialize,
    ) -> io::Result<Self> {
        if transaction_id.trim().is_empty() {
            return Err(io::Error::other("flush transaction must be nonempty"));
        }
        Ok(Self {
            transaction_id,
            generation,
            plan_sha256: Sha256::digest(serde_json::to_vec(plan)?).into(),
        })
    }
}

/// Only `acknowledge` constructs this value, after every durable barrier.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Receipt {
    binding: Binding,
    receipt_id: String,
}

impl Receipt {
    pub(crate) fn authorize(&self, binding: &Binding) -> io::Result<()> {
        if &self.binding != binding {
            return Err(io::Error::other("flush receipt binding mismatch"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    record_kind: String,
    binding: Binding,
    boot_id: String,
    deadline_ms: u64,
    receipt_id: Option<String>,
    rollback_reason: Option<String>,
}

fn validate(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("shutdown flush record exceeds size limit"));
    }
    let record: Record = serde_json::from_slice(bytes)?;
    if record.schema_version != 1
        || record.record_kind != "shutdown_flush"
        || record.binding.transaction_id.trim().is_empty()
        || record.boot_id.is_empty()
    {
        return Err(io::Error::other("unknown shutdown flush record"));
    }
    if let Some(receipt) = &record.receipt_id {
        uuid::Uuid::parse_str(receipt).map_err(io::Error::other)?;
        if record.rollback_reason.is_some() {
            return Err(io::Error::other("rollback record cannot acknowledge flush"));
        }
    }
    Ok(())
}

fn clock() -> io::Result<(String, u64)> {
    #[cfg(unix)]
    {
        let clock = super::probe::ProbeClock::now()?;
        Ok((clock.boot_id, clock.monotonic_ms))
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "acknowledged upgrade flush needs a suspend-inclusive clock",
        ))
    }
}

fn check_deadline(record: &Record, deadline: Instant) -> io::Result<()> {
    check_clock(&record.boot_id, record.deadline_ms, deadline)
}

fn check_clock(boot_id: &str, deadline_ms: u64, deadline: Instant) -> io::Result<()> {
    let (boot, now) = clock()?;
    if Instant::now() >= deadline || boot != boot_id || now >= deadline_ms {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "shutdown flush exceeded its fixed deadline",
        ));
    }
    Ok(())
}

fn wait_receipt(
    receive: &mpsc::Receiver<(io::Result<Receipt>, bool)>,
    boot_id: &str,
    deadline_ms: u64,
    deadline: Instant,
) -> io::Result<(io::Result<Receipt>, bool)> {
    loop {
        check_clock(boot_id, deadline_ms, deadline)?;
        match receive.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50)),
        ) {
            Ok(reported) => {
                check_clock(boot_id, deadline_ms, deadline)?;
                return Ok(reported);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other(
                    "shutdown flush owner exited without acknowledgement",
                ));
            }
        }
    }
}

pub(crate) fn acknowledge(
    root: &Path,
    binding: Binding,
    prepare: impl FnOnce() -> io::Result<()> + Send + 'static,
) -> Result<Receipt, FlushFailure> {
    acknowledge_inner(root, binding, prepare, None, None)
}

#[cfg(test)]
pub(crate) fn acknowledge_with_limit(
    root: &Path,
    binding: Binding,
    prepare: impl FnOnce() -> io::Result<()> + Send + 'static,
    limit: Duration,
) -> Result<Receipt, FlushFailure> {
    acknowledge_inner(root, binding, prepare, Some(limit), None)
}

pub(crate) fn acknowledge_reserved(
    root: &Path,
    binding: Binding,
    prepare: impl FnOnce() -> io::Result<()> + Send + 'static,
    reservation: &Reservation,
) -> Result<Receipt, FlushFailure> {
    acknowledge_inner(root, binding, prepare, None, Some(reservation))
}

fn acknowledge_inner(
    root: &Path,
    binding: Binding,
    prepare: impl FnOnce() -> io::Result<()> + Send + 'static,
    limit: Option<Duration>,
    reservation: Option<&Reservation>,
) -> Result<Receipt, FlushFailure> {
    let hooks = HOOKS
        .lock()
        .map_err(|_| io::Error::other("flush registry poisoned"))?;
    let entry = hooks
        .get(root)
        .cloned()
        .ok_or_else(|| io::Error::other("acknowledged shutdown owner unavailable"))?;
    let limit = limit.unwrap_or(entry.limit).min(entry.limit);
    let deadline = Instant::now() + limit;
    let (boot_id, now) = clock()?;
    if let Some(reservation) = reservation {
        if !Arc::ptr_eq(&entry, &reservation.state.entry)
            || !reservation.state.active.load(Ordering::Acquire)
            || !entry.armed.load(Ordering::Acquire)
        {
            return Err(io::Error::other("shutdown reservation does not own admission").into());
        }
    } else if entry.armed.load(Ordering::Acquire) {
        return Err(io::Error::other("shutdown flush already armed").into());
    }
    if entry.started.load(Ordering::Acquire) {
        // A repeated reserved call does not own this acknowledgement. It
        // must not release the first caller's admission or clear its intent.
        return Err(io::Error::other("shutdown flush already started").into());
    }
    entry.armed.store(true, Ordering::Release);
    entry.started.store(true, Ordering::Release);
    // This call now owns acknowledgement. Only the hook's stop marker
    // distinguishes a pre-stop refusal from a started flush failure.
    drop(hooks);
    let root = entry.root.clone();
    let record = Record {
        schema_version: 1,
        record_kind: "shutdown_flush".into(),
        binding,
        boot_id,
        deadline_ms: now.saturating_add(limit.as_millis() as u64),
        receipt_id: None,
        rollback_reason: None,
    };
    let rollback_root = root.clone();
    let rollback_binding = record.binding.clone();
    let rollback_boot = record.boot_id.clone();
    let rollback_deadline = record.deadline_ms;
    let (send, receive) = mpsc::channel();
    let hook = Arc::clone(&entry.hook);
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = Arc::clone(&stopped);
    let cancelled = Arc::new(Mutex::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let spawn = std::thread::Builder::new()
        .name("x0x-upgrade-flush".into())
        .spawn(move || {
            let mut record = record;
            let stopped = worker_stopped;
            let hook_deadline = Deadline {
                instant: deadline,
                boot_id: record.boot_id.clone(),
                deadline_ms: record.deadline_ms,
                cancelled: worker_cancelled,
            };
            let outcome = (|| {
                check_deadline(&record, deadline)?;
                let path = root.join(RECORD);
                hook_deadline.before_stop(|| {
                    check_previous(&root)?;
                    super::journal::write_auxiliary_record(&path, &record, validate)
                })?;
                prepare()?;
                check_deadline(&record, deadline)?;
                hook(hook_deadline, &stopped)?;
                stopped.store(true, Ordering::Release);
                check_deadline(&record, deadline)?;
                let receipt_id = uuid::Uuid::new_v4().to_string();
                record.receipt_id = Some(receipt_id.clone());
                super::journal::write_auxiliary_record(&path, &record, validate)?;
                check_deadline(&record, deadline)?;
                Ok(Receipt {
                    binding: record.binding.clone(),
                    receipt_id,
                })
            })();
            let started = stopped.load(Ordering::Acquire);
            let _ = send.send((outcome, started));
        });
    let result: Result<Receipt, FlushFailure> = match spawn {
        Ok(worker) => {
            #[cfg(test)]
            entry.workers.lock().expect("flush workers").push(worker);
            #[cfg(not(test))]
            drop(worker);
            match wait_receipt(&receive, &rollback_boot, rollback_deadline, deadline) {
                Ok((Ok(receipt), _)) => Ok(receipt),
                Ok((Err(error), started)) => Err(FlushFailure::owned(error, started)),
                Err(error) => {
                    // Cancel under the same lock used to publish intent and
                    // commit the stop. Cleanup cannot run ahead of a late
                    // intent write, and a late hook cannot stop after refusal.
                    let mut cancelled = cancelled
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *cancelled = true;
                    Err(FlushFailure::owned(error, stopped.load(Ordering::Acquire)))
                }
            }
        }
        // The worker never ran, so the hook never stopped the daemon.
        Err(error) => Err(FlushFailure::Refused(error)),
    };
    if let Err(failure) = &result {
        if failure.started() {
            // Only a failure that stopped the daemon writes the rollback
            // mark: it is written on this calling thread so the caller's
            // immediate `EX_TEMPFAIL` exit cannot lose it. A refusal writes
            // no rollback mark; the daemon keeps serving.
            let record = Record {
                schema_version: 1,
                record_kind: "shutdown_flush".into(),
                binding: rollback_binding,
                boot_id: rollback_boot,
                deadline_ms: rollback_deadline,
                receipt_id: None,
                rollback_reason: Some(failure.error().to_string()),
            };
            if let Err(error) = super::journal::write_auxiliary_record(
                &rollback_root.join(ROLLBACK_RECORD),
                &record,
                validate,
            ) {
                tracing::error!(%error, "failed to persist shutdown flush rollback request");
            }
            // Bounded join of the flush worker (issue #1595): its completion
            // message is the worker's final statement, so receiving it proves
            // every durable write it started has finished before the caller's
            // exit. Wait a short fixed window — never longer — then continue
            // anyway; a stalled worker must not park the stopped daemon. An
            // already-finished worker answers instantly, so only a genuinely
            // stuck hook pays the bound.
            if matches!(
                receive.recv_timeout(WORKER_JOIN_BOUND),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                tracing::warn!(
                    wait = ?WORKER_JOIN_BOUND,
                    "shutdown flush worker did not report completion; \
                     the EX_TEMPFAIL exit continues without it"
                );
            }
        } else {
            // Engineer ruling, 24 Oct 2026: a flush refused before the daemon
            // stops is not a failed start. Give the started marker back so
            // this reservation's unused release can re-open admission,
            // remove this call's own receipt-less intent so a later
            // supervised apply is not refused by it, and — for a call that
            // armed the entry itself — disarm admission here, because no
            // reservation exists to release it later.
            entry.started.store(false, Ordering::Release);
            clear_refused_intent(&rollback_root, &rollback_binding);
            if reservation.is_none() {
                disarm_refused_admission(&entry);
            }
        }
    }
    result
}

/// Remove the receipt-less flush record this refused call wrote. The daemon
/// never stopped behind the hook, so the record is not recovery state; left
/// in place it would refuse every later supervised apply until the next
/// restart. A record of another transaction, or one that carries a receipt,
/// is not ours to remove and stays for the startup cleanup.
fn clear_refused_intent(root: &Path, binding: &Binding) {
    let path = root.join(RECORD);
    let own_intent = super::journal::read_auxiliary_record(&path)
        .ok()
        .filter(|bytes| validate(bytes).is_ok())
        .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok())
        .is_some_and(|record| record.receipt_id.is_none() && record.binding == *binding);
    if own_intent {
        if let Err(error) = std::fs::remove_file(&path) {
            tracing::error!(
                %error,
                "cannot remove the refused flush intent record; supervised apply \
                 stays refused until the next restart clears it"
            );
        }
    }
}

/// Release a refused unreserved call's armed admission and wake an ordinary
/// shutdown that yielded to it (engineer ruling, 24 Oct 2026). Mirrors
/// `ReservationState::release_unused` without a reservation: the refusal
/// never stopped the daemon, so nothing keeps shutdown parked.
fn disarm_refused_admission(entry: &Arc<Entry>) {
    let mut hooks = HOOKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    entry.armed.store(false, Ordering::Release);
    if entry.shutdown_pending.load(Ordering::Acquire) {
        // Shutdown already yielded to this flush. Remove its admission
        // before waking that waiter, without a retry gap.
        hooks.retain(|_, other| !Arc::ptr_eq(other, entry));
    }
    drop(hooks);
    entry.unused_released.notify_waiters();
}

#[cfg(test)]
include!("../../tests/upgrade_flush_receipt.rs");
#[cfg(test)]
flush_receipt_regression_tests!();

#[cfg(all(test, unix))]
mod reservation_release_regressions {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let root = std::env::var_os("X0X_UPGRADE_FLUSH_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/upgrade-flush-fixtures")
            });
        std::fs::create_dir_all(&root).unwrap();
        tempfile::Builder::new()
            .prefix("reservation-")
            .tempdir_in(root)
            .unwrap()
    }

    #[test]
    fn reservation_timeout_cancels_a_hook_paused_before_stop() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let did_stop = Arc::new(AtomicBool::new(false));
        let observed = did_stop.clone();
        let owner = register_with_limit(
            root.clone(),
            Arc::new(move |deadline, stopped| {
                deadline.check()?;
                entered.send(()).unwrap();
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                // The original check succeeded, but the waiter has since refused.
                // This is the production stop commit, not a test-only marker.
                deadline.commit_stop(stopped)?;
                observed.store(true, Ordering::Release);
                Ok(())
            }),
            Duration::from_millis(250),
        )
        .unwrap();
        let worker_root = root.clone();
        let caller = std::thread::spawn(move || {
            acknowledge(
                &worker_root,
                Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap(),
                || Ok(()),
            )
        });
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let result = caller.join().unwrap();
        release.send(()).unwrap();
        owner.join_workers();
        assert!(matches!(result, Err(FlushFailure::Refused(_))));
        assert!(
            !did_stop.load(Ordering::Acquire),
            "a timed-out refusal must not stop later"
        );
        assert!(!root.join(RECORD).exists());
        assert!(!root.join(ROLLBACK_RECORD).exists());
        ensure_ready(&root).unwrap();
        reserve(&root).unwrap().activate().unwrap();
    }

    #[test]
    fn reservation_cancelled_worker_cannot_publish_late_intent() {
        let dir = fixture();
        let deadline = Deadline::for_test(Duration::from_secs(5)).unwrap();
        // The waiter cancelled while the worker was descheduled before its
        // initial write. Use a future clock deadline to isolate cancellation.
        *deadline.cancelled.lock().unwrap() = true;
        let path = dir.path().join(RECORD);
        assert!(deadline
            .before_stop(|| std::fs::write(&path, b"late intent"))
            .is_err());
        assert!(!path.exists());
        let stopped = AtomicBool::new(false);
        assert!(deadline.commit_stop(&stopped).is_err());
        assert!(!stopped.load(Ordering::Acquire));
    }

    #[test]
    fn reservation_last_unused_owner_reopens_upgrade_and_shutdown_admission() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
        let reservation = reserve(&root).unwrap();
        reservation.activate().unwrap();
        let continuation = reservation.clone();
        drop(reservation);
        assert!(
            owner.entry.armed.load(Ordering::Acquire),
            "the continuation still owns admission"
        );
        assert!(ensure_ready(&root).is_err());
        // A non-success/no-op result does not invoke the continuation. Its last
        // unused token must release admission, including an unused NoUpgrade path.
        drop(continuation);
        ensure_ready(&root).unwrap();
        assert!(
            !owner.seal_admission(),
            "ordinary shutdown must not wait forever"
        );
    }

    #[test]
    fn reservation_failed_competing_activation_does_not_disarm_the_winner() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
        let winner = reserve(&root).unwrap();
        let loser = reserve(&root).unwrap();
        winner.activate().unwrap();
        assert!(loser.activate().is_err());
        drop(loser);
        assert!(
            owner.seal_admission(),
            "losing activation cannot release the winner"
        );
        assert!(ensure_ready(&root).is_err());
        assert!(reserve(&root).is_err());
        drop(winner);
    }

    #[test]
    fn reservation_started_acknowledgment_retains_shutdown_custody() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        let owner = register(
            root.clone(),
            Arc::new(move |_, stopped| {
                observed.store(true, Ordering::SeqCst);
                stopped.store(true, Ordering::Release);
                Err(io::Error::other(
                    "injected failure after the daemon stopped",
                ))
            }),
        )
        .unwrap();
        let reservation = reserve(&root).unwrap();
        reservation.activate().unwrap();
        let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
        assert!(acknowledge_reserved(&root, binding, || Ok(()), &reservation).is_err());
        owner.join_workers();
        assert!(called.load(Ordering::SeqCst));
        assert!(owner.entry.started.load(Ordering::Acquire));
        drop(reservation);
        assert!(
            owner.seal_admission(),
            "started acknowledgment keeps recovery custody"
        );
        assert!(ensure_ready(&root).is_err());
        assert!(root.join("upgrade-flush-rollback.json").is_file());
    }

    /// Engineer ruling, 24 Oct 2026: a flush the worker refused before the
    /// daemon stopped (prepare failure or a pre-stop hook failure) is not a
    /// failed start. Its unused reservation must release admission so a
    /// later supervised apply can run; the started marker and the refused
    /// attempt's receipt-less intent must not survive it.
    #[test]
    fn refused_acknowledgment_releases_admission_for_the_next_apply() {
        for refusal in [Refusal::Prepare, Refusal::Hook] {
            let dir = fixture();
            let root = dir.path().canonicalize().unwrap();
            let owner = register(
                root.clone(),
                Arc::new(move |_, _| {
                    Err(io::Error::other(match refusal {
                        Refusal::Prepare => "unreachable: prepare refuses first",
                        Refusal::Hook => "injected pre-stop hook refusal",
                    }))
                }),
            )
            .unwrap();
            let reservation = reserve(&root).unwrap();
            reservation.activate().unwrap();
            let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
            let prepare = move || {
                matches!(refusal, Refusal::Prepare)
                    .then(|| Err(io::Error::other("injected handoff intent write refusal")))
                    .unwrap_or(Ok(()))
            };
            let failure = match acknowledge_reserved(&root, binding.clone(), prepare, &reservation)
            {
                Err(failure) => failure,
                Ok(_) => panic!("{refusal:?} must refuse the flush"),
            };
            assert!(!failure.started(), "{refusal:?} never stopped the daemon");
            owner.join_workers();
            assert!(
                !owner.entry.started.load(Ordering::Acquire),
                "a refusal is not a failed start"
            );
            drop(reservation);
            // A second supervised apply is accepted, and the refused
            // attempt's receipt-less intent no longer refuses it.
            assert!(
                !root.join(RECORD).exists(),
                "the refused attempt clears its own intent record"
            );
            ensure_ready(&root).unwrap();
            reserve(&root).unwrap();
            assert!(
                !owner.seal_admission(),
                "an ordinary shutdown after a refusal must not wait"
            );
        }
    }

    #[test]
    fn reserved_duplicate_acknowledgment_does_not_disarm_or_clear_intent() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
        let reservation = reserve(&root).unwrap();
        reservation.activate().unwrap();
        let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
        acknowledge_reserved(&root, binding.clone(), || Ok(()), &reservation).unwrap();
        owner.join_workers();
        let record = std::fs::read(root.join(RECORD)).unwrap();
        let failure = acknowledge_reserved(
            &root,
            binding,
            || panic!("duplicate cannot prepare"),
            &reservation,
        )
        .unwrap_err();
        assert!(matches!(failure, FlushFailure::NotOwned(_)));
        assert!(owner.entry.armed.load(Ordering::Acquire));
        assert!(owner.entry.started.load(Ordering::Acquire));
        assert_eq!(std::fs::read(root.join(RECORD)).unwrap(), record);
        drop(reservation);
        assert!(owner.seal_admission());
    }

    #[test]
    fn wrong_reservation_does_not_disarm_the_active_owner() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
        let winner = reserve(&root).unwrap();
        let inactive = reserve(&root).unwrap();
        winner.activate().unwrap();
        let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
        let failure =
            acknowledge_reserved(&root, binding.clone(), || panic!("not admitted"), &inactive)
                .unwrap_err();
        assert!(matches!(failure, FlushFailure::NotOwned(_)));
        drop(inactive);
        assert!(owner.entry.armed.load(Ordering::Acquire));
        acknowledge_reserved(&root, binding, || Ok(()), &winner).unwrap();
        owner.join_workers();
    }

    #[derive(Clone, Copy, Debug)]
    enum Refusal {
        Prepare,
        Hook,
    }

    /// Issue #1595: a producers-only drain failure draws the fixed bounded
    /// retry budget before the per-release hold; every other started
    /// failure, and a count that cannot be persisted, holds immediately.
    #[test]
    fn producer_drain_failures_retry_then_hold_and_reset_per_release() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        for attempt in 1..=(PRODUCER_DRAIN_RETRIES + 1) {
            let held = hold_or_retry_started_failure(
                &root,
                "2.0.0",
                &FlushFailure::Started(io::Error::other(PRODUCERS_UNFINISHED)),
            );
            assert_eq!(
                held,
                attempt > PRODUCER_DRAIN_RETRIES,
                "attempt {attempt} of the release"
            );
        }
        assert_eq!(
            release_is_held(&root, &semver::Version::new(2, 0, 0))
                .unwrap()
                .as_deref(),
            Some("2.0.0")
        );
        assert!(release_is_held(&root, &semver::Version::new(2, 0, 1))
            .unwrap()
            .is_none());
        // A different release resets the budget on a fresh root: neither a
        // first failure nor a failure of a new release writes a hold.
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        assert!(!hold_or_retry_started_failure(
            &root,
            "2.0.0",
            &FlushFailure::Started(io::Error::other(PRODUCERS_UNFINISHED))
        ));
        assert!(!hold_or_retry_started_failure(
            &root,
            "3.0.0",
            &FlushFailure::Started(io::Error::other(PRODUCERS_UNFINISHED))
        ));
        assert!(failed_release_hold(&root).unwrap().is_none());
        // A non-producers cause never touches the budget.
        let held = hold_or_retry_started_failure(
            &root,
            "2.0.0",
            &FlushFailure::Started(io::Error::other(
                "unverified symlink in shutdown state: /x/store/link",
            )),
        );
        assert!(held);
        assert!(failed_release_hold(&root).unwrap().is_some());
        // An unreadable retry record is treated as spent: the release is
        // held rather than retried without a count.
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join(RETRY_RECORD), b"not a record").unwrap();
        let held = hold_or_retry_started_failure(
            &root,
            "2.0.0",
            &FlushFailure::Started(io::Error::other(PRODUCERS_UNFINISHED)),
        );
        assert!(held, "an unparsable count must hold, not retry forever");
    }

    /// Issue #1595: after a started failure the caller's EX_TEMPFAIL exit
    /// waits one short fixed window for the worker's completion message,
    /// then continues — a stuck worker must not park the stopped daemon,
    /// and a finished worker must not pay the window at all.
    #[test]
    fn started_failure_waits_one_bounded_window_for_a_stuck_worker() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let owner = register_with_limit(
            root.clone(),
            Arc::new(move |deadline, stopped| {
                deadline.commit_stop(stopped)?;
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30))
                    .map_err(io::Error::other)
            }),
            Duration::from_millis(200),
        )
        .unwrap();
        let worker_root = root.clone();
        let started = Instant::now();
        let caller = std::thread::spawn(move || {
            acknowledge(
                &worker_root,
                Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap(),
                || Ok(()),
            )
        });
        let result = caller.join().unwrap();
        let elapsed = started.elapsed();
        release.send(()).unwrap();
        owner.join_workers();
        assert!(matches!(result, Err(FlushFailure::Started(_))));
        assert!(
            elapsed >= WORKER_JOIN_BOUND,
            "the caller did not wait for the worker's completion: {elapsed:?}"
        );
        assert!(
            elapsed < WORKER_JOIN_BOUND + Duration::from_secs(3),
            "the wait was not bounded: {elapsed:?}"
        );
        assert!(root.join(ROLLBACK_RECORD).is_file());
    }

    #[test]
    fn started_failure_with_a_finished_worker_does_not_wait() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let owner = register(
            root.clone(),
            Arc::new(|deadline, stopped| {
                deadline.commit_stop(stopped)?;
                Err(io::Error::other("injected started flush failure"))
            }),
        )
        .unwrap();
        let started = Instant::now();
        let result = acknowledge(
            &root,
            Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap(),
            || Ok(()),
        );
        let elapsed = started.elapsed();
        owner.join_workers();
        assert!(matches!(result, Err(FlushFailure::Started(_))));
        assert!(
            elapsed < WORKER_JOIN_BOUND,
            "a finished worker must not delay the exit: {elapsed:?}"
        );
    }
}
