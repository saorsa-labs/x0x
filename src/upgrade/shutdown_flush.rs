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

/// Compiled default flush budget. The transient ruling of 23 Oct 2026
/// (ADR 0094 §4) sets the default at 30 s; `[update]
/// shutdown_flush_timeout_secs` configures it per daemon up to `MAX_LIMIT`.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);
/// Hard ceiling for a configured flush budget. The operator-facing floor
/// (1 s) is validated with the config; the registration clamp only refuses
/// a zero budget and this ceiling.
pub(crate) const MAX_LIMIT: Duration = Duration::from_secs(3600);
pub(crate) const RECORD: &str = "upgrade-flush.json";
pub(crate) const ROLLBACK_RECORD: &str = "upgrade-flush-rollback.json";
type Hook = Arc<dyn Fn(Deadline) -> io::Result<()> + Send + Sync>;

/// Why an `acknowledge` call failed, and whether this call had already
/// started the flush when it failed. A caller whose failure is `started`
/// has stopped the daemon behind the hook (no API, no network) and owns
/// the recovery: restore the previous binary and exit `EX_TEMPFAIL`
/// (engineer ruling 23 Oct 2026). A failure that is not `started` left
/// the daemon serving; it is an ordinary refusal.
#[derive(Debug)]
pub(crate) struct FlushFailure {
    pub(crate) error: io::Error,
    pub(crate) started: bool,
}

impl FlushFailure {
    #[cfg(test)]
    pub(crate) fn kind(&self) -> io::ErrorKind {
        self.error.kind()
    }
}

impl std::fmt::Display for FlushFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl From<io::Error> for FlushFailure {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            started: false,
        }
    }
}

/// The original transaction budget, including time spent suspended.
pub(crate) struct Deadline {
    pub(crate) instant: Instant,
    boot_id: String,
    deadline_ms: u64,
}
impl Deadline {
    pub(crate) fn check(&self) -> io::Result<()> {
        check_clock(&self.boot_id, self.deadline_ms, self.instant)
    }

    #[cfg(test)]
    pub(crate) fn for_test(limit: Duration) -> io::Result<Self> {
        let (boot_id, now) = clock()?;
        Ok(Self {
            instant: Instant::now() + limit,
            boot_id,
            deadline_ms: now.saturating_add(limit.as_millis() as u64),
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

// Default-budget registration and the explicit-budget acknowledge variant
// are the regression macros' seams; production always registers the
// configured budget and acknowledges with the entry's budget.
#[cfg(test)]
pub(crate) fn register(root: PathBuf, hook: Hook) -> io::Result<Registration> {
    register_with_limit(root, hook, LIMIT)
}

pub(crate) fn register_with_limit(
    root: PathBuf,
    hook: Hook,
    limit: Duration,
) -> io::Result<Registration> {
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
        limit: limit.max(Duration::from_millis(1)).min(MAX_LIMIT),
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
    hooks.insert(supplied_root, entry);
    drop(hooks);
    check_previous(&root)
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
pub(crate) fn clear_stale_records(root: &Path) {
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
    receive: &mpsc::Receiver<io::Result<Receipt>>,
    boot_id: &str,
    deadline_ms: u64,
    deadline: Instant,
) -> io::Result<Receipt> {
    loop {
        check_clock(boot_id, deadline_ms, deadline)?;
        match receive.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50)),
        ) {
            Ok(result) => {
                check_clock(boot_id, deadline_ms, deadline)?;
                return result;
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
    } else if entry.armed.swap(true, Ordering::AcqRel) {
        return Err(io::Error::other("shutdown flush already armed").into());
    }
    if entry.started.swap(true, Ordering::AcqRel) {
        return Err(io::Error::other("shutdown flush already started").into());
    }
    // Past this gate this call owns the started flush: every later failure,
    // including a deadline overrun, left the daemon stopped behind the hook.
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
    let spawn = std::thread::Builder::new()
        .name("x0x-upgrade-flush".into())
        .spawn(move || {
            let mut record = record;
            let outcome = (|| {
                check_deadline(&record, deadline)?;
                let path = root.join(RECORD);
                check_previous(&root)?;
                super::journal::write_auxiliary_record(&path, &record, validate)?;
                prepare()?;
                check_deadline(&record, deadline)?;
                hook(Deadline {
                    instant: deadline,
                    boot_id: record.boot_id.clone(),
                    deadline_ms: record.deadline_ms,
                })?;
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
            let _ = send.send(outcome);
        });
    let result = match spawn {
        Ok(worker) => {
            #[cfg(test)]
            entry.workers.lock().expect("flush workers").push(worker);
            #[cfg(not(test))]
            drop(worker);
            wait_receipt(&receive, &rollback_boot, rollback_deadline, deadline)
        }
        Err(error) => Err(error),
    };
    if let Err(error) = &result {
        let reason = error.to_string();
        // This separate marker cannot be overwritten by a late receipt worker.
        // The old process must remain alive; blocked I/O never permits exit.
        let rollback_worker = std::thread::Builder::new()
            .name("x0x-flush-rollback".into())
            .spawn(move || {
                let record = Record {
                    schema_version: 1,
                    record_kind: "shutdown_flush".into(),
                    binding: rollback_binding,
                    boot_id: rollback_boot,
                    deadline_ms: rollback_deadline,
                    receipt_id: None,
                    rollback_reason: Some(reason),
                };
                if let Err(error) = super::journal::write_auxiliary_record(
                    &rollback_root.join(ROLLBACK_RECORD),
                    &record,
                    validate,
                ) {
                    tracing::error!(%error, "failed to persist shutdown flush rollback request");
                }
            });
        #[cfg(test)]
        if let Ok(worker) = rollback_worker {
            entry.workers.lock().expect("flush workers").push(worker);
        }
        #[cfg(not(test))]
        if let Err(error) = rollback_worker {
            tracing::error!(%error, "failed to start shutdown flush rollback writer");
        }
    }
    result.map_err(|error| FlushFailure {
        error,
        started: true,
    })
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
    fn reservation_last_unused_owner_reopens_upgrade_and_shutdown_admission() {
        let dir = fixture();
        let root = dir.path().canonicalize().unwrap();
        let owner = register(root.clone(), Arc::new(|_| Ok(()))).unwrap();
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
        let owner = register(root.clone(), Arc::new(|_| Ok(()))).unwrap();
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
            Arc::new(move |_| {
                observed.store(true, Ordering::SeqCst);
                Err(io::Error::other(
                    "injected failure after acknowledgment started",
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
}
