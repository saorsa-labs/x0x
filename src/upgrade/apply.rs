//! Binary upgrade application: download, verify SHA-256, extract, and atomically
//! replace the running binary with rollback on failure.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use sha2::{Digest, Sha256};

use super::manifest::{current_platform_target, ReleaseManifest};
use super::restart;
use super::signature::{verify_bytes_signature_with_key, RELEASE_SIGNING_KEY};
use super::{UpgradeError, UpgradeResult, Upgrader};

/// Delay before the HTTP-owned deferred restart so the apply response can flush.
/// Shared with the historical route helper's 750 ms window (#261 / #1447 RC4).
pub(crate) const HTTP_DEFERRED_RESTART_DELAY: std::time::Duration =
    std::time::Duration::from_millis(750);

/// The probe runs with the existing install locks held, before admission.
type ProbeAdmission = Box<dyn FnOnce(&AtomicBool) -> Result<(), UpgradeError> + Send>;

#[cfg(unix)]
async fn inspect_probe_admission(
    install: PathBuf,
    version: String,
    staging: Option<(super::staging_runtime::Gate, restart::RestartPlan)>,
    permit: Option<&ReleasePermit>,
) -> Result<super::probe::Admission, UpgradeError> {
    run_owned_blocking_with_permit(permit, move |alive| {
        let _lock = super::acquire_host_upgrade_lock(&install)?;
        if !alive.load(Ordering::Acquire) {
            return Err(cancelled_release());
        }
        if let Some((gate, plan)) = staging {
            ensure_canonical_install(&install)?;
            gate.check_apply_policy(&install, &plan)?;
        }
        if !alive.load(Ordering::Acquire) {
            return Err(cancelled_release());
        }
        super::probe::inspect_admission(&install, &version)
            .map_err(|error| UpgradeError::Other(error.to_string()))
    })
    .await
}

#[cfg(all(test, unix))]
async fn probe_retry_delay_for_install(
    install: PathBuf,
    version: String,
) -> Result<Option<super::probe_retry::RetryWait>, UpgradeError> {
    probe_retry_delay_owned(install, version, None).await
}

#[cfg(unix)]
async fn probe_retry_delay_owned(
    install: PathBuf,
    version: String,
    permit: Option<&ReleasePermit>,
) -> Result<Option<super::probe_retry::RetryWait>, UpgradeError> {
    run_owned_blocking_with_permit(permit, move |alive| {
        let _lock = super::acquire_host_upgrade_lock(&install)?;
        if !alive.load(Ordering::Acquire) {
            return Err(cancelled_release());
        }
        probe_retry_state_under_lock(&install, &version)
    })
    .await
}

/// The caller holds the install lock and has completed any staging refusal
/// checks. Inspection can acknowledge durable interrupted-wait clock progress.
#[cfg(unix)]
fn probe_retry_state_under_lock(
    install: &Path,
    version: &str,
) -> Result<Option<super::probe_retry::RetryWait>, UpgradeError> {
    let admission = super::probe::inspect_admission(install, version)
        .map_err(|error| UpgradeError::Other(error.to_string()))?;
    // An expired durable InterruptedWait is an immediate retry, not absence.
    let state = super::probe::read_state(install)
        .map_err(|error| UpgradeError::Other(error.to_string()))?;
    Ok(state
        .filter(|state| {
            state.version == version && state.phase == super::probe::ProbePhase::InterruptedWait
        })
        .map(|state| super::probe_retry::RetryWait {
            delay: match admission {
                super::probe::Admission::Ready => std::time::Duration::ZERO,
                super::probe::Admission::Waiting { retry_after } => retry_after,
            },
            transaction_id: state.transaction_id,
        }))
}

/// Recheck the carried canonical identity after waiting for its lock. Record
/// readers must not follow a changed path while holding the previous lock.
#[cfg(unix)]
fn ensure_canonical_install(install: &Path) -> Result<(), UpgradeError> {
    if std::fs::canonicalize(install)
        .map_err(|error| UpgradeError::Other(format!("staging install unavailable: {error}")))?
        != install
    {
        return Err(UpgradeError::Other("staging install changed".into()));
    }
    Ok(())
}

/// Arm the HTTP deferred-restart owner before any host mutation (#1447 RC5).
///
/// Spawns a parked OS thread first. On `Builder::spawn` failure, returns `Err`
/// so the caller can refuse the apply before backup/replace. On success, the
/// returned closure releases that single owner at admission (`send`); if the
/// apply fails or is cancelled before admission, dropping the sender makes the
/// parked thread exit without restarting.
fn arm_http_deferred_restart_owner(
    binary_name: String,
    stop_on_upgrade: bool,
    restart_context: RestartContext,
    restart_plan: restart::RestartPlan,
    version: String,
) -> Result<Box<dyn FnOnce() + Send>, std::io::Error> {
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    #[cfg(test)]
    let test_restart = http_deferred_restart_seam::capture(&restart_plan.executable);
    spawn_http_deferred_restart_thread(move || match go_rx.recv() {
        Ok(()) => {
            std::thread::sleep(HTTP_DEFERRED_RESTART_DELAY);
            #[cfg(test)]
            if let Some(restart) = test_restart {
                restart(&restart_plan, &version);
                return;
            }
            let owner = AutoApplyUpgrader::new(&binary_name)
                .with_stop_on_upgrade(stop_on_upgrade)
                .with_restart_context(restart_context)
                .with_restart_on_success(false);
            if let Err(e) = owner.trigger_restart(&restart_plan, &version) {
                warn!(
                    error = %e,
                    installed_bytes = true,
                    restart = "not_started",
                    readiness_observed = false,
                    "Deferred HTTP restart after successful upgrade did not start: {e}; \
                     old process keeps serving"
                );
            }
        }
        Err(_) => {
            // Pre-admission cancel / apply failure: sender dropped; no restart.
        }
    })?;
    Ok(Box::new(move || {
        if go_tx.send(()).is_err() {
            warn!(
                installed_bytes = true,
                restart = "not_started",
                "HTTP deferred-restart owner gone before admission signal"
            );
        }
    }))
}

/// Replace only the final external restart in the real armed HTTP owner.
#[cfg(test)]
pub(crate) mod http_deferred_restart_seam {
    use super::restart::RestartPlan;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, LazyLock, Mutex};

    pub(crate) type Hook = Arc<dyn Fn(&RestartPlan, &str) + Send + Sync>;
    static INSTALLED: LazyLock<Mutex<HashMap<PathBuf, Hook>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    pub(crate) struct Guard(PathBuf);

    impl Drop for Guard {
        fn drop(&mut self) {
            INSTALLED
                .lock()
                .expect("HTTP restart hook lock")
                .remove(&self.0);
        }
    }

    pub(crate) fn install(target: PathBuf, hook: Hook) -> Guard {
        assert!(INSTALLED
            .lock()
            .expect("HTTP restart hook lock")
            .insert(target.clone(), hook)
            .is_none());
        Guard(target)
    }

    pub(super) fn capture(target: &Path) -> Option<Hook> {
        INSTALLED
            .lock()
            .expect("HTTP restart hook lock")
            .get(target)
            .cloned()
    }
}

/// Spawn the parked HTTP deferred-restart thread (test seam can force failure).
fn spawn_http_deferred_restart_thread<F>(f: F) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    #[cfg(test)]
    if deferred_spawn_seam::should_fail() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "injected HTTP deferred-spawn failure",
        ));
    }
    std::thread::Builder::new()
        .name("x0x-http-deferred-restart".to_string())
        .spawn(f)
}

/// cfg(test) only: force `spawn_http_deferred_restart_thread` to return
/// `WouldBlock` so RC5 can prove refuse-before-mutation (and prove the RC4
/// post-admission pattern loses the only owner).
///
/// Thread-local so parallel libtest workers cannot steal each other's inject
/// (process-global AtomicBool raced under `--test-threads=8`).
#[cfg(test)]
pub(crate) mod deferred_spawn_seam {
    use std::cell::Cell;

    thread_local! {
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) struct Guard {
        _private: (),
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL.with(|f| f.set(false));
        }
    }

    pub(crate) fn force_would_block() -> Guard {
        FAIL.with(|f| f.set(true));
        Guard { _private: () }
    }

    pub(crate) fn should_fail() -> bool {
        FAIL.with(|f| f.get())
    }
}

/// Removes an upgrade temp dir when dropped, so it is never leaked on an
/// early-return error path (e.g. a failed binary replace on Windows, which
/// otherwise left a ~50 MB archive + extracted binary behind on every attempt).
///
/// The success path explicitly removes the temp dir *before* triggering the
/// restart, because the restart may `_exit` without unwinding, so this guard
/// would not otherwise run there.
struct TempDirGuard {
    path: PathBuf,
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => debug!(
                path = %self.path.display(),
                error = %e,
                "Failed to remove upgrade temp dir on cleanup"
            ),
        }
    }
}

/// Awaits a `spawn_blocking` replace job while tying caller liveness to Drop.
///
/// Aborting/dropping the async caller clears `caller_alive` before the
/// `JoinHandle` is dropped, so the blocking worker can refuse mutation **before
/// admission** (after it acquires host locks, before any backup/replace).
/// Once the worker admits, restart ownership lives with the worker's
/// `on_success` continuation — not with this droppable observer.
/// `spawn_blocking` itself is not cancelled by Drop.
struct CallerAliveJoin<T> {
    caller_alive: Arc<AtomicBool>,
    join: JoinHandle<Result<T, UpgradeError>>,
    _permit: Option<PermitOperation>,
}

impl<T> Future for CallerAliveJoin<T> {
    type Output = Result<Result<T, UpgradeError>, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.join).poll(cx)
    }
}

impl<T> Drop for CallerAliveJoin<T> {
    fn drop(&mut self) {
        // Signal first: the JoinHandle drop does not stop the blocking worker.
        self.caller_alive.store(false, Ordering::Release);
    }
}

/// A background release may withdraw admission without dropping its queued
/// worker. Each operation keeps its own caller flag; completing one operation
/// must not cancel the next observation of the same release.
#[derive(Clone, Default)]
pub(crate) struct ReleasePermit {
    state: Arc<std::sync::Mutex<PermitState>>,
    wake: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    pub observer: Option<Arc<dyn Fn(bool) + Send + Sync>>,
}

#[derive(Default)]
struct PermitState {
    cancelled: bool,
    operation: Option<std::sync::Weak<AtomicBool>>,
    http_wait_slot: Option<Arc<tokio::sync::OwnedMutexGuard<()>>>,
}

impl ReleasePermit {
    pub(crate) fn for_http(slot: Arc<tokio::sync::OwnedMutexGuard<()>>) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(PermitState {
                http_wait_slot: Some(slot),
                ..PermitState::default()
            })),
            ..Self::default()
        }
    }

    fn http_wait_slot(&self) -> Option<Arc<tokio::sync::OwnedMutexGuard<()>>> {
        self.state.lock().ok()?.http_wait_slot.clone()
    }

    pub(crate) fn release_http_wait_slot(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .http_wait_slot = None;
    }

    pub(crate) fn check(&self) -> Result<(), UpgradeError> {
        let state = self.state.lock().map_err(|_| cancelled_release())?;
        if state.cancelled {
            Err(cancelled_release())
        } else {
            Ok(())
        }
    }

    pub(crate) fn cancel(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cancelled = true;
        if let Some(flag) = state.operation.as_ref().and_then(std::sync::Weak::upgrade) {
            flag.store(false, Ordering::Release);
        }
        drop(state);
        self.wake.notify_waiters();
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.check().is_err() {
                return;
            }
            notified.await;
        }
    }

    fn register(&self, flag: &Arc<AtomicBool>) -> Result<PermitOperation, UpgradeError> {
        let mut state = self.state.lock().map_err(|_| cancelled_release())?;
        if state.cancelled
            || state
                .operation
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_some()
        {
            return Err(cancelled_release());
        }
        state.operation = Some(Arc::downgrade(flag));
        Ok(PermitOperation {
            permit: self.clone(),
            flag: Arc::clone(flag),
        })
    }
}

fn cancelled_release() -> UpgradeError {
    UpgradeError::Other("background release admission cancelled".into())
}

struct PermitOperation {
    permit: ReleasePermit,
    flag: Arc<AtomicBool>,
}

impl Drop for PermitOperation {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
        if let Ok(mut state) = self.permit.state.lock() {
            if state
                .operation
                .as_ref()
                .is_some_and(|flag| flag.ptr_eq(&Arc::downgrade(&self.flag)))
            {
                state.operation = None;
            }
        }
    }
}

#[cfg(test)]
struct OperationObservation(Option<Arc<dyn Fn(bool) + Send + Sync>>);
#[cfg(test)]
impl Drop for OperationObservation {
    fn drop(&mut self) {
        if let Some(observer) = &self.0 {
            observer(false);
        }
    }
}

/// Retain a blocking operation's cancellation flag until its observer returns.
/// The operation must check the flag at its own mutation admission boundary.
pub(crate) async fn run_owned_blocking_with_permit<T, F>(
    permit: Option<&ReleasePermit>,
    operation: F,
) -> Result<T, UpgradeError>
where
    T: Send + 'static,
    F: FnOnce(Arc<AtomicBool>) -> Result<T, UpgradeError> + Send + 'static,
{
    let caller_alive = Arc::new(AtomicBool::new(true));
    let registration = permit
        .map(|permit| permit.register(&caller_alive))
        .transpose()?;
    let worker_alive = Arc::clone(&caller_alive);
    let http_wait_slot = permit.and_then(ReleasePermit::http_wait_slot);
    #[cfg(test)]
    let observer = permit.and_then(|permit| permit.observer.clone());
    let join = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let _observation = {
            if let Some(observer) = &observer {
                observer(true);
            }
            OperationObservation(observer)
        };
        // A cancelled HTTP caller cannot free its bounded request slot while
        // this operation remains queued on the install lock.
        let _http_wait_slot = http_wait_slot;
        operation(worker_alive)
    });
    CallerAliveJoin {
        caller_alive,
        join,
        _permit: registration,
    }
    .await
    .map_err(|error| UpgradeError::Other(format!("upgrade worker failed: {error}")))?
}

/// Companion + primary replace on the blocking pool.
///
/// Both production callsites (daemon target and optional companion CLI) take
/// an exclusive host lock via blocking `File::lock`. Running that critical
/// section here keeps Tokio workers free while another process holds the lock
/// (T-self-update-host-backup-guard / #1447 RC1).
///
/// `temp_guard` moves into the blocking task so a cancelled async caller cannot
/// remove the temp directory while compare/backup/replace still needs the
/// extracted binaries. Cleanup happens when the blocking task finishes.
///
/// All host locks are taken before any mutation. If the async caller is
/// cancelled while the worker waits on a lock, the worker releases the locks
/// without replacing bytes (#1447 RC2).
///
/// Once every lock is held and the caller is still alive, replacement is
/// **admitted**: `on_success` (restart / handoff continuation) is owned by
/// this blocking worker for the rest of the critical section. Cancelling the
/// async observer after admission cannot detach installed bytes from that
/// continuation (#1447 RC3). Extra pre-rename boolean checks only move the
/// window; ownership transfer at admission closes it.
#[cfg(test)]
async fn apply_replacements_offloaded(
    upgrader: Upgrader,
    extracted_path: PathBuf,
    target_version: semver::Version,
    companion: Option<(Upgrader, PathBuf)>,
    temp_guard: TempDirGuard,
    on_success: Option<Box<dyn FnOnce() + Send>>,
    probe_admission: Option<ProbeAdmission>,
) -> Result<UpgradeResult, UpgradeError> {
    apply_replacements_with_permit(
        upgrader,
        extracted_path,
        target_version,
        companion,
        temp_guard,
        on_success,
        probe_admission,
        None,
    )
    .await
}

// Keep the existing replacement inputs together with its admission custody.
#[allow(clippy::too_many_arguments)]
async fn apply_replacements_with_permit(
    upgrader: Upgrader,
    extracted_path: PathBuf,
    target_version: semver::Version,
    companion: Option<(Upgrader, PathBuf)>,
    temp_guard: TempDirGuard,
    mut on_success: Option<Box<dyn FnOnce() + Send>>,
    probe_admission: Option<ProbeAdmission>,
    permit: Option<&ReleasePermit>,
) -> Result<UpgradeResult, UpgradeError> {
    let caller_alive = Arc::new(AtomicBool::new(true));
    let registration = permit
        .map(|permit| permit.register(&caller_alive))
        .transpose()?;
    let worker_alive = Arc::clone(&caller_alive);
    let http_wait_slot = permit.and_then(ReleasePermit::http_wait_slot);
    #[cfg(test)]
    let observer = permit.and_then(|permit| permit.observer.clone());

    let join = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let _observation = {
            if let Some(observer) = &observer {
                observer(true);
            }
            OperationObservation(observer)
        };
        let _http_wait_slot = http_wait_slot;
        // Custody stays with this task through every replace. Dropped
        // explicitly before any on_success continuation that may exit without
        // unwinding (#1447 RC4 P2).
        let mut temp_custody = Some(temp_guard);

        upgrader.validate_upgrade(&target_version)?;

        // Companion validate / lock / replace failures stay warn-and-skip (same
        // as the pre-RC2 perform_upgrade match); they must not refuse the
        // daemon replace.
        let mut companion = companion.and_then(|(x0x_upgrader, extracted_x0x)| match x0x_upgrader
            .validate_upgrade(&target_version)
        {
            Ok(()) => Some((x0x_upgrader, extracted_x0x)),
            Err(e) => {
                warn!("Failed to upgrade x0x companion: {e}");
                None
            }
        });

        // Take every host lock before any backup/replace. Nested perform_upgrade
        // locks would deadlock; finish_* assumes the caller already holds them.
        let _companion_lock = if let Some((ref x0x_upgrader, _)) = companion {
            #[cfg(test)]
            tests::acknowledge_host_lock_attempt(x0x_upgrader.target_path());
            match super::acquire_host_upgrade_lock(x0x_upgrader.target_path()) {
                Ok(lock) => Some(lock),
                Err(e) => {
                    warn!("Failed to upgrade x0x companion: {e}");
                    companion = None;
                    None
                }
            }
        } else {
            None
        };
        if !worker_alive.load(Ordering::Acquire) {
            return Err(UpgradeError::Other(
                "upgrade cancelled before host replace".to_string(),
            ));
        }

        #[cfg(test)]
        tests::acknowledge_host_lock_attempt(upgrader.target_path());
        let _daemon_lock = super::acquire_host_upgrade_lock(upgrader.target_path())?;
        if !worker_alive.load(Ordering::Acquire) {
            return Err(UpgradeError::Other(
                "upgrade cancelled before host replace".to_string(),
            ));
        }

        if let Some(probe) = probe_admission {
            probe(&worker_alive)?;
        }
        if !worker_alive.load(Ordering::Acquire) {
            return Err(UpgradeError::Other(
                "upgrade cancelled during candidate probes".to_string(),
            ));
        }

        // Admission: locks held + caller still alive. From here the worker
        // owns mutation through on_success — the async caller is only an
        // observer and may be cancelled without orphaning restart.
        if let Some((x0x_upgrader, extracted_x0x)) = companion {
            match x0x_upgrader.finish_upgrade_under_host_lock(&extracted_x0x, &target_version) {
                Ok(_) => info!("x0x companion upgraded successfully"),
                Err(e) => warn!("Failed to upgrade x0x companion: {e}"),
            }
        }

        let result = upgrader.finish_upgrade_under_host_lock(&extracted_path, &target_version)?;
        if matches!(result, UpgradeResult::Success { .. }) {
            if let Some(cont) = on_success.take() {
                // Clean temp before a continuation that may `_exit` / `exit`
                // without running Drop (#1447 RC4 P2).
                drop(temp_custody.take());
                cont();
            }
        }
        Ok(result)
    });

    CallerAliveJoin {
        caller_alive,
        join,
        _permit: registration,
    }
    .await
    .map_err(|join_err| UpgradeError::Other(format!("upgrade replace task failed: {join_err}")))?
}

/// Context the restart planner needs from the running daemon: where the
/// handoff file lives, which API address the replacement must serve, and how
/// to trigger a bounded graceful shutdown before the old process exits.
///
/// `Default` (no data dir, no address, no shutdown hook) is only useful for
/// tests and non-daemon callers — every daemon apply path supplies all three.
#[derive(Clone, Default)]
pub struct RestartContext {
    /// Daemon data directory (`upgrade-handoff.json` / `UPGRADE_FAILED`).
    pub data_dir: Option<PathBuf>,
    /// Pre-upgrade API address the replacement must serve `/health` on.
    pub api_addr: Option<std::net::SocketAddr>,
    /// Triggers the daemon's graceful shutdown (cancellation). Called inside
    /// the handoff's 5s bounded cancel window.
    pub shutdown: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

/// Auto-apply upgrader that handles the full download → verify → extract → replace → restart flow.
pub struct AutoApplyUpgrader {
    /// Which binary to extract from the archive (e.g. "x0xd", "x0x").
    binary_name: String,
    /// Exit cleanly for service manager restart instead of spawning new process.
    stop_on_upgrade: bool,
    /// Whether a successful apply should immediately restart/exec.
    restart_on_success: bool,
    /// HTTP apply only: arm the ~750 ms deferred restart at admission inside
    /// `apply.rs` (crate-internal). Not inferred from [`RestartContext`].
    http_deferred_restart: bool,
    /// Data directory / API address / shutdown hook for the restart planner.
    restart_context: RestartContext,
    #[cfg(unix)]
    staging: Option<super::staging_runtime::Gate>,
    release_permit: Option<ReleasePermit>,
}

impl AutoApplyUpgrader {
    pub fn new(binary_name: &str) -> Self {
        Self {
            binary_name: binary_name.to_string(),
            stop_on_upgrade: false,
            restart_on_success: true,
            http_deferred_restart: false,
            restart_context: RestartContext::default(),
            #[cfg(unix)]
            staging: None,
            release_permit: None,
        }
    }

    pub(crate) fn with_release_permit(mut self, permit: ReleasePermit) -> Self {
        self.release_permit = Some(permit);
        self
    }

    fn check_release(&self) -> Result<(), UpgradeError> {
        self.release_permit
            .as_ref()
            .map_or(Ok(()), ReleasePermit::check)
    }

    pub(crate) async fn release_cancelled(&self) {
        match &self.release_permit {
            Some(permit) => permit.cancelled().await,
            None => std::future::pending().await,
        }
    }

    pub fn with_stop_on_upgrade(mut self, stop: bool) -> Self {
        self.stop_on_upgrade = stop;
        self
    }

    /// Select the staged install from the independent executable observation,
    /// not from the receipt. Carry this path through locks, plan and mutation.
    /// Legacy unstaged callers and Windows retain their existing raw-path flow.
    fn install_path(&self) -> Result<PathBuf, UpgradeError> {
        let observed = current_binary_path()?;
        #[cfg(unix)]
        if let Some(gate) = &self.staging {
            let install = std::fs::canonicalize(&observed).map_err(|error| {
                UpgradeError::Other(format!("staging install unavailable: {error}"))
            })?;
            if install != gate.request.install {
                return Err(UpgradeError::Other("staging install changed".into()));
            }
            return Ok(install);
        }
        Ok(observed)
    }

    /// Capture actual guide policy evidence after download. The writer must
    /// hold the returned install lock through a fresh observe_locked_at check
    /// requiring Due and the rename; this snapshot alone authorizes no write.
    #[cfg(unix)]
    pub(crate) async fn guide_staging(
        &self,
    ) -> Result<
        Option<(
            PathBuf,
            super::staging_runtime::Gate,
            restart::StagingIdentity,
        )>,
        UpgradeError,
    > {
        let Some(gate) = &self.staging else {
            return Ok(None);
        };
        self.check_release()?;
        let install = self.install_path()?;
        let identity = restart::resolve_staging_identity(
            self.stop_on_upgrade,
            &install,
            self.restart_context.data_dir.as_deref(),
            self.restart_context.api_addr,
            self.release_permit
                .as_ref()
                .and_then(ReleasePermit::http_wait_slot),
        )
        .await
        .map_err(UpgradeError::from)?;
        // Drain the actual identity readback before observing cancellation.
        self.check_release()?;
        let mut gate = gate.clone();
        // The HTTP wait override is not authority to change the guide.
        gate.skip_staging_delay = false;
        Ok(Some((install, gate, identity)))
    }

    #[cfg(unix)]
    pub(crate) fn with_staging_request(mut self, request: super::staging::StagingRequest) -> Self {
        self.staging = Some(super::staging_runtime::Gate {
            request,
            skip_staging_delay: false,
            #[cfg(test)]
            clock: None,
            #[cfg(test)]
            observed: None,
        });
        self
    }

    /// Authenticated D185 override: keep the receipt and mandatory probe wait.
    #[cfg(unix)]
    pub(crate) fn with_staging_now(mut self, now: bool) -> Self {
        if let Some(gate) = &mut self.staging {
            gate.skip_staging_delay = now;
        }
        self
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_staging_clock(
        mut self,
        clock: Option<super::staging_runtime::Clock>,
    ) -> Self {
        if let Some(gate) = &mut self.staging {
            gate.clock = clock;
        }
        self
    }

    /// The existing owned caller retains the wait. No apply mutex or OS lock
    /// remains held across sleep, and cancellation never resets the receipt.
    #[cfg(unix)]
    pub(crate) async fn wait_for_staging(
        &self,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), UpgradeError> {
        let Some(gate) = &self.staging else {
            return Ok(());
        };
        let install = self.install_path()?;
        loop {
            self.check_release()?;
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return Err(UpgradeError::Other("staging cancelled by shutdown".into()));
            }
            // Resolve actual service identity before the first receipt. A
            // pending restart rate window does not erase a verified fleet
            // binding, but it still refuses the later full apply plan.
            let identity = tokio::select! {
                biased;
                _ = shutdown.changed() => return Err(UpgradeError::Other("staging cancelled by shutdown".into())),
                result = restart::resolve_staging_identity(
                    self.stop_on_upgrade, &install,
                    self.restart_context.data_dir.as_deref(), self.restart_context.api_addr,
                    self.release_permit.as_ref().and_then(ReleasePermit::http_wait_slot),
                ) => result.map_err(UpgradeError::from)?,
            };
            self.check_release()?;
            let gate = gate.clone();
            let install = install.clone();
            let worker_shutdown = shutdown.clone();
            let worker =
                run_owned_blocking_with_permit(self.release_permit.as_ref(), move |worker_alive| {
                    let _lock = super::acquire_host_upgrade_lock(&install)?;
                    // A queued blocking task outlives a dropped JoinHandle. Recheck
                    // custody after obtaining the lock and before any record I/O.
                    let shutdown_value = worker_shutdown.borrow();
                    if !worker_alive.load(Ordering::Acquire)
                        || *shutdown_value
                        || worker_shutdown.has_changed().is_err()
                    {
                        return Err(UpgradeError::Other("staging cancelled by shutdown".into()));
                    }
                    // Measure receipt time after lock acquisition: time spent
                    // queued for that lock must not count as durable rollout wait.
                    let clock = gate
                        .clock()
                        .map_err(|error| UpgradeError::Other(error.to_string()))?;
                    gate.observe_locked_at(&install, &clock, &identity)
                });
            let decision = tokio::select! {
                biased;
                _ = shutdown.changed() => return Err(UpgradeError::Other("staging cancelled by shutdown".into())),
                result = worker => result?,
            };
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return Err(UpgradeError::Other("staging cancelled by shutdown".into()));
            }
            #[cfg(test)]
            if let Some(observed) = self
                .staging
                .as_ref()
                .and_then(|gate| gate.observed.as_ref())
            {
                observed(decision.clone());
            }
            self.check_release()?;
            let super::staging::Decision::Waiting(wait) = decision else {
                return Ok(());
            };
            tokio::select! {
                _ = tokio::time::sleep(wait.min(std::time::Duration::from_secs(30))) => {}
                _ = self.release_cancelled() => return Err(cancelled_release()),
                _ = shutdown.changed() => {
                    return Err(UpgradeError::Other("staging cancelled by shutdown".into()));
                }
            }
        }
    }

    /// Supply the daemon-side restart context (data dir, pre-upgrade API
    /// address, graceful-shutdown hook) used by the transactional handoff.
    pub fn with_restart_context(mut self, context: RestartContext) -> Self {
        self.restart_context = context;
        self
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_staging_observer(
        mut self,
        observed: Option<super::staging_runtime::Observer>,
    ) -> Self {
        if let Some(gate) = &mut self.staging {
            gate.observed = observed;
        }
        self
    }

    /// Configure whether a successful apply should immediately restart/exec.
    ///
    /// HTTP handlers should set this to `false`, return their response, then
    /// restart asynchronously so clients can observe the apply result.
    pub fn with_restart_on_success(mut self, restart: bool) -> Self {
        self.restart_on_success = restart;
        self
    }

    /// Crate-internal HTTP opt-in: after admission, `apply.rs` owns one deferred
    /// restart (~750 ms + shared planner) on a non-Tokio thread so cancel of
    /// the HTTP task (or runtime shutdown of async tasks) cannot leave
    /// installed bytes without a restart owner. Does not change public
    /// [`Self::with_restart_on_success`] behaviour: callers with both flags
    /// false do not restart. The read-only `x0xd --check-updates` path never
    /// enters this installer.
    pub(crate) fn with_http_deferred_restart(mut self, enable: bool) -> Self {
        self.http_deferred_restart = enable;
        self
    }

    pub(crate) fn for_probe_retry(&self) -> Self {
        Self {
            binary_name: self.binary_name.clone(),
            stop_on_upgrade: self.stop_on_upgrade,
            restart_on_success: self.restart_on_success,
            http_deferred_restart: self.http_deferred_restart,
            restart_context: self.restart_context.clone(),
            #[cfg(unix)]
            staging: self.staging.clone(),
            release_permit: self.release_permit.clone(),
        }
    }

    /// Read the durable retry state on the blocking pool under the install lock.
    /// Failed holds and ambiguous records never produce a retry timer.
    pub(crate) async fn probe_retry_delay(
        &self,
        version: &str,
    ) -> Result<Option<super::probe_retry::RetryWait>, UpgradeError> {
        #[cfg(unix)]
        {
            let install = self.install_path()?;
            let version = version.to_owned();
            self.check_release()?;
            if let Some(gate) = &self.staging {
                if gate.request.version != version {
                    return Err(UpgradeError::Other("staging retry release changed".into()));
                }
                let identity = restart::resolve_staging_identity(
                    self.stop_on_upgrade,
                    &install,
                    self.restart_context.data_dir.as_deref(),
                    self.restart_context.api_addr,
                    self.release_permit
                        .as_ref()
                        .and_then(ReleasePermit::http_wait_slot),
                )
                .await
                .map_err(UpgradeError::from)?;
                self.check_release()?;
                let gate = gate.clone();
                run_owned_blocking_with_permit(self.release_permit.as_ref(), move |caller_alive| {
                    let _lock = super::acquire_host_upgrade_lock(&install)?;
                    let check_custody = || {
                        if caller_alive.load(Ordering::Acquire) {
                            Ok(())
                        } else {
                            Err(UpgradeError::Other(
                                "staging retry cancelled before record I/O".into(),
                            ))
                        }
                    };
                    check_custody()?;
                    ensure_canonical_install(&install)?;
                    gate.check_retry_policy(&install, &identity)?;
                    check_custody()?;
                    probe_retry_state_under_lock(&install, &version)
                })
                .await
            } else {
                probe_retry_delay_owned(install, version, self.release_permit.as_ref()).await
            }
        }
        #[cfg(not(unix))]
        {
            let _ = version;
            Ok(None)
        }
    }

    /// Restart the current binary using the planned restart mode.
    ///
    /// Unsupervised (the default for a terminal-launched daemon) this runs the
    /// transactional handoff and never returns. Supervised it exits for the
    /// supervisor and never returns. Returns `Err` when the restart contract
    /// cannot be resolved (ADR-0061 §1/§2) or when the handoff could not even
    /// be started (helper spawn failure) — the old process keeps running in
    /// both cases.
    pub async fn restart_current_binary(&self, target_version: &str) -> Result<(), UpgradeError> {
        let target_path = self.install_path()?;
        let plan = self.resolve_restart_plan(&target_path).await?;
        self.trigger_restart(&plan, target_version)
    }

    /// Classify the restart mode for the current environment (I0).
    pub fn restart_mode(&self) -> Result<restart::RestartMode, restart::RestartOwnershipError> {
        self.restart_mode_with(&restart::SupervisionSignals::sample())
    }

    /// Classification with injected signals — the single planner every apply
    /// caller routes through (startup check, gossip, fallback poll, HTTP).
    pub fn restart_mode_with(
        &self,
        signals: &restart::SupervisionSignals,
    ) -> Result<restart::RestartMode, restart::RestartOwnershipError> {
        restart::plan_restart_mode(self.stop_on_upgrade, signals)
    }

    /// Resolve and validate this instance's restart contract (ADR-0061 §1).
    ///
    /// Every apply path calls this **before** replacing any binary, so a
    /// conflicting or unresolvable contract fails while the current image is
    /// still serving and the installed bytes are untouched.
    ///
    /// Async because the launchd readback shells out (#671): the
    /// plutil/launchctl subprocesses run via
    /// [`restart::readback_launchd_policy_offloaded`] on the blocking pool so
    /// a slow `launchctl` cannot stall the runtime worker mid-upgrade. The
    /// readback is a no-op unless the recognized signal is the launchd
    /// marker, so systemd and unsupervised applies shell out to nothing.
    pub async fn resolve_restart_plan(
        &self,
        binary_path: &Path,
    ) -> Result<restart::RestartPlan, UpgradeError> {
        let signals = restart::SupervisionSignals::sample();
        let launchd_readback = restart::readback_launchd_policy_retaining(
            &signals,
            binary_path,
            &restart::current_argv(),
            self.release_permit
                .as_ref()
                .and_then(ReleasePermit::http_wait_slot),
        )
        .await;
        // #690: the systemd-side twin — no-op (NotApplicable) unless a
        // systemd signal classified this instance, so macOS and unsupervised
        // applies shell out to nothing.
        let systemd_readback = restart::readback_systemd_policy_retaining(
            &signals,
            binary_path,
            &restart::current_argv(),
            self.release_permit
                .as_ref()
                .and_then(ReleasePermit::http_wait_slot),
        )
        .await;
        restart::resolve_restart_plan(
            self.stop_on_upgrade,
            &signals,
            binary_path,
            self.restart_context.data_dir.as_deref(),
            self.restart_context.api_addr,
            &launchd_readback,
            &systemd_readback,
        )
        .map_err(UpgradeError::from)
    }

    /// Apply an upgrade from a `ReleaseManifest`.
    ///
    /// 1. Find the platform-appropriate asset
    /// 2. Download archive
    /// 3. Verify SHA-256 hash against manifest (integrity)
    /// 4. Download and verify ML-DSA-65 signature on archive (authenticity)
    /// 5. Extract binary from archive
    /// 6. Replace current binary with backup/rollback
    /// 7. Optionally trigger restart
    pub async fn apply_upgrade_from_manifest(
        &self,
        manifest: &ReleaseManifest,
    ) -> Result<UpgradeResult, UpgradeError> {
        self.check_release()?;
        let current_version_str = crate::VERSION;
        let target_version = semver::Version::parse(&manifest.version)
            .map_err(|e| UpgradeError::Other(format!("invalid version: {e}")))?;
        let current_version = semver::Version::parse(current_version_str)
            .map_err(|e| UpgradeError::Other(format!("invalid current version: {e}")))?;

        info!(
            current_version = %current_version,
            target_version = %target_version,
            "Starting auto-apply upgrade from {} to {}",
            current_version,
            target_version
        );

        // Find platform asset
        let platform_target = current_platform_target().ok_or(UpgradeError::UnsupportedPlatform)?;

        let asset = manifest
            .matches_platform(platform_target)
            .ok_or(UpgradeError::NoPlatformAsset)?;

        let target_path = self.install_path()?;

        // ADR-0061 §1 — resolve before mutation. The restart owner, intended
        // exit behaviour, executable/argv and effective roots are resolved and
        // validated here, before a single byte of either the daemon or the
        // companion binary changes. A conflicting or unresolvable contract
        // (§2) returns Err with the current process still serving and the
        // installed binaries untouched. The plan is then carried through
        // replacement and restart — never re-derived post-swap.
        let restart_plan = self.resolve_restart_plan(&target_path).await?;
        self.check_release()?;
        #[cfg(unix)]
        let probe_launch = super::probe::ProbeLaunch::capture(&restart_plan.cwd);
        // Refuse a failed Unix record barrier before download or replacement.
        // Unmanaged Windows keeps the released legacy helper path; managed
        // Windows is refused by the restart planner and has no M2 barrier.
        #[cfg(unix)]
        super::journal::check_record_barrier_support(&restart_plan.data_root).map_err(|error| {
            UpgradeError::Other(format!("upgrade record barrier unavailable: {error}"))
        })?;
        #[cfg(unix)]
        if let Some(gate) = &self.staging {
            super::monitor::validate_manifest_timestamp(manifest)?;
            if gate.request.version != manifest.version
                || gate.request.archive_sha256 != asset.archive_sha256
                || std::fs::canonicalize(&restart_plan.data_root)
                    .map_err(|error| UpgradeError::Other(error.to_string()))?
                    != gate.request.data_root
            {
                return Err(UpgradeError::Other(
                    "staging release or data root changed".into(),
                ));
            }
            let gate = gate.clone();
            let install = target_path.clone();
            let staging_plan = restart_plan.clone();
            run_owned_blocking_with_permit(self.release_permit.as_ref(), move |caller_alive| {
                let _lock = super::acquire_host_upgrade_lock(&install)?;
                if !caller_alive.load(Ordering::Acquire) {
                    return Err(UpgradeError::Other(
                        "staging admission cancelled before record I/O".into(),
                    ));
                }
                gate.require_due(&install, &staging_plan)
            })
            .await?;
            #[cfg(test)]
            pre_probe_admission_seam::run(&target_path);
        }
        #[cfg(unix)]
        if let super::probe::Admission::Waiting { retry_after } = inspect_probe_admission(
            target_path.clone(),
            manifest.version.clone(),
            self.staging
                .clone()
                .map(|gate| (gate, restart_plan.clone())),
            self.release_permit.as_ref(),
        )
        .await?
        {
            return Err(UpgradeError::Other(
                super::probe::ProbeRefusal::Waiting { retry_after }.to_string(),
            ));
        }
        self.check_release()?;
        info!(
            mode = ?restart_plan.mode,
            supervision = restart_plan.supervision_signal.as_deref().unwrap_or("none"),
            launchd = ?restart_plan.launchd_verified,
            systemd = ?restart_plan.systemd_verified,
            stop_on_upgrade = self.stop_on_upgrade,
            data_root = %restart_plan.data_root.display(),
            spawns_helper = restart_plan.spawns_helper(),
            "Restart contract resolved before replacement"
        );

        // #1196 round 2 test seam (cfg(test) only): when an in-process
        // test has installed an apply attempt, the destructive half —
        // downloads, hash/signature verification, extraction, binary
        // replacement and the restart itself — is the INJECTION, not the
        // filesystem or the network. Everything above (version/platform
        // resolution and the ADR-0061 §1 restart-contract resolution the
        // #1196 behaviour lives in) still runs for real, so a refused
        // contract never reaches this hook. Compiled out entirely in
        // non-test builds; an uninstalled hook changes nothing.
        #[cfg(test)]
        if let Some(result) = apply_attempt_seam::intercept(&restart_plan, manifest) {
            return Ok(result);
        }

        let upgrader = Upgrader::new(target_path.clone(), current_version.clone());
        let temp_dir = upgrader.create_temp_dir()?;
        // Guarantees temp-dir removal on every early-return error path below.
        let _temp_guard = TempDirGuard {
            path: temp_dir.clone(),
        };

        let archive_path = temp_dir.join("archive");
        let sig_path = temp_dir.join("archive.sig");

        // Download archive
        info!(
            target = platform_target,
            "Downloading release archive for {}", platform_target
        );
        download_to_file(&asset.archive_url, &archive_path).await?;

        let archive_data =
            std::fs::read(&archive_path).map_err(|e| UpgradeError::Other(e.to_string()))?;

        // Verify archive SHA-256 against manifest (integrity)
        let actual_hash: [u8; 32] = Sha256::digest(&archive_data).into();
        if actual_hash != asset.archive_sha256 {
            warn!(
                expected = hex::encode(asset.archive_sha256),
                actual = hex::encode(actual_hash),
                "Archive SHA-256 mismatch"
            );
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(UpgradeError::HashMismatch);
        }
        info!("Archive SHA-256 verified against manifest");

        // Download and verify ML-DSA-65 signature on archive (authenticity)
        info!("Downloading signature...");
        download_to_file(&asset.signature_url, &sig_path).await?;
        let sig_data = std::fs::read(&sig_path).map_err(|e| UpgradeError::Other(e.to_string()))?;

        if let Err(e) =
            verify_bytes_signature_with_key(&archive_data, &sig_data, RELEASE_SIGNING_KEY)
        {
            warn!(error = %e, "Signature verification failed");
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(e.into());
        }
        info!("Archive signature verified successfully");

        // Extract binary from archive
        // On Windows, also check for binary_name.exe
        let binary_name = if cfg!(target_os = "windows") && !self.binary_name.ends_with(".exe") {
            format!("{}.exe", self.binary_name)
        } else {
            self.binary_name.clone()
        };
        info!("Extracting binary from archive...");
        let extracted_path = temp_dir.join("extracted-binary");
        extract_binary_from_archive(&archive_path, &extracted_path, &binary_name)?;

        // M2 probes both packaged executables even when the installed CLI is
        // split/package-managed and will not be replaced by this transaction.
        // Preserve the released unmanaged Windows path without an M2 claim.
        #[cfg(unix)]
        let (probe_daemon, probe_cli) = {
            let daemon = if self.binary_name == "x0xd" {
                extracted_path.clone()
            } else {
                let path = temp_dir.join("probe-x0xd");
                extract_binary_from_archive(&archive_path, &path, "x0xd")?;
                path
            };
            let cli = if self.binary_name == "x0x" {
                extracted_path.clone()
            } else {
                let path = temp_dir.join("extracted-x0x");
                extract_binary_from_archive(&archive_path, &path, "x0x")?;
                path
            };
            (daemon, cli)
        };

        // Prepare an optional companion replace; both locks run off-worker below.
        let mut companion = None;
        if self.binary_name == "x0xd" {
            let parent_dir = target_path
                .parent()
                .ok_or_else(|| UpgradeError::Other("target has no parent directory".to_string()))?;
            let x0x_name = if cfg!(target_os = "windows") {
                "x0x.exe"
            } else {
                "x0x"
            };
            let x0x_path = parent_dir.join(x0x_name);
            if x0x_path.exists() {
                info!("Found x0x CLI companion in same directory, upgrading it too...");
                #[cfg(unix)]
                {
                    companion = Some((
                        Upgrader::new(x0x_path, current_version.clone()),
                        probe_cli.clone(),
                    ));
                }
                #[cfg(not(unix))]
                {
                    let extracted_x0x = temp_dir.join("extracted-x0x");
                    if let Err(e) =
                        extract_binary_from_archive(&archive_path, &extracted_x0x, x0x_name)
                    {
                        warn!("Failed to extract companion x0x binary: {e}");
                    } else {
                        companion = Some((
                            Upgrader::new(x0x_path, current_version.clone()),
                            extracted_x0x,
                        ));
                    }
                }
            }
        }

        #[cfg(unix)]
        let probe_admission: Option<ProbeAdmission> = {
            let request = super::probe::ProbeRequest {
                install: target_path.clone(),
                version: manifest.version.clone(),
                platform: platform_target.to_owned(),
                archive_sha256: asset.archive_sha256,
                daemon: probe_daemon,
                cli: probe_cli,
                launch: probe_launch,
            };
            let staging = self.staging.clone();
            let staging_plan = restart_plan.clone();
            let admitted_manifest = manifest.clone();
            Some(Box::new(move |alive| {
                if let Some(gate) = &staging {
                    gate.require_due(&request.install, &staging_plan)?;
                }
                super::probe::run_before_swap(&request, alive)
                    .map(|_| ())
                    .map_err(|error| UpgradeError::Other(error.to_string()))?;
                if staging.is_some() {
                    super::monitor::validate_manifest_timestamp(&admitted_manifest)?;
                }
                Ok(())
            }))
        };
        #[cfg(not(unix))]
        let probe_admission = None;

        // Move temp-dir custody into the blocking task so cancel cannot delete
        // extracted binaries mid-replace. The guard cleans up when that task ends
        // (and is dropped before any non-returning restart continuation — RC4 P2).
        //
        // Restart ownership at admission (#1447 RC3/RC4):
        // - restart_on_success=true → immediate worker-owned trigger_restart
        // - http_deferred_restart=true → OS-thread deferred (~750 ms) owner
        // - both false → no restart (the report-only CLI does not apply)
        // Do not infer HTTP from RestartContext presence.
        let restart_plan_for_cont = restart_plan.clone();
        let version_for_cont = target_version.to_string();
        let binary_name = self.binary_name.clone();
        let stop_on_upgrade = self.stop_on_upgrade;
        let restart_context = self.restart_context.clone();
        let on_success: Option<Box<dyn FnOnce() + Send>> = if self.restart_on_success {
            Some(Box::new(move || {
                let owner = AutoApplyUpgrader::new(&binary_name)
                    .with_stop_on_upgrade(stop_on_upgrade)
                    .with_restart_context(restart_context)
                    .with_restart_on_success(false);
                if let Err(e) = owner.trigger_restart(&restart_plan_for_cont, &version_for_cont) {
                    warn!(
                        error = %e,
                        installed_bytes = true,
                        restart = "not_started",
                        readiness_observed = false,
                        "Restart after successful upgrade did not start: {e}; \
                         old process keeps serving"
                    );
                }
            }))
        } else if self.http_deferred_restart {
            // RC5: create the parked deferred owner *before* host mutation so a
            // Builder::spawn failure refuses the apply instead of returning
            // Success / restart_scheduled:true with no owner.
            Some(
                arm_http_deferred_restart_owner(
                    binary_name,
                    stop_on_upgrade,
                    restart_context,
                    restart_plan_for_cont,
                    version_for_cont,
                )
                .map_err(|e| {
                    UpgradeError::Other(format!(
                        "failed to create HTTP deferred-restart owner before apply: {e}"
                    ))
                })?,
            )
        } else {
            None
        };

        self.check_release()?;
        let result = apply_replacements_with_permit(
            upgrader,
            extracted_path,
            target_version.clone(),
            companion,
            _temp_guard,
            on_success,
            probe_admission,
            self.release_permit.as_ref(),
        )
        .await?;

        if matches!(result, UpgradeResult::Success { .. }) {
            // ADR-0061 §6 — report honestly. Installed bytes, a pending
            // restart, observed readiness and recovery are four distinct
            // facts; only the first is established at this point. Immediate
            // and HTTP-deferred owners are armed at admission (RC3/RC4).
            let restart = if self.restart_on_success {
                "owned_at_admission"
            } else if self.http_deferred_restart {
                "http_deferred_owned_at_admission"
            } else {
                "none"
            };
            info!(
                version = %target_version,
                installed_bytes = true,
                restart,
                restart_mode = ?restart_plan.mode,
                readiness_observed = false,
                recovery = "none",
                "Upgrade bytes installed for version {}; restart ownership \
                 follows restart_on_success / http_deferred_restart",
                target_version
            );
        }

        Ok(result)
    }

    /// Execute an already-resolved restart plan (#261, ADR-0061 §1).
    ///
    /// The plan is *not* re-classified here: it was resolved and validated
    /// before replacement, so this only carries it out.
    ///
    /// - `SupervisedExit` (supervision present **and** `stop_on_upgrade`
    ///   true) writes the intent record and exits for the external owner.
    ///   ADR-0061 §5: no detached helper is spawned on this path, so nothing
    ///   can start a second daemon on the same data root.
    /// - `TransactionalHandoff` (genuinely unsupervised, including the default
    ///   `stop_on_upgrade = true` terminal launch) runs the helper, which
    ///   proves `/health` on the new binary or restores the backup.
    fn trigger_restart(
        &self,
        plan: &restart::RestartPlan,
        target_version: &str,
    ) -> Result<(), UpgradeError> {
        let handoff = restart::UpgradeHandoff::from_plan(plan, target_version);
        let handoff_path = plan.handoff_path();

        match plan.mode {
            restart::RestartMode::SupervisedExit => {
                // I3: write the intent file BEFORE exiting so a supervisor
                // crash loop is diagnosable. Best-effort — the exit contract
                // with Restart=always units must not depend on disk health.
                if let Err(e) = handoff.write(&handoff_path) {
                    warn!(
                        handoff = %handoff_path.display(),
                        error = %e,
                        "Failed to write upgrade intent file before supervised exit"
                    );
                }
                let exit_code = plan
                    .supervised_exit_code
                    .unwrap_or_else(restart::supervised_exit_code);
                // ADR-0061 §6: this exit is a *restart request* to the owner
                // named in `supervision`. It is not health acceptance, and it
                // arms no automatic rollback — recovery on this path is the
                // documented manual operator procedure.
                info!(
                    exit_code = exit_code,
                    supervision = plan.supervision_signal.as_deref().unwrap_or("none"),
                    installed_bytes = true,
                    restart = "requested_from_supervisor",
                    readiness_observed = false,
                    automatic_rollback = false,
                    "Exiting with code {} to request a restart from the service manager; \
                     replacement readiness is observed by the supervisor, not by x0xd",
                    exit_code
                );
                std::process::exit(exit_code);
            }
            restart::RestartMode::TransactionalHandoff => restart::begin_transactional_handoff(
                handoff,
                &handoff_path,
                self.restart_context.shutdown.as_deref(),
            ),
        }
    }
}

/// Get the path to the currently running binary.
///
/// Handles the `/proc/self/exe (deleted)` suffix on Linux.
pub fn current_binary_path() -> Result<PathBuf, UpgradeError> {
    let exe = observe_current_executable()
        .map_err(|e| UpgradeError::Other(format!("failed to resolve current executable: {e}")))?;

    // On Linux, /proc/self/exe can have " (deleted)" suffix after an upgrade
    let path_str = exe.to_string_lossy();
    if path_str.ends_with(" (deleted)") {
        let clean = path_str.trim_end_matches(" (deleted)");
        Ok(PathBuf::from(clean))
    } else {
        Ok(exe)
    }
}

fn observe_current_executable() -> std::io::Result<PathBuf> {
    #[cfg(all(test, unix))]
    if let Some(path) = current_binary_path_seam::observation() {
        return Ok(path);
    }
    std::env::current_exe()
}

/// Replace only the raw executable observation, before path resolution. Tests
/// must keep this thread-local guard on their current-thread async runtime.
#[cfg(all(test, unix))]
pub(crate) mod current_binary_path_seam {
    use std::{cell::RefCell, marker::PhantomData, path::PathBuf, rc::Rc};

    thread_local! {
        static OBSERVATION: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    pub(crate) struct Guard {
        previous: Option<PathBuf>,
        _thread: PhantomData<Rc<()>>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            OBSERVATION.with(|slot| *slot.borrow_mut() = self.previous.take());
        }
    }

    pub(crate) fn install(raw: PathBuf) -> Guard {
        Guard {
            previous: OBSERVATION.with(|slot| slot.replace(Some(raw))),
            _thread: PhantomData,
        }
    }

    pub(super) fn observation() -> Option<PathBuf> {
        OBSERVATION.with(|slot| slot.borrow().clone())
    }
}

/// Observe the actual gap between staged admission and the separate probe
/// lock. The hook changes no input and runs after the first lock is released.
#[cfg(all(test, unix))]
pub(crate) mod pre_probe_admission_seam {
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{LazyLock, Mutex},
    };

    type Hook = Box<dyn FnOnce(&Path) + Send>;
    static HOOKS: LazyLock<Mutex<HashMap<PathBuf, Hook>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    pub(crate) struct Guard {
        target: PathBuf,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Ok(mut hooks) = HOOKS.lock() {
                hooks.remove(&self.target);
            }
        }
    }

    pub(crate) fn install(target: PathBuf, hook: Hook) -> Guard {
        let mut hooks = HOOKS.lock().expect("probe admission seam poisoned");
        assert!(
            !hooks.contains_key(&target),
            "probe admission seam already installed"
        );
        hooks.insert(target.clone(), hook);
        Guard { target }
    }

    pub(super) fn run(target: &Path) {
        let hook = HOOKS
            .lock()
            .expect("probe admission seam poisoned")
            .remove(target);
        if let Some(hook) = hook {
            hook(target);
        }
    }
}

/// #1196 round 2 test seam (cfg(test) only; no env vars, no cargo
/// features): lets an in-process test observe — and stand in for — ONE
/// apply attempt of [`AutoApplyUpgrader::apply_upgrade_from_manifest`].
/// The hook fires only after the ADR-0061 §1 restart contract has resolved
/// for real (a refused contract never reaches it), and replaces the
/// destructive half of the apply: downloads, verification, extraction,
/// replacement, restart. Compiled out entirely in non-test builds; an
/// uninstalled hook changes nothing.
#[cfg(test)]
pub(crate) mod apply_attempt_seam {
    use super::UpgradeResult;
    use crate::upgrade::manifest::ReleaseManifest;
    use crate::upgrade::restart::RestartPlan;
    use std::sync::Mutex;

    /// An installed apply attempt: sees the resolved restart plan and the
    /// manifest being applied, and answers as the destructive half would.
    pub(crate) type Attempt =
        Box<dyn Fn(&RestartPlan, &ReleaseManifest) -> UpgradeResult + Send + Sync>;

    static INSTALLED: Mutex<Option<Attempt>> = Mutex::new(None);

    /// Uninstalls the attempt on drop, so a test cannot leak its injection
    /// into sibling tests in the same process.
    pub(crate) struct Guard {
        _private: (),
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Ok(mut slot) = INSTALLED.lock() {
                *slot = None;
            }
        }
    }

    /// Install `attempt` for the guard's lifetime.
    pub(crate) fn install(attempt: Attempt) -> Guard {
        let mut slot = INSTALLED.lock().expect("apply attempt seam poisoned");
        *slot = Some(attempt);
        Guard { _private: () }
    }

    /// Run the installed attempt, or `None` when nothing is installed
    /// (fall through to the real destructive half).
    pub(crate) fn intercept(
        plan: &RestartPlan,
        manifest: &ReleaseManifest,
    ) -> Option<UpgradeResult> {
        let slot = INSTALLED.lock().expect("apply attempt seam poisoned");
        slot.as_ref().map(|attempt| attempt(plan, manifest))
    }
}

/// Download a URL to a local file, enforcing a maximum size limit.
///
/// Checks `Content-Length` upfront and streams the response to disk with
/// a running byte counter to prevent OOM on oversized payloads.
async fn download_to_file(url: &str, destination: &Path) -> Result<(), UpgradeError> {
    use super::MAX_BINARY_SIZE_BYTES;
    use futures::StreamExt;
    use std::io::Write;

    debug!(url = url, "Downloading: {url}");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| UpgradeError::DownloadError(e.to_string()))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            warn!(error = %e, "Archive download failed: {e}");
            UpgradeError::DownloadError(e.to_string())
        })?
        .error_for_status()
        .map_err(|e| {
            warn!(error = %e, "Archive download failed: {e}");
            UpgradeError::DownloadError(e.to_string())
        })?;

    // Reject early if Content-Length exceeds limit
    if let Some(content_length) = response.content_length() {
        if content_length > MAX_BINARY_SIZE_BYTES {
            return Err(UpgradeError::BinaryTooLarge {
                size: content_length,
                limit: MAX_BINARY_SIZE_BYTES,
            });
        }
    }

    // Stream to disk with running byte counter
    let mut file = std::fs::File::create(destination)
        .map_err(|e| UpgradeError::DownloadError(format!("create file failed: {e}")))?;
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes =
            chunk_result.map_err(|e| UpgradeError::DownloadError(e.to_string()))?;
        downloaded += chunk.len() as u64;
        if downloaded > MAX_BINARY_SIZE_BYTES {
            drop(file);
            let _ = std::fs::remove_file(destination);
            return Err(UpgradeError::BinaryTooLarge {
                size: downloaded,
                limit: MAX_BINARY_SIZE_BYTES,
            });
        }
        file.write_all(&chunk)
            .map_err(|e| UpgradeError::DownloadError(format!("write failed: {e}")))?;
    }

    debug!(
        bytes = downloaded,
        path = %destination.display(),
        "Downloaded {} bytes to {}",
        downloaded,
        destination.display()
    );

    Ok(())
}

/// Extract a binary from an archive (tar.gz or zip, detected by magic bytes).
///
/// The only acceptable entry is a regular file whose final path component is
/// exactly `binary_name` (#1144); an archive holding more than one such entry
/// is refused outright. After extraction the output must carry the magic of a
/// native executable for this platform (ELF/Mach-O/MZ), or it is deleted and
/// the apply is refused — a macOS AppleDouble sidecar like `._x0xd` must never
/// be staged as the daemon.
pub fn extract_binary_from_archive(
    archive_path: &Path,
    output_path: &Path,
    binary_name: &str,
) -> Result<(), UpgradeError> {
    let data = std::fs::read(archive_path)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to read archive: {e}")))?;

    // Detect archive format by magic bytes
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        // gzip magic bytes -> tar.gz
        extract_from_tar_gz(archive_path, output_path, binary_name)?;
    } else if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        // PK zip magic bytes
        extract_from_zip(archive_path, output_path, binary_name)?;
    } else {
        return Err(UpgradeError::ExtractionError(
            "unknown archive format (not tar.gz or zip)".to_string(),
        ));
    }

    verify_extracted_binary_magic(output_path, binary_name)
}

/// Magic-number prefixes accepted as a native executable for the platform
/// this upgrade applies to (the self-update target is always the host).
///
/// Any target other than Linux, macOS or Windows always fails this check:
/// fail closed, since no release asset exists for such a target.
fn has_native_executable_magic(prefix: &[u8]) -> bool {
    if cfg!(target_os = "linux") {
        prefix.starts_with(b"\x7fELF")
    } else if cfg!(target_os = "macos") {
        // MH_MAGIC / MH_MAGIC_64, their byte-swapped CIGAM forms, and the
        // 32-bit (CA FE BA BE) and 64-bit (CA FE BA BF) fat (universal)
        // magics with their byte-swapped forms — the same set `file(1)`
        // accepts.
        matches!(
            prefix.first_chunk::<4>(),
            Some([0xFE, 0xED, 0xFA, 0xCE])
                | Some([0xFE, 0xED, 0xFA, 0xCF])
                | Some([0xCE, 0xFA, 0xED, 0xFE])
                | Some([0xCF, 0xFA, 0xED, 0xFE])
                | Some([0xCA, 0xFE, 0xBA, 0xBE])
                | Some([0xBE, 0xBA, 0xFE, 0xCA])
                | Some([0xCA, 0xFE, 0xBA, 0xBF])
                | Some([0xBF, 0xBA, 0xFE, 0xCA])
        )
    } else if cfg!(target_os = "windows") {
        prefix.starts_with(b"MZ")
    } else {
        // Fail closed: no release asset exists for any other target, so an
        // extracted binary there can never pass this check.
        false
    }
}

/// Refuse an extracted file that does not carry a native executable magic.
///
/// A file that fails the check is removed, so it can never be left where a
/// caller could stage it as the replacement binary.
fn verify_extracted_binary_magic(
    output_path: &Path,
    binary_name: &str,
) -> Result<(), UpgradeError> {
    use std::io::Read;

    let mut prefix = [0u8; 4];
    let read = std::fs::File::open(output_path).and_then(|mut f| f.read_exact(&mut prefix));

    match read {
        Ok(()) if has_native_executable_magic(&prefix) => Ok(()),
        Ok(()) => {
            let _ = std::fs::remove_file(output_path);
            Err(UpgradeError::ExtractionError(format!(
                "extracted '{binary_name}' does not have the magic of a native executable for this platform"
            )))
        }
        Err(e) => {
            let _ = std::fs::remove_file(output_path);
            Err(UpgradeError::ExtractionError(format!(
                "failed to read extracted '{binary_name}' for magic check: {e}"
            )))
        }
    }
}

fn extract_from_tar_gz(
    archive_path: &Path,
    output_path: &Path,
    binary_name: &str,
) -> Result<(), UpgradeError> {
    let file = std::fs::File::open(archive_path)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to open archive: {e}")))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    let mut extracted = false;
    for entry_result in archive
        .entries()
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to read tar entries: {e}")))?
    {
        let mut entry = entry_result
            .map_err(|e| UpgradeError::ExtractionError(format!("bad tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| UpgradeError::ExtractionError(format!("bad entry path: {e}")))?;

        let path_str = path.to_string_lossy();
        // Only a regular file whose last path component is exactly the
        // binary name may match (#1144): an AppleDouble sidecar (`._x0xd`),
        // an `old-x0xd` backup or a symlink must never be extracted.
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if file_name != binary_name {
            continue;
        }
        if extracted {
            // Never pick between candidates — a duplicate could be the
            // wrong artifact, so the whole archive is refused.
            let _ = std::fs::remove_file(output_path);
            return Err(UpgradeError::ExtractionError(format!(
                "multiple entries named '{binary_name}' in tar.gz archive; refusing to pick one"
            )));
        }

        debug!(archive_path = %path_str, "Found binary in tar.gz archive: {}", path_str);
        let mut output = std::fs::File::create(output_path)
            .map_err(|e| UpgradeError::ExtractionError(format!("failed to create output: {e}")))?;
        std::io::copy(&mut entry, &mut output)
            .map_err(|e| UpgradeError::ExtractionError(format!("failed to extract binary: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Stage mode is always 0o755. The archive Unix mode is not
            // applied, so setuid, setgid, and sticky bits in the entry
            // cannot land on the staged binary.
            std::fs::set_permissions(output_path, std::fs::Permissions::from_mode(0o755)).map_err(
                |e| UpgradeError::ExtractionError(format!("failed to set permissions: {e}")),
            )?;
        }

        extracted = true;
    }

    if !extracted {
        return Err(UpgradeError::ExtractionError(format!(
            "binary '{binary_name}' not found in tar.gz archive"
        )));
    }
    Ok(())
}

fn extract_from_zip(
    archive_path: &Path,
    output_path: &Path,
    binary_name: &str,
) -> Result<(), UpgradeError> {
    let file = std::fs::File::open(archive_path)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to open archive: {e}")))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to open zip: {e}")))?;

    let mut extracted = false;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UpgradeError::ExtractionError(format!("bad zip entry: {e}")))?;

        // Only a regular file whose last path component is exactly the
        // binary name may match (#1144) — same rule as the tar.gz branch.
        if !entry.is_file() {
            continue;
        }
        // zip 9 decodes the entry name on demand and returns a `Result`.
        // Drop the borrowed name before the entry is read: `copy` needs
        // `&mut entry`.
        let file_name = {
            let entry_name = entry
                .name()
                .map_err(|e| UpgradeError::ExtractionError(format!("bad zip entry name: {e}")))?;
            Path::new(entry_name.as_ref())
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        };

        if file_name != binary_name {
            continue;
        }
        // Same-basename matches under different directories are still caught
        // by the guard below, but zip's name-keyed IndexMap collapses entries
        // whose *full* names are identical, so an exact same-name duplicate
        // can never be observed on this path (the archive is signed CI
        // output, which never contains one).
        if extracted {
            let _ = std::fs::remove_file(output_path);
            return Err(UpgradeError::ExtractionError(format!(
                "multiple entries named '{binary_name}' in zip archive; refusing to pick one"
            )));
        }

        let mut output = std::fs::File::create(output_path)
            .map_err(|e| UpgradeError::ExtractionError(format!("failed to create output: {e}")))?;
        std::io::copy(&mut entry, &mut output)
            .map_err(|e| UpgradeError::ExtractionError(format!("failed to extract binary: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Stage mode is always 0o755. The archive Unix mode is not
            // applied, so setuid, setgid, and sticky bits in the entry
            // cannot land on the staged binary.
            std::fs::set_permissions(output_path, std::fs::Permissions::from_mode(0o755)).map_err(
                |e| UpgradeError::ExtractionError(format!("failed to set permissions: {e}")),
            )?;
        }

        extracted = true;
    }

    if !extracted {
        return Err(UpgradeError::ExtractionError(format!(
            "binary '{binary_name}' not found in zip archive"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_http_custody.rs"
    ));
    http_custody_regression_tests!();
    #[cfg(unix)]
    include!("../../tests/upgrade_background_staging.rs");
    #[cfg(unix)]
    background_permit_regression_tests!();
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[cfg(unix)]
    struct ProbePairFixture {
        _root: TempDir,
        primary: PathBuf,
        cli: PathBuf,
        stage: PathBuf,
        candidate_daemon: PathBuf,
        candidate_cli: PathBuf,
    }

    #[cfg(unix)]
    impl ProbePairFixture {
        fn new(cli_version: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let evidence = std::env::var_os("X0X_UPGRADE_PROBE_EVIDENCE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning/upgrade-probe-fixtures")
                });
            std::fs::create_dir_all(&evidence).unwrap();
            let root = tempfile::Builder::new()
                .prefix("apply-probe-")
                .tempdir_in(evidence)
                .unwrap();
            let primary = root.path().join("x0xd");
            let cli = root.path().join("x0x");
            let stage = root.path().join("stage");
            std::fs::create_dir(&stage).unwrap();
            std::fs::write(&primary, b"old daemon").unwrap();
            std::fs::write(&cli, b"old cli").unwrap();
            let candidate_daemon = stage.join("daemon");
            let candidate_cli = stage.join("cli");
            for (path, version) in [(&candidate_daemon, "2.0.0"), (&candidate_cli, cli_version)] {
                let output = serde_json::json!({
                    "version": version,
                    "platform": current_platform_target().unwrap(),
                });
                std::fs::write(path, format!("#!/bin/sh\nprintf '%s\\n' '{output}'\n")).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            Self {
                _root: root,
                primary,
                cli,
                stage,
                candidate_daemon,
                candidate_cli,
            }
        }

        fn request(&self) -> super::super::probe::ProbeRequest {
            super::super::probe::ProbeRequest {
                install: self.primary.clone(),
                version: "2.0.0".to_owned(),
                platform: current_platform_target().unwrap().to_owned(),
                archive_sha256: [7; 32],
                daemon: self.candidate_daemon.clone(),
                cli: self.candidate_cli.clone(),
                launch: super::super::probe::ProbeLaunch::capture(self._root.path()),
            }
        }

        fn assert_old_pair(&self) {
            assert_eq!(std::fs::read(&self.primary).unwrap(), b"old daemon");
            assert_eq!(std::fs::read(&self.cli).unwrap(), b"old cli");
            assert!(!self.primary.with_extension("backup").exists());
            assert!(!self.cli.with_extension("backup").exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn durable_probe_retry_bridge_distinguishes_due_waits_from_holds() {
        use super::super::probe::{self, ProbeCause, ProbePhase};

        let fixture = ProbePairFixture::new("2.0.0");
        let check = || probe_retry_delay_for_install(fixture.primary.clone(), "2.0.0".to_owned());
        assert!(check().await.unwrap().is_none());
        {
            let _lock = super::super::acquire_host_upgrade_lock(&fixture.primary).unwrap();
            probe::run_before_swap(&fixture.request(), &AtomicBool::new(true)).unwrap();
        }
        assert!(check().await.unwrap().is_none(), "passed is not pending");
        let path = probe::state_path(&fixture.primary).unwrap();
        let mut state = probe::read_state(&fixture.primary).unwrap().unwrap();
        state.phase = ProbePhase::InterruptedWait;
        state.cause = Some(ProbeCause::Timeout);
        state.retry_remaining_ms = 1;
        state.retry_deadline_ms = 1;
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let due = check().await.unwrap().expect("expired wait must retry");
        assert_eq!(due.delay, std::time::Duration::ZERO);
        assert_eq!(due.transaction_id, state.transaction_id);
        assert!(
            probe_retry_delay_for_install(fixture.primary.clone(), "3.0.0".to_owned())
                .await
                .unwrap()
                .is_none(),
            "a newer release cannot inherit the old transaction's retry"
        );
        for (phase, cause) in [
            (ProbePhase::FailedHold, Some(ProbeCause::VersionMismatch)),
            (ProbePhase::Running, None),
        ] {
            state.phase = phase;
            state.cause = cause;
            state.retry_remaining_ms = 0;
            state.retry_deadline_ms = 0;
            let bytes = serde_json::to_vec(&state).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(check().await.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        state.phase = ProbePhase::Passed;
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let marker = probe::uncertainty_path(&fixture.primary).unwrap();
        std::fs::write(&marker, b"uncertain terminal write").unwrap();
        assert!(check().await.is_err(), "a marker forbids a retry");
        assert_eq!(std::fs::read(marker).unwrap(), b"uncertain terminal write");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn probe_failure_blocks_both_actual_replacements_and_restart() {
        for failure in ["version", "loader", "timeout"] {
            let fixture = ProbePairFixture::new(if failure == "version" {
                "9.0.0"
            } else {
                "2.0.0"
            });
            if failure == "loader" {
                std::fs::write(&fixture.candidate_cli, b"#!/no/such/upgrade-probe-loader\n")
                    .unwrap();
            } else if failure == "timeout" {
                std::fs::write(&fixture.candidate_cli, b"#!/bin/sh\nsleep 5\n").unwrap();
            }
            let request = fixture.request();
            let restarted = Arc::new(AtomicBool::new(false));
            let marker = Arc::clone(&restarted);
            let result = apply_replacements_offloaded(
                Upgrader::new(fixture.primary.clone(), semver::Version::new(1, 0, 0)),
                fixture.candidate_daemon.clone(),
                semver::Version::new(2, 0, 0),
                Some((
                    Upgrader::new(fixture.cli.clone(), semver::Version::new(1, 0, 0)),
                    fixture.candidate_cli.clone(),
                )),
                TempDirGuard {
                    path: fixture.stage.clone(),
                },
                Some(Box::new(move || marker.store(true, Ordering::Release))),
                Some(Box::new(move |alive| {
                    let result = if failure == "timeout" {
                        super::super::probe::run_before_swap_with_options(
                            &request,
                            alive,
                            &super::super::probe::ProbeOptions {
                                clock: super::super::probe::ProbeClock {
                                    boot_id: "apply-boundary-test".to_owned(),
                                    monotonic_ms: 100,
                                },
                                timeout: std::time::Duration::from_secs(2),
                                fail_write: None,
                            },
                        )
                    } else {
                        super::super::probe::run_before_swap(&request, alive)
                    };
                    result
                        .map(|_| ())
                        .map_err(|error| UpgradeError::Other(error.to_string()))
                })),
            )
            .await;
            assert!(result.is_err());
            fixture.assert_old_pair();
            assert!(!restarted.load(Ordering::Acquire));
            assert!(!fixture.stage.exists());
            assert_eq!(
                super::super::probe::read_state(&fixture.primary)
                    .unwrap()
                    .unwrap()
                    .phase,
                if failure == "timeout" {
                    super::super::probe::ProbePhase::InterruptedWait
                } else {
                    super::super::probe::ProbePhase::FailedHold
                }
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_probe_precedes_pair_swap_and_owned_continuation() {
        let fixture = ProbePairFixture::new("2.0.0");
        let request = fixture.request();
        let daemon_bytes = std::fs::read(&fixture.candidate_daemon).unwrap();
        let cli_bytes = std::fs::read(&fixture.candidate_cli).unwrap();
        let primary = fixture.primary.clone();
        let cli = fixture.cli.clone();
        let stage = fixture.stage.clone();
        let continued = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&continued);
        let result = apply_replacements_offloaded(
            Upgrader::new(fixture.primary.clone(), semver::Version::new(1, 0, 0)),
            fixture.candidate_daemon.clone(),
            semver::Version::new(2, 0, 0),
            Some((
                Upgrader::new(fixture.cli.clone(), semver::Version::new(1, 0, 0)),
                fixture.candidate_cli.clone(),
            )),
            TempDirGuard {
                path: fixture.stage.clone(),
            },
            Some(Box::new(move || {
                assert_eq!(std::fs::read(primary).unwrap(), daemon_bytes);
                assert_eq!(std::fs::read(cli).unwrap(), cli_bytes);
                assert!(!stage.exists());
                marker.store(true, Ordering::Release);
            })),
            Some(Box::new(move |alive| {
                assert_eq!(std::fs::read(&request.install).unwrap(), b"old daemon");
                assert!(!request.install.with_extension("backup").exists());
                super::super::probe::run_before_swap(&request, alive)
                    .map(|_| ())
                    .map_err(|error| UpgradeError::Other(error.to_string()))
            })),
        )
        .await
        .unwrap();
        assert!(matches!(result, UpgradeResult::Success { .. }));
        assert!(continued.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_probe_observer_cannot_admit_either_swap() {
        let fixture = ProbePairFixture::new("2.0.0");
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (finished, done) = tokio::sync::oneshot::channel();
        let primary = fixture.primary.clone();
        let cli = fixture.cli.clone();
        let incoming = fixture.candidate_daemon.clone();
        let incoming_cli = fixture.candidate_cli.clone();
        let stage = fixture.stage.clone();
        let restarted = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&restarted);
        let task = tokio::spawn(async move {
            apply_replacements_offloaded(
                Upgrader::new(primary, semver::Version::new(1, 0, 0)),
                incoming,
                semver::Version::new(2, 0, 0),
                Some((
                    Upgrader::new(cli, semver::Version::new(1, 0, 0)),
                    incoming_cli,
                )),
                TempDirGuard { path: stage },
                Some(Box::new(move || marker.store(true, Ordering::Release))),
                Some(Box::new(move |alive| {
                    entered.send(()).unwrap();
                    released
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    assert!(!alive.load(Ordering::Acquire));
                    finished.send(()).unwrap();
                    // The outer worker must recheck cancellation even if a
                    // probe callback returns success after cancellation.
                    Ok(())
                })),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), done)
            .await
            .unwrap()
            .unwrap();
        // Acquiring the same lock waits for the blocking worker to leave its
        // critical section. Its temp guard drops just after the lock.
        let primary = fixture.primary.clone();
        tokio::task::spawn_blocking(move || {
            drop(super::super::acquire_host_upgrade_lock(&primary).unwrap());
        })
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while fixture.stage.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        fixture.assert_old_pair();
        assert!(!fixture.stage.exists());
        assert!(!restarted.load(Ordering::Acquire));
    }

    /// Magic prefix of a native executable on the host platform, so archive
    /// contents built by these tests pass the post-extraction magic check.
    /// Mirrors `has_native_executable_magic` exactly: any target that
    /// function fails closed on has no prefix here either.
    fn native_executable_prefix() -> &'static [u8] {
        if cfg!(target_os = "linux") {
            b"\x7fELF\x02"
        } else if cfg!(target_os = "macos") {
            &[0xCF, 0xFA, 0xED, 0xFE] // MH_MAGIC_64, little-endian
        } else if cfg!(target_os = "windows") {
            b"MZ\x90\x00" // PE
        } else {
            unreachable!(
                "no native executable magic on this target; x0x release assets exist only for linux, macos and windows"
            )
        }
    }

    /// Fake executable body: host magic prefix plus a recognisable tag.
    fn fake_binary(tag: &[u8]) -> Vec<u8> {
        let mut content = native_executable_prefix().to_vec();
        content.extend_from_slice(tag);
        content
    }

    type TarGzBuilder = tar::Builder<flate2::write::GzEncoder<std::fs::File>>;

    fn new_tar_gz(dir: &Path) -> (TarGzBuilder, PathBuf) {
        let archive_path = dir.join("test.tar.gz");
        let file = std::fs::File::create(&archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        (tar::Builder::new(encoder), archive_path)
    }

    /// Append a single tar entry with an explicit entry type: regular files,
    /// the `x0x-<target>/` directory entry the release packaging writes, and
    /// the link types the filter must refuse. `content` is empty for links
    /// and directories.
    fn append_entry(
        builder: &mut TarGzBuilder,
        inner_path: &str,
        entry_type: tar::EntryType,
        link_name: Option<&str>,
        content: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        if let Some(target) = link_name {
            header.set_link_name(target).unwrap();
        }
        header.set_cksum();
        builder
            .append_data(&mut header, inner_path, content)
            .unwrap();
    }

    /// Finish a tar.gz builder into a complete archive on disk: the tar
    /// end-of-archive blocks, then the gzip footer. `Builder::finish`
    /// alone leaves the gzip stream unflushed inside the encoder until it
    /// is dropped — too late when a test reads the archive in the same
    /// scope — so extraction would hit a truncated deflate stream.
    fn finish_tar_gz(builder: TarGzBuilder) {
        builder
            .into_inner()
            .expect("finish tar stream")
            .finish()
            .expect("finish gzip stream");
    }

    fn create_tar_gz_with_entries(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
        let (mut builder, archive_path) = new_tar_gz(dir);

        for &(inner_path, content) in entries {
            append_entry(
                &mut builder,
                inner_path,
                tar::EntryType::Regular,
                None,
                content,
            );
        }
        finish_tar_gz(builder);

        archive_path
    }

    fn create_test_tar_gz(dir: &Path, binary_name: &str, content: &[u8]) -> PathBuf {
        create_tar_gz_with_entries(
            dir,
            &[(&format!("x0x-linux-x64-gnu/{binary_name}"), content)],
        )
    }

    fn create_zip_with_entries(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
        let archive_path = dir.join("test.zip");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (entry_name, content) in entries {
            zip.start_file(*entry_name, options).unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap();

        archive_path
    }

    fn create_test_zip(dir: &Path, binary_name: &str, content: &[u8]) -> PathBuf {
        create_zip_with_entries(dir, &[(binary_name, content)])
    }

    #[test]
    fn test_extract_from_tar_gz() {
        let dir = TempDir::new().unwrap();
        let daemon = fake_binary(b"fake daemon binary");
        let cli = fake_binary(b"fake cli binary");
        // Mirrors the macOS packaging in release.yml: a `x0x-macos-arm64/`
        // directory entry, both binaries plus the provenance/docs files under
        // that prefix, and the AppleDouble sidecar macOS tarring leaves next
        // to `x0xd`.
        let (mut builder, archive) = new_tar_gz(dir.path());
        append_entry(
            &mut builder,
            "x0x-macos-arm64/",
            tar::EntryType::Directory,
            None,
            b"",
        );
        append_entry(
            &mut builder,
            "x0x-macos-arm64/x0xd",
            tar::EntryType::Regular,
            None,
            &daemon,
        );
        append_entry(
            &mut builder,
            "x0x-macos-arm64/x0x",
            tar::EntryType::Regular,
            None,
            &cli,
        );
        append_entry(
            &mut builder,
            "x0x-macos-arm64/._x0xd",
            tar::EntryType::Regular,
            None,
            b"\x00\x05\x16\x07 AppleDouble junk",
        );
        append_entry(
            &mut builder,
            "x0x-macos-arm64/Cargo.lock",
            tar::EntryType::Regular,
            None,
            b"# Cargo.lock\n",
        );
        append_entry(
            &mut builder,
            "x0x-macos-arm64/build-provenance.json",
            tar::EntryType::Regular,
            None,
            b"{\"provenance\":true}\n",
        );
        append_entry(
            &mut builder,
            "x0x-macos-arm64/LICENSE",
            tar::EntryType::Regular,
            None,
            b"license text\n",
        );
        append_entry(
            &mut builder,
            "x0x-macos-arm64/README.md",
            tar::EntryType::Regular,
            None,
            b"readme text\n",
        );
        finish_tar_gz(builder);

        let daemon_output = dir.path().join("extracted-x0xd");
        extract_binary_from_archive(&archive, &daemon_output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&daemon_output).unwrap(), daemon);

        let cli_output = dir.path().join("extracted-x0x");
        extract_binary_from_archive(&archive, &cli_output, "x0x").unwrap();
        assert_eq!(std::fs::read(&cli_output).unwrap(), cli);
    }

    #[test]
    fn test_extract_from_zip() {
        let dir = TempDir::new().unwrap();
        let daemon = fake_binary(b"fake windows daemon");
        let cli = fake_binary(b"fake windows cli");
        // Mirrors the Windows packaging in release.yml: root-level
        // `x0xd.exe` and `x0x.exe` beside the provenance/docs files.
        let archive = create_zip_with_entries(
            dir.path(),
            &[
                ("x0xd.exe", &daemon),
                ("x0x.exe", &cli),
                ("Cargo.lock", b"# Cargo.lock\n"),
                ("build-provenance.json", b"{\"provenance\":true}\n"),
                ("LICENSE", b"license text\n"),
                ("README.md", b"readme text\n"),
            ],
        );

        let daemon_output = dir.path().join("extracted-x0xd.exe");
        extract_binary_from_archive(&archive, &daemon_output, "x0xd.exe").unwrap();
        assert_eq!(std::fs::read(&daemon_output).unwrap(), daemon);

        let cli_output = dir.path().join("extracted-x0x.exe");
        extract_binary_from_archive(&archive, &cli_output, "x0x.exe").unwrap();
        assert_eq!(std::fs::read(&cli_output).unwrap(), cli);
    }

    #[test]
    fn test_extract_nested_path() {
        let dir = TempDir::new().unwrap();
        // create_test_tar_gz puts it at x0x-linux-x64-gnu/x0x
        let content = fake_binary(b"cli binary");
        let archive = create_test_tar_gz(dir.path(), "x0x", &content);
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive, &output, "x0x").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
    }

    #[test]
    fn test_unknown_archive_format_rejected() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("fake.bin");
        std::fs::write(&archive, b"not an archive").unwrap();
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
    }

    #[test]
    fn test_missing_binary_in_tar_gz() {
        let dir = TempDir::new().unwrap();
        let archive = create_test_tar_gz(dir.path(), "other-binary", b"content");
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
    }

    #[test]
    fn test_missing_binary_in_zip() {
        let dir = TempDir::new().unwrap();
        let archive = create_test_zip(dir.path(), "other.exe", b"content");
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd.exe");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
    }

    #[test]
    fn test_extract_appledouble_sidecar_is_ignored() {
        let dir = TempDir::new().unwrap();
        let content = fake_binary(b"real daemon");
        // Sidecar first, as in the gate-7b archive: `._x0xd` merely ends with
        // `x0xd`, so it must never match (#1144).
        let archive = create_tar_gz_with_entries(
            dir.path(),
            &[
                ("._x0xd", b"\x00\x05\x16\x07 AppleDouble junk"),
                ("x0x-linux-x64-gnu/x0xd", &content),
            ],
        );
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive, &output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
    }

    #[test]
    fn test_extract_refuses_archive_with_only_appledouble_sidecar() {
        let dir = TempDir::new().unwrap();
        let archive =
            create_tar_gz_with_entries(dir.path(), &[("._x0xd", b"\x00\x05\x16\x07 junk")]);
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
        assert!(!output.exists());
    }

    #[test]
    fn test_extract_refuses_zip_with_only_appledouble_sidecar() {
        let dir = TempDir::new().unwrap();
        let archive = create_zip_with_entries(dir.path(), &[("._x0xd.exe", b"junk")]);
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd.exe");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
        assert!(!output.exists());
    }

    #[test]
    fn test_extract_refuses_duplicate_binary_in_tar_gz() {
        let dir = TempDir::new().unwrap();
        let archive = create_tar_gz_with_entries(
            dir.path(),
            &[
                ("dir1/x0xd", &fake_binary(b"one")),
                ("dir2/x0xd", &fake_binary(b"two")),
            ],
        );
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd");
        assert!(matches!(
            &result,
            Err(UpgradeError::ExtractionError(msg)) if msg.contains("multiple entries")
        ));
        assert!(
            !output.exists(),
            "a refused duplicate must not leave a staged file"
        );
    }

    #[test]
    fn test_extract_refuses_duplicate_binary_in_zip() {
        let dir = TempDir::new().unwrap();
        let archive = create_zip_with_entries(
            dir.path(),
            &[
                ("dir1/x0xd.exe", &fake_binary(b"one")),
                ("dir2/x0xd.exe", &fake_binary(b"two")),
            ],
        );
        let output = dir.path().join("extracted");
        let result = extract_binary_from_archive(&archive, &output, "x0xd.exe");
        assert!(matches!(
            &result,
            Err(UpgradeError::ExtractionError(msg)) if msg.contains("multiple entries")
        ));
        assert!(
            !output.exists(),
            "a refused duplicate must not leave a staged file"
        );
    }

    #[test]
    fn test_extract_refuses_non_executable_magic() {
        let dir = TempDir::new().unwrap();
        let archive = create_test_tar_gz(dir.path(), "x0xd", b"#!/bin/sh\nnot a binary\n");
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd");
        assert!(matches!(
            &result,
            Err(UpgradeError::ExtractionError(msg)) if msg.contains("magic")
        ));
        assert!(
            !output.exists(),
            "a failed magic check must not leave the file staged"
        );
    }

    #[test]
    fn test_extract_skips_symlink_named_as_binary() {
        let dir = TempDir::new().unwrap();
        let content = fake_binary(b"real daemon");
        // A symlink whose basename matches, next to the real regular binary:
        // the entry-type filter must skip it and extract the regular file
        // (#1144), not merely fail for want of a match.
        let (mut builder, archive_path) = new_tar_gz(dir.path());
        append_entry(
            &mut builder,
            "x0xd",
            tar::EntryType::Symlink,
            Some("elsewhere"),
            b"",
        );
        append_entry(
            &mut builder,
            "x0x-linux-x64-gnu/x0xd",
            tar::EntryType::Regular,
            None,
            &content,
        );
        finish_tar_gz(builder);
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive_path, &output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
    }

    #[test]
    fn test_extract_refuses_hardlink_named_as_binary() {
        let dir = TempDir::new().unwrap();
        // A hard link whose basename matches is the only candidate: the
        // entry-type filter must skip it, so the apply is refused with
        // "not found" rather than staging the link's zero bytes (#1144).
        let (mut builder, archive_path) = new_tar_gz(dir.path());
        append_entry(
            &mut builder,
            "x0x-linux-x64-gnu/x0xd",
            tar::EntryType::Link,
            Some("other-entry"),
            b"",
        );
        finish_tar_gz(builder);
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive_path, &output, "x0xd");
        assert!(matches!(
            &result,
            Err(UpgradeError::ExtractionError(msg))
                if msg == "binary 'x0xd' not found in tar.gz archive"
        ));
        assert!(!output.exists());
    }

    #[test]
    fn test_extract_skips_zip_directory_named_as_binary() {
        let dir = TempDir::new().unwrap();
        let content = fake_binary(b"real daemon");
        // A directory entry whose name matches the binary (`add_directory`
        // stores it as `x0xd/`), next to the real regular file: the
        // entry-type filter must skip it and extract the regular file.
        let archive_path = dir.path().join("test.zip");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.add_directory("x0xd", options).unwrap();
        zip.start_file("x0x-linux-x64-gnu/x0xd", options).unwrap();
        zip.write_all(&content).unwrap();
        zip.finish().unwrap();
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive_path, &output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
    }

    #[cfg(unix)]
    fn assert_staged_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path).expect("staged path exists");
        assert!(
            meta.file_type().is_file(),
            "staged output must be a regular file"
        );
        let mode = meta.permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "extraction sets mode 0o755");
        assert_eq!(
            mode & 0o7000,
            0,
            "extraction must not keep setuid, setgid, or sticky"
        );
    }

    #[test]
    fn test_extract_skips_zip_symlink_named_as_binary() {
        let dir = TempDir::new().unwrap();
        let content = fake_binary(b"real daemon");
        // A symlink whose basename matches, next to the real regular file.
        // The entry-type filter must skip it and extract the regular file.
        // The symlink target must not be created on disk.
        let archive_path = dir.path().join("test.zip");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let escaped = dir.path().join("escaped-target");
        zip.add_symlink("x0xd", escaped.to_string_lossy(), options)
            .unwrap();
        zip.start_file("x0x-linux-x64-gnu/x0xd", options).unwrap();
        zip.write_all(&content).unwrap();
        zip.finish().unwrap();
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive_path, &output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
        assert!(std::fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_file());
        assert!(!escaped.exists(), "symlink target must not be created");
        #[cfg(unix)]
        assert_staged_executable(&output);
    }

    #[test]
    fn test_extract_refuses_zip_with_only_symlink() {
        let dir = TempDir::new().unwrap();
        let archive_path = dir.path().join("test.zip");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        // Absolute target outside the archive. Extraction must refuse the
        // entry and must not create a symlink at the output path.
        zip.add_symlink("x0xd", "/tmp/x0x-zip-symlink-outside", options)
            .unwrap();
        zip.finish().unwrap();
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive_path, &output, "x0xd");
        assert!(matches!(
            &result,
            Err(UpgradeError::ExtractionError(msg))
                if msg == "binary 'x0xd' not found in zip archive"
        ));
        assert!(
            std::fs::symlink_metadata(&output).is_err(),
            "a skipped symlink must not be staged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_extract_zip_forces_executable_mode() {
        let dir = TempDir::new().unwrap();
        let content = fake_binary(b"mode");
        let archive_path = dir.path().join("test.zip");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        // Regular file, mode 0o644, plus setuid, setgid, and sticky in the
        // high half of external_attributes. `unix_permissions` masks those
        // bits away, so the raw attributes are set directly.
        let crafted = 0o100644 | 0o7000;
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .system(zip::System::Unix)
            .external_attributes(crafted << 16);
        zip.start_file("x0xd", options).unwrap();
        zip.write_all(&content).unwrap();
        zip.finish().unwrap();
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive_path, &output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
        assert_staged_executable(&output);
    }

    #[cfg(unix)]
    #[test]
    fn test_extract_tar_gz_forces_executable_mode() {
        let dir = TempDir::new().unwrap();
        let content = fake_binary(b"mode");
        let (mut builder, archive_path) = new_tar_gz(dir.path());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(content.len() as u64);
        // setgid plus a non-executable mode. Extraction must stage 0o755.
        header.set_mode(0o2644);
        header.set_cksum();
        builder
            .append_data(&mut header, "x0xd", content.as_slice())
            .unwrap();
        finish_tar_gz(builder);
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive_path, &output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
        assert_staged_executable(&output);
    }

    #[test]
    fn test_extract_from_deflated_zip() {
        let dir = TempDir::new().unwrap();
        let content = fake_binary(b"deflated daemon");
        // Windows release zips are deflated (`Compress-Archive`). The default
        // method is deflate when that feature is enabled.
        let archive_path = dir.path().join("test.zip");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("x0xd.exe", options).unwrap();
        zip.write_all(&content).unwrap();
        zip.finish().unwrap();
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive_path, &output, "x0xd.exe").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
    }

    #[test]
    fn test_current_binary_path_resolves() {
        // Should resolve to something on any platform
        let path = current_binary_path().unwrap();
        assert!(path.is_absolute() || !path.to_string_lossy().is_empty());
    }

    #[test]
    fn auto_apply_upgrader_new_defaults() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        assert_eq!(upgrader.binary_name, "x0xd");
        assert!(!upgrader.stop_on_upgrade);
        assert!(upgrader.restart_on_success);
        assert!(upgrader.restart_context.data_dir.is_none());
    }

    #[test]
    fn auto_apply_upgrader_with_stop_on_upgrade() {
        let upgrader = AutoApplyUpgrader::new("x0x").with_stop_on_upgrade(true);
        assert!(upgrader.stop_on_upgrade);
    }

    #[test]
    fn auto_apply_upgrader_with_restart_context() {
        let context = RestartContext {
            data_dir: Some(PathBuf::from("/var/lib/x0x")),
            api_addr: Some("127.0.0.1:12700".parse().unwrap()),
            shutdown: None,
        };
        let upgrader = AutoApplyUpgrader::new("x0xd").with_restart_context(context);
        assert_eq!(
            upgrader.restart_context.data_dir.as_deref(),
            Some(Path::new("/var/lib/x0x"))
        );
        assert_eq!(
            upgrader.restart_context.api_addr,
            Some("127.0.0.1:12700".parse().unwrap())
        );
    }

    #[test]
    fn upgrader_restart_mode_routes_through_the_single_planner() {
        // Whatever flags/context an apply caller sets, the mode decision must
        // come from plan_restart_mode — there is no second ad-hoc exit path,
        // and no caller-local way to route around the ADR-0061 refusal.
        for stop in [true, false] {
            let upgrader = AutoApplyUpgrader::new("x0xd").with_stop_on_upgrade(stop);
            for signals in [
                restart::SupervisionSignals::default(),
                restart::SupervisionSignals {
                    invocation_id: true,
                    ..Default::default()
                },
                restart::SupervisionSignals {
                    parent_comm: Some("systemd".to_string()),
                    ..Default::default()
                },
            ] {
                assert_eq!(
                    upgrader.restart_mode_with(&signals),
                    restart::plan_restart_mode(stop, &signals),
                    "stop={stop}, signals={signals:?}"
                );
            }
        }
    }

    #[test]
    fn apply_path_refuses_conflicting_managed_config_before_any_replacement() {
        // ADR-0061 §1+§2 on the apply path itself: `resolve_restart_plan` is
        // what `apply_upgrade_from_manifest` calls before it downloads or
        // replaces anything, so a supervised instance configured with
        // stop_on_upgrade=false must fail here — with the current binary still
        // on disk and still serving — rather than after the swap.
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("x0xd");
        std::fs::write(&binary, b"current image").expect("write binary");

        let upgrader = AutoApplyUpgrader::new("x0xd")
            .with_stop_on_upgrade(false)
            .with_restart_context(RestartContext {
                data_dir: Some(dir.path().to_path_buf()),
                api_addr: None,
                shutdown: None,
            });

        // Sampled signals are the real environment, so drive the refusal
        // through the planner the resolver delegates to.
        let supervised = restart::SupervisionSignals {
            x0x_supervised: true,
            ..Default::default()
        };
        let err = upgrader
            .restart_mode_with(&supervised)
            .expect_err("supervised + stop_on_upgrade=false must be refused");
        assert!(matches!(
            err,
            restart::RestartOwnershipError::SupervisedRestartConflict { .. }
        ));
        assert_eq!(
            std::fs::read(&binary).expect("binary still present"),
            b"current image",
            "a refused apply must leave the installed binary untouched"
        );
    }

    #[test]
    fn auto_apply_upgrader_with_restart_on_success() {
        let upgrader = AutoApplyUpgrader::new("x0xd").with_restart_on_success(false);
        assert!(!upgrader.restart_on_success);
    }

    #[test]
    fn auto_apply_upgrader_chaining() {
        let upgrader = AutoApplyUpgrader::new("x0xd")
            .with_stop_on_upgrade(true)
            .with_restart_on_success(false);
        assert_eq!(upgrader.binary_name, "x0xd");
        assert!(upgrader.stop_on_upgrade);
        assert!(!upgrader.restart_on_success);
    }

    #[tokio::test]
    async fn apply_upgrade_rejects_invalid_manifest_version() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "not-a-version".to_string(),
            timestamp: 0,
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        let result = upgrader.apply_upgrade_from_manifest(&manifest).await;
        assert!(result.is_err(), "invalid version should fail");
        let err = format!("{:?}", result);
        assert!(
            err.contains("invalid version"),
            "error should mention invalid version: {err}"
        );
    }

    #[tokio::test]
    async fn apply_upgrade_rejects_downgrade() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        // Target version lower than current
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "0.1.0".to_string(),
            timestamp: 0,
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        let result = upgrader.apply_upgrade_from_manifest(&manifest).await;
        assert!(result.is_err(), "downgrade should fail");
        // The error may be NoPlatformAsset (checked before downgrade) or DowngradeAttempt
        // Both are valid error paths
    }

    #[tokio::test]
    async fn apply_upgrade_rejects_no_platform_asset() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        // Valid version but no assets matching current platform
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "99.99.99".to_string(),
            timestamp: 0,
            assets: vec![], // No platform assets
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        let result = upgrader.apply_upgrade_from_manifest(&manifest).await;
        assert!(result.is_err(), "no platform asset should fail");
        let err = format!("{:?}", result);
        assert!(
            err.contains("NoPlatformAsset"),
            "error should mention NoPlatformAsset: {err}"
        );
    }

    async fn serve_once(response: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}/archive")
    }

    #[tokio::test]
    async fn download_to_file_writes_successful_response_body() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("downloaded.bin");
        let body = "download bytes";
        let url = serve_once(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ))
        .await;

        download_to_file(&url, &destination).await.unwrap();
        assert_eq!(std::fs::read_to_string(destination).unwrap(), body);
    }

    #[tokio::test]
    async fn download_to_file_rejects_http_error_status() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("downloaded.bin");
        let url =
            serve_once("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found".to_string())
                .await;

        let result = download_to_file(&url, &destination).await;
        assert!(matches!(result, Err(UpgradeError::DownloadError(_))));
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn download_to_file_rejects_oversized_content_length() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("downloaded.bin");
        let too_large = super::super::MAX_BINARY_SIZE_BYTES + 1;
        let url = serve_once(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {too_large}\r\n\r\n"
        ))
        .await;

        let result = download_to_file(&url, &destination).await;
        assert!(matches!(result, Err(UpgradeError::BinaryTooLarge { .. })));
        assert!(!destination.exists());
    }

    /// Host lock waits must not stall the Tokio worker (#1447 RC1).
    ///
    /// On a current-thread runtime the polling thread is the only worker. If
    /// `File::lock` ran inline, a 20ms timer would only fire after the external
    /// holder released (here ~500ms). Offloading keeps the timer near 20ms.
    #[tokio::test(flavor = "current_thread")]
    async fn apply_replacements_offload_keeps_runtime_responsive_while_lock_held() {
        use std::fs::OpenOptions;
        use std::time::{Duration, Instant};

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("x0xd");
        let incoming = dir.path().join("incoming");
        let temp_dir = dir.path().join("upgrade-temp");
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::write(&target, b"original-v1").unwrap();
        std::fs::write(&incoming, b"candidate-v2").unwrap();

        let mut lock_name = target.file_name().unwrap().to_os_string();
        lock_name.push(".upgrade.lock");
        let lock_path = target.with_file_name(lock_name);

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .expect("open host lock");
            file.lock().expect("hold host lock");
            ready_tx.send(()).expect("signal lock held");
            std::thread::sleep(Duration::from_millis(500));
            drop(file);
        });
        ready_rx.recv().expect("holder ready");

        let upgrader = Upgrader::new(target, semver::Version::parse("1.0.0").unwrap());
        let temp_guard = TempDirGuard {
            path: temp_dir.clone(),
        };
        // Keep a second path under temp so Drop has something to remove.
        std::fs::write(temp_dir.join("marker"), b"keep").unwrap();

        let apply = apply_replacements_offloaded(
            upgrader,
            incoming,
            semver::Version::parse("2.0.0").unwrap(),
            None,
            temp_guard,
            None,
            None,
        );

        let start = Instant::now();
        tokio::pin!(apply);
        tokio::select! {
            biased;
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let elapsed = start.elapsed();
                assert!(
                    elapsed < Duration::from_millis(200),
                    "20ms Tokio timer stalled for {elapsed:?}; host lock wait must not run on the runtime worker"
                );
            }
            _ = &mut apply => {
                panic!("apply finished before the responsiveness probe timer; holder should still own the lock");
            }
        }

        // Finish the upgrade after the holder releases.
        let result = apply.await.expect("offloaded replace");
        assert!(matches!(result, UpgradeResult::Success { .. }));
        holder.join().expect("lock holder thread");
    }

    static HOST_LOCK_ATTEMPTS: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, tokio::sync::oneshot::Sender<()>>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    struct HostLockAttemptGuard(PathBuf);

    impl Drop for HostLockAttemptGuard {
        fn drop(&mut self) {
            HOST_LOCK_ATTEMPTS
                .lock()
                .expect("host lock attempt hooks")
                .remove(&self.0);
        }
    }

    fn observe_host_lock_attempt(
        target: &Path,
    ) -> (HostLockAttemptGuard, tokio::sync::oneshot::Receiver<()>) {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        assert!(HOST_LOCK_ATTEMPTS
            .lock()
            .expect("host lock attempt hooks")
            .insert(target.to_path_buf(), sender)
            .is_none());
        (HostLockAttemptGuard(target.to_path_buf()), receiver)
    }

    // Each acknowledgement is tied to one fixture path. It fires immediately
    // before the real lock call, with no intervening cancellation check. Thus
    // the held lock keeps custody even if the caller cancels after this send.
    pub(super) fn acknowledge_host_lock_attempt(target: &Path) {
        let sender = HOST_LOCK_ATTEMPTS
            .lock()
            .expect("host lock attempt hooks")
            .remove(target);
        if let Some(sender) = sender {
            let _ = sender.send(());
        }
    }

    /// Hold a host lock, acknowledge the worker's lock attempt, abort, then
    /// release. After cancel the host must not keep replaced bytes without a
    /// restart continuation (Codex P1 on b937a806 / #1447 RC2).
    async fn cancel_while_lock_held_must_not_orphan_restart(hold_companion: bool) {
        use std::fs::OpenOptions;
        use std::time::Duration;

        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let primary = root.path().join("x0xd");
        let cli = root.path().join("x0x");
        std::fs::write(&primary, b"old-daemon").unwrap();
        std::fs::write(&cli, b"old-cli").unwrap();
        let incoming = scratch.join("daemon");
        let incoming_cli = scratch.join("cli");
        std::fs::write(&incoming, b"new-daemon").unwrap();
        std::fs::write(&incoming_cli, b"new-cli").unwrap();

        let held_target = if hold_companion { &cli } else { &primary };
        let mut lock_name = held_target.file_name().unwrap().to_os_string();
        lock_name.push(".upgrade.lock");
        let lock_path = held_target.with_file_name(lock_name);
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open held host lock");
        held.lock().expect("hold host lock");
        let (_lock_attempt, waiting_rx) = observe_host_lock_attempt(held_target);

        let restart_marker = root.path().join("restart-continuation");
        let marker = restart_marker.clone();
        let scratch_for_task = scratch.clone();
        let upgrade = Upgrader::new(primary.clone(), semver::Version::new(1, 0, 0));
        let companion = hold_companion.then(|| {
            (
                Upgrader::new(cli.clone(), semver::Version::new(1, 0, 0)),
                incoming_cli,
            )
        });
        let task = tokio::spawn(async move {
            // Worker-owned continuation: same ownership site as production
            // restart_on_success (RC3). Pre-admission cancel must not run it.
            let on_success: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
                std::fs::write(&marker, b"restart reached").unwrap();
            }));
            apply_replacements_offloaded(
                upgrade,
                incoming,
                semver::Version::new(2, 0, 0),
                companion,
                TempDirGuard {
                    path: scratch_for_task,
                },
                on_success,
                None,
            )
            .await?;
            Ok::<_, UpgradeError>(())
        });

        // Pending only proves submission. In the daemon-only case a queued
        // worker can observe cancellation before its lock call and correctly
        // remove scratch. Wait until that early-return gate is behind it.
        tokio::time::timeout(Duration::from_secs(3), waiting_rx)
            .await
            .expect("worker reached held host lock within timeout")
            .expect("host lock attempt acknowledgement");
        assert_eq!(
            std::fs::read(&primary).unwrap(),
            b"old-daemon",
            "must still be waiting on the held lock"
        );
        assert!(!restart_marker.exists());

        task.abort();
        assert!(
            task.await.unwrap_err().is_cancelled(),
            "caller must observe abort"
        );
        assert!(
            scratch.exists(),
            "blocking worker must retain temp-dir custody across cancel"
        );
        drop(held);

        tokio::time::timeout(Duration::from_secs(3), async {
            while scratch.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("temp-dir custody must release after the worker finishes");

        let installed = std::fs::read(&primary).unwrap() == b"new-daemon";
        let companion_installed = hold_companion && std::fs::read(&cli).unwrap() == b"new-cli";
        let restarted = restart_marker.exists();
        assert!(
            !installed,
            "cancelled caller must not leave the daemon binary replaced without restart ownership"
        );
        assert!(
            !companion_installed,
            "cancelled caller must not leave the companion binary replaced without restart ownership"
        );
        assert!(
            !installed || restarted,
            "replacement must not outlive its restart continuation"
        );
        assert!(!restarted, "pre-admission cancel must not restart");
        assert!(!primary.with_extension("backup").exists());
        assert!(!cli.with_extension("backup").exists());
        assert_eq!(std::fs::read(&primary).unwrap(), b"old-daemon");
        if hold_companion {
            assert_eq!(std::fs::read(&cli).unwrap(), b"old-cli");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_while_daemon_lock_held_must_not_orphan_restart() {
        cancel_while_lock_held_must_not_orphan_restart(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_while_companion_lock_held_must_not_orphan_restart() {
        cancel_while_lock_held_must_not_orphan_restart(true).await;
    }

    /// Force the other legal ordering behind #1537: the worker has entered,
    /// but cancellation reaches it before the daemon-lock check. Scratch must
    /// then be removed even while another owner still holds the daemon lock.
    #[tokio::test(flavor = "current_thread")]
    async fn cancel_before_daemon_lock_releases_scratch_without_mutation() {
        use std::time::Duration;

        let root = TempDir::new().unwrap();
        let primary = root.path().join("x0xd");
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        std::fs::write(&primary, b"old-daemon").unwrap();
        let incoming = scratch.join("daemon");
        std::fs::write(&incoming, b"new-daemon").unwrap();
        let held = super::super::acquire_host_upgrade_lock(&primary).unwrap();
        let (_lock_attempt, mut lock_attempt) = observe_host_lock_attempt(&primary);
        let restart_marker = root.path().join("restart-continuation");
        let marker = restart_marker.clone();

        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let (release, wait) = std::sync::mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let permit = ReleasePermit {
            observer: Some(Arc::new(move |entered| {
                let _ = events.send(entered);
                if entered {
                    // Dropping the sender also releases this worker on panic.
                    let _ = wait.lock().unwrap().recv();
                }
            })),
            ..ReleasePermit::default()
        };
        let mut replacement = Box::pin(apply_replacements_with_permit(
            Upgrader::new(primary.clone(), semver::Version::new(1, 0, 0)),
            incoming,
            semver::Version::new(2, 0, 0),
            None,
            TempDirGuard {
                path: scratch.clone(),
            },
            Some(Box::new(move || {
                std::fs::write(marker, b"restart reached").unwrap();
            })),
            None,
            Some(&permit),
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                result = &mut replacement => panic!("worker ended before release: {result:?}"),
                entered = observed.recv() => assert_eq!(entered, Some(true)),
            }
        })
        .await
        .expect("worker entered");

        drop(replacement);
        assert!(scratch.exists(), "paused worker still owns scratch");
        release.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), observed.recv())
                .await
                .expect("cancelled worker finished without the daemon lock"),
            Some(false)
        );
        assert!(matches!(
            lock_attempt.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert!(!scratch.exists(), "finished worker releases scratch");
        assert_eq!(std::fs::read(&primary).unwrap(), b"old-daemon");
        assert!(!primary.with_extension("backup").exists());
        assert!(!restart_marker.exists());
        drop(held);
    }

    /// Live control: with companion lock held then released, both installs and
    /// the restart continuation complete together.
    #[tokio::test(flavor = "current_thread")]
    async fn live_companion_lock_retains_restart_continuation() {
        use std::fs::OpenOptions;
        use std::future::{poll_fn, Future};
        use std::time::Duration;

        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let primary = root.path().join("x0xd");
        let cli = root.path().join("x0x");
        std::fs::write(&primary, b"old-daemon").unwrap();
        std::fs::write(&cli, b"old-cli").unwrap();
        let incoming = scratch.join("daemon");
        let incoming_cli = scratch.join("cli");
        std::fs::write(&incoming, b"new-daemon").unwrap();
        std::fs::write(&incoming_cli, b"new-cli").unwrap();

        let mut lock_name = cli.file_name().unwrap().to_os_string();
        lock_name.push(".upgrade.lock");
        let lock_path = cli.with_file_name(lock_name);
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open companion host lock");
        held.lock().expect("hold companion lock");

        let restart_marker = root.path().join("restart-continuation");
        let marker = restart_marker.clone();
        let scratch_for_task = scratch.clone();
        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let on_success: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
                std::fs::write(&marker, b"restart reached").unwrap();
            }));
            let replacement = apply_replacements_offloaded(
                Upgrader::new(primary, semver::Version::new(1, 0, 0)),
                incoming,
                semver::Version::new(2, 0, 0),
                Some((
                    Upgrader::new(cli, semver::Version::new(1, 0, 0)),
                    incoming_cli,
                )),
                TempDirGuard {
                    path: scratch_for_task,
                },
                on_success,
                None,
            );
            tokio::pin!(replacement);
            let mut waiting_tx = Some(waiting_tx);
            let result = poll_fn(|cx| {
                let polled = replacement.as_mut().poll(cx);
                if polled.is_pending() {
                    if let Some(tx) = waiting_tx.take() {
                        let _ = tx.send(());
                    }
                }
                polled
            })
            .await?;
            let _ = result;
            Ok::<_, UpgradeError>(())
        });

        tokio::time::timeout(Duration::from_secs(3), waiting_rx)
            .await
            .expect("offload submitted")
            .expect("waiting signal");
        drop(held);
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("live apply timeout")
            .expect("join")
            .expect("apply");

        assert_eq!(
            std::fs::read(root.path().join("x0xd")).unwrap(),
            b"new-daemon"
        );
        assert_eq!(std::fs::read(root.path().join("x0x")).unwrap(), b"new-cli");
        assert!(
            restart_marker.exists(),
            "live success must reach the restart continuation"
        );
        assert!(!scratch.exists(), "temp-dir custody must clean up");
    }

    /// Pause the blocking worker at the existing `Replacing binary...` event
    /// (after backup, after the final caller-alive check, before rename) so
    /// cancel can land in the admitted window Codex probed on a29beec8.
    ///
    /// Hooks are keyed by `replace_target` path so parallel libtest workers
    /// cannot overwrite or consume each other's pause (Codex/Greptile RC6 P2).
    struct PauseAtReplacingBinary;

    struct ReplaceHook {
        entered: tokio::sync::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    static REPLACE_HOOKS: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, ReplaceHook>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    static REPLACE_HOOK_INIT: std::sync::Once = std::sync::Once::new();

    /// Removes a registered pause hook on drop so a failed test cannot leave a
    /// stale entry that later steals another worker's replace event.
    struct ReplaceHookGuard {
        target: PathBuf,
    }

    impl Drop for ReplaceHookGuard {
        fn drop(&mut self) {
            let mut hooks = REPLACE_HOOKS.lock().expect("replace hooks lock");
            hooks.remove(&self.target);
        }
    }

    #[derive(Default)]
    struct TraceReplaceFields {
        message: String,
        replace_target: Option<String>,
    }

    impl tracing::field::Visit for TraceReplaceFields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let rendered = format!("{value:?}");
            let unquoted = rendered.trim_matches('"');
            if field.name() == "message" {
                self.message = unquoted.to_string();
            } else if field.name() == "replace_target" {
                self.replace_target = Some(unquoted.to_string());
            }
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.message = value.to_string();
            } else if field.name() == "replace_target" {
                self.replace_target = Some(value.to_string());
            }
        }
    }

    impl tracing::Subscriber for PauseAtReplacingBinary {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }
        fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
            Some(tracing::metadata::LevelFilter::TRACE)
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = TraceReplaceFields::default();
            event.record(&mut fields);
            if fields.message != "Replacing binary..." {
                return;
            }
            let Some(target_s) = fields.replace_target else {
                return;
            };
            let target = PathBuf::from(target_s);
            let hook = {
                let mut hooks = REPLACE_HOOKS.lock().expect("replace hooks lock");
                hooks.remove(&target)
            };
            if let Some(h) = hook {
                let _ = h.entered.send(());
                h.release
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("test must release paused replace worker");
            }
        }
    }

    /// Cancel after admission (locks held + alive), between companion/primary
    /// renames, and before the await result is consumed. Installed bytes must
    /// not outlive the restart continuation (Codex P1 on a29beec8 / #1447 RC3).
    async fn cancel_after_admission_must_retain_restart(
        cancel: bool,
        companion: bool,
        pause_number: usize,
    ) {
        use std::time::Duration;

        REPLACE_HOOK_INIT.call_once(|| {
            tracing::subscriber::set_global_default(PauseAtReplacingBinary)
                .expect("install replace-pause subscriber once");
        });

        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let primary = root.path().join("x0xd");
        let cli = root.path().join("x0x");
        std::fs::write(&primary, b"old-daemon").unwrap();
        std::fs::write(&cli, b"old-cli").unwrap();
        let incoming = scratch.join("daemon");
        let incoming_cli = scratch.join("cli");
        std::fs::write(&incoming, b"new-daemon").unwrap();
        std::fs::write(&incoming_cli, b"new-cli").unwrap();

        let restart_marker = root.path().join("restart-continuation");
        let marker = restart_marker.clone();
        let scratch_for_task = scratch.clone();
        let primary_for_task = primary.clone();
        let cli_for_task = cli.clone();

        // pause_number 1 with companion → first replace (cli); otherwise primary.
        // Key the hook to that exact path so concurrent tests cannot steal it.
        let paused_target = if companion && pause_number == 1 {
            cli.clone()
        } else {
            primary.clone()
        };
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        {
            let mut hooks = REPLACE_HOOKS.lock().expect("replace hooks lock");
            hooks.insert(
                paused_target.clone(),
                ReplaceHook {
                    entered: entered_tx,
                    release: release_rx,
                },
            );
        }
        let _hook_guard = ReplaceHookGuard {
            target: paused_target.clone(),
        };

        let task = tokio::spawn(async move {
            // Worker-owned restart continuation (production restart_on_success
            // site). Survives abort of this async observer after admission.
            let on_success: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
                std::fs::write(&marker, b"restart reached").unwrap();
            }));
            let result = apply_replacements_offloaded(
                Upgrader::new(primary_for_task, semver::Version::new(1, 0, 0)),
                incoming,
                semver::Version::new(2, 0, 0),
                companion.then(|| {
                    (
                        Upgrader::new(cli_for_task, semver::Version::new(1, 0, 0)),
                        incoming_cli,
                    )
                }),
                TempDirGuard {
                    path: scratch_for_task,
                },
                on_success,
                None,
            )
            .await?;
            let _ = result;
            Ok::<_, UpgradeError>(())
        });

        tokio::time::timeout(Duration::from_secs(3), entered_rx)
            .await
            .expect("worker reached Replacing binary...")
            .expect("entered signal");

        let expected_old: &[u8] = if companion && pause_number == 1 {
            b"old-cli"
        } else {
            b"old-daemon"
        };
        assert_eq!(std::fs::read(&paused_target).unwrap(), expected_old);
        assert_eq!(
            std::fs::read(paused_target.with_extension("backup")).unwrap(),
            expected_old
        );
        assert!(!restart_marker.exists());

        // Trace-hook pause is on the blocking pool; async timers still progress.
        tokio::time::timeout(
            Duration::from_millis(200),
            tokio::time::sleep(Duration::from_millis(10)),
        )
        .await
        .expect("runtime stays responsive while replace is paused");

        if cancel {
            task.abort();
            assert!(
                task.await.unwrap_err().is_cancelled(),
                "caller must observe abort"
            );
            assert!(
                scratch.exists(),
                "blocking worker must retain temp-dir custody across cancel"
            );
            release_tx.send(()).expect("release paused worker");
        } else {
            release_tx.send(()).expect("release paused worker");
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .expect("live apply timeout")
                .expect("join")
                .expect("apply");
        }

        // RC4 drops temp custody before on_success, so "scratch gone" is no
        // longer a proxy for "continuation finished". Wait for the restart
        // marker (or settle), then assert cleanup.
        tokio::time::timeout(Duration::from_secs(3), async {
            while !restart_marker.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("restart continuation must run after admission");
        tokio::time::timeout(Duration::from_secs(3), async {
            while scratch.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("temp-dir custody must release after the worker finishes");

        let installed = std::fs::read(&primary).unwrap() == b"new-daemon";
        let cli_installed = companion && std::fs::read(&cli).unwrap() == b"new-cli";
        let restarted = restart_marker.exists();
        assert_eq!(
            std::fs::read(primary.with_extension("backup")).unwrap(),
            b"old-daemon"
        );
        if companion {
            assert_eq!(
                std::fs::read(cli.with_extension("backup")).unwrap(),
                b"old-cli"
            );
        }
        assert!(installed, "admitted replace must install daemon bytes");
        if companion {
            assert!(
                cli_installed,
                "admitted replace must install companion bytes"
            );
        }
        assert!(
            !installed || restarted,
            "replacement must not outlive its restart continuation after admission \
             (cancel={cancel}, companion={companion}, pause_number={pause_number}, \
             installed={installed}, cli_installed={cli_installed}, restarted={restarted})"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_primary_after_admission_retains_restart() {
        cancel_after_admission_must_retain_restart(false, false, 1).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_companion_after_admission_retains_restart() {
        cancel_after_admission_must_retain_restart(false, true, 1).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_after_admission_primary_must_retain_restart() {
        cancel_after_admission_must_retain_restart(true, false, 1).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_after_admission_companion_must_retain_restart() {
        cancel_after_admission_must_retain_restart(true, true, 1).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_between_companion_and_primary_must_retain_restart() {
        cancel_after_admission_must_retain_restart(true, true, 2).await;
    }

    /// Cancel after the blocking worker has finished (bytes installed) but
    /// before the abortable caller consumes Success for restart.
    #[tokio::test(flavor = "current_thread")]
    async fn cancel_before_result_consumed_must_retain_restart() {
        use std::future::{poll_fn, Future};
        use std::task::Poll;
        use std::time::Duration;

        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let primary = root.path().join("x0xd");
        std::fs::write(&primary, b"old-daemon").unwrap();
        let incoming = scratch.join("daemon");
        std::fs::write(&incoming, b"new-daemon").unwrap();

        let restart_marker = root.path().join("restart-continuation");
        let marker = restart_marker.clone();
        let scratch_for_task = scratch.clone();
        let primary_watch = primary.clone();

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let on_success: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
                std::fs::write(&marker, b"restart reached").unwrap();
            }));
            let replacement = apply_replacements_offloaded(
                Upgrader::new(primary, semver::Version::new(1, 0, 0)),
                incoming,
                semver::Version::new(2, 0, 0),
                None,
                TempDirGuard {
                    path: scratch_for_task,
                },
                on_success,
                None,
            );
            tokio::pin!(replacement);
            let mut done_tx = Some(done_tx);
            // Observe Ready (worker finished + on_success ran) then park so
            // this abortable observer never "consumes" Success for restart.
            poll_fn(|cx| -> Poll<()> {
                match replacement.as_mut().poll(cx) {
                    Poll::Ready(r) => {
                        if let Some(tx) = done_tx.take() {
                            let _ = tx.send(());
                        }
                        drop(r);
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            unreachable!("caller parked after Ready; abort must win");
        });

        // Wait until daemon bytes are installed (worker finished replace).
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if std::fs::read(&primary_watch).ok().as_deref() == Some(b"new-daemon".as_slice()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("worker must install bytes");
        let _ = tokio::time::timeout(Duration::from_secs(1), done_rx).await;

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        tokio::time::timeout(Duration::from_secs(3), async {
            while !restart_marker.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("restart continuation must run despite late cancel");
        tokio::time::timeout(Duration::from_secs(3), async {
            while scratch.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("temp-dir custody must release");

        let installed = std::fs::read(&primary_watch).unwrap() == b"new-daemon";
        let restarted = restart_marker.exists();
        assert!(installed, "bytes must stay installed after late cancel");
        assert!(
            !installed || restarted,
            "late cancel before result consumption must not detach restart \
             (installed={installed}, restarted={restarted})"
        );
    }

    /// RC5: `Builder::spawn` WouldBlock before mutation must refuse the apply
    /// (no host bytes changed, no Success / restart_scheduled without an owner).
    /// Red on RC4 (`f2f10b22`): spawn ran inside `on_success` after replace,
    /// warned, and still returned Success with the only owner dropped.
    #[tokio::test(flavor = "current_thread")]
    async fn http_deferred_spawn_failure_refuses_before_host_mutation() {
        let _seam = deferred_spawn_seam::force_would_block();

        let root = TempDir::new().unwrap();
        let primary = root.path().join("x0xd");
        let old = b"old-daemon";
        std::fs::write(&primary, old).unwrap();
        let data_root = root.path().join("data");
        std::fs::create_dir(&data_root).unwrap();

        let plan = restart::RestartPlan {
            mode: restart::RestartMode::TransactionalHandoff,
            supervised_exit_code: None,
            supervision_signal: None,
            executable: primary.clone(),
            argv: vec!["x0xd".into()],
            cwd: root.path().to_path_buf(),
            data_root,
            api_addr: "127.0.0.1:9".parse().unwrap(),
            launchd_verified: None,
            systemd_verified: None,
        };

        let arm = arm_http_deferred_restart_owner(
            "x0xd".into(),
            true,
            RestartContext::default(),
            plan,
            "2.0.0".into(),
        );
        assert!(
            arm.is_err(),
            "spawn failure must refuse before apply_replacements_offloaded"
        );
        assert_eq!(
            std::fs::read(&primary).unwrap(),
            old,
            "host bytes must be untouched when deferred-owner spawn fails"
        );

        // Control flow mirror of apply_upgrade_from_manifest: never call
        // apply_replacements_offloaded when arming fails.
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let incoming = scratch.join("daemon");
        std::fs::write(&incoming, b"new-daemon").unwrap();
        // No on_success / no offload — production returns Err at arm time.
        assert_eq!(std::fs::read(&primary).unwrap(), old);
        assert!(
            incoming.exists(),
            "incoming must remain when apply is refused"
        );
    }

    /// RC5: production arming + offload keeps exactly one owner when spawn works,
    /// and never reaches offload when spawn fails (paired with refuse test).
    #[tokio::test(flavor = "current_thread")]
    async fn http_deferred_arm_then_admission_runs_exactly_one_restart() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::time::Duration;

        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let primary = root.path().join("x0xd");
        std::fs::write(&primary, b"old-daemon").unwrap();
        let incoming = scratch.join("daemon");
        std::fs::write(&incoming, b"new-daemon").unwrap();
        let data_root = root.path().join("data");
        std::fs::create_dir(&data_root).unwrap();

        let restart_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&restart_count);
        // Production arm path, but restart body writes a counter instead of
        // trigger_restart (avoid non-returning handoff in-unit).
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        spawn_http_deferred_restart_thread(move || {
            if go_rx.recv().is_ok() {
                std::thread::sleep(HTTP_DEFERRED_RESTART_DELAY);
                counter.fetch_add(1, AtomicOrdering::SeqCst);
            }
        })
        .expect("normal spawn must succeed");
        let on_success: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
            let _ = go_tx.send(());
        }));

        let result = apply_replacements_offloaded(
            Upgrader::new(primary, semver::Version::new(1, 0, 0)),
            incoming,
            semver::Version::new(2, 0, 0),
            None,
            TempDirGuard { path: scratch },
            on_success,
            None,
        )
        .await
        .expect("replace");
        assert!(matches!(result, UpgradeResult::Success { .. }));

        tokio::time::timeout(Duration::from_secs(3), async {
            while restart_count.load(AtomicOrdering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("deferred owner must fire");
        tokio::time::sleep(HTTP_DEFERRED_RESTART_DELAY + Duration::from_millis(100)).await;
        assert_eq!(
            restart_count.load(AtomicOrdering::SeqCst),
            1,
            "exactly one deferred restart owner after admission"
        );
    }

    /// RC4: `restart_on_success=false` with a context and no HTTP deferred
    /// opt-in must never arm a restart owner. This is a library configuration,
    /// not the report-only `x0xd --check-updates` path.
    #[test]
    fn cli_false_with_context_does_not_arm_http_deferred_restart() {
        let upgrader = AutoApplyUpgrader::new("x0xd")
            .with_restart_on_success(false)
            .with_restart_context(RestartContext {
                data_dir: Some(PathBuf::from("/var/lib/x0x")),
                api_addr: Some("127.0.0.1:12700".parse().unwrap()),
                shutdown: None,
            });
        assert!(!upgrader.restart_on_success);
        assert!(
            !upgrader.http_deferred_restart,
            "restart-disabled callers must not opt into HTTP deferred restart"
        );
    }

    /// RC4: HTTP apply opts in explicitly; public false alone is unchanged.
    #[test]
    fn http_deferred_restart_is_explicit_crate_opt_in() {
        let plain = AutoApplyUpgrader::new("x0xd").with_restart_on_success(false);
        assert!(!plain.http_deferred_restart);
        let http = plain.with_http_deferred_restart(true);
        assert!(!http.restart_on_success);
        assert!(http.http_deferred_restart);
    }

    /// RC4: after admission, a deferred OS-thread owner still fires exactly once
    /// when the async caller is cancelled during the defer window.
    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_http_deferred_window_retains_exactly_one_restart() {
        use std::future::{poll_fn, Future};
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::task::Poll;
        use std::time::Duration;

        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let primary = root.path().join("x0xd");
        std::fs::write(&primary, b"old-daemon").unwrap();
        let incoming = scratch.join("daemon");
        std::fs::write(&incoming, b"new-daemon").unwrap();

        let restart_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&restart_count);
        let scratch_for_task = scratch.clone();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let entered_worker = Arc::clone(&entered);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            // Mirrors production HTTP deferred ownership: arm at admission on
            // an OS thread (not a cancellable Tokio task), sleep, then restart.
            let on_success: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
                std::thread::spawn(move || {
                    entered_worker.wait();
                    std::thread::sleep(HTTP_DEFERRED_RESTART_DELAY);
                    counter.fetch_add(1, AtomicOrdering::SeqCst);
                });
            }));
            let replacement = apply_replacements_offloaded(
                Upgrader::new(primary, semver::Version::new(1, 0, 0)),
                incoming,
                semver::Version::new(2, 0, 0),
                None,
                TempDirGuard {
                    path: scratch_for_task,
                },
                on_success,
                None,
            );
            tokio::pin!(replacement);
            let mut ready_tx = Some(ready_tx);
            // Park after Ready so abort can still cancel this observer during
            // the OS-thread defer window (apply itself returns quickly).
            poll_fn(|cx| -> Poll<()> {
                match replacement.as_mut().poll(cx) {
                    Poll::Ready(r) => {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(r);
                        }
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            unreachable!("caller parked after Ready; abort must win");
        });

        let apply_result = tokio::time::timeout(Duration::from_secs(3), ready_rx)
            .await
            .expect("apply ready timeout")
            .expect("ready signal");
        assert!(
            matches!(apply_result, Ok(UpgradeResult::Success { .. })),
            "apply must succeed before deferred restart: {apply_result:?}"
        );

        // Deferred owner armed at admission; sync into its sleep window.
        tokio::task::spawn_blocking(move || {
            entered.wait();
        })
        .await
        .expect("barrier wait");
        assert_eq!(restart_count.load(AtomicOrdering::SeqCst), 0);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        tokio::time::timeout(Duration::from_secs(3), async {
            while restart_count.load(AtomicOrdering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("deferred owner must fire after cancel");
        // Allow a second tick window to prove we do not double-fire.
        tokio::time::sleep(HTTP_DEFERRED_RESTART_DELAY + Duration::from_millis(100)).await;
        assert_eq!(
            restart_count.load(AtomicOrdering::SeqCst),
            1,
            "exactly one deferred restart owner"
        );
        assert!(
            !scratch.exists(),
            "temp custody must be cleaned before deferred continuation returns"
        );
    }

    /// RC4 P2: success continuation must observe temp custody already released
    /// (so a later `process::exit` / `_exit` cannot skip cleanup). Red on RC3
    /// where `cont()` ran while `_temp_custody` was still alive.
    #[tokio::test(flavor = "current_thread")]
    async fn success_continuation_sees_temp_already_cleaned() {
        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        std::fs::write(scratch.join("archive.bin"), b"payload").unwrap();
        let primary = root.path().join("x0xd");
        std::fs::write(&primary, b"old-daemon").unwrap();
        let incoming = scratch.join("daemon");
        std::fs::write(&incoming, b"new-daemon").unwrap();

        let scratch_watch = scratch.clone();
        let cleaned_before_cont = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cleaned_before_cont);
        let on_success: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
            flag.store(!scratch_watch.exists(), Ordering::SeqCst);
        }));

        let result = apply_replacements_offloaded(
            Upgrader::new(primary, semver::Version::new(1, 0, 0)),
            incoming,
            semver::Version::new(2, 0, 0),
            None,
            TempDirGuard { path: scratch },
            on_success,
            None,
        )
        .await
        .expect("replace");
        assert!(matches!(result, UpgradeResult::Success { .. }));
        assert!(
            cleaned_before_cont.load(Ordering::SeqCst),
            "temp custody must be dropped before on_success runs"
        );
    }

    /// RC4 P2 child-process: drop custody then `process::exit` (no destructor
    /// unwind). Parent asserts the scratch directory is gone — proves cleanup
    /// is not relying on Drop after a non-returning restart.
    #[test]
    fn process_exit_after_temp_drop_leaves_no_scratch() {
        use std::process::{Command, Stdio};

        const CHILD_ENV: &str = "X0X_1447_RC4_EXIT_CLEANUP_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let scratch = PathBuf::from(std::env::var("X0X_1447_RC4_SCRATCH").unwrap());
            let marker = PathBuf::from(std::env::var("X0X_1447_RC4_MARKER").unwrap());
            let custody = TempDirGuard {
                path: scratch.clone(),
            };
            drop(custody);
            std::fs::write(&marker, b"exiting").unwrap();
            // process::exit does not run destructors — custody must already
            // have been dropped (same constraint as supervised restart exit).
            std::process::exit(0);
        }

        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        std::fs::write(scratch.join("archive.bin"), b"payload").unwrap();
        let marker = root.path().join("marker");

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "upgrade::apply::tests::process_exit_after_temp_drop_leaves_no_scratch",
            ])
            .env(CHILD_ENV, "1")
            .env("X0X_1447_RC4_SCRATCH", &scratch)
            .env("X0X_1447_RC4_MARKER", &marker)
            .env("RUST_TEST_THREADS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .expect("spawn exit-cleanup child");
        assert!(status.success(), "child exited with {status}");
        assert!(marker.exists(), "child must reach the exit continuation");
        assert!(
            !scratch.exists(),
            "temp dir must be gone after drop-before-process::exit"
        );
    }
}
