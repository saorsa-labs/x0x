//! Route handlers (`category: "upgrade"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::api_error;
use super::super::state::{AppState, CachedUpgradeCheck, DaemonConfig, DaemonUpdateConfig};
use crate as x0x;
use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Mutex};
use x0x::upgrade::apply::{ApplySummary, AutoApplyUpgrader, RestartContext};
use x0x::upgrade::manifest::{decode_signed_manifest, is_newer, ReleaseManifest, RELEASE_TOPIC};
use x0x::upgrade::monitor::UpgradeMonitor;
use x0x::upgrade::restart::RestartOwnershipError;
use x0x::upgrade::rollout::{RolloutState, RolloutTrigger, StagedRelease};
use x0x::upgrade::signature::verify_manifest_signature;
use x0x::Agent;

const UPGRADE_CHECK_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

const UPGRADE_CHECK_ERROR_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

const RELEASE_REBROADCAST_INTERVAL: Duration = Duration::from_secs(300);

const SELF_PUBLISHED_RELEASE_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Default)]
pub(in crate::server) struct SelfPublishedReleaseManifests {
    published_at: HashMap<[u8; 32], Instant>,
}

impl SelfPublishedReleaseManifests {
    fn record_payload(&mut self, payload: &[u8], now: Instant) {
        self.prune(now);
        self.published_at
            .insert(release_manifest_payload_digest(payload), now);
    }

    fn contains_recent_digest(&mut self, digest: &[u8; 32], now: Instant) -> bool {
        self.prune(now);
        self.published_at.contains_key(digest)
    }

    fn prune(&mut self, now: Instant) {
        self.published_at.retain(|_, first_seen| {
            now.saturating_duration_since(*first_seen) < SELF_PUBLISHED_RELEASE_TTL
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseRebroadcastDecision {
    Rebroadcast,
    SkipNotNewer,
    SkipSelfPublished,
    SkipRecentlyRebroadcasted,
}

fn release_manifest_payload_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

fn decide_release_manifest_rebroadcast(
    manifest_version: &str,
    current_version: &str,
    payload_digest: [u8; 32],
    rebroadcasted_versions: &mut HashMap<String, Instant>,
    self_published: &mut SelfPublishedReleaseManifests,
    now: Instant,
) -> ReleaseRebroadcastDecision {
    if !is_newer(manifest_version, current_version) {
        return ReleaseRebroadcastDecision::SkipNotNewer;
    }

    if self_published.contains_recent_digest(&payload_digest, now) {
        return ReleaseRebroadcastDecision::SkipSelfPublished;
    }

    match rebroadcasted_versions.get(manifest_version) {
        Some(last) if now.saturating_duration_since(*last) < RELEASE_REBROADCAST_INTERVAL => {
            ReleaseRebroadcastDecision::SkipRecentlyRebroadcasted
        }
        _ => {
            rebroadcasted_versions.insert(manifest_version.to_string(), now);
            // Keep the active version window compact. publish() re-signs the
            // PlumTree envelope, so unbounded historical versions would keep
            // producing fresh gossip message IDs after their interval expires.
            if rebroadcasted_versions.len() > 2 {
                rebroadcasted_versions.clear();
                rebroadcasted_versions.insert(manifest_version.to_string(), now);
            }
            ReleaseRebroadcastDecision::Rebroadcast
        }
    }
}

// ---------------------------------------------------------------------------
// Restart plumbing (#261): every apply caller builds the same planner context
// ---------------------------------------------------------------------------

/// The graceful-shutdown trigger handed to the transactional handoff: flip the
/// shutdown watch (SSE/WS loops + axum graceful shutdown) and poke the
/// supervisor's mpsc. Bounded by the handoff's 5s cancel window, never waited
/// on unbounded.
pub(in crate::server) fn daemon_shutdown_hook(
    shutdown_notify: &watch::Sender<bool>,
    shutdown_tx: &mpsc::Sender<()>,
) -> Arc<dyn Fn() + Send + Sync> {
    let notify = shutdown_notify.clone();
    let tx = shutdown_tx.clone();
    Arc::new(move || {
        let _ = notify.send(true);
        let _ = tx.try_send(());
    })
}

/// Background-listener context (gossip + fallback poll): the running daemon's
/// bound address and shutdown hook.
pub(in crate::server) fn listener_restart_context(
    data_dir: &std::path::Path,
    api_addr: SocketAddr,
    shutdown: Arc<dyn Fn() + Send + Sync>,
) -> RestartContext {
    RestartContext {
        data_dir: Some(data_dir.to_path_buf()),
        api_addr: Some(api_addr),
        shutdown: Some(shutdown),
    }
}

/// The deferred HTTP restart uses the same planner as every other apply path —
/// there is no second ad-hoc exit in the HTTP handler (#261 test 6).
fn deferred_restart_upgrader(stop_on_upgrade: bool, context: RestartContext) -> AutoApplyUpgrader {
    AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(stop_on_upgrade)
        .with_restart_context(context)
}

/// #1196 round 2 test seam (cfg(test) only; no env vars, no cargo
/// features): lets an in-process test inject the
/// [`x0x::upgrade::monitor::VerifiedRelease`] that
/// [`run_startup_update_check`]'s monitor would have fetched and
/// signature-verified, so the whole startup check — apply decision,
/// restart guard, systemd readback — runs for real without GitHub (the
/// release private key is deliberately not in the repo, so no test can
/// mint a signature the monitor would accept). Compiled out entirely in
/// non-test builds; an uninstalled injection leaves the production fetch
/// untouched.
#[cfg(test)]
mod startup_release_seam {
    use crate::upgrade::monitor::VerifiedRelease;
    use std::sync::Mutex;

    static INJECTED: Mutex<Option<VerifiedRelease>> = Mutex::new(None);

    /// Uninstalls the injection on drop, so a test cannot leak its release
    /// into sibling tests in the same process.
    pub(super) struct Guard {
        _private: (),
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Ok(mut slot) = INJECTED.lock() {
                *slot = None;
            }
        }
    }

    /// Inject `release` as the monitor's next answer for the guard's
    /// lifetime.
    pub(super) fn install(release: VerifiedRelease) -> Guard {
        let mut slot = INJECTED.lock().expect("startup release seam poisoned");
        *slot = Some(release);
        Guard { _private: () }
    }

    /// Take the injected release, or `None` when nothing is installed
    /// (fall through to the real monitor fetch).
    pub(super) fn take() -> Option<VerifiedRelease> {
        INJECTED
            .lock()
            .expect("startup release seam poisoned")
            .take()
    }
}

/// Margin added to the readback's remaining start-rate window before the
/// startup check's single retry (#1196): it covers the gap between the
/// readback's monotonic sample and the retry's fresh sample — error
/// propagation, apply-lock re-acquisition and scheduling jitter.
const START_RATE_RETRY_MARGIN: Duration = Duration::from_secs(2);

/// The wait owed before a start-rate refusal may be retried (#1196): set
/// only when the refusal carries the readback's remaining window, i.e. the
/// guard refused ONLY because the unit's activation had not outlived
/// `StartLimitIntervalUSec` while every other guarantee was confirmed.
/// Every other refusal returns `None` and keeps today's
/// skip-until-the-fallback-poll behaviour.
fn start_rate_retry_wait(error: &x0x::upgrade::UpgradeError) -> Option<Duration> {
    match error {
        x0x::upgrade::UpgradeError::RestartOwnership(
            RestartOwnershipError::SupervisedSystemdPolicyNotGuaranteed {
                retry_after: Some(remaining),
                ..
            },
        ) => Some(*remaining + START_RATE_RETRY_MARGIN),
        _ => None,
    }
}

/// One apply attempt under the shared apply lock and — when it refused ONLY
/// because the systemd start-rate window had not aged out — exactly one
/// retry after waiting out the window plus [`START_RATE_RETRY_MARGIN`]
/// (#1196).
///
/// The wait is bounded by the readback's own numbers (never a hard-coded
/// interval), releases the apply lock for its duration so the gossip release
/// listener, the fallback poll and `/upgrade/apply` are not starved behind
/// it, and is cancelled by daemon shutdown (the original refusal is then
/// returned — no bytes were replaced, nothing was skipped silently).
async fn apply_with_start_rate_retry<F, Fut>(
    apply_lock: Option<&Arc<Mutex<()>>>,
    mut attempt: F,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError>>,
{
    let first = {
        let _guard = match apply_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        attempt().await
        // Guard dropped here on purpose: the window wait below must not
        // hold the shared apply lock.
    };
    let wait = match &first {
        Err(e) => match start_rate_retry_wait(e) {
            Some(wait) => wait,
            None => return first,
        },
        Ok(_) => return first,
    };
    tracing::info!(
        wait_ms = wait.as_millis() as u64,
        "Startup check: activation has not outlived StartLimitIntervalUSec yet; \
         waiting out the start-rate window, then retrying the apply once"
    );
    tokio::select! {
        _ = tokio::time::sleep(wait) => {}
        _ = shutdown.changed() => {
            tracing::info!("Startup check: start-rate window wait cancelled by shutdown");
            return first;
        }
    }
    let _guard = match apply_lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    attempt().await
}

// ---------------------------------------------------------------------------
// Staged rollout (#1106, ADR 0094 §1, rulings D183/D184)
// ---------------------------------------------------------------------------

/// How often a waiting release checkpoints its served wait to disk.
const ROLLOUT_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);

/// A version that failed to apply is not retried by an automatic trigger for
/// this long. One backoff now serves every apply path.
const APPLY_RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

/// Future returned by [`RolloutApplier::apply`].
pub(in crate::server) type ApplyFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError>>
            + Send
            + 'a,
    >,
>;

/// The destructive half of a due apply. Production uses [`DaemonApplier`];
/// inert tests count attempts instead.
pub(in crate::server) trait RolloutApplier: Send + Sync {
    /// Apply `manifest` now. The scheduler holds the in-process apply lock.
    fn apply<'a>(&'a self, manifest: &'a ReleaseManifest, summary: ApplySummary)
        -> ApplyFuture<'a>;
}

/// Production applier: the shared #261 restart planner and the host-locked
/// swap in [`AutoApplyUpgrader::apply_upgrade_from_manifest`].
pub(in crate::server) struct DaemonApplier {
    /// `[update] stop_on_upgrade`.
    pub stop_on_upgrade: bool,
    /// Restart planner context (data dir, API address, shutdown hook).
    pub restart_context: RestartContext,
}

impl RolloutApplier for DaemonApplier {
    fn apply<'a>(
        &'a self,
        manifest: &'a ReleaseManifest,
        summary: ApplySummary,
    ) -> ApplyFuture<'a> {
        Box::pin(async move {
            AutoApplyUpgrader::new("x0xd")
                .with_stop_on_upgrade(self.stop_on_upgrade)
                .with_restart_context(self.restart_context.clone())
                .with_apply_summary(summary)
                .apply_upgrade_from_manifest(manifest)
                .await
        })
    }
}

/// Everything the scheduler needs from the running daemon.
pub(in crate::server) struct RolloutEnv {
    /// This instance's MachineId: the stagger key (ADR 0094 §1).
    pub node_id: [u8; 32],
    /// Effective `[update] rollout_window_minutes` (D183/D184).
    pub window_minutes: u64,
    /// Instance data directory; holds `upgrade-rollout.json`.
    pub data_dir: PathBuf,
    /// The in-process apply lock shared with `POST /upgrade/apply`.
    pub upgrade_apply_lock: Arc<Mutex<()>>,
    /// Daemon shutdown watch: stops waiters and the #1196 retry wait.
    pub shutdown_watch: watch::Receiver<bool>,
    /// The destructive half of a due apply.
    pub applier: Arc<dyn RolloutApplier>,
}

/// What the scheduler decided for one offered release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) enum RolloutOffer {
    /// Not newer than the running version.
    NotNewer,
    /// This process already applied this version or a newer one.
    AlreadyApplied,
    /// The version failed to apply recently (automatic triggers only).
    BackoffActive,
    /// A newer release is already staged; this one is not applied.
    Superseded {
        /// The newer staged version.
        by: String,
    },
    /// The node still waits. A waiter task applies the release when due.
    Waiting(StagedRelease),
    /// The wait is served. The caller applies now with
    /// [`RolloutScheduler::apply_due`].
    Due(StagedRelease),
    /// The stored rollout state cannot be trusted (ADR 0094 §6 fail
    /// closed): nothing applies until a supported binary or an explicit
    /// repair resolves it.
    Blocked {
        /// Why the state is blocked.
        reason: String,
    },
}

/// Per-instance staged-rollout scheduler.
///
/// Every apply path (startup check, gossip listener, fallback poll and
/// `POST /upgrade/apply`) verifies a release first and then offers it here.
/// The scheduler stages the release in the persisted state, and applies it
/// only after this node's delay. While it waits, nothing is downloaded or
/// replaced.
pub(in crate::server) struct RolloutScheduler {
    env: RolloutEnv,
    state_path: PathBuf,
    inner: Mutex<RolloutInner>,
}

struct RolloutInner {
    state: RolloutState,
    waiter: Option<RolloutWaiter>,
    failed: HashMap<String, Instant>,
    applied: Option<String>,
}

impl RolloutInner {
    fn is_current_waiter(&self, version: &str) -> bool {
        self.waiter.as_ref().is_some_and(|w| w.version == version)
    }
}

struct RolloutWaiter {
    version: String,
    task: tokio::task::JoinHandle<()>,
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Log the result of a staged apply the way every path logged it before.
fn log_apply_result(
    trigger: RolloutTrigger,
    result: &Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError>,
) {
    match result {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
            tracing::info!(%version, %trigger, "Successfully upgraded to version {version}");
        }
        Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
            tracing::warn!(%reason, %trigger, "Upgrade rolled back");
        }
        Ok(x0x::upgrade::UpgradeResult::NoUpgrade) => {}
        Err(e) => {
            tracing::error!(error = %e, %trigger, "Upgrade failed: {e}");
        }
    }
}

impl RolloutScheduler {
    /// Load the persisted state and build the scheduler.
    pub(in crate::server) fn new(env: RolloutEnv) -> Arc<Self> {
        let state_path = RolloutState::path_in(&env.data_dir);
        let (state, problem) = RolloutState::load(&state_path);
        if let Some(problem) = problem {
            tracing::warn!(
                path = %state_path.display(),
                reason = %problem.reason,
                "Staged-rollout state is unreadable; self-update apply is BLOCKED until a \
                 supported binary or an operator repair resolves it (the record is kept)"
            );
        }
        Arc::new(Self {
            env,
            state_path,
            inner: Mutex::new(RolloutInner {
                state,
                waiter: None,
                failed: HashMap::new(),
                applied: None,
            }),
        })
    }

    /// The effective rollout window in minutes.
    pub(in crate::server) fn window_minutes(&self) -> u64 {
        self.env.window_minutes
    }

    fn persist(&self, state: &RolloutState) {
        if let Err(e) = state.save(&self.state_path) {
            tracing::warn!(
                path = %self.state_path.display(),
                error = %e,
                "Failed to persist the staged-rollout wait; a restart may serve it again"
            );
        }
    }

    /// Whether `version` failed to apply within [`APPLY_RETRY_AFTER`].
    pub(in crate::server) async fn backoff_active(&self, version: &str) -> bool {
        let mut inner = self.inner.lock().await;
        inner
            .failed
            .retain(|_, failed_at| failed_at.elapsed() < APPLY_RETRY_AFTER);
        inner.failed.contains_key(version)
    }

    /// Record that this process applied `version` (the HTTP path applies
    /// inline), so no waiter applies it a second time.
    pub(in crate::server) async fn mark_applied(&self, version: &str) {
        self.inner.lock().await.applied = Some(version.to_string());
    }

    /// Offer a verified release. The caller has checked its signature and
    /// age. The release is staged (idempotent: a duplicate receipt or a
    /// restart keeps the served wait), and then either reported due or left
    /// to a waiter task.
    pub(in crate::server) async fn offer(
        self: &Arc<Self>,
        manifest: &ReleaseManifest,
        trigger: RolloutTrigger,
        sender: Option<String>,
    ) -> RolloutOffer {
        let version = manifest.version.as_str();
        if !is_newer(version, x0x::VERSION) {
            return RolloutOffer::NotNewer;
        }
        let mut inner = self.inner.lock().await;
        // ADR 0094 §6 fail closed (review F4): an untrusted stored state
        // blocks every trigger, the manual one included.
        if let Some(reason) = &inner.state.blocked {
            return RolloutOffer::Blocked {
                reason: reason.clone(),
            };
        }
        if let Some(applied) = &inner.applied {
            if !is_newer(version, applied) {
                return RolloutOffer::AlreadyApplied;
            }
        }
        if let Some(waiter) = &inner.waiter {
            if !waiter.task.is_finished() && is_newer(&waiter.version, version) {
                return RolloutOffer::Superseded {
                    by: waiter.version.clone(),
                };
            }
        }
        if trigger != RolloutTrigger::Manual {
            inner
                .failed
                .retain(|_, failed_at| failed_at.elapsed() < APPLY_RETRY_AFTER);
            if inner.failed.contains_key(version) {
                return RolloutOffer::BackoffActive;
            }
        }

        let before = inner.state.clone();
        let (staged, is_new) = inner.state.stage(
            version,
            &self.env.node_id,
            self.env.window_minutes,
            trigger,
            unix_now_secs(),
            x0x::VERSION,
        );
        // A duplicate receipt changes nothing; do not rewrite the file.
        if inner.state != before {
            self.persist(&inner.state);
        }
        if is_new {
            tracing::info!(
                version = %staged.version,
                %trigger,
                delay_secs = staged.delay_secs,
                window_minutes = staged.window_minutes,
                "Staged release v{}: this node applies it {}s after first receipt \
                 ({}-minute rollout window, ADR 0094 §1)",
                staged.version,
                staged.delay_secs,
                staged.window_minutes
            );
        }

        let same_waiter = inner
            .waiter
            .as_ref()
            .is_some_and(|w| w.version == version && !w.task.is_finished());
        if same_waiter {
            return RolloutOffer::Waiting(staged);
        }
        // An older waiter, if any, is superseded: it sees that it is no
        // longer current at its next checkpoint and stops without applying.
        inner.waiter = None;
        if staged.is_due() {
            return RolloutOffer::Due(staged);
        }
        let this = Arc::clone(self);
        let waiter_manifest = manifest.clone();
        let task = tokio::spawn(async move {
            this.run_waiter(waiter_manifest, trigger, sender).await;
        });
        inner.waiter = Some(RolloutWaiter {
            version: version.to_string(),
            task,
        });
        RolloutOffer::Waiting(staged)
    }

    /// Apply a due release now, under the in-process apply lock, with the
    /// #1196 single retry after an unaged systemd start-rate window.
    pub(in crate::server) async fn apply_due(
        &self,
        manifest: &ReleaseManifest,
        trigger: RolloutTrigger,
        sender: Option<String>,
        staged: &StagedRelease,
    ) -> Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError> {
        let summary = ApplySummary {
            trigger: Some(trigger),
            sender,
            delay_secs: staged.delay_secs,
        };
        let mut shutdown = self.env.shutdown_watch.clone();
        let attempt = || {
            let summary = summary.clone();
            async move {
                let already = {
                    let inner = self.inner.lock().await;
                    inner
                        .applied
                        .as_deref()
                        .is_some_and(|applied| !is_newer(&manifest.version, applied))
                };
                if already {
                    return Ok(x0x::upgrade::UpgradeResult::NoUpgrade);
                }
                self.env.applier.apply(manifest, summary).await
            }
        };
        let result =
            apply_with_start_rate_retry(Some(&self.env.upgrade_apply_lock), attempt, &mut shutdown)
                .await;
        let mut inner = self.inner.lock().await;
        match &result {
            Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
                inner.applied = Some(version.clone());
            }
            Ok(x0x::upgrade::UpgradeResult::RolledBack { .. }) | Err(_) => {
                inner
                    .failed
                    .insert(manifest.version.clone(), Instant::now());
            }
            Ok(x0x::upgrade::UpgradeResult::NoUpgrade) => {}
        }
        result
    }

    /// Store the served wait. Returns whether `version` is still the
    /// current waiter.
    async fn checkpoint(&self, version: &str, waited_secs: u64) -> bool {
        let mut inner = self.inner.lock().await;
        inner.state.set_waited(version, waited_secs);
        self.persist(&inner.state);
        inner.is_current_waiter(version)
    }

    async fn run_waiter(
        self: Arc<Self>,
        manifest: ReleaseManifest,
        trigger: RolloutTrigger,
        sender: Option<String>,
    ) {
        let version = manifest.version.clone();
        let mut shutdown = self.env.shutdown_watch.clone();
        loop {
            let (waited, remaining) = {
                let inner = self.inner.lock().await;
                if !inner.is_current_waiter(&version) {
                    return;
                }
                match inner.state.entry(&version) {
                    Some(entry) => (entry.waited_secs, entry.remaining()),
                    None => return,
                }
            };
            if remaining.is_zero() {
                break;
            }
            let step = remaining.min(ROLLOUT_CHECKPOINT_INTERVAL);
            let started = tokio::time::Instant::now();
            let stopped = tokio::select! {
                _ = tokio::time::sleep(step) => false,
                changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
            };
            let served = waited.saturating_add(started.elapsed().as_secs());
            let current = self.checkpoint(&version, served).await;
            if stopped || !current {
                return;
            }
        }

        let staged = {
            let inner = self.inner.lock().await;
            if !inner.is_current_waiter(&version) {
                return;
            }
            inner.state.entry(&version).cloned()
        };
        let Some(staged) = staged else {
            return;
        };
        tracing::info!(
            %version,
            %trigger,
            delay_secs = staged.delay_secs,
            "Staged-rollout wait served; applying v{version}"
        );
        let result = self.apply_due(&manifest, trigger, sender, &staged).await;
        log_apply_result(trigger, &result);
        let mut inner = self.inner.lock().await;
        if inner.is_current_waiter(&version) {
            inner.waiter = None;
        }
    }
}

/// One scheduler per daemon data directory, shared by the background apply
/// paths and `POST /upgrade/apply`. Weak entries: the scheduler lives as long
/// as a task or a request holds it.
static ROLLOUT_SCHEDULERS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<PathBuf, std::sync::Weak<RolloutScheduler>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// The scheduler environment of a running daemon.
fn rollout_env_for(state: &AppState) -> RolloutEnv {
    RolloutEnv {
        node_id: *state.agent.machine_id().as_bytes(),
        window_minutes: state.update_config.rollout_window_minutes,
        data_dir: state.data_dir.clone(),
        upgrade_apply_lock: Arc::clone(&state.upgrade_apply_lock),
        shutdown_watch: state.shutdown_notify.subscribe(),
        applier: Arc::new(DaemonApplier {
            stop_on_upgrade: state.update_config.stop_on_upgrade,
            restart_context: listener_restart_context(
                &state.data_dir,
                state.api_address,
                daemon_shutdown_hook(&state.shutdown_notify, &state.shutdown_tx),
            ),
        }),
    }
}

/// The staged-rollout scheduler of this daemon (created on first use).
pub(in crate::server) fn rollout_scheduler_for(state: &AppState) -> Arc<RolloutScheduler> {
    let mut map = ROLLOUT_SCHEDULERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    map.retain(|_, weak| weak.strong_count() > 0);
    if let Some(existing) = map.get(&state.data_dir).and_then(std::sync::Weak::upgrade) {
        return existing;
    }
    let scheduler = RolloutScheduler::new(rollout_env_for(state));
    map.insert(state.data_dir.clone(), Arc::downgrade(&scheduler));
    scheduler
}

/// At start, report a completed self-update once at WARN level:
/// "x0xd upgraded from X to Y" (#1106). The previous version comes from the
/// handoff record that the old process wrote before it exited.
///
/// The line is written once per handoff transaction: the reported
/// transaction is kept in `upgrade-rollout.json`, so a later restart of the
/// same binary (for example a crash loop) does not repeat it. A stale
/// handoff record from an older upgrade says nothing.
pub(in crate::server) fn announce_completed_upgrade(data_dir: &std::path::Path) {
    let handoff_path = data_dir.join(x0x::upgrade::restart::HANDOFF_FILE_NAME);
    let Ok(handoff) = x0x::upgrade::restart::UpgradeHandoff::read(&handoff_path) else {
        return;
    };
    if handoff.to_version != x0x::VERSION {
        return;
    }
    let state_path = RolloutState::path_in(data_dir);
    let (mut state, problem) = RolloutState::load(&state_path);
    if let Some(problem) = problem {
        tracing::debug!(
            path = %state_path.display(),
            reason = %problem.reason,
            "Staged-rollout state is unreadable; the reported upgrade is not recorded"
        );
    }
    let Some(notice) = state.take_upgrade_notice(
        &handoff.from_version,
        &handoff.to_version,
        handoff.started_at,
        x0x::VERSION,
    ) else {
        return;
    };
    tracing::warn!(
        from_version = %notice.from_version,
        to_version = %notice.to_version,
        mode = ?handoff.mode,
        handoff_started_at = notice.started_at,
        "x0xd upgraded from {} to {}",
        notice.from_version,
        notice.to_version
    );
    if let Err(e) = state.save(&state_path) {
        tracing::debug!(
            path = %state_path.display(),
            error = %e,
            "Failed to record the reported upgrade; a restart may report it again"
        );
    }
}

/// Offer a verified release to the staged rollout, and apply it when this
/// node's wait is served (#1106, ADR 0094 §1). Returns the applied version
/// when this call applied it. While the node waits, nothing is downloaded or
/// replaced; a waiter task applies the release when it is due.
async fn stage_and_apply_if_due(
    rollout: &Arc<RolloutScheduler>,
    manifest: &ReleaseManifest,
    trigger: RolloutTrigger,
    sender: Option<String>,
) -> Option<String> {
    match rollout.offer(manifest, trigger, sender.clone()).await {
        RolloutOffer::Due(staged) => {
            tracing::info!(
                version = %manifest.version,
                %trigger,
                delay_secs = staged.delay_secs,
                "Staged-rollout wait served; applying v{}",
                manifest.version
            );
            let result = rollout.apply_due(manifest, trigger, sender, &staged).await;
            log_apply_result(trigger, &result);
            match result {
                Ok(x0x::upgrade::UpgradeResult::Success { version }) => Some(version),
                _ => None,
            }
        }
        RolloutOffer::Waiting(staged) => {
            tracing::debug!(
                version = %manifest.version,
                %trigger,
                remaining_secs = staged.remaining().as_secs(),
                "Release v{} is staged; this node still waits",
                manifest.version
            );
            None
        }
        RolloutOffer::BackoffActive => {
            tracing::debug!(
                version = %manifest.version,
                %trigger,
                "Skipping recently failed upgrade v{} (apply backoff active)",
                manifest.version
            );
            None
        }
        RolloutOffer::Superseded { by } => {
            tracing::debug!(
                version = %manifest.version,
                superseded_by = %by,
                "Release v{} is superseded by staged v{by}",
                manifest.version
            );
            None
        }
        RolloutOffer::Blocked { reason } => {
            tracing::warn!(
                version = %manifest.version,
                %trigger,
                %reason,
                "Release v{} not applied: the staged-rollout state is unreadable (apply blocked until repair)",
                manifest.version
            );
            None
        }
        RolloutOffer::AlreadyApplied | RolloutOffer::NotNewer => None,
    }
}

/// `x0xd --check-updates`: report whether a newer verified release exists.
///
/// Report only (ADR 0094 §1: "Make the fifth path, `x0xd --check-updates`,
/// report-only"). It installs no binary and no SKILL.md. The running daemon
/// applies the release after its staged-rollout wait.
pub(in crate::server) async fn report_available_update(
    config: &DaemonConfig,
) -> Result<Option<String>> {
    let monitor = UpgradeMonitor::new(&config.update.repo, "x0xd", x0x::VERSION)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_include_prereleases(config.update.include_prereleases);
    let checked = monitor
        .check_for_updates()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(checked.map(|verified| verified.manifest.version))
}

/// Startup GitHub check. Returns Some(version) if an update was applied.
///
/// Spawned by `serve_with_options` as a background task after the API
/// listener is bound (#1086: a firewalled update endpoint must never gate
/// API readiness on its ~30 s HTTP timeout). A newer verified release is
/// offered to the staged rollout like every other trigger: it applies only
/// when this node's wait is served (#1106). A due apply hands the restart to
/// the #261 planner and serializes against the gossip release listener and
/// the fallback poll. On a systemd host whose activation has not yet
/// outlived `StartLimitIntervalUSec`, it waits out the window and retries
/// the apply once (#1196) instead of skipping the version.
pub(in crate::server) async fn run_startup_update_check(
    config: &DaemonConfig,
    rollout: &Arc<RolloutScheduler>,
) -> Result<Option<String>> {
    let monitor = UpgradeMonitor::new(&config.update.repo, "x0xd", x0x::VERSION)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_include_prereleases(config.update.include_prereleases);

    // #1196 round 2 test seam (cfg(test) only): an in-process test can
    // inject the verified release the monitor would have fetched and
    // signature-verified, so the startup check runs end to end against the
    // real apply/restart-guard logic without GitHub (the release private
    // key is deliberately not in the repo, so a test cannot mint a real
    // signature). The production fetch below is compiled verbatim in
    // non-test builds; an uninstalled injection changes nothing.
    let checked = {
        #[cfg(test)]
        {
            match startup_release_seam::take() {
                Some(injected) => Some(injected),
                None => monitor
                    .check_for_updates()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
            }
        }
        #[cfg(not(test))]
        {
            monitor
                .check_for_updates()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
        }
    };
    let Some(verified) = checked else {
        return Ok(None);
    };

    tracing::info!(
        new_version = %verified.manifest.version,
        "Startup check: new version available"
    );

    // Update SKILL.md before upgrading (independent of binary update)
    update_skill_if_changed(&verified.manifest, &config.data_dir).await;

    // The startup check runs beside the gossip release listener and the
    // fallback poll now that it no longer gates startup (#1086). A due
    // apply takes the shared apply lock per attempt (not across the #1196
    // start-rate window wait), so concurrent apply paths are not starved
    // behind a time-bound refusal.
    Ok(stage_and_apply_if_due(rollout, &verified.manifest, RolloutTrigger::Startup, None).await)
}

/// Broadcast the current release manifest to gossip after joining the network.
///
/// After a node restarts (possibly after upgrading), it fetches the latest manifest
/// from GitHub and broadcasts it regardless of whether it needs to upgrade. This
/// ensures peers who missed the initial gossip window still receive the manifest.
/// Also syncs SKILL.md to match the current manifest.
pub(in crate::server) async fn broadcast_current_manifest(
    agent: &Agent,
    repo: &str,
    include_prereleases: bool,
    data_dir: &std::path::Path,
    self_published_release_manifests: Arc<Mutex<SelfPublishedReleaseManifests>>,
) {
    let monitor = match UpgradeMonitor::new(repo, "x0xd", x0x::VERSION) {
        Ok(m) => m.with_include_prereleases(include_prereleases),
        Err(e) => {
            tracing::debug!(error = %e, "Failed to create monitor for startup broadcast");
            return;
        }
    };

    match monitor.fetch_current_manifest().await {
        Ok(Some(verified)) => {
            // Sync SKILL.md with current manifest
            update_skill_if_changed(&verified.manifest, data_dir).await;

            tracing::info!(
                version = %verified.manifest.version,
                "Broadcasting current release manifest v{} to gossip",
                verified.manifest.version
            );
            let gossip_payload = verified.gossip_payload;
            {
                let mut self_published = self_published_release_manifests.lock().await;
                self_published.record_payload(&gossip_payload, Instant::now());
            }
            if let Err(e) = agent.publish(RELEASE_TOPIC, gossip_payload).await {
                tracing::debug!(error = %e, "Failed to broadcast current manifest: {e}");
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::debug!(error = %e, "Failed to fetch current manifest for broadcast: {e}");
        }
    }
}

/// Gossip-based release subscription — the primary update mechanism for x0xd.
///
/// A verified, newer manifest is rebroadcast at once and then offered to the
/// staged rollout (#1106): it applies only when this node's wait is served.
/// When an upgrade attempt fails (e.g. hash mismatch), the scheduler backs
/// the version off for 30 minutes, so a release that can never apply here
/// is not re-downloaded on every receipt. A newer release supersedes it.
pub(in crate::server) async fn run_gossip_update_listener(
    agent: Arc<Agent>,
    data_dir: PathBuf,
    self_published_release_manifests: Arc<Mutex<SelfPublishedReleaseManifests>>,
    rollout: Arc<RolloutScheduler>,
) {
    let mut release_sub = match agent.subscribe(RELEASE_TOPIC).await {
        Ok(sub) => sub,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to subscribe to release topic: {e}");
            return;
        }
    };

    // Track rebroadcasted versions with timestamps to prevent exponential gossip storms
    // while still allowing periodic re-rebroadcast for late-connecting peers.
    // publish() re-signs the payload with the local agent key, producing a new PlumTree
    // message ID each time — so PlumTree's transport-layer dedup cannot suppress re-sends.
    let mut rebroadcasted_versions: HashMap<String, Instant> = HashMap::new();

    while let Some(msg) = release_sub.recv().await {
        // The publisher of this copy (a rebroadcast re-signs with the
        // rebroadcaster's agent key), when its signature verified.
        let sender = msg
            .sender
            .as_ref()
            .filter(|_| msg.verified)
            .map(|id| hex::encode(id.as_bytes()));
        tracing::info!(
            sender = sender.as_deref().unwrap_or("unknown"),
            "Received release manifest via gossip"
        );

        // Decode wire format: length-prefixed manifest JSON + signature
        let (manifest_json, sig) = match decode_signed_manifest(&msg.payload) {
            Ok(parts) => parts,
            Err(e) => {
                tracing::warn!(error = %e, "Invalid manifest payload received via gossip");
                continue;
            }
        };

        let manifest: ReleaseManifest = match serde_json::from_slice(manifest_json) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "Invalid manifest JSON: {e}");
                continue;
            }
        };

        // Fast-drop stale release-train manifests before ML-DSA verification.
        // For versions at or below our own, we will neither rebroadcast nor apply
        // the manifest, so signature work only slows the release-topic drain.
        if !is_newer(&manifest.version, x0x::VERSION) {
            tracing::debug!(
                version = %manifest.version,
                "Already on v{} or newer, skipping verification and rebroadcast",
                manifest.version
            );
            continue;
        }

        // Stage 1: verify manifest signature before trusting any newer release.
        if let Err(e) = verify_manifest_signature(manifest_json, sig) {
            tracing::warn!(error = %e, "Release manifest signature verification failed");
            continue;
        }

        // Stage 2: reject replayed manifests that have aged past the policy window.
        // This prevents an attacker from replaying a legitimately signed but
        // stale manifest onto the gossip network to trigger a long-expired
        // upgrade path or to keep the fleet churning on yesterday's release.
        if let Err(e) = x0x::upgrade::monitor::validate_manifest_timestamp(&manifest) {
            tracing::warn!(error = %e, version = %manifest.version,
                "Rejecting stale gossip manifest (timestamp too old)");
            continue;
        }

        // Rebroadcast with time-windowed dedup: allow re-rebroadcast every 5 minutes
        // so late-connecting peers (e.g., after a peer restarts) still receive the manifest.
        // Suppress manifests at or below our own version first; stale release-train
        // manifests were the source of the fleet PubSub flood in Hunt 12e.
        let payload_digest = release_manifest_payload_digest(&msg.payload);
        let rebroadcast_decision = {
            let mut self_published = self_published_release_manifests.lock().await;
            decide_release_manifest_rebroadcast(
                &manifest.version,
                x0x::VERSION,
                payload_digest,
                &mut rebroadcasted_versions,
                &mut self_published,
                Instant::now(),
            )
        };

        match rebroadcast_decision {
            ReleaseRebroadcastDecision::Rebroadcast => {
                tracing::info!(
                    version = %manifest.version,
                    "Rebroadcasting verified release manifest v{}",
                    manifest.version
                );
                {
                    let mut self_published = self_published_release_manifests.lock().await;
                    self_published.record_payload(&msg.payload, Instant::now());
                }
                if let Err(e) = agent.publish(RELEASE_TOPIC, msg.payload.to_vec()).await {
                    tracing::debug!(error = %e, "Failed to rebroadcast release manifest: {e}");
                }
            }
            ReleaseRebroadcastDecision::SkipNotNewer => {
                tracing::debug!(
                    version = %manifest.version,
                    "Already on v{} or newer, skipping rebroadcast",
                    manifest.version
                );
                continue;
            }
            ReleaseRebroadcastDecision::SkipSelfPublished => {
                tracing::debug!(
                    version = %manifest.version,
                    "Skipping rebroadcast of self-published release manifest v{}",
                    manifest.version
                );
            }
            ReleaseRebroadcastDecision::SkipRecentlyRebroadcasted => {
                tracing::debug!(
                    version = %manifest.version,
                    "Already rebroadcasted v{} recently, skipping",
                    manifest.version
                );
            }
        }

        // Ignore if we're already on this version or newer
        if !is_newer(&manifest.version, x0x::VERSION) {
            tracing::debug!(
                version = %manifest.version,
                "Already on latest version {}",
                manifest.version
            );
            continue;
        }

        // Update SKILL.md if changed (independent of binary update)
        update_skill_if_changed(&manifest, &data_dir).await;

        // Stage, and apply only when this node's wait is served. The
        // scheduler skips versions that recently failed to apply: a release
        // that can never succeed here would otherwise re-download and
        // re-extract on every gossip receipt.
        stage_and_apply_if_due(&rollout, &manifest, RolloutTrigger::Gossip, sender).await;
    }
}

/// Background GitHub fallback poll (safety net, every 48h by default).
/// Also broadcasts discovered manifests to gossip and syncs SKILL.md.
///
/// A found release is offered to the staged rollout (#1106) like every other
/// trigger. Versions that failed to apply are skipped for 30 minutes; a
/// newer release supersedes the failed version.
pub(in crate::server) async fn run_fallback_github_poll(
    agent: Arc<Agent>,
    config: DaemonUpdateConfig,
    data_dir: PathBuf,
    self_published_release_manifests: Arc<Mutex<SelfPublishedReleaseManifests>>,
    rollout: Arc<RolloutScheduler>,
) {
    let interval = Duration::from_secs(config.fallback_check_interval_minutes * 60);
    let mut ticker = tokio::time::interval(interval);
    // Skip first tick: the startup check covers the boot window (it runs
    // concurrently as a post-bind background task, #1086), so the poll's
    // first fetch waits one full interval instead of racing it.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        tracing::debug!("Fallback GitHub check");

        let monitor = match UpgradeMonitor::new(&config.repo, "x0xd", x0x::VERSION) {
            Ok(m) => m.with_include_prereleases(config.include_prereleases),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create upgrade monitor: {e}");
                continue;
            }
        };

        match monitor.check_for_updates().await {
            Ok(Some(verified)) => {
                // Skip versions that recently failed to apply
                if rollout.backoff_active(&verified.manifest.version).await {
                    tracing::debug!(
                        version = %verified.manifest.version,
                        "Skipping recently failed version {}",
                        verified.manifest.version
                    );
                    continue;
                }

                tracing::info!(
                    new_version = %verified.manifest.version,
                    "Fallback check: new version found via GitHub"
                );

                // Update SKILL.md (independent of binary update)
                update_skill_if_changed(&verified.manifest, &data_dir).await;

                // Broadcast to gossip with timeout — don't let dead peers block upgrade
                let publish_payload = verified.gossip_payload.clone();
                let publish_agent = agent.clone();
                let self_published_for_publish = Arc::clone(&self_published_release_manifests);
                tokio::spawn(async move {
                    {
                        let mut self_published = self_published_for_publish.lock().await;
                        self_published.record_payload(&publish_payload, Instant::now());
                    }
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        publish_agent.publish(RELEASE_TOPIC, publish_payload),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            tracing::debug!("Broadcast discovered release to gossip");
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(error = %e, "Failed to broadcast discovered release: {e}");
                        }
                        Err(_) => {
                            tracing::debug!(
                                "Gossip broadcast timed out (peers may be unreachable)"
                            );
                        }
                    }
                });

                stage_and_apply_if_due(&rollout, &verified.manifest, RolloutTrigger::Poll, None)
                    .await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Fallback GitHub check failed: {e}");
            }
        }
    }
}

/// Update SKILL.md if the manifest has a different hash.
async fn update_skill_if_changed(manifest: &ReleaseManifest, data_dir: &std::path::Path) {
    let skill_path = data_dir.join("SKILL.md");

    let local_hash = match tokio::fs::read(&skill_path).await {
        Ok(contents) => {
            let hash: [u8; 32] = Sha256::digest(&contents).into();
            hash
        }
        Err(_) => [0u8; 32], // Missing file — always update
    };

    if local_hash == manifest.skill_sha256 {
        return; // Already up to date
    }

    if manifest.skill_url.is_empty() {
        return;
    }

    tracing::info!("Updating SKILL.md from signed manifest");

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to create HTTP client for SKILL.md: {e}");
            return;
        }
    };

    match client.get(&manifest.skill_url).send().await {
        Ok(resp) => match resp.bytes().await {
            Ok(new_contents) => {
                let new_hash: [u8; 32] = Sha256::digest(&new_contents).into();
                if new_hash != manifest.skill_sha256 {
                    tracing::warn!("SKILL.md hash mismatch after download");
                    return;
                }
                // The startup check and the startup manifest broadcast can
                // both reach this write concurrently (#1086): stage the
                // verified bytes in a unique temp file and rename it into
                // place atomically, so readers and the other writer never
                // observe a torn SKILL.md.
                static SKILL_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
                let tmp_path = data_dir.join(format!(
                    "SKILL.md.tmp.{}.{}",
                    std::process::id(),
                    SKILL_TMP_SEQ.fetch_add(1, Ordering::Relaxed)
                ));
                let install = async {
                    tokio::fs::write(&tmp_path, &new_contents).await?;
                    tokio::fs::rename(&tmp_path, &skill_path).await
                };
                match install.await {
                    Ok(()) => tracing::info!("SKILL.md updated successfully"),
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&tmp_path).await;
                        tracing::warn!(error = %e, "Failed to install SKILL.md");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "Failed to download SKILL.md: {e}"),
        },
        Err(e) => tracing::warn!(error = %e, "Failed to download SKILL.md: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// GET /upgrade — check for available updates.
pub(in crate::server) async fn check_upgrade(State(state): State<Arc<AppState>>) -> Response {
    if !state.update_config.enabled {
        return upgrade_response(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "update_available": false,
                "current_version": env!("CARGO_PKG_VERSION"),
                "reason": "updates disabled"
            }),
        );
    }

    if let Some(response) = cached_upgrade_response(state.as_ref()).await {
        return response;
    }

    let monitor =
        match UpgradeMonitor::new(&state.update_config.repo, "x0xd", env!("CARGO_PKG_VERSION")) {
            Ok(m) => m.with_include_prereleases(state.update_config.include_prereleases),
            Err(e) => {
                tracing::error!("upgrade monitor creation failed: {e}");
                return store_upgrade_response(
                    state.as_ref(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({ "ok": false, "error": "upgrade check unavailable" }),
                    UPGRADE_CHECK_ERROR_CACHE_TTL,
                )
                .await;
            }
        };

    match monitor.check_for_updates().await {
        Ok(Some(release)) => {
            store_upgrade_response(
                state.as_ref(),
                StatusCode::OK,
                serde_json::json!({
                "ok": true,
                "update_available": true,
                "version": release.manifest.version,
                "current_version": env!("CARGO_PKG_VERSION")
                }),
                UPGRADE_CHECK_CACHE_TTL,
            )
            .await
        }
        Ok(None) => {
            store_upgrade_response(
                state.as_ref(),
                StatusCode::OK,
                serde_json::json!({
                "ok": true,
                "update_available": false,
                "current_version": env!("CARGO_PKG_VERSION")
                }),
                UPGRADE_CHECK_CACHE_TTL,
            )
            .await
        }
        Err(e) => {
            tracing::error!("upgrade check failed: {e}");
            store_upgrade_response(
                state.as_ref(),
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "ok": false, "error": "upgrade check failed" }),
                UPGRADE_CHECK_ERROR_CACHE_TTL,
            )
            .await
        }
    }
}

fn upgrade_response(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

async fn cached_upgrade_response(state: &AppState) -> Option<Response> {
    let cached = {
        let cache = state.upgrade_check_cache.lock().await;
        cache
            .as_ref()
            .filter(|cached| cached.checked_at.elapsed() < cached.ttl)
            .cloned()
    };

    cached.map(|cached| upgrade_response(cached.status, cached.body))
}

async fn store_upgrade_response(
    state: &AppState,
    status: StatusCode,
    body: serde_json::Value,
    ttl: Duration,
) -> Response {
    let cached = CachedUpgradeCheck {
        checked_at: Instant::now(),
        status,
        body: body.clone(),
        ttl,
    };
    {
        let mut cache = state.upgrade_check_cache.lock().await;
        *cache = Some(cached);
    }

    upgrade_response(status, body)
}

/// POST /upgrade/apply — fetch the latest signed manifest and apply it.
///
/// On a same-version run the monitor returns `None` and the handler reports
/// `applied: false` with `reason: "no upgrade available"`. A newer verified
/// manifest is offered to the staged rollout (#1106) like every other
/// trigger. While this node still waits, the handler reports `applied:
/// false, staged: true` with the delay and the remaining wait, and the
/// daemon applies the release when the wait is served. ADR 0094 leaves an
/// explicit HTTP bypass of the wait open, so this route has none. When the
/// wait is served, this handler serializes the destructive apply with the
/// background update workers, performs the verified binary swap, returns a
/// JSON result, then schedules restart/exec after the response has a chance
/// to flush.
pub(in crate::server) async fn apply_upgrade(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if !state.self_update_enabled {
        // Embed path: never replace/restart the host process via the API.
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "applied": false,
                "reason": "self-update disabled for this process",
                "current_version": env!("CARGO_PKG_VERSION")
            })),
        );
    }
    if !state.update_config.enabled {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "applied": false,
                "reason": "updates disabled",
                "current_version": env!("CARGO_PKG_VERSION")
            })),
        );
    }

    let Ok(_upgrade_guard) = state.upgrade_apply_lock.try_lock() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "applied": false,
                "error": "upgrade already in progress"
            })),
        );
    };

    let monitor =
        match UpgradeMonitor::new(&state.update_config.repo, "x0xd", env!("CARGO_PKG_VERSION")) {
            Ok(m) => m.with_include_prereleases(state.update_config.include_prereleases),
            Err(e) => {
                tracing::error!("upgrade monitor creation failed: {e}");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "upgrade monitor unavailable",
                );
            }
        };

    let release = match monitor.check_for_updates().await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "applied": false,
                    "reason": "no upgrade available",
                    "current_version": env!("CARGO_PKG_VERSION")
                })),
            );
        }
        Err(e) => {
            tracing::error!("upgrade check failed: {e}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "upgrade check failed");
        }
    };

    let rollout = rollout_scheduler_for(&state);
    let sender = Some("local API (durable token)".to_string());
    let staged = match rollout
        .offer(&release.manifest, RolloutTrigger::Manual, sender.clone())
        .await
    {
        RolloutOffer::Due(staged) => staged,
        RolloutOffer::Waiting(staged) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "applied": false,
                    "staged": true,
                    "reason": format!(
                        "staged rollout: v{} applies in {}s (this node's delay is {}s of a \
                         {}-minute window, ADR 0094 §1)",
                        staged.version,
                        staged.remaining().as_secs(),
                        staged.delay_secs,
                        staged.window_minutes
                    ),
                    "version": staged.version,
                    "delay_secs": staged.delay_secs,
                    "remaining_secs": staged.remaining().as_secs(),
                    "window_minutes": staged.window_minutes,
                    "current_version": env!("CARGO_PKG_VERSION")
                })),
            );
        }
        RolloutOffer::Superseded { by } => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "applied": false,
                    "staged": true,
                    "reason": format!("superseded by staged v{by}"),
                    "version": by,
                    "current_version": env!("CARGO_PKG_VERSION")
                })),
            );
        }
        RolloutOffer::AlreadyApplied => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "applied": false,
                    "reason": "upgrade already applied; restart pending",
                    "current_version": env!("CARGO_PKG_VERSION")
                })),
            );
        }
        RolloutOffer::Blocked { reason } => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "applied": false,
                    "blocked": true,
                    "reason": format!(
                        "staged-rollout state is unreadable; apply blocked until repair: {reason}"
                    ),
                    "current_version": env!("CARGO_PKG_VERSION")
                })),
            );
        }
        RolloutOffer::NotNewer | RolloutOffer::BackoffActive => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "applied": false,
                    "reason": "no upgrade available",
                    "current_version": env!("CARGO_PKG_VERSION")
                })),
            );
        }
    };

    let stop_on_upgrade = state.update_config.stop_on_upgrade;
    let restart_context = RestartContext {
        data_dir: Some(state.data_dir.clone()),
        api_addr: Some(state.api_address),
        shutdown: Some(daemon_shutdown_hook(
            &state.shutdown_notify,
            &state.shutdown_tx,
        )),
    };
    let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(stop_on_upgrade)
        .with_restart_on_success(false)
        .with_restart_context(restart_context.clone())
        .with_apply_summary(ApplySummary {
            trigger: Some(RolloutTrigger::Manual),
            sender,
            delay_secs: staged.delay_secs,
        });

    match upgrader
        .apply_upgrade_from_manifest(&release.manifest)
        .await
    {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
            rollout.mark_applied(&version).await;
            schedule_restart_after_response(stop_on_upgrade, restart_context, version.clone());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "applied": true,
                    "version": version,
                    "previous_version": env!("CARGO_PKG_VERSION"),
                    "restart_scheduled": true
                })),
            )
        }
        Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "applied": false,
                "rolled_back": true,
                "reason": reason
            })),
        ),
        Ok(x0x::upgrade::UpgradeResult::NoUpgrade) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "applied": false,
                "reason": "no upgrade required"
            })),
        ),
        Err(e) => {
            tracing::error!("apply upgrade failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false,
                    "applied": false,
                    "error": e.to_string()
                })),
            )
        }
    }
}

fn schedule_restart_after_response(
    stop_on_upgrade: bool,
    restart_context: RestartContext,
    target_version: String,
) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(750)).await;
        // Same planner as every other apply path (#261): unsupervised daemons
        // get the transactional handoff here too — never a bare exit(0).
        let upgrader = deferred_restart_upgrader(stop_on_upgrade, restart_context);
        if let Err(e) = upgrader.restart_current_binary(&target_version).await {
            tracing::error!(error = %e, "failed to restart after manual upgrade apply");
        }
    });
}

// ---------------------------------------------------------------------------
// Network diagnostics handler
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upgrade::restart;
    use x0x::upgrade::manifest::{PlatformAsset, SCHEMA_VERSION};

    fn manifest_with_version(version: &str) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: SCHEMA_VERSION,
            version: version.to_string(),
            timestamp: 4_102_444_800,
            assets: vec![PlatformAsset {
                target: "x86_64-unknown-linux-gnu".to_string(),
                archive_url: "https://example.com/x0x-linux-x64-gnu.tar.gz".to_string(),
                archive_sha256: [0xAA; 32],
                signature_url: "https://example.com/x0x-linux-x64-gnu.tar.gz.sig".to_string(),
            }],
            skill_url: "https://example.com/SKILL.md".to_string(),
            skill_sha256: [0xBB; 32],
        }
    }

    fn encoded_payload_for_manifest(manifest: &ReleaseManifest) -> Vec<u8> {
        let manifest_json = serde_json::to_vec(manifest).expect("serialize manifest fixture");
        x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, b"test-signature")
    }

    fn version_newer_than_current() -> String {
        let mut version = semver::Version::parse(x0x::VERSION).expect("current version is semver");
        version.patch += 1;
        version.to_string()
    }

    #[test]
    fn release_manifest_rebroadcast_only_newer_versions() {
        let older_manifest = manifest_with_version("0.0.1");
        let equal_manifest = manifest_with_version(x0x::VERSION);
        let newer_version = version_newer_than_current();
        let newer_manifest = manifest_with_version(&newer_version);

        let mut rebroadcasted_versions = HashMap::new();
        let mut self_published = SelfPublishedReleaseManifests::default();
        let now = Instant::now();
        let mut republished_versions = Vec::new();

        for manifest in [&older_manifest, &equal_manifest, &newer_manifest] {
            let payload = encoded_payload_for_manifest(manifest);
            let decision = decide_release_manifest_rebroadcast(
                &manifest.version,
                x0x::VERSION,
                release_manifest_payload_digest(&payload),
                &mut rebroadcasted_versions,
                &mut self_published,
                now,
            );
            if decision == ReleaseRebroadcastDecision::Rebroadcast {
                republished_versions.push(manifest.version.clone());
            }
        }

        assert_eq!(republished_versions, vec![newer_version]);
    }

    #[test]
    fn self_published_release_manifest_skips_rebroadcast_until_ttl() {
        let newer_version = version_newer_than_current();
        let manifest = manifest_with_version(&newer_version);
        let payload = encoded_payload_for_manifest(&manifest);
        let digest = release_manifest_payload_digest(&payload);
        let now = Instant::now();

        let mut self_published = SelfPublishedReleaseManifests::default();
        self_published.record_payload(&payload, now);
        let mut rebroadcasted_versions = HashMap::new();

        let decision = decide_release_manifest_rebroadcast(
            &manifest.version,
            x0x::VERSION,
            digest,
            &mut rebroadcasted_versions,
            &mut self_published,
            now,
        );
        assert_eq!(decision, ReleaseRebroadcastDecision::SkipSelfPublished);

        let after_ttl = now + SELF_PUBLISHED_RELEASE_TTL + Duration::from_secs(1);
        let decision_after_ttl = decide_release_manifest_rebroadcast(
            &manifest.version,
            x0x::VERSION,
            digest,
            &mut rebroadcasted_versions,
            &mut self_published,
            after_ttl,
        );
        assert_eq!(decision_after_ttl, ReleaseRebroadcastDecision::Rebroadcast);
    }

    // ------------------------------------------------------------------
    // #1106 / ADR 0094 §1: the staged-rollout scheduler (inert: a counting
    // applier stands in for the download and swap; paused tokio time).
    // ------------------------------------------------------------------

    #[derive(Default)]
    struct CountingApplier {
        attempts: AtomicU64,
        summaries: std::sync::Mutex<Vec<ApplySummary>>,
    }

    impl CountingApplier {
        fn attempts(&self) -> u64 {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    impl RolloutApplier for CountingApplier {
        fn apply<'a>(
            &'a self,
            manifest: &'a ReleaseManifest,
            summary: ApplySummary,
        ) -> ApplyFuture<'a> {
            Box::pin(async move {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                self.summaries
                    .lock()
                    .expect("summaries poisoned")
                    .push(summary);
                Ok(x0x::upgrade::UpgradeResult::Success {
                    version: manifest.version.clone(),
                })
            })
        }
    }

    fn test_scheduler(
        data_dir: &std::path::Path,
        node_id: [u8; 32],
        window_minutes: u64,
        applier: Arc<CountingApplier>,
    ) -> (Arc<RolloutScheduler>, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_watch) = watch::channel(false);
        let scheduler = RolloutScheduler::new(RolloutEnv {
            node_id,
            window_minutes,
            data_dir: data_dir.to_path_buf(),
            upgrade_apply_lock: Arc::new(Mutex::new(())),
            shutdown_watch,
            applier,
        });
        (scheduler, shutdown_tx)
    }

    /// A node whose 60-minute-window delay for `version` is in `range`.
    fn node_with_delay(version: &str, range: std::ops::Range<u64>) -> [u8; 32] {
        (0u8..=255)
            .map(|b| [b; 32])
            .find(|id| {
                let delay = x0x::upgrade::rollout::StagedRollout::new(id, 60)
                    .calculate_delay_for_version(version)
                    .as_secs();
                range.contains(&delay)
            })
            .expect("one of 256 nodes has a delay in the range")
    }

    async fn wait_until(mut done: impl FnMut() -> bool, limit: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        while tokio::time::Instant::now() < deadline {
            if done() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        done()
    }

    #[tokio::test(start_paused = true)]
    async fn a_staged_release_is_not_applied_before_its_delay() {
        let dir = tempfile::TempDir::new().unwrap();
        let version = version_newer_than_current();
        let id = node_with_delay(&version, 600..3000);
        let applier = Arc::new(CountingApplier::default());
        let (scheduler, _shutdown) = test_scheduler(dir.path(), id, 60, Arc::clone(&applier));
        let manifest = manifest_with_version(&version);

        let offer = scheduler
            .offer(&manifest, RolloutTrigger::Gossip, Some("ab".into()))
            .await;
        let RolloutOffer::Waiting(staged) = offer else {
            panic!("a 60-minute window must stage the release, got {offer:?}");
        };
        assert!(staged.delay_secs >= 600, "delay {}s", staged.delay_secs);

        // A duplicate receipt neither applies nor resets the wait.
        tokio::time::sleep(Duration::from_secs(45)).await;
        let again = scheduler.offer(&manifest, RolloutTrigger::Poll, None).await;
        assert!(
            matches!(&again, RolloutOffer::Waiting(s) if s.delay_secs == staged.delay_secs),
            "duplicate receipt: {again:?}"
        );

        // One second before the delay: still nothing applied.
        tokio::time::sleep(staged.delay() - Duration::from_secs(46)).await;
        assert_eq!(applier.attempts(), 0, "no apply before the delay");

        // After the delay: exactly one apply, with the served delay reported.
        assert!(
            wait_until(|| applier.attempts() == 1, Duration::from_secs(10)).await,
            "the waiter applies once the delay is served"
        );
        let summaries = applier.summaries.lock().unwrap().clone();
        assert_eq!(
            summaries,
            vec![ApplySummary {
                trigger: Some(RolloutTrigger::Gossip),
                sender: Some("ab".into()),
                delay_secs: staged.delay_secs,
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_resumes_the_staged_wait_without_a_reroll() {
        let dir = tempfile::TempDir::new().unwrap();
        let version = version_newer_than_current();
        let id = node_with_delay(&version, 600..3000);
        let manifest = manifest_with_version(&version);

        let applier = Arc::new(CountingApplier::default());
        let (first, shutdown) = test_scheduler(dir.path(), id, 60, Arc::clone(&applier));
        let RolloutOffer::Waiting(before) =
            first.offer(&manifest, RolloutTrigger::Gossip, None).await
        else {
            panic!("a 60-minute window must stage the release");
        };
        tokio::time::sleep(Duration::from_secs(65)).await;
        // Daemon stops: the waiter checkpoints and exits.
        shutdown.send(true).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(first);

        // The restarted daemon (same data dir, same MachineId) gets the
        // release again and resumes the wait.
        let (second, _shutdown) = test_scheduler(dir.path(), id, 60, Arc::clone(&applier));
        let RolloutOffer::Waiting(after) =
            second.offer(&manifest, RolloutTrigger::Startup, None).await
        else {
            panic!("the restarted node must still wait");
        };
        assert_eq!(
            after.delay_secs, before.delay_secs,
            "no re-roll after restart"
        );
        assert!(
            after.waited_secs >= 60,
            "the served wait survives the restart: {after:?}"
        );
        assert_eq!(after.first_trigger, RolloutTrigger::Gossip);
        assert_eq!(applier.attempts(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn two_nodes_stage_one_release_with_different_delays() {
        let version = version_newer_than_current();
        let mut delays = Vec::new();
        for byte in [1u8, 2u8] {
            let dir = tempfile::TempDir::new().unwrap();
            let applier = Arc::new(CountingApplier::default());
            let (scheduler, _shutdown) = test_scheduler(dir.path(), [byte; 32], 60, applier);
            let offer = scheduler
                .offer(
                    &manifest_with_version(&version),
                    RolloutTrigger::Gossip,
                    None,
                )
                .await;
            let staged = match offer {
                RolloutOffer::Waiting(s) | RolloutOffer::Due(s) => s,
                other => panic!("unexpected offer {other:?}"),
            };
            delays.push(staged.delay_secs);
        }
        assert_ne!(delays[0], delays[1], "two MachineIds, two delays");
        assert!(delays.iter().all(|d| *d < 3600));
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_window_is_due_at_first_receipt() {
        let dir = tempfile::TempDir::new().unwrap();
        let applier = Arc::new(CountingApplier::default());
        let (scheduler, _shutdown) = test_scheduler(dir.path(), [9; 32], 0, Arc::clone(&applier));
        let manifest = manifest_with_version(&version_newer_than_current());
        let offer = scheduler.offer(&manifest, RolloutTrigger::Poll, None).await;
        let RolloutOffer::Due(staged) = offer else {
            panic!("window 0 must be due at once, got {offer:?}");
        };
        let result = scheduler
            .apply_due(&manifest, RolloutTrigger::Poll, None, &staged)
            .await;
        assert!(matches!(
            result,
            Ok(x0x::upgrade::UpgradeResult::Success { .. })
        ));
        assert_eq!(applier.attempts(), 1);
        assert_eq!(
            scheduler
                .offer(&manifest, RolloutTrigger::Gossip, None)
                .await,
            RolloutOffer::AlreadyApplied,
            "a later receipt does not apply the same version again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_newer_release_supersedes_a_waiting_one() {
        let dir = tempfile::TempDir::new().unwrap();
        let older = version_newer_than_current();
        let newer = {
            let mut v = semver::Version::parse(&older).unwrap();
            v.patch += 1;
            v.to_string()
        };
        // A node that waits for both releases.
        let id = (0u8..=255)
            .map(|b| [b; 32])
            .find(|id| {
                let r = x0x::upgrade::rollout::StagedRollout::new(id, 60);
                r.calculate_delay_for_version(&older).as_secs() > 600
                    && r.calculate_delay_for_version(&newer).as_secs() > 600
            })
            .expect("a node that waits for both releases");
        let applier = Arc::new(CountingApplier::default());
        let (scheduler, _shutdown) = test_scheduler(dir.path(), id, 60, Arc::clone(&applier));
        assert!(matches!(
            scheduler
                .offer(&manifest_with_version(&older), RolloutTrigger::Gossip, None)
                .await,
            RolloutOffer::Waiting(_)
        ));
        assert!(matches!(
            scheduler
                .offer(&manifest_with_version(&newer), RolloutTrigger::Gossip, None)
                .await,
            RolloutOffer::Waiting(_)
        ));
        assert_eq!(
            scheduler
                .offer(&manifest_with_version(&older), RolloutTrigger::Gossip, None)
                .await,
            RolloutOffer::Superseded { by: newer }
        );
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(applier.attempts(), 1, "only the newer release applies");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreadable_rollout_state_blocks_every_apply() {
        // Codex F4: an unreadable or newer-format record must not restart
        // the wait or apply; it stays in place until repair.
        let dir = tempfile::TempDir::new().unwrap();
        let path = RolloutState::path_in(dir.path());
        let bytes = br#"{"format":"x0x.upgrade-rollout","version":2,"releases":[]}"#;
        std::fs::write(&path, bytes).unwrap();
        let applier = Arc::new(CountingApplier::default());
        let (scheduler, _shutdown) = test_scheduler(dir.path(), [5; 32], 0, Arc::clone(&applier));
        let manifest = manifest_with_version(&version_newer_than_current());
        for trigger in [RolloutTrigger::Gossip, RolloutTrigger::Manual] {
            let offer = scheduler.offer(&manifest, trigger, None).await;
            assert!(
                matches!(offer, RolloutOffer::Blocked { .. }),
                "{trigger}: {offer:?}"
            );
        }
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert_eq!(applier.attempts(), 0, "nothing applies while blocked");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "the record is kept");
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_keeps_a_newer_staged_release_ahead_of_an_older_receipt() {
        // Codex F5: 0.x.2 supersedes a waiting 0.x.1; after a restart the
        // older manifest arrives first and must still be superseded.
        let dir = tempfile::TempDir::new().unwrap();
        let older = version_newer_than_current();
        let newer = {
            let mut v = semver::Version::parse(&older).unwrap();
            v.patch += 1;
            v.to_string()
        };
        let id = (0u8..=255)
            .map(|b| [b; 32])
            .find(|id| {
                let r = x0x::upgrade::rollout::StagedRollout::new(id, 60);
                r.calculate_delay_for_version(&older).as_secs() > 600
                    && r.calculate_delay_for_version(&newer).as_secs() > 600
            })
            .expect("a node that waits for both releases");
        let applier = Arc::new(CountingApplier::default());
        let (first, shutdown) = test_scheduler(dir.path(), id, 60, Arc::clone(&applier));
        first
            .offer(&manifest_with_version(&older), RolloutTrigger::Gossip, None)
            .await;
        first
            .offer(&manifest_with_version(&newer), RolloutTrigger::Gossip, None)
            .await;
        shutdown.send(true).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(first);

        let (second, _shutdown) = test_scheduler(dir.path(), id, 60, Arc::clone(&applier));
        assert_eq!(
            second
                .offer(&manifest_with_version(&older), RolloutTrigger::Gossip, None)
                .await,
            RolloutOffer::Superseded { by: newer.clone() },
            "the stored newer release still supersedes the older one"
        );
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(applier.attempts(), 0, "the older release never applies");
    }

    #[test]
    fn the_upgraded_from_line_is_one_warn_line_after_the_restart() {
        let dir = tempfile::TempDir::new().unwrap();
        let handoff = restart::UpgradeHandoff {
            from_version: "0.0.1".to_string(),
            to_version: x0x::VERSION.to_string(),
            target_path: PathBuf::from("/opt/x0x/x0xd"),
            backup_path: PathBuf::from("/opt/x0x/x0xd.backup-0.0.1-00112233"),
            argv: vec!["/opt/x0x/x0xd".to_string()],
            cwd: "/".to_string(),
            env: std::collections::BTreeMap::new(),
            old_pid: 1,
            api_addr: "127.0.0.1:12600".parse().unwrap(),
            started_at: 42,
            mode: restart::RestartMode::SupervisedExit,
            launchd_verified: None,
            systemd_verified: None,
        };
        handoff
            .write(&dir.path().join(restart::HANDOFF_FILE_NAME))
            .unwrap();

        let (first, ()) = crate::upgrade::log_capture::capture_warn(|| {
            announce_completed_upgrade(dir.path());
        });
        let lines: Vec<&str> = first.lines().collect();
        assert_eq!(lines.len(), 1, "one line at the first start: {first:?}");
        assert!(lines[0].contains("WARN"), "{}", lines[0]);
        assert!(
            lines[0].contains(&format!("x0xd upgraded from 0.0.1 to {}", x0x::VERSION)),
            "{}",
            lines[0]
        );

        let (second, ()) = crate::upgrade::log_capture::capture_warn(|| {
            announce_completed_upgrade(dir.path());
        });
        assert!(
            second.is_empty(),
            "a later restart of the same binary is silent: {second:?}"
        );
    }

    fn daemon_restart_context() -> RestartContext {
        RestartContext {
            data_dir: Some(PathBuf::from("/var/lib/x0x")),
            api_addr: Some("127.0.0.1:12700".parse().unwrap()),
            shutdown: Some(Arc::new(|| {})),
        }
    }

    #[test]
    fn http_deferred_restart_uses_the_shared_planner_not_an_ad_hoc_exit() {
        // #261 test 6: schedule_restart_after_response builds its upgrader via
        // deferred_restart_upgrader, whose only mode decision is
        // AutoApplyUpgrader::restart_mode_with — i.e. the same
        // plan_restart_mode every other apply caller uses. There is no second
        // exit path in the HTTP handler.
        let ctx = daemon_restart_context();
        for stop_on_upgrade in [true, false] {
            let upgrader = deferred_restart_upgrader(stop_on_upgrade, ctx.clone());
            for signals in [
                // The #261 incident: config default stop_on_upgrade=true,
                // parent = shell, no INVOCATION_ID, no X0X_SUPERVISED — with
                // and without a TTY on stdin.
                restart::SupervisionSignals {
                    invocation_id: false,
                    x0x_supervised: false,
                    parent_comm: Some("bash".to_string()),
                    stdin_is_tty: true,
                },
                restart::SupervisionSignals {
                    invocation_id: false,
                    x0x_supervised: false,
                    parent_comm: Some("zsh".to_string()),
                    stdin_is_tty: false,
                },
                // Fleet contract: systemd-owned.
                restart::SupervisionSignals {
                    invocation_id: true,
                    x0x_supervised: false,
                    parent_comm: Some("systemd".to_string()),
                    stdin_is_tty: false,
                },
            ] {
                assert_eq!(
                    upgrader.restart_mode_with(&signals),
                    restart::plan_restart_mode(stop_on_upgrade, &signals),
                    "stop={stop_on_upgrade}, signals={signals:?}"
                );
            }
        }

        // Pin the incident itself through the HTTP construction: unsupervised
        // + default stop_on_upgrade=true must be a handoff, not exit(0).
        let terminal_launched = restart::SupervisionSignals {
            invocation_id: false,
            x0x_supervised: false,
            parent_comm: Some("zsh".to_string()),
            stdin_is_tty: true,
        };
        let upgrader = deferred_restart_upgrader(true, ctx.clone());
        assert_eq!(
            upgrader.restart_mode_with(&terminal_launched),
            Ok(restart::RestartMode::TransactionalHandoff)
        );
        // And the fleet contract: systemd + stop_on_upgrade=true still exits.
        let systemd = restart::SupervisionSignals {
            invocation_id: true,
            x0x_supervised: false,
            parent_comm: Some("systemd".to_string()),
            stdin_is_tty: false,
        };
        assert_eq!(
            upgrader.restart_mode_with(&systemd),
            Ok(restart::RestartMode::SupervisedExit)
        );

        // INVERTED from the pre-ADR-0061 expectation that this same HTTP path
        // returned TransactionalHandoff. A daemon under a service manager
        // whose config says stop_on_upgrade=false has two restart owners, so
        // /upgrade/apply must refuse rather than hand the operator a second
        // daemon on the same data root (#493).
        let conflicted = deferred_restart_upgrader(false, ctx);
        assert!(matches!(
            conflicted.restart_mode_with(&systemd),
            Err(restart::RestartOwnershipError::SupervisedRestartConflict { .. })
        ));
    }

    // ------------------------------------------------------------------
    // #1196 round 2: the startup update check END TO END against the
    // systemd start-rate window. The cfg(test) seams inject everything
    // OUTSIDE the decision logic — the verified release (no GitHub), the
    // systemctl show text + monotonic clock (no real systemd), and the
    // apply attempt (no binary replacement) — while the monitor skip-in
    // logic, the apply paths and the ADR-0061 §1 restart guard/readback
    // between them are the production code under test. INVOCATION_ID is
    // the REAL systemd supervision signal, set the way systemd sets it.
    // ------------------------------------------------------------------

    /// The unit invocation id fixture: 32 hex chars, as `systemctl show`
    /// renders `InvocationID` and systemd exports `INVOCATION_ID`.
    const SEAM_INVOCATION_ID: &str = "4a119611961196119611961196119611";

    /// A `systemctl show` output for THIS process on a default unit —
    /// interval 10 s, burst 5 (systemd's StartLimitIntervalSec/Burst
    /// defaults), `Restart=always`, the running test binary as ExecStart
    /// with this process's real argv and pid — with the given
    /// activation-age inputs.
    fn show_for_this_process(interval: &str, burst: &str, active_enter_us: u64) -> String {
        let exec = crate::upgrade::apply::current_binary_path()
            .expect("current binary path")
            .to_string_lossy()
            .into_owned();
        let argv = restart::current_argv().join(" ");
        format!(
            "Type=simple\n\
             Restart=always\n\
             RemainAfterExit=no\n\
             RestartPreventExitStatus=\n\
             MainPID={pid}\n\
             ExecStart={{ path={exec} ; argv[]={argv} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}\n\
             ActiveEnterTimestampMonotonic={active_enter_us}\n\
             StartLimitIntervalUSec={interval}\n\
             StartLimitBurst={burst}\n\
             InvocationID={invocation}\n\
             Environment=X0X_TEMPLATE_VERSION=1\n",
            pid = std::process::id(),
            invocation = SEAM_INVOCATION_ID,
        )
    }

    /// A newer-version manifest carrying an asset for the platform the
    /// test binary is running on, so `apply_upgrade_from_manifest`'s
    /// platform resolution succeeds.
    fn manifest_for_this_platform(version: &str) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: SCHEMA_VERSION,
            version: version.to_string(),
            timestamp: 4_102_444_800,
            assets: vec![PlatformAsset {
                target: x0x::upgrade::manifest::current_platform_target()
                    .expect("current platform target")
                    .to_string(),
                archive_url: "https://example.com/x0xd-archive.tar.gz".to_string(),
                archive_sha256: [0xAA; 32],
                signature_url: "https://example.com/x0xd-archive.tar.gz.sig".to_string(),
            }],
            // Empty skill URL with the missing-file hash: SKILL.md sync
            // takes its already-up-to-date early return, no HTTP.
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        }
    }

    /// A scenario with a single readback call, the given limits, and a
    /// fresh activation (2 s old) — the #1196 starting point.
    fn one_call_scenario(interval: &str, burst: &str) -> restart::systemd_readback_seam::Scenario {
        restart::systemd_readback_seam::Scenario {
            cgroup: "0::/system.slice/x0xd.service".to_string(),
            invocation_id: Some(SEAM_INVOCATION_ID.to_string()),
            calls: vec![restart::systemd_readback_seam::ReadbackCall {
                show_output: show_for_this_process(interval, burst, 1_000_000),
                monotonic_now_us: 3_000_000,
            }],
        }
    }

    /// The daemon-side rollout the end-to-end tests need: the production
    /// applier with a restart context over the given data dir, a fresh
    /// apply lock and a live (never-signalled) shutdown watch. The rollout
    /// window is 0, so the startup check is due at first receipt (#1196 is
    /// about the start-rate retry, not the stagger). The returned sender
    /// keeps the watch's sender alive — a dropped sender would read as
    /// shutdown.
    fn e2e_startup_runtime(
        data_dir: &std::path::Path,
    ) -> (Arc<RolloutScheduler>, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_watch) = watch::channel(false);
        let rollout = RolloutScheduler::new(RolloutEnv {
            node_id: [0x11; 32],
            window_minutes: 0,
            data_dir: data_dir.to_path_buf(),
            upgrade_apply_lock: Arc::new(Mutex::new(())),
            shutdown_watch,
            applier: Arc::new(DaemonApplier {
                stop_on_upgrade: true,
                restart_context: listener_restart_context(
                    data_dir,
                    SocketAddr::from(([127, 0, 0, 1], 12700)),
                    Arc::new(|| {}),
                ),
            }),
        });
        (rollout, shutdown_tx)
    }

    /// The #1196 fleet scenario, end to end: a default unit
    /// (StartLimitIntervalUSec=10 s, StartLimitBurst=5) whose activation
    /// is 2 s old when the daemon's startup update check first applies —
    /// and whose start-rate window has aged out by the time the check
    /// retries. The check must end with the apply ATTEMPTED, not refused
    /// and skipped until the next fallback poll.
    #[tokio::test(start_paused = true)]
    async fn startup_check_applies_after_start_rate_window_ages_out() {
        // Activation entered at monotonic 1 s. The first readback observes
        // monotonic 3 s (2 s into the 10 s window — fresh activation);
        // the retry's observes monotonic 15 s (14 s in — the window has
        // aged out completely).
        let _readback =
            restart::systemd_readback_seam::install(restart::systemd_readback_seam::Scenario {
                cgroup: "0::/system.slice/x0xd.service".to_string(),
                invocation_id: Some(SEAM_INVOCATION_ID.to_string()),
                calls: vec![
                    restart::systemd_readback_seam::ReadbackCall {
                        show_output: show_for_this_process("10s", "5", 1_000_000),
                        monotonic_now_us: 3_000_000,
                    },
                    restart::systemd_readback_seam::ReadbackCall {
                        show_output: show_for_this_process("10s", "5", 1_000_000),
                        monotonic_now_us: 15_000_000,
                    },
                ],
            });

        // The apply attempt: counts attempts and answers as the
        // destructive half succeeding on the new version.
        let attempts = Arc::new(AtomicU64::new(0));
        let hook_attempts = Arc::clone(&attempts);
        let _apply =
            crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |_plan, manifest| {
                hook_attempts.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success {
                    version: manifest.version.clone(),
                }
            }));

        let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
            manifest: manifest_for_this_platform("9.9.9"),
            manifest_json: Vec::new(),
            signature: Vec::new(),
            gossip_payload: Vec::new(),
        });

        let data_dir = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            data_dir: data_dir.path().to_path_buf(),
            ..Default::default()
        };
        let (rollout, _shutdown_tx) = e2e_startup_runtime(data_dir.path());

        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, &rollout).await;

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "#1196: once the start-rate window has aged out, the startup check \
             must end with the apply ATTEMPTED (exactly one apply attempt; the \
             window-refused first try never reached the apply) — not refused, \
             skipped, and deferred to the next fallback poll"
        );
        assert!(
            matches!(&result, Ok(Some(v)) if v == "9.9.9"),
            "the aged-out retry applies the new version: {result:?}"
        );
        assert!(
            before.elapsed() >= Duration::from_secs(10),
            "the retry happens only after the readback's remaining window \
             (8 s) plus the retry margin (2 s) has been waited out; waited \
             {:?} instead",
            before.elapsed()
        );
    }

    /// StartLimitIntervalUSec=0 disables start-rate limiting entirely (man
    /// systemd.service): the readback must verify WITHOUT the window check
    /// — even mid-window — and the startup check must apply on the FIRST
    /// attempt with zero wait. Identical on main and on the fix: the
    /// `interval != 0 && burst != 0` gate predates #1196 and the fix does
    /// not touch it.
    #[tokio::test(start_paused = true)]
    async fn startup_check_applies_immediately_when_start_limit_interval_is_zero() {
        let _readback = restart::systemd_readback_seam::install(one_call_scenario("0", "5"));
        let attempts = Arc::new(AtomicU64::new(0));
        let hook_attempts = Arc::clone(&attempts);
        let _apply =
            crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |_plan, manifest| {
                hook_attempts.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success {
                    version: manifest.version.clone(),
                }
            }));
        let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
            manifest: manifest_for_this_platform("9.9.9"),
            manifest_json: Vec::new(),
            signature: Vec::new(),
            gossip_payload: Vec::new(),
        });
        let data_dir = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            data_dir: data_dir.path().to_path_buf(),
            ..Default::default()
        };
        let (rollout, _shutdown_tx) = e2e_startup_runtime(data_dir.path());
        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, &rollout).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "interval 0: the first attempt applies — no window to wait out"
        );
        assert!(
            matches!(&result, Ok(Some(v)) if v == "9.9.9"),
            "interval 0: the new version applies: {result:?}"
        );
        assert_eq!(
            before.elapsed(),
            Duration::ZERO,
            "interval 0: zero wait before the apply"
        );
    }

    /// StartLimitBurst=0 disables start-rate limiting entirely (man
    /// systemd.service): same contract as interval 0.
    #[tokio::test(start_paused = true)]
    async fn startup_check_applies_immediately_when_start_limit_burst_is_zero() {
        let _readback = restart::systemd_readback_seam::install(one_call_scenario("10s", "0"));
        let attempts = Arc::new(AtomicU64::new(0));
        let hook_attempts = Arc::clone(&attempts);
        let _apply =
            crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |_plan, manifest| {
                hook_attempts.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success {
                    version: manifest.version.clone(),
                }
            }));
        let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
            manifest: manifest_for_this_platform("9.9.9"),
            manifest_json: Vec::new(),
            signature: Vec::new(),
            gossip_payload: Vec::new(),
        });
        let data_dir = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            data_dir: data_dir.path().to_path_buf(),
            ..Default::default()
        };
        let (rollout, _shutdown_tx) = e2e_startup_runtime(data_dir.path());
        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, &rollout).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "burst 0: the first attempt applies — no window to wait out"
        );
        assert!(
            matches!(&result, Ok(Some(v)) if v == "9.9.9"),
            "burst 0: the new version applies: {result:?}"
        );
        assert_eq!(
            before.elapsed(),
            Duration::ZERO,
            "burst 0: zero wait before the apply"
        );
    }

    // ------------------------------------------------------------------
    // #1196: startup check waits out an unaged systemd start-rate window
    // and retries the apply once (inert: injected attempts, no network).
    // ------------------------------------------------------------------

    /// A `SupervisedSystemdPolicyNotGuaranteed` refusal with the given
    /// retry hint — the shape the systemd readback produces for a fresh
    /// activation with a live start-rate limit.
    fn systemd_refusal(retry_after: Option<Duration>) -> x0x::upgrade::UpgradeError {
        x0x::upgrade::UpgradeError::RestartOwnership(
            restart::RestartOwnershipError::SupervisedSystemdPolicyNotGuaranteed {
                signal: "INVOCATION_ID".to_string(),
                exit_code: 0,
                detail: "the unit's current activation has not outlived StartLimitIntervalUSec"
                    .to_string(),
                retry_after,
            },
        )
    }

    /// The fresh-activation, default-unit scenario from the issue: the first
    /// readback refuses with the not-outlived reason, a later one succeeds.
    /// The startup check must attempt the apply a second time after the
    /// readback's own remaining window (+ margin), and that retry applies.
    #[tokio::test(start_paused = true)]
    async fn startup_check_retries_once_after_start_rate_window_elapses() {
        const WINDOW: Duration = Duration::from_secs(10);
        let attempts = Arc::new(AtomicU64::new(0));
        let lock_acquired_during_wait = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lock = Arc::new(Mutex::new(()));
        let (_notify, mut shutdown) = watch::channel(false);

        let attempts_in_attempt = Arc::clone(&attempts);
        let flag = Arc::clone(&lock_acquired_during_wait);
        let lock_for_watcher = Arc::clone(&lock);
        let started = tokio::time::Instant::now();
        let result = apply_with_start_rate_retry(
            Some(&lock),
            move || {
                let attempts = Arc::clone(&attempts_in_attempt);
                let lock = Arc::clone(&lock_for_watcher);
                let flag = Arc::clone(&flag);
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        // A concurrent apply path parking on the shared lock
                        // behind this attempt: it may only get through while
                        // the helper WAITS (the guard is dropped for the
                        // window wait, not held).
                        tokio::spawn(async move {
                            let _guard = lock.lock().await;
                            flag.store(true, Ordering::SeqCst);
                        });
                        Err(systemd_refusal(Some(WINDOW)))
                    } else {
                        // The later readback succeeded: the activation has
                        // now outlived the window.
                        Ok(x0x::upgrade::UpgradeResult::Success {
                            version: "9.9.9".to_string(),
                        })
                    }
                }
            },
            &mut shutdown,
        )
        .await;

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "exactly one retry, not a loop"
        );
        assert!(
            matches!(
                &result,
                Ok(x0x::upgrade::UpgradeResult::Success { version }) if version == "9.9.9"
            ),
            "the retry applies the version instead of skipping it: {result:?}"
        );
        assert!(
            lock_acquired_during_wait.load(Ordering::SeqCst),
            "the apply lock is released for the window wait"
        );
        assert!(
            started.elapsed() >= WINDOW + START_RATE_RETRY_MARGIN,
            "the wait is the readback's remaining window plus the margin, \
             not a hard-coded interval"
        );
    }

    /// Daemon shutdown during the window wait cancels the retry and returns
    /// the original refusal — no bytes were replaced, and shutdown is never
    /// held up by the wait.
    #[tokio::test(start_paused = true)]
    async fn startup_check_start_rate_wait_is_cancelled_by_shutdown() {
        let attempts = Arc::new(AtomicU64::new(0));
        let (notify, mut shutdown) = watch::channel(false);
        let notifier = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = notify.send(true);
        });
        let attempts_in_attempt = Arc::clone(&attempts);
        let started = tokio::time::Instant::now();
        let result = apply_with_start_rate_retry(
            None,
            move || {
                let attempts = Arc::clone(&attempts_in_attempt);
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err(systemd_refusal(Some(Duration::from_secs(10))))
                }
            },
            &mut shutdown,
        )
        .await;
        notifier.await.expect("notifier ran");

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "no retry after shutdown"
        );
        assert!(
            matches!(
                &result,
                Err(x0x::upgrade::UpgradeError::RestartOwnership(
                    restart::RestartOwnershipError::SupervisedSystemdPolicyNotGuaranteed { .. }
                ))
            ),
            "the original refusal is returned: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(12),
            "cancelled far short of the full window wait"
        );
    }

    /// Every refusal that is not ONLY the not-yet-aged-out start-rate window
    /// keeps today's behaviour: one attempt, no wait, the error returned.
    #[tokio::test(start_paused = true)]
    async fn startup_check_does_not_wait_or_retry_other_refusals() {
        #[derive(Debug, Clone, Copy)]
        enum Refusal {
            SystemdWithoutWindow,
            SupervisedRestartConflict,
            HashMismatch,
        }
        let mk = |kind: Refusal| match kind {
            // Same error shape but without a retry hint: a policy defect,
            // not a time-bound window.
            Refusal::SystemdWithoutWindow => systemd_refusal(None),
            Refusal::SupervisedRestartConflict => x0x::upgrade::UpgradeError::RestartOwnership(
                restart::RestartOwnershipError::SupervisedRestartConflict {
                    signal: "INVOCATION_ID".to_string(),
                    exit_code: 0,
                },
            ),
            Refusal::HashMismatch => x0x::upgrade::UpgradeError::HashMismatch,
        };

        for kind in [
            Refusal::SystemdWithoutWindow,
            Refusal::SupervisedRestartConflict,
            Refusal::HashMismatch,
        ] {
            let attempts = Arc::new(AtomicU64::new(0));
            let (_notify, mut shutdown) = watch::channel(false);
            let before = tokio::time::Instant::now();

            let attempts_in_attempt = Arc::clone(&attempts);
            let result = apply_with_start_rate_retry(
                None,
                move || {
                    let attempts = Arc::clone(&attempts_in_attempt);
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Err(mk(kind))
                    }
                },
                &mut shutdown,
            )
            .await;

            assert_eq!(
                attempts.load(Ordering::SeqCst),
                1,
                "{kind:?}: exactly one attempt, no retry"
            );
            assert!(result.is_err(), "{kind:?}: the refusal is returned");
            assert_eq!(
                before.elapsed(),
                Duration::ZERO,
                "{kind:?}: no wait before giving up"
            );
        }
    }
}
