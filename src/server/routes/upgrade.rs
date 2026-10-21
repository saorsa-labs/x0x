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
use futures::{Stream, StreamExt};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Mutex};
use x0x::upgrade::apply::{AutoApplyUpgrader, ReleasePermit, RestartContext};
use x0x::upgrade::manifest::{decode_signed_manifest, is_newer, ReleaseManifest, RELEASE_TOPIC};
use x0x::upgrade::monitor::UpgradeMonitor;
use x0x::upgrade::monitor::VerifiedRelease;
use x0x::upgrade::restart::RestartOwnershipError;
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

/// Runtime pieces the daemon's startup check needs now that it runs AFTER
/// the API listener is bound (#1086), concurrently with the other updater
/// tasks: the #261 restart planner context (bound API address for the
/// health commit + the graceful-shutdown hook) and the apply lock shared
/// with the gossip release listener and the fallback poll.
pub(in crate::server) struct StartupUpdateCheckRuntime {
    /// Restart planner context for a successful apply (bound API address +
    /// shutdown hook).
    pub restart_context: RestartContext,
    /// Serializes destructive binary replacement with the other apply paths.
    pub upgrade_apply_lock: Arc<Mutex<()>>,
    /// Daemon shutdown watch; cancels the #1196 start-rate window wait so
    /// shutdown is never held up by a time-bound refusal.
    pub shutdown_watch: watch::Receiver<bool>,
    #[cfg(unix)]
    pub staging: StartupStagingContext,
}

#[cfg(unix)]
#[derive(Clone)]
pub(in crate::server) struct StartupStagingContext {
    pub install: PathBuf,
    pub identity_root: PathBuf,
    pub machine_id: [u8; 32],
    #[cfg(test)]
    pub clock: Option<crate::upgrade::staging_runtime::Clock>,
    #[cfg(test)]
    pub observed: Option<crate::upgrade::staging_runtime::Observer>,
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

/// The shutdown trigger and watch travel together to updater tasks.
pub(in crate::server) type UpdateShutdown = (Arc<dyn Fn() + Send + Sync>, watch::Receiver<bool>);

/// Resume only a durable interrupted probe. The request/listener returns
/// promptly; this waiter releases the apply mutex throughout every backoff.
/// Its process-local claim prevents duplicate timers, while the install lock
/// and record decide whether a fresh attempt is still allowed.
fn schedule_probe_retry(
    upgrader: &AutoApplyUpgrader,
    manifest: &ReleaseManifest,
    apply_lock: Arc<Mutex<()>>,
    mut shutdown: watch::Receiver<bool>,
) {
    if *shutdown.borrow() || shutdown.has_changed().is_err() {
        return;
    }
    let install = match x0x::upgrade::apply::current_binary_path().and_then(|path| {
        std::fs::canonicalize(path)
            .map_err(|error| x0x::upgrade::UpgradeError::Other(error.to_string()))
    }) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(%error, "Cannot identify install for probe retry");
            return;
        }
    };
    let Some(owner) = x0x::upgrade::probe_retry::claim_retry(install, manifest.version.clone())
    else {
        return;
    };
    let upgrader = upgrader.for_probe_retry();
    let manifest = manifest.clone();
    tokio::spawn(async move {
        let _owner = owner;
        let result = x0x::upgrade::probe_retry::run_retry_loop(
            &apply_lock,
            &mut shutdown,
            || upgrader.probe_retry_delay(&manifest.version),
            || async {
                // A long backoff does not extend a signed manifest's lifetime.
                x0x::upgrade::monitor::validate_manifest_timestamp(&manifest)?;
                upgrader.apply_upgrade_from_manifest(&manifest).await
            },
        )
        .await;
        match result {
            Ok(Some(result)) => {
                tracing::info!(?result, version = %manifest.version, "Probe retry apply finished");
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    version = %manifest.version,
                    "Probe retry stopped; durable state retains the cause"
                );
            }
        }
    });
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
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return Err(x0x::upgrade::UpgradeError::Other(
                "upgrade cancelled by shutdown".into(),
            ));
        }
        let _guard = match apply_lock {
            Some(lock) => Some(tokio::select! {
                guard = lock.lock() => guard,
                _ = shutdown.changed() => return Err(x0x::upgrade::UpgradeError::Other("upgrade cancelled by shutdown".into())),
            }),
            None => None,
        };
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return Err(x0x::upgrade::UpgradeError::Other(
                "upgrade cancelled by shutdown".into(),
            ));
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => Err(x0x::upgrade::UpgradeError::Other("upgrade cancelled by shutdown".into())),
            result = attempt() => result,
        }
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
        Some(lock) => Some(tokio::select! {
            guard = lock.lock() => guard,
            _ = shutdown.changed() => return first,
        }),
        None => None,
    };
    if *shutdown.borrow() || shutdown.has_changed().is_err() {
        return first;
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => first,
        result = attempt() => result,
    }
}
/// Startup GitHub check. Returns Some(version) if an update was applied.
///
/// The daemon's startup check supplies `runtime`. It is
/// spawned by `serve_with_options` as a background task after the API
/// listener is bound (#1086: a firewalled update endpoint must never gate
/// API readiness on its ~30 s HTTP timeout). It hands the restart to the #261
/// planner because a daemon process must come back up, and serializes its
/// apply against the gossip release listener and the fallback poll. On a
/// systemd host whose activation has not yet outlived
/// `StartLimitIntervalUSec`, it waits out the window and retries the apply
/// once (#1196) instead of skipping the version. All production callers
/// supply a runtime. The legacy `None` branch remains for a separate cleanup;
/// `x0xd --check-updates` now uses the read-only reporter and never calls this
/// installer.
pub(in crate::server) async fn run_startup_update_check(
    config: &DaemonConfig,
    agent: Option<&Arc<Agent>>,
    runtime: Option<StartupUpdateCheckRuntime>,
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

    // Broadcast to gossip so other nodes benefit from our discovery
    if let Some(agent) = agent {
        if let Err(e) = agent
            .publish(RELEASE_TOPIC, verified.gossip_payload.clone())
            .await
        {
            tracing::debug!(error = %e, "Failed to broadcast discovered release: {e}");
        }
    }

    // The startup check runs beside the gossip release listener and the
    // fallback poll now that it no longer gates startup (#1086); each apply
    // attempt takes the shared apply lock before touching the binary,
    // exactly as they do. The lock is taken per attempt (not held across
    // the #1196 start-rate window wait) so concurrent apply paths are not
    // starved behind a time-bound refusal.
    let apply_lock = runtime
        .as_ref()
        .map(|runtime| Arc::clone(&runtime.upgrade_apply_lock));
    let mut shutdown_watch = runtime
        .as_ref()
        .map(|runtime| runtime.shutdown_watch.clone());
    #[cfg(unix)]
    let staging_context = runtime.as_ref().map(|runtime| runtime.staging.clone());

    let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(config.update.stop_on_upgrade);
    let upgrader = match runtime {
        Some(runtime) => upgrader
            .with_restart_on_success(true)
            .with_restart_context(runtime.restart_context),
        // Legacy no-runtime mode, unused by production callers. It does
        // not restart, but still supplies the planner's data directory
        // and configured address. The read-only reporter does not use it.
        None => upgrader
            .with_restart_on_success(false)
            .with_restart_context(RestartContext {
                data_dir: Some(config.data_dir.clone()),
                api_addr: Some(config.api_address),
                shutdown: None,
            }),
    };

    #[cfg(unix)]
    let upgrader = if let Some(context) = staging_context {
        let platform = x0x::upgrade::manifest::current_platform_target()
            .ok_or(x0x::upgrade::UpgradeError::UnsupportedPlatform)?;
        let asset = verified
            .manifest
            .matches_platform(platform)
            .ok_or(x0x::upgrade::UpgradeError::NoPlatformAsset)?;
        let upgrader = upgrader.with_staging_request(crate::upgrade::staging::StagingRequest {
            install: context.install,
            data_root: config.data_dir.canonicalize()?,
            identity_root: context.identity_root,
            machine_id: context.machine_id,
            version: verified.manifest.version.clone(),
            manifest_sha256: Sha256::digest(&verified.manifest_json).into(),
            archive_sha256: asset.archive_sha256,
            window_minutes: config.update.rollout_window_minutes,
        });
        #[cfg(test)]
        let upgrader = upgrader
            .with_staging_clock(context.clock)
            .with_staging_observer(context.observed);
        upgrader
    } else {
        upgrader
    };

    let attempt = || upgrader.apply_upgrade_from_manifest(&verified.manifest);
    let result = async {
        #[cfg(unix)]
        if let Some(shutdown) = shutdown_watch.as_mut() {
            upgrader.wait_for_staging(shutdown).await?;
            x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest)?;
        }
        // Staging must precede all release content writes, including the guide.
        update_skill_while_running(
            &verified.manifest,
            &config.data_dir,
            shutdown_watch.clone(),
            #[cfg(unix)]
            Some(&upgrader),
        )
        .await;
        match shutdown_watch.as_mut() {
            // Daemon startup check: #1196 — a refusal that is ONLY the not-yet-
            // aged-out systemd start-rate window is waited out (bounded by the
            // readback's own remaining window) and retried once, instead of
            // skipping the version until the 6-hourly fallback poll.
            Some(shutdown) => {
                apply_with_start_rate_retry(apply_lock.as_ref(), attempt, shutdown).await
            }
            // Legacy no-runtime mode has no shutdown watch or retry.
            None => attempt().await,
        }
    }
    .await;

    match result {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => Ok(Some(version)),
        Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
            tracing::warn!(%reason, "Startup upgrade rolled back");
            Ok(None)
        }
        Ok(x0x::upgrade::UpgradeResult::NoUpgrade) => Ok(None),
        Err(e) => {
            tracing::error!(error = %e, "Startup upgrade failed: {e}");
            if let (Some(lock), Some(shutdown)) = (apply_lock.as_ref(), shutdown_watch.as_ref()) {
                schedule_probe_retry(
                    &upgrader,
                    &verified.manifest,
                    Arc::clone(lock),
                    shutdown.clone(),
                );
            }
            Ok(None)
        }
    }
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

/// One server-owned background worker serves gossip and fallback. Submission
/// replaces only the latest queued release; an active blocking operation is
/// cancelled at admission and still awaited before the next release starts.
pub(in crate::server) struct BackgroundRuntime {
    pub config: DaemonUpdateConfig,
    pub data_dir: PathBuf,
    pub api_addr: SocketAddr,
    pub shutdown: UpdateShutdown,
    pub apply_lock: Arc<Mutex<()>>,
    #[cfg(unix)]
    pub staging: StartupStagingContext,
    #[cfg(test)]
    pub operation_observer: Option<Arc<dyn Fn(bool) + Send + Sync>>,
}

impl BackgroundRuntime {
    /// Resolve the actual boot context before constructing an apply owner.
    pub(in crate::server) async fn from_boot(
        config: &DaemonConfig,
        api_addr: SocketAddr,
        shutdown: UpdateShutdown,
        apply_lock: Arc<Mutex<()>>,
        #[cfg(unix)] identity_dir: Option<PathBuf>,
        #[cfg(unix)] machine_id: [u8; 32],
    ) -> Result<Self> {
        #[cfg(unix)]
        let staging = {
            let identity_root = match identity_dir {
                Some(path) => path,
                None => crate::storage::x0x_dir().await?,
            };
            StartupStagingContext {
                install: crate::upgrade::apply::current_binary_path()?.canonicalize()?,
                identity_root: identity_root.canonicalize()?,
                machine_id,
                #[cfg(test)]
                clock: None,
                #[cfg(test)]
                observed: None,
            }
        };
        Ok(Self {
            config: config.update.clone(),
            data_dir: config.data_dir.clone(),
            api_addr,
            shutdown,
            apply_lock,
            #[cfg(unix)]
            staging,
            #[cfg(test)]
            operation_observer: None,
        })
    }

    /// Spawn the server's real discovery source under its configured gate.
    pub(in crate::server) fn spawn_source<F>(
        enabled: bool,
        submit: Option<BackgroundSubmit>,
        source: impl FnOnce(BackgroundSubmit) -> F,
    ) -> Option<tokio::task::JoinHandle<()>>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if !enabled {
            return None;
        }
        submit.map(|submit| tokio::spawn(source(submit)))
    }
}

/// Intake results only; Accepted does not acknowledge a durable receipt or
/// supersession. The owned worker must still complete those record barriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmitOutcome {
    Accepted,
    Duplicate,
    Older,
    Backoff,
}

#[derive(Default)]
struct BackgroundSlot {
    latest: Option<Arc<VerifiedRelease>>,
    pending: bool,
    active: Option<ReleasePermit>,
    failed_at: Option<Instant>,
    closed: bool,
}

#[derive(Clone, Default)]
pub(in crate::server) struct BackgroundSubmit {
    slot: Arc<std::sync::Mutex<BackgroundSlot>>,
    wake: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    processed: Option<Arc<dyn Fn(String, SubmitOutcome) + Send + Sync>>,
}

impl BackgroundSubmit {
    fn submit(
        &self,
        verified: VerifiedRelease,
    ) -> Result<SubmitOutcome, x0x::upgrade::UpgradeError> {
        let version = verified.manifest.version.clone();
        let outcome = self.submit_inner(verified)?;
        #[cfg(test)]
        if let Some(processed) = &self.processed {
            processed(version.clone(), outcome);
        }
        tracing::debug!(%version, ?outcome, "Background release consumed");
        Ok(outcome)
    }

    fn submit_inner(
        &self,
        verified: VerifiedRelease,
    ) -> Result<SubmitOutcome, x0x::upgrade::UpgradeError> {
        use std::cmp::Ordering as Cmp;
        let error = |message: &str| x0x::upgrade::UpgradeError::Other(message.into());
        x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest)?;
        let version = semver::Version::parse(&verified.manifest.version)
            .map_err(|_| error("invalid background release version"))?;
        let platform = x0x::upgrade::manifest::current_platform_target()
            .ok_or(x0x::upgrade::UpgradeError::UnsupportedPlatform)?;
        verified
            .manifest
            .matches_platform(platform)
            .ok_or(x0x::upgrade::UpgradeError::NoPlatformAsset)?;
        #[cfg(unix)]
        if !version.pre.is_empty() || version.to_string() != verified.manifest.version {
            return Err(error(
                "background staging requires a canonical stable release",
            ));
        }
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| error("background owner unavailable"))?;
        if slot.closed {
            return Err(error("background owner stopped"));
        }
        if let Some(previous) = &slot.latest {
            let prior = semver::Version::parse(&previous.manifest.version)
                .map_err(|_| error("invalid selected background release"))?;
            match version.cmp_precedence(&prior) {
                Cmp::Less => return Ok(SubmitOutcome::Older),
                Cmp::Equal => {
                    if verified.manifest.version != previous.manifest.version
                        || verified.manifest_json != previous.manifest_json
                    {
                        return Err(error("equal-precedence background releases conflict"));
                    }
                    if slot.pending || slot.active.is_some() || slot.failed_at.is_none() {
                        return Ok(SubmitOutcome::Duplicate);
                    }
                    if slot
                        .failed_at
                        .is_some_and(|failed| failed.elapsed() < Duration::from_secs(30 * 60))
                    {
                        return Ok(SubmitOutcome::Backoff);
                    }
                }
                Cmp::Greater => {}
            }
        }
        if let Some(active) = &slot.active {
            active.cancel();
        }
        slot.latest = Some(Arc::new(verified));
        slot.pending = true;
        slot.failed_at = None;
        drop(slot);
        self.wake.notify_one();
        Ok(SubmitOutcome::Accepted)
    }

    // The fallback used to skip both broadcast and apply for a failed
    // version. Keep that policy while sharing the bounded failure slot.
    fn in_retry_backoff(&self, verified: &VerifiedRelease) -> bool {
        let Ok(slot) = self.slot.lock() else {
            return false;
        };
        !slot.pending
            && slot.active.is_none()
            && slot.latest.as_ref().is_some_and(|prior| {
                prior.manifest.version == verified.manifest.version
                    && prior.manifest_json == verified.manifest_json
            })
            && slot
                .failed_at
                .is_some_and(|failed| failed.elapsed() < Duration::from_secs(30 * 60))
    }

    fn close(&self) {
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.closed = true;
        slot.pending = false;
        if let Some(active) = &slot.active {
            active.cancel();
        }
        self.wake.notify_waiters();
    }
}

pub(in crate::server) struct BackgroundOwner {
    submit: BackgroundSubmit,
    runtime: BackgroundRuntime,
}

impl Drop for BackgroundOwner {
    fn drop(&mut self) {
        self.submit.close();
    }
}

pub(in crate::server) fn background_channel(
    runtime: BackgroundRuntime,
) -> (BackgroundSubmit, BackgroundOwner) {
    let submit = BackgroundSubmit::default();
    (submit.clone(), BackgroundOwner { submit, runtime })
}

impl BackgroundOwner {
    pub(in crate::server) async fn run(self) {
        let mut shutdown = self.runtime.shutdown.1.clone();
        loop {
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return;
            }
            let notified = self.submit.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let next = {
                let Ok(mut slot) = self.submit.slot.lock() else {
                    return;
                };
                if slot.closed {
                    return;
                }
                if slot.pending {
                    let permit = ReleasePermit::default();
                    #[cfg(test)]
                    let permit = {
                        let mut permit = permit;
                        permit.observer = self.runtime.operation_observer.clone();
                        permit
                    };
                    slot.active = Some(permit.clone());
                    slot.pending = false;
                    slot.latest.clone().map(|release| (release, permit))
                } else {
                    None
                }
            };
            let Some((release, permit)) = next else {
                tokio::select! {
                    _ = &mut notified => {}
                    _ = shutdown.changed() => return,
                }
                continue;
            };
            // Submissions can cancel the permit and overwrite the single
            // pending slot. They do not drop this future or spawn more workers.
            let (_, result) = tokio::select! {
                result = apply_background_release(&self.runtime, &release, &permit) => result,
                _ = shutdown.changed() => { permit.cancel(); return; }
            };
            {
                let Ok(mut slot) = self.submit.slot.lock() else {
                    return;
                };
                slot.active = None;
                if !slot.pending {
                    slot.failed_at = if matches!(
                        &result,
                        Err(_) | Ok(x0x::upgrade::UpgradeResult::RolledBack { .. })
                    ) {
                        Some(Instant::now())
                    } else {
                        None
                    };
                }
            }
            match result {
                Ok(result) => {
                    tracing::info!(?result, version = %release.manifest.version, "Background apply finished")
                }
                Err(error) => {
                    tracing::warn!(%error, version = %release.manifest.version, "Background apply stopped")
                }
            }
        }
    }
}

async fn apply_background_release(
    runtime: &BackgroundRuntime,
    verified: &VerifiedRelease,
    permit: &ReleasePermit,
) -> (
    AutoApplyUpgrader,
    Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError>,
) {
    let upgrader = AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(runtime.config.stop_on_upgrade)
        .with_restart_context(listener_restart_context(
            &runtime.data_dir,
            runtime.api_addr,
            Arc::clone(&runtime.shutdown.0),
        ))
        .with_release_permit(permit.clone());
    #[cfg(unix)]
    let upgrader = match background_staging_request(runtime, verified) {
        Ok(request) => {
            let upgrader = upgrader.with_staging_request(request);
            #[cfg(test)]
            let upgrader = upgrader
                .with_staging_clock(runtime.staging.clock.clone())
                .with_staging_observer(runtime.staging.observed.clone());
            upgrader
        }
        Err(error) => return (upgrader, Err(error)),
    };
    let mut shutdown = runtime.shutdown.1.clone();
    let result = async {
        if !runtime.config.enabled {
            return Err(x0x::upgrade::UpgradeError::Other("background updates disabled".into()));
        }
        #[cfg(unix)]
        upgrader.wait_for_staging(&mut shutdown).await?;
        permit.check()?;
        // Retain the legacy guide update only after rollout is due. This is
        // not candidate health acceptance or the later host-commit promotion.
        update_skill_inner(
            &verified.manifest,
            &runtime.data_dir,
            Some(shutdown.clone()),
            Some(permit.clone()),
            #[cfg(unix)]
            Some(&upgrader),
        ).await;
        permit.check()?;
        let result = {
            let _guard = tokio::select! {
                guard = runtime.apply_lock.lock() => guard,
                _ = permit.cancelled() => return Err(x0x::upgrade::UpgradeError::Other("background release cancelled".into())),
                _ = shutdown.changed() => return Err(x0x::upgrade::UpgradeError::Other("background shutdown".into())),
            };
            permit.check()?;
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return Err(x0x::upgrade::UpgradeError::Other("background shutdown".into()));
            }
            x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest)?;
            upgrader.apply_upgrade_from_manifest(&verified.manifest).await
        };
        if result.is_ok() { return result; }
        permit.check()?;
        // A retry remains part of this release's owned future. Never detach a
        // timer after the listener has superseded its release or stopped.
        #[cfg(unix)]
        let install = runtime.staging.install.clone();
        #[cfg(not(unix))]
        let install = x0x::upgrade::apply::current_binary_path()?.canonicalize()
            .map_err(|error| x0x::upgrade::UpgradeError::Other(error.to_string()))?;
        let Some(_retry_owner) = x0x::upgrade::probe_retry::claim_retry(install, verified.manifest.version.clone()) else { return result; };
        match x0x::upgrade::probe_retry::run_retry_loop(
            &runtime.apply_lock, &mut shutdown,
            || async { permit.check()?; upgrader.probe_retry_delay(&verified.manifest.version).await },
            || async {
                permit.check()?;
                x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest)?;
                upgrader.apply_upgrade_from_manifest(&verified.manifest).await
            },
        ).await? {
            Some(value) => Ok(value),
            None => result,
        }
    }.await;
    (upgrader, result)
}

#[cfg(unix)]
fn background_staging_request(
    runtime: &BackgroundRuntime,
    verified: &VerifiedRelease,
) -> Result<crate::upgrade::staging::StagingRequest, x0x::upgrade::UpgradeError> {
    let platform = x0x::upgrade::manifest::current_platform_target()
        .ok_or(x0x::upgrade::UpgradeError::UnsupportedPlatform)?;
    let asset = verified
        .manifest
        .matches_platform(platform)
        .ok_or(x0x::upgrade::UpgradeError::NoPlatformAsset)?;
    Ok(crate::upgrade::staging::StagingRequest {
        install: runtime.staging.install.clone(),
        data_root: runtime
            .data_dir
            .canonicalize()
            .map_err(|error| x0x::upgrade::UpgradeError::Other(error.to_string()))?,
        identity_root: runtime.staging.identity_root.clone(),
        machine_id: runtime.staging.machine_id,
        version: verified.manifest.version.clone(),
        manifest_sha256: Sha256::digest(&verified.manifest_json).into(),
        archive_sha256: asset.archive_sha256,
        window_minutes: runtime.config.rollout_window_minutes,
    })
}

/// Gossip remains the primary release source. Verification retains the exact
/// signed bytes; the shared owner alone performs the potentially long wait.
pub(in crate::server) async fn run_gossip_update_listener(
    agent: Arc<Agent>,
    submit: BackgroundSubmit,
    self_published: Arc<Mutex<SelfPublishedReleaseManifests>>,
    shutdown: watch::Receiver<bool>,
) {
    let subscription = match agent.subscribe(RELEASE_TOPIC).await {
        Ok(subscription) => subscription,
        Err(error) => {
            tracing::warn!(%error, "Failed to subscribe to release topic");
            return;
        }
    };
    let releases = futures::stream::unfold(subscription, |mut subscription| async move {
        loop {
            let message = subscription.recv().await?;
            if let Some(verified) = verify_gossip_release(&message.payload) {
                return Some((verified, subscription));
            }
        }
    });
    run_gossip_update_driver(
        releases,
        submit,
        self_published,
        move |payload| {
            let agent = Arc::clone(&agent);
            async move {
                agent
                    .publish(RELEASE_TOPIC, payload)
                    .await
                    .map_err(|error| error.to_string())
            }
        },
        shutdown,
    )
    .await;
}

fn verify_gossip_release(payload: &[u8]) -> Option<VerifiedRelease> {
    let (json, signature) = decode_signed_manifest(payload).ok()?;
    let manifest: ReleaseManifest = serde_json::from_slice(json).ok()?;
    if !is_newer(&manifest.version, x0x::VERSION) {
        return None;
    }
    if let Err(error) = verify_manifest_signature(json, signature) {
        tracing::warn!(%error, "Release manifest signature verification failed");
        return None;
    }
    if let Err(error) = x0x::upgrade::monitor::validate_manifest_timestamp(&manifest) {
        tracing::warn!(%error, "Rejecting stale gossip manifest");
        return None;
    }
    Some(VerifiedRelease {
        manifest,
        manifest_json: json.to_vec(),
        signature: signature.to_vec(),
        gossip_payload: payload.to_vec(),
    })
}

/// Production loop after the real signature verifier. Tests replace only
/// release input and network publication, leaving dedup and submission intact.
async fn run_gossip_update_driver<S, Publish, PublishFuture>(
    releases: S,
    submit: BackgroundSubmit,
    self_published: Arc<Mutex<SelfPublishedReleaseManifests>>,
    mut publish: Publish,
    mut shutdown: watch::Receiver<bool>,
) where
    S: Stream<Item = VerifiedRelease>,
    Publish: FnMut(Vec<u8>) -> PublishFuture,
    PublishFuture: Future<Output = Result<(), String>>,
{
    futures::pin_mut!(releases);
    let mut rebroadcasted = HashMap::new();
    loop {
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return;
        }
        let verified = tokio::select! {
            release = releases.next() => match release { Some(release) => release, None => return },
            _ = shutdown.changed() => return,
        };
        let decision = {
            let mut published = self_published.lock().await;
            decide_release_manifest_rebroadcast(
                &verified.manifest.version,
                x0x::VERSION,
                release_manifest_payload_digest(&verified.gossip_payload),
                &mut rebroadcasted,
                &mut published,
                Instant::now(),
            )
        };
        if decision == ReleaseRebroadcastDecision::SkipNotNewer {
            continue;
        }
        if decision == ReleaseRebroadcastDecision::Rebroadcast {
            self_published
                .lock()
                .await
                .record_payload(&verified.gossip_payload, Instant::now());
            // Keep publication bounded; no detached task accumulates while the
            // owner waits for rollout or another process's canonical lock.
            tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(10), publish(verified.gossip_payload.clone())) => {
                    if !matches!(result, Ok(Ok(()))) { tracing::debug!("Release rebroadcast did not complete"); }
                }
                _ = shutdown.changed() => return,
            }
        }
        if let Err(error) = submit.submit(verified) {
            tracing::warn!(%error, "Gossip release was not queued");
        }
    }
}

pub(in crate::server) async fn run_fallback_github_poll(
    agent: Arc<Agent>,
    config: DaemonUpdateConfig,
    submit: BackgroundSubmit,
    self_published: Arc<Mutex<SelfPublishedReleaseManifests>>,
    shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(config.fallback_check_interval_minutes.saturating_mul(60));
    if interval.is_zero() {
        return;
    }
    if tokio::time::Instant::now().checked_add(interval).is_none() {
        tracing::warn!("Fallback check interval exceeds the monotonic timer range");
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // startup already owns the immediate check
    let ticks = futures::stream::unfold(ticker, |mut ticker| async move {
        ticker.tick().await;
        Some(((), ticker))
    });
    run_fallback_update_driver(
        ticks,
        move || {
            let config = config.clone();
            async move {
                let monitor = UpgradeMonitor::new(&config.repo, "x0xd", x0x::VERSION)
                    .map_err(x0x::upgrade::UpgradeError::Other)?
                    .with_include_prereleases(config.include_prereleases);
                monitor.check_for_updates().await
            }
        },
        submit,
        self_published,
        move |payload| {
            let agent = Arc::clone(&agent);
            async move {
                agent
                    .publish(RELEASE_TOPIC, payload)
                    .await
                    .map_err(|error| error.to_string())
            }
        },
        shutdown,
    )
    .await;
}

/// Production ticker/check loop. Tests supply inert ticks and already-verified
/// monitor results, not a replacement scheduling implementation.
async fn run_fallback_update_driver<S, Check, CheckFuture, Publish, PublishFuture>(
    ticks: S,
    mut check: Check,
    submit: BackgroundSubmit,
    self_published: Arc<Mutex<SelfPublishedReleaseManifests>>,
    mut publish: Publish,
    mut shutdown: watch::Receiver<bool>,
) where
    S: Stream<Item = ()>,
    Check: FnMut() -> CheckFuture,
    CheckFuture: Future<Output = Result<Option<VerifiedRelease>, x0x::upgrade::UpgradeError>>,
    Publish: FnMut(Vec<u8>) -> PublishFuture,
    PublishFuture: Future<Output = Result<(), String>>,
{
    futures::pin_mut!(ticks);
    loop {
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return;
        }
        tokio::select! {
            tick = ticks.next() => if tick.is_none() { return; },
            _ = shutdown.changed() => return,
        }
        let checked = tokio::select! {
            result = check() => result,
            _ = shutdown.changed() => return,
        };
        let verified = match checked {
            Ok(Some(verified)) => verified,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%error, "Fallback GitHub check failed");
                continue;
            }
        };
        if submit.in_retry_backoff(&verified) {
            if let Err(error) = submit.submit(verified) {
                tracing::warn!(%error, "Fallback release backoff could not be observed");
            }
            continue;
        }
        self_published
            .lock()
            .await
            .record_payload(&verified.gossip_payload, Instant::now());
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(10), publish(verified.gossip_payload.clone())) => {
                if !matches!(result, Ok(Ok(()))) { tracing::debug!("Fallback release broadcast did not complete"); }
            }
            _ = shutdown.changed() => return,
        }
        if let Err(error) = submit.submit(verified) {
            tracing::warn!(%error, "Fallback release was not queued");
        }
    }
}

/// Update SKILL.md if the manifest has a different hash.
async fn update_skill_if_changed(manifest: &ReleaseManifest, data_dir: &std::path::Path) {
    update_skill_while_running(
        manifest,
        data_dir,
        None,
        #[cfg(unix)]
        None,
    )
    .await;
}

async fn update_skill_while_running(
    manifest: &ReleaseManifest,
    data_dir: &std::path::Path,
    mut shutdown: Option<watch::Receiver<bool>>,
    #[cfg(unix)] upgrader: Option<&crate::upgrade::apply::AutoApplyUpgrader>,
) {
    let writer_shutdown = shutdown.clone();
    let update = update_skill_inner(
        manifest,
        data_dir,
        writer_shutdown,
        None,
        #[cfg(unix)]
        upgrader,
    );
    match shutdown.as_mut() {
        Some(shutdown) => {
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                return;
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => {}
                _ = update => {}
            }
        }
        None => update.await,
    }
}

#[cfg(test)]
mod skill_download_seam {
    use std::{cell::RefCell, future::Future, pin::Pin};
    type Download = Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
    thread_local! {
        static DOWNLOAD: RefCell<Option<Download>> = const { RefCell::new(None) };
    }
    pub(super) struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            DOWNLOAD.with(|download| download.borrow_mut().take());
        }
    }
    pub(super) fn install(future: impl Future<Output = Vec<u8>> + Send + 'static) -> Guard {
        DOWNLOAD.with(|download| *download.borrow_mut() = Some(Box::pin(future)));
        Guard
    }
    pub(super) fn take() -> Option<Download> {
        DOWNLOAD.with(|download| download.borrow_mut().take())
    }
}

async fn download_skill(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    #[cfg(test)]
    if let Some(download) = skill_download_seam::take() {
        return Ok(download.await);
    }
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
}

#[cfg(test)]
mod skill_install_seam {
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{Arc, LazyLock, Mutex},
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum Event {
        Entered,
        BeforeWrite,
        Exited,
    }

    type Observer = Arc<dyn Fn(Event) + Send + Sync>;
    static OBSERVERS: LazyLock<Mutex<HashMap<PathBuf, Observer>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    pub(super) struct Guard(PathBuf);

    impl Drop for Guard {
        fn drop(&mut self) {
            OBSERVERS.lock().unwrap().remove(&self.0);
        }
    }

    pub(super) fn install(path: PathBuf, observer: Observer) -> Guard {
        assert!(OBSERVERS
            .lock()
            .unwrap()
            .insert(path.clone(), observer)
            .is_none());
        Guard(path)
    }

    pub(super) struct Active(Option<Observer>);

    impl Active {
        pub(super) fn before_write(&self) {
            if let Some(observer) = &self.0 {
                observer(Event::BeforeWrite);
            }
        }
    }

    pub(super) fn entered(path: &Path) -> Active {
        let observer = OBSERVERS.lock().unwrap().get(path).cloned();
        if let Some(observer) = &observer {
            observer(Event::Entered);
        }
        Active(observer)
    }

    impl Drop for Active {
        fn drop(&mut self) {
            if let Some(observer) = &self.0 {
                observer(Event::Exited);
            }
        }
    }
}

async fn update_skill_inner(
    manifest: &ReleaseManifest,
    data_dir: &std::path::Path,
    shutdown: Option<watch::Receiver<bool>>,
    permit: Option<ReleasePermit>,
    #[cfg(unix)] upgrader: Option<&crate::upgrade::apply::AutoApplyUpgrader>,
) {
    if permit
        .as_ref()
        .is_some_and(|permit| permit.check().is_err())
    {
        return;
    }
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

    let downloaded = if let Some(permit) = &permit {
        tokio::select! {
            result = download_skill(&manifest.skill_url) => result,
            _ = permit.cancelled() => return,
        }
    } else {
        download_skill(&manifest.skill_url).await
    };
    match downloaded {
        Ok(new_contents) => {
            let new_hash: [u8; 32] = Sha256::digest(&new_contents).into();
            if new_hash != manifest.skill_sha256 {
                tracing::warn!("SKILL.md hash mismatch after download");
                return;
            }
            // Resolve the independent executable observation after the await.
            // The earlier Due decision cannot authorize this later write.
            #[cfg(unix)]
            let staged_guide = match upgrader {
                // The release owner drains this actual readback even when
                // superseded; do not select cancellation around this await.
                Some(upgrader) => match upgrader.guide_staging().await {
                    Ok(staging) => staging,
                    Err(error) => {
                        tracing::warn!(%error, "Guide staging identity changed");
                        return;
                    }
                },
                None => None,
            };
            #[cfg(unix)]
            let data_dir = if let Some((_, gate, _)) = &staged_guide {
                match data_dir.canonicalize() {
                    Ok(root) if root == gate.request.data_root => gate.request.data_root.as_path(),
                    _ => {
                        tracing::warn!("Guide staging data root changed");
                        return;
                    }
                }
            } else {
                data_dir
            };
            let skill_path = data_dir.join("SKILL.md");
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
            let install = x0x::upgrade::apply::run_owned_blocking_with_permit(
                permit.as_ref(),
                move |caller_alive| {
                    #[cfg(test)]
                    let observation = skill_install_seam::entered(&skill_path);
                    if !caller_alive.load(Ordering::Acquire)
                        || shutdown
                            .as_ref()
                            .is_some_and(|rx| *rx.borrow() || rx.has_changed().is_err())
                    {
                        return Err(x0x::upgrade::UpgradeError::Other(
                            "guide update cancelled before install lock".into(),
                        ));
                    }
                    #[cfg(unix)]
                    let _install_lock = staged_guide
                        .as_ref()
                        .map(|(install, _, _)| crate::upgrade::acquire_host_upgrade_lock(install))
                        .transpose()?;
                    // Watch value custody orders a shutdown signal against
                    // this short atomic install. A cancelled queued worker
                    // cannot begin it after its observer has gone away.
                    let shutdown_value = shutdown.as_ref().map(watch::Receiver::borrow);
                    if !caller_alive.load(Ordering::Acquire)
                        || shutdown_value.as_ref().is_some_and(|value| **value)
                        || shutdown
                            .as_ref()
                            .is_some_and(|rx| rx.has_changed().is_err())
                    {
                        return Err(x0x::upgrade::UpgradeError::Other(
                            "guide update cancelled before install".into(),
                        ));
                    }
                    #[cfg(unix)]
                    if let Some((install, gate, identity)) = &staged_guide {
                        let clock = gate.clock().map_err(|error| {
                            x0x::upgrade::UpgradeError::Other(error.to_string())
                        })?;
                        if let crate::upgrade::staging::Decision::Waiting(wait) =
                            gate.observe_locked_at(install, &clock, identity)?
                        {
                            return Err(x0x::upgrade::UpgradeError::Other(format!(
                                "guide staging is not due; remaining {} seconds",
                                wait.as_secs()
                            )));
                        }
                    }
                    if !caller_alive.load(Ordering::Acquire) {
                        return Err(x0x::upgrade::UpgradeError::Other(
                            "guide update cancelled after staging check".into(),
                        ));
                    }
                    #[cfg(test)]
                    observation.before_write();
                    let result = std::fs::write(&tmp_path, &new_contents)
                        .and_then(|()| std::fs::rename(&tmp_path, &skill_path));
                    if result.is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                    result.map_err(|error| x0x::upgrade::UpgradeError::Other(error.to_string()))
                },
            );
            match install.await {
                Ok(()) => tracing::info!("SKILL.md updated successfully"),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to install SKILL.md");
                }
            }
        }
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
/// `applied: false` with `reason: "no upgrade available"`. When a newer
/// manifest is available, this handler serializes the destructive apply with
/// the background update workers, performs the verified binary swap, returns a
/// JSON result, then schedules restart/exec after the response has a chance to
/// flush.
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

    let stop_on_upgrade = state.update_config.stop_on_upgrade;
    let restart_context = RestartContext {
        data_dir: Some(state.data_dir.clone()),
        api_addr: Some(state.api_address),
        shutdown: Some(daemon_shutdown_hook(
            &state.shutdown_notify,
            &state.shutdown_tx,
        )),
    };
    // RC4: HTTP-only crate-internal deferred-restart opt-in. apply.rs owns the
    // ~750 ms deferred restart at admission; do not schedule a second owner here.
    let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(stop_on_upgrade)
        .with_restart_on_success(false)
        .with_http_deferred_restart(true)
        .with_restart_context(restart_context);

    match upgrader
        .apply_upgrade_from_manifest(&release.manifest)
        .await
    {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "applied": true,
                "version": version,
                "previous_version": env!("CARGO_PKG_VERSION"),
                "restart_scheduled": true
            })),
        ),
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
            schedule_probe_retry(
                &upgrader,
                &release.manifest,
                Arc::clone(&state.upgrade_apply_lock),
                state.shutdown_notify.subscribe(),
            );
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

/// Legacy helper retained for planner-parity unit tests. Production HTTP apply
/// no longer calls this: `AutoApplyUpgrader::with_http_deferred_restart(true)`
/// owns the deferred restart inside `src/upgrade/apply.rs` (#1447 RC4).
#[allow(dead_code)]
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
    #[cfg(unix)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_staging.rs"
    ));
    #[cfg(unix)]
    staging_regression_tests!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_staging_guide.rs"
    ));
    staging_guide_regression_tests!();
    #[cfg(unix)]
    staging_runtime_regression_tests!();
    #[cfg(unix)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_staging_canonical.rs"
    ));
    #[cfg(unix)]
    staging_canonical_regression_tests!();
    #[cfg(unix)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_fleet.rs"
    ));
    #[cfg(unix)]
    fleet_startup_regression_tests!();
    #[cfg(unix)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_staging_supersession.rs"
    ));
    #[cfg(unix)]
    staging_supersession_regression_tests!();
    #[cfg(unix)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_background_staging.rs"
    ));
    #[cfg(unix)]
    background_staging_regression_tests!();
    #[cfg(unix)]
    background_driver_regression_tests!();

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

    #[allow(unused_mut)]
    fn staging_readback(
        mut scenario: restart::systemd_readback_seam::Scenario,
        runtime: &StartupUpdateCheckRuntime,
    ) -> restart::systemd_readback_seam::Scenario {
        // These fixtures isolate start-rate behavior on an untracked unit.
        // Fleet controls explicitly replace this cgroup after this helper.
        scenario.cgroup = "0::/system.slice/x0x-staging-test.service".to_string();
        #[cfg(unix)]
        {
            let current = crate::upgrade::apply::current_binary_path().unwrap();
            for call in &mut scenario.calls {
                call.show_output = call
                    .show_output
                    .replace(
                        current.to_str().unwrap(),
                        runtime.staging.install.to_str().unwrap(),
                    )
                    .replace(
                        &restart::current_argv()[0],
                        runtime.staging.install.to_str().unwrap(),
                    );
            }
        }
        #[cfg(not(unix))]
        let _ = runtime;
        scenario
    }

    /// The daemon-side runtime the end-to-end tests need: a restart
    /// context over the given data dir, a fresh apply lock and a live
    /// (never-signalled) shutdown watch. The returned sender keeps the
    /// watch's sender alive — a dropped sender would read as shutdown.
    fn e2e_startup_runtime(
        data_dir: &std::path::Path,
    ) -> (StartupUpdateCheckRuntime, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_watch) = watch::channel(false);
        #[cfg(unix)]
        let staging = {
            let root = data_dir.canonicalize().unwrap();
            let install = root.join("x0xd");
            std::fs::write(&install, b"owned startup staging executable fixture").unwrap();
            let started = tokio::time::Instant::now();
            StartupStagingContext {
                install,
                identity_root: root,
                machine_id: [42; 32],
                observed: None,
                clock: Some(Arc::new(move || {
                    Ok(crate::upgrade::probe::ProbeClock {
                        boot_id: "startup-fixture".into(),
                        monotonic_ms: 1000
                            + u64::try_from(started.elapsed().as_millis())
                                .map_err(std::io::Error::other)?,
                    })
                })),
            }
        };
        (
            StartupUpdateCheckRuntime {
                restart_context: listener_restart_context(
                    data_dir,
                    SocketAddr::from(([127, 0, 0, 1], 12700)),
                    Arc::new(|| {}),
                ),
                upgrade_apply_lock: Arc::new(Mutex::new(())),
                shutdown_watch,
                #[cfg(unix)]
                staging,
            },
            shutdown_tx,
        )
    }

    /// The #1196 fleet scenario, end to end: a default unit
    /// (StartLimitIntervalUSec=10 s, StartLimitBurst=5) whose activation
    /// is 2 s old when the daemon's startup update check first applies —
    /// and whose start-rate window has aged out by the time the check
    /// retries. The check must end with the apply ATTEMPTED, not refused
    /// and skipped until the next fallback poll.
    #[tokio::test(start_paused = true)]
    async fn startup_check_applies_after_start_rate_window_ages_out() {
        let data_dir = tempfile::TempDir::new().unwrap();
        let mut config = DaemonConfig {
            data_dir: data_dir.path().to_path_buf(),
            ..Default::default()
        };
        config.update.rollout_window_minutes = 0;
        let (runtime, _shutdown_tx) = e2e_startup_runtime(data_dir.path());
        #[cfg(unix)]
        let _observed_executable = crate::upgrade::apply::current_binary_path_seam::install(
            data_dir.path().canonicalize().unwrap().join("x0xd"),
        );
        // Activation entered at monotonic 1 s. The first readback observes
        // monotonic 3 s (2 s into the 10 s window — fresh activation);
        // the retry's observes monotonic 15 s (14 s in — the window has
        // aged out completely).
        let _readback = restart::systemd_readback_seam::install(staging_readback(
            restart::systemd_readback_seam::Scenario {
                cgroup: "0::/system.slice/x0xd.service".to_string(),
                invocation_id: Some(SEAM_INVOCATION_ID.to_string()),
                calls: vec![
                    // Unix staging identity and the first apply each observe
                    // the pending activation; only the retry ages out. Other
                    // platforms enter the apply path without staging readback.
                    #[cfg(unix)]
                    restart::systemd_readback_seam::ReadbackCall {
                        show_output: show_for_this_process("10s", "5", 1_000_000),
                        monotonic_now_us: 3_000_000,
                    },
                    restart::systemd_readback_seam::ReadbackCall {
                        show_output: show_for_this_process("10s", "5", 1_000_000),
                        monotonic_now_us: 3_000_000,
                    },
                    restart::systemd_readback_seam::ReadbackCall {
                        show_output: show_for_this_process("10s", "5", 1_000_000),
                        monotonic_now_us: 15_000_000,
                    },
                ],
            },
            &runtime,
        ));

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

        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, None, Some(runtime)).await;

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
        let data_dir = tempfile::TempDir::new().unwrap();
        let mut config = DaemonConfig {
            data_dir: data_dir.path().to_path_buf(),
            ..Default::default()
        };
        config.update.rollout_window_minutes = 0;
        let (runtime, _shutdown_tx) = e2e_startup_runtime(data_dir.path());
        #[cfg(unix)]
        let _observed_executable = crate::upgrade::apply::current_binary_path_seam::install(
            data_dir.path().canonicalize().unwrap().join("x0xd"),
        );
        let _readback = restart::systemd_readback_seam::install(staging_readback(
            one_call_scenario("0", "5"),
            &runtime,
        ));
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

        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, None, Some(runtime)).await;
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
        let data_dir = tempfile::TempDir::new().unwrap();
        let mut config = DaemonConfig {
            data_dir: data_dir.path().to_path_buf(),
            ..Default::default()
        };
        config.update.rollout_window_minutes = 0;
        let (runtime, _shutdown_tx) = e2e_startup_runtime(data_dir.path());
        #[cfg(unix)]
        let _observed_executable = crate::upgrade::apply::current_binary_path_seam::install(
            data_dir.path().canonicalize().unwrap().join("x0xd"),
        );
        let _readback = restart::systemd_readback_seam::install(staging_readback(
            one_call_scenario("10s", "0"),
            &runtime,
        ));
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

        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, None, Some(runtime)).await;
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
