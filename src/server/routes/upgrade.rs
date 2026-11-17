//! Route handlers (`category: "upgrade"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::api_error;
use super::super::state::{AppState, CachedUpgradeCheck, DaemonConfig, DaemonUpdateConfig};
use crate as x0x;
use anyhow::Result;
use axum::extract::{Query, State};
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
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Mutex};
use x0x::upgrade::apply::{AutoApplyUpgrader, ReleasePermit, RestartContext};
use x0x::upgrade::manifest::{decode_signed_manifest, is_newer, ReleaseManifest, RELEASE_TOPIC};
use x0x::upgrade::monitor::UpgradeMonitor;
use x0x::upgrade::monitor::VerifiedRelease;
use x0x::upgrade::restart::RestartOwnershipError;
use x0x::upgrade::signature::{verify_bytes_signature_with_key, RELEASE_SIGNING_KEY};
use x0x::Agent;

const UPGRADE_CHECK_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

const UPGRADE_CHECK_ERROR_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

const RELEASE_REBROADCAST_INTERVAL: Duration = Duration::from_secs(300);

const SELF_PUBLISHED_RELEASE_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Default)]
pub(in crate::server) struct SelfPublishedReleaseManifests {
    published_at: HashMap<[u8; 32], SelfPublished>,
}

/// One self-published payload: when it was first recorded, and whether
/// `/upgrade/apply` recorded it (#1169). Only a route-recorded payload is
/// owned by an apply: while the route's apply runs, after it succeeds,
/// while a probe retry — scheduled by this route or an earlier failed
/// one — still owns its install, and after the apply's worker was
/// admitted. Before admission every other handler exit — a failed apply
/// with no retry to resume, a no-op apply, a cancelled request, a panic —
/// releases the claim through [`ApplyRouteClaim`], so gossip copies still
/// reach the background owner; after admission the claim outlives the
/// handler (the blocking worker owns the replacement and restart) and
/// ages out with the tracker TTL. Driver rebroadcasts, fallback publishes
/// and the start-up broadcast record without the claim; the owner's
/// version dedup absorbs their repeats.
#[derive(Debug, Clone, Copy)]
struct SelfPublished {
    first_seen: Instant,
    apply_route: bool,
}

impl SelfPublishedReleaseManifests {
    fn record_payload(&mut self, payload: &[u8], now: Instant) {
        self.record(payload, now, false);
    }

    /// Record a payload that `/upgrade/apply` announces for the release it
    /// is applying itself.
    fn record_apply_route_payload(&mut self, payload: &[u8], now: Instant) {
        self.record(payload, now, true);
    }

    /// Release the apply-route claim on an already-digested payload. The
    /// digest stays recorded, so the node still does not rebroadcast
    /// bytes it already published; only the claim that suppresses owner
    /// submission is dropped.
    fn clear_apply_route_digest(&mut self, digest: &[u8; 32], now: Instant) {
        self.prune(now);
        if let Some(entry) = self.published_at.get_mut(digest) {
            entry.apply_route = false;
        }
    }

    fn record(&mut self, payload: &[u8], now: Instant, apply_route: bool) {
        self.prune(now);
        let entry = self
            .published_at
            .entry(release_manifest_payload_digest(payload))
            .or_insert(SelfPublished {
                first_seen: now,
                apply_route,
            });
        entry.first_seen = now;
        entry.apply_route |= apply_route;
    }

    fn contains_recent_digest(&mut self, digest: &[u8; 32], now: Instant) -> bool {
        self.prune(now);
        self.published_at.contains_key(digest)
    }

    /// Whether `/upgrade/apply` recorded this payload within the TTL and an
    /// apply-route owner still holds it: the apply is in progress, admitted,
    /// or succeeded, or a scheduled probe retry owns its install.
    fn recorded_by_apply_route(&mut self, digest: &[u8; 32], now: Instant) -> bool {
        self.prune(now);
        self.published_at
            .get(digest)
            .is_some_and(|entry| entry.apply_route)
    }

    fn prune(&mut self, now: Instant) {
        self.published_at.retain(|_, entry| {
            now.saturating_duration_since(entry.first_seen) < SELF_PUBLISHED_RELEASE_TTL
        });
    }
}

/// The `/upgrade/apply` claim on its announced payload: [`SelfPublishedReleaseManifests::record_apply_route_payload`]
/// records the digest, and dropping this guard without [`ApplyRouteClaim::keep`]
/// releases it again — but only while the apply was never admitted. Before
/// admission every handler exit other than a successful apply or a live
/// probe-retry hand-off releases the claim: a failed apply with no
/// interrupted probe to resume, a no-op apply, a client disconnect that
/// drops the handler future mid-wait, or a panic, so gossip copies of the
/// payload reach the background owner again instead of being dropped for
/// the tracker's TTL. A failed apply that leaves a live probe retry
/// owning its install — one it scheduled, or one an earlier failed apply
/// in this process already left in place — keeps the claim: the retry
/// re-applies this same version when its durable wait elapses, and an
/// echo must not queue a second apply beside it.
/// Once the apply's blocking worker is admitted (host locks held;
/// replacement and restart owned by the worker), a dropped handler no
/// longer releases the claim: the install still runs, and a gossip copy
/// arriving in the seconds before restart must not queue a second apply
/// of it — a real rolled-back apply is always on this side of the
/// boundary, because the rollback runs after admission. On success the
/// claim is kept; on every other post-admission exit it simply ages out
/// with the tracker entry, whose TTL runs from the latest record of any
/// kind — `record_payload` refreshes the entry's clock too, so only a
/// fresh record extends it.
pub(in crate::server) struct ApplyRouteClaim {
    tracker: Arc<StdMutex<SelfPublishedReleaseManifests>>,
    digest: [u8; 32],
    permit: ReleasePermit,
    kept: bool,
}

impl ApplyRouteClaim {
    /// Record the announced payload as apply-route-owned and hold the
    /// claim for the guard's lifetime. `permit` is the apply's admission
    /// owner: its `admitted` flag decides whether a drop still releases.
    fn record(
        tracker: Arc<StdMutex<SelfPublishedReleaseManifests>>,
        payload: &[u8],
        permit: ReleasePermit,
    ) -> Self {
        let digest = release_manifest_payload_digest(payload);
        tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_apply_route_payload(payload, Instant::now());
        Self {
            tracker,
            digest,
            permit,
            kept: false,
        }
    }

    /// The outcomes that keep the claim unconditionally: this route
    /// installed the release, or its failed apply left a live probe
    /// retry owning the install — one it scheduled or an earlier
    /// failure's — in both cases an apply path still owns the release,
    /// and its own echo must not start a second apply of it.
    fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for ApplyRouteClaim {
    fn drop(&mut self) {
        // Post-admission the blocking worker owns the replacement and the
        // restart; the claim outlives this handler and expires with the
        // tracker TTL instead.
        if !self.kept && !self.permit.admitted() {
            self.tracker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear_apply_route_digest(&self.digest, Instant::now());
        }
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
// Upgrade observations (#1381): what `GET /diagnostics/upgrade` reports
// ---------------------------------------------------------------------------

/// Where a release check ran (#1381).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum ReleaseCheckSource {
    /// The check that runs once after the API listener binds.
    Startup,
    /// The periodic GitHub fallback poll.
    FallbackPoll,
    /// A `GET /upgrade` request that was not answered from the cache.
    Api,
}

impl ReleaseCheckSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::FallbackPoll => "fallback_poll",
            Self::Api => "api",
        }
    }
}

/// What a release check found (#1381).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) enum ReleaseCheckOutcome {
    /// A verified release newer than this binary.
    UpdateAvailable(String),
    /// No newer release.
    UpToDate,
    /// The check did not complete.
    Failed,
}

#[derive(Debug, Clone)]
struct ReleaseSighting {
    version: String,
    seen_at_unix: u64,
}

#[derive(Debug, Clone)]
struct ReleaseCheckRecord {
    source: ReleaseCheckSource,
    at_unix: u64,
    outcome: ReleaseCheckOutcome,
}

/// What this daemon has learned about releases since it started (#1381).
/// Memory only: a restart starts empty. `GET /diagnostics/upgrade` reports
/// it; nothing here is sent on the wire.
#[derive(Debug, Default)]
pub(in crate::server) struct UpgradeObservations {
    latest_on_topic: Option<ReleaseSighting>,
    last_check: Option<ReleaseCheckRecord>,
}

impl UpgradeObservations {
    /// Record a verified release received on `x0x/release`. Only the
    /// highest version is kept; a repeat of it refreshes the time.
    pub(in crate::server) fn record_topic_release(&mut self, version: &str, now_unix: u64) {
        let Ok(seen) = semver::Version::parse(version) else {
            return;
        };
        let keep = match &self.latest_on_topic {
            Some(prior) => semver::Version::parse(&prior.version)
                .map(|prior| seen.cmp_precedence(&prior) != std::cmp::Ordering::Less)
                .unwrap_or(true),
            None => true,
        };
        if keep {
            self.latest_on_topic = Some(ReleaseSighting {
                version: version.to_string(),
                seen_at_unix: now_unix,
            });
        }
    }

    /// Record the result of a release check.
    pub(in crate::server) fn record_check(
        &mut self,
        source: ReleaseCheckSource,
        outcome: ReleaseCheckOutcome,
        now_unix: u64,
    ) {
        self.last_check = Some(ReleaseCheckRecord {
            source,
            at_unix: now_unix,
            outcome,
        });
    }

    /// The newest observed version that is newer than `current`.
    fn newest_observed(&self, current: &str) -> Option<(String, &'static str)> {
        let topic = self
            .latest_on_topic
            .as_ref()
            .map(|seen| (seen.version.clone(), "release_topic"));
        let check = self
            .last_check
            .as_ref()
            .and_then(|check| match &check.outcome {
                ReleaseCheckOutcome::UpdateAvailable(version) => {
                    Some((version.clone(), check.source.as_str()))
                }
                _ => None,
            });
        [topic, check]
            .into_iter()
            .flatten()
            .filter(|(version, _)| is_newer(version, current))
            .max_by(
                |(a, _), (b, _)| match (semver::Version::parse(a), semver::Version::parse(b)) {
                    (Ok(a), Ok(b)) => a.cmp_precedence(&b),
                    _ => std::cmp::Ordering::Equal,
                },
            )
    }

    /// The `/diagnostics/upgrade` fields this record owns.
    pub(in crate::server) fn diagnostics_json(
        &self,
        current: &str,
        background: Option<BackgroundStatus>,
    ) -> serde_json::Value {
        let latest_on_topic = self.latest_on_topic.as_ref().map(|seen| {
            serde_json::json!({ "version": seen.version, "seen_at_unix": seen.seen_at_unix })
        });
        let last_check = self.last_check.as_ref().map(|check| {
            let (outcome, version) = match &check.outcome {
                ReleaseCheckOutcome::UpdateAvailable(version) => {
                    ("update_available", Some(version.clone()))
                }
                ReleaseCheckOutcome::UpToDate => ("up_to_date", None),
                ReleaseCheckOutcome::Failed => ("failed", None),
            };
            serde_json::json!({
                "source": check.source.as_str(),
                "at_unix": check.at_unix,
                "outcome": outcome,
                "version": version,
            })
        });
        let pending_update = match background {
            Some(status) => Some(serde_json::json!({
                "version": status.version,
                "state": status.state,
                "source": "background_owner",
            })),
            None => self.newest_observed(current).map(|(version, source)| {
                serde_json::json!({ "version": version, "state": "observed", "source": source })
            }),
        };
        serde_json::json!({
            "latest_release_topic_version": latest_on_topic,
            "last_check": last_check,
            "pending_update": pending_update,
        })
    }
}

/// Seconds since the Unix epoch; 0 if the clock is before it.
pub(in crate::server) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Apply `update` to the shared observations. A poisoned lock still records:
/// the data is diagnostic only.
pub(in crate::server) fn observe_upgrade(
    observations: &std::sync::Mutex<UpgradeObservations>,
    update: impl FnOnce(&mut UpgradeObservations),
) {
    let mut guard = observations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    update(&mut guard);
}

/// The [`ReleaseCheckOutcome`] of a monitor answer.
fn check_outcome<E>(checked: &Result<Option<VerifiedRelease>, E>) -> ReleaseCheckOutcome {
    match checked {
        Ok(Some(release)) => ReleaseCheckOutcome::UpdateAvailable(release.manifest.version.clone()),
        Ok(None) => ReleaseCheckOutcome::UpToDate,
        Err(_) => ReleaseCheckOutcome::Failed,
    }
}

/// The release the background apply owner holds, if it still has work or a
/// recent failure for it (#1381).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct BackgroundStatus {
    version: String,
    state: &'static str,
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
    /// Where the check records its result for `GET /diagnostics/upgrade`
    /// (#1381); `None` records nothing.
    pub observations: Option<Arc<std::sync::Mutex<UpgradeObservations>>>,
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
///
/// Returns whether a live retry timer owns this install and
/// `manifest.version` — one this call spawned, or one an earlier failed
/// apply in this process already left owning it. The durable record is
/// read once up front — the record only, never the staging identity
/// readback, so an HTTP error response never waits on readback
/// subprocesses — and a failure with no interrupted probe to resume
/// spawns nothing and answers `false`: the HTTP route keeps its
/// apply-route claim for exactly the hand-off that answers `true` — the
/// retry re-applies this same version when its durable wait elapses,
/// whichever request left it in place — and releases it otherwise
/// (#1169). The spawned loop rereads the full gated state before every
/// attempt, so a record that changes between the two reads is still
/// caught by the loop's own checks.
async fn schedule_probe_retry(
    upgrader: &AutoApplyUpgrader,
    manifest: &ReleaseManifest,
    apply_lock: Arc<Mutex<()>>,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    if *shutdown.borrow() || shutdown.has_changed().is_err() {
        return false;
    }
    let install = match x0x::upgrade::apply::current_binary_path().and_then(|path| {
        std::fs::canonicalize(path)
            .map_err(|error| x0x::upgrade::UpgradeError::Other(error.to_string()))
    }) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(%error, "Cannot identify install for probe retry");
            return false;
        }
    };
    let Some(owner) =
        x0x::upgrade::probe_retry::claim_retry(install.clone(), manifest.version.clone())
    else {
        // An earlier failed apply in this process already left a retry
        // owning this install and version (or the ownership map is
        // poisoned, which likewise refuses a duplicate waiter): a live
        // retry path still owns the release, so this failure is the same
        // hand-off — the caller keeps the claim instead of releasing a
        // suppression that retry still needs (#1169 round 5).
        return true;
    };
    // The claim follows the retry, not the spawn: a timer without a durable
    // interrupted probe never applies anything, so read the record once here
    // — read-only; the response path acknowledges no probe-clock progress —
    // rather than hand a live-looking suppression to a no-op waiter.
    let resuming = {
        #[cfg(unix)]
        {
            x0x::upgrade::apply::has_durable_probe_wait(install.clone(), manifest.version.clone())
                .await
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    if !resuming {
        tracing::debug!(
            version = %manifest.version,
            "No durable interrupted probe to resume; no retry scheduled"
        );
        return false;
    }
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
    true
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
///
/// This check announces nothing on `RELEASE_TOPIC` (#1169): a boot-time
/// discovery is already announced by `broadcast_current_manifest`, which
/// every launch runs under the same gates and publishes through the same
/// monitor funnel — byte-identically for the same release. It therefore
/// takes no gossip agent; an earlier revision's publish site here never
/// fired in the daemon and is deliberately gone rather than dormant.
pub(in crate::server) async fn run_startup_update_check(
    config: &DaemonConfig,
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
                Some(injected) => Ok(Some(injected)),
                None => monitor.check_for_updates().await,
            }
        }
        #[cfg(not(test))]
        {
            monitor.check_for_updates().await
        }
    };
    if let Some(observations) = runtime
        .as_ref()
        .and_then(|runtime| runtime.observations.as_ref())
    {
        observe_upgrade(observations, |record| {
            record.record_check(
                ReleaseCheckSource::Startup,
                check_outcome(&checked),
                unix_now(),
            )
        });
    }
    let checked = checked.map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(verified) = checked else {
        return Ok(None);
    };
    x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest)?;

    tracing::info!(
        new_version = %verified.manifest.version,
        "Startup check: new version available"
    );

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
                )
                .await;
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
    self_published_release_manifests: Arc<StdMutex<SelfPublishedReleaseManifests>>,
) {
    let monitor = match UpgradeMonitor::new(repo, "x0xd", x0x::VERSION) {
        Ok(m) => m.with_include_prereleases(include_prereleases),
        Err(e) => {
            tracing::debug!(error = %e, "Failed to create monitor for startup broadcast");
            return;
        }
    };

    match broadcast_fetch_current_manifest(&monitor).await {
        Ok(Some(verified)) => {
            if x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest).is_err() {
                return;
            }
            // Sync SKILL.md with current manifest
            update_skill_if_changed(&verified.manifest, data_dir).await;

            tracing::info!(
                version = %verified.manifest.version,
                "Broadcasting current release manifest v{} to gossip",
                verified.manifest.version
            );
            if x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest).is_err() {
                return;
            }
            let gossip_payload = verified.gossip_payload;
            {
                let mut self_published = self_published_release_manifests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        source: impl FnOnce(Option<BackgroundSubmit>) -> F,
    ) -> Option<tokio::task::JoinHandle<()>>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if !enabled {
            return None;
        }
        // Missing apply authority must not disable configured release relay.
        Some(tokio::spawn(source(submit)))
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

    /// The selected release while it is queued, applying, or failed
    /// (#1381). `None` once the owner has nothing left for it.
    pub(in crate::server) fn status(&self) -> Option<BackgroundStatus> {
        let slot = self.slot.lock().ok()?;
        let latest = slot.latest.as_ref()?;
        let state = if slot.active.is_some() {
            "applying"
        } else if slot.pending {
            "queued"
        } else if let Some(failed) = slot.failed_at {
            if failed.elapsed() < Duration::from_secs(30 * 60) {
                "backoff"
            } else {
                "failed"
            }
        } else {
            return None;
        };
        Some(BackgroundStatus {
            version: latest.manifest.version.clone(),
            state,
        })
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
    submit: Option<BackgroundSubmit>,
    self_published: Arc<StdMutex<SelfPublishedReleaseManifests>>,
    observations: Arc<std::sync::Mutex<UpgradeObservations>>,
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
    let releases = observe_topic_releases(releases, observations);
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

/// Record each verified release from `x0x/release` for
/// `GET /diagnostics/upgrade` (#1381) before the driver sees it.
fn observe_topic_releases(
    releases: impl Stream<Item = VerifiedRelease>,
    observations: Arc<std::sync::Mutex<UpgradeObservations>>,
) -> impl Stream<Item = VerifiedRelease> {
    releases.inspect(move |release| {
        observe_upgrade(&observations, |record| {
            record.record_topic_release(&release.manifest.version, unix_now())
        });
    })
}

fn verify_gossip_release(payload: &[u8]) -> Option<VerifiedRelease> {
    verify_gossip_release_with_key(payload, RELEASE_SIGNING_KEY)
}

fn verify_gossip_release_with_key(payload: &[u8], trusted_key: &[u8]) -> Option<VerifiedRelease> {
    let (json, signature) = decode_signed_manifest(payload).ok()?;
    let manifest: ReleaseManifest = serde_json::from_slice(json).ok()?;
    if !is_newer(&manifest.version, x0x::VERSION) {
        return None;
    }
    if let Err(error) = verify_bytes_signature_with_key(json, signature, trusted_key) {
        tracing::warn!(%error, "Release manifest signature verification failed");
        return None;
    }
    if let Err(error) = x0x::upgrade::monitor::validate_manifest_timestamp(&manifest) {
        tracing::warn!(%error, "Rejecting ineligible gossip manifest");
        return None;
    }
    Some(VerifiedRelease {
        manifest,
        manifest_json: json.to_vec(),
        signature: signature.to_vec(),
        gossip_payload: payload.to_vec(),
    })
}

/// #1169: a node that first observes a new release must not stay silent
/// until each peer's fallback poll fires. The announcing observation
/// points — the every-launch manifest broadcast, the fallback poll, the
/// gossip relay and a manual `/upgrade/apply` — publish the signed
/// manifest on `RELEASE_TOPIC`. The startup check announces nothing: its
/// discovery is covered by the manifest broadcast (same gates, every
/// launch, byte-identical payload through the monitor funnel). The
/// read-only `/upgrade` check announces nothing either (Engineer ruling
/// 3 Nov 2026 17:40 GMT): gossip self-delivery would feed this node's own
/// apply owner, i.e. a background install triggered by a read. The GitHub
/// poll cadence stays at its documented fallback (A14 / ADR 0045); gossip
/// is the fast path. Best effort and bounded: a stuck mesh must never
/// block the observer, and peer rebroadcast limiting plus the apply
/// owner's dedup handle repeats.
async fn announce_observed_release<Publish, PublishFuture>(
    release: &VerifiedRelease,
    publish: Publish,
) where
    Publish: FnOnce(Vec<u8>) -> PublishFuture,
    PublishFuture: Future<Output = Result<(), String>>,
{
    match tokio::time::timeout(
        Duration::from_secs(10),
        publish(release.gossip_payload.clone()),
    )
    .await
    {
        Ok(Ok(())) => tracing::info!(
            version = %release.manifest.version,
            "Observed release announced on the release topic"
        ),
        Ok(Err(error)) => tracing::debug!(%error, "Observed release announcement failed"),
        Err(_) => tracing::debug!("Observed release announcement timed out"),
    }
}

/// Production loop after the real signature verifier. Tests replace only
/// release input and network publication, leaving dedup and submission intact.
async fn run_gossip_update_driver<S, Publish, PublishFuture>(
    releases: S,
    submit: impl Into<Option<BackgroundSubmit>>,
    self_published: Arc<StdMutex<SelfPublishedReleaseManifests>>,
    mut publish: Publish,
    mut shutdown: watch::Receiver<bool>,
) where
    S: Stream<Item = VerifiedRelease>,
    Publish: FnMut(Vec<u8>) -> PublishFuture,
    PublishFuture: Future<Output = Result<(), String>>,
{
    let submit = submit.into();
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
        if x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest).is_err() {
            continue;
        }
        let (decision, apply_route_echo) = {
            let mut published = self_published
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let digest = release_manifest_payload_digest(&verified.gossip_payload);
            let decision = decide_release_manifest_rebroadcast(
                &verified.manifest.version,
                x0x::VERSION,
                digest,
                &mut rebroadcasted,
                &mut published,
                Instant::now(),
            );
            (
                decision,
                published.recorded_by_apply_route(&digest, Instant::now()),
            )
        };
        if decision == ReleaseRebroadcastDecision::SkipNotNewer {
            continue;
        }
        // #1169: the echo of an `/upgrade/apply` announcement is not
        // submitted. That route applies the release itself; a submit would
        // start a second apply of the operator-requested release. The
        // route releases its claim only before admission and only when
        // nothing resumes the install — after admission, on success, or
        // while a scheduled probe retry owns it, the claim stands until
        // the tracker TTL — so copies that arrive after a released exit
        // are submitted again. Echoes of
        // driver rebroadcasts, fallback publishes and the start-up
        // broadcast still reach the owner, whose version dedup absorbs
        // them.
        if decision == ReleaseRebroadcastDecision::SkipSelfPublished && apply_route_echo {
            continue;
        }
        if decision == ReleaseRebroadcastDecision::Rebroadcast {
            self_published
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        if let Some(Err(error)) = submit.as_ref().map(|submit| submit.submit(verified)) {
            tracing::warn!(%error, "Gossip release was not queued");
        }
    }
}

pub(in crate::server) async fn run_fallback_github_poll(
    agent: Arc<Agent>,
    config: DaemonUpdateConfig,
    submit: Option<BackgroundSubmit>,
    self_published: Arc<StdMutex<SelfPublishedReleaseManifests>>,
    observations: Arc<std::sync::Mutex<UpgradeObservations>>,
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
            let observations = Arc::clone(&observations);
            async move {
                let checked = async {
                    UpgradeMonitor::new(&config.repo, "x0xd", x0x::VERSION)
                        .map_err(x0x::upgrade::UpgradeError::Other)?
                        .with_include_prereleases(config.include_prereleases)
                        .check_for_updates()
                        .await
                }
                .await;
                observe_upgrade(&observations, |record| {
                    record.record_check(
                        ReleaseCheckSource::FallbackPoll,
                        check_outcome(&checked),
                        unix_now(),
                    )
                });
                checked
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
    submit: impl Into<Option<BackgroundSubmit>>,
    self_published: Arc<StdMutex<SelfPublishedReleaseManifests>>,
    mut publish: Publish,
    mut shutdown: watch::Receiver<bool>,
) where
    S: Stream<Item = ()>,
    Check: FnMut() -> CheckFuture,
    CheckFuture: Future<Output = Result<Option<VerifiedRelease>, x0x::upgrade::UpgradeError>>,
    Publish: FnMut(Vec<u8>) -> PublishFuture,
    PublishFuture: Future<Output = Result<(), String>>,
{
    let submit = submit.into();
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
        if x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest).is_err() {
            continue;
        }
        if let Some(submit) = submit
            .as_ref()
            .filter(|submit| submit.in_retry_backoff(&verified))
        {
            if let Err(error) = submit.submit(verified) {
                tracing::warn!(%error, "Fallback release backoff could not be observed");
            }
            continue;
        }
        self_published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_payload(&verified.gossip_payload, Instant::now());
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(10), publish(verified.gossip_payload.clone())) => {
                if !matches!(result, Ok(Ok(()))) { tracing::debug!("Fallback release broadcast did not complete"); }
            }
            _ = shutdown.changed() => return,
        }
        if let Some(Err(error)) = submit.as_ref().map(|submit| submit.submit(verified)) {
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
    if x0x::upgrade::monitor::validate_manifest_timestamp(manifest).is_err() {
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
            if x0x::upgrade::monitor::validate_manifest_timestamp(manifest).is_err() {
                return;
            }
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
            let admitted_manifest = manifest.clone();
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
                    x0x::upgrade::monitor::validate_manifest_timestamp(&admitted_manifest)?;
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

/// #1169 fix-round test seam (cfg(test) only; no env vars, no cargo
/// features): lets an in-process test inject the monitor answer that
/// [`check_upgrade`] and [`apply_upgrade`] would have fetched and
/// signature-verified, so the routes run for real without GitHub (the
/// release private key is deliberately not in the repo, so no test can
/// mint a signature the monitor would accept). Compiled out entirely in
/// non-test builds; an uninstalled injection leaves the production fetch
/// untouched.
#[cfg(test)]
mod upgrade_check_feed_seam {
    use crate::upgrade::monitor::VerifiedRelease;
    use std::cell::RefCell;

    /// The injected monitor answer: `Some(release)` = a newer verified
    /// release was found, `None` = already up to date.
    type Answer = Option<VerifiedRelease>;

    // Thread-local, like `skill_download_seam`: the route tests below call
    // the handlers directly on the test's current-thread runtime, so a
    // process-wide static could let sibling tests on other threads steal
    // the answer and fall through to a real fetch.
    thread_local! {
        static INJECTED: RefCell<Option<Answer>> = const { RefCell::new(None) };
    }

    /// Uninstalls the injection on drop, so a test cannot leak its answer
    /// into sibling tests on the same thread.
    pub(super) struct Guard {
        _private: (),
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            INJECTED.with(|slot| slot.borrow_mut().take());
        }
    }

    /// Inject the monitor's next answer for the guard's lifetime.
    pub(super) fn install(answer: Answer) -> Guard {
        INJECTED.with(|slot| *slot.borrow_mut() = Some(answer));
        Guard { _private: () }
    }

    /// Take the injected answer, or `None` when nothing is installed
    /// (fall through to the real monitor fetch).
    pub(super) fn take() -> Option<Answer> {
        INJECTED.with(|slot| slot.borrow_mut().take())
    }
}

/// The boot broadcast's injected manifest answer (`Some(release)` = a
/// verified current manifest, `None` = fetch found nothing), mirroring
/// [`upgrade_check_feed_seam`] for `fetch_current_manifest`. Thread-local
/// for the same reason; compiled out entirely in non-test builds.
#[cfg(test)]
mod broadcast_feed_seam {
    use crate::upgrade::monitor::VerifiedRelease;
    use std::cell::RefCell;

    type Answer = Result<Option<VerifiedRelease>, crate::upgrade::UpgradeError>;

    thread_local! {
        static INJECTED: RefCell<Option<Answer>> = const { RefCell::new(None) };
    }

    /// Uninstalls the injection on drop, so a test cannot leak its answer
    /// into sibling tests on the same thread.
    pub(super) struct Guard {
        _private: (),
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            INJECTED.with(|slot| slot.borrow_mut().take());
        }
    }

    /// Inject the broadcast's next fetch answer for the guard's lifetime.
    pub(super) fn install(answer: Answer) -> Guard {
        INJECTED.with(|slot| *slot.borrow_mut() = Some(answer));
        Guard { _private: () }
    }

    /// Take the injected answer, or `None` when nothing is installed
    /// (fall through to the real fetch).
    pub(super) fn take() -> Option<Answer> {
        INJECTED.with(|slot| slot.borrow_mut().take())
    }
}

/// The boot broadcast's manifest fetch: the injected test answer when
/// installed, else the verbatim `fetch_current_manifest`.
#[cfg(test)]
async fn broadcast_fetch_current_manifest(
    monitor: &UpgradeMonitor,
) -> Result<Option<crate::upgrade::monitor::VerifiedRelease>, x0x::upgrade::UpgradeError> {
    match broadcast_feed_seam::take() {
        Some(injected) => injected,
        None => monitor.fetch_current_manifest().await,
    }
}

#[cfg(not(test))]
async fn broadcast_fetch_current_manifest(
    monitor: &UpgradeMonitor,
) -> Result<Option<crate::upgrade::monitor::VerifiedRelease>, x0x::upgrade::UpgradeError> {
    monitor.fetch_current_manifest().await
}

/// The update-monitor answer for a route: the injected test answer when
/// installed, else the real fetch. Test builds only see the seam; the
/// production body is the verbatim `check_for_updates` call.
#[cfg(test)]
async fn monitor_check(
    monitor: &UpgradeMonitor,
) -> Result<Option<crate::upgrade::monitor::VerifiedRelease>, x0x::upgrade::UpgradeError> {
    match upgrade_check_feed_seam::take() {
        Some(injected) => Ok(injected),
        None => monitor.check_for_updates().await,
    }
}

#[cfg(not(test))]
async fn monitor_check(
    monitor: &UpgradeMonitor,
) -> Result<Option<crate::upgrade::monitor::VerifiedRelease>, x0x::upgrade::UpgradeError> {
    monitor.check_for_updates().await
}

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

    // Engineer ruling 3 Nov 2026 17:40 GMT: the /upgrade check is
    // read-only and must never publish the release it observes — gossip
    // self-delivery would feed the announcing node's own apply owner, a
    // background install from a read. It answers and caches only; peers
    // learn the release from an applying node, the fallback poll or
    // relay. `monitor_check` carries the cfg(test) feed seam.
    let checked = monitor_check(&monitor).await;
    observe_upgrade(&state.upgrade_observations, |record| {
        record.record_check(ReleaseCheckSource::Api, check_outcome(&checked), unix_now())
    });
    match checked {
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
    Query(query): Query<UpgradeApplyQuery>,
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

    let Ok(http_wait_guard) = Arc::clone(&state.http_upgrade_wait_lock).try_lock_owned() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "applied": false,
                "error": "upgrade already in progress"
            })),
        );
    };
    let Ok(upgrade_guard) = state.upgrade_apply_lock.try_lock() else {
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

    let release = match monitor_check(&monitor).await {
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

    let restart_context = RestartContext {
        data_dir: Some(state.data_dir.clone()),
        api_addr: Some(state.api_address),
        shutdown: Some(daemon_shutdown_hook(
            &state.shutdown_notify,
            &state.shutdown_tx,
        )),
    };
    // Discovery retains the existing conflict behavior. The potentially long
    // receipt/probe wait must release the shared replacement lock.
    drop(upgrade_guard);

    let runtime = HttpUpgradeRuntime {
        config: state.update_config.clone(),
        restart_context,
        apply_lock: Arc::clone(&state.upgrade_apply_lock),
        wait_slot: Arc::new(http_wait_guard),
        shutdown: state.shutdown_notify.subscribe(),
        #[cfg(unix)]
        staging: state.upgrade_staging.clone(),
        #[cfg(test)]
        operation_observer: None,
    };
    // The claim guard holds a clone of this permit and reads `admitted`
    // when the handler leaves. That read's safety is not this declaration
    // order: the awaited apply future below finishes and drops — its
    // custody finalising the attempt — before the claim leaves scope, and
    // on a mid-apply disconnect `admitted` is marked under the permit
    // state's mutex, atomically with the worker's caller-liveness
    // recheck, so no drop order reads a flag the worker has not settled.
    let permit = ReleasePermit::for_http(Arc::clone(&runtime.wait_slot));

    // #1169: announce before the apply work — the receipt, staging and
    // rollout waits below can take minutes, and peers must not wait for
    // their own fallback poll while this node already saw the release.
    // After the lock drop: a bounded-but-slow publish must not hold the
    // shared replacement lock away from background and startup applies.
    // The only announcing route: an explicit owner action on a release
    // this node is already installing. Self-delivery returns the
    // announcement to this node's own gossip listener. The payload is
    // recorded as published by this route first, so the gossip driver skips
    // both the rebroadcast and the submit for that echo: this route already
    // owns the apply. The claim guard outlives this block: it releases the
    // claim unless this route installs the release — or the apply was
    // admitted, in which case the blocking worker owns the install and the
    // claim must survive whatever way the handler leaves: outcome, client
    // disconnect or panic — or the failed apply hands the install to a
    // live probe retry, which then owns it the same way.
    let claim = ApplyRouteClaim::record(
        Arc::clone(&state.self_published_release_manifests),
        &release.gossip_payload,
        permit.clone(),
    );
    {
        let agent = Arc::clone(&state.agent);
        announce_observed_release(&release, move |payload| async move {
            agent
                .publish(RELEASE_TOPIC, payload)
                .await
                .map_err(|error| error.to_string())
        })
        .await;
    }

    let (upgrader, result) =
        apply_http_release(&runtime, permit.clone(), &release, query.now).await;
    // While the apply ran, the claim kept the announcement's self-echo
    // from queueing a second apply. A release this route did not install
    // is not its to keep — unless the apply was admitted, or its install
    // passed to a live probe retry (this request's or an earlier
    // failure's): then the worker or the retry still owns the
    // replacement, so `claim` holds on its way out (handler return,
    // mid-wait drop by a client disconnect, or a panic unwind) and ages
    // out with the tracker TTL.
    match result {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
            claim.keep();
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
            // A failure that leaves a live probe retry owning the install
            // keeps the claim — whether this request scheduled the retry
            // or an earlier failed apply already did: the retry re-applies
            // this same version when its durable wait elapses, and until
            // then a gossip copy must not queue a second apply beside it.
            // A failure with no interrupted probe to resume keeps nothing
            // — the claim releases on drop like every other pre-admission
            // exit.
            if schedule_probe_retry(
                &upgrader,
                &release.manifest,
                Arc::clone(&state.upgrade_apply_lock),
                state.shutdown_notify.subscribe(),
            )
            .await
            {
                claim.keep();
            }
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

/// `POST /upgrade/clear-hold?version=<v>` (D190, #1376).
#[derive(serde::Deserialize)]
pub(in crate::server) struct UpgradeClearHoldQuery {
    #[serde(default)]
    version: Option<String>,
}

/// D190: an authenticated, recorded local clear of this install's
/// failed-release probe hold for exactly `version`. A newer release already
/// clears such a hold by itself; this route lets an operator retry the held
/// release. It never clears recovery-failed or an unresolved record, and it
/// refuses while another upgrade operation holds the in-process apply lock.
pub(in crate::server) async fn clear_upgrade_hold(
    State(state): State<Arc<AppState>>,
    Query(query): Query<UpgradeClearHoldQuery>,
) -> Response {
    let refuse = |status: StatusCode, error: String| {
        (
            status,
            Json(serde_json::json!({ "ok": false, "cleared": false, "error": error })),
        )
            .into_response()
    };
    if !state.self_update_enabled {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "cleared": false,
                "reason": "self-update disabled for this process"
            })),
        )
            .into_response();
    }
    let Some(version) = query
        .version
        .filter(|version| semver::Version::parse(version).is_ok())
    else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "query parameter version must be a semantic version".into(),
        );
    };
    #[cfg(not(unix))]
    {
        let _ = (&state, version);
        refuse(
            StatusCode::NOT_IMPLEMENTED,
            "release probe holds exist only on Unix installs".into(),
        )
    }
    #[cfg(unix)]
    {
        let Ok(_apply_guard) = state.upgrade_apply_lock.try_lock() else {
            return refuse(StatusCode::CONFLICT, "upgrade already in progress".into());
        };
        // Resolve the install on this task: the executable observation is
        // per thread in tests and must not move to the blocking pool.
        let install = match crate::upgrade::apply::current_binary_path().and_then(|path| {
            path.canonicalize()
                .map_err(|error| x0x::upgrade::UpgradeError::Other(error.to_string()))
        }) {
            Ok(install) => install,
            Err(error) => {
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("install path unavailable: {error}"),
                )
            }
        };
        let requested = version.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let _host_lock = crate::upgrade::acquire_host_upgrade_lock(&install)
                .map_err(|error| error.to_string())?;
            crate::upgrade::probe::clear_failed_hold(&install, &requested)
                .map_err(|error| error.to_string())
        })
        .await;
        match outcome {
            Ok(Ok(crate::upgrade::probe::HoldClear::Cleared(receipt))) => {
                tracing::info!(
                    version = %receipt.version,
                    cause = ?receipt.cause,
                    "Failed-release hold cleared by an authenticated local request"
                );
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "ok": true,
                        "cleared": true,
                        "version": receipt.version,
                        "cause": receipt.cause,
                        "transaction_id": receipt.transaction_id,
                    })),
                )
                    .into_response()
            }
            Ok(Ok(crate::upgrade::probe::HoldClear::NotHeld)) => refuse(
                StatusCode::NOT_FOUND,
                format!("no failed-release hold for {version}"),
            ),
            Ok(Err(error)) => refuse(StatusCode::CONFLICT, error),
            Err(error) => refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("hold clear worker failed: {error}"),
            ),
        }
    }
}

/// D185 is limited to the rollout delay; authentication remains on the route.
#[derive(Default, serde::Deserialize)]
pub(in crate::server) struct UpgradeApplyQuery {
    #[serde(default)]
    now: bool,
}

struct HttpUpgradeRuntime {
    config: DaemonUpdateConfig,
    restart_context: RestartContext,
    apply_lock: Arc<Mutex<()>>,
    wait_slot: Arc<tokio::sync::OwnedMutexGuard<()>>,
    shutdown: watch::Receiver<bool>,
    #[cfg(unix)]
    staging: Option<StartupStagingContext>,
    #[cfg(test)]
    operation_observer: Option<Arc<dyn Fn(bool) + Send + Sync>>,
}

/// A dropped request withdraws admission even if its worker is queued on the
/// install lock. An admitted worker retains its replacement/restart custody.
struct HttpRequestCustody {
    permit: ReleasePermit,
    completed_attempt: bool,
}

impl Drop for HttpRequestCustody {
    fn drop(&mut self) {
        if !self.completed_attempt {
            self.permit.cancel();
        }
        self.permit.release_http_wait_slot();
    }
}

/// The route owns the HTTP wait slot. This future owns cancellation and takes
/// the shared apply mutex only after staging and mandatory retry waits finish.
/// `permit` is the handler's admission owner — created there so the
/// apply-route claim can consult it after this future is dropped.
async fn apply_http_release(
    runtime: &HttpUpgradeRuntime,
    permit: ReleasePermit,
    verified: &VerifiedRelease,
    now: bool,
) -> (
    AutoApplyUpgrader,
    Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError>,
) {
    #[cfg(test)]
    let permit = {
        let mut permit = permit;
        permit.observer = runtime.operation_observer.clone();
        permit
    };
    let mut custody = HttpRequestCustody {
        permit: permit.clone(),
        completed_attempt: false,
    };
    // RC4: apply.rs owns the single deferred restart after admission.
    let upgrader = AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(runtime.config.stop_on_upgrade)
        .with_restart_on_success(false)
        .with_http_deferred_restart(true)
        .with_restart_context(runtime.restart_context.clone())
        .with_release_permit(permit.clone());
    #[cfg(unix)]
    let upgrader = match http_staging_request(runtime, verified) {
        Ok(request) => {
            let upgrader = upgrader.with_staging_request(request).with_staging_now(now);
            #[cfg(test)]
            let upgrader = {
                let context = runtime.staging.as_ref();
                upgrader
                    .with_staging_clock(context.and_then(|context| context.clock.clone()))
                    .with_staging_observer(context.and_then(|context| context.observed.clone()))
            };
            upgrader
        }
        Err(error) => return (upgrader, Err(error)),
    };
    // The approved override adds no managed M2 behavior to legacy Windows.
    #[cfg(not(unix))]
    let _ = now;
    let mut shutdown = runtime.shutdown.clone();
    let result = async {
        permit.check()?;
        check_http_shutdown(&shutdown)?;
        x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest)?;
        if !is_newer(&verified.manifest.version, x0x::VERSION) {
            return Ok(x0x::upgrade::UpgradeResult::NoUpgrade);
        }
        #[cfg(unix)]
        upgrader.wait_for_staging(&mut shutdown).await?;
        let _guard = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                return Err(x0x::upgrade::UpgradeError::Other("HTTP upgrade cancelled by shutdown".into()));
            }
            guard = runtime.apply_lock.lock() => guard,
        };
        // Cancellation or supersession while this request waited cannot
        // authorize a late apply. The installer also rechecks under host lock.
        permit.check()?;
        check_http_shutdown(&shutdown)?;
        x0x::upgrade::monitor::validate_manifest_timestamp(&verified.manifest)?;
        let result = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                permit.cancel();
                return Err(x0x::upgrade::UpgradeError::Other("HTTP upgrade cancelled by shutdown".into()));
            }
            result = upgrader.apply_upgrade_from_manifest(&verified.manifest) => result,
        };
        // Completed attempts retain the existing error-response/probe-retry
        // handoff. Setup, staging and cancelled requests cannot spawn a retry.
        custody.completed_attempt = true;
        result
    }.await;
    (upgrader, result)
}

fn check_http_shutdown(shutdown: &watch::Receiver<bool>) -> Result<(), x0x::upgrade::UpgradeError> {
    if *shutdown.borrow() || shutdown.has_changed().is_err() {
        return Err(x0x::upgrade::UpgradeError::Other(
            "HTTP upgrade cancelled by shutdown".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn http_staging_request(
    runtime: &HttpUpgradeRuntime,
    verified: &VerifiedRelease,
) -> Result<crate::upgrade::staging::StagingRequest, x0x::upgrade::UpgradeError> {
    let context = runtime.staging.as_ref().ok_or_else(|| {
        x0x::upgrade::UpgradeError::Other("HTTP upgrade staging identity is unavailable".into())
    })?;
    let data_root = runtime.restart_context.data_dir.as_ref().ok_or_else(|| {
        x0x::upgrade::UpgradeError::Other("HTTP upgrade data root is unavailable".into())
    })?;
    let platform = x0x::upgrade::manifest::current_platform_target()
        .ok_or(x0x::upgrade::UpgradeError::UnsupportedPlatform)?;
    let asset = verified
        .manifest
        .matches_platform(platform)
        .ok_or(x0x::upgrade::UpgradeError::NoPlatformAsset)?;
    Ok(crate::upgrade::staging::StagingRequest {
        install: context.install.clone(),
        data_root: data_root
            .canonicalize()
            .map_err(|error| x0x::upgrade::UpgradeError::Other(error.to_string()))?,
        identity_root: context.identity_root.clone(),
        machine_id: context.machine_id,
        version: verified.manifest.version.clone(),
        manifest_sha256: Sha256::digest(&verified.manifest_json).into(),
        archive_sha256: asset.archive_sha256,
        window_minutes: runtime.config.rollout_window_minutes,
    })
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
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_http_now.rs"
    ));
    http_now_regression_tests!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_http_staging.rs"
    ));
    http_staging_regression_tests!();
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/upgrade_http_readback.rs"
    ));
    http_readback_regression_tests!();
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
    #[cfg(unix)]
    background_init_regression_tests!();

    use super::*;
    use crate::upgrade::restart;
    use x0x::upgrade::manifest::{PlatformAsset, SCHEMA_VERSION};

    fn manifest_with_version(version: &str) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: SCHEMA_VERSION,
            channel: "stable".into(),
            version: version.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs(),
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

    #[tokio::test]
    async fn manifest_eligibility_gates_gossip_and_both_forwarders() {
        use x0x::upgrade::signature::sign_with_context;
        let (pk, sk) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .unwrap();
        let good =
            serde_json::to_value(manifest_with_version(&version_newer_than_current())).unwrap();
        let now = good["timestamp"].as_u64().unwrap();
        let mut cases = vec![("valid", good.clone(), true)];
        for (field, value) in [
            ("channel", serde_json::json!(0)),
            ("channel", serde_json::json!("")),
            ("channel", serde_json::json!("unknown")),
            ("channel", serde_json::json!("prerelease")),
            ("version", serde_json::json!("99.0.0-rc.1")),
            ("timestamp", serde_json::json!(0)),
            ("timestamp", serde_json::json!(now + 3600)),
            ("timestamp", serde_json::json!(now - 31 * 86400)),
        ] {
            let mut value_case = good.clone();
            value_case[field] = value;
            cases.push((field, value_case, false));
        }
        for field in ["channel", "timestamp"] {
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(field);
            cases.push((field, missing, false));
        }
        let mut prerelease = good.clone();
        prerelease["channel"] = serde_json::json!("prerelease");
        prerelease["version"] = serde_json::json!("99.0.0-rc.1");
        cases.push(("prerelease ban", prerelease, false));
        for (label, value, eligible) in cases {
            let json = serde_json::to_vec(&value).unwrap();
            let signature = sign_with_context(&sk.to_bytes(), &json).unwrap();
            let payload = x0x::upgrade::manifest::encode_signed_manifest(&json, &signature);
            assert_eq!(
                verify_gossip_release_with_key(&payload, &pk.to_bytes()).is_some(),
                eligible,
                "{label}"
            );
            let Ok(manifest) = serde_json::from_slice::<ReleaseManifest>(&json) else {
                continue;
            };
            let verified = VerifiedRelease {
                manifest,
                manifest_json: json,
                signature,
                gossip_payload: payload,
            };
            let (_keep_running, shutdown) = watch::channel(false);
            let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = Arc::clone(&published);
            run_gossip_update_driver(
                futures::stream::iter([verified.clone()]),
                None,
                Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default())),
                move |_| {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async { Ok(()) }
                },
                shutdown.clone(),
            )
            .await;
            let count = Arc::clone(&published);
            run_fallback_update_driver(
                futures::stream::iter([()]),
                move || {
                    let verified = verified.clone();
                    async { Ok(Some(verified)) }
                },
                None,
                Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default())),
                move |_| {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async { Ok(()) }
                },
                shutdown,
            )
            .await;
            assert_eq!(
                published.load(std::sync::atomic::Ordering::SeqCst),
                if eligible { 2 } else { 0 },
                "{label}"
            );
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

    // #1169: an applying node must announce a newly observed release on
    // RELEASE_TOPIC, so subscribed peers never wait for their own fallback
    // poll. The read-only /upgrade check announces nothing (Engineer ruling
    // 3 Nov 2026 17:40 GMT): a check-path announce self-delivers and feeds
    // this node's own apply owner — a background install from a read.

    fn verified_release_with_version(version: &str) -> VerifiedRelease {
        let manifest = manifest_with_version(version);
        let manifest_json = serde_json::to_vec(&manifest).expect("serialize manifest fixture");
        let payload = x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, b"announce");
        VerifiedRelease {
            manifest,
            manifest_json,
            signature: b"announce".to_vec(),
            gossip_payload: payload,
        }
    }

    /// A release this node can apply here: the shared fixture's only asset
    /// targets Linux x64, and the background owner refuses a manifest
    /// without this platform's asset before it records anything.
    fn submittable_release(version: &str) -> VerifiedRelease {
        let mut manifest = manifest_with_version(version);
        manifest.assets[0].target = x0x::upgrade::manifest::current_platform_target()
            .expect("tests run on a supported platform")
            .to_string();
        let manifest_json = serde_json::to_vec(&manifest).expect("serialize manifest fixture");
        let payload = x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, b"announce");
        VerifiedRelease {
            manifest,
            manifest_json,
            signature: b"announce".to_vec(),
            gossip_payload: payload,
        }
    }

    /// Run the real gossip driver over one release and report how many
    /// rebroadcasts it published and which version the background slot
    /// selected.
    async fn drive_one_gossip_release(
        verified: VerifiedRelease,
        self_published: Arc<StdMutex<SelfPublishedReleaseManifests>>,
    ) -> (usize, Option<String>) {
        let submit = BackgroundSubmit::default();
        let (_keep_running, shutdown) = watch::channel(false);
        let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&published);
        run_gossip_update_driver(
            futures::stream::iter([verified]),
            submit.clone(),
            self_published,
            move |_| {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Ok(()) }
            },
            shutdown,
        )
        .await;
        let selected = submit
            .slot
            .lock()
            .unwrap()
            .latest
            .as_ref()
            .map(|release| release.manifest.version.clone());
        (
            published.load(std::sync::atomic::Ordering::SeqCst),
            selected,
        )
    }

    // #1169: `/upgrade/apply` announces and then applies itself. The
    // announcement self-delivers to this node's gossip listener; before the
    // fix the driver skipped only the rebroadcast and still queued the same
    // release on the background owner — a second apply of an
    // operator-requested release.
    #[tokio::test]
    async fn self_published_release_is_not_resubmitted_to_the_background_owner() {
        let version = version_newer_than_current();
        let verified = submittable_release(&version);
        let self_published = Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default()));
        self_published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_apply_route_payload(&verified.gossip_payload, Instant::now());

        let (rebroadcasts, selected) = drive_one_gossip_release(verified, self_published).await;

        assert_eq!(
            rebroadcasts, 0,
            "a self-published payload is not rebroadcast"
        );
        assert_eq!(
            selected, None,
            "a self-delivered announcement must not queue a second apply"
        );
    }

    /// Echoes of this node's own driver rebroadcast, fallback publish or
    /// start-up broadcast are not route-owned: they are not rebroadcast
    /// again but still reach the background owner, which dedups them.
    #[tokio::test]
    async fn non_route_self_published_echo_is_still_submitted() {
        let version = version_newer_than_current();
        let verified = submittable_release(&version);
        let self_published = Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default()));
        self_published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_payload(&verified.gossip_payload, Instant::now());

        let (rebroadcasts, selected) = drive_one_gossip_release(verified, self_published).await;

        assert_eq!(
            rebroadcasts, 0,
            "a self-published payload is not rebroadcast"
        );
        assert_eq!(selected, Some(version), "the echo still reaches the owner");
    }

    /// Control for the test above: the same release from a peer is
    /// rebroadcast once and queued, so the fixture is one the background
    /// owner accepts.
    #[tokio::test]
    async fn peer_published_release_is_rebroadcast_and_submitted() {
        let version = version_newer_than_current();
        let verified = submittable_release(&version);
        let self_published = Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default()));

        let (rebroadcasts, selected) = drive_one_gossip_release(verified, self_published).await;

        assert_eq!(rebroadcasts, 1);
        assert_eq!(selected, Some(version));
    }

    #[tokio::test]
    async fn observed_release_announcement_publishes_the_signed_payload() {
        let verified = verified_release_with_version(&version_newer_than_current());
        let expected = verified.gossip_payload.clone();
        let published = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&published);
        announce_observed_release(&verified, move |payload| {
            record.lock().unwrap().push(payload);
            async { Ok(()) }
        })
        .await;
        assert_eq!(
            published.lock().unwrap().as_slice(),
            &[expected],
            "the observation publishes the exact signed gossip payload"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn observed_release_announcement_is_bounded_on_a_stuck_mesh() {
        let verified = verified_release_with_version(&version_newer_than_current());
        let start = tokio::time::Instant::now();
        announce_observed_release(&verified, |_| std::future::pending()).await;
        assert_eq!(
            tokio::time::Instant::now().duration_since(start),
            Duration::from_secs(10),
            "a publication that never completes is abandoned after ten seconds"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn observed_release_announcement_survives_publish_errors() {
        let verified = verified_release_with_version(&version_newer_than_current());
        let start = tokio::time::Instant::now();
        announce_observed_release(&verified, |_| async {
            Err("gossip unreachable".to_string())
        })
        .await;
        assert_eq!(
            tokio::time::Instant::now().duration_since(start),
            Duration::ZERO,
            "a failed publication is abandoned at once: no wait, no retry"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn announced_release_propagates_to_a_subscribed_peer_immediately() {
        // #1169 acceptance shape, honestly signed: a node observes a
        // release and announces the real signed payload; a subscribed peer
        // verifies it, rebroadcasts it and queues it with its background
        // apply owner. Propagation is immediate — the peer reacts in the
        // same scheduling round, not at a heartbeat or poll boundary, which
        // is what keeps the fleet inside the issue's 2 x heartbeat bar.
        // The two sides are wired by a channel; no network, no testnet.
        use x0x::upgrade::signature::sign_with_context;
        let (pk, sk) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .unwrap();
        let mut manifest = manifest_with_version(&version_newer_than_current());
        if let Some(target) = x0x::upgrade::manifest::current_platform_target() {
            if !manifest.assets.iter().any(|asset| asset.target == target) {
                manifest.assets.push(PlatformAsset {
                    target: target.to_string(),
                    archive_url: "https://example.com/x0x-current-platform.tar.gz".to_string(),
                    archive_sha256: [0xCC; 32],
                    signature_url: "https://example.com/x0x-current-platform.tar.gz.sig"
                        .to_string(),
                });
            }
        }
        let expected_version = manifest.version.clone();
        let manifest_json = serde_json::to_vec(&manifest).unwrap();
        let signature = sign_with_context(&sk.to_bytes(), &manifest_json).unwrap();
        let payload = x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, &signature);
        let verified = VerifiedRelease {
            manifest,
            manifest_json,
            signature,
            gossip_payload: payload.clone(),
        };

        let start = tokio::time::Instant::now();
        let (announce_tx, announce_rx) = mpsc::channel::<Vec<u8>>(8);
        let (relayed_tx, mut relayed_rx) = mpsc::channel::<tokio::time::Instant>(1);
        let queued = Arc::new(std::sync::Mutex::new(Vec::new()));

        // The observing node: announce the verified payload on the topic.
        announce_observed_release(&verified, move |observed| {
            let announce_tx = announce_tx.clone();
            async move { announce_tx.send(observed).await.map_err(|e| e.to_string()) }
        })
        .await;

        // The subscribed peer: verify the payload like the gossip listener
        // does, then run the gossip driver with a background apply owner.
        let releases = futures::stream::unfold(announce_rx, move |mut announce_rx| {
            let pk = pk.clone();
            async move {
                let payload = announce_rx.recv().await?;
                verify_gossip_release_with_key(&payload, &pk.to_bytes())
                    .map(|verified| (verified, announce_rx))
            }
        });
        let record = Arc::clone(&queued);
        let relayer_submit = BackgroundSubmit {
            processed: Some(Arc::new(move |version, outcome| {
                record.lock().unwrap().push((version, outcome))
            })),
            ..Default::default()
        };
        let (_keep_running, relayer_shutdown) = watch::channel(false);
        run_gossip_update_driver(
            releases,
            Some(relayer_submit),
            Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default())),
            move |_| {
                let _ = relayed_tx.try_send(tokio::time::Instant::now());
                async { Ok(()) }
            },
            relayer_shutdown,
        )
        .await;

        let peer_reacted_at = relayed_rx.recv().await.expect("peer reacted");
        assert_eq!(
            peer_reacted_at.duration_since(start),
            Duration::ZERO,
            "the peer reacts in the same scheduling round as the observation"
        );
        assert_eq!(
            queued.lock().unwrap().as_slice(),
            &[(expected_version, SubmitOutcome::Accepted)],
            "the subscribed peer started its own update check from the announcement"
        );
    }

    // Route-level coverage for the 17:40 GMT ruling and the call sites
    // Claude's a8cf431f review asked about (round 5, finding 2): a real
    // AppState through the shared fixture and a loopback-only gossip
    // runtime, so any publish attempt is observable.

    /// A gossip agent bound to loopback only (no bootstrap nodes, no
    /// mDNS, no port mapping): its pubsub works in-process, so tests
    /// observe publishes — including self-delivery — with no real network.
    async fn loopback_gossip_agent(data_dir: &std::path::Path) -> Arc<Agent> {
        Arc::new(
            Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate().expect("agent key"))
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_peer_cache_disabled()
                .with_contact_store_path(data_dir.join("contacts.json"))
                .with_network_config(crate::network::NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
                    bootstrap_nodes: Vec::new(),
                    port_mapping_enabled: false,
                    mdns_enabled: false,
                    ..crate::network::NetworkConfig::default()
                })
                .build()
                .await
                .expect("loopback gossip agent"),
        )
    }

    /// #1169 acceptance over real loopback gossip: node A's real fallback
    /// driver observes a signed release and publishes it on `x0x/release`;
    /// node B's real gossip driver, fed by its own topic subscription and
    /// the listener's verifier, queues it with its background apply owner.
    /// The issue's bar is under 2 × the heartbeat (2 × 600 s); the test
    /// waits for the topic mesh with unique probes, then allows 10 s.
    /// `announced_release_propagates_to_a_subscribed_peer_immediately`
    /// proves the same flow with a channel in place of the network.
    #[tokio::test]
    async fn observed_release_propagates_over_real_gossip_to_a_peer_owner() {
        use x0x::upgrade::signature::sign_with_context;
        let (pk, sk) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .expect("test release key");
        let mut manifest = manifest_with_version(&version_newer_than_current());
        manifest.assets[0].target = x0x::upgrade::manifest::current_platform_target()
            .expect("tests run on a supported platform")
            .to_string();
        let expected_version = manifest.version.clone();
        let manifest_json = serde_json::to_vec(&manifest).expect("manifest json");
        let signature = sign_with_context(&sk.to_bytes(), &manifest_json).expect("sign");
        let payload = x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, &signature);
        let verified = VerifiedRelease {
            manifest,
            manifest_json,
            signature,
            gossip_payload: payload,
        };

        let dir_a = tempfile::tempdir().expect("tmpdir a");
        let dir_b = tempfile::tempdir().expect("tmpdir b");
        let a = loopback_gossip_agent(dir_a.path()).await;
        let b = loopback_gossip_agent(dir_b.path()).await;
        a.join_network().await.expect("a joins");
        b.join_network().await.expect("b joins");
        let _a_topic = a.subscribe(RELEASE_TOPIC).await.expect("a subscribes");
        let b_topic = b.subscribe(RELEASE_TOPIC).await.expect("b subscribes");
        let b_addr = b.bound_addr().await.expect("b bound");
        let b_addr = SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), b_addr.port());
        a.network()
            .expect("a network")
            .connect_addr(b_addr)
            .await
            .expect("a connects to b");

        // Wait until the release topic carries A's messages to B, so the one
        // real publish below cannot race the mesh. Each probe is unique and
        // fails B's signature check, so B's driver drops it.
        let mut b_probe = b
            .subscribe(RELEASE_TOPIC)
            .await
            .expect("b probe subscribes");
        let mut probe_seq = 0u32;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                probe_seq += 1;
                let probe = format!("mesh-probe-{probe_seq}").into_bytes();
                a.publish(RELEASE_TOPIC, probe)
                    .await
                    .expect("a publishes probe");
                if let Ok(Some(message)) =
                    tokio::time::timeout(Duration::from_millis(250), b_probe.recv()).await
                {
                    if message.payload.starts_with(b"mesh-probe-") {
                        break;
                    }
                }
            }
        })
        .await
        .expect("the release topic did not carry A's probes to B within 10 s");
        drop(b_probe);

        // Peer B: subscription -> verifier -> real driver -> owner intake.
        let (queued_tx, mut queued_rx) = mpsc::unbounded_channel();
        let b_submit = BackgroundSubmit {
            processed: Some(Arc::new(move |version, outcome| {
                let _ = queued_tx.send((version, outcome));
            })),
            ..Default::default()
        };
        let releases = futures::stream::unfold(
            (b_topic, pk.to_bytes()),
            |(mut subscription, key)| async move {
                loop {
                    let message = subscription.recv().await?;
                    if let Some(verified) = verify_gossip_release_with_key(&message.payload, &key) {
                        return Some((verified, (subscription, key)));
                    }
                }
            },
        );
        let (_b_running, b_shutdown) = watch::channel(false);
        let b_driver = tokio::spawn(run_gossip_update_driver(
            releases,
            Some(b_submit),
            Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default())),
            |_| async { Ok(()) },
            b_shutdown,
        ));

        // Node A: one real fallback tick observes the release and publishes.
        let (_a_running, a_shutdown) = watch::channel(false);
        let a_publish = Arc::clone(&a);
        let a_driver = tokio::spawn(run_fallback_update_driver(
            futures::stream::iter([()]),
            move || {
                let verified = verified.clone();
                async move { Ok(Some(verified)) }
            },
            None::<BackgroundSubmit>,
            Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default())),
            move |payload| {
                let agent = Arc::clone(&a_publish);
                async move {
                    agent
                        .publish(RELEASE_TOPIC, payload)
                        .await
                        .map_err(|error| error.to_string())
                }
            },
            a_shutdown,
        ));

        let queued = tokio::time::timeout(Duration::from_secs(10), queued_rx.recv())
            .await
            .expect("the peer did not queue the release within 10 s");
        assert_eq!(
            queued,
            Some((expected_version, SubmitOutcome::Accepted)),
            "the peer's owner accepted the announced release"
        );
        a_driver.abort();
        b_driver.abort();
        a.shutdown().await;
        b.shutdown().await;
    }

    /// #1169 review: `/upgrade/apply` records its announcement as
    /// apply-route-owned, so the self-echo cannot queue a second apply
    /// while the route's own apply runs. When that apply does not
    /// succeed and leaves nothing resuming the install — this fixture's
    /// install path does not exist, so no probe retry is scheduled — the
    /// route releases the claim: a gossip copy of the same payload — a
    /// peer's, or this node's own echo — must reach the background owner
    /// again instead of being dropped for the tracker's TTL. Without the
    /// release, the driver's apply-route skip swallows every copy for 30
    /// minutes and the owner depends on a peer re-announce or the
    /// fallback poll. Unix-gated like `current_binary_path_seam`, which
    /// the fast hermetic refusal leans on.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_apply_route_releases_the_release_to_the_background_owner() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = upgrade_route_state(Arc::clone(&agent), dir.path()).await;
        let _no_install =
            crate::upgrade::apply::current_binary_path_seam::install(dir.path().join("no-binary"));

        let verified = submittable_release(&version_newer_than_current());
        let expected_version = verified.manifest.version.clone();
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));
        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["applied"], serde_json::json!(false));

        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        {
            let mut tracker = state
                .self_published_release_manifests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                tracker.contains_recent_digest(&digest, Instant::now()),
                "the announced payload stays recorded: this node does not rebroadcast bytes it already published"
            );
            assert!(
                !tracker.recorded_by_apply_route(&digest, Instant::now()),
                "a route whose apply did not succeed and resumes nothing no longer owns the release"
            );
        }

        // The production consequence, through the real gossip driver over
        // the same tracker the route used: a later copy is submitted to
        // the background owner, and still not rebroadcast.
        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(
            rebroadcasts, 0,
            "self-published bytes are not rebroadcast again"
        );
        assert_eq!(
            selected,
            Some(expected_version),
            "a gossip copy after the failed apply reaches the background owner"
        );
        agent.shutdown().await;
    }

    /// Every caller is unix-gated like `current_binary_path_seam`, so the
    /// helper is too; on Windows it would be dead code.
    #[cfg(unix)]
    fn lock_tracker(
        state: &Arc<AppState>,
    ) -> std::sync::MutexGuard<'_, SelfPublishedReleaseManifests> {
        state
            .self_published_release_manifests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Assert the announced payload's tracker state after a route exit:
    /// still recorded (this node never rebroadcasts bytes it published),
    /// and apply-route owned exactly when `owned` says.
    #[cfg(unix)]
    fn assert_claim(state: &Arc<AppState>, digest: &[u8; 32], owned: bool, because: &str) {
        let mut tracker = lock_tracker(state);
        assert!(
            tracker.contains_recent_digest(digest, Instant::now()),
            "the announced payload stays recorded: {because}"
        );
        assert_eq!(
            tracker.recorded_by_apply_route(digest, Instant::now()),
            owned,
            "{because}"
        );
    }

    /// A staging context like `e2e_startup_runtime`'s: an install fixture
    /// the host upgrade lock can flock, an identity root under the data
    /// dir, a fixed machine id, a monotonic clock, and optionally an
    /// observer that sees every staging-gate decision the route makes.
    #[cfg(unix)]
    fn route_staging_context(
        data_dir: &std::path::Path,
        observed: Option<crate::upgrade::staging_runtime::Observer>,
    ) -> StartupStagingContext {
        let root = data_dir.canonicalize().expect("canonical data dir");
        let install = root.join("x0xd");
        std::fs::write(&install, b"owned route staging executable fixture")
            .expect("install fixture");
        let started = std::time::Instant::now();
        StartupStagingContext {
            install,
            identity_root: root,
            machine_id: [42; 32],
            observed,
            clock: Some(Arc::new(move || {
                Ok(crate::upgrade::probe::ProbeClock {
                    boot_id: "route-fixture".into(),
                    monotonic_ms: 1000
                        + u64::try_from(started.elapsed().as_millis())
                            .map_err(std::io::Error::other)?,
                })
            })),
        }
    }

    /// A route state whose `/upgrade/apply` can get past the fast
    /// staging refusal: it carries the staging identity and the given
    /// rollout window. Zero window lets an apply complete; the default
    /// parks it in the staging wait.
    #[cfg(unix)]
    async fn staging_route_state(
        agent: Arc<Agent>,
        data_dir: &std::path::Path,
        rollout_window_minutes: u64,
    ) -> Arc<AppState> {
        staging_route_state_observed(agent, data_dir, rollout_window_minutes, None).await
    }

    /// [`staging_route_state`] with a staging-gate observer, for tests
    /// that must know the handler is inside the staging wait.
    #[cfg(unix)]
    async fn staging_route_state_observed(
        agent: Arc<Agent>,
        data_dir: &std::path::Path,
        rollout_window_minutes: u64,
        observed: Option<crate::upgrade::staging_runtime::Observer>,
    ) -> Arc<AppState> {
        let update_config = DaemonUpdateConfig {
            rollout_window_minutes,
            ..DaemonUpdateConfig::default()
        };
        super::super::named_groups::tests::secure_endpoint_test_state_with_upgrade_options(
            data_dir,
            agent,
            true,
            Some(route_staging_context(data_dir, observed)),
            update_config,
        )
        .await
        .expect("staging-capable route state")
    }

    /// Readback answers for the route's staging identity and restart
    /// contract resolution: an untracked unit with no start-rate limit.
    /// `show_for_this_process` renders the seam-observed install path as
    /// ExecStart but the real argv[0] inside `argv[]`; the structured
    /// binding check requires both to name the install, so argv[0] is
    /// rewritten like `staging_readback` does. Call after installing
    /// `current_binary_path_seam` on `install`.
    #[cfg(unix)]
    fn route_readback_scenario(
        calls: usize,
        install: &std::path::Path,
    ) -> restart::systemd_readback_seam::Scenario {
        let install_display = install.to_string_lossy().into_owned();
        let show_output = show_for_this_process("0", "5", 1_000_000)
            .replace(&restart::current_argv()[0], &install_display);
        restart::systemd_readback_seam::Scenario {
            cgroup: "0::/system.slice/x0x-staging-test.service".to_string(),
            invocation_id: Some(SEAM_INVOCATION_ID.to_string()),
            calls: (0..calls)
                .map(|_| restart::systemd_readback_seam::ReadbackCall {
                    show_output: show_output.clone(),
                    monotonic_now_us: 3_000_000,
                })
                .collect(),
        }
    }

    /// #1169 review round 2, the cancellation half of the claim-release
    /// invariant: a client that walks away mid-apply (for example
    /// `curl -m 60` against the staging wait) drops the handler future.
    /// Before admission the claim guard must release the claim on that
    /// drop — no outcome was ever produced — so gossip copies of the
    /// payload reach the background owner again. The handler runs against
    /// a 60-minute rollout window on a real staging gate under the data
    /// dir, so it cannot finish on its own; the test observes the live
    /// claim, confirms through the staging observer that the handler is
    /// parked in the staging wait (a `Waiting` gate decision, not a
    /// version-string-lucky sub-second wait), then drops the future the
    /// way a client disconnect would.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_cancelled_apply_route_releases_the_release_to_the_background_owner() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let state = staging_route_state_observed(
            Arc::clone(&agent),
            dir.path(),
            60,
            Some(Arc::new(move |decision| {
                if matches!(decision, crate::upgrade::staging::Decision::Waiting(_)) {
                    let _ = waiting_tx.send(());
                }
            })),
        )
        .await;
        let install = dir.path().canonicalize().expect("canonical").join("x0xd");
        let _current = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        let _readback =
            restart::systemd_readback_seam::install(route_readback_scenario(4, &install));

        let verified = submittable_release(&version_newer_than_current());
        let expected_version = verified.manifest.version.clone();
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));

        let handler_state = Arc::clone(&state);
        let handler = tokio::spawn(async move {
            apply_upgrade(State(handler_state), Query(Default::default())).await
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !lock_tracker(&state).recorded_by_apply_route(&digest, Instant::now()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the route never recorded its apply-route claim; handler finished: {}",
                handler.is_finished()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The staging gate itself says the handler is parked in the
        // rollout wait: the 60-minute window cannot elapse on its own, so
        // the handler cannot finish from here either.
        let wait_deadline = std::time::Instant::now() + Duration::from_secs(10);
        while waiting_rx.try_recv().is_err() {
            assert!(
                std::time::Instant::now() < wait_deadline,
                "the handler never reached the staging wait; handler finished: {}",
                handler.is_finished()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !handler.is_finished(),
            "the handler must still be waiting inside its apply"
        );

        handler.abort();
        let joined = handler.await;
        assert!(
            matches!(&joined, Err(error) if error.is_cancelled()),
            "the handler future was dropped mid-wait"
        );
        assert_claim(
            &state,
            &digest,
            false,
            "a cancelled apply releases the claim: gossip copies must reach the owner again",
        );

        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(rebroadcasts, 0, "self-published bytes are not rebroadcast");
        assert_eq!(
            selected,
            Some(expected_version),
            "a gossip copy after the cancelled apply reaches the background owner"
        );
        agent.shutdown().await;
    }

    /// #1169 review round 3, the admission half of the claim-release
    /// invariant: the claim follows admission, not the handler outcome.
    /// The injected attempt stands in for the destructive half past the
    /// real worker's admission point (it marks the permit admitted via
    /// the attempt's admission handle) and then rolls the apply back.
    /// The handler leaves the way every non-Success exit does — the same
    /// drop-guard path a client disconnect takes — and because the apply
    /// was admitted, the claim survives the exit and ages out with the
    /// tracker TTL: the install was owned by the destructive half, and
    /// its echo must not queue a second apply. Fails on the round-2
    /// rule, where every drop released the claim. The literal disconnect
    /// against the real worker is pinned one layer down, in
    /// `post_admission_disconnect_keeps_the_permit_admitted`.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_post_admission_exit_keeps_the_release_claim() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = staging_route_state(Arc::clone(&agent), dir.path(), 0).await;
        let install = dir.path().canonicalize().expect("canonical").join("x0xd");
        let _current = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        let _readback =
            restart::systemd_readback_seam::install(route_readback_scenario(8, &install));

        let verified = submittable_release(&version_newer_than_current());
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));
        let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(
            |_plan, _manifest, admission| {
                admission.admit();
                x0x::upgrade::UpgradeResult::RolledBack {
                    reason: "fixture post-admission rollback".into(),
                }
            },
        ));

        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["rolled_back"], serde_json::json!(true));
        assert_claim(
            &state,
            &digest,
            true,
            "a post-admission exit keeps the claim: the destructive half owned the install",
        );

        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(rebroadcasts, 0, "self-published bytes are not rebroadcast");
        assert_eq!(
            selected, None,
            "the echo of an apply the destructive half owned must not queue a second apply"
        );
        agent.shutdown().await;
    }

    /// #1169 review round 4 (Claude should-fix 1), the probe-retry
    /// hand-off: a failed apply that schedules a probe retry must not
    /// release the claim. The route's real apply refuses on a durable
    /// `InterruptedWait` — the exact state the probe retry exists to
    /// resume — seeded between the staging gate and the probe admission
    /// check the way the http-readback fixture does, so the staging wait
    /// itself stays due and the refusal is the real "probe retry waits"
    /// error. The handler then hands the install to a live retry timer
    /// on its way out; until that retry re-applies this version, a
    /// gossip copy of the announcement must not queue a second apply
    /// beside it — the claim ages out with the tracker TTL. The route
    /// still releases on failures that resume nothing — that direction
    /// is pinned by the fast-refusal sister test above. Fails on the
    /// round-3 rule, where every pre-admission drop released the claim
    /// and the echo queued behind the background owner.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_probe_retry_hand_off_keeps_the_release_claim() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = staging_route_state(Arc::clone(&agent), dir.path(), 0).await;
        let install = dir.path().canonicalize().expect("canonical").join("x0xd");
        let _current = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        let _readback =
            restart::systemd_readback_seam::install(route_readback_scenario(8, &install));

        let verified = submittable_release(&version_newer_than_current());
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));
        // Seed the durable interrupted probe the route's apply will refuse
        // on and the retry resumes — at the pre-probe-admission point, so
        // the staging gate itself stays due. Current boot like the http-now
        // fixture, and a deadline 30 minutes out: the spawned retry waits
        // on it instead of applying during this test.
        let seed_version = verified.manifest.version.clone();
        let seed_platform = verified.manifest.assets[0].target.clone();
        let seed_archive_sha256 = verified.manifest.assets[0].archive_sha256;
        let _probe_seed = crate::upgrade::apply::pre_probe_admission_seam::install(
            install.clone(),
            Box::new(move |target| {
                let clock = crate::upgrade::probe::ProbeClock::now().expect("probe clock");
                let seeded = crate::upgrade::probe::ProbeState {
                    schema_version: 1,
                    record_kind: "probe".into(),
                    install: target.to_path_buf(),
                    version: seed_version,
                    platform: seed_platform,
                    archive_sha256: seed_archive_sha256,
                    transaction_id: "42424242-4242-4242-8242-424242424242".into(),
                    attempt: 1,
                    phase: crate::upgrade::probe::ProbePhase::InterruptedWait,
                    cause: Some(crate::upgrade::probe::ProbeCause::Timeout),
                    last_pid: None,
                    boot_id: clock.boot_id,
                    retry_remaining_ms: 1_800_000,
                    retry_deadline_ms: clock.monotonic_ms + 1_800_000,
                    daemon_sha256: None,
                    cli_sha256: None,
                };
                let path = crate::upgrade::probe::state_path(target).expect("probe state path");
                std::fs::write(
                    &path,
                    serde_json::to_vec(&seeded).expect("probe state json"),
                )
                .expect("seed probe state");
            }),
        );

        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["applied"], serde_json::json!(false));
        assert_claim(
            &state,
            &digest,
            true,
            "a probe-retry hand-off keeps the claim: the retry still owns the install",
        );

        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(rebroadcasts, 0, "self-published bytes are not rebroadcast");
        assert_eq!(
            selected, None,
            "the echo of a release a probe retry still owns must not queue a second apply"
        );
        agent.shutdown().await;
    }

    /// #1169 review round 5 (Claude should-fix 1), the second apply of
    /// the same bytes: request A fails before admission, hands the
    /// install to a live probe retry and keeps the claim; request B for
    /// the same release then fails without being able to schedule a
    /// retry of its own — A's retry already owns that install and
    /// version process-locally. B's exit must treat that "retry already
    /// owned" answer as the same hand-off and keep the claim: releasing
    /// it would clear the live retry's suppression and let a gossip
    /// copy queue a second apply beside the retry timer. Both requests
    /// refuse on the same durable `InterruptedWait` the retry waits out
    /// (deadline 30 minutes out, seeded at the pre-probe-admission point
    /// the way the http-readback fixture does); B fails before that
    /// wait — after A's retry settles into its durable wait the readback
    /// scenario is replaced with one whose unit no longer names this
    /// install, the pre-admission identity refusal every supervised
    /// apply fails on — so B's handler answers promptly and its Err arm
    /// reaches the scheduler with the install resolvable and the owner
    /// still held. Fails on the round-4 rule, where only the request
    /// that scheduled the retry kept the claim and B's guard released
    /// it on the way out.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_failed_apply_keeps_a_live_retry_claim() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = staging_route_state(Arc::clone(&agent), dir.path(), 0).await;
        let install = dir.path().canonicalize().expect("canonical").join("x0xd");
        let _current = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        let _readback =
            restart::systemd_readback_seam::install(route_readback_scenario(8, &install));

        let verified = submittable_release(&version_newer_than_current());
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));
        // Seed the durable interrupted probe both requests refuse on and
        // A's retry waits out — at the pre-probe-admission point, so the
        // staging gate itself stays due. Current boot like the http-now
        // fixture, and a deadline 30 minutes out.
        let seed_version = verified.manifest.version.clone();
        let seed_platform = verified.manifest.assets[0].target.clone();
        let seed_archive_sha256 = verified.manifest.assets[0].archive_sha256;
        let _probe_seed = crate::upgrade::apply::pre_probe_admission_seam::install(
            install.clone(),
            Box::new(move |target| {
                let clock = crate::upgrade::probe::ProbeClock::now().expect("probe clock");
                let seeded = crate::upgrade::probe::ProbeState {
                    schema_version: 1,
                    record_kind: "probe".into(),
                    install: target.to_path_buf(),
                    version: seed_version,
                    platform: seed_platform,
                    archive_sha256: seed_archive_sha256,
                    transaction_id: "43434343-4343-4343-8343-434343434343".into(),
                    attempt: 1,
                    phase: crate::upgrade::probe::ProbePhase::InterruptedWait,
                    cause: Some(crate::upgrade::probe::ProbeCause::Timeout),
                    last_pid: None,
                    boot_id: clock.boot_id,
                    retry_remaining_ms: 1_800_000,
                    retry_deadline_ms: clock.monotonic_ms + 1_800_000,
                    daemon_sha256: None,
                    cli_sha256: None,
                };
                let path = crate::upgrade::probe::state_path(target).expect("probe state path");
                std::fs::write(
                    &path,
                    serde_json::to_vec(&seeded).expect("probe state json"),
                )
                .expect("seed probe state");
            }),
        );

        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["applied"], serde_json::json!(false));
        assert_claim(
            &state,
            &digest,
            true,
            "the first failed apply hands off to a probe retry and keeps the claim",
        );

        // Give the spawned retry time to settle into its durable wait
        // (its first gated read resolves the staging identity against
        // the verified scenario), then swap the readback for a unit that
        // no longer names this install and re-arm the one-shot feed seam
        // so request B verifies and applies the same bytes.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let _readback_second =
            restart::systemd_readback_seam::install(restart::systemd_readback_seam::Scenario {
                cgroup: "0::/system.slice/x0x-staging-test.service".to_string(),
                invocation_id: Some(SEAM_INVOCATION_ID.to_string()),
                calls: vec![restart::systemd_readback_seam::ReadbackCall {
                    show_output: show_for_this_process("0", "5", 1_000_000),
                    monotonic_now_us: 3_000_000,
                }],
            });
        let _feed_second = upgrade_check_feed_seam::install(Some(verified.clone()));
        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["applied"], serde_json::json!(false));
        assert_claim(
            &state,
            &digest,
            true,
            "a second failed apply must not release the live retry's claim: the retry the first failure left still owns the install",
        );

        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(rebroadcasts, 0, "self-published bytes are not rebroadcast");
        assert_eq!(
            selected, None,
            "the echo of a release a live probe retry owns must not queue a second apply"
        );
        agent.shutdown().await;
    }

    /// #1169 review round 2, the panic half of the claim-release
    /// invariant: a handler that unwinds mid-apply (here a panicking
    /// apply attempt, before any admission is possible) releases the
    /// claim on its way out, exactly like every other pre-admission
    /// non-Success exit.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_panicking_apply_route_releases_the_release_to_the_background_owner() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = staging_route_state(Arc::clone(&agent), dir.path(), 0).await;
        let install = dir.path().canonicalize().expect("canonical").join("x0xd");
        let _current = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        let _readback =
            restart::systemd_readback_seam::install(route_readback_scenario(8, &install));
        let _apply =
            crate::upgrade::apply::apply_attempt_seam::install(Box::new(|_, _, _admission| {
                panic!("apply attempt fixture panic")
            }));

        let verified = submittable_release(&version_newer_than_current());
        let expected_version = verified.manifest.version.clone();
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));

        let handler_state = Arc::clone(&state);
        let handler = tokio::spawn(async move {
            apply_upgrade(State(handler_state), Query(Default::default())).await
        });
        let joined = handler.await;
        assert!(
            matches!(&joined, Err(error) if error.is_panic()),
            "the handler unwound mid-apply"
        );
        assert_claim(
            &state,
            &digest,
            false,
            "a panicking apply releases the claim: gossip copies must reach the owner again",
        );

        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(rebroadcasts, 0, "self-published bytes are not rebroadcast");
        assert_eq!(
            selected,
            Some(expected_version),
            "a gossip copy after the panicking apply reaches the background owner"
        );
        agent.shutdown().await;
    }

    /// The route's outcome space beyond `Err`, at the admission boundary a
    /// `RolledBack` answer can only reach pre-admission through a stand-in
    /// like this one: the real rollback runs after `admit_if_alive`, so a
    /// production `RolledBack` is always post-admission and keeps the
    /// claim (pinned by `a_post_admission_exit_keeps_the_release_claim`,
    /// whose injected attempt admits and then rolls back). Here the
    /// stand-in never admits, so the exit is pre-admission and releases
    /// the claim like a failure does.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_never_admitted_rolled_back_outcome_releases_the_release_to_the_background_owner() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = staging_route_state(Arc::clone(&agent), dir.path(), 0).await;
        let install = dir.path().canonicalize().expect("canonical").join("x0xd");
        let _current = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        let _readback =
            restart::systemd_readback_seam::install(route_readback_scenario(8, &install));
        let _apply =
            crate::upgrade::apply::apply_attempt_seam::install(Box::new(|_, _, _admission| {
                x0x::upgrade::UpgradeResult::RolledBack {
                    reason: "fixture rollback".into(),
                }
            }));

        let verified = submittable_release(&version_newer_than_current());
        let expected_version = verified.manifest.version.clone();
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));
        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["applied"], serde_json::json!(false));
        assert_eq!(body["rolled_back"], serde_json::json!(true));
        assert_claim(
            &state,
            &digest,
            false,
            "a rolled-back outcome the apply never admitted releases the claim: gossip copies must reach the owner again",
        );

        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(rebroadcasts, 0, "self-published bytes are not rebroadcast");
        assert_eq!(
            selected,
            Some(expected_version),
            "a gossip copy after the rolled-back apply reaches the background owner"
        );
        agent.shutdown().await;
    }

    /// The route's outcome space beyond `Err`: a release that is not
    /// newer answers `NoUpgrade`; the announcement's claim is released
    /// because the exit precedes admission — nothing was ever installed
    /// or scheduled. Needs the staging identity (the staging request is
    /// built before the version check), but never reaches the staging
    /// wait. No driver consequence is asserted here: a same-version copy
    /// is skipped by the driver's own version gate, not by any claim —
    /// copies reaching the owner is pinned by the failed, rolled-back,
    /// cancelled and panicking variants.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_no_upgrade_apply_route_releases_the_release_to_the_background_owner() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = staging_route_state(Arc::clone(&agent), dir.path(), 0).await;

        let verified = submittable_release(x0x::VERSION);
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));
        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["applied"], serde_json::json!(false));
        assert_eq!(body["reason"], serde_json::json!("no upgrade required"));
        assert_claim(
            &state,
            &digest,
            false,
            "a no-op apply exits before admission and releases the claim",
        );
        agent.shutdown().await;
    }

    /// The claim's purpose, pinned from the keep side: only a successful
    /// apply keeps it. Inverting the route's keep decision (releasing on
    /// success instead) fails this test — the echo of the route's own
    /// announcement would queue a second apply of the release it just
    /// installed.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_successful_apply_route_keeps_its_release_claim() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = staging_route_state(Arc::clone(&agent), dir.path(), 0).await;
        let install = dir.path().canonicalize().expect("canonical").join("x0xd");
        let _current = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        let _readback =
            restart::systemd_readback_seam::install(route_readback_scenario(8, &install));
        let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(
            |_, manifest, _admission| x0x::upgrade::UpgradeResult::Success {
                version: manifest.version.clone(),
            },
        ));

        let verified = submittable_release(&version_newer_than_current());
        let expected_version = verified.manifest.version.clone();
        let digest = release_manifest_payload_digest(&verified.gossip_payload);
        let _feed = upgrade_check_feed_seam::install(Some(verified.clone()));
        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["applied"], serde_json::json!(true));
        assert_eq!(body["version"], serde_json::json!(expected_version));
        assert_claim(
            &state,
            &digest,
            true,
            "the route that installed the release keeps the claim",
        );

        let (rebroadcasts, selected) = drive_one_gossip_release(
            verified,
            Arc::clone(&state.self_published_release_manifests),
        )
        .await;
        assert_eq!(rebroadcasts, 0, "self-published bytes are not rebroadcast");
        assert_eq!(
            selected, None,
            "the echo of a successful route apply must not queue a second apply"
        );
        agent.shutdown().await;
    }

    /// #1169 review round 2: the claim release on an unknown digest is a
    /// no-op, and releasing a claim never refreshes the record's TTL —
    /// the tracker entry ages out from its latest record of any kind, and
    /// only a fresh record (apply-route, boot broadcast, fallback publish
    /// or driver rebroadcast) would move that clock.
    #[test]
    fn clearing_an_unknown_digest_is_a_no_op_and_does_not_refresh_the_ttl() {
        let payload = encoded_payload_for_manifest(&manifest_with_version("9.9.7"));
        let other = encoded_payload_for_manifest(&manifest_with_version("9.9.8"));
        let digest = release_manifest_payload_digest(&payload);
        let other_digest = release_manifest_payload_digest(&other);
        let now = Instant::now();

        let mut tracker = SelfPublishedReleaseManifests::default();
        tracker.record_apply_route_payload(&payload, now);
        assert!(tracker.recorded_by_apply_route(&digest, now));

        tracker.clear_apply_route_digest(&other_digest, now);
        assert!(
            tracker.recorded_by_apply_route(&digest, now),
            "clearing an unknown digest changes nothing"
        );

        let cleared_at = now + Duration::from_secs(5);
        tracker.clear_apply_route_digest(&digest, cleared_at);
        assert!(!tracker.recorded_by_apply_route(&digest, cleared_at));
        assert!(
            tracker.contains_recent_digest(&digest, cleared_at),
            "the release stays recorded: no rebroadcast of published bytes"
        );
        let just_inside_ttl = now + SELF_PUBLISHED_RELEASE_TTL - Duration::from_secs(1);
        assert!(tracker.contains_recent_digest(&digest, just_inside_ttl));
        let after_ttl = now + SELF_PUBLISHED_RELEASE_TTL + Duration::from_secs(1);
        assert!(
            !tracker.contains_recent_digest(&digest, after_ttl),
            "the clear does not refresh the TTL: it still runs from the record"
        );
    }

    /// #1169 review round 2: the gossip funnel has its own wrong-key
    /// rejection, independent of the binary-file signature tests — a
    /// manifest signed by a key that is not the trusted release key is
    /// dropped before any version or timestamp consideration.
    #[tokio::test]
    async fn gossip_release_verification_rejects_a_wrong_signing_key() {
        use x0x::upgrade::signature::sign_with_context;
        let (pk, sk) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .unwrap();
        let (other_pk, _) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .unwrap();
        let manifest = manifest_with_version(&version_newer_than_current());
        let manifest_json = serde_json::to_vec(&manifest).unwrap();
        let signature = sign_with_context(&sk.to_bytes(), &manifest_json).unwrap();
        let payload = x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, &signature);

        assert!(
            verify_gossip_release_with_key(&payload, &other_pk.to_bytes()).is_none(),
            "a manifest signed by an untrusted key is rejected"
        );
        assert!(
            verify_gossip_release_with_key(&payload, &pk.to_bytes()).is_some(),
            "control: the same manifest verifies under its own key"
        );
    }

    /// #1169 review round 2: the boot broadcast — the every-launch
    /// announce point — publishes the fetched manifest exactly once and
    /// records it without the apply-route claim, so its echo still
    /// reaches the background owner.
    #[tokio::test]
    async fn startup_broadcast_publishes_and_records_the_current_manifest() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let mut release_topic = agent
            .subscribe(RELEASE_TOPIC)
            .await
            .expect("release topic subscription");
        let tracker = Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default()));

        // Current version and an empty skill URL with the missing-file
        // hash: the SKILL.md sync takes its already-up-to-date return, no
        // HTTP. The broadcast publishes what the fetch funnel returned —
        // newer-than-current is not its precondition.
        let mut manifest = manifest_for_this_platform(x0x::VERSION);
        manifest.skill_url = String::new();
        manifest.skill_sha256 = [0u8; 32];
        let manifest_json = serde_json::to_vec(&manifest).expect("manifest fixture");
        let payload = x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, b"announce");
        let verified = VerifiedRelease {
            manifest,
            manifest_json,
            signature: b"announce".to_vec(),
            gossip_payload: payload.clone(),
        };
        let _feed = broadcast_feed_seam::install(Ok(Some(verified)));

        broadcast_current_manifest(
            &agent,
            "saorsa-labs/x0x",
            false,
            dir.path(),
            Arc::clone(&tracker),
        )
        .await;

        let received = tokio::time::timeout(Duration::from_secs(5), release_topic.recv())
            .await
            .expect("the broadcast self-delivers within the timeout")
            .expect("subscription still live");
        assert_eq!(
            &received.payload[..],
            payload.as_slice(),
            "the boot broadcast publishes the fetched manifest's payload"
        );
        let digest = release_manifest_payload_digest(&payload);
        {
            let mut recorded = tracker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                recorded.contains_recent_digest(&digest, Instant::now()),
                "the broadcast records its payload: no rebroadcast of published bytes"
            );
            assert!(
                !recorded.recorded_by_apply_route(&digest, Instant::now()),
                "the boot broadcast is not apply-route owned: its echo still reaches the owner"
            );
        }
        agent.shutdown().await;
    }

    /// The boot broadcast's eligibility gate: a manifest outside the
    /// timestamp window is neither published nor recorded.
    #[tokio::test]
    async fn startup_broadcast_skips_an_ineligible_manifest() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let mut release_topic = agent
            .subscribe(RELEASE_TOPIC)
            .await
            .expect("release topic subscription");
        let tracker = Arc::new(StdMutex::new(SelfPublishedReleaseManifests::default()));

        let mut manifest = manifest_for_this_platform(x0x::VERSION);
        manifest.timestamp = 0;
        let manifest_json = serde_json::to_vec(&manifest).expect("manifest fixture");
        let payload = x0x::upgrade::manifest::encode_signed_manifest(&manifest_json, b"announce");
        let digest = release_manifest_payload_digest(&payload);
        let verified = VerifiedRelease {
            manifest,
            manifest_json,
            signature: b"announce".to_vec(),
            gossip_payload: payload,
        };
        let _feed = broadcast_feed_seam::install(Ok(Some(verified)));

        broadcast_current_manifest(
            &agent,
            "saorsa-labs/x0x",
            false,
            dir.path(),
            Arc::clone(&tracker),
        )
        .await;

        assert!(
            tokio::time::timeout(Duration::from_millis(200), release_topic.recv())
                .await
                .is_err(),
            "an ineligible manifest is not published"
        );
        assert!(!tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_recent_digest(&digest, Instant::now()));
        agent.shutdown().await;
    }

    async fn upgrade_route_state(agent: Arc<Agent>, data_dir: &std::path::Path) -> Arc<AppState> {
        super::super::named_groups::tests::secure_endpoint_test_state_at_with_self_update(
            data_dir, agent, true,
        )
        .await
        .expect("upgrade route state")
    }

    async fn route_response_json(
        response: axum::response::Response,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("response body");
        (
            parts.status,
            serde_json::from_slice(&bytes).expect("response json"),
        )
    }

    async fn diagnostics_json(state: &Arc<AppState>) -> serde_json::Value {
        let response = super::super::network::upgrade_diagnostics(State(Arc::clone(state)))
            .await
            .into_response();
        let (status, body) = route_response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// #1381: `GET /diagnostics/upgrade` reports the channel, the highest
    /// verified version seen on the release topic, the last check and the
    /// pending update. Before anything is observed the fields are present
    /// and null; the background owner's selected release wins over a
    /// sighting.
    #[tokio::test]
    async fn upgrade_diagnostics_reports_topic_check_and_pending_update() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = upgrade_route_state(Arc::clone(&agent), dir.path()).await;

        let body = diagnostics_json(&state).await;
        assert_eq!(body["channel"], "stable", "{body}");
        for field in [
            "latest_release_topic_version",
            "last_check",
            "pending_update",
        ] {
            assert_eq!(
                body.get(field),
                Some(&serde_json::Value::Null),
                "{field} is present and null before anything is observed: {body}"
            );
        }

        let newer = version_newer_than_current();
        observe_upgrade(&state.upgrade_observations, |record| {
            record.record_topic_release(&newer, 1_700_000_000);
            record.record_check(
                ReleaseCheckSource::FallbackPoll,
                ReleaseCheckOutcome::UpToDate,
                1_700_000_100,
            );
        });
        let body = diagnostics_json(&state).await;
        assert_eq!(
            body["latest_release_topic_version"],
            serde_json::json!({ "version": newer, "seen_at_unix": 1_700_000_000u64 })
        );
        assert_eq!(
            body["last_check"],
            serde_json::json!({
                "source": "fallback_poll",
                "at_unix": 1_700_000_100u64,
                "outcome": "up_to_date",
                "version": null,
            })
        );
        assert_eq!(
            body["pending_update"],
            serde_json::json!({ "version": newer, "state": "observed", "source": "release_topic" })
        );

        let submit = BackgroundSubmit::default();
        let queued = submittable_release(&newer);
        assert_eq!(
            submit.submit(queued).expect("queued"),
            SubmitOutcome::Accepted
        );
        assert!(state.background_submit.set(submit).is_ok());
        let body = diagnostics_json(&state).await;
        assert_eq!(
            body["pending_update"],
            serde_json::json!({ "version": newer, "state": "queued", "source": "background_owner" })
        );

        agent.shutdown().await;
    }

    /// #1381: the topic record keeps the highest verified version; an
    /// older release seen later does not replace it.
    #[tokio::test]
    async fn topic_observation_keeps_the_highest_verified_version() {
        let mut higher = semver::Version::parse(x0x::VERSION).expect("semver");
        higher.minor += 1;
        let higher = higher.to_string();
        let lower = version_newer_than_current();
        let observations = Arc::new(std::sync::Mutex::new(UpgradeObservations::default()));
        let seen: Vec<_> = observe_topic_releases(
            futures::stream::iter([
                verified_release_with_version(&higher),
                verified_release_with_version(&lower),
            ]),
            Arc::clone(&observations),
        )
        .collect()
        .await;
        assert_eq!(seen.len(), 2, "observation passes every release on");
        let json = observations
            .lock()
            .expect("observations")
            .diagnostics_json(x0x::VERSION, None);
        assert_eq!(json["latest_release_topic_version"]["version"], higher);
        assert_eq!(json["pending_update"]["version"], higher);
    }

    /// #1381: a `GET /upgrade` check that reaches the monitor records its
    /// result; the cached answer that follows records nothing new.
    #[tokio::test]
    async fn upgrade_check_records_the_last_check() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = upgrade_route_state(Arc::clone(&agent), dir.path()).await;
        let expected = version_newer_than_current();
        let _feed =
            upgrade_check_feed_seam::install(Some(verified_release_with_version(&expected)));
        let (status, _) = route_response_json(check_upgrade(State(Arc::clone(&state))).await).await;
        assert_eq!(status, StatusCode::OK);

        let body = diagnostics_json(&state).await;
        assert_eq!(body["last_check"]["source"], "api", "{body}");
        assert_eq!(body["last_check"]["outcome"], "update_available");
        assert_eq!(body["last_check"]["version"], serde_json::json!(expected));
        assert_eq!(body["pending_update"]["source"], "api");
        assert!(
            body["latest_release_topic_version"].is_null(),
            "a check is not a topic sighting: {body}"
        );
        agent.shutdown().await;
    }

    /// #1381: the background owner reports its release while it has work
    /// for it and nothing once it has none.
    #[test]
    fn background_status_follows_the_slot() {
        let submit = BackgroundSubmit::default();
        assert_eq!(submit.status(), None);
        let version = version_newer_than_current();
        submit
            .submit(submittable_release(&version))
            .expect("queued");
        assert_eq!(
            submit.status().map(|status| (status.version, status.state)),
            Some((version.clone(), "queued"))
        );
        {
            let mut slot = submit.slot.lock().expect("slot");
            slot.pending = false;
            slot.failed_at = Some(Instant::now());
        }
        assert_eq!(submit.status().map(|status| status.state), Some("backoff"));
        submit.slot.lock().expect("slot").failed_at = None;
        assert_eq!(submit.status(), None, "nothing left for the release");
    }

    /// Engineer ruling 3 Nov 2026 17:40 GMT: GET /upgrade is a read-only
    /// check and must never publish the release it observes — gossip
    /// self-delivery would feed this node's own apply owner, a background
    /// install from a read. The self-update flag is on (it armed the
    /// removed announce), and a publish attempt would show in both the
    /// pubsub publish counter and on the topic itself. Fails when the
    /// removed announce block is present; passes when the check answers
    /// and caches only.
    #[tokio::test]
    async fn upgrade_check_finding_a_release_publishes_nothing() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = upgrade_route_state(Arc::clone(&agent), dir.path()).await;
        let mut release_topic = agent
            .subscribe(RELEASE_TOPIC)
            .await
            .expect("release topic subscription");
        let pubsub = agent
            .gossip_runtime
            .as_ref()
            .expect("loopback gossip runtime")
            .pubsub();
        let publishes_before = pubsub.stats().publish_total;

        let expected = version_newer_than_current();
        let _feed =
            upgrade_check_feed_seam::install(Some(verified_release_with_version(&expected)));
        let (status, body) =
            route_response_json(check_upgrade(State(Arc::clone(&state))).await).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["update_available"], serde_json::json!(true));
        assert_eq!(body["version"], serde_json::json!(expected));
        assert!(
            state.upgrade_check_cache.lock().await.is_some(),
            "the check still answers and caches normally: {body}"
        );
        assert_eq!(
            pubsub.stats().publish_total,
            publishes_before,
            "the read-only check must not publish the release it observes"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), release_topic.recv())
                .await
                .is_err(),
            "nothing may self-deliver on the release topic from a check"
        );
    }

    /// A fake install with one probe record in `phase` for `version`.
    #[cfg(unix)]
    fn install_with_probe_record(
        dir: &std::path::Path,
        version: &str,
        phase: crate::upgrade::probe::ProbePhase,
        cause: crate::upgrade::probe::ProbeCause,
    ) -> PathBuf {
        let install = dir.join("x0xd");
        std::fs::write(&install, b"installed daemon").expect("install fixture");
        let install = install.canonicalize().expect("canonical install");
        let state = crate::upgrade::probe::ProbeState {
            schema_version: 1,
            record_kind: "probe".into(),
            install: install.clone(),
            version: version.into(),
            platform: "test-platform".into(),
            archive_sha256: [7; 32],
            transaction_id: uuid::Uuid::new_v4().to_string(),
            attempt: 1,
            phase,
            cause: Some(cause),
            last_pid: None,
            boot_id: "test-boot".into(),
            retry_remaining_ms: 0,
            retry_deadline_ms: 0,
            daemon_sha256: None,
            cli_sha256: None,
        };
        crate::upgrade::journal::write_auxiliary_record(
            &crate::upgrade::probe::state_path(&install).expect("state path"),
            &state,
            |_| Ok(()),
        )
        .expect("probe record fixture");
        install
    }

    // #1376 / D190: an authenticated local clear removes a failed-release
    // hold for exactly that version, records a durable receipt, and the
    // held release is admitted again.
    #[cfg(unix)]
    #[tokio::test]
    async fn clear_upgrade_hold_route_records_and_removes_a_failed_hold() {
        use crate::upgrade::probe::{self, Admission, ProbeCause, ProbePhase};
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = upgrade_route_state(Arc::clone(&agent), dir.path()).await;
        let install = install_with_probe_record(
            dir.path(),
            "9.9.9",
            ProbePhase::FailedHold,
            ProbeCause::VersionMismatch,
        );
        let _install = crate::upgrade::apply::current_binary_path_seam::install(install.clone());
        assert!(
            matches!(
                probe::inspect_admission(&install, "9.9.9"),
                Err(probe::ProbeRefusal::Held { .. })
            ),
            "fixture: the release starts held"
        );

        let clear = |version: &str| {
            clear_upgrade_hold(
                State(Arc::clone(&state)),
                Query(UpgradeClearHoldQuery {
                    version: Some(version.into()),
                }),
            )
        };
        let (status, body) = route_response_json(clear("9.9.8").await).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "another version: {body}");
        assert!(probe::read_state(&install).expect("read").is_some());

        let (status, body) = route_response_json(clear("9.9.9").await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cleared"], serde_json::json!(true));
        assert_eq!(body["cause"], serde_json::json!("version_mismatch"));
        assert!(
            probe::read_state(&install).expect("read").is_none(),
            "the hold record is removed"
        );
        let receipt: probe::HoldClearReceipt = serde_json::from_slice(
            &crate::upgrade::journal::read_auxiliary_record(
                &probe::clear_receipt_path(&install).expect("receipt path"),
            )
            .expect("durable receipt"),
        )
        .expect("receipt decodes");
        assert_eq!(receipt.version, "9.9.9");
        assert_eq!(receipt.cause, ProbeCause::VersionMismatch);
        assert_eq!(
            probe::inspect_admission(&install, "9.9.9").expect("admitted"),
            Admission::Ready
        );

        let (status, body) = route_response_json(clear("9.9.9").await).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a repeat finds no hold: {body}"
        );
        let (status, _) = route_response_json(clear("not-a-version").await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // D190: recovery-failed is never cleared by the local route; the record
    // stays and admission still refuses.
    #[cfg(unix)]
    #[tokio::test]
    async fn clear_upgrade_hold_route_never_clears_recovery_failed() {
        use crate::upgrade::probe::{self, ProbeCause, ProbePhase};
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = upgrade_route_state(Arc::clone(&agent), dir.path()).await;
        let install = install_with_probe_record(
            dir.path(),
            "9.9.9",
            ProbePhase::RecoveryFailed,
            ProbeCause::HoldWriteFailed,
        );
        let _install = crate::upgrade::apply::current_binary_path_seam::install(install.clone());

        let (status, body) = route_response_json(
            clear_upgrade_hold(
                State(Arc::clone(&state)),
                Query(UpgradeClearHoldQuery {
                    version: Some("9.9.9".into()),
                }),
            )
            .await,
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["cleared"], serde_json::json!(false));
        let kept = probe::read_state(&install)
            .expect("read")
            .expect("record kept");
        assert_eq!(kept.phase, ProbePhase::RecoveryFailed);
        assert!(!probe::clear_receipt_path(&install).expect("path").exists());
        assert!(matches!(
            probe::inspect_admission(&install, "9.9.9"),
            Err(probe::ProbeRefusal::RecoveryFailed { .. })
        ));
    }

    /// The apply path is the one announcing route: an explicit owner
    /// action announces before its apply work (the 17:40 GMT ruling keeps
    /// it; the read-only check lost its announce). The apply itself
    /// refuses fast here — the test state carries no staging identity —
    /// which also keeps the test hermetic: no archive download, and the
    /// probe retry never starts because the install path is pointed at
    /// nothing. Because that apply does not succeed, the route releases
    /// its apply-route claim again; the echo-suppression window while the
    /// apply runs and the resubmission after the release are pinned by
    /// the driver-level tests and
    /// `a_failed_apply_route_releases_the_release_to_the_background_owner`.
    /// Unix-gated like the staging apply suites it leans on
    /// (`current_binary_path_seam` and the staging refusal are unix-only
    /// test surface).
    #[cfg(unix)]
    #[tokio::test]
    async fn apply_upgrade_announces_the_release_it_applies() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let state = upgrade_route_state(Arc::clone(&agent), dir.path()).await;
        let mut release_topic = agent
            .subscribe(RELEASE_TOPIC)
            .await
            .expect("release topic subscription");
        let pubsub = agent
            .gossip_runtime
            .as_ref()
            .expect("loopback gossip runtime")
            .pubsub();
        let publishes_before = pubsub.stats().publish_total;
        let _no_install =
            crate::upgrade::apply::current_binary_path_seam::install(dir.path().join("no-binary"));

        let verified = verified_release_with_version(&version_newer_than_current());
        let expected_payload = verified.gossip_payload.clone();
        let _feed = upgrade_check_feed_seam::install(Some(verified));
        let (status, body) = route_response_json(
            apply_upgrade(State(Arc::clone(&state)), Query(Default::default()))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["applied"], serde_json::json!(false));
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("staging")),
            "the refusal is the fast staging-unavailable one: {body}"
        );
        assert_eq!(
            pubsub.stats().publish_total,
            publishes_before + 1,
            "the announcing route publishes exactly once before its apply work"
        );
        let received = tokio::time::timeout(Duration::from_secs(5), release_topic.recv())
            .await
            .expect("the announcement self-delivers within the timeout")
            .expect("subscription still live");
        assert_eq!(
            &received.payload[..],
            expected_payload.as_slice(),
            "the announced payload is the verified gossip payload"
        );
        let mut tracker = state
            .self_published_release_manifests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let digest = release_manifest_payload_digest(&expected_payload);
        assert!(
            tracker.contains_recent_digest(&digest, Instant::now()),
            "the route records its announcement, so those bytes are not rebroadcast"
        );
        assert!(
            !tracker.recorded_by_apply_route(&digest, Instant::now()),
            "a failed apply with no retry to resume releases the claim, so gossip copies still reach the background owner"
        );
    }

    /// The mechanism behind the ruling: a node that publishes an
    /// announcement on the release topic receives its own publication back
    /// (gossip self-delivery), and its listener would feed that payload to
    /// the node's own apply owner — why the read-only /upgrade check must
    /// not announce. The publish below is the announce helper's, through a
    /// real loopback gossip runtime; no peers, no testnet.
    #[tokio::test]
    async fn observed_release_announcement_self_delivers_to_the_publishing_node() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = loopback_gossip_agent(dir.path()).await;
        let mut release_topic = agent
            .subscribe(RELEASE_TOPIC)
            .await
            .expect("release topic subscription");

        let verified = verified_release_with_version(&version_newer_than_current());
        let expected_payload = verified.gossip_payload.clone();
        let publishing_agent = Arc::clone(&agent);
        announce_observed_release(&verified, move |payload| async move {
            publishing_agent
                .publish(RELEASE_TOPIC, payload)
                .await
                .map_err(|error| error.to_string())
        })
        .await;

        let received = tokio::time::timeout(Duration::from_secs(5), release_topic.recv())
            .await
            .expect("self-delivery within the timeout")
            .expect("subscription still live");
        assert_eq!(
            &received.payload[..],
            expected_payload.as_slice(),
            "the publishing node receives its own announcement back"
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
            channel: "stable".into(),
            version: version.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs(),
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
                observations: None,
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
        let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(
            move |_plan, manifest, _admission| {
                hook_attempts.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success {
                    version: manifest.version.clone(),
                }
            },
        ));

        let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
            manifest: manifest_for_this_platform("9.9.9"),
            manifest_json: Vec::new(),
            signature: Vec::new(),
            gossip_payload: Vec::new(),
        });

        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, Some(runtime)).await;

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
        let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(
            move |_plan, manifest, _admission| {
                hook_attempts.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success {
                    version: manifest.version.clone(),
                }
            },
        ));
        let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
            manifest: manifest_for_this_platform("9.9.9"),
            manifest_json: Vec::new(),
            signature: Vec::new(),
            gossip_payload: Vec::new(),
        });

        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, Some(runtime)).await;
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
        let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(
            move |_plan, manifest, _admission| {
                hook_attempts.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success {
                    version: manifest.version.clone(),
                }
            },
        ));
        let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
            manifest: manifest_for_this_platform("9.9.9"),
            manifest_json: Vec::new(),
            signature: Vec::new(),
            gossip_payload: Vec::new(),
        });

        let before = tokio::time::Instant::now();
        let result = run_startup_update_check(&config, Some(runtime)).await;
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
