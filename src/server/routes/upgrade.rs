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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use x0x::upgrade::manifest::{decode_signed_manifest, is_newer, ReleaseManifest, RELEASE_TOPIC};
use x0x::upgrade::monitor::UpgradeMonitor;
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

/// Startup GitHub check. Returns Some(version) if an update was applied.
pub(in crate::server) async fn run_startup_update_check(
    config: &DaemonConfig,
    agent: Option<&Arc<Agent>>,
) -> Result<Option<String>> {
    let monitor = UpgradeMonitor::new(&config.update.repo, "x0xd", x0x::VERSION)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_include_prereleases(config.update.include_prereleases);

    let Some(verified) = monitor
        .check_for_updates()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        return Ok(None);
    };

    tracing::info!(
        new_version = %verified.manifest.version,
        "Startup check: new version available, applying immediately"
    );

    // Update SKILL.md before upgrading (independent of binary update)
    update_skill_if_changed(&verified.manifest, &config.data_dir).await;

    // Broadcast to gossip so other nodes benefit from our discovery
    if let Some(agent) = agent {
        if let Err(e) = agent
            .publish(RELEASE_TOPIC, verified.gossip_payload.clone())
            .await
        {
            tracing::debug!(error = %e, "Failed to broadcast discovered release: {e}");
        }
    }

    let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(config.update.stop_on_upgrade);

    match upgrader
        .apply_upgrade_from_manifest(&verified.manifest)
        .await
    {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => Ok(Some(version)),
        Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
            tracing::warn!(%reason, "Startup upgrade rolled back");
            Ok(None)
        }
        Ok(x0x::upgrade::UpgradeResult::NoUpgrade) => Ok(None),
        Err(e) => {
            tracing::error!(error = %e, "Startup upgrade failed: {e}");
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

/// Gossip-based release subscription — the primary update mechanism for x0xd.
///
/// When an upgrade attempt fails (e.g. hash mismatch), the failed version is
/// tracked so it won't block future attempts. A newer release superseding the
/// failed version will be picked up normally.
pub(in crate::server) async fn run_gossip_update_listener(
    agent: Arc<Agent>,
    config: DaemonUpdateConfig,
    data_dir: PathBuf,
    upgrade_apply_lock: Arc<Mutex<()>>,
    self_published_release_manifests: Arc<Mutex<SelfPublishedReleaseManifests>>,
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

    // Track versions that failed to *apply* so a release that can never succeed
    // in this environment (e.g. a locked binary that won't replace) is not
    // re-downloaded and re-extracted on every gossip receipt. Without this the
    // gossip path retried indefinitely — the cause of the Windows disk-fill
    // loop. Mirrors the backoff in run_fallback_github_poll.
    let mut failed_apply_versions: HashMap<String, Instant> = HashMap::new();
    const APPLY_RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

    while let Some(msg) = release_sub.recv().await {
        tracing::info!("Received release manifest via gossip");

        // Drop expired backoff entries so the map stays bounded.
        failed_apply_versions.retain(|_, failed_at| failed_at.elapsed() < APPLY_RETRY_AFTER);

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

        // Skip versions that recently failed to apply. A release that can never
        // succeed here would otherwise re-download and re-extract on every
        // gossip receipt; the backoff caps that to one attempt per 30 minutes.
        if let Some(failed_at) = failed_apply_versions.get(&manifest.version) {
            if failed_at.elapsed() < APPLY_RETRY_AFTER {
                tracing::debug!(
                    version = %manifest.version,
                    "Skipping recently failed upgrade v{} (apply backoff active)",
                    manifest.version
                );
                continue;
            }
        }

        tracing::info!(
            version = %manifest.version,
            "Applying upgrade immediately"
        );

        let _upgrade_guard = upgrade_apply_lock.lock().await;
        let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
            .with_stop_on_upgrade(config.stop_on_upgrade);
        match upgrader.apply_upgrade_from_manifest(&manifest).await {
            Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
                tracing::info!(%version, "Successfully upgraded to version {version}");
            }
            Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
                tracing::warn!(%reason, "Upgrade rolled back");
                failed_apply_versions.insert(manifest.version.clone(), Instant::now());
            }
            Err(e) => {
                tracing::error!(error = %e, "Upgrade failed: {e}");
                failed_apply_versions.insert(manifest.version.clone(), Instant::now());
            }
            _ => {}
        }
    }
}

/// Background GitHub fallback poll (safety net, every 48h by default).
/// Also broadcasts discovered manifests to gossip and syncs SKILL.md.
///
/// Tracks versions that failed to apply (e.g. due to hash mismatch) and skips
/// them for 30 minutes before retrying. A newer release superseding the failed
/// version will be picked up immediately.
pub(in crate::server) async fn run_fallback_github_poll(
    agent: Arc<Agent>,
    config: DaemonUpdateConfig,
    data_dir: PathBuf,
    upgrade_apply_lock: Arc<Mutex<()>>,
    self_published_release_manifests: Arc<Mutex<SelfPublishedReleaseManifests>>,
) {
    let interval = Duration::from_secs(config.fallback_check_interval_minutes * 60);
    let mut ticker = tokio::time::interval(interval);
    // Skip first tick (startup check already ran)
    ticker.tick().await;

    let mut failed_version: Option<(String, Instant)> = None;
    const RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

    loop {
        ticker.tick().await;
        tracing::debug!("Fallback GitHub check");

        // Clear expired failure skip
        if let Some((_, failed_at)) = &failed_version {
            if failed_at.elapsed() >= RETRY_AFTER {
                tracing::info!("Retry timeout elapsed, clearing failed version skip");
                failed_version = None;
            }
        }

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
                if let Some((ref ver, _)) = failed_version {
                    if ver == &verified.manifest.version {
                        tracing::debug!(
                            version = %verified.manifest.version,
                            "Skipping recently failed version {}",
                            verified.manifest.version
                        );
                        continue;
                    }
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

                let _upgrade_guard = upgrade_apply_lock.lock().await;
                let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
                    .with_stop_on_upgrade(config.stop_on_upgrade);
                match upgrader
                    .apply_upgrade_from_manifest(&verified.manifest)
                    .await
                {
                    Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
                        tracing::info!(%version, "Fallback upgrade successful");
                    }
                    Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
                        tracing::warn!(%reason, "Fallback upgrade rolled back");
                        failed_version = Some((verified.manifest.version.clone(), Instant::now()));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Fallback upgrade failed: {e}");
                        failed_version = Some((verified.manifest.version.clone(), Instant::now()));
                    }
                    _ => {}
                }
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
                if let Err(e) = tokio::fs::write(&skill_path, &new_contents).await {
                    tracing::warn!(error = %e, "Failed to write SKILL.md");
                } else {
                    tracing::info!("SKILL.md updated successfully");
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
                "reason": "self-update disabled for embedded server",
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
    let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
        .with_stop_on_upgrade(stop_on_upgrade)
        .with_restart_on_success(false);

    match upgrader
        .apply_upgrade_from_manifest(&release.manifest)
        .await
    {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
            schedule_restart_after_response(stop_on_upgrade);
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

fn schedule_restart_after_response(stop_on_upgrade: bool) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(750)).await;
        let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
            .with_stop_on_upgrade(stop_on_upgrade);
        if let Err(e) = upgrader.restart_current_binary() {
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
}
