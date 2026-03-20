//! x0xd — local agent daemon for the x0x gossip network.
//!
//! Runs a persistent x0x agent with a REST API for local control.
//! Designed to be started once and left running; external tools
//! (CLI, Fae, scripts) interact through the HTTP endpoints.
//!
//! ## Usage
//!
//! ```bash
//! x0xd                                  # default config
//! x0xd --config /path/to/config.toml    # custom config
//! x0xd --check                          # validate config and exit
//! x0xd --check-updates                  # check/apply updates and exit
//! x0xd --skip-update-check              # start daemon without startup update check
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
use x0x::contacts::{ContactStore, TrustLevel};
use x0x::identity::AgentId;
use x0x::network::NetworkConfig;
use x0x::upgrade::manifest::{decode_signed_manifest, is_newer, ReleaseManifest, RELEASE_TOPIC};
use x0x::upgrade::monitor::UpgradeMonitor;
use x0x::upgrade::signature::verify_manifest_signature;
use x0x::{Agent, Subscription, TaskListHandle};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Daemon configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonConfig {
    /// QUIC bind address for gossip (default 0.0.0.0:0 = random).
    #[serde(default = "default_bind_address")]
    bind_address: SocketAddr,

    /// HTTP API address (default 127.0.0.1:12700).
    #[serde(default = "default_api_address")]
    api_address: SocketAddr,

    /// Data directory for persistent storage.
    #[serde(default = "default_data_dir")]
    data_dir: PathBuf,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    log_level: String,

    /// Log format ("text" or "json").
    #[serde(default = "default_log_format")]
    log_format: String,

    /// Bootstrap peers to connect on startup.
    #[serde(default)]
    bootstrap_peers: Vec<SocketAddr>,

    /// Update configuration.
    #[serde(default)]
    update: DaemonUpdateConfig,

    /// How often to re-announce identity (seconds).
    #[serde(default = "default_heartbeat_interval")]
    heartbeat_interval_secs: u64,

    /// How long before a discovered agent entry is considered stale (seconds).
    #[serde(default = "default_identity_ttl")]
    identity_ttl_secs: u64,

    /// Optional path to a user keypair file for human identity.
    /// When set, the agent can announce with `include_user_identity: true`.
    #[serde(default)]
    user_key_path: Option<PathBuf>,

    /// Enable rendezvous `ProviderSummary` advertisements for global findability.
    #[serde(default = "default_rendezvous_enabled")]
    rendezvous_enabled: bool,

    /// Validity period (milliseconds) for each rendezvous advertisement.
    /// The daemon re-advertises every `validity_ms / 2` so that the record
    /// is always fresh before it expires.
    #[serde(default = "default_rendezvous_validity_ms")]
    rendezvous_validity_ms: u64,
}

fn default_bind_address() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

fn default_api_address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 12700))
}

fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("x0x"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/x0x"))
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

/// Update configuration for x0xd daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonUpdateConfig {
    /// Enable listening for release manifests via gossip and the GitHub fallback poll.
    #[serde(default = "default_true")]
    enabled: bool,

    /// Maximum rollout window in minutes. Default: 1440 (24 hours).
    #[serde(default = "default_rollout_window_minutes")]
    rollout_window_minutes: u64,

    /// Exit cleanly for service manager restart instead of spawning.
    #[serde(default)]
    stop_on_upgrade: bool,

    /// GitHub fallback poll interval in minutes. Default: 2880 (48 hours).
    /// Set to 0 to disable the fallback entirely (gossip-only mode).
    #[serde(default = "default_fallback_check_interval_minutes")]
    fallback_check_interval_minutes: u64,

    /// GitHub repo for update discovery.
    #[serde(default = "default_update_repo")]
    repo: String,

    /// Include pre-releases in update checks (default: false).
    #[serde(default)]
    include_prereleases: bool,

    /// Enable gossip-based release manifest propagation (default: true).
    /// Set to false to only use the GitHub fallback poll.
    #[serde(default = "default_true")]
    gossip_updates: bool,
}

impl Default for DaemonUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rollout_window_minutes: 1440,
            stop_on_upgrade: false,
            fallback_check_interval_minutes: 2880,
            repo: default_update_repo(),
            include_prereleases: false,
            gossip_updates: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_rollout_window_minutes() -> u64 {
    1440
}

fn default_fallback_check_interval_minutes() -> u64 {
    2880
}

fn default_update_repo() -> String {
    "saorsa-labs/x0x".to_string()
}

fn default_heartbeat_interval() -> u64 {
    x0x::IDENTITY_HEARTBEAT_INTERVAL_SECS
}

fn default_identity_ttl() -> u64 {
    x0x::IDENTITY_TTL_SECS
}

fn default_rendezvous_enabled() -> bool {
    true
}

fn default_rendezvous_validity_ms() -> u64 {
    3_600_000 // 1 hour
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            api_address: default_api_address(),
            data_dir: default_data_dir(),
            log_level: default_log_level(),
            log_format: default_log_format(),
            bootstrap_peers: x0x::network::DEFAULT_BOOTSTRAP_PEERS
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            update: DaemonUpdateConfig::default(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            identity_ttl_secs: default_identity_ttl(),
            user_key_path: None,
            rendezvous_enabled: default_rendezvous_enabled(),
            rendezvous_validity_ms: default_rendezvous_validity_ms(),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// SSE event broadcast to connected clients.
#[derive(Debug, Clone, Serialize)]
struct SseEvent {
    /// Event type: "message", "peer:connected", "peer:disconnected".
    #[serde(rename = "type")]
    event_type: String,
    /// Event payload (JSON value).
    data: serde_json::Value,
}

/// Shared state accessible from all route handlers.
struct AppState {
    agent: Arc<Agent>,
    subscriptions: RwLock<HashMap<String, Subscription>>,
    task_lists: RwLock<HashMap<String, TaskListHandle>>,
    contacts: Arc<RwLock<ContactStore>>,
    start_time: Instant,
    broadcast_tx: broadcast::Sender<SseEvent>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// POST /publish request body.
#[derive(Debug, Deserialize)]
struct PublishRequest {
    topic: String,
    /// Base64-encoded payload.
    payload: String,
}

/// POST /subscribe request body.
#[derive(Debug, Deserialize)]
struct SubscribeRequest {
    topic: String,
}

/// POST /announce request body.
#[derive(Debug, Deserialize)]
struct AnnounceIdentityRequest {
    #[serde(default)]
    include_user_identity: bool,
    #[serde(default)]
    human_consent: bool,
}

/// POST /task-lists request body.
#[derive(Debug, Deserialize)]
struct CreateTaskListRequest {
    name: String,
    topic: String,
}

/// POST /task-lists/:id/tasks request body.
#[derive(Debug, Deserialize)]
struct AddTaskRequest {
    title: String,
    description: String,
}

/// PATCH /task-lists/:id/tasks/:tid request body.
#[derive(Debug, Deserialize)]
struct UpdateTaskRequest {
    action: String, // "claim" or "complete"
}

/// POST /contacts request body.
#[derive(Debug, Deserialize)]
struct AddContactRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
    /// Trust level: "blocked", "unknown", "known", or "trusted".
    trust_level: String,
    /// Optional human-readable label.
    label: Option<String>,
}

/// PATCH /contacts/:agent_id request body.
#[derive(Debug, Deserialize)]
struct UpdateContactRequest {
    /// New trust level: "blocked", "unknown", "known", or "trusted".
    trust_level: String,
}

/// POST /contacts/trust request body (quick trust shorthand).
#[derive(Debug, Deserialize)]
struct QuickTrustRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
    /// Trust level: "blocked", "unknown", "known", or "trusted".
    level: String,
}

/// Contact entry for API responses.
#[derive(Debug, Serialize)]
struct ContactEntry {
    agent_id: String,
    trust_level: String,
    label: Option<String>,
    added_at: u64,
    last_seen: Option<u64>,
}

/// Generic JSON response wrapper.
#[derive(Debug, Serialize)]
struct ApiResponse<T: Serialize> {
    ok: bool,
    #[serde(flatten)]
    data: T,
}

/// Health response.
#[derive(Debug, Serialize)]
struct HealthData {
    status: String,
    version: String,
    peers: usize,
    uptime_secs: u64,
}

/// Agent identity response.
#[derive(Debug, Serialize)]
struct AgentData {
    agent_id: String,
    machine_id: String,
    user_id: Option<String>,
}

/// Discovered identity entry from gossip announcements.
#[derive(Debug, Serialize)]
struct DiscoveredAgentEntry {
    agent_id: String,
    machine_id: String,
    user_id: Option<String>,
    addresses: Vec<String>,
    announced_at: u64,
    last_seen: u64,
}

/// Peer entry.
#[derive(Debug, Serialize)]
struct PeerEntry {
    id: String,
}

/// Task list entry.
#[derive(Debug, Serialize)]
struct TaskListEntry {
    id: String,
    topic: String,
}

/// Task snapshot for API response.
#[derive(Debug, Serialize)]
struct TaskEntry {
    id: String,
    title: String,
    description: String,
    state: String,
    assignee: Option<String>,
    priority: u8,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let config_path = if let Some(idx) = args.iter().position(|a| a == "--config") {
        Some(
            args.get(idx + 1)
                .context("--config requires a path argument")?
                .clone(),
        )
    } else {
        None
    };

    let check_only = args.contains(&"--check".to_string());
    let check_updates_only = args.contains(&"--check-updates".to_string());
    let skip_update_check = args.contains(&"--skip-update-check".to_string());

    let config = match &config_path {
        Some(path) => load_config(path).await?,
        None => {
            // Try default path, fall back to default config
            let default_path = dirs::config_dir()
                .map(|d| d.join("x0x").join("config.toml"))
                .unwrap_or_else(|| PathBuf::from("/etc/x0x/config.toml"));
            if default_path.exists() {
                load_config(default_path.to_str().unwrap_or("/etc/x0x/config.toml")).await?
            } else {
                DaemonConfig::default()
            }
        }
    };

    init_logging(&config.log_level, &config.log_format)?;

    if check_only {
        println!("Configuration is valid");
        println!("{:#?}", config);
        return Ok(());
    }

    // Ensure data directory exists early so self-update has a working directory.
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .context("failed to create data directory")?;

    // Startup banner
    tracing::info!(
        version = %x0x::VERSION,
        binary = "x0xd",
        pid = std::process::id(),
        "x0xd started"
    );

    // Startup GitHub check (fallback mechanism — gossip is primary)
    if config.update.enabled && !skip_update_check {
        match run_startup_update_check(&config, None).await {
            Ok(Some(version)) => {
                if check_updates_only {
                    println!("x0xd updated to {version}");
                    return Ok(());
                }
            }
            Ok(None) => {
                if check_updates_only {
                    println!("x0xd is up to date ({})", x0x::VERSION);
                    return Ok(());
                }
            }
            Err(e) => {
                if check_updates_only {
                    return Err(e).context("self-update check failed");
                }
                tracing::warn!(error = %e, "Startup update check failed: {e}");
            }
        }
    } else if check_updates_only {
        if !config.update.enabled {
            println!("self-update checks are disabled by configuration");
        } else {
            println!("self-update check skipped by --skip-update-check");
        }
        return Ok(());
    }

    tracing::info!("Starting x0xd v{}", x0x::VERSION);
    tracing::info!("API address: {}", config.api_address);
    tracing::info!("Bind address: {}", config.bind_address);

    // Create agent
    let network_config = NetworkConfig {
        bind_addr: Some(config.bind_address),
        bootstrap_nodes: config.bootstrap_peers.clone(),
        max_connections: 50,
        connection_timeout: std::time::Duration::from_secs(30),
        stats_interval: std::time::Duration::from_secs(60),
        peer_cache_path: Some(config.data_dir.join("peers.cache")),
    };

    let mut builder = Agent::builder()
        .with_network_config(network_config)
        .with_peer_cache_dir(config.data_dir.join("peers"))
        .with_heartbeat_interval(config.heartbeat_interval_secs)
        .with_identity_ttl(config.identity_ttl_secs);

    if let Some(ref user_key_path) = config.user_key_path {
        builder = builder.with_user_key_path(user_key_path);
        tracing::info!("User key path: {}", user_key_path.display());
    }

    let agent = builder.build().await.context("failed to create agent")?;

    tracing::info!("Agent ID: {}", agent.agent_id());
    tracing::info!("Machine ID: {}", agent.machine_id());
    if let Some(uid) = agent.user_id() {
        tracing::info!("User ID: {}", uid);
    }

    // Create contact store and attach to gossip layer for trust filtering
    let contacts = Arc::new(RwLock::new(ContactStore::new(
        config.data_dir.join("contacts.json"),
    )));
    agent.set_contacts(Arc::clone(&contacts));
    tracing::info!(
        "Contact store loaded from {}",
        config.data_dir.join("contacts.json").display()
    );

    // Join network
    agent
        .join_network()
        .await
        .context("failed to join network")?;

    tracing::info!("Network joined");

    // Initial rendezvous advertisement (if enabled)
    if config.rendezvous_enabled {
        if let Err(e) = agent
            .advertise_identity(config.rendezvous_validity_ms)
            .await
        {
            tracing::warn!("Initial rendezvous advertisement failed: {e}");
        } else {
            tracing::info!("Rendezvous advertisement published");
        }
    }

    // Build shared state
    let (broadcast_tx, _) = broadcast::channel::<SseEvent>(256);
    let state = Arc::new(AppState {
        agent: Arc::new(agent),
        subscriptions: RwLock::new(HashMap::new()),
        task_lists: RwLock::new(HashMap::new()),
        contacts,
        start_time: Instant::now(),
        broadcast_tx,
    });

    // Gossip-based release subscription (primary update mechanism)
    if config.update.enabled && config.update.gossip_updates {
        let update_config = config.update.clone();
        let agent_for_gossip = Arc::clone(&state.agent);
        let data_dir = config.data_dir.clone();
        tokio::spawn(async move {
            run_gossip_update_listener(agent_for_gossip, update_config, data_dir).await;
        });
    }

    // Broadcast current manifest to gossip after joining the network.
    // Ensures nodes that missed the initial gossip window can still receive it.
    // Also syncs SKILL.md with the current manifest.
    if config.update.enabled {
        let agent_for_broadcast = Arc::clone(&state.agent);
        let update_config = config.update.clone();
        let data_dir_for_broadcast = config.data_dir.clone();
        tokio::spawn(async move {
            broadcast_current_manifest(
                &agent_for_broadcast,
                &update_config.repo,
                update_config.include_prereleases,
                &data_dir_for_broadcast,
            )
            .await;
        });
    }

    // GitHub fallback poll (safety net, default every 48h)
    if config.update.enabled && config.update.fallback_check_interval_minutes > 0 {
        let update_config = config.update.clone();
        let agent_for_poll = Arc::clone(&state.agent);
        let data_dir_for_poll = config.data_dir.clone();
        tokio::spawn(async move {
            run_fallback_github_poll(agent_for_poll, update_config, data_dir_for_poll).await;
        });
    }

    // Background rendezvous re-advertisement (re-advertise every validity_ms / 2)
    if config.rendezvous_enabled && config.rendezvous_validity_ms > 0 {
        let rendezvous_agent = Arc::clone(&state.agent);
        let validity_ms = config.rendezvous_validity_ms;
        tokio::spawn(async move {
            let interval_secs = (validity_ms / 2).max(60_000) / 1000;
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.tick().await; // skip immediate tick (already advertised at startup)
            loop {
                ticker.tick().await;
                if let Err(e) = rendezvous_agent.advertise_identity(validity_ms).await {
                    tracing::warn!("Periodic rendezvous re-advertisement failed: {e}");
                } else {
                    tracing::debug!("Rendezvous re-advertisement published");
                }
            }
        });
    }

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/agent", get(agent_info))
        .route("/announce", post(announce_identity))
        .route("/peers", get(peers))
        .route("/publish", post(publish))
        .route("/subscribe", post(subscribe))
        .route("/subscribe/:id", delete(unsubscribe))
        .route("/events", get(events_sse))
        .route("/presence", get(presence))
        .route("/agents/discovered", get(discovered_agents))
        .route("/agents/discovered/:agent_id", get(discovered_agent))
        .route("/users/:user_id/agents", get(agents_by_user_handler))
        .route("/agent/user-id", get(agent_user_id_handler))
        .route("/contacts", get(list_contacts))
        .route("/contacts", post(add_contact))
        .route("/contacts/trust", post(quick_trust))
        .route("/contacts/:agent_id", patch(update_contact))
        .route("/contacts/:agent_id", delete(delete_contact))
        .route("/task-lists", get(list_task_lists))
        .route("/task-lists", post(create_task_list))
        .route("/task-lists/:id/tasks", get(list_tasks))
        .route("/task-lists/:id/tasks", post(add_task))
        .route("/task-lists/:id/tasks/:tid", patch(update_task))
        .layer(CorsLayer::permissive())
        .with_state(Arc::clone(&state));

    // Start server
    let listener = tokio::net::TcpListener::bind(config.api_address)
        .await
        .context("failed to bind API address")?;
    tracing::info!("API server listening on {}", config.api_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("API server error")?;

    state.agent.shutdown().await;
    tracing::info!("Shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    tracing::info!("Received shutdown signal");
}

// ---------------------------------------------------------------------------
// Self-update (gossip-based + GitHub fallback)
// ---------------------------------------------------------------------------

/// Startup GitHub check. Returns Some(version) if an update was applied.
async fn run_startup_update_check(
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
async fn broadcast_current_manifest(
    agent: &Agent,
    repo: &str,
    include_prereleases: bool,
    data_dir: &std::path::Path,
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
            if let Err(e) = agent.publish(RELEASE_TOPIC, verified.gossip_payload).await {
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
async fn run_gossip_update_listener(
    agent: Arc<Agent>,
    config: DaemonUpdateConfig,
    data_dir: PathBuf,
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
    const REBROADCAST_INTERVAL: Duration = Duration::from_secs(300);

    while let Some(msg) = release_sub.recv().await {
        tracing::info!("Received release manifest via gossip");

        // Decode wire format: length-prefixed manifest JSON + signature
        let (manifest_json, sig) = match decode_signed_manifest(&msg.payload) {
            Ok(parts) => parts,
            Err(e) => {
                tracing::warn!(error = %e, "Invalid manifest payload received via gossip");
                continue;
            }
        };

        // Stage 1: verify manifest signature
        if let Err(e) = verify_manifest_signature(manifest_json, sig) {
            tracing::warn!(error = %e, "Release manifest signature verification failed");
            continue;
        }

        let manifest: ReleaseManifest = match serde_json::from_slice(manifest_json) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "Invalid manifest JSON: {e}");
                continue;
            }
        };

        // Rebroadcast with time-windowed dedup: allow re-rebroadcast every 5 minutes
        // so late-connecting peers (e.g., after a peer restarts) still receive the manifest.
        let should_rebroadcast = match rebroadcasted_versions.get(&manifest.version) {
            None => true,
            Some(last) => last.elapsed() >= REBROADCAST_INTERVAL,
        };
        if should_rebroadcast {
            rebroadcasted_versions.insert(manifest.version.clone(), Instant::now());
            // Prune older versions — keep only the current to prevent
            // re-broadcast of old versions after pruning
            if rebroadcasted_versions.len() > 2 {
                let current_version = manifest.version.clone();
                let current_time = Instant::now();
                rebroadcasted_versions.clear();
                rebroadcasted_versions.insert(current_version, current_time);
            }
            tracing::info!(
                version = %manifest.version,
                "Rebroadcasting verified release manifest v{}",
                manifest.version
            );
            if let Err(e) = agent.publish(RELEASE_TOPIC, msg.payload.to_vec()).await {
                tracing::debug!(error = %e, "Failed to rebroadcast release manifest: {e}");
            }
        } else {
            tracing::debug!(
                version = %manifest.version,
                "Already rebroadcasted v{} recently, skipping",
                manifest.version
            );
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

        tracing::info!(
            version = %manifest.version,
            "Applying upgrade immediately"
        );

        let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0xd")
            .with_stop_on_upgrade(config.stop_on_upgrade);
        match upgrader.apply_upgrade_from_manifest(&manifest).await {
            Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
                tracing::info!(%version, "Successfully upgraded to version {version}");
            }
            Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
                tracing::warn!(%reason, "Upgrade rolled back");
            }
            Err(e) => {
                tracing::error!(error = %e, "Upgrade failed: {e}");
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
async fn run_fallback_github_poll(
    agent: Arc<Agent>,
    config: DaemonUpdateConfig,
    data_dir: PathBuf,
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
                tokio::spawn(async move {
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

/// GET /health
async fn health(State(state): State<Arc<AppState>>) -> Json<ApiResponse<HealthData>> {
    let peers = state.agent.peers().await.map(|p| p.len()).unwrap_or(0);

    Json(ApiResponse {
        ok: true,
        data: HealthData {
            status: "healthy".to_string(),
            version: x0x::VERSION.to_string(),
            peers,
            uptime_secs: state.start_time.elapsed().as_secs(),
        },
    })
}

/// GET /agent
async fn agent_info(State(state): State<Arc<AppState>>) -> Json<ApiResponse<AgentData>> {
    Json(ApiResponse {
        ok: true,
        data: AgentData {
            agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            machine_id: hex::encode(state.agent.machine_id().as_bytes()),
            user_id: state.agent.user_id().map(|u| hex::encode(u.as_bytes())),
        },
    })
}

/// POST /announce
async fn announce_identity(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AnnounceIdentityRequest>,
) -> impl IntoResponse {
    match state
        .agent
        .announce_identity(req.include_user_identity, req.human_consent)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "include_user_identity": req.include_user_identity,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /peers
async fn peers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.peers().await {
        Ok(peer_list) => {
            let entries: Vec<PeerEntry> = peer_list
                .into_iter()
                .map(|p| PeerEntry {
                    id: hex::encode(p.to_bytes()),
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "peers": entries })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /publish
async fn publish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishRequest>,
) -> impl IntoResponse {
    // Decode base64 payload
    let payload = match base64::engine::general_purpose::STANDARD.decode(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid base64: {e}") })),
            );
        }
    };

    match state.agent.publish(&req.topic, payload).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /subscribe
async fn subscribe(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubscribeRequest>,
) -> impl IntoResponse {
    match state.agent.subscribe(&req.topic).await {
        Ok(sub) => {
            let id = format!("{:016x}", rand::random::<u64>());
            // Spawn background task to forward messages to SSE broadcast
            let broadcast_tx = state.broadcast_tx.clone();
            let topic = req.topic.clone();
            let mut recv_sub = sub;
            let sub_id = id.clone();
            tokio::spawn(async move {
                while let Some(msg) = recv_sub.recv().await {
                    let event = SseEvent {
                        event_type: "message".to_string(),
                        data: serde_json::json!({
                            "subscription_id": sub_id,
                            "topic": topic,
                            "payload": base64::engine::general_purpose::STANDARD.encode(&msg.payload),
                            "sender": msg.sender.map(|s| hex::encode(s.0)),
                            "verified": msg.verified,
                            "trust_level": msg.trust_level.map(|t| t.to_string()),
                        }),
                    };
                    let _ = broadcast_tx.send(event);
                }
            });

            // We've consumed the subscription in the spawned task;
            // store a placeholder subscription for unsubscribe tracking.
            // (The actual unsubscribe goes through PubSubManager::unsubscribe)
            let mut subs = state.subscriptions.write().await;
            // Create a new subscription for the unsubscribe path
            match state.agent.subscribe(&req.topic).await {
                Ok(new_sub) => {
                    subs.insert(id.clone(), new_sub);
                }
                Err(_) => {
                    // Non-fatal: the forwarding task is already running
                }
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "subscription_id": id })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// DELETE /subscribe/:id
async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut subs = state.subscriptions.write().await;
    if subs.remove(&id).is_some() {
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "subscription not found" })),
        )
    }
}

/// GET /events — Server-Sent Events stream.
async fn events_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.broadcast_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let data = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().event(event.event_type).data(data)))
        }
        Err(_) => None,
    });
    Sse::new(stream)
}

/// GET /presence
async fn presence(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.presence().await {
        Ok(agents) => {
            let entries: Vec<String> = agents.iter().map(|a| hex::encode(a.as_bytes())).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

fn discovered_agent_entry(agent: x0x::DiscoveredAgent) -> DiscoveredAgentEntry {
    DiscoveredAgentEntry {
        agent_id: hex::encode(agent.agent_id.as_bytes()),
        machine_id: hex::encode(agent.machine_id.as_bytes()),
        user_id: agent.user_id.map(|id| hex::encode(id.as_bytes())),
        addresses: agent.addresses.into_iter().map(|a| a.to_string()).collect(),
        announced_at: agent.announced_at,
        last_seen: agent.last_seen,
    }
}

/// GET /agents/discovered
async fn discovered_agents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.discovered_agents().await {
        Ok(agents) => {
            let entries: Vec<DiscoveredAgentEntry> =
                agents.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// Query parameters for `GET /agents/discovered/:agent_id`.
#[derive(Deserialize, Default)]
struct DiscoveredAgentQuery {
    /// When `true`, wait up to 10 s for the agent to announce on its shard
    /// topic before returning `404`. Useful for finding agents that joined
    /// recently and may not be in cache yet.
    #[serde(default)]
    wait: bool,
}

/// GET /agents/discovered/:agent_id[?wait=true]
async fn discovered_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Query(params): Query<DiscoveredAgentQuery>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    if params.wait {
        // Active lookup: subscribe to agent's shard, wait up to 10 s.
        match state.agent.find_agent(agent_id).await {
            Ok(Some(addrs)) => {
                // Return the full discovered_agent entry if available, else
                // synthesise a minimal response from the address list.
                return match state.agent.discovered_agent(agent_id).await {
                    Ok(Some(agent)) => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "ok": true,
                            "agent": discovered_agent_entry(agent),
                        })),
                    ),
                    _ => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "ok": true,
                            "agent": {
                                "agent_id": agent_id_hex,
                                "addresses": addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                            }
                        })),
                    ),
                };
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(
                        serde_json::json!({ "ok": false, "error": "agent not found within timeout" }),
                    ),
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
                );
            }
        }
    }

    match state.agent.discovered_agent(agent_id).await {
        Ok(Some(agent)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "agent": discovered_agent_entry(agent),
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "agent not found" })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /users/:user_id/agents
async fn agents_by_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id_hex): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user_id_bytes = match hex::decode(&user_id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "invalid user_id: expected 64 hex characters"
                })),
            );
        }
    };
    let user_id = x0x::identity::UserId(user_id_bytes);
    match state.agent.find_agents_by_user(user_id).await {
        Ok(agents) => {
            let entries: Vec<DiscoveredAgentEntry> =
                agents.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "user_id": user_id_hex,
                    "agents": entries,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /agent/user-id
async fn agent_user_id_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let user_id = state.agent.user_id().map(|uid| hex::encode(uid.0));
    Json(serde_json::json!({
        "ok": true,
        "user_id": user_id,
    }))
}

// ---------------------------------------------------------------------------
// Contact handlers
// ---------------------------------------------------------------------------

/// Parse a 64-character hex string into an AgentId.
fn parse_agent_id_hex(hex_str: &str) -> Result<AgentId, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(AgentId(arr))
}

/// GET /contacts — list all contacts with trust levels.
async fn list_contacts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.contacts.read().await;
    let entries: Vec<ContactEntry> = store
        .list()
        .into_iter()
        .map(|c| ContactEntry {
            agent_id: hex::encode(c.agent_id.0),
            trust_level: c.trust_level.to_string(),
            label: c.label.clone(),
            added_at: c.added_at,
            last_seen: c.last_seen,
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "contacts": entries }))
}

/// POST /contacts — add a new contact.
async fn add_contact(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddContactRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.trust_level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let contact = x0x::contacts::Contact {
        agent_id,
        trust_level,
        label: req.label,
        added_at: now,
        last_seen: None,
    };

    state.contacts.write().await.add(contact);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "agent_id": hex::encode(agent_id.0) })),
    )
}

/// PATCH /contacts/:agent_id — update trust level for a contact.
async fn update_contact(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Json(req): Json<UpdateContactRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.trust_level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    state
        .contacts
        .write()
        .await
        .set_trust(&agent_id, trust_level);

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// DELETE /contacts/:agent_id — remove a contact.
async fn delete_contact(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let removed = state.contacts.write().await.remove(&agent_id);
    if removed.is_some() {
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "contact not found" })),
        )
    }
}

/// POST /contacts/trust — quick trust shorthand.
async fn quick_trust(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QuickTrustRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    state
        .contacts
        .write()
        .await
        .set_trust(&agent_id, trust_level);

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// GET /task-lists
async fn list_task_lists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let entries: Vec<TaskListEntry> = lists
        .keys()
        .map(|id| TaskListEntry {
            id: id.clone(),
            topic: id.clone(), // topic is used as ID
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "task_lists": entries }))
}

/// POST /task-lists
async fn create_task_list(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTaskListRequest>,
) -> impl IntoResponse {
    match state.agent.create_task_list(&req.name, &req.topic).await {
        Ok(handle) => {
            let id = req.topic.clone();
            state.task_lists.write().await.insert(id.clone(), handle);
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "ok": true, "id": id })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /task-lists/:id/tasks
async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "task list not found" })),
        );
    };

    match handle.list_tasks().await {
        Ok(tasks) => {
            let entries: Vec<TaskEntry> = tasks
                .into_iter()
                .map(|t| TaskEntry {
                    id: format!("{}", t.id),
                    title: t.title,
                    description: t.description,
                    state: format!("{:?}", t.state),
                    assignee: t.assignee.map(|a| format!("{a}")),
                    priority: t.priority,
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "tasks": entries })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /task-lists/:id/tasks
async fn add_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddTaskRequest>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "task list not found" })),
        );
    };

    match handle.add_task(req.title, req.description).await {
        Ok(task_id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "ok": true, "task_id": format!("{task_id}") })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// PATCH /task-lists/:id/tasks/:tid
async fn update_task(
    State(state): State<Arc<AppState>>,
    Path((id, tid)): Path<(String, String)>,
    Json(req): Json<UpdateTaskRequest>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "task list not found" })),
        );
    };

    // Parse task ID from hex
    let task_id_bytes: [u8; 32] = match hex::decode(&tid) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "ok": false, "error": "invalid task ID (expected 64 hex chars)" }),
                ),
            );
        }
    };
    let task_id = x0x::crdt::TaskId::from_bytes(task_id_bytes);

    let result = match req.action.as_str() {
        "claim" => handle.claim_task(task_id).await,
        "complete" => handle.complete_task(task_id).await,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "ok": false, "error": "action must be 'claim' or 'complete'" }),
                ),
            );
        }
    };

    match result {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load configuration from TOML file.
async fn load_config(path: &str) -> Result<DaemonConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config file: {path}"))?;
    toml::from_str(&content).with_context(|| format!("failed to parse config file: {path}"))
}

/// Initialize structured logging.
fn init_logging(level: &str, format: &str) -> Result<()> {
    let level_filter = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    if format == "json" {
        tracing_subscriber::fmt()
            .with_max_level(level_filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(level_filter)
            .init();
    }

    Ok(())
}
