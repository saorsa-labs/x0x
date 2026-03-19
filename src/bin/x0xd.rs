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
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
use x0x::contacts::{ContactStore, TrustLevel};
use x0x::identity::AgentId;
use x0x::network::NetworkConfig;
use x0x::{Agent, GroupId, GroupSummary, Subscription, TaskListHandle};

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

    /// Bootstrap peers to connect on startup.
    #[serde(default)]
    bootstrap_peers: Vec<SocketAddr>,

    /// Enable self-update checks at startup.
    #[serde(default = "default_update_enabled")]
    update_enabled: bool,

    /// Automatically install updates when available.
    #[serde(default = "default_auto_update")]
    auto_update: bool,

    /// Restart daemon after successful self-update.
    #[serde(default = "default_restart_after_update")]
    restart_after_update: bool,

    /// Check interval in hours for background update checks.
    #[serde(default = "default_update_check_interval_hours")]
    update_check_interval_hours: u64,

    /// GitHub repo used for update discovery (owner/repo).
    #[serde(default = "default_update_repo")]
    update_repo: String,

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

fn default_update_enabled() -> bool {
    true
}

fn default_auto_update() -> bool {
    true
}

fn default_restart_after_update() -> bool {
    true
}

fn default_update_check_interval_hours() -> u64 {
    24
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
            bootstrap_peers: x0x::network::DEFAULT_BOOTSTRAP_PEERS
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            update_enabled: default_update_enabled(),
            auto_update: default_auto_update(),
            restart_after_update: default_restart_after_update(),
            update_check_interval_hours: default_update_check_interval_hours(),
            update_repo: default_update_repo(),
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

/// POST /groups request body.
#[derive(Debug, Deserialize)]
struct CreateGroupRequest {
    name: String,
}

/// POST /groups/:id/invite request body.
#[derive(Debug, Deserialize)]
struct InviteRequest {
    /// Hex-encoded AgentId of the invitee (64 hex chars = 32 bytes).
    agent_id: String,
}

/// POST /invites/:group_id/accept and reject request body.
#[derive(Debug, Deserialize)]
struct InviteActionRequest {
    /// Hex-encoded AgentId of the invite sender.
    sender: String,
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

    init_logging(&config.log_level)?;

    if check_only {
        println!("Configuration is valid");
        println!("{:#?}", config);
        return Ok(());
    }

    // Ensure data directory exists early so self-update has a working directory.
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .context("failed to create data directory")?;

    if config.update_enabled && !skip_update_check {
        let update_outcome = match check_and_apply_self_update(&config).await {
            Ok(outcome) => Some(outcome),
            Err(err) => {
                if check_updates_only {
                    return Err(err).context("self-update check failed");
                }
                tracing::warn!("Startup self-update check failed: {err}");
                None
            }
        };

        if let Some(update_outcome) = update_outcome {
            if check_updates_only {
                match update_outcome {
                    UpdateOutcome::UpToDate => println!("x0xd is up to date ({})", x0x::VERSION),
                    UpdateOutcome::Updated {
                        latest_version,
                        can_restart_now,
                    } => {
                        if can_restart_now {
                            println!("x0xd updated to {latest_version}; restarting now")
                        } else {
                            println!("x0xd updated to {latest_version}; restart required")
                        }
                    }
                    UpdateOutcome::UpdateAvailable { latest_version } => {
                        println!("update available: {latest_version}")
                    }
                }
                return Ok(());
            }

            if let UpdateOutcome::Updated {
                can_restart_now: true,
                ..
            } = update_outcome
            {
                if config.restart_after_update {
                    restart_current_process_with_skip_flag(&args)
                        .context("failed to restart after self-update")?;
                    return Ok(());
                }
            }
        } else if check_updates_only {
            println!("update check failed");
            return Ok(());
        }
    } else if check_updates_only {
        if !config.update_enabled {
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

    // Start background invite listener (non-fatal if it fails)
    if let Err(e) = agent.start_invite_listener().await {
        tracing::warn!("failed to start invite listener: {e}");
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

    if config.update_enabled && config.update_check_interval_hours > 0 {
        let update_config = config.clone();
        let startup_args = args.clone();
        tokio::spawn(async move {
            let interval_secs = update_config
                .update_check_interval_hours
                .saturating_mul(3600);
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));

            // Skip immediate tick to avoid duplicate startup check.
            ticker.tick().await;

            loop {
                ticker.tick().await;

                match check_and_apply_self_update(&update_config).await {
                    Ok(UpdateOutcome::UpToDate) => {
                        tracing::debug!("Periodic self-update check: up to date");
                    }
                    Ok(UpdateOutcome::UpdateAvailable { latest_version }) => {
                        tracing::info!(
                            "Periodic self-update check: update available {}",
                            latest_version
                        );
                    }
                    Ok(UpdateOutcome::Updated {
                        latest_version,
                        can_restart_now,
                    }) => {
                        if can_restart_now && update_config.restart_after_update {
                            tracing::info!(
                                "Periodic self-update installed {}. Restarting daemon.",
                                latest_version
                            );

                            if let Err(err) = restart_current_process_with_skip_flag(&startup_args)
                            {
                                tracing::warn!(
                                    "Failed to restart after periodic self-update: {err}"
                                );
                            }
                        } else if can_restart_now {
                            tracing::warn!(
                                "Periodic self-update installed {}. Restart x0xd to run the new version.",
                                latest_version
                            );
                        } else {
                            tracing::warn!(
                                "Periodic self-update staged {}. Restart x0xd to activate it.",
                                latest_version
                            );
                        }
                    }
                    Err(err) => {
                        tracing::warn!("Periodic self-update check failed: {err}");
                    }
                }
            }
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
    let app = build_router(Arc::clone(&state));

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

/// Build the axum Router with all routes and shared state.
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
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
        .route("/groups", post(create_group))
        .route("/groups", get(list_groups))
        .route("/groups/:id", get(get_group))
        .route("/groups/:id/invite", post(invite_to_group))
        .route("/invites", get(list_invites))
        .route("/invites/:group_id/accept", post(accept_invite))
        .route("/invites/:group_id/reject", post(reject_invite))
        .route("/groups/:id/tasks", get(list_group_tasks))
        .route("/groups/:id/tasks", post(add_group_task))
        .route("/groups/:id/tasks/:tid", patch(update_group_task))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    tracing::info!("Received shutdown signal");
}

// ---------------------------------------------------------------------------
// Self-update
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum ArchiveKind {
    TarGz,
    Zip,
}

#[derive(Debug, Clone, Copy)]
struct UpdateAssetSpec {
    archive_name: &'static str,
    signature_name: &'static str,
    inner_binary_path: &'static str,
    archive_kind: ArchiveKind,
}

#[derive(Debug)]
enum UpdateOutcome {
    UpToDate,
    UpdateAvailable {
        latest_version: String,
    },
    Updated {
        latest_version: String,
        can_restart_now: bool,
    },
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn current_update_asset_spec() -> Option<UpdateAssetSpec> {
    Some(UpdateAssetSpec {
        archive_name: "x0x-linux-x64-gnu.tar.gz",
        signature_name: "x0x-linux-x64-gnu.tar.gz.asc",
        inner_binary_path: "x0x-linux-x64-gnu/x0xd",
        archive_kind: ArchiveKind::TarGz,
    })
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn current_update_asset_spec() -> Option<UpdateAssetSpec> {
    Some(UpdateAssetSpec {
        archive_name: "x0x-linux-arm64-gnu.tar.gz",
        signature_name: "x0x-linux-arm64-gnu.tar.gz.asc",
        inner_binary_path: "x0x-linux-arm64-gnu/x0xd",
        archive_kind: ArchiveKind::TarGz,
    })
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn current_update_asset_spec() -> Option<UpdateAssetSpec> {
    Some(UpdateAssetSpec {
        archive_name: "x0x-macos-x64.tar.gz",
        signature_name: "x0x-macos-x64.tar.gz.asc",
        inner_binary_path: "x0x-macos-x64/x0xd",
        archive_kind: ArchiveKind::TarGz,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn current_update_asset_spec() -> Option<UpdateAssetSpec> {
    Some(UpdateAssetSpec {
        archive_name: "x0x-macos-arm64.tar.gz",
        signature_name: "x0x-macos-arm64.tar.gz.asc",
        inner_binary_path: "x0x-macos-arm64/x0xd",
        archive_kind: ArchiveKind::TarGz,
    })
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn current_update_asset_spec() -> Option<UpdateAssetSpec> {
    Some(UpdateAssetSpec {
        archive_name: "x0x-windows-x64.zip",
        signature_name: "x0x-windows-x64.zip.asc",
        inner_binary_path: "x0xd.exe",
        archive_kind: ArchiveKind::Zip,
    })
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn current_update_asset_spec() -> Option<UpdateAssetSpec> {
    None
}

fn normalize_release_version(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

fn parse_semver(version: &str) -> Result<semver::Version> {
    semver::Version::parse(version).with_context(|| format!("invalid semver version: {version}"))
}

fn find_asset_url<'a>(release: &'a GithubRelease, name: &str) -> Option<&'a str> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .map(|asset| asset.browser_download_url.as_str())
}

async fn fetch_latest_release(client: &reqwest::Client, repo: &str) -> Result<GithubRelease> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");

    let response = client
        .get(url)
        .send()
        .await
        .context("failed to query latest GitHub release")?
        .error_for_status()
        .context("GitHub releases API returned an error status")?;

    response
        .json::<GithubRelease>()
        .await
        .context("failed to deserialize GitHub release metadata")
}

async fn download_asset(client: &reqwest::Client, url: &str, destination: &FsPath) -> Result<()> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to download asset: {url}"))?
        .error_for_status()
        .with_context(|| format!("failed to download asset: {url}"))?;

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read downloaded asset: {url}"))?;

    tokio::fs::write(destination, bytes)
        .await
        .with_context(|| format!("failed to write asset: {}", destination.display()))
}

async fn verify_archive_signature(
    public_key_path: &FsPath,
    signature_path: &FsPath,
    archive_path: &FsPath,
) -> Result<()> {
    let public_key_path = public_key_path.to_path_buf();
    let signature_path = signature_path.to_path_buf();
    let archive_path = archive_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let gpg_home = archive_path
            .parent()
            .ok_or_else(|| anyhow!("archive has no parent directory"))?
            .join("gnupg-home");

        std::fs::create_dir_all(&gpg_home)
            .with_context(|| format!("failed to create {}", gpg_home.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&gpg_home, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to set permissions on {}", gpg_home.display()))?;
        }

        let import_status = std::process::Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(&gpg_home)
            .arg("--import")
            .arg(&public_key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run gpg import (is gpg installed?)")?;

        if !import_status.success() {
            return Err(anyhow!("gpg key import failed"));
        }

        let verify_output = std::process::Command::new("gpg")
            .arg("--batch")
            .arg("--no-tty")
            .arg("--status-fd")
            .arg("1")
            .arg("--homedir")
            .arg(&gpg_home)
            .arg("--verify")
            .arg(&signature_path)
            .arg(&archive_path)
            .output()
            .context("failed to run gpg verify")?;

        let stdout = String::from_utf8_lossy(&verify_output.stdout);
        let stderr = String::from_utf8_lossy(&verify_output.stderr);

        if verify_output.status.success()
            && (stdout.contains("[GNUPG:] GOODSIG") || stdout.contains("[GNUPG:] VALIDSIG"))
        {
            Ok(())
        } else {
            Err(anyhow!("signature verification failed: {}", stderr.trim()))
        }
    })
    .await
    .context("signature verification task failed")?
}

async fn extract_daemon_binary(
    archive_path: &FsPath,
    output_path: &FsPath,
    asset_spec: UpdateAssetSpec,
) -> Result<()> {
    let archive_path = archive_path.to_path_buf();
    let output_path = output_path.to_path_buf();

    tokio::task::spawn_blocking(move || -> Result<()> {
        match asset_spec.archive_kind {
            ArchiveKind::TarGz => {
                let archive_file = std::fs::File::open(&archive_path)
                    .with_context(|| format!("failed to open {}", archive_path.display()))?;
                let decoder = flate2::read::GzDecoder::new(archive_file);
                let mut archive = tar::Archive::new(decoder);

                let mut found = false;
                for entry in archive
                    .entries()
                    .context("failed to read tar archive entries")?
                {
                    let mut entry = entry.context("failed to read tar archive entry")?;
                    let path = entry.path().context("failed to read tar entry path")?;
                    if path.to_string_lossy() == asset_spec.inner_binary_path {
                        let mut output =
                            std::fs::File::create(&output_path).with_context(|| {
                                format!("failed to create {}", output_path.display())
                            })?;
                        std::io::copy(&mut entry, &mut output)
                            .context("failed to extract daemon binary")?;
                        found = true;
                        break;
                    }
                }

                if !found {
                    return Err(anyhow!(
                        "daemon binary not found in archive: {}",
                        asset_spec.inner_binary_path
                    ));
                }
            }
            ArchiveKind::Zip => {
                let archive_file = std::fs::File::open(&archive_path)
                    .with_context(|| format!("failed to open {}", archive_path.display()))?;
                let mut archive =
                    zip::ZipArchive::new(archive_file).context("failed to open zip archive")?;

                let mut entry =
                    archive
                        .by_name(asset_spec.inner_binary_path)
                        .with_context(|| {
                            format!("failed to find {} in zip", asset_spec.inner_binary_path)
                        })?;

                let mut output = std::fs::File::create(&output_path)
                    .with_context(|| format!("failed to create {}", output_path.display()))?;
                std::io::copy(&mut entry, &mut output)
                    .context("failed to extract daemon binary")?;
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o755))
                .with_context(|| format!("failed to chmod {}", output_path.display()))?;
        }

        Ok(())
    })
    .await
    .context("binary extraction task failed")?
}

#[allow(dead_code)]
#[derive(Debug)]
enum InstallOutcome {
    Replaced,
    Staged,
}

async fn install_updated_binary(extracted_binary_path: &FsPath) -> Result<InstallOutcome> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;

    #[cfg(unix)]
    {
        let replacement_path = current_exe.with_extension("update");

        tokio::fs::copy(extracted_binary_path, &replacement_path)
            .await
            .with_context(|| {
                format!(
                    "failed to stage update binary at {}",
                    replacement_path.display()
                )
            })?;

        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&replacement_path, std::fs::Permissions::from_mode(0o755))
            .await
            .with_context(|| {
                format!(
                    "failed to set permissions on {}",
                    replacement_path.display()
                )
            })?;

        tokio::fs::rename(&replacement_path, &current_exe)
            .await
            .with_context(|| format!("failed to replace {}", current_exe.display()))?;

        Ok(InstallOutcome::Replaced)
    }

    #[cfg(target_os = "windows")]
    {
        let staged_path = current_exe.with_extension("new.exe");
        tokio::fs::copy(extracted_binary_path, &staged_path)
            .await
            .with_context(|| format!("failed to stage update at {}", staged_path.display()))?;
        Ok(InstallOutcome::Staged)
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = extracted_binary_path;
        Err(anyhow!(
            "self-update installation is not supported on this platform"
        ))
    }
}

async fn check_and_apply_self_update(config: &DaemonConfig) -> Result<UpdateOutcome> {
    let Some(asset_spec) = current_update_asset_spec() else {
        tracing::info!("Self-update not supported on this platform/architecture");
        return Ok(UpdateOutcome::UpToDate);
    };

    let client = reqwest::Client::builder()
        .user_agent(format!("x0xd/{version}", version = x0x::VERSION))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client for updates")?;

    let release = fetch_latest_release(&client, &config.update_repo).await?;
    let latest_version = normalize_release_version(&release.tag_name).to_string();

    let latest_semver = parse_semver(&latest_version)?;
    let current_semver = parse_semver(x0x::VERSION)?;

    if latest_semver <= current_semver {
        tracing::debug!("x0xd is up to date ({})", x0x::VERSION);
        return Ok(UpdateOutcome::UpToDate);
    }

    tracing::info!(
        "Self-update available: current={} latest={}",
        x0x::VERSION,
        latest_version
    );

    if !config.auto_update {
        return Ok(UpdateOutcome::UpdateAvailable { latest_version });
    }

    let work_dir = config.data_dir.join("updates").join(format!(
        "x0xd-{}-{}",
        latest_version,
        std::process::id()
    ));
    tokio::fs::create_dir_all(&work_dir)
        .await
        .with_context(|| format!("failed to create update work dir {}", work_dir.display()))?;

    let archive_path = work_dir.join(asset_spec.archive_name);
    let signature_path = work_dir.join(asset_spec.signature_name);
    let key_path = work_dir.join("SAORSA_PUBLIC_KEY.asc");
    let extracted_binary_path = work_dir.join("x0xd-updated-binary");

    let archive_url = find_asset_url(&release, asset_spec.archive_name)
        .ok_or_else(|| anyhow!("release asset missing: {}", asset_spec.archive_name))?;
    let signature_url = find_asset_url(&release, asset_spec.signature_name)
        .ok_or_else(|| anyhow!("release asset missing: {}", asset_spec.signature_name))?;
    let key_url = find_asset_url(&release, "SAORSA_PUBLIC_KEY.asc")
        .ok_or_else(|| anyhow!("release asset missing: SAORSA_PUBLIC_KEY.asc"))?;

    download_asset(&client, archive_url, &archive_path).await?;
    download_asset(&client, signature_url, &signature_path).await?;
    download_asset(&client, key_url, &key_path).await?;

    verify_archive_signature(&key_path, &signature_path, &archive_path).await?;
    extract_daemon_binary(&archive_path, &extracted_binary_path, asset_spec).await?;

    let install_outcome = install_updated_binary(&extracted_binary_path).await?;

    if let Err(err) = tokio::fs::remove_dir_all(&work_dir).await {
        tracing::warn!("failed to clean update dir {}: {err}", work_dir.display());
    }

    match install_outcome {
        InstallOutcome::Replaced => {
            tracing::info!("Self-update installed successfully: {}", latest_version);
            Ok(UpdateOutcome::Updated {
                latest_version,
                can_restart_now: true,
            })
        }
        InstallOutcome::Staged => {
            tracing::info!(
                "Self-update staged successfully: {} (restart required)",
                latest_version
            );
            Ok(UpdateOutcome::Updated {
                latest_version,
                can_restart_now: false,
            })
        }
    }
}

fn restart_current_process_with_skip_flag(original_args: &[String]) -> Result<()> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;

    let mut restart_args: Vec<OsString> = original_args
        .iter()
        .skip(1)
        .filter(|arg| arg.as_str() != "--skip-update-check")
        .map(OsString::from)
        .collect();
    restart_args.push(OsString::from("--skip-update-check"));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new(current_exe)
            .args(&restart_args)
            .exec();
        Err(anyhow!("exec failed: {error}"))
    }

    #[cfg(not(unix))]
    {
        std::process::Command::new(current_exe)
            .args(&restart_args)
            .spawn()
            .context("failed to spawn updated process")?;
        Ok(())
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
// Group handlers
// ---------------------------------------------------------------------------

/// Serialize a GroupSummary into a JSON value with hex-encoded IDs.
fn group_summary_to_json(g: &GroupSummary) -> serde_json::Value {
    serde_json::json!({
        "group_id": g.group_id.to_hex(),
        "name": g.name,
        "known_members": g.known_members,
        "member_ids": g.member_ids.iter().map(|id| hex::encode(id.0)).collect::<Vec<_>>(),
    })
}

/// POST /groups
async fn create_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    match state.agent.create_group(req.name).await {
        Ok(summary) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "ok": true, "group": group_summary_to_json(&summary) })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /groups
async fn list_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let groups = state.agent.list_groups().await;
    let entries: Vec<serde_json::Value> = groups.iter().map(group_summary_to_json).collect();
    Json(serde_json::json!({ "ok": true, "groups": entries }))
}

/// GET /groups/:id
async fn get_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let group_id = match GroupId::from_hex(&id) {
        Ok(gid) => gid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid group ID: {e}") })),
            );
        }
    };

    let gs = state.agent.group_state().read().await;
    if gs.groups.contains_key(&group_id) {
        let name = gs.group_names.get(&group_id).cloned().unwrap_or_default();
        let member_ids: Vec<AgentId> = gs
            .groups
            .get(&group_id)
            .map(|g| g.members().keys().copied().collect())
            .unwrap_or_default();
        let summary = GroupSummary {
            group_id,
            name,
            known_members: member_ids.len(),
            member_ids,
        };
        (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "group": group_summary_to_json(&summary) })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        )
    }
}

/// POST /groups/:id/invite
async fn invite_to_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<InviteRequest>,
) -> impl IntoResponse {
    let group_id = match GroupId::from_hex(&id) {
        Ok(gid) => gid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid group ID: {e}") })),
            );
        }
    };

    let invitee = match parse_agent_id_hex(&req.agent_id) {
        Ok(aid) => aid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid agent_id: {e}") })),
            );
        }
    };

    match state.agent.invite_to_group(&group_id, invitee).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /invites
async fn list_invites(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let invites = state.agent.list_pending_invites().await;
    let entries: Vec<serde_json::Value> = invites
        .iter()
        .map(|inv| {
            serde_json::json!({
                "group_id": inv.group_id.to_hex(),
                "sender": hex::encode(inv.sender.0),
                "verified": inv.verified,
                "trust_level": inv.trust_level.as_ref().map(|t| format!("{t:?}")),
                "received_at": inv.received_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "invites": entries }))
}

/// POST /invites/:group_id/accept
async fn accept_invite(
    State(state): State<Arc<AppState>>,
    Path(group_id_hex): Path<String>,
    Json(req): Json<InviteActionRequest>,
) -> impl IntoResponse {
    let group_id = match GroupId::from_hex(&group_id_hex) {
        Ok(gid) => gid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid group ID: {e}") })),
            );
        }
    };

    let sender = match parse_agent_id_hex(&req.sender) {
        Ok(aid) => aid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid sender: {e}") })),
            );
        }
    };

    match state.agent.accept_invite(&group_id, &sender).await {
        Ok(summary) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "group": group_summary_to_json(&summary) })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /invites/:group_id/reject
async fn reject_invite(
    State(state): State<Arc<AppState>>,
    Path(group_id_hex): Path<String>,
    Json(req): Json<InviteActionRequest>,
) -> impl IntoResponse {
    let group_id = match GroupId::from_hex(&group_id_hex) {
        Ok(gid) => gid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid group ID: {e}") })),
            );
        }
    };

    let sender = match parse_agent_id_hex(&req.sender) {
        Ok(aid) => aid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid sender: {e}") })),
            );
        }
    };

    match state.agent.reject_invite(&group_id, &sender).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /groups/:id/tasks — list tasks in a group's encrypted task list.
async fn list_group_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let group_id = match GroupId::from_hex(&id) {
        Ok(g) => g,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": "invalid group id"})),
            )
        }
    };

    let group_state = state.agent.group_state().read().await;
    let Some(sync) = group_state.encrypted_syncs.get(&group_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "group not found or no task list"})),
        );
    };

    let list = sync.read().await;
    let tasks: Vec<serde_json::Value> = list
        .tasks_ordered()
        .iter()
        .map(|t| {
            let state_str = match t.current_state() {
                x0x::crdt::CheckboxState::Empty => "empty".to_string(),
                x0x::crdt::CheckboxState::Claimed { .. } => "claimed".to_string(),
                x0x::crdt::CheckboxState::Done { .. } => "done".to_string(),
            };
            serde_json::json!({
                "id": format!("{}", t.id()),
                "title": t.title(),
                "description": t.description(),
                "state": state_str,
                "assignee": t.assignee().map(|a| hex::encode(a.0)),
                "priority": t.priority(),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "tasks": tasks})),
    )
}

/// POST /groups/:id/tasks — add a task to a group's encrypted task list.
async fn add_group_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddTaskRequest>,
) -> impl IntoResponse {
    let group_id = match GroupId::from_hex(&id) {
        Ok(g) => g,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": "invalid group id"})),
            )
        }
    };

    let agent_id = state.agent.agent_id();
    let peer_id = saorsa_gossip_types::PeerId::new(*agent_id.as_bytes());

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let task_id = x0x::crdt::TaskId::new(&req.title, &agent_id, timestamp);
    let metadata =
        x0x::crdt::TaskMetadata::new(req.title, req.description, 128, agent_id, timestamp);
    let task = x0x::crdt::TaskItem::new(task_id, metadata, peer_id);

    let group_state = state.agent.group_state().read().await;
    let Some(sync) = group_state.encrypted_syncs.get(&group_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "group not found or no task list"})),
        );
    };
    let sync = std::sync::Arc::clone(sync);
    drop(group_state);

    // Build delta before mutating
    let mut delta = x0x::crdt::TaskListDelta::new(timestamp);
    let tag = (peer_id, timestamp);
    delta.added_tasks.insert(task_id, (task.clone(), tag));

    // Apply locally
    {
        let mut list = sync.write().await;
        if let Err(e) = list.add_task(task, peer_id, timestamp) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": format!("add_task failed: {e}")})),
            );
        }
    }

    // Best-effort encrypted replication
    if let Err(e) = sync.publish_delta(peer_id, delta).await {
        tracing::warn!("failed to publish encrypted add_task delta: {e}");
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"ok": true, "task_id": format!("{task_id}")})),
    )
}

/// PATCH /groups/:id/tasks/:tid — update a task in a group's encrypted task list.
async fn update_group_task(
    State(state): State<Arc<AppState>>,
    Path((id, tid)): Path<(String, String)>,
    Json(req): Json<UpdateTaskRequest>,
) -> impl IntoResponse {
    let group_id = match GroupId::from_hex(&id) {
        Ok(g) => g,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": "invalid group id"})),
            )
        }
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
                    serde_json::json!({"ok": false, "error": "invalid task ID (expected 64 hex chars)"}),
                ),
            )
        }
    };
    let task_id = x0x::crdt::TaskId::from_bytes(task_id_bytes);

    let agent_id = state.agent.agent_id();
    let peer_id = saorsa_gossip_types::PeerId::new(*agent_id.as_bytes());

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let group_state = state.agent.group_state().read().await;
    let Some(sync) = group_state.encrypted_syncs.get(&group_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "group not found or no task list"})),
        );
    };
    let sync = std::sync::Arc::clone(sync);
    drop(group_state);

    // Apply action to local CRDT
    let mut list = sync.write().await;
    let result = match req.action.as_str() {
        "claim" => list.claim_task(&task_id, agent_id, peer_id, timestamp),
        "complete" => list.complete_task(&task_id, agent_id, peer_id, timestamp),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"ok": false, "error": "action must be 'claim' or 'complete'"}),
                ),
            )
        }
    };

    if let Err(e) = result {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": format!("{e}")})),
        );
    }

    // Build delta with updated task state
    let mut delta = x0x::crdt::TaskListDelta::new(timestamp);
    if let Some(task) = list.get_task(&task_id) {
        delta.task_updates.insert(task_id, task.clone());
    }
    drop(list);

    // Best-effort encrypted replication
    if !delta.is_empty() {
        if let Err(e) = sync.publish_delta(peer_id, delta).await {
            tracing::warn!("failed to publish encrypted update_task delta: {e}");
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
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
fn init_logging(level: &str) -> Result<()> {
    let level_filter = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level_filter)
        .init();

    Ok(())
}

// ---------------------------------------------------------------------------
// REST integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Find a free port by briefly binding and releasing a TCP listener.
    async fn free_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Spawn a local daemon: create an Agent with localhost-only networking,
    /// build AppState + Router, serve on a random port. Returns the base URL,
    /// the Agent (for identity inspection), the QUIC port, and the TempDir.
    async fn spawn_daemon(bootstrap: Vec<SocketAddr>) -> (String, Arc<Agent>, SocketAddr, TempDir) {
        let dir = TempDir::new().unwrap();
        let quic_port = free_port().await;
        let quic_addr: SocketAddr = format!("127.0.0.1:{quic_port}").parse().unwrap();
        let cfg = NetworkConfig {
            bind_addr: Some(quic_addr),
            bootstrap_nodes: bootstrap,
            ..Default::default()
        };
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_network_config(cfg)
            .build()
            .await
            .unwrap();
        agent.join_network().await.unwrap();
        agent.start_invite_listener().await.unwrap();

        let agent = Arc::new(agent);
        let (broadcast_tx, _) = broadcast::channel::<SseEvent>(64);
        let state = Arc::new(AppState {
            agent: Arc::clone(&agent),
            subscriptions: RwLock::new(HashMap::new()),
            task_lists: RwLock::new(HashMap::new()),
            contacts: Arc::new(tokio::sync::RwLock::new(ContactStore::new(
                dir.path().join("contacts.json"),
            ))),
            start_time: Instant::now(),
            broadcast_tx,
        });

        let app = build_router(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let base_url = format!("http://{addr}");
        (base_url, agent, quic_addr, dir)
    }

    /// Full bidirectional collaboration via REST:
    ///   A creates group → invites B → B accepts → A adds task →
    ///   B sees task → B claims task → B completes task → A sees updated state.
    #[tokio::test]
    async fn test_group_collaboration_via_rest() {
        // Daemon A (no bootstrap — it IS the first node)
        let (url_a, agent_a, quic_a, _dir_a) = spawn_daemon(vec![]).await;

        // Daemon B bootstraps to A's QUIC address
        let (url_b, agent_b, _quic_b, _dir_b) = spawn_daemon(vec![quic_a]).await;

        let client = reqwest::Client::new();
        // --- Phase 1: Group creation and membership ---

        // 1. Create group on A
        let resp = client
            .post(format!("{url_a}/groups"))
            .json(&serde_json::json!({ "name": "collab-test" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "create group failed");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], true);
        let group_id = body["group"]["group_id"].as_str().unwrap().to_string();

        // 2. GET /groups/:id on A confirms group exists
        let resp = client
            .get(format!("{url_a}/groups/{group_id}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // 3. Invite B
        let b_agent_id_hex = hex::encode(agent_b.agent_id().0);
        let resp = client
            .post(format!("{url_a}/groups/{group_id}/invite"))
            .json(&serde_json::json!({ "agent_id": b_agent_id_hex }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "invite failed");

        // 4. Poll B's /invites until the invite arrives (timeout: 6s)
        let mut invite_found = false;
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let resp = client.get(format!("{url_b}/invites")).send().await.unwrap();
            let body: serde_json::Value = resp.json().await.unwrap();
            let invites = body["invites"].as_array().unwrap();
            if !invites.is_empty() {
                assert_eq!(
                    invites[0]["group_id"].as_str().unwrap(),
                    group_id,
                    "invite group_id mismatch"
                );
                invite_found = true;
                break;
            }
        }
        assert!(invite_found, "invite did not arrive at B within 20s");

        // 5. Accept invite on B
        let a_agent_id_hex = hex::encode(agent_a.agent_id().0);
        let resp = client
            .post(format!("{url_b}/invites/{group_id}/accept"))
            .json(&serde_json::json!({ "sender": a_agent_id_hex }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "accept failed: {:?}", resp.text().await);

        // 6. Both agents now list the group
        let resp = client.get(format!("{url_a}/groups")).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            !body["groups"].as_array().unwrap().is_empty(),
            "A has no groups"
        );

        let resp = client.get(format!("{url_b}/groups")).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            !body["groups"].as_array().unwrap().is_empty(),
            "B has no groups"
        );

        // --- Phase 2: A adds task, B sees it ---

        // 7. A adds a task
        let resp = client
            .post(format!("{url_a}/groups/{group_id}/tasks"))
            .json(&serde_json::json!({
                "title": "Build thing",
                "description": "build the thing"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "add task failed");
        let body: serde_json::Value = resp.json().await.unwrap();
        let task_id = body["task_id"].as_str().unwrap().to_string();

        // 8. A sees the task
        let resp = client
            .get(format!("{url_a}/groups/{group_id}/tasks"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let tasks = body["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1, "expected 1 task on A");
        assert_eq!(tasks[0]["title"].as_str().unwrap(), "Build thing");
        assert_eq!(tasks[0]["state"].as_str().unwrap(), "empty");

        // 9. Poll B until the task from A appears via encrypted replication.
        let mut b_saw_task = false;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let resp = client
                .get(format!("{url_b}/groups/{group_id}/tasks"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = resp.json().await.unwrap();
            let b_tasks = body["tasks"].as_array().unwrap();

            if let Some(b_task) = b_tasks
                .iter()
                .find(|t| t["id"].as_str().unwrap_or_default() == task_id)
            {
                assert_eq!(b_task["title"].as_str().unwrap(), "Build thing");
                assert_eq!(b_task["state"].as_str().unwrap(), "empty");
                b_saw_task = true;
                break;
            }
        }
        assert!(
            b_saw_task,
            "B did not see A's task via encrypted replication within 6s"
        );

        // --- Phase 3: B updates A's task and A observes updates ---

        // 10. B claims A's task
        let resp = client
            .patch(format!("{url_b}/groups/{group_id}/tasks/{task_id}"))
            .json(&serde_json::json!({ "action": "claim" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "B claim failed");

        // Confirm B observes its own claim locally.
        let b_claim_view: serde_json::Value = client
            .get(format!("{url_b}/groups/{group_id}/tasks"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let b_task_state = b_claim_view["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"].as_str().unwrap_or_default() == task_id)
            .and_then(|t| t["state"].as_str())
            .unwrap_or("<missing>");
        assert_eq!(
            b_task_state, "claimed",
            "B should see its own claim locally"
        );

        // 11. Poll A until the task is claimed.
        let mut a_saw_claimed = false;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let resp = client
                .get(format!("{url_a}/groups/{group_id}/tasks"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = resp.json().await.unwrap();
            if let Some(a_task) = body["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["id"].as_str().unwrap_or_default() == task_id)
            {
                if a_task["state"].as_str().unwrap_or_default() == "claimed" {
                    a_saw_claimed = true;
                    break;
                }
            }
        }
        assert!(a_saw_claimed, "A did not observe B's claim within 6s");

        // 12. B completes A's task
        let resp = client
            .patch(format!("{url_b}/groups/{group_id}/tasks/{task_id}"))
            .json(&serde_json::json!({ "action": "complete" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "B complete failed");

        // 13. Poll A until the task is done.
        let mut a_saw_done = false;
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let resp = client
                .get(format!("{url_a}/groups/{group_id}/tasks"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = resp.json().await.unwrap();
            if let Some(a_task) = body["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["id"].as_str().unwrap_or_default() == task_id)
            {
                if a_task["state"].as_str().unwrap_or_default() == "done" {
                    a_saw_done = true;
                    break;
                }
            }
        }
        assert!(a_saw_done, "A did not observe B's complete within 20s");

        // --- Phase 4: Error paths ---

        // 14. Non-existent group returns 404 for tasks
        let fake_id = "00".repeat(32);
        let resp = client
            .get(format!("{url_a}/groups/{fake_id}/tasks"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);

        // 15. Invalid action returns 400
        let resp = client
            .patch(format!("{url_a}/groups/{group_id}/tasks/{task_id}"))
            .json(&serde_json::json!({ "action": "delete" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    /// Non-member exclusion: agent C cannot access group tasks.
    #[tokio::test]
    async fn test_non_member_excluded_via_rest() {
        // A creates group, C (non-member) tries to access it
        let (url_a, _agent_a, quic_a, _dir_a) = spawn_daemon(vec![]).await;
        let (url_c, _agent_c, _quic_c, _dir_c) = spawn_daemon(vec![quic_a]).await;

        let client = reqwest::Client::new();

        // A creates a group and adds a task
        let resp = client
            .post(format!("{url_a}/groups"))
            .json(&serde_json::json!({ "name": "private-group" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = resp.json().await.unwrap();
        let group_id = body["group"]["group_id"].as_str().unwrap().to_string();

        let resp = client
            .post(format!("{url_a}/groups/{group_id}/tasks"))
            .json(&serde_json::json!({
                "title": "Secret task",
                "description": "only members should see this"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);

        // C does NOT have this group — GET /groups/:id/tasks should 404
        let resp = client
            .get(format!("{url_c}/groups/{group_id}/tasks"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "non-member C should get 404 for group tasks"
        );

        // C cannot add a task to A's group — should 404
        let resp = client
            .post(format!("{url_c}/groups/{group_id}/tasks"))
            .json(&serde_json::json!({
                "title": "Injected task",
                "description": "should not work"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "non-member C should get 404 adding task"
        );

        // C cannot PATCH tasks in A's group — should 404
        let fake_task_id = "aa".repeat(32);
        let resp = client
            .patch(format!("{url_c}/groups/{group_id}/tasks/{fake_task_id}"))
            .json(&serde_json::json!({ "action": "claim" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "non-member C should get 404 patching task"
        );

        // C should not see this group in its group list
        let resp = client.get(format!("{url_c}/groups")).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["groups"].as_array().unwrap().is_empty(),
            "C should have no groups"
        );

        // C has no pending invites
        let resp = client.get(format!("{url_c}/invites")).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["invites"].as_array().unwrap().is_empty(),
            "C should have no invites"
        );

        // Meanwhile, A still sees its task fine
        let resp = client
            .get(format!("{url_a}/groups/{group_id}/tasks"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let tasks = body["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["title"].as_str().unwrap(), "Secret task");
    }

    /// Reject invite flow via REST: invite arrives, B rejects, group not joined.
    #[tokio::test]
    async fn test_reject_invite_via_rest() {
        let (url_a, agent_a, quic_a, _dir_a) = spawn_daemon(vec![]).await;
        let (url_b, agent_b, _quic_b, _dir_b) = spawn_daemon(vec![quic_a]).await;

        let client = reqwest::Client::new();

        // Create group on A and invite B
        let resp = client
            .post(format!("{url_a}/groups"))
            .json(&serde_json::json!({ "name": "reject-test" }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        let group_id = body["group"]["group_id"].as_str().unwrap().to_string();

        let b_id = hex::encode(agent_b.agent_id().0);
        client
            .post(format!("{url_a}/groups/{group_id}/invite"))
            .json(&serde_json::json!({ "agent_id": b_id }))
            .send()
            .await
            .unwrap();

        // Wait for invite to arrive at B
        let mut found = false;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let resp = client.get(format!("{url_b}/invites")).send().await.unwrap();
            let body: serde_json::Value = resp.json().await.unwrap();
            if !body["invites"].as_array().unwrap().is_empty() {
                found = true;
                break;
            }
        }
        assert!(found, "invite did not arrive at B");

        // Reject the invite
        let a_id = hex::encode(agent_a.agent_id().0);
        let resp = client
            .post(format!("{url_b}/invites/{group_id}/reject"))
            .json(&serde_json::json!({ "sender": a_id }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Invites list should now be empty
        let resp = client.get(format!("{url_b}/invites")).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["invites"].as_array().unwrap().is_empty(),
            "invites should be empty after reject"
        );

        // B should NOT be in the group
        let resp = client.get(format!("{url_b}/groups")).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["groups"].as_array().unwrap().is_empty(),
            "B should have no groups after rejecting"
        );
    }
}
