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
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(config.api_address)
        .await
        .context("failed to bind API address")?;
    tracing::info!("API server listening on {}", config.api_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("API server error")?;

    tracing::info!("Shutdown complete");
    Ok(())
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
