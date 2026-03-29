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
//! x0xd --name alice                     # run a named instance (separate identity)
//! x0xd --list                           # list running instances
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
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tokio::signal;
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tower_http::cors::CorsLayer;
use x0x::contacts::{ContactStore, IdentityType, MachineRecord, TrustLevel};
use x0x::identity::AgentId;
use x0x::identity::MachineId;
use x0x::network::NetworkConfig;
use x0x::upgrade::manifest::{decode_signed_manifest, is_newer, ReleaseManifest, RELEASE_TOPIC};
use x0x::upgrade::monitor::UpgradeMonitor;
use x0x::upgrade::signature::verify_manifest_signature;
use x0x::{Agent, KvStoreHandle, TaskListHandle};

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
    /// Defaults to the hardcoded global bootstrap network if not specified.
    #[serde(default = "default_bootstrap_peers")]
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

    /// Instance name for multi-agent support.
    /// When set, identity and data are scoped to this name.
    #[serde(default)]
    instance_name: Option<String>,
}

/// Default QUIC port: 5483 (LIVE on a phone keypad).
/// Every x0x node uses the same well-known port by default.
pub const DEFAULT_QUIC_PORT: u16 = 5483;

fn default_bootstrap_peers() -> Vec<SocketAddr> {
    x0x::network::DEFAULT_BOOTSTRAP_PEERS
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn default_bind_address() -> SocketAddr {
    // Bind to IPv6 unspecified ([::]) which accepts both IPv4 and IPv6
    // via dual-stack sockets. This avoids port conflicts on macOS where
    // binding 0.0.0.0:port prevents a subsequent [::]:port bind.
    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], DEFAULT_QUIC_PORT))
}

fn default_api_address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 12700))
}

fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("x0x"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/x0x"))
}

/// Shared cache directory used by ALL instances (not per-instance).
/// This is always the base `x0x` dir, never `x0x-<name>`.
fn shared_cache_dir() -> PathBuf {
    let dir = dirs::data_dir()
        .map(|d| d.join("x0x"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/x0x"));
    // Ensure it exists
    let _ = std::fs::create_dir_all(&dir);
    dir
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
            instance_name: None,
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
    subscriptions: RwLock<HashMap<String, String>>,
    task_lists: RwLock<HashMap<String, TaskListHandle>>,
    kv_stores: RwLock<HashMap<String, KvStoreHandle>>,
    named_groups: RwLock<HashMap<String, x0x::groups::GroupInfo>>,
    named_groups_path: PathBuf,
    contacts: Arc<RwLock<ContactStore>>,
    mls_groups: RwLock<HashMap<String, x0x::mls::MlsGroup>>,
    #[allow(dead_code)]
    mls_groups_path: PathBuf,
    /// Active WebSocket sessions.
    ws_sessions: RwLock<HashMap<String, WsSession>>,
    /// Shared WS topic state (single lock for channel + subscribers + forwarder per topic).
    ws_topics: RwLock<HashMap<String, SharedTopicState>>,
    api_address: SocketAddr,
    start_time: Instant,
    broadcast_tx: broadcast::Sender<SseEvent>,
    /// Active file transfers.
    file_transfers: RwLock<HashMap<String, x0x::files::TransferState>>,
    /// Incremental SHA-256 hashers for receiving transfers.
    receive_hashers: RwLock<HashMap<String, Sha256>>,
    /// Directory for received file data.
    transfers_dir: PathBuf,
    /// Channel to trigger graceful shutdown from the /shutdown endpoint.
    shutdown_tx: mpsc::Sender<()>,
    /// Broadcasts daemon shutdown so long-lived SSE/WS connections can close.
    shutdown_notify: watch::Sender<bool>,
    /// API bearer token for authenticating local clients.
    api_token: String,
}

// ---------------------------------------------------------------------------
// WebSocket types
// ---------------------------------------------------------------------------

/// State for a single WebSocket connection.
struct WsSession {
    /// Unique session identifier (UUID v4).
    id: String,
    /// Topics this session subscribed to.
    subscribed_topics: HashSet<String>,
    /// Whether this session receives direct messages.
    receives_direct: bool,
    /// Handles for spawned per-session forwarder tasks (aborted on cleanup).
    forwarder_handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Shared state for a single gossip topic subscription shared across WS sessions.
struct SharedTopicState {
    /// Broadcast channel that all WS sessions for this topic tap.
    channel: broadcast::Sender<WsOutbound>,
    /// Session IDs currently subscribed to this topic.
    subscribers: HashSet<String>,
    /// Gossip forwarder task handle (aborted when last subscriber leaves).
    forwarder: tokio::task::JoinHandle<()>,
}

/// Server → Client WebSocket message.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
enum WsOutbound {
    #[serde(rename = "connected")]
    Connected {
        session_id: String,
        agent_id: String,
    },
    #[serde(rename = "message")]
    Message {
        topic: String,
        payload: String,
        origin: Option<String>,
    },
    #[serde(rename = "direct_message")]
    DirectMessage {
        sender: String,
        machine_id: String,
        payload: String,
        received_at: u64,
    },
    #[serde(rename = "subscribed")]
    Subscribed { topics: Vec<String> },
    #[serde(rename = "unsubscribed")]
    Unsubscribed { topics: Vec<String> },
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "error")]
    Error { message: String },
}

/// Client → Server WebSocket command.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WsInbound {
    #[serde(rename = "subscribe")]
    Subscribe { topics: Vec<String> },
    #[serde(rename = "unsubscribe")]
    Unsubscribe { topics: Vec<String> },
    #[serde(rename = "publish")]
    Publish { topic: String, payload: String },
    #[serde(rename = "send_direct")]
    SendDirect { agent_id: String, payload: String },
    #[serde(rename = "ping")]
    Ping,
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
    #[serde(default)]
    description: Option<String>,
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
    trust_level: Option<String>,
    /// New identity type: "anonymous", "known", "trusted", or "pinned".
    identity_type: Option<String>,
}

/// POST /contacts/:agent_id/machines request body.
#[derive(Debug, Deserialize)]
struct AddMachineRequest {
    /// Machine ID as 64-character hex string.
    machine_id: String,
    /// Optional human-readable label.
    label: Option<String>,
    /// Whether to pin this machine immediately.
    #[serde(default)]
    pinned: bool,
}

/// Machine record entry for API responses.
#[derive(Debug, Serialize)]
struct MachineEntry {
    machine_id: String,
    label: Option<String>,
    first_seen: u64,
    last_seen: u64,
    pinned: bool,
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

/// Rich runtime status response.
#[derive(Debug, Serialize)]
struct StatusData {
    status: String,
    version: String,
    uptime_secs: u64,
    api_address: String,
    external_addrs: Vec<String>,
    agent_id: String,
    peers: usize,
    warnings: Vec<String>,
}

/// Agent identity response.
#[derive(Debug, Serialize)]
struct AgentData {
    agent_id: String,
    machine_id: String,
    user_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Direct messaging request / response types
// ---------------------------------------------------------------------------

/// POST /agents/connect request body.
#[derive(Debug, Deserialize)]
struct ConnectAgentRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
}

/// POST /direct/send request body.
#[derive(Debug, Deserialize)]
struct DirectSendRequest {
    /// Target agent ID as 64-character hex string.
    agent_id: String,
    /// Base64-encoded payload.
    payload: String,
}

// ---------------------------------------------------------------------------
// MLS request / response types
// ---------------------------------------------------------------------------

/// POST /mls/groups request body.
#[derive(Debug, Deserialize)]
struct CreateMlsGroupRequest {
    /// Optional group ID as hex string. Random if omitted.
    group_id: Option<String>,
}

/// POST /mls/groups/:id/members request body.
#[derive(Debug, Deserialize)]
struct AddMlsMemberRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
}

/// POST /mls/groups/:id/encrypt request body.
#[derive(Debug, Deserialize)]
struct MlsEncryptRequest {
    /// Base64-encoded plaintext.
    payload: String,
}

/// POST /mls/groups/:id/decrypt request body.
#[derive(Debug, Deserialize)]
struct MlsDecryptRequest {
    /// Base64-encoded ciphertext.
    ciphertext: String,
    /// Epoch used for encryption.
    epoch: u64,
}

/// POST /contacts/:agent_id/revoke request body.
#[derive(Debug, Deserialize)]
struct RevokeContactRequest {
    /// Reason for revocation.
    reason: String,
}

/// POST /trust/evaluate request body.
#[derive(Debug, Deserialize)]
struct EvaluateTrustRequest {
    /// Agent ID as hex string.
    agent_id: String,
    /// Machine ID as hex string.
    machine_id: String,
}

/// POST /mls/groups/:id/welcome request body.
#[derive(Debug, Deserialize)]
struct CreateWelcomeRequest {
    /// Invitee agent ID as hex string.
    agent_id: String,
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
    let doctor_mode = args.iter().any(|arg| arg == "doctor" || arg == "--doctor");

    // Parse --name for multi-instance support
    let instance_name = if let Some(idx) = args.iter().position(|a| a == "--name") {
        let name = args
            .get(idx + 1)
            .context("--name requires an instance name")?
            .clone();
        validate_instance_name(&name)?;
        Some(name)
    } else {
        None
    };

    // Handle --list: discover running instances and exit
    if args.contains(&"--list".to_string()) {
        list_instances().await?;
        return Ok(());
    }

    let mut config = match &config_path {
        Some(path) => load_config(path).await?,
        None => {
            let config_dir_name = match &instance_name {
                Some(name) => format!("x0x-{name}"),
                None => "x0x".to_string(),
            };
            let default_path = dirs::config_dir()
                .map(|d| d.join(&config_dir_name).join("config.toml"))
                .unwrap_or_else(|| PathBuf::from("/etc/x0x/config.toml"));
            if default_path.exists() {
                load_config(default_path.to_str().unwrap_or("/etc/x0x/config.toml")).await?
            } else {
                DaemonConfig::default()
            }
        }
    };

    // CLI --name takes precedence over config file instance_name
    let instance_name = instance_name.or_else(|| config.instance_name.clone());

    // Apply instance-scoped defaults for data_dir and api_address when --name
    // is active but the config didn't explicitly set instance-scoped values.
    if let Some(ref name) = instance_name {
        let default_data_dir = default_data_dir();
        if config.data_dir == default_data_dir {
            config.data_dir = dirs::data_dir()
                .map(|d| d.join(format!("x0x-{name}")))
                .unwrap_or_else(|| PathBuf::from(format!("/var/lib/x0x-{name}")));
        }
        if config.api_address == default_api_address() {
            config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
        }
        config.instance_name = Some(name.clone());
    }

    init_logging(&config.log_level, &config.log_format)?;

    if doctor_mode {
        return run_doctor(&config).await;
    }

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
    if let Some(ref name) = instance_name {
        tracing::info!("Instance name: {name}");
    }
    tracing::info!("API address: {}", config.api_address);

    // Promote IPv4 unspecified (0.0.0.0) to IPv6 unspecified (::) for dual-stack.
    // An IPv6 socket with IPV6_V6ONLY=false accepts both IPv4 and IPv6 traffic,
    // avoiding port conflicts when multiple instances run on the same machine.
    let bind_address = if config.bind_address.ip().is_unspecified() && config.bind_address.is_ipv4()
    {
        let promoted = SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            config.bind_address.port(),
        );
        tracing::info!(
            "Bind address: {} (promoted to {} for dual-stack)",
            config.bind_address,
            promoted
        );
        promoted
    } else {
        tracing::info!("Bind address: {}", config.bind_address);
        config.bind_address
    };

    // Derive instance-scoped identity directory
    let identity_dir = match &instance_name {
        Some(name) => {
            let dir = dirs::home_dir()
                .context("home directory required for instance identity directory")?
                .join(format!(".x0x-{name}"));
            tokio::fs::create_dir_all(&dir)
                .await
                .context("failed to create instance identity directory")?;
            tracing::info!("Identity directory: {}", dir.display());
            Some(dir)
        }
        None => None,
    };

    // Create agent
    let network_config = NetworkConfig {
        bind_addr: Some(bind_address),
        bootstrap_nodes: config.bootstrap_peers.clone(),
        max_connections: 50,
        connection_timeout: std::time::Duration::from_secs(30),
        stats_interval: std::time::Duration::from_secs(60),
        // Shared peer cache across ALL instances (not per-instance)
        peer_cache_path: Some(shared_cache_dir().join("peers.cache")),
        pinned_bootstrap_peers: std::collections::HashSet::new(),
        inbound_allowlist: std::collections::HashSet::new(),
        max_peers_per_ip: 3,
    };

    let mut builder = Agent::builder()
        .with_network_config(network_config)
        .with_peer_cache_dir(shared_cache_dir().join("peers"))
        .with_heartbeat_interval(config.heartbeat_interval_secs)
        .with_identity_ttl(config.identity_ttl_secs);

    if let Some(ref id_dir) = identity_dir {
        builder = builder
            .with_machine_key(id_dir.join("machine.key"))
            .with_agent_key_path(id_dir.join("agent.key"));
    }

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

    // MLS groups are session-scoped (saorsa-mls groups are not serializable)
    let mls_groups_path = config.data_dir.join("mls_groups.bin");
    let mls_groups: HashMap<String, x0x::mls::MlsGroup> = HashMap::new();

    // Load named groups from disk (if any)
    let named_groups_path = config.data_dir.join("named_groups.json");
    let named_groups = match tokio::fs::read_to_string(&named_groups_path).await {
        Ok(json) => match serde_json::from_str::<HashMap<String, x0x::groups::GroupInfo>>(&json) {
            Ok(groups) => {
                tracing::info!(
                    "Loaded {} named groups from {}",
                    groups.len(),
                    named_groups_path.display()
                );
                groups
            }
            Err(e) => {
                tracing::warn!("Failed to parse named groups file, starting fresh: {e}");
                HashMap::new()
            }
        },
        Err(_) => {
            tracing::info!("No named groups file found, starting fresh");
            HashMap::new()
        }
    };

    // Load or generate API bearer token for local authentication.
    let api_token = load_or_generate_api_token(&config.data_dir).await?;

    // Bind the API listener early so the daemon can report the actual bound
    // address even when configured with an ephemeral port.
    let listener = tokio::net::TcpListener::bind(config.api_address)
        .await
        .context("failed to bind API address")?;
    let actual_api_addr = listener.local_addr()?;

    // Build shared state BEFORE joining network so the API server can
    // start immediately. Network-dependent endpoints will return errors
    // until join completes, which is better than blocking the entire API.
    let (broadcast_tx, _) = broadcast::channel::<SseEvent>(256);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let (shutdown_notify, _) = watch::channel(false);
    let agent = Arc::new(agent);
    let state = Arc::new(AppState {
        agent: Arc::clone(&agent),
        subscriptions: RwLock::new(HashMap::new()),
        task_lists: RwLock::new(HashMap::new()),
        kv_stores: RwLock::new(HashMap::new()),
        named_groups: RwLock::new(named_groups),
        named_groups_path,
        contacts,
        mls_groups: RwLock::new(mls_groups),
        mls_groups_path,
        ws_sessions: RwLock::new(HashMap::new()),
        ws_topics: RwLock::new(HashMap::new()),
        api_address: actual_api_addr,
        start_time: Instant::now(),
        broadcast_tx,
        file_transfers: RwLock::new(HashMap::new()),
        receive_hashers: RwLock::new(HashMap::new()),
        transfers_dir: config.data_dir.join("transfers"),
        shutdown_tx,
        shutdown_notify,
        api_token,
    });

    // Join network in background — API is available immediately
    let join_agent = Arc::clone(&agent);
    let rendezvous_enabled = config.rendezvous_enabled;
    let rendezvous_validity_ms = config.rendezvous_validity_ms;
    tokio::spawn(async move {
        match join_agent.join_network().await {
            Ok(()) => {
                tracing::info!("Network joined");
                if rendezvous_enabled {
                    if let Err(e) = join_agent.advertise_identity(rendezvous_validity_ms).await {
                        tracing::warn!("Initial rendezvous advertisement failed: {e}");
                    } else {
                        tracing::info!("Rendezvous advertisement published");
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to join network: {e}");
            }
        }
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

    // Background file-message listener — processes FileMessage on the direct channel
    {
        let file_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = tokio::fs::create_dir_all(&file_state.transfers_dir).await {
                tracing::error!("Failed to create transfers dir: {e}");
            }
            let mut rx = file_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(file_msg) = serde_json::from_slice::<x0x::files::FileMessage>(&msg.payload)
                else {
                    continue; // not a file message
                };
                handle_file_message(&file_state, &msg.sender, file_msg).await;
            }
        });
    }

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/agent", get(agent_info))
        .route("/agent/card", get(get_agent_card))
        .route("/agent/card/import", post(import_agent_card))
        .route("/announce", post(announce_identity))
        .route("/peers", get(peers))
        .route("/network/status", get(network_status))
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
        .route(
            "/contacts/:agent_id/machines",
            get(list_machines).post(add_machine),
        )
        .route(
            "/contacts/:agent_id/machines/:machine_id",
            delete(delete_machine),
        )
        .route("/task-lists", get(list_task_lists))
        .route("/task-lists", post(create_task_list))
        .route("/task-lists/:id/tasks", get(list_tasks))
        .route("/task-lists/:id/tasks", post(add_task))
        .route("/task-lists/:id/tasks/:tid", patch(update_task))
        // Named group endpoints
        .route("/groups", post(create_named_group))
        .route("/groups", get(list_named_groups))
        .route("/groups/:id", get(get_named_group))
        .route("/groups/:id/invite", post(create_group_invite))
        .route("/groups/join", post(join_group_via_invite))
        .route("/groups/:id/display-name", put(set_group_display_name))
        .route("/groups/:id", delete(leave_group))
        // KvStore endpoints
        .route("/stores", get(list_kv_stores))
        .route("/stores", post(create_kv_store))
        .route("/stores/:id/join", post(join_kv_store))
        .route("/stores/:id/keys", get(list_kv_keys))
        .route("/stores/:id/:key", get(get_kv_value))
        .route("/stores/:id/:key", put(put_kv_value))
        .route("/stores/:id/:key", delete(delete_kv_value))
        // Direct messaging endpoints
        .route("/agents/connect", post(connect_agent))
        .route("/direct/send", post(direct_send))
        .route("/direct/connections", get(direct_connections))
        .route("/direct/events", get(direct_events_sse))
        // MLS group encryption endpoints
        .route("/mls/groups", post(create_mls_group))
        .route("/mls/groups", get(list_mls_groups))
        .route("/mls/groups/:id", get(get_mls_group))
        .route("/mls/groups/:id/members", post(add_mls_member))
        .route(
            "/mls/groups/:id/members/:agent_id",
            delete(remove_mls_member),
        )
        .route("/mls/groups/:id/encrypt", post(mls_encrypt))
        .route("/mls/groups/:id/decrypt", post(mls_decrypt))
        // Agent discovery & connectivity
        .route("/agents/find/:agent_id", post(find_agent))
        .route("/agents/reachability/:agent_id", get(agent_reachability))
        // Contact trust extensions
        .route("/contacts/:agent_id/revoke", post(revoke_contact))
        .route("/contacts/:agent_id/revocations", get(list_revocations))
        .route(
            "/contacts/:agent_id/machines/:machine_id/pin",
            post(pin_machine).delete(unpin_machine),
        )
        // Trust evaluation
        .route("/trust/evaluate", post(evaluate_trust))
        // MLS welcome
        .route("/mls/groups/:id/welcome", post(create_mls_welcome))
        // Upgrade
        .route("/upgrade", get(check_upgrade))
        // Network diagnostics
        .route("/network/bootstrap-cache", get(bootstrap_cache_stats))
        // WebSocket endpoints
        .route("/ws", get(ws_handler))
        .route("/ws/direct", get(ws_direct_handler))
        .route("/ws/sessions", get(ws_sessions))
        .route("/shutdown", post(shutdown_handler))
        // File transfer endpoints
        .route("/files/send", post(file_send_handler))
        .route("/files/transfers", get(file_transfers_handler))
        .route("/files/transfers/:id", get(file_transfer_status_handler))
        .route("/files/accept/:id", post(file_accept_handler))
        .route("/files/reject/:id", post(file_reject_handler))
        // Constitution
        .route("/constitution", get(get_constitution))
        .route("/constitution/json", get(get_constitution_json))
        // Embedded GUI
        .route("/gui", get(serve_gui))
        .route("/gui/", get(serve_gui))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1 MB
        .layer({
            // Restrict CORS to localhost origins only.
            // The daemon API is a local control plane — external origins must not access it.
            use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin};
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin, _| {
                    let o = origin.as_bytes();
                    o.starts_with(b"http://127.0.0.1")
                        || o.starts_with(b"http://localhost")
                        || o.starts_with(b"http://[::1]")
                }))
                .allow_methods(AllowMethods::any())
                .allow_headers(AllowHeaders::any())
        })
        // Bearer-token authentication: all endpoints except /health and /gui
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth_middleware,
        ))
        .with_state(Arc::clone(&state));

    // Start server
    let port_file = config.data_dir.join("api.port");
    tokio::fs::write(&port_file, actual_api_addr.to_string()).await?;
    tracing::info!(
        "API server listening on {actual_api_addr} (port file: {})",
        port_file.display()
    );

    let mut server_shutdown_rx = state.shutdown_notify.subscribe();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = server_shutdown_rx.changed().await;
            })
            .await
    });

    tokio::select! {
        _ = signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C shutdown signal");
        }
        _ = shutdown_rx.recv() => {
            tracing::info!("Received API shutdown request");
        }
    }

    let _ = state.shutdown_notify.send(true);

    match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => return Err(anyhow::Error::new(e).context("API server error")),
        Ok(Err(e)) => return Err(anyhow::Error::new(e).context("API server task failed")),
        Err(_) => {
            tracing::warn!(
                "API server did not shut down within 2s; aborting lingering connections"
            );
            server.abort();
            let _ = server.await;
        }
    }

    // Clean up port file on shutdown
    let _ = tokio::fs::remove_file(&port_file).await;
    state.agent.shutdown().await;
    tracing::info!("Shutdown complete");
    Ok(())
}

/// Bearer-token authentication middleware.
///
/// Exempts:
/// - `OPTIONS` (CORS preflight — browsers send these without auth headers)
/// - `/health`, `/gui`, `/gui/` (must be accessible without a token)
///
/// Accepts `?token=` query parameter on endpoints that browsers cannot send
/// headers on: WebSocket (`/ws`, `/ws/direct`) and SSE (`/events`,
/// `/direct/events`).
///
/// All other endpoints require `Authorization: Bearer <token>`.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // CORS preflight: browsers send OPTIONS without auth headers
    if req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }

    let path = req.uri().path();

    // Exempt: health check, GUI serving, and constitution
    if path == "/health" || path == "/gui" || path == "/gui/" || path.starts_with("/constitution") {
        return next.run(req).await;
    }

    // Check Authorization: Bearer header first (works everywhere)
    if let Some(auth) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if token == state.api_token {
                    return next.run(req).await;
                }
            }
        }
    }

    // Endpoints where browsers cannot set headers: accept ?token= query param.
    // WebSocket upgrades and SSE (EventSource API has no header support).
    let accepts_query_token = matches!(path, "/ws" | "/ws/direct" | "/events" | "/direct/events");
    if accepts_query_token {
        if let Some(query) = req.uri().query() {
            for pair in query.split('&') {
                if let Some(token) = pair.strip_prefix("token=") {
                    if token == state.api_token {
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "missing or invalid Authorization: Bearer token"})),
    )
        .into_response()
}

/// Load or generate an API bearer token.
///
/// Reads from `<data_dir>/api-token`. If the file does not exist, generates a
/// random 32-byte hex token and writes it with 0600 permissions.
async fn load_or_generate_api_token(data_dir: &std::path::Path) -> Result<String> {
    let token_path = data_dir.join("api-token");

    // Try to load existing token
    if token_path.exists() {
        let token = tokio::fs::read_to_string(&token_path)
            .await
            .context("failed to read api-token")?
            .trim()
            .to_string();
        if token.len() >= 32 {
            tracing::info!("API token loaded from {}", token_path.display());
            return Ok(token);
        }
    }

    // Generate new token
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);

    tokio::fs::write(&token_path, &token)
        .await
        .context("failed to write api-token")?;

    // Set permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&token_path, perms)
            .await
            .context("failed to set api-token permissions")?;
    }

    tracing::info!("API token generated at {}", token_path.display());
    Ok(token)
}

fn validate_instance_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        anyhow::bail!("instance name must be 1-64 characters");
    }
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !valid {
        anyhow::bail!(
            "instance name must start with alphanumeric and contain only alphanumeric or hyphens"
        );
    }
    Ok(())
}

async fn list_instances() -> Result<()> {
    let data_base = dirs::data_dir().context("cannot determine data directory")?;

    // Collect candidate directories: x0x and x0x-*
    let mut instances: Vec<(String, PathBuf)> = Vec::new();

    let default_port_file = data_base.join("x0x").join("api.port");
    if default_port_file.exists() {
        instances.push(("(default)".to_string(), default_port_file));
    }

    if let Ok(mut entries) = tokio::fs::read_dir(&data_base).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(instance) = name_str.strip_prefix("x0x-") {
                let port_file = entry.path().join("api.port");
                if port_file.exists() {
                    instances.push((instance.to_string(), port_file));
                }
            }
        }
    }

    if instances.is_empty() {
        println!("No running instances found.");
        return Ok(());
    }

    let name_width = instances
        .iter()
        .map(|(n, _)| n.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!("{:<name_width$}  {:<21}  {:<10}", "NAME", "API", "STATUS");
    for (name, port_file) in &instances {
        let addr = tokio::fs::read_to_string(port_file)
            .await
            .unwrap_or_default();
        let addr = addr.trim().to_string();

        let status = if !addr.is_empty() {
            match reqwest::Client::new()
                .get(format!("http://{addr}/health"))
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => "running",
                _ => "stale",
            }
        } else {
            "stale"
        };
        println!("{:<name_width$}  {:<21}  {:<10}", name, addr, status);
    }
    Ok(())
}

/// POST /shutdown — trigger graceful daemon shutdown.
async fn shutdown_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    tracing::info!("Shutdown requested via API");
    let _ = state.shutdown_notify.send(true);
    let _ = state.shutdown_tx.send(()).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "message": "shutting down"})),
    )
}

// ---------------------------------------------------------------------------
// File transfer endpoints
// ---------------------------------------------------------------------------

/// POST /files/send — initiate a file transfer to an agent.
async fn file_send_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id_hex = body.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
    let filename = body
        .get("filename")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed");
    let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
    let sha256 = body.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
    let source_path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");

    if agent_id_hex.is_empty() || sha256.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "agent_id and sha256 are required"})),
        );
    }

    let agent_id = match parse_agent_id_hex(agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": e})),
            );
        }
    };

    let transfer_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let total_chunks = if size == 0 {
        0
    } else {
        size.div_ceil(chunk_size as u64)
    };

    let transfer = x0x::files::TransferState {
        transfer_id: transfer_id.clone(),
        direction: x0x::files::TransferDirection::Sending,
        remote_agent_id: agent_id_hex.to_string(),
        filename: filename.to_string(),
        total_size: size,
        bytes_transferred: 0,
        status: x0x::files::TransferStatus::Pending,
        sha256: sha256.to_string(),
        error: None,
        started_at: now,
        source_path: if source_path.is_empty() {
            None
        } else {
            Some(source_path.to_string())
        },
        output_path: None,
        chunk_size,
        total_chunks,
    };

    state
        .file_transfers
        .write()
        .await
        .insert(transfer_id.clone(), transfer);

    // Send offer to remote agent via direct messaging
    let offer = x0x::files::FileMessage::Offer(x0x::files::FileOffer {
        transfer_id: transfer_id.clone(),
        filename: filename.to_string(),
        size,
        sha256: sha256.to_string(),
        chunk_size,
        total_chunks,
    });

    match serde_json::to_vec(&offer) {
        Ok(payload) => match state.agent.send_direct(&agent_id, payload).await {
            Ok(()) => {
                tracing::info!("File offer sent: {transfer_id} -> {agent_id_hex}");
                (
                    StatusCode::OK,
                    Json(serde_json::json!({"ok": true, "transfer_id": transfer_id})),
                )
            }
            Err(e) => {
                tracing::error!("Failed to send file offer: {e}");
                let mut transfers = state.file_transfers.write().await;
                if let Some(t) = transfers.get_mut(&transfer_id) {
                    t.status = x0x::files::TransferStatus::Failed;
                    t.error = Some(format!("Failed to send offer: {e}"));
                }
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(
                        serde_json::json!({"ok": false, "error": format!("send offer failed: {e}")}),
                    ),
                )
            }
        },
        Err(e) => {
            tracing::error!("Failed to serialize file offer: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "serialization failed"})),
            )
        }
    }
}

/// GET /files/transfers — list all file transfers.
async fn file_transfers_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let transfers = state.file_transfers.read().await;
    let list: Vec<&x0x::files::TransferState> = transfers.values().collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "transfers": list})),
    )
}

/// GET /files/transfers/:id — get a single transfer's status.
async fn file_transfer_status_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let transfers = state.file_transfers.read().await;
    match transfers.get(&id) {
        Some(t) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "transfer": t})),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "transfer not found"})),
        ),
    }
}

/// POST /files/accept/:id — accept an incoming transfer.
async fn file_accept_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let remote_agent_hex;
    {
        let mut transfers = state.file_transfers.write().await;
        match transfers.get_mut(&id) {
            Some(t)
                if t.status == x0x::files::TransferStatus::Pending
                    && t.direction == x0x::files::TransferDirection::Receiving =>
            {
                t.status = x0x::files::TransferStatus::InProgress;
                remote_agent_hex = t.remote_agent_id.clone();
            }
            Some(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"ok": false, "error": "transfer is not a pending receive"}),
                    ),
                );
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"ok": false, "error": "transfer not found"})),
                );
            }
        }
    }

    // Send accept message back to the sender
    let agent_id = match parse_agent_id_hex(&remote_agent_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": e})),
            );
        }
    };

    let accept_msg = x0x::files::FileMessage::Accept {
        transfer_id: id.clone(),
    };
    let delivery_failed = match serde_json::to_vec(&accept_msg) {
        Ok(payload) => match state.agent.send_direct(&agent_id, payload).await {
            Ok(()) => {
                tracing::info!("File accept sent: {id} -> {remote_agent_hex}");
                false
            }
            Err(e) => {
                tracing::warn!("Failed to send accept to sender: {e}");
                true
            }
        },
        Err(_) => true,
    };

    if delivery_failed {
        // Revert to Pending so the accept can be retried
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&id) {
            t.status = x0x::files::TransferStatus::Pending;
        }
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({"ok": false, "error": "accepted but failed to notify sender — reverted to pending"}),
            ),
        )
    } else {
        (StatusCode::OK, Json(serde_json::json!({"ok": true})))
    }
}

/// POST /files/reject/:id — reject an incoming transfer.
async fn file_reject_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let reason = body
        .as_ref()
        .and_then(|b| b.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("rejected by user")
        .to_string();

    let remote_agent_hex;
    {
        let mut transfers = state.file_transfers.write().await;
        match transfers.get_mut(&id) {
            Some(t) if t.status == x0x::files::TransferStatus::Pending => {
                t.status = x0x::files::TransferStatus::Rejected;
                t.error = Some(reason.clone());
                remote_agent_hex = t.remote_agent_id.clone();
            }
            Some(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"ok": false, "error": "transfer is not pending"})),
                );
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"ok": false, "error": "transfer not found"})),
                );
            }
        }
    }

    // Send reject message back to the sender
    let mut delivery_failed = false;
    if let Ok(agent_id) = parse_agent_id_hex(&remote_agent_hex) {
        let reject_msg = x0x::files::FileMessage::Reject {
            transfer_id: id.clone(),
            reason,
        };
        if let Ok(payload) = serde_json::to_vec(&reject_msg) {
            if let Err(e) = state.agent.send_direct(&agent_id, payload).await {
                tracing::warn!("Failed to send reject to sender: {e}");
                delivery_failed = true;
            }
        }
    }

    if delivery_failed {
        (
            StatusCode::OK,
            Json(
                serde_json::json!({"ok": true, "warning": "rejected locally but failed to notify sender"}),
            ),
        )
    } else {
        (StatusCode::OK, Json(serde_json::json!({"ok": true})))
    }
}

// ---------------------------------------------------------------------------
// Doctor — local/runtime diagnostics
// ---------------------------------------------------------------------------

async fn run_doctor(config: &DaemonConfig) -> Result<()> {
    let mut warnings = 0usize;
    let mut failures = 0usize;

    let print_pass = |msg: &str| println!("PASS  {msg}");
    let mut print_warn = |msg: &str| {
        warnings += 1;
        println!("WARN  {msg}");
    };
    let mut print_fail = |msg: &str| {
        failures += 1;
        println!("FAIL  {msg}");
    };

    println!("x0xd doctor");
    println!("-----------");

    // Binary location
    match std::env::current_exe() {
        Ok(path) => print_pass(&format!("binary: {}", path.display())),
        Err(err) => print_warn(&format!("could not determine binary path: {err}")),
    }

    // PATH check
    let in_path = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join("x0xd").exists()))
        .unwrap_or(false);
    if in_path {
        print_pass("x0xd found on PATH");
    } else {
        print_warn("x0xd not found on PATH");
    }

    print_pass("configuration loaded");

    // Probe daemon endpoints
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client")?;

    let base = format!("http://{}", config.api_address);
    let mut daemon_reachable = false;

    match client.get(format!("{base}/health")).send().await {
        Ok(resp) if resp.status().is_success() => {
            daemon_reachable = true;
            print_pass(&format!("daemon reachable at {}", config.api_address));
            match resp.json::<serde_json::Value>().await {
                Ok(body) if body.get("ok").and_then(|v| v.as_bool()) == Some(true) => {
                    print_pass("/health ok=true");
                }
                Ok(body) => print_warn(&format!("/health unexpected payload: {body}")),
                Err(err) => print_warn(&format!("/health invalid JSON: {err}")),
            }
        }
        Ok(resp) => print_warn(&format!("/health HTTP {}", resp.status())),
        Err(err) => print_warn(&format!(
            "daemon not reachable at {}: {err}",
            config.api_address
        )),
    }

    if daemon_reachable {
        // /agent check
        if let Ok(resp) = client.get(format!("{base}/agent")).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    let has_id = body
                        .get("agent_id")
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| !v.is_empty());
                    if has_id {
                        print_pass("/agent returned agent_id");
                    } else {
                        print_warn("/agent response missing agent_id");
                    }
                }
            }
        }

        // /status check
        if let Ok(resp) = client.get(format!("{base}/status")).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    let state = body
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    print_pass(&format!("/status connectivity: {state}"));
                }
            }
        }
    } else {
        // Check if port is free (daemon not running) or blocked (conflict)
        match tokio::net::TcpListener::bind(config.api_address).await {
            Ok(listener) => {
                drop(listener);
                print_warn(&format!(
                    "daemon not running (port {} is free)",
                    config.api_address.port()
                ));
            }
            Err(err) => {
                print_fail(&format!(
                    "port {} in use by another process: {err}",
                    config.api_address.port()
                ));
            }
        }
    }

    println!("-----------");
    if failures > 0 {
        println!("FAIL  {failures} failure(s), {warnings} warning(s)");
        anyhow::bail!("doctor detected failures")
    } else if warnings > 0 {
        println!("WARN  {warnings} warning(s)");
        Ok(())
    } else {
        println!("PASS  all checks passed");
        Ok(())
    }
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

/// GET /status — rich runtime status with connectivity state machine.
async fn status(State(state): State<Arc<AppState>>) -> Json<ApiResponse<StatusData>> {
    let uptime_secs = state.start_time.elapsed().as_secs();
    let mut warnings = Vec::new();

    let peers = match state.agent.peers().await {
        Ok(peer_list) => peer_list.len(),
        Err(err) => {
            warnings.push(format!("failed to query peers: {err}"));
            0
        }
    };

    // Get external addresses: ant-quic observed + local IPv4/IPv6 discovery.
    let mut external_addrs = Vec::new();
    if let Some(network) = state.agent.network() {
        if let Some(ns) = network.node_status().await {
            external_addrs = ns.external_addrs.iter().map(|a| a.to_string()).collect();

            let port = ns.local_addr.port();

            // Discover global IPv4 via UDP socket trick (no data sent).
            if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if sock.connect("8.8.8.8:80").is_ok() {
                    if let Ok(local) = sock.local_addr() {
                        if let std::net::IpAddr::V4(v4) = local.ip() {
                            if !v4.is_loopback() && !v4.is_unspecified() {
                                let addr_str = format!("{v4}:{port}");
                                if !external_addrs.contains(&addr_str) {
                                    external_addrs.push(addr_str);
                                }
                            }
                        }
                    }
                }
            }

            // Discover global IPv6 via UDP socket trick.
            if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
                if sock.connect("[2001:4860:4860::8888]:80").is_ok() {
                    if let Ok(local) = sock.local_addr() {
                        if let std::net::IpAddr::V6(v6) = local.ip() {
                            let segs = v6.segments();
                            let is_global = (segs[0] & 0xffc0) != 0xfe80
                                && (segs[0] & 0xff00) != 0xfd00
                                && !v6.is_loopback();
                            if is_global {
                                let addr_str = format!("[{v6}]:{port}");
                                if !external_addrs.contains(&addr_str) {
                                    external_addrs.push(addr_str);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let connectivity = if !warnings.is_empty() {
        "degraded"
    } else if peers > 0 {
        "connected"
    } else if uptime_secs < 45 {
        "connecting"
    } else {
        "isolated"
    }
    .to_string();

    Json(ApiResponse {
        ok: true,
        data: StatusData {
            status: connectivity,
            version: x0x::VERSION.to_string(),
            uptime_secs,
            api_address: state.api_address.to_string(),
            external_addrs,
            agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            peers,
            warnings,
        },
    })
}

/// GET /network/status — NAT traversal diagnostics and connection stats.
async fn network_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(network) = state.agent.network() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ok": false, "error": "network not initialized" })),
        );
    };

    let Some(status) = network.node_status().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ok": false, "error": "node not available" })),
        );
    };

    let nat_type_str = format!("{:?}", status.nat_type);

    // Collect all known addresses: ant-quic observed + local global IPv6.
    // ant-quic currently only reports IPv4 via OBSERVED_ADDRESS frames,
    // so we detect our global IPv6 locally using a UDP socket connect trick
    // (no data sent — the OS routing table resolves our source address).
    let mut all_addrs: Vec<String> = status
        .external_addrs
        .iter()
        .map(|a| a.to_string())
        .collect();

    let port = status.local_addr.port();

    // Discover global IPv4 address using UDP socket trick.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let std::net::IpAddr::V4(v4) = local.ip() {
                    if !v4.is_loopback() && !v4.is_unspecified() {
                        // Use the external IPv4 we saw in ant-quic logs, or local if no NAT
                        // For now, include our local IPv4 — NAT traversal will handle the rest
                        let addr_str = format!("{v4}:{port}");
                        if !all_addrs.contains(&addr_str) {
                            all_addrs.push(addr_str);
                        }
                    }
                }
            }
        }
    }

    // Discover global IPv6 address using UDP socket trick.
    if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
        if sock.connect("[2001:4860:4860::8888]:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let std::net::IpAddr::V6(v6) = local.ip() {
                    let segs = v6.segments();
                    let is_global = (segs[0] & 0xffc0) != 0xfe80  // not link-local
                        && (segs[0] & 0xff00) != 0xfd00           // not ULA
                        && !v6.is_loopback();
                    if is_global {
                        let addr_str = format!("[{v6}]:{port}");
                        if !all_addrs.contains(&addr_str) {
                            all_addrs.push(addr_str);
                        }
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "local_addr": status.local_addr.to_string(),
            "external_addrs": all_addrs,
            "nat_type": nat_type_str,
            "has_public_ip": status.has_public_ip,
            "can_receive_direct": status.can_receive_direct,
            "connected_peers": status.connected_peers,
            "direct_connections": status.direct_connections,
            "relayed_connections": status.relayed_connections,
            "hole_punch_success_rate": status.hole_punch_success_rate,
            "is_relaying": status.is_relaying,
            "relay_sessions": status.relay_sessions,
            "is_coordinating": status.is_coordinating,
            "coordination_sessions": status.coordination_sessions,
            "avg_rtt_ms": status.avg_rtt.as_millis() as u64,
            "uptime_secs": status.uptime.as_secs(),
        })),
    )
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

/// Request body for POST /agent/card/import.
#[derive(Debug, Deserialize)]
struct ImportCardRequest {
    /// Card link (`x0x://agent/...`) or raw base64.
    card: String,
    /// Trust level to assign (default: "known").
    #[serde(default = "default_import_trust")]
    trust_level: String,
}

fn default_import_trust() -> String {
    "known".to_string()
}

/// Request body for GET /agent/card query params.
#[derive(Debug, Deserialize)]
struct CardQuery {
    /// Display name to include in the card.
    #[serde(default)]
    display_name: Option<String>,
    /// Whether to include group invites.
    #[serde(default)]
    include_groups: Option<bool>,
}

/// GET /agent/card — generate a shareable identity card.
async fn get_agent_card(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<CardQuery>,
) -> impl IntoResponse {
    let agent_id = state.agent.agent_id();
    let machine_id = hex::encode(state.agent.machine_id().as_bytes());
    let display_name = query.display_name.unwrap_or_default();

    let mut card = x0x::groups::card::AgentCard::new(display_name, &agent_id, &machine_id);

    // Add user ID if available
    card.user_id = state.agent.user_id().map(|u| hex::encode(u.as_bytes()));

    // Add external addresses from ant-quic NodeStatus
    if let Some(network) = state.agent.network() {
        if let Some(ns) = network.node_status().await {
            card.addresses = ns.external_addrs.iter().map(|a| a.to_string()).collect();
        }
    }

    // Optionally include group invite links
    if query.include_groups.unwrap_or(false) {
        let groups = state.named_groups.read().await;
        for info in groups.values() {
            let invite = x0x::groups::invite::SignedInvite::new(
                info.mls_group_id.clone(),
                info.name.clone(),
                &agent_id,
                x0x::groups::invite::DEFAULT_EXPIRY_SECS,
            );
            card.groups.push(x0x::groups::card::CardGroup {
                name: info.name.clone(),
                invite_link: invite.to_link(),
            });
        }
    }

    // Include stores
    let stores = state.kv_stores.read().await;
    for (topic, _) in stores.iter() {
        card.stores.push(x0x::groups::card::CardStore {
            name: topic.clone(),
            topic: topic.clone(),
        });
    }

    let link = card.to_link();

    Json(serde_json::json!({
        "ok": true,
        "card": card,
        "link": link,
    }))
}

/// POST /agent/card/import — import an agent card to contacts.
async fn import_agent_card(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportCardRequest>,
) -> impl IntoResponse {
    // Parse card
    let card = match x0x::groups::card::AgentCard::from_link(&req.card) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid card: {e}") })),
            );
        }
    };

    // Parse trust level
    let trust = match req.trust_level.to_lowercase().as_str() {
        "trusted" => x0x::contacts::TrustLevel::Trusted,
        "known" => x0x::contacts::TrustLevel::Known,
        "blocked" => x0x::contacts::TrustLevel::Blocked,
        _ => x0x::contacts::TrustLevel::Known,
    };

    // Parse agent ID
    let agent_id_bytes: [u8; 32] = match hex::decode(&card.agent_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "invalid agent_id in card" })),
            );
        }
    };
    let agent_id = x0x::identity::AgentId(agent_id_bytes);

    // Add to contacts
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let contact = x0x::contacts::Contact {
        agent_id,
        trust_level: trust,
        label: Some(card.display_name.clone()),
        added_at: now,
        last_seen: None,
        identity_type: x0x::contacts::IdentityType::default(),
        machines: Vec::new(),
    };

    state.contacts.write().await.add(contact);

    // Also populate the identity discovery cache so connect_to_agent / send_direct
    // can find this agent without waiting for gossip announcements.
    let machine_id_bytes: [u8; 32] = hex::decode(&card.machine_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0u8; 32]);
    let addresses: Vec<std::net::SocketAddr> = card
        .addresses
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect();

    if machine_id_bytes != [0u8; 32] || !addresses.is_empty() {
        state
            .agent
            .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
                agent_id,
                machine_id: x0x::identity::MachineId(machine_id_bytes),
                user_id: None,
                addresses,
                announced_at: now,
                last_seen: now,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
            })
            .await;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "agent_id": card.agent_id,
            "display_name": card.display_name,
            "trust_level": format!("{trust:?}"),
            "groups": card.groups.len(),
            "stores": card.stores.len(),
        })),
    )
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
    // Reject empty topic
    if req.topic.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "topic must not be empty" })),
        );
    }

    // Decode base64 payload
    let payload = match base64::engine::general_purpose::STANDARD.decode(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!(
                        "invalid base64 in payload field: {e}. \
                         The payload must be base64-encoded \
                         (e.g., use `echo -n \"hello\" | base64`)"
                    )
                })),
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
                    tracing::info!(
                        topic = %topic,
                        sub_id = %sub_id,
                        payload_len = msg.payload.len(),
                        "[5/6 x0xd] received from subscriber channel, broadcasting to SSE"
                    );
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
                    match broadcast_tx.send(event) {
                        Ok(n) => tracing::info!(
                            topic = %topic,
                            receivers = n,
                            "[5/6 x0xd] broadcast sent to {n} SSE receivers"
                        ),
                        Err(_) => tracing::warn!(
                            topic = %topic,
                            "[5/6 x0xd] broadcast send failed (no SSE receivers)"
                        ),
                    }
                }
            });

            // Track the subscription ID and topic for unsubscribe.
            // We don't create a second subscription — just record the
            // topic so the DELETE handler can call unsubscribe().
            let mut subs = state.subscriptions.write().await;
            subs.insert(id.clone(), req.topic.clone());

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
    tracing::info!("[6/6 x0xd] SSE client connected to /events");
    let mut rx = state.broadcast_tx.subscribe();
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    tracing::info!("[6/6 x0xd] SSE client closing due to daemon shutdown");
                    break;
                }
                result = rx.recv() => {
                    match result {
                        Ok(event) => {
                            tracing::info!(
                                event_type = %event.event_type,
                                "[6/6 x0xd] SSE delivering event to client"
                            );
                            let data = serde_json::to_string(&event).unwrap_or_default();
                            yield Ok(Event::default().event(event.event_type).data(data));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(skipped, "[6/6 x0xd] SSE client lagged behind broadcast stream");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    };
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
/// Query parameters for `GET /agents/discovered`.
#[derive(Deserialize, Default)]
struct DiscoveredAgentsQuery {
    /// When `true`, return all cache entries including stale (TTL-expired).
    #[serde(default)]
    unfiltered: bool,
}

async fn discovered_agents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiscoveredAgentsQuery>,
) -> impl IntoResponse {
    let result = if query.unfiltered {
        state.agent.discovered_agents_unfiltered().await
    } else {
        state.agent.discovered_agents().await
    };
    match result {
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
        identity_type: x0x::contacts::IdentityType::default(),
        machines: Vec::new(),
    };

    state.contacts.write().await.add(contact);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "agent_id": hex::encode(agent_id.0) })),
    )
}

/// PATCH /contacts/:agent_id — update trust level and/or identity type for a contact.
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

    let mut store = state.contacts.write().await;

    if let Some(ref tl_str) = req.trust_level {
        let trust_level: TrustLevel = match tl_str.parse() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                );
            }
        };
        store.set_trust(&agent_id, trust_level);
    }

    if let Some(ref it_str) = req.identity_type {
        let identity_type: IdentityType = match it_str.parse() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                );
            }
        };
        store.set_identity_type(&agent_id, identity_type);
    }

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// GET /contacts/:agent_id/machines — list machine records for a contact.
async fn list_machines(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };

    let store = state.contacts.read().await;
    let entries: Vec<MachineEntry> = store
        .machines(&agent_id)
        .iter()
        .map(|m| MachineEntry {
            machine_id: hex::encode(m.machine_id.0),
            label: m.label.clone(),
            first_seen: m.first_seen,
            last_seen: m.last_seen,
            pinned: m.pinned,
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "machines": entries })),
    )
        .into_response()
}

/// POST /contacts/:agent_id/machines — add a machine record for a contact.
async fn add_machine(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Json(req): Json<AddMachineRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };

    let machine_bytes = match hex::decode(&req.machine_id) {
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
                    "error": "machine_id must be a 64-character hex string"
                })),
            )
                .into_response();
        }
    };
    let machine_id = MachineId(machine_bytes);

    let record = MachineRecord::new(machine_id, req.label.clone());
    let mut store = state.contacts.write().await;
    let is_new = store.add_machine(&agent_id, record);

    if req.pinned {
        store.pin_machine(&agent_id, &machine_id);
    }

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let entry = MachineEntry {
        machine_id: hex::encode(machine_id.0),
        label: req.label,
        first_seen: store
            .machines(&agent_id)
            .iter()
            .find(|m| m.machine_id == machine_id)
            .map(|m| m.first_seen)
            .unwrap_or(0),
        last_seen: store
            .machines(&agent_id)
            .iter()
            .find(|m| m.machine_id == machine_id)
            .map(|m| m.last_seen)
            .unwrap_or(0),
        pinned: req.pinned,
    };

    (
        status,
        Json(serde_json::json!({ "ok": true, "machine": entry })),
    )
        .into_response()
}

/// DELETE /contacts/:agent_id/machines/:machine_id — remove a machine record.
async fn delete_machine(
    State(state): State<Arc<AppState>>,
    Path((agent_id_hex, machine_id_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };

    let machine_bytes = match hex::decode(&machine_id_hex) {
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
                    "error": "machine_id must be a 64-character hex string"
                })),
            )
                .into_response();
        }
    };
    let machine_id = MachineId(machine_bytes);

    let removed = state
        .contacts
        .write()
        .await
        .remove_machine(&agent_id, &machine_id);
    if removed {
        (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "machine not found" })),
        )
            .into_response()
    }
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

// ---------------------------------------------------------------------------
// Named group handlers
// ---------------------------------------------------------------------------

/// Request body for POST /groups.
#[derive(Debug, Deserialize)]
struct CreateGroupRequest {
    name: String,
    #[serde(default)]
    description: String,
    /// Optional display name for the creator in this group.
    #[serde(default)]
    display_name: Option<String>,
}

/// Request body for POST /groups/join.
#[derive(Debug, Deserialize)]
struct JoinGroupRequest {
    /// Invite link or raw base64 invite token.
    invite: String,
    /// Optional display name for the joiner.
    #[serde(default)]
    display_name: Option<String>,
}

/// Request body for POST /groups/:id/invite.
#[derive(Debug, Deserialize)]
struct CreateInviteRequest {
    /// Seconds until expiry (default: 7 days, 0 = never).
    #[serde(default = "default_expiry")]
    expiry_secs: u64,
}

fn default_expiry() -> u64 {
    x0x::groups::invite::DEFAULT_EXPIRY_SECS
}

/// Request body for PUT /groups/:id/display-name.
#[derive(Debug, Deserialize)]
struct SetDisplayNameRequest {
    name: String,
}

/// POST /groups — create a named group.
async fn create_named_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    // Generate random MLS group ID
    let mut group_id_bytes = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut group_id_bytes);
    let group_id_hex = hex::encode(&group_id_bytes);

    let agent_id = state.agent.agent_id();

    // Create MLS group
    match x0x::mls::MlsGroup::new(group_id_bytes, agent_id).await {
        Ok(group) => {
            // Create group metadata
            let mut info = x0x::groups::GroupInfo::new(
                req.name,
                req.description,
                agent_id,
                group_id_hex.clone(),
            );

            // Set creator's display name if provided
            if let Some(dn) = req.display_name {
                info.set_display_name(hex::encode(agent_id.as_bytes()), dn);
            }

            // Store MLS group
            state
                .mls_groups
                .write()
                .await
                .insert(group_id_hex.clone(), group);
            save_mls_groups(&state).await;

            let chat_topic = info.general_chat_topic();
            let metadata_topic = info.metadata_topic.clone();

            // Store group info and persist to disk
            state
                .named_groups
                .write()
                .await
                .insert(group_id_hex.clone(), info.clone());
            save_named_groups(&state).await;

            // Auto-subscribe to group topics so messages flow immediately
            let _ = state.agent.subscribe(&chat_topic).await;
            let _ = state.agent.subscribe(&metadata_topic).await;

            // Announce creation on the chat topic
            let agent_hex = hex::encode(agent_id.as_bytes());
            let display = info
                .display_names
                .get(&agent_hex)
                .cloned()
                .unwrap_or_else(|| agent_hex[..8].to_string());
            let announcement = serde_json::json!({
                "type": "group_event",
                "event": "created",
                "agent_id": agent_hex,
                "display_name": display,
                "group_name": info.name,
                "ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
            let _ = state
                .agent
                .publish(&chat_topic, announcement.to_string().into_bytes())
                .await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "ok": true,
                    "group_id": group_id_hex,
                    "name": info.name,
                    "chat_topic": chat_topic,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /groups — list all named groups.
async fn list_named_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let entries: Vec<serde_json::Value> = groups
        .values()
        .map(|info| {
            serde_json::json!({
                "group_id": info.mls_group_id,
                "name": info.name,
                "description": info.description,
                "creator": hex::encode(info.creator.as_bytes()),
                "created_at": info.created_at,
                "member_count": info.display_names.len().max(1),
            })
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "groups": entries }))
}

/// GET /groups/:id — get group details.
async fn get_named_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    let members: Vec<serde_json::Value> = info
        .display_names
        .iter()
        .map(|(agent_hex, name)| {
            serde_json::json!({
                "agent_id": agent_hex,
                "display_name": name,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": info.mls_group_id,
            "name": info.name,
            "description": info.description,
            "creator": hex::encode(info.creator.as_bytes()),
            "created_at": info.created_at,
            "chat_topic": info.general_chat_topic(),
            "metadata_topic": info.metadata_topic,
            "members": members,
        })),
    )
}

/// POST /groups/:id/invite — generate an invite link.
async fn create_group_invite(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<CreateInviteRequest>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    let agent_id = state.agent.agent_id();
    let invite = x0x::groups::invite::SignedInvite::new(
        info.mls_group_id.clone(),
        info.name.clone(),
        &agent_id,
        req.expiry_secs,
    );

    let link = invite.to_link();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "invite_link": link,
            "group_id": info.mls_group_id,
            "group_name": info.name,
            "expires_at": invite.expires_at,
        })),
    )
}

/// POST /groups/join — join a group via invite link.
async fn join_group_via_invite(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JoinGroupRequest>,
) -> impl IntoResponse {
    // Parse invite
    let invite = match x0x::groups::invite::SignedInvite::from_link(&req.invite) {
        Ok(inv) => inv,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid invite: {e}") })),
            );
        }
    };

    // Check expiry
    if invite.is_expired() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "invite has expired" })),
        );
    }

    let agent_id = state.agent.agent_id();
    let group_id_hex = invite.group_id.clone();

    // Create the MLS group locally (in a real flow, the inviter would send
    // a Welcome message; for now, we create a local group and the inviter
    // will add us when they see our presence on the group topic)
    let group_id_bytes = match hex::decode(&group_id_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("invalid group_id hex: {e}") }),
                ),
            );
        }
    };

    match x0x::mls::MlsGroup::new(group_id_bytes, agent_id).await {
        Ok(group) => {
            // Store MLS group
            state
                .mls_groups
                .write()
                .await
                .insert(group_id_hex.clone(), group);
            save_mls_groups(&state).await;

            // Create group info from invite
            let mut info = x0x::groups::GroupInfo::new(
                invite.group_name.clone(),
                String::new(),
                agent_id,
                group_id_hex.clone(),
            );

            // Set joiner's display name if provided
            if let Some(dn) = req.display_name {
                info.set_display_name(hex::encode(agent_id.as_bytes()), dn);
            }

            let chat_topic = info.general_chat_topic();
            let metadata_topic = info.metadata_topic.clone();

            state
                .named_groups
                .write()
                .await
                .insert(group_id_hex.clone(), info.clone());
            save_named_groups(&state).await;

            // Auto-subscribe to group topics so messages flow immediately
            let _ = state.agent.subscribe(&chat_topic).await;
            let _ = state.agent.subscribe(&metadata_topic).await;

            // Announce join on the chat topic so the creator sees us
            let agent_hex = hex::encode(agent_id.as_bytes());
            let display = info
                .display_names
                .get(&agent_hex)
                .cloned()
                .unwrap_or_else(|| agent_hex[..8].to_string());
            let announcement = serde_json::json!({
                "type": "group_event",
                "event": "joined",
                "agent_id": agent_hex,
                "display_name": display,
                "group_id": group_id_hex,
                "group_name": invite.group_name,
                "ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
            let _ = state
                .agent
                .publish(&chat_topic, announcement.to_string().into_bytes())
                .await;

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "group_id": group_id_hex,
                    "group_name": invite.group_name,
                    "chat_topic": chat_topic,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// PUT /groups/:id/display-name — set your display name in a group.
async fn set_group_display_name(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SetDisplayNameRequest>,
) -> impl IntoResponse {
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    let agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    info.set_display_name(agent_hex, req.name.clone());
    drop(groups); // release write lock before saving
    save_named_groups(&state).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "display_name": req.name })),
    )
}

/// DELETE /groups/:id — leave or delete a group.
async fn leave_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Remove from named groups
    let info = state.named_groups.write().await.remove(&id);
    if info.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    }
    save_named_groups(&state).await;

    // Remove MLS group
    state.mls_groups.write().await.remove(&id);
    save_mls_groups(&state).await;

    let name = info.map(|i| i.name).unwrap_or_default();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "left": name })),
    )
}

// ---------------------------------------------------------------------------
// Task list handlers
// ---------------------------------------------------------------------------

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
                    state: format!("{}", t.state),
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

    match handle
        .add_task(req.title, req.description.unwrap_or_default())
        .await
    {
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
// ---------------------------------------------------------------------------
// Embedded GUI
// ---------------------------------------------------------------------------

/// The embedded GUI HTML, compiled into the binary.
const GUI_HTML: &str = include_str!("../gui/x0x-gui.html");

/// GET /gui — serve the embedded GUI with API token injected.
///
/// Injects `const X0X_TOKEN='<token>';` into the HTML so the GUI can
/// authenticate API calls and WebSocket connections automatically.
async fn serve_gui(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let injected = format!("<script>const X0X_TOKEN='{}';</script>", state.api_token);
    // Replace the dedicated marker rather than relying on the first <script> tag.
    let html = GUI_HTML.replace("<!-- X0X_TOKEN_INJECTION_POINT -->", &injected);
    axum::response::Html(html)
}

// ---------------------------------------------------------------------------
// KvStore handlers
// ---------------------------------------------------------------------------

/// Request body for POST /stores.
#[derive(Debug, Deserialize)]
struct CreateStoreRequest {
    name: String,
    topic: String,
}

/// Request body for PUT /stores/:id/:key.
#[derive(Debug, Deserialize)]
struct PutValueRequest {
    value: String,
    content_type: Option<String>,
}

/// Response entry for GET /stores.
#[derive(Debug, Serialize)]
struct StoreListEntry {
    id: String,
    topic: String,
}

/// GET /stores
async fn list_kv_stores(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stores = state.kv_stores.read().await;
    let entries: Vec<StoreListEntry> = stores
        .keys()
        .map(|id| StoreListEntry {
            id: id.clone(),
            topic: id.clone(),
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "stores": entries }))
}

/// POST /stores
async fn create_kv_store(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateStoreRequest>,
) -> impl IntoResponse {
    match state.agent.create_kv_store(&req.name, &req.topic).await {
        Ok(handle) => {
            let id = req.topic.clone();
            state.kv_stores.write().await.insert(id.clone(), handle);
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

/// POST /stores/:id/join
async fn join_kv_store(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.agent.join_kv_store(&id).await {
        Ok(handle) => {
            state.kv_stores.write().await.insert(id.clone(), handle);
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "id": id })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /stores/:id/keys
async fn list_kv_keys(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "store not found" })),
        );
    };

    match handle.keys().await {
        Ok(entries) => {
            let keys: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "key": e.key,
                        "content_type": e.content_type,
                        "content_hash": e.content_hash,
                        "size": e.value.len(),
                        "updated_at": e.updated_at,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "keys": keys })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// PUT /stores/:id/:key
async fn put_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
    Json(req): Json<PutValueRequest>,
) -> impl IntoResponse {
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "store not found" })),
        );
    };

    use base64::Engine;
    let value = match base64::engine::general_purpose::STANDARD.decode(&req.value) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid base64: {e}") })),
            );
        }
    };

    let content_type = req
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    match handle.put(key, value, content_type).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /stores/:id/:key
async fn get_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "store not found" })),
        );
    };

    match handle.get(&key).await {
        Ok(Some(entry)) => {
            use base64::Engine;
            let value_b64 = base64::engine::general_purpose::STANDARD.encode(&entry.value);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "key": entry.key,
                    "value": value_b64,
                    "content_type": entry.content_type,
                    "content_hash": entry.content_hash,
                    "metadata": entry.metadata,
                    "created_at": entry.created_at,
                    "updated_at": entry.updated_at,
                })),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "key not found" })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// DELETE /stores/:id/:key
async fn delete_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "store not found" })),
        );
    };

    match handle.remove(&key).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Direct messaging handlers
// ---------------------------------------------------------------------------

/// POST /agents/connect — connect to a discovered agent.
async fn connect_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectAgentRequest>,
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

    match state.agent.connect_to_agent(&agent_id).await {
        Ok(outcome) => {
            let (outcome_str, addr) = match outcome {
                x0x::connectivity::ConnectOutcome::Direct(a) => ("Direct", Some(a.to_string())),
                x0x::connectivity::ConnectOutcome::Coordinated(a) => {
                    ("Coordinated", Some(a.to_string()))
                }
                x0x::connectivity::ConnectOutcome::Unreachable => ("Unreachable", None),
                x0x::connectivity::ConnectOutcome::NotFound => ("NotFound", None),
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "outcome": outcome_str,
                    "addr": addr
                })),
            )
        }
        Err(e) => {
            tracing::error!("connect_agent failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "connection failed" })),
            )
        }
    }
}

/// POST /direct/send — send a direct message to a connected agent.
async fn direct_send(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DirectSendRequest>,
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

    // Check trust level before sending — reject blocked agents
    {
        let contacts = state.contacts.read().await;
        if let Some(contact) = contacts.get(&agent_id) {
            if contact.trust_level == TrustLevel::Blocked {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "ok": false, "error": "agent is blocked" })),
                );
            }
        }
    }

    let payload = match decode_base64_payload(&req.payload) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    match state.agent.send_direct(&agent_id, payload).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => {
            tracing::error!("direct_send failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "send failed" })),
            )
        }
    }
}

/// GET /direct/connections — list connected agents.
async fn direct_connections(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let connected = state.agent.connected_agents().await;
    let dm = state.agent.direct_messaging();

    let mut entries = Vec::new();
    for agent_id in &connected {
        let machine_id = dm
            .get_machine_id(agent_id)
            .await
            .map(|m| hex::encode(m.as_bytes()));
        entries.push(serde_json::json!({
            "agent_id": hex::encode(agent_id.as_bytes()),
            "machine_id": machine_id
        }));
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "connections": entries })),
    )
}

/// GET /direct/events — SSE stream of incoming direct messages.
async fn direct_events_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    tracing::info!("[6/6 x0xd] SSE client connected to /direct/events");
    let mut rx = state.agent.subscribe_direct();
    let mut shutdown_rx = state.shutdown_notify.subscribe();

    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    tracing::info!("[6/6 x0xd] direct SSE client closing due to daemon shutdown");
                    break;
                }
                maybe_msg = rx.recv() => {
                    let Some(msg) = maybe_msg else {
                        break;
                    };
                    let data = serde_json::json!({
                        "sender": hex::encode(msg.sender.as_bytes()),
                        "machine_id": hex::encode(msg.machine_id.as_bytes()),
                        "payload": base64::engine::general_purpose::STANDARD.encode(&msg.payload),
                        "received_at": msg.received_at
                    });
                    let event = Event::default()
                        .event("direct_message")
                        .data(data.to_string());
                    yield Ok(event);
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

// ---------------------------------------------------------------------------
// MLS group encryption handlers
//
// NOTE: Groups are persisted to <data_dir>/mls_groups.bin on every
// mutation (create, add/remove member). Loaded on startup.
//
// NOTE: Group operations have no ownership model — any caller on the local
// socket can modify any group. This is acceptable because x0xd listens on
// localhost only, so all callers are implicitly the local agent.
// ---------------------------------------------------------------------------

/// POST /mls/groups — create a new MLS group.
async fn create_mls_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateMlsGroupRequest>,
) -> impl IntoResponse {
    let group_id_bytes = match req.group_id {
        Some(hex_str) => match hex::decode(&hex_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": format!("invalid hex: {e}") })),
                );
            }
        },
        None => {
            let mut bytes = vec![0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        }
    };

    let agent_id = state.agent.agent_id();
    let group_id_hex = hex::encode(&group_id_bytes);

    match x0x::mls::MlsGroup::new(group_id_bytes, agent_id).await {
        Ok(group) => {
            let epoch = group.current_epoch();
            let members: Vec<String> = group
                .members()
                .keys()
                .map(|id| hex::encode(id.as_bytes()))
                .collect();

            state
                .mls_groups
                .write()
                .await
                .insert(group_id_hex.clone(), group);
            save_mls_groups(&state).await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "ok": true,
                    "group_id": group_id_hex,
                    "epoch": epoch,
                    "members": members
                })),
            )
        }
        Err(e) => {
            tracing::error!("operation failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "internal error" })),
            )
        }
    }
}

/// GET /mls/groups — list all MLS groups.
async fn list_mls_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let groups = state.mls_groups.read().await;
    let entries: Vec<serde_json::Value> = groups
        .iter()
        .map(|(id, group)| {
            serde_json::json!({
                "group_id": id,
                "epoch": group.current_epoch(),
                "member_count": group.members().len()
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "groups": entries })),
    )
}

/// GET /mls/groups/:id — get details of a specific MLS group.
async fn get_mls_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    let members: Vec<String> = group
        .members()
        .keys()
        .map(|id| hex::encode(id.as_bytes()))
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "epoch": group.current_epoch(),
            "members": members
        })),
    )
}

/// POST /mls/groups/:id/members — add a member to a group.
async fn add_mls_member(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddMlsMemberRequest>,
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

    let mut groups = state.mls_groups.write().await;
    let Some(group) = groups.get_mut(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    // add_member() auto-applies the commit internally (increments epoch).
    // Do NOT call apply_commit() again — it would fail with epoch mismatch.
    match group.add_member(agent_id).await {
        Ok(_commit) => {
            let resp = (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "epoch": group.current_epoch(),
                    "member_count": group.members().len()
                })),
            );
            drop(groups);
            save_mls_groups(&state).await;
            resp
        }
        Err(e) => {
            tracing::error!("add_mls_member failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "operation failed" })),
            )
        }
    }
}

/// DELETE /mls/groups/:id/members/:agent_id — remove a member from a group.
async fn remove_mls_member(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
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

    let mut groups = state.mls_groups.write().await;
    let Some(group) = groups.get_mut(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    // remove_member() auto-applies the commit internally.
    match group.remove_member(agent_id).await {
        Ok(_commit) => {
            let resp = (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "epoch": group.current_epoch(),
                    "member_count": group.members().len()
                })),
            );
            drop(groups);
            save_mls_groups(&state).await;
            resp
        }
        Err(e) => {
            tracing::error!("remove_mls_member failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "internal error" })),
            )
        }
    }
}

/// POST /mls/groups/:id/encrypt — encrypt data with group key.
async fn mls_encrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MlsEncryptRequest>,
) -> impl IntoResponse {
    let plaintext = match decode_base64_payload(&req.payload) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    let (cipher, epoch) = match make_mls_cipher(group) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match cipher.encrypt(&plaintext, &[], epoch) {
        Ok(ciphertext) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
                "epoch": epoch
            })),
        ),
        Err(e) => {
            tracing::error!("mls_encrypt failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "encryption failed" })),
            )
        }
    }
}

/// POST /mls/groups/:id/decrypt — decrypt data with group key.
async fn mls_decrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MlsDecryptRequest>,
) -> impl IntoResponse {
    let ciphertext = match decode_base64_payload(&req.ciphertext) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    let (cipher, _epoch) = match make_mls_cipher(group) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match cipher.decrypt(&ciphertext, &[], req.epoch) {
        Ok(plaintext) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "payload": base64::engine::general_purpose::STANDARD.encode(&plaintext)
            })),
        ),
        Err(e) => {
            tracing::error!("mls_decrypt failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "decryption failed" })),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Agent discovery & connectivity handlers
// ---------------------------------------------------------------------------

/// POST /agents/find/:agent_id — actively search for an agent (3-stage: cache → shard → rendezvous).
async fn find_agent(
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

    match state.agent.find_agent(agent_id).await {
        Ok(Some(addrs)) => {
            let addr_strs: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "found": true, "addresses": addr_strs })),
            )
        }
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "found": false })),
        ),
        Err(e) => {
            tracing::error!("find_agent failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "search failed" })),
            )
        }
    }
}

/// GET /agents/reachability/:agent_id — check reachability before connecting.
async fn agent_reachability(
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

    match state.agent.reachability(&agent_id).await {
        Some(info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "likely_direct": info.likely_direct(),
                "needs_coordination": info.needs_coordination(),
                "is_relay": info.is_relay(),
                "is_coordinator": info.is_coordinator(),
                "addresses": info.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>()
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "agent not in discovery cache" })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Contact trust extension handlers
// ---------------------------------------------------------------------------

/// POST /contacts/:agent_id/revoke — permanently revoke an agent's key.
async fn revoke_contact(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Json(req): Json<RevokeContactRequest>,
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

    let mut store = state.contacts.write().await;
    store.revoke(&agent_id, &req.reason);
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// GET /contacts/:agent_id/revocations — list revocation records.
async fn list_revocations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.contacts.read().await;
    let revocations: Vec<serde_json::Value> = store
        .revocations()
        .iter()
        .map(|r| {
            serde_json::json!({
                "agent_id": hex::encode(r.agent_id.0),
                "reason": r.reason,
                "timestamp": r.timestamp,
                "revoker_id": r.revoker_id.map(|id| hex::encode(id.0))
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revocations": revocations })),
    )
}

/// POST /contacts/:agent_id/machines/:machine_id/pin — pin a machine for identity verification.
async fn pin_machine(
    State(state): State<Arc<AppState>>,
    Path((agent_id_hex, machine_id_hex)): Path<(String, String)>,
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

    let machine_bytes = match hex::decode(&machine_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "invalid machine_id hex" })),
            );
        }
    };
    let machine_id = MachineId(machine_bytes);

    let mut store = state.contacts.write().await;
    let pinned = store.pin_machine(&agent_id, &machine_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "pinned": pinned })),
    )
}

/// DELETE /contacts/:agent_id/machines/:machine_id/pin — unpin a machine.
async fn unpin_machine(
    State(state): State<Arc<AppState>>,
    Path((agent_id_hex, machine_id_hex)): Path<(String, String)>,
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

    let machine_bytes = match hex::decode(&machine_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "invalid machine_id hex" })),
            );
        }
    };
    let machine_id = MachineId(machine_bytes);

    let mut store = state.contacts.write().await;
    let unpinned = store.unpin_machine(&agent_id, &machine_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "unpinned": unpinned })),
    )
}

/// POST /trust/evaluate — evaluate trust decision for an (agent, machine) pair.
async fn evaluate_trust(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvaluateTrustRequest>,
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

    let machine_bytes = match hex::decode(&req.machine_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "invalid machine_id hex" })),
            );
        }
    };
    let machine_id = MachineId(machine_bytes);

    let store = state.contacts.read().await;
    let evaluator = x0x::trust::TrustEvaluator::new(&store);
    let ctx = x0x::trust::TrustContext {
        agent_id: &agent_id,
        machine_id: &machine_id,
    };
    let decision = evaluator.evaluate(&ctx);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "decision": format!("{:?}", decision)
        })),
    )
}

// Note: task deletion not exposed — TaskListHandle doesn't have remove_task().

// ---------------------------------------------------------------------------
// MLS welcome handler
// ---------------------------------------------------------------------------

/// POST /mls/groups/:id/welcome — generate a welcome message for a new member.
async fn create_mls_welcome(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<CreateWelcomeRequest>,
) -> impl IntoResponse {
    let invitee = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    match x0x::mls::MlsWelcome::create(group, &invitee) {
        Ok(welcome) => {
            let welcome_bytes = match bincode::serialize(&welcome) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("welcome serialization failed: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "ok": false, "error": "serialization failed" })),
                    );
                }
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "welcome": base64::engine::general_purpose::STANDARD.encode(&welcome_bytes),
                    "group_id": id,
                    "epoch": welcome.epoch()
                })),
            )
        }
        Err(e) => {
            tracing::error!("create_mls_welcome failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "welcome creation failed" })),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Constitution handlers
// ---------------------------------------------------------------------------

/// GET /constitution — returns the raw markdown text.
async fn get_constitution() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/markdown; charset=utf-8")],
        x0x::constitution::CONSTITUTION_MD,
    )
}

/// GET /constitution/json — returns structured JSON with version metadata.
async fn get_constitution_json() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": x0x::constitution::CONSTITUTION_VERSION,
        "status": x0x::constitution::CONSTITUTION_STATUS,
        "content": x0x::constitution::CONSTITUTION_MD,
    }))
}

// ---------------------------------------------------------------------------
// Upgrade check handler
// ---------------------------------------------------------------------------

/// GET /upgrade — check for available updates.
async fn check_upgrade(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let monitor = match x0x::upgrade::monitor::UpgradeMonitor::new(
        "saorsa-labs/x0x",
        "x0xd",
        env!("CARGO_PKG_VERSION"),
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("upgrade monitor creation failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "upgrade check unavailable" })),
            );
        }
    };

    match monitor.check_for_updates().await {
        Ok(Some(release)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "update_available": true,
                "version": release.manifest.version,
                "current_version": env!("CARGO_PKG_VERSION")
            })),
        ),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "update_available": false,
                "current_version": env!("CARGO_PKG_VERSION")
            })),
        ),
        Err(e) => {
            tracing::error!("upgrade check failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "upgrade check failed" })),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Network diagnostics handler
// ---------------------------------------------------------------------------

/// GET /network/bootstrap-cache — bootstrap peer cache statistics.
async fn bootstrap_cache_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Access bootstrap cache via the network node if available
    match state.agent.network() {
        Some(network) => {
            let connection_count = network.connection_count().await;
            let connected_peers = network.connected_peers().await;
            let peer_addrs: Vec<String> =
                connected_peers.iter().map(|a| format!("{a:?}")).collect();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "connection_count": connection_count,
                    "connected_peers": peer_addrs
                })),
            )
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ok": false, "error": "network not initialized" })),
        ),
    }
}

// ---------------------------------------------------------------------------
// WebSocket handlers
// ---------------------------------------------------------------------------

/// GET /ws — upgrade to WebSocket (general purpose).
async fn ws_handler(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state, false))
}

/// GET /ws/direct — upgrade to WebSocket (auto-subscribes to direct messages).
async fn ws_direct_handler(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state, true))
}

/// GET /ws/sessions — list active WebSocket sessions.
async fn ws_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = state.ws_sessions.read().await;
    let entries: Vec<serde_json::Value> = sessions
        .values()
        .map(|s| {
            serde_json::json!({
                "session_id": s.id,
                "subscribed_topics": s.subscribed_topics.iter().collect::<Vec<_>>(),
                "receives_direct": s.receives_direct,
            })
        })
        .collect();

    // Shared subscription stats
    let topics = state.ws_topics.read().await;
    let shared: HashMap<&str, usize> = topics
        .iter()
        .map(|(topic, ts)| (topic.as_str(), ts.subscribers.len()))
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "sessions": entries,
            "shared_subscriptions": shared
        })),
    )
}

/// Core WebSocket connection lifecycle.
async fn handle_ws_connection(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
    direct_mode: bool,
) {
    use axum::extract::ws::Message;
    use futures::{SinkExt, StreamExt as FutStreamExt};

    let session_id = uuid::Uuid::new_v4().to_string();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<WsOutbound>();

    // Register session
    let session = WsSession {
        id: session_id.clone(),
        subscribed_topics: HashSet::new(),
        receives_direct: direct_mode,
        forwarder_handles: Vec::new(),
    };
    state
        .ws_sessions
        .write()
        .await
        .insert(session_id.clone(), session);

    tracing::info!(session_id = %session_id, direct_mode, "WebSocket session opened");

    // Send "connected" frame
    let agent_id = hex::encode(state.agent.agent_id().as_bytes());
    let _ = outbound_tx.send(WsOutbound::Connected {
        session_id: session_id.clone(),
        agent_id,
    });

    // Spawn writer task: outbound_rx → ws_tx
    let writer_session_id = session_id.clone();
    let writer = tokio::spawn(async move {
        while let Some(msg) = outbound_rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(_) => continue,
            };
            if ws_tx.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
        tracing::debug!(session_id = %writer_session_id, "WebSocket writer stopped");
    });

    // If direct mode, spawn a forwarder for direct messages
    let direct_handle = if direct_mode {
        let mut direct_rx = state.agent.subscribe_direct();
        let tx = outbound_tx.clone();
        let sid = session_id.clone();
        Some(tokio::spawn(async move {
            while let Some(msg) = direct_rx.recv().await {
                let out = WsOutbound::DirectMessage {
                    sender: hex::encode(msg.sender.as_bytes()),
                    machine_id: hex::encode(msg.machine_id.as_bytes()),
                    payload: base64::engine::general_purpose::STANDARD.encode(&msg.payload),
                    received_at: msg.received_at,
                };
                if tx.send(out).is_err() {
                    break;
                }
            }
            tracing::debug!(session_id = %sid, "Direct message forwarder stopped");
        }))
    } else {
        None
    };

    // Spawn keepalive pinger (30s interval)
    let keepalive_tx = outbound_tx.clone();
    let keepalive = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if keepalive_tx.send(WsOutbound::Pong).is_err() {
                break;
            }
        }
    });

    // Reader loop: ws_rx → dispatch commands
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                tracing::info!(session_id = %session_id, "Closing WebSocket session due to daemon shutdown");
                break;
            }
            maybe_msg = futures::StreamExt::next(&mut ws_rx) => {
                let Some(Ok(msg)) = maybe_msg else {
                    break;
                };
                match msg {
                    Message::Text(text) => {
                        handle_ws_command(&state, &session_id, &text, &outbound_tx).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    // Cleanup: remove session, abort per-session forwarders
    let subscribed_topics =
        if let Some(session) = state.ws_sessions.write().await.remove(&session_id) {
            for h in session.forwarder_handles {
                h.abort();
            }
            session.subscribed_topics
        } else {
            HashSet::new()
        };

    // Clean up shared subscriptions for topics where this was the last WS subscriber
    for topic in &subscribed_topics {
        cleanup_ws_topic_if_empty(&state, topic, &session_id).await;
    }

    writer.abort();
    keepalive.abort();
    if let Some(h) = direct_handle {
        h.abort();
    }

    tracing::info!(session_id = %session_id, "WebSocket session closed");
}

/// Remove a session from a shared topic subscription; clean up if last subscriber.
async fn cleanup_ws_topic_if_empty(state: &AppState, topic: &str, session_id: &str) {
    let mut ws_topics = state.ws_topics.write().await;
    let should_remove = if let Some(ts) = ws_topics.get_mut(topic) {
        ts.subscribers.remove(session_id);
        ts.subscribers.is_empty()
    } else {
        false
    };
    if should_remove {
        if let Some(ts) = ws_topics.remove(topic) {
            ts.forwarder.abort();
            tracing::debug!(
                topic,
                "Cleaned up shared WS subscription (last subscriber left)"
            );
        }
    }
}

/// Dispatch an inbound WebSocket JSON command.
async fn handle_ws_command(
    state: &AppState,
    session_id: &str,
    text: &str,
    tx: &mpsc::UnboundedSender<WsOutbound>,
) {
    let cmd: WsInbound = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(WsOutbound::Error {
                message: format!("invalid command: {e}"),
            });
            return;
        }
    };

    match cmd {
        WsInbound::Ping => {
            let _ = tx.send(WsOutbound::Pong);
        }

        WsInbound::Subscribe { topics } => {
            // Shared fan-out: one gossip subscription per topic, broadcast to all WS sessions
            let mut handles = Vec::new();
            for topic in &topics {
                let broadcast_rx = {
                    let mut ws_topics = state.ws_topics.write().await;
                    if let Some(ts) = ws_topics.get_mut(topic) {
                        // Existing shared channel — just subscribe and track
                        ts.subscribers.insert(session_id.to_string());
                        ts.channel.subscribe()
                    } else {
                        // First WS subscriber — create gossip sub + broadcast + forwarder
                        let (broadcast_tx, broadcast_rx) = broadcast::channel::<WsOutbound>(256);
                        let mut subscribers = HashSet::new();
                        subscribers.insert(session_id.to_string());

                        let forwarder =
                            if let Ok(mut gossip_sub) = state.agent.subscribe(topic).await {
                                let btx = broadcast_tx.clone();
                                let topic_clone = topic.clone();
                                tokio::spawn(async move {
                                    while let Some(msg) = gossip_sub.recv().await {
                                        let out = WsOutbound::Message {
                                            topic: topic_clone.clone(),
                                            payload: base64::engine::general_purpose::STANDARD
                                                .encode(&msg.payload),
                                            origin: msg.sender.map(|s| hex::encode(s.as_bytes())),
                                        };
                                        let _ = btx.send(out);
                                    }
                                })
                            } else {
                                tokio::spawn(async {}) // no-op if subscribe failed
                            };

                        ws_topics.insert(
                            topic.clone(),
                            SharedTopicState {
                                channel: broadcast_tx,
                                subscribers,
                                forwarder,
                            },
                        );
                        broadcast_rx
                    }
                };

                // Per-session forwarder: broadcast channel → session outbound
                let tx_clone = tx.clone();
                let handle = tokio::spawn(async move {
                    let mut rx = broadcast_rx;
                    loop {
                        match rx.recv().await {
                            Ok(msg) => {
                                if tx_clone.send(msg).is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("WS session lagged, skipped {n} messages");
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
                handles.push(handle);
            }

            // Store handles in session for cleanup
            if let Some(session) = state.ws_sessions.write().await.get_mut(session_id) {
                session.subscribed_topics.extend(topics.iter().cloned());
                session.forwarder_handles.extend(handles);
            }

            let _ = tx.send(WsOutbound::Subscribed { topics });
        }

        WsInbound::Unsubscribe { topics } => {
            if let Some(session) = state.ws_sessions.write().await.get_mut(session_id) {
                for t in &topics {
                    session.subscribed_topics.remove(t);
                }
            }
            for topic in &topics {
                cleanup_ws_topic_if_empty(state, topic, session_id).await;
            }
            let _ = tx.send(WsOutbound::Unsubscribed { topics });
        }

        WsInbound::Publish { topic, payload } => {
            let bytes = match decode_base64_payload(&payload) {
                Ok(b) => b,
                Err(_) => {
                    let _ = tx.send(WsOutbound::Error {
                        message: "invalid base64 in payload".to_string(),
                    });
                    return;
                }
            };

            if let Err(e) = state.agent.publish(&topic, bytes).await {
                tracing::error!("ws publish failed: {e}");
                let _ = tx.send(WsOutbound::Error {
                    message: "publish failed".to_string(),
                });
            }
        }

        WsInbound::SendDirect { agent_id, payload } => {
            let aid = match parse_agent_id_hex(&agent_id) {
                Ok(id) => id,
                Err(e) => {
                    let _ = tx.send(WsOutbound::Error { message: e });
                    return;
                }
            };

            // Trust check — reject blocked agents (matches REST /direct/send behavior)
            {
                let contacts = state.contacts.read().await;
                if let Some(contact) = contacts.get(&aid) {
                    if contact.trust_level == TrustLevel::Blocked {
                        let _ = tx.send(WsOutbound::Error {
                            message: "agent is blocked".to_string(),
                        });
                        return;
                    }
                }
            }

            let bytes = match decode_base64_payload(&payload) {
                Ok(b) => b,
                Err(_) => {
                    let _ = tx.send(WsOutbound::Error {
                        message: "invalid base64 in payload".to_string(),
                    });
                    return;
                }
            };

            if let Err(e) = state.agent.send_direct(&aid, bytes).await {
                tracing::error!("ws send_direct failed: {e}");
                let _ = tx.send(WsOutbound::Error {
                    message: "send failed".to_string(),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for new endpoints
// ---------------------------------------------------------------------------

/// MLS groups are session-scoped — no persistence (saorsa-mls groups not serializable).
async fn save_mls_groups(_state: &AppState) {
    // MLS groups backed by saorsa-mls are not serializable.
    // They are recreated each session.
}

async fn save_named_groups(state: &AppState) {
    let groups = state.named_groups.read().await;
    match serde_json::to_string_pretty(&*groups) {
        Ok(json) => {
            if let Err(e) = tokio::fs::write(&state.named_groups_path, json).await {
                tracing::error!("Failed to save named groups: {e}");
            }
        }
        Err(e) => tracing::error!("Failed to serialize named groups: {e}"),
    }
}

/// Decode a base64-encoded payload from a request field.
fn decode_base64_payload(encoded: &str) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid base64: {e}") })),
            )
        })
}

/// Derive an MLS cipher from a group's current key schedule.
fn make_mls_cipher(
    group: &x0x::mls::MlsGroup,
) -> Result<(x0x::mls::MlsCipher, u64), (StatusCode, Json<serde_json::Value>)> {
    let key_schedule = x0x::mls::MlsKeySchedule::from_group(group).map_err(|e| {
        tracing::error!("MLS key derivation failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": "key derivation failed" })),
        )
    })?;
    let cipher = x0x::mls::MlsCipher::new(
        key_schedule.encryption_key().to_vec(),
        key_schedule.base_nonce().to_vec(),
    );
    Ok((cipher, group.current_epoch()))
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

// ---------------------------------------------------------------------------
// File transfer message handling
// ---------------------------------------------------------------------------

/// Dispatch an incoming `FileMessage` from the direct messaging channel.
async fn handle_file_message(
    state: &Arc<AppState>,
    sender: &AgentId,
    msg: x0x::files::FileMessage,
) {
    match msg {
        x0x::files::FileMessage::Offer(offer) => {
            handle_file_offer(state, sender, offer).await;
        }
        x0x::files::FileMessage::Accept { transfer_id } => {
            handle_file_accept(state, sender, &transfer_id).await;
        }
        x0x::files::FileMessage::Reject {
            transfer_id,
            reason,
        } => {
            handle_file_reject(state, sender, &transfer_id, &reason).await;
        }
        x0x::files::FileMessage::Chunk(chunk) => {
            handle_file_chunk(state, sender, chunk).await;
        }
        x0x::files::FileMessage::Complete(complete) => {
            handle_file_complete(state, sender, complete).await;
        }
    }
}

/// Handle an incoming file offer — create a receiving TransferState.
async fn handle_file_offer(state: &Arc<AppState>, sender: &AgentId, offer: x0x::files::FileOffer) {
    let sender_hex = hex::encode(sender.as_bytes());

    // Trust filtering: reject offers from blocked agents
    {
        let contacts = state.contacts.read().await;
        if let Some(contact) = contacts.get(sender) {
            if contact.trust_level == TrustLevel::Blocked {
                tracing::info!("Rejected file offer from blocked agent: {sender_hex}");
                return;
            }
        }
    }

    // Size limit check
    if offer.size > x0x::files::MAX_TRANSFER_SIZE {
        tracing::warn!(
            "Rejected file offer from {sender_hex}: size {} exceeds max {}",
            offer.size,
            x0x::files::MAX_TRANSFER_SIZE
        );
        return;
    }

    tracing::info!(
        "Incoming file offer: {} ({} bytes) from {}",
        offer.filename,
        offer.size,
        sender_hex
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let transfer = x0x::files::TransferState {
        transfer_id: offer.transfer_id.clone(),
        direction: x0x::files::TransferDirection::Receiving,
        remote_agent_id: sender_hex.clone(),
        filename: offer.filename.clone(),
        total_size: offer.size,
        bytes_transferred: 0,
        status: x0x::files::TransferStatus::Pending,
        sha256: offer.sha256,
        error: None,
        started_at: now,
        source_path: None,
        output_path: None,
        chunk_size: offer.chunk_size,
        total_chunks: offer.total_chunks,
    };

    state
        .file_transfers
        .write()
        .await
        .insert(offer.transfer_id.clone(), transfer);

    // Emit SSE event so apps can be notified
    let _ = state.broadcast_tx.send(SseEvent {
        event_type: "file:offer".to_string(),
        data: serde_json::json!({
            "transfer_id": offer.transfer_id,
            "filename": offer.filename,
            "size": offer.size,
            "sender": sender_hex,
        }),
    });
}

/// Handle an incoming accept — start streaming chunks to the receiver.
async fn handle_file_accept(state: &Arc<AppState>, sender: &AgentId, transfer_id: &str) {
    let sender_hex = hex::encode(sender.as_bytes());
    tracing::info!("File accept received: {transfer_id} from {sender_hex}");

    let source_path;
    let sha256;
    let remote_agent_hex;
    {
        let mut transfers = state.file_transfers.write().await;
        let Some(t) = transfers.get_mut(transfer_id) else {
            tracing::warn!("Accept for unknown transfer: {transfer_id}");
            return;
        };
        if t.direction != x0x::files::TransferDirection::Sending
            || t.status != x0x::files::TransferStatus::Pending
        {
            tracing::warn!("Accept for non-pending sending transfer: {transfer_id}");
            return;
        }
        // Authenticate: sender must match the remote_agent_id we sent the offer to
        if t.remote_agent_id != sender_hex {
            tracing::warn!(
                "Accept from wrong agent for {transfer_id}: expected {} got {sender_hex}",
                t.remote_agent_id
            );
            return;
        }
        t.status = x0x::files::TransferStatus::InProgress;
        source_path = t.source_path.clone();
        sha256 = t.sha256.clone();
        remote_agent_hex = t.remote_agent_id.clone();
    }

    let Some(path) = source_path else {
        tracing::error!("No source path for transfer {transfer_id}");
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some("No source path available".to_string());
        }
        return;
    };

    let Ok(agent_id) = parse_agent_id_hex(&remote_agent_hex) else {
        tracing::error!("Invalid agent_id in transfer {transfer_id}");
        return;
    };

    // Spawn async task to stream chunks
    let state = Arc::clone(state);
    let transfer_id = transfer_id.to_string();
    tokio::spawn(async move {
        stream_file_chunks(&state, &transfer_id, &path, &sha256, &agent_id).await;
    });
}

/// Stream file chunks to the receiver via direct messaging.
async fn stream_file_chunks(
    state: &Arc<AppState>,
    transfer_id: &str,
    source_path: &str,
    sha256: &str,
    agent_id: &AgentId,
) {
    use tokio::io::AsyncReadExt;

    let mut file = match tokio::fs::File::open(source_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Cannot open file {source_path}: {e}");
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(format!("Cannot open file: {e}"));
            }
            return;
        }
    };

    let mut buf = vec![0u8; x0x::files::DEFAULT_CHUNK_SIZE];
    let mut sequence: u64 = 0;

    loop {
        let n = match file.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                tracing::error!("Read error on {source_path}: {e}");
                let mut transfers = state.file_transfers.write().await;
                if let Some(t) = transfers.get_mut(transfer_id) {
                    t.status = x0x::files::TransferStatus::Failed;
                    t.error = Some(format!("Read error: {e}"));
                }
                return;
            }
        };

        let chunk_data = base64::engine::general_purpose::STANDARD.encode(&buf[..n]);
        let chunk_msg = x0x::files::FileMessage::Chunk(x0x::files::FileChunk {
            transfer_id: transfer_id.to_string(),
            sequence,
            data: chunk_data,
        });

        let payload = match serde_json::to_vec(&chunk_msg) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Serialize chunk failed: {e}");
                let mut transfers = state.file_transfers.write().await;
                if let Some(t) = transfers.get_mut(transfer_id) {
                    t.status = x0x::files::TransferStatus::Failed;
                    t.error = Some(format!("Serialization error: {e}"));
                }
                return;
            }
        };

        if let Err(e) = state.agent.send_direct(agent_id, payload).await {
            tracing::error!("Send chunk {sequence} failed: {e}");
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(format!("Send failed at chunk {sequence}: {e}"));
            }
            return;
        }

        // Update progress
        {
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(transfer_id) {
                t.bytes_transferred += n as u64;
            }
        }

        sequence += 1;
    }

    // Send completion message
    let complete_msg = x0x::files::FileMessage::Complete(x0x::files::FileComplete {
        transfer_id: transfer_id.to_string(),
        sha256: sha256.to_string(),
    });

    if let Ok(payload) = serde_json::to_vec(&complete_msg) {
        if let Err(e) = state.agent.send_direct(agent_id, payload).await {
            tracing::error!("Send complete message failed: {e}");
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(format!("Send complete failed: {e}"));
            }
            return;
        }
    }

    // Mark as complete on sender side
    let mut transfers = state.file_transfers.write().await;
    if let Some(t) = transfers.get_mut(transfer_id) {
        t.status = x0x::files::TransferStatus::Complete;
    }
    tracing::info!("File transfer complete (sender): {transfer_id}");
}

/// Handle an incoming reject — mark the sending transfer as rejected.
async fn handle_file_reject(
    state: &Arc<AppState>,
    sender: &AgentId,
    transfer_id: &str,
    reason: &str,
) {
    let sender_hex = hex::encode(sender.as_bytes());
    tracing::info!("File reject received: {transfer_id} from {sender_hex} — {reason}");
    let mut transfers = state.file_transfers.write().await;
    if let Some(t) = transfers.get_mut(transfer_id) {
        if t.direction == x0x::files::TransferDirection::Sending {
            // Authenticate: sender must match the remote_agent_id
            if t.remote_agent_id != sender_hex {
                tracing::warn!(
                    "Reject from wrong agent for {transfer_id}: expected {} got {sender_hex}",
                    t.remote_agent_id
                );
                return;
            }
            t.status = x0x::files::TransferStatus::Rejected;
            t.error = Some(reason.to_string());
        }
    }
}

/// Handle an incoming file chunk — append to partial file.
/// Clean up partial file and hasher state for a failed transfer.
async fn cleanup_failed_transfer(state: &Arc<AppState>, transfer_id: &str) {
    // Remove .part file
    let part_path = state.transfers_dir.join(format!("{transfer_id}.part"));
    let _ = tokio::fs::remove_file(&part_path).await;

    // Remove hasher
    state.receive_hashers.write().await.remove(transfer_id);
}

async fn handle_file_chunk(state: &Arc<AppState>, sender: &AgentId, chunk: x0x::files::FileChunk) {
    use tokio::io::AsyncWriteExt;

    let sender_hex = hex::encode(sender.as_bytes());

    // Validate: transfer must exist, be a receiving transfer, be InProgress,
    // and the sender must match the original offer's remote_agent_id.
    let expected_sequence = {
        let transfers = state.file_transfers.read().await;
        match transfers.get(&chunk.transfer_id) {
            Some(t)
                if t.direction == x0x::files::TransferDirection::Receiving
                    && t.status == x0x::files::TransferStatus::InProgress =>
            {
                // Authenticate: chunk must come from the agent who made the offer
                if t.remote_agent_id != sender_hex {
                    tracing::warn!(
                        "Chunk from wrong agent for {}: expected {} got {sender_hex}",
                        chunk.transfer_id,
                        t.remote_agent_id
                    );
                    return;
                }
                // Compute expected sequence from bytes received so far
                if t.chunk_size > 0 {
                    t.bytes_transferred / t.chunk_size as u64
                } else {
                    0
                }
            }
            Some(t) => {
                tracing::warn!(
                    "Ignoring chunk for transfer {} (dir={:?} status={:?})",
                    chunk.transfer_id,
                    t.direction,
                    t.status
                );
                return;
            }
            None => {
                tracing::warn!("Ignoring chunk for unknown transfer {}", chunk.transfer_id);
                return;
            }
        }
    };

    // Validate chunk ordering
    if chunk.sequence != expected_sequence {
        tracing::error!(
            "Out-of-order chunk for {}: expected seq {} got {}",
            chunk.transfer_id,
            expected_sequence,
            chunk.sequence
        );
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!(
                "Out-of-order chunk: expected {} got {}",
                expected_sequence, chunk.sequence
            ));
        }
        drop(transfers);
        cleanup_failed_transfer(state, &chunk.transfer_id).await;
        return;
    }

    // Decode base64 data
    let data = match base64::engine::general_purpose::STANDARD.decode(&chunk.data) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Chunk decode error for {}: {e}", chunk.transfer_id);
            return;
        }
    };

    // Enforce cumulative size limit
    {
        let transfers = state.file_transfers.read().await;
        if let Some(t) = transfers.get(&chunk.transfer_id) {
            let new_total = t.bytes_transferred + data.len() as u64;
            if new_total > t.total_size {
                tracing::error!(
                    "Transfer {} exceeds declared size: {} + {} > {}",
                    chunk.transfer_id,
                    t.bytes_transferred,
                    data.len(),
                    t.total_size
                );
                drop(transfers);
                let mut transfers = state.file_transfers.write().await;
                if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
                    t.status = x0x::files::TransferStatus::Failed;
                    t.error = Some("Received data exceeds declared file size".to_string());
                }
                drop(transfers);
                cleanup_failed_transfer(state, &chunk.transfer_id).await;
                return;
            }
        }
    }

    let part_path = state
        .transfers_dir
        .join(format!("{}.part", chunk.transfer_id));

    // Append to partial file
    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Cannot open part file {}: {e}", part_path.display());
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(format!("Cannot write chunk: {e}"));
            }
            drop(transfers);
            cleanup_failed_transfer(state, &chunk.transfer_id).await;
            return;
        }
    };

    if let Err(e) = file.write_all(&data).await {
        tracing::error!("Write chunk failed for {}: {e}", chunk.transfer_id);
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!("Write failed: {e}"));
        }
        drop(transfers);
        cleanup_failed_transfer(state, &chunk.transfer_id).await;
        return;
    }

    // Update incremental SHA-256 hasher
    {
        let mut hashers = state.receive_hashers.write().await;
        hashers
            .entry(chunk.transfer_id.clone())
            .or_insert_with(Sha256::new)
            .update(&data);
    }

    // Update progress
    {
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
            t.bytes_transferred += data.len() as u64;
        }
    }
}

/// Handle a file-complete message — verify SHA-256 and finalize.
async fn handle_file_complete(
    state: &Arc<AppState>,
    sender: &AgentId,
    complete: x0x::files::FileComplete,
) {
    tracing::info!("File complete received: {}", complete.transfer_id);

    let sender_hex = hex::encode(sender.as_bytes());

    // Validate: transfer must exist, be receiving, be InProgress,
    // and the sender must match the original offer's remote_agent_id.
    // Also retrieve the stored SHA-256 from the original offer.
    let expected_sha256 = {
        let transfers = state.file_transfers.read().await;
        match transfers.get(&complete.transfer_id) {
            Some(t)
                if t.direction == x0x::files::TransferDirection::Receiving
                    && t.status == x0x::files::TransferStatus::InProgress =>
            {
                // Authenticate: complete must come from the agent who made the offer
                if t.remote_agent_id != sender_hex {
                    tracing::warn!(
                        "Complete from wrong agent for {}: expected {} got {sender_hex}",
                        complete.transfer_id,
                        t.remote_agent_id
                    );
                    return;
                }
                t.sha256.clone()
            }
            Some(t) => {
                tracing::warn!(
                    "Ignoring complete for transfer {} (dir={:?} status={:?})",
                    complete.transfer_id,
                    t.direction,
                    t.status
                );
                return;
            }
            None => {
                tracing::warn!(
                    "Ignoring complete for unknown transfer {}",
                    complete.transfer_id
                );
                return;
            }
        }
    };

    let part_path = state
        .transfers_dir
        .join(format!("{}.part", complete.transfer_id));

    // Finalize SHA-256
    let computed_hash = {
        let mut hashers = state.receive_hashers.write().await;
        match hashers.remove(&complete.transfer_id) {
            Some(hasher) => hex::encode(hasher.finalize()),
            None => {
                tracing::error!("No hasher found for transfer {}", complete.transfer_id);
                let mut transfers = state.file_transfers.write().await;
                if let Some(t) = transfers.get_mut(&complete.transfer_id) {
                    t.status = x0x::files::TransferStatus::Failed;
                    t.error = Some("No hash state found".to_string());
                }
                return;
            }
        }
    };

    // Compare computed hash against the SHA-256 from the original offer,
    // NOT the attacker-supplied complete.sha256 field.
    if computed_hash != expected_sha256 {
        tracing::error!(
            "SHA-256 mismatch for {}: expected {} got {}",
            complete.transfer_id,
            expected_sha256,
            computed_hash
        );
        // Clean up partial file
        let _ = tokio::fs::remove_file(&part_path).await;
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&complete.transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!(
                "SHA-256 mismatch: expected {} got {}",
                expected_sha256, computed_hash
            ));
        }
        return;
    }

    // Move to final location — sanitize filename to prevent path traversal
    let raw_filename = {
        let transfers = state.file_transfers.read().await;
        transfers
            .get(&complete.transfer_id)
            .map(|t| t.filename.clone())
            .unwrap_or_else(|| complete.transfer_id.clone())
    };
    // Strip any path components — only keep the final filename segment
    let base_name = std::path::Path::new(&raw_filename)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| complete.transfer_id.clone());
    // Prefix with transfer_id to avoid filename collisions (safe slice)
    let id_prefix = if complete.transfer_id.len() >= 8 {
        &complete.transfer_id[..8]
    } else {
        &complete.transfer_id
    };
    let filename = format!("{id_prefix}_{base_name}");

    let final_path = state.transfers_dir.join(&filename);
    if let Err(e) = tokio::fs::rename(&part_path, &final_path).await {
        tracing::error!("Failed to rename part file: {e}");
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&complete.transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!("Failed to finalize file: {e}"));
        }
        return;
    }

    // Mark complete
    {
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&complete.transfer_id) {
            t.status = x0x::files::TransferStatus::Complete;
            t.output_path = Some(final_path.to_string_lossy().to_string());
        }
    }

    // Emit SSE event
    let _ = state.broadcast_tx.send(SseEvent {
        event_type: "file:complete".to_string(),
        data: serde_json::json!({
            "transfer_id": complete.transfer_id,
            "filename": filename,
            "sha256": computed_hash,
            "path": final_path.to_string_lossy(),
        }),
    });

    tracing::info!(
        "File transfer complete (receiver): {} -> {}",
        complete.transfer_id,
        final_path.display()
    );
}
