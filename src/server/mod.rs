//! HTTP/WebSocket server for the x0x daemon.
//!
//! Phase 1 (Issue #110): the daemon's axum router, handlers, SSE/WS
//! plumbing, auth middleware, and serving-side background tasks were
//! relocated here verbatim from `src/bin/x0xd.rs` so the library can
//! expose a serving entrypoint. Behavior is unchanged from the binary.

// The moved handler bodies use thousands of `x0x::...` paths; alias the
// crate to itself so those paths resolve unchanged inside the library.
use crate as x0x;

mod auth;
mod routes;
mod sse;
mod state;
mod ws;

// Re-export the public server API surface so `x0x::server::*` paths are
// unchanged after the #125 / WS1.4 extraction. Internal types (AppState,
// DaemonUpdateConfig, CachedUpgradeCheck) stay private to the crate.
#[cfg(test)]
use routes::CardQuery;
use routes::{
    add_contact, add_machine, agent_info, agent_sign, agent_user_id_handler, agent_verify,
    announce_identity, delete_contact, delete_machine, discovered_machine, discovered_machines,
    get_a2a_agent_card, get_agent_card, import_agent_card, introduction, list_contacts,
    list_machines, list_revocations, machines_by_user_handler, pin_machine,
    populate_invite_base_state_from_group_info, quick_trust, revoke_contact, unpin_machine,
    update_contact,
};
use sse::{direct_events_sse, events_sse, peer_events_handler, presence_events, SseEvent};
pub use state::{
    default_api_address, default_bind_address, default_data_dir, DaemonConfig, ServeOptions,
    ServerHandle, DEFAULT_QUIC_PORT,
};
use state::{shared_cache_dir, AppState, CachedUpgradeCheck, DaemonUpdateConfig};
use ws::{ws_diagnostics, ws_direct_handler, ws_handler, ws_sessions, WsOutboundStats};

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex, RwLock};
use tower_http::cors::CorsLayer;
use x0x::contacts::TrustLevel;
use x0x::identity::AgentId;
use x0x::identity::MachineId;
use x0x::logging::LogHexId;
use x0x::network::NetworkConfig;
use x0x::upgrade::manifest::{decode_signed_manifest, is_newer, ReleaseManifest, RELEASE_TOPIC};
use x0x::upgrade::monitor::UpgradeMonitor;
use x0x::upgrade::signature::verify_manifest_signature;
use x0x::Agent;

// ---------------------------------------------------------------------------
// Optional JSON body helper
// ---------------------------------------------------------------------------

/// Parse an optional JSON body: returns `Ok(T::default())` when the body is
/// empty (no Content-Type or zero-length), but returns an axum 400 error if
/// Content-Type is `application/json` and the body is malformed.
fn parse_optional_json<T: serde::de::DeserializeOwned + Default>(
    headers: &HeaderMap,
    body: &Bytes,
) -> std::result::Result<T, (StatusCode, Json<serde_json::Value>)> {
    if body.is_empty() {
        return Ok(T::default());
    }
    let is_json = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false);
    if !is_json {
        // Non-JSON content type with a body — reject
        return Err(api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        ));
    }
    serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))
}

const GROUP_BACKGROUND_PUBLISH_DELAY: Duration = Duration::from_secs(8);
const NAMED_GROUP_METADATA_PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);
const TREEKEM_PENDING_EVENTS_PER_GROUP_CAP: usize = 64;
const TREEKEM_EVENT_LOG_PER_GROUP_CAP: usize = 128;
// TreeKEM MemberAdded events carry signed state commits plus commit/welcome
// references and are ~35-40 KiB each on the wire. Two events in one catch-up
// response exceed the direct-message payload cap, so paginate one event at a
// time and rely on the existing `truncated` next-page loop.
const TREEKEM_CATCHUP_RESPONSE_EVENT_CAP: usize = 1;
const TREEKEM_CATCHUP_THROTTLE: Duration = Duration::from_secs(5);
const DM_INBOX_START_MAX_ATTEMPTS: u32 = 120;
const DM_INBOX_START_RETRY_DELAY: Duration = Duration::from_millis(250);

#[cfg(test)]
static NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST: StdMutex<Vec<(String, String)>> =
    StdMutex::new(Vec::new());

#[cfg(test)]
static TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY: StdMutex<
    Option<(String, Arc<tokio::sync::Notify>)>,
> = StdMutex::new(None);

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

type WelcomeFetchWaiter = oneshot::Sender<std::result::Result<Vec<u8>, String>>;

/// A live REST `/subscribe` stream tracked so `DELETE /subscribe/:id` can stop it.
struct RestSubscription {
    /// Topic the subscription the subscription is for (retained for diagnostics/logging).
    topic: String,
    /// Forwarder task draining the gossip subscription into the SSE broadcast.
    /// Aborting it drops the underlying `Subscription`, which releases the
    /// gossip topic ref-count and ends delivery — without this, an
    /// unsubscribed stream would keep forwarding messages to SSE forever.
    forwarder: tokio::task::JoinHandle<()>,
}

/// Hard upper bound for the discoverable group-card bridge cache. This cache
/// is populated from untrusted discovery surfaces, so it must not grow without
/// bound even if every incoming card is syntactically valid.
const GROUP_CARD_CACHE_CAP: usize = 8_192;

const UPGRADE_CHECK_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const UPGRADE_CHECK_ERROR_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

fn group_card_expiry_millis(card: &x0x::groups::GroupCard) -> u64 {
    if card.expires_at > card.issued_at {
        card.expires_at
    } else {
        card.issued_at
            .saturating_add(x0x::groups::GroupCard::default_ttl_secs().saturating_mul(1_000))
    }
}

fn group_card_is_expired(card: &x0x::groups::GroupCard, now_ms: u64) -> bool {
    group_card_expiry_millis(card) < now_ms
}

fn prune_expired_group_cards(cache: &mut HashMap<String, x0x::groups::GroupCard>, now_ms: u64) {
    cache.retain(|_, card| !group_card_is_expired(card, now_ms));
}

fn enforce_group_card_cache_cap(cache: &mut HashMap<String, x0x::groups::GroupCard>) {
    if cache.len() <= GROUP_CARD_CACHE_CAP {
        return;
    }

    let remove_count = cache.len().saturating_sub(GROUP_CARD_CACHE_CAP);
    let mut victims: Vec<(String, u64, u64, u64)> = cache
        .iter()
        .map(|(key, card)| {
            (
                key.clone(),
                group_card_expiry_millis(card),
                card.issued_at,
                card.revision,
            )
        })
        .collect();
    victims.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.cmp(&right.3))
            .then_with(|| left.0.cmp(&right.0))
    });
    for (key, _, _, _) in victims.into_iter().take(remove_count) {
        cache.remove(&key);
    }
}

fn prune_and_bound_group_card_cache(
    cache: &mut HashMap<String, x0x::groups::GroupCard>,
    now_ms: u64,
) {
    prune_expired_group_cards(cache, now_ms);
    enforce_group_card_cache_cap(cache);
}

fn cache_group_card_if_newer(
    cache: &mut HashMap<String, x0x::groups::GroupCard>,
    key: String,
    card: x0x::groups::GroupCard,
) -> bool {
    let should_insert = match cache.get(&key) {
        Some(existing) => card.supersedes(existing),
        None => true,
    };
    if should_insert {
        cache.insert(key, card);
    }
    should_insert
}

fn remove_group_card_if_not_stale(
    cache: &mut HashMap<String, x0x::groups::GroupCard>,
    card: &x0x::groups::GroupCard,
) -> bool {
    let should_remove = match cache.get(&card.group_id) {
        Some(existing) => {
            card.revision > existing.revision
                || (card.revision == existing.revision && card.issued_at >= existing.issued_at)
        }
        None => false,
    };
    if should_remove {
        cache.remove(&card.group_id);
    }
    should_remove
}

fn group_card_supersedes_group_info(
    card: &x0x::groups::GroupCard,
    info: &x0x::groups::GroupInfo,
) -> bool {
    card.revision > info.state_revision
        || (card.revision == info.state_revision && card.updated_at >= info.updated_at)
}

fn apply_withdrawn_group_card_to_group_info(
    info: &mut x0x::groups::GroupInfo,
    card: &x0x::groups::GroupCard,
) -> bool {
    if !card.withdrawn || !group_card_supersedes_group_info(card, info) {
        return false;
    }

    info.name = card.name.clone();
    info.description = card.description.clone();
    info.policy = x0x::groups::GroupPolicy::from(&card.policy_summary);
    info.created_at = card.created_at;
    info.updated_at = card.updated_at;
    if let Some(metadata_topic) = card.metadata_topic.clone() {
        info.metadata_topic = metadata_topic;
    }
    info.state_revision = card.revision;
    if !card.state_hash.is_empty() {
        info.state_hash = card.state_hash.clone();
    }
    info.prev_state_hash = card.prev_state_hash.clone();
    info.withdrawn = true;
    clear_group_info_key_material(info);
    if info
        .genesis
        .as_ref()
        .is_none_or(|genesis| genesis.group_id != card.group_id)
    {
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            card.group_id.clone(),
            card.owner_agent_id.clone(),
            card.created_at,
            String::new(),
        ));
    }
    info.members_v2
        .entry(card.owner_agent_id.clone())
        .or_insert_with(|| {
            x0x::groups::GroupMember::new_admin(card.owner_agent_id.clone(), None, card.created_at)
        });
    true
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

// ---------------------------------------------------------------------------
// Direct messaging request / response types
// ---------------------------------------------------------------------------

/// POST /agents/connect request body.
#[derive(Debug, Deserialize)]
struct ConnectAgentRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
}

/// POST /machines/connect request body.
#[derive(Debug, Deserialize)]
struct ConnectMachineRequest {
    /// Machine ID as 64-character hex string.
    machine_id: String,
}

/// POST /direct/send request body.
#[derive(Debug, Deserialize)]
struct DirectSendRequest {
    /// Target agent ID as 64-character hex string.
    agent_id: String,
    /// Base64-encoded payload.
    payload: String,
    /// Prefer the raw-QUIC path when a live direct connection exists.
    #[serde(default)]
    prefer_raw_quic_if_connected: bool,
    /// Optional raw-QUIC receive-pipeline ACK timeout for the message itself.
    #[serde(default)]
    raw_quic_receive_ack_ms: Option<u64>,
    /// If true, do not fall back to gossip-inbox after a preferred raw-QUIC
    /// failure.
    #[serde(default)]
    stop_fallback_on_raw_error: bool,
    /// If true, require gossip-inbox delivery and reject recipients without a
    /// gossip DM capability.
    #[serde(default)]
    require_gossip: bool,
    /// If set, override whether gossip-inbox sends wait for the recipient's
    /// inbox ACK before returning success. When omitted, the daemon default is
    /// used.
    #[serde(default)]
    require_gossip_ack: Option<bool>,
    /// Optional opt-in: after the DM path accepts the message, probe the
    /// recipient's ant-quic receive pipeline for liveness with this timeout.
    /// This does not force the message itself onto raw-QUIC receive-ACK.
    #[serde(default)]
    require_ack_ms: Option<u64>,
}

/// POST /exec/run request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecRunRequest {
    /// Target agent ID as 64-character hex string.
    agent_id: String,
    /// Exact argv vector. Never interpreted by a shell.
    argv: Vec<String>,
    /// Optional base64 stdin payload.
    #[serde(default)]
    stdin_b64: Option<String>,
    /// Optional timeout in milliseconds. Remote ACL caps apply.
    #[serde(default)]
    timeout_ms: Option<u32>,
    /// Requester-controlled CWD is rejected in v1 unless future ACL support is added.
    #[serde(default)]
    cwd: Option<String>,
}

/// POST /exec/cancel request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecCancelRequest {
    /// Request ID as 32 hex chars.
    request_id: String,
    /// Optional target agent ID. If omitted, the local pending-session table is used.
    #[serde(default)]
    agent_id: Option<String>,
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

/// Discovered machine endpoint entry from machine announcements.
#[derive(Debug, Serialize)]
struct DiscoveredMachineEntry {
    machine_id: String,
    addresses: Vec<String>,
    announced_at: u64,
    last_seen: u64,
    nat_type: Option<String>,
    can_receive_direct: Option<bool>,
    is_relay: Option<bool>,
    is_coordinator: Option<bool>,
    agent_ids: Vec<String>,
    user_ids: Vec<String>,
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

/// Run the daemon HTTP/WebSocket server to completion.
///
/// Thin blocking wrapper over [`serve_with_options`]: performs all fallible
/// startup, then awaits run-to-completion. Shutdown is driven by the `/shutdown`
/// HTTP endpoint. This entrypoint does NOT install a Ctrl-C handler — a host
/// process that wants Ctrl-C must use [`serve_with_options`] and select over
/// [`ServerHandle::wait`] alongside its own signal handling (the daemon binary
/// does exactly that).
pub async fn run(config: DaemonConfig, options: ServeOptions) -> anyhow::Result<()> {
    serve_with_options(config, options).await?.wait().await
}

/// CLI `--check-updates`: run the startup update check, print its outcome, and
/// return without serving. Mirrors the print-and-exit behaviour the daemon had
/// inline before the [`serve_with_options`] extraction. Only the binary calls
/// this; the embed path never installs updates.
pub async fn run_update_check_and_report(
    config: &DaemonConfig,
    skip_update_check: bool,
) -> anyhow::Result<()> {
    if config.update.enabled && !skip_update_check {
        match run_startup_update_check(config, None).await {
            Ok(Some(version)) => println!("x0xd updated to {version}"),
            Ok(None) => println!("x0xd is up to date ({})", x0x::VERSION),
            Err(e) => return Err(e).context("self-update check failed"),
        }
    } else if !config.update.enabled {
        println!("self-update checks are disabled by configuration");
    } else {
        println!("self-update check skipped by --skip-update-check");
    }
    Ok(())
}

/// Start the x0x server in-process and return a [`ServerHandle`].
///
/// Self-update install/restart is DISABLED and the startup update check is
/// skipped — an embedded library must never replace or restart the host
/// application. Supply an `identity_dir` (or `data_dir`) in `config` so no
/// state is written under `~/.x0x`. See [`serve_with_options`] for full
/// control over runtime options.
pub async fn serve(config: DaemonConfig) -> anyhow::Result<ServerHandle> {
    let options = ServeOptions {
        skip_update_check: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    };
    serve_with_options(config, options).await
}

/// Start the x0x server in-process with explicit runtime options.
///
/// All synchronous, fallible startup (data-dir create, identity load/gen,
/// API-token load, listener bind, state + router build, `api.port` write) runs
/// here and surfaces as `Err` BEFORE any long-lived task is spawned. On success
/// a single supervisor task is spawned and a [`ServerHandle`] is returned with
/// the bound address already readable.
pub async fn serve_with_options(
    config: DaemonConfig,
    options: ServeOptions,
) -> anyhow::Result<ServerHandle> {
    let ServeOptions {
        skip_update_check,
        cli_no_port_mapping,
        cli_disable_peer_cache,
        instance_name,
        exec_policy,
        self_update_enabled,
    } = options;
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

    // Note: `--check-updates` is a CLI-only print-and-exit mode handled entirely
    // by the binary (see `run_update_check_and_report`) before it ever calls
    // `serve_with_options`; it is intentionally not a `ServeOptions` field.

    // Startup GitHub check (fallback mechanism — gossip is primary).
    // Gated on `self_update_enabled` so embedders never download/install a new
    // binary in-process; the daemon binary sets it to `config.update.enabled`.
    if self_update_enabled && config.update.enabled && !skip_update_check {
        if let Err(e) = run_startup_update_check(&config, None).await {
            tracing::warn!(error = %e, "Startup update check failed: {e}");
        }
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

    // Resolve the identity directory. Precedence:
    //   1. `config.identity_dir` — explicit host-supplied directory. This is the
    //      storage boundary for in-process embedding: when set, ALL identity
    //      keys derive from it and `~/.x0x` is never touched.
    //   2. `~/.x0x-<name>` — instance-scoped directory when `--name` is active.
    //   3. `None` — default daemon behaviour (keys fall back to `~/.x0x`).
    let identity_dir = match (&config.identity_dir, &instance_name) {
        (Some(dir), _) => {
            tokio::fs::create_dir_all(dir)
                .await
                .context("failed to create configured identity directory")?;
            tracing::info!("Identity directory: {} (configured)", dir.display());
            Some(dir.clone())
        }
        (None, Some(name)) => {
            let dir = dirs::home_dir()
                .context("home directory required for instance identity directory")?
                .join(format!(".x0x-{name}"));
            tokio::fs::create_dir_all(&dir)
                .await
                .context("failed to create instance identity directory")?;
            tracing::info!("Identity directory: {}", dir.display());
            Some(dir)
        }
        (None, None) => None,
    };

    // Create agent
    //
    // Peer cache is scoped per data_dir when a custom data_dir is configured
    // (e.g., for named instances or test setups). This prevents VPS peer
    // addresses from previous runs polluting local-only configurations.
    // When using the default data_dir, the shared cache is used so that the
    // main daemon benefits from cached peers across restarts.
    let cache_dir = if config.data_dir != default_data_dir() {
        let dir = config.data_dir.join("peers");
        let _ = std::fs::create_dir_all(&dir);
        dir
    } else {
        shared_cache_dir().join("peers")
    };
    let network_config = NetworkConfig {
        bind_addr: Some(bind_address),
        bootstrap_nodes: config.bootstrap_peers.clone(),
        max_connections: 50,
        connection_timeout: std::time::Duration::from_secs(30),
        stats_interval: std::time::Duration::from_secs(60),
        peer_cache_path: (!cli_disable_peer_cache).then(|| cache_dir.join("peers.cache")),
        pinned_bootstrap_peers: std::collections::HashSet::new(),
        inbound_allowlist: std::collections::HashSet::new(),
        max_peers_per_ip: 3,
        // CLI flag wins over config TOML so operators can override on a
        // single invocation without editing the config file.
        port_mapping_enabled: config.port_mapping_enabled && !cli_no_port_mapping,
    };

    let contacts_path = config.data_dir.join("contacts.json");
    let mut builder = Agent::builder()
        .with_network_config(network_config)
        .with_gossip_config(config.gossip.clone())
        .with_peer_cache_dir(cache_dir)
        .with_contact_store_path(&contacts_path)
        .with_heartbeat_interval(config.heartbeat_interval_secs)
        .with_identity_ttl(config.identity_ttl_secs);

    if let Some(secs) = config.presence_beacon_interval_secs {
        builder = builder.with_presence_beacon_interval(secs);
    }
    if let Some(secs) = config.presence_event_poll_interval_secs {
        builder = builder.with_presence_event_poll_interval(secs);
    }
    if let Some(secs) = config.presence_offline_timeout_secs {
        builder = builder.with_presence_offline_timeout(secs);
    }
    if cli_disable_peer_cache {
        tracing::info!("Peer cache disabled by --disable-peer-cache");
        builder = builder.with_peer_cache_disabled();
    }

    // NOTE: --no-hard-coded-bootstrap only clears configured seed peers.
    // mDNS LAN discovery and the peer cache remain active by design so that:
    //   - Local mesh (two laptops on WiFi) still works via mDNS
    //   - FOAF presence discovery still finds peers
    //   - Previously-seen peers can reconnect via cache

    if let Some(ref id_dir) = identity_dir {
        builder = builder
            .with_machine_key(id_dir.join("machine.key"))
            .with_agent_key_path(id_dir.join("agent.key"))
            .with_agent_cert_path(id_dir.join("agent.cert"));
    }

    if let Some(ref user_key_path) = config.user_key_path {
        builder = builder.with_user_key_path(user_key_path);
        tracing::info!("User key path: {}", user_key_path.display());
    } else if let Some(ref id_dir) = identity_dir {
        // Storage boundary: with an explicit identity directory and no
        // configured user key, scope the (opt-in) user key lookup to that
        // directory so the builder never falls back to reading `~/.x0x/user.key`.
        // `with_user_key_path` loads only if the file exists and never
        // auto-generates, so this stays opt-in.
        builder = builder.with_user_key_path(id_dir.join("user.key"));
    }

    // Fix A (Issue #110 Phase 2): perform every agent-independent fallible
    // startup step BEFORE building the agent. `Agent::builder().build()` spawns
    // the NetworkNode receiver/accept/eviction tasks (and binds the QUIC
    // socket), so any error AFTER it would leak those running tasks for an
    // embedder. The common failure — API port already in use — is caught here,
    // before the agent exists, so `serve_with_options()` returns Err having
    // started nothing.

    // MLS groups are session-scoped (saorsa-mls groups are not serializable)
    let mls_groups_path = config.data_dir.join("mls_groups.bin");
    let mls_groups: HashMap<String, x0x::mls::MlsGroup> = HashMap::new();

    // Load named groups from disk (if any)
    let named_groups_path = config.data_dir.join("named_groups.json");
    let treekem_dir = config.data_dir.join("treekem");
    if let Err(e) = tokio::fs::create_dir_all(&treekem_dir).await {
        tracing::warn!(
            "failed to create TreeKEM snapshot dir {}: {e}",
            treekem_dir.display()
        );
    }
    recover_treekem_named_journals(&named_groups_path, &treekem_dir)
        .await
        .map_err(|e| anyhow::anyhow!("failed to recover TreeKEM persistence journal: {e}"))?;
    let named_groups = load_named_groups(&named_groups_path).await?;

    // Load or generate API bearer token for local authentication.
    let api_token = auth::load_or_generate_api_token(&config.data_dir).await?;

    // Bind the API listener early so the daemon can report the actual bound
    // address even when configured with an ephemeral port. Done before the agent
    // is built so a bind failure (port in use) returns Err with nothing running.
    let listener = tokio::net::TcpListener::bind(config.api_address)
        .await
        .context("failed to bind API address")?;
    let actual_api_addr = listener.local_addr()?;

    let (broadcast_tx, _) = broadcast::channel::<SseEvent>(256);
    // Load or generate the per-daemon ML-KEM-768 keypair. Persisted under
    // `<data_dir>/agent_kem.key` with mode 0600. This keypair is the root of
    // trust for `SecureShareDelivered` — only the holder of the secret half
    // can open group-shared-secret envelopes addressed to this agent.
    let agent_kem_path = config.data_dir.join("agent_kem.key");
    let agent_kem_keypair = Arc::new(
        x0x::groups::kem_envelope::AgentKemKeypair::load_or_generate(&agent_kem_path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to load/generate agent KEM keypair: {e}"))?,
    );
    tracing::info!(
        "agent KEM-768 public key loaded ({} bytes)",
        agent_kem_keypair.public_bytes.len()
    );

    // All agent-independent fallible startup has succeeded. Build the agent now
    // (this spawns the network tasks and binds the QUIC socket). From here on,
    // any fallible step must `agent.shutdown().await` on the error path so a
    // failure does not leak the agent/network/tasks.
    let agent = builder.build().await.context("failed to create agent")?;

    tracing::info!("Agent ID: {}", agent.agent_id());
    tracing::info!("Machine ID: {}", agent.machine_id());
    if let Some(uid) = agent.user_id() {
        tracing::info!("User ID: {}", uid);
    }

    // Attach the agent-owned contact store to gossip and API state so the
    // DM inbox trust evaluator observes the same mutations made by REST
    // contact/card endpoints.
    let contacts = Arc::clone(agent.contacts());
    agent.set_contacts(Arc::clone(&contacts));
    tracing::info!("Contact store loaded from {}", contacts_path.display());

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let (shutdown_notify, _) = watch::channel(false);
    let agent = Arc::new(agent);
    let (exec_dm_tx, exec_dm_rx) = mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1024);
    let (group_public_dm_tx, mut group_public_dm_rx) =
        mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1024);
    let (kv_store_delta_dm_tx, mut kv_store_delta_dm_rx) =
        mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1024);
    let exec_service = x0x::exec::ExecService::spawn(Arc::clone(&agent), exec_policy, exec_dm_rx);

    // ADR-0012 Phase 4: restore live TreeKEM groups from on-disk snapshots.
    // Must happen before the AppState is built so secure endpoints see the
    // groups immediately. Done with `named_groups` still owned (it is moved
    // into the RwLock below).
    let treekem_groups = restore_treekem_groups(&named_groups, agent.as_ref(), &treekem_dir).await;

    let state = Arc::new(AppState {
        agent: Arc::clone(&agent),
        subscriptions: RwLock::new(HashMap::new()),
        task_lists: RwLock::new(HashMap::new()),
        kv_stores: RwLock::new(HashMap::new()),
        named_groups: RwLock::new(named_groups),
        named_groups_path,
        group_metadata_tasks: RwLock::new(HashMap::new()),
        group_card_cache: RwLock::new(HashMap::new()),
        directory_cache: RwLock::new(x0x::groups::DirectoryShardCache::default()),
        directory_subscriptions: RwLock::new(x0x::groups::SubscriptionSet::default()),
        directory_subscriptions_path: config.data_dir.join("directory-subscriptions.json"),
        directory_tasks: RwLock::new(HashMap::new()),
        directory_digest_interval_secs: config
            .directory_digest_interval_secs
            .unwrap_or(DIRECTORY_DIGEST_INTERVAL_SECS),
        directory_resubscribe_jitter_ms: config
            .directory_resubscribe_jitter_ms
            .unwrap_or(DIRECTORY_RESUBSCRIBE_JITTER_MS),
        public_messages: RwLock::new(HashMap::new()),
        public_message_tasks: RwLock::new(HashMap::new()),
        agent_kem_keypair: Arc::clone(&agent_kem_keypair),
        contacts,
        mls_groups: RwLock::new(mls_groups),
        mls_groups_path,
        pending_join_results: RwLock::new(HashMap::new()),
        expected_join_result_inviters: StdMutex::new(HashMap::new()),
        pending_welcomes: RwLock::new(HashMap::new()),
        pending_welcome_receives: RwLock::new(HashMap::new()),
        pending_welcome_waiters: RwLock::new(HashMap::new()),
        pending_welcome_acks: RwLock::new(HashMap::new()),
        treekem_pending_events: RwLock::new(HashMap::new()),
        treekem_event_log: RwLock::new(HashMap::new()),
        treekem_catchup_throttle: RwLock::new(HashMap::new()),
        group_membership_locks: RwLock::new(HashMap::new()),
        treekem_groups: RwLock::new(treekem_groups),
        treekem_dir,
        ws_sessions: RwLock::new(HashMap::new()),
        ws_topics: RwLock::new(HashMap::new()),
        ws_outbound_stats: Arc::new(WsOutboundStats::default()),
        api_address: actual_api_addr,
        start_time: Instant::now(),
        broadcast_tx,
        file_transfers: RwLock::new(HashMap::new()),
        receive_hashers: RwLock::new(HashMap::new()),
        pending_file_chunks: RwLock::new(HashMap::new()),
        file_chunk_acks: RwLock::new(HashMap::new()),
        transfers_dir: config.data_dir.join("transfers"),
        shutdown_tx,
        shutdown_notify,
        update_config: config.update.clone(),
        self_update_enabled,
        upgrade_check_cache: Mutex::new(None),
        upgrade_apply_lock: Arc::new(Mutex::new(())),
        api_token,
        sessions: auth::SessionStore::new(auth::SESSION_TOKEN_TTL),
        exec_service: Arc::clone(&exec_service),
        groups_diagnostics: Arc::new(x0x::groups::GroupsDiagnostics::new()),
    });

    // Fix A (Issue #110 Phase 2 + #116): the `api.port` advertisement is written
    // here, before any long-lived server-owned task is spawned. The agent and the
    // ExecService ARE already built/spawned by this point (both needed for
    // AppState), so on the error path we must tear BOTH down — ExecService first
    // (its loops use the agent transport), then `agent.shutdown()` — so a failed
    // write does not leak the exec loops or the agent/network. The file is removed
    // again in the shutdown tail.
    let port_file = config.data_dir.join("api.port");
    if let Err(e) = tokio::fs::write(&port_file, actual_api_addr.to_string()).await {
        exec_service.shutdown().await;
        agent.shutdown().await;
        return Err(anyhow::Error::new(e).context("failed to write api.port"));
    }
    tracing::info!(
        "API server listening on {actual_api_addr} (port file: {})",
        port_file.display()
    );

    // Fix C (Issue #110 Phase 2): collect every server-owned background-task
    // `JoinHandle` spawned in the startup path so the shutdown tail can
    // grace-await then abort any straggler. (Agent-internal and ExecService tasks
    // are owned by the Agent/ExecService and stopped by their own `shutdown()`
    // calls in the shutdown tail — issue #116 — not collected here.)
    let mut bg_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    let existing_group_ids: Vec<String> = {
        let groups = state.named_groups.read().await;
        groups.keys().cloned().collect()
    };
    for group_id in existing_group_ids {
        // The metadata + public-message listeners spawned here self-register in
        // `state.group_metadata_tasks` / `state.public_message_tasks`; the
        // shutdown tail drains and aborts those maps directly (Fix C), so there
        // is nothing to collect into `bg_tasks` from this call.
        ensure_named_group_listeners(Arc::clone(&state), &group_id).await;
    }

    // P0-1: subscribe to the global group discovery topic so remote public
    // groups populate the local card cache without manual import.
    bg_tasks.extend(spawn_global_discovery_listener(Arc::clone(&state)).await);
    // Phase C.2: load persisted shard subscriptions and re-subscribe with
    // staggered jitter to avoid anti-entropy storms.
    bg_tasks.extend(spawn_directory_resubscribe(Arc::clone(&state)).await);
    // Phase C.2: subscribe inbound direct messages for the
    // ListedToContacts pairwise sync channel.
    bg_tasks.extend(spawn_listed_to_contacts_listener(Arc::clone(&state)).await);
    // Phase E: subscribe to a stable global SignedPublic message fallback so
    // first messages are not dependent on a brand-new per-group topic tree.
    bg_tasks.extend(spawn_global_public_message_listener(Arc::clone(&state)).await);

    // Re-publish our own discoverable group cards after startup so late joiners
    // pick them up.
    let discoverable_ids: Vec<String> = {
        let groups = state.named_groups.read().await;
        groups
            .iter()
            .filter(|(_, info)| {
                info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
            })
            .map(|(id, _)| id.clone())
            .collect()
    };
    let republish_interval_secs = config.group_card_republish_interval_secs.unwrap_or(300);
    if republish_interval_secs > 0 {
        let state_for_republish = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            // First publish after a short warmup so the gossip mesh has a chance
            // to form. Then republish periodically so late joiners also see cards.
            // Without this, a peer that starts after another daemon published
            // would miss the initial card.
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut shutdown = state_for_republish.shutdown_notify.subscribe();
            loop {
                let current_ids: Vec<String> = {
                    let groups = state_for_republish.named_groups.read().await;
                    groups
                        .iter()
                        .filter(|(_, info)| {
                            info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
                        })
                        .map(|(id, _)| id.clone())
                        .collect()
                };
                for id in current_ids {
                    publish_group_card_to_discovery(&state_for_republish, &id).await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(republish_interval_secs)) => {}
                    _ = shutdown.changed() => break,
                }
            }
        }));
    }
    // Consume the pre-computed list to avoid the dead-warning.
    let _ = discoverable_ids;

    // Join network in background — API is available immediately
    let join_agent = Arc::clone(&agent);
    let rendezvous_enabled = config.rendezvous_enabled;
    let rendezvous_validity_ms = config.rendezvous_validity_ms;

    // Start the DM inbox as soon as join_network has created the gossip
    // runtime. join_network may keep working through slow bootstrap/cache
    // peers for a long time; the daemon must still be able to receive gossip
    // DMs once `/agent/card` advertises a KEM key.
    let dm_inbox_agent = Arc::clone(&agent);
    let dm_inbox_kem = Arc::clone(&agent_kem_keypair);
    let dm_inbox_exec_route_tx = exec_dm_tx.clone();
    let dm_inbox_group_public_route_tx = group_public_dm_tx.clone();
    let dm_inbox_kv_store_delta_route_tx = kv_store_delta_dm_tx.clone();
    bg_tasks.push(tokio::spawn(start_dm_inbox_when_gossip_ready(
        dm_inbox_agent,
        dm_inbox_kem,
        dm_inbox_exec_route_tx,
        dm_inbox_group_public_route_tx,
        dm_inbox_kv_store_delta_route_tx,
    )));

    bg_tasks.push(tokio::spawn(async move {
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
    }));

    let self_published_release_manifests =
        Arc::new(Mutex::new(SelfPublishedReleaseManifests::default()));

    // Reclaim upgrade debris left by previous failed/interrupted attempts:
    // orphaned `.x0x-upgrade-*` temp dirs and `*.x0xold-*` sidelined binaries.
    // Runs UNCONDITIONALLY (deliberately NOT gated on self_update_enabled): this
    // is the disk-fill safety net from the Windows self-update fix and must clean
    // a machine even when self-update is disabled. It only matches x0x-specific
    // artifact patterns next to the binary, so it is a harmless no-op for an
    // embedder (which never creates such artifacts) — no host files can match.
    bg_tasks.push(tokio::spawn(async {
        let removed = tokio::task::spawn_blocking(|| {
            let exe = x0x::upgrade::apply::current_binary_path().ok()?;
            let dir = exe.parent()?.to_path_buf();
            Some(x0x::upgrade::sweep_stale_upgrade_artifacts(
                &dir,
                Duration::from_secs(3600),
            ))
        })
        .await
        .ok()
        .flatten()
        .unwrap_or(0);
        if removed > 0 {
            tracing::info!(removed, "Reclaimed stale upgrade artifacts at startup");
        }
    }));

    // Gossip-based release subscription (primary update mechanism). This
    // listener can download + install + restart, so it is gated on
    // `self_update_enabled` — embedders never replace the host binary.
    if self_update_enabled && config.update.enabled && config.update.gossip_updates {
        let update_config = config.update.clone();
        let agent_for_gossip = Arc::clone(&state.agent);
        let data_dir = config.data_dir.clone();
        let upgrade_apply_lock = Arc::clone(&state.upgrade_apply_lock);
        let self_published_for_gossip = Arc::clone(&self_published_release_manifests);
        bg_tasks.push(tokio::spawn(async move {
            run_gossip_update_listener(
                agent_for_gossip,
                update_config,
                data_dir,
                upgrade_apply_lock,
                self_published_for_gossip,
            )
            .await;
        }));
    }

    // Broadcast current manifest to gossip after joining the network.
    // Ensures nodes that missed the initial gossip window can still receive it.
    // Also syncs SKILL.md with the current manifest.
    // Fix D (Issue #110 Phase 2): gated on `self_update_enabled` — this fetches a
    // GitHub release manifest and writes SKILL.md, both updater side-effects an
    // embedder with self-update off must not perform. The daemon keeps it on
    // (self_update_enabled = config.update_enabled()), so behaviour is unchanged.
    if self_update_enabled && config.update.enabled {
        let agent_for_broadcast = Arc::clone(&state.agent);
        let update_config = config.update.clone();
        let data_dir_for_broadcast = config.data_dir.clone();
        let self_published_for_broadcast = Arc::clone(&self_published_release_manifests);
        bg_tasks.push(tokio::spawn(async move {
            broadcast_current_manifest(
                &agent_for_broadcast,
                &update_config.repo,
                update_config.include_prereleases,
                &data_dir_for_broadcast,
                self_published_for_broadcast,
            )
            .await;
        }));
    }

    // GitHub fallback poll (safety net, default every 48h). Install/restart
    // capable, so gated on `self_update_enabled` (embedders opt out).
    if self_update_enabled
        && config.update.enabled
        && config.update.fallback_check_interval_minutes > 0
    {
        let update_config = config.update.clone();
        let agent_for_poll = Arc::clone(&state.agent);
        let data_dir_for_poll = config.data_dir.clone();
        let upgrade_apply_lock = Arc::clone(&state.upgrade_apply_lock);
        let self_published_for_poll = Arc::clone(&self_published_release_manifests);
        bg_tasks.push(tokio::spawn(async move {
            run_fallback_github_poll(
                agent_for_poll,
                update_config,
                data_dir_for_poll,
                upgrade_apply_lock,
                self_published_for_poll,
            )
            .await;
        }));
    }

    // Background rendezvous re-advertisement (re-advertise every validity_ms / 2)
    if config.rendezvous_enabled && config.rendezvous_validity_ms > 0 {
        let rendezvous_agent = Arc::clone(&state.agent);
        let validity_ms = config.rendezvous_validity_ms;
        let mut shutdown_rx = state.shutdown_notify.subscribe();
        bg_tasks.push(tokio::spawn(async move {
            let interval_secs = (validity_ms / 2).max(60_000) / 1000;
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.tick().await; // skip immediate tick (already advertised at startup)
            loop {
                // Watch shutdown so teardown is prompt (Fix C): without this the
                // loop would only stop when aborted at the end of the grace window.
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = ticker.tick() => {}
                }
                if let Err(e) = rendezvous_agent.advertise_identity(validity_ms).await {
                    tracing::warn!("Periodic rendezvous re-advertisement failed: {e}");
                } else {
                    tracing::debug!("Rendezvous re-advertisement published");
                }
            }
        }));
    }

    // Background connectivity snapshot logger — writes an ant-quic NodeStatus
    // summary line every 60 seconds at target "x0x::diag::connectivity". This
    // gives journalctl a tick-by-tick record of UPnP state, external address
    // observations, direct vs relayed counts, and hole-punch success rate so
    // long-running deployments have a time series to diagnose from without
    // polling the HTTP diagnostics endpoint.
    {
        let diag_state = Arc::clone(&state);
        let mut shutdown_rx = state.shutdown_notify.subscribe();
        bg_tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.tick().await; // skip the immediate tick — node is still warming up
            loop {
                // Watch shutdown so teardown is prompt (Fix C).
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = ticker.tick() => {}
                }
                let Some(network) = diag_state.agent.network() else {
                    continue;
                };
                let Some(ns) = network.node_status().await else {
                    continue;
                };
                tracing::info!(
                    target: "x0x::diag::connectivity",
                    nat_type = ?ns.nat_type,
                    can_receive_direct = ?ns.can_receive_direct,
                    has_global_address = ns.has_global_address,
                    external_addrs = ns.external_addrs.len(),
                    port_mapping_active = ns.port_mapping_active,
                    port_mapping_addr = ?ns.port_mapping_addr,
                    mdns_browsing = ns.mdns_browsing,
                    mdns_advertising = ns.mdns_advertising,
                    mdns_discovered = ns.mdns_discovered_peers,
                    connected_peers = ns.connected_peers,
                    direct_connections = ns.direct_connections,
                    relayed_connections = ns.relayed_connections,
                    hole_punch_success_rate = ns.hole_punch_success_rate,
                    avg_rtt_ms = ns.avg_rtt.as_millis() as u64,
                    uptime_s = ns.uptime.as_secs(),
                    "connectivity snapshot"
                );
            }
        }));
    }

    // Background file-message listener — processes FileMessage on the direct channel
    {
        let file_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
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
        }));
    }

    // Background join-result listener — joiner-initiated recovery path for
    // fresh TreeKEM members that miss the anchor's opportunistic MemberAdded push.
    {
        let join_result_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = join_result_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(join_msg) = serde_json::from_slice::<JoinResultMessage>(&msg.payload) else {
                    continue;
                };
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "direct_classified_join_result",
                    sender = %hex::encode(msg.sender.as_bytes()),
                    len = msg.payload.len(),
                    verified = msg.verified,
                );
                handle_join_result_message(&join_result_state, &msg.sender, join_msg).await;
            }
        }));
    }

    // Background TreeKEM Welcome blob listener — pull-based bulk delivery for
    // oversized Welcome payloads referenced by named-group metadata events.
    {
        let welcome_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = welcome_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(welcome_msg) = serde_json::from_slice::<WelcomeBlobMessage>(&msg.payload)
                else {
                    continue;
                };
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "direct_classified_welcome_blob",
                    sender = %hex::encode(msg.sender.as_bytes()),
                    len = msg.payload.len(),
                    verified = msg.verified,
                );
                handle_welcome_blob_message(&welcome_state, &msg.sender, welcome_msg).await;
            }
        }));
    }

    // Background TreeKEM catch-up listener — explicit anti-entropy for
    // order-sensitive membership events that arrive before local readiness or
    // ahead of the local epoch/state frontier.
    {
        let catchup_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = catchup_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                if let Ok(request) = serde_json::from_slice::<TreeKemCatchupRequest>(&msg.payload) {
                    if request.message_type == "treekem_catchup_request" {
                        handle_treekem_catchup_request(
                            &catchup_state,
                            &msg.sender,
                            msg.verified,
                            request,
                        )
                        .await;
                    }
                    continue;
                }
                if let Ok(response) = serde_json::from_slice::<TreeKemCatchupResponse>(&msg.payload)
                {
                    if response.message_type == "treekem_catchup_response" {
                        handle_treekem_catchup_response(
                            &catchup_state,
                            &msg.sender,
                            msg.verified,
                            response,
                        )
                        .await;
                    }
                }
            }
        }));
    }

    // Background named-group metadata listener on the direct channel — applies
    // authority-authored review commits (approve / reject) that are
    // direct-delivered to a requester before they are grafted into the
    // metadata topic's gossip mesh (see `spawn_named_group_event_delivery`).
    // This mirrors the per-group metadata topic-subscription apply loop; the
    // shared apply handler re-validates the signed commit, enforces the same
    // authorization checks, and is idempotent, so applying via both the direct
    // and gossip channels is safe.
    {
        let meta_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            let mut rx = meta_state.agent.subscribe_direct();
            loop {
                let Some(msg) = rx.recv().await else { break };
                let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload)
                else {
                    continue; // not a named-group metadata event
                };
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "direct_classified_metadata_event",
                    sender = %hex::encode(msg.sender.as_bytes()),
                    len = msg.payload.len(),
                    verified = msg.verified,
                    event = named_group_metadata_event_kind(&event),
                );
                apply_named_group_metadata_event(&meta_state, event, msg.sender, msg.verified)
                    .await;
            }
        }));
    }

    // Background signed public-message listener for typed gossip-DM fallback
    // delivery. Per-group pubsub is still the primary fan-out path; this route
    // handles the same signed message when the sender additionally direct-
    // delivers it to active members.
    {
        let public_dm_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            while let Some(typed) = group_public_dm_rx.recv().await {
                if !typed.verified {
                    continue;
                }
                let Some(payload) = typed.payload.strip_prefix(GROUP_PUBLIC_MESSAGE_DM_PREFIX)
                else {
                    continue;
                };
                let Ok(msg) = serde_json::from_slice::<x0x::groups::GroupPublicMessage>(payload)
                else {
                    tracing::debug!(
                        sender = %hex::encode(typed.sender.as_bytes()),
                        "typed group-public DM payload was not a GroupPublicMessage"
                    );
                    continue;
                };
                let group_id = msg.group_id.clone();
                tracing::debug!(
                    group_id = %group_id,
                    sender = %hex::encode(typed.sender.as_bytes()),
                    "direct-delivered public group message received"
                );
                ingest_public_message(&public_dm_state, msg, &group_id).await;
            }
        }));
    }

    // Background KvStore delta listener for typed gossip-DM fallback delivery.
    // Store pub/sub remains the primary path; this side channel gives joined
    // peers a reliable replay of the same CRDT delta when the topic mesh is
    // late or congested. Peers that have not joined the store simply ignore it.
    {
        let kv_delta_state = Arc::clone(&state);
        bg_tasks.push(tokio::spawn(async move {
            while let Some(typed) = kv_store_delta_dm_rx.recv().await {
                if !typed.verified {
                    continue;
                }
                let Some(payload) = typed.payload.strip_prefix(KV_STORE_DELTA_DM_PREFIX) else {
                    continue;
                };
                let Ok(delta_msg) = serde_json::from_slice::<KvStoreDirectDelta>(payload) else {
                    tracing::debug!(
                        sender = %hex::encode(typed.sender.as_bytes()),
                        "typed kv-store DM payload was not a KvStoreDirectDelta"
                    );
                    continue;
                };
                apply_direct_kv_store_delta(&kv_delta_state, typed.sender, delta_msg).await;
            }
        }));
    }

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/agent", get(agent_info))
        .route("/introduction", get(introduction))
        .route("/agent/card", get(get_agent_card))
        .route("/.well-known/agent-card.json", get(get_a2a_agent_card))
        .route("/agent/card/import", post(import_agent_card))
        .route("/agent/sign", post(agent_sign))
        .route("/agent/verify", post(agent_verify))
        .route("/announce", post(announce_identity))
        .route("/peers", get(peers))
        .route("/network/status", get(network_status))
        .route("/publish", post(publish))
        .route("/subscribe", post(subscribe))
        .route("/subscribe/:id", delete(unsubscribe))
        .route("/events", get(events_sse))
        .route("/presence", get(presence))
        .route("/presence/online", get(presence_online))
        .route("/presence/foaf", get(presence_foaf))
        .route("/presence/find/:id", get(presence_find))
        .route("/presence/status/:id", get(presence_status))
        .route("/presence/events", get(presence_events))
        .route("/agents/discovered", get(discovered_agents))
        .route("/agents/discovered/:agent_id", get(discovered_agent))
        .route("/agents/:agent_id/machine", get(machine_for_agent_handler))
        .route("/machines/discovered", get(discovered_machines))
        .route("/machines/discovered/:machine_id", get(discovered_machine))
        .route("/machines/connect", post(connect_machine))
        .route("/users/:user_id/agents", get(agents_by_user_handler))
        .route("/users/:user_id/machines", get(machines_by_user_handler))
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
        // Static-prefix routes BEFORE /groups/:id so axum matches them first.
        .route("/groups/discover", get(discover_groups))
        // Phase C.2: shard discovery + nearby + subscription management.
        .route("/groups/discover/nearby", get(discover_groups_nearby))
        .route(
            "/groups/discover/subscriptions",
            get(list_discovery_subscriptions),
        )
        .route(
            "/groups/discover/subscribe",
            post(create_discovery_subscription),
        )
        .route(
            "/groups/discover/subscribe/:kind/:shard",
            delete(delete_discovery_subscription),
        )
        .route("/groups/cards/import", post(import_group_card))
        .route("/groups/cards/:id", get(get_group_card))
        .route("/groups/join", post(join_group_via_invite))
        .route("/groups/:id", get(get_named_group))
        .route("/groups/:id", patch(update_named_group))
        .route("/groups/:id/policy", patch(update_group_policy))
        .route("/groups/:id/members", get(get_named_group_members))
        .route("/groups/:id/members", post(add_named_group_member))
        .route(
            "/groups/:id/members/:agent_id",
            delete(remove_named_group_member),
        )
        .route(
            "/groups/:id/members/:agent_id/role",
            patch(update_member_role),
        )
        .route("/groups/:id/ban/:agent_id", post(ban_group_member))
        .route("/groups/:id/ban/:agent_id", delete(unban_group_member))
        .route("/groups/:id/requests", get(list_join_requests))
        .route("/groups/:id/requests", post(create_join_request))
        .route(
            "/groups/:id/requests/:request_id/approve",
            post(approve_join_request),
        )
        .route(
            "/groups/:id/requests/:request_id/reject",
            post(reject_join_request),
        )
        .route(
            "/groups/:id/requests/:request_id",
            delete(cancel_join_request),
        )
        // Phase D.2 — cross-daemon secure encrypt/decrypt.
        .route("/groups/:id/secure/encrypt", post(secure_group_encrypt))
        .route("/groups/:id/secure/decrypt", post(secure_group_decrypt))
        .route("/groups/:id/secure/reseal", post(secure_group_reseal))
        .route(
            "/groups/secure/open-envelope",
            post(secure_open_envelope_adversarial),
        )
        // Phase E: public-group messaging.
        .route("/groups/:id/send", post(send_group_public_message))
        .route("/groups/:id/messages", get(get_group_public_messages))
        .route("/groups/:id/invite", post(create_group_invite))
        .route("/groups/:id/display-name", put(set_group_display_name))
        // Phase D.3 — state-commit chain endpoints.
        .route("/groups/:id/state", get(get_group_state))
        .route("/groups/:id/state/commits", get(get_group_state_commits))
        .route("/groups/:id/state/seal", post(seal_group_state))
        .route("/groups/:id/state/withdraw", post(withdraw_group_state))
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
        .route("/upgrade/apply", post(apply_upgrade))
        // Network diagnostics
        .route("/network/bootstrap-cache", get(bootstrap_cache_stats))
        .route("/diagnostics/connectivity", get(connectivity_diagnostics))
        .route("/diagnostics/ack", get(ack_diagnostics))
        .route("/diagnostics/gossip", get(gossip_diagnostics))
        .route("/diagnostics/dm", get(dm_diagnostics))
        .route("/diagnostics/groups", get(groups_diagnostics))
        .route("/diagnostics/exec", get(exec_diagnostics))
        .route("/diagnostics/ws", get(ws_diagnostics))
        .route("/exec/run", post(exec_run))
        .route("/exec/cancel", post(exec_cancel))
        .route("/exec/sessions", get(exec_sessions))
        // Peer observability (ant-quic 0.27.1/0.27.2 surface)
        .route("/peers/:peer_id/probe", post(probe_peer_handler))
        .route("/peers/:peer_id/health", get(peer_health_handler))
        .route("/peers/events", get(peer_events_handler))
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
        // Session-token exchange (#127 / WS1.6): durable bearer → short-lived
        // browser session token, the only kind valid in ?token= query strings.
        .route("/auth/session", post(auth::create_session))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1 MB
        .layer({
            // Restrict CORS to exact loopback origins only.
            // The daemon API is a local control plane — external origins must not access it.
            use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin};
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin, _| {
                    auth::is_allowed_loopback_origin(origin)
                }))
                .allow_methods(AllowMethods::any())
                .allow_headers(AllowHeaders::any())
        })
        // Bearer-token authentication: all control-plane endpoints.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));

    // Note: the `api.port` advertisement is written above (Fix A), before any
    // background task is spawned, so a failure there leaves nothing to tear down.

    // Lifecycle: a CancellationToken drives library-initiated shutdown
    // (ServerHandle::shutdown / Drop). The mpsc `/shutdown` HTTP path still
    // works — the supervisor selects on both. Ctrl-C is deliberately NOT
    // handled here: a library must not steal the host's signal. The daemon
    // binary installs its own Ctrl-C handler around `ServerHandle::wait`.
    let cancel = tokio_util::sync::CancellationToken::new();
    let supervisor_cancel = cancel.clone();

    let task = tokio::spawn(async move {
        let mut server_shutdown_rx = state.shutdown_notify.subscribe();
        let mut server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = server_shutdown_rx.changed().await;
                })
                .await
        });

        // Fix B (Issue #110 Phase 2): include the axum server `JoinHandle` in the
        // select so that if the HTTP task ends on its own (panic / bind loss /
        // Err) the supervisor wakes immediately instead of waiting for an external
        // shutdown signal. The result is still drained and propagated below.
        // When the select observes the axum task ending on its own, capture its
        // result here so it can be propagated out of the supervisor — an Err or a
        // panic (JoinError) must surface from `wait()`/`shutdown_and_wait()`. A
        // clean self-requested graceful stop stays `Ok(())`.
        let mut server_result: Option<anyhow::Result<()>> = None;
        tokio::select! {
            _ = supervisor_cancel.cancelled() => {
                tracing::info!("Received shutdown request (cancellation)");
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Received API shutdown request");
            }
            res = &mut server => {
                server_result = Some(match res {
                    Ok(Ok(())) => {
                        tracing::info!("API server task ended on its own");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        tracing::error!("API server exited with error: {e}");
                        Err(anyhow::Error::new(e).context("API server error"))
                    }
                    Err(e) => {
                        tracing::error!("API server task failed: {e}");
                        Err(anyhow::Error::new(e).context("API server task failed"))
                    }
                });
            }
        }

        // Tell every `shutdown_notify`-watching loop (and the axum graceful
        // shutdown future) to stop.
        let _ = state.shutdown_notify.send(true);

        // Drain the axum server result and propagate any failure. If the select
        // already observed it ending, `server` was consumed there and its result
        // captured above; otherwise await it (with a bound) and propagate.
        let server_result: anyhow::Result<()> = match server_result {
            Some(res) => res,
            None => match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(Ok(Err(e))) => Err(anyhow::Error::new(e).context("API server error")),
                Ok(Err(e)) => Err(anyhow::Error::new(e).context("API server task failed")),
                Err(_) => {
                    tracing::warn!(
                        "API server did not shut down within 2s; aborting lingering connections"
                    );
                    server.abort();
                    let _ = server.await;
                    Ok(())
                }
            },
        };

        // Fix C (Issue #110 Phase 2 + 2b): tear down the server-owned tasks, the
        // ExecService loops, the Agent listeners, and the QUIC node so that when
        // this supervisor returns, the HTTP/SSE server, the server-owned
        // background tasks, the ExecService loops, the Agent-internal listeners,
        // the gossip runtime, and the QUIC NetworkNode are all stopped/closed.
        //
        // 0. `ExecService::shutdown()` first (issue #116): stop the exec inbound,
        //    peer-lifecycle, and session-idle loops while the Agent transport is
        //    still alive, so in-flight sessions can cancel cleanly before the
        //    network goes away.
        state.exec_service.shutdown().await;
        // 1. `Agent::begin_shutdown()` (issue #116 Codex finding 1): cancel the
        //    Agent's shutdown token and close its tracked-task registry NOW,
        //    BEFORE draining the server bg_tasks. A still-bootstrapping
        //    `join_network` is one of those bg_tasks; cancelling first makes its
        //    in-flight `start_identity_heartbeat`/`start_discovery_cache_reaper`/
        //    presence-start/`start_capability_advert_service`/delayed-reannounce
        //    no-op (each checks `is_cancelled()` under its handle lock), so it
        //    cannot leak a dedicated-handle service past `agent.shutdown()`.
        state.agent.begin_shutdown();
        // 2. Grace-await then abort every server background task, INCLUDING
        //    join_network. Tasks tracked in the AppState handle maps (metadata /
        //    public-message / directory shard listeners spawned at startup AND
        //    by request handlers) are included so nothing leaks. The grace
        //    window is a single bounded 2s budget across all tasks (not 2s each)
        //    so shutdown stays prompt regardless of task count; any task still
        //    running after the window is aborted. A cancelled/aborted task
        //    returns a `JoinError`; that is expected, never unwrap it. Draining
        //    here (after begin_shutdown, before agent.shutdown) guarantees
        //    join_network has fully stopped before the Agent stops are run.
        let mut bg_tasks = bg_tasks;
        bg_tasks
            .extend(std::mem::take(&mut *state.group_metadata_tasks.write().await).into_values());
        bg_tasks
            .extend(std::mem::take(&mut *state.public_message_tasks.write().await).into_values());
        bg_tasks.extend(std::mem::take(&mut *state.directory_tasks.write().await).into_values());
        // Keep abort handles so stragglers can be aborted after the grace window.
        // Fix C (issue #116): on the timeout path, AWAIT the aborts too — keep the
        // JoinHandles owned by `join` (select! over `&mut join` vs the 2s sleep)
        // so that after aborting we `join.await` the remainder. Without this, the
        // "join_network fully stopped before agent.shutdown()" guarantee would
        // only hold on the non-timeout path; now it holds on BOTH. A cancelled/
        // aborted task yields Err(JoinError) — expected, never unwrapped.
        let abort_handles: Vec<tokio::task::AbortHandle> =
            bg_tasks.iter().map(|h| h.abort_handle()).collect();
        let mut join = futures::future::join_all(bg_tasks);
        tokio::select! {
            _results = &mut join => {}
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                tracing::warn!("background tasks did not stop within grace; aborting stragglers");
                for handle in &abort_handles {
                    handle.abort();
                }
                let _results: Vec<Result<(), tokio::task::JoinError>> = join.await;
            }
        }
        // 3. Now that join_network is stopped (and the token cancelled so any
        //    in-flight start_* no-ops), tear the Agent down: stop heartbeat /
        //    reaper / DM-inbox / advert / presence, drain the Agent's own
        //    tracked listener tasks, shut down the gossip runtime, and shut down
        //    the QUIC NetworkNode. (The OS frees the UDP socket on process exit;
        //    ant-quic does not release it in-process — embedders that restart
        //    should use an ephemeral QUIC port.)
        state.agent.shutdown().await;

        // Clean up port file on shutdown (kept after task teardown so the
        // existing ordering — port advertisement removed last — is preserved).
        let _ = tokio::fs::remove_file(&port_file).await;
        tracing::info!("Shutdown complete");
        server_result
    });

    Ok(ServerHandle {
        local_addr: actual_api_addr,
        cancel,
        task: Some(task),
    })
}

pub fn validate_instance_name(name: &str) -> Result<()> {
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

pub async fn list_instances() -> Result<()> {
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

fn file_transfer_now() -> (u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs(), now.as_millis() as u64)
}

fn direct_message_send_config() -> x0x::dm::DmSendConfig {
    // Generic daemon/UI DMs should only return success after the inbox path
    // observes the recipient ACK. Callers that intentionally want
    // fire-and-forget gossip can pass `require_gossip_ack: false`.
    //
    // The raw-QUIC fallback (taken whenever the recipient's gossip-inbox
    // capability advert has not converged yet — always the case in the first
    // seconds after boot) must use ant-quic's receive-pipeline ACK. A
    // fire-and-forget raw send into a connection that is being superseded
    // reports Ok while the bytes are lost, the retry machinery never fires,
    // and the recipient's app never sees the message (the dogfood
    // group_join / hop-DM 25s-timeout black hole).
    x0x::dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(8),
        raw_quic_receive_ack_timeout: Some(Duration::from_secs(8)),
        ..x0x::dm::DmSendConfig::default()
    }
}

fn named_group_direct_delivery_config() -> x0x::dm::DmSendConfig {
    // Named-group metadata applies require `DirectMessage::verified == true`.
    // The gossip-inbox DM path verifies the signed DM envelope and marks the
    // bridged direct message verified. Raw QUIC can only mark messages
    // verified when the receiver already has a fresh AgentId -> MachineId
    // binding, so keep it as the fallback for peers whose gossip-inbox
    // capability advert has not converged yet. Terminal signed commits (for
    // example admin delete) are self-authenticating and explicitly re-check
    // authority on apply, so dropping the raw fallback can strand members after
    // their metadata listener exits.
    let mut config = direct_message_send_config();
    config.raw_quic_receive_ack_timeout = Some(Duration::from_secs(8));
    config.require_gossip_ack = true;
    config
}

async fn start_dm_inbox_when_gossip_ready(
    agent: Arc<x0x::Agent>,
    kem_keypair: Arc<x0x::groups::kem_envelope::AgentKemKeypair>,
    exec_route_tx: mpsc::Sender<x0x::dm_inbox::DmTypedPayload>,
    group_public_route_tx: mpsc::Sender<x0x::dm_inbox::DmTypedPayload>,
    kv_store_delta_route_tx: mpsc::Sender<x0x::dm_inbox::DmTypedPayload>,
) {
    for attempt in 1..=DM_INBOX_START_MAX_ATTEMPTS {
        let dm_inbox_config = x0x::dm_inbox::DmInboxConfig::default()
            .with_typed_payload_route(x0x::exec::EXEC_DM_PREFIX, exec_route_tx.clone())
            .with_typed_payload_route(
                GROUP_PUBLIC_MESSAGE_DM_PREFIX,
                group_public_route_tx.clone(),
            )
            .with_typed_payload_route(KV_STORE_DELTA_DM_PREFIX, kv_store_delta_route_tx.clone());
        match agent
            .start_dm_inbox(Arc::clone(&kem_keypair), dm_inbox_config)
            .await
        {
            Ok(()) => {
                if let Err(e) = agent.start_capability_advert_service().await {
                    tracing::warn!(
                        attempt,
                        "Capability advert service not ready after DM inbox start: {e}"
                    );
                }
                tracing::info!(
                    attempt,
                    "DM inbox service started independently of network join completion"
                );
                return;
            }
            Err(e) if attempt < DM_INBOX_START_MAX_ATTEMPTS => {
                tracing::debug!(attempt, "DM inbox not ready yet: {e}");
                tokio::time::sleep(DM_INBOX_START_RETRY_DELAY).await;
            }
            Err(e) => {
                tracing::warn!(
                    attempts = DM_INBOX_START_MAX_ATTEMPTS,
                    "Failed to start DM inbox service: {e}"
                );
                return;
            }
        }
    }
}

fn file_transfer_send_config() -> x0x::dm::DmSendConfig {
    let mut config = x0x::dm::DmSendConfig {
        prefer_raw_quic_if_connected: true,
        stop_fallback_on_raw_error: false,
        ..x0x::dm::DmSendConfig::default()
    };
    // File transfer has a stronger application-level ChunkAck after the
    // receiver persists each chunk, but the raw receive-ACK still matters for
    // stale raw connections: without it, ant-quic can report local send
    // success while the receiver never drains the chunk, leaving the sender to
    // fail only after the 60s application ack timeout. Keep the raw fast path,
    // but allow capability-aware gossip fallback when that raw receive-ACK
    // fails. DEFAULT_CHUNK_SIZE is sized to fit the DM envelope cap.
    config.raw_quic_receive_ack_timeout = Some(Duration::from_secs(8));
    config
}

fn file_transfer_control_send_config() -> x0x::dm::DmSendConfig {
    let mut config = file_transfer_send_config();
    // Offer/accept/reject/complete are low-volume control messages. They must
    // not be fire-and-forget: a stale raw connection can otherwise report local
    // send success while the peer never updates transfer state.
    config.raw_quic_receive_ack_timeout = Some(Duration::from_secs(8));
    config.stop_fallback_on_raw_error = false;
    config
}

/// Maximum number of file chunks a sender may have in flight (sent but
/// not yet acked) at any time. Caps the broadcast/queue pressure that
/// caused the 100M chunk-loss regression on 2026-04-30 — the previous
/// fire-and-forget loop bursted 3200 chunks faster than the receiver's
/// disk write rate, overflowing tokio's `broadcast::channel(256)` and
/// silently shedding chunks. With a window of 8, the sender can never
/// have more than 8 chunks ahead of the receiver's last ack.
const FILE_CHUNK_WINDOW: u64 = 8;

/// Maximum time the sender will wait for a single chunk ack before
/// considering the transfer failed. Generous enough to cover one
/// cross-continent disk-write round-trip; the receiver disk write +
/// QUIC return path is the slow leg.
const FILE_CHUNK_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Per-transfer chunk-ack slot. The sender registers this when it begins
/// streaming chunks; the file-message listener bumps `last_acked` and wakes
/// any waiter every time a `FileMessage::ChunkAck` lands for this transfer;
/// the sender's chunk loop blocks on `wait_for_chunk_window` when its in-flight
/// budget would exceed `FILE_CHUNK_WINDOW`.
pub(crate) struct FileChunkAckSlot {
    /// Highest contiguous sequence number the receiver has acked.
    /// `u64::MAX` is the sentinel for "no ack received yet".
    last_acked: AtomicU64,
    /// Notified every time `last_acked` changes.
    notify: tokio::sync::Notify,
}

impl FileChunkAckSlot {
    fn new() -> Self {
        Self {
            last_acked: AtomicU64::new(u64::MAX),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn record_ack(&self, sequence: u64) {
        // last_acked = max(last_acked, sequence), treating u64::MAX as -infinity.
        let mut current = self.last_acked.load(Ordering::SeqCst);
        loop {
            let new = if current == u64::MAX {
                sequence
            } else {
                current.max(sequence)
            };
            match self.last_acked.compare_exchange_weak(
                current,
                new,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        self.notify.notify_waiters();
    }

    /// Highest contiguous sequence acked, or `-1` if none acked yet (the
    /// `u64::MAX` sentinel). For `welcome.trace` diagnostics.
    fn highest_acked(&self) -> i64 {
        let v = self.last_acked.load(Ordering::SeqCst);
        if v == u64::MAX {
            -1
        } else {
            v as i64
        }
    }
}

/// Block until `last_acked >= n.saturating_sub(FILE_CHUNK_WINDOW)`, i.e.
/// until the sender's in-flight count would drop back to (or below) the
/// window. For the first `FILE_CHUNK_WINDOW` chunks this returns immediately
/// because the window isn't yet saturated.
async fn wait_for_chunk_window(slot: &FileChunkAckSlot, n: u64) -> std::result::Result<(), String> {
    if n < FILE_CHUNK_WINDOW {
        return Ok(());
    }
    let required = n - FILE_CHUNK_WINDOW;
    let deadline = tokio::time::Instant::now() + FILE_CHUNK_ACK_TIMEOUT;
    loop {
        let acked = slot.last_acked.load(Ordering::SeqCst);
        if acked != u64::MAX && acked >= required {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timeout waiting for file chunk ack >= {required}; last_acked={}",
                if acked == u64::MAX {
                    "<none>".to_string()
                } else {
                    acked.to_string()
                }
            ));
        }
        let notified = slot.notify.notified();
        tokio::pin!(notified);
        tokio::select! {
            _ = notified.as_mut() => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

async fn send_file_message(
    state: &Arc<AppState>,
    agent_id: &AgentId,
    msg: &x0x::files::FileMessage,
) -> std::result::Result<x0x::dm::DmReceipt, String> {
    let payload = serde_json::to_vec(msg).map_err(|e| format!("serialization failed: {e}"))?;
    state
        .agent
        .send_direct_with_config(agent_id, payload, file_transfer_control_send_config())
        .await
        .map_err(|e| e.to_string())
}

async fn send_file_chunk_message(
    state: &Arc<AppState>,
    agent_id: &AgentId,
    msg: &x0x::files::FileMessage,
) -> std::result::Result<x0x::dm::DmReceipt, String> {
    let payload = serde_json::to_vec(msg).map_err(|e| format!("serialization failed: {e}"))?;
    state
        .agent
        .send_direct_with_config(agent_id, payload, file_transfer_send_config())
        .await
        .map_err(|e| e.to_string())
}

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
    let mut source_path = body
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if agent_id_hex.is_empty() || sha256.is_empty() {
        return bad_request("agent_id and sha256 are required");
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
    let (now_secs, now_ms) = file_transfer_now();

    if source_path.is_empty() {
        if let Some(data_b64) = body
            .get("data_b64")
            .or_else(|| body.get("data_base64"))
            .and_then(|v| v.as_str())
        {
            let data = match BASE64.decode(data_b64) {
                Ok(data) => data,
                Err(e) => {
                    return bad_request(format!("invalid data_b64: {e}"));
                }
            };
            if data.len() as u64 != size {
                return bad_request("data_b64 length does not match size");
            }
            let actual_sha = hex::encode(Sha256::digest(&data));
            if !sha256.eq_ignore_ascii_case(&actual_sha) {
                return bad_request("data_b64 sha256 mismatch");
            }
            if let Err(e) = tokio::fs::create_dir_all(&state.transfers_dir).await {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to create transfer spool: {e}"),
                );
            }
            let spool_path = state.transfers_dir.join(format!("{transfer_id}.send"));
            if let Err(e) = tokio::fs::write(&spool_path, data).await {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to spool upload: {e}"),
                );
            }
            source_path = spool_path.to_string_lossy().into_owned();
        }
    }

    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let total_chunks = x0x::files::total_chunks_for_size(size, chunk_size);

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
        started_at: now_secs,
        started_at_unix_ms: now_ms,
        completed_at_unix_ms: None,
        source_path: if source_path.is_empty() {
            None
        } else {
            Some(source_path)
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

    match send_file_message(&state, &agent_id, &offer).await {
        Ok(receipt) => {
            tracing::info!(path = ?receipt.path, retries = receipt.retries_used, "File offer sent: {transfer_id} -> {agent_id_hex}");
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
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("send offer failed: {e}"),
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
        None => not_found("transfer not found"),
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
                return bad_request("transfer is not a pending receive");
            }
            None => {
                return not_found("transfer not found");
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
    let delivery_failed = match send_file_message(&state, &agent_id, &accept_msg).await {
        Ok(receipt) => {
            tracing::info!(path = ?receipt.path, retries = receipt.retries_used, "File accept sent: {id} -> {remote_agent_hex}");
            false
        }
        Err(e) => {
            tracing::warn!("Failed to send accept to sender: {e}");
            true
        }
    };

    if delivery_failed {
        // Revert to Pending so the accept can be retried
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&id) {
            t.status = x0x::files::TransferStatus::Pending;
        }
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "accepted but failed to notify sender — reverted to pending",
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
                t.completed_at_unix_ms = Some(file_transfer_now().1);
                remote_agent_hex = t.remote_agent_id.clone();
            }
            Some(_) => {
                return bad_request("transfer is not pending");
            }
            None => {
                return not_found("transfer not found");
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
        if let Err(e) = send_file_message(&state, &agent_id, &reject_msg).await {
            tracing::warn!("Failed to send reject to sender: {e}");
            delivery_failed = true;
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

// ---------------------------------------------------------------------------
// Self-update (gossip-based + GitHub fallback)
// ---------------------------------------------------------------------------

const RELEASE_REBROADCAST_INTERVAL: Duration = Duration::from_secs(300);
const SELF_PUBLISHED_RELEASE_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Default)]
struct SelfPublishedReleaseManifests {
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
async fn run_gossip_update_listener(
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
async fn run_fallback_github_poll(
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
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized");
    };

    let Some(status) = network.node_status().await else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "node not available");
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
    let mut has_global_address = status.has_global_address;

    let port = status.local_addr.port();

    // Discover global IPv4 address using UDP socket trick.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let std::net::IpAddr::V4(v4) = local.ip() {
                    if !v4.is_loopback() && !v4.is_unspecified() {
                        if !v4.is_private() && !v4.is_link_local() {
                            has_global_address = true;
                        }
                        // Include our locally inferred IPv4 candidate even when it is LAN-only.
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
                        has_global_address = true;
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
            "has_global_address": has_global_address,
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// POST /publish
async fn publish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishRequest>,
) -> impl IntoResponse {
    // Reject empty topic
    if req.topic.is_empty() {
        return bad_request("topic must not be empty");
    }

    // Decode base64 payload
    let payload = match BASE64.decode(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return bad_request(format!(
                "invalid base64 in payload field: {e}. \
                         The payload must be base64-encoded \
                         (e.g., use `echo -n \"hello\" | base64`)"
            ));
        }
    };

    match state.agent.publish(&req.topic, payload).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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
            let forwarder = tokio::spawn(async move {
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
                            "payload": BASE64.encode(&msg.payload),
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
                            topic = %LogHexId::topic(&topic),
                            "[5/6 x0xd] broadcast send failed (no SSE receivers)"
                        ),
                    }
                }
            });

            // Track the forwarder task so the DELETE handler can abort it.
            // Aborting drops the underlying `Subscription`, releasing the
            // gossip topic ref-count and stopping SSE delivery.
            let mut subs = state.subscriptions.write().await;
            subs.insert(
                id.clone(),
                RestSubscription {
                    topic: req.topic.clone(),
                    forwarder,
                },
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "subscription_id": id })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// DELETE /subscribe/:id
async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut subs = state.subscriptions.write().await;
    if let Some(sub) = subs.remove(&id) {
        // Stop the forwarder task. Dropping its `Subscription` releases the
        // gossip topic ref-count and ends message delivery for this stream.
        sub.forwarder.abort();
        tracing::info!(
            sub_id = %id,
            topic = %sub.topic,
            "unsubscribed: forwarder aborted, gossip subscription released"
        );
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        not_found("subscription not found")
    }
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// Query parameters for presence endpoints that accept TTL and timeout.
#[derive(Debug, Deserialize)]
struct PresenceQueryParams {
    /// FOAF hop count (default: 3).
    #[serde(default = "default_foaf_ttl")]
    ttl: u8,
    /// Query timeout in milliseconds (default: 5000).
    #[serde(default = "default_foaf_timeout_ms")]
    timeout_ms: u64,
}

fn default_foaf_ttl() -> u8 {
    3
}

fn default_foaf_timeout_ms() -> u64 {
    5000
}

/// GET /presence/online
///
/// List all agents currently online (network view: all non-blocked agents from
/// the local discovery cache).
async fn presence_online(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.online_agents().await {
        Ok(agents) => {
            let contacts = state.agent.contacts().read().await;
            let filtered = x0x::presence::filter_by_trust(
                agents,
                &contacts,
                x0x::presence::PresenceVisibility::Network,
            );
            let entries: Vec<_> = filtered.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /presence/foaf?ttl=3&timeout_ms=5000
///
/// FOAF random-walk discovery of nearby agents (social view: Trusted + Known only).
async fn presence_foaf(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PresenceQueryParams>,
) -> impl IntoResponse {
    match state
        .agent
        .discover_agents_foaf(params.ttl, params.timeout_ms)
        .await
    {
        Ok(agents) => {
            let contacts = state.agent.contacts().read().await;
            let filtered = x0x::presence::filter_by_trust(
                agents,
                &contacts,
                x0x::presence::PresenceVisibility::Social,
            );
            let entries: Vec<_> = filtered.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /presence/find/:id?ttl=3&timeout_ms=5000
///
/// Find a specific agent by hex-encoded AgentId via FOAF random walk.
async fn presence_find(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<PresenceQueryParams>,
) -> impl IntoResponse {
    let bytes = match hex::decode(&id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return bad_request("invalid agent id (expected 64 hex chars)");
        }
    };
    let agent_id = x0x::identity::AgentId(bytes);
    match state
        .agent
        .discover_agent_by_id(agent_id, params.ttl, params.timeout_ms)
        .await
    {
        Ok(Some(agent)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "agent": discovered_agent_entry(agent) })),
        ),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "agent": null })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /presence/status/:id
///
/// Local cache lookup for a specific agent — no network I/O.
async fn presence_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let bytes = match hex::decode(&id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return bad_request("invalid agent id (expected 64 hex chars)");
        }
    };
    let agent_id = x0x::identity::AgentId(bytes);
    let cached = state.agent.cached_agent(&agent_id).await;
    let online = cached.is_some();
    let entry = cached.map(discovered_agent_entry);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "online": online, "agent": entry })),
    )
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

fn discovered_machine_entry(machine: x0x::DiscoveredMachine) -> DiscoveredMachineEntry {
    DiscoveredMachineEntry {
        machine_id: hex::encode(machine.machine_id.as_bytes()),
        addresses: machine
            .addresses
            .into_iter()
            .map(|a| a.to_string())
            .collect(),
        announced_at: machine.announced_at,
        last_seen: machine.last_seen,
        nat_type: machine.nat_type,
        can_receive_direct: machine.can_receive_direct,
        is_relay: machine.is_relay,
        is_coordinator: machine.is_coordinator,
        agent_ids: machine
            .agent_ids
            .into_iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect(),
        user_ids: machine
            .user_ids
            .into_iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect(),
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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
                return not_found("agent not found within timeout");
            }
            Err(e) => {
                return api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"));
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
        Ok(None) => not_found("agent not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /agents/:agent_id/machine
async fn machine_for_agent_handler(
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

    match state.agent.machine_for_agent(agent_id).await {
        Ok(Some(machine)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "agent_id": agent_id_hex,
                "machine": discovered_machine_entry(machine),
            })),
        ),
        Ok(None) => not_found("agent machine not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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
            return bad_request("invalid user_id: expected 64 hex characters");
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
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

/// Parse a 64-character hex string into a MachineId.
fn parse_machine_id_hex(hex_str: &str) -> Result<MachineId, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(MachineId(arr))
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
    /// Policy preset name (private_secure / public_request_secure / public_open /
    /// public_announce). Defaults to `private_secure`.
    #[serde(default)]
    preset: Option<String>,
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

impl Default for CreateInviteRequest {
    fn default() -> Self {
        Self {
            expiry_secs: default_expiry(),
        }
    }
}

fn default_expiry() -> u64 {
    x0x::groups::invite::DEFAULT_EXPIRY_SECS
}

/// Request body for PUT /groups/:id/display-name.
#[derive(Debug, Deserialize)]
struct SetDisplayNameRequest {
    name: String,
}

/// Request body for POST /groups/:id/members.
#[derive(Debug, Deserialize)]
struct AddNamedGroupMemberRequest {
    agent_id: String,
    #[serde(default)]
    display_name: Option<String>,
    /// Base64 postcard-encoded TreeKEM KeyPackage supplied by the target.
    /// Required when directly adding to a TreeKEM group.
    #[serde(default)]
    treekem_key_package_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WelcomeRef {
    welcome_id: String,
    byte_len: u64,
    source: String,
}

#[derive(Debug, Clone)]
struct PendingJoinResult {
    event: NamedGroupMetadataEvent,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct ExpectedJoinResultInviter {
    inviter_agent_id: String,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingWelcome {
    group_id: String,
    joiner_agent: String,
    bytes: Vec<u8>,
    created_at: Instant,
}

struct PendingWelcomeReceive {
    group_id: String,
    source: String,
    byte_len: u64,
    total_chunks: u64,
    chunks: BTreeMap<u64, Vec<u8>>,
    received_bytes: u64,
}

#[derive(Debug, Clone)]
struct PendingTreeKemMetadataEvent {
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    queued_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeKemCatchupRequest {
    message_type: String,
    group_id: String,
    requester_agent_id: String,
    from_revision: u64,
    from_treekem_epoch: u64,
    current_state_hash: String,
    missing_prev_state_hash: Option<String>,
    limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeKemCatchupResponse {
    message_type: String,
    group_id: String,
    events: Vec<NamedGroupMetadataEvent>,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum JoinResultMessage {
    FetchRequest {
        group_id: String,
        member_agent_id: String,
    },
    Result {
        event: Box<NamedGroupMetadataEvent>,
    },
}

fn named_group_metadata_event_kind(event: &NamedGroupMetadataEvent) -> &'static str {
    match event {
        NamedGroupMetadataEvent::MemberAdded { .. } => "member_added",
        NamedGroupMetadataEvent::MemberRemoved { .. } => "member_removed",
        NamedGroupMetadataEvent::GroupDeleted { .. } => "group_deleted",
        NamedGroupMetadataEvent::PolicyUpdated { .. } => "policy_updated",
        NamedGroupMetadataEvent::MemberRoleUpdated { .. } => "member_role_updated",
        NamedGroupMetadataEvent::MemberBanned { .. } => "member_banned",
        NamedGroupMetadataEvent::MemberUnbanned { .. } => "member_unbanned",
        NamedGroupMetadataEvent::JoinRequestCreated { .. } => "join_request_created",
        NamedGroupMetadataEvent::JoinRequestApproved { .. } => "join_request_approved",
        NamedGroupMetadataEvent::JoinRequestRejected { .. } => "join_request_rejected",
        NamedGroupMetadataEvent::JoinRequestCancelled { .. } => "join_request_cancelled",
        NamedGroupMetadataEvent::GroupCardPublished { .. } => "group_card_published",
        NamedGroupMetadataEvent::GroupMetadataUpdated { .. } => "group_metadata_updated",
        NamedGroupMetadataEvent::MemberJoined { .. } => "member_joined",
        NamedGroupMetadataEvent::SecureShareDelivered { .. } => "secure_share_delivered",
    }
}

fn named_group_metadata_event_group_id(event: &NamedGroupMetadataEvent) -> &str {
    match event {
        NamedGroupMetadataEvent::MemberAdded { group_id, .. }
        | NamedGroupMetadataEvent::MemberRemoved { group_id, .. }
        | NamedGroupMetadataEvent::GroupDeleted { group_id, .. }
        | NamedGroupMetadataEvent::PolicyUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberRoleUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberBanned { group_id, .. }
        | NamedGroupMetadataEvent::MemberUnbanned { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCreated { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestRejected { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCancelled { group_id, .. }
        | NamedGroupMetadataEvent::GroupCardPublished { group_id, .. }
        | NamedGroupMetadataEvent::GroupMetadataUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberJoined { group_id, .. }
        | NamedGroupMetadataEvent::SecureShareDelivered { group_id, .. } => group_id,
    }
}

fn withdrawn_group_allows_metadata_event(event: &NamedGroupMetadataEvent) -> bool {
    matches!(
        event,
        NamedGroupMetadataEvent::GroupDeleted {
            commit: Some(commit),
            ..
        } if commit.withdrawn
    )
}

fn named_group_metadata_event_commit(
    event: &NamedGroupMetadataEvent,
) -> Option<&x0x::groups::GroupStateCommit> {
    match event {
        NamedGroupMetadataEvent::MemberAdded { commit, .. }
        | NamedGroupMetadataEvent::MemberRemoved { commit, .. }
        | NamedGroupMetadataEvent::GroupDeleted { commit, .. }
        | NamedGroupMetadataEvent::PolicyUpdated { commit, .. }
        | NamedGroupMetadataEvent::MemberRoleUpdated { commit, .. }
        | NamedGroupMetadataEvent::MemberBanned { commit, .. }
        | NamedGroupMetadataEvent::MemberUnbanned { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestCreated { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestRejected { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestCancelled { commit, .. }
        | NamedGroupMetadataEvent::GroupMetadataUpdated { commit, .. } => commit.as_ref(),
        NamedGroupMetadataEvent::GroupCardPublished { .. }
        | NamedGroupMetadataEvent::MemberJoined { .. }
        | NamedGroupMetadataEvent::SecureShareDelivered { .. } => None,
    }
}

fn live_group_allows_metadata_withdrawal_commit(event: &NamedGroupMetadataEvent) -> bool {
    match named_group_metadata_event_commit(event) {
        Some(commit) if commit.withdrawn => withdrawn_group_allows_metadata_event(event),
        _ => true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WelcomeBlobMessage {
    FetchRequest {
        group_id: String,
        welcome_id: String,
    },
    Offer {
        group_id: String,
        welcome_id: String,
        byte_len: u64,
        chunk_size: usize,
        total_chunks: u64,
        blake3_hex: String,
    },
    Chunk {
        welcome_id: String,
        sequence: u64,
        data: String,
    },
    ChunkAck {
        welcome_id: String,
        sequence: u64,
    },
    Complete {
        welcome_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
// Phase D.3 enlarged GroupCard with a ~6 KB authority signature and a
// long ML-KEM envelope. Boxing any one variant would force serde-boxed
// wire format breaks; the in-memory size delta is irrelevant compared
// to the gossip plumbing cost.
#[allow(clippy::large_enum_variant)]
enum NamedGroupMetadataEvent {
    MemberAdded {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        display_name: Option<String>,
        /// Base64 postcard-encoded TreeKEM Commit for existing members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// Base64 postcard-encoded TreeKEM Welcome for the added member.
        /// Legacy fallback; new events carry `welcome_ref` instead.
        #[serde(default)]
        treekem_welcome_b64: Option<String>,
        /// Content-addressed pull reference for the added member's TreeKEM Welcome.
        #[serde(default)]
        welcome_ref: Option<WelcomeRef>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberRemoved {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        /// Base64 postcard-encoded TreeKEM Commit for remaining members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    GroupDeleted {
        group_id: String,
        revision: u64,
        actor: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    PolicyUpdated {
        group_id: String,
        revision: u64,
        actor: String,
        policy: x0x::groups::GroupPolicy,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberRoleUpdated {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        role: x0x::groups::GroupRole,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberBanned {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        /// For MlsEncrypted groups, the new secret epoch committed into the
        /// signed state hash. Receivers use this to update the security binding
        /// before `finalize_applied_commit`, avoiding dependence on the later
        /// `SecureShareDelivered` arrival order.
        #[serde(default)]
        secret_epoch: Option<u64>,
        /// Base64 postcard-encoded TreeKEM Commit for remaining members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberUnbanned {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestCreated {
        group_id: String,
        request_id: String,
        requester_agent_id: String,
        message: Option<String>,
        ts: u64,
        /// Base64 of the requester's ML-KEM-768 public key, sent so the
        /// approver can later seal a `SecureShareDelivered` envelope to them.
        /// Required for MlsEncrypted groups; optional for others.
        #[serde(default)]
        requester_kem_public_key_b64: Option<String>,
        /// Base64 postcard-encoded TreeKEM KeyPackage for ADR-0012 Phase 3
        /// joins. Present for TreeKEM groups so an approver can produce the
        /// real Commit/Welcome pair; absent for legacy GSS groups and old
        /// requests.
        #[serde(default)]
        treekem_key_package_b64: Option<String>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestApproved {
        group_id: String,
        request_id: String,
        revision: u64,
        actor: String,
        requester_agent_id: String,
        /// Base64 postcard-encoded TreeKEM Commit for existing members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// Base64 postcard-encoded TreeKEM Welcome for the requester.
        /// Legacy fallback; new events carry `welcome_ref` instead.
        #[serde(default)]
        treekem_welcome_b64: Option<String>,
        /// Content-addressed pull reference for the requester's TreeKEM Welcome.
        #[serde(default)]
        welcome_ref: Option<WelcomeRef>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestRejected {
        group_id: String,
        request_id: String,
        actor: String,
        requester_agent_id: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestCancelled {
        group_id: String,
        request_id: String,
        requester_agent_id: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    GroupCardPublished {
        group_id: String,
        card: x0x::groups::GroupCard,
    },
    GroupMetadataUpdated {
        group_id: String,
        revision: u64,
        actor: String,
        name: Option<String>,
        description: Option<String>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    /// Joiner-authored membership announcement on `info.metadata_topic`.
    ///
    /// Emitted by `join_group_via_invite` immediately after the joiner's
    /// local `members_v2.insert`. The original inviter's
    /// `apply_named_group_metadata_event` verifies the joiner's ML-DSA-65
    /// signature, consumes the locally-issued one-time invite record,
    /// rejects any role other than `Member`, then publishes an
    /// authority-signed `MemberAdded` commit. Third-party receivers ignore
    /// this request and apply only the signed commit, keeping durable roster
    /// and `state_hash` mutations inside the D.3 commit chain. This is the
    /// gossip-layer fix for the `WritePolicyViolation { policy:
    /// MembersOnly }` cascade documented in
    /// `docs/design/groups-join-roster-propagation.md`.
    MemberJoined {
        group_id: String,
        /// Stable D.3 group_id, if the joiner already knows it. Receivers
        /// resolve the local group via `mls_group_id` first, then fall
        /// back to this.
        #[serde(default)]
        stable_group_id: Option<String>,
        /// Hex agent_id of the joiner (always equals `sender`).
        member_agent_id: String,
        /// Base64 ML-DSA-65 public key of the joiner. Receivers use this
        /// to verify `signature_b64` and to recompute the AgentId.
        member_public_key_b64: String,
        /// Joiner's requested role on entry. Invite-join v1 accepts only
        /// `Member`; higher roles require a future authority-signed flow.
        role: x0x::groups::GroupRole,
        /// Optional display name carried in the join request body.
        #[serde(default)]
        display_name: Option<String>,
        /// Hex agent_id of the inviter (matches `SignedInvite::inviter`).
        inviter_agent_id: String,
        /// Hex one-time invite secret carried by the join handshake. The
        /// original inviter checks this against `info.issued_invites` and
        /// consumes it before publishing the authoritative `MemberAdded`
        /// commit. Third-party receivers never apply this secret directly.
        invite_secret: String,
        /// Unix-millis timestamp at the joiner.
        ts_ms: u64,
        /// Base64 postcard-encoded TreeKEM KeyPackage for invite joins.
        #[serde(default)]
        treekem_key_package_b64: Option<String>,
        /// Base64 ML-DSA-65 signature over `canonical_member_joined_bytes`.
        signature_b64: String,
    },
    /// Phase D.2 (fixed): Cross-daemon delivery of the group's shared secret,
    /// sealed with ML-KEM-768 to the recipient's published public key.
    ///
    /// **Confidentiality**: a gossip observer who does NOT hold the recipient's
    /// ML-KEM-768 private key cannot recover `shared_secret`, by ML-KEM
    /// IND-CCA2 security. The adversarial E2E proof in
    /// `tests/e2e_named_groups.sh` section 2c verifies this behaviorally.
    ///
    /// Fields (all base64):
    /// - `kem_ciphertext_b64`: ML-KEM-768 encapsulated ciphertext (~1088 bytes).
    /// - `aead_nonce_b64`: 12-byte ChaCha20-Poly1305 nonce.
    /// - `aead_ciphertext_b64`: 48-byte AEAD-encrypted 32-byte secret.
    SecureShareDelivered {
        group_id: String,
        /// Hex agent_id of the intended recipient.
        recipient: String,
        /// New epoch of the shared secret.
        secret_epoch: u64,
        /// Base64 ML-KEM-768 encapsulated ciphertext.
        kem_ciphertext_b64: String,
        /// Base64 12-byte AEAD nonce.
        aead_nonce_b64: String,
        /// Base64 AEAD ciphertext of the 32-byte shared secret (tag included).
        aead_ciphertext_b64: String,
        /// Hex agent_id of the distributor (actor) — for authority checks.
        actor: String,
    },
}

/// Construct the AEAD additional-authenticated-data binding for a
/// `SecureShareDelivered` envelope. Must match exactly between sealer and
/// opener.
fn secure_share_aad(group_id: &str, recipient_hex: &str, secret_epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(b"x0x.group.share.v2|");
    aad.extend_from_slice(group_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(recipient_hex.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(&secret_epoch.to_le_bytes());
    aad
}

/// Build and publish a `SecureShareDelivered` envelope sealed to the named
/// recipient's ML-KEM-768 public key. Used by approval (new member) and
/// ban-rekey (remaining members). Returns true iff the envelope was sealed
/// and broadcast. Returns false if the recipient's KEM pubkey is unknown
/// locally — in that case the caller should log and proceed without the
/// envelope rather than crashing.
#[allow(clippy::too_many_arguments)]
async fn publish_secure_share(
    state: &AppState,
    metadata_topic: &str,
    group_id: &str,
    recipient_hex: &str,
    recipient_kem_public_b64: &str,
    actor_hex: &str,
    secret: &[u8; 32],
    secret_epoch: u64,
) -> bool {
    use base64::Engine as _;
    let recipient_kem_public = match BASE64.decode(recipient_kem_public_b64) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                recipient = %LogHexId::agent(&recipient_hex),
                "publish_secure_share: recipient KEM public key not valid base64: {e}"
            );
            return false;
        }
    };
    let aad = secure_share_aad(group_id, recipient_hex, secret_epoch);
    let (kem_ct, aead_nonce, aead_ct) =
        match x0x::groups::kem_envelope::seal_group_secret_to_recipient(
            &recipient_kem_public,
            &aad,
            secret,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(recipient = %LogHexId::agent(&recipient_hex), "KEM seal failed: {e}");
                return false;
            }
        };
    let event = NamedGroupMetadataEvent::SecureShareDelivered {
        group_id: group_id.to_string(),
        recipient: recipient_hex.to_string(),
        secret_epoch,
        kem_ciphertext_b64: BASE64.encode(&kem_ct),
        aead_nonce_b64: BASE64.encode(aead_nonce),
        aead_ciphertext_b64: BASE64.encode(&aead_ct),
        actor: actor_hex.to_string(),
    };
    publish_named_group_metadata_event(state, metadata_topic, &event).await;
    spawn_named_group_event_delivery(state, recipient_hex, &event);
    spawn_named_group_event_delivery_after(
        state,
        recipient_hex,
        &event,
        GROUP_BACKGROUND_PUBLISH_DELAY,
    );
    true
}

fn named_group_member_values(info: &x0x::groups::GroupInfo) -> Vec<serde_json::Value> {
    // Include active + banned (banned members still appear in the roster for
    // audit / admin view). Removed members are dropped.
    let mut members: Vec<&x0x::groups::GroupMember> = info
        .members_v2
        .values()
        .filter(|m| !m.is_removed())
        .collect();
    members.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    members
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "agent_id": m.agent_id,
                "role": m.role,
                "state": m.state,
                "display_name": m.display_name.clone().unwrap_or_else(|| info.display_name(&m.agent_id)),
                "joined_at": m.joined_at,
                "added_by": m.added_by,
            })
        })
        .collect()
}

#[allow(dead_code)]
fn named_group_member_values_all(info: &x0x::groups::GroupInfo) -> Vec<serde_json::Value> {
    let mut members: Vec<&x0x::groups::GroupMember> = info.members_v2.values().collect();
    members.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    members
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "agent_id": m.agent_id,
                "role": m.role,
                "state": m.state,
                "display_name": m.display_name.clone().unwrap_or_else(|| info.display_name(&m.agent_id)),
                "joined_at": m.joined_at,
                "added_by": m.added_by,
                "removed_by": m.removed_by,
                "updated_at": m.updated_at,
            })
        })
        .collect()
}

/// Well-known gossip topic that every daemon subscribes to for public group card
/// discovery. Publishing a `GroupCardPublished` event here makes the group
/// visible in any peer's `/groups/discover` without requiring manual card import.
const GLOBAL_GROUP_DISCOVERY_TOPIC: &str = "x0x.discovery.groups";

/// Publish a group's card to the global discovery topic when it is discoverable.
/// No-op if the group is Hidden and not withdrawn.
///
/// Phase D.3: the card carries the current committed `state_hash` and is
/// signed with the local agent's ML-DSA-65 key so peers can verify
/// authority and apply higher-revision supersession deterministically.
/// If `reseal=true`, this call also advances the state-commit chain
/// (bumps revision, updates `prev_state_hash`) before signing the card —
/// used by explicit `/state/seal` and `/state/withdraw` endpoints. When
/// `reseal=false`, the card reflects the current already-sealed state.
async fn publish_group_card_to_discovery(state: &AppState, group_id: &str) {
    publish_group_card_to_discovery_inner(state, group_id, false).await;
}

/// Like `publish_group_card_to_discovery` but advances the D.3 state
/// commit chain first. Returns the newly-sealed commit on success.
async fn publish_group_card_with_reseal(
    state: &AppState,
    group_id: &str,
) -> Option<x0x::groups::GroupStateCommit> {
    publish_group_card_to_discovery_inner(state, group_id, true).await
}

async fn publish_group_card_to_discovery_inner(
    state: &AppState,
    group_id: &str,
    reseal: bool,
) -> Option<x0x::groups::GroupStateCommit> {
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let (signed_card, commit) = {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_id)?;
        // Reseal bumps the commit chain; non-reseal republishes the
        // currently-sealed state (idempotent refresh).
        let commit = if reseal {
            if info.withdrawn {
                tracing::warn!(group_id, "refusing to reseal withdrawn group");
                return None;
            }
            match info.seal_commit(signing_kp, now_ms) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(group_id, "seal_commit failed: {e}");
                    return None;
                }
            }
        } else {
            None
        };
        let mut card = info.to_group_card()?;
        if let Err(e) = card.sign(signing_kp) {
            tracing::warn!(group_id, "card sign failed: {e}");
            return None;
        }
        (card, commit)
    };

    if reseal {
        save_named_groups(state).await;
    }

    // Phase C.2 privacy guard. Hidden and ListedToContacts MUST NEVER reach
    // any public discovery surface — neither the legacy bridge topic nor the
    // tag/name/id shard fan-out. ListedToContacts uses only the contact-scoped
    // direct-message path below.
    if !x0x::groups::may_publish_to_public_shards(signed_card.policy_summary.discoverability) {
        if signed_card.policy_summary.discoverability
            == x0x::groups::GroupDiscoverability::ListedToContacts
        {
            // Contact-scoped pairwise delivery: push the signed card via
            // direct-message to each Trusted/Known contact. No public
            // topic is touched.
            publish_listed_to_contacts_card(state, signed_card.clone()).await;
        } else {
            tracing::debug!(
                group_id,
                discoverability = ?signed_card.policy_summary.discoverability,
                "C.2: skipping fan-out (Hidden — stays local)"
            );
        }
        return commit;
    }

    // Bridge-topic publish (kept for backward compat with older peers that
    // haven't migrated to shard subscriptions yet). Only PublicDirectory cards
    // are allowed onto this public topic.
    let event = NamedGroupMetadataEvent::GroupCardPublished {
        group_id: group_id.to_string(),
        card: signed_card.clone(),
    };
    match serde_json::to_vec(&event) {
        Ok(bytes) => match state
            .agent
            .publish(GLOBAL_GROUP_DISCOVERY_TOPIC, bytes)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    group_id,
                    topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
                    reseal,
                    "D.3: published signed card to global discovery topic"
                );
            }
            Err(e) => {
                tracing::warn!(
                    topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
                    "failed to publish card: {e}"
                );
            }
        },
        Err(e) => tracing::debug!("failed to serialize discovery card: {e}"),
    }

    let shards =
        x0x::groups::shards_for_public(&signed_card.tags, &signed_card.name, &signed_card.group_id);
    {
        let mut cache = state.directory_cache.write().await;
        for (kind, shard, _) in &shards {
            let _ = cache.insert(*kind, *shard, signed_card.clone());
        }
    }
    for (kind, shard, key) in shards {
        let topic = x0x::groups::topic_for(kind, shard);
        let msg = x0x::groups::DirectoryMessage::Card {
            card: Box::new(signed_card.clone()),
        };
        match state.agent.publish(&topic, msg.encode()).await {
            Ok(()) => tracing::info!(
                group_id = %signed_card.group_id,
                topic = %topic,
                %key,
                "C.2: published signed card to shard"
            ),
            Err(e) => tracing::warn!(
                topic = %LogHexId::topic(&topic),
                "C.2: shard publish failed: {e}"
            ),
        }
    }

    commit
}

/// Subscribe to the global discovery topic and insert incoming cards into the cache.
/// Listener lives for the daemon's lifetime.
async fn spawn_global_discovery_listener(state: Arc<AppState>) -> Vec<tokio::task::JoinHandle<()>> {
    let mut sub = match state.agent.subscribe(GLOBAL_GROUP_DISCOVERY_TOPIC).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("failed to subscribe to discovery topic: {e}");
            return Vec::new();
        }
    };
    tracing::info!(
        topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
        "P0-1: global group discovery listener subscribed"
    );
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    vec![tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe_msg = sub.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    tracing::info!(
                        topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
                        "P0-1: received discovery gossip msg ({} bytes)",
                        msg.payload.len()
                    );
                    let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload) else { continue; };
                    if let NamedGroupMetadataEvent::GroupCardPublished { card, .. } = event {
                        // Phase D.3: verify authority signature on signed
                        // cards. Unsigned cards (pre-D.3 legacy peers) are
                        // accepted for backward compatibility; signed cards
                        // with a bad signature are dropped silently.
                        if !card.signature.is_empty() {
                            if let Err(e) = card.verify_signature() {
                                tracing::warn!(
                                    group_id = %card.group_id,
                                    "D.3: dropped card with invalid signature: {e}"
                                );
                                continue;
                            }
                        }

                        // Phase D.3: withdrawal supersession. A signed
                        // withdrawal card evicts any existing cache entry
                        // regardless of prior revision (it is, by
                        // construction, a higher revision than anything
                        // local since apply_commit enforced that at the
                        // authority).
                        if card.withdrawn {
                            let mut cache = state.group_card_cache.write().await;
                            prune_expired_group_cards(&mut cache, now_millis_u64());
                            if remove_group_card_if_not_stale(&mut cache, &card) {
                                tracing::info!(
                                    group_id = %card.group_id,
                                    revision = card.revision,
                                    "D.3: withdrawal card superseded prior listing"
                                );
                            }
                            continue;
                        }

                        let local_group_withdrawn = {
                            let groups = state.named_groups.read().await;
                            has_withdrawn_group_record(&groups, &card.group_id)
                        };
                        if local_group_withdrawn {
                            tracing::debug!(
                                group_id = %card.group_id,
                                "D.3: dropped stale non-withdrawn card for withdrawn group"
                            );
                            continue;
                        }

                        // Only accept cards that are allowed on a public
                        // discovery surface. Hidden and ListedToContacts must
                        // never be cached from the global discovery topic.
                        if !x0x::groups::may_publish_to_public_shards(
                            card.policy_summary.discoverability,
                        ) {
                            continue;
                        }

                        // Phase D.3: higher revision supersedes lower
                        // immediately (independent of TTL). On ties, higher
                        // issued_at wins.
                        let mut cache = state.group_card_cache.write().await;
                        prune_expired_group_cards(&mut cache, now_millis_u64());
                        let should_insert = cache_group_card_if_newer(
                            &mut cache,
                            card.group_id.clone(),
                            card.clone(),
                        );
                        if should_insert {
                            tracing::info!(
                                group_id = %card.group_id,
                                name = %card.name,
                                revision = card.revision,
                                "D.3: caching discovered group card (signed={})",
                                !card.signature.is_empty()
                            );
                            enforce_group_card_cache_cap(&mut cache);
                        } else {
                            tracing::debug!(
                                group_id = %card.group_id,
                                revision = card.revision,
                                "D.3: dropped stale card (already have higher rev)"
                            );
                        }
                    }
                }
            }
        }
    })]
}

// ────────────────────────── Phase C.2: shard subscriptions ──────────────

/// Staggered-resubscribe jitter window, in milliseconds. Startup resubscribe
/// picks a random delay in `[0, JITTER_MS)` per shard to avoid AE storms.
const DIRECTORY_RESUBSCRIBE_JITTER_MS: u64 = 30_000;

/// Interval between proactive digest emissions per subscribed shard, in
/// seconds. Peers use these digests for AE reconciliation.
const DIRECTORY_DIGEST_INTERVAL_SECS: u64 = 60;

/// Load persisted directory subscriptions from disk (best-effort).
async fn load_directory_subscriptions(state: &AppState) {
    let path = &state.directory_subscriptions_path;
    match tokio::fs::read(path).await {
        Ok(bytes) => match serde_json::from_slice::<x0x::groups::SubscriptionSet>(&bytes) {
            Ok(set) => {
                let n = set.len();
                *state.directory_subscriptions.write().await = set;
                tracing::info!(
                    "C.2: loaded {n} persisted directory subscriptions from {}",
                    path.display()
                );
            }
            Err(e) => tracing::warn!(
                "C.2: failed to parse directory subscriptions file {}: {e}",
                path.display()
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                "C.2: no persisted directory subscriptions at {}",
                path.display()
            );
        }
        Err(e) => tracing::warn!(
            "C.2: failed to read directory subscriptions file {}: {e}",
            path.display()
        ),
    }
}

/// Save the current subscription set to disk.
async fn save_directory_subscriptions(state: &AppState) {
    let set = state.directory_subscriptions.read().await.clone();
    let path = state.directory_subscriptions_path.clone();
    match serde_json::to_vec_pretty(&set) {
        Ok(bytes) => {
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            if let Err(e) = tokio::fs::write(&path, &bytes).await {
                tracing::warn!(
                    "C.2: failed to persist directory subscriptions to {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => tracing::warn!("C.2: failed to serialise directory subscriptions: {e}"),
    }
}

/// Subscribe to a single shard topic and spawn a listener. Idempotent:
/// re-subscribing to an already-active shard is a no-op. Does not persist
/// on its own — callers must call `save_directory_subscriptions` after
/// mutating the subscription set.
async fn subscribe_shard(state: Arc<AppState>, kind: x0x::groups::ShardKind, shard: u32) {
    {
        let tasks = state.directory_tasks.read().await;
        if tasks.contains_key(&(kind, shard)) {
            return;
        }
    }
    let topic = x0x::groups::topic_for(kind, shard);
    let mut sub = match state.agent.subscribe(&topic).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(topic = %LogHexId::topic(&topic), "C.2: failed to subscribe to shard: {e}");
            return;
        }
    };
    let state_for_listener = Arc::clone(&state);
    let topic_for_log = topic.clone();
    let digest_interval_secs = state.directory_digest_interval_secs.max(1);
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let handle = tokio::spawn(async move {
        // Emit an initial digest on startup so peers can reciprocate.
        emit_shard_digest(&state_for_listener, kind, shard).await;
        let mut digest_ticker =
            tokio::time::interval(std::time::Duration::from_secs(digest_interval_secs));
        digest_ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = digest_ticker.tick() => {
                    emit_shard_digest(&state_for_listener, kind, shard).await;
                }
                maybe_msg = sub.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    handle_directory_message(&state_for_listener, kind, shard, &msg.payload).await;
                }
            }
        }
        tracing::info!(topic = %topic_for_log, "C.2: shard listener shut down");
    });
    state
        .directory_tasks
        .write()
        .await
        .insert((kind, shard), handle);
    tracing::info!(topic = %topic, "C.2: subscribed to directory shard");
}

/// Unsubscribe from a shard (abort the listener task).
async fn unsubscribe_shard(state: &AppState, kind: x0x::groups::ShardKind, shard: u32) {
    if let Some(handle) = state.directory_tasks.write().await.remove(&(kind, shard)) {
        handle.abort();
        tracing::info!(
            kind = ?kind,
            shard,
            "C.2: unsubscribed from directory shard"
        );
    }
}

/// Publish a digest of our known entries in a shard (AE summary).
async fn emit_shard_digest(state: &AppState, kind: x0x::groups::ShardKind, shard: u32) {
    let entries = state.directory_cache.read().await.shard_digest(kind, shard);
    if entries.is_empty() {
        return; // nothing to advertise yet
    }
    let msg = x0x::groups::DirectoryMessage::Digest {
        shard,
        kind,
        entries,
    };
    let topic = x0x::groups::topic_for(kind, shard);
    if let Err(e) = state.agent.publish(&topic, msg.encode()).await {
        tracing::debug!(topic = %topic, "C.2: digest publish failed: {e}");
    }
}

/// Re-publish our own signed cards for groups listed in a Pull request.
async fn respond_to_pull(
    state: &AppState,
    kind: x0x::groups::ShardKind,
    shard: u32,
    group_ids: &[String],
) {
    let signing_kp = state.agent.identity().agent_keypair();
    let topic = x0x::groups::topic_for(kind, shard);
    let groups = state.named_groups.read().await;
    for gid in group_ids {
        // We only re-publish cards for groups we *own* / manage locally,
        // not arbitrary cards from our cache (relays may re-publish cached
        // blobs but cannot re-sign them). Pull requests use stable `group_id`,
        // so resolve by either the local routing key or the D.3 stable id.
        let owned_info = groups.get(gid.as_str()).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == gid.as_str())
        });
        if let Some(info) = owned_info {
            if !x0x::groups::may_publish_to_public_shards(info.policy.discoverability) {
                continue;
            }
            if let Ok(Some(card)) = info.to_signed_group_card(signing_kp) {
                let msg = x0x::groups::DirectoryMessage::Card {
                    card: Box::new(card),
                };
                let _ = state.agent.publish(&topic, msg.encode()).await;
                continue;
            }
        }
        // Fall back to re-broadcasting a cached card verbatim if we have one
        // (relay-forward semantics).
        if let Some(cached) = state.directory_cache.read().await.get(gid) {
            let msg = x0x::groups::DirectoryMessage::Card {
                card: Box::new(cached.clone()),
            };
            let _ = state.agent.publish(&topic, msg.encode()).await;
        }
    }
}

/// Handle one message arriving on a shard topic: Card / Digest / Pull.
async fn handle_directory_message(
    state: &AppState,
    kind: x0x::groups::ShardKind,
    shard: u32,
    payload: &[u8],
) {
    let msg = match x0x::groups::DirectoryMessage::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(shard, ?kind, "C.2: dropped malformed directory msg: {e}");
            return;
        }
    };
    match msg {
        x0x::groups::DirectoryMessage::Card { card } => {
            // Require a signature on shard-delivered cards. Unsigned cards on
            // a directory shard are treated as malformed (directory plane is
            // authority-signed by construction) and dropped.
            if card.signature.is_empty() {
                tracing::debug!(
                    group_id = %card.group_id,
                    "C.2: dropped unsigned card on shard topic"
                );
                return;
            }
            if let Err(e) = card.verify_signature() {
                tracing::warn!(
                    group_id = %card.group_id,
                    "C.2: dropped card with invalid signature: {e}"
                );
                return;
            }
            // Defensive privacy guard: a Hidden or ListedToContacts card must
            // never appear on a public shard topic. Drop if seen.
            if !x0x::groups::may_publish_to_public_shards(card.policy_summary.discoverability) {
                tracing::warn!(
                    group_id = %card.group_id,
                    discoverability = ?card.policy_summary.discoverability,
                    "C.2: dropped privacy-restricted card that leaked to public shard"
                );
                return;
            }
            let local_group_withdrawn = {
                let groups = state.named_groups.read().await;
                has_withdrawn_group_record(&groups, &card.group_id)
            };
            if !card.withdrawn && local_group_withdrawn {
                tracing::debug!(
                    group_id = %card.group_id,
                    "C.2: dropped stale non-withdrawn card for withdrawn group"
                );
                return;
            }
            let accepted = state
                .directory_cache
                .write()
                .await
                .insert(kind, shard, (*card).clone());
            if accepted {
                // Also update the legacy bridge cache so existing
                // /groups/discover responses continue to reflect shard
                // discoveries until D.4 deprecates that path.
                if card.withdrawn {
                    let mut cache = state.group_card_cache.write().await;
                    prune_expired_group_cards(&mut cache, now_millis_u64());
                    remove_group_card_if_not_stale(&mut cache, &card);
                } else if card.policy_summary.discoverability
                    != x0x::groups::GroupDiscoverability::Hidden
                {
                    let mut cache = state.group_card_cache.write().await;
                    prune_expired_group_cards(&mut cache, now_millis_u64());
                    if cache_group_card_if_newer(&mut cache, card.group_id.clone(), (*card).clone())
                    {
                        enforce_group_card_cache_cap(&mut cache);
                    }
                }
                tracing::info!(
                    group_id = %card.group_id,
                    kind = ?kind,
                    shard,
                    revision = card.revision,
                    "C.2: cached shard-delivered signed card"
                );
            }
        }
        x0x::groups::DirectoryMessage::Digest {
            shard: peer_shard,
            kind: peer_kind,
            entries,
        } => {
            if peer_shard != shard || peer_kind != kind {
                return;
            }
            let pulls = state
                .directory_cache
                .read()
                .await
                .pull_targets(kind, shard, &entries);
            if !pulls.is_empty() {
                let req = x0x::groups::DirectoryMessage::Pull {
                    shard,
                    kind,
                    group_ids: pulls,
                };
                let topic = x0x::groups::topic_for(kind, shard);
                let _ = state.agent.publish(&topic, req.encode()).await;
            }
        }
        x0x::groups::DirectoryMessage::Pull {
            shard: peer_shard,
            kind: peer_kind,
            group_ids,
        } => {
            if peer_shard != shard || peer_kind != kind {
                return;
            }
            respond_to_pull(state, kind, shard, &group_ids).await;
        }
    }
}

/// Spawn all persisted shard subscriptions at startup, with jitter so the
/// mesh doesn't storm on restart.
async fn spawn_directory_resubscribe(state: Arc<AppState>) -> Vec<tokio::task::JoinHandle<()>> {
    load_directory_subscriptions(&state).await;
    let subs = state.directory_subscriptions.read().await.clone();
    if subs.is_empty() {
        return Vec::new();
    }
    use rand::Rng;
    let jitter_ms = state.directory_resubscribe_jitter_ms.max(1);
    let mut handles = Vec::new();
    for rec in subs.subscriptions {
        let delay_ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(0..jitter_ms)
        };
        let state_for_spawn = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            subscribe_shard(state_for_spawn, rec.kind, rec.shard).await;
        }));
    }
    handles
}

// ────────────────────── Phase C.2: ListedToContacts pairwise sync ───────

/// Wire-framing prefix for a ListedToContacts card delivered over the
/// direct-message channel. 16 bytes so receivers can do a single
/// constant-length prefix match. Payload after the prefix is the JSON
/// encoding of a signed [`x0x::groups::GroupCard`].
const LTC_CARD_FRAME_PREFIX: &[u8; 16] = b"X0X-LTC-CARD-V1\n";

/// Push a signed `ListedToContacts` `GroupCard` to each Trusted/Known
/// contact via direct-message. Skips contacts we have no record of, any
/// Blocked contacts, and the sender itself.
///
/// This is the privacy-correct distribution path for
/// `ListedToContacts` groups: no public topic is touched. Delivery is
/// O(N contacts), acceptable for the cardinality of this feature.
async fn publish_listed_to_contacts_card(state: &AppState, card: x0x::groups::GroupCard) {
    use x0x::contacts::TrustLevel;
    let contacts = state.contacts.read().await;
    let my_hex = hex::encode(state.agent.agent_id().as_bytes());
    let json = match serde_json::to_vec(&card) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(group_id = %card.group_id, "C.2/LTC: card serialize failed: {e}");
            return;
        }
    };
    let mut payload = Vec::with_capacity(LTC_CARD_FRAME_PREFIX.len() + json.len());
    payload.extend_from_slice(LTC_CARD_FRAME_PREFIX);
    payload.extend_from_slice(&json);

    // Enumerate Trusted + Known contacts. Blocked and Unknown are skipped.
    for contact in contacts.list() {
        if contact.trust_level == TrustLevel::Blocked || contact.trust_level == TrustLevel::Unknown
        {
            continue;
        }
        let hex_id = hex::encode(contact.agent_id.as_bytes());
        if hex_id == my_hex {
            continue;
        }
        match state
            .agent
            .send_direct_with_config(
                &contact.agent_id,
                payload.clone(),
                direct_message_send_config(),
            )
            .await
        {
            Ok(receipt) => tracing::info!(
                group_id = %card.group_id,
                recipient = %hex_id,
                trust = ?contact.trust_level,
                path = ?receipt.path,
                retries = receipt.retries_used,
                "C.2/LTC: delivered signed card to contact"
            ),
            Err(e) => tracing::debug!(
                group_id = %card.group_id,
                recipient = %hex_id,
                "C.2/LTC: contact delivery failed: {e}"
            ),
        }
    }
}

/// Background listener that consumes inbound direct messages and, when it
/// sees an LTC-framed envelope, verifies the card signature and caches it
/// in `group_card_cache` (never on public shards).
async fn spawn_listed_to_contacts_listener(
    state: Arc<AppState>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut direct_rx = state.agent.subscribe_direct();
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    vec![tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe = direct_rx.recv() => {
                    let Some(msg) = maybe else { break; };
                    if msg.payload.len() < LTC_CARD_FRAME_PREFIX.len() {
                        continue;
                    }
                    if &msg.payload[..LTC_CARD_FRAME_PREFIX.len()] != LTC_CARD_FRAME_PREFIX {
                        continue;
                    }
                    let json = &msg.payload[LTC_CARD_FRAME_PREFIX.len()..];
                    let card: x0x::groups::GroupCard = match serde_json::from_slice(json) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!("C.2/LTC: malformed card JSON: {e}");
                            continue;
                        }
                    };
                    // Require a signature; unsigned LTC cards are dropped.
                    if card.signature.is_empty() {
                        continue;
                    }
                    if let Err(e) = card.verify_signature() {
                        tracing::warn!(
                            group_id = %card.group_id,
                            "C.2/LTC: dropped card with invalid signature: {e}"
                        );
                        continue;
                    }
                    // Defensive privacy guard: even via LTC delivery, a
                    // card whose discoverability is not ListedToContacts
                    // should not be cached as if it were. Accept only
                    // ListedToContacts cards on this path.
                    if card.policy_summary.discoverability
                        != x0x::groups::GroupDiscoverability::ListedToContacts
                    {
                        tracing::warn!(
                            group_id = %card.group_id,
                            "C.2/LTC: dropped non-LTC card on contact channel"
                        );
                        continue;
                    }
                    if card.withdrawn {
                        let mut cache = state.group_card_cache.write().await;
                        prune_expired_group_cards(&mut cache, now_millis_u64());
                        if remove_group_card_if_not_stale(&mut cache, &card) {
                            tracing::info!(
                                group_id = %card.group_id,
                                "C.2/LTC: evicted withdrawn card from contact cache"
                            );
                        }
                        continue;
                    }
                    let local_group_withdrawn = {
                        let groups = state.named_groups.read().await;
                        has_withdrawn_group_record(&groups, &card.group_id)
                    };
                    if local_group_withdrawn {
                        tracing::debug!(
                            group_id = %card.group_id,
                            "C.2/LTC: dropped stale non-withdrawn card for withdrawn group"
                        );
                        continue;
                    }
                    let mut cache = state.group_card_cache.write().await;
                    prune_expired_group_cards(&mut cache, now_millis_u64());
                    let insert =
                        cache_group_card_if_newer(&mut cache, card.group_id.clone(), card.clone());
                    if insert {
                        tracing::info!(
                            group_id = %card.group_id,
                            sender = %hex::encode(msg.sender.as_bytes()),
                            revision = card.revision,
                            "C.2/LTC: cached ListedToContacts card from contact"
                        );
                        enforce_group_card_cache_cap(&mut cache);
                    }
                }
            }
        }
    })]
}

/// Domain-separation tag for the `MemberJoined` metadata event signature.
///
/// Bumping this string is a protocol break — receivers verify against the
/// exact byte sequence below.
const MEMBER_JOINED_DOMAIN: &[u8] = b"x0x.named_group.member_joined.v2";

/// Build the canonical bytes signed by the joiner for a `MemberJoined`
/// metadata event.
///
/// Layout (all length-prefixed string fields use a u32 big-endian length
/// followed by the raw bytes; primitives use big-endian):
///
/// ```text
/// MEMBER_JOINED_DOMAIN
/// u32 len + group_id
/// u32 len + stable_group_id (empty string if None)
/// u32 len + member_agent_id
/// u32 len + member_public_key_b64
/// u8 role.as_u8()
/// u32 len + display_name (empty string if None)
/// u32 len + inviter_agent_id
/// u32 len + invite_secret
/// u64 BE  ts_ms
/// u32 len + treekem_key_package_b64 (empty string if None)
/// ```
#[allow(clippy::too_many_arguments)]
fn canonical_member_joined_bytes(
    group_id: &str,
    stable_group_id: Option<&str>,
    member_agent_id: &str,
    member_public_key_b64: &str,
    role: x0x::groups::GroupRole,
    display_name: Option<&str>,
    inviter_agent_id: &str,
    invite_secret: &str,
    ts_ms: u64,
    treekem_key_package_b64: Option<&str>,
) -> Vec<u8> {
    fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    let mut buf = Vec::with_capacity(MEMBER_JOINED_DOMAIN.len() + 256);
    buf.extend_from_slice(MEMBER_JOINED_DOMAIN);
    push_lp(&mut buf, group_id.as_bytes());
    push_lp(&mut buf, stable_group_id.unwrap_or("").as_bytes());
    push_lp(&mut buf, member_agent_id.as_bytes());
    push_lp(&mut buf, member_public_key_b64.as_bytes());
    buf.push(role.as_u8());
    push_lp(&mut buf, display_name.unwrap_or("").as_bytes());
    push_lp(&mut buf, inviter_agent_id.as_bytes());
    push_lp(&mut buf, invite_secret.as_bytes());
    buf.extend_from_slice(&ts_ms.to_be_bytes());
    push_lp(&mut buf, treekem_key_package_b64.unwrap_or("").as_bytes());
    buf
}

async fn publish_named_group_metadata_event(
    state: &AppState,
    metadata_topic: &str,
    event: &NamedGroupMetadataEvent,
) {
    #[cfg(test)]
    if let Ok(mut attempts) = NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST.lock() {
        attempts.push((
            metadata_topic.to_string(),
            named_group_metadata_event_group_id(event).to_string(),
        ));
    }

    match serde_json::to_vec(event) {
        Ok(bytes) => {
            match tokio::time::timeout(
                NAMED_GROUP_METADATA_PUBLISH_TIMEOUT,
                state.agent.publish(metadata_topic, bytes),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(topic = %LogHexId::topic(&metadata_topic), "failed to publish named-group metadata event: {e}");
                }
                Err(_) => {
                    tracing::warn!(
                        topic = %LogHexId::topic(&metadata_topic),
                        timeout_ms = NAMED_GROUP_METADATA_PUBLISH_TIMEOUT.as_millis() as u64,
                        "timed out publishing named-group metadata event"
                    );
                }
            }
        }
        Err(e) => tracing::warn!("failed to serialize named-group metadata event: {e}"),
    }
}

/// Schedule best-effort delivery of a named-group metadata event directly to a
/// single recipient over the authenticated direct-message channel, in addition
/// to the metadata-topic gossip publish.
///
/// Review decisions (approve / reject) target a requester who has only just
/// imported the group card and is not yet grafted into the authority's
/// PlumTree eager-push mesh for the metadata topic. Gossip cannot backfill a
/// message published before the receiver is in the eager set, so the
/// authority-authored, chain-linked commit can fail to reach the one peer that
/// must converge. The direct path closes that gap. The receiver applies the
/// event through the same [`apply_named_group_metadata_event`] path used for
/// gossip, which re-validates the signed commit, enforces the same
/// authorization, and is idempotent — so this is an additive delivery channel
/// that neither weakens authorization nor risks a double apply.
///
/// Direct delivery is intentionally spawned in the background: failures are
/// logged by the task and must not block metadata application, follow-up
/// side-effects, or HTTP responses.
fn spawn_named_group_event_delivery(
    state: &AppState,
    recipient_hex: &str,
    event: &NamedGroupMetadataEvent,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                requester = %LogHexId::agent(&recipient_hex),
                "cannot direct-deliver named-group event: invalid requester id: {e}"
            );
            return;
        }
    };
    let payload = match serde_json::to_vec(event) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("failed to serialize named-group event for direct delivery: {e}");
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let requester = recipient_hex.to_string();
    tokio::spawn(async move {
        if let Err(e) = agent
            .send_direct_with_config(&recipient, payload, named_group_direct_delivery_config())
            .await
        {
            tracing::warn!(
                requester = %LogHexId::agent(&requester),
                "failed to direct-deliver named-group review event: {e}"
            );
        }
    });
}

fn spawn_named_group_event_delivery_after(
    state: &AppState,
    recipient_hex: &str,
    event: &NamedGroupMetadataEvent,
    delay: Duration,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                requester = %LogHexId::agent(&recipient_hex),
                "cannot delayed-direct-deliver named-group event: invalid requester id: {e}"
            );
            return;
        }
    };
    let payload = match serde_json::to_vec(event) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                "failed to serialize named-group event for delayed direct delivery: {e}"
            );
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let requester = recipient_hex.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        if let Err(e) = agent
            .send_direct_with_config(&recipient, payload, named_group_direct_delivery_config())
            .await
        {
            tracing::warn!(
                requester = %LogHexId::agent(&requester),
                "failed to delayed-direct-deliver named-group event: {e}"
            );
        }
    });
}

fn spawn_named_group_event_delivery_to_active_members(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    extra_recipients: &[String],
) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut recipients = HashSet::new();
    for member in info.active_members() {
        if !member.agent_id.eq_ignore_ascii_case(&local_agent_hex) {
            recipients.insert(member.agent_id.clone());
        }
    }
    for recipient in extra_recipients {
        if !recipient.eq_ignore_ascii_case(&local_agent_hex) {
            recipients.insert(recipient.clone());
        }
    }
    for recipient in recipients {
        spawn_named_group_event_delivery(state, &recipient, event);
        spawn_named_group_event_delivery_after(
            state,
            &recipient,
            event,
            GROUP_BACKGROUND_PUBLISH_DELAY,
        );
    }
}

async fn stop_named_group_metadata_listener(state: &AppState, group_id: &str) {
    let handle = state.group_metadata_tasks.write().await.remove(group_id);
    if let Some(handle) = handle {
        handle.abort();
    }
}

fn apply_stateful_event_to_group<F>(
    current: &x0x::groups::GroupInfo,
    commit: &x0x::groups::GroupStateCommit,
    action_kind: x0x::groups::ActionKind,
    mutate: F,
) -> Result<x0x::groups::GroupInfo, x0x::groups::ApplyError>
where
    F: FnOnce(&mut x0x::groups::GroupInfo),
{
    let ctx = x0x::groups::ApplyContext {
        current_state_hash: &current.state_hash,
        current_revision: current.state_revision,
        current_withdrawn: current.withdrawn,
        members_v2: &current.members_v2,
        group_id: current.stable_group_id(),
    };
    x0x::groups::state_commit::validate_apply(&ctx, commit, action_kind)?;
    let mut next = current.clone();
    mutate(&mut next);
    next.finalize_applied_commit(commit)?;
    Ok(next)
}

fn apply_terminal_stateful_event_to_group<F>(
    current: &x0x::groups::GroupInfo,
    commit: &x0x::groups::GroupStateCommit,
    action_kind: x0x::groups::ActionKind,
    mutate: F,
) -> Result<x0x::groups::GroupInfo, x0x::groups::ApplyError>
where
    F: FnOnce(&mut x0x::groups::GroupInfo),
{
    let ctx = x0x::groups::ApplyContext {
        current_state_hash: &current.state_hash,
        current_revision: current.state_revision,
        current_withdrawn: current.withdrawn,
        members_v2: &current.members_v2,
        group_id: current.stable_group_id(),
    };
    x0x::groups::state_commit::validate_apply_terminal(&ctx, commit, action_kind)?;
    let mut next = current.clone();
    mutate(&mut next);
    next.finalize_applied_terminal_commit(commit)?;
    Ok(next)
}

async fn refresh_group_card_cache_from_info(
    state: &AppState,
    key: &str,
    info: &x0x::groups::GroupInfo,
) {
    let mut cache = state.group_card_cache.write().await;
    let now_ms = now_millis_u64();
    prune_expired_group_cards(&mut cache, now_ms);
    let stable_key = info.stable_group_id().to_string();
    match info.to_signed_group_card(state.agent.identity().agent_keypair()) {
        Ok(Some(card)) => {
            cache_group_card_if_newer(&mut cache, key.to_string(), card.clone());
            cache_group_card_if_newer(&mut cache, stable_key, card);
            enforce_group_card_cache_cap(&mut cache);
        }
        Ok(None) => {
            cache.remove(key);
            cache.remove(&stable_key);
        }
        Err(e) => {
            tracing::warn!(group_key = %key, "failed to sign group card for cache refresh: {e}");
            cache.remove(key);
            cache.remove(&stable_key);
        }
    }
}

fn store_named_group_info_locked(
    groups: &mut HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    info: x0x::groups::GroupInfo,
) -> bool {
    if !info.withdrawn
        && has_withdrawn_same_stable_group_record(groups, group_id, Some(info.stable_group_id()))
    {
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            stable_group_id = %LogHexId::group(info.stable_group_id()),
            "refusing to overwrite withdrawn named-group terminal record"
        );
        return false;
    }
    let Some(slot) = groups.get_mut(group_id) else {
        return false;
    };
    *slot = info;
    true
}

async fn store_named_group_info(
    state: &AppState,
    group_id: &str,
    info: x0x::groups::GroupInfo,
) -> bool {
    let mut groups = state.named_groups.write().await;
    store_named_group_info_locked(&mut groups, group_id, info)
}

fn restore_local_treekem_group_from_snapshot(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    snapshot: &[u8],
) -> anyhow::Result<x0x::mls::TreeKemMlsGroup> {
    let group_id_bytes = hex::decode(&info.mls_group_id)
        .map_err(|e| anyhow::anyhow!("invalid TreeKEM group id for rollback: {e}"))?;
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    x0x::mls::TreeKemMlsGroup::restore(snapshot, state.agent.agent_id(), &seed)
        .map_err(|e| anyhow::anyhow!("restore TreeKEM rollback snapshot: {e}"))
}

fn rollback_treekem_group_after_failed_install(
    state: &AppState,
    group_id: &str,
    info: &x0x::groups::GroupInfo,
    snapshot: &[u8],
    group: &mut x0x::mls::TreeKemMlsGroup,
    reason: &str,
) {
    match restore_local_treekem_group_from_snapshot(state, info, snapshot) {
        Ok(restored) => {
            *group = restored;
        }
        Err(e) => {
            tracing::error!(
                group_id = %LogHexId::group(group_id),
                reason,
                "failed to rollback TreeKEM group after rejected install: {e}"
            );
        }
    }
}

#[cfg(test)]
fn notify_treekem_final_install_before_map_write_for_test(group_id: &str) {
    let notify = TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY
        .lock()
        .ok()
        .and_then(|guard| {
            guard
                .as_ref()
                .filter(|(target_group_id, _)| target_group_id == group_id)
                .map(|(_, notify)| Arc::clone(notify))
        });
    if let Some(notify) = notify {
        notify.notify_waiters();
    }
}

async fn install_joined_treekem_group_after_crypto_recheck(
    state: &AppState,
    group_id: &str,
    info: x0x::groups::GroupInfo,
    group: x0x::mls::TreeKemMlsGroup,
    reason: &str,
) -> anyhow::Result<()> {
    let stable_group_id = info.stable_group_id().to_string();
    ensure_named_group_key_material_install_allowed(
        state,
        group_id,
        Some(&stable_group_id),
        reason,
    )
    .await?;
    persist_treekem_and_named_groups_atomic_with_info(state, group_id, info, &group).await?;
    ensure_named_group_key_material_install_allowed(
        state,
        group_id,
        Some(&stable_group_id),
        reason,
    )
    .await?;
    #[cfg(test)]
    notify_treekem_final_install_before_map_write_for_test(group_id);

    let mut treekem_groups = state.treekem_groups.write().await;
    let groups = state.named_groups.read().await;
    if has_withdrawn_same_stable_group_record(&groups, group_id, Some(&stable_group_id)) {
        drop(groups);
        drop(treekem_groups);
        if !repair_withdrawn_named_groups_json_and_wipe_key_material(
            state,
            group_id,
            Some(&stable_group_id),
            reason,
        )
        .await?
        {
            remove_treekem_persistence_for_group_id(state, group_id, reason).await;
        }
        anyhow::bail!("refusing to install key material for withdrawn group");
    }
    // Keep the named-groups read guard through the final insert. That removes
    // the post-check/pre-insert window: a withdrawal that already won is
    // observed above; a later withdrawal cannot acquire the named-groups write
    // lock until after this in-memory insert, then its teardown path removes the
    // key material.
    treekem_groups.insert(
        group_id.to_string(),
        Arc::new(tokio::sync::Mutex::new(group)),
    );
    Ok(())
}

async fn process_treekem_commit_after_crypto_recheck(
    state: &AppState,
    group_id: &str,
    info: &x0x::groups::GroupInfo,
    group: Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>,
    commit_bytes: &[u8],
    expected_epoch: u64,
    reason: &str,
) -> anyhow::Result<()> {
    let mut guard = group.lock().await;
    let rollback_snapshot = guard
        .to_snapshot_bytes()
        .map_err(|e| anyhow::anyhow!("snapshot TreeKEM group before commit: {e}"))?;
    if let Err(e) = guard.process_commit(commit_bytes) {
        rollback_treekem_group_after_failed_install(
            state,
            group_id,
            info,
            &rollback_snapshot,
            &mut guard,
            reason,
        );
        return Err(anyhow::anyhow!("process TreeKEM commit: {e}"));
    }
    if guard.epoch() != expected_epoch {
        let actual_epoch = guard.epoch();
        rollback_treekem_group_after_failed_install(
            state,
            group_id,
            info,
            &rollback_snapshot,
            &mut guard,
            reason,
        );
        anyhow::bail!(
            "TreeKEM commit advanced to unexpected epoch {actual_epoch}, expected {expected_epoch}"
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(state, group_id, info.clone(), &guard)
            .await
    {
        rollback_treekem_group_after_failed_install(
            state,
            group_id,
            info,
            &rollback_snapshot,
            &mut guard,
            reason,
        );
        return Err(e);
    }
    Ok(())
}

async fn maybe_publish_group_card_after_state_change(state: &AppState, group_id: &str) {
    let info = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).cloned()
    };
    if let Some(info) = info {
        refresh_group_card_cache_from_info(state, group_id, &info).await;
        let discoverable = info.withdrawn
            || info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden;
        if discoverable {
            publish_group_card_to_discovery(state, group_id).await;
        } else {
            let mut cache = state.group_card_cache.write().await;
            prune_expired_group_cards(&mut cache, now_millis_u64());
            cache.remove(group_id);
            cache.remove(info.stable_group_id());
        }
    } else {
        let mut cache = state.group_card_cache.write().await;
        prune_expired_group_cards(&mut cache, now_millis_u64());
        cache.remove(group_id);
    }
}

struct TreeKemMembershipFrontier<'a> {
    group_id: &'a str,
    revision: u64,
    epoch: Option<u64>,
    commit: &'a x0x::groups::GroupStateCommit,
    actor: &'a str,
    target: &'a str,
}

fn treekem_membership_event_frontier(
    event: &NamedGroupMetadataEvent,
) -> Option<TreeKemMembershipFrontier<'_>> {
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            group_id,
            revision,
            actor,
            agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        }
        | NamedGroupMetadataEvent::MemberRemoved {
            group_id,
            revision,
            actor,
            agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        }
        | NamedGroupMetadataEvent::MemberBanned {
            group_id,
            revision,
            actor,
            agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        } => Some(TreeKemMembershipFrontier {
            group_id,
            revision: *revision,
            epoch: *treekem_epoch,
            commit,
            actor,
            target: agent_id,
        }),
        NamedGroupMetadataEvent::JoinRequestApproved {
            group_id,
            revision,
            actor,
            requester_agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        } => Some(TreeKemMembershipFrontier {
            group_id,
            revision: *revision,
            epoch: *treekem_epoch,
            commit,
            actor,
            target: requester_agent_id,
        }),
        _ => None,
    }
}

fn treekem_membership_event_key(event: &NamedGroupMetadataEvent) -> Option<String> {
    let frontier = treekem_membership_event_frontier(event)?;
    let kind = match event {
        NamedGroupMetadataEvent::MemberAdded { .. } => "add",
        NamedGroupMetadataEvent::MemberRemoved { .. } => "remove",
        NamedGroupMetadataEvent::MemberBanned { .. } => "ban",
        NamedGroupMetadataEvent::JoinRequestApproved { .. } => "approve",
        _ => return None,
    };
    Some(format!(
        "{}:{kind}:{}:{}:{}:{}",
        frontier.group_id,
        frontier.revision,
        frontier.epoch.unwrap_or_default(),
        frontier.actor,
        frontier.target
    ))
}

fn treekem_membership_event_sort_key(event: &NamedGroupMetadataEvent) -> (u64, u64) {
    treekem_membership_event_frontier(event)
        .map(|frontier| (frontier.revision, frontier.epoch.unwrap_or_default()))
        .unwrap_or_default()
}

fn treekem_event_is_local_welcome(event: &NamedGroupMetadataEvent, local_agent_hex: &str) -> bool {
    match event {
        NamedGroupMetadataEvent::MemberAdded { agent_id, .. } => agent_id == local_agent_hex,
        NamedGroupMetadataEvent::JoinRequestApproved {
            requester_agent_id, ..
        } => requester_agent_id == local_agent_hex,
        _ => false,
    }
}

async fn current_treekem_epoch(state: &AppState, group_id: &str) -> Option<u64> {
    let group = state.treekem_groups.read().await.get(group_id).cloned();
    let group = group?;
    let epoch = group.lock().await.epoch();
    Some(epoch)
}

fn authorized_treekem_membership_event_for_queue(
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    sender_hex: &str,
) -> bool {
    if info.withdrawn {
        return false;
    }
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            actor,
            commit: Some(_),
            treekem_commit_b64: Some(_),
            treekem_epoch: Some(_),
            ..
        } => {
            actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
        }
        NamedGroupMetadataEvent::MemberRemoved {
            actor,
            agent_id,
            commit: Some(_),
            treekem_commit_b64,
            treekem_epoch,
            ..
        } => {
            let admin_remove = actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
                && treekem_commit_b64.is_some()
                && treekem_epoch.is_some();
            let self_leave = sender_hex == agent_id
                && actor == sender_hex
                && treekem_commit_b64.is_none()
                && treekem_epoch.is_none();
            admin_remove || self_leave
        }
        NamedGroupMetadataEvent::MemberBanned {
            actor,
            commit: Some(_),
            treekem_commit_b64: Some(_),
            treekem_epoch: Some(_),
            ..
        } => {
            actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
        }
        NamedGroupMetadataEvent::JoinRequestApproved {
            actor,
            requester_agent_id,
            request_id,
            commit: Some(_),
            treekem_commit_b64: Some(_),
            treekem_epoch: Some(_),
            ..
        } => {
            actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
                && info.join_requests.get(request_id).is_some_and(|req| {
                    req.is_pending() && req.requester_agent_id == *requester_agent_id
                })
        }
        _ => false,
    }
}

fn treekem_state_frontier_gap_reason(
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    local_agent_hex: &str,
    local_epoch: Option<u64>,
) -> Option<String> {
    if info.withdrawn {
        return None;
    }
    if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem {
        return None;
    }
    let frontier = treekem_membership_event_frontier(event)?;
    let is_local_welcome = treekem_event_is_local_welcome(event, local_agent_hex);
    if frontier.commit.revision <= info.state_revision || frontier.revision <= info.roster_revision
    {
        return None;
    }
    if frontier.commit.revision > info.state_revision.saturating_add(1)
        || frontier.revision > info.roster_revision.saturating_add(1)
    {
        return Some("revision_gap".to_string());
    }
    if frontier.commit.prev_state_hash.as_deref() != Some(info.state_hash.as_str()) {
        return Some("state_hash_gap".to_string());
    }
    if let Some(epoch) = frontier.epoch {
        match local_epoch {
            Some(local_epoch) if !is_local_welcome && epoch > local_epoch.saturating_add(1) => {
                return Some("treekem_epoch_gap".to_string());
            }
            None if !is_local_welcome => return Some("treekem_not_ready".to_string()),
            _ => {}
        }
    }
    None
}

async fn should_queue_treekem_membership_event(
    state: &AppState,
    group_id: &str,
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    local_agent_hex: &str,
) -> Option<String> {
    let local_epoch = current_treekem_epoch(state, group_id).await;
    treekem_state_frontier_gap_reason(info, event, local_agent_hex, local_epoch)
}

async fn remember_treekem_membership_event(state: &AppState, event: &NamedGroupMetadataEvent) {
    let Some(frontier) = treekem_membership_event_frontier(event) else {
        return;
    };
    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, frontier.group_id) {
            return;
        }
    }
    let mut logs = state.treekem_event_log.write().await;
    let log = logs.entry(frontier.group_id.to_string()).or_default();
    if let Some(key) = treekem_membership_event_key(event) {
        if log
            .iter()
            .filter_map(treekem_membership_event_key)
            .any(|existing| existing == key)
        {
            return;
        }
    }
    log.push_back(event.clone());
    while log.len() > TREEKEM_EVENT_LOG_PER_GROUP_CAP {
        log.pop_front();
    }
}

async fn queue_treekem_membership_event(
    state: &Arc<AppState>,
    group_id: &str,
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    reason: &str,
) {
    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, group_id) {
            tracing::debug!(
                target: "treekem.trace",
                stage = "queue_treekem_membership_event_reject",
                reason = "withdrawn_group",
                group_id = %LogHexId::group(&group_id),
            );
            return;
        }
    }
    let queued = PendingTreeKemMetadataEvent {
        event: event.clone(),
        sender,
        queued_at: Instant::now(),
    };
    let key = treekem_membership_event_key(&event);
    {
        let mut pending = state.treekem_pending_events.write().await;
        let queue = pending.entry(group_id.to_string()).or_default();
        if let Some(key) = key.as_deref() {
            if queue
                .iter()
                .filter_map(|pending| treekem_membership_event_key(&pending.event))
                .any(|existing| existing == key)
            {
                return;
            }
        }
        queue.push_back(queued);
        queue
            .make_contiguous()
            .sort_by_key(|pending| treekem_membership_event_sort_key(&pending.event));
        while queue.len() > TREEKEM_PENDING_EVENTS_PER_GROUP_CAP {
            queue.pop_front();
        }
    }
    tracing::warn!(group_id = %LogHexId::group(&group_id), reason, "queued TreeKEM membership event pending catch-up/replay");
    request_treekem_catchup_for_gap(state, group_id, &event, sender).await;
}

async fn request_treekem_catchup_for_gap(
    state: &Arc<AppState>,
    group_id: &str,
    event: &NamedGroupMetadataEvent,
    sender: AgentId,
) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let Some(frontier) = treekem_membership_event_frontier(event) else {
        return;
    };
    let (from_revision, from_epoch, current_state_hash) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_id) else {
            return;
        };
        if info.withdrawn {
            return;
        }
        (
            info.state_revision,
            info.secret_epoch,
            info.state_hash.clone(),
        )
    };
    let mut peers = Vec::new();
    if !frontier.actor.eq_ignore_ascii_case(&local_agent_hex) {
        if let Ok(peer) = parse_agent_id_hex(frontier.actor) {
            peers.push(peer);
        }
    }
    let sender_hex = hex::encode(sender.as_bytes());
    if sender_hex != local_agent_hex && !peers.contains(&sender) {
        peers.push(sender);
    }
    for peer in peers {
        let peer_hex = hex::encode(peer.as_bytes());
        let throttle_key = format!("{group_id}:{peer_hex}:{from_revision}:{from_epoch}");
        {
            let mut throttle = state.treekem_catchup_throttle.write().await;
            if throttle
                .get(&throttle_key)
                .is_some_and(|last| last.elapsed() < TREEKEM_CATCHUP_THROTTLE)
            {
                continue;
            }
            throttle.insert(throttle_key, Instant::now());
        }
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: group_id.to_string(),
            requester_agent_id: local_agent_hex.clone(),
            from_revision,
            from_treekem_epoch: from_epoch,
            current_state_hash: current_state_hash.clone(),
            missing_prev_state_hash: frontier.commit.prev_state_hash.clone(),
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        };
        let payload = match serde_json::to_vec(&request) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize TreeKEM catch-up request: {e}");
                continue;
            }
        };
        if let Err(e) = state
            .agent
            .send_direct_with_config(&peer, payload, direct_message_send_config())
            .await
        {
            tracing::debug!(group_id = %group_id, peer = %peer_hex, "TreeKEM catch-up request failed: {e}");
        }
    }
}

async fn replay_pending_treekem_events(state: &Arc<AppState>, group_id: &str) {
    let entries = {
        let mut pending = state.treekem_pending_events.write().await;
        let Some(queue) = pending.get_mut(group_id) else {
            return;
        };
        let mut entries: Vec<_> = queue.drain(..).collect();
        entries.retain(|pending| pending.queued_at.elapsed() < PENDING_JOIN_RESULT_TTL);
        entries.sort_by_key(|pending| treekem_membership_event_sort_key(&pending.event));
        entries
    };
    let mut still_pending = VecDeque::new();
    for pending in entries {
        let applied = apply_named_group_metadata_event_inner(
            state,
            pending.event.clone(),
            pending.sender,
            true,
            false,
        )
        .await;
        if !applied && treekem_membership_event_frontier(&pending.event).is_some() {
            let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
            let info = {
                let groups = state.named_groups.read().await;
                groups.get(group_id).cloned()
            };
            if let Some(info) = info {
                if should_queue_treekem_membership_event(
                    state,
                    group_id,
                    &info,
                    &pending.event,
                    &local_agent_hex,
                )
                .await
                .is_some()
                {
                    still_pending.push_back(pending);
                }
            }
        }
    }
    if !still_pending.is_empty() {
        let mut pending = state.treekem_pending_events.write().await;
        let queue = pending.entry(group_id.to_string()).or_default();
        for item in still_pending {
            queue.push_back(item);
        }
        while queue.len() > TREEKEM_PENDING_EVENTS_PER_GROUP_CAP {
            queue.pop_front();
        }
    }
}

async fn handle_treekem_catchup_request(
    state: &Arc<AppState>,
    sender: &AgentId,
    verified: bool,
    request: TreeKemCatchupRequest,
) {
    if !verified || request.message_type != "treekem_catchup_request" {
        return;
    }
    let sender_hex = hex::encode(sender.as_bytes());
    if sender_hex != request.requester_agent_id {
        return;
    }
    let (authorized, log_keys) = {
        let groups = state.named_groups.read().await;
        if let Some((key, info)) = groups.get_key_value(&request.group_id).or_else(|| {
            groups
                .iter()
                .find(|(_, info)| info.stable_group_id() == request.group_id)
        }) {
            if info.withdrawn {
                return;
            }
            let mut keys = vec![
                request.group_id.clone(),
                key.clone(),
                info.stable_group_id().to_string(),
            ];
            keys.sort();
            keys.dedup();
            (info.has_active_member(&sender_hex), keys)
        } else {
            (false, vec![request.group_id.clone()])
        }
    };
    let target_of_cached_add = {
        let logs = state.treekem_event_log.read().await;
        log_keys.iter().any(|key| {
            logs.get(key).is_some_and(|events| {
                events.iter().any(|event| match event {
                    NamedGroupMetadataEvent::MemberAdded { agent_id, .. } => {
                        agent_id == &sender_hex
                    }
                    NamedGroupMetadataEvent::JoinRequestApproved {
                        requester_agent_id, ..
                    } => requester_agent_id == &sender_hex,
                    _ => false,
                })
            })
        })
    };
    if !authorized && !target_of_cached_add {
        tracing::warn!(group_id = %LogHexId::group(&request.group_id), requester = %sender_hex, "rejecting unauthorized TreeKEM catch-up request");
        return;
    }
    let mut events = {
        let logs = state.treekem_event_log.read().await;
        let mut events = Vec::new();
        for key in &log_keys {
            if let Some(logged) = logs.get(key) {
                events.extend(logged.iter().cloned());
            }
        }
        events
            .into_iter()
            .filter(|event| {
                treekem_membership_event_frontier(event).is_some_and(|frontier| {
                    frontier.revision > request.from_revision
                        || frontier.epoch.unwrap_or_default() > request.from_treekem_epoch
                })
            })
            .collect::<Vec<_>>()
    };
    events.sort_by_key(treekem_membership_event_sort_key);
    let truncated = events.len() > request.limit.min(TREEKEM_CATCHUP_RESPONSE_EVENT_CAP);
    events.truncate(request.limit.min(TREEKEM_CATCHUP_RESPONSE_EVENT_CAP));
    let response = TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: request.group_id.clone(),
        events,
        truncated,
    };
    let payload = match serde_json::to_vec(&response) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(group_id = %LogHexId::group(&request.group_id), "failed to serialize TreeKEM catch-up response: {e}");
            return;
        }
    };
    if let Err(e) = state
        .agent
        .send_direct_with_config(sender, payload, direct_message_send_config())
        .await
    {
        tracing::warn!(group_id = %LogHexId::group(&request.group_id), requester = %sender_hex, "failed to send TreeKEM catch-up response: {e}");
    }
}

async fn handle_treekem_catchup_response(
    state: &Arc<AppState>,
    sender: &AgentId,
    verified: bool,
    response: TreeKemCatchupResponse,
) {
    if !verified || response.message_type != "treekem_catchup_response" {
        return;
    }
    let was_truncated = response.truncated;
    let mut events = response.events;
    events.sort_by_key(treekem_membership_event_sort_key);
    for event in events {
        apply_named_group_metadata_event(state, event, *sender, true).await;
    }
    replay_pending_treekem_events(state, &response.group_id).await;
    if was_truncated {
        tracing::debug!(
            target: "treekem.trace",
            group_id = %response.group_id,
            sender = %hex::encode(sender.as_bytes()),
            "TreeKEM catch-up response was truncated; requesting next page"
        );
        request_treekem_catchup_page(state, &response.group_id, sender).await;
    }
}

async fn request_treekem_catchup_page(state: &Arc<AppState>, group_id: &str, peer: &AgentId) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (from_revision, from_epoch, current_state_hash) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_id).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group_id)
        }) else {
            return;
        };
        (
            info.state_revision,
            info.secret_epoch,
            info.state_hash.clone(),
        )
    };
    let request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.to_string(),
        requester_agent_id: local_agent_hex,
        from_revision,
        from_treekem_epoch: from_epoch,
        current_state_hash,
        missing_prev_state_hash: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
    };
    let payload = match serde_json::to_vec(&request) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize paged TreeKEM catch-up request: {e}");
            return;
        }
    };
    if let Err(e) = state
        .agent
        .send_direct_with_config(peer, payload, direct_message_send_config())
        .await
    {
        tracing::debug!(group_id = %group_id, peer = %hex::encode(peer.as_bytes()), "paged TreeKEM catch-up request failed: {e}");
    }
}

/// Get-or-create the per-group membership serialization mutex. See
/// [`AppState::group_membership_locks`] for why membership applies must be
/// serialized per group.
async fn group_membership_lock(state: &AppState, group_key: &str) -> Arc<Mutex<()>> {
    let lock_key = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_key)
            .map(|info| info.stable_group_id().to_string())
            .or_else(|| {
                groups
                    .values()
                    .find(|info| {
                        info.stable_group_id() == group_key || info.mls_group_id == group_key
                    })
                    .map(|info| info.stable_group_id().to_string())
            })
            .unwrap_or_else(|| group_key.to_string())
    };
    {
        let locks = state.group_membership_locks.read().await;
        if let Some(lock) = locks.get(&lock_key) {
            return Arc::clone(lock);
        }
    }
    let mut locks = state.group_membership_locks.write().await;
    Arc::clone(
        locks
            .entry(lock_key)
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

async fn apply_named_group_metadata_event(
    state: &Arc<AppState>,
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    verified: bool,
) -> bool {
    apply_named_group_metadata_event_inner(state, event, sender, verified, true).await
}

async fn apply_named_group_metadata_event_inner(
    state: &Arc<AppState>,
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    verified: bool,
    allow_queue: bool,
) -> bool {
    let event_kind = named_group_metadata_event_kind(&event);
    let sender_hex = hex::encode(sender.as_bytes());
    tracing::debug!(
        target: "treekem.trace",
        stage = "apply_metadata_event_entry",
        event = event_kind,
        sender = %sender_hex,
        verified,
        allow_queue,
    );
    // The transport `verified` flag asserts the sender's AgentId→MachineId
    // binding is in our identity-discovery cache — a best-effort annotation
    // populated asynchronously from gossip announcements. `MemberRemoved`
    // carries a self-authenticating ML-DSA-signed state commit and is still
    // delivery-critical for the removed member itself, which may no longer be
    // in the metadata-topic eager mesh. `GroupDeleted` is the current delete
    // propagation event (and remains old-peer/replay compatible), carrying the
    // signed terminal withdrawal commit. The apply arms below re-check
    // authority from the signed commit (GroupDeleted: AdminOrHigher via
    // `commit.committed_by`; MemberRemoved: actor/sender binding plus
    // AdminOrHigher or MemberSelf signed-commit validation). The authenticated
    // DM `sender_hex` is reliable regardless of the cache, so bypassing
    // `verified` does not weaken membership authorization — only the racy cache
    // annotation is skipped.
    let bypass_verified = matches!(
        event,
        NamedGroupMetadataEvent::GroupDeleted {
            commit: Some(_),
            ..
        } | NamedGroupMetadataEvent::MemberRemoved {
            commit: Some(_),
            ..
        }
    );
    if !verified && !bypass_verified {
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "unverified",
            event = event_kind,
            sender = %sender_hex,
        );
        return false;
    }

    let group_id = match &event {
        NamedGroupMetadataEvent::MemberAdded { group_id, .. }
        | NamedGroupMetadataEvent::MemberRemoved { group_id, .. }
        | NamedGroupMetadataEvent::GroupDeleted { group_id, .. }
        | NamedGroupMetadataEvent::PolicyUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberRoleUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberBanned { group_id, .. }
        | NamedGroupMetadataEvent::MemberUnbanned { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCreated { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestRejected { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCancelled { group_id, .. }
        | NamedGroupMetadataEvent::GroupCardPublished { group_id, .. }
        | NamedGroupMetadataEvent::GroupMetadataUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberJoined { group_id, .. }
        | NamedGroupMetadataEvent::SecureShareDelivered { group_id, .. } => group_id.clone(),
    };

    let resolved_group_key = {
        let groups = state.named_groups.read().await;
        if groups.contains_key(&group_id) {
            group_id.clone()
        } else if let Some((key, _)) = groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == group_id)
        {
            key.clone()
        } else {
            tracing::debug!(
                target: "treekem.trace",
                stage = "apply_metadata_event_reject",
                reason = "unknown_group",
                event = event_kind,
                group_id = %group_id,
                sender = %sender_hex,
            );
            return false;
        }
    };
    // Serialize every membership apply for this group across the concurrent
    // gossip metadata listener and direct-channel listener. Held for the rest
    // of the apply so the load-mutate-commit sequence below cannot interleave
    // with a duplicate of the same event arriving on the other transport. The
    // direct-DM delivery added for reliability means the owner now receives the
    // same `MemberJoined` on two independent tasks at once; without this guard
    // they double-add to the MLS tree and clobber the roster. `info` is loaded
    // *under* the guard so no stale clone from a racing apply is in flight.
    let membership_lock = group_membership_lock(state, &resolved_group_key).await;
    let _membership_guard = membership_lock.lock().await;
    let info = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&resolved_group_key).cloned() else {
            return false;
        };
        info
    };
    if info.withdrawn && !withdrawn_group_allows_metadata_event(&event) {
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "withdrawn_group",
            event = event_kind,
            group_id = %resolved_group_key,
            sender = %sender_hex,
        );
        return false;
    }
    if !info.withdrawn && !live_group_allows_metadata_withdrawal_commit(&event) {
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "withdrawn_commit_requires_group_deleted",
            event = event_kind,
            group_id = %resolved_group_key,
            sender = %sender_hex,
        );
        return false;
    }
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
        && treekem_metadata_event_requires_phase3(&event)
    {
        tracing::warn!(
            group_id = %LogHexId::group(&resolved_group_key),
            "ignoring TreeKEM metadata membership event without Phase 3 Commit/Welcome transport"
        );
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "missing_phase3_transport",
            event = event_kind,
            group_id = %resolved_group_key,
            sender = %sender_hex,
        );
        return false;
    }

    if allow_queue
        && treekem_membership_event_frontier(&event).is_some()
        && authorized_treekem_membership_event_for_queue(&info, &event, &sender_hex)
    {
        if let Some(reason) = should_queue_treekem_membership_event(
            state,
            &resolved_group_key,
            &info,
            &event,
            &local_agent_hex,
        )
        .await
        {
            tracing::debug!(
                target: "treekem.trace",
                stage = "apply_metadata_event_queued",
                reason = %reason,
                event = event_kind,
                group_id = %resolved_group_key,
                sender = %sender_hex,
            );
            queue_treekem_membership_event(state, &resolved_group_key, event, sender, &reason)
                .await;
            return false;
        }
    }

    let event_for_log = event.clone();

    match event {
        NamedGroupMetadataEvent::MemberAdded {
            revision,
            actor,
            agent_id,
            display_name,
            treekem_commit_b64,
            treekem_welcome_b64,
            welcome_ref,
            treekem_epoch,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let Some(commit_b64) = treekem_commit_b64 else {
                    return false;
                };
                if treekem_welcome_b64.is_none() && welcome_ref.is_none() {
                    return false;
                }
                let Some(epoch) = treekem_epoch else {
                    return false;
                };
                Some((commit_b64, treekem_welcome_b64, welcome_ref, epoch))
            } else {
                None
            };
            let current = info.clone();
            let next = match apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.add_member(
                        agent_id.clone(),
                        x0x::groups::GroupRole::Member,
                        Some(actor.clone()),
                        display_name.clone(),
                    );
                    if let Some(name) = display_name.clone() {
                        next.set_display_name(&agent_id, name);
                    }
                    if let Some((_, _, _, epoch)) = treekem_payload.as_ref() {
                        next.secret_epoch = *epoch;
                        next.security_binding = Some(format!("treekem:epoch={epoch}"));
                    }
                },
            ) {
                Ok(next) => next,
                Err(e) => {
                    tracing::debug!(
                        target: "treekem.trace",
                        stage = "apply_metadata_event_reject",
                        reason = "member_added_state_commit_apply_failed",
                        group_id = %resolved_group_key,
                        member = %agent_id,
                        sender = %sender_hex,
                        revision,
                        commit_revision = commit.revision,
                        local_state_revision = current.state_revision,
                        local_roster_revision = current.roster_revision,
                        local_state_hash = %current.state_hash,
                        commit_prev_state_hash = ?commit.prev_state_hash,
                        error = %e,
                    );
                    return false;
                }
            };
            if let Some((commit_b64, welcome_b64, welcome_ref, epoch)) = treekem_payload {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                if agent_id == local_agent_hex {
                    let welcome_bytes = if let Some(welcome_b64) = welcome_b64 {
                        match BASE64.decode(welcome_b64) {
                            Ok(bytes) => bytes,
                            Err(_) => return false,
                        }
                    } else if let Some(welcome_ref) = welcome_ref {
                        match fetch_treekem_welcome_with_retries(state, &group_id, &welcome_ref)
                            .await
                        {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), welcome_id = %welcome_ref.welcome_id, "failed to fetch TreeKEM Welcome blob after retries: {e}");
                                return false;
                            }
                        }
                    } else {
                        return false;
                    };
                    let group_id_bytes = match hex::decode(&next.mls_group_id) {
                        Ok(bytes) => bytes,
                        Err(_) => return false,
                    };
                    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
                    let prepared = match x0x::mls::TreeKemMlsGroup::prepare_member(
                        state.agent.agent_id(),
                        &seed,
                    ) {
                        Ok(prepared) => prepared,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to prepare local TreeKEM identity for MemberAdded Welcome: {e}");
                            return false;
                        }
                    };
                    let tk = match x0x::mls::TreeKemMlsGroup::join_from_welcome(
                        prepared,
                        &welcome_bytes,
                    ) {
                        Ok(group) => group,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to join TreeKEM group from MemberAdded Welcome: {e}");
                            return false;
                        }
                    };
                    if tk.epoch() != epoch {
                        return false;
                    }
                    if let Err(e) = install_joined_treekem_group_after_crypto_recheck(
                        state,
                        &resolved_group_key,
                        next.clone(),
                        tk,
                        "member_added_welcome",
                    )
                    .await
                    {
                        tracing::error!(group_id = %LogHexId::group(&resolved_group_key), "failed to install TreeKEM snapshot after MemberAdded Welcome: {e}");
                        return false;
                    }
                } else {
                    let group = {
                        let map = state.treekem_groups.read().await;
                        map.get(&resolved_group_key).cloned()
                    };
                    if let Some(group) = group {
                        if let Err(e) = process_treekem_commit_after_crypto_recheck(
                            state,
                            &resolved_group_key,
                            &next,
                            group,
                            &commit_bytes,
                            epoch,
                            "member_added_commit",
                        )
                        .await
                        {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM MemberAdded commit: {e}");
                            return false;
                        }
                    } else if !info.has_active_member(&local_agent_hex) {
                        // This daemon is a pre-Welcome joiner catching up on
                        // authority-signed state commits for members who joined
                        // before it. It has no TreeKEM ratchet yet, so it
                        // cannot process their TreeKEM commits. Applying the
                        // signed metadata commit advances the roster/state hash
                        // so the joiner's own later MemberAdded Welcome can
                        // validate against the correct frontier.
                        tracing::debug!(
                            target: "treekem.trace",
                            stage = "member_added_pre_welcome_state_only_apply",
                            group_id = %resolved_group_key,
                            member = %agent_id,
                            local = %local_agent_hex,
                            revision,
                            epoch,
                        );
                    } else {
                        tracing::debug!(
                            target: "treekem.trace",
                            stage = "apply_metadata_event_reject",
                            reason = "member_added_missing_local_treekem_group",
                            group_id = %resolved_group_key,
                            member = %agent_id,
                            local = %local_agent_hex,
                            revision,
                            epoch,
                        );
                        return false;
                    }
                }
            } else {
                let mut mls_groups = state.mls_groups.write().await;
                if let Some(group) = mls_groups.get_mut(&resolved_group_key) {
                    if let Ok(member_id) = parse_agent_id_hex(&agent_id) {
                        if !group.is_member(&member_id) {
                            let _ = group.add_member(member_id).await;
                        }
                    }
                }
                drop(mls_groups);
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            save_mls_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            true
        }
        NamedGroupMetadataEvent::MemberRemoved {
            revision,
            actor,
            agent_id,
            treekem_commit_b64,
            treekem_epoch,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let admin_remove_auth = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            let self_leave_auth = sender_hex == agent_id && actor == sender_hex;
            if !admin_remove_auth && !self_leave_auth {
                return false;
            }
            let action_kind = if self_leave_auth {
                x0x::groups::ActionKind::MemberSelf
            } else {
                x0x::groups::ActionKind::AdminOrHigher
            };
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                if self_leave_auth {
                    if treekem_commit_b64.is_some() || treekem_epoch.is_some() {
                        return false;
                    }
                    None
                } else {
                    let Some(commit_b64) = treekem_commit_b64 else {
                        return false;
                    };
                    let Some(epoch) = treekem_epoch else {
                        return false;
                    };
                    Some((commit_b64, epoch))
                }
            } else {
                None
            };
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(&current, &commit, action_kind, |next| {
                next.roster_revision = revision.max(next.roster_revision);
                next.remove_member(&agent_id, Some(actor.clone()));
                if let Some((_, epoch)) = treekem_payload.as_ref() {
                    next.secret_epoch = *epoch;
                    next.security_binding = Some(format!("treekem:epoch={epoch}"));
                }
            }) else {
                return false;
            };
            let removed_self = agent_id == local_agent_hex;
            if removed_self {
                state.named_groups.write().await.remove(&resolved_group_key);
            }
            if treekem_payload.is_none() {
                let mut mls_groups = state.mls_groups.write().await;
                if let Some(group) = mls_groups.get_mut(&resolved_group_key) {
                    if let Ok(member_id) = parse_agent_id_hex(&agent_id) {
                        if group.is_member(&member_id) {
                            let _ = group.remove_member(member_id).await;
                        }
                    }
                }
                drop(mls_groups);
            }
            if removed_self {
                state
                    .group_card_cache
                    .write()
                    .await
                    .remove(&resolved_group_key);
                state.mls_groups.write().await.remove(&resolved_group_key);
                state
                    .treekem_groups
                    .write()
                    .await
                    .remove(&resolved_group_key);
                remove_treekem_persistence_for_group_id(
                    state,
                    &resolved_group_key,
                    "member_removed_self",
                )
                .await;
                save_named_groups(state).await;
                save_mls_groups(state).await;
                return true;
            }
            if let Some((commit_b64, _epoch)) = treekem_payload {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&resolved_group_key).cloned()
                };
                let Some(group) = group else {
                    return false;
                };
                if let Err(e) = process_treekem_commit_after_crypto_recheck(
                    state,
                    &resolved_group_key,
                    &next,
                    group,
                    &commit_bytes,
                    _epoch,
                    "member_removed_commit",
                )
                .await
                {
                    tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM remove commit: {e}");
                    return false;
                }
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            save_mls_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            true
        }
        NamedGroupMetadataEvent::GroupDeleted {
            revision,
            actor,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            // Current delete propagation and legacy delete compatibility both
            // use GroupDeleted with a signed terminal withdrawal commit. DELETE
            // /groups/:id now emits MemberRemoved self-leave only. Apply
            // GroupDeleted by the commit signer rather than by the transport
            // sender: terminal apply validation verifies the ML-DSA signature
            // and that `commit.committed_by` held an Admin-or-higher role. The
            // advisory `actor` field must name that verified signer.
            if actor != commit.committed_by {
                return false;
            }
            if !commit.withdrawn {
                return false;
            }
            let current = info.clone();
            let next = match apply_terminal_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.updated_at = commit.committed_at;
                },
            ) {
                Ok(next) => next,
                Err(e) => {
                    tracing::debug!(
                        target: "treekem.trace",
                        stage = "apply_metadata_event_reject",
                        reason = "group_deleted_state_commit_apply_failed",
                        error = %e,
                        event = event_kind,
                        group_id = %resolved_group_key,
                        sender = %sender_hex,
                    );
                    return false;
                }
            };
            // Keep the signed terminal record as a keyless withdrawn tombstone.
            // ADR-0012's "leave nothing behind" is interpreted as wiping MLS,
            // TreeKEM snapshots/queues and GSS shared_secret material; the
            // retained GroupInfo is the guard that blocks stale-card imports
            // from recreating a live authoring-capable group.
            retain_withdrawn_group_tombstone(state, &resolved_group_key, next, "group_deleted")
                .await;
            true
        }
        NamedGroupMetadataEvent::PolicyUpdated {
            revision,
            actor: _,
            policy,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.policy_revision = revision.max(next.policy_revision);
                    next.policy = policy.clone();
                    if next.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
                        && next.discovery_card_topic.is_none()
                    {
                        next.discovery_card_topic = Some(format!(
                            "x0x.group.{}.card",
                            &next.mls_group_id[..16.min(next.mls_group_id.len())]
                        ));
                    }
                    next.updated_at = commit.committed_at;
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::MemberRoleUpdated {
            revision,
            actor,
            agent_id,
            role,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let Some(target) = info.members_v2.get(&agent_id).cloned() else {
                return false;
            };
            if target.is_removed() || target.is_banned() {
                return false;
            }
            // ADR-0016 reserved-role rationale: the REST authoring API rejects
            // Owner/Moderator/Guest assignments. Signed gossip apply rejects only
            // Owner because it is admin-equivalent; Moderator/Guest rank below
            // Admin, grant no control authority, and remain replayable for
            // validly signed legacy/cross-version convergence.
            if role == x0x::groups::GroupRole::Owner {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.set_member_role(&agent_id, role);
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::MemberBanned {
            revision,
            actor,
            agent_id,
            secret_epoch,
            treekem_commit_b64,
            treekem_epoch,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let Some(commit_b64) = treekem_commit_b64 else {
                    return false;
                };
                let Some(epoch) = treekem_epoch else {
                    return false;
                };
                Some((commit_b64, epoch))
            } else {
                None
            };
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.ban_member(&agent_id, Some(actor.clone()));
                    if let Some((_, epoch)) = treekem_payload.as_ref() {
                        next.secret_epoch = *epoch;
                        next.security_binding = Some(format!("treekem:epoch={epoch}"));
                    } else if let Some(secret_epoch) = secret_epoch {
                        let old_epoch = next.secret_epoch;
                        next.secret_epoch = secret_epoch;
                        next.security_binding = Some(format!("gss:epoch={secret_epoch}"));
                        if old_epoch < secret_epoch {
                            next.shared_secret = None;
                        }
                    }
                },
            ) else {
                return false;
            };
            let banned_self = agent_id == local_agent_hex;
            if banned_self {
                state
                    .treekem_groups
                    .write()
                    .await
                    .remove(&resolved_group_key);
                remove_treekem_persistence_for_group_id(
                    state,
                    &resolved_group_key,
                    "member_banned_self",
                )
                .await;
            } else if let Some((commit_b64, epoch)) = treekem_payload {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&resolved_group_key).cloned()
                };
                let Some(group) = group else {
                    return false;
                };
                if let Err(e) = process_treekem_commit_after_crypto_recheck(
                    state,
                    &resolved_group_key,
                    &next,
                    group,
                    &commit_bytes,
                    epoch,
                    "member_banned_commit",
                )
                .await
                {
                    tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM ban commit: {e}");
                    return false;
                }
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            true
        }
        NamedGroupMetadataEvent::MemberUnbanned {
            revision,
            actor,
            agent_id,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    if next.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                        if let Some(member) = next.members_v2.get_mut(&agent_id) {
                            member.state = x0x::groups::GroupMemberState::Removed;
                            member.updated_at = commit.committed_at;
                            member.removed_by = None;
                        }
                    } else {
                        next.unban_member(&agent_id);
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::JoinRequestCreated {
            request_id,
            requester_agent_id,
            message,
            ts,
            requester_kem_public_key_b64,
            treekem_key_package_b64,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            if sender_hex != requester_agent_id {
                return false;
            }
            if info.policy.admission != x0x::groups::GroupAdmission::RequestAccess {
                return false;
            }
            if info.has_active_member(&requester_agent_id) {
                return false;
            }
            if info.is_banned(&requester_agent_id) {
                return false;
            }
            if info
                .join_requests
                .values()
                .any(|r| r.requester_agent_id == requester_agent_id && r.is_pending())
            {
                return false;
            }
            if info.join_requests.contains_key(&request_id) {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::NonMemberRequest,
                |next| {
                    let req = x0x::groups::JoinRequest {
                        request_id: request_id.clone(),
                        group_id: group_id.clone(),
                        requester_agent_id: requester_agent_id.clone(),
                        requester_user_id: None,
                        requested_role: x0x::groups::GroupRole::Member,
                        message: message.clone(),
                        treekem_key_package_b64: treekem_key_package_b64.clone(),
                        created_at: ts,
                        reviewed_at: None,
                        reviewed_by: None,
                        status: x0x::groups::JoinRequestStatus::Pending,
                    };
                    next.join_requests.insert(request_id.clone(), req);
                    if let Some(kem_b64) = requester_kem_public_key_b64.clone() {
                        next.members_v2
                            .entry(requester_agent_id.clone())
                            .and_modify(|m| {
                                m.kem_public_key_b64 = Some(kem_b64.clone());
                            })
                            .or_insert_with(|| x0x::groups::GroupMember {
                                agent_id: requester_agent_id.clone(),
                                user_id: None,
                                role: x0x::groups::GroupRole::Member,
                                state: x0x::groups::GroupMemberState::Pending,
                                display_name: None,
                                joined_at: ts,
                                updated_at: ts,
                                added_by: None,
                                removed_by: None,
                                kem_public_key_b64: Some(kem_b64),
                                treekem_key_package_b64: treekem_key_package_b64.clone(),
                            });
                    }
                    if let Some(kp_b64) = treekem_key_package_b64.clone() {
                        next.set_member_treekem_key_package(&requester_agent_id, kp_b64);
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::JoinRequestApproved {
            request_id,
            revision,
            actor,
            requester_agent_id,
            treekem_commit_b64,
            treekem_welcome_b64,
            welcome_ref,
            treekem_epoch,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let Some(req_snapshot) = info.join_requests.get(&request_id).cloned() else {
                return false;
            };
            if !req_snapshot.is_pending() {
                return false;
            }
            if req_snapshot.requester_agent_id != requester_agent_id {
                return false;
            }
            if info.is_banned(&requester_agent_id) {
                return false;
            }
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let Some(commit_b64) = treekem_commit_b64 else {
                    return false;
                };
                if treekem_welcome_b64.is_none() && welcome_ref.is_none() {
                    return false;
                }
                let Some(epoch) = treekem_epoch else {
                    return false;
                };
                Some((commit_b64, treekem_welcome_b64, welcome_ref, epoch))
            } else {
                None
            };
            let request_key_package_b64 = req_snapshot.treekem_key_package_b64.clone();
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    let now_ms = commit.committed_at;
                    if let Some(req) = next.join_requests.get_mut(&request_id) {
                        req.status = x0x::groups::JoinRequestStatus::Approved;
                        req.reviewed_by = Some(actor.clone());
                        req.reviewed_at = Some(now_ms);
                    }
                    next.roster_revision = revision.max(next.roster_revision);
                    next.add_member(
                        requester_agent_id.clone(),
                        x0x::groups::GroupRole::Member,
                        Some(actor.clone()),
                        None,
                    );
                    if let Some(kp_b64) = request_key_package_b64.clone() {
                        next.set_member_treekem_key_package(&requester_agent_id, kp_b64);
                    }
                    if let Some((_, _, _, epoch)) = treekem_payload.as_ref() {
                        next.secret_epoch = *epoch;
                        next.security_binding = Some(format!("treekem:epoch={epoch}"));
                    }
                },
            ) else {
                return false;
            };
            if let Some((commit_b64, welcome_b64, welcome_ref, _epoch)) = treekem_payload {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                if requester_agent_id == local_agent_hex {
                    let welcome_bytes = if let Some(welcome_b64) = welcome_b64 {
                        match BASE64.decode(welcome_b64) {
                            Ok(bytes) => bytes,
                            Err(_) => return false,
                        }
                    } else if let Some(welcome_ref) = welcome_ref {
                        match fetch_treekem_welcome_with_retries(state, &group_id, &welcome_ref)
                            .await
                        {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), welcome_id = %welcome_ref.welcome_id, "failed to fetch TreeKEM Welcome blob after retries: {e}");
                                return false;
                            }
                        }
                    } else {
                        return false;
                    };
                    let group_id_bytes = match hex::decode(&next.mls_group_id) {
                        Ok(bytes) => bytes,
                        Err(_) => return false,
                    };
                    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
                    let prepared = match x0x::mls::TreeKemMlsGroup::prepare_member(
                        state.agent.agent_id(),
                        &seed,
                    ) {
                        Ok(prepared) => prepared,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to prepare local TreeKEM identity for welcome: {e}");
                            return false;
                        }
                    };
                    let tk = match x0x::mls::TreeKemMlsGroup::join_from_welcome(
                        prepared,
                        &welcome_bytes,
                    ) {
                        Ok(group) => group,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to join TreeKEM group from Welcome: {e}");
                            return false;
                        }
                    };
                    if tk.epoch() != _epoch {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), expected_epoch = _epoch, actual_epoch = tk.epoch(), "TreeKEM Welcome joined at unexpected epoch");
                        return false;
                    }
                    if let Err(e) = install_joined_treekem_group_after_crypto_recheck(
                        state,
                        &resolved_group_key,
                        next.clone(),
                        tk,
                        "join_request_approved_welcome",
                    )
                    .await
                    {
                        tracing::error!(group_id = %LogHexId::group(&resolved_group_key), "failed to install joined TreeKEM snapshot: {e}");
                        return false;
                    }
                } else {
                    let group = {
                        let map = state.treekem_groups.read().await;
                        map.get(&resolved_group_key).cloned()
                    };
                    let Some(group) = group else {
                        return false;
                    };
                    if let Err(e) = process_treekem_commit_after_crypto_recheck(
                        state,
                        &resolved_group_key,
                        &next,
                        group,
                        &commit_bytes,
                        _epoch,
                        "join_request_approved_commit",
                    )
                    .await
                    {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM add commit: {e}");
                        return false;
                    }
                }
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            true
        }
        NamedGroupMetadataEvent::JoinRequestRejected {
            request_id,
            actor,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let Some(req_snapshot) = info.join_requests.get(&request_id).cloned() else {
                return false;
            };
            if !req_snapshot.is_pending() {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    if let Some(req) = next.join_requests.get_mut(&request_id) {
                        req.status = x0x::groups::JoinRequestStatus::Rejected;
                        req.reviewed_by = Some(actor.clone());
                        req.reviewed_at = Some(commit.committed_at);
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::JoinRequestCancelled {
            request_id,
            requester_agent_id,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            if sender_hex != requester_agent_id {
                return false;
            }
            let Some(req_snapshot) = info.join_requests.get(&request_id).cloned() else {
                return false;
            };
            if req_snapshot.requester_agent_id != requester_agent_id || !req_snapshot.is_pending() {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::NonMemberRequest,
                |next| {
                    if let Some(req) = next.join_requests.get_mut(&request_id) {
                        req.status = x0x::groups::JoinRequestStatus::Cancelled;
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::GroupCardPublished { card, .. } => {
            if info.withdrawn && !card.withdrawn {
                return false;
            }
            let sender_is_admin = info
                .caller_role(&sender_hex)
                .is_some_and(|role| role.at_least(x0x::groups::GroupRole::Admin));
            if !sender_is_admin {
                return false;
            }
            if card.group_id != info.stable_group_id() {
                return false;
            }
            if !card.signature.is_empty() && card.verify_signature().is_err() {
                return false;
            }
            let mut cache = state.group_card_cache.write().await;
            prune_expired_group_cards(&mut cache, now_millis_u64());
            if card.withdrawn {
                remove_group_card_if_not_stale(&mut cache, &card);
            } else if cache_group_card_if_newer(&mut cache, card.group_id.clone(), card) {
                enforce_group_card_cache_cap(&mut cache);
            }
            false
        }
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            revision,
            actor,
            name,
            description,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    if let Some(n) = name.clone() {
                        next.name = n;
                    }
                    if let Some(d) = description.clone() {
                        next.description = d;
                    }
                    next.updated_at = commit.committed_at;
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::SecureShareDelivered {
            group_id: ref ev_group_id,
            recipient,
            secret_epoch,
            kem_ciphertext_b64,
            aead_nonce_b64,
            aead_ciphertext_b64,
            actor,
        } => {
            // Only process messages addressed to this daemon. A non-recipient
            // daemon CANNOT open the envelope even if it tried — ML-KEM
            // decapsulation with the wrong key yields a random shared secret
            // and the AEAD auth-tag check fails. The early return here is a
            // performance optimisation, not a security boundary.
            let self_hex = hex::encode(state.agent.agent_id().as_bytes());
            if recipient != self_hex {
                return false;
            }
            if info.withdrawn {
                tracing::debug!(
                    group_id = %ev_group_id,
                    "ignoring SecureShareDelivered for withdrawn group"
                );
                return false;
            }
            // Only accept from an active admin+.
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            // Ignore stale envelopes. Equal-epoch delivery is still accepted
            // if we only know the epoch/security_binding from a prior
            // MemberBanned commit but have not yet received the actual shared
            // secret material.
            if secret_epoch < info.secret_epoch
                || (secret_epoch == info.secret_epoch && info.shared_secret.is_some())
            {
                return false;
            }
            use base64::Engine as _;
            let kem_ct = match BASE64.decode(&kem_ciphertext_b64) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let aead_nonce = match BASE64.decode(&aead_nonce_b64) {
                Ok(b) => b,
                Err(_) => return false,
            };
            if aead_nonce.len() != 12 {
                return false;
            }
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&aead_nonce);
            let aead_ct = match BASE64.decode(&aead_ciphertext_b64) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let aad = secure_share_aad(ev_group_id, &recipient, secret_epoch);
            let opened = x0x::groups::kem_envelope::open_group_secret(
                &state.agent_kem_keypair,
                &aad,
                &kem_ct,
                &nonce_bytes,
                &aead_ct,
            );
            let secret = match opened {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        group_id = %ev_group_id,
                        "KEM envelope decap/decrypt failed: {e}"
                    );
                    return false;
                }
            };
            if let Err(e) = ensure_named_group_key_material_install_allowed(
                state,
                &resolved_group_key,
                Some(info.stable_group_id()),
                "secure_share_delivered",
            )
            .await
            {
                tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "rejecting SecureShareDelivered after post-crypto terminality recheck: {e}");
                return false;
            }
            let mut next = info.clone();
            next.shared_secret = Some(secret.to_vec());
            next.secret_epoch = secret_epoch;
            next.security_binding = Some(format!("gss:epoch={secret_epoch}"));
            if !store_named_group_info(state, &resolved_group_key, next).await {
                return false;
            }
            save_named_groups(state).await;
            tracing::info!(
                group_id = %ev_group_id,
                secret_epoch,
                "Phase D.2: stored new group shared secret (epoch {secret_epoch}) via KEM-sealed envelope"
            );
            false
        }
        NamedGroupMetadataEvent::MemberJoined {
            stable_group_id,
            member_agent_id,
            member_public_key_b64,
            role,
            display_name,
            inviter_agent_id,
            invite_secret,
            ts_ms,
            treekem_key_package_b64,
            signature_b64,
            ..
        } => {
            // 1. The gossip layer's `verified` gate already enforced that
            //    `sender` produced this payload; check sender == member.
            if !sender_hex.eq_ignore_ascii_case(&member_agent_id) {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    sender = %sender_hex,
                    member = %member_agent_id,
                    "MemberJoined: rejecting — sender != member_agent_id"
                );
                return false;
            }

            // 2. Decode the joiner's published public key + signature.
            use base64::Engine as _;
            let pubkey_bytes = match BASE64.decode(&member_public_key_b64) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad public key base64: {e}"
                    );
                    return false;
                }
            };
            let pubkey = match ant_quic::MlDsaPublicKey::from_bytes(&pubkey_bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad public key bytes: {e:?}"
                    );
                    return false;
                }
            };
            let sig_bytes = match BASE64.decode(&signature_b64) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad signature base64: {e}"
                    );
                    return false;
                }
            };
            let sig = match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
                &sig_bytes,
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad signature bytes: {e:?}"
                    );
                    return false;
                }
            };

            // 3. Recompute canonical bytes and verify the joiner's signature.
            //    `stable_group_id` is part of the signing input on the
            //    publisher side; we pass it through verbatim here. Bumping
            //    or stripping the field would break verify on the receiver.
            let canonical = canonical_member_joined_bytes(
                &group_id,
                stable_group_id.as_deref(),
                &member_agent_id,
                &member_public_key_b64,
                role,
                display_name.as_deref(),
                &inviter_agent_id,
                &invite_secret,
                ts_ms,
                treekem_key_package_b64.as_deref(),
            );
            if let Err(e) = ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
                &pubkey, &canonical, &sig,
            ) {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    "MemberJoined: signature did not verify: {e:?}"
                );
                return false;
            }

            // 4. Derived AgentId must match the claimed member_agent_id.
            let derived = hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0);
            if !derived.eq_ignore_ascii_case(&member_agent_id) {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    "MemberJoined: derived agent_id {} != claimed {}",
                    derived,
                    member_agent_id
                );
                return false;
            }

            // 5. Invite-join v1 is strictly role-capped. The joiner signs
            //    the role, but the invite itself grants only Member; accepting
            //    an arbitrary wire role would let an invite holder self-promote.
            if role != x0x::groups::GroupRole::Member {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    member = %member_agent_id,
                    role = ?role,
                    "MemberJoined: rejecting non-member role"
                );
                state
                    .groups_diagnostics
                    .record_member_joined_rejected_non_member_role(&resolved_group_key);
                return false;
            }

            // 6. Only the original local inviter can validate and consume the
            //    one-time invite secret. Third-party receivers deliberately do
            //    NOT apply MemberJoined directly; they wait for the inviter's
            //    authority-signed MemberAdded commit below. This keeps all
            //    durable roster/state_hash mutations inside the signed D.3
            //    state-commit chain.
            let local_is_inviter = local_agent_hex.eq_ignore_ascii_case(&inviter_agent_id);
            if !local_is_inviter {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    inviter = %inviter_agent_id,
                    local = %local_agent_hex,
                    "MemberJoined: ignoring on non-inviter receiver"
                );
                return false;
            }
            let inviter_role = info.caller_role(&inviter_agent_id);
            let inviter_authorised =
                inviter_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !inviter_authorised {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    inviter = %inviter_agent_id,
                    "MemberJoined: local inviter is not an admin/owner"
                );
                return false;
            }
            if info.withdrawn {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    "MemberJoined: rejecting — group is withdrawn"
                );
                return false;
            }

            // 7. Idempotent — if the joiner is already active, a replayed
            //    MemberJoined after the inviter committed the add is a no-op and
            //    must not consume any fresh invite record.
            if info.has_active_member(&member_agent_id) {
                return false;
            }

            // 8. Build the authoritative committed add on a clone first. If
            //    validation/signing fails, the live group remains unchanged.
            let signing_kp = state.agent.identity().agent_keypair();
            let now_ms = now_millis_u64();
            let mut next = info.clone();
            if let Err(reason) =
                next.consume_issued_invite(&invite_secret, &member_agent_id, role, ts_ms, now_ms)
            {
                if reason == "invite_secret_unknown" {
                    state
                        .groups_diagnostics
                        .record_member_joined_rejected_invite_secret_unknown(&resolved_group_key);
                }
                tracing::debug!(
                    group_id = %resolved_group_key,
                    inviter = %inviter_agent_id,
                    reason,
                    "MemberJoined: invite validation failed"
                );
                return false;
            }
            let treekem_key_package_bytes =
                if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                    let Some(kp_b64) = treekem_key_package_b64.clone() else {
                        return false;
                    };
                    match BASE64.decode(kp_b64) {
                        Ok(bytes) => Some(bytes),
                        Err(_) => return false,
                    }
                } else {
                    None
                };
            let mut treekem_epoch = None;
            let mut treekem_commit = None;
            let mut treekem_welcome = None;
            next.roster_revision = next.roster_revision.saturating_add(1);
            next.add_member_with_kem(
                member_agent_id.clone(),
                x0x::groups::GroupRole::Member,
                Some(inviter_agent_id.clone()),
                display_name.clone(),
                None,
            );
            if let Some(ref dn) = display_name {
                next.set_display_name(&member_agent_id, dn.clone());
            }
            if let Some(kp_b64) = treekem_key_package_b64.clone() {
                next.set_member_treekem_key_package(&member_agent_id, kp_b64);
            }
            let revision = next.roster_revision;
            let commit = if let Some(kp_bytes) = treekem_key_package_bytes.as_ref() {
                let member_id = match parse_agent_id_hex(&member_agent_id) {
                    Ok(id) => id,
                    Err(_) => return false,
                };
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&resolved_group_key).cloned()
                };
                let Some(group) = group else {
                    return false;
                };
                let mut guard = group.lock().await;
                let expected_epoch = guard.epoch().saturating_add(1);
                next.secret_epoch = expected_epoch;
                next.security_binding = Some(format!("treekem:epoch={expected_epoch}"));
                let commit = match next.seal_commit(signing_kp, now_ms) {
                    Ok(commit) => commit,
                    Err(e) => {
                        tracing::warn!(
                            group_id = %LogHexId::group(&resolved_group_key),
                            member = %LogHexId::agent(&member_agent_id),
                            "MemberJoined: failed to seal authoritative add: {e}"
                        );
                        return false;
                    }
                };
                let rollback_snapshot = match guard.to_snapshot_bytes() {
                    Ok(snapshot) => snapshot,
                    Err(e) => {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), member = %LogHexId::agent(&member_agent_id), "MemberJoined: failed to snapshot TreeKEM group before add: {e}");
                        return false;
                    }
                };
                let out = match guard.add_member(member_id, kp_bytes) {
                    Ok(out) => out,
                    Err(e) => {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), member = %LogHexId::agent(&member_agent_id), "MemberJoined: TreeKEM add_member failed: {e}");
                        return false;
                    }
                };
                if guard.epoch() != expected_epoch {
                    rollback_treekem_group_after_failed_install(
                        state,
                        &resolved_group_key,
                        &info,
                        &rollback_snapshot,
                        &mut guard,
                        "member_joined_add",
                    );
                    return false;
                }
                if let Err(e) = persist_treekem_and_named_groups_atomic_with_info(
                    state,
                    &resolved_group_key,
                    next.clone(),
                    &guard,
                )
                .await
                {
                    rollback_treekem_group_after_failed_install(
                        state,
                        &resolved_group_key,
                        &info,
                        &rollback_snapshot,
                        &mut guard,
                        "member_joined_add",
                    );
                    tracing::error!(group_id = %LogHexId::group(&resolved_group_key), "failed to persist TreeKEM snapshot after invite add: {e}");
                    return false;
                }
                treekem_epoch = Some(expected_epoch);
                treekem_commit = Some(out.commit);
                treekem_welcome = Some(out.welcome);
                commit
            } else {
                match next.seal_commit(signing_kp, now_ms) {
                    Ok(commit) => commit,
                    Err(e) => {
                        tracing::warn!(
                            group_id = %LogHexId::group(&resolved_group_key),
                            member = %LogHexId::agent(&member_agent_id),
                            "MemberJoined: failed to seal authoritative add: {e}"
                        );
                        return false;
                    }
                }
            };
            let metadata_topic = next.metadata_topic.clone();
            let event_group_id = next.stable_group_id().to_string();
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }

            // Persist and expose the committed roster before any slower MLS or
            // discovery-card side effects. Tests and operators poll
            // /groups/:id/members and /diagnostics/groups as the acceptance
            // signal for this path.
            save_named_groups(state).await;
            state
                .groups_diagnostics
                .record_member_joined(&resolved_group_key);

            if treekem_epoch.is_none() {
                if let Ok(member_id) = parse_agent_id_hex(&member_agent_id) {
                    let mut mls_groups = state.mls_groups.write().await;
                    if let Some(group) = mls_groups.get_mut(&resolved_group_key) {
                        if !group.is_member(&member_id) {
                            let _ = group.add_member(member_id).await;
                        }
                    }
                }
                save_mls_groups(state).await;
            }
            let welcome_ref = if let Some(welcome) = treekem_welcome.take() {
                Some(stage_treekem_welcome(state, &event_group_id, &member_agent_id, welcome).await)
            } else {
                None
            };
            let event = NamedGroupMetadataEvent::MemberAdded {
                group_id: event_group_id.clone(),
                revision,
                actor: inviter_agent_id.clone(),
                agent_id: member_agent_id.clone(),
                display_name: display_name.clone(),
                treekem_commit_b64: treekem_commit.map(|c| BASE64.encode(c)),
                treekem_welcome_b64: None,
                welcome_ref,
                treekem_epoch,
                commit: Some(commit),
            };
            stage_join_result(state, &event_group_id, &member_agent_id, event.clone()).await;
            publish_named_group_metadata_event(state, &metadata_topic, &event).await;
            remember_treekem_membership_event(state, &event).await;
            spawn_named_group_event_delivery_to_active_members(
                state,
                &next,
                &event,
                std::slice::from_ref(&member_agent_id),
            );
            maybe_publish_group_card_after_state_change(state, &resolved_group_key).await;
            tracing::info!(
                group_id = %resolved_group_key,
                member = %member_agent_id,
                inviter = %inviter_agent_id,
                "MemberJoined: accepted and published authoritative MemberAdded commit"
            );
            false
        }
    }
}

async fn ensure_named_group_metadata_listener(state: Arc<AppState>, group_id: &str) {
    if state
        .group_metadata_tasks
        .read()
        .await
        .contains_key(group_id)
    {
        return;
    }

    let metadata_topic = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).and_then(|g| {
            if g.withdrawn {
                None
            } else {
                Some(g.metadata_topic.clone())
            }
        })
    };
    let Some(metadata_topic) = metadata_topic else {
        return;
    };
    let mut sub = match state.agent.subscribe(&metadata_topic).await {
        Ok(sub) => sub,
        Err(e) => {
            tracing::warn!(group_id = %LogHexId::group(&group_id), topic = %LogHexId::topic(&metadata_topic), "failed to subscribe to named-group metadata topic: {e}");
            return;
        }
    };
    let group_id = group_id.to_string();
    let task_group_id = group_id.clone();
    let state_for_task = Arc::clone(&state);
    let handle = tokio::spawn(async move {
        let mut shutdown_rx = state_for_task.shutdown_notify.subscribe();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe_msg = sub.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    let Some(sender) = msg.sender else { continue; };
                    let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload) else { continue; };
                    let should_exit = apply_named_group_metadata_event(&state_for_task, event, sender, msg.verified).await;
                    if should_exit { break; }
                }
            }
        }
        state_for_task
            .group_metadata_tasks
            .write()
            .await
            .remove(&task_group_id);
    });

    state
        .group_metadata_tasks
        .write()
        .await
        .insert(group_id, handle);
}

/// Spawn every gossip listener a member needs for a named group.
///
/// Members must be subscribed to both the metadata topic *and* the
/// public-message topic (`x0x.groups.public.<stable_id>`) before any peer
/// can publish, otherwise the very first signed-public message is silently
/// dropped at the receiver's pubsub layer (Plumtree cannot backfill messages
/// on a topic that had no subscriber at receive time). This helper enforces
/// that invariant in one place — every site that inserts a group into
/// `state.named_groups` must call it.
///
/// Both inner spawners are idempotent, so calling this repeatedly for the
/// same `group_id` is safe. The public-message listener is gated on
/// `confidentiality != MlsEncrypted` to match the convention in
/// `GET /groups/:id/messages`, which rejects MLS-encrypted groups outright.
async fn ensure_named_group_listeners(state: Arc<AppState>, group_id: &str) {
    ensure_named_group_metadata_listener(Arc::clone(&state), group_id).await;
    let public_topic_key = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).and_then(|info| {
            if info.withdrawn
                || info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted
            {
                None
            } else {
                Some(info.stable_group_id().to_string())
            }
        })
    };
    if let Some(stable_id) = public_topic_key {
        spawn_public_message_listener(state, stable_id).await;
    }
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

    // Resolve policy preset (defaults to private_secure).
    let policy = match req.preset.as_deref() {
        Some(name) => match x0x::groups::GroupPolicyPreset::from_name(name) {
            Some(preset) => preset.to_policy(),
            None => {
                return bad_request("unknown preset");
            }
        },
        None => x0x::groups::GroupPolicy::default(),
    };

    // Create the legacy demo MLS group object (kept for the `/mls/groups/:id`
    // surface). `.clone()` because the real-TreeKEM routing below also needs
    // the raw group-id bytes.
    match x0x::mls::MlsGroup::new(group_id_bytes.clone(), agent_id).await {
        Ok(group) => {
            // Create group metadata with explicit policy.
            let mut info = x0x::groups::GroupInfo::with_policy(
                req.name,
                req.description,
                agent_id,
                group_id_hex.clone(),
                policy,
            );
            // Record the owner's ML-KEM-768 public key so the roster knows
            // where to seal future group-shared-secret envelopes.
            {
                use base64::Engine as _;
                let owner_hex = hex::encode(agent_id.as_bytes());
                let owner_kem_b64 = BASE64.encode(&state.agent_kem_keypair.public_bytes);
                info.set_member_kem_public_key(&owner_hex, owner_kem_b64);
            }

            // Set creator's display name if provided
            if let Some(dn) = req.display_name {
                info.set_display_name(&hex::encode(agent_id.as_bytes()), dn);
            }

            // ADR-0012 Phase 2: new PRIVATE (Hidden) MlsEncrypted groups are
            // secure-by-default real TreeKEM (FS/PCS), NOT the legacy GSS
            // shared-secret plane. Public encrypted presets (e.g.
            // `public_request_secure`, PublicDirectory) deliberately stay on the
            // GSS plane — their cross-daemon join-request review converges via
            // the D4 signed-commit path, which the single-committer TreeKEM
            // transport does not provide. This matches ADR-0012's scope ("all
            // new private groups secure-by-default TreeKEM"); gating on
            // MlsEncrypted alone was too broad and swept in public request-secure
            // groups, breaking their join-request convergence.
            // Build the live TreeKEM group (creator = sole leaf 0), persist its
            // snapshot at rest, then relabel `info` so no surface claims GSS for
            // it (drop the GSS shared secret, bind the TreeKEM epoch into the
            // signed state hash). If TreeKEM setup or persistence fails we fail
            // the request rather than store a group mislabelled as secure.
            if info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted
                && info.policy.discoverability == x0x::groups::GroupDiscoverability::Hidden
            {
                let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
                let tk = match x0x::mls::TreeKemMlsGroup::create(
                    group_id_bytes.clone(),
                    agent_id,
                    &seed,
                ) {
                    Ok(tk) => tk,
                    Err(e) => {
                        tracing::error!(group_id = %group_id_hex, "failed to create TreeKEM group: {e}");
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to create secure group: {e}"),
                        );
                    }
                };
                info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
                info.shared_secret = None;
                info.secret_epoch = tk.epoch();
                info.security_binding = Some(format!("treekem:epoch={}", tk.epoch()));
                info.recompute_state_hash();
                state
                    .treekem_groups
                    .write()
                    .await
                    .insert(group_id_hex.clone(), Arc::new(tokio::sync::Mutex::new(tk)));
            }

            // Store MLS group
            state
                .mls_groups
                .write()
                .await
                .insert(group_id_hex.clone(), group);
            save_mls_groups(&state).await;

            let chat_topic = info.general_chat_topic();

            // Store group info and persist to disk
            state
                .named_groups
                .write()
                .await
                .insert(group_id_hex.clone(), info.clone());
            if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&group_id_hex).cloned()
                };
                if let Some(group) = group {
                    let guard = group.lock().await;
                    if let Err(e) =
                        persist_treekem_and_named_groups_atomic(&state, &group_id_hex, &guard).await
                    {
                        tracing::error!(group_id = %group_id_hex, "failed to atomically persist TreeKEM group create: {e}");
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to persist secure group: {e}"),
                        );
                    }
                }
            } else {
                save_named_groups(&state).await;
            }
            ensure_named_group_listeners(Arc::clone(&state), &group_id_hex).await;

            // P0-1: If the group is discoverable, publish its card to the global
            // discovery topic so other daemons find it without manual import.
            //
            // The discovery-card fan-out is a best-effort gossip publish to
            // the global topic plus N tag/name/id shards. Each publish goes
            // through the gossip runtime, which can block tens of seconds
            // under sustained pubsub back-pressure (e.g. release-manifest
            // floods). Spawning the fan-out keeps `POST /groups` sub-second
            // even on a saturated daemon — local state is already committed
            // so the group is fully created from the caller's perspective.
            if info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden {
                match info.to_signed_group_card(state.agent.identity().agent_keypair()) {
                    Ok(Some(card)) => {
                        let stable_group_id = info.stable_group_id().to_string();
                        let mut cache = state.group_card_cache.write().await;
                        prune_expired_group_cards(&mut cache, now_millis_u64());
                        cache_group_card_if_newer(&mut cache, group_id_hex.clone(), card.clone());
                        cache_group_card_if_newer(&mut cache, stable_group_id, card);
                        enforce_group_card_cache_cap(&mut cache);
                        drop(cache);
                        let state_for_card = Arc::clone(&state);
                        let group_id_for_card = group_id_hex.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                            publish_group_card_to_discovery(
                                state_for_card.as_ref(),
                                &group_id_for_card,
                            )
                            .await;
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(group_id = %group_id_hex, "failed to sign initial group card: {e}");
                    }
                }
            }

            // Announce creation on the chat topic — fire-and-forget. The
            // response did not depend on this completing pre-fix either
            // (the result was already discarded with `let _ = ...`); moving
            // it off the request task keeps the handler unblocked when the
            // gossip publish path is slow.
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
            let state_for_chat = Arc::clone(&state);
            let chat_topic_for_chat = chat_topic.clone();
            let announcement_bytes = announcement.to_string().into_bytes();
            tokio::spawn(async move {
                tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                if let Err(e) = state_for_chat
                    .agent
                    .publish(&chat_topic_for_chat, announcement_bytes)
                    .await
                {
                    tracing::debug!(topic = %chat_topic_for_chat, "chat-create publish failed: {e}");
                }
            });

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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /groups — list all named groups.
async fn list_named_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let entries: Vec<serde_json::Value> = groups
        .values()
        .map(|info| {
            let member_count = named_group_member_values(info).len();
            serde_json::json!({
                "group_id": info.mls_group_id,
                "name": info.name,
                "description": info.description,
                "creator": hex::encode(info.creator.as_bytes()),
                "created_at": info.created_at,
                "member_count": member_count,
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
        return not_found("group not found");
    };
    let members = named_group_member_values(info);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": info.mls_group_id,
            "name": info.name,
            "description": info.description,
            "creator": hex::encode(info.creator.as_bytes()),
            "created_at": info.created_at,
            "updated_at": info.updated_at,
            "chat_topic": info.general_chat_topic(),
            "metadata_topic": info.metadata_topic,
            "policy": info.policy,
            "policy_revision": info.policy_revision,
            "roster_revision": info.roster_revision,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

/// GET /groups/:id/members — list local named-group members.
async fn get_named_group_members(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    let members = named_group_member_values(info);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

// ──────────────────────── Phase E: public messaging ────────────────────

/// Maximum number of public messages retained per group. Older entries
/// are dropped on insert (ring-buffer style).
const PUBLIC_MESSAGE_HISTORY_CAP: usize = 512;

/// Stable fleet-wide anti-entropy topic for SignedPublic messages.
///
/// Fresh per-group topics can have asymmetric PlumTree reachability during the
/// first seconds after a cross-region join. Publishing each public message to
/// this long-lived topic as well gives already-subscribed daemons a stable
/// fallback path while receivers still validate/cache only messages for groups
/// they know locally.
const GLOBAL_PUBLIC_MESSAGE_TOPIC: &str = "x0x.groups.public.v1";
const GROUP_PUBLIC_MESSAGE_DM_PREFIX: &[u8] = b"X0X-GROUP-PUBLIC-V1\n";
const KV_STORE_DELTA_DM_PREFIX: &[u8] = b"X0X-KV-DELTA-V1\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KvStoreDirectDelta {
    store_id: String,
    peer_id: saorsa_gossip_types::PeerId,
    delta: x0x::kv::KvStoreDelta,
}

/// Request body for `POST /groups/:id/send`.
#[derive(Debug, Deserialize)]
struct SendGroupMessageRequest {
    /// Message body (UTF-8). Required.
    body: String,
    /// Message kind — `"chat"` (default) or `"announcement"`.
    #[serde(default)]
    kind: Option<String>,
}

/// POST /groups/:id/send — publish a message to the group.
///
/// Branches on `policy.confidentiality`:
///
/// - `SignedPublic` — builds a signed `GroupPublicMessage`, publishes
///   to `x0x.groups.public.{group_id}`, and caches it locally.
///   Write-access is enforced at endpoint time (same rules as
///   `x0x::groups::validate_public_message` applies at ingest).
/// - `MlsEncrypted` — not supported on this endpoint yet; callers
///   should use `/groups/:id/secure/encrypt` (Phase D.2).
async fn send_group_public_message(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SendGroupMessageRequest>,
) -> impl IntoResponse {
    let kind = match req.kind.as_deref().unwrap_or("chat") {
        "chat" => x0x::groups::GroupPublicMessageKind::Chat,
        "announcement" => x0x::groups::GroupPublicMessageKind::Announcement,
        other => {
            return bad_request(format!(
                "unknown kind '{other}' (expected 'chat' or 'announcement')"
            ));
        }
    };

    if req.body.len() > x0x::groups::MAX_PUBLIC_MESSAGE_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body exceeds MAX_PUBLIC_MESSAGE_BYTES",
        );
    }

    let signing_kp = state.agent.identity().agent_keypair();
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Build + endpoint-side authz + sign under the write lock so
    // concurrent role changes can't race the check.
    let (msg, direct_recipients) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic {
            return bad_request("group is not SignedPublic — use /groups/:id/secure/encrypt");
        }
        if info.is_banned(&local_hex) {
            return forbidden("you are banned");
        }
        // Endpoint-side write-access enforcement. Mirror the ingest
        // validator so we reject locally rather than trust receivers.
        let caller_role = info.caller_role(&local_hex);
        match info.policy.write_access {
            x0x::groups::GroupWriteAccess::MembersOnly => {
                if caller_role.is_none() {
                    return forbidden("members-only write policy");
                }
            }
            x0x::groups::GroupWriteAccess::ModeratedPublic => { /* any non-banned */ }
            x0x::groups::GroupWriteAccess::AdminOnly => {
                let ok = caller_role
                    .map(|r| r.at_least(x0x::groups::GroupRole::Admin))
                    .unwrap_or(false);
                if !ok {
                    return forbidden("admin-only write policy");
                }
            }
        }
        let direct_recipients = info
            .active_members()
            .filter(|member| !member.agent_id.eq_ignore_ascii_case(&local_hex))
            .map(|member| member.agent_id.clone())
            .collect::<Vec<_>>();

        match x0x::groups::GroupPublicMessage::sign(
            info.stable_group_id().to_string(),
            info.state_hash.clone(),
            info.state_revision,
            signing_kp,
            None,
            kind,
            req.body,
            now_ms,
        ) {
            Ok(m) => (m, direct_recipients),
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("sign failed: {e}"),
                );
            }
        }
    };

    // Subscribe locally before publishing so the sender's pubsub runtime has
    // the topic fully initialised before the first outbound message. This makes
    // reverse-direction cross-daemon receive far more reliable on fresh topics.
    spawn_public_message_listener(Arc::clone(&state), msg.group_id.clone()).await;

    let topic = x0x::groups::public_topic_for(&msg.group_id);
    let bytes = match serde_json::to_vec(&msg) {
        Ok(b) => b,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("serialize failed: {e}"),
            );
        }
    };
    if let Err(e) = state.agent.publish(&topic, bytes.clone()).await {
        tracing::warn!(topic = %LogHexId::topic(&topic), "E: public-send publish failed: {e}");
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("publish failed: {e}"),
        );
    }
    if let Err(e) = state
        .agent
        .publish(GLOBAL_PUBLIC_MESSAGE_TOPIC, bytes)
        .await
    {
        tracing::warn!(
            topic = GLOBAL_PUBLIC_MESSAGE_TOPIC,
            group_id = %msg.group_id,
            "E: global public-send fallback publish failed: {e}"
        );
    }
    // Publish succeeded, so cache locally. The listener was started before the
    // publish above to avoid first-message topic races.
    cache_public_message(&state, msg.clone()).await;
    spawn_group_public_message_delivery_to_active_members(&state, direct_recipients, &msg);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": msg.group_id,
            "topic": topic,
            "fallback_topic": GLOBAL_PUBLIC_MESSAGE_TOPIC,
            "timestamp": msg.timestamp,
        })),
    )
}

/// GET /groups/:id/messages — retrieve cached public messages.
///
/// If `policy.read_access == Public`, any caller with a valid API
/// token receives the history. If `MembersOnly`, only active members
/// receive it. For `MlsEncrypted` groups, returns 400 — encrypted
/// history belongs in a different surface.
async fn get_group_public_messages(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Resolve the stable_group_id — the public-message cache and topic
    // are keyed on it, while the URL `:id` is typically the
    // mls_group_id for a locally-owned group.
    let (read_access, confidentiality, is_member, stable_id) = {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(&id) {
            if let Some(resp) = reject_withdrawn_group(info) {
                return resp;
            }
            (
                info.policy.read_access,
                info.policy.confidentiality,
                info.has_active_member(&local_hex),
                info.stable_group_id().to_string(),
            )
        } else {
            // Unknown locally — fall through to cache lookup by the
            // supplied id; this supports non-members reading a
            // discovered Public group whose mls_group_id == stable.
            drop(groups);
            (
                x0x::groups::GroupReadAccess::Public,
                x0x::groups::GroupConfidentiality::SignedPublic,
                false,
                id.clone(),
            )
        }
    };
    if confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted {
        return bad_request("MlsEncrypted groups do not publish a plaintext message history");
    }
    if read_access == x0x::groups::GroupReadAccess::MembersOnly && !is_member {
        return forbidden("members-only read policy");
    }

    // Ensure the listener is live on the stable-id topic.
    spawn_public_message_listener(Arc::clone(&state), stable_id.clone()).await;

    let msgs = state
        .public_messages
        .read()
        .await
        .get(&stable_id)
        .cloned()
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "messages": msgs })),
    )
}

/// Append a validated message to the per-group ring buffer (capped).
async fn cache_public_message(state: &AppState, msg: x0x::groups::GroupPublicMessage) {
    let mut all = state.public_messages.write().await;
    let slot = all.entry(msg.group_id.clone()).or_default();
    // Deduplicate by the stable message identity (`signature`) rather
    // than a lossy (author,timestamp,body) tuple so legitimate repeated
    // bodies sent in the same millisecond are still preserved.
    let dup = slot.iter().any(|m| m.signature == msg.signature);
    if !dup {
        slot.push(msg);
        while slot.len() > PUBLIC_MESSAGE_HISTORY_CAP {
            slot.remove(0);
        }
    }
}

fn encode_group_public_message_direct_payload(
    msg: &x0x::groups::GroupPublicMessage,
) -> serde_json::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let mut payload = Vec::with_capacity(GROUP_PUBLIC_MESSAGE_DM_PREFIX.len() + json.len());
    payload.extend_from_slice(GROUP_PUBLIC_MESSAGE_DM_PREFIX);
    payload.extend_from_slice(&json);
    Ok(payload)
}

fn group_public_message_direct_delivery_config() -> x0x::dm::DmSendConfig {
    let mut config = named_group_direct_delivery_config();
    config.require_gossip = true;
    config.require_gossip_ack = true;
    config
}

fn spawn_group_public_message_delivery(
    state: &AppState,
    recipient_hex: &str,
    msg: &x0x::groups::GroupPublicMessage,
    delay: Option<Duration>,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                recipient = %LogHexId::agent(&recipient_hex),
                "cannot direct-deliver public group message: invalid recipient id: {e}"
            );
            return;
        }
    };
    let payload = match encode_group_public_message_direct_payload(msg) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!("failed to serialize public group message for direct delivery: {e}");
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let recipient_label = recipient_hex.to_string();
    let group_id = msg.group_id.clone();
    tokio::spawn(async move {
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if let Err(e) = agent
            .send_direct_with_config(
                &recipient,
                payload,
                group_public_message_direct_delivery_config(),
            )
            .await
        {
            tracing::warn!(
                group_id = %LogHexId::group(&group_id),
                recipient = %LogHexId::agent(&recipient_label),
                "failed to direct-deliver public group message: {e}"
            );
        }
    });
}

fn spawn_group_public_message_delivery_to_active_members(
    state: &AppState,
    recipients: Vec<String>,
    msg: &x0x::groups::GroupPublicMessage,
) {
    for recipient in recipients {
        spawn_group_public_message_delivery(state, &recipient, msg, None);
        spawn_group_public_message_delivery(
            state,
            &recipient,
            msg,
            Some(GROUP_BACKGROUND_PUBLISH_DELAY),
        );
    }
}

async fn ingest_public_message(
    state: &AppState,
    msg: x0x::groups::GroupPublicMessage,
    group_id_for_log: &str,
) {
    // Validate against current group view at apply-time.
    let message_group_id = msg.group_id.clone();
    let snapshot = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id_for_log)
            .or_else(|| {
                groups.get(&message_group_id).or_else(|| {
                    groups
                        .values()
                        .find(|info| info.stable_group_id() == message_group_id.as_str())
                })
            })
            .map(|info| {
                (
                    info.policy.clone(),
                    info.members_v2.clone(),
                    info.stable_group_id().to_string(),
                    info.withdrawn,
                )
            })
    };
    let Some((policy, members, stable_id, withdrawn)) = snapshot else {
        // Unknown group — count under the stable id we were given as the
        // logging key. Useful for spotting messages that arrived before the
        // local daemon learned about the group.
        state.groups_diagnostics.record_other_drop(group_id_for_log);
        return;
    };
    if withdrawn {
        state.groups_diagnostics.record_other_drop(&stable_id);
        tracing::debug!(group_id = %group_id_for_log, "E: dropped public message for withdrawn group");
        return;
    }
    let ctx = x0x::groups::PublicIngestContext {
        group_id: &stable_id,
        policy: &policy,
        members_v2: &members,
    };
    match x0x::groups::validate_public_message(&ctx, &msg) {
        Ok(()) => {
            state
                .groups_diagnostics
                .record_message_received(&stable_id, now_millis_u64());
            cache_public_message(state, msg).await;
        }
        Err(e) => {
            // Map ingest errors to diagnostics buckets so /diagnostics/groups
            // reflects the drop fingerprint for the operator.
            match &e {
                x0x::groups::PublicMessageIngestError::AuthorBanned => {
                    state.groups_diagnostics.record_author_banned(&stable_id)
                }
                x0x::groups::PublicMessageIngestError::WritePolicyViolation { .. } => state
                    .groups_diagnostics
                    .record_write_policy_violation(&stable_id),
                x0x::groups::PublicMessageIngestError::InvalidSignature(_) => {
                    state.groups_diagnostics.record_signature_failed(&stable_id)
                }
                _ => state.groups_diagnostics.record_other_drop(&stable_id),
            }
            tracing::warn!(
                group_id = %group_id_for_log,
                author = %msg.author_agent_id,
                "E: dropped public message: {e}"
            );
        }
    }
}

async fn spawn_global_public_message_listener(
    state: Arc<AppState>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    vec![tokio::spawn(async move {
        let mut sub = match state.agent.subscribe(GLOBAL_PUBLIC_MESSAGE_TOPIC).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    topic = GLOBAL_PUBLIC_MESSAGE_TOPIC,
                    "E: failed to subscribe to global public-message fallback: {e}"
                );
                return;
            }
        };
        tracing::info!(
            topic = GLOBAL_PUBLIC_MESSAGE_TOPIC,
            "E: global public-message fallback listener subscribed"
        );
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe = sub.recv() => {
                    let Some(gossip_msg) = maybe else { break; };
                    let msg: x0x::groups::GroupPublicMessage =
                        match serde_json::from_slice(&gossip_msg.payload) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::debug!("E: dropped malformed global public msg: {e}");
                                // Without a parsed payload we don't know the
                                // group id — bucket as a generic "other"
                                // drop on a sentinel key so we never panic
                                // here. The condition is rare and visible
                                // via the daemon's own debug log too.
                                state.groups_diagnostics.record_decode_failed(
                                    "__global_public__",
                                );
                                continue;
                            }
                        };
                    let group_id_for_log = msg.group_id.clone();
                    ingest_public_message(&state, msg, &group_id_for_log).await;
                }
            }
        }
    })]
}

/// Spawn a listener on `x0x.groups.public.{group_id}`. Idempotent — a
/// duplicate call for the same group_id is a no-op.
///
/// The pubsub subscribe is completed before returning so the first public
/// message published after group creation/join cannot race ahead of the local
/// listener. The spawned task owns only the receive loop.
async fn spawn_public_message_listener(state: Arc<AppState>, group_id: String) {
    {
        let groups = state.named_groups.read().await;
        if groups
            .get(&group_id)
            .or_else(|| {
                groups
                    .values()
                    .find(|info| info.stable_group_id() == group_id.as_str())
            })
            .is_some_and(|info| info.withdrawn)
        {
            return;
        }
    }
    {
        let tasks = state.public_message_tasks.read().await;
        if tasks.contains_key(&group_id) {
            return;
        }
    }
    let topic = x0x::groups::public_topic_for(&group_id);
    let mut sub = match state.agent.subscribe(&topic).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(topic = %LogHexId::topic(&topic), "E: failed to subscribe to public chat: {e}");
            return;
        }
    };
    let state_for_listener = Arc::clone(&state);
    let group_id_for_listener = group_id.clone();
    let topic_for_log = topic.clone();
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let handle = tokio::spawn(async move {
        tracing::info!(topic = %topic_for_log, "E: public-message listener subscribed");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe = sub.recv() => {
                    let Some(gossip_msg) = maybe else { break; };
                    let msg: x0x::groups::GroupPublicMessage =
                        match serde_json::from_slice(&gossip_msg.payload) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::debug!("E: dropped malformed public msg: {e}");
                                state_for_listener
                                    .groups_diagnostics
                                    .record_decode_failed(&group_id_for_listener);
                                continue;
                            }
                        };
                    ingest_public_message(
                        &state_for_listener,
                        msg,
                        &group_id_for_listener,
                    ).await;
                }
            }
        }
    });
    state
        .public_message_tasks
        .write()
        .await
        .insert(group_id, handle);
}

/// POST /groups/:id/invite — generate an invite link (body optional).
async fn create_group_invite(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let req: CreateInviteRequest = match parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return resp.into_response(),
    };
    // Serialize this group-state mutation against concurrent membership applies
    // and the other API mutators (see `AppState::group_membership_locks`): every
    // read-modify-write of one group's `GroupInfo` must hold this lock, or a
    // stale-clone apply storing afterward overwrites the invite we record here.
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    let (link, mls_group_id, group_name, expires_at) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            )
                .into_response();
        };

        let agent_id = state.agent.agent_id();
        let inviter_hex = hex::encode(agent_id.as_bytes());
        if let Err(e) = require_admin_or_above(info, &inviter_hex) {
            return e.into_response();
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp.into_response();
        }
        let mut invite = x0x::groups::invite::SignedInvite::new(
            info.mls_group_id.clone(),
            info.name.clone(),
            &agent_id,
            req.expiry_secs,
        );
        populate_invite_base_state_from_group_info(&mut invite, info);

        // Track this one-time secret on the inviter so a future
        // MemberJoined request carrying it can be authenticated, role-capped,
        // expiry-checked, and consumed locally before the inviter publishes an
        // authority-signed MemberAdded commit.
        info.record_issued_invite(
            invite.invite_secret.clone(),
            invite.created_at,
            invite.expires_at,
            x0x::groups::GroupRole::Member,
        );

        let link = invite.to_link();
        let mls_group_id = info.mls_group_id.clone();
        let group_name = info.name.clone();
        let expires_at = invite.expires_at;
        (link, mls_group_id, group_name, expires_at)
    };
    save_named_groups(&state).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "invite_link": link,
            "group_id": mls_group_id,
            "group_name": group_name,
            "expires_at": expires_at,
        })),
    )
        .into_response()
}

fn invite_join_group_info(
    invite: &x0x::groups::invite::SignedInvite,
    creator: AgentId,
    creator_hex: &str,
    group_id_hex: &str,
    joiner_hex: &str,
    display_name: Option<String>,
    treekem_key_package_b64: Option<String>,
) -> x0x::groups::GroupInfo {
    let invite_is_treekem = invite.secure_plane == Some(x0x::mls::SecureGroupPlane::TreeKem);
    let has_authority_base_state = invite.base_state_hash.is_some();

    // Create group info from invite. D.4 requires the joiner to seed
    // the same stable group identity + policy snapshot as the authority
    // so later signed state commits can chain from the same base.
    let mut info = x0x::groups::GroupInfo::with_policy(
        invite.group_name.clone(),
        invite.group_description.clone().unwrap_or_default(),
        creator,
        group_id_hex.to_string(),
        invite.policy.clone().unwrap_or_default(),
    );
    if let Some(group_created_at) = invite.group_created_at {
        info.created_at = group_created_at;
    }
    if let Some(stable_group_id) = invite.stable_group_id.clone() {
        info.genesis = Some(x0x::groups::GroupGenesis::with_existing_id(
            stable_group_id,
            creator_hex.to_string(),
            info.created_at,
            invite
                .genesis_creation_nonce
                .clone()
                .unwrap_or_else(|| hex::encode(blake3::hash(group_id_hex.as_bytes()).as_bytes())),
        ));
    }
    if let Some(secure_plane) = invite.secure_plane {
        info.secure_plane = secure_plane;
    }
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        info.shared_secret = None;
    }
    if let Some(base_secret_epoch) = invite.base_secret_epoch {
        info.secret_epoch = base_secret_epoch;
    }
    if let Some(base_security_binding) = invite.base_security_binding.clone() {
        info.security_binding = Some(base_security_binding);
    } else if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        info.security_binding = Some(format!("treekem:epoch={}", info.secret_epoch));
    }
    if let Some(base_revision) = invite.base_state_revision {
        info.state_revision = base_revision;
        info.roster_revision = base_revision;
    }
    if let Some(base_members) = invite.base_members_v2.clone() {
        info.members_v2 = base_members;
    }
    if let Some(base_state_hash) = invite.base_state_hash.clone() {
        info.state_hash = base_state_hash;
        info.prev_state_hash = invite.base_prev_state_hash.clone();
    }

    if !invite_is_treekem && has_authority_base_state {
        // Modern non-TreeKEM invite stubs keep the committed role/state roster
        // exactly at the invite authority frontier. If that frontier already
        // contains the local joiner (for example single-daemon self-rejoin via
        // an invite minted before leaving), update only non-committed display /
        // key-package metadata for the local REST view. Role/state stay as the
        // authority snapshot recorded them, and `compute_roster_root` ignores
        // these metadata fields, so the base `state_hash` remains coherent.
        if let Some(member) = info.members_v2.get_mut(joiner_hex) {
            if member.is_active() || member.state == x0x::groups::GroupMemberState::Pending {
                if let Some(display_name) = display_name.clone() {
                    member.display_name = Some(display_name);
                }
                if let Some(kp_b64) = treekem_key_package_b64.clone() {
                    member.treekem_key_package_b64 = Some(kp_b64);
                }
                member.updated_at = now_millis_u64();
            }
        }
    }

    if !has_authority_base_state {
        // The REST invite-join path rejects missing base roster snapshots before
        // reaching this helper (`creator_agent_id_from_base_state`). This
        // defensive recompute exists only for direct/helper construction and
        // deliberately does not derive creator/member authority from unsigned
        // `invite.inviter` metadata.
        info.recompute_state_hash();
    }
    info
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
            return bad_request(format!("invalid invite: {e}"));
        }
    };

    // Check expiry
    if invite.is_expired() {
        return bad_request("invite has expired");
    }
    let invite_is_treekem = invite.secure_plane == Some(x0x::mls::SecureGroupPlane::TreeKem);

    let agent_id = state.agent.agent_id();
    let group_id_hex = invite.group_id.clone();
    let invite_stable_group_id = invite.stable_group_id.as_deref().unwrap_or(&group_id_hex);
    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, &group_id_hex)
            || has_withdrawn_group_record(&groups, invite_stable_group_id)
        {
            return api_error(StatusCode::CONFLICT, "group is withdrawn");
        }
    }
    let inviter = match parse_agent_id_hex(&invite.inviter) {
        Ok(id) => id,
        Err(e) => {
            return bad_request(format!("invalid inviter: {e}"));
        }
    };
    let creator_hex = match invite.creator_agent_id_from_base_state() {
        Ok(creator_hex) => creator_hex,
        Err(e) => {
            return bad_request(e);
        }
    };
    let creator = match parse_agent_id_hex(&creator_hex) {
        Ok(id) => id,
        Err(e) => {
            return bad_request(format!("invalid base-state creator: {e}"));
        }
    };

    // Create the MLS group locally (in a real flow, the inviter would send
    // a Welcome message; for now, we create a local group and the inviter
    // will add us when they see our presence on the group topic)
    let group_id_bytes = match hex::decode(&group_id_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return bad_request(format!("invalid group_id hex: {e}"));
        }
    };

    let treekem_key_package_b64 = if invite_is_treekem {
        use base64::Engine as _;
        let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let prepared = match x0x::mls::TreeKemMlsGroup::prepare_member(agent_id, &seed) {
            Ok(prepared) => prepared,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to prepare TreeKEM KeyPackage: {e}"),
                );
            }
        };
        Some(BASE64.encode(prepared.key_package_bytes()))
    } else {
        None
    };

    match x0x::mls::MlsGroup::new(group_id_bytes, agent_id).await {
        Ok(group) => {
            if !invite_is_treekem {
                // Store legacy demo MLS group. Real TreeKEM groups are stored
                // only after the authority's Welcome is accepted.
                state
                    .mls_groups
                    .write()
                    .await
                    .insert(group_id_hex.clone(), group);
                save_mls_groups(&state).await;
            }

            let joiner_hex = hex::encode(agent_id.as_bytes());
            let info = invite_join_group_info(
                &invite,
                creator,
                &creator_hex,
                &group_id_hex,
                &joiner_hex,
                req.display_name.clone(),
                treekem_key_package_b64.clone(),
            );

            let chat_topic = info.general_chat_topic();

            state
                .named_groups
                .write()
                .await
                .insert(group_id_hex.clone(), info.clone());
            save_named_groups(&state).await;
            ensure_named_group_listeners(Arc::clone(&state), &group_id_hex).await;

            // Publish a signed MemberJoined request on the metadata topic so
            // the original inviter can validate the one-time invite and publish
            // the authority-signed `MemberAdded` commit. Current members apply
            // that commit, not this request, so the committed roster/state_hash
            // advance together; see docs/design/groups-join-roster-propagation.md.
            //
            // Failure here is logged but does not fail the local stub creation;
            // the legacy chat-topic announcement below remains as a
            // defence-in-depth signal.
            let signing_kp = state.agent.identity().agent_keypair();
            let now_ms = now_millis_u64();
            let member_pubkey_b64 = {
                use base64::Engine as _;
                BASE64.encode(signing_kp.public_key().as_bytes())
            };
            let stable_id_for_event = info.stable_group_id().to_string();
            if invite_is_treekem {
                record_expected_join_result_inviter(
                    state.as_ref(),
                    join_result_key(&stable_id_for_event, &joiner_hex),
                    invite.inviter.clone(),
                );
            }
            let display_name_for_event = req.display_name.clone();
            let canonical = canonical_member_joined_bytes(
                &info.mls_group_id,
                Some(&stable_id_for_event),
                &joiner_hex,
                &member_pubkey_b64,
                x0x::groups::GroupRole::Member,
                display_name_for_event.as_deref(),
                &invite.inviter,
                &invite.invite_secret,
                now_ms,
                treekem_key_package_b64.as_deref(),
            );
            match ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                signing_kp.secret_key(),
                &canonical,
            ) {
                Ok(sig) => {
                    use base64::Engine as _;
                    let signature_b64 = BASE64.encode(sig.as_bytes());
                    let event = NamedGroupMetadataEvent::MemberJoined {
                        group_id: info.mls_group_id.clone(),
                        stable_group_id: Some(stable_id_for_event),
                        member_agent_id: joiner_hex.clone(),
                        member_public_key_b64: member_pubkey_b64,
                        role: x0x::groups::GroupRole::Member,
                        display_name: display_name_for_event,
                        inviter_agent_id: invite.inviter.clone(),
                        invite_secret: invite.invite_secret.clone(),
                        ts_ms: now_ms,
                        treekem_key_package_b64: treekem_key_package_b64.clone(),
                        signature_b64,
                    };
                    tracing::info!(
                        group_id = %group_id_hex,
                        topic = %info.metadata_topic,
                        member = %joiner_hex,
                        inviter = %invite.inviter,
                        "MemberJoined: publishing joiner-authored membership event to metadata topic"
                    );
                    // Publish twice: once immediately so the inviter gets it
                    // as soon as the metadata mesh covers them, then again
                    // after `GROUP_BACKGROUND_PUBLISH_DELAY` so members
                    // whose Plumtree links formed late still pick it up.
                    // The applier is idempotent (re-applying the same
                    // event for an already-active member is a no-op), so
                    // double-publish is safe.
                    publish_named_group_metadata_event(&state, &info.metadata_topic, &event).await;
                    // TreeKEM membership is order-sensitive: gossip remains the
                    // broadcast path, but the join trigger must reach the inviter
                    // reliably so they can produce the authoritative add commit.
                    spawn_named_group_event_delivery(&state, &invite.inviter, &event);
                    spawn_named_group_event_delivery_after(
                        &state,
                        &invite.inviter,
                        &event,
                        GROUP_BACKGROUND_PUBLISH_DELAY,
                    );
                    let state_for_replay = Arc::clone(&state);
                    let topic_for_replay = info.metadata_topic.clone();
                    let inviter_for_replay = invite.inviter.clone();
                    let event_for_replay = event;
                    tokio::spawn(async move {
                        tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                        publish_named_group_metadata_event(
                            &state_for_replay,
                            &topic_for_replay,
                            &event_for_replay,
                        )
                        .await;
                        spawn_named_group_event_delivery(
                            &state_for_replay,
                            &inviter_for_replay,
                            &event_for_replay,
                        );
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        group_id = %group_id_hex,
                        "MemberJoined: failed to sign join announcement: {e:?}"
                    );
                }
            }
            if invite_is_treekem {
                let state_for_poll = Arc::clone(&state);
                let group_id_for_poll = group_id_hex.clone();
                let event_group_id_for_poll = info.stable_group_id().to_string();
                let member_for_poll = joiner_hex.clone();
                tokio::spawn(async move {
                    poll_join_result_until_treekem_ready(
                        state_for_poll,
                        group_id_for_poll,
                        event_group_id_for_poll,
                        inviter,
                        member_for_poll,
                    )
                    .await;
                });
            }

            // Announce join on the chat topic so the inviter sees us —
            // fire-and-forget. The result was already discarded pre-fix,
            // and spawning keeps the handler responsive when the gossip
            // publish path is slow under back-pressure.
            let agent_hex = joiner_hex;
            let display = req
                .display_name
                .clone()
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
            let state_for_join = Arc::clone(&state);
            let chat_topic_for_join = chat_topic.clone();
            let announcement_bytes = announcement.to_string().into_bytes();
            tokio::spawn(async move {
                tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                if let Err(e) = state_for_join
                    .agent
                    .publish(&chat_topic_for_join, announcement_bytes)
                    .await
                {
                    tracing::debug!(topic = %chat_topic_for_join, "join announcement publish failed: {e}");
                }
            });

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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    let agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    info.set_display_name(&agent_hex, req.name.clone());
    drop(groups); // release write lock before saving
    save_named_groups(&state).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "display_name": req.name })),
    )
}

/// POST /groups/:id/members — add a member to the named-group roster.
async fn add_named_group_member(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddNamedGroupMemberRequest>,
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
    let local_agent = state.agent.agent_id();
    let actor_hex = hex::encode(local_agent.as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;

    let (metadata_topic, event, members, epoch) = {
        let mut named_groups = state.named_groups.write().await;
        let Some(info) = named_groups.get(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &actor_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
            drop(named_groups);
            return add_treekem_named_group_member(state, id, agent_id, req).await;
        }

        let agent_hex = hex::encode(agent_id.as_bytes());
        if info.has_member(&agent_hex) {
            return api_error(StatusCode::CONFLICT, "member already present");
        }
        let mut next = info.clone();
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            agent_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(actor_hex.clone()),
            req.display_name.clone(),
        );
        if let Some(display_name) = req.display_name.clone() {
            next.set_display_name(&agent_hex, display_name);
        }
        let revision = next.roster_revision;
        let commit = match next.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = next.metadata_topic.clone();
        let event_group_id = next.stable_group_id().to_string();
        let members = named_group_member_values(&next);
        named_groups.insert(id.clone(), next);
        drop(named_groups);

        let mut epoch = None;
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if !group.is_member(&agent_id) {
                match group.add_member(agent_id).await {
                    Ok(_) => epoch = Some(group.current_epoch()),
                    Err(e) => {
                        tracing::warn!("named-group add member MLS update failed: {e}");
                    }
                }
            } else {
                epoch = Some(group.current_epoch());
            }
        }
        drop(mls_groups);
        save_named_groups(&state).await;
        save_mls_groups(&state).await;
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: event_group_id,
            revision,
            actor: actor_hex,
            agent_id: agent_hex,
            display_name: req.display_name,
            treekem_commit_b64: None,
            treekem_welcome_b64: None,
            welcome_ref: None,
            treekem_epoch: None,
            commit: Some(commit),
        };
        (metadata_topic, event, members, epoch)
    };

    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "epoch": epoch,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

async fn add_treekem_named_group_member(
    state: Arc<AppState>,
    id: String,
    agent_id: AgentId,
    req: AddNamedGroupMemberRequest,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let local_agent = state.agent.agent_id();
    let actor_hex = hex::encode(local_agent.as_bytes());
    let agent_hex = hex::encode(agent_id.as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let Some(kp_b64) = req.treekem_key_package_b64.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "TreeKEM direct add requires treekem_key_package_b64 from the target"
            })),
        );
    };
    let kp_bytes = match base64::engine::general_purpose::STANDARD.decode(&kp_b64) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "treekem_key_package_b64 is not valid base64"
                })),
            );
        }
    };

    let (mut next, metadata_topic, event_group_id) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Err(e) = require_admin_or_above(info, &actor_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.has_member(&agent_hex) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "ok": false, "error": "member already present" })),
            );
        }
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
        )
    };

    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return (
            StatusCode::FAILED_DEPENDENCY,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM group not loaded — restart or re-share required" }),
            ),
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.add_member(
        agent_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(actor_hex.clone()),
        req.display_name.clone(),
    );
    if let Some(display_name) = req.display_name.clone() {
        next.set_display_name(&agent_hex, display_name);
    }
    next.set_member_treekem_key_package(&agent_hex, kp_b64);
    next.secret_epoch = treekem_epoch;
    next.security_binding = Some(format!("treekem:epoch={treekem_epoch}"));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let out = match guard.add_member(agent_id, &kp_bytes) {
        Ok(out) => out,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("TreeKEM add_member failed: {e}") }),
                ),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM epoch did not advance as expected" }),
            ),
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after direct add: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "failed to persist secure group state" }),
            ),
        );
    }
    drop(guard);

    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;

    let welcome_ref = stage_treekem_welcome(&state, &event_group_id, &agent_hex, out.welcome).await;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: event_group_id,
        revision,
        actor: actor_hex,
        agent_id: agent_hex.clone(),
        display_name: req.display_name,
        treekem_commit_b64: Some(base64::engine::general_purpose::STANDARD.encode(out.commit)),
        treekem_welcome_b64: None,
        welcome_ref: Some(welcome_ref),
        treekem_epoch: Some(treekem_epoch),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&agent_hex),
    );
    maybe_publish_group_card_after_state_change(&state, &id).await;

    let members = named_group_member_values(&next);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "epoch": treekem_epoch,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

/// DELETE /groups/:id/members/:agent_id — remove a member from the named-group roster.
async fn remove_named_group_member(
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
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(&id) {
            if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                drop(groups);
                return remove_treekem_named_group_member(state, id, agent_id_hex, local_agent_hex)
                    .await;
            }
        }
    }
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (metadata_topic, event, members, epoch) = {
        let mut named_groups = state.named_groups.write().await;
        let Some(info) = named_groups.get(&id) else {
            return not_found("group not found");
        };

        if let Err(e) = require_admin_or_above(info, &local_agent_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if !info.has_member(&agent_id_hex) {
            return not_found("member not found");
        }
        // ADR-0016 R2: friendly pre-check before any mutation/side effect.
        if let Some(resp) = last_admin_precheck(info, |g| g.remove_member(&agent_id_hex, None)) {
            return resp;
        }

        let mut next = info.clone();
        next.roster_revision = next.roster_revision.saturating_add(1);
        let revision = next.roster_revision;
        next.remove_member(&agent_id_hex, Some(local_agent_hex.clone()));
        let commit = match next.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = next.metadata_topic.clone();
        let event_group_id = next.stable_group_id().to_string();
        let members = named_group_member_values(&next);
        named_groups.insert(id.clone(), next);
        drop(named_groups);

        let mut epoch = None;
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if group.is_member(&agent_id) {
                match group.remove_member(agent_id).await {
                    Ok(_) => epoch = Some(group.current_epoch()),
                    Err(e) => tracing::warn!("named-group remove member MLS update failed: {e}"),
                }
            } else {
                epoch = Some(group.current_epoch());
            }
        }
        drop(mls_groups);
        save_named_groups(&state).await;
        save_mls_groups(&state).await;
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: event_group_id,
            revision,
            actor: local_agent_hex,
            agent_id: agent_id_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(commit),
        };
        (metadata_topic, event, members, epoch)
    };

    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "removed_member": agent_id_hex,
            "epoch": epoch,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeKemLeaveDisposition {
    ActiveMember,
    LocalOnlyDrop,
}

fn treekem_leave_disposition(
    info: &x0x::groups::GroupInfo,
    local_agent_hex: &str,
) -> TreeKemLeaveDisposition {
    if info.has_active_member(local_agent_hex) {
        TreeKemLeaveDisposition::ActiveMember
    } else {
        TreeKemLeaveDisposition::LocalOnlyDrop
    }
}

fn treekem_persistence_file_name_for_drop(group_id: &str, extension: &str) -> Option<String> {
    if group_id.is_empty()
        || !group_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(format!("{group_id}.{extension}"))
}

fn treekem_snapshot_file_name_for_drop(group_id: &str) -> Option<String> {
    treekem_persistence_file_name_for_drop(group_id, "snap")
}

fn treekem_journal_file_name_for_drop(group_id: &str) -> Option<String> {
    treekem_persistence_file_name_for_drop(group_id, "journal")
}

fn treekem_snapshot_path_for_drop_in_dir(
    treekem_dir: &FsPath,
    group_id: &str,
) -> Option<std::path::PathBuf> {
    treekem_snapshot_file_name_for_drop(group_id).map(|name| treekem_dir.join(name))
}

fn treekem_journal_path_for_drop_in_dir(
    treekem_dir: &FsPath,
    group_id: &str,
) -> Option<std::path::PathBuf> {
    treekem_journal_file_name_for_drop(group_id).map(|name| treekem_dir.join(name))
}

fn treekem_snapshot_path_for_drop(state: &AppState, group_id: &str) -> Option<std::path::PathBuf> {
    treekem_snapshot_path_for_drop_in_dir(&state.treekem_dir, group_id)
}

fn treekem_journal_path_for_drop(state: &AppState, group_id: &str) -> Option<std::path::PathBuf> {
    treekem_journal_path_for_drop_in_dir(&state.treekem_dir, group_id)
}

async fn remove_treekem_persistence_file(
    path: &FsPath,
    group_id: &str,
    reason: &str,
    file_kind: &str,
) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(group_id = %LogHexId::group(group_id), reason = %reason, file_kind, "failed to remove TreeKEM persistence file while dropping local group state: {e}");
        }
    }
}

async fn remove_treekem_persistence_for_group_id_in_dir(
    treekem_dir: &FsPath,
    group_id: &str,
    reason: &str,
) {
    let Some(treekem_snapshot) = treekem_snapshot_path_for_drop_in_dir(treekem_dir, group_id)
    else {
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            reason = %reason,
            "skipping unsafe TreeKEM persistence id while dropping local group state"
        );
        return;
    };
    let Some(treekem_journal) = treekem_journal_path_for_drop_in_dir(treekem_dir, group_id) else {
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            reason = %reason,
            "skipping unsafe TreeKEM persistence id while dropping local group state"
        );
        return;
    };
    remove_treekem_persistence_file(&treekem_snapshot, group_id, reason, "snapshot").await;
    remove_treekem_persistence_file(&treekem_journal, group_id, reason, "journal").await;
}

async fn remove_treekem_persistence_for_group_id(state: &AppState, group_id: &str, reason: &str) {
    remove_treekem_persistence_for_group_id_in_dir(&state.treekem_dir, group_id, reason).await;
}

fn collect_same_stable_group_aliases(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    id: &str,
    stable_group_id: Option<&str>,
) -> HashSet<String> {
    let mut stable_ids = HashSet::new();
    if let Some(stable_group_id) = stable_group_id.filter(|stable| !stable.is_empty()) {
        stable_ids.insert(stable_group_id.to_string());
    }
    if let Some(info) = groups.get(id) {
        stable_ids.insert(info.stable_group_id().to_string());
    }
    for info in groups.values() {
        let matches_requested_id = info.stable_group_id() == id || info.mls_group_id == id;
        let matches_requested_stable = stable_group_id
            .is_some_and(|stable| info.stable_group_id() == stable || info.mls_group_id == stable);
        if matches_requested_id || matches_requested_stable {
            stable_ids.insert(info.stable_group_id().to_string());
        }
    }

    let mut aliases = HashSet::new();
    aliases.insert(id.to_string());
    if let Some(stable_group_id) = stable_group_id.filter(|stable| !stable.is_empty()) {
        aliases.insert(stable_group_id.to_string());
    }
    for (key, info) in groups {
        if stable_ids.contains(info.stable_group_id()) {
            aliases.insert(key.clone());
            aliases.insert(info.mls_group_id.clone());
            aliases.insert(info.stable_group_id().to_string());
        }
    }
    aliases
}

fn group_id_matches_any_alias(candidate: &str, aliases: &HashSet<String>) -> bool {
    aliases.contains(candidate)
}

fn join_result_key_matches_any_group_alias(key: &str, aliases: &HashSet<String>) -> bool {
    key.split_once(':')
        .map(|(group_id, _)| group_id_matches_any_alias(group_id, aliases))
        .unwrap_or(false)
}

// Named-group terminality helpers are grouped by the boundary they protect:
// withdrawn-record lookup and aliasing, key-material install guards, journal
// replay filtering, card-terminality checks, local crypto teardown / retained
// tombstones vs local drops, post-crypto race rechecks, and test-only race hooks.
fn has_withdrawn_group_record(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> bool {
    groups.get(group_id).is_some_and(|info| info.withdrawn)
        || groups.values().any(|info| {
            info.withdrawn && (info.stable_group_id() == group_id || info.mls_group_id == group_id)
        })
}

fn has_withdrawn_same_stable_group_record(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> bool {
    let mut aliases = collect_same_stable_group_aliases(groups, group_id, stable_group_id);
    aliases.insert(group_id.to_string());
    if let Some(stable) = stable_group_id.filter(|stable| !stable.is_empty()) {
        aliases.insert(stable.to_string());
    }
    aliases
        .iter()
        .any(|alias| has_withdrawn_group_record(groups, alias))
}

// Install / commit choke-points: refuse to add crypto material if durable
// named-group state has already crossed terminality.
async fn ensure_named_group_key_material_install_allowed(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) -> anyhow::Result<()> {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, stable_group_id).await;

    if repair_withdrawn_named_groups_json_and_wipe_key_material(
        state,
        group_id,
        stable_group_id,
        reason,
    )
    .await?
    {
        anyhow::bail!("refusing to install key material for withdrawn group");
    }
    Ok(())
}

async fn repair_withdrawn_named_groups_json_and_wipe_key_material(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) -> anyhow::Result<bool> {
    let repair_json = {
        let groups = state.named_groups.read().await;
        if !has_withdrawn_same_stable_group_record(&groups, group_id, stable_group_id) {
            return Ok(false);
        }
        serde_json::to_string_pretty(&*groups)
            .map_err(|e| anyhow::anyhow!("withdrawn named groups repair encode: {e}"))?
    };

    remove_treekem_persistence_for_group_id(state, group_id, reason).await;
    write_named_groups_json_atomic(&state.named_groups_path, &repair_json)
        .await
        .map_err(|e| anyhow::anyhow!("withdrawn named groups repair write: {e}"))?;
    Ok(true)
}

// Journal-recovery guard: stale TreeKEM journals cannot resurrect a group that
// durable named-group state already records as withdrawn.
fn has_withdrawn_group_record_for_journal_replay(
    durable_groups: &HashMap<String, x0x::groups::GroupInfo>,
    journal_group_id: &str,
    journal_groups: &HashMap<String, x0x::groups::GroupInfo>,
) -> bool {
    let mut aliases = collect_same_stable_group_aliases(durable_groups, journal_group_id, None);
    aliases.insert(journal_group_id.to_string());

    let journal_infos = journal_groups.iter().filter(|(key, info)| {
        key.as_str() == journal_group_id
            || info.stable_group_id() == journal_group_id
            || info.mls_group_id == journal_group_id
    });
    for (key, info) in journal_infos {
        aliases.insert(key.clone());
        aliases.insert(info.mls_group_id.clone());
        aliases.insert(info.stable_group_id().to_string());
        aliases.extend(collect_same_stable_group_aliases(
            durable_groups,
            journal_group_id,
            Some(info.stable_group_id()),
        ));
    }

    aliases
        .iter()
        .any(|alias| has_withdrawn_group_record(durable_groups, alias))
}

fn clear_group_info_key_material(info: &mut x0x::groups::GroupInfo) {
    info.shared_secret = None;
}

// Card-terminality gate: withdrawn discovery cards may mark keyless stubs, but
// must not terminate local keyed state without the signed withdrawal commit.
fn withdrawn_card_can_terminally_mark_local_group(
    info: &x0x::groups::GroupInfo,
    card: &x0x::groups::GroupCard,
    protects_keyed_local_group: bool,
) -> bool {
    card.withdrawn && group_card_supersedes_group_info(card, info) && !protects_keyed_local_group
}

async fn local_group_has_protected_crypto_material(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    aliases: &HashSet<String>,
) -> bool {
    if !info.withdrawn && info.shared_secret.is_some() {
        return true;
    }
    {
        let groups = state.named_groups.read().await;
        if aliases.iter().any(|alias| {
            groups.get(alias).is_some_and(|alias_info| {
                !alias_info.withdrawn && alias_info.shared_secret.is_some()
            })
        }) {
            return true;
        }
    }
    {
        let mls_groups = state.mls_groups.read().await;
        if aliases.iter().any(|alias| mls_groups.contains_key(alias)) {
            return true;
        }
    }
    {
        let treekem_groups = state.treekem_groups.read().await;
        if aliases
            .iter()
            .any(|alias| treekem_groups.contains_key(alias))
        {
            return true;
        }
    }
    for alias in aliases {
        if let Some(path) = treekem_snapshot_path_for_drop(state, alias) {
            if tokio::fs::try_exists(path).await.unwrap_or(true) {
                return true;
            }
        }
        if let Some(path) = treekem_journal_path_for_drop(state, alias) {
            if tokio::fs::try_exists(path).await.unwrap_or(true) {
                return true;
            }
        }
    }
    false
}

// Local crypto teardown: wipe in-memory and persisted key material; either keep
// a keyless withdrawn tombstone or drop only local, non-terminal state.
async fn wipe_local_group_crypto_material(
    state: &AppState,
    id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) {
    let aliases = {
        let mut groups = state.named_groups.write().await;
        let aliases = collect_same_stable_group_aliases(&groups, id, stable_group_id);
        for alias in &aliases {
            if let Some(info) = groups.get_mut(alias) {
                clear_group_info_key_material(info);
            }
        }
        aliases
    };
    {
        let mut cache = state.group_card_cache.write().await;
        for alias in &aliases {
            cache.remove(alias);
        }
    }
    {
        let mut mls_groups = state.mls_groups.write().await;
        for alias in &aliases {
            mls_groups.remove(alias);
        }
    }
    {
        let mut treekem_groups = state.treekem_groups.write().await;
        for alias in &aliases {
            treekem_groups.remove(alias);
        }
    }
    {
        let mut pending = state.treekem_pending_events.write().await;
        for alias in &aliases {
            pending.remove(alias);
        }
    }
    {
        let mut event_log = state.treekem_event_log.write().await;
        for alias in &aliases {
            event_log.remove(alias);
        }
    }
    {
        let mut catchup = state.treekem_catchup_throttle.write().await;
        for alias in &aliases {
            catchup.remove(alias);
        }
    }
    {
        let mut messages = state.public_messages.write().await;
        for alias in &aliases {
            messages.remove(alias);
        }
    }
    {
        let mut tasks = state.group_metadata_tasks.write().await;
        for alias in &aliases {
            if let Some(handle) = tasks.remove(alias) {
                handle.abort();
            }
        }
    }
    {
        let mut tasks = state.public_message_tasks.write().await;
        for alias in &aliases {
            if let Some(handle) = tasks.remove(alias) {
                handle.abort();
            }
        }
    }
    {
        let mut join_results = state.pending_join_results.write().await;
        join_results.retain(|key, pending| {
            !join_result_key_matches_any_group_alias(key, &aliases)
                && !group_id_matches_any_alias(
                    named_group_metadata_event_group_id(&pending.event),
                    &aliases,
                )
        });
    }
    if let Ok(mut expected) = state.expected_join_result_inviters.lock() {
        expected.retain(|key, _| !join_result_key_matches_any_group_alias(key, &aliases));
    }

    let mut welcome_ids = Vec::new();
    {
        let mut welcomes = state.pending_welcomes.write().await;
        welcomes.retain(|welcome_id, pending| {
            let drop = group_id_matches_any_alias(&pending.group_id, &aliases);
            if drop {
                welcome_ids.push(welcome_id.clone());
            }
            !drop
        });
    }
    {
        let mut receives = state.pending_welcome_receives.write().await;
        receives.retain(|welcome_id, pending| {
            let drop = group_id_matches_any_alias(&pending.group_id, &aliases);
            if drop {
                welcome_ids.push(welcome_id.clone());
            }
            !drop
        });
    }
    if !welcome_ids.is_empty() {
        let mut waiters = state.pending_welcome_waiters.write().await;
        let mut acks = state.pending_welcome_acks.write().await;
        for welcome_id in welcome_ids {
            waiters.remove(&welcome_id);
            acks.remove(&welcome_id);
        }
    }

    for alias in &aliases {
        remove_treekem_persistence_for_group_id(state, alias, reason).await;
    }
}

async fn remove_directory_cache_entries_for_group_info(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
) {
    let stable_group_id = info.stable_group_id().to_string();
    let shards = x0x::groups::shards_for_public(&info.tags, &info.name, &stable_group_id);
    let mut cache = state.directory_cache.write().await;
    for (kind, shard, _) in shards {
        cache.remove(kind, shard, &stable_group_id);
    }
}

async fn retain_withdrawn_group_tombstone(
    state: &AppState,
    group_id: &str,
    mut info: x0x::groups::GroupInfo,
    reason: &str,
) {
    let stable_group_id = info.stable_group_id().to_string();
    info.withdrawn = true;
    clear_group_info_key_material(&mut info);
    {
        let mut groups = state.named_groups.write().await;
        let mut aliases =
            collect_same_stable_group_aliases(&groups, group_id, Some(&stable_group_id));
        aliases.insert(group_id.to_string());
        aliases.insert(stable_group_id.clone());
        for alias in aliases {
            groups.insert(alias, info.clone());
        }
    }
    wipe_local_group_crypto_material(state, group_id, Some(&stable_group_id), reason).await;
    remove_directory_cache_entries_for_group_info(state, &info).await;
    refresh_group_card_cache_from_info(state, group_id, &info).await;
    save_named_groups(state).await;
    save_mls_groups(state).await;
}

async fn drop_local_named_group_state(
    state: &AppState,
    id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) {
    let stable_group_id = stable_group_id.filter(|stable| *stable != id);
    {
        let mut groups = state.named_groups.write().await;
        groups.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            groups.remove(stable_group_id);
        }
    }
    {
        let mut cache = state.group_card_cache.write().await;
        cache.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            cache.remove(stable_group_id);
        }
    }
    {
        let mut mls_groups = state.mls_groups.write().await;
        mls_groups.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            mls_groups.remove(stable_group_id);
        }
    }
    {
        let mut treekem_groups = state.treekem_groups.write().await;
        treekem_groups.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            treekem_groups.remove(stable_group_id);
        }
    }
    remove_treekem_persistence_for_group_id(state, id, reason).await;
    if let Some(stable_group_id) = stable_group_id {
        remove_treekem_persistence_for_group_id(state, stable_group_id, reason).await;
    }
    save_named_groups(state).await;
    save_mls_groups(state).await;
    stop_named_group_metadata_listener(state, id).await;
    if let Some(stable_group_id) = stable_group_id {
        stop_named_group_metadata_listener(state, stable_group_id).await;
    }
}

async fn leave_treekem_group(
    state: Arc<AppState>,
    id: String,
    local_agent_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let (mut next, metadata_topic, event_group_id, name, disposition) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let disposition = treekem_leave_disposition(info, &local_agent_hex);
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
            info.name.clone(),
            disposition,
        )
    };
    match disposition {
        TreeKemLeaveDisposition::LocalOnlyDrop => {
            drop_local_named_group_state(
                &state,
                &id,
                Some(&event_group_id),
                "treekem_non_active_leave",
            )
            .await;
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "left": name, "local_only": true })),
            );
        }
        TreeKemLeaveDisposition::ActiveMember => {}
    }

    if let Some(error) = x0x::groups::last_admin_self_leave_precheck_error(&next, &local_agent_hex)
    {
        return api_error(StatusCode::CONFLICT, error);
    }

    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&local_agent_hex, Some(local_agent_hex.clone()));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };

    let mut groups = state.named_groups.write().await;
    groups.remove(&id);
    drop(groups);
    state.group_card_cache.write().await.remove(&id);
    state.mls_groups.write().await.remove(&id);
    state.treekem_groups.write().await.remove(&id);
    remove_treekem_persistence_for_group_id(&state, &id, "treekem_leave").await;
    save_named_groups(&state).await;
    save_mls_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: event_group_id,
        revision,
        actor: local_agent_hex.clone(),
        agent_id: local_agent_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "left": name })),
    )
}

async fn remove_treekem_named_group_member(
    state: Arc<AppState>,
    id: String,
    agent_id_hex: String,
    local_agent_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let target_agent = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let (mut next, metadata_topic, event_group_id, target_kp_bytes) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Err(e) = require_admin_or_above(info, &local_agent_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if !info.has_member(&agent_id_hex) {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "member not found" })),
            );
        }
        // ADR-0016 R2: friendly pre-check before any TreeKEM work begins.
        if let Some(resp) = last_admin_precheck(info, |g| g.remove_member(&agent_id_hex, None)) {
            return resp;
        }
        let Some(kp_b64) = info
            .members_v2
            .get(&agent_id_hex)
            .and_then(|m| m.treekem_key_package_b64.clone())
        else {
            return (
                StatusCode::FAILED_DEPENDENCY,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "member is missing TreeKEM KeyPackage"
                })),
            );
        };
        let target_kp_bytes = match base64::engine::general_purpose::STANDARD.decode(kp_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": "member TreeKEM KeyPackage is not valid base64"
                    })),
                );
            }
        };
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
            target_kp_bytes,
        )
    };

    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return (
            StatusCode::FAILED_DEPENDENCY,
            Json(serde_json::json!({
                "ok": false,
                "error": "TreeKEM group not loaded — restart or re-share required"
            })),
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&agent_id_hex, Some(local_agent_hex.clone()));
    next.secret_epoch = treekem_epoch;
    next.security_binding = Some(format!("treekem:epoch={treekem_epoch}"));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let treekem_commit = match guard.remove_member_verified(target_agent, &target_kp_bytes) {
        Ok(commit) => commit,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("TreeKEM remove_member failed: {e}")
                })),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "error": "TreeKEM epoch did not advance as expected"
            })),
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after removal: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "error": "failed to persist secure group state"
            })),
        );
    }
    drop(guard);

    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;
    save_mls_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: event_group_id,
        revision,
        actor: local_agent_hex,
        agent_id: agent_id_hex.clone(),
        treekem_commit_b64: Some(base64::engine::general_purpose::STANDARD.encode(treekem_commit)),
        treekem_epoch: Some(treekem_epoch),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&agent_id_hex),
    );
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "removed_member": agent_id_hex,
            "epoch": treekem_epoch,
            "member_count": named_group_member_values(&next).len(),
            "members": named_group_member_values(&next),
        })),
    )
}

/// GET /groups/:id/state — Phase D.3: inspect the stable-identity +
/// state-commit chain view of a group.
///
/// Returns `{ group_id, genesis, state_revision, state_hash,
/// prev_state_hash, security_binding, withdrawn, roster_root,
/// policy_hash, public_meta_hash }`.
///
/// Available to anyone holding the group stub — active members and
/// non-member card importers alike. Every field returned here is part of
/// the group's **public projection**: it is exactly the data already
/// published in the signed `GroupCard` (state_hash, revision,
/// prev_state_hash) plus derived commitments (roster_root, policy_hash,
/// public_meta_hash) that are hashes, never member content. The named-groups
/// model (`docs/design/named-groups-full-model.md`) requires non-members to
/// be able to view the public card and converge on the authoritative public
/// state of a discoverable group; private member content (chat, files, KV,
/// secure presence) is never exposed here. Non-discoverable groups cannot be
/// stubbed by a non-member (no card to import), so they 404 above for
/// outsiders rather than relying on this gate.
async fn get_group_state(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    let roster_root = x0x::groups::compute_roster_root(&info.members_v2);
    let policy_hash = x0x::groups::compute_policy_hash(&info.policy);
    let public_meta_hash = x0x::groups::compute_public_meta_hash(&info.public_meta());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": info.stable_group_id(),
            "mls_group_id": info.mls_group_id,
            "genesis": info.genesis,
            "state_revision": info.state_revision,
            "state_hash": info.state_hash,
            "prev_state_hash": info.prev_state_hash,
            "security_binding": info.security_binding,
            "withdrawn": info.withdrawn,
            "roster_root": roster_root,
            "policy_hash": policy_hash,
            "public_meta_hash": public_meta_hash,
        })),
    )
}

/// Query parameters for [`get_group_state_commits`].
#[derive(Debug, Deserialize)]
struct StateCommitsQuery {
    /// Only return retained commits with `revision >= from_revision`.
    #[serde(default)]
    from_revision: u64,
    /// Page size (clamped to `[1, STATE_COMMITS_MAX_LIMIT]`).
    #[serde(default)]
    limit: Option<usize>,
}

/// GET /groups/:id/state/commits — issue #111: paged read over the retained
/// state-commit history (ADR-0016 verification / governance use-cases).
///
/// **Members-only for live groups.** Unlike `/groups/:id/state` (which serves
/// the public projection even to non-member card-importers), retained roster
/// projections are member content, so this endpoint requires the local agent to
/// be an **active member** while the group is live. Withdrawn groups are
/// keyless terminal audit shells after delete; their retained commits
/// remain readable locally so members keep a keyless audit history after key
/// wipe.
///
/// Each entry is `{ commit, roster, roster_root_verified }`, ordered by
/// ascending revision. `roster_root_verified` recomputes the roster root over
/// the retained projection and compares it to the commit's signed
/// `roster_root`, so on-disk corruption surfaces loudly rather than serving
/// silently-wrong history. `first_available_revision` lets callers distinguish
/// a real gap (history began after their `from_revision`, because each daemon
/// retains only the suffix it witnessed) from an empty result.
async fn get_group_state_commits(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<StateCommitsQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    const STATE_COMMITS_DEFAULT_LIMIT: usize = 100;
    const STATE_COMMITS_MAX_LIMIT: usize = 500;
    let limit = q
        .limit
        .unwrap_or(STATE_COMMITS_DEFAULT_LIMIT)
        .clamp(1, STATE_COMMITS_MAX_LIMIT);

    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };

    // Live groups gate retained roster projections to active members. A
    // withdrawn local shell is intentionally keyless but still keeps #111
    // audit history after terminal delete, so keep that history
    // readable from the local daemon after terminality.
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    if !info.withdrawn && !info.has_active_member(&local_agent_hex) {
        return api_error(
            StatusCode::FORBIDDEN,
            "members only: retained state-commit history is member content",
        );
    }

    let matched = info
        .commit_log
        .iter()
        .filter(|rc| rc.commit.revision >= q.from_revision)
        .count();
    let entries: Vec<serde_json::Value> = info
        .commit_log
        .iter()
        .filter(|rc| rc.commit.revision >= q.from_revision)
        .take(limit)
        .map(|rc| {
            serde_json::json!({
                "commit": rc.commit,
                "roster": rc.roster,
                "roster_root_verified": rc.roster_root_consistent(),
            })
        })
        .collect();

    let has_more = matched > entries.len();
    // Cursor for the next page: one past the last returned revision. Safe
    // because the log is monotonic in revision and truncated only from the
    // front, so `last()` is the highest revision on this page.
    let next_from_revision = if has_more {
        info.commit_log
            .iter()
            .filter(|rc| rc.commit.revision >= q.from_revision)
            .nth(entries.len().saturating_sub(1))
            .map(|rc| rc.commit.revision + 1)
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": info.stable_group_id(),
            "state_revision": info.state_revision,
            "withdrawn": info.withdrawn,
            "total_retained": info.commit_log.len(),
            "first_available_revision": info.commit_log.first().map(|rc| rc.commit.revision),
            "latest_retained_revision": info.commit_log.last().map(|rc| rc.commit.revision),
            "from_revision": q.from_revision,
            "limit": limit,
            "count": entries.len(),
            "has_more": has_more,
            "next_from_revision": next_from_revision,
            "commits": entries,
        })),
    )
}

/// POST /groups/:id/state/seal — Phase D.3: advance the state-commit
/// chain and republish the signed public card (no-op payload change —
/// used to refresh / repair / force-propagate the chain).
///
/// Admin or higher only.
async fn seal_group_state(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        let role = info.caller_role(&local_hex);
        if !role
            .map(|r| r.at_least(x0x::groups::GroupRole::Admin))
            .unwrap_or(false)
        {
            return forbidden("admin role required");
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
    }
    let commit = publish_group_card_with_reseal(&state, &id).await;
    let Some(commit) = commit else {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "seal failed");
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "commit": commit,
        })),
    )
}

/// POST /groups/:id/state/withdraw — Phase D.3: seal a terminal withdrawal
/// commit and delete the group. Members receive the signed terminal
/// `GroupDeleted` event over the metadata topic plus direct delivery; the
/// withdrawn card still supersedes public discovery listings where applicable.
///
/// Admin or higher only.
async fn withdraw_group_state(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let signing_kp = state.agent.identity().agent_keypair();

    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;
    let (commit, metadata_topic, event_group_id, delivery_roster, event, terminal_info) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &local_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let event_revision = info.roster_revision.saturating_add(1);
        let commit = match info.seal_withdrawal(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("withdrawal seal failed: {e}"),
                );
            }
        };
        // Delete retains a keyless withdrawn tombstone: ADR-0012's "leave
        // nothing behind" means no MLS/TreeKEM/GSS key material survives, not
        // that the terminal metadata record is deleted. Keeping this record is
        // the stale-card reanimation guard for future imports.
        // `seal_withdrawal` already nulls `shared_secret` on success (its
        // documented contract, covered by `seal_withdrawal_success_clears_shared_secret`),
        // so the wipe lives inside the library method and stays atomic with the
        // withdrawn marker — no redundant server-side clear here.
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        let delivery_roster = info.clone();
        let terminal_info = info.clone();
        let event = NamedGroupMetadataEvent::GroupDeleted {
            group_id: event_group_id.clone(),
            revision: event_revision,
            actor: local_hex.clone(),
            commit: Some(commit.clone()),
        };
        (
            commit,
            metadata_topic,
            event_group_id,
            delivery_roster,
            event,
            terminal_info,
        )
    };
    retain_withdrawn_group_tombstone(&state, &id, terminal_info, "withdraw_delete").await;

    // Refresh the withdrawn-card path for public discovery supersession after
    // stale local cards are gone. Hidden groups still do not publish public
    // cards, so their delete propagation is the signed GroupDeleted
    // metadata/direct event above.
    maybe_publish_group_card_after_state_change(&state, &id).await;
    stop_named_group_metadata_listener(&state, &id).await;
    if event_group_id != id {
        stop_named_group_metadata_listener(&state, &event_group_id).await;
    }

    // Keep the per-group membership lock until local key material is gone and
    // the retained record is visibly withdrawn, so no concurrent API mutator can
    // author a post-withdrawal commit in the narrow terminal window. The
    // network-facing GroupDeleted publish/direct-delivery happens after the lock
    // is released; all required data was captured above.
    drop(membership_guard);

    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "commit": commit,
        })),
    )
}

/// DELETE /groups/:id — leave a group.
async fn leave_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_agent = state.agent.agent_id();
    let local_agent_hex = hex::encode(local_agent.as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;

    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        drop(groups);
        return leave_treekem_group(state, id, local_agent_hex).await;
    }
    let name = info.name.clone();
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    if let Some(resp) = treekem_membership_unsupported(info) {
        return resp;
    }
    if let Some(error) = x0x::groups::last_admin_self_leave_precheck_error(info, &local_agent_hex) {
        return api_error(StatusCode::CONFLICT, error);
    }
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&local_agent_hex, Some(local_agent_hex.clone()));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    *info = next;
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: event_group_id,
        revision,
        actor: local_agent_hex.clone(),
        agent_id: local_agent_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        commit: Some(commit),
    };
    drop(groups);

    save_named_groups(&state).await;
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    state.named_groups.write().await.remove(&id);
    let mut cache = state.group_card_cache.write().await;
    prune_expired_group_cards(&mut cache, now_millis_u64());
    cache.remove(&id);
    state.mls_groups.write().await.remove(&id);
    // ADR-0012: drop the live TreeKEM group and wipe at-rest TreeKEM
    // persistence (snapshot plus replay journal, both containing private key
    // material) so a left secure group leaves nothing behind locally. No-op for
    // GSS groups: no in-memory entry, and the persistence files do not exist
    // (NotFound is ignored).
    state.treekem_groups.write().await.remove(&id);
    remove_treekem_persistence_for_group_id(&state, &id, "leave_group").await;
    save_named_groups(&state).await;
    save_mls_groups(&state).await;
    stop_named_group_metadata_listener(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "left": name })),
    )
}

// ---------------------------------------------------------------------------
// Full named-group model (Phase A/B/C) — policy, roles, join requests, cards
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateGroupPolicyRequest {
    preset: Option<String>,
    discoverability: Option<x0x::groups::GroupDiscoverability>,
    admission: Option<x0x::groups::GroupAdmission>,
    confidentiality: Option<x0x::groups::GroupConfidentiality>,
    read_access: Option<x0x::groups::GroupReadAccess>,
    write_access: Option<x0x::groups::GroupWriteAccess>,
}

#[derive(Debug, Deserialize)]
struct UpdateMemberRoleRequest {
    role: String,
}

#[derive(Debug, Deserialize, Default)]
struct CreateJoinRequestBody {
    message: Option<String>,
}

fn now_millis_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Require the caller to be an active Admin or higher.
fn require_admin_or_above(
    info: &x0x::groups::GroupInfo,
    caller_hex: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    match info.caller_role(caller_hex) {
        Some(role) if role.at_least(x0x::groups::GroupRole::Admin) => Ok(()),
        _ => Err(forbidden("admin role required")),
    }
}

fn reject_withdrawn_group(
    info: &x0x::groups::GroupInfo,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    info.withdrawn
        .then(|| api_error(StatusCode::CONFLICT, "group is withdrawn"))
}

#[cfg(test)]
static POST_CRYPTO_FORCED_WITHDRAWN_GROUPS: std::sync::LazyLock<StdMutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| StdMutex::new(HashSet::new()));

#[cfg(test)]
static ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS: std::sync::LazyLock<
    StdMutex<HashSet<String>>,
> = std::sync::LazyLock::new(|| StdMutex::new(HashSet::new()));

// Test-only hooks that force the post-crypto race windows exercised by the
// terminality unit tests. Production code never populates these sets.
#[cfg(test)]
fn forced_withdrawn_for_test(
    forced: &StdMutex<HashSet<String>>,
    poison_message: &'static str,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> bool {
    let forced = forced.lock().expect(poison_message);
    forced.contains(group_id)
        || stable_group_id
            .filter(|stable| !stable.is_empty())
            .is_some_and(|stable| forced.contains(stable))
}

#[cfg(test)]
async fn maybe_force_withdrawn_group_for_test(
    forced: &StdMutex<HashSet<String>>,
    poison_message: &'static str,
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) {
    if !forced_withdrawn_for_test(forced, poison_message, group_id, stable_group_id) {
        return;
    }

    let mut groups = state.named_groups.write().await;
    let mut aliases = collect_same_stable_group_aliases(&groups, group_id, stable_group_id);
    aliases.insert(group_id.to_string());
    if let Some(stable) = stable_group_id.filter(|stable| !stable.is_empty()) {
        aliases.insert(stable.to_string());
    }
    for alias in aliases {
        if let Some(info) = groups.get_mut(&alias) {
            info.withdrawn = true;
            clear_group_info_key_material(info);
        }
    }
}

#[cfg(test)]
async fn maybe_force_post_crypto_withdrawn_group_for_test(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) {
    maybe_force_withdrawn_group_for_test(
        &POST_CRYPTO_FORCED_WITHDRAWN_GROUPS,
        "post-crypto forced-withdrawn test hook poisoned",
        state,
        group_id,
        stable_group_id,
    )
    .await;
}

#[cfg(test)]
async fn maybe_force_atomic_persist_post_json_withdrawn_group_for_test(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) {
    maybe_force_withdrawn_group_for_test(
        &ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS,
        "atomic-persist forced-withdrawn test hook poisoned",
        state,
        group_id,
        stable_group_id,
    )
    .await;
}

// Post-crypto rechecks: if terminality wins a race after expensive crypto work,
// drop the just-produced effect and report the withdrawn conflict instead.
fn post_crypto_withdrawn_group_conflict(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let selected_withdrawn = groups.get(group_id).is_some_and(|info| info.withdrawn);
    let selected_missing = !groups.contains_key(group_id);
    let stable_group_withdrawn = stable_group_id
        .filter(|stable| !stable.is_empty())
        .is_some_and(|stable| {
            if groups.contains_key(stable) {
                groups.get(stable).is_some_and(|info| info.withdrawn) && selected_missing
            } else {
                selected_missing && has_withdrawn_group_record(groups, stable)
            }
        });
    (selected_withdrawn || stable_group_withdrawn)
        .then(|| api_error(StatusCode::CONFLICT, "group is withdrawn"))
}

fn active_same_stable_keyed_alias_exists(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> bool {
    collect_same_stable_group_aliases(groups, group_id, Some(group_id))
        .iter()
        .any(|alias| {
            groups
                .get(alias)
                .is_some_and(|info| !info.withdrawn && info.shared_secret.is_some())
        })
}

fn open_envelope_withdrawn_group_conflict(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    (has_withdrawn_group_record(groups, group_id)
        && !active_same_stable_keyed_alias_exists(groups, group_id))
    .then(|| api_error(StatusCode::CONFLICT, "group is withdrawn"))
}

async fn reject_withdrawn_group_record_after_crypto(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, stable_group_id).await;

    let groups = state.named_groups.read().await;
    post_crypto_withdrawn_group_conflict(&groups, group_id, stable_group_id)
}

fn secure_group_effect_response_after_terminality_recheck_from_groups(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    stable_group_id: Option<&str>,
    effect: serde_json::Value,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(resp) = post_crypto_withdrawn_group_conflict(groups, group_id, stable_group_id) {
        resp
    } else {
        (StatusCode::OK, Json(effect))
    }
}

async fn secure_group_effect_response_after_terminality_recheck(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
    effect: serde_json::Value,
) -> (StatusCode, Json<serde_json::Value>) {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, stable_group_id).await;

    let groups = state.named_groups.read().await;
    secure_group_effect_response_after_terminality_recheck_from_groups(
        &groups,
        group_id,
        stable_group_id,
        effect,
    )
}

async fn open_envelope_effect_response_after_terminality_recheck(
    state: &AppState,
    group_id: &str,
    effect: serde_json::Value,
) -> (StatusCode, Json<serde_json::Value>) {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, Some(group_id)).await;

    let groups = state.named_groups.read().await;
    if let Some(resp) = open_envelope_withdrawn_group_conflict(&groups, group_id) {
        resp
    } else {
        (StatusCode::OK, Json(effect))
    }
}

/// Friendly REST pre-check for the ADR-0016 last-admin invariant.
///
/// Applies the handler's intended roster mutation to a clone of the group
/// through the shared library helper. Returns the 409 response to send
/// when the act would strip the last active admin (legacy `Owner` counts
/// as Admin). This is UX only — the authoritative enforcement is the same
/// shared check inside
/// `seal_commit` / `finalize_applied_commit` on every delivery path.
fn last_admin_precheck(
    info: &x0x::groups::GroupInfo,
    apply: impl FnOnce(&mut x0x::groups::GroupInfo),
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    x0x::groups::last_admin_precheck_error(info, apply)
        .map(|error| api_error(StatusCode::CONFLICT, error))
}

/// PATCH /groups/:id — update name/description (admin+).
async fn update_named_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateGroupRequest>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    let name_update = req.name.clone();
    let desc_update = req.description.clone();
    if let Some(name) = req.name {
        info.name = name;
    }
    if let Some(desc) = req.description {
        info.description = desc;
    }
    info.updated_at = now_ms;
    info.roster_revision = info.roster_revision.saturating_add(1);
    let revision = info.roster_revision;
    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let updated_name = info.name.clone();
    let updated_desc = info.description.clone();
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    let delivery_roster = info.clone();
    drop(groups);
    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        name: name_update,
        description: desc_update,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "name": updated_name,
            "description": updated_desc,
            "revision": revision,
        })),
    )
}

/// PATCH /groups/:id/policy — update policy (admin+).
async fn update_group_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateGroupPolicyRequest>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    let mut new_policy = info.policy.clone();
    if let Some(preset_name) = req.preset.as_deref() {
        match x0x::groups::GroupPolicyPreset::from_name(preset_name) {
            Some(preset) => new_policy = preset.to_policy(),
            None => {
                return bad_request("unknown preset");
            }
        }
    }
    if let Some(d) = req.discoverability {
        new_policy.discoverability = d;
    }
    if let Some(a) = req.admission {
        new_policy.admission = a;
    }
    if let Some(c) = req.confidentiality {
        new_policy.confidentiality = c;
    }
    if let Some(r) = req.read_access {
        new_policy.read_access = r;
    }
    if let Some(w) = req.write_access {
        new_policy.write_access = w;
    }

    info.policy = new_policy.clone();
    info.policy_revision = info.policy_revision.saturating_add(1);
    let revision = info.policy_revision;
    info.updated_at = now_ms;

    // Establish discovery topic when the group becomes publicly discoverable.
    if info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
        && info.discovery_card_topic.is_none()
    {
        info.discovery_card_topic = Some(format!(
            "x0x.group.{}.card",
            &info.mls_group_id[..16.min(info.mls_group_id.len())]
        ));
    }

    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    let policy_clone = info.policy.clone();
    let delivery_roster = info.clone();
    drop(groups);
    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::PolicyUpdated {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        policy: policy_clone.clone(),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "policy": policy_clone, "revision": revision })),
    )
}

/// PATCH /groups/:id/members/:agent_id/role — change a member's role.
async fn update_member_role(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRoleRequest>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let new_role = match x0x::groups::GroupRole::assignable_from_name(&req.role) {
        Ok(role) => role,
        Err(error) => return bad_request(error),
    };

    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    // P0-7: target must exist in members_v2 (active, banned, or removed — NOT absent).
    let target_entry = info.members_v2.get(&agent_id_hex).cloned();
    let Some(target_entry) = target_entry else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "member not found" })),
        );
    };
    if target_entry.is_removed() || target_entry.is_banned() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "cannot change role of a removed or banned member"
            })),
        );
    }

    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    // ADR-0016 R2: friendly pre-check — a demotion must not strip the last
    // active admin (legacy Owner counts as Admin).
    if let Some(resp) = last_admin_precheck(info, |g| g.set_member_role(&agent_id_hex, new_role)) {
        return resp;
    }

    // Role changes are metadata-only: they do not add/remove TreeKEM leaves or
    // require Commit/Welcome transport, so TreeKEM groups may apply them before
    // Phase 3 membership transport lands.
    info.set_member_role(&agent_id_hex, new_role);
    info.roster_revision = info.roster_revision.saturating_add(1);
    let revision = info.roster_revision;
    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    let delivery_roster = info.clone();
    drop(groups);
    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberRoleUpdated {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex,
        role: new_role,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "role": new_role, "revision": revision })),
    )
}

/// POST /groups/:id/ban/:agent_id — ban a member (admin+).
async fn ban_group_member(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        drop(groups);
        return ban_treekem_group_member(state, id, agent_id_hex, caller_hex).await;
    }
    // ADR-0016 R2: friendly pre-check before any mutation/rekey side effect.
    if let Some(resp) = last_admin_precheck(info, |g| g.ban_member(&agent_id_hex, None)) {
        return resp;
    }
    let mut next = info.clone();
    next.ban_member(&agent_id_hex, Some(caller_hex.clone()));
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    let metadata_topic = next.metadata_topic.clone();
    let event_group_id = next.stable_group_id().to_string();

    // Phase D.2: rotate the group shared secret so banned peer's stale secret
    // cannot decrypt new-epoch content. Capture remaining active members with
    // their KEM pubkeys so we can seal the new secret to each.
    let is_encrypted =
        next.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted;
    type RekeyBundle = (Option<[u8; 32]>, u64, Vec<(String, Option<String>)>);
    let (new_secret, new_epoch, remaining_targets): RekeyBundle = if is_encrypted {
        let (sec_vec, ep) = next.rotate_shared_secret();
        let mut sec = [0u8; 32];
        if sec_vec.len() == 32 {
            sec.copy_from_slice(&sec_vec);
        }
        let remaining: Vec<(String, Option<String>)> = next
            .active_members()
            .map(|m| (m.agent_id.clone(), m.kem_public_key_b64.clone()))
            .collect();
        (Some(sec), ep, remaining)
    } else {
        (None, 0, Vec::new())
    };
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    if !store_named_group_info_locked(&mut groups, &id, next) {
        return api_error(StatusCode::CONFLICT, "group is withdrawn");
    }
    drop(groups);
    save_named_groups(&state).await;

    // Deliver the rotated secret to each remaining member (skip self). Each
    // envelope is sealed to that member's published ML-KEM-768 public key
    // via `seal_group_secret_to_recipient`, so only the recipient's private
    // key can open it.
    if let Some(ref secret) = new_secret {
        for (recipient, recipient_kem_b64) in &remaining_targets {
            if recipient == &caller_hex {
                continue;
            }
            let Some(kem_b64) = recipient_kem_b64 else {
                tracing::warn!(
                    recipient = %LogHexId::agent(&recipient),
                    "rekey: no KEM pubkey on record for remaining member; cannot seal"
                );
                continue;
            };
            publish_secure_share(
                &state,
                &metadata_topic,
                &event_group_id,
                recipient,
                kem_b64,
                &caller_hex,
                secret,
                new_epoch,
            )
            .await;
        }
    }

    // P0-4: drive local MLS remove_member so the banning daemon's MLS state no
    // longer treats the banned peer as a recipient. Cross-daemon rekey
    // propagation to existing members remains Phase D.2.
    if let Ok(target_agent) = parse_agent_id_hex(&agent_id_hex) {
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if group.is_member(&target_agent) {
                match group.remove_member(target_agent).await {
                    Ok(_) => {
                        tracing::debug!(
                            target: "x0x::groups",
                            "banned {} → removed from MLS group {}",
                            &agent_id_hex[..16.min(agent_id_hex.len())],
                            &id[..16.min(id.len())]
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "MLS remove_member on ban failed: {e} — roster banned anyway"
                        );
                    }
                }
            }
        }
    }
    save_mls_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberBanned {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex,
        secret_epoch: if is_encrypted { Some(new_epoch) } else { None },
        treekem_commit_b64: None,
        treekem_epoch: None,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

async fn ban_treekem_group_member(
    state: Arc<AppState>,
    id: String,
    agent_id_hex: String,
    caller_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let target_agent = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };
    let (mut next, metadata_topic, event_group_id, target_kp_bytes) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        // ADR-0016 R2: friendly pre-check before any TreeKEM work begins.
        if let Some(resp) = last_admin_precheck(info, |g| g.ban_member(&agent_id_hex, None)) {
            return resp;
        }
        let Some(kp_b64) = info
            .members_v2
            .get(&agent_id_hex)
            .and_then(|m| m.treekem_key_package_b64.clone())
        else {
            return (
                StatusCode::FAILED_DEPENDENCY,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "member is missing TreeKEM KeyPackage"
                })),
            );
        };
        let target_kp_bytes = match base64::engine::general_purpose::STANDARD.decode(kp_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": "member TreeKEM KeyPackage is not valid base64"
                    })),
                );
            }
        };
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
            target_kp_bytes,
        )
    };
    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return (
            StatusCode::FAILED_DEPENDENCY,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM group not loaded — restart or re-share required" }),
            ),
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.ban_member(&agent_id_hex, Some(caller_hex.clone()));
    next.secret_epoch = treekem_epoch;
    next.security_binding = Some(format!("treekem:epoch={treekem_epoch}"));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let treekem_commit = match guard.remove_member_verified(target_agent, &target_kp_bytes) {
        Ok(commit) => commit,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("TreeKEM ban removal failed: {e}") }),
                ),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM epoch did not advance as expected" }),
            ),
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after ban: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "failed to persist secure group state" }),
            ),
        );
    }
    drop(guard);
    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberBanned {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex.clone(),
        secret_epoch: None,
        treekem_commit_b64: Some(base64::engine::general_purpose::STANDARD.encode(treekem_commit)),
        treekem_epoch: Some(treekem_epoch),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&agent_id_hex),
    );
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

/// DELETE /groups/:id/ban/:agent_id — unban a member (admin+).
async fn unban_group_member(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.is_banned(&agent_id_hex) {
        return bad_request("member is not banned");
    }
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        if let Some(member) = info.members_v2.get_mut(&agent_id_hex) {
            member.state = x0x::groups::GroupMemberState::Removed;
            member.updated_at = now_ms;
            member.removed_by = None;
        }
    } else {
        info.unban_member(&agent_id_hex);
    }
    info.roster_revision = info.roster_revision.saturating_add(1);
    let revision = info.roster_revision;
    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    drop(groups);
    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberUnbanned {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

/// GET /groups/:id/requests — list join requests (admin+).
async fn list_join_requests(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    let mut requests: Vec<&x0x::groups::JoinRequest> = info.join_requests.values().collect();
    requests.sort_by_key(|r| r.created_at);
    let list: Vec<serde_json::Value> = requests
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "requests": list })),
    )
}

/// POST /groups/:id/requests — submit a join request (non-member, non-banned).
async fn create_join_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Option<Json<CreateJoinRequestBody>>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let req_body = body.map(|b| b.0).unwrap_or_default();
    let now_ms = now_millis_u64();

    let (metadata_topic, event_group_id, request, creator_hex, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.policy.admission != x0x::groups::GroupAdmission::RequestAccess {
            return forbidden("group admission is not request_access");
        }
        if info.is_banned(&caller_hex) {
            return forbidden("banned");
        }
        if info.has_active_member(&caller_hex) {
            return api_error(StatusCode::CONFLICT, "already a member");
        }
        if info
            .join_requests
            .values()
            .any(|r| r.requester_agent_id == caller_hex && r.is_pending())
        {
            return api_error(StatusCode::CONFLICT, "pending request already exists");
        }

        let mut request = x0x::groups::JoinRequest::new(
            info.mls_group_id.clone(),
            caller_hex.clone(),
            req_body.message.clone(),
            now_ms,
        );
        if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
            use base64::Engine as _;
            let group_id_bytes = match hex::decode(&info.mls_group_id) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("invalid TreeKEM group id: {e}"),
                    );
                }
            };
            let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
            let prepared =
                match x0x::mls::TreeKemMlsGroup::prepare_member(state.agent.agent_id(), &seed) {
                    Ok(prepared) => prepared,
                    Err(e) => {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to prepare TreeKEM KeyPackage: {e}"),
                        );
                    }
                };
            request.treekem_key_package_b64 = Some(BASE64.encode(prepared.key_package_bytes()));
        }
        info.join_requests
            .insert(request.request_id.clone(), request.clone());
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let creator_hex = hex::encode(info.creator.as_bytes());
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        drop(groups);
        (metadata_topic, event_group_id, request, creator_hex, commit)
    };

    save_named_groups(&state).await;

    // Include our ML-KEM-768 public key so the approver can seal the group
    // shared secret directly to us on approval.
    use base64::Engine as _;
    let requester_kem_b64 = BASE64.encode(&state.agent_kem_keypair.public_bytes);
    let event = NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: event_group_id,
        request_id: request.request_id.clone(),
        requester_agent_id: request.requester_agent_id.clone(),
        message: request.message.clone(),
        ts: request.created_at,
        requester_kem_public_key_b64: Some(requester_kem_b64),
        treekem_key_package_b64: request.treekem_key_package_b64.clone(),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;
    let _ = creator_hex; // reserved for direct-notification future enhancement

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ok": true,
            "request_id": request.request_id,
            "group_id": id,
        })),
    )
}

/// POST /groups/:id/requests/:request_id/approve — approve request (admin+).
async fn approve_join_request(
    State(state): State<Arc<AppState>>,
    Path((id, request_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(&id) {
            if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                drop(groups);
                return approve_treekem_join_request(state, id, request_id, caller_hex).await;
            }
        }
    }
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (metadata_topic, event_group_id, requester_hex, revision, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if let Some(resp) = treekem_membership_unsupported(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get_mut(&request_id) else {
            return not_found("request not found");
        };
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        req.status = x0x::groups::JoinRequestStatus::Approved;
        req.reviewed_by = Some(caller_hex.clone());
        req.reviewed_at = Some(now_ms);
        let requester_hex = req.requester_agent_id.clone();
        info.add_member(
            requester_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(caller_hex.clone()),
            None,
        );
        info.roster_revision = info.roster_revision.saturating_add(1);
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        let revision = info.roster_revision;
        drop(groups);
        (
            metadata_topic,
            event_group_id,
            requester_hex,
            revision,
            commit,
        )
    };

    save_named_groups(&state).await;

    // Phase D.2: deliver the current group shared secret to the new member
    // via a `SecureShareDelivered` envelope on the group metadata topic,
    // sealed with ML-KEM-768 to the requester's published public key. Only
    // applies to MlsEncrypted groups.
    let (shared_secret_snapshot, secret_epoch_snapshot, is_encrypted, requester_kem_b64) = {
        let groups = state.named_groups.read().await;
        groups
            .get(&id)
            .map(|g| {
                let requester_kem = g
                    .members_v2
                    .get(&requester_hex)
                    .and_then(|m| m.kem_public_key_b64.clone());
                (
                    g.shared_secret.clone(),
                    g.secret_epoch,
                    g.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted,
                    requester_kem,
                )
            })
            .unwrap_or((None, 0, false, None))
    };
    if is_encrypted {
        match (shared_secret_snapshot.as_ref(), requester_kem_b64.as_ref()) {
            (Some(sec_vec), Some(kem_b64)) if sec_vec.len() == 32 => {
                let mut sec = [0u8; 32];
                sec.copy_from_slice(sec_vec);
                publish_secure_share(
                    &state,
                    &metadata_topic,
                    &event_group_id,
                    &requester_hex,
                    kem_b64,
                    &caller_hex,
                    &sec,
                    secret_epoch_snapshot,
                )
                .await;
            }
            (None, _) => {
                tracing::warn!(
                    group_id = %LogHexId::group(&id),
                    "approval: no group shared secret yet; requester will receive via next rekey"
                );
            }
            (_, None) => {
                tracing::warn!(
                    group_id = %LogHexId::group(&id),
                    requester = %LogHexId::agent(&requester_hex),
                    "approval: requester KEM pubkey unknown; cannot seal secure share"
                );
            }
            _ => {}
        }
    }

    // P0-3: drive local MLS add_member so the approver's MLS state includes the
    // new member. Cross-daemon welcome propagation (Bob's daemon receives the
    // welcome packet and joins the MLS group) is explicit Phase D.2 — tracked
    // below as "welcome propagation gap".
    let requester_bytes = parse_agent_id_hex(&requester_hex);
    {
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if let Ok(member_id) = requester_bytes {
                if !group.is_member(&member_id) {
                    match group.add_member(member_id).await {
                        Ok(_) => {
                            tracing::debug!(
                                target: "x0x::groups",
                                "approved {} → added to MLS group {}",
                                &requester_hex[..16.min(requester_hex.len())],
                                &id[..16.min(id.len())]
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "MLS add_member on approval failed: {e} — roster updated anyway"
                            );
                        }
                    }
                }
            }
        }
    }
    save_mls_groups(&state).await;

    let event = NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: event_group_id,
        request_id,
        revision,
        actor: caller_hex,
        requester_agent_id: requester_hex.clone(),
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery(&state, &requester_hex, &event);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

async fn approve_treekem_join_request(
    state: Arc<AppState>,
    id: String,
    request_id: String,
    caller_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (mut next, metadata_topic, event_group_id, requester_hex, requester_id, kp_bytes) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get(&request_id) else {
            return not_found("request not found");
        };
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        if info.is_banned(&req.requester_agent_id) {
            return forbidden("requester is banned");
        }
        let requester_id = match parse_agent_id_hex(&req.requester_agent_id) {
            Ok(id) => id,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                );
            }
        };
        let Some(kp_b64) = req.treekem_key_package_b64.clone() else {
            return api_error(
                StatusCode::FAILED_DEPENDENCY,
                "request is missing TreeKEM KeyPackage",
            );
        };
        let kp_bytes = match BASE64.decode(kp_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                return bad_request("request TreeKEM KeyPackage is not valid base64");
            }
        };
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
            req.requester_agent_id.clone(),
            requester_id,
            kp_bytes,
        )
    };

    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "TreeKEM group not loaded — restart or re-share required",
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    if let Some(req) = next.join_requests.get_mut(&request_id) {
        req.status = x0x::groups::JoinRequestStatus::Approved;
        req.reviewed_by = Some(caller_hex.clone());
        req.reviewed_at = Some(now_ms);
    }
    next.add_member(
        requester_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(caller_hex.clone()),
        None,
    );
    next.set_member_treekem_key_package(&requester_hex, BASE64.encode(&kp_bytes));
    next.secret_epoch = treekem_epoch;
    next.security_binding = Some(format!("treekem:epoch={treekem_epoch}"));
    let revision = next.roster_revision;
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let out = match guard.add_member(requester_id, &kp_bytes) {
        Ok(out) => out,
        Err(e) => {
            return api_error(
                StatusCode::CONFLICT,
                format!("TreeKEM add_member failed: {e}"),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "TreeKEM epoch did not advance as expected",
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after approval: {e}");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist secure group state",
        );
    }
    let treekem_commit = out.commit;
    let treekem_welcome = out.welcome;
    drop(guard);

    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;

    let welcome_ref =
        stage_treekem_welcome(&state, &event_group_id, &requester_hex, treekem_welcome).await;
    let event = NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: event_group_id,
        request_id,
        revision,
        actor: caller_hex,
        requester_agent_id: requester_hex.clone(),
        treekem_commit_b64: Some(BASE64.encode(treekem_commit)),
        treekem_welcome_b64: None,
        welcome_ref: Some(welcome_ref),
        treekem_epoch: Some(treekem_epoch),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&requester_hex),
    );
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

/// POST /groups/:id/requests/:request_id/reject — reject request (admin+).
async fn reject_join_request(
    State(state): State<Arc<AppState>>,
    Path((id, request_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (metadata_topic, event_group_id, requester_hex, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get_mut(&request_id) else {
            return not_found("request not found");
        };
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        req.status = x0x::groups::JoinRequestStatus::Rejected;
        req.reviewed_by = Some(caller_hex.clone());
        req.reviewed_at = Some(now_ms);
        let requester_hex = req.requester_agent_id.clone();
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        drop(groups);
        (metadata_topic, event_group_id, requester_hex, commit)
    };

    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::JoinRequestRejected {
        group_id: event_group_id,
        request_id,
        actor: caller_hex,
        requester_agent_id: requester_hex.clone(),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery(&state, &requester_hex, &event);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// DELETE /groups/:id/requests/:request_id — cancel own pending request.
async fn cancel_join_request(
    State(state): State<Arc<AppState>>,
    Path((id, request_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (metadata_topic, event_group_id, requester_hex, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get_mut(&request_id) else {
            return not_found("request not found");
        };
        if req.requester_agent_id != caller_hex {
            return forbidden("not your request");
        }
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        req.status = x0x::groups::JoinRequestStatus::Cancelled;
        let requester_hex = req.requester_agent_id.clone();
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        drop(groups);
        (metadata_topic, event_group_id, requester_hex, commit)
    };

    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::JoinRequestCancelled {
        group_id: event_group_id,
        request_id,
        requester_agent_id: requester_hex,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// GET /groups/discover — list locally known discoverable groups.
async fn discover_groups(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let mut cards: HashMap<String, x0x::groups::GroupCard> = HashMap::new();
    let mut merge_card = |card: &x0x::groups::GroupCard| {
        let entry = cards.entry(card.group_id.clone());
        match entry {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(card.clone());
            }
            std::collections::hash_map::Entry::Occupied(mut o) => {
                if card.supersedes(o.get()) {
                    o.insert(card.clone());
                }
            }
        }
    };

    // Phase C.2: merge the local cache by the card's stable public group_id,
    // not by the cache's internal key. The cache may legitimately contain
    // the same signed card under both the local MLS id and the stable group id.
    {
        let mut card_cache = state.group_card_cache.write().await;
        prune_and_bound_group_card_cache(&mut card_cache, now_millis_u64());
        for card in card_cache.values() {
            merge_card(card);
        }
    }
    // Phase C.2: merge in shard-cache contents. Higher-revision wins on collision.
    {
        let shard_cache = state.directory_cache.read().await;
        for card in shard_cache.iter_all() {
            merge_card(card);
        }
    }
    // Also synthesize signed cards for any local groups the caller owns that are discoverable.
    let groups = state.named_groups.read().await;
    let signing_kp = state.agent.identity().agent_keypair();
    for info in groups.values() {
        if let Ok(Some(card)) = info.to_signed_group_card(signing_kp) {
            merge_card(&card);
        }
    }
    let mut list: Vec<x0x::groups::GroupCard> = cards.into_values().collect();
    // Phase C.2: honour `?q=` by filtering cards through the shard-cache
    // search helper (matches tag/name/id case-insensitively).
    if let Some(q) = params.get("q") {
        if !q.trim().is_empty() {
            let q_lc = q.trim().to_lowercase();
            list.retain(|c| {
                c.name.to_lowercase().contains(&q_lc)
                    || c.tags.iter().any(|t| t.to_lowercase().contains(&q_lc))
                    || c.group_id == q_lc
            });
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "groups": list })),
    )
}

/// GET /groups/discover/nearby — Phase C.2 presence-social browse.
///
/// Returns discoverable group cards weighted toward groups that peers
/// reachable in the current partition are actively using. Privacy rules:
/// - `Hidden` never appears.
/// - `ListedToContacts` never appears on this endpoint (only on
///   contact-scoped surfaces).
/// - `PublicDirectory` appears only if it has been observed on the
///   shard discovery plane.
///
/// IMPORTANT: this endpoint is intentionally a **shard-cache-only
/// witness**. It does not merge the legacy bridge cache or locally
/// synthesised cards, so a hit here is attributable to C.2 discovery
/// rather than local ownership or bridge dual-publish. Tighter
/// FOAF-based weighting is follow-up work.
async fn discover_groups_nearby(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut seen = std::collections::HashSet::<String>::new();
    let mut out: Vec<x0x::groups::GroupCard> = Vec::new();
    let shard_cache = state.directory_cache.read().await;
    for card in shard_cache.iter_all() {
        if card.withdrawn {
            continue;
        }
        if card.policy_summary.discoverability != x0x::groups::GroupDiscoverability::PublicDirectory
        {
            continue;
        }
        if seen.insert(card.group_id.clone()) {
            out.push(card.clone());
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "groups": out })),
    )
}

/// GET /groups/discover/subscriptions — list active shard subscriptions.
async fn list_discovery_subscriptions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let subs = state.directory_subscriptions.read().await.clone();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "count": subs.len(),
            "subscriptions": subs.subscriptions,
        })),
    )
}

/// POST /groups/discover/subscribe — subscribe to a shard derived from
/// either `{ "kind": "tag|name|id", "key": "<token>" }` (shard is computed
/// from the normalised key), or `{ "kind": "...", "shard": <u32> }` if
/// the caller already knows the shard id.
#[derive(Debug, Deserialize)]
struct SubscribeDiscoveryRequest {
    kind: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    shard: Option<u32>,
}

async fn create_discovery_subscription(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubscribeDiscoveryRequest>,
) -> impl IntoResponse {
    let Some(kind) = x0x::groups::ShardKind::from_str(&req.kind) else {
        return bad_request("kind must be 'tag', 'name', or 'id'");
    };
    let (shard, key) = match (req.shard, req.key.as_deref()) {
        (Some(s), k) => (s, k.map(str::to_string)),
        (None, Some(k)) => {
            let normalised = match kind {
                x0x::groups::ShardKind::Tag => x0x::groups::normalize_tag(k),
                x0x::groups::ShardKind::Name => k.trim().to_lowercase(),
                x0x::groups::ShardKind::Id => k.to_string(),
            };
            (x0x::groups::shard_of(kind, &normalised), Some(normalised))
        }
        (None, None) => {
            return bad_request("either 'shard' or 'key' is required");
        }
    };
    if state.directory_subscriptions.read().await.len() >= x0x::groups::DEFAULT_MAX_SUBSCRIPTIONS {
        return api_error(StatusCode::PAYLOAD_TOO_LARGE, "subscription limit reached");
    }
    let rec = x0x::groups::SubscriptionRecord {
        kind,
        shard,
        key,
        subscribed_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    };
    let newly_added = state.directory_subscriptions.write().await.add(rec);
    save_directory_subscriptions(&state).await;
    subscribe_shard(Arc::clone(&state), kind, shard).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "newly_added": newly_added,
            "kind": kind,
            "shard": shard,
            "topic": x0x::groups::topic_for(kind, shard),
        })),
    )
}

/// DELETE /groups/discover/subscribe/:kind/:shard — unsubscribe from a shard.
async fn delete_discovery_subscription(
    State(state): State<Arc<AppState>>,
    Path((kind_str, shard)): Path<(String, u32)>,
) -> impl IntoResponse {
    let Some(kind) = x0x::groups::ShardKind::from_str(&kind_str) else {
        return bad_request("kind must be 'tag', 'name', or 'id'");
    };
    let existed = state
        .directory_subscriptions
        .write()
        .await
        .remove(kind, shard);
    save_directory_subscriptions(&state).await;
    unsubscribe_shard(&state, kind, shard).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "existed": existed })),
    )
}

/// GET /groups/cards/:id — fetch a single group card.
async fn get_group_card(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Prefer cached card; fall back to synthesising from a locally-owned group.
    {
        let mut cache = state.group_card_cache.write().await;
        prune_and_bound_group_card_cache(&mut cache, now_millis_u64());
        if let Some(card) = cache.get(&id) {
            return Json(serde_json::to_value(card).unwrap_or(serde_json::Value::Null))
                .into_response();
        }
    }
    let groups = state.named_groups.read().await;
    if let Some(info) = groups.get(&id) {
        match info.to_signed_group_card(state.agent.identity().agent_keypair()) {
            Ok(Some(card)) => {
                return Json(serde_json::to_value(&card).unwrap_or(serde_json::Value::Null))
                    .into_response();
            }
            Ok(None) => {}
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("card sign failed: {e}"),
                )
                .into_response();
            }
        }
    }
    not_found("card not found").into_response()
}

/// POST /groups/cards/import — accept a discoverable card into the local cache.
///
/// If no local `GroupInfo` exists for the group_id, creates a minimal "discovered"
/// stub so that the caller can submit join requests. The stub records the policy
/// summary (inferred from the card) but has an empty roster (the caller is not a
/// member yet) and no MLS group. When a `JoinRequestApproved` event arrives, the
/// stub is upgraded via `apply_named_group_metadata_event`.
async fn import_group_card(
    State(state): State<Arc<AppState>>,
    Json(card): Json<x0x::groups::GroupCard>,
) -> impl IntoResponse {
    if card.policy_summary.discoverability == x0x::groups::GroupDiscoverability::Hidden {
        return bad_request("card is hidden");
    }
    if let Err(e) = card.verify_signature() {
        return bad_request(format!("invalid signed card: {e}"));
    }
    let group_id = card.group_id.clone();
    let membership_lock = group_membership_lock(&state, &group_id).await;
    let _membership_guard = membership_lock.lock().await;

    if card.withdrawn {
        let mut cache = state.group_card_cache.write().await;
        prune_expired_group_cards(&mut cache, now_millis_u64());
        remove_group_card_if_not_stale(&mut cache, &card);
        drop(cache);

        let local = {
            let groups = state.named_groups.read().await;
            let local_group_key = groups.get(&group_id).map(|_| group_id.clone()).or_else(|| {
                groups
                    .iter()
                    .find(|(_, info)| info.stable_group_id() == group_id)
                    .map(|(key, _)| key.clone())
            });
            local_group_key.and_then(|key| {
                groups.get(&key).cloned().map(|info| {
                    let aliases = collect_same_stable_group_aliases(&groups, &key, Some(&group_id));
                    (key, info, aliases)
                })
            })
        };
        if let Some((key, info, aliases)) = local {
            let protects_keyed_local_group =
                local_group_has_protected_crypto_material(state.as_ref(), &info, &aliases).await;
            if withdrawn_card_can_terminally_mark_local_group(
                &info,
                &card,
                protects_keyed_local_group,
            ) {
                let mut next = info;
                if apply_withdrawn_group_card_to_group_info(&mut next, &card) {
                    retain_withdrawn_group_tombstone(&state, &key, next, "withdrawn_card_import")
                        .await;
                }
            } else if protects_keyed_local_group && group_card_supersedes_group_info(&card, &info) {
                tracing::warn!(
                    group_id = %LogHexId::group(&group_id),
                    authority = %LogHexId::agent(&card.authority_agent_id),
                    "ignored withdrawn card for live keyed group; signed withdrawal commit required"
                );
            }
        }
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "group_id": group_id, "withdrawn": true })),
        );
    }

    // Parse owner hex into an AgentId for the stub.
    let creator = match parse_agent_id_hex(&card.owner_agent_id) {
        Ok(id) => id,
        Err(_) => {
            return bad_request("invalid owner_agent_id");
        }
    };

    // Full policy is reconstructed from the card summary — all five axes round-trip.
    let policy = x0x::groups::GroupPolicy::from(&card.policy_summary);

    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, &group_id) {
            return api_error(StatusCode::CONFLICT, "group is withdrawn");
        }
    }

    {
        let mut cache = state.group_card_cache.write().await;
        prune_expired_group_cards(&mut cache, now_millis_u64());
        if cache_group_card_if_newer(&mut cache, group_id.clone(), card.clone()) {
            enforce_group_card_cache_cap(&mut cache);
        }
    }

    // Create or refresh a local stub GroupInfo keyed by the authority's
    // stable group id from the card.
    let mut groups = state.named_groups.write().await;
    if !groups.contains_key(&group_id) {
        let mut stub = x0x::groups::GroupInfo::with_policy(
            card.name.clone(),
            card.description.clone(),
            creator,
            group_id.clone(),
            policy.clone(),
        );
        if let Some(metadata_topic) = card.metadata_topic.clone() {
            stub.metadata_topic = metadata_topic;
        }
        // Imported stubs must preserve the authority's stable `group_id`
        // from the card. Recomputing a fresh genesis here would mint a new
        // local-only stable id, breaking public-topic alignment and any
        // state-hash / revision metadata copied from the discovered card.
        stub.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            group_id.clone(),
            card.owner_agent_id.clone(),
            card.created_at,
            String::new(),
        ));
        stub.created_at = card.created_at;
        stub.updated_at = card.updated_at;
        stub.state_revision = card.revision;
        if !card.state_hash.is_empty() {
            stub.state_hash = card.state_hash.clone();
        }
        stub.prev_state_hash = card.prev_state_hash.clone();
        stub.withdrawn = card.withdrawn;
        // The stub should not treat the caller as an admin — reset members_v2
        // and store the authority (from card) as the active Admin.
        stub.members_v2.clear();
        stub.members_v2.insert(
            card.owner_agent_id.clone(),
            x0x::groups::GroupMember::new_admin(card.owner_agent_id.clone(), None, card.created_at),
        );
        // Phase D.2: the importer is NOT a member yet. They must not have a
        // shared secret until a SecureShareDelivered envelope arrives after
        // approval. Clearing the auto-generated stub secret also prevents the
        // apply handler from treating "already have a secret at epoch 0" as
        // a reason to drop alice's delivery.
        stub.shared_secret = None;
        stub.secret_epoch = 0;
        groups.insert(group_id.clone(), stub);
    } else if let Some(existing) = groups.get_mut(&group_id) {
        existing.name = card.name.clone();
        existing.description = card.description.clone();
        existing.policy = policy;
        existing.created_at = card.created_at;
        existing.updated_at = card.updated_at;
        if let Some(metadata_topic) = card.metadata_topic.clone() {
            existing.metadata_topic = metadata_topic;
        }
        existing.state_revision = card.revision;
        if !card.state_hash.is_empty() {
            existing.state_hash = card.state_hash.clone();
        }
        existing.prev_state_hash = card.prev_state_hash.clone();
        existing.withdrawn = card.withdrawn;
        if existing
            .genesis
            .as_ref()
            .is_none_or(|genesis| genesis.group_id != group_id)
        {
            existing.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
                group_id.clone(),
                card.owner_agent_id.clone(),
                card.created_at,
                String::new(),
            ));
        }
        existing
            .members_v2
            .entry(card.owner_agent_id.clone())
            .or_insert_with(|| {
                x0x::groups::GroupMember::new_admin(
                    card.owner_agent_id.clone(),
                    None,
                    card.created_at,
                )
            });
    }
    drop(groups);
    save_named_groups(&state).await;
    ensure_named_group_listeners(Arc::clone(&state), &group_id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": group_id,
            // P1-9: be explicit about what an imported stub actually is. The
            // importer is not a member; they have no MLS state; admin
            // operations against this group from this daemon will be denied
            // until a JoinRequestApproved event promotes them.
            "stub": true,
            "discovered": true,
            "secure_access": false,
        })),
    )
}

// ---------------------------------------------------------------------------
// Phase D.2 — Group shared-secret encrypted content (GSS)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SecureEncryptRequest {
    /// Base64-encoded plaintext payload.
    payload_b64: String,
}

#[derive(Debug, Deserialize)]
struct SecureDecryptRequest {
    ciphertext_b64: String,
    /// GSS plane only: per-message nonce. Unused for TreeKEM, whose
    /// `ApplicationCiphertext` carries its own nonce.
    #[serde(default)]
    nonce_b64: String,
    /// GSS plane only: ciphertext epoch (checked against the local epoch).
    /// Unused for TreeKEM, whose epoch is embedded in the ciphertext.
    #[serde(default)]
    secret_epoch: u64,
}

/// POST /groups/:id/secure/encrypt — AEAD-encrypt content using the group's
/// current shared secret. Member-only.
///
/// This is a symmetric-key layer alongside the MLS roster: it gives honest
/// cross-daemon encrypt/decrypt with rekey-on-ban, but does NOT provide the
/// per-message forward secrecy that full MLS TreeKEM would. Documented as
/// Phase D.2 scope.
/// Guard for membership-mutating named-group endpoints that still require a
/// TreeKEM-specific transport shape (direct invites/adds and ban/unban).
///
/// Request-access joins and creator removals use real TreeKEM Commit/Welcome or
/// Commit transport. The remaining guarded handlers still run the legacy GSS
/// rekey path (`rotate_shared_secret` + per-recipient reseal), which would
/// silently re-introduce a shared secret and relabel the plane. Refuse those
/// endpoints loudly until they provide KeyPackage/Welcome or removal Commit
/// inputs.
fn treekem_membership_unsupported(
    info: &x0x::groups::GroupInfo,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        Some(api_error(StatusCode::NOT_IMPLEMENTED, "TreeKEM secure-group membership flow is not supported by this endpoint; use request-access approval/removal transport"))
    } else {
        None
    }
}

fn treekem_metadata_event_requires_phase3(_event: &NamedGroupMetadataEvent) -> bool {
    false
}

/// Encrypt `payload_b64` for a real-TreeKEM group (ADR-0012). The live group's
/// send-ratchet advances, so the snapshot is persisted before returning to
/// prevent send-generation (nonce) reuse across a restart. Returns the
/// self-describing `ApplicationCiphertext` as `ciphertext_b64`.
async fn treekem_group_encrypt(
    state: &AppState,
    group_id_hex: &str,
    stable_group_id: Option<&str>,
    payload_b64: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;
    let plaintext = match BASE64.decode(payload_b64) {
        Ok(p) => p,
        Err(_) => {
            return bad_request("invalid base64 payload");
        }
    };
    let group = {
        let map = state.treekem_groups.read().await;
        match map.get(group_id_hex) {
            Some(g) => Arc::clone(g),
            None => {
                return api_error(
                    StatusCode::FAILED_DEPENDENCY,
                    "TreeKEM group not loaded — restart or re-share required",
                );
            }
        }
    };
    let mut guard = group.lock().await;
    let ciphertext = match guard.encrypt_message(&plaintext) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("treekem encrypt failed: {e}"),
            );
        }
    };
    // Persist the advanced ratchet state before returning. Skipping a burned
    // generation on error is harmless (no reuse); a stale on-disk snapshot is
    // not, so a persist failure fails the request.
    if let Err(e) = persist_treekem_snapshot_bound(state, group_id_hex, &guard).await {
        tracing::error!(group_id = %group_id_hex, "failed to persist TreeKEM snapshot after encrypt: {e}");
        if let Some(resp) =
            reject_withdrawn_group_record_after_crypto(state, group_id_hex, stable_group_id).await
        {
            return resp;
        }
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist secure group state",
        );
    }
    let epoch = guard.epoch();
    drop(guard);
    secure_group_effect_response_after_terminality_recheck(
        state,
        group_id_hex,
        stable_group_id,
        serde_json::json!({
            "ok": true,
            "ciphertext_b64": BASE64.encode(&ciphertext),
            "secret_epoch": epoch,
            "secure_plane": "treekem",
        }),
    )
    .await
}

/// Decrypt a real-TreeKEM `ApplicationCiphertext` (ADR-0012). The per-sender
/// replay window advances, so the snapshot is persisted to keep replay
/// protection across a restart (best-effort: a persist failure is logged but
/// does not invalidate the already-recovered plaintext).
async fn treekem_group_decrypt(
    state: &AppState,
    group_id_hex: &str,
    stable_group_id: Option<&str>,
    ciphertext_b64: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;
    let ciphertext = match BASE64.decode(ciphertext_b64) {
        Ok(c) => c,
        Err(_) => {
            return bad_request("invalid base64 ciphertext");
        }
    };
    let group = {
        let map = state.treekem_groups.read().await;
        match map.get(group_id_hex) {
            Some(g) => Arc::clone(g),
            None => {
                return api_error(
                    StatusCode::FAILED_DEPENDENCY,
                    "TreeKEM group not loaded — restart or re-share required",
                );
            }
        }
    };
    let mut guard = group.lock().await;
    let plaintext = match guard.decrypt_message(&ciphertext) {
        Ok(p) => p,
        Err(e) => {
            return bad_request(format!("treekem decrypt failed: {e}"));
        }
    };
    // Persisting the receive replay window is best-effort. A failure here may
    // permit the same ciphertext to be accepted again after restart, but the
    // plaintext has already been validly recovered and retrying in-process would
    // hit the replay guard. Unlike send-side snapshot failure, this is not a
    // nonce-reuse risk, so return the plaintext and surface the persistence
    // problem in logs.
    if let Err(e) = persist_treekem_snapshot_bound(state, group_id_hex, &guard).await {
        tracing::error!(group_id = %group_id_hex, "failed to persist TreeKEM snapshot after decrypt: {e}");
        if let Some(resp) =
            reject_withdrawn_group_record_after_crypto(state, group_id_hex, stable_group_id).await
        {
            return resp;
        }
    }
    let epoch = guard.epoch();
    drop(guard);
    secure_group_effect_response_after_terminality_recheck(
        state,
        group_id_hex,
        stable_group_id,
        serde_json::json!({
            "ok": true,
            "payload_b64": BASE64.encode(&plaintext),
            "secret_epoch": epoch,
            "secure_plane": "treekem",
        }),
    )
    .await
}

async fn secure_group_encrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SecureEncryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.has_active_member(&caller_hex) {
        return forbidden("not a member");
    }
    if info.policy.confidentiality != x0x::groups::GroupConfidentiality::MlsEncrypted {
        return bad_request("group is not MlsEncrypted — use public send instead");
    }
    // ADR-0012: real-TreeKEM groups encrypt via the live group's ratchet, not
    // the GSS shared secret. Dispatch on the group's plane.
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        let stable_group_id = info.stable_group_id().to_string();
        drop(groups);
        return treekem_group_encrypt(
            state.as_ref(),
            &id,
            Some(&stable_group_id),
            &req.payload_b64,
        )
        .await;
    }
    let Some(key) = info.secure_message_key() else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "no shared secret available — await welcome or ask admin to re-share",
        );
    };
    let epoch = info.secret_epoch;
    let group_id_clone = info.stable_group_id().to_string();
    drop(groups);

    use base64::Engine as _;
    let plaintext = match BASE64.decode(&req.payload_b64) {
        Ok(p) => p,
        Err(_) => {
            return bad_request("invalid base64 payload");
        }
    };

    // Generate a fresh random nonce per message — epoch-keyed AEAD requires
    // per-message nonce uniqueness.
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    use chacha20poly1305::aead::{Aead, KeyInit};
    let cipher = match chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "cipher init failed");
        }
    };
    let aad = format!("x0x.group.secure|{}|{}", group_id_clone, epoch);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let ciphertext = match cipher.encrypt(
        nonce,
        chacha20poly1305::aead::Payload {
            msg: &plaintext,
            aad: aad.as_bytes(),
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encrypt failed: {e}"),
            );
        }
    };

    secure_group_effect_response_after_terminality_recheck(
        state.as_ref(),
        &id,
        Some(&group_id_clone),
        serde_json::json!({
            "ok": true,
            "ciphertext_b64": BASE64.encode(&ciphertext),
            "nonce_b64": BASE64.encode(nonce_bytes),
            "secret_epoch": epoch,
        }),
    )
    .await
}

/// POST /groups/:id/secure/decrypt — AEAD-decrypt content using the group's
/// shared secret at the given epoch.
///
/// Returns 400 if the caller's local shared-secret epoch differs from the
/// ciphertext epoch (i.e. they've been rekeyed out, or haven't caught up yet).
/// A banned peer with a stale secret cannot decrypt new-epoch messages — that
/// proves the rekey-on-ban semantics.
async fn secure_group_decrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SecureDecryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.has_active_member(&caller_hex) && !info.is_banned(&caller_hex) {
        // Removed/never-member callers can't decrypt.
        return forbidden("not a member");
    }
    // ADR-0012: real-TreeKEM groups decrypt via the live group's ratchet. A
    // removed member's leaf is gone from the live group, so decryption of a
    // post-removal epoch fails there — that is the FS/PCS guarantee.
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        let stable_group_id = info.stable_group_id().to_string();
        drop(groups);
        return treekem_group_decrypt(
            state.as_ref(),
            &id,
            Some(&stable_group_id),
            &req.ciphertext_b64,
        )
        .await;
    }
    let Some(local_secret) = info.shared_secret.clone() else {
        return api_error(StatusCode::FAILED_DEPENDENCY, "no shared secret available");
    };
    let local_epoch = info.secret_epoch;
    let group_id_clone = info.stable_group_id().to_string();
    drop(groups);

    // Caller's local epoch must match the ciphertext epoch. A banned member
    // keeps their pre-ban secret; they cannot decrypt ciphertexts at higher
    // epochs because they don't have the new secret.
    if req.secret_epoch != local_epoch {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "epoch mismatch — re-share required",
                "local_epoch": local_epoch,
                "ciphertext_epoch": req.secret_epoch,
            })),
        );
    }

    use base64::Engine as _;
    let ciphertext = match BASE64.decode(&req.ciphertext_b64) {
        Ok(c) => c,
        Err(_) => {
            return bad_request("invalid base64 ciphertext");
        }
    };
    let nonce_bytes = match BASE64.decode(&req.nonce_b64) {
        Ok(n) => n,
        Err(_) => {
            return bad_request("invalid base64 nonce");
        }
    };
    if nonce_bytes.len() != 12 {
        return bad_request("nonce must be 12 bytes");
    }

    let key = x0x::groups::GroupInfo::derive_message_key(
        &local_secret,
        req.secret_epoch,
        &group_id_clone,
    );
    use chacha20poly1305::aead::{Aead, KeyInit};
    let cipher = match chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "cipher init failed");
        }
    };
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let aad = format!("x0x.group.secure|{}|{}", group_id_clone, req.secret_epoch);
    match cipher.decrypt(
        nonce,
        chacha20poly1305::aead::Payload {
            msg: &ciphertext,
            aad: aad.as_bytes(),
        },
    ) {
        Ok(plaintext) => {
            secure_group_effect_response_after_terminality_recheck(
                state.as_ref(),
                &id,
                Some(&group_id_clone),
                serde_json::json!({
                    "ok": true,
                    "payload_b64": BASE64.encode(&plaintext),
                    "secret_epoch": req.secret_epoch,
                }),
            )
            .await
        }
        Err(_) => forbidden("decryption failed"),
    }
}

/// POST /groups/:id/secure/reseal — produce a real `SecureShareDelivered`-
/// format envelope sealing the group's CURRENT shared secret to a named
/// recipient's ML-KEM-768 public key.
///
/// Authorization:
/// - Caller must pass `info.has_active_member(&caller_hex)` (403 otherwise).
/// - The caller's daemon must already hold `info.shared_secret` locally
///   (424 FAILED_DEPENDENCY otherwise).
///
/// These two checks together ensure the endpoint grants no capability the
/// caller does not already possess: an active member whose daemon holds the
/// current secret could re-seal it themselves at the primitive layer using
/// `seal_group_secret_to_recipient`. Note: the active-member check alone is
/// not sufficient — a freshly-approved member is Active before their gossip-
/// delivered envelope arrives; in that window `info.shared_secret` is None
/// and this endpoint returns 424.
///
/// The recipient must be a known member of the group with a published KEM
/// public key (404 / 424 otherwise).
///
/// Used by the D.2 adversarial E2E proof to obtain a **real live-path
/// envelope** (produced via the same `seal_group_secret_to_recipient` +
/// `secure_share_aad` path used on the approve/ban hot path) that can then
/// be posted to another daemon's `POST /groups/secure/open-envelope` to
/// demonstrate that a non-recipient cannot open it — stronger than the
/// "random bytes" adversarial check because the envelope is a genuine
/// sealing-path output bound to the current epoch + AAD.
#[derive(Debug, Deserialize)]
struct ResealRequest {
    /// Agent hex of the recipient whose ML-KEM public key will be used to
    /// seal the envelope. Must be an active member of the group.
    recipient: String,
}

async fn secure_group_reseal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ResealRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.has_active_member(&caller_hex) {
        return forbidden("not a member");
    }
    // Recipient must be a known member with a KEM pubkey.
    let Some(recipient_member) = info.members_v2.get(&req.recipient) else {
        return not_found("recipient is not a member");
    };
    let Some(recipient_kem_b64) = recipient_member.kem_public_key_b64.clone() else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "recipient has no published KEM public key",
        );
    };
    let Some(secret_vec) = info.shared_secret.clone() else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "no shared secret available on this daemon",
        );
    };
    let epoch = info.secret_epoch;
    let group_id_wire = info.stable_group_id().to_string();
    drop(groups);

    if secret_vec.len() != 32 {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "shared secret has unexpected length",
        );
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_vec);

    use base64::Engine as _;
    let recipient_kem_bytes = match BASE64.decode(&recipient_kem_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("recipient KEM public key is not valid base64");
        }
    };
    let aad = secure_share_aad(&group_id_wire, &req.recipient, epoch);
    let (kem_ct, aead_nonce, aead_ct) =
        match x0x::groups::kem_envelope::seal_group_secret_to_recipient(
            &recipient_kem_bytes,
            &aad,
            &secret,
        ) {
            Ok(t) => t,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };

    secure_group_effect_response_after_terminality_recheck(
        state.as_ref(),
        &id,
        Some(&group_id_wire),
        serde_json::json!({
            "ok": true,
            "group_id": group_id_wire,
            "recipient": req.recipient,
            "secret_epoch": epoch,
            "kem_ciphertext_b64": BASE64.encode(&kem_ct),
            "aead_nonce_b64": BASE64.encode(aead_nonce),
            "aead_ciphertext_b64": BASE64.encode(&aead_ct),
        }),
    )
    .await
}

/// POST /groups/secure/open-envelope — ADVERSARIAL TEST endpoint.
///
/// Attempt to open a `SecureShareDelivered` envelope using THIS daemon's
/// ML-KEM-768 private key. If the envelope was not sealed to our public
/// key, this MUST fail. Used by `tests/e2e_named_groups.sh` section 2c to
/// prove recipient-confidentiality: an observer (different daemon, different
/// KEM keypair) cannot recover the group secret from a captured envelope.
#[derive(Debug, Deserialize)]
struct OpenEnvelopeRequest {
    group_id: String,
    recipient: String,
    secret_epoch: u64,
    kem_ciphertext_b64: String,
    aead_nonce_b64: String,
    aead_ciphertext_b64: String,
}

async fn secure_open_envelope_adversarial(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenEnvelopeRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    {
        let groups = state.named_groups.read().await;
        if let Some(resp) = open_envelope_withdrawn_group_conflict(&groups, &req.group_id) {
            return resp;
        }
    }
    use base64::Engine as _;
    let kem_ct = match BASE64.decode(&req.kem_ciphertext_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("bad kem_ciphertext_b64");
        }
    };
    let nonce = match BASE64.decode(&req.aead_nonce_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("bad aead_nonce_b64");
        }
    };
    if nonce.len() != 12 {
        return bad_request("nonce must be 12 bytes");
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce);
    let aead_ct = match BASE64.decode(&req.aead_ciphertext_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("bad aead_ciphertext_b64");
        }
    };
    let aad = secure_share_aad(&req.group_id, &req.recipient, req.secret_epoch);
    match x0x::groups::kem_envelope::open_group_secret(
        &state.agent_kem_keypair,
        &aad,
        &kem_ct,
        &nonce_bytes,
        &aead_ct,
    ) {
        Ok(secret) => {
            open_envelope_effect_response_after_terminality_recheck(
                state.as_ref(),
                &req.group_id,
                serde_json::json!({
                    "ok": true,
                    "opened": true,
                    "secret_b64": BASE64.encode(secret),
                }),
            )
            .await
        }
        Err(_) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "opened": false,
                "error": "envelope not decryptable by this daemon's key",
            })),
        ),
    }
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /task-lists/:id/tasks
async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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
        return not_found("task list not found");
    };

    match handle
        .add_task(req.title, req.description.unwrap_or_default())
        .await
    {
        Ok(task_id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "ok": true, "task_id": format!("{task_id}") })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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
        return not_found("task list not found");
    };

    // Parse task ID from hex
    let task_id_bytes: [u8; 32] = match hex::decode(&tid) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid task ID (expected 64 hex chars)");
        }
    };
    let task_id = x0x::crdt::TaskId::from_bytes(task_id_bytes);

    let result = match req.action.as_str() {
        "claim" => handle.claim_task(task_id).await,
        "complete" => handle.complete_task(task_id).await,
        _ => {
            return bad_request("action must be 'claim' or 'complete'");
        }
    };

    match result {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Embedded GUI
// ---------------------------------------------------------------------------

/// The embedded GUI HTML, compiled into the binary.
const GUI_HTML: &str = include_str!("../gui/x0x-gui.html");

/// GET /gui — serve the embedded GUI shell.
async fn serve_gui() -> impl IntoResponse {
    axum::response::Html(render_gui_html())
}

fn render_gui_html() -> String {
    GUI_HTML.replace("<!-- X0X_TOKEN_INJECTION_POINT -->", "")
}

// ---------------------------------------------------------------------------
// KvStore handlers
// ---------------------------------------------------------------------------

fn encode_kv_store_delta_direct_payload(
    store_id: &str,
    peer_id: saorsa_gossip_types::PeerId,
    delta: &x0x::kv::KvStoreDelta,
) -> serde_json::Result<Vec<u8>> {
    let msg = KvStoreDirectDelta {
        store_id: store_id.to_string(),
        peer_id,
        delta: delta.clone(),
    };
    let json = serde_json::to_vec(&msg)?;
    let mut payload = Vec::with_capacity(KV_STORE_DELTA_DM_PREFIX.len() + json.len());
    payload.extend_from_slice(KV_STORE_DELTA_DM_PREFIX);
    payload.extend_from_slice(&json);
    Ok(payload)
}

fn kv_store_delta_direct_delivery_config() -> x0x::dm::DmSendConfig {
    let mut config = direct_message_send_config();
    config.require_gossip = true;
    config.require_gossip_ack = true;
    config
}

async fn kv_store_delta_direct_recipients(state: &AppState) -> Vec<String> {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let contacts = state.contacts.read().await;
    contacts
        .list()
        .into_iter()
        .filter_map(|contact| {
            let recipient = hex::encode(contact.agent_id.as_bytes());
            if recipient == local_agent_hex || contact.trust_level == TrustLevel::Blocked {
                return None;
            }
            let caps = contact.dm_capabilities.as_ref()?;
            if !caps.gossip_inbox || caps.kem_public_key.is_empty() {
                return None;
            }
            Some(recipient)
        })
        .collect()
}

fn spawn_kv_store_delta_delivery_one(
    state: &AppState,
    recipient_hex: &str,
    store_id: &str,
    peer_id: saorsa_gossip_types::PeerId,
    delta: &x0x::kv::KvStoreDelta,
    delay: Option<Duration>,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                recipient = %LogHexId::agent(&recipient_hex),
                "cannot direct-deliver kv-store delta: invalid recipient id: {e}"
            );
            return;
        }
    };
    let payload = match encode_kv_store_delta_direct_payload(store_id, peer_id, delta) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(
                store_id,
                "failed to serialize kv-store delta for direct delivery: {e}"
            );
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let recipient_label = recipient_hex.to_string();
    let store_label = store_id.to_string();
    tokio::spawn(async move {
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if let Err(e) = agent
            .send_direct_with_config(&recipient, payload, kv_store_delta_direct_delivery_config())
            .await
        {
            tracing::warn!(
                store_id = %store_label,
                recipient = %LogHexId::agent(&recipient_label),
                "failed to direct-deliver kv-store delta: {e}"
            );
        }
    });
}

fn spawn_kv_store_delta_delivery(
    state: &AppState,
    recipients: Vec<String>,
    store_id: &str,
    peer_id: saorsa_gossip_types::PeerId,
    delta: &x0x::kv::KvStoreDelta,
) {
    for recipient in recipients {
        spawn_kv_store_delta_delivery_one(state, &recipient, store_id, peer_id, delta, None);
        spawn_kv_store_delta_delivery_one(
            state,
            &recipient,
            store_id,
            peer_id,
            delta,
            Some(GROUP_BACKGROUND_PUBLISH_DELAY),
        );
    }
}

async fn apply_direct_kv_store_delta(
    state: &AppState,
    sender: x0x::identity::AgentId,
    delta_msg: KvStoreDirectDelta,
) {
    let store_id = delta_msg.store_id.clone();
    let handle = {
        let stores = state.kv_stores.read().await;
        stores.get(&store_id).cloned()
    };
    let Some(handle) = handle else {
        tracing::debug!(
            store_id = %store_id,
            sender = %hex::encode(sender.as_bytes()),
            "ignoring direct kv-store delta for unjoined store"
        );
        return;
    };
    if let Err(e) = handle
        .apply_remote_delta(delta_msg.peer_id, &delta_msg.delta, Some(sender))
        .await
    {
        tracing::warn!(
            store_id = %store_id,
            "failed to apply direct kv-store delta: {e}"
        );
    }
}

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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /stores/:id/keys
async fn list_kv_keys(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return not_found("store not found");
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// PUT /stores/:id/:key
async fn put_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
    Json(req): Json<PutValueRequest>,
) -> impl IntoResponse {
    let handle = {
        let stores = state.kv_stores.read().await;
        let Some(handle) = stores.get(&id) else {
            return not_found("store not found");
        };
        handle.clone()
    };

    use base64::Engine;
    let value = match BASE64.decode(&req.value) {
        Ok(v) => v,
        Err(e) => {
            return bad_request(format!("invalid base64: {e}"));
        }
    };

    let content_type = req
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    match handle.put_with_delta(key, value, content_type).await {
        Ok(delta) => {
            let recipients = kv_store_delta_direct_recipients(&state).await;
            spawn_kv_store_delta_delivery(&state, recipients, &id, handle.peer_id(), &delta);
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => {
            let status = if format!("{e}").contains("value too large") {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
            )
        }
    }
}

/// GET /stores/:id/:key
async fn get_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return not_found("store not found");
    };

    match handle.get(&key).await {
        Ok(Some(entry)) => {
            use base64::Engine;
            let value_b64 = BASE64.encode(&entry.value);
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
        Ok(None) => not_found("key not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// DELETE /stores/:id/:key
async fn delete_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let handle = {
        let stores = state.kv_stores.read().await;
        let Some(handle) = stores.get(&id) else {
            return not_found("store not found");
        };
        handle.clone()
    };

    match handle.remove_with_delta(&key).await {
        Ok(delta) => {
            let recipients = kv_store_delta_direct_recipients(&state).await;
            spawn_kv_store_delta_delivery(&state, recipients, &id, handle.peer_id(), &delta);
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
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

    // Apply a 60-second overall timeout to prevent indefinite hangs when
    // the agent has multiple unreachable addresses (each with its own 30s
    // QUIC timeout).
    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        state.agent.connect_to_agent(&agent_id),
    )
    .await;

    match connect_result {
        Ok(Ok(outcome)) => {
            let (outcome_str, addr) = match outcome {
                x0x::connectivity::ConnectOutcome::Direct(a) => ("Direct", Some(a.to_string())),
                x0x::connectivity::ConnectOutcome::Coordinated(a) => {
                    ("Coordinated", Some(a.to_string()))
                }
                x0x::connectivity::ConnectOutcome::AlreadyConnected => ("AlreadyConnected", None),
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
        Ok(Err(e)) => {
            tracing::error!("connect_agent failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "connection failed")
        }
        Err(_elapsed) => {
            tracing::warn!(
                "connect_agent timed out after 60s for agent {}",
                req.agent_id
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "outcome": "Unreachable",
                    "addr": null
                })),
            )
        }
    }
}

/// POST /machines/connect — connect to a discovered machine.
async fn connect_machine(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectMachineRequest>,
) -> impl IntoResponse {
    let machine_id = match parse_machine_id_hex(&req.machine_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        state.agent.connect_to_machine(&machine_id),
    )
    .await;

    match connect_result {
        Ok(Ok(outcome)) => {
            let (outcome_str, addr) = match outcome {
                x0x::connectivity::ConnectOutcome::Direct(a) => ("Direct", Some(a.to_string())),
                x0x::connectivity::ConnectOutcome::Coordinated(a) => {
                    ("Coordinated", Some(a.to_string()))
                }
                x0x::connectivity::ConnectOutcome::AlreadyConnected => ("AlreadyConnected", None),
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
        Ok(Err(e)) => {
            tracing::error!("connect_machine failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "connection failed")
        }
        Err(_elapsed) => {
            tracing::warn!(
                "connect_machine timed out after 60s for machine {}",
                req.machine_id
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "outcome": "Unreachable",
                    "addr": null
                })),
            )
        }
    }
}

/// POST /exec/run — run a strictly allowlisted command on a remote daemon.
async fn exec_run(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ExecRunRequest>,
) -> axum::response::Response {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };
    if req.argv.is_empty() {
        return bad_request("argv must not be empty").into_response();
    }
    let stdin = match req.stdin_b64.as_deref() {
        Some(encoded) => match BASE64.decode(encoded) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                return bad_request(format!("invalid stdin_b64: {e}")).into_response();
            }
        },
        None => None,
    };
    let options = x0x::exec::ExecRunOptions {
        argv: req.argv,
        stdin,
        timeout_ms: req.timeout_ms,
        cwd: req.cwd,
    };
    match state.exec_service.run_remote(agent_id, options).await {
        Ok(result) => {
            let denial_reason = result.denial_reason.map(|r| r.as_str());
            let warnings: Vec<&'static str> = result.warnings.iter().map(|w| w.as_str()).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "request_id": result.request_id.to_hex(),
                    "code": result.code,
                    "signal": result.signal,
                    "duration_ms": result.duration_ms,
                    "stdout_b64": BASE64.encode(&result.stdout),
                    "stderr_b64": BASE64.encode(&result.stderr),
                    "stdout_bytes_total": result.stdout_bytes_total,
                    "stderr_bytes_total": result.stderr_bytes_total,
                    "truncated": result.truncated,
                    "denial_reason": denial_reason,
                    "warnings": warnings,
                })),
            )
                .into_response()
        }
        Err(e) => {
            let status = match e {
                x0x::exec::service::ExecServiceError::Protocol(_) => StatusCode::BAD_REQUEST,
                x0x::exec::service::ExecServiceError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                x0x::exec::service::ExecServiceError::ResponseChannelClosed => {
                    StatusCode::BAD_GATEWAY
                }
                x0x::exec::service::ExecServiceError::Transport(_)
                | x0x::exec::service::ExecServiceError::Denied(_) => StatusCode::BAD_GATEWAY,
            };
            (
                status,
                Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// POST /exec/cancel — cancel an in-flight exec request originated by this daemon.
async fn exec_cancel(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ExecCancelRequest>,
) -> axum::response::Response {
    let request_id = match x0x::exec::ExecRequestId::from_hex(&req.request_id) {
        Ok(id) => id,
        Err(e) => {
            return bad_request(e.to_string()).into_response();
        }
    };
    let target = match req.agent_id.as_deref() {
        Some(agent_hex) => match parse_agent_id_hex(agent_hex) {
            Ok(id) => Some(id),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                )
                    .into_response();
            }
        },
        None => None,
    };
    match state.exec_service.cancel_remote(request_id, target).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => api_error(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// GET /exec/sessions — list local pending client sessions and remote active sessions.
async fn exec_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.exec_service.sessions_snapshot().await)
}

/// GET /diagnostics/exec — exec counters, active sessions, and safe ACL summary.
async fn exec_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.exec_service.diagnostics_snapshot().await)
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
                return forbidden("agent is blocked");
            }
        }
    }

    let payload = match decode_base64_payload(&req.payload) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let mut send_config = direct_message_send_config();
    send_config.prefer_raw_quic_if_connected = req.prefer_raw_quic_if_connected;
    send_config.stop_fallback_on_raw_error = req.stop_fallback_on_raw_error;
    send_config.require_gossip = req.require_gossip;
    if let Some(require_gossip_ack) = req.require_gossip_ack {
        send_config.require_gossip_ack = require_gossip_ack;
    }
    if let Some(raw_ack_ms) = req.raw_quic_receive_ack_ms {
        send_config.raw_quic_receive_ack_timeout = Some(std::time::Duration::from_millis(
            raw_ack_ms.clamp(100, 30_000),
        ));
    }

    match state
        .agent
        .send_direct_with_config(&agent_id, payload, send_config)
        .await
    {
        Ok(receipt) => {
            let path_str = match receipt.path {
                x0x::dm::DmPath::Loopback => "loopback",
                x0x::dm::DmPath::GossipInbox => "gossip_inbox",
                x0x::dm::DmPath::RawQuic => "raw_quic",
                x0x::dm::DmPath::RawQuicAcked => "raw_quic_acked",
            };
            tracing::debug!(
                target: "dm.trace",
                stage = "accepted_at_api",
                request_id = %hex::encode(receipt.request_id),
                recipient = %hex::encode(agent_id.as_bytes()),
                path = path_str,
                retries_used = receipt.retries_used,
            );
            // Optional post-send liveness confirmation via ant-quic's
            // `probe_peer` primitive. Proves the peer's receive pipeline is
            // alive; it does NOT prove this specific message was delivered
            // (the DM envelope may have been re-broadcast through the caps
            // topic even when raw_quic was the chosen path).
            let ack_result = if let Some(ack_ms) = req.require_ack_ms {
                let ack_timeout = std::time::Duration::from_millis(ack_ms.clamp(100, 30_000));
                if let Some(network) = state.agent.network() {
                    // Resolve AgentId → MachineId via discovery cache, then
                    // reinterpret the 32 bytes as an ant_quic PeerId (they
                    // are the same hash by construction — see CLAUDE.md).
                    let discovered = state.agent.discovered_agent(agent_id).await.ok().flatten();
                    if let Some(rec) = discovered {
                        let peer_id = ant_quic::PeerId(rec.machine_id.0);
                        match network.probe_peer(peer_id, ack_timeout).await {
                            Some(Ok(rtt)) => Some(serde_json::json!({
                                "ok": true,
                                "rtt_ms": rtt.as_millis() as u64,
                            })),
                            Some(Err(e)) => Some(serde_json::json!({
                                "ok": false,
                                "error": format!("probe failed: {e}"),
                            })),
                            None => Some(serde_json::json!({
                                "ok": false,
                                "error": "network node not running",
                            })),
                        }
                    } else {
                        Some(serde_json::json!({
                            "ok": false,
                            "error": "agent not in discovery cache (peer_id unknown)",
                        }))
                    }
                } else {
                    Some(serde_json::json!({
                        "ok": false,
                        "error": "network not initialized",
                    }))
                }
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "path": path_str,
                    "retries_used": receipt.retries_used,
                    "request_id": hex::encode(receipt.request_id),
                    "require_ack": ack_result,
                })),
            )
        }
        Err(e) => {
            let (status, err_kind) = match &e {
                x0x::dm::DmError::RecipientRejected { .. } => {
                    (StatusCode::FORBIDDEN, "recipient_rejected")
                }
                x0x::dm::DmError::RecipientKeyUnavailable(_) => {
                    (StatusCode::NOT_FOUND, "recipient_key_unavailable")
                }
                x0x::dm::DmError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
                x0x::dm::DmError::PeerLikelyOffline { .. } => {
                    (StatusCode::BAD_GATEWAY, "peer_likely_offline")
                }
                x0x::dm::DmError::PeerDisconnected { .. } => {
                    (StatusCode::BAD_GATEWAY, "peer_disconnected")
                }
                x0x::dm::DmError::ReceiverBackpressured { .. } => {
                    (StatusCode::SERVICE_UNAVAILABLE, "receiver_backpressured")
                }
                x0x::dm::DmError::LocalGossipUnavailable(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "local_gossip_unavailable")
                }
                x0x::dm::DmError::EnvelopeConstruction(_) => {
                    (StatusCode::BAD_REQUEST, "envelope_construction")
                }
                x0x::dm::DmError::PayloadTooLarge { .. } => {
                    (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
                }
                x0x::dm::DmError::NoConnectivity(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "no_connectivity")
                }
                x0x::dm::DmError::PublishFailed(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "publish_failed")
                }
            };
            tracing::error!("direct_send failed ({err_kind}): {e}");
            (
                status,
                Json(serde_json::json!({
                    "ok": false,
                    "error": err_kind,
                    "detail": e.to_string(),
                })),
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
                return bad_request(format!("invalid hex: {e}"));
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
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
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
        return not_found("group not found");
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
        return not_found("group not found");
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
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "operation failed")
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
        return not_found("group not found");
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
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// POST /mls/groups/:id/encrypt — encrypt data with group key.
async fn mls_encrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MlsEncryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let plaintext = match decode_base64_payload(&req.payload) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return not_found("group not found");
    };

    let (cipher, epoch) = match make_mls_cipher(group) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match cipher.encrypt(&plaintext, &[], epoch) {
        Ok(ciphertext) => {
            drop(groups);
            secure_group_effect_response_after_terminality_recheck(
                state.as_ref(),
                &id,
                Some(&id),
                serde_json::json!({
                "ok": true,
                "ciphertext": BASE64.encode(&ciphertext),
                "epoch": epoch
                }),
            )
            .await
        }
        Err(e) => {
            tracing::error!("mls_encrypt failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "encryption failed")
        }
    }
}

/// POST /mls/groups/:id/decrypt — decrypt data with group key.
async fn mls_decrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MlsDecryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ciphertext = match decode_base64_payload(&req.ciphertext) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return not_found("group not found");
    };

    let (cipher, _epoch) = match make_mls_cipher(group) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match cipher.decrypt(&ciphertext, &[], req.epoch) {
        Ok(plaintext) => {
            drop(groups);
            secure_group_effect_response_after_terminality_recheck(
                state.as_ref(),
                &id,
                Some(&id),
                serde_json::json!({
                "ok": true,
                "payload": BASE64.encode(&plaintext)
                }),
            )
            .await
        }
        Err(e) => {
            tracing::error!("mls_decrypt failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "decryption failed")
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
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "search failed")
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
        None => not_found("agent not in discovery cache"),
    }
}

// ---------------------------------------------------------------------------
// Contact trust extension handlers
// ---------------------------------------------------------------------------

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
            return bad_request("invalid machine_id hex");
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
        return not_found("group not found");
    };

    match x0x::mls::MlsWelcome::create(group, &invitee) {
        Ok(welcome) => {
            let welcome_bytes = match bincode::serialize(&welcome) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("welcome serialization failed: {e}");
                    return api_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed");
                }
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "welcome": BASE64.encode(&welcome_bytes),
                    "group_id": id,
                    "epoch": welcome.epoch()
                })),
            )
        }
        Err(e) => {
            tracing::error!("create_mls_welcome failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "welcome creation failed")
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
        "ok": true,
        "version": x0x::constitution::CONSTITUTION_VERSION,
        "status": x0x::constitution::CONSTITUTION_STATUS,
        "content": x0x::constitution::CONSTITUTION_MD,
    }))
}

// ---------------------------------------------------------------------------
// Upgrade check handler
// ---------------------------------------------------------------------------

/// GET /upgrade — check for available updates.
async fn check_upgrade(State(state): State<Arc<AppState>>) -> Response {
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
async fn apply_upgrade(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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
        None => api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized"),
    }
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn value_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|obj| obj.get(key))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

fn augment_pubsub_stage_diagnostics<T>(snapshot: Option<T>) -> serde_json::Value
where
    T: Serialize,
{
    let Ok(mut value) = serde_json::to_value(snapshot) else {
        return serde_json::Value::Null;
    };
    let Some(obj) = value.as_object_mut() else {
        return value;
    };

    if !obj.contains_key("suppressed_peers_by_topic") {
        let mut by_topic: BTreeMap<String, Vec<String>> = BTreeMap::new();
        if let Some(rows) = obj.get("suppressed_peers").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(topic) = value_string_field(row, "topic") else {
                    continue;
                };
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                by_topic.entry(topic).or_default().push(peer_id);
            }
        }
        for peers in by_topic.values_mut() {
            peers.sort();
            peers.dedup();
        }
        obj.insert(
            "suppressed_peers_by_topic".to_string(),
            serde_json::json!(by_topic),
        );
    }

    if !obj.contains_key("peer_scores_by_topic") {
        let mut suppression_by_topic_peer: BTreeMap<(String, String), serde_json::Value> =
            BTreeMap::new();
        if let Some(rows) = obj.get("suppressed_peers").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(topic) = value_string_field(row, "topic") else {
                    continue;
                };
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                suppression_by_topic_peer.insert((topic, peer_id), row.clone());
            }
        }

        let mut by_topic: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        if let Some(rows) = obj.get("peer_scores").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(topic) = value_string_field(row, "topic") else {
                    continue;
                };
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                let suppressed = suppression_by_topic_peer.get(&(topic.clone(), peer_id.clone()));
                by_topic.entry(topic).or_default().insert(
                    peer_id,
                    serde_json::json!({
                        "role": row.get("role").cloned().unwrap_or(serde_json::Value::Null),
                        "score": row.get("score").cloned().unwrap_or(serde_json::Value::Null),
                        "send_health": row.get("send_health").cloned().unwrap_or(serde_json::Value::Null),
                        "outbound_send_timeouts": row
                            .get("outbound_send_timeouts")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "cooling_events": row
                            .get("cooling_events")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "eager_eligible": row
                            .get("eager_eligible")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "suppression_state": suppressed
                            .and_then(|s| s.get("state"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "recent_timeout_count": suppressed
                            .and_then(|s| s.get("recent_timeout_count"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "cooldown_ms": suppressed
                            .and_then(|s| s.get("cooldown_ms"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "last_cool_at_unix_ms": suppressed
                            .and_then(|s| s.get("last_suppressed_unix_ms"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                    }),
                );
            }
        }
        obj.insert(
            "peer_scores_by_topic".to_string(),
            serde_json::json!(by_topic),
        );
    }

    if !obj.contains_key("admission_state_by_peer") {
        #[derive(Default)]
        struct AdmissionCounts {
            suppressed: usize,
            cooled: usize,
            recovery_probe: usize,
            recovery_ready: usize,
        }

        let mut by_peer: BTreeMap<String, AdmissionCounts> = BTreeMap::new();
        if let Some(rows) = obj.get("suppressed_peers").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                let entry = by_peer.entry(peer_id).or_default();
                entry.suppressed += 1;
                match value_string_field(row, "state").as_deref() {
                    Some("recovery_probe") => entry.recovery_probe += 1,
                    Some("recovery_ready") => entry.recovery_ready += 1,
                    _ => entry.cooled += 1,
                }
            }
        }

        let mut admission: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        for (peer_id, counts) in by_peer {
            let state = if counts.cooled > 0 {
                "cooled"
            } else if counts.recovery_probe > 0 {
                "recovery_probe"
            } else if counts.recovery_ready > 0 {
                "recovery_ready"
            } else {
                "alive"
            };
            admission.insert(
                peer_id,
                serde_json::json!({
                    "state": state,
                    "suppressed_topics_count": counts.suppressed,
                    "cooled_topics_count": counts.cooled,
                    "recovery_probe_topics_count": counts.recovery_probe,
                    "recovery_ready_topics_count": counts.recovery_ready,
                    "priority_queue_depths": {},
                }),
            );
        }
        obj.insert(
            "admission_state_by_peer".to_string(),
            serde_json::json!(admission),
        );
    }

    value
}

/// GET /diagnostics/connectivity — ant-quic NodeStatus snapshot.
///
/// Returns the full connectivity state so we can answer:
/// - Is UPnP port mapping active?
/// - What external addresses have been observed?
/// - What NAT type has ant-quic detected?
/// - Direct vs relayed connection counts, hole-punch success rate, avg RTT.
/// - mDNS browsing/advertising state and discovered peer count.
///
/// This is the primary observability surface for the 100%-connectivity
/// guarantee ant-quic is responsible for.
async fn connectivity_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized");
    };

    match network.node_status().await {
        Some(ns) => {
            // X0X-0039: real `data_tx` saturation snapshot from ant-quic 0.27.13.
            let data_tx = network.data_channel_diagnostics().await;
            // X0X-0043: real GSO bundle send snapshot from ant-quic 0.27.13.
            let gso = network.gso_diagnostics().await;
            let connection_pool = network.connection_pool_diagnostics();
            let now = Instant::now();
            let mut per_peer_transport = Vec::new();
            // ADR-0011 §4: accumulate path-quality signals across peers so the
            // transport-environment assessment can spot a constrained-MTU /
            // black-holed path even when only some peers are affected.
            let mut min_observed_mtu: Option<u16> = None;
            let mut lost_plpmtud_probes_total: u64 = 0;
            let mut black_holes_total: u64 = 0;
            for peer_id in network.connected_peers().await {
                let health = network.connection_health(peer_id).await;
                let transport_stats = network.connection_transport_stats(peer_id).await;
                let (
                    connected,
                    generation,
                    reader_task_active,
                    last_sent_ago_ms,
                    last_received_ago_ms,
                    idle_for_ms,
                    close_reason,
                ) = match health {
                    Some(health) => (
                        health.connected,
                        health.generation,
                        health.reader_task_active,
                        health.last_sent_at.map(|instant| {
                            duration_millis_u64(now.saturating_duration_since(instant))
                        }),
                        health.last_received_at.map(|instant| {
                            duration_millis_u64(now.saturating_duration_since(instant))
                        }),
                        health.idle_for.map(duration_millis_u64),
                        health.close_reason.map(|reason| format!("{reason:?}")),
                    ),
                    None => (false, None, None, None, None, None, None),
                };
                let row = match transport_stats {
                    Some(ts) => {
                        if let Some(mtu) = ts.current_mtu {
                            min_observed_mtu = Some(min_observed_mtu.map_or(mtu, |m| m.min(mtu)));
                        }
                        lost_plpmtud_probes_total += ts.lost_plpmtud_probes;
                        black_holes_total += ts.black_holes_detected;
                        serde_json::json!({
                        "peer_id": hex::encode(peer_id.0),
                        "transport": "quic",
                        "stats_available": true,
                        "connected": ts.connected || connected,
                        "generation": ts.generation.or(generation),
                        "reader_task_active": reader_task_active,
                        "rtt_ms": ts.rtt_ms,
                        "udp_tx_bytes": ts.udp_tx_bytes,
                        "udp_rx_bytes": ts.udp_rx_bytes,
                        "udp_tx_datagrams": ts.udp_tx_datagrams,
                        "udp_rx_datagrams": ts.udp_rx_datagrams,
                        "congestion_window": ts.congestion_window,
                        "congestion_events": ts.congestion_events,
                        "lost_packets": ts.lost_packets,
                        "lost_bytes": ts.lost_bytes,
                        "sent_packets": ts.sent_packets,
                        "sent_plpmtud_probes": ts.sent_plpmtud_probes,
                        "lost_plpmtud_probes": ts.lost_plpmtud_probes,
                        "black_holes_detected": ts.black_holes_detected,
                        "packet_loss_rate": ts.packet_loss_rate,
                        "current_mtu": ts.current_mtu,
                        "stream_open_blocked_events": ts.stream_open_blocked_events,
                        "data_blocked_events": ts.data_blocked_events,
                        "stream_data_blocked_events": ts.stream_data_blocked_events,
                        "last_sent_ago_ms": ts.last_sent_ago_ms.or(last_sent_ago_ms),
                        "last_received_ago_ms": ts.last_received_ago_ms.or(last_received_ago_ms),
                        "idle_for_ms": ts.idle_for_ms.or(idle_for_ms),
                        "close_reason": close_reason,
                        })
                    }
                    None => serde_json::json!({
                        "peer_id": hex::encode(peer_id.0),
                        "transport": "quic",
                        "stats_available": false,
                        "connected": connected,
                        "generation": generation,
                        "reader_task_active": reader_task_active,
                        "rtt_ms": null,
                        "udp_tx_bytes": null,
                        "udp_rx_bytes": null,
                        "udp_tx_datagrams": null,
                        "udp_rx_datagrams": null,
                        "congestion_window": null,
                        "congestion_events": null,
                        "lost_packets": null,
                        "lost_bytes": null,
                        "sent_packets": null,
                        "sent_plpmtud_probes": null,
                        "lost_plpmtud_probes": null,
                        "black_holes_detected": null,
                        "packet_loss_rate": null,
                        "current_mtu": null,
                        "stream_open_blocked_events": null,
                        "data_blocked_events": null,
                        "stream_data_blocked_events": null,
                        "last_sent_ago_ms": last_sent_ago_ms,
                        "last_received_ago_ms": last_received_ago_ms,
                        "idle_for_ms": idle_for_ms,
                        "close_reason": close_reason,
                    }),
                };
                per_peer_transport.push(row);
            }
            // ADR-0011 §4: full-tunnel-VPN / constrained-MTU / CGNAT assessment.
            let transport_environment = x0x::connectivity::assess_transport_environment(
                &x0x::connectivity::TransportObservation {
                    external_addrs: ns.external_addrs.clone(),
                    can_receive_direct: Some(ns.can_receive_direct),
                    connected_peers: ns.connected_peers,
                    min_observed_mtu,
                    lost_plpmtud_probes: lost_plpmtud_probes_total,
                    black_holes_detected: black_holes_total,
                },
            );
            let snapshot = serde_json::json!({
                "ok": true,
                "peer_id": hex::encode(ns.peer_id.0),
                "local_addr": ns.local_addr.to_string(),
                "external_addrs": ns.external_addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "nat_type": format!("{:?}", ns.nat_type),
                "can_receive_direct": ns.can_receive_direct,
                "direct_reachability_scope": format!("{:?}", ns.direct_reachability_scope),
                "has_global_address": ns.has_global_address,
                "port_mapping": {
                    "active": ns.port_mapping_active,
                    "external_addr": ns.port_mapping_addr.map(|a| a.to_string()),
                },
                "mdns": {
                    "browsing": ns.mdns_browsing,
                    "advertising": ns.mdns_advertising,
                    "discovered_peers": ns.mdns_discovered_peers,
                },
                "services": {
                    "relay_enabled": ns.relay_service_enabled,
                    "coordinator_enabled": ns.coordinator_service_enabled,
                    "bootstrap_enabled": ns.bootstrap_service_enabled,
                },
                "connections": {
                    "connected_peers": ns.connected_peers,
                    "active": ns.active_connections,
                    "direct": ns.direct_connections,
                    "relayed": ns.relayed_connections,
                    "hole_punch_success_rate": ns.hole_punch_success_rate,
                },
                "per_peer_transport": per_peer_transport,
                "connection_pool": connection_pool,
                "relay": {
                    "is_relaying": ns.is_relaying,
                    "sessions": ns.relay_sessions,
                    "bytes_forwarded": ns.relay_bytes_forwarded,
                },
                "coordinator": {
                    "is_coordinating": ns.is_coordinating,
                    "sessions": ns.coordination_sessions,
                },
                "avg_rtt_ms": ns.avg_rtt.as_millis() as u64,
                "uptime_s": ns.uptime.as_secs(),
                // X0X-0039: `data_tx` channel saturation (ant-quic 0.27.13).
                "data_tx": {
                    "data_tx_depth": data_tx.as_ref().map(|d| d.data_tx_depth),
                    "data_tx_capacity": data_tx.as_ref().map(|d| d.data_tx_capacity),
                    "data_tx_high_water_count": data_tx.as_ref().map(|d| d.data_tx_high_water_count),
                },
                // X0X-0043: GSO bundle send counters (ant-quic 0.27.13). See
                // `docs/debug/gso-bundle-tail-drop-x0x-0030.md` for the
                // Quinn issue #2627 GSO-tail-drop hypothesis under test.
                "gso": {
                    "bundle_send_total": gso.as_ref().map(|g| g.bundle_send_total),
                    "bundle_partial_send": gso.as_ref().map(|g| g.bundle_partial_send),
                },
                // ADR-0011 §4: structured full-tunnel-VPN / constrained-MTU signal.
                "transport_environment": transport_environment,
            });
            (StatusCode::OK, Json(snapshot))
        }
        None => api_error(StatusCode::SERVICE_UNAVAILABLE, "node status unavailable"),
    }
}

/// GET /diagnostics/ack — ACK-v2 per-stage latency and outcome diagnostics.
async fn ack_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized");
    };

    match network.ack_diagnostics().await {
        Some(snapshot) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "ack": snapshot,
            })),
        ),
        None => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ACK diagnostics unavailable",
        ),
    }
}

/// GET /diagnostics/gossip — PubSub drop-detection counters.
///
/// The delta between stages proves per-daemon 100% delivery (or surfaces
/// where drops occur). Used by e2e_full_audit / e2e_stress to assert zero
/// drops under load.
async fn gossip_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.gossip_stats() {
        Some(snap) => {
            let pubsub_stages =
                augment_pubsub_stage_diagnostics(state.agent.gossip_pubsub_stage_stats());
            let (agents, machines, users) = state.agent.discovery_cache_entry_counts().await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                "ok": true,
                "stats": snap,
                "pubsub_stages": pubsub_stages,
                "dispatcher": state.agent.gossip_dispatch_stats(),
                "recv_pump": state.agent.recv_pump_diagnostics(),
                "discovery_cache_entries": {
                    "agents": agents,
                    "machines": machines,
                    "users": users,
                },
                })),
            )
        }
        None => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "gossip runtime not initialized",
        ),
    }
}

/// GET /diagnostics/groups — per-group ingest diagnostics.
///
/// Mirrors `/diagnostics/dm` and `/diagnostics/exec`. For each
/// locally-known group (or any group with non-zero counters) returns
/// `members_v2_size`, listener-state booleans, and the per-reason
/// drop buckets used by the public-message ingest pipeline. The
/// `messages_dropped_write_policy_violation` bucket is the canary for
/// the join-roster-propagation regression: a non-zero value on the
/// owner side means joiners' messages are reaching the listener but
/// `members_v2` is stale.
async fn groups_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let metadata_keys: std::collections::HashSet<String> = state
        .group_metadata_tasks
        .read()
        .await
        .keys()
        .cloned()
        .collect();
    let public_keys: std::collections::HashSet<String> = state
        .public_message_tasks
        .read()
        .await
        .keys()
        .cloned()
        .collect();
    // Snapshot the named_groups under a single read lock to avoid
    // repeatedly contending with the metadata listener under load.
    let groups_view: HashMap<String, x0x::groups::GroupInfo> = {
        let groups = state.named_groups.read().await;
        groups.clone()
    };
    let snap = state
        .groups_diagnostics
        .snapshot(&groups_view, &metadata_keys, &public_keys);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "groups": snap.groups,
        })),
    )
}

/// GET /diagnostics/dm — direct-message send/receive diagnostics.
async fn dm_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let x0x::direct::DmDiagnosticsSnapshot {
        stats,
        per_peer,
        subscriber_count,
        subscriber_capacity,
    } = state.agent.direct_messaging().diagnostics_snapshot();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "stats": stats,
            "per_peer": per_peer,
            "subscriber_count": subscriber_count,
            "subscriber_capacity": subscriber_capacity,
            "capability_store_entries": state.agent.capability_store().len(),
        })),
    )
}

/// Parse a hex `peer_id` path segment into an ant-quic `PeerId` (32 bytes).
fn parse_peer_id(hex_str: &str) -> Result<ant_quic::PeerId, (StatusCode, Json<serde_json::Value>)> {
    let bytes =
        hex::decode(hex_str).map_err(|e| bad_request(format!("invalid hex peer_id: {e}")))?;
    if bytes.len() != 32 {
        return Err(bad_request(format!(
            "peer_id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ant_quic::PeerId(arr))
}

/// Query for `POST /peers/:peer_id/probe` — optional timeout (default 2s).
#[derive(Debug, serde::Deserialize, Default)]
struct ProbeQuery {
    /// Probe timeout in milliseconds; clamped to `[100, 30000]`.
    timeout_ms: Option<u64>,
}

/// POST /peers/:peer_id/probe — ant-quic 0.27.2 `probe_peer` active liveness.
///
/// Sends a lightweight probe envelope to the peer and waits for the remote
/// reader's ACK-v1 reply. Returns the measured round-trip time. Probe
/// traffic is invisible to the application recv pipeline.
async fn probe_peer_handler(
    State(state): State<Arc<AppState>>,
    Path(peer_hex): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ProbeQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let peer_id = match parse_peer_id(&peer_hex) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized")
            .into_response();
    };
    let timeout_ms = q.timeout_ms.unwrap_or(2_000).clamp(100, 30_000);
    let timeout = std::time::Duration::from_millis(timeout_ms);

    match network.probe_peer(peer_id, timeout).await {
        Some(Ok(rtt)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "rtt_ms": rtt.as_millis() as u64,
                "rtt_us": rtt.as_micros() as u64,
                "timeout_ms": timeout_ms,
            })),
        )
            .into_response(),
        Some(Err(e)) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("probe failed: {e}"),
        )
        .into_response(),
        None => {
            api_error(StatusCode::SERVICE_UNAVAILABLE, "network node not running").into_response()
        }
    }
}

/// GET /peers/:peer_id/health — ant-quic 0.27.1 `connection_health` snapshot.
///
/// Returns the lifecycle state, generation, directional activity timestamps,
/// and most-recent close reason for a peer. The response carries:
///
/// - `health`: opaque Debug rendering of `ConnectionHealth` (legacy, kept
///   for backwards compatibility — older clients substring-matched this).
/// - `snapshot`: structured object new clients should prefer:
///   `{ connected, generation, reader_task_active, last_received_ms_ago,
///   last_sent_ms_ago, idle_ms, close_reason }`. `Instant`-typed fields
///   are converted to elapsed-millisecond deltas so the wire format
///   stays calendar-agnostic.
async fn peer_health_handler(
    State(state): State<Arc<AppState>>,
    Path(peer_hex): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let peer_id = match parse_peer_id(&peer_hex) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized")
            .into_response();
    };
    match network.connection_health(peer_id).await {
        Some(health) => {
            let now = std::time::Instant::now();
            let snapshot = serde_json::json!({
                "connected": health.connected,
                "generation": health.generation,
                "reader_task_active": health.reader_task_active,
                "last_received_ms_ago": health
                    .last_received_at
                    .map(|t| now.saturating_duration_since(t).as_millis() as u64),
                "last_sent_ms_ago": health
                    .last_sent_at
                    .map(|t| now.saturating_duration_since(t).as_millis() as u64),
                "idle_ms": health.idle_for.map(|d| d.as_millis() as u64),
                "close_reason": health.close_reason.as_ref().map(|r| format!("{r:?}")),
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "peer_id": peer_hex,
                    // `health` is the legacy Debug rendering retained for
                    // backwards compatibility. New clients should consume
                    // `snapshot` (structured fields).
                    "health": format!("{health:?}"),
                    "snapshot": snapshot,
                })),
            )
                .into_response()
        }
        None => {
            api_error(StatusCode::SERVICE_UNAVAILABLE, "network node not running").into_response()
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

/// Derive this agent's per-group TreeKEM identity seed from its long-term
/// ML-DSA secret key and the group's id bytes (ADR-0012). Centralised so the
/// create path and the restore path always agree on the seed (and therefore on
/// the re-derived identity / leaf).
fn agent_treekem_seed(agent: &Agent, group_id_bytes: &[u8]) -> [u8; 32] {
    let (_public, secret) = agent.identity().agent_keypair().to_bytes();
    x0x::mls::treekem::derive_identity_seed(&secret, group_id_bytes)
}

const TREEKEM_DAEMON_SNAPSHOT_MAGIC: &[u8; 4] = b"XTD1";
const TREEKEM_DAEMON_SNAPSHOT_VERSION: u8 = 1;
const TREEKEM_NAMED_JOURNAL_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeKemSnapshotEnvelope {
    version: u8,
    state_revision: u64,
    state_hash: String,
    security_binding: Option<String>,
    snapshot: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeKemNamedPersistJournal {
    version: u8,
    group_id_hex: String,
    named_groups_json: String,
    snapshot_envelope: Vec<u8>,
}

fn treekem_snapshot_path(treekem_dir: &FsPath, group_id_hex: &str) -> PathBuf {
    treekem_dir.join(format!("{group_id_hex}.snap"))
}

fn treekem_journal_path(treekem_dir: &FsPath, group_id_hex: &str) -> PathBuf {
    treekem_dir.join(format!("{group_id_hex}.journal"))
}

fn encode_treekem_snapshot_envelope(
    info: &x0x::groups::GroupInfo,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<Vec<u8>> {
    if info.withdrawn {
        anyhow::bail!("refusing to encode TreeKEM snapshot for withdrawn group");
    }
    let snapshot = group
        .to_snapshot_bytes()
        .map_err(|e| anyhow::anyhow!("treekem snapshot encode: {e}"))?;
    let mut bytes = TREEKEM_DAEMON_SNAPSHOT_MAGIC.to_vec();
    let envelope = TreeKemSnapshotEnvelope {
        version: TREEKEM_DAEMON_SNAPSHOT_VERSION,
        state_revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        security_binding: info.security_binding.clone(),
        snapshot,
    };
    bytes.extend(
        postcard::to_stdvec(&envelope)
            .map_err(|e| anyhow::anyhow!("treekem snapshot envelope encode: {e}"))?,
    );
    Ok(bytes)
}

fn decode_treekem_snapshot_envelope(
    bytes: &[u8],
) -> anyhow::Result<Option<TreeKemSnapshotEnvelope>> {
    let Some(payload) = bytes.strip_prefix(TREEKEM_DAEMON_SNAPSHOT_MAGIC) else {
        return Ok(None);
    };
    let envelope: TreeKemSnapshotEnvelope = postcard::from_bytes(payload)
        .map_err(|e| anyhow::anyhow!("treekem snapshot envelope decode: {e}"))?;
    if envelope.version != TREEKEM_DAEMON_SNAPSHOT_VERSION {
        anyhow::bail!(
            "unsupported TreeKEM snapshot envelope version {}",
            envelope.version
        );
    }
    Ok(Some(envelope))
}

fn treekem_snapshot_envelope_matches_info(
    envelope: &TreeKemSnapshotEnvelope,
    info: &x0x::groups::GroupInfo,
) -> bool {
    envelope.state_revision == info.state_revision
        && envelope.state_hash == info.state_hash
        && envelope.security_binding == info.security_binding
}

async fn persist_treekem_snapshot_bytes(
    treekem_dir: &FsPath,
    group_id_hex: &str,
    bytes: Vec<u8>,
) -> anyhow::Result<()> {
    let path = treekem_snapshot_path(treekem_dir, group_id_hex);
    x0x::storage::write_private_bytes(&path, bytes)
        .await
        .map_err(|e| anyhow::anyhow!("treekem snapshot write: {e}"))?;
    Ok(())
}

/// Persist a TreeKEM snapshot bound to the currently durable named-group state.
async fn persist_treekem_snapshot_bound(
    state: &AppState,
    group_id_hex: &str,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<()> {
    let info = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id_hex)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("named group missing for TreeKEM snapshot"))?
    };
    ensure_treekem_persistence_allowed(
        state,
        group_id_hex,
        Some(info.stable_group_id()),
        "withdrawn_snapshot_persist",
    )
    .await?;
    let bytes = encode_treekem_snapshot_envelope(&info, group)?;
    persist_treekem_snapshot_bytes(&state.treekem_dir, group_id_hex, bytes).await?;
    ensure_treekem_persistence_allowed(
        state,
        group_id_hex,
        Some(info.stable_group_id()),
        "withdrawn_snapshot_persist",
    )
    .await
}

async fn ensure_treekem_persistence_allowed(
    state: &AppState,
    group_id_hex: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) -> anyhow::Result<()> {
    ensure_named_group_key_material_install_allowed(state, group_id_hex, stable_group_id, reason)
        .await
}

/// Persist a supplied named-group state and matching TreeKEM snapshot with a
/// replay journal. The in-memory map is updated only after this returns.
async fn persist_treekem_and_named_groups_atomic_with_info(
    state: &AppState,
    group_id_hex: &str,
    info: x0x::groups::GroupInfo,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<()> {
    let stable_group_id = info.stable_group_id().to_string();
    ensure_treekem_persistence_allowed(
        state,
        group_id_hex,
        Some(&stable_group_id),
        "withdrawn_atomic_persist",
    )
    .await?;
    let named_groups_json = {
        let groups = state.named_groups.read().await;
        let mut next_groups = groups.clone();
        next_groups.insert(group_id_hex.to_string(), info.clone());
        serde_json::to_string_pretty(&next_groups)
            .map_err(|e| anyhow::anyhow!("named groups encode: {e}"))?
    };

    #[cfg(test)]
    maybe_force_atomic_persist_post_json_withdrawn_group_for_test(
        state,
        group_id_hex,
        Some(&stable_group_id),
    )
    .await;

    let snapshot_envelope = encode_treekem_snapshot_envelope(&info, group)?;
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id_hex.to_string(),
        named_groups_json: named_groups_json.clone(),
        snapshot_envelope: snapshot_envelope.clone(),
    };
    let journal_bytes = postcard::to_stdvec(&journal)
        .map_err(|e| anyhow::anyhow!("TreeKEM journal encode: {e}"))?;
    let journal_path = treekem_journal_path(&state.treekem_dir, group_id_hex);
    x0x::storage::write_private_bytes(&journal_path, journal_bytes)
        .await
        .map_err(|e| anyhow::anyhow!("TreeKEM journal write: {e}"))?;
    persist_treekem_snapshot_bytes(&state.treekem_dir, group_id_hex, snapshot_envelope).await?;
    if repair_withdrawn_named_groups_json_and_wipe_key_material(
        state,
        group_id_hex,
        Some(&stable_group_id),
        "withdrawn_atomic_persist_late",
    )
    .await?
    {
        anyhow::bail!("refusing to persist key material for withdrawn group");
    }
    write_named_groups_json_atomic(&state.named_groups_path, &named_groups_json)
        .await
        .map_err(|e| anyhow::anyhow!("named groups write: {e}"))?;
    if let Err(e) = tokio::fs::remove_file(&journal_path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(anyhow::anyhow!("TreeKEM journal cleanup: {e}"));
        }
    }
    Ok(())
}

/// Persist current named-group JSON and a matching bound TreeKEM snapshot.
async fn persist_treekem_and_named_groups_atomic(
    state: &AppState,
    group_id_hex: &str,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<()> {
    let info = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id_hex)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("named group missing for TreeKEM atomic persist"))?
    };
    persist_treekem_and_named_groups_atomic_with_info(state, group_id_hex, info, group).await
}

async fn recover_treekem_named_journals(
    named_groups_path: &FsPath,
    treekem_dir: &FsPath,
) -> anyhow::Result<()> {
    let mut entries = match tokio::fs::read_dir(treekem_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow::anyhow!("read TreeKEM journal dir: {e}")),
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| anyhow::anyhow!("read TreeKEM journal entry: {e}"))?
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("journal") {
            continue;
        }
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| anyhow::anyhow!("read TreeKEM journal {}: {e}", path.display()))?;
        let journal: TreeKemNamedPersistJournal = postcard::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("decode TreeKEM journal {}: {e}", path.display()))?;
        if journal.version != TREEKEM_NAMED_JOURNAL_VERSION {
            tracing::warn!(path = %path.display(), version = journal.version, "ignoring unsupported TreeKEM journal version");
            continue;
        }
        let named_groups: HashMap<String, x0x::groups::GroupInfo> =
            serde_json::from_str(&journal.named_groups_json).map_err(|e| {
                anyhow::anyhow!(
                    "decode named groups JSON in TreeKEM journal {}: {e}",
                    path.display()
                )
            })?;
        if has_withdrawn_group_record(&named_groups, &journal.group_id_hex) {
            remove_treekem_persistence_for_group_id_in_dir(
                treekem_dir,
                &journal.group_id_hex,
                "withdrawn_journal_replay",
            )
            .await;
            if let Err(e) = tokio::fs::remove_file(&path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(anyhow::anyhow!(
                        "remove withdrawn TreeKEM journal {}: {e}",
                        path.display()
                    ));
                }
            }
            tracing::warn!(group_id = %LogHexId::group(&journal.group_id_hex), "discarded TreeKEM/named-group persistence journal for withdrawn group");
            continue;
        }
        let durable_named_groups: Option<HashMap<String, x0x::groups::GroupInfo>> =
            match tokio::fs::read_to_string(named_groups_path).await {
                Ok(json) => {
                    let mut groups: HashMap<String, x0x::groups::GroupInfo> =
                        serde_json::from_str(&json).with_context(|| {
                            format!(
                            "failed to parse named groups file {} before TreeKEM journal replay",
                            named_groups_path.display()
                        )
                        })?;
                    for info in groups.values_mut() {
                        info.migrate_from_v1();
                    }
                    Some(groups)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "failed to read named groups file {} before TreeKEM journal replay",
                            named_groups_path.display()
                        )
                    });
                }
            };
        if durable_named_groups.as_ref().is_some_and(|groups| {
            has_withdrawn_group_record_for_journal_replay(
                groups,
                &journal.group_id_hex,
                &named_groups,
            )
        }) {
            remove_treekem_persistence_for_group_id_in_dir(
                treekem_dir,
                &journal.group_id_hex,
                "withdrawn_durable_journal_replay",
            )
            .await;
            if let Err(e) = tokio::fs::remove_file(&path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(anyhow::anyhow!(
                        "remove durable-withdrawn TreeKEM journal {}: {e}",
                        path.display()
                    ));
                }
            }
            tracing::warn!(group_id = %LogHexId::group(&journal.group_id_hex), "discarded TreeKEM/named-group persistence journal because durable named groups contain a withdrawn record");
            continue;
        }
        persist_treekem_snapshot_bytes(
            treekem_dir,
            &journal.group_id_hex,
            journal.snapshot_envelope,
        )
        .await?;
        write_named_groups_json_atomic(named_groups_path, &journal.named_groups_json)
            .await
            .map_err(|e| anyhow::anyhow!("replay named groups journal: {e}"))?;
        tokio::fs::remove_file(&path)
            .await
            .map_err(|e| anyhow::anyhow!("remove replayed TreeKEM journal: {e}"))?;
        tracing::warn!(group_id = %journal.group_id_hex, "replayed TreeKEM/named-group persistence journal after prior crash");
    }
    Ok(())
}

/// Rebuild the live TreeKEM group map from on-disk snapshots at startup
/// (ADR-0012 Phase 4). For every named group tagged
/// [`x0x::mls::SecureGroupPlane::TreeKem`], restore its snapshot using the
/// agent's per-group identity seed. A missing or unreadable snapshot is logged
/// and skipped — the group stays unusable for secure content until re-shared,
/// never a crash.
async fn restore_treekem_groups(
    named_groups: &HashMap<String, x0x::groups::GroupInfo>,
    agent: &Agent,
    treekem_dir: &FsPath,
) -> HashMap<String, Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>> {
    let mut restored = HashMap::new();
    let agent_id = agent.agent_id();
    for (group_id_hex, info) in named_groups {
        if info.withdrawn {
            remove_treekem_persistence_for_group_id_in_dir(
                treekem_dir,
                group_id_hex,
                "withdrawn_restore",
            )
            .await;
            continue;
        }
        if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem {
            continue;
        }
        let path = treekem_snapshot_path(treekem_dir, group_id_hex);
        let snapshot_bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    group_id = %group_id_hex,
                    "TreeKEM group tagged but no snapshot on disk; secure content unavailable until re-shared"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(group_id = %group_id_hex, "failed to read TreeKEM snapshot: {e}");
                continue;
            }
        };
        let snapshot = match decode_treekem_snapshot_envelope(&snapshot_bytes) {
            Ok(Some(envelope)) => {
                if !treekem_snapshot_envelope_matches_info(&envelope, info) {
                    tracing::warn!(
                        group_id = %group_id_hex,
                        snapshot_revision = envelope.state_revision,
                        named_revision = info.state_revision,
                        "TreeKEM snapshot/named-group binding mismatch; secure content unavailable until repaired"
                    );
                    continue;
                }
                envelope.snapshot
            }
            Ok(None) => {
                tracing::warn!(group_id = %group_id_hex, "restoring legacy unbound TreeKEM snapshot; future writes will bind it to named-group state");
                snapshot_bytes
            }
            Err(e) => {
                tracing::warn!(group_id = %group_id_hex, "failed to decode TreeKEM snapshot envelope: {e}");
                continue;
            }
        };
        let group_id_bytes = match hex::decode(&info.mls_group_id) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    group_id = %group_id_hex,
                    "invalid mls_group_id hex, cannot restore TreeKEM group: {e}"
                );
                continue;
            }
        };
        let seed = agent_treekem_seed(agent, &group_id_bytes);
        match x0x::mls::TreeKemMlsGroup::restore(&snapshot, agent_id, &seed) {
            Ok(g) => {
                tracing::info!(group_id = %group_id_hex, "restored TreeKEM group from snapshot");
                restored.insert(group_id_hex.clone(), Arc::new(tokio::sync::Mutex::new(g)));
            }
            Err(e) => {
                tracing::warn!(
                    group_id = %group_id_hex,
                    "failed to restore TreeKEM group (wrong identity or corrupt snapshot?): {e}"
                );
            }
        }
    }
    restored
}

async fn load_named_groups(
    named_groups_path: &FsPath,
) -> Result<HashMap<String, x0x::groups::GroupInfo>> {
    match tokio::fs::read_to_string(named_groups_path).await {
        Ok(json) => {
            let mut groups = serde_json::from_str::<HashMap<String, x0x::groups::GroupInfo>>(&json)
                .with_context(|| {
                    format!(
                        "failed to parse named groups file {}",
                        named_groups_path.display()
                    )
                })?;
            for info in groups.values_mut() {
                info.migrate_from_v1();
            }
            tracing::info!(
                "Loaded {} named groups from {}",
                groups.len(),
                named_groups_path.display()
            );
            Ok(groups)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No named groups file found, starting fresh");
            Ok(HashMap::new())
        }
        Err(e) => Err(e).with_context(|| {
            format!(
                "failed to read named groups file {}",
                named_groups_path.display()
            )
        }),
    }
}

async fn save_named_groups(state: &AppState) {
    let json = {
        let groups = state.named_groups.read().await;
        serde_json::to_string(&*groups)
    };
    match json {
        Ok(json) => {
            if let Err(e) = write_named_groups_json_atomic(&state.named_groups_path, &json).await {
                tracing::error!("Failed to save named groups: {e}");
            }
        }
        Err(e) => tracing::error!("Failed to serialize named groups: {e}"),
    }
}

async fn write_named_groups_json_atomic(path: &FsPath, json: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut temp_os = path.as_os_str().to_owned();
    temp_os.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let temp_path = PathBuf::from(temp_os);

    let write_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await?;
        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temp_path, path).await
    }
    .await;

    if write_result.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }

    write_result
}

/// Build a uniform `{ "ok": false, "error": <msg> }` JSON error response paired
/// with the given status code. Used by handlers in place of hand-rolled literals.
fn api_error(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": msg.into() })),
    )
}

/// `400 Bad Request` error response.
fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    api_error(StatusCode::BAD_REQUEST, msg)
}

/// `404 Not Found` error response.
fn not_found(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    api_error(StatusCode::NOT_FOUND, msg)
}

/// `403 Forbidden` error response.
fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    api_error(StatusCode::FORBIDDEN, msg)
}

/// Decode a base64-encoded payload from a request field.
fn decode_base64_payload(encoded: &str) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    BASE64
        .decode(encoded)
        .map_err(|e| bad_request(format!("invalid base64: {e}")))
}

/// Derive an MLS cipher from a group's current key schedule.
fn make_mls_cipher(
    group: &x0x::mls::MlsGroup,
) -> Result<(x0x::mls::MlsCipher, u64), (StatusCode, Json<serde_json::Value>)> {
    let key_schedule = x0x::mls::MlsKeySchedule::from_group(group).map_err(|e| {
        tracing::error!("MLS key derivation failed: {e}");
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "key derivation failed")
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

// ---------------------------------------------------------------------------
// TreeKEM join-result and Welcome blob pull handling
// ---------------------------------------------------------------------------

const PENDING_JOIN_RESULT_TTL: Duration = Duration::from_secs(10 * 60);
const JOIN_RESULT_POLL_TIMEOUT: Duration = Duration::from_secs(120);
const JOIN_RESULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
const PENDING_WELCOME_TTL: Duration = Duration::from_secs(10 * 60);
const WELCOME_FETCH_TIMEOUT: Duration = Duration::from_secs(90);
const WELCOME_FETCH_RETRY_DELAYS: [Duration; 4] = [
    Duration::ZERO,
    Duration::from_secs(5),
    Duration::from_secs(20),
    Duration::from_secs(60),
];

fn welcome_id_for_bytes(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

fn join_result_key(group_id: &str, member_agent_id: &str) -> String {
    format!("{group_id}:{member_agent_id}")
}

fn validate_join_result_inviter(
    expected_inviter: Option<&str>,
    sender_hex: &str,
    member_added_actor: &str,
) -> Result<(), &'static str> {
    let Some(expected_inviter) = expected_inviter else {
        return Err("missing_expected_inviter");
    };
    if sender_hex != expected_inviter {
        return Err("unexpected_sender");
    }
    if member_added_actor != expected_inviter {
        return Err("unexpected_actor");
    }
    Ok(())
}

fn record_expected_join_result_inviter(state: &AppState, key: String, inviter_agent_id: String) {
    let Ok(mut expected) = state.expected_join_result_inviters.lock() else {
        tracing::warn!(
            "expected join-result inviter map is poisoned; join-result response will be rejected"
        );
        return;
    };
    expected.retain(|_, pending| pending.created_at.elapsed() < JOIN_RESULT_POLL_TIMEOUT);
    expected.insert(
        key,
        ExpectedJoinResultInviter {
            inviter_agent_id,
            created_at: Instant::now(),
        },
    );
}

fn expected_join_result_inviter(state: &AppState, key: &str) -> Option<String> {
    let Ok(mut expected) = state.expected_join_result_inviters.lock() else {
        tracing::warn!(
            "expected join-result inviter map is poisoned; rejecting join-result response"
        );
        return None;
    };
    expected.retain(|_, pending| pending.created_at.elapsed() < JOIN_RESULT_POLL_TIMEOUT);
    expected
        .get(key)
        .map(|pending| pending.inviter_agent_id.clone())
}

fn clear_expected_join_result_inviter(state: &AppState, key: &str) {
    if let Ok(mut expected) = state.expected_join_result_inviters.lock() {
        expected.remove(key);
    }
}

async fn stage_join_result(
    state: &AppState,
    group_id: &str,
    member_agent_id: &str,
    event: NamedGroupMetadataEvent,
) {
    let key = join_result_key(group_id, member_agent_id);
    let event_kind = named_group_metadata_event_kind(&event);
    let (has_commit, has_commit_b64, has_inline_welcome, welcome_ref_id, treekem_epoch) =
        match &event {
            NamedGroupMetadataEvent::MemberAdded {
                commit,
                treekem_commit_b64,
                treekem_welcome_b64,
                welcome_ref,
                treekem_epoch,
                ..
            } => (
                commit.is_some(),
                treekem_commit_b64.is_some(),
                treekem_welcome_b64.is_some(),
                welcome_ref.as_ref().map(|w| w.welcome_id.clone()),
                *treekem_epoch,
            ),
            _ => (false, false, false, None, None),
        };
    let mut results = state.pending_join_results.write().await;
    results.retain(|_, pending| pending.created_at.elapsed() < PENDING_JOIN_RESULT_TTL);
    results.insert(
        key.clone(),
        PendingJoinResult {
            event,
            created_at: Instant::now(),
        },
    );
    tracing::debug!(
        target: "treekem.trace",
        stage = "stage_join_result",
        key = %key,
        group_id = %group_id,
        member = %member_agent_id,
        event = event_kind,
        has_commit,
        has_commit_b64,
        has_inline_welcome,
        welcome_ref = ?welcome_ref_id,
        treekem_epoch = ?treekem_epoch,
        pending_count = results.len(),
    );
}

async fn handle_join_result_message(
    state: &Arc<AppState>,
    sender: &AgentId,
    msg: JoinResultMessage,
) {
    match msg {
        JoinResultMessage::FetchRequest {
            group_id,
            member_agent_id,
        } => {
            let sender_hex = hex::encode(sender.as_bytes());
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_received",
                group_id = %group_id,
                member = %member_agent_id,
                sender = %sender_hex,
            );
            if sender_hex != member_agent_id {
                tracing::warn!(group_id = %LogHexId::group(&group_id), sender = %LogHexId::agent(&sender_hex), member = %LogHexId::agent(&member_agent_id), "ignoring unauthorized join-result fetch");
                return;
            }
            let key = join_result_key(&group_id, &member_agent_id);
            let (event, pending_count) = {
                let mut results = state.pending_join_results.write().await;
                results.retain(|_, pending| pending.created_at.elapsed() < PENDING_JOIN_RESULT_TTL);
                (
                    results.get(&key).map(|pending| pending.event.clone()),
                    results.len(),
                )
            };
            let Some(event) = event else {
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "fetch_request_lookup_miss",
                    key = %key,
                    group_id = %group_id,
                    member = %member_agent_id,
                    pending_count,
                );
                tracing::debug!(group_id = %group_id, member = %member_agent_id, "join-result fetch before result was staged");
                return;
            };
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_lookup_hit",
                key = %key,
                group_id = %group_id,
                member = %member_agent_id,
                event = named_group_metadata_event_kind(&event),
                pending_count,
            );
            let response = JoinResultMessage::Result {
                event: Box::new(event),
            };
            let payload = match serde_json::to_vec(&response) {
                Ok(payload) => payload,
                Err(e) => {
                    tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize join-result event: {e}");
                    return;
                }
            };
            let payload_len = payload.len();
            let payload_hash = hex::encode(blake3::hash(&payload).as_bytes());
            tracing::debug!(
                target: "treekem.trace",
                stage = "join_result_send_start",
                group_id = %group_id,
                member = %member_agent_id,
                payload_len,
                payload_hash = %payload_hash,
            );
            if let Err(e) = state
                .agent
                .send_direct_with_config(sender, payload, direct_message_send_config())
                .await
            {
                tracing::warn!(group_id = %LogHexId::group(&group_id), member = %LogHexId::agent(&member_agent_id), "failed to send join-result response: {e}");
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "join_result_send_err",
                    group_id = %group_id,
                    member = %member_agent_id,
                    payload_len,
                    payload_hash = %payload_hash,
                    error = %e,
                );
            } else {
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "join_result_send_ok",
                    group_id = %group_id,
                    member = %member_agent_id,
                    payload_len,
                    payload_hash = %payload_hash,
                );
            }
        }
        JoinResultMessage::Result { event } => {
            let event = *event;
            tracing::debug!(
                target: "treekem.trace",
                stage = "join_result_received",
                event = named_group_metadata_event_kind(&event),
                sender = %hex::encode(sender.as_bytes()),
            );
            let (group_id, member_agent_id, inviter_agent_id) = match &event {
                NamedGroupMetadataEvent::MemberAdded {
                    group_id,
                    agent_id,
                    actor,
                    ..
                } => (group_id.clone(), agent_id.clone(), actor.clone()),
                _ => {
                    tracing::warn!("ignoring non-MemberAdded join-result response");
                    return;
                }
            };
            let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
            if member_agent_id != local_agent_hex {
                tracing::warn!(group_id = %LogHexId::group(&group_id), member = %LogHexId::agent(&member_agent_id), local = %LogHexId::agent(&local_agent_hex), "ignoring join-result for different member");
                return;
            }
            let sender_hex = hex::encode(sender.as_bytes());
            let group_exists = {
                let groups = state.named_groups.read().await;
                groups.get(&group_id).is_some()
                    || groups
                        .values()
                        .any(|info| info.stable_group_id() == group_id)
            };
            if !group_exists {
                tracing::warn!(group_id = %LogHexId::group(&group_id), "ignoring join-result for unknown local group");
                return;
            }
            let expected_key = join_result_key(&group_id, &member_agent_id);
            let expected_inviter = expected_join_result_inviter(state.as_ref(), &expected_key);
            if let Err(reason) = validate_join_result_inviter(
                expected_inviter.as_deref(),
                &sender_hex,
                &inviter_agent_id,
            ) {
                tracing::warn!(
                    group_id = %LogHexId::group(&group_id),
                    sender = %LogHexId::agent(&sender_hex),
                    actor = %LogHexId::agent(&inviter_agent_id),
                    expected_inviter = ?expected_inviter.as_deref().map(LogHexId::agent),
                    reason,
                    "ignoring join-result from unexpected inviter"
                );
                return;
            }
            if apply_named_group_metadata_event(state, event, *sender, true).await {
                clear_expected_join_result_inviter(state.as_ref(), &expected_key);
            }
        }
    }
}

async fn poll_join_result_until_treekem_ready(
    state: Arc<AppState>,
    group_id: String,
    event_group_id: String,
    inviter: AgentId,
    member_agent_id: String,
) {
    let deadline = tokio::time::Instant::now() + JOIN_RESULT_POLL_TIMEOUT;
    let expected_key = join_result_key(&event_group_id, &member_agent_id);
    let mut timed_out = true;
    while tokio::time::Instant::now() < deadline {
        if state.treekem_groups.read().await.contains_key(&group_id) {
            timed_out = false;
            break;
        }
        let request = JoinResultMessage::FetchRequest {
            group_id: event_group_id.clone(),
            member_agent_id: member_agent_id.clone(),
        };
        let payload = match serde_json::to_vec(&request) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize join-result fetch request: {e}");
                return;
            }
        };
        let payload_len = payload.len();
        let payload_hash = hex::encode(blake3::hash(&payload).as_bytes());
        tracing::debug!(
            target: "treekem.trace",
            stage = "fetch_request_send_start",
            group_id = %group_id,
            event_group_id = %event_group_id,
            member = %member_agent_id,
            payload_len,
            payload_hash = %payload_hash,
        );
        if let Err(e) = state
            .agent
            .send_direct_with_config(&inviter, payload, direct_message_send_config())
            .await
        {
            tracing::debug!(group_id = %group_id, member = %member_agent_id, "join-result fetch attempt failed: {e}");
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_send_err",
                group_id = %group_id,
                event_group_id = %event_group_id,
                member = %member_agent_id,
                payload_len,
                payload_hash = %payload_hash,
                error = %e,
            );
        } else {
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_send_ok",
                group_id = %group_id,
                event_group_id = %event_group_id,
                member = %member_agent_id,
                payload_len,
                payload_hash = %payload_hash,
            );
        }
        tokio::time::sleep(JOIN_RESULT_POLL_INTERVAL).await;
    }
    clear_expected_join_result_inviter(state.as_ref(), &expected_key);
    if timed_out {
        tracing::warn!(group_id = %LogHexId::group(&group_id), member = %LogHexId::agent(&member_agent_id), "timed out polling anchor for TreeKEM join result");
    }
}

async fn stage_treekem_welcome(
    state: &AppState,
    group_id: &str,
    joiner_agent: &str,
    bytes: Vec<u8>,
) -> WelcomeRef {
    let welcome_id = welcome_id_for_bytes(&bytes);
    let byte_len = bytes.len() as u64;
    let source = hex::encode(state.agent.agent_id().as_bytes());
    let pending = PendingWelcome {
        group_id: group_id.to_string(),
        joiner_agent: joiner_agent.to_string(),
        bytes,
        created_at: Instant::now(),
    };
    let mut welcomes = state.pending_welcomes.write().await;
    welcomes.retain(|_, pending| pending.created_at.elapsed() < PENDING_WELCOME_TTL);
    welcomes.insert(welcome_id.clone(), pending);
    WelcomeRef {
        welcome_id,
        byte_len,
        source,
    }
}

fn welcome_blob_send_config(msg: &WelcomeBlobMessage) -> x0x::dm::DmSendConfig {
    match msg {
        WelcomeBlobMessage::Chunk { .. } => file_transfer_send_config(),
        WelcomeBlobMessage::FetchRequest { .. }
        | WelcomeBlobMessage::Offer { .. }
        | WelcomeBlobMessage::ChunkAck { .. }
        | WelcomeBlobMessage::Complete { .. } => direct_message_send_config(),
    }
}

async fn send_welcome_blob_message(
    state: &Arc<AppState>,
    agent_id: &AgentId,
    msg: &WelcomeBlobMessage,
) -> std::result::Result<x0x::dm::DmReceipt, String> {
    let payload = serde_json::to_vec(msg).map_err(|e| format!("serialization failed: {e}"))?;
    if payload.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return Err(format!(
            "welcome blob message exceeds MAX_PAYLOAD_BYTES ({} > {})",
            payload.len(),
            x0x::dm::MAX_PAYLOAD_BYTES
        ));
    }
    state
        .agent
        .send_direct_with_config(agent_id, payload, welcome_blob_send_config(msg))
        .await
        .map_err(|e| e.to_string())
}

async fn notify_welcome_waiters(
    state: &Arc<AppState>,
    welcome_id: &str,
    result: std::result::Result<Vec<u8>, String>,
) {
    let waiters = state
        .pending_welcome_waiters
        .write()
        .await
        .remove(welcome_id);
    if let Some(waiters) = waiters {
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }
}

async fn cleanup_welcome_fetch_state(state: &Arc<AppState>, welcome_id: &str) {
    state
        .pending_welcome_receives
        .write()
        .await
        .remove(welcome_id);
    state
        .pending_welcome_waiters
        .write()
        .await
        .remove(welcome_id);
}

async fn fetch_treekem_welcome_with_retries(
    state: &Arc<AppState>,
    group_id: &str,
    welcome_ref: &WelcomeRef,
) -> std::result::Result<Vec<u8>, String> {
    let mut last_error = None;
    for (attempt, delay) in WELCOME_FETCH_RETRY_DELAYS.iter().enumerate() {
        if !delay.is_zero() {
            tokio::time::sleep(*delay).await;
        }
        match fetch_treekem_welcome(state, group_id, welcome_ref).await {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                tracing::warn!(
                    target: "welcome.trace",
                    stage = "fetch_retry_failed",
                    group_id,
                    welcome_id = %welcome_ref.welcome_id,
                    attempt,
                    next_delay_ms = ?WELCOME_FETCH_RETRY_DELAYS
                        .get(attempt + 1)
                        .map(|d| d.as_millis() as u64),
                    error = %e,
                );
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| "TreeKEM Welcome fetch did not run".to_string()))
}

async fn fetch_treekem_welcome(
    state: &Arc<AppState>,
    group_id: &str,
    welcome_ref: &WelcomeRef,
) -> std::result::Result<Vec<u8>, String> {
    if welcome_ref.byte_len > x0x::files::MAX_TRANSFER_SIZE {
        return Err("TreeKEM Welcome blob exceeds maximum transfer size".to_string());
    }
    let source = parse_agent_id_hex(&welcome_ref.source)?;
    let total_chunks =
        x0x::files::total_chunks_for_size(welcome_ref.byte_len, x0x::files::DEFAULT_CHUNK_SIZE);
    let (tx, rx) = oneshot::channel();
    let should_send_fetch = {
        let mut receives = state.pending_welcome_receives.write().await;
        let should_send_fetch = match receives.get(&welcome_ref.welcome_id) {
            Some(existing)
                if existing.group_id == group_id
                    && existing.source == welcome_ref.source
                    && existing.byte_len == welcome_ref.byte_len
                    && existing.total_chunks == total_chunks =>
            {
                tracing::debug!(
                    target: "welcome.trace",
                    stage = "fetch_join_inflight",
                    group_id,
                    welcome_id = %welcome_ref.welcome_id,
                );
                false
            }
            Some(_) => {
                return Err("conflicting in-flight TreeKEM Welcome fetch".to_string());
            }
            None => {
                receives.insert(
                    welcome_ref.welcome_id.clone(),
                    PendingWelcomeReceive {
                        group_id: group_id.to_string(),
                        source: welcome_ref.source.clone(),
                        byte_len: welcome_ref.byte_len,
                        total_chunks,
                        chunks: BTreeMap::new(),
                        received_bytes: 0,
                    },
                );
                true
            }
        };
        state
            .pending_welcome_waiters
            .write()
            .await
            .entry(welcome_ref.welcome_id.clone())
            .or_default()
            .push(tx);
        should_send_fetch
    };

    if should_send_fetch {
        let request = WelcomeBlobMessage::FetchRequest {
            group_id: group_id.to_string(),
            welcome_id: welcome_ref.welcome_id.clone(),
        };
        if let Err(e) = send_welcome_blob_message(state, &source, &request).await {
            cleanup_welcome_fetch_state(state, &welcome_ref.welcome_id).await;
            return Err(e);
        }
    }

    let received = match tokio::time::timeout(WELCOME_FETCH_TIMEOUT, rx).await {
        Ok(Ok(result)) => result?,
        Ok(Err(_)) => return Err("TreeKEM Welcome waiter dropped".to_string()),
        Err(_) => {
            cleanup_welcome_fetch_state(state, &welcome_ref.welcome_id).await;
            return Err("timed out waiting for TreeKEM Welcome blob".to_string());
        }
    };
    if received.len() as u64 != welcome_ref.byte_len {
        return Err(format!(
            "TreeKEM Welcome length mismatch: got {}, expected {}",
            received.len(),
            welcome_ref.byte_len
        ));
    }
    let actual = welcome_id_for_bytes(&received);
    if actual != welcome_ref.welcome_id {
        return Err("TreeKEM Welcome blake3 mismatch".to_string());
    }
    Ok(received)
}

async fn handle_welcome_blob_message(
    state: &Arc<AppState>,
    sender: &AgentId,
    msg: WelcomeBlobMessage,
) {
    match msg {
        WelcomeBlobMessage::FetchRequest {
            group_id,
            welcome_id,
        } => handle_welcome_fetch_request(state, sender, group_id, welcome_id).await,
        WelcomeBlobMessage::Offer {
            group_id,
            welcome_id,
            byte_len,
            chunk_size,
            total_chunks,
            blake3_hex,
        } => {
            let source = hex::encode(sender.as_bytes());
            let mismatch = {
                let receives = state.pending_welcome_receives.read().await;
                let Some(receive) = receives.get(&welcome_id) else {
                    tracing::debug!(welcome_id, "ignoring unsolicited Welcome blob offer");
                    return;
                };
                if receive.source != source {
                    tracing::debug!(welcome_id, sender = %source, "ignoring Welcome blob offer from unexpected source");
                    return;
                }
                receive.group_id != group_id
                    || receive.byte_len != byte_len
                    || receive.total_chunks != total_chunks
                    || chunk_size != x0x::files::DEFAULT_CHUNK_SIZE
                    || blake3_hex != welcome_id
            };
            if mismatch {
                state
                    .pending_welcome_receives
                    .write()
                    .await
                    .remove(&welcome_id);
                notify_welcome_waiters(
                    state,
                    &welcome_id,
                    Err("welcome offer did not match requested reference".to_string()),
                )
                .await;
            }
        }
        WelcomeBlobMessage::Chunk {
            welcome_id,
            sequence,
            data,
        } => handle_welcome_blob_chunk(state, sender, welcome_id, sequence, data).await,
        WelcomeBlobMessage::ChunkAck {
            welcome_id,
            sequence,
        } => {
            let matched_pending =
                if let Some(slot) = state.pending_welcome_acks.read().await.get(&welcome_id) {
                    slot.record_ack(sequence);
                    true
                } else {
                    false
                };
            tracing::debug!(target: "welcome.trace", stage = "chunk_ack_recv", welcome_id = %welcome_id, seq = sequence, matched_pending);
        }
        WelcomeBlobMessage::Complete { welcome_id } => {
            handle_welcome_blob_complete(state, sender, &welcome_id).await;
        }
    }
}

async fn handle_welcome_fetch_request(
    state: &Arc<AppState>,
    sender: &AgentId,
    group_id: String,
    welcome_id: String,
) {
    let sender_hex = hex::encode(sender.as_bytes());
    let pending = {
        let welcomes = state.pending_welcomes.read().await;
        welcomes.get(&welcome_id).cloned()
    };
    let Some(pending) = pending else {
        tracing::warn!(welcome_id, "Welcome fetch for unknown blob");
        return;
    };
    if pending.created_at.elapsed() >= PENDING_WELCOME_TTL {
        state.pending_welcomes.write().await.remove(&welcome_id);
        return;
    }
    if pending.group_id != group_id || pending.joiner_agent != sender_hex {
        tracing::warn!(welcome_id = %LogHexId::new("welcome", &welcome_id), sender = %LogHexId::agent(&sender_hex), "unauthorized Welcome fetch request");
        return;
    }
    let state = Arc::clone(state);
    let recipient = *sender;
    tokio::spawn(async move {
        stream_welcome_blob(&state, &recipient, &welcome_id, pending).await;
    });
}

async fn stream_welcome_blob(
    state: &Arc<AppState>,
    recipient: &AgentId,
    welcome_id: &str,
    pending: PendingWelcome,
) {
    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let total_chunks = x0x::files::total_chunks_for_size(pending.bytes.len() as u64, chunk_size);
    let ack_slot = Arc::new(FileChunkAckSlot::new());
    {
        let mut acks = state.pending_welcome_acks.write().await;
        if acks.contains_key(welcome_id) {
            tracing::debug!(
                target: "welcome.trace",
                stage = "stream_duplicate_ignored",
                welcome_id,
                recipient = %hex::encode(recipient.as_bytes()),
            );
            return;
        }
        acks.insert(welcome_id.to_string(), Arc::clone(&ack_slot));
    }

    let offer = WelcomeBlobMessage::Offer {
        group_id: pending.group_id.clone(),
        welcome_id: welcome_id.to_string(),
        byte_len: pending.bytes.len() as u64,
        chunk_size,
        total_chunks,
        blake3_hex: welcome_id.to_string(),
    };
    if let Err(e) = send_welcome_blob_message(state, recipient, &offer).await {
        tracing::warn!(welcome_id, "failed to send Welcome blob offer: {e}");
        state.pending_welcome_acks.write().await.remove(welcome_id);
        return;
    }
    tracing::debug!(
        target: "welcome.trace",
        stage = "offer_sent",
        welcome_id,
        recipient = %hex::encode(recipient.as_bytes()),
        total_chunks,
        byte_len = pending.bytes.len() as u64,
    );

    for (sequence, chunk) in pending.bytes.chunks(chunk_size).enumerate() {
        let sequence = sequence as u64;
        if let Err(e) = wait_for_chunk_window(&ack_slot, sequence).await {
            tracing::warn!(welcome_id, "Welcome blob chunk window failed: {e}");
            state.pending_welcome_acks.write().await.remove(welcome_id);
            return;
        }
        let msg = WelcomeBlobMessage::Chunk {
            welcome_id: welcome_id.to_string(),
            sequence,
            data: BASE64.encode(chunk),
        };
        if let Err(e) = send_welcome_blob_message(state, recipient, &msg).await {
            tracing::warn!(
                welcome_id,
                sequence,
                "failed to send Welcome blob chunk: {e}"
            );
            state.pending_welcome_acks.write().await.remove(welcome_id);
            return;
        }
        tracing::debug!(target: "welcome.trace", stage = "chunk_sent", welcome_id, seq = sequence);
    }

    if total_chunks > 0 {
        let last_seq = total_chunks - 1;
        if let Err(e) = wait_for_final_acks(&ack_slot, last_seq).await {
            tracing::warn!(welcome_id, "Welcome blob final ack wait failed: {e}");
            tracing::debug!(target: "welcome.trace", stage = "final_ack_failed", welcome_id, total_chunks, last_acked = ack_slot.highest_acked(), "{e}");
            state.pending_welcome_acks.write().await.remove(welcome_id);
            return;
        }
        tracing::debug!(target: "welcome.trace", stage = "final_ack_ok", welcome_id, total_chunks);
    }
    let complete = WelcomeBlobMessage::Complete {
        welcome_id: welcome_id.to_string(),
    };
    if let Err(e) = send_welcome_blob_message(state, recipient, &complete).await {
        tracing::warn!(welcome_id, "failed to send Welcome blob complete: {e}");
    }
    state.pending_welcome_acks.write().await.remove(welcome_id);
}

async fn handle_welcome_blob_chunk(
    state: &Arc<AppState>,
    sender: &AgentId,
    welcome_id: String,
    sequence: u64,
    data: String,
) {
    let sender_hex = hex::encode(sender.as_bytes());
    let decoded = match BASE64.decode(data) {
        Ok(bytes) => bytes,
        Err(e) => {
            notify_welcome_waiters(
                state,
                &welcome_id,
                Err(format!("Welcome chunk decode failed: {e}")),
            )
            .await;
            return;
        }
    };
    let mut receives = state.pending_welcome_receives.write().await;
    let Some(receive) = receives.get_mut(&welcome_id) else {
        tracing::debug!(target: "welcome.trace", stage = "chunk_recv_no_pending", welcome_id = %welcome_id, seq = sequence);
        return;
    };
    if receive.source != sender_hex {
        tracing::debug!(target: "welcome.trace", stage = "chunk_recv_wrong_source", welcome_id = %welcome_id, seq = sequence);
        return;
    }
    if sequence >= receive.total_chunks {
        return;
    }
    if !receive.chunks.contains_key(&sequence) {
        receive.received_bytes = receive.received_bytes.saturating_add(decoded.len() as u64);
        receive.chunks.insert(sequence, decoded);
    }
    drop(receives);
    tracing::debug!(target: "welcome.trace", stage = "chunk_recv", welcome_id = %welcome_id, seq = sequence);

    let ack = WelcomeBlobMessage::ChunkAck {
        welcome_id: welcome_id.clone(),
        sequence,
    };
    match send_welcome_blob_message(state, sender, &ack).await {
        Ok(_) => {
            tracing::debug!(target: "welcome.trace", stage = "chunk_ack_sent", welcome_id = %welcome_id, seq = sequence);
        }
        Err(e) => {
            tracing::warn!(welcome_id = %LogHexId::new("welcome", &welcome_id), sequence, "failed to ack Welcome blob chunk: {e}");
        }
    }
}

async fn handle_welcome_blob_complete(state: &Arc<AppState>, sender: &AgentId, welcome_id: &str) {
    let sender_hex = hex::encode(sender.as_bytes());
    {
        let receives = state.pending_welcome_receives.read().await;
        let Some(receive) = receives.get(welcome_id) else {
            return;
        };
        if receive.source != sender_hex {
            return;
        }
    }
    let receive = state
        .pending_welcome_receives
        .write()
        .await
        .remove(welcome_id);
    let Some(receive) = receive else {
        return;
    };
    if receive.received_bytes != receive.byte_len
        || receive.chunks.len() as u64 != receive.total_chunks
    {
        notify_welcome_waiters(
            state,
            welcome_id,
            Err("incomplete Welcome blob transfer".to_string()),
        )
        .await;
        return;
    }
    let mut bytes = Vec::with_capacity(receive.byte_len as usize);
    for sequence in 0..receive.total_chunks {
        let Some(chunk) = receive.chunks.get(&sequence) else {
            notify_welcome_waiters(
                state,
                welcome_id,
                Err("missing Welcome blob chunk".to_string()),
            )
            .await;
            return;
        };
        bytes.extend_from_slice(chunk);
    }
    if receive.group_id.is_empty() {
        notify_welcome_waiters(
            state,
            welcome_id,
            Err("Welcome blob missing group id".to_string()),
        )
        .await;
        return;
    }
    let actual = welcome_id_for_bytes(&bytes);
    if actual != welcome_id {
        notify_welcome_waiters(
            state,
            welcome_id,
            Err("Welcome blob blake3 mismatch".to_string()),
        )
        .await;
        return;
    }
    notify_welcome_waiters(state, welcome_id, Ok(bytes)).await;
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
        x0x::files::FileMessage::ChunkAck {
            transfer_id,
            sequence,
        } => {
            // Wake the sender's chunk loop. Acks for unknown transfers
            // (already torn down, never started here) are silently dropped.
            if let Some(slot) = state.file_chunk_acks.read().await.get(&transfer_id) {
                slot.record_ack(sequence);
            }
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

    if !is_safe_file_transfer_id(&offer.transfer_id) {
        tracing::warn!(
            "Rejected file offer from {sender_hex}: invalid transfer id {}",
            offer.transfer_id
        );
        return;
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

    let (now_secs, now_ms) = file_transfer_now();

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
        started_at: now_secs,
        started_at_unix_ms: now_ms,
        completed_at_unix_ms: None,
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

fn is_safe_file_transfer_id(transfer_id: &str) -> bool {
    match uuid::Uuid::parse_str(transfer_id) {
        Ok(uuid) => transfer_id == uuid.hyphenated().to_string(),
        Err(_) => false,
    }
}

fn safe_file_transfer_part_path(
    transfers_dir: &FsPath,
    transfer_id: &str,
) -> std::result::Result<PathBuf, String> {
    if !is_safe_file_transfer_id(transfer_id) {
        return Err(format!("invalid file transfer id: {transfer_id}"));
    }
    Ok(transfers_dir.join(format!("{transfer_id}.part")))
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
            t.completed_at_unix_ms = Some(file_transfer_now().1);
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
///
/// Sends chunks over the existing direct-QUIC path (`prefer_raw_quic_if_connected`)
/// with a windowed application-level ACK protocol on top: the sender registers
/// a `FileChunkAckSlot`, waits for `FileMessage::ChunkAck` from the receiver
/// to advance the in-flight window, and only allows up to `FILE_CHUNK_WINDOW`
/// chunks ahead of the last ack at any time. This caps queue pressure on the
/// receiver's `subscribe_direct` subscriber queue and prevents the silent
/// chunk-loss regression that bricked 100M transfers on 2026-04-30.
async fn stream_file_chunks(
    state: &Arc<AppState>,
    transfer_id: &str,
    source_path: &str,
    sha256: &str,
    agent_id: &AgentId,
) {
    use tokio::io::AsyncReadExt;

    // Register an ack slot before we start streaming so any acks that race
    // ahead of our first chunk are not dropped.
    let ack_slot = Arc::new(FileChunkAckSlot::new());
    state
        .file_chunk_acks
        .write()
        .await
        .insert(transfer_id.to_string(), Arc::clone(&ack_slot));

    // Helper that always cleans up the ack slot, regardless of how the
    // streaming task exits.
    let mark_failed = |state: &Arc<AppState>, transfer_id: &str, error: String| {
        let state = Arc::clone(state);
        let transfer_id = transfer_id.to_string();
        async move {
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(&transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(error);
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
        }
    };

    let mut file = match tokio::fs::File::open(source_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Cannot open file {source_path}: {e}");
            mark_failed(state, transfer_id, format!("Cannot open file: {e}")).await;
            state.file_chunk_acks.write().await.remove(transfer_id);
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
                mark_failed(state, transfer_id, format!("Read error: {e}")).await;
                state.file_chunk_acks.write().await.remove(transfer_id);
                return;
            }
        };

        // Apply windowed back-pressure before sending: never have more than
        // FILE_CHUNK_WINDOW chunks ahead of the receiver's last ack.
        if let Err(e) = wait_for_chunk_window(&ack_slot, sequence).await {
            tracing::error!("Chunk window wait failed for {transfer_id}: {e}");
            mark_failed(state, transfer_id, e).await;
            state.file_chunk_acks.write().await.remove(transfer_id);
            return;
        }

        let chunk_data = BASE64.encode(&buf[..n]);
        let chunk_msg = x0x::files::FileMessage::Chunk(x0x::files::FileChunk {
            transfer_id: transfer_id.to_string(),
            sequence,
            data: chunk_data,
        });

        if let Err(e) = send_file_chunk_message(state, agent_id, &chunk_msg).await {
            tracing::error!("Send chunk {sequence} failed: {e}");
            mark_failed(
                state,
                transfer_id,
                format!("Send failed at chunk {sequence}: {e}"),
            )
            .await;
            state.file_chunk_acks.write().await.remove(transfer_id);
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

    // Drain the in-flight window: wait until the receiver has acked every
    // chunk we sent before declaring the transfer Complete. Without this,
    // the Complete message can arrive before the receiver has processed the
    // last few chunks, which is exactly what the receiver logged as
    // "file complete arrived before final chunk; deferring finalize".
    if sequence > 0 {
        let last_seq = sequence - 1;
        if let Err(e) = wait_for_final_acks(&ack_slot, last_seq).await {
            tracing::error!("Final chunk ack wait failed for {transfer_id}: {e}");
            mark_failed(state, transfer_id, e).await;
            state.file_chunk_acks.write().await.remove(transfer_id);
            return;
        }
    }

    // Send completion message
    let complete_msg = x0x::files::FileMessage::Complete(x0x::files::FileComplete {
        transfer_id: transfer_id.to_string(),
        sha256: sha256.to_string(),
    });

    if let Err(e) = send_file_message(state, agent_id, &complete_msg).await {
        tracing::error!("Send complete message failed: {e}");
        mark_failed(state, transfer_id, format!("Send complete failed: {e}")).await;
        state.file_chunk_acks.write().await.remove(transfer_id);
        return;
    }

    // Mark as complete on sender side
    {
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Complete;
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
    }
    state.file_chunk_acks.write().await.remove(transfer_id);
    tracing::info!("File transfer complete (sender): {transfer_id}");
}

/// Block until the receiver has acked every chunk up to and including
/// `last_seq`. Used after the sender's final chunk so we don't send the
/// Complete envelope before the receiver has seen the chunks.
async fn wait_for_final_acks(
    slot: &FileChunkAckSlot,
    last_seq: u64,
) -> std::result::Result<(), String> {
    let deadline = tokio::time::Instant::now() + FILE_CHUNK_ACK_TIMEOUT;
    loop {
        let acked = slot.last_acked.load(Ordering::SeqCst);
        if acked != u64::MAX && acked >= last_seq {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timeout waiting for final chunk ack >= {last_seq}; last_acked={}",
                if acked == u64::MAX {
                    "<none>".to_string()
                } else {
                    acked.to_string()
                }
            ));
        }
        let notified = slot.notify.notified();
        tokio::pin!(notified);
        tokio::select! {
            _ = notified.as_mut() => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
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
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
    }
}

/// Handle an incoming file chunk — append to partial file.
/// Clean up partial file and hasher state for a failed transfer.
async fn cleanup_failed_transfer(state: &Arc<AppState>, transfer_id: &str) {
    // Remove .part file
    match safe_file_transfer_part_path(&state.transfers_dir, transfer_id) {
        Ok(part_path) => {
            let _ = tokio::fs::remove_file(&part_path).await;
        }
        Err(e) => {
            tracing::warn!("Skipping partial file cleanup: {e}");
        }
    }

    // Remove hasher + any buffered out-of-order chunks
    state.receive_hashers.write().await.remove(transfer_id);
    state.pending_file_chunks.write().await.remove(transfer_id);
}

async fn handle_file_chunk(state: &Arc<AppState>, sender: &AgentId, chunk: x0x::files::FileChunk) {
    let sender_hex = hex::encode(sender.as_bytes());

    // Validate: transfer must exist, be a receiving transfer, be InProgress,
    // and the sender must match the original offer's remote_agent_id.
    let expected_sequence = {
        let transfers = state.file_transfers.read().await;
        match transfers.get(&chunk.transfer_id) {
            Some(t) => match x0x::files::receive_chunk_expected_sequence(t, &sender_hex) {
                Ok(sequence) => sequence,
                Err(x0x::files::FileChunkValidationError::WrongSender) => {
                    tracing::warn!(
                        "Chunk from wrong agent for {}: expected {} got {sender_hex}",
                        chunk.transfer_id,
                        t.remote_agent_id
                    );
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        "Ignoring chunk for transfer {} (dir={:?} status={:?})",
                        chunk.transfer_id,
                        t.direction,
                        t.status
                    );
                    return;
                }
            },
            None => {
                tracing::warn!("Ignoring chunk for unknown transfer {}", chunk.transfer_id);
                return;
            }
        }
    };

    let data = match BASE64.decode(&chunk.data) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Chunk decode error for {}: {e}", chunk.transfer_id);
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(format!("Chunk decode error: {e}"));
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
            drop(transfers);
            cleanup_failed_transfer(state, &chunk.transfer_id).await;
            return;
        }
    };

    if chunk.sequence < expected_sequence {
        tracing::debug!(
            transfer_id = %chunk.transfer_id,
            sequence = chunk.sequence,
            expected_sequence,
            "ignoring duplicate/stale file chunk"
        );
        return;
    }

    if chunk.sequence > expected_sequence {
        let mut pending = state.pending_file_chunks.write().await;
        let entry = pending.entry(chunk.transfer_id.clone()).or_default();
        if entry.insert(chunk.sequence, data).is_some() {
            tracing::debug!(
                transfer_id = %chunk.transfer_id,
                sequence = chunk.sequence,
                "replaced buffered out-of-order file chunk"
            );
        } else {
            tracing::debug!(
                transfer_id = %chunk.transfer_id,
                sequence = chunk.sequence,
                expected_sequence,
                "buffered out-of-order file chunk"
            );
        }
        // Ack even for buffered chunks: it lets the sender's window advance.
        send_chunk_ack(state, sender, &chunk.transfer_id, chunk.sequence).await;
        return;
    }

    let chunk_seq = chunk.sequence;
    if let Err(e) = apply_ready_file_chunks(state, &chunk.transfer_id, chunk.sequence, data).await {
        tracing::error!("File chunk apply failed for {}: {e}", chunk.transfer_id);
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(e);
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
        drop(transfers);
        cleanup_failed_transfer(state, &chunk.transfer_id).await;
        return;
    }

    // Successful apply — ack the chunk so the sender's in-flight window
    // can advance. Ack carries this chunk's sequence; if `apply_ready_file_chunks`
    // drained additional buffered chunks above this one, those were already
    // acked when they arrived (out-of-order buffer path above).
    send_chunk_ack(state, sender, &chunk.transfer_id, chunk_seq).await;
}

/// Send a `FileMessage::ChunkAck` back to the sender. Failures to send the
/// ack are logged but not propagated — the sender's ack-wait timeout will
/// surface a stuck transfer if too many acks go missing.
async fn send_chunk_ack(state: &Arc<AppState>, sender: &AgentId, transfer_id: &str, sequence: u64) {
    let ack = x0x::files::FileMessage::ChunkAck {
        transfer_id: transfer_id.to_string(),
        sequence,
    };
    if let Err(e) = send_file_message(state, sender, &ack).await {
        tracing::warn!(transfer_id, sequence, "failed to send file chunk ack: {e}");
    }
}

async fn apply_ready_file_chunks(
    state: &Arc<AppState>,
    transfer_id: &str,
    first_sequence: u64,
    first_data: Vec<u8>,
) -> std::result::Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let part_path = safe_file_transfer_part_path(&state.transfers_dir, transfer_id)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part_path)
        .await
        .map_err(|e| format!("Cannot write chunk: {e}"))?;

    let mut sequence = first_sequence;
    let mut data = first_data;

    loop {
        let (expected_sequence, new_total, total_size) = {
            let transfers = state.file_transfers.read().await;
            let t = transfers
                .get(transfer_id)
                .ok_or_else(|| "transfer disappeared during chunk apply".to_string())?;
            let expected = if t.chunk_size > 0 {
                t.bytes_transferred / t.chunk_size as u64
            } else {
                0
            };
            if sequence != expected {
                return Err(format!(
                    "Out-of-order chunk: expected {} got {}",
                    expected, sequence
                ));
            }
            let new_total = t.bytes_transferred + data.len() as u64;
            if new_total > t.total_size {
                return Err(format!(
                    "Received data exceeds declared file size: {} + {} > {}",
                    t.bytes_transferred,
                    data.len(),
                    t.total_size
                ));
            }
            (expected, new_total, t.total_size)
        };

        file.write_all(&data)
            .await
            .map_err(|e| format!("Write failed: {e}"))?;

        {
            let mut hashers = state.receive_hashers.write().await;
            hashers
                .entry(transfer_id.to_string())
                .or_insert_with(Sha256::new)
                .update(&data);
        }

        let maybe_expected_sha256 = {
            let mut transfers = state.file_transfers.write().await;
            let t = transfers
                .get_mut(transfer_id)
                .ok_or_else(|| "transfer disappeared while updating progress".to_string())?;
            t.bytes_transferred = new_total;
            if t.bytes_transferred == t.total_size {
                Some(t.sha256.clone())
            } else {
                None
            }
        };

        if let Some(expected_sha256) = maybe_expected_sha256 {
            finalize_received_transfer(state, transfer_id, &expected_sha256).await;
            return Ok(());
        }

        let next_sequence = expected_sequence + 1;
        let maybe_buffered = {
            let mut pending = state.pending_file_chunks.write().await;
            let next = pending
                .get_mut(transfer_id)
                .and_then(|buffer| buffer.remove(&next_sequence));
            let empty = pending
                .get(transfer_id)
                .is_some_and(std::collections::BTreeMap::is_empty);
            if empty {
                pending.remove(transfer_id);
            }
            next
        };

        match maybe_buffered {
            Some(next) => {
                sequence = next_sequence;
                data = next;
            }
            None => {
                if new_total < total_size {
                    return Ok(());
                }
                return Ok(());
            }
        }
    }
}

async fn finalize_received_transfer(
    state: &Arc<AppState>,
    transfer_id: &str,
    expected_sha256: &str,
) {
    let part_path = match safe_file_transfer_part_path(&state.transfers_dir, transfer_id) {
        Ok(path) => path,
        Err(e) => {
            tracing::error!("Cannot finalize received transfer: {e}");
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(e);
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
            return;
        }
    };

    let computed_hash = {
        let mut hashers = state.receive_hashers.write().await;
        match hashers.remove(transfer_id) {
            Some(hasher) => hex::encode(hasher.finalize()),
            None => {
                tracing::error!("No hasher found for transfer {transfer_id}");
                let mut transfers = state.file_transfers.write().await;
                if let Some(t) = transfers.get_mut(transfer_id) {
                    t.status = x0x::files::TransferStatus::Failed;
                    t.error = Some("No hash state found".to_string());
                    t.completed_at_unix_ms = Some(file_transfer_now().1);
                }
                return;
            }
        }
    };

    if computed_hash != expected_sha256 {
        tracing::error!(
            "SHA-256 mismatch for {transfer_id}: expected {} got {}",
            expected_sha256,
            computed_hash
        );
        let _ = tokio::fs::remove_file(&part_path).await;
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!(
                "SHA-256 mismatch: expected {} got {}",
                expected_sha256, computed_hash
            ));
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
        return;
    }

    let raw_filename = {
        let transfers = state.file_transfers.read().await;
        transfers
            .get(transfer_id)
            .map(|t| t.filename.clone())
            .unwrap_or_else(|| transfer_id.to_string())
    };
    let filename = x0x::files::received_file_output_name(transfer_id, &raw_filename);

    let final_path = state.transfers_dir.join(&filename);
    if let Err(e) = tokio::fs::rename(&part_path, &final_path).await {
        tracing::error!("Failed to rename part file: {e}");
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!("Failed to finalize file: {e}"));
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
        return;
    }

    {
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Complete;
            t.output_path = Some(final_path.to_string_lossy().to_string());
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
    }
    state.pending_file_chunks.write().await.remove(transfer_id);

    let _ = state.broadcast_tx.send(SseEvent {
        event_type: "file:complete".to_string(),
        data: serde_json::json!({
            "transfer_id": transfer_id,
            "filename": filename,
            "sha256": computed_hash,
            "path": final_path.to_string_lossy(),
        }),
    });

    tracing::info!(
        "File transfer complete (receiver): {} -> {}",
        transfer_id,
        final_path.display()
    );
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
    // If the sender's complete arrives before the last chunk is processed,
    // defer finalization — the chunk handler will finalize as soon as the
    // declared byte count has been received.
    let (expected_sha256, bytes_transferred, total_size) = {
        let transfers = state.file_transfers.read().await;
        match transfers.get(&complete.transfer_id) {
            Some(t)
                if t.direction == x0x::files::TransferDirection::Receiving
                    && t.status == x0x::files::TransferStatus::InProgress =>
            {
                if t.remote_agent_id != sender_hex {
                    tracing::warn!(
                        "Complete from wrong agent for {}: expected {} got {sender_hex}",
                        complete.transfer_id,
                        t.remote_agent_id
                    );
                    return;
                }
                (t.sha256.clone(), t.bytes_transferred, t.total_size)
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

    if bytes_transferred < total_size {
        tracing::info!(
            transfer_id = %complete.transfer_id,
            bytes_transferred,
            total_size,
            "file complete arrived before final chunk; deferring finalize until declared bytes are received"
        );
        return;
    }

    finalize_received_transfer(state, &complete.transfer_id, &expected_sha256).await;
}

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

    fn fake_group_state_commit(
        group_id: &str,
        revision: u64,
        committed_by: &str,
    ) -> x0x::groups::GroupStateCommit {
        x0x::groups::GroupStateCommit {
            group_id: group_id.to_string(),
            revision,
            prev_state_hash: Some(format!("state-{}", revision.saturating_sub(1))),
            roster_root: "roster".to_string(),
            policy_hash: "policy".to_string(),
            public_meta_hash: "meta".to_string(),
            security_binding: Some("treekem:epoch=1".to_string()),
            state_hash: format!("state-{revision}"),
            withdrawn: false,
            committed_by: committed_by.to_string(),
            committed_at: revision,
            signer_public_key: "pub".to_string(),
            signature: "sig".to_string(),
        }
    }

    fn sample_group_card(group_id: &str, revision: u64, issued_at: u64) -> x0x::groups::GroupCard {
        x0x::groups::GroupCard {
            group_id: group_id.to_string(),
            name: format!("Group {group_id}"),
            description: String::new(),
            avatar_url: None,
            banner_url: None,
            tags: Vec::new(),
            policy_summary: x0x::groups::GroupPolicySummary {
                discoverability: x0x::groups::GroupDiscoverability::PublicDirectory,
                admission: x0x::groups::GroupAdmission::RequestAccess,
                confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
                read_access: x0x::groups::GroupReadAccess::MembersOnly,
                write_access: x0x::groups::GroupWriteAccess::MembersOnly,
            },
            owner_agent_id: "ff".repeat(32),
            admin_count: 1,
            member_count: 1,
            created_at: issued_at,
            updated_at: issued_at,
            request_access_enabled: true,
            metadata_topic: None,
            revision,
            state_hash: format!("state-{revision}"),
            prev_state_hash: None,
            issued_at,
            expires_at: issued_at + 1_000,
            authority_agent_id: String::new(),
            authority_public_key: String::new(),
            withdrawn: false,
            signature: String::new(),
        }
    }

    fn version_newer_than_current() -> String {
        let mut version = semver::Version::parse(x0x::VERSION).expect("current version is semver");
        version.patch += 1;
        version.to_string()
    }

    #[test]
    fn direct_message_send_config_requires_gossip_ack_by_default() {
        let config = direct_message_send_config();
        assert!(config.require_gossip_ack);
        // Raw-QUIC fallback must be loss-detecting (receive-pipeline ACK), or
        // a send into a superseded connection reports Ok, the retry never
        // fires, and the recipient's app never sees the message.
        assert_eq!(
            config.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
    }

    // ── ADR-0016 R2: REST pre-check (exact §3 string + status code) ─────

    fn sole_owner_group() -> (x0x::groups::GroupInfo, String) {
        let kp = x0x::identity::AgentKeypair::generate().expect("keypair");
        let owner_hex = hex::encode(kp.agent_id().as_bytes());
        let info = x0x::groups::GroupInfo::with_policy(
            "G".to_string(),
            "d".to_string(),
            kp.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        (info, owner_hex)
    }

    /// Why: §3 fixes this error contract verbatim — handlers must return
    /// 409 with exactly this string when an act would strip the last admin.
    #[test]
    fn last_admin_precheck_returns_409_with_exact_spec_string() {
        let (info, owner_hex) = sole_owner_group();
        let (status, body) = last_admin_precheck(&info, |g| {
            g.set_member_role(&owner_hex, x0x::groups::GroupRole::Member)
        })
        .expect("demoting the sole admin must trip the pre-check");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body.0["error"].as_str(),
            Some("a group must always have at least one admin; make another member an admin first")
        );
    }

    /// Why: the pre-check must evaluate the proposed post-mutation roster —
    /// acts that keep at least one active admin (including a legacy Owner
    /// normalising to Admin) must pass untouched.
    #[test]
    fn last_admin_precheck_passes_when_admins_remain() {
        let (mut info, owner_hex) = sole_owner_group();
        // Owner self-normalising to admin keeps the admin count at 1.
        assert!(last_admin_precheck(&info, |g| {
            g.set_member_role(&owner_hex, x0x::groups::GroupRole::Admin)
        })
        .is_none());
        // Removing or banning a plain member never trips the invariant.
        info.add_member(
            "bb".repeat(32),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
        assert!(last_admin_precheck(&info, |g| g.remove_member(&"bb".repeat(32), None)).is_none());
        assert!(last_admin_precheck(&info, |g| g.ban_member(&"bb".repeat(32), None)).is_none());
    }

    /// Why: withdrawn state is the invariant's exemption (the exit valve) —
    /// the pre-check must never block acts on an already-ended group.
    #[test]
    fn last_admin_precheck_exempts_withdrawn_groups() {
        let (mut info, owner_hex) = sole_owner_group();
        info.withdrawn = true;
        assert!(last_admin_precheck(&info, |g| {
            g.set_member_role(&owner_hex, x0x::groups::GroupRole::Member)
        })
        .is_none());
    }

    #[test]
    fn group_card_cache_prunes_expired_cards() {
        let mut cache = HashMap::new();
        cache.insert(
            "expired".to_string(),
            sample_group_card("expired", 1, 1_000),
        );
        cache.insert("fresh".to_string(), sample_group_card("fresh", 1, 3_000));

        prune_expired_group_cards(&mut cache, 2_001);

        assert!(!cache.contains_key("expired"));
        assert!(cache.contains_key("fresh"));
    }

    #[test]
    fn rendered_gui_does_not_disclose_api_token() {
        let html = render_gui_html();

        assert!(!html.contains("super-secret-api-token"));
        assert!(!html.contains("X0X_TOKEN"));
    }

    #[test]
    fn group_card_cache_cap_evicts_earliest_expiry() {
        let mut cache = HashMap::new();
        cache.insert("earliest".to_string(), sample_group_card("earliest", 1, 1));
        for idx in 0..GROUP_CARD_CACHE_CAP {
            let group_id = format!("group-{idx}");
            cache.insert(
                group_id.clone(),
                sample_group_card(&group_id, 1, 10_000 + idx as u64),
            );
        }

        enforce_group_card_cache_cap(&mut cache);

        assert_eq!(cache.len(), GROUP_CARD_CACHE_CAP);
        assert!(!cache.contains_key("earliest"));
    }

    #[test]
    fn group_card_cache_insert_preserves_higher_revision() {
        let mut cache = HashMap::new();
        let high = sample_group_card("same", 3, 1_000);
        let low = sample_group_card("same", 2, 2_000);

        assert!(cache_group_card_if_newer(
            &mut cache,
            "same".to_string(),
            high.clone()
        ));
        assert!(!cache_group_card_if_newer(
            &mut cache,
            "same".to_string(),
            low
        ));

        assert_eq!(
            cache.get("same").expect("card retained").revision,
            high.revision
        );
    }

    #[test]
    fn group_card_cache_stale_withdrawal_does_not_evict_newer_card() {
        let mut cache = HashMap::new();
        let current = sample_group_card("same", 3, 2_000);
        let mut stale_withdrawal = sample_group_card("same", 2, 3_000);
        stale_withdrawal.withdrawn = true;

        cache.insert("same".to_string(), current.clone());

        assert!(!remove_group_card_if_not_stale(
            &mut cache,
            &stale_withdrawal
        ));
        assert_eq!(
            cache.get("same").expect("newer card retained").revision,
            current.revision
        );
    }

    #[test]
    fn withdrawn_group_card_marks_existing_stub_without_regressing_newer_stub() {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "old".to_string(),
            String::new(),
            AgentId([1; 32]),
            "same".to_string(),
            x0x::groups::GroupPolicy::from(&sample_group_card("same", 1, 1_000).policy_summary),
        );
        info.state_revision = 1;
        info.updated_at = 1_000;
        info.withdrawn = false;
        info.shared_secret = Some(vec![9; 32]);

        let mut withdrawal = sample_group_card("same", 2, 2_000);
        withdrawal.withdrawn = true;

        assert!(apply_withdrawn_group_card_to_group_info(
            &mut info,
            &withdrawal
        ));
        assert!(info.withdrawn);
        assert_eq!(info.state_revision, 2);
        assert_eq!(info.state_hash, "state-2");
        assert_eq!(info.shared_secret, None);

        let mut newer_info = info.clone();
        newer_info.withdrawn = false;
        newer_info.state_revision = 3;
        newer_info.updated_at = 3_000;

        assert!(!apply_withdrawn_group_card_to_group_info(
            &mut newer_info,
            &withdrawal
        ));
        assert!(!newer_info.withdrawn);
        assert_eq!(newer_info.state_revision, 3);
    }

    #[test]
    fn withdrawn_group_record_guard_matches_stable_id_for_stale_card_imports() {
        let mut groups = HashMap::new();
        let mut info = x0x::groups::GroupInfo::with_policy(
            "withdrawn".to_string(),
            String::new(),
            AgentId([2; 32]),
            "local-mls-id".to_string(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            "stable-card-id".to_string(),
            "02".repeat(32),
            info.created_at,
            String::new(),
        ));
        info.withdrawn = true;
        groups.insert("local-mls-id".to_string(), info);

        assert!(has_withdrawn_group_record(&groups, "local-mls-id"));
        assert!(has_withdrawn_group_record(&groups, "stable-card-id"));
        let aliases =
            collect_same_stable_group_aliases(&groups, "local-mls-id", Some("stable-card-id"));
        assert!(join_result_key_matches_any_group_alias(
            "stable-card-id:member",
            &aliases,
        ));
    }

    #[test]
    fn ban_store_guard_allows_active_ban_and_rejects_withdrawn_same_stable_record() {
        let group_id = "ban-local-mls-id";
        let withdrawn_alias = "ban-withdrawn-mls-id";
        let stable_group_id = "ban-stable-card-id";
        let admin_hex = "02".repeat(32);
        let target_hex = "03".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "ban guard".to_string(),
            String::new(),
            AgentId([2; 32]),
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            admin_hex.clone(),
            info.created_at,
            String::new(),
        ));
        info.add_member(
            target_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.roster_revision = info.roster_revision.saturating_add(1);
        info.recompute_state_hash();

        let mut allowed_groups = HashMap::from([(group_id.to_string(), info.clone())]);
        let mut banned_next = info.clone();
        banned_next.ban_member(&target_hex, Some(admin_hex.clone()));
        banned_next.roster_revision = banned_next.roster_revision.saturating_add(1);

        assert!(store_named_group_info_locked(
            &mut allowed_groups,
            group_id,
            banned_next
        ));
        assert!(allowed_groups[group_id].members_v2[&target_hex].is_banned());

        let mut withdrawn = info.clone();
        withdrawn.mls_group_id = withdrawn_alias.to_string();
        withdrawn.withdrawn = true;
        withdrawn.shared_secret = None;
        let before = info.clone();
        let mut guarded_groups = HashMap::from([
            (group_id.to_string(), info),
            (withdrawn_alias.to_string(), withdrawn),
        ]);
        let mut rejected_next = before.clone();
        rejected_next.ban_member(&target_hex, Some(admin_hex));
        rejected_next.roster_revision = rejected_next.roster_revision.saturating_add(1);

        assert!(!store_named_group_info_locked(
            &mut guarded_groups,
            group_id,
            rejected_next
        ));
        let stored = &guarded_groups[group_id];
        assert_eq!(stored.members_v2, before.members_v2);
        assert_eq!(stored.roster_revision, before.roster_revision);
        assert_eq!(stored.state_hash, before.state_hash);
        assert!(!stored.members_v2[&target_hex].is_banned());
    }

    fn secure_post_crypto_recheck_group(
        group_id: &str,
        stable_group_id: &str,
        secure_plane: x0x::mls::SecureGroupPlane,
        withdrawn: bool,
    ) -> x0x::groups::GroupInfo {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([2; 32]),
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            "02".repeat(32),
            info.created_at,
            String::new(),
        ));
        info.secure_plane = secure_plane;
        info.secret_epoch = 7;
        info.shared_secret = (!withdrawn).then(|| vec![9; 32]);
        info.withdrawn = withdrawn;
        info
    }

    fn assert_post_crypto_lost_race_drops_secure_effect(
        secure_plane: x0x::mls::SecureGroupPlane,
        effect: serde_json::Value,
        proof_field: &str,
    ) {
        let group_id = "local-mls-id";
        let stable_group_id = "stable-card-id";
        let mut groups = HashMap::from([(
            group_id.to_string(),
            secure_post_crypto_recheck_group(group_id, stable_group_id, secure_plane, false),
        )]);

        let (status, body) = secure_group_effect_response_after_terminality_recheck_from_groups(
            &groups,
            group_id,
            Some(stable_group_id),
            effect.clone(),
        );
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.0.get(proof_field).is_some(),
            "active group should return the computed secure effect field {proof_field}"
        );

        groups.insert(
            group_id.to_string(),
            secure_post_crypto_recheck_group(group_id, stable_group_id, secure_plane, true),
        );
        let (status, body) = secure_group_effect_response_after_terminality_recheck_from_groups(
            &groups,
            group_id,
            Some(stable_group_id),
            effect,
        );

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0["ok"].as_bool(), Some(false));
        assert_eq!(body.0["error"].as_str(), Some("group is withdrawn"));
        for field in [
            "payload_b64",
            "ciphertext_b64",
            "nonce_b64",
            "secret_b64",
            "kem_ciphertext_b64",
            "aead_nonce_b64",
            "aead_ciphertext_b64",
        ] {
            assert!(
                body.0.get(field).is_none(),
                "withdrawn conflict must not leak secure effect field {field}"
            );
        }
    }

    #[test]
    fn treekem_decrypt_lost_race_drops_plaintext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::TreeKem,
            serde_json::json!({
                "ok": true,
                "payload_b64": "c2VjcmV0",
                "secret_epoch": 7,
                "secure_plane": "treekem",
            }),
            "payload_b64",
        );
    }

    #[test]
    fn gss_decrypt_lost_race_drops_plaintext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "payload_b64": "c2VjcmV0",
                "secret_epoch": 7,
            }),
            "payload_b64",
        );
    }

    #[test]
    fn treekem_encrypt_lost_race_drops_ciphertext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::TreeKem,
            serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y2lwaGVydGV4dA==",
                "secret_epoch": 7,
                "secure_plane": "treekem",
            }),
            "ciphertext_b64",
        );
    }

    #[test]
    fn gss_encrypt_lost_race_drops_ciphertext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y2lwaGVydGV4dA==",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 7,
            }),
            "ciphertext_b64",
        );
    }

    #[test]
    fn gss_reseal_lost_race_drops_secret_envelope() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "group_id": "stable-card-id",
                "recipient": "aa",
                "secret_epoch": 7,
                "kem_ciphertext_b64": "a2Vt",
                "aead_nonce_b64": "bm9uY2U=",
                "aead_ciphertext_b64": "YWVhZA==",
            }),
            "kem_ciphertext_b64",
        );
    }

    #[test]
    fn open_envelope_lost_race_drops_opened_secret() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "opened": true,
                "secret_b64": "c2VjcmV0",
            }),
            "secret_b64",
        );
    }

    struct PostCryptoForcedWithdrawal {
        ids: Vec<String>,
    }

    struct AtomicPersistPostJsonForcedWithdrawal {
        ids: Vec<String>,
    }

    impl Drop for PostCryptoForcedWithdrawal {
        fn drop(&mut self) {
            let mut forced = POST_CRYPTO_FORCED_WITHDRAWN_GROUPS
                .lock()
                .expect("post-crypto forced-withdrawn test hook poisoned");
            for id in &self.ids {
                forced.remove(id);
            }
        }
    }

    impl Drop for AtomicPersistPostJsonForcedWithdrawal {
        fn drop(&mut self) {
            let mut forced = ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS
                .lock()
                .expect("atomic-persist forced-withdrawn test hook poisoned");
            for id in &self.ids {
                forced.remove(id);
            }
        }
    }

    fn force_post_crypto_withdrawn_ids(ids: &[&str]) -> PostCryptoForcedWithdrawal {
        let ids = ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
        let mut forced = POST_CRYPTO_FORCED_WITHDRAWN_GROUPS
            .lock()
            .expect("post-crypto forced-withdrawn test hook poisoned");
        for id in &ids {
            forced.insert(id.clone());
        }
        PostCryptoForcedWithdrawal { ids }
    }

    fn force_atomic_persist_post_json_withdrawn_ids(
        ids: &[&str],
    ) -> AtomicPersistPostJsonForcedWithdrawal {
        let ids = ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
        let mut forced = ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS
            .lock()
            .expect("atomic-persist forced-withdrawn test hook poisoned");
        for id in &ids {
            forced.insert(id.clone());
        }
        AtomicPersistPostJsonForcedWithdrawal { ids }
    }

    struct TreeKemFinalInstallBeforeMapWriteGuard {
        group_id: String,
    }

    impl Drop for TreeKemFinalInstallBeforeMapWriteGuard {
        fn drop(&mut self) {
            let Ok(mut guard) = TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY.lock() else {
                return;
            };
            if guard
                .as_ref()
                .is_some_and(|(group_id, _)| group_id == &self.group_id)
            {
                *guard = None;
            }
        }
    }

    fn notify_before_treekem_final_install_map_write(
        group_id: &str,
    ) -> (
        Arc<tokio::sync::Notify>,
        TreeKemFinalInstallBeforeMapWriteGuard,
    ) {
        let notify = Arc::new(tokio::sync::Notify::new());
        let mut guard = TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY
            .lock()
            .expect("TreeKEM final install notify hook poisoned");
        *guard = Some((group_id.to_string(), Arc::clone(&notify)));
        (
            notify,
            TreeKemFinalInstallBeforeMapWriteGuard {
                group_id: group_id.to_string(),
            },
        )
    }

    async fn secure_endpoint_test_state() -> Result<(Arc<AppState>, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path();
        let treekem_dir = data_dir.join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;

        let agent = Arc::new(
            Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate()?)
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_peer_cache_disabled()
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await?,
        );
        let contacts = Arc::clone(agent.contacts());
        agent.set_contacts(Arc::clone(&contacts));

        let (broadcast_tx, _) = broadcast::channel::<SseEvent>(16);
        let (shutdown_tx, _) = mpsc::channel::<()>(1);
        let (shutdown_notify, _) = watch::channel(false);
        let (_exec_dm_tx, exec_dm_rx) = mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1);
        let exec_policy = x0x::exec::ExecPolicy::Disabled {
            path: data_dir.join("exec-acl.toml"),
            reason: "test".to_string(),
            loaded_at_unix_ms: 0,
        };
        let exec_service =
            x0x::exec::ExecService::spawn(Arc::clone(&agent), exec_policy, exec_dm_rx);

        let state = Arc::new(AppState {
            agent,
            subscriptions: RwLock::new(HashMap::new()),
            task_lists: RwLock::new(HashMap::new()),
            kv_stores: RwLock::new(HashMap::new()),
            named_groups: RwLock::new(HashMap::new()),
            named_groups_path: data_dir.join("named_groups.json"),
            group_metadata_tasks: RwLock::new(HashMap::new()),
            group_card_cache: RwLock::new(HashMap::new()),
            directory_cache: RwLock::new(x0x::groups::DirectoryShardCache::default()),
            directory_subscriptions: RwLock::new(x0x::groups::SubscriptionSet::default()),
            directory_subscriptions_path: data_dir.join("directory-subscriptions.json"),
            directory_tasks: RwLock::new(HashMap::new()),
            directory_digest_interval_secs: DIRECTORY_DIGEST_INTERVAL_SECS,
            directory_resubscribe_jitter_ms: DIRECTORY_RESUBSCRIBE_JITTER_MS,
            public_messages: RwLock::new(HashMap::new()),
            public_message_tasks: RwLock::new(HashMap::new()),
            agent_kem_keypair: Arc::new(x0x::groups::kem_envelope::AgentKemKeypair::generate()?),
            contacts,
            mls_groups: RwLock::new(HashMap::new()),
            mls_groups_path: data_dir.join("mls_groups.bin"),
            pending_join_results: RwLock::new(HashMap::new()),
            expected_join_result_inviters: StdMutex::new(HashMap::new()),
            pending_welcomes: RwLock::new(HashMap::new()),
            pending_welcome_receives: RwLock::new(HashMap::new()),
            pending_welcome_waiters: RwLock::new(HashMap::new()),
            pending_welcome_acks: RwLock::new(HashMap::new()),
            treekem_pending_events: RwLock::new(HashMap::new()),
            treekem_event_log: RwLock::new(HashMap::new()),
            treekem_catchup_throttle: RwLock::new(HashMap::new()),
            group_membership_locks: RwLock::new(HashMap::new()),
            treekem_groups: RwLock::new(HashMap::new()),
            treekem_dir,
            ws_sessions: RwLock::new(HashMap::new()),
            ws_topics: RwLock::new(HashMap::new()),
            ws_outbound_stats: Arc::new(WsOutboundStats::default()),
            api_address: "127.0.0.1:0".parse().expect("valid test API address"),
            start_time: Instant::now(),
            broadcast_tx,
            file_transfers: RwLock::new(HashMap::new()),
            receive_hashers: RwLock::new(HashMap::new()),
            pending_file_chunks: RwLock::new(HashMap::new()),
            file_chunk_acks: RwLock::new(HashMap::new()),
            transfers_dir: data_dir.join("transfers"),
            shutdown_tx,
            shutdown_notify,
            update_config: DaemonUpdateConfig::default(),
            self_update_enabled: false,
            upgrade_check_cache: Mutex::new(None),
            upgrade_apply_lock: Arc::new(Mutex::new(())),
            api_token: "test-token".to_string(),
            sessions: auth::SessionStore::new(auth::SESSION_TOKEN_TTL),
            exec_service,
            groups_diagnostics: Arc::new(x0x::groups::GroupsDiagnostics::new()),
        });
        Ok((state, dir))
    }

    async fn response_json(response: Response) -> Result<(StatusCode, serde_json::Value)> {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .context("read response body")?;
        let body = serde_json::from_slice(&bytes).context("decode response body")?;
        Ok((status, body))
    }

    #[tokio::test]
    async fn agent_card_group_invite_from_get_card_is_accepted_on_join() -> Result<()> {
        let (authority, _authority_dir) = secure_endpoint_test_state().await?;
        let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
        let group_id = "5c".repeat(32);
        let authority_id = authority.agent.agent_id();
        let mut authority_info = x0x::groups::GroupInfo::with_policy(
            "card invite provenance".to_string(),
            "base-state fields should survive card export".to_string(),
            authority_id,
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        authority_info.recompute_state_hash();
        let stable_group_id = authority_info.stable_group_id().to_string();
        let authority_state_hash = authority_info.state_hash.clone();
        let authority_members = authority_info.members_v2.clone();
        authority
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), authority_info);

        let card_response = get_agent_card(
            State(Arc::clone(&authority)),
            Query(CardQuery {
                display_name: Some("authority".to_string()),
                include_groups: Some(true),
                include_local_addresses: false,
            }),
        )
        .await
        .into_response();
        let (card_status, card_body) = response_json(card_response).await?;
        assert_eq!(card_status, StatusCode::OK);
        let card: x0x::groups::card::AgentCard = serde_json::from_value(card_body["card"].clone())
            .context("decode agent card from handler response")?;
        let card_group = card
            .groups
            .iter()
            .find(|group| group.name == "card invite provenance")
            .expect("agent card should include the named group invite");
        let invite = x0x::groups::invite::SignedInvite::from_link(&card_group.invite_link)
            .map_err(|e| anyhow::anyhow!("decode card invite: {e}"))?;

        assert_eq!(
            invite.stable_group_id.as_deref(),
            Some(stable_group_id.as_str())
        );
        assert_eq!(
            invite.base_state_hash.as_deref(),
            Some(authority_state_hash.as_str())
        );
        assert_eq!(invite.base_members_v2.as_ref(), Some(&authority_members));
        assert_eq!(
            invite
                .creator_agent_id_from_base_state()
                .map_err(|e| anyhow::anyhow!("derive creator provenance: {e}"))?,
            hex::encode(authority_id.as_bytes())
        );
        {
            let groups = authority.named_groups.read().await;
            let info = groups.get(&group_id).expect("authority group retained");
            assert!(
                info.issued_invites.is_empty(),
                "GET /agent/card must not record or persist card-generated invite secrets"
            );
        }

        NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST
            .lock()
            .expect("publish-attempt recorder poisoned")
            .clear();
        let join_response = join_group_via_invite(
            State(Arc::clone(&joiner)),
            Json(JoinGroupRequest {
                invite: card_group.invite_link.clone(),
                display_name: Some("joiner".to_string()),
            }),
        )
        .await
        .into_response();
        let (join_status, join_body) = response_json(join_response).await?;

        assert_eq!(
            join_status,
            StatusCode::OK,
            "card invite join should be accepted, body: {join_body}"
        );
        assert_ne!(
            join_status,
            StatusCode::BAD_REQUEST,
            "card invite join must not fail with the pre-fix missing-base-state 400"
        );
        let joiner_hex = hex::encode(joiner.agent.agent_id().as_bytes());
        let metadata_topic = {
            let groups = joiner.named_groups.read().await;
            let stub = groups
                .get(&group_id)
                .expect("accepted card invite should create a local join stub");
            assert_eq!(stub.stable_group_id(), stable_group_id.as_str());
            assert_eq!(stub.state_hash, authority_state_hash);
            assert_eq!(stub.members_v2, authority_members);
            assert!(
                !stub.has_active_member(&joiner_hex),
                "card-derived convergence remains Phase 2; this guard only proves accepted join stub formation"
            );
            stub.metadata_topic.clone()
        };
        let publish_attempts = NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST
            .lock()
            .expect("publish-attempt recorder poisoned");
        assert!(
            publish_attempts
                .iter()
                .any(|(topic, event_group_id)| topic == &metadata_topic
                    && event_group_id == &stable_group_id),
            "join handler should attempt to publish the joiner-authored MemberJoined request"
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_card_does_not_export_withdrawn_group_invites() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let active_group_id = "6a".repeat(32);
        let withdrawn_group_id = "6b".repeat(32);
        let stale_active_group_id = "6c".repeat(32);
        let withdrawn_alias_group_id = "6d".repeat(32);
        let agent_id = state.agent.agent_id();
        let mut active = x0x::groups::GroupInfo::with_policy(
            "active card group".to_string(),
            String::new(),
            agent_id,
            active_group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        active.recompute_state_hash();
        let mut withdrawn = x0x::groups::GroupInfo::with_policy(
            "withdrawn card group".to_string(),
            String::new(),
            agent_id,
            withdrawn_group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        withdrawn.withdrawn = true;
        clear_group_info_key_material(&mut withdrawn);
        withdrawn.recompute_state_hash();
        let mut stale_active = x0x::groups::GroupInfo::with_policy(
            "stale active alias".to_string(),
            String::new(),
            agent_id,
            stale_active_group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        stale_active.recompute_state_hash();
        let mut withdrawn_same_stable_alias = stale_active.clone();
        withdrawn_same_stable_alias.name = "withdrawn same-stable alias".to_string();
        withdrawn_same_stable_alias.mls_group_id = withdrawn_alias_group_id.clone();
        withdrawn_same_stable_alias.withdrawn = true;
        clear_group_info_key_material(&mut withdrawn_same_stable_alias);
        withdrawn_same_stable_alias.recompute_state_hash();
        {
            let mut groups = state.named_groups.write().await;
            groups.insert(active_group_id, active);
            groups.insert(withdrawn_group_id, withdrawn);
            groups.insert(stale_active_group_id, stale_active);
            groups.insert(withdrawn_alias_group_id, withdrawn_same_stable_alias);
        }

        let card_response = get_agent_card(
            State(Arc::clone(&state)),
            Query(CardQuery {
                display_name: Some("authority".to_string()),
                include_groups: Some(true),
                include_local_addresses: false,
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(card_response).await?;
        assert_eq!(status, StatusCode::OK);
        let card: x0x::groups::card::AgentCard = serde_json::from_value(body["card"].clone())
            .context("decode agent card from handler response")?;

        assert!(
            card.groups
                .iter()
                .any(|group| group.name == "active card group"),
            "active groups should still be exported when include_groups=true"
        );
        assert!(
            card.groups
                .iter()
                .all(|group| group.name != "withdrawn card group"),
            "withdrawn tombstones must not be re-advertised as joinable card invites"
        );
        assert!(
            card.groups
                .iter()
                .all(|group| group.name != "stale active alias"),
            "stale active aliases for a withdrawn stable group must not be re-advertised"
        );
        Ok(())
    }

    /// Rule 9: prove the *real* REST handlers enforce admin authority.
    ///
    /// `tests/membership_authority.rs` exercises the library authority
    /// primitives, but it re-implements the handler pre-check shape, so it
    /// cannot catch a handler that silently drops `require_admin_or_above`.
    /// This test invokes the actual handlers with a non-admin local caller and
    /// asserts each rejects with 403 — so deleting an authority gate in any of
    /// the membership handlers fails here, exactly the change class ADR-0016
    /// makes load-bearing.
    #[tokio::test]
    async fn membership_handlers_reject_non_admin_local_caller() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "7c".repeat(32);
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let foreign_admin = crate::identity::AgentKeypair::generate()?;
        let foreign_admin_hex = hex::encode(foreign_admin.agent_id().as_bytes());
        let target_hex = "33".repeat(32);

        // GSS (non-TreeKEM) group whose admin is a *foreign* agent; the local
        // daemon agent is only a plain Member, so it must not be able to
        // remove/ban/role-change anyone.
        let mut info = x0x::groups::GroupInfo::with_policy(
            "authority gate".to_string(),
            String::new(),
            foreign_admin.agent_id(),
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(foreign_admin_hex.clone()),
            None,
        );
        info.add_member(
            target_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(foreign_admin_hex),
            None,
        );
        info.roster_revision = info.roster_revision.saturating_add(1);
        info.recompute_state_hash();
        assert_ne!(
            info.secure_plane,
            x0x::mls::SecureGroupPlane::TreeKem,
            "test targets the GSS handler path so the admin gate runs before TreeKEM delegation"
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);

        let remove = remove_named_group_member(
            State(Arc::clone(&state)),
            Path((group_id.clone(), target_hex.clone())),
        )
        .await
        .into_response();
        let (remove_status, remove_body) = response_json(remove).await?;
        assert_eq!(
            remove_status,
            StatusCode::FORBIDDEN,
            "remove_named_group_member must reject a non-admin caller, body: {remove_body}"
        );

        let ban = ban_group_member(
            State(Arc::clone(&state)),
            Path((group_id.clone(), target_hex.clone())),
        )
        .await
        .into_response();
        let (ban_status, ban_body) = response_json(ban).await?;
        assert_eq!(
            ban_status,
            StatusCode::FORBIDDEN,
            "ban_group_member must reject a non-admin caller, body: {ban_body}"
        );

        let role = update_member_role(
            State(Arc::clone(&state)),
            Path((group_id.clone(), target_hex.clone())),
            Json(UpdateMemberRoleRequest {
                role: "member".to_string(),
            }),
        )
        .await
        .into_response();
        let (role_status, role_body) = response_json(role).await?;
        assert_eq!(
            role_status,
            StatusCode::FORBIDDEN,
            "update_member_role must reject a non-admin caller, body: {role_body}"
        );

        // The rejected calls must not have mutated the roster.
        let groups = state.named_groups.read().await;
        let after = groups.get(&group_id).expect("group retained");
        assert_eq!(
            after.caller_role(&target_hex),
            Some(x0x::groups::GroupRole::Member),
            "forbidden handler calls must leave the target untouched"
        );
        Ok(())
    }

    fn secure_endpoint_group_for_agent(
        agent_id: AgentId,
        group_id: &str,
        stable_group_id: &str,
        secure_plane: x0x::mls::SecureGroupPlane,
    ) -> x0x::groups::GroupInfo {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            agent_id,
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            hex::encode(agent_id.as_bytes()),
            info.created_at,
            String::new(),
        ));
        info.secure_plane = secure_plane;
        info.secret_epoch = 7;
        info.shared_secret = Some(vec![9; 32]);
        info
    }

    async fn install_secure_endpoint_group(
        state: &Arc<AppState>,
        group_id: &str,
        stable_group_id: &str,
        secure_plane: x0x::mls::SecureGroupPlane,
    ) {
        let info = secure_endpoint_group_for_agent(
            state.agent.agent_id(),
            group_id,
            stable_group_id,
            secure_plane,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
    }

    fn metadata_terminality_test_group(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> (x0x::groups::GroupInfo, String, String) {
        let admin_hex = hex::encode(state.agent.agent_id().as_bytes());
        let member_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "metadata terminality".to_string(),
            String::new(),
            state.agent.agent_id(),
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.shared_secret = Some(vec![9; 32]);
        info.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.recompute_state_hash();
        (info, admin_hex, member_hex)
    }

    fn sign_metadata_terminality_commit(
        parent: &x0x::groups::GroupInfo,
        scratch: &x0x::groups::GroupInfo,
        state: &Arc<AppState>,
        now_ms: u64,
    ) -> x0x::groups::GroupStateCommit {
        x0x::groups::GroupStateCommit::sign(
            parent.stable_group_id().to_string(),
            parent.state_revision.saturating_add(1),
            Some(parent.state_hash.clone()),
            x0x::groups::compute_roster_root(&scratch.members_v2),
            x0x::groups::compute_policy_hash(&scratch.policy),
            x0x::groups::compute_public_meta_hash(&scratch.public_meta()),
            scratch.security_binding.clone(),
            scratch.withdrawn,
            now_ms,
            state.agent.identity().agent_keypair(),
        )
        .expect("signed terminality commit")
    }

    async fn install_metadata_terminality_group(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> (String, String) {
        let (info, admin_hex, member_hex) = metadata_terminality_test_group(state, group_id);
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
        (admin_hex, member_hex)
    }

    #[tokio::test]
    async fn metadata_member_removed_withdrawn_commit_rejected_for_live_group() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-member-removed-terminality";
        let (admin_hex, member_hex) = install_metadata_terminality_group(&state, group_id).await;
        let parent = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .expect("group installed")
            .clone();
        let mut scratch = parent.clone();
        scratch.remove_member(&member_hex, Some(admin_hex.clone()));
        scratch.withdrawn = true;
        let commit = sign_metadata_terminality_commit(&parent, &scratch, &state, 1_000);
        assert!(commit.withdrawn);

        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: parent.stable_group_id().to_string(),
            revision: 1,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(commit),
        };

        let applied = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;
        assert!(!applied, "non-GroupDeleted withdrawal commit must reject");
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("group retained");
        assert!(!stored.withdrawn);
        assert!(stored.has_active_member(&member_hex));
        assert_eq!(stored.shared_secret, Some(vec![9; 32]));
        Ok(())
    }

    #[tokio::test]
    async fn metadata_role_update_withdrawn_commit_rejected_for_live_group() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-role-update-terminality";
        let (admin_hex, member_hex) = install_metadata_terminality_group(&state, group_id).await;
        let parent = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .expect("group installed")
            .clone();
        let mut scratch = parent.clone();
        scratch.set_member_role(&member_hex, x0x::groups::GroupRole::Admin);
        scratch.withdrawn = true;
        let commit = sign_metadata_terminality_commit(&parent, &scratch, &state, 1_000);
        assert!(commit.withdrawn);

        let event = NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: parent.stable_group_id().to_string(),
            revision: 1,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(commit),
        };

        let applied = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;
        assert!(!applied, "only GroupDeleted may terminalize a live group");
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("group retained");
        assert!(!stored.withdrawn);
        assert_eq!(
            stored.members_v2[&member_hex].role,
            x0x::groups::GroupRole::Member
        );
        assert_eq!(stored.shared_secret, Some(vec![9; 32]));
        Ok(())
    }

    #[tokio::test]
    async fn metadata_group_deleted_withdraws_and_wipes_key_material() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-group-deleted-terminality";
        let (admin_hex, _member_hex) = install_metadata_terminality_group(&state, group_id).await;
        let parent = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .expect("group installed")
            .clone();
        let mut scratch = parent.clone();
        scratch.withdrawn = true;
        let commit = sign_metadata_terminality_commit(&parent, &scratch, &state, 1_000);
        assert!(commit.withdrawn);

        let event = NamedGroupMetadataEvent::GroupDeleted {
            group_id: parent.stable_group_id().to_string(),
            revision: 1,
            actor: admin_hex,
            commit: Some(commit),
        };

        let applied = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;
        assert!(applied, "GroupDeleted is the terminal withdrawal path");
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("terminal tombstone retained");
        assert!(stored.withdrawn);
        assert_eq!(stored.shared_secret, None);
        Ok(())
    }

    fn assert_lost_race_conflict_drops_fields(
        status: StatusCode,
        body: &serde_json::Value,
        leaked_fields: &[&str],
    ) {
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["ok"].as_bool(), Some(false));
        assert_eq!(body["error"].as_str(), Some("group is withdrawn"));
        for field in leaked_fields {
            assert!(
                body.get(*field).is_none(),
                "withdrawn conflict must not leak secure effect field {field}"
            );
        }
    }

    #[tokio::test]
    async fn secure_encrypt_endpoint_gss_lost_race_drops_ciphertext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "gss-encrypt-local";
        let stable_group_id = "gss-encrypt-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["ciphertext_b64", "nonce_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_decrypt_endpoint_gss_lost_race_drops_plaintext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "gss-decrypt-local";
        let stable_group_id = "gss-decrypt-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;
        let (encrypt_status, encrypted) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;
        assert_eq!(encrypt_status, StatusCode::OK);

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_decrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureDecryptRequest {
                ciphertext_b64: encrypted.0["ciphertext_b64"]
                    .as_str()
                    .expect("ciphertext present")
                    .to_string(),
                nonce_b64: encrypted.0["nonce_b64"]
                    .as_str()
                    .expect("nonce present")
                    .to_string(),
                secret_epoch: encrypted.0["secret_epoch"].as_u64().expect("epoch present"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["payload_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_reseal_endpoint_lost_race_drops_secret_envelope() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "gss-reseal-local";
        let stable_group_id = "gss-reseal-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;
        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        state
            .named_groups
            .write()
            .await
            .get_mut(group_id)
            .expect("group installed")
            .set_member_kem_public_key(
                &recipient,
                BASE64.encode(&state.agent_kem_keypair.public_bytes),
            );

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_reseal(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(ResealRequest { recipient }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(
            status,
            &body.0,
            &[
                "kem_ciphertext_b64",
                "aead_nonce_b64",
                "aead_ciphertext_b64",
            ],
        );
        Ok(())
    }

    #[tokio::test]
    async fn secure_open_envelope_endpoint_lost_race_drops_opened_secret() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "open-envelope-stable";
        install_secure_endpoint_group(&state, group_id, group_id, x0x::mls::SecureGroupPlane::Gss)
            .await;
        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        let secret = [7_u8; 32];
        let aad = secure_share_aad(group_id, &recipient, 7);
        let (kem_ct, aead_nonce, aead_ct) =
            x0x::groups::kem_envelope::seal_group_secret_to_recipient(
                &state.agent_kem_keypair.public_bytes,
                &aad,
                &secret,
            )?;

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let (status, body) = secure_open_envelope_adversarial(
            State(Arc::clone(&state)),
            Json(OpenEnvelopeRequest {
                group_id: group_id.to_string(),
                recipient,
                secret_epoch: 7,
                kem_ciphertext_b64: BASE64.encode(&kem_ct),
                aead_nonce_b64: BASE64.encode(aead_nonce),
                aead_ciphertext_b64: BASE64.encode(&aead_ct),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["secret_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn metadata_secure_share_lost_race_does_not_install_secret() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-share-local";
        let stable_group_id = "metadata-share-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;
        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        let secret_epoch = 8;
        let secret = [8_u8; 32];
        let aad = secure_share_aad(stable_group_id, &recipient, secret_epoch);
        let (kem_ct, aead_nonce, aead_ct) =
            x0x::groups::kem_envelope::seal_group_secret_to_recipient(
                &state.agent_kem_keypair.public_bytes,
                &aad,
                &secret,
            )?;
        let event = NamedGroupMetadataEvent::SecureShareDelivered {
            group_id: stable_group_id.to_string(),
            recipient: recipient.clone(),
            secret_epoch,
            kem_ciphertext_b64: BASE64.encode(&kem_ct),
            aead_nonce_b64: BASE64.encode(aead_nonce),
            aead_ciphertext_b64: BASE64.encode(&aead_ct),
            actor: recipient,
        };

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let _ = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;

        let groups = state.named_groups.read().await;
        let info = groups
            .get(group_id)
            .expect("group retained as terminality marker");
        assert!(info.withdrawn, "lost-race withdrawal should win");
        assert_eq!(info.shared_secret, None, "secret must not be installed");
        assert_ne!(info.secret_epoch, secret_epoch, "epoch must not advance");
        Ok(())
    }

    fn treekem_metadata_group_info(
        creator: AgentId,
        group_id: &str,
        stable_group_id: &str,
    ) -> x0x::groups::GroupInfo {
        let creator_hex = hex::encode(creator.as_bytes());
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            creator_hex,
            info.created_at,
            String::new(),
        ));
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.shared_secret = None;
        info.secret_epoch = 0;
        info.security_binding = Some("treekem:epoch=0".to_string());
        info.recompute_state_hash();
        info
    }

    struct MemberJoinedTreeKemFixture {
        state: Arc<AppState>,
        _dir: tempfile::TempDir,
        group_id: String,
        stable_group_id: String,
        member_id: AgentId,
        member_hex: String,
        event: NamedGroupMetadataEvent,
        group: Arc<Mutex<x0x::mls::TreeKemMlsGroup>>,
        initial_epoch: u64,
    }

    async fn member_joined_treekem_fixture(
        group_byte: u8,
        stable_byte: u8,
    ) -> Result<MemberJoinedTreeKemFixture> {
        let (state, dir) = secure_endpoint_test_state().await?;
        let group_id = format!("{group_byte:02x}").repeat(32);
        let stable_group_id = format!("{stable_byte:02x}").repeat(32);
        let group_id_bytes = hex::decode(&group_id)?;
        let inviter = state.agent.agent_id();
        let inviter_hex = hex::encode(inviter.as_bytes());
        let creator_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let live_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, inviter, &creator_seed)?;
        let initial_epoch = live_group.epoch();
        let group = Arc::new(Mutex::new(live_group));
        state
            .treekem_groups
            .write()
            .await
            .insert(group_id.clone(), Arc::clone(&group));

        let mut info = treekem_metadata_group_info(inviter, &group_id, &stable_group_id);
        let now_ms = now_millis_u64();
        let invite_secret = format!("member-joined-invite-{group_byte:02x}");
        info.record_issued_invite(
            invite_secret.clone(),
            now_ms / 1_000,
            0,
            x0x::groups::GroupRole::Member,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);

        let member_keypair = x0x::identity::AgentKeypair::generate()?;
        let member_id = member_keypair.agent_id();
        let member_hex = hex::encode(member_id.as_bytes());
        let member_public_key_b64 = BASE64.encode(member_keypair.public_key().as_bytes());
        let member_seed = [stable_byte; 32];
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &member_seed)?;
        let treekem_key_package_b64 = BASE64.encode(prepared.key_package_bytes());
        let canonical = canonical_member_joined_bytes(
            &group_id,
            Some(&stable_group_id),
            &member_hex,
            &member_public_key_b64,
            x0x::groups::GroupRole::Member,
            None,
            &inviter_hex,
            &invite_secret,
            now_ms,
            Some(&treekem_key_package_b64),
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            member_keypair.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign MemberJoined fixture: {e:?}"))?;
        let event = NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.clone(),
            stable_group_id: Some(stable_group_id.clone()),
            member_agent_id: member_hex.clone(),
            member_public_key_b64,
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: inviter_hex,
            invite_secret,
            ts_ms: now_ms,
            treekem_key_package_b64: Some(treekem_key_package_b64),
            signature_b64: BASE64.encode(signature.as_bytes()),
        };

        Ok(MemberJoinedTreeKemFixture {
            state,
            _dir: dir,
            group_id,
            stable_group_id,
            member_id,
            member_hex,
            event,
            group,
            initial_epoch,
        })
    }

    fn signed_member_joined_event_for_test(
        keypair: &x0x::identity::AgentKeypair,
        group_id: &str,
        inviter_agent_id: &str,
        invite_secret: &str,
        role: x0x::groups::GroupRole,
    ) -> Result<(AgentId, String, String, NamedGroupMetadataEvent)> {
        let member_id = keypair.agent_id();
        let member_hex = hex::encode(member_id.as_bytes());
        let member_public_key_b64 = BASE64.encode(keypair.public_key().as_bytes());
        let ts_ms = now_millis_u64();
        let canonical = canonical_member_joined_bytes(
            group_id,
            Some(group_id),
            &member_hex,
            &member_public_key_b64,
            role,
            None,
            inviter_agent_id,
            invite_secret,
            ts_ms,
            None,
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            keypair.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign MemberJoined fixture: {e:?}"))?;
        let event = NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.to_string(),
            stable_group_id: Some(group_id.to_string()),
            member_agent_id: member_hex.clone(),
            member_public_key_b64: member_public_key_b64.clone(),
            role,
            display_name: None,
            inviter_agent_id: inviter_agent_id.to_string(),
            invite_secret: invite_secret.to_string(),
            ts_ms,
            treekem_key_package_b64: None,
            signature_b64: BASE64.encode(signature.as_bytes()),
        };
        Ok((member_id, member_hex, member_public_key_b64, event))
    }

    async fn group_counters_for_test(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> x0x::groups::GroupCounters {
        let groups = state.named_groups.read().await;
        let empty_topics = HashSet::new();
        state
            .groups_diagnostics
            .snapshot(&groups, &empty_topics, &empty_topics)
            .groups
            .into_iter()
            .find(|row| row.group_id == group_id)
            .map(|row| row.counters)
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn member_joined_forged_role_and_unknown_secret_rejected_single_app_state() -> Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "61".repeat(32);
        let inviter = state.agent.agent_id();
        let inviter_hex = hex::encode(inviter.as_bytes());
        let now_ms = now_millis_u64();
        let invite_secret = "single-app-state-member-joined-invite".to_string();
        let mut info = x0x::groups::GroupInfo::with_policy(
            "single-app-state MemberJoined rejection".to_string(),
            String::new(),
            inviter,
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.record_issued_invite(
            invite_secret.clone(),
            now_ms / 1_000,
            0,
            x0x::groups::GroupRole::Member,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
        save_named_groups(&state).await;

        let forger = x0x::identity::AgentKeypair::generate()?;
        let (forger_id, forger_hex, forger_public_key_b64, forged_admin) =
            signed_member_joined_event_for_test(
                &forger,
                &group_id,
                &inviter_hex,
                &invite_secret,
                x0x::groups::GroupRole::Admin,
            )?;
        let should_exit =
            apply_named_group_metadata_event_inner(&state, forged_admin, forger_id, true, true)
                .await;
        assert!(!should_exit);
        let counters = group_counters_for_test(&state, &group_id).await;
        assert_eq!(
            counters.member_joined_events_rejected_non_member_role, 1,
            "forged admin MemberJoined must be counted as a role-policy rejection"
        );

        let (_, _, _, forged_unknown_secret) = signed_member_joined_event_for_test(
            &forger,
            &group_id,
            &inviter_hex,
            &"00".repeat(32),
            x0x::groups::GroupRole::Member,
        )?;
        let should_exit = apply_named_group_metadata_event_inner(
            &state,
            forged_unknown_secret,
            forger_id,
            true,
            true,
        )
        .await;
        assert!(!should_exit);
        let counters = group_counters_for_test(&state, &group_id).await;
        assert_eq!(
            counters.member_joined_events_rejected_invite_secret_unknown, 1,
            "unknown invite-secret MemberJoined must be counted as an invite-policy rejection"
        );
        assert_eq!(
            counters.member_joined_events_applied, 0,
            "forged MemberJoined events must not apply"
        );

        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group retained");
        assert!(
            !live.has_active_member(&forger_hex),
            "forged MemberJoined must not admit the sender"
        );
        drop(groups);
        let persisted = tokio::fs::read_to_string(&state.named_groups_path).await?;
        assert!(
            !persisted.contains(&forger_hex),
            "forged member id must not be persisted after rejection"
        );
        assert!(
            !persisted.contains(&forger_public_key_b64),
            "forged member public key / protected material must not be persisted after rejection"
        );
        Ok(())
    }

    async fn assert_member_joined_treekem_did_not_install(
        fixture: &MemberJoinedTreeKemFixture,
    ) -> Result<()> {
        let guard = fixture.group.lock().await;
        assert_eq!(
            guard.epoch(),
            fixture.initial_epoch,
            "rejected MemberJoined must roll back in-memory TreeKEM epoch"
        );
        assert_eq!(
            guard.member_count(),
            1,
            "rejected MemberJoined must not leave an added TreeKEM leaf"
        );
        drop(guard);
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(
                &fixture.state.treekem_dir,
                &fixture.group_id,
            ))
            .await?,
            "rejected MemberJoined must not persist TreeKEM snapshot material"
        );
        let groups = fixture.state.named_groups.read().await;
        let live = groups
            .get(&fixture.group_id)
            .expect("live group record retained");
        assert!(
            !live.has_active_member(&fixture.member_hex),
            "rejected MemberJoined must not store roster/key-state advance"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_welcome_lost_race_does_not_install_tree_state() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id_storage = "51".repeat(32);
        let group_id = group_id_storage.as_str();
        let group_id_bytes = hex::decode(group_id)?;
        let authority = AgentId([0x51; 32]);
        let authority_hex = hex::encode(authority.as_bytes());
        let mut authority_group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), authority, &[0x51; 32])?;
        let local_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let prepared =
            x0x::mls::TreeKemMlsGroup::prepare_member(state.agent.agent_id(), &local_seed)?;
        let add =
            authority_group.add_member(state.agent.agent_id(), prepared.key_package_bytes())?;
        let joined = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &add.welcome)?;
        let epoch = joined.epoch();
        let info = treekem_metadata_group_info(authority, group_id, group_id);
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info.clone());
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let mut next = info;
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            local_hex,
            x0x::groups::GroupRole::Member,
            Some(authority_hex),
            None,
        );
        next.secret_epoch = epoch;
        next.security_binding = Some(format!("treekem:epoch={epoch}"));
        next.recompute_state_hash();

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let result = install_joined_treekem_group_after_crypto_recheck(
            state.as_ref(),
            group_id,
            next,
            joined,
            "test_treekem_welcome_lost_race",
        )
        .await;

        assert!(
            result.is_err(),
            "withdrawn recheck must reject welcome install"
        );
        assert!(
            !state.treekem_groups.read().await.contains_key(group_id),
            "welcome must not install in-memory TreeKEM state"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, group_id)).await?,
            "welcome must not persist TreeKEM snapshot material"
        );
        let groups = state.named_groups.read().await;
        assert!(groups.get(group_id).is_some_and(|info| info.withdrawn));
        Ok(())
    }

    #[tokio::test]
    async fn treekem_atomic_persist_lost_race_withdrawn_repairs_named_groups() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "56".repeat(32);
        let stable_group_id = "57".repeat(32);
        let group_id_bytes = hex::decode(&group_id)?;
        let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes, state.agent.agent_id(), &seed)?;
        let epoch = group.epoch();
        let mut current =
            treekem_metadata_group_info(state.agent.agent_id(), &group_id, &stable_group_id);
        current.secret_epoch = epoch;
        current.security_binding = Some(format!("treekem:epoch={epoch}"));
        current.shared_secret = Some(vec![9; 32]);
        current.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), current.clone());
        save_named_groups(&state).await;

        let added_member = "58".repeat(32);
        let mut next = current;
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            added_member.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(state.agent.agent_id().as_bytes())),
            None,
        );
        next.recompute_state_hash();

        let _guard = force_atomic_persist_post_json_withdrawn_ids(&[&stable_group_id]);
        let result = install_joined_treekem_group_after_crypto_recheck(
            state.as_ref(),
            &group_id,
            next,
            group,
            "test_treekem_atomic_persist_lost_race",
        )
        .await;

        assert!(
            result.is_err(),
            "late withdrawn recheck must reject durable TreeKEM install"
        );
        assert!(
            !state.treekem_groups.read().await.contains_key(&group_id),
            "rejected install must not leave in-memory TreeKEM state"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, &group_id)).await?,
            "late withdrawal must wipe snapshot material"
        );
        assert!(
            !tokio::fs::try_exists(treekem_journal_path(&state.treekem_dir, &group_id)).await?,
            "late withdrawal must wipe journal material"
        );
        let durable_groups = load_named_groups(&state.named_groups_path).await?;
        let durable = durable_groups
            .get(&group_id)
            .expect("withdrawn group tombstone remains durable");
        assert!(
            durable.withdrawn,
            "durable named_groups.json must retain withdrawal terminality"
        );
        assert_eq!(
            durable.shared_secret, None,
            "durable withdrawn tombstone must not retain key material"
        );
        assert!(
            !durable.has_active_member(&added_member),
            "durable withdrawn tombstone must not contain the stale TreeKEM roster advance"
        );
        let groups = state.named_groups.read().await;
        let in_memory = groups
            .get(&group_id)
            .expect("withdrawn group tombstone remains in memory");
        assert!(in_memory.withdrawn);
        assert!(!in_memory.has_active_member(&added_member));
        Ok(())
    }

    #[tokio::test]
    async fn treekem_final_install_lock_rechecks_withdrawal_before_insert() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "59".repeat(32);
        let stable_group_id = "5a".repeat(32);
        let group_id_bytes = hex::decode(&group_id)?;
        let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes, state.agent.agent_id(), &seed)?;
        let epoch = group.epoch();
        let mut info =
            treekem_metadata_group_info(state.agent.agent_id(), &group_id, &stable_group_id);
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();

        let map_guard = state.treekem_groups.write().await;
        let (notify, _notify_guard) = notify_before_treekem_final_install_map_write(&group_id);
        let state_for_install = Arc::clone(&state);
        let group_id_for_install = group_id.clone();
        let info_for_install = info.clone();
        let install = tokio::spawn(async move {
            install_joined_treekem_group_after_crypto_recheck(
                state_for_install.as_ref(),
                &group_id_for_install,
                info_for_install,
                group,
                "test_treekem_final_install_lock_recheck",
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(5), notify.notified())
            .await
            .context("install did not reach the final in-memory map write")?;
        {
            let mut groups = state.named_groups.write().await;
            let mut withdrawn = info.clone();
            withdrawn.withdrawn = true;
            clear_group_info_key_material(&mut withdrawn);
            groups.insert(group_id.clone(), withdrawn);
        }
        drop(map_guard);

        let result = install.await.context("install task panicked")?;
        assert!(
            result.is_err(),
            "withdrawal observed under the TreeKEM map lock must reject final install"
        );
        assert!(
            !state.treekem_groups.read().await.contains_key(&group_id),
            "rejected final install must not leave resident TreeKEM key material"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, &group_id)).await?,
            "rejected final install must wipe the just-persisted TreeKEM snapshot"
        );
        assert!(
            !tokio::fs::try_exists(treekem_journal_path(&state.treekem_dir, &group_id)).await?,
            "rejected final install must wipe the just-persisted TreeKEM journal"
        );
        let durable_groups = load_named_groups(&state.named_groups_path).await?;
        assert!(
            durable_groups
                .get(&group_id)
                .is_some_and(|info| info.withdrawn),
            "final check should leave the withdrawn tombstone durable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_commit_lost_race_rolls_back_in_memory_tree_state() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id_storage = "52".repeat(32);
        let group_id = group_id_storage.as_str();
        let group_id_bytes = hex::decode(group_id)?;
        let authority = AgentId([0x54; 32]);
        let authority_hex = hex::encode(authority.as_bytes());
        let mut author_group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), authority, &[0x54; 32])?;
        let local_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let local_prepared =
            x0x::mls::TreeKemMlsGroup::prepare_member(state.agent.agent_id(), &local_seed)?;
        let local_add =
            author_group.add_member(state.agent.agent_id(), local_prepared.key_package_bytes())?;
        let local_group =
            x0x::mls::TreeKemMlsGroup::join_from_welcome(local_prepared, &local_add.welcome)?;
        let initial_epoch = local_group.epoch();
        let pre_commit_snapshot = local_group.to_snapshot_bytes()?;
        let pre_commit_group = x0x::mls::TreeKemMlsGroup::restore(
            &pre_commit_snapshot,
            state.agent.agent_id(),
            &local_seed,
        )?;
        let member = AgentId([0x53; 32]);
        let member_hex = hex::encode(member.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member, &[0x53; 32])?;
        let add = author_group.add_member(member, prepared.key_package_bytes())?;
        let expected_epoch = author_group.epoch();
        let mut info = treekem_metadata_group_info(authority, group_id, group_id);
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        info.add_member(
            local_hex,
            x0x::groups::GroupRole::Member,
            Some(authority_hex.clone()),
            None,
        );
        info.secret_epoch = initial_epoch;
        info.security_binding = Some(format!("treekem:epoch={initial_epoch}"));
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info.clone());
        let group = Arc::new(Mutex::new(pre_commit_group));
        state
            .treekem_groups
            .write()
            .await
            .insert(group_id.to_string(), Arc::clone(&group));
        let mut next = info;
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(authority_hex),
            None,
        );
        next.secret_epoch = expected_epoch;
        next.security_binding = Some(format!("treekem:epoch={expected_epoch}"));
        next.recompute_state_hash();

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let result = process_treekem_commit_after_crypto_recheck(
            state.as_ref(),
            group_id,
            &next,
            Arc::clone(&group),
            &add.commit,
            expected_epoch,
            "test_treekem_commit_lost_race",
        )
        .await;

        assert!(
            result.is_err(),
            "withdrawn recheck must reject commit install"
        );
        assert_eq!(
            group.lock().await.epoch(),
            initial_epoch,
            "rejected commit must roll back in-memory TreeKEM epoch"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, group_id)).await?,
            "rejected commit must not persist TreeKEM snapshot material"
        );
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("withdrawn tombstone retained");
        assert!(stored.withdrawn);
        assert!(
            !stored.has_active_member(&member_hex),
            "rejected commit must not store roster/key-state advance"
        );
        Ok(())
    }

    #[tokio::test]
    async fn member_joined_treekem_lost_race_rolls_back_in_memory_tree_state() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x53, 0x53).await?;
        let _guard = force_post_crypto_withdrawn_ids(&[&fixture.stable_group_id]);

        let should_exit = apply_named_group_metadata_event_inner(
            &fixture.state,
            fixture.event.clone(),
            fixture.member_id,
            true,
            true,
        )
        .await;

        assert!(!should_exit);
        assert_member_joined_treekem_did_not_install(&fixture).await?;
        let groups = fixture.state.named_groups.read().await;
        assert!(
            groups
                .get(&fixture.group_id)
                .is_some_and(|info| info.withdrawn),
            "lost-race withdrawal should win"
        );
        Ok(())
    }

    #[tokio::test]
    async fn member_joined_treekem_withdrawn_same_stable_alias_rolls_back() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x54, 0x55).await?;
        let mut withdrawn_alias = treekem_metadata_group_info(
            fixture.state.agent.agent_id(),
            &fixture.stable_group_id,
            &fixture.stable_group_id,
        );
        withdrawn_alias.withdrawn = true;
        clear_group_info_key_material(&mut withdrawn_alias);
        fixture
            .state
            .named_groups
            .write()
            .await
            .insert(fixture.stable_group_id.clone(), withdrawn_alias);

        let should_exit = apply_named_group_metadata_event_inner(
            &fixture.state,
            fixture.event.clone(),
            fixture.member_id,
            true,
            true,
        )
        .await;

        assert!(!should_exit);
        assert_member_joined_treekem_did_not_install(&fixture).await?;
        let groups = fixture.state.named_groups.read().await;
        assert!(
            groups
                .get(&fixture.stable_group_id)
                .is_some_and(|info| info.withdrawn),
            "withdrawn same-stable alias should remain terminal"
        );
        Ok(())
    }

    async fn install_treekem_endpoint_group(
        state: &Arc<AppState>,
        group_id: &str,
        stable_group_id: &str,
    ) -> Result<()> {
        install_secure_endpoint_group(
            state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::TreeKem,
        )
        .await;
        let group = x0x::mls::TreeKemMlsGroup::create(
            group_id.as_bytes().to_vec(),
            state.agent.agent_id(),
            &[3; 32],
        )?;
        state
            .treekem_groups
            .write()
            .await
            .insert(group_id.to_string(), Arc::new(Mutex::new(group)));
        Ok(())
    }

    #[tokio::test]
    async fn secure_encrypt_endpoint_treekem_lost_race_drops_ciphertext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"ab".repeat(16);
        let stable_group_id = "treekem-encrypt-stable";
        install_treekem_endpoint_group(&state, group_id, stable_group_id).await?;

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["ciphertext_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_decrypt_endpoint_treekem_lost_race_drops_plaintext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"cd".repeat(16);
        let stable_group_id = "treekem-decrypt-stable";
        install_treekem_endpoint_group(&state, group_id, stable_group_id).await?;
        let (encrypt_status, encrypted) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;
        assert_eq!(encrypt_status, StatusCode::OK);

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_decrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureDecryptRequest {
                ciphertext_b64: encrypted.0["ciphertext_b64"]
                    .as_str()
                    .expect("ciphertext present")
                    .to_string(),
                nonce_b64: String::new(),
                secret_epoch: 0,
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["payload_b64"]);
        Ok(())
    }

    async fn install_legacy_mls_endpoint_group(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> Result<()> {
        let group = x0x::mls::MlsGroup::new(hex::decode(group_id)?, state.agent.agent_id()).await?;
        state
            .mls_groups
            .write()
            .await
            .insert(group_id.to_string(), group);
        install_secure_endpoint_group(state, group_id, group_id, x0x::mls::SecureGroupPlane::Gss)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn legacy_mls_encrypt_lost_race_drops_ciphertext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"ef".repeat(16);
        install_legacy_mls_endpoint_group(&state, group_id).await?;

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let (status, body) = mls_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(MlsEncryptRequest {
                payload: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["ciphertext"]);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_mls_decrypt_lost_race_drops_plaintext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"01".repeat(16);
        install_legacy_mls_endpoint_group(&state, group_id).await?;
        let (encrypt_status, encrypted) = mls_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(MlsEncryptRequest {
                payload: BASE64.encode(b"secret"),
            }),
        )
        .await;
        assert_eq!(encrypt_status, StatusCode::OK);

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let (status, body) = mls_decrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(MlsDecryptRequest {
                ciphertext: encrypted.0["ciphertext"]
                    .as_str()
                    .expect("ciphertext present")
                    .to_string(),
                epoch: encrypted.0["epoch"].as_u64().expect("epoch present"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["payload"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_encrypt_endpoint_withdrawn_stable_stub_does_not_poison_live_keyed_alias(
    ) -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "live-keyed-local";
        let stable_group_id = "stale-withdrawn-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;

        let mut stale_stub = secure_endpoint_group_for_agent(
            state.agent.agent_id(),
            stable_group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        );
        stale_stub.shared_secret = None;
        stale_stub.members_v2.clear();
        stale_stub.withdrawn = true;
        state
            .named_groups
            .write()
            .await
            .insert(stable_group_id.to_string(), stale_stub);

        let (status, body) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.0.get("ciphertext_b64").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn open_envelope_withdrawn_stable_stub_does_not_poison_live_keyed_alias() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let stable_group_id = "open-envelope-stale-stable";
        let live_alias = "open-envelope-live-alias";
        install_secure_endpoint_group(
            &state,
            live_alias,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;

        let mut stale_stub = secure_endpoint_group_for_agent(
            state.agent.agent_id(),
            stable_group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        );
        stale_stub.shared_secret = None;
        stale_stub.members_v2.clear();
        stale_stub.withdrawn = true;
        state
            .named_groups
            .write()
            .await
            .insert(stable_group_id.to_string(), stale_stub);

        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        let secret = [7_u8; 32];
        let aad = secure_share_aad(stable_group_id, &recipient, 7);
        let (kem_ct, aead_nonce, aead_ct) =
            x0x::groups::kem_envelope::seal_group_secret_to_recipient(
                &state.agent_kem_keypair.public_bytes,
                &aad,
                &secret,
            )?;

        let (status, body) = secure_open_envelope_adversarial(
            State(Arc::clone(&state)),
            Json(OpenEnvelopeRequest {
                group_id: stable_group_id.to_string(),
                recipient,
                secret_epoch: 7,
                kem_ciphertext_b64: BASE64.encode(&kem_ct),
                aead_nonce_b64: BASE64.encode(aead_nonce),
                aead_ciphertext_b64: BASE64.encode(&aead_ct),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.0.get("secret_b64").is_some());
        Ok(())
    }

    #[test]
    fn same_stable_group_aliases_include_all_local_records() {
        let stable_id = "stable-card-id";
        let mut groups = HashMap::new();
        for (key, mls_id) in [
            ("local-mls-id", "local-mls-id"),
            (stable_id, "local-mls-id"),
            ("legacy-alias", "legacy-mls-id"),
        ] {
            let mut info = x0x::groups::GroupInfo::with_policy(
                key.to_string(),
                String::new(),
                AgentId([2; 32]),
                mls_id.to_string(),
                x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
            );
            info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
                stable_id.to_string(),
                "02".repeat(32),
                info.created_at,
                String::new(),
            ));
            info.shared_secret = Some(vec![7; 32]);
            groups.insert(key.to_string(), info);
        }
        let mut other = x0x::groups::GroupInfo::with_policy(
            "other".to_string(),
            String::new(),
            AgentId([3; 32]),
            "other-mls".to_string(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        other.shared_secret = Some(vec![8; 32]);
        groups.insert("other".to_string(), other);

        let aliases = collect_same_stable_group_aliases(&groups, "local-mls-id", Some(stable_id));
        for expected in ["local-mls-id", stable_id, "legacy-alias", "legacy-mls-id"] {
            assert!(aliases.contains(expected), "missing alias {expected}");
        }
        assert!(!aliases.contains("other"));

        for alias in &aliases {
            if let Some(info) = groups.get_mut(alias) {
                info.withdrawn = true;
                clear_group_info_key_material(info);
            }
        }
        for key in ["local-mls-id", stable_id, "legacy-alias"] {
            let info = groups.get(key).expect("same-stable record retained");
            assert!(info.withdrawn, "alias {key} not marked withdrawn");
            assert_eq!(info.shared_secret, None, "alias {key} kept key material");
        }
        let other = groups.get("other").expect("other group retained");
        assert!(!other.withdrawn);
        assert!(other.shared_secret.is_some());
    }

    #[test]
    fn withdrawn_card_non_admin_cannot_terminally_mark_keyed_live_group() {
        let creator = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let outsider = x0x::identity::AgentKeypair::generate().expect("outsider keypair");
        let mut info = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.state_revision = 1;
        info.updated_at = 1_000;
        info.shared_secret = Some(vec![9; 32]);

        let mut card = sample_group_card(info.stable_group_id(), 2, 2_000);
        card.withdrawn = true;
        card.authority_agent_id = hex::encode(outsider.agent_id().as_bytes());

        assert!(!withdrawn_card_can_terminally_mark_local_group(
            &info, &card, true,
        ));
    }

    #[tokio::test]
    async fn withdrawn_card_protected_crypto_probe_fails_closed_on_io_error() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        tokio::fs::remove_dir_all(&state.treekem_dir).await?;
        tokio::fs::write(&state.treekem_dir, b"not a directory").await?;

        let creator = x0x::identity::AgentKeypair::generate()?;
        let mut info = x0x::groups::GroupInfo::with_policy(
            "keyless stub".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.shared_secret = None;

        let mut aliases = HashSet::new();
        aliases.insert(info.stable_group_id().to_string());

        assert!(
            local_group_has_protected_crypto_material(&state, &info, &aliases).await,
            "TreeKEM persistence probe errors must fail closed as protected"
        );
        Ok(())
    }

    #[test]
    fn withdrawn_card_admin_cannot_terminally_mark_keyed_live_group_without_signed_commit() {
        let creator = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let admin = x0x::identity::AgentKeypair::generate().expect("admin keypair");
        let creator_hex = hex::encode(creator.agent_id().as_bytes());
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut info = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.add_member(
            admin_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(creator_hex),
            None,
        );
        info.state_revision = 1;
        info.updated_at = 1_000;
        info.shared_secret = Some(vec![9; 32]);

        let mut card = sample_group_card(info.stable_group_id(), 2, 2_000);
        card.withdrawn = true;
        card.authority_agent_id = admin_hex;

        assert!(!withdrawn_card_can_terminally_mark_local_group(
            &info, &card, true,
        ));
        assert!(!info.withdrawn);
        assert_eq!(info.shared_secret, Some(vec![9; 32]));
    }

    #[test]
    fn withdrawn_card_can_supersede_keyless_discovery_stub_without_roster_admin() {
        let creator = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let outsider = x0x::identity::AgentKeypair::generate().expect("outsider keypair");
        let mut stub = x0x::groups::GroupInfo::with_policy(
            "stub".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        stub.state_revision = 1;
        stub.updated_at = 1_000;
        stub.shared_secret = None;
        stub.members_v2.clear();

        let mut card = sample_group_card(stub.stable_group_id(), 2, 2_000);
        card.withdrawn = true;
        card.authority_agent_id = hex::encode(outsider.agent_id().as_bytes());

        assert!(withdrawn_card_can_terminally_mark_local_group(
            &stub, &card, false,
        ));
        assert!(apply_withdrawn_group_card_to_group_info(&mut stub, &card));
        assert!(stub.withdrawn);
        assert_eq!(stub.shared_secret, None);
    }

    #[tokio::test]
    async fn withdrawn_card_import_does_not_wipe_same_stable_keyed_alias_via_keyless_stub(
    ) -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let stable_group_id = "same-stable-card";
        let keyed_alias = "same-stable-live-alias";
        let creator = x0x::identity::AgentKeypair::generate()?;
        let creator_hex = hex::encode(creator.agent_id().as_bytes());

        let mut keyless_stub = x0x::groups::GroupInfo::with_policy(
            "stub".to_string(),
            String::new(),
            creator.agent_id(),
            stable_group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        keyless_stub.state_revision = 1;
        keyless_stub.updated_at = 1_000;
        keyless_stub.shared_secret = None;
        keyless_stub.members_v2.clear();

        let mut live_keyed = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            keyed_alias.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        live_keyed.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            creator_hex,
            live_keyed.created_at,
            String::new(),
        ));
        live_keyed.state_revision = 1;
        live_keyed.updated_at = 1_000;
        live_keyed.shared_secret = Some(vec![9; 32]);

        {
            let mut groups = state.named_groups.write().await;
            groups.insert(stable_group_id.to_string(), keyless_stub);
            groups.insert(keyed_alias.to_string(), live_keyed);
        }

        let mut card = sample_group_card(stable_group_id, 2, 2_000);
        card.withdrawn = true;
        card.sign(&creator)?;

        let response = import_group_card(State(Arc::clone(&state)), Json(card))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let groups = state.named_groups.read().await;
        let live = groups.get(keyed_alias).expect("live alias retained");
        assert!(!live.withdrawn);
        assert_eq!(live.shared_secret, Some(vec![9; 32]));
        let stub = groups.get(stable_group_id).expect("keyless stub retained");
        assert!(!stub.withdrawn);
        Ok(())
    }

    #[tokio::test]
    async fn withdrawn_card_import_does_not_wipe_keyed_alias_via_stale_withdrawn_stub() -> Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let stable_group_id = "stale-withdrawn-card";
        let keyed_alias = "stale-withdrawn-live-alias";
        let creator = x0x::identity::AgentKeypair::generate()?;
        let creator_hex = hex::encode(creator.agent_id().as_bytes());

        let mut stale_withdrawn_stub = x0x::groups::GroupInfo::with_policy(
            "stub".to_string(),
            String::new(),
            creator.agent_id(),
            stable_group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        stale_withdrawn_stub.state_revision = 1;
        stale_withdrawn_stub.updated_at = 1_000;
        stale_withdrawn_stub.shared_secret = None;
        stale_withdrawn_stub.members_v2.clear();
        stale_withdrawn_stub.withdrawn = true;

        let mut live_keyed = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            keyed_alias.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        live_keyed.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            creator_hex,
            live_keyed.created_at,
            String::new(),
        ));
        live_keyed.state_revision = 1;
        live_keyed.updated_at = 1_000;
        live_keyed.shared_secret = Some(vec![9; 32]);

        {
            let mut groups = state.named_groups.write().await;
            groups.insert(stable_group_id.to_string(), stale_withdrawn_stub);
            groups.insert(keyed_alias.to_string(), live_keyed);
        }

        let mut card = sample_group_card(stable_group_id, 2, 2_000);
        card.withdrawn = true;
        card.sign(&creator)?;

        let response = import_group_card(State(Arc::clone(&state)), Json(card))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let groups = state.named_groups.read().await;
        let live = groups.get(keyed_alias).expect("live alias retained");
        assert!(!live.withdrawn);
        assert_eq!(live.shared_secret, Some(vec![9; 32]));
        let stub = groups
            .get(stable_group_id)
            .expect("stale withdrawn stub retained");
        assert!(stub.withdrawn);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_named_groups_file_is_rejected_without_replacing_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("named_groups.json");
        let malformed_json = "{\"group\":";
        tokio::fs::write(&path, malformed_json).await?;

        let result = load_named_groups(&path).await;

        assert!(result.is_err());
        assert_eq!(tokio::fs::read_to_string(&path).await?, malformed_json);
        Ok(())
    }

    #[tokio::test]
    async fn named_groups_json_write_replaces_file_without_temp_leftover() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("named_groups.json");

        write_named_groups_json_atomic(&path, "{\"old\":true}").await?;
        write_named_groups_json_atomic(&path, "{\"new\":true}").await?;

        assert_eq!(tokio::fs::read_to_string(&path).await?, "{\"new\":true}");

        let mut entries = tokio::fs::read_dir(dir.path()).await?;
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name());
        }
        assert_eq!(names, vec![std::ffi::OsString::from("named_groups.json")]);
        Ok(())
    }

    #[test]
    fn treekem_snapshot_drop_file_name_rejects_path_traversal_ids() {
        assert_eq!(
            treekem_snapshot_file_name_for_drop(&"ab".repeat(16)),
            Some(format!("{}.snap", "ab".repeat(16)))
        );
        assert_eq!(
            treekem_journal_file_name_for_drop(&"ab".repeat(16)),
            Some(format!("{}.journal", "ab".repeat(16)))
        );
        assert_eq!(
            treekem_snapshot_file_name_for_drop("group-1_ok").as_deref(),
            Some("group-1_ok.snap")
        );
        assert_eq!(
            treekem_journal_file_name_for_drop("group-1_ok").as_deref(),
            Some("group-1_ok.journal")
        );

        for unsafe_id in ["", "../outside", "a/b", "/absolute", "a\\b", "ümlaut"] {
            assert_eq!(
                treekem_snapshot_file_name_for_drop(unsafe_id),
                None,
                "unsafe id should not become a snapshot filename: {unsafe_id:?}"
            );
            assert_eq!(
                treekem_journal_file_name_for_drop(unsafe_id),
                None,
                "unsafe id should not become a journal filename: {unsafe_id:?}"
            );
        }
    }

    #[tokio::test]
    async fn treekem_persistence_drop_removes_snapshot_and_journal() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let group_id = "ab".repeat(16);
        let snapshot_path = treekem_snapshot_path(dir.path(), &group_id);
        let journal_path = treekem_journal_path(dir.path(), &group_id);
        tokio::fs::write(&snapshot_path, b"snapshot").await?;
        tokio::fs::write(&journal_path, b"journal").await?;

        remove_treekem_persistence_for_group_id_in_dir(dir.path(), &group_id, "test").await;

        assert!(!snapshot_path.exists(), "snapshot material must be wiped");
        assert!(!journal_path.exists(), "journal material must be wiped");
        Ok(())
    }

    fn sample_treekem_group_info(group_id: &str, withdrawn: bool) -> x0x::groups::GroupInfo {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([9; 32]),
            group_id.to_string(),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 1;
        info.state_hash = "state".to_string();
        info.security_binding = Some("treekem:epoch=1".to_string());
        info.withdrawn = withdrawn;
        info
    }

    fn sample_treekem_snapshot_envelope() -> Result<Vec<u8>> {
        let mut bytes = TREEKEM_DAEMON_SNAPSHOT_MAGIC.to_vec();
        bytes.extend(postcard::to_stdvec(&TreeKemSnapshotEnvelope {
            version: TREEKEM_DAEMON_SNAPSHOT_VERSION,
            state_revision: 1,
            state_hash: "state".to_string(),
            security_binding: Some("treekem:epoch=1".to_string()),
            snapshot: b"snapshot".to_vec(),
        })?);
        Ok(bytes)
    }

    #[test]
    fn treekem_snapshot_envelope_binding_detects_mismatch() {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([9; 32]),
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 7;
        info.state_hash = "hash-a".to_string();
        info.security_binding = Some("treekem:epoch=3".to_string());
        let envelope = TreeKemSnapshotEnvelope {
            version: TREEKEM_DAEMON_SNAPSHOT_VERSION,
            state_revision: info.state_revision,
            state_hash: info.state_hash.clone(),
            security_binding: info.security_binding.clone(),
            snapshot: b"snapshot".to_vec(),
        };
        assert!(treekem_snapshot_envelope_matches_info(&envelope, &info));

        info.state_hash = "hash-b".to_string();
        assert!(!treekem_snapshot_envelope_matches_info(&envelope, &info));
    }

    #[test]
    fn treekem_snapshot_envelope_rejects_withdrawn_group_info() -> Result<()> {
        let group_id = "ab".repeat(16);
        let info = sample_treekem_group_info(&group_id, true);
        let group = x0x::mls::TreeKemMlsGroup::create(
            group_id.as_bytes().to_vec(),
            AgentId([9; 32]),
            &[7; 32],
        )?;

        let err =
            encode_treekem_snapshot_envelope(&info, &group).expect_err("withdrawn group rejected");

        assert!(
            err.to_string().contains("withdrawn"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_journal_replay_writes_snapshot_and_named_groups() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let treekem_dir = dir.path().join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;
        let named_path = dir.path().join("named_groups.json");
        let snapshot_envelope = sample_treekem_snapshot_envelope()?;
        let group_id = "ab".repeat(16);
        let named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            group_id.clone(),
            sample_treekem_group_info(&group_id, false),
        )]))?;
        let journal = TreeKemNamedPersistJournal {
            version: TREEKEM_NAMED_JOURNAL_VERSION,
            group_id_hex: group_id,
            named_groups_json: named_groups_json.clone(),
            snapshot_envelope: snapshot_envelope.clone(),
        };
        let journal_path = treekem_journal_path(&treekem_dir, &journal.group_id_hex);
        x0x::storage::write_private_bytes(&journal_path, postcard::to_stdvec(&journal)?).await?;

        recover_treekem_named_journals(&named_path, &treekem_dir).await?;

        assert_eq!(
            tokio::fs::read_to_string(&named_path).await?,
            named_groups_json
        );
        assert_eq!(
            tokio::fs::read(treekem_snapshot_path(&treekem_dir, &journal.group_id_hex)).await?,
            snapshot_envelope
        );
        assert!(!journal_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn treekem_journal_replay_preserves_durable_withdrawn_alias() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let treekem_dir = dir.path().join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;
        let named_path = dir.path().join("named_groups.json");
        let snapshot_envelope = sample_treekem_snapshot_envelope()?;
        let group_id = "ab".repeat(16);
        let alias_mls_id = "cd".repeat(16);

        let mut withdrawn_alias = sample_treekem_group_info(&alias_mls_id, true);
        withdrawn_alias.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            group_id.clone(),
            "02".repeat(32),
            withdrawn_alias.created_at,
            String::new(),
        ));
        let durable_named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            "withdrawn-alias".to_string(),
            withdrawn_alias,
        )]))?;
        tokio::fs::write(&named_path, &durable_named_groups_json).await?;

        let journal_named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            group_id.clone(),
            sample_treekem_group_info(&group_id, false),
        )]))?;
        let journal = TreeKemNamedPersistJournal {
            version: TREEKEM_NAMED_JOURNAL_VERSION,
            group_id_hex: group_id.clone(),
            named_groups_json: journal_named_groups_json,
            snapshot_envelope,
        };
        let snapshot_path = treekem_snapshot_path(&treekem_dir, &group_id);
        tokio::fs::write(&snapshot_path, b"stale-snapshot").await?;
        let journal_path = treekem_journal_path(&treekem_dir, &group_id);
        x0x::storage::write_private_bytes(&journal_path, postcard::to_stdvec(&journal)?).await?;

        recover_treekem_named_journals(&named_path, &treekem_dir).await?;

        assert_eq!(
            tokio::fs::read_to_string(&named_path).await?,
            durable_named_groups_json,
            "durable withdrawn named-groups file must not be replaced"
        );
        assert!(
            !snapshot_path.exists(),
            "durable withdrawal must wipe stale snapshot material"
        );
        assert!(
            !journal_path.exists(),
            "durable withdrawal must wipe stale journal material"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_journal_replay_discards_withdrawn_group_material() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let treekem_dir = dir.path().join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;
        let named_path = dir.path().join("named_groups.json");
        let snapshot_envelope = sample_treekem_snapshot_envelope()?;
        let group_id = "ab".repeat(16);
        let named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            group_id.clone(),
            sample_treekem_group_info(&group_id, true),
        )]))?;
        let journal = TreeKemNamedPersistJournal {
            version: TREEKEM_NAMED_JOURNAL_VERSION,
            group_id_hex: group_id.clone(),
            named_groups_json,
            snapshot_envelope,
        };
        let snapshot_path = treekem_snapshot_path(&treekem_dir, &group_id);
        tokio::fs::write(&snapshot_path, b"stale-snapshot").await?;
        let journal_path = treekem_journal_path(&treekem_dir, &group_id);
        x0x::storage::write_private_bytes(&journal_path, postcard::to_stdvec(&journal)?).await?;

        recover_treekem_named_journals(&named_path, &treekem_dir).await?;

        assert!(
            !named_path.exists(),
            "withdrawn journal must not replay named groups"
        );
        assert!(
            !snapshot_path.exists(),
            "withdrawn journal must wipe snapshot material"
        );
        assert!(
            !journal_path.exists(),
            "withdrawn journal must wipe journal material"
        );
        Ok(())
    }

    #[test]
    fn treekem_metadata_event_phase3_classifier_allows_group_delete() {
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            agent_id: "22".repeat(32),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: "aa".repeat(16),
            request_id: "req".to_string(),
            requester_agent_id: "22".repeat(32),
            message: None,
            ts: 1,
            requester_kem_public_key_b64: None,
            treekem_key_package_b64: Some("a2V5".to_string()),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::JoinRequestApproved {
            group_id: "aa".repeat(16),
            request_id: "req".to_string(),
            revision: 2,
            actor: "11".repeat(32),
            requester_agent_id: "22".repeat(32),
            treekem_commit_b64: Some("Y29tbWl0".to_string()),
            treekem_welcome_b64: Some("d2VsY29tZQ==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(1),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::GroupDeleted {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            agent_id: "22".repeat(32),
            role: x0x::groups::GroupRole::Admin,
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            name: Some("name".to_string()),
            description: Some(String::new()),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));
    }

    #[test]
    fn treekem_self_leave_metadata_is_authorized_without_transport_commit() {
        let creator = AgentId([0x11; 32]);
        let creator_hex = hex::encode(creator.as_bytes());
        let member_hex = "22".repeat(32);
        let admin_hex = "33".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.add_member(
            admin_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(creator_hex.clone()),
            None,
        );
        let group_id = info.stable_group_id().to_string();

        let member_added_by_admin = NamedGroupMetadataEvent::MemberAdded {
            group_id: group_id.clone(),
            revision: 2,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(2),
            commit: Some(fake_group_state_commit(&group_id, 2, &admin_hex)),
        };
        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &member_added_by_admin,
            &admin_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &member_added_by_admin,
            &creator_hex
        ));

        let self_leave = NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision: 3,
            actor: member_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(fake_group_state_commit(&group_id, 3, &member_hex)),
        };

        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &self_leave,
            &member_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &self_leave,
            &creator_hex
        ));

        let admin_remove_without_treekem = NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision: 4,
            actor: creator_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(fake_group_state_commit(&group_id, 4, &creator_hex)),
        };
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &admin_remove_without_treekem,
            &creator_hex
        ));

        let admin_remove_with_treekem = NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision: 5,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(2),
            commit: Some(fake_group_state_commit(&group_id, 5, &admin_hex)),
        };
        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &admin_remove_with_treekem,
            &admin_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &admin_remove_with_treekem,
            &creator_hex
        ));

        let ban_owner_by_admin = NamedGroupMetadataEvent::MemberBanned {
            group_id: group_id.clone(),
            revision: 6,
            actor: admin_hex.clone(),
            agent_id: creator_hex.clone(),
            secret_epoch: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(3),
            commit: Some(fake_group_state_commit(&group_id, 6, &admin_hex)),
        };
        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &ban_owner_by_admin,
            &admin_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &ban_owner_by_admin,
            &creator_hex
        ));
    }

    #[test]
    fn withdrawn_treekem_group_never_queues_frontier_gap_events() {
        let creator = AgentId([0x11; 32]);
        let creator_hex = hex::encode(creator.as_bytes());
        let member_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.withdrawn = true;
        info.state_revision = 1;
        info.roster_revision = 1;
        info.security_binding = Some("treekem:epoch=1".to_string());
        info.recompute_state_hash();
        let group_id = info.stable_group_id().to_string();
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: group_id.clone(),
            revision: 3,
            actor: creator_hex.clone(),
            agent_id: member_hex,
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(3),
            commit: Some(fake_group_state_commit(&group_id, 3, &creator_hex)),
        };

        assert_eq!(
            treekem_state_frontier_gap_reason(&info, &event, &creator_hex, Some(1)),
            None,
            "withdrawn groups must short-circuit before TreeKEM queue/catch-up"
        );
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &event,
            &creator_hex,
        ));
        assert!(!withdrawn_group_allows_metadata_event(&event));
    }

    #[test]
    fn treekem_leave_disposition_allows_local_pending_stub_cleanup() {
        let creator = AgentId([0x11; 32]);
        let member = AgentId([0x22; 32]);
        let creator_hex = hex::encode(creator.as_bytes());
        let member_hex = hex::encode(member.as_bytes());
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;

        assert_eq!(
            treekem_leave_disposition(&info, &creator_hex),
            TreeKemLeaveDisposition::ActiveMember
        );
        assert_eq!(
            treekem_leave_disposition(&info, &member_hex),
            TreeKemLeaveDisposition::LocalOnlyDrop
        );

        info.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(creator_hex.clone()),
            None,
        );
        assert_eq!(
            treekem_leave_disposition(&info, &member_hex),
            TreeKemLeaveDisposition::ActiveMember
        );

        info.remove_member(&member_hex, Some(creator_hex));
        assert_eq!(
            treekem_leave_disposition(&info, &member_hex),
            TreeKemLeaveDisposition::LocalOnlyDrop
        );
    }

    #[test]
    fn treekem_invite_stub_matches_authority_base_hash() {
        let creator = AgentId([7; 32]);
        let group_id = "ab".repeat(32);
        let policy = x0x::groups::GroupPolicy::default();
        let mut authority = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            "desc".to_string(),
            creator,
            group_id.clone(),
            policy.clone(),
        );
        authority.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        authority.shared_secret = None;
        authority.secret_epoch = 1;
        authority.security_binding = Some("treekem:epoch=1".to_string());
        authority.recompute_state_hash();

        let mut invite = x0x::groups::invite::SignedInvite::new(
            authority.mls_group_id.clone(),
            authority.name.clone(),
            &creator,
            0,
        );
        invite.stable_group_id = Some(authority.stable_group_id().to_string());
        invite.group_created_at = Some(authority.created_at);
        invite.group_description = Some(authority.description.clone());
        invite.policy = Some(authority.policy.clone());
        invite.genesis_creation_nonce =
            authority.genesis.as_ref().map(|g| g.creation_nonce.clone());
        invite.base_state_revision = Some(authority.state_revision);
        invite.base_state_hash = Some(authority.state_hash.clone());
        invite.base_members_v2 = Some(authority.members_v2.clone());
        invite.base_prev_state_hash = authority.prev_state_hash.clone();
        invite.secure_plane = Some(authority.secure_plane);
        invite.base_secret_epoch = Some(authority.secret_epoch);
        invite.base_security_binding = authority.security_binding.clone();

        let mut stub = x0x::groups::GroupInfo::with_policy(
            invite.group_name.clone(),
            invite.group_description.clone().unwrap_or_default(),
            creator,
            invite.group_id.clone(),
            invite.policy.clone().unwrap_or_default(),
        );
        if let Some(group_created_at) = invite.group_created_at {
            stub.created_at = group_created_at;
        }
        if let Some(stable_group_id) = invite.stable_group_id.clone() {
            stub.genesis = Some(x0x::groups::GroupGenesis::with_existing_id(
                stable_group_id,
                invite.inviter.clone(),
                stub.created_at,
                invite.genesis_creation_nonce.clone().unwrap_or_default(),
            ));
        }
        stub.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        stub.shared_secret = None;
        stub.secret_epoch = invite.base_secret_epoch.unwrap_or_default();
        stub.security_binding = invite.base_security_binding.clone();
        stub.state_revision = invite.base_state_revision.unwrap_or_default();
        stub.roster_revision = stub.roster_revision.max(stub.state_revision);
        if let Some(base_members) = invite.base_members_v2.clone() {
            stub.members_v2 = base_members;
        }
        if let Some(base_state_hash) = invite.base_state_hash.clone() {
            stub.state_hash = base_state_hash;
            stub.prev_state_hash = invite.base_prev_state_hash.clone();
        } else {
            stub.recompute_state_hash();
        }

        assert_eq!(stub.state_hash, authority.state_hash);
        assert_eq!(stub.state_revision, authority.state_revision);
    }

    #[test]
    fn non_treekem_admin_invite_joiner_validates_member_added_state_chain() {
        let creator_kp = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let inviter_kp = x0x::identity::AgentKeypair::generate().expect("inviter keypair");
        let joiner_kp = x0x::identity::AgentKeypair::generate().expect("joiner keypair");
        let creator_hex = hex::encode(creator_kp.agent_id().as_bytes());
        let inviter_hex = hex::encode(inviter_kp.agent_id().as_bytes());
        let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
        let group_id = "cd".repeat(32);

        let mut base = x0x::groups::GroupInfo::with_policy(
            "public".to_string(),
            "non-TreeKEM invite".to_string(),
            creator_kp.agent_id(),
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        assert_ne!(
            base.secure_plane,
            x0x::mls::SecureGroupPlane::TreeKem,
            "fixture must exercise the non-TreeKEM path"
        );
        base.roster_revision = base.roster_revision.saturating_add(1);
        base.add_member(
            inviter_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(creator_hex.clone()),
            Some("inviter-admin".to_string()),
        );
        base.seal_commit(&creator_kp, 1_000)
            .expect("creator promotion commit seals");

        let mut invite = x0x::groups::invite::SignedInvite::new(
            base.mls_group_id.clone(),
            base.name.clone(),
            &inviter_kp.agent_id(),
            0,
        );
        invite.stable_group_id = Some(base.stable_group_id().to_string());
        invite.group_created_at = Some(base.created_at);
        invite.group_description = Some(base.description.clone());
        invite.policy = Some(base.policy.clone());
        invite.genesis_creation_nonce = base.genesis.as_ref().map(|g| g.creation_nonce.clone());
        invite.base_state_revision = Some(base.state_revision);
        invite.base_state_hash = Some(base.state_hash.clone());
        invite.base_members_v2 = Some(base.members_v2.clone());
        invite.base_prev_state_hash = base.prev_state_hash.clone();
        invite.secure_plane = Some(base.secure_plane);
        invite.base_secret_epoch = Some(base.secret_epoch);
        invite.base_security_binding = base.security_binding.clone();

        let display_name = Some("joiner".to_string());
        let joiner_pre_commit = invite_join_group_info(
            &invite,
            creator_kp.agent_id(),
            &creator_hex,
            &group_id,
            &joiner_hex,
            display_name.clone(),
            None,
        );
        assert_eq!(joiner_pre_commit.members_v2, base.members_v2);
        assert_eq!(joiner_pre_commit.state_hash, base.state_hash);
        assert_eq!(joiner_pre_commit.prev_state_hash, base.prev_state_hash);
        assert_eq!(joiner_pre_commit.state_revision, base.state_revision);
        assert_eq!(joiner_pre_commit.roster_revision, base.roster_revision);
        assert!(
            !joiner_pre_commit.members_v2.contains_key(&joiner_hex),
            "joiner stub must not pre-commit the joiner under the authority base hash"
        );

        let mut inviter_after = base.clone();
        inviter_after.roster_revision = inviter_after.roster_revision.saturating_add(1);
        inviter_after.add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(inviter_hex.clone()),
            display_name.clone(),
        );
        let revision = inviter_after.roster_revision;
        let member_added = inviter_after
            .seal_commit(&inviter_kp, 2_000)
            .expect("non-creator admin seals MemberAdded");

        let apply_member_added = |current: &x0x::groups::GroupInfo| {
            apply_stateful_event_to_group(
                current,
                &member_added,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.add_member(
                        joiner_hex.clone(),
                        x0x::groups::GroupRole::Member,
                        Some(inviter_hex.clone()),
                        display_name.clone(),
                    );
                },
            )
        };

        let creator_after = apply_member_added(&base)
            .expect("creator should validate inviter-authored MemberAdded");
        let joiner_after = apply_member_added(&joiner_pre_commit).expect(
            "joiner should validate non-creator inviter MemberAdded against the invite base state",
        );

        let assert_state_hash_coherent = |label: &str, info: &x0x::groups::GroupInfo| {
            let mut recomputed = info.clone();
            recomputed.recompute_state_hash();
            assert_eq!(
                recomputed.state_hash, info.state_hash,
                "{label} state_hash must commit to its current roster/policy/meta/security fields"
            );
        };

        for (label, info) in [
            ("creator", &creator_after),
            ("inviter", &inviter_after),
            ("joiner", &joiner_after),
        ] {
            assert!(
                info.has_active_member(&joiner_hex),
                "{label} roster should contain joiner after MemberAdded"
            );
            assert_eq!(
                info.caller_role(&inviter_hex),
                Some(x0x::groups::GroupRole::Admin),
                "{label} roster should preserve non-creator inviter Admin authority"
            );
            assert_state_hash_coherent(label, info);
        }
        assert_eq!(
            member_added.roster_root,
            x0x::groups::compute_roster_root(&joiner_after.members_v2),
            "MemberAdded commit roster root must match the post-apply joiner roster"
        );
        assert_eq!(creator_after.state_hash, inviter_after.state_hash);
        assert_eq!(joiner_after.state_hash, inviter_after.state_hash);
        assert_eq!(creator_after.state_revision, inviter_after.state_revision);
        assert_eq!(joiner_after.state_revision, inviter_after.state_revision);
    }

    #[test]
    fn non_treekem_invite_stub_refreshes_existing_joiner_display_without_rehash() {
        let creator_kp = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let joiner_kp = x0x::identity::AgentKeypair::generate().expect("joiner keypair");
        let creator_hex = hex::encode(creator_kp.agent_id().as_bytes());
        let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
        let group_id = "ef".repeat(32);

        let mut base = x0x::groups::GroupInfo::with_policy(
            "public".to_string(),
            "self rejoin invite".to_string(),
            creator_kp.agent_id(),
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        base.add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(creator_hex.clone()),
            Some("old display".to_string()),
        );
        base.seal_commit(&creator_kp, 1_000)
            .expect("base member commit seals");

        let mut invite = x0x::groups::invite::SignedInvite::new(
            base.mls_group_id.clone(),
            base.name.clone(),
            &creator_kp.agent_id(),
            0,
        );
        invite.stable_group_id = Some(base.stable_group_id().to_string());
        invite.group_created_at = Some(base.created_at);
        invite.group_description = Some(base.description.clone());
        invite.policy = Some(base.policy.clone());
        invite.genesis_creation_nonce = base.genesis.as_ref().map(|g| g.creation_nonce.clone());
        invite.base_state_revision = Some(base.state_revision);
        invite.base_state_hash = Some(base.state_hash.clone());
        invite.base_members_v2 = Some(base.members_v2.clone());
        invite.base_prev_state_hash = base.prev_state_hash.clone();
        invite.secure_plane = Some(base.secure_plane);
        invite.base_secret_epoch = Some(base.secret_epoch);
        invite.base_security_binding = base.security_binding.clone();

        let stub = invite_join_group_info(
            &invite,
            creator_kp.agent_id(),
            &creator_hex,
            &group_id,
            &joiner_hex,
            Some("new display".to_string()),
            None,
        );

        let joiner = stub
            .members_v2
            .get(&joiner_hex)
            .expect("base-state joiner should still be present");
        assert_eq!(joiner.state, x0x::groups::GroupMemberState::Active);
        assert_eq!(joiner.role, x0x::groups::GroupRole::Member);
        assert_eq!(joiner.display_name.as_deref(), Some("new display"));
        assert_eq!(stub.state_hash, base.state_hash);
        assert_eq!(stub.prev_state_hash, base.prev_state_hash);
        assert_eq!(stub.state_revision, base.state_revision);

        let mut recomputed = stub.clone();
        recomputed.recompute_state_hash();
        assert_eq!(
            recomputed.state_hash, stub.state_hash,
            "display-only refresh must not make the authority base hash incoherent"
        );
    }

    #[test]
    fn local_treekem_welcome_with_state_gap_is_queued() {
        let local_agent_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([1; 32]),
            "aa".repeat(32),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 1;
        info.roster_revision = 1;
        info.state_hash = "rev1".to_string();
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: info.stable_group_id().to_string(),
            revision: 3,
            actor: "11".repeat(32),
            agent_id: local_agent_hex.clone(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: None,
            welcome_ref: Some(WelcomeRef {
                welcome_id: "welcome".to_string(),
                byte_len: 1,
                source: "11".repeat(32),
            }),
            treekem_epoch: Some(3),
            commit: Some(x0x::groups::GroupStateCommit {
                group_id: info.stable_group_id().to_string(),
                revision: 3,
                prev_state_hash: Some("rev2".to_string()),
                roster_root: String::new(),
                policy_hash: String::new(),
                public_meta_hash: String::new(),
                security_binding: Some("treekem:epoch=3".to_string()),
                state_hash: "rev3".to_string(),
                withdrawn: false,
                committed_by: "11".repeat(32),
                committed_at: 1,
                signer_public_key: String::new(),
                signature: String::new(),
            }),
        };

        assert_eq!(
            treekem_state_frontier_gap_reason(&info, &event, &local_agent_hex, None),
            Some("revision_gap".to_string())
        );
    }

    #[test]
    fn join_result_fetch_request_is_small_and_stable() {
        let request = JoinResultMessage::FetchRequest {
            group_id: "aa".repeat(32),
            member_agent_id: "bb".repeat(32),
        };
        let payload = serde_json::to_vec(&request);
        assert!(payload.is_ok(), "join-result fetch request serializes");
        let Ok(payload) = payload else {
            return;
        };
        assert!(payload.len() < x0x::dm::MAX_PAYLOAD_BYTES);
        assert_eq!(
            join_result_key(&"aa".repeat(32), &"bb".repeat(32)),
            format!("{}:{}", "aa".repeat(32), "bb".repeat(32))
        );

        let result = JoinResultMessage::Result {
            event: Box::new(NamedGroupMetadataEvent::MemberAdded {
                group_id: "aa".repeat(32),
                revision: 1,
                actor: "11".repeat(32),
                agent_id: "bb".repeat(32),
                display_name: None,
                treekem_commit_b64: Some("Yw==".to_string()),
                treekem_welcome_b64: None,
                welcome_ref: None,
                treekem_epoch: Some(1),
                commit: None,
            }),
        };
        let result_payload = serde_json::to_vec(&result);
        assert!(result_payload.is_ok(), "join-result response serializes");
        let Ok(result_payload) = result_payload else {
            return;
        };
        assert!(result_payload.len() < x0x::dm::MAX_PAYLOAD_BYTES);
        let parsed = serde_json::from_slice::<JoinResultMessage>(&result_payload);
        assert!(parsed.is_ok(), "join-result response deserializes");
        assert!(matches!(parsed, Ok(JoinResultMessage::Result { .. })));
    }

    #[test]
    fn join_result_requires_stored_expected_inviter() {
        let expected = "11".repeat(32);
        let other = "22".repeat(32);

        assert_eq!(
            validate_join_result_inviter(None, &expected, &expected).unwrap_err(),
            "missing_expected_inviter"
        );
        assert_eq!(
            validate_join_result_inviter(Some(&expected), &other, &expected).unwrap_err(),
            "unexpected_sender"
        );
        assert_eq!(
            validate_join_result_inviter(Some(&expected), &expected, &other).unwrap_err(),
            "unexpected_actor"
        );
        assert!(validate_join_result_inviter(Some(&expected), &expected, &expected).is_ok());
    }

    #[test]
    fn welcome_blob_control_messages_keep_gossip_fallback() {
        let fetch = WelcomeBlobMessage::FetchRequest {
            group_id: "aa".repeat(32),
            welcome_id: "bb".repeat(32),
        };
        let fetch_config = welcome_blob_send_config(&fetch);
        assert!(!fetch_config.prefer_raw_quic_if_connected);
        assert!(!fetch_config.stop_fallback_on_raw_error);

        let chunk = WelcomeBlobMessage::Chunk {
            welcome_id: "bb".repeat(32),
            sequence: 0,
            data: "Yw==".to_string(),
        };
        let chunk_config = welcome_blob_send_config(&chunk);
        assert!(chunk_config.prefer_raw_quic_if_connected);
        // Welcome-blob chunks reuse `file_transfer_send_config()`, which keeps
        // capability-aware gossip fallback enabled (`stop_fallback_on_raw_error
        // == false`) — matching this test's intent ("keep gossip fallback").
        // Issue #110 Phase 1: this assertion was inverted and the test never ran
        // (binary `#[cfg(test)]` mods are skipped by nextest); moving the module
        // into the library activated it and exposed the contradiction. Corrected
        // to reflect the unchanged production behavior; the move itself is verbatim.
        assert!(!chunk_config.stop_fallback_on_raw_error);
    }

    #[test]
    fn file_transfer_control_messages_are_acked_but_chunks_are_windowed() {
        let control = file_transfer_control_send_config();
        assert!(control.prefer_raw_quic_if_connected);
        assert!(!control.stop_fallback_on_raw_error);
        assert_eq!(
            control.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );

        let chunk = file_transfer_send_config();
        assert!(chunk.prefer_raw_quic_if_connected);
        assert!(!chunk.stop_fallback_on_raw_error);
        assert_eq!(
            chunk.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
    }

    #[test]
    fn named_group_metadata_delivery_prefers_verified_gossip_inbox() {
        let config = named_group_direct_delivery_config();

        assert!(!config.prefer_raw_quic_if_connected);
        assert!(!config.require_gossip);
        assert!(!config.stop_fallback_on_raw_error);
        assert_eq!(
            config.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
    }

    #[test]
    fn treekem_welcome_ref_is_content_addressed_and_serialized() {
        let bytes = b"large treekem welcome blob";
        let welcome_id = welcome_id_for_bytes(bytes);
        assert_eq!(welcome_id, hex::encode(blake3::hash(bytes).as_bytes()));

        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: None,
            welcome_ref: Some(WelcomeRef {
                welcome_id: welcome_id.clone(),
                byte_len: bytes.len() as u64,
                source: "11".repeat(32),
            }),
            treekem_epoch: Some(1),
            commit: None,
        };
        let json = serde_json::to_value(event);
        assert!(json.is_ok(), "welcome ref event serializes");
        let Ok(json) = json else {
            return;
        };
        assert_eq!(json["welcome_ref"]["welcome_id"], welcome_id);
        assert_eq!(json["treekem_welcome_b64"], serde_json::Value::Null);
    }

    #[test]
    fn treekem_join_request_events_accept_legacy_json_defaults() {
        let created: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "join_request_created",
            "group_id": "aa",
            "request_id": "req",
            "requester_agent_id": "22",
            "message": null,
            "ts": 1
        }))
        .expect("legacy created event should deserialize");
        match created {
            NamedGroupMetadataEvent::JoinRequestCreated {
                treekem_key_package_b64,
                ..
            } => assert_eq!(treekem_key_package_b64, None),
            other => panic!("unexpected event: {other:?}"),
        }

        let approved: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "join_request_approved",
            "group_id": "aa",
            "request_id": "req",
            "revision": 2,
            "actor": "11",
            "requester_agent_id": "22"
        }))
        .expect("legacy approved event should deserialize");
        match approved {
            NamedGroupMetadataEvent::JoinRequestApproved {
                treekem_commit_b64,
                treekem_welcome_b64,
                treekem_epoch,
                ..
            } => {
                assert_eq!(treekem_commit_b64, None);
                assert_eq!(treekem_welcome_b64, None);
                assert_eq!(treekem_epoch, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn member_joined_canonical_binds_treekem_keypackage() {
        let base = canonical_member_joined_bytes(
            "group",
            Some("stable"),
            &"22".repeat(32),
            "pubkey",
            x0x::groups::GroupRole::Member,
            Some("Alice"),
            &"11".repeat(32),
            "invite-secret",
            42,
            Some("key-package-a"),
        );
        let changed = canonical_member_joined_bytes(
            "group",
            Some("stable"),
            &"22".repeat(32),
            "pubkey",
            x0x::groups::GroupRole::Member,
            Some("Alice"),
            &"11".repeat(32),
            "invite-secret",
            42,
            Some("key-package-b"),
        );
        let legacy = canonical_member_joined_bytes(
            "group",
            Some("stable"),
            &"22".repeat(32),
            "pubkey",
            x0x::groups::GroupRole::Member,
            Some("Alice"),
            &"11".repeat(32),
            "invite-secret",
            42,
            None,
        );

        assert_ne!(base, changed);
        assert_ne!(base, legacy);
    }

    #[test]
    fn direct_add_request_defaults_without_treekem_keypackage() {
        let req: AddNamedGroupMemberRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "22",
            "display_name": "Bob"
        }))
        .expect("request should deserialize");
        assert_eq!(req.agent_id, "22");
        assert_eq!(req.display_name.as_deref(), Some("Bob"));
        assert_eq!(req.treekem_key_package_b64, None);
    }

    #[test]
    fn phase3_metadata_events_accept_legacy_json_defaults() {
        let joined: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "member_joined",
            "group_id": "aa",
            "member_agent_id": "22",
            "member_public_key_b64": "cHVi",
            "role": "member",
            "inviter_agent_id": "11",
            "invite_secret": "secret",
            "ts_ms": 1,
            "signature_b64": "c2ln"
        }))
        .expect("legacy member_joined should deserialize");
        match joined {
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64,
                ..
            } => assert_eq!(treekem_key_package_b64, None),
            other => panic!("unexpected event: {other:?}"),
        }

        let added: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "member_added",
            "group_id": "aa",
            "revision": 1,
            "actor": "11",
            "agent_id": "22",
            "display_name": null
        }))
        .expect("legacy member_added should deserialize");
        match added {
            NamedGroupMetadataEvent::MemberAdded {
                treekem_commit_b64,
                treekem_welcome_b64,
                treekem_epoch,
                ..
            } => {
                assert_eq!(treekem_commit_b64, None);
                assert_eq!(treekem_welcome_b64, None);
                assert_eq!(treekem_epoch, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let banned: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "member_banned",
            "group_id": "aa",
            "revision": 1,
            "actor": "11",
            "agent_id": "22"
        }))
        .expect("legacy member_banned should deserialize");
        match banned {
            NamedGroupMetadataEvent::MemberBanned {
                treekem_commit_b64,
                treekem_epoch,
                ..
            } => {
                assert_eq!(treekem_commit_b64, None);
                assert_eq!(treekem_epoch, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn phase3_metadata_classifier_allows_completed_membership_events() {
        let member_added = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(1),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&member_added));

        let member_banned = NamedGroupMetadataEvent::MemberBanned {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            secret_epoch: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(1),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&member_banned));

        let member_unbanned = NamedGroupMetadataEvent::MemberUnbanned {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&member_unbanned));
    }

    #[test]
    fn treekem_pending_event_helpers_dedupe_and_sort_by_frontier() {
        fn fake_commit(revision: u64, prev: &str) -> x0x::groups::GroupStateCommit {
            x0x::groups::GroupStateCommit {
                group_id: "aa".to_string(),
                revision,
                prev_state_hash: Some(prev.to_string()),
                roster_root: "roster".to_string(),
                policy_hash: "policy".to_string(),
                public_meta_hash: "meta".to_string(),
                security_binding: Some(format!("treekem:epoch={revision}")),
                state_hash: format!("state-{revision}"),
                withdrawn: false,
                committed_by: "11".to_string(),
                committed_at: revision,
                signer_public_key: "pub".to_string(),
                signature: "sig".to_string(),
            }
        }

        let add_epoch_2 = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 2,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(2),
            commit: Some(fake_commit(2, "state-1")),
        };
        let ban_epoch_3 = NamedGroupMetadataEvent::MemberBanned {
            group_id: "aa".to_string(),
            revision: 3,
            actor: "11".to_string(),
            agent_id: "33".to_string(),
            secret_epoch: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(3),
            commit: Some(fake_commit(3, "state-2")),
        };

        assert_eq!(treekem_membership_event_sort_key(&ban_epoch_3), (3, 3));
        assert_eq!(treekem_membership_event_sort_key(&add_epoch_2), (2, 2));
        assert_ne!(
            treekem_membership_event_key(&add_epoch_2),
            treekem_membership_event_key(&ban_epoch_3)
        );
        assert_eq!(
            treekem_membership_event_key(&add_epoch_2),
            treekem_membership_event_key(&add_epoch_2.clone())
        );
    }

    #[test]
    fn treekem_local_welcome_queues_on_authority_state_gap() {
        let local_agent_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([9; 32]),
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 0;
        info.roster_revision = 0;
        info.state_hash = "joiner-stub-hash".to_string();
        let commit = x0x::groups::GroupStateCommit {
            group_id: "aa".to_string(),
            revision: 10,
            prev_state_hash: Some("authority-prev-hash".to_string()),
            roster_root: "roster".to_string(),
            policy_hash: "policy".to_string(),
            public_meta_hash: "meta".to_string(),
            security_binding: Some("treekem:epoch=10".to_string()),
            state_hash: "authority-state-10".to_string(),
            withdrawn: false,
            committed_by: "11".to_string(),
            committed_at: 10,
            signer_public_key: "pub".to_string(),
            signature: "sig".to_string(),
        };
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 10,
            actor: "11".to_string(),
            agent_id: local_agent_hex.clone(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(10),
            commit: Some(commit),
        };

        assert_eq!(
            treekem_state_frontier_gap_reason(&info, &event, &local_agent_hex, None),
            Some("revision_gap".to_string())
        );
    }

    #[test]
    fn treekem_catchup_messages_use_explicit_type_tags() {
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: "aa".to_string(),
            requester_agent_id: "22".to_string(),
            from_revision: 1,
            from_treekem_epoch: 1,
            current_state_hash: "state-1".to_string(),
            missing_prev_state_hash: Some("state-2".to_string()),
            limit: 8,
        };
        let encoded = serde_json::to_value(&request).expect("catch-up request serializes");
        assert_eq!(encoded["message_type"], "treekem_catchup_request");

        let response = TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: "aa".to_string(),
            events: Vec::new(),
            truncated: false,
        };
        let encoded = serde_json::to_value(&response).expect("catch-up response serializes");
        assert_eq!(encoded["message_type"], "treekem_catchup_response");
    }

    #[test]
    fn treekem_membership_guard_returns_501_without_mutating() {
        let creator = AgentId([7; 32]);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        let before_revision = info.roster_revision;
        let before_members = info.members_v2.clone();

        let response = treekem_membership_unsupported(&info);
        assert!(
            response.is_some(),
            "legacy-only TreeKEM endpoints must fail loud instead of running GSS rekey logic"
        );
        let status = response.map(|(status, _body)| status);

        assert_eq!(status, Some(StatusCode::NOT_IMPLEMENTED));
        assert_eq!(info.roster_revision, before_revision);
        assert_eq!(info.members_v2, before_members);
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

    #[test]
    fn safe_file_transfer_id_accepts_canonical_uuid() {
        let transfer_id = uuid::Uuid::new_v4().to_string();
        assert!(is_safe_file_transfer_id(&transfer_id));

        let transfers_dir = PathBuf::from("/tmp/x0x-transfers");
        let part_path = safe_file_transfer_part_path(&transfers_dir, &transfer_id);
        assert_eq!(
            part_path,
            Ok(transfers_dir.join(format!("{transfer_id}.part")))
        );
    }

    #[test]
    fn safe_file_transfer_id_rejects_path_traversal_and_noncanonical_ids() {
        let uuid = uuid::Uuid::new_v4().to_string();
        let invalid_ids = vec![
            "../../escape".to_string(),
            "../escape".to_string(),
            "subdir/file".to_string(),
            r"subdir\file".to_string(),
            "..".to_string(),
            String::new(),
            uuid.to_uppercase(),
            format!("urn:uuid:{uuid}"),
            format!("{{{uuid}}}"),
        ];

        for transfer_id in invalid_ids {
            assert!(!is_safe_file_transfer_id(&transfer_id));
            assert!(
                safe_file_transfer_part_path(FsPath::new("/tmp/x0x-transfers"), &transfer_id)
                    .is_err()
            );
        }
    }

    #[test]
    fn file_chunk_ack_slot_records_max() {
        let slot = FileChunkAckSlot::new();
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), u64::MAX);
        slot.record_ack(5);
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), 5);
        // Older sequence does not regress the high-watermark.
        slot.record_ack(3);
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), 5);
        // Higher sequence advances it.
        slot.record_ack(9);
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), 9);
    }

    #[tokio::test]
    async fn wait_for_chunk_window_does_not_block_inside_window() {
        let slot = FileChunkAckSlot::new();
        // For chunks 0..FILE_CHUNK_WINDOW the window isn't saturated yet.
        for n in 0..FILE_CHUNK_WINDOW {
            wait_for_chunk_window(&slot, n)
                .await
                .expect("must return Ok inside the window");
        }
    }

    #[tokio::test]
    async fn wait_for_chunk_window_releases_when_ack_arrives() {
        let slot = Arc::new(FileChunkAckSlot::new());
        // Sending chunk N=FILE_CHUNK_WINDOW requires ack of chunk 0.
        let n = FILE_CHUNK_WINDOW;
        let waiter_slot = Arc::clone(&slot);
        let waiter = tokio::spawn(async move { wait_for_chunk_window(&waiter_slot, n).await });

        // Give the waiter a chance to park, then deliver the ack.
        tokio::time::sleep(Duration::from_millis(50)).await;
        slot.record_ack(0);

        let res = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must release before the test timeout")
            .expect("waiter task did not panic");
        res.expect("must succeed once ack >= n - WINDOW arrives");
    }

    #[tokio::test]
    async fn wait_for_final_acks_returns_when_last_seq_acked() {
        let slot = Arc::new(FileChunkAckSlot::new());
        let waiter_slot = Arc::clone(&slot);
        let waiter = tokio::spawn(async move { wait_for_final_acks(&waiter_slot, 100).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        slot.record_ack(99); // not enough
        tokio::time::sleep(Duration::from_millis(50)).await;
        slot.record_ack(100); // exact match — must release

        let res = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must release before the test timeout")
            .expect("waiter task did not panic");
        res.expect("must succeed once ack >= last_seq arrives");
    }

    #[test]
    fn group_public_message_direct_payload_is_prefixed_json() {
        let msg = x0x::groups::GroupPublicMessage {
            group_id: "group-1".to_string(),
            state_hash_at_send: "state".to_string(),
            revision_at_send: 7,
            author_agent_id: "aa".repeat(32),
            author_public_key: "bb".repeat(64),
            author_user_id: None,
            kind: x0x::groups::GroupPublicMessageKind::Chat,
            body: "hello".to_string(),
            timestamp: 123,
            signature: "cc".repeat(64),
        };

        let payload =
            encode_group_public_message_direct_payload(&msg).expect("payload should encode");
        assert!(payload.starts_with(GROUP_PUBLIC_MESSAGE_DM_PREFIX));

        let decoded: x0x::groups::GroupPublicMessage =
            serde_json::from_slice(&payload[GROUP_PUBLIC_MESSAGE_DM_PREFIX.len()..])
                .expect("payload JSON should decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn kv_store_delta_direct_payload_is_prefixed_json() {
        let peer_id = saorsa_gossip_types::PeerId::new([9; 32]);
        let delta = x0x::kv::KvStoreDelta::new(42);

        let payload = encode_kv_store_delta_direct_payload("store-1", peer_id, &delta)
            .expect("payload should encode");
        assert!(payload.starts_with(KV_STORE_DELTA_DM_PREFIX));

        let decoded: KvStoreDirectDelta =
            serde_json::from_slice(&payload[KV_STORE_DELTA_DM_PREFIX.len()..])
                .expect("payload JSON should decode");
        assert_eq!(decoded.store_id, "store-1");
        assert_eq!(decoded.peer_id, peer_id);
        assert_eq!(decoded.delta.version, delta.version);
    }
}
