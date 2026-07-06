//! Daemon configuration, server handle, and shared application state.
//!
//! Extracted from `server/mod.rs` (#125 / WS1.4) as a mechanical move.
//! Public API items are re-exported from the parent module; `AppState` and
//! the internal config/cache types are `pub(super)` — internal to `server`.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{broadcast, mpsc, watch, Mutex, RwLock};

use crate as x0x;
use crate::contacts::ContactStore;
use crate::{Agent, KvStoreHandle, TaskListHandle};

// Local types that stay in `mod.rs` (groups/files domain). A child module can
// name private items of its parent, so no `pub(super)` is needed on them —
// they are imported here and claimed by their own submodules later.
use super::auth::SessionStore;
use super::sse::SseEvent;
use super::ws::{SharedTopicState, WsOutboundStats, WsSession};
use super::{
    ExpectedJoinResultInviter, FileChunkAckSlot, NamedGroupMetadataEvent, PendingJoinResult,
    PendingTreeKemMetadataEvent, PendingWelcome, PendingWelcomeReceive, RestSubscription,
    WelcomeFetchWaiter,
};

/// Carries the CLI-derived flags that the server-bringup path consumes.
/// Phase 1: minimal — do not redesign config here.
#[derive(Default)]
pub struct ServeOptions {
    /// Skip the startup GitHub update check.
    pub skip_update_check: bool,
    /// Disable ant-quic UPnP IGD port mapping for this invocation.
    pub cli_no_port_mapping: bool,
    /// Do not load or save the cached peer set.
    pub cli_disable_peer_cache: bool,
    /// Active instance name (`--name`), if any.
    pub instance_name: Option<String>,
    /// Loaded exec ACL policy.
    pub exec_policy: x0x::exec::ExecPolicy,
    /// Loaded connect ACL policy.
    ///
    /// `Default` is [`x0x::connect::ConnectPolicy::Disabled`], so embedders
    /// that build `ServeOptions` without supplying a connect ACL get
    /// default-deny for free.
    pub connect_policy: x0x::connect::ConnectPolicy,
    /// Whether the self-update install/restart paths are allowed to run.
    ///
    /// AND-ed with `config.update.enabled`. The daemon binary sets this to
    /// `config.update.enabled` so its behaviour is unchanged. The public
    /// [`crate::server::serve`] entrypoint defaults it to `false` — an embedded library must
    /// never replace or restart the host application. Manifest *propagation*
    /// (broadcast/listen for informational purposes) is unaffected; only the
    /// paths that download + install + restart are gated.
    pub self_update_enabled: bool,
}

/// Handle to a running, in-process x0x server.
///
/// Returned by [`crate::server::serve`] / [`crate::server::serve_with_options`]. The server runs on a
/// detached supervisor task; the handle owns its lifecycle. All synchronous,
/// fallible startup (data-dir create, identity load/gen, listener bind, state
/// and router build, `api.port` write) has already completed by the time the
/// handle is returned, so [`local_addr`](ServerHandle::local_addr) is readable
/// immediately, which matters when binding `127.0.0.1:0` for tests.
///
/// Dropping the handle requests shutdown (the supervisor is cancelled) but does
/// not block; await [`wait`](ServerHandle::wait) or
/// [`shutdown_and_wait`](ServerHandle::shutdown_and_wait) to observe completion.
pub struct ServerHandle {
    pub(super) local_addr: SocketAddr,
    pub(super) cancel: tokio_util::sync::CancellationToken,
    // `Option` so the consuming `wait`/`shutdown_and_wait` can take the join
    // handle out without conflicting with the `Drop` impl (which only cancels).
    pub(super) task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl ServerHandle {
    /// The actual bound API address. Readable immediately after the handle is
    /// returned, including the resolved port when the caller bound to port 0.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Request graceful shutdown. Idempotent and non-consuming — safe to call
    /// repeatedly and from a `&self` reference. Returns immediately; await the
    /// handle to observe run-to-completion.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// Await the server's run-to-completion, returning its supervisor result.
    pub async fn wait(mut self) -> anyhow::Result<()> {
        // `task` is always `Some` here — it is only taken by this consuming
        // method, so a single `wait`/`shutdown_and_wait` call sees it set.
        let Some(task) = self.task.take() else {
            return Err(anyhow::anyhow!("server handle already consumed"));
        };
        match task.await {
            Ok(res) => res,
            Err(e) => Err(anyhow::Error::new(e).context("server supervisor task failed")),
        }
    }

    /// A clone of the cancellation token that drives shutdown. Lets a host
    /// `select!` over its own signal handling and cancel without holding the
    /// handle (the daemon binary uses this for Ctrl-C). Cancelling the returned
    /// token is equivalent to calling [`shutdown`](ServerHandle::shutdown).
    #[must_use]
    pub fn cancellation_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.clone()
    }

    /// Request shutdown, then await run-to-completion.
    pub async fn shutdown_and_wait(self) -> anyhow::Result<()> {
        self.cancel.cancel();
        self.wait().await
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        // No detached daemon: dropping the handle requests shutdown. Drop does
        // not block — callers that need to observe completion use `wait`.
        self.cancel.cancel();
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Daemon configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// QUIC bind address for gossip (default 0.0.0.0:0 = random).
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,

    /// HTTP API address (default 127.0.0.1:12700).
    #[serde(default = "default_api_address")]
    pub api_address: SocketAddr,

    /// Data directory for persistent storage.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log format ("text" or "json").
    #[serde(default = "default_log_format")]
    pub log_format: String,

    /// Bootstrap peers to connect on startup.
    /// Defaults to the hardcoded global bootstrap network if not specified.
    #[serde(default = "default_bootstrap_peers")]
    pub bootstrap_peers: Vec<SocketAddr>,

    /// X0X-0062 reviewer P2 #2: enable or disable ant-quic's best-effort
    /// UPnP IGD port-mapping. Default `true` (matches ant-quic). Set to
    /// `false` in the daemon TOML (`port_mapping_enabled = false`) or via
    /// the `--no-port-mapping` CLI flag on networks without IGD support
    /// or where unsolicited router port mappings are policy-forbidden.
    #[serde(default = "default_port_mapping_enabled")]
    pub(super) port_mapping_enabled: bool,

    /// X0X-0070b: peer-relay fallback configuration (TOML `[peer_relay]`).
    /// Defaults to disabled — opt in by setting `peer_relay.enabled = true`
    /// and listing relay-candidate hex agent IDs under
    /// `peer_relay.candidates`. The relay path only activates when a direct
    /// DM crosses the failure threshold; the happy path allocates nothing
    /// extra.
    #[serde(default)]
    pub(super) peer_relay: x0x::network::PeerRelayConfig,

    /// Update configuration.
    #[serde(default)]
    pub(super) update: DaemonUpdateConfig,

    /// Gossip overlay configuration (TOML: `[gossip]`).
    #[serde(default)]
    pub gossip: x0x::gossip::GossipConfig,

    /// How often to re-announce identity (seconds).
    #[serde(default = "default_heartbeat_interval")]
    pub(super) heartbeat_interval_secs: u64,

    /// How long before a discovered agent entry is considered stale (seconds).
    #[serde(default = "default_identity_ttl")]
    pub(super) identity_ttl_secs: u64,

    /// Optional path to a user keypair file for human identity.
    /// When set, the agent can announce with `include_user_identity: true`.
    #[serde(default)]
    pub(super) user_key_path: Option<PathBuf>,

    /// Enable rendezvous `ProviderSummary` advertisements for global findability.
    #[serde(default = "default_rendezvous_enabled")]
    pub(super) rendezvous_enabled: bool,

    /// Validity period (milliseconds) for each rendezvous advertisement.
    /// The daemon re-advertises every `validity_ms / 2` so that the record
    /// is always fresh before it expires.
    #[serde(default = "default_rendezvous_validity_ms")]
    pub(super) rendezvous_validity_ms: u64,

    /// Override the presence beacon interval (seconds) for tests / embeddings.
    #[serde(default)]
    pub(super) presence_beacon_interval_secs: Option<u64>,

    /// Override the presence event poll interval (seconds) for tests / embeddings.
    #[serde(default)]
    pub(super) presence_event_poll_interval_secs: Option<u64>,

    /// Override the fallback offline timeout used by presence events (seconds).
    #[serde(default)]
    pub(super) presence_offline_timeout_secs: Option<u64>,

    /// Instance name for multi-agent support.
    /// When set, identity and data are scoped to this name.
    #[serde(default)]
    pub instance_name: Option<String>,

    /// Explicit directory for identity material (machine/agent/user/cert keys).
    ///
    /// When set, ALL identity keys derive from this directory and the daemon
    /// never falls back to `~/.x0x`. This is the storage boundary required for
    /// in-process embedding ([`crate::server::serve`]): the host supplies its own directory so
    /// nothing is written under the user's home. When unset (the default for
    /// the daemon binary), identity falls back to the existing behaviour
    /// (`~/.x0x`, or the `--name`-scoped `~/.x0x-<name>` directory).
    #[serde(default)]
    pub identity_dir: Option<PathBuf>,

    /// Override the shard digest anti-entropy interval (seconds) for tests.
    #[serde(default)]
    pub(super) directory_digest_interval_secs: Option<u64>,

    /// Override discoverable group card republish interval (seconds).
    /// `Some(0)` disables the periodic republish loop for tests.
    #[serde(default)]
    pub(super) group_card_republish_interval_secs: Option<u64>,

    /// Override startup shard resubscribe jitter window (milliseconds)
    /// for restart-persistence tests.
    #[serde(default)]
    pub(super) directory_resubscribe_jitter_ms: Option<u64>,
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

fn default_port_mapping_enabled() -> bool {
    true
}

pub fn default_bind_address() -> SocketAddr {
    // Bind to IPv6 unspecified ([::]) which accepts both IPv4 and IPv6
    // via dual-stack sockets. This avoids port conflicts on macOS where
    // binding 0.0.0.0:port prevents a subsequent [::]:port bind.
    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], DEFAULT_QUIC_PORT))
}

pub fn default_api_address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 12700))
}

pub fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("x0x"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/x0x"))
}

/// Shared cache directory used by ALL instances (not per-instance).
/// This is always the base `x0x` dir, never `x0x-<name>`.
pub(super) fn shared_cache_dir() -> PathBuf {
    let dir = dirs::data_dir()
        .map(|d| d.join("x0x"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/x0x"));
    // Ensure it exists
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn default_log_level() -> String {
    // Privacy by default for operators outside our fleet (issue #85): without
    // an explicit RUST_LOG or config log_level override, x0xd logs warn/error
    // only. Opt in to verbose logging with RUST_LOG=info.
    "warn".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

/// Update configuration for x0xd daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DaemonUpdateConfig {
    /// Enable listening for release manifests via gossip and the GitHub fallback poll.
    #[serde(default = "default_true")]
    pub(super) enabled: bool,

    /// Maximum rollout window in minutes. Default: 0 (immediate — no delay).
    /// Set to a positive value (e.g. 1440 for 24h) to spread upgrades across
    /// the fleet using a deterministic hash of the node MachineId.
    #[serde(default = "default_rollout_window_minutes")]
    pub(super) rollout_window_minutes: u64,

    /// Exit cleanly for service manager restart instead of spawning.
    /// Default: true — the daemon stops with exit code 0 so that systemd
    /// (or any supervisor with Restart=always) picks up the new binary.
    /// Set to false to use `exec()` in-place replacement instead.
    #[serde(default = "default_true")]
    pub(super) stop_on_upgrade: bool,

    /// GitHub fallback poll interval in minutes. Default: 2880 (48 hours).
    /// Set to 0 to disable the fallback entirely (gossip-only mode).
    #[serde(default = "default_fallback_check_interval_minutes")]
    pub(super) fallback_check_interval_minutes: u64,

    /// GitHub repo for update discovery.
    #[serde(default = "default_update_repo")]
    pub(super) repo: String,

    /// Include pre-releases in update checks (default: false).
    #[serde(default)]
    pub(super) include_prereleases: bool,

    /// Enable gossip-based release manifest propagation (default: true).
    /// Set to false to only use the GitHub fallback poll.
    #[serde(default = "default_true")]
    pub(super) gossip_updates: bool,
}

impl Default for DaemonUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rollout_window_minutes: 0,
            stop_on_upgrade: true,
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
    0
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

impl DaemonConfig {
    /// Whether self-update is enabled in this config. The daemon binary uses
    /// this to set [`ServeOptions::self_update_enabled`] so its behaviour is
    /// unchanged by the embed-path default of `false`.
    #[must_use]
    pub fn update_enabled(&self) -> bool {
        self.update.enabled
    }
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
            port_mapping_enabled: default_port_mapping_enabled(),
            peer_relay: x0x::network::PeerRelayConfig::default(),
            update: DaemonUpdateConfig::default(),
            gossip: x0x::gossip::GossipConfig::default(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            identity_ttl_secs: default_identity_ttl(),
            user_key_path: None,
            rendezvous_enabled: default_rendezvous_enabled(),
            rendezvous_validity_ms: default_rendezvous_validity_ms(),
            presence_beacon_interval_secs: None,
            presence_event_poll_interval_secs: None,
            presence_offline_timeout_secs: None,
            instance_name: None,
            identity_dir: None,
            directory_digest_interval_secs: None,
            group_card_republish_interval_secs: None,
            directory_resubscribe_jitter_ms: None,
        }
    }
}

/// Shared state accessible from all route handlers.
pub(super) struct AppState {
    pub(super) agent: Arc<Agent>,
    pub(super) subscriptions: RwLock<HashMap<String, RestSubscription>>,
    pub(super) task_lists: RwLock<HashMap<String, TaskListHandle>>,
    pub(super) kv_stores: RwLock<HashMap<String, KvStoreHandle>>,
    pub(super) named_groups: RwLock<HashMap<String, x0x::groups::GroupInfo>>,
    pub(super) named_groups_path: PathBuf,
    /// Background metadata listeners for named groups (one per group id).
    pub(super) group_metadata_tasks: RwLock<HashMap<String, tokio::task::JoinHandle<()>>>,
    /// Cached group cards discovered via gossip or imported from peers.
    pub(super) group_card_cache: RwLock<HashMap<String, x0x::groups::GroupCard>>,
    /// Phase C.2: per-shard cache of signed cards received via
    /// `x0x.directory.{tag|name|id}.{N}` gossip topics.
    pub(super) directory_cache: RwLock<x0x::groups::DirectoryShardCache>,
    /// Phase C.2: persistent set of shard subscriptions. Survives
    /// daemon restart (see `directory_subscriptions_path`).
    pub(super) directory_subscriptions: RwLock<x0x::groups::SubscriptionSet>,
    /// Phase C.2: disk location for subscription persistence.
    pub(super) directory_subscriptions_path: PathBuf,
    /// Phase C.2: background shard-listener tasks, keyed by (kind, shard).
    pub(super) directory_tasks:
        RwLock<HashMap<(x0x::groups::ShardKind, u32), tokio::task::JoinHandle<()>>>,
    /// Phase C.2: digest anti-entropy interval in seconds.
    pub(super) directory_digest_interval_secs: u64,
    /// Phase C.2: startup shard resubscribe jitter window in milliseconds.
    pub(super) directory_resubscribe_jitter_ms: u64,
    /// Phase E: per-group ring buffer of validated public messages.
    /// Keyed by `group_id`. Bounded by `PUBLIC_MESSAGE_HISTORY_CAP`.
    pub(super) public_messages: RwLock<HashMap<String, Vec<x0x::groups::GroupPublicMessage>>>,
    /// Phase E: background listener tasks on public-chat topics.
    pub(super) public_message_tasks: RwLock<HashMap<String, tokio::task::JoinHandle<()>>>,
    /// Per-daemon ML-KEM-768 keypair used to open `SecureShareDelivered`
    /// envelopes addressed to this agent. Public half is published in the
    /// `/agent` response and in `JoinRequestCreated` so other daemons can
    /// seal to us. Replaces the earlier publicly-derivable envelope key.
    pub(super) agent_kem_keypair: Arc<x0x::groups::kem_envelope::AgentKemKeypair>,
    pub(super) contacts: Arc<RwLock<ContactStore>>,
    pub(super) mls_groups: RwLock<HashMap<String, x0x::mls::MlsGroup>>,
    #[allow(dead_code)]
    pub(super) mls_groups_path: PathBuf,
    /// Authority-signed MemberAdded results staged by an anchor for joiner polling.
    pub(super) pending_join_results: RwLock<HashMap<String, PendingJoinResult>>,
    /// Expected inviter for a pending TreeKEM join-result response, keyed by
    /// stable group id + joining member id. Transient process-local state.
    pub(super) expected_join_result_inviters: StdMutex<HashMap<String, ExpectedJoinResultInviter>>,
    /// TreeKEM Welcome blobs staged by an anchor for pull-based delivery.
    pub(super) pending_welcomes: RwLock<HashMap<String, PendingWelcome>>,
    /// In-progress pulled TreeKEM Welcome blob receives, keyed by blake3 id.
    pub(super) pending_welcome_receives: RwLock<HashMap<String, PendingWelcomeReceive>>,
    /// Waiters blocked on a Welcome blob receive completing.
    pub(super) pending_welcome_waiters: RwLock<HashMap<String, Vec<WelcomeFetchWaiter>>>,
    /// Per-active Welcome blob transfer ack slots.
    pub(super) pending_welcome_acks: RwLock<HashMap<String, Arc<FileChunkAckSlot>>>,
    /// Bounded per-group queue for verified TreeKEM membership events that
    /// arrived before local TreeKEM readiness or ahead of our state frontier.
    pub(super) treekem_pending_events:
        RwLock<HashMap<String, VecDeque<PendingTreeKemMetadataEvent>>>,
    /// Bounded per-group log of locally authored/applied TreeKEM membership
    /// events used to satisfy explicit catch-up requests.
    pub(super) treekem_event_log: RwLock<HashMap<String, VecDeque<NamedGroupMetadataEvent>>>,
    /// Anti-spam throttle for outbound catch-up requests.
    pub(super) treekem_catchup_throttle: RwLock<HashMap<String, Instant>>,
    /// Per-group serialization for authoritative membership mutations. The
    /// owner-side `MemberJoined`→`MemberAdded` add (and every other membership
    /// apply) is a read-modify-write that loads `info`, mutates a clone, mutates
    /// the live MLS tree, then commits the roster — across several locks, not
    /// one. The gossip metadata listener and the direct-channel listener call
    /// `apply_named_group_metadata_event` for the same group concurrently, so
    /// without serialization two stale clones can both pass the
    /// `has_active_member` check, both consume the bearer invite, and double-add
    /// to the MLS tree (the second add fails "already a member") while the
    /// roster is clobbered or never committed — leaving tree and roster
    /// permanently diverged. This per-group mutex serializes those applies so
    /// the second observes the committed add and cleanly no-ops.
    pub(super) group_membership_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
    /// Live real-TreeKEM groups (ADR-0012), keyed by group-id hex. Each is
    /// wrapped in its own async mutex so a group's encrypt/decrypt/commit op
    /// and the snapshot-persist that follows it are serialized per group
    /// without blocking other groups (and without holding the map lock across
    /// disk IO). Snapshots persist under [`Self::treekem_dir`].
    pub(super) treekem_groups:
        RwLock<HashMap<String, Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>>>,
    /// Directory holding `<group_id>.snap` snapshots and `<group_id>.journal`
    /// TreeKEM persistence journals (mode 0600).
    pub(super) treekem_dir: PathBuf,
    /// Active WebSocket sessions.
    pub(super) ws_sessions: RwLock<HashMap<String, WsSession>>,
    /// Shared WS topic state (single lock for channel + subscribers + forwarder per topic).
    pub(super) ws_topics: RwLock<HashMap<String, SharedTopicState>>,
    /// Per-WS-outbound-queue observability (drop / slow-consumer-close counters).
    pub(super) ws_outbound_stats: Arc<WsOutboundStats>,
    pub(super) api_address: SocketAddr,
    pub(super) start_time: Instant,
    pub(super) broadcast_tx: broadcast::Sender<SseEvent>,
    /// Active file transfers.
    pub(super) file_transfers: RwLock<HashMap<String, x0x::files::TransferState>>,
    /// Incremental SHA-256 hashers for receiving transfers.
    pub(super) receive_hashers: RwLock<HashMap<String, Sha256>>,
    /// Out-of-order decoded chunks buffered until their predecessors arrive.
    pub(super) pending_file_chunks: RwLock<HashMap<String, BTreeMap<u64, Vec<u8>>>>,
    /// Per-active-send-transfer chunk-ack slots used to apply windowed
    /// back-pressure. Sender registers a slot at the start of
    /// `stream_file_chunks`; receiver replies with `FileMessage::ChunkAck`
    /// after each chunk is persisted; sender waits before exceeding the
    /// in-flight window. Removed when the transfer terminates. See
    /// `FILE_CHUNK_WINDOW` and `FileChunkAckSlot`.
    pub(super) file_chunk_acks: RwLock<HashMap<String, Arc<FileChunkAckSlot>>>,
    /// Directory for received file data.
    pub(super) transfers_dir: PathBuf,
    /// Channel to trigger graceful shutdown from the /shutdown endpoint.
    pub(super) shutdown_tx: mpsc::Sender<()>,
    /// Broadcasts daemon shutdown so long-lived SSE/WS connections can close.
    pub(super) shutdown_notify: watch::Sender<bool>,
    /// Update configuration honored by manual API-triggered update checks.
    pub(super) update_config: DaemonUpdateConfig,
    /// Whether install/restart-capable self-update is allowed. `false` on the
    /// embed path so `/upgrade/apply` cannot replace/restart the host process.
    pub(super) self_update_enabled: bool,
    /// Cached `/upgrade` response so polling clients cannot hammer GitHub.
    pub(super) upgrade_check_cache: Mutex<Option<CachedUpgradeCheck>>,
    /// Serializes all destructive binary replacement attempts.
    pub(super) upgrade_apply_lock: Arc<Mutex<()>>,
    /// API bearer token for authenticating local clients.
    pub(super) api_token: String,
    /// Short-lived browser session tokens (#127 / WS1.6). The only tokens
    /// accepted via `?token=` query strings on WS/SSE endpoints.
    pub(super) sessions: SessionStore,
    /// Tier-1 remote exec service.
    pub(super) exec_service: Arc<x0x::exec::ExecService>,
    /// Per-group ingest diagnostics surfaced via `/diagnostics/groups`.
    pub(super) groups_diagnostics: Arc<x0x::groups::GroupsDiagnostics>,
    /// Connect-ACL allow/deny counters + policy summary for
    /// `/diagnostics/connect`. Counters read 0 until the T4 forwarder
    /// (issue #132) wires calls to `record_allowed`/`record_denied`.
    pub(super) connect_diagnostics: Arc<x0x::connect::ConnectDiagnostics>,
    /// Tailnet forwarder service (#132 T4/T6): owns the inbound connect-gated
    /// consumer + outbound local-port listeners. `None` when connect is
    /// disabled (no policy) so the daemon runs zero forwarder tasks.
    pub(super) forward_service: Option<Arc<x0x::forward::ForwardService>>,
}

#[derive(Clone)]
pub(super) struct CachedUpgradeCheck {
    pub(super) checked_at: Instant,
    pub(super) status: StatusCode,
    pub(super) body: serde_json::Value,
    pub(super) ttl: Duration,
}
