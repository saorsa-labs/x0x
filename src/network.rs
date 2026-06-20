//! Network transport layer for x0x.
//!
//! This module provides x0x-specific wrappers around ant-quic's
//! P2P node, configured for optimal gossip network participation.
//!
//! ## Bootstrap Nodes
//!
//! The x0x network includes 6 default bootstrap nodes operated by Saorsa Labs.
//! These nodes provide:
//! - Initial peer discovery when joining the network
//! - NAT traversal assistance (coordinator/reflector roles)
//! - Rendezvous services for agent-to-agent connections
//!
//! Agents automatically connect to these bootstrap nodes
//! unless overridden with `AgentBuilder::with_network_config`.
//!
//! Default bootstrap nodes (each reachable on UDP/443 *and* UDP/5483 — ADR-0011):
//! - `142.93.199.50` - NYC, US (DigitalOcean)
//! - `147.182.234.192` - SFO, US (DigitalOcean)
//! - `65.21.157.229` - Helsinki, FI (Hetzner)
//! - `116.203.101.172` - Nuremberg, DE (Hetzner)
//! - `152.42.210.67` - Singapore, SG (DigitalOcean)
//! - `170.64.176.102` - Sydney, AU (DigitalOcean)

use crate::error::{NetworkError, NetworkResult};
use ant_quic::{bootstrap_cache::PeerCapabilities, Node, NodeConfig, TransportAddr};
use bytes::Bytes;
use saorsa_gossip_transport::GossipStreamType;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, RwLock, Semaphore};
use tracing::{debug, error, info, warn};

/// Ant-quic PeerId type alias
type AntPeerId = ant_quic::PeerId;
/// Saorsa gossip PeerId type alias
type GossipPeerId = saorsa_gossip_types::PeerId;

/// Module-private gossip frame queued between ant-quic receive and gossip dispatch.
///
/// `enqueued_at` is intentionally carried with each frame so diagnostics can
/// report queue dwell time. The wrapper never crosses the public API boundary.
#[derive(Debug)]
struct GossipPayload {
    peer_id: AntPeerId,
    data: Bytes,
    enqueued_at: Instant,
}

/// Default port for x0x nodes (when specified).
/// Default QUIC port: 5483 (LIVE on a phone keypad).
pub const DEFAULT_PORT: u16 = 5483;

/// Default health/metrics port.
pub const DEFAULT_METRICS_PORT: u16 = 12600;

/// Default maximum connections.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 32;

/// Default connection timeout.
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default stats collection interval.
pub const DEFAULT_STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Default age after which an idle pooled QUIC connection is evicted.
const CONNECTION_POOL_IDLE_EVICT_AFTER: Duration = Duration::from_secs(300);

/// Default interval for background connection-pool eviction.
const CONNECTION_POOL_EVICTION_INTERVAL: Duration = Duration::from_secs(60);

/// Idle application-data gap after which a peer is probed before reuse.
///
/// QUIC keep-alives are transport-level, but the launch soak showed peers can
/// remain listed as connected after long quiet periods while the next
/// application send stalls. Probe before the first post-idle send so stale UDP
/// paths are repaired before the caller's delivery timeout is spent.
const PRE_SEND_LIVENESS_IDLE_THRESHOLD: Duration = Duration::from_secs(20);

/// Probe budget for the pre-send liveness check.
const PRE_SEND_LIVENESS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Reconnect budget used after a failed pre-send probe.
const PRE_SEND_RECONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Minimum interval between successful app-level liveness checks for a peer.
const PRE_SEND_LIVENESS_COOLDOWN: Duration = Duration::from_secs(60);

/// Bound for lazy liveness bookkeeping in long-lived daemons.
const LIVENESS_STATE_MAX_PEERS: usize = 1024;

/// Maximum concurrent lazy liveness repairs per daemon.
const MAX_CONCURRENT_LIVENESS_REPAIRS: usize = 16;

/// Capacity for the PubSub inbound gossip channel.
const GOSSIP_PUBSUB_RECV_CAPACITY: usize = 10_000;
/// Capacity for low-volume control-style inbound gossip channels.
const GOSSIP_CONTROL_RECV_CAPACITY: usize = 4_000;

/// Maximum allowed size for bincode deserialization of untrusted network input.
///
/// Prevents memory exhaustion from crafted payloads with large length prefixes.
/// Bincode 1.x eagerly allocates based on length prefixes before reading data.
pub const MAX_MESSAGE_DESERIALIZE_SIZE: u64 = 4 * 1024 * 1024;

/// Default bootstrap nodes for the x0x network.
///
/// These are Saorsa Labs VPS nodes running x0xd with coordinator/reflector
/// roles. They form a globally distributed mesh providing bootstrap, NAT traversal,
/// and rendezvous services.
///
/// Each node runs two listeners (ADR-0011): a root instance on `[::]:443` and
/// the original on `[::]:5483` (both dual-stack: accept IPv4 and IPv6).
/// IPv6 addresses are included for nodes that have global IPv6 connectivity.
///
/// Locations:
/// - `142.93.199.50` / `2604:a880:400:d1:0:3:7db3:f001` — NYC, US (DigitalOcean)
/// - `147.182.234.192` / `2604:a880:4:1d0:0:1:6ba1:f000` — SFO, US (DigitalOcean)
/// - `65.21.157.229` / `2a01:4f9:c012:684b::1` — Helsinki, FI (Hetzner)
/// - `116.203.101.172` / `2a01:4f8:1c1a:31e6::1` — Nuremberg, DE (Hetzner)
/// - `152.42.210.67` / `2400:6180:0:d2:0:2:d30b:d000` — Singapore, SG (DigitalOcean)
/// - `170.64.176.102` / `2400:6180:10:200::ba69:b000` — Sydney, AU (DigitalOcean)
///
/// Agents can override these by calling `AgentBuilder::with_network_config`
/// with a custom [`NetworkConfig`] containing different bootstrap nodes.
///
/// X0X-0038 (SOTA-Borrow Phase A): once the connection pipeline routes
/// resolution through `ant_quic::LookupRegistry`, this list becomes the
/// payload for an `ant_quic::HardcodedLookup` registered alongside the
/// `BootstrapCacheLookup` and `MdnsLookup`. The trait + registry are already
/// shipped in ant-quic; rewiring `Endpoint::connect` is intentionally out of
/// scope for X0X-0038 (per the SOTA-Borrow plan: "Don't yet rip out direct
/// mDNS / bootstrap-cache callers in p2p_endpoint.rs").
///
/// ## Dual port: UDP/443 and UDP/5483 (ADR-0011)
///
/// Each bootstrap VPS runs **two** `x0xd` listeners: a dedicated root-run
/// instance bound to UDP/443 *and* the original instance on UDP/5483. The
/// `:443` entries are listed first because that destination port traverses
/// full-tunnel VPNs (Cloudflare WARP), corporate/hotel/CGNAT, and mobile
/// carrier networks that carry mainstream HTTP/3 (UDP/443) cleanly but
/// throttle or drop arbitrary high UDP ports like 5483. Dialing a low
/// *destination* port is unprivileged (ephemeral high source port), so
/// clients never need elevation. Both ports are dialed in parallel
/// (`BootstrapConnector::connect_multiple`); the `:5483` entries are retained
/// for backward compatibility with pre-ADR-0011 clients and unrestricted
/// networks. Identity is key-based, so the two listeners on a host are simply
/// distinct seed hints (see [[0001-bootstrap-peers-are-seed-hints-only]]).
///
/// MTU caveat: UDP/443 mitigates port throttling/DPI but does not raise a
/// path's MTU. A path that cannot carry QUIC's 1200-byte Initial cannot run
/// QUIC on any port.
pub const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[
    // ── UDP/443 (preferred; traverses WARP / full-tunnel VPN / CGNAT / DPI) ──
    // IPv4
    "142.93.199.50:443",   // NYC
    "147.182.234.192:443", // SFO
    "65.21.157.229:443",   // Helsinki
    "116.203.101.172:443", // Nuremberg
    "152.42.210.67:443",   // Singapore
    "170.64.176.102:443",  // Sydney
    // IPv6
    "[2604:a880:400:d1:0:3:7db3:f001]:443", // NYC
    "[2604:a880:4:1d0:0:1:6ba1:f000]:443",  // SFO
    "[2a01:4f9:c012:684b::1]:443",          // Helsinki
    "[2a01:4f8:1c1a:31e6::1]:443",          // Nuremberg
    "[2400:6180:0:d2:0:2:d30b:d000]:443",   // Singapore
    "[2400:6180:10:200::ba69:b000]:443",    // Sydney
    // ── UDP/5483 (original; backward-compatible with pre-ADR-0011 clients) ──
    // IPv4
    "142.93.199.50:5483",   // NYC
    "147.182.234.192:5483", // SFO
    "65.21.157.229:5483",   // Helsinki
    "116.203.101.172:5483", // Nuremberg
    "152.42.210.67:5483",   // Singapore
    "170.64.176.102:5483",  // Sydney
    // IPv6
    "[2604:a880:400:d1:0:3:7db3:f001]:5483", // NYC
    "[2604:a880:4:1d0:0:1:6ba1:f000]:5483",  // SFO
    "[2a01:4f9:c012:684b::1]:5483",          // Helsinki
    "[2a01:4f8:1c1a:31e6::1]:5483",          // Nuremberg
    "[2400:6180:0:d2:0:2:d30b:d000]:5483",   // Singapore
    "[2400:6180:10:200::ba69:b000]:5483",    // Sydney
];

/// x0x network node configuration.
///
/// This struct wraps ant-quic's configuration with x0x-specific
/// defaults optimized for gossip network participation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Socket address to bind to. If None, a random port is chosen.
    #[serde(default)]
    pub bind_addr: Option<SocketAddr>,

    /// Bootstrap nodes to connect to on startup.
    #[serde(default)]
    pub bootstrap_nodes: Vec<SocketAddr>,

    /// Maximum number of concurrent connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Timeout for establishing connections.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: Duration,

    /// Interval for collecting and reporting stats.
    #[serde(default = "default_stats_interval")]
    pub stats_interval: Duration,

    /// Path to persist peer cache.
    #[serde(default)]
    pub peer_cache_path: Option<PathBuf>,

    /// Pinned bootstrap peer IDs. When non-empty, `dial_bootstrap()` rejects
    /// peers whose ID is not in this set. Prevents spoofed bootstrap nodes.
    #[serde(default)]
    pub pinned_bootstrap_peers: std::collections::HashSet<[u8; 32]>,

    /// Inbound connection allowlist. When non-empty, `spawn_accept_loop()`
    /// rejects connections from peers not in this set.
    #[serde(default)]
    pub inbound_allowlist: std::collections::HashSet<[u8; 32]>,

    /// Max concurrent connections from a single IP. Default: 3.
    #[serde(default = "default_max_peers_per_ip")]
    pub max_peers_per_ip: u32,

    /// X0X-0062 reviewer P2 #2: surface ant-quic's best-effort UPnP IGD
    /// port-mapping toggle at the x0x config layer so daemon operators on
    /// networks without IGD support (or with policy against it) can
    /// disable it. ant-quic's default is `true`; x0x mirrors that. When
    /// `false`, x0x calls `port_mapping_enabled(false)` on the ant-quic
    /// builder, which skips the UPnP discovery task entirely.
    ///
    /// Settable via the daemon's TOML config (`port_mapping_enabled = false`)
    /// and via the `--no-port-mapping` CLI flag.
    #[serde(default = "default_port_mapping_enabled")]
    pub port_mapping_enabled: bool,
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

fn default_port_mapping_enabled() -> bool {
    true
}

fn default_connection_timeout() -> Duration {
    DEFAULT_CONNECTION_TIMEOUT
}

fn default_stats_interval() -> Duration {
    DEFAULT_STATS_INTERVAL
}

fn default_max_peers_per_ip() -> u32 {
    3
}

/// Quick check whether the host can bind an IPv6 socket.
///
/// Returns `false` if IPv6 is not available (e.g., containers, VMs,
/// or hosts with `net.ipv6.conf.all.disable_ipv6 = 1`).
fn check_ipv6_available() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

impl Default for NetworkConfig {
    fn default() -> Self {
        // Parse default bootstrap peers, filtering out IPv6 addresses
        // if IPv6 is not available on this host. This avoids wasting time
        // on deterministic connection failures during bootstrap.
        let ipv6_available = check_ipv6_available();
        let bootstrap_nodes = DEFAULT_BOOTSTRAP_PEERS
            .iter()
            .filter_map(|addr| addr.parse::<std::net::SocketAddr>().ok())
            .filter(|addr| ipv6_available || addr.is_ipv4())
            .collect();

        Self {
            bind_addr: None,
            bootstrap_nodes,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            stats_interval: DEFAULT_STATS_INTERVAL,
            peer_cache_path: None,
            pinned_bootstrap_peers: std::collections::HashSet::new(),
            inbound_allowlist: std::collections::HashSet::new(),
            max_peers_per_ip: 3,
            port_mapping_enabled: true,
        }
    }
}

/// Statistics for the network node.
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    /// Total number of connections established.
    pub total_connections: u64,
    /// Currently active connections.
    pub active_connections: u32,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of peers in the local view.
    pub peer_count: usize,
}

/// Snapshot of the x0x-side QUIC connection pool.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionPoolDiagnosticsSnapshot {
    /// Peers currently tracked by the pool.
    pub active_count: usize,
    /// Maximum tracked active connections before LRU eviction.
    pub max_connections: usize,
    /// Idle eviction threshold in seconds.
    pub idle_evict_after_secs: u64,
    /// Connections evicted because they were idle beyond the threshold.
    pub idle_evictions_total: u64,
    /// Connections evicted because the pool was over the configured cap.
    pub lru_evictions_total: u64,
    /// Send-path reconnect/readiness failures observed by the pool facade.
    pub establish_failures_total: u64,
}

#[derive(Debug, Clone, Copy)]
struct PooledConnection {
    last_used: Instant,
}

#[derive(Debug)]
struct ConnectionPool {
    inner: Mutex<HashMap<AntPeerId, PooledConnection>>,
    max_connections: usize,
    idle_evict_after: Duration,
    idle_evictions_total: AtomicU64,
    lru_evictions_total: AtomicU64,
    establish_failures_total: AtomicU64,
}

impl ConnectionPool {
    fn new(max_connections: usize, idle_evict_after: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_connections: max_connections.max(1),
            idle_evict_after,
            idle_evictions_total: AtomicU64::new(0),
            lru_evictions_total: AtomicU64::new(0),
            establish_failures_total: AtomicU64::new(0),
        }
    }

    fn note_activity(&self, peer_id: AntPeerId) -> Vec<AntPeerId> {
        let now = Instant::now();
        let Ok(mut inner) = self.inner.lock() else {
            error!("connection pool map poisoned while recording activity");
            return Vec::new();
        };
        inner.insert(peer_id, PooledConnection { last_used: now });
        self.enforce_lru_cap_locked(&mut inner)
    }

    fn sync_connected_peers(&self, peers: Vec<(AntPeerId, Instant)>) -> Vec<AntPeerId> {
        let Ok(mut inner) = self.inner.lock() else {
            error!("connection pool map poisoned while syncing peers");
            return Vec::new();
        };

        let mut connected = std::collections::HashSet::with_capacity(peers.len());
        for (peer_id, last_activity) in peers {
            connected.insert(peer_id);
            inner
                .entry(peer_id)
                .and_modify(|entry| {
                    if last_activity > entry.last_used {
                        entry.last_used = last_activity;
                    }
                })
                .or_insert(PooledConnection {
                    last_used: last_activity,
                });
        }
        inner.retain(|peer_id, _| connected.contains(peer_id));
        self.enforce_lru_cap_locked(&mut inner)
    }

    fn evict_idle(&self, now: Instant) -> Vec<AntPeerId> {
        let Ok(mut inner) = self.inner.lock() else {
            error!("connection pool map poisoned while evicting idle peers");
            return Vec::new();
        };

        let mut evicted = Vec::new();
        inner.retain(|peer_id, pooled| {
            let should_keep =
                now.saturating_duration_since(pooled.last_used) < self.idle_evict_after;
            if !should_keep {
                evicted.push(*peer_id);
            }
            should_keep
        });
        if !evicted.is_empty() {
            self.idle_evictions_total
                .fetch_add(evicted.len() as u64, Ordering::Relaxed);
        }
        evicted
    }

    fn record_disconnected(&self, peer_id: &AntPeerId) {
        let Ok(mut inner) = self.inner.lock() else {
            error!("connection pool map poisoned while removing disconnected peer");
            return;
        };
        inner.remove(peer_id);
    }

    fn record_establish_failure(&self) {
        self.establish_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ConnectionPoolDiagnosticsSnapshot {
        let active_count = match self.inner.lock() {
            Ok(inner) => inner.len(),
            Err(e) => {
                error!("connection pool diagnostics poisoned: {e}");
                0
            }
        };

        ConnectionPoolDiagnosticsSnapshot {
            active_count,
            max_connections: self.max_connections,
            idle_evict_after_secs: self.idle_evict_after.as_secs(),
            idle_evictions_total: self.idle_evictions_total.load(Ordering::Relaxed),
            lru_evictions_total: self.lru_evictions_total.load(Ordering::Relaxed),
            establish_failures_total: self.establish_failures_total.load(Ordering::Relaxed),
        }
    }

    fn enforce_lru_cap_locked(
        &self,
        inner: &mut HashMap<AntPeerId, PooledConnection>,
    ) -> Vec<AntPeerId> {
        let excess = inner.len().saturating_sub(self.max_connections);
        if excess == 0 {
            return Vec::new();
        }

        let mut entries: Vec<(AntPeerId, Instant)> = inner
            .iter()
            .map(|(peer_id, pooled)| (*peer_id, pooled.last_used))
            .collect();
        entries.sort_by_key(|(_, last_used)| *last_used);

        let mut evicted = Vec::with_capacity(excess);
        for (peer_id, _) in entries.into_iter().take(excess) {
            if inner.remove(&peer_id).is_some() {
                evicted.push(peer_id);
            }
        }
        if !evicted.is_empty() {
            self.lru_evictions_total
                .fetch_add(evicted.len() as u64, Ordering::Relaxed);
        }
        evicted
    }
}

/// Snapshot of one stream in the ant-quic → gossip receive pump.
#[derive(Debug, Clone, Serialize)]
pub struct RecvPumpStreamSnapshot {
    /// Frames observed by the receive pump for this stream.
    pub produced_total: u64,
    /// Frames successfully queued for the gossip runtime dispatcher.
    pub enqueued_total: u64,
    /// Frames dequeued by the gossip runtime dispatcher.
    pub dequeued_total: u64,
    /// Frames dropped because the bounded receive queue was full.
    pub dropped_full: u64,
    /// Recoverable control frames (IHAVE/IWANT/AntiEntropy) proactively shed
    /// while the queue was near-full, to preserve data (EAGER) delivery
    /// (ADR 0010). Distinct from `dropped_full`: an intentional, recoverable
    /// shed, not a hard data loss.
    pub shed_priority: u64,
    /// Frames dropped because the receive queue was closed.
    pub dropped_closed: u64,
    /// Most recently sampled queue depth.
    pub latest_depth: u64,
    /// Maximum sampled queue depth.
    pub max_depth: u64,
    /// Queue capacity.
    pub capacity: u64,
    /// Maximum sampled dwell time between enqueue and dequeue.
    pub max_dwell_ms: u64,
    /// Average sampled dwell time between enqueue and dequeue.
    pub avg_dwell_ms: u64,
    /// Produced frames per second since this node started.
    pub producer_per_sec: f64,
    /// Dequeued frames per second since this node started.
    pub consumer_per_sec: f64,
}

/// Per-peer producer/drop counters in the ant-quic → gossip receive pump.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RecvPumpPeerSnapshot {
    pub pubsub_produced: u64,
    pub membership_produced: u64,
    pub bulk_produced: u64,
    pub pubsub_dropped_full: u64,
    pub membership_dropped_full: u64,
    pub bulk_dropped_full: u64,
}

/// Snapshot of ant-quic → gossip receive-pump diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct RecvPumpDiagnosticsSnapshot {
    /// Seconds since the diagnostics counters were created.
    pub uptime_secs: u64,
    pub pubsub: RecvPumpStreamSnapshot,
    pub membership: RecvPumpStreamSnapshot,
    pub bulk: RecvPumpStreamSnapshot,
    pub per_peer: BTreeMap<String, RecvPumpPeerSnapshot>,
}

#[derive(Debug, Default)]
struct RecvPumpStreamDiagnostics {
    produced_total: std::sync::atomic::AtomicU64,
    enqueued_total: std::sync::atomic::AtomicU64,
    dequeued_total: std::sync::atomic::AtomicU64,
    dropped_full: std::sync::atomic::AtomicU64,
    shed_priority: std::sync::atomic::AtomicU64,
    dropped_closed: std::sync::atomic::AtomicU64,
    latest_depth: std::sync::atomic::AtomicU64,
    max_depth: std::sync::atomic::AtomicU64,
    capacity: std::sync::atomic::AtomicU64,
    max_dwell_ms: std::sync::atomic::AtomicU64,
    total_dwell_ms: std::sync::atomic::AtomicU64,
}

impl RecvPumpStreamDiagnostics {
    fn record_produced(&self, depth: usize, capacity: usize) {
        self.produced_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record_depth(depth, capacity);
    }

    fn record_enqueued(&self, depth: usize, capacity: usize) {
        self.enqueued_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record_depth(depth, capacity);
    }

    fn record_dropped_full(&self, depth: usize, capacity: usize) {
        self.dropped_full
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record_depth(depth, capacity);
    }

    fn record_shed_priority(&self, depth: usize, capacity: usize) {
        self.shed_priority
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record_depth(depth, capacity);
    }

    fn record_dropped_closed(&self, depth: usize, capacity: usize) {
        self.dropped_closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record_depth(depth, capacity);
    }

    fn record_dequeued(&self, dwell: Duration) {
        self.dequeued_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dwell_ms = duration_to_u64_ms(dwell);
        self.total_dwell_ms
            .fetch_add(dwell_ms, std::sync::atomic::Ordering::Relaxed);
        self.max_dwell_ms
            .fetch_max(dwell_ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_depth(&self, depth: usize, capacity: usize) {
        let depth = usize_to_u64_saturating(depth);
        let capacity = usize_to_u64_saturating(capacity);
        self.latest_depth
            .store(depth, std::sync::atomic::Ordering::Relaxed);
        self.max_depth
            .fetch_max(depth, std::sync::atomic::Ordering::Relaxed);
        self.capacity
            .store(capacity, std::sync::atomic::Ordering::Relaxed);
    }

    fn snapshot(&self, uptime: Duration) -> RecvPumpStreamSnapshot {
        let produced_total = self
            .produced_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let enqueued_total = self
            .enqueued_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let dequeued_total = self
            .dequeued_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let total_dwell_ms = self
            .total_dwell_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = uptime.as_secs_f64();
        let rate = |count: u64| {
            if elapsed > 0.0 {
                count as f64 / elapsed
            } else {
                0.0
            }
        };
        RecvPumpStreamSnapshot {
            produced_total,
            enqueued_total,
            dequeued_total,
            dropped_full: self.dropped_full.load(std::sync::atomic::Ordering::Relaxed),
            shed_priority: self
                .shed_priority
                .load(std::sync::atomic::Ordering::Relaxed),
            dropped_closed: self
                .dropped_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            latest_depth: self.latest_depth.load(std::sync::atomic::Ordering::Relaxed),
            max_depth: self.max_depth.load(std::sync::atomic::Ordering::Relaxed),
            capacity: self.capacity.load(std::sync::atomic::Ordering::Relaxed),
            max_dwell_ms: self.max_dwell_ms.load(std::sync::atomic::Ordering::Relaxed),
            avg_dwell_ms: total_dwell_ms.checked_div(dequeued_total).unwrap_or(0),
            producer_per_sec: rate(produced_total),
            consumer_per_sec: rate(dequeued_total),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct RecvPumpPeerCounters {
    pubsub_produced: u64,
    membership_produced: u64,
    bulk_produced: u64,
    pubsub_dropped_full: u64,
    membership_dropped_full: u64,
    bulk_dropped_full: u64,
}

impl RecvPumpPeerCounters {
    fn produced(&mut self, stream_type: GossipStreamType) {
        match stream_type {
            GossipStreamType::PubSub => {
                self.pubsub_produced = self.pubsub_produced.saturating_add(1)
            }
            GossipStreamType::Membership => {
                self.membership_produced = self.membership_produced.saturating_add(1);
            }
            GossipStreamType::Bulk => self.bulk_produced = self.bulk_produced.saturating_add(1),
        }
    }

    fn dropped_full(&mut self, stream_type: GossipStreamType) {
        match stream_type {
            GossipStreamType::PubSub => {
                self.pubsub_dropped_full = self.pubsub_dropped_full.saturating_add(1);
            }
            GossipStreamType::Membership => {
                self.membership_dropped_full = self.membership_dropped_full.saturating_add(1);
            }
            GossipStreamType::Bulk => {
                self.bulk_dropped_full = self.bulk_dropped_full.saturating_add(1);
            }
        }
    }

    fn snapshot(&self) -> RecvPumpPeerSnapshot {
        RecvPumpPeerSnapshot {
            pubsub_produced: self.pubsub_produced,
            membership_produced: self.membership_produced,
            bulk_produced: self.bulk_produced,
            pubsub_dropped_full: self.pubsub_dropped_full,
            membership_dropped_full: self.membership_dropped_full,
            bulk_dropped_full: self.bulk_dropped_full,
        }
    }
}

#[derive(Debug)]
struct RecvPumpDiagnostics {
    started_at: Instant,
    pubsub: RecvPumpStreamDiagnostics,
    membership: RecvPumpStreamDiagnostics,
    bulk: RecvPumpStreamDiagnostics,
    per_peer: Mutex<HashMap<AntPeerId, RecvPumpPeerCounters>>,
}

impl RecvPumpDiagnostics {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            pubsub: RecvPumpStreamDiagnostics::default(),
            membership: RecvPumpStreamDiagnostics::default(),
            bulk: RecvPumpStreamDiagnostics::default(),
            per_peer: Mutex::new(HashMap::new()),
        }
    }

    fn stream(&self, stream_type: GossipStreamType) -> &RecvPumpStreamDiagnostics {
        match stream_type {
            GossipStreamType::PubSub => &self.pubsub,
            GossipStreamType::Membership => &self.membership,
            GossipStreamType::Bulk => &self.bulk,
        }
    }

    fn record_produced(
        &self,
        peer_id: AntPeerId,
        stream_type: GossipStreamType,
        depth: usize,
        capacity: usize,
    ) {
        self.stream(stream_type).record_produced(depth, capacity);
        self.with_peer(peer_id, |peer| peer.produced(stream_type));
    }

    fn record_enqueued(&self, stream_type: GossipStreamType, depth: usize, capacity: usize) {
        self.stream(stream_type).record_enqueued(depth, capacity);
    }

    fn record_dropped_full(
        &self,
        peer_id: AntPeerId,
        stream_type: GossipStreamType,
        depth: usize,
        capacity: usize,
    ) {
        self.stream(stream_type)
            .record_dropped_full(depth, capacity);
        self.with_peer(peer_id, |peer| peer.dropped_full(stream_type));
    }

    fn record_shed_priority(&self, stream_type: GossipStreamType, depth: usize, capacity: usize) {
        self.stream(stream_type)
            .record_shed_priority(depth, capacity);
    }

    fn record_dropped_closed(&self, stream_type: GossipStreamType, depth: usize, capacity: usize) {
        self.stream(stream_type)
            .record_dropped_closed(depth, capacity);
    }

    fn record_dequeued(&self, stream_type: GossipStreamType, dwell: Duration) {
        self.stream(stream_type).record_dequeued(dwell);
    }

    fn snapshot(&self) -> RecvPumpDiagnosticsSnapshot {
        let uptime = self.started_at.elapsed();
        let per_peer = match self.per_peer.lock() {
            Ok(guard) => guard
                .iter()
                .map(|(peer_id, counters)| (hex::encode(peer_id.0), counters.snapshot()))
                .collect(),
            Err(e) => {
                error!("receive pump peer diagnostics poisoned: {e}");
                BTreeMap::new()
            }
        };
        RecvPumpDiagnosticsSnapshot {
            uptime_secs: uptime.as_secs(),
            pubsub: self.pubsub.snapshot(uptime),
            membership: self.membership.snapshot(uptime),
            bulk: self.bulk.snapshot(uptime),
            per_peer,
        }
    }

    fn with_peer(&self, peer_id: AntPeerId, update: impl FnOnce(&mut RecvPumpPeerCounters)) {
        match self.per_peer.try_lock() {
            Ok(mut guard) => update(guard.entry(peer_id).or_default()),
            Err(TryLockError::WouldBlock) => {
                // Per-peer counters are diagnostics only; never let them become
                // a new receive-pump choke point under the saturation they are
                // meant to measure.
            }
            Err(TryLockError::Poisoned(e)) => error!("receive pump peer diagnostics poisoned: {e}"),
        }
    }
}

impl Default for RecvPumpDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

fn duration_to_u64_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .ok()
        .map_or(u64::MAX, |v| v)
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).ok().map_or(u64::MAX, |v| v)
}

/// Stream type byte for direct messages (distinct from gossip: 0, 1, 2).
pub const DIRECT_MESSAGE_STREAM_TYPE: u8 = 0x10;

const CHANNEL_PRESSURE_INFO_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ChannelPressureKey {
    channel_name: &'static str,
    stream_name: &'static str,
}

#[derive(Debug, Default)]
struct ChannelPressureInfoLimiter {
    last_info_at: Mutex<HashMap<ChannelPressureKey, Instant>>,
}

impl ChannelPressureInfoLimiter {
    fn should_emit(&self, key: ChannelPressureKey, now: Instant, interval: Duration) -> bool {
        match self.last_info_at.lock() {
            Ok(mut guard) => {
                let should_emit = guard
                    .get(&key)
                    .is_none_or(|last| now.saturating_duration_since(*last) >= interval);
                if should_emit {
                    guard.insert(key, now);
                }
                should_emit
            }
            Err(e) => {
                error!("receive forward pressure info limiter poisoned: {e}");
                true
            }
        }
    }
}

static CHANNEL_PRESSURE_INFO_LIMITER: OnceLock<ChannelPressureInfoLimiter> = OnceLock::new();
static CHANNEL_PRESSURE_WARN_LIMITER: OnceLock<ChannelPressureInfoLimiter> = OnceLock::new();
static CHANNEL_DROP_WARN_LIMITER: OnceLock<ChannelPressureInfoLimiter> = OnceLock::new();

fn channel_pressure_info_limiter() -> &'static ChannelPressureInfoLimiter {
    CHANNEL_PRESSURE_INFO_LIMITER.get_or_init(ChannelPressureInfoLimiter::default)
}

/// Rate limiter for the per-call ">80% full" pressure WARN.
///
/// Before ADR 0009 the producer was back-pressured by `mpsc::Sender::send().await`,
/// which naturally bounded the WARN call rate to roughly the consumer drain rate.
/// Under the new `try_send` policy on PubSub the producer is no longer throttled,
/// so a sustained slow-consumer event would fire this WARN once per
/// `forward_gossip_payload` call (i.e. at producer rate). The pressure WARN is
/// kept as the operator cue but is now rate-limited per (channel, stream) so it
/// surfaces a regime change rather than spamming the journal under steady
/// pressure. The authoritative steady-state signals are
/// `recv_pump.<stream>.{producer_per_sec, consumer_per_sec, max_depth, dropped_full}`.
fn channel_pressure_warn_limiter() -> &'static ChannelPressureInfoLimiter {
    CHANNEL_PRESSURE_WARN_LIMITER.get_or_init(ChannelPressureInfoLimiter::default)
}

/// Rate limiter for the per-frame "dropping PubSub frame" WARN.
///
/// Without rate-limiting, the drop WARN fires once per dropped frame at the
/// producer rate. Under sustained PubSub saturation that produces tens of
/// drops per second per peer, the WARN volume itself becomes an operational
/// problem — journald takes the brunt and the authoritative `dropped_full`
/// counter signal is buried in noise. The actual operator signal is the
/// counter; the WARN is just a "look here" cue and should be sparse.
fn channel_drop_warn_limiter() -> &'static ChannelPressureInfoLimiter {
    CHANNEL_DROP_WARN_LIMITER.get_or_init(ChannelPressureInfoLimiter::default)
}

fn channel_pressure_key(
    channel_name: &'static str,
    stream_type: Option<GossipStreamType>,
) -> ChannelPressureKey {
    let stream_name = match stream_type {
        Some(GossipStreamType::PubSub) => "pubsub",
        Some(GossipStreamType::Membership) => "membership",
        Some(GossipStreamType::Bulk) => "bulk",
        None => "none",
    };
    ChannelPressureKey {
        channel_name,
        stream_name,
    }
}

fn channel_pressure_exceeds_half(available: usize, max: usize) -> bool {
    available.saturating_mul(2) < max
}

fn channel_pressure_exceeds_warn_threshold(available: usize, max: usize) -> bool {
    available.saturating_mul(5) < max
}

/// True when the PubSub forward channel is more than 90% full, i.e.
/// `available < max/10` (on the production 10k channel that is >9000 used; on
/// small channels integer rounding makes it slightly stricter). Above this the
/// recv pump proactively sheds recoverable control frames (IHAVE/IWANT/AntiEntropy)
/// before they consume the last slots, preserving data (EAGER) delivery
/// (ADR 0010). Refines ADR 0009's flat PubSub try_send/drop policy into a
/// priority-aware shed; the kind-peek is gated on this threshold so the
/// steady-state hot path pays no decode cost.
fn channel_pressure_exceeds_shed_threshold(available: usize, max: usize) -> bool {
    available.saturating_mul(10) < max
}

/// ADR 0010: PubSub frame kinds that are safe to shed under near-overload
/// because they are recoverable by PlumTree's lazy-push recovery. EAGER (data)
/// and tree-maintenance frames (Prune/Graft) are never shed here.
fn is_pubsub_shed_eligible(kind: saorsa_gossip_types::MessageKind) -> bool {
    use saorsa_gossip_types::MessageKind;
    matches!(
        kind,
        MessageKind::IHave | MessageKind::IWant | MessageKind::AntiEntropy
    )
}

fn channel_depth<T>(tx: &mpsc::Sender<T>) -> usize {
    tx.max_capacity().saturating_sub(tx.capacity())
}

/// The x0x network node.
///
/// This wraps ant-quic's Node with x0x-specific functionality
/// including peer cache management and configuration.
fn warn_forward_channel_pressure<T>(
    tx: &mpsc::Sender<T>,
    peer_id: AntPeerId,
    stream_type: Option<GossipStreamType>,
    channel_name: &'static str,
) {
    let available = tx.capacity();
    let max = tx.max_capacity();
    let used = max.saturating_sub(available);
    let used_pct = (used.saturating_mul(100)) / max.max(1);
    if channel_pressure_exceeds_half(available, max)
        && channel_pressure_info_limiter().should_emit(
            channel_pressure_key(channel_name, stream_type),
            Instant::now(),
            CHANNEL_PRESSURE_INFO_INTERVAL,
        )
    {
        info!(
            available,
            used,
            max,
            used_pct,
            peer = ?peer_id,
            stream = ?stream_type,
            channel = channel_name,
            "[1/6 network] receive forward channel >50% full — watch back-pressure trend before ant-quic recv drain"
        );
    }
    if channel_pressure_exceeds_warn_threshold(available, max)
        && channel_pressure_warn_limiter().should_emit(
            channel_pressure_key(channel_name, stream_type),
            Instant::now(),
            CHANNEL_PRESSURE_INFO_INTERVAL,
        )
    {
        warn!(
            available,
            used,
            max,
            used_pct,
            peer = %crate::logging::LogTransportPeerId::from(&peer_id),
            stream = ?stream_type,
            channel = channel_name,
            "[1/6 network] receive forward channel >80% full — back-pressure active before ant-quic recv drain (rate-limited; see recv_pump.<stream>.{{producer_per_sec, consumer_per_sec, max_depth, dropped_full}} for steady-state)"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardGossipOutcome {
    Enqueued,
    DroppedFull,
    /// A recoverable PubSub control frame was proactively shed under
    /// near-overload to preserve EAGER delivery (ADR 0010). Like
    /// `DroppedFull`, the recv pump skips it; counted in `shed_priority`.
    Shed,
}

async fn forward_gossip_payload(
    tx: &mpsc::Sender<GossipPayload>,
    peer_id: AntPeerId,
    stream_type: GossipStreamType,
    payload: Bytes,
    channel_name: &'static str,
    diagnostics: &RecvPumpDiagnostics,
) -> Result<ForwardGossipOutcome, mpsc::error::SendError<GossipPayload>> {
    warn_forward_channel_pressure(tx, peer_id, Some(stream_type), channel_name);
    let max = tx.max_capacity();
    diagnostics.record_produced(peer_id, stream_type, channel_depth(tx), max);
    let message = GossipPayload {
        peer_id,
        data: payload,
        enqueued_at: Instant::now(),
    };

    if stream_type == GossipStreamType::PubSub {
        // ADR 0010: under near-overload (>90% full, available < max/10), proactively shed
        // recoverable control frames (IHAVE/IWANT/AntiEntropy) so the last
        // slots stay available for data (EAGER). The kind-peek is gated on the
        // shed threshold, so the steady-state path keeps ADR 0009's flat
        // try_send behavior with no decode cost.
        if channel_pressure_exceeds_shed_threshold(tx.capacity(), max)
            && saorsa_gossip_pubsub::peek_message_kind(&message.data)
                .is_some_and(is_pubsub_shed_eligible)
        {
            let depth = channel_depth(tx);
            diagnostics.record_shed_priority(stream_type, depth, max);
            if channel_drop_warn_limiter().should_emit(
                channel_pressure_key(channel_name, Some(stream_type)),
                Instant::now(),
                CHANNEL_PRESSURE_INFO_INTERVAL,
            ) {
                warn!(
                    peer = %crate::logging::LogTransportPeerId::from(&peer_id),
                    stream = ?stream_type,
                    channel = channel_name,
                    depth,
                    max,
                    "[1/6 network] shedding recoverable PubSub control frame (channel >90% full) to preserve EAGER delivery (ADR 0010; rate-limited; see recv_pump.pubsub.shed_priority)"
                );
            }
            return Ok(ForwardGossipOutcome::Shed);
        }
        return match tx.try_send(message) {
            Ok(()) => {
                diagnostics.record_enqueued(stream_type, channel_depth(tx), max);
                Ok(ForwardGossipOutcome::Enqueued)
            }
            Err(mpsc::error::TrySendError::Full(_message)) => {
                let depth = channel_depth(tx);
                diagnostics.record_dropped_full(peer_id, stream_type, depth, max);
                if channel_drop_warn_limiter().should_emit(
                    channel_pressure_key(channel_name, Some(stream_type)),
                    Instant::now(),
                    CHANNEL_PRESSURE_INFO_INTERVAL,
                ) {
                    let dropped_full = diagnostics
                        .pubsub
                        .dropped_full
                        .load(std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        peer = %crate::logging::LogTransportPeerId::from(&peer_id),
                        stream = ?stream_type,
                        channel = channel_name,
                        depth,
                        max,
                        dropped_full,
                        "[1/6 network] dropping PubSub frame because receive forward channel is full (rate-limited; see recv_pump.pubsub.dropped_full for total)"
                    );
                }
                Ok(ForwardGossipOutcome::DroppedFull)
            }
            Err(mpsc::error::TrySendError::Closed(message)) => {
                diagnostics.record_dropped_closed(stream_type, channel_depth(tx), max);
                Err(mpsc::error::SendError(message))
            }
        };
    }

    match tx.send(message).await {
        Ok(()) => {
            diagnostics.record_enqueued(stream_type, channel_depth(tx), max);
            Ok(ForwardGossipOutcome::Enqueued)
        }
        Err(e) => {
            diagnostics.record_dropped_closed(stream_type, channel_depth(tx), max);
            Err(e)
        }
    }
}

async fn disconnect_pool_candidates(
    node: &Node,
    event_sender: &broadcast::Sender<NetworkEvent>,
    connection_pool: &ConnectionPool,
    peer_ids: Vec<AntPeerId>,
    reason: &'static str,
) {
    for peer_id in peer_ids {
        match node.disconnect(&peer_id).await {
            Ok(()) => {
                connection_pool.record_disconnected(&peer_id);
                let _ = event_sender.send(NetworkEvent::PeerDisconnected { peer_id: peer_id.0 });
                tracing::info!(
                    target: "x0x::connect",
                    peer_id_prefix = %hex_prefix(&peer_id.0, 4),
                    reason,
                    "connection pool evicted peer"
                );
            }
            Err(e) => {
                connection_pool.record_disconnected(&peer_id);
                tracing::debug!(
                    target: "x0x::connect",
                    peer_id_prefix = %hex_prefix(&peer_id.0, 4),
                    reason,
                    error = %e,
                    "connection pool eviction could not disconnect peer"
                );
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkNode {
    /// ant-quic P2P node (wrapped in `Arc<RwLock>` for shared async access).
    node: Arc<RwLock<Option<Node>>>,
    /// Configuration for this node.
    config: NetworkConfig,
    /// Sender for broadcasting network events.
    event_sender: broadcast::Sender<NetworkEvent>,
    /// Receiver channel for PubSub gossip messages.
    recv_pubsub_tx: mpsc::Sender<GossipPayload>,
    recv_pubsub_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<GossipPayload>>>,
    /// Receiver channel for membership gossip messages.
    recv_membership_tx: mpsc::Sender<GossipPayload>,
    recv_membership_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<GossipPayload>>>,
    /// Receiver channel for Bulk gossip messages (presence beacons).
    recv_bulk_tx: mpsc::Sender<GossipPayload>,
    recv_bulk_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<GossipPayload>>>,
    /// Diagnostics for the ant-quic → gossip receive pump.
    recv_pump_diagnostics: Arc<RecvPumpDiagnostics>,
    /// Receiver channel for direct messages (separate from gossip).
    direct_tx: mpsc::Sender<(AntPeerId, Bytes)>,
    direct_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(AntPeerId, Bytes)>>>,
    /// Cached local peer ID (ant-quic PeerId).
    peer_id: AntPeerId,
    /// Bootstrap peer cache for recording connection outcomes.
    bootstrap_cache: Option<Arc<ant_quic::BootstrapCache>>,
    /// x0x-side connection pool tracking activity, caps, and idle eviction.
    connection_pool: Arc<ConnectionPool>,
    /// Per-peer liveness repair locks. Prevents concurrent fanout and
    /// maintenance tasks from repeatedly disconnecting/reconnecting the same
    /// stale connection.
    liveness_locks: Arc<Mutex<HashMap<AntPeerId, Arc<tokio::sync::Mutex<()>>>>>,
    /// Last time a peer completed an app-level liveness check or reconnect.
    liveness_last_ready: Arc<Mutex<HashMap<AntPeerId, Instant>>>,
    /// Daemon-local cap for concurrent pre-send probe/reconnect work.
    liveness_repair_semaphore: Arc<Semaphore>,
    /// Handles to the background tasks spawned at construction (receiver, accept
    /// loop, connection-pool eviction).
    ///
    /// Tracked so [`shutdown`] can abort them: the receiver and accept loops park
    /// in `node.recv()/accept().await` while holding a *read* guard on `node`, so
    /// they must be aborted before `shutdown` can take the *write* lock to drop
    /// the node. Without this, `shutdown` would deadlock on an idle node that
    /// never receives another packet/connection. (Note: ant-quic frees the bound
    /// UDP socket only on process exit — saorsa-labs/ant-quic#196.)
    background_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl NetworkNode {
    /// Create a new network node with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Network configuration options.
    /// * `bootstrap_cache` - Optional bootstrap peer cache for quality-scored reconnection.
    /// * `keypair` - Optional ML-DSA-65 keypair for identity unification. When provided,
    ///   the ant-quic `Node` uses this keypair for QUIC TLS, making the transport PeerId
    ///   equal to the x0x MachineId derived from the same key.
    ///
    /// # Returns
    ///
    /// A new NetworkNode on success.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if node creation fails.
    pub async fn new(
        config: NetworkConfig,
        bootstrap_cache: Option<Arc<ant_quic::BootstrapCache>>,
        keypair: Option<(ant_quic::MlDsaPublicKey, ant_quic::MlDsaSecretKey)>,
    ) -> NetworkResult<Self> {
        let mut builder = NodeConfig::builder()
            // Mitigation, not a correctness fix: give ant-quic's bounded
            // app-facing recv queue enough headroom to match x0x's forwarding
            // queues during explicit raw receive-ACK stress. This trades memory
            // for fewer ACK-starvation false negatives; the forwarding channel
            // pressure warnings below are the operator signal that the system is
            // leaning on this buffer and needs load shedding or a structural
            // recv-pump fix.
            //
            // X0X-0063 bumped this from 10_000 → 50_000 after the 4 h
            // confirmatory soak on x0x 0.19.35 (sg 0.5.40, ant-quic 0.27.15)
            // recorded **1,025,150 high_water_count events on nyc** —
            // saturation occurring continuously at ~67/s. The 10_000 ceiling
            // was insufficient once X0X-0061 bumped the saorsa-gossip
            // PER_PEER_REPUBLISH_TIMEOUT 750 ms → 2500 ms, because each
            // outbound send task now holds a data_tx slot for up to 2.5 s
            // (3.3× the prior hold time). 50_000 gives proportional headroom.
            // This remains a mitigation — under truly sustained overload
            // backpressure earlier in the pubsub flush_ihave_batches loop is
            // the proper fix.
            .data_channel_capacity(50_000)
            .max_concurrent_uni_streams(50_000);

        if let Some(bind_addr) = config.bind_addr {
            builder = builder.bind_addr(bind_addr);
        }

        for peer_addr in &config.bootstrap_nodes {
            builder = builder.known_peer(*peer_addr);
        }

        // Pass the machine keypair to ant-quic so that transport PeerId == MachineId
        if let Some((pk, sk)) = keypair {
            builder = builder.keypair(pk, sk);
        }

        // X0X-0062 reviewer P2 #2: surface ant-quic's best-effort UPnP
        // port-mapping toggle so operators on networks without IGD support
        // (or with policy against it) can disable it via `NetworkConfig`
        // (and downstream via the daemon's config TOML / CLI flag).
        builder = builder.port_mapping_enabled(config.port_mapping_enabled);

        let node = Node::with_config(builder.build()).await.map_err(|e| {
            NetworkError::NodeCreation(format!("Failed to create ant-quic node: {}", e))
        })?;

        let peer_id = node.peer_id();
        let (event_sender, _event_receiver) = broadcast::channel(32);
        // Inbound gossip buffers are split by stream type so PubSub back-pressure
        // cannot block Bulk presence beacons or Membership/SWIM control traffic.
        // PubSub keeps the historical 10k capacity to match subscription buffers;
        // lower-volume control streams use smaller dedicated queues.
        let (recv_pubsub_tx, recv_pubsub_rx) = mpsc::channel(GOSSIP_PUBSUB_RECV_CAPACITY);
        let (recv_membership_tx, recv_membership_rx) = mpsc::channel(GOSSIP_CONTROL_RECV_CAPACITY);
        let (recv_bulk_tx, recv_bulk_rx) = mpsc::channel(GOSSIP_CONTROL_RECV_CAPACITY);
        let (direct_tx, direct_rx) = mpsc::channel(10_000);
        let recv_pump_diagnostics = Arc::new(RecvPumpDiagnostics::new());
        let pool_max_connections = if config.max_connections == 0 {
            DEFAULT_MAX_CONNECTIONS as usize
        } else {
            config.max_connections as usize
        };
        let connection_pool = Arc::new(ConnectionPool::new(
            pool_max_connections,
            CONNECTION_POOL_IDLE_EVICT_AFTER,
        ));

        let network_node = Self {
            node: Arc::new(RwLock::new(Some(node))),
            config,
            event_sender,
            recv_pubsub_tx,
            recv_pubsub_rx: Arc::new(tokio::sync::Mutex::new(recv_pubsub_rx)),
            recv_membership_tx,
            recv_membership_rx: Arc::new(tokio::sync::Mutex::new(recv_membership_rx)),
            recv_bulk_tx,
            recv_bulk_rx: Arc::new(tokio::sync::Mutex::new(recv_bulk_rx)),
            recv_pump_diagnostics,
            direct_tx,
            direct_rx: Arc::new(tokio::sync::Mutex::new(direct_rx)),
            peer_id,
            bootstrap_cache,
            connection_pool,
            liveness_locks: Arc::new(Mutex::new(HashMap::new())),
            liveness_last_ready: Arc::new(Mutex::new(HashMap::new())),
            liveness_repair_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_LIVENESS_REPAIRS)),
            background_tasks: Arc::new(Mutex::new(Vec::new())),
        };

        let receiver = network_node.spawn_receiver();
        let accept = network_node.spawn_accept_loop();
        let eviction = network_node.spawn_connection_pool_eviction();
        // Record the handles so `shutdown` can abort them (letting it take the
        // node write lock and shut the node down without deadlocking). This runs
        // at construction before the node is shared, so there is no contention;
        // if the lock is somehow poisoned, recover the guard rather than panic
        // (the handles are only used for clean teardown).
        match network_node.background_tasks.lock() {
            Ok(mut tasks) => tasks.extend([receiver, accept, eviction]),
            Err(poisoned) => poisoned.into_inner().extend([receiver, accept, eviction]),
        }

        Ok(network_node)
    }

    /// Get the configuration for this node.
    ///
    /// # Returns
    ///
    /// A reference to the network configuration.
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Get the configured bind address (may contain port 0 before binding).
    ///
    /// # Returns
    ///
    /// The bind address from config. Note: if the config specifies port 0,
    /// this returns port 0. Use `bound_addr()` for the real OS-assigned port.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.config.bind_addr
    }

    /// Get the actual bound address from the QUIC endpoint.
    ///
    /// Unlike `local_addr()` which returns the config value (possibly port 0),
    /// this queries the running endpoint for the real OS-assigned address.
    /// Falls back to the config bind address if the endpoint is unavailable.
    pub async fn bound_addr(&self) -> Option<SocketAddr> {
        if let Some(status) = self.node_status().await {
            Some(status.local_addr)
        } else {
            self.config.bind_addr
        }
    }

    /// Get the external address as observed by remote peers.
    ///
    /// Returns `None` until at least one connection has completed and the
    /// remote peer has reported our address via OBSERVED_ADDRESS frames.
    pub async fn external_addr(&self) -> Option<SocketAddr> {
        let node_guard = self.node.read().await;
        node_guard.as_ref().and_then(|n| n.external_addr())
    }

    /// Get the best routable address for advertising to other peers.
    ///
    /// Prefers the external (observed) address over the local bind address.
    /// Filters out unroutable addresses (unspecified IP or port 0).
    pub async fn routable_addr(&self) -> Option<SocketAddr> {
        // Prefer observed external address
        if let Some(addr) = self.external_addr().await {
            return Some(addr);
        }
        // Fall back to the real bound address (resolves OS-assigned ports),
        // then to the config bind address. Either way, reject unspecified
        // IPs and port 0 — those are not connectable.
        let addr = self.bound_addr().await?;
        if addr.ip().is_unspecified() || addr.port() == 0 {
            return None;
        }
        Some(addr)
    }

    /// Get the full node status from ant-quic, including NAT type,
    /// external addresses, connection stats, and relay/coordinator state.
    pub async fn node_status(&self) -> Option<ant_quic::NodeStatus> {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.status().await)
    }

    /// Snapshot ACK-v2 per-stage latency and outcome diagnostics.
    pub async fn ack_diagnostics(&self) -> Option<ant_quic::AckDiagnosticsSnapshot> {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.ack_diagnostics())
    }

    /// Snapshot `data_tx` channel saturation diagnostics (X0X-0039).
    ///
    /// Surfaces depth, capacity, and cumulative high-water-count for the
    /// shared `mpsc::Sender` fed by every per-connection reader task.
    /// Returns `None` when the network node is not yet initialised.
    pub async fn data_channel_diagnostics(
        &self,
    ) -> Option<ant_quic::DataChannelDiagnosticsSnapshot> {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.data_channel_diagnostics())
    }

    /// Snapshot GSO bundle send diagnostics (X0X-0043).
    ///
    /// Returns cumulative counts of multi-segment GSO bundles submitted to
    /// the kernel send path and of bundles reported as partial / failed.
    /// Returns `None` when the network node is not yet initialised.
    pub async fn gso_diagnostics(&self) -> Option<ant_quic::GsoDiagnosticsSnapshot> {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.gso_diagnostics())
    }

    /// Active liveness probe for a peer (ant-quic 0.27.2 #173).
    ///
    /// Sends a lightweight probe envelope, waits for the remote reader's
    /// ACK-v1 reply, and returns measured RTT. Invisible to the recv pipeline.
    /// Returns `None` when the network node is not yet initialised.
    pub async fn probe_peer(
        &self,
        peer_id: AntPeerId,
        timeout: std::time::Duration,
    ) -> Option<Result<std::time::Duration, ant_quic::NodeError>> {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.probe_peer(&peer_id, timeout).await)
    }

    /// Best-effort connection health snapshot for a peer (ant-quic 0.27.1 #170).
    pub async fn connection_health(
        &self,
        peer_id: AntPeerId,
    ) -> Option<ant_quic::ConnectionHealth> {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.connection_health(&peer_id).await)
    }

    /// X0X-0075 Part C wiring: qlog-style transport telemetry for a live peer.
    /// Companion to `connection_health` — health answers "is the lifecycle
    /// live?", this snapshot answers "how is the path performing right now?".
    /// Returns `None` when the network node is not yet initialised or the
    /// peer has no live connection.
    pub async fn connection_transport_stats(
        &self,
        peer_id: AntPeerId,
    ) -> Option<ant_quic::ConnectionTransportStats> {
        let node = self.node.read().await.as_ref().cloned()?;
        node.connection_transport_stats(&peer_id).await
    }

    /// Send data and wait for the remote receive pipeline to acknowledge
    /// (ant-quic 0.27.1 #172). Returns `None` when the network node is not
    /// yet initialised.
    pub async fn send_with_receive_ack(
        &self,
        peer_id: AntPeerId,
        data: &[u8],
        timeout: std::time::Duration,
    ) -> Option<Result<(), ant_quic::NodeError>> {
        if let Err(e) = self.get_or_connect_pooled_peer(&peer_id).await {
            return Some(Err(ant_quic::NodeError::Connection(e.to_string())));
        }
        let node = self.node.read().await.as_ref().cloned()?;
        let result = node.send_with_receive_ack(&peer_id, data, timeout).await;
        if result.is_ok() {
            self.note_connection_pool_activity(peer_id).await;
        }
        Some(result)
    }

    /// Subscribe to lifecycle events for all peers (ant-quic 0.27.1 #171).
    pub async fn subscribe_all_peer_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<(ant_quic::PeerId, ant_quic::PeerLifecycleEvent)>>
    {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.subscribe_all_peer_events())
    }

    /// Get current network statistics.
    ///
    /// # Returns
    ///
    /// Network statistics for this node.
    pub async fn stats(&self) -> NetworkStats {
        let Some(node) = self.node.read().await.as_ref().cloned() else {
            return NetworkStats::default();
        };
        let status = node.status().await;
        NetworkStats {
            total_connections: status.direct_connections + status.relayed_connections,
            active_connections: status.active_connections as u32,
            bytes_sent: status.relay_bytes_forwarded,
            bytes_received: 0, // TODO: Track in future
            peer_count: status.connected_peers,
        }
    }

    /// Get the number of active connections.
    ///
    /// # Returns
    ///
    /// The number of currently connected peers.
    pub async fn connection_count(&self) -> usize {
        let Some(node) = self.node.read().await.as_ref().cloned() else {
            return 0;
        };
        node.status().await.connected_peers
    }

    /// Subscribe to network events.
    ///
    /// Returns a receiver that will receive all network events
    /// including peer connections, disconnections, and errors.
    ///
    /// # Returns
    ///
    /// A receiver for network events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_sender.subscribe()
    }

    /// Emit a network event to all subscribers.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to emit.
    pub fn emit_event(&self, event: NetworkEvent) {
        let _ = self.event_sender.send(event);
    }

    /// Snapshot x0x-side connection-pool diagnostics.
    #[must_use]
    pub fn connection_pool_diagnostics(&self) -> ConnectionPoolDiagnosticsSnapshot {
        self.connection_pool.snapshot()
    }

    async fn note_connection_pool_activity(&self, peer_id: AntPeerId) {
        let evicted = self.connection_pool.note_activity(peer_id);
        self.disconnect_pool_candidates(evicted, "lru").await;
    }

    async fn get_or_connect_pooled_peer(&self, peer_id: &AntPeerId) -> NetworkResult<()> {
        if let Err(e) = self.ensure_peer_send_ready(peer_id).await {
            self.connection_pool.record_establish_failure();
            return Err(e);
        }
        self.note_connection_pool_activity(*peer_id).await;
        Ok(())
    }

    async fn disconnect_pool_candidates(&self, peer_ids: Vec<AntPeerId>, reason: &'static str) {
        if peer_ids.is_empty() {
            return;
        }

        let Some(node) = self.node.read().await.as_ref().cloned() else {
            return;
        };
        disconnect_pool_candidates(
            &node,
            &self.event_sender,
            &self.connection_pool,
            peer_ids,
            reason,
        )
        .await;
    }

    async fn connected_peer_snapshot(
        &self,
        peer_id: &AntPeerId,
    ) -> Option<(Option<SocketAddr>, Duration)> {
        let node = self.require_node().await.ok()?;
        let now = Instant::now();
        node.connected_peers()
            .await
            .into_iter()
            .find(|conn| conn.peer_id == *peer_id)
            .map(|conn| {
                let addr = match conn.remote_addr {
                    TransportAddr::Udp(addr) => Some(addr),
                    _ => None,
                };
                (addr, now.saturating_duration_since(conn.last_activity))
            })
    }

    fn peer_needs_pre_send_probe(
        health: &ant_quic::ConnectionHealth,
        idle_for: Duration,
        last_ready_elapsed: Option<Duration>,
    ) -> bool {
        if !health.connected || health.reader_task_active != Some(true) {
            return true;
        }
        if last_ready_elapsed.is_some_and(|elapsed| elapsed < PRE_SEND_LIVENESS_COOLDOWN) {
            return false;
        }
        idle_for >= PRE_SEND_LIVENESS_IDLE_THRESHOLD
    }

    async fn refresh_peer_connection(
        &self,
        peer_id: &AntPeerId,
        fallback_addr: Option<SocketAddr>,
        reason: String,
    ) -> NetworkResult<()> {
        tracing::warn!(
            target: "x0x::connect",
            peer_id_prefix = %crate::logging::LogTransportPeerId::from(peer_id),
            fallback_addr = ?fallback_addr
                .map(|a| crate::logging::LogHexId::addr(&a.to_string()).to_string()),
            reason,
            "refreshing peer connection before send"
        );

        if self.is_connected(peer_id).await {
            if let Err(e) = self.disconnect(peer_id).await {
                tracing::debug!(
                    target: "x0x::connect",
                    peer_id_prefix = %hex_prefix(&peer_id.0, 4),
                    error = %e,
                    "disconnect before peer refresh failed; continuing with reconnect"
                );
            }
        }

        let cache_result = tokio::time::timeout(
            PRE_SEND_RECONNECT_TIMEOUT,
            self.connect_cached_peer(*peer_id),
        )
        .await;

        match cache_result {
            Ok(Ok(_)) => Ok(()),
            Err(_) => {
                let Some(addr) = fallback_addr else {
                    return Err(NetworkError::ConnectionTimeout {
                        peer_id: peer_id.0,
                        timeout: PRE_SEND_RECONNECT_TIMEOUT,
                    });
                };

                match tokio::time::timeout(PRE_SEND_RECONNECT_TIMEOUT, self.connect_addr(addr))
                    .await
                {
                    Ok(Ok(connected_peer)) if connected_peer == *peer_id => Ok(()),
                    Ok(Ok(connected_peer)) => Err(NetworkError::ConnectionFailed(format!(
                        "peer refresh at {addr} connected to unexpected peer {:?}",
                        connected_peer
                    ))),
                    Ok(Err(addr_err)) => Err(NetworkError::ConnectionFailed(format!(
                        "peer refresh timed out via cache after {:?} and fallback {addr} failed ({addr_err})",
                        PRE_SEND_RECONNECT_TIMEOUT
                    ))),
                    Err(_) => Err(NetworkError::ConnectionTimeout {
                        peer_id: peer_id.0,
                        timeout: PRE_SEND_RECONNECT_TIMEOUT,
                    }),
                }
            }
            Ok(Err(cache_err)) => {
                let Some(addr) = fallback_addr else {
                    return Err(cache_err);
                };

                match tokio::time::timeout(PRE_SEND_RECONNECT_TIMEOUT, self.connect_addr(addr))
                    .await
                {
                    Ok(Ok(connected_peer)) if connected_peer == *peer_id => Ok(()),
                    Ok(Ok(connected_peer)) => Err(NetworkError::ConnectionFailed(format!(
                        "peer refresh at {addr} connected to unexpected peer {:?}",
                        connected_peer
                    ))),
                    Ok(Err(addr_err)) => Err(NetworkError::ConnectionFailed(format!(
                        "peer refresh failed via cache ({cache_err}) and fallback {addr} ({addr_err})"
                    ))),
                    Err(_) => Err(NetworkError::ConnectionTimeout {
                        peer_id: peer_id.0,
                        timeout: PRE_SEND_RECONNECT_TIMEOUT,
                    }),
                }
            }
        }
    }

    fn liveness_lock_for_peer(
        &self,
        peer_id: AntPeerId,
    ) -> NetworkResult<Arc<tokio::sync::Mutex<()>>> {
        let mut locks = self.liveness_locks.lock().map_err(|_| {
            NetworkError::NodeCreation("peer liveness lock map poisoned".to_string())
        })?;
        Ok(locks
            .entry(peer_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone())
    }

    fn maybe_remove_liveness_lock(&self, peer_id: &AntPeerId, lock: &Arc<tokio::sync::Mutex<()>>) {
        if Arc::strong_count(lock) > 2 {
            return;
        }
        let Ok(mut locks) = self.liveness_locks.lock() else {
            return;
        };
        if Arc::strong_count(lock) > 2 {
            return;
        }
        let should_remove = match locks.get(peer_id) {
            Some(stored) => Arc::ptr_eq(stored, lock),
            None => false,
        };
        if should_remove {
            locks.remove(peer_id);
        }
    }

    fn peer_liveness_ready_elapsed(&self, peer_id: &AntPeerId) -> NetworkResult<Option<Duration>> {
        let ready = self.liveness_last_ready.lock().map_err(|_| {
            NetworkError::NodeCreation("peer liveness cooldown map poisoned".to_string())
        })?;
        let now = Instant::now();
        Ok(ready
            .get(peer_id)
            .map(|last_ready| now.saturating_duration_since(*last_ready)))
    }

    fn remember_peer_send_ready(&self, peer_id: AntPeerId) -> NetworkResult<()> {
        let mut ready = self.liveness_last_ready.lock().map_err(|_| {
            NetworkError::NodeCreation("peer liveness cooldown map poisoned".to_string())
        })?;
        let now = Instant::now();
        if ready.len() >= LIVENESS_STATE_MAX_PEERS && !ready.contains_key(&peer_id) {
            ready.retain(|_, last_ready| {
                now.saturating_duration_since(*last_ready) <= PRE_SEND_LIVENESS_COOLDOWN
            });
            if ready.len() >= LIVENESS_STATE_MAX_PEERS {
                return Ok(());
            }
        }
        ready.insert(peer_id, now);
        Ok(())
    }

    async fn peer_needs_send_readiness_repair(&self, peer_id: &AntPeerId) -> NetworkResult<bool> {
        let Some((_fallback_addr, idle_for)) = self.connected_peer_snapshot(peer_id).await else {
            return Ok(true);
        };

        let health = self
            .connection_health(*peer_id)
            .await
            .ok_or_else(|| NetworkError::NodeCreation("Node not initialized".to_string()))?;
        let last_ready_elapsed = self.peer_liveness_ready_elapsed(peer_id)?;
        Ok(Self::peer_needs_pre_send_probe(
            &health,
            idle_for,
            last_ready_elapsed,
        ))
    }

    /// Drive a bounded single-flight readiness repair for a peer.
    ///
    /// Called from both gossip and raw-DM send paths when the peer's
    /// connection looks idle, broken, or absent. Per-peer mutex
    /// (`liveness_lock_for_peer`) plus a global semaphore
    /// (`liveness_repair_semaphore`, see X0X-0031) keep concurrent fanout from
    /// stampeding the same peer with simultaneous reconnects. When
    /// `connected_peer_snapshot` returns `None` (peer not in the live table at
    /// all, e.g. dropped after idle), the inner repair drops into
    /// `connect_cached_peer`, which dials cached addresses from the bootstrap
    /// cache.
    pub async fn ensure_peer_send_ready(&self, peer_id: &AntPeerId) -> NetworkResult<()> {
        if !self.peer_needs_send_readiness_repair(peer_id).await? {
            return Ok(());
        }

        let lock = self.liveness_lock_for_peer(*peer_id)?;
        let guard = lock.lock().await;
        let permit = self
            .liveness_repair_semaphore
            .acquire()
            .await
            .map_err(|_| {
                NetworkError::NodeCreation("peer liveness repair semaphore closed".to_string())
            })?;

        let result = if !self.peer_needs_send_readiness_repair(peer_id).await? {
            Ok(())
        } else {
            self.ensure_peer_send_ready_inner(peer_id).await
        };
        drop(permit);
        drop(guard);
        self.maybe_remove_liveness_lock(peer_id, &lock);
        result
    }

    async fn ensure_peer_send_ready_inner(&self, peer_id: &AntPeerId) -> NetworkResult<()> {
        let Some((fallback_addr, idle_for)) = self.connected_peer_snapshot(peer_id).await else {
            self.connect_cached_peer(*peer_id).await?;
            self.remember_peer_send_ready(*peer_id)?;
            return Ok(());
        };

        let health = self
            .connection_health(*peer_id)
            .await
            .ok_or_else(|| NetworkError::NodeCreation("Node not initialized".to_string()))?;
        let last_ready_elapsed = self.peer_liveness_ready_elapsed(peer_id)?;
        if !Self::peer_needs_pre_send_probe(&health, idle_for, last_ready_elapsed) {
            return Ok(());
        }

        if health.connected && health.reader_task_active == Some(true) {
            match self
                .probe_peer(*peer_id, PRE_SEND_LIVENESS_PROBE_TIMEOUT)
                .await
            {
                Some(Ok(rtt)) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        peer_id_prefix = %hex_prefix(&peer_id.0, 4),
                        idle_ms = idle_for.as_millis() as u64,
                        rtt_ms = rtt.as_millis() as u64,
                        "pre-send liveness probe succeeded"
                    );
                    self.remember_peer_send_ready(*peer_id)?;
                    return Ok(());
                }
                Some(Err(e)) => {
                    self.refresh_peer_connection(
                        peer_id,
                        fallback_addr,
                        format!("probe failed: {e}"),
                    )
                    .await?;
                    self.remember_peer_send_ready(*peer_id)?;
                    return Ok(());
                }
                None => {
                    return Err(NetworkError::NodeCreation(
                        "Node not initialized".to_string(),
                    ));
                }
            }
        }

        self.refresh_peer_connection(
            peer_id,
            fallback_addr,
            "connection health not send-ready".to_string(),
        )
        .await?;
        self.remember_peer_send_ready(*peer_id)?;
        Ok(())
    }

    /// Connect to a cached peer using its expected peer ID.
    ///
    /// Tries the cached addresses for `peer_id` until one resolves back to the
    /// same authenticated peer. Stale cache entries that now point at a
    /// different peer are rejected.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if the peer is not cached or none of its cached
    /// addresses lead back to the expected peer.
    pub async fn connect_cached_peer(&self, peer_id: AntPeerId) -> NetworkResult<SocketAddr> {
        if self.is_connected(&peer_id).await {
            let node_guard = self.node.read().await;
            if let Some(node) = node_guard.as_ref() {
                if let Some(addr) = node
                    .connected_peers()
                    .await
                    .into_iter()
                    .find(|conn| conn.peer_id == peer_id)
                    .and_then(|conn| match conn.remote_addr {
                        TransportAddr::Udp(addr) => Some(addr),
                        _ => None,
                    })
                {
                    return Ok(addr);
                }
            }
        }

        let cache = self.bootstrap_cache.as_ref().ok_or_else(|| {
            NetworkError::ConnectionFailed("bootstrap cache not configured".to_string())
        })?;
        let cached_peer = cache.get_peer(&peer_id).await.ok_or_else(|| {
            NetworkError::ConnectionFailed(format!(
                "peer {:?} not found in bootstrap cache",
                peer_id
            ))
        })?;

        let candidate_addrs = cached_peer.preferred_addresses();
        for addr in &candidate_addrs {
            match self.connect_addr(*addr).await {
                Ok(connected_peer) if connected_peer == peer_id => return Ok(*addr),
                Ok(connected_peer) => {
                    warn!(
                        "Cached address {} for peer {:?} resolved to unexpected peer {:?}",
                        addr, peer_id, connected_peer
                    );
                }
                Err(e) => {
                    debug!(
                        "Cached dial to peer {:?} at {} failed: {}",
                        peer_id, addr, e
                    );
                }
            }
        }

        cache.record_failure(&peer_id).await;
        Err(NetworkError::ConnectionFailed(format!(
            "peer {:?} not reachable via {} cached addresses",
            peer_id,
            candidate_addrs.len()
        )))
    }

    /// Connect to a peer by address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the peer to connect to.
    ///
    /// # Returns
    ///
    /// Returns the peer's ID on successful connection.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if connection fails or node is not initialized.
    pub async fn connect_addr(&self, addr: SocketAddr) -> NetworkResult<AntPeerId> {
        let node = self.require_node().await?;
        let family = if addr.is_ipv4() { "v4" } else { "v6" };
        tracing::debug!(
            target: "x0x::connect",
            strategy = "direct_addr",
            %addr,
            family,
            "starting direct dial"
        );
        let start = std::time::Instant::now();
        let result = node.connect_addr(addr).await;
        let dur_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(peer_conn) => {
                let rtt_ms = dur_ms as u32;
                if let Some(ref cache) = self.bootstrap_cache {
                    cache
                        .add_from_connection(peer_conn.peer_id, vec![addr], None)
                        .await;
                    cache.record_success(&peer_conn.peer_id, rtt_ms).await;
                }
                self.emit_event(NetworkEvent::PeerConnected {
                    peer_id: peer_conn.peer_id.0,
                    address: addr,
                });
                self.note_connection_pool_activity(peer_conn.peer_id).await;
                tracing::info!(
                    target: "x0x::connect",
                    strategy = "direct_addr",
                    %addr,
                    family,
                    peer_id_prefix = %hex_prefix(&peer_conn.peer_id.0, 4),
                    dur_ms,
                    outcome = "ok",
                    "direct dial succeeded"
                );
                Ok(peer_conn.peer_id)
            }
            Err(e) => {
                // Record failure for any cached peers at this address so quality
                // scores degrade when a peer becomes unreachable.
                if let Some(ref cache) = self.bootstrap_cache {
                    let all_peers = cache.all_peers().await;
                    for peer in &all_peers {
                        if peer.addresses.contains(&addr) {
                            debug!(
                                "Recording connection failure for peer {:?} at {addr}",
                                peer.peer_id
                            );
                            cache.record_failure(&peer.peer_id).await;
                        }
                    }
                }
                tracing::info!(
                    target: "x0x::connect",
                    strategy = "direct_addr",
                    %addr,
                    family,
                    dur_ms,
                    outcome = "fail",
                    error = %e,
                    "direct dial failed"
                );
                Err(NetworkError::ConnectionFailed(e.to_string()))
            }
        }
    }

    /// Connect to a specific peer by ID.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's ID.
    ///
    /// # Returns
    ///
    /// Returns the peer's address on successful connection.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if connection fails.
    pub async fn connect_peer(&self, peer_id: AntPeerId) -> NetworkResult<(SocketAddr, AntPeerId)> {
        let node = self.require_node().await?;
        let start = std::time::Instant::now();
        let peer_conn = node
            .connect_peer(peer_id)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        let addr = match peer_conn.remote_addr {
            TransportAddr::Udp(socket_addr) => socket_addr,
            _ => {
                return Err(NetworkError::ConnectionFailed(
                    "Unsupported transport type".to_string(),
                ))
            }
        };

        // Record in bootstrap cache so future connections use the cached address
        let rtt_ms = start.elapsed().as_millis() as u32;
        if let Some(ref cache) = self.bootstrap_cache {
            cache
                .add_from_connection(peer_conn.peer_id, vec![addr], None)
                .await;
            cache.record_success(&peer_conn.peer_id, rtt_ms).await;
        }

        self.emit_event(NetworkEvent::PeerConnected {
            peer_id: peer_conn.peer_id.0,
            address: addr,
        });
        self.note_connection_pool_activity(peer_conn.peer_id).await;

        Ok((addr, peer_conn.peer_id))
    }

    /// Connect to a specific peer by ID using explicit address hints.
    ///
    /// This lets the transport combine peer-authenticated dialing with caller-
    /// supplied address candidates, which is important when higher layers know
    /// candidate addresses (for example from imported agent cards) but ant-quic
    /// has not yet learned them itself.
    pub async fn connect_peer_with_addrs(
        &self,
        peer_id: AntPeerId,
        addrs: Vec<SocketAddr>,
    ) -> NetworkResult<(SocketAddr, AntPeerId)> {
        let node = self.require_node().await?;
        let v4_count = addrs.iter().filter(|a| a.is_ipv4()).count();
        let v6_count = addrs.len() - v4_count;
        tracing::debug!(
            target: "x0x::connect",
            strategy = "peer_with_addrs",
            peer_id_prefix = %hex_prefix(&peer_id.0, 4),
            addr_count = addrs.len(),
            v4_count,
            v6_count,
            "starting peer-authenticated dial with hints"
        );
        let start = std::time::Instant::now();
        let peer_conn_res = node.connect_peer_with_addrs(peer_id, addrs).await;
        let dur_ms = start.elapsed().as_millis() as u64;

        let peer_conn = match peer_conn_res {
            Ok(pc) => pc,
            Err(e) => {
                tracing::info!(
                    target: "x0x::connect",
                    strategy = "peer_with_addrs",
                    peer_id_prefix = %hex_prefix(&peer_id.0, 4),
                    dur_ms,
                    outcome = "fail",
                    error = %e,
                    "peer-authenticated dial failed"
                );
                return Err(NetworkError::ConnectionFailed(e.to_string()));
            }
        };

        let addr = match peer_conn.remote_addr {
            TransportAddr::Udp(socket_addr) => socket_addr,
            _ => {
                tracing::warn!(
                    target: "x0x::connect",
                    strategy = "peer_with_addrs",
                    peer_id_prefix = %crate::logging::LogTransportPeerId::from(&peer_id),
                    dur_ms,
                    "connected but transport type unsupported"
                );
                return Err(NetworkError::ConnectionFailed(
                    "Unsupported transport type".to_string(),
                ));
            }
        };

        let family = if addr.is_ipv4() { "v4" } else { "v6" };
        let rtt_ms = dur_ms as u32;
        if let Some(ref cache) = self.bootstrap_cache {
            cache
                .add_from_connection(peer_conn.peer_id, vec![addr], None)
                .await;
            cache.record_success(&peer_conn.peer_id, rtt_ms).await;
        }

        self.emit_event(NetworkEvent::PeerConnected {
            peer_id: peer_conn.peer_id.0,
            address: addr,
        });
        self.note_connection_pool_activity(peer_conn.peer_id).await;

        tracing::info!(
            target: "x0x::connect",
            strategy = "peer_with_addrs",
            peer_id_prefix = %hex_prefix(&peer_id.0, 4),
            verified_prefix = %hex_prefix(&peer_conn.peer_id.0, 4),
            selected_addr = %addr,
            family,
            dur_ms,
            outcome = "ok",
            "peer-authenticated dial succeeded"
        );

        Ok((addr, peer_conn.peer_id))
    }

    /// Merge externally discovered peer hints into ant-quic's transport view.
    pub async fn upsert_peer_hints(
        &self,
        peer_id: AntPeerId,
        addrs: Vec<SocketAddr>,
        capabilities: Option<PeerCapabilities>,
    ) -> NetworkResult<()> {
        let node = self.require_node().await?;
        node.upsert_peer_hints(peer_id, addrs, capabilities).await;
        Ok(())
    }

    /// Disconnect from a peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's ID.
    ///
    /// # Returns
    ///
    /// Ok on successful disconnection.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if disconnection fails.
    pub async fn disconnect(&self, peer_id: &AntPeerId) -> NetworkResult<()> {
        let node = self.require_node().await?;
        node.disconnect(peer_id)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        self.emit_event(NetworkEvent::PeerDisconnected { peer_id: peer_id.0 });
        self.connection_pool.record_disconnected(peer_id);

        Ok(())
    }

    /// Get list of connected peer IDs.
    ///
    /// # Returns
    ///
    /// Vector of connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<AntPeerId> {
        let node_guard = self.node.read().await;
        match node_guard.as_ref() {
            Some(node) => node
                .connected_peers()
                .await
                .iter()
                .map(|conn| conn.peer_id)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Check if connected to a specific peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's ID to check.
    ///
    /// # Returns
    ///
    /// True if connected to the peer.
    pub async fn is_connected(&self, peer_id: &AntPeerId) -> bool {
        let node_guard = self.node.read().await;
        match node_guard.as_ref() {
            Some(node) => node.is_connected(peer_id).await,
            None => false,
        }
    }

    /// Return the current gossip receive queue depth and max capacity.
    ///
    /// This is sampled by the gossip runtime dispatcher before handling each
    /// dequeued message so diagnostics can distinguish handler stalls from
    /// network receiver back-pressure.
    #[must_use]
    pub fn gossip_recv_queue_depth(&self, stream_type: GossipStreamType) -> (usize, usize) {
        let (available, max) = match stream_type {
            GossipStreamType::PubSub => (
                self.recv_pubsub_tx.capacity(),
                self.recv_pubsub_tx.max_capacity(),
            ),
            GossipStreamType::Membership => (
                self.recv_membership_tx.capacity(),
                self.recv_membership_tx.max_capacity(),
            ),
            GossipStreamType::Bulk => (
                self.recv_bulk_tx.capacity(),
                self.recv_bulk_tx.max_capacity(),
            ),
        };
        (max.saturating_sub(available), max)
    }

    /// Snapshot ant-quic → gossip receive-pump diagnostics.
    #[must_use]
    pub fn recv_pump_diagnostics(&self) -> RecvPumpDiagnosticsSnapshot {
        self.recv_pump_diagnostics.snapshot()
    }

    /// Gracefully shut down the node: abort the background tasks, close all
    /// connections, and shut down the ant-quic node.
    ///
    /// The background receiver and accept loops park in `recv()`/`accept().await`
    /// while holding a *read* guard on `node`, so they are aborted FIRST —
    /// otherwise taking the *write* lock below would deadlock on an idle node
    /// that never receives another packet. After the tasks are aborted (releasing
    /// their read guards and `node` clones), the node is taken and shut down.
    ///
    /// NOTE: this closes connections but does **not** synchronously free the
    /// bound UDP socket — ant-quic's endpoint driver releases it only on process
    /// exit (saorsa-labs/ant-quic#196). In-process callers that restart must bind
    /// an *ephemeral* QUIC port rather than reuse a fixed one, until that upstream
    /// fix lands.
    pub async fn shutdown(&self) {
        let handles: Vec<tokio::task::JoinHandle<()>> = match self.background_tasks.lock() {
            Ok(mut tasks) => tasks.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        };
        for handle in &handles {
            handle.abort();
        }
        // Await the aborted tasks so their `Node` clones are dropped before we
        // drop the node here. An aborted task yields `Err(JoinError::Cancelled)`;
        // that is expected.
        for handle in handles {
            let _ = handle.await;
        }
        // Take the node out and shut it down explicitly so connections close
        // deterministically. As of ant-quic 0.27.27 (#196), `Node::shutdown()`
        // releases the bound endpoint UDP socket in-process (it swaps in a
        // throwaway ephemeral socket and drops the original), so a same-process
        // re-bind on the SAME fixed QUIC port works for a single stop→restart
        // (proven by tests/server_inprocess.rs::serve_tears_down_cleanly_and_rebinds).
        // The release is NOT perfectly synchronous: the OS FD for the fixed port
        // closes once the endpoint driver drops its last reference, shortly after
        // this returns, so a tight zero-gap loop re-binding the same fixed port
        // may still see "address already in use" — an embedder should retry.
        let node = {
            let mut node_guard = self.node.write().await;
            node_guard.take()
        };
        if let Some(node) = node {
            node.shutdown().await;
        }
    }

    /// Get a clone of the inner node, returning an error if not initialized.
    ///
    /// This helper reduces boilerplate in methods that need exclusive
    /// access to the node after releasing the read lock.
    async fn require_node(&self) -> NetworkResult<Node> {
        self.node
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| NetworkError::NodeCreation("Node not initialized".to_string()))
    }

    /// Get the local peer ID.
    ///
    /// # Returns
    ///
    /// The PeerId for this node.
    pub fn peer_id(&self) -> AntPeerId {
        self.peer_id
    }

    // === Direct Messaging ===

    /// Send a direct message to a connected peer.
    ///
    /// The message is prefixed with the direct message stream type (0x10)
    /// and the sender's agent ID for identification.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The ant-quic PeerId of the recipient (maps to MachineId).
    /// * `sender_agent_id` - The AgentId of the sender (included in message).
    /// * `payload` - The message payload.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if the peer is not connected or send fails.
    pub async fn send_direct(
        &self,
        peer_id: &AntPeerId,
        sender_agent_id: &[u8; 32],
        payload: &[u8],
    ) -> NetworkResult<()> {
        self.get_or_connect_pooled_peer(peer_id).await?;

        // Build wire format: [0x10][sender_agent_id: 32 bytes][payload]
        let mut buf = Vec::with_capacity(1 + 32 + payload.len());
        buf.push(DIRECT_MESSAGE_STREAM_TYPE);
        buf.extend_from_slice(sender_agent_id);
        buf.extend_from_slice(payload);

        // Send via ant-quic
        let node = self.require_node().await?;
        node.send(peer_id, &buf)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("send failed: {}", e)))?;
        self.note_connection_pool_activity(*peer_id).await;

        debug!(
            "[1/6 network] send_direct: {} bytes to peer {:?}",
            payload.len(),
            peer_id
        );

        Ok(())
    }

    /// Receive the next direct message.
    ///
    /// Blocks until a direct message is received. Returns the sender's
    /// MachineId (as ant-quic PeerId) and the raw payload (including
    /// the sender's AgentId prefix).
    ///
    /// # Returns
    ///
    /// Tuple of (sender_peer_id, payload_with_agent_id).
    pub async fn recv_direct(&self) -> Option<(AntPeerId, Bytes)> {
        let mut rx = self.direct_rx.lock().await;
        rx.recv().await
    }

    async fn receive_from_gossip_channel(
        rx: &Arc<tokio::sync::Mutex<mpsc::Receiver<GossipPayload>>>,
        diagnostics: &RecvPumpDiagnostics,
        stream_type: GossipStreamType,
        stream_name: &'static str,
    ) -> anyhow::Result<(GossipPeerId, Bytes)> {
        let mut rx = rx.lock().await;
        let payload = rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("{stream_name} receive channel closed"))?;
        diagnostics.record_dequeued(stream_type, payload.enqueued_at.elapsed());
        Ok((ant_to_gossip_peer_id(&payload.peer_id), payload.data))
    }

    /// Receive the next PubSub gossip message from the dedicated PubSub queue.
    pub async fn receive_pubsub_message(&self) -> anyhow::Result<(GossipPeerId, Bytes)> {
        Self::receive_from_gossip_channel(
            &self.recv_pubsub_rx,
            self.recv_pump_diagnostics.as_ref(),
            GossipStreamType::PubSub,
            "PubSub",
        )
        .await
    }

    /// Receive the next Membership gossip message from the dedicated Membership queue.
    pub async fn receive_membership_message(&self) -> anyhow::Result<(GossipPeerId, Bytes)> {
        Self::receive_from_gossip_channel(
            &self.recv_membership_rx,
            self.recv_pump_diagnostics.as_ref(),
            GossipStreamType::Membership,
            "Membership",
        )
        .await
    }

    /// Receive the next Bulk gossip message from the dedicated Bulk queue.
    pub async fn receive_bulk_message(&self) -> anyhow::Result<(GossipPeerId, Bytes)> {
        Self::receive_from_gossip_channel(
            &self.recv_bulk_rx,
            self.recv_pump_diagnostics.as_ref(),
            GossipStreamType::Bulk,
            "Bulk",
        )
        .await
    }

    /// Spawn background receiver task that parses gossip stream types.
    ///
    /// This task continuously receives messages from ant-quic, parses the
    /// stream type from the first byte, and forwards parsed messages to:
    /// - Direct message channel (for 0x10 direct messages)
    /// - Gossip transport channel (for 0x00, 0x01, 0x02 gossip messages)
    fn spawn_receiver(&self) -> tokio::task::JoinHandle<()> {
        let node = Arc::clone(&self.node);
        let recv_pubsub_tx = self.recv_pubsub_tx.clone();
        let recv_membership_tx = self.recv_membership_tx.clone();
        let recv_bulk_tx = self.recv_bulk_tx.clone();
        let recv_pump_diagnostics = Arc::clone(&self.recv_pump_diagnostics);
        let direct_tx = self.direct_tx.clone();

        tokio::spawn(async move {
            debug!("NetworkNode receiver task started");

            loop {
                // Get node read lock
                let node_guard = node.read().await;
                let node_ref = match node_guard.as_ref() {
                    Some(n) => n,
                    None => {
                        debug!("Node not initialized, receiver stopping");
                        break;
                    }
                };

                let recv_result = node_ref.recv().await;
                // Explicitly drop the read lock guard so we don't hold it
                // across channel sends — otherwise a backpressured direct_tx
                // or stream-specific gossip channel can stall every other caller
                // that wants the same read lock and masks as a delivery bug.
                drop(node_guard);

                match recv_result {
                    Ok((peer_id, data)) => {
                        if data.is_empty() {
                            continue;
                        }

                        // Parse stream type from first byte (safe: data is non-empty)
                        let type_byte = data[0];

                        // Handle direct messages separately (0x10)
                        if type_byte == DIRECT_MESSAGE_STREAM_TYPE {
                            // Direct message: forward to direct channel (includes full payload with sender AgentId)
                            let payload = Bytes::copy_from_slice(&data[1..]);

                            // Enforce max payload size (16 MB) to prevent memory exhaustion
                            // payload = 32-byte AgentId prefix + actual data, so effective
                            // data limit is exactly MAX_DIRECT_PAYLOAD_SIZE (16 MB)
                            if payload.len() > crate::direct::MAX_DIRECT_PAYLOAD_SIZE + 32 {
                                warn!(
                                    "[1/6 network] dropping oversized direct message: {} bytes from peer {:?} (max: {})",
                                    payload.len(),
                                    peer_id,
                                    crate::direct::MAX_DIRECT_PAYLOAD_SIZE + 32
                                );
                                continue;
                            }

                            debug!(
                                "[1/6 network] recv direct: {} bytes from peer {:?}",
                                payload.len(),
                                peer_id
                            );
                            warn_forward_channel_pressure(&direct_tx, peer_id, None, "direct_tx");
                            if let Err(e) = direct_tx.send((peer_id, payload)).await {
                                error!("Failed to forward direct message: {}", e);
                                break;
                            }
                            continue;
                        }

                        // Handle gossip messages (0x00, 0x01, 0x02)
                        let stream_type = match GossipStreamType::from_byte(type_byte) {
                            Some(st) => st,
                            None => {
                                warn!("Unknown stream type byte: {}", type_byte);
                                continue;
                            }
                        };

                        // Extract payload (everything after the type byte)
                        let payload = Bytes::copy_from_slice(&data[1..]);

                        debug!(
                            "[1/6 network] recv: {} bytes ({:?}) from peer {:?}",
                            data.len() - 1,
                            stream_type,
                            peer_id
                        );

                        let forward_result = match stream_type {
                            GossipStreamType::PubSub => {
                                forward_gossip_payload(
                                    &recv_pubsub_tx,
                                    peer_id,
                                    stream_type,
                                    payload,
                                    "recv_pubsub_tx",
                                    recv_pump_diagnostics.as_ref(),
                                )
                                .await
                            }
                            GossipStreamType::Membership => {
                                forward_gossip_payload(
                                    &recv_membership_tx,
                                    peer_id,
                                    stream_type,
                                    payload,
                                    "recv_membership_tx",
                                    recv_pump_diagnostics.as_ref(),
                                )
                                .await
                            }
                            GossipStreamType::Bulk => {
                                forward_gossip_payload(
                                    &recv_bulk_tx,
                                    peer_id,
                                    stream_type,
                                    payload,
                                    "recv_bulk_tx",
                                    recv_pump_diagnostics.as_ref(),
                                )
                                .await
                            }
                        };

                        match forward_result {
                            Ok(ForwardGossipOutcome::Enqueued) => {}
                            Ok(ForwardGossipOutcome::DroppedFull | ForwardGossipOutcome::Shed) => {
                                continue
                            }
                            Err(e) => {
                                error!("Failed to forward gossip message: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Receive error: {}", e);
                    }
                }
            }

            debug!("NetworkNode receiver task stopped");
        })
    }

    /// Spawn a background task that accepts inbound connections.
    ///
    /// Without this, only outbound connections (initiated by `connect_addr`)
    /// are registered in `connected_peers`. Inbound peers would complete the
    /// QUIC handshake but never have a reader task spawned, so `recv()` would
    /// never deliver their data.
    fn spawn_accept_loop(&self) -> tokio::task::JoinHandle<()> {
        let node = Arc::clone(&self.node);
        let event_sender = self.event_sender.clone();
        let bootstrap_cache = self.bootstrap_cache.clone();
        let inbound_allowlist = self.config.inbound_allowlist.clone();
        let connection_pool = Arc::clone(&self.connection_pool);

        tokio::spawn(async move {
            debug!("NetworkNode accept loop started");

            loop {
                let node_guard = node.read().await;
                let node_ref = match node_guard.as_ref() {
                    Some(n) => n,
                    None => {
                        debug!("Node not initialized, accept loop stopping");
                        break;
                    }
                };

                match node_ref.accept().await {
                    Some(peer_conn) => {
                        // Reject peers not in inbound allowlist (when configured)
                        if !inbound_allowlist.is_empty()
                            && !inbound_allowlist.contains(&peer_conn.peer_id.0)
                        {
                            tracing::warn!(
                                "SECURITY: Rejecting inbound connection from non-allowlisted peer {:?}",
                                peer_conn.peer_id
                            );
                            continue;
                        }

                        tracing::info!(
                            "Accepted inbound connection from peer {:?} at {:?}",
                            peer_conn.peer_id,
                            peer_conn.remote_addr
                        );
                        let addr = match peer_conn.remote_addr {
                            ant_quic::TransportAddr::Udp(addr) => Some(addr),
                            _ => None,
                        };
                        if let (Some(ref cache), Some(addr)) = (&bootstrap_cache, addr) {
                            cache
                                .add_from_connection(peer_conn.peer_id, vec![addr], None)
                                .await;
                            cache.record_success(&peer_conn.peer_id, 0).await;
                        }
                        let addr =
                            addr.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
                        let _ = event_sender.send(NetworkEvent::PeerConnected {
                            peer_id: peer_conn.peer_id.0,
                            address: addr,
                        });
                        let evicted = connection_pool.note_activity(peer_conn.peer_id);
                        if !evicted.is_empty() {
                            disconnect_pool_candidates(
                                node_ref,
                                &event_sender,
                                connection_pool.as_ref(),
                                evicted,
                                "lru",
                            )
                            .await;
                        }
                    }
                    None => {
                        debug!("Accept loop ended (node shutting down)");
                        break;
                    }
                }
            }

            debug!("NetworkNode accept loop stopped");
        })
    }

    fn spawn_connection_pool_eviction(&self) -> tokio::task::JoinHandle<()> {
        let node = Arc::clone(&self.node);
        let event_sender = self.event_sender.clone();
        let connection_pool = Arc::clone(&self.connection_pool);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CONNECTION_POOL_EVICTION_INTERVAL);
            loop {
                interval.tick().await;

                let Some(node_ref) = node.read().await.as_ref().cloned() else {
                    debug!("Node not initialized, connection pool eviction stopping");
                    break;
                };

                let connected_peers = node_ref
                    .connected_peers()
                    .await
                    .into_iter()
                    .map(|conn| (conn.peer_id, conn.last_activity))
                    .collect();
                let lru_evicted = connection_pool.sync_connected_peers(connected_peers);
                disconnect_pool_candidates(
                    &node_ref,
                    &event_sender,
                    connection_pool.as_ref(),
                    lru_evicted,
                    "lru",
                )
                .await;

                let idle_evicted = connection_pool.evict_idle(Instant::now());
                disconnect_pool_candidates(
                    &node_ref,
                    &event_sender,
                    connection_pool.as_ref(),
                    idle_evicted,
                    "idle",
                )
                .await;
            }
        })
    }
}

// ============================================================================
// PeerId Conversion Helpers
// ============================================================================

/// Short hex prefix for compact logging of 32-byte peer/machine IDs.
pub(crate) fn hex_prefix(bytes: &[u8; 32], n: usize) -> String {
    let n = n.min(32);
    let mut s = String::with_capacity(n * 2);
    for b in &bytes[..n] {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Convert ant-quic PeerId to saorsa-gossip PeerId
fn ant_to_gossip_peer_id(ant_id: &AntPeerId) -> GossipPeerId {
    GossipPeerId::new(ant_id.0)
}

/// Convert saorsa-gossip PeerId to ant-quic PeerId
fn gossip_to_ant_peer_id(gossip_id: &GossipPeerId) -> AntPeerId {
    ant_quic::PeerId(gossip_id.to_bytes())
}

// ============================================================================
// GossipTransport Implementation
// ============================================================================

#[async_trait::async_trait]
impl saorsa_gossip_transport::GossipTransport for NetworkNode {
    async fn dial(&self, peer: GossipPeerId, addr: SocketAddr) -> anyhow::Result<()> {
        let ant_peer = gossip_to_ant_peer_id(&peer);

        // Check if already connected
        if self.is_connected(&ant_peer).await {
            debug!("Already connected to peer {:?} at {}", peer, addr);
            return Ok(());
        }

        // Connect by address
        let connected_peer = self
            .connect_addr(addr)
            .await
            .map_err(|e| anyhow::anyhow!("dial failed: {}", e))?;

        // Verify we connected to the expected peer
        if connected_peer != ant_peer {
            warn!(
                "SECURITY: Peer mismatch - expected {:?}, got {:?}",
                peer, connected_peer
            );
            return Err(anyhow::anyhow!(
                "Connected to unexpected peer {:?} when dialing {:?}",
                connected_peer,
                peer
            ));
        }

        Ok(())
    }

    async fn dial_bootstrap(&self, addr: SocketAddr) -> anyhow::Result<GossipPeerId> {
        let ant_peer_id = self
            .connect_addr(addr)
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap dial failed: {}", e))?;

        // Reject bootstrap peers not in the pinned set (when configured).
        if !self.config.pinned_bootstrap_peers.is_empty()
            && !self.config.pinned_bootstrap_peers.contains(&ant_peer_id.0)
        {
            warn!(
                "SECURITY: Bootstrap peer at {} has unexpected ID {:?} — not in pinned set",
                addr, ant_peer_id
            );
            let _ = self.disconnect(&ant_peer_id).await;
            return Err(anyhow::anyhow!(
                "Bootstrap peer at {} has unpinned ID {:?}",
                addr,
                ant_peer_id
            ));
        }

        Ok(ant_to_gossip_peer_id(&ant_peer_id))
    }

    async fn listen(&self, _bind: SocketAddr) -> anyhow::Result<()> {
        // No-op: NetworkNode binds its QUIC transport during construction
        debug!("listen() no-op - NetworkNode already bound");
        Ok(())
    }

    async fn close(&self) -> anyhow::Result<()> {
        self.shutdown().await;
        Ok(())
    }

    async fn send_to_peer(
        &self,
        peer: GossipPeerId,
        stream_type: saorsa_gossip_transport::GossipStreamType,
        data: bytes::Bytes,
    ) -> anyhow::Result<()> {
        let ant_peer = gossip_to_ant_peer_id(&peer);

        // Prepare message: [stream_type_byte | data]
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(stream_type.to_byte());
        buf.extend_from_slice(&data);

        // Send via ant-quic Node
        //
        // Do not run `ensure_peer_send_ready` here. Saorsa-gossip wraps
        // per-peer sends in a small timeout; a multi-second liveness repair on
        // this path turns healthy gossip degradation into a timeout/log storm.
        let node_guard = self.node.read().await;
        let node = node_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("node not initialized"))?;

        node.send(&ant_peer, &buf)
            .await
            .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;
        drop(node_guard);
        self.note_connection_pool_activity(ant_peer).await;

        debug!(
            "[1/6 network] send: {} bytes ({:?}) to peer {:?}",
            buf.len(),
            stream_type,
            peer
        );

        Ok(())
    }

    async fn connected_peer_ids(&self) -> Vec<GossipPeerId> {
        self.connected_peers()
            .await
            .into_iter()
            .map(|peer| ant_to_gossip_peer_id(&peer))
            .collect()
    }

    async fn receive_message(
        &self,
    ) -> anyhow::Result<(
        GossipPeerId,
        saorsa_gossip_transport::GossipStreamType,
        bytes::Bytes,
    )> {
        let mut bulk_rx = self.recv_bulk_rx.lock().await;
        let mut membership_rx = self.recv_membership_rx.lock().await;
        let mut pubsub_rx = self.recv_pubsub_rx.lock().await;

        tokio::select! {
            biased;
            msg = bulk_rx.recv() => {
                let payload = msg.ok_or_else(|| anyhow::anyhow!("Bulk receive channel closed"))?;
                self.recv_pump_diagnostics
                    .record_dequeued(GossipStreamType::Bulk, payload.enqueued_at.elapsed());
                Ok((ant_to_gossip_peer_id(&payload.peer_id), GossipStreamType::Bulk, payload.data))
            }
            msg = membership_rx.recv() => {
                let payload = msg.ok_or_else(|| anyhow::anyhow!("Membership receive channel closed"))?;
                self.recv_pump_diagnostics
                    .record_dequeued(GossipStreamType::Membership, payload.enqueued_at.elapsed());
                Ok((ant_to_gossip_peer_id(&payload.peer_id), GossipStreamType::Membership, payload.data))
            }
            msg = pubsub_rx.recv() => {
                let payload = msg.ok_or_else(|| anyhow::anyhow!("PubSub receive channel closed"))?;
                self.recv_pump_diagnostics
                    .record_dequeued(GossipStreamType::PubSub, payload.enqueued_at.elapsed());
                Ok((ant_to_gossip_peer_id(&payload.peer_id), GossipStreamType::PubSub, payload.data))
            }
        }
    }

    fn local_peer_id(&self) -> GossipPeerId {
        ant_to_gossip_peer_id(&self.peer_id())
    }
}

/// Events emitted by the network node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new peer connected.
    PeerConnected {
        /// The peer's ID.
        peer_id: [u8; 32],
        /// The peer's address.
        address: SocketAddr,
    },

    /// A peer disconnected.
    PeerDisconnected {
        /// The peer's ID.
        peer_id: [u8; 32],
    },

    /// NAT type was detected.
    NatTypeDetected {
        /// The detected NAT type.
        nat_type: String,
    },

    /// External address was discovered.
    ExternalAddressDiscovered {
        /// The discovered external address.
        address: SocketAddr,
    },

    /// Connection error occurred.
    ConnectionError {
        /// The peer ID if applicable.
        peer_id: Option<[u8; 32]>,
        /// The error message.
        error: String,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use saorsa_gossip_transport::GossipTransport;

    fn test_ant_peer(byte: u8) -> AntPeerId {
        ant_quic::PeerId([byte; 32])
    }

    #[tokio::test]
    async fn test_gossip_transport_trait() {
        let config = NetworkConfig::default();
        let node = NetworkNode::new(config, None, None).await.unwrap();

        // Test local_peer_id() method
        let peer_id = node.local_peer_id();
        assert_eq!(peer_id.to_bytes().len(), 32);

        // Test close() method
        assert!(node.close().await.is_ok());
    }

    #[test]
    fn test_peer_id_conversion() {
        // Create a test peer ID
        let bytes = [42u8; 32];
        let ant_peer = ant_quic::PeerId(bytes);
        let gossip_peer = ant_to_gossip_peer_id(&ant_peer);

        // Convert back
        let ant_peer_2 = gossip_to_ant_peer_id(&gossip_peer);

        // Should be identical
        assert_eq!(ant_peer, ant_peer_2);
        assert_eq!(gossip_peer.to_bytes(), bytes);
    }

    #[test]
    fn test_network_config_defaults() {
        let config = NetworkConfig::default();

        assert!(config.bind_addr.is_none());

        // Verify default bootstrap nodes are included. ADR-0011: each of the 6
        // VPS is seeded on both UDP/443 and UDP/5483, in IPv4 and IPv6 →
        // 6 nodes × 2 ports × 2 families = 24 entries when IPv6 is available.
        assert_eq!(
            config.bootstrap_nodes.len(),
            24,
            "Should have 24 default bootstrap nodes (6 nodes × {{443,5483}} × {{IPv4,IPv6}})"
        );

        // Verify specific bootstrap addresses
        let expected_addrs: Vec<SocketAddr> = DEFAULT_BOOTSTRAP_PEERS
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        for expected in &expected_addrs {
            assert!(
                config.bootstrap_nodes.contains(expected),
                "Bootstrap nodes should include {}",
                expected
            );
        }

        assert_eq!(config.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(config.connection_timeout, DEFAULT_CONNECTION_TIMEOUT);
    }

    #[test]
    fn pool_evicts_after_idle_threshold() {
        let pool = ConnectionPool::new(8, Duration::from_secs(5));
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_secs(10)).unwrap_or(now);
        let fresh = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
        let stale_peer = test_ant_peer(1);
        let fresh_peer = test_ant_peer(2);

        assert!(pool
            .sync_connected_peers(vec![(stale_peer, old), (fresh_peer, fresh)])
            .is_empty());

        let evicted = pool.evict_idle(now);
        assert_eq!(evicted, vec![stale_peer]);

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.active_count, 1);
        assert_eq!(snapshot.idle_evictions_total, 1);
    }

    #[test]
    fn pool_caps_active_connections_at_max() {
        let pool = ConnectionPool::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let p1 = test_ant_peer(1);
        let p2 = test_ant_peer(2);
        let p3 = test_ant_peer(3);

        let evicted = pool.sync_connected_peers(vec![
            (p1, now.checked_sub(Duration::from_secs(3)).unwrap_or(now)),
            (p2, now.checked_sub(Duration::from_secs(2)).unwrap_or(now)),
            (p3, now.checked_sub(Duration::from_secs(1)).unwrap_or(now)),
        ]);

        assert_eq!(evicted, vec![p1]);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.active_count, 2);
        assert_eq!(snapshot.max_connections, 2);
        assert_eq!(snapshot.lru_evictions_total, 1);
    }

    #[test]
    fn pool_lru_eviction_respects_recent_activity() {
        let pool = ConnectionPool::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let p1 = test_ant_peer(1);
        let p2 = test_ant_peer(2);
        let p3 = test_ant_peer(3);

        assert!(pool
            .sync_connected_peers(vec![
                (p1, now.checked_sub(Duration::from_secs(10)).unwrap_or(now)),
                (p2, now.checked_sub(Duration::from_secs(9)).unwrap_or(now)),
            ])
            .is_empty());
        assert!(pool.note_activity(p1).is_empty());

        let evicted = pool.note_activity(p3);
        assert_eq!(evicted, vec![p2]);

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.active_count, 2);
        assert_eq!(snapshot.lru_evictions_total, 1);
    }

    #[test]
    fn pre_send_probe_not_needed_for_fresh_ready_connection() {
        let health = ant_quic::ConnectionHealth {
            connected: true,
            reader_task_active: Some(true),
            ..Default::default()
        };

        assert!(!NetworkNode::peer_needs_pre_send_probe(
            &health,
            Duration::from_secs(1),
            None
        ));
    }

    #[test]
    fn pre_send_probe_needed_for_idle_ready_connection() {
        let health = ant_quic::ConnectionHealth {
            connected: true,
            reader_task_active: Some(true),
            ..Default::default()
        };

        assert!(NetworkNode::peer_needs_pre_send_probe(
            &health,
            PRE_SEND_LIVENESS_IDLE_THRESHOLD,
            None
        ));
    }

    #[test]
    fn pre_send_probe_not_needed_during_liveness_cooldown() {
        let health = ant_quic::ConnectionHealth {
            connected: true,
            reader_task_active: Some(true),
            ..Default::default()
        };

        assert!(!NetworkNode::peer_needs_pre_send_probe(
            &health,
            PRE_SEND_LIVENESS_IDLE_THRESHOLD.saturating_mul(10),
            Some(Duration::from_secs(5))
        ));
    }

    #[test]
    fn pre_send_probe_needed_after_liveness_cooldown_expires() {
        let health = ant_quic::ConnectionHealth {
            connected: true,
            reader_task_active: Some(true),
            ..Default::default()
        };

        assert!(NetworkNode::peer_needs_pre_send_probe(
            &health,
            PRE_SEND_LIVENESS_IDLE_THRESHOLD,
            Some(PRE_SEND_LIVENESS_COOLDOWN)
        ));
    }

    #[test]
    fn pre_send_probe_needed_for_inactive_reader() {
        let health = ant_quic::ConnectionHealth {
            connected: true,
            reader_task_active: Some(false),
            ..Default::default()
        };

        assert!(NetworkNode::peer_needs_pre_send_probe(
            &health,
            Duration::from_secs(1),
            Some(Duration::from_secs(5))
        ));
    }

    #[test]
    fn pre_send_probe_needed_for_disconnected_peer_during_cooldown() {
        let health = ant_quic::ConnectionHealth {
            connected: false,
            reader_task_active: Some(true),
            ..Default::default()
        };

        assert!(NetworkNode::peer_needs_pre_send_probe(
            &health,
            Duration::from_secs(1),
            Some(Duration::from_secs(5))
        ));
    }

    #[test]
    fn test_default_bootstrap_peers_parseable() {
        // Verify all bootstrap peer strings are valid SocketAddrs
        for peer in DEFAULT_BOOTSTRAP_PEERS {
            peer.parse::<SocketAddr>()
                .unwrap_or_else(|_| panic!("Bootstrap peer '{}' is not a valid SocketAddr", peer));
        }
    }

    #[tokio::test]
    async fn test_network_stats_default() {
        let stats = NetworkStats::default();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.peer_count, 0);
    }
}

#[tokio::test]
async fn test_network_node_subscribe_events() {
    let config = NetworkConfig::default();
    let node = NetworkNode::new(config, None, None).await.unwrap();

    // Subscribe to events
    let mut receiver = node.subscribe();

    // Emit an event
    let event = NetworkEvent::PeerConnected {
        peer_id: [1; 32],
        address: "127.0.0.1:9000".parse().unwrap(),
    };
    node.emit_event(event);

    // Receive the event
    let received = receiver.recv().await;
    assert!(received.is_ok());

    match received.unwrap() {
        NetworkEvent::PeerConnected { peer_id, address } => {
            assert_eq!(peer_id, [1; 32]);
            assert_eq!(address, "127.0.0.1:9000".parse().unwrap());
        }
        _ => panic!("Expected PeerConnected event"),
    }
}

#[tokio::test]
async fn test_network_node_multiple_subscribers() {
    let config = NetworkConfig::default();
    let node = NetworkNode::new(config, None, None).await.unwrap();

    // Multiple subscribers
    let mut rx1 = node.subscribe();
    let mut rx2 = node.subscribe();

    // Emit event
    let event = NetworkEvent::NatTypeDetected {
        nat_type: "Full Cone".to_string(),
    };
    node.emit_event(event);

    // Both should receive
    assert!(rx1.recv().await.is_ok());
    assert!(rx2.recv().await.is_ok());
}

/// Test that connections between local nodes are bidirectionally visible.
///
/// This reproduces the "phantom connection" bug where `connect_addr()` succeeds
/// on the initiator side but the acceptor never registers the connection,
/// resulting in asymmetric peer counts.
///
/// This test creates nodes with ephemeral ports and attempts to form a full mesh.
/// Due to dual-stack socket complexities on some platforms, not all connections
/// may succeed — but any connection that does succeed MUST be bidirectional.
///
/// See: .planning/ant-quic-phantom-connections.md
#[ignore = "timing-sensitive mesh test — run manually with: cargo test test_mesh -- --ignored --nocapture"]
#[tokio::test]
async fn test_mesh_connections_are_bidirectional() {
    const NODE_COUNT: usize = 4;
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    // Create nodes with ephemeral ports (port 0) to avoid conflicts
    let mut nodes = Vec::with_capacity(NODE_COUNT);
    let mut addrs = Vec::with_capacity(NODE_COUNT);

    for _ in 0..NODE_COUNT {
        let config = NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: Vec::new(),
            max_connections: 100,
            connection_timeout: CONNECT_TIMEOUT,
            stats_interval: std::time::Duration::from_secs(60),
            peer_cache_path: None,
            pinned_bootstrap_peers: std::collections::HashSet::new(),
            inbound_allowlist: std::collections::HashSet::new(),
            max_peers_per_ip: 3,
            port_mapping_enabled: true,
        };

        let node = NetworkNode::new(config, None, None).await.unwrap();
        nodes.push(node);
    }

    // Collect bound addresses — force IPv4 loopback since bound_addr() may
    // return [::]:port on dual-stack systems even when we bound to 127.0.0.1.
    for node in &nodes {
        let bound = node
            .bound_addr()
            .await
            .expect("node must have a bound address");
        let addr: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();
        addrs.push(addr);
    }

    // Each node connects to all others in parallel (simulating bootstrap)
    let mut handles = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        for (j, target_addr) in addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            let node = node.clone();
            let addr = *target_addr;
            handles.push(tokio::spawn(async move {
                let result = tokio::time::timeout(CONNECT_TIMEOUT, node.connect_addr(addr)).await;
                (i, j, result)
            }));
        }
    }

    // Wait for all connections — track successes and failures
    let mut successful_connections = 0u32;
    for handle in handles {
        let (from, to, result) = handle.await.unwrap();
        match result {
            Ok(Ok(_)) => {
                successful_connections += 1;
            }
            Ok(Err(e)) => {
                eprintln!("Connection {}->{} failed: {}", from, to, e);
            }
            Err(_) => {
                eprintln!("Connection {}->{} timed out", from, to);
            }
        }
    }

    // Allow connections to stabilize
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Log connection counts
    for (i, node) in nodes.iter().enumerate() {
        let count = node.connection_count().await;
        eprintln!("Node {} ({}) has {} peers", i, addrs[i], count);
    }

    // BIDIRECTIONALITY CHECK (the core assertion):
    // For every pair (A, B), if A sees B as connected then B MUST also see A.
    // A phantom connection bug would break this symmetry.
    for i in 0..NODE_COUNT {
        let peers_i = nodes[i].connected_peers().await;
        for j in 0..NODE_COUNT {
            if i == j {
                continue;
            }
            let j_peer_id = nodes[j].peer_id();
            let i_sees_j = peers_i.contains(&j_peer_id);
            if i_sees_j {
                let peers_j = nodes[j].connected_peers().await;
                let i_peer_id = nodes[i].peer_id();
                let j_sees_i = peers_j.contains(&i_peer_id);
                assert!(
                    j_sees_i,
                    "Phantom connection: node {} sees node {} but node {} does not see node {} back",
                    i, j, j, i
                );
            }
        }
    }

    // Require at least some connections succeeded (otherwise the test is vacuous)
    assert!(
        successful_connections > 0,
        "No connections succeeded at all — this indicates a transport/binding issue, not a phantom connection bug"
    );
}
/// A message transmitted through the x0x network.
///
/// Messages are the basic unit of communication in the x0x gossip network.
/// Each message includes a unique ID, sender information, topic, payload,
/// timestamp, and sequence number for ordering.
///
/// # Examples
///
/// ```no_run
/// use x0x::network::Message;
///
/// let message = Message::new(
///     [1; 32],  // sender peer_id
///     "chat".to_string(),
///     b"Hello, world!".to_vec(),
/// ).expect("Failed to create message");
///
/// assert_eq!(message.topic, "chat");
/// assert_eq!(message.payload, b"Hello, world!".to_vec());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    /// Unique message identifier (BLAKE3 hash of content).
    pub id: [u8; 32],

    /// Sender's peer ID.
    pub sender: [u8; 32],

    /// Topic for gossip pub/sub routing.
    pub topic: String,

    /// Binary message payload.
    pub payload: Vec<u8>,

    /// Unix timestamp in seconds when message was created.
    pub timestamp: u64,

    /// Sequence number for total ordering of messages from a sender.
    pub sequence: u64,
}

impl Message {
    /// Create a new message with automatic timestamp and ID generation.
    ///
    /// # Arguments
    ///
    /// * `sender` - The peer ID of the message sender.
    /// * `topic` - The topic string for routing.
    /// * `payload` - The message payload bytes.
    ///
    /// # Returns
    ///
    /// A new Message with generated ID and timestamp.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if timestamp generation fails.
    pub fn new(sender: [u8; 32], topic: String, payload: Vec<u8>) -> NetworkResult<Self> {
        let timestamp = current_timestamp()?;
        let id = generate_message_id(&sender, &topic, &payload, timestamp);

        Ok(Self {
            id,
            sender,
            topic,
            payload,
            timestamp,
            sequence: 0,
        })
    }

    /// Create a message with an explicit sequence number.
    ///
    /// # Arguments
    ///
    /// * `sender` - The peer ID of the message sender.
    /// * `topic` - The topic string for routing.
    /// * `payload` - The message payload bytes.
    /// * `sequence` - The sequence number for ordering.
    ///
    /// # Returns
    ///
    /// A new Message with generated ID and timestamp.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if timestamp generation fails.
    pub fn with_sequence(
        sender: [u8; 32],
        topic: String,
        payload: Vec<u8>,
        sequence: u64,
    ) -> NetworkResult<Self> {
        let mut msg = Self::new(sender, topic, payload)?;
        msg.sequence = sequence;
        Ok(msg)
    }

    /// Serialize message to JSON format.
    ///
    /// # Returns
    ///
    /// JSON-encoded message bytes.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if JSON serialization fails.
    pub fn to_json(&self) -> NetworkResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| NetworkError::SerializationError(format!("JSON encode failed: {}", e)))
    }

    /// Deserialize message from JSON format.
    ///
    /// # Arguments
    ///
    /// * `data` - JSON-encoded message bytes.
    ///
    /// # Returns
    ///
    /// Deserialized Message.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if JSON deserialization fails.
    pub fn from_json(data: &[u8]) -> NetworkResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| NetworkError::SerializationError(format!("JSON decode failed: {}", e)))
    }

    /// Serialize message to binary format (bincode).
    ///
    /// # Returns
    ///
    /// Binary-encoded message bytes.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if binary serialization fails.
    pub fn to_binary(&self) -> NetworkResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NetworkError::SerializationError(format!("Binary encode failed: {}", e)))
    }

    /// Deserialize message from binary format (bincode).
    ///
    /// # Arguments
    ///
    /// * `data` - Binary-encoded message bytes.
    ///
    /// # Returns
    ///
    /// Deserialized Message.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if binary deserialization fails.
    pub fn from_binary(data: &[u8]) -> NetworkResult<Self> {
        use bincode::Options;
        bincode::options()
            .with_fixint_encoding()
            .with_limit(MAX_MESSAGE_DESERIALIZE_SIZE)
            .allow_trailing_bytes()
            .deserialize(data)
            .map_err(|e| NetworkError::SerializationError(format!("Binary decode failed: {}", e)))
    }

    /// Get the size of this message when serialized to binary.
    ///
    /// # Returns
    ///
    /// The binary size in bytes.
    pub fn binary_size(&self) -> NetworkResult<usize> {
        self.to_binary().map(|b| b.len())
    }

    /// Get the size of this message when serialized to JSON.
    ///
    /// # Returns
    ///
    /// The JSON size in bytes.
    pub fn json_size(&self) -> NetworkResult<usize> {
        self.to_json().map(|j| j.len())
    }
}

/// Get the current Unix timestamp in seconds.
///
/// # Returns
///
/// Current Unix timestamp.
///
/// # Errors
///
/// Returns `NetworkError` if system time is before UNIX_EPOCH.
fn current_timestamp() -> NetworkResult<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| NetworkError::TimestampError("System time before UNIX_EPOCH".to_string()))
}

/// Generate a unique message ID using BLAKE3 hash.
///
/// The ID is a deterministic hash of sender, topic, payload, and timestamp.
///
/// # Arguments
///
/// * `sender` - The sender's peer ID.
/// * `topic` - The message topic.
/// * `payload` - The message payload.
/// * `timestamp` - The message timestamp.
///
/// # Returns
///
/// A 32-byte BLAKE3 hash as the message ID.
fn generate_message_id(sender: &[u8; 32], topic: &str, payload: &[u8], timestamp: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(sender);
    hasher.update(topic.as_bytes());
    hasher.update(payload);
    hasher.update(&timestamp.to_le_bytes());
    let hash = hasher.finalize();
    *hash.as_bytes()
}

#[cfg(test)]
mod pressure_tests {
    use super::*;

    #[test]
    fn warn_forward_channel_pressure_thresholds_match_existing_warn_behavior() {
        assert!(!channel_pressure_exceeds_half(5_000, 10_000));
        assert!(channel_pressure_exceeds_half(4_999, 10_000));
        assert!(!channel_pressure_exceeds_warn_threshold(2_000, 10_000));
        assert!(channel_pressure_exceeds_warn_threshold(1_999, 10_000));
    }

    #[test]
    fn warn_forward_channel_pressure_info_limiter_emits_first_and_rate_limits() {
        let limiter = ChannelPressureInfoLimiter::default();
        let key = channel_pressure_key("recv_pubsub_tx", Some(GossipStreamType::PubSub));
        let start = Instant::now();

        assert!(limiter.should_emit(key, start, CHANNEL_PRESSURE_INFO_INTERVAL));
        assert!(!limiter.should_emit(
            key,
            start + Duration::from_secs(1),
            CHANNEL_PRESSURE_INFO_INTERVAL
        ));
        assert!(limiter.should_emit(
            key,
            start + CHANNEL_PRESSURE_INFO_INTERVAL + Duration::from_millis(1),
            CHANNEL_PRESSURE_INFO_INTERVAL
        ));
    }

    #[test]
    fn warn_forward_channel_pressure_info_limiter_is_per_channel_stream() {
        let limiter = ChannelPressureInfoLimiter::default();
        let pubsub = channel_pressure_key("recv_pubsub_tx", Some(GossipStreamType::PubSub));
        let bulk = channel_pressure_key("recv_bulk_tx", Some(GossipStreamType::Bulk));
        let start = Instant::now();

        assert!(limiter.should_emit(pubsub, start, CHANNEL_PRESSURE_INFO_INTERVAL));
        assert!(limiter.should_emit(bulk, start, CHANNEL_PRESSURE_INFO_INTERVAL));
        assert!(!limiter.should_emit(
            pubsub,
            start + Duration::from_secs(1),
            CHANNEL_PRESSURE_INFO_INTERVAL
        ));
    }

    #[tokio::test]
    async fn recv_pump_pubsub_full_drops_instead_of_blocking() {
        let (tx, _rx) = mpsc::channel(1);
        let diagnostics = RecvPumpDiagnostics::new();
        let peer = ant_quic::PeerId([7; 32]);

        let first = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::PubSub,
            Bytes::from_static(b"one"),
            "recv_pubsub_tx",
            &diagnostics,
        )
        .await
        .unwrap();
        let second = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::PubSub,
            Bytes::from_static(b"two"),
            "recv_pubsub_tx",
            &diagnostics,
        )
        .await
        .unwrap();

        assert_eq!(first, ForwardGossipOutcome::Enqueued);
        assert_eq!(second, ForwardGossipOutcome::DroppedFull);

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.pubsub.produced_total, 2);
        assert_eq!(snapshot.pubsub.enqueued_total, 1);
        assert_eq!(snapshot.pubsub.dropped_full, 1);
        let peer_snapshot = snapshot.per_peer.get(&hex::encode(peer.0)).unwrap();
        assert_eq!(peer_snapshot.pubsub_produced, 2);
        assert_eq!(peer_snapshot.pubsub_dropped_full, 1);
    }

    #[tokio::test]
    async fn recv_pump_membership_full_blocks_instead_of_dropping() {
        // ADR 0009 §2: Membership and Bulk keep blocking sends. Lock that
        // policy in: a full Membership channel must not return DroppedFull;
        // it must await for capacity. We assert the await side by timing out
        // a second send while the first occupies the only slot.
        let (tx, mut rx) = mpsc::channel(1);
        let diagnostics = RecvPumpDiagnostics::new();
        let peer = ant_quic::PeerId([9; 32]);

        let first = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::Membership,
            Bytes::from_static(b"first"),
            "recv_membership_tx",
            &diagnostics,
        )
        .await
        .unwrap();
        assert_eq!(first, ForwardGossipOutcome::Enqueued);

        let pending = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::Membership,
            Bytes::from_static(b"second"),
            "recv_membership_tx",
            &diagnostics,
        );
        let blocked = tokio::time::timeout(std::time::Duration::from_millis(100), pending).await;
        assert!(
            blocked.is_err(),
            "Membership send must await capacity, not return DroppedFull"
        );

        // Drain to release the second send and confirm it then completes
        // (i.e. the await was the right behaviour, not a deadlock).
        rx.recv().await.expect("first message");
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.membership.produced_total, 2);
        assert_eq!(snapshot.membership.enqueued_total, 1);
        assert_eq!(
            snapshot.membership.dropped_full, 0,
            "Membership must never increment dropped_full per ADR 0009"
        );
    }

    #[tokio::test]
    async fn recv_pump_bulk_full_blocks_instead_of_dropping() {
        // ADR 0009 §2: Bulk follows Membership policy.
        let (tx, mut rx) = mpsc::channel(1);
        let diagnostics = RecvPumpDiagnostics::new();
        let peer = ant_quic::PeerId([10; 32]);

        forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::Bulk,
            Bytes::from_static(b"first"),
            "recv_bulk_tx",
            &diagnostics,
        )
        .await
        .unwrap();

        let pending = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::Bulk,
            Bytes::from_static(b"second"),
            "recv_bulk_tx",
            &diagnostics,
        );
        let blocked = tokio::time::timeout(std::time::Duration::from_millis(100), pending).await;
        assert!(
            blocked.is_err(),
            "Bulk send must await capacity, not return DroppedFull"
        );
        rx.recv().await.expect("first message");
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.bulk.dropped_full, 0);
    }

    #[tokio::test]
    async fn recv_pump_pubsub_sheds_control_under_near_full_but_preserves_eager() {
        // ADR 0010: when the PubSub channel is near-full (>90%, available < max/10), recoverable
        // control frames (IHAVE/IWANT/AntiEntropy) are shed so the last slots
        // stay available for data (EAGER). EAGER is never silently shed — when
        // the channel is truly full it hard-drops (dropped_full) as ADR 0009
        // already specified. WHY it matters: preserving EAGER under bursts
        // keeps payload delivery flowing while sacrificing only frames that
        // PlumTree can recover via IHAVE/IWANT.
        use saorsa_gossip_pubsub::GossipMessage;
        use saorsa_gossip_types::{MessageHeader, MessageKind, TopicId};

        fn frame(kind: MessageKind) -> Bytes {
            let msg = GossipMessage {
                header: MessageHeader {
                    version: 1,
                    topic: TopicId::new([0u8; 32]),
                    msg_id: [0u8; 32],
                    kind,
                    hop: 0,
                    ttl: 10,
                },
                payload: None,
                signature: Vec::new(),
                public_key: Vec::new(),
            };
            postcard::to_stdvec(&msg).expect("frame serializes").into()
        }

        // Capacity 20: the shed threshold (available*10 < max) activates at
        // available <= 1, so 19/20 full still leaves one slot to prove the
        // control frame is shed while EAGER claims that slot.
        let (tx, _rx) = mpsc::channel::<GossipPayload>(20);
        let diagnostics = RecvPumpDiagnostics::new();
        let peer = ant_quic::PeerId([11; 32]);

        for _ in 0..19 {
            tx.try_send(GossipPayload {
                peer_id: peer,
                data: Bytes::from_static(b"x"),
                enqueued_at: Instant::now(),
            })
            .expect("prefill should fit");
        }
        assert_eq!(tx.capacity(), 1, "channel should have one free slot");

        // IHAVE (recoverable control) is shed; the free slot is preserved.
        let ihave = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::PubSub,
            frame(MessageKind::IHave),
            "recv_pubsub_tx",
            &diagnostics,
        )
        .await
        .unwrap();
        assert_eq!(ihave, ForwardGossipOutcome::Shed);
        assert_eq!(
            tx.capacity(),
            1,
            "shedding a control frame must not consume the preserved slot"
        );

        // EAGER (data) is NOT shed: it claims the preserved slot.
        let eager = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::PubSub,
            frame(MessageKind::Eager),
            "recv_pubsub_tx",
            &diagnostics,
        )
        .await
        .unwrap();
        assert_eq!(eager, ForwardGossipOutcome::Enqueued);
        assert_eq!(tx.capacity(), 0, "EAGER must claim the preserved slot");

        // Channel now full: EAGER hard-drops (dropped_full), never silently shed.
        let eager_full = forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::PubSub,
            frame(MessageKind::Eager),
            "recv_pubsub_tx",
            &diagnostics,
        )
        .await
        .unwrap();
        assert_eq!(eager_full, ForwardGossipOutcome::DroppedFull);

        let snapshot = diagnostics.snapshot();
        assert_eq!(
            snapshot.pubsub.shed_priority, 1,
            "exactly one recoverable control frame shed"
        );
        assert_eq!(
            snapshot.pubsub.dropped_full, 1,
            "EAGER hard-dropped exactly once when the channel was full"
        );
        assert_eq!(
            snapshot.pubsub.enqueued_total, 1,
            "exactly one EAGER enqueued into the preserved slot"
        );
    }

    #[tokio::test]
    async fn recv_pump_drop_warn_is_rate_limited() {
        // Saturate PubSub channel and confirm the drop WARN limiter only
        // releases on the configured interval boundary. The drop counter
        // remains the authoritative signal; the WARN should fire sparsely.
        let limiter = ChannelPressureInfoLimiter::default();
        let key = channel_pressure_key("recv_pubsub_tx", Some(GossipStreamType::PubSub));
        let start = Instant::now();
        assert!(limiter.should_emit(key, start, CHANNEL_PRESSURE_INFO_INTERVAL));
        // Subsequent drops within the interval do not re-emit.
        for offset_ms in [10, 100, 1_000, 5_000, 29_999] {
            assert!(!limiter.should_emit(
                key,
                start + Duration::from_millis(offset_ms),
                CHANNEL_PRESSURE_INFO_INTERVAL,
            ));
        }
        // After the interval, the next drop WARN releases.
        assert!(limiter.should_emit(
            key,
            start + CHANNEL_PRESSURE_INFO_INTERVAL + Duration::from_millis(1),
            CHANNEL_PRESSURE_INFO_INTERVAL,
        ));
    }

    #[tokio::test]
    async fn warn_forward_channel_pressure_warn_limiter_is_independent_of_info_and_drop() {
        // Three limiter instances must hold their own state so that a >50%
        // INFO emission cannot suppress a subsequent >80% WARN, and the drop
        // WARN limiter cannot suppress either pressure log. Each is a fresh
        // ChannelPressureInfoLimiter — sharing the same underlying type is
        // intentional, but the three statics in production must be distinct.
        let info = ChannelPressureInfoLimiter::default();
        let warn = ChannelPressureInfoLimiter::default();
        let drop = ChannelPressureInfoLimiter::default();
        let key = channel_pressure_key("recv_pubsub_tx", Some(GossipStreamType::PubSub));
        let now = Instant::now();
        assert!(info.should_emit(key, now, CHANNEL_PRESSURE_INFO_INTERVAL));
        assert!(warn.should_emit(key, now, CHANNEL_PRESSURE_INFO_INTERVAL));
        assert!(drop.should_emit(key, now, CHANNEL_PRESSURE_INFO_INTERVAL));
        // Each limiter independently rate-limits its own next emission.
        assert!(!info.should_emit(
            key,
            now + Duration::from_secs(1),
            CHANNEL_PRESSURE_INFO_INTERVAL,
        ));
        assert!(!warn.should_emit(
            key,
            now + Duration::from_secs(1),
            CHANNEL_PRESSURE_INFO_INTERVAL,
        ));
        assert!(!drop.should_emit(
            key,
            now + Duration::from_secs(1),
            CHANNEL_PRESSURE_INFO_INTERVAL,
        ));
    }

    #[tokio::test]
    async fn recv_pump_records_dequeue_dwell() {
        let (tx, rx) = mpsc::channel(1);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let diagnostics = RecvPumpDiagnostics::new();
        let peer = ant_quic::PeerId([8; 32]);

        forward_gossip_payload(
            &tx,
            peer,
            GossipStreamType::PubSub,
            Bytes::from_static(b"payload"),
            "recv_pubsub_tx",
            &diagnostics,
        )
        .await
        .unwrap();
        let (got_peer, got_data) = NetworkNode::receive_from_gossip_channel(
            &rx,
            &diagnostics,
            GossipStreamType::PubSub,
            "PubSub",
        )
        .await
        .unwrap();

        assert_eq!(got_peer, ant_to_gossip_peer_id(&peer));
        assert_eq!(got_data, Bytes::from_static(b"payload"));
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.pubsub.dequeued_total, 1);
        assert_eq!(snapshot.pubsub.enqueued_total, 1);
    }
}

#[cfg(test)]
mod message_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_message_creation() {
        let sender = [1; 32];
        let topic = "test".to_string();
        let payload = b"Hello".to_vec();

        let msg = Message::new(sender, topic.clone(), payload.clone()).unwrap();

        assert_eq!(msg.sender, sender);
        assert_eq!(msg.topic, topic);
        assert_eq!(msg.payload, payload);
        assert!(msg.timestamp > 0);
        assert_eq!(msg.sequence, 0);
        assert_ne!(msg.id, [0; 32]);
    }

    #[test]
    fn test_message_with_sequence() {
        let sender = [2; 32];
        let topic = "ordered".to_string();
        let payload = b"Message 42".to_vec();
        let sequence = 42u64;

        let msg = Message::with_sequence(sender, topic, payload, sequence).unwrap();

        assert_eq!(msg.sequence, 42);
        assert_eq!(msg.sender, sender);
    }

    #[test]
    fn test_message_json_roundtrip() {
        let sender = [3; 32];
        let topic = "json".to_string();
        let payload = b"Test payload".to_vec();

        let original = Message::new(sender, topic, payload).unwrap();

        let json = original.to_json().unwrap();
        let deserialized = Message::from_json(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_message_binary_roundtrip() {
        let sender = [4; 32];
        let topic = "binary".to_string();
        let payload = b"Binary test".to_vec();

        let original = Message::new(sender, topic, payload).unwrap();

        let binary = original.to_binary().unwrap();
        let deserialized = Message::from_binary(&binary).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_message_binary_size() {
        let sender = [6; 32];
        let topic = "sizing".to_string();
        let payload = b"Payload for size test".to_vec();

        let msg = Message::new(sender, topic, payload).unwrap();

        let binary_size = msg.binary_size().unwrap();
        assert!(binary_size > 0);

        let json_size = msg.json_size().unwrap();
        assert!(json_size > 0);

        assert!(json_size > binary_size);
    }

    #[test]
    fn test_message_empty_payload() {
        let sender = [7; 32];
        let topic = "empty".to_string();
        let payload = Vec::new();

        let msg = Message::new(sender, topic, payload).unwrap();

        assert_eq!(msg.payload.len(), 0);
        assert_ne!(msg.id, [0; 32]);
    }

    #[test]
    fn test_message_large_payload() {
        let sender = [8; 32];
        let topic = "large".to_string();
        let payload = vec![42u8; 10000];

        let msg = Message::new(sender, topic, payload.clone()).unwrap();

        assert_eq!(msg.payload.len(), 10000);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_message_unicode_topic() {
        let sender = [10; 32];
        let topic = "тема/главная/система".to_string();
        let payload = b"Unicode test".to_vec();

        let msg = Message::new(sender, topic.clone(), payload).unwrap();

        assert_eq!(msg.topic, topic);

        let json = msg.to_json().unwrap();
        let deserialized = Message::from_json(&json).unwrap();
        assert_eq!(deserialized.topic, topic);
    }

    #[test]
    fn test_current_timestamp_positive() {
        let ts = current_timestamp().unwrap();
        assert!(ts > 1600000000);
        assert!(ts < 2000000000);
    }

    #[test]
    fn default_max_connections_value() {
        assert_eq!(default_max_connections(), 32);
    }

    #[test]
    fn default_port_mapping_enabled_value() {
        assert!(default_port_mapping_enabled());
    }

    #[test]
    fn default_connection_timeout_value() {
        assert_eq!(default_connection_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn default_stats_interval_value() {
        assert_eq!(default_stats_interval(), Duration::from_secs(60));
    }

    #[test]
    fn default_max_peers_per_ip_value() {
        assert_eq!(default_max_peers_per_ip(), 3);
    }

    #[test]
    fn network_config_defaults_are_consistent() {
        let config = NetworkConfig::default();
        assert_eq!(config.max_connections, default_max_connections());
        assert_eq!(config.port_mapping_enabled, default_port_mapping_enabled());
        assert_eq!(config.connection_timeout, default_connection_timeout());
        assert_eq!(config.stats_interval, default_stats_interval());
        assert_eq!(config.max_peers_per_ip, default_max_peers_per_ip());
    }
}
