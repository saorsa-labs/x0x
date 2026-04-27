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
//! Default bootstrap nodes:
//! - `142.93.199.50:5483` - NYC, US (DigitalOcean)
//! - `147.182.234.192:5483` - SFO, US (DigitalOcean)
//! - `65.21.157.229:5483` - Helsinki, FI (Hetzner)
//! - `116.203.101.172:5483` - Nuremberg, DE (Hetzner)
//! - `152.42.210.67:5483` - Singapore, SG (DigitalOcean)
//! - `170.64.176.102:5483` - Sydney, AU (DigitalOcean)

use crate::error::{NetworkError, NetworkResult};
use ant_quic::{bootstrap_cache::PeerCapabilities, Node, NodeConfig, TransportAddr};
use bytes::Bytes;
use saorsa_gossip_transport::GossipStreamType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Ant-quic PeerId type alias
type AntPeerId = ant_quic::PeerId;
/// Saorsa gossip PeerId type alias
type GossipPeerId = saorsa_gossip_types::PeerId;
type GossipPayload = (AntPeerId, Bytes);

/// Default port for x0x nodes (when specified).
/// Default QUIC port: 5483 (LIVE on a phone keypad).
pub const DEFAULT_PORT: u16 = 5483;

/// Default health/metrics port.
pub const DEFAULT_METRICS_PORT: u16 = 12600;

/// Default maximum connections.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 100;

/// Default connection timeout.
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default stats collection interval.
pub const DEFAULT_STATS_INTERVAL: Duration = Duration::from_secs(60);

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
/// All nodes bind to `[::]:5483` (dual-stack: accepts both IPv4 and IPv6).
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
pub const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[
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
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
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

/// Stream type byte for direct messages (distinct from gossip: 0, 1, 2).
pub const DIRECT_MESSAGE_STREAM_TYPE: u8 = 0x10;

/// The x0x network node.
///
/// This wraps ant-quic's Node with x0x-specific functionality
/// including peer cache management and configuration.
async fn forward_gossip_payload(
    tx: &mpsc::Sender<GossipPayload>,
    peer_id: AntPeerId,
    stream_type: GossipStreamType,
    payload: Bytes,
    channel_name: &'static str,
) -> Result<(), mpsc::error::SendError<GossipPayload>> {
    let capacity = tx.capacity();
    let max_capacity = tx.max_capacity();
    if capacity.saturating_mul(5) < max_capacity {
        warn!(
            available = capacity,
            max = max_capacity,
            peer = ?peer_id,
            stream = ?stream_type,
            channel = channel_name,
            "[1/6 network] gossip receive channel >80% full — stream-specific back-pressure active"
        );
    }
    tx.send((peer_id, payload)).await
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
    /// Receiver channel for direct messages (separate from gossip).
    direct_tx: mpsc::Sender<(AntPeerId, Bytes)>,
    direct_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(AntPeerId, Bytes)>>>,
    /// Cached local peer ID (ant-quic PeerId).
    peer_id: AntPeerId,
    /// Bootstrap peer cache for recording connection outcomes.
    bootstrap_cache: Option<Arc<ant_quic::BootstrapCache>>,
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
            .data_channel_capacity(1024)
            .max_concurrent_uni_streams(10_000);

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
            direct_tx,
            direct_rx: Arc::new(tokio::sync::Mutex::new(direct_rx)),
            peer_id,
            bootstrap_cache,
        };

        network_node.spawn_receiver();
        network_node.spawn_accept_loop();

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

    /// Send data and wait for the remote receive pipeline to acknowledge
    /// (ant-quic 0.27.1 #172). Returns `None` when the network node is not
    /// yet initialised.
    pub async fn send_with_receive_ack(
        &self,
        peer_id: AntPeerId,
        data: &[u8],
        timeout: std::time::Duration,
    ) -> Option<Result<(), ant_quic::NodeError>> {
        let node = self.node.read().await.as_ref().cloned()?;
        Some(node.send_with_receive_ack(&peer_id, data, timeout).await)
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
                    peer_id_prefix = %hex_prefix(&peer_id.0, 4),
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

    /// Gracefully shutdown the node.
    ///
    /// Drops the inner node, closing all connections.
    pub async fn shutdown(&self) {
        let mut node_guard = self.node.write().await;
        // Taking the node drops it, closing all connections
        let _ = node_guard.take();
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
        // Check connection first
        if !self.is_connected(peer_id).await {
            return Err(NetworkError::NotConnected(peer_id.0));
        }

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

        info!(
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
        stream_name: &'static str,
    ) -> anyhow::Result<(GossipPeerId, Bytes)> {
        let mut rx = rx.lock().await;
        let (ant_peer, data) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("{stream_name} receive channel closed"))?;
        Ok((ant_to_gossip_peer_id(&ant_peer), data))
    }

    /// Receive the next PubSub gossip message from the dedicated PubSub queue.
    pub async fn receive_pubsub_message(&self) -> anyhow::Result<(GossipPeerId, Bytes)> {
        Self::receive_from_gossip_channel(&self.recv_pubsub_rx, "PubSub").await
    }

    /// Receive the next Membership gossip message from the dedicated Membership queue.
    pub async fn receive_membership_message(&self) -> anyhow::Result<(GossipPeerId, Bytes)> {
        Self::receive_from_gossip_channel(&self.recv_membership_rx, "Membership").await
    }

    /// Receive the next Bulk gossip message from the dedicated Bulk queue.
    pub async fn receive_bulk_message(&self) -> anyhow::Result<(GossipPeerId, Bytes)> {
        Self::receive_from_gossip_channel(&self.recv_bulk_rx, "Bulk").await
    }

    /// Spawn background receiver task that parses gossip stream types.
    ///
    /// This task continuously receives messages from ant-quic, parses the
    /// stream type from the first byte, and forwards parsed messages to:
    /// - Direct message channel (for 0x10 direct messages)
    /// - Gossip transport channel (for 0x00, 0x01, 0x02 gossip messages)
    fn spawn_receiver(&self) {
        let node = Arc::clone(&self.node);
        let recv_pubsub_tx = self.recv_pubsub_tx.clone();
        let recv_membership_tx = self.recv_membership_tx.clone();
        let recv_bulk_tx = self.recv_bulk_tx.clone();
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

                            info!(
                                "[1/6 network] recv direct: {} bytes from peer {:?}",
                                payload.len(),
                                peer_id
                            );
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

                        info!(
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
                                )
                                .await
                            }
                        };

                        if let Err(e) = forward_result {
                            error!("Failed to forward gossip message: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Receive error: {}", e);
                    }
                }
            }

            debug!("NetworkNode receiver task stopped");
        });
    }

    /// Spawn a background task that accepts inbound connections.
    ///
    /// Without this, only outbound connections (initiated by `connect_addr`)
    /// are registered in `connected_peers`. Inbound peers would complete the
    /// QUIC handshake but never have a reader task spawned, so `recv()` would
    /// never deliver their data.
    fn spawn_accept_loop(&self) {
        let node = Arc::clone(&self.node);
        let event_sender = self.event_sender.clone();
        let bootstrap_cache = self.bootstrap_cache.clone();
        let inbound_allowlist = self.config.inbound_allowlist.clone();

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
                    }
                    None => {
                        debug!("Accept loop ended (node shutting down)");
                        break;
                    }
                }
            }

            debug!("NetworkNode accept loop stopped");
        });
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

        // If not connected, try to establish a connection before giving up.
        // HyParView exchanges PeerIds via SHUFFLE without addresses, so peers
        // in the passive/active view may not yet have a QUIC connection.
        if !self.is_connected(&ant_peer).await {
            if let Err(e) = self.connect_cached_peer(ant_peer).await {
                return Err(anyhow::anyhow!(
                    "Peer {:?} not connected and bootstrap cache dial failed: {}",
                    peer,
                    e,
                ));
            }
        }

        // Prepare message: [stream_type_byte | data]
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(stream_type.to_byte());
        buf.extend_from_slice(&data);

        // Send via ant-quic Node
        let node_guard = self.node.read().await;
        let node = node_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("node not initialized"))?;

        node.send(&ant_peer, &buf)
            .await
            .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;

        info!(
            "[1/6 network] send: {} bytes ({:?}) to peer {:?}",
            buf.len(),
            stream_type,
            peer
        );

        Ok(())
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
                let (ant_peer, data) = msg.ok_or_else(|| anyhow::anyhow!("Bulk receive channel closed"))?;
                Ok((ant_to_gossip_peer_id(&ant_peer), GossipStreamType::Bulk, data))
            }
            msg = membership_rx.recv() => {
                let (ant_peer, data) = msg.ok_or_else(|| anyhow::anyhow!("Membership receive channel closed"))?;
                Ok((ant_to_gossip_peer_id(&ant_peer), GossipStreamType::Membership, data))
            }
            msg = pubsub_rx.recv() => {
                let (ant_peer, data) = msg.ok_or_else(|| anyhow::anyhow!("PubSub receive channel closed"))?;
                Ok((ant_to_gossip_peer_id(&ant_peer), GossipStreamType::PubSub, data))
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

        // Verify default bootstrap nodes are included
        assert_eq!(
            config.bootstrap_nodes.len(),
            12,
            "Should have 12 default bootstrap nodes (6 IPv4 + 6 IPv6)"
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
}
