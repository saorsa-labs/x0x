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
//! - `142.93.199.50:12000` - NYC, US
//! - `147.182.234.192:12000` - SFO, US
//! - `65.21.157.229:12000` - Helsinki, FI
//! - `116.203.101.172:12000` - Nuremberg, DE
//! - `149.28.156.231:12000` - Singapore, SG
//! - `45.77.176.184:12000` - Tokyo, JP

use crate::error::{NetworkError, NetworkResult};
use ant_quic::{Node, NodeConfig, TransportAddr};
use bytes::Bytes;
use rand::seq::SliceRandom;
use saorsa_gossip_transport::GossipStreamType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, warn};

/// Ant-quic PeerId type alias
type AntPeerId = ant_quic::PeerId;
/// Saorsa gossip PeerId type alias
type GossipPeerId = saorsa_gossip_types::PeerId;

/// Default port for x0x nodes (when specified).
pub const DEFAULT_PORT: u16 = 12000;

/// Default health/metrics port.
pub const DEFAULT_METRICS_PORT: u16 = 12600;

/// Default maximum connections.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 100;

/// Default connection timeout.
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default stats collection interval.
pub const DEFAULT_STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Default bootstrap nodes for the x0x network.
///
/// These are Saorsa Labs VPS nodes running x0x-bootstrap with coordinator/reflector
/// roles. They form a globally distributed mesh providing bootstrap, NAT traversal,
/// and rendezvous services.
///
/// All nodes bind to `[::]:12000` (dual-stack: accepts both IPv4 and IPv6).
/// IPv6 addresses are included for nodes that have global IPv6 connectivity.
///
/// Locations:
/// - `142.93.199.50` / `2604:a880:400:d1:0:3:7db3:f001` — NYC, US (DigitalOcean)
/// - `147.182.234.192` / `2604:a880:4:1d0:0:1:6ba1:f000` — SFO, US (DigitalOcean)
/// - `65.21.157.229` / `2a01:4f9:c012:684b::1` — Helsinki, FI (Hetzner)
/// - `116.203.101.172` / `2a01:4f8:1c1a:31e6::1` — Nuremberg, DE (Hetzner)
/// - `149.28.156.231` / `2001:19f0:4401:346:5400:5ff:fed9:9735` — Singapore, SG (Vultr)
/// - `45.77.176.184` / `2401:c080:1000:4c32:5400:5ff:fed9:9737` — Tokyo, JP (Vultr)
///
/// Agents can override these by calling `AgentBuilder::with_network_config`
/// with a custom [`NetworkConfig`] containing different bootstrap nodes.
pub const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[
    // IPv4
    "142.93.199.50:12000",            // NYC
    "147.182.234.192:12000",          // SFO
    "65.21.157.229:12000",            // Helsinki
    "116.203.101.172:12000",          // Nuremberg
    "149.28.156.231:12000",           // Singapore
    "45.77.176.184:12000",            // Tokyo
    // IPv6
    "[2604:a880:400:d1:0:3:7db3:f001]:12000",          // NYC
    "[2604:a880:4:1d0:0:1:6ba1:f000]:12000",           // SFO
    "[2a01:4f9:c012:684b::1]:12000",                    // Helsinki
    "[2a01:4f8:1c1a:31e6::1]:12000",                    // Nuremberg
    "[2001:19f0:4401:346:5400:5ff:fed9:9735]:12000",    // Singapore
    "[2401:c080:1000:4c32:5400:5ff:fed9:9737]:12000",   // Tokyo
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

impl Default for NetworkConfig {
    fn default() -> Self {
        // Parse default bootstrap peers
        let bootstrap_nodes = DEFAULT_BOOTSTRAP_PEERS
            .iter()
            .filter_map(|addr| addr.parse().ok())
            .collect();

        Self {
            bind_addr: None,
            bootstrap_nodes,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            stats_interval: DEFAULT_STATS_INTERVAL,
            peer_cache_path: None,
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

/// The x0x network node.
///
/// This wraps ant-quic's Node with x0x-specific functionality
/// including peer cache management and configuration.
#[derive(Debug, Clone)]
pub struct NetworkNode {
    /// ant-quic P2P node (wrapped in `Arc<RwLock>` for shared async access).
    node: Arc<RwLock<Option<Node>>>,
    /// Configuration for this node.
    config: NetworkConfig,
    /// Sender for broadcasting network events.
    event_sender: broadcast::Sender<NetworkEvent>,
    /// Receiver channel for gossip messages (with stream type parsing).
    /// Used by GossipTransport::receive_message().
    recv_tx: mpsc::Sender<(AntPeerId, GossipStreamType, Bytes)>,
    recv_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(AntPeerId, GossipStreamType, Bytes)>>>,
    /// Cached local peer ID (ant-quic PeerId).
    peer_id: AntPeerId,
}

impl NetworkNode {
    /// Create a new network node with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Network configuration options.
    ///
    /// # Returns
    ///
    /// A new NetworkNode on success.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if node creation fails.
    pub async fn new(config: NetworkConfig) -> NetworkResult<Self> {
        let mut builder = NodeConfig::builder();

        if let Some(bind_addr) = config.bind_addr {
            builder = builder.bind_addr(bind_addr);
        }

        for peer_addr in &config.bootstrap_nodes {
            builder = builder.known_peer(*peer_addr);
        }

        let node = Node::with_config(builder.build()).await.map_err(|e| {
            NetworkError::NodeCreation(format!("Failed to create ant-quic node: {}", e))
        })?;

        let peer_id = node.peer_id();
        let (event_sender, _event_receiver) = broadcast::channel(32);
        let (recv_tx, recv_rx) = mpsc::channel(128);

        let network_node = Self {
            node: Arc::new(RwLock::new(Some(node))),
            config,
            event_sender,
            recv_tx,
            recv_rx: Arc::new(tokio::sync::Mutex::new(recv_rx)),
            peer_id,
        };

        network_node.spawn_receiver();

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

    /// Get the local socket address.
    ///
    /// # Returns
    ///
    /// The local address this node is bound to.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.config.bind_addr
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
        let peer_conn = node
            .connect_addr(addr)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        self.emit_event(NetworkEvent::PeerConnected {
            peer_id: peer_conn.peer_id.0,
            address: addr,
        });

        Ok(peer_conn.peer_id)
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
    pub async fn connect_peer(&self, peer_id: AntPeerId) -> NetworkResult<SocketAddr> {
        let node = self.require_node().await?;
        let peer_conn = node
            .connect(peer_id)
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

        self.emit_event(NetworkEvent::PeerConnected {
            peer_id: peer_conn.peer_id.0,
            address: addr,
        });

        Ok(addr)
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

    /// Spawn background receiver task that parses gossip stream types.
    ///
    /// This task continuously receives messages from ant-quic, parses the
    /// stream type from the first byte, and forwards parsed messages to
    /// the internal channel for GossipTransport::receive_message().
    fn spawn_receiver(&self) {
        let node = Arc::clone(&self.node);
        let recv_tx = self.recv_tx.clone();

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

                match node_ref.recv().await {
                    Ok((peer_id, data)) => {
                        if data.is_empty() {
                            continue;
                        }

                        // Parse stream type from first byte (safe: data is non-empty)
                        let type_byte = data[0];
                        let stream_type = match GossipStreamType::from_byte(type_byte) {
                            Some(st) => st,
                            None => {
                                warn!("Unknown stream type byte: {}", type_byte);
                                continue;
                            }
                        };

                        // Extract payload (everything after the type byte)
                        let payload = Bytes::copy_from_slice(&data[1..]);

                        if let Err(e) = recv_tx.send((peer_id, stream_type, payload)).await {
                            error!("Failed to forward message: {}", e);
                            break;
                        }

                        debug!(
                            "Forwarded {} bytes ({:?}) from peer {:?}",
                            data.len() - 1,
                            stream_type,
                            peer_id
                        );
                    }
                    Err(e) => {
                        debug!("Receive error: {}", e);
                    }
                }
            }

            debug!("NetworkNode receiver task stopped");
        });
    }
}

// ============================================================================
// PeerId Conversion Helpers
// ============================================================================

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

        // Check if connected
        if !self.is_connected(&ant_peer).await {
            return Err(anyhow::anyhow!("Peer {:?} not connected", peer));
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

        debug!(
            "Sent {} bytes ({:?}) to peer {:?}",
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
        let mut recv_rx = self.recv_rx.lock().await;

        let (ant_peer, stream_type, data) = recv_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Receive channel closed"))?;

        Ok((ant_to_gossip_peer_id(&ant_peer), stream_type, data))
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

/// In-memory peer cache for bootstrap persistence.
///
/// Uses epsilon-greedy algorithm for peer selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCache {
    /// Cached peers with their addresses and success metrics.
    peers: Vec<CachedPeer>,
    /// Path to the cache file.
    #[serde(skip)]
    #[allow(dead_code)]
    cache_path: PathBuf,
    /// Epsilon value for epsilon-greedy selection.
    epsilon: f64,
}

impl PeerCache {
    /// Load peer cache from disk, or create a new one.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the cache file.
    ///
    /// # Returns
    ///
    /// A new PeerCache, either loaded or created.
    pub async fn load_or_create(path: &PathBuf) -> NetworkResult<Self> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| NetworkError::CacheError(e.to_string()))?;
            }
        }

        if path.exists() {
            let data = tokio::fs::read(path)
                .await
                .map_err(|e| NetworkError::CacheError(e.to_string()))?;
            let cache: PeerCache =
                bincode::deserialize(&data).map_err(|e| NetworkError::CacheError(e.to_string()))?;
            return Ok(cache);
        }

        Ok(Self {
            peers: Vec::new(),
            cache_path: path.clone(),
            epsilon: 0.1, // 10% exploration rate
        })
    }

    /// Add a peer to the cache.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's ID.
    /// * `address` - The peer's address.
    pub fn add_peer(&mut self, peer_id: [u8; 32], address: SocketAddr) {
        // Update existing peer or add new one.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0); // Fallback to 0 if system time is invalid (extremely unlikely)

        if let Some(existing) = self.peers.iter_mut().find(|p| p.peer_id == peer_id) {
            existing.address = address;
            existing.success_count += 1;
            existing.last_seen = now;
        } else {
            self.peers.push(CachedPeer {
                peer_id,
                address,
                success_count: 1,
                attempt_count: 0,
                last_seen: now,
                last_attempt: 0,
            });
        }
    }

    /// Select peers using epsilon-greedy algorithm.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of peers to select.
    ///
    /// # Returns
    ///
    /// A vector of peer addresses.
    pub fn select_peers(&self, count: usize) -> Vec<SocketAddr> {
        if self.peers.is_empty() {
            return Vec::new();
        }

        let mut sorted_peers: Vec<_> = self.peers.iter().collect();

        // Sort by success rate (descending).
        sorted_peers.sort_by(|a, b| {
            let a_rate = a.success_count as f64 / (a.attempt_count.max(1) as f64);
            let b_rate = b.success_count as f64 / (b.attempt_count.max(1) as f64);
            b_rate
                .partial_cmp(&a_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let exploit_count = ((count as f64) * (1.0 - self.epsilon)).floor() as usize;
        let explore_count =
            (count - exploit_count).min(self.peers.len().saturating_sub(exploit_count));

        let mut selected: Vec<SocketAddr> = sorted_peers[..exploit_count.min(count)]
            .iter()
            .map(|p| p.address)
            .collect();

        // Add random exploration peers from the remaining pool.
        let explore_pool = &sorted_peers[exploit_count..];
        if !explore_pool.is_empty() {
            let mut rng = rand::thread_rng();
            for _ in 0..explore_count {
                if let Some(random_peer) = explore_pool.choose(&mut rng) {
                    selected.push(random_peer.address);
                }
            }
        }

        selected
    }

    /// Save the peer cache to disk.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to save to (overrides the original path).
    ///
    /// # Errors
    ///
    /// Returns an error if saving fails.
    pub async fn save(&self, path: &PathBuf) -> NetworkResult<()> {
        let data = bincode::serialize(self).map_err(|e| NetworkError::CacheError(e.to_string()))?;
        tokio::fs::write(path, data)
            .await
            .map_err(|e| NetworkError::CacheError(e.to_string()))?;
        Ok(())
    }

    /// Get the number of cached peers.
    ///
    /// # Returns
    ///
    /// The number of peers in the cache.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if the cache is empty.
    ///
    /// # Returns
    ///
    /// True if the cache has no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// A cached peer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedPeer {
    /// The peer's ID.
    peer_id: [u8; 32],
    /// The peer's address.
    address: SocketAddr,
    /// Number of successful connections.
    success_count: u32,
    /// Number of connection attempts.
    attempt_count: u32,
    /// Timestamp of last successful connection.
    last_seen: u64,
    /// Timestamp of last connection attempt.
    last_attempt: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use saorsa_gossip_transport::GossipTransport;

    #[tokio::test]
    async fn test_gossip_transport_trait() {
        let config = NetworkConfig::default();
        let node = NetworkNode::new(config).await.unwrap();

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
    async fn test_peer_cache_add_and_select() {
        let mut cache = PeerCache {
            peers: Vec::new(),
            cache_path: PathBuf::from("/tmp/test_peer_cache.bin"),
            epsilon: 0.1,
        };

        // Add some peers.
        cache.add_peer([1; 32], "127.0.0.1:9000".parse().unwrap());
        cache.add_peer([2; 32], "127.0.0.1:9001".parse().unwrap());
        cache.add_peer([3; 32], "127.0.0.1:9002".parse().unwrap());

        // Select peers.
        let selected = cache.select_peers(2);
        assert_eq!(selected.len(), 2);
    }

    #[tokio::test]
    async fn test_peer_cache_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("peer_cache.bin");

        {
            let mut cache = PeerCache {
                peers: Vec::new(),
                cache_path: cache_path.clone(),
                epsilon: 0.1,
            };

            cache.add_peer([1; 32], "127.0.0.1:9000".parse().unwrap());
            cache.save(&cache_path).await.unwrap();
        }

        // Load from disk.
        let loaded = PeerCache::load_or_create(&cache_path).await.unwrap();
        assert_eq!(loaded.len(), 1);
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
async fn test_peer_cache_epsilon_greedy_selection() {
    let mut cache = PeerCache {
        peers: Vec::new(),
        cache_path: PathBuf::from("/tmp/test"),
        epsilon: 0.5, // 50% exploration for testing
    };

    // Add peers with different success rates
    // Peer A: 10 attempts, 9 successes (90% success rate)
    cache.peers.push(CachedPeer {
        peer_id: [1; 32],
        address: "127.0.0.1:9000".parse().unwrap(),
        success_count: 9,
        attempt_count: 10,
        last_seen: 0,
        last_attempt: 0,
    });

    // Peer B: 10 attempts, 5 successes (50% success rate)
    cache.peers.push(CachedPeer {
        peer_id: [2; 32],
        address: "127.0.0.1:9001".parse().unwrap(),
        success_count: 5,
        attempt_count: 10,
        last_seen: 0,
        last_attempt: 0,
    });

    // Peer C: 10 attempts, 2 successes (20% success rate)
    cache.peers.push(CachedPeer {
        peer_id: [3; 32],
        address: "127.0.0.1:9002".parse().unwrap(),
        success_count: 2,
        attempt_count: 10,
        last_seen: 0,
        last_attempt: 0,
    });

    // Select 2 peers with 50% exploration
    // Should mostly select A, sometimes B or C
    let selected = cache.select_peers(2);
    assert_eq!(selected.len(), 2);

    // Peer A (highest success rate) should always be in selection
    assert!(selected.contains(&"127.0.0.1:9000".parse().unwrap()));
}

#[tokio::test]
async fn test_peer_cache_empty() {
    let cache = PeerCache {
        peers: Vec::new(),
        cache_path: PathBuf::from("/tmp/test"),
        epsilon: 0.1,
    };

    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
    assert!(cache.select_peers(5).is_empty());
}

#[tokio::test]
async fn test_network_node_subscribe_events() {
    let config = NetworkConfig::default();
    let node = NetworkNode::new(config).await.unwrap();

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
    let node = NetworkNode::new(config).await.unwrap();

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
/// See: .planning/ant-quic-phantom-connections.md
#[tokio::test]
async fn test_mesh_connections_are_bidirectional() {
    const NODE_COUNT: usize = 4;
    let base_port: u16 = 19200;

    // Create N nodes with explicit bind addresses and no bootstrap peers
    let mut nodes = Vec::with_capacity(NODE_COUNT);
    let mut addrs = Vec::with_capacity(NODE_COUNT);

    for i in 0..NODE_COUNT {
        let addr: SocketAddr = format!("127.0.0.1:{}", base_port + i as u16)
            .parse()
            .unwrap();
        addrs.push(addr);

        let config = NetworkConfig {
            bind_addr: Some(addr),
            bootstrap_nodes: Vec::new(),
            max_connections: 100,
            connection_timeout: std::time::Duration::from_secs(10),
            stats_interval: std::time::Duration::from_secs(60),
            peer_cache_path: None,
        };

        let node = NetworkNode::new(config).await.unwrap();
        nodes.push(node);
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
                (i, j, node.connect_addr(addr).await)
            }));
        }
    }

    // Wait for all connections
    for handle in handles {
        let (from, to, result) = handle.await.unwrap();
        if let Err(e) = &result {
            eprintln!("Connection {}->{} failed: {}", from, to, e);
        }
    }

    // Allow connections to stabilize
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // CRITICAL CHECK: Every node must see exactly (NODE_COUNT - 1) peers.
    // A phantom connection bug would cause asymmetry: one node sees fewer
    // peers than others because the acceptor side never registered the
    // connection.
    let mut counts = Vec::with_capacity(NODE_COUNT);
    for (i, node) in nodes.iter().enumerate() {
        let count = node.connection_count().await;
        eprintln!("Node {} (:{}) has {} peers", i, base_port + i as u16, count);
        counts.push(count);
    }

    let expected = NODE_COUNT - 1;
    for (i, count) in counts.iter().enumerate() {
        assert_eq!(
            *count, expected,
            "Node {} has {} peers, expected {} — possible phantom connection (asymmetric state)",
            i, count, expected
        );
    }

    // BIDIRECTIONALITY CHECK: For every pair (A, B), if A sees B as connected
    // then B must also see A as connected.
    for i in 0..NODE_COUNT {
        let peers_i = nodes[i].connected_peers().await;
        for j in 0..NODE_COUNT {
            if i == j {
                continue;
            }
            let peers_j = nodes[j].connected_peers().await;
            let j_peer_id = nodes[j].peer_id();

            let i_sees_j = peers_i.contains(&j_peer_id);
            if i_sees_j {
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
        bincode::deserialize(data)
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
