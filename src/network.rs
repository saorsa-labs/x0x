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
use ant_quic::{Node, NodeConfig};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};

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
/// Locations:
/// - `142.93.199.50` - NYC, US (DigitalOcean)
/// - `147.182.234.192` - SFO, US (DigitalOcean)
/// - `65.21.157.229` - Helsinki, FI (Hetzner)
/// - `116.203.101.172` - Nuremberg, DE (Hetzner)
/// - `149.28.156.231` - Singapore, SG (Vultr)
/// - `45.77.176.184` - Tokyo, JP (Vultr)
///
/// Agents can override these by calling `AgentBuilder::with_network_config`
/// with a custom [`NetworkConfig`] containing different bootstrap nodes.
pub const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[
    "142.93.199.50:12000",   // NYC
    "147.182.234.192:12000", // SFO
    "65.21.157.229:12000",   // Helsinki
    "116.203.101.172:12000", // Nuremberg
    "149.28.156.231:12000",  // Singapore
    "45.77.176.184:12000",   // Tokyo
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
    /// ant-quic P2P node (wrapped in Arc<RwLock> for shared async access).
    node: Arc<RwLock<Option<Node>>>,
    /// Configuration for this node.
    config: NetworkConfig,
    /// Sender for broadcasting network events.
    event_sender: broadcast::Sender<NetworkEvent>,
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
        // Create ant-quic NodeConfig using builder
        let mut builder = NodeConfig::builder();

        // Set bind address if specified
        if let Some(bind_addr) = config.bind_addr {
            builder = builder.bind_addr(bind_addr);
        }

        // Add bootstrap peers
        for peer_addr in &config.bootstrap_nodes {
            builder = builder.known_peer(*peer_addr);
        }

        let node_config = builder.build();

        // Create ant-quic Node (this binds QUIC transport)
        let node = Node::with_config(node_config)
            .await
            .map_err(|e| NetworkError::NodeCreation(format!("Failed to create ant-quic node: {}", e)))?;

        let (event_sender, _event_receiver) = broadcast::channel(32);

        Ok(Self {
            node: Arc::new(RwLock::new(Some(node))),
            config,
            event_sender,
        })
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
        let node_guard = self.node.read().await;
        if let Some(node) = node_guard.as_ref() {
            let status = node.status().await;
            NetworkStats {
                total_connections: status.direct_connections + status.relayed_connections,
                active_connections: status.active_connections as u32,
                bytes_sent: status.relay_bytes_forwarded,  // Approximate with relay bytes
                bytes_received: 0,  // TODO: Track in future
                peer_count: status.connected_peers,
            }
        } else {
            NetworkStats::default()
        }
    }

    /// Get the number of active connections.
    ///
    /// # Returns
    ///
    /// The number of currently connected peers.
    pub async fn connection_count(&self) -> usize {
        let node_guard = self.node.read().await;
        if let Some(node) = node_guard.as_ref() {
            let status = node.status().await;
            status.connected_peers
        } else {
            0
        }
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

    /// Gracefully shutdown the node.
    ///
    /// This closes all connections and stops the node.
    pub async fn shutdown(&self) {
        // Placeholder for node shutdown
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

        // Add random exploration peers.
        if explore_count > 0 && self.peers.len() > exploit_count {
            let explore_from: Vec<_> = sorted_peers[exploit_count..].to_vec();

            // Convert Vec<&CachedPeer> to slice for choose()
            let explore_slice: Vec<CachedPeer> = explore_from.iter().map(|&p| p.clone()).collect();
            let explore_refs: Vec<&CachedPeer> = explore_slice.iter().collect();

            let mut rng = rand::thread_rng();
            for _ in 0..explore_count {
                if let Some(random_peer) = explore_refs.as_slice().choose(&mut rng) {
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

    #[test]
    fn test_network_config_defaults() {
        let config = NetworkConfig::default();

        assert!(config.bind_addr.is_none());

        // Verify default bootstrap nodes are included
        assert_eq!(
            config.bootstrap_nodes.len(),
            6,
            "Should have 6 default bootstrap nodes"
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
