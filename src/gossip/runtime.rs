//! Gossip runtime orchestration.

use super::config::GossipConfig;
use super::pubsub::{PubSubManager, SigningContext};
use crate::error::NetworkResult;
use crate::network::NetworkNode;
use crate::presence::PresenceWrapper;
use saorsa_gossip_membership::{HyParViewMembership, MembershipConfig};
use saorsa_gossip_transport::GossipStreamType;
use saorsa_gossip_types::PeerId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Maximum time to spend handling one inbound presence Bulk message.
///
/// Bulk has its own dispatcher, but a wedged presence handler must still be
/// bounded so future Bulk presence beacons continue to drain from the dedicated
/// Bulk receive queue.
const PRESENCE_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time to spend handling one inbound PubSub message.
const PUBSUB_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time to spend handling one inbound membership message.
const MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-stream dispatcher counters.
#[derive(Debug, Default)]
pub struct DispatchStreamStats {
    received: AtomicU64,
    completed: AtomicU64,
    timed_out: AtomicU64,
    max_elapsed_ms: AtomicU64,
}

/// JSON-friendly snapshot of per-stream dispatcher counters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchStreamStatsSnapshot {
    pub received: u64,
    pub completed: u64,
    pub timed_out: u64,
    pub max_elapsed_ms: u64,
}

impl DispatchStreamStats {
    fn record_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    fn record_completed(&self, elapsed: Duration) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.max_elapsed_ms
            .fetch_max(duration_ms(elapsed), Ordering::Relaxed);
    }

    fn record_timed_out(&self, elapsed: Duration) {
        self.timed_out.fetch_add(1, Ordering::Relaxed);
        self.max_elapsed_ms
            .fetch_max(duration_ms(elapsed), Ordering::Relaxed);
    }

    fn snapshot(&self) -> DispatchStreamStatsSnapshot {
        DispatchStreamStatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            max_elapsed_ms: self.max_elapsed_ms.load(Ordering::Relaxed),
        }
    }
}

/// Per-stream receive queue depth counters.
#[derive(Debug, Default)]
struct DispatchQueueStats {
    latest: AtomicU64,
    max: AtomicU64,
    capacity: AtomicU64,
}

/// JSON-friendly snapshot of receive queue depth counters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchQueueStatsSnapshot {
    pub latest: u64,
    pub max: u64,
    pub capacity: u64,
}

impl DispatchQueueStats {
    fn record(&self, depth: usize, capacity: usize) {
        let depth = usize_to_u64(depth);
        let capacity = usize_to_u64(capacity);
        self.latest.store(depth, Ordering::Relaxed);
        self.max.fetch_max(depth, Ordering::Relaxed);
        self.capacity.store(capacity, Ordering::Relaxed);
    }

    fn snapshot(&self) -> DispatchQueueStatsSnapshot {
        DispatchQueueStatsSnapshot {
            latest: self.latest.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
            capacity: self.capacity.load(Ordering::Relaxed),
        }
    }
}

/// Dispatcher counters for the inbound gossip receive pipeline.
#[derive(Debug, Default)]
pub struct GossipDispatchStats {
    pubsub: DispatchStreamStats,
    membership: DispatchStreamStats,
    bulk: DispatchStreamStats,
    pubsub_queue: DispatchQueueStats,
    membership_queue: DispatchQueueStats,
    bulk_queue: DispatchQueueStats,
}

/// JSON-friendly snapshot of [`GossipDispatchStats`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct GossipDispatchStatsSnapshot {
    pub pubsub: DispatchStreamStatsSnapshot,
    pub membership: DispatchStreamStatsSnapshot,
    pub bulk: DispatchStreamStatsSnapshot,
    pub recv_depth: DispatchQueueDepthSnapshot,
}

/// JSON-friendly snapshot of per-stream receive queue depths.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchQueueDepthSnapshot {
    pub pubsub: DispatchQueueStatsSnapshot,
    pub membership: DispatchQueueStatsSnapshot,
    pub bulk: DispatchQueueStatsSnapshot,
}

impl GossipDispatchStats {
    fn record_dequeue(&self, stream_type: GossipStreamType, depth: usize, capacity: usize) {
        match stream_type {
            GossipStreamType::PubSub => self.pubsub_queue.record(depth, capacity),
            GossipStreamType::Membership => self.membership_queue.record(depth, capacity),
            GossipStreamType::Bulk => self.bulk_queue.record(depth, capacity),
        }
    }

    /// Snapshot dispatcher counters.
    #[must_use]
    pub fn snapshot(&self) -> GossipDispatchStatsSnapshot {
        GossipDispatchStatsSnapshot {
            pubsub: self.pubsub.snapshot(),
            membership: self.membership.snapshot(),
            bulk: self.bulk.snapshot(),
            recv_depth: DispatchQueueDepthSnapshot {
                pubsub: self.pubsub_queue.snapshot(),
                membership: self.membership_queue.snapshot(),
                bulk: self.bulk_queue.snapshot(),
            },
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .ok()
        .map_or(u64::MAX, |ms| ms)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).ok().map_or(u64::MAX, |v| v)
}

/// The gossip runtime that manages all gossip components.
///
/// This orchestrates HyParView membership, SWIM failure detection,
/// and pub/sub messaging via the saorsa-gossip stack.
pub struct GossipRuntime {
    config: GossipConfig,
    network: Arc<NetworkNode>,
    membership: Arc<HyParViewMembership<NetworkNode>>,
    pubsub: Arc<PubSubManager>,
    peer_id: PeerId,
    presence: std::sync::Mutex<Option<Arc<PresenceWrapper>>>,
    dispatcher_handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    peer_sync_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    keepalive_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    dispatch_stats: Arc<GossipDispatchStats>,
}

impl std::fmt::Debug for GossipRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipRuntime")
            .field("config", &self.config)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

async fn run_pubsub_dispatcher(
    network: Arc<NetworkNode>,
    pubsub: Arc<PubSubManager>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    loop {
        match network.receive_pubsub_message().await {
            Ok((peer, data)) => {
                let (recv_depth, recv_capacity) =
                    network.gossip_recv_queue_depth(GossipStreamType::PubSub);
                dispatch_stats.record_dequeue(GossipStreamType::PubSub, recv_depth, recv_capacity);
                dispatch_stats.pubsub.record_received();
                let bytes = data.len();
                let started = Instant::now();
                tracing::debug!(
                    from = %peer,
                    bytes,
                    recv_depth,
                    recv_capacity,
                    stream_type = "PubSub",
                    "[2/6 runtime] dispatching gossip message"
                );
                match tokio::time::timeout(
                    PUBSUB_MESSAGE_HANDLE_TIMEOUT,
                    pubsub.handle_incoming(peer, data),
                )
                .await
                {
                    Ok(()) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.pubsub.record_completed(elapsed);
                        tracing::debug!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            stream_type = "PubSub",
                            "[2/6 runtime] completed gossip message dispatch"
                        );
                    }
                    Err(_) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.pubsub.record_timed_out(elapsed);
                        tracing::warn!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            timeout_secs = PUBSUB_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                            stream_type = "PubSub",
                            "Timed out handling gossip message"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!("PubSub message receive failed: {}", e);
                break;
            }
        }
    }
    tracing::info!("Gossip PubSub dispatcher shut down");
}

async fn run_membership_dispatcher(
    network: Arc<NetworkNode>,
    membership: Arc<HyParViewMembership<NetworkNode>>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    loop {
        match network.receive_membership_message().await {
            Ok((peer, data)) => {
                let (recv_depth, recv_capacity) =
                    network.gossip_recv_queue_depth(GossipStreamType::Membership);
                dispatch_stats.record_dequeue(
                    GossipStreamType::Membership,
                    recv_depth,
                    recv_capacity,
                );
                dispatch_stats.membership.record_received();
                let bytes = data.len();
                let started = Instant::now();
                tracing::debug!(
                    from = %peer,
                    bytes,
                    recv_depth,
                    recv_capacity,
                    stream_type = "Membership",
                    "[2/6 runtime] dispatching gossip message"
                );
                match tokio::time::timeout(
                    MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT,
                    membership.dispatch_message(peer, &data),
                )
                .await
                {
                    Ok(Ok(())) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.membership.record_completed(elapsed);
                        tracing::debug!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            stream_type = "Membership",
                            "[2/6 runtime] completed gossip message dispatch"
                        );
                    }
                    Ok(Err(e)) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.membership.record_completed(elapsed);
                        tracing::debug!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            stream_type = "Membership",
                            "Failed to handle membership message: {e}"
                        );
                    }
                    Err(_) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.membership.record_timed_out(elapsed);
                        tracing::warn!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            timeout_secs = MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                            stream_type = "Membership",
                            "Timed out handling gossip message"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!("Membership message receive failed: {}", e);
                break;
            }
        }
    }
    tracing::info!("Gossip Membership dispatcher shut down");
}

async fn run_bulk_dispatcher(
    network: Arc<NetworkNode>,
    presence: Option<Arc<PresenceWrapper>>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    loop {
        match network.receive_bulk_message().await {
            Ok((peer, data)) => {
                let (recv_depth, recv_capacity) =
                    network.gossip_recv_queue_depth(GossipStreamType::Bulk);
                dispatch_stats.record_dequeue(GossipStreamType::Bulk, recv_depth, recv_capacity);
                dispatch_stats.bulk.record_received();
                let bytes = data.len();
                let started = Instant::now();
                tracing::debug!(
                    from = %peer,
                    bytes,
                    recv_depth,
                    recv_capacity,
                    stream_type = "Bulk",
                    "[2/6 runtime] dispatching gossip message"
                );
                if let Some(ref pm) = presence {
                    match tokio::time::timeout(
                        PRESENCE_MESSAGE_HANDLE_TIMEOUT,
                        pm.manager().handle_presence_message(&data),
                    )
                    .await
                    {
                        Ok(Ok(Some(source))) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_completed(elapsed);
                            tracing::debug!(
                                from = %source,
                                peer = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                stream_type = "Bulk",
                                "Handled presence beacon"
                            );
                        }
                        Ok(Ok(None)) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_completed(elapsed);
                            tracing::debug!(
                                from = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                stream_type = "Bulk",
                                "Presence message processed (no source)"
                            );
                        }
                        Ok(Err(e)) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_completed(elapsed);
                            tracing::debug!(
                                from = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                stream_type = "Bulk",
                                "Failed to handle presence message: {e}"
                            );
                        }
                        Err(_) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_timed_out(elapsed);
                            tracing::warn!(
                                from = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                timeout_secs = PRESENCE_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                                stream_type = "Bulk",
                                "Timed out handling gossip message"
                            );
                        }
                    }
                } else {
                    let elapsed = started.elapsed();
                    dispatch_stats.bulk.record_completed(elapsed);
                    tracing::debug!(
                        from = %peer,
                        bytes,
                        elapsed_ms = duration_ms(elapsed),
                        stream_type = "Bulk",
                        "Ignoring Bulk stream (presence not configured)"
                    );
                }
            }
            Err(e) => {
                tracing::error!("Bulk message receive failed: {}", e);
                break;
            }
        }
    }
    tracing::info!("Gossip Bulk dispatcher shut down");
}

impl GossipRuntime {
    /// Create a new gossip runtime with the given configuration and network node.
    ///
    /// This initializes HyParView membership, SWIM failure detection, and
    /// pub/sub messaging. Call `start()` to begin gossip protocol operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The gossip configuration
    /// * `network` - The network node (implements GossipTransport)
    ///
    /// # Returns
    ///
    /// A new `GossipRuntime` instance
    ///
    /// # Errors
    ///
    /// Returns an error if configuration validation fails.
    pub async fn new(
        config: GossipConfig,
        network: Arc<NetworkNode>,
        signing: Option<Arc<SigningContext>>,
    ) -> NetworkResult<Self> {
        config.validate().map_err(|e| {
            crate::error::NetworkError::NodeCreation(format!("invalid gossip config: {e}"))
        })?;

        let peer_id = saorsa_gossip_transport::GossipTransport::local_peer_id(network.as_ref());
        let membership_config = MembershipConfig::default();
        let membership = Arc::new(HyParViewMembership::new(
            peer_id,
            membership_config,
            Arc::clone(&network),
        ));
        let pubsub = Arc::new(PubSubManager::new(Arc::clone(&network), signing)?);

        Ok(Self {
            config,
            network,
            membership,
            pubsub,
            peer_id,
            presence: std::sync::Mutex::new(None),
            dispatcher_handles: std::sync::Mutex::new(Vec::new()),
            peer_sync_handle: std::sync::Mutex::new(None),
            keepalive_handle: std::sync::Mutex::new(None),
            dispatch_stats: Arc::new(GossipDispatchStats::default()),
        })
    }

    /// Get the PubSubManager for this runtime.
    ///
    /// # Returns
    ///
    /// A reference to the `PubSubManager`.
    #[must_use]
    pub fn pubsub(&self) -> &Arc<PubSubManager> {
        &self.pubsub
    }

    /// Get the HyParView membership manager.
    ///
    /// # Returns
    ///
    /// A reference to the `HyParViewMembership`.
    #[must_use]
    pub fn membership(&self) -> &Arc<HyParViewMembership<NetworkNode>> {
        &self.membership
    }

    /// Get the local peer ID.
    ///
    /// # Returns
    ///
    /// The `PeerId` for this node.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Set the presence wrapper for Bulk stream dispatch.
    ///
    /// Must be called before `start()` so that the Bulk dispatcher can route
    /// `GossipStreamType::Bulk` messages to the presence manager.
    pub fn set_presence(&self, presence: Arc<PresenceWrapper>) {
        if let Ok(mut guard) = self.presence.lock() {
            *guard = Some(presence);
        }
    }

    /// Get the presence wrapper, if configured.
    #[must_use]
    pub fn presence(&self) -> Option<Arc<PresenceWrapper>> {
        self.presence.lock().ok().and_then(|guard| guard.clone())
    }

    /// Snapshot inbound dispatcher counters.
    #[must_use]
    pub fn dispatch_stats(&self) -> GossipDispatchStatsSnapshot {
        self.dispatch_stats.snapshot()
    }

    /// Start the gossip runtime.
    ///
    /// This initializes all gossip components and begins protocol operations.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn start(&self) -> NetworkResult<()> {
        let network = Arc::clone(&self.network);
        let membership = Arc::clone(&self.membership);
        let pubsub = Arc::clone(&self.pubsub);
        let presence = self.presence();
        let dispatch_stats = Arc::clone(&self.dispatch_stats);

        let pubsub_handle = tokio::spawn(run_pubsub_dispatcher(
            Arc::clone(&network),
            pubsub,
            Arc::clone(&dispatch_stats),
        ));
        let membership_handle = tokio::spawn(run_membership_dispatcher(
            Arc::clone(&network),
            membership,
            Arc::clone(&dispatch_stats),
        ));
        let bulk_handle = tokio::spawn(run_bulk_dispatcher(
            Arc::clone(&network),
            presence,
            Arc::clone(&dispatch_stats),
        ));

        // Periodically refresh PlumTree topic peers with current connections.
        // This ensures newly connected peers (discovered via HyParView or
        // direct connection) are added to the eager set for existing topics.
        // Using 1-second interval to minimize the window where a newly-connected
        // peer could miss a published message (e.g. release manifest broadcast).
        let pubsub_refresh = Arc::clone(&self.pubsub);
        let peer_sync_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                pubsub_refresh.refresh_topic_peers().await;
            }
        });

        if let Ok(mut guard) = self.peer_sync_handle.lock() {
            *guard = Some(peer_sync_handle);
        }

        // Keepalive: send a SWIM Ping to every connected peer every 15 seconds.
        // This prevents QUIC idle timeout (30s) from dropping direct connections
        // that were established via auto-connect. Without this, connections with
        // no application traffic are closed by QUIC after 30s of inactivity.
        // See ADR-0002 for rationale.
        let keepalive_membership = Arc::clone(&self.membership);
        let keepalive_network = Arc::clone(&self.network);
        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;

                let peers = keepalive_network.connected_peers().await;
                for peer in peers {
                    let gossip_peer = PeerId::new(peer.0);
                    if let Err(e) = keepalive_membership.send_ping(gossip_peer).await {
                        tracing::debug!(
                            peer = %gossip_peer,
                            "Keepalive ping failed: {e}"
                        );
                    }
                }
            }
        });

        if let Ok(mut guard) = self.keepalive_handle.lock() {
            *guard = Some(keepalive_handle);
        }

        match self.dispatcher_handles.lock() {
            Ok(mut guard) => {
                guard.push(pubsub_handle);
                guard.push(membership_handle);
                guard.push(bulk_handle);
            }
            Err(_) => {
                return Err(crate::error::NetworkError::NodeCreation(
                    "dispatcher handles lock poisoned".into(),
                ));
            }
        }
        Ok(())
    }

    /// Shutdown the gossip runtime.
    ///
    /// This gracefully stops all gossip components and cleans up resources.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&self) -> NetworkResult<()> {
        if let Ok(mut guard) = self.keepalive_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.peer_sync_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.dispatcher_handles.lock() {
            for handle in guard.drain(..) {
                handle.abort();
            }
        }
        Ok(())
    }

    /// Get the runtime configuration.
    #[must_use]
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Get the network node.
    #[must_use]
    pub fn network(&self) -> &Arc<NetworkNode> {
        &self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkConfig;

    #[tokio::test]
    async fn test_runtime_creation() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(config, Arc::new(network), None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(
            runtime.config().active_view_size,
            GossipConfig::default().active_view_size
        );
    }

    #[tokio::test]
    async fn test_runtime_start_stop() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(config, Arc::new(network), None)
            .await
            .expect("Failed to create runtime");

        assert!(runtime.start().await.is_ok());
        assert!(runtime.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_accessors() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let runtime = GossipRuntime::new(config.clone(), network_arc.clone(), None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(runtime.config().active_view_size, config.active_view_size);
        assert!(Arc::ptr_eq(runtime.network(), &network_arc));
    }

    #[tokio::test]
    async fn test_runtime_peer_id() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let expected_peer_id =
            saorsa_gossip_transport::GossipTransport::local_peer_id(network_arc.as_ref());
        let runtime = GossipRuntime::new(config, network_arc, None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(runtime.peer_id(), expected_peer_id);
    }

    #[tokio::test]
    async fn test_runtime_invalid_config() {
        let config = GossipConfig {
            active_view_size: 0,
            ..Default::default()
        };
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let result = GossipRuntime::new(config, Arc::new(network), None).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_dispatch_stats_record_per_stream_queue_depth() {
        let stats = GossipDispatchStats::default();

        stats.record_dequeue(GossipStreamType::PubSub, 42, 10_000);
        stats.record_dequeue(GossipStreamType::Membership, 7, 4_000);
        stats.record_dequeue(GossipStreamType::Bulk, 3, 4_000);
        stats.record_dequeue(GossipStreamType::PubSub, 4, 10_000);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.recv_depth.pubsub.latest, 4);
        assert_eq!(snapshot.recv_depth.pubsub.max, 42);
        assert_eq!(snapshot.recv_depth.pubsub.capacity, 10_000);
        assert_eq!(snapshot.recv_depth.membership.latest, 7);
        assert_eq!(snapshot.recv_depth.membership.max, 7);
        assert_eq!(snapshot.recv_depth.membership.capacity, 4_000);
        assert_eq!(snapshot.recv_depth.bulk.latest, 3);
        assert_eq!(snapshot.recv_depth.bulk.max, 3);
        assert_eq!(snapshot.recv_depth.bulk.capacity, 4_000);
    }
}
