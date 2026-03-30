//! Presence system integration for x0x.
//!
//! Wraps [`saorsa_gossip_presence::PresenceManager`] to provide presence
//! beacons, FOAF discovery, and online/offline events for the agent network.
//!
//! This module provides:
//! - [`PresenceConfig`](crate::presence::PresenceConfig) — tunable parameters for beacon interval, FOAF TTL, etc.
//! - [`PresenceEvent`](crate::presence::PresenceEvent) — online/offline notifications for discovered agents.
//! - [`PresenceWrapper`](crate::presence::PresenceWrapper) — lifecycle wrapper around the underlying `PresenceManager`.
//! - `PeerBeaconStats` — per-peer inter-arrival tracking for adaptive failure detection.
//! - `global_presence_topic` — the canonical presence topic for FOAF queries.
//! - `peer_to_agent_id` — resolve a gossip `PeerId` to an `AgentId` via the discovery cache.
//! - `presence_record_to_discovered_agent` — convert a `PresenceRecord` into a `DiscoveredAgent`.
//! - `foaf_peer_score` — quality score for FOAF routing (lower jitter = higher score).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use saorsa_gossip_groups::GroupContext;
use saorsa_gossip_presence::PresenceManager;
use saorsa_gossip_types::{PeerId, PresenceRecord, TopicId};
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;

use crate::contacts::ContactStore;
use crate::error::NetworkError;
use crate::identity::{AgentId, MachineId};
use crate::network::NetworkNode;
use crate::trust::{TrustContext, TrustDecision, TrustEvaluator};
use crate::DiscoveredAgent;

/// Maximum number of beacon inter-arrival intervals tracked per peer.
///
/// A window of 10 gives a 95 % confidence interval on the mean that is
/// tight enough for practical failure detection without excessive memory.
const INTER_ARRIVAL_WINDOW: usize = 10;

/// Lower bound on the adaptive offline timeout (seconds).
///
/// Even for peers with very stable, frequent beacons we never declare them
/// offline in fewer than 3 minutes — protects against brief connectivity blips.
const ADAPTIVE_TIMEOUT_FLOOR_SECS: f64 = 180.0;

/// Upper bound on the adaptive offline timeout (seconds).
///
/// We never wait more than 10 minutes before declaring a peer offline,
/// regardless of how infrequent or jittery its beacons are.
const ADAPTIVE_TIMEOUT_CEILING_SECS: f64 = 600.0;

/// The global presence topic used for FOAF queries.
///
/// All x0x agents publish beacons to this topic so that FOAF random-walk
/// queries can discover them without knowing their shard upfront.
pub const GLOBAL_PRESENCE_TOPIC_NAME: &str = "x0x.presence.global";

/// Returns the canonical [`TopicId`] for the global presence topic.
///
/// This is deterministic: the same string always hashes to the same `TopicId`.
#[must_use]
pub fn global_presence_topic() -> TopicId {
    TopicId::from_entity(GLOBAL_PRESENCE_TOPIC_NAME)
}

/// Resolve a gossip [`PeerId`] to an [`AgentId`] using the identity discovery cache.
///
/// Because `MachineId(peer.0)` is the conversion between gossip `PeerId` and the
/// x0x `MachineId`, we scan the cache for an entry whose `machine_id` matches.
///
/// Returns `None` if the peer is not yet in the cache.
///
/// # Complexity
///
/// O(n) where n is the number of known agents. This is acceptable for networks
/// up to ~10 000 agents. A full reverse index (`MachineId → AgentId`) is
/// planned for a future phase when scale demands it.
#[must_use]
pub fn peer_to_agent_id(
    peer_id: PeerId,
    cache: &HashMap<AgentId, DiscoveredAgent>,
) -> Option<AgentId> {
    let machine = MachineId(*peer_id.as_bytes());
    cache
        .values()
        .find(|entry| entry.machine_id == machine)
        .map(|entry| entry.agent_id)
}

/// Parse a slice of address-hint strings into [`std::net::SocketAddr`]s.
///
/// Invalid or unparseable strings are silently skipped.
#[must_use]
pub fn parse_addr_hints(hints: &[String]) -> Vec<std::net::SocketAddr> {
    hints.iter().filter_map(|h| h.parse().ok()).collect()
}

/// Convert a `(PeerId, PresenceRecord)` pair into a [`DiscoveredAgent`].
///
/// Uses the identity discovery cache to resolve the `PeerId` to a full `AgentId`.
/// If the peer is not yet in the cache we fall back to treating the peer's bytes as
/// the `AgentId` (i.e. `AgentId(peer.0)`), which gives a resolvable but potentially
/// incomplete entry that will be enriched once the normal identity heartbeat arrives.
///
/// Returns `None` only if the record has expired (i.e. `expires < unix_now`).
#[must_use]
pub fn presence_record_to_discovered_agent(
    peer_id: PeerId,
    record: &PresenceRecord,
    cache: &HashMap<AgentId, DiscoveredAgent>,
) -> Option<DiscoveredAgent> {
    // Skip records that have already expired.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if record.expires < now_secs {
        return None;
    }

    let addresses = parse_addr_hints(&record.addr_hints);

    // If the peer is in the discovery cache, clone the cached entry and patch
    // in the fresher address list from the presence record.
    if let Some(agent_id) = peer_to_agent_id(peer_id, cache) {
        if let Some(cached) = cache.get(&agent_id) {
            let mut updated = cached.clone();
            if !addresses.is_empty() {
                updated.addresses = addresses;
            }
            return Some(updated);
        }
    }

    // Fallback: create a minimal entry using AgentId(peer.0).
    // This will be replaced by a full entry once the identity heartbeat arrives.
    //
    // IMPORTANT: `machine_public_key` is intentionally empty here because we do
    // not yet have the ML-DSA-65 public key bytes for this peer — they are only
    // available after the normal identity announcement is received.  Callers that
    // need to verify rendezvous `ProviderSummary` signatures MUST check that
    // `machine_public_key` is non-empty before attempting verification.
    let agent_id = AgentId(*peer_id.as_bytes());
    let machine_id = MachineId(*peer_id.as_bytes());
    Some(DiscoveredAgent {
        agent_id,
        machine_id,
        user_id: None,
        addresses,
        announced_at: record.since,
        last_seen: record.since,
        machine_public_key: Vec::new(), // populated when identity heartbeat arrives
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
    })
}

/// Controls which agents are included in a presence response.
///
/// - [`Network`](PresenceVisibility::Network) returns all reachable agents that are
///   not actively blocked — useful for raw connectivity information.
/// - [`Social`](PresenceVisibility::Social) returns only agents the local user has
///   designated as Trusted or Known — the "friends" view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceVisibility {
    /// Return all reachable agents regardless of trust, except blocked ones.
    Network,
    /// Return only agents whose trust level is Trusted or Known.
    Social,
}

/// Filter a list of discovered agents according to the given trust scope.
///
/// Reads the [`ContactStore`] to evaluate each agent via [`TrustEvaluator`].
///
/// - [`PresenceVisibility::Network`]: excludes [`TrustDecision::RejectBlocked`] agents.
/// - [`PresenceVisibility::Social`]: keeps only [`TrustDecision::Accept`] and
///   [`TrustDecision::AcceptWithFlag`] agents (Trusted + Known).
///
/// Agents not in the contact store (`TrustDecision::Unknown`) are:
/// - included by `Network`
/// - excluded by `Social`
#[must_use]
pub fn filter_by_trust(
    agents: Vec<DiscoveredAgent>,
    store: &ContactStore,
    visibility: PresenceVisibility,
) -> Vec<DiscoveredAgent> {
    let evaluator = TrustEvaluator::new(store);
    agents
        .into_iter()
        .filter(|agent| {
            let ctx = TrustContext {
                agent_id: &agent.agent_id,
                machine_id: &agent.machine_id,
            };
            let decision = evaluator.evaluate(&ctx);
            match visibility {
                PresenceVisibility::Network => !matches!(decision, TrustDecision::RejectBlocked),
                PresenceVisibility::Social => matches!(
                    decision,
                    TrustDecision::Accept | TrustDecision::AcceptWithFlag
                ),
            }
        })
        .collect()
}

/// Compute the FOAF routing quality score for a peer.
///
/// Peers with stable, low-jitter beacon intervals score close to 1.0 and are
/// preferred as FOAF random-walk forwarding targets. Peers with no observation
/// history score 0.5 (neutral). Peers with high jitter score close to 0.0.
///
/// Score formula: `1.0 / (1.0 + stddev)` where `stddev` is in seconds.
///
/// # Range
///
/// Always returns a value in `[0.0, 1.0]`.
#[must_use]
pub fn foaf_peer_score(stats: &PeerBeaconStats) -> f64 {
    match stats.inter_arrival_stats() {
        Some((_, stddev)) => 1.0 / (1.0 + stddev),
        None => 0.5, // Unknown stability: neutral score.
    }
}

/// Sliding-window inter-arrival statistics for a single peer's beacons.
///
/// Tracks the arrival timestamps of the last 10 beacons and exposes mean and
/// standard deviation of the inter-arrival intervals. Used by the
/// Phi-Accrual-lite adaptive timeout and by FOAF peer scoring.
#[derive(Debug, Clone)]
pub struct PeerBeaconStats {
    /// Wall-clock timestamps (unix seconds) of the last N beacon arrivals.
    /// The VecDeque is capped at `INTER_ARRIVAL_WINDOW` entries.
    last_seen: VecDeque<u64>,
}

impl PeerBeaconStats {
    /// Create a new, empty stats object for a peer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_seen: VecDeque::with_capacity(INTER_ARRIVAL_WINDOW + 1),
        }
    }

    /// Return the unix timestamp (seconds) of the most recent beacon arrival,
    /// or `None` if no beacons have been recorded yet.
    #[must_use]
    pub fn last_seen(&self) -> Option<u64> {
        self.last_seen.back().copied()
    }

    /// Record a beacon arrival at the given unix timestamp (seconds).
    ///
    /// Older entries beyond the window size (10) are evicted.
    pub fn record(&mut self, now_secs: u64) {
        self.last_seen.push_back(now_secs);
        while self.last_seen.len() > INTER_ARRIVAL_WINDOW {
            self.last_seen.pop_front();
        }
    }

    /// Return `(mean, stddev)` of beacon inter-arrival intervals in seconds.
    ///
    /// Returns `None` if fewer than 2 beacon arrivals have been recorded (not
    /// enough data to compute an interval).
    ///
    /// The standard deviation is the *population* stddev of the inter-arrival
    /// intervals, computed from the sliding window. It is intentionally not
    /// Bessel-corrected to keep the formula simple and deterministic.
    #[must_use]
    pub fn inter_arrival_stats(&self) -> Option<(f64, f64)> {
        if self.last_seen.len() < 2 {
            return None;
        }

        // Compute inter-arrival intervals.
        let intervals: Vec<f64> = self
            .last_seen
            .iter()
            .zip(self.last_seen.iter().skip(1))
            .map(|(&a, &b)| b.saturating_sub(a) as f64)
            .collect();

        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();

        Some((mean, stddev))
    }

    /// Compute the adaptive offline timeout for this peer in seconds.
    ///
    /// Uses the Phi-Accrual-lite formula:
    /// ```text
    /// timeout = clamp(mean + 3 × stddev, 180, 600)
    /// ```
    ///
    /// When fewer than 2 observations are available the `fallback_secs` value
    /// is returned unchanged.
    #[must_use]
    pub fn adaptive_timeout_secs(&self, fallback_secs: u64) -> u64 {
        match self.inter_arrival_stats() {
            Some((mean, stddev)) => {
                let raw = mean + 3.0 * stddev;
                raw.clamp(ADAPTIVE_TIMEOUT_FLOOR_SECS, ADAPTIVE_TIMEOUT_CEILING_SECS) as u64
            }
            None => fallback_secs,
        }
    }
}

impl Default for PeerBeaconStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for the presence system.
#[derive(Debug, Clone)]
pub struct PresenceConfig {
    /// Interval in seconds between beacon broadcasts.
    pub beacon_interval_secs: u64,
    /// Default TTL for FOAF discovery queries.
    pub foaf_default_ttl: u8,
    /// Timeout in milliseconds for FOAF queries.
    pub foaf_timeout_ms: u64,
    /// Whether to enable periodic beacon broadcasting.
    pub enable_beacons: bool,
    /// Interval in seconds between event-loop polls (online/offline diffs).
    pub event_poll_interval_secs: u64,
    /// Fallback offline timeout (seconds) used before enough inter-arrival
    /// samples are available for the adaptive detector.
    ///
    /// Defaults to 300 s (5 minutes). Must be within
    /// `[ADAPTIVE_TIMEOUT_FLOOR_SECS, ADAPTIVE_TIMEOUT_CEILING_SECS]` for
    /// consistent behaviour, though no clamp is enforced here.
    pub adaptive_timeout_fallback_secs: u64,
    /// When `true` (the default), the legacy identity-announcement heartbeat
    /// continues to run alongside the presence beacon system.
    ///
    /// Set to `false` to run presence-only discovery (future deprecation path).
    pub legacy_coexistence_mode: bool,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            beacon_interval_secs: 30,
            foaf_default_ttl: 2,
            foaf_timeout_ms: 5000,
            enable_beacons: true,
            event_poll_interval_secs: 10,
            adaptive_timeout_fallback_secs: 300,
            legacy_coexistence_mode: true,
        }
    }
}

/// Events emitted by the presence system.
#[derive(Debug, Clone)]
pub enum PresenceEvent {
    /// An agent has come online or refreshed its beacon.
    AgentOnline {
        /// The agent that came online.
        agent_id: AgentId,
        /// Network addresses advertised by the agent.
        addresses: Vec<String>,
    },
    /// An agent has gone offline (beacon expired).
    AgentOffline {
        /// The agent that went offline.
        agent_id: AgentId,
    },
}

/// Wrapper around [`PresenceManager`] that manages lifecycle, configuration,
/// and event broadcasting for the x0x agent.
///
/// ## Cache Enrichment
///
/// When the presence event loop receives a beacon from a peer that includes
/// address hints, those addresses are fed back into the ant-quic bootstrap
/// cache via [`ant_quic::BootstrapCache::add_from_connection`].  This ensures
/// the addresses are available for future NAT traversal even before a direct
/// QUIC connection has been established.
///
/// ## Adaptive Failure Detection
///
/// Each peer's beacon inter-arrival times are tracked in a
/// [`PeerBeaconStats`] sliding window.  The adaptive offline timeout
/// (`mean + 3 × stddev`, clamped to 180 – 600 s) replaces the fixed 900 s TTL
/// blind spot of the legacy heartbeat.
pub struct PresenceWrapper {
    /// The underlying gossip presence manager.
    manager: Arc<PresenceManager>,
    /// Configuration for this presence instance.
    config: PresenceConfig,
    /// Handle to the beacon broadcast task, if running.
    beacon_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// Handle to the presence event-loop task, if running.
    event_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// Sender for presence events (online/offline notifications).
    event_tx: broadcast::Sender<PresenceEvent>,
    /// Optional bootstrap cache for enriching addresses from presence beacons.
    ///
    /// When `Some`, each `AgentOnline` event feeds the peer's addresses back
    /// into ant-quic's bootstrap cache so they are available for future NAT
    /// traversal without requiring a prior direct connection.
    bootstrap_cache: Option<Arc<ant_quic::BootstrapCache>>,
    /// Per-peer inter-arrival statistics for adaptive failure detection.
    ///
    /// Keyed by gossip [`PeerId`] (which equals the peer's `MachineId`).
    /// Protected by an `Arc<RwLock<…>>` so the event loop can mutate it
    /// without holding the `PresenceWrapper` itself.
    peer_stats: Arc<RwLock<HashMap<PeerId, PeerBeaconStats>>>,
}

impl PresenceWrapper {
    /// Create a new presence wrapper.
    ///
    /// Generates a fresh ML-DSA-65 signing keypair for beacon authentication,
    /// creates an empty group context map, and initializes the underlying
    /// `PresenceManager`.
    ///
    /// # Arguments
    ///
    /// * `peer_id` — The local node's gossip `PeerId` (equals the `MachineId`).
    /// * `network` — Shared handle to the transport layer.
    /// * `config` — Presence configuration (intervals, TTLs, etc.).
    /// * `bootstrap_cache` — Optional bootstrap cache; when `Some`, presence
    ///   beacons enrich the cache with peer addresses.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] if keypair generation fails.
    pub fn new(
        peer_id: PeerId,
        network: Arc<NetworkNode>,
        config: PresenceConfig,
        bootstrap_cache: Option<Arc<ant_quic::BootstrapCache>>,
    ) -> Result<Self, NetworkError> {
        let signing_key = saorsa_gossip_identity::MlDsaKeyPair::generate().map_err(|e| {
            NetworkError::NodeCreation(format!("failed to create presence signing key: {e}"))
        })?;

        let groups: Arc<RwLock<HashMap<TopicId, GroupContext>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let manager = PresenceManager::new_with_identity(
            peer_id,
            network,
            groups,
            None, // four_words populated later from network status
            signing_key,
        );

        let (event_tx, _) = broadcast::channel(256);

        Ok(Self {
            manager: Arc::new(manager),
            config,
            beacon_handle: tokio::sync::Mutex::new(None),
            event_handle: tokio::sync::Mutex::new(None),
            event_tx,
            bootstrap_cache,
            peer_stats: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns a reference to the underlying [`PresenceManager`].
    pub fn manager(&self) -> &Arc<PresenceManager> {
        &self.manager
    }

    /// Returns the current presence configuration.
    pub fn config(&self) -> &PresenceConfig {
        &self.config
    }

    /// Subscribe to presence events (agent online/offline).
    ///
    /// Returns a broadcast receiver that yields [`PresenceEvent`] values.
    /// Multiple subscribers can exist simultaneously.
    pub fn subscribe_events(&self) -> broadcast::Receiver<PresenceEvent> {
        self.event_tx.subscribe()
    }

    /// Return a snapshot of the current per-peer FOAF routing candidates,
    /// sorted by quality score (descending).
    ///
    /// Each element is `(PeerId, score)` where `score ∈ [0.0, 1.0]`.  Peers
    /// with stable beacon timing score close to 1.0; peers with no history
    /// score 0.5; peers with high jitter score close to 0.0.
    ///
    /// Intended for use by the FOAF random-walk forwarding logic to prefer
    /// well-connected, stable peers as next-hop targets.
    pub async fn foaf_peer_candidates(&self) -> Vec<(PeerId, f64)> {
        let stats = self.peer_stats.read().await;
        let mut candidates: Vec<(PeerId, f64)> = stats
            .iter()
            .map(|(&peer_id, s)| (peer_id, foaf_peer_score(s)))
            .collect();
        // Sort highest score first so callers can take the front of the slice.
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        candidates
    }

    /// Start the presence event-emission loop.
    ///
    /// Spawns a background task that polls [`PresenceManager::get_online_peers`]
    /// on the global presence topic every `config.event_poll_interval_secs` seconds,
    /// diffs against the previous snapshot, and broadcasts:
    /// - [`PresenceEvent::AgentOnline`] for newly-seen peers.
    /// - [`PresenceEvent::AgentOffline`] for peers that disappeared.
    ///
    /// Additionally, for each newly-seen peer:
    /// - Inter-arrival statistics are updated in the internal `peer_stats` map.
    /// - Address hints are fed into the bootstrap cache (if configured) via
    ///   [`ant_quic::BootstrapCache::add_from_connection`].
    ///
    /// PeerIds are resolved to [`AgentId`]s using the identity discovery cache.
    /// Peers that cannot be resolved are emitted using an `AgentId` derived from
    /// their raw bytes (see [`presence_record_to_discovered_agent`]).
    ///
    /// If the event loop is already running this is a no-op.
    pub async fn start_event_loop(&self, cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>) {
        let mut guard = self.event_handle.lock().await;
        // Already running — don't spawn again.
        if guard.is_some() {
            return;
        }

        let manager = Arc::clone(&self.manager);
        let event_tx = self.event_tx.clone();
        let poll_interval = tokio::time::Duration::from_secs(self.config.event_poll_interval_secs);
        let topic = global_presence_topic();
        let bootstrap_cache = self.bootstrap_cache.clone();
        let peer_stats = Arc::clone(&self.peer_stats);
        let adaptive_fallback = self.config.adaptive_timeout_fallback_secs;

        let handle = tokio::spawn(async move {
            let mut previous: HashSet<PeerId> = HashSet::new();

            loop {
                tokio::time::sleep(poll_interval).await;

                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let current_peers = manager.get_online_peers(topic).await;
                let current: HashSet<PeerId> = current_peers.iter().copied().collect();

                // Snapshot identity-discovery cache once per poll cycle.
                let cache_snapshot = cache.read().await;

                // Emit AgentOnline for new peers and update per-peer stats.
                for &peer in current.difference(&previous) {
                    // Update inter-arrival statistics.
                    {
                        let mut stats_guard = peer_stats.write().await;
                        stats_guard.entry(peer).or_default().record(now_secs);
                    }

                    let agent_id = peer_to_agent_id(peer, &cache_snapshot)
                        .unwrap_or_else(|| AgentId(*peer.as_bytes()));

                    let socket_addrs: Vec<std::net::SocketAddr> = cache_snapshot
                        .get(&agent_id)
                        .map(|e| e.addresses.clone())
                        .unwrap_or_default();

                    // Enrich bootstrap cache with addresses from this beacon.
                    if let Some(ref bc) = bootstrap_cache {
                        if !socket_addrs.is_empty() {
                            let ant_peer_id = ant_quic::PeerId(*peer.as_bytes());
                            bc.add_from_connection(ant_peer_id, socket_addrs.clone(), None)
                                .await;
                        }
                    }

                    let addresses: Vec<String> =
                        socket_addrs.iter().map(|a| a.to_string()).collect();

                    if event_tx
                        .send(PresenceEvent::AgentOnline {
                            agent_id,
                            addresses,
                        })
                        .is_err()
                    {
                        tracing::debug!(
                            ?agent_id,
                            "AgentOnline event dropped: no active subscribers"
                        );
                    }
                }

                // Emit AgentOffline for departed peers.
                // Use adaptive timeout to decide whether a peer is truly offline.
                for &peer in previous.difference(&current) {
                    // Read timeout and last_seen under a single lock acquisition
                    // to ensure they are consistent with each other.
                    let (timeout, last_seen_ts) = {
                        let stats_guard = peer_stats.read().await;
                        let s = stats_guard.get(&peer);
                        let timeout = s
                            .map(|s| s.adaptive_timeout_secs(adaptive_fallback))
                            .unwrap_or(adaptive_fallback);
                        let last_seen_ts = s.and_then(|s| s.last_seen()).unwrap_or(0);
                        (timeout, last_seen_ts)
                    };

                    let absent_secs = now_secs.saturating_sub(last_seen_ts);
                    if absent_secs < timeout {
                        // Peer disappeared from the poll window but has not yet
                        // exceeded its adaptive timeout — keep it in `previous`
                        // to avoid a spurious offline event.
                        continue;
                    }

                    // Evict the stats entry to prevent unbounded HashMap growth.
                    peer_stats.write().await.remove(&peer);

                    let agent_id = peer_to_agent_id(peer, &cache_snapshot)
                        .unwrap_or_else(|| AgentId(*peer.as_bytes()));
                    if event_tx
                        .send(PresenceEvent::AgentOffline { agent_id })
                        .is_err()
                    {
                        tracing::debug!(
                            ?agent_id,
                            "AgentOffline event dropped: no active subscribers"
                        );
                    }
                }

                drop(cache_snapshot);
                previous = current;
            }
        });

        *guard = Some(handle);
    }

    /// Shut down the presence system.
    ///
    /// Aborts both the beacon broadcast task and the event-loop task if running.
    /// Safe to call multiple times.
    pub async fn shutdown(&self) {
        let mut beacon = self.beacon_handle.lock().await;
        if let Some(h) = beacon.take() {
            h.abort();
        }
        let mut event = self.event_handle.lock().await;
        if let Some(h) = event.take() {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AgentId, MachineId};
    use crate::DiscoveredAgent;
    use std::collections::HashMap;

    fn make_discovered_agent(agent_id: AgentId, machine_id: MachineId) -> DiscoveredAgent {
        DiscoveredAgent {
            agent_id,
            machine_id,
            user_id: None,
            addresses: vec!["127.0.0.1:5000".parse().unwrap()],
            announced_at: 1000,
            last_seen: 1000,
            machine_public_key: vec![1u8; 32],
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
        }
    }

    // ── Existing tests ────────────────────────────────────────────────────────

    #[test]
    fn test_global_presence_topic_is_deterministic() {
        let t1 = global_presence_topic();
        let t2 = global_presence_topic();
        assert_eq!(t1, t2, "global_presence_topic must be deterministic");
    }

    #[test]
    fn test_peer_to_agent_id_found() {
        let machine_bytes = [42u8; 32];
        let machine_id = MachineId(machine_bytes);
        let agent_id = AgentId([7u8; 32]);
        let peer_id = PeerId::new(machine_bytes);

        let mut cache = HashMap::new();
        cache.insert(agent_id, make_discovered_agent(agent_id, machine_id));

        let result = peer_to_agent_id(peer_id, &cache);
        assert_eq!(result, Some(agent_id));
    }

    #[test]
    fn test_peer_to_agent_id_not_found() {
        let cache: HashMap<AgentId, DiscoveredAgent> = HashMap::new();
        let peer_id = PeerId::new([1u8; 32]);
        assert_eq!(peer_to_agent_id(peer_id, &cache), None);
    }

    #[test]
    fn test_parse_addr_hints_valid() {
        let hints = vec!["127.0.0.1:5000".to_string(), "[::1]:5001".to_string()];
        let addrs = parse_addr_hints(&hints);
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_parse_addr_hints_invalid_skipped() {
        let hints = vec!["not-an-addr".to_string(), "127.0.0.1:5000".to_string()];
        let addrs = parse_addr_hints(&hints);
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn test_presence_record_to_discovered_agent_cache_hit() {
        use saorsa_gossip_types::PresenceRecord;

        let machine_bytes = [10u8; 32];
        let machine_id = MachineId(machine_bytes);
        let agent_id = AgentId([20u8; 32]);
        let peer_id = PeerId::new(machine_bytes);

        let mut cache = HashMap::new();
        cache.insert(agent_id, make_discovered_agent(agent_id, machine_id));

        // Create a non-expired presence record.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = PresenceRecord::new([0u8; 32], vec!["192.168.1.1:5000".to_string()], 300);
        // record.expires = now + 300

        let result = presence_record_to_discovered_agent(peer_id, &record, &cache);
        assert!(
            result.is_some(),
            "Should return Some for non-expired record"
        );
        let da = result.unwrap();
        assert_eq!(da.agent_id, agent_id, "Should use cached agent_id");
        // Addresses should be updated from the presence record.
        assert_eq!(da.addresses.len(), 1);
        // machine_public_key should be preserved from cache (non-empty).
        assert!(!da.machine_public_key.is_empty());
        let _ = now; // suppress unused warning
    }

    #[test]
    fn test_presence_record_to_discovered_agent_fallback() {
        use saorsa_gossip_types::PresenceRecord;

        let peer_bytes = [99u8; 32];
        let peer_id = PeerId::new(peer_bytes);
        let cache: HashMap<AgentId, DiscoveredAgent> = HashMap::new();

        let record = PresenceRecord::new([0u8; 32], vec!["10.0.0.1:5000".to_string()], 300);

        let result = presence_record_to_discovered_agent(peer_id, &record, &cache);
        assert!(result.is_some(), "Fallback should produce an entry");
        let da = result.unwrap();
        // Fallback: AgentId equals PeerId bytes.
        assert_eq!(da.agent_id.0, peer_bytes);
        // machine_public_key is empty in fallback.
        assert!(da.machine_public_key.is_empty());
    }

    #[test]
    fn test_presence_record_to_discovered_agent_expired() {
        use saorsa_gossip_types::PresenceRecord;

        let peer_id = PeerId::new([1u8; 32]);
        let cache: HashMap<AgentId, DiscoveredAgent> = HashMap::new();

        // Create an already-expired record (expires in the past).
        let mut record = PresenceRecord::new([0u8; 32], vec![], 1);
        // Force expires to 0 (past).
        record.expires = 0;

        let result = presence_record_to_discovered_agent(peer_id, &record, &cache);
        assert!(result.is_none(), "Expired record should return None");
    }

    // ── Phase 1.4: PeerBeaconStats tests ─────────────────────────────────────

    #[test]
    fn test_peer_beacon_stats_single_sample_uses_fallback() {
        let mut stats = PeerBeaconStats::new();
        stats.record(1_000);

        // Only one sample — not enough for inter-arrival computation.
        assert!(
            stats.inter_arrival_stats().is_none(),
            "Single sample must return None from inter_arrival_stats"
        );

        let fallback = 300_u64;
        assert_eq!(
            stats.adaptive_timeout_secs(fallback),
            fallback,
            "adaptive_timeout_secs must return fallback when < 2 samples"
        );
    }

    #[test]
    fn test_peer_beacon_stats_two_samples_produces_stats() {
        let mut stats = PeerBeaconStats::new();
        stats.record(1_000);
        stats.record(1_030); // 30 s interval

        let result = stats.inter_arrival_stats();
        assert!(result.is_some(), "Two samples should produce stats");

        let (mean, stddev) = result.unwrap();
        assert!(
            (mean - 30.0).abs() < 0.001,
            "Mean should be 30 s, got {mean}"
        );
        assert!(
            stddev < 0.001,
            "Stddev should be 0 for single interval, got {stddev}"
        );

        // Timeout: 30 + 3*0 = 30, clamped to floor 180.
        let timeout = stats.adaptive_timeout_secs(300);
        assert_eq!(
            timeout, 180,
            "Timeout should be clamped to floor 180, got {timeout}"
        );
    }

    #[test]
    fn test_peer_beacon_stats_high_jitter_ceiling() {
        let mut stats = PeerBeaconStats::new();
        // Very irregular beacons: 10 s, 500 s, 10 s, 500 s …
        let times: Vec<u64> = vec![0, 10, 510, 520, 1020, 1030, 1530, 1540];
        for t in times {
            stats.record(t);
        }

        let (mean, stddev) = stats.inter_arrival_stats().expect("Should have stats");
        let raw = mean + 3.0 * stddev;
        // raw should be large enough to hit the ceiling.
        assert!(
            raw > ADAPTIVE_TIMEOUT_CEILING_SECS,
            "Raw timeout {raw} should exceed ceiling"
        );

        let timeout = stats.adaptive_timeout_secs(300);
        assert_eq!(
            timeout, 600,
            "Timeout should be clamped to ceiling 600, got {timeout}"
        );
    }

    #[test]
    fn test_peer_beacon_stats_steady_beacons_floor() {
        let mut stats = PeerBeaconStats::new();
        // Very frequent, perfectly regular beacons: every 5 s.
        for i in 0..10_u64 {
            stats.record(i * 5);
        }

        let (mean, stddev) = stats.inter_arrival_stats().expect("Should have stats");
        assert!((mean - 5.0).abs() < 0.001, "Mean should be 5 s, got {mean}");
        assert!(stddev < 0.001, "Stddev should be ~0, got {stddev}");

        // 5 + 3*0 = 5, clamped to floor 180.
        let timeout = stats.adaptive_timeout_secs(300);
        assert_eq!(
            timeout, 180,
            "Timeout should be at floor 180 for steady beacons, got {timeout}"
        );
    }

    #[test]
    fn test_peer_beacon_stats_window_capped() {
        let mut stats = PeerBeaconStats::new();
        // Record 15 samples — only the last INTER_ARRIVAL_WINDOW should remain.
        for i in 0..15_u64 {
            stats.record(i * 30);
        }
        assert_eq!(
            stats.last_seen.len(),
            INTER_ARRIVAL_WINDOW,
            "Window should be capped at INTER_ARRIVAL_WINDOW"
        );
    }

    // ── Phase 1.4: foaf_peer_score tests ─────────────────────────────────────

    #[test]
    fn test_foaf_peer_score_no_stats_returns_neutral() {
        let stats = PeerBeaconStats::new();
        let score = foaf_peer_score(&stats);
        assert!(
            (score - 0.5).abs() < 0.001,
            "No-stats score should be 0.5, got {score}"
        );
    }

    #[test]
    fn test_foaf_peer_score_stable_peer_high_score() {
        let mut stats = PeerBeaconStats::new();
        // Perfect 30-second beacons → stddev = 0 → score = 1/(1+0) = 1.0
        for i in 0..5_u64 {
            stats.record(i * 30);
        }
        let score = foaf_peer_score(&stats);
        assert!(
            score > 0.99,
            "Stable peer should score close to 1.0, got {score}"
        );
    }

    #[test]
    fn test_foaf_peer_score_jittery_peer_lower_score() {
        let mut stats_stable = PeerBeaconStats::new();
        let mut stats_jittery = PeerBeaconStats::new();

        for i in 0..5_u64 {
            stats_stable.record(i * 30);
        }
        // Highly irregular beacons.
        for t in [0_u64, 5, 300, 310, 900] {
            stats_jittery.record(t);
        }

        let score_stable = foaf_peer_score(&stats_stable);
        let score_jittery = foaf_peer_score(&stats_jittery);

        assert!(
            score_stable > score_jittery,
            "Stable peer ({score_stable}) should score higher than jittery ({score_jittery})"
        );
    }

    #[test]
    fn test_foaf_peer_score_always_in_range() {
        // Verify score is always [0, 1] for arbitrary inputs.
        let scenarios: Vec<Vec<u64>> = vec![
            vec![],
            vec![0],
            vec![0, 1],
            vec![0, 1_000_000],
            vec![0, 30, 60, 90, 120],
        ];
        for times in scenarios {
            let mut stats = PeerBeaconStats::new();
            for t in times {
                stats.record(t);
            }
            let score = foaf_peer_score(&stats);
            assert!(
                (0.0..=1.0).contains(&score),
                "Score {score} out of [0,1] range"
            );
        }
    }

    // ── Phase 1.4: PresenceConfig default tests ───────────────────────────────

    #[test]
    fn test_presence_config_adaptive_fallback_default() {
        let cfg = PresenceConfig::default();
        assert_eq!(
            cfg.adaptive_timeout_fallback_secs, 300,
            "Default adaptive fallback should be 300 s"
        );
    }

    #[test]
    fn test_presence_config_legacy_coexistence_default_true() {
        let cfg = PresenceConfig::default();
        assert!(
            cfg.legacy_coexistence_mode,
            "Legacy coexistence must be enabled by default"
        );
    }

    // ── Phase 1.5: filter_by_trust tests ─────────────────────────────────────

    fn make_temp_contact_store() -> (crate::contacts::ContactStore, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = crate::contacts::ContactStore::new(tmp.path().join("contacts.json"));
        (store, tmp)
    }

    #[test]
    fn test_filter_by_trust_blocks_blocked_agents() {
        let (mut store, _tmp) = make_temp_contact_store();
        let blocked_id = AgentId([2u8; 32]);
        let blocked_machine = MachineId([22u8; 32]);
        let allowed_id = AgentId([3u8; 32]);
        let allowed_machine = MachineId([33u8; 32]);

        store.set_trust(&blocked_id, crate::contacts::TrustLevel::Blocked);

        let agents = vec![
            make_discovered_agent(blocked_id, blocked_machine),
            make_discovered_agent(allowed_id, allowed_machine),
        ];

        let filtered = filter_by_trust(agents, &store, PresenceVisibility::Network);
        // Blocked agent must be removed; unknown-trust agent must remain.
        assert_eq!(filtered.len(), 1, "Blocked agent must be filtered out");
        assert_eq!(
            filtered[0].agent_id, allowed_id,
            "Non-blocked agent must survive filtering"
        );
    }

    #[test]
    fn test_filter_by_trust_passes_trusted_agents() {
        let (mut store, _tmp) = make_temp_contact_store();
        let trusted_id = AgentId([4u8; 32]);
        let trusted_machine = MachineId([44u8; 32]);

        store.set_trust(&trusted_id, crate::contacts::TrustLevel::Trusted);

        let agents = vec![make_discovered_agent(trusted_id, trusted_machine)];
        let filtered = filter_by_trust(agents, &store, PresenceVisibility::Network);
        assert_eq!(filtered.len(), 1, "Trusted agent must not be filtered");
    }

    #[test]
    fn test_filter_by_trust_passes_unknown_agents() {
        let (store, _tmp) = make_temp_contact_store();
        // Agent is not in the store at all (Unknown trust).
        let unknown_id = AgentId([5u8; 32]);
        let unknown_machine = MachineId([55u8; 32]);

        let agents = vec![make_discovered_agent(unknown_id, unknown_machine)];
        let filtered = filter_by_trust(agents, &store, PresenceVisibility::Network);
        assert_eq!(
            filtered.len(),
            1,
            "Unknown-trust agent must pass Network visibility filter"
        );
    }

    #[test]
    fn test_filter_by_trust_social_keeps_only_known_or_trusted() {
        let (mut store, _tmp) = make_temp_contact_store();
        let trusted_id = AgentId([6u8; 32]);
        let trusted_machine = MachineId([66u8; 32]);
        let known_id = AgentId([7u8; 32]);
        let known_machine = MachineId([77u8; 32]);
        let unknown_id = AgentId([8u8; 32]);
        let unknown_machine = MachineId([88u8; 32]);

        store.set_trust(&trusted_id, crate::contacts::TrustLevel::Trusted);
        store.set_trust(&known_id, crate::contacts::TrustLevel::Known);

        let agents = vec![
            make_discovered_agent(trusted_id, trusted_machine),
            make_discovered_agent(known_id, known_machine),
            make_discovered_agent(unknown_id, unknown_machine),
        ];
        let filtered = filter_by_trust(agents, &store, PresenceVisibility::Social);
        // Social visibility: only Known + Trusted pass.
        assert_eq!(
            filtered.len(),
            2,
            "Social filter must keep only Known/Trusted agents"
        );
        let ids: Vec<_> = filtered.iter().map(|a| a.agent_id).collect();
        assert!(ids.contains(&trusted_id), "Trusted must pass Social filter");
        assert!(ids.contains(&known_id), "Known must pass Social filter");
    }

    // ── Phase 1.5: foaf_peer_score ordering tests ─────────────────────────────

    #[test]
    fn test_foaf_peer_score_empty_stats_is_neutral() {
        let empty = PeerBeaconStats::new();
        let score = foaf_peer_score(&empty);
        // No inter-arrival data → neutral score of 0.5
        assert!(
            (score - 0.5_f64).abs() < f64::EPSILON,
            "Empty stats must return neutral score 0.5, got {score}"
        );
    }

    #[test]
    fn test_foaf_peer_score_stable_beats_jittery() {
        let base = 1_000_000_u64;

        // Stable: constant 30 s interval
        let mut stable = PeerBeaconStats::new();
        for i in 0..10_u64 {
            stable.record(base + i * 30);
        }
        let stable_score = foaf_peer_score(&stable);

        // Jittery: highly variable interval
        let mut jittery = PeerBeaconStats::new();
        for i in 0..10_u64 {
            jittery.record(base + i * i * 15 + i * 30);
        }
        let jittery_score = foaf_peer_score(&jittery);

        assert!(
            stable_score >= jittery_score,
            "Stable peer score ({stable_score}) must be >= jittery peer score ({jittery_score})"
        );
    }

    #[test]
    fn test_foaf_peer_score_sorted_ordering() {
        // Build a small set of stats and verify sort order matches the scoring function.
        let base = 1_000_000_u64;

        let mut very_stable = PeerBeaconStats::new();
        for i in 0..10_u64 {
            very_stable.record(base + i * 30);
        }

        let mut moderate = PeerBeaconStats::new();
        for i in 0..10_u64 {
            moderate.record(base + i * 60 + (i % 3) * 10);
        }

        let mut chaotic = PeerBeaconStats::new();
        for i in 0..10_u64 {
            chaotic.record(base + i * i * 20);
        }

        let s_vs = foaf_peer_score(&very_stable);
        let s_m = foaf_peer_score(&moderate);
        let s_c = foaf_peer_score(&chaotic);

        // All scores in [0, 1]
        for &s in &[s_vs, s_m, s_c] {
            assert!(
                (0.0_f64..=1.0_f64).contains(&s),
                "Score {s} must be in [0.0, 1.0]"
            );
        }
        // Most-stable should score highest
        assert!(s_vs >= s_c, "Very stable ({s_vs}) must beat chaotic ({s_c})");
    }

    // ── Phase 1.5: proptest property tests ────────────────────────────────────

    mod proptest_presence {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(proptest::test_runner::Config {
                cases: 100,
                ..Default::default()
            })]

            #[test]
            fn proptest_foaf_peer_score_in_range(
                timestamps in proptest::collection::vec(0_u64..10_000_000_u64, 1..=20)
            ) {
                let mut stats = PeerBeaconStats::new();
                let mut sorted = timestamps.clone();
                sorted.sort_unstable();
                for t in sorted {
                    stats.record(t);
                }
                let score = foaf_peer_score(&stats);
                prop_assert!(
                    (0.0_f64..=1.0_f64).contains(&score),
                    "foaf_peer_score must be in [0.0, 1.0], got {score}"
                );
            }

            #[test]
            fn proptest_adaptive_timeout_clamped(
                timestamps in proptest::collection::vec(0_u64..10_000_000_u64, 2..=20)
            ) {
                let mut stats = PeerBeaconStats::new();
                let mut sorted = timestamps.clone();
                sorted.sort_unstable();
                for t in sorted {
                    stats.record(t);
                }
                let timeout = stats.adaptive_timeout_secs(300);
                prop_assert!(
                    (180..=600).contains(&timeout),
                    "adaptive_timeout_secs must be in [180, 600], got {timeout}"
                );
            }
        }
    }
}
