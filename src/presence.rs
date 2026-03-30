//! Presence system integration for x0x.
//!
//! Wraps [`saorsa_gossip_presence::PresenceManager`] to provide presence
//! beacons, FOAF discovery, and online/offline events for the agent network.
//!
//! This module provides:
//! - [`PresenceConfig`](crate::presence::PresenceConfig) — tunable parameters for beacon interval, FOAF TTL, etc.
//! - [`PresenceEvent`](crate::presence::PresenceEvent) — online/offline notifications for discovered agents.
//! - [`PresenceWrapper`](crate::presence::PresenceWrapper) — lifecycle wrapper around the underlying `PresenceManager`.
//! - `global_presence_topic` — the canonical presence topic for FOAF queries.
//! - `peer_to_agent_id` — resolve a gossip `PeerId` to an `AgentId` via the discovery cache.
//! - `presence_record_to_discovered_agent` — convert a `PresenceRecord` into a `DiscoveredAgent`.

use std::collections::{HashMap, HashSet};
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
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            beacon_interval_secs: 30,
            foaf_default_ttl: 2,
            foaf_timeout_ms: 5000,
            enable_beacons: true,
            event_poll_interval_secs: 10,
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
}

impl PresenceWrapper {
    /// Create a new presence wrapper.
    ///
    /// Generates a fresh ML-DSA-65 signing keypair for beacon authentication,
    /// creates an empty group context map, and initializes the underlying
    /// `PresenceManager`.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] if keypair generation fails.
    pub fn new(
        peer_id: PeerId,
        network: Arc<NetworkNode>,
        config: PresenceConfig,
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

    /// Start the presence event-emission loop.
    ///
    /// Spawns a background task that polls [`PresenceManager::get_online_peers`]
    /// on the global presence topic every `config.event_poll_interval_secs` seconds,
    /// diffs against the previous snapshot, and broadcasts:
    /// - [`PresenceEvent::AgentOnline`] for newly-seen peers.
    /// - [`PresenceEvent::AgentOffline`] for peers that disappeared.
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

        let handle = tokio::spawn(async move {
            let mut previous: HashSet<PeerId> = HashSet::new();

            loop {
                tokio::time::sleep(poll_interval).await;

                let current_peers = manager.get_online_peers(topic).await;
                let current: HashSet<PeerId> = current_peers.iter().copied().collect();

                // Snapshot cache once per poll cycle.
                let cache_snapshot = cache.read().await;

                // Emit AgentOnline for new peers.
                for &peer in current.difference(&previous) {
                    let agent_id = peer_to_agent_id(peer, &cache_snapshot)
                        .unwrap_or_else(|| AgentId(*peer.as_bytes()));
                    let addresses = cache_snapshot
                        .get(&agent_id)
                        .map(|e| e.addresses.iter().map(|a| a.to_string()).collect())
                        .unwrap_or_default();
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
                for &peer in previous.difference(&current) {
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
}
