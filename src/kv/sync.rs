//! KvStore synchronization using anti-entropy gossip.
//!
//! Wraps a KvStore in `Arc<RwLock<>>` for concurrent access and
//! synchronizes it via gossip pub/sub delta propagation.

use crate::gossip::PubSubManager;
use crate::kv::{KvStore, KvStoreDelta, Result};
use saorsa_gossip_crdt_sync::AntiEntropyManager;
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Suffix appended to a store topic to form its state-sync side channel.
///
/// State requests travel on a separate topic so the main topic keeps its
/// existing `(PeerId, KvStoreDelta)` wire format — pre-#96 nodes simply
/// never subscribe to the side channel and are unaffected.
const STATE_SYNC_TOPIC_SUFFIX: &str = "/state-sync";

/// Delays between state-request retries for a first-time joiner whose
/// store is still empty. Spread out so a slow mesh (peer discovery,
/// subscription propagation) still converges without flooding.
const STATE_REQUEST_RETRY_SECS: [u64; 4] = [1, 5, 15, 30];

/// Message exchanged on the state-sync side topic.
#[derive(Debug, Serialize, Deserialize)]
enum KvSyncMessage {
    /// A peer with no local state for the store asks holders to republish
    /// their full state (as a regular delta) on the main topic.
    StateRequest { requester: PeerId },
}

/// Synchronization wrapper for a KvStore.
///
/// Manages automatic background synchronization using anti-entropy gossip.
/// Changes are propagated via deltas published to a gossip topic.
pub struct KvStoreSync {
    /// The store being synchronized.
    store: Arc<RwLock<KvStore>>,

    /// Anti-entropy manager for periodic sync.
    #[allow(dead_code)]
    anti_entropy: AntiEntropyManager<KvStore>,

    /// Pub/sub manager for topic-based messaging.
    pubsub: Arc<PubSubManager>,

    /// Topic name for this store.
    topic: String,

    /// This node's gossip peer id — identifies our deltas and state
    /// requests on the wire.
    local_peer_id: PeerId,
}

impl KvStoreSync {
    /// Create a new KvStore synchronization manager.
    ///
    /// # Arguments
    ///
    /// * `store` - The KvStore to synchronize.
    /// * `pubsub` - Pub/sub manager for gossip messaging.
    /// * `topic` - Topic name for pub/sub.
    /// * `sync_interval_secs` - How often to run anti-entropy.
    /// * `local_peer_id` - This node's gossip peer id.
    pub fn new(
        store: KvStore,
        pubsub: Arc<PubSubManager>,
        topic: String,
        sync_interval_secs: u64,
        local_peer_id: PeerId,
    ) -> Result<Self> {
        let store = Arc::new(RwLock::new(store));
        let anti_entropy = AntiEntropyManager::new(Arc::clone(&store), sync_interval_secs);

        Ok(Self {
            store,
            anti_entropy,
            pubsub,
            topic,
            local_peer_id,
        })
    }

    /// The state-sync side topic for this store.
    fn state_sync_topic(&self) -> String {
        format!("{}{}", self.topic, STATE_SYNC_TOPIC_SUFFIX)
    }

    /// Start background synchronization.
    ///
    /// Subscribes to the gossip topic and begins receiving remote deltas.
    /// Also joins the state-sync side channel: holders answer state
    /// requests by republishing their full state, and — issue #96 — a
    /// first-time joiner (empty local store) requests that state so it
    /// bootstraps keys written before it joined. Without this, only
    /// deltas published *after* subscribing ever arrive.
    pub async fn start(&self) -> Result<()> {
        let mut sub = self.pubsub.subscribe(self.topic.clone()).await;
        let store = Arc::clone(&self.store);

        tokio::spawn(async move {
            while let Some(msg) = sub.recv().await {
                let decoded = {
                    use bincode::Options;
                    bincode::options()
                        .with_fixint_encoding()
                        .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
                        .allow_trailing_bytes()
                        .deserialize::<(PeerId, KvStoreDelta)>(&msg.payload)
                };
                match decoded {
                    Ok((peer_id, delta)) => {
                        let mut s = store.write().await;
                        // Pass sender identity for access control enforcement.
                        // The gossip V2 wire format includes a verified AgentId.
                        let writer = msg.sender.as_ref();
                        if let Err(e) = s.merge_delta(&delta, peer_id, writer) {
                            tracing::warn!("Failed to merge KvStore delta: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize KvStore delta: {e}");
                    }
                }
            }
        });

        // Responder: holders with non-empty state answer StateRequests by
        // republishing their full state as a regular delta on the main
        // topic. CRDT merge makes duplicate responses from multiple
        // holders harmless (idempotent), so no response suppression is
        // needed at current mesh sizes.
        let mut sync_sub = self.pubsub.subscribe(self.state_sync_topic()).await;
        let responder_store = Arc::clone(&self.store);
        let responder_pubsub = Arc::clone(&self.pubsub);
        let responder_topic = self.topic.clone();
        let local_peer_id = self.local_peer_id;
        tokio::spawn(async move {
            while let Some(msg) = sync_sub.recv().await {
                let Ok(KvSyncMessage::StateRequest { requester }) =
                    bincode::deserialize::<KvSyncMessage>(&msg.payload)
                else {
                    continue;
                };
                if requester == local_peer_id {
                    continue;
                }
                let full = {
                    let s = responder_store.read().await;
                    if s.is_empty() {
                        continue;
                    }
                    s.full_delta()
                };
                let Ok(serialized) = bincode::serialize(&(local_peer_id, full)) else {
                    continue;
                };
                if let Err(e) = responder_pubsub
                    .publish(responder_topic.clone(), bytes::Bytes::from(serialized))
                    .await
                {
                    tracing::warn!("KvStore state-response publish failed: {e}");
                }
            }
        });

        // Bootstrap requester: a first-time joiner starts with an empty
        // store and has no other way to learn keys written before it
        // subscribed (the gossip message cache only replays ~60s, and
        // pruning on busy topics removes older deltas entirely). Ask
        // holders to republish over a short retry schedule. The full
        // schedule always runs — a partial state arriving early (for
        // example fresh keys via cache replay) must not stop the
        // request for the complete historical state. Requests and the
        // full-delta responses they trigger are idempotent CRDT merges,
        // so the extra chatter is bounded and harmless. A creator of a
        // genuinely new store also sends these — nobody answers.
        if self.store.read().await.is_empty() {
            let requester_pubsub = Arc::clone(&self.pubsub);
            let sync_topic = self.state_sync_topic();
            tokio::spawn(async move {
                for delay_secs in STATE_REQUEST_RETRY_SECS {
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                    let request = KvSyncMessage::StateRequest {
                        requester: local_peer_id,
                    };
                    let Ok(serialized) = bincode::serialize(&request) else {
                        return;
                    };
                    if let Err(e) = requester_pubsub
                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                        .await
                    {
                        tracing::debug!("KvStore state-request publish failed: {e}");
                    }
                }
            });
        }

        Ok(())
    }

    /// Stop background synchronization.
    pub async fn stop(&self) -> Result<()> {
        self.pubsub.unsubscribe(&self.topic).await;
        self.pubsub.unsubscribe(&self.state_sync_topic()).await;
        Ok(())
    }

    /// Publish a local delta to the gossip network.
    pub async fn publish_delta(&self, local_peer_id: PeerId, delta: KvStoreDelta) -> Result<()> {
        let serialized = bincode::serialize(&(local_peer_id, delta))
            .map_err(|e| crate::kv::KvError::Gossip(format!("serialize delta failed: {e}")))?;

        self.pubsub
            .publish(self.topic.clone(), bytes::Bytes::from(serialized))
            .await
            .map_err(|e| crate::kv::KvError::Gossip(format!("publish delta failed: {e}")))?;

        Ok(())
    }

    /// Get a read-only reference to the store.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, KvStore> {
        self.store.read().await
    }

    /// Get a mutable reference to the store.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, KvStore> {
        self.store.write().await
    }

    /// Get the topic name.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentId;
    use crate::kv::store::AccessPolicy;
    use crate::kv::{KvEntry, KvStoreId};

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn store_id(n: u8) -> KvStoreId {
        KvStoreId::new([n; 32])
    }

    #[tokio::test]
    async fn test_kv_store_sync_creation() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        let _store_for_sync = store;
    }

    #[tokio::test]
    async fn test_apply_delta_directly() {
        let owner = agent(1);
        let writer = agent(2);
        let p2 = peer(2);

        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        );
        store.allow_writer(writer, &owner).expect("allow");
        let store_arc = Arc::new(RwLock::new(store));

        let entry = KvEntry::new(
            "newkey".to_string(),
            b"value".to_vec(),
            "text/plain".to_string(),
        );
        let mut delta = KvStoreDelta::new(1);
        delta.added.insert("newkey".to_string(), (entry, (p2, 1)));

        {
            let mut s = store_arc.write().await;
            s.merge_delta(&delta, p2, Some(&writer)).expect("merge");
        }

        {
            let s = store_arc.read().await;
            assert!(s.get("newkey").is_some());
        }
    }

    #[tokio::test]
    async fn test_concurrent_reads() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        let store_arc = Arc::new(RwLock::new(store));

        let s1 = store_arc.read().await;
        let s2 = store_arc.read().await;

        assert_eq!(s1.name(), "Test");
        assert_eq!(s2.name(), "Test");
    }
}
