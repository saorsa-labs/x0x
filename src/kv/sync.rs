//! KvStore synchronization using anti-entropy gossip.
//!
//! Wraps a KvStore in `Arc<RwLock<>>` for concurrent access and
//! synchronizes it via gossip pub/sub delta propagation.

use crate::gossip::wire::{decode_delta, encode_delta};
use crate::gossip::PubSubManager;
use crate::identity::AgentId;
use crate::kv::store::AccessPolicy;
use crate::kv::{KvStore, KvStoreDelta, Result};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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
///
/// Wire compatibility: `StateRequest` keeps its variant index and shape, so
/// v0.30.1 peers decode it unchanged. Older peers receiving the newer
/// `OwnerAnnounce` variant fail to deserialize it and skip the message
/// (their receive loop tolerates undecodable payloads), so the addition is
/// purely additive.
#[derive(Debug, Serialize, Deserialize)]
enum KvSyncMessage {
    /// A peer with no local state for the store asks holders to republish
    /// their full state (as a regular delta) on the main topic.
    StateRequest { requester: PeerId },
    /// The store owner's self-attestation of the store's authoritative
    /// metadata, published in response to a `StateRequest`.
    ///
    /// Trust model: the pub/sub layer verifies the ML-DSA-65 signature of
    /// every delivered v2 message and exposes the verified sender `AgentId`.
    /// The verified sender must equal the claimed `owner` — an owner can only
    /// attest to its own stores, and no third party can assign ownership.
    ///
    /// **Ownership is never established from this message.** A receiver's
    /// owner is anchored only at construction (see `KvStore::new_replica`).
    /// The announce can solely refresh policy (when the owner matches AND
    /// `policy_version` is strictly newer, blocking a replayed stale announce
    /// from downgrading policy) or record a conflict.
    OwnerAnnounce {
        /// The owning agent (must equal the verified message sender).
        owner: AgentId,
        /// The store's access policy as set by the owner.
        policy: AccessPolicy,
        /// Monotonic freshness counter — a refresh applies only when this is
        /// strictly greater than the receiver's current `policy_version`.
        policy_version: u64,
    },
}

/// Synchronization wrapper for a KvStore.
///
/// Manages automatic background synchronization using anti-entropy gossip.
/// Changes are propagated via deltas published to a gossip topic.
pub struct KvStoreSync {
    /// The store being synchronized.
    store: Arc<RwLock<KvStore>>,

    /// Pub/sub manager for topic-based messaging.
    pubsub: Arc<PubSubManager>,

    /// Topic name for this store.
    topic: String,

    /// This node's gossip peer id — identifies our deltas and state
    /// requests on the wire.
    local_peer_id: PeerId,

    /// This node's agent id, when known. Used to decide whether this node
    /// is the store owner (and should answer state requests with an
    /// [`KvSyncMessage::OwnerAnnounce`]) and to ignore its own announces.
    local_agent_id: Option<AgentId>,

    /// Optional on-disk snapshot path. When set (see
    /// [`set_persist_path`](Self::set_persist_path)), the full store state is
    /// bincode-snapshotted atomically after every local mutation and every
    /// merged remote delta, so a restart restores policy, keyset, entry
    /// contents, the latest adopted checkpoint, and the checkpoint high-water
    /// mark instead of coming back as an empty replica. This is what makes
    /// `AppendOnly` immutability survive a restart: an owner (or replica)
    /// with amnesia would otherwise accept rewrites of keys it no longer
    /// remembers holding.
    persist_path: std::sync::Mutex<Option<PathBuf>>,
}

impl KvStoreSync {
    /// Create a new KvStore synchronization manager.
    ///
    /// # Arguments
    ///
    /// * `store` - The KvStore to synchronize.
    /// * `pubsub` - Pub/sub manager for gossip messaging.
    /// * `topic` - Topic name for pub/sub.
    /// * `local_peer_id` - This node's gossip peer id.
    /// * `local_agent_id` - This node's agent id, if available. Required for
    ///   the owner to answer state requests with an ownership announcement;
    ///   `None` disables announcing (joined replicas can still adopt).
    pub fn new(
        store: KvStore,
        pubsub: Arc<PubSubManager>,
        topic: String,
        local_peer_id: PeerId,
        local_agent_id: Option<AgentId>,
    ) -> Result<Self> {
        let store = Arc::new(RwLock::new(store));

        Ok(Self {
            store,
            pubsub,
            topic,
            local_peer_id,
            local_agent_id,
            persist_path: std::sync::Mutex::new(None),
        })
    }

    /// Enable on-disk snapshot persistence at `path`.
    ///
    /// Call before [`start`](Self::start) so no merged delta can land
    /// unpersisted. The caller is responsible for loading any existing
    /// snapshot BEFORE constructing this sync (see
    /// [`load_snapshot`](load_snapshot)); this method only arms writes.
    pub fn set_persist_path(&self, path: PathBuf) {
        if let Ok(mut guard) = self.persist_path.lock() {
            *guard = Some(path);
        }
    }

    /// Snapshot the store to the configured persist path (no-op when
    /// persistence is not armed). Failures are error-logged, never silent —
    /// the in-memory state is already committed and published, so the write
    /// path does not unwind, but a failing disk must be loud (it reopens the
    /// restart-amnesia window this exists to close).
    pub async fn persist(&self) {
        let path = match self.persist_path.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        };
        if let Some(path) = path {
            persist_snapshot(&self.store, &path).await;
        }
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
        self.start_with_spawner(|fut| {
            tokio::spawn(fut);
        })
        .await
    }

    /// Start background synchronization with a caller-supplied spawner.
    ///
    /// Identical to [`start`](Self::start), but routes the background loops
    /// (delta-merge listener, state-request responder, and the bounded
    /// bootstrap requester) through `spawn` instead of detaching them with
    /// `tokio::spawn`. The `Agent` passes its tracked-task spawner so these
    /// loops are registered with the `Agent::shutdown()` drain and aborted on
    /// teardown (issue #126); callers without an `Agent` use
    /// [`start`](Self::start), which detaches via `tokio::spawn` as before.
    pub async fn start_with_spawner<S>(&self, spawn: S) -> Result<()>
    where
        S: Fn(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>)
            + Send
            + Sync,
    {
        let mut sub = self.pubsub.subscribe(self.topic.clone()).await;
        let store = Arc::clone(&self.store);
        // Capture emptiness BEFORE any listener can merge a cached delta.
        // Otherwise a partial cache replay landing between subscribe and this
        // check would make the store non-empty and skip the bootstrap
        // state-request schedule — aged/pruned keys would never arrive.
        let bootstrap_needed = store.read().await.is_empty();
        // Defense in depth against cross-topic replay: the v2 signature covers
        // the embedded topic, but pub/sub delivery does not re-check it against
        // this subscription, so a raw-mesh participant could place a valid
        // owner-signed envelope from store A under topic B. Each listener binds
        // to the exact topic it subscribed to.
        let main_topic = self.topic.clone();
        // Snapshot the persist path once: it is armed before start() by
        // construction (set_persist_path docs), so the loops never observe a
        // late change.
        let persist_path = self.persist_path.lock().ok().and_then(|g| g.clone());

        let loop_persist_path = persist_path.clone();
        spawn(Box::pin(async move {
            while let Some(msg) = sub.recv().await {
                if msg.topic != main_topic {
                    // Cross-topic replay defense: ignore envelopes not on our
                    // subscribed topic (see start_with_spawner).
                    continue;
                }
                let decoded = decode_delta::<KvStoreDelta>(&msg.payload);
                match decoded {
                    Ok((peer_id, delta)) => {
                        let merged = {
                            let mut s = store.write().await;
                            // Pass sender identity for access control enforcement.
                            // The gossip V2 wire format includes a verified AgentId.
                            let writer = msg.sender.as_ref();
                            match s.merge_delta(&delta, peer_id, writer) {
                                Ok(()) => true,
                                Err(e) => {
                                    tracing::warn!("Failed to merge KvStore delta: {e}");
                                    false
                                }
                            }
                        };
                        // Persist OUTSIDE the write guard so disk latency
                        // never blocks other writers.
                        if merged {
                            if let Some(path) = loop_persist_path.as_ref() {
                                persist_snapshot(&store, path).await;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize KvStore delta: {e}");
                    }
                }
            }
        }));

        // Responder + ownership listener on the state-sync side topic.
        //
        // StateRequest: holders with non-empty state answer by republishing
        // their full state as a regular delta on the main topic. CRDT merge
        // makes duplicate responses from multiple holders harmless
        // (idempotent), so no response suppression is needed at current mesh
        // sizes. Additionally, if this node is the store OWNER it publishes
        // an OwnerAnnounce (regardless of emptiness) so joined replicas can
        // learn the authoritative owner and policy.
        //
        // OwnerAnnounce: a replica with an unknown owner adopts the owner
        // and policy — but only when the announcement's pub/sub-verified
        // sender is the claimed owner itself (see KvSyncMessage docs).
        let mut sync_sub = self.pubsub.subscribe(self.state_sync_topic()).await;
        let responder_store = Arc::clone(&self.store);
        let responder_persist_path = persist_path.clone();
        let responder_pubsub = Arc::clone(&self.pubsub);
        let responder_topic = self.topic.clone();
        let sync_topic = self.state_sync_topic();
        let local_peer_id = self.local_peer_id;
        let local_agent_id = self.local_agent_id;
        spawn(Box::pin(async move {
            while let Some(msg) = sync_sub.recv().await {
                if msg.topic != sync_topic {
                    // Cross-topic replay defense (see start_with_spawner).
                    continue;
                }
                let Ok(sync_msg) = bincode::deserialize::<KvSyncMessage>(&msg.payload) else {
                    continue;
                };
                match sync_msg {
                    KvSyncMessage::StateRequest { requester } => {
                        if requester == local_peer_id {
                            continue;
                        }
                        // Owner: announce authoritative metadata so anchored
                        // joiners can refresh policy / confirm ownership.
                        // (Ownership itself is never learned from this — a
                        // joiner anchors its owner at construction.)
                        let announce = {
                            let s = responder_store.read().await;
                            match (local_agent_id, s.owner()) {
                                (Some(me), Some(owner)) if me == *owner => {
                                    Some(KvSyncMessage::OwnerAnnounce {
                                        owner: me,
                                        policy: s.policy().clone(),
                                        policy_version: s.policy_version(),
                                    })
                                }
                                _ => None,
                            }
                        };
                        if let Some(announce) = announce {
                            match bincode::serialize(&announce) {
                                Ok(serialized) => {
                                    if let Err(e) = responder_pubsub
                                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                                        .await
                                    {
                                        tracing::warn!(
                                            "KvStore owner-announce publish failed: {e}"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("KvStore owner-announce serialize failed: {e}");
                                }
                            }
                        }
                        let full = {
                            let s = responder_store.read().await;
                            if s.is_empty() {
                                continue;
                            }
                            s.full_delta()
                        };
                        let Ok(serialized) = encode_delta(local_peer_id, &full) else {
                            continue;
                        };
                        if let Err(e) = responder_pubsub
                            .publish(responder_topic.clone(), bytes::Bytes::from(serialized))
                            .await
                        {
                            tracing::warn!("KvStore state-response publish failed: {e}");
                        }
                    }
                    KvSyncMessage::OwnerAnnounce {
                        owner,
                        policy,
                        policy_version,
                    } => {
                        // Only a signature-verified sender is trusted; the
                        // pub/sub layer drops signed messages that fail
                        // verification, so `sender: Some(..)` is verified.
                        let Some(sender) = msg.sender else {
                            tracing::warn!(
                                "ignoring unsigned KvStore ownership announcement on {}",
                                msg.topic
                            );
                            continue;
                        };
                        if local_agent_id.is_some_and(|me| me == sender) {
                            continue; // our own announce echoed back
                        }
                        let learned = {
                            let mut s = responder_store.write().await;
                            // learn_ownership can only refresh policy (when the
                            // owner matches and policy_version is forward) or
                            // record a conflict; it never establishes ownership.
                            // AppendOnly is terminal: a downgrade announce is
                            // rejected inside learn_ownership regardless of
                            // policy_version.
                            match s.learn_ownership(owner, policy, policy_version, &sender) {
                                Ok(()) => {
                                    tracing::info!(
                                        "KvStore {} processed owner announce from {} (policy {}, version {})",
                                        s.id(),
                                        hex::encode(owner.as_bytes()),
                                        s.policy(),
                                        s.policy_version()
                                    );
                                    true
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "rejected KvStore ownership announcement from {}: {e}",
                                        hex::encode(sender.as_bytes())
                                    );
                                    false
                                }
                            }
                        };
                        // A policy refresh mutates durable state — persist it
                        // (outside the write guard).
                        if learned {
                            if let Some(path) = responder_persist_path.as_ref() {
                                persist_snapshot(&responder_store, path).await;
                            }
                        }
                    }
                }
            }
        }));

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
        if bootstrap_needed {
            let requester_pubsub = Arc::clone(&self.pubsub);
            let sync_topic = self.state_sync_topic();
            spawn(Box::pin(async move {
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
            }));
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
        let serialized = encode_delta(local_peer_id, &delta)
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

/// Monotonic counter for unique snapshot temp-file names — concurrent
/// persists (receive loop vs. local write) must never clobber each other's
/// temp file mid-rename.
static SNAPSHOT_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Snapshot the store to `path` (bincode, atomic temp-file + fsync + rename).
///
/// Failures are error-logged and never unwind the caller: the in-memory
/// mutation is already committed and published, so the correct response to a
/// failing disk is a loud log, not a poisoned store.
async fn persist_snapshot(store: &Arc<RwLock<KvStore>>, path: &Path) {
    let bytes = {
        let s = store.read().await;
        match bincode::serialize(&*s) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("kv snapshot serialize failed for {}: {e}", path.display());
                return;
            }
        }
    };
    if let Err(e) = write_snapshot_atomic(path, &bytes) {
        tracing::error!("kv snapshot write failed for {}: {e}", path.display());
    }
}

/// Durable atomic file write: unique temp file in the same directory,
/// fsync, then rename over the destination.
fn write_snapshot_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let n = SNAPSHOT_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{n}", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Load a previously persisted store snapshot from `path`.
///
/// Returns:
/// - `Ok(Some(store))` — snapshot present and valid.
/// - `Ok(None)` — no snapshot at `path` (first run).
/// - `Err(_)` — snapshot present but unreadable/undecodable. Callers MUST
///   fail closed on this (refuse to start an empty replica over a corrupt
///   snapshot): silently discarding it would reopen the restart-amnesia
///   window (an `AppendOnly` owner that forgets its keys will re-accept
///   rewrites of them).
///
/// The restored store's in-memory `seq_counter` (not serialized) is floored
/// to `version` so freshly minted OR-Set tags can never collide with tags
/// issued before the restart.
///
/// # Errors
///
/// [`crate::kv::KvError::Io`]/[`crate::kv::KvError::Serialization`] as above.
pub fn load_snapshot(path: &Path) -> Result<Option<KvStore>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let store: KvStore = bincode::deserialize(&bytes)?;
    store.floor_seq_counter_to_version();
    Ok(Some(store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentId;
    use crate::kv::store::AccessPolicy;
    use crate::kv::{KvEntry, KvStoreId};
    use crate::network::{NetworkConfig, NetworkNode};
    use std::time::Duration;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn store_id(n: u8) -> KvStoreId {
        KvStoreId::new([n; 32])
    }

    /// Construct an isolated network node (mirrors the helper in
    /// `src/gossip/pubsub.rs` tests). `PubSubManager` is fully constructable
    /// in tests, so `KvStoreSync` is testable end-to-end without a live mesh.
    async fn make_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(NetworkConfig::default(), None, None)
                .await
                .expect("network node"),
        )
    }

    /// Build a `KvStoreSync` around a fresh node + pubsub, with
    /// `owner = agent(1)` and `local_peer_id = peer(1)`.
    async fn make_sync(topic: &str, policy: AccessPolicy) -> KvStoreSync {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let store = KvStore::new(store_id(1), "Test".to_string(), agent(1), policy);
        KvStoreSync::new(store, pubsub, topic.to_string(), peer(1), Some(agent(1)))
            .expect("kv sync")
    }

    /// Build a `KvStoreSync` that shares its pubsub with the caller (so the
    /// caller can subscribe before the sync publishes).
    async fn make_sync_with_pubsub(
        topic: &str,
        policy: AccessPolicy,
    ) -> (KvStoreSync, Arc<PubSubManager>) {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let store = KvStore::new(store_id(1), "Test".to_string(), agent(1), policy);
        let sync = KvStoreSync::new(
            store,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(agent(1)),
        )
        .expect("kv sync");
        (sync, pubsub)
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

    // ------------------------------------------------------------------
    // new() / topic() / read() / write()
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn new_sets_topic_and_yields_accessible_guards() {
        let sync = make_sync("store/A", AccessPolicy::Signed).await;

        // topic() reports exactly the topic handed to new().
        assert_eq!(sync.topic(), "store/A");

        // read() exposes the underlying store unchanged.
        {
            let s = sync.read().await;
            assert_eq!(s.name(), "Test");
            assert!(s.is_empty());
        }

        // write() returns a mutable guard; verify it is usable by merging
        // an owner-authored delta into the Signed store, then observe it via
        // read(). This also exercises the read/write guard pair end-to-end.
        let owner = agent(1);
        let entry = KvEntry::new(
            "owner-key".to_string(),
            b"v".to_vec(),
            "text/plain".to_string(),
        );
        let mut delta = KvStoreDelta::new(1);
        delta
            .added
            .insert("owner-key".to_string(), (entry, (peer(1), 1)));
        {
            let mut s = sync.write().await;
            s.merge_delta(&delta, peer(1), Some(&owner))
                .expect("owner merge");
        }

        let s = sync.read().await;
        assert!(s.get("owner-key").is_some(), "owner write must be visible");
    }

    // ------------------------------------------------------------------
    // state_sync_topic() (private helper exercised from the test module)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn state_sync_topic_appends_side_channel_suffix() {
        let sync = make_sync("store/B", AccessPolicy::Signed).await;
        // The private helper forms the side channel by appending the suffix.
        assert_eq!(sync.state_sync_topic(), "store/B/state-sync");

        // Suffix is appended exactly once, regardless of slashes in topic.
        let sync2 = make_sync("store/B/nested", AccessPolicy::Signed).await;
        assert_eq!(sync2.state_sync_topic(), "store/B/nested/state-sync");
    }

    // ------------------------------------------------------------------
    // publish_delta(): wire round-trip observed by a subscriber
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn publish_delta_delivers_encoded_pair_to_subscriber() {
        let (sync, pubsub) = make_sync_with_pubsub("store/C", AccessPolicy::Signed).await;

        // Subscribe to the main topic BEFORE publishing so we observe the
        // exact bytes KvStoreSync places on the wire.
        let mut sub = pubsub.subscribe("store/C".to_string()).await;

        let sender = peer(7);
        let entry = KvEntry::new(
            "remote".to_string(),
            b"payload".to_vec(),
            "application/octet-stream".to_string(),
        );
        let mut delta = KvStoreDelta::new(9);
        delta
            .added
            .insert("remote".to_string(), (entry, (sender, 3)));

        sync.publish_delta(sender, delta)
            .await
            .expect("publish_delta");

        let msg = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .expect("timed out waiting for published delta")
            .expect("subscriber stream closed");

        // The published payload must decode back to the (sender, delta) pair
        // that publish_delta encoded — proving the wire format is correct.
        let (observed_sender, observed_delta) =
            decode_delta::<KvStoreDelta>(&msg.payload).expect("wire decode");
        assert_eq!(observed_sender, sender);
        assert_eq!(observed_delta.version, 9);
        assert!(observed_delta.added.contains_key("remote"));
        assert_eq!(msg.topic, "store/C");
        // Sanity: the same delta also round-trips through encode_delta alone.
        let reencoded = encode_delta(sender, &observed_delta).expect("re-encode");
        let (s2, d2) = decode_delta::<KvStoreDelta>(&reencoded).expect("re-decode");
        assert_eq!(s2, sender);
        assert_eq!(d2.version, 9);
    }

    // ------------------------------------------------------------------
    // start_with_spawner(): subscribes + returns Ok with a drop-spawner
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn start_with_spawner_subscribes_and_returns_ok() {
        // Unique value vs `start_default_spawner_merges_remote_delta`: this
        // routes the background futures through a *custom* (non-`tokio::spawn`)
        // spawner closure — a drop-spawner — exercising that generic code path
        // and asserting `start_with_spawner` returns `Ok` without panicking.
        //
        // It deliberately does NOT assert that a subscription or merge
        // occurred: a drop-spawner makes subscription unobservable, so this
        // would still pass against a no-op `Ok(())` impl. The real
        // subscribe->merge behaviour is asserted end-to-end by
        // `start_default_spawner_merges_remote_delta`, which drives
        // `start_with_spawner(tokio::spawn)` and verifies the key lands.
        let sync = make_sync("store/D", AccessPolicy::Signed).await;
        sync.start_with_spawner(|_fut| {
            // intentionally drop the future
        })
        .await
        .expect("start_with_spawner");
    }

    // ------------------------------------------------------------------
    // start(): default spawner merges a remotely-published delta
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn start_default_spawner_merges_remote_delta() {
        // End-to-end exercise of the delta-merge listener: a delta published
        // on the topic is received by the background loop spawned by start()
        // and merged into the local store. We use an Encrypted policy so an
        // unsigned (anonymous-sender) delta is accepted by the store's
        // access control — matching what the wire delivers for an unsigned
        // publish via a PubSubManager with no signing context.
        let sync = make_sync(
            "store/E",
            AccessPolicy::Encrypted {
                group_id: vec![1, 2, 3],
            },
        )
        .await;

        sync.start().await.expect("start");

        // Let the spawned subscribe-forwarder register before we publish.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let entry = KvEntry::new(
            "merged-key".to_string(),
            b"hello".to_vec(),
            "text/plain".to_string(),
        );
        let mut delta = KvStoreDelta::new(1);
        delta
            .added
            .insert("merged-key".to_string(), (entry, (peer(2), 1)));
        sync.publish_delta(peer(2), delta).await.expect("publish");

        // The merge is asynchronous; poll the store until it lands.
        let landed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let present = {
                    let s = sync.read().await;
                    s.get("merged-key").is_some()
                };
                if present {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        assert!(
            landed.is_ok(),
            "remote delta was not merged by start() loop"
        );
    }

    // ------------------------------------------------------------------
    // stop(): returns Ok and is idempotent
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn stop_returns_ok_and_is_idempotent() {
        let sync = make_sync("store/F", AccessPolicy::Signed).await;
        sync.stop().await.expect("first stop");
        // stop() unsubscribes both the main and the state-sync topic;
        // unsubscribe is infallible and tolerant of already-removed topics,
        // so a second stop() must remain Ok.
        sync.stop().await.expect("second stop (idempotent)");
    }
}
