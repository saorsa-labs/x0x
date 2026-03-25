//! Delta-CRDT implementation for bandwidth-efficient KvStore synchronization.
//!
//! Instead of sending the entire KvStore on every sync, we track version
//! numbers and generate deltas containing only changes since a given version.

use crate::identity::AgentId;
use crate::kv::{KvEntry, KvStore};
use saorsa_gossip_crdt_sync::DeltaCrdt;
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Unique tag for OR-Set elements: (PeerId, sequence_number).
pub type UniqueTag = (PeerId, u64);

/// Delta representing changes to a KvStore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvStoreDelta {
    /// Keys/entries that were added (key -> (entry, unique_tag)).
    pub added: HashMap<String, (KvEntry, UniqueTag)>,

    /// Keys that were removed (key -> set of tags to remove).
    pub removed: HashMap<String, HashSet<UniqueTag>>,

    /// Value updates to existing keys (key -> full entry).
    pub updated: HashMap<String, KvEntry>,

    /// Name update (LWW semantics).
    pub name_update: Option<String>,

    /// Agents added to the allowlist (owner-only, propagated via delta).
    pub allowlist_additions: Option<Vec<AgentId>>,

    /// Agents removed from the allowlist (owner-only, propagated via delta).
    pub allowlist_removals: Option<Vec<AgentId>>,

    /// Version number of this delta.
    pub version: u64,
}

impl KvStoreDelta {
    /// Create an empty delta at a given version.
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self {
            added: HashMap::new(),
            removed: HashMap::new(),
            updated: HashMap::new(),
            name_update: None,
            allowlist_additions: None,
            allowlist_removals: None,
            version,
        }
    }

    /// Create a delta for a single put operation.
    #[must_use]
    pub fn for_put(key: String, entry: KvEntry, tag: UniqueTag, version: u64) -> Self {
        let mut delta = Self::new(version);
        delta.added.insert(key, (entry, tag));
        delta
    }

    /// Create a delta for a value update.
    #[must_use]
    pub fn for_update(key: String, entry: KvEntry, version: u64) -> Self {
        let mut delta = Self::new(version);
        delta.updated.insert(key, entry);
        delta
    }

    /// Check if this delta is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.updated.is_empty()
            && self.name_update.is_none()
            && self.allowlist_additions.is_none()
            && self.allowlist_removals.is_none()
    }
}

/// Implement `DeltaCrdt` trait for KvStore.
///
/// Enables participation in saorsa-gossip's delta-based sync infrastructure.
impl DeltaCrdt for KvStore {
    type Delta = KvStoreDelta;

    fn merge(&mut self, delta: &Self::Delta) -> anyhow::Result<()> {
        let peer_id = PeerId::new([0u8; 32]);
        // Anti-entropy merges don't carry writer identity — for Encrypted
        // stores this is fine (MLS group membership is the auth). For
        // Signed/Allowlisted stores, the main sync path in KvStoreSync
        // provides the writer identity; this trait-level merge is only
        // used by the anti-entropy background task.
        self.merge_delta(delta, peer_id, None)
            .map_err(|e| anyhow::anyhow!("KvStore delta merge failed: {e}"))
    }

    fn delta(&self, since_version: u64) -> Option<Self::Delta> {
        let current = self.current_version();
        if since_version >= current {
            return None;
        }
        Some(self.full_delta())
    }

    fn version(&self) -> u64 {
        self.current_version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentId;
    use crate::kv::store::AccessPolicy;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn store_id(n: u8) -> crate::kv::KvStoreId {
        crate::kv::KvStoreId::new([n; 32])
    }

    #[test]
    fn test_empty_delta() {
        let delta = KvStoreDelta::new(1);
        assert!(delta.is_empty());
        assert_eq!(delta.version, 1);
    }

    #[test]
    fn test_delta_with_put() {
        let entry = KvEntry::new("k".to_string(), b"v".to_vec(), "text/plain".to_string());
        let delta = KvStoreDelta::for_put("k".to_string(), entry, (peer(1), 1), 1);
        assert!(!delta.is_empty());
        assert_eq!(delta.added.len(), 1);
    }

    #[test]
    fn test_delta_with_update() {
        let entry = KvEntry::new("k".to_string(), b"v".to_vec(), "text/plain".to_string());
        let delta = KvStoreDelta::for_update("k".to_string(), entry, 2);
        assert!(!delta.is_empty());
        assert_eq!(delta.updated.len(), 1);
    }

    #[test]
    fn test_merge_delta_with_new_entry() {
        let owner = agent(1);
        let writer = agent(2);
        let id = store_id(1);

        // Allowlisted store so both agents can write
        let mut store = KvStore::new(id, "Store".to_string(), owner, AccessPolicy::Allowlisted);
        store.allow_writer(writer, &owner).expect("allow");

        let entry = KvEntry::new(
            "newkey".to_string(),
            b"value".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put("newkey".to_string(), entry, (peer(2), 1), 1);

        store
            .merge_delta(&delta, peer(2), Some(&writer))
            .expect("merge delta");
        assert!(store.get("newkey").is_some());
        assert_eq!(store.get("newkey").expect("entry").value, b"value");
    }

    #[test]
    fn test_merge_delta_with_name_update() {
        let owner = agent(1);
        let id = store_id(1);
        let mut store = KvStore::new(id, "Original".to_string(), owner, AccessPolicy::Signed);

        let mut delta = KvStoreDelta::new(1);
        delta.name_update = Some("Updated".to_string());

        store
            .merge_delta(&delta, peer(1), Some(&owner))
            .expect("merge delta");
        assert_eq!(store.name(), "Updated");
    }

    #[test]
    fn test_delta_crdt_trait() {
        let owner = agent(1);
        let id = store_id(1);

        // DeltaCrdt trait uses merge(None) — use Encrypted policy to allow it
        let mut s1 = KvStore::new(
            id,
            "Store".to_string(),
            owner,
            AccessPolicy::Encrypted {
                group_id: vec![1, 2, 3],
            },
        );
        let mut s2 = KvStore::new(
            id,
            "Store".to_string(),
            owner,
            AccessPolicy::Encrypted {
                group_id: vec![1, 2, 3],
            },
        );

        s2.put(
            "key".to_string(),
            b"val".to_vec(),
            "text/plain".to_string(),
            peer(2),
        )
        .expect("put");

        let delta = DeltaCrdt::delta(&s2, 0).expect("delta");
        DeltaCrdt::merge(&mut s1, &delta).expect("merge");

        assert!(DeltaCrdt::version(&s1) > 0);
    }

    #[test]
    fn test_delta_serialization() {
        let mut delta = KvStoreDelta::new(5);
        // Add allowlist to exercise all serialization paths
        delta.allowlist_additions = Some(vec![agent(1), agent(2)]);

        let bytes = bincode::serialize(&delta).expect("serialize");
        let restored: KvStoreDelta = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(delta.version, restored.version);
        assert!(restored.allowlist_additions.is_some());
        assert_eq!(restored.allowlist_additions.as_ref().map(Vec::len), Some(2));
    }
}
