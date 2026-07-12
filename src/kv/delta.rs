//! Delta-CRDT implementation for bandwidth-efficient KvStore synchronization.
//!
//! Instead of sending the entire KvStore on every sync, we track version
//! numbers and generate deltas containing only changes since a given version.

use crate::identity::AgentId;
use crate::kv::{KvEntry, KvStore};
use saorsa_gossip_crdt_sync::{DeltaCrdt, LwwRegister};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Unique tag for OR-Set elements: (PeerId, sequence_number).
pub type UniqueTag = (PeerId, u64);

/// Deserialize an optional owner checkpoint, tolerating its absence (trailing
/// field). A legacy peer's delta omits this field entirely; decoding it on a
/// current node yields `None` instead of an EOF error, preserving cross-version
/// delta compatibility. A malformed value is also treated as `None` (the delta
/// then falls back to sender-auth).
pub(crate) fn deserialize_checkpoint_opt<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<crate::kv::store::OwnerCheckpoint>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(Option::<crate::kv::store::OwnerCheckpoint>::deserialize(deserializer).unwrap_or(None))
}

/// Delta representing changes to a KvStore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvStoreDelta {
    /// Keys/entries that were added (key -> (entry, unique_tag)).
    pub added: HashMap<String, (KvEntry, UniqueTag)>,

    /// Keys that were removed (key -> set of tags to remove).
    pub removed: HashMap<String, HashSet<UniqueTag>>,

    /// Value updates to existing keys (key -> full entry).
    pub updated: HashMap<String, KvEntry>,

    /// Name update, carried as the full LWW register (value + vector clock)
    /// so the receiver resolves it by causality rather than adopting it
    /// unconditionally.
    pub name_update: Option<LwwRegister<String>>,

    /// Agents added to the allowlist (owner-only, propagated via delta).
    pub allowlist_additions: Option<Vec<AgentId>>,

    /// Agents removed from the allowlist (owner-only, propagated via delta).
    pub allowlist_removals: Option<Vec<AgentId>>,

    /// Version number of this delta.
    pub version: u64,

    /// Owner-signed checkpoint carried by owner-published deltas and relays.
    /// Replicas cache it; an anchored receiver verifies the owner signature +
    /// recomputed content root and adopts the proven entries independent of
    /// the relayer. `None` uses the existing sender-auth path. The field is
    /// trailing and deserializes to `None` if absent (so a legacy pre-checkpoint
    /// peer's 7-field delta still decodes on a current node).
    #[serde(default, deserialize_with = "deserialize_checkpoint_opt")]
    pub owner_checkpoint: Option<crate::kv::store::OwnerCheckpoint>,
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
            owner_checkpoint: None,
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
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.updated.is_empty()
            && self.name_update.is_none()
            && self.allowlist_additions.is_none()
            && self.allowlist_removals.is_none()
            && self.owner_checkpoint.is_none()
    }
}

/// Implement `DeltaCrdt` trait for KvStore.
///
/// Enables participation in saorsa-gossip's delta-based sync infrastructure.
impl DeltaCrdt for KvStore {
    type Delta = KvStoreDelta;

    fn merge(&mut self, delta: &Self::Delta) -> anyhow::Result<()> {
        let peer_id = PeerId::new([0u8; 32]);
        // Anti-entropy merges don't carry writer identity. Signed/Allowlisted
        // stores rely on the main sync path in KvStoreSync to provide the
        // writer identity; Encrypted is currently a reserved policy shape, not
        // transport confidentiality for KvStore deltas.
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

        // A peer renames the store on top of the shared initial state; its
        // name register causally dominates ours, so the LWW merge adopts it.
        let mut other = KvStore::new(id, "Original".to_string(), owner, AccessPolicy::Signed);
        other.update_name("Updated".to_string(), peer(1));

        let mut delta = KvStoreDelta::new(1);
        delta.name_update = Some(other.name_register().clone());

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

    #[test]
    fn test_legacy_delta_without_checkpoint_decodes() {
        // A pre-checkpoint (legacy / v0.30.1) delta omits the owner_checkpoint
        // field entirely. It must still decode on a current node, with the
        // checkpoint defaulting to None — otherwise cross-version Signed-store
        // convergence (legacy owner -> current joiner) would break.
        #[derive(Serialize)]
        struct LegacyDelta {
            added: HashMap<String, (KvEntry, UniqueTag)>,
            removed: HashMap<String, HashSet<UniqueTag>>,
            updated: HashMap<String, KvEntry>,
            name_update: Option<LwwRegister<String>>,
            allowlist_additions: Option<Vec<AgentId>>,
            allowlist_removals: Option<Vec<AgentId>>,
            version: u64,
        }
        let legacy = LegacyDelta {
            added: HashMap::new(),
            removed: HashMap::new(),
            updated: HashMap::new(),
            name_update: None,
            allowlist_additions: None,
            allowlist_removals: None,
            version: 7,
        };
        let bytes = bincode::serialize(&legacy).expect("serialize legacy");
        let restored: KvStoreDelta =
            bincode::deserialize(&bytes).expect("legacy delta must decode");
        assert_eq!(restored.version, 7);
        assert!(restored.owner_checkpoint.is_none());
    }
}
