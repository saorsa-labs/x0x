//! KvStore CRDT — a replicated key-value store with access control.
//!
//! Uses OR-Set for key membership (adds win over removes),
//! LWW semantics for values, and HashMap for content storage.
//!
//! ## Access Policies
//!
//! - **Signed**: Only the owner can write. Anyone can read. Incoming deltas
//!   from non-owners are rejected. Use for app stores, agent skill registries.
//! - **Allowlisted**: Only explicitly allowed writers can write. The owner
//!   manages the allowlist. Use for team workspaces, private swarms.
//! - **Encrypted**: Only MLS group members can read or write. Deltas are
//!   encrypted with the group key. Use for private data sharing.

use crate::identity::AgentId;
use crate::kv::{KvEntry, KvError, KvStoreDelta, Result};
use saorsa_gossip_crdt_sync::{LwwRegister, OrSet};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Access control policy for a KvStore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessPolicy {
    /// Only the owner can write. Anyone can read and replicate.
    /// Incoming deltas from non-owners are silently rejected.
    Signed,

    /// Only explicitly allowlisted agents can write.
    /// The owner manages the allowlist.
    Allowlisted,

    /// Only MLS group members can read or write.
    /// Deltas are encrypted with the group key before gossip.
    Encrypted {
        /// MLS group ID for this store.
        group_id: Vec<u8>,
    },
}

impl std::fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signed => write!(f, "signed"),
            Self::Allowlisted => write!(f, "allowlisted"),
            Self::Encrypted { .. } => write!(f, "encrypted"),
        }
    }
}

/// Unique identifier for a KvStore (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KvStoreId([u8; 32]);

impl KvStoreId {
    /// Create from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a store ID from a name and creator.
    #[must_use]
    pub fn from_content(name: &str, creator: &AgentId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.store");
        hasher.update(name.as_bytes());
        hasher.update(creator.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}

impl std::fmt::Display for KvStoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

fn default_seq_counter() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(0))
}

/// A replicated key-value store using CRDTs with access control.
///
/// Combines:
/// - OR-Set for key membership (which keys exist)
/// - HashMap for entry content (the KvEntry values)
/// - LWW-Register for store metadata (name)
/// - Access control via owner, allowlist, and policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvStore {
    /// Unique identifier for this store.
    id: KvStoreId,

    /// Key membership — OR-Set ensures adds win over removes.
    keys: OrSet<String>,

    /// Key-value entries indexed by key name.
    entries: HashMap<String, KvEntry>,

    /// Store name (LWW semantics).
    name: LwwRegister<String>,

    /// Access control policy.
    #[serde(default = "default_policy")]
    policy: AccessPolicy,

    /// Store owner (the agent that created it).
    /// For Signed and Allowlisted policies, only the owner (and allowlisted
    /// writers) can write.
    #[serde(default)]
    owner: Option<AgentId>,

    /// Agents allowed to write (for Allowlisted policy).
    /// The owner is implicitly allowed and does not need to be in this set.
    #[serde(default)]
    allowed_writers: HashSet<AgentId>,

    /// Version counter — incremented on every mutation.
    #[serde(default)]
    version: u64,

    /// Monotonic sequence counter for unique OR-Set tags.
    #[serde(skip, default = "default_seq_counter")]
    seq_counter: Arc<AtomicU64>,
}

fn default_policy() -> AccessPolicy {
    AccessPolicy::Signed
}

impl KvStore {
    /// Create a new empty KvStore with the given access policy.
    #[must_use]
    pub fn new(id: KvStoreId, name: String, owner: AgentId, policy: AccessPolicy) -> Self {
        Self {
            id,
            keys: OrSet::new(),
            entries: HashMap::new(),
            name: LwwRegister::new(name),
            policy,
            owner: Some(owner),
            allowed_writers: HashSet::new(),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the next monotonically-increasing sequence number.
    pub fn next_seq(&self) -> u64 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Get the current version.
    #[must_use]
    pub fn current_version(&self) -> u64 {
        self.version
    }

    /// Get the store ID.
    #[must_use]
    pub fn id(&self) -> &KvStoreId {
        &self.id
    }

    /// Get the store name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.get()
    }

    /// Get the access policy.
    #[must_use]
    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    /// Get the store owner.
    #[must_use]
    pub fn owner(&self) -> Option<&AgentId> {
        self.owner.as_ref()
    }

    /// Get the set of allowed writers.
    #[must_use]
    pub fn allowed_writers(&self) -> &HashSet<AgentId> {
        &self.allowed_writers
    }

    /// Get the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if an agent is authorized to write to this store.
    #[must_use]
    pub fn is_authorized(&self, agent_id: &AgentId) -> bool {
        match &self.policy {
            AccessPolicy::Signed => {
                // Only the owner can write
                self.owner.as_ref().is_some_and(|o| o == agent_id)
            }
            AccessPolicy::Allowlisted => {
                // Owner + allowlisted agents can write
                self.owner.as_ref().is_some_and(|o| o == agent_id)
                    || self.allowed_writers.contains(agent_id)
            }
            AccessPolicy::Encrypted { .. } => {
                // Authorization is handled by MLS group membership;
                // if you can decrypt, you're authorized.
                true
            }
        }
    }

    /// Add an agent to the allowlist (owner-only operation).
    ///
    /// # Errors
    ///
    /// Returns `KvError::Unauthorized` if the caller is not the owner.
    pub fn allow_writer(&mut self, writer: AgentId, caller: &AgentId) -> Result<()> {
        if !self.owner.as_ref().is_some_and(|o| o == caller) {
            return Err(KvError::Unauthorized(
                "only the store owner can modify the allowlist".to_string(),
            ));
        }
        self.allowed_writers.insert(writer);
        self.version += 1;
        Ok(())
    }

    /// Remove an agent from the allowlist (owner-only operation).
    ///
    /// # Errors
    ///
    /// Returns `KvError::Unauthorized` if the caller is not the owner.
    pub fn deny_writer(&mut self, writer: &AgentId, caller: &AgentId) -> Result<()> {
        if !self.owner.as_ref().is_some_and(|o| o == caller) {
            return Err(KvError::Unauthorized(
                "only the store owner can modify the allowlist".to_string(),
            ));
        }
        self.allowed_writers.remove(writer);
        self.version += 1;
        Ok(())
    }

    /// Put a key-value entry.
    ///
    /// If the key already exists, the value is updated using LWW semantics.
    pub fn put(
        &mut self,
        key: String,
        value: Vec<u8>,
        content_type: String,
        peer_id: PeerId,
    ) -> Result<()> {
        if value.len() > crate::kv::entry::MAX_INLINE_SIZE {
            return Err(KvError::ValueTooLarge {
                size: value.len(),
                max: crate::kv::entry::MAX_INLINE_SIZE,
            });
        }

        let seq = self.next_seq();

        // Add key to OR-Set
        self.keys
            .add(key.clone(), (peer_id, seq))
            .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;

        // Create or update entry
        if let Some(existing) = self.entries.get_mut(&key) {
            existing.update_value(value, content_type);
        } else {
            self.entries
                .insert(key.clone(), KvEntry::new(key, value, content_type));
        }

        self.version += 1;
        Ok(())
    }

    /// Get an entry by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&KvEntry> {
        let key_string = key.to_string();
        if self.keys.elements().contains(&&key_string) {
            self.entries.get(key)
        } else {
            None
        }
    }

    /// Remove a key from the store.
    pub fn remove(&mut self, key: &str) -> Result<()> {
        if !self.entries.contains_key(key) {
            return Err(KvError::KeyNotFound(key.to_string()));
        }

        self.keys
            .remove(&key.to_string())
            .map_err(|e| KvError::Merge(format!("OR-Set remove failed: {e}")))?;
        self.entries.remove(key);

        self.version += 1;
        Ok(())
    }

    /// List all active keys (not tombstoned).
    #[must_use]
    pub fn active_keys(&self) -> Vec<&String> {
        self.keys.elements().into_iter().collect()
    }

    /// List all active entries.
    #[must_use]
    pub fn active_entries(&self) -> Vec<&KvEntry> {
        let active: HashSet<String> = self.keys.elements().into_iter().cloned().collect();
        self.entries
            .values()
            .filter(|e| active.contains(&e.key))
            .collect()
    }

    /// Update the store name.
    pub fn update_name(&mut self, name: String, peer_id: PeerId) {
        self.name.set(name, peer_id);
        self.version += 1;
    }

    /// Merge a delta into this store.
    ///
    /// Enforces access control: if the store has a Signed or Allowlisted
    /// policy, the `writer` must be authorized. Unauthorized deltas are
    /// silently rejected (returns Ok but does not apply changes).
    pub fn merge_delta(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        writer: Option<&AgentId>,
    ) -> Result<()> {
        // Access control: reject unauthorized writes
        if let Some(writer_id) = writer {
            if !self.is_authorized(writer_id) {
                tracing::debug!(
                    "rejected delta from unauthorized writer {} for store {}",
                    hex::encode(writer_id.as_bytes()),
                    self.id
                );
                return Ok(()); // Silent rejection — don't propagate errors for spam
            }
        } else {
            // No writer identity — only allowed for Encrypted stores
            // (where MLS group membership is the authorization)
            match &self.policy {
                AccessPolicy::Encrypted { .. } => {} // OK
                _ => {
                    tracing::debug!(
                        "rejected anonymous delta for non-encrypted store {}",
                        self.id
                    );
                    return Ok(());
                }
            }
        }

        // Apply allowlist changes from the delta (owner-only)
        if let Some(ref additions) = delta.allowlist_additions {
            if writer.is_some_and(|w| self.owner.as_ref().is_some_and(|o| o == w)) {
                for agent in additions {
                    self.allowed_writers.insert(*agent);
                }
            }
        }
        if let Some(ref removals) = delta.allowlist_removals {
            if writer.is_some_and(|w| self.owner.as_ref().is_some_and(|o| o == w)) {
                for agent in removals {
                    self.allowed_writers.remove(agent);
                }
            }
        }

        // Apply added entries
        for (key, (entry, tag)) in &delta.added {
            self.keys
                .add(key.clone(), *tag)
                .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;

            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                self.entries.insert(key.clone(), entry.clone());
            }
        }

        // Apply removed keys
        for key in delta.removed.keys() {
            let _ = self.keys.remove(&key.to_string());
            self.entries.remove(key.as_str());
        }

        // Apply updated entries (upsert)
        for (key, entry) in &delta.updated {
            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                self.keys
                    .add(key.clone(), (peer_id, 0))
                    .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;
                self.entries.insert(key.clone(), entry.clone());
            }
        }

        // Apply name update
        if let Some(ref new_name) = delta.name_update {
            self.name.set(new_name.clone(), peer_id);
        }

        self.version += 1;
        Ok(())
    }

    /// Merge another store into this one.
    pub fn merge(&mut self, other: &KvStore) -> Result<()> {
        if self.id != other.id {
            return Err(KvError::StoreIdMismatch);
        }

        self.keys
            .merge_state(&other.keys)
            .map_err(|e| KvError::Merge(format!("OR-Set merge failed: {e}")))?;

        for (key, other_entry) in &other.entries {
            if let Some(our_entry) = self.entries.get_mut(key) {
                our_entry.merge(other_entry);
            } else {
                self.entries.insert(key.clone(), other_entry.clone());
            }
        }

        // Merge allowlists (union)
        for writer in &other.allowed_writers {
            self.allowed_writers.insert(*writer);
        }

        self.name.merge(&other.name);
        self.version += 1;
        Ok(())
    }

    /// Generate a delta containing all state (for initial sync).
    #[must_use]
    pub fn full_delta(&self) -> KvStoreDelta {
        let mut delta = KvStoreDelta::new(self.version);
        let active: HashSet<String> = self.keys.elements().into_iter().cloned().collect();

        for (key, entry) in &self.entries {
            if active.contains(key) {
                let tag = (PeerId::new([0u8; 32]), 0);
                delta.added.insert(key.clone(), (entry.clone(), tag));
            }
        }

        delta.name_update = Some(self.name().to_string());

        // Include allowlist in full delta
        if !self.allowed_writers.is_empty() {
            delta.allowlist_additions = Some(self.allowed_writers.iter().copied().collect());
        }

        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn store_id(n: u8) -> KvStoreId {
        KvStoreId::new([n; 32])
    }

    #[test]
    fn test_new_store() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        assert_eq!(store.name(), "Test");
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert_eq!(store.owner(), Some(&owner));
        assert_eq!(*store.policy(), AccessPolicy::Signed);
    }

    #[test]
    fn test_put_and_get() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );

        store
            .put(
                "key1".to_string(),
                b"hello".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");

        let entry = store.get("key1").expect("get");
        assert_eq!(entry.value, b"hello");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_put_update() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );

        store
            .put(
                "key1".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");
        store
            .put(
                "key1".to_string(),
                b"new".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");

        assert_eq!(store.get("key1").expect("get").value, b"new");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_remove() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );

        store
            .put(
                "key1".to_string(),
                b"val".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");
        store.remove("key1").expect("remove");
        assert!(store.get("key1").is_none());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );
        assert!(store.remove("nope").is_err());
    }

    #[test]
    fn test_value_too_large() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );
        let big = vec![0u8; 100_000];
        let result = store.put(
            "big".to_string(),
            big,
            "application/octet-stream".to_string(),
            p,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_active_keys() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );

        store
            .put("a".to_string(), b"1".to_vec(), "text/plain".to_string(), p)
            .expect("put");
        store
            .put("b".to_string(), b"2".to_vec(), "text/plain".to_string(), p)
            .expect("put");
        store
            .put("c".to_string(), b"3".to_vec(), "text/plain".to_string(), p)
            .expect("put");

        assert_eq!(store.active_keys().len(), 3);
    }

    #[test]
    fn test_merge_stores() {
        let p1 = peer(1);
        let p2 = peer(2);
        let id = store_id(1);
        let owner = agent(1);

        let mut s1 = KvStore::new(id, "Store".to_string(), owner, AccessPolicy::Signed);
        let mut s2 = KvStore::new(id, "Store".to_string(), owner, AccessPolicy::Signed);

        s1.put("a".to_string(), b"1".to_vec(), "text/plain".to_string(), p1)
            .expect("put");
        s2.put("b".to_string(), b"2".to_vec(), "text/plain".to_string(), p2)
            .expect("put");

        s1.merge(&s2).expect("merge");
        assert_eq!(s1.len(), 2);
    }

    #[test]
    fn test_merge_different_ids_fails() {
        let owner = agent(1);
        let mut s1 = KvStore::new(store_id(1), "A".to_string(), owner, AccessPolicy::Signed);
        let s2 = KvStore::new(store_id(2), "B".to_string(), owner, AccessPolicy::Signed);
        assert!(s1.merge(&s2).is_err());
    }

    #[test]
    fn test_version_increments() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );
        assert_eq!(store.current_version(), 0);

        store
            .put("k".to_string(), b"v".to_vec(), "text/plain".to_string(), p)
            .expect("put");
        assert_eq!(store.current_version(), 1);

        store.remove("k").expect("remove");
        assert_eq!(store.current_version(), 2);
    }

    #[test]
    fn test_store_id_from_content() {
        let a = agent(1);
        let id1 = KvStoreId::from_content("store1", &a);
        let id2 = KvStoreId::from_content("store1", &a);
        let id3 = KvStoreId::from_content("store2", &a);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );
        store
            .put(
                "key1".to_string(),
                b"val".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");

        let bytes = bincode::serialize(&store).expect("serialize");
        let restored: KvStore = bincode::deserialize(&bytes).expect("deserialize");

        assert_eq!(store.id(), restored.id());
        assert_eq!(store.name(), restored.name());
        assert_eq!(store.len(), restored.len());
    }

    #[test]
    fn test_next_seq_monotonic() {
        let store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        );
        let s1 = store.next_seq();
        let s2 = store.next_seq();
        assert!(s2 > s1);
    }

    // -- Access control tests --

    #[test]
    fn test_signed_policy_owner_authorized() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        assert!(store.is_authorized(&owner));
    }

    #[test]
    fn test_signed_policy_non_owner_rejected() {
        let owner = agent(1);
        let other = agent(2);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        assert!(!store.is_authorized(&other));
    }

    #[test]
    fn test_signed_policy_rejects_unauthorized_delta() {
        let owner = agent(1);
        let attacker = agent(99);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);

        let entry = KvEntry::new(
            "spam".to_string(),
            b"junk".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put("spam".to_string(), entry, (peer(99), 1), 1);

        // Merge should succeed (silent rejection) but not apply the delta
        store
            .merge_delta(&delta, peer(99), Some(&attacker))
            .expect("should not error");
        assert!(store.get("spam").is_none(), "spam should be rejected");
    }

    #[test]
    fn test_signed_policy_accepts_owner_delta() {
        let owner = agent(1);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);

        let entry = KvEntry::new(
            "legit".to_string(),
            b"data".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put("legit".to_string(), entry, (peer(1), 1), 1);

        store
            .merge_delta(&delta, peer(1), Some(&owner))
            .expect("merge");
        assert!(store.get("legit").is_some());
    }

    #[test]
    fn test_allowlisted_policy() {
        let owner = agent(1);
        let writer = agent(2);
        let outsider = agent(3);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        );

        // Owner can add writers
        store.allow_writer(writer, &owner).expect("allow");

        assert!(store.is_authorized(&owner));
        assert!(store.is_authorized(&writer));
        assert!(!store.is_authorized(&outsider));
    }

    #[test]
    fn test_allowlisted_rejects_non_owner_allowlist_change() {
        let owner = agent(1);
        let other = agent(2);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        );

        let result = store.allow_writer(agent(3), &other);
        assert!(result.is_err());
    }

    #[test]
    fn test_deny_writer() {
        let owner = agent(1);
        let writer = agent(2);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        );

        store.allow_writer(writer, &owner).expect("allow");
        assert!(store.is_authorized(&writer));

        store.deny_writer(&writer, &owner).expect("deny");
        assert!(!store.is_authorized(&writer));
    }

    #[test]
    fn test_allowlist_delta_propagation() {
        let owner = agent(1);
        let writer = agent(2);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        );
        store.allow_writer(writer, &owner).expect("allow");

        // Full delta should include the allowlist
        let delta = store.full_delta();
        assert!(delta.allowlist_additions.is_some());
        assert!(delta
            .allowlist_additions
            .as_ref()
            .is_some_and(|a| a.contains(&writer)));
    }

    #[test]
    fn test_anonymous_delta_rejected_for_signed_store() {
        let owner = agent(1);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);

        let entry = KvEntry::new(
            "anon".to_string(),
            b"spam".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put("anon".to_string(), entry, (peer(99), 1), 1);

        // No writer identity → rejected silently
        store
            .merge_delta(&delta, peer(99), None)
            .expect("silent rejection");
        assert!(store.get("anon").is_none());
    }

    #[test]
    fn test_policy_display() {
        assert_eq!(format!("{}", AccessPolicy::Signed), "signed");
        assert_eq!(format!("{}", AccessPolicy::Allowlisted), "allowlisted");
        assert_eq!(
            format!(
                "{}",
                AccessPolicy::Encrypted {
                    group_id: vec![1, 2, 3]
                }
            ),
            "encrypted"
        );
    }
}
