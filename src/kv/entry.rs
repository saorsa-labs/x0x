//! Key-value entry type for the KvStore.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum inline value size (64 KB).
///
/// Values larger than this should be stored externally and referenced
/// by content hash.
pub const MAX_INLINE_SIZE: usize = 65_536;

fn sorted_metadata(metadata: &HashMap<String, String>) -> Vec<(&String, &String)> {
    let mut pairs: Vec<_> = metadata.iter().collect();
    pairs.sort();
    pairs
}

/// What [`KvEntry::merge_tracked`] changed.
#[derive(Debug)]
pub(crate) enum MergePrior {
    /// Nothing changed.
    Unchanged,
    /// Only `created_at` moved; this is its earlier value.
    CreatedAt(u64),
    /// The other entry won; this is the entry as it was.
    Replaced(KvEntry),
}

/// A single key-value entry in the store.
///
/// Uses LWW (Last-Writer-Wins) semantics for conflict resolution:
/// the entry with the highest `updated_at` timestamp wins. Ties are
/// broken deterministically by comparing the BLAKE3 content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvEntry {
    /// The key this entry belongs to.
    pub key: String,

    /// The value (raw bytes). Empty if the value is stored externally.
    pub value: Vec<u8>,

    /// BLAKE3 hash of the value.
    pub content_hash: [u8; 32],

    /// Content type hint (e.g., "text/plain", "application/json").
    pub content_type: String,

    /// Arbitrary user metadata.
    pub metadata: HashMap<String, String>,

    /// Unix milliseconds when this entry was created.
    pub created_at: u64,

    /// Unix milliseconds when this entry was last updated.
    /// Used for LWW conflict resolution.
    pub updated_at: u64,
}

impl KvEntry {
    /// Create a new entry.
    ///
    /// # Arguments
    ///
    /// * `key` - The key name.
    /// * `value` - The value bytes.
    /// * `content_type` - MIME type hint.
    ///
    /// # Returns
    ///
    /// A new `KvEntry` with timestamps set to now.
    #[must_use]
    pub fn new(key: String, value: Vec<u8>, content_type: String) -> Self {
        let content_hash = *blake3::hash(&value).as_bytes();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            key,
            value,
            content_hash,
            content_type,
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the value, bumping `updated_at`. The previous writer's mark
    /// (#1094 P1) no longer covers the new content, so it is removed.
    pub fn update_value(&mut self, value: Vec<u8>, content_type: String) {
        super::provenance::strip(&mut self.metadata);
        self.content_hash = *blake3::hash(&value).as_bytes();
        self.value = value;
        self.content_type = content_type;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }

    /// Merge another entry into this one using LWW semantics.
    ///
    /// The entry with the greater [`Self::lww_order`] wins: `updated_at`,
    /// then the content hash, then the content type, then the sorted
    /// metadata. This is the one LWW rule of every store merge path
    /// (deltas, SelfKeyed, checkpoints, retained images, legacy history),
    /// and it is a pure function of the two entries, so every replica keeps
    /// the same winner whatever the order of arrival.
    ///
    /// #1094 P1 (A10, review of #1963): on a tie of time and content the
    /// value is identical and only the metadata, such as a writer mark,
    /// differs. The rule does not verify marks: verification depends on
    /// which keys a daemon knows, and a merge must not. So any member or
    /// relay can replace a mark on such a tie, as any member can overwrite
    /// the entry; a mark shows who signed the current bytes, and the
    /// absence of a valid mark shows nothing.
    pub fn merge(&mut self, other: &Self) {
        let _ = self.merge_tracked(other);
    }

    /// [`Self::merge`], returning what it replaced so a caller can undo it
    /// without copying the entry first.
    pub(crate) fn merge_tracked(&mut self, other: &Self) -> MergePrior {
        let wins = other.lww_order() > self.lww_order();
        let created_at = self.created_at;
        // #1094 (review of #1974): `created_at` is the earliest of the two
        // whichever entry wins, so the merge is commutative on it too and
        // every replica converges on the same value.
        self.created_at = created_at.min(other.created_at);
        if wins {
            return MergePrior::Replaced(Self {
                key: self.key.clone(),
                value: std::mem::replace(&mut self.value, other.value.clone()),
                content_hash: std::mem::replace(&mut self.content_hash, other.content_hash),
                content_type: std::mem::replace(&mut self.content_type, other.content_type.clone()),
                metadata: std::mem::replace(&mut self.metadata, other.metadata.clone()),
                created_at,
                updated_at: std::mem::replace(&mut self.updated_at, other.updated_at),
            });
        }
        if self.created_at != created_at {
            return MergePrior::CreatedAt(created_at);
        }
        MergePrior::Unchanged
    }

    /// The bincode length of this entry, computed from its field lengths
    /// without walking the value bytes.
    #[must_use]
    pub(crate) fn wire_len(&self) -> u64 {
        // String/Vec/map lengths are u64 prefixes; the hash is a fixed
        // 32-byte array; the two timestamps are u64.
        let metadata: usize = self
            .metadata
            .iter()
            .map(|(k, v)| 16 + k.len() + v.len())
            .sum();
        (8 + self.key.len()
            + 8
            + self.value.len()
            + 32
            + 8
            + self.content_type.len()
            + 8
            + metadata
            + 16) as u64
    }

    /// The LWW order of this entry: `updated_at`, content hash, content
    /// type, sorted metadata. [`Self::merge`] keeps the greater.
    #[must_use]
    pub fn lww_order(&self) -> (u64, [u8; 32], &str, Vec<(&String, &String)>) {
        (
            self.updated_at,
            self.content_hash,
            &self.content_type,
            sorted_metadata(&self.metadata),
        )
    }

    /// Check if this entry's value is stored inline (vs externally).
    #[must_use]
    pub fn is_inline(&self) -> bool {
        !self.value.is_empty()
    }

    /// Get the value size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.value.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_entry() {
        let entry = KvEntry::new(
            "key1".to_string(),
            b"hello".to_vec(),
            "text/plain".to_string(),
        );
        assert_eq!(entry.key, "key1");
        assert_eq!(entry.value, b"hello");
        assert_eq!(entry.content_type, "text/plain");
        assert!(entry.is_inline());
        assert_eq!(entry.size(), 5);
        assert!(entry.created_at > 0);
        assert_eq!(entry.created_at, entry.updated_at);
    }

    #[test]
    fn test_content_hash_deterministic() {
        let e1 = KvEntry::new("k".to_string(), b"data".to_vec(), "text/plain".to_string());
        let e2 = KvEntry::new("k".to_string(), b"data".to_vec(), "text/plain".to_string());
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn test_content_hash_changes_with_value() {
        let e1 = KvEntry::new("k".to_string(), b"aaa".to_vec(), "text/plain".to_string());
        let e2 = KvEntry::new("k".to_string(), b"bbb".to_vec(), "text/plain".to_string());
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn test_update_value() {
        let mut entry = KvEntry::new(
            "key1".to_string(),
            b"old".to_vec(),
            "text/plain".to_string(),
        );
        let old_hash = entry.content_hash;

        entry.update_value(b"new".to_vec(), "application/json".to_string());

        assert_eq!(entry.value, b"new");
        assert_eq!(entry.content_type, "application/json");
        assert_ne!(entry.content_hash, old_hash);
        assert!(entry.updated_at >= entry.created_at);
    }

    #[test]
    fn test_merge_newer_wins() {
        let mut older = KvEntry::new("k".to_string(), b"old".to_vec(), "text/plain".to_string());
        older.updated_at = 100;

        let mut newer = KvEntry::new("k".to_string(), b"new".to_vec(), "text/plain".to_string());
        newer.updated_at = 200;

        older.merge(&newer);
        assert_eq!(older.value, b"new");
        assert_eq!(older.updated_at, 200);
    }

    #[test]
    fn test_merge_older_loses() {
        let mut newer = KvEntry::new("k".to_string(), b"new".to_vec(), "text/plain".to_string());
        newer.updated_at = 200;

        let mut older = KvEntry::new("k".to_string(), b"old".to_vec(), "text/plain".to_string());
        older.updated_at = 100;

        newer.merge(&older);
        assert_eq!(newer.value, b"new"); // unchanged
        assert_eq!(newer.updated_at, 200);
    }

    #[test]
    fn test_merge_tie_broken_by_hash() {
        let mut e1 = KvEntry::new("k".to_string(), b"aaa".to_vec(), "text/plain".to_string());
        e1.updated_at = 100;

        let mut e2 = KvEntry::new("k".to_string(), b"zzz".to_vec(), "text/plain".to_string());
        e2.updated_at = 100;

        // The one with higher hash wins
        let e2_hash = e2.content_hash;
        e1.merge(&e2);

        if e2_hash > *blake3::hash(b"aaa").as_bytes() {
            assert_eq!(e1.value, b"zzz");
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let entry = KvEntry::new(
            "key1".to_string(),
            b"hello".to_vec(),
            "text/plain".to_string(),
        );

        let bytes = bincode::serialize(&entry).expect("serialize");
        let restored: KvEntry = bincode::deserialize(&bytes).expect("deserialize");

        assert_eq!(entry.key, restored.key);
        assert_eq!(entry.value, restored.value);
        assert_eq!(entry.content_hash, restored.content_hash);
        assert_eq!(entry.content_type, restored.content_type);
    }
}
