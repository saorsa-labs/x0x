//! Contact store with trust levels for message filtering.
//!
//! The contact store maintains a local database of known agents with
//! associated trust levels. When integrated with [`crate::gossip::PubSubManager`],
//! messages from blocked senders are dropped and messages from unknown
//! senders are tagged with their trust level.
//!
//! ## Key Revocation
//!
//! When a peer's key is compromised, the [`ContactStore::revoke`] method
//! permanently marks that key as revoked. Revoked keys are persisted to disk
//! alongside contacts and cannot be un-revoked by calling [`ContactStore::set_trust`].
//! The gossip layer checks revocation status before delivering messages.

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Trust level assigned to a contact.
///
/// Controls how messages from this agent are handled:
/// - `Blocked`: Silently dropped, never rebroadcast
/// - `Unknown`: Delivered but flagged (consumer decides)
/// - `Known`: Delivered normally
/// - `Trusted`: Full delivery, can trigger actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Messages silently dropped, never rebroadcast.
    Blocked,
    /// Default for new senders — messages delivered but flagged.
    Unknown,
    /// Seen before, not explicitly trusted — messages delivered normally.
    Known,
    /// Friend — full message delivery, can trigger actions.
    Trusted,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked => write!(f, "blocked"),
            Self::Unknown => write!(f, "unknown"),
            Self::Known => write!(f, "known"),
            Self::Trusted => write!(f, "trusted"),
        }
    }
}

impl std::str::FromStr for TrustLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blocked" => Ok(Self::Blocked),
            "unknown" => Ok(Self::Unknown),
            "known" => Ok(Self::Known),
            "trusted" => Ok(Self::Trusted),
            _ => Err(format!("invalid trust level: {s}")),
        }
    }
}

/// A contact entry in the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// The agent's unique identifier.
    pub agent_id: AgentId,
    /// Trust level for this contact.
    pub trust_level: TrustLevel,
    /// Human-readable label (e.g., "David's Fae").
    pub label: Option<String>,
    /// Unix timestamp when the contact was added.
    pub added_at: u64,
    /// Unix timestamp of last message seen from this contact.
    pub last_seen: Option<u64>,
}

/// A record of a key revocation event.
///
/// Revocations are permanent — once a key is revoked it cannot be
/// un-revoked. The record captures who revoked the key, when, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// The revoked agent's identifier (raw 32-byte key).
    pub agent_id: AgentId,
    /// Human-readable reason for the revocation.
    pub reason: String,
    /// Unix timestamp when the revocation was issued.
    pub timestamp: u64,
    /// The agent ID of the node that issued the revocation.
    pub revoker_id: Option<AgentId>,
}

/// Persistent contact store backed by a JSON file.
///
/// Thread-safe access is managed externally (e.g., via `Arc<RwLock<ContactStore>>`).
#[derive(Debug)]
pub struct ContactStore {
    contacts: HashMap<[u8; 32], Contact>,
    revoked_keys: HashSet<[u8; 32]>,
    revocations: Vec<RevocationRecord>,
    storage_path: PathBuf,
}

/// Serializable format for the contacts file.
#[derive(Serialize, Deserialize)]
struct ContactsFile {
    contacts: Vec<Contact>,
    #[serde(default)]
    revocations: Vec<RevocationRecord>,
}

impl ContactStore {
    /// Create a new contact store backed by the given file path.
    ///
    /// If the file exists, contacts are loaded from it. Otherwise,
    /// an empty store is created.
    pub fn new(storage_path: PathBuf) -> Self {
        let mut store = Self {
            contacts: HashMap::new(),
            revoked_keys: HashSet::new(),
            revocations: Vec::new(),
            storage_path,
        };
        // Best-effort load from disk
        let _ = store.load();
        store
    }

    /// Add or update a contact.
    ///
    /// If the agent's key has been revoked, the contact is added with
    /// trust level forced to `Blocked`.
    pub fn add(&mut self, mut contact: Contact) {
        if self.revoked_keys.contains(&contact.agent_id.0) {
            contact.trust_level = TrustLevel::Blocked;
        }
        self.contacts.insert(contact.agent_id.0, contact);
        let _ = self.save();
    }

    /// Remove a contact by agent ID.
    ///
    /// Returns the removed contact, if it existed.
    /// Note: removing a contact does NOT remove a revocation.
    pub fn remove(&mut self, agent_id: &AgentId) -> Option<Contact> {
        let result = self.contacts.remove(&agent_id.0);
        if result.is_some() {
            let _ = self.save();
        }
        result
    }

    /// Set the trust level for an existing contact, or create a new entry.
    ///
    /// If the agent's key has been revoked, the trust level is forced to
    /// `Blocked` regardless of the requested level.
    pub fn set_trust(&mut self, agent_id: &AgentId, trust_level: TrustLevel) {
        let effective_trust = if self.revoked_keys.contains(&agent_id.0) {
            TrustLevel::Blocked
        } else {
            trust_level
        };
        let entry = self.contacts.entry(agent_id.0).or_insert_with(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Contact {
                agent_id: *agent_id,
                trust_level: effective_trust,
                label: None,
                added_at: now,
                last_seen: None,
            }
        });
        entry.trust_level = effective_trust;
        let _ = self.save();
    }

    /// Revoke an agent's key permanently.
    ///
    /// This adds the key to the revoked set, sets the contact's trust
    /// level to `Blocked`, and persists a `RevocationRecord` to disk.
    /// Once revoked, the key cannot be un-revoked via `set_trust()`.
    pub fn revoke(&mut self, agent_id: &AgentId, reason: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.revoked_keys.insert(agent_id.0);

        // Record the revocation event
        self.revocations.push(RevocationRecord {
            agent_id: *agent_id,
            reason: reason.to_string(),
            timestamp: now,
            revoker_id: None,
        });

        // Force-block the contact entry
        self.set_trust(agent_id, TrustLevel::Blocked);
    }

    /// Revoke an agent's key with an explicit revoker identity.
    ///
    /// Same as [`revoke`](Self::revoke) but also records who issued the
    /// revocation, which is useful for audit trails and future revocation
    /// propagation across the network.
    pub fn revoke_with_revoker(
        &mut self,
        agent_id: &AgentId,
        reason: &str,
        revoker_id: &AgentId,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.revoked_keys.insert(agent_id.0);

        self.revocations.push(RevocationRecord {
            agent_id: *agent_id,
            reason: reason.to_string(),
            timestamp: now,
            revoker_id: Some(*revoker_id),
        });

        self.set_trust(agent_id, TrustLevel::Blocked);
    }

    /// Check if an agent's key has been revoked.
    pub fn is_revoked(&self, agent_id: &AgentId) -> bool {
        self.revoked_keys.contains(&agent_id.0)
    }

    /// Get all revocation records.
    pub fn revocations(&self) -> &[RevocationRecord] {
        &self.revocations
    }

    /// Get a contact by agent ID.
    pub fn get(&self, agent_id: &AgentId) -> Option<&Contact> {
        self.contacts.get(&agent_id.0)
    }

    /// List all contacts.
    pub fn list(&self) -> Vec<&Contact> {
        self.contacts.values().collect()
    }

    /// Check if an agent is trusted (trust level `Trusted`).
    pub fn is_trusted(&self, agent_id: &AgentId) -> bool {
        self.contacts
            .get(&agent_id.0)
            .map(|c| c.trust_level == TrustLevel::Trusted)
            .unwrap_or(false)
    }

    /// Check if an agent is blocked.
    pub fn is_blocked(&self, agent_id: &AgentId) -> bool {
        self.contacts
            .get(&agent_id.0)
            .map(|c| c.trust_level == TrustLevel::Blocked)
            .unwrap_or(false)
    }

    /// Get the trust level for an agent, defaulting to `Unknown`.
    pub fn trust_level(&self, agent_id: &AgentId) -> TrustLevel {
        self.contacts
            .get(&agent_id.0)
            .map(|c| c.trust_level)
            .unwrap_or(TrustLevel::Unknown)
    }

    /// Update the last_seen timestamp for a contact.
    pub fn touch(&mut self, agent_id: &AgentId) {
        if let Some(contact) = self.contacts.get_mut(&agent_id.0) {
            contact.last_seen = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            let _ = self.save();
        }
    }

    /// Persist contacts and revocations to disk.
    fn save(&self) -> std::io::Result<()> {
        let file = ContactsFile {
            contacts: self.contacts.values().cloned().collect(),
            revocations: self.revocations.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::other(format!("serialize: {e}")))?;

        // Ensure parent directory exists
        if let Some(parent) = self.storage_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Atomic write via temp file
        let tmp = self.storage_path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.storage_path)?;
        Ok(())
    }

    /// Load contacts and revocations from disk.
    fn load(&mut self) -> std::io::Result<()> {
        if !self.storage_path.exists() {
            return Ok(());
        }
        let json = std::fs::read_to_string(&self.storage_path)?;
        let file: ContactsFile = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::other(format!("deserialize: {e}")))?;
        for contact in file.contacts {
            self.contacts.insert(contact.agent_id.0, contact);
        }
        for record in &file.revocations {
            self.revoked_keys.insert(record.agent_id.0);
        }
        self.revocations = file.revocations;
        Ok(())
    }

    /// Get the storage path.
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;

    fn test_agent_id() -> AgentId {
        AgentKeypair::generate().expect("keygen").agent_id()
    }

    #[test]
    fn test_trust_level_display_and_parse() {
        for level in [
            TrustLevel::Blocked,
            TrustLevel::Unknown,
            TrustLevel::Known,
            TrustLevel::Trusted,
        ] {
            let s = level.to_string();
            let parsed: TrustLevel = s.parse().expect("parse");
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn test_trust_level_parse_invalid() {
        assert!("invalid".parse::<TrustLevel>().is_err());
    }

    #[test]
    fn test_contact_store_add_get_remove() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.add(Contact {
            agent_id: id,
            trust_level: TrustLevel::Trusted,
            label: Some("Test".to_string()),
            added_at: 1000,
            last_seen: None,
        });

        assert!(store.get(&id).is_some());
        assert!(store.is_trusted(&id));
        assert!(!store.is_blocked(&id));

        let removed = store.remove(&id);
        assert!(removed.is_some());
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn test_contact_store_set_trust() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.set_trust(&id, TrustLevel::Known);
        assert_eq!(store.trust_level(&id), TrustLevel::Known);

        store.set_trust(&id, TrustLevel::Blocked);
        assert!(store.is_blocked(&id));
    }

    #[test]
    fn test_contact_store_default_unknown() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = ContactStore::new(dir.path().join("contacts.json"));
        let id = test_agent_id();
        assert_eq!(store.trust_level(&id), TrustLevel::Unknown);
    }

    #[test]
    fn test_contact_store_list() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id1 = test_agent_id();
        let id2 = test_agent_id();
        store.set_trust(&id1, TrustLevel::Trusted);
        store.set_trust(&id2, TrustLevel::Known);

        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn test_contact_store_persistence() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("contacts.json");

        let id = test_agent_id();
        {
            let mut store = ContactStore::new(path.clone());
            store.add(Contact {
                agent_id: id,
                trust_level: TrustLevel::Trusted,
                label: Some("Persistent".to_string()),
                added_at: 2000,
                last_seen: None,
            });
        }

        // Reload from disk
        let store = ContactStore::new(path);
        let contact = store.get(&id).expect("should exist after reload");
        assert_eq!(contact.trust_level, TrustLevel::Trusted);
        assert_eq!(contact.label.as_deref(), Some("Persistent"));
    }

    #[test]
    fn test_contact_store_touch() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.set_trust(&id, TrustLevel::Known);
        assert!(store.get(&id).expect("exists").last_seen.is_none());

        store.touch(&id);
        assert!(store.get(&id).expect("exists").last_seen.is_some());
    }

    #[test]
    fn test_trust_level_serde() {
        let json = serde_json::to_string(&TrustLevel::Trusted).expect("ser");
        assert_eq!(json, "\"trusted\"");
        let parsed: TrustLevel = serde_json::from_str(&json).expect("de");
        assert_eq!(parsed, TrustLevel::Trusted);
    }

    // -----------------------------------------------------------------------
    // Key revocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_revoke_blocks_future_messages() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.set_trust(&id, TrustLevel::Trusted);
        assert!(store.is_trusted(&id));
        assert!(!store.is_revoked(&id));

        store.revoke(&id, "key compromised");

        assert!(store.is_revoked(&id));
        assert!(store.is_blocked(&id));
        assert!(!store.is_trusted(&id));
        assert_eq!(store.trust_level(&id), TrustLevel::Blocked);
    }

    #[test]
    fn test_revocations_persist_across_reload() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("contacts.json");

        let id = test_agent_id();
        {
            let mut store = ContactStore::new(path.clone());
            store.set_trust(&id, TrustLevel::Trusted);
            store.revoke(&id, "stolen key");
        }

        // Reload from disk
        let store = ContactStore::new(path);
        assert!(store.is_revoked(&id));
        assert!(store.is_blocked(&id));
        assert_eq!(store.revocations().len(), 1);
        assert_eq!(store.revocations()[0].reason, "stolen key");
    }

    #[test]
    fn test_revoked_key_cannot_be_unrevoked_by_set_trust() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.set_trust(&id, TrustLevel::Trusted);
        store.revoke(&id, "compromised");

        // Attempt to un-revoke by setting trust back to Trusted
        store.set_trust(&id, TrustLevel::Trusted);

        // Should still be blocked and revoked
        assert!(store.is_revoked(&id));
        assert!(store.is_blocked(&id));
        assert_eq!(store.trust_level(&id), TrustLevel::Blocked);
    }

    #[test]
    fn test_revoked_key_stays_blocked_after_add() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.revoke(&id, "bad actor");

        // Try adding a contact with Trusted level for a revoked key
        store.add(Contact {
            agent_id: id,
            trust_level: TrustLevel::Trusted,
            label: Some("Sneaky".to_string()),
            added_at: 3000,
            last_seen: None,
        });

        assert!(store.is_revoked(&id));
        assert!(store.is_blocked(&id));
    }

    #[test]
    fn test_revoke_with_revoker() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let target = test_agent_id();
        let revoker = test_agent_id();

        store.revoke_with_revoker(&target, "audit finding", &revoker);

        assert!(store.is_revoked(&target));
        let record = &store.revocations()[0];
        assert_eq!(record.revoker_id, Some(revoker));
        assert_eq!(record.reason, "audit finding");
    }

    #[test]
    fn test_revocation_record_fields() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.revoke(&id, "test reason");

        assert_eq!(store.revocations().len(), 1);
        let record = &store.revocations()[0];
        assert_eq!(record.agent_id, id);
        assert_eq!(record.reason, "test reason");
        assert!(record.timestamp > 0);
        assert_eq!(record.revoker_id, None);
    }
}