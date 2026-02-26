//! Contact store with trust levels for message filtering.
//!
//! The contact store maintains a local database of known agents with
//! associated trust levels. When integrated with [`crate::gossip::PubSubManager`],
//! messages from blocked senders are dropped and messages from unknown
//! senders are tagged with their trust level.

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// Persistent contact store backed by a JSON file.
///
/// Thread-safe access is managed externally (e.g., via `Arc<RwLock<ContactStore>>`).
#[derive(Debug)]
pub struct ContactStore {
    contacts: HashMap<[u8; 32], Contact>,
    storage_path: PathBuf,
}

/// Serializable format for the contacts file.
#[derive(Serialize, Deserialize)]
struct ContactsFile {
    contacts: Vec<Contact>,
}

impl ContactStore {
    /// Create a new contact store backed by the given file path.
    ///
    /// If the file exists, contacts are loaded from it. Otherwise,
    /// an empty store is created.
    pub fn new(storage_path: PathBuf) -> Self {
        let mut store = Self {
            contacts: HashMap::new(),
            storage_path,
        };
        // Best-effort load from disk
        let _ = store.load();
        store
    }

    /// Add or update a contact.
    pub fn add(&mut self, contact: Contact) {
        self.contacts.insert(contact.agent_id.0, contact);
        let _ = self.save();
    }

    /// Remove a contact by agent ID.
    ///
    /// Returns the removed contact, if it existed.
    pub fn remove(&mut self, agent_id: &AgentId) -> Option<Contact> {
        let result = self.contacts.remove(&agent_id.0);
        if result.is_some() {
            let _ = self.save();
        }
        result
    }

    /// Set the trust level for an existing contact, or create a new entry.
    pub fn set_trust(&mut self, agent_id: &AgentId, trust_level: TrustLevel) {
        let entry = self.contacts.entry(agent_id.0).or_insert_with(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Contact {
                agent_id: *agent_id,
                trust_level,
                label: None,
                added_at: now,
                last_seen: None,
            }
        });
        entry.trust_level = trust_level;
        let _ = self.save();
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

    /// Persist contacts to disk.
    fn save(&self) -> std::io::Result<()> {
        let file = ContactsFile {
            contacts: self.contacts.values().cloned().collect(),
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

    /// Load contacts from disk.
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
}
