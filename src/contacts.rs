//! Contact store with trust levels for message filtering.
//!
//! The contact store maintains a local database of known agents with
//! associated trust levels. When integrated with [`crate::gossip::PubSubManager`],
//! messages from blocked senders are dropped and messages from unknown
//! senders are tagged with their trust level.
//!
//! ## Key Revocation
//!
//! When a peer's key is compromised, the `ContactStore::revoke` method
//! permanently marks that key as revoked. Revoked keys are persisted to disk
//! alongside contacts and cannot be un-revoked by calling `ContactStore::set_trust`.
//! The gossip layer checks revocation status before delivering messages.
//!
//! # Machine Records and Identity Pinning
//!
//! Each contact can have one or more `MachineRecord` entries that track the
//! machines an agent has been observed running on. When an agent's
//! `IdentityType` is set to `Pinned`, messages are only
//! accepted from machine IDs that appear in the contact's machine list.

use crate::identity::{AgentId, MachineId};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Messages silently dropped, never rebroadcast.
    Blocked,
    /// Default for new senders — messages delivered but flagged.
    #[default]
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
            _ => Err(format!(
                "invalid trust level: {s} (valid values: blocked, unknown, known, trusted)"
            )),
        }
    }
}

impl TrustLevel {
    /// Numeric rank for ordering: Blocked(0) < Unknown(1) < Known(2) < Trusted(3).
    ///
    /// Used by `IntroductionCard` trust gating to decide whether a peer's
    /// trust level meets or exceeds a service's `min_trust` requirement.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Blocked => 0,
            Self::Unknown => 1,
            Self::Known => 2,
            Self::Trusted => 3,
        }
    }
}

/// How strongly we identify and constrain this contact's machine.
///
/// Controls whether machine identity is taken into account when accepting
/// messages from this contact:
///
/// - `Anonymous`: No machine constraint — agent is trusted regardless of machine.
/// - `Known`: Machine seen but not pinned — accepted from any known machine.
/// - `Trusted`: Trusted identity; accepted from any machine.
/// - `Pinned`: Messages only accepted from machine IDs that appear in the
///   contact's machine list with `pinned: true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    /// No machine information — agent is trusted regardless of machine.
    #[default]
    Anonymous,
    /// Machine seen but not pinned — accepted from any known machine.
    Known,
    /// Trusted identity; accepted from any machine.
    Trusted,
    /// Pinned to specific machine(s) — only those machine_ids are accepted.
    Pinned,
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => write!(f, "anonymous"),
            Self::Known => write!(f, "known"),
            Self::Trusted => write!(f, "trusted"),
            Self::Pinned => write!(f, "pinned"),
        }
    }
}

impl std::str::FromStr for IdentityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anonymous" => Ok(Self::Anonymous),
            "known" => Ok(Self::Known),
            "trusted" => Ok(Self::Trusted),
            "pinned" => Ok(Self::Pinned),
            _ => Err(format!("invalid identity type: {s}")),
        }
    }
}

/// A record of a known machine for a contact.
///
/// Tracks the machines an agent has been observed running on.
/// When the contact's [`IdentityType`] is [`IdentityType::Pinned`],
/// only machines with `pinned: true` will have their messages accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineRecord {
    /// Machine identity (SHA-256 of ML-DSA-65 public key).
    pub machine_id: MachineId,
    /// Human-readable label for this machine.
    pub label: Option<String>,
    /// Unix timestamp when first seen.
    pub first_seen: u64,
    /// Unix timestamp when last seen.
    pub last_seen: u64,
    /// Whether to reject messages from other machines for this contact.
    pub pinned: bool,
}

impl MachineRecord {
    /// Create a new `MachineRecord` with the current time as both `first_seen` and `last_seen`.
    #[must_use]
    pub fn new(machine_id: MachineId, label: Option<String>) -> Self {
        let now = now_secs();
        Self {
            machine_id,
            label,
            first_seen: now,
            last_seen: now,
            pinned: false,
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
    /// How machine identity is applied to this contact.
    #[serde(default)]
    pub identity_type: IdentityType,
    /// Known machines for this contact.
    #[serde(default)]
    pub machines: Vec<MachineRecord>,
}

/// A record of a key revocation event.
///
/// Revocations are permanent — once a key is revoked it cannot be
/// un-revoked. The record captures who revoked the key, when, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// The revoked agent's identifier.
    pub agent_id: AgentId,
    /// Human-readable reason for the revocation.
    pub reason: String,
    /// Unix timestamp when the revocation was issued.
    pub timestamp: u64,
    /// The agent that issued the revocation (for audit trails).
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        // Auto-upgrade identity_type from Anonymous when trust is elevated,
        // so the UI doesn't show a contradictory "Anonymous + Trusted" state.
        if matches!(contact.trust_level, TrustLevel::Known | TrustLevel::Trusted)
            && contact.identity_type == IdentityType::Anonymous
        {
            contact.identity_type = IdentityType::Known;
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
        let entry = self.contacts.entry(agent_id.0).or_insert_with(|| Contact {
            agent_id: *agent_id,
            trust_level: effective_trust,
            label: None,
            added_at: now_secs(),
            last_seen: None,
            identity_type: IdentityType::default(),
            machines: Vec::new(),
        });
        entry.trust_level = effective_trust;
        // When elevating trust to Known or Trusted, auto-upgrade identity_type
        // from the default Anonymous so the UI doesn't show a contradictory state.
        if matches!(effective_trust, TrustLevel::Known | TrustLevel::Trusted)
            && entry.identity_type == IdentityType::Anonymous
        {
            entry.identity_type = IdentityType::Known;
        }
        let _ = self.save();
    }

    /// Revoke an agent's key permanently.
    ///
    /// This adds the key to the revoked set, sets the contact's trust
    /// level to `Blocked`, and persists a [`RevocationRecord`] to disk.
    /// Once revoked, the key cannot be un-revoked via [`set_trust`](Self::set_trust).
    pub fn revoke(&mut self, agent_id: &AgentId, reason: &str) {
        if self.revoked_keys.contains(&agent_id.0) {
            return;
        }
        self.revoked_keys.insert(agent_id.0);
        self.revocations.push(RevocationRecord {
            agent_id: *agent_id,
            reason: reason.to_string(),
            timestamp: now_secs(),
            revoker_id: None,
        });
        self.set_trust(agent_id, TrustLevel::Blocked);
    }

    /// Revoke an agent's key with an explicit revoker identity.
    ///
    /// Same as [`revoke`](Self::revoke) but also records who issued the
    /// revocation, useful for audit trails.
    pub fn revoke_with_revoker(&mut self, agent_id: &AgentId, reason: &str, revoker_id: &AgentId) {
        if self.revoked_keys.contains(&agent_id.0) {
            return;
        }
        self.revoked_keys.insert(agent_id.0);
        self.revocations.push(RevocationRecord {
            agent_id: *agent_id,
            reason: reason.to_string(),
            timestamp: now_secs(),
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

    /// Get a mutable reference to a contact by agent ID.
    pub fn get_mut(&mut self, agent_id: &AgentId) -> Option<&mut Contact> {
        self.contacts.get_mut(&agent_id.0)
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
            contact.last_seen = Some(now_secs());
            let _ = self.save();
        }
    }

    /// Add or update a machine record for a contact.
    ///
    /// Returns `true` if this is the first time this machine was recorded.
    /// If the machine already exists, its `last_seen` timestamp is updated.
    /// Creates the contact entry if it does not exist yet.
    pub fn add_machine(&mut self, agent_id: &AgentId, record: MachineRecord) -> bool {
        let contact = self.contacts.entry(agent_id.0).or_insert_with(|| Contact {
            agent_id: *agent_id,
            trust_level: TrustLevel::Unknown,
            label: None,
            added_at: now_secs(),
            last_seen: None,
            identity_type: IdentityType::default(),
            machines: Vec::new(),
        });

        if let Some(existing) = contact
            .machines
            .iter_mut()
            .find(|m| m.machine_id == record.machine_id)
        {
            existing.last_seen = now_secs();
            if record.label.is_some() {
                existing.label = record.label;
            }
            let _ = self.save();
            false
        } else {
            contact.machines.push(record);
            let _ = self.save();
            true
        }
    }

    /// Remove a machine record from a contact.
    ///
    /// Returns `true` if the machine was found and removed.
    pub fn remove_machine(&mut self, agent_id: &AgentId, machine_id: &MachineId) -> bool {
        if let Some(contact) = self.contacts.get_mut(&agent_id.0) {
            let before = contact.machines.len();
            contact.machines.retain(|m| m.machine_id != *machine_id);
            let removed = contact.machines.len() < before;
            if removed {
                let _ = self.save();
            }
            removed
        } else {
            false
        }
    }

    /// Return the machine records for a contact.
    pub fn machines(&self, agent_id: &AgentId) -> &[MachineRecord] {
        self.contacts
            .get(&agent_id.0)
            .map(|c| c.machines.as_slice())
            .unwrap_or(&[])
    }

    /// Pin a machine for a contact.
    ///
    /// Sets `pinned: true` for the machine record with the given ID and
    /// sets `identity_type` to `Pinned` on the contact.
    /// Returns `true` if the machine was found.
    pub fn pin_machine(&mut self, agent_id: &AgentId, machine_id: &MachineId) -> bool {
        if let Some(contact) = self.contacts.get_mut(&agent_id.0) {
            if let Some(record) = contact
                .machines
                .iter_mut()
                .find(|m| m.machine_id == *machine_id)
            {
                record.pinned = true;
                contact.identity_type = IdentityType::Pinned;
                let _ = self.save();
                return true;
            }
        }
        false
    }

    /// Unpin a machine for a contact.
    ///
    /// Sets `pinned: false` for the machine record with the given ID.
    /// If no machines remain pinned, resets `identity_type` to `Known`.
    /// Returns `true` if the machine was found.
    pub fn unpin_machine(&mut self, agent_id: &AgentId, machine_id: &MachineId) -> bool {
        if let Some(contact) = self.contacts.get_mut(&agent_id.0) {
            if let Some(record) = contact
                .machines
                .iter_mut()
                .find(|m| m.machine_id == *machine_id)
            {
                record.pinned = false;
                // If no machines are still pinned, downgrade identity type
                if !contact.machines.iter().any(|m| m.pinned) {
                    contact.identity_type = IdentityType::Known;
                }
                let _ = self.save();
                return true;
            }
        }
        false
    }

    /// Set the identity type for a contact.
    ///
    /// Creates the contact entry (with `Unknown` trust) if it does not exist.
    pub fn set_identity_type(&mut self, agent_id: &AgentId, identity_type: IdentityType) {
        let contact = self.contacts.entry(agent_id.0).or_insert_with(|| Contact {
            agent_id: *agent_id,
            trust_level: TrustLevel::Unknown,
            label: None,
            added_at: now_secs(),
            last_seen: None,
            identity_type: IdentityType::default(),
            machines: Vec::new(),
        });
        contact.identity_type = identity_type;
        let _ = self.save();
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

    fn test_machine_id() -> MachineId {
        // Use a random machine keypair to generate a unique machine id for tests
        let kp = crate::identity::MachineKeypair::generate().expect("keygen");
        kp.machine_id()
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
    fn test_identity_type_display_and_parse() {
        for ty in [
            IdentityType::Anonymous,
            IdentityType::Known,
            IdentityType::Trusted,
            IdentityType::Pinned,
        ] {
            let s = ty.to_string();
            let parsed: IdentityType = s.parse().expect("parse");
            assert_eq!(parsed, ty);
        }
    }

    #[test]
    fn test_identity_type_parse_invalid() {
        assert!("invalid".parse::<IdentityType>().is_err());
    }

    #[test]
    fn test_identity_type_default() {
        assert_eq!(IdentityType::default(), IdentityType::Anonymous);
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
            identity_type: IdentityType::default(),
            machines: Vec::new(),
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
                identity_type: IdentityType::default(),
                machines: Vec::new(),
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

    #[test]
    fn test_machine_record_new() {
        let mid = test_machine_id();
        let rec = MachineRecord::new(mid, Some("laptop".to_string()));
        assert_eq!(rec.machine_id, mid);
        assert_eq!(rec.label.as_deref(), Some("laptop"));
        assert!(!rec.pinned);
        assert!(rec.first_seen > 0);
        assert_eq!(rec.first_seen, rec.last_seen);
    }

    #[test]
    fn test_add_machine_new() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let agent = test_agent_id();
        let machine = test_machine_id();
        let rec = MachineRecord::new(machine, None);
        let is_new = store.add_machine(&agent, rec);
        assert!(is_new);
        assert_eq!(store.machines(&agent).len(), 1);
    }

    #[test]
    fn test_add_machine_duplicate_updates_last_seen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let agent = test_agent_id();
        let machine = test_machine_id();

        store.add_machine(&agent, MachineRecord::new(machine, None));
        let is_new = store.add_machine(&agent, MachineRecord::new(machine, Some("new".into())));
        assert!(!is_new);
        assert_eq!(store.machines(&agent).len(), 1);
        assert_eq!(store.machines(&agent)[0].label.as_deref(), Some("new"));
    }

    #[test]
    fn test_remove_machine() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let agent = test_agent_id();
        let machine = test_machine_id();

        store.add_machine(&agent, MachineRecord::new(machine, None));
        assert!(store.remove_machine(&agent, &machine));
        assert_eq!(store.machines(&agent).len(), 0);

        // Removing non-existent machine returns false
        assert!(!store.remove_machine(&agent, &machine));
    }

    #[test]
    fn test_pin_and_unpin_machine() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let agent = test_agent_id();
        let machine = test_machine_id();

        store.add_machine(&agent, MachineRecord::new(machine, None));
        assert!(store.pin_machine(&agent, &machine));
        assert_eq!(
            store.get(&agent).expect("exists").identity_type,
            IdentityType::Pinned
        );
        assert!(store.machines(&agent)[0].pinned);

        // Pinning unknown machine returns false
        let other = test_machine_id();
        assert!(!store.pin_machine(&agent, &other));

        // Unpin
        assert!(store.unpin_machine(&agent, &machine));
        assert!(!store.machines(&agent)[0].pinned);
        // identity_type downgraded to Known because no pinned machines remain
        assert_eq!(
            store.get(&agent).expect("exists").identity_type,
            IdentityType::Known
        );
    }

    #[test]
    fn test_set_identity_type() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let agent = test_agent_id();
        store.set_identity_type(&agent, IdentityType::Trusted);
        assert_eq!(
            store.get(&agent).expect("exists").identity_type,
            IdentityType::Trusted
        );
    }

    #[test]
    fn test_machine_record_persistence() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("contacts.json");

        let agent = test_agent_id();
        let machine = test_machine_id();

        {
            let mut store = ContactStore::new(path.clone());
            store.add_machine(&agent, MachineRecord::new(machine, Some("desktop".into())));
            store.pin_machine(&agent, &machine);
        }

        let store = ContactStore::new(path);
        let machines = store.machines(&agent);
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].machine_id, machine);
        assert_eq!(machines[0].label.as_deref(), Some("desktop"));
        assert!(machines[0].pinned);
        assert_eq!(
            store.get(&agent).expect("exists").identity_type,
            IdentityType::Pinned
        );
    }

    #[test]
    fn test_backward_compat_no_machines_field() {
        // Simulate loading an old-format JSON without machines/identity_type fields.
        // Build the JSON by first saving a contact, then removing the new fields via serde_json.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("contacts.json");

        let agent_id = test_agent_id();
        {
            // Write the contact using the new format
            let mut store = ContactStore::new(path.clone());
            store.add(Contact {
                agent_id,
                trust_level: TrustLevel::Trusted,
                label: None,
                added_at: 1000,
                last_seen: None,
                identity_type: IdentityType::Anonymous,
                machines: Vec::new(),
            });
        }

        // Remove new fields from each contact entry to simulate an old-format file
        let json = std::fs::read_to_string(&path).expect("read");
        let mut root: serde_json::Value =
            serde_json::from_str(&json).expect("parse saved contacts");
        if let Some(contacts) = root.get_mut("contacts").and_then(|v| v.as_array_mut()) {
            for c in contacts.iter_mut() {
                if let Some(obj) = c.as_object_mut() {
                    obj.remove("identity_type");
                    obj.remove("machines");
                }
            }
        }
        let stripped = serde_json::to_string_pretty(&root).expect("serialize");
        std::fs::write(&path, &stripped).expect("write");

        let store = ContactStore::new(path);
        let contact = store.get(&agent_id).expect("should load");
        assert_eq!(contact.trust_level, TrustLevel::Trusted);
        assert_eq!(contact.identity_type, IdentityType::Anonymous);
        assert!(contact.machines.is_empty());
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

        store.add(Contact {
            agent_id: id,
            trust_level: TrustLevel::Trusted,
            label: Some("Sneaky".to_string()),
            added_at: 3000,
            last_seen: None,
            identity_type: IdentityType::default(),
            machines: Vec::new(),
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
    fn test_duplicate_revocation_ignored() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));

        let id = test_agent_id();
        store.revoke(&id, "first revocation");
        store.revoke(&id, "second revocation");

        assert_eq!(store.revocations().len(), 1);
        assert_eq!(store.revocations()[0].reason, "first revocation");
    }
}
