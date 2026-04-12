//! High-level group management for x0x.
//!
//! A Group ties together:
//! - An MLS group (encryption, membership)
//! - A KvStore (group metadata, display names, settings)
//! - Gossip topics (chat rooms, notifications)
//! - CRDT task lists (kanban boards)
//! - A [`GroupPolicy`] that governs discovery/admission/read/write
//!
//! Groups are the primary collaboration primitive for agents and humans.

pub mod card;
pub mod directory;
pub mod invite;
pub mod kem_envelope;
pub mod member;
pub mod policy;
pub mod request;

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub use self::directory::GroupCard;
pub use self::member::{GroupMember, GroupMemberState, GroupRole};
pub use self::policy::{
    GroupAdmission, GroupConfidentiality, GroupDiscoverability, GroupPolicy, GroupPolicyPreset,
    GroupPolicySummary, GroupReadAccess, GroupWriteAccess,
};
pub use self::request::{JoinRequest, JoinRequestStatus};

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Metadata for a group.
///
/// Persisted as JSON. The legacy v1 layout used a flat `members: BTreeSet`
/// plus a parallel `display_names: HashMap`. The v2 layout uses a structured
/// `members_v2: BTreeMap<String, GroupMember>`. For migration, the v1 fields
/// are deserialised (`#[serde(default)]`) but never written back
/// (`skip_serializing`). Call [`GroupInfo::migrate_from_v1`] at load time to
/// fold any v1 data into v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    // ── v1 compat (read-only) ───────────────────────────────────────────
    #[serde(default, skip_serializing)]
    pub members: BTreeSet<String>,
    #[serde(default, skip_serializing)]
    pub display_names: HashMap<String, String>,
    #[serde(default, skip_serializing)]
    pub membership_revision: u64,

    // ── v2 identity + topics ────────────────────────────────────────────
    pub name: String,
    pub description: String,
    pub creator: AgentId,
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    pub mls_group_id: String,
    pub metadata_topic: String,
    pub chat_topic_prefix: String,

    // ── v2 policy + roster ──────────────────────────────────────────────
    #[serde(default)]
    pub policy: GroupPolicy,
    #[serde(default)]
    pub policy_revision: u64,
    #[serde(default)]
    pub roster_revision: u64,
    #[serde(default)]
    pub members_v2: BTreeMap<String, GroupMember>,
    #[serde(default)]
    pub join_requests: BTreeMap<String, JoinRequest>,
    #[serde(default)]
    pub discovery_card_topic: Option<String>,

    // ── Phase D.2: Group Shared Secret (GSS) for cross-daemon encrypted
    //    content delivery. This is a symmetric-key layer distributed via
    //    welcomes, NOT full MLS TreeKEM. It gives:
    //      - cross-daemon encrypt/decrypt (proven from the correct peer)
    //      - rekey-on-ban semantics (banned peer loses future access)
    //    It does NOT give per-message forward secrecy within an epoch.
    //    Full TreeKEM cross-daemon join is blocked on saorsa-mls upstream
    //    providing a `from_welcome` constructor.
    /// 32-byte random secret for MlsEncrypted groups. None for SignedPublic or
    /// for stub entries created via card import (importer isn't a member yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_secret: Option<Vec<u8>>,
    /// Monotonic epoch for the shared secret. Incremented on rekey (ban/remove).
    #[serde(default)]
    pub secret_epoch: u64,
}

impl GroupInfo {
    /// Create a new `GroupInfo` with the given policy (defaults to `private_secure`).
    #[must_use]
    pub fn new(name: String, description: String, creator: AgentId, mls_group_id: String) -> Self {
        Self::with_policy(
            name,
            description,
            creator,
            mls_group_id,
            GroupPolicy::default(),
        )
    }

    /// Create a new `GroupInfo` with an explicit policy.
    #[must_use]
    pub fn with_policy(
        name: String,
        description: String,
        creator: AgentId,
        mls_group_id: String,
        policy: GroupPolicy,
    ) -> Self {
        let now = now_millis();
        let metadata_topic = format!(
            "x0x.group.{}.meta",
            &mls_group_id[..16.min(mls_group_id.len())]
        );
        let chat_topic_prefix = format!(
            "x0x.group.{}.chat",
            &mls_group_id[..16.min(mls_group_id.len())]
        );
        let discovery_card_topic = if policy.discoverability != GroupDiscoverability::Hidden {
            Some(format!(
                "x0x.group.{}.card",
                &mls_group_id[..16.min(mls_group_id.len())]
            ))
        } else {
            None
        };

        let creator_hex = hex::encode(creator.as_bytes());
        let mut members_v2 = BTreeMap::new();
        members_v2.insert(
            creator_hex.clone(),
            GroupMember::new_owner(creator_hex.clone(), None, now),
        );

        // Generate a fresh shared secret for MlsEncrypted groups. SignedPublic
        // groups don't need one — their content is signed but not encrypted.
        let shared_secret = if policy.confidentiality == GroupConfidentiality::MlsEncrypted {
            use rand::RngCore;
            let mut secret = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            Some(secret)
        } else {
            None
        };

        Self {
            members: BTreeSet::new(),
            display_names: HashMap::new(),
            membership_revision: 0,

            name,
            description,
            creator,
            created_at: now,
            updated_at: now,
            mls_group_id,
            metadata_topic,
            chat_topic_prefix,
            policy,
            policy_revision: 0,
            roster_revision: 0,
            members_v2,
            join_requests: BTreeMap::new(),
            discovery_card_topic,
            shared_secret,
            secret_epoch: 0,
        }
    }

    /// Rotate the group's shared secret (called on ban/remove in MlsEncrypted
    /// groups). Returns the new secret and new epoch. Previous-epoch content
    /// encrypted by members still in the group is NOT decryptable at the new
    /// epoch — that's forward secrecy across epochs.
    ///
    /// Callers must arrange to distribute the new secret to remaining members
    /// (never to the departed/banned peer).
    #[must_use]
    pub fn rotate_shared_secret(&mut self) -> (Vec<u8>, u64) {
        use rand::RngCore;
        let mut new_secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_secret);
        self.secret_epoch = self.secret_epoch.saturating_add(1);
        self.shared_secret = Some(new_secret.clone());
        (new_secret, self.secret_epoch)
    }

    /// Derive the per-message AEAD key from the group's current shared secret.
    /// Returns None if the group has no shared secret (e.g., SignedPublic, or
    /// the caller hasn't received a welcome yet).
    #[must_use]
    pub fn secure_message_key(&self) -> Option<Vec<u8>> {
        let secret = self.shared_secret.as_ref()?;
        Some(Self::derive_message_key(
            secret,
            self.secret_epoch,
            &self.mls_group_id,
        ))
    }

    /// Pure helper so both encryptor and decryptor derive the same key from
    /// (secret, epoch, group_id).
    #[must_use]
    pub fn derive_message_key(secret: &[u8], epoch: u64, group_id: &str) -> Vec<u8> {
        let mut material = Vec::with_capacity(secret.len() + 48);
        material.extend_from_slice(b"x0x.group.secure\0");
        material.extend_from_slice(secret);
        material.extend_from_slice(&epoch.to_le_bytes());
        material.extend_from_slice(group_id.as_bytes());
        let hash = blake3::hash(&material);
        hash.as_bytes()[..32].to_vec()
    }

    /// Migrate v1 (BTreeSet + display_names) data into v2 structured members.
    /// Idempotent: no-op if `members_v2` is already populated.
    pub fn migrate_from_v1(&mut self) {
        if !self.members_v2.is_empty() {
            return;
        }
        let now = now_millis();
        let creator_hex = hex::encode(self.creator.as_bytes());
        let mut all_ids: BTreeSet<String> = self.members.clone();
        all_ids.insert(creator_hex.clone());
        for id in self.display_names.keys() {
            all_ids.insert(id.clone());
        }
        for id in all_ids {
            let display_name = self.display_names.get(&id).cloned();
            let member = if id == creator_hex {
                GroupMember::new_owner(id.clone(), display_name, now)
            } else {
                GroupMember::new_member(id.clone(), display_name, Some(creator_hex.clone()), now)
            };
            self.members_v2.insert(id, member);
        }
        if self.roster_revision == 0 {
            self.roster_revision = self.membership_revision;
        }
        if self.updated_at == 0 {
            self.updated_at = self.created_at;
        }
    }

    /// Add or update a member. If the member already exists, updates state to Active.
    pub fn add_member(
        &mut self,
        agent_id_hex: String,
        role: GroupRole,
        added_by: Option<String>,
        display_name: Option<String>,
    ) {
        self.add_member_with_kem(agent_id_hex, role, added_by, display_name, None);
    }

    /// Add or update a member, optionally recording their ML-KEM-768 public
    /// key for future secure-share delivery. If `kem_public_key_b64` is
    /// `Some`, it overwrites any previously-recorded value; `None` preserves
    /// the existing one.
    pub fn add_member_with_kem(
        &mut self,
        agent_id_hex: String,
        role: GroupRole,
        added_by: Option<String>,
        display_name: Option<String>,
        kem_public_key_b64: Option<String>,
    ) {
        let now = now_millis();
        self.members_v2
            .entry(agent_id_hex.clone())
            .and_modify(|m| {
                m.role = role;
                m.state = GroupMemberState::Active;
                m.updated_at = now;
                if let Some(dn) = display_name.clone() {
                    m.display_name = Some(dn);
                }
                if added_by.is_some() {
                    m.added_by = added_by.clone();
                }
                if let Some(ref k) = kem_public_key_b64 {
                    m.kem_public_key_b64 = Some(k.clone());
                }
            })
            .or_insert_with(|| GroupMember {
                agent_id: agent_id_hex,
                user_id: None,
                role,
                state: GroupMemberState::Active,
                display_name,
                joined_at: now,
                updated_at: now,
                added_by,
                removed_by: None,
                kem_public_key_b64,
            });
    }

    /// Record a member's ML-KEM-768 public key without changing any other
    /// state. Used when we learn a key for an existing member via a later
    /// event (e.g. `JoinRequestCreated` after a stub was already seeded).
    pub fn set_member_kem_public_key(&mut self, agent_id_hex: &str, kem_public_key_b64: String) {
        if let Some(m) = self.members_v2.get_mut(agent_id_hex) {
            m.kem_public_key_b64 = Some(kem_public_key_b64);
            m.updated_at = now_millis();
        }
    }

    /// Mark a member as Removed (soft delete — entry retained for audit).
    pub fn remove_member(&mut self, agent_id_hex: &str, removed_by: Option<String>) {
        if let Some(m) = self.members_v2.get_mut(agent_id_hex) {
            m.state = GroupMemberState::Removed;
            m.updated_at = now_millis();
            m.removed_by = removed_by;
        }
    }

    /// Mark a member as Banned.
    pub fn ban_member(&mut self, agent_id_hex: &str, banned_by: Option<String>) {
        let now = now_millis();
        self.members_v2
            .entry(agent_id_hex.to_string())
            .and_modify(|m| {
                m.state = GroupMemberState::Banned;
                m.updated_at = now;
                m.removed_by = banned_by.clone();
            })
            .or_insert_with(|| GroupMember {
                agent_id: agent_id_hex.to_string(),
                user_id: None,
                role: GroupRole::Guest,
                state: GroupMemberState::Banned,
                display_name: None,
                joined_at: now,
                updated_at: now,
                added_by: None,
                removed_by: banned_by,
                kem_public_key_b64: None,
            });
    }

    /// Unban — transition Banned → Active (keeps current role).
    pub fn unban_member(&mut self, agent_id_hex: &str) {
        if let Some(m) = self.members_v2.get_mut(agent_id_hex) {
            if m.state == GroupMemberState::Banned {
                m.state = GroupMemberState::Active;
                m.updated_at = now_millis();
                m.removed_by = None;
            }
        }
    }

    /// Change a member's role. Caller must verify caller's authority first.
    pub fn set_member_role(&mut self, agent_id_hex: &str, role: GroupRole) {
        if let Some(m) = self.members_v2.get_mut(agent_id_hex) {
            m.role = role;
            m.updated_at = now_millis();
        }
    }

    /// Check that a member is present and Active.
    #[must_use]
    pub fn has_active_member(&self, agent_id_hex: &str) -> bool {
        self.members_v2
            .get(agent_id_hex)
            .is_some_and(GroupMember::is_active)
    }

    /// Legacy compat: true if active (matches old `has_member` semantics).
    #[must_use]
    pub fn has_member(&self, agent_id_hex: &str) -> bool {
        self.has_active_member(agent_id_hex)
    }

    /// Returns the caller's effective role if they are an active member.
    #[must_use]
    pub fn caller_role(&self, agent_id_hex: &str) -> Option<GroupRole> {
        self.members_v2
            .get(agent_id_hex)
            .filter(|m| m.is_active())
            .map(|m| m.role)
    }

    /// Returns true if the agent is currently banned.
    #[must_use]
    pub fn is_banned(&self, agent_id_hex: &str) -> bool {
        self.members_v2
            .get(agent_id_hex)
            .is_some_and(GroupMember::is_banned)
    }

    /// Set a display name for a member. Member must exist.
    pub fn set_display_name(&mut self, agent_id_hex: &str, name: String) {
        if let Some(m) = self.members_v2.get_mut(agent_id_hex) {
            m.display_name = Some(name);
            m.updated_at = now_millis();
        }
    }

    /// Get a member's display name, falling back to truncated agent ID.
    #[must_use]
    pub fn display_name(&self, agent_id_hex: &str) -> String {
        if let Some(m) = self.members_v2.get(agent_id_hex) {
            if let Some(dn) = &m.display_name {
                return dn.clone();
            }
        }
        if agent_id_hex.len() >= 8 {
            format!("{}…", &agent_id_hex[..8])
        } else {
            agent_id_hex.to_string()
        }
    }

    /// Iterator over currently active members.
    pub fn active_members(&self) -> impl Iterator<Item = &GroupMember> {
        self.members_v2.values().filter(|m| m.is_active())
    }

    /// Count of currently active members.
    #[must_use]
    pub fn active_member_count(&self) -> usize {
        self.active_members().count()
    }

    /// Count of currently active Admins (including Owner).
    #[must_use]
    pub fn active_admin_count(&self) -> usize {
        self.members_v2
            .values()
            .filter(|m| m.is_active() && m.role.at_least(GroupRole::Admin))
            .count()
    }

    /// Owner's agent hex, if one exists.
    #[must_use]
    pub fn owner_agent_id(&self) -> Option<String> {
        self.members_v2
            .values()
            .find(|m| m.is_active() && m.role == GroupRole::Owner)
            .map(|m| m.agent_id.clone())
    }

    /// Default chat topic for the group ("general" room).
    #[must_use]
    pub fn general_chat_topic(&self) -> String {
        format!("{}/general", self.chat_topic_prefix)
    }

    /// Build a shareable discoverable `GroupCard` from this group's state.
    /// Returns None if the group is `Hidden`.
    #[must_use]
    pub fn to_group_card(&self) -> Option<GroupCard> {
        if self.policy.discoverability == GroupDiscoverability::Hidden {
            return None;
        }
        let owner = self
            .owner_agent_id()
            .unwrap_or_else(|| hex::encode(self.creator.as_bytes()));
        Some(GroupCard {
            group_id: self.mls_group_id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            avatar_url: None,
            banner_url: None,
            tags: Vec::new(),
            policy_summary: GroupPolicySummary::from(&self.policy),
            owner_agent_id: owner,
            admin_count: self.active_admin_count() as u32,
            member_count: self.active_member_count() as u32,
            created_at: self.created_at,
            updated_at: self.updated_at,
            request_access_enabled: self.policy.admission == GroupAdmission::RequestAccess,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_group_info_new_seeds_owner() {
        let info = GroupInfo::new(
            "Test Group".to_string(),
            "A test".to_string(),
            agent(1),
            "aabb".repeat(8),
        );
        let creator_hex = hex::encode([1u8; 32]);
        let owner = info.members_v2.get(&creator_hex).unwrap();
        assert_eq!(owner.role, GroupRole::Owner);
        assert!(owner.is_active());
        assert_eq!(info.policy, GroupPolicy::default());
        assert_eq!(info.active_member_count(), 1);
    }

    #[test]
    fn test_display_name_fallback() {
        let mut info = GroupInfo::new(
            "Test".to_string(),
            String::new(),
            agent(1),
            "aabb".repeat(8),
        );
        let creator_hex = hex::encode([1u8; 32]);
        let name = info.display_name(&creator_hex);
        assert!(name.ends_with('…'));

        info.set_display_name(&creator_hex, "Alice".to_string());
        assert_eq!(info.display_name(&creator_hex), "Alice");
    }

    #[test]
    fn test_add_and_remove_member() {
        let mut info = GroupInfo::new(
            "Test".to_string(),
            String::new(),
            agent(1),
            "aabb".repeat(8),
        );
        let bob_hex = hex::encode([2u8; 32]);
        info.add_member(
            bob_hex.clone(),
            GroupRole::Member,
            Some("alice".into()),
            None,
        );
        assert!(info.has_active_member(&bob_hex));
        assert_eq!(info.active_member_count(), 2);

        info.remove_member(&bob_hex, Some("alice".into()));
        assert!(!info.has_active_member(&bob_hex));
        assert_eq!(info.active_member_count(), 1);
    }

    #[test]
    fn test_ban_unban() {
        let mut info = GroupInfo::new("T".into(), "".into(), agent(1), "aa".repeat(16));
        let hex_b = hex::encode([2u8; 32]);
        info.add_member(hex_b.clone(), GroupRole::Member, None, None);
        info.ban_member(&hex_b, Some("alice".into()));
        assert!(info.is_banned(&hex_b));
        assert!(!info.has_active_member(&hex_b));
        info.unban_member(&hex_b);
        assert!(info.has_active_member(&hex_b));
        assert!(!info.is_banned(&hex_b));
    }

    #[test]
    fn test_migrate_from_v1() {
        // Simulate a v1 blob missing v2 fields
        let bob_key = hex::encode([2u8; 32]);
        let charlie_key = hex::encode([3u8; 32]);
        let creator_bytes: Vec<u8> = vec![1u8; 32];
        let v1_json = serde_json::json!({
            "members": [bob_key.clone(), charlie_key],
            "display_names": { bob_key.clone(): "Bob" },
            "membership_revision": 5,
            "name": "Old",
            "description": "",
            "creator": creator_bytes,
            "created_at": 1000,
            "mls_group_id": "aa".repeat(16),
            "metadata_topic": "x0x.group.aa.meta",
            "chat_topic_prefix": "x0x.group.aa.chat",
        });
        let mut info: GroupInfo = serde_json::from_value(v1_json).unwrap();
        assert!(info.members_v2.is_empty());
        info.migrate_from_v1();
        // creator + 2 members = 3 entries
        assert_eq!(info.members_v2.len(), 3);
        let creator_hex = hex::encode([1u8; 32]);
        let bob_hex = hex::encode([2u8; 32]);
        assert_eq!(info.members_v2[&creator_hex].role, GroupRole::Owner);
        assert_eq!(info.members_v2[&bob_hex].role, GroupRole::Member);
        assert_eq!(
            info.members_v2[&bob_hex].display_name.as_deref(),
            Some("Bob")
        );
        assert_eq!(info.roster_revision, 5);

        // Idempotent
        let count = info.members_v2.len();
        info.migrate_from_v1();
        assert_eq!(info.members_v2.len(), count);
    }

    #[test]
    fn test_to_group_card_hidden_returns_none() {
        let info = GroupInfo::new("T".into(), "".into(), agent(1), "aa".repeat(16));
        assert!(info.to_group_card().is_none());
    }

    #[test]
    fn test_to_group_card_public() {
        let info = GroupInfo::with_policy(
            "T".into(),
            "d".into(),
            agent(1),
            "aa".repeat(16),
            GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        let card = info.to_group_card().unwrap();
        assert_eq!(card.name, "T");
        assert_eq!(card.member_count, 1);
        assert!(card.request_access_enabled);
    }

    #[test]
    fn test_caller_role() {
        let info = GroupInfo::new("T".into(), "".into(), agent(1), "aa".repeat(16));
        let creator_hex = hex::encode([1u8; 32]);
        assert_eq!(info.caller_role(&creator_hex), Some(GroupRole::Owner));
        let stranger_hex = hex::encode([9u8; 32]);
        assert_eq!(info.caller_role(&stranger_hex), None);
    }
}
