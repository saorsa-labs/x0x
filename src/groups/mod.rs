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
pub mod discovery;
pub mod invite;
pub mod kem_envelope;
pub mod member;
pub mod policy;
pub mod public_message;
pub mod request;
pub mod state_commit;

use crate::identity::{AgentId, AgentKeypair};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub use self::directory::GroupCard;
pub use self::discovery::{
    may_publish_to_public_shards, name_words, normalize_tag, shard_of, shards_for_public,
    topic_for, DigestEntry, DirectoryMessage, DirectoryShardCache, ListedToContactsCard,
    ListedToContactsDigest, ListedToContactsPull, ShardKind, SubscriptionRecord, SubscriptionSet,
    DEFAULT_MAX_ENTRIES_PER_SHARD, DEFAULT_MAX_SUBSCRIPTIONS, DIRECTORY_TOPIC_PREFIX,
    MAX_NAME_WORDS, MAX_TAGS_PER_GROUP, SHARD_COUNT,
};
pub use self::member::{GroupMember, GroupMemberState, GroupRole};
pub use self::policy::{
    GroupAdmission, GroupConfidentiality, GroupDiscoverability, GroupPolicy, GroupPolicyPreset,
    GroupPolicySummary, GroupReadAccess, GroupWriteAccess,
};
pub use self::public_message::{
    public_topic_for, validate_public_message, GroupPublicMessage, GroupPublicMessageKind,
    IngestError as PublicMessageIngestError, PublicIngestContext, MAX_PUBLIC_MESSAGE_BYTES,
    PUBLIC_GROUP_TOPIC_PREFIX, PUBLIC_MESSAGE_DOMAIN,
};
pub use self::request::{JoinRequest, JoinRequestStatus};
pub use self::state_commit::{
    compute_policy_hash, compute_public_meta_hash, compute_roster_root, compute_state_hash,
    ActionKind, ApplyContext, ApplyError, GroupGenesis, GroupPublicMeta, GroupStateCommit,
    CARD_SIGNATURE_DOMAIN, DEFAULT_CARD_TTL_SECS, EVENT_SIGNATURE_DOMAIN, STATE_COMMIT_DOMAIN,
};

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

    // ── Phase D.3: Stable identity + evolving validity ──────────────────
    /// Stable genesis record — establishes the group's permanent `group_id`.
    /// Reconstructed from `mls_group_id` + creator + created_at when
    /// migrating pre-D.3 blobs (see [`GroupInfo::migrate_from_v1`]).
    #[serde(default)]
    pub genesis: Option<state_commit::GroupGenesis>,
    /// Monotonic revision of the signed state-commit chain. 0 = genesis
    /// (no authority-signed commits yet); bumped on every accepted event.
    #[serde(default)]
    pub state_revision: u64,
    /// Current `state_hash` — commitment to (group_id, revision, prev_hash,
    /// roster_root, policy_hash, public_meta_hash, security_binding,
    /// withdrawn). Recomputed by `recompute_state_hash()` after every
    /// mutation.
    #[serde(default)]
    pub state_hash: String,
    /// Previous `state_hash` so receivers can verify chain linking. None
    /// at genesis.
    #[serde(default)]
    pub prev_state_hash: Option<String>,
    /// Current security binding — for `MlsEncrypted` groups, a string of
    /// the form `"gss:epoch=N"` so roster/policy/epoch changes cannot
    /// silently drift apart. `None` for `SignedPublic`.
    #[serde(default)]
    pub security_binding: Option<String>,
    /// Optional tags for public discovery (Phase C.2 will hash these into
    /// shard topics). Only meaningful for `PublicDirectory` groups.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional avatar URL for public cards.
    #[serde(default)]
    pub avatar_url: Option<String>,
    /// Optional banner URL for public cards.
    #[serde(default)]
    pub banner_url: Option<String>,
    /// Withdrawal/hidden supersession marker. Once set by a higher-revision
    /// signed commit, no further non-withdrawal actions may apply and
    /// subsequent public cards must carry the withdrawal flag.
    #[serde(default)]
    pub withdrawn: bool,
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

        // Phase D.3: stable genesis. Derive the genesis record so the same
        // creator+timestamp+nonce deterministically yields the same
        // `group_id`. For backward compatibility with existing callers, we
        // keep `mls_group_id` as the persisted topic-derivation key, but
        // `genesis.group_id` is the stable authoritative identifier.
        let genesis = state_commit::GroupGenesis::new(creator_hex.clone(), now);

        let confidentiality = policy.confidentiality;
        let mut info = Self {
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

            genesis: Some(genesis),
            state_revision: 0,
            state_hash: String::new(),
            prev_state_hash: None,
            security_binding: match confidentiality {
                GroupConfidentiality::MlsEncrypted => Some("gss:epoch=0".into()),
                GroupConfidentiality::SignedPublic => None,
            },
            tags: Vec::new(),
            avatar_url: None,
            banner_url: None,
            withdrawn: false,
        };
        info.recompute_state_hash();
        info
    }

    /// Rotate the group's shared secret (called on ban/remove in MlsEncrypted
    /// groups). Returns the new secret and new epoch. Previous-epoch content
    /// encrypted by members still in the group is NOT decryptable at the new
    /// epoch — that's forward secrecy across epochs.
    ///
    /// Callers must arrange to distribute the new secret to remaining members
    /// (never to the departed/banned peer).
    ///
    /// Phase D.3: also refreshes `security_binding` so the next state commit
    /// incorporates the new epoch into `state_hash`.
    #[must_use]
    pub fn rotate_shared_secret(&mut self) -> (Vec<u8>, u64) {
        use rand::RngCore;
        let mut new_secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_secret);
        self.secret_epoch = self.secret_epoch.saturating_add(1);
        self.shared_secret = Some(new_secret.clone());
        self.security_binding = Some(format!("gss:epoch={}", self.secret_epoch));
        (new_secret, self.secret_epoch)
    }

    // ── Phase D.3: state-commit chain ──────────────────────────────────

    /// The stable `group_id` (Phase D.3). Falls back to `mls_group_id` for
    /// pre-D.3 groups where genesis has not yet been reconstructed.
    #[must_use]
    pub fn stable_group_id(&self) -> &str {
        self.genesis
            .as_ref()
            .map(|g| g.group_id.as_str())
            .unwrap_or(self.mls_group_id.as_str())
    }

    /// Snapshot of the public metadata that contributes to the state hash.
    #[must_use]
    pub fn public_meta(&self) -> state_commit::GroupPublicMeta {
        state_commit::GroupPublicMeta {
            name: self.name.clone(),
            description: self.description.clone(),
            tags: self.tags.clone(),
            avatar_url: self.avatar_url.clone(),
            banner_url: self.banner_url.clone(),
        }
    }

    /// Recompute and store `state_hash` from the current fields. Called
    /// after every mutation; also called by constructors and the v1
    /// migration path so new and migrated groups have a valid hash.
    pub fn recompute_state_hash(&mut self) {
        let roster_root = state_commit::compute_roster_root(&self.members_v2);
        let policy_hash = state_commit::compute_policy_hash(&self.policy);
        let meta_hash = state_commit::compute_public_meta_hash(&self.public_meta());
        self.state_hash = state_commit::compute_state_hash(
            self.stable_group_id(),
            self.state_revision,
            self.prev_state_hash.as_deref(),
            &roster_root,
            &policy_hash,
            &meta_hash,
            self.security_binding.as_deref(),
            self.withdrawn,
        );
    }

    /// Seal the current (already-mutated) state into a signed commit.
    ///
    /// - bumps `state_revision` by 1,
    /// - records `prev_state_hash = self.state_hash` (pre-bump hash),
    /// - recomputes the new `state_hash`,
    /// - returns a signed [`state_commit::GroupStateCommit`].
    ///
    /// Callers must mutate the group first (e.g. `add_member`, `ban_member`,
    /// policy update) **and then** call `seal_commit` to produce the
    /// authority-signed commit that can be published and verified by peers.
    pub fn seal_commit(
        &mut self,
        keypair: &AgentKeypair,
        now_ms: u64,
    ) -> Result<state_commit::GroupStateCommit, state_commit::ApplyError> {
        // Ensure the genesis record is present — callers may reach here via
        // migrated paths that didn't set it yet.
        if self.genesis.is_none() {
            let creator_hex = hex::encode(self.creator.as_bytes());
            self.genesis = Some(state_commit::GroupGenesis::with_existing_id(
                self.mls_group_id.clone(),
                creator_hex,
                self.created_at,
                // Deterministic nonce from mls_group_id so migration is
                // idempotent across daemon restarts.
                hex::encode(blake3::hash(self.mls_group_id.as_bytes()).as_bytes()),
            ));
        }
        // NOTE: do NOT recompute here. `self.state_hash` reflects the
        // *last committed* state; that is what the new commit's
        // `prev_state_hash` must link to. Mutations the caller made
        // since the last commit are intentionally not yet reflected in
        // `self.state_hash` — the recompute below folds them in under
        // the new revision.
        let prev = self.state_hash.clone();
        self.state_revision = self.state_revision.saturating_add(1);
        self.prev_state_hash = Some(prev.clone());
        self.updated_at = now_ms;
        self.recompute_state_hash();

        let roster_root = state_commit::compute_roster_root(&self.members_v2);
        let policy_hash = state_commit::compute_policy_hash(&self.policy);
        let meta_hash = state_commit::compute_public_meta_hash(&self.public_meta());

        state_commit::GroupStateCommit::sign(
            self.stable_group_id().to_string(),
            self.state_revision,
            Some(prev),
            roster_root,
            policy_hash,
            meta_hash,
            self.security_binding.clone(),
            self.withdrawn,
            now_ms,
            keypair,
        )
    }

    /// Mark the group as withdrawn and seal the terminal higher-revision
    /// commit. A withdrawn group is superseded immediately for public
    /// discovery purposes — peers holding stale public cards must drop them
    /// on receipt of this commit regardless of TTL.
    ///
    /// Withdrawal is owner-authored; callers must check role before calling.
    pub fn seal_withdrawal(
        &mut self,
        keypair: &AgentKeypair,
        now_ms: u64,
    ) -> Result<state_commit::GroupStateCommit, state_commit::ApplyError> {
        self.withdrawn = true;
        self.seal_commit(keypair, now_ms)
    }

    /// Accept a peer-authored signed commit on the apply-side.
    ///
    /// Performs [`state_commit::validate_apply`] with the given action kind
    /// and, on success, updates the local chain fields
    /// (`state_revision`, `state_hash`, `prev_state_hash`, `withdrawn`) to
    /// mirror the commit. Domain-specific mutations (roster/policy/meta)
    /// are the caller's responsibility and must be performed **before**
    /// calling this method, so the post-mutation recomputed hash matches
    /// `commit.state_hash`.
    pub fn apply_commit(
        &mut self,
        commit: &state_commit::GroupStateCommit,
        action_kind: state_commit::ActionKind,
    ) -> Result<(), state_commit::ApplyError> {
        let ctx = state_commit::ApplyContext {
            current_state_hash: &self.state_hash,
            current_revision: self.state_revision,
            current_withdrawn: self.withdrawn,
            members_v2: &self.members_v2,
            group_id: self.stable_group_id(),
        };
        state_commit::validate_apply(&ctx, commit, action_kind)?;

        // After the caller has mutated local state to mirror the committed
        // action, verify our recomputed hash matches the commit's claim.
        self.state_revision = commit.revision;
        self.prev_state_hash = commit.prev_state_hash.clone();
        self.withdrawn = commit.withdrawn;
        self.recompute_state_hash();
        if self.state_hash != commit.state_hash {
            return Err(state_commit::ApplyError::StateHashMismatch {
                expected: commit.state_hash.clone(),
                got: self.state_hash.clone(),
            });
        }
        Ok(())
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
    /// Also backfills Phase D.3 stable-genesis + state-hash fields for
    /// blobs written before D.3 landed. Idempotent: may be called multiple
    /// times.
    pub fn migrate_from_v1(&mut self) {
        if self.members_v2.is_empty() {
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
                    GroupMember::new_member(
                        id.clone(),
                        display_name,
                        Some(creator_hex.clone()),
                        now,
                    )
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
        // Phase D.3: backfill stable-genesis deterministically from the
        // existing mls_group_id so migrated blobs carry the same
        // `stable_group_id` across restarts.
        if self.genesis.is_none() {
            let creator_hex = hex::encode(self.creator.as_bytes());
            let nonce = hex::encode(blake3::hash(self.mls_group_id.as_bytes()).as_bytes());
            self.genesis = Some(state_commit::GroupGenesis::with_existing_id(
                self.mls_group_id.clone(),
                creator_hex,
                self.created_at,
                nonce,
            ));
        }
        // Phase D.3: if security_binding is unset on an MlsEncrypted group,
        // derive it from the current secret_epoch.
        if self.security_binding.is_none()
            && self.policy.confidentiality == GroupConfidentiality::MlsEncrypted
        {
            self.security_binding = Some(format!("gss:epoch={}", self.secret_epoch));
        }
        // Phase D.3: recompute state_hash if absent.
        if self.state_hash.is_empty() {
            self.recompute_state_hash();
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
    ///
    /// The returned card carries the Phase D.3 state-commit binding
    /// (`revision`, `state_hash`, `prev_state_hash`, `issued_at`,
    /// `expires_at`, `withdrawn`) but is **unsigned**. Callers with the
    /// authority's keypair should call `GroupCard::sign` before
    /// publishing to turn it into a verifiable public artifact.
    #[must_use]
    pub fn to_group_card(&self) -> Option<GroupCard> {
        if self.policy.discoverability == GroupDiscoverability::Hidden && !self.withdrawn {
            return None;
        }
        let owner = self
            .owner_agent_id()
            .unwrap_or_else(|| hex::encode(self.creator.as_bytes()));
        let issued_at = now_millis();
        let expires_at =
            issued_at.saturating_add(state_commit::DEFAULT_CARD_TTL_SECS.saturating_mul(1_000));
        Some(GroupCard {
            group_id: self.stable_group_id().to_string(),
            name: self.name.clone(),
            description: self.description.clone(),
            avatar_url: self.avatar_url.clone(),
            banner_url: self.banner_url.clone(),
            tags: self.tags.clone(),
            policy_summary: GroupPolicySummary::from(&self.policy),
            owner_agent_id: owner,
            admin_count: self.active_admin_count() as u32,
            member_count: self.active_member_count() as u32,
            created_at: self.created_at,
            updated_at: self.updated_at,
            request_access_enabled: self.policy.admission == GroupAdmission::RequestAccess,
            revision: self.state_revision,
            state_hash: self.state_hash.clone(),
            prev_state_hash: self.prev_state_hash.clone(),
            issued_at,
            expires_at,
            authority_agent_id: String::new(),
            authority_public_key: String::new(),
            withdrawn: self.withdrawn,
            signature: String::new(),
        })
    }

    /// Build and sign a `GroupCard` in one step.
    ///
    /// Returns None if the group is `Hidden` AND not withdrawn. Callers
    /// publishing a withdrawal card must call `seal_withdrawal()` first to
    /// advance the state chain, then this helper to emit the terminal
    /// signed card.
    pub fn to_signed_group_card(
        &self,
        keypair: &AgentKeypair,
    ) -> Result<Option<GroupCard>, state_commit::ApplyError> {
        let Some(mut card) = self.to_group_card() else {
            return Ok(None);
        };
        card.sign(keypair)?;
        Ok(Some(card))
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
