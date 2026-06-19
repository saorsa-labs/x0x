//! State-commit chain for named groups (Phase D.3).
//!
//! Design source of truth: `docs/design/named-groups-full-model.md`.
//!
//! Provides a stable [`GroupGenesis`] and an evolving, authority-signed
//! [`GroupStateCommit`]. Every privileged state-changing action in the
//! group control plane produces a new commit whose `state_hash` commits
//! to:
//!
//! - the stable `group_id`
//! - a monotonic `revision`
//! - the previous `state_hash` (for chain linking)
//! - the roster root (active + banned members, role, state)
//! - the policy hash
//! - the public metadata hash (name / description / tags / avatar / banner)
//! - an optional security binding (e.g. GSS `secret_epoch` for the interim
//!   v1 secure model — see `docs/primers/groups.md` for the honest scope of
//!   what GSS provides)
//!
//! Apply-side validation ([`validate_apply`]) enforces:
//!
//! 1. **Monotonic revision** — a new event must have `revision == current + 1`
//!    (or `> current` for idempotent replays we silently skip).
//! 2. **Prev-hash chain** — `prev_state_hash` must equal the current
//!    `state_hash` of the local `GroupInfo`.
//! 3. **Authority** — the signer's role at the local view must permit the
//!    action (e.g. Owner for policy changes, Admin for member management).
//! 4. **Signature** — the event is signed by the advertised signer's
//!    ML-DSA-65 key, and the `committed_by` field binds the actor.
//! 5. **Withdrawal terminality** — once a group is marked withdrawn by a
//!    higher revision, later stale events are rejected.
//!
//! Relays may republish exact signed commits and cards but **cannot mint**
//! new revisions unless they are also authorised group-state authorities.

use crate::groups::member::{GroupMember, GroupMemberState, GroupRole};
use crate::groups::policy::GroupPolicy;
use crate::identity::AgentKeypair;
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain-separation tag for `GroupStateCommit::state_hash` computation.
pub const STATE_COMMIT_DOMAIN: &[u8] = b"x0x.group.state-commit.v1";

/// Domain-separation tag for authority-signed `GroupCard` payloads.
pub const CARD_SIGNATURE_DOMAIN: &[u8] = b"x0x.group.card.v1";

/// Domain-separation tag for signed group control-plane events.
pub const EVENT_SIGNATURE_DOMAIN: &[u8] = b"x0x.group.event.v1";

/// Default public-card validity window, in seconds.
/// Cards past `expires_at` are cache-cleanup candidates; this is **not** the
/// primary validity mechanism — higher signed revisions supersede lower ones
/// immediately.
pub const DEFAULT_CARD_TTL_SECS: u64 = 24 * 60 * 60;

// ─────────────────────────── Hash primitives ────────────────────────────

fn blake3_hex(input: &[u8]) -> String {
    hex::encode(blake3::hash(input).as_bytes())
}

/// Compute the canonical roster root for a group's `members_v2` map.
///
/// Only **access-bearing** entries contribute: `Active` members (with their
/// role) and `Banned` entries (so ban state is part of the commit).
/// `Removed` and `Pending` entries are excluded because they do not
/// currently affect effective access.
#[must_use]
pub fn compute_roster_root(members_v2: &BTreeMap<String, GroupMember>) -> String {
    let mut entries: Vec<(&str, GroupRole, GroupMemberState)> = members_v2
        .iter()
        .filter(|(_, m)| matches!(m.state, GroupMemberState::Active | GroupMemberState::Banned))
        .map(|(id, m)| (id.as_str(), m.role, m.state))
        .collect();
    roster_root_from_entries(&mut entries)
}

/// Shared hashing core for the roster root. Sorts `entries` by id and folds
/// `(id, role, state)` into the canonical `x0x.roster-root.v1` digest. Both
/// [`compute_roster_root`] (over a live roster) and
/// [`roster_root_of_projection`] (over a retained projection) route through
/// this so a retained projection re-derives the exact root its commit signed.
fn roster_root_from_entries(entries: &mut [(&str, GroupRole, GroupMemberState)]) -> String {
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut buf = Vec::with_capacity(entries.len() * 48 + 16);
    buf.extend_from_slice(b"x0x.roster-root.v1");
    for (id, role, state) in entries.iter() {
        buf.push(b'|');
        buf.extend_from_slice(id.as_bytes());
        buf.push(b':');
        buf.push(role_byte(*role));
        buf.push(state_byte(*state));
    }
    blake3_hex(&buf)
}

/// Minimal, verifiable roster projection captured alongside a retained commit:
/// exactly the `(role, state)` tuples that feed [`compute_roster_root`]
/// (`Active` + `Banned` members). Sufficient to answer "what did the signed
/// roster say at revision N" and to re-derive the commit's `roster_root`
/// independently — without having witnessed every prior commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMemberSnapshot {
    pub role: GroupRole,
    pub state: GroupMemberState,
}

/// Project the roster-root-relevant view of a roster: `Active` + `Banned`
/// members with their `(role, state)`. Mirrors [`compute_roster_root`]'s
/// filter exactly so [`roster_root_of_projection`] re-derives the same root.
#[must_use]
pub fn roster_projection(
    members_v2: &BTreeMap<String, GroupMember>,
) -> BTreeMap<String, RosterMemberSnapshot> {
    members_v2
        .iter()
        .filter(|(_, m)| matches!(m.state, GroupMemberState::Active | GroupMemberState::Banned))
        .map(|(id, m)| {
            (
                id.clone(),
                RosterMemberSnapshot {
                    role: m.role,
                    state: m.state,
                },
            )
        })
        .collect()
}

/// Re-derive the roster root from a projection (see [`roster_projection`]).
#[must_use]
pub fn roster_root_of_projection(projection: &BTreeMap<String, RosterMemberSnapshot>) -> String {
    let mut entries: Vec<(&str, GroupRole, GroupMemberState)> = projection
        .iter()
        .map(|(id, s)| (id.as_str(), s.role, s.state))
        .collect();
    roster_root_from_entries(&mut entries)
}

/// A retained, applied state commit paired with the roster projection it
/// effected (issue #111). Each entry is independently verifiable: recomputing
/// the root over `roster` yields `commit.roster_root` (see
/// [`RetainedCommit::roster_root_consistent`]). Retained entries let
/// verification and governance integrators answer roster-at-revision questions
/// long after the fact, which the head-only `GroupInfo` snapshot cannot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedCommit {
    pub commit: GroupStateCommit,
    pub roster: BTreeMap<String, RosterMemberSnapshot>,
}

impl RetainedCommit {
    /// Capture a retained entry from a just-committed roster and the signed
    /// commit that produced it. `members_v2` must already reflect the
    /// committed state.
    #[must_use]
    pub fn capture(commit: GroupStateCommit, members_v2: &BTreeMap<String, GroupMember>) -> Self {
        Self {
            roster: roster_projection(members_v2),
            commit,
        }
    }

    /// True iff the retained roster projection re-derives the commit's signed
    /// `roster_root` — i.e. the entry is internally consistent and was not
    /// corrupted at rest.
    #[must_use]
    pub fn roster_root_consistent(&self) -> bool {
        roster_root_of_projection(&self.roster) == self.commit.roster_root
    }
}

/// Compute the canonical policy hash.
#[must_use]
pub fn compute_policy_hash(policy: &GroupPolicy) -> String {
    // bincode is deterministic for simple enums/structs without maps.
    let bytes = bincode::serialize(policy).unwrap_or_default();
    let mut buf = Vec::with_capacity(bytes.len() + 32);
    buf.extend_from_slice(b"x0x.policy-hash.v1");
    buf.extend_from_slice(&bytes);
    blake3_hex(&buf)
}

/// Compute the canonical public-metadata hash.
#[must_use]
pub fn compute_public_meta_hash(meta: &GroupPublicMeta) -> String {
    // Canonical encoding: length-prefixed UTF-8.
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"x0x.public-meta.v1");
    push_len_prefixed(&mut buf, meta.name.as_bytes());
    push_len_prefixed(&mut buf, meta.description.as_bytes());
    let mut tags_sorted = meta.tags.clone();
    tags_sorted.sort();
    tags_sorted.dedup();
    buf.extend_from_slice(&(tags_sorted.len() as u32).to_le_bytes());
    for tag in &tags_sorted {
        push_len_prefixed(&mut buf, tag.as_bytes());
    }
    push_len_prefixed(
        &mut buf,
        meta.avatar_url.as_deref().unwrap_or("").as_bytes(),
    );
    push_len_prefixed(
        &mut buf,
        meta.banner_url.as_deref().unwrap_or("").as_bytes(),
    );
    blake3_hex(&buf)
}

/// Compose the final `state_hash` from its parts.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn compute_state_hash(
    group_id: &str,
    revision: u64,
    prev_state_hash: Option<&str>,
    roster_root: &str,
    policy_hash: &str,
    public_meta_hash: &str,
    security_binding: Option<&str>,
    withdrawn: bool,
) -> String {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(STATE_COMMIT_DOMAIN);
    push_len_prefixed(&mut buf, group_id.as_bytes());
    buf.extend_from_slice(&revision.to_le_bytes());
    push_len_prefixed(&mut buf, prev_state_hash.unwrap_or("").as_bytes());
    push_len_prefixed(&mut buf, roster_root.as_bytes());
    push_len_prefixed(&mut buf, policy_hash.as_bytes());
    push_len_prefixed(&mut buf, public_meta_hash.as_bytes());
    push_len_prefixed(&mut buf, security_binding.unwrap_or("").as_bytes());
    buf.push(if withdrawn { 1 } else { 0 });
    blake3_hex(&buf)
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn role_byte(role: GroupRole) -> u8 {
    match role {
        GroupRole::Owner => 4,
        GroupRole::Admin => 3,
        GroupRole::Moderator => 2,
        GroupRole::Member => 1,
        GroupRole::Guest => 0,
    }
}

fn state_byte(state: GroupMemberState) -> u8 {
    match state {
        GroupMemberState::Active => 1,
        GroupMemberState::Banned => 2,
        GroupMemberState::Removed => 3,
        GroupMemberState::Pending => 4,
    }
}

// ─────────────────────────── Core types ─────────────────────────────────

/// Immutable genesis record for a group.
///
/// The stable `group_id` is derived from `(creator_agent_id, created_at,
/// creation_nonce)` via BLAKE3 and never changes, regardless of rename or
/// roster churn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupGenesis {
    /// Stable hex group identifier. Never changes for the lifetime of the group.
    pub group_id: String,
    /// Hex agent_id of the creator.
    pub creator_agent_id: String,
    /// Unix milliseconds at creation.
    pub created_at: u64,
    /// 32-byte hex random nonce so two groups created at the same ms by the
    /// same creator still get distinct ids.
    pub creation_nonce: String,
}

impl GroupGenesis {
    /// Create a new genesis record and derive its stable `group_id`.
    #[must_use]
    pub fn new(creator_agent_id: String, created_at: u64) -> Self {
        let nonce = {
            use rand::RngCore;
            let mut n = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut n);
            hex::encode(n)
        };
        let group_id = Self::derive_group_id(&creator_agent_id, created_at, &nonce);
        Self {
            group_id,
            creator_agent_id,
            created_at,
            creation_nonce: nonce,
        }
    }

    /// Reconstruct a genesis record from known components (e.g. when
    /// migrating from legacy blobs where `mls_group_id` is already the stable
    /// id).
    #[must_use]
    pub fn with_existing_id(
        group_id: String,
        creator_agent_id: String,
        created_at: u64,
        creation_nonce: String,
    ) -> Self {
        Self {
            group_id,
            creator_agent_id,
            created_at,
            creation_nonce,
        }
    }

    /// Derive a stable `group_id` from creator + timestamp + nonce.
    #[must_use]
    pub fn derive_group_id(creator_agent_id: &str, created_at: u64, nonce: &str) -> String {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"x0x.group.genesis.v1");
        push_len_prefixed(&mut buf, creator_agent_id.as_bytes());
        buf.extend_from_slice(&created_at.to_le_bytes());
        push_len_prefixed(&mut buf, nonce.as_bytes());
        blake3_hex(&buf)
    }
}

/// Public metadata that contributes to the state hash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPublicMeta {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub banner_url: Option<String>,
}

/// A signed commitment to the current valid group state.
///
/// Each transition through [`validate_apply`] produces a new
/// `GroupStateCommit` whose `state_hash` supersedes the previous one.
/// Higher revisions supersede lower ones **immediately**; stale commits
/// are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStateCommit {
    pub group_id: String,
    pub revision: u64,
    #[serde(default)]
    pub prev_state_hash: Option<String>,
    pub roster_root: String,
    pub policy_hash: String,
    pub public_meta_hash: String,
    #[serde(default)]
    pub security_binding: Option<String>,
    pub state_hash: String,
    #[serde(default)]
    pub withdrawn: bool,
    pub committed_by: String,
    pub committed_at: u64,
    /// Hex ML-DSA-65 public key of the signer (for verification without a
    /// separate key-lookup path).
    pub signer_public_key: String,
    /// Hex ML-DSA-65 signature over the canonical commit bytes.
    pub signature: String,
}

impl GroupStateCommit {
    /// Bytes that are signed by `signer` to produce the `signature` field.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(STATE_COMMIT_DOMAIN);
        push_len_prefixed(&mut buf, self.group_id.as_bytes());
        buf.extend_from_slice(&self.revision.to_le_bytes());
        push_len_prefixed(
            &mut buf,
            self.prev_state_hash.as_deref().unwrap_or("").as_bytes(),
        );
        push_len_prefixed(&mut buf, self.roster_root.as_bytes());
        push_len_prefixed(&mut buf, self.policy_hash.as_bytes());
        push_len_prefixed(&mut buf, self.public_meta_hash.as_bytes());
        push_len_prefixed(
            &mut buf,
            self.security_binding.as_deref().unwrap_or("").as_bytes(),
        );
        buf.push(if self.withdrawn { 1 } else { 0 });
        push_len_prefixed(&mut buf, self.state_hash.as_bytes());
        push_len_prefixed(&mut buf, self.committed_by.as_bytes());
        buf.extend_from_slice(&self.committed_at.to_le_bytes());
        buf
    }

    /// Produce a signed commit from the working state fields and an actor
    /// keypair. The caller must have already computed the final `state_hash`
    /// consistent with the `roster_root` / `policy_hash` / `public_meta_hash`
    /// / `security_binding` / `withdrawn` inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        group_id: String,
        revision: u64,
        prev_state_hash: Option<String>,
        roster_root: String,
        policy_hash: String,
        public_meta_hash: String,
        security_binding: Option<String>,
        withdrawn: bool,
        committed_at: u64,
        keypair: &AgentKeypair,
    ) -> Result<Self, ApplyError> {
        let committed_by = hex::encode(keypair.agent_id().as_bytes());
        let signer_public_key = hex::encode(keypair.public_key().as_bytes());
        let state_hash = compute_state_hash(
            &group_id,
            revision,
            prev_state_hash.as_deref(),
            &roster_root,
            &policy_hash,
            &public_meta_hash,
            security_binding.as_deref(),
            withdrawn,
        );

        let mut commit = Self {
            group_id,
            revision,
            prev_state_hash,
            roster_root,
            policy_hash,
            public_meta_hash,
            security_binding,
            state_hash,
            withdrawn,
            committed_by,
            committed_at,
            signer_public_key,
            signature: String::new(),
        };
        let sig = sign_with_ml_dsa(keypair.secret_key(), &commit.signable_bytes())
            .map_err(|e| ApplyError::InvalidSignature(format!("{e:?}")))?;
        commit.signature = hex::encode(sig.as_bytes());
        Ok(commit)
    }

    /// Verify the commit's internal structure:
    /// - `state_hash` is consistent with the component hashes.
    /// - `signature` verifies under `signer_public_key`.
    /// - `committed_by` matches the AgentId derived from `signer_public_key`.
    pub fn verify_structure(&self) -> Result<(), ApplyError> {
        let expected = compute_state_hash(
            &self.group_id,
            self.revision,
            self.prev_state_hash.as_deref(),
            &self.roster_root,
            &self.policy_hash,
            &self.public_meta_hash,
            self.security_binding.as_deref(),
            self.withdrawn,
        );
        if expected != self.state_hash {
            return Err(ApplyError::StateHashMismatch {
                expected,
                got: self.state_hash.clone(),
            });
        }

        let pubkey_bytes = hex::decode(&self.signer_public_key)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad pubkey hex: {e}")))?;
        let pubkey = MlDsaPublicKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad pubkey: {e:?}")))?;

        // Derived AgentId must match committed_by.
        let derived = hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0);
        if derived != self.committed_by {
            return Err(ApplyError::InvalidSignature(format!(
                "committed_by {} does not match signer_public_key-derived {}",
                self.committed_by, derived
            )));
        }

        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad sig hex: {e}")))?;
        let sig = MlDsaSignature::from_bytes(&sig_bytes)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad sig: {e:?}")))?;
        verify_with_ml_dsa(&pubkey, &self.signable_bytes(), &sig)
            .map_err(|e| ApplyError::InvalidSignature(format!("verify failed: {e:?}")))?;
        Ok(())
    }
}

// ─────────────────────────── Apply errors ───────────────────────────────

/// Errors produced during apply-side validation.
///
/// These must be at least as strict as endpoint-time checks — events
/// arriving via gossip are re-validated against the local view.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ApplyError {
    /// The revision is lower than or equal to what we already have.
    #[error("stale revision: got {got}, have {have}")]
    StaleRevision { got: u64, have: u64 },

    /// The event's `prev_state_hash` does not match our current `state_hash`.
    #[error("prev_state_hash mismatch: expected {expected:?}, got {got:?}")]
    PrevHashMismatch {
        expected: Option<String>,
        got: Option<String>,
    },

    /// The signer is not authorised for this action at the current view.
    #[error("unauthorised signer {signer} for action {action}")]
    Unauthorized {
        signer: String,
        action: &'static str,
    },

    /// The signature or signer-key binding is invalid.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// A structural invariant was violated (e.g. owner removal, duplicate).
    #[error("invariant violation: {0}")]
    Invariant(String),

    /// The group has been withdrawn; no further non-owner actions apply.
    #[error("group is withdrawn")]
    Withdrawn,

    /// The action targets an entity that does not exist.
    #[error("missing target: {0}")]
    MissingTarget(String),

    /// The claimed `state_hash` does not equal the recomputed value.
    #[error("state hash mismatch: expected {expected}, got {got}")]
    StateHashMismatch { expected: String, got: String },

    /// The event's `group_id` does not match the target group.
    #[error("group_id mismatch: got {got}, expected {expected}")]
    GroupIdMismatch { expected: String, got: String },
}

// ─────────────────────────── Apply checks ───────────────────────────────

/// Classification of a privileged action, for authorisation checks.
///
/// Each variant names the minimum role required. These are checked at
/// apply-time against the signer's current effective role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    /// Owner-only: policy change, role-change-of-admin-or-above, withdrawal.
    OwnerOnly,
    /// Admin or higher: add/remove member, approve/reject request, ban, unban,
    /// role-change-of-member-or-below, metadata edit.
    AdminOrHigher,
    /// Active-member self-action (e.g. leave group).
    MemberSelf,
    /// Non-member or pending-requester action (e.g. create/cancel join request).
    NonMemberRequest,
}

impl ActionKind {
    /// Human-readable name for error reporting.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::OwnerOnly => "owner-only",
            Self::AdminOrHigher => "admin-or-higher",
            Self::MemberSelf => "member-self",
            Self::NonMemberRequest => "non-member-request",
        }
    }
}

/// Input to [`validate_apply`].
///
/// Receivers recompute the hash of the committed payload and verify:
/// - the signed event chains from the current state,
/// - the signer is authorised,
/// - the advertised `new_state_hash` matches the recomputed result.
#[derive(Debug, Clone)]
pub struct ApplyContext<'a> {
    /// Hex agent_id currently holding `GroupInfo`.
    pub current_state_hash: &'a str,
    pub current_revision: u64,
    pub current_withdrawn: bool,
    /// Map used to look up the signer's current role (active-only).
    pub members_v2: &'a BTreeMap<String, GroupMember>,
    pub group_id: &'a str,
}

/// Validate a signed commit against the local view **before** mutating any
/// state. Returns `Ok(())` if the caller should proceed to mutate; returns
/// `Err` to reject (stale, chain break, unauthorized, bad signature, …).
///
/// This function is **read-only** with respect to `GroupInfo`. It enforces
/// all the checks required by `docs/design/named-groups-full-model.md`
/// §"Apply-side validation".
pub fn validate_apply(
    ctx: &ApplyContext<'_>,
    commit: &GroupStateCommit,
    action_kind: ActionKind,
) -> Result<(), ApplyError> {
    // 1. group_id match
    if commit.group_id != ctx.group_id {
        return Err(ApplyError::GroupIdMismatch {
            expected: ctx.group_id.to_string(),
            got: commit.group_id.clone(),
        });
    }

    // 2. signature + state_hash consistency (structural)
    commit.verify_structure()?;

    // 3. revision monotonicity
    if commit.revision <= ctx.current_revision {
        return Err(ApplyError::StaleRevision {
            got: commit.revision,
            have: ctx.current_revision,
        });
    }

    // 4. prev_state_hash chain. The current local `state_hash` (whether
    //    it is the genesis-derived hash at revision 0 or the hash of the
    //    last-applied commit at revision N) must equal the commit's
    //    `prev_state_hash`. Callers must recompute `state_hash` before
    //    apply so the chain check is meaningful.
    let expected_prev = Some(ctx.current_state_hash.to_string());
    if commit.prev_state_hash != expected_prev {
        return Err(ApplyError::PrevHashMismatch {
            expected: expected_prev,
            got: commit.prev_state_hash.clone(),
        });
    }

    // 5. withdrawal terminality
    if ctx.current_withdrawn && !commit.withdrawn {
        return Err(ApplyError::Withdrawn);
    }

    // 6. authority
    let signer_role = ctx
        .members_v2
        .get(&commit.committed_by)
        .filter(|m| m.is_active())
        .map(|m| m.role);

    let authorized = match action_kind {
        ActionKind::OwnerOnly => signer_role == Some(GroupRole::Owner),
        ActionKind::AdminOrHigher => signer_role
            .map(|r| r.at_least(GroupRole::Admin))
            .unwrap_or(false),
        ActionKind::MemberSelf => signer_role.is_some(),
        ActionKind::NonMemberRequest => signer_role.is_none(),
    };
    if !authorized {
        return Err(ApplyError::Unauthorized {
            signer: commit.committed_by.clone(),
            action: action_kind.name(),
        });
    }

    Ok(())
}

// ─────────────────────────────── Tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::member::GroupMember;
    use crate::groups::policy::GroupPolicyPreset;

    fn make_owner(hex_id: &str) -> GroupMember {
        GroupMember::new_owner(hex_id.to_string(), Some("Owner".into()), 1_000)
    }

    fn make_member(hex_id: &str, role: GroupRole) -> GroupMember {
        let mut m = GroupMember::new_member(hex_id.to_string(), None, None, 2_000);
        m.role = role;
        m
    }

    fn make_banned(hex_id: &str) -> GroupMember {
        let mut m = make_member(hex_id, GroupRole::Member);
        m.state = GroupMemberState::Banned;
        m
    }

    fn make_removed(hex_id: &str) -> GroupMember {
        let mut m = make_member(hex_id, GroupRole::Member);
        m.state = GroupMemberState::Removed;
        m
    }

    #[test]
    fn group_id_is_stable_across_renames() {
        let g = GroupGenesis::new("aa".repeat(32), 1_000);
        let reconstructed =
            GroupGenesis::derive_group_id(&g.creator_agent_id, g.created_at, &g.creation_nonce);
        assert_eq!(g.group_id, reconstructed);
        // Different nonce => different id even with same creator/time.
        let g2 = GroupGenesis::new("aa".repeat(32), 1_000);
        assert_ne!(g.group_id, g2.group_id);
    }

    #[test]
    fn roster_projection_rederives_roster_root() {
        // issue #111: a retained roster projection must hash to the exact root
        // its commit signed — that is what makes a single retained entry
        // independently verifiable without the prior chain.
        let mut m = BTreeMap::new();
        m.insert("aa".repeat(32), make_owner(&"aa".repeat(32)));
        m.insert(
            "bb".repeat(32),
            make_member(&"bb".repeat(32), GroupRole::Admin),
        );
        m.insert("cc".repeat(32), make_banned(&"cc".repeat(32)));
        // Excluded from the root: Removed + Pending must not appear in the
        // projection (mirrors compute_roster_root's filter exactly).
        m.insert("dd".repeat(32), make_removed(&"dd".repeat(32)));

        let projection = roster_projection(&m);
        assert!(
            projection.contains_key(&"cc".repeat(32)),
            "banned members are part of the root and must be projected"
        );
        assert!(
            !projection.contains_key(&"dd".repeat(32)),
            "removed members are excluded from the root and the projection"
        );
        assert_eq!(
            roster_root_of_projection(&projection),
            compute_roster_root(&m),
            "projection must re-derive the live roster root"
        );
    }

    #[test]
    fn retained_commit_capture_is_self_consistent() {
        let mut m = BTreeMap::new();
        m.insert("aa".repeat(32), make_owner(&"aa".repeat(32)));
        m.insert(
            "bb".repeat(32),
            make_member(&"bb".repeat(32), GroupRole::Member),
        );

        let kp = AgentKeypair::generate().unwrap();
        let commit = GroupStateCommit::sign(
            "gid".into(),
            1,
            Some("prev".into()),
            compute_roster_root(&m),
            compute_policy_hash(&GroupPolicy::default()),
            compute_public_meta_hash(&GroupPublicMeta::default()),
            None,
            false,
            5_000,
            &kp,
        )
        .unwrap();

        let retained = RetainedCommit::capture(commit, &m);
        assert!(
            retained.roster_root_consistent(),
            "captured projection must re-derive the commit's signed roster_root"
        );

        // A tampered projection must fail the consistency check (this is the
        // on-disk-corruption guard the endpoint surfaces as roster_root_verified).
        let mut tampered = retained.clone();
        tampered.roster.get_mut(&"bb".repeat(32)).unwrap().role = GroupRole::Admin;
        assert!(
            !tampered.roster_root_consistent(),
            "a mutated projection must no longer match the signed root"
        );
    }

    #[test]
    fn roster_root_excludes_removed_and_pending() {
        let mut m = BTreeMap::new();
        m.insert("aa".repeat(32), make_owner(&"aa".repeat(32)));
        m.insert(
            "bb".repeat(32),
            make_member(&"bb".repeat(32), GroupRole::Member),
        );
        m.insert("cc".repeat(32), make_removed(&"cc".repeat(32)));
        let mut p = BTreeMap::new();
        p.insert("dd".repeat(32), {
            let mut x = make_member(&"dd".repeat(32), GroupRole::Member);
            x.state = GroupMemberState::Pending;
            x
        });
        p.insert("aa".repeat(32), make_owner(&"aa".repeat(32)));
        p.insert(
            "bb".repeat(32),
            make_member(&"bb".repeat(32), GroupRole::Member),
        );
        assert_eq!(compute_roster_root(&m), compute_roster_root(&p));
    }

    #[test]
    fn roster_root_covers_ban_state() {
        let mut active = BTreeMap::new();
        active.insert("aa".repeat(32), make_owner(&"aa".repeat(32)));
        active.insert(
            "bb".repeat(32),
            make_member(&"bb".repeat(32), GroupRole::Member),
        );

        let mut banned = active.clone();
        banned.insert("bb".repeat(32), make_banned(&"bb".repeat(32)));

        assert_ne!(compute_roster_root(&active), compute_roster_root(&banned));
    }

    #[test]
    fn roster_root_covers_role_change() {
        let mut a = BTreeMap::new();
        a.insert("aa".repeat(32), make_owner(&"aa".repeat(32)));
        a.insert(
            "bb".repeat(32),
            make_member(&"bb".repeat(32), GroupRole::Member),
        );

        let mut b = a.clone();
        b.insert(
            "bb".repeat(32),
            make_member(&"bb".repeat(32), GroupRole::Admin),
        );

        assert_ne!(compute_roster_root(&a), compute_roster_root(&b));
    }

    #[test]
    fn policy_hash_changes_with_policy() {
        let p1 = GroupPolicyPreset::PrivateSecure.to_policy();
        let p2 = GroupPolicyPreset::PublicRequestSecure.to_policy();
        assert_ne!(compute_policy_hash(&p1), compute_policy_hash(&p2));
    }

    #[test]
    fn public_meta_hash_stable_across_tag_reorder() {
        let a = GroupPublicMeta {
            name: "N".into(),
            description: "D".into(),
            tags: vec!["ai".into(), "rust".into()],
            avatar_url: None,
            banner_url: None,
        };
        let b = GroupPublicMeta {
            name: "N".into(),
            description: "D".into(),
            tags: vec!["rust".into(), "ai".into()],
            avatar_url: None,
            banner_url: None,
        };
        assert_eq!(compute_public_meta_hash(&a), compute_public_meta_hash(&b));
    }

    #[test]
    fn public_meta_hash_dedups_tags() {
        let a = GroupPublicMeta {
            name: "N".into(),
            description: "".into(),
            tags: vec!["ai".into()],
            ..Default::default()
        };
        let b = GroupPublicMeta {
            name: "N".into(),
            description: "".into(),
            tags: vec!["ai".into(), "ai".into()],
            ..Default::default()
        };
        assert_eq!(compute_public_meta_hash(&a), compute_public_meta_hash(&b));
    }

    #[test]
    fn state_hash_deterministic() {
        let h1 = compute_state_hash(
            "g1",
            1,
            Some("prev"),
            "roster",
            "policy",
            "meta",
            Some("epoch:3"),
            false,
        );
        let h2 = compute_state_hash(
            "g1",
            1,
            Some("prev"),
            "roster",
            "policy",
            "meta",
            Some("epoch:3"),
            false,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn state_hash_sensitive_to_every_component() {
        let base = || {
            compute_state_hash(
                "g1",
                1,
                Some("prev"),
                "roster",
                "policy",
                "meta",
                Some("epoch:3"),
                false,
            )
        };
        assert_ne!(
            base(),
            compute_state_hash(
                "g2",
                1,
                Some("prev"),
                "roster",
                "policy",
                "meta",
                Some("epoch:3"),
                false
            )
        );
        assert_ne!(
            base(),
            compute_state_hash(
                "g1",
                2,
                Some("prev"),
                "roster",
                "policy",
                "meta",
                Some("epoch:3"),
                false
            )
        );
        assert_ne!(
            base(),
            compute_state_hash(
                "g1",
                1,
                Some("other"),
                "roster",
                "policy",
                "meta",
                Some("epoch:3"),
                false
            )
        );
        assert_ne!(
            base(),
            compute_state_hash(
                "g1",
                1,
                Some("prev"),
                "XX",
                "policy",
                "meta",
                Some("epoch:3"),
                false
            )
        );
        assert_ne!(
            base(),
            compute_state_hash(
                "g1",
                1,
                Some("prev"),
                "roster",
                "XX",
                "meta",
                Some("epoch:3"),
                false
            )
        );
        assert_ne!(
            base(),
            compute_state_hash(
                "g1",
                1,
                Some("prev"),
                "roster",
                "policy",
                "XX",
                Some("epoch:3"),
                false
            )
        );
        assert_ne!(
            base(),
            compute_state_hash(
                "g1",
                1,
                Some("prev"),
                "roster",
                "policy",
                "meta",
                Some("epoch:4"),
                false
            )
        );
        assert_ne!(
            base(),
            compute_state_hash(
                "g1",
                1,
                Some("prev"),
                "roster",
                "policy",
                "meta",
                Some("epoch:3"),
                true
            )
        );
    }

    #[test]
    fn commit_sign_and_verify_roundtrip() {
        let kp = AgentKeypair::generate().unwrap();
        let commit = GroupStateCommit::sign(
            "g1".into(),
            1,
            None,
            "roster".into(),
            "policy".into(),
            "meta".into(),
            Some("epoch:0".into()),
            false,
            12_345,
            &kp,
        )
        .unwrap();
        commit.verify_structure().unwrap();
    }

    #[test]
    fn commit_signature_tampering_detected() {
        let kp = AgentKeypair::generate().unwrap();
        let mut commit = GroupStateCommit::sign(
            "g1".into(),
            1,
            None,
            "roster".into(),
            "policy".into(),
            "meta".into(),
            None,
            false,
            12_345,
            &kp,
        )
        .unwrap();
        // Tamper with state_hash (but keep signature): verify_structure
        // recomputes state_hash first, so tampered state_hash is caught
        // before we even hit the signature check.
        commit.state_hash = "deadbeef".into();
        assert!(matches!(
            commit.verify_structure(),
            Err(ApplyError::StateHashMismatch { .. })
        ));
    }

    #[test]
    fn commit_committed_by_must_match_pubkey() {
        let kp = AgentKeypair::generate().unwrap();
        let mut commit = GroupStateCommit::sign(
            "g1".into(),
            1,
            None,
            "roster".into(),
            "policy".into(),
            "meta".into(),
            None,
            false,
            12_345,
            &kp,
        )
        .unwrap();
        commit.committed_by = "aa".repeat(32);
        // state_hash does not cover committed_by directly, but verify_structure
        // re-derives from signer_public_key and compares.
        // The signature over signable_bytes includes committed_by, so the sig
        // won't verify either, but the pubkey-derived AgentId check fires
        // first.
        assert!(matches!(
            commit.verify_structure(),
            Err(ApplyError::InvalidSignature(_))
        ));
    }

    #[test]
    fn validate_apply_rejects_stale_revision() {
        let owner_hex = "aa".repeat(32);
        let kp = AgentKeypair::generate().unwrap();
        let signer_hex = hex::encode(kp.agent_id().as_bytes());
        let mut members = BTreeMap::new();
        members.insert(signer_hex.clone(), make_owner(&signer_hex));

        let commit = GroupStateCommit::sign(
            "g1".into(),
            1, // stale: current_revision is already 1
            Some("old".into()),
            "r".into(),
            "p".into(),
            "m".into(),
            None,
            false,
            0,
            &kp,
        )
        .unwrap();

        let ctx = ApplyContext {
            current_state_hash: "current",
            current_revision: 1,
            current_withdrawn: false,
            members_v2: &members,
            group_id: "g1",
        };
        let err = validate_apply(&ctx, &commit, ActionKind::OwnerOnly).unwrap_err();
        assert!(matches!(err, ApplyError::StaleRevision { got: 1, have: 1 }));
        let _ = owner_hex; // silence unused
    }

    #[test]
    fn validate_apply_rejects_prev_hash_break() {
        let kp = AgentKeypair::generate().unwrap();
        let signer_hex = hex::encode(kp.agent_id().as_bytes());
        let mut members = BTreeMap::new();
        members.insert(signer_hex.clone(), make_owner(&signer_hex));

        let commit = GroupStateCommit::sign(
            "g1".into(),
            2,
            Some("wrong-prev".into()),
            "r".into(),
            "p".into(),
            "m".into(),
            None,
            false,
            0,
            &kp,
        )
        .unwrap();
        let ctx = ApplyContext {
            current_state_hash: "current-real",
            current_revision: 1,
            current_withdrawn: false,
            members_v2: &members,
            group_id: "g1",
        };
        let err = validate_apply(&ctx, &commit, ActionKind::OwnerOnly).unwrap_err();
        assert!(matches!(err, ApplyError::PrevHashMismatch { .. }));
    }

    #[test]
    fn validate_apply_rejects_unauthorized_owner_action() {
        let kp = AgentKeypair::generate().unwrap();
        let signer_hex = hex::encode(kp.agent_id().as_bytes());
        let owner_hex = "ff".repeat(32);
        let mut members = BTreeMap::new();
        members.insert(owner_hex.clone(), make_owner(&owner_hex));
        members.insert(
            signer_hex.clone(),
            make_member(&signer_hex, GroupRole::Member),
        );

        let commit = GroupStateCommit::sign(
            "g1".into(),
            2,
            Some("current".into()),
            "r".into(),
            "p".into(),
            "m".into(),
            None,
            false,
            0,
            &kp,
        )
        .unwrap();
        let ctx = ApplyContext {
            current_state_hash: "current",
            current_revision: 1,
            current_withdrawn: false,
            members_v2: &members,
            group_id: "g1",
        };
        let err = validate_apply(&ctx, &commit, ActionKind::OwnerOnly).unwrap_err();
        assert!(matches!(err, ApplyError::Unauthorized { .. }));
    }

    #[test]
    fn validate_apply_allows_admin_action_from_admin() {
        let kp = AgentKeypair::generate().unwrap();
        let signer_hex = hex::encode(kp.agent_id().as_bytes());
        let owner_hex = "ff".repeat(32);
        let mut members = BTreeMap::new();
        members.insert(owner_hex.clone(), make_owner(&owner_hex));
        members.insert(
            signer_hex.clone(),
            make_member(&signer_hex, GroupRole::Admin),
        );

        let commit = GroupStateCommit::sign(
            "g1".into(),
            2,
            Some("current".into()),
            "r".into(),
            "p".into(),
            "m".into(),
            None,
            false,
            0,
            &kp,
        )
        .unwrap();
        let ctx = ApplyContext {
            current_state_hash: "current",
            current_revision: 1,
            current_withdrawn: false,
            members_v2: &members,
            group_id: "g1",
        };
        validate_apply(&ctx, &commit, ActionKind::AdminOrHigher).unwrap();
    }

    #[test]
    fn validate_apply_rejects_post_withdrawal_non_withdrawal() {
        let kp = AgentKeypair::generate().unwrap();
        let signer_hex = hex::encode(kp.agent_id().as_bytes());
        let mut members = BTreeMap::new();
        members.insert(signer_hex.clone(), make_owner(&signer_hex));

        let commit = GroupStateCommit::sign(
            "g1".into(),
            3,
            Some("current".into()),
            "r".into(),
            "p".into(),
            "m".into(),
            None,
            false, // not a withdrawal
            0,
            &kp,
        )
        .unwrap();
        let ctx = ApplyContext {
            current_state_hash: "current",
            current_revision: 2,
            current_withdrawn: true,
            members_v2: &members,
            group_id: "g1",
        };
        let err = validate_apply(&ctx, &commit, ActionKind::OwnerOnly).unwrap_err();
        assert!(matches!(err, ApplyError::Withdrawn));
    }

    #[test]
    fn validate_apply_rejects_wrong_group_id() {
        let kp = AgentKeypair::generate().unwrap();
        let signer_hex = hex::encode(kp.agent_id().as_bytes());
        let mut members = BTreeMap::new();
        members.insert(signer_hex.clone(), make_owner(&signer_hex));

        let commit = GroupStateCommit::sign(
            "g-wrong".into(),
            2,
            Some("current".into()),
            "r".into(),
            "p".into(),
            "m".into(),
            None,
            false,
            0,
            &kp,
        )
        .unwrap();
        let ctx = ApplyContext {
            current_state_hash: "current",
            current_revision: 1,
            current_withdrawn: false,
            members_v2: &members,
            group_id: "g-right",
        };
        let err = validate_apply(&ctx, &commit, ActionKind::OwnerOnly).unwrap_err();
        assert!(matches!(err, ApplyError::GroupIdMismatch { .. }));
    }
}
