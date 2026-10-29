//! ADR 0110 §4: `CryptoExclusionV1`, the crypto-only exclusion of an
//! already-Removed target that still has a retained cryptographic leaf.
//!
//! The roster stays Removed. The chain revision and the crypto binding and
//! epoch advance together, in one signed `GroupStateCommit`. There is no
//! admission and no restoration of the seat.
//!
//! This module is pure and I/O-free. It holds:
//!
//! - the frozen v1 wire shape: typed prefix [`CRYPTO_EXCLUSION_PREFIX`]
//!   (`X0XCE1`), an explicit v1 postcard body consumed exactly, and an
//!   outer ML-DSA-65 agent signature in domain
//!   [`CRYPTO_EXCLUSION_SIGNATURE_DOMAIN`] (`x0x.crypto-exclusion.v1`)
//!   over the canonical body, including the crypto payload and the commit
//!   header;
//! - the receiver's L4 acceptance checks ([`validate_against_parent`]);
//! - the D76 hold rule ([`receiver_upgrade_holders`]).
//!
//! The capability that gates every send is `crypto_exclusion_v1`
//! ([`crate::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1`], bit 5). The body
//! never goes inside a container that a released binary decodes, and it is
//! never published on the ungated metadata topic.

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::groups::member::{GroupMemberState, GroupRole};
use crate::groups::state_commit::GroupStateCommit;
use crate::groups::GroupInfo;
use crate::identity::AgentKeypair;

/// The typed direct-message prefix of a `CryptoExclusionV1` frame.
pub const CRYPTO_EXCLUSION_PREFIX: &[u8] = b"X0XCE1";

/// The outer agent-signature domain.
pub const CRYPTO_EXCLUSION_SIGNATURE_DOMAIN: &[u8] = b"x0x.crypto-exclusion.v1";

/// The domain of the removal-proof hash (§4 "roster-removal/self-leave
/// proof hash").
pub const REMOVAL_PROOF_DOMAIN: &[u8] = b"x0x.crypto-exclusion.removal-proof.v1";

/// The frozen v1 mirror of the signed [`GroupStateCommit`] header. It is a
/// separate type so that a later change to the commit's serde shape cannot
/// change this postcard layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitHeaderV1 {
    /// `GroupStateCommit::group_id`.
    pub group_id: String,
    /// `GroupStateCommit::revision`.
    pub revision: u64,
    /// `GroupStateCommit::prev_state_hash`.
    pub prev_state_hash: Option<String>,
    /// `GroupStateCommit::roster_root`.
    pub roster_root: String,
    /// `GroupStateCommit::policy_hash`.
    pub policy_hash: String,
    /// `GroupStateCommit::public_meta_hash`.
    pub public_meta_hash: String,
    /// `GroupStateCommit::security_binding`.
    pub security_binding: Option<String>,
    /// `GroupStateCommit::state_hash`.
    pub state_hash: String,
    /// `GroupStateCommit::withdrawn`.
    pub withdrawn: bool,
    /// `GroupStateCommit::committed_by`.
    pub committed_by: String,
    /// `GroupStateCommit::committed_at`.
    pub committed_at: u64,
    /// `GroupStateCommit::signer_public_key`.
    pub signer_public_key: String,
    /// `GroupStateCommit::signature`.
    pub signature: String,
}

impl From<&GroupStateCommit> for CommitHeaderV1 {
    fn from(commit: &GroupStateCommit) -> Self {
        Self {
            group_id: commit.group_id.clone(),
            revision: commit.revision,
            prev_state_hash: commit.prev_state_hash.clone(),
            roster_root: commit.roster_root.clone(),
            policy_hash: commit.policy_hash.clone(),
            public_meta_hash: commit.public_meta_hash.clone(),
            security_binding: commit.security_binding.clone(),
            state_hash: commit.state_hash.clone(),
            withdrawn: commit.withdrawn,
            committed_by: commit.committed_by.clone(),
            committed_at: commit.committed_at,
            signer_public_key: commit.signer_public_key.clone(),
            signature: commit.signature.clone(),
        }
    }
}

impl CommitHeaderV1 {
    /// The signed commit this header carries.
    #[must_use]
    pub fn to_commit(&self) -> GroupStateCommit {
        GroupStateCommit {
            group_id: self.group_id.clone(),
            revision: self.revision,
            prev_state_hash: self.prev_state_hash.clone(),
            roster_root: self.roster_root.clone(),
            policy_hash: self.policy_hash.clone(),
            public_meta_hash: self.public_meta_hash.clone(),
            security_binding: self.security_binding.clone(),
            state_hash: self.state_hash.clone(),
            withdrawn: self.withdrawn,
            committed_by: self.committed_by.clone(),
            committed_at: self.committed_at,
            signer_public_key: self.signer_public_key.clone(),
            signature: self.signature.clone(),
        }
    }
}

/// The crypto transition of one exclusion (§4: "TreeKEM commit and next
/// epoch or GSS next secret epoch").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoExclusionCryptoV1 {
    /// A TreeKEM removal of the target's retained leaf.
    TreeKem {
        /// The committed `treekem_key_package_hash` of the target's leaf.
        leaf_key_package_hash: String,
        /// The TreeKEM commit bytes.
        commit: Vec<u8>,
        /// The TreeKEM epoch after the commit.
        next_epoch: u64,
    },
    /// One GSS rotation for a grandfathered GSS `MlsEncrypted` group
    /// (§3 L217). The new secret goes to each remaining Active member in
    /// the existing sealed `SecureShareDelivered` envelope, never in this
    /// frame.
    Gss {
        /// The secret epoch after the rotation.
        next_secret_epoch: u64,
    },
}

/// The frozen v1 `CryptoExclusionV1` body. Field order is the postcard
/// layout; a later layout needs a new prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoExclusionBodyV1 {
    /// The group's stable ID.
    pub stable_group_id: String,
    /// The signing admin (raw agent ID).
    pub actor: [u8; 32],
    /// The already-Removed target (raw agent ID).
    pub target: [u8; 32],
    /// The parent head (`state_hash`) this exclusion extends.
    pub prior_head: String,
    /// The parent `state_revision`.
    pub prior_revision: u64,
    /// The `state_revision` after the exclusion (`prior_revision + 1`).
    pub next_revision: u64,
    /// The roster revision after the exclusion (adopted, never lowered).
    pub roster_revision: u64,
    /// [`removal_proof_hash`] of the target's committed Removed entry.
    pub removal_proof_hash: [u8; 32],
    /// The crypto transition.
    pub crypto: CryptoExclusionCryptoV1,
    /// The signed `GroupStateCommit` of the exclusion.
    pub commit: CommitHeaderV1,
}

/// A signed `CryptoExclusionV1` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCryptoExclusionV1 {
    /// The body.
    pub body: CryptoExclusionBodyV1,
    /// ML-DSA-65 signature by `body.actor` over [`signable_bytes`].
    pub signature: Vec<u8>,
}

/// Why a frame or an exclusion is refused. The `snake_case` names are the
/// typed reasons in logs and status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CryptoExclusionRefusal {
    /// Not an `X0XCE1` payload.
    WrongPrefix,
    /// The body did not decode or was not consumed exactly.
    Malformed,
    /// The outer signature or the commit signature does not verify, or the
    /// actor is not the commit signer.
    BadSignature,
    /// The group ID does not match.
    GroupMismatch,
    /// The parent head or revision is not this node's current head.
    HeadMismatch,
    /// The next revision is not exactly the parent revision + 1.
    RevisionMismatch,
    /// The signer is not an Active admin on the parent roster, is the
    /// target, or is revoked.
    ActorIneligible,
    /// The target is not Removed on the parent roster.
    TargetNotRemoved,
    /// The removal-proof hash does not match the committed Removed entry.
    RemovalProofMismatch,
    /// The leaf KeyPackage hash does not match the committed one.
    LeafMismatch,
    /// The next epoch is not exactly the current epoch + 1, or the signed
    /// binding does not name these commit bytes.
    EpochMismatch,
    /// The group is withdrawn or holds a fork-quarantine marker.
    GroupContained,
    /// The parent roster breaks the last-admin invariant.
    LastAdminInvariant,
    /// The crypto plane is not supported by this binary or this group.
    CryptoPlaneUnsupported,
}

impl CryptoExclusionRefusal {
    /// The typed reason string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongPrefix => "wrong_prefix",
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::GroupMismatch => "group_mismatch",
            Self::HeadMismatch => "head_mismatch",
            Self::RevisionMismatch => "revision_mismatch",
            Self::ActorIneligible => "actor_ineligible",
            Self::TargetNotRemoved => "target_not_removed",
            Self::RemovalProofMismatch => "removal_proof_mismatch",
            Self::LeafMismatch => "leaf_mismatch",
            Self::EpochMismatch => "epoch_mismatch",
            Self::GroupContained => "group_contained",
            Self::LastAdminInvariant => "last_admin_invariant",
            Self::CryptoPlaneUnsupported => "crypto_plane_unsupported",
        }
    }
}

impl std::fmt::Display for CryptoExclusionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CryptoExclusionRefusal {}

/// The bytes the outer signature covers: the domain, then the
/// length-prefixed canonical postcard body.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn signable_bytes(body: &CryptoExclusionBodyV1) -> Result<Vec<u8>, postcard::Error> {
    let encoded = postcard::to_stdvec(body)?;
    let mut out = Vec::with_capacity(
        CRYPTO_EXCLUSION_SIGNATURE_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(encoded.len()),
    );
    out.extend_from_slice(CRYPTO_EXCLUSION_SIGNATURE_DOMAIN);
    out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Sign a body with the actor's agent key.
///
/// # Errors
///
/// Returns [`CryptoExclusionRefusal::ActorIneligible`] when the keypair is
/// not the body's actor, [`CryptoExclusionRefusal::Malformed`] when the
/// body does not encode and [`CryptoExclusionRefusal::BadSignature`] when
/// signing fails.
pub fn sign(
    body: CryptoExclusionBodyV1,
    keypair: &AgentKeypair,
) -> Result<SignedCryptoExclusionV1, CryptoExclusionRefusal> {
    if keypair.agent_id().as_bytes() != &body.actor {
        return Err(CryptoExclusionRefusal::ActorIneligible);
    }
    let bytes = signable_bytes(&body).map_err(|_| CryptoExclusionRefusal::Malformed)?;
    let signature = sign_with_ml_dsa(keypair.secret_key(), &bytes)
        .map_err(|_| CryptoExclusionRefusal::BadSignature)?;
    Ok(SignedCryptoExclusionV1 {
        body,
        signature: signature.as_bytes().to_vec(),
    })
}

/// Encode a signed frame as a direct-message payload.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_frame(frame: &SignedCryptoExclusionV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = CRYPTO_EXCLUSION_PREFIX.to_vec();
    out.extend(postcard::to_stdvec(frame)?);
    Ok(out)
}

/// Decode a frame with exact consumption. This checks the shape only; use
/// [`verify_signatures`] and [`validate_against_parent`] before any use.
///
/// # Errors
///
/// Returns why the payload is refused.
pub fn decode_frame(payload: &[u8]) -> Result<SignedCryptoExclusionV1, CryptoExclusionRefusal> {
    let body = payload
        .strip_prefix(CRYPTO_EXCLUSION_PREFIX)
        .ok_or(CryptoExclusionRefusal::WrongPrefix)?;
    let (frame, rest) = postcard::take_from_bytes::<SignedCryptoExclusionV1>(body)
        .map_err(|_| CryptoExclusionRefusal::Malformed)?;
    if !rest.is_empty() {
        return Err(CryptoExclusionRefusal::Malformed);
    }
    Ok(frame)
}

/// Verify the outer signature and the embedded commit's own signature and
/// structure. The commit's signer key derives the actor's agent ID
/// (`GroupStateCommit::verify_structure`), and that same key verifies the
/// outer signature, so the actor signed both.
///
/// # Errors
///
/// Returns [`CryptoExclusionRefusal::BadSignature`] or
/// [`CryptoExclusionRefusal::Malformed`].
pub fn verify_signatures(frame: &SignedCryptoExclusionV1) -> Result<(), CryptoExclusionRefusal> {
    let body = &frame.body;
    let commit = body.commit.to_commit();
    commit
        .verify_structure()
        .map_err(|_| CryptoExclusionRefusal::BadSignature)?;
    if commit.committed_by != hex::encode(body.actor) {
        return Err(CryptoExclusionRefusal::BadSignature);
    }
    let key_bytes =
        hex::decode(&commit.signer_public_key).map_err(|_| CryptoExclusionRefusal::BadSignature)?;
    let key =
        MlDsaPublicKey::from_bytes(&key_bytes).map_err(|_| CryptoExclusionRefusal::BadSignature)?;
    let signature = MlDsaSignature::from_bytes(&frame.signature)
        .map_err(|_| CryptoExclusionRefusal::BadSignature)?;
    let bytes = signable_bytes(body).map_err(|_| CryptoExclusionRefusal::Malformed)?;
    verify_with_ml_dsa(&key, &bytes, &signature).map_err(|_| CryptoExclusionRefusal::BadSignature)
}

/// The TreeKEM security binding a crypto-only exclusion must sign: the
/// epoch and the BLAKE3 digest of the exact commit bytes. The loose
/// `treekem:epoch=<n>` form of the shipped admin removal is not accepted.
#[must_use]
pub fn treekem_binding(epoch: u64, commit: &[u8]) -> String {
    format!(
        "treekem:epoch={epoch}:commit={}",
        blake3::hash(commit).to_hex()
    )
}

/// The removal-proof hash of the target's committed Removed entry. It
/// uses only fields the signed roster root covers (not the local
/// `updated_at` clock), so every node on the same head computes the same
/// value. With the parent head it binds the exclusion to that exact
/// removal and leaf incarnation.
#[must_use]
pub fn removal_proof_hash(
    stable_group_id: &str,
    target_hex: &str,
    removed_by: Option<&str>,
    leaf_key_package_hash: Option<&str>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REMOVAL_PROOF_DOMAIN);
    for part in [
        stable_group_id,
        target_hex,
        removed_by.unwrap_or(""),
        leaf_key_package_hash.unwrap_or(""),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// [`removal_proof_hash`] of `target_hex` on `info`'s committed roster;
/// `None` when the target is not Removed there.
#[must_use]
pub fn removal_proof_for(info: &GroupInfo, target_hex: &str) -> Option<[u8; 32]> {
    let member = info.members_v2.get(target_hex)?;
    (member.state == GroupMemberState::Removed).then(|| {
        removal_proof_hash(
            info.stable_group_id(),
            target_hex,
            member.removed_by.as_deref(),
            member.treekem_key_package_hash.as_deref(),
        )
    })
}

/// The GSS security binding of secret epoch `epoch` (as
/// [`GroupInfo::rotate_shared_secret`] writes it).
pub use crate::groups::owner_recovery::gss_binding;

fn gss_epoch_of(binding: Option<&str>) -> Option<u64> {
    binding?.strip_prefix("gss:epoch=")?.parse().ok()
}

/// The membership incarnation of `target_hex` in `info` (ADR 0110 §1: "an
/// old exclusion never certifies a new leaf"). S4 binds each obligation
/// row to it, so the departure of a later seat reopens completed work and
/// a replay of the old departure does not (#1508 review, Codex P1).
///
/// It is the admitted TreeKEM KeyPackage hash when the roster holds one.
/// A GSS or legacy seat has no leaf, so it is the state hash of the
/// commit that opened the target's newest seat: the oldest retained
/// commit of the newest run of retained commits that seat it (Active or
/// Pending). A rejoin opens a new run, so it is a new incarnation. `None`
/// when no retained commit seats the target.
#[must_use]
pub fn seat_incarnation(info: &GroupInfo, target_hex: &str) -> Option<String> {
    if let Some(hash) = info
        .members_v2
        .get(target_hex)
        .and_then(|member| member.treekem_key_package_hash.clone())
    {
        return Some(hash);
    }
    let seated = |retained: &&crate::groups::state_commit::RetainedCommit| {
        retained.roster.get(target_hex).is_some_and(|seat| {
            matches!(
                seat.state,
                GroupMemberState::Active | GroupMemberState::Pending
            )
        })
    };
    info.commit_log
        .iter()
        .rev()
        .skip_while(|retained| !seated(retained))
        .take_while(seated)
        .last()
        .map(|opened| format!("seat:{}", opened.commit.state_hash))
}

/// Whether `info` is a GSS `MlsEncrypted` group: the plane of the GSS
/// form of this exclusion.
#[must_use]
pub fn is_gss_encrypted(info: &GroupInfo) -> bool {
    info.secure_plane == crate::mls::SecureGroupPlane::Gss
        && info.policy.confidentiality == crate::groups::GroupConfidentiality::MlsEncrypted
}

/// The secret epoch that `info`'s current head commits to: the binding of
/// the retained head commit. A sealed share can raise the local
/// `secret_epoch` before the commit of that epoch arrives, so the L4 rule
/// uses this value, not the local one. Falls back to `secret_epoch` when
/// the head commit is not retained.
#[must_use]
pub fn committed_secret_epoch(info: &GroupInfo) -> u64 {
    info.commit_log
        .iter()
        .rev()
        .find(|retained| retained.commit.state_hash == info.state_hash)
        .and_then(|retained| gss_epoch_of(retained.commit.security_binding.as_deref()))
        .unwrap_or(info.secret_epoch)
}

/// The GSS form of a "retained cryptographic leaf" (§1, §3 L217): a
/// Removed member of a GSS `MlsEncrypted` group that still holds the
/// current secret. That is true when no rotation followed the last
/// retained commit that seated it as Active: the secret epoch of that
/// commit is not below the epoch the current head commits to. A removal
/// that rotated in its own commit (admin remove, ban) is not retained.
///
/// A member with no retained seated commit is not retained: this node did
/// not witness its seat, so it cannot prove which secret the member holds.
/// This rule opens work only on proof. Open work completes only on the
/// opposite proof ([`gss_secret_excluded`]).
#[must_use]
pub fn gss_secret_retained(info: &GroupInfo, target_hex: &str) -> bool {
    gss_secret_hold(info, target_hex) == Some(true)
}

/// The GSS completion proof (§1, D128): the retained commits show that a
/// rotation followed the departure of `target_hex`, so it no longer holds
/// the current secret. Open work completes only on this proof, never on
/// missing evidence. The commit log is bounded
/// ([`crate::groups::COMMIT_LOG_CAP`]): while a D76 hold waits, later
/// commits that do not rotate can trim the commit that seated the target.
/// That loss is not a rotation, so the work stays open and the exclusion
/// still runs (#1508 review, Codex P1).
///
/// True for a target that is not Removed (Banned rotates in its own
/// commit), and for a group that is not GSS `MlsEncrypted`.
#[must_use]
pub fn gss_secret_excluded(info: &GroupInfo, target_hex: &str) -> bool {
    gss_secret_hold(info, target_hex) == Some(false)
}

fn is_removed(info: &GroupInfo, target_hex: &str) -> bool {
    info.members_v2
        .get(target_hex)
        .is_some_and(|member| member.state == GroupMemberState::Removed)
}

/// Whether the Removed `target_hex` of a GSS `MlsEncrypted` group holds
/// the current secret: `Some(true)` retained, `Some(false)` a rotation
/// followed its departure, `None` the retained commits cannot tell.
///
/// The newest retained commit that seats the target as Active decides:
/// its secret epoch is the newest secret the target received. When no
/// retained commit seats it, a retained commit below the current epoch
/// still proves a later rotation, because the target was not seated at
/// that commit. Otherwise the commit that seated it was trimmed or never
/// witnessed (`None`).
fn gss_secret_hold(info: &GroupInfo, target_hex: &str) -> Option<bool> {
    if !is_gss_encrypted(info) || info.withdrawn || !is_removed(info, target_hex) {
        return Some(false);
    }
    let current = committed_secret_epoch(info);
    let seated = info.commit_log.iter().rev().find(|retained| {
        retained
            .roster
            .get(target_hex)
            .is_some_and(|seat| seat.state == GroupMemberState::Active)
    });
    if let Some(seated) = seated {
        return gss_epoch_of(seated.commit.security_binding.as_deref())
            .map(|seated_epoch| seated_epoch >= current);
    }
    info.commit_log
        .iter()
        .filter_map(|retained| gss_epoch_of(retained.commit.security_binding.as_deref()))
        .any(|epoch| epoch < current)
        .then_some(false)
}

/// ADR 0110 §2 (#1508 rc18): the checks this node can make on an
/// exclusion that does not chain on its head `latest` yet, before the
/// exclusion may count as known higher-head evidence. The caller verified
/// both signatures ([`verify_signatures`]). The actor must have standing
/// on `latest` (an Active admin that is not the target; the caller checks
/// that the actor is not revoked), and
/// the target must have a seat there. An exclusion that fails stays
/// unverified: it is kept for a retry but holds nothing.
///
/// # Errors
///
/// The [`CryptoExclusionRefusal`] of the first check that fails.
pub fn check_ahead(
    body: &CryptoExclusionBodyV1,
    latest: &GroupInfo,
) -> Result<(), CryptoExclusionRefusal> {
    if body.stable_group_id != latest.stable_group_id()
        || body.commit.group_id != latest.stable_group_id()
    {
        return Err(CryptoExclusionRefusal::GroupMismatch);
    }
    if body.actor == body.target
        || !latest
            .members_v2
            .get(&hex::encode(body.actor))
            .is_some_and(|member| {
                member.state == GroupMemberState::Active && member.role.at_least(GroupRole::Admin)
            })
    {
        return Err(CryptoExclusionRefusal::ActorIneligible);
    }
    // #1578 rc11 (audit): the join's key-only marker row is not a seat
    // — the target reads as absent, exactly main's roster, where the
    // pre-admission joiner holds no row.
    let target_hex = hex::encode(body.target);
    if !latest.members_v2.contains_key(&target_hex) || latest.join_seat_key_marker_only(&target_hex)
    {
        return Err(CryptoExclusionRefusal::TargetNotRemoved);
    }
    Ok(())
}

/// The receiver's L4 checks against its current verified parent state
/// (§4, L249): an Active Admin-or-higher signer that is not the target, the
/// chained prior removal, the target/leaf binding, the exact next revision
/// and epoch, unchanged membership, the last-admin invariant and
/// containment. `current_epoch` is this node's TreeKEM epoch, or for the
/// GSS form the [`committed_secret_epoch`] of the parent.
///
/// `is_actor_revoked` is this node's current agent-revocation set (§3
/// enforcement point 4). The check is part of the acceptance rule, so no
/// caller can accept a frame a revoked admin signed. A caller holds the
/// group's membership lock and calls this immediately before it applies
/// the commit (§3 L231).
///
/// The embedded commit must still pass the ordinary `validate_apply` and
/// `finalize_applied_commit` checks (signature, parent-roster authority,
/// prev-hash, revocation, fork); they recompute the post-state hash from
/// the unchanged roster, so a commit that changes membership, policy or
/// metadata fails there. The cryptographic removal proof (the leaf is gone
/// after the TreeKEM commit) is checked by the caller after it processes
/// the commit on a copy of its tree.
///
/// # Errors
///
/// Returns the first failed check.
pub fn validate_against_parent(
    body: &CryptoExclusionBodyV1,
    parent: &GroupInfo,
    current_epoch: u64,
    is_actor_revoked: impl Fn(&[u8; 32]) -> bool,
) -> Result<(), CryptoExclusionRefusal> {
    if body.stable_group_id != parent.stable_group_id()
        || body.commit.group_id != parent.stable_group_id()
    {
        return Err(CryptoExclusionRefusal::GroupMismatch);
    }
    if parent.withdrawn || parent.fork_quarantine.is_some() || body.commit.withdrawn {
        return Err(CryptoExclusionRefusal::GroupContained);
    }
    if body.prior_head != parent.state_hash
        || body.prior_revision != parent.state_revision
        || body.commit.prev_state_hash.as_deref() != Some(parent.state_hash.as_str())
    {
        return Err(CryptoExclusionRefusal::HeadMismatch);
    }
    if body.next_revision != parent.state_revision.saturating_add(1)
        || body.commit.revision != body.next_revision
    {
        return Err(CryptoExclusionRefusal::RevisionMismatch);
    }
    let actor_hex = hex::encode(body.actor);
    let target_hex = hex::encode(body.target);
    if body.actor == body.target
        || is_actor_revoked(&body.actor)
        || !parent.members_v2.get(&actor_hex).is_some_and(|member| {
            member.state == GroupMemberState::Active && member.role.at_least(GroupRole::Admin)
        })
    {
        return Err(CryptoExclusionRefusal::ActorIneligible);
    }
    let Some(target) = parent.members_v2.get(&target_hex) else {
        return Err(CryptoExclusionRefusal::TargetNotRemoved);
    };
    if target.state != GroupMemberState::Removed {
        return Err(CryptoExclusionRefusal::TargetNotRemoved);
    }
    if removal_proof_for(parent, &target_hex) != Some(body.removal_proof_hash) {
        return Err(CryptoExclusionRefusal::RemovalProofMismatch);
    }
    crate::groups::state_commit::enforce_last_admin_invariant(&parent.members_v2, false)
        .map_err(|_| CryptoExclusionRefusal::LastAdminInvariant)?;
    match &body.crypto {
        CryptoExclusionCryptoV1::TreeKem {
            leaf_key_package_hash,
            commit,
            next_epoch,
        } => {
            if parent.secure_plane != crate::mls::SecureGroupPlane::TreeKem {
                return Err(CryptoExclusionRefusal::CryptoPlaneUnsupported);
            }
            if target.treekem_key_package_hash.as_deref() != Some(leaf_key_package_hash.as_str()) {
                return Err(CryptoExclusionRefusal::LeafMismatch);
            }
            if *next_epoch != current_epoch.saturating_add(1)
                || body.commit.security_binding.as_deref()
                    != Some(treekem_binding(*next_epoch, commit).as_str())
            {
                return Err(CryptoExclusionRefusal::EpochMismatch);
            }
            Ok(())
        }
        CryptoExclusionCryptoV1::Gss { next_secret_epoch } => {
            if !is_gss_encrypted(parent) {
                return Err(CryptoExclusionRefusal::CryptoPlaneUnsupported);
            }
            if *next_secret_epoch != current_epoch.saturating_add(1)
                || body.commit.security_binding.as_deref()
                    != Some(gss_binding(*next_secret_epoch).as_str())
            {
                return Err(CryptoExclusionRefusal::EpochMismatch);
            }
            Ok(())
        }
    }
}

/// The D76 hold rule (§4 L253, §6 "Hold"): the survivors whose current
/// verified advert lacks `crypto_exclusion_v1` (`Some(false)`). Unknown or
/// expired support (`None`) and offline survivors do not hold the commit;
/// they are stranded until they upgrade. Returns the holders in raw-ID
/// order; an empty result means the commit may proceed.
#[must_use]
pub fn receiver_upgrade_holders(
    survivors: impl IntoIterator<Item = ([u8; 32], Option<bool>)>,
) -> Vec<[u8; 32]> {
    let mut holders: Vec<[u8; 32]> = survivors
        .into_iter()
        .filter(|(_, supports)| *supports == Some(false))
        .map(|(id, _)| id)
        .collect();
    holders.sort_unstable();
    holders.dedup();
    holders
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::member::GroupMember;

    fn keypair() -> AgentKeypair {
        AgentKeypair::generate().expect("keypair")
    }

    fn treekem_group(admin: &AgentKeypair, target: [u8; 32]) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            admin.agent_id(),
            "ab".repeat(16),
        );
        info.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
        let target_hex = hex::encode(target);
        let mut member = GroupMember::new_member(
            target_hex.clone(),
            None,
            Some(hex::encode(admin.agent_id().as_bytes())),
            1,
        );
        member.treekem_key_package_hash = Some("kp-hash".to_string());
        info.members_v2.insert(target_hex.clone(), member);
        info.remove_member(&target_hex, Some(target_hex.clone()));
        info.recompute_state_hash();
        info
    }

    fn body_for(
        info: &GroupInfo,
        admin: &AgentKeypair,
        target: [u8; 32],
        epoch: u64,
    ) -> CryptoExclusionBodyV1 {
        let commit_bytes = vec![7u8; 40];
        let next_epoch = epoch + 1;
        let mut next = info.clone();
        next.secret_epoch = next_epoch;
        next.security_binding = Some(treekem_binding(next_epoch, &commit_bytes));
        let commit = next.seal_commit(admin, 1_000).expect("seal");
        CryptoExclusionBodyV1 {
            stable_group_id: info.stable_group_id().to_string(),
            actor: *admin.agent_id().as_bytes(),
            target,
            prior_head: info.state_hash.clone(),
            prior_revision: info.state_revision,
            next_revision: info.state_revision + 1,
            roster_revision: info.roster_revision + 1,
            removal_proof_hash: removal_proof_for(info, &hex::encode(target)).expect("removed"),
            crypto: CryptoExclusionCryptoV1::TreeKem {
                leaf_key_package_hash: "kp-hash".to_string(),
                commit: commit_bytes,
                next_epoch,
            },
            commit: CommitHeaderV1::from(&commit),
        }
    }

    #[test]
    fn frame_round_trips_and_verifies() {
        let admin = keypair();
        let target = [9u8; 32];
        let info = treekem_group(&admin, target);
        let frame = sign(body_for(&info, &admin, target, 3), &admin).expect("sign");
        let bytes = encode_frame(&frame).expect("encode");
        assert!(bytes.starts_with(CRYPTO_EXCLUSION_PREFIX));
        let decoded = decode_frame(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        verify_signatures(&decoded).expect("signatures");
        validate_against_parent(&decoded.body, &info, 3, |_| false).expect("valid");
    }

    #[test]
    fn decode_requires_exact_consumption_and_prefix() {
        let admin = keypair();
        let target = [9u8; 32];
        let info = treekem_group(&admin, target);
        let frame = sign(body_for(&info, &admin, target, 0), &admin).expect("sign");
        let mut bytes = encode_frame(&frame).expect("encode");
        bytes.push(0);
        assert_eq!(decode_frame(&bytes), Err(CryptoExclusionRefusal::Malformed));
        assert_eq!(
            decode_frame(b"X0XEVH1rest"),
            Err(CryptoExclusionRefusal::WrongPrefix)
        );
        assert_eq!(
            decode_frame(b"X0XCE1"),
            Err(CryptoExclusionRefusal::Malformed)
        );
    }

    #[test]
    fn tampered_body_fails_the_outer_signature() {
        let admin = keypair();
        let target = [9u8; 32];
        let info = treekem_group(&admin, target);
        let mut frame = sign(body_for(&info, &admin, target, 0), &admin).expect("sign");
        frame.body.roster_revision += 1;
        assert_eq!(
            verify_signatures(&frame),
            Err(CryptoExclusionRefusal::BadSignature)
        );
    }

    #[test]
    fn other_key_cannot_sign_for_the_actor() {
        let admin = keypair();
        let other = keypair();
        let target = [9u8; 32];
        let info = treekem_group(&admin, target);
        let body = body_for(&info, &admin, target, 0);
        assert_eq!(
            sign(body, &other).err(),
            Some(CryptoExclusionRefusal::ActorIneligible)
        );
    }

    #[test]
    fn parent_checks_refuse_each_violation() {
        let admin = keypair();
        let target = [9u8; 32];
        let info = treekem_group(&admin, target);
        let good = body_for(&info, &admin, target, 2);
        assert!(validate_against_parent(&good, &info, 2, |_| false).is_ok());
        assert_eq!(
            validate_against_parent(&good, &info, 3, |_| false),
            Err(CryptoExclusionRefusal::EpochMismatch)
        );
        let mut stale = good.clone();
        stale.prior_head = "other".to_string();
        assert_eq!(
            validate_against_parent(&stale, &info, 2, |_| false),
            Err(CryptoExclusionRefusal::HeadMismatch)
        );
        let mut proof = good.clone();
        proof.removal_proof_hash = [0u8; 32];
        assert_eq!(
            validate_against_parent(&proof, &info, 2, |_| false),
            Err(CryptoExclusionRefusal::RemovalProofMismatch)
        );
        let mut leaf = good.clone();
        if let CryptoExclusionCryptoV1::TreeKem {
            leaf_key_package_hash,
            ..
        } = &mut leaf.crypto
        {
            *leaf_key_package_hash = "other".to_string();
        }
        assert_eq!(
            validate_against_parent(&leaf, &info, 2, |_| false),
            Err(CryptoExclusionRefusal::LeafMismatch)
        );
        let mut self_signed = good.clone();
        self_signed.actor = target;
        assert_eq!(
            validate_against_parent(&self_signed, &info, 2, |_| false),
            Err(CryptoExclusionRefusal::ActorIneligible)
        );
        let mut gss = good.clone();
        gss.crypto = CryptoExclusionCryptoV1::Gss {
            next_secret_epoch: 1,
        };
        assert_eq!(
            validate_against_parent(&gss, &info, 2, |_| false),
            Err(CryptoExclusionRefusal::CryptoPlaneUnsupported)
        );
        let mut quarantined = info.clone();
        quarantined.withdrawn = true;
        assert_eq!(
            validate_against_parent(&good, &quarantined, 2, |_| false),
            Err(CryptoExclusionRefusal::GroupContained)
        );
    }

    /// A GSS group in which `target` was seated at secret epoch 0 (a
    /// retained commit holds that roster) and then self-left.
    fn gss_group(admin: &AgentKeypair, target: [u8; 32]) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            admin.agent_id(),
            "cd".repeat(16),
        );
        let target_hex = hex::encode(target);
        info.add_member(
            target_hex.clone(),
            GroupRole::Member,
            Some(hex::encode(admin.agent_id().as_bytes())),
            None,
        );
        info.seal_commit(admin, 500).expect("seat");
        info.remove_member(&target_hex, Some(target_hex.clone()));
        info.recompute_state_hash();
        info
    }

    fn gss_body_for(
        info: &GroupInfo,
        admin: &AgentKeypair,
        target: [u8; 32],
        next_secret_epoch: u64,
    ) -> CryptoExclusionBodyV1 {
        let mut next = info.clone();
        next.secret_epoch = next_secret_epoch;
        next.security_binding = Some(gss_binding(next_secret_epoch));
        let commit = next.seal_commit(admin, 1_000).expect("seal");
        CryptoExclusionBodyV1 {
            stable_group_id: info.stable_group_id().to_string(),
            actor: *admin.agent_id().as_bytes(),
            target,
            prior_head: info.state_hash.clone(),
            prior_revision: info.state_revision,
            next_revision: info.state_revision + 1,
            roster_revision: info.roster_revision + 1,
            removal_proof_hash: removal_proof_for(info, &hex::encode(target)).expect("removed"),
            crypto: CryptoExclusionCryptoV1::Gss { next_secret_epoch },
            commit: CommitHeaderV1::from(&commit),
        }
    }

    /// #1508 review P1 (GSS self-leave): the GSS form of §4 is accepted on
    /// a GSS group for an already-Removed target when the next secret
    /// epoch is exactly the committed epoch + 1 and the signed binding
    /// names it. Each violation is refused with its typed reason.
    #[test]
    fn gss_frame_is_accepted_and_each_violation_refused() {
        let admin = keypair();
        let target = [9u8; 32];
        let info = gss_group(&admin, target);
        let good = gss_body_for(&info, &admin, target, 1);
        assert_eq!(validate_against_parent(&good, &info, 0, |_| false), Ok(()));
        let frame = sign(good.clone(), &admin).expect("sign");
        let decoded = decode_frame(&encode_frame(&frame).expect("encode")).expect("decode");
        verify_signatures(&decoded).expect("signatures");
        // The next epoch is not the committed epoch + 1.
        assert_eq!(
            validate_against_parent(&good, &info, 1, |_| false),
            Err(CryptoExclusionRefusal::EpochMismatch)
        );
        let skipped = gss_body_for(&info, &admin, target, 2);
        assert_eq!(
            validate_against_parent(&skipped, &info, 0, |_| false),
            Err(CryptoExclusionRefusal::EpochMismatch)
        );
        // The signed binding does not name the next epoch.
        let mut unbound = good.clone();
        unbound.crypto = CryptoExclusionCryptoV1::Gss {
            next_secret_epoch: 1,
        };
        unbound.commit.security_binding = Some("gss:epoch=7".to_string());
        assert_eq!(
            validate_against_parent(&unbound, &info, 0, |_| false),
            Err(CryptoExclusionRefusal::EpochMismatch)
        );
        // The target is seated on the parent.
        let mut seated = info.clone();
        if let Some(member) = seated.members_v2.get_mut(&hex::encode(target)) {
            member.state = GroupMemberState::Active;
        }
        assert_eq!(
            validate_against_parent(&good, &seated, 0, |_| false),
            Err(CryptoExclusionRefusal::TargetNotRemoved)
        );
        // A GSS transition on a TreeKEM group, and on a SignedPublic group.
        let mut treekem = info.clone();
        treekem.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
        assert_eq!(
            validate_against_parent(&good, &treekem, 0, |_| false),
            Err(CryptoExclusionRefusal::CryptoPlaneUnsupported)
        );
        let mut public = info.clone();
        public.policy.confidentiality = crate::groups::GroupConfidentiality::SignedPublic;
        assert_eq!(
            validate_against_parent(&good, &public, 0, |_| false),
            Err(CryptoExclusionRefusal::CryptoPlaneUnsupported)
        );
    }

    /// #1508 review P1: the GSS "retained leaf". A self-leaver keeps the
    /// secret until a later commit rotates it; a removal that rotated in
    /// its own commit never retains it.
    #[test]
    fn gss_self_leaver_retains_the_secret_until_a_rotation() {
        let admin = keypair();
        let target = [9u8; 32];
        let target_hex = hex::encode(target);
        let mut info = gss_group(&admin, target);
        info.seal_commit(&admin, 600).expect("leave");
        assert!(gss_secret_retained(&info, &target_hex));
        assert_eq!(committed_secret_epoch(&info), 0);
        // A share raises the local epoch before its commit: still retained.
        info.secret_epoch = 1;
        assert_eq!(committed_secret_epoch(&info), 0);
        assert!(gss_secret_retained(&info, &target_hex));
        info.secret_epoch = 0;
        let _ = info.rotate_shared_secret();
        info.seal_commit(&admin, 700).expect("rotate");
        assert_eq!(committed_secret_epoch(&info), 1);
        assert!(!gss_secret_retained(&info, &target_hex));

        // An admin removal that rotates in its own commit.
        let other = [8u8; 32];
        let other_hex = hex::encode(other);
        info.add_member(other_hex.clone(), GroupRole::Member, None, None);
        info.seal_commit(&admin, 800).expect("seat");
        info.remove_member(&other_hex, Some(hex::encode(admin.agent_id().as_bytes())));
        let _ = info.rotate_shared_secret();
        info.seal_commit(&admin, 900).expect("remove");
        assert!(!gss_secret_retained(&info, &other_hex));
        // TreeKEM groups use their tree, not this rule.
        let mut treekem = gss_group(&admin, target);
        treekem.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
        assert!(!gss_secret_retained(&treekem, &target_hex));
    }

    /// #1508 review (Codex P1 on 50b6531): bounded history is not a
    /// rotation. Once later commits without a rotation trim the seat of a
    /// self-leaver, the node can prove neither that it holds the secret
    /// nor that a rotation excluded it. A rotation after that is proof.
    #[test]
    fn gss_trimmed_seat_is_not_proof_of_exclusion() {
        let admin = keypair();
        let target = [9u8; 32];
        let target_hex = hex::encode(target);
        let mut info = gss_group(&admin, target);
        info.seal_commit(&admin, 600).expect("leave");
        assert!(gss_secret_retained(&info, &target_hex));
        assert!(!gss_secret_excluded(&info, &target_hex));
        for at in 0..=crate::groups::COMMIT_LOG_CAP as u64 {
            info.seal_commit(&admin, 700 + at).expect("later commit");
        }
        assert_eq!(info.secret_epoch, 0, "no rotation");
        assert!(!gss_secret_retained(&info, &target_hex));
        assert!(
            !gss_secret_excluded(&info, &target_hex),
            "trimmed history must not prove exclusion"
        );
        let _ = info.rotate_shared_secret();
        info.seal_commit(&admin, 10_000).expect("rotate");
        assert!(!gss_secret_retained(&info, &target_hex));
        assert!(gss_secret_excluded(&info, &target_hex));
        // A seated target is outside this rule: the seat decides first.
        let mut seated = info.clone();
        if let Some(member) = seated.members_v2.get_mut(&target_hex) {
            member.state = GroupMemberState::Active;
        }
        assert!(gss_secret_excluded(&seated, &target_hex));
    }

    #[test]
    fn revoked_actor_is_refused() {
        let admin = keypair();
        let target = [9u8; 32];
        let info = treekem_group(&admin, target);
        let good = body_for(&info, &admin, target, 2);
        let actor = good.actor;
        assert_eq!(
            validate_against_parent(&good, &info, 2, |id| *id == actor),
            Err(CryptoExclusionRefusal::ActorIneligible)
        );
        assert!(validate_against_parent(&good, &info, 2, |id| *id == target).is_ok());
    }

    #[test]
    fn seated_target_is_refused() {
        let admin = keypair();
        let target = [9u8; 32];
        let mut info = treekem_group(&admin, target);
        let good = body_for(&info, &admin, target, 0);
        if let Some(member) = info.members_v2.get_mut(&hex::encode(target)) {
            member.state = GroupMemberState::Active;
        }
        assert_eq!(
            validate_against_parent(&good, &info, 0, |_| false),
            Err(CryptoExclusionRefusal::TargetNotRemoved)
        );
    }

    #[test]
    fn only_known_lacking_adverts_hold() {
        let holders = receiver_upgrade_holders([
            ([3u8; 32], Some(false)),
            ([1u8; 32], Some(true)),
            ([2u8; 32], None),
            ([0u8; 32], Some(false)),
        ]);
        assert_eq!(holders, vec![[0u8; 32], [3u8; 32]]);
        assert!(receiver_upgrade_holders([([1u8; 32], None)]).is_empty());
    }

    #[test]
    fn removal_proof_binds_the_removal_and_the_leaf() {
        let base = removal_proof_hash("g", "t", Some("t"), Some("kp"));
        assert_ne!(base, removal_proof_hash("g2", "t", Some("t"), Some("kp")));
        assert_ne!(base, removal_proof_hash("g", "t", Some("a"), Some("kp")));
        assert_ne!(base, removal_proof_hash("g", "t", Some("t"), Some("kp2")));
        assert_eq!(base, removal_proof_hash("g", "t", Some("t"), Some("kp")));
    }
}
