//! ADR 0110 §4b(1): owner recovery of an `OwnerCertified` group (Home
//! included) whose admins are all revoked.
//!
//! - **Mandate.** The group's owner signs [`OwnerRecoveryMandateBodyV1`]
//!   with user key U, in domain [`OWNER_RECOVERY_MANDATE_DOMAIN`]
//!   (`x0x.owner-recovery.v1`). It names the group ID, the parent head it
//!   applies to, each revoked admin with the hashes of its verified
//!   revocation records, and one promoted member with its committed
//!   certificate digest.
//! - **Commit.** The promoted member authors one chained
//!   [`OwnerRecoveryBodyV1`] commit under the mandate. It removes each
//!   revoked admin's seat (with its TreeKEM leaf, with one GSS rotation,
//!   or the roster seat alone in a `SignedPublic` group) and sets the
//!   promoted member's role to Admin. Nothing else changes. An outer
//!   ML-DSA-65 agent signature in domain [`OWNER_RECOVERY_COMMIT_DOMAIN`]
//!   covers the canonical body, which embeds the mandate.
//! - **Wire.** Both travel on the direct-message carrier with the typed
//!   prefix [`OWNER_RECOVERY_PREFIX`] (`X0XORC1`), as an explicit v1
//!   postcard [`OwnerRecoveryFrameV1`] consumed exactly, gated on
//!   `owner_recovery_v1` ([`crate::dm::CapabilityRegistry::OWNER_RECOVERY_V1`],
//!   bit 7). The frame never goes inside a container that a released binary
//!   decodes, and it carries no class-K material.
//! - **Acceptance** ([`validate_against_parent`]) is a new L4 rule, a named
//!   exception to ADR 0016 Decisions 1 and 2 scoped to this commit kind:
//!   the signer is the promoted member, not an admin on the parent roster.
//!   Every other commit kind is checked exactly as before.
//!
//! This module is pure and I/O-free.

use std::collections::{BTreeMap, BTreeSet};

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::groups::crypto_exclusion::CommitHeaderV1;
use crate::groups::member::{GroupMemberState, GroupRole};
use crate::groups::policy::GroupConfidentiality;
use crate::groups::GroupInfo;
use crate::identity::{AgentCertificate, AgentKeypair, UserId, UserKeypair};

/// The typed direct-message prefix of every owner-recovery frame.
pub const OWNER_RECOVERY_PREFIX: &[u8] = b"X0XORC1";

/// The owner (user key U) signature domain of the mandate.
pub const OWNER_RECOVERY_MANDATE_DOMAIN: &[u8] = b"x0x.owner-recovery.v1";

/// The promoted member's outer agent-signature domain of the commit.
pub const OWNER_RECOVERY_COMMIT_DOMAIN: &[u8] = b"x0x.owner-recovery.commit.v1";

/// One revoked admin named by a mandate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedAdminV1 {
    /// The admin's raw agent ID.
    pub agent: [u8; 32],
    /// The hashes of its verified Agent-subject revocation records, sorted.
    pub revocation_hashes: Vec<[u8; 32]>,
}

/// The frozen v1 mandate body. Field order is the postcard layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerRecoveryMandateBodyV1 {
    /// The group's stable ID.
    pub stable_group_id: String,
    /// The parent head (`state_hash`) the mandate applies to.
    pub parent_head: String,
    /// The parent `state_revision`.
    pub parent_revision: u64,
    /// Every revoked Admin-or-higher Active seat, sorted by agent ID.
    pub revoked_admins: Vec<RevokedAdminV1>,
    /// The promoted member (raw agent ID).
    pub promoted: [u8; 32],
    /// The promoted member's committed certificate digest (hex).
    pub promoted_certificate_digest: String,
    /// The owner's ML-DSA-65 user public key (U).
    pub owner_public_key: Vec<u8>,
    /// When the owner signed (Unix ms). Informational.
    pub issued_at_ms: u64,
}

/// A mandate signed by the owner's user key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOwnerRecoveryMandateV1 {
    /// The body.
    pub body: OwnerRecoveryMandateBodyV1,
    /// ML-DSA-65 signature by U over [`mandate_signable_bytes`].
    pub signature: Vec<u8>,
}

/// One removed seat of the commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedSeatV1 {
    /// The revoked admin (raw agent ID).
    pub agent: [u8; 32],
    /// Its committed `treekem_key_package_hash` (TreeKEM groups only).
    pub leaf_key_package_hash: Option<String>,
}

/// The crypto transition of the commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerRecoveryCryptoV1 {
    /// One TreeKEM removal commit per removed leaf, in [`OwnerRecoveryBodyV1::removed`]
    /// order; each advances the epoch by one.
    TreeKem {
        /// The TreeKEM commit bytes, in order.
        commits: Vec<Vec<u8>>,
        /// The TreeKEM epoch after the last commit.
        next_epoch: u64,
    },
    /// One GSS rotation in a grandfathered GSS `MlsEncrypted` group. The
    /// new secret reaches each survivor in a guarded envelope (D60).
    Gss {
        /// The secret epoch after the rotation.
        next_secret_epoch: u64,
    },
    /// A `SignedPublic` group: the roster seat alone.
    SignedPublic,
}

/// The frozen v1 `OwnerRecoveryV1` commit body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerRecoveryBodyV1 {
    /// The group's stable ID.
    pub stable_group_id: String,
    /// The signer: the promoted member (raw agent ID).
    pub actor: [u8; 32],
    /// The parent head this commit extends.
    pub prior_head: String,
    /// The parent `state_revision`.
    pub prior_revision: u64,
    /// The `state_revision` after the commit (`prior_revision + 1`).
    pub next_revision: u64,
    /// The roster revision after the commit (adopted, never lowered).
    pub roster_revision: u64,
    /// The embedded owner mandate.
    pub mandate: SignedOwnerRecoveryMandateV1,
    /// The promoted member's selected certificate (bincode bytes), so
    /// every receiver can verify it against U.
    pub promoted_certificate: Vec<u8>,
    /// The removed seats, in the mandate's order.
    pub removed: Vec<RemovedSeatV1>,
    /// The crypto transition.
    pub crypto: OwnerRecoveryCryptoV1,
    /// The signed `GroupStateCommit`.
    pub commit: CommitHeaderV1,
}

/// A signed `OwnerRecoveryV1` commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOwnerRecoveryV1 {
    /// The body.
    pub body: OwnerRecoveryBodyV1,
    /// ML-DSA-65 signature by `body.actor` over [`commit_signable_bytes`].
    pub signature: Vec<u8>,
}

/// One `X0XORC1` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerRecoveryFrameV1 {
    /// The owner's mandate, sent to the promoted member.
    Mandate(SignedOwnerRecoveryMandateV1),
    /// The promoted member's commit, sent to the survivors.
    Commit(Box<SignedOwnerRecoveryV1>),
}

/// Why a frame, a mandate or a commit is refused. The `snake_case` names
/// are the typed reasons; the last six are the §4b(1) refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRecoveryRefusal {
    /// Not an `X0XORC1` payload.
    WrongPrefix,
    /// The frame did not decode or was not consumed exactly.
    Malformed,
    /// An eligible admin exists on the parent roster (by this node's
    /// verified revocation records).
    RecoveryNotNeeded,
    /// The mandate or the commit does not apply to this node's head.
    RecoveryHeadMismatch,
    /// The mandate is not signed by the group policy's owner U.
    RecoverySignerNotOwner,
    /// The promoted member is not Active, is revoked or banned, did not
    /// sign the commit, or lacks an unexpired certificate that verifies
    /// against U.
    RecoveryMemberIneligible,
    /// The named admins, the removed seats, the crypto removal proof or
    /// the post-state do not match.
    RecoveryProofInvalid,
    /// The group is withdrawn or holds an ADR 0064 quarantine marker.
    RecoveryGroupQuarantined,
}

impl OwnerRecoveryRefusal {
    /// The typed reason string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongPrefix => "wrong_prefix",
            Self::Malformed => "malformed",
            Self::RecoveryNotNeeded => "recovery_not_needed",
            Self::RecoveryHeadMismatch => "recovery_head_mismatch",
            Self::RecoverySignerNotOwner => "recovery_signer_not_owner",
            Self::RecoveryMemberIneligible => "recovery_member_ineligible",
            Self::RecoveryProofInvalid => "recovery_proof_invalid",
            Self::RecoveryGroupQuarantined => "recovery_group_quarantined",
        }
    }
}

impl std::fmt::Display for OwnerRecoveryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for OwnerRecoveryRefusal {}

/// The verified Agent-subject revocation record hashes this node holds,
/// per revoked agent.
pub type VerifiedAgentRevocations = BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>;

fn domain_framed(domain: &[u8], encoded: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len().saturating_add(8).saturating_add(encoded.len()));
    out.extend_from_slice(domain);
    out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    out.extend_from_slice(encoded);
    out
}

/// The bytes the owner signs: the mandate domain, then the
/// length-prefixed canonical postcard body.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn mandate_signable_bytes(
    body: &OwnerRecoveryMandateBodyV1,
) -> Result<Vec<u8>, postcard::Error> {
    Ok(domain_framed(
        OWNER_RECOVERY_MANDATE_DOMAIN,
        &postcard::to_stdvec(body)?,
    ))
}

/// The bytes the promoted member signs: the commit domain, then the
/// length-prefixed canonical postcard body (with the embedded mandate).
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn commit_signable_bytes(body: &OwnerRecoveryBodyV1) -> Result<Vec<u8>, postcard::Error> {
    Ok(domain_framed(
        OWNER_RECOVERY_COMMIT_DOMAIN,
        &postcard::to_stdvec(body)?,
    ))
}

/// The BLAKE3 hex digest of a signed mandate's encoded bytes (its ID in
/// logs and status).
#[must_use]
pub fn mandate_id(mandate: &SignedOwnerRecoveryMandateV1) -> String {
    let bytes = postcard::to_stdvec(mandate).unwrap_or_default();
    blake3::hash(&bytes).to_hex().to_string()
}

/// Sign a mandate with the owner's user key. The body's
/// `owner_public_key` is set from the keypair.
///
/// # Errors
///
/// Returns [`OwnerRecoveryRefusal::Malformed`] when the body does not
/// encode and [`OwnerRecoveryRefusal::RecoverySignerNotOwner`] when signing
/// fails.
pub fn sign_mandate(
    mut body: OwnerRecoveryMandateBodyV1,
    owner: &UserKeypair,
) -> Result<SignedOwnerRecoveryMandateV1, OwnerRecoveryRefusal> {
    body.owner_public_key = owner.public_key().as_bytes().to_vec();
    let bytes = mandate_signable_bytes(&body).map_err(|_| OwnerRecoveryRefusal::Malformed)?;
    let signature = sign_with_ml_dsa(owner.secret_key(), &bytes)
        .map_err(|_| OwnerRecoveryRefusal::RecoverySignerNotOwner)?;
    Ok(SignedOwnerRecoveryMandateV1 {
        body,
        signature: signature.as_bytes().to_vec(),
    })
}

/// Sign a commit body with the promoted member's agent key.
///
/// # Errors
///
/// Returns [`OwnerRecoveryRefusal::RecoveryMemberIneligible`] when the
/// keypair is not the body's actor or signing fails, and
/// [`OwnerRecoveryRefusal::Malformed`] when the body does not encode.
pub fn sign_commit(
    body: OwnerRecoveryBodyV1,
    keypair: &AgentKeypair,
) -> Result<SignedOwnerRecoveryV1, OwnerRecoveryRefusal> {
    if keypair.agent_id().as_bytes() != &body.actor {
        return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
    }
    let bytes = commit_signable_bytes(&body).map_err(|_| OwnerRecoveryRefusal::Malformed)?;
    let signature = sign_with_ml_dsa(keypair.secret_key(), &bytes)
        .map_err(|_| OwnerRecoveryRefusal::RecoveryMemberIneligible)?;
    Ok(SignedOwnerRecoveryV1 {
        body,
        signature: signature.as_bytes().to_vec(),
    })
}

/// Encode a frame as a direct-message payload.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_frame(frame: &OwnerRecoveryFrameV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = OWNER_RECOVERY_PREFIX.to_vec();
    out.extend(postcard::to_stdvec(frame)?);
    Ok(out)
}

/// Decode a frame with exact consumption. This checks the shape only.
///
/// # Errors
///
/// Returns [`OwnerRecoveryRefusal::WrongPrefix`] or
/// [`OwnerRecoveryRefusal::Malformed`].
pub fn decode_frame(payload: &[u8]) -> Result<OwnerRecoveryFrameV1, OwnerRecoveryRefusal> {
    let body = payload
        .strip_prefix(OWNER_RECOVERY_PREFIX)
        .ok_or(OwnerRecoveryRefusal::WrongPrefix)?;
    let (frame, rest) = postcard::take_from_bytes::<OwnerRecoveryFrameV1>(body)
        .map_err(|_| OwnerRecoveryRefusal::Malformed)?;
    if !rest.is_empty() {
        return Err(OwnerRecoveryRefusal::Malformed);
    }
    Ok(frame)
}

/// Verify the owner signature: the embedded key derives the policy's
/// owner U, and that key signed the body.
///
/// # Errors
///
/// Returns [`OwnerRecoveryRefusal::RecoverySignerNotOwner`].
pub fn verify_mandate_signature(
    mandate: &SignedOwnerRecoveryMandateV1,
    owner: &UserId,
) -> Result<(), OwnerRecoveryRefusal> {
    let refuse = |_| OwnerRecoveryRefusal::RecoverySignerNotOwner;
    let key = MlDsaPublicKey::from_bytes(&mandate.body.owner_public_key).map_err(refuse)?;
    if &UserId::from_public_key(&key) != owner {
        return Err(OwnerRecoveryRefusal::RecoverySignerNotOwner);
    }
    let signature = MlDsaSignature::from_bytes(&mandate.signature).map_err(refuse)?;
    let bytes = mandate_signable_bytes(&mandate.body)
        .map_err(|_| OwnerRecoveryRefusal::RecoverySignerNotOwner)?;
    verify_with_ml_dsa(&key, &bytes, &signature).map_err(refuse)
}

/// Verify the outer signature and the embedded commit's own signature and
/// structure. The commit's signer key derives the actor's agent ID, and
/// that same key verifies the outer signature, so the actor signed both.
///
/// # Errors
///
/// Returns [`OwnerRecoveryRefusal::RecoveryMemberIneligible`].
pub fn verify_commit_signatures(frame: &SignedOwnerRecoveryV1) -> Result<(), OwnerRecoveryRefusal> {
    let refuse = OwnerRecoveryRefusal::RecoveryMemberIneligible;
    let body = &frame.body;
    let commit = body.commit.to_commit();
    commit.verify_structure().map_err(|_| refuse)?;
    if commit.committed_by != hex::encode(body.actor) {
        return Err(refuse);
    }
    let key_bytes = hex::decode(&commit.signer_public_key).map_err(|_| refuse)?;
    let key = MlDsaPublicKey::from_bytes(&key_bytes).map_err(|_| refuse)?;
    let signature = MlDsaSignature::from_bytes(&frame.signature).map_err(|_| refuse)?;
    let bytes = commit_signable_bytes(body).map_err(|_| OwnerRecoveryRefusal::Malformed)?;
    verify_with_ml_dsa(&key, &bytes, &signature).map_err(|_| refuse)
}

/// The TreeKEM security binding the commit must sign: the final epoch and
/// the BLAKE3 digest of the length-prefixed commit bytes, in order.
#[must_use]
pub fn treekem_binding(next_epoch: u64, commits: &[Vec<u8>]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x0x.owner-recovery.treekem.v1");
    for commit in commits {
        hasher.update(&(commit.len() as u64).to_le_bytes());
        hasher.update(commit);
    }
    format!(
        "treekem:epoch={next_epoch}:owner-recovery={}",
        hasher.finalize().to_hex()
    )
}

/// The GSS security binding of a rotation to `epoch` (as
/// [`GroupInfo::rotate_shared_secret`] writes it).
#[must_use]
pub fn gss_binding(epoch: u64) -> String {
    format!("gss:epoch={epoch}")
}

/// Admin-or-higher Active seats of `info`, sorted by raw ID.
#[must_use]
pub fn active_admins(info: &GroupInfo) -> Vec<[u8; 32]> {
    let mut admins: Vec<[u8; 32]> = info
        .active_members()
        .filter(|member| member.role.at_least(GroupRole::Admin))
        .filter_map(|member| agent_bytes(&member.agent_id))
        .collect();
    admins.sort_unstable();
    admins
}

fn agent_bytes(hex_id: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_id).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// The revoked admins of `info` with their verified record hashes, when
/// every Admin-or-higher Active seat holds one; `None` while an eligible
/// admin remains or the roster has no admin at all (ADR 0088 §2 item 3).
#[must_use]
pub fn revoked_admins_when_needed(
    info: &GroupInfo,
    revocations: &VerifiedAgentRevocations,
) -> Option<Vec<RevokedAdminV1>> {
    let admins = active_admins(info);
    if admins.is_empty() {
        return None;
    }
    admins
        .into_iter()
        .map(|agent| {
            let hashes = revocations.get(&agent).filter(|set| !set.is_empty())?;
            Some(RevokedAdminV1 {
                agent,
                revocation_hashes: hashes.iter().copied().collect(),
            })
        })
        .collect()
}

/// The crypto shape this group needs (by confidentiality and plane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCryptoKind {
    /// TreeKEM `MlsEncrypted`.
    TreeKem,
    /// Grandfathered GSS `MlsEncrypted`.
    Gss,
    /// `SignedPublic`: roster only.
    SignedPublic,
}

/// The crypto shape of `info`.
#[must_use]
pub fn crypto_kind(info: &GroupInfo) -> RecoveryCryptoKind {
    if info.policy.confidentiality == GroupConfidentiality::SignedPublic {
        RecoveryCryptoKind::SignedPublic
    } else if info.secure_plane == crate::mls::SecureGroupPlane::TreeKem {
        RecoveryCryptoKind::TreeKem
    } else {
        RecoveryCryptoKind::Gss
    }
}

/// Apply the commit's roster change to `next`: each removed seat becomes
/// Removed (by the actor), and the actor becomes Admin. Authors and
/// receivers both run this, so the signed post-state hash covers it.
pub fn apply_roster_change(next: &mut GroupInfo, body: &OwnerRecoveryBodyV1) {
    let actor_hex = hex::encode(body.actor);
    for seat in &body.removed {
        next.remove_member(&hex::encode(seat.agent), Some(actor_hex.clone()));
    }
    next.set_member_role(&actor_hex, GroupRole::Admin);
}

/// Decode the commit's promoted certificate.
#[must_use]
pub fn decode_certificate(bytes: &[u8]) -> Option<AgentCertificate> {
    bincode::deserialize(bytes).ok()
}

/// The mandate checks against this node's current parent state (§4b(1)):
/// containment, the owner signature against U, the parent head, that no
/// eligible admin remains, that the named admins are exactly the revoked
/// Admin-or-higher Active seats with verified records, and that the
/// promoted member is Active, unrevoked and holds an unexpired committed
/// certificate that verifies against U. `promoted_certificate` is the
/// certificate to check (the commit carries it; the promoted member uses
/// its own committed one).
///
/// # Errors
///
/// Returns the first failed check.
pub fn validate_mandate(
    mandate: &SignedOwnerRecoveryMandateV1,
    parent: &GroupInfo,
    revocations: &VerifiedAgentRevocations,
    promoted_certificate: Option<&AgentCertificate>,
    now_unix: u64,
) -> Result<(), OwnerRecoveryRefusal> {
    let body = &mandate.body;
    if parent.withdrawn || parent.fork_quarantine.is_some() {
        return Err(OwnerRecoveryRefusal::RecoveryGroupQuarantined);
    }
    let Some(owner) = parent.policy.admission.owner_certified_user_id() else {
        return Err(OwnerRecoveryRefusal::RecoverySignerNotOwner);
    };
    verify_mandate_signature(mandate, owner)?;
    if body.stable_group_id != parent.stable_group_id()
        || body.parent_head != parent.state_hash
        || body.parent_revision != parent.state_revision
    {
        return Err(OwnerRecoveryRefusal::RecoveryHeadMismatch);
    }
    let Some(expected) = revoked_admins_when_needed(parent, revocations) else {
        return Err(OwnerRecoveryRefusal::RecoveryNotNeeded);
    };
    let named: Vec<[u8; 32]> = body
        .revoked_admins
        .iter()
        .map(|admin| admin.agent)
        .collect();
    let expected_ids: Vec<[u8; 32]> = expected.iter().map(|admin| admin.agent).collect();
    if named != expected_ids {
        return Err(OwnerRecoveryRefusal::RecoveryProofInvalid);
    }
    for admin in &body.revoked_admins {
        let held = revocations.get(&admin.agent);
        let verified = !admin.revocation_hashes.is_empty()
            && admin
                .revocation_hashes
                .iter()
                .all(|hash| held.is_some_and(|set| set.contains(hash)));
        if !verified {
            // This node does not hold the named record: by its own
            // verified evidence that admin is still eligible.
            return Err(OwnerRecoveryRefusal::RecoveryNotNeeded);
        }
    }
    let promoted_hex = hex::encode(body.promoted);
    let Some(member) = parent.members_v2.get(&promoted_hex) else {
        return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
    };
    let revoked = revocations
        .get(&body.promoted)
        .is_some_and(|set| !set.is_empty());
    if member.state != GroupMemberState::Active
        || revoked
        || named.contains(&body.promoted)
        || member.certificate_digest.as_deref() != Some(body.promoted_certificate_digest.as_str())
    {
        return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
    }
    let Some(certificate) = promoted_certificate else {
        return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
    };
    if crate::groups::owner_cert::certificate_digest_hex(certificate)
        != body.promoted_certificate_digest
    {
        return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
    }
    crate::groups::owner_cert::verify_cert_against_owner(
        owner,
        &promoted_hex,
        certificate,
        revoked,
        now_unix,
    )
    .map_err(|_| OwnerRecoveryRefusal::RecoveryMemberIneligible)
}

/// The receiver's L4 checks for an `OwnerRecoveryV1` commit against its
/// current verified parent state. `current_epoch` is this node's TreeKEM
/// epoch (ignored for other planes).
///
/// The caller holds the group's membership lock and calls this
/// immediately before it applies the commit. The embedded commit must
/// still pass the ordinary `validate_apply` (prev-hash, structure, an
/// Active signer) and `finalize_applied_commit` (the recomputed post-state
/// hash), with [`apply_roster_change`] as the only roster mutation; a
/// commit that changes anything else fails there. The cryptographic
/// removal proof (the leaves are gone after the TreeKEM commits) is checked
/// by the caller on its tree.
///
/// # Errors
///
/// Returns the first failed check.
pub fn validate_against_parent(
    body: &OwnerRecoveryBodyV1,
    parent: &GroupInfo,
    current_epoch: u64,
    revocations: &VerifiedAgentRevocations,
    now_unix: u64,
) -> Result<(), OwnerRecoveryRefusal> {
    if parent.withdrawn || parent.fork_quarantine.is_some() || body.commit.withdrawn {
        return Err(OwnerRecoveryRefusal::RecoveryGroupQuarantined);
    }
    if body.stable_group_id != parent.stable_group_id()
        || body.commit.group_id != parent.stable_group_id()
        || body.prior_head != parent.state_hash
        || body.prior_revision != parent.state_revision
        || body.commit.prev_state_hash.as_deref() != Some(parent.state_hash.as_str())
        || body.next_revision != parent.state_revision.saturating_add(1)
        || body.commit.revision != body.next_revision
    {
        return Err(OwnerRecoveryRefusal::RecoveryHeadMismatch);
    }
    let certificate = decode_certificate(&body.promoted_certificate);
    validate_mandate(
        &body.mandate,
        parent,
        revocations,
        certificate.as_ref(),
        now_unix,
    )?;
    if body.actor != body.mandate.body.promoted {
        return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
    }
    let kind = crypto_kind(parent);
    if body.removed.len() != body.mandate.body.revoked_admins.len() {
        return Err(OwnerRecoveryRefusal::RecoveryProofInvalid);
    }
    for (seat, named) in body.removed.iter().zip(&body.mandate.body.revoked_admins) {
        let committed_leaf = parent
            .members_v2
            .get(&hex::encode(seat.agent))
            .and_then(|member| member.treekem_key_package_hash.clone());
        let expected_leaf = (kind == RecoveryCryptoKind::TreeKem)
            .then_some(committed_leaf)
            .flatten();
        if seat.agent != named.agent || seat.leaf_key_package_hash != expected_leaf {
            return Err(OwnerRecoveryRefusal::RecoveryProofInvalid);
        }
    }
    let binding_ok = match (&body.crypto, kind) {
        (
            OwnerRecoveryCryptoV1::TreeKem {
                commits,
                next_epoch,
            },
            RecoveryCryptoKind::TreeKem,
        ) => {
            let leaves = body
                .removed
                .iter()
                .filter(|seat| seat.leaf_key_package_hash.is_some())
                .count();
            commits.len() == leaves
                && *next_epoch == current_epoch.saturating_add(commits.len() as u64)
                && body.commit.security_binding.as_deref()
                    == Some(treekem_binding(*next_epoch, commits).as_str())
        }
        (OwnerRecoveryCryptoV1::Gss { next_secret_epoch }, RecoveryCryptoKind::Gss) => {
            *next_secret_epoch == parent.secret_epoch.saturating_add(1)
                && body.commit.security_binding.as_deref()
                    == Some(gss_binding(*next_secret_epoch).as_str())
        }
        (OwnerRecoveryCryptoV1::SignedPublic, RecoveryCryptoKind::SignedPublic) => {
            body.commit.security_binding == parent.security_binding
        }
        _ => false,
    };
    if !binding_ok {
        return Err(OwnerRecoveryRefusal::RecoveryProofInvalid);
    }
    let mut next = parent.clone();
    apply_roster_change(&mut next, body);
    if crate::groups::state_commit::enforce_last_admin_invariant(&next.members_v2, false).is_err()
        || crate::groups::state_commit::compute_roster_root(&next.members_v2)
            != body.commit.roster_root
    {
        return Err(OwnerRecoveryRefusal::RecoveryProofInvalid);
    }
    Ok(())
}

/// ADR 0110 §2 fork containment: whether `body`, which
/// [`validate_against_parent`] refused with `recovery_head_mismatch` on
/// `current`, is an authenticated sibling of a commit on `current`'s
/// retained chain. That is: the policy owner U signed its mandate for the
/// commit's own parent; the promoted member is the actor; the commit
/// chains exactly from that parent; and `current` retains a different
/// commit at the same revision on the same parent. When `current` retains
/// the parent itself, the promoted member must hold an Active seat there,
/// with the mandate's certificate digest when the snapshot records one.
///
/// The caller has already run [`verify_commit_signatures`], so the actor
/// signed the frame and the embedded commit.
///
/// # Errors
///
/// Returns the first failed check; `recovery_head_mismatch` when the
/// commit is no sibling of the retained chain.
pub fn validate_sibling(
    body: &OwnerRecoveryBodyV1,
    current: &GroupInfo,
) -> Result<(), OwnerRecoveryRefusal> {
    let Some(owner) = current.policy.admission.owner_certified_user_id() else {
        return Err(OwnerRecoveryRefusal::RecoverySignerNotOwner);
    };
    verify_mandate_signature(&body.mandate, owner)?;
    let mandate = &body.mandate.body;
    let stable = current.stable_group_id();
    if body.stable_group_id != stable
        || body.commit.group_id != stable
        || mandate.stable_group_id != stable
        || mandate.parent_head != body.prior_head
        || mandate.parent_revision != body.prior_revision
        || body.commit.prev_state_hash.as_deref() != Some(body.prior_head.as_str())
        || body.next_revision != body.prior_revision.saturating_add(1)
        || body.commit.revision != body.next_revision
    {
        return Err(OwnerRecoveryRefusal::RecoveryHeadMismatch);
    }
    if body.actor != mandate.promoted {
        return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
    }
    let sibling = current.commit_log.iter().any(|retained| {
        retained.commit.prev_state_hash.as_deref() == Some(body.prior_head.as_str())
            && retained.commit.revision == body.next_revision
            && retained.commit.state_hash != body.commit.state_hash
    });
    if !sibling {
        return Err(OwnerRecoveryRefusal::RecoveryHeadMismatch);
    }
    if let Some(parent) = current
        .commit_log
        .iter()
        .find(|retained| retained.commit.state_hash == body.prior_head)
    {
        let seated = parent
            .roster
            .get(&hex::encode(mandate.promoted))
            .is_some_and(|seat| {
                seat.state == GroupMemberState::Active
                    && seat
                        .certificate_digest
                        .as_deref()
                        .is_none_or(|digest| digest == mandate.promoted_certificate_digest)
            });
        if !seated {
            return Err(OwnerRecoveryRefusal::RecoveryMemberIneligible);
        }
    }
    Ok(())
}

/// The D76 hold rule (§4b(1) "Mixed versions"): the Active members whose
/// current verified advert lacks `owner_recovery_v1` (`Some(false)`).
/// Unknown, expired or offline members do not hold the commit; they are
/// stranded until they upgrade. Returns the holders in raw-ID order.
#[must_use]
pub fn receiver_upgrade_holders(
    members: impl IntoIterator<Item = ([u8; 32], Option<bool>)>,
) -> Vec<[u8; 32]> {
    crate::groups::crypto_exclusion::receiver_upgrade_holders(members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::member::GroupMember;
    use crate::groups::policy::GroupAdmission;
    use crate::identity::UserKeypair;

    const NOW: u64 = 1_800_000_000;

    struct Fixture {
        owner: UserKeypair,
        admin: AgentKeypair,
        promoted: AgentKeypair,
        other: AgentKeypair,
        info: GroupInfo,
        revocations: VerifiedAgentRevocations,
        cert: AgentCertificate,
    }

    fn member_with_cert(
        owner: &UserKeypair,
        agent: &AgentKeypair,
        role: GroupRole,
    ) -> (GroupMember, AgentCertificate) {
        let cert = AgentCertificate::issue(owner, agent).expect("cert");
        let hex_id = hex::encode(agent.agent_id().as_bytes());
        let mut member = GroupMember::new_member(hex_id, None, None, 1);
        member.role = role;
        member.certificate_digest = Some(crate::groups::owner_cert::certificate_digest_hex(&cert));
        member.certificate = Some(cert.clone());
        member.treekem_key_package_hash = Some(format!(
            "kp-{}",
            hex::encode(&agent.agent_id().as_bytes()[..4])
        ));
        (member, cert)
    }

    fn fixture(
        confidentiality: GroupConfidentiality,
        plane: crate::mls::SecureGroupPlane,
    ) -> Fixture {
        let owner = UserKeypair::generate().expect("user");
        let admin = AgentKeypair::generate().expect("admin");
        let promoted = AgentKeypair::generate().expect("promoted");
        let other = AgentKeypair::generate().expect("other");
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            admin.agent_id(),
            "ab".repeat(16),
        );
        info.policy.admission = GroupAdmission::OwnerCertified(owner.user_id());
        info.policy.confidentiality = confidentiality;
        info.secure_plane = plane;
        info.members_v2.clear();
        let (a, _) = member_with_cert(&owner, &admin, GroupRole::Admin);
        let (b, cert) = member_with_cert(&owner, &promoted, GroupRole::Member);
        let (c, _) = member_with_cert(&owner, &other, GroupRole::Member);
        for member in [a, b, c] {
            info.members_v2.insert(member.agent_id.clone(), member);
        }
        info.secret_epoch = 4;
        info.recompute_state_hash();
        let mut revocations = VerifiedAgentRevocations::new();
        revocations
            .entry(*admin.agent_id().as_bytes())
            .or_default()
            .insert([7u8; 32]);
        Fixture {
            owner,
            admin,
            promoted,
            other,
            info,
            revocations,
            cert,
        }
    }

    fn mandate_for(f: &Fixture) -> SignedOwnerRecoveryMandateV1 {
        let revoked = revoked_admins_when_needed(&f.info, &f.revocations).expect("needed");
        sign_mandate(
            OwnerRecoveryMandateBodyV1 {
                stable_group_id: f.info.stable_group_id().to_string(),
                parent_head: f.info.state_hash.clone(),
                parent_revision: f.info.state_revision,
                revoked_admins: revoked,
                promoted: *f.promoted.agent_id().as_bytes(),
                promoted_certificate_digest: crate::groups::owner_cert::certificate_digest_hex(
                    &f.cert,
                ),
                owner_public_key: Vec::new(),
                issued_at_ms: 1,
            },
            &f.owner,
        )
        .expect("sign mandate")
    }

    fn commit_for(
        f: &Fixture,
        mandate: SignedOwnerRecoveryMandateV1,
        epoch: u64,
    ) -> OwnerRecoveryBodyV1 {
        let kind = crypto_kind(&f.info);
        let removed: Vec<RemovedSeatV1> = mandate
            .body
            .revoked_admins
            .iter()
            .map(|admin| RemovedSeatV1 {
                agent: admin.agent,
                leaf_key_package_hash: (kind == RecoveryCryptoKind::TreeKem)
                    .then(|| {
                        f.info
                            .members_v2
                            .get(&hex::encode(admin.agent))
                            .and_then(|m| m.treekem_key_package_hash.clone())
                    })
                    .flatten(),
            })
            .collect();
        let mut body = OwnerRecoveryBodyV1 {
            stable_group_id: f.info.stable_group_id().to_string(),
            actor: *f.promoted.agent_id().as_bytes(),
            prior_head: f.info.state_hash.clone(),
            prior_revision: f.info.state_revision,
            next_revision: f.info.state_revision + 1,
            roster_revision: f.info.roster_revision + 1,
            mandate,
            promoted_certificate: bincode::serialize(&f.cert).expect("cert bytes"),
            removed,
            crypto: OwnerRecoveryCryptoV1::SignedPublic,
            commit: CommitHeaderV1::from(&{
                let mut placeholder = f.info.clone();
                placeholder
                    .seal_commit_evicting(&f.promoted, 1)
                    .expect("seal")
            }),
        };
        let mut next = f.info.clone();
        apply_roster_change(&mut next, &body);
        match kind {
            RecoveryCryptoKind::TreeKem => {
                let commits = vec![vec![1u8; 24]];
                let next_epoch = epoch + 1;
                next.secret_epoch = next_epoch;
                next.security_binding = Some(treekem_binding(next_epoch, &commits));
                body.crypto = OwnerRecoveryCryptoV1::TreeKem {
                    commits,
                    next_epoch,
                };
            }
            RecoveryCryptoKind::Gss => {
                let next_secret_epoch = f.info.secret_epoch + 1;
                next.secret_epoch = next_secret_epoch;
                next.security_binding = Some(gss_binding(next_secret_epoch));
                body.crypto = OwnerRecoveryCryptoV1::Gss { next_secret_epoch };
            }
            RecoveryCryptoKind::SignedPublic => {}
        }
        let commit = next.seal_commit_evicting(&f.promoted, 1_000).expect("seal");
        body.commit = CommitHeaderV1::from(&commit);
        body
    }

    fn treekem() -> Fixture {
        fixture(
            GroupConfidentiality::MlsEncrypted,
            crate::mls::SecureGroupPlane::TreeKem,
        )
    }

    #[test]
    fn frames_round_trip_with_exact_consumption() {
        let f = treekem();
        let mandate = mandate_for(&f);
        let frame = OwnerRecoveryFrameV1::Mandate(mandate.clone());
        let bytes = encode_frame(&frame).expect("encode");
        assert!(bytes.starts_with(OWNER_RECOVERY_PREFIX));
        assert_eq!(decode_frame(&bytes), Ok(frame));
        let commit = sign_commit(commit_for(&f, mandate, 3), &f.promoted).expect("sign");
        let frame = OwnerRecoveryFrameV1::Commit(Box::new(commit));
        let mut bytes = encode_frame(&frame).expect("encode");
        assert_eq!(decode_frame(&bytes), Ok(frame));
        bytes.push(0);
        assert_eq!(decode_frame(&bytes), Err(OwnerRecoveryRefusal::Malformed));
        assert_eq!(
            decode_frame(b"X0XCE1rest"),
            Err(OwnerRecoveryRefusal::WrongPrefix)
        );
        assert_eq!(
            decode_frame(b"X0XORC1"),
            Err(OwnerRecoveryRefusal::Malformed)
        );
    }

    #[test]
    fn valid_commit_is_accepted_on_every_plane() {
        for f in [
            treekem(),
            fixture(
                GroupConfidentiality::MlsEncrypted,
                crate::mls::SecureGroupPlane::Gss,
            ),
            fixture(
                GroupConfidentiality::SignedPublic,
                crate::mls::SecureGroupPlane::TreeKem,
            ),
        ] {
            let mandate = mandate_for(&f);
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&f.cert), NOW)
                .expect("mandate");
            let frame = sign_commit(commit_for(&f, mandate, 3), &f.promoted).expect("sign");
            verify_commit_signatures(&frame).expect("signatures");
            validate_against_parent(&frame.body, &f.info, 3, &f.revocations, NOW).expect("valid");
        }
    }

    #[test]
    fn tampered_commit_fails_the_outer_signature() {
        let f = treekem();
        let mut frame = sign_commit(commit_for(&f, mandate_for(&f), 0), &f.promoted).expect("sign");
        frame.body.roster_revision += 1;
        assert_eq!(
            verify_commit_signatures(&frame),
            Err(OwnerRecoveryRefusal::RecoveryMemberIneligible)
        );
        let body = commit_for(&f, mandate_for(&f), 0);
        assert_eq!(
            sign_commit(body, &f.other).err(),
            Some(OwnerRecoveryRefusal::RecoveryMemberIneligible)
        );
    }

    #[test]
    fn eligible_admin_means_recovery_not_needed() {
        let mut f = treekem();
        let mandate = mandate_for(&f);
        f.revocations.clear();
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&f.cert), NOW),
            Err(OwnerRecoveryRefusal::RecoveryNotNeeded)
        );
    }

    #[test]
    fn missing_named_record_means_recovery_not_needed() {
        let mut f = treekem();
        let mandate = mandate_for(&f);
        f.revocations
            .insert(*f.admin.agent_id().as_bytes(), BTreeSet::from([[8u8; 32]]));
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&f.cert), NOW),
            Err(OwnerRecoveryRefusal::RecoveryNotNeeded)
        );
    }

    #[test]
    fn older_or_later_head_is_a_head_mismatch() {
        let mut f = treekem();
        let mandate = mandate_for(&f);
        f.info.state_hash = "later".to_string();
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&f.cert), NOW),
            Err(OwnerRecoveryRefusal::RecoveryHeadMismatch)
        );
    }

    #[test]
    fn non_owner_key_is_refused() {
        let f = treekem();
        let mut mandate = mandate_for(&f);
        let stranger = UserKeypair::generate().expect("user");
        mandate = sign_mandate(mandate.body, &stranger).expect("sign");
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&f.cert), NOW),
            Err(OwnerRecoveryRefusal::RecoverySignerNotOwner)
        );
        let mut forged = mandate_for(&f);
        forged.body.issued_at_ms += 1;
        assert_eq!(
            validate_mandate(&forged, &f.info, &f.revocations, Some(&f.cert), NOW),
            Err(OwnerRecoveryRefusal::RecoverySignerNotOwner)
        );
    }

    #[test]
    fn revoked_or_expired_promoted_member_is_ineligible() {
        let mut f = treekem();
        let mandate = mandate_for(&f);
        f.revocations
            .entry(*f.promoted.agent_id().as_bytes())
            .or_default()
            .insert([9u8; 32]);
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&f.cert), NOW),
            Err(OwnerRecoveryRefusal::RecoveryMemberIneligible)
        );
        let f = treekem();
        let mandate = mandate_for(&f);
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, None, NOW),
            Err(OwnerRecoveryRefusal::RecoveryMemberIneligible)
        );
        let expired =
            AgentCertificate::issue_with_expiry(&f.owner, &f.promoted, Some(NOW - 10_000))
                .expect("cert");
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&expired), NOW),
            Err(OwnerRecoveryRefusal::RecoveryMemberIneligible)
        );
    }

    #[test]
    fn quarantined_group_is_refused() {
        let mut f = treekem();
        let mandate = mandate_for(&f);
        f.info.withdrawn = true;
        assert_eq!(
            validate_mandate(&mandate, &f.info, &f.revocations, Some(&f.cert), NOW),
            Err(OwnerRecoveryRefusal::RecoveryGroupQuarantined)
        );
    }

    #[test]
    fn wrong_crypto_or_roster_is_a_proof_failure() {
        let f = treekem();
        let good = commit_for(&f, mandate_for(&f), 2);
        assert!(validate_against_parent(&good, &f.info, 2, &f.revocations, NOW).is_ok());
        assert_eq!(
            validate_against_parent(&good, &f.info, 3, &f.revocations, NOW),
            Err(OwnerRecoveryRefusal::RecoveryProofInvalid)
        );
        let mut seats = good.clone();
        seats.removed.clear();
        assert_eq!(
            validate_against_parent(&seats, &f.info, 2, &f.revocations, NOW),
            Err(OwnerRecoveryRefusal::RecoveryProofInvalid)
        );
        let mut plane = good.clone();
        plane.crypto = OwnerRecoveryCryptoV1::SignedPublic;
        assert_eq!(
            validate_against_parent(&plane, &f.info, 2, &f.revocations, NOW),
            Err(OwnerRecoveryRefusal::RecoveryProofInvalid)
        );
        let mut root = good.clone();
        root.commit.roster_root = "other".to_string();
        assert_eq!(
            validate_against_parent(&root, &f.info, 2, &f.revocations, NOW),
            Err(OwnerRecoveryRefusal::RecoveryProofInvalid)
        );
        let mut actor = good;
        actor.actor = *f.other.agent_id().as_bytes();
        assert_eq!(
            validate_against_parent(&actor, &f.info, 2, &f.revocations, NOW),
            Err(OwnerRecoveryRefusal::RecoveryMemberIneligible)
        );
    }

    /// ADR 0110 §2 (#1508 r5): only an owner-mandated commit that chains
    /// from the parent of a retained commit at the same revision is a
    /// sibling (fork evidence); a forged mandate, a wrong actor or a
    /// commit with no retained sibling is not.
    #[test]
    fn only_an_owner_mandated_child_of_a_retained_parent_is_a_sibling() {
        let f = fixture(
            GroupConfidentiality::SignedPublic,
            crate::mls::SecureGroupPlane::default(),
        );
        let theirs = commit_for(&f, mandate_for(&f), 0);
        // This node committed its own recovery on the same parent: it
        // also promoted another member.
        let mut ours = f.info.clone();
        apply_roster_change(&mut ours, &theirs);
        ours.members_v2
            .get_mut(&hex::encode(f.other.agent_id().as_bytes()))
            .expect("other seat")
            .role = GroupRole::Admin;
        let own = ours.seal_commit_evicting(&f.promoted, 2_000).expect("seal");
        assert_ne!(own.state_hash, theirs.commit.state_hash);
        assert_eq!(validate_sibling(&theirs, &ours), Ok(()));

        // No retained child of the parent: not a sibling.
        assert_eq!(
            validate_sibling(&theirs, &f.info),
            Err(OwnerRecoveryRefusal::RecoveryHeadMismatch)
        );
        // A mandate that U did not sign.
        let mut forged = theirs.clone();
        let stranger = UserKeypair::generate().expect("user");
        forged.mandate = sign_mandate(forged.mandate.body, &stranger).expect("sign");
        assert_eq!(
            validate_sibling(&forged, &ours),
            Err(OwnerRecoveryRefusal::RecoverySignerNotOwner)
        );
        // The actor is not the promoted member.
        let mut wrong_actor = theirs.clone();
        wrong_actor.actor = *f.other.agent_id().as_bytes();
        assert_eq!(
            validate_sibling(&wrong_actor, &ours),
            Err(OwnerRecoveryRefusal::RecoveryMemberIneligible)
        );
        // A commit that does not chain from the mandate's parent.
        let mut unchained = theirs;
        unchained.prior_head = "other".to_string();
        assert_eq!(
            validate_sibling(&unchained, &ours),
            Err(OwnerRecoveryRefusal::RecoveryHeadMismatch)
        );
    }

    #[test]
    fn replayed_commit_on_a_later_head_is_refused() {
        let f = treekem();
        let body = commit_for(&f, mandate_for(&f), 2);
        let mut later = f.info.clone();
        later.state_revision += 1;
        later.state_hash = "later".to_string();
        assert_eq!(
            validate_against_parent(&body, &later, 2, &f.revocations, NOW),
            Err(OwnerRecoveryRefusal::RecoveryHeadMismatch)
        );
    }

    #[test]
    fn roster_change_removes_admins_and_promotes_only_the_member() {
        let f = treekem();
        let body = commit_for(&f, mandate_for(&f), 0);
        let mut next = f.info.clone();
        apply_roster_change(&mut next, &body);
        let admin = &next.members_v2[&hex::encode(f.admin.agent_id().as_bytes())];
        let promoted = &next.members_v2[&hex::encode(f.promoted.agent_id().as_bytes())];
        let other = &next.members_v2[&hex::encode(f.other.agent_id().as_bytes())];
        assert_eq!(admin.state, GroupMemberState::Removed);
        assert_eq!(promoted.role, GroupRole::Admin);
        assert_eq!(other.role, GroupRole::Member);
        assert_eq!(other.state, GroupMemberState::Active);
    }

    #[test]
    fn only_known_lacking_adverts_hold() {
        let holders = receiver_upgrade_holders([
            ([3u8; 32], Some(false)),
            ([1u8; 32], Some(true)),
            ([2u8; 32], None),
        ]);
        assert_eq!(holders, vec![[3u8; 32]]);
    }
}
