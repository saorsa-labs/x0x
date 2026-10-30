//! ADR 0110 §4a: `CertificateRebindV1`, the commit that binds a renewed
//! certificate into an Active seat in place (D129, D135).
//!
//! The commit changes only the seat's committed certificate and its
//! digest. Role, membership, TreeKEM leaf and epoch stay unchanged, and the
//! commit carries no key material.
//!
//! This module is pure and I/O-free. It holds:
//!
//! - the frozen v1 wire shape: typed prefix [`CERTIFICATE_REBIND_PREFIX`]
//!   (`X0XCRB1`), an explicit v1 postcard body consumed exactly, and an
//!   outer ML-DSA-65 agent signature in domain
//!   [`CERTIFICATE_REBIND_SIGNATURE_DOMAIN`] (`x0x.certificate-rebind.v1`)
//!   over the canonical body;
//! - the receiver's L4 acceptance rule ([`validate_against_parent`]) with
//!   the typed refusals `rebind_signer_ineligible`,
//!   `rebind_seat_not_active`, `rebind_digest_mismatch`,
//!   `rebind_certificate_invalid` and `rebind_not_later`;
//! - the authoring step ([`seal`]);
//! - the self-rebind cutoff `not_after − τ` ([`self_rebind_window_open`]);
//! - the mixed-version rules: an ordinary rebind needs every Active
//!   member's current verified advert to set `certificate_rebind_v1`
//!   ([`rebind_allowed_for_members`]); the §4b(2) every-admin-expired
//!   self-rebind follows the D76 hold rule instead
//!   ([`crate::groups::crypto_exclusion::receiver_upgrade_holders`]);
//! - the ADR 0064 ancestor-walk exception for a self-rebind link
//!   ([`is_self_rebind_link`]);
//! - the displaced-certificate retention that keeps a superseded parent
//!   certificate verifiable for a later competing sibling rebind (#1650)
//!   ([`install_certificate`], [`DISPLACED_CERTIFICATE_CAP`]).
//!
//! The capability that gates every send is `certificate_rebind_v1`
//! ([`crate::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1`], bit 6). The
//! body never goes inside a container that a released binary decodes, and
//! it is never published on the ungated metadata topic.

use std::collections::BTreeMap;

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::groups::crypto_exclusion::CommitHeaderV1;
use crate::groups::eviction::{own_expiry_trigger_due, EXPIRY_TOLERANCE_SECS};
use crate::groups::member::{GroupMember, GroupMemberState, GroupRole};
use crate::groups::state_commit::{self, ActionKind, RosterMemberSnapshot};
use crate::groups::{owner_cert, GroupInfo};
use crate::identity::{AgentCertificate, AgentKeypair};

/// The typed direct-message prefix of a `CertificateRebindV1` frame.
pub const CERTIFICATE_REBIND_PREFIX: &[u8] = b"X0XCRB1";

/// The outer agent-signature domain.
pub const CERTIFICATE_REBIND_SIGNATURE_DOMAIN: &[u8] = b"x0x.certificate-rebind.v1";

/// The frozen v1 `CertificateRebindV1` body (§4a "Wire"). Field order is
/// the postcard layout; a later layout needs a new prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRebindBodyV1 {
    /// The group's stable ID.
    pub stable_group_id: String,
    /// The seat whose certificate is rebound (raw agent ID).
    pub seat: [u8; 32],
    /// The signer (raw agent ID): an eligible admin, or the seat's own
    /// agent.
    pub signer: [u8; 32],
    /// The parent head (`state_hash`) this rebind extends.
    pub prior_head: String,
    /// The `state_revision` after the rebind (parent revision + 1).
    pub next_revision: u64,
    /// The committed certificate digest being replaced.
    pub old_certificate_digest: String,
    /// The renewed certificate: its canonical bincode bytes, the same
    /// bytes the roster digest covers.
    pub new_certificate: Vec<u8>,
    /// The signed `GroupStateCommit` of the rebind.
    pub commit: CommitHeaderV1,
}

/// A signed `CertificateRebindV1` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCertificateRebindV1 {
    /// The body.
    pub body: CertificateRebindBodyV1,
    /// ML-DSA-65 signature by `body.signer` over [`signable_bytes`].
    pub signature: Vec<u8>,
}

/// Why a frame or a rebind is refused. [`Self::as_str`] gives the typed
/// reason in logs, status and API refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertificateRebindRefusal {
    /// Not an `X0XCRB1` payload.
    WrongPrefix,
    /// The body did not decode or was not consumed exactly.
    Malformed,
    /// The outer signature or the commit signature does not verify, or the
    /// signer is not the commit signer.
    BadSignature,
    /// The group ID does not match.
    GroupMismatch,
    /// The group is withdrawn or holds a fork-quarantine marker.
    GroupContained,
    /// The parent head is not this node's current head.
    HeadMismatch,
    /// The next revision is not exactly the parent revision + 1.
    RevisionMismatch,
    /// The signer is not an eligible admin on the parent roster and not the
    /// seat's own agent, or it is revoked (§4a).
    SignerIneligible,
    /// The seat is not Active (Removed, banned, pending or absent).
    SeatNotActive,
    /// The seat's committed digest differs from the body's old digest.
    DigestMismatch,
    /// The new certificate does not verify against the group owner for
    /// that agent, is revoked or expired, or the group has no owner axis.
    CertificateInvalid,
    /// The new certificate's `not_after` is not later than the committed
    /// one.
    NotLater,
    /// This node lacks the committed certificate bytes for the seat, so it
    /// cannot compare `not_after` yet (§1a `waiting_for_certificate_evidence`).
    /// A local wait, not a sender defect.
    CertificateEvidenceMissing,
    /// The commit changes more than the seat's certificate and digest.
    StateMismatch,
    /// Signing or sealing failed locally.
    SealFailed,
}

impl CertificateRebindRefusal {
    /// The typed reason string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongPrefix => "wrong_prefix",
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::GroupMismatch => "group_mismatch",
            Self::GroupContained => "group_contained",
            Self::HeadMismatch => "head_mismatch",
            Self::RevisionMismatch => "revision_mismatch",
            Self::SignerIneligible => "rebind_signer_ineligible",
            Self::SeatNotActive => "rebind_seat_not_active",
            Self::DigestMismatch => "rebind_digest_mismatch",
            Self::CertificateInvalid => "rebind_certificate_invalid",
            Self::NotLater => "rebind_not_later",
            Self::CertificateEvidenceMissing => "waiting_for_certificate_evidence",
            Self::StateMismatch => "state_mismatch",
            Self::SealFailed => "seal_failed",
        }
    }
}

impl std::fmt::Display for CertificateRebindRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CertificateRebindRefusal {}

/// Who signed an accepted rebind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebindSigner {
    /// An eligible admin on the parent roster.
    Admin,
    /// The seat's own agent (§4 named exception, D129).
    SeatAgent,
}

impl RebindSigner {
    /// The ordinary apply-side authority check the embedded commit must
    /// also pass. An admin signer passes `AdminOrHigher`; the seat's own
    /// agent passes `MemberSelf`, and [`validate_against_parent`] narrows
    /// that to a change of its own certificate only.
    #[must_use]
    pub fn action_kind(self) -> ActionKind {
        match self {
            Self::Admin => ActionKind::AdminOrHigher,
            Self::SeatAgent => ActionKind::MemberSelf,
        }
    }
}

/// The bytes the outer signature covers: the domain, then the
/// length-prefixed canonical postcard body.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn signable_bytes(body: &CertificateRebindBodyV1) -> Result<Vec<u8>, postcard::Error> {
    let encoded = postcard::to_stdvec(body)?;
    let mut out = Vec::with_capacity(
        CERTIFICATE_REBIND_SIGNATURE_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(encoded.len()),
    );
    out.extend_from_slice(CERTIFICATE_REBIND_SIGNATURE_DOMAIN);
    out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Sign a body with the signer's agent key.
///
/// # Errors
///
/// Returns [`CertificateRebindRefusal::SignerIneligible`] when the keypair
/// is not the body's signer, [`CertificateRebindRefusal::Malformed`] when
/// the body does not encode and [`CertificateRebindRefusal::SealFailed`]
/// when signing fails.
pub fn sign(
    body: CertificateRebindBodyV1,
    keypair: &AgentKeypair,
) -> Result<SignedCertificateRebindV1, CertificateRebindRefusal> {
    if keypair.agent_id().as_bytes() != &body.signer {
        return Err(CertificateRebindRefusal::SignerIneligible);
    }
    let bytes = signable_bytes(&body).map_err(|_| CertificateRebindRefusal::Malformed)?;
    let signature = sign_with_ml_dsa(keypair.secret_key(), &bytes)
        .map_err(|_| CertificateRebindRefusal::SealFailed)?;
    Ok(SignedCertificateRebindV1 {
        body,
        signature: signature.as_bytes().to_vec(),
    })
}

/// Encode a signed frame as a direct-message payload.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_frame(frame: &SignedCertificateRebindV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = CERTIFICATE_REBIND_PREFIX.to_vec();
    out.extend(postcard::to_stdvec(frame)?);
    Ok(out)
}

/// Decode a frame with exact consumption. This checks the shape only; use
/// [`verify_signatures`] and [`validate_against_parent`] before any use.
///
/// # Errors
///
/// Returns why the payload is refused.
pub fn decode_frame(payload: &[u8]) -> Result<SignedCertificateRebindV1, CertificateRebindRefusal> {
    let body = payload
        .strip_prefix(CERTIFICATE_REBIND_PREFIX)
        .ok_or(CertificateRebindRefusal::WrongPrefix)?;
    let (frame, rest) = postcard::take_from_bytes::<SignedCertificateRebindV1>(body)
        .map_err(|_| CertificateRebindRefusal::Malformed)?;
    if !rest.is_empty() {
        return Err(CertificateRebindRefusal::Malformed);
    }
    Ok(frame)
}

/// Verify the outer signature and the embedded commit's own signature and
/// structure. The commit's signer key derives the signer's agent ID
/// (`GroupStateCommit::verify_structure`), and that same key verifies the
/// outer signature, so the signer signed both.
///
/// # Errors
///
/// Returns [`CertificateRebindRefusal::BadSignature`] or
/// [`CertificateRebindRefusal::Malformed`].
pub fn verify_signatures(
    frame: &SignedCertificateRebindV1,
) -> Result<(), CertificateRebindRefusal> {
    let body = &frame.body;
    let commit = body.commit.to_commit();
    commit
        .verify_structure()
        .map_err(|_| CertificateRebindRefusal::BadSignature)?;
    if commit.committed_by != hex::encode(body.signer) {
        return Err(CertificateRebindRefusal::BadSignature);
    }
    let key_bytes = hex::decode(&commit.signer_public_key)
        .map_err(|_| CertificateRebindRefusal::BadSignature)?;
    let key = MlDsaPublicKey::from_bytes(&key_bytes)
        .map_err(|_| CertificateRebindRefusal::BadSignature)?;
    let signature = MlDsaSignature::from_bytes(&frame.signature)
        .map_err(|_| CertificateRebindRefusal::BadSignature)?;
    let bytes = signable_bytes(body).map_err(|_| CertificateRebindRefusal::Malformed)?;
    verify_with_ml_dsa(&key, &bytes, &signature).map_err(|_| CertificateRebindRefusal::BadSignature)
}

/// Decode certificate bytes with exact, canonical consumption: the bytes
/// must be the canonical bincode encoding of the certificate, the same
/// bytes its roster digest covers.
#[must_use]
pub fn decode_certificate(bytes: &[u8]) -> Option<AgentCertificate> {
    let cert: AgentCertificate = bincode::deserialize(bytes).ok()?;
    let canonical = bincode::serialize(&cert).ok()?;
    (canonical == bytes).then_some(cert)
}

/// The canonical bincode bytes of a certificate.
#[must_use]
pub fn encode_certificate(cert: &AgentCertificate) -> Option<Vec<u8>> {
    bincode::serialize(cert).ok()
}

/// The committed certificate digest of a seat: the committed digest, or
/// the digest of embedded bytes on a legacy entry without one.
#[must_use]
pub fn committed_digest(member: &GroupMember) -> Option<String> {
    member.certificate_digest.clone().or_else(|| {
        member
            .certificate
            .as_ref()
            .map(owner_cert::certificate_digest_hex)
    })
}

/// The committed certificate bytes of a seat, when this node holds bytes
/// that match the committed digest (§1a "selected certificate").
#[must_use]
pub fn committed_certificate(member: &GroupMember) -> Option<&AgentCertificate> {
    let digest = committed_digest(member)?;
    member
        .certificate
        .as_ref()
        .filter(|cert| owner_cert::certificate_digest_hex(cert) == digest)
}

/// Whether `new` expires later than `old`. A certificate with no
/// `not_after` never expires; nothing is later than it.
#[must_use]
pub fn expires_later(new: Option<u64>, old: Option<u64>) -> bool {
    match (new, old) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(new), Some(old)) => new > old,
    }
}

/// The self-rebind cutoff (D155): `not_after − τ` of the committed
/// certificate being replaced.
#[must_use]
pub fn rebind_cutoff(not_after: u64) -> u64 {
    not_after.saturating_sub(EXPIRY_TOLERANCE_SECS)
}

/// Whether the seat's own agent may still self-rebind on its own clock:
/// before the cutoff `not_after − τ`. A certificate without `not_after`
/// never reaches a cutoff.
#[must_use]
pub fn self_rebind_window_open(not_after: Option<u64>, now_unix: u64) -> bool {
    not_after.is_none_or(|not_after| now_unix < rebind_cutoff(not_after))
}

/// §4a mixed versions (D129): an ordinary rebind (admin, or a self-rebind
/// outside §4b(2)) is used only when every other Active member's current
/// verified advert sets `certificate_rebind_v1`. Unknown or expired support
/// (`None`) and a lacking advert (`Some(false)`) both disable it; the seat
/// is then evicted as in §1a.
#[must_use]
pub fn rebind_allowed_for_members(supports: impl IntoIterator<Item = Option<bool>>) -> bool {
    supports.into_iter().all(|support| support == Some(true))
}

/// §1a and §4b(2): when every admin other than `target` holds an expired
/// selected certificate on this node's clock (own trigger, `not_after +
/// τ`), the admins that need a renewal in raw-ID order; `None` when an
/// admin other than the target holds an unexpired certificate, or when no
/// other admin exists. `admins` pairs each Admin-or-higher Active seat with
/// its selected certificate's `not_after` (`None`: never expires, or no
/// bytes held).
#[must_use]
pub fn admins_needing_renewal(
    admins: &[([u8; 32], Option<u64>)],
    target: &[u8; 32],
    now_unix: u64,
) -> Option<Vec<[u8; 32]>> {
    let mut others: Vec<([u8; 32], Option<u64>)> = admins
        .iter()
        .copied()
        .filter(|(id, _)| id != target)
        .collect();
    if others.is_empty() {
        return None;
    }
    let all_expired = others.iter().all(|(_, not_after)| {
        not_after.is_some_and(|not_after| own_expiry_trigger_due(not_after, now_unix))
    });
    if !all_expired {
        return None;
    }
    others.sort_unstable();
    others.dedup();
    Some(others.into_iter().map(|(id, _)| id).collect())
}

/// The receiver's L4 acceptance rule (§4a "Receiver checks") against its
/// current verified parent state. Returns the signer kind and the decoded
/// renewed certificate.
///
/// `is_revoked` is this node's current agent-revocation set. A caller
/// holds the group's membership lock and calls this immediately before it
/// applies the commit. `now_unix` is this node's wall clock.
///
/// The embedded commit must still pass the ordinary apply checks
/// ([`apply_to_parent`], or the daemon's shared apply hook): signature,
/// prev-hash, the [`RebindSigner::action_kind`] authority, the recomputed
/// post-state hash (so a commit that changes anything other than this
/// seat's certificate and digest fails), fork and last-admin checks.
///
/// # Errors
///
/// Returns the first failed check.
pub fn validate_against_parent(
    body: &CertificateRebindBodyV1,
    parent: &GroupInfo,
    now_unix: u64,
    is_revoked: impl Fn(&[u8; 32]) -> bool,
) -> Result<(RebindSigner, AgentCertificate), CertificateRebindRefusal> {
    if body.stable_group_id != parent.stable_group_id()
        || body.commit.group_id != parent.stable_group_id()
    {
        return Err(CertificateRebindRefusal::GroupMismatch);
    }
    if parent.withdrawn || parent.fork_quarantine.is_some() || body.commit.withdrawn {
        return Err(CertificateRebindRefusal::GroupContained);
    }
    if body.prior_head != parent.state_hash
        || body.commit.prev_state_hash.as_deref() != Some(parent.state_hash.as_str())
    {
        return Err(CertificateRebindRefusal::HeadMismatch);
    }
    if body.next_revision != parent.state_revision.saturating_add(1)
        || body.commit.revision != body.next_revision
    {
        return Err(CertificateRebindRefusal::RevisionMismatch);
    }
    let signer_hex = hex::encode(body.signer);
    let seat_hex = hex::encode(body.seat);
    let signer_is_admin = parent.members_v2.get(&signer_hex).is_some_and(|member| {
        member.state == GroupMemberState::Active && member.role.at_least(GroupRole::Admin)
    });
    if is_revoked(&body.signer) || (!signer_is_admin && body.signer != body.seat) {
        return Err(CertificateRebindRefusal::SignerIneligible);
    }
    // "An eligible current admin" (§2, §4a): an admin that rebinds another
    // seat must hold a selected certificate that is not expired on this
    // node's clock (`not_after + τ`, §1a). The seat's own agent signs under
    // the §4 named exception instead, which is how an expired admin renews
    // itself (§4b(2)). Missing bytes do not refuse here, as for the local
    // committer rule: the digest check below still binds the seat.
    if body.signer != body.seat
        && parent
            .members_v2
            .get(&signer_hex)
            .and_then(committed_certificate)
            .and_then(AgentCertificate::not_after)
            .is_some_and(|not_after| own_expiry_trigger_due(not_after, now_unix))
    {
        return Err(CertificateRebindRefusal::SignerIneligible);
    }
    let Some(seat) = parent
        .members_v2
        .get(&seat_hex)
        .filter(|member| member.state == GroupMemberState::Active)
    else {
        return Err(CertificateRebindRefusal::SeatNotActive);
    };
    if committed_digest(seat).as_deref() != Some(body.old_certificate_digest.as_str()) {
        return Err(CertificateRebindRefusal::DigestMismatch);
    }
    let Some(owner) = parent.policy.admission.owner_certified_user_id() else {
        return Err(CertificateRebindRefusal::CertificateInvalid);
    };
    let Some(new_cert) = decode_certificate(&body.new_certificate) else {
        return Err(CertificateRebindRefusal::CertificateInvalid);
    };
    owner_cert::verify_cert_against_owner(
        owner,
        &seat_hex,
        &new_cert,
        is_revoked(&body.seat),
        now_unix,
    )
    .map_err(|_| CertificateRebindRefusal::CertificateInvalid)?;
    let Some(old_cert) = committed_certificate(seat) else {
        return Err(CertificateRebindRefusal::CertificateEvidenceMissing);
    };
    if owner_cert::certificate_digest_hex(&new_cert) == body.old_certificate_digest
        || !expires_later(new_cert.not_after(), old_cert.not_after())
    {
        return Err(CertificateRebindRefusal::NotLater);
    }
    let signer = if signer_is_admin {
        RebindSigner::Admin
    } else {
        RebindSigner::SeatAgent
    };
    Ok((signer, new_cert))
}

/// ADR 0110 §2 (#1508 rc18): the checks this node can make on a rebind
/// that does not chain on its head `latest` yet, before the rebind may
/// count as known higher-head evidence. The caller verified both
/// signatures ([`verify_signatures`]). The signer must have standing on
/// `latest`: an Active, unrevoked admin, or the seat's own agent; and the
/// new certificate must verify against the group owner for the seat. A
/// rebind that fails stays unverified: it is kept for a retry but holds
/// nothing.
///
/// # Errors
///
/// The [`CertificateRebindRefusal`] of the first check that fails.
pub fn check_ahead(
    body: &CertificateRebindBodyV1,
    latest: &GroupInfo,
    now_unix: u64,
    is_revoked: impl Fn(&[u8; 32]) -> bool,
) -> Result<(), CertificateRebindRefusal> {
    if body.stable_group_id != latest.stable_group_id()
        || body.commit.group_id != latest.stable_group_id()
    {
        return Err(CertificateRebindRefusal::GroupMismatch);
    }
    let signer = latest
        .members_v2
        .get(&hex::encode(body.signer))
        .filter(|member| member.state == GroupMemberState::Active)
        .ok_or(CertificateRebindRefusal::SignerIneligible)?;
    if is_revoked(&body.signer)
        || (body.signer != body.seat && !signer.role.at_least(GroupRole::Admin))
    {
        return Err(CertificateRebindRefusal::SignerIneligible);
    }
    let owner = latest
        .policy
        .admission
        .owner_certified_user_id()
        .ok_or(CertificateRebindRefusal::CertificateInvalid)?;
    let new_cert = decode_certificate(&body.new_certificate)
        .ok_or(CertificateRebindRefusal::CertificateInvalid)?;
    owner_cert::verify_cert_against_owner(
        owner,
        &hex::encode(body.seat),
        &new_cert,
        is_revoked(&body.seat),
        now_unix,
    )
    .map_err(|_| CertificateRebindRefusal::CertificateInvalid)
}

/// ADR 0110 §2 fork containment and §4a "Receiver checks": whether
/// `body`, which [`validate_against_parent`] refused with
/// `rebind_head_mismatch` on `current`, is a valid rebind on a sibling
/// branch of `current`'s retained chain. Only such a rebind is fork
/// evidence (#1508 Codex P1 A).
///
/// The parent is the retained commit whose `state_hash` is the body's
/// `prior_head`, and `current` retains a different commit at the same
/// revision on that parent. The §4a checks then run against the parent's
/// retained roster: the signer is not revoked and is an Active admin there
/// or the seat's own agent; an admin signer's selected certificate is not
/// expired; the seat is Active with the body's old digest; the new
/// certificate verifies against the group owner for the seat and is not
/// the old one. The commit changes only that seat's certificate digest:
/// its roster root is the parent's roster with the new digest, and its
/// policy, metadata and security binding are the parent's.
///
/// The parent snapshot keeps digests, not certificate bytes. The old and
/// the admin certificates are taken from `current` when their digests
/// match, and they are required: the new certificate must expire later
/// than the old one, and an admin signer's certificate must not be
/// expired (#1533 r11). A sibling quarantines the whole group, so it is
/// never trusted without that parent evidence. When this node's own
/// branch replaced a certificate, the displaced bytes are retained by
/// digest ([`GroupInfo::displaced_certificates`], #1650), so the checks
/// still run in full and the sibling records as fork evidence. Only a
/// node that holds no bytes for the parent's committed digest (live or
/// retained, for example a digest-only roster) refuses with
/// `rebind_certificate_evidence_missing`: it records nothing (an
/// unverifiable sibling is never accepted as evidence, #1533 r11).
///
/// The caller has already run [`verify_signatures`], so the signer signed
/// the frame and the embedded commit.
///
/// # Errors
///
/// Returns the first failed check; `rebind_head_mismatch` when the parent
/// is not retained or the body is no sibling of the retained chain.
pub fn validate_sibling(
    body: &CertificateRebindBodyV1,
    current: &GroupInfo,
    now_unix: u64,
    is_revoked: impl Fn(&[u8; 32]) -> bool,
) -> Result<RebindSigner, CertificateRebindRefusal> {
    if body.stable_group_id != current.stable_group_id()
        || body.commit.group_id != current.stable_group_id()
    {
        return Err(CertificateRebindRefusal::GroupMismatch);
    }
    if current.withdrawn || current.fork_quarantine.is_some() || body.commit.withdrawn {
        return Err(CertificateRebindRefusal::GroupContained);
    }
    if body.commit.prev_state_hash.as_deref() != Some(body.prior_head.as_str()) {
        return Err(CertificateRebindRefusal::HeadMismatch);
    }
    let Some(parent) = current
        .commit_log
        .iter()
        .find(|retained| retained.commit.state_hash == body.prior_head)
    else {
        return Err(CertificateRebindRefusal::HeadMismatch);
    };
    if body.next_revision != parent.commit.revision.saturating_add(1)
        || body.commit.revision != body.next_revision
    {
        return Err(CertificateRebindRefusal::RevisionMismatch);
    }
    let sibling = current.commit_log.iter().any(|retained| {
        retained.commit.prev_state_hash.as_deref() == Some(body.prior_head.as_str())
            && retained.commit.revision == body.next_revision
            && retained.commit.state_hash != body.commit.state_hash
    });
    if !sibling {
        return Err(CertificateRebindRefusal::HeadMismatch);
    }
    let signer_hex = hex::encode(body.signer);
    let seat_hex = hex::encode(body.seat);
    let signer_at_parent = parent.roster.get(&signer_hex);
    let signer_is_admin = signer_at_parent.is_some_and(|snapshot| {
        snapshot.state == GroupMemberState::Active && snapshot.role.at_least(GroupRole::Admin)
    });
    if is_revoked(&body.signer) || (!signer_is_admin && body.signer != body.seat) {
        return Err(CertificateRebindRefusal::SignerIneligible);
    }
    let held_certificate = |id: &str, digest: Option<&String>| {
        current
            .members_v2
            .get(id)
            .and_then(committed_certificate)
            .filter(|cert| Some(&owner_cert::certificate_digest_hex(cert)) == digest)
            // #1650: this node's own branch may have displaced the parent
            // certificate; the retained copy verifies the sibling.
            .or_else(|| {
                current
                    .displaced_certificates
                    .get(digest?)
                    .map(|retained| &retained.certificate)
            })
    };
    if body.signer != body.seat {
        let signer_cert = held_certificate(
            &signer_hex,
            signer_at_parent.and_then(|snapshot| snapshot.certificate_digest.as_ref()),
        )
        .ok_or(CertificateRebindRefusal::CertificateEvidenceMissing)?;
        if signer_cert
            .not_after()
            .is_some_and(|not_after| own_expiry_trigger_due(not_after, now_unix))
        {
            return Err(CertificateRebindRefusal::SignerIneligible);
        }
    }
    let Some(seat) = parent
        .roster
        .get(&seat_hex)
        .filter(|snapshot| snapshot.state == GroupMemberState::Active)
    else {
        return Err(CertificateRebindRefusal::SeatNotActive);
    };
    if seat.certificate_digest.as_deref() != Some(body.old_certificate_digest.as_str()) {
        return Err(CertificateRebindRefusal::DigestMismatch);
    }
    let Some(owner) = current.policy.admission.owner_certified_user_id() else {
        return Err(CertificateRebindRefusal::CertificateInvalid);
    };
    let Some(new_cert) = decode_certificate(&body.new_certificate) else {
        return Err(CertificateRebindRefusal::CertificateInvalid);
    };
    owner_cert::verify_cert_against_owner(
        owner,
        &seat_hex,
        &new_cert,
        is_revoked(&body.seat),
        now_unix,
    )
    .map_err(|_| CertificateRebindRefusal::CertificateInvalid)?;
    let new_digest = owner_cert::certificate_digest_hex(&new_cert);
    let old_cert = held_certificate(&seat_hex, seat.certificate_digest.as_ref())
        .ok_or(CertificateRebindRefusal::CertificateEvidenceMissing)?;
    if new_digest == body.old_certificate_digest
        || !expires_later(new_cert.not_after(), old_cert.not_after())
    {
        return Err(CertificateRebindRefusal::NotLater);
    }
    let mut roster = parent.roster.clone();
    if let Some(snapshot) = roster.get_mut(&seat_hex) {
        snapshot.certificate_digest = Some(new_digest);
    }
    if body.commit.roster_root != state_commit::roster_root_of_projection(&roster)
        || body.commit.policy_hash != parent.commit.policy_hash
        || body.commit.public_meta_hash != parent.commit.public_meta_hash
        || body.commit.security_binding != parent.commit.security_binding
    {
        return Err(CertificateRebindRefusal::StateMismatch);
    }
    Ok(if signer_is_admin {
        RebindSigner::Admin
    } else {
        RebindSigner::SeatAgent
    })
}

/// Bind `cert` into `seat_hex`'s entry: its committed certificate and
/// digest. Nothing else changes. A certificate the seat already holds with
/// a different digest is displaced: it is retained by digest (#1650) so a
/// later competing sibling rebind on the same parent stays fully
/// verifiable.
pub fn install_certificate(info: &mut GroupInfo, seat_hex: &str, cert: AgentCertificate) {
    let new_digest = owner_cert::certificate_digest_hex(&cert);
    let displaced = info.members_v2.get(seat_hex).and_then(|member| {
        let displaced = member.certificate.clone()?;
        (owner_cert::certificate_digest_hex(&displaced) != new_digest).then_some(displaced)
    });
    if let Some(displaced) = displaced {
        retain_displaced_certificate(info, displaced);
    }
    if let Some(member) = info.members_v2.get_mut(seat_hex) {
        member.certificate_digest = Some(new_digest);
        member.certificate = Some(cert);
    }
}

/// The retained-evidence bound per group (#1650). A rebind displaces at
/// most one certificate, so this caps the retained history — and the
/// sidecar record, one ML-DSA-65 certificate per entry — at
/// `DISPLACED_CERTIFICATE_CAP` rebinds per group.
pub const DISPLACED_CERTIFICATE_CAP: usize = 16;

/// One entry of [`GroupInfo::displaced_certificates`]: the displaced
/// bytes plus their retention recency. `retained_seq` is a per-group
/// monotonic counter — each retention takes `max + 1` — so
/// [`enforce_displaced_certificate_cap`] can always tell the oldest
/// retention from the newest parent evidence. It persists with the
/// entry in the S4 sidecar, so the eviction order survives a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedCertificate {
    /// The displaced certificate bytes: the parent evidence a later
    /// sibling rebind is checked against.
    pub certificate: AgentCertificate,
    /// Retention recency within the group; higher is newer.
    pub retained_seq: u64,
}

/// Retain `cert` as the parent evidence a later sibling rebind is checked
/// against (#1650, ADR 0110 §4a), keyed by the digest the parent roster
/// signed. The entry takes the newest `retained_seq`, so the cap
/// enforcement below can never evict it — the next competing sibling
/// needs exactly the certificate just displaced.
fn retain_displaced_certificate(info: &mut GroupInfo, cert: AgentCertificate) {
    let retained = owner_cert::certificate_digest_hex(&cert);
    let retained_seq = info
        .displaced_certificates
        .values()
        .map(|entry| entry.retained_seq)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    info.displaced_certificates.insert(
        retained,
        RetainedCertificate {
            certificate: cert,
            retained_seq,
        },
    );
    enforce_displaced_certificate_cap(info);
}

/// Enforce [`DISPLACED_CERTIFICATE_CAP`] by retention recency: the
/// lowest `retained_seq` — the oldest retention — is dropped first, so
/// the newest parent evidence is never the entry evicted (#1650 review:
/// the cache must keep the most recent parent evidence, not the largest
/// digest keys). An eviction only drops evidence, it never weakens a
/// check — a sibling whose parent bytes were evicted is again refused
/// with `rebind_certificate_evidence_missing` and records nothing, as
/// before #1650.
pub fn enforce_displaced_certificate_cap(info: &mut GroupInfo) {
    while info.displaced_certificates.len() > DISPLACED_CERTIFICATE_CAP {
        let Some(dropped) = info
            .displaced_certificates
            .iter()
            .min_by_key(|(_, entry)| entry.retained_seq)
            .map(|(digest, _)| digest.clone())
        else {
            break;
        };
        info.displaced_certificates.remove(&dropped);
    }
}

/// #1650 (review P2): retain the parent certificates a wholesale roster
/// replacement displaces — the SignedPublic catch-up install path. The
/// winner's snapshot commits the new digests and carries no foreign
/// retained evidence (it is stripped outbound and refused inbound), so
/// without this the bytes this node held from the parent are gone and a
/// competing sibling rebind on that parent is refused with
/// `rebind_certificate_evidence_missing` — which records nothing —
/// instead of verifying as fork evidence. A seat whose committed digest
/// the replacement leaves unchanged retains nothing.
pub fn retain_displaced_by_roster_replacement(next: &mut GroupInfo, parent: &GroupInfo) {
    for (seat, parent_member) in &parent.members_v2 {
        let Some(displaced) = parent_member.certificate.as_ref() else {
            continue;
        };
        let displaced_digest = owner_cert::certificate_digest_hex(displaced);
        let installed = next.members_v2.get(seat).and_then(|member| {
            member.certificate_digest.clone().or_else(|| {
                member
                    .certificate
                    .as_ref()
                    .map(owner_cert::certificate_digest_hex)
            })
        });
        if installed.as_deref() != Some(displaced_digest.as_str()) {
            retain_displaced_certificate(next, displaced.clone());
        }
    }
}

/// Apply an accepted rebind to a copy of the parent: the ordinary apply
/// checks for `signer`'s authority, the certificate install, then the
/// recomputed post-state hash check.
///
/// # Errors
///
/// Returns [`CertificateRebindRefusal::StateMismatch`] when the ordinary
/// checks fail.
pub fn apply_to_parent(
    parent: &GroupInfo,
    body: &CertificateRebindBodyV1,
    signer: RebindSigner,
    cert: AgentCertificate,
) -> Result<GroupInfo, CertificateRebindRefusal> {
    let commit = body.commit.to_commit();
    let ctx = state_commit::ApplyContext {
        current_state_hash: &parent.state_hash,
        current_revision: parent.state_revision,
        current_withdrawn: parent.withdrawn,
        members_v2: &parent.members_v2,
        // #1578 rc11 (Claude blocking 1, audit): the join's key-only
        // marker row is not a seat for the authority check either.
        join_seat_marker_agents: parent.join_seat_key_marker_agents(),
        group_id: parent.stable_group_id(),
    };
    state_commit::validate_apply(&ctx, &commit, signer.action_kind())
        .map_err(|_| CertificateRebindRefusal::StateMismatch)?;
    let mut next = parent.clone();
    install_certificate(&mut next, &hex::encode(body.seat), cert);
    next.finalize_applied_commit(&commit)
        .map_err(|_| CertificateRebindRefusal::StateMismatch)?;
    Ok(next)
}

/// Author a rebind of `seat`'s certificate on `parent`, signed by
/// `keypair`. Returns the post-state and the signed frame. The caller
/// checks the result with [`validate_against_parent`] before it persists
/// anything; `parent` is never changed.
///
/// # Errors
///
/// Returns [`CertificateRebindRefusal::SeatNotActive`] when the seat is
/// absent, [`CertificateRebindRefusal::DigestMismatch`] when it has no
/// committed digest, and a seal or signing failure otherwise.
pub fn seal(
    parent: &GroupInfo,
    seat: [u8; 32],
    cert: &AgentCertificate,
    keypair: &AgentKeypair,
    now_ms: u64,
) -> Result<(GroupInfo, SignedCertificateRebindV1), CertificateRebindRefusal> {
    let seat_hex = hex::encode(seat);
    let member = parent
        .members_v2
        .get(&seat_hex)
        .ok_or(CertificateRebindRefusal::SeatNotActive)?;
    let old_certificate_digest =
        committed_digest(member).ok_or(CertificateRebindRefusal::DigestMismatch)?;
    let new_certificate =
        encode_certificate(cert).ok_or(CertificateRebindRefusal::CertificateInvalid)?;
    let mut next = parent.clone();
    install_certificate(&mut next, &seat_hex, cert.clone());
    let commit = next
        .seal_commit_inner(keypair, now_ms)
        .map_err(|_| CertificateRebindRefusal::SealFailed)?;
    let body = CertificateRebindBodyV1 {
        stable_group_id: parent.stable_group_id().to_string(),
        seat,
        signer: *keypair.agent_id().as_bytes(),
        prior_head: parent.state_hash.clone(),
        next_revision: commit.revision,
        old_certificate_digest,
        new_certificate,
        commit: CommitHeaderV1::from(&commit),
    };
    let frame = sign(body, keypair)?;
    Ok((next, frame))
}

/// The ADR 0064 Decision 2 ancestor-walk exception (§4 named exception):
/// a retained link whose committer is not an admin is accepted only when
/// it is a self-rebind. The committer is Active on the predecessor
/// roster, and the link roster equals the predecessor roster except that
/// the committer's own certificate digest changed to another committed
/// digest. Role, state, leaf and every other entry stay unchanged. The
/// link is not an owner anchor.
#[must_use]
pub fn is_self_rebind_link(
    predecessor: &BTreeMap<String, RosterMemberSnapshot>,
    link: &BTreeMap<String, RosterMemberSnapshot>,
    committer: &str,
) -> bool {
    let (Some(before), Some(after)) = (predecessor.get(committer), link.get(committer)) else {
        return false;
    };
    if before.state != GroupMemberState::Active
        || after.state != GroupMemberState::Active
        || before.role != after.role
        || before.treekem_key_package_hash != after.treekem_key_package_hash
        || after.certificate_digest.is_none()
        || before.certificate_digest == after.certificate_digest
    {
        return false;
    }
    if predecessor.len() != link.len() {
        return false;
    }
    predecessor
        .iter()
        .all(|(id, snapshot)| id == committer || link.get(id) == Some(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::policy::GroupAdmission;
    use crate::identity::UserKeypair;

    const NOW: u64 = 1_000_000;

    struct Fixture {
        owner: UserKeypair,
        admin: AgentKeypair,
        member: AgentKeypair,
        info: GroupInfo,
    }

    fn agent() -> AgentKeypair {
        AgentKeypair::generate().expect("agent keypair")
    }

    fn cert(owner: &UserKeypair, agent: &AgentKeypair, not_after: Option<u64>) -> AgentCertificate {
        AgentCertificate::issue_with_expiry(owner, agent, not_after).expect("issue")
    }

    fn hex_of(agent: &AgentKeypair) -> String {
        hex::encode(agent.agent_id().as_bytes())
    }

    /// An `OwnerCertified` group with admin `admin` and member `member`,
    /// each seated with a committed certificate expiring at `NOW + 600`.
    fn fixture() -> Fixture {
        let owner = UserKeypair::generate().expect("user keypair");
        let admin = agent();
        let member = agent();
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            admin.agent_id(),
            "ab".repeat(16),
        );
        info.policy.admission = GroupAdmission::OwnerCertified(owner.user_id());
        let member_hex = hex_of(&member);
        info.members_v2.insert(
            member_hex.clone(),
            GroupMember::new_member(member_hex.clone(), None, Some(hex_of(&admin)), 1),
        );
        install_certificate(
            &mut info,
            &hex_of(&admin),
            cert(&owner, &admin, Some(NOW + 600)),
        );
        install_certificate(
            &mut info,
            &member_hex,
            cert(&owner, &member, Some(NOW + 600)),
        );
        info.recompute_state_hash();
        Fixture {
            owner,
            admin,
            member,
            info,
        }
    }

    fn rebind(
        fixture: &Fixture,
        signer: &AgentKeypair,
        seat: &AgentKeypair,
        not_after: Option<u64>,
    ) -> SignedCertificateRebindV1 {
        let renewal = cert(&fixture.owner, seat, not_after);
        seal(
            &fixture.info,
            *seat.agent_id().as_bytes(),
            &renewal,
            signer,
            NOW * 1000,
        )
        .expect("seal")
        .1
    }

    fn resign(
        frame: SignedCertificateRebindV1,
        signer: &AgentKeypair,
    ) -> SignedCertificateRebindV1 {
        sign(frame.body, signer).expect("sign")
    }

    #[test]
    fn frame_round_trips_verifies_and_applies() {
        let f = fixture();
        let frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        let bytes = encode_frame(&frame).expect("encode");
        assert!(bytes.starts_with(CERTIFICATE_REBIND_PREFIX));
        let decoded = decode_frame(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        verify_signatures(&decoded).expect("signatures");
        let (signer, cert) =
            validate_against_parent(&decoded.body, &f.info, NOW, |_| false).expect("valid");
        assert_eq!(signer, RebindSigner::Admin);
        let next = apply_to_parent(&f.info, &decoded.body, signer, cert).expect("apply");
        // Only the seat's certificate and digest changed.
        let before = &f.info.members_v2[&hex_of(&f.member)];
        let after = &next.members_v2[&hex_of(&f.member)];
        assert_eq!(before.role, after.role);
        assert_eq!(before.state, after.state);
        assert_eq!(
            before.treekem_key_package_hash,
            after.treekem_key_package_hash
        );
        assert_ne!(before.certificate_digest, after.certificate_digest);
        assert_eq!(next.secret_epoch, f.info.secret_epoch);
        assert_eq!(next.security_binding, f.info.security_binding);
        assert_eq!(next.state_revision, f.info.state_revision + 1);
    }

    #[test]
    fn decode_requires_exact_consumption_and_prefix() {
        let f = fixture();
        let frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        let mut bytes = encode_frame(&frame).expect("encode");
        bytes.push(0);
        assert_eq!(
            decode_frame(&bytes),
            Err(CertificateRebindRefusal::Malformed)
        );
        assert_eq!(
            decode_frame(b"X0XCE1rest"),
            Err(CertificateRebindRefusal::WrongPrefix)
        );
        assert_eq!(
            decode_frame(b"X0XCRB1"),
            Err(CertificateRebindRefusal::Malformed)
        );
    }

    #[test]
    fn certificate_bytes_must_be_canonical() {
        let f = fixture();
        let renewal = cert(&f.owner, &f.member, Some(NOW + 6000));
        let mut bytes = encode_certificate(&renewal).expect("encode");
        assert!(decode_certificate(&bytes).is_some());
        bytes.push(0);
        assert!(decode_certificate(&bytes).is_none());
    }

    #[test]
    fn tampered_body_fails_the_outer_signature() {
        let f = fixture();
        let mut frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        frame.body.old_certificate_digest = "00".repeat(32);
        assert_eq!(
            verify_signatures(&frame),
            Err(CertificateRebindRefusal::BadSignature)
        );
    }

    #[test]
    fn other_key_cannot_sign_for_the_signer() {
        let f = fixture();
        let frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        assert_eq!(
            sign(frame.body, &f.member).err(),
            Some(CertificateRebindRefusal::SignerIneligible)
        );
    }

    #[test]
    fn seat_agent_self_rebind_is_accepted_under_member_self() {
        let f = fixture();
        let frame = rebind(&f, &f.member, &f.member, Some(NOW + 6000));
        verify_signatures(&frame).expect("signatures");
        let (signer, cert) =
            validate_against_parent(&frame.body, &f.info, NOW, |_| false).expect("valid");
        assert_eq!(signer, RebindSigner::SeatAgent);
        assert_eq!(signer.action_kind(), ActionKind::MemberSelf);
        apply_to_parent(&f.info, &frame.body, signer, cert).expect("apply");
    }

    #[test]
    fn non_admin_cannot_rebind_another_seat() {
        let f = fixture();
        let frame = rebind(&f, &f.member, &f.admin, Some(NOW + 6000));
        assert_eq!(
            validate_against_parent(&frame.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::SignerIneligible)
        );
    }

    /// §2/§4a "an eligible current admin": an admin whose own selected
    /// certificate expired on the receiver's clock (`not_after + τ`) may not
    /// rebind another seat. It may still rebind its own seat (§4b(2)).
    #[test]
    fn expired_admin_cannot_rebind_another_seat_but_can_rebind_itself() {
        let f = fixture();
        // The fixture's admin certificate expires at NOW + 600.
        let after_expiry = NOW + 600 + EXPIRY_TOLERANCE_SECS + 1;
        let other = rebind(&f, &f.admin, &f.member, Some(NOW + 60_000));
        assert_eq!(
            validate_against_parent(&other.body, &f.info, after_expiry, |_| false).err(),
            Some(CertificateRebindRefusal::SignerIneligible)
        );
        // Within τ of `not_after` the admin is still eligible.
        validate_against_parent(&other.body, &f.info, NOW + 600, |_| false)
            .expect("within tolerance");
        let own = rebind(&f, &f.admin, &f.admin, Some(NOW + 60_000));
        let (signer, _) = validate_against_parent(&own.body, &f.info, after_expiry, |_| false)
            .expect("the expired admin's self-rebind");
        assert_eq!(signer, RebindSigner::Admin);
    }

    #[test]
    fn revoked_signer_is_refused() {
        let f = fixture();
        let frame = rebind(&f, &f.member, &f.member, Some(NOW + 6000));
        let revoked = *f.member.agent_id().as_bytes();
        assert_eq!(
            validate_against_parent(&frame.body, &f.info, NOW, |id| *id == revoked).err(),
            Some(CertificateRebindRefusal::SignerIneligible)
        );
    }

    #[test]
    fn removed_seat_is_refused() {
        let f = fixture();
        let frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        let mut removed = f.info.clone();
        removed.remove_member(&hex_of(&f.member), Some(hex_of(&f.admin)));
        removed.state_hash = f.info.state_hash.clone();
        assert_eq!(
            validate_against_parent(&frame.body, &removed, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::SeatNotActive)
        );
    }

    #[test]
    fn digest_mismatch_is_refused() {
        let f = fixture();
        let mut frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        frame.body.old_certificate_digest = "11".repeat(32);
        let frame = resign(frame, &f.admin);
        assert_eq!(
            validate_against_parent(&frame.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::DigestMismatch)
        );
    }

    #[test]
    fn certificate_from_another_owner_is_invalid() {
        let f = fixture();
        let other_owner = UserKeypair::generate().expect("user keypair");
        let foreign = cert(&other_owner, &f.member, Some(NOW + 6000));
        let frame = seal(
            &f.info,
            *f.member.agent_id().as_bytes(),
            &foreign,
            &f.admin,
            NOW * 1000,
        )
        .expect("seal")
        .1;
        assert_eq!(
            validate_against_parent(&frame.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::CertificateInvalid)
        );
    }

    #[test]
    fn certificate_for_another_agent_is_invalid() {
        let f = fixture();
        let wrong = cert(&f.owner, &f.admin, Some(NOW + 6000));
        let frame = seal(
            &f.info,
            *f.member.agent_id().as_bytes(),
            &wrong,
            &f.admin,
            NOW * 1000,
        )
        .expect("seal")
        .1;
        assert_eq!(
            validate_against_parent(&frame.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::CertificateInvalid)
        );
    }

    #[test]
    fn expired_renewal_is_invalid() {
        let f = fixture();
        // A self-rebind: at `late` the admin's own certificate has expired
        // too, which would refuse an admin signer first.
        let frame = rebind(&f, &f.member, &f.member, Some(NOW + 6000));
        let late = NOW + 6000 + EXPIRY_TOLERANCE_SECS + 1;
        assert_eq!(
            validate_against_parent(&frame.body, &f.info, late, |_| false).err(),
            Some(CertificateRebindRefusal::CertificateInvalid)
        );
    }

    #[test]
    fn older_or_equal_certificate_is_not_later() {
        let f = fixture();
        let older = rebind(&f, &f.admin, &f.member, Some(NOW + 300));
        assert_eq!(
            validate_against_parent(&older.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::NotLater)
        );
        let same = rebind(&f, &f.admin, &f.member, Some(NOW + 600));
        assert_eq!(
            validate_against_parent(&same.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::NotLater)
        );
    }

    #[test]
    fn digest_only_seat_waits_for_certificate_evidence() {
        let f = fixture();
        let frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        let mut digest_only = f.info.clone();
        if let Some(member) = digest_only.members_v2.get_mut(&hex_of(&f.member)) {
            member.certificate = None;
        }
        assert_eq!(
            validate_against_parent(&frame.body, &digest_only, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::CertificateEvidenceMissing)
        );
    }

    #[test]
    fn stale_parent_and_wrong_revision_are_refused() {
        let f = fixture();
        let frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        let mut moved = f.info.clone();
        moved.state_hash = "other".to_string();
        assert_eq!(
            validate_against_parent(&frame.body, &moved, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::HeadMismatch)
        );
        let mut bumped = frame.clone();
        bumped.body.next_revision += 1;
        assert_eq!(
            validate_against_parent(&bumped.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::RevisionMismatch)
        );
        let mut quarantined = f.info.clone();
        quarantined.withdrawn = true;
        assert_eq!(
            validate_against_parent(&frame.body, &quarantined, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::GroupContained)
        );
    }

    #[test]
    fn group_without_owner_axis_refuses_the_certificate() {
        let mut f = fixture();
        f.info.policy.admission = GroupAdmission::InviteOnly;
        f.info.recompute_state_hash();
        let frame = rebind(&f, &f.admin, &f.member, Some(NOW + 6000));
        assert_eq!(
            validate_against_parent(&frame.body, &f.info, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::CertificateInvalid)
        );
    }

    #[test]
    fn commit_that_changes_more_than_the_certificate_fails_apply() {
        let f = fixture();
        // An admin seals a role change and presents it as a rebind.
        let renewal = cert(&f.owner, &f.member, Some(NOW + 6000));
        let mut next = f.info.clone();
        install_certificate(&mut next, &hex_of(&f.member), renewal.clone());
        if let Some(member) = next.members_v2.get_mut(&hex_of(&f.member)) {
            member.role = GroupRole::Admin;
        }
        let commit = next.seal_commit_inner(&f.admin, NOW * 1000).expect("seal");
        let body = CertificateRebindBodyV1 {
            stable_group_id: f.info.stable_group_id().to_string(),
            seat: *f.member.agent_id().as_bytes(),
            signer: *f.admin.agent_id().as_bytes(),
            prior_head: f.info.state_hash.clone(),
            next_revision: commit.revision,
            old_certificate_digest: committed_digest(&f.info.members_v2[&hex_of(&f.member)])
                .expect("digest"),
            new_certificate: encode_certificate(&renewal).expect("encode"),
            commit: CommitHeaderV1::from(&commit),
        };
        let (signer, cert) =
            validate_against_parent(&body, &f.info, NOW, |_| false).expect("parent checks");
        assert_eq!(
            apply_to_parent(&f.info, &body, signer, cert).err(),
            Some(CertificateRebindRefusal::StateMismatch)
        );
    }

    #[test]
    fn cutoff_is_not_after_minus_tau() {
        let not_after = NOW + 600;
        assert_eq!(rebind_cutoff(not_after), not_after - EXPIRY_TOLERANCE_SECS);
        assert!(self_rebind_window_open(
            Some(not_after),
            rebind_cutoff(not_after) - 1
        ));
        assert!(!self_rebind_window_open(
            Some(not_after),
            rebind_cutoff(not_after)
        ));
        assert!(self_rebind_window_open(None, u64::MAX));
    }

    #[test]
    fn later_ordering_treats_absent_expiry_as_never() {
        assert!(expires_later(Some(2), Some(1)));
        assert!(!expires_later(Some(1), Some(1)));
        assert!(expires_later(None, Some(1)));
        assert!(!expires_later(None, None));
        assert!(!expires_later(Some(5), None));
    }

    #[test]
    fn ordinary_rebind_needs_every_member_capable() {
        assert!(rebind_allowed_for_members([Some(true), Some(true)]));
        assert!(rebind_allowed_for_members(std::iter::empty()));
        assert!(!rebind_allowed_for_members([Some(true), None]));
        assert!(!rebind_allowed_for_members([Some(true), Some(false)]));
    }

    #[test]
    fn admins_needing_renewal_only_when_every_other_admin_expired() {
        let a = [1u8; 32];
        let d = [2u8; 32];
        let target = [9u8; 32];
        let expired = NOW - EXPIRY_TOLERANCE_SECS - 1;
        assert_eq!(
            admins_needing_renewal(&[(d, Some(expired)), (a, Some(expired))], &target, NOW),
            Some(vec![a, d])
        );
        assert_eq!(
            admins_needing_renewal(&[(a, Some(expired)), (d, Some(NOW + 10))], &target, NOW),
            None
        );
        assert_eq!(
            admins_needing_renewal(&[(a, Some(expired)), (d, None)], &target, NOW),
            None
        );
        assert_eq!(
            admins_needing_renewal(&[(target, Some(expired))], &target, NOW),
            None
        );
    }

    fn snapshot(role: GroupRole, digest: Option<&str>) -> RosterMemberSnapshot {
        RosterMemberSnapshot {
            role,
            state: GroupMemberState::Active,
            treekem_key_package_hash: Some("kp".to_string()),
            certificate_digest: digest.map(str::to_string),
        }
    }

    #[test]
    fn ancestor_walk_accepts_only_a_self_rebind_link() {
        let mut before = BTreeMap::new();
        before.insert("a".to_string(), snapshot(GroupRole::Admin, Some("da")));
        before.insert("b".to_string(), snapshot(GroupRole::Member, Some("d1")));
        let mut rebound = before.clone();
        rebound.insert("b".to_string(), snapshot(GroupRole::Member, Some("d2")));
        assert!(is_self_rebind_link(&before, &rebound, "b"));
        // Another member's digest may not change.
        assert!(!is_self_rebind_link(&before, &rebound, "a"));
        // A role change is not a rebind.
        let mut promoted = rebound.clone();
        promoted.insert("b".to_string(), snapshot(GroupRole::Admin, Some("d2")));
        assert!(!is_self_rebind_link(&before, &promoted, "b"));
        // Nothing else may change.
        let mut other = rebound.clone();
        other.insert("a".to_string(), snapshot(GroupRole::Admin, Some("dx")));
        assert!(!is_self_rebind_link(&before, &other, "b"));
        let mut added = rebound.clone();
        added.insert("c".to_string(), snapshot(GroupRole::Member, None));
        assert!(!is_self_rebind_link(&before, &added, "b"));
        // An unchanged digest is not a rebind.
        assert!(!is_self_rebind_link(&before, &before, "b"));
    }

    /// A retained parent (the admin renews its own certificate) and this
    /// node's head on it, where `own_seat`'s certificate was replaced by a
    /// valid rebind (#1533 r11 Codex P1). The displaced parent certificate
    /// is retained (#1650), so the sibling checks still read it.
    fn own_branch_replaced(f: &Fixture, own_seat: &AgentKeypair) -> (GroupInfo, GroupInfo) {
        let admin_renewal = cert(&f.owner, &f.admin, Some(NOW + 700));
        let (parent, _) = seal(
            &f.info,
            *f.admin.agent_id().as_bytes(),
            &admin_renewal,
            &f.admin,
            NOW * 1000,
        )
        .expect("parent");
        let renewal = cert(&f.owner, own_seat, Some(NOW + 900));
        let (current, _) = seal(
            &parent,
            *own_seat.agent_id().as_bytes(),
            &renewal,
            &f.admin,
            NOW * 1000 + 1,
        )
        .expect("own branch");
        assert!(
            current
                .commit_log
                .iter()
                .any(|retained| retained.commit.state_hash == parent.state_hash),
            "the parent is retained"
        );
        (parent, current)
    }

    /// #1650: two valid self-rebinds of one seat on one parent. A node
    /// that applied either sibling retains the displaced parent
    /// certificate, so the other sibling is fully verified: fork evidence
    /// on every node (ADR 0110 §4a `waiting_for_fork_resolution`), not
    /// `CertificateEvidenceMissing`.
    #[test]
    fn two_valid_same_seat_siblings_are_fork_evidence_whichever_installs() {
        let f = fixture();
        let admin_renewal = cert(&f.owner, &f.admin, Some(NOW + 700));
        let (parent, _) = seal(
            &f.info,
            *f.admin.agent_id().as_bytes(),
            &admin_renewal,
            &f.admin,
            NOW * 1000,
        )
        .expect("parent");
        let sibling = |not_after| {
            let renewal = cert(&f.owner, &f.member, Some(not_after));
            seal(
                &parent,
                *f.member.agent_id().as_bytes(),
                &renewal,
                &f.member,
                NOW * 1000 + 2,
            )
            .expect("sibling")
            .1
        };
        let first = sibling(NOW + 7000);
        let second = sibling(NOW + 8000);
        let parent_digest = committed_digest(&parent.members_v2[&hex_of(&f.member)])
            .expect("the parent's committed digest");
        for (applied, competing) in [(&first, &second), (&second, &first)] {
            let (signer, renewal) = validate_against_parent(&applied.body, &parent, NOW, |_| false)
                .expect("valid on the parent");
            let current = apply_to_parent(&parent, &applied.body, signer, renewal).expect("apply");
            assert!(
                current.displaced_certificates.contains_key(&parent_digest),
                "the displaced parent certificate is retained"
            );
            verify_signatures(competing).expect("signatures");
            assert_eq!(
                validate_sibling(&competing.body, &current, NOW, |_| false),
                Ok(RebindSigner::SeatAgent),
                "the competing sibling on the same parent is fork evidence"
            );
        }
    }

    /// #1650 review P2: a wholesale roster replacement (the SignedPublic
    /// catch-up install) retains the parent bytes it displaces, and only
    /// those — a seat whose committed digest is unchanged retains
    /// nothing. The wired path is
    /// `catchup_retains_displaced_parent_evidence_for_a_competing_sibling`
    /// in the route tests.
    #[test]
    fn roster_replacement_retains_the_displaced_parent_bytes() {
        let f = fixture();
        let parent = f.info.clone();
        let parent_digest = owner_cert::certificate_digest_hex(
            parent.members_v2[&hex_of(&f.member)]
                .certificate
                .as_ref()
                .expect("the parent holds the member certificate"),
        );
        // The winner's roster: the same seats, the member's certificate
        // replaced, and no retained evidence of its own — a sanitized
        // snapshot never carries the winner's local map.
        let winner_renewal = cert(&f.owner, &f.member, Some(NOW + 7000));
        let mut winner = parent.clone();
        winner.displaced_certificates.clear();
        if let Some(member) = winner.members_v2.get_mut(&hex_of(&f.member)) {
            member.certificate_digest = Some(owner_cert::certificate_digest_hex(&winner_renewal));
            member.certificate = Some(winner_renewal);
        }
        let mut next = parent.clone();
        next.members_v2.clone_from(&winner.members_v2);
        retain_displaced_by_roster_replacement(&mut next, &parent);
        assert!(
            next.displaced_certificates.contains_key(&parent_digest),
            "the parent certificate the replacement displaced is retained"
        );
        assert_eq!(
            next.displaced_certificates.len(),
            1,
            "the admin seat, whose committed digest is unchanged, retains nothing"
        );
    }

    /// #1650: the retained displaced history stays bounded. Each further
    /// renewal of one seat displaces the last; past
    /// [`DISPLACED_CERTIFICATE_CAP`] the retained map stops growing at the
    /// cap, holds only displaced digests (never the live certificate), and
    /// eviction is by retention recency — exactly the oldest displacements
    /// are gone and the newest displacement stays.
    #[test]
    fn displaced_certificate_retention_is_bounded() {
        let f = fixture();
        let mut info = f.info.clone();
        let mut displacement_order = Vec::new();
        let steps = DISPLACED_CERTIFICATE_CAP + 4;
        for i in 0..=steps {
            let renewal = cert(&f.owner, &f.member, Some(NOW + 100 + i as u64));
            let displaced_now = owner_cert::certificate_digest_hex(
                info.members_v2[&hex_of(&f.member)]
                    .certificate
                    .as_ref()
                    .expect("the seat holds a certificate"),
            );
            displacement_order.push(displaced_now);
            install_certificate(&mut info, &hex_of(&f.member), renewal);
        }
        assert_eq!(
            info.displaced_certificates.len(),
            DISPLACED_CERTIFICATE_CAP,
            "the retained map is capped below the displacements"
        );
        assert!(
            info.displaced_certificates
                .keys()
                .all(|digest| displacement_order.contains(digest)),
            "only displaced digests are retained"
        );
        let live = owner_cert::certificate_digest_hex(
            info.members_v2[&hex_of(&f.member)]
                .certificate
                .as_ref()
                .expect("the live certificate"),
        );
        assert!(
            !info.displaced_certificates.contains_key(&live),
            "the live certificate is not retained evidence"
        );
        // Retention recency decides: the oldest displacements are evicted,
        // the newest [`DISPLACED_CERTIFICATE_CAP`] all survive.
        let evicted = &displacement_order[..displacement_order.len() - DISPLACED_CERTIFICATE_CAP];
        let retained = &displacement_order[displacement_order.len() - DISPLACED_CERTIFICATE_CAP..];
        for digest in evicted {
            assert!(
                !info.displaced_certificates.contains_key(digest),
                "the oldest retention {digest} is evicted"
            );
        }
        for digest in retained {
            assert!(
                info.displaced_certificates.contains_key(digest),
                "the newer retention {digest} survives"
            );
        }
    }

    /// #1650 review P2: at the cap, eviction keeps the newest parent
    /// evidence — by retention recency, not digest order. A full cache
    /// whose digest-key order is the inverse of its recency (the newest
    /// evidence at the lexicographically smallest digest, the oldest at
    /// the largest) must still drop the oldest retention and keep the
    /// newest, including the entry the same call just retained.
    #[test]
    fn cap_eviction_never_drops_the_newest_parent_evidence() {
        let f = fixture();
        let mut info = f.info.clone();
        info.displaced_certificates.clear();
        let newest = "07";
        let oldest = "f6";
        let inverted = [
            (newest, 16u64),
            ("18", 15),
            ("29", 14),
            ("3a", 13),
            ("4b", 12),
            ("5c", 11),
            ("6d", 10),
            ("7e", 9),
            ("8f", 8),
            ("9a", 7),
            ("ab", 6),
            ("bc", 5),
            ("cd", 4),
            ("de", 3),
            ("ef", 2),
            (oldest, 1),
        ];
        assert_eq!(inverted.len(), DISPLACED_CERTIFICATE_CAP);
        for (digest, retained_seq) in inverted {
            info.displaced_certificates.insert(
                digest.to_string(),
                RetainedCertificate {
                    certificate: cert(&f.owner, &f.member, Some(NOW + 700)),
                    retained_seq,
                },
            );
        }
        let displaced_now = cert(&f.owner, &f.member, Some(NOW + 800));
        let just_retained = owner_cert::certificate_digest_hex(&displaced_now);
        retain_displaced_certificate(&mut info, displaced_now);
        assert_eq!(
            info.displaced_certificates.len(),
            DISPLACED_CERTIFICATE_CAP,
            "one entry beyond the cap is evicted"
        );
        assert!(
            !info.displaced_certificates.contains_key(oldest),
            "the oldest retention — here the lexicographically largest digest — is evicted"
        );
        assert!(
            info.displaced_certificates.contains_key(newest),
            "the newest parent evidence — here the lexicographically smallest digest — survives"
        );
        assert!(
            info.displaced_certificates.contains_key(&just_retained),
            "the entry the same call just retained survives"
        );
    }

    /// #1533 r11 Codex P1, kept by #1650: after a valid rebind replaced
    /// the seat's parent certificate, a regular member signs a sibling
    /// self-rebind with an older (but unexpired) certificate from the same
    /// owner. The retained displaced bytes make the later-expiry check
    /// run, and the older certificate is refused: not later, so no fork
    /// evidence.
    #[test]
    fn sibling_with_an_older_certificate_is_refused_as_not_later() {
        let f = fixture();
        let (parent, current) = own_branch_replaced(&f, &f.member);
        let older = cert(&f.owner, &f.member, Some(NOW + 300));
        let (_, frame) = seal(
            &parent,
            *f.member.agent_id().as_bytes(),
            &older,
            &f.member,
            NOW * 1000 + 2,
        )
        .expect("sibling");
        verify_signatures(&frame).expect("signatures");
        assert_eq!(
            validate_sibling(&frame.body, &current, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::NotLater)
        );
    }

    /// #1533 r11's narrowing itself stays: a node that holds no bytes for
    /// the parent's committed digest (neither live nor retained) refuses
    /// the sibling and records nothing. An unverifiable sibling is never
    /// accepted as evidence. This holds for the seat's certificate and
    /// for an admin signer's.
    #[test]
    fn sibling_without_any_parent_certificate_bytes_is_no_fork_evidence() {
        let f = fixture();
        let (parent, mut current) = own_branch_replaced(&f, &f.member);
        if let Some(member) = current.members_v2.get_mut(&hex_of(&f.member)) {
            member.certificate = None;
        }
        current.displaced_certificates.clear();
        let later = cert(&f.owner, &f.member, Some(NOW + 6000));
        let (_, frame) = seal(
            &parent,
            *f.member.agent_id().as_bytes(),
            &later,
            &f.member,
            NOW * 1000 + 2,
        )
        .expect("sibling");
        assert_eq!(
            validate_sibling(&frame.body, &current, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::CertificateEvidenceMissing)
        );

        // The signer side: an admin whose parent certificate bytes are
        // gone signs a valid rebind of another seat. The expiry check on
        // the signer cannot run, so the sibling records nothing either.
        let (parent, mut current) = own_branch_replaced(&f, &f.admin);
        if let Some(admin) = current.members_v2.get_mut(&hex_of(&f.admin)) {
            admin.certificate = None;
        }
        current.displaced_certificates.clear();
        let renewal = cert(&f.owner, &f.member, Some(NOW + 6000));
        let (_, frame) = seal(
            &parent,
            *f.member.agent_id().as_bytes(),
            &renewal,
            &f.admin,
            NOW * 1000 + 2,
        )
        .expect("admin-signed sibling");
        assert_eq!(
            validate_sibling(&frame.body, &current, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::CertificateEvidenceMissing)
        );
    }

    /// #1650, the signer side: an admin signer's expiry check needs its
    /// parent certificate. When this node's branch replaced it, the
    /// retained displaced bytes keep the check running and a valid sibling
    /// is fork evidence.
    #[test]
    fn sibling_after_the_admin_certificate_was_displaced_is_fork_evidence() {
        let f = fixture();
        let (parent, current) = own_branch_replaced(&f, &f.admin);
        let renewal = cert(&f.owner, &f.member, Some(NOW + 6000));
        let (_, frame) = seal(
            &parent,
            *f.member.agent_id().as_bytes(),
            &renewal,
            &f.admin,
            NOW * 1000 + 2,
        )
        .expect("sibling");
        assert_eq!(
            validate_sibling(&frame.body, &current, NOW, |_| false),
            Ok(RebindSigner::Admin)
        );
    }

    /// The control: with the parent bytes held, an older certificate is
    /// refused as not later and a later one is a valid sibling.
    #[test]
    fn sibling_with_parent_certificates_checks_expiry() {
        let f = fixture();
        // This node's branch changes another seat: the admin renews again.
        let (parent, current) = own_branch_replaced(&f, &f.admin);
        let sibling = |not_after| {
            let renewal = cert(&f.owner, &f.member, Some(not_after));
            seal(
                &parent,
                *f.member.agent_id().as_bytes(),
                &renewal,
                &f.member,
                NOW * 1000 + 2,
            )
            .expect("sibling")
            .1
        };
        assert_eq!(
            validate_sibling(&sibling(NOW + 300).body, &current, NOW, |_| false).err(),
            Some(CertificateRebindRefusal::NotLater)
        );
        assert_eq!(
            validate_sibling(&sibling(NOW + 6000).body, &current, NOW, |_| false),
            Ok(RebindSigner::SeatAgent)
        );
    }
}
