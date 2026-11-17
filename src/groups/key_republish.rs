//! #1663: `MemberKeyRepublishV1`, the signed republication of a member's
//! KEM key on its own already-Active seat.
//!
//! A GSS survivor whose roster seat has no KEM public key cannot receive
//! a re-sealed share (#1578). It republishes a key through this frame
//! without leaving and re-joining.
//!
//! This module is pure and I/O-free. It holds:
//!
//! - the frozen v1 wire shape: typed prefix [`KEY_REPUBLISH_PREFIX`]
//!   (`X0XKR1`), an explicit v1 postcard body consumed exactly, and an
//!   outer ML-DSA-65 agent signature in domain
//!   [`KEY_REPUBLISH_SIGNATURE_DOMAIN`] (`x0x.member-key-republish.v1`)
//!   over the canonical body;
//! - the receiver's seat checks ([`validate_against_seat`]).
//!
//! The republish is ordered by a per-seat position
//! `(state_revision, key_sequence)` (`GroupMember::kem_key_revision` and
//! `GroupMember::kem_key_sequence`, local data the roster root does not
//! hash): a frame must order strictly after the seat's seated position,
//! so a replay or a stale key is refused. The signed `state_revision` is
//! the group state revision the actor held when it signed. It binds the
//! frame to the seat's admission (David's ruling, 2 Nov 2026 20:34 GMT):
//! a re-admission moves the seat's floor to the revision the receiver
//! held then, and a frame the actor signed in an earlier admission
//! carries a lower revision, so a relayed replay of it is refused. The
//! signature
//! must verify under the embedded agent public key, and that key must
//! derive the claimed actor, so an unsigned or wrong-signer frame is
//! refused. The capability that gates every send is `key_republish_v1`
//! ([`crate::dm::CapabilityRegistry::KEY_REPUBLISH_V1`], bit 12). The
//! body never goes inside a container that a released binary decodes, and
//! it is never published on the ungated metadata topic.

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use saorsa_pqc::api::kem::MlKemPublicKey;

use crate::groups::member::GroupMemberState;
use crate::groups::GroupInfo;
use crate::identity::AgentKeypair;

/// The typed direct-message prefix of a `MemberKeyRepublishV1` frame.
pub const KEY_REPUBLISH_PREFIX: &[u8] = b"X0XKR1";

/// The outer agent-signature domain.
pub const KEY_REPUBLISH_SIGNATURE_DOMAIN: &[u8] = b"x0x.member-key-republish.v1";

/// The length of an ML-KEM-768 public key ([`crate::groups::kem_envelope`]
/// `KEM_VARIANT`). A body whose key is not exactly this length is refused.
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;

/// The frozen v1 republish body. Field order is the postcard layout; a
/// later layout needs a new prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberKeyRepublishBodyV1 {
    /// The group's stable ID.
    pub stable_group_id: String,
    /// The republishing member (raw agent ID). The key seats on this
    /// member's own row only.
    pub actor: [u8; 32],
    /// The actor's ML-DSA-65 public key (base64). It verifies the outer
    /// signature and derives `actor`, so no directory lookup is needed.
    pub agent_public_key_b64: String,
    /// The ML-KEM-768 public key (base64) to seat on the actor's row.
    pub kem_public_key_b64: String,
    /// The group `state_revision` the actor held when it signed: the
    /// admission binding. With `key_sequence` it must order strictly after
    /// the seat's `GroupMember::republish_position`.
    pub state_revision: u64,
    /// The seat's republication counter within the admission; `0` is
    /// refused (a seat that never republished counts as `0`).
    pub key_sequence: u64,
}

/// A signed `MemberKeyRepublishV1` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMemberKeyRepublishV1 {
    /// The body.
    pub body: MemberKeyRepublishBodyV1,
    /// ML-DSA-65 signature by `body.actor` over [`signable_bytes`].
    pub signature: Vec<u8>,
}

/// Why a frame is refused. The `snake_case` names are the typed reasons in
/// logs and status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MemberKeyRepublishRefusal {
    /// Not an `X0XKR1` payload.
    WrongPrefix,
    /// The body did not decode, was not consumed exactly, carries a
    /// non-positive sequence, or its KEM key is not an ML-KEM-768 public
    /// key.
    Malformed,
    /// The signature does not verify, or the embedded agent public key
    /// does not derive the claimed actor.
    BadSignature,
    /// The group ID does not match this group.
    GroupMismatch,
    /// The group is withdrawn or holds a fork-quarantine marker.
    GroupContained,
    /// The signer is not an Active member of this group on the seat the
    /// key names (an absent row and the join's key-only marker row read as
    /// not seated).
    ActorIneligible,
    /// The group is not a GSS `MlsEncrypted` group — the only plane whose
    /// seats take a KEM key this way.
    CryptoPlaneUnsupported,
    /// The `(state_revision, key_sequence)` position does not advance the
    /// seat's seated position: a replay, a stale key, or a frame signed
    /// before the seat's current admission.
    StaleKey,
}

impl MemberKeyRepublishRefusal {
    /// The typed reason string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongPrefix => "wrong_prefix",
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::GroupMismatch => "group_mismatch",
            Self::GroupContained => "group_contained",
            Self::ActorIneligible => "actor_ineligible",
            Self::CryptoPlaneUnsupported => "crypto_plane_unsupported",
            Self::StaleKey => "stale_key",
        }
    }
}

impl std::fmt::Display for MemberKeyRepublishRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for MemberKeyRepublishRefusal {}

/// The bytes the outer signature covers: the domain, then the
/// length-prefixed canonical postcard body.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn signable_bytes(body: &MemberKeyRepublishBodyV1) -> Result<Vec<u8>, postcard::Error> {
    let encoded = postcard::to_stdvec(body)?;
    let mut out = Vec::with_capacity(
        KEY_REPUBLISH_SIGNATURE_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(encoded.len()),
    );
    out.extend_from_slice(KEY_REPUBLISH_SIGNATURE_DOMAIN);
    out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Sign a body with the actor's agent key.
///
/// # Errors
///
/// Returns [`MemberKeyRepublishRefusal::ActorIneligible`] when the keypair
/// is not the body's actor, [`MemberKeyRepublishRefusal::Malformed`] when
/// the body does not encode and
/// [`MemberKeyRepublishRefusal::BadSignature`] when signing fails.
pub fn sign(
    body: MemberKeyRepublishBodyV1,
    keypair: &AgentKeypair,
) -> Result<SignedMemberKeyRepublishV1, MemberKeyRepublishRefusal> {
    if keypair.agent_id().as_bytes() != &body.actor {
        return Err(MemberKeyRepublishRefusal::ActorIneligible);
    }
    let bytes = signable_bytes(&body).map_err(|_| MemberKeyRepublishRefusal::Malformed)?;
    let signature = sign_with_ml_dsa(keypair.secret_key(), &bytes)
        .map_err(|_| MemberKeyRepublishRefusal::BadSignature)?;
    Ok(SignedMemberKeyRepublishV1 {
        body,
        signature: signature.as_bytes().to_vec(),
    })
}

/// Encode a signed frame as a direct-message payload.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_frame(frame: &SignedMemberKeyRepublishV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = KEY_REPUBLISH_PREFIX.to_vec();
    out.extend(postcard::to_stdvec(frame)?);
    Ok(out)
}

/// Decode a frame with exact consumption. This checks the shape only; use
/// [`verify_signatures`] and [`validate_against_seat`] before any use.
///
/// # Errors
///
/// Returns why the payload is refused.
pub fn decode_frame(
    payload: &[u8],
) -> Result<SignedMemberKeyRepublishV1, MemberKeyRepublishRefusal> {
    let body = payload
        .strip_prefix(KEY_REPUBLISH_PREFIX)
        .ok_or(MemberKeyRepublishRefusal::WrongPrefix)?;
    let (frame, rest) = postcard::take_from_bytes::<SignedMemberKeyRepublishV1>(body)
        .map_err(|_| MemberKeyRepublishRefusal::Malformed)?;
    if !rest.is_empty() {
        return Err(MemberKeyRepublishRefusal::Malformed);
    }
    Ok(frame)
}

/// Verify the outer signature: the embedded agent public key must verify
/// it and must derive the claimed actor. The actor therefore signed this
/// exact body with the agent key its ID is the hash of — an unsigned or
/// wrong-signer frame can not pass.
///
/// # Errors
///
/// Returns [`MemberKeyRepublishRefusal::BadSignature`] or
/// [`MemberKeyRepublishRefusal::Malformed`].
pub fn verify_signatures(
    frame: &SignedMemberKeyRepublishV1,
) -> Result<(), MemberKeyRepublishRefusal> {
    let body = &frame.body;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.agent_public_key_b64)
        .map_err(|_| MemberKeyRepublishRefusal::BadSignature)?;
    let key = MlDsaPublicKey::from_bytes(&key_bytes)
        .map_err(|_| MemberKeyRepublishRefusal::BadSignature)?;
    if crate::identity::AgentId::from_public_key(&key).as_bytes() != &body.actor {
        return Err(MemberKeyRepublishRefusal::BadSignature);
    }
    let signature = MlDsaSignature::from_bytes(&frame.signature)
        .map_err(|_| MemberKeyRepublishRefusal::BadSignature)?;
    let bytes = signable_bytes(body).map_err(|_| MemberKeyRepublishRefusal::Malformed)?;
    verify_with_ml_dsa(&key, &bytes, &signature)
        .map_err(|_| MemberKeyRepublishRefusal::BadSignature)
}

/// The receiver's seat checks against its saved group state: the group is
/// a live GSS `MlsEncrypted` group, the actor is an Active member of it
/// (the join's key-only marker row is Pending, so it reads as not seated,
/// as every seat check does since #1578 rc11), the KEM key parses as an
/// ML-KEM-768 public key, and the `(state_revision, key_sequence)`
/// position advances the seat's seated position. The caller verified the
/// signatures and holds the group's membership lock.
///
/// # Errors
///
/// Returns the first failed check.
pub fn validate_against_seat(
    body: &MemberKeyRepublishBodyV1,
    info: &GroupInfo,
) -> Result<(), MemberKeyRepublishRefusal> {
    if body.stable_group_id != info.stable_group_id() {
        return Err(MemberKeyRepublishRefusal::GroupMismatch);
    }
    if info.withdrawn || info.fork_quarantine.is_some() {
        return Err(MemberKeyRepublishRefusal::GroupContained);
    }
    if !crate::groups::crypto_exclusion::is_gss_encrypted(info) {
        return Err(MemberKeyRepublishRefusal::CryptoPlaneUnsupported);
    }
    // Only an Active row is a seat: the join's key-only marker row is Pending.
    let Some(seat) = info
        .members_v2
        .get(&hex::encode(body.actor))
        .filter(|member| member.state == GroupMemberState::Active)
    else {
        return Err(MemberKeyRepublishRefusal::ActorIneligible);
    };
    if body.key_sequence == 0 {
        return Err(MemberKeyRepublishRefusal::Malformed);
    }
    let kem_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.kem_public_key_b64)
        .map_err(|_| MemberKeyRepublishRefusal::Malformed)?;
    if kem_bytes.len() != ML_KEM_768_PUBLIC_KEY_BYTES
        || MlKemPublicKey::from_bytes(crate::groups::kem_envelope::KEM_VARIANT, &kem_bytes).is_err()
    {
        return Err(MemberKeyRepublishRefusal::Malformed);
    }
    if (body.state_revision, body.key_sequence) <= seat.republish_position() {
        return Err(MemberKeyRepublishRefusal::StaleKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::member::{GroupMember, GroupRole};

    fn keypair() -> AgentKeypair {
        AgentKeypair::generate().expect("keypair")
    }

    fn kem_b64() -> String {
        let kem = crate::groups::kem_envelope::AgentKemKeypair::generate().expect("kem");
        base64::engine::general_purpose::STANDARD.encode(kem.public_bytes)
    }

    fn group(actor: &AgentKeypair, actor_key: Option<&str>) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            actor.agent_id(),
            "ab".repeat(16),
        );
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        let mut member = GroupMember::new_member(actor_hex.clone(), None, None, 1);
        member.kem_public_key_b64 = actor_key.map(str::to_string);
        info.members_v2.insert(actor_hex, member);
        info.add_member("aa".repeat(32), GroupRole::Admin, None, None);
        info.recompute_state_hash();
        info
    }

    fn body_for(info: &GroupInfo, actor: &AgentKeypair, sequence: u64) -> MemberKeyRepublishBodyV1 {
        MemberKeyRepublishBodyV1 {
            stable_group_id: info.stable_group_id().to_string(),
            actor: *actor.agent_id().as_bytes(),
            agent_public_key_b64: base64::engine::general_purpose::STANDARD
                .encode(actor.public_key().as_bytes()),
            kem_public_key_b64: kem_b64(),
            state_revision: info.state_revision,
            key_sequence: sequence,
        }
    }

    #[test]
    fn frame_round_trips_and_verifies() {
        let actor = keypair();
        let info = group(&actor, None);
        let frame = sign(body_for(&info, &actor, 1), &actor).expect("sign");
        let bytes = encode_frame(&frame).expect("encode");
        assert!(bytes.starts_with(KEY_REPUBLISH_PREFIX));
        let decoded = decode_frame(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        verify_signatures(&decoded).expect("signatures");
        validate_against_seat(&decoded.body, &info).expect("valid");
    }

    #[test]
    fn decode_requires_exact_consumption_and_prefix() {
        let actor = keypair();
        let info = group(&actor, None);
        let frame = sign(body_for(&info, &actor, 1), &actor).expect("sign");
        let mut bytes = encode_frame(&frame).expect("encode");
        bytes.push(0);
        assert_eq!(
            decode_frame(&bytes),
            Err(MemberKeyRepublishRefusal::Malformed)
        );
        assert_eq!(
            decode_frame(b"X0XCE1rest"),
            Err(MemberKeyRepublishRefusal::WrongPrefix)
        );
        assert_eq!(
            decode_frame(b"X0XKR1"),
            Err(MemberKeyRepublishRefusal::Malformed)
        );
    }

    #[test]
    fn tampered_body_and_wrong_key_fail_the_signature() {
        let actor = keypair();
        let info = group(&actor, None);
        let mut frame = sign(body_for(&info, &actor, 1), &actor).expect("sign");
        frame.body.key_sequence = 2;
        assert_eq!(
            verify_signatures(&frame),
            Err(MemberKeyRepublishRefusal::BadSignature)
        );
        let other = keypair();
        let body = body_for(&info, &actor, 1);
        assert_eq!(
            sign(body, &other).err(),
            Some(MemberKeyRepublishRefusal::ActorIneligible)
        );
        let mut frame = sign(body_for(&info, &other, 1), &other).expect("sign");
        frame.body.actor = *actor.agent_id().as_bytes();
        assert_eq!(
            verify_signatures(&frame),
            Err(MemberKeyRepublishRefusal::BadSignature)
        );
    }

    #[test]
    fn seat_checks_refuse_each_violation() {
        let actor = keypair();
        let info = group(&actor, None);
        let good = body_for(&info, &actor, 1);
        assert!(validate_against_seat(&good, &info).is_ok());
        let mut other_group = good.clone();
        other_group.stable_group_id = "other".to_string();
        assert_eq!(
            validate_against_seat(&other_group, &info),
            Err(MemberKeyRepublishRefusal::GroupMismatch)
        );
        let mut zero = good.clone();
        zero.key_sequence = 0;
        assert_eq!(
            validate_against_seat(&zero, &info),
            Err(MemberKeyRepublishRefusal::Malformed)
        );
        let mut junk = good.clone();
        junk.kem_public_key_b64 = "not-base64!!".to_string();
        assert_eq!(
            validate_against_seat(&junk, &info),
            Err(MemberKeyRepublishRefusal::Malformed)
        );
        let mut short = good;
        short.kem_public_key_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert_eq!(
            validate_against_seat(&short, &info),
            Err(MemberKeyRepublishRefusal::Malformed)
        );
    }

    #[test]
    fn stale_sequence_replay_and_each_seat_violation_refused() {
        let actor = keypair();
        let mut info = group(&actor, None);
        if let Some(member) = info
            .members_v2
            .get_mut(&hex::encode(actor.agent_id().as_bytes()))
        {
            member.kem_key_sequence = Some(3);
        }
        let stale = body_for(&info, &actor, 3);
        assert_eq!(
            validate_against_seat(&stale, &info),
            Err(MemberKeyRepublishRefusal::StaleKey)
        );
        let older = body_for(&info, &actor, 1);
        assert_eq!(
            validate_against_seat(&older, &info),
            Err(MemberKeyRepublishRefusal::StaleKey)
        );
        let fresh = body_for(&info, &actor, 4);
        assert!(validate_against_seat(&fresh, &info).is_ok());
        let mut removed = info.clone();
        if let Some(member) = removed
            .members_v2
            .get_mut(&hex::encode(actor.agent_id().as_bytes()))
        {
            member.state = GroupMemberState::Removed;
        }
        assert_eq!(
            validate_against_seat(&fresh, &removed),
            Err(MemberKeyRepublishRefusal::ActorIneligible)
        );
        let mut contained = info.clone();
        contained.withdrawn = true;
        assert_eq!(
            validate_against_seat(&fresh, &contained),
            Err(MemberKeyRepublishRefusal::GroupContained)
        );
        let mut treekem = info;
        treekem.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
        assert_eq!(
            validate_against_seat(&fresh, &treekem),
            Err(MemberKeyRepublishRefusal::CryptoPlaneUnsupported)
        );
    }

    #[test]
    fn a_readmitted_seat_starts_a_fresh_republication_counter() {
        let actor = keypair();
        let key = kem_b64();
        let mut info = group(&actor, Some(&key));
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        assert!(info.install_republished_kem_key(&actor_hex, &key, 0, 3));
        info.remove_member(&actor_hex, Some(actor_hex.clone()));
        info.state_revision = 5;
        info.add_member_with_kem(
            actor_hex.clone(),
            GroupRole::Member,
            None,
            None,
            Some(key.clone()),
        );
        let seat = info.members_v2.get(&actor_hex).expect("seat");
        assert_eq!(seat.kem_key_sequence, None, "the counter resets");
        assert_eq!(seat.republish_position(), (5, 0), "the floor moves");
        let fresh_key = kem_b64();
        assert!(
            info.install_republished_kem_key(&actor_hex, &fresh_key, 5, 1),
            "the re-joined member's first republication seats"
        );
        info.add_member_with_kem(
            actor_hex.clone(),
            GroupRole::Member,
            None,
            None,
            Some(fresh_key.clone()),
        );
        assert_eq!(
            info.members_v2
                .get(&actor_hex)
                .map(GroupMember::republish_position),
            Some((5, 1)),
            "an already-Active row keeps its position"
        );
    }

    #[test]
    fn an_unbanned_seat_starts_a_fresh_republication_counter() {
        let actor = keypair();
        let key = kem_b64();
        let mut info = group(&actor, Some(&key));
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        assert!(info.install_republished_kem_key(&actor_hex, &key, 0, 3));
        info.ban_member(&actor_hex, None);
        info.state_revision = 7;
        info.unban_member(&actor_hex);
        let seat = info.members_v2.get(&actor_hex).expect("seat");
        assert_eq!(seat.state, GroupMemberState::Active);
        assert_eq!(seat.kem_key_sequence, None, "the counter resets");
        assert_eq!(seat.republish_position(), (7, 0), "the floor moves");
        let mut body = body_for(&info, &actor, 1);
        assert!(validate_against_seat(&body, &info).is_ok());
        body.state_revision = 6;
        assert_eq!(
            validate_against_seat(&body, &info),
            Err(MemberKeyRepublishRefusal::StaleKey),
            "a frame signed before the unban is refused"
        );
    }

    #[test]
    fn a_frame_from_an_earlier_admission_is_refused_after_readmission() {
        let actor = keypair();
        let mut info = group(&actor, None);
        info.state_revision = 3;
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        let old = sign(body_for(&info, &actor, 4), &actor).expect("sign");
        info.remove_member(&actor_hex, None);
        info.state_revision = 4;
        info.add_member(actor_hex.clone(), GroupRole::Member, None, None);
        info.state_revision = 5;
        verify_signatures(&old).expect("the old frame is still authentic");
        assert_eq!(
            validate_against_seat(&old.body, &info),
            Err(MemberKeyRepublishRefusal::StaleKey),
            "the pre-removal frame can not seat its key"
        );
        assert!(!info.install_republished_kem_key(
            &actor_hex,
            &old.body.kem_public_key_b64,
            old.body.state_revision,
            old.body.key_sequence,
        ));
        let new = body_for(&info, &actor, 1);
        assert!(validate_against_seat(&new, &info).is_ok());
        assert!(info.install_republished_kem_key(
            &actor_hex,
            &new.kem_public_key_b64,
            new.state_revision,
            new.key_sequence,
        ));
    }

    #[test]
    fn join_marker_row_is_not_a_seat() {
        let actor = keypair();
        let mut info = group(&actor, None);
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        if let Some(member) = info.members_v2.get_mut(&actor_hex) {
            member.state = GroupMemberState::Pending;
            member.added_by = None;
            member.kem_public_key_b64 = Some(kem_b64());
        }
        assert!(
            info.join_seat_key_marker_only(&actor_hex),
            "the fixture is the join's marker row"
        );
        let body = body_for(&info, &actor, 1);
        assert_eq!(
            validate_against_seat(&body, &info),
            Err(MemberKeyRepublishRefusal::ActorIneligible)
        );
    }

    #[test]
    fn a_kem_key_that_does_not_parse_is_refused() {
        let actor = keypair();
        let info = group(&actor, None);
        let mut body = body_for(&info, &actor, 1);
        body.kem_public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode([0xff; ML_KEM_768_PUBLIC_KEY_BYTES]);
        assert_eq!(
            validate_against_seat(&body, &info),
            Err(MemberKeyRepublishRefusal::Malformed)
        );
    }
}
