//! #1663: `MemberKeyRepublishV1`, the signed republication of a member's
//! KEM key on its own already-Active seat.
//!
//! A GSS survivor of an encrypted group whose roster seat carries no KEM
//! public key can not receive the re-sealed share of a rotated secret
//! (#1578). David's ruling of 28 Oct 2026 02:25 GMT: such a member
//! republishes a key **without leaving and re-joining**, through this
//! typed frame. Peers verify it and seat the key on the member's row; the
//! next share is then sealed to that seat through the existing share
//! path, which ends the keyless hold and the head disclaimer.
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
//! The republish is ordered by a per-seat monotonic counter
//! (`GroupMember::kem_key_sequence`, local data the roster root does not
//! hash): a frame must carry a sequence strictly greater than the seat's
//! seated counter, so a replay or a stale key is refused. The signature
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
    /// The seat's republication counter. Strictly greater than the seated
    /// `GroupMember::kem_key_sequence`; `0` is refused (a seat that never
    /// republished counts as `0`).
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
    /// The sequence does not advance the seat's seated counter: a replay
    /// or a stale key.
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
/// (the join's key-only marker row reads as not seated, as every seat
/// check does since #1578 rc11), the KEM key is an ML-KEM-768 public key,
/// and the sequence advances the seat's seated counter. The caller
/// verified the signatures and holds the group's membership lock.
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
    let actor_hex = hex::encode(body.actor);
    // #1578 rc11: the join's key-only marker row is not a seat — the
    // actor reads as absent, exactly main's roster.
    if !info
        .members_v2
        .get(&actor_hex)
        .is_some_and(|member| member.state == GroupMemberState::Active)
        || info.join_seat_key_marker_only(&actor_hex)
    {
        return Err(MemberKeyRepublishRefusal::ActorIneligible);
    }
    if body.key_sequence == 0 {
        return Err(MemberKeyRepublishRefusal::Malformed);
    }
    let kem_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.kem_public_key_b64)
        .map_err(|_| MemberKeyRepublishRefusal::Malformed)?;
    if kem_bytes.len() != ML_KEM_768_PUBLIC_KEY_BYTES {
        return Err(MemberKeyRepublishRefusal::Malformed);
    }
    if body.key_sequence
        <= info
            .members_v2
            .get(&actor_hex)
            .and_then(|member| member.kem_key_sequence)
            .unwrap_or(0)
    {
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

    /// A GSS `MlsEncrypted` group whose actor seat is Active and keyless.
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
        // A key that does not derive the claimed actor can not sign for it.
        let other = keypair();
        let body = body_for(&info, &actor, 1);
        assert_eq!(
            sign(body, &other).err(),
            Some(MemberKeyRepublishRefusal::ActorIneligible)
        );
        // A frame another key signed, then re-labelled with the actor's
        // id, does not verify: the claim is inside the signed bytes.
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
        // A seated sequence refuses a replay (the same sequence) and a
        // stale key (a lower one).
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
        // A removed actor is not seated; a contained group and another
        // plane refuse the frame.
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

    /// #1663 review round 4 (Claude, 30 Oct): a Removed row that becomes
    /// Active again starts a fresh republication epoch. The re-joined
    /// member's own row is new (no counter), so a counter retained across
    /// the re-admission would refuse its every republication as stale;
    /// the reset rides the re-admission every peer applies alike, and an
    /// already-Active row keeps its counter.
    #[test]
    fn a_readmitted_seat_starts_a_fresh_republication_counter() {
        let actor = keypair();
        let key = kem_b64();
        let mut info = group(&actor, Some(&key));
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        assert!(info.install_republished_kem_key(&actor_hex, &key, 3));
        info.remove_member(&actor_hex, Some(actor_hex.clone()));
        info.add_member_with_kem(
            actor_hex.clone(),
            GroupRole::Member,
            None,
            None,
            Some(key.clone()),
        );
        assert_eq!(
            info.members_v2
                .get(&actor_hex)
                .and_then(|seat| seat.kem_key_sequence),
            None,
            "the re-admission resets the retained republication counter"
        );
        let fresh_key = kem_b64();
        assert!(
            info.install_republished_kem_key(&actor_hex, &fresh_key, 1),
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
                .and_then(|seat| seat.kem_key_sequence),
            Some(1),
            "an already-Active row keeps its counter"
        );
    }

    /// The join's key-only marker row (#1578 rc7/rc11) is not a seat: a
    /// republish for a pre-admission joiner is refused.
    #[test]
    fn join_marker_row_is_not_a_seat() {
        let actor = keypair();
        let mut info = group(&actor, None);
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        if let Some(member) = info.members_v2.get_mut(&actor_hex) {
            member.state = GroupMemberState::Pending;
            member.kem_public_key_b64 = Some(kem_b64());
        }
        let body = body_for(&info, &actor, 1);
        assert_eq!(
            validate_against_seat(&body, &info),
            Err(MemberKeyRepublishRefusal::ActorIneligible)
        );
    }
}
