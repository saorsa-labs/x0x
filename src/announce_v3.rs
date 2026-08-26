//! V3 identity announcement — merged, slimmed, self-verifying (L3, #380 residue).
//!
//! A V2 heartbeat costs three ML-DSA-signed messages per beat (identity ~17 KB
//! with cert, machine ~15 KB, caps advert ~14 KB), each broadcast O(network).
//! V3 collapses the identity + machine information into ONE announcement and
//! moves the optional user→agent certificate behind a BLAKE3 digest with
//! fetch-on-miss, cutting the steady-state beat to ≤8 KB while remaining fully
//! verifiable standalone:
//!
//! - Both public keys stay inline (a receiver can always check the machine
//!   signature and both id↔key bindings without fetching anything).
//! - `cert_digest` commits to the `(user_id, agent_certificate)` pair. A
//!   receiver that needs the certificate (user attribution, issuer-revocation
//!   authority) fetches the full V2 announcement once by digest and verifies
//!   it under the V2 rules before caching. Design: `.scratch/omp-l3l4-design.md`
//!   + Claude review addendum (the pubkey-digested ≤3.5 KB variant was rejected
//!   for v1 because it is unverifiable before fetch).
//! - V3 is signed over its OWN canonical bytes (magic `X0A3`); it never reuses
//!   a V2 signature. Old nodes see an unknown magic, fail the legacy bincode
//!   decode, and drop the payload — V2 continues to be published alongside V3
//!   during the transition, so old nodes lose nothing.

use crate::{error, identity};

/// Wire magic for the V3 envelope. Legacy payloads start with the bincode of a
/// 32-byte `agent_id` (a hash prefix), so a fixed ASCII magic is
/// collision-resistant the same way `X0A2` is.
pub const IDENTITY_ANNOUNCEMENT_V3_MAGIC: &[u8; 4] = b"X0A3";

/// Everything the machine key signs. `agent_public_key` is INSIDE the signed
/// struct (unlike V2, where it rides outside the signature and is only
/// self-certified) — a V3 receiver rejects a swapped agent key on signature
/// grounds, not just the id-binding check.
#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityAnnouncementV3Unsigned {
    agent_id: identity::AgentId,
    machine_id: identity::MachineId,
    agent_public_key: Vec<u8>,
    machine_public_key: Vec<u8>,
    addresses: Vec<std::net::SocketAddr>,
    announced_at: u64,
    nat_type: Option<String>,
    can_receive_direct: Option<bool>,
    is_relay: Option<bool>,
    is_coordinator: Option<bool>,
    reachable_via: Vec<identity::MachineId>,
    relay_candidates: Vec<identity::MachineId>,
    cert_digest: [u8; 32],
    payload_version: u64,
}

/// Signed V3 identity announcement.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityAnnouncementV3 {
    /// Portable agent identity (= SHA-256 of `agent_public_key`).
    pub agent_id: identity::AgentId,
    /// Machine identity (= SHA-256 of `machine_public_key`).
    pub machine_id: identity::MachineId,
    /// Raw ML-DSA-65 agent public key bytes (inline: self-verifying).
    pub agent_public_key: Vec<u8>,
    /// Raw ML-DSA-65 machine public key bytes (inline: self-verifying).
    pub machine_public_key: Vec<u8>,
    /// Reachability hints (same filtering rules as V2).
    pub addresses: Vec<std::net::SocketAddr>,
    /// Unix timestamp (seconds) of announcement creation.
    pub announced_at: u64,
    /// NAT type as detected by the network layer.
    pub nat_type: Option<String>,
    /// Whether the machine can receive direct inbound connections.
    pub can_receive_direct: Option<bool>,
    /// Stable relay-capability hint.
    pub is_relay: Option<bool>,
    /// Stable coordinator-capability hint.
    pub is_coordinator: Option<bool>,
    /// Coordinator machines through which this agent is reachable.
    pub reachable_via: Vec<identity::MachineId>,
    /// Relay machines proposed as fallback paths.
    pub relay_candidates: Vec<identity::MachineId>,
    /// BLAKE3 hash of `bincode((user_id, agent_certificate))` from the V2
    /// announcement this V3 was derived from. Receivers that need the
    /// certificate fetch the full V2 payload by this digest and verify it
    /// under V2 rules before caching. For an anonymous agent this is the
    /// digest of `(None, None)` — a well-known constant receivers can skip.
    pub cert_digest: [u8; 32],
    /// Monotonic version of the digested payload — lets a receiver detect a
    /// stale cached blob without fetching. Publishers bump it whenever the
    /// `(user_id, agent_certificate)` pair changes.
    pub payload_version: u64,
    /// ML-DSA-65 machine signature over the bincode of the unsigned struct.
    pub machine_signature: Vec<u8>,
}

/// Digest committing to the fetchable part of an announcement:
/// `blake3(bincode((user_id, agent_certificate)))`.
pub fn cert_digest(
    user_id: &Option<identity::UserId>,
    cert: &Option<identity::AgentCertificate>,
) -> [u8; 32] {
    // Serialization of these small enums cannot fail; fall back to the
    // digest of an empty buffer rather than panicking if it ever does.
    let bytes = bincode::serialize(&(user_id, cert)).unwrap_or_default();
    *blake3::hash(&bytes).as_bytes()
}

/// The digest of an anonymous announcement (`(None, None)`), precomputable by
/// receivers so anonymous agents never trigger a fetch.
pub fn anonymous_cert_digest() -> [u8; 32] {
    cert_digest(&None, &None)
}

impl IdentityAnnouncementV3 {
    fn to_unsigned(&self) -> IdentityAnnouncementV3Unsigned {
        IdentityAnnouncementV3Unsigned {
            agent_id: self.agent_id,
            machine_id: self.machine_id,
            agent_public_key: self.agent_public_key.clone(),
            machine_public_key: self.machine_public_key.clone(),
            addresses: self.addresses.clone(),
            announced_at: self.announced_at,
            nat_type: self.nat_type.clone(),
            can_receive_direct: self.can_receive_direct,
            is_relay: self.is_relay,
            is_coordinator: self.is_coordinator,
            reachable_via: self.reachable_via.clone(),
            relay_candidates: self.relay_candidates.clone(),
            cert_digest: self.cert_digest,
            payload_version: self.payload_version,
        }
    }

    /// Build and sign a V3 announcement from an already-built V2 announcement.
    ///
    /// The V2 announcement is the source of truth for every field; the V3
    /// drops the inline certificate/user pair behind `cert_digest` and signs
    /// its own canonical bytes with the machine key.
    pub fn build_from_v2(
        v2: &crate::IdentityAnnouncement,
        machine_secret: &ant_quic::MlDsaSecretKey,
        payload_version: u64,
    ) -> error::Result<Self> {
        let mut v3 = Self {
            agent_id: v2.agent_id,
            machine_id: v2.machine_id,
            agent_public_key: v2.agent_public_key.clone(),
            machine_public_key: v2.machine_public_key.clone(),
            addresses: v2.addresses.clone(),
            announced_at: v2.announced_at,
            nat_type: v2.nat_type.clone(),
            can_receive_direct: v2.can_receive_direct,
            is_relay: v2.is_relay,
            is_coordinator: v2.is_coordinator,
            reachable_via: v2.reachable_via.clone(),
            relay_candidates: v2.relay_candidates.clone(),
            cert_digest: cert_digest(&v2.user_id, &v2.agent_certificate),
            payload_version,
            machine_signature: Vec::new(),
        };
        let unsigned_bytes = bincode::serialize(&v3.to_unsigned()).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize unsigned v3 announcement: {e}"
            ))
        })?;
        v3.machine_signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            machine_secret,
            &unsigned_bytes,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "failed to sign v3 announcement with machine key: {e:?}"
            )))
        })?
        .as_bytes()
        .to_vec();
        Ok(v3)
    }

    /// Verify the V3 announcement standalone: machine-key ↔ machine_id
    /// binding, agent-key ↔ agent_id binding, and the ML-DSA machine
    /// signature over the canonical unsigned bytes.
    pub fn verify(&self) -> error::Result<()> {
        let machine_pub =
            ant_quic::MlDsaPublicKey::from_bytes(&self.machine_public_key).map_err(|_| {
                error::IdentityError::CertificateVerification(
                    "invalid machine public key in v3 announcement".to_string(),
                )
            })?;
        if identity::MachineId::from_public_key(&machine_pub) != self.machine_id {
            return Err(error::IdentityError::CertificateVerification(
                "v3 machine_id does not match machine public key".to_string(),
            ));
        }
        let agent_pub =
            ant_quic::MlDsaPublicKey::from_bytes(&self.agent_public_key).map_err(|_| {
                error::IdentityError::CertificateVerification(
                    "invalid agent public key in v3 announcement".to_string(),
                )
            })?;
        if identity::AgentId::from_public_key(&agent_pub) != self.agent_id {
            return Err(error::IdentityError::CertificateVerification(
                "v3 agent_id does not match agent public key".to_string(),
            ));
        }
        let unsigned_bytes = bincode::serialize(&self.to_unsigned()).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize v3 announcement for verification: {e}"
            ))
        })?;
        let signature = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            &self.machine_signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "invalid machine signature in v3 announcement: {e:?}"
            ))
        })?;
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &machine_pub,
            &unsigned_bytes,
            &signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "v3 machine signature verification failed: {e:?}"
            ))
        })?;
        Ok(())
    }

    /// Convert into the V2 in-memory shape for the shared discovery pipeline.
    ///
    /// The certificate/user pair is NOT part of a V3 beat: both are `None`
    /// until (and unless) the digest blob is fetched and verified. The cache
    /// merge never erases an existing cert/user with an absent one, so a V3
    /// beat refreshing a peer that previously sent a full V2 keeps its
    /// attribution. `machine_signature` carries the V3 signature bytes — the
    /// converted value must NOT be re-verified under V2 rules (the discovery
    /// arm verifies BEFORE conversion).
    pub fn into_announcement(self) -> crate::IdentityAnnouncement {
        crate::IdentityAnnouncement {
            agent_id: self.agent_id,
            machine_id: self.machine_id,
            user_id: None,
            agent_certificate: None,
            machine_public_key: self.machine_public_key,
            machine_signature: self.machine_signature,
            addresses: self.addresses,
            announced_at: self.announced_at,
            nat_type: self.nat_type,
            can_receive_direct: self.can_receive_direct,
            is_relay: self.is_relay,
            is_coordinator: self.is_coordinator,
            reachable_via: self.reachable_via,
            relay_candidates: self.relay_candidates,
            agent_public_key: self.agent_public_key,
        }
    }
}

/// Whether a raw discovery payload is a V3 envelope.
pub fn is_v3_payload(payload: &[u8]) -> bool {
    payload.len() >= IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()
        && &payload[..IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()] == IDENTITY_ANNOUNCEMENT_V3_MAGIC
}

/// Serialize a V3 announcement in its envelope (magic prefix + bincode).
pub fn serialize_v3(
    announcement: &IdentityAnnouncementV3,
) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    use bincode::Options;
    let body = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(announcement)?;
    let mut out = Vec::with_capacity(IDENTITY_ANNOUNCEMENT_V3_MAGIC.len() + body.len());
    out.extend_from_slice(IDENTITY_ANNOUNCEMENT_V3_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Deserialize a V3 envelope. Callers MUST run [`IdentityAnnouncementV3::verify`]
/// before acting on the result.
pub fn deserialize_v3(payload: &[u8]) -> Result<IdentityAnnouncementV3, Box<bincode::ErrorKind>> {
    use bincode::Options;
    if !is_v3_payload(payload) {
        return Err(Box::new(bincode::ErrorKind::Custom(
            "missing X0A3 magic".to_string(),
        )));
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
        .reject_trailing_bytes()
        .deserialize(&payload[IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()..])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::{AgentKeypair, MachineKeypair};

    /// Build a V2 announcement (anonymous) with real keypairs, then derive V3.
    fn v2_and_v3() -> (crate::IdentityAnnouncement, IdentityAnnouncementV3) {
        let agent = AgentKeypair::generate().unwrap();
        let machine = MachineKeypair::generate().unwrap();
        let v2 = crate::IdentityAnnouncement {
            agent_id: agent.agent_id(),
            machine_id: machine.machine_id(),
            user_id: None,
            agent_certificate: None,
            machine_public_key: machine.public_key().as_bytes().to_vec(),
            machine_signature: Vec::new(), // V3 never reads the V2 signature
            addresses: vec!["203.0.113.7:5483".parse().unwrap()],
            announced_at: 1_700_000_000,
            nat_type: Some("FullCone".to_string()),
            can_receive_direct: Some(true),
            is_relay: Some(false),
            is_coordinator: Some(false),
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            agent_public_key: agent.public_key().as_bytes().to_vec(),
        };
        let v3 = IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0).unwrap();
        (v2, v3)
    }

    /// L3's whole point: the self-verifying beat must stay small. 8 KB is the
    /// design ceiling (2 ML-DSA pubkeys + 1 signature + fields + envelope);
    /// a regression above it means someone re-inlined a blob that belongs
    /// behind the digest.
    #[test]
    fn v3_wire_size_stays_under_8kb() {
        let (_, v3) = v2_and_v3();
        let encoded = serialize_v3(&v3).unwrap();
        assert!(
            encoded.len() <= 8192,
            "v3 announcement is {} bytes; the L3 design ceiling is 8192",
            encoded.len()
        );
        // And it must be dramatically smaller than a V2 carrying a cert
        // (~15-17 KB): sanity-floor so the test can't pass vacuously.
        assert!(
            encoded.len() >= 5000,
            "suspiciously small: {}",
            encoded.len()
        );
    }

    #[test]
    fn v3_round_trip_verifies() {
        let (v2, v3) = v2_and_v3();
        let encoded = serialize_v3(&v3).unwrap();
        assert!(is_v3_payload(&encoded));
        let decoded = deserialize_v3(&encoded).unwrap();
        decoded.verify().expect("freshly built v3 must verify");
        assert_eq!(decoded.cert_digest, anonymous_cert_digest());
        let converted = decoded.into_announcement();
        assert_eq!(converted.agent_id, v2.agent_id);
        assert_eq!(converted.machine_id, v2.machine_id);
        assert_eq!(converted.addresses, v2.addresses);
        assert_eq!(converted.agent_public_key, v2.agent_public_key);
        assert!(converted.agent_certificate.is_none());
        assert!(converted.user_id.is_none());
    }

    /// Verification is the security boundary: any signed-field tamper must
    /// fail, and a swapped agent key must fail BOTH the signature and the
    /// id-binding (the V2 design only had the binding).
    #[test]
    fn v3_tampered_fields_are_rejected() {
        let (_, v3) = v2_and_v3();
        let mut addr_tampered = v3.clone();
        addr_tampered.addresses = vec!["198.51.100.9:9999".parse().unwrap()];
        assert!(
            addr_tampered.verify().is_err(),
            "tampered addresses must fail"
        );

        let mut digest_tampered = v3.clone();
        digest_tampered.cert_digest = [7u8; 32];
        assert!(
            digest_tampered.verify().is_err(),
            "tampered digest must fail"
        );

        let other_agent = AgentKeypair::generate().unwrap();
        let mut key_swapped = v3.clone();
        key_swapped.agent_public_key = other_agent.public_key().as_bytes().to_vec();
        assert!(key_swapped.verify().is_err(), "swapped agent key must fail");
    }

    /// Old-node safety: a V3 payload must NOT decode as a V2/legacy
    /// announcement (old daemons log-and-drop it instead of mis-parsing).
    #[test]
    fn v3_payload_is_rejected_by_v2_decoder() {
        let (_, v3) = v2_and_v3();
        let encoded = serialize_v3(&v3).unwrap();
        assert!(
            crate::deserialize_identity_announcement(&encoded).is_err(),
            "a V3 envelope must not be decodable under V2/legacy rules"
        );
    }
}
