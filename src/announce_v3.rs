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
//! - ADR-0036 V3.1: the agent self-name rides a NEW envelope (`X0A4`), never
//!   an in-place extension of `X0A3`. The V3 body is positional bincode under
//!   `reject_trailing_bytes`, so an appended field would make every pre-0036
//!   decoder drop the beat (and V2 is retired by default) — the agent would
//!   vanish from old peers. A named install therefore dual-publishes: `X0A3`
//!   (name dropped, byte-identical to pre-0036) for old peers, `X0A4`
//!   (carrying `self_name`) for new ones. The name stays outside
//!   `cert_digest` and outside the legacy `X0A3` machine signature; on
//!   `X0A4` it rides INSIDE the V3.1 machine signature (`sign_v3_1`
//!   signing the private `IdentityAnnouncementV31Unsigned` body), so
//!   verification and the blob fetch path are untouched by either
//!   envelope.

use crate::{error, identity};

/// Wire magic for the V3 envelope. Legacy payloads start with the bincode of a
/// 32-byte `agent_id` (a hash prefix), so a fixed ASCII magic is
/// collision-resistant the same way `X0A2` is.
pub const IDENTITY_ANNOUNCEMENT_V3_MAGIC: &[u8; 4] = b"X0A3";

/// Wire magic for the V3.1 envelope (ADR-0036): the V3 shape plus the
/// trailing `self_name`. Pre-0036 nodes treat it exactly as they treated
/// `X0A3` before it existed: an unknown magic, log-and-drop — which is why
/// the legacy `X0A3` beat is dual-published alongside it while named.
pub const IDENTITY_ANNOUNCEMENT_V3_1_MAGIC: &[u8; 4] = b"X0A4";

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

/// Everything the machine key signs for a V3.1 (`X0A4`) beat: the V3
/// unsigned shape PLUS `self_name` (ADR-0036 review P0-3: the name is
/// machine-signed on named beats — an unsigned suffix would let any peer
/// republish another agent's core with an attacker-chosen name and have it
/// cached). The legacy `X0A3` signature never covers the name.
#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityAnnouncementV31Unsigned {
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
    self_name: Option<String>,
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
    /// Agent self-name (ADR-0036). Serialization depends on the envelope:
    /// the legacy V3 (`X0A3`) serializer DROPS it so the beat stays
    /// byte-identical to pre-0036 and old decoders keep working (for them
    /// the name is effectively unsigned and never cached), while the V3.1
    /// (`X0A4`) envelope carries it INSIDE the machine-signed V3.1
    /// unsigned body (the private `IdentityAnnouncementV31Unsigned`
    /// shape) — [`Self::sign_v3_1`] signs it
    /// (ADR-0036 review P0-3: an unsigned name would let any peer
    /// republish another agent's core under an attacker-chosen name).
    /// The X0A4 body always serializes the field (bincode is positional; a
    /// conditionally-absent trailing field would be undecodable), `None`
    /// meaning "explicitly unnamed"; which form was signed is recorded in
    /// [`Self::v31_signed`]. It never enters `cert_digest` — that digest
    /// commits to `bincode((user_id, agent_certificate))` only, so the
    /// digest gate and the blob fetch/verify path are untouched.
    #[serde(default)]
    pub self_name: Option<String>,

    /// Which canonical form `machine_signature` covers: `false` = the
    /// legacy V3 unsigned bytes (`X0A3`), `true` = the V3.1 unsigned bytes
    /// (`X0A4`, name signed). Set by [`Self::sign_v3_1`] and by
    /// [`deserialize_v3`] (from the envelope magic); never serialized —
    /// `verify()` uses it to reconstruct the signed bytes, so flipping it
    /// on a forged card merely fails the signature.
    #[serde(skip)]
    pub v31_signed: bool,
}

/// The V3 (`X0A3`) wire shape: [`IdentityAnnouncementV3`] minus the
/// trailing `self_name` — exactly what pre-0036 peers encode and decode.
/// bincode is positional and NOT self-describing, so the V3 and V3.1
/// bodies are distinct FIXED layouts distinguished by envelope magic, not
/// by field presence (`#[serde(default)]` cannot express "field absent" in
/// bincode's struct-as-seq decode — it errors `UnexpectedEof` instead).
/// Keep this struct in lockstep with `IdentityAnnouncementV3`'s
/// pre-`self_name` fields — `x0a3_beat_is_byte_identical_to_pre0036_shape`
/// guards the pairing against a frozen copy of the old struct.
#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityAnnouncementV3Core {
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
    machine_signature: Vec<u8>,
}

impl IdentityAnnouncementV3Core {
    /// Project the current shape onto the legacy V3 body (name dropped).
    fn from_current(v: &IdentityAnnouncementV3) -> Self {
        Self {
            agent_id: v.agent_id,
            machine_id: v.machine_id,
            agent_public_key: v.agent_public_key.clone(),
            machine_public_key: v.machine_public_key.clone(),
            addresses: v.addresses.clone(),
            announced_at: v.announced_at,
            nat_type: v.nat_type.clone(),
            can_receive_direct: v.can_receive_direct,
            is_relay: v.is_relay,
            is_coordinator: v.is_coordinator,
            reachable_via: v.reachable_via.clone(),
            relay_candidates: v.relay_candidates.clone(),
            cert_digest: v.cert_digest,
            payload_version: v.payload_version,
            machine_signature: v.machine_signature.clone(),
        }
    }
}

impl From<IdentityAnnouncementV3Core> for IdentityAnnouncementV3 {
    fn from(core: IdentityAnnouncementV3Core) -> Self {
        Self {
            agent_id: core.agent_id,
            machine_id: core.machine_id,
            agent_public_key: core.agent_public_key,
            machine_public_key: core.machine_public_key,
            addresses: core.addresses,
            announced_at: core.announced_at,
            nat_type: core.nat_type,
            can_receive_direct: core.can_receive_direct,
            is_relay: core.is_relay,
            is_coordinator: core.is_coordinator,
            reachable_via: core.reachable_via,
            relay_candidates: core.relay_candidates,
            cert_digest: core.cert_digest,
            payload_version: core.payload_version,
            machine_signature: core.machine_signature,
            self_name: None,
            v31_signed: false,
        }
    }
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

/// Sign canonical bytes with the machine key (shared by both envelopes).
fn sign_canonical_bytes(
    machine_secret: &ant_quic::MlDsaSecretKey,
    bytes: &[u8],
) -> error::Result<Vec<u8>> {
    ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(machine_secret, bytes)
        .map(|sig| sig.as_bytes().to_vec())
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "failed to sign announcement with machine key: {e:?}"
            )))
        })
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
            self_name: v2.self_name.clone(),
            payload_version,
            machine_signature: Vec::new(),
            v31_signed: false,
        };
        // Signs the LEGACY (X0A3) canonical form — the form every existing
        // peer verifies. Call [`Self::sign_v3_1`] afterwards to re-sign for
        // the V3.1 envelope before [`serialize_v3_1`].
        v3.machine_signature = sign_canonical_bytes(
            machine_secret,
            &bincode::serialize(&v3.to_unsigned()).map_err(|e| {
                error::IdentityError::Serialization(format!(
                    "failed to serialize unsigned v3 announcement: {e}"
                ))
            })?,
        )?;
        Ok(v3)
    }

    /// Re-sign for the V3.1 (`X0A4`) envelope: the machine signature is
    /// recomputed over the V3.1 canonical bytes, which COMMIT `self_name`
    /// (review P0-3 — a name outside the signature was forgeable by
    /// republishing another agent's core). After this call the in-memory
    /// value verifies as V3.1 only; serialize the legacy beat BEFORE
    /// calling this.
    ///
    /// # Errors
    /// Returns an error if serialization or ML-DSA signing fails.
    pub fn sign_v3_1(&mut self, machine_secret: &ant_quic::MlDsaSecretKey) -> error::Result<()> {
        let unsigned = IdentityAnnouncementV31Unsigned {
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
            self_name: self.self_name.clone(),
        };
        self.machine_signature = sign_canonical_bytes(
            machine_secret,
            &bincode::serialize(&unsigned).map_err(|e| {
                error::IdentityError::Serialization(format!(
                    "failed to serialize unsigned v3.1 announcement: {e}"
                ))
            })?,
        )?;
        self.v31_signed = true;
        Ok(())
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
        // Pick the canonical form the signature covers. The flag is set at
        // decode time from the envelope magic and at sign time — an
        // attacker flipping it only changes WHICH bytes are reconstructed,
        // and the signature matches exactly one of the two forms.
        let unsigned_bytes = if self.v31_signed {
            let v31 = IdentityAnnouncementV31Unsigned {
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
                self_name: self.self_name.clone(),
            };
            bincode::serialize(&v31).map_err(|e| {
                error::IdentityError::Serialization(format!(
                    "failed to serialize unsigned v3.1 announcement: {e}"
                ))
            })?
        } else {
            bincode::serialize(&self.to_unsigned()).map_err(|e| {
                error::IdentityError::Serialization(format!(
                    "failed to serialize v3 announcement for verification: {e}"
                ))
            })?
        };
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
            self_name: self.self_name,
        }
    }
}

/// Whether a raw discovery payload is a V3-family envelope (V3 `X0A3` or
/// V3.1 `X0A4`).
pub fn is_v3_payload(payload: &[u8]) -> bool {
    payload.len() >= IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()
        && (&payload[..IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()] == IDENTITY_ANNOUNCEMENT_V3_MAGIC
            || &payload[..IDENTITY_ANNOUNCEMENT_V3_1_MAGIC.len()]
                == IDENTITY_ANNOUNCEMENT_V3_1_MAGIC)
}

/// Serialize a V3 announcement in the LEGACY `X0A3` envelope.
///
/// The `self_name` is deliberately DROPPED: this body is byte-identical to
/// the pre-0036 wire form so pre-0036 decoders (positional bincode +
/// `reject_trailing_bytes`) keep accepting every beat. A named install
/// publishes [`serialize_v3_1`] alongside this.
pub fn serialize_v3(
    announcement: &IdentityAnnouncementV3,
) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    use bincode::Options;
    let body = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&IdentityAnnouncementV3Core::from_current(announcement))?;
    let mut out = Vec::with_capacity(IDENTITY_ANNOUNCEMENT_V3_MAGIC.len() + body.len());
    out.extend_from_slice(IDENTITY_ANNOUNCEMENT_V3_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Serialize a V3.1 announcement in the `X0A4` envelope, carrying
/// `self_name`. Published IN ADDITION to the legacy [`serialize_v3`] beat
/// while an install is named; pre-0036 nodes see an unknown magic and drop
/// it, losing nothing (their beat arrives as `X0A3`).
pub fn serialize_v3_1(
    announcement: &IdentityAnnouncementV3,
) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    use bincode::Options;
    let body = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(announcement)?;
    let mut out = Vec::with_capacity(IDENTITY_ANNOUNCEMENT_V3_1_MAGIC.len() + body.len());
    out.extend_from_slice(IDENTITY_ANNOUNCEMENT_V3_1_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Deserialize a V3-family envelope. The magic selects the fixed body
/// layout (positional bincode cannot self-describe, so each envelope
/// parses with exactly one strict shape — no cross-shape fallback, no
/// trailing bytes). Callers MUST run [`IdentityAnnouncementV3::verify`]
/// before acting on the result.
pub fn deserialize_v3(payload: &[u8]) -> Result<IdentityAnnouncementV3, Box<bincode::ErrorKind>> {
    use bincode::Options;
    let opts = || {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
            .reject_trailing_bytes()
    };
    if payload.len() >= IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()
        && &payload[..IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()] == IDENTITY_ANNOUNCEMENT_V3_MAGIC
    {
        return opts()
            .deserialize::<IdentityAnnouncementV3Core>(
                &payload[IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()..],
            )
            .map(IdentityAnnouncementV3::from);
    }
    if payload.len() >= IDENTITY_ANNOUNCEMENT_V3_1_MAGIC.len()
        && &payload[..IDENTITY_ANNOUNCEMENT_V3_1_MAGIC.len()] == IDENTITY_ANNOUNCEMENT_V3_1_MAGIC
    {
        let mut v31: IdentityAnnouncementV3 =
            opts().deserialize(&payload[IDENTITY_ANNOUNCEMENT_V3_1_MAGIC.len()..])?;
        v31.v31_signed = true;
        return Ok(v31);
    }
    Err(Box::new(bincode::ErrorKind::Custom(
        "missing X0A3/X0A4 magic".to_string(),
    )))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::{AgentKeypair, MachineKeypair};

    /// Build a V2 announcement (anonymous) with real keypairs, then derive V3.
    fn v2_and_v3() -> (
        crate::IdentityAnnouncement,
        MachineKeypair,
        IdentityAnnouncementV3,
    ) {
        let agent = AgentKeypair::generate().unwrap();
        let machine = MachineKeypair::generate().unwrap();
        let v2 = crate::IdentityAnnouncement {
            self_name: None,
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
        (v2, machine, v3)
    }

    /// L3's whole point: the self-verifying beat must stay small. 8 KB is the
    /// design ceiling (2 ML-DSA pubkeys + 1 signature + fields + envelope);
    /// a regression above it means someone re-inlined a blob that belongs
    /// behind the digest.
    #[test]
    fn v3_wire_size_stays_under_8kb() {
        let (_, _machine, v3) = v2_and_v3();
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
        let (v2, _machine, v3) = v2_and_v3();
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
        let (_, _machine, v3) = v2_and_v3();
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
        let (_, _machine, v3) = v2_and_v3();
        let encoded = serialize_v3(&v3).unwrap();
        assert!(
            crate::deserialize_identity_announcement(&encoded).is_err(),
            "a V3 envelope must not be decodable under V2/legacy rules"
        );
    }

    // ── ADR-0036: agent self-name on the V3 announce ─────────────────────

    /// The pre-0036 wire shape: exactly `IdentityAnnouncementV3` minus
    /// `self_name`. Defined in the test so compat is proven against a
    /// frozen copy of the old struct, not against today's.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct IdentityAnnouncementV3Pre0036 {
        agent_id: crate::identity::AgentId,
        machine_id: crate::identity::MachineId,
        agent_public_key: Vec<u8>,
        machine_public_key: Vec<u8>,
        addresses: Vec<std::net::SocketAddr>,
        announced_at: u64,
        nat_type: Option<String>,
        can_receive_direct: Option<bool>,
        is_relay: Option<bool>,
        is_coordinator: Option<bool>,
        reachable_via: Vec<crate::identity::MachineId>,
        relay_candidates: Vec<crate::identity::MachineId>,
        cert_digest: [u8; 32],
        payload_version: u64,
        machine_signature: Vec<u8>,
    }

    impl IdentityAnnouncementV3Pre0036 {
        fn from_current(v: &IdentityAnnouncementV3) -> Self {
            Self {
                agent_id: v.agent_id,
                machine_id: v.machine_id,
                agent_public_key: v.agent_public_key.clone(),
                machine_public_key: v.machine_public_key.clone(),
                addresses: v.addresses.clone(),
                announced_at: v.announced_at,
                nat_type: v.nat_type.clone(),
                can_receive_direct: v.can_receive_direct,
                is_relay: v.is_relay,
                is_coordinator: v.is_coordinator,
                reachable_via: v.reachable_via.clone(),
                relay_candidates: v.relay_candidates.clone(),
                cert_digest: v.cert_digest,
                payload_version: v.payload_version,
                machine_signature: v.machine_signature.clone(),
            }
        }
    }

    /// WHY: the legacy `X0A3` serializer drops the name by construction, so
    /// even a NAMED install's legacy beat must serialize to exactly the
    /// pre-0036 bytes — old peers run `reject_trailing_bytes` on this body
    /// and would drop a beat that grew even one tag byte.
    #[test]
    fn x0a3_beat_is_byte_identical_to_pre0036_shape() {
        let (_, _machine, v3) = v2_and_v3();
        let encoded = serialize_v3(&v3).unwrap();
        let old_bytes = {
            use bincode::Options;
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .serialize(&IdentityAnnouncementV3Pre0036::from_current(&v3))
                .unwrap()
        };
        assert_eq!(
            &encoded[IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()..],
            &old_bytes[..],
            "the X0A3 body must be byte-identical to the frozen pre-0036 shape"
        );
        assert_eq!(
            &encoded[..IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()],
            IDENTITY_ANNOUNCEMENT_V3_MAGIC
        );
    }

    /// WHY: bidirectional old-peer compat on the legacy envelope. (a) A beat
    /// from a pre-0036 peer carries no self_name — the `X0A3` decode maps it
    /// to `None` and the machine signature still verifies (the name lives
    /// outside the signed struct). (b) A named install's `X0A3` beat must
    /// decode under a FROZEN pre-0036 decoder — the exact path an old peer
    /// runs, proving the dual publish keeps old peers' caches populated.
    #[test]
    fn x0a3_beat_decodes_under_frozen_pre0036_decoder_and_back() {
        use bincode::Options;
        let (_, _machine, v3) = v2_and_v3();
        // (a) old peer's beat → new decoder.
        let old_body = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&IdentityAnnouncementV3Pre0036::from_current(&v3))
            .unwrap();
        let mut envelope = IDENTITY_ANNOUNCEMENT_V3_MAGIC.to_vec();
        envelope.extend_from_slice(&old_body);
        let decoded = deserialize_v3(&envelope).expect("old-shape body must decode");
        assert_eq!(decoded.self_name, None);
        decoded
            .verify()
            .expect("old-shape beat must still verify (name outside signature)");

        // (b) named install's legacy beat → frozen pre-0036 decoder.
        let legacy = serialize_v3(&v3).unwrap();
        let frozen: IdentityAnnouncementV3Pre0036 = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
            .reject_trailing_bytes()
            .deserialize(&legacy[IDENTITY_ANNOUNCEMENT_V3_MAGIC.len()..])
            .expect("an X0A3 beat must parse under the old decoder");
        assert_eq!(frozen.agent_id, v3.agent_id);
    }

    /// `v2_and_v3` with a self-name set on the V2 (the machine key is the
    /// one the V2's `machine_public_key` was built from, so re-deriving V3
    /// from this V2 verifies).
    fn v2_and_v3_named() -> (
        crate::IdentityAnnouncement,
        MachineKeypair,
        IdentityAnnouncementV3,
    ) {
        let (mut v2, machine, mut v3) = v2_and_v3();
        v2.self_name = Some("fae".to_string());
        v3.self_name = Some("fae".to_string());
        // V3.1 requires the dedicated re-sign: build_from_v2 signs the
        // legacy form; the X0A4 beat must sign the name-inclusive bytes.
        v3.sign_v3_1(machine.secret_key()).unwrap();
        (v2, machine, v3)
    }

    /// WHY: a named V3.1 (`X0A4`) beat must round-trip its self-name
    /// end-to-end and stay verifiable; the same announcement's legacy
    /// `X0A3` beat must drop the name (dual publish); and the name must
    /// never leak into `cert_digest` — the digest gate and the blob cache
    /// are keyed on `blake3(bincode((user_id, cert)))` and old peers verify
    /// fetched blobs under exactly that rule.
    #[test]
    fn v3_1_self_name_round_trips_and_leaves_cert_digest_untouched() {
        let (v2, machine, v3) = v2_and_v3_named();
        let digest_before = cert_digest(&v2.user_id, &v2.agent_certificate);

        assert_eq!(v3.self_name.as_deref(), Some("fae"));
        assert_eq!(v3.cert_digest, digest_before);
        v3.verify().expect("named v3 must verify");

        // V3.1 wire round-trip keeps the name through the V2 conversion.
        let x0a4 = serialize_v3_1(&v3).unwrap();
        assert_eq!(
            &x0a4[..IDENTITY_ANNOUNCEMENT_V3_1_MAGIC.len()],
            IDENTITY_ANNOUNCEMENT_V3_1_MAGIC
        );
        let decoded = deserialize_v3(&x0a4).unwrap();
        assert_eq!(decoded.self_name.as_deref(), Some("fae"));
        let converted = decoded.into_announcement();
        assert_eq!(converted.self_name.as_deref(), Some("fae"));

        // The legacy beat of the SAME announcement drops the name and still
        // verifies as X0A3. The publisher serializes the legacy beat BEFORE
        // the V3.1 re-sign (see the heartbeat path); mirror that order by
        // building a legacy-signed struct from the same v2.
        let legacy_struct =
            IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0).unwrap();
        let legacy = deserialize_v3(&serialize_v3(&legacy_struct).unwrap()).unwrap();
        assert_eq!(legacy.self_name, None);
        assert_eq!(legacy.agent_id, v3.agent_id);
        legacy
            .verify()
            .expect("the legacy companion beat must verify as X0A3");

        // The name never changes the digest (pair-only input).
        let digest_after = cert_digest(&v2.user_id, &v2.agent_certificate);
        assert_eq!(digest_before, digest_after);
    }

    /// WHY (review P0-3): the self-name must be UNFORGEABLE. On V3.1 it is
    /// machine-signed, so a peer that captures a beat and republishes it
    /// with a replaced, stripped, or flag-flipped name fails signature
    /// verification — the attack of "relabel another agent's core with an
    /// attacker-chosen name and have it cached" is closed.
    #[test]
    fn v3_1_self_name_tampering_fails_signature_verification() {
        let (_, _machine, v3) = v2_and_v3_named();

        // Replace the name on an otherwise-valid V3.1 beat.
        let mut renamed = v3.clone();
        renamed.self_name = Some("mallory".to_string());
        assert!(
            renamed.verify().is_err(),
            "a replaced self_name must fail the V3.1 signature"
        );

        // Strip the name from a named V3.1 beat (relabel to anonymous).
        let mut stripped = v3.clone();
        stripped.self_name = None;
        assert!(
            stripped.verify().is_err(),
            "stripping the self_name must fail the V3.1 signature"
        );

        // Flip the canonical-form flag on a LEGACY-signed beat to try to
        // smuggle an unsigned name through the V3.1 path.
        let (v2, machine, _) = v2_and_v3_named();
        let mut legacy =
            IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0).unwrap();
        legacy.self_name = Some("mallory".to_string());
        legacy.v31_signed = true; // pretends the name is signed
        assert!(
            legacy.verify().is_err(),
            "a legacy signature must never validate the V3.1 form"
        );
    }
}
