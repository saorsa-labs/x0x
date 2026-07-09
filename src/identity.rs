#![allow(missing_docs)]
//! Core identity types for x0x agents.
//!
//! This module provides the cryptographic identity foundation for x0x,
//! implementing a three-layer hierarchy:
//!
//! - **MachineId**: Machine-pinned identity for QUIC authentication
//! - **AgentId**: Portable agent identity for cross-machine persistence
//! - **UserId**: Human/operator identity that owns multiple agents
//!
//! The trust chain flows: User → Agent → Machine, where each layer
//! signs a certificate binding the layer below.

use ant_quic::{
    derive_peer_id_from_public_key, MlDsaPublicKey, MlDsaSecretKey, PeerId as AntQuicPeerId,
};
use hex;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Length of a PeerId in bytes (SHA-256 hash output).
pub const PEER_ID_LENGTH: usize = 32;

/// PeerId type from ant-quic.
/// A PeerId is a 32-byte identifier derived from a public key via SHA-256 hashing.
pub type PeerId = AntQuicPeerId;

/// Machine-pinned identity derived from ML-DSA-65 keypair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub [u8; PEER_ID_LENGTH]);

/// Portable agent identity derived from ML-DSA-65 keypair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub [u8; PEER_ID_LENGTH]);

/// Human/operator identity derived from ML-DSA-65 keypair.
///
/// A UserId represents a long-lived human identity that can own
/// multiple agents. This enables trust scoring across machines:
/// "user X has used machines X, Y, Z."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub [u8; PEER_ID_LENGTH]);

impl MachineId {
    /// Derive a MachineId from an ML-DSA-65 public key.
    #[inline]
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }
    /// Get the raw 32-byte representation.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LENGTH] {
        &self.0
    }
    /// Convert to `Vec<u8>`.
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    /// Verify that this MachineId matches the given public key.
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<(), crate::error::IdentityError> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived {
            Ok(())
        } else {
            Err(crate::error::IdentityError::PeerIdMismatch)
        }
    }
}

impl AgentId {
    /// Derive an AgentId from an ML-DSA-65 public key.
    #[inline]
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }
    /// Get the raw 32-byte representation.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LENGTH] {
        &self.0
    }
    /// Convert to `Vec<u8>`.
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    /// Verify that this AgentId matches the given public key.
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<(), crate::error::IdentityError> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived {
            Ok(())
        } else {
            Err(crate::error::IdentityError::PeerIdMismatch)
        }
    }
}

impl UserId {
    /// Derive a UserId from an ML-DSA-65 public key.
    #[inline]
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }
    /// Get the raw 32-byte representation.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LENGTH] {
        &self.0
    }
    /// Convert to `Vec<u8>`.
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    /// Verify that this UserId matches the given public key.
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<(), crate::error::IdentityError> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived {
            Ok(())
        } else {
            Err(crate::error::IdentityError::PeerIdMismatch)
        }
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserId(0x{})", hex::encode(&self.0[..8]))
    }
}

impl std::fmt::Display for MachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MachineId(0x{})", hex::encode(&self.0[..8]))
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgentId(0x{})", hex::encode(&self.0[..8]))
    }
}

/// Machine-pinned ML-DSA-65 keypair.
pub struct MachineKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl std::fmt::Debug for MachineKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineKeypair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<REDACTED>")
            .finish()
    }
}

impl Drop for MachineKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl MachineKeypair {
    /// Generate a new random MachineKeypair.
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        let (public_key, secret_key) = ant_quic::generate_ml_dsa_keypair()
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
    /// Get a reference to the public key.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }
    /// Get the MachineId for this keypair.
    #[inline]
    #[must_use]
    pub fn machine_id(&self) -> MachineId {
        MachineId::from_public_key(&self.public_key)
    }
    /// Get a reference to the secret key.
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &MlDsaSecretKey {
        &self.secret_key
    }
    /// Create a MachineKeypair from serialized bytes.
    pub fn from_bytes(
        public_key_bytes: &[u8],
        secret_key_bytes: &[u8],
    ) -> Result<Self, crate::error::IdentityError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes).map_err(|_| {
            crate::error::IdentityError::InvalidPublicKey("failed to parse public key".to_string())
        })?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes).map_err(|_| {
            crate::error::IdentityError::InvalidSecretKey("failed to parse secret key".to_string())
        })?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
    /// Serialize the keypair to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.public_key.as_bytes().to_vec(),
            self.secret_key.as_bytes().to_vec(),
        )
    }
}

/// Portable agent ML-DSA-65 keypair.
pub struct AgentKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl std::fmt::Debug for AgentKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKeypair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<REDACTED>")
            .finish()
    }
}

impl Drop for AgentKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl AgentKeypair {
    /// Generate a new random AgentKeypair.
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        let (public_key, secret_key) = ant_quic::generate_ml_dsa_keypair()
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
    /// Get a reference to the public key.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }
    /// Get the AgentId for this keypair.
    #[inline]
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        AgentId::from_public_key(&self.public_key)
    }
    /// Get a reference to the secret key.
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &MlDsaSecretKey {
        &self.secret_key
    }
    /// Create an AgentKeypair from serialized bytes.
    pub fn from_bytes(
        public_key_bytes: &[u8],
        secret_key_bytes: &[u8],
    ) -> Result<Self, crate::error::IdentityError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes).map_err(|_| {
            crate::error::IdentityError::InvalidPublicKey("failed to parse public key".to_string())
        })?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes).map_err(|_| {
            crate::error::IdentityError::InvalidSecretKey("failed to parse secret key".to_string())
        })?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
    /// Serialize the keypair to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.public_key.as_bytes().to_vec(),
            self.secret_key.as_bytes().to_vec(),
        )
    }
}

/// Human/operator ML-DSA-65 keypair.
///
/// Represents the long-lived cryptographic identity of a human operator.
/// Unlike machine and agent keys which auto-generate, user keys must be
/// explicitly created — creating a human identity is an intentional act.
pub struct UserKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl std::fmt::Debug for UserKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserKeypair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<REDACTED>")
            .finish()
    }
}

impl Drop for UserKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl UserKeypair {
    /// Generate a new random UserKeypair.
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        let (public_key, secret_key) = ant_quic::generate_ml_dsa_keypair()
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Generate a UserKeypair deterministically from a 32-byte seed.
    ///
    /// Uses the FIPS 204 seeded KeyGen (the ξ input), so the same seed
    /// produces the same ML-DSA-65 keypair on any machine, every time —
    /// the foundation for mnemonic-based identity portability (issue #95).
    /// Mnemonic ↔ seed encoding (e.g. BIP-39) is the consumer
    /// application's responsibility; x0x performs only the
    /// seed → keypair step.
    ///
    /// The seed must be high-entropy (32 random bytes). Anyone who learns
    /// the seed can reconstruct the secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated key bytes cannot be converted
    /// into the transport key types (never expected for a valid seed).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, crate::error::IdentityError> {
        use fips204::traits::{KeyGen, SerDes};
        let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(seed);
        let public_key = MlDsaPublicKey::from_bytes(&pk.into_bytes())
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{e:?}")))?;
        let secret_key = MlDsaSecretKey::from_bytes(&sk.into_bytes())
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{e:?}")))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
    /// Get a reference to the public key.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }
    /// Get the UserId for this keypair.
    #[inline]
    #[must_use]
    pub fn user_id(&self) -> UserId {
        UserId::from_public_key(&self.public_key)
    }
    /// Get a reference to the secret key.
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &MlDsaSecretKey {
        &self.secret_key
    }
    /// Create a UserKeypair from serialized bytes.
    pub fn from_bytes(
        public_key_bytes: &[u8],
        secret_key_bytes: &[u8],
    ) -> Result<Self, crate::error::IdentityError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes).map_err(|_| {
            crate::error::IdentityError::InvalidPublicKey("failed to parse public key".to_string())
        })?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes).map_err(|_| {
            crate::error::IdentityError::InvalidSecretKey("failed to parse secret key".to_string())
        })?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
    /// Serialize the keypair to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.public_key.as_bytes().to_vec(),
            self.secret_key.as_bytes().to_vec(),
        )
    }
}

/// Clock-skew tolerance, in seconds, applied to every credential expiry
/// check across the codebase (certificates today; future expiring records).
///
/// A credential is only treated as expired once `now` is more than this many
/// seconds past its `not_after`, so honestly-issued credentials are not
/// rejected because two machines' clocks disagree by a few minutes.
pub const EXPIRY_CLOCK_SKEW_SECS: u64 = 300;

/// Return whether an optional `not_after` expiry has elapsed at `now_unix`,
/// applying [`EXPIRY_CLOCK_SKEW_SECS`] tolerance.
///
/// **Absence of expiry means valid forever**: `None` is never expired. This
/// is the default-safe rule that keeps pre-expiry credentials (old key files
/// and certificates with no `not_after`) valid without any migration. Fail
/// **open** only for a genuinely-missing expiry — never for a present one.
#[must_use]
pub fn is_expired(not_after: Option<u64>, now_unix: u64) -> bool {
    match not_after {
        None => false,
        Some(not_after) => now_unix > not_after.saturating_add(EXPIRY_CLOCK_SKEW_SECS),
    }
}

/// Certificate binding an agent to a user identity.
///
/// An `AgentCertificate` is a cryptographic attestation that a specific agent
/// belongs to a specific user. It is created by signing the agent's public key
/// with the user's secret key.
///
/// # Signed message format and versioning
///
/// When the certificate has **no expiry** (`not_after == None`) the signed
/// message is byte-identical to every certificate x0x has ever issued:
/// `b"x0x-agent-cert-v1" || user_pubkey || agent_pubkey || issued_at`.
/// Such a certificate verifies unchanged — **absence of expiry means valid
/// forever**.
///
/// When an expiry **is** present the signed message uses a distinct domain
/// prefix and appends the expiry, so `not_after` is signature-covered:
/// `b"x0x-agent-cert-v2" || user_pubkey || agent_pubkey || issued_at ||
/// not_after`. Stripping or altering the expiry therefore fails verification
/// rather than silently extending validity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCertificate {
    /// The user's ML-DSA-65 public key bytes.
    user_public_key: Vec<u8>,
    /// The agent's ML-DSA-65 public key bytes.
    agent_public_key: Vec<u8>,
    /// ML-DSA-65 signature over the certificate message.
    signature: Vec<u8>,
    /// Unix timestamp when the certificate was issued.
    issued_at: u64,
    /// Optional Unix timestamp after which the certificate is expired.
    ///
    /// `None` (the default for legacy certificates) means the certificate
    /// never expires. When present it is covered by the signature.
    ///
    /// NOTE on `#[serde(default)]`: bincode is a positional (non-self-describing)
    /// format and IGNORES `serde(default)` — it cannot recover a trailing field
    /// that is absent from the byte stream. This attribute therefore only aids
    /// self-describing formats (JSON/TOML). On-disk cert files stay
    /// backward-compatible via the explicit magic-marker versioning in
    /// [`to_storage_bytes`](Self::to_storage_bytes) /
    /// [`from_storage_bytes`](Self::from_storage_bytes), NOT via this attribute.
    /// For certificates embedded in gossip announcements the extra positional
    /// bytes ARE a wire-format change: this is the known, coordinated
    /// fleet-upgrade break documented in the plan (D3) — the "no breaking
    /// change" guarantee covers on-disk key/cert files only, not the
    /// announcement wire format in a mixed-version fleet carrying user-certified
    /// agents.
    #[serde(default)]
    not_after: Option<u64>,
}

/// On-disk shape of a pre-#130 (`v1`) certificate: the four original fields
/// with no `not_after`. Used only to decode legacy `agent.cert` files, which
/// were written as a bare `bincode(AgentCertificate)` before the expiry field
/// existed. Mapped into an [`AgentCertificate`] with `not_after: None`.
#[derive(Serialize, Deserialize)]
struct AgentCertificateV1Disk {
    user_public_key: Vec<u8>,
    agent_public_key: Vec<u8>,
    signature: Vec<u8>,
    issued_at: u64,
}

impl AgentCertificate {
    /// Certificate message prefix for domain separation (no-expiry / v1).
    const CERT_PREFIX: &'static [u8] = b"x0x-agent-cert-v1";

    /// Certificate message prefix for domain separation (with-expiry / v2).
    const CERT_V2_PREFIX: &'static [u8] = b"x0x-agent-cert-v2";

    /// Magic marker prefixing an expiry-carrying (`v2`) certificate on disk.
    ///
    /// A legacy `agent.cert` begins with the bincode length prefix of the
    /// ML-DSA-65 user public key (`0xA0 0x07 …`), so it can never collide
    /// with this marker; its absence unambiguously means "legacy, no expiry".
    const CERT_DISK_V2_MAGIC: &'static [u8; 4] = b"X0C2";

    /// Issue a new certificate binding an agent to a user.
    ///
    /// Signs `b"x0x-agent-cert-v1" || user_pubkey || agent_pubkey || timestamp`
    /// with the user's secret key.
    pub fn issue(
        user_kp: &UserKeypair,
        agent_kp: &AgentKeypair,
    ) -> Result<Self, crate::error::IdentityError> {
        Self::issue_with_expiry(user_kp, agent_kp, None)
    }

    /// Issue a new certificate binding an agent to a user, with an optional
    /// expiry.
    ///
    /// `not_after == None` produces a non-expiring certificate whose signed
    /// message is byte-identical to [`issue`](Self::issue) (v1). `Some`
    /// produces a v2 certificate whose expiry is covered by the signature.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::IdentityError::CertificateVerification`] if the
    /// system clock is before the Unix epoch or signing fails.
    pub fn issue_with_expiry(
        user_kp: &UserKeypair,
        agent_kp: &AgentKeypair,
        not_after: Option<u64>,
    ) -> Result<Self, crate::error::IdentityError> {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                crate::error::IdentityError::CertificateVerification(format!(
                    "system time error: {}",
                    e
                ))
            })?
            .as_secs();

        let user_pub_bytes = user_kp.public_key().as_bytes().to_vec();
        let agent_pub_bytes = agent_kp.public_key().as_bytes().to_vec();

        let message = Self::build_message(&user_pub_bytes, &agent_pub_bytes, issued_at, not_after);

        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            user_kp.secret_key(),
            &message,
        )
        .map_err(|e| {
            crate::error::IdentityError::CertificateVerification(format!("signing failed: {:?}", e))
        })?;

        Ok(Self {
            user_public_key: user_pub_bytes,
            agent_public_key: agent_pub_bytes,
            signature: signature.as_bytes().to_vec(),
            issued_at,
            not_after,
        })
    }

    /// Verify the certificate signature.
    ///
    /// Reconstructs the signed message and verifies the ML-DSA-65 signature
    /// against the stored user public key.
    pub fn verify(&self) -> Result<(), crate::error::IdentityError> {
        let user_pubkey = MlDsaPublicKey::from_bytes(&self.user_public_key).map_err(|_| {
            crate::error::IdentityError::CertificateVerification(
                "invalid user public key in certificate".to_string(),
            )
        })?;

        let signature =
            ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&self.signature)
                .map_err(|e| {
                    crate::error::IdentityError::CertificateVerification(format!(
                        "invalid signature format: {:?}",
                        e
                    ))
                })?;

        let message = Self::build_message(
            &self.user_public_key,
            &self.agent_public_key,
            self.issued_at,
            self.not_after,
        );

        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &user_pubkey,
            &message,
            &signature,
        )
        .map_err(|e| {
            crate::error::IdentityError::CertificateVerification(format!(
                "signature verification failed: {:?}",
                e
            ))
        })
    }

    /// Derive the UserId from the stored user public key.
    pub fn user_id(&self) -> Result<UserId, crate::error::IdentityError> {
        let pubkey = MlDsaPublicKey::from_bytes(&self.user_public_key).map_err(|_| {
            crate::error::IdentityError::CertificateVerification(
                "invalid user public key in certificate".to_string(),
            )
        })?;
        Ok(UserId::from_public_key(&pubkey))
    }

    /// Derive the AgentId from the stored agent public key.
    pub fn agent_id(&self) -> Result<AgentId, crate::error::IdentityError> {
        let pubkey = MlDsaPublicKey::from_bytes(&self.agent_public_key).map_err(|_| {
            crate::error::IdentityError::CertificateVerification(
                "invalid agent public key in certificate".to_string(),
            )
        })?;
        Ok(AgentId::from_public_key(&pubkey))
    }

    /// Get the raw ML-DSA-65 agent public key bytes stored in this certificate.
    ///
    /// Used by the forward-attestation path to look up the cached agent key
    /// for verifying an inbound `ForwardV2` header signature (#204).
    #[must_use]
    pub fn agent_public_key(&self) -> &[u8] {
        &self.agent_public_key
    }

    /// Get the issuance timestamp.
    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Get the optional expiry timestamp (`None` ⇒ never expires).
    #[must_use]
    pub fn not_after(&self) -> Option<u64> {
        self.not_after
    }

    /// Return whether this certificate is expired at `now_unix`, applying
    /// [`EXPIRY_CLOCK_SKEW_SECS`] tolerance. A certificate with no expiry is
    /// never expired.
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        is_expired(self.not_after, now_unix)
    }

    /// Encode this certificate for on-disk storage.
    ///
    /// A non-expiring certificate is written as the legacy `v1` bincode shape
    /// (byte-identical to pre-#130 `agent.cert` files) so downgrades keep
    /// working; an expiring certificate is written as the `X0C2` magic marker
    /// followed by the full bincode encoding.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::IdentityError::Serialization`] on encode failure.
    pub fn to_storage_bytes(&self) -> Result<Vec<u8>, crate::error::IdentityError> {
        match self.not_after {
            None => {
                let v1 = AgentCertificateV1Disk {
                    user_public_key: self.user_public_key.clone(),
                    agent_public_key: self.agent_public_key.clone(),
                    signature: self.signature.clone(),
                    issued_at: self.issued_at,
                };
                bincode::serialize(&v1)
                    .map_err(|e| crate::error::IdentityError::Serialization(e.to_string()))
            }
            Some(_) => {
                let body = bincode::serialize(self)
                    .map_err(|e| crate::error::IdentityError::Serialization(e.to_string()))?;
                let mut out = Vec::with_capacity(Self::CERT_DISK_V2_MAGIC.len() + body.len());
                out.extend_from_slice(Self::CERT_DISK_V2_MAGIC);
                out.extend_from_slice(&body);
                Ok(out)
            }
        }
    }

    /// Decode a certificate from on-disk storage bytes.
    ///
    /// Detects the v2 magic marker; without it the bytes are a legacy v1
    /// `agent.cert` and decode with `not_after: None` (valid forever).
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::IdentityError::Serialization`] on decode failure.
    pub fn from_storage_bytes(bytes: &[u8]) -> Result<Self, crate::error::IdentityError> {
        if bytes.len() >= Self::CERT_DISK_V2_MAGIC.len()
            && &bytes[..Self::CERT_DISK_V2_MAGIC.len()] == Self::CERT_DISK_V2_MAGIC
        {
            bincode::deserialize(&bytes[Self::CERT_DISK_V2_MAGIC.len()..])
                .map_err(|e| crate::error::IdentityError::Serialization(e.to_string()))
        } else {
            let v1: AgentCertificateV1Disk = bincode::deserialize(bytes)
                .map_err(|e| crate::error::IdentityError::Serialization(e.to_string()))?;
            Ok(Self {
                user_public_key: v1.user_public_key,
                agent_public_key: v1.agent_public_key,
                signature: v1.signature,
                issued_at: v1.issued_at,
                not_after: None,
            })
        }
    }

    /// Build the message that gets signed/verified.
    ///
    /// Version-selecting: `not_after == None` reproduces the exact v1 bytes;
    /// `Some` uses the v2 prefix and appends the expiry so it is signed over.
    fn build_message(
        user_pubkey: &[u8],
        agent_pubkey: &[u8],
        timestamp: u64,
        not_after: Option<u64>,
    ) -> Vec<u8> {
        match not_after {
            None => {
                let mut message = Vec::with_capacity(
                    Self::CERT_PREFIX.len() + user_pubkey.len() + agent_pubkey.len() + 8,
                );
                message.extend_from_slice(Self::CERT_PREFIX);
                message.extend_from_slice(user_pubkey);
                message.extend_from_slice(agent_pubkey);
                message.extend_from_slice(&timestamp.to_le_bytes());
                message
            }
            Some(not_after) => {
                let mut message = Vec::with_capacity(
                    Self::CERT_V2_PREFIX.len() + user_pubkey.len() + agent_pubkey.len() + 16,
                );
                message.extend_from_slice(Self::CERT_V2_PREFIX);
                message.extend_from_slice(user_pubkey);
                message.extend_from_slice(agent_pubkey);
                message.extend_from_slice(&timestamp.to_le_bytes());
                message.extend_from_slice(&not_after.to_le_bytes());
                message
            }
        }
    }
}

/// Unified identity combining machine, agent, and optional user keypairs.
///
/// The three-layer hierarchy is:
/// ```text
/// User (human, long-lived, owns many agents)
///   └─ Agent (portable, runs on many machines)
///        └─ Machine (hardware-pinned)
/// ```
pub struct Identity {
    machine_keypair: MachineKeypair,
    agent_keypair: AgentKeypair,
    user_keypair: Option<UserKeypair>,
    agent_certificate: Option<AgentCertificate>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("machine_keypair", &self.machine_keypair)
            .field("agent_keypair", &self.agent_keypair)
            .field("user_keypair", &self.user_keypair)
            .field("agent_certificate", &self.agent_certificate)
            .finish()
    }
}

impl Identity {
    /// Create a new Identity from machine and agent keypairs.
    #[inline]
    pub fn new(machine_keypair: MachineKeypair, agent_keypair: AgentKeypair) -> Self {
        Self {
            machine_keypair,
            agent_keypair,
            user_keypair: None,
            agent_certificate: None,
        }
    }
    /// Create a new Identity with all three layers.
    #[inline]
    pub fn new_with_user(
        machine_keypair: MachineKeypair,
        agent_keypair: AgentKeypair,
        user_keypair: UserKeypair,
        agent_certificate: AgentCertificate,
    ) -> Self {
        Self {
            machine_keypair,
            agent_keypair,
            user_keypair: Some(user_keypair),
            agent_certificate: Some(agent_certificate),
        }
    }
    /// Generate a new Identity with fresh machine and agent keypairs.
    ///
    /// User keys are not auto-generated — creating a human identity
    /// is an intentional act via [`crate::AgentBuilder::with_user_key`].
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        Ok(Self {
            machine_keypair: MachineKeypair::generate()?,
            agent_keypair: AgentKeypair::generate()?,
            user_keypair: None,
            agent_certificate: None,
        })
    }
    /// Get the machine ID.
    #[inline]
    #[must_use]
    pub fn machine_id(&self) -> MachineId {
        self.machine_keypair.machine_id()
    }
    /// Get the agent ID.
    #[inline]
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        self.agent_keypair.agent_id()
    }
    /// Get the user ID, if a user keypair is present.
    #[inline]
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        self.user_keypair.as_ref().map(|kp| kp.user_id())
    }
    /// Get a reference to the machine keypair.
    #[inline]
    #[must_use]
    pub fn machine_keypair(&self) -> &MachineKeypair {
        &self.machine_keypair
    }
    /// Get a reference to the agent keypair.
    #[inline]
    #[must_use]
    pub fn agent_keypair(&self) -> &AgentKeypair {
        &self.agent_keypair
    }
    /// Get a reference to the user keypair, if present.
    #[inline]
    #[must_use]
    pub fn user_keypair(&self) -> Option<&UserKeypair> {
        self.user_keypair.as_ref()
    }
    /// Get a reference to the agent certificate, if present.
    #[inline]
    #[must_use]
    pub fn agent_certificate(&self) -> Option<&AgentCertificate> {
        self.agent_certificate.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Introduction card
// ---------------------------------------------------------------------------

/// A trust-gated service offered by an agent.
///
/// Advertised in the agent's `IntroductionCard` so that peers can discover
/// capabilities before establishing a full connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Machine-readable service name (e.g. "file-transfer", "mls-group").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Minimum trust level required to access this service.
    pub min_trust: String,
}

/// Unsigned view of an `IntroductionCard`, used as the canonical signing
/// message. Field order must stay stable — any change is a wire break.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntroductionCardUnsigned {
    agent_id: AgentId,
    machine_id: MachineId,
    user_id: Option<UserId>,
    certificate: Option<AgentCertificate>,
    display_name: Option<String>,
    identity_words: String,
    services: Vec<ServiceEntry>,
    /// Machine ML-DSA-65 public key bytes. Included in the signed payload so
    /// verifiers can bind the signature to this specific machine key without
    /// trusting an out-of-band lookup.
    machine_public_key: Vec<u8>,
}

/// An introduction card presented to peers during connection setup.
///
/// Contains the agent's identity, optional human-owner binding, advertised
/// services, and a machine signature over the payload so recipients can
/// verify authenticity without a round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroductionCard {
    /// Permanent agent identity (32-byte SHA-256 of ML-DSA-65 public key).
    pub agent_id: AgentId,
    /// Current machine identity.
    pub machine_id: MachineId,
    /// Human-owner identity, if this agent is human-backed.
    pub user_id: Option<UserId>,
    /// Certificate binding agent → user (proves user ownership).
    pub certificate: Option<AgentCertificate>,
    /// Optional human-readable display name.
    pub display_name: Option<String>,
    /// Four-word speakable identity (e.g. "bodily example dismiss galaxy").
    /// For human-backed agents: "agent words @ user words".
    pub identity_words: String,
    /// Trust-gated services offered by this agent.
    pub services: Vec<ServiceEntry>,
    /// Machine ML-DSA-65 public key bytes. Needed by verifiers to check
    /// [`IntroductionCard::signature`]; also independently bound to
    /// [`IntroductionCard::machine_id`] (which is its SHA-256).
    pub machine_public_key: Vec<u8>,
    /// ML-DSA-65 signature by the machine secret key over the canonical
    /// bincode serialisation of the card fields (excluding this signature).
    pub signature: Vec<u8>,
}

impl IntroductionCard {
    /// Domain-separation prefix for canonical card bytes. Bumped on any
    /// change to the signed field set.
    const CARD_PREFIX: &'static [u8] = b"x0x-introduction-card-v1";

    fn to_unsigned(&self) -> IntroductionCardUnsigned {
        IntroductionCardUnsigned {
            agent_id: self.agent_id,
            machine_id: self.machine_id,
            user_id: self.user_id,
            certificate: self.certificate.clone(),
            display_name: self.display_name.clone(),
            identity_words: self.identity_words.clone(),
            services: self.services.clone(),
            machine_public_key: self.machine_public_key.clone(),
        }
    }

    fn canonical_message(
        unsigned: &IntroductionCardUnsigned,
    ) -> Result<Vec<u8>, crate::error::IdentityError> {
        let body = bincode::serialize(unsigned).map_err(|e| {
            crate::error::IdentityError::Serialization(format!(
                "failed to serialise introduction card for signing: {e}"
            ))
        })?;
        let mut msg = Vec::with_capacity(Self::CARD_PREFIX.len() + body.len());
        msg.extend_from_slice(Self::CARD_PREFIX);
        msg.extend_from_slice(&body);
        Ok(msg)
    }

    /// Build an introduction card from an `Identity`, computing identity words
    /// automatically and signing the canonical payload with the machine key.
    ///
    /// # Errors
    ///
    /// Returns an error if bincode serialisation or ML-DSA-65 signing fails.
    pub fn from_identity(
        identity: &Identity,
        display_name: Option<String>,
        services: Vec<ServiceEntry>,
    ) -> Result<Self, crate::error::IdentityError> {
        let agent_id = identity.agent_id();
        let machine_id = identity.machine_id();
        let user_id = identity.user_id();
        let certificate = identity.agent_certificate().cloned();

        let encoder = four_word_networking::IdentityEncoder::new();
        let identity_words = if let Some(uid) = user_id {
            encoder
                .encode_full(agent_id.as_bytes(), uid.as_bytes())
                .map(|w| w.to_string())
                .unwrap_or_default()
        } else {
            encoder
                .encode_agent(agent_id.as_bytes())
                .map(|w| w.to_string())
                .unwrap_or_default()
        };

        let machine_public_key = identity.machine_keypair().public_key().as_bytes().to_vec();
        let unsigned = IntroductionCardUnsigned {
            agent_id,
            machine_id,
            user_id,
            certificate: certificate.clone(),
            display_name: display_name.clone(),
            identity_words: identity_words.clone(),
            services: services.clone(),
            machine_public_key: machine_public_key.clone(),
        };
        let message = Self::canonical_message(&unsigned)?;
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            identity.machine_keypair().secret_key(),
            &message,
        )
        .map_err(|e| {
            crate::error::IdentityError::CertificateVerification(format!(
                "failed to sign introduction card: {e:?}"
            ))
        })?
        .as_bytes()
        .to_vec();

        Ok(Self {
            agent_id,
            machine_id,
            user_id,
            certificate,
            display_name,
            identity_words,
            services,
            machine_public_key,
            signature,
        })
    }

    /// Verify the card's machine signature and embedded agent certificate.
    ///
    /// Checks:
    /// 1. `machine_id` matches SHA-256 of `machine_public_key`.
    /// 2. ML-DSA-65 signature over the canonical card bytes is valid.
    /// 3. If `certificate` is present: its signature verifies, its
    ///    `agent_id` matches this card's `agent_id`, and its `user_id`
    ///    matches `user_id` (when disclosed).
    ///
    /// # Errors
    ///
    /// Returns an error describing which check failed.
    pub fn verify(&self) -> Result<(), crate::error::IdentityError> {
        let machine_pub = MlDsaPublicKey::from_bytes(&self.machine_public_key).map_err(|_| {
            crate::error::IdentityError::CertificateVerification(
                "invalid machine public key in introduction card".to_string(),
            )
        })?;
        let derived_machine_id = MachineId::from_public_key(&machine_pub);
        if derived_machine_id != self.machine_id {
            return Err(crate::error::IdentityError::CertificateVerification(
                "machine_id does not match machine public key in introduction card".to_string(),
            ));
        }

        let message = Self::canonical_message(&self.to_unsigned())?;
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&self.signature)
                .map_err(|e| {
                    crate::error::IdentityError::CertificateVerification(format!(
                        "invalid introduction card signature format: {e:?}"
                    ))
                })?;
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &machine_pub,
            &message,
            &signature,
        )
        .map_err(|e| {
            crate::error::IdentityError::CertificateVerification(format!(
                "introduction card signature verification failed: {e:?}"
            ))
        })?;

        match (self.user_id, self.certificate.as_ref()) {
            (Some(user_id), Some(cert)) => {
                cert.verify()?;
                let cert_agent_id = cert.agent_id()?;
                if cert_agent_id != self.agent_id {
                    return Err(crate::error::IdentityError::CertificateVerification(
                        "introduction card certificate agent_id mismatch".to_string(),
                    ));
                }
                let cert_user_id = cert.user_id()?;
                if cert_user_id != user_id {
                    return Err(crate::error::IdentityError::CertificateVerification(
                        "introduction card certificate user_id mismatch".to_string(),
                    ));
                }
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err(crate::error::IdentityError::CertificateVerification(
                "introduction card: user disclosure without matching certificate".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn test_machine_id_from_public_key() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = MachineId::from_public_key(keypair.public_key());
        assert_eq!(machine_id.as_bytes().len(), PEER_ID_LENGTH);
    }
    #[test]
    fn test_machine_id_verification() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = MachineId::from_public_key(keypair.public_key());
        machine_id.verify(keypair.public_key()).unwrap();
    }
    #[test]
    fn user_keypair_from_seed_is_deterministic_and_functional() {
        // Issue #95: identical seeds must yield byte-identical keypairs
        // (the portability contract), and the derived keypair must be a
        // working ML-DSA-65 signer — not just stable bytes.
        let seed = [7u8; 32];
        let kp1 = UserKeypair::from_seed(&seed).unwrap();
        let kp2 = UserKeypair::from_seed(&seed).unwrap();
        assert_eq!(
            kp1.public_key().as_bytes(),
            kp2.public_key().as_bytes(),
            "same seed must derive the same public key"
        );
        assert_eq!(kp1.user_id(), kp2.user_id());

        let kp3 = UserKeypair::from_seed(&[8u8; 32]).unwrap();
        assert_ne!(kp1.user_id(), kp3.user_id());

        // UserId binds to the derived public key.
        kp1.user_id().verify(kp1.public_key()).unwrap();

        // Derived secret key signs; derived public key verifies.
        let msg = b"seeded keypair must be usable";
        let sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(kp1.secret_key(), msg)
            .unwrap();
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(kp1.public_key(), msg, &sig)
            .unwrap();
    }
    #[test]
    fn test_agent_id_from_public_key() {
        let keypair = AgentKeypair::generate().unwrap();
        let agent_id = AgentId::from_public_key(keypair.public_key());
        assert_eq!(agent_id.as_bytes().len(), PEER_ID_LENGTH);
    }
    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate().unwrap();
        assert!(identity.machine_id().as_bytes().len() == PEER_ID_LENGTH);
        assert!(identity.agent_id().as_bytes().len() == PEER_ID_LENGTH);
        // User layer defaults to None
        assert!(identity.user_id().is_none());
        assert!(identity.user_keypair().is_none());
        assert!(identity.agent_certificate().is_none());
    }
    #[test]
    fn test_user_id_from_public_key() {
        let keypair = UserKeypair::generate().unwrap();
        let user_id = UserId::from_public_key(keypair.public_key());
        assert_eq!(user_id.as_bytes().len(), PEER_ID_LENGTH);
    }
    #[test]
    fn test_user_id_verification() {
        let keypair = UserKeypair::generate().unwrap();
        let user_id = UserId::from_public_key(keypair.public_key());
        user_id.verify(keypair.public_key()).unwrap();
    }
    #[test]
    fn test_user_id_verification_fails_with_wrong_key() {
        let keypair1 = UserKeypair::generate().unwrap();
        let keypair2 = UserKeypair::generate().unwrap();
        let user_id = UserId::from_public_key(keypair1.public_key());
        assert!(user_id.verify(keypair2.public_key()).is_err());
    }
    #[test]
    fn test_user_keypair_generation() {
        let keypair = UserKeypair::generate().unwrap();
        let user_id = keypair.user_id();
        assert_ne!(user_id.as_bytes(), &[0u8; PEER_ID_LENGTH]);
    }
    #[test]
    fn test_user_keypair_serialization_roundtrip() {
        let keypair = UserKeypair::generate().unwrap();
        let (pub_bytes, sec_bytes) = keypair.to_bytes();
        let restored = UserKeypair::from_bytes(&pub_bytes, &sec_bytes).unwrap();
        assert_eq!(keypair.user_id(), restored.user_id());
    }
    #[test]
    fn test_user_id_display() {
        let keypair = UserKeypair::generate().unwrap();
        let user_id = keypair.user_id();
        let display = format!("{}", user_id);
        assert!(display.starts_with("UserId(0x"));
        // 8 bytes = 16 hex chars
        assert_eq!(display.len(), "UserId(0x)".len() + 16);
    }
    #[test]
    fn test_agent_certificate_issue_and_verify() {
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();

        let cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();

        // Verify succeeds
        cert.verify().unwrap();

        // IDs match
        assert_eq!(cert.user_id().unwrap(), user_kp.user_id());
        assert_eq!(cert.agent_id().unwrap(), agent_kp.agent_id());

        // Timestamp is recent
        assert!(cert.issued_at() > 0);
    }

    // ── Certificate expiry (issue #130) ──

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn cert_v1_without_not_after_still_verifies() {
        // The no-break guarantee: a certificate with no expiry must sign and
        // verify over the exact v1 message bytes, forever. If this regresses,
        // every existing certificate on the network stops verifying.
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();
        assert_eq!(cert.not_after(), None, "issue() must produce a v1 cert");
        cert.verify().expect("a no-expiry cert must verify");
        // The signed message must use the v1 prefix (byte-for-byte legacy).
        let msg = AgentCertificate::build_message(
            user_kp.public_key().as_bytes(),
            agent_kp.public_key().as_bytes(),
            cert.issued_at(),
            None,
        );
        assert_eq!(
            &msg[..AgentCertificate::CERT_PREFIX.len()],
            AgentCertificate::CERT_PREFIX,
            "a no-expiry cert must sign over the v1 domain prefix"
        );
        assert!(
            !cert.is_expired(now_unix()),
            "no-expiry cert is never expired"
        );
    }

    #[test]
    fn cert_with_not_after_signs_and_verifies() {
        // A v2 (expiring) cert must round-trip: sign over the v2 message and
        // verify, with the expiry preserved.
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let expiry = now_unix() + 3600;
        let cert = AgentCertificate::issue_with_expiry(&user_kp, &agent_kp, Some(expiry)).unwrap();
        assert_eq!(cert.not_after(), Some(expiry));
        cert.verify()
            .expect("a within-validity v2 cert must verify");
    }

    #[test]
    fn cert_not_after_tamper_fails_verification() {
        // not_after is signature-covered: stripping it (v2 -> None) or moving
        // it must break verification, so an attacker cannot extend validity or
        // downgrade an expiring cert into a non-expiring one.
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let expiry = now_unix() + 3600;
        let mut cert =
            AgentCertificate::issue_with_expiry(&user_kp, &agent_kp, Some(expiry)).unwrap();

        // Strip the expiry: signature was over the v2 message, so verifying
        // as v1 must fail.
        cert.not_after = None;
        assert!(
            cert.verify().is_err(),
            "stripping the expiry must fail verification, not read as never-expiring"
        );

        // Extend the expiry: a different not_after changes the signed bytes.
        cert.not_after = Some(expiry + 1_000_000);
        assert!(
            cert.verify().is_err(),
            "altering the expiry must fail verification"
        );
    }

    #[test]
    fn expiry_allows_within_skew() {
        // A cert whose not_after is 120s in the past is still honored because
        // it is within the 300s clock-skew tolerance — honestly-issued certs
        // must not be rejected over minor clock disagreement.
        let now = 1_000_000_000u64;
        let not_after = now - 120;
        assert!(
            !is_expired(Some(not_after), now),
            "an expiry 120s past must be tolerated (within {EXPIRY_CLOCK_SKEW_SECS}s skew)"
        );
    }

    #[test]
    fn expiry_rejects_beyond_skew() {
        // A cert 600s past its not_after is beyond tolerance and must be
        // treated as expired.
        let now = 1_000_000_000u64;
        let not_after = now - 600;
        assert!(
            is_expired(Some(not_after), now),
            "an expiry 600s past must be rejected (beyond {EXPIRY_CLOCK_SKEW_SECS}s skew)"
        );
        // And None is never expired regardless of now.
        assert!(!is_expired(None, now), "absence of expiry is never expired");
    }

    #[test]
    fn cert_v1_disk_bytes_load_unchanged() {
        // A pre-#130 agent.cert (bare v1 bincode, no expiry) must decode via
        // the new versioned loader with not_after=None, and a no-expiry cert
        // must serialize back to those exact legacy bytes (downgrade-safe).
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();
        let legacy = bincode::serialize(&AgentCertificateV1Disk {
            user_public_key: cert.user_public_key.clone(),
            agent_public_key: cert.agent_public_key.clone(),
            signature: cert.signature.clone(),
            issued_at: cert.issued_at,
        })
        .unwrap();
        assert_eq!(
            cert.to_storage_bytes().unwrap(),
            legacy,
            "a no-expiry cert must write the exact legacy disk bytes"
        );
        let loaded = AgentCertificate::from_storage_bytes(&legacy).unwrap();
        assert_eq!(loaded, cert, "legacy disk bytes must decode unchanged");
        loaded.verify().expect("legacy-loaded cert must verify");
    }

    #[test]
    fn cert_v2_disk_bytes_roundtrip() {
        // An expiring cert must round-trip through the v2 disk format.
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let expiry = now_unix() + 86_400;
        let cert = AgentCertificate::issue_with_expiry(&user_kp, &agent_kp, Some(expiry)).unwrap();
        let bytes = cert.to_storage_bytes().unwrap();
        let loaded = AgentCertificate::from_storage_bytes(&bytes).unwrap();
        assert_eq!(loaded, cert, "v2 disk bytes must round-trip exactly");
        assert_eq!(loaded.not_after(), Some(expiry));
        loaded.verify().expect("v2-loaded cert must verify");
    }

    #[test]
    fn test_agent_certificate_wrong_key_fails() {
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();

        let mut cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();

        // Tamper with the user public key (swap in a different user's key)
        let other_user = UserKeypair::generate().unwrap();
        cert.user_public_key = other_user.public_key().as_bytes().to_vec();

        // Verification should fail because signature doesn't match new key
        assert!(cert.verify().is_err());
    }
    #[test]
    fn test_agent_certificate_tampered_agent_key_fails() {
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();

        let mut cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();

        // Tamper with the agent public key
        let other_agent = AgentKeypair::generate().unwrap();
        cert.agent_public_key = other_agent.public_key().as_bytes().to_vec();

        // Verification should fail because message changed
        assert!(cert.verify().is_err());
    }
    #[test]
    fn test_identity_with_user() {
        let machine_kp = MachineKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let user_kp = UserKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();

        let expected_user_id = user_kp.user_id();
        let identity = Identity::new_with_user(machine_kp, agent_kp, user_kp, cert);

        assert_eq!(identity.user_id(), Some(expected_user_id));
        assert!(identity.user_keypair().is_some());
        assert!(identity.agent_certificate().is_some());
    }

    #[test]
    fn test_introduction_card_signature_round_trip() {
        let identity = Identity::generate().unwrap();
        let card = IntroductionCard::from_identity(&identity, None, Vec::new()).unwrap();
        card.verify().expect("newly-minted card must verify");
        assert_eq!(card.machine_id, identity.machine_id());
        assert_eq!(
            card.machine_public_key,
            identity.machine_keypair().public_key().as_bytes()
        );
        // Signature must not be a raw public key anymore (placeholder bug).
        assert_ne!(card.signature, card.machine_public_key);
    }

    #[test]
    fn test_introduction_card_with_user_verifies() {
        let machine_kp = MachineKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let user_kp = UserKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();
        let identity = Identity::new_with_user(machine_kp, agent_kp, user_kp, cert);

        let card = IntroductionCard::from_identity(
            &identity,
            Some("alice".to_string()),
            vec![ServiceEntry {
                name: "presence".to_string(),
                description: "online/offline".to_string(),
                min_trust: "unknown".to_string(),
            }],
        )
        .unwrap();
        card.verify().expect("user-backed card must verify");
    }

    #[test]
    fn test_introduction_card_tampered_display_name_fails() {
        let identity = Identity::generate().unwrap();
        let mut card = IntroductionCard::from_identity(&identity, None, Vec::new()).unwrap();
        card.display_name = Some("imposter".to_string());
        assert!(
            card.verify().is_err(),
            "mutation of signed field must invalidate signature"
        );
    }

    #[test]
    fn test_introduction_card_tampered_agent_id_fails() {
        let identity = Identity::generate().unwrap();
        let mut card = IntroductionCard::from_identity(&identity, None, Vec::new()).unwrap();
        let other_agent = AgentKeypair::generate().unwrap();
        card.agent_id = other_agent.agent_id();
        assert!(card.verify().is_err());
    }

    #[test]
    fn test_introduction_card_mismatched_machine_id_fails() {
        let identity = Identity::generate().unwrap();
        let mut card = IntroductionCard::from_identity(&identity, None, Vec::new()).unwrap();
        // Corrupt machine_id while leaving the public key intact — verify must
        // reject before even attempting the ML-DSA check.
        card.machine_id = MachineId([0xAAu8; PEER_ID_LENGTH]);
        assert!(card.verify().is_err());
    }

    #[test]
    fn test_introduction_card_foreign_signature_fails() {
        let identity_a = Identity::generate().unwrap();
        let identity_b = Identity::generate().unwrap();

        let mut card = IntroductionCard::from_identity(&identity_a, None, Vec::new()).unwrap();
        // Splice a valid signature from a different identity; machine_id +
        // machine_public_key still refer to identity_a, so verification must fail.
        let forged_donor = IntroductionCard::from_identity(&identity_b, None, Vec::new()).unwrap();
        card.signature = forged_donor.signature;
        assert!(card.verify().is_err());
    }

    // ── MachineId ──────────────────────────────────────────────────────

    #[test]
    fn machine_id_as_bytes_returns_inner() {
        let id = MachineId([0xAA; 32]);
        assert_eq!(id.as_bytes(), &[0xAA; 32]);
    }

    #[test]
    fn machine_id_to_vec_returns_copy() {
        let id = MachineId([0xBB; 32]);
        let vec = id.to_vec();
        assert_eq!(vec.len(), 32);
        assert_eq!(vec, vec![0xBBu8; 32]);
    }

    #[test]
    fn machine_id_debug_contains_bytes() {
        let id = MachineId([0xCC; 32]);
        let debug = format!("{:?}", id);
        // Debug is derived, so it shows the array
        assert!(
            debug.contains("204"),
            "should contain decimal 204 (0xCC): {debug}"
        );
    }

    #[test]
    fn machine_id_verify_mismatch_returns_error() {
        let id = MachineId([0xDD; 32]);
        let kp = MachineKeypair::generate().unwrap();
        let result = id.verify(kp.public_key());
        assert!(result.is_err());
    }

    // ── AgentId ────────────────────────────────────────────────────────

    #[test]
    fn agent_id_to_vec_returns_copy() {
        let id = AgentId([0xEE; 32]);
        let vec = id.to_vec();
        assert_eq!(vec.len(), 32);
        assert_eq!(vec, vec![0xEEu8; 32]);
    }

    #[test]
    fn agent_id_verify_mismatch_returns_error() {
        let id = AgentId([0xFF; 32]);
        let kp = AgentKeypair::generate().unwrap();
        let result = id.verify(kp.public_key());
        assert!(result.is_err());
    }

    // ── UserId ─────────────────────────────────────────────────────────

    #[test]
    fn user_id_to_vec_returns_copy() {
        let id = UserId([0x11; 32]);
        let vec = id.to_vec();
        assert_eq!(vec.len(), 32);
        assert_eq!(vec, vec![0x11u8; 32]);
    }

    // ── Keypair Debug ──────────────────────────────────────────────────

    #[test]
    fn machine_keypair_debug_redacts_secret() {
        let kp = MachineKeypair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(
            debug.contains("<REDACTED>"),
            "debug should redact secret key"
        );
        assert!(debug.contains("public_key"), "debug should show public_key");
    }

    #[test]
    fn agent_keypair_debug_redacts_secret() {
        let kp = AgentKeypair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(
            debug.contains("<REDACTED>"),
            "debug should redact secret key"
        );
    }

    // ── Display ────────────────────────────────────────────────────────

    #[test]
    fn machine_id_display_hex_format() {
        let id = MachineId([0x22; 32]);
        let display = format!("{}", id);
        assert!(display.contains("2222"));
    }

    #[test]
    fn agent_id_display_hex_format() {
        let id = AgentId([0x33; 32]);
        let display = format!("{}", id);
        assert!(display.contains("3333"));
    }

    // ========================================================================
    // #124 / WS1.3 tranche 3 — AgentCertificate verification failure paths.
    //
    // The wrong-user-key and tampered-agent-key cases are covered above
    // (asserting `is_err()`). The gap is a corrupted SIGNATURE: an attacker
    // (or bit-rot) that changes the signature bytes while leaving the keys
    // intact must fail verification and surface the failure as the STRUCTURED
    // `IdentityError::CertificateVerification` variant — never a panic and
    // never a silent accept. Two sub-cases: a same-length corrupted signature
    // (reaches the ML-DSA verify step, fails there) and a wrong-length
    // signature (rejected at the signature-format parse).
    // ========================================================================

    #[test]
    fn agent_certificate_corrupted_signature_fails_with_structured_error() {
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let mut cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();

        // The freshly-issued cert must verify (positive control).
        cert.verify().expect("freshly-issued cert must verify");

        // Corrupt one byte of the signature, preserving its length so the
        // signature still parses as a valid ML-DSA signature blob and the
        // failure happens at the cryptographic verify step, not format parse.
        let original_sig = cert.signature.clone();
        cert.signature[0] ^= 0xFF;
        assert_ne!(
            cert.signature, original_sig,
            "signature must actually change"
        );

        let err = cert
            .verify()
            .expect_err("corrupted signature must fail verify");
        assert!(
            matches!(err, crate::error::IdentityError::CertificateVerification(_)),
            "corrupted signature must surface as CertificateVerification, got {err:?}"
        );
    }

    #[test]
    fn agent_certificate_wrong_length_signature_fails_with_structured_error() {
        let user_kp = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let mut cert = AgentCertificate::issue(&user_kp, &agent_kp).unwrap();

        // A truncated / wrong-length signature blob is rejected at the
        // signature-format parse (before any crypto) — still a structured
        // CertificateVerification error, never a panic.
        cert.signature = vec![0u8; 10];

        let err = cert
            .verify()
            .expect_err("wrong-length signature must fail verify");
        assert!(
            matches!(err, crate::error::IdentityError::CertificateVerification(_)),
            "wrong-length signature must surface as CertificateVerification, got {err:?}"
        );
    }
}
