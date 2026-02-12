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

/// Certificate binding an agent to a user identity.
///
/// An `AgentCertificate` is a cryptographic attestation that a specific agent
/// belongs to a specific user. It is created by signing the agent's public key
/// with the user's secret key.
///
/// The signed message format is:
/// `b"x0x-agent-cert-v1" || user_pubkey || agent_pubkey || timestamp`
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
}

impl AgentCertificate {
    /// Certificate message prefix for domain separation.
    const CERT_PREFIX: &'static [u8] = b"x0x-agent-cert-v1";

    /// Issue a new certificate binding an agent to a user.
    ///
    /// Signs `b"x0x-agent-cert-v1" || user_pubkey || agent_pubkey || timestamp`
    /// with the user's secret key.
    pub fn issue(
        user_kp: &UserKeypair,
        agent_kp: &AgentKeypair,
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

        let message = Self::build_message(&user_pub_bytes, &agent_pub_bytes, issued_at);

        let signature =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(user_kp.secret_key(), &message)
                .map_err(|e| {
                    crate::error::IdentityError::CertificateVerification(format!(
                        "signing failed: {:?}",
                        e
                    ))
                })?;

        Ok(Self {
            user_public_key: user_pub_bytes,
            agent_public_key: agent_pub_bytes,
            signature: signature.as_bytes().to_vec(),
            issued_at,
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

        let signature = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            &self.signature,
        )
        .map_err(|e| {
            crate::error::IdentityError::CertificateVerification(format!(
                "invalid signature format: {:?}",
                e
            ))
        })?;

        let message =
            Self::build_message(&self.user_public_key, &self.agent_public_key, self.issued_at);

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

    /// Get the issuance timestamp.
    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Build the message that gets signed/verified.
    fn build_message(user_pubkey: &[u8], agent_pubkey: &[u8], timestamp: u64) -> Vec<u8> {
        let mut message = Vec::with_capacity(
            Self::CERT_PREFIX.len() + user_pubkey.len() + agent_pubkey.len() + 8,
        );
        message.extend_from_slice(Self::CERT_PREFIX);
        message.extend_from_slice(user_pubkey);
        message.extend_from_slice(agent_pubkey);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message
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
}
