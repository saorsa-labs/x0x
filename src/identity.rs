// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://www.saorsalabs.com/licenses

//! Core identity types for x0x agents.
//!
//! This module provides [`crate::identity::MachineId`] and [`crate::identity::AgentId`] types that wrap
//! ML-DSA-65 derived PeerIds for machine-pinned and portable agent identities.
//!
//! ## Architecture
//!
//! x0x uses a dual-identity system:
//!
//! - **Machine Identity**: Tied to the local machine via `~/.x0x/machine.key`
//!   Used for QUIC transport authentication via ant-quic.
//!
//! - **Agent Identity**: Portable across machines, can be exported/imported.
//!   Used for cross-machine agent persistence and reputation.
//!
//! Both identities derive their PeerIds from ML-DSA-65 public keys via
//! SHA-256 hashing, providing post-quantum security.

use ant_quic::{derive_peer_id_from_public_key, MlDsaPublicKey, MlDsaSecretKey};
use serde::{Deserialize, Serialize};
// Used for Display impl to show hex fingerprints
use hex;

/// Length of a PeerId in bytes (SHA-256 hash output).
pub const PEER_ID_LENGTH: usize = 32;

/// Machine-pinned identity derived from ML-DSA-65 keypair.
///
/// A MachineId is a 32-byte identifier derived from the machine's ML-DSA-65
/// public key via SHA-256 hashing. It is tied to the local machine and
/// used for QUIC transport authentication.
///
/// The MachineId is stored persistently in `~/.x0x/machine.key` and
/// should not be shared across machines.
///
/// # Example
///
/// ```ignore
/// use x0x::identity::MachineKeypair;
///
/// let keypair = MachineKeypair::generate()?;
/// let machine_id = keypair.machine_id();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub [u8; PEER_ID_LENGTH]);

/// Portable agent identity derived from ML-DSA-65 keypair.
///
/// An AgentId is a 32-byte identifier derived from the agent's ML-DSA-65
/// public key via SHA-256 hashing. Unlike MachineId, the AgentId is portable
/// and can be exported/imported across machines.
///
/// This enables agents to maintain a consistent identity regardless of
/// which machine they run on.
///
/// # Example
///
/// ```ignore
/// use x0x::identity::AgentKeypair;
///
/// let keypair = AgentKeypair::generate()?;
/// let agent_id = keypair.agent_id();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub [u8; PEER_ID_LENGTH]);

impl MachineId {
    /// Derive a MachineId from an ML-DSA-65 public key.
    ///
    /// This uses ant-quic's `derive_peer_id_from_public_key` which computes
    /// SHA-256(domain || pubkey) to produce a 32-byte PeerId.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The ML-DSA-65 public key to derive from.
    ///
    /// # Returns
    ///
    /// A new MachineId derived from the public key.
    #[inline]
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }

    /// Get the raw 32-byte representation of this MachineId.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte array.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LENGTH] {
        &self.0
    }

    /// Convert this MachineId to a byte vector.
    ///
    /// # Returns
    ///
    /// A new vector containing the 32 bytes.
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Verify that this MachineId was derived from the given public key.
    ///
    /// This is used to detect key substitution attacks. If the public key
    /// doesn't match this MachineId, it indicates either corruption or
    /// an attack.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The public key to verify against.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the verification succeeds, `Err(IdentityError::PeerIdMismatch)` otherwise.
    ///
    /// # Security
    ///
    /// This check prevents an attacker from substituting a different public key
    /// while claiming to have the same MachineId.
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
    ///
    /// This uses ant-quic's `derive_peer_id_from_public_key` which computes
    /// SHA-256(domain || pubkey) to produce a 32-byte PeerId.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The ML-DSA-65 public key to derive from.
    ///
    /// # Returns
    ///
    /// A new AgentId derived from the public key.
    #[inline]
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }

    /// Get the raw 32-byte representation of this AgentId.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte array.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LENGTH] {
        &self.0
    }

    /// Convert this AgentId to a byte vector.
    ///
    /// # Returns
    ///
    /// A new vector containing the 32 bytes.
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Verify that this AgentId was derived from the given public key.
    ///
    /// This is used to detect key substitution attacks. If the public key
    /// doesn't match this AgentId, it indicates either corruption or
    /// an attack.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The public key to verify against.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the verification succeeds, `Err(IdentityError::PeerIdMismatch)` otherwise.
    ///
    /// # Security
    ///
    /// This check prevents an attacker from substituting a different public key
    /// while claiming to have the same AgentId.
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<(), crate::error::IdentityError> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived {
            Ok(())
        } else {
            Err(crate::error::IdentityError::PeerIdMismatch)
        }
    }
}

/// Display implementation for MachineId showing hex fingerprint.
///
/// Shows the first 8 bytes as hex for human identification.
impl std::fmt::Display for MachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MachineId(0x{})", hex::encode(&self.0[..8]))
    }
}

/// Display implementation for AgentId showing hex fingerprint.
///
/// Shows the first 8 bytes as hex for human identification.
impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgentId(0x{})", hex::encode(&self.0[..8]))
    }
}

/// Machine-pinned ML-DSA-65 keypair.
///
/// This keypair is tied to the local machine and stored in `~/.x0x/machine.key`.
/// It is used for QUIC transport authentication via ant-quic.
///
/// The secret key is never exposed directly - accessors return references
/// to prevent cloning.
pub struct MachineKeypair {
    /// The public key component.
    public_key: MlDsaPublicKey,
    /// The secret key component (never exposed directly).
    secret_key: MlDsaSecretKey,
}

/// Custom Debug implementation that redacts secret key material.
///
/// This prevents secret keys from being leaked in logs or debug output.
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
    ///
    /// Uses ant-quic's cryptographically secure ML-DSA-65 keypair generation.
    ///
    /// # Returns
    ///
    /// A new keypair on success, or an error if key generation fails.
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        let (public_key, secret_key) = ant_quic::generate_ml_dsa_keypair()
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get a reference to the public key.
    ///
    /// # Returns
    ///
    /// A reference to the ML-DSA-65 public key.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Get the MachineId derived from this keypair's public key.
    ///
    /// # Returns
    ///
    /// The MachineId for this keypair.
    #[inline]
    #[must_use]
    pub fn machine_id(&self) -> MachineId {
        MachineId::from_public_key(&self.public_key)
    }

    /// Get a reference to the secret key.
    ///
    /// Returns a reference to prevent cloning of the secret key.
    ///
    /// # Returns
    ///
    /// A reference to the ML-DSA-65 secret key.
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &MlDsaSecretKey {
        &self.secret_key
    }

    /// Reconstruct a MachineKeypair from raw key bytes.
    ///
    /// Used for deserialization from storage.
    ///
    /// # Arguments
    ///
    /// * `public_key_bytes` - The raw public key bytes.
    /// * `secret_key_bytes` - The raw secret key bytes.
    ///
    /// # Returns
    ///
    /// A new MachineKeypair on success, or an error if the bytes are invalid.
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

    /// Serialize this keypair to bytes.
    ///
    /// Used for persistent storage.
    ///
    /// # Returns
    ///
    /// A tuple of (public_key_bytes, secret_key_bytes).
    #[must_use]
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.public_key.as_bytes().to_vec(),
            self.secret_key.as_bytes().to_vec(),
        )
    }
}

/// Portable agent ML-DSA-65 keypair.
///
/// This keypair represents the agent's portable identity. Unlike MachineKeypair,
/// it can be exported and imported across machines, enabling agents to maintain
/// a consistent identity regardless of where they run.
///
/// The secret key is never exposed directly - accessors return references
/// to prevent cloning.
pub struct AgentKeypair {
    /// The public key component.
    public_key: MlDsaPublicKey,
    /// The secret key component (never exposed directly).
    secret_key: MlDsaSecretKey,
}

/// Custom Debug implementation that redacts secret key material.
///
/// This prevents secret keys from being leaked in logs or debug output.
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
    ///
    /// Uses ant-quic's cryptographically secure ML-DSA-65 keypair generation.
    ///
    /// # Returns
    ///
    /// A new keypair on success, or an error if key generation fails.
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        let (public_key, secret_key) = ant_quic::generate_ml_dsa_keypair()
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get a reference to the public key.
    ///
    /// # Returns
    ///
    /// A reference to the ML-DSA-65 public key.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Get the AgentId derived from this keypair's public key.
    ///
    /// # Returns
    ///
    /// The AgentId for this keypair.
    #[inline]
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        AgentId::from_public_key(&self.public_key)
    }

    /// Get a reference to the secret key.
    ///
    /// Returns a reference to prevent cloning of the secret key.
    ///
    /// # Returns
    ///
    /// A reference to the ML-DSA-65 secret key.
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &MlDsaSecretKey {
        &self.secret_key
    }

    /// Reconstruct an AgentKeypair from raw key bytes.
    ///
    /// Used for deserialization from storage or import.
    ///
    /// # Arguments
    ///
    /// * `public_key_bytes` - The raw public key bytes.
    /// * `secret_key_bytes` - The raw secret key bytes.
    ///
    /// # Returns
    ///
    /// A new AgentKeypair on success, or an error if the bytes are invalid.
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

    /// Serialize this keypair to bytes.
    ///
    /// Used for persistent storage or export.
    ///
    /// # Returns
    ///
    /// A tuple of (public_key_bytes, secret_key_bytes).
    #[must_use]
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.public_key.as_bytes().to_vec(),
            self.secret_key.as_bytes().to_vec(),
        )
    }
}

/// Complete x0x agent identity.
///
/// An Identity combines both the machine-pinned identity (MachineKeypair)
/// and the portable agent identity (AgentKeypair).
///
/// The machine keypair is stored locally and used for transport authentication.
/// The agent keypair is portable and represents the agent's persistent identity.
pub struct Identity {
    /// The machine-pinned keypair for QUIC transport.
    machine_keypair: MachineKeypair,
    /// The portable agent keypair for cross-machine identity.
    agent_keypair: AgentKeypair,
}

/// Custom Debug implementation that redacts secret key material.
///
/// This prevents secret keys from being leaked in logs or debug output.
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("machine_keypair", &self.machine_keypair)
            .field("agent_keypair", &self.agent_keypair)
            .finish()
    }
}

impl Identity {
    /// Create a new identity from existing keypairs.
    ///
    /// # Arguments
    ///
    /// * `machine_keypair` - The machine-pinned keypair.
    /// * `agent_keypair` - The portable agent keypair.
    ///
    /// # Returns
    ///
    /// A new Identity combining both keypairs.
    #[inline]
    pub fn new(machine_keypair: MachineKeypair, agent_keypair: AgentKeypair) -> Self {
        Self {
            machine_keypair,
            agent_keypair,
        }
    }

    /// Create a new identity with freshly generated keys.
    ///
    /// Generates both a new MachineKeypair (stored locally) and AgentKeypair.
    ///
    /// # Returns
    ///
    /// A new Identity on success.
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        Ok(Self {
            machine_keypair: MachineKeypair::generate()?,
            agent_keypair: AgentKeypair::generate()?,
        })
    }

    /// Get the machine identity.
    ///
    /// # Returns
    ///
    /// A reference to the MachineId.
    #[inline]
    #[must_use]
    pub fn machine_id(&self) -> MachineId {
        self.machine_keypair.machine_id()
    }

    /// Get the agent identity.
    ///
    /// # Returns
    ///
    /// A reference to the AgentId.
    #[inline]
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        self.agent_keypair.agent_id()
    }

    /// Get a reference to the machine keypair.
    ///
    /// # Returns
    ///
    /// A reference to the MachineKeypair.
    #[inline]
    #[must_use]
    pub fn machine_keypair(&self) -> &MachineKeypair {
        &self.machine_keypair
    }

    /// Get a reference to the agent keypair.
    ///
    /// # Returns
    ///
    /// A reference to the AgentKeypair.
    #[inline]
    #[must_use]
    pub fn agent_keypair(&self) -> &AgentKeypair {
        &self.agent_keypair
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_machine_id_from_public_key() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = MachineId::from_public_key(keypair.public_key());

        // Verify it's a 32-byte array
        assert_eq!(machine_id.as_bytes().len(), PEER_ID_LENGTH);
    }

    #[test]
    fn test_machine_id_verification() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = MachineId::from_public_key(keypair.public_key());

        // Verify round-trip
        machine_id.verify(keypair.public_key()).unwrap();
    }

    #[test]
    fn test_machine_id_verification_failure() {
        let keypair1 = MachineKeypair::generate().unwrap();
        let keypair2 = MachineKeypair::generate().unwrap();

        let machine_id = MachineId::from_public_key(keypair1.public_key());

        // Different key should fail verification
        assert!(machine_id.verify(keypair2.public_key()).is_err());
    }

    #[test]
    fn test_agent_id_from_public_key() {
        let keypair = AgentKeypair::generate().unwrap();
        let agent_id = AgentId::from_public_key(keypair.public_key());

        // Verify it's a 32-byte array
        assert_eq!(agent_id.as_bytes().len(), PEER_ID_LENGTH);
    }

    #[test]
    fn test_agent_id_verification() {
        let keypair = AgentKeypair::generate().unwrap();
        let agent_id = AgentId::from_public_key(keypair.public_key());

        // Verify round-trip
        agent_id.verify(keypair.public_key()).unwrap();
    }

    #[test]
    fn test_agent_id_verification_failure() {
        let keypair1 = AgentKeypair::generate().unwrap();
        let keypair2 = AgentKeypair::generate().unwrap();

        let agent_id = AgentId::from_public_key(keypair1.public_key());

        // Different key should fail verification
        assert!(agent_id.verify(keypair2.public_key()).is_err());
    }

    #[test]
    fn test_keypair_generation() {
        let machine_kp = MachineKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();

        assert!(!machine_kp.public_key().as_bytes().is_empty());
        assert!(!agent_kp.public_key().as_bytes().is_empty());
    }

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate().unwrap();

        assert!(identity.machine_id().as_bytes().len() == PEER_ID_LENGTH);
        assert!(identity.agent_id().as_bytes().len() == PEER_ID_LENGTH);
    }

    #[test]
    fn test_different_keys_different_ids() {
        let identity1 = Identity::generate().unwrap();
        let identity2 = Identity::generate().unwrap();

        // Machine IDs should be different (different keypairs)
        assert_ne!(identity1.machine_id(), identity2.machine_id());
        // Agent IDs should be different
        assert_ne!(identity1.agent_id(), identity2.agent_id());
    }

    #[test]
    fn test_keypair_serialization_roundtrip() {
        let original = MachineKeypair::generate().unwrap();
        let (pub_bytes, sec_bytes) = original.to_bytes();

        let recovered = MachineKeypair::from_bytes(&pub_bytes, &sec_bytes).unwrap();

        assert_eq!(original.machine_id(), recovered.machine_id());
    }

    #[test]
    fn test_agent_keypair_serialization_roundtrip() {
        let original = AgentKeypair::generate().unwrap();
        let (pub_bytes, sec_bytes) = original.to_bytes();

        let recovered = AgentKeypair::from_bytes(&pub_bytes, &sec_bytes).unwrap();

        assert_eq!(original.agent_id(), recovered.agent_id());
    }

    #[test]
    fn test_machine_id_as_bytes() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = keypair.machine_id();

        let bytes = machine_id.as_bytes();
        assert_eq!(bytes.len(), 32);

        let vec = machine_id.to_vec();
        assert_eq!(vec.len(), 32);
        assert_eq!(&vec[..], &bytes[..]);
    }

    #[test]
    fn test_display_impl() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = keypair.machine_id();

        let display = format!("{}", machine_id);
        assert!(display.starts_with("MachineId(0x"));
        assert!(display.len() > "MachineId(0x".len());

        let keypair = AgentKeypair::generate().unwrap();
        let agent_id = keypair.agent_id();

        let display = format!("{}", agent_id);
        assert!(display.starts_with("AgentId(0x"));
        assert!(display.len() > "AgentId(0x".len());
    }

    #[test]
    fn test_machine_id_serialization() {
        let id = MachineId([3u8; 32]);

        // Verify Serialize/Deserialize are derived correctly
        let serialized = bincode::serialize(&id).expect("serialization failed");
        let deserialized: MachineId =
            bincode::deserialize(&serialized).expect("deserialization failed");

        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_agent_id_serialization() {
        let id = AgentId([4u8; 32]);

        // Verify Serialize/Deserialize are derived correctly
        let serialized = bincode::serialize(&id).expect("serialization failed");
        let deserialized: AgentId =
            bincode::deserialize(&serialized).expect("deserialization failed");

        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_machine_id_hash() {
        let id1 = MachineId([5u8; 32]);
        let id2 = MachineId([5u8; 32]);
        let id3 = MachineId([6u8; 32]);

        // Test Hash trait implementation
        use std::hash::{DefaultHasher, Hash, Hasher};

        let mut hasher1 = DefaultHasher::new();
        id1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        id2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        let mut hasher3 = DefaultHasher::new();
        id3.hash(&mut hasher3);
        let hash3 = hasher3.finish();

        // Equal values should have equal hashes
        assert_eq!(hash1, hash2);
        // Different values should (with high probability) have different hashes
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_agent_id_hash() {
        let id1 = AgentId([7u8; 32]);
        let id2 = AgentId([7u8; 32]);
        let id3 = AgentId([8u8; 32]);

        // Test Hash trait implementation
        use std::hash::{DefaultHasher, Hash, Hasher};

        let mut hasher1 = DefaultHasher::new();
        id1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        id2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        let mut hasher3 = DefaultHasher::new();
        id3.hash(&mut hasher3);
        let hash3 = hasher3.finish();

        // Equal values should have equal hashes
        assert_eq!(hash1, hash2);
        // Different values should (with high probability) have different hashes
        assert_ne!(hash1, hash3);
    }
}
