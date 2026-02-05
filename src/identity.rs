//! Core identity types for x0x agents.
//!
//! This module defines the cryptographic identity types used throughout x0x:
//! - [`MachineId`]: Machine-pinned identity derived from ML-DSA-65 keypair
//! - [`AgentId`]: Portable agent identity derived from ML-DSA-65 keypair
//!
//! Both IDs are 32-byte SHA-256 hashes derived from ML-DSA-65 public keys via
//! the ant-quic library's PeerId derivation function.

use ant_quic::crypto::raw_public_keys::pqc::{derive_peer_id_from_public_key, MlDsaPublicKey};
use serde::{Deserialize, Serialize};

/// Machine-pinned identity derived from an ML-DSA-65 keypair.
///
/// A `MachineId` is a 32-byte SHA-256 hash derived from a machine's ML-DSA-65
/// public key. It serves as a persistent identity tied to a specific machine
/// and is used for QUIC transport authentication via ant-quic.
///
/// # Derivation
///
/// The ID is computed as:
/// ```text
/// MachineId = SHA-256("AUTONOMI_PEER_ID_V2:" || ML-DSA-65 public key)
/// ```
///
/// # Examples
///
/// ```
/// use x0x::identity::MachineId;
/// use x0x::error::Result;
///
/// # #[cfg(feature = "test-utils")]
/// # fn example() -> Result<()> {
/// # // This example requires key generation utilities
/// # Ok(())
/// # }
/// # example().unwrap()
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub [u8; 32]);

impl MachineId {
    /// Derives a MachineId from an ML-DSA-65 public key.
    ///
    /// This function uses ant-quic's PeerId derivation to compute a stable
    /// 32-byte identifier from the public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - Reference to the ML-DSA-65 public key
    ///
    /// # Returns
    ///
    /// A MachineId wrapping the 32-byte hash
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use x0x::identity::MachineId;
    /// use x0x::identity::MachineKeypair;
    /// use x0x::error::Result;
    ///
    /// fn example() -> Result<()> {
    ///     let keypair = MachineKeypair::generate()?;
    ///     let machine_id = MachineId::from_public_key(keypair.public_key());
    ///     Ok(())
    /// }
    /// ```
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }

    /// Returns the underlying 32-byte identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x::identity::MachineId;
    ///
    /// let id = MachineId([0u8; 32]);
    /// let bytes: &[u8; 32] = id.as_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Portable agent identity derived from an ML-DSA-65 keypair.
///
/// An `AgentId` is a 32-byte SHA-256 hash derived from an agent's ML-DSA-65
/// public key. Unlike MachineId, AgentId is portable across machines and
/// represents the agent's persistent identity in the x0x network.
///
/// # Derivation
///
/// The ID is computed as:
/// ```text
/// AgentId = SHA-256("AUTONOMI_PEER_ID_V2:" || ML-DSA-65 public key)
/// ```
///
/// # Portability
///
/// Agent identities are designed to be imported and exported across machines:
/// - Agent keypairs can be serialized and transferred
/// - The same AgentId persists regardless of which machine the agent runs on
/// - This enables agent migration and backup/restore workflows
///
/// # Examples
///
/// ```
/// use x0x::identity::AgentId;
/// use x0x::error::Result;
///
/// # #[cfg(feature = "test-utils")]
/// # fn example() -> Result<()> {
/// # // This example requires key generation utilities
/// # Ok(())
/// # }
/// # example().unwrap()
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub [u8; 32]);

impl AgentId {
    /// Derives an AgentId from an ML-DSA-65 public key.
    ///
    /// This function uses ant-quic's PeerId derivation to compute a stable
    /// 32-byte identifier from the public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - Reference to the ML-DSA-65 public key
    ///
    /// # Returns
    ///
    /// An AgentId wrapping the 32-byte hash
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use x0x::identity::AgentId;
    /// use x0x::identity::AgentKeypair;
    /// use x0x::error::Result;
    ///
    /// fn example() -> Result<()> {
    ///     let keypair = AgentKeypair::generate()?;
    ///     let agent_id = AgentId::from_public_key(keypair.public_key());
    ///     Ok(())
    /// }
    /// ```
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }

    /// Returns the underlying 32-byte identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x::identity::AgentId;
    ///
    /// let id = AgentId([0u8; 32]);
    /// let bytes: &[u8; 32] = id.as_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    use super::*;

    /// Helper function to create a test public key
    ///
    /// In production tests, we'd use ant-quic's test utilities to generate
    /// real ML-DSA-65 keypairs. For now, we use a mock key for structural testing.
    fn mock_public_key() -> MlDsaPublicKey {
        // ML-DSA-65 public keys are 1952 bytes
        MlDsaPublicKey::from_bytes(&[42u8; 1952]).expect("mock key should be valid size")
    }

    #[test]
    fn test_machine_id_from_public_key() {
        let pubkey = mock_public_key();
        let machine_id = MachineId::from_public_key(&pubkey);

        // Verify it's a 32-byte array
        assert_eq!(machine_id.as_bytes().len(), 32);
    }

    #[test]
    fn test_machine_id_as_bytes() {
        let id = MachineId([1u8; 32]);
        let bytes = id.as_bytes();

        assert_eq!(bytes, &[1u8; 32]);
    }

    #[test]
    fn test_machine_id_derivation_deterministic() {
        let pubkey = mock_public_key();
        let id1 = MachineId::from_public_key(&pubkey);
        let id2 = MachineId::from_public_key(&pubkey);

        // Same public key should always derive the same MachineId
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_agent_id_from_public_key() {
        let pubkey = mock_public_key();
        let agent_id = AgentId::from_public_key(&pubkey);

        // Verify it's a 32-byte array
        assert_eq!(agent_id.as_bytes().len(), 32);
    }

    #[test]
    fn test_agent_id_as_bytes() {
        let id = AgentId([2u8; 32]);
        let bytes = id.as_bytes();

        assert_eq!(bytes, &[2u8; 32]);
    }

    #[test]
    fn test_agent_id_derivation_deterministic() {
        let pubkey = mock_public_key();
        let id1 = AgentId::from_public_key(&pubkey);
        let id2 = AgentId::from_public_key(&pubkey);

        // Same public key should always derive the same AgentId
        assert_eq!(id1, id2);
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
