#![allow(missing_docs)]
//! Core identity types for x0x agents.
//!
//! This module provides the cryptographic identity foundation for x0x:
//! - MachineId: Machine-pinned identity for QUIC authentication
//! - AgentId: Portable agent identity for cross-machine persistence

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

/// Unified identity combining machine and agent keypairs.
pub struct Identity {
    machine_keypair: MachineKeypair,
    agent_keypair: AgentKeypair,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("machine_keypair", &self.machine_keypair)
            .field("agent_keypair", &self.agent_keypair)
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
        }
    }
    /// Generate a new Identity with fresh keypairs.
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        Ok(Self {
            machine_keypair: MachineKeypair::generate()?,
            agent_keypair: AgentKeypair::generate()?,
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
    }
}
