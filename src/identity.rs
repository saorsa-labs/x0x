// Copyright 2024 Saorsa Labs Ltd.
//! Core identity types for x0x agents.
//!
//! This module provides cryptographic identity primitives for agents in the x0x network:
//!
//! - **MachineId**: Identifies physical hardware (one per machine)
//! - **AgentId**: Identifies individual AI agents (one per agent instance)
//! - **Keypairs**: ML-DSA-65 post-quantum cryptographic keypairs
//! - **Identity**: Combined machine + agent identity for network participation
//!
//! All identifiers are cryptographically derived from ML-DSA-65 public keys,
//! ensuring tamper-proof and verifiable identities without central authorities.

use ant_quic::{derive_peer_id_from_public_key, MlDsaPublicKey, MlDsaSecretKey, PeerId as AntQuicPeerId};
use serde::{Deserialize, Serialize};
use hex;

pub const PEER_ID_LENGTH: usize = 32;
pub type PeerId = AntQuicPeerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub [u8; PEER_ID_LENGTH]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub [u8; PEER_ID_LENGTH]);

impl MachineId {
    #[inline]
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LENGTH] { &self.0 }
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> { self.0.to_vec() }
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<(), crate::error::IdentityError> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived { Ok(()) } else { Err(crate::error::IdentityError::PeerIdMismatch) }
    }
}

impl AgentId {
    #[inline]
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LENGTH] { &self.0 }
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> { self.0.to_vec() }
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<(), crate::error::IdentityError> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived { Ok(()) } else { Err(crate::error::IdentityError::PeerIdMismatch) }
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

pub struct MachineKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl std::fmt::Debug for MachineKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineKeypair").field("public_key", &self.public_key).field("secret_key", &"<REDACTED>").finish()
    }
}

impl MachineKeypair {
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        let (public_key, secret_key) = ant_quic::generate_ml_dsa_keypair()
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self { public_key, secret_key })
    }
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey { &self.public_key }
    #[inline]
    #[must_use]
    pub fn machine_id(&self) -> MachineId { MachineId::from_public_key(&self.public_key) }
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &MlDsaSecretKey { &self.secret_key }
    pub fn from_bytes(public_key_bytes: &[u8], secret_key_bytes: &[u8]) -> Result<Self, crate::error::IdentityError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes).map_err(|_| crate::error::IdentityError::InvalidPublicKey("failed to parse public key".to_string()))?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes).map_err(|_| crate::error::IdentityError::InvalidSecretKey("failed to parse secret key".to_string()))?;
        Ok(Self { public_key, secret_key })
    }
    #[must_use]
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) { (self.public_key.as_bytes().to_vec(), self.secret_key.as_bytes().to_vec()) }
}

pub struct AgentKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl std::fmt::Debug for AgentKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKeypair").field("public_key", &self.public_key).field("secret_key", &"<REDACTED>").finish()
    }
}

impl AgentKeypair {
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        let (public_key, secret_key) = ant_quic::generate_ml_dsa_keypair()
            .map_err(|e| crate::error::IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self { public_key, secret_key })
    }
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey { &self.public_key }
    #[inline]
    #[must_use]
    pub fn agent_id(&self) -> AgentId { AgentId::from_public_key(&self.public_key) }
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &MlDsaSecretKey { &self.secret_key }
    pub fn from_bytes(public_key_bytes: &[u8], secret_key_bytes: &[u8]) -> Result<Self, crate::error::IdentityError> {
        let public_key = MlDsaPublicKey::from_bytes(public_key_bytes).map_err(|_| crate::error::IdentityError::InvalidPublicKey("failed to parse public key".to_string()))?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes).map_err(|_| crate::error::IdentityError::InvalidSecretKey("failed to parse secret key".to_string()))?;
        Ok(Self { public_key, secret_key })
    }
    #[must_use]
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) { (self.public_key.as_bytes().to_vec(), self.secret_key.as_bytes().to_vec()) }
}

pub struct Identity {
    machine_keypair: MachineKeypair,
    agent_keypair: AgentKeypair,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("machine_keypair", &self.machine_keypair).field("agent_keypair", &self.agent_keypair).finish()
    }
}

impl Identity {
    #[inline]
    pub fn new(machine_keypair: MachineKeypair, agent_keypair: AgentKeypair) -> Self { Self { machine_keypair, agent_keypair } }
    pub fn generate() -> Result<Self, crate::error::IdentityError> {
        Ok(Self { machine_keypair: MachineKeypair::generate()?, agent_keypair: AgentKeypair::generate()? })
    }
    #[inline]
    #[must_use]
    pub fn machine_id(&self) -> MachineId { self.machine_keypair.machine_id() }
    #[inline]
    #[must_use]
    pub fn agent_id(&self) -> AgentId { self.agent_keypair.agent_id() }
    #[inline]
    #[must_use]
    pub fn machine_keypair(&self) -> &MachineKeypair { &self.machine_keypair }
    #[inline]
    #[must_use]
    pub fn agent_keypair(&self) -> &AgentKeypair { &self.agent_keypair }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test] fn test_machine_id_from_public_key() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = MachineId::from_public_key(keypair.public_key());
        assert_eq!(machine_id.as_bytes().len(), PEER_ID_LENGTH);
    }
    #[test] fn test_machine_id_verification() {
        let keypair = MachineKeypair::generate().unwrap();
        let machine_id = MachineId::from_public_key(keypair.public_key());
        machine_id.verify(keypair.public_key()).unwrap();
    }
    #[test] fn test_agent_id_from_public_key() {
        let keypair = AgentKeypair::generate().unwrap();
        let agent_id = AgentId::from_public_key(keypair.public_key());
        assert_eq!(agent_id.as_bytes().len(), PEER_ID_LENGTH);
    }
    #[test] fn test_identity_generation() {
        let identity = Identity::generate().unwrap();
        assert!(identity.machine_id().as_bytes().len() == PEER_ID_LENGTH);
        assert!(identity.agent_id().as_bytes().len() == PEER_ID_LENGTH);
    }
}
