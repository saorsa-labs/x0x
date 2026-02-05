// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://www.saorsalabs.com/licenses

//! Key storage serialization for x0x identities.
//!
//! This module provides serialization and deserialization functions for
//! MachineKeypair and AgentKeypair, enabling persistent storage and
//! cross-machine portability.

use crate::error::{IdentityError, Result};
use crate::identity::{AgentKeypair, MachineKeypair};
use serde::{Deserialize, Serialize};

/// Serialized keypair format for storage.
#[derive(Serialize, Deserialize)]
struct SerializedKeypair {
    /// The public key bytes.
    public_key: Vec<u8>,
    /// The secret key bytes.
    secret_key: Vec<u8>,
}

/// Serialize a MachineKeypair to bytes.
///
/// Uses bincode for compact, efficient serialization. The serialized format
/// includes both public and secret key components.
///
/// # Arguments
///
/// * `kp` - The MachineKeypair to serialize.
///
/// # Returns
///
/// A byte vector containing the serialized keypair.
///
/// # Errors
///
/// Returns `IdentityError::Serialization` if bincode serialization fails.
pub fn serialize_machine_keypair(kp: &MachineKeypair) -> Result<Vec<u8>> {
    let (pub_bytes, sec_bytes) = kp.to_bytes();
    let data = SerializedKeypair {
        public_key: pub_bytes,
        secret_key: sec_bytes,
    };
    bincode::serialize(&data)
        .map_err(|e| IdentityError::Serialization(e.to_string()))
}

/// Deserialize a MachineKeypair from bytes.
///
/// Reconstructs a MachineKeypair from previously serialized data.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair bytes.
///
/// # Returns
///
/// The deserialized MachineKeypair.
///
/// # Errors
///
/// Returns `IdentityError::Serialization` if deserialization fails, or
/// `IdentityError::InvalidPublicKey`/`InvalidSecretKey` if the key bytes are invalid.
pub fn deserialize_machine_keypair(bytes: &[u8]) -> Result<MachineKeypair> {
    let data: SerializedKeypair = bincode::deserialize(bytes)
        .map_err(|e| IdentityError::Serialization(e.to_string()))?;
    MachineKeypair::from_bytes(&data.public_key, &data.secret_key)
}

/// Serialize an AgentKeypair to bytes.
///
/// Uses bincode for compact, efficient serialization. The serialized format
/// includes both public and secret key components.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to serialize.
///
/// # Returns
///
/// A byte vector containing the serialized keypair.
///
/// # Errors
///
/// Returns `IdentityError::Serialization` if bincode serialization fails.
pub fn serialize_agent_keypair(kp: &AgentKeypair) -> Result<Vec<u8>> {
    let (pub_bytes, sec_bytes) = kp.to_bytes();
    let data = SerializedKeypair {
        public_key: pub_bytes,
        secret_key: sec_bytes,
    };
    bincode::serialize(&data)
        .map_err(|e| IdentityError::Serialization(e.to_string()))
}

/// Deserialize an AgentKeypair from bytes.
///
/// Reconstructs an AgentKeypair from previously serialized data.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair bytes.
///
/// # Returns
///
/// The deserialized AgentKeypair.
///
/// # Errors
///
/// Returns `IdentityError::Serialization` if deserialization fails, or
/// `IdentityError::InvalidPublicKey`/`InvalidSecretKey` if the key bytes are invalid.
pub fn deserialize_agent_keypair(bytes: &[u8]) -> Result<AgentKeypair> {
    let data: SerializedKeypair = bincode::deserialize(bytes)
        .map_err(|e| IdentityError::Serialization(e.to_string()))?;
    AgentKeypair::from_bytes(&data.public_key, &data.secret_key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_machine_keypair_serialization_roundtrip() {
        let original = MachineKeypair::generate().unwrap();
        let serialized = serialize_machine_keypair(&original).unwrap();
        let deserialized = deserialize_machine_keypair(&serialized).unwrap();

        assert_eq!(original.machine_id(), deserialized.machine_id());
    }

    #[test]
    fn test_agent_keypair_serialization_roundtrip() {
        let original = AgentKeypair::generate().unwrap();
        let serialized = serialize_agent_keypair(&original).unwrap();
        let deserialized = deserialize_agent_keypair(&serialized).unwrap();

        assert_eq!(original.agent_id(), deserialized.agent_id());
    }

    #[test]
    fn test_serialization_produces_output() {
        let keypair = MachineKeypair::generate().unwrap();
        let serialized = serialize_machine_keypair(&keypair).unwrap();

        // ML-DSA-65 public key is 1952 bytes, secret key is 4016 bytes
        // Bincode adds some overhead for length prefixes
        assert!(serialized.len() > 4000);
    }

    #[test]
    fn test_deserialization_invalid_data_returns_error() {
        let invalid_data = vec![0u8; 10];
        let result = deserialize_machine_keypair(&invalid_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_deserialization_corrupted_data_returns_error() {
        let keypair = MachineKeypair::generate().unwrap();
        let mut serialized = serialize_machine_keypair(&keypair).unwrap();

        // Corrupt the data
        serialized[0] = 0xFF;
        serialized[1] = 0xFF;

        let result = deserialize_machine_keypair(&serialized);
        // Should return an error (either deserialization error or invalid key error)
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_keypair_different_from_machine_keypair() {
        let machine_kp = MachineKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();

        // Different keypairs should have different serialized forms
        let machine_serialized = serialize_machine_keypair(&machine_kp).unwrap();
        let agent_serialized = serialize_agent_keypair(&agent_kp).unwrap();

        // The serialization format is the same, but the keys are different
        assert_ne!(machine_serialized, agent_serialized);
    }
}
