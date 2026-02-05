//! MLS key derivation for secure group encryption.
//!
//! This module implements the key schedule for deriving encryption keys and nonces
//! from MLS group state. It provides deterministic key derivation with support for
//! key rotation on epoch changes.

use crate::mls::{MlsGroup, Result};
use blake3;

/// MLS key schedule for deriving encryption keys and nonces.
///
/// The key schedule derives cryptographic material from the group's current epoch
/// and secrets. Each epoch produces unique keys, providing forward secrecy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsKeySchedule {
    /// Current epoch number.
    epoch: u64,
    /// Hash of pre-shared key identifiers.
    psk_id_hash: Vec<u8>,
    /// Derived secret material.
    secret: Vec<u8>,
    /// Encryption key for AEAD.
    key: Vec<u8>,
    /// Base nonce for message encryption.
    base_nonce: Vec<u8>,
}

impl MlsKeySchedule {
    /// Derives a key schedule from an MLS group.
    ///
    /// This generates all cryptographic material needed for encryption/decryption
    /// from the group's current state and epoch.
    ///
    /// # Arguments
    /// * `group` - The MLS group to derive keys from
    ///
    /// # Returns
    /// A new `MlsKeySchedule` with derived keys and nonces.
    ///
    /// # Errors
    /// Currently does not error, but returns `Result` for future extensibility.
    ///
    /// # Security
    /// Keys are deterministically derived using BLAKE3 for both speed and security.
    /// Each epoch produces completely different keys, providing forward secrecy.
    pub fn from_group(group: &MlsGroup) -> Result<Self> {
        let epoch = group.current_epoch();
        let context = group.context();

        // Derive PSK ID hash from group ID and epoch
        let mut psk_material = Vec::new();
        psk_material.extend_from_slice(context.group_id());
        psk_material.extend_from_slice(&epoch.to_le_bytes());
        let psk_id_hash = blake3::hash(&psk_material).as_bytes().to_vec();

        // Derive secret from group ID, context hashes, and epoch
        let mut secret_material = Vec::new();
        secret_material.extend_from_slice(context.group_id()); // Include group ID for uniqueness
        secret_material.extend_from_slice(context.tree_hash());
        secret_material.extend_from_slice(context.confirmed_transcript_hash());
        secret_material.extend_from_slice(&epoch.to_le_bytes());
        let secret = blake3::hash(&secret_material).as_bytes().to_vec();

        // Derive encryption key from secret
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&secret);
        key_material.extend_from_slice(b"encryption");
        key_material.extend_from_slice(&epoch.to_le_bytes());
        let key_hash = blake3::hash(&key_material);
        let key = key_hash.as_bytes()[..32].to_vec(); // ChaCha20 uses 32-byte keys

        // Derive base nonce from secret
        let mut nonce_material = Vec::new();
        nonce_material.extend_from_slice(&secret);
        nonce_material.extend_from_slice(b"nonce");
        nonce_material.extend_from_slice(&epoch.to_le_bytes());
        let nonce_hash = blake3::hash(&nonce_material);
        let base_nonce = nonce_hash.as_bytes()[..12].to_vec(); // ChaCha20-Poly1305 uses 12-byte nonces

        Ok(Self {
            epoch,
            psk_id_hash,
            secret,
            key,
            base_nonce,
        })
    }

    /// Gets the encryption key.
    ///
    /// This key should be used for ChaCha20-Poly1305 AEAD encryption.
    ///
    /// # Returns
    /// A 32-byte encryption key.
    #[must_use]
    pub fn encryption_key(&self) -> &[u8] {
        &self.key
    }

    /// Gets the base nonce.
    ///
    /// The base nonce is XORed with a message counter to produce unique nonces
    /// for each encrypted message.
    ///
    /// # Returns
    /// A 12-byte base nonce.
    #[must_use]
    pub fn base_nonce(&self) -> &[u8] {
        &self.base_nonce
    }

    /// Derives a unique nonce for a specific message counter.
    ///
    /// This XORs the base nonce with the counter to produce a unique nonce
    /// for each message. The counter should increment for each message sent.
    ///
    /// # Arguments
    /// * `counter` - Message counter (should be unique per message)
    ///
    /// # Returns
    /// A 12-byte nonce unique to this counter value.
    ///
    /// # Security
    /// **CRITICAL**: Never reuse the same counter value with the same key.
    /// Nonce reuse completely breaks ChaCha20-Poly1305 security.
    #[must_use]
    pub fn derive_nonce(&self, counter: u64) -> Vec<u8> {
        let counter_bytes = counter.to_le_bytes();
        let mut nonce = self.base_nonce.clone();

        // XOR counter into nonce (last 8 bytes)
        for (i, byte) in counter_bytes.iter().enumerate() {
            if i + 4 < nonce.len() {
                nonce[i + 4] ^= byte;
            }
        }

        nonce
    }

    /// Gets the current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Gets the PSK ID hash.
    #[must_use]
    pub fn psk_id_hash(&self) -> &[u8] {
        &self.psk_id_hash
    }

    /// Gets the derived secret.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentId;

    fn test_agent_id(id: u8) -> AgentId {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        AgentId(bytes)
    }

    #[test]
    fn test_key_derivation_from_group() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).unwrap();
        let schedule = MlsKeySchedule::from_group(&group);

        assert!(schedule.is_ok());
        let schedule = schedule.unwrap();

        // Verify key and nonce lengths
        assert_eq!(schedule.encryption_key().len(), 32); // ChaCha20 key size
        assert_eq!(schedule.base_nonce().len(), 12); // ChaCha20-Poly1305 nonce size
        assert_eq!(schedule.epoch(), 0);
    }

    #[test]
    fn test_key_derivation_is_deterministic() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).unwrap();

        // Derive keys twice
        let schedule1 = MlsKeySchedule::from_group(&group).unwrap();
        let schedule2 = MlsKeySchedule::from_group(&group).unwrap();

        // Should produce identical keys
        assert_eq!(schedule1.encryption_key(), schedule2.encryption_key());
        assert_eq!(schedule1.base_nonce(), schedule2.base_nonce());
        assert_eq!(schedule1.secret(), schedule2.secret());
        assert_eq!(schedule1.psk_id_hash(), schedule2.psk_id_hash());
    }

    #[test]
    fn test_different_epochs_produce_different_keys() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        // Get keys at epoch 0
        let schedule_epoch0 = MlsKeySchedule::from_group(&group).unwrap();

        // Advance epoch
        let commit = group.commit().unwrap();
        group.apply_commit(&commit).unwrap();
        assert_eq!(group.current_epoch(), 1);

        // Get keys at epoch 1
        let schedule_epoch1 = MlsKeySchedule::from_group(&group).unwrap();

        // Keys should be different
        assert_ne!(
            schedule_epoch0.encryption_key(),
            schedule_epoch1.encryption_key()
        );
        assert_ne!(schedule_epoch0.base_nonce(), schedule_epoch1.base_nonce());
        assert_ne!(schedule_epoch0.secret(), schedule_epoch1.secret());
        assert_ne!(schedule_epoch0.epoch(), schedule_epoch1.epoch());
    }

    #[test]
    fn test_nonce_derivation_is_deterministic() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).unwrap();
        let schedule = MlsKeySchedule::from_group(&group).unwrap();

        let counter = 42;
        let nonce1 = schedule.derive_nonce(counter);
        let nonce2 = schedule.derive_nonce(counter);

        assert_eq!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 12);
    }

    #[test]
    fn test_nonce_unique_per_counter() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).unwrap();
        let schedule = MlsKeySchedule::from_group(&group).unwrap();

        let nonce0 = schedule.derive_nonce(0);
        let nonce1 = schedule.derive_nonce(1);
        let nonce100 = schedule.derive_nonce(100);

        // All nonces should be different
        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce1, nonce100);
        assert_ne!(nonce0, nonce100);

        // All should be 12 bytes
        assert_eq!(nonce0.len(), 12);
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce100.len(), 12);
    }

    #[test]
    fn test_nonce_xor_with_counter() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).unwrap();
        let schedule = MlsKeySchedule::from_group(&group).unwrap();

        let base = schedule.base_nonce();
        let nonce0 = schedule.derive_nonce(0);

        // Counter 0 should match base nonce
        assert_eq!(base, nonce0.as_slice());

        // Counter 1 should differ in last bytes
        let nonce1 = schedule.derive_nonce(1);
        assert_ne!(base, nonce1.as_slice());
    }

    #[test]
    fn test_different_groups_produce_different_keys() {
        let initiator = test_agent_id(1);

        let group1 = MlsGroup::new(b"group-1".to_vec(), initiator).unwrap();
        let group2 = MlsGroup::new(b"group-2".to_vec(), initiator).unwrap();

        let schedule1 = MlsKeySchedule::from_group(&group1).unwrap();
        let schedule2 = MlsKeySchedule::from_group(&group2).unwrap();

        // Different groups should have different keys
        assert_ne!(schedule1.encryption_key(), schedule2.encryption_key());
        assert_ne!(schedule1.base_nonce(), schedule2.base_nonce());
        assert_ne!(schedule1.psk_id_hash(), schedule2.psk_id_hash());
    }

    #[test]
    fn test_key_schedule_accessors() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).unwrap();
        let schedule = MlsKeySchedule::from_group(&group).unwrap();

        // Verify all accessors work
        assert_eq!(schedule.epoch(), 0);
        assert!(!schedule.encryption_key().is_empty());
        assert!(!schedule.base_nonce().is_empty());
        assert!(!schedule.psk_id_hash().is_empty());
        assert!(!schedule.secret().is_empty());
    }

    #[test]
    fn test_key_schedule_clone() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).unwrap();
        let schedule1 = MlsKeySchedule::from_group(&group).unwrap();
        let schedule2 = schedule1.clone();

        assert_eq!(schedule1, schedule2);
        assert_eq!(schedule1.encryption_key(), schedule2.encryption_key());
        assert_eq!(schedule1.base_nonce(), schedule2.base_nonce());
    }
}
