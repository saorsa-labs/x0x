//! Encrypted CRDT task list deltas for secure group collaboration.
//!
//! This module provides an encryption layer for `TaskListDelta`, allowing secure
//! synchronization of task lists within MLS-encrypted groups. Deltas are encrypted
//! with group keys and authenticated to prevent tampering.

use crate::crdt::TaskListDelta;
use crate::mls::{MlsCipher, MlsError, MlsGroup, MlsKeySchedule, Result as MlsResult};
use serde::{Deserialize, Serialize};

/// Encrypted task list delta for secure group synchronization.
///
/// This wraps a `TaskListDelta` with encryption, allowing task lists to be
/// synchronized securely within MLS groups. Each delta is encrypted with the
/// group's current epoch key and includes authentication via AEAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTaskListDelta {
    /// Group identifier for this encrypted delta.
    group_id: Vec<u8>,
    /// Epoch when this delta was encrypted.
    epoch: u64,
    /// Encrypted delta ciphertext (includes authentication tag).
    ciphertext: Vec<u8>,
    /// Additional authenticated data (group_id + epoch).
    aad: Vec<u8>,
}

impl EncryptedTaskListDelta {
    /// Encrypts a task list delta for a specific group.
    ///
    /// Uses the group's current epoch key to encrypt the delta with ChaCha20-Poly1305 AEAD.
    /// The ciphertext includes an authentication tag to prevent tampering.
    ///
    /// # Arguments
    /// * `delta` - The task list delta to encrypt
    /// * `group` - The MLS group (provides group_id and epoch)
    /// * `cipher` - The MLS cipher with current epoch key
    ///
    /// # Returns
    /// An `EncryptedTaskListDelta` ready for transmission.
    ///
    /// # Errors
    /// Returns `MlsError::EncryptionError` if:
    /// - Delta serialization fails
    /// - Encryption operation fails
    ///
    /// # Security
    /// The group_id and epoch are included in the AAD (Additional Authenticated Data),
    /// binding the ciphertext to a specific group and epoch. This prevents replay attacks
    /// and cross-group confusion.
    pub fn encrypt(delta: &TaskListDelta, group: &MlsGroup, cipher: &MlsCipher) -> MlsResult<Self> {
        let context = group.context();
        let group_id = context.group_id().to_vec();
        let epoch = context.epoch();

        // Serialize the delta
        let plaintext = bincode::serialize(delta)
            .map_err(|e| MlsError::EncryptionError(format!("delta serialization failed: {e}")))?;

        // Build AAD: "EncryptedDelta" || group_id || epoch
        let mut aad = Vec::new();
        aad.extend_from_slice(b"EncryptedDelta");
        aad.extend_from_slice(&group_id);
        aad.extend_from_slice(&epoch.to_le_bytes());

        // Encrypt with counter 0 (each delta is a single message)
        let ciphertext = cipher.encrypt(&plaintext, &aad, 0)?;

        Ok(Self {
            group_id,
            epoch,
            ciphertext,
            aad,
        })
    }

    /// Decrypts this encrypted delta using the provided cipher.
    ///
    /// Verifies the authentication tag and decrypts the task list delta.
    ///
    /// # Arguments
    /// * `cipher` - The MLS cipher with the appropriate epoch key
    ///
    /// # Returns
    /// The decrypted `TaskListDelta`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Authentication fails (tampering detected)
    /// - Decryption fails (wrong key or corrupted data)
    /// - Deserialization fails (invalid delta format)
    ///
    /// # Security
    /// Authentication failure indicates either:
    /// - The ciphertext was tampered with
    /// - Wrong epoch key is being used
    /// - The AAD doesn't match (wrong group or epoch)
    pub fn decrypt(&self, cipher: &MlsCipher) -> MlsResult<TaskListDelta> {
        // Decrypt with counter 0
        let plaintext = cipher.decrypt(&self.ciphertext, &self.aad, 0)?;

        // Deserialize the delta
        bincode::deserialize(&plaintext)
            .map_err(|e| MlsError::DecryptionError(format!("delta deserialization failed: {e}")))
    }

    /// Encrypts a delta using the key schedule derived from a group.
    ///
    /// This is a convenience method that derives the cipher from the group's
    /// key schedule and encrypts the delta.
    ///
    /// # Arguments
    /// * `delta` - The task list delta to encrypt
    /// * `group` - The MLS group
    ///
    /// # Returns
    /// An `EncryptedTaskListDelta` ready for transmission.
    ///
    /// # Errors
    /// Returns `MlsError` if key derivation or encryption fails.
    pub fn encrypt_with_group(delta: &TaskListDelta, group: &MlsGroup) -> MlsResult<Self> {
        let key_schedule = MlsKeySchedule::from_group(group)?;
        let cipher = MlsCipher::new(
            key_schedule.encryption_key().to_vec(),
            key_schedule.base_nonce().to_vec(),
        );
        Self::encrypt(delta, group, &cipher)
    }

    /// Decrypts this delta using the key schedule derived from a group.
    ///
    /// This is a convenience method that derives the cipher from the group's
    /// key schedule and decrypts the delta.
    ///
    /// # Arguments
    /// * `group` - The MLS group (must be at the same epoch as encryption)
    ///
    /// # Returns
    /// The decrypted `TaskListDelta`.
    ///
    /// # Errors
    /// Returns `MlsError` if:
    /// - Epoch mismatch (group is at different epoch)
    /// - Key derivation fails
    /// - Decryption fails
    pub fn decrypt_with_group(&self, group: &MlsGroup) -> MlsResult<TaskListDelta> {
        let context = group.context();

        // Verify epoch matches
        if context.epoch() != self.epoch {
            return Err(MlsError::EpochMismatch {
                current: context.epoch(),
                received: self.epoch,
            });
        }

        // Verify group_id matches
        if context.group_id() != self.group_id {
            return Err(MlsError::MlsOperation(format!(
                "group ID mismatch: expected {:?}, got {:?}",
                context.group_id(),
                self.group_id
            )));
        }

        let key_schedule = MlsKeySchedule::from_group(group)?;
        let cipher = MlsCipher::new(
            key_schedule.encryption_key().to_vec(),
            key_schedule.base_nonce().to_vec(),
        );
        self.decrypt(&cipher)
    }

    /// Gets the group ID for this encrypted delta.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Gets the epoch when this delta was encrypted.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Gets the ciphertext (including authentication tag).
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Gets the additional authenticated data.
    #[must_use]
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{TaskId, TaskItem, TaskMetadata};
    use crate::identity::Identity;
    use crate::mls::MlsGroup;
    use saorsa_gossip_types::PeerId;

    fn create_test_group() -> (MlsGroup, Vec<u8>) {
        let identity = Identity::generate().expect("identity generation failed");
        let agent_id = identity.agent_id();
        let group_id = b"test-encryption-group".to_vec();
        let group = MlsGroup::new(group_id.clone(), agent_id).expect("group creation failed");
        (group, group_id)
    }

    fn create_test_delta() -> TaskListDelta {
        let mut delta = TaskListDelta::new(1);

        // Add a task
        let identity = Identity::generate().expect("identity generation failed");
        let agent_id = identity.agent_id();
        let timestamp = 1000;
        let task_id = TaskId::new("Test task", &agent_id, timestamp);

        let metadata = TaskMetadata {
            title: "Test task".to_string(),
            description: "Test description".to_string(),
            priority: 128,
            created_by: agent_id,
            created_at: timestamp,
            tags: vec![],
        };

        let peer_id = PeerId::new(*agent_id.as_bytes());
        let task = TaskItem::new(task_id, metadata, peer_id);
        let tag = (peer_id, 1);
        delta.added_tasks.insert(task_id, (task, tag));

        delta
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (group, _group_id) = create_test_group();
        let delta = create_test_delta();

        // Encrypt
        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        assert_eq!(encrypted.group_id(), group.context().group_id());
        assert_eq!(encrypted.epoch(), group.current_epoch());
        assert!(!encrypted.ciphertext().is_empty());

        // Decrypt
        let decrypted = encrypted
            .decrypt_with_group(&group)
            .expect("decryption failed");

        // Verify delta content matches
        assert_eq!(decrypted.version, delta.version);
        assert_eq!(decrypted.added_tasks.len(), delta.added_tasks.len());
    }

    #[test]
    fn test_encrypted_delta_includes_group_metadata() {
        let (group, group_id) = create_test_group();
        let delta = create_test_delta();

        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        assert_eq!(encrypted.group_id(), &group_id);
        assert_eq!(encrypted.epoch(), 0);
    }

    #[test]
    fn test_decryption_fails_with_wrong_epoch() {
        let (mut group, _) = create_test_group();
        let delta = create_test_delta();

        // Encrypt at epoch 0
        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        // Simulate epoch change
        let commit = group.commit().expect("commit failed");
        group.apply_commit(&commit).expect("apply failed");

        // Try to decrypt with new epoch
        let result = encrypted.decrypt_with_group(&group);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MlsError::EpochMismatch { .. }
        ));
    }

    #[test]
    fn test_decryption_fails_with_wrong_group() {
        let identity1 = Identity::generate().expect("identity generation failed");
        let agent_id1 = identity1.agent_id();
        let group_id1 = b"test-group-1".to_vec();
        let group1 = MlsGroup::new(group_id1, agent_id1).expect("group creation failed");

        let identity2 = Identity::generate().expect("identity generation failed");
        let agent_id2 = identity2.agent_id();
        let group_id2 = b"test-group-2".to_vec(); // Different group ID
        let group2 = MlsGroup::new(group_id2, agent_id2).expect("group creation failed");

        let delta = create_test_delta();

        // Encrypt with group1
        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group1).expect("encryption failed");

        // Try to decrypt with group2 (different group_id)
        let result = encrypted.decrypt_with_group(&group2);
        assert!(result.is_err());
        // Should be a group ID mismatch error
        match result.unwrap_err() {
            MlsError::MlsOperation(msg) => assert!(msg.contains("group ID mismatch")),
            _ => panic!("Expected MlsOperation error for group ID mismatch"),
        }
    }

    #[test]
    fn test_authentication_prevents_tampering() {
        let (group, _) = create_test_group();
        let delta = create_test_delta();

        let mut encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        // Tamper with ciphertext
        encrypted.ciphertext[0] ^= 1;

        // Decryption should fail due to authentication failure
        let result = encrypted.decrypt_with_group(&group);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::DecryptionError(_)));
    }

    #[test]
    fn test_different_epochs_produce_different_ciphertexts() {
        let (mut group, _) = create_test_group();
        let delta = create_test_delta();

        // Encrypt at epoch 0
        let encrypted1 =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        // Advance epoch
        let commit = group.commit().expect("commit failed");
        group.apply_commit(&commit).expect("apply failed");

        // Encrypt same delta at epoch 1
        let encrypted2 =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        // Ciphertexts should be different
        assert_ne!(encrypted1.ciphertext(), encrypted2.ciphertext());
        assert_ne!(encrypted1.epoch(), encrypted2.epoch());
    }

    #[test]
    fn test_empty_delta_encryption() {
        let (group, _) = create_test_group();
        let delta = TaskListDelta::new(1); // Empty delta

        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        let decrypted = encrypted
            .decrypt_with_group(&group)
            .expect("decryption failed");

        assert_eq!(decrypted.version, delta.version);
        assert!(decrypted.added_tasks.is_empty());
    }

    #[test]
    fn test_large_delta_encryption() {
        let (group, _) = create_test_group();
        let mut delta = TaskListDelta::new(1);

        let identity = Identity::generate().expect("identity generation failed");
        let agent_id = identity.agent_id();
        let peer_id = PeerId::new(*agent_id.as_bytes());

        // Add many tasks
        for i in 0..100 {
            let task_id = TaskId::new(&format!("Task {i}"), &agent_id, 1000 + i);

            let metadata = TaskMetadata {
                title: format!("Task {i}"),
                description: format!("Description {i}"),
                priority: 128,
                created_by: agent_id,
                created_at: 1000 + i,
                tags: vec![],
            };

            let task = TaskItem::new(task_id, metadata, peer_id);
            let tag = (peer_id, i);
            delta.added_tasks.insert(task_id, (task, tag));
        }

        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        let decrypted = encrypted
            .decrypt_with_group(&group)
            .expect("decryption failed");

        assert_eq!(decrypted.added_tasks.len(), 100);
    }

    #[test]
    fn test_encrypted_delta_serialization() {
        let (group, _) = create_test_group();
        let delta = create_test_delta();

        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        // Serialize and deserialize (using bincode)
        let serialized = bincode::serialize(&encrypted).expect("serialization failed");
        let deserialized: EncryptedTaskListDelta =
            bincode::deserialize(&serialized).expect("deserialization failed");

        assert_eq!(deserialized.group_id(), encrypted.group_id());
        assert_eq!(deserialized.epoch(), encrypted.epoch());
        assert_eq!(deserialized.ciphertext(), encrypted.ciphertext());
    }

    #[test]
    fn test_aad_includes_group_and_epoch() {
        let (group, _) = create_test_group();
        let delta = create_test_delta();

        let encrypted =
            EncryptedTaskListDelta::encrypt_with_group(&delta, &group).expect("encryption failed");

        let aad = encrypted.aad();

        // AAD should start with "EncryptedDelta"
        assert!(aad.starts_with(b"EncryptedDelta"));

        // AAD should be longer than just the prefix (includes group_id and epoch)
        assert!(aad.len() > b"EncryptedDelta".len());
    }
}
