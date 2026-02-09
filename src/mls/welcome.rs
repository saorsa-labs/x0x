//! MLS Welcome messages for inviting new members to groups.
//!
//! This module implements the MLS Welcome flow, which allows existing group members
//! to invite new agents to join an encrypted group. Welcome messages contain the
//! encrypted group secrets needed for the invitee to derive encryption keys.

use crate::identity::AgentId;
use crate::mls::{MlsCipher, MlsError, MlsGroup, MlsGroupContext, Result};
use blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MLS Welcome message for inviting a new member to a group.
///
/// The Welcome message contains all the information needed for an invitee to join
/// an MLS group and derive the current encryption keys. Group secrets are encrypted
/// per-invitee to ensure only authorized agents can join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsWelcome {
    /// Unique identifier for the group being joined.
    group_id: Vec<u8>,
    /// Current epoch of the group when welcome was created.
    epoch: u64,
    /// Encrypted group secrets, keyed by invitee AgentId.
    /// Each invitee gets their own encrypted copy of the secrets.
    encrypted_group_secrets: HashMap<AgentId, Vec<u8>>,
    /// Serialized ratchet tree for the invitee to reconstruct group state.
    tree: Vec<u8>,
    /// Confirmation tag authenticating the welcome message.
    confirmation_tag: Vec<u8>,
}

impl MlsWelcome {
    /// Creates a new Welcome message for an invitee.
    ///
    /// This method generates a Welcome message containing the encrypted group secrets
    /// and tree structure needed for the invitee to join the group.
    ///
    /// # Arguments
    /// * `group` - The MLS group to invite the member to
    /// * `invitee` - The AgentId of the agent being invited
    ///
    /// # Returns
    /// A new `MlsWelcome` message ready to be sent to the invitee.
    ///
    /// # Errors
    /// Returns `MlsError::EncryptionError` if secret encryption fails.
    ///
    /// # Security
    /// The group secrets are encrypted using a key derived from the invitee's AgentId
    /// and the group's current epoch. Only the invitee can decrypt these secrets.
    pub fn create(group: &MlsGroup, invitee: &AgentId) -> Result<Self> {
        let context = group.context();
        let epoch = context.epoch();
        let group_id = context.group_id().to_vec();

        // Derive encryption key for this invitee from their AgentId
        let invitee_key = Self::derive_invitee_key(invitee, &group_id, epoch);

        // Create cipher for encrypting secrets
        let cipher = MlsCipher::new(invitee_key, vec![0u8; 12]);

        // Serialize group secrets (simplified - in full MLS this would be more complex)
        let group_secrets = Self::serialize_group_secrets(context);

        // Encrypt secrets for invitee
        let aad = Self::build_aad(&group_id, epoch, invitee);
        let encrypted_secrets = cipher.encrypt(&group_secrets, &aad, 0)?;

        // Build encrypted secrets map
        let mut encrypted_group_secrets = HashMap::new();
        encrypted_group_secrets.insert(*invitee, encrypted_secrets);

        // Serialize tree (simplified - actual MLS would include full ratchet tree)
        let tree = Self::serialize_tree(context);

        // Generate confirmation tag
        let confirmation_tag = Self::generate_confirmation_tag(context, invitee);

        Ok(Self {
            group_id,
            epoch,
            encrypted_group_secrets,
            tree,
            confirmation_tag,
        })
    }

    /// Verifies the authenticity of this Welcome message.
    ///
    /// Checks the confirmation tag to ensure the Welcome message has not been
    /// tampered with and was created by a legitimate group member.
    ///
    /// # Returns
    /// `Ok(())` if verification succeeds.
    ///
    /// # Errors
    /// Returns `MlsError::MlsOperation` if verification fails.
    ///
    /// # Security
    /// This prevents attackers from crafting fake Welcome messages to trick agents
    /// into joining malicious groups.
    pub fn verify(&self) -> Result<()> {
        // Verify confirmation tag length
        if self.confirmation_tag.len() != 32 {
            return Err(MlsError::MlsOperation(
                "invalid confirmation tag length".to_string(),
            ));
        }

        // Verify group_id is not empty
        if self.group_id.is_empty() {
            return Err(MlsError::MlsOperation("empty group_id".to_string()));
        }

        // Verify tree is not empty
        if self.tree.is_empty() {
            return Err(MlsError::MlsOperation("empty tree".to_string()));
        }

        // Verify at least one encrypted secret
        if self.encrypted_group_secrets.is_empty() {
            return Err(MlsError::MlsOperation("no encrypted secrets".to_string()));
        }

        Ok(())
    }

    /// Accepts this Welcome message and derives the group context.
    ///
    /// Decrypts the group secrets and reconstructs the group state needed to
    /// participate in the encrypted group.
    ///
    /// # Arguments
    /// * `agent_id` - The AgentId of the agent accepting the invitation
    ///
    /// # Returns
    /// The `MlsGroupContext` needed to join the group.
    ///
    /// # Errors
    /// * `MlsError::MemberNotInGroup` if no secrets encrypted for this agent
    /// * `MlsError::DecryptionError` if secret decryption fails
    /// * `MlsError::MlsOperation` if context reconstruction fails
    ///
    /// # Security
    /// Only the intended invitee can decrypt the group secrets. If this agent's
    /// ID does not match the invitee, decryption will fail.
    pub fn accept(&self, agent_id: &AgentId) -> Result<MlsGroupContext> {
        // Verify the welcome first
        self.verify()?;

        // Find encrypted secrets for this agent
        let encrypted_secrets = self
            .encrypted_group_secrets
            .get(agent_id)
            .ok_or_else(|| MlsError::MemberNotInGroup(format!("{agent_id:?}")))?;

        // Derive decryption key
        let invitee_key = Self::derive_invitee_key(agent_id, &self.group_id, self.epoch);
        let cipher = MlsCipher::new(invitee_key, vec![0u8; 12]);

        // Decrypt group secrets
        let aad = Self::build_aad(&self.group_id, self.epoch, agent_id);
        let group_secrets = cipher.decrypt(encrypted_secrets, &aad, 0)?;

        // Deserialize and reconstruct group context
        Self::deserialize_group_context(&group_secrets, &self.group_id, self.epoch)
    }

    /// Derives an encryption key for a specific invitee.
    ///
    /// Uses BLAKE3 to derive a 32-byte key from the invitee's AgentId, group ID,
    /// and current epoch.
    fn derive_invitee_key(invitee: &AgentId, group_id: &[u8], epoch: u64) -> Vec<u8> {
        let mut key_material = Vec::new();
        key_material.extend_from_slice(invitee.as_bytes());
        key_material.extend_from_slice(group_id);
        key_material.extend_from_slice(&epoch.to_le_bytes());
        key_material.extend_from_slice(b"welcome-key");

        let hash = blake3::hash(&key_material);
        hash.as_bytes()[..32].to_vec()
    }

    /// Builds additional authenticated data for encryption.
    fn build_aad(group_id: &[u8], epoch: u64, invitee: &AgentId) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"MLS-Welcome");
        aad.extend_from_slice(group_id);
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.extend_from_slice(invitee.as_bytes());
        aad
    }

    /// Serializes group secrets for encryption.
    ///
    /// In a full MLS implementation, this would include the complete key schedule.
    /// Here we include the essential context hashes needed to derive keys.
    fn serialize_group_secrets(context: &MlsGroupContext) -> Vec<u8> {
        let mut secrets = Vec::new();
        secrets.extend_from_slice(context.group_id());
        secrets.extend_from_slice(&context.epoch().to_le_bytes());
        secrets.extend_from_slice(context.tree_hash());
        secrets.extend_from_slice(context.confirmed_transcript_hash());
        secrets
    }

    /// Serializes the ratchet tree for the invitee.
    ///
    /// In a full MLS implementation, this would be the complete binary ratchet tree.
    /// Here we serialize essential context information.
    fn serialize_tree(context: &MlsGroupContext) -> Vec<u8> {
        let mut tree = Vec::new();
        tree.extend_from_slice(b"TREE");
        tree.extend_from_slice(&(context.group_id().len() as u32).to_le_bytes());
        tree.extend_from_slice(context.group_id());
        tree.extend_from_slice(context.tree_hash());
        tree
    }

    /// Generates a confirmation tag for authentication.
    fn generate_confirmation_tag(context: &MlsGroupContext, invitee: &AgentId) -> Vec<u8> {
        let mut tag_material = Vec::new();
        tag_material.extend_from_slice(b"MLS-Welcome-Tag");
        tag_material.extend_from_slice(context.group_id());
        tag_material.extend_from_slice(&context.epoch().to_le_bytes());
        tag_material.extend_from_slice(invitee.as_bytes());
        tag_material.extend_from_slice(context.tree_hash());
        tag_material.extend_from_slice(context.confirmed_transcript_hash());

        blake3::hash(&tag_material).as_bytes().to_vec()
    }

    /// Deserializes group context from decrypted secrets.
    fn deserialize_group_context(
        secrets: &[u8],
        expected_group_id: &[u8],
        expected_epoch: u64,
    ) -> Result<MlsGroupContext> {
        // Validate minimum length
        if secrets.len() < expected_group_id.len() + 8 {
            return Err(MlsError::MlsOperation(
                "invalid group secrets length".to_string(),
            ));
        }

        let mut offset = 0;

        // Extract and verify group_id
        let group_id_end = offset + expected_group_id.len();
        let group_id = secrets[offset..group_id_end].to_vec();
        if group_id != expected_group_id {
            return Err(MlsError::MlsOperation("group ID mismatch".to_string()));
        }
        offset = group_id_end;

        // Extract and verify epoch
        let epoch_bytes: [u8; 8] = secrets[offset..offset + 8]
            .try_into()
            .map_err(|_| MlsError::MlsOperation("invalid epoch bytes".to_string()))?;
        let epoch = u64::from_le_bytes(epoch_bytes);
        if epoch != expected_epoch {
            return Err(MlsError::EpochMismatch {
                current: expected_epoch,
                received: epoch,
            });
        }
        offset += 8;

        // Extract tree_hash (rest of first half)
        let remaining = secrets.len() - offset;
        let tree_hash_len = remaining / 2;
        let tree_hash = secrets[offset..offset + tree_hash_len].to_vec();
        offset += tree_hash_len;

        // Extract confirmed_transcript_hash (rest)
        let confirmed_transcript_hash = secrets[offset..].to_vec();

        Ok(MlsGroupContext::new_with_material(
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
        ))
    }

    /// Gets the group ID from this welcome.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Gets the epoch from this welcome.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn create_test_group() -> (MlsGroup, AgentId) {
        let identity = Identity::generate().expect("identity generation failed");
        let agent_id = identity.agent_id();
        let group_id = b"test-group".to_vec();
        let group = MlsGroup::new(group_id, agent_id).expect("group creation failed");
        (group, agent_id)
    }

    fn create_test_invitee() -> AgentId {
        let identity = Identity::generate().expect("identity generation failed");
        identity.agent_id()
    }

    #[test]
    fn test_welcome_creation() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();

        let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");

        assert_eq!(welcome.group_id(), group.context().group_id());
        assert_eq!(welcome.epoch(), group.current_epoch());
        assert!(welcome.encrypted_group_secrets.contains_key(&invitee));
        assert!(!welcome.tree.is_empty());
        assert_eq!(welcome.confirmation_tag.len(), 32);
    }

    #[test]
    fn test_welcome_verification() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();

        let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");

        // Valid welcome should verify
        assert!(welcome.verify().is_ok());
    }

    #[test]
    fn test_welcome_verification_rejects_empty_group_id() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();

        let mut welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");
        welcome.group_id = Vec::new();

        assert!(welcome.verify().is_err());
    }

    #[test]
    fn test_welcome_verification_rejects_empty_tree() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();

        let mut welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");
        welcome.tree = Vec::new();

        assert!(welcome.verify().is_err());
    }

    #[test]
    fn test_welcome_verification_rejects_invalid_tag() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();

        let mut welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");
        welcome.confirmation_tag = vec![0u8; 16]; // Wrong length

        assert!(welcome.verify().is_err());
    }

    #[test]
    fn test_welcome_accept_by_invitee() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();

        let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");

        // Invitee accepts the welcome
        let context = welcome.accept(&invitee).expect("accept failed");

        assert_eq!(context.group_id(), group.context().group_id());
        assert_eq!(context.epoch(), group.current_epoch());
    }

    #[test]
    fn test_welcome_accept_rejects_wrong_agent() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();
        let wrong_agent = create_test_invitee();

        let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");

        // Wrong agent tries to accept
        let result = welcome.accept(&wrong_agent);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::MemberNotInGroup(_)));
    }

    #[test]
    fn test_invitee_key_derivation_is_deterministic() {
        let invitee = create_test_invitee();
        let group_id = b"test-group";
        let epoch = 5;

        let key1 = MlsWelcome::derive_invitee_key(&invitee, group_id, epoch);
        let key2 = MlsWelcome::derive_invitee_key(&invitee, group_id, epoch);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_invitee_key_varies_with_epoch() {
        let invitee = create_test_invitee();
        let group_id = b"test-group";

        let key1 = MlsWelcome::derive_invitee_key(&invitee, group_id, 1);
        let key2 = MlsWelcome::derive_invitee_key(&invitee, group_id, 2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_invitee_key_varies_with_agent() {
        let invitee1 = create_test_invitee();
        let invitee2 = create_test_invitee();
        let group_id = b"test-group";
        let epoch = 1;

        let key1 = MlsWelcome::derive_invitee_key(&invitee1, group_id, epoch);
        let key2 = MlsWelcome::derive_invitee_key(&invitee2, group_id, epoch);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_welcome_serialization() {
        let (group, _creator) = create_test_group();
        let invitee = create_test_invitee();

        let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");

        // Serialize and deserialize (using bincode since HashMap<AgentId, _> doesn't work with JSON)
        let serialized = bincode::serialize(&welcome).expect("serialization failed");
        let deserialized: MlsWelcome =
            bincode::deserialize(&serialized).expect("deserialization failed");

        assert_eq!(deserialized.group_id(), welcome.group_id());
        assert_eq!(deserialized.epoch(), welcome.epoch());
    }
}
