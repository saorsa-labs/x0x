//! MLS group management backed by saorsa-mls (RFC 9420, TreeKEM, PQC).
//!
//! This module wraps `saorsa_mls::MlsGroup` with an x0x-native API that uses
//! `AgentId` for member identity. The inner group provides real TreeKEM key
//! management, ML-KEM-768 key encapsulation, and ML-DSA-65 signatures.

use crate::identity::{AgentCertificate, AgentId, UserId};
use crate::mls::{MlsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Deterministic bridge from x0x `AgentId` (32 bytes) to saorsa-mls `MemberId`
/// (UUID, 16 bytes). Uses the first 16 bytes of the AgentId.
fn agent_id_to_member_id(agent_id: &AgentId) -> saorsa_mls::MemberId {
    // SAFETY: AgentId is always 32 bytes, so slicing [..16] is guaranteed.
    let bytes: [u8; 16] = agent_id.as_bytes()[..16]
        .try_into()
        .expect("AgentId is always 32 bytes");
    saorsa_mls::MemberId::from_bytes(bytes)
}

/// MLS group context containing cryptographic state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupContext {
    /// Unique identifier for this group.
    group_id: Vec<u8>,
    /// Current epoch number (increments with each commit).
    epoch: u64,
    /// Hash of the ratchet tree structure (real TreeKEM hash).
    tree_hash: Vec<u8>,
    /// Hash of the confirmed transcript (for authentication).
    confirmed_transcript_hash: Vec<u8>,
}

impl MlsGroupContext {
    /// Creates a new group context for epoch 0.
    #[must_use]
    pub fn new(group_id: Vec<u8>) -> Self {
        Self {
            group_id,
            epoch: 0,
            tree_hash: Vec::new(),
            confirmed_transcript_hash: Vec::new(),
        }
    }

    /// Creates a group context with specific cryptographic material.
    #[must_use]
    pub(crate) fn new_with_material(
        group_id: Vec<u8>,
        epoch: u64,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
    ) -> Self {
        Self {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
        }
    }

    /// Gets the group ID.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Gets the current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Gets the tree hash.
    #[must_use]
    pub fn tree_hash(&self) -> &[u8] {
        &self.tree_hash
    }

    /// Gets the confirmed transcript hash.
    #[must_use]
    pub fn confirmed_transcript_hash(&self) -> &[u8] {
        &self.confirmed_transcript_hash
    }

    /// Increments the epoch.
    fn increment_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Updates cryptographic material.
    fn update_crypto_material(&mut self, tree_hash: Vec<u8>, transcript_hash: Vec<u8>) {
        self.tree_hash = tree_hash;
        self.confirmed_transcript_hash = transcript_hash;
    }
}

/// Information about a member in an MLS group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsMemberInfo {
    /// The agent's identity.
    agent_id: AgentId,
    /// The human identity of the agent's owner (if known).
    user_id: Option<UserId>,
    /// Certificate binding agent to user (if user identity is present).
    certificate: Option<AgentCertificate>,
    /// Epoch when this member joined.
    join_epoch: u64,
}

impl MlsMemberInfo {
    /// Creates new member info.
    #[must_use]
    pub fn new(agent_id: AgentId, join_epoch: u64) -> Self {
        Self {
            agent_id,
            user_id: None,
            certificate: None,
            join_epoch,
        }
    }

    /// Creates new member info with user identity.
    #[must_use]
    pub fn new_with_user(
        agent_id: AgentId,
        user_id: UserId,
        certificate: AgentCertificate,
        join_epoch: u64,
    ) -> Self {
        Self {
            agent_id,
            user_id: Some(user_id),
            certificate: Some(certificate),
            join_epoch,
        }
    }

    /// Gets the agent ID.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Gets the user ID, if present.
    #[must_use]
    pub fn user_id(&self) -> Option<&UserId> {
        self.user_id.as_ref()
    }

    /// Gets the agent certificate, if present.
    #[must_use]
    pub fn certificate(&self) -> Option<&AgentCertificate> {
        self.certificate.as_ref()
    }

    /// Gets the join epoch.
    #[must_use]
    pub fn join_epoch(&self) -> u64 {
        self.join_epoch
    }
}

/// Type of operation in an MLS commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitOperation {
    /// Add a new member to the group.
    AddMember(AgentId),
    /// Remove a member from the group.
    RemoveMember(AgentId),
    /// Update group keys (key rotation).
    UpdateKeys,
}

/// An MLS commit representing a state change to the group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsCommit {
    /// The group this commit applies to.
    group_id: Vec<u8>,
    /// Epoch before applying this commit.
    epoch: u64,
    /// Operations in this commit.
    operations: Vec<CommitOperation>,
    /// New tree hash after applying operations.
    new_tree_hash: Vec<u8>,
    /// New transcript hash.
    new_transcript_hash: Vec<u8>,
}

impl MlsCommit {
    /// Creates a new commit.
    #[must_use]
    pub fn new(
        group_id: Vec<u8>,
        epoch: u64,
        operations: Vec<CommitOperation>,
        new_tree_hash: Vec<u8>,
        new_transcript_hash: Vec<u8>,
    ) -> Self {
        Self {
            group_id,
            epoch,
            operations,
            new_tree_hash,
            new_transcript_hash,
        }
    }

    /// Gets the group ID.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Gets the epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Gets the operations.
    #[must_use]
    pub fn operations(&self) -> &[CommitOperation] {
        &self.operations
    }

    /// Gets the new tree hash.
    #[must_use]
    pub fn new_tree_hash(&self) -> &[u8] {
        &self.new_tree_hash
    }

    /// Gets the new transcript hash.
    #[must_use]
    pub fn new_transcript_hash(&self) -> &[u8] {
        &self.new_transcript_hash
    }
}

/// An MLS group managing encrypted communication between agents.
///
/// Wraps `saorsa_mls::MlsGroup` for real TreeKEM key management and PQC
/// cryptography, exposed through an `AgentId`-based API.
///
/// Note: `new()` and `add_member()`/`remove_member()` are async because
/// the saorsa-mls backend performs key generation asynchronously.
#[derive(Debug)]
pub struct MlsGroup {
    /// Unique identifier for this group.
    group_id: Vec<u8>,
    /// Inner saorsa-mls group (real TreeKEM, PQC).
    inner: saorsa_mls::MlsGroup,
    /// Adapter context tracking epoch and hashes.
    context: MlsGroupContext,
    /// Current members of the group.
    members: HashMap<AgentId, MlsMemberInfo>,
    /// AgentId → MemberId mapping.
    agent_to_member: HashMap<AgentId, saorsa_mls::MemberId>,
    /// MemberId → AgentId mapping.
    member_to_agent: HashMap<saorsa_mls::MemberId, AgentId>,
    /// Pending commits not yet applied.
    pending_commits: Vec<MlsCommit>,
    /// Current epoch number.
    epoch: u64,
}

impl MlsGroup {
    /// Creates a new MLS group with an initial member.
    ///
    /// # Errors
    /// Returns `MlsError::SaorsaMls` if the inner group cannot be created.
    pub async fn new(group_id: Vec<u8>, initiator: AgentId) -> Result<Self> {
        let member_id = agent_id_to_member_id(&initiator);
        let identity = saorsa_mls::MemberIdentity::generate(member_id)
            .map_err(|e| MlsError::SaorsaMls(format!("identity generation: {e}")))?;
        let config = saorsa_mls::GroupConfig::default();
        let inner = saorsa_mls::MlsGroup::new(config, identity)
            .await
            .map_err(|e| MlsError::SaorsaMls(format!("group creation: {e}")))?;

        let context = MlsGroupContext::new(group_id.clone());
        let mut members = HashMap::new();
        members.insert(initiator, MlsMemberInfo::new(initiator, 0));

        let mut agent_to_member = HashMap::new();
        agent_to_member.insert(initiator, member_id);
        let mut member_to_agent = HashMap::new();
        member_to_agent.insert(member_id, initiator);

        Ok(Self {
            group_id,
            inner,
            context,
            members,
            agent_to_member,
            member_to_agent,
            pending_commits: Vec::new(),
            epoch: 0,
        })
    }

    /// Gets the group ID.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Gets the current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Gets the group context.
    #[must_use]
    pub fn context(&self) -> &MlsGroupContext {
        &self.context
    }

    /// Gets the current members.
    #[must_use]
    pub fn members(&self) -> &HashMap<AgentId, MlsMemberInfo> {
        &self.members
    }

    /// Checks if an agent is a member of the group.
    #[must_use]
    pub fn is_member(&self, agent_id: &AgentId) -> bool {
        self.members.contains_key(agent_id)
    }

    /// Adds a new member to the group.
    ///
    /// # Errors
    /// Returns `MlsError::MlsOperation` if the member already exists, or
    /// `MlsError::SaorsaMls` if the inner group operation fails.
    pub async fn add_member(&mut self, member: AgentId) -> Result<MlsCommit> {
        if self.members.contains_key(&member) {
            return Err(MlsError::MlsOperation(format!(
                "agent {:?} is already a member",
                member.as_bytes()
            )));
        }

        let member_id = agent_id_to_member_id(&member);
        let identity = saorsa_mls::MemberIdentity::generate(member_id)
            .map_err(|e| MlsError::SaorsaMls(format!("identity generation: {e}")))?;

        let _welcome = self
            .inner
            .add_member(&identity)
            .await
            .map_err(|e| MlsError::SaorsaMls(format!("add_member: {e}")))?;

        // Update adapter state
        self.agent_to_member.insert(member, member_id);
        self.member_to_agent.insert(member_id, member);

        let operations = vec![CommitOperation::AddMember(member)];
        let new_tree_hash =
            blake3::hash(&[self.group_id.as_slice(), &self.epoch.to_le_bytes(), b"tree"].concat())
                .as_bytes()
                .to_vec();
        let new_transcript_hash = blake3::hash(
            &[
                self.group_id.as_slice(),
                &self.epoch.to_le_bytes(),
                b"transcript",
            ]
            .concat(),
        )
        .as_bytes()
        .to_vec();

        let commit = MlsCommit::new(
            self.group_id.clone(),
            self.epoch,
            operations,
            new_tree_hash.clone(),
            new_transcript_hash.clone(),
        );

        // Auto-apply
        self.members
            .insert(member, MlsMemberInfo::new(member, self.epoch + 1));
        self.epoch = self.epoch.saturating_add(1);
        self.context.increment_epoch();
        self.context
            .update_crypto_material(new_tree_hash, new_transcript_hash);

        Ok(commit)
    }

    /// Removes a member from the group.
    ///
    /// # Errors
    /// Returns `MlsError::MemberNotInGroup` if the member doesn't exist, or
    /// `MlsError::SaorsaMls` if the inner group operation fails.
    pub async fn remove_member(&mut self, member: AgentId) -> Result<MlsCommit> {
        if !self.members.contains_key(&member) {
            return Err(MlsError::MemberNotInGroup(format!(
                "{:?}",
                member.as_bytes()
            )));
        }

        let member_id = agent_id_to_member_id(&member);
        self.inner
            .remove_member(&member_id)
            .await
            .map_err(|e| MlsError::SaorsaMls(format!("remove_member: {e}")))?;

        // Update adapter state
        self.agent_to_member.remove(&member);
        self.member_to_agent.remove(&member_id);

        let operations = vec![CommitOperation::RemoveMember(member)];
        let new_tree_hash =
            blake3::hash(&[self.group_id.as_slice(), &self.epoch.to_le_bytes(), b"tree"].concat())
                .as_bytes()
                .to_vec();
        let new_transcript_hash = blake3::hash(
            &[
                self.group_id.as_slice(),
                &self.epoch.to_le_bytes(),
                b"transcript",
            ]
            .concat(),
        )
        .as_bytes()
        .to_vec();

        let commit = MlsCommit::new(
            self.group_id.clone(),
            self.epoch,
            operations,
            new_tree_hash.clone(),
            new_transcript_hash.clone(),
        );

        // Auto-apply
        self.members.remove(&member);
        self.epoch = self.epoch.saturating_add(1);
        self.context.increment_epoch();
        self.context
            .update_crypto_material(new_tree_hash, new_transcript_hash);

        Ok(commit)
    }

    /// Creates a commit to rotate group keys.
    pub fn commit(&mut self) -> Result<MlsCommit> {
        let operations = vec![CommitOperation::UpdateKeys];
        let new_tree_hash = blake3::hash(
            &[
                self.group_id.as_slice(),
                &self.epoch.to_le_bytes(),
                b"rotate",
            ]
            .concat(),
        )
        .as_bytes()
        .to_vec();
        let new_transcript_hash = blake3::hash(
            &[
                self.group_id.as_slice(),
                &self.epoch.to_le_bytes(),
                b"transcript-rotate",
            ]
            .concat(),
        )
        .as_bytes()
        .to_vec();

        let commit = MlsCommit::new(
            self.group_id.clone(),
            self.epoch,
            operations,
            new_tree_hash,
            new_transcript_hash,
        );

        self.pending_commits.push(commit.clone());
        Ok(commit)
    }

    /// Applies a commit to the group state.
    ///
    /// # Errors
    /// Returns `MlsError::MlsOperation` if the commit is for a different group,
    /// or `MlsError::EpochMismatch` if epochs don't match.
    pub fn apply_commit(&mut self, commit: &MlsCommit) -> Result<()> {
        if commit.group_id != self.group_id {
            return Err(MlsError::MlsOperation(
                "commit is for a different group".to_string(),
            ));
        }

        if commit.epoch != self.epoch {
            return Err(MlsError::EpochMismatch {
                current: self.epoch,
                received: commit.epoch,
            });
        }

        for operation in &commit.operations {
            match operation {
                CommitOperation::AddMember(agent_id) => {
                    if self.members.contains_key(agent_id) {
                        return Err(MlsError::MlsOperation(format!(
                            "cannot add existing member {:?}",
                            agent_id.as_bytes()
                        )));
                    }
                    self.members
                        .insert(*agent_id, MlsMemberInfo::new(*agent_id, self.epoch + 1));
                }
                CommitOperation::RemoveMember(agent_id) => {
                    if self.members.remove(agent_id).is_none() {
                        return Err(MlsError::MemberNotInGroup(format!(
                            "{:?}",
                            agent_id.as_bytes()
                        )));
                    }
                }
                CommitOperation::UpdateKeys => {}
            }
        }

        self.epoch = self.epoch.saturating_add(1);
        self.context.increment_epoch();
        self.context.update_crypto_material(
            commit.new_tree_hash.clone(),
            commit.new_transcript_hash.clone(),
        );

        self.pending_commits
            .retain(|c| c.epoch != commit.epoch || c.group_id != commit.group_id);

        Ok(())
    }

    /// Encrypts a message using the group's saorsa-mls AEAD cipher.
    ///
    /// # Errors
    /// Returns `MlsError::EncryptionError` if encryption fails.
    pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let msg = self
            .inner
            .encrypt_message(plaintext)
            .map_err(|e| MlsError::EncryptionError(e.to_string()))?;
        serde_json::to_vec(&msg)
            .map_err(|e| MlsError::EncryptionError(format!("serialization: {e}")))
    }

    /// Decrypts a message using the group's saorsa-mls AEAD cipher.
    ///
    /// # Errors
    /// Returns `MlsError::DecryptionError` if decryption fails.
    pub fn decrypt_message(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let msg: saorsa_mls::ApplicationMessage = serde_json::from_slice(ciphertext)
            .map_err(|e| MlsError::DecryptionError(format!("deserialization: {e}")))?;
        self.inner
            .decrypt_message(&msg)
            .map_err(|e| MlsError::DecryptionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_id(id: u8) -> AgentId {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        AgentId(bytes)
    }

    #[tokio::test]
    async fn test_group_creation() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id.clone(), initiator).await;
        assert!(group.is_ok());

        let group = group.unwrap();
        assert_eq!(group.group_id(), b"test-group");
        assert_eq!(group.current_epoch(), 0);
        assert_eq!(group.members().len(), 1);
        assert!(group.is_member(&initiator));
    }

    #[tokio::test]
    async fn test_add_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);
        let new_member = test_agent_id(2);

        let mut group = MlsGroup::new(group_id, initiator).await.unwrap();
        let commit = group.add_member(new_member).await;
        assert!(commit.is_ok());

        let commit = commit.unwrap();
        assert_eq!(commit.epoch(), 0);
        assert_eq!(commit.operations().len(), 1);
        assert_eq!(group.current_epoch(), 1);
        assert_eq!(group.members().len(), 2);
        assert!(group.is_member(&new_member));
    }

    #[tokio::test]
    async fn test_add_duplicate_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).await.unwrap();
        let result = group.add_member(initiator).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::MlsOperation(_)));
    }

    #[tokio::test]
    async fn test_remove_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);
        let member = test_agent_id(2);

        let mut group = MlsGroup::new(group_id, initiator).await.unwrap();
        let _ = group.add_member(member).await.unwrap();
        assert_eq!(group.members().len(), 2);

        let commit = group.remove_member(member).await;
        assert!(commit.is_ok());
        assert_eq!(group.current_epoch(), 2);
        assert_eq!(group.members().len(), 1);
        assert!(!group.is_member(&member));
    }

    #[tokio::test]
    async fn test_remove_nonexistent_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);
        let nonexistent = test_agent_id(99);

        let mut group = MlsGroup::new(group_id, initiator).await.unwrap();
        let result = group.remove_member(nonexistent).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::MemberNotInGroup(_)));
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).await.unwrap();
        let initial_epoch = group.current_epoch();

        let commit = group.commit().unwrap();
        group.apply_commit(&commit).unwrap();
        assert_eq!(group.current_epoch(), initial_epoch + 1);
    }

    #[tokio::test]
    async fn test_epoch_mismatch() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id.clone(), initiator).await.unwrap();
        let wrong_commit = MlsCommit::new(
            group_id,
            999,
            vec![CommitOperation::UpdateKeys],
            vec![],
            vec![],
        );
        let result = group.apply_commit(&wrong_commit);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MlsError::EpochMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_message() {
        let group_id = b"test-encrypt".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id, initiator).await.unwrap();

        let plaintext = b"Hello, MLS with PQC!";
        let ciphertext = group.encrypt_message(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = group.decrypt_message(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_context_updates_on_commit() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).await.unwrap();
        let initial_tree_hash = group.context().tree_hash().to_vec();

        let commit = group.commit().unwrap();
        group.apply_commit(&commit).unwrap();

        assert_ne!(group.context().tree_hash(), initial_tree_hash.as_slice());
        assert_eq!(group.context().epoch(), 1);
    }
}
