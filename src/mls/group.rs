//! MLS group management for secure multi-agent communication.
//!
//! This module implements MLS (Messaging Layer Security) group structures for managing
//! encrypted group communications between agents. It handles group membership, epoch
//! management, and commit operations for forward-secure group encryption.

use crate::identity::AgentId;
use crate::mls::{MlsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MLS group context containing cryptographic state.
///
/// The group context represents the shared state of an MLS group at a specific epoch.
/// It includes the group identifier, current epoch, and cryptographic material needed
/// for key derivation and authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupContext {
    /// Unique identifier for this group.
    group_id: Vec<u8>,
    /// Current epoch number (increments with each commit).
    epoch: u64,
    /// Hash of the ratchet tree structure.
    tree_hash: Vec<u8>,
    /// Hash of the confirmed transcript (for authentication).
    confirmed_transcript_hash: Vec<u8>,
}

impl MlsGroupContext {
    /// Creates a new group context for epoch 0.
    ///
    /// # Arguments
    /// * `group_id` - Unique identifier for the group
    ///
    /// # Returns
    /// A new `MlsGroupContext` initialized at epoch 0.
    #[must_use]
    pub fn new(group_id: Vec<u8>) -> Self {
        Self {
            group_id,
            epoch: 0,
            tree_hash: Vec::new(),
            confirmed_transcript_hash: Vec::new(),
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

    /// Increments the epoch (called when a commit is applied).
    fn increment_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Updates cryptographic material (tree hash and transcript).
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
    /// Epoch when this member joined.
    join_epoch: u64,
}

impl MlsMemberInfo {
    /// Creates new member info.
    #[must_use]
    pub fn new(agent_id: AgentId, join_epoch: u64) -> Self {
        Self {
            agent_id,
            join_epoch,
        }
    }

    /// Gets the agent ID.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
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
///
/// Commits are used to modify group membership or rotate keys. Each commit
/// increments the group epoch and updates the cryptographic state.
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
/// The `MlsGroup` tracks membership, handles commits, and manages the group's
/// cryptographic state across epochs. It provides the foundation for end-to-end
/// encrypted group messaging.
#[derive(Debug, Clone)]
pub struct MlsGroup {
    /// Unique identifier for this group.
    group_id: Vec<u8>,
    /// Current cryptographic context.
    context: MlsGroupContext,
    /// Current members of the group.
    members: HashMap<AgentId, MlsMemberInfo>,
    /// Pending commits not yet applied.
    pending_commits: Vec<MlsCommit>,
    /// Current epoch number.
    epoch: u64,
}

impl MlsGroup {
    /// Creates a new MLS group with an initial member.
    ///
    /// # Arguments
    /// * `group_id` - Unique identifier for the group
    /// * `initiator` - Agent ID of the group creator
    ///
    /// # Returns
    /// A new `MlsGroup` with the initiator as the only member at epoch 0.
    ///
    /// # Errors
    /// Currently does not error, but returns `Result` for future extensibility.
    pub fn new(group_id: Vec<u8>, initiator: AgentId) -> Result<Self> {
        let context = MlsGroupContext::new(group_id.clone());
        let mut members = HashMap::new();
        members.insert(initiator, MlsMemberInfo::new(initiator, 0));

        Ok(Self {
            group_id,
            context,
            members,
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
    /// Creates a commit that adds the specified agent to the group. The commit
    /// must be applied via `apply_commit` to take effect.
    ///
    /// # Arguments
    /// * `member` - Agent ID to add to the group
    ///
    /// # Returns
    /// An `MlsCommit` representing the add operation.
    ///
    /// # Errors
    /// Returns `MlsError::MlsOperation` if the member is already in the group.
    pub fn add_member(&mut self, member: AgentId) -> Result<MlsCommit> {
        // Check if already a member
        if self.members.contains_key(&member) {
            return Err(MlsError::MlsOperation(format!(
                "agent {:?} is already a member",
                member.as_bytes()
            )));
        }

        // Create commit with add operation
        let operations = vec![CommitOperation::AddMember(member)];
        let commit = self.create_commit(operations)?;

        // Store as pending
        self.pending_commits.push(commit.clone());

        Ok(commit)
    }

    /// Removes a member from the group.
    ///
    /// Creates a commit that removes the specified agent from the group. The commit
    /// must be applied via `apply_commit` to take effect.
    ///
    /// # Arguments
    /// * `member` - Agent ID to remove from the group
    ///
    /// # Returns
    /// An `MlsCommit` representing the remove operation.
    ///
    /// # Errors
    /// Returns `MlsError::MemberNotInGroup` if the member is not in the group.
    pub fn remove_member(&mut self, member: AgentId) -> Result<MlsCommit> {
        // Check if member exists
        if !self.members.contains_key(&member) {
            return Err(MlsError::MemberNotInGroup(format!(
                "{:?}",
                member.as_bytes()
            )));
        }

        // Create commit with remove operation
        let operations = vec![CommitOperation::RemoveMember(member)];
        let commit = self.create_commit(operations)?;

        // Store as pending
        self.pending_commits.push(commit.clone());

        Ok(commit)
    }

    /// Creates a commit to rotate group keys.
    ///
    /// Key rotation provides forward secrecy by generating new encryption keys.
    /// This should be done periodically or when a member leaves.
    ///
    /// # Returns
    /// An `MlsCommit` representing the key rotation.
    ///
    /// # Errors
    /// Currently does not error, but returns `Result` for future extensibility.
    pub fn commit(&mut self) -> Result<MlsCommit> {
        let operations = vec![CommitOperation::UpdateKeys];
        let commit = self.create_commit(operations)?;
        self.pending_commits.push(commit.clone());
        Ok(commit)
    }

    /// Applies a commit to the group state.
    ///
    /// This processes the commit's operations and updates the group's membership
    /// and cryptographic state. The epoch is incremented.
    ///
    /// # Arguments
    /// * `commit` - The commit to apply
    ///
    /// # Errors
    /// * `MlsError::EpochMismatch` - If commit epoch doesn't match current epoch
    /// * `MlsError::MlsOperation` - If operations are invalid
    pub fn apply_commit(&mut self, commit: &MlsCommit) -> Result<()> {
        // Verify commit is for this group
        if commit.group_id != self.group_id {
            return Err(MlsError::MlsOperation(
                "commit is for a different group".to_string(),
            ));
        }

        // Verify epoch matches
        if commit.epoch != self.epoch {
            return Err(MlsError::EpochMismatch {
                current: self.epoch,
                received: commit.epoch,
            });
        }

        // Apply operations
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
                CommitOperation::UpdateKeys => {
                    // Key rotation doesn't change membership
                }
            }
        }

        // Update epoch and context
        self.epoch = self.epoch.saturating_add(1);
        self.context.increment_epoch();
        self.context.update_crypto_material(
            commit.new_tree_hash.clone(),
            commit.new_transcript_hash.clone(),
        );

        // Remove from pending if it exists
        self.pending_commits
            .retain(|c| c.epoch != commit.epoch || c.group_id != commit.group_id);

        Ok(())
    }

    /// Creates a commit for the given operations.
    ///
    /// This is an internal helper that generates cryptographic material for the commit.
    fn create_commit(&self, operations: Vec<CommitOperation>) -> Result<MlsCommit> {
        // In a real implementation, this would:
        // 1. Compute new ratchet tree
        // 2. Derive new secrets
        // 3. Generate tree hash and transcript hash
        //
        // For now, we use placeholder hashes.
        let new_tree_hash = blake3::hash(b"tree").as_bytes().to_vec();
        let new_transcript_hash = blake3::hash(b"transcript").as_bytes().to_vec();

        Ok(MlsCommit::new(
            self.group_id.clone(),
            self.epoch,
            operations,
            new_tree_hash,
            new_transcript_hash,
        ))
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

    #[test]
    fn test_group_creation() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let group = MlsGroup::new(group_id.clone(), initiator);
        assert!(group.is_ok());

        let group = group.unwrap();
        assert_eq!(group.group_id(), b"test-group");
        assert_eq!(group.current_epoch(), 0);
        assert_eq!(group.members().len(), 1);
        assert!(group.is_member(&initiator));
    }

    #[test]
    fn test_add_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);
        let new_member = test_agent_id(2);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        // Add member
        let commit = group.add_member(new_member);
        assert!(commit.is_ok());

        let commit = commit.unwrap();
        assert_eq!(commit.epoch(), 0);
        assert_eq!(commit.operations().len(), 1);

        // Apply commit
        let result = group.apply_commit(&commit);
        assert!(result.is_ok());

        // Verify member was added
        assert_eq!(group.current_epoch(), 1);
        assert_eq!(group.members().len(), 2);
        assert!(group.is_member(&new_member));
    }

    #[test]
    fn test_add_duplicate_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        // Try to add initiator again
        let result = group.add_member(initiator);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::MlsOperation(_)));
    }

    #[test]
    fn test_remove_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);
        let member = test_agent_id(2);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        // Add and apply
        let commit = group.add_member(member).unwrap();
        group.apply_commit(&commit).unwrap();

        assert_eq!(group.members().len(), 2);

        // Remove member
        let commit = group.remove_member(member);
        assert!(commit.is_ok());

        let commit = commit.unwrap();
        let result = group.apply_commit(&commit);
        assert!(result.is_ok());

        // Verify member was removed
        assert_eq!(group.current_epoch(), 2);
        assert_eq!(group.members().len(), 1);
        assert!(!group.is_member(&member));
    }

    #[test]
    fn test_remove_nonexistent_member() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);
        let nonexistent = test_agent_id(99);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        // Try to remove non-member
        let result = group.remove_member(nonexistent);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlsError::MemberNotInGroup(_)));
    }

    #[test]
    fn test_key_rotation() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        let initial_epoch = group.current_epoch();

        // Commit (key rotation)
        let commit = group.commit();
        assert!(commit.is_ok());

        let commit = commit.unwrap();
        let result = group.apply_commit(&commit);
        assert!(result.is_ok());

        // Verify epoch incremented
        assert_eq!(group.current_epoch(), initial_epoch + 1);
    }

    #[test]
    fn test_epoch_increment_on_commits() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        assert_eq!(group.current_epoch(), 0);

        // Multiple commits should increment epoch
        for i in 1..=3 {
            let commit = group.commit().unwrap();
            group.apply_commit(&commit).unwrap();
            assert_eq!(group.current_epoch(), i);
        }
    }

    #[test]
    fn test_epoch_mismatch() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id.clone(), initiator).unwrap();

        // Create commit for wrong epoch
        let wrong_commit = MlsCommit::new(
            group_id,
            999, // Wrong epoch
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

    #[test]
    fn test_context_updates_on_commit() {
        let group_id = b"test-group".to_vec();
        let initiator = test_agent_id(1);

        let mut group = MlsGroup::new(group_id, initiator).unwrap();

        let initial_tree_hash = group.context().tree_hash().to_vec();

        // Apply commit
        let commit = group.commit().unwrap();
        group.apply_commit(&commit).unwrap();

        // Verify context updated
        assert_ne!(group.context().tree_hash(), initial_tree_hash.as_slice());
        assert_eq!(group.context().epoch(), 1);
    }

    #[test]
    fn test_group_context_accessors() {
        let group_id = b"test-group".to_vec();
        let context = MlsGroupContext::new(group_id.clone());

        assert_eq!(context.group_id(), b"test-group");
        assert_eq!(context.epoch(), 0);
        assert!(context.tree_hash().is_empty());
        assert!(context.confirmed_transcript_hash().is_empty());
    }

    #[test]
    fn test_member_info() {
        let agent = test_agent_id(42);
        let info = MlsMemberInfo::new(agent, 5);

        assert_eq!(info.agent_id(), &agent);
        assert_eq!(info.join_epoch(), 5);
    }

    #[test]
    fn test_commit_accessors() {
        let group_id = b"test".to_vec();
        let operations = vec![CommitOperation::UpdateKeys];
        let tree_hash = vec![1, 2, 3];
        let transcript_hash = vec![4, 5, 6];

        let commit = MlsCommit::new(
            group_id.clone(),
            10,
            operations.clone(),
            tree_hash.clone(),
            transcript_hash.clone(),
        );

        assert_eq!(commit.group_id(), group_id.as_slice());
        assert_eq!(commit.epoch(), 10);
        assert_eq!(commit.operations().len(), 1);
        assert_eq!(commit.new_tree_hash(), tree_hash.as_slice());
        assert_eq!(commit.new_transcript_hash(), transcript_hash.as_slice());
    }
}
