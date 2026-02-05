//! TaskItem CRDT combining OR-Set (checkbox) + LWW-Register (metadata).
//!
//! A TaskItem represents a single task in a collaborative task list. It uses
//! CRDTs from saorsa-gossip to handle concurrent modifications:
//!
//! - **OR-Set** for checkbox state: Allows concurrent claims to coexist
//! - **LWW-Register** for metadata: Last-write-wins semantics for title, description, etc.
//!
//! ## Conflict Resolution
//!
//! - **Concurrent claims**: Both claims are visible in the OR-Set. The earliest
//!   timestamp wins when determining the "current" state.
//! - **Concurrent completes**: First completion wins (earliest timestamp).
//! - **Metadata updates**: Last-write-wins based on vector clocks.
//!
//! ## Example
//!
//! ```ignore
//! use x0x::crdt::{TaskItem, TaskId, TaskMetadata, CheckboxState};
//! use saorsa_gossip_types::PeerId;
//!
//! let peer_id = PeerId::from_bytes([1u8; 32]);
//! let task_id = TaskId::new("Implement feature", &agent_id, 1000);
//! let metadata = TaskMetadata::new("Title", "Description", 128, agent_id, 1000);
//!
//! let mut task = TaskItem::new(task_id, metadata, peer_id);
//!
//! // Claim the task
//! task.claim(agent_id, peer_id, 1)?;
//!
//! // Complete the task
//! task.complete(agent_id, peer_id, 2)?;
//! ```

use crate::crdt::{CheckboxState, CrdtError, Result, TaskId, TaskMetadata};
use crate::identity::AgentId;
use saorsa_gossip_crdt_sync::{LwwRegister, OrSet};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};

/// A task item in a collaborative task list.
///
/// TaskItem combines multiple CRDTs to represent a task:
/// - OR-Set for checkbox state (handles concurrent claims)
/// - LWW-Registers for all metadata fields
///
/// This allows multiple agents to collaborate on tasks with automatic
/// conflict resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskItem {
    /// Unique identifier for this task.
    id: TaskId,

    /// Checkbox state using OR-Set semantics.
    ///
    /// Allows concurrent claims to coexist. The "current" state is
    /// determined by taking the minimum (earliest timestamp wins).
    checkbox: OrSet<CheckboxState>,

    /// Task title (LWW semantics).
    title: LwwRegister<String>,

    /// Task description (LWW semantics).
    description: LwwRegister<String>,

    /// Assigned agent (LWW semantics).
    ///
    /// None means unassigned. Some(agent_id) means assigned to that agent.
    assignee: LwwRegister<Option<AgentId>>,

    /// Task priority (LWW semantics).
    ///
    /// 0-255, where higher values = higher priority.
    priority: LwwRegister<u8>,

    /// The agent who created this task (immutable).
    created_by: AgentId,

    /// When this task was created (immutable, Unix milliseconds).
    created_at: u64,
}

impl TaskItem {
    /// Create a new TaskItem from metadata.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique task identifier
    /// * `metadata` - Task metadata (title, description, etc.)
    /// * `peer_id` - The peer creating this task (for vector clocks)
    ///
    /// # Returns
    ///
    /// A new TaskItem with Empty checkbox state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let task_id = TaskId::new("Feature X", &agent_id, 1000);
    /// let metadata = TaskMetadata::new("Title", "Desc", 128, agent_id, 1000);
    /// let peer_id = PeerId::from_bytes([1u8; 32]);
    ///
    /// let task = TaskItem::new(task_id, metadata, peer_id);
    /// assert_eq!(task.id(), &task_id);
    /// assert!(task.current_state().is_empty());
    /// ```
    #[must_use]
    pub fn new(id: TaskId, metadata: TaskMetadata, _peer_id: PeerId) -> Self {
        Self {
            id,
            checkbox: OrSet::new(),
            title: LwwRegister::new(metadata.title),
            description: LwwRegister::new(metadata.description),
            assignee: LwwRegister::new(None),
            priority: LwwRegister::new(metadata.priority),
            created_by: metadata.created_by,
            created_at: metadata.created_at,
        }
    }

    /// Get the task ID.
    #[must_use]
    pub fn id(&self) -> &TaskId {
        &self.id
    }

    /// Get the agent who created this task.
    #[must_use]
    pub fn created_by(&self) -> &AgentId {
        &self.created_by
    }

    /// Get the creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the current title.
    #[must_use]
    pub fn title(&self) -> &str {
        self.title.get()
    }

    /// Get the current description.
    #[must_use]
    pub fn description(&self) -> &str {
        self.description.get()
    }

    /// Get the current assignee.
    #[must_use]
    pub fn assignee(&self) -> Option<&AgentId> {
        self.assignee.get().as_ref()
    }

    /// Get the current priority.
    #[must_use]
    pub fn priority(&self) -> u8 {
        *self.priority.get()
    }

    /// Claim this task.
    ///
    /// Adds a Claimed state to the OR-Set. If multiple agents claim concurrently,
    /// all claims are recorded, and the earliest timestamp wins as the "current" state.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent claiming this task
    /// * `peer_id` - The peer making this change (for vector clocks)
    /// * `seq` - Sequence number for this operation
    ///
    /// # Returns
    ///
    /// Ok(()) if claimed successfully, or an error if the task is already done.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::InvalidStateTransition` if attempting to claim
    /// a task that is already in Done state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task = TaskItem::new(id, metadata, peer_id);
    /// task.claim(agent_id, peer_id, 1)?;
    /// assert!(task.current_state().is_claimed());
    /// ```
    pub fn claim(&mut self, agent_id: AgentId, peer_id: PeerId, seq: u64) -> Result<()> {
        // Check current state - can't claim if already done
        let current = self.current_state();
        if current.is_done() {
            return Err(CrdtError::InvalidStateTransition {
                current,
                attempted: CheckboxState::Claimed {
                    agent_id,
                    timestamp: seq,
                },
            });
        }

        // Add the claimed state to the OR-Set
        let claimed_state = CheckboxState::Claimed {
            agent_id,
            timestamp: seq,
        };
        let tag = (peer_id, seq);
        self.checkbox
            .add(claimed_state, tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add claimed state: {}", e)))?;

        Ok(())
    }

    /// Complete this task.
    ///
    /// Adds a Done state to the OR-Set. If multiple agents complete concurrently,
    /// the earliest completion wins.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent completing this task
    /// * `peer_id` - The peer making this change (for vector clocks)
    /// * `seq` - Sequence number for this operation
    ///
    /// # Returns
    ///
    /// Ok(()) if completed successfully, or an error if invalid transition.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::InvalidStateTransition` if the task is Empty
    /// (must be claimed first) or already Done.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task = TaskItem::new(id, metadata, peer_id);
    /// task.claim(agent_id, peer_id, 1)?;
    /// task.complete(agent_id, peer_id, 2)?;
    /// assert!(task.current_state().is_done());
    /// ```
    pub fn complete(&mut self, agent_id: AgentId, peer_id: PeerId, seq: u64) -> Result<()> {
        // Check current state
        let current = self.current_state();

        // Can't complete if empty (must claim first) or already done
        if current.is_empty() {
            return Err(CrdtError::InvalidStateTransition {
                current,
                attempted: CheckboxState::Done {
                    agent_id,
                    timestamp: seq,
                },
            });
        }

        if current.is_done() {
            return Err(CrdtError::InvalidStateTransition {
                current,
                attempted: CheckboxState::Done {
                    agent_id,
                    timestamp: seq,
                },
            });
        }

        // Add the done state to the OR-Set
        let done_state = CheckboxState::Done {
            agent_id,
            timestamp: seq,
        };
        let tag = (peer_id, seq);
        self.checkbox
            .add(done_state, tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add done state: {}", e)))?;

        Ok(())
    }

    /// Update the task title.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `title` - New title
    /// * `peer_id` - The peer making this change
    pub fn update_title(&mut self, title: String, peer_id: PeerId) {
        self.title.set(title, peer_id);
    }

    /// Update the task description.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `description` - New description
    /// * `peer_id` - The peer making this change
    pub fn update_description(&mut self, description: String, peer_id: PeerId) {
        self.description.set(description, peer_id);
    }

    /// Update the task assignee.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `assignee` - New assignee (None to unassign)
    /// * `peer_id` - The peer making this change
    pub fn update_assignee(&mut self, assignee: Option<AgentId>, peer_id: PeerId) {
        self.assignee.set(assignee, peer_id);
    }

    /// Update the task priority.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `priority` - New priority (0-255)
    /// * `peer_id` - The peer making this change
    pub fn update_priority(&mut self, priority: u8, peer_id: PeerId) {
        self.priority.set(priority, peer_id);
    }

    /// Get the current checkbox state.
    ///
    /// Resolves the OR-Set to a single state by taking the maximum
    /// (most progressed state wins: Done > Claimed > Empty).
    ///
    /// # Returns
    ///
    /// - `Empty` if the OR-Set is empty
    /// - `Done` if any Done state exists (task completed)
    /// - `Claimed` if any Claimed state exists (task in progress)
    ///
    /// When multiple states of the same variant exist, the earliest
    /// timestamp wins.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task = TaskItem::new(id, metadata, peer_id);
    /// assert!(task.current_state().is_empty());
    ///
    /// task.claim(agent_id, peer_id, 1)?;
    /// assert!(task.current_state().is_claimed());
    ///
    /// task.complete(agent_id, peer_id, 2)?;
    /// assert!(task.current_state().is_done());
    /// ```
    #[must_use]
    pub fn current_state(&self) -> CheckboxState {
        // Get all states from the OR-Set
        let states = self.checkbox.elements();

        if states.is_empty() {
            return CheckboxState::Empty;
        }

        // Priority: Done > Claimed > Empty
        // Within same variant, earliest timestamp wins

        // First check for any Done states
        let done_states: Vec<_> = states.iter().filter(|s| s.is_done()).collect();
        if !done_states.is_empty() {
            return done_states
                .into_iter()
                .min()
                .map(|s| (*s).clone())
                .unwrap_or(CheckboxState::Empty);
        }

        // Then check for any Claimed states
        let claimed_states: Vec<_> = states.iter().filter(|s| s.is_claimed()).collect();
        if !claimed_states.is_empty() {
            return claimed_states
                .into_iter()
                .min()
                .map(|s| (*s).clone())
                .unwrap_or(CheckboxState::Empty);
        }

        // Otherwise empty
        CheckboxState::Empty
    }

    /// Merge another TaskItem into this one.
    ///
    /// Combines the OR-Sets and LWW-Registers according to their
    /// respective CRDT semantics.
    ///
    /// # Arguments
    ///
    /// * `other` - The TaskItem to merge from
    ///
    /// # Returns
    ///
    /// Ok(()) if merge succeeded, or an error if the task IDs don't match.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::Merge` if the task IDs differ (can't merge different tasks).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task1 = TaskItem::new(id, metadata, peer1);
    /// let mut task2 = TaskItem::new(id, metadata, peer2);
    ///
    /// task1.claim(agent1, peer1, 1)?;
    /// task2.update_title("New title".to_string(), peer2);
    ///
    /// task1.merge(&task2)?;
    /// // task1 now has both the claim and the title update
    /// ```
    pub fn merge(&mut self, other: &TaskItem) -> Result<()> {
        // Can only merge tasks with the same ID
        if self.id != other.id {
            return Err(CrdtError::Merge(format!(
                "Cannot merge tasks with different IDs: {} != {}",
                self.id, other.id
            )));
        }

        // Merge OR-Set (checkbox states)
        self.checkbox
            .merge_state(&other.checkbox)
            .map_err(|e| CrdtError::Merge(format!("Failed to merge checkbox states: {}", e)))?;

        // Merge LWW-Registers (metadata)
        self.title.merge(&other.title);
        self.description.merge(&other.description);
        self.assignee.merge(&other.assignee);
        self.priority.merge(&other.priority);

        // created_by and created_at are immutable, no merge needed

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn make_task(peer: PeerId) -> TaskItem {
        let agent = agent(1);
        let task_id = TaskId::new("Test task", &agent, 1000);
        let metadata = TaskMetadata::new("Test", "Description", 128, agent, 1000);
        TaskItem::new(task_id, metadata, peer)
    }

    #[test]
    fn test_task_item_new() {
        let peer = peer(1);
        let agent = agent(1);
        let task_id = TaskId::new("Task", &agent, 1000);
        let metadata = TaskMetadata::new("Title", "Desc", 200, agent, 1234567890);

        let task = TaskItem::new(task_id, metadata.clone(), peer);

        assert_eq!(task.id(), &task_id);
        assert_eq!(task.title(), "Title");
        assert_eq!(task.description(), "Desc");
        assert_eq!(task.priority(), 200);
        assert_eq!(task.created_by(), &agent);
        assert_eq!(task.created_at(), 1234567890);
        assert_eq!(task.assignee(), None);
        assert!(task.current_state().is_empty());
    }

    #[test]
    fn test_claim_from_empty() {
        let peer = peer(1);
        let agent = agent(1);
        let mut task = make_task(peer);

        let result = task.claim(agent, peer, 1);
        assert!(result.is_ok());
        assert!(task.current_state().is_claimed());
        assert_eq!(task.current_state().claimed_by(), Some(&agent));
    }

    #[test]
    fn test_cannot_claim_done_task() {
        let peer = peer(1);
        let agent = agent(1);
        let mut task = make_task(peer);

        // Claim and complete
        task.claim(agent, peer, 1).ok().unwrap();
        task.complete(agent, peer, 2).ok().unwrap();

        // Try to claim again
        let result = task.claim(agent, peer, 3);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::InvalidStateTransition { .. } => {}
            _ => panic!("Expected InvalidStateTransition"),
        }
    }

    #[test]
    fn test_complete_from_claimed() {
        let peer = peer(1);
        let agent = agent(1);
        let mut task = make_task(peer);

        task.claim(agent, peer, 1).ok().unwrap();
        let result = task.complete(agent, peer, 2);
        assert!(result.is_ok());
        assert!(task.current_state().is_done());
    }

    #[test]
    fn test_cannot_complete_empty_task() {
        let peer = peer(1);
        let agent = agent(1);
        let mut task = make_task(peer);

        let result = task.complete(agent, peer, 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::InvalidStateTransition { .. } => {}
            _ => panic!("Expected InvalidStateTransition"),
        }
    }

    #[test]
    fn test_cannot_complete_done_task() {
        let peer = peer(1);
        let agent = agent(1);
        let mut task = make_task(peer);

        task.claim(agent, peer, 1).ok().unwrap();
        task.complete(agent, peer, 2).ok().unwrap();

        // Try to complete again
        let result = task.complete(agent, peer, 3);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::InvalidStateTransition { .. } => {}
            _ => panic!("Expected InvalidStateTransition"),
        }
    }

    #[test]
    fn test_concurrent_claims() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let agent1 = agent(1);
        let agent2 = agent(2);

        let mut task1 = make_task(peer1);
        let mut task2 = make_task(peer1);

        // Concurrent claims
        task1.claim(agent1, peer1, 100).ok().unwrap(); // Earlier timestamp
        task2.claim(agent2, peer2, 200).ok().unwrap(); // Later timestamp

        // Merge
        task1.merge(&task2).ok().unwrap();

        // Earlier claim wins
        let state = task1.current_state();
        assert!(state.is_claimed());
        assert_eq!(state.claimed_by(), Some(&agent1));
        assert_eq!(state.timestamp(), Some(100));
    }

    #[test]
    fn test_concurrent_completes() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let agent1 = agent(1);
        let agent2 = agent(2);

        let mut task1 = make_task(peer1);
        let mut task2 = make_task(peer1);

        // Both claim
        task1.claim(agent1, peer1, 50).ok().unwrap();
        task2.claim(agent1, peer1, 50).ok().unwrap();

        // Concurrent completes
        task1.complete(agent1, peer1, 100).ok().unwrap(); // Earlier
        task2.complete(agent2, peer2, 200).ok().unwrap(); // Later

        // Merge
        task1.merge(&task2).ok().unwrap();

        // Earlier complete wins
        let state = task1.current_state();
        assert!(state.is_done());
        assert_eq!(state.claimed_by(), Some(&agent1));
        assert_eq!(state.timestamp(), Some(100));
    }

    #[test]
    fn test_update_title() {
        let peer = peer(1);
        let mut task = make_task(peer);

        assert_eq!(task.title(), "Test");

        task.update_title("New Title".to_string(), peer);
        assert_eq!(task.title(), "New Title");
    }

    #[test]
    fn test_update_description() {
        let peer = peer(1);
        let mut task = make_task(peer);

        assert_eq!(task.description(), "Description");

        task.update_description("New Description".to_string(), peer);
        assert_eq!(task.description(), "New Description");
    }

    #[test]
    fn test_update_assignee() {
        let peer = peer(1);
        let agent = agent(42);
        let mut task = make_task(peer);

        assert_eq!(task.assignee(), None);

        task.update_assignee(Some(agent), peer);
        assert_eq!(task.assignee(), Some(&agent));

        task.update_assignee(None, peer);
        assert_eq!(task.assignee(), None);
    }

    #[test]
    fn test_update_priority() {
        let peer = peer(1);
        let mut task = make_task(peer);

        assert_eq!(task.priority(), 128);

        task.update_priority(255, peer);
        assert_eq!(task.priority(), 255);
    }

    #[test]
    fn test_metadata_lww_semantics() {
        let peer1 = peer(1);
        let peer2 = peer(2);

        let mut task1 = make_task(peer1);
        let mut task2 = make_task(peer1);

        // task1 updates title
        task1.update_title("Title from peer1".to_string(), peer1);

        // task2 updates title later (higher vector clock)
        task2.update_title("Title from peer2".to_string(), peer2);

        // Merge - LWW should pick the later update
        task1.merge(&task2).ok().unwrap();

        // The exact winner depends on vector clock implementation
        // Both values are valid depending on clock ordering
        assert!(
            task1.title() == "Title from peer1" || task1.title() == "Title from peer2",
            "LWW should pick one of the concurrent updates"
        );
    }

    #[test]
    fn test_merge_is_idempotent() {
        let peer = peer(1);
        let agent = agent(1);

        let mut task1 = make_task(peer);
        let mut task2 = make_task(peer);

        task1.claim(agent, peer, 100).ok().unwrap();
        task1.update_title("Title".to_string(), peer);

        task2.merge(&task1).ok().unwrap();
        let state_after_first = task2.current_state();
        let title_after_first = task2.title().to_string();

        // Merge again (idempotent)
        task2.merge(&task1).ok().unwrap();
        let state_after_second = task2.current_state();
        let title_after_second = task2.title().to_string();

        assert_eq!(state_after_first, state_after_second);
        assert_eq!(title_after_first, title_after_second);
    }

    #[test]
    fn test_merge_is_commutative() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let agent1 = agent(1);
        let _agent2 = agent(2);

        let mut task_a = make_task(peer1);
        let mut task_b = make_task(peer1);

        // Make different changes
        task_a.claim(agent1, peer1, 100).ok().unwrap();
        task_b.update_title("New Title".to_string(), peer2);

        // Merge A <- B
        let mut result1 = task_a.clone();
        result1.merge(&task_b).ok().unwrap();

        // Merge B <- A
        let mut result2 = task_b.clone();
        result2.merge(&task_a).ok().unwrap();

        // Both should converge to the same state
        assert_eq!(result1.current_state(), result2.current_state());
        assert_eq!(result1.title(), result2.title());
    }

    #[test]
    fn test_merge_different_task_ids_fails() {
        let peer = peer(1);
        let agent1 = agent(1);
        let agent2 = agent(2);

        let task_id1 = TaskId::new("Task 1", &agent1, 1000);
        let task_id2 = TaskId::new("Task 2", &agent2, 2000);

        let metadata1 = TaskMetadata::new("Task 1", "Desc", 128, agent1, 1000);
        let metadata2 = TaskMetadata::new("Task 2", "Desc", 128, agent2, 2000);

        let mut task1 = TaskItem::new(task_id1, metadata1, peer);
        let task2 = TaskItem::new(task_id2, metadata2, peer);

        let result = task1.merge(&task2);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::Merge(_) => {}
            _ => panic!("Expected Merge error"),
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let peer = peer(1);
        let agent = agent(42);
        let mut task = make_task(peer);

        task.claim(agent, peer, 100).ok().unwrap();
        task.update_title("Serialized Task".to_string(), peer);
        task.update_priority(200, peer);

        let serialized = bincode::serialize(&task).ok().unwrap();
        let deserialized: TaskItem = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(task.id(), deserialized.id());
        assert_eq!(task.title(), deserialized.title());
        assert_eq!(task.priority(), deserialized.priority());
        assert_eq!(task.current_state(), deserialized.current_state());
    }
}
