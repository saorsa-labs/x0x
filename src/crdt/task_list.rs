//! TaskList CRDT for collaborative task management.
//!
//! Implements a distributed task list using:
//! - OR-Set for task membership (adds win over removes)
//! - LWW-Register for task ordering (last write wins)
//! - HashMap for task content storage
//!
//! ## Ordering Strategy
//!
//! Since saorsa-gossip doesn't provide RGA (Replicated Growable Array),
//! we use `LwwRegister<Vec<TaskId>>` for ordering:
//! - On merge, the latest vector clock wins
//! - Tasks in OR-Set but not in ordering vector are appended to the end
//!
//! This provides eventual consistency with deterministic conflict resolution.

use crate::crdt::{CrdtError, Result, TaskId, TaskItem};
use crate::identity::AgentId;
use saorsa_gossip_crdt_sync::{LwwRegister, OrSet};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Task list identifier.
///
/// A 32-byte unique identifier for a task list, typically derived from
/// BLAKE3(list_name || creator || timestamp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskListId([u8; 32]);

impl TaskListId {
    /// Create a new TaskListId from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from content (name, creator, timestamp).
    #[must_use]
    pub fn from_content(name: &str, creator: &AgentId, timestamp: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(name.as_bytes());
        hasher.update(creator.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        let hash = hasher.finalize();
        Self(*hash.as_bytes())
    }
}

impl std::fmt::Display for TaskListId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// A collaborative task list using CRDTs.
///
/// TaskList combines multiple CRDTs to provide a conflict-free task list:
/// - OR-Set for task membership (which tasks exist)
/// - HashMap for task content (the TaskItem CRDTs)
/// - LWW-Register for ordering (task display order)
/// - LWW-Register for metadata (list name)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskList {
    /// Unique identifier for this task list.
    id: TaskListId,

    /// Set of task IDs (OR-Set semantics - adds win).
    tasks: OrSet<TaskId>,

    /// Task content indexed by ID.
    task_data: HashMap<TaskId, TaskItem>,

    /// Task ordering (LWW semantics).
    ///
    /// Contains the ordered list of TaskIds. On merge, the ordering
    /// with the latest vector clock wins. Tasks in the OR-Set but
    /// not in this vector are appended to the end.
    ordering: LwwRegister<Vec<TaskId>>,

    /// List name (LWW semantics).
    name: LwwRegister<String>,
}

impl TaskList {
    /// Create a new empty task list.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this list
    /// * `name` - Human-readable name
    /// * `_peer_id` - Creating peer (for future use)
    ///
    /// # Returns
    ///
    /// A new empty TaskList.
    #[must_use]
    pub fn new(id: TaskListId, name: String, _peer_id: PeerId) -> Self {
        Self {
            id,
            tasks: OrSet::new(),
            task_data: HashMap::new(),
            ordering: LwwRegister::new(Vec::new()),
            name: LwwRegister::new(name),
        }
    }

    /// Get the task list ID.
    #[must_use]
    pub fn id(&self) -> &TaskListId {
        &self.id
    }

    /// Get the current name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.get()
    }

    /// Add a task to the list.
    ///
    /// # Arguments
    ///
    /// * `task` - The task to add
    /// * `peer_id` - The peer making this change
    /// * `seq` - Sequence number for the operation
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the OR-Set operation fails.
    pub fn add_task(&mut self, task: TaskItem, peer_id: PeerId, seq: u64) -> Result<()> {
        let task_id = *task.id();

        // Add to OR-Set
        let tag = (peer_id, seq);
        self.tasks
            .add(task_id, tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add task to OR-Set: {}", e)))?;

        // Store or merge task data
        if let Some(existing) = self.task_data.get_mut(&task_id) {
            // Task already exists - merge CRDT state instead of overwriting
            existing.merge(&task)?;
        } else {
            // New task - insert
            self.task_data.insert(task_id, task);
        }

        // Add to ordering (append to end)
        let mut current_order = self.ordering.get().clone();
        if !current_order.contains(&task_id) {
            current_order.push(task_id);
            self.ordering.set(current_order, peer_id);
        }

        Ok(())
    }

    /// Remove a task from the list.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to remove
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::TaskNotFound` if the task doesn't exist.
    pub fn remove_task(&mut self, task_id: &TaskId) -> Result<()> {
        if !self.task_data.contains_key(task_id) {
            return Err(CrdtError::TaskNotFound(*task_id));
        }

        // Remove from OR-Set (marks as tombstone)
        self.tasks
            .remove(task_id)
            .map_err(|e| CrdtError::Merge(format!("Failed to remove task from OR-Set: {}", e)))?;

        // Remove from task data
        self.task_data.remove(task_id);

        // Note: We don't remove from ordering vector to preserve order of remaining tasks
        // The ordering will be filtered when tasks_ordered() is called

        Ok(())
    }

    /// Claim a task in the list.
    ///
    /// Delegates to the TaskItem's claim method.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to claim
    /// * `agent_id` - Agent claiming the task
    /// * `peer_id` - Peer making this change
    /// * `seq` - Sequence number
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the task doesn't exist or state transition is invalid.
    pub fn claim_task(
        &mut self,
        task_id: &TaskId,
        agent_id: AgentId,
        peer_id: PeerId,
        seq: u64,
    ) -> Result<()> {
        let task = self
            .task_data
            .get_mut(task_id)
            .ok_or(CrdtError::TaskNotFound(*task_id))?;

        task.claim(agent_id, peer_id, seq)
    }

    /// Complete a task in the list.
    ///
    /// Delegates to the TaskItem's complete method.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to complete
    /// * `agent_id` - Agent completing the task
    /// * `peer_id` - Peer making this change
    /// * `seq` - Sequence number
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the task doesn't exist or state transition is invalid.
    pub fn complete_task(
        &mut self,
        task_id: &TaskId,
        agent_id: AgentId,
        peer_id: PeerId,
        seq: u64,
    ) -> Result<()> {
        let task = self
            .task_data
            .get_mut(task_id)
            .ok_or(CrdtError::TaskNotFound(*task_id))?;

        task.complete(agent_id, peer_id, seq)
    }

    /// Reorder the tasks in the list.
    ///
    /// # Arguments
    ///
    /// * `new_order` - New ordering of task IDs
    /// * `peer_id` - Peer making this change
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if any task ID in the new order doesn't exist.
    pub fn reorder(&mut self, new_order: Vec<TaskId>, peer_id: PeerId) -> Result<()> {
        // Validate that all task IDs in the new order exist
        for task_id in &new_order {
            if !self.task_data.contains_key(task_id) {
                return Err(CrdtError::TaskNotFound(*task_id));
            }
        }

        // Update ordering
        self.ordering.set(new_order, peer_id);

        Ok(())
    }

    /// Get tasks in their current order.
    ///
    /// Returns tasks ordered according to the LWW ordering vector.
    /// Tasks in the OR-Set but not in the ordering vector are appended at the end.
    ///
    /// # Returns
    ///
    /// Vector of task references in display order.
    #[must_use]
    pub fn tasks_ordered(&self) -> Vec<&TaskItem> {
        use std::collections::HashSet;

        let current_order = self.ordering.get();
        let or_set_tasks: HashSet<TaskId> = self.tasks.elements().into_iter().copied().collect();

        // Start with tasks in the ordering vector, but only if they're in the OR-Set
        let mut ordered: Vec<&TaskItem> = current_order
            .iter()
            .filter(|id| or_set_tasks.contains(id)) // Filter by OR-Set membership first!
            .filter_map(|id| self.task_data.get(id))
            .collect();

        // Append tasks that are in OR-Set but not in ordering
        for task_id in &or_set_tasks {
            if !current_order.contains(task_id) {
                if let Some(task) = self.task_data.get(task_id) {
                    ordered.push(task);
                }
            }
        }

        ordered
    }

    /// Merge another TaskList into this one.
    ///
    /// Combines OR-Sets, HashMap task data, and LWW registers according to
    /// their respective CRDT semantics.
    ///
    /// # Arguments
    ///
    /// * `other` - The TaskList to merge from
    ///
    /// # Returns
    ///
    /// Ok(()) if merge succeeded.
    ///
    /// # Errors
    ///
    /// Returns an error if the task list IDs don't match.
    pub fn merge(&mut self, other: &TaskList) -> Result<()> {
        // Can only merge lists with the same ID
        if self.id != other.id {
            return Err(CrdtError::Merge(format!(
                "Cannot merge task lists with different IDs: {} != {}",
                self.id, other.id
            )));
        }

        // Merge OR-Set (task membership)
        self.tasks
            .merge_state(&other.tasks)
            .map_err(|e| CrdtError::Merge(format!("Failed to merge task OR-Sets: {}", e)))?;

        // Merge task data (HashMap)
        // For each task in other, either add it or merge it if it exists
        for (task_id, other_task) in &other.task_data {
            if let Some(our_task) = self.task_data.get_mut(task_id) {
                // Merge existing task
                our_task.merge(other_task)?;
            } else {
                // Add new task
                self.task_data.insert(*task_id, other_task.clone());
            }
        }

        // Merge LWW registers (ordering and name)
        self.ordering.merge(&other.ordering);
        self.name.merge(&other.name);

        Ok(())
    }

    /// Update the list name.
    ///
    /// # Arguments
    ///
    /// * `name` - New name
    /// * `peer_id` - Peer making this change
    pub fn update_name(&mut self, name: String, peer_id: PeerId) {
        self.name.set(name, peer_id);
    }

    /// Get the number of tasks in the list.
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.task_data.len()
    }

    /// Get a specific task by ID.
    #[must_use]
    pub fn get_task(&self, task_id: &TaskId) -> Option<&TaskItem> {
        self.task_data.get(task_id)
    }

    /// Get a mutable reference to a specific task.
    pub fn get_task_mut(&mut self, task_id: &TaskId) -> Option<&mut TaskItem> {
        self.task_data.get_mut(task_id)
    }

    /// Encode the task list into persistence payload bytes.
    pub fn to_persistence_payload(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(CrdtError::Serialization)
    }

    /// Decode a task list from persistence payload bytes.
    pub fn from_persistence_payload(payload: &[u8]) -> Result<Self> {
        bincode::deserialize(payload).map_err(CrdtError::Serialization)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::TaskMetadata;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn list_id(n: u8) -> TaskListId {
        TaskListId::new([n; 32])
    }

    fn make_task(id_byte: u8, peer: PeerId) -> TaskItem {
        let agent = agent(1);
        let task_id = TaskId::from_bytes([id_byte; 32]);
        let metadata = TaskMetadata::new(
            format!("Task {}", id_byte),
            format!("Description {}", id_byte),
            128,
            agent,
            1000,
        );
        TaskItem::new(task_id, metadata, peer)
    }

    #[test]
    fn test_task_list_new() {
        let peer = peer(1);
        let id = list_id(1);
        let list = TaskList::new(id, "My List".to_string(), peer);

        assert_eq!(list.id(), &id);
        assert_eq!(list.name(), "My List");
        assert_eq!(list.task_count(), 0);
        assert!(list.tasks_ordered().is_empty());
    }

    #[test]
    fn test_add_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        let result = list.add_task(task, peer, 1);
        assert!(result.is_ok());
        assert_eq!(list.task_count(), 1);

        let tasks = list.tasks_ordered();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id(), &task_id);
    }

    #[test]
    fn test_remove_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        list.add_task(task, peer, 1).ok().unwrap();
        assert_eq!(list.task_count(), 1);

        let result = list.remove_task(&task_id);
        assert!(result.is_ok());
        assert_eq!(list.task_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task_id = TaskId::from_bytes([99; 32]);
        let result = list.remove_task(&task_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::TaskNotFound(_) => {}
            _ => panic!("Expected TaskNotFound"),
        }
    }

    #[test]
    fn test_claim_task() {
        let peer = peer(1);
        let agent = agent(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        list.add_task(task, peer, 1).ok().unwrap();

        let result = list.claim_task(&task_id, agent, peer, 2);
        assert!(result.is_ok());

        let task = list.get_task(&task_id).unwrap();
        assert!(task.current_state().is_claimed());
    }

    #[test]
    fn test_complete_task() {
        let peer = peer(1);
        let agent = agent(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        list.add_task(task, peer, 1).ok().unwrap();
        list.claim_task(&task_id, agent, peer, 2).ok().unwrap();

        let result = list.complete_task(&task_id, agent, peer, 3);
        assert!(result.is_ok());

        let task = list.get_task(&task_id).unwrap();
        assert!(task.current_state().is_done());
    }

    #[test]
    fn test_reorder_tasks() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task1 = make_task(1, peer);
        let task2 = make_task(2, peer);
        let task3 = make_task(3, peer);

        let id1 = *task1.id();
        let id2 = *task2.id();
        let id3 = *task3.id();

        list.add_task(task1, peer, 1).ok().unwrap();
        list.add_task(task2, peer, 2).ok().unwrap();
        list.add_task(task3, peer, 3).ok().unwrap();

        // Initial order: 1, 2, 3
        let tasks = list.tasks_ordered();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0].id(), &id1);
        assert_eq!(tasks[1].id(), &id2);
        assert_eq!(tasks[2].id(), &id3);

        // Reorder to: 3, 1, 2
        let new_order = vec![id3, id1, id2];
        let result = list.reorder(new_order, peer);
        assert!(result.is_ok());

        let tasks = list.tasks_ordered();
        assert_eq!(tasks[0].id(), &id3);
        assert_eq!(tasks[1].id(), &id1);
        assert_eq!(tasks[2].id(), &id2);
    }

    #[test]
    fn test_reorder_with_invalid_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();
        list.add_task(task, peer, 1).ok().unwrap();

        let invalid_id = TaskId::from_bytes([99; 32]);
        let new_order = vec![task_id, invalid_id];

        let result = list.reorder(new_order, peer);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::TaskNotFound(_) => {}
            _ => panic!("Expected TaskNotFound"),
        }
    }

    #[test]
    fn test_merge_task_lists() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List 1".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List 2".to_string(), peer2);

        // list1 adds task1
        let task1 = make_task(1, peer1);
        let id1 = *task1.id();
        list1.add_task(task1, peer1, 1).ok().unwrap();

        // list2 adds task2
        let task2 = make_task(2, peer2);
        let id2 = *task2.id();
        list2.add_task(task2, peer2, 1).ok().unwrap();

        // Merge list2 into list1
        let result = list1.merge(&list2);
        assert!(result.is_ok());

        // list1 should now have both tasks
        assert_eq!(list1.task_count(), 2);
        assert!(list1.get_task(&id1).is_some());
        assert!(list1.get_task(&id2).is_some());
    }

    #[test]
    fn test_merge_with_concurrent_task_modifications() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let agent1 = agent(1);
        let _agent2 = agent(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List".to_string(), peer2);

        // Both add the same task
        let task1 = make_task(1, peer1);
        let task2 = make_task(1, peer2);
        let task_id = *task1.id();

        list1.add_task(task1, peer1, 1).ok().unwrap();
        list2.add_task(task2, peer2, 1).ok().unwrap();

        // list1 claims the task
        list1.claim_task(&task_id, agent1, peer1, 2).ok().unwrap();

        // list2 updates the title
        list2
            .get_task_mut(&task_id)
            .unwrap()
            .update_title("Updated".to_string(), peer2);

        // Merge
        list1.merge(&list2).ok().unwrap();

        // Should have both modifications
        let task = list1.get_task(&task_id).unwrap();
        assert!(task.current_state().is_claimed());
        // Title update depends on vector clock ordering
    }

    #[test]
    fn test_merge_different_list_ids_fails() {
        let peer = peer(1);
        let id1 = list_id(1);
        let id2 = list_id(2);

        let mut list1 = TaskList::new(id1, "List 1".to_string(), peer);
        let list2 = TaskList::new(id2, "List 2".to_string(), peer);

        let result = list1.merge(&list2);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::Merge(_) => {}
            _ => panic!("Expected Merge error"),
        }
    }

    #[test]
    fn test_tasks_ordered_with_removed_tasks() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task1 = make_task(1, peer);
        let task2 = make_task(2, peer);
        let task3 = make_task(3, peer);

        let id1 = *task1.id();
        let id2 = *task2.id();
        let id3 = *task3.id();

        list.add_task(task1, peer, 1).ok().unwrap();
        list.add_task(task2, peer, 2).ok().unwrap();
        list.add_task(task3, peer, 3).ok().unwrap();

        // Remove middle task
        list.remove_task(&id2).ok().unwrap();

        // Should only show task1 and task3
        let tasks = list.tasks_ordered();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].id(), &id1);
        assert_eq!(tasks[1].id(), &id3);
    }

    #[test]
    fn test_update_name() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Original".to_string(), peer);

        assert_eq!(list.name(), "Original");

        list.update_name("Updated".to_string(), peer);
        assert_eq!(list.name(), "Updated");
    }

    #[test]
    fn test_task_list_id_from_content() {
        let agent = agent(1);
        let id1 = TaskListId::from_content("My List", &agent, 1000);
        let id2 = TaskListId::from_content("My List", &agent, 1000);

        assert_eq!(id1, id2); // Deterministic

        let id3 = TaskListId::from_content("Different", &agent, 1000);
        assert_ne!(id1, id3); // Different content
    }

    #[test]
    fn test_task_list_id_display() {
        let id = TaskListId::new([42u8; 32]);
        let display = format!("{}", id);
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        list.add_task(task, peer, 1).ok().unwrap();

        let serialized = bincode::serialize(&list).ok().unwrap();
        let deserialized: TaskList = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(list.id(), deserialized.id());
        assert_eq!(list.name(), deserialized.name());
        assert_eq!(list.task_count(), deserialized.task_count());
    }
}
