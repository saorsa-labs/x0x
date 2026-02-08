//! Delta-CRDT implementation for bandwidth-efficient TaskList synchronization.
//!
//! This module provides delta-based CRDT operations for TaskList, allowing
//! efficient incremental synchronization between peers.
//!
//! ## Delta Strategy
//!
//! Instead of sending the entire TaskList on every sync, we:
//! 1. Track version numbers for each change
//! 2. Generate deltas containing only changes since a given version
//! 3. Apply deltas incrementally
//!
//! This significantly reduces bandwidth usage in collaborative scenarios.

use crate::crdt::{Result, TaskId, TaskItem, TaskList};
use saorsa_gossip_crdt_sync::DeltaCrdt;
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Unique tag for OR-Set elements: (PeerId, sequence_number)
pub type UniqueTag = (PeerId, u64);

/// Delta representing changes to a TaskList.
///
/// Contains only the changes made since a specific version, enabling
/// bandwidth-efficient synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskListDelta {
    /// Tasks that were added (task_id -> (task, unique_tag))
    pub added_tasks: HashMap<TaskId, (TaskItem, UniqueTag)>,

    /// Tasks that were removed (task_id -> set of tags to remove)
    pub removed_tasks: HashMap<TaskId, HashSet<UniqueTag>>,

    /// Updates to existing tasks (task_id -> full task state)
    ///
    /// Note: For simplicity, we currently send the full TaskItem state.
    /// A future optimization could implement TaskItemDelta for finer-grained updates.
    pub task_updates: HashMap<TaskId, TaskItem>,

    /// Update to task ordering (new_order, timestamp)
    ///
    /// If Some, the ordering changed. The receiver should merge this using LWW semantics.
    pub ordering_update: Option<Vec<TaskId>>,

    /// Update to list name (new_name)
    ///
    /// If Some, the name changed. The receiver should merge this using LWW semantics.
    pub name_update: Option<String>,

    /// Version number of this delta
    pub version: u64,
}

impl TaskListDelta {
    /// Create an empty delta at a given version.
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self {
            added_tasks: HashMap::new(),
            removed_tasks: HashMap::new(),
            task_updates: HashMap::new(),
            ordering_update: None,
            name_update: None,
            version,
        }
    }

    /// Check if this delta is empty (contains no changes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added_tasks.is_empty()
            && self.removed_tasks.is_empty()
            && self.task_updates.is_empty()
            && self.ordering_update.is_none()
            && self.name_update.is_none()
    }
}

/// Extension to TaskList to support delta-based synchronization.
///
/// This implementation adds version tracking and delta generation/merging
/// capabilities to TaskList.
impl TaskList {
    /// Get the current version of this TaskList.
    ///
    /// The version is incremented on each modification. This enables
    /// delta-based synchronization.
    ///
    /// Note: This is a placeholder implementation. A production version
    /// would track the actual version in TaskList's state.
    #[must_use]
    pub fn version(&self) -> u64 {
        // For now, we use the task count as a proxy for version
        // A production implementation would add a version field to TaskList
        self.task_count() as u64
    }

    /// Generate a delta containing changes since a given version.
    ///
    /// Returns None if no changes have occurred since the specified version.
    ///
    /// # Arguments
    ///
    /// * `since_version` - The version to generate delta from
    ///
    /// # Returns
    ///
    /// Some(delta) if there are changes, None otherwise.
    ///
    /// Note: This is a simplified implementation. A production version would
    /// maintain a changelog to generate accurate deltas.
    #[must_use]
    pub fn delta(&self, since_version: u64) -> Option<TaskListDelta> {
        let current_version = self.version();

        // If versions match, no changes
        if since_version >= current_version {
            return None;
        }

        // For simplicity, we generate a full-state delta
        // A production implementation would track actual changes
        let mut delta = TaskListDelta::new(current_version);

        // Add all current tasks as "added"
        // In a real implementation, we'd only include tasks added since the version
        for task in self.tasks_ordered() {
            let task_id = *task.id();
            let tag = (PeerId::new([0u8; 32]), 0); // Placeholder tag
            delta.added_tasks.insert(task_id, (task.clone(), tag));
        }

        // Include current ordering
        delta.ordering_update = Some(self.tasks_ordered().iter().map(|t| *t.id()).collect());

        // Include current name
        delta.name_update = Some(self.name().to_string());

        Some(delta)
    }

    /// Merge a delta into this TaskList.
    ///
    /// Applies the changes from the delta according to CRDT semantics:
    /// - Added tasks are merged using OR-Set semantics
    /// - Removed tasks are tombstoned
    /// - Task updates are merged
    /// - Ordering uses LWW semantics
    /// - Name uses LWW semantics
    ///
    /// # Arguments
    ///
    /// * `delta` - The delta to merge
    ///
    /// # Returns
    ///
    /// Ok(()) if merge succeeded.
    ///
    /// # Errors
    ///
    /// Returns an error if merge operations fail.
    pub fn merge_delta(&mut self, delta: &TaskListDelta, peer_id: PeerId) -> Result<()> {
        // Apply added tasks
        for (task_id, (task, tag)) in &delta.added_tasks {
            // If task doesn't exist, add it
            if self.get_task(task_id).is_none() {
                self.add_task(task.clone(), tag.0, tag.1)?;
            } else {
                // Task exists, merge it
                if let Some(existing_task) = self.get_task_mut(task_id) {
                    existing_task.merge(task)?;
                }
            }
        }

        // Apply removed tasks
        for task_id in delta.removed_tasks.keys() {
            // Attempt to remove (will fail silently if task doesn't exist)
            let _ = self.remove_task(task_id);
        }

        // Apply task updates
        for (task_id, updated_task) in &delta.task_updates {
            if let Some(existing_task) = self.get_task_mut(task_id) {
                existing_task.merge(updated_task)?;
            }
        }

        // Apply ordering update (LWW semantics via merge)
        if let Some(ref new_order) = delta.ordering_update {
            // Validate all task IDs exist before reordering
            let valid_order: Vec<TaskId> = new_order
                .iter()
                .filter(|id| self.get_task(id).is_some())
                .copied()
                .collect();

            if !valid_order.is_empty() {
                let _ = self.reorder(valid_order, peer_id);
            }
        }

        // Apply name update (LWW semantics via merge)
        if let Some(ref new_name) = delta.name_update {
            self.update_name(new_name.clone(), peer_id);
        }

        Ok(())
    }
}

/// Implement DeltaCrdt trait for TaskList.
///
/// This enables TaskList to participate in saorsa-gossip's delta-based
/// synchronization infrastructure.
impl DeltaCrdt for TaskList {
    type Delta = TaskListDelta;

    fn merge(&mut self, delta: &Self::Delta) -> anyhow::Result<()> {
        // Use a default peer_id for the merge
        // In a real implementation, the peer_id would come from the sync context
        let peer_id = PeerId::new([0u8; 32]);
        self.merge_delta(delta, peer_id)
            .map_err(|e| anyhow::anyhow!("Failed to merge delta: {e}"))
    }

    fn delta(&self, since_version: u64) -> Option<Self::Delta> {
        self.delta(since_version)
    }

    fn version(&self) -> u64 {
        self.version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{TaskListId, TaskMetadata};
    use crate::identity::AgentId;

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
            format!("Task {id_byte}"),
            format!("Description {id_byte}"),
            128,
            agent,
            1000,
        );
        TaskItem::new(task_id, metadata, peer)
    }

    #[test]
    fn test_empty_delta() {
        let delta = TaskListDelta::new(1);
        assert!(delta.is_empty());
        assert_eq!(delta.version, 1);
    }

    #[test]
    fn test_delta_with_added_task() {
        let mut delta = TaskListDelta::new(2);
        let peer = peer(1);
        let task = make_task(1, peer);
        let task_id = *task.id();
        let tag = (peer, 1);

        delta.added_tasks.insert(task_id, (task, tag));

        assert!(!delta.is_empty());
        assert_eq!(delta.added_tasks.len(), 1);
    }

    #[test]
    fn test_task_list_version() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Test".to_string(), peer);

        let initial_version = list.version();

        // Add a task
        let task = make_task(1, peer);
        list.add_task(task, peer, 1).ok().unwrap();

        let new_version = list.version();
        assert!(new_version > initial_version);
    }

    #[test]
    fn test_delta_generation() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Test".to_string(), peer);

        // Add a task
        let task = make_task(1, peer);
        list.add_task(task, peer, 1).ok().unwrap();

        // Generate delta from version 0
        let delta = list.delta(0);
        assert!(delta.is_some());

        let delta = delta.unwrap();
        assert!(!delta.is_empty());
        assert!(!delta.added_tasks.is_empty());
    }

    #[test]
    fn test_delta_no_changes() {
        let peer = peer(1);
        let id = list_id(1);
        let list = TaskList::new(id, "Test".to_string(), peer);

        let current_version = list.version();

        // Delta from current version should be None
        let delta = list.delta(current_version);
        assert!(delta.is_none());
    }

    #[test]
    fn test_merge_delta_with_new_task() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List 1".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List 2".to_string(), peer2);

        // list2 adds a task
        let task = make_task(1, peer2);
        list2.add_task(task, peer2, 1).ok().unwrap();

        // Generate delta from list2
        let delta = list2.delta(0).unwrap();

        // Merge delta into list1
        let result = list1.merge_delta(&delta, peer1);
        assert!(result.is_ok());

        // list1 should now have the task
        assert_eq!(list1.task_count(), 1);
    }

    #[test]
    fn test_delta_crdt_trait_merge() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List".to_string(), peer2);

        // list2 adds a task
        let task = make_task(1, peer2);
        list2.add_task(task, peer2, 1).ok().unwrap();

        // Use DeltaCrdt trait
        let delta = DeltaCrdt::delta(&list2, 0).unwrap();
        let result = DeltaCrdt::merge(&mut list1, &delta);
        assert!(result.is_ok());

        assert_eq!(DeltaCrdt::version(&list1), 1);
    }

    #[test]
    fn test_delta_serialization() {
        let delta = TaskListDelta::new(5);

        let serialized = bincode::serialize(&delta).ok().unwrap();
        let deserialized: TaskListDelta = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(delta.version, deserialized.version);
        assert_eq!(delta.is_empty(), deserialized.is_empty());
    }

    #[test]
    fn test_merge_delta_with_ordering_update() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Test".to_string(), peer);

        // Add tasks
        let task1 = make_task(1, peer);
        let task2 = make_task(2, peer);
        let id1 = *task1.id();
        let id2 = *task2.id();

        list.add_task(task1, peer, 1).ok().unwrap();
        list.add_task(task2, peer, 2).ok().unwrap();

        // Create delta with ordering update
        let mut delta = TaskListDelta::new(10);
        delta.ordering_update = Some(vec![id2, id1]); // Reversed order

        // Merge delta
        list.merge_delta(&delta, peer).ok().unwrap();

        // Verify ordering changed
        let tasks = list.tasks_ordered();
        assert_eq!(tasks[0].id(), &id2);
        assert_eq!(tasks[1].id(), &id1);
    }

    #[test]
    fn test_merge_delta_with_name_update() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Original".to_string(), peer);

        // Create delta with name update
        let mut delta = TaskListDelta::new(5);
        delta.name_update = Some("Updated".to_string());

        // Merge delta
        list.merge_delta(&delta, peer).ok().unwrap();

        // Verify name changed
        assert_eq!(list.name(), "Updated");
    }
}
