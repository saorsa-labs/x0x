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
use saorsa_gossip_crdt_sync::{DeltaCrdt, LwwRegister};
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

    /// Update to task ordering, carried as the full LWW register (value +
    /// vector clock) so the receiver resolves it by causality rather than
    /// adopting it unconditionally.
    pub ordering_update: Option<LwwRegister<Vec<TaskId>>>,

    /// Update to list name, carried as the full LWW register (value + vector
    /// clock) so the receiver resolves it by causality.
    pub name_update: Option<LwwRegister<String>>,

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

    /// Create a delta for a single add_task operation.
    #[must_use]
    pub fn for_add(task_id: TaskId, task: TaskItem, tag: UniqueTag, version: u64) -> Self {
        let mut delta = Self::new(version);
        delta.added_tasks.insert(task_id, (task, tag));
        delta
    }

    /// Create a delta for a state change (claim or complete).
    ///
    /// Includes the full TaskItem so receivers can upsert if they
    /// haven't received the add delta yet (out-of-order delivery).
    #[must_use]
    pub fn for_state_change(task_id: TaskId, full_task: TaskItem, version: u64) -> Self {
        let mut delta = Self::new(version);
        delta.task_updates.insert(task_id, full_task);
        delta
    }

    /// Create a delta for a reorder operation.
    ///
    /// Takes the post-reorder ordering register (with its vector clock) so the
    /// change merges by causality on the receiver.
    #[must_use]
    pub fn for_reorder(order_register: LwwRegister<Vec<TaskId>>, version: u64) -> Self {
        let mut delta = Self::new(version);
        delta.ordering_update = Some(order_register);
        delta
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
        self.current_version()
    }

    /// Generate a delta containing the task list's entire current state.
    ///
    /// Mirrors `KvStore::full_delta`: every active task is emitted as an
    /// "added" entry plus the current ordering and name. Receivers apply it
    /// with `merge_delta`, whose upsert/LWW semantics make a full snapshot a
    /// safe superset of any incremental change — this is the producer used to
    /// answer cold-start state requests (see `TaskListSync`). The OR-Set tags
    /// are synthetic because the receiver re-derives membership on merge.
    #[must_use]
    pub fn full_delta(&self) -> TaskListDelta {
        let mut delta = TaskListDelta::new(self.version());

        let ordered = self.tasks_ordered();
        for task in &ordered {
            let task_id = *task.id();
            let tag = (PeerId::new([0u8; 32]), 0);
            delta.added_tasks.insert(task_id, ((*task).clone(), tag));
        }

        // Carry the registers themselves (value + clock) so a cold-start
        // snapshot merges by causality and cannot clobber a newer local
        // ordering/name on an already-populated peer.
        delta.ordering_update = Some(self.ordering_register().clone());
        delta.name_update = Some(self.name_register().clone());

        delta
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

        // Apply task updates (upsert: merge if exists, insert if missing).
        // The upsert is critical for out-of-order delivery — a claim/complete
        // delta may arrive before the corresponding add delta. Since the
        // TaskItem in task_updates contains full state, inserting it directly
        // is safe and preserves the state change.
        for (task_id, updated_task) in &delta.task_updates {
            if let Some(existing_task) = self.get_task_mut(task_id) {
                existing_task.merge(updated_task)?;
            } else {
                // Task not yet known — insert it with a synthetic OR-Set add.
                // Use the peer_id from the delta sender and seq=0 (the OR-Set
                // tag just needs to exist; uniqueness is already guaranteed by
                // the sender's monotonic counter).
                self.add_task(updated_task.clone(), peer_id, 0)?;
            }
        }

        // Apply ordering update via LWW (vector-clock) merge. The merged
        // ordering may reference task IDs not yet present (out-of-order
        // delivery); tasks_ordered filters those at read time.
        if let Some(ref order_register) = delta.ordering_update {
            self.merge_ordering(order_register);
        }

        // Apply name update via LWW (vector-clock) merge.
        if let Some(ref name_register) = delta.name_update {
            self.merge_name(name_register);
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
            .map_err(|e| anyhow::anyhow!("Failed to merge delta: {}", e))
    }

    fn delta(&self, since_version: u64) -> Option<Self::Delta> {
        // A full-state delta is a sound conservative answer to "changes since
        // version N": merge_delta is idempotent and LWW/upsert-based, so the
        // receiver converges regardless of how much extra state we include.
        if since_version >= self.version() {
            None
        } else {
            Some(self.full_delta())
        }
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
            format!("Task {}", id_byte),
            format!("Description {}", id_byte),
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

        // A full-state delta carries every active task.
        let delta = list.full_delta();
        assert!(!delta.is_empty());
        assert!(!delta.added_tasks.is_empty());
    }

    #[test]
    fn test_delta_no_changes() {
        let peer = peer(1);
        let id = list_id(1);
        let list = TaskList::new(id, "Test".to_string(), peer);

        let current_version = list.version();

        // Asking the DeltaCrdt trait for changes since the current version
        // yields nothing.
        let delta = DeltaCrdt::delta(&list, current_version);
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

        // Generate a full-state delta from list2
        let delta = list2.full_delta();

        // Merge delta into list1
        let result = list1.merge_delta(&delta, peer1);
        assert!(result.is_ok());

        // list1 should now have the task
        assert_eq!(list1.task_count(), 1);
    }

    #[test]
    fn full_delta_lets_a_late_joiner_converge() {
        // WHY: a peer that subscribes after tasks were already added has no
        // organic deltas to replay. The cold-start path (TaskListSync's
        // StateRequest) answers with `full_delta()`; merging it must reproduce
        // the holder's complete state — every task, the ordering, and the name
        // — or a late joiner would converge to a partial list.
        let holder_peer = peer(1);
        let joiner_peer = peer(2);
        let id = list_id(1);

        let mut holder = TaskList::new(id, "Sprint".to_string(), holder_peer);
        let t1 = make_task(1, holder_peer);
        let t2 = make_task(2, holder_peer);
        let t3 = make_task(3, holder_peer);
        let (id1, id2, id3) = (*t1.id(), *t2.id(), *t3.id());
        holder.add_task(t1, holder_peer, 1).expect("add t1");
        holder.add_task(t2, holder_peer, 2).expect("add t2");
        holder.add_task(t3, holder_peer, 3).expect("add t3");
        holder
            .reorder(vec![id3, id1, id2], holder_peer)
            .expect("reorder");
        holder.update_name("Sprint Backlog".to_string(), holder_peer);

        // Fresh joiner with an empty list applies only the cold-start snapshot.
        let mut joiner = TaskList::new(id, String::new(), joiner_peer);
        let snapshot = holder.full_delta();
        joiner.merge_delta(&snapshot, holder_peer).expect("merge");

        assert_eq!(joiner.task_count(), 3, "all tasks transferred");
        assert_eq!(joiner.name(), "Sprint Backlog", "name transferred");
        let joiner_order: Vec<_> = joiner.tasks_ordered().iter().map(|t| *t.id()).collect();
        let holder_order: Vec<_> = holder.tasks_ordered().iter().map(|t| *t.id()).collect();
        assert_eq!(joiner_order, holder_order, "ordering converged");
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

        // Version reflects all mutations from the merge: add_task + reorder + update_name
        assert!(
            DeltaCrdt::version(&list1) > 0,
            "version should be bumped after merge"
        );
        assert_eq!(list1.task_count(), 1);
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

        // Build an ordering register that causally dominates the local one
        // (a peer that reversed the order on top of the shared history), so
        // the LWW merge adopts it.
        let mut order_register = list.ordering_register().clone();
        order_register.set(vec![id2, id1], peer); // Reversed order, newer clock
        let mut delta = TaskListDelta::new(10);
        delta.ordering_update = Some(order_register);

        // Merge delta
        list.merge_delta(&delta, peer).ok().unwrap();

        // Verify ordering changed
        let tasks = list.tasks_ordered();
        assert_eq!(tasks[0].id(), &id2);
        assert_eq!(tasks[1].id(), &id1);
    }

    #[test]
    fn stale_name_delta_does_not_clobber_newer_local_name() {
        // WHY: a cold-start responder broadcasts its full state on the main
        // topic, reaching established peers. A peer that renamed the list more
        // recently must not have its name reverted by an older holder's
        // snapshot — the register's vector clock decides the winner.
        let local = peer(1);
        let remote = peer(2);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Original".to_string(), local);

        // `remote` renames the list; capture that register as the "stale" one.
        list.update_name("FromRemote".to_string(), remote);
        let stale = list.name_register().clone();

        // `local` then renames on top — causally newer (its clock includes the
        // remote rename), so a later redelivery of the stale register loses.
        list.update_name("Newest".to_string(), local);

        let mut delta = TaskListDelta::new(7);
        delta.name_update = Some(stale);
        list.merge_delta(&delta, remote).ok().unwrap();

        assert_eq!(list.name(), "Newest", "stale name must not clobber newer");
    }

    #[test]
    fn test_merge_delta_with_name_update() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Original".to_string(), peer);

        // A peer renames on top of the shared initial state; its register
        // causally dominates ours, so the LWW merge adopts it.
        let mut other = TaskList::new(id, "Original".to_string(), peer);
        other.update_name("Updated".to_string(), peer);
        let mut delta = TaskListDelta::new(5);
        delta.name_update = Some(other.name_register().clone());

        // Merge delta
        list.merge_delta(&delta, peer).ok().unwrap();

        // Verify name changed
        assert_eq!(list.name(), "Updated");
    }
}
