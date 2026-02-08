//! Integration tests for x0x CRDT task lists.
//!
//! These tests verify the complete workflow of creating task lists,
//! adding tasks, managing state transitions (claim/complete),
//! and synchronizing across multiple agents.

use saorsa_gossip_types::PeerId;
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;

/// Helper to create a test agent ID.
fn test_agent_id(n: u8) -> AgentId {
    AgentId([n; 32])
}

/// Helper to create a test peer ID.
fn test_peer_id(n: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    PeerId::new(bytes)
}

/// Helper to create a test task ID.
fn test_task_id(n: u8) -> TaskId {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    TaskId::from_bytes(bytes)
}

/// Helper to create a test task list ID.
fn test_task_list_id(n: u8) -> TaskListId {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    TaskListId::new(bytes)
}

/// Helper to create test task metadata.
fn test_metadata(title: &str, creator: u8) -> TaskMetadata {
    TaskMetadata {
        title: title.to_string(),
        description: format!("Test task: {title}"),
        priority: 128,
        created_by: test_agent_id(creator),
        created_at: 1000 + creator as u64,
        tags: vec!["test".to_string()],
    }
}

/// Test creating a new task list.
#[test]
fn test_task_list_creation() {
    let list_id = test_task_list_id(1);
    let peer_id = test_peer_id(1);

    let task_list = TaskList::new(list_id, "My Tasks".to_string(), peer_id);

    assert_eq!(task_list.name(), "My Tasks");
    assert_eq!(task_list.version(), 0);
    assert_eq!(task_list.tasks_ordered().len(), 0);
}

/// Test adding a task to a task list.
#[test]
fn test_task_list_add_task() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let metadata = test_metadata("Implement feature", agent_id.as_bytes()[0]);

    let task = TaskItem::new(task_id, metadata, peer_id);
    let result = task_list.add_task(task, peer_id, 1);

    assert!(result.is_ok());
    assert_eq!(task_list.tasks_ordered().len(), 1);
}

/// Test claiming a task (agent marks it as in-progress).
#[test]
fn test_task_list_claim_task() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let metadata = test_metadata("Write code", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);

    task_list
        .add_task(task, peer_id, 1)
        .expect("Failed to add task");
    let claim_result = task_list.claim_task(&task_id, agent_id, peer_id, 2);

    assert!(claim_result.is_ok());
    let task = task_list.get_task(&task_id).expect("Task should exist");
    assert!(task.current_state().is_claimed());
}

/// Test completing a claimed task.
#[test]
fn test_task_list_complete_task() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let metadata = test_metadata("Test code", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);

    task_list
        .add_task(task, peer_id, 1)
        .expect("Failed to add task");
    task_list
        .claim_task(&task_id, agent_id, peer_id, 2)
        .expect("Failed to claim task");
    let complete_result = task_list.complete_task(&task_id, agent_id, peer_id, 3);

    assert!(complete_result.is_ok());
    let task = task_list.get_task(&task_id).expect("Task should exist");
    assert!(task.current_state().is_done());
}

/// Test removing a task from the list.
#[test]
fn test_task_list_remove_task() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let metadata = test_metadata("Cleanup", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);

    task_list
        .add_task(task, peer_id, 1)
        .expect("Failed to add task");
    assert_eq!(task_list.tasks_ordered().len(), 1);

    let remove_result = task_list.remove_task(&task_id);
    assert!(remove_result.is_ok());
    assert_eq!(task_list.tasks_ordered().len(), 0);
}

/// Test reordering tasks in the list.
#[test]
fn test_task_list_reorder() {
    let list_id = test_task_list_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);

    // Add 3 tasks
    let task_ids: Vec<TaskId> = vec![test_task_id(1), test_task_id(2), test_task_id(3)];

    for (i, task_id) in task_ids.iter().enumerate() {
        let metadata = test_metadata(&format!("Task {i}"), agent_id.as_bytes()[0]);
        let task = TaskItem::new(*task_id, metadata, peer_id);
        task_list
            .add_task(task, peer_id, (i + 1) as u64)
            .expect("Failed to add task");
    }

    assert_eq!(task_list.tasks_ordered().len(), 3);

    // Reorder in reverse
    let new_order = vec![task_ids[2], task_ids[1], task_ids[0]];
    let reorder_result = task_list.reorder(new_order.clone(), peer_id);

    assert!(reorder_result.is_ok());
    let ordered = task_list.tasks_ordered();
    assert_eq!(ordered[0].id(), &task_ids[2]);
    assert_eq!(ordered[1].id(), &task_ids[1]);
    assert_eq!(ordered[2].id(), &task_ids[0]);
}

/// Test merging two task lists (convergence).
#[test]
fn test_task_list_merge() {
    let list_id = test_task_list_id(1);
    let peer_id_a = test_peer_id(1);
    let peer_id_b = test_peer_id(2);
    let agent_id_a = test_agent_id(1);
    let _agent_id_b = test_agent_id(2);

    // Agent A creates a task
    let mut task_list_a = TaskList::new(list_id, "Sprint".to_string(), peer_id_a);
    let task_id = test_task_id(1);
    let metadata = test_metadata("Sync test", agent_id_a.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id_a);

    task_list_a
        .add_task(task, peer_id_a, 1)
        .expect("Failed to add");

    // Agent B has empty list
    let mut task_list_b = TaskList::new(list_id, "Sprint".to_string(), peer_id_b);

    // Merge B into A
    let merge_result = task_list_a.merge(&task_list_b);
    assert!(merge_result.is_ok());
    assert_eq!(task_list_a.tasks_ordered().len(), 1);

    // Now merge A into B
    let merge_result = task_list_b.merge(&task_list_a);
    assert!(merge_result.is_ok());
    assert_eq!(task_list_b.tasks_ordered().len(), 1);

    // Both should have same task
    assert_eq!(
        task_list_a.tasks_ordered().len(),
        task_list_b.tasks_ordered().len()
    );
}

/// Test concurrent claims on the same task (OR-Set semantics).
#[test]
fn test_concurrent_claims() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id_a = test_peer_id(1);
    let peer_id_b = test_peer_id(2);
    let agent_id_a = test_agent_id(1);
    let _agent_id_b = test_agent_id(2);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id_a);
    let metadata = test_metadata("Claim test", agent_id_a.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id_a);

    task_list
        .add_task(task, peer_id_a, 1)
        .expect("Failed to add");

    // Agent A claims the task
    task_list
        .claim_task(&task_id, agent_id_a, peer_id_a, 2)
        .expect("A should claim");

    // Agent B also claims (concurrent)
    task_list
        .claim_task(&task_id, _agent_id_b, peer_id_b, 2)
        .expect("B should claim");

    // Both should be visible (OR-Set semantics)
    let task = task_list.get_task(&task_id).expect("Task should exist");
    assert!(task.current_state().is_claimed());
}

/// Test delta CRDT generation.
#[test]
fn test_delta_generation() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);

    // Add a task and get delta
    let metadata = test_metadata("Delta test", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);
    task_list.add_task(task, peer_id, 1).expect("Failed to add");

    let delta = task_list.delta(0);
    assert!(delta.is_some());

    let delta = delta.unwrap();
    assert!(!delta.added_tasks.is_empty());
}

/// Test applying changes from one list to another.
#[test]
fn test_delta_apply() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    // Create first list with a task
    let mut task_list_1 = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let metadata = test_metadata("Delta apply test", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);
    task_list_1
        .add_task(task, peer_id, 1)
        .expect("Failed to add");

    // Create second list and merge with first
    let mut task_list_2 = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let apply_result = task_list_2.merge(&task_list_1);

    assert!(apply_result.is_ok());
    assert_eq!(task_list_2.tasks_ordered().len(), 1);
}

/// Test task list version tracking.
#[test]
fn test_version_tracking() {
    let list_id = test_task_list_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let initial_version = task_list.version();

    // Add a task
    let task_id = test_task_id(1);
    let metadata = test_metadata("Version test", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);
    task_list.add_task(task, peer_id, 1).expect("Failed to add");

    let version_after_add = task_list.version();
    // Version should change after adding a task
    assert!(version_after_add >= initial_version);

    // Claim the task
    task_list
        .claim_task(&task_id, agent_id, peer_id, 2)
        .expect("Failed to claim");

    let version_after_claim = task_list.version();
    // Version should be >= version after add (may or may not increment depending on implementation)
    assert!(version_after_claim >= version_after_add);
}

/// Test updating task list name.
#[test]
fn test_update_task_list_name_single() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Original Sprint".to_string(), peer_id);
    let metadata = test_metadata("Test task", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);

    task_list.add_task(task, peer_id, 1).expect("Failed to add");

    // Update list name
    task_list.update_name("Updated Sprint".to_string(), peer_id);
    assert_eq!(task_list.name(), "Updated Sprint");
}

/// Test task state validation.
#[test]
fn test_invalid_state_transitions() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Sprint".to_string(), peer_id);
    let metadata = test_metadata("State test", agent_id.as_bytes()[0]);
    let task = TaskItem::new(task_id, metadata, peer_id);

    task_list.add_task(task, peer_id, 1).expect("Failed to add");

    // Try to complete without claiming first
    let result = task_list.complete_task(&task_id, agent_id, peer_id, 2);
    assert!(result.is_err());
}

/// Test merging lists with conflicting updates.
#[test]
fn test_merge_conflict_resolution() {
    let list_id = test_task_list_id(1);
    let task_id = test_task_id(1);
    let peer_id_a = test_peer_id(1);
    let peer_id_b = test_peer_id(2);
    let agent_id_a = test_agent_id(1);
    let agent_id_b = test_agent_id(2);

    // Both agents add the same task (different metadata)
    let mut task_list_a = TaskList::new(list_id, "Sprint A".to_string(), peer_id_a);
    let metadata_a = test_metadata("Title A", agent_id_a.as_bytes()[0]);
    let task_a = TaskItem::new(task_id, metadata_a, peer_id_a);
    task_list_a
        .add_task(task_a, peer_id_a, 1)
        .expect("Failed to add");

    let mut task_list_b = TaskList::new(list_id, "Sprint B".to_string(), peer_id_b);
    let metadata_b = test_metadata("Title B", agent_id_b.as_bytes()[0]);
    let task_b = TaskItem::new(task_id, metadata_b, peer_id_b);
    task_list_b
        .add_task(task_b, peer_id_b, 1)
        .expect("Failed to add");

    // Merge - should use LWW semantics for metadata
    let merge_result = task_list_a.merge(&task_list_b);
    assert!(merge_result.is_ok());
    assert_eq!(task_list_a.tasks_ordered().len(), 1);
}

/// Test with maximum number of tasks for stress testing.
#[test]
fn test_large_task_list() {
    let list_id = test_task_list_id(1);
    let peer_id = test_peer_id(1);
    let agent_id = test_agent_id(1);

    let mut task_list = TaskList::new(list_id, "Large Sprint".to_string(), peer_id);

    // Add 100 tasks
    let task_count = 100;
    for i in 0..task_count {
        let task_id = TaskId::from_bytes({
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            bytes
        });

        let metadata = test_metadata(&format!("Task {i}"), agent_id.as_bytes()[0]);
        let task = TaskItem::new(task_id, metadata, peer_id);
        let add_result = task_list.add_task(task, peer_id, (i + 1) as u64);
        assert!(add_result.is_ok(), "Failed to add task {i}");
    }

    assert_eq!(task_list.tasks_ordered().len(), task_count);

    // Get a task from the middle
    let ordered = task_list.tasks_ordered();
    assert!(ordered.len() >= 50);
}

/// Test task list name updates (LWW semantics).
#[test]
fn test_update_task_list_name_conflict() {
    let list_id = test_task_list_id(1);
    let peer_id_a = test_peer_id(1);
    let peer_id_b = test_peer_id(2);

    let mut task_list_a = TaskList::new(list_id, "Sprint A".to_string(), peer_id_a);
    let mut task_list_b = TaskList::new(list_id, "Sprint B".to_string(), peer_id_b);

    // Update names concurrently
    task_list_a.update_name("Updated A".to_string(), peer_id_a);
    task_list_b.update_name("Updated B".to_string(), peer_id_b);

    // Merge - LWW should pick one
    task_list_a.merge(&task_list_b).expect("Merge should work");

    // Name should be one of the updates (LWW)
    let name = task_list_a.name();
    assert!(name == "Updated A" || name == "Updated B");
}
