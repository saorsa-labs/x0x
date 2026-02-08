//! CRDT Partition Tolerance Tests
//!
//! Verifies that CRDTs repair correctly after network partitions and message loss.
//! Tests anti-entropy, IBLT reconciliation, and eventual consistency.

use saorsa_gossip_types::PeerId;
use std::time::{SystemTime, UNIX_EPOCH};
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;

/// Helper to create unique agent ID
fn agent_id(n: u8) -> AgentId {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    bytes[1] = 0xAA;
    AgentId(bytes)
}

/// Helper to create unique peer ID
fn peer_id(n: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    bytes[1] = 0xBB;
    PeerId::new(bytes)
}

/// Helper to create unique task ID
fn task_id(n: u8) -> TaskId {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    bytes[1] = 0xCC;
    TaskId::from_bytes(bytes)
}

/// Helper to create task list ID
fn list_id(n: u8) -> TaskListId {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    TaskListId::new(bytes)
}

/// Helper to create task metadata
fn metadata(title: &str, creator: u8) -> TaskMetadata {
    TaskMetadata {
        title: title.to_string(),
        description: format!("Task: {title}"),
        priority: 128,
        created_by: agent_id(creator),
        created_at: unix_timestamp_ms(),
        tags: vec!["partition-test".to_string()],
    }
}

/// Get current Unix timestamp in milliseconds
fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Test 1: Simple partition - add tasks on both sides, verify merge
///
/// Scenario: 2 groups of agents partitioned, each adds tasks independently,
/// then network heals and they converge.
#[test]
fn test_simple_partition_recovery() {
    let task_list_id = list_id(1);

    // Create 2 groups: Group A (3 agents), Group B (3 agents)
    let mut group_a: Vec<TaskList> = (1..=3)
        .map(|i| TaskList::new(task_list_id, "Partitioned List".to_string(), peer_id(i)))
        .collect();

    let mut group_b: Vec<TaskList> = (4..=6)
        .map(|i| TaskList::new(task_list_id, "Partitioned List".to_string(), peer_id(i)))
        .collect();

    // During partition: Group A adds tasks 1-3
    for (i, replica) in group_a.iter_mut().enumerate() {
        let tid = task_id(i as u8 + 1);
        let meta = metadata(&format!("GroupA-Task{}", i + 1), i as u8 + 1);
        let task = TaskItem::new(tid, meta, peer_id(i as u8 + 1));
        replica
            .add_task(task, peer_id(i as u8 + 1), (i + 1) as u64)
            .expect("Failed to add task");
    }

    // During partition: Group B adds tasks 4-6
    for (i, replica) in group_b.iter_mut().enumerate() {
        let tid = task_id(i as u8 + 4);
        let meta = metadata(&format!("GroupB-Task{}", i + 1), i as u8 + 4);
        let task = TaskItem::new(tid, meta, peer_id(i as u8 + 4));
        replica
            .add_task(task, peer_id(i as u8 + 4), (i + 4) as u64)
            .expect("Failed to add task");
    }

    // Internal convergence within each group
    let group_a_clone = group_a.clone();
    for replica in &mut group_a {
        for other in &group_a_clone {
            replica.merge(other).expect("Group A merge failed");
        }
    }

    let group_b_clone = group_b.clone();
    for replica in &mut group_b {
        for other in &group_b_clone {
            replica.merge(other).expect("Group B merge failed");
        }
    }

    // Verify group A has 3 tasks, group B has 3 tasks
    for replica in &group_a {
        assert_eq!(
            replica.tasks_ordered().len(),
            3,
            "Group A should have 3 tasks"
        );
    }
    for replica in &group_b {
        assert_eq!(
            replica.tasks_ordered().len(),
            3,
            "Group B should have 3 tasks"
        );
    }

    // Network heals: merge groups
    for replica_a in &mut group_a {
        for replica_b in &group_b {
            replica_a
                .merge(replica_b)
                .expect("Cross-group merge failed");
        }
    }

    for replica_b in &mut group_b {
        for replica_a in &group_a {
            replica_b
                .merge(replica_a)
                .expect("Cross-group merge failed");
        }
    }

    // All replicas should now have 6 tasks
    for replica in &group_a {
        assert_eq!(
            replica.tasks_ordered().len(),
            6,
            "After partition repair, should have 6 tasks"
        );
    }
    for replica in &group_b {
        assert_eq!(
            replica.tasks_ordered().len(),
            6,
            "After partition repair, should have 6 tasks"
        );
    }
}

/// Test 2: Conflicting claims during partition
///
/// Scenario: Both groups claim the same task during partition, verify earliest-wins resolution.
/// This prevents claim stealing - first to claim keeps the task.
#[test]
fn test_partition_conflicting_claims() {
    let task_list_id = list_id(2);
    let contested_task_id = task_id(100);

    // Create initial task visible to both groups
    let initial_meta = metadata("Contested Task", 1);
    let initial_task = TaskItem::new(contested_task_id, initial_meta, peer_id(1));

    // Group A: 2 replicas
    let mut group_a: Vec<TaskList> = (1..=2)
        .map(|i| {
            let mut list = TaskList::new(task_list_id, "Contested List".to_string(), peer_id(i));
            list.add_task(initial_task.clone(), peer_id(1), 1)
                .expect("Failed to add initial task");
            list
        })
        .collect();

    // Group B: 2 replicas
    let mut group_b: Vec<TaskList> = (3..=4)
        .map(|i| {
            let mut list = TaskList::new(task_list_id, "Contested List".to_string(), peer_id(i));
            list.add_task(initial_task.clone(), peer_id(1), 1)
                .expect("Failed to add initial task");
            list
        })
        .collect();

    // Partition: Group A claims task (timestamp t1, later)
    let timestamp_b = unix_timestamp_ms();
    group_b[0]
        .claim_task(&contested_task_id, agent_id(2), peer_id(2), timestamp_b)
        .expect("Group B claim failed");

    // Partition: Group B claims task (timestamp t2, earlier)
    let timestamp_a = timestamp_b - 100; // Earlier timestamp wins
    group_a[0]
        .claim_task(&contested_task_id, agent_id(1), peer_id(1), timestamp_a)
        .expect("Group A claim failed");

    // Internal propagation within groups
    {
        let a0 = group_a[0].clone();
        group_a[1].merge(&a0).expect("Group A propagation failed");
    }
    {
        let b0 = group_b[0].clone();
        group_b[1].merge(&b0).expect("Group B propagation failed");
    }

    // Network heals: merge groups
    for replica_a in &mut group_a {
        for replica_b in &group_b {
            replica_a
                .merge(replica_b)
                .expect("Cross-group merge failed");
        }
    }

    for replica_b in &mut group_b {
        for replica_a in &group_a {
            replica_b
                .merge(replica_a)
                .expect("Cross-group merge failed");
        }
    }

    // Verify: Earliest timestamp wins (agent 1 from group A)
    // This prevents claim stealing - first to claim keeps it
    for replica in group_a.iter().chain(group_b.iter()) {
        let task = replica
            .get_task(&contested_task_id)
            .expect("Task should exist");
        assert!(task.current_state().is_claimed(), "Task should be claimed");

        // Earliest claim (Group A, timestamp_a) should win
        if let Some(claiming_agent) = task.current_state().claimed_by() {
            assert_eq!(
                claiming_agent,
                &agent_id(1),
                "Earliest claim (Group A, agent 1) should win - prevents claim stealing"
            );
        }
    }
}

/// Test 3: Asymmetric partition - one group sees partial updates
///
/// Scenario: Group A sees some updates from Group B before partition completes.
#[test]
fn test_asymmetric_partition() {
    let task_list_id = list_id(3);

    // Group A: 2 replicas
    let mut group_a: Vec<TaskList> = (1..=2)
        .map(|i| TaskList::new(task_list_id, "Asymmetric".to_string(), peer_id(i)))
        .collect();

    // Group B: 2 replicas
    let mut group_b: Vec<TaskList> = (3..=4)
        .map(|i| TaskList::new(task_list_id, "Asymmetric".to_string(), peer_id(i)))
        .collect();

    // Group B adds task 1
    let task1 = TaskItem::new(task_id(1), metadata("Task1", 3), peer_id(3));
    group_b[0]
        .add_task(task1.clone(), peer_id(3), 1)
        .expect("Failed to add task1");

    // Partial propagation: Group A replica 1 sees task1 before partition
    {
        let b0 = group_b[0].clone();
        group_a[0].merge(&b0).expect("Partial merge failed");
    }

    // Partition happens now
    // Group A replica 2 does NOT see task1
    // Group B adds task 2
    let task2 = TaskItem::new(task_id(2), metadata("Task2", 3), peer_id(3));
    group_b[0]
        .add_task(task2, peer_id(3), 2)
        .expect("Failed to add task2");

    // Group A adds task 3 (only replica 1 has task1)
    let task3 = TaskItem::new(task_id(3), metadata("Task3", 1), peer_id(1));
    group_a[0]
        .add_task(task3, peer_id(1), 3)
        .expect("Failed to add task3");

    // State before healing:
    // Group A replica 1: tasks 1, 3
    // Group A replica 2: task 3
    // Group B: tasks 1, 2

    // Network heals: full mesh merge
    let all_replicas: Vec<TaskList> = group_a.iter().chain(group_b.iter()).cloned().collect();

    for replica in group_a.iter_mut().chain(group_b.iter_mut()) {
        for other in &all_replicas {
            replica.merge(other).expect("Merge failed");
        }
    }

    // All replicas should converge to 3 tasks (1, 2, 3)
    for replica in group_a.iter().chain(group_b.iter()) {
        assert_eq!(
            replica.tasks_ordered().len(),
            3,
            "After asymmetric partition repair, should have 3 tasks"
        );

        // Verify all 3 tasks are present
        assert!(
            replica.get_task(&task_id(1)).is_some(),
            "Should have task 1"
        );
        assert!(
            replica.get_task(&task_id(2)).is_some(),
            "Should have task 2"
        );
        assert!(
            replica.get_task(&task_id(3)).is_some(),
            "Should have task 3"
        );
    }
}

/// Test 4: Multiple partition/repair cycles
///
/// Scenario: Network partitions, heals, partitions again, verify no data loss.
#[test]
fn test_multiple_partition_cycles() {
    let task_list_id = list_id(4);

    let mut replicas: Vec<TaskList> = (1..=4)
        .map(|i| TaskList::new(task_list_id, "Multi-Partition".to_string(), peer_id(i)))
        .collect();

    // Cycle 1: Partition into {1,2} and {3,4}
    // Group {1,2} adds task 1
    let task1 = TaskItem::new(task_id(1), metadata("Task1", 1), peer_id(1));
    replicas[0]
        .add_task(task1, peer_id(1), 1)
        .expect("Failed to add task1");
    {
        let r0 = replicas[0].clone();
        replicas[1].merge(&r0).expect("Failed to sync within group");
    }

    // Group {3,4} adds task 2
    let task2 = TaskItem::new(task_id(2), metadata("Task2", 3), peer_id(3));
    replicas[2]
        .add_task(task2, peer_id(3), 2)
        .expect("Failed to add task2");
    {
        let r2 = replicas[2].clone();
        replicas[3].merge(&r2).expect("Failed to sync within group");
    }

    // Heal cycle 1
    let clones: Vec<TaskList> = replicas.clone();
    for replica in &mut replicas {
        for other in &clones {
            replica.merge(other).expect("Heal failed");
        }
    }

    // All should have 2 tasks
    for replica in &replicas {
        assert_eq!(replica.tasks_ordered().len(), 2, "After heal 1: 2 tasks");
    }

    // Cycle 2: Different partition {1,3} and {2,4}
    // Group {1,3} adds task 3
    let task3 = TaskItem::new(task_id(3), metadata("Task3", 1), peer_id(1));
    replicas[0]
        .add_task(task3, peer_id(1), 3)
        .expect("Failed to add task3");
    {
        let r0 = replicas[0].clone();
        replicas[2].merge(&r0).expect("Failed to sync within group");
    }

    // Group {2,4} adds task 4
    let task4 = TaskItem::new(task_id(4), metadata("Task4", 2), peer_id(2));
    replicas[1]
        .add_task(task4, peer_id(2), 4)
        .expect("Failed to add task4");
    {
        let r1 = replicas[1].clone();
        replicas[3].merge(&r1).expect("Failed to sync within group");
    }

    // Heal cycle 2
    let clones: Vec<TaskList> = replicas.clone();
    for replica in &mut replicas {
        for other in &clones {
            replica.merge(other).expect("Heal failed");
        }
    }

    // All should have 4 tasks, no data loss
    for replica in &replicas {
        assert_eq!(
            replica.tasks_ordered().len(),
            4,
            "After heal 2: 4 tasks, no data loss"
        );
    }
}

/// Test 5: Partition with concurrent state transitions
///
/// Scenario: One group claims task, other group completes it during partition.
#[test]
fn test_partition_state_transitions() {
    let task_list_id = list_id(5);
    let task_id_shared = task_id(50);

    // Initial task shared by all
    let initial_task = TaskItem::new(task_id_shared, metadata("Shared Task", 1), peer_id(1));

    let mut group_a: Vec<TaskList> = (1..=2)
        .map(|i| {
            let mut list = TaskList::new(task_list_id, "State Transition".to_string(), peer_id(i));
            list.add_task(initial_task.clone(), peer_id(1), 1)
                .expect("Failed to add initial task");
            list
        })
        .collect();

    let mut group_b: Vec<TaskList> = (3..=4)
        .map(|i| {
            let mut list = TaskList::new(task_list_id, "State Transition".to_string(), peer_id(i));
            list.add_task(initial_task.clone(), peer_id(1), 1)
                .expect("Failed to add initial task");
            list
        })
        .collect();

    // During partition:
    // Group A claims the task
    let timestamp_claim = unix_timestamp_ms();
    group_a[0]
        .claim_task(&task_id_shared, agent_id(1), peer_id(1), timestamp_claim)
        .expect("Claim failed");

    // Group B also claims and completes the task (later timestamps)
    let timestamp_claim_b = timestamp_claim + 50;
    let timestamp_complete = timestamp_claim + 100;

    group_b[0]
        .claim_task(&task_id_shared, agent_id(2), peer_id(2), timestamp_claim_b)
        .expect("Claim B failed");
    group_b[0]
        .complete_task(&task_id_shared, agent_id(2), peer_id(2), timestamp_complete)
        .expect("Complete failed");

    // Heal
    for replica_a in &mut group_a {
        for replica_b in &group_b {
            replica_a.merge(replica_b).expect("Merge failed");
        }
    }

    for replica_b in &mut group_b {
        for replica_a in &group_a {
            replica_b.merge(replica_a).expect("Merge failed");
        }
    }

    // After merge: task should be Done (completion wins)
    for replica in group_a.iter().chain(group_b.iter()) {
        let task = replica.get_task(&task_id_shared).expect("Task exists");
        assert!(
            task.current_state().is_done(),
            "Task should be done after merge"
        );
    }
}
