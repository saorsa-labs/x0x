//! End-to-end integration tests for task list synchronization.
//!
//! These tests verify that per-operation deltas published through
//! TaskListSync are received and correctly merged on subscriber replicas.
//! Uses a single NetworkNode with local pubsub delivery to test the
//! full publish → serialize → subscribe → deserialize → merge path.

use saorsa_gossip_types::PeerId;
use std::sync::Arc;
use x0x::crdt::{
    TaskId, TaskItem, TaskList, TaskListDelta, TaskListId, TaskListSync, TaskMetadata,
};
use x0x::gossip::PubSubManager;
use x0x::identity::AgentId;
use x0x::network::{NetworkConfig, NetworkNode};

fn agent(n: u8) -> AgentId {
    AgentId([n; 32])
}

fn peer(n: u8) -> PeerId {
    PeerId::new([n; 32])
}

fn list_id(n: u8) -> TaskListId {
    TaskListId::new([n; 32])
}

fn make_task(id_byte: u8, peer_id: PeerId) -> TaskItem {
    let agent = agent(1);
    let task_id = TaskId::from_bytes([id_byte; 32]);
    let metadata = TaskMetadata::new(
        format!("Task {}", id_byte),
        format!("Description {}", id_byte),
        128,
        agent,
        1000,
    );
    TaskItem::new(task_id, metadata, peer_id)
}

async fn test_node() -> Arc<NetworkNode> {
    Arc::new(
        NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create test node"),
    )
}

/// End-to-end test: add_task delta published by one TaskListSync instance
/// is received and merged by another TaskListSync sharing the same pubsub.
#[tokio::test]
async fn test_sync_add_task_end_to_end() {
    let node = test_node().await;
    let pubsub = Arc::new(PubSubManager::new(node, None));
    let topic = "test-sync-add".to_string();
    let peer1 = peer(1);
    let peer2 = peer(2);
    let id = list_id(1);

    // Create "remote" replica and start its sync (subscribes to topic)
    let remote_list = TaskList::new(id, "Remote".to_string(), peer2);
    let remote_sync = TaskListSync::new(remote_list, Arc::clone(&pubsub), topic.clone(), 300)
        .expect("remote sync creation");
    remote_sync.start().await.expect("remote sync start");

    // Give subscriber time to register
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Create "local" TaskListSync for publishing
    let local_list = TaskList::new(id, "Local".to_string(), peer1);
    let local_sync = TaskListSync::new(local_list, Arc::clone(&pubsub), topic, 300)
        .expect("local sync creation");

    // Simulate what TaskListHandle::add_task does:
    // 1. Mutate local state
    let task = make_task(1, peer1);
    let task_id = *task.id();
    let timestamp = 1000u64;

    {
        let mut list = local_sync.write().await;
        list.add_task(task.clone(), peer1, timestamp)
            .expect("local add_task");
    }

    // 2. Build per-operation delta
    let mut delta = TaskListDelta::new(timestamp);
    delta
        .added_tasks
        .insert(task_id, (task, (peer1, timestamp)));

    // 3. Publish delta
    local_sync
        .publish_delta(peer1, delta)
        .await
        .expect("publish delta");

    // Wait for async delivery
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify remote replica received and merged the task
    let remote = remote_sync.read().await;
    assert_eq!(
        remote.task_count(),
        1,
        "remote should have received the task via sync"
    );
    assert!(
        remote.get_task(&task_id).is_some(),
        "remote should have the specific task"
    );
    assert_eq!(remote.get_task(&task_id).unwrap().title(), "Task 1");
}

/// End-to-end test: claim and complete deltas propagate through sync.
#[tokio::test]
async fn test_sync_claim_complete_end_to_end() {
    let node = test_node().await;
    let pubsub = Arc::new(PubSubManager::new(node, None));
    let topic = "test-sync-claim-complete".to_string();
    let peer1 = peer(1);
    let peer2 = peer(2);
    let agent1 = agent(1);
    let id = list_id(2);

    // Both replicas start with the same task (simulating prior sync)
    let task = make_task(1, peer1);
    let task_id = *task.id();

    let mut remote_list = TaskList::new(id, "Remote".to_string(), peer2);
    remote_list
        .add_task(task.clone(), peer1, 1)
        .expect("remote pre-add");
    let remote_sync = TaskListSync::new(remote_list, Arc::clone(&pubsub), topic.clone(), 300)
        .expect("remote sync");
    remote_sync.start().await.expect("remote start");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut local_list = TaskList::new(id, "Local".to_string(), peer1);
    local_list.add_task(task, peer1, 1).expect("local pre-add");
    let local_sync =
        TaskListSync::new(local_list, Arc::clone(&pubsub), topic, 300).expect("local sync");

    // Claim task locally
    {
        let mut list = local_sync.write().await;
        list.claim_task(&task_id, agent1, peer1, 2000)
            .expect("claim");
    }

    // Publish claim delta
    let mut claim_delta = TaskListDelta::new(2000);
    {
        let list = local_sync.read().await;
        claim_delta
            .task_updates
            .insert(task_id, list.get_task(&task_id).unwrap().clone());
    }
    local_sync
        .publish_delta(peer1, claim_delta)
        .await
        .expect("publish claim");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify remote sees claim
    {
        let remote = remote_sync.read().await;
        assert!(
            remote
                .get_task(&task_id)
                .unwrap()
                .current_state()
                .is_claimed(),
            "remote should see task as claimed"
        );
    }

    // Complete task locally
    {
        let mut list = local_sync.write().await;
        list.complete_task(&task_id, agent1, peer1, 3000)
            .expect("complete");
    }

    // Publish complete delta
    let mut complete_delta = TaskListDelta::new(3000);
    {
        let list = local_sync.read().await;
        complete_delta
            .task_updates
            .insert(task_id, list.get_task(&task_id).unwrap().clone());
    }
    local_sync
        .publish_delta(peer1, complete_delta)
        .await
        .expect("publish complete");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify remote sees completion
    let remote = remote_sync.read().await;
    assert!(
        remote.get_task(&task_id).unwrap().current_state().is_done(),
        "remote should see task as done"
    );
}

/// Self-delivery idempotence: publishing a delta on a sync that also
/// subscribes to the same topic should not cause inconsistency.
#[tokio::test]
async fn test_sync_self_delivery_is_idempotent() {
    let node = test_node().await;
    let pubsub = Arc::new(PubSubManager::new(node, None));
    let topic = "test-self-delivery".to_string();
    let peer1 = peer(1);
    let id = list_id(3);

    let local_list = TaskList::new(id, "Self".to_string(), peer1);
    let sync =
        TaskListSync::new(local_list, Arc::clone(&pubsub), topic, 300).expect("sync creation");
    sync.start().await.expect("sync start");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Add task locally
    let task = make_task(1, peer1);
    let task_id = *task.id();
    {
        let mut list = sync.write().await;
        list.add_task(task.clone(), peer1, 1000).expect("add");
    }

    // Publish delta — this will be delivered back to ourselves
    let mut delta = TaskListDelta::new(1000);
    delta.added_tasks.insert(task_id, (task, (peer1, 1000)));
    sync.publish_delta(peer1, delta).await.expect("publish");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Should still have exactly 1 task (idempotent merge)
    let list = sync.read().await;
    assert_eq!(list.task_count(), 1, "self-delivery should be idempotent");
    assert_eq!(list.get_task(&task_id).unwrap().title(), "Task 1");
}
