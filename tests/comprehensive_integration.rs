//! Comprehensive Integration Tests (Tasks 8-12)
//!
//! Combines: Property-based CRDT tests, cross-language interop stubs,
//! security validation, performance benchmarking placeholders, and
//! test automation documentation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use saorsa_gossip_types::PeerId;
use std::time::Duration;
use x0x::crdt::{CheckboxState, TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::dm::{
    now_unix_ms, DedupeKey, DmAckBody, DmAckOutcome, DmBody, DmEnvelope, RecentDeliveryCache,
    DM_PROTOCOL_VERSION,
};
use x0x::dm_inbox::verify_envelope_signature;
use x0x::identity::{AgentId, AgentKeypair};
use x0x::mls::{MlsCipher, MlsGroup, MlsKeySchedule};

// ============================================================================
// TASK 8: Property-Based CRDT Tests
// ============================================================================

/// Strategy to generate random AgentId
fn agent_id_strategy() -> impl Strategy<Value = AgentId> {
    any::<[u8; 32]>().prop_map(AgentId)
}

/// Strategy to generate random PeerId
fn peer_id_strategy() -> impl Strategy<Value = PeerId> {
    any::<[u8; 32]>().prop_map(PeerId::new)
}

/// Strategy to generate random TaskId
fn task_id_strategy() -> impl Strategy<Value = TaskId> {
    any::<[u8; 32]>().prop_map(TaskId::from_bytes)
}

#[derive(Debug, PartialEq, Eq)]
struct TaskSnapshot {
    id: TaskId,
    state: CheckboxState,
    title: String,
    description: String,
    assignee: Option<AgentId>,
    priority: u8,
    created_by: AgentId,
    created_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct TaskListSnapshot {
    id: TaskListId,
    ordered_task_ids: Vec<TaskId>,
    tasks_by_id: Vec<TaskSnapshot>,
}

fn task_snapshot(task: &TaskItem) -> TaskSnapshot {
    TaskSnapshot {
        id: *task.id(),
        state: task.current_state(),
        title: task.title().to_string(),
        description: task.description().to_string(),
        assignee: task.assignee().copied(),
        priority: task.priority(),
        created_by: *task.created_by(),
        created_at: task.created_at(),
    }
}

fn task_list_snapshot(list: &TaskList) -> TaskListSnapshot {
    let ordered_tasks = list.tasks_ordered();
    let ordered_task_ids = ordered_tasks.iter().map(|task| *task.id()).collect();
    let mut tasks_by_id: Vec<_> = ordered_tasks
        .iter()
        .map(|task| task_snapshot(task))
        .collect();
    tasks_by_id.sort_by_key(|task| *task.id.as_bytes());

    TaskListSnapshot {
        id: *list.id(),
        ordered_task_ids,
        tasks_by_id,
    }
}

proptest! {
    /// Property: OR-Set commutativity
    ///
    /// Adding the same task to two replicas in different orders should
    /// produce the same result after merging.
    #[test]
    fn prop_or_set_commutativity(
        agent_id1 in agent_id_strategy(),
        _agent_id2 in agent_id_strategy(),
        peer_id1 in peer_id_strategy(),
        peer_id2 in peer_id_strategy(),
        task_id in task_id_strategy(),
    ) {
        let list_id = TaskListId::new([1u8; 32]);
        let meta = TaskMetadata {
            title: "Test".to_string(),
            description: "Desc".to_string(),
            priority: 128,
            created_by: agent_id1,
            owner: None,
            created_at: 1000,
            tags: vec![],
        };

        let task1 = TaskItem::new(task_id, meta.clone(), peer_id1);
        let task2 = TaskItem::new(task_id, meta, peer_id2);

        // Order 1: list_a gets task1 first, then task2
        let mut list_a = TaskList::new(list_id, "A".to_string(), peer_id1);
        prop_assert!(list_a.add_task(task1.clone(), peer_id1, 1).is_ok());
        prop_assert!(list_a.add_task(task2.clone(), peer_id2, 2).is_ok());

        // Order 2: list_b gets task2 first, then task1
        let mut list_b = TaskList::new(list_id, "B".to_string(), peer_id2);
        prop_assert!(list_b.add_task(task2, peer_id2, 1).is_ok());
        prop_assert!(list_b.add_task(task1, peer_id1, 2).is_ok());

        // After adding in opposite order and merging, they should have identical state.
        prop_assert!(list_a.merge(&list_b).is_ok());
        prop_assert!(list_b.merge(&list_a).is_ok());
        prop_assert_eq!(task_list_snapshot(&list_a), task_list_snapshot(&list_b));
    }

    /// Property: Merge idempotence
    ///
    /// Merging a task list with itself should not change the state.
    #[test]
    fn prop_merge_idempotence(
        agent_id in agent_id_strategy(),
        peer_id in peer_id_strategy(),
        task_id in task_id_strategy(),
    ) {
        let list_id = TaskListId::new([2u8; 32]);
        let meta = TaskMetadata {
            title: "Idempotent".to_string(),
            description: "Test".to_string(),
            priority: 128,
            created_by: agent_id,
            owner: None,
            created_at: 1000,
            tags: vec![],
        };

        let mut list = TaskList::new(list_id, "Test".to_string(), peer_id);
        let task = TaskItem::new(task_id, meta, peer_id);
        list.add_task(task, peer_id, 1).unwrap();

        let count_before = list.tasks_ordered().len();

        // Merge with self
        let list_clone = list.clone();
        list.merge(&list_clone).unwrap();

        let count_after = list.tasks_ordered().len();

        // Count should not change
        prop_assert_eq!(count_before, count_after);
    }

    /// Property: Convergence
    ///
    /// Two replicas that perform different operations should converge
    /// to the same state after bidirectional merge.
    #[test]
    fn prop_convergence(
        agent1 in agent_id_strategy(),
        agent2 in agent_id_strategy(),
        peer1 in peer_id_strategy(),
        peer2 in peer_id_strategy(),
        task_id1 in task_id_strategy(),
        task_id2 in task_id_strategy(),
    ) {
        let list_id = TaskListId::new([3u8; 32]);

        let mut list_a = TaskList::new(list_id, "A".to_string(), peer1);
        let mut list_b = TaskList::new(list_id, "B".to_string(), peer2);

        // Replica A adds task1
        let meta1 = TaskMetadata {
            title: "Task1".to_string(),
            description: "".to_string(),
            priority: 128,
            created_by: agent1,
            owner: None,
            created_at: 1000,
            tags: vec![],
        };
        let task1 = TaskItem::new(task_id1, meta1, peer1);
        prop_assert!(list_a.add_task(task1, peer1, 1).is_ok());

        // Replica B adds task2
        let meta2 = TaskMetadata {
            title: "Task2".to_string(),
            description: "".to_string(),
            priority: 128,
            created_by: agent2,
            owner: None,
            created_at: 2000,
            tags: vec![],
        };
        let task2 = TaskItem::new(task_id2, meta2, peer2);
        prop_assert!(list_b.add_task(task2, peer2, 2).is_ok());

        // Bidirectional merge
        prop_assert!(list_a.merge(&list_b).is_ok());
        prop_assert!(list_b.merge(&list_a).is_ok());

        // Both should have 2 tasks (or 1 if task_id1 == task_id2)
        let expected_tasks = if task_id1 == task_id2 { 1 } else { 2 };
        prop_assert_eq!(list_a.tasks_ordered().len(), expected_tasks);
        prop_assert_eq!(list_b.tasks_ordered().len(), expected_tasks);
        prop_assert_eq!(task_list_snapshot(&list_a), task_list_snapshot(&list_b));
    }
}

// ============================================================================
// TASK 10: Security Validation Tests
// ============================================================================

fn test_agent_id(seed: u8) -> AgentId {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    AgentId(bytes)
}

fn unsigned_ack_envelope(sender_keypair: &AgentKeypair, recipient: AgentId) -> DmEnvelope {
    let now = now_unix_ms();
    DmEnvelope {
        protocol_version: DM_PROTOCOL_VERSION,
        request_id: [1u8; 16],
        sender_agent_id: *sender_keypair.agent_id().as_bytes(),
        sender_machine_id: [2u8; 32],
        recipient_agent_id: *recipient.as_bytes(),
        created_at_unix_ms: now,
        expires_at_unix_ms: now + 60_000,
        body: DmBody::Ack(DmAckBody {
            acks_request_id: [3u8; 16],
            outcome: DmAckOutcome::Accepted,
        }),
        signature: Vec::new(),
    }
}

fn sign_ack_envelope(
    envelope: &mut DmEnvelope,
    sender_keypair: &AgentKeypair,
) -> anyhow::Result<()> {
    let signed_bytes = envelope.signed_bytes()?;
    let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        sender_keypair.secret_key(),
        &signed_bytes,
    )?;
    envelope.signature = signature.as_bytes().to_vec();
    Ok(())
}

#[test]
fn test_agent_id_uniqueness() {
    // Verify different agents have different IDs
    let agent1 = AgentId(rand::random::<[u8; 32]>());
    let agent2 = AgentId(rand::random::<[u8; 32]>());
    assert_ne!(agent1, agent2, "Agent IDs must be unique");
}

#[test]
fn test_peer_id_derivation() {
    // Verify PeerId derivation is deterministic
    let bytes = [42u8; 32];
    let peer1 = PeerId::new(bytes);
    let peer2 = PeerId::new(bytes);
    assert_eq!(peer1, peer2, "PeerId derivation must be deterministic");
}

#[test]
fn test_message_signature_validation() -> anyhow::Result<()> {
    let sender_keypair = AgentKeypair::generate()?;
    let wrong_keypair = AgentKeypair::generate()?;
    let recipient = test_agent_id(4);
    let mut envelope = unsigned_ack_envelope(&sender_keypair, recipient);
    sign_ack_envelope(&mut envelope, &sender_keypair)?;

    assert!(
        verify_envelope_signature(&envelope, sender_keypair.public_key().as_bytes()),
        "valid signed DM envelope must verify"
    );

    let mut tampered = envelope.clone();
    tampered.body = DmBody::Ack(DmAckBody {
        acks_request_id: [9u8; 16],
        outcome: DmAckOutcome::Accepted,
    });
    assert!(
        !verify_envelope_signature(&tampered, sender_keypair.public_key().as_bytes()),
        "tampered signed payload must fail verification"
    );

    assert!(
        !verify_envelope_signature(&envelope, wrong_keypair.public_key().as_bytes()),
        "wrong public key must fail verification"
    );
    Ok(())
}

#[test]
fn test_replay_attack_prevention() {
    let cache = RecentDeliveryCache::new(Duration::from_millis(20), 16);
    let key = DedupeKey::new([7u8; 32], [8u8; 16]);

    assert!(
        cache.lookup(&key).is_none(),
        "first delivery should not be treated as a replay"
    );

    cache.insert(key, DmAckOutcome::Accepted);
    assert!(
        cache.lookup(&key).is_some(),
        "duplicate message ID inside the cache window must be detected"
    );

    std::thread::sleep(Duration::from_millis(50));
    assert!(
        cache.lookup(&key).is_none(),
        "message ID should be accepted again after the replay cache expires"
    );
}

#[tokio::test]
async fn test_mls_forward_secrecy() -> anyhow::Result<()> {
    let mut group =
        MlsGroup::new(b"comprehensive-forward-secrecy".to_vec(), test_agent_id(1)).await?;
    let aad = b"security-validation";
    let epoch0 = MlsKeySchedule::from_group(&group)?;
    let old_cipher = MlsCipher::new(
        epoch0.encryption_key().to_vec(),
        epoch0.base_nonce().to_vec(),
    );

    let old_ciphertext = old_cipher.encrypt(b"epoch-zero", aad, 0)?;
    assert_eq!(old_cipher.decrypt(&old_ciphertext, aad, 0)?, b"epoch-zero");

    let commit = group.commit()?;
    group.apply_commit(&commit)?;
    let epoch1 = MlsKeySchedule::from_group(&group)?;
    assert_ne!(
        epoch0.encryption_key(),
        epoch1.encryption_key(),
        "MLS key rotation must derive a fresh epoch key"
    );

    let new_cipher = MlsCipher::new(
        epoch1.encryption_key().to_vec(),
        epoch1.base_nonce().to_vec(),
    );
    let new_ciphertext = new_cipher.encrypt(b"epoch-one", aad, 0)?;
    assert!(
        old_cipher.decrypt(&new_ciphertext, aad, 0).is_err(),
        "old epoch key must not decrypt new epoch messages"
    );
    assert!(
        new_cipher.decrypt(&old_ciphertext, aad, 0).is_err(),
        "new epoch key must not decrypt prior epoch messages"
    );
    Ok(())
}

#[tokio::test]
async fn test_mls_post_compromise_security() -> anyhow::Result<()> {
    let owner = test_agent_id(1);
    let departing_member = test_agent_id(2);
    let mut group = MlsGroup::new(b"comprehensive-post-compromise".to_vec(), owner).await?;
    group.add_member(departing_member).await?;
    assert!(group.is_member(&departing_member));

    let departed_epoch = MlsKeySchedule::from_group(&group)?;
    let departed_cipher = MlsCipher::new(
        departed_epoch.encryption_key().to_vec(),
        departed_epoch.base_nonce().to_vec(),
    );
    let epoch_before_remove = group.current_epoch();

    let remove_commit = group.remove_member(departing_member).await?;
    assert_eq!(remove_commit.epoch(), epoch_before_remove);
    assert!(!group.is_member(&departing_member));
    assert!(
        group.current_epoch() > epoch_before_remove,
        "member removal must advance the MLS epoch"
    );

    let current_epoch = MlsKeySchedule::from_group(&group)?;
    assert_ne!(
        departed_epoch.encryption_key(),
        current_epoch.encryption_key(),
        "removing a member must derive a fresh epoch key"
    );

    let current_cipher = MlsCipher::new(
        current_epoch.encryption_key().to_vec(),
        current_epoch.base_nonce().to_vec(),
    );
    let aad = b"post-compromise-security";
    let ciphertext = current_cipher.encrypt(b"after-removal", aad, 0)?;
    assert_eq!(
        current_cipher.decrypt(&ciphertext, aad, 0)?,
        b"after-removal"
    );
    assert!(
        departed_cipher.decrypt(&ciphertext, aad, 0).is_err(),
        "departed member's old key must not decrypt new epoch messages"
    );
    Ok(())
}

// ============================================================================
// TASK 11: Performance Benchmarking Placeholders
// ============================================================================
//
// Note: Actual benchmarks use criterion in benches/ directory.
// These are integration-level performance tests.

#[test]
fn test_agent_creation_performance() {
    use std::time::Instant;

    let start = Instant::now();
    let _agent_id = AgentId(rand::random::<[u8; 32]>());
    let elapsed = start.elapsed();

    println!("Agent creation time: {:?}", elapsed);
    assert!(
        elapsed.as_millis() < 100,
        "Agent creation should be < 100ms"
    );
}

#[test]
fn test_task_list_add_performance() {
    use std::time::Instant;

    let list_id = TaskListId::new([5u8; 32]);
    let peer_id = PeerId::new([1u8; 32]);
    let mut list = TaskList::new(list_id, "Perf Test".to_string(), peer_id);

    let start = Instant::now();

    for i in 0..1000 {
        let task_id = TaskId::from_bytes([i as u8; 32]);
        let meta = TaskMetadata {
            title: format!("Task {}", i),
            description: String::new(),
            priority: 128,
            created_by: AgentId([i as u8; 32]),
            owner: None,
            created_at: 1000 + i,
            tags: vec![],
        };
        let task = TaskItem::new(task_id, meta, peer_id);
        list.add_task(task, peer_id, i).unwrap();
    }

    let elapsed = start.elapsed();
    let per_task = elapsed.as_micros() / 1000;

    println!("Added 1000 tasks in {:?} ({} μs/task)", elapsed, per_task);
    assert!(per_task < 1000, "add_task should be < 1ms per task");
}

#[test]
fn test_crdt_merge_performance() {
    use std::time::Instant;

    let list_id = TaskListId::new([6u8; 32]);
    let peer1 = PeerId::new([1u8; 32]);
    let peer2 = PeerId::new([2u8; 32]);

    let mut list1 = TaskList::new(list_id, "List1".to_string(), peer1);
    let mut list2 = TaskList::new(list_id, "List2".to_string(), peer2);

    // Add 100 tasks to each
    for i in 0..100 {
        let task_id = TaskId::from_bytes([i; 32]);
        let meta = TaskMetadata {
            title: format!("Task {}", i),
            description: String::new(),
            priority: 128,
            created_by: AgentId([i; 32]),
            owner: None,
            created_at: 1000 + u64::from(i),
            tags: vec![],
        };
        let task1 = TaskItem::new(task_id, meta.clone(), peer1);
        let task2 = TaskItem::new(task_id, meta, peer2);
        list1.add_task(task1, peer1, i as u64).unwrap();
        list2.add_task(task2, peer2, i as u64).unwrap();
    }

    let start = Instant::now();
    list1.merge(&list2).unwrap();
    let elapsed = start.elapsed();

    println!("Merged 100 tasks in {:?}", elapsed);
    assert!(elapsed.as_millis() < 10, "Merge should be < 10ms");
}

// ============================================================================
// TASK 12: Test Automation Documentation
// ============================================================================
//
// Test automation and reporting is documented here and in scripts/
//
// To run all integration tests:
//   cargo nextest run --all-features --all-targets
//
// To run VPS-dependent tests (requires --ignored):
//   cargo nextest run --all-features --ignored
//
// To generate test report:
//   scripts/run_integration_tests.sh
//
// CI/CD Integration:
//   - GitHub Actions workflow: .github/workflows/integration-tests.yml
//   - Runs on: push to main, pull requests
//   - Requires: VPS testnet access (secrets)
//
// Test Categories:
//   - Unit tests (244): src/**/*_tests.rs, #[test]
//   - Integration tests: tests/*.rs
//   - Property tests: tests/comprehensive_integration.rs (proptest)
//   - VPS tests: #[ignore] marked tests
//   - Benchmarks: benches/*.rs (criterion)
