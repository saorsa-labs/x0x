//! Property-based tests for x0x CRDT types.
//!
//! Tests CRDT convergence, commutativity, idempotence, and state machine
//! invariants for TaskItem, TaskList, and CheckboxState.
//!
//! Runs without a daemon — pure library testing.

use proptest::prelude::*;
use saorsa_gossip_types::PeerId;
use x0x::crdt::{CheckboxState, TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;

// ── Strategies ──────────────────────────────────────────────────────────

fn arb_timestamp() -> impl Strategy<Value = u64> {
    1_000_000u64..2_000_000_000u64
}

fn make_peer_id(bytes: [u8; 32]) -> PeerId {
    PeerId::from_pubkey(&bytes)
}

fn make_alternate_peer_id(mut bytes: [u8; 32]) -> PeerId {
    bytes[0] ^= 0x80;
    make_peer_id(bytes)
}

fn make_task_item(title: &str, agent_id: AgentId, peer_id: PeerId) -> TaskItem {
    let task_id = TaskId::new(title, &agent_id, 1000);
    let metadata = TaskMetadata::new(title, "description", 128, agent_id, 1000);
    TaskItem::new(task_id, metadata, peer_id)
}

fn make_task_list(name: &str, peer_id: PeerId) -> TaskList {
    let id = TaskListId::new([0u8; 32]);
    TaskList::new(id, name.to_string(), peer_id)
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
    name: String,
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
        name: list.name().to_string(),
        ordered_task_ids,
        tasks_by_id,
    }
}

// ── TaskId Properties ──────────────────────────────────────────────────

proptest! {
    /// TaskId is deterministic: same inputs → same ID.
    #[test]
    fn task_id_deterministic(
        title in "[a-zA-Z ]{1,30}",
        agent_bytes in prop::array::uniform32(any::<u8>()),
        timestamp in arb_timestamp(),
    ) {
        let agent = AgentId(agent_bytes);
        let id1 = TaskId::new(&title, &agent, timestamp);
        let id2 = TaskId::new(&title, &agent, timestamp);
        prop_assert_eq!(id1, id2, "Same inputs must produce same TaskId");
    }

    /// Different titles produce different TaskIds (collision resistance).
    #[test]
    fn task_id_different_titles(
        title1 in "[a-z]{1,10}",
        title2 in "[a-z]{11,20}",
        agent_bytes in prop::array::uniform32(any::<u8>()),
        timestamp in arb_timestamp(),
    ) {
        let agent = AgentId(agent_bytes);
        let id1 = TaskId::new(&title1, &agent, timestamp);
        let id2 = TaskId::new(&title2, &agent, timestamp);
        // With very high probability, different inputs → different IDs
        // (BLAKE3 collision resistance)
        if title1 != title2 {
            prop_assert_ne!(id1, id2);
        }
    }
}

// ── CheckboxState Properties ───────────────────────────────────────────

proptest! {
    /// CheckboxState::claim always produces Claimed variant.
    #[test]
    fn checkbox_claim_produces_claimed(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        timestamp in arb_timestamp(),
    ) {
        let agent = AgentId(agent_bytes);
        let state = CheckboxState::claim(agent, timestamp);
        prop_assert!(state.is_ok(), "claim should succeed");
        match state {
            Ok(CheckboxState::Claimed { .. }) => {}
            Ok(other) => prop_assert!(false, "Expected Claimed, got {:?}", other),
            Err(err) => prop_assert!(false, "claim should succeed: {:?}", err),
        }
    }

    /// CheckboxState::complete always produces Done variant.
    #[test]
    fn checkbox_complete_produces_done(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        timestamp in arb_timestamp(),
    ) {
        let agent = AgentId(agent_bytes);
        let state = CheckboxState::complete(agent, timestamp);
        prop_assert!(state.is_ok(), "complete should succeed");
        match state {
            Ok(CheckboxState::Done { .. }) => {}
            Ok(other) => prop_assert!(false, "Expected Done, got {:?}", other),
            Err(err) => prop_assert!(false, "complete should succeed: {:?}", err),
        }
    }
}

// ── TaskItem Properties ────────────────────────────────────────────────

proptest! {
    /// Claiming an empty task succeeds.
    #[test]
    fn task_item_claim_empty_succeeds(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        peer_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let agent = AgentId(agent_bytes);
        let peer = make_peer_id(peer_bytes);
        let mut task = make_task_item("test", agent, peer);

        let result = task.claim(agent, peer, 1);
        prop_assert!(result.is_ok(), "claim on empty should succeed");

        let state = task.current_state();
        match state {
            CheckboxState::Claimed { .. } => {}
            other => prop_assert!(false, "Expected Claimed, got {:?}", other),
        }
    }

    /// Completing a claimed task succeeds.
    #[test]
    fn task_item_complete_claimed_succeeds(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        peer_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let agent = AgentId(agent_bytes);
        let peer = make_peer_id(peer_bytes);
        let mut task = make_task_item("test", agent, peer);

        prop_assert!(task.claim(agent, peer, 1).is_ok(), "claim should succeed");
        let result = task.complete(agent, peer, 2);
        prop_assert!(result.is_ok(), "complete on claimed should succeed");

        let state = task.current_state();
        match state {
            CheckboxState::Done { .. } => {}
            other => prop_assert!(false, "Expected Done, got {:?}", other),
        }
    }

    /// TaskItem merge is idempotent: A.merge(B).merge(B) == A.merge(B).
    #[test]
    fn task_item_merge_idempotent(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        peer_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let agent = AgentId(agent_bytes);
        let peer = make_peer_id(peer_bytes);

        let mut a = make_task_item("test", agent, peer);
        let mut b = make_task_item("test", agent, peer);
        prop_assert!(b.claim(agent, peer, 1).is_ok(), "claim should succeed");
        b.update_title("updated title".to_string(), peer);
        b.update_description("updated description".to_string(), peer);
        b.update_assignee(Some(agent), peer);
        b.update_priority(255, peer);

        // First merge
        prop_assert!(a.merge(&b).is_ok(), "first merge should succeed");
        let snapshot_after_one = task_snapshot(&a);

        // Second merge (same b)
        prop_assert!(a.merge(&b).is_ok(), "second merge should succeed");
        let snapshot_after_two = task_snapshot(&a);

        prop_assert_eq!(snapshot_after_one, snapshot_after_two, "merge should be idempotent");
    }
}

// ── TaskList Properties ────────────────────────────────────────────────

proptest! {
    /// Adding a task increments the version.
    #[test]
    fn task_list_add_increments_version(
        peer_bytes in prop::array::uniform32(any::<u8>()),
        agent_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let peer = make_peer_id(peer_bytes);
        let agent = AgentId(agent_bytes);
        let mut list = make_task_list("test", peer);

        let v_before = list.version();
        let task_id = TaskId::new("task-1", &agent, 1000);
        let metadata = TaskMetadata::new("task-1", "desc", 128, agent, 1000);
        let task = TaskItem::new(task_id, metadata, peer);
        let seq = list.next_seq();
        prop_assert!(list.add_task(task, peer, seq).is_ok(), "add should succeed");

        prop_assert!(list.version() > v_before, "version should increment after add");
    }

    /// next_seq produces unique values.
    #[test]
    fn task_list_seq_counter_unique(
        peer_bytes in prop::array::uniform32(any::<u8>()),
        n in 2usize..100,
    ) {
        let peer = make_peer_id(peer_bytes);
        let list = make_task_list("test", peer);

        let mut seqs = std::collections::HashSet::new();
        for _ in 0..n {
            let seq = list.next_seq();
            prop_assert!(seqs.insert(seq), "seq_counter should never repeat: got {seq} again");
        }
    }

    /// TaskList merge is idempotent.
    #[test]
    fn task_list_merge_idempotent(
        peer_bytes in prop::array::uniform32(any::<u8>()),
        agent_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let peer = make_peer_id(peer_bytes);
        let agent = AgentId(agent_bytes);

        let mut a = make_task_list("test", peer);
        let mut b = make_task_list("test", peer);

        // Add a task to b
        let task_id = TaskId::new("from-b", &agent, 1000);
        let metadata = TaskMetadata::new("from-b", "desc", 128, agent, 1000);
        let mut task = TaskItem::new(task_id, metadata, peer);
        task.update_title("from-b updated".to_string(), peer);
        task.update_description("from-b updated desc".to_string(), peer);
        task.update_assignee(Some(agent), peer);
        task.update_priority(200, peer);
        let seq = b.next_seq();
        prop_assert!(b.add_task(task, peer, seq).is_ok(), "add to b should succeed");
        b.update_name("test updated".to_string(), peer);

        // First merge
        prop_assert!(a.merge(&b).is_ok(), "first merge should succeed");
        let snapshot_after_one = task_list_snapshot(&a);

        // Second merge (idempotent)
        prop_assert!(a.merge(&b).is_ok(), "second merge should succeed");
        let snapshot_after_two = task_list_snapshot(&a);

        prop_assert_eq!(snapshot_after_one, snapshot_after_two, "merge should be idempotent");
    }

    /// TaskList merge is commutative: A⊕B produces same tasks as B⊕A.
    #[test]
    fn task_list_merge_commutative(
        peer_bytes in prop::array::uniform32(any::<u8>()),
        agent_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let peer = make_peer_id(peer_bytes);
        let other_peer = make_alternate_peer_id(peer_bytes);
        let agent = AgentId(agent_bytes);

        let mut a = make_task_list("test", peer);
        let mut b = make_task_list("test", peer);

        // Add the same task to each replica, then diverge observable state.
        let task_id = TaskId::new("shared-task", &agent, 1000);
        let metadata = TaskMetadata::new("shared-task", "desc", 128, agent, 1000);
        let mut task_a = TaskItem::new(task_id, metadata.clone(), peer);
        prop_assert!(task_a.claim(agent, peer, 2).is_ok(), "claim should succeed");
        task_a.update_title("title from a".to_string(), peer);
        let seq_a = a.next_seq();
        prop_assert!(a.add_task(task_a, peer, seq_a).is_ok(), "add to a should succeed");
        a.update_name("list from a".to_string(), peer);

        let mut task_b = TaskItem::new(task_id, metadata, other_peer);
        task_b.update_description("desc from b".to_string(), other_peer);
        task_b.update_assignee(Some(agent), other_peer);
        task_b.update_priority(255, other_peer);
        let seq_b = b.next_seq();
        prop_assert!(
            b.add_task(task_b, other_peer, seq_b).is_ok(),
            "add to b should succeed"
        );
        b.update_name("list from b".to_string(), other_peer);

        // A⊕B
        let mut ab = a.clone();
        prop_assert!(ab.merge(&b).is_ok(), "merge a⊕b should succeed");

        // B⊕A
        let mut ba = b.clone();
        prop_assert!(ba.merge(&a).is_ok(), "merge b⊕a should succeed");

        prop_assert_eq!(task_list_snapshot(&ab), task_list_snapshot(&ba), "merge should be commutative");
    }
}
