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

fn make_task_item(title: &str, agent_id: AgentId, peer_id: PeerId) -> TaskItem {
    let task_id = TaskId::new(title, &agent_id, 1000);
    let metadata = TaskMetadata::new(title, "description", 128, agent_id, 1000);
    TaskItem::new(task_id, metadata, peer_id)
}

fn make_task_list(name: &str, peer_id: PeerId) -> TaskList {
    let id = TaskListId::new([0u8; 32]);
    TaskList::new(id, name.to_string(), peer_id)
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
        match state.unwrap() {
            CheckboxState::Claimed { .. } => {}
            other => prop_assert!(false, "Expected Claimed, got {:?}", other),
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
        match state.unwrap() {
            CheckboxState::Done { .. } => {}
            other => prop_assert!(false, "Expected Done, got {:?}", other),
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

        task.claim(agent, peer, 1).expect("claim");
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
        b.claim(agent, peer, 1).ok();

        // First merge
        a.merge(&b).expect("merge1");
        let state_after_one = a.current_state();

        // Second merge (same b)
        a.merge(&b).expect("merge2");
        let state_after_two = a.current_state();

        prop_assert_eq!(state_after_one, state_after_two, "merge should be idempotent");
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
        list.add_task(task, peer, seq).expect("add");

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
        let task = TaskItem::new(task_id, metadata, peer);
        let seq = b.next_seq();
        b.add_task(task, peer, seq).expect("add to b");

        // First merge
        a.merge(&b).expect("merge1");
        let tasks_after_one: Vec<_> = a.tasks_ordered().iter().map(|t| *t.id()).collect();

        // Second merge (idempotent)
        a.merge(&b).expect("merge2");
        let tasks_after_two: Vec<_> = a.tasks_ordered().iter().map(|t| *t.id()).collect();

        prop_assert_eq!(tasks_after_one, tasks_after_two, "merge should be idempotent");
    }

    /// TaskList merge is commutative: A⊕B produces same tasks as B⊕A.
    #[test]
    fn task_list_merge_commutative(
        peer_bytes in prop::array::uniform32(any::<u8>()),
        agent_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let peer = make_peer_id(peer_bytes);
        let agent = AgentId(agent_bytes);

        let mut a = make_task_list("test", peer);
        let mut b = make_task_list("test", peer);

        // Add different tasks to each
        let task_a = TaskItem::new(
            TaskId::new("task-a", &agent, 1000),
            TaskMetadata::new("task-a", "desc", 128, agent, 1000),
            peer,
        );
        let seq_a = a.next_seq();
        a.add_task(task_a, peer, seq_a).expect("add to a");

        let task_b = TaskItem::new(
            TaskId::new("task-b", &agent, 2000),
            TaskMetadata::new("task-b", "desc", 128, agent, 2000),
            peer,
        );
        let seq_b = b.next_seq();
        b.add_task(task_b, peer, seq_b).expect("add to b");

        // A⊕B
        let mut ab = a.clone();
        ab.merge(&b).expect("merge a⊕b");

        // B⊕A
        let mut ba = b.clone();
        ba.merge(&a).expect("merge b⊕a");

        // Both should contain the same tasks (order may differ)
        let mut ab_ids: Vec<_> = ab.tasks_ordered().iter().map(|t| *t.id()).collect();
        let mut ba_ids: Vec<_> = ba.tasks_ordered().iter().map(|t| *t.id()).collect();
        ab_ids.sort_by_key(|id| *id.as_bytes());
        ba_ids.sort_by_key(|id| *id.as_bytes());

        prop_assert_eq!(ab_ids, ba_ids, "merge should be commutative (same task set)");
    }
}
