//! #503: the deliberate, non-gating timing lane for `TaskList` CRDT merges.
//!
//! The PR-gating test (`tests/comprehensive_integration.rs::
//! test_crdt_merge_performance`) records merge duration as an observation
//! only — a wall-clock budget there is a property of the shared runner's
//! scheduling, not of the merge, and produced red builds on unrelated PRs
//! (#502). Any merge-cost regression guard belongs HERE: criterion
//! statistics with real headroom, run explicitly
//! (`cargo bench --bench crdt_merge_throughput`), never gating CI.
//!
//! Measurement shape (#503 review): `iter_batched_ref` with per-iteration
//! UNTIMED setup clones the destination replica, so the timed routine is
//! **`TaskList::merge` only** — no clone, no `tasks_ordered`, no assert, no
//! drop inside the measurement. The correctness spot-check runs untimed,
//! after the group.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use saorsa_gossip_types::PeerId;
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;

fn bytes_from_counter(counter: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&counter.to_le_bytes());
    bytes
}

fn task_id_from_counter(counter: u64) -> TaskId {
    TaskId::from_bytes(bytes_from_counter(counter))
}

/// Build one replica holding `tasks` tasks with REPLICA-UNIQUE titles and
/// distinct task ids (offset per replica), mirroring the integration test's
/// construction.
fn replica(label: &str, peer: PeerId, tasks: u64, id_offset: u64, title_prefix: &str) -> TaskList {
    let mut list = TaskList::new(TaskListId::new([6u8; 32]), label.to_string(), peer);
    for i in 0..tasks {
        let meta = TaskMetadata {
            title: format!("{title_prefix} Task {i}"),
            description: String::new(),
            priority: 128,
            created_by: AgentId(bytes_from_counter(i)),
            owner: None,
            created_at: 1000 + i,
            tags: vec![],
        };
        let task = TaskItem::new(task_id_from_counter(id_offset + i), meta, peer);
        list.add_task(task, peer, i)
            .expect("bench fixture: add_task is infallible for distinct ids");
    }
    list
}

fn bench_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("crdt_task_list_merge");
    for per_replica in [100u64, 1_000] {
        let peer1 = PeerId::new([1u8; 32]);
        let peer2 = PeerId::new([2u8; 32]);
        let base1 = replica("List1", peer1, per_replica, 0, "P1");
        let base2 = replica("List2", peer2, per_replica, per_replica, "P2");

        // Timed routine = merge only. Setup (destination clone) is untimed;
        // the batch input/output drops happen outside the measurement.
        group.bench_with_input(
            BenchmarkId::new("two_replicas", per_replica),
            &per_replica,
            |b, &n| {
                b.iter_batched_ref(
                    || base1.clone(),
                    |merged| {
                        merged.merge(&base2).expect("merge succeeds");
                    },
                    BatchSize::PerIteration,
                );
                black_box(n);
            },
        );
    }
    group.finish();

    // Untimed correctness spot-check: one merge from a fresh clone yields
    // the exact expected union (count + replica-unique titles).
    let peer1 = PeerId::new([1u8; 32]);
    let peer2 = PeerId::new([2u8; 32]);
    let base1 = replica("List1", peer1, 100, 0, "P1");
    let base2 = replica("List2", peer2, 100, 100, "P2");
    let mut merged = base1.clone();
    merged.merge(&base2).expect("verification merge succeeds");
    let titles: std::collections::HashSet<String> = merged
        .tasks_ordered()
        .into_iter()
        .map(|task| task.title().to_string())
        .collect();
    assert_eq!(merged.tasks_ordered().len(), 200);
    for i in 0..100u64 {
        assert!(titles.contains(&format!("P1 Task {i}")), "P1 Task {i} lost");
        assert!(titles.contains(&format!("P2 Task {i}")), "P2 Task {i} lost");
    }
}

criterion_group!(benches, bench_merge);
criterion_main!(benches);
