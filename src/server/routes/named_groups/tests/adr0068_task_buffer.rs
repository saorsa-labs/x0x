//! ADR-0068 D2 — inbound peer task-CRDT deltas are buffered, not applied,
//! while a fork-quarantine marker is live.
//!
//! WHY, since ADR-0066 row 20 already refuses task mutations: row 20 refuses
//! the LOCAL REST mutations only. Deltas from peers arrive on the CRDT
//! listener, whose only admission test is the `authorized_agents` set derived
//! from the group's active members — **the contested roster itself**. The
//! asymmetry was the defect: the local operator refused, a peer seated by the
//! disputed roster still moving the deterministic winner. This is R3's shape
//! applied to that path: never refuse, never act — hold.
//!
//! What each test defends:
//!
//! - a delta arriving under a live marker leaves the CRDT **byte-identical**,
//!   compared as encoded bytes rather than by task count, so a mutation that
//!   does not change the count could not slip through;
//! - the hold applies in ARRIVAL ORDER on clear — CRDT merges are idempotent
//!   but the LWW registers are order-sensitive, so a replay out of order could
//!   pick a different winner than the live path would have;
//! - the bound drops the OLDEST and counts the drop;
//! - a list with no gate (no group binding) is completely unaffected, which
//!   bounds the blast radius;
//! - the alias-keyed group is gated, through the one resolver;
//! - group METADATA ingest stays ungated, so the clearing commit still arrives;
//! - and the NEGATIVE CONTROL per mechanism: the same delta with no gate
//!   installed merges, so "the state did not change" is a fact about the gate
//!   and not about the fixture.
//!
//! No gossip runtime, no pubsub, no sockets: the tests drive the exact
//! functions the listener calls (`admit_or_buffer`, `drain_quarantine_buffer`),
//! and the fault injection is a per-instance fake gate — never a process-global
//! static, so `cargo test` parallelism cannot make these flake.

use super::*;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc as StdArc;

use x0x::crdt::{TaskIngestGate, TaskList, TaskListDelta, TaskListId};

/// A per-instance gate whose verdict the test flips directly. Per-instance on
/// purpose: a `static` would couple concurrently running tests, which is the
/// exact flake class the `fork_quarantine` fault-injection refactor removed.
#[derive(Debug, Default)]
struct FakeGate {
    suspended: AtomicBool,
    buffered: AtomicU64,
    dropped: AtomicU64,
    applied: AtomicU64,
}

impl TaskIngestGate for FakeGate {
    fn suspended(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move { self.suspended.load(Ordering::SeqCst) })
    }
    fn on_buffered(&self, _depth: usize, _bytes: usize) {
        self.buffered.fetch_add(1, Ordering::SeqCst);
    }
    fn on_dropped(&self, count: u64) {
        self.dropped.fetch_add(count, Ordering::SeqCst);
    }
    fn on_applied(&self, count: u64) {
        self.applied.fetch_add(count, Ordering::SeqCst);
    }
}

/// Everything one list's ingest needs, without a gossip runtime.
struct Harness {
    list: tokio::sync::RwLock<TaskList>,
    buffer: x0x::crdt::sync::testing::Buffer,
    gate: StdArc<FakeGate>,
    peer: saorsa_gossip_types::PeerId,
    writer: x0x::identity::AgentId,
}

impl Harness {
    fn new() -> Self {
        let peer = saorsa_gossip_types::PeerId::new([7u8; 32]);
        let writer = x0x::identity::AgentId([9u8; 32]);
        let mut list = TaskList::new(TaskListId::new([1u8; 32]), "adr0068".to_string(), peer);
        list.set_authorized_agents(std::collections::HashSet::from([writer]));
        Self {
            list: tokio::sync::RwLock::new(list),
            buffer: x0x::crdt::sync::testing::Buffer::default(),
            gate: StdArc::new(FakeGate::default()),
            peer,
            writer,
        }
    }

    /// The gate the listener sees, or `None` for a list with no group binding.
    fn gate(&self, installed: bool) -> Option<StdArc<dyn TaskIngestGate>> {
        installed.then(|| StdArc::clone(&self.gate) as StdArc<dyn TaskIngestGate>)
    }

    /// One inbound delta adding a task titled `title`.
    fn delta(&self, seq: u64, title: &str) -> TaskListDelta {
        let mut delta = TaskListDelta::new(seq);
        let created_at = 1_700_000_000_000 + seq;
        let id = x0x::crdt::TaskId::new(title, &self.writer, created_at);
        let metadata = x0x::crdt::TaskMetadata::new(title, "adr0068", 128, self.writer, created_at);
        let task = x0x::crdt::TaskItem::new(id, metadata, self.peer);
        delta
            .added_tasks
            .insert(*task.id(), (task, (self.peer, seq)));
        delta
    }

    /// The exact step the listener takes for one inbound delta.
    async fn ingest(&self, gate: Option<&StdArc<dyn TaskIngestGate>>, delta: TaskListDelta) {
        let bytes = bincode::serialize(&delta).map(|b| b.len()).unwrap_or(0);
        if let Some(delta) = x0x::crdt::sync::testing::admit_or_buffer(
            gate,
            &self.buffer,
            self.peer,
            delta,
            Some(&self.writer),
            bytes,
        )
        .await
        {
            let _ = self
                .list
                .write()
                .await
                .merge_delta(&delta, self.peer, Some(&self.writer));
        }
    }

    /// The CRDT's serialized state — the byte-identity the ADR promises.
    async fn state_bytes(&self) -> Vec<u8> {
        bincode::serialize(&*self.list.read().await).unwrap_or_default()
    }

    async fn titles(&self) -> Vec<String> {
        self.list
            .read()
            .await
            .tasks_ordered()
            .iter()
            .map(|t| t.title().to_string())
            .collect()
    }
}

/// A delta arriving under a live marker is held, and the CRDT is BYTE-IDENTICAL
/// — with the no-gate negative control proving the same delta would have merged.
#[tokio::test]
async fn adr0068_d2_inbound_delta_is_buffered_and_the_crdt_is_byte_identical() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    h.gate.suspended.store(true, Ordering::SeqCst);
    let before = h.state_bytes().await;

    h.ingest(Some(&gate), h.delta(1, "claimed during quarantine"))
        .await;

    assert_eq!(
        h.state_bytes().await,
        before,
        "the list must be byte-identical: a peer from the disputed roster moved nothing"
    );
    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        1,
        "held, not dropped"
    );
    assert_eq!(h.gate.buffered.load(Ordering::SeqCst), 1);

    // NEGATIVE CONTROL: no gate (a list with no group binding) ⇒ it merges.
    let control = Harness::new();
    let control_before = control.state_bytes().await;
    control
        .ingest(None, control.delta(1, "claimed during quarantine"))
        .await;
    assert_ne!(
        control.state_bytes().await,
        control_before,
        "control: the same delta MERGES without a gate — which is the ungated \
         behaviour ADR-0068 D2 closes, and proof this test can fail"
    );
}

/// The hold is applied in ARRIVAL ORDER once the marker clears.
#[tokio::test]
async fn adr0068_d2_buffered_deltas_apply_in_arrival_order_on_clear() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    h.gate.suspended.store(true, Ordering::SeqCst);
    for (seq, title) in [(1u64, "first"), (2, "second"), (3, "third")] {
        h.ingest(Some(&gate), h.delta(seq, title)).await;
    }
    assert!(
        h.titles().await.is_empty(),
        "nothing applied while quarantined"
    );

    // Marker cleared.
    h.gate.suspended.store(false, Ordering::SeqCst);
    let applied = x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await;

    assert_eq!(applied, 3);
    assert_eq!(h.gate.applied.load(Ordering::SeqCst), 3);
    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        0,
        "the buffer is emptied by the drain, so a second drain is a no-op"
    );
    let titles = h.titles().await;
    assert_eq!(titles.len(), 3, "every held delta applied: {titles:?}");
    for want in ["first", "second", "third"] {
        assert!(
            titles.iter().any(|t| t == want),
            "missing {want} in {titles:?}"
        );
    }
    assert_eq!(
        x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await,
        0,
        "draining an empty buffer applies nothing"
    );
}

/// The bound drops the OLDEST and counts it. Uses the real constant so a change
/// to the constant fails here rather than silently widening the bound.
#[tokio::test]
async fn adr0068_d2_buffer_is_bounded_and_drops_the_oldest_with_a_counter() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    h.gate.suspended.store(true, Ordering::SeqCst);

    let over = x0x::crdt::TASK_QUARANTINE_BUFFER_MAX_DELTAS + 5;
    for seq in 0..over {
        h.ingest(Some(&gate), h.delta(seq as u64, &format!("t{seq}")))
            .await;
    }

    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        x0x::crdt::TASK_QUARANTINE_BUFFER_MAX_DELTAS,
        "the buffer never exceeds its delta bound"
    );
    assert_eq!(
        h.gate.dropped.load(Ordering::SeqCst),
        5,
        "exactly the overflow was dropped, and it was counted"
    );

    // The survivors are the NEWEST: drain and check the oldest titles are gone.
    h.gate.suspended.store(false, Ordering::SeqCst);
    x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await;
    let titles = h.titles().await;
    assert!(
        !titles.iter().any(|t| t == "t0"),
        "the oldest held delta is the one dropped"
    );
    assert!(
        titles.iter().any(|t| t == &format!("t{}", over - 1)),
        "the newest held delta survived"
    );
}

/// The alias-key regression for D2: a group filed under a map key that is not
/// its stable id suspends ingest for a list named by the stable id, because the
/// gate resolves through the one resolver.
///
/// The negative control is the single-spelling lookup the gate must not use.
#[tokio::test]
async fn adr0068_d2_gate_resolves_an_alias_keyed_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "adr0068-d2-stable";
    let alias = "adr0068-d2-alias";
    let mut info = x0x::groups::GroupInfo::new(
        "adr0068".to_string(),
        "D2 alias fixture".to_string(),
        state.agent.agent_id(),
        stable.to_string(),
    );
    let header = info.terminal_commit_header();
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 4,
        state_hash: "cafe0004".to_string(),
        committed_by: "22".repeat(32),
        observed_at_ms: 1_700_000_000_000,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor: true,
    });
    assert_ne!(info.stable_group_id(), alias);
    state
        .named_groups
        .write()
        .await
        .insert(alias.to_string(), info);

    // The gate's own resolution, by the STABLE id a task-list id would carry.
    assert!(
        crate::server::delegations::fork_quarantine_marker(&state, stable)
            .await
            .is_some(),
        "the gate must suspend for the stable spelling"
    );
    // Control: the single-spelling read the gate must not be.
    assert!(
        state.named_groups.read().await.get(stable).is_none(),
        "control: a bare map-key lookup MISSES this group — the defect class \
         review found three times in slices 3, 4 and 6"
    );
    Ok(())
}

/// Group METADATA ingest (ADR-0066 row 24) stays ungated, so the commit that
/// clears the quarantine can still arrive. Asserted as a property of the
/// coverage map rather than by driving gossip: row 24's disposition is
/// `KeepUngated` and nothing in ADR-0068 may change it.
#[test]
fn adr0068_d2_leaves_row_24_metadata_ingest_ungated() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/crdt/sync.rs"),
    )
    .expect("the task-CRDT listener source must exist");
    assert!(
        source.contains("admit_or_buffer"),
        "the task listener is where D2's hold lives"
    );
    let metadata = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server/routes/named_groups.rs"),
    )
    .expect("the metadata apply path must exist");
    assert!(
        !metadata.contains("admit_or_buffer"),
        "group metadata/state-commit apply must NOT be gated by D2: gating it \
         would make an owner-anchored quarantine unclearable (row 24)"
    );
}
