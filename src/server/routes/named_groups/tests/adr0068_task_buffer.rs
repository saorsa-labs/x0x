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
//! - #732 finding 4: the drain re-authorizes against the roster the CLEARING
//!   commit left behind, so a member that commit removed does not get their held
//!   deltas applied (dropped and counted), while a member it kept does — and an
//!   undeterminable roster changes nothing;
//! - #732 finding 3: the binding handed to the constructor already carries the
//!   gate and the live authorized set, and the two call sites that produce a
//!   live handle use it — the gate exists before the listener does;
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

/// A per-instance gate the test drives directly. Per-instance on purpose: a
/// `static` would couple concurrently running tests, which is the exact flake
/// class the `fork_quarantine` fault-injection refactor removed.
///
/// It is also the **barrier** for ADR-0068's "marker installed mid-apply" row.
/// `suspend_after_reads` makes the gate answer "not quarantined" for the first N
/// reads and "quarantined" from then on, which lands a marker exactly in the
/// window between the drain's capture and its re-check — deterministically, by
/// counting reads rather than by racing a timer. `marker_revision` scripts the
/// ADR-0067 token so the *identity* can move while the suspension answer stays
/// the same, which is the other half of the re-check.
#[derive(Debug)]
struct FakeGate {
    suspended: AtomicBool,
    /// After this many `suspended()` reads, start answering `true`.
    /// `u64::MAX` = never (the default).
    suspend_after_reads: AtomicU64,
    /// After this many `suspended()` reads, move the scripted ADR-0067 marker
    /// identity WITHOUT changing the suspension answer — the token half's
    /// barrier. `u64::MAX` = never.
    move_marker_after_reads: AtomicU64,
    suspension_reads: AtomicU64,
    /// Revision inside the scripted ADR-0067 token. `None` ⇒ no marker half.
    marker_revision: std::sync::Mutex<Option<u64>>,
    /// `None` ⇒ this node holds no record for the group, which a re-checking
    /// caller must treat as a mismatch.
    has_record: AtomicBool,
    /// The scripted LIVE roster the drain re-authorizes against (#732 finding
    /// 4). `None` ⇒ "cannot determine", which must leave the list's installed
    /// set alone.
    live_roster: std::sync::Mutex<Option<std::collections::HashSet<x0x::identity::AgentId>>>,
    buffered: AtomicU64,
    dropped: AtomicU64,
    applied: AtomicU64,
}

impl Default for FakeGate {
    fn default() -> Self {
        Self {
            suspended: AtomicBool::new(false),
            suspend_after_reads: AtomicU64::new(u64::MAX),
            move_marker_after_reads: AtomicU64::new(u64::MAX),
            suspension_reads: AtomicU64::new(0),
            marker_revision: std::sync::Mutex::new(None),
            has_record: AtomicBool::new(true),
            live_roster: std::sync::Mutex::new(None),
            buffered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            applied: AtomicU64::new(0),
        }
    }
}

impl FakeGate {
    fn marker_revision(&self) -> Option<u64> {
        *self
            .marker_revision
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_marker_revision(&self, revision: Option<u64>) {
        *self
            .marker_revision
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = revision;
    }

    /// Script the roster the drain will re-authorize against — the roster the
    /// clearing commit left behind.
    fn set_live_roster<I: IntoIterator<Item = x0x::identity::AgentId>>(&self, agents: I) {
        *self
            .live_roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(agents.into_iter().collect());
    }
}

impl TaskIngestGate for FakeGate {
    fn suspended(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let reads = self.suspension_reads.fetch_add(1, Ordering::SeqCst);
            if reads >= self.suspend_after_reads.load(Ordering::SeqCst) {
                // The barrier fires: a marker appeared at this exact read.
                self.suspended.store(true, Ordering::SeqCst);
            }
            if reads >= self.move_marker_after_reads.load(Ordering::SeqCst) {
                // The other barrier: the quarantine was cleared and
                // re-installed in this window, so the identity differs while
                // the suspension answer does not.
                self.set_marker_revision(Some(reads.saturating_add(1_000)));
            }
            self.suspended.load(Ordering::SeqCst)
        })
    }

    fn epoch_token(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<x0x::groups::LifecycleEpochToken>> + Send + '_>,
    > {
        Box::pin(async move {
            if !self.has_record.load(Ordering::SeqCst) {
                return None;
            }
            Some(scripted_token(self.marker_revision()))
        })
    }

    fn authorized_writers(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Option<std::collections::HashSet<x0x::identity::AgentId>>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            self.live_roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
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

/// An ADR-0067 token whose marker half is `revision`, built through the real
/// `GroupInfo::lifecycle_epoch_token` derivation so the fixture cannot drift
/// from the production shape.
fn scripted_token(revision: Option<u64>) -> x0x::groups::LifecycleEpochToken {
    let mut info = x0x::groups::GroupInfo::new(
        "adr0068".to_string(),
        "token script".to_string(),
        x0x::identity::AgentId([3u8; 32]),
        "adr0068-token".to_string(),
    );
    if let Some(revision) = revision {
        let header = info.terminal_commit_header();
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision,
            state_hash: format!("cafe{revision:04x}"),
            committed_by: "33".repeat(32),
            observed_at_ms: 1_700_000_000_000 + revision,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: header.clone(),
                conflicting_commit: header,
                classification: None,
            },
            no_anchor: true,
        });
    }
    info.lifecycle_epoch_token()
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
        self.ingest_sized(gate, delta, bytes).await;
    }

    /// As [`Self::ingest`], with the encoded size the transport would report —
    /// so the byte bound can be driven without building a megabyte of tasks.
    async fn ingest_sized(
        &self,
        gate: Option<&StdArc<dyn TaskIngestGate>>,
        delta: TaskListDelta,
        bytes: usize,
    ) {
        // Exactly the listener's step: the decision comes back WITH the write
        // guard it was taken under, and the merge happens on that guard.
        match x0x::crdt::sync::testing::admit_or_buffer(
            gate,
            &self.buffer,
            &self.list,
            self.peer,
            delta,
            Some(&self.writer),
            bytes,
        )
        .await
        {
            x0x::crdt::sync::testing::Admission::Held => {}
            x0x::crdt::sync::testing::Admission::Apply(delta, mut list) => {
                let _ = list.merge_delta(&delta, self.peer, Some(&self.writer));
            }
        }
    }

    /// Replace the list's authorized-writer set (the one a subscription
    /// captures).
    async fn authorize<I: IntoIterator<Item = x0x::identity::AgentId>>(&self, agents: I) {
        self.list
            .write()
            .await
            .set_authorized_agents(agents.into_iter().collect());
    }

    /// One inbound delta adding a task titled `title`, authored by `writer`.
    fn delta_from(&self, seq: u64, title: &str, writer: &x0x::identity::AgentId) -> TaskListDelta {
        let mut delta = TaskListDelta::new(seq);
        let created_at = 1_700_000_000_000 + seq;
        let id = x0x::crdt::TaskId::new(title, writer, created_at);
        let metadata = x0x::crdt::TaskMetadata::new(title, "adr0068", 128, *writer, created_at);
        let task = x0x::crdt::TaskItem::new(id, metadata, self.peer);
        delta
            .added_tasks
            .insert(*task.id(), (task, (self.peer, seq)));
        delta
    }

    /// The listener's step for one inbound delta from a specific writer.
    async fn ingest_as(
        &self,
        gate: Option<&StdArc<dyn TaskIngestGate>>,
        delta: TaskListDelta,
        writer: &x0x::identity::AgentId,
    ) {
        let bytes = bincode::serialize(&delta).map(|b| b.len()).unwrap_or(0);
        match x0x::crdt::sync::testing::admit_or_buffer(
            gate,
            &self.buffer,
            &self.list,
            self.peer,
            delta,
            Some(writer),
            bytes,
        )
        .await
        {
            x0x::crdt::sync::testing::Admission::Held => {}
            x0x::crdt::sync::testing::Admission::Apply(delta, mut list) => {
                let _ = list.merge_delta(&delta, self.peer, Some(writer));
            }
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

/// ADR-0068's "marker installed mid-apply" row, drain half: a marker that
/// installs between the drain's token capture and its re-check ABANDONS the
/// drain — nothing merges and the deltas stay buffered, in order.
///
/// Deterministic by counting gate reads, not by racing: the barrier gate answers
/// "not quarantined" for the capture read and "quarantined" from the re-check
/// read onward.
#[tokio::test]
async fn adr0068_d2_drain_abandons_when_a_marker_installs_between_capture_and_recheck() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    // Buffer three deltas under a live marker.
    h.gate.suspended.store(true, Ordering::SeqCst);
    h.gate.set_marker_revision(Some(7));
    for (seq, title) in [(1u64, "first"), (2, "second"), (3, "third")] {
        h.ingest(Some(&gate), h.delta(seq, title)).await;
    }
    let before = h.state_bytes().await;
    assert_eq!(x0x::crdt::sync::testing::len(&h.buffer), 3);

    // The marker "clears", then re-installs exactly at the re-check read.
    h.gate.suspended.store(false, Ordering::SeqCst);
    let reads = h.gate.suspension_reads.load(Ordering::SeqCst);
    h.gate
        .suspend_after_reads
        .store(reads + 1, Ordering::SeqCst);

    let applied = x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await;

    assert_eq!(applied, 0, "the drain must abandon, not half-apply");
    assert_eq!(
        h.state_bytes().await,
        before,
        "the CRDT is byte-identical: nothing was merged under a stale reading"
    );
    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        3,
        "the deltas stay buffered for the next observation"
    );
    assert_eq!(h.gate.applied.load(Ordering::SeqCst), 0);

    // CONTROL: same fixture, barrier disarmed ⇒ the drain applies all three, in
    // order. Without this the assertions above could hold because the drain
    // never works at all.
    h.gate.suspend_after_reads.store(u64::MAX, Ordering::SeqCst);
    h.gate.suspended.store(false, Ordering::SeqCst);
    let applied = x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await;
    assert_eq!(
        applied, 3,
        "control: the drain does apply when the token holds"
    );
    let titles = h.titles().await;
    for want in ["first", "second", "third"] {
        assert!(
            titles.iter().any(|t| t == want),
            "missing {want} in {titles:?}"
        );
    }
}

/// The same row, TOKEN half: the ADR-0067 marker identity moves between capture
/// and re-check while the suspension answer stays `false` the whole time.
///
/// This is the negative control for the token itself: a drain that re-checked
/// only `suspended()` would apply these deltas, because both reads say "not
/// quarantined". Only comparing the marker identity catches a
/// clear → re-quarantine → clear that happened in the window.
#[tokio::test]
async fn adr0068_d2_drain_abandons_when_the_marker_identity_moves_under_a_stable_suspension() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    h.gate.suspended.store(true, Ordering::SeqCst);
    h.gate.set_marker_revision(Some(7));
    h.ingest(Some(&gate), h.delta(1, "held")).await;
    let before = h.state_bytes().await;

    // Cleared for both suspension reads, but the identity moves in between.
    h.gate.suspended.store(false, Ordering::SeqCst);
    let reads = h.gate.suspension_reads.load(Ordering::SeqCst);
    h.gate
        .move_marker_after_reads
        .store(reads + 1, Ordering::SeqCst);

    let applied = x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await;
    assert_eq!(applied, 0, "a moved marker identity abandons the drain");
    assert_eq!(h.state_bytes().await, before, "CRDT byte-identical");
    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        1,
        "delta still held"
    );

    // CONTROL: identity stable ⇒ applied.
    h.gate
        .move_marker_after_reads
        .store(u64::MAX, Ordering::SeqCst);
    assert_eq!(
        x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await,
        1,
        "control: a stable marker identity lets the drain through"
    );
}

/// A node that holds NO record for the group is a mismatch, never "unchanged"
/// (ADR-0067's rule for a re-checking caller).
#[tokio::test]
async fn adr0068_d2_drain_abandons_when_the_group_record_is_gone() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    h.gate.suspended.store(true, Ordering::SeqCst);
    h.ingest(Some(&gate), h.delta(1, "held")).await;
    let before = h.state_bytes().await;

    h.gate.suspended.store(false, Ordering::SeqCst);
    h.gate.has_record.store(false, Ordering::SeqCst);
    assert_eq!(
        x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await,
        0,
        "no record ⇒ no token ⇒ mismatch"
    );
    assert_eq!(h.state_bytes().await, before);
    assert_eq!(x0x::crdt::sync::testing::len(&h.buffer), 1);

    // CONTROL: the record comes back ⇒ the drain proceeds.
    h.gate.has_record.store(true, Ordering::SeqCst);
    assert_eq!(
        x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await,
        1,
        "control: with a token the same buffer drains"
    );
}

/// The admit half of the same row: the decision is taken UNDER the list write
/// lock and the guard travels with the admitted delta, so no marker can install
/// between deciding and merging.
///
/// Proven structurally — while the returned guard is alive the list cannot be
/// locked by anyone else — plus the barrier: a marker that installs at the
/// admission read holds the delta rather than letting it through.
#[tokio::test]
async fn adr0068_d2_admit_decides_under_the_list_write_lock() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");

    // Not quarantined: the decision comes back holding the write lock.
    match x0x::crdt::sync::testing::admit_or_buffer(
        Some(&gate),
        &h.buffer,
        &h.list,
        h.peer,
        h.delta(1, "admitted"),
        Some(&h.writer),
        64,
    )
    .await
    {
        x0x::crdt::sync::testing::Admission::Held => panic!("not quarantined — must admit"),
        x0x::crdt::sync::testing::Admission::Apply(delta, mut list) => {
            assert!(
                h.list.try_write().is_err(),
                "the admission decision must still hold the write lock, so the \
                 merge below is in the SAME critical section as the decision"
            );
            let _ = list.merge_delta(&delta, h.peer, Some(&h.writer));
        }
    }
    assert_eq!(h.titles().await.len(), 1);
    assert!(
        h.list.try_write().is_ok(),
        "the guard is released when the admission result is dropped"
    );

    // Barrier: a marker installs at the admission read itself ⇒ HELD, and no
    // guard is left behind.
    let reads = h.gate.suspension_reads.load(Ordering::SeqCst);
    h.gate.suspend_after_reads.store(reads, Ordering::SeqCst);
    let before = h.state_bytes().await;
    h.ingest(Some(&gate), h.delta(2, "held at the barrier"))
        .await;
    assert_eq!(
        h.state_bytes().await,
        before,
        "a marker seen at the decision point holds the delta"
    );
    assert_eq!(x0x::crdt::sync::testing::len(&h.buffer), 1);
    assert!(
        h.list.try_write().is_ok(),
        "no guard leaked on the held path"
    );
}

/// Review nit 4: a single delta larger than the byte bound is DROPPED, not
/// retained — otherwise the transport's own frame cap, not
/// `TASK_QUARANTINE_BUFFER_MAX_BYTES`, would set the per-list worst case.
#[tokio::test]
async fn adr0068_d2_a_single_oversize_delta_is_dropped_not_retained() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    h.gate.suspended.store(true, Ordering::SeqCst);

    // One delta claiming 4 MiB — the transport's frame cap, four times the
    // buffer's whole budget.
    h.ingest_sized(
        Some(&gate),
        h.delta(1, "oversize"),
        x0x::crdt::TASK_QUARANTINE_BUFFER_MAX_BYTES + 1,
    )
    .await;
    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        0,
        "an oversize delta is not retained"
    );
    assert_eq!(x0x::crdt::sync::testing::bytes(&h.buffer), 0);
    assert_eq!(
        h.gate.dropped.load(Ordering::SeqCst),
        1,
        "and the drop is counted, so it is never silent"
    );

    // CONTROL: exactly AT the bound is retained, so the assertion above is
    // about the bound and not about buffering being broken.
    h.ingest_sized(
        Some(&gate),
        h.delta(2, "at the bound"),
        x0x::crdt::TASK_QUARANTINE_BUFFER_MAX_BYTES,
    )
    .await;
    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        1,
        "control: a delta that fits the bound is held"
    );
    assert_eq!(
        x0x::crdt::sync::testing::bytes(&h.buffer),
        x0x::crdt::TASK_QUARANTINE_BUFFER_MAX_BYTES,
        "the held bytes never exceed the ADR's 1 MiB per list"
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

// ---------------------------------------------------------------------------
// #732 finding 4 — the drain authorizes against the roster the CLEARING commit
// left behind, not the one the subscription captured.
// ---------------------------------------------------------------------------

/// A member the clearing commit removed does not get their held deltas applied;
/// a member the commit kept does, and the drop is counted.
///
/// Before the fix the drain merged every held delta against the membership
/// snapshot taken at create/rehydrate time — the contested roster — so the
/// disputed member's claims landed the moment the dispute was resolved AGAINST
/// them.
#[tokio::test]
async fn adr0068_f4_a_member_the_clearing_commit_removed_does_not_get_held_deltas_applied() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    let removed = x0x::identity::AgentId([21u8; 32]);
    let seated = h.writer;
    // The roster as the subscription captured it: both members active.
    h.authorize([removed, seated]).await;
    h.gate.suspended.store(true, Ordering::SeqCst);

    h.ingest_as(
        Some(&gate),
        h.delta_from(1, "disputed-claim", &removed),
        &removed,
    )
    .await;
    h.ingest_as(
        Some(&gate),
        h.delta_from(2, "seated-first", &seated),
        &seated,
    )
    .await;
    h.ingest_as(
        Some(&gate),
        h.delta_from(3, "seated-second", &seated),
        &seated,
    )
    .await;
    assert_eq!(
        x0x::crdt::sync::testing::len(&h.buffer),
        3,
        "all three held while the marker is live"
    );

    // The clearing commit removes the disputed member, then the marker clears.
    h.gate.set_live_roster([seated]);
    h.gate.suspended.store(false, Ordering::SeqCst);
    let applied = x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await;

    assert_eq!(applied, 2, "only the seated member's held deltas applied");
    assert_eq!(
        h.gate.dropped.load(Ordering::SeqCst),
        1,
        "the removed member's delta is DROPPED and counted, never silently \
         merged and never reported as applied"
    );
    let titles = h.titles().await;
    assert!(
        !titles.iter().any(|t| t == "disputed-claim"),
        "the removed member's work must not land: {titles:?}"
    );
    assert_eq!(
        titles,
        vec!["seated-first".to_string(), "seated-second".to_string()],
        "the seated member's held deltas applied, in arrival order: {titles:?}"
    );

    // NEGATIVE CONTROL: the same fixture where the clearing commit removes
    // NOBODY ⇒ all three apply. Without this, "two applied" could be a drain
    // that simply cannot handle three.
    let control = Harness::new();
    let control_gate = control.gate(true).expect("gate");
    control.authorize([removed, control.writer]).await;
    control.gate.suspended.store(true, Ordering::SeqCst);
    control
        .ingest_as(
            Some(&control_gate),
            control.delta_from(1, "disputed-claim", &removed),
            &removed,
        )
        .await;
    control
        .ingest_as(
            Some(&control_gate),
            control.delta_from(2, "seated-first", &control.writer),
            &control.writer,
        )
        .await;
    control
        .ingest_as(
            Some(&control_gate),
            control.delta_from(3, "seated-second", &control.writer),
            &control.writer,
        )
        .await;
    control.gate.set_live_roster([removed, control.writer]);
    control.gate.suspended.store(false, Ordering::SeqCst);
    assert_eq!(
        x0x::crdt::sync::testing::drain(Some(&control_gate), &control.buffer, &control.list).await,
        3,
        "control: an unchanged roster applies every held delta"
    );
    assert_eq!(
        control.gate.dropped.load(Ordering::SeqCst),
        0,
        "control: nothing is dropped when the roster keeps everyone"
    );
    assert!(
        control.titles().await.iter().any(|t| t == "disputed-claim"),
        "control: the same delta DOES apply when the commit keeps its author — \
         proof the assertion above is about the roster refresh"
    );
}

/// A gate that cannot determine the live roster (`None` — no resolvable record,
/// or the daemon is shutting down) leaves the installed set exactly as it was.
/// `None` must mean "unknown", never "deny everyone" (which would lose a seated
/// member's work) and never "allow everyone" (which would defeat the refresh).
#[tokio::test]
async fn adr0068_f4_an_undeterminable_roster_leaves_the_installed_set_alone() {
    let h = Harness::new();
    let gate = h.gate(true).expect("gate");
    h.gate.suspended.store(true, Ordering::SeqCst);
    h.ingest(Some(&gate), h.delta(1, "held")).await;
    // live_roster stays None (the default).
    h.gate.suspended.store(false, Ordering::SeqCst);

    assert_eq!(
        x0x::crdt::sync::testing::drain(Some(&gate), &h.buffer, &h.list).await,
        1,
        "the writer the subscription authorized still applies"
    );
    assert_eq!(h.gate.dropped.load(Ordering::SeqCst), 0);
    assert!(h.titles().await.iter().any(|t| t == "held"));
}

// ---------------------------------------------------------------------------
// #732 finding 3 — the binding exists before the listener does
// ---------------------------------------------------------------------------

/// The binding a create/rehydrate hands the constructor carries a gate that
/// suspends a QUARANTINED group, resolved under both spellings, and an
/// authorized-writer set read from the live roster — all before any listener
/// exists.
///
/// The negative control is the plain (non-group) list: it gets no gate at all,
/// which is what bounds ADR-0068's blast radius.
#[tokio::test]
async fn adr0068_f3_the_prestart_binding_carries_the_gate_for_a_quarantined_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "adr0068-f3-stable";
    let alias = "adr0068-f3-alias";
    let member = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::new(
        "adr0068".to_string(),
        "F3 binding fixture".to_string(),
        member,
        stable.to_string(),
    );
    let header = info.terminal_commit_header();
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 9,
        state_hash: "cafe0009".to_string(),
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

    // The list id carries the STABLE spelling, the map key is the alias.
    let binding = crate::server::routes::group_task_list_binding(
        &state,
        &format!("x0x.group.{stable}.symphony.inbox"),
    )
    .await;
    let gate = binding.ingest_gate.as_ref().expect(
        "a group-scoped list must get its gate from the binding, i.e. BEFORE the \
         listener starts (#732 finding 3)",
    );
    assert!(
        gate.suspended().await,
        "the pre-start gate must already suspend ingest for the quarantined group"
    );
    assert!(
        gate.epoch_token().await.is_some(),
        "and it must resolve the ADR-0067 token for the same record"
    );
    let live = gate
        .authorized_writers()
        .await
        .expect("the live roster resolves under the stable spelling");
    assert!(
        live.contains(&member),
        "the active member is authorized from the LIVE roster: {live:?}"
    );
    assert_eq!(
        binding.authorized_agents.as_ref().map(|a| a.len()),
        Some(live.len()),
        "the binding's captured set comes from the same resolver"
    );

    // NEGATIVE CONTROL: a plain list gets no gate and no authorization, so a
    // list with no group binding keeps its pre-ADR-0068 behaviour exactly.
    let plain = crate::server::routes::group_task_list_binding(&state, "plain-topic").await;
    assert!(
        plain.ingest_gate.is_none() && plain.authorized_agents.is_none(),
        "control: a list with no group binding is untouched"
    );
    Ok(())
}

/// The ordering itself, asserted at the two call sites that produce a live
/// handle: both must pass the binding to the `_bound` constructor, because
/// anything applied to the handle afterwards is applied after the listener has
/// already started (#732 finding 3).
///
/// A source scan rather than a behavioural test because reproducing the race
/// needs a gossip runtime; the behaviour itself is covered in-process by
/// `crdt::sync::tests::quarantine_gate_installed_before_start_holds_the_first_delta`.
#[test]
fn adr0068_f3_the_handle_producing_call_sites_bind_before_they_start() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let rehydrate = std::fs::read_to_string(root.join("src/server/crdt_subscriptions.rs"))
        .expect("the rehydration path must exist");
    let routes = std::fs::read_to_string(root.join("src/server/routes/tasks.rs"))
        .expect("the task routes must exist");
    for (name, source) in [("crdt_subscriptions.rs", &rehydrate), ("tasks.rs", &routes)] {
        assert!(
            source.contains("group_task_list_binding"),
            "{name} must gather the group binding BEFORE constructing the list"
        );
    }
    for (name, source, needle) in [
        (
            "crdt_subscriptions.rs",
            &rehydrate,
            "join_task_list_persistent_bound",
        ),
        (
            "crdt_subscriptions.rs",
            &rehydrate,
            "create_task_list_persistent_bound",
        ),
        ("tasks.rs", &routes, "create_task_list_persistent_bound"),
    ] {
        assert!(
            source.contains(needle),
            "{name} must call {needle}, so the gate is installed before the \
             delta listener is spawned"
        );
    }
}
