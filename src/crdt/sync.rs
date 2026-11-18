//! Task list synchronization using gossip pub/sub.
//!
//! This module provides automatic synchronization of TaskLists across peers
//! using saorsa-gossip's pub/sub delta propagation.
//!
//! This provides eventual consistency across all peers sharing the same topic.

use crate::crdt::persistence::TaskListStorage;
use crate::crdt::sealed::{
    decode_sealed_task_record, encode_sealed_task_record, SealedTaskRecordBody, TaskDeltaProtector,
    TaskPublication, TaskSealRejection,
};
use crate::crdt::{Result, TaskList, TaskListDelta, TaskListId};
use crate::gossip::wire::{decode_delta, encode_delta};
use crate::gossip::PubSubManager;
use crate::identity::AgentId;
use crate::kv::encrypted::KvMutationKind;
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Suffix appended to a task-list topic to form its state-sync side channel.
///
/// State requests travel on a separate topic so the main topic keeps its
/// existing `(PeerId, TaskListDelta)` wire format — peers that predate this
/// channel simply never subscribe to it and are unaffected.
const STATE_SYNC_TOPIC_SUFFIX: &str = "/state-sync";

const STATE_REQUEST_RETRY_SECS: [u64; 4] = [1, 5, 15, 30];

const STATE_REQUEST_TAIL_START_SECS: u64 = 30;

const STATE_REQUEST_TAIL_CAP_SECS: u64 = 300;

/// Infinite by design: holders answer state requests only reactively and never
/// volunteer state, so a bounded schedule leaves a replica that rehydrated
/// while every holder was offline un-synced for good. Convergence is the only
/// stop condition, and the requester loop owns that check.
fn state_request_delays() -> impl Iterator<Item = u64> {
    let tail = std::iter::successors(Some(STATE_REQUEST_TAIL_START_SECS), |d| {
        Some(d.saturating_mul(2).min(STATE_REQUEST_TAIL_CAP_SECS))
    });
    STATE_REQUEST_RETRY_SECS.into_iter().chain(tail)
}

/// The response is a broadcast on the main topic, so one per window serves
/// every bootstrapping replica.
const STATE_RESPONSE_COOLDOWN_SECS: u64 = 15;

fn jittered_secs(secs: u64) -> std::time::Duration {
    let factor = 0.8 + rand::random::<f64>() * 0.4;
    std::time::Duration::from_secs_f64(secs as f64 * factor)
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
enum TaskListSyncMessage {
    StateRequest {
        requester: PeerId,
    },
    /// Sent only by a non-empty holder: under this unverifiable marker two empty
    /// replicas would talk each other into a false "converged empty".
    ///
    /// Wire compatibility: additive variant — older peers fail to
    /// deserialize it and skip the message (same precedent as the kv-store
    /// side channel).
    StateServed {
        responder: PeerId,
    },
    /// Wire compatibility: additive variant, same precedent as the v1
    /// marker — older peers fail to deserialize it and skip the message;
    /// new peers treat v1 markers as weaker evidence when no v2 digest has
    /// been seen. The marker rides along with the full-state broadcast
    /// (never separately) when there is state to serve.
    StateServedV2 {
        responder: PeerId,
        digest: [u8; 32],
        entry_count: u32,
    },
}

#[cfg(test)]
#[test]
fn task_list_sync_message_wire_matches_main() {
    crate::wire_golden_tests::check::<TaskListSyncMessage>(
        "TaskListSyncMessage",
        &[(
            crate::wire_golden_tests::Codec::Bincode,
            crate::wire_golden_tests::Mode::RoundTrip,
        )],
        &["StateRequest", "StateServed", "StateServedV2"],
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServedState {
    digest: [u8; 32],
    entry_count: u32,
}

#[derive(Debug, Default)]
struct TaskServedEvidence {
    saw_v1: bool,
    /// Keyed by responder: a newer declaration replaces the older one, so a
    /// replayed stale serve cannot roll a verified adopt backwards.
    digests: std::collections::HashMap<PeerId, ServedState>,
}

/// If any declaration is non-empty, only a non-empty match converges: an empty
/// holder must not retire a requester while a full holder advertised content.
/// With only v1 markers the weak rule applies (a marker and local
/// non-emptiness). No evidence is never convergence.
fn tasklist_converged(ev: &TaskServedEvidence, task_count: usize, local_digest: [u8; 32]) -> bool {
    if !ev.digests.is_empty() {
        let any_nonempty = ev.digests.values().any(|d| d.entry_count > 0);
        return ev
            .digests
            .values()
            .any(|d| d.digest == local_digest && (d.entry_count > 0 || !any_nonempty));
    }
    ev.saw_v1 && task_count > 0
}

/// Disarms the bootstrap-active flag on every requester exit path, so the
/// listener's digest-verified full-replace adopt cannot fire outside the
/// bootstrap window.
struct BootstrapGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for BootstrapGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

const TASK_SEAL_ATTEMPTS: usize = 3;

/// The protector's permit can hold the group's roster commits off, so a
/// stalled publish must not hold it indefinitely.
const TASK_SEALED_PUBLISH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

fn publish_err(e: impl std::fmt::Display) -> crate::crdt::CrdtError {
    crate::crdt::CrdtError::Gossip(format!("failed to publish delta: {e}"))
}

/// Never falls back to plaintext on a seal error, and never publishes a record
/// sealed under an epoch the group has since left.
async fn seal_and_publish(
    protector: Option<&Arc<dyn TaskDeltaProtector>>,
    pubsub: &PubSubManager,
    topic: &str,
    local_peer_id: PeerId,
    kind: KvMutationKind,
    plain: Vec<u8>,
) -> Result<()> {
    let Some(protector) = protector else {
        return pubsub
            .publish(topic.to_string(), bytes::Bytes::from(plain))
            .await
            .map_err(publish_err);
    };
    for _ in 0..TASK_SEAL_ATTEMPTS {
        // The seal runs with no permit held: the protector's seal may take the
        // same group locks the permit does, and they are not re-entrant.
        let sealed = protector.seal(kind, &plain).await?;
        let Some(body) = sealed else {
            let guarded = tokio::time::timeout(TASK_SEALED_PUBLISH_DEADLINE, async {
                match protector.confirm_plaintext_publication().await? {
                    TaskPublication::Stale => Ok(false),
                    TaskPublication::Current(permit) => {
                        let published = pubsub
                            .publish(topic.to_string(), bytes::Bytes::copy_from_slice(&plain))
                            .await
                            .map_err(publish_err);
                        drop(permit);
                        published.map(|()| true)
                    }
                }
            })
            .await
            .map_err(|_| publish_err("plaintext publish exceeded its deadline"))?;
            if guarded? {
                return Ok(());
            }
            tracing::debug!(
                topic,
                "group policy left signed-public, or a ciphertext hold answered, \
                 after a plaintext seal; re-sealing (#1100, #1581)"
            );
            continue;
        };
        let guarded = tokio::time::timeout(TASK_SEALED_PUBLISH_DEADLINE, async {
            match protector.confirm_publication(&body).await? {
                TaskPublication::Stale => Ok(false),
                TaskPublication::Current(permit) => {
                    let wire = encode_sealed_task_record(local_peer_id, body.clone())?;
                    let published = pubsub
                        .publish(topic.to_string(), bytes::Bytes::from(wire))
                        .await
                        .map_err(publish_err);
                    drop(permit);
                    published.map(|()| true)
                }
            }
        })
        .await
        .map_err(|_| publish_err("sealed publish exceeded its deadline"))?;
        if guarded? {
            return Ok(());
        }
        tracing::debug!(
            topic,
            "group epoch moved, or a ciphertext hold answered, after sealing \
             a task delta; re-sealing (#975, #1581)"
        );
    }
    Err(crate::crdt::CrdtError::Gossip(format!(
        "group policy or epoch changed during each of {TASK_SEAL_ATTEMPTS} seals; \
         task delta not published"
    )))
}

async fn admit_plaintext(protector: &Arc<dyn TaskDeltaProtector>) -> bool {
    if protector.admits_plaintext().await {
        return true;
    }
    protector.on_rejected(TaskSealRejection::PlaintextRefused);
    tracing::warn!(
        "refused plaintext task delta on a group-encrypted list (#895): \
         the sender has not upgraded, or is not a member"
    );
    false
}

async fn open_sealed(
    protector: &Arc<dyn TaskDeltaProtector>,
    body: &SealedTaskRecordBody,
    sender: Option<&AgentId>,
) -> Option<Vec<u8>> {
    let opened = match protector.open(body).await {
        Ok(opened) => opened,
        Err(e) => {
            protector.on_rejected(TaskSealRejection::OpenFailed);
            tracing::warn!("refused sealed task record (#895): {e}");
            return None;
        }
    };
    if sender.is_some_and(|s| *s != opened.author) {
        protector.on_rejected(TaskSealRejection::SenderMismatch);
        tracing::warn!("refused sealed task record: sealed author is not the gossip sender");
        return None;
    }
    Some(opened.payload)
}

/// #895: decides whether a `StateRequest` may trigger a full-state serve,
/// given the request's gossip-verified sender (`None` when unsigned).
///
/// Installed for the legacy plaintext space board: without it, any peer that
/// derives the topic could ask a holder to broadcast the whole list.
pub type StateServeGate = Arc<
    dyn Fn(Option<AgentId>) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync,
>;

/// One change notice for an open task list (#1094 `task:changed`). It
/// carries no task content: a subscriber reads the list through its own
/// authorised path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskListChanged {
    /// The list's topic (the id the REST API uses).
    pub topic: String,
    /// Where the change came from.
    pub origin: crate::kv::KvChangeOrigin,
}

#[derive(Debug, Clone)]
struct TaskChangeSink {
    tx: tokio::sync::broadcast::Sender<TaskListChanged>,
    topic: String,
}

#[derive(Debug, Default)]
struct TaskChangeSlot(std::sync::OnceLock<TaskChangeSink>);

impl TaskChangeSlot {
    fn set(&self, tx: tokio::sync::broadcast::Sender<TaskListChanged>, topic: String) {
        let _ = self.0.set(TaskChangeSink { tx, topic });
    }

    fn note(&self, origin: crate::kv::KvChangeOrigin) {
        if let Some(sink) = self.0.get() {
            let _ = sink.tx.send(TaskListChanged {
                topic: sink.topic.clone(),
                origin,
            });
        }
    }
}

/// Synchronization wrapper for a TaskList.
///
/// Manages automatic background synchronization of a TaskList using gossip
/// pub/sub. Changes are propagated via deltas published to a gossip topic.
pub struct TaskListSync {
    task_list: Arc<RwLock<TaskList>>,

    pubsub: Arc<PubSubManager>,

    topic: String,

    persist: std::sync::Mutex<Option<Arc<TaskPersistCtx>>>,

    change_sink: Arc<TaskChangeSlot>,

    local_peer_id: PeerId,

    stopped: Arc<std::sync::atomic::AtomicBool>,

    /// All background loops select on it, so a discarded sync tears down without
    /// the topic-wide `unsubscribe` that would kill unrelated subscribers of the
    /// same topic string.
    cancel: tokio_util::sync::CancellationToken,

    /// Receive-path lifecycle fence. The listener holds it across one whole
    /// `[cancel check -> (drain) -> admit -> merge -> snapshot persist]` section,
    /// and [`cancel_sync_and_drain`](Self::cancel_sync_and_drain) takes it once
    /// after cancelling, so when that returns no section is in flight or can
    /// start.
    ///
    /// The cancel check sits under the lock: a bare flag check cannot fence a
    /// section that already pulled its message past `recv` when the cancel lands.
    ///
    /// Lock order — `lifecycle` is the outermost lock of a section:
    /// `lifecycle` -> quarantine buffer `Mutex` (leaf) -> `TaskList` write
    /// (admission/merge; the ingest gate takes `named_groups` read inside it,
    /// synchronously) -> guard released -> persist gate `Mutex` -> `TaskList`
    /// read -> file I/O. Nothing may await
    /// [`cancel_sync_and_drain`](Self::cancel_sync_and_drain) while holding a
    /// `TaskList` guard, the persist gate, or a `named_groups` guard.
    lifecycle: Arc<tokio::sync::Mutex<()>>,

    ingest_gate: Arc<TaskIngestGateSlot>,

    quarantine_buffer: Arc<std::sync::Mutex<QuarantineDeltaBuffer>>,

    drain_poll_millis: Arc<std::sync::atomic::AtomicU64>,

    /// Installed before [`start`](Self::start). Empty for a personal list, whose
    /// wire format is unchanged.
    protector: std::sync::OnceLock<Arc<dyn TaskDeltaProtector>>,

    serve_gate: std::sync::OnceLock<StateServeGate>,
}

/// ADR-0068 D2: maximum inbound deltas one task list buffers while its group
/// is fork-quarantined. Oldest is dropped on overflow.
pub const TASK_QUARANTINE_BUFFER_MAX_DELTAS: usize = 1024;

/// ADR-0068 D2: maximum buffered delta bytes per task list (1 MiB). Whichever
/// of this and [`TASK_QUARANTINE_BUFFER_MAX_DELTAS`] is reached first drops
/// the oldest buffered delta.
///
/// The bound is absolute: a single delta larger than this is dropped, not
/// retained. Dropping is safe because merges are idempotent and the state-sync
/// side channel re-serves full state after the clear.
pub const TASK_QUARANTINE_BUFFER_MAX_BYTES: usize = 1_048_576;

/// ADR-0068 D2: how often a listener holding buffered deltas re-checks whether
/// the marker has gone.
///
/// The drain observes the marker's absence instead of hooking each site that
/// can clear it: an enumeration of clear writers fails open when one forgets
/// to drain. The poll is armed only while the buffer is non-empty, and its
/// deadline is a pinned sleep that receives do not reset, so traffic faster
/// than this period cannot starve the drain.
pub const TASK_QUARANTINE_DRAIN_POLL_SECS: u64 = 5;

/// ADR-0068 D2: whether inbound task-CRDT deltas may be applied right now.
pub trait TaskIngestGate: Send + Sync + 'static {
    /// Is application suspended (a live fork-quarantine marker)? Consulted
    /// once per inbound delta and once per drain attempt.
    fn suspended(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;

    /// The ADR-0067 lifecycle epoch token for the bound group, or `None` when
    /// this node holds no record for it.
    ///
    /// `None` is a MISMATCH for a re-checking caller, never "unchanged" — the
    /// same rule `lifecycle_epoch_token_locked` documents. The CRDT layer never
    /// interprets the token; it only asks whether the marker half still
    /// describes the same quarantine it decided against.
    fn epoch_token(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<crate::groups::LifecycleEpochToken>>
                + Send
                + '_,
        >,
    >;

    /// Run `apply` while the group's roster is **pinned**, handing it the live
    /// active-member set and the lifecycle token derived from that same pinned
    /// read (`None` when this node holds no resolvable record for the group).
    ///
    /// **Contract for implementations.**
    /// - Acquire ONE roster guard; derive both the member set and the token from
    ///   it; call `apply` exactly once while it is held.
    /// - `apply` is synchronous and must stay so: `await`ing under a roster guard
    ///   is what would make this a deadlock risk rather than a fix.
    /// - Lock order is `TaskList` → `named_groups`, the documented one: the caller
    ///   already holds the task-list write guard when it calls this. Acquiring the
    ///   roster guard *after* the list guard is that order, not its inverse.
    /// - Still call `apply(None)` when the record cannot be resolved (or the
    ///   daemon is gone), so the caller can decide; it must not be skipped.
    fn with_pinned_roster<'a>(
        &'a self,
        apply: &'a mut (dyn FnMut(Option<&AuthorizedRoster>) + Send),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;

    /// A delta was buffered instead of applied; `depth`/`bytes` are the
    /// buffer's state after the push.
    fn on_buffered(&self, depth: usize, bytes: usize);

    /// `count` buffered deltas were dropped rather than applied: either to make
    /// room (oldest first) or because the refreshed roster no longer seats their
    /// writer (#732 finding 4). One counter, two reasons — the reason is named
    /// in the warning that accompanies every increment.
    fn on_dropped(&self, count: u64);

    /// `count` buffered deltas were applied after the marker cleared.
    fn on_applied(&self, count: u64);
}

/// A live active-member set and the lifecycle token it was derived at, both read
/// from one pinned roster guard.
#[derive(Debug, Clone)]
pub struct AuthorizedRoster {
    /// The group's active members, as CRDT writer identities.
    pub agents: std::collections::HashSet<crate::identity::AgentId>,
    /// The ADR-0067 lifecycle token read under the same guard as `agents`.
    pub token: crate::groups::LifecycleEpochToken,
}

/// Set-once slot for the [`TaskIngestGate`].
///
/// The daemon installs the gate after `start_with_spawner` has spawned the
/// listener, so the listener reads it through this slot on every delta.
#[derive(Default)]
pub struct TaskIngestGateSlot(std::sync::OnceLock<Arc<dyn TaskIngestGate>>);

impl std::fmt::Debug for TaskIngestGateSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskIngestGateSlot")
            .field("installed", &self.0.get().is_some())
            .finish()
    }
}

impl TaskIngestGateSlot {
    /// Install the gate. `false` when one was already installed (kept).
    pub fn install(&self, gate: Arc<dyn TaskIngestGate>) -> bool {
        self.0.set(gate).is_ok()
    }

    /// The installed gate, if any.
    #[must_use]
    pub fn gate(&self) -> Option<&Arc<dyn TaskIngestGate>> {
        self.0.get()
    }
}

#[derive(Debug, Clone)]
struct BufferedDelta {
    seq: u64,
    held: HeldDelta,
    writer: Option<crate::identity::AgentId>,
    bytes: usize,
}

#[derive(Debug, Clone)]
enum HeldDelta {
    Open {
        peer_id: PeerId,
        delta: Box<TaskListDelta>,
    },
    /// A group-sealed record held unopened: the TreeKEM protector refuses to
    /// open during quarantine, so it is opened after the clear and merged in
    /// its arrival position.
    Sealed(SealedTaskRecordBody),
}

/// ADR-0068 D2: bounded, arrival-ordered hold for one task list's inbound
/// deltas while its group is fork-quarantined.
///
/// Process-local and never persisted: a restart loses it and the CRDT
/// re-converges by anti-entropy, exactly as it does for any delta the node was
/// offline for.
///
/// `pub` only because the `cfg(test)` `testing` surface names it.
#[derive(Debug, Default)]
pub struct QuarantineDeltaBuffer {
    entries: std::collections::VecDeque<BufferedDelta>,
    bytes: usize,
    next_seq: u64,
}

impl QuarantineDeltaBuffer {
    fn push(&mut self, mut entry: BufferedDelta) -> u64 {
        entry.seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let mut dropped = 0u64;
        if entry.bytes > TASK_QUARANTINE_BUFFER_MAX_BYTES {
            return 1;
        }
        self.bytes = self.bytes.saturating_add(entry.bytes);
        self.entries.push_back(entry);
        while self.entries.len() > TASK_QUARANTINE_BUFFER_MAX_DELTAS
            || self.bytes > TASK_QUARANTINE_BUFFER_MAX_BYTES
        {
            match self.entries.pop_front() {
                Some(old) => {
                    self.bytes = self.bytes.saturating_sub(old.bytes);
                    dropped += 1;
                }
                None => break,
            }
        }
        dropped
    }

    fn take(&mut self) -> Vec<BufferedDelta> {
        self.bytes = 0;
        self.entries.drain(..).collect()
    }

    fn restore_front(&mut self, entries: Vec<BufferedDelta>) {
        for entry in entries.into_iter().rev() {
            self.bytes = self.bytes.saturating_add(entry.bytes);
            self.entries.push_front(entry);
        }
    }

    fn sealed(&self) -> Vec<(u64, SealedTaskRecordBody, Option<AgentId>)> {
        self.entries
            .iter()
            .filter_map(|e| match &e.held {
                HeldDelta::Sealed(body) => Some((e.seq, body.clone(), e.writer)),
                HeldDelta::Open { .. } => None,
            })
            .collect()
    }

    fn resolve(&mut self, seq: u64, peer_id: PeerId, delta: TaskListDelta) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.seq == seq) {
            entry.held = HeldDelta::Open {
                peer_id,
                delta: Box::new(delta),
            };
        }
    }

    fn remove(&mut self, seq: u64) -> bool {
        let Some(index) = self.entries.iter().position(|e| e.seq == seq) else {
            return false;
        };
        if let Some(entry) = self.entries.remove(index) {
            self.bytes = self.bytes.saturating_sub(entry.bytes);
        }
        true
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Recovers a poisoned mutex: a panic while the hold was locked must not wedge
/// replication for the rest of the process's life.
fn lock_buffer(
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
) -> std::sync::MutexGuard<'_, QuarantineDeltaBuffer> {
    buffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// ADR-0068 D2: the outcome of the admission step.
///
/// `Apply` carries the list write guard the decision was taken under, so the
/// caller's merge happens in the same critical section as the decision.
// Boxing the admitted delta to even the variants out would put an allocation
// on the ingest hot path.
#[allow(clippy::large_enum_variant)]
pub enum Admission<'a> {
    /// Merge this delta, using the guard the decision was taken under.
    Apply(TaskListDelta, tokio::sync::RwLockWriteGuard<'a, TaskList>),
    /// The delta is held and the list untouched: either a marker is live, or
    /// older deltas are still pending and this one must not overtake them.
    Held,
}

/// ADR-0068 D2: the admission step — apply this delta now, or hold it?
///
/// Decides under the list write lock and hands the guard back, so the decision
/// and the caller's merge share one critical section. It does not merge
/// itself: the listener's merge shares its critical section with the
/// digest-verified full-replace adopt, and splitting that would let an
/// interleaved merge be pruned.
///
/// **Lock order: `TaskList` write → `named_groups` read** (the gate's own
/// lookup). Nothing in the daemon holds a `named_groups` guard across a
/// `TaskList` lock acquisition, so this order cannot cycle. A caller that
/// awaits a task list while holding `named_groups` would break it.
///
/// A delta is admitted only when the buffer is empty, read under the same
/// guard as the marker: the LWW registers are order-sensitive, so a newer
/// delta must not overtake held ones. While a buffer cannot be drained, newer
/// deltas queue behind it under the same bounds.
///
/// Accepted residual: the live path is not roster-pinned (that would put a
/// `named_groups` read on the ingest hot path), so at most one already-admitted
/// delta per listener can merge just after a marker installs. The drain path
/// is pinned.
pub(crate) async fn admit_or_buffer<'a>(
    gate: Option<&Arc<dyn TaskIngestGate>>,
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
    task_list: &'a RwLock<TaskList>,
    peer_id: PeerId,
    delta: TaskListDelta,
    writer: Option<&crate::identity::AgentId>,
    encoded_bytes: usize,
) -> Admission<'a> {
    let Some(gate) = gate else {
        return Admission::Apply(delta, task_list.write().await);
    };
    let list = task_list.write().await;
    let suspended = gate.suspended().await;
    let pending = !lock_buffer(buffer).is_empty();
    if !suspended && !pending {
        return Admission::Apply(delta, list);
    }
    hold(
        gate,
        buffer,
        HeldDelta::Open {
            peer_id,
            delta: Box::new(delta),
        },
        writer,
        encoded_bytes,
    );
    drop(list);
    Admission::Held
}

fn hold(
    gate: &Arc<dyn TaskIngestGate>,
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
    held: HeldDelta,
    writer: Option<&crate::identity::AgentId>,
    encoded_bytes: usize,
) {
    let (depth, bytes, dropped) = {
        let mut buffered = lock_buffer(buffer);
        let dropped = buffered.push(BufferedDelta {
            seq: 0,
            held,
            writer: writer.copied(),
            bytes: encoded_bytes,
        });
        (buffered.len(), buffered.bytes(), dropped)
    };
    gate.on_buffered(depth, bytes);
    if dropped > 0 {
        gate.on_dropped(dropped);
        tracing::warn!(
            dropped,
            depth,
            bytes,
            "[tasks] fork-quarantine delta buffer full — dropped oldest \
             (ADR-0068 D2; anti-entropy refills after the clear)"
        );
    }
}

/// The [`admit_or_buffer`] decision, taken before a sealed record is opened:
/// the TreeKEM protector refuses to open while the group is quarantined, so
/// opening first would turn "buffer" into "drop".
pub(crate) enum SealedHold {
    Proceed(SealedTaskRecordBody),
    Held { suspended: bool },
}

pub(crate) async fn hold_sealed_if_held(
    gate: Option<&Arc<dyn TaskIngestGate>>,
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
    task_list: &RwLock<TaskList>,
    body: SealedTaskRecordBody,
    writer: Option<&crate::identity::AgentId>,
    encoded_bytes: usize,
) -> SealedHold {
    let Some(gate) = gate else {
        return SealedHold::Proceed(body);
    };
    let list = task_list.write().await;
    let suspended = gate.suspended().await;
    let pending = !lock_buffer(buffer).is_empty();
    if !suspended && !pending {
        return SealedHold::Proceed(body);
    }
    hold(gate, buffer, HeldDelta::Sealed(body), writer, encoded_bytes);
    drop(list);
    SealedHold::Held { suspended }
}

/// Opens with no list guard held (a TreeKEM open takes the group membership
/// lock and `named_groups`). An entry that fails to open is removed and
/// counted, unless the marker is live again: then it stays held.
async fn open_held_sealed(
    gate: Option<&Arc<dyn TaskIngestGate>>,
    protector: Option<&Arc<dyn TaskDeltaProtector>>,
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
    task_list: &RwLock<TaskList>,
) {
    let Some(protector) = protector else {
        return;
    };
    let sealed = lock_buffer(buffer).sealed();
    for (seq, body, writer) in sealed {
        if let Some(gate) = gate {
            if gate.suspended().await {
                return;
            }
        }
        let outcome = match protector.open(&body).await {
            Ok(opened) if writer.is_some_and(|w| w != opened.author) => {
                Err(TaskSealRejection::SenderMismatch)
            }
            Ok(opened) => decode_delta::<TaskListDelta>(&opened.payload).map_err(|e| {
                let _ = crate::wire_compat::classify_bincode("TaskListDelta", &e);
                TaskSealRejection::OpenFailed
            }),
            Err(e) => {
                if let Some(gate) = gate {
                    if gate.suspended().await {
                        return;
                    }
                }
                tracing::warn!("refused held sealed task record after the clear (#895): {e}");
                Err(TaskSealRejection::OpenFailed)
            }
        };
        let _list = task_list.write().await;
        let mut held = lock_buffer(buffer);
        match outcome {
            Ok((peer_id, delta)) => held.resolve(seq, peer_id, delta),
            Err(reason) => {
                if held.remove(seq) {
                    drop(held);
                    protector.on_rejected(reason);
                }
            }
        }
    }
}

/// ADR-0068 D2: apply every buffered delta, in arrival order, once the marker
/// is gone. Returns how many were applied.
///
/// Arrival order matters: the LWW registers are order-sensitive.
///
/// The drain is one pinned critical section. Under the list write guard the
/// gate pins the roster ([`TaskIngestGate::with_pinned_roster`]) and, with no
/// await, the marker is re-checked against the captured token (no record is a
/// mismatch, ADR-0067), the authorized-writer set is replaced by the pinned
/// one, and the buffer is merged. A roster commit cannot land between the
/// refresh and the merge. Abandoning leaves the buffer intact and in order.
///
/// Lock order: `TaskList` write → roster read, as in [`admit_or_buffer`]. The
/// pin is held for one bounded CPU-only batch; a roster writer waits it out.
pub(crate) async fn drain_quarantine_buffer(
    gate: Option<&Arc<dyn TaskIngestGate>>,
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
    task_list: &RwLock<TaskList>,
) -> usize {
    let empty = {
        let held = lock_buffer(buffer);
        held.is_empty()
    };
    if empty {
        // Refresh the cached authorization even with nothing to apply, so the
        // next deltas are admitted against the roster the clearing commit left.
        if let Some(gate) = gate {
            if !gate.suspended().await {
                let mut list = task_list.write().await;
                let mut refresh = |roster: Option<&AuthorizedRoster>| {
                    if let Some(roster) = roster {
                        if roster.token.marker().is_none() {
                            list.set_authorized_agents(roster.agents.clone());
                        }
                    }
                };
                gate.with_pinned_roster(&mut refresh).await;
            }
        }
        return 0;
    }
    let captured = match gate {
        Some(gate) => {
            if gate.suspended().await {
                return 0;
            }
            let Some(token) = gate.epoch_token().await else {
                // No record for the group is a mismatch (ADR-0067).
                return 0;
            };
            Some(token)
        }
        None => None,
    };
    let mut applied = 0usize;
    let mut refused = 0u64;
    {
        let mut list = task_list.write().await;
        match (gate, captured.as_ref()) {
            (Some(gate), Some(captured)) => {
                let mut merge = |roster: Option<&AuthorizedRoster>| {
                    let Some(roster) = roster else {
                        return;
                    };
                    // Both clauses on purpose: "do not merge while a marker is live" must
                    // not depend on `suspended()` and `epoch_token()` reading one record.
                    if roster.token.marker().is_some() || !roster.token.same_marker(captured) {
                        return;
                    }
                    list.set_authorized_agents(roster.agents.clone());
                    let mut pending = lock_buffer(buffer).take().into_iter();
                    while let Some(entry) = pending.next() {
                        let HeldDelta::Open { peer_id, delta } = &entry.held else {
                            let mut rest = vec![entry];
                            rest.extend(pending);
                            lock_buffer(buffer).restore_front(rest);
                            break;
                        };
                        // A writer the pinned roster no longer seats is skipped and counted.
                        // `merge_delta` would drop its content but return `Ok`, and the delta
                        // would be reported as applied.
                        if entry
                            .writer
                            .is_some_and(|writer| !list.is_authorized_content_writer(&writer))
                        {
                            refused += 1;
                            continue;
                        }
                        match list.merge_delta(delta, *peer_id, entry.writer.as_ref()) {
                            Ok(()) => applied += 1,
                            Err(e) => tracing::warn!(
                                "failed to merge task delta buffered under fork quarantine: {e}"
                            ),
                        }
                    }
                };
                gate.with_pinned_roster(&mut merge).await;
            }
            _ => {
                let mut pending = lock_buffer(buffer).take().into_iter();
                while let Some(entry) = pending.next() {
                    let HeldDelta::Open { peer_id, delta } = &entry.held else {
                        let mut rest = vec![entry];
                        rest.extend(pending);
                        lock_buffer(buffer).restore_front(rest);
                        break;
                    };
                    match list.merge_delta(delta, *peer_id, entry.writer.as_ref()) {
                        Ok(()) => applied += 1,
                        Err(e) => tracing::warn!(
                            "failed to merge task delta buffered under fork quarantine: {e}"
                        ),
                    }
                }
            }
        }
    }
    if let Some(gate) = gate {
        gate.on_applied(applied as u64);
        if refused > 0 {
            gate.on_dropped(refused);
            tracing::warn!(
                refused,
                reason = "writer is not in the roster the clearing commit left behind",
                "[tasks] dropped task deltas buffered under fork quarantine (ADR-0068 D2; \
                 #732 finding 4 — anti-entropy refills anything a seated member still owes)"
            );
        }
    }
    if applied > 0 {
        tracing::info!(
            applied,
            "[tasks] applied task deltas buffered under fork quarantine (ADR-0068 D2)"
        );
    }
    applied
}

#[cfg(test)]
pub mod testing {
    use super::*;

    pub type Buffer = std::sync::Mutex<QuarantineDeltaBuffer>;

    pub async fn admit_or_buffer<'a>(
        gate: Option<&Arc<dyn TaskIngestGate>>,
        buffer: &Buffer,
        task_list: &'a RwLock<TaskList>,
        peer_id: PeerId,
        delta: TaskListDelta,
        writer: Option<&crate::identity::AgentId>,
        encoded_bytes: usize,
    ) -> Admission<'a> {
        super::admit_or_buffer(
            gate,
            buffer,
            task_list,
            peer_id,
            delta,
            writer,
            encoded_bytes,
        )
        .await
    }

    pub use super::Admission;

    pub async fn drain(
        gate: Option<&Arc<dyn TaskIngestGate>>,
        buffer: &Buffer,
        task_list: &RwLock<TaskList>,
    ) -> usize {
        super::drain_quarantine_buffer(gate, buffer, task_list).await
    }

    #[must_use]
    pub fn len(buffer: &Buffer) -> usize {
        lock_buffer(buffer).len()
    }

    #[must_use]
    pub fn bytes(buffer: &Buffer) -> usize {
        lock_buffer(buffer).bytes()
    }
}

/// The background loops hold clones of the token, the list and the pubsub,
/// never the sync itself, so dropping the last `TaskListSync` cancels every
/// loop, including the infinite bootstrap requester.
impl Drop for TaskListSync {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct TaskPersistCtx {
    storage: TaskListStorage,
    list_id: TaskListId,
    /// Serializes snapshot commits and holds the last durably-persisted version.
    /// `(version, bytes)` are captured under this lock, so commit order equals
    /// capture order: a persist burst cannot rename an older snapshot over a
    /// newer one.
    gate: tokio::sync::Mutex<Option<u64>>,
    /// While set, local mutations are refused; remote-delta merges continue so
    /// replication is not wedged.
    degraded: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    persisted: tokio::sync::watch::Sender<u64>,
}

async fn persist_snapshot(task_list: &RwLock<TaskList>, ctx: &TaskPersistCtx) -> Result<()> {
    let result = async {
        let mut last = ctx.gate.lock().await;
        let snapshot = task_list.read().await.clone();
        let version = snapshot.current_version();
        if last.is_some_and(|l| l >= version) {
            return Ok(());
        }
        ctx.storage.save_task_list(&ctx.list_id, &snapshot).await?;
        *last = Some(version);
        #[cfg(test)]
        let _ = ctx.persisted.send(version);
        Ok(())
    }
    .await;
    ctx.degraded
        .store(result.is_err(), std::sync::atomic::Ordering::Relaxed);
    if let Err(e) = &result {
        tracing::error!(
            "task-list snapshot persist failed for list {}: {e} — list is durability-degraded; local mutations are refused until a snapshot succeeds",
            ctx.list_id
        );
    }
    result
}

async fn drain_and_persist(
    gate: &TaskIngestGateSlot,
    protector: Option<&Arc<dyn TaskDeltaProtector>>,
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
    task_list: &RwLock<TaskList>,
    persist: Option<&Arc<TaskPersistCtx>>,
    changes: &TaskChangeSlot,
) -> usize {
    open_held_sealed(gate.gate(), protector, buffer, task_list).await;
    let applied = drain_quarantine_buffer(gate.gate(), buffer, task_list).await;
    if applied > 0 {
        changes.note(crate::kv::KvChangeOrigin::Remote);
        if let Some(ctx) = persist {
            if let Err(e) = persist_snapshot(task_list, ctx).await {
                tracing::warn!("failed to persist drained fork-quarantine task deltas: {e}");
            }
        }
    }
    applied
}

impl TaskListSync {
    /// Create a new TaskList synchronization manager.
    ///
    /// # Arguments
    ///
    /// * `task_list` - The TaskList to synchronize
    /// * `pubsub` - Pub/sub manager for gossip messaging
    /// * `topic` - Topic name for pub/sub (typically task list ID)
    /// * `local_peer_id` - This node's gossip peer id
    ///
    /// # Returns
    ///
    /// A new TaskListSync instance ready to start.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let task_list = TaskList::new(id, "My List".to_string(), peer_id);
    /// let sync = TaskListSync::new(
    ///     task_list,
    ///     pubsub,
    ///     "tasklist-abc123".to_string(),
    ///     peer_id,
    /// )?;
    /// ```
    pub fn new(
        task_list: TaskList,
        pubsub: Arc<PubSubManager>,
        topic: String,
        local_peer_id: PeerId,
    ) -> Result<Self> {
        let task_list = Arc::new(RwLock::new(task_list));

        Ok(Self {
            task_list,
            pubsub,
            topic,
            local_peer_id,
            persist: std::sync::Mutex::new(None),
            change_sink: Arc::new(TaskChangeSlot::default()),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancel: tokio_util::sync::CancellationToken::new(),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            ingest_gate: Arc::new(TaskIngestGateSlot::default()),
            quarantine_buffer: Arc::new(std::sync::Mutex::new(QuarantineDeltaBuffer::default())),
            drain_poll_millis: Arc::new(std::sync::atomic::AtomicU64::new(
                TASK_QUARANTINE_DRAIN_POLL_SECS.saturating_mul(1_000),
            )),
            protector: std::sync::OnceLock::new(),
            serve_gate: std::sync::OnceLock::new(),
        })
    }

    /// #895: install the state-serve gate. Must precede
    /// [`start`](Self::start), which captures it. Returns `false` if one was
    /// already installed (set-once).
    pub fn install_serve_gate(&self, gate: StateServeGate) -> bool {
        self.serve_gate.set(gate).is_ok()
    }

    /// #895: install the group-key protector. Must precede
    /// [`start`](Self::start): the loops capture it when they are spawned, so
    /// a protector installed later would leave them publishing and merging
    /// plaintext. Returns `false` if one was already installed (set-once).
    pub fn install_protector(&self, protector: Arc<dyn TaskDeltaProtector>) -> bool {
        self.protector.set(protector).is_ok()
    }

    #[cfg(test)]
    pub(crate) fn set_drain_poll_millis(&self, millis: u64) {
        self.drain_poll_millis
            .store(millis.max(1), std::sync::atomic::Ordering::Relaxed);
    }

    /// ADR-0068 D2: the inbound-delta gate slot, for the daemon to install a
    /// fork-quarantine gate on a group-scoped list after `start`.
    #[must_use]
    pub fn ingest_gate(&self) -> &Arc<TaskIngestGateSlot> {
        &self.ingest_gate
    }

    /// ADR-0068 D2: apply the deltas buffered under fork quarantine, in
    /// arrival order, and persist once. Returns how many were applied.
    ///
    /// #759: the drain is itself a mutation path, so it runs as a lifecycle
    /// section — it takes the same `lifecycle` lock the listener's
    /// admit/merge/persist sections take and re-checks cancellation under
    /// it. A list that was retired (`cancel_sync`) answers 0 and applies
    /// nothing: a resume racing a retire can never resurrect a retired
    /// listener's buffer into a merge. The empty-buffer authorization
    /// refresh takes the same fence.
    pub async fn resume_quarantined_ingest(&self) -> usize {
        let _section = self.lifecycle.lock().await;
        if self.cancel.is_cancelled() {
            return 0;
        }
        drain_and_persist(
            &self.ingest_gate,
            self.protector.get(),
            &self.quarantine_buffer,
            &self.task_list,
            self.persist_ctx().as_ref(),
            &self.change_sink,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn admit_delta_for_testing(
        &self,
        peer_id: PeerId,
        delta: TaskListDelta,
        writer: Option<&AgentId>,
        encoded_bytes: usize,
    ) -> bool {
        match admit_or_buffer(
            self.ingest_gate.gate(),
            &self.quarantine_buffer,
            &self.task_list,
            peer_id,
            delta,
            writer,
            encoded_bytes,
        )
        .await
        {
            Admission::Held => true,
            Admission::Apply(..) => {
                panic!("admit_delta_for_testing staged no live marker: the delta was admitted, not held")
            }
        }
    }

    /// ADR-0068 D2: how many inbound deltas are currently held because the
    /// group is fork-quarantined.
    #[must_use]
    pub fn quarantined_buffer_len(&self) -> usize {
        lock_buffer(&self.quarantine_buffer).len()
    }

    fn state_sync_topic(&self) -> String {
        format!("{}{}", self.topic, STATE_SYNC_TOPIC_SUFFIX)
    }

    /// Start background synchronization.
    ///
    /// Subscribes to the gossip topic and begins receiving remote deltas.
    /// Also joins the state-sync side channel: holders answer state requests
    /// by republishing their full state, and a first-time joiner (empty local
    /// list) requests that state so it bootstraps tasks written before it
    /// subscribed. Without this, only deltas published *after* subscribing
    /// ever arrive. This method returns immediately; synchronization runs in
    /// the background.
    ///
    /// # Returns
    ///
    /// Ok(()) if started successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if subscription startup fails.
    pub async fn start(&self) -> Result<()> {
        self.start_with_spawner(|fut| {
            tokio::spawn(fut);
        })
        .await
    }

    /// Start background synchronization with a caller-supplied spawner.
    pub async fn start_with_spawner<S>(&self, spawn: S) -> Result<()>
    where
        S: Fn(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>)
            + Send
            + Sync,
    {
        let mut sub = self.pubsub.subscribe(self.topic.clone()).await;
        let task_list = Arc::clone(&self.task_list);
        let listener_cancel = self.cancel.clone();
        let served_evidence = Arc::new(std::sync::Mutex::new(TaskServedEvidence::default()));
        // Armed only while the bootstrap requester runs: a converged replica must
        // never let a divergent holder's serve truncate state it legitimately holds.
        let bootstrap_active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener_served = Arc::clone(&served_evidence);
        let listener_bootstrap_active = Arc::clone(&bootstrap_active);
        let listener_persist = self.persist_ctx();
        let listener_changes = Arc::clone(&self.change_sink);
        let listener_gate = Arc::clone(&self.ingest_gate);
        let listener_buffer = Arc::clone(&self.quarantine_buffer);
        let listener_poll_millis = Arc::clone(&self.drain_poll_millis);
        let listener_lifecycle = Arc::clone(&self.lifecycle);
        // Captured once: the protector is installed before start by contract.
        let listener_protector = self.protector.get().cloned();
        let listener_local_peer = self.local_peer_id;

        spawn(Box::pin(async move {
            // The drain deadline is pinned across receives and reset only once it has
            // fired: a fresh `sleep` per `select!` iteration let every received message
            // cancel it, so steady traffic starved the drain.
            let poll = tokio::time::sleep(std::time::Duration::from_millis(
                listener_poll_millis.load(std::sync::atomic::Ordering::Relaxed),
            ));
            tokio::pin!(poll);
            let mut poll_armed = false;
            loop {
                let buffered = !lock_buffer(&listener_buffer).is_empty();
                if !buffered {
                    poll_armed = false;
                } else if !poll_armed {
                    poll.as_mut().reset(
                        tokio::time::Instant::now()
                            + std::time::Duration::from_millis(
                                listener_poll_millis.load(std::sync::atomic::Ordering::Relaxed),
                            ),
                    );
                    poll_armed = true;
                }
                let (poll_fired, msg) = tokio::select! {
                    // Cancel first: an unbiased select could still fetch a queued delta for
                    // a retired listener. The authoritative fence is the cancel check under
                    // `lifecycle` below.
                    biased;
                    () = listener_cancel.cancelled() => return,
                    () = &mut poll, if poll_armed => {
                        poll_armed = false;
                        (true, None)
                    }
                    msg = sub.recv() => (false, msg),
                };
                if poll_fired {
                    // The drain applies held deltas, so it is a mutation section and takes
                    // the fence: a retired listener never drains.
                    let _section = listener_lifecycle.lock().await;
                    if listener_cancel.is_cancelled() {
                        return;
                    }
                    drain_and_persist(
                        &listener_gate,
                        listener_protector.as_ref(),
                        &listener_buffer,
                        &task_list,
                        listener_persist.as_ref(),
                        &listener_changes,
                    )
                    .await;
                    continue;
                }
                let Some(msg) = msg else {
                    // The subscription is gone, so this sync can no longer replicate: cancel
                    // so the sibling loops (the infinite bootstrap requester) do not outlive it.
                    listener_cancel.cancel();
                    return;
                };
                // Sealed records are opened before any lock: a TreeKEM open takes the
                // group membership lock. Plaintext on a group-bound list is refused.
                let payload: std::borrow::Cow<'_, [u8]> = match &listener_protector {
                    None => std::borrow::Cow::Borrowed(&msg.payload[..]),
                    Some(protector) => match decode_sealed_task_record(&msg.payload) {
                        None => {
                            if !admit_plaintext(protector).await {
                                continue;
                            }
                            std::borrow::Cow::Borrowed(&msg.payload[..])
                        }
                        Some((peer, _))
                            if peer == listener_local_peer
                                && msg.sender.is_some()
                                && msg.sender == protector.local_agent() =>
                        {
                            // Our own echo: a TreeKEM sender cannot open its own ciphertext.
                            // The outer peer tag is not authenticated, so the skip also
                            // requires the gossip-verified sender to be this agent.
                            continue;
                        }
                        Some((_, body)) => match hold_sealed_if_held(
                            listener_gate.gate(),
                            &listener_buffer,
                            &task_list,
                            body,
                            msg.sender.as_ref(),
                            msg.payload.len(),
                        )
                        .await
                        {
                            SealedHold::Held { suspended } => {
                                if !suspended {
                                    let _section = listener_lifecycle.lock().await;
                                    if listener_cancel.is_cancelled() {
                                        return;
                                    }
                                    drain_and_persist(
                                        &listener_gate,
                                        Some(protector),
                                        &listener_buffer,
                                        &task_list,
                                        listener_persist.as_ref(),
                                        &listener_changes,
                                    )
                                    .await;
                                }
                                continue;
                            }
                            SealedHold::Proceed(body) => {
                                match open_sealed(protector, &body, msg.sender.as_ref()).await {
                                    Some(opened) => std::borrow::Cow::Owned(opened),
                                    None => continue,
                                }
                            }
                        },
                    },
                };
                match decode_delta::<TaskListDelta>(&payload) {
                    Ok((peer_id, delta)) => {
                        // Held to the end of this iteration: drain, admission, merge and
                        // the snapshot write are one section a draining retire waits out.
                        // The cancel check sits under the lock because a delta already
                        // pulled past `recv` when the cancel lands must not merge either.
                        let _section = listener_lifecycle.lock().await;
                        if listener_cancel.is_cancelled() {
                            return;
                        }
                        // Held deltas drain before this newer one is admitted: the LWW
                        // registers are order-sensitive, and draining here lets traffic
                        // speed the catch-up instead of waiting on the timer.
                        if !lock_buffer(&listener_buffer).is_empty() {
                            drain_and_persist(
                                &listener_gate,
                                listener_protector.as_ref(),
                                &listener_buffer,
                                &task_list,
                                listener_persist.as_ref(),
                                &listener_changes,
                            )
                            .await;
                        }
                        let (delta, admitted) = match admit_or_buffer(
                            listener_gate.gate(),
                            &listener_buffer,
                            &task_list,
                            peer_id,
                            delta,
                            msg.sender.as_ref(),
                            payload.len(),
                        )
                        .await
                        {
                            Admission::Held => continue,
                            Admission::Apply(delta, guard) => (delta, guard),
                        };
                        let mut merged_ok = false;
                        {
                            let mut list = admitted;
                            // The V2-envelope-verified sender is the writer identity; the
                            // payload `peer_id` is an OR-Set tag only.
                            let writer = msg.sender.as_ref();
                            if let Err(e) = list.merge_delta(&delta, peer_id, writer) {
                                tracing::warn!("Failed to merge remote delta: {}", e);
                            } else {
                                merged_ok = true;
                            }
                            if merged_ok
                                && listener_bootstrap_active
                                    .load(std::sync::atomic::Ordering::Relaxed)
                            {
                                // Digest-verified full-replace adopt: while bootstrapping,
                                // a delta whose digest and task count match the sender's
                                // latest v2 declaration is that holder's complete state, so
                                // local tasks it does not carry are pruned. Without the
                                // verification any holder could truncate local state.
                                let declared = listener_served
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .digests
                                    .get(&peer_id)
                                    .copied();
                                if let Some(declared) = declared {
                                    let list_id = *list.id();
                                    if delta.added_tasks.len() == declared.entry_count as usize
                                        && delta
                                            .served_digest(&list_id)
                                            .is_some_and(|dg| dg == declared.digest)
                                    {
                                        let pruned = list.prune_to_served_set(&delta, writer);
                                        if pruned > 0 {
                                            tracing::info!(
                                                "pruned {pruned} stale task(s) after \
                                             digest-verified full serve for list {}",
                                                list.id()
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        if merged_ok {
                            listener_changes.note(crate::kv::KvChangeOrigin::Remote);
                            if let Some(ctx) = &listener_persist {
                                if let Err(e) = persist_snapshot(&task_list, ctx).await {
                                    tracing::warn!("failed to persist merged task-list delta: {e}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let e = crate::wire_compat::classify_bincode("TaskListDelta", &e);
                        tracing::warn!("Failed to deserialize delta from topic: {}", e);
                    }
                }
            }
        }));

        let mut sync_sub = self.pubsub.subscribe(self.state_sync_topic()).await;
        let responder_list = Arc::clone(&self.task_list);
        let responder_pubsub = Arc::clone(&self.pubsub);
        let responder_topic = self.topic.clone();
        let sync_topic = self.state_sync_topic();
        let responder_served = Arc::clone(&served_evidence);
        let responder_cancel = self.cancel.clone();
        let local_peer_id = self.local_peer_id;
        let responder_protector = self.protector.get().cloned();
        let responder_serve_gate = self.serve_gate.get().cloned();
        spawn(Box::pin(async move {
            // One full-state response per cooldown window. A request inside the
            // window gets no response and no marker: a marker must witness a real
            // broadcast, or a requester that never received the state stops asking.
            let mut last_full_response: Option<tokio::time::Instant> = None;
            loop {
                let msg = tokio::select! {
                    // This loop only publishes and never mutates the CRDT, so it takes
                    // no lifecycle fence.
                    biased;
                    () = responder_cancel.cancelled() => return,
                    msg = sync_sub.recv() => msg,
                };
                let Some(msg) = msg else {
                    // Without the side topic no `StateServed` evidence can arrive and
                    // the requester could never stop: cancel the sibling loops.
                    responder_cancel.cancel();
                    return;
                };
                let Ok(sync_msg) = crate::wire_compat::decode_bincode::<TaskListSyncMessage>(
                    "TaskListSyncMessage",
                    &msg.payload,
                ) else {
                    continue;
                };
                match sync_msg {
                    TaskListSyncMessage::StateRequest { requester } => {
                        if requester == local_peer_id {
                            continue;
                        }
                        if let Some(gate) = &responder_serve_gate {
                            if !gate(msg.sender).await {
                                continue;
                            }
                        }
                        let mut markers: Vec<TaskListSyncMessage> = Vec::new();
                        if responder_list.read().await.task_count() == 0 {
                            // An empty holder declares only the v2 digest of the empty
                            // set, which an empty requester verifies locally. No v1
                            // marker: under that unverifiable rule two empty replicas
                            // would agree on a false "converged empty".
                            let digest = responder_list.read().await.served_digest();
                            markers.push(TaskListSyncMessage::StateServedV2 {
                                responder: local_peer_id,
                                digest,
                                entry_count: 0,
                            });
                        } else {
                            let cooled_down = last_full_response.is_some_and(|t| {
                                t.elapsed()
                                    < std::time::Duration::from_secs(STATE_RESPONSE_COOLDOWN_SECS)
                            });
                            if cooled_down {
                                continue;
                            }
                            // One snapshot for the full delta and the digest, so the
                            // declaration commits to exactly what was broadcast.
                            let (full, digest, count) = {
                                let list = responder_list.read().await;
                                (
                                    list.full_delta(),
                                    list.served_digest(),
                                    list.task_count() as u32,
                                )
                            };
                            let Ok(plain) = encode_delta(local_peer_id, &full) else {
                                continue;
                            };
                            if let Err(e) = seal_and_publish(
                                responder_protector.as_ref(),
                                &responder_pubsub,
                                &responder_topic,
                                local_peer_id,
                                KvMutationKind::FullState,
                                plain,
                            )
                            .await
                            {
                                tracing::warn!("TaskList state-response seal/publish failed: {e}");
                                continue;
                            }
                            last_full_response = Some(tokio::time::Instant::now());
                            markers.push(TaskListSyncMessage::StateServed {
                                responder: local_peer_id,
                            });
                            markers.push(TaskListSyncMessage::StateServedV2 {
                                responder: local_peer_id,
                                digest,
                                entry_count: count,
                            });
                        }
                        for marker in markers {
                            match bincode::serialize(&marker) {
                                Ok(serialized) => {
                                    if let Err(e) = responder_pubsub
                                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                                        .await
                                    {
                                        tracing::warn!(
                                            "TaskList state-served marker publish failed: {e}"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "TaskList state-served marker serialize failed: {e}"
                                    );
                                }
                            }
                        }
                    }
                    TaskListSyncMessage::StateServed { responder } => {
                        if responder == local_peer_id {
                            continue;
                        }
                        // A forged marker steers only when the requester stops
                        // asking, never list content, and the requester still
                        // requires local non-emptiness.
                        responder_served
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .saw_v1 = true;
                    }
                    TaskListSyncMessage::StateServedV2 {
                        responder,
                        digest,
                        entry_count,
                    } => {
                        if responder == local_peer_id {
                            continue;
                        }
                        // The digest is self-verifying: a forged declaration
                        // matches only local state that equals the declared content.
                        responder_served
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .digests
                            .insert(
                                responder,
                                ServedState {
                                    digest,
                                    entry_count,
                                },
                            );
                    }
                }
            }
        }));

        // A first-time joiner has no other way to learn tasks written before it
        // subscribed. The full front burst always runs: one incremental task
        // arriving by live gossip must not cancel the request for the complete
        // history. The tail is infinite (see `state_request_delays`).
        if self.task_list.read().await.task_count() == 0 {
            let requester_pubsub = Arc::clone(&self.pubsub);
            // Weak: the requester must not keep the list alive on its own.
            let requester_list = Arc::downgrade(&self.task_list);
            let sync_topic = self.state_sync_topic();
            let stopped = Arc::clone(&self.stopped);
            let requester_cancel = self.cancel.clone();
            let requester_served = Arc::clone(&served_evidence);
            let requester_bootstrap_active = Arc::clone(&bootstrap_active);
            bootstrap_active.store(true, std::sync::atomic::Ordering::Relaxed);
            spawn(Box::pin(async move {
                let _guard = BootstrapGuard(requester_bootstrap_active);
                for (attempt, delay_secs) in state_request_delays().enumerate() {
                    tokio::select! {
                        biased;
                        () = requester_cancel.cancelled() => return,
                        () = tokio::time::sleep(jittered_secs(delay_secs)) => {}
                    }
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    if attempt >= STATE_REQUEST_RETRY_SECS.len() {
                        let Some(list) = requester_list.upgrade() else {
                            return;
                        };
                        let (count, local_digest) = {
                            let l = list.read().await;
                            (l.task_count(), l.served_digest())
                        };
                        let converged = {
                            let ev = requester_served
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            tasklist_converged(&ev, count, local_digest)
                        };
                        if converged {
                            return;
                        }
                    }
                    let request = TaskListSyncMessage::StateRequest {
                        requester: local_peer_id,
                    };
                    let Ok(serialized) = bincode::serialize(&request) else {
                        return;
                    };
                    if let Err(e) = requester_pubsub
                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                        .await
                    {
                        tracing::debug!("TaskList state-request publish failed: {e}");
                    }
                }
            }));
        }

        Ok(())
    }

    /// Stop background synchronization.
    ///
    /// Unsubscribes from the gossip topic and its state-sync side channel.
    ///
    /// # Returns
    ///
    /// Ok(()) if stopped successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if operations fail.
    pub async fn stop(&self) -> Result<()> {
        // Cancel first: unsubscribing does not end the bootstrap requester,
        // which holds no subscription.
        self.cancel_sync();
        self.pubsub.unsubscribe(&self.topic).await;
        self.pubsub.unsubscribe(&self.state_sync_topic()).await;
        Ok(())
    }

    /// Silence ONLY this sync's bootstrap requester (its schedule is
    /// infinite while unconverged — issue #238), leaving the listener and
    /// responder loops serving. Discarded handles want
    /// [`cancel_sync`](Self::cancel_sync).
    pub fn silence_bootstrap(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Tear down ALL of this sync's background loops (delta listener,
    /// state-request responder, bootstrap requester) WITHOUT touching topic
    /// subscriptions.
    ///
    /// This is the correct teardown for a discarded handle inside a daemon:
    /// `PubSubManager::unsubscribe` (what [`stop`](Self::stop) does) removes
    /// the ENTIRE topic — including subscriptions owned by other components
    /// that legally share the topic string. Ending the loops drops their
    /// `Subscription` receivers, so the pub/sub layer prunes the closed
    /// senders on its next delivery.
    pub fn cancel_sync(&self) {
        self.cancel.cancel();
    }

    /// #759: retire this sync AND wait out its in-flight receive sections.
    ///
    /// `cancel_sync` alone is a REQUEST: one section that already passed its
    /// under-`lifecycle` cancel check still completes — its merge AND its
    /// snapshot write — possibly after `cancel_sync` returned. This cancels,
    /// then takes the `lifecycle` lock once and drops it, so when it returns
    /// no receive section (listener iteration or route-triggered resume
    /// drain) is in flight or can start.
    ///
    /// Must NOT be awaited while holding any lock a section takes inside
    /// `lifecycle`: a `TaskList` guard, the persist gate, or a
    /// `named_groups` guard (the ingest gate reads it synchronously under
    /// the list write). The `task_lists` registry is NOT taken by a section,
    /// so it is safe — though pointlessly blocking — to hold it here.
    pub async fn cancel_sync_and_drain(&self) {
        self.cancel.cancel();
        drop(self.lifecycle.lock().await);
    }

    #[cfg(test)]
    pub(crate) fn receive_section_active_for_test(&self) -> bool {
        self.lifecycle.try_lock().is_err()
    }

    /// Apply a delta received from a remote peer.
    ///
    /// This is called when a delta is received via the gossip topic.
    /// The delta is merged into the local TaskList using CRDT semantics.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer who sent this delta (OR-Set tag source only,
    ///   never an identity)
    /// * `delta` - The delta to apply
    /// * `writer` - The envelope-verified sender, if any. Content fields
    ///   (add/metadata/name/order/remove) apply only for a `Some` writer
    ///   authorized by the list's member set; anonymous deltas fail closed
    ///   (issue #349, Layer A). Attested checkbox operations on existing
    ///   tasks still converge.
    ///
    /// # Returns
    ///
    /// Ok(()) if the delta was applied successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if the merge fails.
    pub async fn apply_remote_delta(
        &self,
        peer_id: PeerId,
        delta: TaskListDelta,
        writer: Option<&AgentId>,
    ) -> Result<()> {
        {
            let mut task_list = self.task_list.write().await;
            task_list.merge_delta(&delta, peer_id, writer)?;
        }
        self.change_sink.note(crate::kv::KvChangeOrigin::Remote);
        Ok(())
    }

    /// Send this list's change notices (#1094 `task:changed`) to `tx`. Set
    /// once, before [`Self::start`]; a second call is ignored. Without a
    /// sink the list sends nothing.
    pub fn set_change_sink(&self, tx: tokio::sync::broadcast::Sender<TaskListChanged>) {
        self.change_sink.set(tx, self.topic.clone());
    }

    /// Send a change notice for a change made outside the sync loops (a
    /// local mutation). Call it once the content has changed, whatever
    /// persist and publish then do.
    pub fn note_change(&self, origin: crate::kv::KvChangeOrigin) {
        self.change_sink.note(origin);
    }

    /// Publish a local delta to the gossip network.
    ///
    /// Call this after making local changes to propagate them to other peers.
    ///
    /// # Arguments
    ///
    /// * `local_peer_id` - The local peer's ID
    /// * `delta` - The delta to publish
    ///
    /// # Returns
    ///
    /// Ok(()) if published successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or publishing fails.
    pub async fn publish_delta(&self, local_peer_id: PeerId, delta: TaskListDelta) -> Result<()> {
        let plain = encode_delta(local_peer_id, &delta).map_err(|e| {
            crate::crdt::CrdtError::Gossip(format!("failed to serialize delta: {e}"))
        })?;
        seal_and_publish(
            self.protector.get(),
            &self.pubsub,
            &self.topic,
            local_peer_id,
            KvMutationKind::Delta,
            plain,
        )
        .await
    }

    /// Arm on-disk snapshot persistence for this list.
    ///
    /// After this call the full list state is snapshotted through
    /// `storage` after every local mutation and every merged remote delta.
    /// Must be called BEFORE [`start`](Self::start) so no merged delta can
    /// land unpersisted (the daemon's persistent create/join paths write an
    /// initial snapshot immediately after arming — see
    /// [`persist`](Self::persist)).
    pub fn set_persistence(&self, storage: TaskListStorage, list_id: TaskListId) {
        if let Ok(mut guard) = self.persist.lock() {
            *guard = Some(Arc::new(TaskPersistCtx {
                storage,
                list_id,
                gate: tokio::sync::Mutex::new(None),
                degraded: std::sync::atomic::AtomicBool::new(false),
                #[cfg(test)]
                persisted: tokio::sync::watch::Sender::new(0),
            }));
        }
    }

    fn persist_ctx(&self) -> Option<Arc<TaskPersistCtx>> {
        self.persist.lock().ok().and_then(|g| g.clone())
    }

    /// Snapshot the list to the configured storage (`Ok` no-op when
    /// persistence is not armed).
    ///
    /// On success the last durably-persisted version advances, so repeat or
    /// racing persists can never regress durable state. On failure the list
    /// is flagged **durability-degraded**
    /// ([`durability_degraded`](Self::durability_degraded)) and this returns
    /// `Err`: callers on the LOCAL-mutation path must surface it (and not
    /// publish the delta — durability before announcement); the remote-merge
    /// path only logs, so a failing disk never wedges replication.
    ///
    /// # Errors
    ///
    /// Serialization or I/O failure writing the snapshot.
    pub async fn persist(&self) -> Result<()> {
        match self.persist_ctx() {
            Some(ctx) => persist_snapshot(&self.task_list, &ctx).await,
            None => Ok(()),
        }
    }

    /// Whether a prior snapshot write failed and has not yet succeeded
    /// again. Local mutations are refused in this state (fail-closed).
    pub fn durability_degraded(&self) -> bool {
        self.persist_ctx()
            .is_some_and(|c| c.degraded.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// If the list is durability-degraded, retry persisting the CURRENT
    /// state before any new mutation is accepted. `Ok` when not degraded,
    /// not persistent, or the retry succeeded.
    ///
    /// # Errors
    ///
    /// The retry failed — the caller must refuse the local mutation.
    pub async fn ensure_durable(&self) -> Result<()> {
        match self.persist_ctx() {
            Some(ctx) if ctx.degraded.load(std::sync::atomic::Ordering::Relaxed) => {
                persist_snapshot(&self.task_list, &ctx).await
            }
            _ => Ok(()),
        }
    }

    /// Get a read-only reference to the task list.
    ///
    /// Useful for querying the current state without modifying it.
    ///
    /// # Returns
    ///
    /// A read guard to the TaskList.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, TaskList> {
        self.task_list.read().await
    }

    /// Get a mutable reference to the task list.
    ///
    /// Use this to make local changes. After modifying, call `publish_delta`
    /// to propagate changes to peers.
    ///
    /// # Returns
    ///
    /// A write guard to the TaskList.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, TaskList> {
        self.task_list.write().await
    }

    /// Get the topic name for this task list.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{TaskId, TaskItem, TaskListId, TaskMetadata};
    use crate::identity::AgentId;
    use crate::network::{NetworkConfig, NetworkNode};
    use std::time::Duration;

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

    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..NetworkConfig::default()
        }
    }

    async fn make_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        )
    }

    async fn make_sync(topic: &str) -> TaskListSync {
        let node = make_node().await;
        let pubsub = Arc::new(
            PubSubManager::new(node, crate::gossip::pubsub::test_support::signing_context())
                .expect("pubsub"),
        );
        let list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        TaskListSync::new(list, pubsub, topic.to_string(), peer(1)).expect("task list sync")
    }

    async fn signed_pubsub() -> Arc<PubSubManager> {
        signed_pubsub_with_signer().await.0
    }

    async fn signed_pubsub_with_signer() -> (Arc<PubSubManager>, AgentId) {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        let signer = kp.agent_id();
        let signing = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        (
            Arc::new(PubSubManager::new(node, signing).expect("pubsub")),
            signer,
        )
    }

    async fn make_sync_with_pubsub(topic: &str) -> (TaskListSync, Arc<PubSubManager>) {
        sync_on_pubsub(topic, signed_pubsub().await)
    }

    async fn make_sync_with_pubsub_signed_by(
        topic: &str,
        kp: &crate::identity::AgentKeypair,
    ) -> (TaskListSync, Arc<PubSubManager>) {
        sync_on_pubsub(topic, pubsub_signed_by(kp).await)
    }

    fn sync_on_pubsub(
        topic: &str,
        pubsub: Arc<PubSubManager>,
    ) -> (TaskListSync, Arc<PubSubManager>) {
        let list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        let sync = TaskListSync::new(list, Arc::clone(&pubsub), topic.to_string(), peer(1))
            .expect("task list sync");
        (sync, pubsub)
    }

    #[tokio::test]
    async fn test_task_list_sync_creation() {
        let peer = peer(1);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test List".to_string(), peer);

        let _list_for_sync = task_list;
    }

    #[tokio::test]
    async fn test_apply_delta() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test".to_string(), peer1);

        let task_list_arc = Arc::new(RwLock::new(task_list));

        let mut delta = TaskListDelta::new(1);
        let task = make_task(1, peer2);
        let task_id = *task.id();
        let tag = (peer2, 1);
        delta.added_tasks.insert(task_id, (task, tag));

        {
            let mut list = task_list_arc.write().await;
            let result = list.merge_delta(&delta, peer2, Some(&agent(2)));
            assert!(result.is_ok());
        }

        {
            let list = task_list_arc.read().await;
            assert_eq!(list.task_count(), 1);
        }
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let peer = peer(1);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test".to_string(), peer);
        let task_list_arc = Arc::new(RwLock::new(task_list));

        let list1 = task_list_arc.read().await;
        let list2 = task_list_arc.read().await;

        assert_eq!(list1.name(), "Test");
        assert_eq!(list2.name(), "Test");

        drop(list1);
        drop(list2);

        {
            let mut list = task_list_arc.write().await;
            list.update_name("Updated".to_string(), peer);
        }

        let list = task_list_arc.read().await;
        assert_eq!(list.name(), "Updated");
    }

    #[tokio::test]
    async fn new_sets_topic_and_yields_accessible_guards() {
        let sync = make_sync("tasks/A").await;

        assert_eq!(sync.topic(), "tasks/A");

        {
            let list = sync.read().await;
            assert_eq!(list.name(), "Test List");
            assert_eq!(list.task_count(), 0);
        }

        {
            let mut list = sync.write().await;
            list.update_name("Renamed".to_string(), peer(1));
        }
        let list = sync.read().await;
        assert_eq!(list.name(), "Renamed", "write-guard rename must be visible");
    }

    #[tokio::test]
    async fn state_sync_topic_appends_side_channel_suffix() {
        let sync = make_sync("tasks/B").await;
        assert_eq!(sync.state_sync_topic(), "tasks/B/state-sync");

        let sync2 = make_sync("tasks/B/nested").await;
        assert_eq!(sync2.state_sync_topic(), "tasks/B/nested/state-sync");
    }

    #[tokio::test]
    async fn apply_remote_delta_merges_task_into_list() {
        let sync = make_sync("tasks/C").await;

        assert_eq!(sync.read().await.task_count(), 0);

        let remote = peer(2);
        let task = make_task(7, remote);
        let task_id = *task.id();
        let mut delta = TaskListDelta::new(1);
        delta.added_tasks.insert(task_id, (task, (remote, 1)));

        let alice = agent(1);
        sync.apply_remote_delta(remote, delta, Some(&alice))
            .await
            .expect("apply_remote_delta");

        let list = sync.read().await;
        assert_eq!(list.task_count(), 1, "merged task must bump the count");
        assert!(
            list.get_task(&task_id).is_some(),
            "merged task must be retrievable by id"
        );
    }

    #[tokio::test]
    async fn publish_delta_delivers_encoded_pair_to_subscriber() {
        let (sync, pubsub) = make_sync_with_pubsub("tasks/D").await;

        let mut sub = pubsub.subscribe("tasks/D".to_string()).await;

        let sender = peer(7);
        let task = make_task(3, sender);
        let task_id = *task.id();
        let mut delta = TaskListDelta::new(9);
        delta.added_tasks.insert(task_id, (task, (sender, 3)));

        sync.publish_delta(sender, delta)
            .await
            .expect("publish_delta");

        let msg = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .expect("timed out waiting for published delta")
            .expect("subscriber stream closed");

        let (observed_sender, observed_delta) =
            decode_delta::<TaskListDelta>(&msg.payload).expect("wire decode");
        assert_eq!(observed_sender, sender);
        assert_eq!(observed_delta.version, 9);
        assert!(
            observed_delta.added_tasks.contains_key(&task_id),
            "published delta must carry the task"
        );
        assert_eq!(msg.topic, "tasks/D");
    }

    const SEALED_TITLE: &str = "SEALED-TITLE-895";
    const SEALED_DESCRIPTION: &str = "SEALED-DESCRIPTION-895";

    struct GssFixtureProtector {
        info: crate::groups::GroupInfo,
        topic: String,
        signing: crate::kv::encrypted::AuthorSigning,
        public: bool,
        rejected: std::sync::atomic::AtomicU64,
        refuse_open: std::sync::atomic::AtomicBool,
        fail_seal: std::sync::atomic::AtomicBool,
    }

    impl GssFixtureProtector {
        fn new(
            info: crate::groups::GroupInfo,
            topic: &str,
            kp: &crate::identity::AgentKeypair,
        ) -> Arc<Self> {
            Arc::new(Self {
                info,
                topic: topic.to_string(),
                signing: crate::kv::encrypted::AuthorSigning::from_keypair(kp).expect("signing"),
                public: false,
                rejected: std::sync::atomic::AtomicU64::new(0),
                refuse_open: std::sync::atomic::AtomicBool::new(false),
                fail_seal: std::sync::atomic::AtomicBool::new(false),
            })
        }

        fn rejected(&self) -> u64 {
            self.rejected.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl TaskDeltaProtector for GssFixtureProtector {
        fn seal<'a>(
            &'a self,
            kind: KvMutationKind,
            payload: &'a [u8],
        ) -> crate::crdt::sealed::TaskSealFuture<
            'a,
            Option<crate::crdt::sealed::SealedTaskRecordBody>,
        > {
            Box::pin(async move {
                if self.fail_seal.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(crate::crdt::CrdtError::Gossip("no group key".to_string()));
                }
                if self.public {
                    return Ok(None);
                }
                crate::crdt::sealed::seal_gss_task_payload(
                    &self.info,
                    &self.signing,
                    kind,
                    &self.topic,
                    payload,
                )
                .map(Some)
            })
        }

        fn open<'a>(
            &'a self,
            body: &'a crate::crdt::sealed::SealedTaskRecordBody,
        ) -> crate::crdt::sealed::TaskSealFuture<'a, crate::crdt::sealed::OpenedTaskPayload>
        {
            Box::pin(async move {
                if self.refuse_open.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(crate::crdt::CrdtError::Gossip(
                        "group is fork-quarantined".to_string(),
                    ));
                }
                match body {
                    crate::crdt::sealed::SealedTaskRecordBody::Gss(record) => {
                        crate::crdt::sealed::open_gss_task_record(&self.info, &self.topic, record)
                    }
                    crate::crdt::sealed::SealedTaskRecordBody::TreeKem(_) => Err(
                        crate::crdt::CrdtError::Gossip("fixture is GSS-only".to_string()),
                    ),
                }
            })
        }

        fn admits_plaintext(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
            Box::pin(async move { self.public })
        }

        fn on_rejected(&self, _reason: TaskSealRejection) {
            self.rejected
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn local_agent(&self) -> Option<AgentId> {
            Some(self.signing.agent_id)
        }

        fn confirm_publication<'a>(
            &'a self,
            _body: &'a crate::crdt::sealed::SealedTaskRecordBody,
        ) -> crate::crdt::sealed::TaskSealFuture<'a, TaskPublication> {
            Box::pin(async {
                Ok(TaskPublication::Current(
                    crate::crdt::sealed::TaskPublicationPermit::none(),
                ))
            })
        }
    }

    fn gss_group(member: AgentId) -> crate::groups::GroupInfo {
        let mut info =
            crate::groups::GroupInfo::new("g895".to_string(), String::new(), member, "g895".into());
        info.migrate_from_v1();
        let _ = info.rotate_shared_secret();
        info
    }

    fn secret_task_delta(from: PeerId) -> (TaskId, TaskListDelta) {
        let task = TaskItem::new(
            TaskId::from_bytes([95; 32]),
            TaskMetadata::new(SEALED_TITLE, SEALED_DESCRIPTION, 128, agent(1), 1000),
            from,
        );
        let id = *task.id();
        let mut delta = TaskListDelta::new(1);
        delta.added_tasks.insert(id, (task, (from, 1)));
        (id, delta)
    }

    fn carries(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    async fn pubsub_signed_by(kp: &crate::identity::AgentKeypair) -> Arc<PubSubManager> {
        let signing = Arc::new(crate::gossip::SigningContext::from_keypair(kp));
        Arc::new(PubSubManager::new(make_node().await, signing).expect("pubsub"))
    }

    #[tokio::test]
    async fn group_list_publish_hands_gossip_only_sealed_bytes() {
        let topic = "x0x.group.g895.symphony.wire";
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let (sync, pubsub) = make_sync_with_pubsub(topic).await;
        let protector = GssFixtureProtector::new(gss_group(kp.agent_id()), topic, &kp);
        assert!(sync.install_protector(protector.clone()));
        let mut probe = pubsub.subscribe(topic.to_string()).await;

        let (task_id, delta) = secret_task_delta(peer(1));
        sync.publish_delta(peer(1), delta).await.expect("publish");
        let msg = tokio::time::timeout(Duration::from_secs(2), probe.recv())
            .await
            .expect("published record")
            .expect("probe open");

        assert!(!carries(&msg.payload, SEALED_TITLE), "title on the wire");
        assert!(
            !carries(&msg.payload, SEALED_DESCRIPTION),
            "description on the wire"
        );
        assert!(
            decode_delta::<TaskListDelta>(&msg.payload)
                .map_or(true, |(_, d)| !d.added_tasks.contains_key(&task_id)),
            "the published bytes must not decode as a plaintext delta"
        );
        let (_, body) =
            crate::crdt::sealed::decode_sealed_task_record(&msg.payload).expect("sealed record");
        let opened = protector.open(&body).await.expect("member opens");
        let (_, inner) = decode_delta::<TaskListDelta>(&opened.payload).expect("inner delta");
        assert!(inner.added_tasks.contains_key(&task_id));
    }

    #[tokio::test]
    async fn group_list_state_serve_is_sealed() {
        let topic = "x0x.group.g895.symphony.serve";
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let (sync, pubsub) = make_sync_with_pubsub_signed_by(topic, &kp).await;
        assert!(sync.install_protector(GssFixtureProtector::new(
            gss_group(kp.agent_id()),
            topic,
            &kp
        )));
        {
            let (_, delta) = secret_task_delta(peer(1));
            let (task, _) = delta.added_tasks.into_values().next().expect("task");
            sync.write().await.add_task(task, peer(1), 1).expect("seed");
        }
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut probe = pubsub.subscribe(topic.to_string()).await;
        let request = bincode::serialize(&TaskListSyncMessage::StateRequest { requester: peer(9) })
            .expect("request");
        pubsub
            .publish(sync.state_sync_topic(), bytes::Bytes::from(request))
            .await
            .expect("publish request");
        let msg = tokio::time::timeout(Duration::from_secs(2), probe.recv())
            .await
            .expect("full-state serve")
            .expect("probe open");
        assert!(crate::crdt::sealed::decode_sealed_task_record(&msg.payload).is_some());
        assert!(!carries(&msg.payload, SEALED_TITLE));
        assert!(!carries(&msg.payload, SEALED_DESCRIPTION));
    }

    #[tokio::test]
    async fn member_opens_and_applies_sealed_delta() {
        let topic = "x0x.group.g895.symphony.member";
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let info = gss_group(kp.agent_id());
        let pubsub = pubsub_signed_by(&kp).await;
        let sender = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(1)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
        )
        .expect("sender");
        let receiver = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(2)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
        )
        .expect("receiver");
        assert!(sender.install_protector(GssFixtureProtector::new(info.clone(), topic, &kp)));
        let receiver_protector = GssFixtureProtector::new(info, topic, &kp);
        assert!(receiver.install_protector(receiver_protector.clone()));
        receiver.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (task_id, delta) = secret_task_delta(peer(1));
        sender.publish_delta(peer(1), delta).await.expect("publish");
        let landed = eventually(Duration::from_secs(3), || async {
            receiver.read().await.get_task(&task_id).is_some()
        })
        .await;
        assert!(landed, "a member must apply the sealed delta");
        assert_eq!(receiver_protector.rejected(), 0);
    }

    #[tokio::test]
    async fn removed_member_and_plaintext_fail_closed() {
        let topic = "x0x.group.g895.symphony.removed";
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let at_n = gss_group(kp.agent_id());
        let mut at_n1 = at_n.clone();
        let _ = at_n1.rotate_shared_secret();
        let pubsub = pubsub_signed_by(&kp).await;
        let sender = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(1)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
        )
        .expect("sender");
        let removed = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(2)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
        )
        .expect("removed member");
        assert!(sender.install_protector(GssFixtureProtector::new(at_n1, topic, &kp)));
        let stale = GssFixtureProtector::new(at_n, topic, &kp);
        assert!(removed.install_protector(stale.clone()));
        removed.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (sealed_id, delta) = secret_task_delta(peer(1));
        sender.publish_delta(peer(1), delta).await.expect("publish");
        let plain_task = make_task(42, peer(3));
        let plain_id = *plain_task.id();
        let mut plain = TaskListDelta::new(2);
        plain
            .added_tasks
            .insert(plain_id, (plain_task, (peer(3), 1)));
        pubsub
            .publish(
                topic.to_string(),
                bytes::Bytes::from(encode_delta(peer(3), &plain).expect("encode")),
            )
            .await
            .expect("publish plaintext");

        let both_refused =
            eventually(Duration::from_secs(3), || async { stale.rejected() >= 2 }).await;
        assert!(both_refused, "both deltas must be refused and counted");
        let list = removed.read().await;
        assert!(
            list.get_task(&sealed_id).is_none(),
            "N+1 record applied with N key"
        );
        assert!(
            list.get_task(&plain_id).is_none(),
            "plaintext applied to a group list"
        );
    }

    #[tokio::test]
    async fn sealed_delta_during_quarantine_is_buffered_then_applied() {
        let topic = "x0x.group.g895.symphony.quarantine";
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let info = gss_group(kp.agent_id());
        let pubsub = pubsub_signed_by(&kp).await;
        let sender = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(1)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
        )
        .expect("sender");
        let receiver = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(2)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
        )
        .expect("receiver");
        assert!(sender.install_protector(GssFixtureProtector::new(info.clone(), topic, &kp)));
        let protector = GssFixtureProtector::new(info, topic, &kp);
        protector
            .refuse_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(receiver.install_protector(protector.clone()));
        let gate = Arc::new(ListenerGate::seating(kp.agent_id()));
        gate.suspend(true);
        assert!(receiver
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        receiver.set_drain_poll_millis(600_000);
        receiver.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (task_id, delta) = secret_task_delta(peer(1));
        sender.publish_delta(peer(1), delta).await.expect("publish");
        assert!(
            eventually(Duration::from_secs(5), || async {
                receiver.quarantined_buffer_len() == 1
            })
            .await,
            "the sealed delta must be HELD during the quarantine"
        );
        assert_eq!(protector.rejected(), 0, "held, not refused");
        assert!(receiver.read().await.get_task(&task_id).is_none());

        gate.suspend(false);
        protector
            .refuse_open
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(receiver.resume_quarantined_ingest().await, 1);
        assert!(receiver.read().await.get_task(&task_id).is_some());
        assert_eq!(receiver.quarantined_buffer_len(), 0);
        assert_eq!(protector.rejected(), 0);
    }

    #[tokio::test]
    async fn sealed_author_must_be_the_gossip_sender() {
        let topic = "x0x.group.g895.symphony.mismatch";
        let author = crate::identity::AgentKeypair::generate().expect("author");
        let relayer = crate::identity::AgentKeypair::generate().expect("relayer");
        let info = gss_group(author.agent_id());
        let pubsub = pubsub_signed_by(&relayer).await;
        let sender = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(1)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
        )
        .expect("sender");
        let receiver = TaskListSync::new(
            TaskList::new(list_id(1), "L".to_string(), peer(2)),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
        )
        .expect("receiver");
        assert!(sender.install_protector(GssFixtureProtector::new(info.clone(), topic, &author)));
        let protector = GssFixtureProtector::new(info, topic, &author);
        assert!(receiver.install_protector(protector.clone()));
        receiver.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (task_id, delta) = secret_task_delta(peer(1));
        sender.publish_delta(peer(1), delta).await.expect("publish");
        assert!(
            eventually(Duration::from_secs(3), || async {
                protector.rejected() >= 1
            })
            .await,
            "the mismatched record must be refused and counted"
        );
        assert_eq!(protector.rejected(), 1);
        assert!(
            receiver.read().await.get_task(&task_id).is_none(),
            "a record whose sealed author is not the sender must never merge"
        );
    }

    #[tokio::test]
    async fn seal_failure_publishes_nothing() {
        let topic = "x0x.group.g895.symphony.sealfail";
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let (sync, pubsub) = make_sync_with_pubsub_signed_by(topic, &kp).await;
        let protector = GssFixtureProtector::new(gss_group(kp.agent_id()), topic, &kp);
        protector
            .fail_seal
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(sync.install_protector(protector.clone()));
        {
            let (_, delta) = secret_task_delta(peer(1));
            let (task, _) = delta.added_tasks.into_values().next().expect("task");
            sync.write().await.add_task(task, peer(1), 1).expect("seed");
        }
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut main = pubsub.subscribe(topic.to_string()).await;
        let mut side = pubsub.subscribe(sync.state_sync_topic()).await;

        let (_, delta) = secret_task_delta(peer(1));
        assert!(
            sync.publish_delta(peer(1), delta).await.is_err(),
            "a seal failure must surface as an error"
        );
        let request = bincode::serialize(&TaskListSyncMessage::StateRequest { requester: peer(9) })
            .expect("request");
        pubsub
            .publish(sync.state_sync_topic(), bytes::Bytes::from(request))
            .await
            .expect("publish request");
        assert!(
            tokio::time::timeout(Duration::from_millis(1_000), main.recv())
                .await
                .is_err(),
            "nothing may be published on the list topic when sealing fails"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut saw_our_request = false;
        while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, side.recv()).await {
            let decoded = bincode::deserialize::<TaskListSyncMessage>(&msg.payload);
            if let Ok(TaskListSyncMessage::StateRequest { requester }) = &decoded {
                saw_our_request |= *requester == peer(9);
            }
            let marker = matches!(
                decoded,
                Ok(TaskListSyncMessage::StateServed { .. }
                    | TaskListSyncMessage::StateServedV2 { .. })
            );
            assert!(
                !marker,
                "no served marker without a real (sealed) broadcast"
            );
        }
        assert!(saw_our_request, "the side probe must see our StateRequest");
    }

    #[tokio::test]
    async fn serve_gate_denies_state_requests_it_does_not_admit() {
        let topic = "x0x-board-servegate895";
        let (sync, pubsub, _signer) = make_signed_sync_with_pubsub(topic).await;
        let admit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate_admit = Arc::clone(&admit);
        assert!(sync.install_serve_gate(Arc::new(move |_sender| {
            let admit = gate_admit.load(std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { admit })
        })));
        {
            let (_, delta) = secret_task_delta(peer(1));
            let (task, _) = delta.added_tasks.into_values().next().expect("task");
            sync.write().await.add_task(task, peer(1), 1).expect("seed");
        }
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut main = pubsub.subscribe(topic.to_string()).await;
        let ask = |requester: PeerId| {
            let pubsub = Arc::clone(&pubsub);
            let side = sync.state_sync_topic();
            async move {
                let request = bincode::serialize(&TaskListSyncMessage::StateRequest { requester })
                    .expect("request");
                pubsub
                    .publish(side, bytes::Bytes::from(request))
                    .await
                    .expect("publish request");
            }
        };

        ask(peer(9)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(800), main.recv())
                .await
                .is_err(),
            "a denied requester must get no full-state broadcast"
        );

        admit.store(true, std::sync::atomic::Ordering::SeqCst);
        ask(peer(8)).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), main.recv())
                .await
                .is_ok(),
            "control: an admitted requester is served"
        );
    }

    #[tokio::test]
    async fn personal_list_wire_format_is_unchanged() {
        let (sync, pubsub) = make_sync_with_pubsub("tasks/personal-895").await;
        let mut probe = pubsub.subscribe("tasks/personal-895".to_string()).await;
        let (task_id, delta) = secret_task_delta(peer(1));
        sync.publish_delta(peer(1), delta).await.expect("publish");
        let msg = tokio::time::timeout(Duration::from_secs(2), probe.recv())
            .await
            .expect("published")
            .expect("probe open");
        assert!(crate::crdt::sealed::decode_sealed_task_record(&msg.payload).is_none());
        let (_, observed) = decode_delta::<TaskListDelta>(&msg.payload).expect("plain pair");
        assert!(observed.added_tasks.contains_key(&task_id));
        assert!(carries(&msg.payload, SEALED_TITLE));
    }

    // Smoke test of the custom-spawner path only: a drop-spawner makes the
    // subscription unobservable, so nothing here proves a merge. The real
    // subscribe->merge behaviour is `start_default_spawner_merges_remote_delta`.
    #[tokio::test]
    async fn start_with_spawner_accepts_custom_spawner_and_returns_ok() {
        let sync = make_sync("tasks/E").await;
        sync.start_with_spawner(|_fut| {
            // intentionally drop the future
        })
        .await
        .expect("start_with_spawner");
    }

    #[tokio::test]
    async fn issue1094_a_merged_remote_task_delta_sends_one_change_notice() {
        let (pubsub, publisher) = signed_pubsub_with_signer().await;
        let (sync, _pubsub) = sync_on_pubsub("tasks/1094", pubsub);
        sync.write()
            .await
            .set_authorized_agents(std::collections::HashSet::from([publisher]));
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        sync.set_change_sink(tx);
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let remote = peer(2);
        let task = make_task(7, remote);
        let task_id = *task.id();
        let mut delta = TaskListDelta::new(1);
        delta.added_tasks.insert(task_id, (task, (remote, 1)));
        sync.publish_delta(remote, delta).await.expect("publish");
        let change = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a merged delta sends a notice")
            .expect("notice");
        assert_eq!(
            change,
            TaskListChanged {
                topic: "tasks/1094".to_string(),
                origin: crate::kv::KvChangeOrigin::Remote,
            }
        );
        assert!(sync.read().await.get_task(&task_id).is_some());
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        let other = make_task(8, remote);
        let mut direct = TaskListDelta::new(2);
        direct.added_tasks.insert(*other.id(), (other, (remote, 2)));
        sync.apply_remote_delta(remote, direct, Some(&publisher))
            .await
            .expect("direct delta");
        assert_eq!(
            rx.try_recv().expect("direct notice").origin,
            crate::kv::KvChangeOrigin::Remote
        );
        sync.note_change(crate::kv::KvChangeOrigin::Local);
        assert_eq!(
            rx.try_recv().expect("local notice").origin,
            crate::kv::KvChangeOrigin::Local
        );
    }

    #[tokio::test]
    async fn start_default_spawner_merges_remote_delta() {
        let (pubsub, publisher) = signed_pubsub_with_signer().await;
        let (sync, _pubsub) = sync_on_pubsub("tasks/F", pubsub);
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        let signing = crate::gossip::SigningContext::from_keypair(&kp);
        let claimer = kp.agent_id();
        assert_ne!(publisher, claimer);
        sync.write()
            .await
            .set_authorized_agents(std::collections::HashSet::from([claimer]));

        sync.start().await.expect("start");

        tokio::time::sleep(Duration::from_millis(100)).await;

        let remote = peer(2);
        let existing = make_task(5, remote);
        let existing_id = *existing.id();
        {
            let mut list = sync.write().await;
            list.add_task(existing, remote, 1).expect("seed local task");
        }

        let mut claimed = make_task(5, remote);
        claimed
            .claim(list_id(1), claimer, remote, 1, &signing)
            .expect("attest claim");

        let new_task = make_task(6, remote);
        let new_task_id = *new_task.id();
        let mut delta = TaskListDelta::new(1);
        delta
            .added_tasks
            .insert(new_task_id, (new_task, (remote, 2)));
        delta.task_updates.insert(existing_id, claimed);
        sync.publish_delta(remote, delta).await.expect("publish");

        let claim_applied = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let claimed_landed = sync
                    .read()
                    .await
                    .get_task(&existing_id)
                    .is_some_and(|t| t.current_state().is_claimed());
                if claimed_landed {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        assert!(
            claim_applied.is_ok(),
            "a non-member's signed publish must still reach checkbox admission"
        );

        assert!(
            sync.read().await.get_task(&new_task_id).is_none(),
            "a non-member writer's publish must not create a task (I2/I8)"
        );
        assert_eq!(
            sync.read().await.task_count(),
            1,
            "only the locally seeded task is present"
        );
    }

    #[tokio::test]
    async fn stop_returns_ok_and_is_idempotent() {
        let sync = make_sync("tasks/G").await;
        sync.stop().await.expect("first stop");
        sync.stop().await.expect("second stop (idempotent)");
    }

    #[tokio::test]
    async fn stop_and_silence_arm_their_kill_switches() {
        let sync = make_sync("tasks/stopflag").await;
        assert!(
            !sync.cancel.is_cancelled() && !sync.stopped.load(std::sync::atomic::Ordering::Relaxed),
            "both switches must start disarmed"
        );
        sync.silence_bootstrap();
        assert!(
            sync.stopped.load(std::sync::atomic::Ordering::Relaxed),
            "silence_bootstrap() arms the requester-only flag"
        );
        assert!(
            !sync.cancel.is_cancelled(),
            "silence_bootstrap() must NOT cancel the listener/responder loops"
        );
        sync.stop().await.expect("stop");
        assert!(
            sync.cancel.is_cancelled(),
            "stop() must cancel ALL background loops via the token"
        );
    }

    #[tokio::test]
    async fn dropping_the_sync_cancels_all_loops() {
        let sync = make_sync("tasks/dropcancel").await;
        let token = sync.cancel.clone();
        assert!(!token.is_cancelled());
        drop(sync);
        assert!(
            token.is_cancelled(),
            "dropping the last sync reference must cancel every loop"
        );
    }

    #[test]
    fn state_request_schedule_never_terminates_while_unconverged() {
        let front: Vec<u64> = state_request_delays().take(4).collect();
        assert_eq!(front, STATE_REQUEST_RETRY_SECS, "front burst unchanged");
        let tail: Vec<u64> = state_request_delays().skip(4).take(8).collect();
        assert_eq!(
            tail,
            [30, 60, 120, 240, 300, 300, 300, 300],
            "tail doubles to the cap, then holds it"
        );
        assert_eq!(
            state_request_delays().nth(10_000),
            Some(STATE_REQUEST_TAIL_CAP_SECS),
            "the schedule is infinite — convergence, not the schedule, \
             is what ends the requester"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn single_incremental_delta_does_not_stop_recovery() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-238-bait";

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        tokio::time::sleep(Duration::from_secs(70)).await;

        let bait_task = make_task(2, peer(3));
        let bait_id = *bait_task.id();
        let mut bait = TaskListDelta::new(1);
        bait.added_tasks.insert(bait_id, (bait_task, (peer(3), 1)));
        let encoded = encode_delta(peer(3), &bait).expect("encode bait");
        pubsub
            .publish(topic.to_string(), bytes::Bytes::from(encoded))
            .await
            .expect("publish bait");
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(
            joiner.read().await.task_count(),
            1,
            "bait delta merged — the false-convergence precondition holds"
        );

        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("holder task 1");
        holder_list
            .add_task(make_task(2, peer(1)), peer(1), 2)
            .expect("holder task 2");
        let holder =
            TaskListSync::new(holder_list, Arc::clone(&pubsub), topic.to_string(), peer(1))
                .expect("holder sync");
        holder.start().await.expect("start holder");

        let historical = TaskId::from_bytes([1; 32]);
        let mut converged = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get_task(&historical).is_some() {
                converged = true;
                break;
            }
        }
        assert!(
            converged,
            "the requester must survive the bait delta and recover the \
             historical task from the late holder"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn requester_recovers_when_holder_returns_after_old_hard_cap() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-238-zombie";

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        tokio::time::sleep(Duration::from_secs(700)).await;
        assert_eq!(
            joiner.read().await.task_count(),
            0,
            "nobody was online to answer"
        );

        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("add task");
        let holder =
            TaskListSync::new(holder_list, Arc::clone(&pubsub), topic.to_string(), peer(1))
                .expect("holder sync");
        holder.start().await.expect("start holder");

        let mut converged = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.task_count() > 0 {
                converged = true;
                break;
            }
        }
        assert!(
            converged,
            "the infinite tail must recover state from a holder that \
             returns after the old hard cap (zombie subscription, issue #238)"
        );
    }

    async fn drain_state_requests(probe: &mut crate::gossip::Subscription, from: PeerId) -> usize {
        let mut n = 0;
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(1), probe.recv()).await
        {
            if let Ok(TaskListSyncMessage::StateRequest { requester }) =
                bincode::deserialize::<TaskListSyncMessage>(&msg.payload)
            {
                if requester == from {
                    n += 1;
                }
            }
        }
        n
    }

    #[test]
    fn tasklist_convergence_rule() {
        const D1: [u8; 32] = [1u8; 32];
        const D2: [u8; 32] = [2u8; 32];
        const D_EMPTY: [u8; 32] = [9u8; 32];
        let none = TaskServedEvidence::default();
        assert!(!tasklist_converged(&none, 0, D1));
        assert!(!tasklist_converged(&none, 5, D1));

        let v1 = TaskServedEvidence {
            saw_v1: true,
            digests: std::collections::HashMap::new(),
        };
        assert!(!tasklist_converged(&v1, 0, D1));
        assert!(tasklist_converged(&v1, 3, D1));

        let mut ev = TaskServedEvidence::default();
        ev.digests.insert(
            peer(9),
            ServedState {
                digest: D1,
                entry_count: 2,
            },
        );
        assert!(tasklist_converged(&ev, 2, D1));
        assert!(!tasklist_converged(&ev, 1, D2));
        ev.saw_v1 = true;
        assert!(
            !tasklist_converged(&ev, 1, D2),
            "v2 declarations outrank weak v1 evidence"
        );

        let mut ev_empty = TaskServedEvidence::default();
        ev_empty.digests.insert(
            peer(9),
            ServedState {
                digest: D_EMPTY,
                entry_count: 0,
            },
        );
        assert!(tasklist_converged(&ev_empty, 0, D_EMPTY));
        ev_empty.digests.insert(
            peer(10),
            ServedState {
                digest: D1,
                entry_count: 2,
            },
        );
        assert!(
            !tasklist_converged(&ev_empty, 0, D_EMPTY),
            "a data-bearing declaration outranks the empty one — keep asking"
        );
        assert!(tasklist_converged(&ev_empty, 2, D1));
    }

    #[test]
    fn served_digest_is_deterministic_content_bound_and_metadata_independent() {
        let mut a = TaskList::new(list_id(1), "alpha".to_string(), peer(1));
        let mut b = TaskList::new(list_id(1), "beta".to_string(), peer(2));
        assert_eq!(
            a.served_digest(),
            b.served_digest(),
            "empty lists with the same id digest alike (name is not content)"
        );
        let c = TaskList::new(list_id(2), "alpha".to_string(), peer(1));
        assert_ne!(
            a.served_digest(),
            c.served_digest(),
            "the list id binds the digest (cross-list replay defense)"
        );

        let task = make_task(7, peer(3));
        a.add_task(task.clone(), peer(1), 1).expect("add a");
        b.add_task(task, peer(2), 1).expect("add b");
        assert_eq!(a.served_digest(), b.served_digest());

        let full = a.full_delta();
        assert_eq!(full.served_digest(&list_id(1)), Some(a.served_digest()));
        let inc = TaskListDelta::for_add(
            TaskId::from_bytes([8; 32]),
            make_task(8, peer(1)),
            (peer(1), 1),
            2,
        );
        assert_eq!(inc.served_digest(&list_id(1)), None);

        b.add_task(make_task(9, peer(2)), peer(2), 2)
            .expect("add b2");
        assert_ne!(a.served_digest(), b.served_digest());
    }

    #[tokio::test(start_paused = true)]
    async fn lost_full_delta_with_surviving_marker_keeps_requester_asking() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-lost-broadcast";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("holder t1");
        holder_list
            .add_task(make_task(2, peer(1)), peer(1), 2)
            .expect("holder t2");

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        let mut probe = pubsub.subscribe(side.clone()).await;
        joiner.start().await.expect("start joiner");

        let t2_only = {
            let full = holder_list.full_delta();
            let (id, (task, tag)) = full
                .added_tasks
                .iter()
                .find(|(id, _)| *id.as_bytes() == [2; 32])
                .expect("t2 in full delta");
            let mut d = TaskListDelta::new(1);
            d.added_tasks.insert(*id, (task.clone(), *tag));
            d
        };
        joiner
            .write()
            .await
            .merge_delta(&t2_only, peer(1), Some(&agent(1)))
            .expect("seed t2");

        let marker = TaskListSyncMessage::StateServedV2 {
            responder: peer(1),
            digest: holder_list.served_digest(),
            entry_count: 2,
        };
        let bytes = bincode::serialize(&marker).expect("serialize marker");
        pubsub
            .publish(side.clone(), bytes::Bytes::from(bytes))
            .await
            .expect("publish marker");

        let mut requests = 0;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            requests += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert!(
            requests > 0,
            "a requester whose full delta was lost must keep asking (digest mismatch)"
        );
        assert_eq!(
            joiner.read().await.task_count(),
            1,
            "the lost broadcast never arrived"
        );

        let holder =
            TaskListSync::new(holder_list, Arc::clone(&pubsub), topic.to_string(), peer(1))
                .expect("holder sync");
        holder.start().await.expect("start holder");

        let historical = TaskId::from_bytes([1; 32]);
        let mut recovered = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get_task(&historical).is_some() {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "the still-alive requester must recover the lost task"
        );

        tokio::time::sleep(Duration::from_secs(160)).await;
        drain_state_requests(&mut probe, peer(2)).await;
        let mut relapse = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            relapse += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert_eq!(relapse, 0, "a digest-matched requester must fall silent");
    }

    #[tokio::test(start_paused = true)]
    async fn digest_verified_full_serve_prunes_stale_tasks() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-prune-stale";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("holder t1");
        holder_list
            .add_task(make_task(9, peer(2)), peer(2), 1)
            .expect("holder t_stale (once merged from the replica)");
        holder_list
            .remove_task(&TaskId::from_bytes([9; 32]))
            .expect("holder deletes t_stale");

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        let mut probe = pubsub.subscribe(side.clone()).await;
        joiner.start().await.expect("start joiner");
        let t1_only = {
            let full = holder_list.full_delta();
            let (id, (task, tag)) = full
                .added_tasks
                .iter()
                .find(|(id, _)| *id.as_bytes() == [1; 32])
                .expect("t1 in full delta");
            let mut d = TaskListDelta::new(1);
            d.added_tasks.insert(*id, (task.clone(), *tag));
            d
        };
        {
            let mut l = joiner.write().await;
            l.merge_delta(&t1_only, peer(1), Some(&agent(1)))
                .expect("seed t1");
            l.add_task(make_task(9, peer(2)), peer(2), 1)
                .expect("seed stale task");
        }

        let holder =
            TaskListSync::new(holder_list, Arc::clone(&pubsub), topic.to_string(), peer(1))
                .expect("holder sync");
        holder.start().await.expect("start holder");

        let stale = TaskId::from_bytes([9; 32]);
        let mut pruned = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let l = joiner.read().await;
            if l.get_task(&stale).is_none() && l.task_count() == 1 {
                pruned = true;
                break;
            }
        }
        assert!(
            pruned,
            "the digest-verified full serve must prune the stale task \
             (deletion cold-sync)"
        );

        tokio::time::sleep(Duration::from_secs(160)).await;
        drain_state_requests(&mut probe, peer(2)).await;
        let mut relapse = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            relapse += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert_eq!(relapse, 0, "the requester must stop once the digests match");
    }

    #[tokio::test(start_paused = true)]
    async fn stale_full_serve_after_live_add_must_not_prune_the_live_task() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-643-stale-serve-race";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(0, peer(1)), peer(1), 1)
            .expect("holder t0");
        let (stale_serve, stale_digest, stale_count) = {
            let digest = holder_list.served_digest();
            let count = holder_list.task_count() as u32;
            (holder_list.full_delta(), digest, count)
        };
        assert_eq!(stale_count, 1, "the stale serve must be production-shaped");
        assert_eq!(stale_count as usize, stale_serve.added_tasks.len());
        assert!(
            stale_serve.removed_tasks.is_empty(),
            "no deletion evidence in flight — only absence"
        );

        let task = make_task(5, peer(1));
        let tid = *task.id();
        let add_seq = holder_list.next_seq();
        holder_list
            .add_task(task.clone(), peer(1), add_seq)
            .expect("holder add");
        let add_delta =
            TaskListDelta::for_add(tid, task, (peer(1), add_seq), holder_list.current_version());

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        let mut probe = pubsub.subscribe(side.clone()).await;
        joiner.start().await.expect("start joiner");

        let bytes = encode_delta(peer(1), &add_delta).expect("encode add");
        pubsub
            .publish(topic.to_string(), bytes::Bytes::from(bytes))
            .await
            .expect("publish add");
        let mut visible = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if joiner.read().await.get_task(&tid).is_some() {
                visible = true;
                break;
            }
        }
        assert!(visible, "the add delta must make the task visible");

        let marker = TaskListSyncMessage::StateServedV2 {
            responder: peer(1),
            digest: stale_digest,
            entry_count: stale_count,
        };
        let bytes = bincode::serialize(&marker).expect("serialize marker");
        pubsub
            .publish(side.clone(), bytes::Bytes::from(bytes))
            .await
            .expect("publish marker");
        let bytes = encode_delta(peer(1), &stale_serve).expect("encode serve");
        pubsub
            .publish(topic.to_string(), bytes::Bytes::from(bytes))
            .await
            .expect("publish serve");

        let mut cycles = 0;
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            cycles += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert!(
            cycles >= 2,
            "the unconverged joiner keeps asking; cycles={cycles}"
        );

        assert!(
            joiner.read().await.get_task(&tid).is_some(),
            "a stale serve must not prune a task the replica merged after \
             its last state request (adds-win)"
        );
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        let signing = crate::gossip::SigningContext::from_keypair(&kp);
        {
            let mut l = joiner.write().await;
            let seq = l.next_seq();
            l.claim_task(&tid, kp.agent_id(), peer(2), seq, &signing)
                .expect("claim must succeed — the task the read saw is present");
        }

        joiner.cancel_sync();
    }

    #[tokio::test(start_paused = true)]
    async fn empty_holder_v2_marker_terminates_empty_requester() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-empty-silence";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        let holder =
            TaskListSync::new(holder_list, Arc::clone(&pubsub), topic.to_string(), peer(1))
                .expect("holder sync");
        holder.start().await.expect("start holder");
        let mut probe = pubsub.subscribe(side.clone()).await;

        tokio::time::sleep(Duration::from_secs(160)).await;
        let warm = drain_state_requests(&mut probe, peer(2)).await;
        assert!(warm > 0, "the probe must hear the joiner's front requests");
        let mut late = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            late += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert_eq!(
            late, 0,
            "an empty holder's verifiable digest must terminate the empty \
             requester's tail (genuinely-empty lists converge silently)"
        );
    }

    /// WHY: wire compatibility is additive — a fleet with only v1 (older)
    /// responders must behave exactly as before: a v1 marker plus local
    /// state converges the requester. The v2 machinery must not require
    /// v2 markers to make progress against old peers.
    #[tokio::test(start_paused = true)]
    async fn v1_marker_from_old_peer_still_converges() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-v1-compat";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        tokio::time::sleep(Duration::from_secs(20)).await;
        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("holder t1");
        let full = holder_list.full_delta();
        let encoded = encode_delta(peer(1), &full).expect("encode full");
        pubsub
            .publish(topic.to_string(), bytes::Bytes::from(encoded))
            .await
            .expect("publish full delta");
        let marker = TaskListSyncMessage::StateServed { responder: peer(1) };
        let marker_bytes = bincode::serialize(&marker).expect("serialize v1 marker");
        pubsub
            .publish(side.clone(), bytes::Bytes::from(marker_bytes))
            .await
            .expect("publish v1 marker");

        let historical = TaskId::from_bytes([1; 32]);
        let mut recovered = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get_task(&historical).is_some() {
                recovered = true;
                break;
            }
        }
        assert!(recovered, "the old peer's full delta must merge");

        tokio::time::sleep(Duration::from_secs(160)).await;
        drain_state_requests(&mut probe, peer(2)).await;
        let mut late = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            late += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert_eq!(
            late, 0,
            "v1 evidence from an old peer must still converge the requester"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tampered_digest_is_rejected_and_does_not_wedge_recovery() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-tampered";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        let marker = TaskListSyncMessage::StateServedV2 {
            responder: peer(1),
            digest: [0xAB; 32],
            entry_count: 2,
        };
        let bytes = bincode::serialize(&marker).expect("serialize marker");
        pubsub
            .publish(side.clone(), bytes::Bytes::from(bytes))
            .await
            .expect("publish tampered marker");

        let mut requests = 0;
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            requests += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert!(
            requests > 0,
            "a tampered digest must not converge the requester"
        );
        assert_eq!(
            joiner.read().await.task_count(),
            0,
            "no state can have been adopted from a forged declaration"
        );

        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("holder t1");
        let holder =
            TaskListSync::new(holder_list, Arc::clone(&pubsub), topic.to_string(), peer(1))
                .expect("holder sync");
        holder.start().await.expect("start holder");

        let historical = TaskId::from_bytes([1; 32]);
        let mut recovered = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get_task(&historical).is_some() {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "a tampered marker must not wedge recovery from a genuine holder"
        );
    }

    #[test]
    fn pruned_task_is_accepted_when_re_served_with_fresh_tags() {
        let mut holder = TaskList::new(list_id(1), "List".to_string(), peer(1));
        holder
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("add t1");
        holder
            .add_task(make_task(2, peer(1)), peer(1), 2)
            .expect("add t2");

        let mut replica = TaskList::new(list_id(1), "List".to_string(), peer(2));
        let s1 = holder.full_delta();
        replica
            .merge_delta(&s1, peer(1), Some(&agent(1)))
            .expect("serve 1");
        assert_eq!(replica.task_count(), 2);

        let doomed = TaskId::from_bytes([2; 32]);
        holder.remove_task(&doomed).expect("delete");
        let s2 = holder.full_delta();
        assert_eq!(
            s2.served_digest(&list_id(1)),
            Some(holder.served_digest()),
            "the serve must carry the holder's declared digest"
        );
        replica
            .merge_delta(&s2, peer(1), Some(&agent(1)))
            .expect("serve 2");
        assert_eq!(replica.prune_to_served_set(&s2, Some(&agent(1))), 1);
        assert!(replica.get_task(&doomed).is_none());

        holder
            .add_task(make_task(2, peer(1)), peer(1), 3)
            .expect("re-add");
        let s3 = holder.full_delta();
        replica
            .merge_delta(&s3, peer(1), Some(&agent(1)))
            .expect("serve 3");
        assert!(
            replica.get_task(&doomed).is_some(),
            "a re-served task must be accepted after a prune"
        );
    }

    #[test]
    fn delete_then_reorder_full_serve_still_prunes_without_resurrection() {
        let t1 = TaskId::from_bytes([1; 32]);
        let doomed = TaskId::from_bytes([2; 32]);

        let mut holder = TaskList::new(list_id(1), "List".to_string(), peer(1));
        holder
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("add t1");
        holder
            .add_task(make_task(2, peer(1)), peer(1), 2)
            .expect("add doomed");
        holder.remove_task(&doomed).expect("delete doomed");
        holder
            .reorder(vec![t1], peer(1))
            .expect("reorder to live set");

        let serve = holder.full_delta();
        assert!(
            !serve.added_tasks.contains_key(&doomed),
            "deleted task is not served live"
        );
        assert_eq!(
            serve.removed_tasks.get(&doomed).map(|tags| tags.len()),
            Some(0),
            "the monotone evidence carrier still names the deletion"
        );
        assert!(
            !serve
                .ordering_update
                .as_ref()
                .is_some_and(|o| o.get().contains(&doomed)),
            "pin the hazard: the ordering register DID forget the deletion"
        );

        let mut replica = TaskList::new(list_id(1), "List".to_string(), peer(2));
        replica
            .add_task(make_task(1, peer(2)), peer(2), 1)
            .expect("replica t1");
        replica
            .add_task(make_task(2, peer(2)), peer(2), 2)
            .expect("replica doomed (stale — the deletion not yet merged)");
        replica
            .merge_delta(&serve, peer(1), Some(&agent(1)))
            .expect("merge serve");
        assert!(
            replica.get_task(&doomed).is_some(),
            "general merge must not delete on evidence entries"
        );
        assert_eq!(
            replica.prune_to_served_set(&serve, Some(&agent(1))),
            1,
            "the adopt gate prunes on explicit deletion evidence"
        );
        assert!(replica.get_task(&doomed).is_none());
        assert!(replica.get_task(&t1).is_some(), "live task survives");

        let re_serve = replica.full_delta();
        assert!(
            !re_serve.added_tasks.contains_key(&doomed),
            "a pruned replica must not re-serve the deleted task"
        );
        assert_eq!(
            re_serve.removed_tasks.get(&doomed).map(|tags| tags.len()),
            Some(0),
            "the replica forwards the deletion evidence onward"
        );
    }

    #[test]
    fn ordering_entry_without_add_or_evidence_is_not_pruned() {
        let phantom = TaskId::from_bytes([7; 32]);

        let mut holder = TaskList::new(list_id(1), "List".to_string(), peer(1));
        holder
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("add t1");
        let mut serve = holder.full_delta();
        let ordering = serve.ordering_update.as_mut().expect("full serve ordering");
        let mut grafted = ordering.get().clone();
        grafted.push(phantom);
        *ordering = saorsa_gossip_crdt_sync::LwwRegister::new(grafted);
        assert!(
            !serve.added_tasks.contains_key(&phantom),
            "the add never arrived"
        );
        assert!(
            !serve.removed_tasks.contains_key(&phantom),
            "no deletion evidence exists"
        );

        let mut replica = TaskList::new(list_id(1), "List".to_string(), peer(2));
        replica
            .add_task(make_task(7, peer(2)), peer(2), 1)
            .expect("seed phantom");
        replica
            .merge_delta(&serve, peer(1), Some(&agent(1)))
            .expect("merge serve");
        assert_eq!(
            replica.prune_to_served_set(&serve, Some(&agent(1))),
            0,
            "an ordering mention is not deletion evidence"
        );
        assert!(
            replica.get_task(&phantom).is_some(),
            "adds-win keeps the live task the holder merely never saw"
        );
    }

    #[test]
    fn unauthorized_holder_removal_evidence_cannot_prune_group_list() {
        let t1 = TaskId::from_bytes([1; 32]);
        let doomed = TaskId::from_bytes([2; 32]);

        let mut holder = TaskList::new(list_id(1), "Group".to_string(), peer(1));
        holder
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("add t1");
        holder
            .add_task(make_task(2, peer(1)), peer(1), 2)
            .expect("add doomed");
        holder.remove_task(&doomed).expect("delete doomed");
        let serve = holder.full_delta();
        assert_eq!(
            serve.removed_tasks.get(&doomed).map(|tags| tags.len()),
            Some(0),
            "the serve carries explicit deletion evidence"
        );

        let make_replica = || {
            let mut replica = TaskList::new(list_id(1), "Group".to_string(), peer(2));
            replica.set_authorized_agents(std::collections::HashSet::from([agent(1)]));
            replica
                .add_task(make_task(1, peer(2)), peer(2), 1)
                .expect("replica t1");
            replica
                .add_task(make_task(2, peer(2)), peer(2), 2)
                .expect("replica doomed");
            replica
        };

        let mut replica = make_replica();
        replica
            .merge_delta(&serve, peer(9), Some(&agent(9)))
            .expect("merge non-member serve");
        assert_eq!(
            replica.prune_to_served_set(&serve, Some(&agent(9))),
            0,
            "removal evidence from a writer the policy rejects must not prune"
        );
        assert!(
            replica.get_task(&doomed).is_some(),
            "the task survives the non-member's serve"
        );
        assert!(
            !replica.known_removed_ids().contains(&doomed),
            "the non-member's evidence must not even be recorded for forwarding"
        );

        let mut replica = make_replica();
        replica
            .merge_delta(&serve, peer(1), None)
            .expect("merge unverified serve");
        assert_eq!(
            replica.prune_to_served_set(&serve, None),
            0,
            "an unverified envelope must not prune"
        );
        assert!(replica.get_task(&doomed).is_some());

        let mut replica = make_replica();
        replica
            .merge_delta(&serve, peer(1), Some(&agent(1)))
            .expect("merge member serve");
        assert_eq!(
            replica.prune_to_served_set(&serve, Some(&agent(1))),
            1,
            "an authorized member's deletion evidence still prunes"
        );
        assert!(replica.get_task(&doomed).is_none());
        assert!(replica.get_task(&t1).is_some(), "live task survives");
    }

    #[derive(Debug, Default)]
    struct ListenerGate {
        suspended: std::sync::atomic::AtomicBool,
        roster: std::sync::Mutex<std::collections::HashSet<crate::identity::AgentId>>,
        buffered: std::sync::atomic::AtomicU64,
        dropped: std::sync::atomic::AtomicU64,
        applied: std::sync::atomic::AtomicU64,
    }

    impl ListenerGate {
        fn seating(signer: AgentId) -> Self {
            let gate = Self::default();
            gate.roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(signer);
            gate
        }

        fn suspend(&self, value: bool) {
            self.suspended
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn count(counter: &std::sync::atomic::AtomicU64) -> u64 {
            counter.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn marker_free_token() -> crate::groups::LifecycleEpochToken {
            crate::groups::GroupInfo::new(
                "listener-gate".to_string(),
                "listener gate".to_string(),
                agent(3),
                "listener-gate".to_string(),
            )
            .lifecycle_epoch_token()
        }
    }

    impl TaskIngestGate for ListenerGate {
        fn suspended(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
            Box::pin(async move { self.suspended.load(std::sync::atomic::Ordering::SeqCst) })
        }

        fn epoch_token(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Option<crate::groups::LifecycleEpochToken>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move { Some(Self::marker_free_token()) })
        }

        fn with_pinned_roster<'a>(
            &'a self,
            apply: &'a mut (dyn FnMut(Option<&AuthorizedRoster>) + Send),
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                let agents = self
                    .roster
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let roster = AuthorizedRoster {
                    agents,
                    token: Self::marker_free_token(),
                };
                apply(Some(&roster));
            })
        }

        fn on_buffered(&self, _depth: usize, _bytes: usize) {
            self.buffered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn on_dropped(&self, count: u64) {
            self.dropped
                .fetch_add(count, std::sync::atomic::Ordering::SeqCst);
        }

        fn on_applied(&self, count: u64) {
            self.applied
                .fetch_add(count, std::sync::atomic::Ordering::SeqCst);
        }
    }

    async fn make_signed_sync(topic: &str) -> (TaskListSync, AgentId) {
        let (sync, _pubsub, signer) = make_signed_sync_with_pubsub(topic).await;
        (sync, signer)
    }

    async fn make_signed_sync_with_pubsub(
        topic: &str,
    ) -> (TaskListSync, Arc<PubSubManager>, AgentId) {
        let (pubsub, signer) = signed_pubsub_with_signer().await;
        let list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        let sync = TaskListSync::new(list, Arc::clone(&pubsub), topic.to_string(), peer(1))
            .expect("task list sync");
        (sync, pubsub, signer)
    }

    fn add_delta(seq: u64, id_byte: u8, from: PeerId) -> TaskListDelta {
        let task = make_task(id_byte, from);
        let mut delta = TaskListDelta::new(seq);
        delta.added_tasks.insert(*task.id(), (task, (from, seq)));
        delta
    }

    async fn eventually<F, Fut>(within: Duration, mut check: F) -> bool
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        tokio::time::timeout(within, async {
            loop {
                if check().await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }

    // This test and its siblings do not use `tokio::time::pause()`: they drive
    // a real `PubSubManager` over a loopback QUIC node, whose gossip and
    // transport timers either never fire under paused time or fire in an order
    // the test does not control. They depend on no elapsed time instead: the
    // poll period is injected and every wait is a bounded poll on state.
    #[tokio::test]
    async fn quarantine_gate_installed_before_start_holds_the_first_delta() {
        let (sync, signer) = make_signed_sync("tasks/adr0068-before-start").await;
        let gate = Arc::new(ListenerGate::seating(signer));
        gate.suspend(true);
        assert!(sync
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let before = bincode::serialize(&*sync.read().await).expect("encode state");
        let delta = add_delta(1, 7, peer(2));
        let task_id = *delta.added_tasks.keys().next().expect("one task");
        sync.publish_delta(peer(2), delta).await.expect("publish");

        assert!(
            eventually(Duration::from_secs(5), || async {
                sync.quarantined_buffer_len() == 1
            })
            .await,
            "the delta must be HELD, not merged"
        );
        assert_eq!(
            bincode::serialize(&*sync.read().await).expect("encode state"),
            before,
            "the CRDT must be byte-identical while the marker is live"
        );
        assert!(sync.read().await.get_task(&task_id).is_none());
        assert_eq!(ListenerGate::count(&gate.buffered), 1);

        let (control, control_signer) = make_signed_sync("tasks/adr0068-after-start").await;
        control.start().await.expect("start control");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let control_delta = add_delta(1, 8, peer(2));
        let control_task = *control_delta
            .added_tasks
            .keys()
            .next()
            .expect("one control task");
        control
            .publish_delta(peer(2), control_delta)
            .await
            .expect("publish control");
        assert!(
            eventually(Duration::from_secs(5), || async {
                control.read().await.get_task(&control_task).is_some()
            })
            .await,
            "control: with the gate slot still empty the delta MERGES — the \
             window #732 finding 3 closes, and proof this test can fail"
        );
        let late = Arc::new(ListenerGate::seating(control_signer));
        late.suspend(true);
        assert!(control
            .ingest_gate()
            .install(late as Arc<dyn TaskIngestGate>));
    }

    #[tokio::test]
    async fn a_newer_delta_drains_the_buffer_before_it_is_admitted() {
        let (sync, signer) = make_signed_sync("tasks/adr0068-drain-first").await;
        let gate = Arc::new(ListenerGate::seating(signer));
        gate.suspend(true);
        assert!(sync
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        sync.set_drain_poll_millis(600_000);
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let held = add_delta(1, 7, peer(2));
        let held_id = *held.added_tasks.keys().next().expect("held task");
        sync.publish_delta(peer(2), held)
            .await
            .expect("publish held");
        assert!(
            eventually(Duration::from_secs(5), || async {
                sync.quarantined_buffer_len() == 1
            })
            .await,
            "the first delta is held while the marker is live"
        );

        let still_quarantined = add_delta(2, 9, peer(2));
        sync.publish_delta(peer(2), still_quarantined)
            .await
            .expect("publish second");
        assert!(
            eventually(Duration::from_secs(5), || async {
                sync.quarantined_buffer_len() == 2
            })
            .await,
            "control: traffic under a live marker is held, not applied"
        );
        assert_eq!(sync.read().await.task_count(), 0);

        gate.suspend(false);
        let after_clear = add_delta(3, 11, peer(2));
        let after_id = *after_clear.added_tasks.keys().next().expect("newer task");
        sync.publish_delta(peer(2), after_clear)
            .await
            .expect("publish after clear");

        assert!(
            eventually(Duration::from_secs(5), || async {
                sync.read().await.get_task(&after_id).is_some()
            })
            .await,
            "the post-clear delta applies"
        );
        assert_eq!(
            sync.quarantined_buffer_len(),
            0,
            "the held deltas drained on that same message — a buffer still full \
             here is the starvation #732 finding 5 describes"
        );
        assert!(
            sync.read().await.get_task(&held_id).is_some(),
            "the delta held before the clear is applied too"
        );
        assert_eq!(
            ListenerGate::count(&gate.applied),
            2,
            "both held deltas were applied by the drain, before the newer one"
        );
        assert_eq!(ListenerGate::count(&gate.dropped), 0);
    }

    #[tokio::test]
    async fn an_idle_buffer_drains_on_the_poll_and_then_disarms() {
        let (sync, signer) = make_signed_sync("tasks/adr0068-idle-poll").await;
        let gate = Arc::new(ListenerGate::seating(signer));
        gate.suspend(true);
        assert!(sync
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        sync.set_drain_poll_millis(50);
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let held = add_delta(1, 7, peer(2));
        let held_id = *held.added_tasks.keys().next().expect("held task");
        sync.publish_delta(peer(2), held)
            .await
            .expect("publish held");
        assert!(
            eventually(Duration::from_secs(5), || async {
                sync.quarantined_buffer_len() == 1
            })
            .await,
            "held while the marker is live"
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            sync.quarantined_buffer_len(),
            1,
            "control: the poll does not drain under a live marker"
        );
        assert_eq!(ListenerGate::count(&gate.applied), 0);

        gate.suspend(false);
        assert!(
            eventually(Duration::from_secs(5), || async {
                sync.read().await.get_task(&held_id).is_some()
            })
            .await,
            "the poll drains the buffer with no inbound traffic"
        );
        assert_eq!(sync.quarantined_buffer_len(), 0);
        let applied_once = ListenerGate::count(&gate.applied);
        assert_eq!(applied_once, 1);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            ListenerGate::count(&gate.applied),
            applied_once,
            "an empty buffer disarms the poll: nothing drains again"
        );
    }

    #[tokio::test]
    async fn undecodable_traffic_cannot_postpone_the_drain_deadline() {
        let (sync, pubsub, signer) =
            make_signed_sync_with_pubsub("tasks/adr0068-garbage-flood").await;
        let gate = Arc::new(ListenerGate::seating(signer));
        gate.suspend(true);
        assert!(sync
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        sync.set_drain_poll_millis(200);
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let held = add_delta(1, 7, peer(2));
        let held_id = *held.added_tasks.keys().next().expect("held task");
        sync.publish_delta(peer(2), held)
            .await
            .expect("publish held");
        assert!(
            eventually(Duration::from_secs(5), || async {
                sync.quarantined_buffer_len() == 1
            })
            .await,
            "held while the marker is live"
        );

        gate.suspend(false);
        let flood = tokio::spawn({
            let pubsub = Arc::clone(&pubsub);
            async move {
                loop {
                    let _ = pubsub
                        .publish(
                            "tasks/adr0068-garbage-flood".to_string(),
                            bytes::Bytes::from_static(b"not a task delta"),
                        )
                        .await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        });

        let drained = eventually(Duration::from_secs(3), || async {
            sync.read().await.get_task(&held_id).is_some()
        })
        .await;
        assert!(
            !flood.is_finished(),
            "the flood must still be running, so the drain happened UNDER traffic"
        );
        flood.abort();
        assert!(
            drained,
            "the pinned deadline must fire while undecodable traffic keeps \
             arriving — a timer re-created per message never would"
        );
        assert_eq!(sync.quarantined_buffer_len(), 0);
        assert_eq!(ListenerGate::count(&gate.applied), 1);
    }

    use std::future::Future;

    type HeldLoops = Arc<std::sync::Mutex<Vec<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>>>;

    async fn retire_list_fixture(
        topic: &str,
        dir: &tempfile::TempDir,
    ) -> (TaskListSync, Arc<PubSubManager>, std::path::PathBuf) {
        let (pubsub, _signer) = signed_pubsub_with_signer().await;
        let list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        let sync =
            TaskListSync::new(list, Arc::clone(&pubsub), topic.to_string(), peer(1)).expect("sync");
        sync.set_persistence(TaskListStorage::new(dir.path().to_path_buf()), list_id(1));
        let snapshot = dir.path().join(format!("{}.bin", list_id(1)));
        (sync, pubsub, snapshot)
    }

    async fn publish_queued_task_delta(
        sync: &TaskListSync,
        pubsub: &Arc<PubSubManager>,
        id_byte: u8,
    ) -> TaskId {
        let delta = add_delta(1, id_byte, peer(2));
        let task_id = *delta.added_tasks.keys().next().expect("task id");
        let delivered_before = pubsub.stats().delivered_to_subscriber;
        sync.publish_delta(peer(2), delta).await.expect("publish");
        tokio::time::timeout(Duration::from_secs(10), async {
            while pubsub.stats().delivered_to_subscriber == delivered_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("delta must reach the listener's channel");
        task_id
    }

    async fn start_list_joinable(sync: &TaskListSync) -> Vec<tokio::task::JoinHandle<()>> {
        let handles: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&handles);
        sync.start_with_spawner(move |fut| {
            sink.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(tokio::spawn(fut));
        })
        .await
        .expect("start_with_spawner");
        let mut guard = handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    async fn join_list_loops(loops: Vec<tokio::task::JoinHandle<()>>) {
        for handle in loops {
            tokio::time::timeout(Duration::from_secs(10), handle)
                .await
                .expect("a cancelled loop must exit")
                .expect("loop must not panic");
        }
    }

    #[tokio::test]
    async fn live_control_listener_merges_and_persists_a_queued_delta_759() {
        let dir = tempfile::tempdir().expect("dir");
        let (sync, pubsub, _snapshot) = retire_list_fixture("tasks/759-live-control", &dir).await;
        let loops = start_list_joinable(&sync).await;
        let ctx = sync.persist_ctx().expect("persist armed");
        let mut persisted = ctx.persisted.subscribe();
        let durable_before = *persisted.borrow();
        let task_id = publish_queued_task_delta(&sync, &pubsub, 0xB1).await;
        tokio::time::timeout(
            Duration::from_secs(10),
            persisted.wait_for(|&v| v > durable_before),
        )
        .await
        .expect("control: the merged delta's snapshot write landed")
        .expect("the persist context outlives this wait");
        assert!(
            sync.read().await.get_task(&task_id).is_some(),
            "control: a live listener merges the queued delta"
        );
        let reloaded = TaskListStorage::new(dir.path().to_path_buf())
            .load_task_list(&list_id(1))
            .await
            .expect("the listener's snapshot must reload");
        assert!(
            reloaded.get_task(&task_id).is_some(),
            "the persisted snapshot contains the queued delta's task"
        );
        sync.cancel_sync_and_drain().await;
        join_list_loops(loops).await;
    }

    #[tokio::test]
    async fn retired_listener_never_merges_or_persists_a_queued_delta_759() {
        let dir = tempfile::tempdir().expect("dir");
        let (sync, pubsub, snapshot) = retire_list_fixture("tasks/759-queued", &dir).await;
        let held: HeldLoops = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&held);
        sync.start_with_spawner(move |fut| {
            sink.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fut);
        })
        .await
        .expect("start_with_spawner");

        let task_id = publish_queued_task_delta(&sync, &pubsub, 0xB2).await;

        sync.cancel_sync();
        let loops = std::mem::take(
            &mut *held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for fut in loops {
            tokio::time::timeout(Duration::from_secs(10), fut)
                .await
                .expect("a cancelled loop must exit");
        }
        assert!(
            sync.read().await.get_task(&task_id).is_none(),
            "a queued delta merged after the retire"
        );
        assert!(!snapshot.exists(), "a retired listener wrote the snapshot");
    }

    #[tokio::test]
    async fn task_delta_pulled_before_cancel_is_dropped_under_the_lifecycle_lock_759() {
        let dir = tempfile::tempdir().expect("dir");
        let (sync, pubsub, snapshot) = retire_list_fixture("tasks/759-pulled", &dir).await;
        let held: HeldLoops = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&held);
        sync.start_with_spawner(move |fut| {
            sink.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fut);
        })
        .await
        .expect("start_with_spawner");
        let parked = sync.lifecycle.clone().lock_owned().await;
        let task_id = publish_queued_task_delta(&sync, &pubsub, 0xB3).await;
        let mut loops = std::mem::take(
            &mut *held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for fut in &mut loops {
            assert!(
                futures::poll!(fut.as_mut()).is_pending(),
                "every loop must be parked, none finished"
            );
        }
        sync.cancel_sync();
        drop(parked);
        for fut in loops {
            tokio::time::timeout(Duration::from_secs(10), fut)
                .await
                .expect("a cancelled loop must exit");
        }
        assert!(
            sync.read().await.get_task(&task_id).is_none(),
            "a delta pulled before the cancel was merged after it"
        );
        assert!(!snapshot.exists(), "a retired listener wrote the snapshot");
    }

    #[tokio::test]
    async fn draining_retire_waits_for_an_in_flight_task_merge_and_persist_759() {
        let dir = tempfile::tempdir().expect("dir");
        let (sync, pubsub, snapshot) = retire_list_fixture("tasks/759-inflight", &dir).await;
        let loops = start_list_joinable(&sync).await;
        let ctx = sync.persist_ctx().expect("persist armed");
        let persist_gate = ctx.gate.lock().await;
        let task_id = publish_queued_task_delta(&sync, &pubsub, 0xB4).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while sync.read().await.get_task(&task_id).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("listener must merge the delta in memory");
        assert!(
            sync.receive_section_active_for_test(),
            "the listener is inside a receive section, parked on the persist gate"
        );
        let mut drain = Box::pin(sync.cancel_sync_and_drain());
        for _ in 0..64 {
            assert!(
                futures::poll!(drain.as_mut()).is_pending(),
                "drain completed while a receive section was still in flight"
            );
            tokio::task::yield_now().await;
        }
        assert!(
            !snapshot.exists(),
            "the parked snapshot write must not have landed yet"
        );
        drop(persist_gate);
        tokio::time::timeout(Duration::from_secs(10), &mut drain)
            .await
            .expect("drain must finish once the in-flight section completes");
        assert!(
            snapshot.exists(),
            "the in-flight section's snapshot write completed before the drain returned"
        );
        join_list_loops(loops).await;
    }

    #[tokio::test]
    async fn resume_after_retire_applies_nothing_and_keeps_the_buffer_759() {
        let dir = tempfile::tempdir().expect("dir");
        let (sync, _pubsub, snapshot) = retire_list_fixture("tasks/759-resume-retired", &dir).await;
        let signer = agent(9);
        let gate = Arc::new(ListenerGate::seating(signer));
        gate.suspend(true);
        assert!(sync
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        let delta = add_delta(1, 0xB5, peer(2));
        let task_id = *delta.added_tasks.keys().next().expect("task id");
        match testing::admit_or_buffer(
            sync.ingest_gate().gate(),
            &sync.quarantine_buffer,
            &sync.task_list,
            peer(2),
            delta,
            Some(&signer),
            64,
        )
        .await
        {
            Admission::Held => {}
            Admission::Apply(..) => panic!("a suspended gate must hold the delta"),
        }
        assert_eq!(sync.quarantined_buffer_len(), 1);
        gate.suspend(false);
        sync.cancel_sync();
        let applied = sync.resume_quarantined_ingest().await;
        assert_eq!(applied, 0, "a retired list must apply nothing");
        assert_eq!(
            sync.quarantined_buffer_len(),
            1,
            "the buffer stays intact and in order for the next incarnation"
        );
        assert!(sync.read().await.get_task(&task_id).is_none());
        assert!(!snapshot.exists());
    }

    #[tokio::test]
    async fn empty_buffer_resume_refreshes_the_authorized_roster_759() {
        let dir = tempfile::tempdir().expect("dir");
        let (sync, _pubsub, _snapshot) = retire_list_fixture("tasks/759-empty-refresh", &dir).await;
        let seated = agent(9);
        let gate = Arc::new(ListenerGate::seating(seated));
        assert!(sync
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        sync.write()
            .await
            .set_authorized_agents(std::collections::HashSet::from([agent(5)]));
        assert_eq!(sync.quarantined_buffer_len(), 0);
        let applied = sync.resume_quarantined_ingest().await;
        assert_eq!(applied, 0, "nothing buffered — nothing to apply");
        let list = sync.read().await;
        assert!(
            list.is_authorized_content_writer(&seated),
            "the pinned roster the resume observed is now the writer set"
        );
        assert!(
            !list.is_authorized_content_writer(&agent(5)),
            "the stale captured set was replaced, not merged"
        );
    }
}
