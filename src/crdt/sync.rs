//! Task list synchronization using gossip pub/sub.
//!
//! This module provides automatic synchronization of TaskLists across peers
//! using saorsa-gossip's pub/sub delta propagation.
//!
//! ## Architecture
//!
//! - `TaskListSync` wraps a TaskList in Arc<RwLock<>> for concurrent access
//! - Publishes deltas to a gossip topic when local changes occur
//! - Subscribes to the topic to receive and apply remote deltas
//! - Runs a `StateRequest` cold-start side channel so a first-time joiner
//!   bootstraps tasks written before it subscribed (mirrors `KvStoreSync`)
//!
//! This provides eventual consistency across all peers sharing the same topic.

use crate::crdt::persistence::TaskListStorage;
use crate::crdt::{Result, TaskList, TaskListDelta, TaskListId};
use crate::gossip::wire::{decode_delta, encode_delta};
use crate::gossip::PubSubManager;
use crate::identity::AgentId;
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

/// Delays between state-request retries for a first-time joiner whose task
/// list is still empty. Spread out so a slow mesh still converges without
/// flooding.
const STATE_REQUEST_RETRY_SECS: [u64; 4] = [1, 5, 15, 30];

/// First persistent-tail delay after the front-loaded schedule exhausts.
const STATE_REQUEST_TAIL_START_SECS: u64 = 30;

/// Ceiling for the persistent tail's exponential backoff. While a list is
/// still empty it keeps requesting at most this often — the steady-state
/// cost is one ~50-byte side-topic message per list per 5 minutes.
const STATE_REQUEST_TAIL_CAP_SECS: u64 = 300;

/// The complete state-request delay schedule: the front-loaded burst, then
/// an infinite exponential tail (30s doubling to a 300s ceiling).
///
/// Infinite BY DESIGN (issue #238): holders answer state requests only
/// reactively and never volunteer state to late subscribers, so a bounded
/// schedule (the previous 20 × 30s ≈ 10 min hard cap) left a replica that
/// rehydrated while every holder was offline permanently un-synced once the
/// cap expired. Convergence — a `StateServed` marker plus local state — is
/// the only legitimate stop condition, and the requester loop owns that
/// check.
fn state_request_delays() -> impl Iterator<Item = u64> {
    let tail = std::iter::successors(Some(STATE_REQUEST_TAIL_START_SECS), |d| {
        Some(d.saturating_mul(2).min(STATE_REQUEST_TAIL_CAP_SECS))
    });
    STATE_REQUEST_RETRY_SECS.into_iter().chain(tail)
}

/// Minimum spacing between full-state responses from ONE holder for ONE
/// list — the same response-storm damping as `KvStoreSync` (issue #238
/// review): the response is a broadcast on the main topic, so one response
/// per window serves every concurrently-bootstrapping replica.
const STATE_RESPONSE_COOLDOWN_SECS: u64 = 15;

/// Sleep duration for a scheduled delay with ±20% jitter, so a fleet of
/// replicas restarted together does not phase-lock its request (and thus
/// full-state response) schedule. Mirrors the reconnect-backoff jitter in
/// `lib.rs`.
fn jittered_secs(secs: u64) -> std::time::Duration {
    let factor = 0.8 + rand::random::<f64>() * 0.4;
    std::time::Duration::from_secs_f64(secs as f64 * factor)
}

/// Message exchanged on the state-sync side topic.
#[derive(Debug, Serialize, Deserialize)]
enum TaskListSyncMessage {
    /// A peer with no local state for the list asks holders to republish
    /// their full state (as a regular delta) on the main topic.
    StateRequest { requester: PeerId },
    /// A NON-EMPTY holder's declaration that it has answered a
    /// `StateRequest` (its full state was republished on the main topic,
    /// possibly earlier within the response cooldown). Requesters exit their
    /// bootstrap tail only after seeing a marker AND holding local state —
    /// mere non-emptiness is not convergence evidence (a single incremental
    /// delta must not silence recovery, round-2 review). Task lists have no
    /// authoritative owner, so an empty holder NEVER declares (two empty
    /// bootstrapping replicas must not talk each other into a false
    /// "converged empty"); a genuinely-empty list keeps its capped-cadence
    /// tail (~one tiny message per 5 minutes) until state exists.
    ///
    /// Wire compatibility: additive variant — older peers fail to
    /// deserialize it and skip the message (same precedent as the kv-store
    /// side channel).
    StateServed {
        /// The declaring holder (receivers skip their own echo).
        responder: PeerId,
    },
    /// A holder's digest-committed declaration that it has answered a
    /// `StateRequest` (issue #240): `digest` commits to the FULL served
    /// task set (see `TaskList::served_digest`), so a requester can verify
    /// "served us, completely" against its OWN state instead of trusting
    /// that the full delta and the marker both arrived (the v1 cross-topic
    /// loss window). A requester stops only when its local digest matches a
    /// declared digest — a lost full delta leaves the local digest
    /// different, so it keeps asking.
    ///
    /// Empty holders declare the digest of the empty set, which any empty
    /// requester can compute locally — two empty replicas verifiably agree
    /// on the empty state, so converging on empty is now CORRECT (not the
    /// false convergence the v1 silence rule defended against), and the
    /// genuinely-empty chatter tail terminates. Because the digest is
    /// self-verifying, an empty declaration needs no full-delta broadcast
    /// to witness.
    ///
    /// Wire compatibility: additive variant, same precedent as the v1
    /// marker — older peers fail to deserialize it and skip the message;
    /// new peers treat v1 markers as weaker evidence when no v2 digest has
    /// been seen. The marker rides along with the full-state broadcast
    /// (never separately) when there is state to serve.
    StateServedV2 {
        /// The declaring holder (receivers skip their own echo).
        responder: PeerId,
        /// Canonical BLAKE3 digest over the served task set.
        digest: [u8; 32],
        /// Number of tasks in the served set — a cheap shape check for the
        /// verified full-replace adopt path (and useful in logs).
        entry_count: u32,
    },
}

/// One responder's latest v2 digest declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServedState {
    /// The declared content digest.
    digest: [u8; 32],
    /// The declared number of tasks.
    entry_count: u32,
}

/// Aggregated `StateServed`/`StateServedV2` evidence observed by one
/// replica's responder loop, consumed by its bootstrap requester to decide
/// convergence.
#[derive(Debug, Default)]
struct TaskServedEvidence {
    /// A v1 marker from some holder (weak evidence — old peers).
    saw_v1: bool,
    /// Latest digest declaration per responder (bounded by mesh size — a
    /// responder's newer declaration REPLACES its older one, so a replayed
    /// stale serve can never roll a verified full-replace adopt backwards).
    digests: std::collections::HashMap<PeerId, ServedState>,
}

/// Convergence rule for the bootstrap tail (pure for unit-testing).
///
/// When any v2 digest declarations exist, the local digest must match one
/// of them — with the data-bearing-claim-wins rule: if any declaration is
/// non-empty, only a non-empty match converges (an empty holder's
/// declaration must not retire a requester while a full holder advertised
/// content). Otherwise (only v1 markers seen — old peers) the legacy weak
/// rule: a marker AND local non-emptiness. No evidence is NEVER
/// convergence.
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

/// Disarms the bootstrap-active flag on ANY requester exit path (converged,
/// silenced, cancelled, torn down) so the listener's digest-verified
/// full-replace adopt can never fire outside the bootstrap window.
struct BootstrapGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for BootstrapGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Synchronization wrapper for a TaskList.
///
/// Manages automatic background synchronization of a TaskList using gossip
/// pub/sub. Changes are propagated via deltas published to a gossip topic.
pub struct TaskListSync {
    /// The task list being synchronized (wrapped for concurrent access).
    task_list: Arc<RwLock<TaskList>>,

    /// Pub/sub manager for topic-based messaging.
    pubsub: Arc<PubSubManager>,

    /// Topic name for this task list.
    topic: String,

    /// Optional persistence context. When armed (see
    /// [`set_persistence`](Self::set_persistence)), the full list state is
    /// snapshotted to disk after every local mutation and every merged
    /// remote delta, so a restart restores task content — ids, titles,
    /// claim/complete provenance, order and version material — instead of
    /// coming back as an empty replica (issue #557). Mirrors
    /// `KvStoreSync::persist`.
    persist: std::sync::Mutex<Option<Arc<TaskPersistCtx>>>,

    /// This node's gossip peer id — identifies our deltas and state
    /// requests on the wire.
    local_peer_id: PeerId,

    /// Set by [`silence_bootstrap`](Self::silence_bootstrap). The bootstrap
    /// requester checks it every iteration: its schedule is infinite (issue
    /// #238), so a sync that should stop generating traffic — but keep
    /// serving — arms this without ending the listener/responder loops.
    stopped: Arc<std::sync::atomic::AtomicBool>,

    /// Cancelled by [`cancel_sync`](Self::cancel_sync) / [`stop`](Self::stop).
    /// ALL background loops (delta listener, responder, requester) select on
    /// it, so a discarded sync tears down completely without the topic-wide
    /// `unsubscribe` that would kill unrelated subscribers sharing the topic
    /// string (round-4 review: flag-only teardown left ghost listeners and a
    /// live responder until daemon shutdown).
    cancel: tokio_util::sync::CancellationToken,

    /// ADR-0068 D2: set-once inbound-delta admission gate, installed by the
    /// daemon for a task list bound to a named group. Shared with the listener
    /// loop, which is already running by the time the daemon installs it.
    ingest_gate: Arc<TaskIngestGateSlot>,

    /// ADR-0068 D2: deltas received while the gate reported the group
    /// quarantined, held in arrival order until the marker clears.
    quarantine_buffer: Arc<std::sync::Mutex<QuarantineDeltaBuffer>>,

    /// The drain poll period in milliseconds, [`TASK_QUARANTINE_DRAIN_POLL_SECS`]
    /// in production. Per-instance and only ever changed by
    /// [`set_drain_poll_millis`](Self::set_drain_poll_millis), a `cfg(test)`
    /// hook: the poll fixtures must not sleep for whole seconds, and a
    /// process-global knob would couple concurrently running tests.
    drain_poll_millis: Arc<std::sync::atomic::AtomicU64>,
}

/// ADR-0068 D2: maximum inbound deltas one task list buffers while its group
/// is fork-quarantined. Oldest is dropped on overflow.
pub const TASK_QUARANTINE_BUFFER_MAX_DELTAS: usize = 1024;

/// ADR-0068 D2: maximum buffered delta bytes per task list (1 MiB). Whichever
/// of this and [`TASK_QUARANTINE_BUFFER_MAX_DELTAS`] is reached first drops
/// the oldest buffered delta.
///
/// The bound is ABSOLUTE, including for a single delta: one delta larger than
/// this on its own is dropped rather than retained (review nit 4 — an
/// "always keep at least one" rule would have let the transport's own 4 MiB
/// frame cap set the real per-list worst case, five times what the ADR states).
/// Dropping is safe: merges are idempotent and the state-sync side channel
/// re-serves full state after the clear.
pub const TASK_QUARANTINE_BUFFER_MAX_BYTES: usize = 1_048_576;

/// ADR-0068 D2: how often a listener holding buffered deltas re-checks whether
/// the marker has gone.
///
/// The drain is driven by OBSERVING the marker's absence rather than by hooking
/// each site that can clear it — `fork_quarantine` is cleared at the manual
/// route, on the metadata-apply path, at an explicit owner seal and on rollback
/// arms, and an enumeration of clear writers whose failure mode is "one clear
/// forgot to drain" is the fail-open census ADR-0067 rejected. This poll arm is
/// armed ONLY while the buffer is non-empty, so a healthy list adds no timer.
///
/// The deadline is a PINNED sleep that survives receives and is reset only once
/// it has fired (#732 finding 5): re-creating it inside `select!` let every
/// inbound message cancel it, so traffic arriving faster than this period
/// starved the drain and this bound was not a bound at all. Inbound deltas also
/// drain the buffer before they are admitted, so under traffic the catch-up
/// happens on the next delta rather than on this timer.
pub const TASK_QUARANTINE_DRAIN_POLL_SECS: u64 = 5;

/// ADR-0068 D2: whether inbound task-CRDT deltas may be applied right now.
///
/// The CRDT layer knows nothing about fork quarantine, so the daemon installs
/// this for a group-scoped task list (`x0x.group.<gid>.symphony.<lid>`) and
/// resolves the marker through the one resolver, under both spellings. A list
/// with no gate — any list not bound to a named group — behaves exactly as it
/// did before ADR-0068.
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
    /// This is the shape that makes re-authorization airtight (#756 review r2).
    /// The implementation acquires its roster read guard, derives the
    /// [`AuthorizedRoster`], calls `apply` **synchronously** while still holding
    /// that guard, and only then releases it. The drain therefore installs the
    /// refreshed set, filters the buffer and runs the whole merge loop with the
    /// roster held still: a roster commit cannot land between the refresh and the
    /// merge, because a writer cannot acquire the roster until `apply` returns.
    /// The earlier design — derive, release, re-read the token and compare —
    /// closed the same hole only probabilistically and could be starved by
    /// sustained revision churn.
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
///
/// The pairing is the point (#756 review P1/P2). The drain must not authorize
/// against one roster state and merge against another, and the two cannot be
/// reconciled after the fact by comparing revisions: that is a probabilistic
/// check, and sustained revision churn could make it fail forever. So the set and
/// the token are derived together and handed to the drain
/// [`TaskIngestGate::with_pinned_roster`] while the roster is still held, and the
/// merge runs inside that window. `state_revision` and the marker identity
/// therefore describe exactly the state the merge is authorized against.
#[derive(Debug, Clone)]
pub struct AuthorizedRoster {
    /// The group's active members, as CRDT writer identities.
    pub agents: std::collections::HashSet<crate::identity::AgentId>,
    /// The ADR-0067 lifecycle token read under the same guard as `agents`.
    pub token: crate::groups::LifecycleEpochToken,
}

/// Set-once slot for the [`TaskIngestGate`].
///
/// Set-once because the daemon installs exactly one gate per handle, and it
/// does so AFTER `start_with_spawner` has already spawned the listener — so the
/// listener reads the gate through this slot on every delta rather than
/// capturing it once.
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

/// One inbound delta held while the group is quarantined, with everything the
/// merge needs so the replay is the SAME call the listener would have made.
#[derive(Debug, Clone)]
struct BufferedDelta {
    /// OR-Set tag identity from the payload (issue #349 I3).
    peer_id: PeerId,
    /// The delta itself.
    delta: TaskListDelta,
    /// The V2-envelope-verified sender — the writer identity content policy
    /// admits on. `None` for an unverified sender, exactly as the live path
    /// passes it.
    writer: Option<crate::identity::AgentId>,
    /// Encoded size, for the byte bound.
    bytes: usize,
}

/// ADR-0068 D2: bounded, arrival-ordered hold for one task list's inbound
/// deltas while its group is fork-quarantined.
///
/// Process-local and never persisted: a restart loses it and the CRDT
/// re-converges by anti-entropy, exactly as it does for any delta the node was
/// offline for.
/// Visibility: `pub` only because the `cfg(test)` `testing` surface names it;
/// its fields and constructors stay private to this module.
#[derive(Debug, Default)]
pub struct QuarantineDeltaBuffer {
    entries: std::collections::VecDeque<BufferedDelta>,
    bytes: usize,
}

impl QuarantineDeltaBuffer {
    /// Append a delta, dropping the OLDEST entries until both bounds hold.
    /// Returns how many were dropped.
    ///
    /// Oldest-first because the newest deltas carry the most recent state, and
    /// anything dropped is recoverable: merges are idempotent and the
    /// state-sync side channel re-serves full state after the clear.
    fn push(&mut self, entry: BufferedDelta) -> u64 {
        let mut dropped = 0u64;
        // A delta that cannot fit the byte bound on its own is dropped rather
        // than retained (review nit 4): keeping it would let the transport's
        // own frame cap — not this constant — decide the per-list worst case.
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

    /// Take everything, in arrival order.
    fn take(&mut self) -> Vec<BufferedDelta> {
        self.bytes = 0;
        self.entries.drain(..).collect()
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

/// Lock the quarantine buffer, recovering a poisoned mutex.
///
/// Poison recovery rather than propagation: the buffer is a hold for deltas the
/// node has decided not to apply, so a panic while it was locked must not wedge
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
/// caller's merge happens inside the SAME critical section as the decision — no
/// other task-list writer can interleave, and no marker observed by this call can
/// be raced (review nit 2). It does NOT mean the marker cannot change at all: the
/// gate's roster read is released before the verdict, so one already-admitted
/// delta per listener can still merge just after a marker installs — see the
/// admission step's own documentation for why that residual is accepted and what
/// bounds it.
// `Apply` carries a delta and a lock guard while `Held` carries nothing, so the
// variants differ in size by design: boxing the admitted delta to even them out
// would put an allocation on the ingest hot path to save nothing (the value is
// consumed immediately by the caller's merge, never stored or queued).
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
/// **Decides under the list write lock and hands the guard back.** ADR-0068's
/// "marker installed mid-apply" row asks that the decision and the effect share
/// one critical section; an earlier draft decided first and let the caller lock
/// afterwards, so a marker installing in that gap let one delta through — and
/// worse, the list could be locked by someone else in between (review nit 2). It
/// deliberately does NOT perform the merge itself: the
/// listener's merge shares its critical section with the issue-#240
/// digest-verified full-replace adopt, and splitting THAT would let an
/// interleaved merge be pruned. So the guard travels instead of the merge.
///
/// **Lock order: `TaskList` write → `named_groups` read** (the gate's own
/// lookup). Nothing in the daemon holds a `named_groups` guard across a
/// `TaskList` lock acquisition — `apply_group_authorization` drops its read
/// guard before `set_authorized_agents`, and the clear route's resume runs after
/// its write guard is released — so this order cannot cycle. A future caller
/// that awaits a task list while holding `named_groups` would break it, which is
/// why the order is stated here and at the resume helper.
///
/// **Admission is coupled to the buffer, not just to the marker (#756 review
/// P2).** A delta is admitted ONLY when the buffer is empty. Checking suspension
/// alone left an overtaking window: the caller's drain attempt can observe a live
/// marker (or abandon on the ADR-0067 re-check) and return without consuming the
/// buffer, and if the marker clears before this function's own suspension read,
/// the newer delta merged straight past deltas that arrived before it — and the
/// LWW registers are order-sensitive. Both facts are now read under the same list
/// write guard, so the decision cannot be split. The consequence, stated plainly:
/// while a buffer cannot be drained (a group record that never comes back, so the
/// ADR-0067 re-check keeps abandoning), newer deltas queue behind it under the
/// same bounds and drop counter rather than applying out of order. That is
/// bounded, counted, and cleared by a restart.
///
/// **Accepted residual: one in-flight delta per listener (#756 review r3).** This
/// is the LIVE path and it is deliberately NOT roster-pinned — pinning it would put
/// a `named_groups` read on the ingest hot path, which ADR-0068's cost section
/// rules out. `gate.suspended()` therefore releases the roster read before this
/// function returns `Apply`, so a marker installing in that instant is not seen and
/// the caller's merge proceeds: **at most one already-admitted delta per listener**
/// can land immediately after a marker installs. Nothing accumulates — the next
/// delta reads the new marker and is held — and the drain path, where a whole
/// buffer is at stake, IS pinned. So the honest statement of ADR-0068 D2's freeze
/// is "byte-identical from the first delta that observes the marker", not "from the
/// instant the marker installs". Row 20's local refusals are unaffected, and the
/// admitted delta is a normal authenticated delta, not an unauthorized one.
///
/// Hot path when no marker is live: one gate read (a resolver read behind the
/// daemon's implementation), one buffer-empty check and a scalar compare, inside
/// the lock the merge needed anyway.
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
        // No group binding — pre-ADR-0068 behaviour, one lock, no gate read.
        return Admission::Apply(delta, task_list.write().await);
    };
    let list = task_list.write().await;
    let suspended = gate.suspended().await;
    // The buffer cannot change while this guard is held: every path that
    // consumes or appends to it (the drain, the resume entry point, this
    // function) takes the list write lock first. So "suspended" and "anything
    // pending" are read as ONE fact, and a newer delta cannot overtake older
    // pending ones (#756 review P2).
    let pending = !lock_buffer(buffer).is_empty();
    if !suspended && !pending {
        return Admission::Apply(delta, list);
    }
    // Still holding the write guard: a merge cannot slip between this verdict
    // and the buffering below, and a concurrent drain cannot interleave.
    let (depth, bytes, dropped) = {
        let mut held = lock_buffer(buffer);
        let dropped = held.push(BufferedDelta {
            peer_id,
            delta,
            writer: writer.copied(),
            bytes: encoded_bytes,
        });
        (held.len(), held.bytes(), dropped)
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
    drop(list);
    Admission::Held
}

/// ADR-0068 D2: apply every buffered delta, in arrival order, once the marker
/// is gone. Returns how many were applied.
///
/// Arrival order matters even though CRDT merges are idempotent: the LWW
/// registers are order-sensitive, so a replay out of order could pick a
/// different winner than the live path would have.
///
/// Takes the buffer's contents under the list write lock, so a concurrent
/// inbound delta queues behind this batch rather than interleaving with it.
///
/// **One pinned critical section (ADR-0068's "marker installed mid-apply" row,
/// ADR-0067's re-check, and #732 finding 4 — unified by #756 review r2).** The
/// drain takes the task-list write guard and then asks the gate to pin the roster
/// ([`TaskIngestGate::with_pinned_roster`]). Inside that pin, synchronously and
/// with no await anywhere:
///
/// 1. the marker half is checked against the token captured when the drain
///    decided to run — a marker that installed since abandons the drain, and a
///    `None` roster (no record for the group) abandons it too, which is ADR-0067's
///    rule that "no record" is a mismatch, never "unchanged";
/// 2. the authorized-writer set is replaced with the pinned one, so authorization
///    is the roster the CLEARING commit left behind rather than the contested one
///    the subscription captured;
/// 3. the buffer is taken and merged in arrival order, skipping (and counting) any
///    entry whose writer that roster no longer seats.
///
/// Because the roster cannot be written while the pin is held, there is no window
/// between this drain's refresh and its merge — the compare-and-retry loop this
/// replaces was only a probabilistic version of the same property, and could be
/// starved indefinitely by revision churn (review r2, P1+P2 together). That
/// statement is about the DRAIN only: the live admission path is unpinned by
/// design and carries its own one-delta residual, stated at the admission step. Abandoning
/// leaves the buffer intact, in order, for the next observation; nothing is ever
/// half-applied, because the buffer is only emptied after the checks pass.
///
/// **Lock order and hold time.** `TaskList` write → roster read is the documented
/// order (see [`admit_or_buffer`]); acquiring the roster *after* the list guard is
/// that order, not its inverse. The pin is held for one bounded synchronous batch:
/// at most [`TASK_QUARANTINE_BUFFER_MAX_DELTAS`] deltas totalling at most
/// [`TASK_QUARANTINE_BUFFER_MAX_BYTES`], CPU-only — no I/O, no network and no
/// persistence (the snapshot write happens after the guard is released). It is NOT
/// free per delta: `merge_delta` runs the ADR-0068/issue-#349 admission checks,
/// which verify checkbox attestations, and brackets the merge with two
/// `state_fingerprint` scans over the resolved list. So the honest bound is "that
/// batch of merges, whatever they cost on this machine", not a wall-clock figure.
/// Worst case a roster WRITER waits that batch out; roster readers are unaffected
/// except behind a queued writer, and this path runs only while a group is or has
/// just been fork-quarantined.
///
/// **Empty buffer (#756 review P4).** With nothing to drain the authorization is
/// still refreshed under the same pin, so a clear that finds an empty buffer does
/// not leave the cached roster stale for the deltas that arrive next.
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
        // #756 review P4: refresh the cached authorization even with nothing to
        // apply, so the roster the NEXT deltas are admitted against is the one the
        // clearing commit left behind. Reached from the explicit resume entry
        // point; the poll and the pre-admission drain both run while the buffer is
        // non-empty, so this costs nothing on the ingest path.
        if let Some(gate) = gate {
            if !gate.suspended().await {
                let mut list = task_list.write().await;
                let mut refresh = |roster: Option<&AuthorizedRoster>| {
                    // Under the pin, "no marker" is authoritative — the
                    // `suspended()` read above was only the cheap pre-check.
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
    // Cheap early-out before taking the list write lock. The authoritative check
    // is the pinned one below; this only avoids locking when the answer is already
    // "still quarantined".
    let captured = match gate {
        Some(gate) => {
            if gate.suspended().await {
                return 0; // still quarantined — nothing to do
            }
            let Some(token) = gate.epoch_token().await else {
                // No record for the group at all ⇒ mismatch by ADR-0067's rule.
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
                // Everything from here to the last merge happens under the pinned
                // roster, synchronously.
                let mut merge = |roster: Option<&AuthorizedRoster>| {
                    let Some(roster) = roster else {
                        // No resolvable record: abandon, buffer intact.
                        return;
                    };
                    if roster.token.marker().is_some() || !roster.token.same_marker(captured) {
                        // Under the pin, this is the whole ADR-0067 re-check: a
                        // marker live right now, or an identity that is not the one
                        // this drain decided against, abandons it — buffer intact,
                        // in order, nothing merged. Both clauses are stated even
                        // though a node whose `suspended()` and `epoch_token()`
                        // come from one record makes the first imply the second:
                        // "do not merge while a marker is live" must not depend on
                        // that coincidence.
                        return;
                    }
                    list.set_authorized_agents(roster.agents.clone());
                    let pending = lock_buffer(buffer).take();
                    for entry in pending {
                        // #732 finding 4: a writer the pinned roster no longer
                        // seats is not merged at all, and the drop is counted.
                        // `merge_delta` would already drop the delta's CONTENT for
                        // such a writer, but it would return `Ok`, so the delta
                        // would be counted as applied — the operator would read
                        // "caught up" for work this node refused. Skipping the
                        // whole entry also declines any checkbox element riding in
                        // a removed member's envelope; that is the containment
                        // this ADR asks for, and anything a still-seated third
                        // party owes the list is refilled by anti-entropy, exactly
                        // as for an overflow drop.
                        if entry
                            .writer
                            .is_some_and(|writer| !list.is_authorized_content_writer(&writer))
                        {
                            refused += 1;
                            continue;
                        }
                        match list.merge_delta(&entry.delta, entry.peer_id, entry.writer.as_ref()) {
                            Ok(()) => applied += 1,
                            Err(e) => tracing::warn!(
                                "failed to merge task delta buffered under fork quarantine: {e}"
                            ),
                        }
                    }
                };
                gate.with_pinned_roster(&mut merge).await;
            }
            // No gate at all (a list with no group binding): no roster to pin and
            // no authorization to refresh — merge the hold as it stands.
            _ => {
                let pending = lock_buffer(buffer).take();
                for entry in pending {
                    match list.merge_delta(&entry.delta, entry.peer_id, entry.writer.as_ref()) {
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

/// ADR-0068 D2: the admission step, the drain and the buffer type, exposed for
/// in-process fixtures.
///
/// WHY a testing surface rather than tests in this module: the fixtures live
/// beside the other ADR-0066/0068 quarantine fixtures, where a reviewer reads
/// them as one family, and they drive the EXACT functions the listener calls —
/// so a fixture cannot pass against a copy of the logic. `cfg(test)` only, so
/// none of this is public API.
#[cfg(test)]
pub mod testing {
    use super::*;

    /// The per-list hold. Per-instance, never a `static`: a global would couple
    /// concurrently running tests, which is the flake class the `fork_quarantine`
    /// fault-injection refactor removed.
    pub type Buffer = std::sync::Mutex<QuarantineDeltaBuffer>;

    /// [`super::admit_or_buffer`], verbatim — including the fact that the
    /// decision is taken under the list write lock and the guard travels with
    /// the admitted delta, which is what the barrier fixtures exercise.
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

    /// [`super::drain_quarantine_buffer`], verbatim.
    pub async fn drain(
        gate: Option<&Arc<dyn TaskIngestGate>>,
        buffer: &Buffer,
        task_list: &RwLock<TaskList>,
    ) -> usize {
        super::drain_quarantine_buffer(gate, buffer, task_list).await
    }

    /// How many deltas are held.
    #[must_use]
    pub fn len(buffer: &Buffer) -> usize {
        lock_buffer(buffer).len()
    }

    /// Held bytes, for the byte-bound fixture.
    #[must_use]
    pub fn bytes(buffer: &Buffer) -> usize {
        lock_buffer(buffer).bytes()
    }
}

/// Structural teardown (parallel-review finding): the background loops hold
/// clones of the token, the list, and the pubsub — never the sync itself —
/// so when the last `TaskListSync` reference drops, every loop (including
/// the INFINITE bootstrap requester, issue #238) is cancelled without any
/// caller having to remember `cancel_sync()`. The explicit rollback calls
/// remain as belt-and-braces.
impl Drop for TaskListSync {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Shared persistence context for one task list's snapshot file (mirrors
/// `kv::sync::PersistCtx`).
struct TaskPersistCtx {
    /// Storage backend (directory + per-list file naming).
    storage: TaskListStorage,
    /// The list this context persists — the snapshot file name key.
    list_id: TaskListId,
    /// Serializes snapshot commits AND records the last durably-persisted
    /// list version. `(version, bytes)` are captured under this lock, so
    /// commit order equals capture order — a concurrent persist burst can
    /// never rename an older snapshot over a newer one — and the version
    /// gate skips writes that would not advance durable state.
    gate: tokio::sync::Mutex<Option<u64>>,
    /// True after a failed snapshot write; cleared by the next success.
    /// While set, LOCAL mutations are refused (fail-closed for what this
    /// node controls); remote-delta merges continue (replication is not
    /// wedged).
    degraded: std::sync::atomic::AtomicBool,
}

/// Capture the list's `(version, bytes)` under the list read lock and the
/// commit gate, then write atomically. The gate both serializes snapshot
/// commits and records the last durably-persisted version, so commit order
/// equals capture order — a concurrent persist burst can never rename an
/// older snapshot over a newer one — and the version gate skips writes that
/// would not advance durable state. Success clears the degraded flag;
/// failure sets it and is error-logged here (callers decide whether to
/// propagate — local mutations must, remote merges must not).
async fn persist_snapshot(task_list: &RwLock<TaskList>, ctx: &TaskPersistCtx) -> Result<()> {
    let result = async {
        let mut last = ctx.gate.lock().await;
        let snapshot = task_list.read().await.clone();
        let version = snapshot.current_version();
        if last.is_some_and(|l| l >= version) {
            // Durable state already at (or beyond) this version.
            return Ok(());
        }
        ctx.storage.save_task_list(&ctx.list_id, &snapshot).await?;
        *last = Some(version);
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

/// ADR-0068 D2: drain the held deltas and persist once if any applied.
///
/// One helper for BOTH places the listener drains — the poll and, since #732
/// finding 5, the moment before a newly received delta is admitted — so the two
/// cannot drift on the persist-once rule. Cheap when there is nothing to do:
/// [`drain_quarantine_buffer`] returns immediately for an empty buffer and after
/// a single gate read while the marker is still live.
async fn drain_and_persist(
    gate: &TaskIngestGateSlot,
    buffer: &std::sync::Mutex<QuarantineDeltaBuffer>,
    task_list: &RwLock<TaskList>,
    persist: Option<&Arc<TaskPersistCtx>>,
) -> usize {
    let applied = drain_quarantine_buffer(gate.gate(), buffer, task_list).await;
    if applied > 0 {
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
        // Wrap task list for concurrent access
        let task_list = Arc::new(RwLock::new(task_list));

        Ok(Self {
            task_list,
            pubsub,
            topic,
            local_peer_id,
            persist: std::sync::Mutex::new(None),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancel: tokio_util::sync::CancellationToken::new(),
            ingest_gate: Arc::new(TaskIngestGateSlot::default()),
            quarantine_buffer: Arc::new(std::sync::Mutex::new(QuarantineDeltaBuffer::default())),
            drain_poll_millis: Arc::new(std::sync::atomic::AtomicU64::new(
                TASK_QUARANTINE_DRAIN_POLL_SECS.saturating_mul(1_000),
            )),
        })
    }

    /// Shorten the ADR-0068 D2 drain poll for a fixture. `cfg(test)` only and
    /// per-instance, so the poll fixtures are fast without a process-global knob
    /// that would couple parallel tests. Must be called before
    /// [`start_with_spawner`](Self::start_with_spawner).
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
    /// The listener also drains on its own once it observes the marker gone;
    /// this is the explicit entry point for the clear route and for
    /// deterministic tests, so neither has to wait for a poll.
    pub async fn resume_quarantined_ingest(&self) -> usize {
        drain_and_persist(
            &self.ingest_gate,
            &self.quarantine_buffer,
            &self.task_list,
            self.persist_ctx().as_ref(),
        )
        .await
    }

    /// ADR-0068 D2: how many inbound deltas are currently held because the
    /// group is fork-quarantined.
    #[must_use]
    pub fn quarantined_buffer_len(&self) -> usize {
        lock_buffer(&self.quarantine_buffer).len()
    }

    /// The state-sync side topic for this task list.
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
    ///
    /// Identical to [`start`](Self::start), but routes the background loops
    /// (delta-merge listener, state-request responder, and the bounded
    /// bootstrap requester) through `spawn` instead of detaching them with
    /// `tokio::spawn`. The `Agent` passes its tracked-task spawner so these
    /// loops are registered with the `Agent::shutdown()` drain and aborted on
    /// teardown (issue #126); callers without an `Agent` use
    /// [`start`](Self::start), which detaches via `tokio::spawn` as before.
    pub async fn start_with_spawner<S>(&self, spawn: S) -> Result<()>
    where
        S: Fn(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>)
            + Send
            + Sync,
    {
        // Subscribe to topic — received messages will contain serialized deltas.
        let mut sub = self.pubsub.subscribe(self.topic.clone()).await;
        let task_list = Arc::clone(&self.task_list);
        let listener_cancel = self.cancel.clone();
        // StateServed evidence: written by the responder loop (which owns
        // the side-topic subscription), read by the listener (verified
        // full-replace adopt, issue #240) and the bootstrap requester
        // (convergence). Created BEFORE the loops so all three share it.
        let served_evidence = Arc::new(std::sync::Mutex::new(TaskServedEvidence::default()));
        // Armed only while the bootstrap requester runs: the verified
        // full-replace adopt fires exclusively in that window — a converged
        // replica must never let a divergent holder's serve truncate state
        // it legitimately holds.
        let bootstrap_active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener_served = Arc::clone(&served_evidence);
        let listener_bootstrap_active = Arc::clone(&bootstrap_active);
        // #557: snapshot merged remote deltas when persistence is armed.
        // Best-effort by design — a failing disk must never wedge
        // replication (the degraded flag refuses LOCAL mutations instead).
        let listener_persist = self.persist_ctx();
        // ADR-0068 D2: read through the slot on every delta — the daemon
        // installs the gate after this loop is already running.
        let listener_gate = Arc::clone(&self.ingest_gate);
        let listener_buffer = Arc::clone(&self.quarantine_buffer);
        let listener_poll_millis = Arc::clone(&self.drain_poll_millis);

        spawn(Box::pin(async move {
            // #732 finding 5: the drain deadline lives ACROSS receives. It used
            // to be a fresh `sleep` created inside `select!` on every iteration,
            // so every received message cancelled the timer and traffic arriving
            // faster than the poll starved the drain indefinitely — the runbook's
            // "picked up within five seconds" was false under load. The sleep is
            // pinned here and reset only when it has FIRED, so a message
            // postpones nothing.
            let poll = tokio::time::sleep(std::time::Duration::from_millis(
                listener_poll_millis.load(std::sync::atomic::Ordering::Relaxed),
            ));
            tokio::pin!(poll);
            let mut poll_armed = false;
            loop {
                // ADR-0068 D2: the drain poll is armed ONLY while deltas are
                // held, so a list that was never quarantined adds no timer.
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
                let msg = tokio::select! {
                    // cancel_sync tears down every loop (round-4 review) —
                    // recv alone would keep this listener alive until
                    // daemon shutdown.
                    () = listener_cancel.cancelled() => return,
                    () = &mut poll, if poll_armed => {
                        // Observed rather than hooked at each clear site: see
                        // TASK_QUARANTINE_DRAIN_POLL_SECS for why. The drain
                        // itself re-reads the marker, so there is no separate
                        // suspension pre-check to disagree with it.
                        poll_armed = false;
                        drain_and_persist(
                            &listener_gate,
                            &listener_buffer,
                            &task_list,
                            listener_persist.as_ref(),
                        )
                        .await;
                        continue;
                    }
                    msg = sub.recv() => msg,
                };
                let Some(msg) = msg else {
                    // The main-topic subscription is gone: this sync can no
                    // longer replicate, so it is half-dead — self-cancel so
                    // the sibling loops (in particular the INFINITE
                    // bootstrap requester) never outlive it (parallel-review
                    // finding: a dead sibling must not leave the requester
                    // chattering at capped cadence forever).
                    listener_cancel.cancel();
                    return;
                };
                match decode_delta::<TaskListDelta>(&msg.payload) {
                    Ok((peer_id, delta)) => {
                        // #732 finding 5: older HELD deltas drain before this
                        // newer one is admitted. Two reasons. Ordering: applying
                        // post-clear traffic first would put it ahead of deltas
                        // that arrived before it, and the LWW registers are
                        // order-sensitive. Liveness: the drain then happens on
                        // the first delta after the clear instead of waiting on
                        // a timer, which is what makes continuous traffic
                        // accelerate the catch-up rather than starve it. Costs
                        // one gate read per delta ONLY while the buffer is
                        // non-empty, i.e. only during an incident.
                        if !lock_buffer(&listener_buffer).is_empty() {
                            drain_and_persist(
                                &listener_gate,
                                &listener_buffer,
                                &task_list,
                                listener_persist.as_ref(),
                            )
                            .await;
                        }
                        // ADR-0068 D2: from the first delta that OBSERVES a live
                        // fork-quarantine marker, deltas are HELD in arrival order
                        // and the list is left byte-identical — the remote mirror
                        // of row 20's local refusals, so a peer seated by the
                        // disputed roster cannot move the CRDT winner during the
                        // incident. One delta already admitted when the marker
                        // installs may still merge; that residual is stated at
                        // `admit_or_buffer` and is bounded to one per listener.
                        let (delta, admitted) = match admit_or_buffer(
                            listener_gate.gate(),
                            &listener_buffer,
                            &task_list,
                            peer_id,
                            delta,
                            msg.sender.as_ref(),
                            msg.payload.len(),
                        )
                        .await
                        {
                            Admission::Held => continue,
                            Admission::Apply(delta, guard) => (delta, guard),
                        };
                        let mut merged_ok = false;
                        {
                            // The guard the admission decision was taken
                            // under: decision and merge are one critical
                            // section (ADR-0068 D2, review nit 2).
                            let mut list = admitted;
                            // Layer A (issue #349): the V2-envelope-verified
                            // sender is the writer identity; the payload
                            // `peer_id` stays an OR-Set tag only (I3).
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
                                // Digest-verified full-replace adopt (issue
                                // #240, deletion cold-sync): while
                                // bootstrapping, when the sender's latest v2
                                // declaration matches this delta's served
                                // content (digest AND task count), the delta IS
                                // that holder's complete state — prune local
                                // tasks it does not carry. Without verification
                                // any holder could truncate local state at
                                // will. Which tasks may be pruned is decided
                                // by `prune_to_served_set` on holder-carried
                                // deletion evidence (issue #643), and only
                                // for a writer the list's content policy
                                // accepts (issue #654).
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
                        } // write guard released before persisting
                        if merged_ok {
                            if let Some(ctx) = &listener_persist {
                                if let Err(e) = persist_snapshot(&task_list, ctx).await {
                                    tracing::warn!("failed to persist merged task-list delta: {e}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize delta from topic: {}", e);
                    }
                }
            }
        }));

        // Responder: holders with non-empty state answer StateRequests by
        // republishing their full state as a regular delta on the main topic.
        // CRDT merge makes duplicate responses from multiple holders harmless
        // (idempotent), so no response suppression is needed at current mesh
        // sizes.
        let mut sync_sub = self.pubsub.subscribe(self.state_sync_topic()).await;
        let responder_list = Arc::clone(&self.task_list);
        let responder_pubsub = Arc::clone(&self.pubsub);
        let responder_topic = self.topic.clone();
        let sync_topic = self.state_sync_topic();
        let responder_served = Arc::clone(&served_evidence);
        let responder_cancel = self.cancel.clone();
        let local_peer_id = self.local_peer_id;
        spawn(Box::pin(async move {
            // Response-storm damping (issue #238 review): one full-state
            // response per cooldown window — the response is a broadcast,
            // so it serves every concurrently-bootstrapping replica. A
            // request landing inside the window gets NOTHING (no response,
            // no marker — markers must witness a real broadcast, round-3
            // review); the requester is served by its next scheduled
            // attempt.
            let mut last_full_response: Option<tokio::time::Instant> = None;
            loop {
                let msg = tokio::select! {
                    // cancel_sync tears down every loop (round-4 review).
                    () = responder_cancel.cancelled() => return,
                    msg = sync_sub.recv() => msg,
                };
                let Some(msg) = msg else {
                    // The side-topic subscription is gone: this sync can no
                    // longer receive StateServed evidence, so the requester
                    // could never legitimately stop — self-cancel so it
                    // (and the sibling loops) never outlive the responder.
                    responder_cancel.cancel();
                    return;
                };
                let Ok(sync_msg) = bincode::deserialize::<TaskListSyncMessage>(&msg.payload) else {
                    continue;
                };
                match sync_msg {
                    TaskListSyncMessage::StateRequest { requester } => {
                        if requester == local_peer_id {
                            continue;
                        }
                        let mut markers: Vec<TaskListSyncMessage> = Vec::new();
                        if responder_list.read().await.task_count() == 0 {
                            // Empty holder: the v2 digest of the empty set
                            // is universally computable, so an empty
                            // requester verifies it locally and stops
                            // (issue #240; no broadcast to witness because
                            // there is nothing to serve, and no cooldown —
                            // damping exists to bound FULL-state storms).
                            // v1 behavior is preserved for old peers:
                            // silence (two empty replicas must not talk
                            // each other into a false converged-empty under
                            // the unverifiable v1 rule).
                            let digest = responder_list.read().await.served_digest();
                            markers.push(TaskListSyncMessage::StateServedV2 {
                                responder: local_peer_id,
                                digest,
                                entry_count: 0,
                            });
                        } else {
                            // The StateServed markers are published ONLY
                            // alongside an actual full-delta publish: a
                            // marker must witness a real broadcast — one
                            // sent for a cooldown-suppressed response could
                            // convince a requester that never received the
                            // state to stop asking (round-3 review). A
                            // requester inside the window is served by its
                            // next scheduled attempt. Checked BEFORE
                            // building the full delta — no point cloning
                            // the whole list for a suppressed response.
                            let cooled_down = last_full_response.is_some_and(|t| {
                                t.elapsed()
                                    < std::time::Duration::from_secs(STATE_RESPONSE_COOLDOWN_SECS)
                            });
                            if cooled_down {
                                continue;
                            }
                            // One snapshot for the full delta AND the v2
                            // digest, so the declaration commits to exactly
                            // what was broadcast.
                            let (full, digest, count) = {
                                let list = responder_list.read().await;
                                (
                                    list.full_delta(),
                                    list.served_digest(),
                                    list.task_count() as u32,
                                )
                            };
                            let Ok(serialized) = encode_delta(local_peer_id, &full) else {
                                continue;
                            };
                            if let Err(e) = responder_pubsub
                                .publish(responder_topic.clone(), bytes::Bytes::from(serialized))
                                .await
                            {
                                tracing::warn!("TaskList state-response publish failed: {e}");
                                continue;
                            }
                            last_full_response = Some(tokio::time::Instant::now());
                            markers.push(TaskListSyncMessage::StateServed {
                                responder: local_peer_id,
                            });
                            // The v2 marker rides along with the broadcast
                            // it commits to — never separately
                            // (response-storm damping, issue #240).
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
                            continue; // our own marker echoed back
                        }
                        // Trust note: the marker steers only WHEN the
                        // requester stops asking, never list content, and
                        // the requester still requires local non-emptiness
                        // — a forged marker cannot inject state and stops
                        // recovery no earlier than a real holder could.
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
                            continue; // our own marker echoed back
                        }
                        // Trust note: the digest is SELF-VERIFYING — a
                        // forged declaration can only match local state
                        // that actually equals the declared content, so a
                        // forgery's worst case is the requester keeps
                        // asking (the same bound as a forged v1 marker).
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

        // Bootstrap requester: a first-time joiner starts with an empty list
        // and has no other way to learn tasks written before it subscribed
        // (the gossip message cache only replays recent deltas). Ask holders
        // to republish. The schedule is front-loaded for a fast mesh, then
        // runs an INFINITE backoff tail (issue #238): holders answer only
        // reactively, so a hard-capped tail left a list that rehydrated
        // while every holder was offline permanently un-synced once the cap
        // expired. The FULL front burst always runs (aligned with
        // `KvStoreSync`, round-1 review): a single incremental task arriving
        // via live gossip before the first request must not cancel the
        // request for the complete historical state. The tail then
        // self-terminates the moment the local list is non-empty; until
        // then a genuinely-new list costs one tiny side-topic message per
        // backoff interval. Requests and the full-delta responses they
        // trigger are idempotent CRDT merges, so the extra chatter is
        // harmless.
        if self.task_list.read().await.task_count() == 0 {
            let requester_pubsub = Arc::clone(&self.pubsub);
            // Weak: the requester must not keep the list alive on its own.
            // (Belt-and-braces — the sibling loops hold strong Arcs, so the
            // authoritative kill switch is the `stopped` flag below.)
            let requester_list = Arc::downgrade(&self.task_list);
            let sync_topic = self.state_sync_topic();
            let stopped = Arc::clone(&self.stopped);
            let requester_cancel = self.cancel.clone();
            let requester_served = Arc::clone(&served_evidence);
            let requester_bootstrap_active = Arc::clone(&bootstrap_active);
            bootstrap_active.store(true, std::sync::atomic::Ordering::Relaxed);
            spawn(Box::pin(async move {
                // Disarms the adopt window on ANY exit (converged, silenced,
                // cancelled, torn down) — the listener's verified
                // full-replace adopt must never fire outside bootstrap.
                let _guard = BootstrapGuard(requester_bootstrap_active);
                for (attempt, delay_secs) in state_request_delays().enumerate() {
                    tokio::select! {
                        // cancel_sync tears down every loop promptly, even
                        // mid-sleep (round-4 review).
                        () = requester_cancel.cancelled() => return,
                        () = tokio::time::sleep(jittered_secs(delay_secs)) => {}
                    }
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        return; // silenced — never chatter for a dead sync
                    }
                    // Tail attempts stop on convergence; front attempts
                    // always run (see above). Convergence requires BOTH a
                    // StateServed marker (a holder actually answered) AND
                    // local state — mere non-emptiness can be faked by one
                    // incremental delta while full history is still missing
                    // (round-2 review). v2 digest evidence makes the check
                    // exact (issue #240): the requester stops only when its
                    // OWN content digest matches a holder's declaration —
                    // including the universally-computable empty digest,
                    // which lets a genuinely-empty list fall silent.
                    if attempt >= STATE_REQUEST_RETRY_SECS.len() {
                        let Some(list) = requester_list.upgrade() else {
                            return; // sync torn down — nothing left to bootstrap
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
                            return; // a holder served us and local state matches
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
        // End the loops FIRST: the bootstrap requester's schedule is
        // infinite while the list is empty (issue #238), and unsubscribing
        // does not end that loop (it holds no subscription).
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
        let mut task_list = self.task_list.write().await;
        task_list.merge_delta(&delta, peer_id, writer)?;
        Ok(())
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
        let serialized = encode_delta(local_peer_id, &delta).map_err(|e| {
            crate::crdt::CrdtError::Gossip(format!("failed to serialize delta: {e}"))
        })?;

        self.pubsub
            .publish(self.topic.clone(), bytes::Bytes::from(serialized))
            .await
            .map_err(|e| crate::crdt::CrdtError::Gossip(format!("failed to publish delta: {e}")))?;

        Ok(())
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
            }));
        }
    }

    /// Clone the armed persistence context, if any.
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

    /// Construct an isolated network node (mirrors the helper in
    /// `src/gossip/pubsub.rs` tests). `PubSubManager` is fully constructable
    /// in tests, so `TaskListSync` is testable end-to-end without a live mesh.
    /// Explicit test-only network config (#417/#337): loopback bind, no
    /// seeds, discovery/port-mapping off. Still a real socket constructor.
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

    /// Build a `TaskListSync` around a fresh node + pubsub, with
    /// `local_peer_id = peer(1)` and list id `list_id(1)`.
    async fn make_sync(topic: &str) -> TaskListSync {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        TaskListSync::new(list, pubsub, topic.to_string(), peer(1)).expect("task list sync")
    }

    /// Shared pubsub with a SIGNING context: local publishes carry a
    /// V2-envelope-verified sender, so the delta-merge listener's Layer A
    /// gate (issue #349) admits their content. The convergence tests below
    /// need this — an unsigned pubsub would fail closed on every serve.
    async fn signed_pubsub() -> Arc<PubSubManager> {
        signed_pubsub_with_signer().await.0
    }

    /// As [`signed_pubsub`], also returning the signer's `AgentId` — the writer
    /// identity the listener will see on every publish, which the ADR-0068
    /// fixtures need in order to script a roster that actually seats it.
    async fn signed_pubsub_with_signer() -> (Arc<PubSubManager>, AgentId) {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        let signer = kp.agent_id();
        let signing = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        (
            Arc::new(PubSubManager::new(node, Some(signing)).expect("pubsub")),
            signer,
        )
    }

    /// Build a `TaskListSync` that shares its pubsub with the caller (so the
    /// caller can subscribe before the sync publishes).
    async fn make_sync_with_pubsub(topic: &str) -> (TaskListSync, Arc<PubSubManager>) {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
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

        // We cannot create a real PubSubManager in a unit test without a NetworkNode
        // For now, we just verify the types are correct
        let _list_for_sync = task_list;
    }

    #[tokio::test]
    async fn test_apply_delta() {
        // Create a task list
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test".to_string(), peer1);

        // Wrap in Arc<RwLock<>>
        let task_list_arc = Arc::new(RwLock::new(task_list));

        // Create a delta with a new task
        let mut delta = TaskListDelta::new(1);
        let task = make_task(1, peer2);
        let task_id = *task.id();
        let tag = (peer2, 1);
        delta.added_tasks.insert(task_id, (task, tag));

        // Apply delta directly (simulating what TaskListSync::apply_remote_delta does)
        {
            let mut list = task_list_arc.write().await;
            let result = list.merge_delta(&delta, peer2, Some(&agent(2)));
            assert!(result.is_ok());
        }

        // Verify task was added
        {
            let list = task_list_arc.read().await;
            assert_eq!(list.task_count(), 1);
        }
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        // Test that RwLock allows multiple readers
        let peer = peer(1);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test".to_string(), peer);
        let task_list_arc = Arc::new(RwLock::new(task_list));

        // Multiple concurrent reads should work
        let list1 = task_list_arc.read().await;
        let list2 = task_list_arc.read().await;

        assert_eq!(list1.name(), "Test");
        assert_eq!(list2.name(), "Test");

        drop(list1);
        drop(list2);

        // Write should work after readers drop
        {
            let mut list = task_list_arc.write().await;
            list.update_name("Updated".to_string(), peer);
        }

        // Verify update
        let list = task_list_arc.read().await;
        assert_eq!(list.name(), "Updated");
    }

    // ------------------------------------------------------------------
    // new() / topic() / read() / write()
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn new_sets_topic_and_yields_accessible_guards() {
        let sync = make_sync("tasks/A").await;

        // topic() reports exactly the topic handed to new().
        assert_eq!(sync.topic(), "tasks/A");

        // read() exposes the underlying list unchanged.
        {
            let list = sync.read().await;
            assert_eq!(list.name(), "Test List");
            assert_eq!(list.task_count(), 0);
        }

        // write() returns a mutable guard; verify it is usable by renaming
        // the list, then observe the rename via read().
        {
            let mut list = sync.write().await;
            list.update_name("Renamed".to_string(), peer(1));
        }
        let list = sync.read().await;
        assert_eq!(list.name(), "Renamed", "write-guard rename must be visible");
    }

    // ------------------------------------------------------------------
    // state_sync_topic() (private helper exercised from the test module)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn state_sync_topic_appends_side_channel_suffix() {
        let sync = make_sync("tasks/B").await;
        // The private helper forms the side channel by appending the suffix.
        assert_eq!(sync.state_sync_topic(), "tasks/B/state-sync");

        // Suffix is appended exactly once, regardless of slashes in topic.
        let sync2 = make_sync("tasks/B/nested").await;
        assert_eq!(sync2.state_sync_topic(), "tasks/B/nested/state-sync");
    }

    // ------------------------------------------------------------------
    // apply_remote_delta(): direct (off-wire) merge into the local list
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn apply_remote_delta_merges_task_into_list() {
        let sync = make_sync("tasks/C").await;

        // Start empty.
        assert_eq!(sync.read().await.task_count(), 0);

        // Build a delta carrying one task authored by peer(2).
        let remote = peer(2);
        let task = make_task(7, remote);
        let task_id = *task.id();
        let mut delta = TaskListDelta::new(1);
        delta.added_tasks.insert(task_id, (task, (remote, 1)));

        // Layer A (issue #349): the honest path needs an envelope-verified
        // writer for content to apply.
        let alice = agent(1);
        sync.apply_remote_delta(remote, delta, Some(&alice))
            .await
            .expect("apply_remote_delta");

        // The task must be present and retrievable by id.
        let list = sync.read().await;
        assert_eq!(list.task_count(), 1, "merged task must bump the count");
        assert!(
            list.get_task(&task_id).is_some(),
            "merged task must be retrievable by id"
        );
    }

    // ------------------------------------------------------------------
    // publish_delta(): wire round-trip observed by a subscriber
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn publish_delta_delivers_encoded_pair_to_subscriber() {
        let (sync, pubsub) = make_sync_with_pubsub("tasks/D").await;

        // Subscribe to the main topic BEFORE publishing so we observe the
        // exact bytes TaskListSync places on the wire.
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

        // The published payload must decode back to the (sender, delta) pair
        // that publish_delta encoded — proving the wire format is correct.
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

    // ------------------------------------------------------------------
    // start_with_spawner(): custom spawner path (documented smoke test)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn start_with_spawner_accepts_custom_spawner_and_returns_ok() {
        // Unique value vs `start_default_spawner_merges_remote_delta`: this
        // routes the background futures through a *custom* (non-`tokio::spawn`)
        // spawner closure — a drop-spawner — exercising that generic code path
        // and asserting `start_with_spawner` returns `Ok` without panicking.
        //
        // It deliberately does NOT assert that a subscription or merge
        // occurred: a drop-spawner makes subscription unobservable, so this
        // would still pass against a no-op `Ok(())` impl. The real
        // subscribe->merge behaviour is asserted end-to-end by
        // `start_default_spawner_merges_remote_delta`, which drives
        // `start_with_spawner(tokio::spawn)` and proves Layer A I2 (unsigned add does not land).
        let sync = make_sync("tasks/E").await;
        sync.start_with_spawner(|_fut| {
            // intentionally drop the future
        })
        .await
        .expect("start_with_spawner");
    }

    // ------------------------------------------------------------------
    // start(): default spawner merges a remotely-published delta
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn start_default_spawner_merges_remote_delta() {
        // End-to-end exercise of the delta-merge listener through the Layer A
        // gate (issue #349, I2): a delta published on the topic is received
        // by the background loop spawned by start() and merged with the
        // V2-envelope-verified sender as the writer. A PubSubManager with no
        // signing context publishes UNSIGNED (anonymous-sender) messages, so
        // the listener must fail closed on content: the delta's first-seen
        // task add must NOT land, while an attested checkbox claim on a task
        // the receiver already holds must still converge (checkbox admission
        // is gated by OpAttestation, not by the envelope writer).
        let sync = make_sync("tasks/F").await;

        sync.start().await.expect("start");

        // Let the spawned subscribe-forwarder register before we publish.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Seed an existing local task (local mutators are the trusted path —
        // they are not the untrusted apply route this test exercises).
        let remote = peer(2);
        let existing = make_task(5, remote);
        let existing_id = *existing.id();
        {
            let mut list = sync.write().await;
            list.add_task(existing, remote, 1).expect("seed local task");
        }

        // Unsigned delta: a first-seen add PLUS a validly-attested claim on
        // the existing task. The claim is the positive evidence that the
        // listener processed the message, so "add did not land" below is a
        // real gate decision, not a dead listener.
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        let signing = crate::gossip::SigningContext::from_keypair(&kp);
        let claimer = kp.agent_id();
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

        // The claim applies (checkbox path still runs for writer=None)…
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
            "unsigned publish must still reach checkbox admission"
        );

        // …but the unsigned content must NOT land (I2).
        assert!(
            sync.read().await.get_task(&new_task_id).is_none(),
            "unsigned (anonymous-sender) publish must not create a task (I2)"
        );
        assert_eq!(
            sync.read().await.task_count(),
            1,
            "only the locally seeded task is present"
        );
    }

    // ------------------------------------------------------------------
    // stop(): returns Ok and is idempotent
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn stop_returns_ok_and_is_idempotent() {
        let sync = make_sync("tasks/G").await;
        sync.stop().await.expect("first stop");
        // stop() unsubscribes both the main and the state-sync topic;
        // unsubscribe is infallible and tolerant of already-removed topics,
        // so a second stop() must remain Ok.
        sync.stop().await.expect("second stop (idempotent)");
    }

    /// WHY (rounds 1+4 review): the requester's schedule is INFINITE while
    /// the list is empty, and the sibling loops hold strong `Arc`s to the
    /// list — so the cancellation token (all loops) and the
    /// silence_bootstrap flag (requester only) are the only things that end
    /// a discarded sync's background work before daemon shutdown.
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

    /// WHY (parallel-review finding): teardown must be STRUCTURAL — a
    /// caller that discards its last reference without remembering
    /// cancel_sync() must still end all background loops (the requester is
    /// infinite while unconverged), so Drop cancels the token.
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

    // ------------------------------------------------------------------
    // Issue #238: the bootstrap requester must never give up while empty
    // ------------------------------------------------------------------

    /// WHY: holders answer state requests reactively and never volunteer
    /// state to a late subscriber, so the request schedule is the only
    /// recovery trigger. The previous hard cap (20 × 30s ≈ 10 min) left a
    /// list that rehydrated while every holder was offline permanently
    /// empty once the cap expired. The schedule must be front-loaded, then
    /// an infinite capped tail — convergence is the only stop condition.
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

    /// WHY (round-2 review — P1: one incremental delta must not silence
    /// recovery): a live task arriving before any holder has actually
    /// SERVED full state makes the list non-empty, and the round-1 tail
    /// exited on non-emptiness alone — permanently missing all older
    /// tasks. Convergence now additionally requires a StateServed marker,
    /// so the bait delta leaves the requester alive and a late full holder
    /// still gets asked.
    #[tokio::test(start_paused = true)]
    async fn single_incremental_delta_does_not_stop_recovery() {
        // Signed pubsub (Layer A, issue #349): the bait delta and the late
        // holder's serves must carry an envelope-verified writer or the
        // listener drops their content.
        let pubsub = signed_pubsub().await;
        let topic = "tasks-238-bait";

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        // Past the front burst with nobody online.
        tokio::time::sleep(Duration::from_secs(70)).await;

        // The bait: ONE live incremental delta (task 2) — no full response,
        // no StateServed marker. The list becomes non-empty.
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

        // A holder with the FULL history (task 1 and task 2) appears long
        // after the bait. Only a still-alive requester can reach it.
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

    /// WHY (issue #238 — zombie subscription): a joiner whose every request
    /// fired while all holders were offline must still converge when a
    /// holder returns — even long after the OLD hard cap (front ~51s +
    /// 20 × 30s ≈ 651s) would have silenced the requester forever. Paused
    /// time drives the virtual clock, so the >10-minute scenario runs in
    /// moments.
    #[tokio::test(start_paused = true)]
    async fn requester_recovers_when_holder_returns_after_old_hard_cap() {
        // Signed pubsub (Layer A, issue #349): the holder's serve must carry
        // an envelope-verified writer or the listener drops its content.
        let pubsub = signed_pubsub().await;
        let topic = "tasks-238-zombie";

        // Empty joiner: subscribes and starts requesting into the void.
        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        // Sail PAST the old hard cap with no holder online. The old code is
        // permanently silent from here on — this is the zombie window.
        tokio::time::sleep(Duration::from_secs(700)).await;
        assert_eq!(
            joiner.read().await.task_count(),
            0,
            "nobody was online to answer"
        );

        // A holder with state appears. It only answers when ASKED, so the
        // joiner's tail must still be alive to ask.
        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("add task");
        let holder =
            TaskListSync::new(holder_list, Arc::clone(&pubsub), topic.to_string(), peer(1))
                .expect("holder sync");
        holder.start().await.expect("start holder");

        // The next tail request is at most STATE_REQUEST_TAIL_CAP_SECS away.
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

    // ------------------------------------------------------------------
    // Issue #240: digest-verified convergence evidence
    // ------------------------------------------------------------------

    /// Drain every side-topic `StateRequest` from `from` already queued on
    /// `probe` without blocking (the 1ms virtual timeout yields immediately
    /// under the paused clock when the queue is empty).
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

    /// WHY (issue #240): the convergence rule must weigh v2 digest evidence
    /// above the weak v1 rule, with the data-bearing-claim-wins tiebreak —
    /// and NO evidence is NEVER convergence.
    #[test]
    fn tasklist_convergence_rule() {
        const D1: [u8; 32] = [1u8; 32];
        const D2: [u8; 32] = [2u8; 32];
        const D_EMPTY: [u8; 32] = [9u8; 32];
        let none = TaskServedEvidence::default();
        assert!(!tasklist_converged(&none, 0, D1));
        assert!(!tasklist_converged(&none, 5, D1));

        // v1 weak rule: marker + local non-emptiness.
        let v1 = TaskServedEvidence {
            saw_v1: true,
            digests: std::collections::HashMap::new(),
        };
        assert!(!tasklist_converged(&v1, 0, D1));
        assert!(tasklist_converged(&v1, 3, D1));

        // v2 digest gate: match stops, mismatch keeps asking, and v2
        // outranks the weak v1 rule.
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

        // Empty-holder declarations converge an empty requester only when
        // every declaration is empty (data-bearing claim wins).
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

    /// WHY: the v2 digest commits to the served task set so a requester can
    /// verify completeness LOCALLY. It must be deterministic across
    /// replicas, sensitive to membership, insensitive to name/ordering
    /// metadata, and bound to the list id; a full delta's carried digest
    /// must equal the serving list's local digest.
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

        // The same task in both lists ⇒ the same digest, however it got
        // there (OR-Set writer tags are transport, not content).
        let task = make_task(7, peer(3));
        a.add_task(task.clone(), peer(1), 1).expect("add a");
        b.add_task(task, peer(2), 1).expect("add b");
        assert_eq!(a.served_digest(), b.served_digest());

        // A full delta's served digest equals the local digest; an
        // incremental delta is not full-state-shaped and must not
        // impersonate a serve.
        let full = a.full_delta();
        assert_eq!(full.served_digest(&list_id(1)), Some(a.served_digest()));
        let inc = TaskListDelta::for_add(
            TaskId::from_bytes([8; 32]),
            make_task(8, peer(1)),
            (peer(1), 1),
            2,
        );
        assert_eq!(inc.served_digest(&list_id(1)), None);

        // Different membership ⇒ different digest.
        b.add_task(make_task(9, peer(2)), peer(2), 2)
            .expect("add b2");
        assert_ne!(a.served_digest(), b.served_digest());
    }

    /// WHY (issue #240, residual 1 — the cross-topic loss window): the full
    /// delta travels on the main topic, its marker on the side topic, with
    /// no delivery coupling. If the delta is lost while the marker
    /// survives, the v1 rule stopped a non-empty requester with incomplete
    /// history. With the v2 digest the requester detects the mismatch
    /// (local {t2} vs declared {t1,t2}) and keeps asking until the real
    /// state arrives.
    #[tokio::test(start_paused = true)]
    async fn lost_full_delta_with_surviving_marker_keeps_requester_asking() {
        // Signed pubsub (Layer A, issue #349): the holder's full serve must
        // carry an envelope-verified writer or the listener drops its
        // content.
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-lost-broadcast";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // The full holder state (offline for now): {t1, t2}.
        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("holder t1");
        holder_list
            .add_task(make_task(2, peer(1)), peer(1), 2)
            .expect("holder t2");

        // The joiner starts EMPTY (a non-empty task list never bootstraps
        // — only empty lists run the requester).
        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        let mut probe = pubsub.subscribe(side.clone()).await;
        joiner.start().await.expect("start joiner");

        // "One live incremental delta": the joiner ends up holding only t2,
        // cloned out of the holder's own full delta so the resolved fields
        // are byte-identical and the post-recovery digests can match
        // exactly. Merged directly into the store — this is the state the
        // live-gossip bait leaves behind.
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

        // The loss window: the marker survives, the full delta does not.
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

        // Well past the front burst the requester must STILL be asking —
        // its local digest ({t2}) does not match the declaration ({t1,t2}).
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

        // The real holder returns: the next serve delivers {t1,t2}, the
        // local digest then matches the declaration, and the tail stops.
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

        // Convergence is terminal: no further requests.
        tokio::time::sleep(Duration::from_secs(160)).await;
        drain_state_requests(&mut probe, peer(2)).await;
        let mut relapse = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            relapse += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert_eq!(relapse, 0, "a digest-matched requester must fall silent");
    }

    /// WHY (issue #240, residual 2 — deletion cold-sync): a full delta
    /// carries only live tasks, so a plain merge could never delete a stale
    /// replica's obsolete tasks. The digest-verified full-replace adopt
    /// closes that: the serve's delta content is bound to the holder's
    /// declared digest, and since #643 the prune additionally requires
    /// holder-carried DELETION EVIDENCE. Since #654 the prune is also
    /// gated by the list's content policy — an UNSIGNED serve (no
    /// envelope-verified writer) fails closed exactly like its adds
    /// would, which is why this test drives a signing pubsub (see
    /// `stale_full_serve_after_live_add_must_not_prune_the_live_task`).
    #[tokio::test(start_paused = true)]
    async fn digest_verified_full_serve_prunes_stale_tasks() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-prune-stale";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // Holder: added t1 and t_stale, then DELETED t_stale — its serve
        // carries the live set {t1} plus an ordering register that still
        // names t_stale, the causal evidence of the deletion.
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

        // Stale joiner: starts EMPTY (only empty lists run the requester),
        // then state lands the way it would in production — t1 (from the
        // holder's full delta, byte-identical) and t_stale (an obsolete
        // task the holder deleted while this replica was away) merge
        // directly into the store before the holder ever comes online.
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

        // The verified adopt must remove the stale task while t1 stays.
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

        // And convergence follows: local state now equals the declared
        // digest, so the requester falls silent.
        tokio::time::sleep(Duration::from_secs(160)).await;
        drain_state_requests(&mut probe, peer(2)).await;
        let mut relapse = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            relapse += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert_eq!(relapse, 0, "the requester must stop once the digests match");
    }

    /// WHY (issue #643): a digest-verified full serve proves the delta
    /// equals the holder's COMPLETE state at serve time — it does NOT prove
    /// that state is fresh relative to this replica. A serve solicited
    /// before the holder merged a live add delta can arrive AFTER this
    /// replica already merged the add; pruning on absence observe-removes
    /// the task, so a visibility read (GET) and a subsequent claim
    /// disagree and the claim fails `task not found` (observed as HTTP 500
    /// in the convergence soak, run 10 of 20260911-092818). The prune
    /// fires ONLY on explicit holder-carried removal evidence
    /// (empty-tag-set `removed_tasks` entries, #643 round 2) — a task the
    /// serve merely lacks is newer knowledge than the serve and adds-win
    /// keeps it.
    ///
    /// The stale holder here is NON-EMPTY (it carries an older task): that
    /// is the only serve shape production emits — responders with empty
    /// lists stay silent — and it makes the serve's digest and entry_count
    /// exactly what a live mesh would declare.
    #[tokio::test(start_paused = true)]
    async fn stale_full_serve_after_live_add_must_not_prune_the_live_task() {
        let pubsub = signed_pubsub().await;
        let topic = "tasks-643-stale-serve-race";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // The holder's PRE-add state: a real, non-empty full serve
        // (carrying the older task t0), snapshot and declaration captured
        // together exactly as the responder loop does.
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

        // The live add: T exists on the holder only as a published delta.
        let task = make_task(5, peer(1));
        let tid = *task.id();
        let add_seq = holder_list.next_seq();
        holder_list
            .add_task(task.clone(), peer(1), add_seq)
            .expect("holder add");
        let add_delta =
            TaskListDelta::for_add(tid, task, (peer(1), add_seq), holder_list.current_version());

        // The claimant: empty list, bootstrap requester armed (the adopt
        // window this race lives in).
        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        let mut probe = pubsub.subscribe(side.clone()).await;
        joiner.start().await.expect("start joiner");

        // The add delta lands via live gossip — the visibility read sees T.
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

        // The in-flight stale serve arrives next: declaration first (side
        // topic), then the serve itself (main topic) — a broadcast answered
        // before the holder ever merged the add.
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

        // Drive the bootstrap schedule well past delivery: request cycles
        // observed AFTER the serve prove the listener had ample turns to
        // process it. The joiner never converges here (local {T} vs
        // declared empty), exactly like the live mesh before any holder
        // declares the new content.
        let mut cycles = 0;
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            cycles += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert!(
            cycles >= 2,
            "the unconverged joiner keeps asking; cycles={cycles}"
        );

        // The claim must succeed against the same state the read saw.
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

    /// WHY (issue #240, residual 3 — genuinely-empty chatter): the v1 rule
    /// kept every empty list requesting forever (~1 side-topic message per
    /// 5 minutes) because an empty holder had to stay silent (two empty
    /// replicas must not talk each other into a FALSE converged-empty).
    /// The v2 digest of the empty set is universally computable, so an
    /// empty holder can now declare authoritative emptiness any empty
    /// requester verifies locally — converging on empty is verifiably
    /// CORRECT, and the chatter tail terminates.
    #[tokio::test(start_paused = true)]
    async fn empty_holder_v2_marker_terminates_empty_requester() {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let topic = "tasks-240-empty-silence";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // Both lists genuinely EMPTY.
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

        // Warm-up: the front burst fires and the empty holder's v2
        // declarations arrive; convergence should follow within a few tail
        // checks.
        tokio::time::sleep(Duration::from_secs(160)).await;
        drain_state_requests(&mut probe, peer(2)).await;
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
        // Signed pubsub (Layer A, issue #349): the full delta on the main
        // topic must carry an envelope-verified writer; the v1/v2 question
        // this test exercises is the SIDE-topic marker format, which stays
        // a raw v1 StateServed below.
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-v1-compat";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        // An "old peer" answers a request: full delta on the main topic,
        // v1 StateServed marker on the side topic — never a v2 marker.
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

        // Weak-evidence convergence: v1 marker + local state ⇒ the tail stops.
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

    /// WHY: a v2 marker whose digest does not correspond to any state the
    /// requester can hold (forged or corrupt) must NEVER converge it — the
    /// digest is self-verifying, so a bad declaration can only delay, never
    /// cause, convergence. Nor may it wedge later recovery: a genuine
    /// holder's fresh declaration replaces the bad one (per-responder
    /// latest-wins).
    #[tokio::test(start_paused = true)]
    async fn tampered_digest_is_rejected_and_does_not_wedge_recovery() {
        // Signed pubsub (Layer A, issue #349): the genuine holder's serve
        // must carry an envelope-verified writer; the tampered marker is
        // still published as a raw side-topic payload.
        let pubsub = signed_pubsub().await;
        let topic = "tasks-240-tampered";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let joiner_list = TaskList::new(list_id(1), "Test List".to_string(), peer(2));
        let joiner =
            TaskListSync::new(joiner_list, Arc::clone(&pubsub), topic.to_string(), peer(2))
                .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        // The tampered marker: a random digest no real state can match.
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

        // The requester keeps asking: its (empty) local digest can never
        // equal the forged declaration.
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

        // The genuine holder appears; its fresh declaration replaces the
        // tampered one (per-responder latest-wins) and recovery completes.
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

    /// WHY (F3, fix-loop — tombstone + hardcoded-tag deadlock): the adopt's
    /// prune is a local observe-remove, tombstoning the tags a previous
    /// full delta used. With a hardcoded synthetic tag, a later serve
    /// re-adding the same task would be silently rejected forever. Full
    /// deltas now mint FRESH tags, so a re-served task is accepted.
    #[test]
    fn pruned_task_is_accepted_when_re_served_with_fresh_tags() {
        let mut holder = TaskList::new(list_id(1), "List".to_string(), peer(1));
        holder
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("add t1");
        holder
            .add_task(make_task(2, peer(1)), peer(1), 2)
            .expect("add t2");

        // The replica absorbs a first full serve (both tasks).
        let mut replica = TaskList::new(list_id(1), "List".to_string(), peer(2));
        let s1 = holder.full_delta();
        replica
            .merge_delta(&s1, peer(1), Some(&agent(1)))
            .expect("serve 1");
        assert_eq!(replica.task_count(), 2);

        // The holder deletes the task; the next VERIFIED serve prunes it
        // (tombstoning the first serve's synthetic tag locally).
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

        // The holder RE-ADDS the task: a later serve must be accepted —
        // pre-fix, its synthetic tag was tombstoned by the prune and the
        // re-add silently dropped.
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

    /// WHY (issue #643 round 2, review case a): `reorder` rebuilds the
    /// LWW ordering register from LIVE ids only, so after a delete any
    /// reorder strips the deleted id from the ordering — the round-1
    /// "ordering names deleted ids" evidence rule then failed to prune,
    /// the stale replica kept the task with live tags, and its next full
    /// serve re-served the deleted task with FRESH tags — fleet-wide
    /// resurrection (#226 class). Deletion evidence must ride a MONOTONE
    /// carrier: the raise-only observed-removed set, carried in the serve
    /// as empty-tag-set `removed_tasks` entries. Delete → reorder → serve
    /// must still prune, and the pruned replica must not re-serve the
    /// task.
    #[test]
    fn delete_then_reorder_full_serve_still_prunes_without_resurrection() {
        let t1 = TaskId::from_bytes([1; 32]);
        let doomed = TaskId::from_bytes([2; 32]);

        // Holder: {t1, doomed}, then DELETES doomed, then REORDERS to the
        // live set — the register no longer names doomed.
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

        // The serve is a REAL full serve from the post-reorder holder.
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

        // A stale replica still holding both tasks merges the serve (which
        // must NOT delete on general merge) and then the digest-verified
        // adopt prunes doomed on the explicit evidence.
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

        // No resurrection: the pruned replica's own serve carries doomed
        // only as evidence — never as a fresh-tagged live entry.
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

    /// WHY (issue #643 round 2, review case b): out-of-order delivery can
    /// land a reorder delta whose ordering register names a task whose ADD
    /// has not arrived yet (delta.rs documents this as expected). An
    /// ordering mention is therefore not deletion evidence; under the
    /// round-1 rule this shape false-pruned a task the holder never even
    /// carried. Only explicit empty-tag-set removal evidence may prune.
    #[test]
    fn ordering_entry_without_add_or_evidence_is_not_pruned() {
        let phantom = TaskId::from_bytes([7; 32]);

        // Holder: {t1} only; its serve's ordering register is grafted to
        // ALSO name `phantom` — a reorder delta that outran phantom's add.
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

        // A replica holding phantom (its add landed separately) merges the
        // serve and runs the adopt prune: the ordering mention must not
        // remove phantom.
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

    /// WHY (issue #654): deletion is content. `merge_delta` drops removal
    /// evidence from a writer the list's policy would not accept content
    /// from (a removed member, an unverified envelope), but the adopt-gate
    /// prune acted directly on the wire delta — so on a group-scoped list
    /// a holder the policy just rejected could still DELETE tasks via
    /// empty-tag removal evidence in its serve, and the pruned replica
    /// would then forward that evidence fleet-wide. The prune must obey
    /// the same authorization as the merge that surrounds it.
    #[test]
    fn unauthorized_holder_removal_evidence_cannot_prune_group_list() {
        let t1 = TaskId::from_bytes([1; 32]);
        let doomed = TaskId::from_bytes([2; 32]);

        // Holder (member agent(1)) deletes `doomed`; its full serve
        // carries the deletion as explicit evidence and `t1` live.
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

        // Group-scoped replica: only agent(1) may write content.
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

        // A non-member's serve: the merge drops its content, and the
        // adopt prune must not act on its evidence either.
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

        // An unverified envelope (writer None) is not a content writer
        // either — `merge_delta` treats it the same way.
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

        // The same evidence from the authorized member still prunes —
        // the gate must not break legitimate deletion cold-sync.
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

    // ------------------------------------------------------------------
    // #732 findings 3 and 5 — the listener's gate ordering and its drain
    // ------------------------------------------------------------------

    /// A per-instance ADR-0068 D2 gate for the listener fixtures.
    ///
    /// Per-instance, never a `static`: these tests run in parallel with the rest
    /// of the module and a process-global switch would couple them — the flake
    /// class the `fork_quarantine` fault-injection refactor removed.
    #[derive(Debug, Default)]
    struct ListenerGate {
        suspended: std::sync::atomic::AtomicBool,
        /// The roster the pinned refresh installs. Seeded with the pubsub's
        /// signer, so the refresh authorizes exactly the writer these fixtures
        /// publish as — anything else would deny its content and the assertions
        /// would be about authorization rather than about ordering.
        roster: std::sync::Mutex<std::collections::HashSet<crate::identity::AgentId>>,
        buffered: std::sync::atomic::AtomicU64,
        dropped: std::sync::atomic::AtomicU64,
        applied: std::sync::atomic::AtomicU64,
    }

    impl ListenerGate {
        /// A gate whose pinned roster seats `signer`.
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

        /// A stable ADR-0067 token with no marker half — "this group is not
        /// quarantined right now", which is what the drain must see to proceed.
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
            // A stable token: these fixtures are about ordering and liveness,
            // not about the ADR-0067 re-check (which has its own fixtures in
            // `named_groups/tests/adr0068_task_buffer.rs`).
            Box::pin(async move { Some(Self::marker_free_token()) })
        }

        fn with_pinned_roster<'a>(
            &'a self,
            apply: &'a mut (dyn FnMut(Option<&AuthorizedRoster>) + Send),
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            // These listener fixtures are about the gate's ORDERING (installed
            // before the listener) and the drain's liveness. The pinning property
            // itself — a roster writer blocked for the whole merge — is asserted in
            // `named_groups/tests/adr0068_task_buffer.rs` against this same
            // function. Here the roster simply seats the publisher and carries no
            // marker, so the drain proceeds.
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

    /// A signed sync: publishes carry a V2-envelope-verified sender, so merged
    /// content actually lands and "the task is present" is a real merge. The
    /// returned `AgentId` is that sender.
    async fn make_signed_sync(topic: &str) -> (TaskListSync, AgentId) {
        let (sync, _pubsub, signer) = make_signed_sync_with_pubsub(topic).await;
        (sync, signer)
    }

    /// As [`make_signed_sync`], handing back the shared pubsub so a test can put
    /// arbitrary bytes on the same topic the listener reads.
    async fn make_signed_sync_with_pubsub(
        topic: &str,
    ) -> (TaskListSync, Arc<PubSubManager>, AgentId) {
        let (pubsub, signer) = signed_pubsub_with_signer().await;
        let list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        let sync = TaskListSync::new(list, Arc::clone(&pubsub), topic.to_string(), peer(1))
            .expect("task list sync");
        (sync, pubsub, signer)
    }

    /// One inbound delta that adds a distinct task.
    fn add_delta(seq: u64, id_byte: u8, from: PeerId) -> TaskListDelta {
        let task = make_task(id_byte, from);
        let mut delta = TaskListDelta::new(seq);
        delta.added_tasks.insert(*task.id(), (task, (from, seq)));
        delta
    }

    /// Wait for `check` to hold, or give up. Bounded polling rather than a fixed
    /// sleep, so a slow machine cannot make the assertion flake in either
    /// direction.
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

    /// #732 finding 3: a gate installed BEFORE `start` holds the first delta the
    /// listener ever sees. The negative control is the pre-fix ordering — a
    /// delta arriving while the slot is still empty MERGES, which is exactly
    /// what a restart with a quarantined group used to do.
    ///
    /// **Why this test and its siblings do NOT use `tokio::time::pause()`**
    /// (raised by both #756 reviewers, and a fair question). These four tests
    /// drive the REAL listener, which means a real `PubSubManager` over a real
    /// loopback QUIC node: gossip and transport keep their own timers, and under
    /// paused time either they never fire (delivery stalls forever) or
    /// auto-advance fires them in an order the test does not control — the test
    /// would be less deterministic, not more. Determinism here comes from not
    /// depending on elapsed time at all: the poll period is injected per instance
    /// (`set_drain_poll_millis`), every wait is a bounded poll on observable
    /// state rather than a fixed sleep, and no assertion mentions a duration. The
    /// interleaving properties that DO need exact orderings — the ADR-0067
    /// re-check, the #756 P1 roster race and the P2 clear-between-steps window —
    /// are asserted with counting barriers and no clock at all, in
    /// `named_groups/tests/adr0068_task_buffer.rs`, against the same functions
    /// this listener calls.
    #[tokio::test]
    async fn quarantine_gate_installed_before_start_holds_the_first_delta() {
        let (sync, signer) = make_signed_sync("tasks/adr0068-before-start").await;
        let gate = Arc::new(ListenerGate::seating(signer));
        gate.suspend(true);
        // The ordering the binding gives us: gate first, listener afterwards.
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

        // NEGATIVE CONTROL: the same delta on a list whose gate is installed
        // only AFTER it arrives — the pre-fix order — merges.
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

    /// #732 finding 5: a newly received delta drains the held ones BEFORE it is
    /// admitted — so post-clear traffic never applies ahead of deltas that
    /// arrived before it, and continuous traffic accelerates the catch-up
    /// instead of starving it. No timer is involved: the drain rides the very
    /// next message.
    #[tokio::test]
    async fn a_newer_delta_drains_the_buffer_before_it_is_admitted() {
        let (sync, signer) = make_signed_sync("tasks/adr0068-drain-first").await;
        let gate = Arc::new(ListenerGate::seating(signer));
        gate.suspend(true);
        assert!(sync
            .ingest_gate()
            .install(Arc::clone(&gate) as Arc<dyn TaskIngestGate>));
        // A poll far longer than this test: the drain below must come from the
        // inbound delta, never from the timer.
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

        // CONTROL: while the marker is still live a second delta is ALSO held,
        // so the assertions below are about the clear and not about a listener
        // that merges everything.
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

        // The marker clears. The next inbound delta must drain the two held
        // ones first and then apply itself.
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

    /// #732 finding 5, idle half: with NO further traffic the poll still drains,
    /// and once the buffer is empty it disarms (no further drains happen).
    ///
    /// The period is shortened through the per-instance `cfg(test)` hook, so this
    /// is fast without a process-global knob.
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

        // CONTROL: the poll fires repeatedly and must NOT apply anything while
        // the marker is live.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            sync.quarantined_buffer_len(),
            1,
            "control: the poll does not drain under a live marker"
        );
        assert_eq!(ListenerGate::count(&gate.applied), 0);

        // Cleared, with no traffic at all: the poll is the only trigger.
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
        // Disarmed: an empty buffer means the poll arm is not selected, so no
        // further drain (and no further gate read) happens.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            ListenerGate::count(&gate.applied),
            applied_once,
            "an empty buffer disarms the poll: nothing drains again"
        );
    }

    /// #732 finding 5, timer half: traffic the listener CANNOT drain on must not
    /// postpone the drain deadline either.
    ///
    /// Undecodable payloads are the discriminating case. They reach the listener,
    /// so the old per-iteration `sleep` inside `select!` was cancelled and
    /// re-created by every one of them — a peer publishing garbage faster than
    /// the poll period starved the drain for as long as it kept publishing, and
    /// the drain-before-admit path cannot help because such a message never gets
    /// as far as admission. With the deadline pinned across receives the buffer
    /// drains WHILE the garbage is still arriving.
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

        // The marker clears, and a flood of undecodable payloads starts —
        // faster than the poll period, and never reaching admission.
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
}
