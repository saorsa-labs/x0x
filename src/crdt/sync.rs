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

use crate::crdt::{Result, TaskList, TaskListDelta};
use crate::gossip::wire::{decode_delta, encode_delta};
use crate::gossip::PubSubManager;
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
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancel: tokio_util::sync::CancellationToken::new(),
        })
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

        spawn(Box::pin(async move {
            loop {
                let msg = tokio::select! {
                    // cancel_sync tears down every loop (round-4 review) —
                    // recv alone would keep this listener alive until
                    // daemon shutdown.
                    () = listener_cancel.cancelled() => return,
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
                        let mut list = task_list.write().await;
                        if let Err(e) = list.merge_delta(&delta, peer_id) {
                            tracing::warn!("Failed to merge remote delta: {}", e);
                        } else if listener_bootstrap_active
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
                            // will.
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
                                    let pruned = list.prune_to_served_set(&delta);
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
    /// * `peer_id` - The peer who sent this delta
    /// * `delta` - The delta to apply
    ///
    /// # Returns
    ///
    /// Ok(()) if the delta was applied successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if the merge fails.
    pub async fn apply_remote_delta(&self, peer_id: PeerId, delta: TaskListDelta) -> Result<()> {
        let mut task_list = self.task_list.write().await;
        task_list.merge_delta(&delta, peer_id)?;
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
    async fn make_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(NetworkConfig::default(), None, None)
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
            let result = list.merge_delta(&delta, peer2);
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

        sync.apply_remote_delta(remote, delta)
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
        // `start_with_spawner(tokio::spawn)` and verifies the task lands.
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
        // End-to-end exercise of the delta-merge listener: a delta published
        // on the topic is received by the background loop spawned by start()
        // and merged into the local list. TaskList::merge_delta takes no
        // writer identity, so an unsigned (anonymous-sender) publish — what
        // the wire delivers via a PubSubManager with no signing context —
        // merges without any access-control consideration.
        let sync = make_sync("tasks/F").await;

        sync.start().await.expect("start");

        // Let the spawned subscribe-forwarder register before we publish.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let remote = peer(2);
        let task = make_task(5, remote);
        let task_id = *task.id();
        let mut delta = TaskListDelta::new(1);
        delta.added_tasks.insert(task_id, (task, (remote, 1)));
        sync.publish_delta(remote, delta).await.expect("publish");

        // The merge is asynchronous; poll the list until the task lands.
        let landed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let count = sync.read().await.task_count();
                if count == 1 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        assert!(
            landed.is_ok(),
            "remote delta was not merged by start() loop"
        );
        // Confirm it's the right task, not just any count bump.
        assert!(
            sync.read().await.get_task(&task_id).is_some(),
            "merged task must be retrievable by id"
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
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
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
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
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
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
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
            .merge_delta(&t2_only, peer(1))
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
    /// declared digest, so pruning local tasks it omits is safe.
    #[tokio::test(start_paused = true)]
    async fn digest_verified_full_serve_prunes_stale_tasks() {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let topic = "tasks-240-prune-stale";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // Holder: only t1.
        let mut holder_list = TaskList::new(list_id(1), "Test List".to_string(), peer(1));
        holder_list
            .add_task(make_task(1, peer(1)), peer(1), 1)
            .expect("holder t1");

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
            l.merge_delta(&t1_only, peer(1)).expect("seed t1");
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
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
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
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
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
        replica.merge_delta(&s1, peer(1)).expect("serve 1");
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
        replica.merge_delta(&s2, peer(1)).expect("serve 2");
        assert_eq!(replica.prune_to_served_set(&s2), 1);
        assert!(replica.get_task(&doomed).is_none());

        // The holder RE-ADDS the task: a later serve must be accepted —
        // pre-fix, its synthetic tag was tombstoned by the prune and the
        // re-add silently dropped.
        holder
            .add_task(make_task(2, peer(1)), peer(1), 3)
            .expect("re-add");
        let s3 = holder.full_delta();
        replica.merge_delta(&s3, peer(1)).expect("serve 3");
        assert!(
            replica.get_task(&doomed).is_some(),
            "a re-served task must be accepted after a prune"
        );
    }
}
