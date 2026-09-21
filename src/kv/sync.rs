//! KvStore synchronization using anti-entropy gossip.
//!
//! Wraps a KvStore in `Arc<RwLock<>>` for concurrent access and
//! synchronizes it via gossip pub/sub delta propagation.

use crate::gossip::wire::{decode_delta, encode_delta};
use crate::gossip::PubSubManager;
use crate::identity::AgentId;
#[cfg(test)]
use crate::kv::encrypted::{bind_public_payload, sign_mutation_with_snapshot};
use crate::kv::encrypted::{
    open_mutation, open_public_payload, open_signed_mutation, open_signed_mutation_bound,
    AuthorSigning, EncryptedKvStoreRecordV1, KvMutationKind, SharedKvSecureContext,
    SignedKvMutation,
};
use crate::kv::retained_paging::{
    decode_page, RetainedPageBinding, RetainedPagePool, RetainedPageV1,
};
use crate::kv::store::{AccessPolicy, MergeOutcome};
use crate::kv::treekem::{SharedTreeKemKvProtector, TreeKemKvStoreRecordV1};
use crate::kv::{KvError, KvStore, KvStoreDelta, KvStoreId, Result};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Suffix appended to a store topic to form its state-sync side channel.
///
/// State requests travel on a separate topic so the main topic keeps its
/// existing `(PeerId, KvStoreDelta)` wire format — pre-#96 nodes simply
/// never subscribe to the side channel and are unaffected.
const STATE_SYNC_TOPIC_SUFFIX: &str = "/state-sync";

/// An async hook that refreshes the sync's
/// [`KvSecureContext`](crate::kv::encrypted::KvSecureContext) snapshot
/// before cryptographic or membership decisions.
///
/// Encrypted stores (#341 Phase B) bind to a context whose authoritative
/// state (group secret, epoch, active membership) lives in async daemon
/// state, while the trait itself is synchronous. The daemon supplies this
/// hook — typically [`crate::groups::GssKvSecureContext::refresh_hook`] —
/// and every encrypted publish/receive path awaits it first, so a rekey or
/// roster change takes effect on the very next record.
pub type SecureRefreshFn = std::sync::Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync,
>;

struct GroupHistorySeal<'a> {
    store: &'a Arc<RwLock<KvStore>>,
    treekem: Option<&'a SharedTreeKemKvProtector>,
    secure: Option<&'a SharedKvSecureContext>,
    refresh: Option<&'a SecureRefreshFn>,
    signing: &'a Arc<AuthorSigning>,
    encrypted: bool,
    local_peer_id: PeerId,
}

struct RetainedHistoryPublish<'a> {
    seal: GroupHistorySeal<'a>,
    pubsub: &'a PubSubManager,
    topic: &'a str,
    #[cfg(test)]
    test_state: Option<&'a std::sync::Mutex<RetainedPublishTestState>>,
}

/// Delays between state-request retries for a first-time joiner whose
/// store is still empty. Spread out so a slow mesh (peer discovery,
/// subscription propagation) still converges without flooding.
const STATE_REQUEST_RETRY_SECS: [u64; 4] = [1, 5, 15, 30];

/// First persistent-tail delay after the front-loaded schedule exhausts.
const STATE_REQUEST_TAIL_START_SECS: u64 = 30;

/// Ceiling for the persistent tail's exponential backoff. While a replica
/// is still empty it keeps requesting at most this often — the steady-state
/// cost is one ~50-byte side-topic message per store per 5 minutes.
const STATE_REQUEST_TAIL_CAP_SECS: u64 = 300;

/// The complete state-request delay schedule: the front-loaded burst, then
/// an infinite exponential tail (30s doubling to a 300s ceiling).
///
/// Infinite BY DESIGN (issue #238): the owner answers state requests only
/// reactively and never volunteers state to late subscribers, so a finite
/// schedule left a replica that rehydrated while the owner was offline
/// permanently un-synced (a "zombie subscription" — even the owner
/// returning did not revive it; only a full daemon restart did, by minting
/// a fresh schedule). Convergence — `StateServed` evidence matched against
/// local state, see [`bootstrap_converged`] — is the only legitimate stop
/// condition, and the requester loop owns that check.
fn state_request_delays() -> impl Iterator<Item = u64> {
    let tail = std::iter::successors(Some(STATE_REQUEST_TAIL_START_SECS), |d| {
        Some(d.saturating_mul(2).min(STATE_REQUEST_TAIL_CAP_SECS))
    });
    STATE_REQUEST_RETRY_SECS.into_iter().chain(tail)
}

/// Minimum spacing between full-state responses from ONE holder for ONE
/// store. Every empty replica's request would otherwise make every holder
/// republish its complete state — after a fleet restart N replicas × M
/// holders align on the same schedule and the amplification is N×M full
/// publications per cadence. One response per window per holder serves all
/// concurrently-bootstrapping replicas (the response is a broadcast on the
/// main topic); a request that lands inside the window is served by the
/// requester's next scheduled attempt.
const STATE_RESPONSE_COOLDOWN_SECS: u64 = 15;
const MAX_RETAINED_GROUP_IMAGE_BYTES: usize = crate::kv::retained_paging::MAX_RETAINED_IMAGE_BYTES;

fn serialize_retained_group_image(store: &KvStore) -> Result<Vec<u8>> {
    let bytes = bincode::serialize(store)
        .map_err(|e| KvError::Gossip(format!("retained group image serialization failed: {e}")))?;
    if bytes.len() > MAX_RETAINED_GROUP_IMAGE_BYTES {
        return Err(KvError::Gossip(format!(
            "complete group history is {} bytes, above the {}-byte retained-image resource limit",
            bytes.len(),
            MAX_RETAINED_GROUP_IMAGE_BYTES
        )));
    }
    Ok(bytes)
}

fn assemble_retained_group_image(
    payload: &[u8],
    store_id: &KvStoreId,
    endorser: &AgentId,
    authorization: [u8; 32],
    pool: &Arc<std::sync::Mutex<RetainedPagePool>>,
) -> Result<Option<Vec<u8>>> {
    let Some(frame) = decode_page(payload)? else {
        return Ok(Some(payload.to_vec()));
    };
    let image_id = match &frame {
        RetainedPageV1::Manifest { image_id, .. } | RetainedPageV1::Page { image_id, .. } => {
            *image_id
        }
    };
    let binding = RetainedPageBinding {
        store_id: *store_id.as_bytes(),
        endorser: *endorser.as_bytes(),
        authorization,
        image_id,
    };
    pool.lock()
        .map_err(|_| KvError::Gossip("retained page pool lock poisoned".to_string()))?
        .push(binding, frame)
}

fn treekem_page_authorization(binding: [u8; 32], epoch: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x0x.kv.treekem-retained-pages.v1");
    hasher.update(&binding);
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Sleep duration for a scheduled delay with ±20% jitter, so a fleet of
/// replicas restarted together does not phase-lock its request (and thus
/// full-state response) schedule. Mirrors the reconnect-backoff jitter in
/// `lib.rs`.
fn jittered_secs(secs: u64) -> std::time::Duration {
    let factor = 0.8 + rand::random::<f64>() * 0.4;
    std::time::Duration::from_secs_f64(secs as f64 * factor)
}

/// Message exchanged on the state-sync side topic.
///
/// Wire compatibility: `StateRequest` keeps its variant index and shape, so
/// v0.30.1 peers decode it unchanged. Older peers receiving the newer
/// `OwnerAnnounce` variant fail to deserialize it and skip the message
/// (their receive loop tolerates undecodable payloads), so the addition is
/// purely additive.
#[derive(Debug, Serialize, Deserialize)]
enum KvSyncMessage {
    /// A peer with no local state for the store asks holders to republish
    /// their full state (as a regular delta) on the main topic.
    StateRequest { requester: PeerId },
    /// The store owner's self-attestation of the store's authoritative
    /// metadata, published in response to a `StateRequest`.
    ///
    /// Trust model: the pub/sub layer verifies the ML-DSA-65 signature of
    /// every delivered v2 message and exposes the verified sender `AgentId`.
    /// The verified sender must equal the claimed `owner` — an owner can only
    /// attest to its own stores, and no third party can assign ownership.
    ///
    /// **Ownership is never established from this message.** A receiver's
    /// owner is anchored only at construction (see `KvStore::new_replica`).
    /// The announce can solely refresh policy (when the owner matches AND
    /// `policy_version` is strictly newer, blocking a replayed stale announce
    /// from downgrading policy) or record a conflict.
    OwnerAnnounce {
        /// The owning agent (must equal the verified message sender).
        owner: AgentId,
        /// The store's access policy as set by the owner.
        policy: AccessPolicy,
        /// Monotonic freshness counter — a refresh applies only when this is
        /// strictly greater than the receiver's current `policy_version`.
        policy_version: u64,
    },
    /// A holder's declaration that it has answered a `StateRequest`: its
    /// full state either was republished on the main topic (possibly
    /// earlier, within the response cooldown) or there is nothing to serve.
    /// Requesters match this against their OWN state to decide whether the
    /// bootstrap tail may stop — mere non-emptiness is not convergence
    /// evidence (a single incremental delta must not silence recovery).
    ///
    /// Wire compatibility: additive variant, same precedent as
    /// `OwnerAnnounce` — v0.33.0 peers fail to deserialize it and skip the
    /// message. Against a fleet of only-older responders no markers arrive
    /// and the requester keeps its capped-cadence tail (bounded chatter,
    /// never a zombie).
    StateServed {
        /// The declaring holder (receivers skip their own echo).
        responder: PeerId,
        /// True when the holder's store is empty. Only the OWNER ever
        /// declares emptiness (an empty non-owner replica stays silent) —
        /// otherwise two empty bootstrapping replicas would convince each
        /// other the store is legitimately empty and re-create the zombie.
        empty: bool,
        /// The holder's owner-signed checkpoint high-water mark, when it
        /// holds one. A requester whose own mark has reached this value has
        /// provably absorbed at least this much owner history — the exact
        /// convergence gate for checkpoint-bearing stores.
        checkpoint_seq: Option<u64>,
    },
    /// A holder's digest-committed declaration that it has answered a
    /// `StateRequest` (issue #240): `digest` commits to the FULL served
    /// entry set (see `served_content_digest`), so a requester can verify
    /// "served us, completely" against its OWN state instead of trusting
    /// that the full delta and the marker both arrived (the v1 cross-topic
    /// loss window). A requester stops only when its local digest matches a
    /// declared digest — a lost full delta leaves the local digest
    /// different, so it keeps asking.
    ///
    /// Empty holders (owner or not) declare the digest of the empty set,
    /// which any empty requester can compute locally — authoritative
    /// emptiness without an owner, terminating the genuinely-empty chatter
    /// tail (v1 behavior for old peers is unchanged: only the OWNER declares
    /// emptiness there). Because the digest is self-verifying, an empty
    /// declaration needs no full-delta broadcast to witness.
    ///
    /// Wire compatibility: additive variant, same precedent as
    /// `OwnerAnnounce`/`StateServed` — older peers fail to deserialize it
    /// and skip the message; new peers treat v1 markers as weaker evidence
    /// when no v2 digest has been seen. The marker rides along with the
    /// full-state broadcast (never separately) when there is state to serve.
    StateServedV2 {
        /// The declaring holder (receivers skip their own echo).
        responder: PeerId,
        /// Canonical BLAKE3 digest over the served entry set.
        digest: [u8; 32],
        /// Number of entries in the served set — a cheap shape check for the
        /// verified full-replace adopt path (and useful in logs).
        entry_count: u32,
    },
}

/// One responder's latest v2 digest declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServedState {
    /// The declared content digest.
    digest: [u8; 32],
    /// The declared number of entries.
    entry_count: u32,
}

/// Aggregated `StateServed`/`StateServedV2` evidence observed by one
/// replica's responder loop, consumed by its bootstrap requester to decide
/// convergence.
#[derive(Debug, Default, Clone)]
struct ServedEvidence {
    /// A holder declared non-empty state.
    saw_nonempty: bool,
    /// The OWNER declared the store legitimately empty.
    saw_owner_empty: bool,
    /// Highest checkpoint sequence any holder declared.
    max_checkpoint_seq: u64,
    /// Latest digest declaration per responder (bounded by mesh size — a
    /// responder's newer declaration REPLACES its older one, so a replayed
    /// stale serve can never roll a verified full-replace adopt backwards).
    digests: std::collections::HashMap<PeerId, ServedState>,
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

/// Convergence rule for the bootstrap tail (pure for unit-testing).
///
/// Strongest available evidence wins:
/// - a declared checkpoint sequence must be matched by this replica's own
///   high-water mark (exact, survives partial/lost responses);
/// - otherwise, when any v2 digest declarations exist, the local digest
///   must match one of them — with the data-bearing-claim-wins rule: if any
///   declaration is non-empty, only a non-empty match converges (an empty
///   holder's declaration must not retire a requester while a full holder
///   advertised content);
/// - otherwise (only v1 markers seen — old peers) the legacy weak rules:
///   declared non-empty requires local non-emptiness; emptiness counts only
///   when the owner declared it.
///
/// No evidence at all (`ServedEvidence::default()`) is NEVER convergence.
fn bootstrap_converged(
    ev: &ServedEvidence,
    is_empty: bool,
    highest_checkpoint_seq: u64,
    local_digest: [u8; 32],
) -> bool {
    if ev.max_checkpoint_seq > 0 {
        return highest_checkpoint_seq >= ev.max_checkpoint_seq;
    }
    if !ev.digests.is_empty() {
        let any_nonempty = ev.digests.values().any(|d| d.entry_count > 0);
        return ev
            .digests
            .values()
            .any(|d| d.digest == local_digest && (d.entry_count > 0 || !any_nonempty));
    }
    if ev.saw_nonempty {
        !is_empty
    } else {
        ev.saw_owner_empty
    }
}

/// Synchronization wrapper for a KvStore.
///
/// Manages automatic background synchronization using anti-entropy gossip.
/// Changes are propagated via deltas published to a gossip topic.
pub struct KvStoreSync {
    /// The store being synchronized.
    store: Arc<RwLock<KvStore>>,

    /// Pub/sub manager for topic-based messaging.
    pubsub: Arc<PubSubManager>,

    /// Topic name for this store.
    topic: String,

    /// This node's gossip peer id — identifies our deltas and state
    /// requests on the wire.
    local_peer_id: PeerId,

    /// This node's agent id, when known. Used to decide whether this node
    /// is the store owner (and should answer state requests with an
    /// [`KvSyncMessage::OwnerAnnounce`]) and to ignore its own announces.
    local_agent_id: Option<AgentId>,

    /// Optional persistence context. When armed (see
    /// [`set_persist_path`](Self::set_persist_path)), the full store state is
    /// snapshotted atomically after every local mutation and every merged
    /// remote delta, so a restart restores policy, keyset, entry contents,
    /// the latest adopted checkpoint, the checkpoint high-water mark, and the
    /// OR-Set sequence-counter ceiling instead of coming back as an empty
    /// replica. This is what makes `AppendOnly` immutability survive a
    /// restart: an owner (or replica) with amnesia would otherwise accept
    /// rewrites of keys it no longer remembers holding.
    persist: std::sync::Mutex<Option<Arc<PersistCtx>>>,

    /// The #760 open lease of the open that committed THIS sync (#765).
    /// Adopted by the agent's commit step (see
    /// [`KvStoreSync::adopt_committed_open_lease`]) so the lease is owned
    /// by the sync itself, never by a registry: it is released exactly when
    /// the last strong `KvStoreSync` reference drops, which is what keeps
    /// last-handle-drop semantics intact (structural loop-cancellation
    /// request via [`Drop`]) while an agent shutdown can still reach the
    /// retirement path through a weak reference. Note the two stages of
    /// that teardown: the LEASE drops synchronously with the sync, but the
    /// fence entry only becomes prunable once the cancelled loop futures
    /// drop their captured `PersistCtx` (its `PersistOwner` is the last
    /// `PathFence` reference) as the executor polls them to termination —
    /// see the `loop_exits` test instrument. A leaf lock, like `persist`.
    open_lease: std::sync::Mutex<Option<super::snapshot_fence::StoreOpenLease>>,

    /// Set by [`silence_bootstrap`](Self::silence_bootstrap). The bootstrap
    /// requester checks it every iteration: its schedule is infinite (issue
    /// #238), so a sync that should stop generating traffic — but keep
    /// serving (e.g. the deletion-test harness) — arms this without ending
    /// the listener/responder loops.
    stopped: Arc<std::sync::atomic::AtomicBool>,

    /// Cancelled by [`cancel_sync`](Self::cancel_sync) / [`stop`](Self::stop).
    /// ALL background loops (delta listener, responder, requester) select on
    /// it, so a discarded sync tears down completely without the topic-wide
    /// `unsubscribe` that would kill unrelated subscribers sharing the topic
    /// string (round-4 review: flag-only teardown left ghost listeners and a
    /// live responder until daemon shutdown).
    cancel: tokio_util::sync::CancellationToken,

    /// Receive-path lifecycle fence (#757). The listener holds it across one
    /// whole `[cancel check -> merge -> persist]` iteration and the responder
    /// across its owner-announce arm `[cancel check -> learn_ownership ->
    /// persist]`. [`cancel_sync_and_drain`](Self::cancel_sync_and_drain)
    /// takes it once AFTER cancelling, so when that returns none of those
    /// sections is in flight or can start.
    ///
    /// NOT covered: the responder's state-serve arms and the bootstrap
    /// requester. They only read the store and publish, run outside this
    /// lock (it is never held across a network await), and may still be
    /// finishing when a drain returns.
    ///
    /// Lock order — `lifecycle` is the OUTERMOST lock of a section:
    /// `lifecycle` -> `named_groups` / `kv_stores` (secure-refresh hook) ->
    /// TreeKEM protector (group membership guard, live ratchet) -> `store`
    /// write guard (the mutation). The mutation guard is RELEASED before
    /// persisting; `persist_snapshot` then takes `PersistCtx::gate` ->
    /// `store` read guard, in that order.
    lifecycle: Arc<tokio::sync::Mutex<()>>,

    /// Group secure context for an [`AccessPolicy::Encrypted`] store
    /// (#341 Phase B). `None` for every plaintext policy. When set, ALL
    /// publications (deltas, full-state serves, side-topic control
    /// messages) are sign-then-encrypt sealed and every receipt is opened,
    /// author-verified, and membership-checked before merge.
    secure: Option<SharedKvSecureContext>,

    /// Async real-TreeKEM record protector. Mutually exclusive with `secure`;
    /// the daemon adapter owns the live ratchet and durable snapshot.
    treekem_secure: Option<SharedTreeKemKvProtector>,

    /// Async hook refreshing `secure` before each seal/open decision (see
    /// [`SecureRefreshFn`]). Optional: contexts that cannot go stale (test
    /// fixtures) need no refresh.
    secure_refresh: Option<SecureRefreshFn>,

    /// The local agent's ML-DSA-65 signing material, REQUIRED for encrypted
    /// stores (every member signs its own mutations; the design doc's
    /// sign-then-encrypt flow).
    author_signing: Option<std::sync::Arc<AuthorSigning>>,
    retained_pages: Arc<std::sync::Mutex<RetainedPagePool>>,
    #[cfg(test)]
    retained_publish_test: Arc<std::sync::Mutex<RetainedPublishTestState>>,
    /// Deterministic barrier fired after a plaintext remote merge and before
    /// its snapshot write. Tests use the stored permit; production has no hook.
    #[cfg(test)]
    receive_merged_test: Arc<tokio::sync::Notify>,
    /// #765 test instrument: termination counter for the background loop
    /// futures `start_with_spawner` spawns for this sync. Dropping the
    /// last `KvStoreSync` reference (or a shutdown sweep's `cancel_sync`)
    /// only REQUESTS loop exit; each future still holds its captured
    /// `Arc<PersistCtx>` — and with it the fence's `PersistOwner` — until
    /// the executor polls it to termination (or drops it whole). Every
    /// spawned loop is wrapped in `TrackedLoopFuture`, which records an
    /// exit only AFTER the whole inner future is destroyed, so awaiting a
    /// count here is a terminal resource-release proof. Tests that must
    /// observe a prunable fence entry, or prove the sweep's cancel already
    /// ran, await the exact loop-exit count here instead of sleeping or
    /// racing the executor.
    #[cfg(test)]
    loop_exits: Arc<LoopExitTracker>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct RetainedPublishTestState {
    fail_after: Option<usize>,
    accepted: usize,
}

/// #765: counts terminated background-loop futures of one sync (see
/// `KvStoreSync::loop_exits`). A future "terminates" when it returns OR is
/// dropped — including a drop that never polled it (the drop-spawner
/// tests) — because the count is recorded by the `TrackedLoopFuture`
/// WRAPPER, which exists from construction. An exit is recorded only
/// after the whole inner future (and every capture it holds) is
/// destroyed, so the count is exact per `start_with_spawner` call AND
/// terminal: reaching `n` proves those `n` futures' resources are
/// released. `wait_for` needs no missable-wakeup reasoning:
/// `notify_one` stores a permit when no waiter is registered, and the
/// count is re-checked after every wake.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct LoopExitTracker {
    exited: std::sync::atomic::AtomicUsize,
    progressed: tokio::sync::Notify,
}

#[cfg(test)]
impl LoopExitTracker {
    fn record_exit(&self) {
        self.exited
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.progressed.notify_one();
    }

    /// Wait until at least `n` of this sync's loop futures terminated.
    pub(crate) async fn wait_for(&self, n: usize) {
        loop {
            if self.exited.load(std::sync::atomic::Ordering::SeqCst) >= n {
                return;
            }
            self.progressed.notified().await;
        }
    }
}

#[cfg(test)]
use std::future::Future;
/// #765 r4: wraps one WHOLE background-loop future so the sync's
/// [`LoopExitTracker`] counts its termination — return, cancellation, or a
/// drop that never polled it — only AFTER the inner future is destroyed.
///
/// The r3 instrument was a guard constructed INSIDE the async body, so a
/// future dropped before its first poll never created one (undercounting),
/// and its `Drop` fired while the future's remaining fields — including
/// the captured `Arc<PersistCtx>` and its fence `PersistOwner` — were
/// still alive: `wait_for` was therefore not a terminal resource-release
/// barrier. Owning the inner future here makes the record strictly
/// terminal for every exit path, polled or not.
#[cfg(test)]
struct TrackedLoopFuture<F> {
    /// Pre-pinned so the wrapper is unconditionally `Unpin` and `poll`
    /// needs no structural pinning of its own.
    inner: Option<std::pin::Pin<Box<F>>>,
    tracker: Arc<LoopExitTracker>,
}

#[cfg(test)]
impl<F> TrackedLoopFuture<F> {
    fn wrap(tracker: Arc<LoopExitTracker>, inner: F) -> Self {
        Self {
            inner: Some(Box::pin(inner)),
            tracker,
        }
    }
}

#[cfg(test)]
impl<F: Future<Output = ()>> Future for TrackedLoopFuture<F> {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let this = self.get_mut();
        match this.inner.as_mut() {
            // `None` is constructed only by this wrapper's own `Drop`,
            // which never polls.
            Some(inner) => inner.as_mut().poll(cx),
            None => std::task::Poll::Ready(()),
        }
    }
}

#[cfg(test)]
impl<F> Drop for TrackedLoopFuture<F> {
    fn drop(&mut self) {
        // Destroy the inner future FIRST — releasing its captured persist
        // contexts — then record. A `Drop` body runs before the struct's
        // fields drop, so the sequencing has to be this explicit.
        self.inner.take();
        self.tracker.record_exit();
    }
}

/// Structural teardown (parallel-review finding): the background loops hold
/// clones of the token, the store, and the pubsub — never the sync itself —
/// so when the last `KvStoreSync` reference drops, every loop (including the
/// INFINITE bootstrap requester, issue #238) is cancelled without any caller
/// having to remember `cancel_sync()`. The explicit rollback calls remain as
/// belt-and-braces.
impl Drop for KvStoreSync {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Shared persistence context for one store's snapshot file.
struct PersistCtx {
    /// Snapshot-fence ownership retained for this context's whole lifetime.
    /// A write only renames while this generation still owns the path; the
    /// retained path entry also prevents registry pruning before first use.
    owner: super::snapshot_fence::PersistOwner,
    /// Serializes snapshot commits AND records the last durably-persisted
    /// store version. `(version, bytes)` are captured under this lock, so
    /// commit order equals capture order — a concurrent persist burst can
    /// never rename an older snapshot over a newer one — and the version
    /// gate skips writes that would not advance durable state.
    gate: tokio::sync::Mutex<Option<u64>>,
    /// True after a failed snapshot write; cleared by the next success.
    /// While set, LOCAL writes are refused (fail-closed for what this node
    /// controls); remote-delta merges continue (replication is not wedged).
    degraded: std::sync::atomic::AtomicBool,
}

impl KvStoreSync {
    /// Create a new KvStore synchronization manager.
    ///
    /// # Arguments
    ///
    /// * `store` - The KvStore to synchronize.
    /// * `pubsub` - Pub/sub manager for gossip messaging.
    /// * `topic` - Topic name for pub/sub.
    /// * `local_peer_id` - This node's gossip peer id.
    /// * `local_agent_id` - This node's agent id, if available. Required for
    ///   the owner to answer state requests with an ownership announcement;
    ///   `None` disables announcing (joined replicas can still adopt).
    pub fn new(
        store: KvStore,
        pubsub: Arc<PubSubManager>,
        topic: String,
        local_peer_id: PeerId,
        local_agent_id: Option<AgentId>,
    ) -> Result<Self> {
        let store = Arc::new(RwLock::new(store));

        Ok(Self {
            store,
            pubsub,
            topic,
            local_peer_id,
            local_agent_id,
            persist: std::sync::Mutex::new(None),
            open_lease: std::sync::Mutex::new(None),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancel: tokio_util::sync::CancellationToken::new(),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            secure: None,
            treekem_secure: None,
            secure_refresh: None,
            author_signing: None,
            retained_pages: Arc::new(std::sync::Mutex::new(RetainedPagePool::default())),
            #[cfg(test)]
            retained_publish_test: Arc::new(std::sync::Mutex::new(
                RetainedPublishTestState::default(),
            )),
            #[cfg(test)]
            receive_merged_test: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            loop_exits: Arc::new(LoopExitTracker::default()),
        })
    }

    /// Attach the group security/authorization context and refresh hook.
    ///
    /// MUST be called before [`start`](Self::start): the loops capture the
    /// context once. [`start_with_spawner`](Self::start_with_spawner) fails
    /// at startup when an encrypted store runs without one — a sync that
    /// could only ever fail-open (plaintext publication) must never start.
    ///
    /// # Panics
    ///
    /// Debug-asserts the store is actually `Encrypted`: the context drives
    /// the SEALED publish/receive branch, so attaching one to a plaintext
    /// store would silently flip its wire format. A mismatch is a wiring
    /// bug, not a runtime condition.
    pub fn set_secure_context(
        &mut self,
        ctx: SharedKvSecureContext,
        refresh: Option<SecureRefreshFn>,
    ) {
        debug_assert!(self.secure.is_none(), "secure context attached twice");
        if let Ok(store) = self.store.try_read() {
            debug_assert!(
                store.is_encrypted() || store.is_group_signed(),
                "set_secure_context requires an encrypted or group-signed store"
            );
        }
        self.secure = Some(ctx);
        self.secure_refresh = refresh;
    }

    /// Attach a real-TreeKEM protector before starting an encrypted store.
    pub fn set_treekem_context(&mut self, protector: SharedTreeKemKvProtector) {
        debug_assert!(self.secure.is_none(), "group protector attached twice");
        debug_assert!(
            self.treekem_secure.is_none(),
            "TreeKEM protector attached twice"
        );
        if let Ok(store) = self.store.try_read() {
            debug_assert!(
                store.is_treekem_encrypted(),
                "TreeKEM protector requires a TreeKemEncrypted store"
            );
        }
        self.treekem_secure = Some(protector);
    }

    /// Attach the local agent's signing material, required to publish to an
    /// encrypted store. MUST be called before
    /// [`start`](Self::start) for encrypted stores.
    pub fn set_author_signing(&mut self, signing: AuthorSigning) {
        self.author_signing = Some(std::sync::Arc::new(signing));
    }

    /// Invalidate this sync's secure context (group lifecycle: leave,
    /// removal, withdrawal — see
    /// [`KvSecureContext::invalidate`](crate::kv::encrypted::KvSecureContext::invalidate)).
    ///
    /// After this, LOCAL authorization fails closed (the store consults the
    /// same context for membership) and every seal/open refuses. Pair with
    /// [`cancel_sync`](Self::cancel_sync) — that is what
    /// `KvStoreHandle::retire` does.
    pub fn invalidate_secure_context(&self) {
        if let Some(ctx) = self.secure.as_ref() {
            ctx.invalidate();
        }
        if let Some(ctx) = self.treekem_secure.as_ref() {
            ctx.invalidate();
        }
    }

    /// Seal a delta publication for an encrypted store into gossip bytes.
    ///
    /// Used by [`publish_delta`](Self::publish_delta) (incremental) and the
    /// responder's full-state serve — the design doc requires that NO
    /// plaintext `KvStoreDelta` can leave the process for an encrypted
    /// store, so both paths go through the same sealer.
    async fn seal_publication(
        store: &Arc<RwLock<KvStore>>,
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        signing: &Arc<AuthorSigning>,
        kind: KvMutationKind,
        local_peer_id: PeerId,
        delta: &KvStoreDelta,
    ) -> Result<Vec<u8>> {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        let store_id = { *store.read().await.id() };
        let payload = bincode::serialize(delta)
            .map_err(|e| KvError::Gossip(format!("sealed delta serialize failed: {e}")))?;
        let record = ctx.seal_authorized(signing.as_ref(), kind, &store_id, &payload)?;
        encode_delta(local_peer_id, &record)
            .map_err(|e| KvError::Gossip(format!("sealed delta encode failed: {e}")))
    }

    async fn seal_treekem_payload(
        store: &Arc<RwLock<KvStore>>,
        protector: &SharedTreeKemKvProtector,
        signing: &Arc<AuthorSigning>,
        kind: KvMutationKind,
        local_peer_id: PeerId,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let store_id = { *store.read().await.id() };
        let record = protector
            .seal_record(signing, kind, &store_id, payload, false)
            .await?;
        encode_delta(local_peer_id, &record)
            .map_err(|e| KvError::Gossip(format!("TreeKEM record encode failed: {e}")))
    }

    async fn merge_treekem_record(
        protector: &SharedTreeKemKvProtector,
        store: &Arc<RwLock<KvStore>>,
        store_id: &KvStoreId,
        local_peer: PeerId,
        payload: &[u8],
        pages: &Arc<std::sync::Mutex<RetainedPagePool>>,
    ) -> bool {
        let (sender_peer, record) = match decode_delta::<TreeKemKvStoreRecordV1>(payload) {
            Ok(decoded) => decoded,
            Err(error) => {
                tracing::warn!("rejected malformed TreeKEM record for store {store_id}: {error}");
                return false;
            }
        };
        let opened = match protector.open_record(store_id, &record).await {
            Ok(opened) => opened,
            Err(error) => {
                tracing::warn!("rejected TreeKEM record for store {store_id}: {error}");
                return false;
            }
        };
        if opened.reader_only {
            tracing::warn!("rejected read-only TreeKEM record on main store topic");
            return false;
        }
        let retained_image = if opened.mutation.kind == KvMutationKind::RetainedState {
            match assemble_retained_group_image(
                &opened.mutation.payload,
                store_id,
                &opened.mutation.author_id,
                treekem_page_authorization(opened.authorization_binding, opened.epoch),
                pages,
            ) {
                Ok(Some(image)) => Some(image),
                Ok(None) => return false,
                Err(error) => {
                    tracing::warn!(%error, "rejected retained TreeKEM page");
                    return false;
                }
            }
        } else {
            None
        };
        protector
            .merge_main_record(opened, sender_peer, local_peer, store, retained_image)
            .await
            .is_ok()
    }

    async fn seal_treekem_control(
        protector: &SharedTreeKemKvProtector,
        signing: &Arc<AuthorSigning>,
        store_id: &KvStoreId,
        local_peer_id: PeerId,
        msg: &KvSyncMessage,
    ) -> Option<Vec<u8>> {
        let authorized = match msg {
            KvSyncMessage::StateRequest { .. } => {
                protector.is_authorized_reader(&signing.agent_id).await
            }
            KvSyncMessage::StateServed { .. } | KvSyncMessage::StateServedV2 { .. } => {
                protector.is_authorized_writer(&signing.agent_id).await
            }
            KvSyncMessage::OwnerAnnounce { .. } => false,
        };
        if !authorized {
            return None;
        }
        let payload = bincode::serialize(msg).ok()?;
        let record = protector
            .seal_record(
                signing,
                KvMutationKind::Control,
                store_id,
                &payload,
                matches!(msg, KvSyncMessage::StateRequest { .. }),
            )
            .await
            .ok()?;
        encode_delta(local_peer_id, &record).ok()
    }

    async fn open_treekem_control(
        protector: &SharedTreeKemKvProtector,
        store_id: &KvStoreId,
        payload: &[u8],
    ) -> Option<(AgentId, KvSyncMessage)> {
        let (_, record) = decode_delta::<TreeKemKvStoreRecordV1>(payload).ok()?;
        let opened = protector.open_record(store_id, &record).await.ok()?;
        let mutation = opened.mutation;
        if mutation.kind != KvMutationKind::Control {
            return None;
        }
        let msg = bincode::deserialize::<KvSyncMessage>(&mutation.payload).ok()?;
        let authorized = match msg {
            KvSyncMessage::StateRequest { .. } => {
                opened.reader_only && protector.is_authorized_reader(&mutation.author_id).await
            }
            KvSyncMessage::StateServed { .. } | KvSyncMessage::StateServedV2 { .. } => {
                !opened.reader_only && protector.is_authorized_writer(&mutation.author_id).await
            }
            KvSyncMessage::OwnerAnnounce { .. } => false,
        };
        authorized.then_some((mutation.author_id, msg))
    }

    async fn sign_publication(
        store: &Arc<RwLock<KvStore>>,
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        signing: &Arc<AuthorSigning>,
        kind: KvMutationKind,
        local_peer_id: PeerId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        let store_id = { *store.read().await.id() };
        let record = ctx.sign_authorized(signing, kind, &store_id, &payload)?;
        encode_delta(local_peer_id, &record)
            .map_err(|e| KvError::Gossip(format!("signed mutation encode failed: {e}")))
    }

    async fn seal_group_history_payload(
        seal: GroupHistorySeal<'_>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if let Some(protector) = seal.treekem {
            return Self::seal_treekem_payload(
                seal.store,
                protector,
                seal.signing,
                KvMutationKind::RetainedState,
                seal.local_peer_id,
                &payload,
            )
            .await;
        }
        let ctx = seal.secure.ok_or_else(|| {
            KvError::SecureRecord("group history requires a security context".to_string())
        })?;
        if seal.encrypted {
            if let Some(refresh) = seal.refresh {
                refresh().await;
            }
            let store_id = { *seal.store.read().await.id() };
            let record = ctx.seal_authorized(
                seal.signing,
                KvMutationKind::RetainedState,
                &store_id,
                &payload,
            )?;
            encode_delta(seal.local_peer_id, &record)
                .map_err(|e| KvError::Gossip(format!("sealed retained image encode failed: {e}")))
        } else {
            Self::sign_publication(
                seal.store,
                ctx,
                seal.refresh,
                seal.signing,
                KvMutationKind::RetainedState,
                seal.local_peer_id,
                payload,
            )
            .await
        }
    }

    async fn publish_retained_history_frames(
        publish: RetainedHistoryPublish<'_>,
        retained: &[u8],
    ) -> Result<()> {
        let max_wire = crate::gossip::pubsub::max_signed_v3_payload_bytes(publish.topic)
            .ok_or_else(|| {
                KvError::Gossip("group history topic is too large for signed V3".to_string())
            })?;
        let frames =
            crate::kv::retained_paging::split_image(retained, max_wire.saturating_sub(16 * 1024))?;
        for frame in frames {
            #[cfg(test)]
            if let Some(state) = publish.test_state {
                let state = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.fail_after == Some(state.accepted) {
                    return Err(KvError::Gossip(
                        "injected retained image publication failure".to_string(),
                    ));
                }
            }
            let serialized = Self::seal_group_history_payload(
                GroupHistorySeal {
                    store: publish.seal.store,
                    treekem: publish.seal.treekem,
                    secure: publish.seal.secure,
                    refresh: publish.seal.refresh,
                    signing: publish.seal.signing,
                    encrypted: publish.seal.encrypted,
                    local_peer_id: publish.seal.local_peer_id,
                },
                frame,
            )
            .await?;
            if serialized.len() > max_wire {
                return Err(KvError::Gossip(
                    "sealed retained image frame exceeds signed V3 wire limit".to_string(),
                ));
            }
            publish
                .pubsub
                .publish(publish.topic.to_string(), bytes::Bytes::from(serialized))
                .await
                .map_err(|error| {
                    KvError::Gossip(format!("retained image publish failed: {error}"))
                })?;
            #[cfg(test)]
            if let Some(state) = publish.test_state {
                state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .accepted += 1;
            }
        }
        Ok(())
    }

    async fn merge_group_signed_record(
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        store: &Arc<RwLock<KvStore>>,
        store_id: &KvStoreId,
        local_peer: PeerId,
        payload: &[u8],
        pages: &Arc<std::sync::Mutex<RetainedPagePool>>,
    ) -> bool {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        let (sender_peer, record) = match decode_delta::<SignedKvMutation>(payload) {
            Ok(decoded) => decoded,
            Err(e) => {
                tracing::warn!("rejected malformed group-signed record: {e}");
                return false;
            }
        };
        let mutation = match open_signed_mutation(ctx.as_ref(), store_id, record) {
            Ok(mutation) => mutation,
            Err(e) => {
                tracing::warn!("rejected group-signed record: {e}");
                return false;
            }
        };
        let mutation_payload = match open_public_payload(ctx.as_ref(), &mutation.payload) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!("rejected group-signed authorization binding: {e}");
                return false;
            }
        };
        let retained_image = if mutation.kind == KvMutationKind::RetainedState {
            let authorization = ctx.authorization_binding().unwrap_or_else(|| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&ctx.group_id());
                hasher.update(&ctx.current_epoch().to_le_bytes());
                *hasher.finalize().as_bytes()
            });
            match assemble_retained_group_image(
                mutation_payload,
                store_id,
                &mutation.author_id,
                authorization,
                pages,
            ) {
                Ok(Some(image)) => Some(image),
                Ok(None) => return false,
                Err(error) => {
                    tracing::warn!(%error, "rejected retained group page");
                    return false;
                }
            }
        } else {
            None
        };
        let mut target = store.write().await;
        let result = match mutation.kind {
            KvMutationKind::Delta => bincode::deserialize::<KvStoreDelta>(mutation_payload)
                .map_err(|e| KvError::Gossip(format!("bad signed delta: {e}")))
                .and_then(|delta| {
                    target
                        .merge_delta_with_outcome(&delta, sender_peer, Some(&mutation.author_id))
                        .and_then(|outcome| match outcome {
                            crate::kv::store::MergeOutcome::Applied => Ok(()),
                            crate::kv::store::MergeOutcome::Rejected => Err(KvError::Merge(
                                "group-signed delta rejected by content admission".to_string(),
                            )),
                        })
                }),
            KvMutationKind::RetainedState => {
                let mutation_payload = retained_image.as_deref().unwrap_or_default();
                if mutation_payload.len() > MAX_RETAINED_GROUP_IMAGE_BYTES {
                    Err(KvError::Gossip(
                        "retained group image exceeds size limit".to_string(),
                    ))
                } else {
                    bincode::deserialize::<KvStore>(mutation_payload)
                        .map_err(|e| KvError::Gossip(format!("bad retained group image: {e}")))
                        .and_then(|image| {
                            target.merge_group_retained_image(
                                &image,
                                mutation.author_id,
                                local_peer,
                            )
                        })
                }
            }
            _ => Err(KvError::Gossip(
                "wrong mutation kind on group-signed main topic".to_string(),
            )),
        };
        result.map(|()| true).unwrap_or_else(|e| {
            tracing::warn!("failed to merge group-signed record: {e}");
            false
        })
    }

    /// Open and merge one encrypted record received on the main topic.
    ///
    /// Implements the design doc's receive flow: decrypt → verify author
    /// binding + signature → membership check → merge with the VERIFIED
    /// author identity preserved at the merge decision point. Returns true
    /// when the store mutated (callers persist after merge).
    async fn merge_encrypted_record(
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        store: &Arc<RwLock<KvStore>>,
        store_id: &KvStoreId,
        local_peer: PeerId,
        payload: &[u8],
        pages: &Arc<std::sync::Mutex<RetainedPagePool>>,
    ) -> bool {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        // Envelope decode: a plaintext delta arriving on an encrypted
        // store's topic fails to decode as an envelope and is dropped here
        // — it can never reach the merge. The envelope's sender peer tags
        // the OR-Set merge (the same role the plaintext path's tuple
        // sender plays); AUTHORITY comes from the inner signature.
        let (sender_peer, record) = match decode_delta::<EncryptedKvStoreRecordV1>(payload) {
            Ok(decoded) => decoded,
            Err(e) => {
                tracing::warn!("rejected malformed sealed record for store {store_id}: {e}");
                return false;
            }
        };
        let mutation = match open_mutation(ctx.as_ref(), store_id, &record) {
            Ok(m) => m,
            Err(e) => {
                // Reason is safe to log: never contains decrypted content.
                tracing::warn!("rejected sealed record for store {store_id}: {e}");
                return false;
            }
        };
        if !matches!(
            mutation.kind,
            KvMutationKind::Delta | KvMutationKind::FullState | KvMutationKind::RetainedState
        ) {
            tracing::warn!(
                "rejected sealed main-topic record for store {store_id}: wrong kind {:?}",
                mutation.kind
            );
            return false;
        }
        if !ctx.is_authorized_writer(&mutation.author_id) {
            tracing::warn!(
                "rejected sealed record for store {store_id}: author {} is not a current authorized writer",
                hex::encode(mutation.author_id.as_bytes())
            );
            return false;
        }
        let retained_image = if mutation.kind == KvMutationKind::RetainedState {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&ctx.group_id());
            hasher.update(&ctx.current_epoch().to_le_bytes());
            let authorization = *hasher.finalize().as_bytes();
            match assemble_retained_group_image(
                &mutation.payload,
                store_id,
                &mutation.author_id,
                authorization,
                pages,
            ) {
                Ok(Some(image)) => Some(image),
                Ok(None) => return false,
                Err(error) => {
                    tracing::warn!(%error, "rejected retained encrypted page");
                    return false;
                }
            }
        } else {
            None
        };
        let mut s = store.write().await;
        let result = if mutation.kind == KvMutationKind::RetainedState {
            let payload = retained_image.as_deref().unwrap_or_default();
            if payload.len() > MAX_RETAINED_GROUP_IMAGE_BYTES {
                Err(KvError::Gossip(
                    "retained encrypted group image exceeds size limit".to_string(),
                ))
            } else {
                bincode::deserialize::<KvStore>(payload)
                    .map_err(|e| KvError::Gossip(format!("bad retained encrypted image: {e}")))
                    .and_then(|image| {
                        s.merge_group_retained_image(&image, mutation.author_id, local_peer)
                    })
            }
        } else {
            bincode::deserialize::<KvStoreDelta>(&mutation.payload)
                .map_err(|e| KvError::Gossip(format!("bad sealed delta payload: {e}")))
                .and_then(|delta| s.merge_delta(&delta, sender_peer, Some(&mutation.author_id)))
        };
        match result {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("failed to merge sealed delta for store {store_id}: {e}");
                false
            }
        }
    }

    /// Seal a state-sync control message for an encrypted store. Returns
    /// ready-to-publish gossip bytes, or `None` (logged) on any failure.
    async fn seal_control_message(
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        signing: &Arc<AuthorSigning>,
        store_id: &KvStoreId,
        local_peer_id: PeerId,
        msg: &KvSyncMessage,
    ) -> Option<Vec<u8>> {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        let authorized = match msg {
            KvSyncMessage::StateRequest { .. } => ctx.is_authorized_reader(&signing.agent_id),
            KvSyncMessage::StateServed { .. } | KvSyncMessage::StateServedV2 { .. } => {
                ctx.is_authorized_writer(&signing.agent_id)
            }
            KvSyncMessage::OwnerAnnounce { .. } => false,
        };
        if !authorized {
            return None;
        }
        let payload = bincode::serialize(msg).ok()?;
        let record = ctx
            .seal_authorized(
                signing.as_ref(),
                KvMutationKind::Control,
                store_id,
                &payload,
            )
            .map_err(|e| tracing::warn!("failed to seal control message: {e}"))
            .ok()?;
        encode_delta(local_peer_id, &record).ok()
    }

    /// Open a sealed state-sync control message.
    ///
    /// Returns the message AND the verified inner author (the pubsub
    /// transport sender may be a relay; for sealed control traffic the
    /// author signature inside the envelope is the trusted identity —
    /// exactly the "author binding" of the design doc applied to control
    /// messages such as `OwnerAnnounce`).
    async fn open_control_message(
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        store_id: &KvStoreId,
        payload: &[u8],
    ) -> Option<(AgentId, KvSyncMessage)> {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        let (_, record) = decode_delta::<EncryptedKvStoreRecordV1>(payload).ok()?;
        let mutation = open_mutation(ctx.as_ref(), store_id, &record)
            .map_err(|e| {
                tracing::warn!("rejected sealed control message for store {store_id}: {e}")
            })
            .ok()?;
        if mutation.kind != KvMutationKind::Control {
            tracing::warn!(
                "rejected sealed control message for store {store_id}: wrong kind {:?}",
                mutation.kind
            );
            return None;
        }
        let msg = bincode::deserialize::<KvSyncMessage>(&mutation.payload).ok()?;
        let authorized = match &msg {
            KvSyncMessage::StateRequest { .. } => ctx.is_authorized_reader(&mutation.author_id),
            KvSyncMessage::StateServed { .. } | KvSyncMessage::StateServedV2 { .. } => {
                ctx.is_authorized_writer(&mutation.author_id)
            }
            KvSyncMessage::OwnerAnnounce { .. } => false,
        };
        if !authorized {
            tracing::warn!(
                "rejected sealed control message for store {store_id}: author {} is not authorized for this control kind",
                hex::encode(mutation.author_id.as_bytes())
            );
            return None;
        }
        Some((mutation.author_id, msg))
    }

    async fn sign_public_control_message(
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        signing: &Arc<AuthorSigning>,
        store_id: &KvStoreId,
        local_peer_id: PeerId,
        msg: &KvSyncMessage,
    ) -> Option<Vec<u8>> {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        let payload = bincode::serialize(msg).ok()?;
        let record = ctx
            .sign_control_authorized(
                signing,
                store_id,
                &payload,
                matches!(msg, KvSyncMessage::StateRequest { .. }),
            )
            .ok()?;
        encode_delta(local_peer_id, &record).ok()
    }

    async fn open_public_control_message(
        ctx: &SharedKvSecureContext,
        refresh: Option<&SecureRefreshFn>,
        store_id: &KvStoreId,
        payload: &[u8],
    ) -> Option<(AgentId, KvSyncMessage)> {
        if let Some(refresh) = refresh {
            refresh().await;
        }
        let (_, record) = decode_delta::<SignedKvMutation>(payload).ok()?;
        let mutation = open_signed_mutation_bound(ctx.as_ref(), store_id, record).ok()?;
        if mutation.kind != KvMutationKind::Control {
            return None;
        }
        let payload = open_public_payload(ctx.as_ref(), &mutation.payload).ok()?;
        let msg: KvSyncMessage = bincode::deserialize(payload).ok()?;
        if matches!(msg, KvSyncMessage::OwnerAnnounce { .. }) {
            return None;
        }
        if matches!(msg, KvSyncMessage::StateRequest { .. })
            && !ctx.is_authorized_reader(&mutation.author_id)
        {
            return None;
        }
        if !matches!(msg, KvSyncMessage::StateRequest { .. })
            && !ctx.is_authorized_writer(&mutation.author_id)
        {
            return None;
        }
        Some((mutation.author_id, msg))
    }

    /// Enable on-disk snapshot persistence at `path`.
    ///
    /// Call before [`start`](Self::start) so no merged delta can land
    /// unpersisted. The caller is responsible for loading any existing
    /// snapshot BEFORE constructing this sync (see
    /// [`load_snapshot`]); this method only arms writes — and claims the
    /// path's youngest persist generation for THIS sync (#760): any older
    /// sync's still-admitted write over the same file is fenced out from
    /// this moment on.
    pub fn set_persist_path(&self, path: PathBuf) {
        if let Ok(mut guard) = self.persist.lock() {
            let owner = super::snapshot_fence::arm_persist(&path);
            *guard = Some(Arc::new(PersistCtx {
                owner,
                gate: tokio::sync::Mutex::new(None),
                degraded: std::sync::atomic::AtomicBool::new(false),
            }));
        }
    }

    /// Arm persistence through the lifecycle lease held by a high-level
    /// persistent-store constructor. A predecessor-backed or trampled lease
    /// is refused before it can supersede the current file owner.
    pub(crate) fn set_persist_path_for_open(
        &self,
        lease: &super::snapshot_fence::StoreOpenLease,
    ) -> Result<()> {
        let mut guard = self.persist.lock().map_err(|_| {
            KvError::Io(std::io::Error::other(
                "kv persistence context lock poisoned",
            ))
        })?;
        let owner = lease.arm_persist().ok_or(KvError::SnapshotSuperseded)?;
        *guard = Some(Arc::new(PersistCtx {
            owner,
            gate: tokio::sync::Mutex::new(None),
            degraded: std::sync::atomic::AtomicBool::new(false),
        }));
        Ok(())
    }

    /// Adopt the #760 open lease of a CONSTRUCTED and COMMITTED open (#765).
    ///
    /// Called by the agent's commit step — under its snapshot-lease registry
    /// lock and only after the lease's fence commit succeeded — so a sync
    /// never owns a lease whose open did not commit. Ownership lives HERE,
    /// not in any registry: the lease is released exactly when the last
    /// strong `KvStoreSync` reference drops, keeping last-handle-drop
    /// semantics intact — the [`Drop`] impl cancels the loops, and the
    /// fence entry becomes prunable once those cancelled futures drop
    /// their captured persist contexts (an asynchronous stage; the r3
    /// tests await the sync's loop exits before asserting a re-open) —
    /// while a later agent shutdown can still reach the retirement path
    /// through a weak reference to this sync.
    pub(crate) fn adopt_committed_open_lease(&self, lease: super::snapshot_fence::StoreOpenLease) {
        *self
            .open_lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lease);
    }

    /// #765 agent-shutdown retirement for this sync's snapshot path: mark it
    /// `Retiring` through the adopted open lease and invalidate the secure
    /// context — both synchronous leaf calls, safe under any lock. The
    /// caller still cancels the loops ([`cancel_sync`](Self::cancel_sync))
    /// and completes the returned token only after its drain. `None` means
    /// there is nothing this sync may retire: an in-memory store never
    /// adopted a lease, and a lease whose lineage a successor already owns
    /// can never retire it.
    pub(crate) fn begin_shutdown_retirement(
        &self,
    ) -> Option<super::snapshot_fence::RetirementToken> {
        let lease = self
            .open_lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        let token = lease.begin_retire();
        self.invalidate_secure_context();
        token
    }

    /// Refresh and enforce the current group read policy before exposing
    /// locally cached group content. Plain stores have no group context and
    /// remain readable through their existing API.
    pub(crate) async fn authorize_local_read(&self, reader: &AgentId) -> Result<()> {
        if let Some(refresh) = self.secure_refresh.as_ref() {
            refresh().await;
        }
        if let Some(ctx) = self.secure.as_ref() {
            if !ctx.is_authorized_reader(reader) {
                return Err(KvError::Unauthorized(
                    "current group read policy denies access".to_string(),
                ));
            }
        }
        if let Some(ctx) = self.treekem_secure.as_ref() {
            if !ctx.is_authorized_reader(reader).await {
                return Err(KvError::Unauthorized(
                    "current TreeKEM group read policy denies access".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Refresh and enforce the current group writer policy before a local
    /// mutation changes in-memory or persisted state.
    pub(crate) async fn authorize_local_write(&self, writer: &AgentId) -> Result<()> {
        if let Some(refresh) = self.secure_refresh.as_ref() {
            refresh().await;
        }
        if let Some(ctx) = self.secure.as_ref() {
            if !ctx.is_authorized_writer(writer) {
                return Err(KvError::Unauthorized(
                    "current group writer policy denies mutation".to_string(),
                ));
            }
        }
        if let Some(ctx) = self.treekem_secure.as_ref() {
            if !ctx.is_authorized_writer(writer).await {
                return Err(KvError::Unauthorized(
                    "current TreeKEM group writer policy denies mutation".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Clone the armed persistence context, if any.
    fn persist_ctx(&self) -> Option<Arc<PersistCtx>> {
        self.persist.lock().ok().and_then(|g| g.clone())
    }

    /// Snapshot the store to the configured persist path (`Ok` no-op when
    /// persistence is not armed).
    ///
    /// Durability contract:
    /// - Commits are serialized per store and version-gated, so concurrent
    ///   persists can never regress durable state.
    /// - On failure the store is flagged **durability-degraded**
    ///   ([`durability_degraded`](Self::durability_degraded)): callers on the
    ///   LOCAL write path must propagate the error to the writer and MUST NOT
    ///   publish the mutation (durability before announcement); callers on
    ///   the REMOTE merge path log and continue (replication is not wedged —
    ///   peers hold the data; only this node's disk is behind).
    /// - The next successful persist (including via
    ///   [`ensure_durable`](Self::ensure_durable)) clears the flag.
    /// - #760: if a YOUNGER generation owns the snapshot path (this sync was
    ///   retired and the store re-opened), the write is refused with
    ///   [`KvError::SnapshotSuperseded`] and the degraded flag is set —
    ///   success would acknowledge bytes that were never made durable.
    ///
    /// # Errors
    ///
    /// I/O or serialization failure writing the snapshot, or
    /// [`KvError::SnapshotSuperseded`] when a younger generation owns the
    /// path.
    pub async fn persist(&self) -> Result<()> {
        match self.persist_ctx() {
            Some(ctx) => match persist_snapshot(&self.store, &ctx).await {
                Ok(PersistOutcome::Superseded) => {
                    // Caller-driven durability: fail closed (#760). The
                    // receive-path callers of `persist_snapshot` suppress
                    // this outcome instead (their merge belongs to a
                    // discarded generation).
                    ctx.degraded
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    Err(KvError::SnapshotSuperseded)
                }
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            None => Ok(()),
        }
    }

    /// True while the last snapshot attempt failed and no retry has
    /// succeeded. Local writes are refused in this state (fail-closed).
    pub fn durability_degraded(&self) -> bool {
        self.persist_ctx()
            .is_some_and(|c| c.degraded.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// If the store is durability-degraded, retry persisting the CURRENT
    /// state before any new mutation is accepted. `Ok` when not degraded,
    /// not persistent, or the retry succeeded.
    ///
    /// # Errors
    ///
    /// The retry failed — the caller must refuse the local write —
    /// including [`KvError::SnapshotSuperseded`] when a younger generation
    /// owns the path (#760).
    pub async fn ensure_durable(&self) -> Result<()> {
        match self.persist_ctx() {
            Some(ctx) if ctx.degraded.load(std::sync::atomic::Ordering::Relaxed) => {
                self.persist().await
            }
            _ => Ok(()),
        }
    }

    /// The state-sync side topic for this store.
    fn state_sync_topic(&self) -> String {
        format!("{}{}", self.topic, STATE_SYNC_TOPIC_SUFFIX)
    }

    /// Start background synchronization.
    ///
    /// Subscribes to the gossip topic and begins receiving remote deltas.
    /// Also joins the state-sync side channel: holders answer state
    /// requests by republishing their full state, and — issue #96 — a
    /// first-time joiner (empty local store) requests that state so it
    /// bootstraps keys written before it joined. Without this, only
    /// deltas published *after* subscribing ever arrive.
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
        let mut sub = self.pubsub.subscribe(self.topic.clone()).await;
        let store = Arc::clone(&self.store);
        // #341 Phase B fail-closed startup: an encrypted store syncs ONLY
        // through the sealed path, which requires the secure context and the
        // author signing material. Refusing to start here can never degrade
        // into plaintext publication.
        let (store_is_encrypted, store_is_group_signed, store_is_treekem) = {
            let store = store.read().await;
            (
                store.is_encrypted(),
                store.is_group_signed(),
                store.is_treekem_encrypted(),
            )
        };
        let backend_mismatch = if store_is_treekem {
            self.treekem_secure.is_none() || self.secure.is_some()
        } else {
            self.secure.is_none() || self.treekem_secure.is_some()
        };
        if (store_is_encrypted || store_is_group_signed)
            && (backend_mismatch || self.author_signing.is_none())
        {
            return Err(KvError::SecureRecord(
                "encrypted store sync requires an attached secure context and author \
                 signing material (set_secure_context + set_author_signing) before start"
                    .to_string(),
            ));
        }
        // Capture the encrypted-path handles once: the policy is
        // creation-fixed, so a stale snapshot cannot drift mid-life.
        let listener_secure = self.secure.clone();
        let listener_treekem = self.treekem_secure.clone();
        let listener_pages = Arc::clone(&self.retained_pages);
        let listener_refresh = self.secure_refresh.clone();
        let listener_is_encrypted = store_is_encrypted;
        // Capture the bootstrap decision BEFORE any listener can merge a
        // cached delta. Otherwise a partial cache replay landing between
        // subscribe and this check could make the store non-empty and skip
        // the bootstrap state-request schedule — aged/pruned keys would
        // never arrive.
        //
        // Non-owner replicas ALWAYS bootstrap: a snapshot-restored replica
        // may have missed deltas while it was offline, and emptiness cannot
        // distinguish "fresh join" from "restored but stale" (the gossip
        // cache only replays ~60s of history). Owners are authoritative and
        // request only when EMPTY — that is snapshot-loss recovery from
        // their replicas.
        let bootstrap_needed = {
            let s = store.read().await;
            let local_is_owner =
                self.local_agent_id.is_some() && s.owner() == self.local_agent_id.as_ref();
            store_is_encrypted || store_is_group_signed || !local_is_owner || s.is_empty()
        };
        // Defense in depth against cross-topic replay: the v2 signature covers
        // the embedded topic, but pub/sub delivery does not re-check it against
        // this subscription, so a raw-mesh participant could place a valid
        // owner-signed envelope from store A under topic B. Each listener binds
        // to the exact topic it subscribed to.
        let main_topic = self.topic.clone();
        // Snapshot the persist context once: it is armed before start() by
        // construction (set_persist_path docs), so the loops never observe a
        // late change.
        let persist_ctx = self.persist_ctx();

        let loop_persist_ctx = persist_ctx.clone();
        let listener_cancel = self.cancel.clone();
        let listener_lifecycle = Arc::clone(&self.lifecycle);
        #[cfg(test)]
        let listener_receive_merged_test = Arc::clone(&self.receive_merged_test);
        #[cfg(test)]
        let listener_loop_exits = Arc::clone(&self.loop_exits);
        let listener_local_peer_id = self.local_peer_id;
        // Store id snapshot for the encrypted receive path (static for the
        // store's life).
        let listener_store_id = { *store.read().await.id() };
        // StateServed evidence: written by the responder loop (which owns
        // the side-topic subscription), read by the listener (verified
        // full-replace adopt, issue #240) and the bootstrap requester
        // (convergence). Created BEFORE the loops so all three share it.
        let served_evidence = Arc::new(std::sync::Mutex::new(ServedEvidence::default()));
        // Armed only while the bootstrap requester runs: the verified
        // full-replace adopt fires exclusively in that window — a converged
        // replica must never let a divergent holder's serve truncate state
        // it legitimately holds.
        let bootstrap_active = Arc::new(std::sync::atomic::AtomicBool::new(bootstrap_needed));
        let listener_served = Arc::clone(&served_evidence);
        let listener_bootstrap_active = Arc::clone(&bootstrap_active);
        // #765 r4: the loop-exit tracker wraps the WHOLE loop future, so
        // termination is recorded only after this future — and every
        // capture it holds, including the persist context — is destroyed
        // (see `TrackedLoopFuture`).
        let listener_loop = async move {
            loop {
                let msg = tokio::select! {
                    // Cancel-first (#757): an unbiased select picks at
                    // random when a queued message and the cancel are both
                    // ready, so a retired sync still merged and persisted.
                    biased;
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
                if msg.topic != main_topic {
                    // Cross-topic replay defense: ignore envelopes not on our
                    // subscribed topic (see start_with_spawner).
                    continue;
                }
                // #757 lifecycle fence: held to the end of this iteration, so
                // the merge AND its snapshot write are one section a draining
                // retire waits out. The cancel check is under the lock: once
                // cancelled, no new section can start. Nothing below is ever
                // dropped mid-flight — the TreeKEM path advances a receive
                // ratchet that must reach its persist/rollback.
                let _lifecycle = listener_lifecycle.lock().await;
                if listener_cancel.is_cancelled() {
                    return;
                }
                // #341 Phase B: an encrypted store takes the SEALED path —
                // the payload is an EncryptedKvStoreRecordV1, and a plaintext
                // delta can never decode, verify, or merge here.
                if let Some(protector) = listener_treekem.as_ref() {
                    if Self::merge_treekem_record(
                        protector,
                        &store,
                        &listener_store_id,
                        listener_local_peer_id,
                        &msg.payload,
                        &listener_pages,
                    )
                    .await
                    {
                        if let Some(ctx) = loop_persist_ctx.as_ref() {
                            let _ = persist_snapshot(&store, ctx).await;
                        }
                    }
                } else if let Some(ctx) = listener_secure.as_ref() {
                    let merged = if listener_is_encrypted {
                        Self::merge_encrypted_record(
                            ctx,
                            listener_refresh.as_ref(),
                            &store,
                            &listener_store_id,
                            listener_local_peer_id,
                            &msg.payload,
                            &listener_pages,
                        )
                        .await
                    } else {
                        Self::merge_group_signed_record(
                            ctx,
                            listener_refresh.as_ref(),
                            &store,
                            &listener_store_id,
                            listener_local_peer_id,
                            &msg.payload,
                            &listener_pages,
                        )
                        .await
                    };
                    if merged {
                        if let Some(ctx) = loop_persist_ctx.as_ref() {
                            let _ = persist_snapshot(&store, ctx).await;
                        }
                    }
                    continue;
                }
                let decoded = decode_delta::<KvStoreDelta>(&msg.payload);
                match decoded {
                    Ok((peer_id, delta)) => {
                        let merged = {
                            let mut s = store.write().await;
                            // Pass sender identity for access control enforcement.
                            // The gossip V2 wire format includes a verified AgentId.
                            let writer = msg.sender.as_ref();
                            match s.merge_delta_with_outcome(&delta, peer_id, writer) {
                                Ok(MergeOutcome::Rejected) => false,
                                Ok(MergeOutcome::Applied) => {
                                    // Digest-verified full-replace adopt
                                    // (issue #240, checkpoint-less deletion
                                    // cold-sync): while bootstrapping, when
                                    // the sender's latest v2 declaration
                                    // matches this delta's served content
                                    // (digest AND entry count), the delta IS
                                    // that holder's complete state — prune
                                    // local keys it does not carry. Gated on
                                    // the sender being an AUTHORIZED writer:
                                    // merge_delta silently ignores
                                    // unauthorized deltas, and the prune
                                    // must not apply what the merge would
                                    // not. Without verification any holder
                                    // could truncate local state at will.
                                    // Checkpointed replacement is handled atomically by
                                    // merge_delta_with_outcome. A digest declaration
                                    // carries no freshness and must never override that
                                    // checkpoint/HWM (including a stale rejected serve).
                                    // Keep this decision, merge and prune under `s`.
                                    if delta.owner_checkpoint.is_none()
                                        && s.highest_checkpoint_seq == 0
                                        && listener_bootstrap_active
                                            .load(std::sync::atomic::Ordering::Relaxed)
                                    {
                                        let declared = listener_served
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                                            .digests
                                            .get(&peer_id)
                                            .copied();
                                        if let Some(declared) = declared {
                                            // Prune authority (F2,
                                            // fix-loop): absence from a
                                            // verified serve proves
                                            // deletion ONLY when the
                                            // sender is the SOLE possible
                                            // content author. Under
                                            // Signed that is the anchored
                                            // owner — and every key this
                                            // replica can hold was
                                            // admitted under that same
                                            // auth (or an owner-signed
                                            // checkpoint), so the owner's
                                            // serve is complete about all
                                            // of them. Under Allowlisted
                                            // the owner's serve can be
                                            // legitimately incomplete
                                            // about co-writers' keys (an
                                            // owner that has not merged
                                            // an allowlisted write would
                                            // otherwise TRUNCATE it), so
                                            // pruning is disabled there —
                                            // deletions still propagate
                                            // via live `removed` deltas,
                                            // and the digest mismatch
                                            // resolves when the owner
                                            // absorbs the co-write and
                                            // re-serves. (The review's
                                            // alternative count guard —
                                            // prune only when local-count
                                            // <= declared-count — was
                                            // rejected: the residual-2
                                            // stale replica is exactly a
                                            // local SUPERSET of the serve,
                                            // so that rule disables
                                            // pruning precisely where
                                            // deletion cold-sync needs
                                            // it.)
                                            let sole_author =
                                                matches!(s.policy(), AccessPolicy::Signed)
                                                    && writer.is_some()
                                                    && s.owner() == writer;
                                            if sole_author
                                                && delta.added.len()
                                                    == declared.entry_count as usize
                                                && delta
                                                    .served_digest(s.id())
                                                    .is_some_and(|dg| dg == declared.digest)
                                            {
                                                let pruned = s.prune_to_served_set(&delta);
                                                if pruned > 0 {
                                                    tracing::info!(
                                                        "pruned {pruned} stale key(s) after \
                                                         digest-verified full serve for store {}",
                                                        s.id()
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    true
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to merge KvStore delta: {e}");
                                    false
                                }
                            }
                        };
                        // Persist OUTSIDE the write guard so disk latency
                        // never blocks other writers. A failure flags the
                        // store durability-degraded (persist_snapshot logs);
                        // remote merges continue — replication must not
                        // wedge on this node's disk.
                        if merged {
                            #[cfg(test)]
                            listener_receive_merged_test.notify_one();
                            if let Some(ctx) = loop_persist_ctx.as_ref() {
                                let _ = persist_snapshot(&store, ctx).await;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize KvStore delta: {e}");
                    }
                }
            }
        };
        #[cfg(test)]
        let listener_loop = TrackedLoopFuture::wrap(listener_loop_exits, listener_loop);
        spawn(Box::pin(listener_loop));

        // Responder + ownership listener on the state-sync side topic.
        //
        // StateRequest: holders with non-empty state answer by republishing
        // their full state as a regular delta on the main topic. CRDT merge
        // makes duplicate responses from multiple holders harmless
        // (idempotent), so no response suppression is needed at current mesh
        // sizes. Additionally, if this node is the store OWNER it publishes
        // an OwnerAnnounce (regardless of emptiness) so joined replicas can
        // learn the authoritative owner and policy.
        //
        // OwnerAnnounce: a replica with an unknown owner adopts the owner
        // and policy — but only when the announcement's pub/sub-verified
        // sender is the claimed owner itself (see KvSyncMessage docs).
        let mut sync_sub = self.pubsub.subscribe(self.state_sync_topic()).await;
        let responder_store = Arc::clone(&self.store);
        let responder_persist_ctx = persist_ctx.clone();
        let responder_pubsub = Arc::clone(&self.pubsub);
        let responder_topic = self.topic.clone();
        let sync_topic = self.state_sync_topic();
        let local_peer_id = self.local_peer_id;
        let local_agent_id = self.local_agent_id;
        let responder_served = Arc::clone(&served_evidence);
        let responder_cancel = self.cancel.clone();
        let responder_lifecycle = Arc::clone(&self.lifecycle);
        // Encrypted-path handles (#341 Phase B): Some together whenever the
        // store is encrypted (enforced by the startup guard above).
        let responder_secure = self.secure.clone();
        let responder_treekem = self.treekem_secure.clone();
        let responder_refresh = self.secure_refresh.clone();
        let responder_signing = self.author_signing.clone();
        let responder_is_encrypted = store_is_encrypted;
        let responder_is_group_signed = store_is_group_signed;
        let responder_uses_retained = responder_is_encrypted || responder_is_group_signed;
        let responder_store_id = { *self.store.read().await.id() };
        #[cfg(test)]
        let responder_loop_exits = Arc::clone(&self.loop_exits);
        // #765 r4: the loop-exit tracker wraps the WHOLE loop future, so
        // termination is recorded only after this future — and every
        // capture it holds, including the persist context — is destroyed
        // (see `TrackedLoopFuture`).
        let responder_loop = async move {
            // Response-storm damping (issue #238 review): one full-state
            // response per cooldown window, regardless of how many replicas
            // are requesting — the response is a broadcast, so it serves
            // them all.
            let mut last_full_response: Option<tokio::time::Instant> = None;
            loop {
                let msg = tokio::select! {
                    // Cancel-first (#757), as in the listener above.
                    biased;
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
                if msg.topic != sync_topic {
                    // Cross-topic replay defense (see start_with_spawner).
                    continue;
                }
                // #341 Phase B: encrypted stores seal their control traffic
                // too. The verified identity is then the INNER signature's
                // author (a relay's transport sender proves nothing); the
                // plaintext path keeps the pub/sub-verified sender.
                let (sync_msg, verified_sender) = if let Some(protector) =
                    responder_treekem.as_ref()
                {
                    match Self::open_treekem_control(protector, &responder_store_id, &msg.payload)
                        .await
                    {
                        Some((author, message)) => (message, Some(author)),
                        None => continue,
                    }
                } else if let Some(ctx) = responder_secure.as_ref() {
                    let opened = if responder_is_encrypted {
                        Self::open_control_message(
                            ctx,
                            responder_refresh.as_ref(),
                            &responder_store_id,
                            &msg.payload,
                        )
                        .await
                    } else {
                        Self::open_public_control_message(
                            ctx,
                            responder_refresh.as_ref(),
                            &responder_store_id,
                            &msg.payload,
                        )
                        .await
                    };
                    match opened {
                        Some((author, m)) => (m, Some(author)),
                        None => continue,
                    }
                } else {
                    match bincode::deserialize::<KvSyncMessage>(&msg.payload) {
                        Ok(m) => (m, msg.sender),
                        Err(_) => continue,
                    }
                };
                match sync_msg {
                    KvSyncMessage::StateRequest { requester } => {
                        if requester == local_peer_id {
                            continue;
                        }
                        // Owner: announce authoritative metadata so anchored
                        // joiners can refresh policy / confirm ownership.
                        // (Ownership itself is never learned from this — a
                        // joiner anchors its owner at construction.)
                        let announce = if responder_secure.is_some() || responder_treekem.is_some()
                        {
                            None
                        } else {
                            let s = responder_store.read().await;
                            match (local_agent_id, s.owner()) {
                                (Some(me), Some(owner)) if me == *owner => {
                                    Some(KvSyncMessage::OwnerAnnounce {
                                        owner: me,
                                        policy: s.policy().clone(),
                                        policy_version: s.policy_version(),
                                    })
                                }
                                _ => None,
                            }
                        };
                        if let Some(announce) = announce {
                            let serialized = if let (Some(ctx), Some(signing)) =
                                (responder_secure.as_ref(), responder_signing.as_ref())
                            {
                                if responder_is_encrypted {
                                    Self::seal_control_message(
                                        ctx,
                                        responder_refresh.as_ref(),
                                        signing,
                                        &responder_store_id,
                                        local_peer_id,
                                        &announce,
                                    )
                                    .await
                                } else {
                                    Self::sign_public_control_message(
                                        ctx,
                                        responder_refresh.as_ref(),
                                        signing,
                                        &responder_store_id,
                                        local_peer_id,
                                        &announce,
                                    )
                                    .await
                                }
                                .ok_or_else(|| "seal failed".to_string())
                            } else {
                                bincode::serialize(&announce).map_err(|e| e.to_string())
                            };
                            match serialized {
                                Ok(serialized) => {
                                    if let Err(e) = responder_pubsub
                                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                                        .await
                                    {
                                        tracing::warn!(
                                            "KvStore owner-announce publish failed: {e}"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("KvStore owner-announce serialize failed: {e}");
                                }
                            }
                        }
                        // Cooldown gates the full-state broadcast. The
                        // StateServed marker is published ONLY alongside an
                        // actual full-delta publish (or for an owner's
                        // checkpoint-less empty store, which has no payload
                        // at all): a marker must witness a real broadcast —
                        // a marker for a cooldown-suppressed response could
                        // convince a requester that never received the state
                        // to stop asking (round-3 review). Checked BEFORE
                        // building the full delta — no point cloning the
                        // whole store for a suppressed response.
                        let cooled_down = last_full_response.is_some_and(|t| {
                            t.elapsed()
                                < std::time::Duration::from_secs(STATE_RESPONSE_COOLDOWN_SECS)
                        });
                        // Snapshot state once for the full-delta and the
                        // StateServed markers below. A full response is
                        // served when the store is non-empty, OR when it is
                        // empty but holds an owner checkpoint: the
                        // checkpoint-adopt merge path is a full REPLACE
                        // (keys absent from the signed set are removed), so
                        // a checkpoint-bearing empty delta is exactly how a
                        // deleted-to-empty store cold-syncs to a stale
                        // replica (round-3 review — an empty owner must not
                        // be silent while stale holders keep advertising
                        // obsolete state). The v2 digest is computed over
                        // the SAME snapshot as the full delta, so the
                        // declaration always commits to exactly what was
                        // broadcast.
                        let (
                            full,
                            retained,
                            is_empty,
                            is_owner,
                            checkpoint_seq,
                            has_payload,
                            served,
                        ) = {
                            let s = responder_store.read().await;
                            let is_owner =
                                local_agent_id.is_some() && s.owner() == local_agent_id.as_ref();
                            let cp =
                                (s.highest_checkpoint_seq > 0).then_some(s.highest_checkpoint_seq);
                            let has_payload = if responder_uses_retained {
                                s.has_retained_group_history()
                            } else {
                                !s.is_empty() || s.latest_checkpoint.is_some()
                            };
                            let full = if has_payload && !cooled_down && !responder_uses_retained {
                                match s.full_delta() {
                                    Ok(delta) => Some(delta),
                                    Err(error) => {
                                        tracing::warn!(%error, "cannot allocate full-state delta tags");
                                        None
                                    }
                                }
                            } else {
                                None
                            };
                            let retained = if has_payload && !cooled_down && responder_uses_retained
                            {
                                match serialize_retained_group_image(&s) {
                                    Ok(bytes) => Some(bytes),
                                    Err(error) => {
                                        tracing::warn!(%error, "cannot serve complete group history");
                                        None
                                    }
                                }
                            } else {
                                None
                            };
                            let served = (s.served_digest(), s.checkpoint_pairs().len() as u32);
                            (
                                full,
                                retained,
                                s.is_empty(),
                                is_owner,
                                cp,
                                has_payload,
                                served,
                            )
                        };
                        let mut markers: Vec<KvSyncMessage> = Vec::new();
                        if let Some(retained) = retained {
                            let Some(signing) = responder_signing.as_ref() else {
                                continue;
                            };
                            let published = Self::publish_retained_history_frames(
                                RetainedHistoryPublish {
                                    seal: GroupHistorySeal {
                                        store: &responder_store,
                                        treekem: responder_treekem.as_ref(),
                                        secure: responder_secure.as_ref(),
                                        refresh: responder_refresh.as_ref(),
                                        signing,
                                        encrypted: responder_is_encrypted,
                                        local_peer_id,
                                    },
                                    pubsub: responder_pubsub.as_ref(),
                                    topic: &responder_topic,
                                    #[cfg(test)]
                                    test_state: None,
                                },
                                &retained,
                            )
                            .await;
                            if published.is_ok() {
                                last_full_response = Some(tokio::time::Instant::now());
                                markers.push(KvSyncMessage::StateServedV2 {
                                    responder: local_peer_id,
                                    digest: served.0,
                                    entry_count: served.1,
                                });
                            } else if let Err(error) = published {
                                tracing::warn!(%error, "cannot publish complete group history");
                            }
                        } else if let Some(full) = full {
                            // #341 Phase B: the full-state serve on the main
                            // topic is SEALED for encrypted stores — never a
                            // plaintext delta.
                            let serialized = if let (Some(ctx), Some(signing)) =
                                (responder_secure.as_ref(), responder_signing.as_ref())
                            {
                                Self::seal_publication(
                                    &responder_store,
                                    ctx,
                                    responder_refresh.as_ref(),
                                    signing,
                                    KvMutationKind::FullState,
                                    local_peer_id,
                                    &full,
                                )
                                .await
                                .map_err(|e| e.to_string())
                            } else {
                                encode_delta(local_peer_id, &full).map_err(|e| e.to_string())
                            };
                            if let Ok(serialized) = serialized {
                                if let Err(e) = responder_pubsub
                                    .publish(
                                        responder_topic.clone(),
                                        bytes::Bytes::from(serialized),
                                    )
                                    .await
                                {
                                    tracing::warn!("KvStore state-response publish failed: {e}");
                                } else {
                                    last_full_response = Some(tokio::time::Instant::now());
                                    markers.push(KvSyncMessage::StateServed {
                                        responder: local_peer_id,
                                        empty: is_empty,
                                        checkpoint_seq,
                                    });
                                    // The v2 marker rides along with the
                                    // broadcast it commits to — never
                                    // separately (response-storm damping,
                                    // issue #240).
                                    markers.push(KvSyncMessage::StateServedV2 {
                                        responder: local_peer_id,
                                        digest: served.0,
                                        entry_count: served.1,
                                    });
                                }
                            }
                        } else if !has_payload {
                            // Checkpoint-less empty. The v2 digest of the
                            // empty set is universally computable, so ANY
                            // empty holder may declare it — an empty
                            // requester verifies locally and stops (issue
                            // #240; no broadcast to witness because there
                            // is nothing to serve).
                            markers.push(KvSyncMessage::StateServedV2 {
                                responder: local_peer_id,
                                digest: served.0,
                                entry_count: 0,
                            });
                            if is_owner {
                                // v1 behavior for older peers is unchanged:
                                // only the OWNER declares emptiness — an
                                // empty non-owner replica stays silent on
                                // v1 so bootstrapping replicas can never
                                // talk each other into a false "converged
                                // empty".
                                markers.push(KvSyncMessage::StateServed {
                                    responder: local_peer_id,
                                    empty: true,
                                    checkpoint_seq: None,
                                });
                            }
                        }
                        for marker in markers {
                            let serialized = if let (Some(protector), Some(signing)) =
                                (responder_treekem.as_ref(), responder_signing.as_ref())
                            {
                                Self::seal_treekem_control(
                                    protector,
                                    signing,
                                    &responder_store_id,
                                    local_peer_id,
                                    &marker,
                                )
                                .await
                                .ok_or_else(|| "TreeKEM control seal failed".to_string())
                            } else if let (Some(ctx), Some(signing)) =
                                (responder_secure.as_ref(), responder_signing.as_ref())
                            {
                                if responder_is_encrypted {
                                    Self::seal_control_message(
                                        ctx,
                                        responder_refresh.as_ref(),
                                        signing,
                                        &responder_store_id,
                                        local_peer_id,
                                        &marker,
                                    )
                                    .await
                                } else {
                                    Self::sign_public_control_message(
                                        ctx,
                                        responder_refresh.as_ref(),
                                        signing,
                                        &responder_store_id,
                                        local_peer_id,
                                        &marker,
                                    )
                                    .await
                                }
                                .ok_or_else(|| "seal failed".to_string())
                            } else {
                                bincode::serialize(&marker).map_err(|e| e.to_string())
                            };
                            match serialized {
                                Ok(serialized) => {
                                    if let Err(e) = responder_pubsub
                                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                                        .await
                                    {
                                        tracing::warn!(
                                            "KvStore state-served marker publish failed: {e}"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "KvStore state-served marker serialize failed: {e}"
                                    );
                                }
                            }
                        }
                    }
                    KvSyncMessage::StateServed {
                        responder,
                        empty,
                        checkpoint_seq,
                    } => {
                        if responder == local_peer_id {
                            continue; // our own marker echoed back
                        }
                        // Trust note: markers steer only WHEN the bootstrap
                        // requester stops asking — never store content, and
                        // convergence is re-checked against local state
                        // (`bootstrap_converged`), so a forged marker cannot
                        // inject state. A forged NON-EMPTY marker at worst
                        // stops the tail no earlier than a real holder could
                        // (the any-holder-answers trust the protocol already
                        // has). The two evidence classes that could do real
                        // damage are trusted only from the pub/sub-verified
                        // anchored owner:
                        // - EMPTY would stop an empty replica's recovery
                        //   outright;
                        // - CHECKPOINT_SEQ is the exact convergence gate,
                        //   and a forged u64::MAX would pin the requester
                        //   at capped cadence forever while a forged low
                        //   value could retire a stale replica early
                        //   (round-3 review).
                        // Owner-marker checkpoints also self-correlate: the
                        // local high-water mark only rises by MERGING the
                        // checkpoint-bearing full delta, so satisfying the
                        // gate proves the state actually arrived. For sealed
                        // control traffic the verified identity is the INNER
                        // author (`verified_sender`), never a relay's
                        // transport sender.
                        let owner_verified = {
                            let anchored = responder_store.read().await.owner().copied();
                            anchored.is_some() && verified_sender.as_ref() == anchored.as_ref()
                        };
                        let mut ev = responder_served
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if empty {
                            if owner_verified {
                                ev.saw_owner_empty = true;
                            }
                        } else {
                            ev.saw_nonempty = true;
                        }
                        if let Some(seq) = checkpoint_seq.filter(|_| owner_verified) {
                            ev.max_checkpoint_seq = ev.max_checkpoint_seq.max(seq);
                        }
                    }
                    KvSyncMessage::StateServedV2 {
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
                        // The verified full-replace adopt additionally
                        // requires the full-delta SENDER to be an
                        // authorized writer (see the listener), so a
                        // marker alone can never truncate anything.
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
                    KvSyncMessage::OwnerAnnounce {
                        owner,
                        policy,
                        policy_version,
                    } => {
                        // Only a signature-verified sender is trusted. On the
                        // plaintext path that is the pub/sub layer's verified
                        // transport sender; on the sealed path (#341 Phase B)
                        // it is the inner mutation's verified author (and the
                        // message was additionally membership-gated).
                        let Some(sender) = verified_sender else {
                            tracing::warn!(
                                "ignoring unsigned KvStore ownership announcement on {}",
                                msg.topic
                            );
                            continue;
                        };
                        if local_agent_id.is_some_and(|me| me == sender) {
                            continue; // our own announce echoed back
                        }
                        // Validate BEFORE the receive section (#757 r3): an
                        // announce that would be rejected, or change
                        // nothing, must not queue behind the listener's
                        // merge + snapshot write — it would stall the state
                        // requests behind it in this loop. `learn_ownership`
                        // re-validates under the lock below.
                        let effect = responder_store.read().await.check_ownership_announce(
                            owner,
                            &policy,
                            policy_version,
                            &sender,
                        );
                        match effect {
                            Err(e) => {
                                tracing::warn!(
                                    "rejected KvStore ownership announcement from {}: {e}",
                                    hex::encode(sender.as_bytes())
                                );
                                continue;
                            }
                            Ok(crate::kv::store::OwnershipAnnounceEffect::Stale) => continue,
                            Ok(_) => {}
                        }
                        // #757 lifecycle fence — see the listener. Scoped to
                        // this arm only: the state-serve arms publish on the
                        // network and never mutate the store.
                        let _lifecycle = responder_lifecycle.lock().await;
                        if responder_cancel.is_cancelled() {
                            return;
                        }
                        let learned = {
                            let mut s = responder_store.write().await;
                            // learn_ownership can only refresh policy (when the
                            // owner matches and policy_version is forward) or
                            // record a conflict; it never establishes ownership.
                            // AppendOnly is terminal: a downgrade announce is
                            // rejected inside learn_ownership regardless of
                            // policy_version.
                            match s.learn_ownership(owner, policy, policy_version, &sender) {
                                Ok(()) => {
                                    tracing::info!(
                                        "KvStore {} processed owner announce from {} (policy {}, version {})",
                                        s.id(),
                                        hex::encode(owner.as_bytes()),
                                        s.policy(),
                                        s.policy_version()
                                    );
                                    true
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "rejected KvStore ownership announcement from {}: {e}",
                                        hex::encode(sender.as_bytes())
                                    );
                                    false
                                }
                            }
                        };
                        // A policy refresh mutates durable state — persist it
                        // (outside the write guard).
                        if learned {
                            if let Some(ctx) = responder_persist_ctx.as_ref() {
                                let _ = persist_snapshot(&responder_store, ctx).await;
                            }
                        }
                    }
                }
            }
        };
        #[cfg(test)]
        let responder_loop = TrackedLoopFuture::wrap(responder_loop_exits, responder_loop);
        spawn(Box::pin(responder_loop));

        // Bootstrap requester: a first-time joiner starts with an empty
        // store and has no other way to learn keys written before it
        // subscribed (the gossip message cache only replays ~60s, and
        // pruning on busy topics removes older deltas entirely). Ask
        // holders to republish. The full FRONT schedule always runs — a
        // partial state arriving early (for example fresh keys via cache
        // replay) must not stop the request for the complete historical
        // state. After the front schedule, an infinite backoff tail keeps
        // asking while the store is STILL EMPTY (issue #238): holders
        // answer only reactively, so a replica whose requests all fired
        // while the owner was offline would otherwise stay a zombie
        // forever. The tail self-terminates the moment any state merges
        // (the owner's full-delta response also carries its checkpoint,
        // so policy converges with the data). Requests and the full-delta
        // responses they trigger are idempotent CRDT merges, so the
        // chatter is harmless; a genuinely-new empty store costs one tiny
        // side-topic message per backoff interval until its first write.
        if bootstrap_needed {
            let requester_pubsub = Arc::clone(&self.pubsub);
            let sync_topic = self.state_sync_topic();
            // Weak: the requester must not keep the store alive on its own.
            // (Belt-and-braces — the sibling loops hold strong Arcs, so the
            // authoritative kill switch is the `stopped` flag below.)
            let requester_store = Arc::downgrade(&self.store);
            let stopped = Arc::clone(&self.stopped);
            let requester_cancel = self.cancel.clone();
            let requester_served = Arc::clone(&served_evidence);
            let requester_bootstrap_active = Arc::clone(&bootstrap_active);
            // Encrypted-path handles: StateRequest is SEALED for encrypted
            // stores, so only members can trigger full-state broadcasts.
            let requester_secure = self.secure.clone();
            let requester_treekem = self.treekem_secure.clone();
            let requester_refresh = self.secure_refresh.clone();
            let requester_signing = self.author_signing.clone();
            let requester_store_id = { *self.store.read().await.id() };
            let requester_is_encrypted = store_is_encrypted;
            #[cfg(test)]
            let requester_loop_exits = Arc::clone(&self.loop_exits);
            // #765 r4: the loop-exit tracker wraps the WHOLE loop future,
            // so termination is recorded only after this future — and
            // every capture it holds — is destroyed (see
            // `TrackedLoopFuture`).
            let requester_loop = async move {
                // Disarms the adopt window on ANY exit (converged, silenced,
                // cancelled, torn down) — the listener's verified
                // full-replace adopt must never fire outside bootstrap.
                let _guard = BootstrapGuard(requester_bootstrap_active);
                for (attempt, delay_secs) in state_request_delays().enumerate() {
                    tokio::select! {
                        biased;
                        // cancel_sync tears down every loop promptly, even
                        // mid-sleep (round-4 review).
                        () = requester_cancel.cancelled() => return,
                        () = tokio::time::sleep(jittered_secs(delay_secs)) => {}
                    }
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        return; // silenced — never chatter for a dead sync
                    }
                    // Tail attempts stop on convergence; front attempts
                    // always run (see above — partial early state must not
                    // cancel the request for full history). Convergence is
                    // judged against StateServed evidence matched to local
                    // state (`bootstrap_converged`) — NOT mere non-emptiness,
                    // which a single incremental delta can fake while the
                    // full historical state is still missing (round-2
                    // review). v2 digest evidence makes the check exact for
                    // checkpoint-less state (issue #240): the requester
                    // stops only when its OWN content digest matches a
                    // holder's declaration.
                    if attempt >= STATE_REQUEST_RETRY_SECS.len() {
                        let Some(store) = requester_store.upgrade() else {
                            return; // sync torn down — nothing left to bootstrap
                        };
                        let ev = requester_served
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone();
                        let (is_empty, cp_hwm, local_digest) = {
                            let s = store.read().await;
                            (s.is_empty(), s.highest_checkpoint_seq, s.served_digest())
                        };
                        if bootstrap_converged(&ev, is_empty, cp_hwm, local_digest) {
                            return; // a holder served us and local state matches
                        }
                    }
                    let request = KvSyncMessage::StateRequest {
                        requester: local_peer_id,
                    };
                    let serialized = if let (Some(protector), Some(signing)) =
                        (requester_treekem.as_ref(), requester_signing.as_ref())
                    {
                        Self::seal_treekem_control(
                            protector,
                            signing,
                            &requester_store_id,
                            local_peer_id,
                            &request,
                        )
                        .await
                    } else if let (Some(ctx), Some(signing)) =
                        (requester_secure.as_ref(), requester_signing.as_ref())
                    {
                        // #341 Phase B: sealed state request — non-members
                        // cannot even trigger a full-state broadcast.
                        if requester_is_encrypted {
                            Self::seal_control_message(
                                ctx,
                                requester_refresh.as_ref(),
                                signing,
                                &requester_store_id,
                                local_peer_id,
                                &request,
                            )
                            .await
                        } else {
                            Self::sign_public_control_message(
                                ctx,
                                requester_refresh.as_ref(),
                                signing,
                                &requester_store_id,
                                local_peer_id,
                                &request,
                            )
                            .await
                        }
                    } else {
                        bincode::serialize(&request).ok()
                    };
                    let Some(serialized) = serialized else {
                        return;
                    };
                    if let Err(e) = requester_pubsub
                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                        .await
                    {
                        tracing::debug!("KvStore state-request publish failed: {e}");
                    }
                }
            };
            #[cfg(test)]
            let requester_loop = TrackedLoopFuture::wrap(requester_loop_exits, requester_loop);
            spawn(Box::pin(requester_loop));
        }

        Ok(())
    }

    /// Silence ONLY this sync's bootstrap requester (its schedule is
    /// infinite while unconverged — issue #238), leaving the listener and
    /// responder loops serving.
    ///
    /// Use when the replica should keep replicating but never generate
    /// bootstrap chatter (e.g. an authoritative holder in a single-identity
    /// test harness). Discarded handles want [`cancel_sync`](Self::cancel_sync).
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

    /// Whether receive sections of THIS sync run a TreeKEM protector. Such a
    /// section can wait on locks the protector takes (in the daemon: the
    /// group membership guard) while holding the lifecycle lock, so a caller
    /// holding one of those must not drain it (#757).
    pub fn has_treekem_protector(&self) -> bool {
        self.treekem_secure.is_some()
    }

    /// [`cancel_sync`](Self::cancel_sync), then wait out any receive-path
    /// section already running (#757).
    ///
    /// When this returns, no background merge, ownership update or snapshot
    /// write for this store is in flight, and none can start. (Read-only
    /// state serves and the requester's publish are outside the fence — see
    /// the `lifecycle` field.) `cancel_sync` alone is only a request: ONE
    /// section that already passed its cancel check still completes,
    /// including its snapshot write, possibly after `cancel_sync` returned.
    ///
    /// Must NOT be awaited while holding any lock a section takes — the
    /// group membership guard (TreeKEM stores), `named_groups`, `kv_stores`,
    /// this store's own guard, or its persist gate — nor from inside the
    /// secure-refresh hook, which runs within a section. Either deadlocks;
    /// those callers use `cancel_sync` and accept the residual (#760).
    pub async fn cancel_sync_and_drain(&self) {
        self.cancel.cancel();
        drop(self.lifecycle.lock().await);
    }

    /// Wait until the plaintext listener has merged one remote delta and is
    /// about to persist it. `Notify` retains one permit, so the test cannot
    /// miss the barrier if the merge wins the race to this call.
    #[cfg(test)]
    pub(crate) async fn wait_receive_merged_for_test(&self) {
        self.receive_merged_test.notified().await;
    }

    /// This sync's background-loop termination counter (#765): the
    /// deterministic signal that every loop future `start_with_spawner`
    /// spawned has been DESTROYED — each exit is recorded only after the
    /// whole wrapped future (captured persist context included) drops, so
    /// reaching the full count means the fence entry is prunable — or, at
    /// a lower count, that a shutdown sweep's `cancel_sync` already ended
    /// the sibling loops.
    #[cfg(test)]
    pub(crate) fn loop_exit_tracker(&self) -> Arc<LoopExitTracker> {
        Arc::clone(&self.loop_exits)
    }

    /// Stop background synchronization.
    ///
    /// Topic-wide: unsubscribes the main and state-sync topics for the
    /// WHOLE process (every subscriber of those topic strings), which is
    /// only appropriate when this sync is the topics' sole consumer.
    /// In-process daemons discarding one handle should use
    /// [`cancel_sync`](Self::cancel_sync) — or simply drop every handle
    /// clone: the [`Drop`] impl cancels structurally.
    pub async fn stop(&self) -> Result<()> {
        // End the loops FIRST: the bootstrap requester's schedule is
        // infinite while the store is empty (issue #238), and unsubscribing
        // does not end that loop (it holds no subscription).
        self.cancel_sync();
        self.pubsub.unsubscribe(&self.topic).await;
        self.pubsub.unsubscribe(&self.state_sync_topic()).await;
        Ok(())
    }

    /// Publish a local delta to the gossip network.
    ///
    /// For an encrypted store (#341 Phase B) the delta is NEVER serialized
    /// plaintext: it is sign-then-encrypt sealed into an
    /// `EncryptedKvStoreRecordV1` envelope first. A missing context or
    /// signing material is a hard error — the plaintext path is unreachable
    /// by construction for encrypted stores.
    pub async fn publish_delta(&self, local_peer_id: PeerId, delta: KvStoreDelta) -> Result<()> {
        // Policy check at the PUBLIC boundary (the start() guard only covers
        // the background loops): a sync constructed for an encrypted store
        // but never configured (or not yet started) must hard-error here —
        // falling through to the plaintext branch would leak the delta.
        let (store_is_encrypted, store_is_group_signed, store_is_treekem) = {
            let store = self.store.read().await;
            (
                store.is_encrypted(),
                store.is_group_signed(),
                store.is_treekem_encrypted(),
            )
        };
        if (store_is_encrypted || store_is_group_signed)
            && self.secure.is_none()
            && self.treekem_secure.is_none()
        {
            return Err(KvError::SecureRecord(
                "encrypted store publish refused: no secure context attached                  (set_secure_context) — plaintext publication is unreachable for encrypted stores"
                    .to_string(),
            ));
        }
        let serialized = if store_is_treekem {
            let payload = bincode::serialize(&delta)
                .map_err(|e| KvError::Gossip(format!("TreeKEM delta serialize failed: {e}")))?;
            Self::seal_treekem_payload(
                &self.store,
                self.treekem_secure.as_ref().ok_or_else(|| {
                    KvError::SecureRecord("encrypted store has no TreeKEM protector".to_string())
                })?,
                self.author_signing.as_ref().ok_or_else(|| {
                    KvError::SecureRecord(
                        "TreeKEM store publish requires author signing material".to_string(),
                    )
                })?,
                KvMutationKind::Delta,
                local_peer_id,
                &payload,
            )
            .await?
        } else if store_is_encrypted {
            let ctx = self.secure.as_ref().ok_or_else(|| {
                KvError::SecureRecord("encrypted store has no context".to_string())
            })?;
            Self::seal_publication(
                &self.store,
                ctx,
                self.secure_refresh.as_ref(),
                self.author_signing.as_ref().ok_or_else(|| {
                    KvError::SecureRecord(
                        "encrypted store publish requires author signing material".to_string(),
                    )
                })?,
                KvMutationKind::Delta,
                local_peer_id,
                &delta,
            )
            .await?
        } else if store_is_group_signed {
            let ctx = self.secure.as_ref().ok_or_else(|| {
                KvError::SecureRecord("group-signed store has no context".to_string())
            })?;
            let payload = bincode::serialize(&delta)
                .map_err(|e| KvError::Gossip(format!("signed delta serialize failed: {e}")))?;
            Self::sign_publication(
                &self.store,
                ctx,
                self.secure_refresh.as_ref(),
                self.author_signing.as_ref().ok_or_else(|| {
                    KvError::SecureRecord(
                        "group-signed store publish requires author signing material".to_string(),
                    )
                })?,
                KvMutationKind::Delta,
                local_peer_id,
                payload,
            )
            .await?
        } else {
            encode_delta(local_peer_id, &delta)
                .map_err(|e| KvError::Gossip(format!("serialize delta failed: {e}")))?
        };

        self.pubsub
            .publish(self.topic.clone(), bytes::Bytes::from(serialized))
            .await
            .map_err(|e| KvError::Gossip(format!("publish delta failed: {e}")))?;

        Ok(())
    }

    /// Publish the current complete retained group history through the same
    /// authenticated, bounded frame path used by reactive state responses.
    pub(crate) async fn publish_retained_group_history(&self) -> Result<()> {
        let (retained, encrypted, group_policy) = {
            let store = self.store.read().await;
            (
                serialize_retained_group_image(&store)?,
                store.is_encrypted(),
                store.is_encrypted() || store.is_group_signed(),
            )
        };
        if !group_policy {
            return Err(KvError::SecureRecord(
                "retained group history publication requires a group store".to_string(),
            ));
        }
        let signing = self.author_signing.as_ref().ok_or_else(|| {
            KvError::SecureRecord(
                "retained group history publication requires author signing material".to_string(),
            )
        })?;
        Self::publish_retained_history_frames(
            RetainedHistoryPublish {
                seal: GroupHistorySeal {
                    store: &self.store,
                    treekem: self.treekem_secure.as_ref(),
                    secure: self.secure.as_ref(),
                    refresh: self.secure_refresh.as_ref(),
                    signing,
                    encrypted,
                    local_peer_id: self.local_peer_id,
                },
                pubsub: &self.pubsub,
                topic: &self.topic,
                #[cfg(test)]
                test_state: Some(&self.retained_publish_test),
            },
            &retained,
        )
        .await
    }

    /// True while a background receive section holds the lifecycle lock.
    #[cfg(test)]
    pub(crate) fn receive_section_active_for_test(&self) -> bool {
        self.lifecycle.try_lock().is_err()
    }

    /// Run `during` while this store's snapshot gate is held, so any
    /// receive-path persist that starts meanwhile parks in flight (#757).
    #[cfg(test)]
    pub(crate) async fn with_persist_gate_held_for_test<F: std::future::Future>(
        &self,
        during: F,
    ) -> F::Output {
        let ctx = self.persist_ctx();
        let _gate = match ctx.as_ref() {
            Some(ctx) => Some(ctx.gate.lock().await),
            None => None,
        };
        during.await
    }

    #[cfg(test)]
    pub(crate) fn fail_retained_publish_after_for_test(&self, accepted_frames: usize) {
        let mut state = self
            .retained_publish_test
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.fail_after = Some(accepted_frames);
        state.accepted = 0;
    }

    #[cfg(test)]
    pub(crate) fn retained_publish_accepted_for_test(&self) -> usize {
        self.retained_publish_test
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accepted
    }

    #[cfg(test)]
    pub(crate) fn clear_retained_publish_failure_for_test(&self) {
        let mut state = self
            .retained_publish_test
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.fail_after = None;
        state.accepted = 0;
    }

    /// Get a read-only reference to the store.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, KvStore> {
        self.store.read().await
    }

    /// Get a mutable reference to the store.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, KvStore> {
        self.store.write().await
    }

    /// Get the topic name.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

/// Monotonic counter for unique snapshot temp-file names — concurrent
/// persists (receive loop vs. local write) must never clobber each other's
/// temp file mid-rename.
static SNAPSHOT_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Magic prefix of the v1 snapshot file format.
///
/// Format: `MAGIC(8) || bincode(SnapshotBody { store, seq_counter })`.
/// The envelope exists so the OR-Set sequence-counter ceiling (which is
/// `serde(skip)` on `KvStore` for wire/legacy-layout reasons) survives a
/// restart exactly. The format is introduced unreleased — no shipped binary
/// ever wrote a bare-`KvStore` snapshot — so there is no compat read path:
/// a file without the magic is rejected (fail closed) rather than guessed at.
const SNAPSHOT_MAGIC: &[u8; 8] = b"X0XKVS1\0";

/// Owned snapshot body (decode side).
#[derive(Deserialize)]
struct SnapshotBody {
    store: KvStore,
    seq_counter: u64,
}

/// Borrowing snapshot body (encode side — avoids cloning the store).
#[derive(Serialize)]
struct SnapshotBodyRef<'a> {
    store: &'a KvStore,
    seq_counter: u64,
}

/// Encode a store into v1 snapshot bytes (magic + body).
fn encode_snapshot(store: &KvStore) -> Result<Vec<u8>> {
    let body = SnapshotBodyRef {
        store,
        seq_counter: store.seq_counter_value(),
    };
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.extend_from_slice(&bincode::serialize(&body)?);
    Ok(out)
}

/// Outcome of one snapshot commit attempt.
enum PersistOutcome {
    /// Bytes captured and renamed into place.
    Written,
    /// Skipped: durable state is already at (or beyond) the captured
    /// version AND this generation still owns the snapshot path (#760) —
    /// a stale equal-version handle reports [`PersistOutcome::Superseded`]
    /// instead.
    Current,
    /// Suppressed: a younger generation owns the snapshot path (#760).
    /// Policy is caller-dependent — receive paths skip (the merge belongs
    /// to a discarded generation), caller-driven persistence escalates to
    /// [`KvError::SnapshotSuperseded`] + durability-degraded.
    Superseded,
}

/// Snapshot the store to the persistence context's path.
///
/// Serialized per store via `ctx.gate`: `(version, bytes)` are captured
/// under the gate, so commit order equals capture order and a slow persist
/// can never rename an older snapshot over a newer one; the recorded
/// last-persisted version additionally skips writes that would not advance
/// durable state — and that skip is ownership-fenced like the write itself
/// (#760): `Current` is answered only while this generation still owns the
/// path, so a stale handle at an unchanged version reports
/// [`PersistOutcome::Superseded`] instead of success. The rename itself
/// runs under the snapshot path's fence
/// mutex with an ownership check on `ctx.owner` (#760): once a younger
/// sync arms the same path, this ctx's writes are suppressed —
/// [`PersistOutcome::Superseded`] — so an older admitted write can never
/// land after a younger generation's. Success clears the degraded flag;
/// failure sets it and is error-logged here (callers decide whether to
/// propagate — local writes must, remote merges must not); a superseded
/// write touches neither the flag nor the file.
///
/// # Errors
///
/// Serialization or I/O failure writing the snapshot.
async fn persist_snapshot(
    store: &Arc<RwLock<KvStore>>,
    ctx: &PersistCtx,
) -> Result<PersistOutcome> {
    let result: Result<PersistOutcome> = async {
        let mut last = ctx.gate.lock().await;
        let (version, bytes) = {
            let s = store.read().await;
            (s.current_version(), encode_snapshot(&s)?)
        };
        if last.is_some_and(|l| l >= version) {
            // Durable state already at (or beyond) this version. The skip
            // is ownership-fenced (#760): the query takes the same leaf
            // mutex `arm_persist` uses, so it linearizes exactly like a
            // write — a pre-arm residual stays `Current`, while a handle
            // whose successor has already armed is typed `Superseded` and
            // must not clear the degraded flag on bytes it no longer owns.
            // Neither path rewrites the file.
            return Ok(if ctx.owner.is_current_owner() {
                PersistOutcome::Current
            } else {
                PersistOutcome::Superseded
            });
        }
        match super::snapshot_fence::write_if_owner(&ctx.owner, &bytes, write_snapshot_atomic)? {
            true => {
                *last = Some(version);
                Ok(PersistOutcome::Written)
            }
            false => {
                tracing::debug!(
                    "kv snapshot persist suppressed for {}: superseded generation {} (#760)",
                    ctx.owner.path().display(),
                    ctx.owner.generation()
                );
                Ok(PersistOutcome::Superseded)
            }
        }
    }
    .await;
    match &result {
        Ok(PersistOutcome::Written) | Ok(PersistOutcome::Current) => {
            ctx.degraded
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        // Suppressed is the retire protocol working, not a disk failure:
        // neither clear nor set the flag here.
        Ok(PersistOutcome::Superseded) => {}
        Err(e) => {
            ctx.degraded
                .store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                "kv snapshot persist failed for {}: {e} — store is durability-degraded; \
                 local writes are refused until a snapshot succeeds",
                ctx.owner.path().display()
            );
        }
    }
    result
}

/// Durable atomic file write: unique temp file in the same directory,
/// fsync, rename over the destination, then (Unix) fsync the parent
/// directory so the rename itself survives power loss.
///
/// Platform note: on non-Unix targets the parent-directory fsync is skipped
/// (std cannot fsync a directory handle there); the rename is still atomic,
/// but its durability across power loss is not guaranteed. SIGKILL/power
/// loss beyond the parent fsync (e.g. hardware write caches) is out of
/// scope.
fn write_snapshot_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let n = SNAPSHOT_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{n}", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Load a previously persisted store snapshot from `path`.
///
/// Returns:
/// - `Ok(Some(store))` — snapshot present and valid.
/// - `Ok(None)` — no snapshot at `path` (first run).
/// - `Err(_)` — snapshot present but unreadable, undecodable, or not in the
///   v1 format. Callers MUST fail closed on this (refuse to start an empty
///   replica over a corrupt snapshot): silently discarding it would reopen
///   the restart-amnesia window (an `AppendOnly` owner that forgets its keys
///   will re-accept rewrites of them).
///
/// The restored store's in-memory `seq_counter` is set to the persisted
/// counter (floored by `version` as defense in depth), so freshly minted
/// OR-Set `(peer, seq)` tags can never collide with tags issued before the
/// restart — including the extra per-put delta tag minted by
/// `KvStoreHandle::put_with_delta`.
///
/// # Errors
///
/// [`crate::kv::KvError::Io`]/[`crate::kv::KvError::Serialization`] as above.
pub fn load_snapshot(path: &Path) -> Result<Option<KvStore>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    load_snapshot_bytes(&bytes).map(Some)
}

/// Decode one already-bounded snapshot buffer.
///
/// This is used by explicit import paths that must hash and validate the
/// exact bytes they decode, without reopening a mutable filesystem path.
pub(crate) fn load_snapshot_bytes(bytes: &[u8]) -> Result<KvStore> {
    let Some(body_bytes) = bytes.strip_prefix(SNAPSHOT_MAGIC.as_slice()) else {
        return Err(std::io::Error::other(
            "unrecognized kv snapshot format (missing v1 magic) — corrupt or foreign file; \
             refusing to start with amnesia",
        )
        .into());
    };
    let body: SnapshotBody = bincode::deserialize(body_bytes)?;
    let store = body.store;
    // #341: a snapshot carrying the Encrypted policy opens fail-closed
    // (the secure context is `serde(skip)` and must be re-attached by the
    // caller — see `KvStore::set_secure_context`) unless/until that happens:
    // no authorized writer, no local writes, no delta application. Surface
    // that loudly at open time, not only on first rejected use.
    if let AccessPolicy::Encrypted { group_id } = store.policy() {
        tracing::warn!(
            target: "x0x::kv",
            "opened snapshot of encrypted store {} (group_id {}) WITHOUT a secure context — replica is fail-closed until a context is re-attached (set_secure_context)",
            store.id(),
            hex::encode(group_id)
        );
    }
    store.restore_seq_counter(body.seq_counter.max(store.current_version()));
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentId;
    use crate::kv::encrypted::seal_mutation;
    use crate::kv::store::AccessPolicy;
    use crate::kv::TreeKemKvProtector;
    use crate::kv::{KvEntry, KvStoreId};
    use crate::network::{NetworkConfig, NetworkNode};
    use std::time::Duration;

    struct TestTreeKemProtector {
        group_id: Vec<u8>,
        group: tokio::sync::Mutex<crate::mls::TreeKemMlsGroup>,
        readers: std::collections::HashSet<AgentId>,
        writers: std::sync::Mutex<std::collections::HashSet<AgentId>>,
        authorization: [u8; 32],
    }

    #[async_trait::async_trait]
    impl crate::kv::TreeKemKvProtector for TestTreeKemProtector {
        fn group_id(&self) -> Vec<u8> {
            self.group_id.clone()
        }

        async fn seal_record(
            &self,
            signing: &AuthorSigning,
            kind: KvMutationKind,
            store_id: &KvStoreId,
            payload: &[u8],
            reader_only: bool,
        ) -> Result<TreeKemKvStoreRecordV1> {
            let admitted = if reader_only {
                self.readers.contains(&signing.agent_id)
            } else {
                self.writers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&signing.agent_id)
            };
            if !admitted {
                return Err(KvError::Unauthorized("test TreeKEM role denied".into()));
            }
            let mut group = self.group.lock().await;
            let epoch = group.epoch();
            let inner = crate::kv::treekem::sign_inner_mutation(
                signing,
                kind,
                payload,
                crate::kv::treekem::TreeKemInnerBinding {
                    group_id: self.group_id.clone(),
                    epoch,
                    store_id,
                    authorization_binding: self.authorization,
                    reader_only,
                },
            )?;
            let ciphertext = group
                .encrypt_message(&inner)
                .map_err(|error| KvError::SecureRecord(error.to_string()))?;
            Ok(TreeKemKvStoreRecordV1 {
                version: 1,
                group_id: self.group_id.clone(),
                store_id: *store_id.as_bytes(),
                epoch,
                reader_only,
                ciphertext,
            })
        }

        async fn open_record(
            &self,
            store_id: &KvStoreId,
            record: &TreeKemKvStoreRecordV1,
        ) -> Result<crate::kv::treekem::OpenedTreeKemKvRecord> {
            if record.group_id != self.group_id || record.store_id != *store_id.as_bytes() {
                return Err(KvError::SecureRecord(
                    "test TreeKEM binding mismatch".into(),
                ));
            }
            let mut group = self.group.lock().await;
            let plaintext = group
                .decrypt_message(&record.ciphertext)
                .map_err(|error| KvError::SecureRecord(error.to_string()))?;
            let opened = crate::kv::treekem::open_inner_mutation(
                &self.group_id,
                record.epoch,
                store_id,
                &plaintext,
                self.authorization,
            )?;
            let admitted = if opened.reader_only {
                self.readers.contains(&opened.mutation.author_id)
            } else {
                self.writers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&opened.mutation.author_id)
            };
            if !admitted {
                return Err(KvError::Unauthorized("test TreeKEM role denied".into()));
            }
            Ok(opened)
        }

        async fn is_authorized_reader(&self, agent: &AgentId) -> bool {
            self.readers.contains(agent)
        }

        async fn is_authorized_writer(&self, agent: &AgentId) -> bool {
            self.writers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(agent)
        }

        async fn merge_main_record(
            &self,
            opened: crate::kv::treekem::OpenedTreeKemKvRecord,
            sender_peer: PeerId,
            local_peer: PeerId,
            store: &Arc<RwLock<KvStore>>,
            retained_image: Option<Vec<u8>>,
        ) -> Result<()> {
            if !self.is_authorized_writer(&opened.mutation.author_id).await
                || opened.authorization_binding != self.authorization
            {
                return Err(KvError::Unauthorized("test TreeKEM merge denied".into()));
            }
            let mut store = store.write().await;
            match opened.mutation.kind {
                KvMutationKind::RetainedState => {
                    let image: KvStore = bincode::deserialize(
                        retained_image
                            .as_deref()
                            .ok_or_else(|| KvError::Gossip("missing retained image".into()))?,
                    )?;
                    store.merge_group_retained_image(&image, opened.mutation.author_id, local_peer)
                }
                KvMutationKind::Delta | KvMutationKind::FullState => {
                    let delta: KvStoreDelta = bincode::deserialize(&opened.mutation.payload)?;
                    store.merge_delta(&delta, sender_peer, Some(&opened.mutation.author_id))
                }
                KvMutationKind::Control => {
                    Err(KvError::Unauthorized("control on main topic".into()))
                }
            }
        }

        fn invalidate(&self) {
            self.writers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn store_id(n: u8) -> KvStoreId {
        KvStoreId::new([n; 32])
    }

    #[test]
    fn snapshot_roundtrip_missing_and_corrupt() {
        // WHY: snapshot restore is what makes AppendOnly immutability
        // survive a restart. Missing file = clean first run (Ok(None));
        // a valid snapshot must round-trip policy, entries, and the
        // checkpoint high-water mark; a corrupt file must be an Err so
        // callers FAIL CLOSED instead of silently starting empty (amnesia).
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("kv").join("snap.bin");

        assert!(
            matches!(load_snapshot(&path), Ok(None)),
            "missing snapshot is a clean first run"
        );

        let mut store = KvStore::new(
            store_id(7),
            "log".to_string(),
            agent(1),
            AccessPolicy::AppendOnly,
        )
        .expect("kv store");
        store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        store.highest_checkpoint_seq = 5;
        // Simulate the handle-layer double seq mint: the counter can run
        // ahead of `version`. The persisted counter — not a version-derived
        // floor — must be the restore ceiling.
        let _ = store.next_seq().expect("sequence");
        let _ = store.next_seq().expect("sequence");
        let counter_before = store.seq_counter_value();
        let bytes = encode_snapshot(&store).expect("encode");
        write_snapshot_atomic(&path, &bytes).expect("atomic write");

        let restored = load_snapshot(&path)
            .expect("load ok")
            .expect("snapshot present");
        assert_eq!(*restored.policy(), AccessPolicy::AppendOnly);
        assert_eq!(
            restored.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec())
        );
        assert_eq!(restored.highest_checkpoint_seq, 5);
        // Exact tag ceiling restored: the next minted seq is strictly above
        // every pre-restart seq (no OR-Set (peer, seq) tag reuse).
        assert!(
            restored.next_seq().expect("sequence") > counter_before,
            "restored seq counter must exceed every pre-restart seq"
        );

        // A file without the v1 magic (e.g. a bare-bincode or foreign file)
        // fails closed.
        std::fs::write(&path, bincode::serialize(&store).expect("serialize")).expect("write bare");
        assert!(
            load_snapshot(&path).is_err(),
            "missing-magic snapshot must be an error (fail closed)"
        );

        std::fs::write(&path, b"not a snapshot").expect("corrupt");
        assert!(
            load_snapshot(&path).is_err(),
            "corrupt snapshot must be an error (fail closed), not a silent fresh start"
        );

        // Truncated/garbage body AFTER a valid magic also fails closed.
        let mut evil = SNAPSHOT_MAGIC.to_vec();
        evil.extend_from_slice(b"\x01\x02\x03");
        std::fs::write(&path, evil).expect("write garbage body");
        assert!(
            load_snapshot(&path).is_err(),
            "garbage body must be an error (fail closed)"
        );
    }

    #[test]
    fn retained_import_sequence_floor_survives_snapshot_restart() {
        let owner = agent(1);
        let mut group = crate::groups::GroupInfo::new(
            "public".to_string(),
            String::new(),
            owner,
            "09".repeat(16),
        );
        group.migrate_from_v1();
        group.policy.confidentiality = crate::groups::GroupConfidentiality::SignedPublic;
        group.policy.read_access = crate::groups::GroupReadAccess::Public;
        let group_id = group.stable_group_id().as_bytes().to_vec();
        let id = store_id(19);
        let local_peer = peer(4);
        let ctx = Arc::new(
            crate::groups::PublicGroupKvContext::from_group(&group).expect("public context"),
        );
        let mut source =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group_id.clone(), ctx.clone())
                .expect("source");
        source
            .put(
                "page".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                local_peer,
            )
            .expect("source put");
        source.remove("page").expect("source remove");
        let source: KvStore =
            bincode::deserialize(&bincode::serialize(&source).expect("retained image encode"))
                .expect("retained image decode");

        let mut target = KvStore::new_group_signed(id, "Wiki".to_string(), owner, group_id, ctx)
            .expect("fresh target");
        target
            .merge_group_retained_image(&source, owner, local_peer)
            .expect("authenticated import");
        target
            .put(
                "page".to_string(),
                b"first".to_vec(),
                "text/plain".to_string(),
                local_peer,
            )
            .expect("first re-add");

        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("kv").join("retained.bin");
        write_snapshot_atomic(&path, &encode_snapshot(&target).expect("snapshot encode"))
            .expect("snapshot write");
        let mut restored = load_snapshot(&path)
            .expect("snapshot load")
            .expect("snapshot present");
        restored.remove("page").expect("remove after restart");
        restored
            .put(
                "page".to_string(),
                b"second".to_vec(),
                "text/plain".to_string(),
                local_peer,
            )
            .expect("second re-add after restart");
        assert_eq!(
            restored.get("page").expect("visible re-add").value,
            b"second"
        );
    }

    #[test]
    fn snapshot_with_reserved_encrypted_policy_opens_fail_closed() {
        // WHY (#341 Phase A): a snapshot written before the reservation
        // guard can carry the reserved Encrypted policy. Restoring it must
        // neither error (that would lose the data) nor silently downgrade
        // to Signed (that would invent write authority): the replica
        // restores as-is and the store's fail-closed arms apply.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("kv").join("enc.bin");
        let store = KvStore::new_encrypted_unchecked(
            store_id(7),
            "enc".to_string(),
            agent(1),
            vec![1, 2, 3],
        );
        let bytes = encode_snapshot(&store).expect("encode");
        write_snapshot_atomic(&path, &bytes).expect("write");

        let restored = load_snapshot(&path).expect("load").expect("present");
        assert!(
            matches!(restored.policy(), AccessPolicy::Encrypted { .. }),
            "policy restores verbatim — never silently downgraded"
        );
        assert!(
            !restored.is_authorized(&agent(1)),
            "restored reserved replica is fail-closed, even for its owner"
        );
    }

    /// Construct an isolated network node (mirrors the helper in
    /// `src/gossip/pubsub.rs` tests). `PubSubManager` is fully constructable
    /// in tests, so `KvStoreSync` is testable end-to-end without a live mesh.
    async fn make_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(
                NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
                    bootstrap_nodes: Vec::new(),
                    mdns_enabled: false,
                    port_mapping_enabled: false,
                    ..NetworkConfig::default()
                },
                Some(ant_quic::BootstrapCacheConfig {
                    persist: false,
                    ..ant_quic::BootstrapCacheConfig::default()
                }),
                None,
            )
            .await
            .expect("network node"),
        )
    }

    /// Build a `KvStoreSync` around a fresh node + pubsub, with
    /// `owner = agent(1)` and `local_peer_id = peer(1)`.
    async fn make_sync(topic: &str, policy: AccessPolicy) -> KvStoreSync {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let store =
            KvStore::new(store_id(1), "Test".to_string(), agent(1), policy).expect("kv store");
        KvStoreSync::new(store, pubsub, topic.to_string(), peer(1), Some(agent(1)))
            .expect("kv sync")
    }

    /// Build a `KvStoreSync` that shares its pubsub with the caller (so the
    /// caller can subscribe before the sync publishes).
    async fn make_sync_with_pubsub(
        topic: &str,
        policy: AccessPolicy,
    ) -> (KvStoreSync, Arc<PubSubManager>) {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let store =
            KvStore::new(store_id(1), "Test".to_string(), agent(1), policy).expect("kv store");
        let sync = KvStoreSync::new(
            store,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(agent(1)),
        )
        .expect("kv sync");
        (sync, pubsub)
    }

    #[tokio::test]
    async fn group_signed_responder_serves_tombstone_only_history() {
        let _ = tracing_subscriber::fmt::try_init();
        let node = make_node().await;
        let keypair = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = keypair.agent_id();
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let mut group = crate::groups::GroupInfo::new(
            "public".to_string(),
            String::new(),
            owner,
            "ab".repeat(16),
        );
        group.migrate_from_v1();
        group.policy.confidentiality = crate::groups::GroupConfidentiality::SignedPublic;
        group.policy.read_access = crate::groups::GroupReadAccess::Public;
        let context = Arc::new(
            crate::groups::PublicGroupKvContext::from_group(&group).expect("public context"),
        );
        assert!(context.is_authorized_writer(&owner));
        let id = store_id(1);
        let mut store = KvStore::new_group_signed(
            id,
            "Wiki".to_string(),
            owner,
            group.stable_group_id().as_bytes().to_vec(),
            context.clone(),
        )
        .expect("group store");
        store
            .put(
                "gone".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        store.remove("gone").expect("remove");
        assert!(store.is_empty());
        assert!(store.has_retained_group_history());

        let mut sync = KvStoreSync::new(
            store,
            Arc::clone(&pubsub),
            "group/public/wiki".to_string(),
            peer(1),
            Some(owner),
        )
        .expect("sync");
        sync.set_secure_context(context.clone(), None);
        let signing = Arc::new(AuthorSigning::from_keypair(&keypair).expect("signing"));
        sync.set_author_signing((*signing).clone());
        let mut main_probe = pubsub.subscribe("group/public/wiki".to_string()).await;
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let request = KvSyncMessage::StateRequest { requester: peer(9) };
        let request_bytes = KvStoreSync::sign_public_control_message(
            &(context.clone() as SharedKvSecureContext),
            None,
            &signing,
            &id,
            peer(9),
            &request,
        )
        .await
        .expect("signed request");
        let (_, request_record) =
            decode_delta::<SignedKvMutation>(&request_bytes).expect("decode request");
        let request_record = open_signed_mutation_bound(context.as_ref(), &id, request_record)
            .expect("request signature and binding");
        let request_payload = open_public_payload(context.as_ref(), &request_record.payload)
            .expect("request roster binding");
        assert!(matches!(
            bincode::deserialize::<KvSyncMessage>(request_payload).expect("request message"),
            KvSyncMessage::StateRequest { .. }
        ));
        let authority_message = KvSyncMessage::OwnerAnnounce {
            owner,
            policy: AccessPolicy::Signed,
            policy_version: u64::MAX,
        };
        let authority_bytes = KvStoreSync::sign_public_control_message(
            &(context.clone() as SharedKvSecureContext),
            None,
            &signing,
            &id,
            peer(9),
            &authority_message,
        )
        .await
        .expect("signed authority message");
        assert!(
            KvStoreSync::open_public_control_message(
                &(context.clone() as SharedKvSecureContext),
                None,
                &id,
                &authority_bytes,
            )
            .await
            .is_none(),
            "group-signed control must never import owner policy authority"
        );
        pubsub
            .publish(
                "group/public/wiki/state-sync".to_string(),
                bytes::Bytes::from(request_bytes),
            )
            .await
            .expect("publish request");

        let authorization = context.authorization_binding().expect("roster binding");
        let pages = Arc::new(std::sync::Mutex::new(RetainedPagePool::default()));
        let image_bytes = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let response = main_probe.recv().await.expect("retained response");
                let (_, mutation) =
                    decode_delta::<SignedKvMutation>(&response.payload).expect("decode");
                assert_eq!(mutation.kind, KvMutationKind::RetainedState);
                let mutation =
                    open_signed_mutation(context.as_ref(), &id, mutation).expect("verify");
                let payload =
                    open_public_payload(context.as_ref(), &mutation.payload).expect("binding");
                if let Some(image) = assemble_retained_group_image(
                    payload,
                    &id,
                    &mutation.author_id,
                    authorization,
                    &pages,
                )
                .expect("assemble retained image")
                {
                    break image;
                }
            }
        })
        .await
        .expect("retained response timeout");
        let image: KvStore = bincode::deserialize(&image_bytes).expect("image");
        assert!(image.is_empty());
        assert!(image.has_retained_group_history());
        sync.stop().await.expect("stop");
    }

    #[test]
    fn group_signed_history_uses_actual_inner_and_outer_wire_bounds() {
        let topic = "group/public/wiki";
        let max_payload =
            crate::gossip::pubsub::max_signed_v3_payload_bytes(topic).expect("valid topic bound");
        let mutation = SignedKvMutation {
            group_id: b"group".to_vec(),
            store_id: [1; 32],
            epoch: 1,
            author_id: agent(1),
            author_pubkey: vec![0; 1952],
            algorithm: 0,
            kind: KvMutationKind::RetainedState,
            payload: Vec::new(),
            signature: vec![0; 3309],
        };
        let fixed_overhead = encode_delta(peer(1), &mutation).expect("encode").len();
        let fitting_len = max_payload.checked_sub(fixed_overhead).expect("wire room");
        let mut fitting = mutation.clone();
        fitting.payload = vec![0; fitting_len];
        assert_eq!(
            encode_delta(peer(1), &fitting)
                .expect("encode at bound")
                .len(),
            max_payload
        );
        fitting.payload.push(0);
        assert!(
            encode_delta(peer(1), &fitting)
                .expect("encode beyond bound")
                .len()
                > max_payload
        );
    }

    #[tokio::test]
    async fn authenticated_group_signed_delta_cannot_import_owner_checkpoint_authority() {
        let owner_keypair = crate::identity::AgentKeypair::generate().expect("owner keypair");
        let owner = owner_keypair.agent_id();
        let mut group = crate::groups::GroupInfo::new(
            "public".to_string(),
            String::new(),
            owner,
            "de".repeat(16),
        );
        group.migrate_from_v1();
        group.policy.confidentiality = crate::groups::GroupConfidentiality::SignedPublic;
        group.policy.read_access = crate::groups::GroupReadAccess::Public;
        let context = Arc::new(
            crate::groups::PublicGroupKvContext::from_group(&group).expect("public context"),
        );
        let id = store_id(3);
        let group_id = group.stable_group_id().as_bytes().to_vec();
        let mut source = KvStore::new_group_signed(
            id,
            "Wiki".to_string(),
            owner,
            group_id.clone(),
            context.clone(),
        )
        .expect("source");
        source
            .put(
                "remote".to_string(),
                b"replacement".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("remote put");
        let pairs = source.checkpoint_pairs();
        let checkpoint =
            crate::kv::store::make_owner_checkpoint(crate::kv::store::OwnerCheckpointParams {
                topic: "group/public/fenced",
                store_id: &id,
                secret_key: owner_keypair.secret_key(),
                public_key: owner_keypair.public_key(),
                policy: &AccessPolicy::Signed,
                policy_version: u64::MAX,
                checkpoint_seq: 1,
                content_root: crate::kv::store::content_root(&id, source.name(), &pairs),
                timestamp: 0,
            })
            .expect("genuine creator checkpoint");
        let mut hostile = source.full_delta().expect("full delta");
        hostile.owner_checkpoint = Some(checkpoint);

        let mut target = KvStore::new_group_signed(
            id,
            "Wiki".to_string(),
            owner,
            group_id.clone(),
            context.clone(),
        )
        .expect("target");
        target
            .put(
                "concurrent".to_string(),
                b"local".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("concurrent put");
        let target = Arc::new(RwLock::new(target));
        let signing = Arc::new(AuthorSigning::from_keypair(&owner_keypair).expect("signing"));
        let encoded = KvStoreSync::sign_publication(
            &target,
            &(context.clone() as SharedKvSecureContext),
            None,
            &signing,
            KvMutationKind::Delta,
            peer(1),
            bincode::serialize(&hostile).expect("delta bytes"),
        )
        .await
        .expect("authenticated group delta");

        assert!(
            !KvStoreSync::merge_group_signed_record(
                &(context as SharedKvSecureContext),
                None,
                &target,
                &id,
                peer(1),
                &encoded,
                &Arc::new(std::sync::Mutex::new(RetainedPagePool::default())),
            )
            .await,
            "non-content authority rejects the whole authenticated delta"
        );
        let target = target.read().await;
        assert!(
            target.get("concurrent").is_some(),
            "concurrent content survives"
        );
        assert!(
            target.get("remote").is_none(),
            "replacement content is not imported"
        );
        assert_eq!(target.name(), "Wiki");
        assert_eq!(target.owner(), Some(&owner));
        assert!(matches!(
            target.policy(),
            AccessPolicy::GroupSigned { group_id: current } if current == &group_id
        ));
    }

    #[tokio::test]
    async fn public_state_requests_follow_bound_current_read_policy() {
        let owner = agent(1);
        let outsider_keypair = crate::identity::AgentKeypair::generate().expect("outsider keypair");
        let outsider_signing =
            Arc::new(AuthorSigning::from_keypair(&outsider_keypair).expect("outsider signing"));
        let mut group = crate::groups::GroupInfo::new(
            "public".to_string(),
            String::new(),
            owner,
            "bc".repeat(16),
        );
        group.migrate_from_v1();
        group.policy.confidentiality = crate::groups::GroupConfidentiality::SignedPublic;
        group.policy.read_access = crate::groups::GroupReadAccess::Public;
        let context = Arc::new(
            crate::groups::PublicGroupKvContext::from_group(&group).expect("public context"),
        );
        let shared = context.clone() as SharedKvSecureContext;
        let id = store_id(5);
        let request = KvSyncMessage::StateRequest { requester: peer(9) };
        let public_bytes = KvStoreSync::sign_public_control_message(
            &shared,
            None,
            &outsider_signing,
            &id,
            peer(9),
            &request,
        )
        .await
        .expect("public read permits a nonmember request");
        assert!(
            KvStoreSync::open_public_control_message(&shared, None, &id, &public_bytes)
                .await
                .is_some()
        );

        group.policy.read_access = crate::groups::GroupReadAccess::MembersOnly;
        group.state_revision += 1;
        context.update_from_group(&group);
        assert!(
            KvStoreSync::open_public_control_message(&shared, None, &id, &public_bytes)
                .await
                .is_none(),
            "the signed payload is bound to the old read policy"
        );
        assert!(
            KvStoreSync::sign_public_control_message(
                &shared,
                None,
                &outsider_signing,
                &id,
                peer(9),
                &request,
            )
            .await
            .is_none(),
            "a local nonmember cannot request members-only history"
        );

        // Bypass the local helper to model a malicious nonmember that signs
        // a correctly bound current-policy request. Receive admission still
        // rejects the author before the responder serves history.
        let payload = bind_public_payload(
            shared.authorization_binding().expect("binding"),
            &bincode::serialize(&request).expect("request bytes"),
        );
        let record = sign_mutation_with_snapshot(
            shared.group_id(),
            shared.current_epoch(),
            &outsider_signing,
            KvMutationKind::Control,
            &id,
            &payload,
        )
        .expect("malicious signed request");
        let bytes = encode_delta(peer(9), &record).expect("wire request");
        assert!(
            KvStoreSync::open_public_control_message(&shared, None, &id, &bytes)
                .await
                .is_none(),
            "members-only receive rejects a current-policy nonmember"
        );

        group.add_member(
            hex::encode(outsider_signing.agent_id.as_bytes()),
            crate::groups::GroupRole::Member,
            Some(hex::encode(owner.as_bytes())),
            None,
        );
        group.policy.write_access = crate::groups::GroupWriteAccess::AdminOnly;
        group.state_revision += 1;
        context.update_from_group(&group);
        assert!(shared.is_authorized_reader(&outsider_signing.agent_id));
        assert!(!shared.is_authorized_writer(&outsider_signing.agent_id));
        let member_request = KvStoreSync::sign_public_control_message(
            &shared,
            None,
            &outsider_signing,
            &id,
            peer(9),
            &request,
        )
        .await
        .expect("members-only reader need not be a writer");
        assert!(
            KvStoreSync::open_public_control_message(&shared, None, &id, &member_request)
                .await
                .is_some()
        );
    }

    #[test]
    fn group_history_above_single_frame_serializes_and_pages_losslessly() {
        let owner = agent(1);
        let mut group = crate::groups::GroupInfo::new(
            "public".to_string(),
            String::new(),
            owner,
            "fa".repeat(16),
        );
        group.migrate_from_v1();
        group.policy.confidentiality = crate::groups::GroupConfidentiality::SignedPublic;
        group.policy.read_access = crate::groups::GroupReadAccess::Public;
        let ctx = Arc::new(
            crate::groups::PublicGroupKvContext::from_group(&group).expect("public context"),
        );
        let mut store = KvStore::new_group_signed(
            store_id(4),
            "Wiki".to_string(),
            owner,
            group.stable_group_id().as_bytes().to_vec(),
            ctx,
        )
        .expect("store");
        for index in 0..17 {
            store
                .put(
                    format!("large-{index}"),
                    vec![7; crate::kv::entry::MAX_INLINE_SIZE],
                    "application/octet-stream".to_string(),
                    peer(1),
                )
                .expect("large value");
        }
        let image = serialize_retained_group_image(&store).expect("bounded retained image");
        let max_wire = crate::gossip::pubsub::max_signed_v3_payload_bytes("store/public-paged")
            .expect("signed wire budget");
        assert!(
            image.len() > max_wire,
            "fixture must exceed one signed gossip frame"
        );
        let encoded_pages = crate::kv::retained_paging::split_image(&image, max_wire)
            .expect("large retained image must page");
        assert!(encoded_pages.len() > 2, "manifest plus multiple pages");

        let manifest = crate::kv::retained_paging::decode_page(&encoded_pages[0])
            .expect("decode manifest")
            .expect("framed manifest");
        let mut assembler =
            crate::kv::retained_paging::RetainedPageAssembler::from_manifest(&manifest)
                .expect("valid manifest");
        let mut reassembled = None;
        for encoded in encoded_pages.iter().skip(1) {
            let page = crate::kv::retained_paging::decode_page(encoded)
                .expect("decode page")
                .expect("framed page");
            reassembled = assembler.push(page).expect("valid page");
        }
        assert!(
            reassembled.as_deref() == Some(image.as_slice()),
            "reassembled retained image must match source bytes"
        );
    }

    #[test]
    fn treekem_retained_pages_are_isolated_by_epoch() {
        let roster_policy = [7; 32];
        assert_ne!(
            treekem_page_authorization(roster_policy, 3),
            treekem_page_authorization(roster_policy, 4),
            "identical roster policy at a later TreeKEM epoch must not share an assembler"
        );
    }

    #[tokio::test]
    async fn nonempty_group_creator_bootstraps_other_writer_history() {
        let node = make_node().await;
        let owner_keypair = crate::identity::AgentKeypair::generate().expect("owner keypair");
        let writer_keypair = crate::identity::AgentKeypair::generate().expect("writer keypair");
        let owner = owner_keypair.agent_id();
        let writer = writer_keypair.agent_id();
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let mut group = crate::groups::GroupInfo::new(
            "public".to_string(),
            String::new(),
            owner,
            "cd".repeat(16),
        );
        group.migrate_from_v1();
        group.policy.confidentiality = crate::groups::GroupConfidentiality::SignedPublic;
        group.policy.read_access = crate::groups::GroupReadAccess::Public;
        group.add_member(
            hex::encode(writer.as_bytes()),
            crate::groups::GroupRole::Member,
            Some(hex::encode(owner.as_bytes())),
            None,
        );
        let owner_context = Arc::new(
            crate::groups::PublicGroupKvContext::from_group(&group).expect("owner context"),
        );
        let writer_context = Arc::new(
            crate::groups::PublicGroupKvContext::from_group(&group).expect("writer context"),
        );
        let id = store_id(2);
        let mut stale = KvStore::new_group_signed(
            id,
            "Wiki".to_string(),
            owner,
            group.stable_group_id().as_bytes().to_vec(),
            owner_context.clone(),
        )
        .expect("stale store");
        stale
            .put(
                "base".to_string(),
                b"base".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("base");
        let mut holder = stale.clone();
        holder
            .set_secure_context(writer_context.clone())
            .expect("writer context");
        holder
            .put(
                "offline".to_string(),
                b"writer".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("offline edit");

        let mut holder_sync = KvStoreSync::new(
            holder,
            Arc::clone(&pubsub),
            "group/public/catchup".to_string(),
            peer(2),
            Some(writer),
        )
        .expect("holder sync");
        holder_sync.set_secure_context(writer_context, None);
        holder_sync.set_author_signing(
            AuthorSigning::from_keypair(&writer_keypair).expect("writer signing"),
        );
        let mut creator_sync = KvStoreSync::new(
            stale,
            Arc::clone(&pubsub),
            "group/public/catchup".to_string(),
            peer(1),
            Some(owner),
        )
        .expect("creator sync");
        creator_sync.set_secure_context(owner_context, None);
        creator_sync.set_author_signing(
            AuthorSigning::from_keypair(&owner_keypair).expect("owner signing"),
        );
        holder_sync.start().await.expect("start holder");
        creator_sync.start().await.expect("start creator");

        assert!(
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if creator_sync.read().await.get("offline").is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .is_ok(),
            "a nonempty creator must request and merge another writer's offline edit"
        );
        creator_sync.stop().await.expect("stop creator");
        holder_sync.stop().await.expect("stop holder");
    }

    #[tokio::test]
    async fn test_kv_store_sync_creation() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        let _store_for_sync = store;
    }

    #[tokio::test]
    async fn test_apply_delta_directly() {
        let owner = agent(1);
        let writer = agent(2);
        let p2 = peer(2);

        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        )
        .expect("kv store");
        store.allow_writer(writer, &owner).expect("allow");
        let store_arc = Arc::new(RwLock::new(store));

        let entry = KvEntry::new(
            "newkey".to_string(),
            b"value".to_vec(),
            "text/plain".to_string(),
        );
        let mut delta = KvStoreDelta::new(1);
        delta.added.insert("newkey".to_string(), (entry, (p2, 1)));

        {
            let mut s = store_arc.write().await;
            s.merge_delta(&delta, p2, Some(&writer)).expect("merge");
        }

        {
            let s = store_arc.read().await;
            assert!(s.get("newkey").is_some());
        }
    }

    #[tokio::test]
    async fn test_concurrent_reads() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        let store_arc = Arc::new(RwLock::new(store));

        let s1 = store_arc.read().await;
        let s2 = store_arc.read().await;

        assert_eq!(s1.name(), "Test");
        assert_eq!(s2.name(), "Test");
    }

    // ------------------------------------------------------------------
    // new() / topic() / read() / write()
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn new_sets_topic_and_yields_accessible_guards() {
        let sync = make_sync("store/A", AccessPolicy::Signed).await;

        // topic() reports exactly the topic handed to new().
        assert_eq!(sync.topic(), "store/A");

        // read() exposes the underlying store unchanged.
        {
            let s = sync.read().await;
            assert_eq!(s.name(), "Test");
            assert!(s.is_empty());
        }

        // write() returns a mutable guard; verify it is usable by merging
        // an owner-authored delta into the Signed store, then observe it via
        // read(). This also exercises the read/write guard pair end-to-end.
        let owner = agent(1);
        let entry = KvEntry::new(
            "owner-key".to_string(),
            b"v".to_vec(),
            "text/plain".to_string(),
        );
        let mut delta = KvStoreDelta::new(1);
        delta
            .added
            .insert("owner-key".to_string(), (entry, (peer(1), 1)));
        {
            let mut s = sync.write().await;
            s.merge_delta(&delta, peer(1), Some(&owner))
                .expect("owner merge");
        }

        let s = sync.read().await;
        assert!(s.get("owner-key").is_some(), "owner write must be visible");
    }

    // ------------------------------------------------------------------
    // state_sync_topic() (private helper exercised from the test module)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn state_sync_topic_appends_side_channel_suffix() {
        let sync = make_sync("store/B", AccessPolicy::Signed).await;
        // The private helper forms the side channel by appending the suffix.
        assert_eq!(sync.state_sync_topic(), "store/B/state-sync");

        // Suffix is appended exactly once, regardless of slashes in topic.
        let sync2 = make_sync("store/B/nested", AccessPolicy::Signed).await;
        assert_eq!(sync2.state_sync_topic(), "store/B/nested/state-sync");
    }

    // ------------------------------------------------------------------
    // publish_delta(): wire round-trip observed by a subscriber
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn publish_delta_delivers_encoded_pair_to_subscriber() {
        let (sync, pubsub) = make_sync_with_pubsub("store/C", AccessPolicy::Signed).await;

        // Subscribe to the main topic BEFORE publishing so we observe the
        // exact bytes KvStoreSync places on the wire.
        let mut sub = pubsub.subscribe("store/C".to_string()).await;

        let sender = peer(7);
        let entry = KvEntry::new(
            "remote".to_string(),
            b"payload".to_vec(),
            "application/octet-stream".to_string(),
        );
        let mut delta = KvStoreDelta::new(9);
        delta
            .added
            .insert("remote".to_string(), (entry, (sender, 3)));

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
            decode_delta::<KvStoreDelta>(&msg.payload).expect("wire decode");
        assert_eq!(observed_sender, sender);
        assert_eq!(observed_delta.version, 9);
        assert!(observed_delta.added.contains_key("remote"));
        assert_eq!(msg.topic, "store/C");
        // Sanity: the same delta also round-trips through encode_delta alone.
        let reencoded = encode_delta(sender, &observed_delta).expect("re-encode");
        let (s2, d2) = decode_delta::<KvStoreDelta>(&reencoded).expect("re-decode");
        assert_eq!(s2, sender);
        assert_eq!(d2.version, 9);
    }

    // ------------------------------------------------------------------
    // start_with_spawner(): subscribes + returns Ok with a drop-spawner
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn start_with_spawner_subscribes_and_returns_ok() {
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
        // `start_with_spawner(tokio::spawn)` and verifies the key lands.
        let sync = make_sync("store/D", AccessPolicy::Signed).await;
        sync.start_with_spawner(|_fut| {
            // intentionally drop the future
        })
        .await
        .expect("start_with_spawner");
    }

    // ------------------------------------------------------------------
    // #765 r4: TrackedLoopFuture — exit recorded only after inner
    // destruction (structural, inert control)
    // ------------------------------------------------------------------

    /// Inert inner future whose `Drop` proves it was destroyed while the
    /// tracker had NOT yet recorded this wrapper's exit.
    struct InnerProbe {
        tracker: Arc<LoopExitTracker>,
        dropped: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl Future for InnerProbe {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            std::task::Poll::Pending
        }
    }

    impl Drop for InnerProbe {
        fn drop(&mut self) {
            assert_eq!(
                self.tracker
                    .exited
                    .load(std::sync::atomic::Ordering::SeqCst),
                0,
                "exit recorded before the inner future was destroyed"
            );
            self.dropped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("inner");
        }
    }

    fn inner_probe(
        tracker: &Arc<LoopExitTracker>,
        dropped: &Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) -> InnerProbe {
        InnerProbe {
            tracker: Arc::clone(tracker),
            dropped: Arc::clone(dropped),
        }
    }

    #[tokio::test]
    async fn tracked_loop_records_exit_only_after_inner_future_destruction() {
        // Case 1 — dropped WITHOUT EVER BEING POLLED: the r3 guard was
        // constructed inside the async body and never existed here, so an
        // unpolled drop recorded nothing. The wrapper exists from
        // construction and must record exactly one exit, strictly after
        // the inner future is destroyed (InnerProbe::drop asserts the
        // not-yet-recorded half of that ordering).
        let tracker = Arc::new(LoopExitTracker::default());
        let dropped = Arc::new(std::sync::Mutex::new(Vec::new()));
        let wrapper =
            TrackedLoopFuture::wrap(Arc::clone(&tracker), inner_probe(&tracker, &dropped));
        drop(wrapper);
        assert_eq!(
            tracker.exited.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a never-polled dropped wrapper records exactly one exit"
        );
        assert_eq!(
            *dropped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["inner"],
            "the inner future was destroyed exactly once"
        );

        // Case 2 — polled once (Pending), then dropped: same ordering.
        let tracker = Arc::new(LoopExitTracker::default());
        let dropped = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut wrapper = Box::pin(TrackedLoopFuture::wrap(
            Arc::clone(&tracker),
            inner_probe(&tracker, &dropped),
        ));
        assert!(
            futures::poll!(&mut wrapper).is_pending(),
            "the probe future never completes"
        );
        drop(wrapper);
        assert_eq!(
            tracker.exited.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a polled-then-dropped wrapper records exactly one exit"
        );
        assert_eq!(
            *dropped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["inner"]
        );

        // Case 3 — inner completes: the wrapper returns Ready, and the
        // exit is still recorded exactly once on drop.
        let tracker = Arc::new(LoopExitTracker::default());
        let mut wrapper = Box::pin(TrackedLoopFuture::wrap(
            Arc::clone(&tracker),
            futures::future::ready(()),
        ));
        assert!(futures::poll!(&mut wrapper).is_ready());
        drop(wrapper);
        assert_eq!(
            tracker.exited.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a completed wrapper records exactly one exit"
        );
    }

    // ------------------------------------------------------------------
    // start(): default spawner merges a remotely-published delta
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn start_default_spawner_merges_remote_delta() {
        // End-to-end exercise of the delta-merge listener: a delta published
        // on the topic is received by the background loop spawned by start()
        // and merged into the local store. The publish goes out through a
        // SigningContext for the store owner so the delivered v2 message
        // carries a verified sender — the only writer a Signed store accepts.
        // (#341 Phase A: anonymous deltas apply nothing under every policy;
        // the reserved Encrypted policy is no longer an unsigned-publish
        // escape hatch.)
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        let sync = KvStoreSync::new(store, pubsub, "store/E".to_string(), peer(1), Some(owner))
            .expect("kv sync");

        sync.start().await.expect("start");

        // Let the spawned subscribe-forwarder register before we publish.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let entry = KvEntry::new(
            "merged-key".to_string(),
            b"hello".to_vec(),
            "text/plain".to_string(),
        );
        let mut delta = KvStoreDelta::new(1);
        delta
            .added
            .insert("merged-key".to_string(), (entry, (peer(2), 1)));
        sync.publish_delta(peer(2), delta).await.expect("publish");

        // The merge is asynchronous; poll the store until it lands.
        let landed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let present = {
                    let s = sync.read().await;
                    s.get("merged-key").is_some()
                };
                if present {
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
    }

    // ------------------------------------------------------------------
    // #757: a retired sync must not merge or persist a queued delta
    // ------------------------------------------------------------------

    type HeldLoops =
        Arc<std::sync::Mutex<Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>>>;

    /// One #757 scenario. The background loops are HELD (never polled) by a
    /// gated spawner while a valid delta is published and observed to reach
    /// the listener's channel, so when the loops are finally driven the
    /// queued delta and (if `retire`) the cancellation are ready in the same
    /// poll — the exact ordering an unbiased `select!` resolved at random.
    /// Returns `(key merged, snapshot bytes changed)`.
    /// A persistent owner-signed sync with a baseline snapshot on disk.
    struct RetireFixture {
        sync: KvStoreSync,
        pubsub: Arc<PubSubManager>,
        _dir: tempfile::TempDir,
        snapshot: PathBuf,
        before: Vec<u8>,
    }

    async fn retire_fixture(topic: &str) -> RetireFixture {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        let sync = KvStoreSync::new(
            store,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner),
        )
        .expect("kv sync");
        let dir = tempfile::tempdir().expect("tempdir");
        let snapshot = dir.path().join("store.bin");
        sync.set_persist_path(snapshot.clone());
        sync.persist().await.expect("baseline snapshot");
        let before = std::fs::read(&snapshot).expect("baseline bytes");
        RetireFixture {
            sync,
            pubsub,
            _dir: dir,
            snapshot,
            before,
        }
    }

    #[tokio::test]
    async fn superseded_local_persist_is_typed_and_never_reports_durable() {
        let fx = retire_fixture("store/760-stale-local").await;
        let owner = fx.sync.local_agent_id.expect("owner identity");
        fx.sync
            .authorize_local_write(&owner)
            .await
            .expect("local authorization passes before mutation");
        fx.sync
            .write()
            .await
            .put(
                "stale-local".to_string(),
                b"must-not-land".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("in-memory mutation");

        // A direct replacement sync retains the new path owner even though
        // no lifecycle handle owns it. This is the low-level call path that
        // motivated PersistOwner retaining the exact registry entry.
        let replacement_store = KvStore::new(
            store_id(1),
            "replacement".into(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("replacement store");
        let replacement = KvStoreSync::new(
            replacement_store,
            Arc::clone(&fx.pubsub),
            "store/760-replacement".into(),
            peer(3),
            Some(owner),
        )
        .expect("replacement sync");
        replacement.set_persist_path(fx.snapshot.clone());

        let error = fx
            .sync
            .persist()
            .await
            .expect_err("old owner must fail closed");
        assert!(matches!(error, KvError::SnapshotSuperseded));
        assert!(fx.sync.durability_degraded());
        assert_eq!(
            std::fs::read(&fx.snapshot).expect("snapshot remains readable"),
            fx.before,
            "superseded caller must not touch the snapshot or report success"
        );
    }

    #[tokio::test]
    async fn superseded_equal_version_persist_is_typed_and_keeps_degraded() {
        // WHY (#760): the version-gated `Current` fast path must be
        // ownership-fenced like the write path. A stale handle whose
        // durable version already matches the store (no mutation since
        // its own last successful persist) must not report durable — or
        // clear the degraded flag — once a successor has armed the same
        // canonical path.
        let fx = retire_fixture("store/760-stale-equal").await;
        let owner = fx.sync.local_agent_id.expect("owner identity");
        let ctx = fx.sync.persist_ctx().expect("persist armed");
        let set_degraded = |v: bool| ctx.degraded.store(v, std::sync::atomic::Ordering::Relaxed);

        // Transient snapshot failure at the unchanged version: degraded,
        // but durable bytes and store version are untouched.
        set_degraded(true);

        // Pre-arm control: while this generation owns the path, the
        // residual no-op is legitimately `Current` — it succeeds,
        // repairs the flag, and does not rewrite the file.
        fx.sync
            .persist()
            .await
            .expect("pre-arm unchanged-version persist is current");
        assert!(
            !fx.sync.durability_degraded(),
            "legitimately current persist clears the degraded flag"
        );
        assert_eq!(
            std::fs::read(&fx.snapshot).expect("snapshot remains readable"),
            fx.before,
            "current fast path must not rewrite the snapshot"
        );

        // Re-degrade, then arm a replacement owner on the exact same path.
        set_degraded(true);
        let replacement_store = KvStore::new(
            store_id(1),
            "replacement".into(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("replacement store");
        let replacement = KvStoreSync::new(
            replacement_store,
            Arc::clone(&fx.pubsub),
            "store/760-replacement-equal".into(),
            peer(4),
            Some(owner),
        )
        .expect("replacement sync");
        replacement.set_persist_path(fx.snapshot.clone());

        // The discriminator: unchanged version, stale generation.
        let error = fx
            .sync
            .persist()
            .await
            .expect_err("stale equal-version persist must fail closed");
        assert!(matches!(error, KvError::SnapshotSuperseded));
        assert!(
            fx.sync.durability_degraded(),
            "superseded must not clear the degraded flag"
        );
        assert_eq!(
            std::fs::read(&fx.snapshot).expect("snapshot remains readable"),
            fx.before,
            "superseded equal-version persist must not touch the file"
        );

        // Repeat: the failure is stable — never a degraded reset.
        let again = fx
            .sync
            .persist()
            .await
            .expect_err("repeat stays typed-superseded");
        assert!(matches!(again, KvError::SnapshotSuperseded));
        assert!(fx.sync.durability_degraded());
        assert_eq!(
            std::fs::read(&fx.snapshot).expect("snapshot remains readable"),
            fx.before
        );
    }

    #[tokio::test]
    async fn reopen_waits_for_admitted_delta_then_preserves_it_with_new_write() {
        let fx = retire_fixture("store/760-admitted-reopen").await;
        let lease = crate::kv::snapshot_fence::claim_open(&fx.snapshot).await;
        assert!(lease.commit());
        let loops = start_joinable(&fx.sync).await;
        let ctx = fx.sync.persist_ctx().expect("persist armed");
        let gate = ctx.gate.lock().await;

        publish_late_delta(&fx).await;
        tokio::time::timeout(
            Duration::from_secs(10),
            fx.sync.wait_receive_merged_for_test(),
        )
        .await
        .expect("A merged before its persist");

        let retirement = lease.begin_retire().expect("old handle marks retirement");
        let mut drain = Box::pin(fx.sync.cancel_sync_and_drain());
        assert!(futures::poll!(drain.as_mut()).is_pending());
        let mut reopen = Box::pin(crate::kv::snapshot_fence::claim_open(&fx.snapshot));
        assert!(
            futures::poll!(reopen.as_mut()).is_pending(),
            "reopen must wait while A's admitted persist is outstanding"
        );

        drop(gate);
        tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .expect("old receive section drains");
        retirement.complete();
        let successor = tokio::time::timeout(Duration::from_secs(10), reopen)
            .await
            .expect("reopen proceeds after drain");

        let restored = load_snapshot(&fx.snapshot)
            .expect("snapshot decodes")
            .expect("snapshot exists");
        assert!(restored.get("late-key").is_some(), "raw snapshot retains A");
        let successor_sync = KvStoreSync::new(
            restored,
            Arc::clone(&fx.pubsub),
            "store/760-successor".into(),
            peer(3),
            fx.sync.local_agent_id,
        )
        .expect("successor sync");
        successor_sync.set_persist_path(fx.snapshot.clone());
        successor_sync
            .write()
            .await
            .put(
                "successor-x".into(),
                b"x".to_vec(),
                "text/plain".into(),
                peer(3),
            )
            .expect("successor writes X");
        successor_sync.persist().await.expect("X persists");
        assert!(successor.commit());

        let raw = load_snapshot(&fx.snapshot)
            .expect("final snapshot decodes")
            .expect("final snapshot exists");
        assert!(raw.get("late-key").is_some(), "A survives reopen");
        assert!(raw.get("successor-x").is_some(), "X lands after reopen");
        join_loops(loops).await;
    }

    #[tokio::test]
    async fn trampled_predecessor_open_cannot_suppress_or_clobber_admitted_delta() {
        let fx = retire_fixture("store/760-trampled-open").await;
        let old = crate::kv::snapshot_fence::claim_open(&fx.snapshot).await;
        assert!(old.commit());
        // Selector: B claims while old is Active, before retirement begins.
        let stale_open = crate::kv::snapshot_fence::claim_open(&fx.snapshot).await;
        let loops = start_joinable(&fx.sync).await;
        let ctx = fx.sync.persist_ctx().expect("old persist armed");
        let gate = ctx.gate.lock().await;
        publish_late_delta(&fx).await;
        tokio::time::timeout(
            Duration::from_secs(10),
            fx.sync.wait_receive_merged_for_test(),
        )
        .await
        .expect("A is admitted and parked before persist");

        // B loaded the pre-A snapshot. If it can arm, it can either suppress
        // A or later overwrite A with this stale image.
        let stale_image = load_snapshot(&fx.snapshot)
            .expect("baseline snapshot decodes")
            .expect("baseline snapshot exists");
        assert!(stale_image.get("late-key").is_none());
        let stale_sync = KvStoreSync::new(
            stale_image,
            Arc::clone(&fx.pubsub),
            "store/760-trampled-successor".into(),
            peer(3),
            fx.sync.local_agent_id,
        )
        .expect("stale successor sync");

        let retirement = old.begin_retire().expect("predecessor tramples B");
        let mut drain = Box::pin(fx.sync.cancel_sync_and_drain());
        assert!(futures::poll!(drain.as_mut()).is_pending());
        let error = stale_sync
            .set_persist_path_for_open(&stale_open)
            .expect_err("trampled B cannot arm or write its stale image");
        assert!(matches!(error, KvError::SnapshotSuperseded));

        drop(gate);
        tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .expect("old admitted A drains");
        retirement.complete();
        assert!(
            !stale_open.commit(),
            "trampled B cannot become the active successor"
        );
        let after_a = load_snapshot(&fx.snapshot)
            .expect("A snapshot decodes")
            .expect("A snapshot exists");
        assert!(after_a.get("late-key").is_some(), "A was not suppressed");

        // Positive control: a retry claimed from Idle can arm, preserve A,
        // and persist X. This also proves the failed B left no ownership.
        let retry = crate::kv::snapshot_fence::claim_open(&fx.snapshot).await;
        let restored = load_snapshot(&fx.snapshot)
            .expect("retry snapshot decodes")
            .expect("retry snapshot exists");
        let retry_sync = KvStoreSync::new(
            restored,
            Arc::clone(&fx.pubsub),
            "store/760-retry".into(),
            peer(4),
            fx.sync.local_agent_id,
        )
        .expect("retry sync");
        retry_sync
            .set_persist_path_for_open(&retry)
            .expect("fresh retry owns persistence");
        retry_sync
            .write()
            .await
            .put(
                "successor-x".into(),
                b"x".to_vec(),
                "text/plain".into(),
                peer(4),
            )
            .expect("retry writes X");
        retry_sync.persist().await.expect("retry persists A plus X");
        assert!(retry.commit());
        let final_image = load_snapshot(&fx.snapshot)
            .expect("final snapshot decodes")
            .expect("final snapshot exists");
        assert!(final_image.get("late-key").is_some());
        assert!(final_image.get("successor-x").is_some());
        join_loops(loops).await;
    }

    /// Publish one admissible delta and wait (barrier, not oracle) until it
    /// sits in the listener's channel.
    async fn publish_late_delta(fx: &RetireFixture) {
        let entry = KvEntry::new(
            "late-key".to_string(),
            b"late".to_vec(),
            "text/plain".to_string(),
        );
        let mut delta = KvStoreDelta::new(1);
        delta
            .added
            .insert("late-key".to_string(), (entry, (peer(2), 1)));
        let delivered_before = fx.pubsub.stats().delivered_to_subscriber;
        fx.sync
            .publish_delta(peer(2), delta)
            .await
            .expect("publish");
        tokio::time::timeout(Duration::from_secs(10), async {
            while fx.pubsub.stats().delivered_to_subscriber == delivered_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("delta must reach the listener's channel");
    }

    /// Start the loops on the runtime, keeping their join handles so a test
    /// can prove they have fully exited.
    async fn start_joinable(sync: &KvStoreSync) -> Vec<tokio::task::JoinHandle<()>> {
        let handles = Arc::new(std::sync::Mutex::new(Vec::new()));
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

    async fn join_loops(loops: Vec<tokio::task::JoinHandle<()>>) {
        for handle in loops {
            tokio::time::timeout(Duration::from_secs(10), handle)
                .await
                .expect("a cancelled loop must exit")
                .expect("loop must not panic");
        }
    }

    async fn queued_delta_outcome(topic: &str, retire: bool) -> (bool, bool) {
        let fx = retire_fixture(topic).await;
        let (sync, snapshot, before) = (&fx.sync, &fx.snapshot, &fx.before);

        let held: HeldLoops = Arc::new(std::sync::Mutex::new(Vec::new()));
        let gate = Arc::clone(&held);
        sync.start_with_spawner(move |fut| {
            gate.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fut);
        })
        .await
        .expect("start_with_spawner");

        publish_late_delta(&fx).await;

        if retire {
            sync.cancel_sync();
        }
        let loops = std::mem::take(
            &mut *held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if retire {
            // Cancelled loops must run to completion on their own.
            for fut in loops {
                tokio::time::timeout(Duration::from_secs(10), fut)
                    .await
                    .expect("a cancelled loop must exit");
            }
        } else {
            for fut in loops {
                tokio::spawn(fut);
            }
            tokio::time::timeout(Duration::from_secs(10), async {
                while sync.read().await.get("late-key").is_none()
                    || std::fs::read(snapshot).expect("snapshot bytes") == *before
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("control: a live listener merges and persists the queued delta");
        }
        let merged = sync.read().await.get("late-key").is_some();
        let persisted = std::fs::read(snapshot).expect("snapshot bytes") != *before;
        sync.cancel_sync();
        (merged, persisted)
    }

    #[tokio::test]
    async fn retired_sync_never_merges_or_persists_a_queued_delta() {
        // Control: the identical queued delta IS merged and persisted by a
        // live listener, so the retired assertions below cannot pass merely
        // because the delta was undeliverable or inadmissible.
        assert_eq!(
            queued_delta_outcome("store/757-live", false).await,
            (true, true)
        );
        // WHY (#757): retire()/cancel_sync() is the fence callers rely on
        // when a group store goes away or its snapshot path is being
        // replaced. A listener that still takes a queued delta after the
        // fence mutates a retired replica and writes its snapshot behind the
        // caller's back (in CI: a rename onto a directory, latching the
        // store durability-degraded). The unbiased select lost this race
        // about half the time, so repeat: 16 clean runs cannot happen by
        // luck (p = 2^-16) if the select is ever made unbiased again.
        for round in 0..16 {
            assert_eq!(
                queued_delta_outcome(&format!("store/757-retired-{round}"), true).await,
                (false, false),
                "round {round}: retired sync merged/persisted a queued delta"
            );
        }
    }

    #[tokio::test]
    async fn delta_pulled_before_cancel_is_dropped_under_the_lifecycle_lock() {
        // WHY (#757 r2): cancel-first selects only cover a delta still in the
        // channel. A listener that already PULLED the delta when the cancel
        // lands must not merge it either, and a bare flag check cannot fence
        // that across threads — the check has to sit under the lifecycle
        // lock the draining retire takes. Holding that lock here parks the
        // listener after its recv and before its check, then cancels.
        // (With the loops held and hand-polled, the queued message cannot be
        // dropped by the cancel-first select instead: the cancel is set only
        // after the listener has consumed it.)
        let fx = retire_fixture("store/757-pulled").await;
        let held: HeldLoops = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&held);
        fx.sync
            .start_with_spawner(move |fut| {
                sink.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(fut);
            })
            .await
            .expect("start_with_spawner");
        let parked = fx.sync.lifecycle.clone().lock_owned().await;
        publish_late_delta(&fx).await;
        let mut loops = std::mem::take(
            &mut *held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        // Barrier by construction: the delta is in the channel and no cancel
        // is set, so ONE poll takes the listener through `recv` and leaves
        // it Pending on the lifecycle lock held above.
        for fut in &mut loops {
            assert!(futures::poll!(fut.as_mut()).is_pending());
        }
        fx.sync.cancel_sync();
        drop(parked);
        for fut in loops {
            tokio::time::timeout(Duration::from_secs(10), fut)
                .await
                .expect("a cancelled loop must exit");
        }
        assert!(
            fx.sync.read().await.get("late-key").is_none(),
            "a delta pulled before the cancel was merged after it"
        );
        assert_eq!(
            std::fs::read(&fx.snapshot).expect("snapshot bytes"),
            fx.before,
            "a retired listener wrote the snapshot"
        );
    }

    #[tokio::test]
    async fn draining_retire_waits_for_an_in_flight_persist() {
        // WHY (#757 r2): a merge admitted before the cancel still owes its
        // snapshot write, and that write can start arbitrarily late (here:
        // parked on the persist gate). "Retired" must therefore mean the
        // write has FINISHED, or a caller that replaces the snapshot path
        // next gets a rename onto its directory and a store latched
        // durability-degraded — the CI failure this issue is about.
        let fx = retire_fixture("store/757-inflight").await;
        let loops = start_joinable(&fx.sync).await;
        let ctx = fx.sync.persist_ctx().expect("persist armed");
        let gate = ctx.gate.lock().await;
        publish_late_delta(&fx).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while fx.sync.read().await.get("late-key").is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("listener must merge the delta");
        // Merged in memory, snapshot write parked on the gate: in flight.
        let mut drain = Box::pin(fx.sync.cancel_sync_and_drain());
        for _ in 0..64 {
            assert!(
                futures::poll!(drain.as_mut()).is_pending(),
                "drain completed while a snapshot write was still in flight"
            );
            tokio::task::yield_now().await;
        }
        assert_eq!(
            std::fs::read(&fx.snapshot).expect("snapshot bytes"),
            fx.before
        );
        drop(gate);
        tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .expect("drain must complete once the write finishes");
        // No yield since the drain returned: the write is already on disk.
        assert_ne!(
            std::fs::read(&fx.snapshot).expect("snapshot bytes"),
            fx.before,
            "drain returned before the in-flight snapshot write landed"
        );
        // The caller now owns the path. Block it the way the stores
        // legacy-import test does; nothing may touch it again.
        std::fs::remove_file(&fx.snapshot).expect("remove snapshot");
        std::fs::create_dir(&fx.snapshot).expect("block snapshot path");
        join_loops(loops).await;
        assert!(
            !fx.sync.durability_degraded(),
            "a retired loop wrote to the snapshot path after the drain"
        );
        assert_eq!(
            std::fs::read_dir(&fx.snapshot)
                .expect("still a directory")
                .count(),
            0
        );
    }

    // ------------------------------------------------------------------
    // #341 Phase B: encrypted store sync (sealed publish/receive paths)
    // ------------------------------------------------------------------

    use crate::groups::{GroupInfo, GssKvSecureContext};
    use crate::identity::AgentKeypair;
    use crate::kv::encrypted::{AuthorSigning, KvSecureContext};

    /// Build a minimal MlsEncrypted group whose active members are `members`
    /// (member[0] is the creator) with a rotated shared secret (epoch >= 1),
    /// plus one INDEPENDENT context per member — the same shape as two
    /// daemons each holding their own snapshot of the same group.
    fn encrypted_group(members: &[AgentId]) -> (GroupInfo, Vec<Arc<GssKvSecureContext>>, Vec<u8>) {
        let mut info = GroupInfo::new(
            "kv-group".to_string(),
            String::new(),
            members[0],
            "ab".repeat(16),
        );
        info.migrate_from_v1();
        for m in &members[1..] {
            info.members_v2.insert(
                hex::encode(m.as_bytes()),
                crate::groups::GroupMember::new_member(
                    hex::encode(m.as_bytes()),
                    None,
                    Some(hex::encode(members[0].as_bytes())),
                    0,
                ),
            );
        }
        let _ = info.rotate_shared_secret();
        let group_id = info.stable_group_id().as_bytes().to_vec();
        let ctxs = members
            .iter()
            .map(|_| {
                Arc::new(
                    GssKvSecureContext::from_group(&info).expect("group holds a shared secret"),
                )
            })
            .collect();
        (info, ctxs, group_id)
    }

    /// Build an encrypted-store sync bound to `ctx`, signed as `local_kp`.
    #[allow(clippy::too_many_arguments)]
    async fn make_encrypted_sync(
        topic: &str,
        pubsub: Arc<PubSubManager>,
        id_byte: u8,
        creator: AgentId,
        local: AgentId,
        local_kp: &AgentKeypair,
        ctx: Arc<GssKvSecureContext>,
        group_id: Vec<u8>,
        gossip_peer: PeerId,
    ) -> KvStoreSync {
        let store = KvStore::new_encrypted(
            store_id(id_byte),
            "Enc".to_string(),
            creator,
            group_id,
            ctx.clone() as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        let mut sync = KvStoreSync::new(store, pubsub, topic.to_string(), gossip_peer, Some(local))
            .expect("kv sync");
        sync.set_secure_context(ctx, None);
        sync.set_author_signing(AuthorSigning::from_keypair(local_kp).expect("author signing"));
        sync
    }

    #[tokio::test]
    async fn encrypted_controls_separate_reader_requests_from_writer_evidence() {
        let owner_keypair = AgentKeypair::generate().expect("owner keypair");
        let reader_keypair = AgentKeypair::generate().expect("reader keypair");
        let owner = owner_keypair.agent_id();
        let reader = reader_keypair.agent_id();
        let (mut info, contexts, _) = encrypted_group(&[owner, reader]);
        info.policy.write_access = crate::groups::GroupWriteAccess::AdminOnly;
        for context in &contexts {
            context.update_from_group(&info);
        }
        let context = contexts[1].clone() as SharedKvSecureContext;
        let signing = Arc::new(AuthorSigning::from_keypair(&reader_keypair).expect("signing"));
        let id = store_id(12);
        let request = KvSyncMessage::StateRequest { requester: peer(2) };
        let request_bytes =
            KvStoreSync::seal_control_message(&context, None, &signing, &id, peer(2), &request)
                .await
                .expect("active nonwriter may request encrypted state");
        assert!(
            KvStoreSync::open_control_message(&context, None, &id, &request_bytes)
                .await
                .is_some()
        );

        let evidence = KvSyncMessage::StateServedV2 {
            responder: peer(2),
            digest: [0; 32],
            entry_count: 0,
        };
        assert!(
            KvStoreSync::seal_control_message(&context, None, &signing, &id, peer(2), &evidence,)
                .await
                .is_none(),
            "nonwriter cannot endorse retained state"
        );
        let owner_announce = KvSyncMessage::OwnerAnnounce {
            owner,
            policy: AccessPolicy::Signed,
            policy_version: u64::MAX,
        };
        assert!(
            KvStoreSync::seal_control_message(
                &context,
                None,
                &signing,
                &id,
                peer(2),
                &owner_announce,
            )
            .await
            .is_none(),
            "group stores never publish legacy owner authority"
        );

        // A current member can bypass the local semantic helper and produce
        // a cryptographically valid Control record. Receive admission still
        // rejects writer evidence and legacy authority by decoded kind.
        for message in [evidence, owner_announce] {
            let payload = bincode::serialize(&message).expect("control payload");
            let record = context
                .seal_authorized(&signing, KvMutationKind::Control, &id, &payload)
                .expect("valid member control envelope");
            let bytes = encode_delta(peer(2), &record).expect("control wire");
            assert!(
                KvStoreSync::open_control_message(&context, None, &id, &bytes)
                    .await
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn encrypted_responder_serves_tombstone_only_retained_history() {
        let node = make_node().await;
        let keypair = AgentKeypair::generate().expect("keypair");
        let owner = keypair.agent_id();
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let (_, contexts, group_id) = encrypted_group(&[owner]);
        let context = contexts[0].clone();
        let id = store_id(13);
        let mut store = KvStore::new_encrypted(
            id,
            "Home".to_string(),
            owner,
            group_id,
            context.clone() as SharedKvSecureContext,
        )
        .expect("encrypted store");
        store
            .put(
                "gone".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        store.remove("gone").expect("remove");
        assert!(store.is_empty());
        assert!(store.has_retained_group_history());

        let mut sync = KvStoreSync::new(
            store,
            Arc::clone(&pubsub),
            "group/private/home".to_string(),
            peer(1),
            Some(owner),
        )
        .expect("sync");
        sync.set_secure_context(context.clone(), None);
        let signing = Arc::new(AuthorSigning::from_keypair(&keypair).expect("signing"));
        sync.set_author_signing((*signing).clone());
        let mut main_probe = pubsub.subscribe("group/private/home".to_string()).await;
        sync.start().await.expect("start");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let request = KvSyncMessage::StateRequest { requester: peer(9) };
        let request_bytes = KvStoreSync::seal_control_message(
            &(context.clone() as SharedKvSecureContext),
            None,
            &signing,
            &id,
            peer(9),
            &request,
        )
        .await
        .expect("sealed request");
        pubsub
            .publish(
                "group/private/home/state-sync".to_string(),
                bytes::Bytes::from(request_bytes),
            )
            .await
            .expect("publish request");

        let mut hasher = blake3::Hasher::new();
        hasher.update(&context.group_id());
        hasher.update(&context.current_epoch().to_le_bytes());
        let authorization = *hasher.finalize().as_bytes();
        let pages = Arc::new(std::sync::Mutex::new(RetainedPagePool::default()));
        let image_bytes = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let response = main_probe.recv().await.expect("retained response");
                let (_, record) = decode_delta::<EncryptedKvStoreRecordV1>(&response.payload)
                    .expect("decode envelope");
                let mutation =
                    open_mutation(context.as_ref(), &id, &record).expect("open response");
                assert_eq!(mutation.kind, KvMutationKind::RetainedState);
                if let Some(image) = assemble_retained_group_image(
                    &mutation.payload,
                    &id,
                    &mutation.author_id,
                    authorization,
                    &pages,
                )
                .expect("assemble retained image")
                {
                    break image;
                }
            }
        })
        .await
        .expect("retained response timeout");
        let image: KvStore = bincode::deserialize(&image_bytes).expect("retained image");
        assert!(image.is_empty());
        assert!(image.has_retained_group_history());
        sync.stop().await.expect("stop");
    }

    async fn wait_for_key(sync: &KvStoreSync, key: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let present = { sync.read().await.get(key).is_some() };
                if present {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok()
    }

    /// A fresh, authorized sealed publication must pass through the same
    /// subscription and serial listener as the adversarial message. Never put
    /// the marker locally: observing it must prove the listener merged it.
    async fn encrypted_listener_barrier(sync: &KvStoreSync, key: &str, seq: u64) {
        assert!(sync.read().await.get(key).is_none(), "marker must be fresh");
        let entry = KvEntry::new(
            key.to_string(),
            b"barrier".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put(key.to_string(), entry, (peer(99), seq), seq);
        sync.publish_delta(peer(99), delta)
            .await
            .expect("publish authorized sealed barrier");
        assert!(
            wait_for_key(sync, key).await,
            "encrypted listener did not consume sealed barrier {key}"
        );
    }

    #[tokio::test]
    async fn encrypted_publication_rejects_removed_signer_before_encoding() {
        // The public sync seam must fail closed even when a removed signer
        // still has the old usable group secret. This avoids emitting an
        // authenticated record that every receiver would have to discard.
        let kp_a = AgentKeypair::generate().expect("kp a");
        let kp_b = AgentKeypair::generate().expect("kp b");
        let (a, b) = (kp_a.agent_id(), kp_b.agent_id());
        let (mut info, mut ctxs, group_id) = encrypted_group(&[a, b]);
        let ctx_a = ctxs.remove(0);
        info.remove_member(&hex::encode(a.as_bytes()), Some(hex::encode(b.as_bytes())));
        ctx_a.update_from_group(&info);
        assert!(!ctx_a.is_active_member(&a));

        let store = KvStore::new_encrypted(
            store_id(9),
            "Enc".to_string(),
            a,
            group_id,
            ctx_a.clone() as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        let store = Arc::new(RwLock::new(store));
        let signing = Arc::new(AuthorSigning::from_keypair(&kp_a).expect("author signing"));
        let err = KvStoreSync::seal_publication(
            &store,
            &(ctx_a.clone() as SharedKvSecureContext),
            None,
            &signing,
            KvMutationKind::Delta,
            peer(1),
            &KvStoreDelta::new(1),
        )
        .await
        .expect_err("removed signer must not produce a sealed payload");
        assert!(
            matches!(err, KvError::SecureRecord(message) if message.contains("current member/write policy"))
        );
    }

    #[tokio::test]
    async fn encrypted_publication_rechecks_membership_after_refresh() {
        // The refresh hook is authoritative and runs before sealing. This
        // control makes the signer active in the initial context, then
        // removes it only from the state returned by that hook.
        let kp_a = AgentKeypair::generate().expect("kp a");
        let kp_b = AgentKeypair::generate().expect("kp b");
        let (a, b) = (kp_a.agent_id(), kp_b.agent_id());
        let (info, mut ctxs, group_id) = encrypted_group(&[a, b]);
        let ctx_a = ctxs.remove(0);
        assert!(ctx_a.is_active_member(&a));
        let mut refreshed_info = info.clone();
        refreshed_info.remove_member(&hex::encode(a.as_bytes()), Some(hex::encode(b.as_bytes())));
        let refreshed_info = Arc::new(refreshed_info);
        let refresh_ctx = Arc::clone(&ctx_a);
        let refresh: SecureRefreshFn = Arc::new(move || {
            let ctx = Arc::clone(&refresh_ctx);
            let info = Arc::clone(&refreshed_info);
            Box::pin(async move {
                ctx.update_from_group(&info);
            })
        });

        let store = KvStore::new_encrypted(
            store_id(12),
            "Enc".to_string(),
            a,
            group_id,
            ctx_a.clone() as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        let store = Arc::new(RwLock::new(store));
        let signing = Arc::new(AuthorSigning::from_keypair(&kp_a).expect("author signing"));
        let shared: SharedKvSecureContext = ctx_a;
        let err = KvStoreSync::seal_publication(
            &store,
            &shared,
            Some(&refresh),
            &signing,
            KvMutationKind::Delta,
            peer(1),
            &KvStoreDelta::new(1),
        )
        .await
        .expect_err("refresh-removal must block the publication");
        assert!(
            matches!(err, KvError::SecureRecord(message) if message.contains("current member/write policy"))
        );
        assert!(!shared.is_active_member(&a));
    }

    #[tokio::test]
    async fn encrypted_publication_rejects_removal_during_store_wait() {
        // The publication reaches its store read after the refresh and must
        // not carry the old membership decision across that await.  Rotate
        // the real GSS snapshot while the read is held; atomic admission must
        // reject the removed author rather than sealing under the new epoch.
        use std::future::Future;
        use std::task::Poll;

        let kp_a = AgentKeypair::generate().expect("kp a");
        let kp_b = AgentKeypair::generate().expect("kp b");
        let (a, b) = (kp_a.agent_id(), kp_b.agent_id());
        let (mut info, mut ctxs, group_id) = encrypted_group(&[a, b]);
        let ctx = ctxs.remove(0);
        let old_epoch = ctx.current_epoch();
        let shared: SharedKvSecureContext = ctx.clone();
        let store = Arc::new(RwLock::new(
            KvStore::new_encrypted(
                store_id(14),
                "race".to_string(),
                a,
                group_id,
                shared.clone(),
            )
            .expect("store"),
        ));
        let signing = Arc::new(AuthorSigning::from_keypair(&kp_a).expect("signer"));
        let delta = KvStoreDelta::new(1);
        let store_guard = store.write().await;
        let future = KvStoreSync::seal_publication(
            &store,
            &shared,
            None,
            &signing,
            KvMutationKind::Delta,
            peer(1),
            &delta,
        );
        tokio::pin!(future);
        std::future::poll_fn(|cx| {
            assert!(
                future.as_mut().poll(cx).is_pending(),
                "publication must reach the held store read"
            );
            Poll::Ready(())
        })
        .await;

        info.remove_member(&hex::encode(a.as_bytes()), Some(hex::encode(b.as_bytes())));
        info.secret_epoch = old_epoch + 1;
        info.shared_secret = Some(vec![0x57; 32]);
        ctx.update_from_group(&info);
        assert!(!ctx.is_active_member(&a));
        assert_eq!(ctx.current_epoch(), old_epoch + 1);
        drop(store_guard);

        let result = future.await;
        assert!(
            result.is_err(),
            "an author absent throughout the new epoch must not encode a publication"
        );
    }

    #[tokio::test]
    async fn encrypted_main_topic_rejects_authenticated_control_kind() {
        // A valid encrypted Control payload must not be interpreted as a
        // main-topic delta. The payload is deliberately a valid delta so the
        // assertion exercises the kind gate rather than deserialization.
        let kp = AgentKeypair::generate().expect("kp");
        let a = kp.agent_id();
        let (_info, mut ctxs, group_id) = encrypted_group(&[a]);
        let ctx = ctxs.pop().expect("ctx");
        let shared: SharedKvSecureContext = ctx.clone();
        let store = KvStore::new_encrypted(
            store_id(10),
            "Enc".to_string(),
            a,
            group_id,
            ctx.clone() as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        let store = Arc::new(RwLock::new(store));
        let delta = KvStoreDelta::for_put(
            "wrong-kind".to_string(),
            KvEntry::new(
                "wrong-kind".to_string(),
                b"must-not-merge".to_vec(),
                "text/plain".to_string(),
            ),
            (peer(1), 1),
            1,
        );
        let signing = AuthorSigning::from_keypair(&kp).expect("author signing");
        let record = seal_mutation(
            shared.as_ref(),
            &signing,
            KvMutationKind::Control,
            &store_id(10),
            &bincode::serialize(&delta).expect("delta bytes"),
        )
        .expect("control envelope");
        let encoded = encode_delta(peer(1), &record).expect("encoded envelope");
        assert!(
            !KvStoreSync::merge_encrypted_record(
                &shared,
                None,
                &store,
                &store_id(10),
                peer(1),
                &encoded,
                &Arc::new(std::sync::Mutex::new(RetainedPagePool::default())),
            )
            .await
        );
        assert!(store.read().await.get("wrong-kind").is_none());
    }

    #[tokio::test]
    async fn encrypted_publication_allows_active_delta_and_full_state() {
        // Positive controls retain both legitimate main-topic mutation kinds.
        let kp = AgentKeypair::generate().expect("kp");
        let a = kp.agent_id();
        let (_info, mut ctxs, group_id) = encrypted_group(&[a]);
        let ctx = ctxs.pop().expect("ctx");
        let shared: SharedKvSecureContext = ctx.clone();
        let store = KvStore::new_encrypted(
            store_id(11),
            "Enc".to_string(),
            a,
            group_id,
            ctx.clone() as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        let store = Arc::new(RwLock::new(store));
        let signing = Arc::new(AuthorSigning::from_keypair(&kp).expect("author signing"));
        for kind in [KvMutationKind::Delta, KvMutationKind::FullState] {
            let encoded = KvStoreSync::seal_publication(
                &store,
                &shared,
                None,
                &signing,
                kind,
                peer(1),
                &KvStoreDelta::new(1),
            )
            .await
            .expect("active member publication");
            let (_, record) =
                decode_delta::<EncryptedKvStoreRecordV1>(&encoded).expect("sealed envelope");
            let opened = open_mutation(shared.as_ref(), &store_id(11), &record)
                .expect("open sealed envelope");
            assert_eq!(opened.kind, kind);
        }
    }

    #[tokio::test]
    async fn encrypted_store_sealed_delta_round_trip() {
        // WHY (#341 Phase B): the core end-to-end property — a member's put
        // on an encrypted store is published as a SEALED record, and a peer
        // member's listener opens it, verifies the author, checks group
        // membership, and merges. No plaintext delta is involved at any
        // point on the wire.
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let kp_a = AgentKeypair::generate().expect("kp");
        let kp_b = AgentKeypair::generate().expect("kp");
        let (a, b) = (kp_a.agent_id(), kp_b.agent_id());
        let (_info, mut ctxs, group_id) = encrypted_group(&[a, b]);
        let ctx_b = ctxs.pop().expect("ctx b");
        let ctx_a = ctxs.pop().expect("ctx a");

        let topic = "store/enc-rt";
        let sync_a = make_encrypted_sync(
            topic,
            Arc::clone(&pubsub),
            1,
            a,
            a,
            &kp_a,
            ctx_a,
            group_id.clone(),
            peer(1),
        )
        .await;
        let sync_b = make_encrypted_sync(
            topic,
            Arc::clone(&pubsub),
            1,
            a,
            b,
            &kp_b,
            ctx_b,
            group_id,
            peer(2),
        )
        .await;
        sync_a.start().await.expect("start a");
        sync_b.start().await.expect("start b");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A mutates locally and publishes through the SEALED path.
        let delta = {
            let mut s = sync_a.write().await;
            s.put(
                "secret-key".to_string(),
                b"hush".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
            let entry = s.get("secret-key").cloned().expect("entry");
            KvStoreDelta::for_put(
                "secret-key".to_string(),
                entry,
                (peer(1), s.next_seq().expect("sequence")),
                s.current_version(),
            )
        };
        sync_a.publish_delta(peer(1), delta).await.expect("publish");

        assert!(
            wait_for_key(&sync_b, "secret-key").await,
            "peer member must decrypt, verify, and merge the sealed delta"
        );
        let value = sync_b
            .read()
            .await
            .get("secret-key")
            .map(|e| e.value.clone());
        assert_eq!(value, Some(b"hush".to_vec()));
    }

    #[tokio::test]
    async fn rejected_owner_announce_does_not_wait_behind_a_receive_section() {
        // WHY (#757 r3, Codex P2): the responder serves state requests from
        // the same loop that handles owner announces. If an announce that
        // will be REJECTED first queued for the lifecycle lock, any peer
        // could stall this replica's state serving for as long as the
        // listener's merge + snapshot write takes (here: parked forever).
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        // Anchored owner is NOT the pub/sub signer, so the signer's control
        // messages are a remote peer's, not our own echo.
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Allowlisted,
        )
        .expect("kv store");
        store.allow_writer(sender, &agent(1)).expect("allow signer");
        let sync = KvStoreSync::new(
            store,
            Arc::clone(&pubsub),
            "store/757-announce".to_string(),
            peer(1),
            Some(agent(1)),
        )
        .expect("kv sync");
        let dir = tempfile::tempdir().expect("tempdir");
        sync.set_persist_path(dir.path().join("store.bin"));
        sync.persist().await.expect("baseline snapshot");
        let mut side = pubsub.subscribe(sync.state_sync_topic()).await;
        let loops = start_joinable(&sync).await;

        let served = sync
            .with_persist_gate_held_for_test(async {
                let entry = KvEntry::new(
                    "late-key".to_string(),
                    b"late".to_vec(),
                    "text/plain".to_string(),
                );
                let mut delta = KvStoreDelta::new(1);
                delta
                    .added
                    .insert("late-key".to_string(), (entry, (peer(2), 1)));
                sync.publish_delta(peer(2), delta).await.expect("publish");
                // Barrier: merged, so the listener now sits in its receive
                // section with the snapshot write parked on the gate.
                tokio::time::timeout(Duration::from_secs(10), async {
                    while sync.read().await.get("late-key").is_none() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("listener must merge the delta");

                // Rejected: the verified sender is not the claimed owner.
                let announce = KvSyncMessage::OwnerAnnounce {
                    owner: agent(9),
                    policy: AccessPolicy::Signed,
                    policy_version: 7,
                };
                for message in [announce, KvSyncMessage::StateRequest { requester: peer(3) }] {
                    pubsub
                        .publish(
                            sync.state_sync_topic(),
                            bytes::Bytes::from(bincode::serialize(&message).expect("control")),
                        )
                        .await
                        .expect("publish control");
                }
                // Safety net, not a sleep oracle: success is the served
                // marker arriving; the bound only turns a stall into a FAIL.
                tokio::time::timeout(Duration::from_secs(10), async {
                    while let Some(msg) = side.recv().await {
                        if matches!(
                            bincode::deserialize::<KvSyncMessage>(&msg.payload),
                            Ok(KvSyncMessage::StateServed { .. }
                                | KvSyncMessage::StateServedV2 { .. })
                        ) {
                            return true;
                        }
                    }
                    false
                })
                .await
            })
            .await;
        assert_eq!(
            served,
            Ok(true),
            "state request stalled behind a rejected owner announce"
        );
        assert_eq!(sync.read().await.owner(), Some(&agent(1)));
        sync.cancel_sync_and_drain().await;
        join_loops(loops).await;
    }

    /// Delegating protector whose `merge_main_record` parks on a gate AFTER
    /// `open_record` has already advanced the real receive ratchet (#757).
    struct GatedTreeKemProtector {
        inner: Arc<TestTreeKemProtector>,
        gate: tokio::sync::Semaphore,
        entered: std::sync::atomic::AtomicUsize,
        settled: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::kv::TreeKemKvProtector for GatedTreeKemProtector {
        fn group_id(&self) -> Vec<u8> {
            self.inner.group_id()
        }

        async fn seal_record(
            &self,
            signing: &AuthorSigning,
            kind: KvMutationKind,
            store_id: &KvStoreId,
            payload: &[u8],
            reader_only: bool,
        ) -> Result<TreeKemKvStoreRecordV1> {
            self.inner
                .seal_record(signing, kind, store_id, payload, reader_only)
                .await
        }

        async fn open_record(
            &self,
            store_id: &KvStoreId,
            record: &TreeKemKvStoreRecordV1,
        ) -> Result<crate::kv::treekem::OpenedTreeKemKvRecord> {
            self.inner.open_record(store_id, record).await
        }

        async fn is_authorized_reader(&self, agent: &AgentId) -> bool {
            self.inner.is_authorized_reader(agent).await
        }

        async fn is_authorized_writer(&self, agent: &AgentId) -> bool {
            self.inner.is_authorized_writer(agent).await
        }

        async fn merge_main_record(
            &self,
            opened: crate::kv::treekem::OpenedTreeKemKvRecord,
            sender_peer: PeerId,
            local_peer: PeerId,
            store: &Arc<RwLock<KvStore>>,
            retained_image: Option<Vec<u8>>,
        ) -> Result<()> {
            use std::sync::atomic::Ordering::SeqCst;
            self.entered.fetch_add(1, SeqCst);
            self.gate
                .acquire()
                .await
                .map_err(|e| KvError::Gossip(format!("test gate closed: {e}")))?
                .forget();
            let merged = self
                .inner
                .merge_main_record(opened, sender_peer, local_peer, store, retained_image)
                .await;
            self.settled.fetch_add(1, SeqCst);
            merged
        }

        fn invalidate(&self) {
            self.inner.invalidate();
        }
    }

    #[tokio::test]
    async fn draining_retire_lets_an_opened_treekem_record_settle() {
        // WHY (#757 r2, Codex P2): `open_record` advances the shared TreeKEM
        // receive ratchet. A retire that cancelled the receive future after
        // that point (r1's `unless_cancelled`) stranded the ratchet ahead of
        // the store and its snapshot. A record that has been opened must run
        // through merge AND persist, and a draining retire must wait for it.
        use std::sync::atomic::Ordering::SeqCst;
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let owner_kp = AgentKeypair::generate().expect("owner kp");
        let reader_kp = AgentKeypair::generate().expect("reader kp");
        let owner = owner_kp.agent_id();
        let reader = reader_kp.agent_id();
        let (_info, mut contexts, group_id) = encrypted_group(&[owner, reader]);
        let reader_ctx = contexts.pop().expect("reader context");
        let owner_ctx = contexts.pop().expect("owner context");
        let mut owner_group =
            crate::mls::TreeKemMlsGroup::create(group_id.clone(), owner, &[1; 32])
                .expect("owner group");
        let prepared =
            crate::mls::TreeKemMlsGroup::prepare_member(reader, &[2; 32]).expect("reader kp");
        let add = owner_group
            .add_member(reader, prepared.key_package_bytes())
            .expect("add reader");
        let reader_group = crate::mls::TreeKemMlsGroup::join_from_welcome(prepared, &add.welcome)
            .expect("reader join");
        let members = std::collections::HashSet::from([owner, reader]);
        let authorization = *blake3::hash(b"757 roster").as_bytes();
        let owner_protector = Arc::new(TestTreeKemProtector {
            group_id: group_id.clone(),
            group: tokio::sync::Mutex::new(owner_group),
            readers: members.clone(),
            writers: std::sync::Mutex::new(members.clone()),
            authorization,
        });
        let gated = Arc::new(GatedTreeKemProtector {
            inner: Arc::new(TestTreeKemProtector {
                group_id: group_id.clone(),
                group: tokio::sync::Mutex::new(reader_group),
                readers: members.clone(),
                writers: std::sync::Mutex::new(members),
                authorization,
            }),
            gate: tokio::sync::Semaphore::new(0),
            entered: std::sync::atomic::AtomicUsize::new(0),
            settled: std::sync::atomic::AtomicUsize::new(0),
        });
        let source = KvStore::new_treekem_encrypted(
            store_id(57),
            "Home".to_string(),
            owner,
            group_id,
            owner_ctx,
        )
        .expect("owner store");
        let mut target = source.clone();
        target
            .set_secure_context(reader_ctx)
            .expect("reader context");

        let topic = "store/757-treekem";
        let mut owner_sync = KvStoreSync::new(
            source,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner),
        )
        .expect("owner sync");
        owner_sync.set_treekem_context(owner_protector);
        owner_sync
            .set_author_signing(AuthorSigning::from_keypair(&owner_kp).expect("owner signing"));
        let mut reader_sync = KvStoreSync::new(
            target,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(reader),
        )
        .expect("reader sync");
        reader_sync.set_treekem_context(gated.clone());
        reader_sync
            .set_author_signing(AuthorSigning::from_keypair(&reader_kp).expect("reader signing"));
        let dir = tempfile::tempdir().expect("tempdir");
        let snapshot = dir.path().join("store.bin");
        reader_sync.set_persist_path(snapshot.clone());
        reader_sync.persist().await.expect("baseline snapshot");
        let before = std::fs::read(&snapshot).expect("baseline bytes");
        let loops = start_joinable(&reader_sync).await;

        let delta = {
            let mut s = owner_sync.write().await;
            s.put(
                "sealed-key".to_string(),
                b"hush".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
            let entry = s.get("sealed-key").cloned().expect("entry");
            KvStoreDelta::for_put(
                "sealed-key".to_string(),
                entry,
                (peer(1), s.next_seq().expect("sequence")),
                s.current_version(),
            )
        };
        owner_sync
            .publish_delta(peer(1), delta)
            .await
            .expect("publish");
        // Barrier: the record is OPENED (ratchet advanced) and its merge is
        // parked on the gate, inside the listener's section.
        tokio::time::timeout(Duration::from_secs(10), async {
            while gated.entered.load(SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader must open the sealed record");

        let mut drain = Box::pin(reader_sync.cancel_sync_and_drain());
        for _ in 0..64 {
            assert!(
                futures::poll!(drain.as_mut()).is_pending(),
                "retire completed with an opened TreeKEM record unsettled"
            );
            tokio::task::yield_now().await;
        }
        assert_eq!(gated.settled.load(SeqCst), 0);
        gated.gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .expect("drain must complete once the record settles");
        assert_eq!(
            (gated.entered.load(SeqCst), gated.settled.load(SeqCst)),
            (1, 1),
            "an opened record was abandoned mid-flight"
        );
        assert!(reader_sync.read().await.get("sealed-key").is_some());
        assert_ne!(
            std::fs::read(&snapshot).expect("snapshot bytes"),
            before,
            "ratchet and store advanced but the snapshot did not"
        );
        join_loops(loops).await;
    }

    #[tokio::test]
    async fn treekem_responder_pages_large_history_and_receiver_reassembles_out_of_order() {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let owner_kp = AgentKeypair::generate().expect("owner kp");
        let writer_kp = AgentKeypair::generate().expect("writer kp");
        let reader_kp = AgentKeypair::generate().expect("reader kp");
        let owner = owner_kp.agent_id();
        let writer = writer_kp.agent_id();
        let reader = reader_kp.agent_id();
        let (group_info, mut contexts, group_id) = encrypted_group(&[owner, writer, reader]);
        let reader_ctx = contexts.pop().expect("reader context");
        let writer_ctx = contexts.pop().expect("writer context");
        let _owner_ctx = contexts.pop().expect("owner context");

        let mut owner_group =
            crate::mls::TreeKemMlsGroup::create(group_id.clone(), owner, &[1; 32])
                .expect("owner group");
        let writer_prepared =
            crate::mls::TreeKemMlsGroup::prepare_member(writer, &[2; 32]).expect("writer kp");
        let writer_add = owner_group
            .add_member(writer, writer_prepared.key_package_bytes())
            .expect("add writer");
        let mut writer_group =
            crate::mls::TreeKemMlsGroup::join_from_welcome(writer_prepared, &writer_add.welcome)
                .expect("writer join");
        let reader_prepared =
            crate::mls::TreeKemMlsGroup::prepare_member(reader, &[3; 32]).expect("reader kp");
        let reader_add = owner_group
            .add_member(reader, reader_prepared.key_package_bytes())
            .expect("add reader");
        writer_group
            .process_commit(&reader_add.commit)
            .expect("writer advances");
        let reader_group =
            crate::mls::TreeKemMlsGroup::join_from_welcome(reader_prepared, &reader_add.welcome)
                .expect("reader join");
        drop(owner_group); // the canonical owner is offline while the writer serves.

        let readers = std::collections::HashSet::from([owner, writer, reader]);
        let writers = std::collections::HashSet::from([owner, writer]);
        let authorization = *blake3::hash(b"current roster and AdminOnly policy").as_bytes();
        let writer_protector = Arc::new(TestTreeKemProtector {
            group_id: group_id.clone(),
            group: tokio::sync::Mutex::new(writer_group),
            readers: readers.clone(),
            writers: std::sync::Mutex::new(writers.clone()),
            authorization,
        });
        let reader_protector = Arc::new(TestTreeKemProtector {
            group_id: group_id.clone(),
            group: tokio::sync::Mutex::new(reader_group),
            readers,
            writers: std::sync::Mutex::new(writers),
            authorization,
        });
        let id = store_id(44);
        let mut source = KvStore::new_treekem_encrypted(
            id,
            "Home".to_string(),
            owner,
            group_id.clone(),
            writer_ctx,
        )
        .expect("writer store");
        source
            .put(
                "removed".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed removal");
        for index in 0..17 {
            source
                .put(
                    format!("large-{index}"),
                    vec![index as u8; crate::kv::entry::MAX_INLINE_SIZE],
                    "application/octet-stream".to_string(),
                    peer(2),
                )
                .expect("large entry");
        }
        let mut target = source.clone();
        target
            .set_secure_context(reader_ctx)
            .expect("reader context");
        source.remove("removed").expect("retained tombstone");
        target
            .put(
                "concurrent".to_string(),
                b"local".to_vec(),
                "text/plain".to_string(),
                peer(3),
            )
            .expect("concurrent target write");

        let topic = "store/treekem-paged-history";
        let mut main_probe = pubsub.subscribe(topic.to_string()).await;
        let mut writer_sync = KvStoreSync::new(
            source,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(writer),
        )
        .expect("writer sync");
        writer_sync.set_treekem_context(writer_protector.clone());
        writer_sync
            .set_author_signing(AuthorSigning::from_keypair(&writer_kp).expect("writer signing"));
        writer_sync.start().await.expect("start responder");
        let retained = {
            let store = writer_sync.read().await;
            serialize_retained_group_image(&store).expect("retained image")
        };
        let max_wire =
            crate::gossip::pubsub::max_signed_v3_payload_bytes(topic).expect("wire budget");
        let expected_frames =
            crate::kv::retained_paging::split_image(&retained, max_wire.saturating_sub(16 * 1024))
                .expect("paged frames")
                .len();
        assert!(
            expected_frames > 2,
            "history must span multiple data frames"
        );

        let request = KvSyncMessage::StateRequest { requester: peer(3) };
        let reader_signing =
            Arc::new(AuthorSigning::from_keypair(&reader_kp).expect("reader signing"));
        let reader_trait: SharedTreeKemKvProtector = reader_protector.clone();
        let request_bytes = KvStoreSync::seal_treekem_control(
            &reader_trait,
            &reader_signing,
            &id,
            peer(3),
            &request,
        )
        .await
        .expect("reader state request");
        pubsub
            .publish(
                format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}"),
                bytes::Bytes::from(request_bytes),
            )
            .await
            .expect("publish request");

        let mut wire_frames = Vec::with_capacity(expected_frames);
        for _ in 0..expected_frames {
            let message = tokio::time::timeout(Duration::from_secs(5), main_probe.recv())
                .await
                .expect("responder frame timeout")
                .expect("responder frame");
            assert!(message.payload.len() <= max_wire);
            wire_frames.push(message.payload);
        }
        wire_frames.reverse();
        let target = Arc::new(RwLock::new(target));
        let pages = Arc::new(std::sync::Mutex::new(RetainedPagePool::default()));
        for payload in wire_frames {
            let _ = KvStoreSync::merge_treekem_record(
                &reader_trait,
                &target,
                &id,
                peer(3),
                &payload,
                &pages,
            )
            .await;
        }
        let merged = target.read().await;
        assert!(merged.get("removed").is_none());
        assert_eq!(
            merged.get("concurrent").expect("concurrent").value,
            b"local"
        );
        assert_eq!(merged.last_history_endorser(), Some(&writer));
        drop(merged);

        reader_protector
            .writers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&writer);
        let hostile = writer_protector
            .seal_record(
                &AuthorSigning::from_keypair(&writer_kp).expect("writer signing"),
                KvMutationKind::Delta,
                &id,
                &bincode::serialize(&KvStoreDelta::new(99)).expect("delta"),
                false,
            )
            .await
            .expect("stale writer record");
        let hostile = encode_delta(peer(2), &hostile).expect("wire record");
        assert!(
            !KvStoreSync::merge_treekem_record(
                &reader_trait,
                &target,
                &id,
                peer(3),
                &hostile,
                &pages,
            )
            .await
        );
        let _ = group_info;
    }

    #[tokio::test]
    async fn treekem_retained_publisher_retries_partial_frames_and_receiver_reassembles() {
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let owner_kp = AgentKeypair::generate().expect("owner kp");
        let writer_kp = AgentKeypair::generate().expect("writer kp");
        let reader_kp = AgentKeypair::generate().expect("reader kp");
        let owner = owner_kp.agent_id();
        let writer = writer_kp.agent_id();
        let reader = reader_kp.agent_id();
        let (group_info, mut contexts, group_id) = encrypted_group(&[owner, writer, reader]);
        let reader_ctx = contexts.pop().expect("reader context");
        let writer_ctx = contexts.pop().expect("writer context");
        let _owner_ctx = contexts.pop().expect("owner context");

        let mut owner_group =
            crate::mls::TreeKemMlsGroup::create(group_id.clone(), owner, &[1; 32])
                .expect("owner group");
        let writer_prepared =
            crate::mls::TreeKemMlsGroup::prepare_member(writer, &[2; 32]).expect("writer kp");
        let writer_add = owner_group
            .add_member(writer, writer_prepared.key_package_bytes())
            .expect("add writer");
        let mut writer_group =
            crate::mls::TreeKemMlsGroup::join_from_welcome(writer_prepared, &writer_add.welcome)
                .expect("writer join");
        let reader_prepared =
            crate::mls::TreeKemMlsGroup::prepare_member(reader, &[3; 32]).expect("reader kp");
        let reader_add = owner_group
            .add_member(reader, reader_prepared.key_package_bytes())
            .expect("add reader");
        writer_group
            .process_commit(&reader_add.commit)
            .expect("writer advances");
        let reader_group =
            crate::mls::TreeKemMlsGroup::join_from_welcome(reader_prepared, &reader_add.welcome)
                .expect("reader join");
        drop(owner_group); // the canonical owner is offline while the writer serves.

        let readers = std::collections::HashSet::from([owner, writer, reader]);
        let writers = std::collections::HashSet::from([owner, writer]);
        let authorization = *blake3::hash(b"current roster and AdminOnly policy").as_bytes();
        let writer_protector = Arc::new(TestTreeKemProtector {
            group_id: group_id.clone(),
            group: tokio::sync::Mutex::new(writer_group),
            readers: readers.clone(),
            writers: std::sync::Mutex::new(writers.clone()),
            authorization,
        });
        let reader_protector = Arc::new(TestTreeKemProtector {
            group_id: group_id.clone(),
            group: tokio::sync::Mutex::new(reader_group),
            readers,
            writers: std::sync::Mutex::new(writers),
            authorization,
        });
        let id = store_id(44);
        let mut source = KvStore::new_treekem_encrypted(
            id,
            "Home".to_string(),
            owner,
            group_id.clone(),
            writer_ctx,
        )
        .expect("writer store");
        source
            .put(
                "removed".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed removal");
        for index in 0..17 {
            source
                .put(
                    format!("large-{index}"),
                    vec![index as u8; crate::kv::entry::MAX_INLINE_SIZE],
                    "application/octet-stream".to_string(),
                    peer(2),
                )
                .expect("large entry");
        }
        let mut target = source.clone();
        target
            .set_secure_context(reader_ctx)
            .expect("reader context");
        source.remove("removed").expect("retained tombstone");
        target
            .put(
                "concurrent".to_string(),
                b"local".to_vec(),
                "text/plain".to_string(),
                peer(3),
            )
            .expect("concurrent target write");

        let topic = "store/treekem-paged-history";
        let mut main_probe = pubsub.subscribe(topic.to_string()).await;
        let mut writer_sync = KvStoreSync::new(
            source,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(writer),
        )
        .expect("writer sync");
        writer_sync.set_treekem_context(writer_protector.clone());
        writer_sync
            .set_author_signing(AuthorSigning::from_keypair(&writer_kp).expect("writer signing"));
        writer_sync.start().await.expect("start responder");
        let retained = {
            let store = writer_sync.read().await;
            serialize_retained_group_image(&store).expect("retained image")
        };
        let max_wire =
            crate::gossip::pubsub::max_signed_v3_payload_bytes(topic).expect("wire budget");
        let expected_frames =
            crate::kv::retained_paging::split_image(&retained, max_wire.saturating_sub(16 * 1024))
                .expect("paged frames")
                .len();
        assert!(
            expected_frames > 2,
            "history must span multiple data frames"
        );

        let reader_trait: SharedTreeKemKvProtector = reader_protector.clone();
        writer_sync.fail_retained_publish_after_for_test(1);
        assert!(
            writer_sync.publish_retained_group_history().await.is_err(),
            "injected failure must stop after one actually accepted frame"
        );
        assert_eq!(writer_sync.retained_publish_accepted_for_test(), 1);
        let partial = tokio::time::timeout(Duration::from_secs(5), main_probe.recv())
            .await
            .expect("partial frame timeout")
            .expect("partial frame");
        assert!(partial.payload.len() <= max_wire);
        let target = Arc::new(RwLock::new(target));
        let pages = Arc::new(std::sync::Mutex::new(RetainedPagePool::default()));
        assert!(
            !KvStoreSync::merge_treekem_record(
                &reader_trait,
                &target,
                &id,
                peer(3),
                &partial.payload,
                &pages,
            )
            .await,
            "one accepted frame cannot partially mutate the receiver"
        );

        writer_sync.clear_retained_publish_failure_for_test();
        writer_sync
            .publish_retained_group_history()
            .await
            .expect("retry complete retained publication");
        assert_eq!(
            writer_sync.retained_publish_accepted_for_test(),
            expected_frames
        );

        let mut wire_frames = Vec::with_capacity(expected_frames);
        for _ in 0..expected_frames {
            let message = tokio::time::timeout(Duration::from_secs(5), main_probe.recv())
                .await
                .expect("responder frame timeout")
                .expect("responder frame");
            assert!(message.payload.len() <= max_wire);
            wire_frames.push(message.payload);
        }
        wire_frames.reverse();
        for payload in wire_frames {
            let _ = KvStoreSync::merge_treekem_record(
                &reader_trait,
                &target,
                &id,
                peer(3),
                &payload,
                &pages,
            )
            .await;
        }
        let merged = target.read().await;
        assert!(merged.get("removed").is_none());
        assert_eq!(
            merged.get("concurrent").expect("concurrent").value,
            b"local"
        );
        assert_eq!(merged.last_history_endorser(), Some(&writer));
        drop(merged);

        reader_protector
            .writers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&writer);
        let hostile = writer_protector
            .seal_record(
                &AuthorSigning::from_keypair(&writer_kp).expect("writer signing"),
                KvMutationKind::Delta,
                &id,
                &bincode::serialize(&KvStoreDelta::new(99)).expect("delta"),
                false,
            )
            .await
            .expect("stale writer record");
        let hostile = encode_delta(peer(2), &hostile).expect("wire record");
        assert!(
            !KvStoreSync::merge_treekem_record(
                &reader_trait,
                &target,
                &id,
                peer(3),
                &hostile,
                &pages,
            )
            .await
        );
        let _ = group_info;
    }

    #[tokio::test]
    async fn encrypted_store_rejects_nonmember_author() {
        // WHY (#341 Phase B): AEAD alone proves only "a key holder sealed
        // this". A peer holding the group secret but NOT in the roster (the
        // removed-before-rekey case) must fail the membership gate at every
        // receiver — even though its record decrypts and its signature is
        // valid.
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let kp_a = AgentKeypair::generate().expect("kp");
        let kp_b = AgentKeypair::generate().expect("kp");
        let kp_c = AgentKeypair::generate().expect("kp"); // holds a context, NOT a member
        let (a, b, c) = (kp_a.agent_id(), kp_b.agent_id(), kp_c.agent_id());
        let (_info, mut ctxs, group_id) = encrypted_group(&[a, b]);
        let ctx_c = ctxs.pop().expect("ctx outsider");
        let ctx_b = ctxs.pop().expect("ctx b");
        let hostile_ctx = Arc::clone(&ctx_c);

        let topic = "store/enc-nonmember";
        let sync_c = make_encrypted_sync(
            topic,
            Arc::clone(&pubsub),
            1,
            a,
            c,
            &kp_c,
            ctx_c,
            group_id.clone(),
            peer(3),
        )
        .await;
        let sync_b = make_encrypted_sync(
            topic,
            Arc::clone(&pubsub),
            1,
            a,
            b,
            &kp_b,
            ctx_b,
            group_id,
            peer(2),
        )
        .await;
        sync_b.start().await.expect("start b");
        sync_c.start().await.expect("start c");
        encrypted_listener_barrier(&sync_b, "nonmember-ready", 1001).await;

        let delta = {
            let mut s = sync_c.write().await;
            s.put(
                "intruder-key".to_string(),
                b"x".to_vec(),
                "text/plain".to_string(),
                peer(3),
            )
            .expect("put");
            let entry = s.get("intruder-key").cloned().expect("entry");
            KvStoreDelta::for_put(
                "intruder-key".to_string(),
                entry,
                (peer(3), s.next_seq().expect("sequence")),
                s.current_version(),
            )
        };
        // Deliberately bypass the public publisher: it must reject a
        // non-member before encoding.  The receiver control still needs an
        // authenticated hostile envelope, so construct it through the
        // low-level sealer using the retained group key and publish the
        // resulting bytes directly.
        let hostile_signing = AuthorSigning::from_keypair(&kp_c).expect("hostile signing");
        let hostile_record = seal_mutation(
            hostile_ctx.as_ref(),
            &hostile_signing,
            KvMutationKind::Delta,
            &store_id(1),
            &bincode::serialize(&delta).expect("delta bytes"),
        )
        .expect("low-level hostile envelope");
        let hostile_bytes = encode_delta(peer(3), &hostile_record).expect("hostile envelope");
        pubsub
            .publish(topic.to_string(), bytes::Bytes::from(hostile_bytes))
            .await
            .expect("publish hostile envelope");

        // Sequential local publishes enter the same FIFO subscription. The
        // marker proves the earlier adversarial record reached the listener.
        encrypted_listener_barrier(&sync_b, "nonmember-processed", 1002).await;
        assert!(
            sync_b.read().await.get("intruder-key").is_none(),
            "non-member author's sealed record must never merge"
        );
    }

    #[tokio::test]
    async fn encrypted_store_rejects_plaintext_delta() {
        // WHY (#341 Phase B, hard requirement 1): a plaintext KvStoreDelta
        // injected onto an encrypted store's topic must not decode as a
        // sealed envelope and must never reach the merge.
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let kp_a = AgentKeypair::generate().expect("kp");
        let a = kp_a.agent_id();
        let (_info, ctxs, group_id) = encrypted_group(&[a]);
        let topic = "store/enc-plain";
        let sync_a = make_encrypted_sync(
            topic,
            Arc::clone(&pubsub),
            1,
            a,
            a,
            &kp_a,
            ctxs.into_iter().next().expect("ctx"),
            group_id,
            peer(1),
        )
        .await;
        sync_a.start().await.expect("start");
        encrypted_listener_barrier(&sync_a, "plaintext-ready", 1001).await;

        let mut delta = KvStoreDelta::new(1);
        delta.added.insert(
            "plaintext-key".to_string(),
            (
                KvEntry::new(
                    "plaintext-key".to_string(),
                    b"leak".to_vec(),
                    "text/plain".to_string(),
                ),
                (peer(9), 1),
            ),
        );
        let raw = encode_delta(peer(9), &delta).expect("encode plaintext delta");
        pubsub
            .publish(topic.to_string(), bytes::Bytes::from(raw))
            .await
            .expect("publish plaintext");

        // The post-publication barrier must merge before absence is checked;
        // a scheduler delay cannot masquerade as a plaintext ingestion failure.
        encrypted_listener_barrier(&sync_a, "plaintext-processed", 1002).await;
        assert!(
            sync_a.read().await.get("plaintext-key").is_none(),
            "plaintext delta must never apply to an encrypted store"
        );
    }

    #[tokio::test]
    async fn unconfigured_encrypted_sync_never_publishes_plaintext() {
        // WHY (PR #508 review P1): publish_delta is a PUBLIC method callable
        // before start()/configuration — the startup guard does not cover
        // direct calls. An encrypted store's sync with no secure context
        // must hard-error at this boundary instead of falling into the
        // plaintext branch, and a subscribed observer must receive NOTHING.
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let kp = AgentKeypair::generate().expect("kp");
        let a = kp.agent_id();
        let (_info, mut ctxs, group_id) = encrypted_group(&[a]);
        let store = KvStore::new_encrypted(
            store_id(1),
            "Enc".to_string(),
            a,
            group_id,
            ctxs.pop().expect("ctx") as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        // NOTE: no set_secure_context / set_author_signing, no start().
        let sync = KvStoreSync::new(
            store,
            Arc::clone(&pubsub),
            "store/enc-unpub".to_string(),
            peer(1),
            Some(a),
        )
        .expect("kv sync");

        // Observer watches the topic from BEFORE the publish attempt.
        let mut observer = pubsub.subscribe("store/enc-unpub".to_string()).await;

        let mut delta = KvStoreDelta::new(1);
        delta.added.insert(
            "confidential-key".to_string(),
            (
                KvEntry::new(
                    "confidential-key".to_string(),
                    b"secret".to_vec(),
                    "text/plain".to_string(),
                ),
                (peer(1), 1),
            ),
        );
        let err = sync
            .publish_delta(peer(1), delta)
            .await
            .expect_err("unconfigured encrypted publish must hard-error");
        assert!(
            matches!(err, crate::kv::KvError::SecureRecord(ref m) if m.contains("no secure context")),
            "got {err:?}"
        );

        // The observer heard nothing: no plaintext ever left the process.
        let leak = tokio::time::timeout(Duration::from_millis(300), observer.recv()).await;
        assert!(leak.is_err(), "plaintext delta was published to the topic");
    }

    #[tokio::test]
    async fn encrypted_sync_requires_context_and_signing() {
        // WHY (#341 Phase B): an encrypted store sync without its secure
        // context or author signing material must REFUSE TO START — the
        // only alternative would be a plaintext-capable sync window.
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let kp = AgentKeypair::generate().expect("kp");
        let a = kp.agent_id();
        let (_info, mut ctxs, group_id) = encrypted_group(&[a]);
        let store = KvStore::new_encrypted(
            store_id(1),
            "Enc".to_string(),
            a,
            group_id,
            // Satisfy the store constructor; the SYNC is what must refuse.
            ctxs.pop().expect("ctx") as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        let sync = KvStoreSync::new(
            store,
            pubsub,
            "store/enc-guard".to_string(),
            peer(1),
            Some(a),
        )
        .expect("kv sync");
        // NOTE: no set_secure_context / set_author_signing.
        let err = sync
            .start_with_spawner(|fut| {
                tokio::spawn(fut);
            })
            .await
            .expect_err("encrypted sync must refuse to start unconfigured");
        assert!(
            matches!(err, crate::kv::KvError::SecureRecord(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn encrypted_bootstrap_converges_via_sealed_state_request() {
        // WHY (#341 Phase B): late joiners bootstrap from current state —
        // the state request, the full-state serve, and the evidence markers
        // ALL travel sealed. B joins after A's write and must still receive
        // the pre-join key.
        let node = make_node().await;
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let kp_a = AgentKeypair::generate().expect("kp");
        let kp_b = AgentKeypair::generate().expect("kp");
        let (a, b) = (kp_a.agent_id(), kp_b.agent_id());
        let (_info, mut ctxs, group_id) = encrypted_group(&[a, b]);
        let ctx_b = ctxs.pop().expect("ctx b");
        let ctx_a = ctxs.pop().expect("ctx a");

        let topic = "store/enc-bootstrap";
        let sync_a = make_encrypted_sync(
            topic,
            Arc::clone(&pubsub),
            1,
            a,
            a,
            &kp_a,
            ctx_a,
            group_id.clone(),
            peer(1),
        )
        .await;
        sync_a.start().await.expect("start a");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The owner writes BEFORE B ever joins (B misses this delta).
        {
            let mut s = sync_a.write().await;
            s.put(
                "early-key".to_string(),
                b"early".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }

        let sync_b = make_encrypted_sync(
            topic,
            Arc::clone(&pubsub),
            1,
            a,
            b,
            &kp_b,
            ctx_b,
            group_id,
            peer(2),
        )
        .await;
        sync_b.start().await.expect("start b");

        assert!(
            wait_for_key(&sync_b, "early-key").await,
            "late joiner must converge via the sealed state-request path"
        );
    }

    // ------------------------------------------------------------------
    // stop(): returns Ok and is idempotent
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn stop_returns_ok_and_is_idempotent() {
        let sync = make_sync("store/F", AccessPolicy::Signed).await;
        sync.stop().await.expect("first stop");
        // stop() unsubscribes both the main and the state-sync topic;
        // unsubscribe is infallible and tolerant of already-removed topics,
        // so a second stop() must remain Ok.
        sync.stop().await.expect("second stop (idempotent)");
    }

    /// WHY (rounds 1+4 review): the requester's schedule is INFINITE while
    /// the store is empty, and the sibling loops hold strong `Arc`s to the
    /// store — so the cancellation token (all loops) and the
    /// silence_bootstrap flag (requester only) are the only things that end
    /// a discarded sync's background work before daemon shutdown.
    #[tokio::test]
    async fn stop_and_silence_arm_their_kill_switches() {
        let sync = make_sync("store/stopflag", AccessPolicy::Signed).await;
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
        let sync = make_sync("store/dropcancel", AccessPolicy::Signed).await;
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

    /// WHY: the request schedule is the ONLY trigger for state recovery —
    /// holders answer reactively and never volunteer state to a late
    /// subscriber. A finite schedule therefore turned "owner offline while
    /// the schedule ran" into a permanent zombie: the replica stayed empty
    /// forever, even after the owner returned. The schedule must be
    /// front-loaded (a fast mesh converges in seconds) and then an
    /// infinite capped tail (bounded chatter, unbounded patience).
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

    /// WHY (round-2 review): the convergence rule must weigh evidence
    /// correctly — checkpoint match is exact; declared-non-empty requires
    /// local state; emptiness counts only when the owner declared it; and
    /// NO evidence is NEVER convergence (a replica that heard nothing keeps
    /// asking, whatever its local state looks like). Issue #240 adds the
    /// digest gate: when v2 declarations exist they OUTRANK the weak v1
    /// rules, and a data-bearing declaration outranks an empty one.
    #[test]
    fn bootstrap_convergence_rule() {
        const D1: [u8; 32] = [1u8; 32];
        const D2: [u8; 32] = [2u8; 32];
        const D_EMPTY: [u8; 32] = [9u8; 32];
        let none = ServedEvidence::default();
        // No evidence: never converged, empty or not.
        assert!(!bootstrap_converged(&none, true, 0, D1));
        assert!(!bootstrap_converged(&none, false, 9, D1));

        // Checkpoint evidence is exact: local HWM must reach it.
        let cp = ServedEvidence {
            saw_nonempty: true,
            saw_owner_empty: false,
            max_checkpoint_seq: 5,
            digests: std::collections::HashMap::new(),
        };
        assert!(
            !bootstrap_converged(&cp, false, 4, D1),
            "behind the served HWM"
        );
        assert!(bootstrap_converged(&cp, false, 5, D1));
        assert!(bootstrap_converged(&cp, false, 7, D1));

        // Non-empty holder, no checkpoint: local non-emptiness required.
        let nonempty = ServedEvidence {
            saw_nonempty: true,
            saw_owner_empty: false,
            max_checkpoint_seq: 0,
            digests: std::collections::HashMap::new(),
        };
        assert!(!bootstrap_converged(&nonempty, true, 0, D1));
        assert!(bootstrap_converged(&nonempty, false, 0, D1));

        // Owner-declared empty (and nothing stronger): converged even empty.
        let owner_empty = ServedEvidence {
            saw_nonempty: false,
            saw_owner_empty: true,
            max_checkpoint_seq: 0,
            digests: std::collections::HashMap::new(),
        };
        assert!(bootstrap_converged(&owner_empty, true, 0, D1));
        // A non-empty holder claim outranks owner-empty when both were seen.
        let mixed = ServedEvidence {
            saw_nonempty: true,
            saw_owner_empty: true,
            max_checkpoint_seq: 0,
            digests: std::collections::HashMap::new(),
        };
        assert!(
            !bootstrap_converged(&mixed, true, 0, D1),
            "divergent holders: the data-bearing claim must win, keep asking"
        );

        // ---- v2 digest evidence (issue #240) ----
        let digest_ev = |decls: &[(&[u8; 32], u32)]| ServedEvidence {
            saw_nonempty: false,
            saw_owner_empty: false,
            max_checkpoint_seq: 0,
            digests: decls
                .iter()
                .enumerate()
                .map(|(i, (d, c))| {
                    (
                        peer(i as u8 + 10),
                        ServedState {
                            digest: **d,
                            entry_count: *c,
                        },
                    )
                })
                .collect(),
        };
        // Match stops: local digest equals a declared non-empty digest.
        let ev = digest_ev(&[(&D1, 3)]);
        assert!(bootstrap_converged(&ev, false, 0, D1));
        // Mismatch keeps asking — the lost-full-delta window is closed.
        assert!(!bootstrap_converged(&ev, false, 0, D2));
        // Weak v1 evidence must NOT rescue a digest mismatch.
        let mut ev_v1_too = digest_ev(&[(&D1, 3)]);
        ev_v1_too.saw_nonempty = true;
        assert!(
            !bootstrap_converged(&ev_v1_too, false, 0, D2),
            "v2 declarations outrank weak v1 evidence"
        );
        // Empty-holder declarations converge an empty requester (and ONLY
        // when every declaration is empty).
        let ev_empty = digest_ev(&[(&D_EMPTY, 0)]);
        assert!(bootstrap_converged(&ev_empty, true, 0, D_EMPTY));
        let ev_divergent = digest_ev(&[(&D_EMPTY, 0), (&D1, 2)]);
        assert!(
            !bootstrap_converged(&ev_divergent, true, 0, D_EMPTY),
            "a data-bearing declaration outranks the empty one — keep asking"
        );
        assert!(bootstrap_converged(&ev_divergent, false, 0, D1));
    }

    /// WHY (round-2 review — P1: restored non-empty replicas still became
    /// zombies): round 1 made non-owner replicas run the front burst, but
    /// the tail still exited on mere non-emptiness — a restored replica
    /// whose owner stayed offline through the burst exited on its first
    /// tail check and never asked again. Convergence now requires
    /// StateServed evidence: the replica must keep asking until a holder
    /// actually answers, however long the owner is away.
    #[tokio::test(start_paused = true)]
    async fn restored_replica_keeps_asking_until_a_holder_serves() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-238-restored-late-owner";

        // Snapshot-restored replica: non-empty, owner OFFLINE.
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::Persistence,
        );
        replica
            .put(
                "k_old".to_string(),
                b"v_old".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed restored key");
        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        // The entire front burst fires with the owner away. The round-1
        // code exited the tail right here (non-empty ⇒ "converged").
        tokio::time::sleep(Duration::from_secs(90)).await;

        // Owner returns much later, holding a key the replica missed.
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        owned
            .put(
                "k_old".to_string(),
                b"v_old".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner k_old");
        owned
            .put(
                "k_new".to_string(),
                b"v_new".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner k_new");
        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        let mut recovered = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get("k_new").is_some() {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "a restored non-empty replica must keep requesting until a \
             holder serves it — non-emptiness alone is not convergence"
        );
    }

    /// WHY (round-3 review — deleted-to-empty must cold-sync): an owner
    /// whose store is legitimately empty but checkpointed (everything
    /// deleted) must still serve state requests: the checkpoint-adopt merge
    /// path is a full REPLACE, so its checkpoint-bearing EMPTY full delta
    /// is exactly what removes a stale replica's obsolete keys. Before this
    /// fix the empty owner was silent while stale holders kept advertising
    /// old state; convergence was also unreachable (the marker declared a
    /// checkpoint the replica could never adopt).
    #[tokio::test(start_paused = true)]
    async fn checkpointed_empty_owner_deletes_stale_replica_state() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-238-deleted-to-empty";

        // Owner: EMPTY store carrying an owner-signed checkpoint over the
        // empty set (the state after deleting everything).
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let public_key =
            ant_quic::MlDsaPublicKey::from_bytes(&pub_bytes).expect("public key bytes");
        let secret_key =
            ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret key bytes");
        let pairs = owned.checkpoint_pairs();
        let root = crate::kv::store::content_root(owned.id(), owned.name(), &pairs);
        let cp = crate::kv::store::make_owner_checkpoint(crate::kv::store::OwnerCheckpointParams {
            topic,
            store_id: &store_id(1),
            secret_key: &secret_key,
            public_key: &public_key,
            policy: &AccessPolicy::Signed,
            policy_version: owned.policy_version(),
            checkpoint_seq: 3,
            content_root: root,
            timestamp: 1,
        })
        .expect("sign empty checkpoint");
        owned.latest_checkpoint = Some(cp);
        owned.highest_checkpoint_seq = 3;
        // Stale replica: still holds a key the owner deleted (hwm 0).
        // Started FIRST so its subscriptions are fully registered before
        // any response can be published (in-process paused-time harness:
        // a response racing the main-topic registration is silently
        // missed; production requesters simply retry, but the poll loop
        // below burns virtual time much faster than real deliveries).
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::Persistence,
        );
        replica
            .put(
                "k_stale".to_string(),
                b"obsolete".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed stale key");
        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        // Harness artifact: both syncs share ONE signing identity (the
        // pubsub ctx), so the stale joiner's responses arrive signed AS THE
        // OWNER — the empty owner's own bootstrap requester (empty ⇒
        // snapshot-loss recovery) would adopt the stale key back and its
        // checkpoint root would never match again. Production daemons have
        // distinct identities (a stale replica's response is not
        // owner-authorized), so silence the owner's requester: it is not
        // the machinery under test.
        owner_sync.silence_bootstrap();
        owner_sync.start().await.expect("start owner");

        // The replica's request must be answered with the checkpoint-bearing
        // empty full delta; adopting it removes the stale key and raises the
        // high-water mark to the served checkpoint (convergence reachable).
        // Poll generously: virtual time advances the requester schedule, but
        // the signing/delivery pipeline runs in REAL time (blocking-pool
        // ML-DSA ops) — each iteration donates a real scheduling window, so
        // under CPU contention more iterations are needed, not more virtual
        // seconds.
        let mut cleaned = false;
        for _ in 0..400 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let s = joiner.read().await;
            if s.get("k_stale").is_none() && s.highest_checkpoint_seq == 3 {
                cleaned = true;
                break;
            }
        }
        assert!(
            cleaned,
            "the checkpointed empty owner's response must full-replace the \
             stale replica (key removed, checkpoint HWM adopted)"
        );
        assert!(
            joiner.read().await.is_empty(),
            "replica converges to the owner's (empty) state"
        );
    }

    /// WHY (round-1 review — missed-delta recovery): a snapshot-restored
    /// NON-OWNER replica is non-empty, but may have missed deltas written
    /// while it was offline, and the gossip cache only replays ~60s. The
    /// old `is_empty()` bootstrap gate meant such a replica NEVER requested
    /// state — the missed keys were unrecoverable without another restart
    /// race. Non-owner replicas must always run the front burst.
    #[tokio::test(start_paused = true)]
    async fn restored_non_empty_replica_still_requests_missed_state() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-238-missed-delta";

        // Owner holds k_old AND k_new (k_new written while the replica was
        // "offline" — i.e. absent from the replica's restored snapshot).
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        owned
            .put(
                "k_old".to_string(),
                b"v_old".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put k_old");
        owned
            .put(
                "k_new".to_string(),
                b"v_new".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put k_new");
        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        // Snapshot-restored replica: NON-empty (has k_old), anchored on the
        // owner, local agent is NOT the owner. Under the old gate this
        // replica never requested anything.
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::Persistence,
        );
        replica
            .put(
                "k_old".to_string(),
                b"v_old".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed restored key");
        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        // The front burst must fire despite the replica being non-empty,
        // and the owner's full-state response must deliver the missed key.
        let mut recovered = false;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if joiner.read().await.get("k_new").is_some() {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "a restored non-empty non-owner replica must still request \
             state and recover deltas it missed while offline"
        );
    }

    /// WHY (issue #238 — zombie subscription + transient policy misreport):
    /// a replica that joins while the store owner is offline must still
    /// converge when the owner returns AFTER the front-loaded request
    /// schedule has exhausted. Before the fix the requester died at ~51s
    /// and nothing ever asked again; the replica stayed permanently empty
    /// (and permanently reported the `signed` replica-default policy) until
    /// a full daemon restart minted a fresh schedule. Paused time drives
    /// the virtual clock, so the multi-minute scenario runs in moments.
    #[tokio::test(start_paused = true)]
    async fn requester_tail_recovers_when_owner_returns_after_front_schedule() {
        let node = make_node().await;
        // Sign as the owner so the OwnerAnnounce path (policy refresh) is
        // exercised: v2 delivery exposes the verified sender AgentId, which
        // learn_ownership requires to equal the claimed owner.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-238-zombie";

        // Empty replica anchored on the (offline) owner — exactly what the
        // daemon's rehydration path builds for a joined store.
        let replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::RestParam,
        );
        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");

        // The entire front schedule (~51s) fires into the void.
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(
            joiner.read().await.is_empty(),
            "nobody was online to answer the front schedule"
        );
        assert_eq!(
            *joiner.read().await.policy(),
            AccessPolicy::Signed,
            "replica still reports its construction-default policy while \
             the owner is away (the transient misreport under test)"
        );

        // The owner comes online only AFTER the front schedule exhausted —
        // the window in which the old requester was already dead.
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::AppendOnly,
        )
        .expect("kv store");
        owned
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put");
        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        // The persistent tail must ask again and converge the data.
        let mut converged = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if !joiner.read().await.is_empty() {
                converged = true;
                break;
            }
        }
        assert!(
            converged,
            "the tail requester must recover the store once the owner \
             returns (zombie subscription, issue #238)"
        );
        assert_eq!(
            joiner.read().await.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "the owner's key must arrive via the state response"
        );

        // Defect 3: the owner's announce rides the same recovery, so the
        // policy misreport heals with the data (poll — the announce and the
        // full-delta response are separate messages).
        let mut policy_ok = false;
        for _ in 0..60 {
            if *joiner.read().await.policy() == AccessPolicy::AppendOnly {
                policy_ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(
            policy_ok,
            "the owner announce must refresh the replica policy \
             (transient `signed` misreport, issue #238)"
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
            if let Ok(KvSyncMessage::StateRequest { requester }) =
                bincode::deserialize::<KvSyncMessage>(&msg.payload)
            {
                if requester == from {
                    n += 1;
                }
            }
        }
        n
    }

    /// WHY: the v2 digest commits to the served entry set so a requester
    /// can verify completeness LOCALLY. It must be deterministic across
    /// replicas, sensitive to content, insensitive to the (placeholder)
    /// name, and bound to the store id; a full delta's carried digest must
    /// equal the serving store's local digest.
    #[test]
    fn served_digest_is_deterministic_content_bound_and_name_independent() {
        let owner = agent(1);
        let mut a = KvStore::new(
            store_id(1),
            "alpha".to_string(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        let mut b = KvStore::new(store_id(1), "beta".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        // Empty stores: same id ⇒ same digest; the name is not content.
        assert_eq!(a.served_digest(), b.served_digest());
        let c = KvStore::new(
            store_id(2),
            "alpha".to_string(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        assert_ne!(
            a.served_digest(),
            c.served_digest(),
            "the store id binds the digest (cross-store replay defense)"
        );

        // The same entry bytes in both stores ⇒ the same digest, however
        // they got there (writer tags are transport, not content).
        let entry = KvEntry::new("k".to_string(), b"v".to_vec(), "text/plain".to_string());
        let mut d1 = KvStoreDelta::new(1);
        d1.added.insert("k".to_string(), (entry, (peer(1), 1)));
        a.merge_delta(&d1, peer(1), Some(&owner)).expect("merge a");
        b.merge_delta(&d1, peer(1), Some(&owner)).expect("merge b");
        assert_eq!(a.served_digest(), b.served_digest());

        // A delta's served digest exists only for full-state shapes
        // (name_update present), and then equals the local digest.
        assert_eq!(
            d1.served_digest(&store_id(1)),
            None,
            "incremental shape must not impersonate a full serve"
        );
        d1.name_update = Some(a.name_register().clone());
        assert_eq!(d1.served_digest(&store_id(1)), Some(a.served_digest()));

        // Different membership ⇒ different digest.
        let entry2 = KvEntry::new("k2".to_string(), b"w".to_vec(), "text/plain".to_string());
        let mut d2 = KvStoreDelta::new(2);
        d2.added.insert("k2".to_string(), (entry2, (peer(1), 2)));
        b.merge_delta(&d2, peer(1), Some(&owner)).expect("merge b2");
        assert_ne!(a.served_digest(), b.served_digest());
    }

    /// WHY (issue #240, residual 1 — the cross-topic loss window): the full
    /// delta travels on the main topic, its marker on the side topic, with
    /// no delivery coupling. If the delta is lost while the marker
    /// survives, the v1 rule stopped a non-empty requester with incomplete
    /// history. With the v2 digest the requester detects the mismatch
    /// (local {k2} vs declared {k1,k2}) and keeps asking until the real
    /// state arrives.
    #[tokio::test(start_paused = true)]
    async fn lost_full_delta_with_surviving_marker_keeps_requester_asking() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-240-lost-broadcast";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // The full holder state (owner offline for now): {k1, k2}.
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        owned
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("k1");
        owned
            .put(
                "k2".to_string(),
                b"v2".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("k2");

        // The joiner holds only k2 — "one live incremental delta" — with
        // entry bytes IDENTICAL to the holder's (merged out of the holder's
        // own full delta), so the post-recovery digests can match exactly.
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::RestParam,
        );
        let k2_only = {
            let full = owned.full_delta().expect("full delta");
            let (key, (entry, tag)) = full
                .added
                .iter()
                .find(|(k, _)| k.as_str() == "k2")
                .expect("k2 in full delta");
            let mut d = KvStoreDelta::new(1);
            d.added.insert(key.clone(), (entry.clone(), *tag));
            d
        };
        replica
            .merge_delta(&k2_only, peer(1), Some(&owner_id))
            .expect("seed k2");
        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        // The loss window: the marker survives, the full delta does not.
        // Publish ONLY the v2 marker the holder would have sent.
        let marker = KvSyncMessage::StateServedV2 {
            responder: peer(1),
            digest: owned.served_digest(),
            entry_count: 2,
        };
        let bytes = bincode::serialize(&marker).expect("serialize marker");
        pubsub
            .publish(side.clone(), bytes::Bytes::from(bytes))
            .await
            .expect("publish marker");

        // Well past the front burst the requester must STILL be asking —
        // its local digest ({k2}) does not match the declaration ({k1,k2}).
        let mut requests = 0;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            requests += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert!(
            requests > 0,
            "a requester whose full delta was lost must keep asking (digest mismatch)"
        );
        assert!(
            joiner.read().await.get("k1").is_none(),
            "the lost broadcast never arrived"
        );

        // The real holder returns: the next serve delivers {k1,k2}, the
        // local digest then matches the declaration, and the tail stops.
        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        let mut recovered = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get("k1").is_some() {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "the still-alive requester must recover the lost key"
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

    /// WHY (issue #240, residual 2 — deletion cold-sync): a checkpoint-less
    /// full delta carries only live entries, so a plain merge could never
    /// delete a stale replica's obsolete keys. The digest-verified
    /// full-replace adopt closes that: the serve's delta content is bound
    /// to the holder's declared digest, so pruning local keys it omits is
    /// safe. A plain v1-era merge leaves the stale key in place (the
    /// pre-#240 behavior the issue describes).
    #[tokio::test(start_paused = true)]
    async fn digest_verified_full_serve_prunes_stale_keys() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-240-prune-stale";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // Owner: checkpoint-less, holding only k_live.
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        owned
            .put(
                "k_live".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put");

        // Stale replica: k_live (byte-identical, from the owner's own full
        // delta) PLUS k_stale, an obsolete key the owner deleted while the
        // replica was away. Started FIRST so its subscriptions are fully
        // registered before any response can be published (in-process
        // paused-time harness).
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::Persistence,
        );
        let live_only = {
            let full = owned.full_delta().expect("full delta");
            let (key, (entry, tag)) = full
                .added
                .iter()
                .find(|(k, _)| k.as_str() == "k_live")
                .expect("k_live in full delta");
            let mut d = KvStoreDelta::new(1);
            d.added.insert(key.clone(), (entry.clone(), *tag));
            d
        };
        replica
            .merge_delta(&live_only, peer(1), Some(&owner_id))
            .expect("seed k_live");
        replica
            .put(
                "k_stale".to_string(),
                b"obsolete".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed stale key");
        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        // The verified adopt must remove the stale key while k_live stays.
        let mut pruned = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let s = joiner.read().await;
            if s.get("k_stale").is_none() && s.get("k_live").is_some() {
                pruned = true;
                break;
            }
        }
        assert!(
            pruned,
            "the digest-verified full serve must prune the stale key \
             (checkpoint-less deletion cold-sync)"
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
    /// kept every empty checkpoint-less replica requesting forever (~1
    /// side-topic message per 5 minutes) because an empty non-owner holder
    /// had to stay silent. The v2 digest of the empty set is universally
    /// computable, so an empty holder can now declare authoritative
    /// emptiness ANY empty requester verifies locally — two empty replicas
    /// converging on empty is verifiably CORRECT, not false convergence.
    #[tokio::test(start_paused = true)]
    async fn empty_holder_v2_marker_terminates_empty_requester() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-240-empty-silence";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // Both EMPTY non-owner replicas anchored on the (offline) owner.
        let joiner = KvStoreSync::new(
            KvStore::new_replica(
                store_id(1),
                String::new(),
                Some(owner_id),
                crate::kv::store::AnchorChannel::RestParam,
            ),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let holder = KvStoreSync::new(
            KvStore::new_replica(
                store_id(1),
                String::new(),
                Some(owner_id),
                crate::kv::store::AnchorChannel::RestParam,
            ),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(agent(3)),
        )
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
             requester's tail (genuinely-empty stores converge silently)"
        );
    }

    /// WHY: wire compatibility is additive — a fleet with only v1 (older)
    /// responders must behave exactly as before: a v1 marker plus local
    /// state converges the requester. The v2 machinery must not require
    /// v2 markers to make progress against old peers.
    #[tokio::test(start_paused = true)]
    async fn v1_marker_from_old_peer_still_converges() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-240-v1-compat";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let joiner = KvStoreSync::new(
            KvStore::new_replica(
                store_id(1),
                String::new(),
                Some(owner_id),
                crate::kv::store::AnchorChannel::RestParam,
            ),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        // An "old peer" answers a request: full delta on the main topic,
        // v1 StateServed marker on the side topic — never a v2 marker.
        tokio::time::sleep(Duration::from_secs(20)).await;
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        owned
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("k1");
        let full = owned.full_delta().expect("full delta");
        let encoded = encode_delta(peer(1), &full).expect("encode full");
        pubsub
            .publish(topic.to_string(), bytes::Bytes::from(encoded))
            .await
            .expect("publish full delta");
        let marker = KvSyncMessage::StateServed {
            responder: peer(1),
            empty: false,
            checkpoint_seq: None,
        };
        let marker_bytes = bincode::serialize(&marker).expect("serialize v1 marker");
        pubsub
            .publish(side.clone(), bytes::Bytes::from(marker_bytes))
            .await
            .expect("publish v1 marker");

        let mut recovered = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get("k1").is_some() {
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
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-240-tampered";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        let joiner = KvStoreSync::new(
            KvStore::new_replica(
                store_id(1),
                String::new(),
                Some(owner_id),
                crate::kv::store::AnchorChannel::RestParam,
            ),
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;

        // The tampered marker: a random digest no real state can match.
        let marker = KvSyncMessage::StateServedV2 {
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
        assert!(
            joiner.read().await.is_empty(),
            "no state can have been adopted from a forged declaration"
        );

        // The genuine holder appears; its fresh declaration replaces the
        // tampered one (per-responder latest-wins) and recovery completes.
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        owned
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("k1");
        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        let mut recovered = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get("k1").is_some() {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "a tampered marker must not wedge recovery from a genuine holder"
        );
    }

    /// WHY (F1, fix-loop — delete+recreate wedge): `KvEntry::merge`
    /// preserves the EARLIEST `created_at`, so a replica holding the
    /// original entry and an owner that deleted+re-created the key
    /// permanently disagree on `created_at`. A served digest committing it
    /// could never match and the requester would wedge at capped cadence
    /// forever. The digest excludes `created_at` (merge-converged fields
    /// only), so the re-created key converges.
    #[tokio::test(start_paused = true)]
    async fn recreated_key_converges_after_owner_delete_and_recreate() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-240-recreate";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");

        // The ORIGINAL entry, as the replica synced it before going offline.
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        owned
            .put(
                "k".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("original put");
        // Age the replica's copy deterministically: even in the same
        // wall-clock millisecond, the replica's created/updated timestamps
        // are strictly older than the re-created entry's.
        let mut aged = owned.get("k").expect("original entry").clone();
        aged.created_at -= 10_000;
        aged.updated_at -= 10_000;

        // The owner DELETES and RE-CREATES the key while the replica is
        // away: the owner's entry now carries a fresh created_at.
        owned.remove("k").expect("owner delete");
        owned
            .put(
                "k".to_string(),
                b"v2".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner recreate");

        // The replica returns holding the ORIGINAL (aged) entry.
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::Persistence,
        );
        let mut seed = KvStoreDelta::new(1);
        seed.added.insert("k".to_string(), (aged, (peer(1), 1)));
        replica
            .merge_delta(&seed, peer(1), Some(&owner_id))
            .expect("seed original entry");
        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let mut probe = pubsub.subscribe(side.clone()).await;
        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        // The re-created value must arrive…
        let mut recovered = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if joiner.read().await.get("k").map(|e| e.value.clone()) == Some(b"v2".to_vec()) {
                recovered = true;
                break;
            }
        }
        assert!(recovered, "the re-created entry must merge");

        // …and the requester must CONVERGE, not wedge on the created_at
        // mismatch (the pre-fix failure mode).
        tokio::time::sleep(Duration::from_secs(160)).await;
        drain_state_requests(&mut probe, peer(2)).await;
        let mut relapse = 0;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            relapse += drain_state_requests(&mut probe, peer(2)).await;
        }
        assert_eq!(
            relapse, 0,
            "a delete+recreate must not wedge the requester on created_at"
        );
    }

    /// WHY (F2, fix-loop — multi-writer truncation): absence from a
    /// verified serve proves deletion ONLY when the sender is the sole
    /// possible content author. In an Allowlisted store the owner's serve
    /// can be legitimately incomplete about co-writers' keys, so the adopt
    /// must NOT prune there — otherwise an owner-only serve truncates an
    /// allowlisted writer's legitimate key during the bootstrap window.
    #[tokio::test(start_paused = true)]
    async fn allowlisted_writer_key_survives_owner_only_serve() {
        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner_id = kp.agent_id();
        let ctx = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(ctx)).expect("pubsub"));
        let topic = "kv-240-allowlisted";
        let writer = agent(7);

        // Owner: Allowlisted, holding only k_owner.
        let mut owned = KvStore::new(
            store_id(1),
            "log".to_string(),
            owner_id,
            AccessPolicy::Allowlisted,
        )
        .expect("kv store");
        owned.allow_writer(writer, &owner_id).expect("allow writer");
        owned
            .put(
                "k_owner".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put");

        // Replica: anchored on the owner and already POLICY-AWARE (a
        // restored replica has the allowlist persisted; the merge below
        // requires it — under the Signed default the writer's key would be
        // rejected outright). It holds k_owner (aged copy from the owner's
        // own delta — the serve must refresh its updated_at, proving the
        // verified adopt path actually ran) and k_writer, written by the
        // allowlisted writer, which the owner has NOT merged.
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner_id),
            crate::kv::store::AnchorChannel::Persistence,
        );
        replica
            .learn_ownership(
                owner_id,
                AccessPolicy::Allowlisted,
                owned.policy_version(),
                &owner_id,
            )
            .expect("learn policy");
        // The replica must also know the allowlist itself (learned via
        // owner-gated deltas in production) or the writer's key merge is
        // rejected by access control.
        replica
            .allow_writer(writer, &owner_id)
            .expect("learn allowlist");
        let k_owner_seed = {
            let full = owned.full_delta().expect("full delta");
            let (key, (entry, tag)) = full
                .added
                .iter()
                .find(|(k, _)| k.as_str() == "k_owner")
                .expect("k_owner in full delta");
            let mut aged = entry.clone();
            aged.created_at -= 10_000;
            aged.updated_at -= 10_000;
            let mut d = KvStoreDelta::new(1);
            d.added.insert(key.clone(), (aged, *tag));
            d
        };
        replica
            .merge_delta(&k_owner_seed, peer(1), Some(&owner_id))
            .expect("seed k_owner");
        let writer_entry = KvEntry::new(
            "k_writer".to_string(),
            b"w".to_vec(),
            "text/plain".to_string(),
        );
        let mut writer_delta = KvStoreDelta::new(2);
        writer_delta
            .added
            .insert("k_writer".to_string(), (writer_entry, (peer(7), 1)));
        replica
            .merge_delta(&writer_delta, peer(7), Some(&writer))
            .expect("seed k_writer");
        let owner_updated_at = owned.get("k_owner").expect("owner entry").updated_at;

        let joiner = KvStoreSync::new(
            replica,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(2),
            Some(agent(2)),
        )
        .expect("joiner sync");
        joiner.start().await.expect("start joiner");
        let owner_sync = KvStoreSync::new(
            owned,
            Arc::clone(&pubsub),
            topic.to_string(),
            peer(1),
            Some(owner_id),
        )
        .expect("owner sync");
        owner_sync.start().await.expect("start owner");

        // Drive several serve windows (the requester keeps asking — its
        // digest {k_owner,k_writer} never matches the owner's {k_owner}
        // declaration until the owner absorbs the co-write).
        let mut serve_landed = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let s = joiner.read().await;
            assert!(
                s.get("k_writer").is_some(),
                "an owner-only serve must NOT prune an allowlisted writer's key"
            );
            if s.get("k_owner").map(|e| e.updated_at) == Some(owner_updated_at) {
                serve_landed = true;
            }
        }
        assert!(
            serve_landed,
            "the owner's verified serve must have merged (aged entry refreshed)"
        );
    }

    /// WHY (F3, fix-loop — tombstone + hardcoded-tag deadlock): the adopt's
    /// prune is a local observe-remove, tombstoning the tags a previous
    /// full delta used. With a hardcoded synthetic tag, a later serve
    /// re-adding the same key would be silently rejected forever. Full
    /// deltas now mint FRESH tags, so a re-served key is accepted.
    #[test]
    fn pruned_key_is_accepted_when_re_served_with_fresh_tags() {
        let owner = agent(1);
        let mut holder = KvStore::new(store_id(1), "log".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        holder
            .put(
                "k_live".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put live");
        holder
            .put(
                "k_doomed".to_string(),
                b"x".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put doomed");

        // The replica absorbs a first full serve (both keys).
        let mut replica = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner),
            crate::kv::store::AnchorChannel::RestParam,
        );
        let s1 = holder.full_delta().expect("full delta");
        replica
            .merge_delta(&s1, peer(1), Some(&owner))
            .expect("serve 1");
        assert!(replica.get("k_doomed").is_some());

        // The holder deletes the key; the next VERIFIED serve prunes it
        // (tombstoning the first serve's synthetic tag locally).
        holder.remove("k_doomed").expect("delete");
        let s2 = holder.full_delta().expect("full delta");
        assert_eq!(
            s2.served_digest(&store_id(1)),
            Some(holder.served_digest()),
            "the serve must carry the holder's declared digest"
        );
        replica
            .merge_delta(&s2, peer(1), Some(&owner))
            .expect("serve 2");
        assert_eq!(replica.prune_to_served_set(&s2), 1);
        assert!(replica.get("k_doomed").is_none());

        // The holder RE-ADDS the key: a later serve must be accepted —
        // pre-fix, its synthetic tag was tombstoned by the prune and the
        // re-add silently dropped.
        holder
            .put(
                "k_doomed".to_string(),
                b"y".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("re-add");
        let s3 = holder.full_delta().expect("full delta");
        replica
            .merge_delta(&s3, peer(1), Some(&owner))
            .expect("serve 3");
        let entry = replica
            .get("k_doomed")
            .expect("a re-served key must be accepted after a prune");
        assert_eq!(entry.value, b"y");
    }

    /// A replayed owner's old full serve must not prune an already adopted
    /// checkpoint, including after restart. Exercise BOTH pubsub listener loops:
    /// the side-topic declaration arrives before the main-topic stale snapshot.
    #[tokio::test(start_paused = true)]
    async fn stale_checkpoint_full_serve_cannot_prune_newer_state_across_restart() {
        use crate::kv::store::{
            content_root, make_owner_checkpoint, AnchorChannel, OwnerCheckpointParams,
        };

        fn checkpointed(
            store: &KvStore,
            kp: &crate::identity::AgentKeypair,
            seq: u64,
        ) -> KvStoreDelta {
            let mut delta = store.full_delta().expect("full delta");
            delta.owner_checkpoint = Some(
                make_owner_checkpoint(OwnerCheckpointParams {
                    topic: "kv-stale-checkpoint-prune",
                    store_id: store.id(),
                    secret_key: kp.secret_key(),
                    public_key: kp.public_key(),
                    policy: store.policy(),
                    policy_version: store.policy_version(),
                    checkpoint_seq: seq,
                    content_root: content_root(store.id(), store.name(), &store.checkpoint_pairs()),
                    timestamp: 0,
                })
                .expect("checkpoint"),
            );
            delta
        }

        async fn publish(pubsub: &PubSubManager, topic: &str, delta: &KvStoreDelta) {
            pubsub
                .publish(
                    topic.to_string(),
                    bytes::Bytes::from(encode_delta(peer(1), delta).expect("encode")),
                )
                .await
                .expect("publish delta");
        }

        let node = make_node().await;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let signing = Arc::new(crate::gossip::SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(node, Some(signing)).expect("pubsub"));
        let topic = "kv-stale-checkpoint-prune";
        let side = format!("{topic}{STATE_SYNC_TOPIC_SUFFIX}");
        let mut origin = KvStore::new(store_id(1), "S".into(), owner, AccessPolicy::Signed)
            .expect("owner store");
        origin
            .put(
                "prejoin".into(),
                b"one".to_vec(),
                "text/plain".into(),
                peer(1),
            )
            .expect("prejoin");
        let mut stale = checkpointed(&origin, &kp, 1);
        for key in ["live", "offline"] {
            origin
                .put(
                    key.into(),
                    key.as_bytes().to_vec(),
                    "text/plain".into(),
                    peer(1),
                )
                .expect("put");
        }
        let mut current = checkpointed(&origin, &kp, 3);
        let temp = tempfile::tempdir().expect("snapshot directory");
        let snapshot = temp.path().join("replica.bin");
        let mut restored = None;

        for round in 0..2 {
            let replica = restored.take().unwrap_or_else(|| {
                KvStore::new_replica(
                    store_id(1),
                    String::new(),
                    Some(owner),
                    AnchorChannel::RestParam,
                )
            });
            let sync = KvStoreSync::new(
                replica,
                Arc::clone(&pubsub),
                topic.into(),
                peer(2),
                Some(agent(2)),
            )
            .expect("replica sync");
            sync.set_persist_path(snapshot.clone());
            sync.start().await.expect("start");
            current.version += 10; // fresh delivery, including same-checkpoint replay after restart
            publish(&pubsub, topic, &current).await;
            for _ in 0..100 {
                if sync.read().await.highest_checkpoint_seq == 3 + round {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(sync.read().await.highest_checkpoint_seq, 3 + round);

            // An authenticated OwnerAnnounce follows the marker on the SAME
            // side-topic queue. Observing its version proves the declaration
            // was consumed; no arbitrary sleep substitutes for that ordering.
            for message in [
                KvSyncMessage::StateServedV2 {
                    responder: peer(1),
                    digest: stale.served_digest(&store_id(1)).expect("full digest"),
                    entry_count: 1,
                },
                KvSyncMessage::OwnerAnnounce {
                    owner,
                    policy: AccessPolicy::Signed,
                    policy_version: 100 + round,
                },
            ] {
                pubsub
                    .publish(
                        side.clone(),
                        bytes::Bytes::from(bincode::serialize(&message).expect("side message")),
                    )
                    .await
                    .expect("publish side");
            }
            for _ in 0..100 {
                if sync.read().await.policy_version() == 100 + round {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(sync.read().await.policy_version(), 100 + round);
            stale.version += 1;
            publish(&pubsub, topic, &stale).await;
            // Current-checkpoint replay must also remain harmless.
            current.version += 10;
            publish(&pubsub, topic, &current).await;
            let barrier_key = format!("barrier-{round}");
            let mut barrier = KvStoreDelta::new(1000 + round);
            barrier.added.insert(
                barrier_key.clone(),
                (
                    KvEntry::new(
                        barrier_key.clone(),
                        b"barrier".to_vec(),
                        "text/plain".into(),
                    ),
                    (peer(1), 1000 + round),
                ),
            );
            publish(&pubsub, topic, &barrier).await;
            for _ in 0..100 {
                if sync.read().await.get(&barrier_key).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            {
                let state = sync.read().await;
                assert!(
                    state.get(&barrier_key).is_some(),
                    "main-topic ordering barrier"
                );
                assert!(
                    state.get("live").is_some(),
                    "stale serve must not erase newer live data"
                );
                if round == 0 {
                    assert!(
                        state.get("offline").is_some(),
                        "stale serve must not erase recovered offline data"
                    );
                }
                assert_eq!(state.highest_checkpoint_seq, 3 + round);
            }

            // Positive control: a newer genuine owner checkpoint still performs
            // authoritative deletion, removing both the named key and barrier.
            let deleted = if round == 0 { "offline" } else { "live" };
            origin.remove(deleted).expect("owner deletion");
            current = checkpointed(&origin, &kp, 4 + round);
            publish(&pubsub, topic, &current).await;
            for _ in 0..100 {
                if sync.read().await.highest_checkpoint_seq == 4 + round {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            {
                let state = sync.read().await;
                assert_eq!(state.highest_checkpoint_seq, 4 + round);
                assert!(
                    state.get(deleted).is_none(),
                    "new checkpoint deletion must apply"
                );
                assert!(
                    state.get(&barrier_key).is_none(),
                    "new checkpoint replaces complete set"
                );
                assert!(state.get("prejoin").is_some());
            }
            sync.persist().await.expect("persist");
            sync.cancel_sync();
            restored = load_snapshot(&snapshot).expect("reload");
            assert_eq!(
                restored.as_ref().expect("snapshot").highest_checkpoint_seq,
                4 + round
            );
        }
    }
}
