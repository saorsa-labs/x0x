//! ADR 0110 (slice S4 of ADR 0088): the daemon side of revocation
//! eviction, designated first.
//!
//! The pure model (rows, phases, typed waits, designation, timing, file
//! codecs) lives in [`x0x::groups::eviction`]. This module owns:
//!
//! - §1 intake: it drains the queue that the revocation choke point in
//!   `lib.rs` feeds after `verify_and_insert` returns `Ok(true)` (and the
//!   startup load), and it scans the loaded rosters for self-leave and
//!   certificate-expiry triggers. Each trigger becomes an obligation keyed
//!   by (stable group ID, target agent ID).
//! - §2: designation, ranked fallback and the typed waits, and the queue
//!   for a non-designated manual remove, ban or seal before its fallback
//!   time ([`s4_manual_request_gate`]).
//! - §3: the commit through the existing signed removal path, with the
//!   `.evjournal` prepare barrier before it and the `.evs` sidecar barrier
//!   after it, and restart resume.
//! - §5: the `revocation-evictions.evs` sidecar and the per-group
//!   `.evjournal` journals, with the ADR 0108 §5a quarantine and rebuild.
//! - Completion: a row completes only when the verified roster and crypto
//!   state exclude the target, and the saved event of a committed
//!   exclusion reached every eligible survivor (`removal_delivery`).
//!
//! The revocation-set lock is always released before this module takes a
//! group or persistence lock (§1). The S4 state lock is never held across
//! a call into a route handler.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::crypto_exclusion as ce;
use x0x::groups::eviction::{
    self as s4, CommitPermission, EvJournalV1, EvictionKey, EvictionTrigger, EvsBodyV1,
    IntakeOutcome, ObligationRow, ObligationStore, Phase, QueuedBanV1, RowAction, RowBudget,
    RowContext, S4Timing, SidecarDecodeError, SidecarState, TerminationCause,
    VerifiedAgentRevocation, WaitingCause, WaitingState,
};
use x0x::groups::{GroupInfo, GroupMemberState, GroupRole};

pub(super) mod crypto_exclusion;
mod handoff_log;
pub(super) mod owner_recovery;
pub(super) mod rebind;
mod removal_delivery;
pub(super) mod removal_journal;

pub(super) use removal_delivery::{record_committed_removal, removal_blob_serve_admitted};

/// The worker's idle re-check interval. Budgets and expiry checks run at
/// least this often; intake wakes the worker at once.
const S4_WORKER_TICK: Duration = Duration::from_secs(1);

/// After a failed commit attempt the worker retries no sooner than this.
const S4_COMMIT_RETRY: Duration = Duration::from_secs(5);

/// Retry interval of a queued ban whose target holds no seat.
const S4_UNSEATED_BAN_RETRY: Duration = Duration::from_secs(60);

/// A manual request that §2 queued instead of rekeying early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum ManualRequestKind {
    /// `DELETE /groups/:id/members/:agent_id`.
    Remove,
    /// `POST /groups/:id/ban/:agent_id`.
    Ban,
    /// `POST /groups/:id/state/seal` that would evict the target.
    Seal,
}

impl ManualRequestKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Remove => "remove",
            Self::Ban => "ban",
            Self::Seal => "seal",
        }
    }
}

#[derive(Debug, Clone)]
struct QueuedManual {
    kind: ManualRequestKind,
    queued_at_unix_ms: u64,
}

/// The ADR 0108 §5a state of the `.evs` file, with its detail.
#[derive(Debug, Clone)]
struct SidecarStatus {
    state: SidecarState,
    /// `cause` for `sidecar_unavailable`, `version` for
    /// `sidecar_newer_format`, `step` for `sidecar_quarantine_failed`.
    detail: Option<String>,
}

impl Default for SidecarStatus {
    fn default() -> Self {
        Self {
            state: SidecarState::Ok,
            detail: None,
        }
    }
}

/// The last evaluation of an open row.
#[derive(Debug, Clone)]
struct StoredEvaluation {
    permission: Option<CommitPermission>,
    action: RowAction,
    stable_group_key: String,
}

/// S4 runtime state held on [`AppState`].
pub(in crate::server) struct S4Runtime {
    /// The timing values (the measured defaults, see [`S4Timing`]).
    pub(in crate::server) timing: S4Timing,
    /// Random per-process boot identity (§2, §5).
    boot_id: [u8; 16],
    /// When this process started counting (restart sync wait, §2).
    boot_instant: Instant,
    inner: tokio::sync::Mutex<S4Inner>,
    /// ADR 0108 §5a writer lock for `revocation-evictions.evs`.
    evs_writer: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct S4Inner {
    store: ObligationStore,
    /// In-boot monotonic budgets, keyed like the rows.
    budgets: HashMap<EvictionKey, RowBudget>,
    /// The revocation-set generation at the last full reconciliation.
    reconciled_generation: Option<u64>,
    /// [`revocation_seats`] at the last full reconciliation.
    reconciled_seats: Option<[u8; 32]>,
    /// The `.evs` file was read (or found absent) at startup.
    loaded: bool,
    sidecar: SidecarStatus,
    /// `rebuilt_from` of the current `.evs` (ADR 0108 §5a).
    rebuilt_from: Vec<[u8; 16]>,
    /// A rebuild is running: rows show `rebuilding_obligation_store`.
    rebuilding: bool,
    /// The `.evs` file exists on disk.
    file_exists: bool,
    /// The store changed since the last snapshot a writer took. A writer
    /// clears it when it takes its snapshot, under this lock, and sets it
    /// again when its write fails, so a change made while the write is in
    /// flight is never cleared by that write.
    dirty: bool,
    /// Change counter for [`Self::not_durable`]: each material change of a
    /// row takes the next value.
    change_seq: u64,
    /// Rows whose latest material change is not durable yet, with the
    /// change counter of that change. A successful write retires only the
    /// changes its snapshot covered.
    not_durable: BTreeMap<EvictionKey, u64>,
    /// §2: per stable group ID, the current head catch-up round.
    head_rounds: HashMap<String, HeadRound>,
    /// §2: the last ask of each peer in the current round.
    head_round_asks: HeadRoundAsks,
    /// §2: accepted `202 queued` manual bans, persisted in the `.evs` v2
    /// extension until the ban is applied.
    queued_bans: BTreeMap<EvictionKey, u64>,
    /// The earliest next attempt to apply a queued ban.
    ban_next_attempt: HashMap<EvictionKey, Instant>,
    /// §2: manual requests queued while this node waits for its rank.
    queued_manual: HashMap<EvictionKey, Vec<QueuedManual>>,
    /// The earliest next commit attempt per row.
    next_attempt: HashMap<EvictionKey, Instant>,
    /// A typed wait set by the last commit attempt (for example a missing
    /// KeyPackage); cleared when the evaluation changes.
    attempt_wait: HashMap<EvictionKey, WaitingState>,
    /// The last evaluation per open row.
    evaluations: HashMap<EvictionKey, StoredEvaluation>,
    /// §4: rows whose first hand-off dispatch is due.
    pending_dispatch: BTreeSet<EvictionKey>,
    /// §4: admins whose current verified advert lacks
    /// `eviction_handoff_v1`, per row (unsupported attempts).
    unsupported_handoff: HashMap<EvictionKey, BTreeSet<[u8; 32]>>,
    /// §4: crypto-only exclusion holds, deliveries, catch-up frames and
    /// restart fork evidence.
    ce: crypto_exclusion::CeState,
    /// §4b(1): owner-recovery mandates, held mandates and commit deliveries.
    orc: owner_recovery::OrcState,
    /// §3: committed seated-target removals whose saved event is still
    /// being delivered to the survivors.
    removals: HashMap<EvictionKey, removal_delivery::RemovalDelivery>,
    /// §4a, §4b(2): certificate rebind deliveries, renewals and waits.
    rebind: rebind::RebindState,
    /// §1a: verified expiry hand-offs kept until this node selects the
    /// same certificate and its clock passes the raw `not_after`.
    expiry_handoffs: BTreeMap<EvictionKey, ExpiryHandoff>,
    /// [`Self::expiry_handoffs`] changed since the last `.evh` write.
    expiry_handoffs_dirty: bool,
    /// The `.evh` file has a newer layout: it is never rewritten.
    expiry_handoffs_newer_file: bool,
}

/// A kept §1a expiry hand-off.
#[derive(Debug, Clone)]
struct ExpiryHandoff {
    /// The committed digest that the hand-off names.
    certificate_digest: String,
    /// When this node received it.
    received_unix_ms: u64,
}

impl S4Inner {
    /// Record a material change of `key` that is not durable yet.
    fn mark_not_durable(&mut self, key: &EvictionKey) {
        self.change_seq = self.change_seq.saturating_add(1);
        self.not_durable.insert(key.clone(), self.change_seq);
        self.dirty = true;
    }
}

impl Default for S4Runtime {
    fn default() -> Self {
        Self::new(S4Timing::default())
    }
}

impl S4Runtime {
    /// A runtime with the given timing values.
    pub(in crate::server) fn new(timing: S4Timing) -> Self {
        let mut boot_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut boot_id);
        Self {
            timing,
            boot_id,
            boot_instant: Instant::now(),
            inner: tokio::sync::Mutex::new(S4Inner::default()),
            evs_writer: tokio::sync::Mutex::new(()),
        }
    }

    /// §2 restart rule, the minimum part only: the bounded restart sync
    /// wait from process start has elapsed (D73).
    ///
    /// This is necessary, not sufficient. ADR 0110 §2 says timeout alone
    /// must not authorize a seal: [`group_head_synced`] adds a completed
    /// current catch-up round for the group and no unresolved higher-head
    /// evidence. Every S4 seal decision uses that per-group check.
    ///
    /// The wait applies on every process start, including a first boot with
    /// no saved `.evs`. ADR 0110 §2 (L191) requires a current catch-up round
    /// before **every** seal, not only after a restart; L192 only adds that
    /// a saved, expired budget does not waive it. A missing `.evs` does not
    /// prove the local head is current: a node upgraded from a pre-S4
    /// binary loads its saved groups with no `.evs`. Harness arms that
    /// trigger within the wait therefore measure H from the wait's end.
    fn restart_wait_elapsed(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.boot_instant) >= self.timing.restart_sync_wait
    }
}

// ─── §2 head catch-up round ───────────────────────────────────────────────

/// Most peers one worker pass asks for a catch-up page, per group. The
/// pass runs every [`S4_WORKER_TICK`], so a round reaches more peers on
/// later passes.
const HEAD_ROUND_PEERS_PER_PASS: usize = 3;

/// A holder that has not answered this round is asked again after this
/// long (ADR 0110 §2: "failure to progress with an available holder is a
/// defect"). One lost request or answer must not hold a seal for the whole
/// restart sync wait: a designated admin that observes late has only the
/// rest of W before the ranked fallback may sign.
const HEAD_ROUND_REASK: Duration = Duration::from_secs(2);

/// §2: one head catch-up round of one group.
///
/// A round confirms one local head. It completes when an authenticated
/// holder answers a catch-up page, after that page is applied, with
/// exactly the local head (any holder; no quorum). If no holder answers,
/// the bounded restart sync wait from the round start ends discovery
/// (D73). A holder that reports a different head is unresolved head
/// evidence: the round cannot complete, and it restarts (asks again) after
/// the wait. A new local head starts a new round.
///
/// A retry or a new round never erases unresolved evidence (§2: "no known
/// higher/conflicting head ... may remain unresolved"). The evidence of a
/// holder clears only when that holder itself reports a head on the local
/// chain, or when it is no longer a holder. A new local head does not
/// clear it either: the round keeps only the holder, not the head it
/// reported, so the new round asks that holder again and classifies its
/// new answer against the new local chain.
#[derive(Debug, Clone)]
struct HeadRound {
    /// The local head this round confirms.
    head: String,
    started: Instant,
    /// Peers this round asked.
    asked: BTreeSet<[u8; 32]>,
    /// A verified holder reported `head` after its page was applied.
    confirmed: bool,
    /// Verified holders whose last report named a head this node does not
    /// have. Carried into each later round until resolved.
    conflicting: BTreeSet<[u8; 32]>,
}

impl HeadRound {
    fn new(head: &str, now: Instant) -> Self {
        Self {
            head: head.to_string(),
            started: now,
            asked: BTreeSet::new(),
            confirmed: false,
            conflicting: BTreeSet::new(),
        }
    }

    /// Start the next round for `head`: ask every holder again (the new
    /// start resets the [`RoundAsks`]), and keep the unresolved evidence
    /// of this round.
    fn restart(&mut self, head: &str, now: Instant) {
        let conflicting = std::mem::take(&mut self.conflicting);
        *self = Self {
            conflicting,
            ..Self::new(head, now)
        };
    }

    /// The §2 seal condition for this round. `holders` is the number of
    /// other members that could hold a later head; `unresolved` is the
    /// higher-head evidence from [`unresolved_head_evidence`].
    fn synced(
        &self,
        current_head: &str,
        holders: usize,
        unresolved: bool,
        restart_wait_elapsed: bool,
        now: Instant,
        wait: Duration,
    ) -> bool {
        restart_wait_elapsed
            && !unresolved
            && self.head == current_head
            && self.conflicting.is_empty()
            && (self.confirmed
                || holders == 0
                || now.saturating_duration_since(self.started) >= wait)
    }
}

/// Keep the round of one group current and return the peers to ask now.
/// A new local head starts a new round; a round that met a conflicting
/// report asks every holder again once the wait has passed. Both keep the
/// unresolved evidence ([`HeadRound::restart`]). Evidence of a peer that
/// is no longer a holder (it left, or it is now an open target) is
/// dropped: [`HeadRound::synced`] does not count that peer either.
fn refresh_head_round(
    rounds: &mut HashMap<String, HeadRound>,
    asks: &mut HeadRoundAsks,
    stable_group_id: &str,
    current_head: &str,
    holders: &[[u8; 32]],
    now: Instant,
    wait: Duration,
) -> Vec<[u8; 32]> {
    let round = rounds
        .entry(stable_group_id.to_string())
        .or_insert_with(|| HeadRound::new(current_head, now));
    round.conflicting.retain(|peer| holders.contains(peer));
    if round.head != current_head
        || (!round.conflicting.is_empty() && now.saturating_duration_since(round.started) >= wait)
    {
        round.restart(current_head, now);
    }
    if round.confirmed && round.conflicting.is_empty() {
        return Vec::new();
    }
    let round_asks = round_asks(asks, stable_group_id, round.started);
    // A peer that reported a head in this round is answered; a confirmed
    // round with no unresolved evidence returned above. A silent peer is
    // asked again after [`HEAD_ROUND_REASK`].
    let ask: Vec<[u8; 32]> = holders
        .iter()
        .filter(|peer| {
            !round_asks.answered.contains(*peer)
                && round_asks
                    .last_ask
                    .get(*peer)
                    .is_none_or(|at| now.saturating_duration_since(*at) >= HEAD_ROUND_REASK)
        })
        .take(HEAD_ROUND_PEERS_PER_PASS)
        .copied()
        .collect();
    round.asked.extend(ask.iter().copied());
    round_asks
        .last_ask
        .extend(ask.iter().map(|peer| (*peer, now)));
    ask
}

/// The ask bookkeeping of one round. It belongs to the round that started
/// at `started` only: a new round (a retry or a new local head) starts
/// with none, so it asks every holder again.
#[derive(Debug)]
struct RoundAsks {
    started: Instant,
    /// The last ask time of each peer in this round.
    last_ask: BTreeMap<[u8; 32], Instant>,
    /// Peers that answered this round; they are not asked again in it.
    /// This is separate from [`HeadRound::conflicting`], which a new
    /// round keeps.
    answered: BTreeSet<[u8; 32]>,
}

/// Per stable group ID: the asks of the group's current round.
type HeadRoundAsks = HashMap<String, RoundAsks>;

/// The asks of the round of `stable_group_id` that started at `started`.
fn round_asks<'a>(
    asks: &'a mut HeadRoundAsks,
    stable_group_id: &str,
    started: Instant,
) -> &'a mut RoundAsks {
    let fresh = || RoundAsks {
        started,
        last_ask: BTreeMap::new(),
        answered: BTreeSet::new(),
    };
    let entry = asks
        .entry(stable_group_id.to_string())
        .or_insert_with(fresh);
    if entry.started != started {
        *entry = fresh();
    }
    entry
}

/// How a holder's reported head relates to the local verified chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadReport {
    /// The local head itself, or a head on the local verified chain
    /// before it (the holder is behind, for example a survivor that has
    /// not yet received this node's own exclusion). The holder holds
    /// nothing this node lacks.
    OnLocalChain,
    /// A head this node does not have: a later head, or a sibling. This
    /// is unresolved higher-head evidence (§2).
    Unknown,
}

/// Classify `reported` against the local verified chain: the current head
/// and every head the retained commit log links (each commit's own hash
/// and its parent). A head older than the retained log cannot be proved
/// an ancestor and stays [`HeadReport::Unknown`].
fn classify_head_report(info: &GroupInfo, reported: &str) -> HeadReport {
    let on_chain = reported == info.state_hash
        || info.commit_log.iter().any(|retained| {
            retained.commit.state_hash == reported
                || retained.commit.prev_state_hash.as_deref() == Some(reported)
        });
    if on_chain {
        HeadReport::OnLocalChain
    } else {
        HeadReport::Unknown
    }
}

/// Record one verified, applied, non-truncated catch-up page answer. A
/// holder at the local head or behind it on the local chain completes the
/// round: it answered and holds no later head. A holder at a head this
/// node does not have blocks the seal (the stale-replica protection).
/// Only a report about a later or sibling head is evidence; a survivor
/// that is behind must not block the delivery that brings it forward. A
/// report for a new local head starts the new round first, and keeps the
/// unresolved evidence ([`HeadRound::restart`]).
fn note_head_report(
    rounds: &mut HashMap<String, HeadRound>,
    asks: &mut HeadRoundAsks,
    stable_group_id: &str,
    current_head: &str,
    sender: [u8; 32],
    report: HeadReport,
    now: Instant,
) {
    let round = rounds
        .entry(stable_group_id.to_string())
        .or_insert_with(|| HeadRound::new(current_head, now));
    if round.head != current_head {
        round.restart(current_head, now);
    }
    round_asks(asks, stable_group_id, round.started)
        .answered
        .insert(sender);
    match report {
        HeadReport::OnLocalChain => {
            round.confirmed = true;
            round.conflicting.remove(&sender);
        }
        HeadReport::Unknown => {
            round.conflicting.insert(sender);
        }
    }
}

/// Other active members that could hold a later head of `info`: every
/// active member except this node and the targets of open rows.
fn head_holders(
    info: &GroupInfo,
    local: &[u8; 32],
    excluded: &BTreeSet<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut holders: Vec<(bool, [u8; 32])> = info
        .active_members()
        .filter_map(|member| {
            super::parse_agent_id_hex(&member.agent_id)
                .ok()
                .map(|agent| (!member.role.at_least(GroupRole::Admin), *agent.as_bytes()))
        })
        .filter(|(_, id)| id != local && !excluded.contains(id))
        .collect();
    // Admins first: they sign membership commits.
    holders.sort();
    holders.dedup();
    holders.into_iter().map(|(_, id)| id).collect()
}

/// §2 "no known higher/conflicting head or incomplete replay may remain
/// unresolved": the existing catch-up machinery's open evidence for one
/// group. That is a queued membership event that waits for a missing
/// predecessor or replay, epoch-ahead traffic the epoch-ahead catch-up is
/// still chasing (#1427), or an open catch-up page stream or replay fence
/// (#1113).
async fn unresolved_head_evidence(
    state: &AppState,
    group_key: &str,
    info: &GroupInfo,
    local_epoch: u64,
) -> bool {
    let ids = [
        group_key.to_string(),
        info.stable_group_id().to_string(),
        info.mls_group_id.clone(),
    ];
    let queued = {
        let pending = state.treekem_pending_events.read().await;
        ids.iter()
            .any(|id| pending.get(id).is_some_and(|queue| !queue.is_empty()))
    };
    if queued {
        return true;
    }
    let ahead = {
        let targets = state.treekem_epoch_ahead_targets.lock().await;
        ids.iter().any(|id| {
            targets
                .get(id)
                .is_some_and(|target| target.epoch > local_epoch)
        })
    };
    ahead || super::self_leave_rekey_fence_any_open(&ids)
}

/// The local TreeKEM epoch of a group, or its saved secret epoch.
async fn local_epoch_of(state: &AppState, group_key: &str, info: &GroupInfo) -> u64 {
    super::current_treekem_epoch(state, group_key)
        .await
        .unwrap_or(info.secret_epoch)
}

/// §2: whether this replica may seal in `group_key` now. Requires the
/// restart minimum, a completed current catch-up round for the current
/// local head, and no unresolved higher-head evidence. It re-reads the
/// head and the evidence on every call, so a caller can check just before
/// a seal.
pub(super) async fn group_head_synced(state: &AppState, group_key: &str) -> bool {
    let runtime = &state.revocation_evictions;
    let now = Instant::now();
    if !runtime.restart_wait_elapsed(now) {
        return false;
    }
    let Some((key, info)) = ({
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, group_key)
            .map(|(key, info)| (key.to_string(), info.clone()))
    }) else {
        return false;
    };
    let local_epoch = local_epoch_of(state, &key, &info).await;
    let unresolved = unresolved_head_evidence(state, &key, &info, local_epoch).await;
    let local = *state.agent.agent_id().as_bytes();
    let inner = runtime.inner.lock().await;
    let excluded: BTreeSet<[u8; 32]> = inner
        .store
        .open_rows_for_group(info.stable_group_id())
        .map(|row| row.target)
        .chain(
            inner
                .queued_bans
                .keys()
                .filter(|key| key.stable_group_id == info.stable_group_id())
                .map(|key| key.target),
        )
        .collect();
    let holders = head_holders(&info, &local, &excluded).len();
    inner
        .head_rounds
        .get(info.stable_group_id())
        .is_some_and(|round| {
            round.synced(
                &info.state_hash,
                holders,
                unresolved,
                true,
                now,
                runtime.timing.restart_sync_wait,
            )
        })
}

/// Test-only: one line of the S4 seal state of `target_hex` in
/// `group_key`, for a W3-H receipt (#1533 late-observation flake). It reads
/// every input of the seal decision: the row, the last evaluation, the
/// last attempt (wait and next time), the head round and each part of the
/// higher-head evidence. It changes nothing.
#[cfg(test)]
pub(in crate::server) async fn seal_probe_for_test(
    state: &AppState,
    group_key: &str,
    target_hex: &str,
) -> String {
    let Some((key_name, info)) = ({
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, group_key)
            .map(|(key, info)| (key.to_string(), info.clone()))
    }) else {
        return "group not found".to_string();
    };
    let Ok(target) = super::parse_agent_id_hex(target_hex) else {
        return "bad target".to_string();
    };
    let stable = info.stable_group_id().to_string();
    let ids = [key_name.clone(), stable.clone(), info.mls_group_id.clone()];
    let local_epoch = local_epoch_of(state, &key_name, &info).await;
    let queued: usize = {
        let pending = state.treekem_pending_events.read().await;
        ids.iter()
            .map(|id| pending.get(id).map_or(0, std::collections::VecDeque::len))
            .sum()
    };
    let ahead: Option<u64> = {
        let targets = state.treekem_epoch_ahead_targets.lock().await;
        ids.iter()
            .filter_map(|id| targets.get(id).map(|target| target.epoch))
            .max()
    };
    let fence = super::self_leave_rekey_fence_any_open(&ids);
    let synced = group_head_synced(state, &key_name).await;
    let key_package =
        super::holds_member_key_package_for_removal(state, &key_name, target_hex).await;
    let key = EvictionKey::new(stable, *target.as_bytes());
    let now = Instant::now();
    let inner = state.revocation_evictions.inner.lock().await;
    let row = inner.store.get(&key).map(|row| {
        format!(
            "phase={} waiting={:?}",
            row.phase.as_str(),
            row.waiting.as_ref().map(|waiting| waiting.cause.as_str())
        )
    });
    let evaluation = inner
        .evaluations
        .get(&key)
        .map(|evaluation| format!("{:?} {:?}", evaluation.action, evaluation.permission));
    let attempt_wait = inner
        .attempt_wait
        .get(&key)
        .map(|waiting| waiting.cause.as_str());
    let next_attempt_ms = inner
        .next_attempt
        .get(&key)
        .map(|at| s4::duration_ms(at.saturating_duration_since(now)));
    let elapsed_ms = inner
        .budgets
        .get(&key)
        .map(|budget| s4::duration_ms(budget.elapsed(now)));
    let round = inner.head_rounds.get(info.stable_group_id()).map(|round| {
        format!(
            "current_head={} confirmed={} asked={} conflicting={} age_ms={}",
            round.head == info.state_hash,
            round.confirmed,
            round.asked.len(),
            round.conflicting.len(),
            s4::duration_ms(now.saturating_duration_since(round.started))
        )
    });
    format!(
        "row={row:?} evaluation={evaluation:?} attempt_wait={attempt_wait:?} \
         next_attempt_in_ms={next_attempt_ms:?} elapsed_ms={elapsed_ms:?} \
         head_synced={synced} round={round:?} pending_events={queued} \
         epoch_ahead={ahead:?} local_epoch={local_epoch} fence_open={fence} \
         key_package={key_package}"
    )
}

/// §2: the catch-up response handler calls this for each verified,
/// applied, non-truncated page that carries the responder's saved head
/// (`responder_state_hash`). The sender is an active, unrevoked member;
/// the handler checked that. §3: the same answer is the sender's survivor
/// convergence evidence for the S4 deliveries of the group
/// ([`crypto_exclusion::note_survivor_head`]).
pub(in crate::server) async fn note_catchup_head(
    state: &AppState,
    group_ids: &[String],
    sender_hex: &str,
    reported: Option<&str>,
) {
    let Some(reported) = reported else {
        return;
    };
    let Ok(sender) = super::parse_agent_id_hex(sender_hex) else {
        return;
    };
    let current = {
        let groups = state.named_groups.read().await;
        group_ids.iter().find_map(|id| {
            crate::server::resolve_group_entry_locked(&groups, id).map(|(_, info)| {
                (
                    info.stable_group_id().to_string(),
                    info.state_hash.clone(),
                    classify_head_report(info, reported),
                )
            })
        })
    };
    let Some((stable, head, report)) = current else {
        return;
    };
    let mut inner = state.revocation_evictions.inner.lock().await;
    // §3: the answer is also the sender's convergence evidence for the
    // S4 deliveries of this group whose result is the reported head.
    crypto_exclusion::note_survivor_head(&mut inner, &stable, sender.as_bytes(), reported);
    // Only groups with S4 work keep a round (the worker pass creates it).
    if !inner.head_rounds.contains_key(&stable) {
        return;
    }
    let state_inner = &mut *inner;
    note_head_report(
        &mut state_inner.head_rounds,
        &mut state_inner.head_round_asks,
        &stable,
        &head,
        *sender.as_bytes(),
        report,
        Instant::now(),
    );
}

/// ADR 0094 host-commit gate (§5). S4 creates or materially writes its
/// files only after host commit. This tree has no ADR 0094 upgrade-trial
/// state machine yet, so every boot runs outside a trial and the gate is
/// open; the ADR's follow-up "clarify the host-commit gate when M2 is
/// absent" covers this. `waiting_for_host_commit` is shown when the gate
/// is closed.
fn host_commit_gate_open(_state: &AppState) -> bool {
    true
}

// ─── Worker ────────────────────────────────────────────────────────────────

/// The S4 worker. Runs until the task is aborted at shutdown.
pub(in crate::server) async fn run_revocation_eviction_worker(state: Arc<AppState>) {
    let timing = state.revocation_evictions.timing;
    tracing::info!(
        designated_window_ms = s4::duration_ms(timing.designated_window),
        completion_bound_ms = s4::duration_ms(timing.completion_bound),
        fallback_stagger_ms = s4::duration_ms(timing.fallback_stagger),
        restart_sync_wait_ms = s4::duration_ms(timing.restart_sync_wait),
        "ADR 0110 S4 timing values"
    );
    load_persisted_obligations(&state).await;
    let notify = state.agent.s4_revocation_intake().notified();
    loop {
        revocation_eviction_pass(&state).await;
        // The `.evh` drops a kept hand-off only after the `.evs` holds the
        // row it opened.
        if persist_obligations(&state).await {
            handoff_log::persist(&state).await;
        }
        dispatch_handoffs(&state).await;
        drive_exclusions(&state).await;
        drive_queued_bans(&state).await;
        crypto_exclusion::drive_deliveries(&state).await;
        removal_delivery::drive(&state).await;
        crypto_exclusion::retry_stash(&state).await;
        rebind::drive(&state).await;
        owner_recovery::drive(&state).await;
        tokio::select! {
            () = notify.notified() => {}
            () = tokio::time::sleep(S4_WORKER_TICK) => {}
        }
    }
}

/// One worker pass: intake, scan, reconcile, evaluate. It never commits.
pub(in crate::server) async fn revocation_eviction_pass(state: &Arc<AppState>) {
    let groups = snapshot_groups(state).await;
    let leaves = snapshot_retained_leaves(state, &groups).await;
    let revocations =
        collect_verified_agent_revocations(state, revocation_seats(&groups, &leaves)).await;
    let revoked_admins = revoked_admins_in(state, &groups).await;
    // §2: the open higher-head evidence of each group, read before the S4
    // state lock (lock order: never hold it across these reads).
    let mut head_evidence: HashMap<String, bool> = HashMap::new();
    for (group_key, info) in &groups {
        if info.withdrawn {
            continue;
        }
        let local_epoch = leaves
            .epoch(info.stable_group_id())
            .unwrap_or(info.secret_epoch);
        head_evidence.insert(
            info.stable_group_id().to_string(),
            unresolved_head_evidence(state, group_key, info, local_epoch).await,
        );
    }
    let now_unix_ms = now_unix_ms();
    let now_unix = now_unix_ms / 1000;
    let local = *state.agent.agent_id().as_bytes();
    let runtime = &state.revocation_evictions;
    let now = Instant::now();
    let restart_wait_elapsed = runtime.restart_wait_elapsed(now);
    let mut inner = runtime.inner.lock().await;
    let boot_id = runtime.boot_id;
    let mut created = Vec::new();
    for (key, trigger, incarnation) in derive_triggers(&groups, &leaves, &revocations, now_unix) {
        let outcome =
            inner
                .store
                .intake(&key, trigger, incarnation.as_deref(), now_unix_ms, boot_id);
        if outcome.changed() {
            inner.mark_not_durable(&key);
        }
        if matches!(outcome, IntakeOutcome::Created | IntakeOutcome::Reopened) {
            created.push(key);
        }
    }
    // §1a: a kept expiry hand-off opens the work once this node selects
    // the same certificate and its clock has passed the raw `not_after`;
    // T_obs is that moment, not the own trigger time `not_after + τ`.
    let kept_before = inner.expiry_handoffs.len();
    let handoff_triggers =
        expiry_handoff_triggers(&mut inner.expiry_handoffs, &groups, now_unix_ms);
    if inner.expiry_handoffs.len() != kept_before {
        inner.expiry_handoffs_dirty = true;
    }
    for (key, trigger, incarnation, observed_ms) in handoff_triggers {
        let outcome =
            inner
                .store
                .intake(&key, trigger, incarnation.as_deref(), now_unix_ms, boot_id);
        if outcome.changed() {
            inner.mark_not_durable(&key);
        }
        if matches!(outcome, IntakeOutcome::Created | IntakeOutcome::Reopened) {
            created.push(key.clone());
        }
        if let Some(row) = inner.store.get_mut(&key).filter(|row| row.phase.is_open()) {
            let earliest = row
                .earliest_handoff_receipt_unix_ms
                .map_or(observed_ms, |seen| seen.min(observed_ms));
            if row.earliest_handoff_receipt_unix_ms != Some(earliest) {
                row.earliest_handoff_receipt_unix_ms = Some(earliest);
                inner.dirty = true;
            }
        }
    }
    for key in created {
        inner
            .budgets
            .insert(key, RowBudget::resume(Duration::ZERO, now));
    }
    let mut delivering = inner.ce.delivering();
    delivering.extend(inner.removals.keys().cloned());
    let memory_only = !inner.sidecar.state.writable();
    reconcile_and_retain(
        &mut inner,
        &groups,
        &leaves,
        &delivering,
        now_unix_ms,
        memory_only,
    );
    // Rows loaded from an earlier boot resume their saved budget.
    let rows: Vec<(EvictionKey, u64)> = inner
        .store
        .rows()
        .filter(|row| row.phase.is_open())
        .map(|row| (row.key(), row.elapsed_budget_ms))
        .collect();
    for (key, saved_ms) in &rows {
        inner
            .budgets
            .entry(key.clone())
            .or_insert_with(|| RowBudget::resume(Duration::from_millis(*saved_ms), now));
    }
    let open: BTreeSet<EvictionKey> = rows.into_iter().map(|(key, _)| key).collect();
    inner.budgets.retain(|key, _| open.contains(key));
    inner.queued_manual.retain(|key, _| open.contains(key));
    inner.next_attempt.retain(|key, _| open.contains(key));
    inner.attempt_wait.retain(|key, _| open.contains(key));
    // A `terminated` row keeps its entry until the `.evs` holds the end.
    let ended: BTreeSet<EvictionKey> = inner
        .store
        .rows()
        .filter(|row| row.phase == Phase::Terminated)
        .map(ObligationRow::key)
        .collect();
    inner
        .not_durable
        .retain(|key, _| open.contains(key) || ended.contains(key));
    let queued_bans: BTreeSet<EvictionKey> = inner.queued_bans.keys().cloned().collect();
    inner
        .ban_next_attempt
        .retain(|key, _| queued_bans.contains(key));
    inner.removals.retain(|key, _| open.contains(key));
    inner.pending_dispatch.retain(|key| open.contains(key));
    inner
        .unsupported_handoff
        .retain(|key, _| open.contains(key));
    inner.evaluations.clear();
    let gate_open = host_commit_gate_open(state);
    let by_stable: HashMap<&str, (&String, &GroupInfo)> = groups
        .iter()
        .map(|(key, info)| (info.stable_group_id(), (key, info)))
        .collect();
    // §2: one head catch-up round per group with open work. A seal needs
    // the round for the current head complete and no unresolved evidence;
    // elapsed time alone never authorizes it.
    let mut group_synced: HashMap<String, bool> = HashMap::new();
    let mut head_requests: Vec<(String, x0x::identity::AgentId)> = Vec::new();
    // A queued ban is a seal too, so its group keeps a round after its row
    // completed.
    let round_keys: BTreeSet<EvictionKey> = open
        .iter()
        .chain(inner.queued_bans.keys())
        .cloned()
        .collect();
    // Work that waits for `group_head_synced` with no open row also keeps
    // its group's round, or nothing would ask for the head and the work
    // would wait until it expires (#1508 Codex P1). Each plane names its
    // groups and the peers it excludes from the holders:
    // - §4b(1): a held owner-recovery mandate (its named admins) and a
    //   restored owner-recovery delivery;
    // - §2/§3: a restored rebind delivery and a held §4b(2) self-rebind.
    let mut extra_rounds = inner.orc.head_round_groups();
    for (stable, peers) in inner.rebind.head_round_groups() {
        extra_rounds.entry(stable).or_default().extend(peers);
    }
    let open_groups: BTreeSet<String> = round_keys
        .iter()
        .map(|key| key.stable_group_id.clone())
        .chain(extra_rounds.keys().cloned())
        .collect();
    inner
        .head_rounds
        .retain(|stable, _| open_groups.contains(stable));
    inner
        .head_round_asks
        .retain(|stable, _| open_groups.contains(stable));
    for stable in &open_groups {
        let Some((group_key, info)) = by_stable.get(stable.as_str()) else {
            continue;
        };
        let excluded: BTreeSet<[u8; 32]> = round_keys
            .iter()
            .filter(|key| &key.stable_group_id == stable)
            .map(|key| key.target)
            .chain(extra_rounds.get(stable).into_iter().flatten().copied())
            .collect();
        let holders = head_holders(info, &local, &excluded);
        let state_inner = &mut *inner;
        let ask = refresh_head_round(
            &mut state_inner.head_rounds,
            &mut state_inner.head_round_asks,
            stable,
            &info.state_hash,
            &holders,
            now,
            runtime.timing.restart_sync_wait,
        );
        head_requests.extend(
            ask.into_iter()
                .map(|peer| ((*group_key).clone(), x0x::identity::AgentId(peer))),
        );
        let unresolved = head_evidence.get(stable).copied().unwrap_or(true);
        let synced = inner.head_rounds.get(stable).is_some_and(|round| {
            round.synced(
                &info.state_hash,
                holders.len(),
                unresolved,
                restart_wait_elapsed,
                now,
                runtime.timing.restart_sync_wait,
            )
        });
        group_synced.insert(stable.clone(), synced);
    }
    for key in open {
        let Some((group_key, info)) = by_stable.get(key.stable_group_id.as_str()) else {
            continue;
        };
        let Some(row) = inner.store.get(&key).cloned() else {
            continue;
        };
        let elapsed = inner
            .budgets
            .get(&key)
            .map_or(Duration::ZERO, |budget| budget.elapsed(now));
        let active_admins = active_admins_of(info);
        let target_hex = hex::encode(key.target);
        let target_seated = info
            .members_v2
            .get(&target_hex)
            .is_some_and(|member| is_seated(member.state));
        // §5 memory-only durability: every trigger S4 derives today is
        // durable elsewhere (the revocation store, the verified chain or a
        // committed certificate), so a memory-only sidecar does not hold
        // the seal. A failed write of a writable sidecar does.
        let durable = memory_only || !inner.not_durable.contains_key(&key);
        let head_synced = group_synced
            .get(&key.stable_group_id)
            .copied()
            .unwrap_or(false);
        let ctx = RowContext {
            local,
            active_admins: &active_admins,
            revoked_admins: &revoked_admins,
            quarantined: info.fork_quarantine.is_some(),
            target_seated,
            elapsed,
            head_synced,
            durable,
            now_unix,
            local_certificate_expired: local_certificate_expired(info, &local, now_unix),
        };
        let mut evaluation = s4::evaluate_row(&row, &ctx, &runtime.timing);
        if inner.rebuilding {
            evaluation.waiting = Some(WaitingState::cause(WaitingCause::RebuildingObligationStore));
            evaluation.action = RowAction::None;
        } else if !gate_open {
            evaluation.waiting = Some(WaitingState::cause(WaitingCause::WaitingForHostCommit));
            evaluation.action = RowAction::None;
        } else if evaluation.action != RowAction::None {
            if let Some(wait) = inner.attempt_wait.get(&key) {
                evaluation.waiting = Some(wait.clone());
            }
        } else {
            inner.attempt_wait.remove(&key);
        }
        // §4: a hand-off to an unsupported designated admin waits for W
        // with cause `designated_admin_unsupported`.
        if let (Some(waiting), Some(designation)) =
            (evaluation.waiting.as_mut(), evaluation.designation.as_ref())
        {
            let unsupported = inner
                .unsupported_handoff
                .get(&key)
                .is_some_and(|ids| ids.contains(&designation.designated));
            if unsupported && waiting.designated_detail == Some(s4::DesignatedWaitDetail::Rank) {
                waiting.designated_detail =
                    Some(s4::DesignatedWaitDetail::DesignatedAdminUnsupported);
            }
        }
        // §4 (D76): the crypto-only exclusion of an already-Removed target
        // is held while an Active survivor's current verified advert lacks
        // `crypto_exclusion_v1`; the state names each holder on every
        // upgraded member. §3: a saved frame that met a competing branch
        // waits for fork resolution and is never published.
        if inner.ce.fork.contains(&key) {
            evaluation.waiting = Some(WaitingState::cause(WaitingCause::WaitingForForkResolution));
            evaluation.action = RowAction::None;
        } else if !target_seated
            && row.phase == Phase::Pending
            && (info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
                || ce::is_gss_encrypted(info))
        {
            let holders = crypto_exclusion::holders(state, info, &local, &key.target);
            if holders.is_empty() {
                inner.ce.holders.remove(&key);
            } else {
                let mut waiting = WaitingState::cause(WaitingCause::WaitingForReceiverUpgrade);
                waiting.named = holders.clone();
                evaluation.waiting = Some(waiting);
                evaluation.action = RowAction::None;
                inner.ce.holders.insert(key.clone(), holders);
            }
        }
        // §1a, §4b(2): every admin other than the target is expired; the
        // row waits for an owner renewal and the admin's self-rebind.
        if let Some(wait) = rebind::row_override(&inner.rebind, info, &row, target_seated, now_unix)
        {
            evaluation.waiting = Some(wait);
            evaluation.action = RowAction::None;
        }
        // §2: each observing admin forwards the trigger evidence to every
        // eligible admin once; the dispatch time is recorded before route
        // resolution (T_obs).
        let local_is_admin = active_admins.contains(&local) && key.target != local;
        if local_is_admin && row.first_dispatch_unix_ms.is_none() {
            if let Some(stored) = inner.store.get_mut(&key) {
                stored.first_dispatch_unix_ms = Some(now_unix_ms);
            }
            inner.pending_dispatch.insert(key.clone());
            inner.dirty = true;
        }
        let designation = evaluation.designation.clone();
        let changed_designation = designation.as_ref().is_some_and(|designation| {
            row.designated != Some(designation.designated) || row.ranks != designation.ranks
        });
        // §2 (L175, L194; #1508 r7, Codex P2 6): the consumed budget is
        // written while it still gates a fallback rank, so a restart
        // resumes it and cannot extend the window. One stagger past the
        // last rank's offset (and past the completion bound) it gates
        // nothing more, so a long wait does not rewrite the sidecar on
        // every tick.
        let ranks = designation
            .as_ref()
            .map_or(row.ranks.len(), |designation| designation.ranks.len());
        let budget_cap = s4::duration_ms(
            runtime
                .timing
                .fallback_offset(ranks.saturating_add(1))
                .max(runtime.timing.completion_bound),
        );
        let mut budget_moved = false;
        if let Some(row) = inner.store.get_mut(&key) {
            let elapsed_ms = s4::duration_ms(elapsed);
            budget_moved =
                elapsed_ms != row.elapsed_budget_ms && row.elapsed_budget_ms < budget_cap;
            row.elapsed_budget_ms = elapsed_ms;
            row.boot_id = boot_id;
            if let Some(designation) = &designation {
                row.designated = Some(designation.designated);
                row.ranks = designation.ranks.clone();
            }
        }
        if changed_designation || budget_moved {
            inner.dirty = true;
        }
        inner.store.set_waiting(&key, evaluation.waiting.clone());
        inner.evaluations.insert(
            key,
            StoredEvaluation {
                permission: evaluation.permission,
                action: evaluation.action,
                stable_group_key: (*group_key).clone(),
            },
        );
    }
    if inner.rebuilding {
        // The rebuild source (§5) is the revocation store, the verified
        // chain and the committed certificates; this pass re-derived every
        // derivable row from them, so the rebuild is done.
        inner.rebuilding = false;
        inner.dirty = true;
    }
    inner.loaded = true;
    drop(inner);
    // §2: ask the round's holders for a catch-up page on the existing
    // request path. The response handler applies the page with all its
    // usual checks and then reports the responder's head
    // ([`note_catchup_head`]). Sends run detached: an offline peer must
    // not hold the worker.
    for (group_key, peer) in head_requests {
        let task_state = Arc::clone(state);
        let _admitted = state.spawn_detached(async move {
            super::request_treekem_catchup_page(&task_state, &group_key, &peer).await;
        });
    }
}

/// Drain the intake queue and, when needed, rescan the whole revocation
/// set. Only records that this node's own set holds are kept: the hook
/// already verified them, and the check guards against a stale queue.
///
/// `seats` is [`revocation_seats`] of this pass's snapshot. §1 (#1508 r7,
/// Codex P1 4): a revocation creates work only where its target has a
/// seat or a retained leaf, so a record consumed before a delayed
/// `MemberAdded` or a catch-up seats its target must be read again when
/// the seats change, although the set's generation did not.
async fn collect_verified_agent_revocations(
    state: &AppState,
    seats: [u8; 32],
) -> Vec<VerifiedAgentRevocation> {
    let intake = state.agent.s4_revocation_intake();
    let (mut items, reconcile_all) = intake.drain();
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    let generation = set.generation();
    let full = {
        let inner = state.revocation_evictions.inner.lock().await;
        reconcile_all
            || inner.reconciled_generation != Some(generation)
            || inner.reconciled_seats != Some(seats)
    };
    if full {
        for record in set.all_records() {
            if let x0x::revocation::RevokedSubject::Agent(agent) = &record.subject {
                items.push(VerifiedAgentRevocation {
                    target: *agent.as_bytes(),
                    record_hash: record.record_hash(),
                    record_bytes: bincode::serialize(&record).unwrap_or_default(),
                    from_startup_load: false,
                });
            }
        }
    }
    items.retain(|item| set.contains_hash(&item.record_hash));
    drop(set);
    if full {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.reconciled_generation = Some(generation);
        inner.reconciled_seats = Some(seats);
    }
    items
}

/// A digest of the seats that a revocation can create work on: per group,
/// each roster entry with its seat state, retained leaf and incarnation,
/// the inputs that [`derive_triggers`] reads besides the revocations.
fn revocation_seats(groups: &[(String, GroupInfo)], leaves: &RetainedLeaves) -> [u8; 32] {
    let mut sorted: Vec<&GroupInfo> = groups.iter().map(|(_, info)| info).collect();
    sorted.sort_by(|a, b| a.stable_group_id().cmp(b.stable_group_id()));
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x0x.s4.revocation-seats.v1");
    for info in sorted {
        let stable = info.stable_group_id();
        hasher.update(&(stable.len() as u64).to_le_bytes());
        hasher.update(stable.as_bytes());
        hasher.update(&[u8::from(info.withdrawn)]);
        for member in info.members_v2.values() {
            let target = super::parse_agent_id_hex(&member.agent_id)
                .map(|agent| *agent.as_bytes())
                .unwrap_or_default();
            hasher.update(&target);
            hasher.update(&[
                u8::from(is_seated(member.state)),
                match leaves.tracks(stable, &target) {
                    Some(true) => 1,
                    Some(false) => 0,
                    None => 2,
                },
            ]);
            let incarnation = ce::seat_incarnation(info, &member.agent_id).unwrap_or_default();
            hasher.update(&(incarnation.len() as u64).to_le_bytes());
            hasher.update(incarnation.as_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// Every group with its roster map key. Withdrawn groups are kept so
/// that their rows terminate (`group_deleted`).
async fn snapshot_groups(state: &AppState) -> Vec<(String, GroupInfo)> {
    state
        .named_groups
        .read()
        .await
        .iter()
        .map(|(key, info)| (key.clone(), info.clone()))
        .collect()
}

/// The admins of every group that hold a verified Agent-subject
/// revocation. Takes the revocation-set read lock alone.
async fn revoked_admins_in(state: &AppState, groups: &[(String, GroupInfo)]) -> BTreeSet<[u8; 32]> {
    let admins: BTreeSet<[u8; 32]> = groups
        .iter()
        .flat_map(|(_, info)| active_admins_of(info))
        .collect();
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    admins
        .into_iter()
        .filter(|id| set.is_agent_revoked(&x0x::identity::AgentId(*id)))
        .collect()
}

/// Admin-or-higher Active seats (legacy `Owner` is Admin-equivalent).
fn active_admins_of(info: &GroupInfo) -> Vec<[u8; 32]> {
    info.active_members()
        .filter(|member| member.role.at_least(GroupRole::Admin))
        .filter_map(|member| super::parse_agent_id_hex(&member.agent_id).ok())
        .map(|agent| *agent.as_bytes())
        .collect()
}

/// §1a: an admin whose own selected certificate is expired on its clock
/// may not seal.
fn local_certificate_expired(info: &GroupInfo, local: &[u8; 32], now_unix: u64) -> bool {
    if !owner_certified(info) {
        return false;
    }
    info.members_v2
        .get(&hex::encode(local))
        .and_then(selected_certificate_expiry)
        .is_some_and(|(_, not_after)| s4::own_expiry_trigger_due(not_after, now_unix))
}

/// The agents with a leaf in one tree, and the tree epoch.
type TrackedLeaves = (Vec<[u8; 32]>, u64);

/// Retained TreeKEM leaves per stable group ID: the agent IDs whose leaf
/// is still in this node's ratchet tree, with the tree epoch. A group whose
/// tree is busy is skipped for this pass (`None`), never read as empty.
///
/// A GSS `MlsEncrypted` group has no tree. Its entry holds the Removed
/// members that still hold the current secret
/// ([`ce::gss_secret_retained`], #1508 review P1), with the secret epoch.
#[derive(Default)]
struct RetainedLeaves {
    by_group: HashMap<String, Option<TrackedLeaves>>,
}

impl RetainedLeaves {
    fn tracks(&self, stable_group_id: &str, agent: &[u8; 32]) -> Option<bool> {
        match self.by_group.get(stable_group_id) {
            Some(Some((tracked, _))) => Some(tracked.contains(agent)),
            Some(None) => None,
            None => Some(false),
        }
    }

    fn epoch(&self, stable_group_id: &str) -> Option<u64> {
        match self.by_group.get(stable_group_id) {
            Some(Some((_, epoch))) => Some(*epoch),
            _ => None,
        }
    }

    fn known(&self, stable_group_id: &str) -> bool {
        !matches!(self.by_group.get(stable_group_id), Some(None))
    }
}

async fn snapshot_retained_leaves(
    state: &AppState,
    groups: &[(String, GroupInfo)],
) -> RetainedLeaves {
    let mut leaves = RetainedLeaves::default();
    let trees = state.treekem_groups.read().await;
    for (key, info) in groups {
        if info.withdrawn {
            continue;
        }
        if ce::is_gss_encrypted(info) {
            let retained = info
                .members_v2
                .keys()
                .filter(|member| ce::gss_secret_retained(info, member))
                .filter_map(|member| super::parse_agent_id_hex(member).ok())
                .map(|agent| *agent.as_bytes())
                .collect();
            leaves.by_group.insert(
                info.stable_group_id().to_string(),
                Some((retained, info.secret_epoch)),
            );
            continue;
        }
        if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem {
            continue;
        }
        let stable = info.stable_group_id().to_string();
        let tree = trees
            .get(key)
            .or_else(|| trees.get(&info.mls_group_id))
            .or_else(|| trees.get(&stable))
            .cloned();
        let Some(tree) = tree else {
            continue;
        };
        let entry = match tree.try_lock() {
            Ok(group) => {
                let tracked = info
                    .members_v2
                    .values()
                    .filter_map(|member| super::parse_agent_id_hex(&member.agent_id).ok())
                    .filter(|agent| group.tracks_member(agent))
                    .map(|agent| *agent.as_bytes())
                    .collect();
                Some((tracked, group.epoch()))
            }
            Err(_) => None,
        };
        leaves.by_group.insert(stable, entry);
    }
    leaves
}

fn is_seated(state: GroupMemberState) -> bool {
    matches!(state, GroupMemberState::Active | GroupMemberState::Pending)
}

fn owner_certified(info: &GroupInfo) -> bool {
    matches!(
        info.policy.admission,
        x0x::groups::policy::GroupAdmission::OwnerCertified(_)
    )
}

/// §1 and §1a: the triggers this pass observes, with the target's current
/// incarnation ([`ce::seat_incarnation`]).
fn derive_triggers(
    groups: &[(String, GroupInfo)],
    leaves: &RetainedLeaves,
    revocations: &[VerifiedAgentRevocation],
    now_unix: u64,
) -> Vec<(EvictionKey, EvictionTrigger, Option<String>)> {
    let mut out = Vec::new();
    let mut revoked_by_target: HashMap<[u8; 32], Vec<&VerifiedAgentRevocation>> = HashMap::new();
    for item in revocations {
        revoked_by_target.entry(item.target).or_default().push(item);
    }
    for (_, info) in groups {
        if info.withdrawn {
            continue;
        }
        let stable = info.stable_group_id();
        for member in info.members_v2.values() {
            let Ok(agent) = super::parse_agent_id_hex(&member.agent_id) else {
                continue;
            };
            let target = *agent.as_bytes();
            let retained_leaf = leaves.tracks(stable, &target).unwrap_or(false);
            let seated = is_seated(member.state);
            let incarnation = ce::seat_incarnation(info, &member.agent_id);
            // §1: an Agent-subject revocation creates work where the target
            // has a seat or a retained cryptographic leaf.
            if seated || retained_leaf {
                if let Some(records) = revoked_by_target.get(&target) {
                    for record in records {
                        out.push((
                            EvictionKey::new(stable, target),
                            EvictionTrigger::AgentRevocation {
                                record_hash: record.record_hash,
                                record_bytes: record.record_bytes.clone(),
                            },
                            incarnation.clone(),
                        ));
                    }
                }
            }
            // §1: a verified, chained self-leave applied to the roster
            // (including through catch-up) whose leaf is still retained.
            let self_left = member.state == GroupMemberState::Removed
                && member.removed_by.as_deref() == Some(member.agent_id.as_str());
            if self_left && retained_leaf {
                out.push((
                    EvictionKey::new(stable, target),
                    EvictionTrigger::SelfLeave {
                        commit_hash: info.state_hash.clone(),
                    },
                    incarnation.clone(),
                ));
            }
            // §1a: expiry of the committed certificate of an Active seat in
            // an OwnerCertified group, on this node's own clock + τ.
            if member.state == GroupMemberState::Active && owner_certified(info) {
                if let Some((digest, not_after)) = selected_certificate_expiry(member) {
                    if s4::own_expiry_trigger_due(not_after, now_unix) {
                        out.push((
                            EvictionKey::new(stable, target),
                            EvictionTrigger::CertificateExpiry {
                                certificate_digest: digest,
                                not_after,
                            },
                            incarnation.clone(),
                        ));
                    }
                }
            }
        }
    }
    out
}

/// §1a: the selected certificate is the one the committed roster binds to
/// the seat — its embedded bytes when they match the committed digest.
/// Returns its digest and `not_after`; `None` when it never expires or the
/// bytes are missing.
fn selected_certificate_expiry(member: &x0x::groups::GroupMember) -> Option<(String, u64)> {
    let cert = member.certificate.as_ref()?;
    let digest = x0x::groups::owner_cert::certificate_digest_hex(cert);
    if member
        .certificate_digest
        .as_deref()
        .is_some_and(|committed| committed != digest)
    {
        return None;
    }
    cert.not_after().map(|not_after| (digest, not_after))
}

/// Reconcile completion, then apply §5 retention. §1a: a renewal moves
/// the row to `terminated` with cause `certificate_valid`; §5: "Drop
/// `terminated` rows once the deletion or cancellation is durable". A row
/// this pass ended is marked not durable, and retention waits until a
/// `.evs` write holds every ended row, so the end is durable and visible
/// before the row goes. A memory-only sidecar never becomes durable, so
/// it does not hold retention.
fn reconcile_and_retain(
    inner: &mut S4Inner,
    groups: &[(String, GroupInfo)],
    leaves: &RetainedLeaves,
    delivering: &BTreeSet<EvictionKey>,
    now_unix_ms: u64,
    memory_only: bool,
) {
    let open_before: Vec<EvictionKey> = inner
        .store
        .rows()
        .filter(|row| row.phase.is_open())
        .map(ObligationRow::key)
        .collect();
    if reconcile_completion(&mut inner.store, groups, leaves, delivering, now_unix_ms) {
        inner.dirty = true;
    }
    for key in open_before {
        if inner
            .store
            .get(&key)
            .is_some_and(|row| row.phase == Phase::Terminated)
        {
            inner.mark_not_durable(&key);
        }
    }
    let end_not_durable = !memory_only
        && inner.store.rows().any(|row| {
            row.phase == Phase::Terminated && inner.not_durable.contains_key(&row.key())
        });
    if !end_not_durable && inner.store.apply_retention(now_unix_ms) {
        inner.dirty = true;
    }
}

/// Re-derive completion from the verified roster and crypto state (§1,
/// D128). A row completes only when the target holds no seat and, in a
/// TreeKEM group, no retained leaf, or, in a GSS `MlsEncrypted` group,
/// the retained commits prove a rotation after its departure
/// ([`ce::gss_secret_excluded`]). A withdrawn group terminates its rows
/// (`group_deleted`); a group this node no longer holds ends local
/// retention. Returns whether the store changed.
fn reconcile_completion(
    store: &mut ObligationStore,
    groups: &[(String, GroupInfo)],
    leaves: &RetainedLeaves,
    delivering: &BTreeSet<EvictionKey>,
    now_unix_ms: u64,
) -> bool {
    let by_stable: HashMap<&str, &GroupInfo> = groups
        .iter()
        .map(|(_, info)| (info.stable_group_id(), info))
        .collect();
    let open: Vec<EvictionKey> = store
        .rows()
        .filter(|row| row.phase.is_open())
        .map(ObligationRow::key)
        .collect();
    let mut changed = false;
    let mut gone_groups = BTreeSet::new();
    let mut withdrawn_groups = BTreeSet::new();
    for key in open {
        let Some(info) = by_stable.get(key.stable_group_id.as_str()) else {
            gone_groups.insert(key.stable_group_id.clone());
            continue;
        };
        if info.withdrawn {
            withdrawn_groups.insert(key.stable_group_id.clone());
            continue;
        }
        let target_hex = hex::encode(key.target);
        let member = info.members_v2.get(&target_hex);
        let seated = member.is_some_and(|member| is_seated(member.state));
        let stable = key.stable_group_id.as_str();
        if seated {
            // §1a/D135: an expiry-only row ends when the committed
            // certificate changed to an unexpired one (a rebind).
            if let Some(member) = member {
                let row_digests = store
                    .get(&key)
                    .map(|row| row.expiry_only().then(|| row.expired_certificates.clone()));
                if let Some(Some(expired)) = row_digests {
                    let now_unix = now_unix_ms / 1000;
                    let renewed = selected_certificate_expiry(member).map_or(
                        member.certificate.is_some(),
                        |(digest, not_after)| {
                            !expired.contains_key(&digest)
                                && !s4::own_expiry_trigger_due(not_after, now_unix)
                        },
                    );
                    if renewed {
                        changed |= store.terminate(&key, TerminationCause::CertificateValid);
                    }
                }
            }
            continue;
        }
        if delivering.contains(&key) {
            // §3: a committed crypto-only exclusion stays
            // `committed_delivery_pending` while its delivery runs.
            continue;
        }
        // A GSS group completes only on proof that a rotation excluded the
        // target (#1508 review P1), never because bounded commit history
        // lost the commit that seated it.
        if ce::is_gss_encrypted(info) {
            if !ce::gss_secret_excluded(info, &target_hex) {
                continue;
            }
        } else if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
            if !leaves.known(stable) {
                // The tree was busy; decide on a later pass.
                continue;
            }
            if leaves.tracks(stable, &key.target).unwrap_or(true) {
                continue;
            }
        }
        changed |= store.complete(
            &key,
            Some(info.state_hash.clone()),
            leaves.epoch(stable).or(Some(info.secret_epoch)),
            now_unix_ms,
        );
    }
    for stable in withdrawn_groups {
        changed |= store.terminate_group(&stable) > 0;
    }
    for stable in gone_groups {
        changed |= store.forget_group(&stable) > 0;
    }
    changed
}

// ─── §2 manual-request queue ───────────────────────────────────────────────

/// §2 amendment to ADR 0016 §6: a non-designated admin that asks to
/// remove, ban or seal an S4 target before its ranked fallback time queues
/// and hands off the request and gets `waiting_for_designated_admin`; it
/// must not rekey that target early. Returns the `202` response to send,
/// or `None` when the request may proceed (no open obligation, or this
/// node is designated or past its fallback time).
pub(in crate::server) async fn s4_manual_request_gate(
    state: &Arc<AppState>,
    group_key: &str,
    target_hex: &str,
    kind: ManualRequestKind,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let target = super::parse_agent_id_hex(target_hex).ok()?;
    let stable = {
        let groups = state.named_groups.read().await;
        let info = groups.get(group_key).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group_key)
        })?;
        info.stable_group_id().to_string()
    };
    // Bring intake up to date first, so a request that races the worker
    // still sees a just-verified revocation.
    revocation_eviction_pass(state).await;
    let key = EvictionKey::new(stable.clone(), *target.as_bytes());
    let mut inner = state.revocation_evictions.inner.lock().await;
    // §1a/D135 (#1508 review): the reconciliation above can end the row
    // of the worker's own prepared removal (a rebind landed while the
    // journal was written). That removal stops; it never continues as an
    // ordinary removal of the renewed seat.
    if s4_prepared_removal_of(&key)
        && inner.store.get(&key).map(|row| row.phase) != Some(Phase::Prepared)
    {
        return Some(s4_exclusion_cancelled_response());
    }
    let row = inner.store.get(&key)?;
    if !row.phase.is_open() {
        return None;
    }
    let evaluation = inner.evaluations.get(&key)?;
    let CommitPermission::Wait {
        designated,
        remaining,
    } = evaluation.permission.clone()?
    else {
        return None;
    };
    let rank = row
        .ranks
        .iter()
        .position(|id| id == state.agent.agent_id().as_bytes())
        .map(|index| index.saturating_add(1));
    let now_ms = now_unix_ms();
    if kind == ManualRequestKind::Ban {
        // §2: an accepted ban must be applied as a ban, after the
        // designated removal or at this node's fallback time, and must
        // survive a restart (the `.evs` v2 extension).
        inner.queued_bans.entry(key.clone()).or_insert(now_ms);
        inner.dirty = true;
    }
    inner
        .queued_manual
        .entry(key)
        .or_default()
        .push(QueuedManual {
            kind,
            queued_at_unix_ms: now_ms,
        });
    drop(inner);
    if kind == ManualRequestKind::Ban && !persist_obligations(state).await {
        tracing::warn!(
            group_id = %super::LogHexId::group(&stable),
            "ADR 0110 S4: a queued manual ban is not durable yet; the worker retries the write"
        );
    }
    let designated_hex = hex::encode(designated);
    Some((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ok": true,
            "queued": true,
            "status": WaitingCause::WaitingForDesignatedAdmin.as_str(),
            "group_id": stable,
            "target": target_hex.to_ascii_lowercase(),
            "request": kind.as_str(),
            "waiting": {
                "cause": WaitingCause::WaitingForDesignatedAdmin.as_str(),
                "designated_admin": designated_hex,
                "detail": "rank",
                "local_rank": rank,
                "remaining_ms": s4::duration_ms(remaining),
                "fallback_at_unix_ms": now_ms.saturating_add(s4::duration_ms(remaining)),
            },
        })),
    ))
}

/// §2: an explicit seal in an `OwnerCertified` group would evict a pending
/// S4 target as a side effect (ADR-0038 seal-time re-check). Before this
/// node's fallback time it defers the seal. Returns the `202` response, or
/// `None` when the seal may proceed.
pub(in crate::server) async fn s4_seal_request_gate(
    state: &Arc<AppState>,
    group_key: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let (stable, seated_targets) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(group_key).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group_key)
        })?;
        if !owner_certified(info) {
            return None;
        }
        let seated: Vec<String> = info
            .members_v2
            .values()
            .filter(|member| is_seated(member.state))
            .map(|member| member.agent_id.clone())
            .collect();
        (info.stable_group_id().to_string(), seated)
    };
    let pending: Vec<String> = {
        revocation_eviction_pass(state).await;
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .store
            .open_rows_for_group(&stable)
            .map(|row| hex::encode(row.target))
            .filter(|target| seated_targets.iter().any(|seated| seated == target))
            .collect()
    };
    for target in pending {
        if let Some(resp) =
            s4_manual_request_gate(state, group_key, &target, ManualRequestKind::Seal).await
        {
            return Some(resp);
        }
    }
    None
}

// ─── §4 and §4b: no eligible admin (D75, D126) ─────────────────────────────

/// Public status string of the §4b(3) definitive refusal.
pub(in crate::server) const GROUP_ADMIN_REVOKED: &str = "group_admin_revoked";

/// The derived no-eligible-admin state of one group, when it applies.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NoEligibleAdmin {
    /// §4, §4b(1)/(2): every member waits (D75); the exit names the
    /// owner-held path (`owner_recovery`) or, for an ordinary group before
    /// its catch-up round, the deletion exit.
    Waiting {
        revoked_admins: Vec<String>,
        exit: &'static str,
    },
    /// §4b(3): an ordinary group ends locally (D126).
    GroupAdminRevoked {
        revoked_admins: Vec<String>,
        recreate_members: Vec<String>,
        name: String,
        policy: serde_json::Value,
    },
}

/// The revoked seats of a group whose verified revocations cover every
/// Admin-or-higher Active seat.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RevokedAdminCover {
    /// Every Admin-or-higher Active seat, sorted. All are revoked.
    admins: Vec<[u8; 32]>,
    /// Every revoked Active seat.
    members: BTreeSet<[u8; 32]>,
}

/// §4 (D75): the cover test. `is_revoked` answers for one agent from the
/// verified revocation set. Returns `None` for a withdrawn group, for a
/// genuinely admin-empty roster (ADR 0088 §2 item 3), or when one admin
/// seat is not revoked.
fn revoked_admin_cover(
    info: &GroupInfo,
    is_revoked: impl Fn(&[u8; 32]) -> bool,
) -> Option<RevokedAdminCover> {
    if info.withdrawn {
        return None;
    }
    let mut admins = active_admins_of(info);
    if admins.is_empty() || !admins.iter().all(&is_revoked) {
        return None;
    }
    admins.sort();
    admins.dedup();
    let members: BTreeSet<[u8; 32]> = info
        .active_members()
        .filter_map(|member| super::parse_agent_id_hex(&member.agent_id).ok())
        .map(|agent| *agent.as_bytes())
        .filter(&is_revoked)
        .collect();
    Some(RevokedAdminCover { admins, members })
}

/// The cover of `info` under this node's verified revocation set. It takes
/// only the revocation-set read lock.
async fn revoked_admin_cover_now(state: &AppState, info: &GroupInfo) -> Option<RevokedAdminCover> {
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    revoked_admin_cover(info, |id| {
        set.is_agent_revoked(&x0x::identity::AgentId(*id))
    })
}

/// §4 (D75) and §4b(3) (D126) at the ciphertext boundary: true while
/// verified Agent-subject revocations cover every Admin-or-higher Active
/// seat of `info`. Every seal and publication path asks this through
/// `group_ciphertext_withheld`, just before it makes ciphertext.
///
/// Both derived states (`Waiting` and `GroupAdminRevoked`) refuse, so this
/// does not derive which one applies. That needs the head-sync check,
/// which locks the group's TreeKEM mutex (`local_epoch_of`). A seal holds
/// that mutex, so the boundary must not call it. This function takes only
/// the revocation-set read lock. No path holds the revocation-set write
/// lock while it waits for a group, membership or TreeKEM lock.
pub(in crate::server) async fn s4_withholds_ciphertext(state: &AppState, info: &GroupInfo) -> bool {
    revoked_admin_cover_now(state, info).await.is_some()
}

#[cfg(test)]
mod revoked_admin_cover_tests {
    use super::*;
    use x0x::identity::AgentId;

    /// Creator `[1; 32]` (Owner), Admin `[2; 32]`, Member `[3; 32]`.
    fn group() -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            String::new(),
            AgentId([1; 32]),
            "ab".repeat(16),
        );
        info.migrate_from_v1();
        info.add_member(
            hex::encode([2; 32]),
            GroupRole::Admin,
            Some(hex::encode([1; 32])),
            None,
        );
        info.add_member(
            hex::encode([3; 32]),
            GroupRole::Member,
            Some(hex::encode([1; 32])),
            None,
        );
        info
    }

    #[test]
    fn every_admin_seat_revoked_is_a_cover() {
        let revoked: BTreeSet<[u8; 32]> = [[2; 32], [1; 32], [3; 32]].into();
        let cover = revoked_admin_cover(&group(), |id| revoked.contains(id))
            .expect("Owner and Admin are both revoked");
        assert_eq!(cover.admins, vec![[1; 32], [2; 32]]);
        assert_eq!(cover.members, revoked);
    }

    #[test]
    fn one_unrevoked_admin_seat_is_no_cover() {
        let revoked: BTreeSet<[u8; 32]> = [[1; 32], [3; 32]].into();
        assert_eq!(
            revoked_admin_cover(&group(), |id| revoked.contains(id)),
            None
        );
        assert_eq!(revoked_admin_cover(&group(), |_| false), None);
    }

    #[test]
    fn a_withdrawn_group_is_no_cover() {
        let mut info = group();
        info.withdrawn = true;
        assert_eq!(revoked_admin_cover(&info, |_| true), None);
    }
}

/// Derive the state from the verified revocation records and the verified
/// head. It is not signed: a later head with an eligible admin clears it
/// (§4b(3) "late evidence").
async fn no_eligible_admin_state(state: &AppState, info: &GroupInfo) -> Option<NoEligibleAdmin> {
    let RevokedAdminCover {
        admins: revoked,
        members: revoked_members,
    } = revoked_admin_cover_now(state, info).await?;
    let revoked_admins: Vec<String> = revoked.iter().map(hex::encode).collect();
    if owner_certified(info) {
        return Some(NoEligibleAdmin::Waiting {
            revoked_admins,
            exit: "owner_recovery",
        });
    }
    // §4b(3): derive the end only after a current catch-up round (§2).
    if !group_head_synced(state, info.stable_group_id()).await {
        return Some(NoEligibleAdmin::Waiting {
            revoked_admins,
            exit: GROUP_ADMIN_REVOKED,
        });
    }
    let mut recreate_members: Vec<String> = info
        .active_members()
        .filter_map(|member| super::parse_agent_id_hex(&member.agent_id).ok())
        .filter(|agent| !revoked_members.contains(agent.as_bytes()))
        .map(|agent| hex::encode(agent.as_bytes()))
        .collect();
    recreate_members.sort();
    Some(NoEligibleAdmin::GroupAdminRevoked {
        revoked_admins,
        recreate_members,
        name: info.name.clone(),
        policy: serde_json::to_value(&info.policy).unwrap_or(serde_json::Value::Null),
    })
}

fn no_eligible_admin_json(state: &NoEligibleAdmin) -> serde_json::Value {
    match state {
        NoEligibleAdmin::Waiting {
            revoked_admins,
            exit,
        } => serde_json::json!({
            "state": WaitingCause::WaitingForEligibleAdminRevocation.as_str(),
            "revoked_admins": revoked_admins,
            "exit": exit,
        }),
        NoEligibleAdmin::GroupAdminRevoked {
            revoked_admins,
            recreate_members,
            name,
            policy,
        } => serde_json::json!({
            "state": GROUP_ADMIN_REVOKED,
            "revoked_admins": revoked_admins,
            "exit": GROUP_ADMIN_REVOKED,
            "recreate_offer": {
                "members": recreate_members,
                "name": name,
                "policy": policy,
            },
        }),
    }
}

/// §4 (D75) and §4b(3) (D126): while verified Agent-subject revocations
/// cover every Admin-or-higher Active seat, member sends, admission,
/// invites, seals and key delivery are refused with the typed state, so no
/// new message reaches a revoked key. Returns the refusal, or `None`.
pub(in crate::server) async fn s4_no_eligible_admin_refusal(
    state: &AppState,
    group_key: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let info = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_key)
            .or_else(|| {
                groups.values().find(|info| {
                    info.stable_group_id() == group_key || info.mls_group_id == group_key
                })
            })?
            .clone()
    };
    let derived = no_eligible_admin_state(state, &info).await?;
    let (status, reason) = match &derived {
        NoEligibleAdmin::Waiting { .. } => (
            StatusCode::CONFLICT,
            WaitingCause::WaitingForEligibleAdminRevocation.as_str(),
        ),
        NoEligibleAdmin::GroupAdminRevoked { .. } => (StatusCode::GONE, GROUP_ADMIN_REVOKED),
    };
    let mut body = no_eligible_admin_json(&derived);
    if let Some(object) = body.as_object_mut() {
        object.insert("ok".into(), serde_json::Value::Bool(false));
        object.insert("error".into(), serde_json::Value::String(reason.into()));
        object.insert("reason".into(), serde_json::Value::String(reason.into()));
        object.insert(
            "group_id".into(),
            serde_json::Value::String(info.stable_group_id().to_string()),
        );
    }
    Some((status, Json(body)))
}

// ─── §4 EvictionHandoffV1 ──────────────────────────────────────────────────

/// Send the first hand-off of every due row to every other eligible admin
/// whose current verified advert sets `eviction_handoff_v1` (§2, §4). A
/// known lacking advert is an unsupported attempt; an unknown advert sends
/// nothing (ADR 0093: unknown support never implies support).
async fn dispatch_handoffs(state: &Arc<AppState>) {
    let due: Vec<(EvictionKey, ObligationRow)> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        let keys: Vec<EvictionKey> = std::mem::take(&mut inner.pending_dispatch)
            .into_iter()
            .collect();
        keys.into_iter()
            .filter_map(|key| inner.store.get(&key).cloned().map(|row| (key, row)))
            .collect()
    };
    if due.is_empty() {
        return;
    }
    let local = *state.agent.agent_id().as_bytes();
    let capabilities = state.agent.capability_store();
    for (key, row) in due {
        let Some((recipients, handoff)) = build_handoff(state, &row).await else {
            continue;
        };
        let payload = match s4::encode_handoff(&handoff) {
            Ok(payload) if payload.len() <= x0x::dm::MAX_PAYLOAD_BYTES => payload,
            // An oversized proof waits for the existing authorized evidence
            // route (§4); the receiver's own observation still applies.
            _ => continue,
        };
        let mut unsupported = BTreeSet::new();
        for recipient in recipients
            .into_iter()
            .filter(|id| *id != local && *id != key.target)
        {
            let agent = x0x::identity::AgentId(recipient);
            match capabilities.verified_registry_supports(
                &agent,
                x0x::dm::CapabilityRegistry::EVICTION_HANDOFF_V1,
            ) {
                Some(true) => {
                    let send_state = Arc::clone(state);
                    let bytes = payload.clone();
                    let _spawned = state.spawn_detached(async move {
                        if let Err(error) = send_state.agent.send_direct(&agent, bytes).await {
                            tracing::debug!(%error, "ADR 0110 S4: hand-off send failed");
                        }
                    });
                }
                Some(false) => {
                    unsupported.insert(recipient);
                }
                None => {}
            }
        }
        if !unsupported.is_empty() {
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .unsupported_handoff
                .entry(key)
                .or_default()
                .extend(unsupported);
        }
    }
}

/// Build the hand-off body of one row and its recipients (the eligible
/// admins of the current roster).
async fn build_handoff(
    state: &AppState,
    row: &ObligationRow,
) -> Option<(Vec<[u8; 32]>, s4::EvictionHandoffV1)> {
    let groups = state.named_groups.read().await;
    let info = groups
        .values()
        .find(|info| info.stable_group_id() == row.stable_group_id)?;
    let recipients = active_admins_of(info);
    let target_hex = hex::encode(row.target);
    let expired_certificate = row.expired_certificates.keys().next().map(|digest| {
        let certificate_bytes = info
            .members_v2
            .get(&target_hex)
            .and_then(|member| member.certificate.as_ref())
            .filter(|cert| x0x::groups::owner_cert::certificate_digest_hex(cert) == *digest)
            .and_then(|cert| bincode::serialize(cert).ok());
        s4::HandoffExpiredCertificate {
            certificate_digest: digest.clone(),
            certificate_bytes,
        }
    });
    let handoff = s4::EvictionHandoffV1 {
        stable_group_id: row.stable_group_id.clone(),
        target: row.target,
        observed_parent_head: info.state_hash.clone(),
        revocation_records: row
            .revocation_records
            .values()
            .take(s4::MAX_HANDOFF_REVOCATION_RECORDS)
            .cloned()
            .collect(),
        self_leave_commit: row.self_leave_commits.iter().next().cloned(),
        expired_certificate,
        renewed_certificate: None,
    };
    handoff.has_evidence().then_some((recipients, handoff))
}

/// The direct-message listener hands every `X0XEVH1` payload here.
pub(in crate::server) fn spawn_handoff_receipt(
    state: &Arc<AppState>,
    sender: x0x::identity::AgentId,
    verified: bool,
    payload: Vec<u8>,
) {
    if !verified {
        // The carrier could not bind the claimed agent to its machine.
        return;
    }
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        receive_handoff(&task_state, sender, &payload).await;
    });
}

/// Verify a hand-off independently (§4): the sender is an Active member
/// of the group, this node is an Active admin, and every revocation record
/// verifies through the §1 choke point. Only a verified trigger schedules
/// work; the receipt time can only make T_obs earlier, never later.
async fn receive_handoff(state: &Arc<AppState>, sender: x0x::identity::AgentId, payload: &[u8]) {
    let handoff = match s4::decode_handoff(payload) {
        Ok(handoff) => handoff,
        Err(error) => {
            tracing::debug!(?error, "ADR 0110 S4: hand-off refused at decode");
            return;
        }
    };
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let sender_hex = hex::encode(sender.as_bytes());
    let target_hex = hex::encode(handoff.target);
    let target_cert = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups
            .values()
            .find(|info| info.stable_group_id() == handoff.stable_group_id && !info.withdrawn)
        else {
            return;
        };
        let local_admin = info
            .active_members()
            .any(|member| member.agent_id == local_hex && member.role.at_least(GroupRole::Admin));
        let sender_member = info
            .active_members()
            .any(|member| member.agent_id == sender_hex);
        if !local_admin || !sender_member {
            return;
        }
        info.members_v2
            .get(&target_hex)
            .and_then(|member| member.certificate.clone())
    };
    let mut verified_any = false;
    for bytes in &handoff.revocation_records {
        let Ok(record) = bincode::deserialize::<x0x::revocation::RevocationRecord>(bytes) else {
            continue;
        };
        let names_target = matches!(
            &record.subject,
            x0x::revocation::RevokedSubject::Agent(agent) if agent.as_bytes() == &handoff.target
        );
        if !names_target {
            continue;
        }
        match state
            .agent
            .ingest_eviction_handoff_revocation(record, target_cert.as_ref())
            .await
        {
            Ok(true) => verified_any = true,
            Ok(false) => {}
            Err(error) => {
                tracing::debug!(%error, "ADR 0110 S4: hand-off revocation record refused");
            }
        }
    }
    // §4a (D155): a renewal from the seat's own agent after its cutoff.
    if let Some(bytes) = &handoff.renewed_certificate {
        if rebind::note_handoff_renewal(
            state,
            &handoff.stable_group_id,
            handoff.target,
            sender,
            bytes,
        )
        .await
        {
            verified_any = true;
        }
    }
    // §1a: verify and install the carried certificate, and keep the
    // hand-off until this node's own clock passes the raw `not_after`.
    if let Some(expired) = &handoff.expired_certificate {
        note_expiry_handoff(state, &handoff.stable_group_id, handoff.target, expired).await;
    }
    // Self-leave and expiry evidence is re-derived from this node's own
    // chain and clock (§1a: a hand-off never shortens another node's
    // expiry budget); the pass below picks it up.
    if verified_any || handoff.self_leave_commit.is_some() || handoff.expired_certificate.is_some()
    {
        revocation_eviction_pass(state).await;
        let key = EvictionKey::new(handoff.stable_group_id, handoff.target);
        let mut inner = state.revocation_evictions.inner.lock().await;
        if let Some(row) = inner.store.get_mut(&key) {
            let now_ms = now_unix_ms();
            let earliest = row
                .earliest_handoff_receipt_unix_ms
                .map_or(now_ms, |seen| seen.min(now_ms));
            if row.earliest_handoff_receipt_unix_ms != Some(earliest) {
                row.earliest_handoff_receipt_unix_ms = Some(earliest);
                inner.dirty = true;
            }
        }
    }
}

/// §1a hand-off evidence: the hand-off must name the seat's committed
/// digest. When this node lacks the bytes of that digest-only seat, the
/// carried bytes must hash to the digest and pass the existing owner
/// certificate check (signature, owner chain, agent binding; expiry is the
/// expected result). They are installed through the digest-anchored seat
/// hydrate. The hand-off is then kept for [`expiry_handoff_triggers`].
async fn note_expiry_handoff(
    state: &AppState,
    stable_group_id: &str,
    target: [u8; 32],
    expired: &s4::HandoffExpiredCertificate,
) {
    let target_hex = hex::encode(target);
    let (group_key, install) = {
        let groups = state.named_groups.read().await;
        let Some((group_key, info)) = groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == stable_group_id)
        else {
            return;
        };
        let Some(owner) = info.policy.admission.owner_certified_user_id() else {
            return;
        };
        let Some(member) = info.members_v2.get(&target_hex) else {
            return;
        };
        let committed = member.certificate_digest.clone().or_else(|| {
            member
                .certificate
                .as_ref()
                .map(x0x::groups::owner_cert::certificate_digest_hex)
        });
        if committed.as_deref() != Some(expired.certificate_digest.as_str()) {
            return;
        }
        let install = if member.certificate.is_none() {
            let Some(cert) = verified_handoff_certificate(owner, &target_hex, expired) else {
                return;
            };
            Some(cert)
        } else {
            None
        };
        (group_key.clone(), install)
    };
    if let Some(cert) = install {
        let membership = super::group_membership_lock(state, &group_key).await;
        let _serialized = membership.lock().await;
        let pairs = vec![(target_hex.clone(), cert)];
        let outcome = super::persist_named_groups_mutation(state, |groups| {
            groups
                .get_mut(&group_key)
                .is_some_and(|info| info.hydrate_member_certificates(&pairs) > 0)
        })
        .await;
        if let Err(error) = outcome {
            tracing::warn!(%error, "ADR 0110 S4: hand-off certificate install failed");
            return;
        }
    }
    let key = EvictionKey::new(stable_group_id.to_string(), target);
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        if inner.expiry_handoffs.contains_key(&key) {
            return;
        }
        inner.expiry_handoffs.insert(
            key,
            ExpiryHandoff {
                certificate_digest: expired.certificate_digest.clone(),
                received_unix_ms: now_unix_ms(),
            },
        );
        inner.expiry_handoffs_dirty = true;
    }
    // §2: the verified receipt time is persisted before it is used.
    handoff_log::persist(state).await;
}

/// The carried certificate of an expiry hand-off, when its bytes hash to
/// the named digest and it verifies against the owner for `target_hex`.
fn verified_handoff_certificate(
    owner: &x0x::identity::UserId,
    target_hex: &str,
    expired: &s4::HandoffExpiredCertificate,
) -> Option<x0x::identity::AgentCertificate> {
    let bytes = expired.certificate_bytes.as_deref()?;
    let cert: x0x::identity::AgentCertificate = bincode::deserialize(bytes).ok()?;
    if x0x::groups::owner_cert::certificate_digest_hex(&cert) != expired.certificate_digest {
        return None;
    }
    let now_unix = now_unix_ms() / 1000;
    match x0x::groups::owner_cert::verify_cert_against_owner(
        owner, target_hex, &cert, false, now_unix,
    ) {
        Ok(()) | Err(x0x::groups::owner_cert::OwnerCertFailure::Expired) => Some(cert),
        Err(_) => None,
    }
}

/// §1a hand-off timing. A kept hand-off becomes a trigger once this node
/// selects the certificate it names and its clock has passed the raw
/// `not_after`; the returned time is T_obs (the later of the receipt and
/// that moment). A hand-off whose seat or committed certificate changed is
/// dropped; one still waiting for the clock or for the seat's bytes stays.
fn expiry_handoff_triggers(
    kept: &mut BTreeMap<EvictionKey, ExpiryHandoff>,
    groups: &[(String, GroupInfo)],
    now_unix_ms: u64,
) -> Vec<(EvictionKey, EvictionTrigger, Option<String>, u64)> {
    let now_unix = now_unix_ms / 1000;
    let mut out = Vec::new();
    kept.retain(|key, handoff| {
        let Some((info, member)) = groups
            .iter()
            .map(|(_, info)| info)
            .find(|info| {
                info.stable_group_id() == key.stable_group_id
                    && !info.withdrawn
                    && owner_certified(info)
            })
            .and_then(|info| {
                info.members_v2
                    .get(&hex::encode(key.target))
                    .map(|member| (info, member))
            })
            .filter(|(_, member)| member.state == GroupMemberState::Active)
        else {
            return false;
        };
        let Some((digest, not_after)) = selected_certificate_expiry(member) else {
            // Keep a digest-only seat that still waits for its bytes.
            return member.certificate.is_none()
                && member.certificate_digest.as_deref()
                    == Some(handoff.certificate_digest.as_str());
        };
        if digest != handoff.certificate_digest {
            return false;
        }
        if !s4::raw_expiry_passed(not_after, now_unix) {
            return true;
        }
        let observed_ms = handoff
            .received_unix_ms
            .max(not_after.saturating_add(1).saturating_mul(1000));
        out.push((
            key.clone(),
            EvictionTrigger::CertificateExpiry {
                certificate_digest: digest,
                not_after,
            },
            ce::seat_incarnation(info, &member.agent_id),
            observed_ms,
        ));
        false
    });
    out
}

// ─── §3 commit ─────────────────────────────────────────────────────────────

/// Run every commit the last evaluation allows (§3). Each runs through the
/// existing signed removal path, which takes the membership lock and
/// re-reads the head under it before it seals.
async fn drive_exclusions(state: &Arc<AppState>) {
    let now = Instant::now();
    let candidates: Vec<(EvictionKey, String, RowAction)> = {
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .evaluations
            .iter()
            .filter(|(key, evaluation)| {
                evaluation.action != RowAction::None
                    && inner
                        .store
                        .get(key)
                        .is_some_and(|row| row.phase == Phase::Pending)
                    && inner.next_attempt.get(*key).is_none_or(|at| *at <= now)
            })
            .map(|(key, evaluation)| {
                (
                    key.clone(),
                    evaluation.stable_group_key.clone(),
                    evaluation.action,
                )
            })
            .collect()
    };
    for (key, group_key, action) in candidates {
        match action {
            RowAction::CommitRemoval { rank } => {
                // §4a: with a verified renewal and every member capable,
                // the expiry worker rebinds instead of removing.
                if !rebind::try_admin_rebind(state, &key, &group_key).await {
                    commit_removal(state, &key, &group_key, rank).await;
                }
            }
            RowAction::SelfLeaveRekey { rank } => {
                // The responsive self-leave rekey (#1113, PR #1337) already
                // runs the crypto exclusion of a self-leaver's retained
                // leaf through its own durable outbox; S4 schedules it and
                // completes the row from the chain.
                tracing::debug!(
                    group_id = %super::LogHexId::group(&group_key),
                    rank,
                    "ADR 0110 S4: scheduling the responsive self-leave rekey"
                );
                if crypto_exclusion::gss_group(state, &group_key).await {
                    // #1508 review P1: a GSS group has no #1337 rekey
                    // pass; S4 commits the GSS `CryptoExclusionV1` itself.
                    crypto_exclusion::commit_gss(state, &key, &group_key).await;
                } else {
                    super::schedule_self_leave_rekey_if_idle(state, &group_key).await;
                }
                state
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .next_attempt
                    .insert(key, Instant::now() + S4_COMMIT_RETRY);
            }
            RowAction::None => {}
        }
    }
}

async fn commit_removal(state: &Arc<AppState>, key: &EvictionKey, group_key: &str, rank: usize) {
    let target_hex = hex::encode(key.target);
    // §2: re-read the head and the evidence just before every seal. The
    // evaluation that allowed this commit may be one pass old.
    if !group_head_synced(state, group_key).await {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.attempt_wait.insert(
            key.clone(),
            WaitingState::cause(WaitingCause::WaitingForHeadSync),
        );
        inner
            .next_attempt
            .insert(key.clone(), Instant::now() + S4_WORKER_TICK);
        return;
    }
    // §5 transaction order: fsync a prepared `.evjournal` with the
    // evidence and the parent head, then run the unchanged legacy
    // roster/crypto transaction, then fsync the reconciled `.evs`.
    let (parent_head, next_revision) = {
        let groups = state.named_groups.read().await;
        match groups.get(group_key) {
            Some(info) => (
                info.state_hash.clone(),
                info.state_revision.saturating_add(1),
            ),
            None => return,
        }
    };
    let prepared = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        // §2: an accepted queued ban is applied as a ban by this commit.
        let kind = if inner.queued_bans.contains_key(key) {
            ManualRequestKind::Ban
        } else {
            ManualRequestKind::Remove
        };
        let Some(row) = inner.store.get_mut(key) else {
            return;
        };
        if row.phase != Phase::Pending {
            return;
        }
        row.phase = Phase::Prepared;
        row.parent_head = Some(parent_head.clone());
        let journal = prepared_journal(row, parent_head, next_revision);
        // The row is `prepared` now, so the scope marks this run as the
        // worker's own removal (§1a/D135 cancellation).
        let scope = eviction_seal_scope(&inner.store, key);
        inner.dirty = true;
        Some((journal, kind, scope))
    };
    let Some((journal, kind, scope)) = prepared else {
        return;
    };
    let journal_path = evjournal_path(state, &key.stable_group_id);
    let journal_written = write_evjournal(&journal_path, &journal).await;
    let evs_durable = persist_obligations(state).await;
    if !journal_written || !evs_durable {
        let mut inner = state.revocation_evictions.inner.lock().await;
        if let Some(row) = inner.store.get_mut(key) {
            row.phase = Phase::Pending;
            row.parent_head = None;
        }
        inner.mark_not_durable(key);
        inner
            .next_attempt
            .insert(key.clone(), Instant::now() + S4_COMMIT_RETRY);
        drop(inner);
        remove_file_durably(&journal_path).await;
        return;
    }
    tracing::info!(
        group_id = %super::LogHexId::group(group_key),
        target = %super::LogHexId::agent(&target_hex),
        rank,
        "ADR 0110 S4: excluding a revoked or expired member"
    );
    let (status, body) = run_member_route(state, group_key, &target_hex, kind, scope).await;
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        if status == StatusCode::OK {
            if let Some(row) = inner.store.get_mut(key) {
                row.phase = Phase::CommittedDeliveryPending;
                // §5: the removal barrier saved the exact event's epoch; the
                // reply's `epoch` is the legacy MLS epoch (GSS) or absent
                // (bans), so it only fills a row the barrier left empty.
                if row.result_epoch.is_none() {
                    row.result_epoch = body.get("epoch").and_then(serde_json::Value::as_u64);
                }
            }
            inner.attempt_wait.remove(key);
            inner.queued_manual.remove(key);
            if kind == ManualRequestKind::Ban {
                inner.queued_bans.remove(key);
                inner.ban_next_attempt.remove(key);
            }
        } else {
            // §1a/D135: a rebind that landed meanwhile ended the row; a
            // refused attempt never reopens it.
            let mut cancelled = true;
            if let Some(row) = inner.store.get_mut(key) {
                if row.phase == Phase::Prepared {
                    row.phase = Phase::Pending;
                    row.parent_head = None;
                    cancelled = false;
                }
            }
            let error = body
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if error == "member_key_package_pending" {
                // §3: a miss never counts as an absent leaf; the existing
                // member-keyed catch-up was requested by the removal path.
                inner.attempt_wait.insert(
                    key.clone(),
                    WaitingState::cause(WaitingCause::WaitingForMemberKeyPackage),
                );
            } else if status != StatusCode::NOT_FOUND && !cancelled {
                tracing::warn!(
                    group_id = %super::LogHexId::group(group_key),
                    target = %super::LogHexId::agent(&target_hex),
                    %status,
                    error,
                    "ADR 0110 S4: exclusion attempt refused; retrying"
                );
            }
            inner
                .next_attempt
                .insert(key.clone(), Instant::now() + S4_COMMIT_RETRY);
        }
        inner.dirty = true;
    }
    // The legacy transaction is durable (or refused): reconcile the `.evs`
    // and only then retire the S4 journal.
    persist_obligations(state).await;
    remove_file_durably(&journal_path).await;
}

tokio::task_local! {
    /// §3: set while the S4 worker runs one removal or ban through the
    /// existing route, so that route's `OwnerCertified` seal knows which
    /// other failing seats are open S4 work (see
    /// [`s4_eviction_seal_tolerates`]).
    static S4_EVICTION_SEAL: EvictionSealScope;
}

/// The S4 removal or ban that the current task runs.
#[derive(Debug, Clone)]
struct EvictionSealScope {
    stable_group_id: String,
    /// The lowercase hex of the excluded target.
    target_hex: String,
    /// Lowercase hex of the targets of the group's other open rows.
    pending_targets: BTreeSet<String>,
    /// The worker's own removal or ban of a `prepared` row
    /// ([`commit_removal`]), not a queued ban of an ended row.
    prepared_removal: bool,
}

fn eviction_seal_scope(store: &ObligationStore, key: &EvictionKey) -> EvictionSealScope {
    EvictionSealScope {
        stable_group_id: key.stable_group_id.clone(),
        target_hex: hex::encode(key.target),
        pending_targets: store
            .open_rows_for_group(&key.stable_group_id)
            .filter(|row| row.target != key.target)
            .map(|row| hex::encode(row.target))
            .collect(),
        prepared_removal: store
            .get(key)
            .is_some_and(|row| row.phase == Phase::Prepared),
    }
}

/// §3 and ADR-0038 B3: an `OwnerCertified` seal normally needs an
/// all-clean roster. When two or more seats of one group are revoked or
/// expired, the removal of the first leaves the others failing, and that
/// seal is refused, so no removal could ever land. ADR 0110 §3 lets Home
/// and other `OwnerCertified` groups use the `OwnerCertified` engine,
/// which evicts one member per sealed transition and seals each
/// transition while the later failing members are still seated
/// (`seal_commit_evicting`). This returns true, and the caller seals the
/// same way, only inside an S4 removal or ban whose working copy has
/// already excluded its target and when every remaining failing seat is
/// the target of another open S4 row of the same group. Each of those
/// rows then gets its own transition under its own designation and
/// timing. Any other failing seat keeps the all-clean refusal.
pub(in crate::server) fn s4_eviction_seal_tolerates(info: &GroupInfo, failed: &[String]) -> bool {
    S4_EVICTION_SEAL
        .try_with(|scope| eviction_seal_tolerates(scope, info, failed))
        .unwrap_or(false)
}

fn eviction_seal_tolerates(scope: &EvictionSealScope, info: &GroupInfo, failed: &[String]) -> bool {
    scope.stable_group_id == info.stable_group_id()
        && !info
            .members_v2
            .get(&scope.target_hex)
            .is_some_and(|member| is_seated(member.state))
        && !failed.is_empty()
        && failed
            .iter()
            .all(|hex| scope.pending_targets.contains(&hex.to_ascii_lowercase()))
}

/// Whether the current task runs the worker's own removal or ban of the
/// `prepared` row `key` ([`commit_removal`]).
fn s4_prepared_removal_of(key: &EvictionKey) -> bool {
    S4_EVICTION_SEAL
        .try_with(|scope| {
            scope.prepared_removal
                && scope.stable_group_id == key.stable_group_id
                && scope.target_hex == hex::encode(key.target)
        })
        .unwrap_or(false)
}

/// The typed reply to the worker's cancelled removal or ban (§1a/D135).
pub(in crate::server) fn s4_exclusion_cancelled_response() -> (StatusCode, Json<serde_json::Value>)
{
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({ "ok": false, "error": "s4_exclusion_cancelled" })),
    )
}

/// The S4 state of a removal or ban of `key`, read under the caller's
/// membership lock against the current committed `seat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockedRemoval {
    /// Not the worker's prepared removal: the legacy path runs unchanged.
    NotS4,
    /// The worker's prepared removal, still eligible.
    Prepared,
    /// The worker's removal, cancelled: the row ended or a rebind changed
    /// the seat's committed certificate.
    Cancelled,
}

async fn locked_removal_state(
    state: &AppState,
    key: &EvictionKey,
    seat: Option<&x0x::groups::GroupMember>,
) -> LockedRemoval {
    let now_unix = now_unix_ms() / 1000;
    let inner = state.revocation_evictions.inner.lock().await;
    match inner.store.get(key) {
        Some(row) if row.phase == Phase::Prepared && row.parent_head.is_some() => {
            if exclusion_still_eligible(row, seat, now_unix) {
                LockedRemoval::Prepared
            } else {
                LockedRemoval::Cancelled
            }
        }
        _ if s4_prepared_removal_of(key) => LockedRemoval::Cancelled,
        _ => LockedRemoval::NotS4,
    }
}

/// §1a/D135 (#1508 review): the remove and ban routes call this right
/// after they take the group's membership lock, on every plane. A rebind
/// commit takes the same lock, so none can land between this check and
/// the commit. Returns the `409` reply when the worker's removal or ban
/// is cancelled.
pub(in crate::server) async fn s4_exclusion_cancelled_under_lock(
    state: &AppState,
    group_key: &str,
    target_hex: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let target = super::parse_agent_id_hex(target_hex).ok()?;
    let (stable, seat) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(group_key)?;
        (
            info.stable_group_id().to_string(),
            info.members_v2
                .get(&hex::encode(target.as_bytes()))
                .cloned(),
        )
    };
    let key = EvictionKey::new(stable, *target.as_bytes());
    (locked_removal_state(state, &key, seat.as_ref()).await == LockedRemoval::Cancelled).then(
        || {
            tracing::info!(
                group_id = %super::LogHexId::group(group_key),
                target = %super::LogHexId::agent(target_hex),
                "ADR 0110 S4: the expiry removal is cancelled by a renewal; the seat stays"
            );
            s4_exclusion_cancelled_response()
        },
    )
}

/// §1a/D135 pre-seal re-check of a prepared row against the current
/// committed seat, run under the membership lock just before the removal
/// commits. An expiry-only row stays eligible only while the seat's
/// committed certificate is one that the row names and this node's clock
/// is past its raw `not_after`. A rebind (a new committed certificate)
/// cancels it. A renewal never cancels revocation or self-leave work.
fn exclusion_still_eligible(
    row: &ObligationRow,
    member: Option<&x0x::groups::GroupMember>,
    now_unix: u64,
) -> bool {
    let Some(member) = member.filter(|member| row.expiry_only() && is_seated(member.state)) else {
        return true;
    };
    let digest = match (&member.certificate, &member.certificate_digest) {
        (Some(cert), committed) => {
            let digest = x0x::groups::owner_cert::certificate_digest_hex(cert);
            if committed
                .as_deref()
                .is_some_and(|committed| committed != digest)
            {
                return false;
            }
            digest
        }
        (None, Some(committed)) => committed.clone(),
        (None, None) => return false,
    };
    row.expired_certificates
        .get(&digest)
        .is_some_and(|not_after| s4::raw_expiry_passed(*not_after, now_unix))
}

/// Run the existing signed remove or ban route for an S4 exclusion, under
/// the S4 eviction scope. Returns the status and the JSON body.
async fn run_member_route(
    state: &Arc<AppState>,
    group_key: &str,
    target_hex: &str,
    kind: ManualRequestKind,
    scope: EvictionSealScope,
) -> (StatusCode, serde_json::Value) {
    let actor =
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true });
    let path = Path((group_key.to_string(), target_hex.to_string()));
    let route = async {
        if kind == ManualRequestKind::Ban {
            super::ban_group_member(State(Arc::clone(state)), actor, path)
                .await
                .into_response()
        } else {
            super::remove_named_group_member(State(Arc::clone(state)), actor, path)
                .await
                .into_response()
        }
    };
    let response = S4_EVICTION_SEAL.scope(scope, route).await;
    let status = response.status();
    let body: serde_json::Value = match axum::body::to_bytes(response.into_body(), 1 << 20).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::Value::Null,
    };
    (status, body)
}

/// §2: apply each accepted queued ban whose row no longer has open work:
/// the designated (or another) admin's removal landed, or the row ended.
/// The ban runs through the existing ban route, so the target cannot
/// renew and rejoin. A ban that this node cannot apply yet (not an admin,
/// head not synced, route refused) stays queued and durable.
async fn drive_queued_bans(state: &Arc<AppState>) {
    let now = Instant::now();
    let due: Vec<EvictionKey> = {
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .queued_bans
            .keys()
            .filter(|key| {
                inner.store.get(key).is_none_or(|row| !row.phase.is_open())
                    && inner.ban_next_attempt.get(*key).is_none_or(|at| *at <= now)
            })
            .cloned()
            .collect()
    };
    if due.is_empty() {
        return;
    }
    let groups = snapshot_groups(state).await;
    let local = *state.agent.agent_id().as_bytes();
    let mut changed = false;
    for key in due {
        let found = groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == key.stable_group_id);
        let target_hex = hex::encode(key.target);
        let settled = found.is_none_or(|(_, info)| {
            info.withdrawn
                || info
                    .members_v2
                    .get(&target_hex)
                    .is_some_and(|member| member.state == GroupMemberState::Banned)
        });
        if settled {
            let mut inner = state.revocation_evictions.inner.lock().await;
            inner.queued_bans.remove(&key);
            inner.ban_next_attempt.remove(&key);
            inner.dirty = true;
            changed = true;
            continue;
        }
        let Some((group_key, info)) = found else {
            continue;
        };
        let ready =
            active_admins_of(info).contains(&local) && group_head_synced(state, group_key).await;
        if !ready {
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ban_next_attempt
                .insert(key.clone(), Instant::now() + S4_COMMIT_RETRY);
            continue;
        }
        let scope = {
            let inner = state.revocation_evictions.inner.lock().await;
            eviction_seal_scope(&inner.store, &key)
        };
        let (status, body) =
            run_member_route(state, group_key, &target_hex, ManualRequestKind::Ban, scope).await;
        let mut inner = state.revocation_evictions.inner.lock().await;
        if status == StatusCode::OK {
            inner.queued_bans.remove(&key);
            inner.ban_next_attempt.remove(&key);
            inner.dirty = true;
            changed = true;
        } else {
            tracing::warn!(
                group_id = %super::LogHexId::group(group_key),
                target = %super::LogHexId::agent(&target_hex),
                %status,
                error = body.get("error").and_then(serde_json::Value::as_str).unwrap_or_default(),
                "ADR 0110 S4: a queued manual ban could not be applied yet; retrying"
            );
            // A TreeKEM ban of a target with no leaf cannot run through
            // the existing route; it applies once the target is seated
            // again (a rejoin), so retry slowly while it is not.
            let seated = info
                .members_v2
                .get(&target_hex)
                .is_some_and(|member| is_seated(member.state));
            let retry = if seated {
                S4_COMMIT_RETRY
            } else {
                S4_UNSEATED_BAN_RETRY
            };
            inner
                .ban_next_attempt
                .insert(key.clone(), Instant::now() + retry);
        }
    }
    if changed {
        persist_obligations(state).await;
    }
}

fn prepared_journal(row: &ObligationRow, parent_head: String, next_revision: u64) -> EvJournalV1 {
    let mut txid = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut txid);
    let mut evidence: Vec<[u8; 32]> = row.revocation_hashes.iter().copied().collect();
    evidence.extend(
        row.self_leave_commits
            .iter()
            .chain(row.expired_certificates.keys())
            .map(|text| *blake3::hash(text.as_bytes()).as_bytes()),
    );
    EvJournalV1 {
        txid,
        stable_group_id: row.stable_group_id.clone(),
        target: row.target,
        parent_head,
        next_revision,
        result_epoch: None,
        evidence,
        // The legacy removal path adds its exact event before it commits
        // (`removal_journal::prepare_committed_removal`).
        outgoing_event: Vec::new(),
        result_head: None,
    }
}

// ─── §4 crypto-only exclusion: S4 row transitions ──────────────────────────

/// §2 for the responsive self-leave rekey: whether this node's ranked
/// fallback time for an open crypto-only row of `stable_group_id` has
/// passed. The #1337 pass lets only the lowest active admin commit; S4
/// adds the ranked fallback after W.
pub(super) async fn s4_self_leave_fallback_allowed(
    state: &AppState,
    stable_group_id: &str,
) -> bool {
    let inner = state.revocation_evictions.inner.lock().await;
    inner.evaluations.iter().any(|(key, evaluation)| {
        key.stable_group_id == stable_group_id
            && matches!(evaluation.action, RowAction::SelfLeaveRekey { rank } if rank > 0)
            && matches!(
                evaluation.permission,
                Some(CommitPermission::Fallback { .. })
            )
    })
}

/// Record the D76 holders of one row (empty clears the hold).
async fn note_receiver_upgrade_hold(state: &AppState, key: &EvictionKey, holders: Vec<[u8; 32]>) {
    let mut inner = state.revocation_evictions.inner.lock().await;
    if holders.is_empty() {
        inner.ce.holders.remove(key);
        return;
    }
    let mut waiting = WaitingState::cause(WaitingCause::WaitingForReceiverUpgrade);
    waiting.named = holders.clone();
    inner.ce.holders.insert(key.clone(), holders);
    if inner.store.set_waiting(key, Some(waiting)) {
        inner.dirty = true;
    }
}

/// §5 step 1 of a crypto-only exclusion: make sure the row exists, move it
/// to `prepared` with the exact outgoing frame, fsync the `.evjournal`,
/// then the `.evs`. Returns whether both are durable; on failure the row
/// returns to `pending` and the journal is removed.
async fn prepare_crypto_exclusion(
    state: &AppState,
    key: &EvictionKey,
    journal: &EvJournalV1,
    incarnation: Option<String>,
) -> bool {
    let now_ms = now_unix_ms();
    {
        let runtime = &state.revocation_evictions;
        let mut inner = runtime.inner.lock().await;
        let outcome = inner.store.intake(
            key,
            EvictionTrigger::SelfLeave {
                commit_hash: journal.parent_head.clone(),
            },
            incarnation.as_deref(),
            now_ms,
            runtime.boot_id,
        );
        if matches!(outcome, IntakeOutcome::Created | IntakeOutcome::Reopened) {
            inner.budgets.insert(
                key.clone(),
                RowBudget::resume(Duration::ZERO, Instant::now()),
            );
        }
        let Some(row) = inner.store.get_mut(key) else {
            return false;
        };
        row.phase = Phase::Prepared;
        row.termination = None;
        row.completed_at_unix_ms = None;
        row.parent_head = Some(journal.parent_head.clone());
        row.result_head = journal.result_head.clone();
        row.result_epoch = journal.result_epoch;
        row.outgoing_event = Some(journal.outgoing_event.clone());
        inner.dirty = true;
    }
    let path = evjournal_path(state, &key.stable_group_id);
    let written = write_evjournal(&path, journal).await;
    let durable = written && persist_obligations(state).await;
    if !durable {
        abandon_crypto_exclusion(state, key).await;
    }
    durable
}

/// The legacy transaction did not commit: the row returns to `pending`,
/// the speculative preparation is abandoned and the journal retired.
async fn abandon_crypto_exclusion(state: &AppState, key: &EvictionKey) {
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        if let Some(row) = inner.store.get_mut(key) {
            row.phase = Phase::Pending;
            row.parent_head = None;
            row.result_head = None;
            row.result_epoch = None;
            row.outgoing_event = None;
        }
        inner.mark_not_durable(key);
        inner
            .next_attempt
            .insert(key.clone(), Instant::now() + S4_COMMIT_RETRY);
    }
    persist_obligations(state).await;
    remove_file_durably(&evjournal_path(state, &key.stable_group_id)).await;
}

/// §5 last steps: the legacy transaction is durable. The row moves to
/// `committed_delivery_pending`, its delivery starts, the `.evs` is
/// reconciled and only then is the journal retired.
#[allow(clippy::too_many_arguments)]
async fn committed_crypto_exclusion(
    state: &AppState,
    key: &EvictionKey,
    result_head: &str,
    result_epoch: u64,
    next_revision: u64,
    bytes: Vec<u8>,
    recipients: Vec<[u8; 32]>,
) {
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        if let Some(row) = inner.store.get_mut(key) {
            row.phase = Phase::CommittedDeliveryPending;
            row.result_head = Some(result_head.to_string());
            row.result_epoch = Some(result_epoch);
            row.waiting = None;
        }
        inner.ce.holders.remove(key);
        inner.attempt_wait.remove(key);
        inner.queued_manual.remove(key);
        crypto_exclusion::new_delivery(
            &mut inner.ce,
            key,
            result_head,
            next_revision,
            Arc::new(bytes),
            recipients,
            false,
        );
        inner.dirty = true;
    }
    persist_obligations(state).await;
    remove_file_durably(&evjournal_path(state, &key.stable_group_id)).await;
}

/// §3 restart: reconcile every row that holds a saved crypto-only frame
/// (from the `.evs` or a prepared `.evjournal`) against the loaded,
/// verified chain. Never publish a saved frame over a competing branch.
async fn resume_crypto_exclusions(
    state: &AppState,
    store: &mut ObligationStore,
    journals: &HashMap<EvictionKey, EvJournalV1>,
    ce_state: &mut crypto_exclusion::CeState,
) {
    let groups = snapshot_groups(state).await;
    let local = *state.agent.agent_id().as_bytes();
    let saved: Vec<(EvictionKey, Vec<u8>)> = store
        .rows()
        .filter(|row| row.phase.is_open())
        .filter_map(|row| {
            let key = row.key();
            let journal_frame = journals
                .get(&key)
                .map(|journal| journal.outgoing_event.clone())
                .filter(|frame| !frame.is_empty());
            journal_frame
                .or_else(|| row.outgoing_event.clone())
                .filter(|frame| !frame.is_empty())
                .map(|frame| (key, frame))
        })
        .collect();
    for (key, frame) in saved {
        let Some((parent_head, result_head, next_revision)) =
            crypto_exclusion::saved_frame_heads(&frame)
        else {
            continue;
        };
        let Some(info) = groups
            .iter()
            .map(|(_, info)| info)
            .find(|info| info.stable_group_id() == key.stable_group_id)
        else {
            continue;
        };
        let classified = crypto_exclusion::classify_saved_frame(info, &parent_head, &result_head);
        let Some(row) = store.get_mut(&key) else {
            continue;
        };
        match classified {
            crypto_exclusion::SavedFrameState::CurrentHead => {
                row.phase = Phase::CommittedDeliveryPending;
                row.result_head = Some(result_head.clone());
                row.outgoing_event = Some(frame.clone());
                let recipients = info
                    .active_members()
                    .filter_map(|member| super::parse_agent_id_hex(&member.agent_id).ok())
                    .map(|agent| *agent.as_bytes())
                    .filter(|id| *id != local && *id != key.target)
                    .collect();
                crypto_exclusion::new_delivery(
                    ce_state,
                    &key,
                    &result_head,
                    next_revision,
                    Arc::new(frame),
                    recipients,
                    true,
                );
            }
            crypto_exclusion::SavedFrameState::Superseded => {
                // Completion is re-derived from the chain by the next
                // pass; the obsolete delivery is discarded. The frame stays
                // as §4 catch-up replay evidence (never resent live).
                row.phase = Phase::CommittedDeliveryPending;
                row.result_head = Some(result_head);
                row.outgoing_event = Some(frame);
            }
            crypto_exclusion::SavedFrameState::Abandoned => {
                row.phase = Phase::Pending;
                row.parent_head = None;
                row.result_head = None;
                row.result_epoch = None;
                row.outgoing_event = None;
            }
            crypto_exclusion::SavedFrameState::Fork => {
                // Keep the frame as fork evidence; never publish it.
                row.outgoing_event = Some(frame);
                ce_state.fork.insert(key.clone());
                tracing::warn!(
                    group_id = %super::LogHexId::group(&key.stable_group_id),
                    target = %super::LogHexId::agent(&hex::encode(key.target)),
                    "ADR 0110 S4: a saved crypto-only exclusion meets a competing branch; waiting for fork resolution"
                );
            }
            crypto_exclusion::SavedFrameState::Unknown => {
                // Keep the frame; the head-sync wait decides later.
                row.outgoing_event = Some(frame);
                let mut waiting = WaitingState::cause(WaitingCause::WaitingForHeadSync);
                waiting.named = Vec::new();
                row.waiting = Some(waiting);
            }
        }
    }
}

// ─── §5 persistence ────────────────────────────────────────────────────────

fn evs_path(state: &AppState) -> PathBuf {
    state.data_dir.join(s4::EVS_FILE_NAME)
}

/// `<data_dir>/treekem/<stable-group-id>.evjournal`. A stable ID that is
/// not a plain file stem is hashed so it can never escape the directory.
fn evjournal_path(state: &AppState, stable_group_id: &str) -> PathBuf {
    let stem_ok = !stable_group_id.is_empty()
        && stable_group_id.len() <= 128
        && stable_group_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let stem = if stem_ok {
        stable_group_id.to_string()
    } else {
        hex::encode(blake3::hash(stable_group_id.as_bytes()).as_bytes())
    };
    state
        .treekem_dir
        .join(format!("{stem}.{}", s4::EVJOURNAL_EXTENSION))
}

/// Write the `.evs` sidecar when the store changed (§5). Returns whether
/// the store is durable afterwards (memory-only counts as durable for
/// evidence held elsewhere).
///
/// Writers are serialized by `evs_writer`, and the state lock is not held
/// across the disk I/O, so other tasks change rows while a write runs.
/// [`begin_persist`] takes the snapshot and clears `dirty` under the state
/// lock; [`finish_persist`] retires only the changes that snapshot covered.
/// A change made during the write keeps `dirty` set and stays in
/// `not_durable`, so it is never reported durable before a later write
/// covers it.
async fn persist_obligations(state: &AppState) -> bool {
    let runtime = &state.revocation_evictions;
    let _writer = runtime.evs_writer.lock().await;
    let snapshot = {
        let mut inner = runtime.inner.lock().await;
        match begin_persist(&mut inner, host_commit_gate_open(state)) {
            Ok(snapshot) => snapshot,
            Err(durable) => return durable,
        }
    };
    let path = evs_path(state);
    let result = write_bytes_durably(&path, &snapshot.bytes, None).await;
    if let Err(error) = &result {
        tracing::warn!(
            %error,
            path = %path.display(),
            "ADR 0110 S4: obligation sidecar write failed (waiting_for_durable_intake)"
        );
    }
    let mut inner = runtime.inner.lock().await;
    finish_persist(&mut inner, snapshot.change_seq, result.is_ok())
}

/// The bytes one `.evs` write puts on disk, and the change counter they
/// cover.
struct PersistSnapshot {
    bytes: Vec<u8>,
    change_seq: u64,
}

/// Take the snapshot of one `.evs` write under the state lock. `Err`
/// carries the durability answer when no write is needed or possible.
fn begin_persist(inner: &mut S4Inner, gate_open: bool) -> Result<PersistSnapshot, bool> {
    if !inner.dirty {
        return Err(inner.not_durable.is_empty());
    }
    if !inner.sidecar.state.writable() {
        // Memory-only (ADR 0108 §5a): never rewrite a newer or
        // unreadable file.
        inner.dirty = false;
        return Err(true);
    }
    if !gate_open {
        return Err(false);
    }
    if inner.store.is_empty() && inner.queued_bans.is_empty() && !inner.file_exists {
        // Created lazily on the first verified trigger persist.
        inner.dirty = false;
        return Err(true);
    }
    let body = EvsBodyV1 {
        rebuilt_from: inner.rebuilt_from.clone(),
        rows: inner.store.to_rows(),
    };
    let queued_bans: Vec<QueuedBanV1> = inner
        .queued_bans
        .iter()
        .map(|(key, queued_at_unix_ms)| QueuedBanV1 {
            stable_group_id: key.stable_group_id.clone(),
            target: key.target,
            queued_at_unix_ms: *queued_at_unix_ms,
        })
        .collect();
    match s4::encode_evs_with_queued_bans(&body, &queued_bans) {
        Ok(bytes) => {
            inner.dirty = false;
            Ok(PersistSnapshot {
                bytes,
                change_seq: inner.change_seq,
            })
        }
        Err(error) => {
            tracing::error!(%error, "ADR 0110 S4: cannot encode the obligation sidecar");
            Err(false)
        }
    }
}

/// Record the result of the write that `begin_persist` prepared. Only the
/// changes up to `covered_seq` become durable; a failed write leaves the
/// store dirty for the next writer.
fn finish_persist(inner: &mut S4Inner, covered_seq: u64, written: bool) -> bool {
    if !written {
        inner.dirty = true;
        return false;
    }
    inner.file_exists = true;
    inner.not_durable.retain(|_, seq| *seq > covered_seq);
    true
}

/// Temp write, fsync, atomic rename and directory fsync (§5).
///
/// The temp file is created owner-only (`0600`) before any byte goes in,
/// whatever the umask: S3/S4 sidecars can hold private key material
/// (ADR 0012). The rename keeps that mode.
async fn write_bytes_durably(
    path: &FsPath,
    bytes: &[u8],
    temp_txid: Option<&[u8; 16]>,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("s4");
    let suffix = match temp_txid {
        Some(txid) => hex::encode(txid),
        None => {
            let mut random = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
            hex::encode(random)
        }
    };
    let temp = path.with_file_name(format!("{file_name}.tmp-{suffix}"));
    let write = async {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp).await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temp, path).await
    };
    if let Err(error) = write.await {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(error);
    }
    sync_dir_of(path).await
}

async fn sync_dir_of(path: &FsPath) -> std::io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || super::sync_parent_dir_for_path(&path))
        .await
        .map_err(std::io::Error::other)?
}

async fn write_evjournal(path: &FsPath, journal: &EvJournalV1) -> bool {
    let bytes = match s4::encode_evjournal(journal) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "ADR 0110 S4: cannot encode the prepare journal");
            return false;
        }
    };
    match write_bytes_durably(path, &bytes, None).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "ADR 0110 S4: prepare journal write failed");
            false
        }
    }
}

async fn remove_file_durably(path: &FsPath) {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {
            if let Err(error) = sync_dir_of(path).await {
                tracing::warn!(%error, path = %path.display(), "ADR 0110 S4: directory fsync after journal retire failed");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "ADR 0110 S4: cannot retire the prepare journal");
        }
    }
}

/// ADR 0108 §5a steps 1 to 3: move a damaged file aside under its pending
/// name, fsync the directory and verify the copy. Returns the `txid` and
/// the pending path, or the failed step.
async fn quarantine_file(path: &FsPath, bytes: &[u8]) -> Result<([u8; 16], PathBuf), &'static str> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("rename")?;
    let mut txid = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut txid);
    let pending = path.with_file_name(s4::quarantine_pending_name(file_name, &txid, bytes));
    tokio::fs::rename(path, &pending)
        .await
        .map_err(|_| "rename")?;
    sync_dir_of(path).await.map_err(|_| "fsync")?;
    let copy = tokio::fs::read(&pending).await.map_err(|_| "verify")?;
    if s4::quarantine_hash_hex(&copy) != s4::quarantine_hash_hex(bytes) {
        return Err("verify");
    }
    Ok((txid, pending))
}

/// ADR 0108 §5a step 5: mark a pending copy as history.
async fn finalize_quarantine(pending: &FsPath) -> bool {
    let Some(name) = pending.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(history) = s4::quarantine_history_name(name) else {
        return false;
    };
    let history = pending.with_file_name(history);
    if tokio::fs::rename(pending, &history).await.is_err() {
        return false;
    }
    sync_dir_of(&history).await.is_ok()
}

/// ADR 0108 §5a resume: the verified pending copies of `file` (set `V`) in
/// `txid` order. A copy that fails verification stays pending.
async fn verified_pending_copies(path: &FsPath) -> (Vec<([u8; 16], PathBuf)>, bool) {
    let Some(dir) = path.parent() else {
        return (Vec::new(), false);
    };
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return (Vec::new(), false);
    };
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return (Vec::new(), false);
    };
    let mut found = Vec::new();
    let mut failed = false;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((txid, h)) = s4::parse_quarantine_pending_name(file_name, name) else {
            continue;
        };
        match tokio::fs::read(entry.path()).await {
            Ok(copy) if s4::quarantine_hash_hex(&copy) == h => found.push((txid, entry.path())),
            _ => failed = true,
        }
    }
    found.sort_by_key(|entry| entry.0);
    (found, failed)
}

/// Load the `.evs` sidecar and reconcile leftover `.evjournal` files at
/// worker start (§5). Never touches legacy files.
async fn load_persisted_obligations(state: &AppState) {
    let runtime = &state.revocation_evictions;
    let _writer = runtime.evs_writer.lock().await;
    let path = evs_path(state);
    let (pending, verify_failed) = match sync_dir_of(&path).await {
        Ok(()) => verified_pending_copies(&path).await,
        Err(_) => (Vec::new(), true),
    };
    let mut sidecar = SidecarStatus::default();
    let mut store = ObligationStore::new();
    let mut rebuilt_from = Vec::new();
    let mut rebuilding = false;
    let mut file_exists = false;
    let mut queued_bans = BTreeMap::new();
    let mut covered: Vec<([u8; 16], PathBuf)> = Vec::new();
    let mut finalize: Vec<PathBuf> = Vec::new();
    match tokio::fs::read(&path).await {
        Ok(bytes) => match s4::decode_evs_with_queued_bans(&bytes) {
            Ok((body, bans)) => {
                store = ObligationStore::from_rows(body.rows);
                queued_bans = bans
                    .into_iter()
                    .map(|ban| {
                        (
                            EvictionKey::new(ban.stable_group_id, ban.target),
                            ban.queued_at_unix_ms,
                        )
                    })
                    .collect();
                rebuilt_from = body.rebuilt_from;
                file_exists = true;
                finalize.extend(pending.into_iter().map(|(_, copy)| copy));
            }
            Err(SidecarDecodeError::NewerFormat(version)) => {
                sidecar.state = SidecarState::SidecarNewerFormat;
                sidecar.detail = Some(format!("version {version}"));
            }
            Err(SidecarDecodeError::Damaged(reason)) => {
                tracing::warn!(reason, path = %path.display(), "ADR 0110 S4: damaged obligation sidecar; quarantining (ADR 0108 §5a)");
                covered = pending;
                match quarantine_file(&path, &bytes).await {
                    Ok(entry) => covered.push(entry),
                    Err(step) => {
                        sidecar.state = SidecarState::SidecarQuarantineFailed;
                        sidecar.detail = Some(format!("step {step}"));
                    }
                }
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            covered = pending;
        }
        Err(_) => {
            sidecar.state = SidecarState::SidecarUnavailable;
            sidecar.detail = Some("cause read_error".to_string());
        }
    }
    if verify_failed && sidecar.state == SidecarState::Ok && covered.is_empty() && !file_exists {
        sidecar.state = SidecarState::SidecarQuarantineFailed;
        sidecar.detail = Some("step verify".to_string());
    }
    if !covered.is_empty() && sidecar.state == SidecarState::Ok {
        // ADR 0108 §5a step 4: one empty replacement that covers `V`; the
        // next pass refills it from the rebuild source (§5).
        covered.sort_by_key(|entry| entry.0);
        let txids: Vec<[u8; 16]> = covered.iter().map(|(txid, _)| *txid).collect();
        let body = EvsBodyV1 {
            rebuilt_from: txids.clone(),
            rows: Vec::new(),
        };
        let written = match (s4::encode_evs(&body), txids.first()) {
            (Ok(bytes), Some(first)) => write_bytes_durably(&path, &bytes, Some(first))
                .await
                .is_ok(),
            _ => false,
        };
        if written {
            sidecar.state = SidecarState::Rebuilt;
            rebuilt_from = txids;
            rebuilding = true;
            file_exists = true;
            finalize.extend(covered.into_iter().map(|(_, copy)| copy));
        } else {
            sidecar.state = SidecarState::SidecarQuarantineFailed;
            sidecar.detail = Some("step replace".to_string());
        }
    }
    for copy in finalize {
        if !finalize_quarantine(&copy).await {
            tracing::warn!(path = %copy.display(), "ADR 0110 S4: cannot finalize a quarantined copy");
        }
    }
    // Speculative preparation never survives a restart on its own (§5).
    let journals = reconcile_evjournals(state).await;
    for row in store.to_rows() {
        if row.phase == Phase::Prepared && !journals.contains_key(&row.key()) {
            if let Some(stored) = store.get_mut(&row.key()) {
                stored.phase = Phase::Pending;
                stored.parent_head = None;
            }
        }
    }
    let mut ce_state = crypto_exclusion::CeState::default();
    resume_crypto_exclusions(state, &mut store, &journals, &mut ce_state).await;
    removal_journal::adopt_journal_removals(&mut store, &journals);
    let mut removals = HashMap::new();
    let loaded_groups = snapshot_groups(state).await;
    removal_delivery::resume_after_load(
        &loaded_groups,
        state.agent.agent_id().as_bytes(),
        &mut store,
        &mut removals,
        &mut ce_state,
    );
    // §4: the catch-up log survives the restart from the rows' frames.
    crypto_exclusion::rebuild_catchup_log(&loaded_groups, &store, &mut ce_state);
    for key in journals.keys() {
        if let Some(stored) = store.get_mut(key) {
            if stored.phase == Phase::Prepared {
                // An unchanged parent with no legacy commit evidence returns
                // to pending; a landed commit is recognised from the chain
                // by the next reconciliation.
                stored.phase = Phase::Pending;
                stored.parent_head = None;
            }
        }
    }
    let mut inner = runtime.inner.lock().await;
    inner.store = store;
    inner.sidecar = sidecar;
    inner.rebuilt_from = rebuilt_from;
    inner.rebuilding = rebuilding;
    inner.file_exists = file_exists;
    // A receipt that ran before this load keeps its held frames.
    ce_state.keep_live_held_log(&mut inner.ce);
    inner.ce = ce_state;
    inner.removals = removals;
    inner.queued_bans = queued_bans;
    inner.dirty = !journals.is_empty();
    drop(inner);
    handoff_log::load(state).await;
}

/// Read every `.evjournal` in the TreeKEM directory, classify it, and
/// retire it (§5). Damaged journals are quarantined with no replacement
/// (ADR 0110 §5 "a missing journal is the normal state"). Returns the keys
/// of the prepared transitions found.
async fn reconcile_evjournals(state: &AppState) -> HashMap<EvictionKey, EvJournalV1> {
    let mut keys = HashMap::new();
    let Ok(mut entries) = tokio::fs::read_dir(&state.treekem_dir).await else {
        return keys;
    };
    let mut paths = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some(s4::EVJOURNAL_EXTENSION) {
            paths.push(path);
        }
    }
    for path in paths {
        let Ok(bytes) = tokio::fs::read(&path).await else {
            continue;
        };
        match s4::decode_evjournal(&bytes) {
            Ok(journal) => {
                let key = EvictionKey::new(journal.stable_group_id.clone(), journal.target);
                keys.insert(key, journal);
                remove_file_durably(&path).await;
            }
            Err(SidecarDecodeError::NewerFormat(_)) => {}
            Err(SidecarDecodeError::Damaged(reason)) => {
                tracing::warn!(reason, path = %path.display(), "ADR 0110 S4: damaged prepare journal; quarantining (ADR 0108 §5a)");
                match quarantine_file(&path, &bytes).await {
                    Ok((_, pending)) => {
                        finalize_quarantine(&pending).await;
                    }
                    Err(step) => {
                        tracing::warn!(step, path = %path.display(), "ADR 0110 S4: prepare journal quarantine failed");
                    }
                }
            }
        }
    }
    keys
}

// ─── Public status (D64) ───────────────────────────────────────────────────

fn waiting_json(waiting: &WaitingState) -> serde_json::Value {
    let named: Vec<String> = waiting.named.iter().map(hex::encode).collect();
    let designated = (waiting.cause == WaitingCause::WaitingForDesignatedAdmin
        || waiting.cause == WaitingCause::LocalCommitterIneligible)
        .then(|| named.first().cloned())
        .flatten();
    serde_json::json!({
        "cause": waiting.cause.as_str(),
        "named": named,
        "designated_admin": designated,
        "detail": waiting.designated_detail,
        "remaining_ms": waiting.remaining_ms,
    })
}

/// The S4 public status of one group for `GET /groups/:id`.
pub(in crate::server) struct GroupS4Status {
    /// `revocation_evictions`: one entry per obligation row.
    pub(in crate::server) rows: serde_json::Value,
    /// `revocation_eviction_store`: the `.evs` sidecar state.
    pub(in crate::server) store: serde_json::Value,
    /// `admin_availability`: the derived §4/§4b state, `null` while an
    /// eligible admin exists.
    pub(in crate::server) admin_availability: serde_json::Value,
    /// `certificate_evidence_waits`: §1a `waiting_for_certificate_evidence`
    /// for each Active digest-only seat of an `OwnerCertified` group whose
    /// committed certificate bytes this node lacks.
    pub(in crate::server) certificate_evidence_waits: serde_json::Value,
    /// `certificate_rebind`: §4a `waiting_for_admin_rebind`, §4b(2) held
    /// self-rebinds and the renewals this admin holds.
    pub(in crate::server) certificate_rebind: serde_json::Value,
}

/// §1a: Active seats whose committed digest has no matching bytes here.
fn certificate_evidence_waits(info: &GroupInfo) -> serde_json::Value {
    if !owner_certified(info) || info.withdrawn {
        return serde_json::Value::Array(Vec::new());
    }
    let waits: Vec<serde_json::Value> = info
        .active_members()
        .filter_map(|member| {
            let digest = member.certificate_digest.as_deref()?;
            let held = member.certificate.as_ref().is_some_and(|cert| {
                x0x::groups::owner_cert::certificate_digest_hex(cert) == digest
            });
            (!held).then(|| {
                serde_json::json!({
                    "cause": WaitingCause::WaitingForCertificateEvidence.as_str(),
                    "agent_id": member.agent_id,
                    "certificate_digest": digest,
                })
            })
        })
        .collect();
    serde_json::Value::Array(waits)
}

/// The S4 rows of one group, the sidecar state and the §4 admin state.
pub(in crate::server) async fn group_status_json(
    state: &AppState,
    info: &GroupInfo,
) -> GroupS4Status {
    let mut admin_availability = no_eligible_admin_state(state, info)
        .await
        .map_or(serde_json::Value::Null, |derived| {
            no_eligible_admin_json(&derived)
        });
    if let Some(object) = admin_availability.as_object_mut() {
        // §4b(1): the owner-recovery progress behind exit `owner_recovery`.
        object.insert(
            "owner_recovery".into(),
            owner_recovery::status_json(state, info.stable_group_id()).await,
        );
    }
    let (rows, store) = group_rows_json(state, info).await;
    let certificate_rebind =
        rebind::status_json(&state.revocation_evictions.inner.lock().await.rebind, info);
    GroupS4Status {
        rows,
        store,
        admin_availability,
        certificate_evidence_waits: certificate_evidence_waits(info),
        certificate_rebind,
    }
}

async fn group_rows_json(
    state: &AppState,
    info: &GroupInfo,
) -> (serde_json::Value, serde_json::Value) {
    let stable = info.stable_group_id();
    let inner = state.revocation_evictions.inner.lock().await;
    let rows: Vec<serde_json::Value> = inner
        .store
        .rows_for_group(stable)
        .map(|row| {
            let key = row.key();
            let mut queued: Vec<serde_json::Value> = inner
                .queued_manual
                .get(&key)
                .map(|requests| {
                    requests
                        .iter()
                        .map(|request| {
                            serde_json::json!({
                                "request": request.kind.as_str(),
                                "queued_at_unix_ms": request.queued_at_unix_ms,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            // A queued ban survives a restart; the in-memory list does not.
            let listed_ban = inner.queued_manual.get(&key).is_some_and(|requests| {
                requests
                    .iter()
                    .any(|request| request.kind == ManualRequestKind::Ban)
            });
            if let (false, Some(queued_at)) = (listed_ban, inner.queued_bans.get(&key)) {
                queued.push(serde_json::json!({
                    "request": ManualRequestKind::Ban.as_str(),
                    "queued_at_unix_ms": queued_at,
                }));
            }
            serde_json::json!({
                "target": hex::encode(row.target),
                "phase": row.phase.as_str(),
                "triggers": row.trigger_kinds(),
                "termination_cause": row.termination.map(TerminationCause::as_str),
                "designated_admin": row.designated.map(hex::encode),
                "fallback_ranks": row.ranks.iter().map(hex::encode).collect::<Vec<_>>(),
                "waiting": row.waiting.as_ref().map(waiting_json),
                "queued_requests": queued,
                "observed_at_unix_ms": row.observed_at_unix_ms,
                "result_head": row.result_head,
                "result_epoch": row.result_epoch,
                "receiver_upgrade_members": inner.ce.stranded_json(&key),
            })
        })
        .collect();
    let store = serde_json::json!({
        "state": inner.sidecar.state,
        "file": s4::EVS_FILE_NAME,
        "detail": inner.sidecar.detail,
        "rebuilt_from": inner.rebuilt_from.iter().map(hex::encode).collect::<Vec<_>>(),
    });
    (serde_json::Value::Array(rows), store)
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Codex round 1, item 2: persistence generation ─────────────────

    #[test]
    fn a_change_made_during_a_write_stays_dirty_and_not_durable() {
        let mut inner = S4Inner {
            file_exists: true,
            ..S4Inner::default()
        };
        let first = EvictionKey::new("g".to_string(), [1; 32]);
        let second = EvictionKey::new("g".to_string(), [2; 32]);
        inner.mark_not_durable(&first);
        let snapshot = begin_persist(&mut inner, true).expect("a write is due");
        // Another task changes rows while the disk write is in flight.
        inner.mark_not_durable(&first);
        inner.mark_not_durable(&second);
        assert!(finish_persist(&mut inner, snapshot.change_seq, true));
        assert!(inner.dirty, "the newer change still needs a write");
        assert!(inner.not_durable.contains_key(&first));
        assert!(inner.not_durable.contains_key(&second));
        let next = begin_persist(&mut inner, true).expect("the newer change is written");
        assert!(finish_persist(&mut inner, next.change_seq, true));
        assert!(!inner.dirty);
        assert!(inner.not_durable.is_empty());
        assert_eq!(begin_persist(&mut inner, true).err(), Some(true));
    }

    #[test]
    fn a_failed_write_keeps_the_store_dirty() {
        let mut inner = S4Inner {
            file_exists: true,
            ..S4Inner::default()
        };
        let key = EvictionKey::new("g".to_string(), [1; 32]);
        inner.mark_not_durable(&key);
        let snapshot = begin_persist(&mut inner, true).expect("a write is due");
        assert!(!finish_persist(&mut inner, snapshot.change_seq, false));
        assert!(inner.dirty);
        assert!(inner.not_durable.contains_key(&key));
        assert_eq!(begin_persist(&mut inner, false).err(), Some(false));
    }

    // ─── Codex round 1, item 4: queued bans survive a restart ──────────

    #[test]
    fn a_queued_ban_is_written_and_read_back() {
        let mut inner = S4Inner::default();
        let key = EvictionKey::new("g".to_string(), [3; 32]);
        inner.queued_bans.insert(key.clone(), 77);
        inner.dirty = true;
        // The store has no row and no file yet: the ban alone creates it.
        let snapshot = begin_persist(&mut inner, true).expect("the ban is written");
        let (body, bans) = s4::decode_evs_with_queued_bans(&snapshot.bytes).expect("decode");
        assert!(body.rows.is_empty());
        assert_eq!(
            bans,
            vec![QueuedBanV1 {
                stable_group_id: "g".into(),
                target: [3; 32],
                queued_at_unix_ms: 77,
            }]
        );
    }

    // ─── Codex round 1, item 3: head sync is not elapsed time ──────────

    #[test]
    fn elapsed_time_alone_does_not_sync_a_head_with_unresolved_evidence() {
        let wait = Duration::from_secs(13);
        let start = Instant::now();
        let mut rounds = HashMap::new();
        let mut asks = HeadRoundAsks::new();
        let holders = [[9; 32]];
        let asked = refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, start, wait);
        assert_eq!(asked, holders.to_vec());
        let later = start + wait * 10;
        let round = rounds.get("g").expect("round");
        // A stale replica: queued higher-head evidence is still open.
        assert!(!round.synced("h1", 1, true, true, later, wait));
        // The restart minimum is necessary.
        assert!(!round.synced("h1", 1, false, false, later, wait));
        // No evidence and no answer: the bounded wait ends discovery (D73).
        assert!(!round.synced("h1", 1, false, true, start, wait));
        assert!(round.synced("h1", 1, false, true, later, wait));
        // The round confirms one head only.
        assert!(!round.synced("h2", 1, false, true, later, wait));
    }

    /// CI DIAG #1546 W3-H `s4_designated_late_observation` (iteration 11):
    /// the designated admin observes at about W/2 and must seal within the
    /// rest of W. A round asked each holder once, so one lost request or
    /// answer left it waiting for the 13 s restart sync wait, longer than
    /// the time left, and the ranked fallback signed instead. ADR 0110 §2:
    /// "failure to progress with an available holder is a defect". A holder
    /// that has not answered is asked again, well inside the wait.
    #[test]
    fn a_holder_that_did_not_answer_is_asked_again_inside_the_wait() {
        let wait = Duration::from_secs(13);
        let start = Instant::now();
        let mut rounds = HashMap::new();
        let mut asks = HeadRoundAsks::new();
        let holders = [[8; 32], [9; 32]];
        assert_eq!(
            refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, start, wait),
            holders.to_vec()
        );
        assert!(
            refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, start, wait).is_empty(),
            "no second ask in the same instant"
        );
        // [9; 32] reports a head this node does not have; [8; 32] is silent.
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h1",
            [9; 32],
            HeadReport::Unknown,
            start,
        );
        let later = start + Duration::from_secs(3);
        assert_eq!(
            refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, later, wait),
            vec![[8; 32]],
            "the silent holder is asked again; the one that answered is not"
        );
    }

    /// #1508 Codex P1: a retry asks every holder again, but it must not
    /// erase the unresolved report. ADR 0110 §2: "no known
    /// higher/conflicting head ... may remain unresolved". Only the
    /// reporting holder's own later report on the local chain resolves it.
    #[test]
    fn a_conflicting_head_report_blocks_the_seal_until_resolved() {
        let wait = Duration::from_secs(13);
        let start = Instant::now();
        let mut rounds = HashMap::new();
        let mut asks = HeadRoundAsks::new();
        let (a, b) = ([8; 32], [9; 32]);
        let holders = [a, b];
        refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, start, wait);
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h1",
            a,
            HeadReport::Unknown,
            start,
        );
        let later = start + wait * 10;
        assert!(!rounds
            .get("g")
            .expect("round")
            .synced("h1", 2, false, true, later, wait));
        // After the wait the round asks every holder again, A included.
        let again = refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, later, wait);
        assert_eq!(again, holders.to_vec());
        // B confirms the local head. A's report is still unresolved.
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h1",
            b,
            HeadReport::OnLocalChain,
            later,
        );
        assert!(
            !rounds
                .get("g")
                .expect("round")
                .synced("h1", 2, false, true, later, wait),
            "the retry kept A's unknown-head report"
        );
        // A itself now reports a head on the local chain: resolved.
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h1",
            a,
            HeadReport::OnLocalChain,
            later,
        );
        assert!(rounds
            .get("g")
            .expect("round")
            .synced("h1", 2, false, true, later, wait));
        // A new local head needs a new round.
        refresh_head_round(&mut rounds, &mut asks, "g", "h2", &holders, later, wait);
        assert!(!rounds
            .get("g")
            .expect("round")
            .synced("h2", 2, false, true, later, wait));
    }

    /// #1508 Codex P1, the head-change path: a new local head starts a new
    /// round, in [`refresh_head_round`] and in [`note_head_report`]. The
    /// new round keeps A's unresolved report and asks A again; another
    /// holder's confirmation does not resolve it.
    #[test]
    fn a_new_local_head_keeps_an_unresolved_head_report() {
        let wait = Duration::from_secs(13);
        let start = Instant::now();
        let (a, b) = ([8; 32], [9; 32]);
        let holders = [a, b];
        // The worker pass sees the new head first.
        let mut rounds = HashMap::new();
        let mut asks = HeadRoundAsks::new();
        refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, start, wait);
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h1",
            a,
            HeadReport::Unknown,
            start,
        );
        let next = start + Duration::from_millis(1);
        let asked = refresh_head_round(&mut rounds, &mut asks, "g", "h2", &holders, next, wait);
        assert_eq!(asked, holders.to_vec(), "the new round asks A again");
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h2",
            b,
            HeadReport::OnLocalChain,
            next,
        );
        let round = rounds.get("g").expect("round");
        assert!(!round.synced("h2", 2, false, true, next, wait));
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h2",
            a,
            HeadReport::OnLocalChain,
            next,
        );
        let round = rounds.get("g").expect("round");
        assert!(round.synced("h2", 2, false, true, next, wait));
        // A report arrives first for the new head.
        let mut rounds = HashMap::new();
        let mut asks = HeadRoundAsks::new();
        refresh_head_round(&mut rounds, &mut asks, "g", "h1", &holders, start, wait);
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h1",
            a,
            HeadReport::Unknown,
            start,
        );
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h2",
            b,
            HeadReport::OnLocalChain,
            start,
        );
        let round = rounds.get("g").expect("round");
        assert!(
            !round.synced("h2", 2, false, true, start, wait),
            "the head change in the report path kept A's report"
        );
        // A holder that is no longer a holder (it left, or it is now an
        // open target) no longer blocks.
        refresh_head_round(&mut rounds, &mut asks, "g", "h2", &[b], start, wait);
        let round = rounds.get("g").expect("round");
        assert!(round.synced("h2", 1, false, true, start, wait));
    }

    /// CI W3-H `w3h_1357_red_s4_restart_intake_prepare`: the committer is
    /// at r+1 after its own removal; the survivor that missed it is still
    /// at r. Its report must not block the resend that brings it forward.
    #[test]
    fn a_holder_behind_on_the_local_chain_does_not_block_the_seal() -> anyhow::Result<()> {
        let kp = x0x::identity::AgentKeypair::generate()?;
        let admin = *kp.agent_id().as_bytes();
        let mut info = group_with(admin, [2; 32]);
        info.seal_commit(&kp, 1)?;
        let parent = info.state_hash.clone();
        let mut sibling = info.clone();
        info.seal_commit(&kp, 2)?;
        let head = info.state_hash.clone();
        sibling.add_member(hex::encode([5; 32]), GroupRole::Member, None, None);
        sibling.seal_commit(&kp, 3)?;
        assert_ne!(sibling.state_hash, head);
        let mut later = info.clone();
        later.seal_commit(&kp, 4)?;

        assert_eq!(classify_head_report(&info, &head), HeadReport::OnLocalChain);
        assert_eq!(
            classify_head_report(&info, &parent),
            HeadReport::OnLocalChain
        );
        assert_eq!(
            classify_head_report(&info, &later.state_hash),
            HeadReport::Unknown
        );
        assert_eq!(
            classify_head_report(&info, &sibling.state_hash),
            HeadReport::Unknown
        );

        let wait = Duration::from_secs(13);
        let now = Instant::now();
        let holder = [8; 32];
        let synced_after = |reported: &str| {
            let mut rounds = HashMap::new();
            let mut asks = HeadRoundAsks::new();
            refresh_head_round(&mut rounds, &mut asks, "g", &head, &[holder], now, wait);
            let report = classify_head_report(&info, reported);
            note_head_report(&mut rounds, &mut asks, "g", &head, holder, report, now);
            rounds
                .get("g")
                .is_some_and(|round| round.synced(&head, 1, false, true, now, wait))
        };
        // Behind at r (our parent): synced at once.
        assert!(synced_after(&parent));
        // r+2, which this node does not have: not synced.
        assert!(!synced_after(&later.state_hash));
        // A sibling at r+1: not synced.
        assert!(!synced_after(&sibling.state_hash));
        Ok(())
    }

    #[test]
    fn a_confirmed_round_or_no_holder_syncs_at_once() {
        let wait = Duration::from_secs(13);
        let now = Instant::now();
        let mut rounds = HashMap::new();
        let mut asks = HeadRoundAsks::new();
        refresh_head_round(&mut rounds, &mut asks, "g", "h1", &[[8; 32]], now, wait);
        assert!(!rounds
            .get("g")
            .expect("round")
            .synced("h1", 1, false, true, now, wait));
        note_head_report(
            &mut rounds,
            &mut asks,
            "g",
            "h1",
            [8; 32],
            HeadReport::OnLocalChain,
            now,
        );
        assert!(rounds
            .get("g")
            .expect("round")
            .synced("h1", 1, false, true, now, wait));
        let alone = HeadRound::new("h1", now);
        assert!(alone.synced("h1", 0, false, true, now, wait));
        assert!(!alone.synced("h1", 0, true, true, now, wait));
    }

    // ─── Codex round 1, item 1: several revoked OwnerCertified seats ───

    #[test]
    fn an_s4_removal_seal_tolerates_only_other_open_s4_targets() {
        let (admin, first, second, other) = ([1; 32], [2; 32], [3; 32], [4; 32]);
        let mut info = group_with(admin, first);
        info.add_member(hex::encode(second), GroupRole::Member, None, None);
        info.add_member(hex::encode(other), GroupRole::Member, None, None);
        let stable = info.stable_group_id().to_string();
        let mut store = ObligationStore::new();
        for (target, hash) in [(first, 7), (second, 8)] {
            store.intake(
                &EvictionKey::new(stable.clone(), target),
                EvictionTrigger::AgentRevocation {
                    record_hash: [hash; 32],
                    record_bytes: vec![hash],
                },
                None,
                0,
                [0; 16],
            );
        }
        let scope = eviction_seal_scope(&store, &EvictionKey::new(stable.clone(), first));
        let failed_second = vec![hex::encode(second)];
        // The working copy still seats the target: no tolerance.
        assert!(!eviction_seal_tolerates(&scope, &info, &failed_second));
        info.remove_member(&hex::encode(first), Some(hex::encode(admin)));
        // The second revoked seat is open S4 work: the first removal seals.
        assert!(eviction_seal_tolerates(&scope, &info, &failed_second));
        // Any failing seat that is not open S4 work keeps the refusal.
        let with_other = vec![hex::encode(second), hex::encode(other)];
        assert!(!eviction_seal_tolerates(&scope, &info, &with_other));
        assert!(!eviction_seal_tolerates(&scope, &info, &[]));
        // Outside an S4 removal nothing is tolerated.
        assert!(!s4_eviction_seal_tolerates(&info, &failed_second));
        // The second removal then needs no tolerance: its seal is clean.
        let second_scope = eviction_seal_scope(&store, &EvictionKey::new(stable, second));
        assert!(second_scope.pending_targets.contains(&hex::encode(first)));
    }

    #[test]
    fn retained_leaves_unknown_group_is_not_tracked() {
        let leaves = RetainedLeaves::default();
        assert_eq!(leaves.tracks("g", &[1; 32]), Some(false));
        assert!(leaves.known("g"));
    }

    #[test]
    fn busy_tree_is_unknown_not_empty() {
        let mut leaves = RetainedLeaves::default();
        leaves.by_group.insert("g".into(), None);
        assert_eq!(leaves.tracks("g", &[1; 32]), None);
        assert!(!leaves.known("g"));
    }

    fn group_with(admin: [u8; 32], member: [u8; 32]) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".into(),
            String::new(),
            x0x::identity::AgentId(admin),
            "mls-g".into(),
        );
        info.add_member(hex::encode(admin), GroupRole::Admin, None, None);
        info.add_member(hex::encode(member), GroupRole::Member, None, None);
        info
    }

    fn revocation_of(target: [u8; 32], hash: u8) -> VerifiedAgentRevocation {
        VerifiedAgentRevocation {
            target,
            record_hash: [hash; 32],
            record_bytes: vec![hash],
            from_startup_load: false,
        }
    }

    #[test]
    fn revocation_of_a_seated_member_creates_work_and_removal_completes_it() {
        let admin_kp = x0x::identity::AgentKeypair::generate().expect("keypair");
        let (admin, member) = (*admin_kp.agent_id().as_bytes(), [2; 32]);
        let mut info = group_with(admin, member);
        info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
        info.seal_commit(&admin_kp, 1).expect("seat");
        let groups = vec![("k".to_string(), info.clone())];
        let leaves = RetainedLeaves::default();
        let triggers = derive_triggers(&groups, &leaves, &[revocation_of(member, 7)], 0);
        assert_eq!(triggers.len(), 1);
        let (key, trigger, _) = triggers.into_iter().next().expect("trigger");
        assert_eq!(key.target, member);
        let mut store = ObligationStore::new();
        store.intake(&key, trigger, None, 0, [0; 16]);
        // Still seated: nothing completes.
        assert!(!reconcile_completion(
            &mut store,
            &groups,
            &leaves,
            &BTreeSet::new(),
            1
        ));
        info.remove_member(&hex::encode(member), Some(hex::encode(admin)));
        // A GSS admin removal rotates the secret in its own commit: that
        // rotation is the proof that completes the row (#1508 review).
        let _ = info.rotate_shared_secret();
        info.seal_commit(&admin_kp, 2).expect("remove");
        let removed = vec![("k".to_string(), info)];
        // A running crypto-only delivery keeps the row open (§3).
        let delivering: BTreeSet<EvictionKey> = [key.clone()].into_iter().collect();
        assert!(!reconcile_completion(
            &mut store,
            &removed,
            &leaves,
            &delivering,
            2
        ));
        assert_eq!(store.get(&key).expect("row").phase, Phase::Pending);
        assert!(reconcile_completion(
            &mut store,
            &removed,
            &leaves,
            &BTreeSet::new(),
            2
        ));
        assert_eq!(store.get(&key).expect("row").phase, Phase::Complete);
    }

    #[test]
    fn a_self_leaver_without_a_retained_leaf_creates_no_work() {
        let (admin, member) = ([1; 32], [2; 32]);
        let mut info = group_with(admin, member);
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.remove_member(&hex::encode(member), Some(hex::encode(member)));
        let stable = info.stable_group_id().to_string();
        let groups = vec![("k".to_string(), info)];
        let mut leaves = RetainedLeaves::default();
        leaves
            .by_group
            .insert(stable.clone(), Some((Vec::new(), 3)));
        assert!(derive_triggers(&groups, &leaves, &[revocation_of(member, 7)], 0).is_empty());
        // With the leaf still in the tree, the leave and the revocation
        // both open the one (group, target) row.
        leaves.by_group.insert(stable, Some((vec![member], 3)));
        let triggers = derive_triggers(&groups, &leaves, &[revocation_of(member, 7)], 0);
        assert_eq!(triggers.len(), 2);
        assert!(triggers.iter().all(|(key, _, _)| key.target == member));
    }

    #[test]
    fn a_withdrawn_group_terminates_its_rows() {
        let (admin, member) = ([1; 32], [2; 32]);
        let mut info = group_with(admin, member);
        let key = EvictionKey::new(info.stable_group_id(), member);
        let mut store = ObligationStore::new();
        store.intake(
            &key,
            EvictionTrigger::AgentRevocation {
                record_hash: [7; 32],
                record_bytes: vec![7],
            },
            None,
            0,
            [0; 16],
        );
        info.withdrawn = true;
        let groups = vec![("k".to_string(), info)];
        assert!(reconcile_completion(
            &mut store,
            &groups,
            &RetainedLeaves::default(),
            &BTreeSet::new(),
            1
        ));
        let row = store.get(&key).expect("row");
        assert_eq!(row.phase, Phase::Terminated);
        assert_eq!(row.termination, Some(TerminationCause::GroupDeleted));
    }

    #[tokio::test]
    async fn durable_write_replaces_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(s4::EVS_FILE_NAME);
        write_bytes_durably(&path, b"one", None)
            .await
            .expect("write one");
        write_bytes_durably(&path, b"two", None)
            .await
            .expect("write two");
        assert_eq!(tokio::fs::read(&path).await.expect("read"), b"two");
        let leftovers = std::fs::read_dir(dir.path())
            .expect("dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(leftovers, 0);
    }

    /// ADR 0012 (#1533 review): every S3/S4 sidecar can hold private key
    /// material (the re-seat journal holds a TreeKEM snapshot), so a durable
    /// write is owner-only under the common umask 022, also when it replaces
    /// an older world-readable file.
    #[cfg(unix)]
    #[tokio::test]
    async fn durable_write_is_owner_only_under_umask_022() {
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: `umask` only swaps the process file-mode mask. nextest
        // runs each test in its own process.
        let previous = unsafe { libc::umask(0o022) };
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("group.grecov");
        std::fs::write(&path, b"old").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let written = write_bytes_durably(&path, b"secret", None).await;
        // SAFETY: as above.
        unsafe { libc::umask(previous) };
        written.expect("write");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "sidecar bytes are private");
    }

    #[tokio::test]
    async fn quarantine_moves_damage_aside_and_finalizes_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(s4::EVS_FILE_NAME);
        tokio::fs::write(&path, b"X0XEVICT1").await.expect("seed");
        let (txid, pending) = quarantine_file(&path, b"X0XEVICT1")
            .await
            .expect("quarantine");
        assert!(!path.exists());
        let (copies, failed) = verified_pending_copies(&path).await;
        assert!(!failed);
        assert_eq!(copies, vec![(txid, pending.clone())]);
        assert!(finalize_quarantine(&pending).await);
        assert!(!pending.exists());
        let history = std::fs::read_dir(dir.path())
            .expect("dir")
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.starts_with("revocation-evictions.evs.q-") && !name.ends_with(".pending")
            })
            .count();
        assert_eq!(history, 1);
    }

    /// An `OwnerCertified` group whose seat `target` commits `cert`.
    fn certified_group(cert: &x0x::identity::AgentCertificate, target: [u8; 32]) -> GroupInfo {
        let mut info = group_with([1; 32], target);
        let owner = cert.user_id().expect("owner");
        info.policy.admission = x0x::groups::policy::GroupAdmission::OwnerCertified(owner);
        info.set_member_certificate(&hex::encode(target), cert.clone())
            .expect("certificate");
        info
    }

    fn expiring(not_after: u64) -> (x0x::identity::AgentCertificate, [u8; 32]) {
        let owner = x0x::identity::UserKeypair::generate().expect("owner");
        let agent = x0x::identity::AgentKeypair::generate().expect("agent");
        let cert =
            x0x::identity::AgentCertificate::issue_with_expiry(&owner, &agent, Some(not_after))
                .expect("cert");
        (cert, *agent.agent_id().as_bytes())
    }

    /// #1508 review P1 #2 (CI DIAG #1547, #1548): every S4 route run for a
    /// `prepared` row is the worker's own removal, so the gate and the
    /// under-lock check cancel it once a rebind ends the row. The mark
    /// comes from the row, not from a flag that each caller must set.
    #[test]
    fn the_seal_scope_of_a_prepared_row_marks_the_workers_removal() {
        let key = EvictionKey::new("g", [2; 32]);
        let mut store = ObligationStore::new();
        let expiry = EvictionTrigger::CertificateExpiry {
            certificate_digest: "d".into(),
            not_after: 1,
        };
        store.intake(&key, expiry, None, 0, [0; 16]);
        assert!(
            !eviction_seal_scope(&store, &key).prepared_removal,
            "pending"
        );
        store.get_mut(&key).expect("row").phase = Phase::Prepared;
        assert!(
            eviction_seal_scope(&store, &key).prepared_removal,
            "prepared"
        );
        store.terminate(&key, TerminationCause::CertificateValid);
        assert!(
            !eviction_seal_scope(&store, &key).prepared_removal,
            "a queued ban of an ended row is not the worker's removal"
        );
    }

    /// CI on 05d1ecc (`a_rebind_during_the_expiry_prepare_keeps_the_renewed_seat`):
    /// the pass ended the row and dropped it in the same step, so the end
    /// (`terminated`, `certificate_valid`) was never durable or visible.
    /// ADR 0110 §5: drop a `terminated` row once the end is durable.
    #[test]
    fn an_ended_row_stays_terminated_until_the_evs_holds_it() {
        let now = now_unix_ms() / 1000;
        let (renewed, target) = expiring(now + 86_400);
        let info = certified_group(&renewed, target);
        let key = EvictionKey::new(info.stable_group_id(), target);
        let groups = vec![("k".to_string(), info)];
        let leaves = RetainedLeaves::default();
        let fresh = || {
            let mut inner = S4Inner::default();
            let expiry = EvictionTrigger::CertificateExpiry {
                certificate_digest: "ab".repeat(32),
                not_after: now - 1_000,
            };
            inner.store.intake(&key, expiry, None, 0, [0; 16]);
            inner
        };
        let mut inner = fresh();
        let at = now * 1000;
        reconcile_and_retain(&mut inner, &groups, &leaves, &BTreeSet::new(), at, false);
        let row = inner.store.get(&key).expect("the ended row is kept");
        assert_eq!(row.phase, Phase::Terminated);
        assert_eq!(row.termination, Some(TerminationCause::CertificateValid));
        assert!(inner.not_durable.contains_key(&key));
        // A later pass before the `.evs` write still keeps it.
        reconcile_and_retain(&mut inner, &groups, &leaves, &BTreeSet::new(), at, false);
        assert!(inner.store.get(&key).is_some());
        // The `.evs` write covered it: the next pass drops it.
        inner.not_durable.clear();
        reconcile_and_retain(&mut inner, &groups, &leaves, &BTreeSet::new(), at, false);
        assert!(inner.store.get(&key).is_none());
        // A memory-only sidecar never becomes durable: no hold.
        let mut memory_only = fresh();
        reconcile_and_retain(
            &mut memory_only,
            &groups,
            &leaves,
            &BTreeSet::new(),
            at,
            true,
        );
        assert!(memory_only.store.get(&key).is_none());
    }

    #[test]
    fn a_rebind_cancels_only_expiry_work_under_the_lock() {
        let now = 1_000_000;
        let (old, target) = expiring(now - 10);
        let info = certified_group(&old, target);
        let key = EvictionKey::new(info.stable_group_id(), target);
        let mut store = ObligationStore::new();
        let expiry = EvictionTrigger::CertificateExpiry {
            certificate_digest: x0x::groups::owner_cert::certificate_digest_hex(&old),
            not_after: now - 10,
        };
        store.intake(&key, expiry, None, 0, [0; 16]);
        let seat = info.members_v2.get(&hex::encode(target));
        let row = store.get(&key).expect("row").clone();
        assert!(exclusion_still_eligible(&row, seat, now));
        assert!(
            !exclusion_still_eligible(&row, seat, now - 20),
            "raw not_after"
        );
        // The rebind commits a renewed certificate into the seat.
        let mut renewed = seat.expect("seat").clone();
        renewed.certificate_digest = Some("ab".repeat(32));
        renewed.certificate = None;
        assert!(!exclusion_still_eligible(&row, Some(&renewed), now));
        // A renewal never cancels revocation work on the same key.
        store.intake(
            &key,
            EvictionTrigger::AgentRevocation {
                record_hash: [3; 32],
                record_bytes: vec![3],
            },
            None,
            0,
            [0; 16],
        );
        let row = store.get(&key).expect("row");
        assert!(exclusion_still_eligible(row, Some(&renewed), now));
    }

    #[test]
    fn an_expiry_handoff_triggers_at_the_raw_not_after_not_at_tau() {
        let now = now_unix_ms() / 1000;
        let (cert, target) = expiring(now - 10);
        let info = certified_group(&cert, target);
        let digest = x0x::groups::owner_cert::certificate_digest_hex(&cert);
        let key = EvictionKey::new(info.stable_group_id(), target);
        let groups = vec![("k".to_string(), info)];
        let leaves = RetainedLeaves::default();
        assert!(
            derive_triggers(&groups, &leaves, &[], now).is_empty(),
            "the own trigger waits for not_after + τ"
        );
        let handoff = ExpiryHandoff {
            certificate_digest: digest.clone(),
            received_unix_ms: (now - 5) * 1000,
        };
        let mut kept = BTreeMap::from([(key.clone(), handoff.clone())]);
        let before = expiry_handoff_triggers(&mut kept, &groups, (now - 20) * 1000);
        assert!(
            before.is_empty() && kept.contains_key(&key),
            "kept until not_after"
        );
        let triggers = expiry_handoff_triggers(&mut kept, &groups, now * 1000);
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0].0, key);
        assert_eq!(triggers[0].3, (now - 5) * 1000, "T_obs is the receipt");
        assert!(kept.is_empty());
        let mut other = BTreeMap::from([(
            key.clone(),
            ExpiryHandoff {
                certificate_digest: "cd".repeat(32),
                ..handoff
            },
        )]);
        assert!(expiry_handoff_triggers(&mut other, &groups, now * 1000).is_empty());
        assert!(
            other.is_empty(),
            "a hand-off for another certificate is dropped"
        );
    }

    /// ADR 0110 §1a hand-off evidence (#1508 review P2 #5): a verified
    /// expiry hand-off carries the bytes of a digest-only seat's committed
    /// certificate. The receiver verifies and installs them, and its
    /// observation starts once its clock passes the raw `not_after`, not
    /// only at its own trigger time `not_after + τ`.
    #[tokio::test]
    async fn an_expiry_handoff_installs_its_certificate_and_starts_at_raw_not_after(
    ) -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let owner = x0x::identity::UserKeypair::generate()?;
        let target_kp = x0x::identity::AgentKeypair::generate()?;
        let target_hex = hex::encode(target_kp.agent_id().as_bytes());
        let sender = x0x::identity::AgentKeypair::generate()?.agent_id();
        let now_unix = now_unix_ms() / 1000;
        // Past the raw `not_after`, but not past `not_after + τ`.
        let not_after = now_unix - 10;
        let cert = x0x::identity::AgentCertificate::issue_with_expiry(
            &owner,
            &target_kp,
            Some(not_after),
        )?;
        let digest = x0x::groups::owner_cert::certificate_digest_hex(&cert);
        let group_id = "a1".repeat(16);
        let stable = {
            let local = state.agent.agent_id();
            let mut info =
                GroupInfo::new("s4-handoff".into(), String::new(), local, group_id.clone());
            info.policy.admission =
                x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
            let local_hex = hex::encode(local.as_bytes());
            info.add_member(
                target_hex.clone(),
                GroupRole::Member,
                Some(local_hex.clone()),
                None,
            );
            info.add_member(
                hex::encode(sender.as_bytes()),
                GroupRole::Admin,
                Some(local_hex),
                None,
            );
            // A digest-only seat: the roster commits the digest only.
            info.members_v2
                .get_mut(&target_hex)
                .expect("seat")
                .certificate_digest = Some(digest.clone());
            info.recompute_state_hash();
            let stable = info.stable_group_id().to_string();
            state
                .named_groups
                .write()
                .await
                .insert(group_id.clone(), info);
            stable
        };
        let handoff = s4::EvictionHandoffV1 {
            stable_group_id: stable.clone(),
            target: *target_kp.agent_id().as_bytes(),
            observed_parent_head: String::new(),
            revocation_records: Vec::new(),
            self_leave_commit: None,
            expired_certificate: Some(s4::HandoffExpiredCertificate {
                certificate_digest: digest.clone(),
                certificate_bytes: Some(bincode::serialize(&cert)?),
            }),
            renewed_certificate: None,
        };
        let payload = s4::encode_handoff(&handoff)?;
        receive_handoff(&state, sender, &payload).await;

        let installed = state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .and_then(|info| info.members_v2.get(&target_hex))
            .and_then(|member| member.certificate.clone());
        assert_eq!(
            installed.as_ref(),
            Some(&cert),
            "the carried bytes are installed"
        );
        let key = EvictionKey::new(stable, *target_kp.agent_id().as_bytes());
        let inner = state.revocation_evictions.inner.lock().await;
        let row = inner
            .store
            .get(&key)
            .expect("the hand-off opens expiry work at the raw not_after");
        assert_eq!(row.expired_certificates.get(&digest), Some(&not_after));
        assert!(row.earliest_handoff_receipt_unix_ms.is_some());
        Ok(())
    }

    /// ADR 0110 §1a and §2 (L175) restart (#1508 review gap 3): a verified
    /// expiry hand-off kept before this node's clock passes the raw
    /// `not_after` survives a restart. After the restart, T_obs still
    /// starts at the raw `not_after`, not at the own trigger `not_after + τ`.
    #[tokio::test]
    async fn a_kept_expiry_handoff_survives_a_restart() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let owner = x0x::identity::UserKeypair::generate()?;
        let target_kp = x0x::identity::AgentKeypair::generate()?;
        let target_hex = hex::encode(target_kp.agent_id().as_bytes());
        let sender = x0x::identity::AgentKeypair::generate()?.agent_id();
        let not_after = now_unix_ms() / 1000 + 2;
        let cert = x0x::identity::AgentCertificate::issue_with_expiry(
            &owner,
            &target_kp,
            Some(not_after),
        )?;
        let digest = x0x::groups::owner_cert::certificate_digest_hex(&cert);
        let group_id = "a5".repeat(16);
        let local = state.agent.agent_id();
        let mut info = GroupInfo::new("s4-kept".into(), String::new(), local, group_id.clone());
        info.policy.admission =
            x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
        let local_hex = hex::encode(local.as_bytes());
        info.add_member(
            target_hex.clone(),
            GroupRole::Member,
            Some(local_hex.clone()),
            None,
        );
        info.add_member(
            hex::encode(sender.as_bytes()),
            GroupRole::Admin,
            Some(local_hex),
            None,
        );
        info.set_member_certificate(&target_hex, cert)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        state.named_groups.write().await.insert(group_id, info);
        let handoff = s4::EvictionHandoffV1 {
            stable_group_id: stable.clone(),
            target: *target_kp.agent_id().as_bytes(),
            observed_parent_head: String::new(),
            revocation_records: Vec::new(),
            self_leave_commit: None,
            expired_certificate: Some(s4::HandoffExpiredCertificate {
                certificate_digest: digest,
                certificate_bytes: None,
            }),
            renewed_certificate: None,
        };
        receive_handoff(&state, sender, &s4::encode_handoff(&handoff)?).await;
        let key = EvictionKey::new(stable, *target_kp.agent_id().as_bytes());
        assert!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .store
                .get(&key)
                .is_none(),
            "before the raw not_after the hand-off is only kept"
        );

        // Restart: the S4 state is reloaded from disk.
        *state.revocation_evictions.inner.lock().await = S4Inner::default();
        load_persisted_obligations(&state).await;
        while now_unix_ms() / 1000 <= not_after {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        revocation_eviction_pass(&state).await;

        let inner = state.revocation_evictions.inner.lock().await;
        let row = inner
            .store
            .get(&key)
            .expect("the kept hand-off survives the restart and opens the work");
        assert_eq!(
            row.earliest_handoff_receipt_unix_ms,
            Some((not_after + 1) * 1000),
            "T_obs is the raw not_after"
        );
        Ok(())
    }

    /// A `GSS` group of a remote admin with `target` seated as a Member,
    /// or not yet seated, held by `state` under `group_id`.
    async fn hold_remote_admin_group(
        state: &AppState,
        group_id: &str,
        target: &x0x::identity::AgentId,
        seated: bool,
    ) -> anyhow::Result<GroupInfo> {
        let admin = x0x::identity::AgentKeypair::generate()?.agent_id();
        let mut info = GroupInfo::new("s4-r7".into(), String::new(), admin, group_id.to_string());
        info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
        if seated {
            info.add_member(
                hex::encode(target.as_bytes()),
                GroupRole::Member,
                Some(hex::encode(admin.as_bytes())),
                None,
            );
        }
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info.clone());
        Ok(info)
    }

    /// A verified Agent-subject revocation of `target` in `state`'s set.
    async fn revoke_agent(
        state: &AppState,
        target: &x0x::identity::AgentKeypair,
    ) -> anyhow::Result<()> {
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(target.agent_id()),
            target.public_key(),
            target.secret_key(),
            1,
            None,
        )?;
        let inserted = state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)?;
        anyhow::ensure!(inserted, "the revocation is held");
        Ok(())
    }

    /// #1508 r7 (Codex P1 4, ADR 0110 §1): a revocation that this node
    /// consumed before a delayed `MemberAdded` seats its target still
    /// opens the work once the roster catch-up lands. The revocation
    /// generation does not change and nothing requests a reconcile.
    #[tokio::test]
    async fn a_revocation_before_its_target_is_seated_opens_work_on_catch_up() -> anyhow::Result<()>
    {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let target = x0x::identity::AgentKeypair::generate()?;
        let group_id = "a6".repeat(16);
        let info = hold_remote_admin_group(&state, &group_id, &target.agent_id(), false).await?;
        let key = EvictionKey::new(info.stable_group_id(), *target.agent_id().as_bytes());
        revoke_agent(&state, &target).await?;
        revocation_eviction_pass(&state).await;
        assert!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .store
                .get(&key)
                .is_none(),
            "no seat yet: no work"
        );
        revocation_eviction_pass(&state).await;

        // The roster catch-up seats the revoked member.
        hold_remote_admin_group(&state, &group_id, &target.agent_id(), true).await?;
        revocation_eviction_pass(&state).await;
        assert!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .store
                .get(&key)
                .is_some(),
            "the seated revoked member gets eviction work"
        );
        Ok(())
    }

    /// #1508 r7 (Codex P2 6, ADR 0110 §2 L175/L194): the fallback budget
    /// that a waiting row consumes is written to the `.evs`, so a restart
    /// resumes it and cannot extend the window.
    #[tokio::test]
    async fn a_consumed_budget_survives_a_restart() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let target = x0x::identity::AgentKeypair::generate()?;
        let group_id = "a7".repeat(16);
        let info = hold_remote_admin_group(&state, &group_id, &target.agent_id(), true).await?;
        let key = EvictionKey::new(info.stable_group_id(), *target.agent_id().as_bytes());
        revoke_agent(&state, &target).await?;
        revocation_eviction_pass(&state).await;
        assert!(persist_obligations(&state).await, "the intake is durable");
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        revocation_eviction_pass(&state).await;
        assert!(persist_obligations(&state).await);

        // Restart: the S4 state is reloaded from disk.
        *state.revocation_evictions.inner.lock().await = S4Inner::default();
        load_persisted_obligations(&state).await;
        revocation_eviction_pass(&state).await;
        let inner = state.revocation_evictions.inner.lock().await;
        let row = inner
            .store
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("the row survives"))?;
        assert!(row.phase.is_open(), "the row still waits");
        assert!(
            row.elapsed_budget_ms >= 1_200,
            "the consumed budget is resumed, not restarted: {} ms",
            row.elapsed_budget_ms
        );
        Ok(())
    }
}
