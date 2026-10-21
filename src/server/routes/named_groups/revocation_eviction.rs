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
use x0x::groups::eviction::{
    self as s4, CommitPermission, EvJournalV1, EvictionKey, EvictionTrigger, EvsBodyV1,
    IntakeOutcome, ObligationRow, ObligationStore, Phase, QueuedBanV1, RowAction, RowBudget,
    RowContext, S4Timing, SidecarDecodeError, SidecarState, TerminationCause,
    VerifiedAgentRevocation, WaitingCause, WaitingState,
};
use x0x::groups::{GroupInfo, GroupMemberState, GroupRole};

pub(super) mod crypto_exclusion;
pub(super) mod owner_recovery;
pub(super) mod rebind;
mod removal_delivery;
pub(super) mod removal_journal;

pub(super) use removal_delivery::record_committed_removal;

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
    fn head_synced(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.boot_instant) >= self.timing.restart_sync_wait
    }
}

// ─── §2 head catch-up round ───────────────────────────────────────────────

/// Most peers one worker pass asks for a catch-up page, per group. The
/// pass runs every [`S4_WORKER_TICK`], so a round reaches more peers on
/// later passes.
const HEAD_ROUND_PEERS_PER_PASS: usize = 3;

/// §2: one head catch-up round of one group.
///
/// A round confirms one local head. It completes when an authenticated
/// holder answers a catch-up page, after that page is applied, with
/// exactly the local head (any holder; no quorum). If no holder answers,
/// the bounded restart sync wait from the round start ends discovery
/// (D73). A holder that reports a different head is unresolved head
/// evidence: the round cannot complete, and it restarts (asks again) after
/// the wait. A new local head starts a new round.
#[derive(Debug, Clone)]
struct HeadRound {
    /// The local head this round confirms.
    head: String,
    started: Instant,
    /// Peers this round asked.
    asked: BTreeSet<[u8; 32]>,
    /// A verified holder reported `head` after its page was applied.
    confirmed: bool,
    /// Verified holders whose last report named a different head.
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
/// report asks every holder again once the wait has passed.
fn refresh_head_round(
    rounds: &mut HashMap<String, HeadRound>,
    stable_group_id: &str,
    current_head: &str,
    holders: &[[u8; 32]],
    now: Instant,
    wait: Duration,
) -> Vec<[u8; 32]> {
    let round = rounds
        .entry(stable_group_id.to_string())
        .or_insert_with(|| HeadRound::new(current_head, now));
    if round.head != current_head
        || (!round.conflicting.is_empty() && now.saturating_duration_since(round.started) >= wait)
    {
        *round = HeadRound::new(current_head, now);
    }
    if round.confirmed {
        return Vec::new();
    }
    let ask: Vec<[u8; 32]> = holders
        .iter()
        .filter(|peer| !round.asked.contains(*peer))
        .take(HEAD_ROUND_PEERS_PER_PASS)
        .copied()
        .collect();
    round.asked.extend(ask.iter().copied());
    ask
}

/// Record one verified, applied, non-truncated catch-up page answer.
fn note_head_report(
    rounds: &mut HashMap<String, HeadRound>,
    stable_group_id: &str,
    current_head: &str,
    sender: [u8; 32],
    reported: &str,
    now: Instant,
) {
    let round = rounds
        .entry(stable_group_id.to_string())
        .or_insert_with(|| HeadRound::new(current_head, now));
    if round.head != current_head {
        *round = HeadRound::new(current_head, now);
    }
    if reported == current_head {
        round.confirmed = true;
        round.conflicting.remove(&sender);
    } else {
        round.conflicting.insert(sender);
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
    if !runtime.head_synced(now) {
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

/// §2: the catch-up response handler calls this for each verified,
/// applied, non-truncated page that carries the responder's saved head
/// (`responder_state_hash`). The sender is an active, unrevoked member;
/// the handler checked that.
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
            crate::server::resolve_group_entry_locked(&groups, id)
                .map(|(_, info)| (info.stable_group_id().to_string(), info.state_hash.clone()))
        })
    };
    let Some((stable, head)) = current else {
        return;
    };
    let mut inner = state.revocation_evictions.inner.lock().await;
    // Only groups with S4 work keep a round (the worker pass creates it).
    if !inner.head_rounds.contains_key(&stable) {
        return;
    }
    note_head_report(
        &mut inner.head_rounds,
        &stable,
        &head,
        *sender.as_bytes(),
        reported,
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
        persist_obligations(&state).await;
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
    let revocations = collect_verified_agent_revocations(state).await;
    let groups = snapshot_groups(state).await;
    let leaves = snapshot_retained_leaves(state, &groups).await;
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
    let restart_wait_elapsed = runtime.head_synced(now);
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
    for key in created {
        inner
            .budgets
            .insert(key, RowBudget::resume(Duration::ZERO, now));
    }
    let mut delivering = inner.ce.delivering();
    delivering.extend(inner.removals.keys().cloned());
    if reconcile_completion(&mut inner.store, &groups, &leaves, &delivering, now_unix_ms) {
        inner.dirty = true;
    }
    if inner.store.apply_retention(now_unix_ms) {
        inner.dirty = true;
    }
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
    inner.not_durable.retain(|key, _| open.contains(key));
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
    let memory_only = !inner.sidecar.state.writable();
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
    let open_groups: BTreeSet<String> = round_keys
        .iter()
        .map(|key| key.stable_group_id.clone())
        .collect();
    inner
        .head_rounds
        .retain(|stable, _| open_groups.contains(stable));
    for stable in &open_groups {
        let Some((group_key, info)) = by_stable.get(stable.as_str()) else {
            continue;
        };
        let excluded: BTreeSet<[u8; 32]> = round_keys
            .iter()
            .filter(|key| &key.stable_group_id == stable)
            .map(|key| key.target)
            .collect();
        let holders = head_holders(info, &local, &excluded);
        let ask = refresh_head_round(
            &mut inner.head_rounds,
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
            && info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
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
        if let Some(row) = inner.store.get_mut(&key) {
            row.elapsed_budget_ms = s4::duration_ms(elapsed);
            row.boot_id = boot_id;
            if let Some(designation) = &designation {
                row.designated = Some(designation.designated);
                row.ranks = designation.ranks.clone();
            }
        }
        if changed_designation {
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
async fn collect_verified_agent_revocations(state: &AppState) -> Vec<VerifiedAgentRevocation> {
    let intake = state.agent.s4_revocation_intake();
    let (mut items, reconcile_all) = intake.drain();
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    let generation = set.generation();
    let full = {
        let inner = state.revocation_evictions.inner.lock().await;
        reconcile_all || inner.reconciled_generation != Some(generation)
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
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .reconciled_generation = Some(generation);
    }
    items
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
        if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem || info.withdrawn {
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
/// incarnation (its KeyPackage hash).
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
            let incarnation = member.treekem_key_package_hash.clone();
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

/// Re-derive completion from the verified roster and crypto state (§1,
/// D128). A row completes only when the target holds no seat and, in a
/// TreeKEM group, no retained leaf. A withdrawn group terminates its rows
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
        if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
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

/// Derive the state from the verified revocation records and the verified
/// head. It is not signed: a later head with an eligible admin clears it
/// (§4b(3) "late evidence").
async fn no_eligible_admin_state(state: &AppState, info: &GroupInfo) -> Option<NoEligibleAdmin> {
    if info.withdrawn {
        return None;
    }
    let admins = active_admins_of(info);
    if admins.is_empty() {
        // A genuinely admin-empty roster stays ADR 0088 §2 item 3.
        return None;
    }
    let (revoked, revoked_members): (Vec<[u8; 32]>, BTreeSet<[u8; 32]>) = {
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        let revoked: Vec<[u8; 32]> = admins
            .iter()
            .copied()
            .filter(|id| set.is_agent_revoked(&x0x::identity::AgentId(*id)))
            .collect();
        let members: BTreeSet<[u8; 32]> = info
            .active_members()
            .filter_map(|member| super::parse_agent_id_hex(&member.agent_id).ok())
            .map(|agent| *agent.as_bytes())
            .filter(|id| set.is_agent_revoked(&x0x::identity::AgentId(*id)))
            .collect();
        (revoked, members)
    };
    if revoked.len() != admins.len() {
        return None;
    }
    let mut revoked_admins: Vec<String> = revoked.iter().map(hex::encode).collect();
    revoked_admins.sort();
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
    state: &Arc<AppState>,
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
                super::schedule_self_leave_rekey_if_idle(state, &group_key).await;
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
        let scope = eviction_seal_scope(&inner.store, key);
        let Some(row) = inner.store.get_mut(key) else {
            return;
        };
        if row.phase != Phase::Pending {
            return;
        }
        row.phase = Phase::Prepared;
        row.parent_head = Some(parent_head.clone());
        let journal = prepared_journal(row, parent_head, next_revision);
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
                row.result_epoch = body.get("epoch").and_then(serde_json::Value::as_u64);
            }
            inner.attempt_wait.remove(key);
            inner.queued_manual.remove(key);
            if kind == ManualRequestKind::Ban {
                inner.queued_bans.remove(key);
                inner.ban_next_attempt.remove(key);
            }
        } else {
            if let Some(row) = inner.store.get_mut(key) {
                row.phase = Phase::Pending;
                row.parent_head = None;
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
            } else if status != StatusCode::NOT_FOUND {
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
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .await?;
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
    inner.ce = ce_state;
    inner.removals = removals;
    inner.queued_bans = queued_bans;
    inner.dirty = !journals.is_empty();
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
        let holders = [[9; 32]];
        let asked = refresh_head_round(&mut rounds, "g", "h1", &holders, start, wait);
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

    #[test]
    fn a_conflicting_head_report_blocks_the_seal_until_resolved() {
        let wait = Duration::from_secs(13);
        let start = Instant::now();
        let mut rounds = HashMap::new();
        let holders = [[8; 32], [9; 32]];
        refresh_head_round(&mut rounds, "g", "h1", &holders, start, wait);
        note_head_report(&mut rounds, "g", "h1", [8; 32], "higher", start);
        let later = start + wait * 10;
        assert!(!rounds
            .get("g")
            .expect("round")
            .synced("h1", 2, false, true, later, wait));
        // After the wait the round asks every holder again.
        let again = refresh_head_round(&mut rounds, "g", "h1", &holders, later, wait);
        assert_eq!(again, holders.to_vec());
        note_head_report(&mut rounds, "g", "h1", [9; 32], "h1", later);
        assert!(rounds
            .get("g")
            .expect("round")
            .synced("h1", 2, false, true, later, wait));
        // A new local head needs a new round.
        refresh_head_round(&mut rounds, "g", "h2", &holders, later, wait);
        assert!(!rounds
            .get("g")
            .expect("round")
            .synced("h2", 2, false, true, later, wait));
    }

    #[test]
    fn a_confirmed_round_or_no_holder_syncs_at_once() {
        let wait = Duration::from_secs(13);
        let now = Instant::now();
        let mut rounds = HashMap::new();
        refresh_head_round(&mut rounds, "g", "h1", &[[8; 32]], now, wait);
        assert!(!rounds
            .get("g")
            .expect("round")
            .synced("h1", 1, false, true, now, wait));
        note_head_report(&mut rounds, "g", "h1", [8; 32], "h1", now);
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
        let (admin, member) = ([1; 32], [2; 32]);
        let mut info = group_with(admin, member);
        info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
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
}
