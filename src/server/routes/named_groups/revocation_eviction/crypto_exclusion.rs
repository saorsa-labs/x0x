//! ADR 0110 §3, §4 and §6: the daemon side of `CryptoExclusionV1`, the
//! crypto-only exclusion of an already-Removed target with a retained
//! TreeKEM leaf (a self-leaver, or a target revoked after it self-left).
//!
//! - **Commit** ([`commit_locked`]). The responsive self-leave rekey
//!   (#1113, PR #1337) keeps its triggers, fences and designation. At the
//!   one point where it built a repeated admin `MemberRemoved` on the
//!   Removed seat, it now builds this signed crypto-only commit instead.
//!   The roster stays Removed; the chain revision and the TreeKEM epoch
//!   advance together.
//! - **Hold (D76).** While an Active survivor's current verified advert
//!   lacks `crypto_exclusion_v1`, the commit does not run. The obligation
//!   shows `waiting_for_receiver_upgrade`, naming each holding survivor.
//!   Unknown, expired and offline survivors do not hold it.
//! - **§5 order.** The exact outgoing frame goes into a prepared
//!   `.evjournal` and the `.evs` row first; then the unchanged legacy
//!   roster/crypto transaction runs; then the row moves to
//!   `committed_delivery_pending` and the journal is retired.
//! - **Delivery** ([`drive_deliveries`]). Per-recipient, capability-gated
//!   direct delivery only, never the metadata topic and never a
//!   legacy-decoded container. Every physical write goes through the same
//!   guarded admission as catch-up ([`guarded_admission`]): ADR 0107's
//!   serving guard (Active, unbanned, unrevoked, certificate-eligible, not
//!   withdrawn, not quarantined) plus D60 (machine and binding
//!   revocations), the capability bit and the head rule. The pre-phase
//!   runs under the group's membership lock; the seam re-checks the same
//!   inputs immediately before `write_all`. A recipient with unknown
//!   support first gets an advert refresh; one whose advert lacks the bit
//!   is stranded (`waiting_for_receiver_upgrade` with the gap revision).
//!   Resends stop once the head moves past the result (no old crypto
//!   material after an epoch change). The `InFlight` status of a recipient
//!   is installed, with a per-attempt token, before its send task starts,
//!   and a completion writes only over its own token.
//! - **Restart** (`resume_crypto_exclusions` in the parent). A saved frame
//!   is resent only after the group's head is synced
//!   ([`super::group_head_synced`], not elapsed time alone) and only while
//!   its result is the current head. A competing branch on the parent keeps the frame
//!   as fork evidence and shows `waiting_for_fork_resolution`; nothing is
//!   published.
//! - **Receive** ([`spawn_receipt`]) verifies the frame and the L4 rule and
//!   installs it atomically. **Catch-up** ([`serve_catchup`]) sends held
//!   frames to a capable requester on this same carrier, only while the
//!   frame's result is on this node's verified chain.
//! - **Replay evidence** (§4 catch-up across restart). The frame stays in
//!   its `.evs` row after completion (the existing `outgoing_event` field;
//!   no new file or layout), for the newest
//!   [`x0x::groups::eviction::MAX_REPLAY_FRAMES_PER_GROUP`] completed rows
//!   of a group. A survivor that installed a received frame attaches it to
//!   its own completed row. A restart rebuilds the catch-up log from those
//!   rows ([`rebuild_catchup_log`]), so a survivor that missed the
//!   transition still catches up after the head moves and this node
//!   restarts.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::crypto_exclusion as ce;
use x0x::groups::eviction::{EvJournalV1, EvictionKey, ObligationStore, Phase};
use x0x::groups::GroupInfo;
use x0x::identity::AgentId;

use super::super::{LogHexId, SelfLeaveRekeyStep};

/// A delivery round runs no more often than this per row.
const CE_RESEND_INTERVAL: Duration = Duration::from_secs(5);
/// Frames held per group for catch-up serving: the same bound as the
/// replay frames kept in completed `.evs` rows.
const CE_LOG_PER_GROUP: usize = x0x::groups::eviction::MAX_REPLAY_FRAMES_PER_GROUP;
/// The per-exchange bound of one live delivery or catch-up frame write.
const CE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
/// Frames that arrived ahead of this node's head, waiting for it.
const CE_STASH_CAP: usize = 64;
/// A stashed frame is dropped after this long.
const CE_STASH_TTL: Duration = Duration::from_secs(600);

/// The delivery state of one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecipientDelivery {
    /// A send is due.
    Due,
    /// A send is running. The token names the attempt: only that
    /// attempt's completion may replace this status.
    InFlight(u64),
    /// The carrier accepted the frame.
    Sent,
    /// The recipient's current verified advert lacks the bit: stranded
    /// until it upgrades (§6).
    Lacking,
    /// No current verified advert; a refresh was requested.
    Unknown,
}

/// The retained delivery of one committed crypto-only exclusion.
#[derive(Debug, Clone)]
pub(super) struct CeDelivery {
    bytes: Arc<Vec<u8>>,
    result_head: String,
    next_revision: u64,
    /// The frame was saved by an earlier boot: no resend before the
    /// group's head is synced (§3 "re-sync the head before any resend").
    resumed: bool,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
}

/// A frame held for catch-up serving.
#[derive(Debug, Clone)]
struct CeLogEntry {
    next_revision: u64,
    /// The frame's result head: it is served only while this head is on
    /// the verified chain.
    result_head: String,
    bytes: Arc<Vec<u8>>,
}

/// A verified-shape frame that arrived before this node reached its parent.
#[derive(Debug, Clone)]
struct StashedFrame {
    sender: AgentId,
    bytes: Vec<u8>,
    at: Instant,
}

/// The crypto-only exclusion state held in the S4 runtime.
#[derive(Debug, Default)]
pub(super) struct CeState {
    deliveries: HashMap<EvictionKey, CeDelivery>,
    log: HashMap<String, VecDeque<CeLogEntry>>,
    stash: Vec<StashedFrame>,
    /// Installed received frames waiting for their row to complete, so the
    /// frame is kept there as durable replay evidence.
    replay_pending: HashMap<EvictionKey, Arc<Vec<u8>>>,
    /// Rows whose saved frame meets a competing branch (§3).
    pub(super) fork: BTreeSet<EvictionKey>,
    /// Rows held by the D76 rule, with the holding survivors.
    pub(super) holders: HashMap<EvictionKey, Vec<[u8; 32]>>,
}

impl CeState {
    /// Rows with a delivery still running; they do not complete yet.
    pub(super) fn delivering(&self) -> BTreeSet<EvictionKey> {
        self.deliveries.keys().cloned().collect()
    }

    /// Per-member `waiting_for_receiver_upgrade` of one row: the
    /// recipients stranded by a lacking or unknown advert, with the gap
    /// revision (§6 "Stranded").
    pub(super) fn stranded_json(&self, key: &EvictionKey) -> serde_json::Value {
        let Some(delivery) = self.deliveries.get(key) else {
            return serde_json::Value::Array(Vec::new());
        };
        let entries: Vec<serde_json::Value> = delivery
            .recipients
            .iter()
            .filter(|(_, status)| {
                matches!(
                    status,
                    RecipientDelivery::Lacking | RecipientDelivery::Unknown
                )
            })
            .map(|(id, status)| {
                serde_json::json!({
                    "cause": x0x::groups::eviction::WaitingCause::WaitingForReceiverUpgrade.as_str(),
                    "agent_id": hex::encode(id),
                    "gap_revision": delivery.next_revision,
                    "advert": if *status == RecipientDelivery::Lacking { "lacking" } else { "unknown" },
                })
            })
            .collect();
        serde_json::Value::Array(entries)
    }

    fn remember(
        &mut self,
        stable_group_id: &str,
        next_revision: u64,
        result_head: &str,
        bytes: Arc<Vec<u8>>,
    ) {
        let log = self.log.entry(stable_group_id.to_string()).or_default();
        if log.iter().any(|entry| entry.next_revision == next_revision) {
            return;
        }
        let at = log
            .iter()
            .position(|entry| entry.next_revision > next_revision)
            .unwrap_or(log.len());
        log.insert(
            at,
            CeLogEntry {
                next_revision,
                result_head: result_head.to_string(),
                bytes,
            },
        );
        while log.len() > CE_LOG_PER_GROUP {
            log.pop_front();
        }
    }

    /// The frames held for any of `group_ids` above `from_revision`, oldest
    /// first, with their result heads.
    fn catchup_frames(
        &self,
        group_ids: &[String],
        from_revision: u64,
    ) -> Vec<(String, String, Arc<Vec<u8>>)> {
        group_ids
            .iter()
            .find_map(|id| self.log.get(id).map(|log| (id, log)))
            .map(|(id, log)| {
                log.iter()
                    .filter(|entry| entry.next_revision > from_revision)
                    .map(|entry| {
                        (
                            id.clone(),
                            entry.result_head.clone(),
                            Arc::clone(&entry.bytes),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Keep an installed received frame until its row completes (bounded).
    fn note_replay_pending(&mut self, key: EvictionKey, bytes: Arc<Vec<u8>>) {
        if self.replay_pending.len() >= CE_STASH_CAP && !self.replay_pending.contains_key(&key) {
            return;
        }
        self.replay_pending.insert(key, bytes);
    }
}

/// Attach each installed received frame to its row once the row is
/// complete, as durable replay evidence for catch-up after a restart.
/// A row that is gone drops the frame; an open row keeps it waiting (an
/// open row's `outgoing_event` is a frame this node must deliver, which a
/// receiver never does). Returns whether the store changed.
pub(super) fn attach_replay_evidence(ce_state: &mut CeState, store: &mut ObligationStore) -> bool {
    let mut changed = false;
    ce_state.replay_pending.retain(|key, bytes| {
        let Some(row) = store.get_mut(key) else {
            return false;
        };
        match row.phase {
            Phase::Complete => {
                if row.outgoing_event.is_none() {
                    row.outgoing_event = Some(bytes.to_vec());
                    changed = true;
                }
                false
            }
            Phase::Terminated => false,
            Phase::Pending | Phase::Prepared | Phase::CommittedDeliveryPending => true,
        }
    });
    changed
}

/// §4 catch-up across restart: rebuild the catch-up log from the frames
/// kept in `.evs` rows. A completed row's frame was verified on the chain
/// when it completed; an open row's frame counts only when its result is
/// the head or on the retained chain (never a fork or an unknown branch).
/// [`serve_catchup`] re-checks the chain before every write.
pub(super) fn rebuild_catchup_log(
    groups: &[(String, GroupInfo)],
    store: &ObligationStore,
    ce_state: &mut CeState,
) {
    let mut frames: Vec<(String, u64, String, Vec<u8>)> = Vec::new();
    for row in store.rows() {
        let Some(bytes) = row.outgoing_event.as_deref() else {
            continue;
        };
        let Ok(frame) = ce::decode_frame(bytes) else {
            continue;
        };
        if frame.body.stable_group_id != row.stable_group_id || frame.body.target != row.target {
            continue;
        }
        let result_head = frame.body.commit.state_hash.clone();
        let keep = match row.phase {
            Phase::Complete => true,
            Phase::Terminated => false,
            Phase::Pending | Phase::Prepared | Phase::CommittedDeliveryPending => groups
                .iter()
                .find(|(_, info)| info.stable_group_id() == row.stable_group_id)
                .is_some_and(|(_, info)| {
                    matches!(
                        classify_saved_frame(info, &frame.body.prior_head, &result_head),
                        SavedFrameState::CurrentHead | SavedFrameState::Superseded
                    )
                }),
        };
        if keep {
            frames.push((
                row.stable_group_id.clone(),
                frame.body.next_revision,
                result_head,
                bytes.to_vec(),
            ));
        }
    }
    frames.sort_by_key(|(_, revision, _, _)| *revision);
    for (stable_group_id, next_revision, result_head, bytes) in frames {
        ce_state.remember(
            &stable_group_id,
            next_revision,
            &result_head,
            Arc::new(bytes),
        );
    }
}

// ─── Send attempts (per-attempt tokens) ────────────────────────────────────

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

/// A fresh send-attempt token.
pub(super) fn next_attempt() -> u64 {
    NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed)
}

/// One planned change to a recipient's status, made from a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RoundUpdate {
    pub(super) recipient: [u8; 32],
    /// The status the plan read. A change applies only while the stored
    /// status is still this one, so a newer write is never overwritten.
    pub(super) observed: RecipientDelivery,
    /// The new status; `None` drops the recipient.
    pub(super) next: Option<RecipientDelivery>,
}

/// Apply one round's planned updates under the runtime lock. Returns the
/// `(recipient, attempt)` sends whose `InFlight` status was installed: the
/// caller starts exactly those, after this returns, so a send can never
/// complete before its `InFlight` status exists.
pub(super) fn apply_round(
    recipients: &mut BTreeMap<[u8; 32], RecipientDelivery>,
    updates: Vec<RoundUpdate>,
) -> Vec<([u8; 32], u64)> {
    let mut started = Vec::new();
    for update in updates {
        if recipients.get(&update.recipient) != Some(&update.observed) {
            continue;
        }
        match update.next {
            Some(status) => {
                recipients.insert(update.recipient, status);
                if let RecipientDelivery::InFlight(attempt) = status {
                    started.push((update.recipient, attempt));
                }
            }
            None => {
                recipients.remove(&update.recipient);
            }
        }
    }
    started
}

/// Record the result of send attempt `attempt`. It writes only over that
/// attempt's own `InFlight` status; a stale or replaced attempt changes
/// nothing. Returns whether it wrote.
pub(super) fn finish_attempt(
    recipients: &mut BTreeMap<[u8; 32], RecipientDelivery>,
    recipient: &[u8; 32],
    attempt: u64,
    status: RecipientDelivery,
) -> bool {
    match recipients.get_mut(recipient) {
        Some(entry) if *entry == RecipientDelivery::InFlight(attempt) => {
            *entry = status;
            true
        }
        _ => false,
    }
}

fn agent_bytes(hex_id: &str) -> Option<[u8; 32]> {
    super::super::parse_agent_id_hex(hex_id)
        .ok()
        .map(|agent| *agent.as_bytes())
}

/// The Active survivors of `info` other than `local` and `target`.
fn survivors(info: &GroupInfo, local: &[u8; 32], target: &[u8; 32]) -> Vec<[u8; 32]> {
    info.active_members()
        .filter_map(|member| agent_bytes(&member.agent_id))
        .filter(|id| id != local && id != target)
        .collect()
}

/// The D76 holders of a crypto-only exclusion on `info` (§4 L253).
pub(super) fn holders(
    state: &AppState,
    info: &GroupInfo,
    local: &[u8; 32],
    target: &[u8; 32],
) -> Vec<[u8; 32]> {
    let capabilities = state.agent.capability_store();
    ce::receiver_upgrade_holders(survivors(info, local, target).into_iter().map(|id| {
        (
            id,
            capabilities.verified_registry_supports(
                &AgentId(id),
                x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
            ),
        )
    }))
}

// ─── Commit ────────────────────────────────────────────────────────────────

#[cfg(test)]
thread_local! {
    static LEGACY_AUTHORING_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only: make the responsive rekey on this thread author the
/// repeated `MemberRemoved` of a released (v0.48.1) binary. Tests of the
/// retained legacy paths (its saved-outbox replay, and receivers that must
/// still verify a legacy admin's event) use it to produce that event.
#[cfg(test)]
pub(in crate::server) fn author_legacy_rekeys_on_this_thread_for_test() {
    LEGACY_AUTHORING_FOR_TEST.with(|flag| flag.set(true));
}

/// Whether this binary authors `CryptoExclusionV1` for an already-Removed
/// target (ADR 0110 §3 L216, §4 L247). It always does. The responsive
/// rekey's repeated-`MemberRemoved` build is what released binaries send;
/// this binary keeps only its receive side and the replay of events an
/// earlier binary saved in the outbox.
pub(in crate::server) fn authoring_enabled() -> bool {
    #[cfg(test)]
    if LEGACY_AUTHORING_FOR_TEST.with(std::cell::Cell::get) {
        return false;
    }
    true
}

/// Commit the crypto-only exclusion of `leaver_hex`'s retained leaf. The
/// caller is the #1337 rekey pass: it holds this group's membership lock
/// and the TreeKEM group lock (`tree`), it found the leaf and its
/// KeyPackage bytes, and it checked the fences, the queue and the head.
#[allow(clippy::too_many_arguments)]
pub(in crate::server) async fn commit_locked(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    tree: &mut x0x::mls::TreeKemMlsGroup,
    leaver_hex: &str,
    target: AgentId,
    kp_bytes: &[u8],
) -> SelfLeaveRekeyStep {
    use super::super as ng;
    let local = *state.agent.agent_id().as_bytes();
    let key = EvictionKey::new(info.stable_group_id(), *target.as_bytes());
    let hold = holders(state, info, &local, target.as_bytes());
    let held = !hold.is_empty();
    super::note_receiver_upgrade_hold(state, &key, hold).await;
    if held {
        if ng::self_leave_rekey_log_once(&format!("ce-hold:{group_key}:{}", info.state_hash)) {
            tracing::info!(
                group_id = %LogHexId::group(group_key),
                leaver = %LogHexId::agent(leaver_hex),
                "ADR 0110 S4: crypto-only exclusion held; an Active survivor's advert lacks crypto_exclusion_v1"
            );
        }
        return SelfLeaveRekeyStep::Deferred;
    }
    let (Some(removal_proof), Some(leaf_hash)) = (
        ce::removal_proof_for(info, leaver_hex),
        info.members_v2
            .get(leaver_hex)
            .and_then(|member| member.treekem_key_package_hash.clone()),
    ) else {
        return SelfLeaveRekeyStep::Deferred;
    };
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = ng::now_millis_u64();
    let mut next = info.clone();
    let next_epoch = tree.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let rollback_snapshot = match tree.to_snapshot_bytes() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::error!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: crypto-only exclusion deferred: snapshot failed: {error}");
            return SelfLeaveRekeyStep::Deferred;
        }
    };
    let rollback = |tree: &mut x0x::mls::TreeKemMlsGroup, next: &GroupInfo, reason: &str| {
        ng::rollback_treekem_group_after_failed_install(
            state,
            group_key,
            next,
            &rollback_snapshot,
            tree,
            reason,
        );
    };
    let treekem_commit = match tree.remove_member_verified(target, kp_bytes) {
        Ok(commit) => commit,
        Err(error) => {
            tracing::warn!(group_id = %LogHexId::group(group_key), leaver = %LogHexId::agent(leaver_hex), "ADR 0110 S4: crypto-only exclusion deferred: remove_member failed: {error}");
            return SelfLeaveRekeyStep::Deferred;
        }
    };
    if tree.epoch() != next_epoch {
        rollback(tree, &next, "crypto_exclusion_epoch_mismatch");
        return SelfLeaveRekeyStep::Deferred;
    }
    next.secret_epoch = next_epoch;
    next.security_binding = Some(ce::treekem_binding(next_epoch, &treekem_commit));
    let commit = match ng::seal_commit_owner_certified(state, &mut next, signing_kp, now_ms).await {
        Ok(commit) => commit,
        Err(error) => {
            rollback(tree, &next, "crypto_exclusion_seal_failed");
            tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: crypto-only exclusion deferred: seal failed: {error}");
            return SelfLeaveRekeyStep::Deferred;
        }
    };
    ng::quiesce_member_join_egress(state, group_key, leaver_hex).await;
    // Re-check under the membership lock, after the awaits above.
    if ng::self_leave_rekey_batch_held()
        || ng::self_leave_rekey_fence_open(group_key)
        || ng::self_leave_rekey_fence_open(info.stable_group_id())
        || ng::self_leave_startup_blocks(state, info, group_key)
        || !ng::self_leave_rekey_queue_clear(state, group_key, info.stable_group_id()).await
        || !ng::self_leave_candidate_extends_stored_head(state, group_key, info).await
    {
        rollback(tree, &next, "crypto_exclusion_head_moved");
        return SelfLeaveRekeyStep::Deferred;
    }
    let body = ce::CryptoExclusionBodyV1 {
        stable_group_id: info.stable_group_id().to_string(),
        actor: local,
        target: *target.as_bytes(),
        prior_head: info.state_hash.clone(),
        prior_revision: info.state_revision,
        next_revision: commit.revision,
        roster_revision: next.roster_revision,
        removal_proof_hash: removal_proof,
        crypto: ce::CryptoExclusionCryptoV1::TreeKem {
            leaf_key_package_hash: leaf_hash.clone(),
            commit: treekem_commit,
            next_epoch,
        },
        commit: ce::CommitHeaderV1::from(&commit),
    };
    let Some(bytes) = ce::sign(body, signing_kp)
        .ok()
        .and_then(|frame| ce::encode_frame(&frame).ok())
    else {
        rollback(tree, &next, "crypto_exclusion_sign_failed");
        return SelfLeaveRekeyStep::Deferred;
    };
    if bytes.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        // §4: an oversized proof waits for the existing authorized evidence
        // route; no new carrier is invented.
        rollback(tree, &next, "crypto_exclusion_oversized");
        tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: crypto-only exclusion deferred: the frame exceeds the direct carrier limit");
        return SelfLeaveRekeyStep::Deferred;
    }
    // §5: fsync the prepared journal with the exact outgoing frame first.
    let mut txid = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut txid);
    let journal = EvJournalV1 {
        txid,
        stable_group_id: info.stable_group_id().to_string(),
        target: *target.as_bytes(),
        parent_head: info.state_hash.clone(),
        next_revision: commit.revision,
        result_epoch: Some(next_epoch),
        evidence: vec![removal_proof],
        outgoing_event: bytes.clone(),
        result_head: Some(commit.state_hash.clone()),
    };
    if !super::prepare_crypto_exclusion(state, &key, &journal, Some(leaf_hash)).await {
        rollback(tree, &next, "crypto_exclusion_journal_failed");
        return SelfLeaveRekeyStep::Deferred;
    }
    // The unchanged legacy roster/crypto transaction.
    if let Err(error) =
        ng::persist_treekem_and_named_groups_atomic_with_info(state, group_key, next.clone(), tree)
            .await
    {
        if ng::self_leave_persist_left_epoch_installed(&error) {
            tracing::error!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: crypto-only exclusion persist reported an error after the epoch was installed: {error}");
            let mut groups = state.named_groups.write().await;
            if groups
                .get(group_key)
                .map(|stored| stored.state_hash.as_str())
                != Some(next.state_hash.as_str())
            {
                groups.insert(group_key.to_string(), next.clone());
            }
        } else {
            rollback(tree, &next, "crypto_exclusion_persist_failed");
            super::abandon_crypto_exclusion(state, &key).await;
            tracing::error!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: crypto-only exclusion deferred: persist failed before the epoch was installed: {error}");
            return SelfLeaveRekeyStep::Deferred;
        }
    }
    ng::purge_join_artifacts_if_ineligible(state, group_key, leaver_hex).await;
    let _ = ng::prune_treekem_cache_member(state, group_key, leaver_hex, "crypto_exclusion").await;
    let recipients = survivors(&next, &local, target.as_bytes());
    super::committed_crypto_exclusion(
        state,
        &key,
        &commit.state_hash,
        next_epoch,
        commit.revision,
        bytes,
        recipients,
    )
    .await;
    tracing::info!(
        group_id = %LogHexId::group(group_key),
        leaver = %LogHexId::agent(leaver_hex),
        epoch = next_epoch,
        "ADR 0110 S4: crypto-only exclusion committed"
    );
    let task_state = Arc::clone(state);
    let card_key = group_key.to_string();
    let _spawned = state.spawn_detached(async move {
        ng::maybe_publish_group_card_after_state_change(&task_state, &card_key).await;
        drive_deliveries(&task_state).await;
    });
    SelfLeaveRekeyStep::Committed
}

/// A new delivery for a just-committed frame.
pub(super) fn new_delivery(
    ce_state: &mut CeState,
    key: &EvictionKey,
    result_head: &str,
    next_revision: u64,
    bytes: Arc<Vec<u8>>,
    recipients: Vec<[u8; 32]>,
    resumed: bool,
) {
    ce_state.remember(
        &key.stable_group_id,
        next_revision,
        result_head,
        Arc::clone(&bytes),
    );
    ce_state.deliveries.insert(
        key.clone(),
        CeDelivery {
            bytes,
            result_head: result_head.to_string(),
            next_revision,
            resumed,
            recipients: recipients
                .into_iter()
                .map(|id| (id, RecipientDelivery::Due))
                .collect(),
            next_at: Instant::now(),
        },
    );
}

// ─── Restart (§3) ──────────────────────────────────────────────────────────

/// How a saved frame relates to this node's verified chain after restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SavedFrameState {
    /// The result is the current head: finish its eligible delivery
    /// without another rekey.
    CurrentHead,
    /// The result is on the chain and the head moved on: complete, and
    /// discard the delivery (no old crypto material after an epoch change).
    Superseded,
    /// The parent is still the head: the legacy commit did not land; the
    /// row returns to pending and the preparation is abandoned.
    Abandoned,
    /// A different child of the parent is on the chain, or the group holds
    /// a fork-quarantine marker: keep the frame as fork evidence and never
    /// publish it.
    Fork,
    /// The relation is unknown yet: `waiting_for_head_sync`.
    Unknown,
}

/// Classify a saved frame (`parent_head` → `result_head`) against `info`.
pub(super) fn classify_saved_frame(
    info: &GroupInfo,
    parent_head: &str,
    result_head: &str,
) -> SavedFrameState {
    if info.fork_quarantine.is_some() {
        return SavedFrameState::Fork;
    }
    if info.state_hash == result_head {
        return SavedFrameState::CurrentHead;
    }
    let on_chain = info
        .commit_log
        .iter()
        .any(|retained| retained.commit.state_hash == result_head);
    if on_chain {
        return SavedFrameState::Superseded;
    }
    if info.state_hash == parent_head {
        return SavedFrameState::Abandoned;
    }
    let sibling = info.commit_log.iter().any(|retained| {
        retained.commit.prev_state_hash.as_deref() == Some(parent_head)
            && retained.commit.state_hash != result_head
    });
    if sibling {
        SavedFrameState::Fork
    } else {
        SavedFrameState::Unknown
    }
}

/// Decode the parent head, the result head and the next revision of a
/// saved frame.
pub(super) fn saved_frame_heads(bytes: &[u8]) -> Option<(String, String, u64)> {
    let frame = ce::decode_frame(bytes).ok()?;
    Some((
        frame.body.prior_head,
        frame.body.commit.state_hash,
        frame.body.next_revision,
    ))
}

// ─── Delivery ──────────────────────────────────────────────────────────────

/// §2 and §3 "re-sync the head before any resend": the groups of the
/// `resumed` candidates whose head is synced now
/// ([`super::group_head_synced`]: the restart minimum, a completed current
/// catch-up round and no unresolved higher-head evidence). Elapsed time
/// alone never releases a resend that an earlier boot saved. Call it with
/// no S4 lock held.
pub(super) async fn resumed_groups_head_synced(
    state: &AppState,
    candidates: &[(EvictionKey, bool)],
) -> BTreeSet<String> {
    let groups: BTreeSet<&str> = candidates
        .iter()
        .filter(|(_, resumed)| *resumed)
        .map(|(key, _)| key.stable_group_id.as_str())
        .collect();
    let mut synced = BTreeSet::new();
    for group in groups {
        if super::group_head_synced(state, group).await {
            synced.insert(group.to_string());
        }
    }
    synced
}

/// Whether a delivery of `key` is due now: its resend time has come and,
/// for a delivery an earlier boot saved, its group's head is synced.
pub(super) fn resend_due(
    next_at: Instant,
    resumed: bool,
    synced: &BTreeSet<String>,
    key: &EvictionKey,
    now: Instant,
) -> bool {
    next_at <= now && (!resumed || synced.contains(&key.stable_group_id))
}

/// One delivery round for every due row: per recipient, re-check the
/// roster and the agent, machine and binding revocations, then send only
/// to a recipient whose current verified advert sets the bit. Each send
/// runs [`guarded_admission`] again at the physical write.
pub(super) async fn drive_deliveries(state: &Arc<AppState>) {
    let runtime = &state.revocation_evictions;
    let now = Instant::now();
    let candidates: Vec<(EvictionKey, bool)> = {
        let mut guard = runtime.inner.lock().await;
        let inner = &mut *guard;
        if attach_replay_evidence(&mut inner.ce, &mut inner.store) {
            inner.dirty = true;
        }
        inner
            .ce
            .deliveries
            .iter()
            .filter(|(_, delivery)| delivery.next_at <= now)
            .map(|(key, delivery)| (key.clone(), delivery.resumed))
            .collect()
    };
    let synced = resumed_groups_head_synced(state, &candidates).await;
    let due: Vec<(EvictionKey, CeDelivery)> = {
        let mut inner = runtime.inner.lock().await;
        candidates
            .into_iter()
            .filter_map(|(key, _)| {
                let delivery = inner.ce.deliveries.get_mut(&key)?;
                if !resend_due(delivery.next_at, delivery.resumed, &synced, &key, now) {
                    return None;
                }
                delivery.next_at = now + CE_RESEND_INTERVAL;
                Some((key, delivery.clone()))
            })
            .collect()
    };
    if due.is_empty() {
        return;
    }
    let local = *state.agent.agent_id().as_bytes();
    let capabilities = state.agent.capability_store();
    for (key, delivery) in due {
        let info = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == key.stable_group_id)
                .cloned()
        };
        let Some(info) = info.filter(|info| !info.withdrawn) else {
            runtime.inner.lock().await.ce.deliveries.remove(&key);
            continue;
        };
        if info.fork_quarantine.is_some() {
            let mut inner = runtime.inner.lock().await;
            inner.ce.deliveries.remove(&key);
            inner.ce.fork.insert(key.clone());
            continue;
        }
        if info.state_hash != delivery.result_head {
            // The head moved past the exclusion: never resend old crypto
            // material after an epoch change. Stranded members recover by
            // catch-up (the frame stays in the catch-up log and the row).
            runtime.inner.lock().await.ce.deliveries.remove(&key);
            continue;
        }
        let active: BTreeSet<[u8; 32]> =
            survivors(&info, &local, &key.target).into_iter().collect();
        let mut updates: Vec<RoundUpdate> = Vec::new();
        let mut refreshes: Vec<AgentId> = Vec::new();
        for (recipient, status) in &delivery.recipients {
            let observed = *status;
            if !active.contains(recipient) {
                updates.push(RoundUpdate {
                    recipient: *recipient,
                    observed,
                    next: None,
                });
                continue;
            }
            if matches!(
                status,
                RecipientDelivery::Sent | RecipientDelivery::InFlight(_)
            ) {
                continue;
            }
            let agent = AgentId(*recipient);
            if !write_allowed(state, &agent).await {
                continue;
            }
            let next = match capabilities.verified_registry_supports(
                &agent,
                x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
            ) {
                Some(true) => RecipientDelivery::InFlight(next_attempt()),
                Some(false) => RecipientDelivery::Lacking,
                None => {
                    refreshes.push(agent);
                    RecipientDelivery::Unknown
                }
            };
            updates.push(RoundUpdate {
                recipient: *recipient,
                observed,
                next: Some(next),
            });
        }
        // Install every status, `InFlight` included, BEFORE any send task
        // starts: a fast completion can then never be overwritten.
        let started = {
            let mut inner = runtime.inner.lock().await;
            let Some(stored) = inner.ce.deliveries.get_mut(&key) else {
                continue;
            };
            let started = apply_round(&mut stored.recipients, updates);
            if stored
                .recipients
                .values()
                .all(|status| *status == RecipientDelivery::Sent)
            {
                inner.ce.deliveries.remove(&key);
                inner.dirty = true;
            }
            started
        };
        for (recipient, attempt) in started {
            spawn_send(
                state,
                key.clone(),
                AgentId(recipient),
                attempt,
                delivery.result_head.clone(),
                Arc::clone(&delivery.bytes),
            );
        }
        for agent in refreshes {
            let task_state = Arc::clone(state);
            let _spawned = state.spawn_detached(async move {
                task_state
                    .agent
                    .refresh_application_capability(
                        agent,
                        x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
                    )
                    .await;
            });
        }
    }
}

/// D60 and §3 inputs at the write: the recipient's agent is not revoked,
/// and neither its advertised machine nor that agent-machine binding is.
pub(super) async fn write_allowed(state: &AppState, agent: &AgentId) -> bool {
    let machine = state
        .agent
        .capability_store()
        .lookup_binding(agent)
        .map(|binding| binding.machine_id);
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    if set.is_agent_revoked(agent) {
        return false;
    }
    machine.is_none_or(|machine| {
        !set.is_machine_revoked(&machine) && !set.is_binding_revoked(agent, &machine)
    })
}

/// The synchronous seam form of [`write_allowed`]: every lock is taken
/// with `try_*`, and contention refuses (a retryable withhold).
fn write_allowed_at_seam(state: &AppState, agent: &AgentId) -> bool {
    let machine = state
        .agent
        .capability_store()
        .lookup_binding(agent)
        .map(|binding| binding.machine_id);
    let revocation_set = state.agent.revocation_set();
    let Ok(set) = revocation_set.try_read() else {
        return false;
    };
    if set.is_agent_revoked(agent) {
        return false;
    }
    machine.is_none_or(|machine| {
        !set.is_machine_revoked(&machine) && !set.is_binding_revoked(agent, &machine)
    })
}

fn spawn_send(
    state: &Arc<AppState>,
    key: EvictionKey,
    agent: AgentId,
    attempt: u64,
    result_head: String,
    bytes: Arc<Vec<u8>>,
) {
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let admission = guarded_admission(
            &task_state,
            &key.stable_group_id,
            &agent,
            HeadRule::Current(result_head),
        );
        let resolve_within =
            std::cmp::min(x0x::dm::PINNED_RESOLUTION_WAIT, CE_EXCHANGE_TIMEOUT / 2);
        let exchange = task_state.agent.send_direct_pinned_admitted(
            &agent,
            bytes.as_slice(),
            &admission,
            resolve_within,
        );
        let status = match tokio::time::timeout(CE_EXCHANGE_TIMEOUT, exchange).await {
            Ok(Ok(_)) => RecipientDelivery::Sent,
            Ok(Err(x0x::dm::DmError::RecipientUpgradeRequired { .. })) => {
                RecipientDelivery::Lacking
            }
            Ok(Err(error)) => {
                // An admission refusal is a withhold: the next round
                // re-evaluates the recipient from the current state.
                tracing::debug!(%error, "ADR 0110 S4: crypto-only exclusion send refused or failed; retrying");
                RecipientDelivery::Due
            }
            Err(_) => {
                tracing::debug!("ADR 0110 S4: crypto-only exclusion exchange deadline elapsed; retrying");
                RecipientDelivery::Due
            }
        };
        let mut inner = task_state.revocation_evictions.inner.lock().await;
        if let Some(delivery) = inner.ce.deliveries.get_mut(&key) {
            finish_attempt(&mut delivery.recipients, agent.as_bytes(), attempt, status);
        }
    });
}

// ─── Guarded egress (§3 L231, §4) ──────────────────────────────────────────

/// The group-state rule of one frame write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HeadRule {
    /// Live delivery: the frame's result must still be the current head
    /// (the epoch has not moved past it).
    Current(String),
    /// Catch-up: the frame's result must be on this node's verified chain
    /// (the current head or a retained commit).
    OnChain(String),
}

/// Whether `info` still admits a frame under `rule`. A quarantined or
/// withdrawn group admits nothing (containment).
pub(super) fn head_rule_admits(info: &GroupInfo, rule: &HeadRule) -> bool {
    if info.withdrawn || info.is_fork_quarantined() {
        return false;
    }
    match rule {
        HeadRule::Current(head) => info.state_hash == *head,
        HeadRule::OnChain(head) => {
            info.state_hash == *head
                || info
                    .commit_log
                    .iter()
                    .any(|retained| retained.commit.state_hash == *head)
        }
    }
}

/// Serve the frames this node holds for the group (any of `group_ids`) above
/// `from_revision` to a catch-up requester, on the distinct gated carrier
/// only. A requester without a current verified advert setting the bit
/// gets nothing new: the frame never goes into a legacy-decoded catch-up
/// page.
///
/// Each write uses [`guarded_admission`] with [`HeadRule::OnChain`].
pub(in crate::server) async fn serve_catchup(
    state: &Arc<AppState>,
    requester: &AgentId,
    group_ids: &[String],
    from_revision: u64,
) {
    let frames = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .ce
        .catchup_frames(group_ids, from_revision);
    if frames.is_empty() {
        return;
    }
    for (group_id, result_head, bytes) in frames {
        let admission =
            guarded_admission(state, &group_id, requester, HeadRule::OnChain(result_head));
        let resolve_within =
            std::cmp::min(x0x::dm::PINNED_RESOLUTION_WAIT, CE_EXCHANGE_TIMEOUT / 2);
        let exchange = state.agent.send_direct_pinned_admitted(
            requester,
            bytes.as_slice(),
            &admission,
            resolve_within,
        );
        match tokio::time::timeout(CE_EXCHANGE_TIMEOUT, exchange).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "ADR 0110 S4: crypto-only exclusion catch-up send refused or failed");
                return;
            }
            Err(_) => {
                tracing::debug!(
                    "ADR 0110 S4: crypto-only exclusion catch-up exchange deadline elapsed"
                );
                return;
            }
        }
    }
}

/// The guarded-egress admission of one frame write to `recipient`, for
/// live delivery and catch-up alike (§3 L231). The pre-phase holds the
/// group's membership lock while it takes ADR 0107's serving check
/// (Active, unbanned, unrevoked, certificate-eligible, not withdrawn, not
/// quarantined), the D60 machine/binding check, the capability gate and
/// the head rule. The seam re-takes the serving check, the D60 check and
/// the head rule synchronously, immediately before the write. The seam of
/// `send_direct_pinned_admitted` adds this agent's own revocation, pairing
/// and binding checks.
pub(super) fn guarded_admission(
    state: &Arc<AppState>,
    group_id: &str,
    recipient: &AgentId,
    rule: HeadRule,
) -> x0x::dm::ArtifactAdmission {
    guarded_admission_for(
        state,
        group_id,
        recipient,
        rule,
        x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
    )
}

/// As [`guarded_admission`], gated on the application `capability` bit
/// instead of `CRYPTO_EXCLUSION_V1`.
pub(super) fn guarded_admission_for(
    state: &Arc<AppState>,
    group_id: &str,
    recipient: &AgentId,
    rule: HeadRule,
    capability: u64,
) -> x0x::dm::ArtifactAdmission {
    guarded_admission_gated(state, group_id, recipient, rule, Some(capability))
}

/// As [`guarded_admission`], with no capability gate: the admission of a
/// saved `MemberRemoved` (§3). That event is the legacy removal event,
/// which every member decodes, so a legacy survivor without a capability
/// bit must still receive it. Every other check is the same.
pub(super) fn guarded_removal_admission(
    state: &Arc<AppState>,
    group_id: &str,
    recipient: &AgentId,
    rule: HeadRule,
) -> x0x::dm::ArtifactAdmission {
    guarded_admission_gated(state, group_id, recipient, rule, None)
}

/// The shared body of the guarded admissions. `capability: None` skips
/// only the capability gate.
fn guarded_admission_gated(
    state: &Arc<AppState>,
    group_id: &str,
    recipient: &AgentId,
    rule: HeadRule,
    capability: Option<u64>,
) -> x0x::dm::ArtifactAdmission {
    use super::super as ng;
    let state = Arc::clone(state);
    let group_id = group_id.to_string();
    let recipient = *recipient;
    Arc::new(move || {
        let state = Arc::clone(&state);
        let group_id = group_id.clone();
        let rule = rule.clone();
        Box::pin(async move {
            let recipient_hex = hex::encode(recipient.as_bytes());
            let lock = ng::group_membership_lock_for_known_group(&state, &group_id).await?;
            let evidence = {
                let _membership_guard = lock.lock().await;
                let evidence = ng::join_artifact_serving_check(&state, &group_id, &recipient_hex)
                    .await
                    .ok()?;
                let head_ok = {
                    let roster = state.named_groups.read().await;
                    crate::server::resolve_group_entry_locked(&roster, &group_id)
                        .is_some_and(|(_, info)| head_rule_admits(info, &rule))
                };
                let supported = capability.is_none_or(|bit| {
                    state
                        .agent
                        .capability_store()
                        .verified_registry_supports(&recipient, bit)
                        == Some(true)
                });
                if !head_ok || !supported || !write_allowed(&state, &recipient).await {
                    return None;
                }
                evidence
            };
            let seam: x0x::dm::SeamAdmission = Box::new(move || {
                if ng::join_artifact_seam_refusal(&state, &group_id, &recipient_hex, evidence)
                    .is_some()
                {
                    return false;
                }
                if !write_allowed_at_seam(&state, &recipient) {
                    return false;
                }
                let Ok(roster) = state.named_groups.try_read() else {
                    return false;
                };
                crate::server::resolve_group_entry_locked(&roster, &group_id)
                    .is_some_and(|(_, info)| head_rule_admits(info, &rule))
            });
            Some(seam)
        })
    })
}

// ─── Receive (§4 L249) ─────────────────────────────────────────────────────

/// The result of one receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum ReceiveOutcome {
    /// The exclusion was verified and installed.
    Applied,
    /// This node already holds the result.
    Duplicate,
    /// This node is behind the frame's parent; the frame is stashed.
    Behind,
    /// The frame was refused.
    Refused(ce::CryptoExclusionRefusal),
    /// The frame was valid but this node could not persist the result (a
    /// local fault). Nothing was installed; the frame is kept for retry and
    /// is never counted as a sender defect.
    LocalFailure,
    /// The group is unknown here, or the node is not a survivor.
    NotApplicable,
}

impl ReceiveOutcome {
    /// The frame stays in the stash for a later retry: this node is behind
    /// it, or a local fault stopped the install.
    pub(in crate::server) fn is_retained(self) -> bool {
        matches!(self, Self::Behind | Self::LocalFailure)
    }
}

/// The direct-message listener hands every `X0XCE1` payload here.
pub(in crate::server) fn spawn_receipt(
    state: &Arc<AppState>,
    sender: AgentId,
    verified: bool,
    payload: Vec<u8>,
) {
    if !verified {
        return;
    }
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let outcome = receive(&task_state, sender, &payload).await;
        if outcome.is_retained() {
            let mut inner = task_state.revocation_evictions.inner.lock().await;
            if inner.ce.stash.len() >= CE_STASH_CAP {
                inner.ce.stash.remove(0);
            }
            inner.ce.stash.push(StashedFrame {
                sender,
                bytes: payload,
                at: Instant::now(),
            });
        }
    });
}

/// Retry every stashed frame; keep the ones still ahead of this node or
/// stopped by a local fault.
pub(super) async fn retry_stash(state: &Arc<AppState>) {
    let stash = std::mem::take(&mut state.revocation_evictions.inner.lock().await.ce.stash);
    let now = Instant::now();
    let mut keep = Vec::new();
    for frame in stash {
        if now.saturating_duration_since(frame.at) > CE_STASH_TTL {
            continue;
        }
        if receive(state, frame.sender, &frame.bytes)
            .await
            .is_retained()
        {
            keep.push(frame);
        }
    }
    if !keep.is_empty() {
        let mut inner = state.revocation_evictions.inner.lock().await;
        keep.append(&mut inner.ce.stash);
        let excess = keep.len().saturating_sub(CE_STASH_CAP);
        keep.drain(..excess);
        inner.ce.stash = keep;
    }
}

/// Verify and install one frame.
pub(in crate::server) async fn receive(
    state: &Arc<AppState>,
    sender: AgentId,
    payload: &[u8],
) -> ReceiveOutcome {
    use super::super as ng;
    let frame = match ce::decode_frame(payload) {
        Ok(frame) => frame,
        Err(refusal) => return ReceiveOutcome::Refused(refusal),
    };
    if let Err(refusal) = ce::verify_signatures(&frame) {
        tracing::debug!(
            reason = refusal.as_str(),
            "ADR 0110 S4: crypto-only exclusion refused"
        );
        return ReceiveOutcome::Refused(refusal);
    }
    let body = frame.body;
    {
        // Enforcement point 4: a revoked signer or sender fails closed.
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        if set.is_agent_revoked(&AgentId(body.actor)) || set.is_agent_revoked(&sender) {
            return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::ActorIneligible);
        }
    }
    let Some(group_key) = ng::resolve_named_group_storage_key(state, &body.stable_group_id).await
    else {
        return ReceiveOutcome::NotApplicable;
    };
    let membership_lock = ng::group_membership_lock(state, &group_key).await;
    let membership_guard = membership_lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return ReceiveOutcome::NotApplicable;
    };
    let sender_hex = hex::encode(sender.as_bytes());
    // The frame is self-authenticating (the actor signed it); a relaying
    // sender must still be an Active member of the group.
    if sender.as_bytes() != &body.actor && !info.has_active_member(&sender_hex) {
        return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::ActorIneligible);
    }
    if info.state_hash == body.commit.state_hash {
        return ReceiveOutcome::Duplicate;
    }
    if info.state_hash != body.prior_head && info.state_revision < body.prior_revision {
        return ReceiveOutcome::Behind;
    }
    let tree = {
        let map = state.treekem_groups.read().await;
        map.get(&group_key)
            .or_else(|| map.get(info.stable_group_id()))
            .cloned()
    };
    let Some(tree) = tree else {
        return ReceiveOutcome::NotApplicable;
    };
    let commit = body.commit.to_commit();
    let mut guard = tree.lock().await;
    // §3 L231: re-read the revocation set under the membership lock,
    // immediately before the apply, so a revocation that landed since the
    // early check above also refuses the frame.
    let validated = {
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        if set.is_agent_revoked(&sender) {
            Err(ce::CryptoExclusionRefusal::ActorIneligible)
        } else {
            ce::validate_against_parent(&body, &info, guard.epoch(), |actor| {
                set.is_agent_revoked(&AgentId(*actor))
            })
        }
    };
    if let Err(refusal) = validated {
        drop(guard);
        if refusal == ce::CryptoExclusionRefusal::HeadMismatch {
            // A competing child of our head: let the shared apply hook
            // record the fork evidence it records for any commit.
            let _ = ng::apply_stateful_event_with_evidence(
                state,
                &group_key,
                &info,
                &commit,
                None,
                false,
                None,
                x0x::groups::ActionKind::AdminOrHigher,
                |_| {},
            )
            .await;
        }
        tracing::info!(
            group_id = %LogHexId::group(&group_key),
            reason = refusal.as_str(),
            "ADR 0110 S4: crypto-only exclusion refused"
        );
        return ReceiveOutcome::Refused(refusal);
    }
    let ce::CryptoExclusionCryptoV1::TreeKem {
        commit: treekem_commit,
        next_epoch,
        ..
    } = &body.crypto
    else {
        return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::CryptoPlaneUnsupported);
    };
    let next_epoch = *next_epoch;
    let signed_binding = commit.security_binding.clone();
    let roster_revision = body.roster_revision;
    let next = match ng::apply_stateful_event_with_evidence(
        state,
        &group_key,
        &info,
        &commit,
        None,
        false,
        None,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.roster_revision = ng::adopt_roster_revision(next.roster_revision, roster_revision);
            next.secret_epoch = next_epoch;
            next.security_binding = signed_binding;
        },
    )
    .await
    {
        Ok(next) => next,
        Err(error) => {
            tracing::info!(group_id = %LogHexId::group(&group_key), "ADR 0110 S4: crypto-only exclusion commit refused: {error}");
            return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::BadSignature);
        }
    };
    let target = AgentId(body.target);
    let Ok(rollback_snapshot) = guard.to_snapshot_bytes() else {
        return ReceiveOutcome::NotApplicable;
    };
    let refuse = |guard: &mut x0x::mls::TreeKemMlsGroup, reason: &str| {
        ng::rollback_treekem_group_after_failed_install(
            state,
            &group_key,
            &next,
            &rollback_snapshot,
            guard,
            reason,
        );
    };
    if guard.process_commit(treekem_commit).is_err() || guard.epoch() != next_epoch {
        refuse(&mut guard, "crypto_exclusion_process_failed");
        return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::EpochMismatch);
    }
    // The cryptographic removal proof: the target's leaf is gone.
    if guard.tracks_member(&target) {
        refuse(&mut guard, "crypto_exclusion_leaf_retained");
        return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::LeafMismatch);
    }
    if let Err(error) = ng::persist_treekem_and_named_groups_atomic_with_info(
        state,
        &group_key,
        next.clone(),
        &guard,
    )
    .await
    {
        if !ng::self_leave_persist_left_epoch_installed(&error) {
            refuse(&mut guard, "crypto_exclusion_persist_failed");
            tracing::warn!(group_id = %LogHexId::group(&group_key), "ADR 0110 S4: crypto-only exclusion not installed: {error}");
            // A local storage fault, not a sender defect: keep the frame
            // and try again.
            return ReceiveOutcome::LocalFailure;
        }
    }
    drop(guard);
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    let _ = ng::prune_treekem_cache_member(
        state,
        &group_key,
        &hex::encode(body.target),
        "crypto_exclusion",
    )
    .await;
    {
        let frame_bytes = Arc::new(payload.to_vec());
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.ce.remember(
            &body.stable_group_id,
            body.next_revision,
            &body.commit.state_hash,
            Arc::clone(&frame_bytes),
        );
        // Durable replay evidence: kept in this node's own row once it
        // completes, so catch-up still has the frame after a restart.
        inner.ce.note_replay_pending(
            EvictionKey::new(body.stable_group_id.clone(), body.target),
            frame_bytes,
        );
    }
    drop(membership_guard);
    tracing::info!(
        group_id = %LogHexId::group(&group_key),
        epoch = next_epoch,
        "ADR 0110 S4: crypto-only exclusion installed"
    );
    // Later commits that queued behind this gap can now chain.
    ng::replay_pending_treekem_events(state, &group_key).await;
    state.agent.s4_revocation_intake().request_reconcile();
    ReceiveOutcome::Applied
}

/// Test-only: the newest frame this node holds for `stable_group_id`.
#[cfg(test)]
pub(in crate::server) async fn latest_frame_for_test(
    state: &AppState,
    stable_group_id: &str,
) -> Option<Vec<u8>> {
    let inner = state.revocation_evictions.inner.lock().await;
    inner
        .ce
        .log
        .get(stable_group_id)
        .and_then(|log| log.back())
        .map(|entry| entry.bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with_log(head: &str, log: &[(&str, &str)]) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            AgentId([1; 32]),
            "ab".repeat(16),
        );
        info.state_hash = head.to_string();
        for (prev, hash) in log {
            let commit = x0x::groups::state_commit::GroupStateCommit {
                group_id: "g".to_string(),
                revision: 1,
                prev_state_hash: Some((*prev).to_string()),
                roster_root: String::new(),
                policy_hash: String::new(),
                public_meta_hash: String::new(),
                security_binding: None,
                state_hash: (*hash).to_string(),
                withdrawn: false,
                committed_by: String::new(),
                committed_at: 0,
                signer_public_key: String::new(),
                signature: String::new(),
            };
            info.commit_log
                .push(x0x::groups::state_commit::RetainedCommit {
                    commit,
                    roster: BTreeMap::new(),
                    meta: None,
                });
        }
        info
    }

    #[test]
    fn saved_frame_on_the_current_head_finishes_delivery() {
        let info = info_with_log("r", &[("p", "r")]);
        assert_eq!(
            classify_saved_frame(&info, "p", "r"),
            SavedFrameState::CurrentHead
        );
    }

    #[test]
    fn saved_frame_behind_a_later_head_is_superseded() {
        let info = info_with_log("later", &[("p", "r"), ("r", "later")]);
        assert_eq!(
            classify_saved_frame(&info, "p", "r"),
            SavedFrameState::Superseded
        );
    }

    #[test]
    fn unchanged_parent_abandons_the_preparation() {
        let info = info_with_log("p", &[]);
        assert_eq!(
            classify_saved_frame(&info, "p", "r"),
            SavedFrameState::Abandoned
        );
    }

    #[test]
    fn competing_child_of_the_parent_is_a_fork() {
        let info = info_with_log("other", &[("p", "other")]);
        assert_eq!(classify_saved_frame(&info, "p", "r"), SavedFrameState::Fork);
    }

    #[test]
    fn unrelated_head_waits_for_head_sync() {
        let info = info_with_log("x", &[("y", "x")]);
        assert_eq!(
            classify_saved_frame(&info, "p", "r"),
            SavedFrameState::Unknown
        );
    }

    #[test]
    fn local_failure_is_retained_and_is_not_a_refusal() {
        assert!(ReceiveOutcome::LocalFailure.is_retained());
        assert!(ReceiveOutcome::Behind.is_retained());
        assert!(!ReceiveOutcome::Applied.is_retained());
        assert!(!ReceiveOutcome::Duplicate.is_retained());
        assert!(!ReceiveOutcome::NotApplicable.is_retained());
        assert!(
            !ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::ActorIneligible).is_retained()
        );
    }

    #[test]
    fn catchup_log_is_bounded_and_deduplicated() {
        let mut ce_state = CeState::default();
        for revision in 0..(CE_LOG_PER_GROUP as u64 + 4) {
            ce_state.remember("g", revision, "r", Arc::new(vec![1]));
            ce_state.remember("g", revision, "r", Arc::new(vec![2]));
        }
        let log = ce_state.log.get("g").map(VecDeque::len);
        assert_eq!(log, Some(CE_LOG_PER_GROUP));
    }

    #[test]
    fn stranded_recipients_name_the_gap_revision() {
        let mut ce_state = CeState::default();
        let key = EvictionKey::new("g", [9; 32]);
        new_delivery(
            &mut ce_state,
            &key,
            "r",
            7,
            Arc::new(vec![1]),
            vec![[1; 32], [2; 32], [3; 32]],
            false,
        );
        if let Some(delivery) = ce_state.deliveries.get_mut(&key) {
            delivery
                .recipients
                .insert([1; 32], RecipientDelivery::Lacking);
            delivery.recipients.insert([2; 32], RecipientDelivery::Sent);
            delivery
                .recipients
                .insert([3; 32], RecipientDelivery::Unknown);
        }
        let stranded = ce_state.stranded_json(&key);
        let entries = stranded.as_array().cloned().unwrap_or_default();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry["gap_revision"] == 7));
        assert_eq!(entries[0]["advert"], "lacking");
        assert_eq!(entries[1]["advert"], "unknown");
        assert!(ce_state.delivering().contains(&key));
    }

    // ─── #1357 review P2: InFlight installed before the send starts ──────

    /// The old round spawned the send, then wrote `InFlight` after it. A
    /// send that finished first had its `Sent` overwritten by `InFlight`,
    /// and the recipient was never retried or completed. Now the round
    /// installs `InFlight(token)` and returns the sends to start; only the
    /// same token's completion writes.
    #[test]
    fn a_fast_completion_is_never_overwritten_by_in_flight() {
        let survivor = [5; 32];
        let mut recipients = BTreeMap::from([(survivor, RecipientDelivery::Due)]);
        let attempt = next_attempt();
        let started = apply_round(
            &mut recipients,
            vec![RoundUpdate {
                recipient: survivor,
                observed: RecipientDelivery::Due,
                next: Some(RecipientDelivery::InFlight(attempt)),
            }],
        );
        assert_eq!(started, vec![(survivor, attempt)]);
        // The send completes at once, before anything else runs.
        assert!(finish_attempt(
            &mut recipients,
            &survivor,
            attempt,
            RecipientDelivery::Sent
        ));
        assert_eq!(recipients.get(&survivor), Some(&RecipientDelivery::Sent));
        // A late round write planned from the old `Due` snapshot changes
        // nothing: the stored status is no longer the observed one.
        let late = apply_round(
            &mut recipients,
            vec![RoundUpdate {
                recipient: survivor,
                observed: RecipientDelivery::Due,
                next: Some(RecipientDelivery::InFlight(next_attempt())),
            }],
        );
        assert!(late.is_empty());
        assert_eq!(recipients.get(&survivor), Some(&RecipientDelivery::Sent));
    }

    /// A failed send returns the recipient to `Due`, so the next round
    /// retries it; a stale attempt's completion is ignored.
    #[test]
    fn a_failed_attempt_is_retried_and_stale_completions_are_ignored() {
        let survivor = [6; 32];
        let mut recipients = BTreeMap::from([(survivor, RecipientDelivery::Due)]);
        let first = next_attempt();
        apply_round(
            &mut recipients,
            vec![RoundUpdate {
                recipient: survivor,
                observed: RecipientDelivery::Due,
                next: Some(RecipientDelivery::InFlight(first)),
            }],
        );
        assert!(finish_attempt(
            &mut recipients,
            &survivor,
            first,
            RecipientDelivery::Due
        ));
        let second = next_attempt();
        let started = apply_round(
            &mut recipients,
            vec![RoundUpdate {
                recipient: survivor,
                observed: RecipientDelivery::Due,
                next: Some(RecipientDelivery::InFlight(second)),
            }],
        );
        assert_eq!(started, vec![(survivor, second)], "the retry starts");
        assert!(
            !finish_attempt(&mut recipients, &survivor, first, RecipientDelivery::Sent),
            "the first attempt's late completion must not write"
        );
        assert_eq!(
            recipients.get(&survivor),
            Some(&RecipientDelivery::InFlight(second))
        );
        // A recipient dropped from the roster ignores its completion.
        apply_round(
            &mut recipients,
            vec![RoundUpdate {
                recipient: survivor,
                observed: RecipientDelivery::InFlight(second),
                next: None,
            }],
        );
        assert!(!finish_attempt(
            &mut recipients,
            &survivor,
            second,
            RecipientDelivery::Sent
        ));
        assert!(recipients.is_empty());
    }

    // ─── #1357 review P1: guarded egress head rule ───────────────────────

    #[test]
    fn live_delivery_needs_the_current_head_and_no_containment() {
        let mut info = info_with_log("r", &[("p", "r")]);
        let live = HeadRule::Current("r".to_string());
        assert!(head_rule_admits(&info, &live));
        // The head moved (a later epoch): live delivery refuses.
        info.state_hash = "later".to_string();
        assert!(!head_rule_admits(&info, &live));
        // Catch-up still serves a result that is on the chain.
        assert!(head_rule_admits(&info, &HeadRule::OnChain("r".to_string())));
        assert!(!head_rule_admits(
            &info,
            &HeadRule::OnChain("fork".to_string())
        ));
        // Containment: a quarantined or withdrawn group admits nothing.
        info.state_hash = "r".to_string();
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: 1,
            state_hash: "other".to_string(),
            committed_by: String::new(),
            observed_at_ms: 0,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        });
        assert!(!head_rule_admits(&info, &live));
        assert!(!head_rule_admits(
            &info,
            &HeadRule::OnChain("r".to_string())
        ));
        info.fork_quarantine = None;
        info.withdrawn = true;
        assert!(!head_rule_admits(&info, &live));
    }

    /// #1357 CI (493c2a6): the live head rule follows the state hash, and
    /// the state hash commits to the TreeKEM epoch through the security
    /// binding, not through `secret_epoch`. An epoch bump alone is not a
    /// head move (the daemon test's old mutation); a production epoch move
    /// (epoch and binding together) is, and the rule then refuses.
    #[test]
    fn an_epoch_move_moves_the_head_through_its_binding() {
        let admin = AgentId([1; 32]);
        let mut info = GroupInfo::new("e".into(), String::new(), admin, "ab".repeat(16));
        info.security_binding = Some(format!("treekem:epoch={}", info.secret_epoch));
        info.recompute_state_hash();
        let live = HeadRule::Current(info.state_hash.clone());
        assert!(head_rule_admits(&info, &live));
        let mut epoch_only = info.clone();
        epoch_only.secret_epoch = epoch_only.secret_epoch.saturating_add(1);
        epoch_only.recompute_state_hash();
        assert_eq!(epoch_only.state_hash, info.state_hash);
        assert!(head_rule_admits(&epoch_only, &live));
        let mut moved = info.clone();
        moved.secret_epoch = moved.secret_epoch.saturating_add(1);
        moved.security_binding = Some(format!("treekem:epoch={}", moved.secret_epoch));
        moved.recompute_state_hash();
        assert_ne!(moved.state_hash, info.state_hash);
        assert!(!head_rule_admits(&moved, &live));
    }

    // ─── #1357 review P1: replay evidence across restart ─────────────────

    fn signed_frame(
        stable_group_id: &str,
        prior_head: &str,
        result_head: &str,
        next_revision: u64,
    ) -> Vec<u8> {
        let kp = x0x::identity::AgentKeypair::generate().expect("keypair");
        let commit = x0x::groups::state_commit::GroupStateCommit {
            group_id: "g".to_string(),
            revision: next_revision,
            prev_state_hash: Some(prior_head.to_string()),
            roster_root: String::new(),
            policy_hash: String::new(),
            public_meta_hash: String::new(),
            security_binding: None,
            state_hash: result_head.to_string(),
            withdrawn: false,
            committed_by: String::new(),
            committed_at: 0,
            signer_public_key: String::new(),
            signature: String::new(),
        };
        let body = ce::CryptoExclusionBodyV1 {
            stable_group_id: stable_group_id.to_string(),
            actor: *kp.agent_id().as_bytes(),
            target: [9; 32],
            prior_head: prior_head.to_string(),
            prior_revision: next_revision.saturating_sub(1),
            next_revision,
            roster_revision: next_revision,
            removal_proof_hash: [3; 32],
            crypto: ce::CryptoExclusionCryptoV1::TreeKem {
                leaf_key_package_hash: "leaf".to_string(),
                commit: vec![1, 2, 3],
                next_epoch: 2,
            },
            commit: ce::CommitHeaderV1::from(&commit),
        };
        let frame = ce::sign(body, &kp).expect("sign");
        ce::encode_frame(&frame).expect("encode")
    }

    /// The restart case of the review: the exclusion committed, a survivor
    /// was offline, the head moved on and this node restarted. The row
    /// completed (keeping its frame) or is still open with a superseded
    /// frame; either way the rebuilt catch-up log serves it. A fork frame
    /// is never served.
    #[test]
    fn restart_rebuilds_the_catchup_log_from_row_frames() {
        let info = info_with_log("later", &[("p", "r"), ("r", "later")]);
        let stable = info.stable_group_id().to_string();
        let key = EvictionKey::new(stable.clone(), [9; 32]);
        let frame = signed_frame(&stable, "p", "r", 5);
        let groups = vec![("g".to_string(), info)];
        for complete in [true, false] {
            let mut store = ObligationStore::new();
            store.intake(
                &key,
                x0x::groups::eviction::EvictionTrigger::SelfLeave {
                    commit_hash: "p".to_string(),
                },
                None,
                0,
                [0; 16],
            );
            let row = store.get_mut(&key).expect("row");
            row.phase = Phase::CommittedDeliveryPending;
            row.outgoing_event = Some(frame.clone());
            if complete {
                assert!(store.complete(&key, Some("later".into()), Some(3), 1));
            }
            let mut ce_state = CeState::default();
            rebuild_catchup_log(&groups, &store, &mut ce_state);
            let served = ce_state.catchup_frames(std::slice::from_ref(&stable), 4);
            assert_eq!(served.len(), 1, "complete={complete}");
            assert_eq!(served[0].1, "r");
            assert_eq!(served[0].2.as_slice(), frame.as_slice());
            assert!(ce_state
                .catchup_frames(std::slice::from_ref(&stable), 5)
                .is_empty());
        }
        // An open row whose frame meets a competing child is fork evidence.
        let fork_groups = vec![("g".to_string(), info_with_log("other", &[("p", "other")]))];
        assert_eq!(fork_groups[0].1.stable_group_id(), stable);
        let mut store = ObligationStore::new();
        store.intake(
            &key,
            x0x::groups::eviction::EvictionTrigger::SelfLeave {
                commit_hash: "p".to_string(),
            },
            None,
            0,
            [0; 16],
        );
        store.get_mut(&key).expect("row").outgoing_event = Some(frame);
        let mut ce_state = CeState::default();
        rebuild_catchup_log(&fork_groups, &store, &mut ce_state);
        assert!(ce_state
            .catchup_frames(std::slice::from_ref(&stable), 0)
            .is_empty());
    }

    /// A survivor keeps an installed frame in its own row once that row
    /// completes, never in an open row (which would make it deliver).
    #[test]
    fn received_frame_is_attached_to_the_completed_row_only() {
        let key = EvictionKey::new("g", [9; 32]);
        let mut store = ObligationStore::new();
        store.intake(
            &key,
            x0x::groups::eviction::EvictionTrigger::SelfLeave {
                commit_hash: "p".to_string(),
            },
            None,
            0,
            [0; 16],
        );
        let mut ce_state = CeState::default();
        ce_state.note_replay_pending(key.clone(), Arc::new(vec![7]));
        assert!(!attach_replay_evidence(&mut ce_state, &mut store));
        assert!(store.get(&key).expect("row").outgoing_event.is_none());
        assert!(store.complete(&key, Some("r".into()), Some(2), 1));
        assert!(attach_replay_evidence(&mut ce_state, &mut store));
        assert_eq!(
            store.get(&key).expect("row").outgoing_event.as_deref(),
            Some(&[7u8][..])
        );
        assert!(ce_state.replay_pending.is_empty());
    }

    #[test]
    fn catchup_frames_are_served_oldest_first() {
        let mut ce_state = CeState::default();
        ce_state.remember("g", 7, "r7", Arc::new(vec![7]));
        ce_state.remember("g", 5, "r5", Arc::new(vec![5]));
        ce_state.remember("g", 6, "r6", Arc::new(vec![6]));
        let heads: Vec<String> = ce_state
            .catchup_frames(&["g".to_string()], 5)
            .into_iter()
            .map(|(_, head, _)| head)
            .collect();
        assert_eq!(heads, vec!["r6".to_string(), "r7".to_string()]);
    }
}

/// Daemon-level tests (an in-process `AppState`; no network). They run in
/// CI under the isolated test runner.
#[cfg(test)]
mod daemon_tests {
    use super::super::super as ng;
    use super::*;
    use anyhow::Result;
    use base64::Engine as _;

    fn advertise_crypto_exclusion(state: &AppState, peer: AgentId) {
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry {
            version: 1,
            bits: x0x::dm::CapabilityRegistry::current().bits,
        };
        assert!(
            state.agent.capability_store().insert(
                peer,
                x0x::identity::MachineId([4; 32]),
                capabilities,
                x0x::dm_capability::now_unix_ms(),
            ),
            "verified capability advert"
        );
    }

    async fn admit(
        state: &Arc<AppState>,
        group_id: &str,
        recipient: &AgentId,
        rule: &HeadRule,
    ) -> Option<x0x::dm::SeamAdmission> {
        guarded_admission(state, group_id, recipient, rule.clone())().await
    }

    /// #1357 review P1: live delivery goes through the guarded admission,
    /// evaluated again at the write. A recipient that was eligible when the
    /// round scheduled it, then was removed, banned, saw the head (epoch)
    /// move, or saw the group quarantined, is refused by the seam (after a
    /// passing pre-phase) and by a fresh pre-phase.
    #[tokio::test]
    async fn live_delivery_refuses_a_recipient_that_became_ineligible() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let survivor = AgentId([0x77; 32]);
        let survivor_hex = hex::encode(survivor.as_bytes());
        let group_id = "ce".repeat(16);
        let mut info = GroupInfo::new("ce".into(), String::new(), admin, group_id.clone());
        info.add_member(
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        let rule = HeadRule::Current(info.state_hash.clone());
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        advertise_crypto_exclusion(&state, survivor);

        let seam = admit(&state, &stable, &survivor, &rule).await;
        assert!(
            seam.is_some_and(|seam| seam()),
            "an eligible recipient is admitted"
        );

        type Change = fn(&mut GroupInfo, &str);
        let changes: [(&str, Change); 4] = [
            ("removed", |info, member| {
                info.remove_member(member, None);
            }),
            ("banned", |info, member| {
                info.ban_member(member, None);
            }),
            ("head moved", |info, _| {
                // A TreeKEM epoch move as production commits it: the epoch
                // and its security binding move together, and the binding
                // is what the state hash commits to (#1357 CI: the epoch
                // alone left the head unchanged).
                let before = info.state_hash.clone();
                info.secret_epoch = info.secret_epoch.saturating_add(1);
                info.security_binding = Some(format!("treekem:epoch={}", info.secret_epoch));
                info.recompute_state_hash();
                assert_ne!(info.state_hash, before, "the head must move");
            }),
            ("quarantined", |info, _| {
                info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
                    revision: 1,
                    state_hash: "other".into(),
                    committed_by: String::new(),
                    observed_at_ms: 0,
                    snapshot: x0x::groups::ForkSnapshot {
                        terminal_commit: info.terminal_commit_header(),
                        conflicting_commit: info.terminal_commit_header(),
                        classification: None,
                    },
                    no_anchor: true,
                });
            }),
        ];
        for (label, change) in changes {
            // Scheduled while eligible: the pre-phase passes.
            let seam = admit(&state, &stable, &survivor, &rule)
                .await
                .unwrap_or_else(|| panic!("{label}: the pre-phase must admit first"));
            // The recipient becomes ineligible before the physical write.
            {
                let mut groups = state.named_groups.write().await;
                let stored = groups.get_mut(&group_id).expect("group");
                change(stored, &survivor_hex);
            }
            assert!(!seam(), "{label}: the seam must refuse the write");
            assert!(
                admit(&state, &stable, &survivor, &rule).await.is_none(),
                "{label}: a fresh pre-phase must refuse"
            );
            state
                .named_groups
                .write()
                .await
                .insert(group_id.clone(), info.clone());
        }
        Ok(())
    }

    /// #1357 review P1: crypto-only catch-up survives a restart. The
    /// exclusion commits while a survivor is offline, the head moves on (so
    /// live delivery stops and the row completes), and the committer
    /// restarts. The rebuilt catch-up log still holds the frame, and the
    /// survivor that missed the transition installs it.
    #[tokio::test]
    async fn survivor_catches_up_after_head_move_and_committer_restart() -> Result<()> {
        let (state, dir) = ng::tests::secure_endpoint_test_state().await?;
        state
            .named_group_test_recorders
            .metadata_publish_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let admin = state.agent.agent_id();
        let admin_hex = hex::encode(admin.as_bytes());
        let group_id = "cf".repeat(16);
        let group_id_bytes = hex::decode(&group_id)?;
        let seed = ng::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let mut admin_group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), admin, &seed)?;
        // The leaver.
        let leaver_kp = x0x::identity::AgentKeypair::generate()?;
        let leaver = leaver_kp.agent_id();
        let leaver_hex = hex::encode(leaver.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(leaver, &[9u8; 32])?;
        let leaver_kp_bytes = prepared.key_package_bytes().to_vec();
        admin_group.add_member(leaver, &leaver_kp_bytes)?;
        // The survivor, offline during the transition.
        let survivor_seed = [7u8; 32];
        let survivor = x0x::identity::AgentKeypair::generate()?.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(survivor, &survivor_seed)?;
        let survivor_kp_bytes = prepared.key_package_bytes().to_vec();
        let added = admin_group.add_member(survivor, &survivor_kp_bytes)?;
        let survivor_group =
            x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
        let survivor_snapshot = survivor_group.to_snapshot_bytes()?;
        let epoch = admin_group.epoch();

        let mut info = GroupInfo::new("ce-restart".into(), String::new(), admin, group_id.clone());
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        for (member_hex, kp_bytes) in [
            (&leaver_hex, &leaver_kp_bytes),
            (&survivor_hex, &survivor_kp_bytes),
        ] {
            info.add_member(
                member_hex.clone(),
                x0x::groups::GroupRole::Member,
                Some(admin_hex.clone()),
                None,
            );
            info.set_member_treekem_key_package(
                member_hex,
                base64::engine::general_purpose::STANDARD.encode(kp_bytes),
            );
        }
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        state.treekem_groups.write().await.insert(
            group_id.clone(),
            Arc::new(tokio::sync::Mutex::new(admin_group)),
        );
        let pre_leave = info.clone();

        // The self-leave; the committer seals the retained leaf.
        let mut leaving = info.clone();
        leaving.roster_revision = leaving.roster_revision.saturating_add(1);
        let revision = leaving.roster_revision;
        leaving.remove_member(&leaver_hex, Some(leaver_hex.clone()));
        let leave_commit = leaving.seal_commit(&leaver_kp, ng::now_millis_u64())?;
        let leave = ng::NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision,
            actor: leaver_hex.clone(),
            agent_id: leaver_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            commit: Some(leave_commit),
        };
        let applied =
            ng::apply_named_group_metadata_event(&state, leave.clone(), leaver, true, None).await;
        assert!(applied.accepted, "the leave must apply: {applied:?}");
        let frame = latest_frame_for_test(&state, &stable)
            .await
            .expect("the crypto-only exclusion committed");
        let result_head = ce::decode_frame(&frame)
            .map(|frame| frame.body.commit.state_hash)
            .expect("frame");

        // The head moves on before the survivor returns.
        {
            let mut groups = state.named_groups.write().await;
            let stored = groups.get_mut(&group_id).expect("group");
            assert_eq!(stored.state_hash, result_head);
            stored.description = "moved on".into();
            stored.seal_commit(state.agent.identity().agent_keypair(), ng::now_millis_u64())?;
            assert_ne!(stored.state_hash, result_head);
        }
        assert!(
            ng::save_named_groups(&state).await,
            "the moved head is durable"
        );
        // Live delivery stops (no old crypto material after the move) and
        // the row completes from the chain. The commit's own spawned round
        // may have deferred the next one; make it due now.
        for delivery in state
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .deliveries
            .values_mut()
        {
            delivery.next_at = Instant::now();
        }
        drive_deliveries(&state).await;
        super::super::revocation_eviction_pass(&state).await;
        assert!(super::super::persist_obligations(&state).await);
        {
            let inner = state.revocation_evictions.inner.lock().await;
            assert!(inner.ce.deliveries.is_empty(), "live delivery stopped");
            let row = inner
                .store
                .get(&EvictionKey::new(stable.clone(), *leaver.as_bytes()))
                .expect("row");
            assert_eq!(row.phase, Phase::Complete);
            assert_eq!(row.outgoing_event.as_deref(), Some(frame.as_slice()));
        }

        // The committer restarts.
        let data_dir = dir.path().to_path_buf();
        let restarted =
            ng::tests::secure_endpoint_test_state_at(&data_dir, Arc::clone(&state.agent)).await?;
        let named = restarted.named_groups.read().await.clone();
        let restored =
            ng::restore_treekem_groups(&named, restarted.agent.as_ref(), &restarted.treekem_dir)
                .await;
        *restarted.treekem_groups.write().await = restored;
        super::super::load_persisted_obligations(&restarted).await;
        let served = restarted
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .catchup_frames(std::slice::from_ref(&stable), pre_leave.state_revision);
        assert_eq!(
            served
                .iter()
                .map(|(_, _, bytes)| bytes.to_vec())
                .collect::<Vec<_>>(),
            vec![frame.clone()],
            "the restarted committer still serves the frame on catch-up"
        );

        // The survivor returns, takes the self-leave, then the served frame.
        let (replica, _replica_dir) = ng::tests::secure_endpoint_test_state().await?;
        replica
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), pre_leave);
        let survivor_tree =
            x0x::mls::TreeKemMlsGroup::restore(&survivor_snapshot, survivor, &survivor_seed)?;
        replica.treekem_groups.write().await.insert(
            group_id.clone(),
            Arc::new(tokio::sync::Mutex::new(survivor_tree)),
        );
        let replica_leave =
            ng::apply_named_group_metadata_event(&replica, leave, leaver, true, None).await;
        assert!(replica_leave.accepted, "{replica_leave:?}");
        assert_eq!(
            receive(&replica, admin, &frame).await,
            ReceiveOutcome::Applied,
            "the survivor installs the exclusion it missed"
        );
        assert_eq!(
            replica
                .named_groups
                .read()
                .await
                .get(&group_id)
                .map(|info| info.state_hash.clone()),
            Some(result_head)
        );
        Ok(())
    }
}
