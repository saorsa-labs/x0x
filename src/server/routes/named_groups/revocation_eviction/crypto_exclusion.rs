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
//!   direct metadata delivery only, never the metadata topic and never a
//!   legacy-decoded container. Each write re-checks roster membership and
//!   the agent, machine and binding revocations just before it. A
//!   recipient with unknown support first gets an advert refresh; one whose
//!   advert lacks the bit is stranded (`waiting_for_receiver_upgrade` with
//!   the gap revision). Resends stop once the head moves past the result
//!   (no old crypto material after an epoch change).
//! - **Restart** ([`resume_after_load`]). A saved frame is resent only
//!   after the restart sync wait and only while its result is the current
//!   head. A competing branch on the parent keeps the frame as fork
//!   evidence and shows `waiting_for_fork_resolution`; nothing is
//!   published.
//! - **Receive** ([`spawn_receipt`]) verifies the frame and the L4 rule and
//!   installs it atomically. **Catch-up** ([`serve_catchup`]) sends held
//!   frames to a capable requester on this same carrier.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::crypto_exclusion as ce;
use x0x::groups::eviction::{EvJournalV1, EvictionKey};
use x0x::groups::GroupInfo;
use x0x::identity::AgentId;

use super::super::{LogHexId, SelfLeaveRekeyStep};

/// A delivery round runs no more often than this per row.
const CE_RESEND_INTERVAL: Duration = Duration::from_secs(5);
/// Frames held per group for catch-up serving.
const CE_LOG_PER_GROUP: usize = 16;
/// Frames that arrived ahead of this node's head, waiting for it.
const CE_STASH_CAP: usize = 64;
/// A stashed frame is dropped after this long.
const CE_STASH_TTL: Duration = Duration::from_secs(600);

/// The delivery state of one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecipientDelivery {
    /// A send is due.
    Due,
    /// A send is running.
    InFlight,
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
    /// restart sync wait (§3 "re-sync the head before any resend").
    resumed: bool,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
}

/// A frame held for catch-up serving.
#[derive(Debug, Clone)]
struct CeLogEntry {
    next_revision: u64,
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

    fn remember(&mut self, stable_group_id: &str, next_revision: u64, bytes: Arc<Vec<u8>>) {
        let log = self.log.entry(stable_group_id.to_string()).or_default();
        if log.iter().any(|entry| entry.next_revision == next_revision) {
            return;
        }
        log.push_back(CeLogEntry {
            next_revision,
            bytes,
        });
        while log.len() > CE_LOG_PER_GROUP {
            log.pop_front();
        }
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
    ce_state.remember(&key.stable_group_id, next_revision, Arc::clone(&bytes));
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

/// One delivery round for every due row: per recipient, re-check the
/// roster and the agent, machine and binding revocations, then send only
/// to a recipient whose current verified advert sets the bit.
pub(super) async fn drive_deliveries(state: &Arc<AppState>) {
    let runtime = &state.revocation_evictions;
    let now = Instant::now();
    let head_synced = runtime.head_synced(now);
    let due: Vec<(EvictionKey, CeDelivery)> = {
        let mut inner = runtime.inner.lock().await;
        let keys: Vec<EvictionKey> = inner
            .ce
            .deliveries
            .iter()
            .filter(|(_, delivery)| delivery.next_at <= now && (!delivery.resumed || head_synced))
            .map(|(key, _)| key.clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| {
                let delivery = inner.ce.deliveries.get_mut(&key)?;
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
            // the existing guarded recovery path.
            runtime.inner.lock().await.ce.deliveries.remove(&key);
            continue;
        }
        let active: BTreeSet<[u8; 32]> =
            survivors(&info, &local, &key.target).into_iter().collect();
        let mut updates: Vec<([u8; 32], Option<RecipientDelivery>)> = Vec::new();
        for (recipient, status) in &delivery.recipients {
            if !active.contains(recipient) {
                updates.push((*recipient, None));
                continue;
            }
            if matches!(
                status,
                RecipientDelivery::Sent | RecipientDelivery::InFlight
            ) {
                continue;
            }
            let agent = AgentId(*recipient);
            if !write_allowed(state, &agent).await {
                continue;
            }
            match capabilities.verified_registry_supports(
                &agent,
                x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
            ) {
                Some(true) => {
                    updates.push((*recipient, Some(RecipientDelivery::InFlight)));
                    spawn_send(state, key.clone(), agent, Arc::clone(&delivery.bytes));
                }
                Some(false) => updates.push((*recipient, Some(RecipientDelivery::Lacking))),
                None => {
                    updates.push((*recipient, Some(RecipientDelivery::Unknown)));
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
        let mut inner = runtime.inner.lock().await;
        if let Some(stored) = inner.ce.deliveries.get_mut(&key) {
            for (recipient, update) in updates {
                match update {
                    Some(status) => {
                        stored.recipients.insert(recipient, status);
                    }
                    None => {
                        stored.recipients.remove(&recipient);
                    }
                }
            }
            if stored
                .recipients
                .values()
                .all(|status| *status == RecipientDelivery::Sent)
            {
                inner.ce.deliveries.remove(&key);
                inner.dirty = true;
            }
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

fn spawn_send(state: &Arc<AppState>, key: EvictionKey, agent: AgentId, bytes: Arc<Vec<u8>>) {
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let status = match task_state.agent.send_direct(&agent, bytes.to_vec()).await {
            Ok(_) => RecipientDelivery::Sent,
            Err(x0x::dm::DmError::RecipientUpgradeRequired { .. }) => RecipientDelivery::Lacking,
            Err(error) => {
                tracing::debug!(%error, "ADR 0110 S4: crypto-only exclusion send failed; retrying");
                RecipientDelivery::Due
            }
        };
        let mut inner = task_state.revocation_evictions.inner.lock().await;
        if let Some(delivery) = inner.ce.deliveries.get_mut(&key) {
            if let Some(entry) = delivery.recipients.get_mut(agent.as_bytes()) {
                *entry = status;
            }
        }
    });
}

// ─── Catch-up (§4) ─────────────────────────────────────────────────────────

/// The per-exchange bound of one catch-up frame write.
const CE_CATCHUP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

/// Serve the frames this node holds for the group (any of `group_ids`) above
/// `from_revision` to a catch-up requester, on the distinct gated carrier
/// only. A requester without a current verified advert setting the bit
/// gets nothing new: the frame never goes into a legacy-decoded catch-up
/// page.
///
/// Each write uses ADR 0107's serving guard plus D60 (§3 L231): under the
/// group's membership lock the requester must be an Active, unbanned,
/// unrevoked member of a group that is not withdrawn or quarantined, with
/// no machine or binding revocation, and the seam re-checks the same
/// inputs immediately before the physical write.
pub(in crate::server) async fn serve_catchup(
    state: &Arc<AppState>,
    requester: &AgentId,
    group_ids: &[String],
    from_revision: u64,
) {
    let frames: Vec<(String, Arc<Vec<u8>>)> = {
        let inner = state.revocation_evictions.inner.lock().await;
        group_ids
            .iter()
            .find_map(|id| inner.ce.log.get(id).map(|log| (id, log)))
            .map(|(id, log)| {
                log.iter()
                    .filter(|entry| entry.next_revision > from_revision)
                    .map(|entry| (id.clone(), Arc::clone(&entry.bytes)))
                    .collect()
            })
            .unwrap_or_default()
    };
    if frames.is_empty() {
        return;
    }
    for (group_id, bytes) in frames {
        let admission = catchup_admission(state, &group_id, requester);
        let resolve_within = std::cmp::min(
            x0x::dm::PINNED_RESOLUTION_WAIT,
            CE_CATCHUP_EXCHANGE_TIMEOUT / 2,
        );
        let exchange = state.agent.send_direct_pinned_admitted(
            requester,
            bytes.as_slice(),
            &admission,
            resolve_within,
        );
        match tokio::time::timeout(CE_CATCHUP_EXCHANGE_TIMEOUT, exchange).await {
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

/// The guarded-egress admission of one catch-up frame (§3 L231). The
/// pre-phase holds the membership lock while it takes ADR 0107's serving
/// check, the D60 machine/binding check and the capability gate; the seam
/// re-takes the serving check synchronously before the write.
fn catchup_admission(
    state: &Arc<AppState>,
    group_id: &str,
    requester: &AgentId,
) -> x0x::dm::ArtifactAdmission {
    use super::super as ng;
    let state = Arc::clone(state);
    let group_id = group_id.to_string();
    let requester = *requester;
    Arc::new(move || {
        let state = Arc::clone(&state);
        let group_id = group_id.clone();
        Box::pin(async move {
            let requester_hex = hex::encode(requester.as_bytes());
            let lock = ng::group_membership_lock_for_known_group(&state, &group_id).await?;
            let evidence = {
                let _membership_guard = lock.lock().await;
                let evidence = ng::join_artifact_serving_check(&state, &group_id, &requester_hex)
                    .await
                    .ok()?;
                let supported = state.agent.capability_store().verified_registry_supports(
                    &requester,
                    x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
                );
                if supported != Some(true) || !write_allowed(&state, &requester).await {
                    return None;
                }
                evidence
            };
            let seam: x0x::dm::SeamAdmission = Box::new(move || {
                ng::join_artifact_seam_refusal(&state, &group_id, &requester_hex, evidence)
                    .is_none()
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
    state.revocation_evictions.inner.lock().await.ce.remember(
        &body.stable_group_id,
        body.next_revision,
        Arc::new(payload.to_vec()),
    );
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
            ce_state.remember("g", revision, Arc::new(vec![1]));
            ce_state.remember("g", revision, Arc::new(vec![2]));
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
}
