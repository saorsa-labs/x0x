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
//! - **GSS** ([`commit_gss`], #1508 review P1). A GSS self-leave changes
//!   the roster and not the secret, so the leaver keeps the key. Its
//!   "retained leaf" is the current secret
//!   ([`ce::gss_secret_retained`]). S4 commits the GSS form (one
//!   rotation, `next_secret_epoch`) through the same hold, §5 order,
//!   delivery and restart rules, and seals the new secret to each
//!   remaining Active member in the existing `SecureShareDelivered`
//!   envelope (D60 guarded egress). A receiver installs the frame, then
//!   takes the secret from its share.
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
//!   and a completion writes only over its own token. A successful write
//!   is `Sent`, not delivered (§3 "survivor convergence, not a transport
//!   ACK, proves delivery"): the recipient is asked for its head and sent
//!   the frame again on each round until its verified catch-up answer
//!   names the result head ([`note_survivor_head`]). Only then is it
//!   `Converged`, and only a delivery whose recipients all converged ends.
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
//! - **Replay evidence** (§4 catch-up across restart). An authored frame
//!   stays in its `.evs` row after completion (the existing
//!   `outgoing_event` field), for the newest
//!   [`x0x::groups::eviction::MAX_REPLAY_FRAMES_PER_GROUP`] completed rows
//!   of a group. A restart rebuilds the catch-up log from those rows
//!   ([`rebuild_catchup_log`]), so a survivor that missed the transition
//!   still catches up after the head moves and this node restarts.
//! - **Received frames** (#1508 review, Codex P1). A receiver often holds
//!   no `.evs` row for the exclusion, so a row cannot keep its frame. The
//!   receiver writes the exact received frame durably before it installs
//!   the state that the frame carries. It uses the held log of the rebind
//!   and owner-recovery planes ([`super::rebind::replay_log`]), in its own
//!   `<stem>.celog` file. A restart loads that file, so a restarted
//!   survivor serves the frame to a lagging survivor while the author is
//!   offline. A frame above the loaded head (a crash between the write and
//!   the install) goes through the full receive checks again.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use super::rebind::replay_log;

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
    /// The carrier accepted the frame. This is not delivery (§3 "survivor
    /// convergence, not a transport ACK, proves delivery"): the recipient
    /// can stop before it installs the frame. Each later round asks the
    /// recipient for its head and sends the frame again, until
    /// [`Self::Converged`].
    Sent,
    /// The recipient reported the frame's result as its own head, on a
    /// verified, applied catch-up answer ([`note_survivor_head`]). Only
    /// this status ends the recipient's delivery.
    Converged,
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
    /// A resumed GSS frame: the sealed shares of its secret were not
    /// durable, so the first synced round seals them again (#1508 review
    /// P1).
    gss_shares_pending: bool,
    /// The new secret epoch of a GSS frame. Each send of the frame seals
    /// that secret to the recipient again, and the delivery runs while
    /// that secret is current (#1508 review P1).
    gss_epoch: Option<u64>,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
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
    /// Frames held for catch-up serving. The received frames are durable
    /// in the `.celog` ([`replay_log`]); the authored frames are durable in
    /// their `.evs` rows.
    log: replay_log::HeldLog<CE_LOG_PER_GROUP>,
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

    /// Hold a frame for catch-up serving (memory only; the caller made it
    /// durable).
    fn remember(
        &mut self,
        stable_group_id: &str,
        next_revision: u64,
        result_head: &str,
        bytes: Arc<Vec<u8>>,
        authored: bool,
    ) {
        self.log
            .remember(stable_group_id, next_revision, result_head, bytes, authored);
    }

    /// The frames held for any of `group_ids` above `from_revision`, oldest
    /// first, with their result heads.
    fn catchup_frames(
        &self,
        group_ids: &[String],
        from_revision: u64,
    ) -> Vec<(String, String, Arc<Vec<u8>>)> {
        self.log.catchup_frames(group_ids, from_revision)
    }

    /// The boot load (`load_persisted_obligations`) replaces the runtime
    /// state with this rebuilt one. A receipt can run before that load
    /// (#1508 review, Codex P1 boot race): it loaded the `.celog` and wrote
    /// its frame. Keep that live held log, and its load state, and add the
    /// frames rebuilt from the `.evs` rows to it. Otherwise a later frame
    /// write would rewrite the `.celog` without the earlier frames.
    pub(super) fn keep_live_held_log(&mut self, live: &mut CeState) {
        let rebuilt = std::mem::replace(&mut self.log, std::mem::take(&mut live.log));
        self.log.absorb(rebuilt);
    }
}

fn held(inner: &mut super::S4Inner) -> &mut replay_log::HeldLog<CE_LOG_PER_GROUP> {
    &mut inner.ce.log
}

/// Load the durable received frames once (#1508 review, Codex P1), before
/// this node serves catch-up, receives or retries a frame. A received
/// frame that a crash stopped before its install goes to the stash: the
/// next pass receives it again, with every receiver check. An authored
/// frame's delivery resumes from its `.evs` row, not from this file.
async fn ensure_restored(state: &AppState) {
    let restored = replay_log::ensure_restored(state, replay_log::CE_EXTENSION, held).await;
    if restored.received.is_empty() {
        return;
    }
    let mut inner = state.revocation_evictions.inner.lock().await;
    for bytes in restored.received {
        // The frame is self-authenticating; its actor is the sender.
        let Ok(frame) = ce::decode_frame(&bytes) else {
            continue;
        };
        if inner.ce.stash.len() >= CE_STASH_CAP {
            inner.ce.stash.remove(0);
        }
        inner.ce.stash.push(StashedFrame {
            sender: AgentId(frame.body.actor),
            bytes: bytes.to_vec(),
            at: Instant::now(),
        });
    }
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
            true,
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

// ─── Survivor convergence (§3) ─────────────────────────────────────────────

/// §3 "survivor convergence, not a transport ACK, proves delivery": a
/// delivery is complete only when every remaining recipient converged. A
/// recipient that left the survivors is dropped from the map by the round.
pub(super) fn all_converged(recipients: &BTreeMap<[u8; 32], RecipientDelivery>) -> bool {
    recipients
        .values()
        .all(|status| *status == RecipientDelivery::Converged)
}

/// Record that `sender` holds each head in `installed`: its reported head
/// and that head's ancestors on the local chain. A recipient of a delivery
/// whose result is in `installed` converged: it installed the transition.
/// A running attempt is replaced too, so its late completion (it writes
/// only over its own `InFlight` token) changes nothing.
pub(super) fn note_converged(
    recipients: &mut BTreeMap<[u8; 32], RecipientDelivery>,
    result_head: &str,
    sender: &[u8; 32],
    installed: &BTreeSet<String>,
) {
    if installed.contains(result_head) {
        if let Some(status) = recipients.get_mut(sender) {
            *status = RecipientDelivery::Converged;
        }
    }
}

/// §3 survivor convergence for the S4 deliveries of one group. The
/// catch-up response handler reports each verified, applied answer
/// through [`super::note_catchup_head`]; that answer names the
/// responder's own head; `installed` is that head and its ancestors on
/// the local chain. It is the convergence evidence for the crypto-only
/// exclusion, saved-removal, certificate-rebind and owner-recovery commit
/// deliveries of `stable_group_id` whose result the responder holds.
pub(super) fn note_survivor_head(
    inner: &mut super::S4Inner,
    stable_group_id: &str,
    sender: &[u8; 32],
    installed: &BTreeSet<String>,
) {
    for (key, delivery) in &mut inner.ce.deliveries {
        if key.stable_group_id == stable_group_id {
            note_converged(
                &mut delivery.recipients,
                &delivery.result_head,
                sender,
                installed,
            );
        }
    }
    super::removal_delivery::note_survivor_head(
        &mut inner.removals,
        stable_group_id,
        sender,
        installed,
    );
    super::rebind::note_survivor_head(&mut inner.rebind, stable_group_id, sender, installed);
    super::owner_recovery::note_survivor_head(&mut inner.orc, stable_group_id, sender, installed);
}

/// Ask each of `peers` for a catch-up page of `group_id`, on the existing
/// request path, detached (an offline peer must not hold the worker).
/// The answer reports the peer's head ([`note_survivor_head`]).
pub(super) fn ask_heads(state: &Arc<AppState>, group_id: &str, peers: Vec<AgentId>) {
    for peer in peers {
        let task_state = Arc::clone(state);
        let group_id = group_id.to_string();
        let _spawned = state.spawn_detached(async move {
            super::super::request_treekem_catchup_page(&task_state, &group_id, &peer).await;
        });
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
    // ADR 0110 §2 (#1508 review P1): the one locked S4 re-check, before
    // this seal touches the tree: the target's own open row and current
    // evaluation, head synced, this node still designated or past that
    // row's fallback time, intake durable. A self-leaver or a revoked
    // target is S4 work, so with no row yet it waits for the pass to open
    // one. A Removed seat that is neither (an earlier binary's removal
    // without a rekey) has no S4 obligation; the rekey pass's own checks
    // decide. The caller holds the membership lock, so no roster change
    // lands before the seal, and the TreeKEM lock, so it gives the epoch.
    let s4_target = super::s4_row_open(state, &key).await
        || info
            .members_v2
            .get(leaver_hex)
            .is_some_and(|member| member.removed_by.as_deref() == Some(member.agent_id.as_str()))
        || state
            .agent
            .revocation_set()
            .read()
            .await
            .is_agent_revoked(&target);
    let mode = super::SealMode::SelfLeaveRekey {
        tree_epoch: tree.epoch(),
    };
    if s4_target
        && super::s4_seal_recheck_locked(state, group_key, &key, mode)
            .await
            .is_some()
    {
        return SelfLeaveRekeyStep::Deferred;
    }
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
    // The target's attested `MemberJoined` stays cached: it is the leaf
    // evidence a survivor that holds only the committed hash asks for
    // before it can prove this exclusion (#1508 review P1). It never
    // refills the Removed seat (#205); it serves and installs only on a
    // hash match.
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

/// Whether `group_key` is a GSS `MlsEncrypted` group (#1508 review P1).
pub(super) async fn gss_group(state: &AppState, group_key: &str) -> bool {
    state
        .named_groups
        .read()
        .await
        .get(group_key)
        .is_some_and(ce::is_gss_encrypted)
}

/// Commit the GSS crypto-only exclusion of an already-Removed target that
/// still holds the current secret (#1508 review P1; ADR 0110 §3 L217, §4).
/// S4 calls it for a `SelfLeaveRekey` action that the designation, the
/// durable intake and the head round allow. It takes the membership lock
/// and re-checks the head, the retained secret and the D76 hold under it.
///
/// The §5 order is the TreeKEM one: the exact frame goes into a prepared
/// `.evjournal` and the `.evs` row first; then the rotated group record is
/// persisted; then the row moves to `committed_delivery_pending`. The new
/// secret goes to each remaining Active member in a sealed
/// `SecureShareDelivered` envelope under the D60 guarded egress, and the
/// frame under the same guarded, capability-gated delivery.
pub(super) async fn commit_gss(state: &Arc<AppState>, key: &EvictionKey, group_key: &str) {
    use super::super as ng;
    let local = *state.agent.agent_id().as_bytes();
    let target_hex = hex::encode(key.target);
    let membership_lock = ng::group_membership_lock(state, group_key).await;
    let _membership_guard = membership_lock.lock().await;
    // §2 (#1508 review P1): re-read the head and the evidence under the
    // lock, just before the seal.
    if super::s4_seal_recheck_locked(state, group_key, key, super::SealMode::S4Work)
        .await
        .is_some()
    {
        return;
    }
    let Some(info) = state.named_groups.read().await.get(group_key).cloned() else {
        return;
    };
    if info.stable_group_id() != key.stable_group_id
        || info.fork_quarantine.is_some()
        // Open work rotates unless a rotation already excluded the target:
        // trimmed history is not that proof (#1508 review, Codex P1).
        || ce::gss_secret_excluded(&info, &target_hex)
        || ng::self_leave_rekey_batch_held()
        || ng::self_leave_rekey_fence_open(group_key)
        || ng::self_leave_rekey_fence_open(info.stable_group_id())
    {
        return;
    }
    let hold = holders(state, &info, &local, &key.target);
    let held = !hold.is_empty();
    super::note_receiver_upgrade_hold(state, key, hold).await;
    if held {
        return;
    }
    let Some(removal_proof) = ce::removal_proof_for(&info, &target_hex) else {
        return;
    };
    let current_epoch = ce::committed_secret_epoch(&info);
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.secret_epoch = current_epoch;
    let (_, next_secret_epoch) = next.rotate_shared_secret();
    let signing_kp = state.agent.identity().agent_keypair();
    let commit = match ng::seal_commit_owner_certified(
        state,
        &mut next,
        signing_kp,
        ng::now_millis_u64(),
    )
    .await
    {
        Ok(commit) => commit,
        Err(error) => {
            tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: GSS crypto-only exclusion deferred: seal failed: {error}");
            return;
        }
    };
    ng::quiesce_member_join_egress(state, group_key, &target_hex).await;
    // Re-check under the membership lock, after the awaits above.
    if state
        .named_groups
        .read()
        .await
        .get(group_key)
        .map(|stored| stored.state_hash.as_str())
        != Some(info.state_hash.as_str())
    {
        return;
    }
    let body = ce::CryptoExclusionBodyV1 {
        stable_group_id: info.stable_group_id().to_string(),
        actor: local,
        target: key.target,
        prior_head: info.state_hash.clone(),
        prior_revision: info.state_revision,
        next_revision: commit.revision,
        roster_revision: next.roster_revision,
        removal_proof_hash: removal_proof,
        crypto: ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch },
        commit: ce::CommitHeaderV1::from(&commit),
    };
    // The author runs the receivers' L4 rule on its own frame first.
    if let Err(refusal) = ce::validate_against_parent(&body, &info, current_epoch, |_| false) {
        tracing::warn!(group_id = %LogHexId::group(group_key), reason = refusal.as_str(), "ADR 0110 S4: GSS crypto-only exclusion self-check failed");
        return;
    }
    let Some(bytes) = ce::sign(body, signing_kp)
        .ok()
        .and_then(|frame| ce::encode_frame(&frame).ok())
        .filter(|bytes| bytes.len() <= x0x::dm::MAX_PAYLOAD_BYTES)
    else {
        return;
    };
    // §5: fsync the prepared journal with the exact outgoing frame first.
    let mut txid = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut txid);
    let journal = EvJournalV1 {
        txid,
        stable_group_id: info.stable_group_id().to_string(),
        target: key.target,
        parent_head: info.state_hash.clone(),
        next_revision: commit.revision,
        result_epoch: Some(next_secret_epoch),
        evidence: vec![removal_proof],
        outgoing_event: bytes.clone(),
        result_head: Some(commit.state_hash.clone()),
    };
    let incarnation = ce::seat_incarnation(&info, &target_hex);
    if !super::prepare_crypto_exclusion(state, key, &journal, incarnation).await {
        return;
    }
    // The rotated group record. A rename without the directory fsync has
    // installed the epoch, as in the TreeKEM path; the guarded egress holds
    // the frame until the re-save is durable (§5).
    if !matches!(
        ng::persist_named_group_info(state, group_key, next.clone()).await,
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
    ) {
        super::abandon_crypto_exclusion(state, key).await;
        tracing::error!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: GSS crypto-only exclusion deferred: persist failed before the epoch was installed");
        return;
    }
    ng::purge_join_artifacts_if_ineligible(state, group_key, &target_hex).await;
    remove_legacy_mls_member(state, group_key, AgentId(key.target)).await;
    let recipients = survivors(&next, &local, &key.target);
    super::committed_crypto_exclusion(
        state,
        key,
        &commit.state_hash,
        next_secret_epoch,
        commit.revision,
        bytes,
        recipients,
    )
    .await;
    spawn_gss_shares(state, &next, &key.target);
    tracing::info!(
        group_id = %LogHexId::group(group_key),
        target = %LogHexId::agent(&target_hex),
        secret_epoch = next_secret_epoch,
        "ADR 0110 S4: GSS crypto-only exclusion committed"
    );
    let task_state = Arc::clone(state);
    let card_key = group_key.to_string();
    let _spawned = state.spawn_detached(async move {
        ng::maybe_publish_group_card_after_state_change(&task_state, &card_key).await;
        drive_deliveries(&task_state).await;
    });
}

/// Seal `info`'s current secret to each remaining Active member other
/// than this node and `target`, each as a D60 guarded class-K delivery.
fn spawn_gss_shares(state: &Arc<AppState>, info: &GroupInfo, target: &[u8; 32]) {
    let local = *state.agent.agent_id().as_bytes();
    for member in info.active_members() {
        if agent_bytes(&member.agent_id).is_some_and(|id| id != local && id != *target) {
            spawn_gss_share_to(state, info, &member.agent_id);
        }
    }
}

/// Seal `info`'s current secret to the Active member `recipient_hex`. The
/// D60 verdict re-checks its eligibility and the epoch at each write. A
/// member without a roster KEM key cannot get a share; it is logged and
/// skipped, as in the ban path.
fn spawn_gss_share_to(state: &Arc<AppState>, info: &GroupInfo, recipient_hex: &str) {
    use super::super as ng;
    let Some(secret) = info
        .shared_secret
        .as_deref()
        .and_then(|secret| <[u8; 32]>::try_from(secret).ok())
    else {
        return;
    };
    let Some(member) = info
        .active_members()
        .find(|member| member.agent_id == recipient_hex)
    else {
        return;
    };
    let Some(kem) = member.kem_public_key_b64.as_deref() else {
        tracing::warn!(recipient = %LogHexId::agent(recipient_hex), "ADR 0110 S4: no KEM key on record for a survivor; cannot seal the GSS share");
        return;
    };
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    match ng::build_secure_share_event(
        info.stable_group_id(),
        recipient_hex,
        kem,
        &local_hex,
        &secret,
        info.secret_epoch,
    ) {
        Ok(event) => {
            ng::spawn_secure_share_delivery(state, &event);
        }
        Err(_) => {
            tracing::warn!(recipient = %LogHexId::agent(recipient_hex), "ADR 0110 S4: the GSS share could not be sealed");
        }
    }
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
        true,
    );
    let gss_epoch = ce::decode_frame(&bytes)
        .ok()
        .and_then(|frame| match frame.body.crypto {
            ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } => Some(next_secret_epoch),
            ce::CryptoExclusionCryptoV1::TreeKem { .. } => None,
        });
    let gss_shares_pending = resumed && gss_epoch.is_some();
    ce_state.deliveries.insert(
        key.clone(),
        CeDelivery {
            bytes,
            result_head: result_head.to_string(),
            next_revision,
            resumed,
            gss_shares_pending,
            gss_epoch,
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
        let inner = runtime.inner.lock().await;
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
        // The new secret of a GSS frame, while it is still the current one.
        let gss_current = delivery.gss_epoch.filter(|epoch| {
            info.secret_epoch == *epoch && ce::committed_secret_epoch(&info) == *epoch
        });
        if info.state_hash != delivery.result_head {
            // A GSS survivor installs the frame only with its share, so a
            // later commit that kept the secret does not end the delivery:
            // that survivor still needs the share (#1508 review P1).
            let on_chain = info
                .commit_log
                .iter()
                .any(|retained| retained.commit.state_hash == delivery.result_head);
            if gss_current.is_none() || !on_chain {
                // The head moved past the exclusion: never resend old
                // crypto material after an epoch change. Stranded members
                // recover by catch-up (the frame stays in the catch-up log
                // and the row).
                runtime.inner.lock().await.ce.deliveries.remove(&key);
                continue;
            }
        }
        if delivery.gss_shares_pending {
            spawn_gss_shares(state, &info, &key.target);
            if let Some(stored) = runtime.inner.lock().await.ce.deliveries.get_mut(&key) {
                stored.gss_shares_pending = false;
            }
        }
        let active: BTreeSet<[u8; 32]> =
            survivors(&info, &local, &key.target).into_iter().collect();
        let mut updates: Vec<RoundUpdate> = Vec::new();
        let mut refreshes: Vec<AgentId> = Vec::new();
        let mut head_asks: Vec<AgentId> = Vec::new();
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
                RecipientDelivery::Converged | RecipientDelivery::InFlight(_)
            ) {
                continue;
            }
            let agent = AgentId(*recipient);
            // §3: a written frame is not a delivered one. Ask the
            // recipient for its head (its convergence evidence) and send
            // the frame again, admitted afresh, until it converges.
            if *status == RecipientDelivery::Sent {
                head_asks.push(agent);
            }
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
            if all_converged(&stored.recipients) {
                inner.ce.deliveries.remove(&key);
                inner.dirty = true;
            }
            started
        };
        ask_heads(state, &key.stable_group_id, head_asks);
        for (recipient, attempt) in started {
            // §3 (#1508 review P1): a GSS survivor installs the frame only
            // with its new secret, so every send seals that secret again.
            if gss_current.is_some() {
                spawn_gss_share_to(state, &info, &hex::encode(recipient));
            }
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
            // The in-process stand-in reports an admitted exchange with its
            // marker error (test builds only), as for the class-K shares.
            #[cfg(test)]
            Ok(Err(error)) if error.to_string().contains(x0x::dm::PINNED_STANDIN_ADMITTED) => {
                RecipientDelivery::Sent
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
    /// A saved removal (ADR 0110 §3): the frame's result is on this node's
    /// verified chain and no epoch change followed it, so the current head
    /// commits to the result's security binding. A later roster-only
    /// commit (a rename) keeps the delivery; a later rekey ends it.
    OnChainAtEpoch(String),
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
        HeadRule::OnChainAtEpoch(head) => {
            info.state_hash == *head
                || info.commit_log.iter().any(|retained| {
                    retained.commit.state_hash == *head
                        && retained.commit.security_binding == info.security_binding
                })
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
    ensure_restored(state).await;
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
    let mut gss_groups = BTreeSet::new();
    for (group_id, result_head, bytes) in frames {
        if ce::decode_frame(&bytes)
            .is_ok_and(|frame| matches!(frame.body.crypto, ce::CryptoExclusionCryptoV1::Gss { .. }))
        {
            gss_groups.insert(group_id.clone());
        }
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
    // #1508 review P1: a GSS frame moves the requester's epoch without the
    // secret; an admin also seals its current secret to the requester.
    let requester_hex = hex::encode(requester.as_bytes());
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    for group_id in gss_groups {
        let info = {
            let groups = state.named_groups.read().await;
            crate::server::resolve_group_entry_locked(&groups, &group_id)
                .map(|(_, info)| info.clone())
        };
        if let Some(info) = info.filter(|info| {
            info.caller_role(&local_hex)
                .is_some_and(|role| role.at_least(x0x::groups::GroupRole::Admin))
        }) {
            spawn_gss_share_to(state, &info, &requester_hex);
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
///
/// ADR 0110 §5, "only then publish": the pre-phase also confirms that no
/// roster replacement waits for its directory fsync, and the seam
/// re-checks it. A commit whose roster write returned `ReplacedNotDurable`
/// keeps its frame and delivery, but no frame leaves until the re-save is
/// `Durable`. This is the one rule for every S4 publishing path (rebind,
/// owner recovery, crypto exclusion and saved removals, live and
/// catch-up), so a crash cannot restore the old roster after a peer took
/// the new commit (#1508 rc12 Codex P1).
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
            if !ng::roster_durable_for_publication(&state).await {
                return None;
            }
            let recipient_hex = hex::encode(recipient.as_bytes());
            let lock = ng::group_membership_lock_for_known_group(&state, &group_id).await?;
            let evidence = {
                let _membership_guard = lock.lock().await;
                let evidence = ng::join_artifact_member_check(&state, &group_id, &recipient_hex)
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
                if !ng::roster_durable_at_seam(&state) {
                    return false;
                }
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
    /// A valid GSS frame whose new secret has not arrived in its sealed
    /// share. Nothing was installed; the frame is kept and installs with
    /// the share (#1508 review P1).
    WaitingForShare,
    /// The group is unknown here, or the node is not a survivor.
    NotApplicable,
}

impl ReceiveOutcome {
    /// The frame stays in the stash for a later retry: this node is behind
    /// it, or a local fault stopped the install.
    pub(in crate::server) fn is_retained(self) -> bool {
        matches!(
            self,
            Self::Behind | Self::LocalFailure | Self::WaitingForShare
        )
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
    ensure_restored(state).await;
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
    // The load runs first, so the frame write below keeps the frames that
    // a restart restored.
    ensure_restored(state).await;
    // #1508 review P1: the GSS form has no tree; its epoch is the secret
    // epoch the parent head commits to.
    let gss = match body.crypto {
        ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } => Some(next_secret_epoch),
        ce::CryptoExclusionCryptoV1::TreeKem { .. } => None,
    };
    let tree = if gss.is_some() {
        None
    } else {
        let map = state.treekem_groups.read().await;
        let Some(tree) = map
            .get(&group_key)
            .or_else(|| map.get(info.stable_group_id()))
            .cloned()
        else {
            return ReceiveOutcome::NotApplicable;
        };
        Some(tree)
    };
    let commit = body.commit.to_commit();
    let guard = match &tree {
        Some(tree) => Some(tree.lock().await),
        None => None,
    };
    let current_epoch = guard
        .as_ref()
        .map_or_else(|| ce::committed_secret_epoch(&info), |tree| tree.epoch());
    // §3 L231: re-read the revocation set under the membership lock,
    // immediately before the apply, so a revocation that landed since the
    // early check above also refuses the frame.
    // Set when the frame is a valid exclusion on a sibling branch.
    let mut sibling = false;
    let validated = {
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        let is_revoked = |actor: &[u8; 32]| set.is_agent_revoked(&AgentId(*actor));
        if set.is_agent_revoked(&sender) {
            Err(ce::CryptoExclusionRefusal::ActorIneligible)
        } else {
            match ce::validate_against_parent(&body, &info, current_epoch, is_revoked) {
                // #1508 r6 (Codex P1 A): a frame that does not chain from
                // this node's head is checked against its retained parent
                // before it can be fork evidence. A frame that fails there
                // is refused with that reason and records nothing; a frame
                // whose parent is not retained stays unvalidated.
                Err(ce::CryptoExclusionRefusal::HeadMismatch) => {
                    match validate_sibling(&body, &info, is_revoked) {
                        Ok(()) => {
                            sibling = true;
                            Err(ce::CryptoExclusionRefusal::HeadMismatch)
                        }
                        Err(refusal) => Err(refusal),
                    }
                }
                other => other,
            }
        }
    };
    if let Err(refusal) = validated {
        drop(guard);
        if sibling {
            // #1508 r6 (Codex P1 B): a valid competing child of a retained
            // parent contains the group on every record, the creator's
            // too. Live delivery already stops on the marker.
            super::rebind::install_sibling_evidence(state, &group_key, &info, &commit).await;
        }
        tracing::info!(
            group_id = %LogHexId::group(&group_key),
            reason = refusal.as_str(),
            "ADR 0110 S4: crypto-only exclusion refused"
        );
        return ReceiveOutcome::Refused(refusal);
    }
    // #1508 review (Codex P1): the exact received frame is durable before
    // the roster and crypto state it carries are installed, in a store
    // that needs no S4 row. A restarted receiver then serves it to a
    // survivor that missed it while the author is offline.
    let frame_bytes = Arc::new(payload.to_vec());
    let stable = body.stable_group_id.as_str();
    let at = (body.next_revision, body.commit.state_hash.as_str());
    let ext = replay_log::CE_EXTENSION;
    if !replay_log::write_received(state, ext, held, stable, at, &frame_bytes).await {
        return ReceiveOutcome::LocalFailure;
    }
    let Some(mut guard) = guard else {
        // There is no tree only for the GSS form.
        let outcome = match gss {
            Some(next_secret_epoch) => {
                install_gss(
                    state,
                    &group_key,
                    &info,
                    &body,
                    &commit,
                    next_secret_epoch,
                    frame_bytes,
                )
                .await
            }
            None => ReceiveOutcome::NotApplicable,
        };
        return unhold_unless_kept(state, stable, outcome).await;
    };
    let ce::CryptoExclusionCryptoV1::TreeKem {
        commit: treekem_commit,
        next_epoch,
        ..
    } = &body.crypto
    else {
        let refused = ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::CryptoPlaneUnsupported);
        return unhold_unless_kept(state, stable, refused).await;
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
            let refused = ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::BadSignature);
            return unhold_unless_kept(state, stable, refused).await;
        }
    };
    let target = AgentId(body.target);
    let Ok(rollback_snapshot) = guard.to_snapshot_bytes() else {
        return unhold_unless_kept(state, stable, ReceiveOutcome::NotApplicable).await;
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
        let refused = ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::EpochMismatch);
        return unhold_unless_kept(state, stable, refused).await;
    }
    // The cryptographic removal proof: the tree no longer holds the
    // target's committed leaf. The local leaf map alone is not proof; with
    // no evidence the frame stays pending (#1508 review P1).
    let leaf_present = ng::roster_treekem_leaf_presence(&guard, &info)
        .remove(&hex::encode(target.as_bytes()))
        .flatten();
    match leaf_present {
        Some(false) => {}
        Some(true) => {
            refuse(&mut guard, "crypto_exclusion_leaf_retained");
            let refused = ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::LeafMismatch);
            return unhold_unless_kept(state, stable, refused).await;
        }
        None => {
            // No KeyPackage here (a Welcome joiner holds only the hash):
            // ask for the evidence, keep the frame, retry (#1508 review P1).
            refuse(&mut guard, "crypto_exclusion_leaf_unproven");
            ng::request_missing_leaf_evidence(state, &group_key, &hex::encode(target.as_bytes()));
            return ReceiveOutcome::LocalFailure;
        }
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
            // (durable and in the stash) and try again.
            return ReceiveOutcome::LocalFailure;
        }
    }
    drop(guard);
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    // The target's cached `MemberJoined` stays: later survivors ask this
    // node for it (#1508 review P1).
    remember_installed(state, &body, frame_bytes).await;
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

/// Install a validated GSS frame (#1508 review P1). The caller holds the
/// group's membership lock. The chained commit moves the secret epoch and
/// its binding together; the secret itself comes in the sealed
/// `SecureShareDelivered` envelope, as for every GSS rotation.
///
/// The frame installs only when this node already holds the new secret
/// (#1508 review P1). The committer reads this node's head as proof that
/// the exclusion was delivered, so the head with the frame's result must
/// mean that the key is installed too. Until the share arrives the frame
/// waits, kept durable in the `.celog` and in the stash; the share
/// wakes the worker, which retries it.
async fn install_gss(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    body: &ce::CryptoExclusionBodyV1,
    commit: &x0x::groups::GroupStateCommit,
    next_secret_epoch: u64,
    frame_bytes: Arc<Vec<u8>>,
) -> ReceiveOutcome {
    use super::super as ng;
    if info.secret_epoch < next_secret_epoch || info.shared_secret.is_none() {
        tracing::info!(
            group_id = %LogHexId::group(group_key),
            secret_epoch = next_secret_epoch,
            "ADR 0110 S4: GSS crypto-only exclusion waits for its sealed share"
        );
        // The frame verified, and this node keeps the old secret, which the
        // excluded member holds: make no ciphertext until the share
        // installs. The hold is durable and has no time limit (#1508/#1533
        // rc13).
        ng::gss_share_hold::hold_exclusion(state, group_key, &info.state_hash, next_secret_epoch)
            .await;
        return ReceiveOutcome::WaitingForShare;
    }
    let roster_revision = body.roster_revision;
    let next = match ng::apply_stateful_event_with_evidence(
        state,
        group_key,
        info,
        commit,
        None,
        false,
        None,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            // The secret and its epoch came with the share (checked above).
            next.roster_revision = ng::adopt_roster_revision(next.roster_revision, roster_revision);
            next.security_binding = Some(ce::gss_binding(next_secret_epoch));
        },
    )
    .await
    {
        Ok(next) => next,
        Err(error) => {
            tracing::info!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: GSS crypto-only exclusion commit refused: {error}");
            return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::BadSignature);
        }
    };
    if !matches!(
        ng::persist_named_group_info(state, group_key, next.clone()).await,
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
    ) {
        // A local storage fault, not a sender defect: keep the frame.
        return ReceiveOutcome::LocalFailure;
    }
    remove_legacy_mls_member(state, group_key, AgentId(body.target)).await;
    ng::refresh_group_card_cache_from_info(state, group_key, &next).await;
    ng::purge_join_artifacts_if_ineligible(state, group_key, &hex::encode(body.target)).await;
    remember_installed(state, body, frame_bytes).await;
    tracing::info!(
        group_id = %LogHexId::group(group_key),
        secret_epoch = next_secret_epoch,
        "ADR 0110 S4: GSS crypto-only exclusion installed with its new secret"
    );
    ng::gss_share_hold::release_exclusions(state, group_key, next_secret_epoch).await;
    state.agent.s4_revocation_intake().request_reconcile();
    ReceiveOutcome::Applied
}

/// Keep an installed frame for catch-up serving. The `.celog` already
/// holds it (written before the install).
async fn remember_installed(
    state: &AppState,
    body: &ce::CryptoExclusionBodyV1,
    frame_bytes: Arc<Vec<u8>>,
) {
    state.revocation_evictions.inner.lock().await.ce.remember(
        &body.stable_group_id,
        body.next_revision,
        &body.commit.state_hash,
        frame_bytes,
        false,
    );
}

/// After the frame write: a frame that this node refused or cannot
/// install leaves the `.celog` again (written as memory holds the log).
/// A local fault keeps it, so the stash or the restart installs it later.
async fn unhold_unless_kept(
    state: &AppState,
    stable_group_id: &str,
    outcome: ReceiveOutcome,
) -> ReceiveOutcome {
    if !outcome.is_retained() {
        replay_log::rewrite_from_memory(state, replay_log::CE_EXTENSION, held, stable_group_id)
            .await;
    }
    outcome
}

/// The GSS plane's legacy local MLS view: the excluded agent is no longer
/// a recipient (as the ban path does).
async fn remove_legacy_mls_member(state: &AppState, group_key: &str, target: AgentId) {
    use super::super as ng;
    let removed = {
        let mut mls_groups = state.mls_groups.write().await;
        match mls_groups.get_mut(group_key) {
            Some(group) if group.is_member(&target) => group.remove_member(target).await.is_ok(),
            _ => false,
        }
    };
    if removed {
        ng::save_mls_groups(state).await;
    }
}

/// ADR 0110 §2 fork containment and §4 L249 (#1508 r6, Codex P1 A):
/// whether `body`, which [`ce::validate_against_parent`] refused with
/// `head_mismatch` on `current`, is a valid exclusion on a sibling branch
/// of `current`'s retained chain. Only such a frame is fork evidence.
///
/// The parent is the retained commit whose `state_hash` is the body's
/// `prior_head`, and `current` retains a different commit at the same
/// revision on that parent. The L4 checks then run against the parent's
/// retained roster and commit: the actor is not revoked, is not the
/// target, and is an Active admin there; the target is not Active there
/// and is Removed with the body's removal proof; the commit keeps the
/// parent's roster root, policy and metadata; and the epoch is the
/// parent's committed epoch + 1 with the exact security binding (the
/// committed leaf for the TreeKEM form).
///
/// The caller has already run [`ce::verify_signatures`].
fn validate_sibling(
    body: &ce::CryptoExclusionBodyV1,
    current: &GroupInfo,
    is_actor_revoked: impl Fn(&[u8; 32]) -> bool,
) -> Result<(), ce::CryptoExclusionRefusal> {
    use ce::CryptoExclusionRefusal as Refusal;
    use x0x::groups::{GroupMemberState, GroupRole};
    if body.stable_group_id != current.stable_group_id()
        || body.commit.group_id != current.stable_group_id()
    {
        return Err(Refusal::GroupMismatch);
    }
    if current.withdrawn || current.fork_quarantine.is_some() || body.commit.withdrawn {
        return Err(Refusal::GroupContained);
    }
    if body.commit.prev_state_hash.as_deref() != Some(body.prior_head.as_str()) {
        return Err(Refusal::HeadMismatch);
    }
    let Some(parent) = current
        .commit_log
        .iter()
        .find(|retained| retained.commit.state_hash == body.prior_head)
    else {
        return Err(Refusal::HeadMismatch);
    };
    if body.prior_revision != parent.commit.revision
        || body.next_revision != parent.commit.revision.saturating_add(1)
        || body.commit.revision != body.next_revision
    {
        return Err(Refusal::RevisionMismatch);
    }
    let sibling = current.commit_log.iter().any(|retained| {
        retained.commit.prev_state_hash.as_deref() == Some(body.prior_head.as_str())
            && retained.commit.revision == body.next_revision
            && retained.commit.state_hash != body.commit.state_hash
    });
    if !sibling {
        return Err(Refusal::HeadMismatch);
    }
    let actor_hex = hex::encode(body.actor);
    let target_hex = hex::encode(body.target);
    if body.actor == body.target
        || is_actor_revoked(&body.actor)
        || !parent.roster.get(&actor_hex).is_some_and(|snapshot| {
            snapshot.state == GroupMemberState::Active && snapshot.role.at_least(GroupRole::Admin)
        })
    {
        return Err(Refusal::ActorIneligible);
    }
    if parent
        .roster
        .get(&target_hex)
        .is_some_and(|snapshot| snapshot.state == GroupMemberState::Active)
    {
        return Err(Refusal::TargetNotRemoved);
    }
    let Some(proof) = ce::removal_proof_for(current, &target_hex) else {
        return Err(Refusal::TargetNotRemoved);
    };
    if proof != body.removal_proof_hash {
        return Err(Refusal::RemovalProofMismatch);
    }
    // Crypto only: the membership, policy and metadata are the parent's.
    if body.commit.roster_root != parent.commit.roster_root
        || body.commit.policy_hash != parent.commit.policy_hash
        || body.commit.public_meta_hash != parent.commit.public_meta_hash
    {
        return Err(Refusal::Malformed);
    }
    let parent_binding = parent
        .commit
        .security_binding
        .as_deref()
        .unwrap_or_default();
    let (parent_epoch, next_epoch, binding) = match &body.crypto {
        ce::CryptoExclusionCryptoV1::TreeKem {
            leaf_key_package_hash,
            commit,
            next_epoch,
        } => {
            if current.secure_plane != x0x::mls::SecureGroupPlane::TreeKem {
                return Err(Refusal::CryptoPlaneUnsupported);
            }
            let leaf = current
                .members_v2
                .get(&target_hex)
                .and_then(|member| member.treekem_key_package_hash.as_deref());
            if leaf != Some(leaf_key_package_hash.as_str()) {
                return Err(Refusal::LeafMismatch);
            }
            let parent_epoch = parent_binding
                .strip_prefix("treekem:epoch=")
                .and_then(|rest| rest.split(':').next())
                .and_then(|epoch| epoch.parse::<u64>().ok());
            (
                parent_epoch,
                *next_epoch,
                ce::treekem_binding(*next_epoch, commit),
            )
        }
        ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } => {
            if !ce::is_gss_encrypted(current) {
                return Err(Refusal::CryptoPlaneUnsupported);
            }
            let parent_epoch = parent_binding
                .strip_prefix("gss:epoch=")
                .and_then(|epoch| epoch.parse::<u64>().ok());
            (
                parent_epoch,
                *next_secret_epoch,
                ce::gss_binding(*next_secret_epoch),
            )
        }
    };
    if parent_epoch.map(|epoch| epoch.saturating_add(1)) != Some(next_epoch)
        || body.commit.security_binding.as_deref() != Some(binding.as_str())
    {
        return Err(Refusal::EpochMismatch);
    }
    Ok(())
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
        .catchup_frames(&[stable_group_id.to_string()], 0)
        .pop()
        .map(|(_, _, bytes)| bytes.to_vec())
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
            ce_state.remember("g", revision, "r", Arc::new(vec![1]), false);
            ce_state.remember("g", revision, "r", Arc::new(vec![2]), false);
        }
        let log = ce_state.log.len("g");
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

    #[test]
    fn catchup_frames_are_served_oldest_first() {
        let mut ce_state = CeState::default();
        ce_state.remember("g", 7, "r7", Arc::new(vec![7]), false);
        ce_state.remember("g", 5, "r5", Arc::new(vec![5]), false);
        ce_state.remember("g", 6, "r6", Arc::new(vec![6]), false);
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

    /// Only the per-group head round holds an S4 seal here, not the boot
    /// wait (ADR 0110 §2).
    fn zero_restart_wait(state: &mut Arc<AppState>) {
        super::super::zero_restart_wait_for_test(state);
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

    /// #1508 rc12 Codex P1 (ADR 0110 §5, "only then publish"): the roster
    /// write renames the file and the directory fsync fails
    /// (`ReplacedNotDurable`), then every re-save fails. No S4 frame
    /// leaves: the seam taken before the write refuses, and a fresh
    /// pre-phase refuses. Once a re-save is durable, the frame leaves.
    /// Before the fix both admitted the write, so a crash could restore the
    /// old roster after a peer took the new commit.
    #[tokio::test]
    async fn no_frame_leaves_before_the_roster_is_durable() -> Result<()> {
        use anyhow::Context as _;
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let survivor = AgentId([0x78; 32]);
        let group_id = "cd".repeat(16);
        let mut info = GroupInfo::new("cd".into(), String::new(), admin, group_id.clone());
        info.add_member(
            hex::encode(survivor.as_bytes()),
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
        let seam = admit(&state, &stable, &survivor, &rule)
            .await
            .context("an eligible recipient is admitted while the roster is durable")?;

        let fault =
            ng::set_save_fault(&state, ng::SaveFault::ReplacedNotDurableAfterWriteThenError);
        assert_eq!(
            ng::persist_named_group_info(&state, &group_id, info.clone()).await?,
            ng::AtomicWriteOutcome::ReplacedNotDurable
        );
        assert!(!seam(), "the seam refuses while the roster is not durable");
        assert!(
            admit(&state, &stable, &survivor, &rule).await.is_none(),
            "the pre-phase refuses while every re-save fails"
        );

        drop(fault);
        let seam = admit(&state, &stable, &survivor, &rule)
            .await
            .context("the pre-phase re-save is durable")?;
        assert!(seam(), "the frame leaves once the roster is durable");
        Ok(())
    }

    /// #1357 review P1: crypto-only catch-up survives a restart. The
    /// exclusion commits while a survivor is offline, the head moves on (so
    /// live delivery stops and the row completes), and the committer
    /// restarts. The rebuilt catch-up log still holds the frame, and the
    /// survivor that missed the transition installs it.
    #[tokio::test]
    async fn survivor_catches_up_after_head_move_and_committer_restart() -> Result<()> {
        let (mut state, dir) = ng::tests::secure_endpoint_test_state().await?;
        zero_restart_wait(&mut state);
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
        // ADR 0110 §2 (#1508 review P1): the exclusion seals from the S4 row.
        run_worker(&state).await;
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

    /// #1508 review P1: a non-admin survivor that joined through a Welcome
    /// holds only the leaver's committed KeyPackage hash, so it cannot
    /// prove the exclusion from its tree. It keeps the frame, asks for the
    /// evidence through the member-keyed catch-up (red before: it only
    /// retried and stayed on the old epoch), and installs the frame on the
    /// retry once the KeyPackage arrives.
    #[tokio::test]
    async fn a_hash_only_survivor_asks_for_the_leavers_key_package() -> Result<()> {
        let (mut state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        zero_restart_wait(&mut state);
        state
            .named_group_test_recorders
            .metadata_publish_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let admin = state.agent.agent_id();
        let admin_hex = hex::encode(admin.as_bytes());
        let group_id = "c7".repeat(16);
        let group_id_bytes = hex::decode(&group_id)?;
        let seed = ng::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let mut admin_group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), admin, &seed)?;
        let leaver_kp = x0x::identity::AgentKeypair::generate()?;
        let leaver = leaver_kp.agent_id();
        let leaver_hex = hex::encode(leaver.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(leaver, &[9u8; 32])?;
        let leaver_kp_bytes = prepared.key_package_bytes().to_vec();
        admin_group.add_member(leaver, &leaver_kp_bytes)?;
        // The survivor (the replica's own agent) joins after the leaver.
        let (replica, _replica_dir) = ng::tests::secure_endpoint_test_state().await?;
        let survivor = replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        // The daemon's own seed: a rollback restores the tree with it.
        let survivor_seed = ng::agent_treekem_seed(replica.agent.as_ref(), &group_id_bytes);
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(survivor, &survivor_seed)?;
        let survivor_kp_bytes = prepared.key_package_bytes().to_vec();
        let added = admin_group.add_member(survivor, &survivor_kp_bytes)?;
        let survivor_tree = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
        assert!(
            !survivor_tree.tracks_member(&leaver),
            "premise: the Welcome joiner's leaf map lacks the leaver"
        );
        let epoch = admin_group.epoch();

        let mut info = GroupInfo::new(
            "ce-hash-only".into(),
            String::new(),
            admin,
            group_id.clone(),
        );
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
        // ADR 0110 §2 (#1508 review P1): the exclusion seals from the S4 row.
        run_worker(&state).await;
        let frame = latest_frame_for_test(&state, &stable)
            .await
            .expect("the crypto-only exclusion committed");
        let result_head = ce::decode_frame(&frame)
            .map(|frame| frame.body.commit.state_hash)
            .expect("frame");

        // The survivor's roster commits the leaver's hash, not its bytes.
        let mut hash_only = pre_leave;
        if let Some(member) = hash_only.members_v2.get_mut(&leaver_hex) {
            member.treekem_key_package_b64 = None;
        }
        replica
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), hash_only);
        replica.treekem_groups.write().await.insert(
            group_id.clone(),
            Arc::new(tokio::sync::Mutex::new(survivor_tree)),
        );
        let replica_leave =
            ng::apply_named_group_metadata_event(&replica, leave, leaver, true, None).await;
        assert!(replica_leave.accepted, "{replica_leave:?}");
        replica.treekem_catchup_throttle.write().await.clear();

        assert_eq!(
            receive(&replica, admin, &frame).await,
            ReceiveOutcome::LocalFailure,
            "no evidence is no proof: the frame stays pending"
        );
        let asked = format!("{group_id}:member:{leaver_hex}:{admin_hex}");
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while !replica
            .treekem_catchup_throttle
            .read()
            .await
            .contains_key(&asked)
        {
            assert!(
                Instant::now() < deadline,
                "the survivor must ask the leaver's inviter for the KeyPackage"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_ne!(
            head_of(&replica, &group_id).await,
            Some(result_head.clone())
        );

        // The KeyPackage arrives (as the catch-up answer installs it); the
        // retry proves the exclusion from the tree and installs it.
        {
            let mut groups = replica.named_groups.write().await;
            let stored = groups.get_mut(&group_id).expect("group");
            stored.set_member_treekem_key_package(
                &leaver_hex,
                base64::engine::general_purpose::STANDARD.encode(&leaver_kp_bytes),
            );
        }
        assert_eq!(
            receive(&replica, admin, &frame).await,
            ReceiveOutcome::Applied,
            "with the evidence the survivor installs the exclusion"
        );
        assert_eq!(head_of(&replica, &group_id).await, Some(result_head));
        Ok(())
    }

    /// A GSS `MlsEncrypted` group on the committer `state` (the only admin)
    /// with a leaver and the survivor `replica`, and the leaver's signed
    /// self-leave. The roster that seats both is a retained commit at
    /// secret epoch 0.
    struct GssLeave {
        state: Arc<AppState>,
        dir: tempfile::TempDir,
        replica: Arc<AppState>,
        _replica_dir: tempfile::TempDir,
        group_id: String,
        stable: String,
        leaver: AgentId,
        leaver_kp: x0x::identity::AgentKeypair,
        leave: ng::NamedGroupMetadataEvent,
        old_secret: Vec<u8>,
    }

    async fn gss_leave_fixture() -> Result<GssLeave> {
        let (mut state, dir) = ng::tests::secure_endpoint_test_state().await?;
        // Only the per-group head round holds a seal, not the boot wait.
        anyhow::Context::context(
            Arc::get_mut(&mut state),
            "the fresh test state is not shared yet",
        )?
        .revocation_evictions = super::super::S4Runtime::new(x0x::groups::eviction::S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..x0x::groups::eviction::S4Timing::default()
        });
        state
            .named_group_test_recorders
            .metadata_publish_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (replica, replica_dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let admin_hex = hex::encode(admin.as_bytes());
        let survivor_hex = hex::encode(replica.agent.agent_id().as_bytes());
        let survivor_kem = base64::engine::general_purpose::STANDARD
            .encode(&replica.agent_kem_keypair.public_bytes);
        let leaver_kp = x0x::identity::AgentKeypair::generate()?;
        let leaver = leaver_kp.agent_id();
        let leaver_hex = hex::encode(leaver.as_bytes());
        let group_id = "c9".repeat(16);
        let mut info = GroupInfo::new("ce-gss".into(), String::new(), admin, group_id.clone());
        assert_eq!(info.secure_plane, x0x::mls::SecureGroupPlane::Gss);
        info.add_member(
            leaver_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.add_member_with_kem(
            survivor_hex,
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
            Some(survivor_kem),
        );
        info.seal_commit(state.agent.identity().agent_keypair(), ng::now_millis_u64())?;
        let old_secret = info.shared_secret.clone().expect("GSS secret");
        let stable = info.stable_group_id().to_string();
        for target in [&state, &replica] {
            target
                .named_groups
                .write()
                .await
                .insert(group_id.clone(), info.clone());
        }
        let mut leaving = info.clone();
        leaving.roster_revision = leaving.roster_revision.saturating_add(1);
        let revision = leaving.roster_revision;
        leaving.remove_member(&leaver_hex, Some(leaver_hex.clone()));
        let leave_commit = leaving.seal_commit(&leaver_kp, ng::now_millis_u64())?;
        let leave = ng::NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision,
            actor: leaver_hex.clone(),
            agent_id: leaver_hex,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            commit: Some(leave_commit),
        };
        Ok(GssLeave {
            state,
            dir,
            replica,
            _replica_dir: replica_dir,
            group_id,
            stable,
            leaver,
            leaver_kp,
            leave,
            old_secret,
        })
    }

    /// Run the S4 worker steps of one tick until the row commits.
    async fn run_worker(state: &Arc<AppState>) {
        super::super::run_worker_steps_for_test(state).await;
    }

    /// #1508 review P1: a GSS self-leave changes the roster and not the
    /// secret, so the leaver keeps the key for later ciphertext. S4 must
    /// open self-leave work for it, the designated admin must author the
    /// GSS `CryptoExclusionV1` (one rotation), seal the new secret to the
    /// survivor, and the survivor must install the frame and then the
    /// share. The leaver's old secret cannot derive the new message key.
    #[tokio::test]
    async fn gss_self_leave_rotates_the_secret_and_the_survivor_installs_it() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "the leave must apply: {applied:?}");
        run_worker(&fx.state).await;

        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .expect("the GSS crypto-only exclusion committed");
        let decoded = ce::decode_frame(&frame).expect("frame");
        assert_eq!(
            decoded.body.crypto,
            ce::CryptoExclusionCryptoV1::Gss {
                next_secret_epoch: 1
            }
        );
        let committed = fx
            .state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .expect("group");
        assert_eq!(committed.state_hash, decoded.body.commit.state_hash);
        assert_eq!(committed.secret_epoch, 1);
        let new_secret = committed.shared_secret.clone().expect("new secret");
        assert_ne!(new_secret, fx.old_secret, "the secret rotated");
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            let row = inner.store.get(&key).expect("S4 self-leave row");
            assert_eq!(row.phase, Phase::CommittedDeliveryPending);
            assert_eq!(row.outgoing_event.as_deref(), Some(frame.as_slice()));
        }
        // The new secret is sealed to the survivor only.
        let survivor_hex = hex::encode(fx.replica.agent.agent_id().as_bytes());
        let shares: Vec<(String, String, Vec<u8>)> = fx
            .state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
            .map(|scheduled| scheduled.clone())
            .unwrap_or_default();
        let share: ng::NamedGroupMetadataEvent = shares
            .iter()
            .find(|(_, recipient, _)| *recipient == survivor_hex)
            .and_then(|(_, _, payload)| serde_json::from_slice(payload).ok())
            .expect("a share for the survivor");
        assert!(
            shares
                .iter()
                .all(|(_, recipient, _)| *recipient == survivor_hex),
            "no share for the leaver or the committer"
        );

        // The survivor takes the leave, the frame, then the share.
        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        let admin = fx.state.agent.agent_id();
        // #1508 review P1: the frame installs only with its new secret.
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::WaitingForShare
        );
        // Success of a share is observed in the stored state.
        let _ = ng::apply_named_group_metadata_event(&fx.replica, share, admin, true, None).await;
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied
        );
        let survivor = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .expect("group");
        assert_eq!(survivor.state_hash, committed.state_hash);
        assert_eq!(survivor.secret_epoch, 1);
        assert_eq!(
            survivor.shared_secret.as_deref(),
            Some(new_secret.as_slice()),
            "the survivor took the new secret from its share"
        );
        assert_eq!(
            survivor.secure_message_key(),
            committed.secure_message_key()
        );
        // The leaver holds only the old secret.
        assert_ne!(
            Some(GroupInfo::derive_message_key(&fx.old_secret, 1, &fx.stable)),
            committed.secure_message_key(),
            "the old secret must not derive the new message key"
        );

        // Completion: the rotation excludes the leaver, so once delivery
        // ends the row completes from the chain and no new work opens.
        fx.state.revocation_evictions.inner.lock().await.ce = CeState::default();
        super::super::revocation_eviction_pass(&fx.state).await;
        let inner = fx.state.revocation_evictions.inner.lock().await;
        assert_eq!(
            inner.store.get(&key).map(|row| row.phase),
            Some(Phase::Complete)
        );
        Ok(())
    }

    /// The delivery status of `recipient` in the live delivery of `key`.
    async fn delivery_status(
        state: &AppState,
        key: &EvictionKey,
        recipient: &AgentId,
    ) -> Option<RecipientDelivery> {
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .ce
            .deliveries
            .get(key)
            .and_then(|delivery| delivery.recipients.get(recipient.as_bytes()).copied())
    }

    /// Run one real delivery round and wait until no send of it runs.
    async fn delivery_round(state: &Arc<AppState>, key: &EvictionKey, recipient: &AgentId) {
        drive_deliveries(state).await;
        for _ in 0..200 {
            if !matches!(
                delivery_status(state, key, recipient).await,
                Some(RecipientDelivery::InFlight(_))
            ) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// #1508 r7 F5 (Codex P1), ADR 0110 §3: "survivor convergence, not a
    /// transport ACK, proves delivery". The frame write to a survivor
    /// succeeds, and the survivor stops before it installs the frame (a
    /// crash). The delivery stays tracked and is sent again on the resend
    /// interval, and the row stays `committed_delivery_pending`. Only the
    /// survivor's own head report at the exclusion's result (the call of
    /// the catch-up response handler, [`super::super::note_catchup_head`])
    /// ends its delivery; then the row completes.
    #[tokio::test]
    async fn a_written_frame_without_survivor_convergence_keeps_the_delivery() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        // The survivor advertises the bit before the commit: the commit's
        // own detached delivery round may run first, and it must write.
        advertise_crypto_exclusion(&fx.state, fx.replica.agent.agent_id());
        fx.state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        run_worker(&fx.state).await;
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .expect("the GSS crypto-only exclusion committed");
        let result_head = ce::decode_frame(&frame)
            .expect("frame")
            .body
            .commit
            .state_hash;
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let phase = |state: Arc<AppState>| {
            let key = key.clone();
            async move {
                let inner = state.revocation_evictions.inner.lock().await;
                inner.store.get(&key).map(|row| row.phase)
            }
        };

        // The first round (the commit's own, or this one) writes the
        // frame; the carrier takes it.
        delivery_round(&fx.state, &key, &survivor).await;
        assert_eq!(
            delivery_status(&fx.state, &key, &survivor).await,
            Some(RecipientDelivery::Sent),
            "the frame write to the survivor succeeded"
        );
        // The survivor stopped before it installed the frame. The next
        // rounds, after the resend interval, must keep the delivery.
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        assert!(
            fx.state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ce
                .delivering()
                .contains(&key),
            "a transport success without convergence keeps the delivery"
        );
        assert_eq!(
            phase(Arc::clone(&fx.state)).await,
            Some(Phase::CommittedDeliveryPending),
            "the obligation does not complete on a transport success"
        );

        // The survivor restarts, installs the frame with its share and
        // reports its head.
        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        let admin = fx.state.agent.agent_id();
        let share = shares_for(&fx.state, &survivor_hex)
            .pop()
            .expect("a share for the survivor");
        let took =
            ng::apply_named_group_metadata_event(&fx.replica, share, admin, true, None).await;
        assert!(took.accepted, "{took:?}");
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied
        );
        let survivor_head = head_of(&fx.replica, &fx.group_id).await;
        assert_eq!(survivor_head.as_deref(), Some(result_head.as_str()));
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            survivor_head.as_deref(),
        )
        .await;
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        assert!(
            !fx.state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ce
                .delivering()
                .contains(&key),
            "the survivor's convergence ends the delivery"
        );
        assert_eq!(
            phase(Arc::clone(&fx.state)).await,
            Some(Phase::Complete),
            "the obligation completes once every survivor converged"
        );
        Ok(())
    }

    /// #1508 review P1, §3/§5: a restart after the GSS exclusion committed
    /// keeps the exact frame in the row and resumes its delivery; the
    /// rotated secret is durable.
    #[tokio::test]
    async fn gss_exclusion_frame_survives_a_committer_restart() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        run_worker(&fx.state).await;
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .expect("the GSS crypto-only exclusion committed");

        let restarted =
            ng::tests::secure_endpoint_test_state_at(fx.dir.path(), Arc::clone(&fx.state.agent))
                .await?;
        super::super::load_persisted_obligations(&restarted).await;
        let stored = restarted
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .expect("group");
        assert_eq!(stored.secret_epoch, 1, "the rotation is durable");
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        let inner = restarted.revocation_evictions.inner.lock().await;
        let row = inner.store.get(&key).expect("row");
        assert_eq!(row.phase, Phase::CommittedDeliveryPending);
        assert_eq!(row.outgoing_event.as_deref(), Some(frame.as_slice()));
        assert!(
            inner.ce.delivering().contains(&key),
            "the saved frame's delivery resumes"
        );
        Ok(())
    }

    /// Apply the fixture's leave, run the real worker until the GSS
    /// exclusion commits, end delivery and run one more pass, so the row
    /// completes from the chain. Returns the group as it was after the
    /// leave and before the exclusion (a stale snapshot of the departure),
    /// and the exclusion frame.
    async fn exclude_first_leave(fx: &GssLeave) -> Result<(GroupInfo, Vec<u8>)> {
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "the leave must apply: {applied:?}");
        let departed = fx
            .state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .expect("group");
        run_worker(&fx.state).await;
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .expect("the first exclusion frame");
        fx.state.revocation_evictions.inner.lock().await.ce = CeState::default();
        super::super::revocation_eviction_pass(&fx.state).await;
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        let inner = fx.state.revocation_evictions.inner.lock().await;
        assert_eq!(
            inner.store.get(&key).map(|row| row.phase),
            Some(Phase::Complete),
            "the first exclusion completed"
        );
        Ok((departed, frame))
    }

    async fn stored_group(fx: &GssLeave) -> GroupInfo {
        fx.state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .expect("group")
    }

    /// #1508 review (Codex P1 on a00455a): a later departure of a new
    /// membership incarnation reopens completed exclusion work. The leaver
    /// is excluded (row `Complete`), the admin adds it again through the
    /// real add-member route, and it leaves again. The second departure
    /// keeps the current secret, so the real worker pass must reopen the
    /// row and the GSS exclusion must run again: a new epoch, and no share
    /// for the departed member.
    #[tokio::test]
    async fn gss_second_departure_after_rejoin_reopens_and_rotates_again() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let (_, first_frame) = exclude_first_leave(&fx).await?;
        let leaver_hex = hex::encode(fx.leaver.as_bytes());

        // The rejoin: the admin seats the leaver again.
        let added = ng::add_named_group_member(
            axum::extract::State(Arc::clone(&fx.state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            axum::extract::Path(fx.group_id.clone()),
            axum::Json(ng::AddNamedGroupMemberRequest {
                agent_id: leaver_hex.clone(),
                display_name: None,
                treekem_key_package_b64: None,
            }),
        )
        .await;
        let added = axum::response::IntoResponse::into_response(added);
        assert_eq!(added.status(), axum::http::StatusCode::OK, "the rejoin");
        let rejoined = stored_group(&fx).await;
        assert_eq!(
            rejoined
                .members_v2
                .get(&leaver_hex)
                .map(|member| member.state),
            Some(x0x::groups::GroupMemberState::Active)
        );

        // The second departure: a new signed self-leave of the new seat.
        let mut leaving = rejoined.clone();
        leaving.roster_revision = leaving.roster_revision.saturating_add(1);
        let revision = leaving.roster_revision;
        leaving.remove_member(&leaver_hex, Some(leaver_hex.clone()));
        let leave_commit = leaving.seal_commit(&fx.leaver_kp, ng::now_millis_u64())?;
        let second_leave = ng::NamedGroupMetadataEvent::MemberRemoved {
            group_id: fx.group_id.clone(),
            revision,
            actor: leaver_hex.clone(),
            agent_id: leaver_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            commit: Some(leave_commit),
        };
        let applied =
            ng::apply_named_group_metadata_event(&fx.state, second_leave, fx.leaver, true, None)
                .await;
        assert!(applied.accepted, "the second leave must apply: {applied:?}");
        let departed = stored_group(&fx).await;
        assert!(
            ce::gss_secret_retained(&departed, &leaver_hex),
            "the second leaver still holds the current secret"
        );
        let departed_epoch = ce::committed_secret_epoch(&departed);
        if let Ok(mut scheduled) = fx
            .state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
        {
            scheduled.clear();
        }

        run_worker(&fx.state).await;

        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            let row = inner.store.get(&key).expect("row");
            assert_eq!(
                row.phase,
                Phase::CommittedDeliveryPending,
                "the second departure reopened the row and the exclusion committed"
            );
        }
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .expect("a second exclusion frame");
        assert_ne!(frame, first_frame, "a new exclusion ran");
        let decoded = ce::decode_frame(&frame).expect("frame");
        assert_eq!(
            decoded.body.crypto,
            ce::CryptoExclusionCryptoV1::Gss {
                next_secret_epoch: departed_epoch + 1
            }
        );
        let committed = stored_group(&fx).await;
        assert_eq!(committed.secret_epoch, departed_epoch + 1, "a new epoch");
        assert!(!ce::gss_secret_retained(&committed, &leaver_hex));
        let shares = fx
            .state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
            .map(|scheduled| scheduled.clone())
            .unwrap_or_default();
        assert!(!shares.is_empty(), "the survivor gets the new secret");
        assert!(
            shares
                .iter()
                .all(|(_, recipient, _)| *recipient != leaver_hex),
            "no share for the departed member"
        );
        Ok(())
    }

    /// The negative of the test above: a replay of the old departure does
    /// not reopen completed work. Neither the old leave event applied again
    /// nor a stale snapshot of the departed group (the old incarnation,
    /// read before the exclusion) reopens the `Complete` row or commits a
    /// second exclusion.
    #[tokio::test]
    async fn gss_replayed_old_departure_does_not_reopen_completed_work() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let (departed, _) = exclude_first_leave(&fx).await?;
        let epoch = stored_group(&fx).await.secret_epoch;

        let _ = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        run_worker(&fx.state).await;

        let stale = vec![(fx.group_id.clone(), departed)];
        let leaves = super::super::snapshot_retained_leaves(&fx.state, &stale).await;
        let triggers = super::super::derive_triggers(&stale, &leaves, &[], 0);
        assert!(!triggers.is_empty(), "the stale snapshot shows the leave");
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        {
            let runtime = &fx.state.revocation_evictions;
            let mut inner = runtime.inner.lock().await;
            for (trigger_key, trigger, incarnation) in triggers {
                let outcome = inner.store.intake(
                    &trigger_key,
                    trigger,
                    incarnation.as_deref(),
                    1,
                    runtime.boot_id,
                );
                assert_ne!(outcome, x0x::groups::eviction::IntakeOutcome::Reopened);
            }
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::Complete),
                "the replayed departure does not reopen the row"
            );
        }
        assert_eq!(
            latest_frame_for_test(&fx.state, &fx.stable).await,
            None,
            "no second exclusion"
        );
        assert_eq!(stored_group(&fx).await.secret_epoch, epoch);
        Ok(())
    }

    /// Insert a verified advert for `peer` with the capability bits `bits`,
    /// signed at `created_at_unix_ms` (a later advert replaces it).
    fn advertise_bits(state: &AppState, peer: AgentId, bits: u64, created_at_unix_ms: u64) {
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry { version: 1, bits };
        assert!(
            state.agent.capability_store().insert(
                peer,
                x0x::identity::MachineId([4; 32]),
                capabilities,
                created_at_unix_ms,
            ),
            "verified capability advert"
        );
    }

    /// #1508 review (Codex P1 on 50b6531): bounded commit history must not
    /// complete GSS exclusion work. The leaver keeps the current secret
    /// while a legacy survivor holds the exclusion (D76). More than
    /// [`x0x::groups::COMMIT_LOG_CAP`] later commits, none of which
    /// rotates the secret, trim the commit that seated the leaver. The
    /// real worker pass must keep the row open; once the survivor
    /// upgrades, the exclusion rotates the secret and only then completes.
    #[tokio::test]
    async fn gss_exclusion_held_for_upgrade_survives_commit_log_trimming() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let survivor = fx.replica.agent.agent_id();
        let all = x0x::dm::CapabilityRegistry::current().bits;
        let advertised_at = x0x::dm_capability::now_unix_ms();
        advertise_bits(
            &fx.state,
            survivor,
            all & !x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
            advertised_at,
        );
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "the leave must apply: {applied:?}");
        run_worker(&fx.state).await;
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            let row = inner.store.get(&key).expect("S4 self-leave row");
            assert!(row.phase.is_open(), "{:?}", row.phase);
            assert_eq!(
                row.waiting.as_ref().map(|waiting| waiting.cause),
                Some(x0x::groups::eviction::WaitingCause::WaitingForReceiverUpgrade),
                "the legacy survivor holds the exclusion"
            );
        }
        assert_eq!(latest_frame_for_test(&fx.state, &fx.stable).await, None);

        // Later commits that do not rotate the secret trim the history.
        let mut info = stored_group(&fx).await;
        let leaver_hex = hex::encode(fx.leaver.as_bytes());
        let admin_kp = fx.state.agent.identity().agent_keypair();
        for _ in 0..=x0x::groups::COMMIT_LOG_CAP {
            info.seal_commit(admin_kp, ng::now_millis_u64())?;
        }
        assert_eq!(info.commit_log.len(), x0x::groups::COMMIT_LOG_CAP);
        assert!(
            info.commit_log.iter().all(|retained| retained
                .roster
                .get(&leaver_hex)
                .is_none_or(|seat| seat.state != x0x::groups::GroupMemberState::Active)),
            "no retained commit seats the leaver"
        );
        assert_eq!(info.secret_epoch, 0, "no rotation");
        assert!(matches!(
            ng::persist_named_group_info(&fx.state, &fx.group_id, info).await,
            Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
        ));

        // The leaver still holds the current secret: the row stays open.
        run_worker(&fx.state).await;
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            let row = inner.store.get(&key).expect("S4 self-leave row");
            assert!(
                row.phase.is_open(),
                "trimmed history must not complete the exclusion: {:?}",
                row.phase
            );
        }
        assert_eq!(stored_group(&fx).await.secret_epoch, 0);

        // The survivor upgrades: the exclusion rotates, then completes.
        advertise_bits(&fx.state, survivor, all, advertised_at + 1);
        run_worker(&fx.state).await;
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .expect("the GSS crypto-only exclusion committed after the upgrade");
        assert_eq!(
            ce::decode_frame(&frame).expect("frame").body.crypto,
            ce::CryptoExclusionCryptoV1::Gss {
                next_secret_epoch: 1
            }
        );
        assert_eq!(stored_group(&fx).await.secret_epoch, 1);
        fx.state.revocation_evictions.inner.lock().await.ce = CeState::default();
        super::super::revocation_eviction_pass(&fx.state).await;
        let inner = fx.state.revocation_evictions.inner.lock().await;
        assert_eq!(
            inner.store.get(&key).map(|row| row.phase),
            Some(Phase::Complete),
            "the rotation completes the row"
        );
        Ok(())
    }

    /// The author `A` (`fx.state`) commits the GSS exclusion; the survivor
    /// `C` (`fx.replica`) takes the leave and holds the parent durably.
    /// Returns the exact frame, its result head and `C`'s parent.
    async fn authored_frame_and_parent(fx: &GssLeave) -> Result<(Vec<u8>, String, GroupInfo)> {
        use anyhow::Context as _;
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        anyhow::ensure!(applied.accepted, "the leave must apply: {applied:?}");
        run_worker(&fx.state).await;
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .context("the GSS crypto-only exclusion committed")?;
        let result_head = ce::decode_frame(&frame)
            .map(|frame| frame.body.commit.state_hash)
            .map_err(|refused| anyhow::anyhow!("decode: {}", refused.as_str()))?;
        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        anyhow::ensure!(applied.accepted, "{applied:?}");
        // #1508 review P1: the frame installs only with its new secret, so
        // the replica takes its share first (a share may arrive first).
        let share = shares_for(
            &fx.state,
            &hex::encode(fx.replica.agent.agent_id().as_bytes()),
        )
        .pop()
        .context("a share for the replica")?;
        let admin = fx.state.agent.agent_id();
        let took =
            ng::apply_named_group_metadata_event(&fx.replica, share, admin, true, None).await;
        anyhow::ensure!(took.accepted, "the replica takes the share: {took:?}");
        anyhow::ensure!(
            ng::save_named_groups(&fx.replica).await,
            "the parent is durable"
        );
        let parent = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        Ok((frame, result_head, parent))
    }

    async fn head_of(state: &AppState, group_id: &str) -> Option<String> {
        state
            .named_groups
            .read()
            .await
            .get(group_id)
            .map(|info| info.state_hash.clone())
    }

    /// The share events scheduled for `recipient_hex` since the recorder
    /// was last cleared.
    fn shares_for(state: &AppState, recipient_hex: &str) -> Vec<ng::NamedGroupMetadataEvent> {
        state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
            .map(|scheduled| scheduled.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, recipient, _)| recipient == recipient_hex)
            .filter_map(|(_, _, payload)| serde_json::from_slice(&payload).ok())
            .collect()
    }

    /// #1508 review P1 (ADR 0110 §3): the survivor's head is the
    /// committer's delivery evidence, so a GSS survivor must never hold the
    /// exclusion's result head without the new secret. Here the frame
    /// arrives, the share is lost and the survivor restarts. The survivor
    /// stays at the parent head, the committer keeps the delivery and seals
    /// the secret again on its next send, and the restarted survivor
    /// installs the kept frame with that share. Only then does the
    /// delivery end.
    #[tokio::test]
    async fn a_gss_survivor_restart_between_frame_and_share_keeps_the_key_delivery() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture().await?;
        advertise_crypto_exclusion(&fx.state, fx.replica.agent.agent_id());
        fx.state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        run_worker(&fx.state).await;
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .context("the GSS crypto-only exclusion committed")?;
        let result_head = ce::decode_frame(&frame)
            .map_err(|refusal| anyhow::anyhow!("frame: {refusal:?}"))?
            .body
            .commit
            .state_hash;
        let new_secret = fx
            .state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .and_then(|info| info.shared_secret.clone())
            .context("new secret")?;
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let admin = fx.state.agent.agent_id();

        // The survivor takes the leave, then the frame; the share is lost.
        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        let parent = head_of(&fx.replica, &fx.group_id).await;
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::WaitingForShare,
            "the frame waits for its share"
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await,
            parent,
            "no result head without the new secret"
        );

        // The survivor's head report is not convergence; the next send
        // seals the secret to it again.
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            parent.as_deref(),
        )
        .await;
        if let Ok(mut scheduled) = fx
            .state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
        {
            scheduled.clear();
        }
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            assert!(
                inner.ce.delivering().contains(&key),
                "the delivery runs until the survivor holds the key"
            );
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::CommittedDeliveryPending)
            );
        }
        let share = shares_for(&fx.state, &survivor_hex)
            .pop()
            .context("the resend seals the secret to the survivor again")?;

        // The survivor restarts between the frame and the share. Its KEM
        // key is durable in a real daemon; the test state keeps it.
        let mut restarted = ng::tests::secure_endpoint_test_state_at(
            fx._replica_dir.path(),
            Arc::clone(&fx.replica.agent),
        )
        .await?;
        Arc::get_mut(&mut restarted)
            .context("the restarted state is not shared yet")?
            .agent_kem_keypair = Arc::clone(&fx.replica.agent_kem_keypair);
        super::super::load_persisted_obligations(&restarted).await;
        retry_stash(&restarted).await;
        assert_eq!(head_of(&restarted, &fx.group_id).await, parent);
        let took = ng::apply_named_group_metadata_event(&restarted, share, admin, true, None).await;
        assert!(
            took.accepted,
            "the restarted survivor takes the share: {took:?}"
        );
        retry_stash(&restarted).await;
        let installed = restarted
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        assert_eq!(installed.state_hash, result_head, "the kept frame installs");
        assert_eq!(
            installed.shared_secret.as_deref(),
            Some(new_secret.as_slice()),
            "with the new secret"
        );

        // Now the survivor's head is key evidence and ends the delivery.
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            Some(result_head.as_str()),
        )
        .await;
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        assert!(
            !fx.state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ce
                .delivering()
                .contains(&key),
            "the survivor's convergence ends the delivery"
        );
        Ok(())
    }

    /// #1508/#1533 rc13 (Codex P1): a survivor that verified a GSS
    /// crypto-only exclusion keeps the old secret, which the excluded
    /// member holds, until the share arrives. It makes no new ciphertext in
    /// that wait, and a restart does not end the wait. The installed share
    /// ends it. Before the fix this path had no send hold at all.
    #[tokio::test]
    async fn a_pending_gss_crypto_exclusion_withholds_ciphertext_across_restart() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture().await?;
        advertise_crypto_exclusion(&fx.state, fx.replica.agent.agent_id());
        fx.state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let applied = ng::apply_named_group_metadata_event(
            &fx.state,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        run_worker(&fx.state).await;
        let frame = latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .context("the GSS crypto-only exclusion committed")?;
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let admin = fx.state.agent.agent_id();

        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            None,
            "no false hold before the exclusion"
        );
        let parent = head_of(&fx.replica, &fx.group_id).await;
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::WaitingForShare
        );
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval),
            "the verified exclusion holds new ciphertext"
        );

        // Get the share from the committer's next send.
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            parent.as_deref(),
        )
        .await;
        if let Ok(mut scheduled) = fx
            .state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
        {
            scheduled.clear();
        }
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        let share = shares_for(&fx.state, &survivor_hex)
            .pop()
            .context("the resend seals the secret to the survivor")?;

        // The survivor restarts before the share arrives.
        let mut restarted = ng::tests::secure_endpoint_test_state_at(
            fx._replica_dir.path(),
            Arc::clone(&fx.replica.agent),
        )
        .await?;
        Arc::get_mut(&mut restarted)
            .context("the restarted state is not shared yet")?
            .agent_kem_keypair = Arc::clone(&fx.replica.agent_kem_keypair);
        assert_eq!(head_of(&restarted, &fx.group_id).await, parent);
        assert_eq!(
            ng::group_ciphertext_withheld(&restarted, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval),
            "the hold survives the restart"
        );
        super::super::load_persisted_obligations(&restarted).await;
        retry_stash(&restarted).await;
        assert_eq!(
            ng::group_ciphertext_withheld(&restarted, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval)
        );

        let took = ng::apply_named_group_metadata_event(&restarted, share, admin, true, None).await;
        assert!(took.accepted, "{took:?}");
        retry_stash(&restarted).await;
        assert_eq!(
            ng::group_ciphertext_withheld(&restarted, &fx.group_id, None).await,
            None,
            "the installed share ends the hold"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&restarted, &fx.group_id),
            0
        );
        Ok(())
    }

    /// `C` restarts: the runtime state is dropped and the real load path
    /// runs, then one tick of the worker's crypto-exclusion steps.
    async fn restart_receiver(fx: &GssLeave) -> Result<Arc<AppState>> {
        let restarted = ng::tests::secure_endpoint_test_state_at(
            fx._replica_dir.path(),
            Arc::clone(&fx.replica.agent),
        )
        .await?;
        super::super::load_persisted_obligations(&restarted).await;
        drive_deliveries(&restarted).await;
        retry_stash(&restarted).await;
        Ok(restarted)
    }

    /// The frames `C` serves on catch-up above `from_revision`.
    async fn served(state: &AppState, stable: &str, from_revision: u64) -> Vec<Vec<u8>> {
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .catchup_frames(std::slice::from_ref(&stable.to_string()), from_revision)
            .into_iter()
            .map(|(_, _, bytes)| bytes.to_vec())
            .collect()
    }

    /// A lagging survivor `B` at `parent` installs `frame`, relayed by `C`.
    async fn lagging_peer_installs(
        fx: &GssLeave,
        parent: &GroupInfo,
        relay: AgentId,
        frame: &[u8],
        result_head: &str,
    ) -> Result<()> {
        let (lagging, _lagging_dir) = ng::tests::secure_endpoint_test_state().await?;
        lagging
            .named_groups
            .write()
            .await
            .insert(fx.group_id.clone(), parent.clone());
        assert_eq!(
            receive(&lagging, relay, frame).await,
            ReceiveOutcome::Applied,
            "the lagging survivor installs the served frame"
        );
        assert_eq!(
            head_of(&lagging, &fx.group_id).await.as_deref(),
            Some(result_head)
        );
        Ok(())
    }

    /// #1508 review (Codex P1): a survivor that installed a received
    /// exclusion and holds no S4 row for it restarts while the author is
    /// offline. The restarted survivor serves the exact frame, and a
    /// lagging survivor installs it from that copy.
    #[tokio::test]
    async fn a_restarted_receiver_serves_the_received_exclusion_frame() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let (frame, result_head, parent) = authored_frame_and_parent(&fx).await?;
        let admin = fx.state.agent.agent_id();
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied
        );
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        assert!(
            fx.replica
                .revocation_evictions
                .inner
                .lock()
                .await
                .store
                .get(&key)
                .is_none(),
            "the receiver holds no obligation row"
        );

        // `C` stops; the author `A` is offline from here on.
        fx.state.agent.shutdown().await;
        let restarted = restart_receiver(&fx).await?;
        assert_eq!(
            head_of(&restarted, &fx.group_id).await.as_ref(),
            Some(&result_head),
            "the installed exclusion survived the restart"
        );
        let frames = served(&restarted, &fx.stable, parent.state_revision).await;
        assert!(
            frames == [frame.clone()],
            "the restarted receiver serves the exact frame at catch-up (served {})",
            frames.len()
        );
        let relay = restarted.agent.agent_id();
        lagging_peer_installs(&fx, &parent, relay, &frames[0], &result_head).await
    }

    /// #1508 review (Codex P1, boot race): a frame received before the S4
    /// load runs stays held after the load. The interleaving is a second
    /// receipt that did its once-per-process `.celog` load before
    /// `load_persisted_obligations` replaced the runtime, and writes its
    /// frame after it. That write must keep the first frame in the file.
    #[tokio::test]
    async fn a_frame_received_before_the_s4_load_stays_held_after_it() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let (frame, result_head, parent) = authored_frame_and_parent(&fx).await?;
        let admin = fx.state.agent.agent_id();
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied
        );

        // The worker's boot load runs after the receipt.
        super::super::load_persisted_obligations(&fx.replica).await;
        let held_now = fx
            .replica
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .catchup_frames(std::slice::from_ref(&fx.stable), parent.state_revision);
        assert!(
            held_now.len() == 1 && held_now[0].2.as_slice() == frame.as_slice(),
            "the live held frame survives the load (held {})",
            held_now.len()
        );

        // The second receipt's frame write lands after the load.
        let ext = super::super::rebind::replay_log::CE_EXTENSION;
        let later = Arc::new(b"X0XCE1\0later frame".to_vec());
        let at = (parent.state_revision.saturating_add(2), "later-head");
        assert!(
            super::super::rebind::replay_log::write_received(
                &fx.replica,
                ext,
                held,
                &fx.stable,
                at,
                &later
            )
            .await
        );
        let on_disk =
            super::super::rebind::replay_log::tests::frames_on_disk(&fx.replica, ext, &fx.stable)
                .await;
        assert!(
            on_disk
                .iter()
                .any(|held| held.frame == frame && held.result_head == result_head),
            "the first frame is still durable ({} frames on disk)",
            on_disk.len()
        );
        Ok(())
    }

    /// #1508 review (Codex P1): the received frame is durable before the
    /// state it carries is installed. The install fails (a crash at that
    /// point); after the restart the node installs its own copy and serves
    /// it, with the author offline.
    #[tokio::test]
    async fn a_crash_before_the_exclusion_install_keeps_the_frame_durable() -> Result<()> {
        use super::super::rebind::restart_tests::{block_install, unblock_install};
        let fx = gss_leave_fixture().await?;
        let (frame, result_head, parent) = authored_frame_and_parent(&fx).await?;
        let admin = fx.state.agent.agent_id();
        let blocked = block_install(&fx.replica).await?;
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::LocalFailure,
            "the install failed"
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await.as_ref(),
            Some(&parent.state_hash),
            "the exclusion is not installed"
        );
        let ext = super::super::rebind::replay_log::CE_EXTENSION;
        let on_disk =
            super::super::rebind::replay_log::tests::frames_on_disk(&fx.replica, ext, &fx.stable)
                .await;
        assert_eq!(on_disk.len(), 1, "the received frame is durable");
        assert!(on_disk[0].frame == frame, "exact bytes on disk");
        assert_eq!(on_disk[0].result_head, result_head);
        assert!(!on_disk[0].authored);

        // The process dies before the install; the author stays offline.
        fx.state.agent.shutdown().await;
        unblock_install(blocked).await?;
        let restarted = restart_receiver(&fx).await?;
        assert_eq!(
            head_of(&restarted, &fx.group_id).await.as_ref(),
            Some(&result_head),
            "the restarted node installs its durable copy"
        );
        let frames = served(&restarted, &fx.stable, parent.state_revision).await;
        assert!(
            frames == [frame.clone()],
            "exact bytes at catch-up (served {})",
            frames.len()
        );
        let relay = restarted.agent.agent_id();
        lagging_peer_installs(&fx, &parent, relay, &frames[0], &result_head).await
    }

    /// #1508 review P1: the survivor's receive path refuses a GSS frame
    /// whose next secret epoch skips one, and one whose target is seated.
    #[tokio::test]
    async fn survivor_refuses_a_bad_gss_frame() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        let parent = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .expect("group");
        let admin_kp = fx.state.agent.identity().agent_keypair();
        let frame_for = |target: [u8; 32], next_secret_epoch: u64| -> Result<Vec<u8>> {
            let mut next = parent.clone();
            next.roster_revision = next.roster_revision.saturating_add(1);
            next.secret_epoch = next_secret_epoch;
            next.security_binding = Some(format!("gss:epoch={next_secret_epoch}"));
            let commit = next.seal_commit(admin_kp, ng::now_millis_u64())?;
            let target_hex = hex::encode(target);
            let body = ce::CryptoExclusionBodyV1 {
                stable_group_id: fx.stable.clone(),
                actor: *admin_kp.agent_id().as_bytes(),
                target,
                prior_head: parent.state_hash.clone(),
                prior_revision: parent.state_revision,
                next_revision: commit.revision,
                roster_revision: next.roster_revision,
                removal_proof_hash: ce::removal_proof_for(&parent, &target_hex).unwrap_or([0; 32]),
                crypto: ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch },
                commit: ce::CommitHeaderV1::from(&commit),
            };
            let frame = ce::sign(body, admin_kp).map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(ce::encode_frame(&frame)?)
        };
        let admin = fx.state.agent.agent_id();
        assert_eq!(
            receive(&fx.replica, admin, &frame_for(*fx.leaver.as_bytes(), 2)?).await,
            ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::EpochMismatch),
            "the next secret epoch must be the committed epoch + 1"
        );
        let survivor = *fx.replica.agent.agent_id().as_bytes();
        assert_eq!(
            receive(&fx.replica, admin, &frame_for(survivor, 1)?).await,
            ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::TargetNotRemoved),
            "a seated target is refused"
        );
        let unchanged = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .map(|info| (info.state_hash.clone(), info.secret_epoch));
        assert_eq!(unchanged, Some((parent.state_hash.clone(), 0)));
        Ok(())
    }
}

/// #1508 r6: sibling `CryptoExclusionV1` frames (ADR 0110 §2 fork
/// containment, §4 L249 receiver checks). Each test drives the real
/// receive function on an offline daemon (no network node).
#[cfg(test)]
mod sibling_tests {
    use super::super::rebind::restart_tests::{hold_persisted, offline_daemon};
    use super::*;
    use anyhow::{Context as _, Result};
    use x0x::identity::{AgentKeypair, UserKeypair};

    /// A GSS `MlsEncrypted` `OwnerCertified` group created by `creator`,
    /// with `admin` a second admin, a bystander and `members` Members.
    /// `target` leaves without a rotation (`parent`, retained), and
    /// `creator` then removes the bystander with a rotation on it
    /// (`head`). Two GSS exclusions of one target on one parent have the
    /// same state, so the own branch is another commit.
    struct Race {
        parent: GroupInfo,
        head: GroupInfo,
        target_hex: String,
    }

    fn race(
        owner: &UserKeypair,
        creator: &AgentKeypair,
        admin: &AgentKeypair,
        target: &AgentKeypair,
        members: &[&AgentKeypair],
    ) -> Result<Race> {
        let now_ms = super::super::super::now_millis_u64();
        let creator_hex = hex::encode(creator.agent_id().as_bytes());
        let mut info = GroupInfo::new(
            "ce-sibling".to_string(),
            String::new(),
            creator.agent_id(),
            "ca".repeat(16),
        );
        info.policy.admission =
            x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
        let bystander = AgentKeypair::generate()?;
        let bystander_hex = hex::encode(bystander.agent_id().as_bytes());
        for (member, role) in std::iter::once((admin, x0x::groups::GroupRole::Admin))
            .chain(std::iter::once((
                &bystander,
                x0x::groups::GroupRole::Member,
            )))
            .chain(std::iter::once((target, x0x::groups::GroupRole::Member)))
            .chain(members.iter().map(|m| (*m, x0x::groups::GroupRole::Member)))
        {
            info.add_member(
                hex::encode(member.agent_id().as_bytes()),
                role,
                Some(creator_hex.clone()),
                None,
            );
        }
        info.seal_commit_evicting(creator, now_ms)?;
        anyhow::ensure!(ce::is_gss_encrypted(&info), "a GSS MlsEncrypted group");
        let target_hex = hex::encode(target.agent_id().as_bytes());
        let mut parent = info;
        parent.roster_revision = parent.roster_revision.saturating_add(1);
        parent.remove_member(&target_hex, Some(target_hex.clone()));
        parent.seal_commit_evicting(target, now_ms + 1)?;
        // The creator's own branch: it removes the bystander and rotates
        // to secret epoch 1. A GSS exclusion of the target on the same
        // parent is a sibling with another state.
        let mut head = parent.clone();
        head.roster_revision = head.roster_revision.saturating_add(1);
        head.remove_member(&bystander_hex, Some(creator_hex));
        head.secret_epoch = 1;
        head.security_binding = Some(ce::gss_binding(1));
        head.seal_commit_evicting(creator, now_ms + 2)?;
        Ok(Race {
            parent,
            head,
            target_hex,
        })
    }

    /// A GSS exclusion of `target_hex` on `parent`, signed by `actor`.
    fn exclusion(
        parent: &GroupInfo,
        target_hex: &str,
        actor: &AgentKeypair,
        next_secret_epoch: u64,
        now_ms: u64,
    ) -> Result<(GroupInfo, Vec<u8>)> {
        let mut next = parent.clone();
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.secret_epoch = next_secret_epoch;
        next.security_binding = Some(ce::gss_binding(next_secret_epoch));
        let commit = next.seal_commit_evicting(actor, now_ms)?;
        let mut target = [0u8; 32];
        hex::decode_to_slice(target_hex, &mut target)?;
        let body = ce::CryptoExclusionBodyV1 {
            stable_group_id: parent.stable_group_id().to_string(),
            actor: *actor.agent_id().as_bytes(),
            target,
            prior_head: parent.state_hash.clone(),
            prior_revision: parent.state_revision,
            next_revision: commit.revision,
            roster_revision: next.roster_revision,
            removal_proof_hash: ce::removal_proof_for(parent, target_hex).unwrap_or([0; 32]),
            crypto: ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch },
            commit: ce::CommitHeaderV1::from(&commit),
        };
        let frame = ce::sign(body, actor).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok((next, ce::encode_frame(&frame)?))
    }

    async fn quarantine_of(state: &AppState, stable: &str) -> Option<x0x::groups::ForkQuarantine> {
        state
            .named_groups
            .read()
            .await
            .get(stable)
            .and_then(|info| info.fork_quarantine.clone())
    }

    /// Codex P1 A, for `CryptoExclusionV1`: a frame that does not chain
    /// from this node's head is checked against its retained parent
    /// before it can be fork evidence. An unrevoked ordinary member signs
    /// an exclusion sibling, and an admin signs one at a wrong epoch.
    /// Neither quarantines an invite-derived receiver; each is refused
    /// with its own reason. A valid sibling by the other admin does.
    #[tokio::test]
    async fn an_invalid_exclusion_sibling_quarantines_no_receiver() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let receiver = offline_daemon(dir.path(), None).await?;
        let owner = UserKeypair::generate()?;
        let creator = AgentKeypair::generate()?;
        let admin = AgentKeypair::generate()?;
        let target = AgentKeypair::generate()?;
        let member = AgentKeypair::generate()?;
        let me = receiver.agent.identity().agent_keypair();
        let fx = race(&owner, &creator, &admin, &target, &[&member, me])?;
        let mut head = fx.head.clone();
        head.invite_lineage = Some(x0x::groups::InviteLineage {
            base_revision: fx.parent.state_revision,
            base_hash: fx.parent.state_hash.clone(),
            seated_at_revision: Some(fx.parent.state_revision),
            ..Default::default()
        });
        let stable = head.stable_group_id().to_string();
        hold_persisted(&receiver, &head).await?;
        let now_ms = super::super::super::now_millis_u64();

        let (_, by_member) = exclusion(&fx.parent, &fx.target_hex, &member, 1, now_ms)?;
        let outcome = receive(&receiver, member.agent_id(), &by_member).await;
        assert_eq!(
            quarantine_of(&receiver, &stable).await,
            None,
            "a member's exclusion is no fork evidence"
        );
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::ActorIneligible)
        );
        let (_, wrong_epoch) = exclusion(&fx.parent, &fx.target_hex, &admin, 5, now_ms)?;
        let outcome = receive(&receiver, admin.agent_id(), &wrong_epoch).await;
        assert_eq!(
            quarantine_of(&receiver, &stable).await,
            None,
            "an exclusion at a wrong epoch is no fork evidence"
        );
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::EpochMismatch)
        );

        // The control: the other admin's valid exclusion on the same parent.
        let (sibling, valid) = exclusion(&fx.parent, &fx.target_hex, &admin, 1, now_ms)?;
        let outcome = receive(&receiver, admin.agent_id(), &valid).await;
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::HeadMismatch)
        );
        let marker = quarantine_of(&receiver, &stable)
            .await
            .context("the valid sibling contains the group")?;
        assert_eq!(marker.state_hash, sibling.state_hash);
        receiver.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 B, for `CryptoExclusionV1` (ADR 0110 §2): the creator
    /// commits its own branch; the other admin's valid sibling exclusion on
    /// the same parent then arrives. The creator's record has no invite
    /// lineage, and it is still contained, durably across a restart.
    #[tokio::test]
    async fn a_valid_exclusion_sibling_contains_the_creator() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let creator = offline_daemon(dir.path(), None).await?;
        let owner = UserKeypair::generate()?;
        let admin = AgentKeypair::generate()?;
        let target = AgentKeypair::generate()?;
        let survivor = AgentKeypair::generate()?;
        let me = creator.agent.identity().agent_keypair();
        let fx = race(&owner, me, &admin, &target, &[&survivor])?;
        assert!(
            fx.head.invite_lineage.is_none(),
            "the creator has no lineage"
        );
        let stable = fx.head.stable_group_id().to_string();
        hold_persisted(&creator, &fx.head).await?;

        let now_ms = super::super::super::now_millis_u64();
        let (sibling, valid) = exclusion(&fx.parent, &fx.target_hex, &admin, 1, now_ms)?;
        let outcome = receive(&creator, admin.agent_id(), &valid).await;
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::HeadMismatch)
        );
        let marker = quarantine_of(&creator, &stable)
            .await
            .context("the creator is contained")?;
        assert_eq!(marker.state_hash, sibling.state_hash);
        assert_eq!(marker.revision, fx.head.state_revision);
        let head = creator
            .named_groups
            .read()
            .await
            .get(&stable)
            .map(|info| info.state_hash.clone());
        assert_eq!(
            head,
            Some(fx.head.state_hash.clone()),
            "no node applies both"
        );

        creator.agent.shutdown().await;
        drop(creator);
        let restarted = offline_daemon(dir.path(), None).await?;
        assert_eq!(
            quarantine_of(&restarted, &stable)
                .await
                .map(|marker| marker.state_hash),
            Some(sibling.state_hash),
            "the containment survives a restart"
        );
        restarted.agent.shutdown().await;
        Ok(())
    }
}
