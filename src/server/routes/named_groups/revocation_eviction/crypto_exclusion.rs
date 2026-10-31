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
//!   takes the secret from its share. A survivor whose roster seat carries
//!   no KEM public key can never receive that share (#1578): it installs
//!   the frame keyless — the head moves, the old secret is dropped, the
//!   share hold stays — and a share that arrives once the seat re-joins
//!   with a verified KEM binding ends the hold. That keyless install is
//!   local fact only (Engineer ruling, 27 Oct 22:10 GMT: it never proves
//!   delivery, and a transport ACK closes no seat): while it lasts the
//!   survivor claims no head in its catch-up answers
//!   ([`super::super::gss_share_hold::reported_head`]) — David's ruling,
//!   28 Oct 02:09 GMT: the absence is keyless-only, and every other
//!   responder, a superseded intermediate head included, serves exactly
//!   main's answer — so it converges no author's delivery row. The
//!   author's row for such a seat stays open until it can seal (the seat
//!   re-joins with a verified KEM binding) or a survivor's head claim
//!   proves delivery.
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
//!   A seat this author cannot seal a share to (no KEM key on its roster
//!   seat, #1578) is no exception: its ACK closes nothing, and the row
//!   stays open until the author can seal or a head claim proves
//!   delivery.
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

use super::owner_recovery::LaterAdminKey;
use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::crypto_exclusion as ce;
use x0x::groups::eviction::{EvJournalV1, EvictionKey, ObligationStore, Phase};
use x0x::groups::GroupInfo;
use x0x::identity::AgentId;

use super::super::{LogHexId, SelfLeaveRekeyStep};
use super::frame_stash::{FrameStash, StashedFrame};
use super::rebind::replay_log;

/// A delivery round runs no more often than this per row.
const CE_RESEND_INTERVAL: Duration = Duration::from_secs(5);
/// Frames held per group for catch-up serving: the same bound as the
/// replay frames kept in completed `.evs` rows.
const CE_LOG_PER_GROUP: usize = x0x::groups::eviction::MAX_REPLAY_FRAMES_PER_GROUP;
/// The per-exchange bound of one live delivery or catch-up frame write.
const CE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
/// Frames that arrived ahead of this node's head, waiting for it
/// ([`FrameStash`]).
const CE_STASH_CAP: usize = 64;

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
    /// #1660: per recipient, the record that a sealed share of this row's
    /// secret went to the recipient's seat key. A report closes the seat
    /// only when the key the sender's seat carries now is the record's
    /// key and a head ask went to the seat after the seal
    /// ([`report_may_close`]), so a seat whose key arrives mid-send stays
    /// open until a round seals the share to that key and asks again.
    share_went_to: BTreeMap<[u8; 32], ShareRecord>,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
}

/// The crypto-only exclusion state held in the S4 runtime.
#[derive(Debug, Default)]
pub(super) struct CeState {
    deliveries: HashMap<EvictionKey, CeDelivery>,
    /// Frames held for catch-up serving. The received frames are durable
    /// in the `.celog` ([`replay_log`]); the authored frames are durable in
    /// their `.evs` rows.
    log: replay_log::HeldLog<CE_LOG_PER_GROUP>,
    stash: FrameStash<CE_STASH_CAP>,
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

impl CeState {
    /// #1508 rc17 (Codex P1): whether a retained crypto-only exclusion
    /// frame of `stable_group_id` commits a revision above `revision`.
    /// #1508 rc18 (Codex P1): only a frame that passed [`ce::check_ahead`]
    /// on this node's latest head, or every receiver check, counts, with no
    /// time limit ([`FrameStash`]).
    pub(super) fn stash_ahead(&self, stable_group_id: &str, revision: u64) -> bool {
        self.stash.ahead(stable_group_id, revision)
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
        // The frame is self-authenticating; its actor is the sender. It
        // passed every receiver check before it was written.
        let Ok(frame) = ce::decode_frame(&bytes) else {
            continue;
        };
        let body = &frame.body;
        let _kept = inner.ce.stash.push(StashedFrame::new(
            AgentId(body.actor),
            bytes.to_vec(),
            &body.stable_group_id,
            body.next_revision,
            true,
        ));
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

/// #1660 (ADR 0110 §3): the live-roster facts of a head report's sender.
/// The delivery completion step re-reads them before it closes a seat as
/// delivered.
///
/// `None` — the sender is no longer an Active member of the live roster,
/// or the revocation verdict refuses it (a revoked agent, machine or
/// binding). Its report is not a survivor's, so it closes no seat. A member removed or revoked
/// mid-send keeps the seat it had. The round drops a removed seat and
/// withholds a revoked one. Neither is closed as delivered: §3 has no
/// mid-send exception, and entitlement is not fixed at commit (D60).
///
/// `key` — the KEM public key the sender's Active seat carries on this
/// node's live roster view, the only key a GSS share could be sealed to.
/// `None` is the #1578 keyless seat: it can never take a share.
#[derive(Debug, Clone)]
pub(super) struct SenderSeat {
    pub(super) key: Option<String>,
}

/// #1660: the record that a sealed share of a row's secret went to a
/// seat's KEM key. `ask_seq_at_seal` is the seat's head-ask count at the
/// seal (Engineer ruling, 29 Oct 17:12 GMT): a report closes the seat
/// only after the count moved past it, so only an answer that could
/// answer an ask sent after the seal closes the seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShareRecord {
    /// The KEM public key (b64) the share was sealed to.
    pub(super) key: String,
    /// The seat's head-ask count when the share was sealed.
    pub(super) ask_seq_at_seal: u64,
}

/// #1660: whether a report from `seat` may close a seat of a delivery
/// whose rounds seal GSS shares (`shares`: the row's `gss_epoch`).
///
/// Every row requires a live, D60-clean sender. A GSS row additionally
/// requires both halves of the share proof. `went_to` — the record of a
/// share sealed for this seat — must carry the key the seat holds now.
/// And `ask_seq` — this node's head-ask count for the seat now — must be
/// past the count at the seal, so the answer could answer an ask sent
/// after the share was sealed (Engineer ruling, 29 Oct 17:12 GMT; ADR
/// 0110 §3, #1578: a keyless install proves no delivery, and an answer
/// that raced the share proves nothing about it).
pub(super) fn report_may_close(
    seat: Option<SenderSeat>,
    shares: bool,
    went_to: Option<&ShareRecord>,
    ask_seq: Option<u64>,
) -> bool {
    match seat {
        Some(seat) => {
            !shares
                || (ask_seq
                    .is_some_and(|now| went_to.is_some_and(|record| now > record.ask_seq_at_seal))
                    && seat.key.as_deref() == went_to.map(|record| record.key.as_str()))
        }
        None => false,
    }
}

/// §3 survivor convergence for the S4 deliveries of one group. The
/// catch-up response handler reports each verified, applied answer
/// through [`super::note_catchup_head`]; that answer names the
/// responder's own head; `installed` is that head and its ancestors on
/// the local chain. It is the convergence evidence for the crypto-only
/// exclusion, saved-removal, certificate-rebind and owner-recovery commit
/// deliveries of `stable_group_id` whose result the responder holds.
/// `sender_seat` is the sender's live-roster facts at this moment
/// (#1660): a report closes a seat only while its sender is still a
/// live, D60-clean survivor, and a GSS row's report only when a sealed
/// share went to the key the sender's seat carries now.
pub(super) fn note_survivor_head(
    inner: &mut super::S4Inner,
    stable_group_id: &str,
    sender: &[u8; 32],
    installed: &BTreeSet<String>,
    sender_seat: Option<SenderSeat>,
) {
    // #1660 (Engineer ruling, 29 Oct 17:12 GMT): the seat's head-ask
    // count now. A GSS row's report closes its seat only when the count
    // is past the count at the seal.
    let ask_seq = inner
        .head_ask_seq
        .get(&(stable_group_id.to_string(), *sender))
        .copied();
    for (key, delivery) in &mut inner.ce.deliveries {
        if key.stable_group_id == stable_group_id
            && report_may_close(
                sender_seat.clone(),
                delivery.gss_epoch.is_some(),
                delivery.share_went_to.get(sender),
                ask_seq,
            )
        {
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
        sender_seat.clone(),
        ask_seq,
    );
    super::rebind::note_survivor_head(
        &mut inner.rebind,
        stable_group_id,
        sender,
        installed,
        sender_seat.clone(),
        ask_seq,
    );
    super::owner_recovery::note_survivor_head(
        &mut inner.orc,
        stable_group_id,
        sender,
        installed,
        sender_seat,
        ask_seq,
    );
}

/// #1660 (Claude round 5): keep a seat's share record. A seal to the
/// key the record already holds keeps the EARLIEST ask count — the
/// rounds of a live row seal again every pass, and a later seal's count
/// must not push the bar past the ask the answer rode on. A seal to a
/// different key (a rotation) resets the record to that seal. Returns
/// whether this seal ESTABLISHED the record — created it or changed its
/// key; a same-key re-seal returns `false` ([`note_share_went_to`] moves
/// the generation only for an establishing seal).
pub(super) fn keep_share_record(
    map: &mut BTreeMap<[u8; 32], ShareRecord>,
    recipient: &[u8; 32],
    kem: &str,
    ask_seq_at_seal: u64,
) -> bool {
    match map.get_mut(recipient) {
        Some(record) if record.key == kem => {
            record.ask_seq_at_seal = record.ask_seq_at_seal.min(ask_seq_at_seal);
            false
        }
        Some(record) => {
            *record = ShareRecord {
                key: kem.to_string(),
                ask_seq_at_seal,
            };
            true
        }
        None => {
            map.insert(
                *recipient,
                ShareRecord {
                    key: kem.to_string(),
                    ask_seq_at_seal,
                },
            );
            true
        }
    }
}

/// #1660: record that a sealed share of the group secret `epoch` went to
/// `recipient`'s seat key `kem`. Every S4 plane that seals a share calls
/// this after its send task is admitted, while no caller holds the S4
/// lock (this function takes it). Each of its GSS delivery rows of that
/// group and epoch keeps the record — the key and the seat's head-ask
/// count at the seal — and a later report from the seat closes the row
/// only against this record ([`report_may_close`]). The same critical
/// section moves the seat's share-seal generation, but only when this
/// seal ESTABLISHED the seat's record — created it or changed its key
/// (Engineer ruling, 30 Oct 05:10 GMT). A re-seal to the same key keeps
/// the earliest bar and does not advance the generation, so an ask whose
/// request left after that bar is still credited when its send completes:
/// owner recovery's rounds re-send the commit and re-seal the same key
/// every pass, and their convergence must not depend on the commit's ACK
/// losing the race with the ask's ([`ask_heads`], Codex P2, 30 Oct).
pub(super) async fn note_share_went_to(
    state: &AppState,
    stable_group_id: &str,
    epoch: u64,
    recipient: &[u8; 32],
    kem: &str,
) {
    let mut inner = state.revocation_evictions.inner.lock().await;
    let ask_seq_at_seal = inner
        .head_ask_seq
        .get(&(stable_group_id.to_string(), *recipient))
        .copied()
        .unwrap_or(0);
    // #1660 (Engineer ruling, 30 Oct 05:10 GMT): an establishing seal
    // moves the seat's share-seal generation, so an ask whose request
    // left before it cannot credit the count on its late completion
    // ([`ask_heads`]). A same-key re-seal moves nothing.
    let mut established = false;
    for (key, delivery) in &mut inner.ce.deliveries {
        if key.stable_group_id == stable_group_id && delivery.gss_epoch == Some(epoch) {
            established |=
                keep_share_record(&mut delivery.share_went_to, recipient, kem, ask_seq_at_seal);
        }
    }
    established |= super::removal_delivery::note_share_went_to(
        &mut inner.removals,
        stable_group_id,
        epoch,
        recipient,
        kem,
        ask_seq_at_seal,
    );
    established |= super::owner_recovery::note_share_went_to(
        &mut inner.orc,
        stable_group_id,
        epoch,
        recipient,
        kem,
        ask_seq_at_seal,
    );
    if established {
        *inner
            .share_seal_seq
            .entry((stable_group_id.to_string(), *recipient))
            .or_insert(0) += 1;
    }
}

/// Ask each of `peers` for a catch-up page of `stable_group_id`, on the
/// existing request path, detached (an offline peer must not hold the
/// worker). The answer reports the peer's head ([`note_survivor_head`]).
/// #1660 (Engineer ruling, 29 Oct 17:12 GMT): a request that went out
/// counts, per seat, as a head ask. The count advances inside the task,
/// after the send succeeded — a refused admission, a task still parked
/// at the send boundary and a failed send count nothing, so no answer
/// can ride a count for an ask that never left this node (Codex P2,
/// 29 Oct). #1660 (Codex P2, 30 Oct): the send returns only after the
/// recipient's ACK, so a seal can record its bar while an earlier ask
/// is still in flight. The task reads the seat's share-seal generation
/// before the request leaves and credits the count only when the
/// generation still holds at completion — a completion whose send was
/// in flight across an ESTABLISHING seal is a pre-seal ask's, and
/// counts nothing ([`note_share_went_to`] bumps the generation only
/// when a seal creates the seat's record or changes its key, Engineer
/// ruling, 30 Oct 05:10 GMT; a same-key re-seal keeps the earliest bar
/// and moves nothing, so owner recovery's rounds converge without
/// winning the ACK race). A delivery row's share record keeps the count
/// at its seal, and a report closes a GSS seat only after the count
/// moved past that — only answers that could answer an ask sent after
/// the seal close the seat. No caller holds the S4 lock; the task takes
/// it only for the generation and the count. In tests the task parks at
/// the `head-ask-settled:{group}` seam once its decision is made, so a
/// test waits out a failed send without a fixed sleep.
pub(super) async fn ask_heads(state: &Arc<AppState>, group_id: &str, peers: Vec<AgentId>) {
    for peer in peers {
        let task_state = Arc::clone(state);
        let group_id = group_id.to_string();
        #[cfg(test)]
        let settled_key = format!("head-ask-settled:{group_id}");
        let _spawned = state.spawn_detached(async move {
            let seal_seq_before = {
                let inner = task_state.revocation_evictions.inner.lock().await;
                inner
                    .share_seal_seq
                    .get(&(group_id.clone(), *peer.as_bytes()))
                    .copied()
                    .unwrap_or(0)
            };
            if super::super::request_treekem_catchup_page(&task_state, &group_id, &peer).await {
                let mut inner = task_state.revocation_evictions.inner.lock().await;
                let seal_seq_now = inner
                    .share_seal_seq
                    .get(&(group_id.clone(), *peer.as_bytes()))
                    .copied()
                    .unwrap_or(0);
                if seal_seq_now == seal_seq_before {
                    *inner
                        .head_ask_seq
                        .entry((group_id, *peer.as_bytes()))
                        .or_insert(0) += 1;
                }
            }
            #[cfg(test)]
            super::super::detached_send_test_seam::park(&settled_key).await;
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
    spawn_post_commit_round(state, group_key);
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
    spawn_gss_shares(state, &next, &key.target).await;
    tracing::info!(
        group_id = %LogHexId::group(group_key),
        target = %LogHexId::agent(&target_hex),
        secret_epoch = next_secret_epoch,
        "ADR 0110 S4: GSS crypto-only exclusion committed"
    );
    spawn_post_commit_round(state, group_key);
}

/// After a committed crypto-only exclusion (TreeKEM or GSS), publish the
/// group card of `group_key` and run one delivery round, in a detached
/// task. #1699: the delivery worker walks every group's live record, also
/// when a staged re-seat join's apply committed this exclusion, so the
/// task runs outside any re-seat scope.
fn spawn_post_commit_round(state: &Arc<AppState>, group_key: &str) {
    use super::super as ng;
    let task_state = Arc::clone(state);
    let card_key = group_key.to_string();
    let _spawned = state.spawn_detached(crate::server::reseat_scope::outside_reseat_scope(
        async move {
            ng::maybe_publish_group_card_after_state_change(&task_state, &card_key).await;
            drive_deliveries(&task_state).await;
        },
    ));
}

/// Seal `info`'s current secret to each remaining Active member other
/// than this node and `target`, each as a D60 guarded class-K delivery.
async fn spawn_gss_shares(state: &Arc<AppState>, info: &GroupInfo, target: &[u8; 32]) {
    let local = *state.agent.agent_id().as_bytes();
    for member in info.active_members() {
        if agent_bytes(&member.agent_id).is_some_and(|id| id != local && id != *target) {
            spawn_gss_share_to(state, info, &member.agent_id).await;
        }
    }
}

/// Seal `info`'s current secret to the Active member `recipient_hex`. The
/// D60 verdict re-checks its eligibility and the epoch at each write. A
/// member without a roster KEM key cannot get a share; it is logged and
/// skipped, as in the ban path (#1578: such a survivor installs a received
/// frame keyless instead of waiting for the share). #1660: a successful
/// seal is recorded ([`note_share_went_to`]) before the send task leaves,
/// so a later report from the seat closes a delivery row only after a
/// share went to the key the seat carries then.
async fn spawn_gss_share_to(state: &Arc<AppState>, info: &GroupInfo, recipient_hex: &str) {
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
    let recipient = agent_bytes(recipient_hex);
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
            // #1660 (Claude review): the record claims a share went out.
            // A refused spawn sealed nothing, so it records nothing — no
            // report may close against it.
            if ng::spawn_secure_share_delivery(state, &event) {
                if let Some(recipient) = recipient {
                    note_share_went_to(
                        state,
                        info.stable_group_id(),
                        info.secret_epoch,
                        &recipient,
                        kem,
                    )
                    .await;
                }
            }
        }
        Err(_) => {
            tracing::warn!(recipient = %LogHexId::agent(recipient_hex), "ADR 0110 S4: the GSS share could not be sealed");
        }
    }
}

/// #1578: whether a share of the rotated secret can never be sealed to
/// this node. Its own roster seat is Active but carries no KEM public
/// key, so this node cannot identify a share sealed for its seat, and
/// waiting for one would hold the verified frame for ever. The seat's
/// KEM key is local data — not in the roster root or the state hash — so
/// another member's view of the seat can differ; that is why the keyless
/// install is local fact only: it never proves delivery (Engineer
/// ruling, 27 Oct 22:10 GMT), and while it lasts this node claims no
/// head in its catch-up answers
/// ([`super::super::gss_share_hold::reported_head`]) — David's ruling,
/// 28 Oct 02:09 GMT — so it converges no author's delivery row. The
/// serve path reads this from the saved group state itself, so the
/// head claim survives a hold write that fails and a restart.
pub(in crate::server::routes::named_groups) fn own_seat_cannot_take_a_share(
    state: &AppState,
    info: &GroupInfo,
) -> bool {
    let own_hex = hex::encode(state.agent.agent_id().as_bytes());
    info.active_members()
        .any(|member| member.agent_id == own_hex && member.kem_public_key_b64.is_none())
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
    let gss_epoch = frame_gss_epoch(&bytes);
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
            share_went_to: BTreeMap::new(),
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

/// The rotated secret epoch a saved GSS frame commits to (`None` for a
/// TreeKEM frame, which carries its own key material).
pub(super) fn frame_gss_epoch(bytes: &[u8]) -> Option<u64> {
    ce::decode_frame(bytes)
        .ok()
        .and_then(|frame| match frame.body.crypto {
            ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } => Some(next_secret_epoch),
            ce::CryptoExclusionCryptoV1::TreeKem { .. } => None,
        })
}

/// #1574 item 3: whether a saved GSS frame the chain superseded still
/// needs its delivery at restart. The live round rule in
/// `drive_deliveries` keeps a delivery while the rotated secret is still
/// the current committed one, because a GSS survivor installs the frame
/// only with its sealed share, and the crash may have lost the shares
/// before any survivor converged (#1508 review P1). The restart
/// classification must not end that delivery earlier than the live rule
/// would: without a delivery the row would complete on the chain proof
/// alone, with no round ever re-sealing the share. `gss_epoch` is the
/// frame's rotated epoch ([`frame_gss_epoch`]).
pub(super) fn superseded_gss_delivery_kept(info: &GroupInfo, gss_epoch: Option<u64>) -> bool {
    let Some(epoch) = gss_epoch else {
        return false;
    };
    info.secret_epoch == epoch && ce::committed_secret_epoch(info) == epoch
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
            spawn_gss_shares(state, &info, &key.target).await;
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
        for (recipient, attempt) in started {
            // §3 (#1508 review P1): a GSS survivor installs the frame only
            // with its new secret, so every send seals that secret again.
            // #1578: a seat with no roster KEM key cannot be sealed to;
            // the spawn logs the skip, and such a survivor installs the
            // frame keyless on receipt.
            if gss_current.is_some() {
                spawn_gss_share_to(state, &info, &hex::encode(recipient)).await;
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
        // #1660 (Engineer ruling, 29 Oct 17:12 GMT): the asks leave after
        // this round's shares are sealed and recorded, so their answers
        // are answers to asks sent after the seal — the only answers the
        // gate accepts.
        ask_heads(state, &key.stable_group_id, head_asks).await;
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
/// with `try_*`, and contention refuses (a retryable withhold). The
/// delivery completion step re-runs the verdict under the S4 lock with
/// it (#1660, Claude review: a revocation that lands between the
/// unlocked verdict and the S4 lock must still refuse).
pub(super) fn write_allowed_at_seam(state: &AppState, agent: &AgentId) -> bool {
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
            // The in-process stand-in reports an admitted exchange with its
            // marker error (test builds only), as the live delivery path
            // does ([`spawn_send`]); without this arm no local test can
            // reach the catch-up share step below (#1576).
            #[cfg(test)]
            Ok(Err(error)) if error.to_string().contains(x0x::dm::PINNED_STANDIN_ADMITTED) => {}
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
            spawn_gss_share_to(state, &info, &requester_hex).await;
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
    /// `verified`: the frame passed [`ce::check_ahead`] on this node's
    /// latest head, so it is known higher-head evidence (#1508 rc18,
    /// [`FrameStash`]).
    Behind { verified: bool },
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
            Self::Behind { .. } | Self::LocalFailure | Self::WaitingForShare
        )
    }

    /// A retained frame that is known higher-head evidence (§2): it passed
    /// [`ce::check_ahead`], or every receiver check before it waited.
    pub(in crate::server) fn head_evidence(self) -> bool {
        matches!(
            self,
            Self::Behind { verified: true } | Self::LocalFailure | Self::WaitingForShare
        )
    }
}

/// The stash entry of an exclusion frame, or `None` when it does not
/// decode.
fn stashed(sender: AgentId, bytes: Vec<u8>, evidence: bool) -> Option<StashedFrame> {
    let body = ce::decode_frame(&bytes).ok()?.body;
    Some(StashedFrame::new(
        sender,
        bytes,
        &body.stable_group_id,
        body.next_revision,
        evidence,
    ))
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
            if let Some(frame) = stashed(sender, payload, outcome.head_evidence()) {
                let mut inner = task_state.revocation_evictions.inner.lock().await;
                let _kept = inner.ce.stash.push(frame);
            }
        }
    });
}

/// Retry every stashed frame; keep the ones still ahead of this node or
/// stopped by a local fault. #1508 rc18 (Codex P1): the frames stay in the
/// stash while the retry runs, so head evidence holds throughout, and each
/// retained frame's evidence state is checked again on the new head.
pub(super) async fn retry_stash(state: &Arc<AppState>) {
    ensure_restored(state).await;
    // #1580: converge the legacy MLS views with the durable rosters on
    // the same pass. A received frame the restore kept at the head (the
    // crash between the durable install and the MLS removal) never
    // re-enters [`receive`], so the frames below cannot redo it.
    converge_legacy_mls_views_with_rosters(state).await;
    let frames = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .ce
        .stash
        .retry_set(Instant::now());
    if frames.is_empty() {
        return;
    }
    let mut results = Vec::with_capacity(frames.len());
    for frame in frames {
        let outcome = receive(state, frame.sender, &frame.bytes).await;
        let kept = outcome.is_retained().then(|| outcome.head_evidence());
        results.push((frame, kept));
    }
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .ce
        .stash
        .settle(results);
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
        // #1580: the frame's result is this node's head, so it installed
        // here before (or a peer resent the exact durable frame). The
        // local legacy MLS removal is not durable, so this replay of the
        // durable frame reruns it. The roster, not the frame, is
        // authoritative: the removal runs only for a seat this node's
        // roster already holds Removed or Banned (rc2 review, security) —
        // a forged frame that names an Active member changes nothing.
        // Idempotent: a view without the target, including the empty view
        // of a fresh process, changes nothing.
        if matches!(body.crypto, ce::CryptoExclusionCryptoV1::Gss { .. })
            && seat_left_the_roster(&info, &body.target)
        {
            remove_legacy_mls_member(state, &group_key, AgentId(body.target)).await;
        }
        return ReceiveOutcome::Duplicate;
    }
    if info.state_hash != body.prior_head && info.state_revision < body.prior_revision {
        // #1508 rc18 (Codex P1): a frame of a later revision is head
        // evidence only when its actor has standing on this node's latest
        // head. A forged future frame is kept for a retry but holds
        // nothing. The revocation check above covered the actor and the
        // sender.
        let verified = ce::check_ahead(&body, &info).is_ok();
        return ReceiveOutcome::Behind { verified };
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
    // ADR 0109 §2 "Conflict" (#1533 r6): the one conflict gate bounds
    // this commit as it bounds every metadata route.
    if !ng::group_recovery::conflict_admits_commit(state, &info, &commit).await {
        tracing::warn!(
            group_id = %LogHexId::group(&group_key),
            revision = commit.revision,
            "ADR 0109 S3: crypto-only exclusion past the attestation conflict's common prefix refused"
        );
        return ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::GroupContained);
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
        let outcome = unhold_unless_kept(state, stable, outcome).await;
        // #1508 rc13: the commits and shares that chain on this frame
        // re-enter the ordinary apply, so no group lock may be held.
        drop(membership_guard);
        if outcome == ReceiveOutcome::Applied {
            super::owner_recovery::replay_after_gss_install(state, stable).await;
        }
        return outcome;
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
///
/// #1508 rc13 (Codex P1): the share can come from a later admin that the
/// actor promoted on this frame's result and that this node does not know
/// as an admin yet ([`super::owner_recovery::promoted_admin_secret`]). The
/// frame then installs with that secret, and the held promotion and the
/// parked share replay after it. #1508 rc15: when that admin's held
/// rotation moved the group past this frame's epoch, the frame installs as
/// an intermediate head ([`LaterAdminKey::Superseded`]).
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
    let waiting = info.secret_epoch < next_secret_epoch || info.shared_secret.is_none();
    let roster_revision = body.roster_revision;
    // The frame's verified result without its key: the roster that a later
    // admin's promotion chains on.
    let keyless = || {
        ng::apply_stateful_event_to_group(
            info,
            commit,
            x0x::groups::ActionKind::AdminOrHigher,
            |next| {
                next.roster_revision =
                    ng::adopt_roster_revision(next.roster_revision, roster_revision);
                next.secret_epoch = next_secret_epoch;
                next.security_binding = Some(ce::gss_binding(next_secret_epoch));
            },
        )
        .ok()
    };
    let result = if waiting { keyless() } else { None };
    let promoted = match result {
        Some(result) => {
            super::owner_recovery::promoted_admin_secret(state, &result, next_secret_epoch).await
        }
        None => None,
    };
    let superseded = promoted == Some(LaterAdminKey::Superseded);
    // #1578: a survivor whose own roster seat carries no KEM public key
    // cannot identify a share sealed to its seat, so waiting would keep
    // the verified frame pending for ever, holding this group's head.
    // Such a survivor installs the frame keyless instead: the head moves
    // to the verified result, the old secret (which the excluded member
    // holds) is dropped, and the share hold stays until a share of this
    // epoch installs — through the existing share path once the seat
    // re-joins with a verified KEM binding (the only exit today: no wire
    // event seats a key on an already-Active seat; a key-republication
    // message is David's 02:25 ruling, a separate follow-up).
    // The install is local fact only (Engineer ruling, 27 Oct 22:10 GMT:
    // it never proves delivery, and an ACK closes no seat): while it
    // lasts this node claims no head in its catch-up answers (David's
    // ruling, 28 Oct 02:09 GMT: the absence is keyless-only, and the
    // Engineer ruling of 28 Oct 09:35 GMT scopes it to encrypted groups
    // — a SignedPublic member keeps main's answer; every other
    // responder, a superseded intermediate head included, serves exactly
    // main's answer), and the install converges no author's delivery
    // row. That head claim reads the group state itself, so it holds
    // even when the hold write below fails and a restart follows; the
    // durable hold orders the ciphertext withholding, not the claim.
    let awaiting_share = waiting && promoted.is_none() && own_seat_cannot_take_a_share(state, info);
    if waiting && promoted.is_none() && !awaiting_share {
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
    if awaiting_share {
        // The keyless install holds through the same durable hold: it is
        // written before the state change, so a crash between the two
        // leaves the hold and a retry that installs again.
        ng::gss_share_hold::hold_exclusion(state, group_key, &info.state_hash, next_secret_epoch)
            .await;
    }
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
            // The secret and its epoch came with the share (checked above),
            // or from a later admin's share.
            next.roster_revision = ng::adopt_roster_revision(next.roster_revision, roster_revision);
            // #1508 rc15: a superseded frame installs as an intermediate
            // head with no secret; the held chain replays on it and
            // installs the later secret.
            if let Some(key) = promoted {
                next.shared_secret = match key {
                    LaterAdminKey::Exact(secret) => Some(secret.to_vec()),
                    LaterAdminKey::Superseded => None,
                };
                next.secret_epoch = next_secret_epoch;
            } else if awaiting_share {
                // #1578: no share can be sealed to this seat. Install the
                // verified result keyless, as a superseded rotation does:
                // the epoch advances without a secret, so the share hold
                // keeps withholding new ciphertext until a share installs.
                next.shared_secret = None;
                next.secret_epoch = next_secret_epoch;
            }
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
        from_later_admin = promoted.is_some(),
        superseded,
        awaiting_share,
        "ADR 0110 S4: GSS crypto-only exclusion installed"
    );
    // An intermediate head holds no secret of this epoch: its hold stays
    // until the later secret installs ([`ng::gss_share_hold::holds`]). So
    // does the #1578 keyless install, until a share of this epoch arrives.
    if !superseded && !awaiting_share {
        ng::gss_share_hold::release_exclusions(state, group_key, next_secret_epoch).await;
    }
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

/// #1580: the durable roster is authoritative for the legacy MLS view. A
/// rerun removes a member only when this node's roster holds its seat
/// `Removed` or `Banned` — never because a frame names it (rc2 review,
/// security).
fn seat_left_the_roster(info: &GroupInfo, target: &[u8; 32]) -> bool {
    matches!(
        info.members_v2
            .get(&hex::encode(target))
            .map(|seat| seat.state),
        Some(x0x::groups::GroupMemberState::Removed) | Some(x0x::groups::GroupMemberState::Banned)
    )
}

/// #1580: the local legacy MLS view of a GSS group lists only seats the
/// durable roster still holds Active. Every removal that keeps it (this
/// module, the ban and removal arms) is an in-memory step after the
/// durable roster write, so a crash between the two leaves a Removed or
/// Banned seat listed, and the restart never re-receives the frame that
/// carried the removal (a restored received frame at the head is kept for
/// serving only). The worker's stash pass reruns the removal from the
/// loaded roster instead: idempotent, and a no-op while the fresh process
/// holds no view yet.
///
/// A group's removal runs under that group's membership lock, and each
/// seat is re-read at the moment of the removal (lock order membership,
/// MLS, named groups — the order the apply paths use). The GSS
/// `MemberAdded` arm adds the view entry before it persists the roster
/// under the same lock, so this pass can never run inside that window and
/// drop the seat the re-add is about to seat (rc3 review, race).
pub(super) async fn converge_legacy_mls_views_with_rosters(state: &AppState) {
    use super::super as ng;
    // A read-only pass first: only a group whose view lists a seat the
    // roster holds Removed or Banned takes any write lock.
    let stale: Vec<String> = {
        let views = state.mls_groups.read().await;
        let groups = state.named_groups.read().await;
        views
            .iter()
            .filter(|(key, view)| {
                let Some(info) = groups.get(key.as_str()) else {
                    return false;
                };
                info.secure_plane == x0x::mls::SecureGroupPlane::Gss
                    && view
                        .members()
                        .keys()
                        .any(|agent| seat_left_the_roster(info, agent.as_bytes()))
            })
            .map(|(key, _)| key.clone())
            .collect()
    };
    for key in stale {
        let membership_lock = ng::group_membership_lock(state, &key).await;
        let _membership_guard = membership_lock.lock().await;
        let mut removed_any = false;
        {
            let mut views = state.mls_groups.write().await;
            let Some(view) = views.get_mut(&key) else {
                continue;
            };
            let groups = state.named_groups.read().await;
            let Some(info) = groups.get(&key) else {
                continue;
            };
            let agents: Vec<AgentId> = view.members().keys().copied().collect();
            for agent in agents {
                if seat_left_the_roster(info, agent.as_bytes())
                    && view.is_member(&agent)
                    && view.remove_member(agent).await.is_ok()
                {
                    removed_any = true;
                }
            }
        }
        if removed_any {
            ng::save_mls_groups(state).await;
            tracing::info!(
                group_id = %LogHexId::group(&key),
                "ADR 0110 S4: a removed seat left the legacy MLS view again (#1580)"
            );
        }
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

    /// #1574 item 3: the restart rule for a superseded GSS frame mirrors
    /// the live round rule — the delivery survives while the rotated
    /// secret is still the current committed one, and a later rekey (or a
    /// TreeKEM frame with no rotated secret) ends it.
    #[test]
    fn a_superseded_gss_frame_keeps_its_delivery_while_its_secret_is_current() {
        let mut info = info_with_log("c", &[("p", "r"), ("r", "c")]);
        for retained in info.commit_log.iter_mut() {
            retained.commit.security_binding = Some(ce::gss_binding(2));
        }
        info.security_binding = Some(ce::gss_binding(2));
        info.secret_epoch = 2;
        assert!(superseded_gss_delivery_kept(&info, Some(2)));
        // A rekey moved the committed epoch past the frame's rotation.
        info.commit_log
            .last_mut()
            .expect("head commit")
            .commit
            .security_binding = Some(ce::gss_binding(3));
        info.security_binding = Some(ce::gss_binding(3));
        info.secret_epoch = 3;
        assert!(!superseded_gss_delivery_kept(&info, Some(2)));
        // A TreeKEM frame carries no rotated secret epoch.
        assert!(!superseded_gss_delivery_kept(&info, None));
        // The committed epoch is the frame's again, but a sealed share of
        // a newer epoch already raised the local one: the live rule needs
        // both to agree, so the delivery is not current.
        info.commit_log
            .last_mut()
            .expect("head commit")
            .commit
            .security_binding = Some(ce::gss_binding(2));
        info.security_binding = Some(ce::gss_binding(2));
        info.secret_epoch = 5;
        assert!(!superseded_gss_delivery_kept(&info, Some(2)));
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
        assert!(ReceiveOutcome::Behind { verified: false }.is_retained());
        assert!(!ReceiveOutcome::Behind { verified: false }.head_evidence());
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

    /// #1699 (#1689 review P3): both commit paths (`commit_locked` and
    /// `commit_gss`) start their detached card and delivery round through
    /// [`spawn_post_commit_round`]. A staged re-seat join's apply can commit
    /// an exclusion, so that round must run outside the caller's re-seat
    /// scope and judge the delivery by the live record. Here the live
    /// original is contained (fork-quarantined) and the staged copy is not.
    /// The round, started inside the open staging, must see the live marker
    /// and move the row to the fork set. In the scope it would see the
    /// staged copy, find no recipient left and drop the row. Inert: an
    /// offline agent.
    #[tokio::test]
    async fn the_post_commit_round_started_in_a_reseat_scope_sees_the_live_map() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let group_id = "cd".repeat(16);
        let mut staged = GroupInfo::new("ce-reseat".into(), String::new(), admin, group_id.clone());
        staged.recompute_state_hash();
        let stable = staged.stable_group_id().to_string();
        let mut live = staged.clone();
        live.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: 1,
            state_hash: "sibling".into(),
            committed_by: String::new(),
            observed_at_ms: 0,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: live.terminal_commit_header(),
                conflicting_commit: live.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        });
        state
            .named_groups
            .live_write()
            .await
            .insert(group_id.clone(), live);
        state
            .named_groups
            .staging_write()
            .await
            .insert(group_id.clone(), staged.clone());
        let key = EvictionKey::new(stable.clone(), [0x79; 32]);
        new_delivery(
            &mut state.revocation_evictions.inner.lock().await.ce,
            &key,
            &staged.state_hash,
            staged.state_revision.saturating_add(1),
            Arc::new(Vec::new()),
            Vec::new(),
            false,
        );

        let scope = state.reseat_stagings.open(&group_id, &stable);
        crate::server::reseat_scope::in_reseat_scope(scope, async {
            assert!(crate::server::reseat_scope::in_any_reseat_scope());
            assert!(
                state
                    .named_groups
                    .read()
                    .await
                    .get(&group_id)
                    .is_some_and(|info| info.fork_quarantine.is_none()),
                "the caller sees the staged copy"
            );
            spawn_post_commit_round(&state, &group_id);
        })
        .await;
        for _ in 0..500 {
            if !state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ce
                .deliveries
                .contains_key(&key)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state.reseat_stagings.scope_for(&group_id).is_some(),
            "the staging stayed open while the round ran"
        );
        let inner = state.revocation_evictions.inner.lock().await;
        assert!(
            !inner.ce.deliveries.contains_key(&key),
            "the round ran and ended the delivery"
        );
        assert!(
            inner.ce.fork.contains(&key),
            "the round judged the delivery by the live, contained original"
        );
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
        gss_leave_fixture_with(None).await
    }

    /// [`gss_leave_fixture`], with `extra` seated as one more Member.
    async fn gss_leave_fixture_with(extra: Option<AgentId>) -> Result<GssLeave> {
        gss_leave_fixture_build(extra, true).await
    }

    /// [`gss_leave_fixture`], choosing whether the survivor's seat carries
    /// a KEM public key. Without one (#1578) no author can seal a share to
    /// the survivor.
    async fn gss_leave_fixture_build(
        extra: Option<AgentId>,
        survivor_seats_kem: bool,
    ) -> Result<GssLeave> {
        gss_leave_fixture_views(extra, survivor_seats_kem, survivor_seats_kem).await
    }

    /// [`gss_leave_fixture`], with independent views of the survivor
    /// seat's KEM public key (#1578 round 1, Claude P1: the KEM key is
    /// local data, not in the roster root or the state hash, so the
    /// committer and the survivor can disagree about the seat). Both
    /// copies share the sealed commits, so they keep one chain.
    async fn gss_leave_fixture_views(
        extra: Option<AgentId>,
        committer_seats_kem: bool,
        replica_seats_kem: bool,
    ) -> Result<GssLeave> {
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
        let survivor_kem_b64 = base64::engine::general_purpose::STANDARD
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
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
            committer_seats_kem.then(|| survivor_kem_b64.clone()),
        );
        if let Some(extra) = extra {
            info.add_member(
                hex::encode(extra.as_bytes()),
                x0x::groups::GroupRole::Member,
                Some(admin_hex.clone()),
                None,
            );
        }
        info.seal_commit(state.agent.identity().agent_keypair(), ng::now_millis_u64())?;
        let old_secret = info.shared_secret.clone().expect("GSS secret");
        let stable = info.stable_group_id().to_string();
        // The survivor's own copy keeps the same sealed chain; only its
        // view of its own seat's KEM key differs.
        let mut replica_info = info.clone();
        // The survivor's own copy seats or drops its key per the flag,
        // independent of the author's view — both divergent directions
        // build (review: `true` must seat the key, not only "not drop"
        // it, or a keyless author's copy stays keyless on the replica).
        if let Some(member) = replica_info.members_v2.get_mut(&survivor_hex) {
            member.kem_public_key_b64 = replica_seats_kem.then(|| survivor_kem_b64.clone());
        }
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        replica
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), replica_info);
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

    /// #1576: a restored crypto-exclusion delivery keeps a head round
    /// through its open row. The `reconcile_and_retain` delivering set
    /// holds the row `committed_delivery_pending` on the pass after the
    /// restart — the chain alone would complete it (the rotation excluded
    /// the leaver) — and the open row keeps the group's §2 head round,
    /// which the restored frame's resends wait for. No dedicated restart
    /// test proved this before.
    #[tokio::test]
    async fn a_restored_exclusion_delivery_keeps_the_head_round_through_its_open_row() -> Result<()>
    {
        use anyhow::Context as _;
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
        latest_frame_for_test(&fx.state, &fx.stable)
            .await
            .context("the GSS crypto-only exclusion committed")?;
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());

        // The process restarts: the groups and the `.evs` load again.
        let restarted =
            ng::tests::secure_endpoint_test_state_at(fx.dir.path(), Arc::clone(&fx.state.agent))
                .await?;
        super::super::load_persisted_obligations(&restarted).await;
        {
            let inner = restarted.revocation_evictions.inner.lock().await;
            assert!(inner.ce.delivering().contains(&key), "the delivery resumes");
        }

        // The pass after the restart: the delivering set keeps the row
        // open, and the open row keeps the group's head round.
        super::super::revocation_eviction_pass(&restarted).await;
        {
            let inner = restarted.revocation_evictions.inner.lock().await;
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::CommittedDeliveryPending),
                "the delivering set holds the row open"
            );
            assert!(
                inner.head_rounds.contains_key(&fx.stable),
                "the open row keeps the group's head round"
            );
        }

        // The negative control: without the delivery the same pass
        // completes the row from the chain, and the group's round goes.
        restarted.revocation_evictions.inner.lock().await.ce = CeState::default();
        super::super::revocation_eviction_pass(&restarted).await;
        let inner = restarted.revocation_evictions.inner.lock().await;
        assert_eq!(
            inner.store.get(&key).map(|row| row.phase),
            Some(Phase::Complete),
            "no delivering set: the chain completes the row"
        );
        assert!(
            !inner.head_rounds.contains_key(&fx.stable),
            "no open row: no head round"
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

    /// #1616: the transport machine of a simulated DM whose sender device
    /// is clean — the same id named_groups' `clean_sender_machine` uses,
    /// which no test revokes.
    fn clean_sender_machine() -> x0x::identity::MachineId {
        x0x::identity::MachineId([0x16; 32])
    }

    /// The `responder_state_hash` this node really serves in a catch-up
    /// answer for `group_id` (#1578 review: the tests feed the served
    /// answer, never a hand-built value).
    async fn served_responder_head(
        state: &Arc<AppState>,
        requester: AgentId,
        group_id: &str,
    ) -> Result<Option<String>> {
        use anyhow::Context as _;
        let info = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .cloned()
            .context("group")?;
        ng::handle_treekem_catchup_request(
            state,
            &requester,
            &clean_sender_machine(),
            true,
            ng::TreeKemCatchupRequest {
                message_type: "treekem_catchup_request".to_string(),
                group_id: group_id.to_string(),
                requester_agent_id: hex::encode(requester.as_bytes()),
                from_revision: info.state_revision,
                from_treekem_epoch: 0,
                current_state_hash: info.state_hash.clone(),
                missing_prev_state_hash: None,
                target_member_id: None,
                limit: 64,
            },
        )
        .await;
        let served = state
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .context("the catch-up answer was served")?;
        let page: ng::TreeKemCatchupResponse =
            serde_json::from_slice(&served).map_err(|error| anyhow::anyhow!("page: {error}"))?;
        Ok(page.responder_state_hash.clone())
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

    /// #1578: a GSS survivor whose own roster seat carries no KEM public
    /// key cannot identify a share sealed to its seat. Before the fix the
    /// verified frame waited for its share for ever: the survivor's head
    /// stayed at the parent, the frame stayed pending in the stash, and
    /// the author's delivery never converged. Now such a survivor
    /// installs the frame keyless: the head moves to the verified result,
    /// the old secret (which the excluded member holds) is dropped, and
    /// new ciphertext stays withheld by the typed share hold. That
    /// keyless install never proves delivery (Engineer ruling, 27 Oct
    /// 22:10 GMT): the survivor claims no head while it is keyless
    /// (David's ruling, 28 Oct 02:09 GMT), so it converges no author's
    /// row, and the frame's transport ACK closes nothing (ADR 0110 §3
    /// L228) — the author's row stays open until the seat re-joins with
    /// a verified KEM binding and the share installs. A KEM-seated
    /// survivor keeps the wait-for-share flow (the fixture test above).
    #[tokio::test]
    async fn a_gss_survivor_without_a_roster_kem_key_installs_the_frame_keyless() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture_build(None, false).await?;
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
        let decoded = ce::decode_frame(&frame).context("frame")?;
        let result_head = decoded.body.commit.state_hash.clone();
        let next_revision = decoded.body.next_revision;
        let ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } = decoded.body.crypto else {
            anyhow::bail!("the fixture commits the GSS form");
        };
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let admin = fx.state.agent.agent_id();
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        assert!(
            shares_for(&fx.state, &survivor_hex).is_empty(),
            "no share can be sealed to a seat with no KEM key: the stranding premise of #1578"
        );

        // The survivor takes the leave, then the frame. It holds no new
        // secret and no share can ever arrive, so the frame installs
        // keyless instead of pending for ever.
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
            ReceiveOutcome::Applied,
            "the keyless survivor installs the verified frame (#1578)"
        );
        {
            let installed = fx
                .replica
                .named_groups
                .read()
                .await
                .get(&fx.group_id)
                .cloned()
                .context("group")?;
            assert_eq!(installed.state_hash, result_head, "the head moves");
            assert_eq!(installed.secret_epoch, next_secret_epoch);
            assert!(
                installed.shared_secret.is_none(),
                "the old secret, which the excluded member holds, is dropped"
            );
            assert!(
                installed.secure_message_key().is_none(),
                "no message key exists at the new epoch"
            );
        }
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval),
            "the typed share hold withholds new ciphertext while the share is awaited"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            1,
            "the hold stays until a share of this epoch installs"
        );
        // The frame is no longer pending: the stash holds no higher-head
        // evidence for the group.
        {
            let inner = fx.replica.revocation_evictions.inner.lock().await;
            assert!(
                !inner
                    .ce
                    .stash_ahead(&fx.stable, next_revision.saturating_sub(1)),
                "the installed frame leaves no pending higher-head evidence"
            );
        }
        assert_ne!(
            head_of(&fx.replica, &fx.group_id).await.as_deref(),
            parent.as_deref(),
            "the survivor left the parent head"
        );

        // Engineer ruling, 27 Oct 22:10 GMT: the keyless install never
        // proves delivery, and the send's transport ACK never closes the
        // seat (ADR 0110 §3 L228). The row stays open until the author
        // can seal — the seat re-joins with a verified KEM binding — or
        // a survivor's head claim proves delivery.
        assert!(
            ng::gss_share_hold::test_seam::hold_file_exists(&fx.replica, &fx.group_id),
            "the durable hold is written to disk while the share is awaited"
        );
        // The real served catch-up answer, not a hand-built value: the
        // keyless survivor's page claims no head at all.
        let served = served_responder_head(&fx.replica, admin, &fx.group_id).await?;
        assert_eq!(
            served, None,
            "the served answer omits the field while the responder is keyless"
        );
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            served.as_deref(),
        )
        .await;
        // The parent head — the answer David's ruled-out alternative
        // would have served — must not converge the row either: a head
        // behind the result proves the survivor holds no key of it.
        // (Ruling, 28 Oct 02:09 GMT: the keyless survivor omits the
        // field; both shapes leave the row open, pinned here.)
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            parent.as_deref(),
        )
        .await;
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        assert_eq!(
            delivery_status(&fx.state, &key, &survivor).await,
            Some(RecipientDelivery::Sent),
            "the carrier's acceptance is Sent, not delivery: an ACK closes no seat"
        );
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            assert!(
                inner.ce.delivering().contains(&key),
                "the row stays open: this author cannot seal and no head claim arrived"
            );
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::CommittedDeliveryPending),
                "the obligation stays open until the seat can take a share"
            );
        }

        // The recovery path, ADR 0024 item 7: the keyless install never
        // completes the removal for the author. Only when the seat
        // re-joins with a verified KEM binding (no wire event seats a
        // key on an already-Active seat — David's 02:25 ruling puts a
        // key-republication message on a separate follow-up — so the
        // test seats the key as the /secure/reseal endpoint test does)
        // can the author's own S4 delivery spawn seal the current
        // secret, and only the installed share — whose report is then
        // the result head — converges the row.
        fx.state
            .named_groups
            .write()
            .await
            .get_mut(&fx.group_id)
            .context("the author's group")?
            .set_member_kem_public_key(
                &survivor_hex,
                base64::engine::general_purpose::STANDARD
                    .encode(&fx.replica.agent_kem_keypair.public_bytes),
            );
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        let share = shares_for(&fx.state, &survivor_hex)
            .pop()
            .context("the author's own spawn sealed the share once the seat had a key")?;
        let took =
            ng::apply_named_group_metadata_event(&fx.replica, share, admin, true, None).await;
        assert!(took.accepted, "the awaited share installs: {took:?}");
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            None,
            "the installed share ends the hold"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            0
        );
        assert!(
            !ng::gss_share_hold::test_seam::hold_file_exists(&fx.replica, &fx.group_id),
            "the prune that ended the hold wrote the file: no hold residue survives it"
        );
        // The share is the proof: only now does the survivor report a
        // head, and only that report completes the author's row.
        let reported = served_responder_head(&fx.replica, admin, &fx.group_id).await?;
        assert_eq!(
            reported.as_deref(),
            Some(result_head.as_str()),
            "with the share held the report is the result head: a share-proof"
        );
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            reported.as_deref(),
        )
        .await;
        assert_eq!(
            delivery_status(&fx.state, &key, &survivor).await,
            Some(RecipientDelivery::Converged),
            "the share-proof report converges the seat"
        );
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            assert!(
                !inner.ce.delivering().contains(&key),
                "the confirmed share ends the delivery"
            );
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::Complete),
                "the obligation completes only after the seat is keyed and the share is sealed"
            );
        }
        Ok(())
    }

    /// #1635 fix round (Codex P1, 28 Oct): the delayed-exclusion shape.
    /// The survivor already installed the exclusion keyless — its head is
    /// the result H1, it holds no secret and its seat carries no KEM key
    /// — while an admin is still at H0, the exclusion frame not yet
    /// arrived on its own delivery row. Before David's 28 Oct 02:09 GMT
    /// ruling the keyless survivor reported the hold's parent H0 in its
    /// catch-up answers: the lagging admin's classify passed (the report
    /// named its own head), its head round confirmed and its startup
    /// check satisfied the peer, so the admin could seal at H0 against
    /// the H1 chain. The ruling closes the vector at the source: the
    /// keyless survivor's served answer omits `responder_state_hash`, so
    /// the lagging admin reads no head from it. The parent shape — the
    /// pre-fix answer — is pinned as the vector: it passes both gates.
    #[tokio::test]
    async fn a_keyless_survivors_answer_confirms_no_lagging_admins_round() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture_build(None, false).await?;
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
        // The replica's post-leave state is H0 — the lagging admin's view.
        // It is cloned BEFORE the frame moves the replica to H1.
        let parent_info = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        let parent_head = parent_info.state_hash.clone();
        let stable = parent_info.stable_group_id().to_string();
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied,
            "the survivor installs the verified frame keyless (#1578)"
        );
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());

        // The lagging admin: still at H0, the exclusion not yet arrived.
        // Its head round is open and its startup gate waits on the
        // survivor.
        let (lagging, _lagging_dir) = ng::tests::secure_endpoint_test_state().await?;
        lagging
            .named_groups
            .write()
            .await
            .insert(fx.group_id.clone(), parent_info);
        {
            let mut inner = lagging.revocation_evictions.inner.lock().await;
            inner.head_rounds.insert(
                stable.clone(),
                super::super::HeadRound::new(&parent_head, Instant::now()),
            );
        }
        ng::self_leave_startup_require(
            &lagging,
            std::slice::from_ref(&fx.group_id),
            std::slice::from_ref(&survivor_hex),
        );

        // The real served answer of the keyless survivor at H1: no head.
        // The gated serve answers a member requester (the author, as the
        // fixture test above asks); the answer the lagging admin reads
        // from the gated carrier is this same page.
        let served = served_responder_head(&fx.replica, admin, &fx.group_id).await?;
        assert_eq!(
            served, None,
            "the keyless survivor claims no head (David's ruling, 28 Oct 02:09 GMT)"
        );
        super::super::note_catchup_head(
            &lagging,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            served.as_deref(),
        )
        .await;
        {
            let inner = lagging.revocation_evictions.inner.lock().await;
            assert!(
                !inner.head_rounds.get(&stable).expect("the round").confirmed,
                "the keyless disclaimer confirms no round: no seal at H0 against the H1 chain"
            );
        }
        ng::self_leave_startup_note_verified_head(
            &lagging,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            served.as_deref(),
        )
        .await;
        assert!(
            ng::self_leave_startup_open(&lagging, &fx.group_id),
            "the absent field satisfies no startup peer"
        );

        // The ruled-out shape: had the keyless survivor reported the
        // hold's parent H0 — the pre-fix answer — both gates would pass.
        // That is the vector the keyless absence closes, pinned here.
        super::super::note_catchup_head(
            &lagging,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            Some(&parent_head),
        )
        .await;
        {
            let inner = lagging.revocation_evictions.inner.lock().await;
            assert!(
                inner.head_rounds.get(&stable).expect("the round").confirmed,
                "a parent report is OnLocalChain at H0: the vector the keyless absence closes"
            );
        }
        ng::self_leave_startup_note_verified_head(
            &lagging,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            Some(&parent_head),
        )
        .await;
        assert!(
            !ng::self_leave_startup_open(&lagging, &fx.group_id),
            "a parent report would satisfy the startup peer: the vector, pinned"
        );
        Ok(())
    }

    /// #1635 review round 5 (Claude P1 at a00ab3a): a keyless GSS
    /// install holds the ciphertext boundary, and
    /// `POST /groups/:id/secure/encrypt` must answer the typed 409
    /// (David's approval, 28 Oct 08:59 GMT; the API-docs row and the
    /// W3-H case `w3h_1578_red_…` promise the same). The GSS arm read
    /// `secure_message_key()` before the hold check, and a keyless
    /// install holds no secret, so the route fell into the
    /// waiting-joiner 424. The hold check in the keyless arm serves the
    /// typed refusal; a member with no hold (a joiner awaiting its
    /// welcome share) keeps the 424. This test fails if the 424 comes
    /// back.
    #[tokio::test]
    async fn a_keyless_survivors_encrypt_answers_the_typed_409_not_the_joiners_424() -> Result<()> {
        use anyhow::Context as _;
        use base64::Engine as _;
        let fx = gss_leave_fixture_build(None, false).await?;
        advertise_crypto_exclusion(&fx.state, fx.replica.agent.agent_id());
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
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied,
            "the survivor installs the verified frame keyless (#1578)"
        );
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        // The state the 409 names: the install moved the head, the
        // survivor holds no secret of the new epoch, and the durable
        // exclusion hold is active.
        {
            let groups = fx.replica.named_groups.read().await;
            let info = groups.get(&fx.group_id).context("group")?;
            assert!(
                info.shared_secret.is_none(),
                "the install is keyless: no secret of the new epoch"
            );
        }
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            1,
            "the exclusion hold is active"
        );
        let (status, body) = ng::secure_group_encrypt(
            axum::extract::State(std::sync::Arc::clone(&fx.replica)),
            axum::extract::Path(fx.group_id.clone()),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            axum::Json(ng::SecureEncryptRequest {
                payload_b64: base64::engine::general_purpose::STANDARD.encode(b"#1635 probe"),
            }),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::CONFLICT,
            "the keyless survivor's encrypt answers the typed 409, not the joiner's 424: {body:?}"
        );
        assert!(
            body["error"].as_str().is_some_and(
                |text| text.contains(ng::GroupCiphertextHold::PendingGssRemoval.reason())
            ),
            "the refusal is the hold's typed reason: {body:?}"
        );
        // The other side of the boundary (the review's P3): a member
        // with no secret and NO hold — a joiner awaiting its welcome
        // share — keeps the waiting answer, the 424. The hold is the
        // only thing that separates the two answers.
        let joiner_id = "e4".repeat(16);
        let mut joiner =
            x0x::groups::GroupInfo::new("e3".into(), String::new(), survivor, joiner_id.clone());
        joiner.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
        joiner.add_member(
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(survivor_hex.clone()),
            None,
        );
        // A joiner holds no secret: genesis seats the creator's secret,
        // and the welcome share has not arrived, so the seat waits.
        joiner.shared_secret = None;
        joiner.recompute_state_hash();
        fx.replica
            .named_groups
            .write()
            .await
            .insert(joiner_id.clone(), joiner);
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &joiner_id),
            0,
            "the joiner's group has no hold"
        );
        let (status, body) = ng::secure_group_encrypt(
            axum::extract::State(std::sync::Arc::clone(&fx.replica)),
            axum::extract::Path(joiner_id),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            axum::Json(ng::SecureEncryptRequest {
                payload_b64: base64::engine::general_purpose::STANDARD
                    .encode(b"#1635 joiner probe"),
            }),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::FAILED_DEPENDENCY,
            "a joiner with no hold keeps the waiting answer: {body:?}"
        );
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|text| text.contains("no shared secret available")),
            "the joiner's refusal names the welcome wait, not the hold: {body:?}"
        );
        Ok(())
    }

    /// #1578 review (Claude, 28 Oct): the keyless install writes its
    /// durable hold BEFORE the apply. If the apply is then refused — the
    /// snapshot the install seals by no longer chains, as a sibling
    /// commit under the same frame would leave it — the refusal must
    /// leave the durable hold in place: this node holds no secret of the
    /// new epoch, and the old one (which the excluded member still
    /// holds) must keep withholding new ciphertext, with no time limit,
    /// exactly as the wait path's hold (#1508/#1533 rc13). The hold is
    /// no dead end: a retry that chains installs, and the fixture test
    /// above ends its hold with the awaited share. `receive` refuses a
    /// stale frame before `install_gss` runs, so the test drives the
    /// install directly with a snapshot that does not chain.
    #[tokio::test]
    async fn a_refused_apply_after_the_hold_written_keeps_the_durable_hold() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture_build(None, false).await?;
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
        let decoded = ce::decode_frame(&frame).context("frame")?;
        let result_head = decoded.body.commit.state_hash.clone();
        let commit = decoded.body.commit.to_commit();
        let body = decoded.body.clone();
        let next_secret_epoch = match body.crypto {
            ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } => next_secret_epoch,
            _ => anyhow::bail!("the fixture commits the GSS form"),
        };
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
            .context("group")?;

        // The install runs with a snapshot the commit no longer applies
        // to (a sibling commit moved the revision past it): the hold is
        // written first, then the apply refuses.
        let mut stale = parent.clone();
        stale.state_revision = commit.revision + 1;
        let refused = install_gss(
            &fx.replica,
            &fx.group_id,
            &stale,
            &body,
            &commit,
            next_secret_epoch,
            Arc::new(frame.clone()),
        )
        .await;
        assert!(
            matches!(refused, ReceiveOutcome::Refused(_)),
            "the apply refuses (any refusal kind): the commit is stale against the snapshot"
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await,
            Some(parent.state_hash.clone()),
            "nothing installed on the refusal"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            1,
            "the durable hold stays: no secret of the new epoch exists here"
        );
        assert!(
            ng::gss_share_hold::test_seam::hold_file_exists(&fx.replica, &fx.group_id),
            "the hold outlives the refused apply on disk"
        );
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval),
            "the old secret keeps withholding new ciphertext after the refusal"
        );

        // The hold is no dead end: a retry that chains installs keyless
        // and keeps the hold until a share of the epoch arrives.
        assert_eq!(
            install_gss(
                &fx.replica,
                &fx.group_id,
                &parent,
                &body,
                &commit,
                next_secret_epoch,
                Arc::new(frame.clone()),
            )
            .await,
            ReceiveOutcome::Applied,
            "the retry that chains installs"
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await,
            Some(result_head),
            "the keyless install moves the head"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            1,
            "the keyless install keeps the hold until a share arrives"
        );
        Ok(())
    }

    /// #1578 review: the other direction of the divergent seat view. The
    /// author's view of the survivor's seat holds no KEM key (for
    /// example after an outbound snapshot that strips KEM keys) while
    /// the survivor's own copy has it, so the survivor takes the
    /// wait-for-share path and the frame stays stashed at the parent
    /// head. Under ADR 0110 §3 L228 (Engineer ruling, 27 Oct 22:10 GMT)
    /// the send's transport ACK closes nothing: the author's row stays
    /// open — it owes a share it cannot seal until its view learns the
    /// key — so it keeps resending, and the row completes only when the
    /// seat gains a key and the sealed share installs.
    #[tokio::test]
    async fn an_unsealable_seat_keeps_the_authors_row_open_while_the_keyed_survivor_waits(
    ) -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture_views(None, false, true).await?;
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
        let decoded = ce::decode_frame(&frame).context("frame")?;
        let result_head = decoded.body.commit.state_hash.clone();
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let admin = fx.state.agent.agent_id();
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        // The author's view of the seat carries no KEM key, so it sealed
        // no share and recorded the skip instead.
        assert!(
            shares_for(&fx.state, &survivor_hex).is_empty(),
            "the author never sealed a share: its view of the seat has no KEM key"
        );

        // The survivor's own view seats its key, so the verified frame
        // waits for its sealed share: nothing installs, the head stays.
        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        let head_before = head_of(&fx.replica, &fx.group_id)
            .await
            .context("the head")?;
        let outcome = receive(&fx.replica, admin, &frame).await;
        assert_eq!(
            outcome,
            ReceiveOutcome::WaitingForShare,
            "the keyed survivor takes the wait-for-share path"
        );
        assert!(
            outcome.is_retained() && outcome.head_evidence(),
            "the waiting frame stays retained head evidence: the listener stashes it until the share arrives"
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await.as_deref(),
            Some(head_before.as_str()),
            "nothing installs before the share"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            1,
            "the waiting survivor holds: no new ciphertext until the share installs"
        );

        // The waiting survivor still holds the old secret, so its served
        // answer keeps the field's existing meaning: its saved head, the
        // parent. Fed to the author, that real head converges nothing —
        // the row needs the result head, which only an installed share
        // proves.
        let served = served_responder_head(&fx.replica, admin, &fx.group_id).await?;
        assert_eq!(
            served.as_deref(),
            Some(head_before.as_str()),
            "a waiting node with a secret reports its saved head"
        );
        assert_ne!(
            served.as_deref(),
            Some(result_head.as_str()),
            "the stranded survivor does not hold the result head"
        );
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            served.as_deref(),
        )
        .await;

        // ADR 0110 §3 L228 (Engineer ruling, 27 Oct 22:10 GMT): the
        // carrier's acceptance of the frame is Sent, not delivery. The
        // author cannot seal this seat, but the ACK closes nothing and
        // the row stays open, so a later view that learns the key seals
        // and completes the row.
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        assert_eq!(
            delivery_status(&fx.state, &key, &survivor).await,
            Some(RecipientDelivery::Sent),
            "the transport ACK leaves the seat Sent, never Converged"
        );
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            assert!(
                inner.ce.delivering().contains(&key),
                "the row stays open: the author still owes a share it cannot seal"
            );
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::CommittedDeliveryPending),
                "the obligation is not falsely complete while the survivor waits"
            );
        }
        assert_ne!(
            head_of(&fx.replica, &fx.group_id).await.as_deref(),
            Some(result_head.as_str()),
            "the stranded survivor: its view holds the key, the frame still waits for the share, and the author's row stays open"
        );
        Ok(())
    }

    /// #1578 round 1, Claude P1/P2 (Engineer ruling, 27 Oct 22:10 GMT):
    /// the KEM key of a roster seat is local data — not in the roster
    /// root or the state hash — so the author and the survivor can
    /// disagree about the seat. Here the author's view seats the
    /// survivor's KEM key and seals the share, while the survivor's own
    /// copy shows no key, so it installs the frame keyless. That local
    /// keyless fact must not end the author's re-seal obligation: the
    /// survivor's catch-up answer claims no head at all (the real serve
    /// path), the author's delivery row stays open and keeps the share
    /// owed, and only the installed share — whose report is then the
    /// result head, a share-proof — ends it.
    #[tokio::test]
    async fn a_divergent_seat_view_keyless_install_keeps_the_authors_row_open() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture_views(None, true, false).await?;
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
        let decoded = ce::decode_frame(&frame).context("frame")?;
        let result_head = decoded.body.commit.state_hash.clone();
        let ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } = decoded.body.crypto else {
            anyhow::bail!("the fixture commits the GSS form");
        };
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let admin = fx.state.agent.agent_id();
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        // The author's view seats the KEM key, so it owes this seat a
        // sealed share and never records a skip for it.
        assert!(
            !shares_for(&fx.state, &survivor_hex).is_empty(),
            "the author sealed the share: its view of the seat carries the KEM key"
        );

        // The survivor's own view shows no KEM key for its seat, so it
        // installs the verified frame keyless.
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
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied,
            "the divergent-view survivor installs the verified frame keyless (#1578)"
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await.as_deref(),
            Some(result_head.as_str()),
            "the head moves"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            1,
            "the keyless install keeps the durable share hold"
        );

        // The survivor's real catch-up answer claims no head at all
        // while it holds no secret of the epoch: the local keyless fact
        // never reaches the author as convergence evidence.
        let reported = served_responder_head(&fx.replica, admin, &fx.group_id).await?;
        assert_ne!(
            reported.as_deref(),
            Some(result_head.as_str()),
            "the keyless survivor never reports the installed result"
        );
        assert_eq!(
            reported, None,
            "the answer claims no head while the responder is keyless (the field keeps its saved-head meaning)"
        );

        // The author takes that answer: its row stays open. The re-seal
        // obligation continues — the share is still owed — and the row
        // does not complete from the keyless install.
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            reported.as_deref(),
        )
        .await;
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            assert!(
                inner.ce.delivering().contains(&key),
                "a keyless install of a seat the author sealed converges nothing"
            );
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::CommittedDeliveryPending),
                "the author's re-seal obligation stays open"
            );
        }

        // The owed share installs — sealed to the KEM key the author sees,
        // decrypted with the keypair the survivor always held: the hold
        // ends, the report becomes the result head, and that share-proof,
        // not the keyless install, ends the delivery.
        let share = shares_for(&fx.state, &survivor_hex)
            .pop()
            .context("the author's sealed share")?;
        let took =
            ng::apply_named_group_metadata_event(&fx.replica, share, admin, true, None).await;
        assert!(took.accepted, "the owed share installs: {took:?}");
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&fx.replica, &fx.group_id),
            0,
            "the share's prune dropped the keyless hold from memory"
        );
        assert!(
            !ng::gss_share_hold::test_seam::hold_file_exists(&fx.replica, &fx.group_id),
            "the share's prune wrote the hold file: no residue survives it"
        );
        let sealed_info = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        assert_eq!(sealed_info.secret_epoch, next_secret_epoch);
        assert!(
            sealed_info.shared_secret.is_some(),
            "the survivor holds the rotated secret"
        );
        let reported = served_responder_head(&fx.replica, admin, &fx.group_id).await?;
        assert_eq!(
            reported.as_deref(),
            Some(result_head.as_str()),
            "with the share held the report is the result head again: a share-proof"
        );
        super::super::note_catchup_head(
            &fx.state,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            reported.as_deref(),
        )
        .await;
        assert_eq!(
            delivery_status(&fx.state, &key, &survivor).await,
            Some(RecipientDelivery::Converged),
            "the share-proof report converges the seat the author sealed"
        );
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&fx.state, &key, &survivor).await;
        super::super::revocation_eviction_pass(&fx.state).await;
        {
            let inner = fx.state.revocation_evictions.inner.lock().await;
            assert!(
                !inner.ce.delivering().contains(&key),
                "the confirmed share ends the delivery"
            );
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::Complete),
                "the obligation completes on the share-proof report"
            );
        }
        Ok(())
    }

    /// #1578, restart case: the keyless install persists (the group state
    /// and the durable share hold file), a restarted survivor still holds
    /// the result head with no secret and no pending frame, and a share
    /// that arrives after the restart installs and ends the hold.
    #[tokio::test]
    async fn a_keyless_gss_install_survives_a_restart() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture_build(None, false).await?;
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
        let decoded = ce::decode_frame(&frame).context("frame")?;
        let result_head = decoded.body.commit.state_hash.clone();
        let next_revision = decoded.body.next_revision;
        let ce::CryptoExclusionCryptoV1::Gss { next_secret_epoch } = decoded.body.crypto else {
            anyhow::bail!("the fixture commits the GSS form");
        };
        let new_secret = fx
            .state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .and_then(|info| info.shared_secret.clone())
            .context("the rotated secret")?;
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
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied,
            "the keyless survivor installs the verified frame (#1578)"
        );

        // The survivor restarts while the share is still awaited.
        let mut restarted = ng::tests::secure_endpoint_test_state_at(
            fx._replica_dir.path(),
            Arc::clone(&fx.replica.agent),
        )
        .await?;
        Arc::get_mut(&mut restarted)
            .context("the restarted state is not shared yet")?
            .agent_kem_keypair = Arc::clone(&fx.replica.agent_kem_keypair);
        assert_eq!(
            head_of(&restarted, &fx.group_id).await,
            Some(result_head.clone())
        );
        {
            let installed = restarted
                .named_groups
                .read()
                .await
                .get(&fx.group_id)
                .cloned()
                .context("group")?;
            assert_eq!(
                installed.secret_epoch, next_secret_epoch,
                "the keyless install is durable"
            );
            assert!(installed.shared_secret.is_none(), "still keyless");
        }
        assert_eq!(
            ng::group_ciphertext_withheld(&restarted, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval),
            "the durable hold keeps withholding after the restart"
        );
        // The boot load and the stash retry leave the installed frame
        // resolved: nothing is pending, and the head does not move back.
        super::super::load_persisted_obligations(&restarted).await;
        retry_stash(&restarted).await;
        assert_eq!(
            head_of(&restarted, &fx.group_id).await,
            Some(result_head.clone()),
            "no pending frame after the restart"
        );
        {
            let inner = restarted.revocation_evictions.inner.lock().await;
            assert!(!inner
                .ce
                .stash_ahead(&fx.stable, next_revision.saturating_sub(1)));
        }

        // #1578 rc3 (review finding 1): the head claim must not depend on
        // the hold file. A hold write that fails, followed by a restart,
        // leaves the keyless install with no hold in memory or on disk —
        // and the restarted node still claims no head, because the
        // keyless state lives in the saved group state (no secret of the
        // epoch, no KEM key on its own seat). Before the fix the missing
        // hold turned the claim back into the keyless result head: false
        // proof of delivery, and the author's row converged with no
        // share ever sealed to this survivor.
        ng::gss_share_hold::test_seam::simulate_restart(&restarted).await;
        std::fs::remove_file(ng::gss_share_hold::test_seam::hold_path_for(
            &restarted,
            &fx.group_id,
        ))
        .ok();
        assert!(
            !ng::gss_share_hold::test_seam::hold_file_exists(&restarted, &fx.group_id),
            "the hold is gone, as a failed write and a restart leave it"
        );
        assert_eq!(
            served_responder_head(&restarted, admin, &fx.group_id).await?,
            None,
            "no hold anywhere, still no head claim: the installed GSS head keeps implying its key"
        );

        // The share arrives after the restart and ends the hold.
        let survivor_hex = hex::encode(fx.replica.agent.agent_id().as_bytes());
        let secret: [u8; 32] = new_secret.as_slice().try_into().context("secret bytes")?;
        let share = ng::build_secure_share_event(
            &fx.stable,
            &survivor_hex,
            &base64::engine::general_purpose::STANDARD
                .encode(&restarted.agent_kem_keypair.public_bytes),
            &hex::encode(admin.as_bytes()),
            &secret,
            next_secret_epoch,
        )
        .map_err(|error| anyhow::anyhow!("seal the share: {error:?}"))?;
        let took = ng::apply_named_group_metadata_event(&restarted, share, admin, true, None).await;
        assert!(
            took.accepted,
            "the restarted survivor takes the share: {took:?}"
        );
        assert_eq!(
            ng::group_ciphertext_withheld(&restarted, &fx.group_id, None).await,
            None,
            "the installed share ends the hold"
        );
        assert_eq!(
            ng::gss_share_hold::test_seam::held_exclusions(&restarted, &fx.group_id),
            0,
            "the share's prune dropped the hold from memory after the restart"
        );
        assert!(
            !ng::gss_share_hold::test_seam::hold_file_exists(&restarted, &fx.group_id),
            "the share's prune wrote the hold file after the restart"
        );
        let installed = restarted
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        assert_eq!(installed.secret_epoch, next_secret_epoch);
        assert_eq!(
            installed.shared_secret.as_deref(),
            Some(new_secret.as_slice()),
            "the restarted survivor holds the rotated secret"
        );
        let reported = served_responder_head(&restarted, admin, &fx.group_id).await?;
        assert_eq!(
            reported.as_deref(),
            Some(result_head.as_str()),
            "after the share installs the restarted survivor reports the result head"
        );
        Ok(())
    }

    /// #1578 rc3 (review finding 4): main's answer for a group this
    /// responder does not know is a present, empty `responder_state_hash`.
    /// The page is reachable through the `target_of_cached_add` path: the
    /// responder witnessed the requester's add (the event log holds it)
    /// but holds no group state of its own. The served field must stay
    /// `Some("")`, exactly main's answer — the keyless absence never
    /// leaks into the unknown-group reply.
    #[tokio::test]
    async fn an_unknown_group_serves_a_present_empty_responder_state_hash() -> Result<()> {
        use anyhow::Context as _;
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let requester = state.agent.agent_id();
        let requester_hex = hex::encode(requester.as_bytes());
        let group_id = "d4".repeat(16);
        // The responder witnessed the add (so the request passes the
        // authorization gate) but has no group state for it.
        state.treekem_event_log.write().await.insert(
            group_id.clone(),
            vec![ng::NamedGroupMetadataEvent::MemberAdded {
                roster_certificates_b64: Vec::new(),
                group_id: group_id.clone(),
                revision: 1,
                actor: requester_hex.clone(),
                agent_id: requester_hex.clone(),
                display_name: None,
                treekem_commit_b64: None,
                treekem_welcome_b64: None,
                welcome_ref: None,
                treekem_epoch: None,
                treekem_key_package_hash: None,
                member_joined_recovery: None,
                member_recovery_history: Vec::new(),
                certificate_b64: None,
                owner_mandate: None,
                commit: None,
                reseat_mandate: None,
            }]
            .into(),
        );
        ng::handle_treekem_catchup_request(
            &state,
            &requester,
            &clean_sender_machine(),
            true,
            ng::TreeKemCatchupRequest {
                message_type: "treekem_catchup_request".to_string(),
                group_id: group_id.clone(),
                requester_agent_id: requester_hex,
                from_revision: 0,
                from_treekem_epoch: 0,
                current_state_hash: String::new(),
                missing_prev_state_hash: None,
                target_member_id: None,
                limit: 64,
            },
        )
        .await;
        let served = state
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .context("the catch-up answer was served")?;
        let page: ng::TreeKemCatchupResponse = serde_json::from_slice(&served)?;
        assert_eq!(
            page.responder_state_hash,
            Some(String::new()),
            "an unknown group keeps main's answer: a present, empty saved head"
        );
        Ok(())
    }

    /// #1578, the author's restart (Engineer ruling, 27 Oct 22:10 GMT):
    /// the persisted roster still seats the survivor with no KEM key,
    /// so the restarted author cannot seal to it. The survivor's seat is
    /// keyless in its own copy too, but it holds the old secret at the
    /// parent head, so it is no keyless survivor of the ruling — a node
    /// that holds a secret vouches for the head it holds, and its served
    /// answer is that saved head, a head the author's row cannot
    /// converge on (only the result head, which an installed share
    /// proves, does that). The resumed delivery sends the frame again,
    /// the carrier accepts it, and nothing closes: a transport ACK never
    /// closes a seat (ADR 0110 §3 L228). The row stays open across the
    /// author's restart, until the seat re-joins with a verified KEM
    /// binding and a sealed share installs.
    #[tokio::test]
    async fn a_restarted_author_keeps_an_unsealable_seat_row_open() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture_build(None, false).await?;
        // No advert before the commit: nothing sends yet, so the row is
        // still mid-delivery at the restart.
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
        let _ = &frame; // the commit's frame exists; the restart resends it

        // The author restarts mid-delivery. The row and its frame persist,
        // the delivery resumes, and the durable roster still seats the
        // survivor with no KEM key.
        let mut restarted =
            ng::tests::secure_endpoint_test_state_at(fx.dir.path(), Arc::clone(&fx.state.agent))
                .await?;
        super::super::zero_restart_wait_for_test(&mut restarted);
        super::super::load_persisted_obligations(&restarted).await;
        let key = EvictionKey::new(fx.stable.clone(), *fx.leaver.as_bytes());
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        {
            let inner = restarted.revocation_evictions.inner.lock().await;
            assert!(
                inner.ce.delivering().contains(&key),
                "the saved frame's delivery resumes"
            );
        }
        let seated = restarted
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        assert!(
            seated.active_members().any(
                |member| member.agent_id == survivor_hex && member.kem_public_key_b64.is_none()
            ),
            "the persisted roster still seats the survivor with no KEM key"
        );

        // The restarted author runs its rounds. The survivor still holds
        // the old secret at a head behind the result (its keyless seat
        // changes nothing: a node that holds a secret vouches for the
        // head it holds), so its real served answer is exactly that
        // saved head — a head the author's row cannot converge on (only
        // the result head, which an installed share proves, does that).
        // The head round still syncs on the restart wait, and the
        // resumed send's acceptance leaves the seat Sent — never
        // Converged.
        advertise_crypto_exclusion(&restarted, survivor);
        restarted
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        super::super::revocation_eviction_pass(&restarted).await;
        let served =
            served_responder_head(&fx.replica, fx.state.agent.agent_id(), &fx.group_id).await?;
        let survivor_saved_head = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .map(|info| info.state_hash.clone())
            .context("the survivor's group")?;
        assert_eq!(
            served.as_deref(),
            Some(survivor_saved_head.as_str()),
            "the survivor holds a secret, so its answer keeps the field's saved-head meaning"
        );
        super::super::note_catchup_head(
            &restarted,
            std::slice::from_ref(&fx.group_id),
            &survivor_hex,
            served.as_deref(),
        )
        .await;
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&restarted, &key, &survivor).await;
        assert_eq!(
            delivery_status(&restarted, &key, &survivor).await,
            Some(RecipientDelivery::Sent),
            "the resumed send's acceptance is Sent: an ACK closes no seat"
        );
        tokio::time::sleep(CE_RESEND_INTERVAL + Duration::from_millis(100)).await;
        delivery_round(&restarted, &key, &survivor).await;
        super::super::revocation_eviction_pass(&restarted).await;
        {
            let inner = restarted.revocation_evictions.inner.lock().await;
            assert!(
                inner.ce.delivering().contains(&key),
                "the delivery stays open across the author's restart"
            );
            assert_eq!(
                inner.store.get(&key).map(|row| row.phase),
                Some(Phase::CommittedDeliveryPending),
                "the restarted author owes the share until the seat can take one"
            );
        }
        Ok(())
    }

    /// #1578 rc4 (Engineer ruling, 28 Oct 09:35 GMT; Claude blocking 1,
    /// Codex P2 on #1635): a SignedPublic group is GSS-plane by default
    /// and holds no secret and no seat KEM key by design, so an
    /// invite-joined member is not a keyless survivor. The rc3
    /// predicate matched every such member, disclaimed its head for
    /// ever, and left its S4 rows no survivor-convergence evidence. The
    /// confidentiality check keeps main's answer: the member serves its
    /// saved head, and that served answer feeds `note_survivor_head`
    /// and confirms the head round. This test fails if the check is
    /// dropped.
    #[tokio::test]
    async fn a_signed_public_member_serves_its_head_and_feeds_survivor_convergence() -> Result<()> {
        use x0x::groups::{GroupPolicy, GroupRole};
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let (replica, _replica_dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let admin_hex = hex::encode(admin.as_bytes());
        let member = replica.agent.agent_id();
        let member_hex = hex::encode(member.as_bytes());
        let group_id = "d1".repeat(16);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "signed-public".into(),
            String::new(),
            admin,
            group_id.clone(),
            GroupPolicy {
                confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
                ..GroupPolicy::default()
            },
        );
        assert_eq!(info.secure_plane, x0x::mls::SecureGroupPlane::Gss);
        assert!(
            info.shared_secret.is_none(),
            "a SignedPublic group holds no secret by design"
        );
        // The invite-joined member's seat carries no KEM key (the
        // roster projection seats none): the rc3 predicate's other three
        // inputs all hold.
        info.add_member(member_hex.clone(), GroupRole::Member, Some(admin_hex), None);
        assert!(
            info.active_members()
                .any(|seat| seat.agent_id == member_hex && seat.kem_public_key_b64.is_none()),
            "the member's seat is seated with no KEM key, as a projection seats it"
        );
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        replica
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        // The author owes a delivery whose result is the shared head.
        let key = EvictionKey::new(stable.clone(), [0x11; 32]);
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .deliveries
            .insert(
                key.clone(),
                CeDelivery {
                    bytes: Arc::new(Vec::new()),
                    result_head: info.state_hash.clone(),
                    next_revision: 1,
                    resumed: false,
                    gss_shares_pending: false,
                    gss_epoch: None,
                    share_went_to: BTreeMap::new(),
                    recipients: [(*member.as_bytes(), RecipientDelivery::Due)]
                        .into_iter()
                        .collect(),
                    next_at: Instant::now(),
                },
            );
        // The worker keeps a head round only for groups with open work;
        // the delivery row above is that work, so the round exists.
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .head_rounds
            .insert(
                stable.clone(),
                super::super::HeadRound {
                    head: info.state_hash.clone(),
                    started: Instant::now(),
                    asked: std::collections::BTreeSet::new(),
                    confirmed: false,
                    conflicting: std::collections::BTreeSet::new(),
                },
            );
        // The real served answer of the SignedPublic member.
        let served = served_responder_head(&replica, admin, &group_id).await?;
        assert_eq!(
            served.as_deref(),
            Some(info.state_hash.as_str()),
            "a SignedPublic member keeps main's answer: its saved head"
        );
        super::super::note_catchup_head(
            &state,
            std::slice::from_ref(&group_id),
            &member_hex,
            served.as_deref(),
        )
        .await;
        assert_eq!(
            delivery_status(&state, &key, &member).await,
            Some(RecipientDelivery::Converged),
            "the served answer feeds note_survivor_head: the seat converges"
        );
        assert!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .head_rounds
                .get(&stable)
                .is_some_and(|round| round.confirmed),
            "the served answer confirms the head round"
        );
        Ok(())
    }

    /// #1578 rc4 (Claude blocking 1): an `MlsEncrypted` joiner that
    /// still waits for its welcome share holds no secret and its own
    /// seat is not an Active keyless seat — the joiner's stub does not
    /// seat it at all; the seat arrives with the KEM key its
    /// `MemberJoined` published. It is not a keyless survivor either:
    /// its served answer keeps main's meaning and feeds
    /// `note_survivor_head` while the share is still on its way.
    #[tokio::test]
    async fn an_encrypted_group_joiner_waiting_for_its_share_serves_its_head() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let (joiner, _joiner_dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let member = joiner.agent.agent_id();
        let member_hex = hex::encode(member.as_bytes());
        let group_id = "d2".repeat(16);
        let mut info = x0x::groups::GroupInfo::new(
            "waiting-joiner".into(),
            String::new(),
            admin,
            group_id.clone(),
        );
        assert_eq!(info.secure_plane, x0x::mls::SecureGroupPlane::Gss);
        // The joiner's stub: the committed base the invite carried seats
        // everyone but the joiner (its seat arrives with the KEM key its
        // own `MemberJoined` published), and no secret is kept — the
        // authority's sealed share delivers it. The secret and its epoch
        // are local data: the saved head is the base head unchanged.
        let mut stub = info.clone();
        stub.shared_secret = None;
        stub.secret_epoch = 5;
        // The sender of the report below is a live member of the author's
        // roster only (#1660): production's response handler refuses a
        // non-member's answer before it reaches `note_catchup_head`, and
        // the completion step re-checks the seat the same way. The
        // author's copy seats the joiner with the KEM key its
        // `MemberJoined` published; the joiner's own stub does not seat
        // it at all.
        info.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
        let member_kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
        info.set_member_kem_public_key(
            &member_hex,
            base64::engine::general_purpose::STANDARD.encode(&member_kem.public_bytes),
        );
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        assert!(
            !super::own_seat_cannot_take_a_share(&joiner, &stub),
            "the waiting joiner's own seat is not an Active keyless seat"
        );
        joiner
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), stub);
        // The author owes a delivery whose result is the shared head.
        let key = EvictionKey::new(stable, [0x22; 32]);
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .deliveries
            .insert(
                key.clone(),
                CeDelivery {
                    bytes: Arc::new(Vec::new()),
                    result_head: info.state_hash.clone(),
                    next_revision: 1,
                    resumed: false,
                    gss_shares_pending: false,
                    gss_epoch: None,
                    share_went_to: BTreeMap::new(),
                    recipients: [(*member.as_bytes(), RecipientDelivery::Due)]
                        .into_iter()
                        .collect(),
                    next_at: Instant::now(),
                },
            );
        // The real served answer of the waiting joiner.
        let served = served_responder_head(&joiner, admin, &group_id).await?;
        assert_eq!(
            served.as_deref(),
            Some(info.state_hash.as_str()),
            "a waiting joiner keeps main's answer: its saved head"
        );
        super::super::note_catchup_head(
            &state,
            std::slice::from_ref(&group_id),
            &member_hex,
            served.as_deref(),
        )
        .await;
        assert_eq!(
            delivery_status(&state, &key, &member).await,
            Some(RecipientDelivery::Converged),
            "the served answer feeds note_survivor_head: the seat converges"
        );
        Ok(())
    }

    /// #1508 rc13 (Codex P1): the actor A of a GSS crypto-only exclusion
    /// promotes B and goes offline. A lagging survivor catches up from B
    /// only: the frame that B relays, A's signed promotion (it does not
    /// chain here yet) and B's share of the new secret (refused while B is
    /// a Member here). The survivor must install the frame with B's
    /// secret, chain the promotion and end at A's promotion head with the
    /// new secret. Before the fix the frame
    /// waited for a share from an admin and B's share waited for the
    /// promotion, for ever. B's share alone, with no commit of the actor
    /// on the frame's result, still installs nothing.
    #[tokio::test]
    async fn a_gss_exclusion_catchup_from_a_later_admin_reaches_its_head() -> Result<()> {
        use anyhow::Context as _;
        let b = x0x::identity::AgentKeypair::generate()?.agent_id();
        let b_hex = hex::encode(b.as_bytes());
        let fx = gss_leave_fixture_with(Some(b)).await?;
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
        let excluded = fx
            .state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        let new_secret = excluded.shared_secret.clone().context("new secret")?;
        let survivor_hex = hex::encode(fx.replica.agent.agent_id().as_bytes());
        let admin = fx.state.agent.agent_id();
        let admin_hex = hex::encode(admin.as_bytes());

        // A promotes B on the exclusion's result, then goes offline.
        let mut promoted = excluded.clone();
        promoted.set_member_role(&b_hex, x0x::groups::GroupRole::Admin);
        promoted.roster_revision = promoted.roster_revision.saturating_add(1);
        let revision = promoted.roster_revision;
        let commit = promoted.seal_commit(
            fx.state.agent.identity().agent_keypair(),
            ng::now_millis_u64(),
        )?;
        let promotion = ng::NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: fx.group_id.clone(),
            revision,
            actor: admin_hex,
            agent_id: b_hex.clone(),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(commit),
        };
        // B seals its current secret (the exclusion's) to the survivor.
        let mut b_share = shares_for(&fx.state, &survivor_hex)
            .pop()
            .context("a share for the survivor")?;
        let ng::NamedGroupMetadataEvent::SecureShareDelivered { actor, .. } = &mut b_share else {
            anyhow::bail!("not a share");
        };
        *actor = b_hex;

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
            receive(&fx.replica, b, &frame).await,
            ReceiveOutcome::WaitingForShare
        );
        // The worker keeps the waiting frame, as `spawn_receipt` does.
        fx.replica
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .stash
            .push(stashed(b, frame.clone(), true).context("decode")?);
        let refused =
            ng::apply_named_group_metadata_event(&fx.replica, b_share.clone(), b, true, None).await;
        assert!(!refused.accepted, "B is a Member here: {refused:?}");
        retry_stash(&fx.replica).await;
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await,
            parent,
            "a share from a Member alone installs nothing"
        );
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval)
        );

        let refused =
            ng::apply_named_group_metadata_event(&fx.replica, promotion, admin, true, None).await;
        assert!(!refused.accepted, "the promotion does not chain yet");
        retry_stash(&fx.replica).await;
        let reached = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        assert_eq!(
            reached.state_hash, promoted.state_hash,
            "the survivor reaches A's promotion head"
        );
        assert_eq!(
            reached.shared_secret.as_deref(),
            Some(new_secret.as_slice()),
            "with B's share of the new secret"
        );
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            None
        );
        Ok(())
    }

    /// #1576: the catch-up GSS share step of [`serve_catchup`]. An admin
    /// that serves a held GSS exclusion frame to a catch-up requester
    /// also seals its current secret to that requester (#1508 review P1:
    /// the frame alone moves the requester's epoch without the secret).
    /// No test reached the step: an offline admin's frame send fails
    /// first — the in-process stand-in reports an admitted exchange with
    /// its marker error — so only the network path covered it.
    #[tokio::test]
    async fn a_gss_exclusion_catchup_serves_the_frame_and_seals_the_share() -> Result<()> {
        use anyhow::Context as _;
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
            .context("the GSS crypto-only exclusion committed")?;
        let committed = fx
            .state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        let new_secret = committed.shared_secret.clone().context("new secret")?;

        // A survivor behind the exclusion: it took the leave, and then
        // asks the committer for a catch-up from that revision.
        let applied = ng::apply_named_group_metadata_event(
            &fx.replica,
            fx.leave.clone(),
            fx.leaver,
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "{applied:?}");
        let ng::NamedGroupMetadataEvent::MemberRemoved { revision, .. } = &fx.leave else {
            anyhow::bail!("the fixture's leave is a MemberRemoved");
        };
        let survivor = fx.replica.agent.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        advertise_crypto_exclusion(&fx.state, survivor);

        let before = shares_for(&fx.state, &survivor_hex).len();
        serve_catchup(
            &fx.state,
            &survivor,
            std::slice::from_ref(&fx.stable),
            *revision,
        )
        .await;
        let sealed = shares_for(&fx.state, &survivor_hex);
        anyhow::ensure!(
            sealed.len() > before,
            "the serving admin seals a share to the catch-up requester"
        );

        // The sealed share is the current secret: the served frame, which
        // waits for it, installs with it and moves the survivor to the
        // new head and secret.
        let admin = fx.state.agent.agent_id();
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::WaitingForShare
        );
        let _ = ng::apply_named_group_metadata_event(
            &fx.replica,
            sealed.last().cloned().context("the sealed share")?,
            admin,
            true,
            None,
        )
        .await;
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied,
            "the catch-up share installs the served frame"
        );
        let held = fx
            .replica
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        assert_eq!(held.state_hash, committed.state_hash);
        assert_eq!(held.secret_epoch, committed.secret_epoch);
        assert_eq!(
            held.shared_secret.as_deref(),
            Some(new_secret.as_slice()),
            "the catch-up share carries the current secret"
        );
        Ok(())
    }

    /// #1508 rc13 (Codex P1): the share is lost and A then commits a
    /// same-epoch rename on the exclusion's result. A's delivery stays open
    /// across that commit, and a survivor head at the rename result would
    /// end it. So the survivor must not install the exclusion without its
    /// key: it stays at the parent, holding sends. Before the fix the held
    /// rename made the exclusion install as a keyless intermediate head.
    #[tokio::test]
    async fn a_lost_gss_exclusion_share_with_a_later_rename_keeps_the_parent() -> Result<()> {
        use anyhow::Context as _;
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
            .context("the GSS crypto-only exclusion committed")?;
        let excluded = fx
            .state
            .named_groups
            .read()
            .await
            .get(&fx.group_id)
            .cloned()
            .context("group")?;
        let admin = fx.state.agent.agent_id();
        let mut renamed = excluded.clone();
        renamed.name = "renamed".to_string();
        let commit = renamed.seal_commit(
            fx.state.agent.identity().agent_keypair(),
            ng::now_millis_u64(),
        )?;
        let rename = ng::NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: fx.group_id.clone(),
            revision: renamed.roster_revision,
            actor: hex::encode(admin.as_bytes()),
            name: Some("renamed".to_string()),
            description: None,
            commit: Some(commit),
        };

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
            ReceiveOutcome::WaitingForShare
        );
        fx.replica
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .stash
            .push(stashed(admin, frame.clone(), true).context("decode")?);
        let refused =
            ng::apply_named_group_metadata_event(&fx.replica, rename, admin, true, None).await;
        assert!(!refused.accepted, "the rename does not chain yet");
        retry_stash(&fx.replica).await;
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await,
            parent,
            "no head past the exclusion without its key"
        );
        assert_eq!(
            ng::group_ciphertext_withheld(&fx.replica, &fx.group_id, None).await,
            Some(ng::GroupCiphertextHold::PendingGssRemoval)
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

    /// Seed a live legacy MLS view for `fx`'s group on `state`: the local
    /// agent and the leaver, the listing a process holds when its MLS
    /// mirror saw both seats (#1580).
    async fn seeded_legacy_mls_view(fx: &GssLeave, state: &Arc<AppState>) -> Result<()> {
        let mut mls =
            x0x::mls::MlsGroup::new(hex::decode(&fx.group_id)?, state.agent.agent_id()).await?;
        mls.add_member(fx.leaver).await?;
        state
            .mls_groups
            .write()
            .await
            .insert(fx.group_id.clone(), mls);
        Ok(())
    }

    /// #1580: the GSS exclusion's local legacy MLS removal is an
    /// in-memory step after the durable roster write. A crash between the
    /// two leaves the received frame held in the `.celog` (its write ran
    /// before the install; the tail that unholds it did not) with the
    /// roster already at the result head — and the restart never
    /// re-receives that frame (the restore keeps an at-head received frame
    /// for serving only). The restarted receiver must still converge: the
    /// worker's stash pass reruns the removal from the durable roster, so
    /// the view no longer lists the removed member.
    #[tokio::test]
    async fn a_restart_reruns_the_gss_exclusions_legacy_mls_removal() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture().await?;
        let (frame, result_head, _parent) = authored_frame_and_parent(&fx).await?;
        let admin = fx.state.agent.agent_id();

        // The durable half of the flow ran on the receiver: the roster
        // reached the frame's result head (the replica took its share, so
        // the install is `Applied`). The replica holds no MLS view here,
        // so the install's own removal had nothing to do.
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await.as_deref(),
            Some(result_head.as_str())
        );
        assert!(
            ng::save_named_groups(&fx.replica).await,
            "the installed roster is durable"
        );

        // The crash residue: the frame is held in the `.celog` again, as
        // the write-before-install left it when the tail never ran.
        let decoded = ce::decode_frame(&frame).context("frame")?;
        let at = (
            decoded.body.next_revision,
            decoded.body.commit.state_hash.as_str(),
        );
        assert!(
            replay_log::write_received(
                &fx.replica,
                replay_log::CE_EXTENSION,
                held,
                &fx.stable,
                at,
                &Arc::new(frame.clone()),
            )
            .await,
            "the frame is held, as the crash left it"
        );

        // The receiver restarts from its data dir. Its session-scoped MLS
        // view is rebuilt and lists the removed member — the state the
        // crash left behind.
        let restarted = ng::tests::secure_endpoint_test_state_at(
            fx._replica_dir.path(),
            Arc::clone(&fx.replica.agent),
        )
        .await?;
        super::super::load_persisted_obligations(&restarted).await;
        seeded_legacy_mls_view(&fx, &restarted).await?;
        {
            let views = restarted.mls_groups.read().await;
            let view = views.get(&fx.group_id).context("the view")?;
            assert!(view.is_member(&fx.leaver));
            assert!(view.is_member(&restarted.agent.agent_id()));
        }

        // One worker stash pass converges the view with the durable
        // roster; the roster itself is unchanged.
        retry_stash(&restarted).await;
        assert_eq!(
            head_of(&restarted, &fx.group_id).await.as_deref(),
            Some(result_head.as_str()),
            "the convergence installs nothing new"
        );
        {
            let views = restarted.mls_groups.read().await;
            let view = views.get(&fx.group_id).context("the view")?;
            assert!(
                !view.is_member(&fx.leaver),
                "#1580: the removed member left the legacy MLS view"
            );
            assert!(
                view.is_member(&restarted.agent.agent_id()),
                "the survivor keeps its seat"
            );
        }
        Ok(())
    }

    /// #1580, the in-process form: a peer resends the exact durable frame
    /// after this node already installed it. The duplicate replay reruns
    /// the local legacy MLS removal, so a view that still lists the
    /// removed member (the crash between the durable write and the
    /// removal) converges on the resend.
    #[tokio::test]
    async fn a_duplicate_gss_exclusion_frame_reruns_the_legacy_mls_removal() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture().await?;
        let (frame, result_head, _parent) = authored_frame_and_parent(&fx).await?;
        let admin = fx.state.agent.agent_id();
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied
        );

        // The stale listing: the removal never ran on it.
        seeded_legacy_mls_view(&fx, &fx.replica).await?;
        {
            let views = fx.replica.mls_groups.read().await;
            let view = views.get(&fx.group_id).context("the view")?;
            assert!(view.is_member(&fx.leaver));
        }

        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Duplicate
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await.as_deref(),
            Some(result_head.as_str()),
            "the duplicate installs nothing new"
        );
        let views = fx.replica.mls_groups.read().await;
        let view = views.get(&fx.group_id).context("the view")?;
        assert!(
            !view.is_member(&fx.leaver),
            "#1580: the duplicate reran the legacy MLS removal"
        );
        assert!(
            view.is_member(&fx.replica.agent.agent_id()),
            "the survivor keeps its seat"
        );
        Ok(())
    }

    /// #1533 r6 (Codex P1 1), ADR 0109 §2 "Conflict": "Nothing past the
    /// common prefix applies" holds for an S4 crypto-only exclusion too.
    /// The survivor records an attestation conflict on the parent (no fork
    /// marker), then the valid GSS exclusion on that parent arrives: it is
    /// refused and the head does not move. Before the fix the exclusion
    /// receiver applied the commit without the conflict gate. Inert.
    #[tokio::test]
    async fn a_recorded_attestation_conflict_refuses_a_valid_exclusion() -> Result<()> {
        let fx = gss_leave_fixture().await?;
        let (frame, _result_head, parent) = authored_frame_and_parent(&fx).await?;
        anyhow::ensure!(
            ng::group_recovery::record_conflict_at_head_for_test(&fx.replica, &parent).await?,
            "the conflict is durable"
        );
        let admin = fx.state.agent.agent_id();
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Refused(ce::CryptoExclusionRefusal::GroupContained)
        );
        assert_eq!(
            head_of(&fx.replica, &fx.group_id).await.as_ref(),
            Some(&parent.state_hash),
            "nothing past the common prefix applies (crypto-only exclusion)"
        );
        Ok(())
    }

    /// #1580 rc2 (review, security): the Duplicate arm must not trust the
    /// frame's target. A stranger signs a frame whose commit hash is this
    /// node's head and whose target is an Active member. The replay is a
    /// duplicate, but the roster — not the frame — is authoritative, so
    /// the Active member stays in the legacy MLS view.
    #[tokio::test]
    async fn a_forged_duplicate_frame_never_drops_an_active_member() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture().await?;
        let (frame, _result_head, _parent) = authored_frame_and_parent(&fx).await?;
        let admin = fx.state.agent.agent_id();
        assert_eq!(
            receive(&fx.replica, admin, &frame).await,
            ReceiveOutcome::Applied
        );
        seeded_legacy_mls_view(&fx, &fx.replica).await?;
        let survivor_hex = hex::encode(fx.replica.agent.agent_id().as_bytes());
        assert!(
            fx.replica
                .named_groups
                .read()
                .await
                .get(&fx.group_id)
                .and_then(|info| info.members_v2.get(&survivor_hex))
                .is_some_and(|seat| seat.state == x0x::groups::GroupMemberState::Active),
            "the forged frame's target is an Active member"
        );

        // The stranger's frame: the head's own state (every component the
        // state hash commits to, copied from the installed commit), signed
        // by the stranger itself, with the Active survivor as the target.
        let stranger = x0x::identity::AgentKeypair::generate()?;
        let real = ce::decode_frame(&frame)
            .context("frame")?
            .body
            .commit
            .to_commit();
        let forged_commit = x0x::groups::state_commit::GroupStateCommit::sign(
            real.group_id.clone(),
            real.revision,
            real.prev_state_hash.clone(),
            real.roster_root.clone(),
            real.policy_hash.clone(),
            real.public_meta_hash.clone(),
            real.security_binding.clone(),
            real.withdrawn,
            real.committed_at,
            &stranger,
        )
        .context("the stranger signs the head's own state")?;
        assert_eq!(
            forged_commit.state_hash, real.state_hash,
            "the forged commit carries the head's state hash"
        );
        let mut forged_body = ce::decode_frame(&frame).context("frame")?.body;
        forged_body.actor = *stranger.agent_id().as_bytes();
        forged_body.target = *fx.replica.agent.agent_id().as_bytes();
        forged_body.commit = ce::CommitHeaderV1::from(&forged_commit);
        let forged = ce::sign(forged_body, &stranger).context("sign")?;
        let bytes = ce::encode_frame(&forged).context("encode")?;
        assert_eq!(
            receive(&fx.replica, stranger.agent_id(), &bytes).await,
            ReceiveOutcome::Duplicate,
            "the forged frame is a duplicate of the installed head"
        );

        let views = fx.replica.mls_groups.read().await;
        let view = views.get(&fx.group_id).context("the view")?;
        assert!(
            view.is_member(&fx.replica.agent.agent_id()),
            "an Active member the roster still seats never leaves the view"
        );
        Ok(())
    }

    /// #1580 rc3 (review, race): the GSS `MemberAdded` arm adds the view
    /// entry before it persists the roster, both under the group's
    /// membership lock. The convergence pass takes the same lock per
    /// group, so it can never run inside that window and drop the seat
    /// the re-add is about to seat: while the lock is held the pass
    /// removes nothing, and it converges once the lock frees.
    #[tokio::test]
    async fn the_legacy_mls_convergence_waits_for_the_group_membership_lock() -> Result<()> {
        use anyhow::Context as _;
        let fx = gss_leave_fixture().await?;
        let (_frame, _result_head, _parent) = authored_frame_and_parent(&fx).await?;
        // The author's roster holds the leaver Removed; its view lists it
        // — the mid-re-add shape the apply path builds under the lock.
        seeded_legacy_mls_view(&fx, &fx.state).await?;
        {
            let views = fx.state.mls_groups.read().await;
            assert!(views
                .get(&fx.group_id)
                .context("the view")?
                .is_member(&fx.leaver));
        }

        let holder = ng::group_membership_lock(&fx.state, &fx.group_id).await;
        let held = holder.lock().await;
        let pass_state = Arc::clone(&fx.state);
        let pass =
            tokio::spawn(async move { converge_legacy_mls_views_with_rosters(&pass_state).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        {
            let views = fx.state.mls_groups.read().await;
            assert!(
                views
                    .get(&fx.group_id)
                    .context("the view")?
                    .is_member(&fx.leaver),
                "the pass removes nothing while the group's membership lock is held"
            );
        }
        drop(held);
        pass.await.expect("the pass runs");
        {
            let views = fx.state.mls_groups.read().await;
            assert!(
                !views
                    .get(&fx.group_id)
                    .context("the view")?
                    .is_member(&fx.leaver),
                "the pass converges the view once the lock frees"
            );
        }
        Ok(())
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

    // ─── #1660: the completion step re-checks the live roster ──────────

    /// #1660 fixture: one author node with one GSS crypto-exclusion
    /// delivery whose only seat is `Sent` (a send the round planned while
    /// the sender was eligible), plus helpers to change the live roster
    /// mid-send and to feed a head report at the entry point the response
    /// handler uses.
    struct SeatReportFixture {
        state: Arc<AppState>,
        group_id: String,
        key: EvictionKey,
        survivor: AgentId,
        /// The survivor's own keypair. The D60 tests revoke the subject
        /// itself: an agent revocation verifies only against the
        /// subject's key.
        survivor_kp: x0x::identity::AgentKeypair,
        survivor_hex: String,
        result_head: String,
    }

    impl SeatReportFixture {
        /// The sender's seat state in the delivery row.
        async fn seat(&self) -> Option<RecipientDelivery> {
            self.state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ce
                .deliveries
                .get(&self.key)
                .and_then(|delivery| delivery.recipients.get(self.survivor.as_bytes()).copied())
        }

        /// Whether the delivery row is still open.
        async fn row_open(&self) -> bool {
            self.state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ce
                .deliveries
                .contains_key(&self.key)
        }

        /// Feed the sender's catch-up answer at the entry point the
        /// response handler calls.
        async fn feed_report(&self, reported: Option<&str>) {
            super::super::note_catchup_head(
                &self.state,
                std::slice::from_ref(&self.group_id),
                &self.survivor_hex,
                reported,
            )
            .await;
        }

        /// The mid-send removal: the seat left the live roster while the
        /// answer was on the wire; the removal's own commit has not
        /// chained yet, so the result head is still this node's head.
        async fn remove_sender_mid_send(&self) {
            self.set_sender_seat_state(x0x::groups::GroupMemberState::Removed)
                .await;
        }

        /// Put the sender's seat in `state`: the mid-send removal, ban or
        /// pending demotion. The delivery's own commit has not chained
        /// yet, so the result head is still this node's head.
        async fn set_sender_seat_state(&self, state: x0x::groups::GroupMemberState) {
            let mut groups = self.state.named_groups.write().await;
            let stored = groups.get_mut(&self.group_id).expect("the author's group");
            stored
                .members_v2
                .get_mut(&self.survivor_hex)
                .expect("the sender's seat")
                .state = state;
        }

        /// Seat a KEM public key on the sender's roster seat (the keyed
        /// re-join of the #1578 recovery).
        async fn key_sender_seat(&self, kem_b64: String) {
            let mut groups = self.state.named_groups.write().await;
            let stored = groups.get_mut(&self.group_id).expect("the author's group");
            stored.set_member_kem_public_key(&self.survivor_hex, kem_b64);
        }

        /// Record, as a sealing round does, a share of the row's epoch
        /// (2, the fixture's) sealed to the KEM key the seat carries now.
        /// No head ask has gone out since: the pre-seal-answer shape.
        async fn record_share_to_seat_key(&self) {
            let kem_b64 = {
                let groups = self.state.named_groups.read().await;
                groups
                    .get(&self.group_id)
                    .and_then(|info| info.members_v2.get(&self.survivor_hex))
                    .and_then(|member| member.kem_public_key_b64.clone())
                    .expect("the seat's KEM key")
            };
            note_share_went_to(
                &self.state,
                &self.key.stable_group_id,
                2,
                self.survivor.as_bytes(),
                &kem_b64,
            )
            .await;
        }

        /// Count one head ask to the sender since the seal (the next
        /// round's ask): the post-seal-answer shape (Engineer ruling,
        /// 29 Oct 17:12 GMT).
        async fn record_post_seal_ask(&self) {
            let mut inner = self.state.revocation_evictions.inner.lock().await;
            *inner
                .head_ask_seq
                .entry((self.key.stable_group_id.clone(), *self.survivor.as_bytes()))
                .or_insert(0) += 1;
        }

        /// The seat's live head-ask count — `None` until an ask that went
        /// out advanced it.
        async fn ask_count(&self) -> Option<u64> {
            self.state
                .revocation_evictions
                .inner
                .lock()
                .await
                .head_ask_seq
                .get(&(self.key.stable_group_id.clone(), *self.survivor.as_bytes()))
                .copied()
        }

        /// Wait until the round's send task recorded the sealed share
        /// for the sender ([`note_share_went_to`]) — the record a report
        /// closes against. The seat proves nothing meanwhile.
        async fn await_share_recorded(&self) {
            for _ in 0..250 {
                let recorded = {
                    let inner = self.state.revocation_evictions.inner.lock().await;
                    inner.ce.deliveries.get(&self.key).is_some_and(|delivery| {
                        delivery
                            .share_went_to
                            .contains_key(self.survivor.as_bytes())
                    })
                };
                if recorded {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            panic!("the round's sealed share was never recorded");
        }

        /// How many sealed shares were scheduled to the sender.
        async fn shares_to_sender(&self) -> usize {
            self.state
                .named_group_test_recorders
                .secure_share_scheduled
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .filter(|(_, recipient, _)| recipient == &self.survivor_hex)
                .count()
        }

        /// Run one delivery round now (no resend-interval wait).
        async fn round_now(&self) {
            self.state
                .revocation_evictions
                .inner
                .lock()
                .await
                .ce
                .deliveries
                .get_mut(&self.key)
                .expect("the delivery row")
                .next_at = tokio::time::Instant::now();
            drive_deliveries(&self.state).await;
        }
    }

    /// Build the #1660 fixture: an `MlsEncrypted` group whose rotated
    /// secret (epoch 2) the author holds, and a GSS frame delivery at
    /// that epoch whose result is the current head. The survivor starts
    /// `keyed` or keyless.
    async fn seat_report_fixture(keyed: bool) -> Result<SeatReportFixture> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let survivor_kp = x0x::identity::AgentKeypair::generate()?;
        let survivor = survivor_kp.agent_id();
        let survivor_hex = hex::encode(survivor.as_bytes());
        let group_id = "b6".repeat(16);
        let mut info = GroupInfo::new("b5".into(), String::new(), admin, group_id.clone());
        info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
        info.add_member(
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
        if keyed {
            let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
            info.set_member_kem_public_key(
                &survivor_hex,
                base64::engine::general_purpose::STANDARD.encode(&kem.public_bytes),
            );
        }
        info.secret_epoch = 2;
        info.shared_secret = Some(vec![11u8; 32]);
        info.recompute_state_hash();
        let key = EvictionKey::new(info.stable_group_id().to_string(), [0x5e; 32]);
        let result_head = info.state_hash.clone();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .ce
            .deliveries
            .insert(
                key.clone(),
                CeDelivery {
                    bytes: Arc::new(b"X0XCE1\0#1660".to_vec()),
                    result_head: result_head.clone(),
                    next_revision: 2,
                    resumed: false,
                    gss_shares_pending: false,
                    gss_epoch: Some(2),
                    share_went_to: BTreeMap::new(),
                    recipients: BTreeMap::from([(*survivor.as_bytes(), RecipientDelivery::Sent)]),
                    next_at: tokio::time::Instant::now(),
                },
            );
        advertise_crypto_exclusion(&state, survivor);
        Ok(SeatReportFixture {
            state,
            group_id,
            key,
            survivor,
            survivor_kp,
            survivor_hex,
            result_head,
        })
    }

    /// #1660 (ADR 0110 §3, no mid-send exception): a member removed
    /// mid-send never has its seat closed as delivered. The round planned
    /// the send while the sender was a survivor; the removal landed on
    /// the live roster before the sender's head report arrived. The
    /// completion step re-checks the roster at the report: a report from
    /// a seat that is no longer Active is not a survivor's convergence
    /// evidence, so it closes no seat. The round later drops the seat the
    /// ordinary way; the delivery never records it as delivered.
    #[tokio::test]
    async fn a_report_from_a_member_removed_mid_send_closes_no_seat() -> Result<()> {
        // The control: a share went to the seat's key, and the same
        // report from the live member converges it. The refusal below
        // then checks the roster gate, not the share rule.
        let control = seat_report_fixture(true).await?;
        control.record_share_to_seat_key().await;
        control.record_post_seal_ask().await;
        control.feed_report(Some(&control.result_head)).await;
        assert_eq!(
            control.seat().await,
            Some(RecipientDelivery::Converged),
            "the control report converges the seat"
        );
        let fx = seat_report_fixture(true).await?;
        fx.record_share_to_seat_key().await;
        fx.record_post_seal_ask().await;
        fx.remove_sender_mid_send().await;
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "a removed member's report closes no seat as delivered (#1660, ADR 0110 §3)"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        Ok(())
    }

    /// #1660 (ADR 0110 §3 with D60, no mid-send exception): a member
    /// revoked mid-send never has its seat closed as delivered. The
    /// sender's machine is revoked after the round planned the send;
    /// D60's entitlement is not fixed at commit, so the completion step
    /// re-runs the revocation verdict on the sender before any seat
    /// closes, and the report of a revoked device closes nothing.
    #[tokio::test]
    async fn a_report_from_a_member_revoked_mid_send_closes_no_seat() -> Result<()> {
        // The control: a share went to the seat's key, and the same
        // report from the clean member converges it.
        let control = seat_report_fixture(true).await?;
        control.record_share_to_seat_key().await;
        control.record_post_seal_ask().await;
        control.feed_report(Some(&control.result_head)).await;
        assert_eq!(
            control.seat().await,
            Some(RecipientDelivery::Converged),
            "the control report converges the seat"
        );
        let fx = seat_report_fixture(true).await?;
        fx.record_share_to_seat_key().await;
        fx.record_post_seal_ask().await;
        // The sender's advertised machine (a real keypair, so its
        // revocation record verifies), revoked after the send began. The
        // advert replaces the fixture's with a strictly later timestamp:
        // the store refuses a same-millisecond insert as a replay.
        let machine = x0x::identity::MachineKeypair::generate()?;
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry {
            version: x0x::dm::CapabilityRegistry::current().version,
            bits: x0x::dm::CapabilityRegistry::current().bits,
        };
        assert!(
            fx.state.agent.capability_store().insert(
                fx.survivor,
                machine.machine_id(),
                capabilities,
                x0x::dm_capability::now_unix_ms().saturating_add(1_000),
            ),
            "verified advert with a real machine binding"
        );
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Machine(machine.machine_id()),
            machine.public_key(),
            machine.secret_key(),
            x0x::groups::owner_cert::restore_clock_now(),
            Some("#1660 mid-send revocation".to_string()),
        )?;
        fx.state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)?;
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "a revoked member's report closes no seat as delivered (#1660, D60)"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        Ok(())
    }

    /// #1660 (ADR 0110 §3, the issue's litmus): a seat whose KEM key
    /// arrives mid-send stays open and gets its share. The sender holds
    /// and reports the delivery's result head while its roster seat here
    /// carries no KEM key (the seat's key is local data; another member's
    /// view of it can differ, #1578). A GSS row's report proves delivery
    /// only through a keyed seat — a keyless one cannot have taken its
    /// sealed share — so the report closes nothing. Once the key arrives,
    /// the still-open row's next round seals the share to the seat, and
    /// only a report after that converges it and ends the row.
    #[tokio::test]
    async fn a_keyless_seats_report_closes_no_seat_and_a_late_key_gets_its_share() -> Result<()> {
        let fx = seat_report_fixture(false).await?;
        // The report names the result head from a seat this roster sees
        // keyless: the strongest report shape, and it still closes nothing.
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "a keyless seat's report closes no seat: it proves no share (#1660)"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        assert_eq!(
            fx.shares_to_sender().await,
            0,
            "no share was sealed while the seat had no key"
        );
        // The KEM key arrives mid-send: the keyed re-join. The next round
        // seals the rotated secret to the seat — the seat gets its share —
        // and the seat stays open until a report after that.
        let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
        fx.key_sender_seat(base64::engine::general_purpose::STANDARD.encode(&kem.public_bytes))
            .await;
        fx.round_now().await;
        assert_eq!(
            fx.shares_to_sender().await,
            1,
            "the round sealed the share to the keyed seat: it gets its share"
        );
        // The round's send task seals the share and records it; the
        // report below converges only against that record, so wait for
        // it to land. The seat itself proves nothing meanwhile: only a
        // report closes it (ADR 0110 §3).
        fx.await_share_recorded().await;
        assert_ne!(
            fx.seat().await,
            Some(RecipientDelivery::Converged),
            "the share alone closes no seat: only a report does (ADR 0110 §3)"
        );
        // The post-key report — the share-proof of a keyed survivor, on
        // an ask past that seal — converges the seat, and the next round
        // completes the row.
        fx.record_post_seal_ask().await;
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Converged),
            "the keyed seat's report converges the seat"
        );
        fx.round_now().await;
        assert!(!fx.row_open().await, "the converged row completes");
        Ok(())
    }

    /// #1660 (the review's mid-send order): the KEM key arrives, and the
    /// head report lands before the next round seals the share. The seat
    /// is keyed, but no share went to that key yet. A keyed seat alone
    /// proves no delivery, so the report closes nothing. The next round
    /// seals the share to the key, and only a report after that
    /// converges the seat.
    #[tokio::test]
    async fn a_report_before_the_round_seals_the_share_closes_no_seat() -> Result<()> {
        let fx = seat_report_fixture(false).await?;
        // The KEM key arrives mid-send: the keyed re-join. No round has
        // run, so no share is sealed yet.
        let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
        fx.key_sender_seat(base64::engine::general_purpose::STANDARD.encode(&kem.public_bytes))
            .await;
        assert_eq!(
            fx.shares_to_sender().await,
            0,
            "no share is sealed to the keyed seat yet"
        );
        // The head report lands before the next round. The keyed seat's
        // report must close nothing: no share went to that key.
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "a keyed seat with no sealed share proves no delivery (#1660)"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        // The next round seals the share to the key the seat carries
        // now; its send task records the seal, and the report after that
        // — on an ask past it — converges the seat.
        fx.round_now().await;
        assert_eq!(
            fx.shares_to_sender().await,
            1,
            "the round sealed the share: the seat gets its share"
        );
        fx.await_share_recorded().await;
        fx.record_post_seal_ask().await;
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Converged),
            "the report after the share went to the seat's key converges it"
        );
        fx.round_now().await;
        assert!(!fx.row_open().await, "the converged row completes");
        Ok(())
    }

    /// #1660 (Engineer ruling, 29 Oct 17:12 GMT): a delayed answer to a
    /// head ask sent before the seal arrives after the share was sealed
    /// and recorded. It closes nothing: no head ask has gone to the seat
    /// since the seal, so the answer could only answer a pre-seal ask.
    /// The next round's ask leaves (post-seal), and only an answer after
    /// that converges the seat.
    #[tokio::test]
    async fn an_answer_to_a_pre_seal_ask_closes_no_seat_until_a_post_seal_ask() -> Result<()> {
        let fx = seat_report_fixture(true).await?;
        fx.record_share_to_seat_key().await;
        // The delayed pre-seal answer: the record exists, the key
        // matches, and the report still closes nothing.
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "an answer that could only answer a pre-seal ask closes no seat (#1660)"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        // The boundary: the ask count EQUALS the seal's count — the
        // answer rode the same-numbered ask, not one after the seal. It
        // closes nothing; the gate is strict.
        {
            let mut inner = fx.state.revocation_evictions.inner.lock().await;
            let sealed_at = inner
                .ce
                .deliveries
                .get(&fx.key)
                .and_then(|delivery| delivery.share_went_to.get(fx.survivor.as_bytes()))
                .map(|record| record.ask_seq_at_seal)
                .expect("the seal record");
            inner.head_ask_seq.insert(
                (fx.key.stable_group_id.clone(), *fx.survivor.as_bytes()),
                sealed_at,
            );
        }
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "an answer at the seal's own ask count closes nothing: the gate is strict"
        );
        // The next round's ask leaves — after the seal. The fresh answer
        // converges the seat.
        fx.record_post_seal_ask().await;
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Converged),
            "the answer to a post-seal ask converges the seat"
        );
        fx.round_now().await;
        assert!(!fx.row_open().await, "the converged row completes");
        Ok(())
    }

    /// #1660 (Codex P2, 29 Oct): a head ask counts only when its page
    /// request went out. The ask task is parked at the send boundary
    /// while a delayed answer to an earlier ask arrives: the count has
    /// not moved, so the answer — which could only answer a pre-seal
    /// ask — closes nothing. Released, the send fails (the fixture peer
    /// has no route) and still counts nothing: no answer can ride a
    /// count for an ask that never left this node. The failed-send leg
    /// waits for the ask task to settle its decision (the
    /// `head-ask-settled` seam), not a fixed sleep, so a removed gate
    /// fails this test.
    #[tokio::test]
    async fn a_parked_or_failed_head_ask_counts_nothing() -> Result<()> {
        let fx = seat_report_fixture(true).await?;
        fx.record_share_to_seat_key().await;
        let pause = ng::detached_send_test_seam::arm(&format!(
            "treekem-catchup-page:{}",
            fx.key.stable_group_id
        ));
        let settled = ng::detached_send_test_seam::arm(&format!(
            "head-ask-settled:{}",
            fx.key.stable_group_id
        ));
        ask_heads(&fx.state, &fx.key.stable_group_id, vec![fx.survivor]).await;
        for _ in 0..250 {
            if pause.reached() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(4)).await;
        }
        assert!(pause.reached(), "the ask task parked at the send boundary");
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "a delayed answer while the ask is parked closes nothing: it counts only when its request went out"
        );
        drop(pause);
        for _ in 0..250 {
            if settled.reached() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(4)).await;
        }
        assert!(
            settled.reached(),
            "the ask task settled its count decision after the failed send"
        );
        assert_eq!(
            fx.ask_count().await,
            None,
            "a failed send counts no ask (Codex P2, 29 Oct): the count stays at the seal's"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        Ok(())
    }

    /// #1660 (Codex P2): the same ask path with its request sent (the
    /// test recorder's forced success — the offline fixture has no
    /// transport): the count advances inside the task, and only then
    /// does the survivor's answer converge the seat. The entry-point
    /// gate driven end to end through a real dispatch.
    #[tokio::test]
    async fn a_sent_head_ask_advances_the_count_and_its_answer_converges() -> Result<()> {
        let fx = seat_report_fixture(true).await?;
        fx.record_share_to_seat_key().await;
        fx.state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        ask_heads(&fx.state, &fx.key.stable_group_id, vec![fx.survivor]).await;
        for _ in 0..250 {
            if fx.ask_count().await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(4)).await;
        }
        assert_eq!(
            fx.ask_count().await,
            Some(1),
            "the ask that went out advanced the seat's count to 1"
        );
        let sent_asks = {
            let recorded = fx
                .state
                .named_group_test_recorders
                .catchup_responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            recorded.len()
        };
        assert_eq!(sent_asks, 1, "the ask's page request went out");
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Converged),
            "the answer to the sent ask converges the seat"
        );
        Ok(())
    }

    /// #1660 (Codex P2, 30 Oct): a head ask whose request left BEFORE
    /// the share was sealed, and whose ACK (the completion the count
    /// waits on) lands AFTER the seal recorded its bar. The ask is held
    /// at the ACK seam — the request is out, the send is in flight —
    /// while the seal lands. The completion of that in-flight send
    /// counts nothing — no ask went out after the seal — so the delayed
    /// answer to the pre-seal ask closes no seat. The fresh ask's send
    /// observes the seal, counts normally, and only its answer converges
    /// the seat.
    #[tokio::test]
    async fn a_pre_seal_ask_completing_after_the_seal_counts_nothing() -> Result<()> {
        let fx = seat_report_fixture(true).await?;
        fx.state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let ack = ng::detached_send_test_seam::arm(&format!(
            "treekem-catchup-page-ack:{}",
            fx.key.stable_group_id
        ));
        let settled = ng::detached_send_test_seam::arm(&format!(
            "head-ask-settled:{}",
            fx.key.stable_group_id
        ));
        ask_heads(&fx.state, &fx.key.stable_group_id, vec![fx.survivor]).await;
        for _ in 0..250 {
            if ack.reached() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(4)).await;
        }
        assert!(
            ack.reached(),
            "the ask's request went out and its ACK is held: the send is in flight"
        );
        // The seal happens while the ask's send is in flight, so the bar
        // is recorded at a count of zero completed asks. This first seal
        // creates the seat's record, so it establishes the bar.
        fx.record_share_to_seat_key().await;
        // The ACK lands: the pre-seal send completes, and its completion
        // must not publish a count.
        drop(ack);
        for _ in 0..250 {
            if settled.reached() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(4)).await;
        }
        assert!(
            settled.reached(),
            "the ask task settled its count decision after the late ACK"
        );
        assert_eq!(
            fx.ask_count().await,
            None,
            "the late completion of a send that left before the seal counts nothing"
        );
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "the delayed answer to the pre-seal ask closes nothing: its ask left before the seal"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        // The post-seal ask: its send observes the seal's generation, so
        // its completion counts, and only its answer converges the seat.
        ask_heads(&fx.state, &fx.key.stable_group_id, vec![fx.survivor]).await;
        for _ in 0..250 {
            if fx.ask_count().await == Some(1) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(4)).await;
        }
        assert_eq!(
            fx.ask_count().await,
            Some(1),
            "the ask sent after the seal counts"
        );
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Converged),
            "the answer to the post-seal ask converges the seat"
        );
        Ok(())
    }

    /// #1660 round 3 (Codex P2): the completion step re-reads the
    /// sender's seat under the S4 lock, so a re-key that lands while the
    /// report waits between its first roster read and that lock still
    /// refuses. The report is held inside the revocation verdict's read
    /// — past its first roster read — while the seat's KEM key rotates:
    /// the share record of the old key matches nothing the seat carries
    /// now, so the report closes no seat. The control runs the same
    /// hold-and-release with no re-key and converges, so the refusal
    /// checks the in-lock key re-read, not the hold.
    #[tokio::test]
    async fn a_rekey_while_the_report_waits_for_the_lock_closes_no_seat() -> Result<()> {
        // The control: the same held verdict, no re-key — the report
        // converges the seat.
        let control = seat_report_fixture(true).await?;
        control.record_share_to_seat_key().await;
        control.record_post_seal_ask().await;
        {
            let set = control.state.agent.revocation_set();
            let held = set.write().await;
            let report = {
                let state = Arc::clone(&control.state);
                let group = control.group_id.clone();
                let sender = control.survivor_hex.clone();
                let head = control.result_head.clone();
                tokio::spawn(async move {
                    super::super::note_catchup_head(&state, &[group], &sender, Some(&head)).await;
                })
            };
            // The report runs to the verdict's revocation-set read and
            // waits there, past its first roster read (the current key).
            tokio::task::yield_now().await;
            drop(held);
            report.await.map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        assert_eq!(
            control.seat().await,
            Some(RecipientDelivery::Converged),
            "the control report converges the seat through the held verdict"
        );
        let fx = seat_report_fixture(true).await?;
        fx.record_share_to_seat_key().await;
        fx.record_post_seal_ask().await;
        {
            let set = fx.state.agent.revocation_set();
            let held = set.write().await;
            let report = {
                let state = Arc::clone(&fx.state);
                let group = fx.group_id.clone();
                let sender = fx.survivor_hex.clone();
                let head = fx.result_head.clone();
                tokio::spawn(async move {
                    super::super::note_catchup_head(&state, &[group], &sender, Some(&head)).await;
                })
            };
            tokio::task::yield_now().await;
            // The re-key lands while the report waits: the seat carries a
            // new key, and the share went to the old one.
            let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
            fx.key_sender_seat(base64::engine::general_purpose::STANDARD.encode(&kem.public_bytes))
                .await;
            drop(held);
            report.await.map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "the report of a seat re-keyed under it closes nothing: the share went to the key it no longer carries (#1660 round 3)"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
        Ok(())
    }

    /// #1660 (ADR 0110 §3): a Pending or Banned sender is no Active
    /// member of the live roster, so its report is not a survivor's and
    /// closes no seat — the same gate as a removal, without one.
    #[tokio::test]
    async fn a_report_from_a_seat_demoted_mid_send_closes_no_seat() -> Result<()> {
        // The control: a share went to the seat's key, and the report
        // from the live member converges it.
        let control = seat_report_fixture(true).await?;
        control.record_share_to_seat_key().await;
        control.record_post_seal_ask().await;
        control.feed_report(Some(&control.result_head)).await;
        assert_eq!(
            control.seat().await,
            Some(RecipientDelivery::Converged),
            "the control report converges the seat"
        );
        for state in [
            x0x::groups::GroupMemberState::Pending,
            x0x::groups::GroupMemberState::Banned,
        ] {
            let fx = seat_report_fixture(true).await?;
            fx.record_share_to_seat_key().await;
            fx.record_post_seal_ask().await;
            fx.set_sender_seat_state(state).await;
            fx.feed_report(Some(&fx.result_head)).await;
            assert_eq!(
                fx.seat().await,
                Some(RecipientDelivery::Sent),
                "a {state:?} sender's report closes no seat as delivered (#1660)"
            );
            assert!(fx.row_open().await, "the delivery row stays open");
        }
        Ok(())
    }

    /// #1660 (ADR 0110 §3 with D60): an agent revoked mid-send never has
    /// its seat closed as delivered. The sender revokes its own agent
    /// key after the round planned the send; D60's entitlement is not
    /// fixed at commit, so the completion step refuses the sender before
    /// any seat closes. The machine and binding verdicts share the same
    /// `write_allowed` path (the machine case is the test above).
    #[tokio::test]
    async fn a_report_from_an_agent_revoked_mid_send_closes_no_seat() -> Result<()> {
        // The control: a share went to the seat's key, and the same
        // report from the clean member converges it.
        let control = seat_report_fixture(true).await?;
        control.record_share_to_seat_key().await;
        control.record_post_seal_ask().await;
        control.feed_report(Some(&control.result_head)).await;
        assert_eq!(
            control.seat().await,
            Some(RecipientDelivery::Converged),
            "the control report converges the seat"
        );
        let fx = seat_report_fixture(true).await?;
        fx.record_share_to_seat_key().await;
        fx.record_post_seal_ask().await;
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(fx.survivor),
            fx.survivor_kp.public_key(),
            fx.survivor_kp.secret_key(),
            x0x::groups::owner_cert::restore_clock_now(),
            Some("#1660 mid-send agent revocation".to_string()),
        )?;
        fx.state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)?;
        fx.feed_report(Some(&fx.result_head)).await;
        assert_eq!(
            fx.seat().await,
            Some(RecipientDelivery::Sent),
            "an agent-revoked member's report closes no seat as delivered (#1660, D60)"
        );
        assert!(fx.row_open().await, "the delivery row stays open");
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
