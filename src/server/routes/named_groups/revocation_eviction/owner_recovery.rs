//! ADR 0110 §4b(1): the daemon side of owner recovery for an
//! `OwnerCertified` group (Home included) whose admins are all revoked.
//!
//! - **Owner node** ([`sign_recovery_mandate`], `POST
//!   /owner/groups/:id/recovery-mandate`). On a node that holds the owner's
//!   user key U, it signs `OwnerRecoveryMandateV1` for one promoted member
//!   and sends it to that member over the direct-message carrier, gated on
//!   `owner_recovery_v1`. Until the head moves past the mandate's parent,
//!   the owner node shows `waiting_for_recovery_member`, naming the
//!   promoted member.
//! - **Promoted member.** It verifies the mandate, applies the D76 hold
//!   (`waiting_for_receiver_upgrade` naming each known Active member whose
//!   current verified advert lacks bit 7), then authors the one chained
//!   `OwnerRecoveryV1` commit. It reuses the existing remove and rekey
//!   primitives: `remove_member_verified` per revoked TreeKEM leaf, one GSS
//!   rotation with guarded survivor envelopes (D60), or the roster seat
//!   alone in a `SignedPublic` group.
//! - **Delivery.** Per-recipient, capability-gated direct delivery only;
//!   never the metadata topic and never a legacy-decoded container. A
//!   recipient whose advert lacks the bit is stranded
//!   (`waiting_for_receiver_upgrade` with the gap revision).
//! - **Receive.** The §4b(1) L4 rule, then the frame is made durable in
//!   the held log ([`replay_log`]), then the ordinary chained apply with
//!   the roster change as its only mutation, then the crypto removal proof.
//! - **Restart.** A delivery that a restart restored waits for the §2 head
//!   sync before each round. The owner's `waiting_for_recovery_member`
//!   wait and a member's held mandate load from the group's
//!   pending-mandate file after a restart (#1625).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::Json;
use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::owner_recovery as orc;
use x0x::groups::GroupInfo;
use x0x::identity::AgentId;

use super::crypto_exclusion::{
    all_converged, apply_round, ask_heads, finish_attempt, guarded_admission_for, head_rule_admits,
    next_attempt, note_converged, report_may_close, write_allowed, HeadRule, RecipientDelivery,
    RoundUpdate, SenderSeat,
};
use super::frame_stash::{FrameStash, StashedFrame};
use super::mandate_store::{self, PendingOrcV1};
use super::rebind::replay_log;

/// The owner node's typed state until the promoted member commits.
pub(in crate::server) const WAITING_FOR_RECOVERY_MEMBER: &str = "waiting_for_recovery_member";

/// A send round runs no more often than this per mandate or commit.
const ORC_RESEND_INTERVAL: Duration = Duration::from_secs(5);
/// A stashed frame, held commit or parked share is dropped after this
/// long. A held mandate is not (#1508 rc16).
const ORC_RETAIN_TTL: Duration = Duration::from_secs(600);
/// Frames held for a later retry.
const ORC_STASH_CAP: usize = 32;
/// #1533 rc18: parked shares per group from senders that are not Active
/// members on this node's roster ([`park_early_share`]).
const ORC_CANDIDATE_SHARES_PER_GROUP: usize = 4;
/// A commit attempt that met a transient wait retries no sooner than this.
const ORC_COMMIT_RETRY: Duration = Duration::from_secs(5);
/// The per-exchange bound of one mandate, commit or catch-up frame write.
const ORC_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
/// Recovery frames held per group for catch-up serving: the same bound as
/// the crypto-only exclusion log.
const ORC_LOG_PER_GROUP: usize = x0x::groups::eviction::MAX_REPLAY_FRAMES_PER_GROUP;

/// The owner node's delivery of one mandate.
#[derive(Debug, Clone)]
struct MandateDelivery {
    /// The signed mandate the wait is for, so it survives a restart
    /// ([`mandate_store`], #1625).
    mandate: orc::SignedOwnerRecoveryMandateV1,
    bytes: Arc<Vec<u8>>,
    mandate_id: String,
    promoted: [u8; 32],
    parent_head: String,
    /// The one recipient (the promoted member) and its delivery status,
    /// kept as a map so the shared per-attempt round helpers apply.
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
}

/// A verified mandate held by the promoted member until it commits.
#[derive(Debug, Clone)]
struct PendingMandate {
    mandate: orc::SignedOwnerRecoveryMandateV1,
    /// The last typed wait of a commit attempt, with the named members.
    wait: Option<(&'static str, Vec<[u8; 32]>)>,
    next_at: Instant,
}

/// The promoted member's delivery of one committed recovery.
#[derive(Debug, Clone)]
struct CommitDelivery {
    bytes: Arc<Vec<u8>>,
    result_head: String,
    next_revision: u64,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
    /// A restart restored this delivery from the held log: each round
    /// waits for the group's §2 head sync first (#1508 review F3).
    resumed: bool,
    /// The removed seats of the recovery: they are not head holders.
    removed: BTreeSet<[u8; 32]>,
    /// A GSS recovery: the epoch whose secret each survivor gets, sealed
    /// after the write of the frame to that survivor (#1508 r5). A share
    /// that goes first is refused, because its sender is still a Member on
    /// the survivor's roster. The value comes from the frame, so a
    /// restored delivery keeps it: the sealed shares were not durable, the
    /// secret is, in the persisted group (#1508 review).
    reshare_epoch: Option<u64>,
    /// #1660: per recipient, the share record of this row's epoch — the
    /// KEM key (b64) a sealed share went to and the seat's head-ask
    /// count at the earliest seal to that key. A report closes the seat
    /// only when the key the sender's seat carries now is the record's
    /// key and an ask went to the seat past the seal
    /// ([`report_may_close`]).
    share_went_to: BTreeMap<[u8; 32], super::crypto_exclusion::ShareRecord>,
}

/// A GSS share that arrived before the recovery that makes its sender an
/// admin ([`park_early_share`]).
#[derive(Debug, Clone)]
struct ParkedShare {
    stable_group_id: String,
    event: super::super::NamedGroupMetadataEvent,
    sender: AgentId,
    at: Instant,
    /// The sender was not an Active member on this node's roster when the
    /// share was parked (#1533 rc18): a candidate that only a verified
    /// successor chain can make an admin.
    candidate: bool,
}

/// A verified catch-up commit of a GSS `OwnerCertified` group that does
/// not chain on this node's head yet ([`hold_unchained_event`]): it may
/// chain on a recovery that has not installed here.
#[derive(Debug, Clone)]
struct HeldEvent {
    stable_group_id: String,
    event: super::super::NamedGroupMetadataEvent,
    /// The verified signer of the event's commit.
    author: AgentId,
    prev_state_hash: Option<String>,
    at: Instant,
}

/// The owner-recovery state held in the S4 runtime, keyed by stable
/// group ID.
#[derive(Debug, Default)]
pub(super) struct OrcState {
    mandates: HashMap<String, MandateDelivery>,
    pending: HashMap<String, PendingMandate>,
    deliveries: HashMap<String, CommitDelivery>,
    stash: FrameStash<ORC_STASH_CAP>,
    /// Early GSS shares, held until their recovery installs.
    early_shares: Vec<ParkedShare>,
    /// Catch-up commits held until their recovery installs.
    held_events: Vec<HeldEvent>,
    /// The pending-mandate files were read this process (#1625).
    mandates_restored: bool,
    /// Authored and installed recovery commits, for catch-up serving; the
    /// authored and the received frames are durable ([`replay_log`]).
    log: replay_log::HeldLog<ORC_LOG_PER_GROUP, true>,
}

impl OrcState {
    /// #1660 (Claude round 5): the stable group IDs of the live commit
    /// deliveries — fresh or resumed. The worker pass keeps their
    /// groups' head-ask counts through its retain; only the ask counts,
    /// not the §2 head rounds, which stay with the open work
    /// ([`head_round_groups`]).
    pub(super) fn delivery_groups(&self) -> impl Iterator<Item = &str> {
        self.deliveries.keys().map(String::as_str)
    }

    /// §2: the groups that need a head catch-up round, each with the
    /// agents that are not head holders. A held mandate needs one before
    /// its seal (its named, revoked admins are excluded). A delivery that
    /// a restart restored needs one before any resend of its frame or its
    /// GSS shares (its removed seats are excluded).
    pub(super) fn head_round_groups(&self) -> BTreeMap<String, BTreeSet<[u8; 32]>> {
        let mut groups: BTreeMap<String, BTreeSet<[u8; 32]>> = BTreeMap::new();
        for (stable, pending) in &self.pending {
            groups.entry(stable.clone()).or_default().extend(
                pending
                    .mandate
                    .body
                    .revoked_admins
                    .iter()
                    .map(|admin| admin.agent),
            );
        }
        for (stable, delivery) in self.deliveries.iter().filter(|(_, d)| d.resumed) {
            groups
                .entry(stable.clone())
                .or_default()
                .extend(delivery.removed.iter().copied());
        }
        groups
    }

    /// Install one planned mandate status, if the delivery still holds
    /// mandate `mandate_id`. Returns the sends to start, after this.
    fn install_mandate_round(
        &mut self,
        stable: &str,
        mandate_id: &str,
        update: RoundUpdate,
    ) -> Vec<([u8; 32], u64)> {
        match self.mandates.get_mut(stable) {
            Some(delivery) if delivery.mandate_id == mandate_id => {
                apply_round(&mut delivery.recipients, vec![update])
            }
            _ => Vec::new(),
        }
    }

    /// Record the result of mandate send `attempt`; a stale attempt, or one
    /// for a replaced mandate, changes nothing.
    fn finish_mandate_attempt(
        &mut self,
        stable: &str,
        mandate_id: &str,
        recipient: &[u8; 32],
        attempt: u64,
        status: RecipientDelivery,
    ) -> bool {
        match self.mandates.get_mut(stable) {
            Some(delivery) if delivery.mandate_id == mandate_id => {
                finish_attempt(&mut delivery.recipients, recipient, attempt, status)
            }
            _ => false,
        }
    }

    /// Install one commit round's planned statuses, if the delivery still
    /// holds the commit with `result_head`, and drop a delivery whose
    /// recipients all converged (ADR 0110 §3: survivor convergence, not a
    /// write, proves delivery). Returns the sends to start, after this.
    fn install_commit_round(
        &mut self,
        stable: &str,
        result_head: &str,
        updates: Vec<RoundUpdate>,
    ) -> Vec<([u8; 32], u64)> {
        let Some(stored) = self
            .deliveries
            .get_mut(stable)
            .filter(|delivery| delivery.result_head == result_head)
        else {
            return Vec::new();
        };
        let started = apply_round(&mut stored.recipients, updates);
        if all_converged(&stored.recipients) {
            self.deliveries.remove(stable);
        }
        started
    }

    /// Record the result of commit send `attempt`; a stale attempt, or one
    /// for another commit, changes nothing.
    fn finish_commit_attempt(
        &mut self,
        stable: &str,
        result_head: &str,
        recipient: &[u8; 32],
        attempt: u64,
        status: RecipientDelivery,
    ) -> bool {
        match self.deliveries.get_mut(stable) {
            Some(delivery) if delivery.result_head == result_head => {
                finish_attempt(&mut delivery.recipients, recipient, attempt, status)
            }
            _ => false,
        }
    }
}

/// §3 survivor convergence ([`super::crypto_exclusion::note_survivor_head`]):
/// `sender` holds each head in `installed`, so it converged in the commit
/// delivery of `stable_group_id` when its result is one of them.
/// `sender_seat` is the sender's live-roster facts at this moment
/// (#1660): every row requires a live, D60-clean sender, and a GSS
/// recovery (`reshare_epoch`) additionally requires that a sealed share
/// went to the key the sender's seat carries now — its rounds seal the
/// rotated secret, so the report must prove the sealed share like any
/// GSS row's.
pub(super) fn note_survivor_head(
    orc: &mut OrcState,
    stable_group_id: &str,
    sender: &[u8; 32],
    installed: &BTreeSet<String>,
    sender_seat: Option<SenderSeat>,
    ask_seq: Option<u64>,
) {
    let Some(delivery) = orc.deliveries.get_mut(stable_group_id) else {
        return;
    };
    if !report_may_close(
        sender_seat,
        delivery.reshare_epoch.is_some(),
        delivery.share_went_to.get(sender),
        ask_seq,
    ) {
        return;
    }
    note_converged(
        &mut delivery.recipients,
        &delivery.result_head,
        sender,
        installed,
    );
}

/// #1660 ([`super::crypto_exclusion::note_share_went_to`]): keep, on the
/// GSS commit delivery of `stable_group_id` at `epoch`, the record of a
/// sealed share of that epoch's secret for `recipient` — the key and the
/// seat's head-ask count at the seal. Returns whether the seal
/// established the record — created it or changed its key.
pub(super) fn note_share_went_to(
    orc: &mut OrcState,
    stable_group_id: &str,
    epoch: u64,
    recipient: &[u8; 32],
    kem: &str,
    ask_seq_at_seal: u64,
) -> bool {
    let Some(delivery) = orc.deliveries.get_mut(stable_group_id) else {
        return false;
    };
    if delivery.reshare_epoch != Some(epoch) {
        return false;
    }
    super::crypto_exclusion::keep_share_record(
        &mut delivery.share_went_to,
        recipient,
        kem,
        ask_seq_at_seal,
    )
}

impl OrcState {
    /// #1508 rc17 (Codex P1): whether a retained owner-recovery frame of
    /// `stable_group_id` commits a revision above `revision`. #1508 rc18
    /// (Codex P1): only a frame that passed [`orc::check_ahead`] on this
    /// node's latest head, or every receiver check, counts, with no time
    /// limit ([`FrameStash`]).
    pub(super) fn stash_ahead(&self, stable_group_id: &str, revision: u64) -> bool {
        self.stash.ahead(stable_group_id, revision)
    }
}

fn held(inner: &mut super::S4Inner) -> &mut replay_log::HeldLog<ORC_LOG_PER_GROUP, true> {
    &mut inner.orc.log
}

/// #1625: write the group's pending-mandate file through the shared
/// durable writer, behind the ADR 0094 host-commit gate like the other S4
/// files. Called after each memory change, best effort: a failed write
/// leaves the memory state as it is, and a restart then loses that side,
/// as before the file existed. The `.evs`/`.evh` writer lock serializes
/// the write with its snapshot, so two changes of one group cannot write
/// out of order.
async fn persist_mandates(state: &AppState, stable: &str) {
    // §5: no S4 file write inside an ADR 0094 trial.
    if !super::host_commit_gate_open(state) {
        return;
    }
    let _writer = state.revocation_evictions.evs_writer.lock().await;
    let (owner_wait, member_hold) = {
        let inner = state.revocation_evictions.inner.lock().await;
        (
            inner.orc.mandates.get(stable).map(|d| d.mandate.clone()),
            inner
                .orc
                .pending
                .get(stable)
                .map(|pending| pending.mandate.clone()),
        )
    };
    if owner_wait.is_none() && member_hold.is_none() {
        mandate_store::retire(state, stable).await;
        return;
    }
    let durable = mandate_store::write(
        state,
        &PendingOrcV1 {
            stable_group_id: stable.to_string(),
            owner_wait,
            member_hold,
        },
    )
    .await;
    if !durable {
        tracing::warn!(group_id = %super::super::LogHexId::group(stable), "ADR 0110 S4: the pending owner-recovery state is not durable; a restart can lose it");
    }
}

/// #1625: load the pending-mandate files once per process and install
/// each side that still applies. A loaded mandate is installed only after
/// it verifies against the loaded group again, so a restart never
/// installs an unverified mandate; the full §4b(1) checks run again at
/// each commit attempt. A quarantined group keeps its sides, as the live
/// refusal path does: the containment can lift. A file whose sides can
/// never apply again (no group, no owner, a failed signature, a head past
/// the mandate's parent) is retired at load, outside a trial.
async fn restore_mandates(state: &AppState) {
    if state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .mandates_restored
    {
        return;
    }
    let gate_open = super::host_commit_gate_open(state);
    let files = mandate_store::read_all(state, gate_open).await;
    let groups: HashMap<String, GroupInfo> = state
        .named_groups
        .read()
        .await
        .values()
        .map(|info| (info.stable_group_id().to_string(), info.clone()))
        .collect();
    let local = *state.agent.agent_id().as_bytes();
    let mut stale: Vec<String> = Vec::new();
    let mut wake = false;
    let mut inner = state.revocation_evictions.inner.lock().await;
    if inner.orc.mandates_restored {
        return;
    }
    inner.orc.mandates_restored = true;
    for file in files {
        let Some(info) = groups.get(&file.stable_group_id) else {
            stale.push(file.stable_group_id.clone());
            continue;
        };
        let Some(owner) = info.policy.admission.owner_certified_user_id() else {
            stale.push(file.stable_group_id.clone());
            continue;
        };
        // The side applies while this node's head is the mandate's parent
        // or behind it (the member may still catch up): a head past the
        // parent consumed the mandate or forked away from it.
        let applies = |mandate: &orc::SignedOwnerRecoveryMandateV1| {
            mandate.body.stable_group_id == file.stable_group_id
                && (info.state_hash == mandate.body.parent_head
                    || info.state_revision < mandate.body.parent_revision)
        };
        let mut kept = false;
        if let Some(mandate) = file.owner_wait {
            if inner.orc.mandates.contains_key(&file.stable_group_id) {
                // A mandate signed in this process is the newer wait.
                kept = true;
            } else {
                let restored = if applies(&mandate)
                    && orc::verify_mandate_signature(&mandate, owner).is_ok()
                {
                    orc::encode_frame(&orc::OwnerRecoveryFrameV1::Mandate(mandate.clone())).ok()
                } else {
                    None
                };
                if let Some(bytes) = restored {
                    let promoted = mandate.body.promoted;
                    inner.orc.mandates.insert(
                        file.stable_group_id.clone(),
                        MandateDelivery {
                            promoted,
                            mandate_id: orc::mandate_id(&mandate),
                            parent_head: mandate.body.parent_head.clone(),
                            bytes: Arc::new(bytes),
                            mandate,
                            recipients: BTreeMap::from([(promoted, RecipientDelivery::Due)]),
                            next_at: Instant::now(),
                        },
                    );
                    kept = true;
                }
            }
        }
        if let Some(mandate) = file.member_hold {
            if inner.orc.pending.contains_key(&file.stable_group_id) {
                kept = true;
            } else if mandate.body.promoted == local
                && applies(&mandate)
                && orc::verify_mandate_signature(&mandate, owner).is_ok()
            {
                inner.orc.pending.insert(
                    file.stable_group_id.clone(),
                    PendingMandate {
                        mandate,
                        wait: None,
                        next_at: Instant::now(),
                    },
                );
                kept = true;
                wake = true;
            }
        }
        if !kept {
            stale.push(file.stable_group_id.clone());
        }
    }
    drop(inner);
    if wake {
        state.agent.s4_revocation_intake().request_reconcile();
    }
    // §5: no S4 file write inside an ADR 0094 trial; a later process
    // re-reads and re-drops what the file holds. Under the sidecar writer
    // lock, and only while the group still holds no side in memory, so a
    // mandate that arrived while the files were read cannot lose its file.
    if gate_open && !stale.is_empty() {
        let _writer = state.revocation_evictions.evs_writer.lock().await;
        for stable in stale {
            let live = {
                let inner = state.revocation_evictions.inner.lock().await;
                inner.orc.mandates.contains_key(&stable) || inner.orc.pending.contains_key(&stable)
            };
            if !live {
                mandate_store::retire(state, &stable).await;
            }
        }
    }
}

/// Load the durable recovery frames once, and deliver an authored commit
/// that is still its group's head again (#1508 review). A received commit
/// that a crash stopped before its install goes to the stash: the next
/// pass receives it again, with every receiver check. The pending
/// mandates load here too (#1625).
async fn ensure_restored(state: &AppState) {
    restore_mandates(state).await;
    let restored = replay_log::ensure_restored(state, replay_log::RECOVERY_EXTENSION, held).await;
    let local = *state.agent.agent_id().as_bytes();
    let mut inner = state.revocation_evictions.inner.lock().await;
    for bytes in restored.received {
        // The frame is self-authenticating; its actor is the sender. It
        // passed every receiver check before it was written.
        let Ok(orc::OwnerRecoveryFrameV1::Commit(frame)) = orc::decode_frame(&bytes) else {
            continue;
        };
        let _kept = inner.orc.stash.push(stashed(
            AgentId(frame.body.actor),
            bytes.to_vec(),
            &frame.body,
            true,
        ));
    }
    for resume in restored.resumes {
        let recipients = survivors(&resume.info, &local, &BTreeSet::new());
        let stable = resume.stable_group_id;
        let body = match orc::decode_frame(&resume.bytes) {
            Ok(orc::OwnerRecoveryFrameV1::Commit(frame)) => Some(frame.body),
            _ => None,
        };
        let removed = body
            .iter()
            .flat_map(|body| body.removed.iter().map(|seat| seat.agent))
            .collect();
        let reshare_epoch = body.as_ref().and_then(gss_epoch);
        inner
            .orc
            .deliveries
            .entry(stable)
            .or_insert_with(|| CommitDelivery {
                bytes: resume.bytes,
                result_head: resume.result_head,
                next_revision: resume.next_revision,
                recipients: recipients
                    .into_iter()
                    .map(|id| (id, RecipientDelivery::Due))
                    .collect(),
                next_at: Instant::now(),
                resumed: true,
                removed,
                reshare_epoch,
                share_went_to: BTreeMap::new(),
            });
    }
}

fn agent_bytes(hex_id: &str) -> Option<[u8; 32]> {
    super::super::parse_agent_id_hex(hex_id)
        .ok()
        .map(|agent| *agent.as_bytes())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// The verified Agent-subject revocation records this node holds (§1's
/// choke point inserted each one after `verify_and_insert`).
async fn verified_agent_revocations(state: &AppState) -> orc::VerifiedAgentRevocations {
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    let mut out = orc::VerifiedAgentRevocations::new();
    for record in set.all_records() {
        if let x0x::revocation::RevokedSubject::Agent(agent) = &record.subject {
            out.entry(*agent.as_bytes())
                .or_default()
                .insert(record.record_hash());
        }
    }
    out
}

async fn group_by_stable(state: &AppState, group_id: &str) -> Option<(String, GroupInfo)> {
    let key = super::super::resolve_named_group_storage_key(state, group_id).await?;
    let info = state.named_groups.read().await.get(&key).cloned()?;
    Some((key, info))
}

/// `group_by_stable` behind `named_groups_persistence_lock`. #1574 item 5:
/// `persist_named_group_info` shows its candidate in the map before the
/// write and restores the map when the write fails, so a drop decided on an
/// unlocked read ("group gone", "head moved") can act on a candidate that
/// rolls back. The drives call this for their drop decisions; the
/// informational reads keep the unlocked form. Lock order: persistence,
/// then `named_groups` (the pass's snapshot order). Call it with no S4
/// lock held.
async fn committed_group_by_stable(state: &AppState, group_id: &str) -> Option<GroupInfo> {
    let _committed = state.named_groups_persistence_lock.lock().await;
    group_by_stable(state, group_id).await.map(|(_, info)| info)
}

/// The members a recovery commit on `info` must reach: the Active seats
/// other than `local` and the named admins.
fn survivors(info: &GroupInfo, local: &[u8; 32], removed: &BTreeSet<[u8; 32]>) -> Vec<[u8; 32]> {
    info.active_members()
        .filter_map(|member| agent_bytes(&member.agent_id))
        .filter(|id| id != local && !removed.contains(id))
        .collect()
}

/// The new secret epoch of a GSS recovery; `None` for the other planes.
fn gss_epoch(body: &orc::OwnerRecoveryBodyV1) -> Option<u64> {
    match body.crypto {
        orc::OwnerRecoveryCryptoV1::Gss { next_secret_epoch } => Some(next_secret_epoch),
        _ => None,
    }
}

fn refusal_status(refusal: orc::OwnerRecoveryRefusal) -> StatusCode {
    match refusal {
        orc::OwnerRecoveryRefusal::RecoverySignerNotOwner => StatusCode::FORBIDDEN,
        orc::OwnerRecoveryRefusal::WrongPrefix | orc::OwnerRecoveryRefusal::Malformed => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::CONFLICT,
    }
}

fn refusal_response(
    refusal: orc::OwnerRecoveryRefusal,
    group_id: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        refusal_status(refusal),
        Json(serde_json::json!({
            "ok": false,
            "error": refusal.as_str(),
            "reason": refusal.as_str(),
            "group_id": group_id,
        })),
    )
}

// ─── Owner node: the mandate route ─────────────────────────────────────────

/// `POST /owner/groups/:id/recovery-mandate`: sign `OwnerRecoveryMandateV1`
/// with the local owner key `user_kp` for `promoted_hex`, and send it to
/// that member. The caller has already checked the durable owner token and
/// that this node holds U's key.
pub(in crate::server) async fn sign_recovery_mandate(
    state: &Arc<AppState>,
    user_kp: &x0x::identity::UserKeypair,
    group_id: &str,
    promoted_hex: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let promoted = match super::super::parse_agent_id_hex(promoted_hex) {
        Ok(agent) => agent,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": error })),
            );
        }
    };
    let Some((group_key, info)) = group_by_stable(state, group_id).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };
    let stable = info.stable_group_id().to_string();
    if info.withdrawn || info.fork_quarantine.is_some() {
        return refusal_response(orc::OwnerRecoveryRefusal::RecoveryGroupQuarantined, &stable);
    }
    if info.policy.admission.owner_certified_user_id() != Some(&user_kp.user_id()) {
        return refusal_response(orc::OwnerRecoveryRefusal::RecoverySignerNotOwner, &stable);
    }
    let revocations = verified_agent_revocations(state).await;
    let Some(revoked_admins) = orc::revoked_admins_when_needed(&info, &revocations) else {
        return refusal_response(orc::OwnerRecoveryRefusal::RecoveryNotNeeded, &stable);
    };
    let member = info.members_v2.get(&hex::encode(promoted.as_bytes()));
    let Some(digest) = member.and_then(|member| member.certificate_digest.clone()) else {
        return refusal_response(orc::OwnerRecoveryRefusal::RecoveryMemberIneligible, &stable);
    };
    let certificate = member.and_then(|member| member.certificate.clone());
    let body = orc::OwnerRecoveryMandateBodyV1 {
        stable_group_id: stable.clone(),
        parent_head: info.state_hash.clone(),
        parent_revision: info.state_revision,
        revoked_admins,
        promoted: *promoted.as_bytes(),
        promoted_certificate_digest: digest,
        owner_public_key: Vec::new(),
        issued_at_ms: super::super::now_millis_u64(),
    };
    let mandate = match orc::sign_mandate(body, user_kp) {
        Ok(mandate) => mandate,
        Err(refusal) => return refusal_response(refusal, &stable),
    };
    // The owner node runs the receiver's own mandate checks first, so it
    // never sends a mandate the promoted member must refuse.
    if let Err(refusal) = orc::validate_mandate(
        &mandate,
        &info,
        &revocations,
        certificate.as_ref(),
        now_unix(),
    ) {
        return refusal_response(refusal, &stable);
    }
    let mandate_id = orc::mandate_id(&mandate);
    let Some(bytes) = orc::encode_frame(&orc::OwnerRecoveryFrameV1::Mandate(mandate.clone())).ok()
    else {
        return refusal_response(orc::OwnerRecoveryRefusal::Malformed, &stable);
    };
    if bytes.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(
                serde_json::json!({ "ok": false, "error": "mandate exceeds the direct carrier limit" }),
            ),
        );
    }
    let local = *state.agent.agent_id().as_bytes();
    let revoked: Vec<String> = mandate
        .body
        .revoked_admins
        .iter()
        .map(|admin| hex::encode(admin.agent))
        .collect();
    if *promoted.as_bytes() == local {
        // The owner's own agent is the promoted member: no carrier hop.
        accept_mandate(state, mandate).await;
    } else {
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .mandates
            .insert(
                stable.clone(),
                MandateDelivery {
                    mandate: mandate.clone(),
                    bytes: Arc::new(bytes),
                    mandate_id: mandate_id.clone(),
                    promoted: *promoted.as_bytes(),
                    parent_head: info.state_hash.clone(),
                    recipients: BTreeMap::from([(*promoted.as_bytes(), RecipientDelivery::Due)]),
                    next_at: Instant::now(),
                },
            );
        // #1625: the owner's `waiting_for_recovery_member` wait is written
        // to the pending-mandate file, so a restart of the owner keeps it.
        persist_mandates(state, &stable).await;
    }
    tracing::info!(
        group_id = %super::super::LogHexId::group(&group_key),
        promoted = %super::super::LogHexId::agent(promoted_hex),
        "ADR 0110 S4: owner recovery mandate signed"
    );
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move { drive(&task_state).await });
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ok": true,
            "group_id": stable,
            "state": WAITING_FOR_RECOVERY_MEMBER,
            "promoted_member": hex::encode(promoted.as_bytes()),
            "mandate_id": mandate_id,
            "parent_head": info.state_hash,
            "parent_revision": info.state_revision,
            "revoked_admins": revoked,
        })),
    )
}

// ─── Worker ────────────────────────────────────────────────────────────────

/// One owner-recovery round: mandate sends, commit attempts, commit
/// deliveries and stashed frames.
pub(super) async fn drive(state: &Arc<AppState>) {
    ensure_restored(state).await;
    drive_mandates(state).await;
    let due: Vec<String> = {
        let now = Instant::now();
        // #1508 rc16 (Codex P2): a held mandate has no time limit. It ends
        // when it commits or a check refuses it ([`try_commit`]); an
        // upgrade wait keeps it (ADR 0110 §4, D76).
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .orc
            .pending
            .iter()
            .filter(|(_, pending)| pending.next_at <= now)
            .map(|(id, _)| id.clone())
            .collect()
    };
    for stable in due {
        try_commit(state, &stable).await;
    }
    drive_deliveries(state).await;
    retry_stash(state).await;
}

async fn drive_mandates(state: &Arc<AppState>) {
    let now = Instant::now();
    let due: Vec<(String, MandateDelivery)> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner
            .orc
            .mandates
            .iter_mut()
            .filter(|(_, delivery)| delivery.next_at <= now)
            .map(|(id, delivery)| {
                delivery.next_at = now + ORC_RESEND_INTERVAL;
                (id.clone(), delivery.clone())
            })
            .collect()
    };
    let capabilities = state.agent.capability_store();
    for (stable, delivery) in due {
        // #1574 item 5: the gone/head-moved read below ends the owner's
        // wait and retires its mandate file, so it reads committed roster
        // state only (`committed_group_by_stable`).
        let head = committed_group_by_stable(state, &stable)
            .await
            .filter(|info| !info.withdrawn)
            .map(|info| info.state_hash);
        if head.as_deref() != Some(delivery.parent_head.as_str()) {
            // The commit landed (or the head moved and the mandate no
            // longer applies): the owner's wait ends.
            let mut inner = state.revocation_evictions.inner.lock().await;
            if inner
                .orc
                .mandates
                .get(&stable)
                .is_some_and(|stored| stored.mandate_id == delivery.mandate_id)
            {
                inner.orc.mandates.remove(&stable);
                drop(inner);
                // #1625: the ended wait leaves the pending-mandate file.
                persist_mandates(state, &stable).await;
            }
            continue;
        }
        let promoted = delivery.promoted;
        let Some(observed) = delivery.recipients.get(&promoted).copied() else {
            continue;
        };
        // A running attempt owns the status. A `Sent` mandate is sent
        // again until the commit lands: the promoted member deduplicates
        // by head, and `Sent` means only that the carrier took it.
        if matches!(observed, RecipientDelivery::InFlight(_)) {
            continue;
        }
        let agent = AgentId(promoted);
        if !write_allowed(state, &agent).await {
            continue;
        }
        let mut refresh = false;
        let next = match capabilities
            .verified_registry_supports(&agent, x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1)
        {
            Some(true) => RecipientDelivery::InFlight(next_attempt()),
            Some(false) => RecipientDelivery::Lacking,
            None => {
                refresh = true;
                RecipientDelivery::Unknown
            }
        };
        // Install the status, `InFlight` included, BEFORE the send task
        // starts: a fast completion can then never be overwritten.
        let started = state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .install_mandate_round(
                &stable,
                &delivery.mandate_id,
                RoundUpdate {
                    recipient: promoted,
                    observed,
                    next: Some(next),
                },
            );
        for (recipient, attempt) in started {
            spawn_mandate_send(state, &stable, &delivery, AgentId(recipient), attempt);
        }
        if refresh {
            let task_state = Arc::clone(state);
            let _spawned = state.spawn_detached(async move {
                task_state
                    .agent
                    .refresh_application_capability(
                        agent,
                        x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1,
                    )
                    .await;
            });
        }
    }
}

/// One guarded frame write of an owner-recovery frame to `agent`: the
/// ADR 0107 serving guard, D60, the `owner_recovery_v1` gate and `rule`,
/// in the pre-phase and again at the write seam.
async fn send_guarded(
    state: &Arc<AppState>,
    group_id: &str,
    agent: &AgentId,
    rule: HeadRule,
    bytes: &[u8],
) -> RecipientDelivery {
    let admission = guarded_admission_for(
        state,
        group_id,
        agent,
        rule,
        x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1,
    );
    let resolve_within = std::cmp::min(x0x::dm::PINNED_RESOLUTION_WAIT, ORC_EXCHANGE_TIMEOUT / 2);
    let exchange =
        state
            .agent
            .send_direct_pinned_admitted(agent, bytes, &admission, resolve_within);
    match tokio::time::timeout(ORC_EXCHANGE_TIMEOUT, exchange).await {
        Ok(Ok(_)) => RecipientDelivery::Sent,
        Ok(Err(x0x::dm::DmError::RecipientUpgradeRequired { .. })) => RecipientDelivery::Lacking,
        // The in-process stand-in reports an admitted exchange with its
        // marker error (test builds only), as for the class-K shares.
        #[cfg(test)]
        Ok(Err(error)) if error.to_string().contains(x0x::dm::PINNED_STANDIN_ADMITTED) => {
            RecipientDelivery::Sent
        }
        Ok(Err(error)) => {
            // An admission refusal is a withhold: the next round
            // re-evaluates the recipient from the current state.
            tracing::debug!(%error, "ADR 0110 S4: owner recovery send refused or failed; retrying");
            RecipientDelivery::Due
        }
        Err(_) => {
            tracing::debug!("ADR 0110 S4: owner recovery exchange deadline elapsed; retrying");
            RecipientDelivery::Due
        }
    }
}

fn spawn_mandate_send(
    state: &Arc<AppState>,
    stable: &str,
    delivery: &MandateDelivery,
    agent: AgentId,
    attempt: u64,
) {
    let task_state = Arc::clone(state);
    let stable = stable.to_string();
    let mandate_id = delivery.mandate_id.clone();
    let rule = HeadRule::Current(delivery.parent_head.clone());
    let bytes = Arc::clone(&delivery.bytes);
    let _spawned = state.spawn_detached(async move {
        let status = send_guarded(&task_state, &stable, &agent, rule, bytes.as_slice()).await;
        task_state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .finish_mandate_attempt(&stable, &mandate_id, agent.as_bytes(), attempt, status);
    });
}

// ─── Promoted member: mandate intake and commit ────────────────────────────

/// Keep a mandate that names this node as the promoted member, after the
/// owner-signature check. The full §4b(1) checks run again at commit time.
async fn accept_mandate(state: &Arc<AppState>, mandate: orc::SignedOwnerRecoveryMandateV1) {
    if &mandate.body.promoted != state.agent.agent_id().as_bytes() {
        return;
    }
    let Some((_, info)) = group_by_stable(state, &mandate.body.stable_group_id).await else {
        return;
    };
    let Some(owner) = info.policy.admission.owner_certified_user_id() else {
        return;
    };
    if let Err(refusal) = orc::verify_mandate_signature(&mandate, owner) {
        tracing::info!(
            reason = refusal.as_str(),
            "ADR 0110 S4: owner recovery mandate refused"
        );
        return;
    }
    let stable = info.stable_group_id().to_string();
    let now = Instant::now();
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .pending
        .insert(
            stable.clone(),
            PendingMandate {
                mandate,
                wait: None,
                next_at: now,
            },
        );
    // #1625: the held mandate is written to the pending-mandate file, so a
    // restart of the promoted member keeps it.
    persist_mandates(state, &stable).await;
    state.agent.s4_revocation_intake().request_reconcile();
}

async fn set_wait(state: &AppState, stable: &str, wait: Option<(&'static str, Vec<[u8; 32]>)>) {
    if let Some(pending) = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .pending
        .get_mut(stable)
    {
        pending.wait = wait;
        pending.next_at = Instant::now() + ORC_COMMIT_RETRY;
    }
}

/// Author and install the `OwnerRecoveryV1` commit for a held mandate.
async fn try_commit(state: &Arc<AppState>, stable: &str) {
    use super::super as ng;
    let Some(group_key) = ng::resolve_named_group_storage_key(state, stable).await else {
        return;
    };
    let membership_lock = ng::group_membership_lock(state, &group_key).await;
    let _membership_guard = membership_lock.lock().await;
    // Read the held mandate under the membership lock: a concurrent
    // attempt (the worker pass and the route's own drive both run here)
    // may have committed it and removed it while this one waited. A
    // snapshot taken before the lock would author the same recovery again
    // on whatever head this node then holds.
    let Some(pending) = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .pending
        .get(stable)
        .cloned()
    else {
        return;
    };
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return;
    };
    let local = *state.agent.agent_id().as_bytes();
    let local_hex = hex::encode(local);
    let revocations = verified_agent_revocations(state).await;
    let certificate = info
        .members_v2
        .get(&local_hex)
        .and_then(|member| member.certificate.clone());
    if let Err(refusal) = orc::validate_mandate(
        &pending.mandate,
        &info,
        &revocations,
        certificate.as_ref(),
        now_unix(),
    ) {
        match refusal {
            // The revocation records may still be arriving, or this node
            // is behind the mandate's head: keep it.
            orc::OwnerRecoveryRefusal::RecoveryNotNeeded => {
                set_wait(state, stable, Some((refusal.as_str(), Vec::new()))).await;
            }
            orc::OwnerRecoveryRefusal::RecoveryHeadMismatch
                if info.state_revision < pending.mandate.body.parent_revision =>
            {
                set_wait(state, stable, Some((refusal.as_str(), Vec::new()))).await;
            }
            // #1625: a refusal that more data can clear is transient: the
            // containment can lift a quarantine, the revocation sets can
            // converge, and the seat's own state can change. Keep the
            // mandate with the typed cause and retry; every check runs
            // again before any commit, and a fresh mandate from the owner
            // replaces this one. Before, the drop made the recovery wait
            // for the owner's 5 s resend or a fresh signature.
            orc::OwnerRecoveryRefusal::RecoveryGroupQuarantined
            | orc::OwnerRecoveryRefusal::RecoveryProofInvalid
            | orc::OwnerRecoveryRefusal::RecoveryMemberIneligible => {
                set_wait(state, stable, Some((refusal.as_str(), Vec::new()))).await;
            }
            _ => {
                tracing::info!(
                    group_id = %ng::LogHexId::group(&group_key),
                    reason = refusal.as_str(),
                    "ADR 0110 S4: owner recovery mandate refused"
                );
                // Drop only the mandate this attempt checked; a newer one
                // that arrived meanwhile gets its own attempt. The head
                // left the mandate's parent (the recovery committed or the
                // group forked) or the signer is not the owner, so this
                // mandate can never chain here.
                let dropped = {
                    let mut inner = state.revocation_evictions.inner.lock().await;
                    let dropped = inner
                        .orc
                        .pending
                        .get(stable)
                        .is_some_and(|held| held.mandate == pending.mandate);
                    if dropped {
                        inner.orc.pending.remove(stable);
                    }
                    dropped
                };
                if dropped {
                    persist_mandates(state, stable).await;
                }
            }
        }
        return;
    }
    let Some(certificate) = certificate else {
        return;
    };
    let named: BTreeSet<[u8; 32]> = pending
        .mandate
        .body
        .revoked_admins
        .iter()
        .map(|admin| admin.agent)
        .collect();
    // D76: hold while a known Active member's current verified advert
    // lacks `owner_recovery_v1`; unknown or offline members are stranded.
    let capabilities = state.agent.capability_store();
    let holders =
        orc::receiver_upgrade_holders(survivors(&info, &local, &named).into_iter().map(|id| {
            (
                id,
                capabilities.verified_registry_supports(
                    &AgentId(id),
                    x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1,
                ),
            )
        }));
    if !holders.is_empty() {
        set_wait(
            state,
            stable,
            Some((
                x0x::groups::eviction::WaitingCause::WaitingForReceiverUpgrade.as_str(),
                holders,
            )),
        )
        .await;
        return;
    }
    // §2: a completed current catch-up round for this head and no
    // unresolved higher-head evidence, re-read under the membership lock
    // just before the seal. Elapsed time alone never authorizes it.
    if !super::group_head_synced(state, &group_key).await {
        set_wait(
            state,
            stable,
            Some((
                x0x::groups::eviction::WaitingCause::WaitingForHeadSync.as_str(),
                Vec::new(),
            )),
        )
        .await;
        return;
    }
    let kind = orc::crypto_kind(&info);
    let removed: Vec<orc::RemovedSeatV1> = pending
        .mandate
        .body
        .revoked_admins
        .iter()
        .map(|admin| orc::RemovedSeatV1 {
            agent: admin.agent,
            leaf_key_package_hash: (kind == orc::RecoveryCryptoKind::TreeKem)
                .then(|| {
                    info.members_v2
                        .get(&hex::encode(admin.agent))
                        .and_then(|member| member.treekem_key_package_hash.clone())
                })
                .flatten(),
        })
        .collect();
    let Ok(promoted_certificate) = bincode::serialize(&certificate) else {
        return;
    };
    let mut body = orc::OwnerRecoveryBodyV1 {
        stable_group_id: stable.to_string(),
        actor: local,
        prior_head: info.state_hash.clone(),
        prior_revision: info.state_revision,
        next_revision: info.state_revision.saturating_add(1),
        roster_revision: info.roster_revision.saturating_add(1),
        mandate: pending.mandate.clone(),
        promoted_certificate,
        removed,
        crypto: orc::OwnerRecoveryCryptoV1::SignedPublic,
        commit: x0x::groups::crypto_exclusion::CommitHeaderV1::from(
            &x0x::groups::GroupStateCommit {
                group_id: String::new(),
                revision: 0,
                prev_state_hash: None,
                roster_root: String::new(),
                policy_hash: String::new(),
                public_meta_hash: String::new(),
                security_binding: None,
                state_hash: String::new(),
                withdrawn: false,
                committed_by: String::new(),
                committed_at: 0,
                signer_public_key: String::new(),
                signature: String::new(),
            },
        ),
    };
    let mut next = info.clone();
    next.roster_revision = body.roster_revision;
    orc::apply_roster_change(&mut next, &body);
    match kind {
        orc::RecoveryCryptoKind::TreeKem => {
            commit_treekem(state, &group_key, &info, next, body, &revocations).await;
        }
        orc::RecoveryCryptoKind::Gss => {
            let (secret, next_secret_epoch) = next.rotate_shared_secret();
            let Ok(secret) = <[u8; 32]>::try_from(secret.as_slice()) else {
                return;
            };
            body.crypto = orc::OwnerRecoveryCryptoV1::Gss { next_secret_epoch };
            // Build every survivor envelope before the commit: a keyless
            // survivor aborts the rotation (F1 §5 fail-closed). The shares
            // leave later, each after the frame write to its survivor
            // ([`spawn_commit_send`], #1508 r5).
            for member in next.active_members() {
                if member.agent_id == local_hex {
                    continue;
                }
                let Some(kem) = member.kem_public_key_b64.as_deref() else {
                    tracing::warn!(group_id = %ng::LogHexId::group(&group_key), "ADR 0110 S4: owner recovery deferred: a survivor has no roster KEM key");
                    set_wait(state, stable, None).await;
                    return;
                };
                if ng::build_secure_share_event(
                    stable,
                    &member.agent_id,
                    kem,
                    &local_hex,
                    &secret,
                    next_secret_epoch,
                )
                .is_err()
                {
                    set_wait(state, stable, None).await;
                    return;
                }
            }
            if finish_commit(state, &group_key, &info, next, body, &revocations, None).await {
                let mut mls_groups = state.mls_groups.write().await;
                if let Some(group) = mls_groups.get_mut(&group_key) {
                    for agent in &named {
                        if group.is_member(&AgentId(*agent)) {
                            let _ = group.remove_member(AgentId(*agent)).await;
                        }
                    }
                }
                drop(mls_groups);
                ng::save_mls_groups(state).await;
            }
        }
        orc::RecoveryCryptoKind::SignedPublic => {
            finish_commit(state, &group_key, &info, next, body, &revocations, None).await;
        }
    }
}

/// The TreeKEM arm: one `remove_member_verified` per revoked leaf on this
/// node's tree, then the shared seal/persist/deliver tail.
async fn commit_treekem(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    mut next: GroupInfo,
    mut body: orc::OwnerRecoveryBodyV1,
    revocations: &orc::VerifiedAgentRevocations,
) {
    use super::super as ng;
    use base64::Engine as _;
    let stable = info.stable_group_id().to_string();
    let tree = {
        let map = state.treekem_groups.read().await;
        map.get(group_key)
            .or_else(|| map.get(&info.mls_group_id))
            .or_else(|| map.get(&stable))
            .cloned()
    };
    let Some(tree) = tree else {
        set_wait(state, &stable, None).await;
        return;
    };
    let mut guard = tree.lock().await;
    let Ok(rollback_snapshot) = guard.to_snapshot_bytes() else {
        return;
    };
    let mut commits = Vec::new();
    for seat in &body.removed {
        if seat.leaf_key_package_hash.is_none() {
            continue;
        }
        let seat_hex = hex::encode(seat.agent);
        let kp = match ng::resolve_member_treekem_kp_for_removal_locked(state, group_key, &seat_hex)
            .await
            .ok()
            .and_then(|b64| ng::BASE64.decode(b64).ok())
        {
            Some(kp) => kp,
            None => {
                // §3: a miss never counts as an absent leaf; the
                // member-keyed catch-up was requested.
                ng::rollback_treekem_group_after_failed_install(
                    state,
                    group_key,
                    info,
                    &rollback_snapshot,
                    &mut guard,
                    "owner_recovery_key_package_pending",
                );
                set_wait(
                    state,
                    &stable,
                    Some((
                        x0x::groups::eviction::WaitingCause::WaitingForMemberKeyPackage.as_str(),
                        vec![seat.agent],
                    )),
                )
                .await;
                return;
            }
        };
        match guard.remove_member_verified(AgentId(seat.agent), &kp) {
            Ok(commit) => commits.push(commit),
            Err(error) => {
                ng::rollback_treekem_group_after_failed_install(
                    state,
                    group_key,
                    info,
                    &rollback_snapshot,
                    &mut guard,
                    "owner_recovery_remove_failed",
                );
                tracing::warn!(group_id = %ng::LogHexId::group(group_key), "ADR 0110 S4: owner recovery deferred: remove_member failed: {error}");
                set_wait(state, &stable, None).await;
                return;
            }
        }
    }
    let next_epoch = guard.epoch();
    next.secret_epoch = next_epoch;
    next.security_binding = Some(orc::treekem_binding(next_epoch, &commits));
    body.crypto = orc::OwnerRecoveryCryptoV1::TreeKem {
        commits,
        next_epoch,
    };
    // The removed admins' attested `MemberJoined` entries stay cached:
    // they are the leaf evidence a survivor that holds only the committed
    // hash asks for before it can prove this commit (#1508 review P1).
    finish_commit(
        state,
        group_key,
        info,
        next.clone(),
        body,
        revocations,
        Some((&mut *guard, rollback_snapshot.as_slice())),
    )
    .await;
}

/// Seal, sign, self-check, persist and schedule delivery. `tree` is the
/// TreeKEM group (already holding the removals) with its rollback
/// snapshot. Returns whether the commit is installed.
async fn finish_commit(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    mut next: GroupInfo,
    mut body: orc::OwnerRecoveryBodyV1,
    revocations: &orc::VerifiedAgentRevocations,
    mut tree: Option<(&mut x0x::mls::TreeKemMlsGroup, &[u8])>,
) -> bool {
    use super::super as ng;
    let stable = info.stable_group_id().to_string();
    let current_epoch = info.secret_epoch;
    let rollback = |tree: &mut Option<(&mut x0x::mls::TreeKemMlsGroup, &[u8])>,
                    next: &GroupInfo,
                    reason: &str| {
        if let Some((guard, snapshot)) = tree.as_mut() {
            ng::rollback_treekem_group_after_failed_install(
                state, group_key, next, snapshot, guard, reason,
            );
        }
    };
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
            rollback(&mut tree, &next, "owner_recovery_seal_failed");
            tracing::warn!(group_id = %ng::LogHexId::group(group_key), "ADR 0110 S4: owner recovery deferred: seal failed: {error}");
            set_wait(state, &stable, None).await;
            return false;
        }
    };
    body.commit = x0x::groups::crypto_exclusion::CommitHeaderV1::from(&commit);
    // The author runs the receivers' L4 rule on its own frame first.
    let tree_epoch = match &body.crypto {
        orc::OwnerRecoveryCryptoV1::TreeKem {
            commits,
            next_epoch,
        } => next_epoch.saturating_sub(commits.len() as u64),
        _ => current_epoch,
    };
    if let Err(refusal) =
        orc::validate_against_parent(&body, info, tree_epoch, revocations, now_unix())
    {
        rollback(&mut tree, &next, "owner_recovery_self_check_failed");
        tracing::warn!(group_id = %ng::LogHexId::group(group_key), reason = refusal.as_str(), "ADR 0110 S4: owner recovery self-check failed");
        set_wait(state, &stable, None).await;
        return false;
    }
    let removed: Vec<String> = body
        .removed
        .iter()
        .map(|seat| hex::encode(seat.agent))
        .collect();
    let next_revision = body.next_revision;
    let reshare_epoch = gss_epoch(&body);
    let Some(bytes) = orc::sign_commit(body, signing_kp).ok().and_then(|frame| {
        orc::encode_frame(&orc::OwnerRecoveryFrameV1::Commit(Box::new(frame))).ok()
    }) else {
        rollback(&mut tree, &next, "owner_recovery_sign_failed");
        return false;
    };
    if bytes.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        // §4: an oversized frame waits for the existing evidence route; no
        // new carrier is invented.
        rollback(&mut tree, &next, "owner_recovery_oversized");
        tracing::warn!(group_id = %ng::LogHexId::group(group_key), "ADR 0110 S4: owner recovery deferred: the frame exceeds the direct carrier limit");
        set_wait(state, &stable, None).await;
        return false;
    }
    // #1508 review: the exact frame is durable before the local commit, so
    // a crash before the delivery cannot lose the chain link.
    let bytes = Arc::new(bytes);
    let ext = replay_log::RECOVERY_EXTENSION;
    ensure_restored(state).await;
    let at = (next_revision, commit.state_hash.as_str());
    if !replay_log::write_planned(state, ext, held, &stable, at, &bytes).await {
        rollback(&mut tree, &next, "owner_recovery_frame_not_durable");
        tracing::error!(group_id = %ng::LogHexId::group(group_key), "ADR 0110 S4: owner recovery deferred: the frame is not durable");
        set_wait(state, &stable, None).await;
        return false;
    }
    for seat in &removed {
        ng::quiesce_member_join_egress(state, group_key, seat).await;
    }
    // #1574 item 1: both non-durable shapes below are treated as
    // committed, and that evidence is enough for the drops after them.
    // `ReplacedNotDurable` keeps the installed candidate in the map (the
    // persist rolls back only refusal outcomes and hard errors), so this
    // process never sees the install revert — the preflight refusal
    // stages nothing and reports its own outcomes, so it never reaches
    // these committed arms.
    // The epoch-installed error is committed state: the journal it leaves
    // is already the commit point, which a restart replays, and its
    // non-durable roster arm converges memory to the candidate and sets
    // the same confirmation flag.
    // A power loss before a confirming save is the one revert. It erases
    // this node's memory, so the `pending` entry is gone regardless of
    // the drop above; the durable loss is the mandate retire. When the
    // owner is another node, its durable wait still applies (the reverted
    // head is the mandate's parent) and `drive_mandates` sends the
    // mandate again, so the member re-holds it and commits a fresh frame.
    // When this node is the owner's own agent, no wait exists anywhere
    // and nothing re-sends; the owner issues the mandate again, and its
    // route still applies to the reverted head. The durable frame above
    // is chain evidence, not a re-drive (a restart restores an authored
    // frame only at the loaded head), and it was never sent (the §5
    // egress guard held it), so a fresh frame cannot equivocate with it.
    let persisted = match tree.as_ref() {
        Some((guard, _)) => {
            match ng::persist_treekem_and_named_groups_atomic_with_info(
                state,
                group_key,
                next.clone(),
                guard,
            )
            .await
            {
                Ok(()) => true,
                Err(error) => ng::self_leave_persist_left_epoch_installed(&error),
            }
        }
        // #1508 r6: `ReplacedNotDurable` installed the new roster (only
        // the directory fsync failed), so the commit stands and the frame
        // and its delivery must stay. The guarded egress publishes nothing
        // until the re-save is durable (§5, #1508 rc12). The preflight
        // refusal stages nothing and reports `NotReplaced` (#1574 item 1,
        // slice 3), so a refused commit never reaches the drops below.
        None => matches!(
            ng::persist_named_group_info(state, group_key, next.clone()).await,
            Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
        ),
    };
    if !persisted {
        replay_log::rewrite_without(state, ext, held, &stable, at).await;
        rollback(&mut tree, &next, "owner_recovery_persist_failed");
        tracing::error!(group_id = %ng::LogHexId::group(group_key), "ADR 0110 S4: owner recovery deferred: persist failed");
        set_wait(state, &stable, None).await;
        return false;
    }
    for seat in &removed {
        ng::purge_join_artifacts_if_ineligible(state, group_key, seat).await;
    }
    let local = *state.agent.agent_id().as_bytes();
    let removed_ids: BTreeSet<[u8; 32]> = removed.iter().filter_map(|id| agent_bytes(id)).collect();
    let recipients = survivors(&next, &local, &removed_ids);
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.orc.pending.remove(&stable);
        inner.orc.log.remember(
            &stable,
            next_revision,
            &commit.state_hash,
            Arc::clone(&bytes),
            true,
        );
        inner.orc.deliveries.insert(
            stable.clone(),
            CommitDelivery {
                bytes,
                result_head: commit.state_hash.clone(),
                next_revision,
                recipients: recipients
                    .into_iter()
                    .map(|id| (id, RecipientDelivery::Due))
                    .collect(),
                next_at: Instant::now(),
                resumed: false,
                removed: removed_ids,
                reshare_epoch,
                share_went_to: BTreeMap::new(),
            },
        );
    }
    // #1625: the consumed mandate leaves the pending-mandate file, so a
    // restart cannot resurrect it.
    persist_mandates(state, &stable).await;
    tracing::info!(
        group_id = %ng::LogHexId::group(group_key),
        removed = removed.len(),
        "ADR 0110 S4: owner recovery committed; this node is now an admin"
    );
    state.agent.s4_revocation_intake().request_reconcile();
    let task_state = Arc::clone(state);
    let card_key = group_key.to_string();
    let _spawned = state.spawn_detached(async move {
        ng::maybe_publish_group_card_after_state_change(&task_state, &card_key).await;
        drive_deliveries(&task_state).await;
    });
    true
}

// ─── Commit delivery ───────────────────────────────────────────────────────

async fn drive_deliveries(state: &Arc<AppState>) {
    let now = Instant::now();
    let restored: BTreeSet<String> = {
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .orc
            .deliveries
            .iter()
            .filter(|(_, delivery)| delivery.resumed && delivery.next_at <= now)
            .map(|(stable, _)| stable.clone())
            .collect()
    };
    // #1508 review F3: a restored delivery waits for its group's real
    // head sync (ADR 0110 §3), the gate of the removal and crypto-exclusion
    // resends, not only for the local chain.
    let synced = super::rebind::restored_groups_head_synced(state, restored).await;
    let due: Vec<(String, CommitDelivery)> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner
            .orc
            .deliveries
            .iter_mut()
            .filter(|(stable, delivery)| {
                delivery.next_at <= now && (!delivery.resumed || synced.contains(*stable))
            })
            .map(|(id, delivery)| {
                delivery.next_at = now + ORC_RESEND_INTERVAL;
                (id.clone(), delivery.clone())
            })
            .collect()
    };
    let local = *state.agent.agent_id().as_bytes();
    let capabilities = state.agent.capability_store();
    for (stable, delivery) in due {
        // #1574 item 5: the gone/head-moved read below drops the delivery
        // and its GSS reshare obligation, so it reads committed roster
        // state only (`committed_group_by_stable`).
        let info = committed_group_by_stable(state, &stable).await;
        let Some(info) = info.filter(|info| {
            !info.withdrawn
                && info.fork_quarantine.is_none()
                && info.state_hash == delivery.result_head
        }) else {
            // The head moved past the recovery (or the group is contained):
            // stop. Stranded members recover through catch-up.
            let mut inner = state.revocation_evictions.inner.lock().await;
            if inner
                .orc
                .deliveries
                .get(&stable)
                .is_some_and(|stored| stored.result_head == delivery.result_head)
            {
                inner.orc.deliveries.remove(&stable);
            }
            continue;
        };
        let active: BTreeSet<[u8; 32]> = survivors(&info, &local, &BTreeSet::new())
            .into_iter()
            .collect();
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
            // §3: a written commit is not an installed one. Ask the
            // survivor for its head and send the commit again, admitted
            // afresh, until it converges.
            if *status == RecipientDelivery::Sent {
                head_asks.push(agent);
            }
            if !write_allowed(state, &agent).await {
                continue;
            }
            let next = match capabilities
                .verified_registry_supports(&agent, x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1)
            {
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
        let started = state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .install_commit_round(&stable, &delivery.result_head, updates);
        for (recipient, attempt) in started {
            spawn_commit_send(state, &stable, &delivery, AgentId(recipient), attempt);
        }
        // #1660 (Engineer ruling, 30 Oct 05:10 GMT): this ask is
        // dispatched after this round's send tasks, and its count lands
        // only when its request went out. A round's re-seal to the same
        // key keeps the earliest bar and does not advance the share-seal
        // generation, so the ask is credited even when the commit's ACK
        // and re-seal land while it is in flight: the seat closes on
        // this round's answer, not only in a round whose ask wins that
        // race.
        ask_heads(state, &stable, head_asks).await;
        for agent in refreshes {
            let task_state = Arc::clone(state);
            let _spawned = state.spawn_detached(async move {
                task_state
                    .agent
                    .refresh_application_capability(
                        agent,
                        x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1,
                    )
                    .await;
            });
        }
    }
}

/// Seal `info`'s current GSS secret to `recipient` with the envelope the
/// commit built ([`super::super::build_secure_share_event`]), a D60
/// class-K delivery with a fresh epoch-bound admission per write. Nothing
/// is sealed when the group's secret epoch is not `epoch`: old key
/// material is never sent after an epoch change. A survivor without a
/// roster KEM key cannot get a share; it is logged and skipped. #1660: a
/// successful seal is recorded ([`super::crypto_exclusion::note_share_went_to`])
/// before the share's send task leaves, so a later report from the seat
/// closes the row only after a share went to the key the seat carries
/// then.
async fn seal_gss_share(state: &Arc<AppState>, info: &GroupInfo, recipient: &[u8; 32], epoch: u64) {
    use super::super as ng;
    if info.secret_epoch != epoch {
        return;
    }
    let Some(secret) = info
        .shared_secret
        .as_deref()
        .and_then(|secret| <[u8; 32]>::try_from(secret).ok())
    else {
        return;
    };
    let stable = info.stable_group_id();
    let actor = hex::encode(state.agent.agent_id().as_bytes());
    let recipient_hex = hex::encode(recipient);
    let Some(kem) = info
        .members_v2
        .get(&recipient_hex)
        .and_then(|member| member.kem_public_key_b64.as_deref())
    else {
        tracing::warn!(group_id = %ng::LogHexId::group(stable), recipient = %ng::LogHexId::agent(&recipient_hex), "ADR 0110 S4: no KEM key on record for a survivor; cannot seal the recovery secret");
        return;
    };
    match ng::build_secure_share_event(stable, &recipient_hex, kem, &actor, &secret, epoch) {
        Ok(event) => {
            // #1660 (Claude review): the record claims a share went out.
            // A refused spawn sealed nothing, so it records nothing.
            if ng::spawn_secure_share_delivery(state, &event) {
                super::crypto_exclusion::note_share_went_to(state, stable, epoch, recipient, kem)
                    .await;
            }
        }
        Err(_) => tracing::warn!(
            group_id = %ng::LogHexId::group(stable),
            recipient = %ng::LogHexId::agent(&recipient_hex),
            "ADR 0110 S4: cannot seal the recovery secret to a survivor"
        ),
    }
}

fn spawn_commit_send(
    state: &Arc<AppState>,
    stable: &str,
    delivery: &CommitDelivery,
    agent: AgentId,
    attempt: u64,
) {
    let task_state = Arc::clone(state);
    let stable = stable.to_string();
    let result_head = delivery.result_head.clone();
    let bytes = Arc::clone(&delivery.bytes);
    let reshare_epoch = delivery.reshare_epoch;
    let _spawned = state.spawn_detached(async move {
        let rule = HeadRule::Current(result_head.clone());
        let status = send_guarded(&task_state, &stable, &agent, rule, bytes.as_slice()).await;
        let recorded = task_state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .finish_commit_attempt(&stable, &result_head, agent.as_bytes(), attempt, status);
        // #1508 r5: a GSS survivor's share follows its frame write, so the
        // obligation stays with the frame until that write lands, and a
        // restored delivery (all recipients `Due`) seals it again. The
        // receiver also holds a share that still overtakes the frame
        // ([`park_early_share`]).
        if !recorded || status != RecipientDelivery::Sent {
            return;
        }
        let Some(epoch) = reshare_epoch else {
            return;
        };
        let info = group_by_stable(&task_state, &stable)
            .await
            .map(|(_, info)| info)
            .filter(|info| {
                !info.withdrawn && info.fork_quarantine.is_none() && info.state_hash == result_head
            });
        if let Some(info) = info {
            seal_gss_share(&task_state, &info, agent.as_bytes(), epoch).await;
        }
    });
}

// ─── Catch-up serving ──────────────────────────────────────────────────────

/// Serve the recovery commit frames this node holds for the group (any of
/// `group_ids`) above `from_revision` to a catch-up requester, oldest
/// first, on the distinct gated carrier only, never inside a legacy
/// catch-up page (§4b(1) "Mixed versions"). A competing frame kept as
/// fork evidence (#1579) is not on this node's verified chain, so it is
/// skipped, not served, and it does not stop the round. A
/// fork-quarantined group serves nothing on purpose: `head_rule_admits`
/// refuses every frame of it, so the skip leaves the round empty. Each
/// write uses the guarded admission with [`HeadRule::OnChain`] and the
/// `owner_recovery_v1` gate.
///
/// The author's frames survive a restart ([`replay_log`]). A GSS frame
/// moves the requester's epoch without the secret, so an admin also seals
/// its current secret to the requester (#1508 review), as the
/// crypto-exclusion catch-up does.
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
        .orc
        .log
        .catchup_frames(group_ids, from_revision);
    if frames.is_empty() {
        return;
    }
    // The frames all come from one group (`catchup_frames` serves the
    // first of `group_ids` that has a log).
    let Some(first_group) = frames.first().map(|(group, _, _)| group.clone()) else {
        return;
    };
    let Some((_, info)) = group_by_stable(state, &first_group).await else {
        return;
    };
    let mut gss_groups = BTreeSet::new();
    for (group_id, result_head, bytes) in frames {
        // #1579: a competing frame kept as fork evidence is not on this
        // node's verified chain. It is never served, and it does not stop
        // the round for the frames that are.
        if !head_rule_admits(&info, &HeadRule::OnChain(result_head.clone())) {
            continue;
        }
        if matches!(
            orc::decode_frame(&bytes),
            Ok(orc::OwnerRecoveryFrameV1::Commit(frame))
                if matches!(frame.body.crypto, orc::OwnerRecoveryCryptoV1::Gss { .. })
        ) {
            gss_groups.insert(group_id.clone());
        }
        let status = send_guarded(
            state,
            &group_id,
            requester,
            HeadRule::OnChain(result_head),
            bytes.as_slice(),
        )
        .await;
        if status != RecipientDelivery::Sent {
            return;
        }
    }
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    for group_id in gss_groups {
        let info = group_by_stable(state, &group_id)
            .await
            .map(|(_, info)| info);
        if let Some(info) = info.filter(|info| {
            info.caller_role(&local_hex)
                .is_some_and(|role| role.at_least(x0x::groups::GroupRole::Admin))
        }) {
            seal_gss_share(state, &info, requester.as_bytes(), info.secret_epoch).await;
        }
    }
}

// ─── Receive ───────────────────────────────────────────────────────────────

/// The result of one commit receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveOutcome {
    Applied,
    Duplicate,
    /// Behind the parent, missing revocation evidence, or a local fault:
    /// keep the frame for a retry. `verified`: the frame passed every
    /// check this node can make on its latest head, so it is known
    /// higher-head evidence (#1508 rc18, [`FrameStash`]).
    Retained {
        verified: bool,
    },
    Refused(orc::OwnerRecoveryRefusal),
    NotApplicable,
}

/// The direct-message listener hands every `X0XORC1` payload here.
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
        match orc::decode_frame(&payload) {
            Ok(orc::OwnerRecoveryFrameV1::Mandate(mandate)) => {
                accept_mandate(&task_state, mandate).await;
            }
            Ok(orc::OwnerRecoveryFrameV1::Commit(frame)) => {
                let body = frame.body.clone();
                if let ReceiveOutcome::Retained { verified } =
                    receive_commit(&task_state, sender, *frame, &payload).await
                {
                    let frame = stashed(sender, payload, &body, verified);
                    let mut inner = task_state.revocation_evictions.inner.lock().await;
                    let _kept = inner.orc.stash.push(frame);
                }
            }
            Err(refusal) => {
                tracing::debug!(
                    reason = refusal.as_str(),
                    "ADR 0110 S4: owner recovery frame refused"
                );
            }
        }
    });
}

/// #1508 r5: hold a `SecureShareDelivered` that the share arm refused
/// because its actor is not an admin on this node's roster, when it can be
/// the share of a GSS owner recovery, or of a GSS crypto-only exclusion,
/// that has not installed here yet (#1508 rc13: the sender can be an admin
/// that a later commit promotes). The share and the frame use different
/// carriers, so the share can arrive first, and the sender seals it only
/// once. The group is a GSS group, the sender is the actor, and the share
/// is for a later epoch. Nothing is opened or installed here:
/// [`replay_early_shares`] runs the full share apply again after the frame
/// installs. Bounded by [`ORC_STASH_CAP`] and [`ORC_RETAIN_TTL`].
///
/// #1533 rc18 (Codex P1): the sender can also be absent from this node's
/// roster. A later admin can add B, promote B and go offline; B is not on
/// a stale survivor's roster. Such a share is a candidate: it is kept
/// only in a bound of [`ORC_CANDIDATE_SHARES_PER_GROUP`] per group and one
/// per sender, and it is evicted before a member's share. Its sender is
/// validated when it is used: [`promoted_admin_secret`] uses a share only
/// from an admin of a roster that the verified held chain reaches. When
/// the group's candidate bound is full, a new candidate is kept only when
/// a held, signed commit of the group adds its sender
/// ([`held_add_names`]), and it replaces a candidate that no held commit
/// adds.
pub(in crate::server) async fn park_early_share(
    state: &AppState,
    info: &GroupInfo,
    event: &super::super::NamedGroupMetadataEvent,
    sender: AgentId,
    verified: bool,
) {
    let super::super::NamedGroupMetadataEvent::SecureShareDelivered {
        secret_epoch,
        actor,
        ..
    } = event
    else {
        return;
    };
    let sender_hex = hex::encode(sender.as_bytes());
    if !verified
        || info.withdrawn
        || orc::crypto_kind(info) != orc::RecoveryCryptoKind::Gss
        || *actor != sender_hex
        || *secret_epoch < info.secret_epoch
        || (*secret_epoch == info.secret_epoch && info.shared_secret.is_some())
    {
        return;
    }
    let share = ParkedShare {
        stable_group_id: info.stable_group_id().to_string(),
        event: event.clone(),
        sender,
        at: Instant::now(),
        candidate: !info.has_active_member(&sender_hex),
    };
    let mut inner = state.revocation_evictions.inner.lock().await;
    let orc = &mut inner.orc;
    if !park_share(&mut orc.early_shares, &orc.held_events, share) {
        return;
    }
    drop(inner);
    // A stashed GSS recovery waits for this share (#1508 rc12).
    state.agent.s4_revocation_intake().request_reconcile();
}

/// Add `share` to `parked` under the [`park_early_share`] bounds. Returns
/// whether it was kept.
fn park_share(parked: &mut Vec<ParkedShare>, held: &[HeldEvent], share: ParkedShare) -> bool {
    let now = share.at;
    parked.retain(|kept| now.saturating_duration_since(kept.at) <= ORC_RETAIN_TTL);
    if share.candidate {
        // One candidate per sender and group: the newer share replaces it.
        parked.retain(|kept| {
            !(kept.candidate
                && kept.stable_group_id == share.stable_group_id
                && kept.sender == share.sender)
        });
        let in_group =
            |kept: &ParkedShare| kept.candidate && kept.stable_group_id == share.stable_group_id;
        if parked.iter().filter(|kept| in_group(kept)).count() >= ORC_CANDIDATE_SHARES_PER_GROUP {
            if !held_add_names(held, &share.stable_group_id, &share.sender) {
                return false;
            }
            let Some(at) = parked.iter().position(|kept| {
                in_group(kept) && !held_add_names(held, &kept.stable_group_id, &kept.sender)
            }) else {
                return false;
            };
            parked.remove(at);
        }
    }
    if parked.len() >= ORC_STASH_CAP {
        // A candidate goes before a member's share.
        let at = parked.iter().position(|kept| kept.candidate).unwrap_or(0);
        parked.remove(at);
    }
    parked.push(share);
    true
}

/// A held, signed commit of `stable_group_id` adds `sender`
/// ([`hold_unchained_event`]). This only orders the candidate bound: the
/// share is still used only from an admin of a verified walked roster.
fn held_add_names(held: &[HeldEvent], stable_group_id: &str, sender: &AgentId) -> bool {
    let sender_hex = hex::encode(sender.as_bytes());
    held.iter().any(|held| {
        held.stable_group_id == stable_group_id
            && matches!(
                &held.event,
                super::super::NamedGroupMetadataEvent::MemberAdded { agent_id, .. }
                    if *agent_id == sender_hex
            )
    })
}

/// What the parked early shares of `body`'s group hold for this node, for
/// a GSS recovery to epoch `epoch` ([`parked_key`]).
enum ParkedKey {
    /// `body`'s actor sealed the secret of `epoch` to this node.
    Exact([u8; 32]),
    /// No share of `epoch`, but the actor (`may_seal_later`) sealed a later
    /// epoch's secret to this node, and it opens: the recovery is an
    /// intermediate head of the chain.
    Later,
    Missing,
}

/// Look up the parked early shares of `body`'s group addressed to this
/// node, opened with this node's KEM key. The shares stay parked:
/// [`replay_early_shares`] runs their full apply after the install.
async fn parked_key(
    state: &AppState,
    body: &orc::OwnerRecoveryBodyV1,
    epoch: u64,
    may_seal_later: impl Fn(&AgentId) -> bool,
) -> ParkedKey {
    let parked = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .early_shares
        .clone();
    let open = |share: &ParkedShare| open_parked_share(state, share);
    let mut later = false;
    for share in parked
        .iter()
        .filter(|share| share.stable_group_id == body.stable_group_id)
    {
        match open(share) {
            Some((at, secret)) if at == epoch && share.sender.as_bytes() == &body.actor => {
                return ParkedKey::Exact(secret);
            }
            Some((at, _)) if at > epoch && may_seal_later(&share.sender) => later = true,
            _ => {}
        }
    }
    if later {
        ParkedKey::Later
    } else {
        ParkedKey::Missing
    }
}

/// Open a parked share addressed to this node with its KEM key: its
/// secret epoch and secret.
fn open_parked_share(state: &AppState, share: &ParkedShare) -> Option<(u64, [u8; 32])> {
    use base64::Engine as _;
    let super::super::NamedGroupMetadataEvent::SecureShareDelivered {
        group_id,
        recipient,
        secret_epoch,
        kem_ciphertext_b64,
        aead_nonce_b64,
        aead_ciphertext_b64,
        ..
    } = &share.event
    else {
        return None;
    };
    if *recipient != hex::encode(state.agent.agent_id().as_bytes()) {
        return None;
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let nonce: [u8; 12] = b64.decode(aead_nonce_b64).ok()?.try_into().ok()?;
    let secret = x0x::groups::kem_envelope::open_group_secret(
        &state.agent_kem_keypair,
        &x0x::groups::aad::secure_share_aad(group_id, recipient, *secret_epoch),
        &b64.decode(kem_ciphertext_b64).ok()?,
        &nonce,
        &b64.decode(aead_ciphertext_b64).ok()?,
    )
    .ok()?;
    Some((*secret_epoch, secret))
}

/// What [`promoted_admin_secret`] found for a waiting GSS transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum LaterAdminKey {
    /// The secret of the transition's epoch: the transition installs with
    /// it.
    Exact([u8; 32]),
    /// #1508 rc15 (Codex P1): the checked held chain rotates past the
    /// transition's epoch, and a share of the chain's later epoch opens.
    /// No holder seals the transition's own secret any more, so the
    /// transition installs as an intermediate head with no secret (the old
    /// secret is dropped, so nothing is sealed under it). The held chain
    /// then replays on it, and its last rotation installs the later secret
    /// through the ordinary apply. The only delivery that this keyless head
    /// can end is that of the transition's own secret, which the later
    /// secret supersedes; the later rotation's delivery stays open until
    /// this node's head reaches it, with its key.
    Superseded,
}

/// #1508 rc13/rc14 (Codex P1): the secret of `epoch` for a GSS removal,
/// ban or crypto-only exclusion whose verified, keyless result is
/// `result`, from a later admin. The transition's actor can promote an
/// admin and go offline, also after other commits (a rename); a lagging
/// survivor then catches up from that admin. Its share is refused while it
/// is a Member here, and the later commits chain on the transition, which
/// waits for a share.
///
/// The share is used only when the held commits after `result` make its
/// sender an active admin. Each step is checked as the ordinary apply
/// checks it, on the roster the step before produced
/// ([`next_held_state`]): the revocation gate, the commit's signature and
/// signer authority, the event's own authority rules, and the result state
/// hash, which binds the
/// signed roster root to the event's fields. So a held event whose fields
/// do not match its commit (a forged promotion around a genuine commit)
/// promotes nobody. The transition then installs with this secret, so its
/// head still means that the key is installed: a keyless head could end a
/// key delivery that later same-epoch commits keep open. The ordinary
/// apply checks the held commits again when they replay.
///
/// #1508 rc15 (Codex P1): the walk also follows a held GSS removal or ban
/// that an admin of the walked roster signed, which rotates to a later
/// epoch. Catch-up seals the current secret only, so after such a rotation
/// no holder seals `epoch`'s secret any more. A share of the later epoch
/// from an admin of that later roster gives [`LaterAdminKey::Superseded`].
pub(in crate::server) async fn promoted_admin_secret(
    state: &AppState,
    result: &GroupInfo,
    epoch: u64,
) -> Option<LaterAdminKey> {
    let stable_group_id = result.stable_group_id().to_string();
    let now = Instant::now();
    let (held, parked): (Vec<HeldEvent>, Vec<ParkedShare>) = {
        let inner = state.revocation_evictions.inner.lock().await;
        (
            inner
                .orc
                .held_events
                .iter()
                .filter(|held| {
                    held.stable_group_id == stable_group_id
                        && now.saturating_duration_since(held.at) <= ORC_RETAIN_TTL
                })
                .cloned()
                .collect(),
            inner
                .orc
                .early_shares
                .iter()
                .filter(|share| {
                    share.stable_group_id == stable_group_id
                        && now.saturating_duration_since(share.at) <= ORC_RETAIN_TTL
                })
                .cloned()
                .collect(),
        )
    };
    if parked.is_empty() {
        return None;
    }
    // A revoked agent signs no step and sends no trusted share, as in the
    // ordinary apply's revocation gate. A revoked agent is not added either
    // (the OwnerCertified add check).
    let (held, parked) = {
        let revocation_set = state.agent.revocation_set();
        let revoked = revocation_set.read().await;
        (
            held.into_iter()
                .filter(|held| {
                    !revoked.is_agent_revoked(&held.author)
                        && match &held.event {
                            super::super::NamedGroupMetadataEvent::MemberAdded {
                                agent_id, ..
                            } => super::super::parse_agent_id_hex(agent_id)
                                .is_ok_and(|agent| !revoked.is_agent_revoked(&agent)),
                            _ => true,
                        }
                })
                .collect::<Vec<_>>(),
            parked
                .into_iter()
                .filter(|share| !revoked.is_agent_revoked(&share.sender))
                .collect::<Vec<_>>(),
        )
    };
    // A share of the roster's own epoch from an admin of that roster.
    let admin_share = |roster: &GroupInfo| {
        parked
            .iter()
            .filter(|share| {
                roster
                    .caller_role(&hex::encode(share.sender.as_bytes()))
                    .is_some_and(|role| role.at_least(x0x::groups::GroupRole::Admin))
            })
            .find_map(|share| match open_parked_share(state, share) {
                Some((at, secret)) if at == roster.secret_epoch => Some(secret),
                _ => None,
            })
    };
    let mut cursor = result.clone();
    // Each step moves the revision up, so the walk ends; the bound keeps it
    // to the held set.
    for _ in 0..=held.len() {
        if let Some(secret) = admin_share(&cursor) {
            return Some(if cursor.secret_epoch == epoch {
                LaterAdminKey::Exact(secret)
            } else {
                LaterAdminKey::Superseded
            });
        }
        match held.iter().find_map(|held| next_held_state(&cursor, held)) {
            Some(next) => cursor = next,
            None => return None,
        }
    }
    None
}

/// The state after the held commit `held` on `cursor`, checked as the
/// ordinary apply checks it, or `None`. Only same-epoch roster and
/// metadata steps (a role update, a rename, a GSS add (#1508 rc16), a
/// policy update or an unban (#1508 rc17), or a member's own GSS leave
/// (#1533 rc17)) and
/// an admin's GSS removal or ban to a later epoch (#1508 rc15) are walked;
/// any other event, or one that fails a check, ends the walk, and the
/// transition keeps waiting for its share.
///
/// #1508 rc18 / #1533 rc19 (Codex P1): the rule is that every valid
/// intervening commit that the ordinary GSS apply accepts is walked: an
/// admin's removal or ban with or without a rotation, a member's own
/// leave, and the request-based admission steps (a request, its approval,
/// rejection or cancellation).
fn next_held_state(cursor: &GroupInfo, held: &HeldEvent) -> Option<GroupInfo> {
    use super::super::NamedGroupMetadataEvent as Event;
    let commit = super::super::named_group_metadata_event_commit(&held.event)?;
    if commit.prev_state_hash.as_deref() != Some(cursor.state_hash.as_str()) {
        return None;
    }
    let author = hex::encode(held.author.as_bytes());
    let admin = |actor: &str| {
        *actor == author
            && cursor
                .caller_role(actor)
                .is_some_and(|role| role.at_least(x0x::groups::GroupRole::Admin))
    };
    let next = match &held.event {
        Event::MemberRoleUpdated {
            revision,
            actor,
            agent_id,
            role,
            ..
        } => {
            // #1578 rc11 (audit): the join's key-only marker row is not
            // a seat — the replay stops on it, exactly as the apply
            // side parks a role update for a member that has not
            // landed.
            let target = cursor
                .members_v2
                .get(agent_id)
                .filter(|_| !cursor.join_seat_key_marker_only(agent_id))?;
            if !admin(actor)
                || target.is_removed()
                || target.is_banned()
                || *role == x0x::groups::GroupRole::Owner
            {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision =
                        super::super::adopt_roster_revision(next.roster_revision, *revision);
                    next.set_member_role(agent_id, *role);
                },
            )
        }
        Event::GroupMetadataUpdated {
            revision,
            actor,
            name,
            description,
            ..
        } => {
            if !admin(actor) {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision =
                        super::super::adopt_roster_revision(next.roster_revision, *revision);
                    if let Some(name) = name.clone() {
                        next.name = name;
                    }
                    if let Some(description) = description.clone() {
                        next.description = description;
                    }
                    next.updated_at = commit.committed_at;
                },
            )
        }
        // #1508 rc16 (Codex P1): an admin's GSS add between the removal
        // and a promotion. It seats a Member only and keeps the epoch.
        // An OwnerCertified add carries a certificate that verifies
        // against the owner, as in the ordinary apply; the caller drops an
        // add whose target is revoked.
        Event::MemberAdded {
            revision,
            actor,
            agent_id,
            display_name,
            treekem_commit_b64: None,
            treekem_epoch: None,
            certificate_b64,
            ..
        } => {
            if !admin(actor)
                || cursor.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
                || cursor
                    .members_v2
                    .get(agent_id)
                    .is_some_and(|m| m.is_active() || m.is_banned())
            {
                return None;
            }
            let certificate = match cursor.policy.admission.owner_certified_user_id() {
                Some(owner) => {
                    use base64::Engine as _;
                    let bytes = super::super::BASE64
                        .decode(certificate_b64.as_deref()?)
                        .ok()?;
                    let cert: x0x::identity::AgentCertificate =
                        bincode::deserialize(&bytes).ok()?;
                    x0x::groups::owner_cert::verify_cert_against_owner(
                        owner,
                        agent_id,
                        &cert,
                        false,
                        x0x::groups::owner_cert::restore_clock_now(),
                    )
                    .ok()?;
                    Some(cert)
                }
                None => None,
            };
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision =
                        super::super::adopt_roster_revision(next.roster_revision, *revision);
                    next.add_member(
                        agent_id.clone(),
                        x0x::groups::GroupRole::Member,
                        Some(actor.clone()),
                        display_name.clone(),
                    );
                    if let Some(cert) = certificate {
                        // A mismatched digest fails the result hash check.
                        let _ = next.set_member_certificate(agent_id, cert);
                    }
                    if let Some(name) = display_name.clone() {
                        next.set_display_name(agent_id, name);
                    }
                },
            )
        }
        // #1508 rc17 (Codex P1): an admin's policy update, or an unban,
        // between the removal and a promotion. Neither changes the epoch.
        // A policy update keeps an OwnerCertified owner axis, as in the
        // ordinary apply.
        Event::PolicyUpdated {
            revision,
            actor,
            policy,
            ..
        } => {
            if !admin(actor)
                || cursor
                    .policy
                    .admission
                    .owner_certified_user_id()
                    .is_some_and(|owner| policy.admission.owner_certified_user_id() != Some(owner))
            {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    super::super::set_policy_update(next, *revision, policy, commit.committed_at)
                },
            )
        }
        Event::MemberUnbanned {
            revision,
            actor,
            agent_id,
            ..
        } => {
            if !admin(actor) || cursor.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision =
                        super::super::adopt_roster_revision(next.roster_revision, *revision);
                    next.unban_member(agent_id);
                },
            )
        }
        // #1533 rc17 (Codex P1): an active member's own GSS leave between
        // the removal and a promotion, checked as the ordinary self-leave
        // apply checks it: the leaver signs, names itself, and neither
        // rotates nor carries a TreeKEM commit. It keeps the epoch.
        Event::MemberRemoved {
            revision,
            actor,
            agent_id,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            ..
        } if *actor == author && *agent_id == author => {
            if cursor.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
                || !cursor.has_active_member(agent_id)
            {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::MemberSelf,
                |next| {
                    next.roster_revision =
                        super::super::adopt_roster_revision(next.roster_revision, *revision);
                    next.remove_member(agent_id, Some(actor.clone()));
                },
            )
        }
        // #1508 rc18 (Codex P1): an admin's GSS removal or ban that does
        // not rotate, which the ordinary apply accepts too. It keeps the
        // epoch.
        Event::MemberRemoved {
            revision,
            actor,
            agent_id,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            ..
        }
        | Event::MemberBanned {
            revision,
            actor,
            agent_id,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            ..
        } => {
            let ban = matches!(held.event, Event::MemberBanned { .. });
            // #1578 rc11 (audit): the join's key-only marker row reads
            // as no seat here, and the mutation below drops it first —
            // ban_member on the marker would keep its Member role on
            // the Banned row, and the roster root binds the role, so
            // the reconstructed root would diverge from main's.
            let target = cursor
                .members_v2
                .get(agent_id)
                .filter(|_| !cursor.join_seat_key_marker_only(agent_id));
            if !admin(actor)
                || cursor.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
                || target.is_some_and(|member| member.is_banned())
                || (!ban && target.is_none_or(|member| member.is_removed()))
            {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision =
                        super::super::adopt_roster_revision(next.roster_revision, *revision);
                    if next.join_seat_key_marker_only(agent_id) {
                        next.members_v2.remove(agent_id);
                    }
                    if ban {
                        next.ban_member(agent_id, Some(actor.clone()));
                    } else {
                        next.remove_member(agent_id, Some(actor.clone()));
                    }
                },
            )
        }
        // #1508 rc15 (Codex P1): a later admin's GSS rotation, checked as
        // the ordinary removal and ban apply checks it.
        Event::MemberRemoved {
            revision,
            actor,
            agent_id,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: Some(to),
            ..
        } => {
            // #1578 rc11 (audit): the join's key-only marker row is not
            // a seat — the replay stops on it, and the mutation drops
            // it first so the removal sees exactly main's roster.
            let target = cursor
                .members_v2
                .get(agent_id)
                .filter(|_| !cursor.join_seat_key_marker_only(agent_id))?;
            if !admin(actor) || target.is_removed() || target.is_banned() {
                return None;
            }
            return gss_rotation_step(cursor, commit, *revision, *to, |next| {
                if next.join_seat_key_marker_only(agent_id) {
                    next.members_v2.remove(agent_id);
                }
                next.remove_member(agent_id, Some(actor.clone()));
            });
        }
        Event::MemberBanned {
            revision,
            actor,
            agent_id,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: Some(to),
            ..
        } => {
            if !admin(actor)
                || cursor
                    .members_v2
                    .get(agent_id)
                    .is_some_and(|m| m.is_banned())
            {
                return None;
            }
            return gss_rotation_step(cursor, commit, *revision, *to, |next| {
                // #1578 rc11 (audit): drop the join's key-only marker
                // row first — ban_member on it would keep its Member
                // role on the Banned row, and the roster root binds
                // the role.
                if next.join_seat_key_marker_only(agent_id) {
                    next.members_v2.remove(agent_id);
                }
                next.ban_member(agent_id, Some(actor.clone()));
            });
        }
        // #1533 rc19 (Codex P1): the request-based admission steps, checked
        // as the ordinary GSS apply checks them. A requester's own request
        // or cancellation, and an admin's approval or rejection of a
        // pending request. None changes the epoch.
        Event::JoinRequestCreated {
            group_id,
            request_id,
            requester_agent_id,
            message,
            ts,
            requester_kem_public_key_b64,
            treekem_key_package_b64,
            ..
        } => {
            if *requester_agent_id != author
                || cursor.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
                || cursor.policy.admission != x0x::groups::GroupAdmission::RequestAccess
                || cursor.has_active_member(requester_agent_id)
                || cursor.is_banned(requester_agent_id)
                || cursor.join_requests.contains_key(request_id)
                || cursor.join_requests.values().any(|request| {
                    request.requester_agent_id == *requester_agent_id && request.is_pending()
                })
            {
                return None;
            }
            let request = x0x::groups::JoinRequest {
                request_id: request_id.clone(),
                group_id: group_id.clone(),
                requester_agent_id: requester_agent_id.clone(),
                requester_user_id: None,
                requested_role: x0x::groups::GroupRole::Member,
                message: message.clone(),
                treekem_key_package_b64: treekem_key_package_b64.clone(),
                created_at: *ts,
                reviewed_at: None,
                reviewed_by: None,
                status: x0x::groups::JoinRequestStatus::Pending,
                predecessor_envelope_digest: None,
                predecessor_first_seen_ms: None,
            };
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::NonMemberRequest,
                |next| {
                    super::super::set_join_request_created(
                        next,
                        request,
                        requester_kem_public_key_b64.clone(),
                    )
                },
            )
        }
        Event::JoinRequestApproved {
            request_id,
            revision,
            actor,
            requester_agent_id,
            treekem_commit_b64: None,
            treekem_welcome_b64: None,
            welcome_ref: None,
            treekem_key_package_hash: None,
            treekem_epoch: None,
            ..
        } => {
            if !admin(actor)
                || cursor.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
                || cursor.is_banned(requester_agent_id)
                || !cursor.join_requests.get(request_id).is_some_and(|request| {
                    request.is_pending() && request.requester_agent_id == *requester_agent_id
                })
            {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    super::super::set_join_request_approved(
                        next,
                        request_id,
                        actor,
                        requester_agent_id,
                        *revision,
                        commit.committed_at,
                    )
                },
            )
        }
        Event::JoinRequestRejected {
            request_id, actor, ..
        } => {
            if !admin(actor)
                || !cursor
                    .join_requests
                    .get(request_id)
                    .is_some_and(|request| request.is_pending())
            {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    super::super::set_join_request_rejected(
                        next,
                        request_id,
                        actor,
                        commit.committed_at,
                    )
                },
            )
        }
        Event::JoinRequestCancelled {
            request_id,
            requester_agent_id,
            ..
        } => {
            if *requester_agent_id != author
                || !cursor.join_requests.get(request_id).is_some_and(|request| {
                    request.is_pending() && request.requester_agent_id == *requester_agent_id
                })
            {
                return None;
            }
            super::super::apply_stateful_event_to_group(
                cursor,
                commit,
                x0x::groups::ActionKind::NonMemberRequest,
                |next| {
                    super::super::set_join_request_cancelled(next, request_id, requester_agent_id)
                },
            )
        }
        _ => return None,
    }
    .ok()?;
    (next.secret_epoch == cursor.secret_epoch).then_some(next)
}

/// The state after a held GSS removal or ban that rotates `cursor` to the
/// later epoch `to`, with no secret ([`next_held_state`]).
fn gss_rotation_step(
    cursor: &GroupInfo,
    commit: &x0x::groups::GroupStateCommit,
    revision: u64,
    to: u64,
    seat: impl FnOnce(&mut GroupInfo),
) -> Option<GroupInfo> {
    if cursor.secure_plane == x0x::mls::SecureGroupPlane::TreeKem || to <= cursor.secret_epoch {
        return None;
    }
    super::super::apply_stateful_event_to_group(
        cursor,
        commit,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.roster_revision =
                super::super::adopt_roster_revision(next.roster_revision, revision);
            seat(next);
            next.secret_epoch = to;
            next.security_binding = Some(orc::gss_binding(to));
            next.shared_secret = None;
        },
    )
    .ok()
}

/// #1508 rc12 (Codex P1): hold a verified commit of a GSS group that does
/// not chain on this node's head yet. It may chain on an owner recovery,
/// or a crypto-only exclusion (#1508 rc13), that has not installed here: a
/// lagging survivor gets the frame from any holder, on its own carrier,
/// and the later commits on theirs (direct delivery, the topic or a
/// catch-up page), in any order, so their ordinary apply refuses them.
/// [`receive_commit`] uses a held commit that the recovery's actor signed on the recovery result
/// as the evidence that the group moved on, and [`replay_held_events`]
/// applies the held commits after the install, each as its verified
/// signer (the catch-up rule for a relayed removal), so the ordinary apply
/// checks every signer's authority on the chain. Nothing is applied here.
/// Bounded by [`ORC_STASH_CAP`] and [`ORC_RETAIN_TTL`]. Returns whether
/// the event was held now (not held before).
pub(in crate::server) async fn hold_unchained_event(
    state: &AppState,
    event: &super::super::NamedGroupMetadataEvent,
) -> bool {
    let Some(commit) = super::super::named_group_metadata_event_commit(event) else {
        return false;
    };
    let group_id = super::super::named_group_metadata_event_group_id(event);
    let Some(info) = ({
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, group_id).map(|(_, info)| info.clone())
    }) else {
        return false;
    };
    if info.withdrawn
        || orc::crypto_kind(&info) != orc::RecoveryCryptoKind::Gss
        || commit.revision <= info.state_revision
        || commit.prev_state_hash.as_deref() == Some(info.state_hash.as_str())
    {
        return false;
    }
    let now = Instant::now();
    {
        let inner = state.revocation_evictions.inner.lock().await;
        // The whole event, not only its commit: a forged event around a
        // genuine commit must not crowd the genuine one out
        // ([`promoted_admin_secret`] checks each event's fields).
        if inner
            .orc
            .held_events
            .iter()
            .any(|held| held.event == *event)
        {
            return false;
        }
    }
    if commit.verify_structure().is_err() {
        return false;
    }
    let Ok(author) = super::super::parse_agent_id_hex(&commit.committed_by) else {
        return false;
    };
    let mut inner = state.revocation_evictions.inner.lock().await;
    let kept = &mut inner.orc.held_events;
    kept.retain(|held| now.saturating_duration_since(held.at) <= ORC_RETAIN_TTL);
    if kept.len() >= ORC_STASH_CAP {
        kept.remove(0);
    }
    kept.push(HeldEvent {
        stable_group_id: info.stable_group_id().to_string(),
        event: event.clone(),
        author,
        prev_state_hash: commit.prev_state_hash.clone(),
        at: now,
    });
    drop(inner);
    // A stashed frame can wait for this commit (#1508 rc13).
    state.agent.s4_revocation_intake().request_reconcile();
    true
}

/// Whether this node holds a verified commit that `actor` signed on the
/// frame result `result_state_hash` of `stable_group_id`
/// ([`hold_unchained_event`]).
pub(super) async fn holds_actor_successor(
    state: &AppState,
    stable_group_id: &str,
    actor: &[u8; 32],
    result_state_hash: &str,
) -> bool {
    let now = Instant::now();
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .held_events
        .iter()
        .any(|held| {
            held.stable_group_id == stable_group_id
                && now.saturating_duration_since(held.at) <= ORC_RETAIN_TTL
                && held.author.as_bytes() == actor
                && held.prev_state_hash.as_deref() == Some(result_state_hash)
        })
}

/// Apply the held catch-up commits of `stable_group_id` that chain on
/// this node's head, one after another, each as its verified signer.
/// Commits that do not chain stay held (bounded by [`ORC_STASH_CAP`] and
/// [`ORC_RETAIN_TTL`]); they are not applied, so they bump no refusal
/// counter. A chaining commit that the apply refuses is dropped, and the
/// next one is tried. Returns whether any commit applied.
async fn replay_held_events(state: &Arc<AppState>, stable_group_id: &str) -> bool {
    let mut any = false;
    while let Some(held) = take_chaining_held(state, stable_group_id).await {
        let applied = super::super::apply_named_group_metadata_event(
            state,
            held.event,
            held.author,
            true,
            None,
        )
        .await;
        any |= applied.accepted;
    }
    any
}

/// Remove and return the held commit of `stable_group_id` whose parent is
/// this node's head now.
async fn take_chaining_held(state: &AppState, stable_group_id: &str) -> Option<HeldEvent> {
    let head = {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, stable_group_id)
            .map(|(_, info)| info.state_hash.clone())?
    };
    let now = Instant::now();
    let mut inner = state.revocation_evictions.inner.lock().await;
    let held = &mut inner.orc.held_events;
    held.retain(|kept| now.saturating_duration_since(kept.at) <= ORC_RETAIN_TTL);
    let at = held.iter().position(|kept| {
        kept.stable_group_id == stable_group_id
            && kept.prev_state_hash.as_deref() == Some(head.as_str())
    })?;
    Some(held.remove(at))
}

/// Apply again, through the ordinary share apply, every early share of
/// `stable_group_id` once a GSS recovery or crypto-only exclusion installed
/// here. Call it with no group lock held. A share that the apply refuses
/// again is held again only if the park rule still holds.
async fn replay_early_shares(state: &Arc<AppState>, stable_group_id: &str) {
    let now = Instant::now();
    let due: Vec<ParkedShare> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        let (due, keep) = std::mem::take(&mut inner.orc.early_shares)
            .into_iter()
            .filter(|share| now.saturating_duration_since(share.at) <= ORC_RETAIN_TTL)
            .partition(|share| share.stable_group_id == stable_group_id);
        inner.orc.early_shares = keep;
        due
    };
    for share in due {
        let _ = super::super::apply_named_group_metadata_event(
            state,
            share.event,
            share.sender,
            true,
            None,
        )
        .await;
    }
}

/// After a GSS recovery or crypto-only exclusion installed here: apply the
/// held commits that chain on it, then the parked shares. Call it with no
/// group lock held: both re-enter the ordinary apply.
pub(super) async fn replay_after_gss_install(state: &Arc<AppState>, stable_group_id: &str) {
    replay_held_events(state, stable_group_id).await;
    replay_early_shares(state, stable_group_id).await;
}

/// #1508 rc13: after any accepted commit of `stable_group_id`, apply the
/// held commits that now chain on it and, if one applied (a later admin's
/// promotion), the parked shares of that group.
pub(in crate::server) async fn replay_after_commit(state: &Arc<AppState>, stable_group_id: &str) {
    if replay_held_events(state, stable_group_id).await {
        replay_early_shares(state, stable_group_id).await;
    }
}

/// The stash entry of a recovery commit.
fn stashed(
    sender: AgentId,
    bytes: Vec<u8>,
    body: &orc::OwnerRecoveryBodyV1,
    evidence: bool,
) -> StashedFrame {
    StashedFrame::new(
        sender,
        bytes,
        &body.stable_group_id,
        body.next_revision,
        evidence,
    )
}

/// Retry every stashed commit. #1508 rc18 (Codex P1): the frames stay in
/// the stash while the retry runs, so head evidence holds throughout, and
/// each retained frame's evidence state is checked again on the new head.
async fn retry_stash(state: &Arc<AppState>) {
    let frames = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .stash
        .retry_set(Instant::now());
    if frames.is_empty() {
        return;
    }
    let mut results = Vec::with_capacity(frames.len());
    for frame in frames {
        let kept = match orc::decode_frame(&frame.bytes) {
            Ok(orc::OwnerRecoveryFrameV1::Commit(commit)) => {
                match receive_commit(state, frame.sender, *commit, &frame.bytes).await {
                    ReceiveOutcome::Retained { verified } => Some(verified),
                    _ => None,
                }
            }
            _ => None,
        };
        results.push((frame, kept));
    }
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .stash
        .settle(results);
}

/// Verify and install one `OwnerRecoveryV1` commit (§4b(1) L4 rule).
async fn receive_commit(
    state: &Arc<AppState>,
    sender: AgentId,
    frame: orc::SignedOwnerRecoveryV1,
    payload: &[u8],
) -> ReceiveOutcome {
    use super::super as ng;
    if let Err(refusal) = orc::verify_commit_signatures(&frame) {
        return ReceiveOutcome::Refused(refusal);
    }
    let body = frame.body;
    let Some(group_key) = ng::resolve_named_group_storage_key(state, &body.stable_group_id).await
    else {
        return ReceiveOutcome::NotApplicable;
    };
    let membership_lock = ng::group_membership_lock(state, &group_key).await;
    let membership_guard = membership_lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return ReceiveOutcome::NotApplicable;
    };
    if info.state_hash == body.commit.state_hash {
        return ReceiveOutcome::Duplicate;
    }
    // The frame is self-authenticating; a relaying sender must still be
    // an Active member.
    if sender.as_bytes() != &body.actor && !info.has_active_member(&hex::encode(sender.as_bytes()))
    {
        return ReceiveOutcome::Refused(orc::OwnerRecoveryRefusal::RecoveryMemberIneligible);
    }
    if info.state_hash != body.prior_head && info.state_revision < body.prior_revision {
        // #1508 rc18 (Codex P1): a commit of a later revision is head
        // evidence only when its mandate and actor verify on this node's
        // latest head. A forged future commit is kept for a retry but
        // holds nothing.
        let revocations = verified_agent_revocations(state).await;
        let verified = revocations
            .get(sender.as_bytes())
            .is_none_or(BTreeSet::is_empty)
            && orc::check_ahead(&body, &info, &revocations, now_unix()).is_ok();
        return ReceiveOutcome::Retained { verified };
    }
    // Load the held log before the tree lock (#1508 review F2, below).
    ensure_restored(state).await;
    let kind = orc::crypto_kind(&info);
    let tree = if kind == orc::RecoveryCryptoKind::TreeKem {
        let map = state.treekem_groups.read().await;
        let tree = map
            .get(&group_key)
            .or_else(|| map.get(&info.mls_group_id))
            .or_else(|| map.get(info.stable_group_id()))
            .cloned();
        if tree.is_none() {
            return ReceiveOutcome::NotApplicable;
        }
        tree
    } else {
        None
    };
    let mut guard = match tree.as_ref() {
        Some(tree) => Some(tree.lock().await),
        None => None,
    };
    let current_epoch = guard
        .as_ref()
        .map_or(info.secret_epoch, |guard| guard.epoch());
    // §1's choke point: re-read the verified revocation records under the
    // membership lock, immediately before the apply.
    let revocations = verified_agent_revocations(state).await;
    if revocations
        .get(sender.as_bytes())
        .is_some_and(|set| !set.is_empty())
    {
        return ReceiveOutcome::Refused(orc::OwnerRecoveryRefusal::RecoveryMemberIneligible);
    }
    if let Err(refusal) =
        orc::validate_against_parent(&body, &info, current_epoch, &revocations, now_unix())
    {
        tracing::info!(
            group_id = %ng::LogHexId::group(&group_key),
            reason = refusal.as_str(),
            "ADR 0110 S4: owner recovery commit refused"
        );
        if refusal == orc::OwnerRecoveryRefusal::RecoveryHeadMismatch {
            // The tree lock is not needed for the fork-evidence install.
            drop(guard);
            contain_sibling(state, &group_key, &info, &body, &revocations).await;
        }
        return if refusal == orc::OwnerRecoveryRefusal::RecoveryNotNeeded {
            // The named revocation records may still be on their way.
            ReceiveOutcome::Retained {
                verified: orc::check_ahead(&body, &info, &revocations, now_unix()).is_ok(),
            }
        } else {
            ReceiveOutcome::Refused(refusal)
        };
    }
    let commit = body.commit.to_commit();
    // ADR 0109 §2 "Conflict" (#1533 r6): the one conflict gate bounds
    // this commit as it bounds every metadata route.
    if !ng::group_recovery::conflict_admits_commit(state, &info, &commit).await {
        tracing::warn!(
            group_id = %ng::LogHexId::group(&group_key),
            revision = commit.revision,
            "ADR 0109 S3: owner recovery past the attestation conflict's common prefix refused"
        );
        return ReceiveOutcome::Refused(orc::OwnerRecoveryRefusal::RecoveryGroupQuarantined);
    }
    // #1508 review F2: the received frame is durable before the roster it
    // carries is installed, in the held log that the author uses. A
    // restarted receiver then serves it to a survivor that missed it while
    // the author is offline. The load ran first (above), so this write
    // keeps the frames that a restart restored.
    let frame_bytes = Arc::new(payload.to_vec());
    let ext = replay_log::RECOVERY_EXTENSION;
    let stable = body.stable_group_id.clone();
    let at = (body.next_revision, body.commit.state_hash.as_str());
    if !replay_log::write_received(state, ext, held, &stable, at, &frame_bytes).await {
        return ReceiveOutcome::Retained { verified: true };
    }
    // #1508 rc12 (Codex P1): a GSS recovery installs only with its new
    // secret, as a GSS crypto-only exclusion does. The installed head is
    // the author's convergence evidence, so a head without its key would
    // end the delivery while this survivor cannot decrypt. Until the
    // share arrives the frame waits, durable and in the stash; the share
    // wakes the worker ([`park_early_share`]), and the author seals it
    // again after each frame write.
    let gss_secret = match &body.crypto {
        orc::OwnerRecoveryCryptoV1::Gss { next_secret_epoch }
            if info.secret_epoch < *next_secret_epoch || info.shared_secret.is_none() =>
        {
            // #1508 rc12 (Codex P1): the group may have moved on past this
            // recovery while this node was away, so no node seals this
            // epoch's secret any more (catch-up seals the current secret
            // only, and the holder that serves it may be an admin that the
            // author promoted later). The recovery is then an intermediate
            // head: it installs with no secret, the later commits chain on
            // it ([`replay_held_events`]), and their current secret installs
            // through the ordinary share rules ([`replay_early_shares`]).
            //
            // The evidence that the group moved on is rooted in the actor,
            // the only admin of the post-recovery roster (§4b(1): every
            // other admin seat is revoked and removed): a parked share of a
            // later epoch that the actor sealed to this node, or a held,
            // verified commit that the actor signed on this recovery's
            // result. Either one exists only after the actor's own head
            // left this result. The actor's live delivery of this recovery
            // exists only while its head is this result (the delivery
            // round drops it once the head moves; a restart restores it
            // only at the head). So a keyless head here never answers a
            // live delivery of this recovery, and the rule "an installed
            // recovery head implies its key" holds for every head answer
            // that can end that delivery. A share or a commit from any
            // other member, or from a removed or revoked seat, is no such
            // evidence; later admins get their authority from the actor's
            // verified chain, which the replay applies first.
            let actor = AgentId(body.actor);
            let may_seal_later = |sender: &AgentId| *sender == actor;
            match parked_key(state, &body, *next_secret_epoch, may_seal_later).await {
                ParkedKey::Exact(secret) => {
                    if let Err(error) = ng::ensure_named_group_key_material_install_allowed(
                        state,
                        &group_key,
                        Some(&body.stable_group_id),
                        "owner_recovery_gss_share",
                    )
                    .await
                    {
                        tracing::warn!(group_id = %ng::LogHexId::group(&group_key), "ADR 0110 S4: owner recovery secret refused: {error}");
                        return ReceiveOutcome::Retained { verified: true };
                    }
                    Some(secret)
                }
                ParkedKey::Later => {
                    tracing::info!(
                        group_id = %ng::LogHexId::group(&group_key),
                        secret_epoch = next_secret_epoch,
                        "ADR 0110 S4: GSS owner recovery installs as an intermediate head; a later share holds the current secret"
                    );
                    None
                }
                ParkedKey::Missing
                    if holds_actor_successor(
                        state,
                        &body.stable_group_id,
                        &body.actor,
                        &body.commit.state_hash,
                    )
                    .await =>
                {
                    tracing::info!(
                        group_id = %ng::LogHexId::group(&group_key),
                        secret_epoch = next_secret_epoch,
                        "ADR 0110 S4: GSS owner recovery installs as an intermediate head; the actor's later commit is held"
                    );
                    None
                }
                ParkedKey::Missing => {
                    tracing::info!(
                        group_id = %ng::LogHexId::group(&group_key),
                        secret_epoch = next_secret_epoch,
                        "ADR 0110 S4: GSS owner recovery waits for its sealed share"
                    );
                    return ReceiveOutcome::Retained { verified: true };
                }
            }
        }
        _ => None,
    };
    let signed_binding = commit.security_binding.clone();
    let roster_revision = body.roster_revision;
    let crypto = body.crypto.clone();
    // The named exception (§4): the signer is the promoted member, not an
    // admin on the parent roster. The ordinary chained apply runs with the
    // member-signer check; the §4b(1) rule above is the authority, and the
    // recomputed post-state hash proves the roster change is the only one.
    let next = match ng::apply_stateful_event_with_evidence(
        state,
        &group_key,
        &info,
        &commit,
        None,
        false,
        None,
        x0x::groups::ActionKind::MemberSelf,
        |next| {
            next.roster_revision = ng::adopt_roster_revision(next.roster_revision, roster_revision);
            orc::apply_roster_change(next, &body);
            match &crypto {
                orc::OwnerRecoveryCryptoV1::TreeKem { next_epoch, .. } => {
                    next.secret_epoch = *next_epoch;
                    next.security_binding = signed_binding;
                }
                orc::OwnerRecoveryCryptoV1::Gss { next_secret_epoch } => {
                    // The secret and its epoch install with the head. An
                    // intermediate head holds no secret of its epoch.
                    if let Some(secret) = &gss_secret {
                        next.shared_secret = Some(secret.to_vec());
                    } else if next.secret_epoch < *next_secret_epoch {
                        next.shared_secret = None;
                    }
                    next.secret_epoch = *next_secret_epoch;
                    next.security_binding = Some(orc::gss_binding(*next_secret_epoch));
                }
                orc::OwnerRecoveryCryptoV1::SignedPublic => {}
            }
        },
    )
    .await
    {
        Ok(next) => next,
        Err(error) => {
            replay_log::rewrite_without(state, ext, held, &stable, at).await;
            tracing::info!(group_id = %ng::LogHexId::group(&group_key), "ADR 0110 S4: owner recovery commit refused by the chained apply: {error}");
            return ReceiveOutcome::Refused(orc::OwnerRecoveryRefusal::RecoveryProofInvalid);
        }
    };
    let removed: Vec<AgentId> = body
        .removed
        .iter()
        .map(|seat| AgentId(seat.agent))
        .collect();
    // #1574 item 1: the two non-durable arms below treat the install as
    // done, and that evidence is enough for the drops after them. The
    // frame was made durable before the install (`write_received`
    // above), and a restart puts a received frame above the loaded head
    // back through the stash, so a power-loss revert re-runs this
    // install and these drops on the durable frame. The epoch-installed
    // arm is committed by the journal it leaves (the commit point a
    // restart replays). The in-memory `pending`/`mandates` drop retires
    // no file here, so a restart also re-arms the held sides from the
    // pending-mandate file while the reverted head is the mandate's
    // parent; the owner's re-send covers the same recovery.
    let installed = match (guard.as_mut(), &body.crypto) {
        (
            Some(guard),
            orc::OwnerRecoveryCryptoV1::TreeKem {
                commits,
                next_epoch,
            },
        ) => {
            let Ok(rollback_snapshot) = guard.to_snapshot_bytes() else {
                return ReceiveOutcome::Retained { verified: true };
            };
            let processed = commits
                .iter()
                .all(|treekem_commit| guard.process_commit(treekem_commit).is_ok());
            // The cryptographic removal proof: the tree holds no revoked
            // seat's committed leaf. The local leaf map alone is not proof;
            // a seat with no evidence keeps the frame pending (#1508
            // review P1).
            let presence = ng::roster_treekem_leaf_presence(guard, &info);
            let leaves: Vec<Option<bool>> = removed
                .iter()
                .map(|agent| {
                    presence
                        .get(&hex::encode(agent.as_bytes()))
                        .copied()
                        .flatten()
                })
                .collect();
            // An undecided seat keeps the frame pending even when another
            // seat's leaf is still present: the proof is retried whole.
            let installed = processed && guard.epoch() == *next_epoch;
            if installed && leaves.contains(&None) {
                ng::rollback_treekem_group_after_failed_install(
                    state,
                    &group_key,
                    &next,
                    &rollback_snapshot,
                    guard,
                    "owner_recovery_leaf_unproven",
                );
                // Ask for each undecided seat's KeyPackage before the
                // retry (#1508 review P1).
                for (agent, _) in removed
                    .iter()
                    .zip(&leaves)
                    .filter(|(_, leaf)| leaf.is_none())
                {
                    ng::request_missing_leaf_evidence(
                        state,
                        &group_key,
                        &hex::encode(agent.as_bytes()),
                    );
                }
                return ReceiveOutcome::Retained { verified: true };
            }
            if !installed || leaves.contains(&Some(true)) {
                ng::rollback_treekem_group_after_failed_install(
                    state,
                    &group_key,
                    &next,
                    &rollback_snapshot,
                    guard,
                    "owner_recovery_proof_failed",
                );
                replay_log::rewrite_without(state, ext, held, &stable, at).await;
                return ReceiveOutcome::Refused(orc::OwnerRecoveryRefusal::RecoveryProofInvalid);
            }
            match ng::persist_treekem_and_named_groups_atomic_with_info(
                state,
                &group_key,
                next.clone(),
                guard,
            )
            .await
            {
                Ok(()) => true,
                Err(error) if ng::self_leave_persist_left_epoch_installed(&error) => true,
                Err(error) => {
                    ng::rollback_treekem_group_after_failed_install(
                        state,
                        &group_key,
                        &next,
                        &rollback_snapshot,
                        guard,
                        "owner_recovery_persist_failed",
                    );
                    tracing::warn!(group_id = %ng::LogHexId::group(&group_key), "ADR 0110 S4: owner recovery not installed: {error}");
                    false
                }
            }
        }
        (None, orc::OwnerRecoveryCryptoV1::TreeKem { .. }) => false,
        // #1508 r6: `ReplacedNotDurable` installed the roster. The
        // preflight refusal stages nothing and reports `NotReplaced`
        // (#1574 item 1, slice 3), so a refused install never reaches
        // the drops below.
        _ => matches!(
            ng::persist_named_group_info(state, &group_key, next.clone()).await,
            Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
        ),
    };
    drop(guard);
    if !installed {
        // A local storage fault, not a sender defect: keep the frame, in
        // the stash and durable in the held log.
        return ReceiveOutcome::Retained { verified: true };
    }
    if kind == orc::RecoveryCryptoKind::Gss {
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&group_key) {
            for agent in &removed {
                if group.is_member(agent) {
                    let _ = group.remove_member(*agent).await;
                }
            }
        }
    }
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    for agent in &removed {
        let agent_hex = hex::encode(agent.as_bytes());
        ng::purge_join_artifacts_if_ineligible(state, &group_key, &agent_hex).await;
        // The cached `MemberJoined` stays: later survivors ask this node
        // for it (#1508 review P1).
    }
    drop(membership_guard);
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.orc.pending.remove(&body.stable_group_id);
        inner.orc.mandates.remove(&body.stable_group_id);
        // Any installed replica serves the frame to a survivor that
        // missed it (catch-up, §4).
        inner.orc.log.remember(
            &body.stable_group_id,
            body.next_revision,
            &body.commit.state_hash,
            frame_bytes,
            false,
        );
    }
    tracing::info!(
        group_id = %ng::LogHexId::group(&group_key),
        bytes = payload.len(),
        "ADR 0110 S4: owner recovery installed"
    );
    match kind {
        orc::RecoveryCryptoKind::TreeKem => {
            ng::replay_pending_treekem_events(state, &group_key).await;
        }
        orc::RecoveryCryptoKind::Gss => {
            replay_after_gss_install(state, &body.stable_group_id).await;
        }
        orc::RecoveryCryptoKind::SignedPublic => {}
    }
    state.agent.s4_revocation_intake().request_reconcile();
    ReceiveOutcome::Applied
}

/// ADR 0110 §2 (#1508 r5): a valid recovery commit on a sibling branch of
/// this node's chain (for example, a second owner mandate on the same
/// parent, for another member) is fork evidence. Keep it with the
/// existing fork-quarantine marker, as for any authenticated conflict:
/// the group is contained (no seal, delivery or key serving), no node
/// applies both siblings, and ADR 0064's owner-anchored recovery resolves
/// it. S4 adds no fork choice. The sibling frame is not kept for serving.
/// A commit that is no authenticated sibling records nothing.
async fn contain_sibling(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    body: &orc::OwnerRecoveryBodyV1,
    revocations: &orc::VerifiedAgentRevocations,
) {
    use super::super as ng;
    // #1508 r7 (Codex P1 1): the §4b(1) checks run against the retained
    // parent first; an invalid alternative child stops nothing.
    if let Err(refusal) = orc::validate_sibling(body, info, revocations, now_unix()) {
        tracing::debug!(
            group_id = %ng::LogHexId::group(group_key),
            reason = refusal.as_str(),
            "ADR 0110 S4: a mismatched owner recovery is no authenticated sibling"
        );
        return;
    }
    let commit = body.commit.to_commit();
    let evidence = x0x::groups::ForkEvidence {
        revision: commit.revision,
        state_hash: commit.state_hash.clone(),
        committed_by: commit.committed_by.clone(),
        observed_at_ms: ng::now_millis_u64(),
    };
    let quarantine = ng::fork_quarantine_for_evidence(
        info,
        &evidence,
        &commit,
        Some(ng::FORK_EVIDENCE_CLASSIFICATION_OWNER_ANCHORED),
    );
    if ng::install_fork_evidence(state, group_key, evidence, quarantine, false, None).await {
        // The own branch's recovery work stops now, not at its next round.
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.orc.deliveries.remove(&body.stable_group_id);
        inner.orc.pending.remove(&body.stable_group_id);
        drop(inner);
        tracing::warn!(
            group_id = %ng::LogHexId::group(group_key),
            revision = commit.revision,
            state_hash = %commit.state_hash,
            committed_by = %ng::LogHexId::agent(&commit.committed_by),
            "ADR 0110 S4: sibling owner recovery kept as fork evidence; the group is contained"
        );
    }
}

// ─── Status ────────────────────────────────────────────────────────────────

/// The owner-recovery progress of one group for its `admin_availability`
/// status: the owner node's `waiting_for_recovery_member`, the promoted
/// member's held mandate (with a D76 `waiting_for_receiver_upgrade`), and
/// stranded members of a committed recovery. `null` when none applies.
pub(super) async fn status_json(state: &AppState, stable_group_id: &str) -> serde_json::Value {
    let inner = state.revocation_evictions.inner.lock().await;
    let owner = inner.orc.mandates.get(stable_group_id).map(|delivery| {
        let status = delivery.recipients.get(&delivery.promoted).copied();
        let (cause, advert) = match status.unwrap_or(RecipientDelivery::Due) {
            RecipientDelivery::Lacking => (
                x0x::groups::eviction::WaitingCause::WaitingForReceiverUpgrade.as_str(),
                "lacking",
            ),
            RecipientDelivery::Unknown => (WAITING_FOR_RECOVERY_MEMBER, "unknown"),
            _ => (WAITING_FOR_RECOVERY_MEMBER, "supported"),
        };
        serde_json::json!({
            "state": cause,
            "promoted_member": hex::encode(delivery.promoted),
            "mandate_id": delivery.mandate_id,
            "parent_head": delivery.parent_head,
            "advert": advert,
        })
    });
    let promoted = inner.orc.pending.get(stable_group_id).map(|pending| {
        let (cause, named) = pending
            .wait
            .as_ref()
            .map_or(("mandate_received", Vec::new()), |(cause, named)| {
                (*cause, named.iter().map(hex::encode).collect::<Vec<_>>())
            });
        serde_json::json!({
            "state": cause,
            "named": named,
            "parent_head": pending.mandate.body.parent_head,
        })
    });
    let stranded: Vec<serde_json::Value> = inner
        .orc
        .deliveries
        .get(stable_group_id)
        .map(|delivery| {
            delivery
                .recipients
                .iter()
                .filter(|(_, status)| {
                    matches!(status, RecipientDelivery::Lacking | RecipientDelivery::Unknown)
                })
                .map(|(id, status)| {
                    serde_json::json!({
                        "cause": x0x::groups::eviction::WaitingCause::WaitingForReceiverUpgrade.as_str(),
                        "agent_id": hex::encode(id),
                        "gap_revision": delivery.next_revision,
                        "advert": if *status == RecipientDelivery::Lacking { "lacking" } else { "unknown" },
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if owner.is_none() && promoted.is_none() && stranded.is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "owner": owner,
        "promoted_member": promoted,
        "receiver_upgrade_members": stranded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_map_to_http_statuses() {
        assert_eq!(
            refusal_status(orc::OwnerRecoveryRefusal::RecoverySignerNotOwner),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            refusal_status(orc::OwnerRecoveryRefusal::RecoveryNotNeeded),
            StatusCode::CONFLICT
        );
        let (status, Json(body)) =
            refusal_response(orc::OwnerRecoveryRefusal::RecoveryHeadMismatch, "g");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "recovery_head_mismatch");
        assert_eq!(body["group_id"], "g");
    }

    /// #1533 rc18: candidate shares (senders not on this roster) are
    /// bounded per group and per sender, evicted before a member's share,
    /// and a full bound admits a new candidate only when a held commit
    /// adds its sender. A flood of candidates never evicts a member share.
    #[test]
    fn candidate_shares_are_bounded_and_go_first() {
        let event =
            |group: &str| super::super::super::NamedGroupMetadataEvent::SecureShareDelivered {
                group_id: group.to_string(),
                recipient: String::new(),
                secret_epoch: 1,
                kem_ciphertext_b64: String::new(),
                aead_nonce_b64: String::new(),
                aead_ciphertext_b64: String::new(),
                actor: String::new(),
            };
        let share = |group: &str, sender: u8, candidate: bool| ParkedShare {
            stable_group_id: group.to_string(),
            event: event(group),
            sender: AgentId([sender; 32]),
            at: Instant::now(),
            candidate,
        };
        let mut parked = Vec::new();
        assert!(park_share(&mut parked, &[], share("g", 1, false)));
        for sender in 10..10 + ORC_CANDIDATE_SHARES_PER_GROUP as u8 {
            assert!(park_share(&mut parked, &[], share("g", sender, true)));
        }
        // The same sender replaces its candidate.
        assert!(park_share(&mut parked, &[], share("g", 10, true)));
        assert_eq!(parked.len(), 1 + ORC_CANDIDATE_SHARES_PER_GROUP);
        // The bound is full: an unnamed candidate is dropped.
        assert!(!park_share(&mut parked, &[], share("g", 99, true)));
        // A candidate that a held commit adds replaces an unnamed one.
        let named = AgentId([98; 32]);
        let add = HeldEvent {
            stable_group_id: "g".to_string(),
            event: super::super::super::NamedGroupMetadataEvent::MemberAdded {
                roster_certificates_b64: Vec::new(),
                group_id: "g".to_string(),
                revision: 2,
                actor: String::new(),
                agent_id: hex::encode(named.as_bytes()),
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
            },
            author: AgentId([0; 32]),
            prev_state_hash: None,
            at: Instant::now(),
        };
        assert!(park_share(&mut parked, &[add], share("g", 98, true)));
        assert!(parked.iter().any(|kept| kept.sender == named));
        assert_eq!(parked.len(), 1 + ORC_CANDIDATE_SHARES_PER_GROUP);
        // Candidates of many groups fill the global cap: they go first,
        // and the member share stays.
        for group in 0..ORC_STASH_CAP {
            let _ = park_share(&mut parked, &[], share(&format!("h{group}"), 50, true));
        }
        assert!(parked.len() <= ORC_STASH_CAP);
        assert!(parked
            .iter()
            .any(|kept| !kept.candidate && kept.sender == AgentId([1; 32])));
    }

    /// #1508 review (Codex P1 #3): the promoted member writes the recovery
    /// frame before its local commit and dies before any delivery. The
    /// restart serves the exact bytes at catch-up and resumes the delivery.
    #[tokio::test]
    async fn a_crash_after_the_recovery_commit_keeps_the_exact_frame() {
        let (local, survivor) = (AgentId([1; 32]), [2u8; 32]);
        let (stable, groups) = replay_log::tests::committed_group(local, survivor);
        let frame = Arc::new(b"X0XORC1\0exact frame bytes".to_vec());
        let resumes = replay_log::tests::crash_and_restart::<ORC_LOG_PER_GROUP>(
            replay_log::RECOVERY_EXTENSION,
            &stable,
            &groups,
            &frame,
        )
        .await;
        assert_eq!(resumes.len(), 1, "the restart resumes the delivery");
        assert_eq!(resumes[0].bytes.as_slice(), frame.as_slice());
        let none = BTreeSet::new();
        assert_eq!(
            survivors(&resumes[0].info, local.as_bytes(), &none),
            [survivor]
        );
    }

    #[test]
    fn survivors_skip_the_local_node_and_the_removed_admins() {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            AgentId([1; 32]),
            "ab".repeat(16),
        );
        info.members_v2.clear();
        for id in [[1u8; 32], [2u8; 32], [3u8; 32]] {
            let hex_id = hex::encode(id);
            info.members_v2.insert(
                hex_id.clone(),
                x0x::groups::GroupMember::new_member(hex_id, None, None, 1),
            );
        }
        let removed = BTreeSet::from([[2u8; 32]]);
        assert_eq!(survivors(&info, &[1; 32], &removed), vec![[3u8; 32]]);
    }

    fn commit_delivery(result_head: &str, recipient: [u8; 32]) -> CommitDelivery {
        CommitDelivery {
            bytes: Arc::new(vec![1, 2, 3]),
            result_head: result_head.to_string(),
            next_revision: 2,
            recipients: BTreeMap::from([(recipient, RecipientDelivery::Due)]),
            next_at: Instant::now(),
            resumed: false,
            removed: BTreeSet::new(),
            reshare_epoch: None,
            share_went_to: BTreeMap::new(),
        }
    }

    /// ADR 0110 §3 (#1508 review r8 P1): a successful write is `Sent`,
    /// not delivered. A survivor that took the commit but did not install
    /// it keeps the delivery: the next round sends it again. Only the
    /// survivor's head report that holds the result head ends it.
    #[test]
    fn a_written_recovery_commit_without_install_keeps_retrying() {
        let survivor = [7; 32];
        let mut orc = OrcState::default();
        orc.deliveries
            .insert("g".into(), commit_delivery("head-1", survivor));
        let round = |orc: &mut OrcState, observed| {
            orc.install_commit_round(
                "g",
                "head-1",
                vec![RoundUpdate {
                    recipient: survivor,
                    observed,
                    next: Some(RecipientDelivery::InFlight(next_attempt())),
                }],
            )
        };
        let &[(_, attempt)] = round(&mut orc, RecipientDelivery::Due).as_slice() else {
            panic!("one send starts");
        };
        assert!(orc.finish_commit_attempt(
            "g",
            "head-1",
            &survivor,
            attempt,
            RecipientDelivery::Sent
        ));
        // The receiver crashed before it persisted the commit: no install.
        // A round that starts nothing keeps the delivery.
        assert!(orc
            .install_commit_round("g", "head-1", Vec::new())
            .is_empty());
        assert!(
            orc.deliveries.contains_key("g"),
            "a write without an install ended the delivery"
        );
        let resend = round(&mut orc, RecipientDelivery::Sent);
        assert_eq!(
            resend.len(),
            1,
            "a write without an install is retried, not complete"
        );
        assert!(orc.deliveries.contains_key("g"));
        // The survivor's verified head report names a later head on the
        // chain through the result: it converged, and the delivery ends.
        let installed = BTreeSet::from(["head-1".to_string(), "head-2".to_string()]);
        let &[(_, resent)] = resend.as_slice() else {
            panic!("one resend starts");
        };
        assert!(orc.finish_commit_attempt(
            "g",
            "head-1",
            &survivor,
            resent,
            RecipientDelivery::Sent
        ));
        note_survivor_head(
            &mut orc,
            "g",
            &survivor,
            &installed,
            Some(SenderSeat { key: None }),
            Some(1),
        );
        orc.install_commit_round("g", "head-1", Vec::new());
        assert!(!orc.deliveries.contains_key("g"));
    }

    /// #1660 (ADR 0110 §3; Engineer ruling, 29 Oct 17:12 GMT): a head
    /// report closes a seat only through a live, D60-clean seat and — for
    /// a GSS recovery, whose rounds seal the rotated secret — only when a
    /// sealed share went to the key the seat carries now and a head ask
    /// went to the seat after that seal. A keyed seat whose share was not
    /// sealed yet, or whose answer could only answer a pre-seal ask,
    /// closes nothing.
    #[test]
    fn a_report_closes_a_recovery_seat_only_after_its_share_went_to_its_key() {
        let survivor = [7u8; 32];
        let installed: BTreeSet<String> = ["head-1".to_string()].into_iter().collect();
        let mut orc = OrcState::default();
        let mut delivery = commit_delivery("head-1", survivor);
        delivery.reshare_epoch = Some(4);
        delivery
            .recipients
            .insert(survivor, RecipientDelivery::Sent);
        orc.deliveries.insert("g".into(), delivery);
        let seat = |orc: &OrcState| orc.deliveries["g"].recipients[&survivor];
        let keyed = || {
            Some(SenderSeat {
                key: Some("key-now".to_string()),
            })
        };
        // A member removed mid-send has no live seat: the report closes
        // nothing.
        note_survivor_head(&mut orc, "g", &survivor, &installed, None, Some(1));
        assert_eq!(seat(&orc), RecipientDelivery::Sent);
        // A live but keyless seat cannot have taken its sealed share.
        note_survivor_head(
            &mut orc,
            "g",
            &survivor,
            &installed,
            Some(SenderSeat { key: None }),
            Some(1),
        );
        assert_eq!(seat(&orc), RecipientDelivery::Sent);
        // A keyed seat whose share was not sealed to that key yet — the
        // key arrived and the report landed before the next round —
        // closes nothing: no share went to the seat's current key.
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(1));
        assert_eq!(seat(&orc), RecipientDelivery::Sent);
        // A share of another epoch is not this row's secret: the record
        // keeps only the row's reshare epoch.
        note_share_went_to(&mut orc, "g", 3, &survivor, "key-now", 0);
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(1));
        assert_eq!(
            seat(&orc),
            RecipientDelivery::Sent,
            "a share of another epoch records nothing for this row"
        );
        // A share sealed to a key the seat no longer carries (the rotated
        // stale key) proves nothing about the key it carries now.
        note_share_went_to(&mut orc, "g", 4, &survivor, "key-rotated", 0);
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(1));
        assert_eq!(
            seat(&orc),
            RecipientDelivery::Sent,
            "a share that went to a stale key closes nothing"
        );
        // A seal to a DIFFERENT key resets the record to that seal (a
        // rotation): the bar is the new seal's count, and this round's
        // count (1) has not passed it.
        note_share_went_to(&mut orc, "g", 4, &survivor, "key-now", 3);
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(1));
        assert_eq!(
            seat(&orc),
            RecipientDelivery::Sent,
            "a seal to a different key resets the count to that seal"
        );
        // The rounds of a live row seal again every pass. A later seal to
        // the SAME key keeps the EARLIEST count — the bar stays the first
        // seal's (3), not the later seal's (5): an answer at the earliest
        // bar itself (3) closes nothing, and one past the earliest but
        // below the later seal (4) closes the seat. A replacing record
        // would keep the bar at 5 and refuse the 4.
        note_share_went_to(&mut orc, "g", 4, &survivor, "key-now", 5);
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(3));
        assert_eq!(
            seat(&orc),
            RecipientDelivery::Sent,
            "an answer at the earliest seal's own count closes nothing"
        );
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(4));
        assert_eq!(
            seat(&orc),
            RecipientDelivery::Converged,
            "an answer past the EARLIEST seal closes the seat: the later same-key seal raised no bar"
        );
        // Back to the base record and an open seat: a rotation away and
        // a seal at count 0.
        orc.deliveries
            .get_mut("g")
            .expect("the delivery row")
            .recipients
            .insert(survivor, RecipientDelivery::Sent);
        note_share_went_to(&mut orc, "g", 4, &survivor, "key-rotated", 0);
        note_share_went_to(&mut orc, "g", 4, &survivor, "key-now", 0);
        // The share went to the seat's current key — the round's record —
        // and the report converges it only after a head ask went out past
        // the seal. An answer with no ask since the seal (the ruling's
        // pre-seal answer, arrived late) closes nothing; the ask count at
        // the seal was 0.
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), None);
        assert_eq!(
            seat(&orc),
            RecipientDelivery::Sent,
            "an answer with no head ask on record closes nothing"
        );
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(0));
        assert_eq!(
            seat(&orc),
            RecipientDelivery::Sent,
            "an answer to a pre-seal ask closes nothing (Engineer ruling, 29 Oct 17:12 GMT)"
        );
        note_survivor_head(&mut orc, "g", &survivor, &installed, keyed(), Some(1));
        assert_eq!(seat(&orc), RecipientDelivery::Converged);
    }

    /// #1660 (ADR 0110 §3): a non-GSS recovery row — `reshare_epoch` is
    /// `None` — seals no shares in its rounds, so `went_to` gates nothing.
    /// A report from a live, D60-clean seat converges it with no key, and
    /// with a key no share ever went to.
    #[test]
    fn a_report_closes_a_non_gss_recovery_seat_without_a_share() {
        let survivor = [7u8; 32];
        let installed: BTreeSet<String> = ["head-1".to_string()].into_iter().collect();
        let seat = |orc: &OrcState| orc.deliveries["g"].recipients[&survivor];
        for sender_seat in [
            SenderSeat { key: None },
            SenderSeat {
                key: Some("key-never-sealed".to_string()),
            },
        ] {
            let mut orc = OrcState::default();
            let mut delivery = commit_delivery("head-1", survivor);
            // `commit_delivery` leaves `reshare_epoch` None: the row seals
            // no shares.
            delivery
                .recipients
                .insert(survivor, RecipientDelivery::Sent);
            orc.deliveries.insert("g".into(), delivery);
            note_survivor_head(
                &mut orc,
                "g",
                &survivor,
                &installed,
                Some(sender_seat),
                Some(0),
            );
            assert_eq!(
                seat(&orc),
                RecipientDelivery::Converged,
                "went_to gates nothing when the row seals no shares"
            );
        }
    }

    fn mandate_delivery(mandate_id: &str, promoted: [u8; 32]) -> MandateDelivery {
        MandateDelivery {
            mandate: orc::SignedOwnerRecoveryMandateV1 {
                body: orc::OwnerRecoveryMandateBodyV1 {
                    stable_group_id: "g".to_string(),
                    parent_head: "parent".to_string(),
                    parent_revision: 1,
                    revoked_admins: Vec::new(),
                    promoted,
                    promoted_certificate_digest: String::new(),
                    owner_public_key: Vec::new(),
                    issued_at_ms: 0,
                },
                signature: Vec::new(),
            },
            bytes: Arc::new(vec![4, 5, 6]),
            mandate_id: mandate_id.to_string(),
            promoted,
            parent_head: "parent".to_string(),
            recipients: BTreeMap::from([(promoted, RecipientDelivery::Due)]),
            next_at: Instant::now(),
        }
    }

    /// #1357 (Codex P2 class): a commit send's `InFlight` status is
    /// installed before the send starts, and a completion writes only over
    /// its own attempt. A late round planned from an old snapshot, a stale
    /// attempt and an attempt for a replaced commit change nothing.
    #[test]
    fn commit_completion_writes_only_its_own_attempt() {
        let survivor = [7; 32];
        let mut orc = OrcState::default();
        orc.deliveries
            .insert("g".into(), commit_delivery("head-1", survivor));
        let attempt = next_attempt();
        let started = orc.install_commit_round(
            "g",
            "head-1",
            vec![RoundUpdate {
                recipient: survivor,
                observed: RecipientDelivery::Due,
                next: Some(RecipientDelivery::InFlight(attempt)),
            }],
        );
        assert_eq!(started, vec![(survivor, attempt)]);
        // A stale attempt's completion is ignored.
        assert!(!orc.finish_commit_attempt(
            "g",
            "head-1",
            &survivor,
            attempt.wrapping_add(1_000_000),
            RecipientDelivery::Due
        ));
        // The send completes at once.
        assert!(orc.finish_commit_attempt(
            "g",
            "head-1",
            &survivor,
            attempt,
            RecipientDelivery::Sent
        ));
        // A late round write planned from the old `Due` snapshot changes
        // nothing.
        let late = orc.install_commit_round(
            "g",
            "head-1",
            vec![RoundUpdate {
                recipient: survivor,
                observed: RecipientDelivery::Due,
                next: Some(RecipientDelivery::InFlight(next_attempt())),
            }],
        );
        assert!(late.is_empty());
        // A duplicate completion of the same attempt writes nothing.
        assert!(!orc.finish_commit_attempt(
            "g",
            "head-1",
            &survivor,
            attempt,
            RecipientDelivery::Due
        ));
        // Reset: the replaced-commit case below starts from a fresh delivery.
        orc.deliveries.remove("g");

        // An attempt for a replaced commit (another result head) is ignored.
        orc.deliveries
            .insert("g".into(), commit_delivery("head-1", survivor));
        let old = next_attempt();
        assert_eq!(
            orc.install_commit_round(
                "g",
                "head-1",
                vec![RoundUpdate {
                    recipient: survivor,
                    observed: RecipientDelivery::Due,
                    next: Some(RecipientDelivery::InFlight(old)),
                }],
            ),
            vec![(survivor, old)]
        );
        let mut replaced = commit_delivery("head-2", survivor);
        replaced
            .recipients
            .insert(survivor, RecipientDelivery::InFlight(old));
        orc.deliveries.insert("g".into(), replaced);
        assert!(!orc.finish_commit_attempt("g", "head-1", &survivor, old, RecipientDelivery::Sent));
        assert_eq!(
            orc.deliveries["g"].recipients.get(&survivor),
            Some(&RecipientDelivery::InFlight(old))
        );
    }

    /// #1357 (Codex P2 class), mandate side: the same per-attempt rule, and
    /// a completion for a mandate that a newer one replaced is ignored.
    #[test]
    fn mandate_completion_writes_only_its_own_attempt() {
        let promoted = [9; 32];
        let mut orc = OrcState::default();
        orc.mandates
            .insert("g".into(), mandate_delivery("m1", promoted));
        let attempt = next_attempt();
        let update = RoundUpdate {
            recipient: promoted,
            observed: RecipientDelivery::Due,
            next: Some(RecipientDelivery::InFlight(attempt)),
        };
        // A plan for another mandate installs nothing.
        assert!(orc.install_mandate_round("g", "m0", update).is_empty());
        assert_eq!(
            orc.install_mandate_round("g", "m1", update),
            vec![(promoted, attempt)]
        );
        assert!(orc.finish_mandate_attempt("g", "m1", &promoted, attempt, RecipientDelivery::Sent));
        // A late round planned from `Due` does not overwrite `Sent`.
        assert!(orc.install_mandate_round("g", "m1", update).is_empty());
        assert_eq!(
            orc.mandates["g"].recipients.get(&promoted),
            Some(&RecipientDelivery::Sent)
        );

        // The owner signs a new mandate while an attempt for the old one
        // runs: the old completion must not touch the new delivery.
        let old = next_attempt();
        let mut running = mandate_delivery("m1", promoted);
        running
            .recipients
            .insert(promoted, RecipientDelivery::InFlight(old));
        orc.mandates.insert("g".into(), running);
        orc.mandates
            .insert("g".into(), mandate_delivery("m2", promoted));
        assert!(!orc.finish_mandate_attempt("g", "m1", &promoted, old, RecipientDelivery::Lacking));
        assert_eq!(
            orc.mandates["g"].recipients.get(&promoted),
            Some(&RecipientDelivery::Due)
        );
    }

    /// #1357: recovery commit frames are held for catch-up serving, oldest
    /// first, above the requested revision, deduplicated and bounded.
    /// #1579: a frame at a held revision with a different result head is a
    /// competing commit: it is kept beside the held one, as fork evidence,
    /// and it never replaces it.
    #[test]
    fn catchup_frames_are_bounded_ordered_and_above_the_revision() {
        let mut orc = OrcState::default();
        let total = ORC_LOG_PER_GROUP as u64 + 2;
        for revision in (1..=total).rev() {
            orc.log.remember(
                "g",
                revision,
                &format!("h{revision}"),
                Arc::new(vec![revision as u8]),
                false,
            );
        }
        orc.log
            .remember("g", total, "dup", Arc::new(vec![0]), false);
        let all = orc.log.catchup_frames(&["x".into(), "g".into()], 0);
        assert_eq!(all.len(), ORC_LOG_PER_GROUP);
        let heads: Vec<&str> = all.iter().map(|(_, head, _)| head.as_str()).collect();
        let mut expected: Vec<String> =
            (4..=total).map(|revision| format!("h{revision}")).collect();
        expected.push("dup".to_string());
        assert_eq!(heads, expected);
        assert!(all.iter().all(|(id, _, _)| id == "g"));
        let tail = orc.log.catchup_frames(&["g".into()], total - 1);
        assert_eq!(tail.len(), 2, "the competing frame is held too");
        assert_eq!(tail[0].1, format!("h{total}"));
        assert_eq!(tail[1].1, "dup");
        assert!(orc.log.catchup_frames(&["other".into()], 0).is_empty());
    }

    /// #1357 / ADR 0110 §2: a held mandate keeps its group in the head
    /// catch-up rounds, and its named (revoked) admins are not holders.
    #[test]
    fn held_mandates_keep_a_head_round_without_their_named_admins() {
        let mut orc = OrcState::default();
        let mandate = orc::SignedOwnerRecoveryMandateV1 {
            body: orc::OwnerRecoveryMandateBodyV1 {
                stable_group_id: "g".into(),
                parent_head: "parent".into(),
                parent_revision: 1,
                revoked_admins: vec![
                    orc::RevokedAdminV1 {
                        agent: [1; 32],
                        revocation_hashes: vec![[0; 32]],
                    },
                    orc::RevokedAdminV1 {
                        agent: [2; 32],
                        revocation_hashes: vec![[0; 32]],
                    },
                ],
                promoted: [3; 32],
                promoted_certificate_digest: String::new(),
                owner_public_key: Vec::new(),
                issued_at_ms: 0,
            },
            signature: Vec::new(),
        };
        assert!(orc.head_round_groups().is_empty());
        orc.pending.insert(
            "g".into(),
            PendingMandate {
                mandate,
                wait: None,
                next_at: Instant::now(),
            },
        );
        let rounds = orc.head_round_groups();
        assert_eq!(
            rounds.get("g"),
            Some(&BTreeSet::from([[1u8; 32], [2u8; 32]]))
        );
    }

    /// Install a verified advert created at `created_at_unix_ms`. The store
    /// keeps an advert only if it is strictly newer than the held one, so a
    /// test that replaces an advert must give the first an earlier time.
    /// #1357 W3-H `s4_owner_recovery`: the promoted member waited forever
    /// for the revoked creator's KeyPackage (`waiting_for_member_key_package`
    /// naming A). A member that joined after the creator's attesting commit
    /// never retains it, so it refused the creator's attested recovery
    /// record and never held the package; once A was revoked its DMs were
    /// dropped and the leaf could not be removed. A later joiner now accepts
    /// the record while the attesting commit predates its retained history,
    /// still bound to the roster's committed package hash; a commit inside
    /// the retained window must still be on it.
    #[test]
    fn a_later_joiner_accepts_the_creators_attested_key_package() {
        use super::super::super as ng;
        let creator = x0x::identity::AgentKeypair::generate().unwrap();
        let creator_hex = hex::encode(creator.agent_id().as_bytes());
        let gid = "ab".repeat(16);
        let mut info = GroupInfo::new("g".into(), String::new(), creator.agent_id(), gid.clone());
        let package = "creator-key-package".to_string();
        info.set_member_treekem_key_package(&creator_hex, package.clone());
        let original = ng::NamedGroupMetadataEvent::MemberJoined {
            group_id: gid.clone(),
            stable_group_id: Some(info.stable_group_id().to_string()),
            member_agent_id: creator_hex.clone(),
            member_public_key_b64: String::new(),
            role: x0x::groups::GroupRole::Admin,
            display_name: None,
            inviter_agent_id: creator_hex.clone(),
            invite_secret: String::new(),
            ts_ms: 1,
            treekem_key_package_b64: Some(package),
            kem_public_key_b64: None,
            kem_signature_b64: None,
            certificate_b64: None,
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: String::new(),
        };
        info.security_binding = ng::treekem_recovery_security_binding(0, &original);
        let creator_commit = info.seal_commit(&creator, 1).unwrap();
        let record =
            ng::attest_member_joined_recovery_event(&original, &creator, &creator_commit).unwrap();
        assert!(
            ng::verify_authority_attested_member_joined_recovery(&info, &record),
            "the creator's own view accepts its record"
        );

        // Later history: a member is seated by a later commit.
        info.add_member(
            hex::encode([0x42; 32]),
            x0x::groups::GroupRole::Member,
            Some(creator_hex.clone()),
            None,
        );
        let later = info.seal_commit(&creator, 2).unwrap();
        assert!(later.revision > creator_commit.revision);

        // A joiner retains history from its join onwards only.
        let mut joiner = info.clone();
        joiner
            .commit_log
            .retain(|retained| retained.commit == later);
        assert_eq!(joiner.commit_log.len(), 1);
        assert!(
            ng::verify_authority_attested_member_joined_recovery(&joiner, &record),
            "a later joiner accepts the creator's attested package"
        );

        // The roster's committed hash still binds the bytes.
        let mut rebound = joiner.clone();
        rebound.set_member_treekem_key_package_hash(&creator_hex, "00".repeat(32));
        assert!(!ng::verify_authority_attested_member_joined_recovery(
            &rebound, &record
        ));

        // Inside the retained window, a commit that is not on it (a sibling
        // at the same revision) is refused.
        let mut forked = info.clone();
        for retained in &mut forked.commit_log {
            if retained.commit == creator_commit {
                retained.commit.state_hash = "f0".repeat(32);
            }
        }
        assert!(forked
            .commit_log
            .first()
            .is_some_and(|first| first.commit.revision <= creator_commit.revision));
        assert!(!ng::verify_authority_attested_member_joined_recovery(
            &forked, &record
        ));
    }

    pub(super) fn advertise(state: &AppState, peer: AgentId, bits: u64, created_at_unix_ms: u64) {
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

    /// #1357 / ADR 0110 §3, D60: a recovery commit or mandate write goes
    /// through the guarded admission with the `owner_recovery_v1` gate,
    /// evaluated again at the write seam. A recipient whose advert lacks
    /// bit 7 is refused; one that became ineligible (removed, banned, the
    /// head moved, or the group quarantined) after a passing pre-phase is
    /// refused by the seam and by a fresh pre-phase. Daemon-level (an
    /// in-process `AppState`); CI only.
    #[tokio::test]
    async fn recovery_egress_refuses_an_ineligible_recipient() -> anyhow::Result<()> {
        let (state, _dir) = super::super::super::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let survivor = AgentId([0x78; 32]);
        let survivor_hex = hex::encode(survivor.as_bytes());
        let group_id = "0c".repeat(16);
        let mut info = GroupInfo::new("orc".into(), String::new(), admin, group_id.clone());
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
        let admit = |rule: HeadRule| {
            guarded_admission_for(
                &state,
                &stable,
                &survivor,
                rule,
                x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1,
            )
        };

        // An advert with every other S4 bit but not bit 7 is refused. It is
        // 1 s old, so the upgraded advert below is strictly newer (two
        // inserts in one millisecond would drop the second).
        let now_ms = x0x::dm_capability::now_unix_ms();
        advertise(
            &state,
            survivor,
            x0x::dm::CapabilityRegistry::current().bits
                & !x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V1,
            now_ms.saturating_sub(1_000),
        );
        assert!(
            admit(rule.clone())().await.is_none(),
            "a recipient lacking owner_recovery_v1 is refused"
        );

        advertise(
            &state,
            survivor,
            x0x::dm::CapabilityRegistry::current().bits,
            now_ms,
        );
        let seam = admit(rule.clone())().await;
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
                // An epoch move as production commits it: the epoch and its
                // security binding move together, and the binding is what
                // the state hash commits to (the epoch alone leaves the
                // head unchanged).
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
            let seam = admit(rule.clone())()
                .await
                .unwrap_or_else(|| panic!("{label}: the pre-phase must admit first"));
            {
                let mut groups = state.named_groups.write().await;
                let stored = groups.get_mut(&group_id).expect("group");
                change(stored, &survivor_hex);
            }
            assert!(!seam(), "{label}: the seam must refuse the write");
            assert!(
                admit(rule.clone())().await.is_none(),
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

    /// ADR 0110 §4b(1) end to end in one daemon, for a `SignedPublic`
    /// `OwnerCertified` group: the owner route signs a mandate for this
    /// node's own agent, the promoted member authors the commit (A
    /// Removed, this node Admin), the frame passes the receivers' L4 rule
    /// against the parent, and the receive path installs it on the parent
    /// state through the chained apply.
    #[tokio::test]
    async fn owner_recovery_commit_authors_and_installs_on_signed_public() {
        let (_dir, state, info, admin_hex) = recovery_fixture().await;
        let stable = info.stable_group_id().to_string();
        let owner = state.agent.identity().user_keypair().unwrap();
        let local = state.agent.identity().agent_keypair();
        let local_hex = hex::encode(local.agent_id().as_bytes());

        let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");

        // ADR 0110 §2: no seal before a completed current catch-up round.
        try_commit(&state, &stable).await;
        let held = state
            .named_groups
            .read()
            .await
            .get(&stable)
            .cloned()
            .unwrap();
        assert_eq!(held.state_hash, info.state_hash, "no seal before head sync");
        {
            let inner = state.revocation_evictions.inner.lock().await;
            let wait = inner.orc.pending.get(&stable).and_then(|p| p.wait.clone());
            assert_eq!(
                wait.map(|(cause, _)| cause),
                Some(x0x::groups::eviction::WaitingCause::WaitingForHeadSync.as_str())
            );
            assert!(inner.orc.head_round_groups().contains_key(&stable));
        }
        sync_head(&state, &info).await;
        try_commit(&state, &stable).await;
        let committed = state
            .named_groups
            .read()
            .await
            .get(&stable)
            .cloned()
            .unwrap();
        assert_eq!(
            committed.members_v2[&local_hex].role,
            x0x::groups::GroupRole::Admin
        );
        assert_eq!(
            committed.members_v2[&admin_hex].state,
            x0x::groups::GroupMemberState::Removed
        );
        assert_eq!(committed.state_revision, info.state_revision + 1);
        // The committed frame is held for catch-up serving. Read it there:
        // this fixture has no other survivor, so the live delivery
        // converges at once and the spawned delivery task may already
        // have dropped it (a CI race at 2e73321).
        let served = state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .log
            .catchup_frames(std::slice::from_ref(&stable), info.state_revision);
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].1, committed.state_hash);
        let bytes = served[0].2.to_vec();
        let Ok(orc::OwnerRecoveryFrameV1::Commit(frame)) = orc::decode_frame(&bytes) else {
            panic!("an X0XORC1 commit frame");
        };
        orc::verify_commit_signatures(&frame).unwrap();
        let revocations = verified_agent_revocations(&state).await;
        orc::validate_against_parent(&frame.body, &info, 0, &revocations, now_unix()).unwrap();

        // A receiver still on the parent installs the same commit.
        state
            .named_groups
            .write()
            .await
            .insert(stable.clone(), info.clone());
        let outcome = receive_commit(&state, local.agent_id(), *frame, &bytes).await;
        assert_eq!(outcome, ReceiveOutcome::Applied);
        let installed = state
            .named_groups
            .read()
            .await
            .get(&stable)
            .cloned()
            .unwrap();
        assert_eq!(installed.state_hash, committed.state_hash);
        assert_eq!(
            installed.members_v2[&local_hex].role,
            x0x::groups::GroupRole::Admin
        );
        state.agent.shutdown().await;
    }

    /// #1508 review (Codex P1 #3), daemon level: the real commit path
    /// writes the frame before it persists the group. The in-memory
    /// recovery state is dropped (a crash before the delivery), and the
    /// catch-up after the restart serves the exact committed frame.
    /// Daemon-level; CI only.
    #[tokio::test]
    async fn a_restart_after_the_recovery_commit_serves_the_exact_frame() {
        let (_dir, state, info, _admin_hex) = recovery_fixture().await;
        let stable = info.stable_group_id().to_string();
        let owner = state.agent.identity().user_keypair().unwrap();
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        sync_head(&state, &info).await;
        try_commit(&state, &stable).await;
        let committed = state.named_groups.read().await[&stable].clone();
        assert_eq!(committed.state_revision, info.state_revision + 1);
        let bytes = {
            let mut inner = state.revocation_evictions.inner.lock().await;
            // The expected frame is read from the durable log, not from
            // `deliveries`: this fixture's survivor set is empty (the
            // revoked admin is removed and the promotee is local), so
            // the delivery is born converged (`all_converged` holds
            // vacuously) and a delivery pass may legitimately remove it
            // before this lock. The log is the commit's own record and
            // is never swept, so the bytes this test compares against
            // after the restart are the bytes the commit wrote.
            let planned = inner
                .orc
                .log
                .catchup_frames(std::slice::from_ref(&stable), info.state_revision);
            assert_eq!(planned.len(), 1, "the commit wrote exactly one frame");
            let bytes = planned[0].2.as_ref().clone();
            inner.orc = OrcState::default();
            bytes
        };
        ensure_restored(&state).await;
        let inner = state.revocation_evictions.inner.lock().await;
        let from = info.state_revision;
        let served = inner
            .orc
            .log
            .catchup_frames(std::slice::from_ref(&stable), from);
        assert_eq!(served.len(), 1, "the frame is missing after the restart");
        assert_eq!(served[0].1, committed.state_hash);
        assert_eq!(served[0].2.as_slice(), bytes.as_slice());
        assert!(inner.orc.deliveries.contains_key(&stable));
        drop(inner);
        state.agent.shutdown().await;
    }

    /// #1576: a held mandate's group where the mandate's named (revoked)
    /// admin is the only other active member has no head holders left.
    /// The worker pass's round excludes that admin, so nobody is asked;
    /// the §2 head gate (`group_head_synced`, which gates the mandate's
    /// seal) must agree and open once the restart minimum elapsed, with
    /// no confirmed round. Before the fix the gate still counted the
    /// revoked admin as a holder, so the seal waited the full restart
    /// sync wait for an answer that cannot come.
    #[tokio::test]
    async fn a_held_mandate_with_no_head_holders_opens_the_head_gate() {
        let (_dir, mut state, info, _admin_hex) = recovery_fixture().await;
        // A restart sync wait no paused-clock auto-advance can cover, so
        // only the holder count can open the round.
        Arc::get_mut(&mut state)
            .expect("the fresh state is not shared yet")
            .revocation_evictions = super::super::S4Runtime::new(x0x::groups::eviction::S4Timing {
            restart_sync_wait: Duration::from_secs(3600),
            ..x0x::groups::eviction::S4Timing::default()
        });
        let stable = info.stable_group_id().to_string();
        let owner = state.agent.identity().user_keypair().unwrap();
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        // The restart minimum elapses. The mandate is the group's only S4
        // work — no row and no queued ban — so the worker keeps the
        // group's head round through the owner-recovery plane alone, and
        // only the owner-recovery exclusions can drop the revoked admin
        // from the holders. The round for the current head just started
        // and has no answer yet, as a seal attempt right after a new head
        // meets.
        tokio::time::pause();
        tokio::time::advance(state.revocation_evictions.timing.restart_sync_wait).await;
        {
            let mut inner = state.revocation_evictions.inner.lock().await;
            assert!(
                inner.store.rows().next().is_none(),
                "no row: the mandate is the only work"
            );
            assert!(
                inner.orc.head_round_groups().contains_key(&stable),
                "the mandate's group keeps a head round with its named admin excluded"
            );
            inner.head_rounds.insert(
                stable.clone(),
                super::super::HeadRound {
                    head: info.state_hash.clone(),
                    started: Instant::now(),
                    asked: BTreeSet::new(),
                    confirmed: false,
                    conflicting: BTreeSet::new(),
                },
            );
        }
        assert!(
            super::super::group_head_synced(&state, &stable).await,
            "no holders left: the gate opens without a confirmed round"
        );
        // The held mandate seals on that gate.
        try_commit(&state, &stable).await;
        let committed = state.named_groups.read().await[&stable].clone();
        assert_eq!(
            committed.state_revision,
            info.state_revision + 1,
            "the recovery commits without waiting the restart sync wait"
        );
        state.agent.shutdown().await;
    }

    /// The restart minimum elapses (paused clock) and a holder confirms
    /// `info`'s head, so `group_head_synced` holds for it.
    async fn sync_head(state: &Arc<AppState>, info: &GroupInfo) {
        tokio::time::pause();
        tokio::time::advance(state.revocation_evictions.timing.restart_sync_wait).await;
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .head_rounds
            .insert(
                info.stable_group_id().to_string(),
                super::super::HeadRound {
                    head: info.state_hash.clone(),
                    started: Instant::now(),
                    asked: BTreeSet::new(),
                    confirmed: true,
                    conflicting: BTreeSet::new(),
                },
            );
    }

    /// One daemon holding a `SignedPublic` `OwnerCertified` group whose only
    /// admin is revoked; this node's agent is a certified Member and holds
    /// the owner key. Returns the parent state and the admin's hex ID.
    async fn recovery_fixture() -> (tempfile::TempDir, Arc<AppState>, GroupInfo, String) {
        let dir = tempfile::tempdir().unwrap();
        let user = x0x::identity::UserKeypair::from_seed(&[0x5F; 32]).unwrap();
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_identity_dir(dir.path().join("identity"))
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate().unwrap())
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .with_network_config(x0x::network::NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    bootstrap_nodes: Vec::new(),
                    mdns_enabled: false,
                    port_mapping_enabled: false,
                    ..Default::default()
                })
                .build()
                .await
                .unwrap(),
        );
        let state = super::super::super::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&agent),
        )
        .await
        .unwrap();
        let owner = state.agent.identity().user_keypair().unwrap();
        let admin = x0x::identity::AgentKeypair::generate().unwrap();
        let local = state.agent.identity().agent_keypair();
        let seat = |agent: &x0x::identity::AgentKeypair, role: x0x::groups::GroupRole| {
            let cert = x0x::identity::AgentCertificate::issue(owner, agent).unwrap();
            let id = hex::encode(agent.agent_id().as_bytes());
            let mut member = x0x::groups::GroupMember::new_member(id, None, None, 1);
            member.role = role;
            member.certificate_digest =
                Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
            member.certificate = Some(cert);
            member
        };
        let mut info = GroupInfo::new(
            "recovery".to_string(),
            String::new(),
            admin.agent_id(),
            "ef".repeat(16),
        );
        info.policy.admission =
            x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
        info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::SignedPublic;
        info.members_v2.clear();
        for member in [
            seat(&admin, x0x::groups::GroupRole::Admin),
            seat(local, x0x::groups::GroupRole::Member),
        ] {
            info.members_v2.insert(member.agent_id.clone(), member);
        }
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(stable.clone(), info.clone());
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(admin.agent_id()),
            admin.public_key(),
            admin.secret_key(),
            1,
            None,
        )
        .unwrap();
        assert!(state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)
            .unwrap());
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        (dir, state, info, admin_hex)
    }

    /// #1508 rc16 (Codex P2): the owner promotes its own agent, and a known
    /// Active member L's advert lacks `owner_recovery_v1`. The mandate
    /// waits for L's upgrade (D76) for longer than the retain TTL, and no
    /// outbound mandate replaces it. It must stay held, with the wait
    /// visible. Before the fix it was dropped after 600 s, so L's upgrade
    /// did not resume the recovery.
    #[tokio::test]
    async fn an_upgrade_wait_keeps_the_held_mandate_past_the_retain_ttl() {
        let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
        let stable = info.stable_group_id().to_string();
        let owner = state.agent.identity().user_keypair().unwrap();
        let legacy = x0x::identity::AgentKeypair::generate().unwrap();
        let legacy_hex = hex::encode(legacy.agent_id().as_bytes());
        let cert = x0x::identity::AgentCertificate::issue(owner, &legacy).unwrap();
        let mut member = x0x::groups::GroupMember::new_member(legacy_hex.clone(), None, None, 1);
        member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
        member.certificate = Some(cert);
        info.members_v2.insert(legacy_hex, member);
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(stable.clone(), info.clone());
        advertise(&state, legacy.agent_id(), 0, x0x::dm::now_unix_ms());

        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        sync_head(&state, &info).await;
        let upgrade = x0x::groups::eviction::WaitingCause::WaitingForReceiverUpgrade.as_str();
        let wait = |state: Arc<AppState>, stable: String| async move {
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .orc
                .pending
                .get(&stable)
                .map(|pending| pending.wait.as_ref().map(|(cause, _)| *cause))
        };
        try_commit(&state, &stable).await;
        assert_eq!(
            wait(Arc::clone(&state), stable.clone()).await,
            Some(Some(upgrade))
        );

        tokio::time::advance(ORC_RETAIN_TTL + Duration::from_secs(1)).await;
        drive(&state).await;
        assert_eq!(
            wait(Arc::clone(&state), stable.clone()).await,
            Some(Some(upgrade)),
            "the mandate is held until L upgrades"
        );
        state.agent.shutdown().await;
    }

    /// #1625: `try_commit` keeps a held mandate across a refusal that more
    /// data can clear. A quarantined group refuses the attempt; the
    /// mandate stays held with the typed cause, and once the containment
    /// lifts the same mandate commits. Before the fix the refusal dropped
    /// it, so the recovery waited for the owner's 5 s resend or a fresh
    /// signature.
    #[tokio::test]
    async fn a_transient_refusal_keeps_the_held_mandate() {
        let (_dir, state, info, _admin_hex) = recovery_fixture().await;
        let stable = info.stable_group_id().to_string();
        let owner = state.agent.identity().user_keypair().unwrap();
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        sync_head(&state, &info).await;

        let quarantined = {
            let mut quarantined = info.clone();
            quarantined.fork_quarantine = Some(x0x::groups::ForkQuarantine {
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
            quarantined
        };
        state
            .named_groups
            .write()
            .await
            .insert(stable.clone(), quarantined);
        try_commit(&state, &stable).await;
        {
            let inner = state.revocation_evictions.inner.lock().await;
            let pending = inner
                .orc
                .pending
                .get(&stable)
                .expect("#1625: the refusal keeps the held mandate");
            assert_eq!(
                pending.wait.as_ref().map(|(cause, _)| *cause),
                Some(orc::OwnerRecoveryRefusal::RecoveryGroupQuarantined.as_str()),
                "the wait names the transient refusal"
            );
        }
        assert_eq!(
            state
                .named_groups
                .read()
                .await
                .get(&stable)
                .map(|held| held.state_hash.clone()),
            Some(info.state_hash.clone()),
            "no commit while the group is quarantined"
        );

        // The containment lifts: the same mandate commits, with no resend
        // and no fresh signature.
        state
            .named_groups
            .write()
            .await
            .insert(stable.clone(), info.clone());
        try_commit(&state, &stable).await;
        let committed = state.named_groups.read().await[&stable].clone();
        assert_eq!(
            committed.state_revision,
            info.state_revision + 1,
            "the kept mandate commits once the refusal clears"
        );
        state.agent.shutdown().await;
    }

    /// #1357 CI (493c2a6): a commit attempt that waited on the membership
    /// lock while a concurrent attempt committed the mandate must not
    /// author it again. Before the fix the attempt took its snapshot of the
    /// held mandate before the lock, so it re-authored the same recovery
    /// on the head it found (here the restored parent). Daemon-level; CI
    /// only.
    #[tokio::test]
    async fn a_consumed_mandate_is_not_committed_by_a_waiting_attempt() {
        let (_dir, state, info, _admin_hex) = recovery_fixture().await;
        let stable = info.stable_group_id().to_string();
        let owner = state.agent.identity().user_keypair().unwrap();
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        // The route starts its own drive. Finish it before the head syncs.
        // Its first pass restores the pending-mandate file (#1625). If that
        // restore lands after the removal below, it puts back the mandate
        // that this test treats as consumed, and the waiting attempt then
        // commits it once. Before the sync, the drive only records the
        // head-sync wait.
        let tasks = {
            let mut tasks = state
                .detached_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tasks.as_mut().map(std::mem::take).unwrap_or_default()
        };
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            state
                .named_groups
                .read()
                .await
                .get(&stable)
                .map(|info| info.state_hash.clone())
                .as_deref(),
            Some(info.state_hash.as_str()),
            "the route's drive waits for head sync"
        );
        sync_head(&state, &info).await;

        let lock = super::super::super::group_membership_lock(&state, &stable).await;
        let guard = lock.lock().await;
        let attempt = {
            let state = Arc::clone(&state);
            let stable = stable.clone();
            tokio::spawn(async move { try_commit(&state, &stable).await })
        };
        // Let the attempt run up to the membership lock.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        // A concurrent attempt committed and consumed the mandate.
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .pending
            .remove(&stable);
        drop(guard);
        attempt.await.unwrap();
        let head = state
            .named_groups
            .read()
            .await
            .get(&stable)
            .map(|info| info.state_hash.clone());
        assert_eq!(
            head.as_deref(),
            Some(info.state_hash.as_str()),
            "a consumed mandate is never committed again"
        );
        assert!(!state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .deliveries
            .contains_key(&stable));
        state.agent.shutdown().await;
    }

    /// One group with the local admin and `survivor` as Active members,
    /// inserted under its raw id, for the drive tests below.
    async fn drive_group(state: &AppState, group_id: &str, survivor: &AgentId) -> GroupInfo {
        let admin = state.agent.agent_id();
        let mut info = GroupInfo::new("s4".into(), String::new(), admin, group_id.to_string());
        info.add_member(
            hex::encode(survivor.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info.clone());
        info
    }

    /// #1574 item 5: `drive_mandates` ends the owner's wait on its
    /// "head moved" read, so the read must hold
    /// `named_groups_persistence_lock`:
    /// `persist_named_group_info` shows its candidate in the map before
    /// the write and restores the map when the write fails. Before the
    /// fix the drive read a mid-write head candidate and retired the
    /// owner's wait (and its mandate file) on a head the committed roster
    /// never moved to.
    #[tokio::test]
    async fn an_ended_mandate_wait_waits_out_a_roster_candidate_that_rolls_back() {
        let (state, _dir) = super::super::super::tests::secure_endpoint_test_state()
            .await
            .unwrap();
        let survivor = AgentId([0x71; 32]);
        let promoted = *survivor.as_bytes();
        let group_id = "e7".repeat(16);
        let info = drive_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        {
            let mut inner = state.revocation_evictions.inner.lock().await;
            inner.orc.mandates.insert(
                stable.clone(),
                MandateDelivery {
                    mandate: orc::SignedOwnerRecoveryMandateV1 {
                        body: orc::OwnerRecoveryMandateBodyV1 {
                            stable_group_id: stable.clone(),
                            parent_head: info.state_hash.clone(),
                            parent_revision: info.state_revision,
                            revoked_admins: Vec::new(),
                            promoted,
                            promoted_certificate_digest: String::new(),
                            owner_public_key: Vec::new(),
                            issued_at_ms: 0,
                        },
                        signature: Vec::new(),
                    },
                    bytes: Arc::new(vec![4, 5, 6]),
                    mandate_id: "m1".to_string(),
                    promoted,
                    parent_head: info.state_hash.clone(),
                    recipients: BTreeMap::from([(promoted, RecipientDelivery::Due)]),
                    next_at: Instant::now(),
                },
            );
        }
        // The mid-write window: a moved-head candidate is in the map while
        // the persistence lock is held — exactly what a failing
        // `persist_named_group_info` restores.
        let guard = state.named_groups_persistence_lock.lock().await;
        let mut candidate = info.clone();
        candidate.state_hash = format!("{}-candidate", info.state_hash);
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), candidate);
        let driven = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { drive_mandates(&state).await })
        };
        for _ in 0..30 {
            if driven.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .orc
                .mandates
                .contains_key(&stable),
            "the ended wait must block on the persistence lock, not read the mid-write candidate"
        );
        // The write failed: the map is restored under the same lock hold.
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        drop(guard);
        driven.await.unwrap();
        let inner = state.revocation_evictions.inner.lock().await;
        let stored = inner
            .orc
            .mandates
            .get(&stable)
            .expect("the committed head is the mandate's parent, so the owner keeps waiting");
        assert_ne!(
            stored.recipients.get(&promoted),
            Some(&RecipientDelivery::Due),
            "the committed head's round ran"
        );
        drop(inner);
        state.agent.shutdown().await;
    }

    /// #1574 item 5: `drive_deliveries` drops a recovery delivery on its
    /// "head moved" read, so the read must hold
    /// `named_groups_persistence_lock` (the same candidate window as the
    /// mandate wait above). Before the fix the drive read a mid-write head
    /// candidate and dropped the delivery — and its GSS reshare
    /// obligation — on a head the committed roster never moved to.
    #[tokio::test]
    async fn a_dropped_recovery_delivery_waits_out_a_roster_candidate_that_rolls_back() {
        let (state, _dir) = super::super::super::tests::secure_endpoint_test_state()
            .await
            .unwrap();
        let survivor = AgentId([0x72; 32]);
        let group_id = "e8".repeat(16);
        let info = drive_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        {
            let mut inner = state.revocation_evictions.inner.lock().await;
            inner.orc.deliveries.insert(
                stable.clone(),
                CommitDelivery {
                    bytes: Arc::new(vec![1, 2, 3]),
                    result_head: info.state_hash.clone(),
                    next_revision: info.state_revision.saturating_add(1),
                    recipients: BTreeMap::from([(*survivor.as_bytes(), RecipientDelivery::Due)]),
                    next_at: Instant::now(),
                    resumed: false,
                    removed: BTreeSet::new(),
                    reshare_epoch: None,
                    share_went_to: BTreeMap::new(),
                },
            );
        }
        let guard = state.named_groups_persistence_lock.lock().await;
        let mut candidate = info.clone();
        candidate.state_hash = format!("{}-candidate", info.state_hash);
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), candidate);
        let driven = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { drive_deliveries(&state).await })
        };
        for _ in 0..30 {
            if driven.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .orc
                .deliveries
                .contains_key(&stable),
            "the drop must block on the persistence lock, not read the mid-write candidate"
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        drop(guard);
        driven.await.unwrap();
        let inner = state.revocation_evictions.inner.lock().await;
        let delivery = inner
            .orc
            .deliveries
            .get(&stable)
            .expect("the committed roster keeps the delivery");
        assert_ne!(
            delivery.recipients.get(survivor.as_bytes()),
            Some(&RecipientDelivery::Due),
            "the committed roster's round ran"
        );
        drop(inner);
        state.agent.shutdown().await;
    }
}

/// #1508 review (Codex P1 F2 and F3): a received recovery frame survives a
/// restart of its receiver, and a restored delivery waits for the §2 head
/// sync. Offline daemons only (no network node), so the tests are inert.
#[cfg(test)]
mod restart_tests {
    use super::super::rebind::restart_tests::{
        block_install, hold_persisted, insert_group, offline_daemon, set_evidence,
        state_past_restart_wait, unblock_install, HeadEvidence,
    };
    use super::super::{HeadRound, S4Runtime};
    use super::*;
    use anyhow::{Context, Result};
    use x0x::groups::eviction::S4Timing;

    /// The parent of a recovery: a `SignedPublic` `OwnerCertified` group
    /// whose only admin is revoked, with the author and the receiver as
    /// certified Members.
    fn recovery_parent<const N: usize>(
        owner: &x0x::identity::UserKeypair,
        admin: &x0x::identity::AgentKeypair,
        members: [&x0x::identity::AgentKeypair; N],
    ) -> Result<GroupInfo> {
        let seat = |agent: &x0x::identity::AgentKeypair,
                    role: x0x::groups::GroupRole|
         -> Result<x0x::groups::GroupMember> {
            let cert = x0x::identity::AgentCertificate::issue(owner, agent)?;
            let id = hex::encode(agent.agent_id().as_bytes());
            let mut member = x0x::groups::GroupMember::new_member(id, None, None, 1);
            member.role = role;
            member.certificate_digest =
                Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
            member.certificate = Some(cert);
            Ok(member)
        };
        let mut info = GroupInfo::new(
            "recovery".to_string(),
            String::new(),
            admin.agent_id(),
            "e9".repeat(16),
        );
        info.policy.admission =
            x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
        info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::SignedPublic;
        info.members_v2.clear();
        let mut seats = vec![seat(admin, x0x::groups::GroupRole::Admin)?];
        for member in members {
            seats.push(seat(member, x0x::groups::GroupRole::Member)?);
        }
        for member in seats {
            info.members_v2.insert(member.agent_id.clone(), member);
        }
        info.recompute_state_hash();
        Ok(info)
    }

    async fn revoke(state: &AppState, admin: &x0x::identity::AgentKeypair) -> Result<()> {
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(admin.agent_id()),
            admin.public_key(),
            admin.secret_key(),
            1,
            None,
        )?;
        let inserted = state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)?;
        anyhow::ensure!(inserted, "the admin revocation is held");
        Ok(())
    }

    /// The promoted member (offline, holding the owner key) authors the
    /// recovery; the receiver holds the parent on disk. Returns the
    /// receiver, the parent, the exact frame, its result head and the
    /// revoked admin. The author is shut down: it is offline from here on.
    async fn received_recovery(
        author_dir: &std::path::Path,
        receiver_dir: &std::path::Path,
    ) -> Result<(
        Arc<AppState>,
        GroupInfo,
        Vec<u8>,
        String,
        x0x::identity::AgentKeypair,
    )> {
        let user = x0x::identity::UserKeypair::from_seed(&[0x6E; 32])?;
        let mut author = offline_daemon(author_dir, Some(user)).await?;
        // The author's head sync: the restart minimum is zero and a holder
        // confirmed the parent head (set below).
        Arc::get_mut(&mut author)
            .context("the fresh author state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        let receiver = offline_daemon(receiver_dir, None).await?;
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let info = recovery_parent(
            owner,
            &admin,
            [
                author.agent.identity().agent_keypair(),
                receiver.agent.identity().agent_keypair(),
            ],
        )?;
        let stable = info.stable_group_id().to_string();
        for state in [&author, &receiver] {
            hold_persisted(state, &info).await?;
            revoke(state, &admin).await?;
        }
        let author_hex = hex::encode(author.agent.agent_id().as_bytes());
        let (status, Json(body)) =
            sign_recovery_mandate(&author, owner, &stable, &author_hex).await;
        anyhow::ensure!(status == StatusCode::ACCEPTED, "mandate: {body}");
        {
            let mut round = HeadRound::new(&info.state_hash, Instant::now());
            round.confirmed = true;
            let mut inner = author.revocation_evictions.inner.lock().await;
            inner.head_rounds.insert(stable.clone(), round);
        }
        try_commit(&author, &stable).await;
        let committed = author.named_groups.read().await[&stable].clone();
        anyhow::ensure!(
            committed.state_revision == info.state_revision + 1,
            "the author committed the recovery"
        );
        let bytes = author
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .deliveries[&stable]
            .bytes
            .to_vec();
        author.agent.shutdown().await;
        Ok((receiver, info, bytes, committed.state_hash, admin))
    }

    async fn receive_bytes(state: &Arc<AppState>, bytes: &[u8]) -> Result<ReceiveOutcome> {
        let Ok(orc::OwnerRecoveryFrameV1::Commit(frame)) = orc::decode_frame(bytes) else {
            anyhow::bail!("an X0XORC1 commit frame");
        };
        let sender = AgentId(frame.body.actor);
        Ok(receive_commit(state, sender, *frame, bytes).await)
    }

    async fn head_of(state: &AppState, stable: &str) -> Option<String> {
        state
            .named_groups
            .read()
            .await
            .get(stable)
            .map(|info| info.state_hash.clone())
    }

    async fn served(state: &AppState, stable: &str, from: u64) -> Vec<(String, Vec<u8>)> {
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .log
            .catchup_frames(std::slice::from_ref(&stable.to_string()), from)
            .into_iter()
            .map(|(_, head, bytes)| (head, bytes.to_vec()))
            .collect()
    }

    /// #1533 r6 (Codex P1 1), ADR 0109 §2 "Conflict": "Nothing past the
    /// common prefix applies" holds for an S4 owner recovery too. The
    /// receiver records an attestation conflict on the parent (no fork
    /// marker), then the valid recovery commit on that parent arrives: it
    /// is refused and the head does not move. Before the fix the recovery
    /// receiver applied the commit without the conflict gate. Inert.
    #[tokio::test]
    async fn a_recorded_attestation_conflict_refuses_a_valid_recovery() -> Result<()> {
        let (author_dir, receiver_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (receiver, info, bytes, _result_head, _admin) =
            received_recovery(author_dir.path(), receiver_dir.path()).await?;
        let stable = info.stable_group_id().to_string();
        anyhow::ensure!(
            super::super::super::group_recovery::record_conflict_at_head_for_test(&receiver, &info)
                .await?,
            "the conflict is durable"
        );
        assert_eq!(
            receive_bytes(&receiver, &bytes).await?,
            ReceiveOutcome::Refused(orc::OwnerRecoveryRefusal::RecoveryGroupQuarantined)
        );
        assert_eq!(
            head_of(&receiver, &stable).await.as_ref(),
            Some(&info.state_hash),
            "nothing past the common prefix applies (owner recovery)"
        );
        Ok(())
    }

    /// F2 (a): a survivor installs a recovery, then restarts while the
    /// author is offline. The restarted survivor serves the exact frame to
    /// another survivor that asks for catch-up from the parent revision.
    #[tokio::test]
    async fn a_restarted_receiver_serves_the_received_recovery_frame() -> Result<()> {
        let (author_dir, receiver_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (receiver, info, bytes, result_head, _admin) =
            received_recovery(author_dir.path(), receiver_dir.path()).await?;
        let stable = info.stable_group_id().to_string();
        assert_eq!(
            receive_bytes(&receiver, &bytes).await?,
            ReceiveOutcome::Applied
        );

        receiver.agent.shutdown().await;
        drop(receiver);
        let restarted = offline_daemon(receiver_dir.path(), None).await?;
        assert_eq!(
            head_of(&restarted, &stable).await.as_ref(),
            Some(&result_head),
            "the installed recovery survived the restart"
        );
        ensure_restored(&restarted).await;
        let frames = served(&restarted, &stable, info.state_revision).await;
        assert_eq!(
            frames,
            vec![(result_head, bytes)],
            "the restarted receiver serves the exact frame at catch-up"
        );
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// #1625: the owner's `waiting_for_recovery_member` wait and the
    /// promoted member's held mandate are durable. The owner signs for
    /// another node, both processes restart, and the member still holds
    /// the mandate and commits the recovery once its head syncs; the owner
    /// still shows the wait. Before the fix both sides were memory-only,
    /// so the recovery waited for the owner's 5 s resend or a fresh
    /// signature.
    #[tokio::test]
    async fn a_restart_keeps_the_held_mandate_and_the_owner_wait() -> Result<()> {
        let owner_dir = tempfile::tempdir()?;
        let member_dir = tempfile::tempdir()?;
        let user = || x0x::identity::UserKeypair::from_seed(&[0x72; 32]);
        let owner = offline_daemon(owner_dir.path(), Some(user()?)).await?;
        let member = offline_daemon(member_dir.path(), None).await?;
        let owner_kp = owner.agent.identity().user_keypair().context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let info = recovery_parent(owner_kp, &admin, [member.agent.identity().agent_keypair()])?;
        let stable = info.stable_group_id().to_string();
        for state in [&owner, &member] {
            hold_persisted(state, &info).await?;
            revoke(state, &admin).await?;
        }
        let member_hex = hex::encode(member.agent.agent_id().as_bytes());
        let (status, Json(body)) =
            sign_recovery_mandate(&owner, owner_kp, &stable, &member_hex).await;
        anyhow::ensure!(status == StatusCode::ACCEPTED, "mandate: {body}");
        let mandate = {
            let inner = owner.revocation_evictions.inner.lock().await;
            let bytes = inner.orc.mandates[&stable].bytes.clone();
            match orc::decode_frame(&bytes)? {
                orc::OwnerRecoveryFrameV1::Mandate(mandate) => mandate,
                _ => anyhow::bail!("an X0XORC1 mandate frame"),
            }
        };
        // No carrier in this fixture: the frame is handed to the member's
        // intake, as the direct-message listener would.
        accept_mandate(&member, mandate).await;
        {
            let inner = member.revocation_evictions.inner.lock().await;
            assert!(
                inner.orc.pending.contains_key(&stable),
                "the member holds the mandate"
            );
        }
        // The member restarts while its group is quarantined: the refusal
        // path keeps a held mandate across a quarantine, so the restart
        // must keep it too (#1625 review).
        let mut quarantined = info.clone();
        quarantined.fork_quarantine = Some(x0x::groups::ForkQuarantine {
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
        hold_persisted(&member, &quarantined).await?;

        owner.agent.shutdown().await;
        drop(owner);
        member.agent.shutdown().await;
        drop(member);
        let owner = offline_daemon(owner_dir.path(), Some(user()?)).await?;
        let member = zero_restart_wait(offline_daemon(member_dir.path(), None).await?)?;
        ensure_restored(&member).await;
        ensure_restored(&owner).await;
        {
            let inner = member.revocation_evictions.inner.lock().await;
            assert!(
                inner.orc.pending.contains_key(&stable),
                "#1625: the held mandate survived the restart under quarantine"
            );
        }
        {
            let inner = owner.revocation_evictions.inner.lock().await;
            assert!(
                inner.orc.mandates.contains_key(&stable),
                "#1625: the owner's wait survived the restart"
            );
            assert_eq!(inner.orc.mandates[&stable].parent_head, info.state_hash);
        }

        // The containment lifts and the restarted member commits the held
        // mandate on its own: the owner is offline, so no resend and no
        // fresh signature exist.
        member
            .named_groups
            .write()
            .await
            .insert(stable.clone(), info.clone());
        revoke(&member, &admin).await?;
        {
            let mut round = HeadRound::new(&info.state_hash, Instant::now());
            round.confirmed = true;
            member
                .revocation_evictions
                .inner
                .lock()
                .await
                .head_rounds
                .insert(stable.clone(), round);
        }
        try_commit(&member, &stable).await;
        let committed = member.named_groups.read().await[&stable].clone();
        assert_eq!(
            committed.state_revision,
            info.state_revision + 1,
            "the restarted member commits the held mandate"
        );
        assert_eq!(
            committed.members_v2[&member_hex].role,
            x0x::groups::GroupRole::Admin
        );
        // The consumed mandate leaves the file: a second restart cannot
        // resurrect it.
        assert!(!mandate_store::path(&member, &stable).exists());
        member.agent.shutdown().await;
        owner.agent.shutdown().await;
        Ok(())
    }

    /// F2 (b): the frame is durable before the roster it carries is
    /// installed. The install fails (a crash at that point), the frame is
    /// on disk, and after the restart the node installs it from its own
    /// copy and serves it, with the author offline.
    #[tokio::test]
    async fn a_crash_before_the_recovery_install_keeps_the_frame_durable() -> Result<()> {
        let (author_dir, receiver_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (receiver, info, bytes, result_head, admin) =
            received_recovery(author_dir.path(), receiver_dir.path()).await?;
        let stable = info.stable_group_id().to_string();

        let blocked = block_install(&receiver).await?;
        assert_eq!(
            receive_bytes(&receiver, &bytes).await?,
            ReceiveOutcome::Retained { verified: true },
            "the install failed"
        );
        assert_eq!(
            head_of(&receiver, &stable).await.as_ref(),
            Some(&info.state_hash),
            "the roster is not installed"
        );
        let on_disk =
            replay_log::tests::frames_on_disk(&receiver, replay_log::RECOVERY_EXTENSION, &stable)
                .await;
        assert_eq!(on_disk.len(), 1, "the received frame is durable");
        assert_eq!(on_disk[0].frame, bytes, "exact bytes");
        assert_eq!(on_disk[0].result_head, result_head);
        assert!(!on_disk[0].authored);

        receiver.agent.shutdown().await;
        drop(receiver);
        unblock_install(blocked).await?;
        let restarted = offline_daemon(receiver_dir.path(), None).await?;
        assert_eq!(
            head_of(&restarted, &stable).await.as_ref(),
            Some(&info.state_hash)
        );
        // A daemon keeps its verified revocations on disk; this test agent
        // has no identity directory, so it holds the record again.
        revoke(&restarted, &admin).await?;
        ensure_restored(&restarted).await;
        retry_stash(&restarted).await;
        assert_eq!(
            head_of(&restarted, &stable).await.as_ref(),
            Some(&result_head),
            "the restarted node installs its durable copy"
        );
        let frames = served(&restarted, &stable, info.state_revision).await;
        assert_eq!(frames, vec![(result_head, bytes)]);
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 (#1508 r6), author side: the roster write of a
    /// `SignedPublic` recovery renames the file, and then the directory
    /// fsync fails (`ReplacedNotDurable`). The new roster is installed, so
    /// the commit stands: the frame stays held and durable, and its
    /// delivery is scheduled. Before the fix the author took this as a
    /// failure, erased the held frame and scheduled no delivery, so the
    /// survivors could not get the chain link.
    #[tokio::test]
    async fn a_recovery_whose_roster_fsync_fails_keeps_its_frame_and_delivery() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let author = offline_author(dir.path(), [0x73; 32]).await?;
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let survivor = x0x::identity::AgentKeypair::generate()?;
        let info = recovery_parent(
            owner,
            &admin,
            [author.agent.identity().agent_keypair(), &survivor],
        )?;
        let stable = info.stable_group_id().to_string();
        hold_persisted(&author, &info).await?;
        revoke(&author, &admin).await?;
        let author_hex = hex::encode(author.agent.agent_id().as_bytes());
        let (status, Json(body)) =
            sign_recovery_mandate(&author, owner, &stable, &author_hex).await;
        anyhow::ensure!(status == StatusCode::ACCEPTED, "mandate: {body}");
        super::super::revocation_eviction_pass(&author).await;

        let _fault = super::super::super::set_save_fault(
            &author,
            super::super::super::SaveFault::ReplacedNotDurableAfterWrite,
        );
        try_commit(&author, &stable).await;
        let committed = author.named_groups.read().await[&stable].clone();
        assert_eq!(
            committed.state_revision,
            info.state_revision + 1,
            "the new roster is installed"
        );
        let delivery = author
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .deliveries
            .get(&stable)
            .cloned()
            .context("the installed recovery is scheduled for delivery")?;
        assert_eq!(delivery.result_head, committed.state_hash);
        assert!(delivery
            .recipients
            .contains_key(survivor.agent_id().as_bytes()));
        let frames = served(&author, &stable, info.state_revision).await;
        assert_eq!(
            frames,
            vec![(committed.state_hash.clone(), delivery.bytes.to_vec())],
            "the frame is held for catch-up"
        );
        let on_disk =
            replay_log::tests::frames_on_disk(&author, replay_log::RECOVERY_EXTENSION, &stable)
                .await;
        assert_eq!(on_disk.len(), 1, "the frame stays durable");
        assert_eq!(on_disk[0].frame, delivery.bytes.to_vec());
        author.agent.shutdown().await;
        Ok(())
    }

    /// #1574 item 1: the plain roster persist also refuses while an
    /// earlier write is still unconfirmed and its re-save fails again —
    /// that refusal stages no candidate. The author keeps its held
    /// mandate and schedules no delivery; the roster keeps the parent.
    /// Before the root fix the refusal read as `ReplacedNotDurable` —
    /// staged — and the author retired its mandate — here the owner's own
    /// agent is the promoted member, so no owner wait existed to re-send
    /// it — and scheduled a delivery for a roster the map never
    /// installed.
    #[tokio::test]
    async fn a_recovery_whose_confirming_resave_fails_keeps_its_mandate() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let author = offline_author(dir.path(), [0x74; 32]).await?;
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let info = recovery_parent(owner, &admin, [author.agent.identity().agent_keypair()])?;
        let stable = info.stable_group_id().to_string();
        hold_persisted(&author, &info).await?;
        revoke(&author, &admin).await?;
        let author_hex = hex::encode(author.agent.agent_id().as_bytes());
        let (status, Json(body)) =
            sign_recovery_mandate(&author, owner, &stable, &author_hex).await;
        anyhow::ensure!(status == StatusCode::ACCEPTED, "mandate: {body}");
        // The route starts its own drive. Finish that attempt before
        // the pass opens the head-sync round and before installing the
        // one-shot fault below. Otherwise it can race the explicit
        // attempt, consume the fault, and let the other attempt commit.
        let tasks = {
            let mut tasks = author
                .detached_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tasks.as_mut().map(std::mem::take).unwrap_or_default()
        };
        for task in tasks {
            task.await?;
        }
        assert_eq!(
            head_of(&author, &stable).await.as_ref(),
            Some(&info.state_hash),
            "the route's drive waits for head sync before the fault is armed"
        );
        super::super::revocation_eviction_pass(&author).await;

        author
            .named_groups_requires_durability_confirmation
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _fault = super::super::super::set_save_fault(
            &author,
            super::super::super::SaveFault::ReplacedNotDurableAfterWrite,
        );
        try_commit(&author, &stable).await;
        {
            let inner = author.revocation_evictions.inner.lock().await;
            assert!(
                inner.orc.pending.contains_key(&stable),
                "the held mandate is kept"
            );
            assert!(
                !inner.orc.deliveries.contains_key(&stable),
                "no delivery is scheduled for an install that never happened"
            );
        }
        assert_eq!(
            head_of(&author, &stable).await.as_ref(),
            Some(&info.state_hash),
            "the roster keeps the parent head"
        );
        author.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 (#1508 r6), receiver side: the receiver's roster write
    /// renames the file and the directory fsync fails. The recovery is
    /// installed, so the receiver reports it applied and serves the frame.
    /// Before the fix it reported `Retained` on an installed roster.
    #[tokio::test]
    async fn a_received_recovery_whose_roster_fsync_fails_is_applied() -> Result<()> {
        let (author_dir, receiver_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (receiver, info, bytes, result_head, _admin) =
            received_recovery(author_dir.path(), receiver_dir.path()).await?;
        let stable = info.stable_group_id().to_string();
        let _fault = super::super::super::set_save_fault(
            &receiver,
            super::super::super::SaveFault::ReplacedNotDurableAfterWrite,
        );
        assert_eq!(
            receive_bytes(&receiver, &bytes).await?,
            ReceiveOutcome::Applied
        );
        assert_eq!(
            head_of(&receiver, &stable).await.as_ref(),
            Some(&result_head)
        );
        let frames = served(&receiver, &stable, info.state_revision).await;
        assert_eq!(frames, vec![(result_head, bytes)]);
        receiver.agent.shutdown().await;
        Ok(())
    }

    /// #1574 item 1: the durability preflight's refusal stages nothing,
    /// so the receiver keeps the frame (`Retained`) and the roster keeps
    /// the parent. Before the root fix the refusal read as
    /// `ReplacedNotDurable` — staged — so the receiver returned `Applied`
    /// and dropped its mandate waits for an install that never happened.
    #[tokio::test]
    async fn a_received_recovery_refuses_a_durability_preflight_refusal() -> Result<()> {
        let (author_dir, receiver_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (receiver, info, bytes, _result_head, _admin) =
            received_recovery(author_dir.path(), receiver_dir.path()).await?;
        let stable = info.stable_group_id().to_string();
        receiver
            .named_groups_requires_durability_confirmation
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _fault = super::super::super::set_save_fault(
            &receiver,
            super::super::super::SaveFault::ReplacedNotDurableAfterWrite,
        );
        assert_eq!(
            receive_bytes(&receiver, &bytes).await?,
            ReceiveOutcome::Retained { verified: true },
            "nothing was installed"
        );
        assert_eq!(
            head_of(&receiver, &stable).await.as_ref(),
            Some(&info.state_hash),
            "the roster keeps the parent head"
        );
        receiver.agent.shutdown().await;
        Ok(())
    }

    /// `state` with a zero restart sync wait: only the per-group head
    /// round holds a seal or a restored resend.
    fn zero_restart_wait(mut state: Arc<AppState>) -> Result<Arc<AppState>> {
        Arc::get_mut(&mut state)
            .context("the fresh state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        Ok(state)
    }

    /// One S4 worker tick for owner recovery: the pass (it keeps the §2
    /// head rounds) and the owner-recovery drive.
    async fn worker_tick(state: &Arc<AppState>) {
        super::super::revocation_eviction_pass(state).await;
        drive(state).await;
    }

    /// The `SecureShareDelivered` envelopes `state` scheduled, by recipient.
    fn scheduled_shares(
        state: &AppState,
    ) -> Vec<(String, super::super::super::NamedGroupMetadataEvent)> {
        state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
            .map(|scheduled| scheduled.clone())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, recipient, payload)| {
                serde_json::from_slice(&payload)
                    .ok()
                    .map(|event| (recipient, event))
            })
            .collect()
    }

    /// Open a `SecureShareDelivered` envelope with the recipient's KEM key.
    fn open_share(
        event: &super::super::super::NamedGroupMetadataEvent,
        kem: &x0x::groups::kem_envelope::AgentKemKeypair,
    ) -> Result<(u64, [u8; 32])> {
        use base64::Engine as _;
        let super::super::super::NamedGroupMetadataEvent::SecureShareDelivered {
            group_id,
            recipient,
            secret_epoch,
            kem_ciphertext_b64,
            aead_nonce_b64,
            aead_ciphertext_b64,
            ..
        } = event
        else {
            anyhow::bail!("not a secure share");
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let nonce: [u8; 12] = b64
            .decode(aead_nonce_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("nonce length"))?;
        let secret = x0x::groups::kem_envelope::open_group_secret(
            kem,
            &x0x::groups::aad::secure_share_aad(group_id, recipient, *secret_epoch),
            &b64.decode(kem_ciphertext_b64)?,
            &nonce,
            &b64.decode(aead_ciphertext_b64)?,
        )?;
        Ok((*secret_epoch, secret))
    }

    /// Codex P1 (#1508): a GSS owner recovery commits, and the process
    /// crashes before the survivors' key envelopes leave. After the real
    /// restart (the group and the frame load from disk) and the real
    /// worker ticks, the survivor gets an envelope that opens to the new
    /// epoch's secret, once the group's head is synced and after the frame
    /// write to it (#1508 r5). Before the fix the
    /// restored delivery resent only the frame: the survivor moved to the
    /// new epoch without its secret.
    #[tokio::test]
    async fn a_restart_before_the_gss_key_delivery_reseals_the_new_secret() -> Result<()> {
        let author_dir = tempfile::tempdir()?;
        let seed = [0x6F; 32];
        let author = zero_restart_wait(
            offline_daemon(
                author_dir.path(),
                Some(x0x::identity::UserKeypair::from_seed(&seed)?),
            )
            .await?,
        )?;
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let survivor = x0x::identity::AgentKeypair::generate()?;
        let survivor_kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
        let survivor_hex = hex::encode(survivor.agent_id().as_bytes());
        let mut info = recovery_parent(
            owner,
            &admin,
            [author.agent.identity().agent_keypair(), &survivor],
        )?;
        info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
        {
            use base64::Engine as _;
            let member = info
                .members_v2
                .get_mut(&survivor_hex)
                .context("survivor seat")?;
            member.kem_public_key_b64 =
                Some(base64::engine::general_purpose::STANDARD.encode(&survivor_kem.public_bytes));
        }
        info.recompute_state_hash();
        assert_eq!(orc::crypto_kind(&info), orc::RecoveryCryptoKind::Gss);
        let stable = info.stable_group_id().to_string();
        hold_persisted(&author, &info).await?;
        revoke(&author, &admin).await?;
        let author_hex = hex::encode(author.agent.agent_id().as_bytes());
        let (status, Json(body)) =
            sign_recovery_mandate(&author, owner, &stable, &author_hex).await;
        anyhow::ensure!(status == StatusCode::ACCEPTED, "mandate: {body}");
        // The real pass opens the held mandate's head round; the commit
        // attempt runs now (the route's own attempt deferred the next).
        super::super::revocation_eviction_pass(&author).await;
        try_commit(&author, &stable).await;
        let committed = author.named_groups.read().await[&stable].clone();
        assert_eq!(committed.state_revision, info.state_revision + 1);
        assert_eq!(committed.secret_epoch, info.secret_epoch + 1);
        let new_secret = committed.shared_secret.clone().context("new secret")?;
        // #1508 r5: the share follows the frame write to the survivor;
        // with no advert for it yet, neither has left.
        assert!(
            !scheduled_shares(&author)
                .iter()
                .any(|(recipient, _)| *recipient == survivor_hex),
            "no share before the frame write to the survivor"
        );

        // Crash before the envelope delivery: every runtime task, recorder
        // and in-memory delivery is gone.
        author.agent.shutdown().await;
        drop(author);
        let restarted = zero_restart_wait(
            offline_daemon(
                author_dir.path(),
                Some(x0x::identity::UserKeypair::from_seed(&seed)?),
            )
            .await?,
        )?;
        assert_eq!(
            head_of(&restarted, &stable).await.as_ref(),
            Some(&committed.state_hash),
            "the committed recovery survived the restart"
        );
        assert!(scheduled_shares(&restarted).is_empty());
        // The survivor's current verified advert sets `owner_recovery_v1`.
        super::tests::advertise(
            &restarted,
            survivor.agent_id(),
            x0x::dm::CapabilityRegistry::current().bits,
            x0x::dm_capability::now_unix_ms(),
        );
        let mut shares = Vec::new();
        for _ in 0..100 {
            worker_tick(&restarted).await;
            shares = scheduled_shares(&restarted)
                .into_iter()
                .filter(|(recipient, _)| *recipient == survivor_hex)
                .collect();
            if !shares.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (_, share) = shares
            .first()
            .context("the restored delivery seals the new secret to the survivor again")?;
        let (epoch, secret) = open_share(share, &survivor_kem)?;
        assert_eq!(epoch, committed.secret_epoch, "the new epoch");
        assert_eq!(secret.as_slice(), new_secret.as_slice(), "the new secret");
        assert!(
            scheduled_shares(&restarted)
                .iter()
                .all(|(recipient, _)| *recipient == survivor_hex),
            "no share for the removed admin or the author"
        );
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// F3 (c): a recovery delivery restored after a restart is not resent
    /// while the group has higher-head or conflicting-head evidence, even
    /// though the restart wait has elapsed. It uses the same §2 gate as
    /// the removal and crypto-exclusion deliveries, and the real worker
    /// pass opens the group's head round for it (no open row and no held
    /// mandate keep one). Once the evidence resolves, the same round
    /// delivers it.
    #[tokio::test]
    async fn a_restored_recovery_delivery_waits_for_the_head_sync() -> Result<()> {
        let (state, _dir) = state_past_restart_wait().await?;
        let survivor = AgentId([0x5B; 32]);
        let group_id = "c9".repeat(16);
        let info = insert_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        let frame = Arc::new(b"X0XORC1\0restored frame".to_vec());
        let at = (info.state_revision, info.state_hash.as_str());
        let ext = replay_log::RECOVERY_EXTENSION;
        assert!(replay_log::write_planned(&state, ext, held, &stable, at, &frame).await);
        ensure_restored(&state).await;
        super::super::revocation_eviction_pass(&state).await;
        let scheduled = {
            let inner = state.revocation_evictions.inner.lock().await;
            anyhow::ensure!(
                inner.head_rounds.contains_key(&stable),
                "the worker pass opens a head round for the restored delivery"
            );
            inner
                .orc
                .deliveries
                .get(&stable)
                .context("restored")?
                .next_at
        };
        let held_back = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            let stable = stable.clone();
            async move {
                let inner = state.revocation_evictions.inner.lock().await;
                let delivery = inner.orc.deliveries.get(&stable).cloned();
                delivery.is_some_and(|delivery| {
                    delivery.next_at == scheduled
                        && delivery.recipients.get(survivor.as_bytes())
                            == Some(&RecipientDelivery::Due)
                })
            }
        };
        for evidence in [HeadEvidence::Higher, HeadEvidence::Conflicting] {
            set_evidence(&state, &group_id, &info, evidence, true).await;
            drive_deliveries(&state).await;
            assert!(
                held_back(&state).await,
                "{evidence:?} head evidence holds the restored delivery"
            );
            set_evidence(&state, &group_id, &info, evidence, false).await;
        }
        drive_deliveries(&state).await;
        assert!(
            !held_back(&state).await,
            "the synced group's restored delivery ran"
        );
        Ok(())
    }

    /// An offline promoted member that holds the owner key `seed`, with a
    /// zero restart sync wait.
    async fn offline_author(dir: &std::path::Path, seed: [u8; 32]) -> Result<Arc<AppState>> {
        zero_restart_wait(
            offline_daemon(dir, Some(x0x::identity::UserKeypair::from_seed(&seed)?)).await?,
        )
    }

    /// `author` signs a mandate for its own agent and commits the recovery
    /// through the real worker pass and commit attempt. Returns the
    /// committed state and the exact frame.
    async fn commit_own_recovery(
        author: &Arc<AppState>,
        stable: &str,
        parent: &GroupInfo,
    ) -> Result<(GroupInfo, Vec<u8>)> {
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let author_hex = hex::encode(author.agent.agent_id().as_bytes());
        let (status, Json(body)) = sign_recovery_mandate(author, owner, stable, &author_hex).await;
        anyhow::ensure!(status == StatusCode::ACCEPTED, "mandate: {body}");
        super::super::revocation_eviction_pass(author).await;
        try_commit(author, stable).await;
        let committed = author.named_groups.read().await[stable].clone();
        anyhow::ensure!(
            committed.state_revision == parent.state_revision + 1,
            "the author committed the recovery"
        );
        let bytes = author
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .deliveries
            .get(stable)
            .map(|delivery| delivery.bytes.to_vec())
            .context("the committed frame is held for delivery")?;
        Ok((committed, bytes))
    }

    /// Codex P1 (#1508 r5, A): the GSS recovery share and the recovery
    /// frame travel on different carriers, so a survivor can get the share
    /// first. The share goes through the real direct metadata apply, and
    /// then the frame through the real receive path. The survivor must
    /// end at the new epoch WITH its secret. Before the fix the share was
    /// refused (its sender was still a Member on the survivor's roster)
    /// and dropped, and the frame then moved the survivor to the new epoch
    /// with no secret and no later share.
    #[tokio::test]
    async fn a_gss_share_before_the_recovery_frame_still_installs_the_new_secret() -> Result<()> {
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let author = offline_author(author_dir.path(), [0x71; 32]).await?;
        let survivor = offline_daemon(survivor_dir.path(), None).await?;
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let survivor_id = survivor.agent.agent_id();
        let survivor_hex = hex::encode(survivor_id.as_bytes());
        let mut info = recovery_parent(
            owner,
            &admin,
            [
                author.agent.identity().agent_keypair(),
                survivor.agent.identity().agent_keypair(),
            ],
        )?;
        info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
        {
            use base64::Engine as _;
            let member = info
                .members_v2
                .get_mut(&survivor_hex)
                .context("survivor seat")?;
            member.kem_public_key_b64 = Some(
                base64::engine::general_purpose::STANDARD
                    .encode(&survivor.agent_kem_keypair.public_bytes),
            );
        }
        info.recompute_state_hash();
        assert_eq!(orc::crypto_kind(&info), orc::RecoveryCryptoKind::Gss);
        let stable = info.stable_group_id().to_string();
        for state in [&author, &survivor] {
            hold_persisted(state, &info).await?;
            revoke(state, &admin).await?;
        }
        // The survivor's current verified advert sets `owner_recovery_v1`.
        super::tests::advertise(
            &author,
            survivor_id,
            x0x::dm::CapabilityRegistry::current().bits,
            x0x::dm_capability::now_unix_ms(),
        );
        let (committed, frame) = commit_own_recovery(&author, &stable, &info).await?;
        let new_secret = committed.shared_secret.clone().context("new secret")?;

        // The real worker ticks deliver the recovery and its share.
        let mut share = None;
        for _ in 0..100 {
            worker_tick(&author).await;
            share = scheduled_shares(&author)
                .into_iter()
                .find(|(recipient, _)| *recipient == survivor_hex)
                .map(|(_, share)| share);
            if share.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let share = share.context("the author seals the new secret to the survivor")?;

        // The share lands first, through the direct metadata apply.
        let early = super::super::super::apply_named_group_metadata_event(
            &survivor,
            share,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(
            !early.accepted,
            "the promoted member is not an admin on the survivor's roster yet"
        );
        // Then the recovery frame.
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Applied
        );
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, committed.state_hash, "the recovery head");
        assert_eq!(held.secret_epoch, committed.secret_epoch, "the new epoch");
        assert_eq!(
            held.shared_secret.as_deref(),
            Some(new_secret.as_slice()),
            "the survivor holds the new epoch's secret"
        );
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// A committed GSS owner recovery on `author` with one survivor that
    /// has a roster KEM key: (author, survivor, parent, committed, frame,
    /// revoked admin).
    #[allow(clippy::type_complexity)]
    async fn committed_gss_recovery(
        author_dir: &std::path::Path,
        survivor_dir: &std::path::Path,
        bystander: Option<&x0x::identity::AgentKeypair>,
        bystander_kem: Option<&[u8]>,
    ) -> Result<(
        Arc<AppState>,
        Arc<AppState>,
        GroupInfo,
        GroupInfo,
        Vec<u8>,
        x0x::identity::AgentKeypair,
    )> {
        use base64::Engine as _;
        let author = offline_author(author_dir, [0x72; 32]).await?;
        let survivor = offline_daemon(survivor_dir, None).await?;
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        let pair = [
            author.agent.identity().agent_keypair(),
            survivor.agent.identity().agent_keypair(),
        ];
        let mut info = match bystander {
            Some(bystander) => recovery_parent(owner, &admin, [pair[0], pair[1], bystander])?,
            None => recovery_parent(owner, &admin, pair)?,
        };
        info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
        info.members_v2
            .get_mut(&survivor_hex)
            .context("survivor seat")?
            .kem_public_key_b64 = Some(
            base64::engine::general_purpose::STANDARD
                .encode(&survivor.agent_kem_keypair.public_bytes),
        );
        let mut advertised = vec![survivor.agent.agent_id()];
        if let Some(bystander) = bystander {
            let generated = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
            let kem = bystander_kem.unwrap_or(&generated.public_bytes);
            info.members_v2
                .get_mut(&hex::encode(bystander.agent_id().as_bytes()))
                .context("bystander seat")?
                .kem_public_key_b64 = Some(base64::engine::general_purpose::STANDARD.encode(kem));
            advertised.push(bystander.agent_id());
        }
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        for state in [&author, &survivor] {
            hold_persisted(state, &info).await?;
            revoke(state, &admin).await?;
        }
        for agent in advertised {
            super::tests::advertise(
                &author,
                agent,
                x0x::dm::CapabilityRegistry::current().bits,
                x0x::dm_capability::now_unix_ms(),
            );
        }
        let (committed, frame) = commit_own_recovery(&author, &stable, &info).await?;
        Ok((author, survivor, info, committed, frame, admin))
    }

    /// Run `author`'s worker, with its resend interval elapsed, until it
    /// sealed more than `seen` shares to `recipient`; the newest one.
    async fn next_share(
        author: &Arc<AppState>,
        stable: &str,
        recipient: &str,
        seen: usize,
    ) -> Result<super::super::super::NamedGroupMetadataEvent> {
        for _ in 0..100 {
            if let Some(delivery) = author
                .revocation_evictions
                .inner
                .lock()
                .await
                .orc
                .deliveries
                .get_mut(stable)
            {
                delivery.next_at = Instant::now();
            }
            worker_tick(author).await;
            let shares: Vec<_> = scheduled_shares(author)
                .into_iter()
                .filter(|(to, _)| to == recipient)
                .map(|(_, share)| share)
                .collect();
            if shares.len() > seen {
                return shares.last().cloned().context("a share");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        anyhow::bail!("the author sealed no new share to {recipient}")
    }

    /// The survivor answers the author's head ask with its current head.
    async fn report_head(author: &AppState, survivor: &AppState, stable: &str) -> Result<()> {
        let head = head_of(survivor, stable).await.context("survivor head")?;
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        super::super::note_catchup_head(author, &[stable.to_string()], &survivor_hex, Some(&head))
            .await;
        Ok(())
    }

    /// Whether `author` still delivers `stable`'s recovery to `survivor`.
    async fn still_delivering(author: &AppState, stable: &str, survivor: &AppState) -> bool {
        author
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .deliveries
            .get(stable)
            .and_then(|delivery| {
                delivery
                    .recipients
                    .get(survivor.agent.agent_id().as_bytes())
                    .copied()
            })
            .is_some_and(|status| status != RecipientDelivery::Converged)
    }

    /// Codex P1 (#1508 rc12), lost share: a survivor gets a GSS recovery
    /// frame, and its share is lost. It must not install the recovery head
    /// without the new secret, because that head is the author's
    /// convergence evidence: the author keeps the delivery and seals the
    /// share again, and the survivor installs head and secret together.
    /// Before the fix the survivor installed the head with no secret, its
    /// head answer ended the delivery, and no share came again.
    #[tokio::test]
    async fn a_lost_gss_recovery_share_keeps_the_delivery_until_the_key_installs() -> Result<()> {
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (author, survivor, info, committed, frame, _admin) =
            committed_gss_recovery(author_dir.path(), survivor_dir.path(), None, None).await?;
        let stable = info.stable_group_id().to_string();
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        let new_secret = committed.shared_secret.clone().context("new secret")?;
        // The first share is sealed and lost.
        next_share(&author, &stable, &survivor_hex, 0).await?;

        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Retained { verified: true },
            "the frame waits for its share"
        );
        assert_eq!(
            head_of(&survivor, &stable).await.as_ref(),
            Some(&info.state_hash),
            "no recovery head without its secret"
        );
        report_head(&author, &survivor, &stable).await?;
        assert!(
            still_delivering(&author, &stable, &survivor).await,
            "the survivor's head answer does not end the delivery"
        );

        // The author seals the share again; it arrives, then the frame.
        let share = next_share(&author, &stable, &survivor_hex, 1).await?;
        let early = super::super::super::apply_named_group_metadata_event(
            &survivor,
            share,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(!early.accepted, "the share is parked");
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Applied
        );
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, committed.state_hash);
        assert_eq!(held.secret_epoch, committed.secret_epoch);
        assert_eq!(held.shared_secret.as_deref(), Some(new_secret.as_slice()));
        // The next round's ask leaves after the re-seal (Engineer ruling,
        // 29 Oct 17:12 GMT); the survivor's answer to that ask ends the
        // delivery.
        {
            let mut inner = author.revocation_evictions.inner.lock().await;
            *inner
                .head_ask_seq
                .entry((stable.clone(), *survivor.agent.agent_id().as_bytes()))
                .or_insert(0) += 1;
        }
        report_head(&author, &survivor, &stable).await?;
        assert!(
            !still_delivering(&author, &stable, &survivor).await,
            "the delivery ends once the key installed"
        );
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// #1660 round 5 (Claude blocking at ccd7389): a LIVE owner-recovery
    /// delivery — never restarted, so no resumed row keeps its group in
    /// the worker's open set — converges through the real worker pass.
    /// The rounds' page asks are sent through the recorder (the offline
    /// fixture has no transport), so each one that went out advances the
    /// seat's count; the counts survive the pass, and the rounds'
    /// repeated seals to the same key keep the earliest seal's count, so
    /// the ask past that seal closes the seat on the survivor's answer.
    /// No ask count is raised by hand.
    #[tokio::test]
    async fn a_live_gss_recovery_delivery_converges_on_a_post_seal_answer() -> Result<()> {
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (author, survivor, info, committed, frame, _admin) =
            committed_gss_recovery(author_dir.path(), survivor_dir.path(), None, None).await?;
        let stable = info.stable_group_id().to_string();
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        let new_secret = committed.shared_secret.clone().context("new secret")?;
        // The fixture daemons share no transport: the head asks count
        // only when their page request went out (Codex P2, 29 Oct), so
        // the recorder carries the sends and records each one.
        author
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // The share arrives first and parks; the frame installs with it.
        let share = next_share(&author, &stable, &survivor_hex, 0).await?;
        let early = super::super::super::apply_named_group_metadata_event(
            &survivor,
            share,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(!early.accepted, "the share is parked");
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Applied
        );
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, committed.state_hash);
        assert_eq!(held.shared_secret.as_deref(), Some(new_secret.as_slice()));
        // The rounds keep asking, sealing and sending; the survivor
        // answers each ask. The delivery must end on one of them.
        for _ in 0..200 {
            report_head(&author, &survivor, &stable).await?;
            if !still_delivering(&author, &stable, &survivor).await {
                break;
            }
            {
                let mut inner = author.revocation_evictions.inner.lock().await;
                if let Some(delivery) = inner.orc.deliveries.get_mut(&stable) {
                    delivery.next_at = Instant::now();
                }
            }
            worker_tick(&author).await;
        }
        assert!(
            !still_delivering(&author, &stable, &survivor).await,
            "a live delivery converges on an answer to a post-seal ask (#1660, Engineer ruling, 29 Oct 17:12 GMT)"
        );
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// #1660 round 8 (Claude blocking at c5e18510): a live GSS
    /// recovery's round re-sends the commit and re-seals the rotated
    /// secret to the same key while the round's head ask is still out —
    /// the ask's request left, its ACK has not landed (the
    /// `treekem-catchup-page-ack` seam holds the send open, so the
    /// ordering does not lean on the recorder returning at once). The
    /// re-seal to the same key keeps the earliest bar and does not
    /// advance the share-seal generation (Engineer ruling, 30 Oct 05:10
    /// GMT), so the ask's late completion still credits the count, and
    /// the survivor's answer closes the seat in THAT round: convergence
    /// does not depend on the commit's ACK losing the race with the
    /// ask's. At c5e18510 the re-seal moved the generation, the late
    /// completion credited nothing, and the seat stayed open.
    #[tokio::test]
    async fn a_recovery_seat_closes_in_the_round_that_re_seals_while_its_ask_is_out() -> Result<()>
    {
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (author, survivor, info, _committed, frame, _admin) =
            committed_gss_recovery(author_dir.path(), survivor_dir.path(), None, None).await?;
        let stable = info.stable_group_id().to_string();
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        let survivor_id = *survivor.agent.agent_id().as_bytes();
        // The share arrives and parks; the frame installs with it, so the
        // survivor's head names the result the delivery waits on.
        let share = next_share(&author, &stable, &survivor_hex, 0).await?;
        let early = super::super::super::apply_named_group_metadata_event(
            &survivor,
            share,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(!early.accepted, "the share is parked");
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Applied
        );
        // Rounds run with the recorder off: the fixture has no transport,
        // so every page ask fails and counts nothing, and the first seal
        // records its bar at zero. The survivor answers each round, so
        // the §2 head round holds it answered and the parked round below
        // dispatches only the delivery's own ask.
        let mut sealed_at_zero = false;
        for _ in 0..100 {
            let state = {
                let inner = author.revocation_evictions.inner.lock().await;
                let recorded = inner
                    .orc
                    .deliveries
                    .get(&stable)
                    .is_some_and(|d| d.share_went_to.contains_key(&survivor_id));
                let count = inner
                    .head_ask_seq
                    .get(&(stable.clone(), survivor_id))
                    .copied();
                recorded && count.is_none()
            };
            if state {
                sealed_at_zero = true;
                break;
            }
            report_head(&author, &survivor, &stable).await?;
            {
                let mut inner = author.revocation_evictions.inner.lock().await;
                if let Some(delivery) = inner.orc.deliveries.get_mut(&stable) {
                    delivery.next_at = Instant::now();
                }
            }
            worker_tick(&author).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            sealed_at_zero,
            "the first seal recorded its bar with no ask that went out"
        );
        assert!(
            still_delivering(&author, &stable, &survivor).await,
            "the sealed share alone closes nothing: only a report does"
        );
        let shares_before = scheduled_shares(&author)
            .into_iter()
            .filter(|(to, _)| to == &survivor_hex)
            .count();
        // The parked round: the ask goes out and is held at its ACK while
        // the same round's commit resend re-seals to the same key.
        author
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let ack = super::super::super::detached_send_test_seam::arm(&format!(
            "treekem-catchup-page-ack:{stable}"
        ));
        {
            let mut inner = author.revocation_evictions.inner.lock().await;
            if let Some(delivery) = inner.orc.deliveries.get_mut(&stable) {
                delivery.next_at = Instant::now();
            }
        }
        worker_tick(&author).await;
        for _ in 0..250 {
            if ack.reached() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(4)).await;
        }
        assert!(
            ack.reached(),
            "the round's ask went out and its ACK is held: the send is in flight"
        );
        let mut re_sealed = false;
        for _ in 0..250 {
            let shares = scheduled_shares(&author)
                .into_iter()
                .filter(|(to, _)| to == &survivor_hex)
                .count();
            if shares > shares_before {
                re_sealed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(4)).await;
        }
        assert!(
            re_sealed,
            "the round's commit resend re-sealed the share while the ask was out"
        );
        // The ruling: the same-key re-seal moved neither the generation
        // the ask read before its request left nor the earliest bar.
        {
            let inner = author.revocation_evictions.inner.lock().await;
            assert_eq!(
                inner
                    .share_seal_seq
                    .get(&(stable.clone(), survivor_id))
                    .copied(),
                Some(1),
                "a re-seal to the same key does not advance the share-seal generation"
            );
            assert_eq!(
                inner
                    .orc
                    .deliveries
                    .get(&stable)
                    .and_then(|d| d.share_went_to.get(&survivor_id))
                    .map(|record| record.ask_seq_at_seal),
                Some(0),
                "the re-seal keeps the earliest seal's bar"
            );
        }
        // The ACK lands. The ask's send was in flight across the re-seal,
        // and its completion still counts — that is the round-8 fix.
        drop(ack);
        let mut counted = None;
        for _ in 0..250 {
            counted = {
                let inner = author.revocation_evictions.inner.lock().await;
                inner
                    .head_ask_seq
                    .get(&(stable.clone(), survivor_id))
                    .copied()
            };
            if counted == Some(1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(4)).await;
        }
        assert_eq!(
            counted,
            Some(1),
            "the ask that was out across the same-key re-seal still counts"
        );
        report_head(&author, &survivor, &stable).await?;
        assert!(
            !still_delivering(&author, &stable, &survivor).await,
            "the seat closes in the round that re-sealed while its ask was out (#1660 round 8)"
        );
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// #1660 round 6 (Claude blocking at bf01e28): a live recovery
    /// delivery's group is in no open row, held mandate or restored
    /// delivery, so before round 5's fix the worker pass's retain wiped
    /// its head-ask counts every second and the gate's anchor was gone.
    /// The group here owns a live delivery and nothing else — no
    /// revocation row keeps it in the open set — and a real dispatched
    /// ask built its count. The pass alone — no delivery drive after it
    /// — must keep that count. Red at ccd7389, where the retain dropped
    /// live delivery groups: the entry comes back `None`.
    #[tokio::test]
    async fn a_live_recovery_delivery_keeps_its_ask_counts_through_the_worker_pass() {
        let (state, _dir) = super::super::super::tests::secure_endpoint_test_state()
            .await
            .unwrap();
        let survivor = AgentId([0x72; 32]);
        let group_id = "e9".repeat(16);
        let admin = state.agent.agent_id();
        let mut info = GroupInfo::new("s4".into(), String::new(), admin, group_id.clone());
        info.add_member(
            hex::encode(survivor.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        let stable = info.stable_group_id().to_string();
        {
            let mut inner = state.revocation_evictions.inner.lock().await;
            inner.orc.deliveries.insert(
                stable.clone(),
                CommitDelivery {
                    bytes: Arc::new(vec![1, 2, 3]),
                    result_head: info.state_hash.clone(),
                    next_revision: info.state_revision.saturating_add(1),
                    recipients: BTreeMap::from([(*survivor.as_bytes(), RecipientDelivery::Sent)]),
                    next_at: Instant::now(),
                    resumed: false,
                    removed: BTreeSet::new(),
                    reshare_epoch: None,
                    share_went_to: BTreeMap::new(),
                },
            );
        }
        // Asks count only when their request went out (Codex P2): the
        // recorder carries the fixture's sends.
        state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // The delivery's round dispatched a head ask to the survivor and
        // it went out: the count exists.
        let mut asked = None;
        for _ in 0..100 {
            {
                let mut inner = state.revocation_evictions.inner.lock().await;
                if let Some(delivery) = inner.orc.deliveries.get_mut(&stable) {
                    delivery.next_at = Instant::now();
                }
                asked = inner
                    .head_ask_seq
                    .get(&(stable.clone(), *survivor.as_bytes()))
                    .copied();
            }
            if asked.is_some() {
                break;
            }
            worker_tick(&state).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let asked = asked.expect("a round dispatched a head ask that went out");
        // The pass alone — the step whose retain dropped live delivery
        // groups before round 5's fix. The count it built must survive
        // it.
        super::super::revocation_eviction_pass(&state).await;
        let kept = {
            let inner = state.revocation_evictions.inner.lock().await;
            inner
                .head_ask_seq
                .get(&(stable.clone(), *survivor.as_bytes()))
                .copied()
        };
        assert_eq!(
            kept,
            Some(asked),
            "a live recovery delivery's ask counts survive the worker pass"
        );
        state.agent.shutdown().await;
    }

    /// #1633: a GSS owner recovery aimed at a survivor whose seat this
    /// author's roster shows with no KEM public key, so no share can be
    /// sealed to it. ADR 0110 §3 L228 holds: survivor convergence, not a
    /// transport ACK, proves delivery. The carrier takes the frame each
    /// round, but that closes no seat — the close call of 25 Oct (an
    /// author-side skip record) lived under a day, 27 Oct 23:42 UTC to
    /// 28 Oct 00:18 UTC — and a keyless
    /// survivor claims no head while it is keyless (#1627, 28 Oct 02:09
    /// GMT), so it converges no author's row: the obligation stays open.
    /// The KEM key is local data, not in the roster root (#1578), so the
    /// recovery is the re-seated key, the resealed share, and the report
    /// the survivor makes after it installs head and secret together.
    #[tokio::test]
    async fn a_keyless_seat_stays_pending_until_the_reseated_key_installs_the_share() -> Result<()>
    {
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (author, survivor, info, committed, frame, _admin) =
            committed_gss_recovery(author_dir.path(), survivor_dir.path(), None, None).await?;
        let stable = info.stable_group_id().to_string();
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        let new_secret = committed.shared_secret.clone().context("new secret")?;
        // The seat's KEM key is local data (#1578): keep it, then remove
        // the author's view of it, so no share can be sealed to the seat.
        let saved_kem = author
            .named_groups
            .read()
            .await
            .get(&stable)
            .context("group")?
            .members_v2
            .get(&survivor_hex)
            .context("survivor seat")?
            .kem_public_key_b64
            .clone()
            .context("the fixture seats a KEM key")?;
        author
            .named_groups
            .write()
            .await
            .get_mut(&stable)
            .context("group")?
            .members_v2
            .get_mut(&survivor_hex)
            .context("survivor seat")?
            .kem_public_key_b64 = None;
        // The survivor holds the frame Retained: it has its key, but the
        // share that must land with the head did not come.
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Retained { verified: true },
            "the frame waits for its share"
        );

        // Pending phase: the author's rounds run. The carrier takes the
        // frame every round, but no ACK closes a seat (ADR 0110 §3), so
        // the obligation stays open while the seat cannot take a share.
        let shares_to_survivor = |author: &Arc<AppState>| {
            scheduled_shares(author)
                .into_iter()
                .filter(|(to, _)| to == &survivor_hex)
                .count()
        };
        let sealed = shares_to_survivor(&author);
        for _ in 0..25 {
            if let Some(delivery) = author
                .revocation_evictions
                .inner
                .lock()
                .await
                .orc
                .deliveries
                .get_mut(&stable)
            {
                delivery.next_at = Instant::now();
            }
            worker_tick(&author).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The carrier really took the frame in those rounds: the seat's
        // status is Sent — the acceptance that must close nothing. The
        // last round's send completes asynchronously, so poll for it,
        // and only then check the row: a close made when the send
        // completes must not slip through between the two checks.
        let mut accepted = false;
        for _ in 0..250 {
            let seat = author
                .revocation_evictions
                .inner
                .lock()
                .await
                .orc
                .deliveries
                .get(&stable)
                .and_then(|delivery| {
                    delivery
                        .recipients
                        .get(survivor.agent.agent_id().as_bytes())
                        .copied()
                });
            if seat == Some(RecipientDelivery::Sent) {
                accepted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            accepted,
            "the carrier took the frame: its acceptance is Sent, and it closes nothing"
        );
        assert!(
            still_delivering(&author, &stable, &survivor).await,
            "the carrier's acceptance of the frame closes no keyless seat"
        );
        assert_eq!(
            shares_to_survivor(&author),
            sealed,
            "no new share is sealed while the seat has no KEM key"
        );
        assert_eq!(
            head_of(&survivor, &stable).await.as_ref(),
            Some(&info.state_hash),
            "the survivor stays below the recovery, Retained frame and no share"
        );

        // Recovery: the seat re-joins keyed. The author's next round seals
        // the share again; the parked share and the Retained frame make
        // head and secret install together, and only the report of that
        // installed head ends the delivery.
        author
            .named_groups
            .write()
            .await
            .get_mut(&stable)
            .context("group")?
            .members_v2
            .get_mut(&survivor_hex)
            .context("survivor seat")?
            .kem_public_key_b64 = Some(saved_kem);
        let share = next_share(&author, &stable, &survivor_hex, sealed).await?;
        let early = super::super::super::apply_named_group_metadata_event(
            &survivor,
            share,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(!early.accepted, "the share is parked until its recovery");
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Applied,
            "the share makes head and secret install together"
        );
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, committed.state_hash);
        assert_eq!(held.secret_epoch, committed.secret_epoch);
        assert_eq!(held.shared_secret.as_deref(), Some(new_secret.as_slice()));
        // The author's next round's ask leaves after the re-seal (#1660,
        // Engineer ruling, 29 Oct 17:12 GMT); the survivor's answer to
        // that ask ends the delivery.
        {
            let mut inner = author.revocation_evictions.inner.lock().await;
            *inner
                .head_ask_seq
                .entry((stable.clone(), *survivor.agent.agent_id().as_bytes()))
                .or_insert(0) += 1;
        }
        report_head(&author, &survivor, &stable).await?;
        assert!(
            !still_delivering(&author, &stable, &survivor).await,
            "only the installed share's report ends the delivery"
        );
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 (#1508 rc12), receiver restart: the survivor gets the GSS
    /// recovery frame and restarts before its share arrives. The frame is
    /// durable; after the real restart the share arrives, the real worker
    /// installs the kept frame with the new epoch's secret, and the
    /// author's delivery did not end before that. Before the fix the
    /// survivor restarted at the recovery head with no secret, and its
    /// head answer ended the delivery.
    #[tokio::test]
    async fn a_survivor_restart_before_the_gss_share_installs_the_new_secret() -> Result<()> {
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (author, survivor, info, committed, frame, admin) =
            committed_gss_recovery(author_dir.path(), survivor_dir.path(), None, None).await?;
        let stable = info.stable_group_id().to_string();
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        let new_secret = committed.shared_secret.clone().context("new secret")?;
        let kem = Arc::clone(&survivor.agent_kem_keypair);
        next_share(&author, &stable, &survivor_hex, 0).await?;
        receive_bytes(&survivor, &frame).await?;

        // The survivor restarts; the share sent meanwhile is lost.
        survivor.agent.shutdown().await;
        drop(survivor);
        let mut restarted = offline_daemon(survivor_dir.path(), None).await?;
        Arc::get_mut(&mut restarted)
            .context("the restarted state is not shared yet")?
            .agent_kem_keypair = kem;
        // The test revocation set is in memory: hold the record again.
        revoke(&restarted, &admin).await?;
        ensure_restored(&restarted).await;
        report_head(&author, &restarted, &stable).await?;
        assert!(
            still_delivering(&author, &stable, &restarted).await,
            "the restarted survivor's head answer does not end the delivery"
        );

        let share = next_share(&author, &stable, &survivor_hex, 1).await?;
        super::super::super::apply_named_group_metadata_event(
            &restarted,
            share,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        drive(&restarted).await;
        let held = restarted.named_groups.read().await[&stable].clone();
        assert_eq!(
            held.state_hash, committed.state_hash,
            "the kept frame installs"
        );
        assert_eq!(held.secret_epoch, committed.secret_epoch);
        assert_eq!(
            held.shared_secret.as_deref(),
            Some(new_secret.as_slice()),
            "the restarted survivor holds the new epoch's secret"
        );
        author.agent.shutdown().await;
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 (#1508 rc12 r2), catch-up after another rotation: the GSS
    /// recovery moves the group to epoch E+1, and the author then removes
    /// a member with a GSS rekey to E+2, while a survivor is away. The
    /// survivor's catch-up from the author (the real serving path) seals
    /// only E+2's secret. The survivor gets that share, then the E+1
    /// recovery frame, then the E+2 removal. It must install the recovery
    /// as an intermediate head, take E+2's secret, and chain the removal.
    /// Before the fix the recovery waited for an E+1 share that no node
    /// seals any more, so the survivor could chain nothing after it.
    #[tokio::test]
    async fn a_gss_recovery_catchup_after_a_later_rotation_installs_and_chains() -> Result<()> {
        use super::super::super as ng;
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let bystander = x0x::identity::AgentKeypair::generate()?;
        let (author, survivor, parent, committed, frame, _admin) = committed_gss_recovery(
            author_dir.path(),
            survivor_dir.path(),
            Some(&bystander),
            None,
        )
        .await?;
        let stable = parent.stable_group_id().to_string();
        let survivor_id = survivor.agent.agent_id();
        let survivor_hex = hex::encode(survivor_id.as_bytes());
        let author_hex = hex::encode(author.agent.agent_id().as_bytes());
        let bystander_hex = hex::encode(bystander.agent_id().as_bytes());

        // The author removes the bystander with a GSS rekey to E+2, as the
        // admin removal path does.
        let mut removed = committed.clone();
        removed.roster_revision = removed.roster_revision.saturating_add(1);
        let revision = removed.roster_revision;
        removed.remove_member(&bystander_hex, Some(author_hex.clone()));
        let (new_secret, removal_epoch) = removed.rotate_shared_secret();
        anyhow::ensure!(removal_epoch == committed.secret_epoch + 1, "E+2");
        let now_ms = ng::now_millis_u64();
        let verdict =
            removed.owner_cert_verdict(&x0x::groups::owner_cert::OwnerCertEvidence::new(now_ms));
        let (commit, _) = removed.seal_commit_with_owner_certs(
            author.agent.identity().agent_keypair(),
            now_ms,
            &verdict,
        )?;
        let removal = ng::NamedGroupMetadataEvent::MemberRemoved {
            group_id: stable.clone(),
            revision,
            actor: author_hex.clone(),
            agent_id: bystander_hex,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: Some(removal_epoch),
            commit: Some(commit),
        };
        hold_persisted(&author, &removed).await?;

        // The survivor's catch-up from the author: the frames, and the
        // current (E+2) secret only.
        let before = scheduled_shares(&author).len();
        serve_catchup(
            &author,
            &survivor_id,
            std::slice::from_ref(&stable),
            parent.state_revision,
        )
        .await;
        let shares: Vec<_> = scheduled_shares(&author)
            .into_iter()
            .skip(before)
            .filter(|(to, _)| *to == survivor_hex)
            .map(|(_, share)| share)
            .collect();
        let share = shares.last().cloned().context("catch-up seals a share")?;
        assert_eq!(
            open_share(&share, &survivor.agent_kem_keypair)?,
            (removal_epoch, <[u8; 32]>::try_from(new_secret.as_slice())?),
            "catch-up seals the current secret only"
        );

        // The share, then the recovery frame, then the removal.
        let early = ng::apply_named_group_metadata_event(
            &survivor,
            share,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(!early.accepted, "the share is parked");
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Applied,
            "the recovery installs as an intermediate head"
        );
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, committed.state_hash);
        assert_eq!(
            held.secret_epoch, removal_epoch,
            "the later share installed"
        );
        assert_eq!(held.shared_secret.as_deref(), Some(new_secret.as_slice()));
        let applied = ng::apply_named_group_metadata_event(
            &survivor,
            removal,
            author.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(applied.accepted, "the removal chains: {applied:?}");
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, removed.state_hash, "the removal head");
        assert_eq!(held.secret_epoch, removal_epoch);
        assert_eq!(held.shared_secret.as_deref(), Some(new_secret.as_slice()));
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// The exact-share rule holds against any other sealer: a later-epoch
    /// share from a member that is no admin on the post-recovery roster
    /// does not let the recovery install without its secret.
    #[tokio::test]
    async fn a_later_gss_share_from_a_non_admin_does_not_skip_the_recovery_key() -> Result<()> {
        use super::super::super as ng;
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let bystander = x0x::identity::AgentKeypair::generate()?;
        let (author, survivor, parent, committed, frame, _admin) = committed_gss_recovery(
            author_dir.path(),
            survivor_dir.path(),
            Some(&bystander),
            None,
        )
        .await?;
        let stable = parent.stable_group_id().to_string();
        let survivor_hex = hex::encode(survivor.agent.agent_id().as_bytes());
        let kem = parent.members_v2[&survivor_hex]
            .kem_public_key_b64
            .clone()
            .context("survivor KEM key")?;
        let forged = ng::build_secure_share_event(
            &stable,
            &survivor_hex,
            &kem,
            &hex::encode(bystander.agent_id().as_bytes()),
            &[0x33; 32],
            committed.secret_epoch + 1,
        )
        .map_err(|_| anyhow::anyhow!("share build"))?;
        ng::apply_named_group_metadata_event(&survivor, forged, bystander.agent_id(), true, None)
            .await;
        assert_eq!(
            receive_bytes(&survivor, &frame).await?,
            ReceiveOutcome::Retained { verified: true },
            "the recovery still waits for its own share"
        );
        assert_eq!(
            head_of(&survivor, &stable).await.as_ref(),
            Some(&parent.state_hash)
        );
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// Seal `next` (already mutated) as `signer` on an owner-certified group.
    fn seal_owner_certified(
        next: &mut GroupInfo,
        signer: &x0x::identity::AgentKeypair,
    ) -> Result<x0x::groups::GroupStateCommit> {
        let now_ms = super::super::super::now_millis_u64();
        let verdict =
            next.owner_cert_verdict(&x0x::groups::owner_cert::OwnerCertEvidence::new(now_ms));
        Ok(next
            .seal_commit_with_owner_certs(signer, now_ms, &verdict)?
            .0)
    }

    /// The #1508 rc12 r3 chain: the recovery promotes P (the author) at
    /// E+1; Q installs it with its share; P promotes Q (a roster-only
    /// commit, still E+1). The survivor got P's promotion directly (its
    /// ordinary apply refuses it: the recovery is not installed there) but
    /// missed the recovery. Returns (P, Q, survivor, parent, recovery,
    /// promotion head, frame, promotion event).
    #[allow(clippy::type_complexity)]
    async fn recovery_then_promotion(
        dirs: [&std::path::Path; 3],
    ) -> Result<(
        Arc<AppState>,
        Arc<AppState>,
        Arc<AppState>,
        GroupInfo,
        GroupInfo,
        GroupInfo,
        Vec<u8>,
    )> {
        use super::super::super as ng;
        let q = offline_daemon(dirs[2], None).await?;
        let q_kp = q.agent.identity().agent_keypair();
        let (p, survivor, parent, recovery, frame, admin) = committed_gss_recovery(
            dirs[0],
            dirs[1],
            Some(q_kp),
            Some(&q.agent_kem_keypair.public_bytes),
        )
        .await?;
        let stable = parent.stable_group_id().to_string();
        hold_persisted(&q, &parent).await?;
        revoke(&q, &admin).await?;
        let q_hex = hex::encode(q.agent.agent_id().as_bytes());
        let p_hex = hex::encode(p.agent.agent_id().as_bytes());
        // Q installs the recovery with its share.
        let share = next_share(&p, &stable, &q_hex, 0).await?;
        ng::apply_named_group_metadata_event(&q, share, p.agent.agent_id(), true, None).await;
        anyhow::ensure!(
            receive_bytes(&q, &frame).await? == ReceiveOutcome::Applied,
            "Q installs the recovery"
        );
        // P promotes Q.
        let mut promoted = recovery.clone();
        promoted.set_member_role(&q_hex, x0x::groups::GroupRole::Admin);
        promoted.roster_revision = promoted.roster_revision.saturating_add(1);
        let revision = promoted.roster_revision;
        let commit = seal_owner_certified(&mut promoted, p.agent.identity().agent_keypair())?;
        let promotion = ng::NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: stable.clone(),
            revision,
            actor: p_hex,
            agent_id: q_hex,
            role: x0x::groups::GroupRole::Admin,
            commit: Some(commit),
        };
        hold_persisted(&p, &promoted).await?;
        let applied = ng::apply_named_group_metadata_event(
            &q,
            promotion.clone(),
            p.agent.agent_id(),
            true,
            None,
        )
        .await;
        anyhow::ensure!(applied.accepted, "Q applies its promotion: {applied:?}");
        let refused = ng::apply_named_group_metadata_event(
            &survivor,
            promotion,
            p.agent.agent_id(),
            true,
            None,
        )
        .await;
        anyhow::ensure!(
            !refused.accepted,
            "the survivor cannot chain the promotion yet"
        );
        Ok((p, q, survivor, parent, recovery, promoted, frame))
    }

    /// Q serves the survivor's catch-up (the real serving path): the
    /// recovery frame that Q holds, and Q's current secret. Returns the
    /// share.
    async fn catch_up_from(
        q: &Arc<AppState>,
        survivor: &AppState,
        parent: &GroupInfo,
    ) -> Result<super::super::super::NamedGroupMetadataEvent> {
        let survivor_id = survivor.agent.agent_id();
        let survivor_hex = hex::encode(survivor_id.as_bytes());
        let stable = parent.stable_group_id().to_string();
        // Q holds the survivor's current verified advert.
        super::tests::advertise(
            q,
            survivor_id,
            x0x::dm::CapabilityRegistry::current().bits,
            x0x::dm_capability::now_unix_ms(),
        );
        let before = scheduled_shares(q).len();
        serve_catchup(
            q,
            &survivor_id,
            std::slice::from_ref(&stable),
            parent.state_revision,
        )
        .await;
        scheduled_shares(q)
            .into_iter()
            .skip(before)
            .filter(|(to, _)| *to == survivor_hex)
            .map(|(_, share)| share)
            .next_back()
            .context("Q seals its current secret to the survivor")
    }

    /// #1579: a competing recovery frame kept below the head never stops
    /// the catch-up round — proven at the real `serve_catchup` loop. Two
    /// promoted members hold the owner key and seal competing recoveries
    /// from one parent; this node commits its own and holds the other as
    /// evidence, first in the log. The round skips the competitor, sends
    /// the on-chain frame (the test-build in-process stand-in admits it)
    /// and then seals the current secret to the requester: the scheduled
    /// share is the evidence the round ran past the competitor to its
    /// end. A `return` at the skip ends the round on the competitor, and
    /// no share is sealed.
    #[tokio::test]
    async fn the_catchup_round_skips_a_competing_recovery_frame_and_seals_the_share() -> Result<()>
    {
        let (author_dir, survivor_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let owner_seed = [0x73; 32];
        let author = offline_author(author_dir.path(), owner_seed).await?;
        let survivor = zero_restart_wait(
            offline_daemon(
                survivor_dir.path(),
                Some(x0x::identity::UserKeypair::from_seed(&owner_seed)?),
            )
            .await?,
        )?;
        let owner = author
            .agent
            .identity()
            .user_keypair()
            .context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let survivor_id = survivor.agent.agent_id();
        let survivor_hex = hex::encode(survivor_id.as_bytes());
        let author_hex = hex::encode(author.agent.agent_id().as_bytes());
        let mut info = recovery_parent(
            owner,
            &admin,
            [
                author.agent.identity().agent_keypair(),
                survivor.agent.identity().agent_keypair(),
            ],
        )?;
        info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
        {
            use base64::Engine as _;
            for (state, seat) in [
                (&author, author_hex.clone()),
                (&survivor, survivor_hex.clone()),
            ] {
                info.members_v2
                    .get_mut(&seat)
                    .context("seat")?
                    .kem_public_key_b64 = Some(
                    base64::engine::general_purpose::STANDARD
                        .encode(&state.agent_kem_keypair.public_bytes),
                );
            }
        }
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        for state in [&author, &survivor] {
            hold_persisted(state, &info).await?;
            revoke(state, &admin).await?;
        }
        // Each daemon holds the other's current verified advert, so the
        // capability gate never withholds and no commit waits on D76.
        let bits = x0x::dm::CapabilityRegistry::current().bits;
        let now = x0x::dm_capability::now_unix_ms();
        super::tests::advertise(&author, survivor_id, bits, now);
        super::tests::advertise(&survivor, author.agent.agent_id(), bits, now);
        // The survivor seals a competing recovery from the same parent.
        let (competed, competitor_bytes) = commit_own_recovery(&survivor, &stable, &info).await?;
        // The competitor enters this node's log first: the evidence the
        // round must serve past, before this node commits its own branch.
        {
            let mut inner = author.revocation_evictions.inner.lock().await;
            inner.orc.log.remember(
                &stable,
                competed.state_revision,
                competed.state_hash.as_str(),
                Arc::new(competitor_bytes),
                false,
            );
        }
        let (committed, _bytes) = commit_own_recovery(&author, &stable, &info).await?;
        anyhow::ensure!(
            committed.state_revision == competed.state_revision
                && committed.state_hash != competed.state_hash,
            "the two recoveries compete at one revision"
        );
        let order: Vec<String> = author
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .log
            .catchup_frames(std::slice::from_ref(&stable), info.state_revision)
            .into_iter()
            .map(|(_, head, _)| head)
            .collect();
        assert_eq!(
            order,
            vec![competed.state_hash.clone(), committed.state_hash.clone()],
            "the round meets the competitor first, then the on-chain frame"
        );
        // The real round: skip the competitor, serve the on-chain frame,
        // seal the current secret to the requester.
        let before = scheduled_shares(&author).len();
        serve_catchup(
            &author,
            &survivor_id,
            std::slice::from_ref(&stable),
            info.state_revision,
        )
        .await;
        let share = scheduled_shares(&author)
            .into_iter()
            .skip(before)
            .filter(|(to, _)| *to == survivor_hex)
            .map(|(_, share)| share)
            .next_back()
            .context("the round served past the competitor and sealed the share")?;
        let expected = <[u8; 32]>::try_from(
            committed
                .shared_secret
                .as_deref()
                .context("the committed secret")?,
        )?;
        assert_eq!(
            open_share(&share, &survivor.agent_kem_keypair)?,
            (committed.secret_epoch, expected),
            "the share opens to the current secret"
        );
        author.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 (#1508 rc12 r3): the recovery promotes P, P promotes Q,
    /// then P goes offline. A lagging survivor catches up from Q only: Q
    /// serves the recovery frame and its current secret (still E+1, the
    /// promotion is roster-only). The survivor must install the recovery,
    /// chain P's promotion and take Q's share, and end at Q's head with
    /// the right secret. Before the fix the recovery accepted its epoch's
    /// share only from P, Q's authority needed the recovery installed
    /// first, and the frame waited forever.
    #[tokio::test]
    async fn a_gss_recovery_catchup_from_a_later_admin_reaches_its_head() -> Result<()> {
        use super::super::super as ng;
        let dirs = [
            tempfile::tempdir()?,
            tempfile::tempdir()?,
            tempfile::tempdir()?,
        ];
        let (p, q, survivor, parent, recovery, promoted, frame) =
            recovery_then_promotion([dirs[0].path(), dirs[1].path(), dirs[2].path()]).await?;
        let stable = parent.stable_group_id().to_string();
        p.agent.shutdown().await;

        let share = catch_up_from(&q, &survivor, &parent).await?;
        let early =
            ng::apply_named_group_metadata_event(&survivor, share, q.agent.agent_id(), true, None)
                .await;
        assert!(
            !early.accepted,
            "Q is no admin on the survivor's roster yet"
        );
        let Ok(orc::OwnerRecoveryFrameV1::Commit(commit)) = orc::decode_frame(&frame) else {
            anyhow::bail!("a recovery commit frame");
        };
        assert_eq!(
            receive_commit(&survivor, q.agent.agent_id(), *commit, &frame).await,
            ReceiveOutcome::Applied,
            "the recovery installs from Q"
        );
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, promoted.state_hash, "Q's head");
        assert_eq!(held.secret_epoch, recovery.secret_epoch);
        assert_eq!(
            held.shared_secret.as_deref(),
            recovery.shared_secret.as_deref(),
            "the survivor holds the current secret"
        );
        q.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 (#1508 rc12 r3), variant: after its promotion Q removes P
    /// with a GSS rekey to E+2. The survivor catches up from Q only: Q's
    /// removal, Q's E+2 share, then the recovery frame. It must end at Q's
    /// removal head with the E+2 secret.
    #[tokio::test]
    async fn a_gss_recovery_catchup_after_a_later_admin_rotation_reaches_its_head() -> Result<()> {
        use super::super::super as ng;
        let dirs = [
            tempfile::tempdir()?,
            tempfile::tempdir()?,
            tempfile::tempdir()?,
        ];
        let (p, q, survivor, parent, _recovery, promoted, frame) =
            recovery_then_promotion([dirs[0].path(), dirs[1].path(), dirs[2].path()]).await?;
        let stable = parent.stable_group_id().to_string();
        let p_hex = hex::encode(p.agent.agent_id().as_bytes());
        let q_hex = hex::encode(q.agent.agent_id().as_bytes());
        p.agent.shutdown().await;

        // Q removes P with a GSS rekey, as the admin removal path does.
        let mut removed = promoted.clone();
        removed.roster_revision = removed.roster_revision.saturating_add(1);
        let revision = removed.roster_revision;
        removed.remove_member(&p_hex, Some(q_hex.clone()));
        let (new_secret, epoch) = removed.rotate_shared_secret();
        let commit = seal_owner_certified(&mut removed, q.agent.identity().agent_keypair())?;
        let removal = ng::NamedGroupMetadataEvent::MemberRemoved {
            group_id: stable.clone(),
            revision,
            actor: q_hex,
            agent_id: p_hex,
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: Some(epoch),
            commit: Some(commit),
        };
        hold_persisted(&q, &removed).await?;

        // The survivor's catch-up from Q: the removal (a page event), Q's
        // current (E+2) share, then the recovery frame.
        let early_removal = ng::apply_named_group_metadata_event(
            &survivor,
            removal,
            q.agent.agent_id(),
            true,
            None,
        )
        .await;
        assert!(!early_removal.accepted, "the removal cannot chain yet");
        let share = catch_up_from(&q, &survivor, &parent).await?;
        ng::apply_named_group_metadata_event(&survivor, share, q.agent.agent_id(), true, None)
            .await;
        let Ok(orc::OwnerRecoveryFrameV1::Commit(commit)) = orc::decode_frame(&frame) else {
            anyhow::bail!("a recovery commit frame");
        };
        assert_eq!(
            receive_commit(&survivor, q.agent.agent_id(), *commit, &frame).await,
            ReceiveOutcome::Applied,
            "the recovery installs from Q"
        );
        let held = survivor.named_groups.read().await[&stable].clone();
        assert_eq!(held.state_hash, removed.state_hash, "Q's removal head");
        assert_eq!(held.secret_epoch, epoch);
        assert_eq!(held.shared_secret.as_deref(), Some(new_secret.as_slice()));
        q.agent.shutdown().await;
        survivor.agent.shutdown().await;
        Ok(())
    }

    /// Codex P1 (#1508 r5, B), ADR 0110 §2: the owner signs two valid
    /// mandates on one parent, for two members. Each member commits its
    /// own recovery, so two sibling recoveries promote different members.
    /// Each replica then receives the other's sibling. It must keep the
    /// authenticated conflict as fork evidence and contain the group (the
    /// existing fork-quarantine marker; ADR 0064's owner anchor resolves
    /// it), across a restart, and stop sealing and delivering on its own
    /// branch. Before the fix the sibling was refused with
    /// `recovery_head_mismatch` and dropped: each side went on alone.
    #[tokio::test]
    async fn sibling_owner_recoveries_contain_the_group_on_each_replica() -> Result<()> {
        let seed = [0x72; 32];
        let (dir_a, dir_b) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let a = offline_author(dir_a.path(), seed).await?;
        let b = offline_author(dir_b.path(), seed).await?;
        let owner = a.agent.identity().user_keypair().context("owner key")?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let mut info = recovery_parent(
            owner,
            &admin,
            [
                a.agent.identity().agent_keypair(),
                b.agent.identity().agent_keypair(),
            ],
        )?;
        // #1508 r7: the parent is a sealed head, so each replica retains it
        // and can check the other's sibling against it.
        info.seal_commit_evicting(&admin, 1)?;
        let stable = info.stable_group_id().to_string();
        for state in [&a, &b] {
            hold_persisted(state, &info).await?;
            revoke(state, &admin).await?;
        }
        let (head_a, frame_a) = commit_own_recovery(&a, &stable, &info).await?;
        let (head_b, frame_b) = commit_own_recovery(&b, &stable, &info).await?;
        assert_ne!(head_a.state_hash, head_b.state_hash, "two siblings");

        for (replica, own, sibling) in [(&a, &head_a, &frame_b), (&b, &head_b, &frame_a)] {
            let sibling_head = match orc::decode_frame(sibling) {
                Ok(orc::OwnerRecoveryFrameV1::Commit(frame)) => frame.body.commit.state_hash,
                _ => anyhow::bail!("an X0XORC1 commit frame"),
            };
            assert_ne!(
                receive_bytes(replica, sibling).await?,
                ReceiveOutcome::Applied,
                "no node applies both siblings"
            );
            let held = replica.named_groups.read().await[&stable].clone();
            assert_eq!(held.state_hash, own.state_hash, "the own branch is kept");
            let marker = held
                .fork_quarantine
                .as_ref()
                .context("the sibling recovery is kept as fork evidence")?;
            assert_eq!(marker.state_hash, sibling_head, "the sibling's head");
            assert_eq!(marker.revision, own.state_revision);
            assert!(!marker.no_anchor, "the owner anchor resolves it");
            // Containment: the delivery of the own branch stops.
            drive_deliveries(replica).await;
            assert!(
                !replica
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .orc
                    .deliveries
                    .contains_key(&stable),
                "a contained group delivers no recovery"
            );
        }

        // The evidence survives a restart.
        a.agent.shutdown().await;
        drop(a);
        let restarted = offline_daemon(dir_a.path(), None).await?;
        let held = restarted.named_groups.read().await[&stable].clone();
        assert!(
            held.fork_quarantine.is_some(),
            "the fork evidence survives the restart"
        );
        restarted.agent.shutdown().await;
        b.agent.shutdown().await;
        Ok(())
    }
}
