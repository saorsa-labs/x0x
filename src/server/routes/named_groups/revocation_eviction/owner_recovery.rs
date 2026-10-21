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
//! - **Receive.** The §4b(1) L4 rule, then the ordinary chained apply with
//!   the roster change as its only mutation, then the crypto removal proof.

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
    apply_round, finish_attempt, guarded_admission_for, next_attempt, write_allowed, HeadRule,
    RecipientDelivery, RoundUpdate,
};
use super::rebind::replay_log;

/// The owner node's typed state until the promoted member commits.
pub(in crate::server) const WAITING_FOR_RECOVERY_MEMBER: &str = "waiting_for_recovery_member";

/// A send round runs no more often than this per mandate or commit.
const ORC_RESEND_INTERVAL: Duration = Duration::from_secs(5);
/// A retained mandate or stashed frame is dropped after this long.
const ORC_RETAIN_TTL: Duration = Duration::from_secs(600);
/// Frames held for a later retry.
const ORC_STASH_CAP: usize = 32;
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
    received_at: Instant,
}

/// The promoted member's delivery of one committed recovery.
#[derive(Debug, Clone)]
struct CommitDelivery {
    bytes: Arc<Vec<u8>>,
    result_head: String,
    next_revision: u64,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
}

#[derive(Debug, Clone)]
struct StashedFrame {
    sender: AgentId,
    bytes: Vec<u8>,
    at: Instant,
}

/// The owner-recovery state held in the S4 runtime, keyed by stable
/// group ID.
#[derive(Debug, Default)]
pub(super) struct OrcState {
    mandates: HashMap<String, MandateDelivery>,
    pending: HashMap<String, PendingMandate>,
    deliveries: HashMap<String, CommitDelivery>,
    stash: Vec<StashedFrame>,
    /// Authored and installed recovery commits, for catch-up serving; the
    /// author's are durable ([`replay_log`]).
    log: replay_log::HeldLog<ORC_LOG_PER_GROUP>,
}

impl OrcState {
    /// §2: the groups whose held mandate needs a head catch-up round
    /// before its seal, each with the named (revoked) admins, which are
    /// not head holders.
    pub(super) fn head_round_groups(&self) -> BTreeMap<String, BTreeSet<[u8; 32]>> {
        self.pending
            .iter()
            .map(|(stable, pending)| {
                (
                    stable.clone(),
                    pending
                        .mandate
                        .body
                        .revoked_admins
                        .iter()
                        .map(|admin| admin.agent)
                        .collect(),
                )
            })
            .collect()
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
    /// holds the commit with `result_head`, and drop a delivery that is
    /// complete. Returns the sends to start, after this.
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
        if stored
            .recipients
            .values()
            .all(|status| *status == RecipientDelivery::Sent)
        {
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

fn held(inner: &mut super::S4Inner) -> &mut replay_log::HeldLog<ORC_LOG_PER_GROUP> {
    &mut inner.orc.log
}

/// Load the durable recovery frames once, and deliver an authored commit
/// that is still its group's head again (#1508 review).
async fn ensure_restored(state: &AppState) {
    let resumes = replay_log::ensure_restored(state, replay_log::RECOVERY_EXTENSION, held).await;
    let local = *state.agent.agent_id().as_bytes();
    let mut inner = state.revocation_evictions.inner.lock().await;
    for resume in resumes {
        let recipients = survivors(&resume.info, &local, &BTreeSet::new());
        let stable = resume.stable_group_id;
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

/// The members a recovery commit on `info` must reach: the Active seats
/// other than `local` and the named admins.
fn survivors(info: &GroupInfo, local: &[u8; 32], removed: &BTreeSet<[u8; 32]>) -> Vec<[u8; 32]> {
    info.active_members()
        .filter_map(|member| agent_bytes(&member.agent_id))
        .filter(|id| id != local && !removed.contains(id))
        .collect()
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
                    bytes: Arc::new(bytes),
                    mandate_id: mandate_id.clone(),
                    promoted: *promoted.as_bytes(),
                    parent_head: info.state_hash.clone(),
                    recipients: BTreeMap::from([(*promoted.as_bytes(), RecipientDelivery::Due)]),
                    next_at: Instant::now(),
                },
            );
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
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.orc.pending.retain(|_, pending| {
            now.saturating_duration_since(pending.received_at) <= ORC_RETAIN_TTL
        });
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
        let head = group_by_stable(state, &stable)
            .await
            .filter(|(_, info)| !info.withdrawn)
            .map(|(_, info)| info.state_hash);
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
            stable,
            PendingMandate {
                mandate,
                wait: None,
                next_at: now,
                received_at: now,
            },
        );
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
            // is behind the mandate's head: keep it until its TTL.
            orc::OwnerRecoveryRefusal::RecoveryNotNeeded => {
                set_wait(state, stable, Some((refusal.as_str(), Vec::new()))).await;
            }
            orc::OwnerRecoveryRefusal::RecoveryHeadMismatch
                if info.state_revision < pending.mandate.body.parent_revision =>
            {
                set_wait(state, stable, Some((refusal.as_str(), Vec::new()))).await;
            }
            _ => {
                tracing::info!(
                    group_id = %ng::LogHexId::group(&group_key),
                    reason = refusal.as_str(),
                    "ADR 0110 S4: owner recovery mandate refused"
                );
                // Drop only the mandate this attempt checked; a newer one
                // that arrived meanwhile gets its own attempt.
                let mut inner = state.revocation_evictions.inner.lock().await;
                if inner
                    .orc
                    .pending
                    .get(stable)
                    .is_some_and(|held| held.mandate == pending.mandate)
                {
                    inner.orc.pending.remove(stable);
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
            commit_treekem(state, &group_key, &info, next, body, &revocations, &named).await;
        }
        orc::RecoveryCryptoKind::Gss => {
            let (secret, next_secret_epoch) = next.rotate_shared_secret();
            let Ok(secret) = <[u8; 32]>::try_from(secret.as_slice()) else {
                return;
            };
            body.crypto = orc::OwnerRecoveryCryptoV1::Gss { next_secret_epoch };
            // Build every survivor envelope before the commit: a keyless
            // survivor aborts the rotation (F1 §5 fail-closed).
            let mut envelopes = Vec::new();
            for member in next.active_members() {
                if member.agent_id == local_hex {
                    continue;
                }
                let Some(kem) = member.kem_public_key_b64.as_deref() else {
                    tracing::warn!(group_id = %ng::LogHexId::group(&group_key), "ADR 0110 S4: owner recovery deferred: a survivor has no roster KEM key");
                    set_wait(state, stable, None).await;
                    return;
                };
                match ng::build_secure_share_event(
                    stable,
                    &member.agent_id,
                    kem,
                    &local_hex,
                    &secret,
                    next_secret_epoch,
                ) {
                    Ok(event) => envelopes.push(event),
                    Err(_) => {
                        set_wait(state, stable, None).await;
                        return;
                    }
                }
            }
            if finish_commit(state, &group_key, &info, next, body, &revocations, None).await {
                // D60: each survivor share is a class-K delivery with a
                // fresh epoch-bound admission per write; never a publish.
                for event in &envelopes {
                    ng::spawn_secure_share_delivery(state, event);
                }
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
    named: &BTreeSet<[u8; 32]>,
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
    let installed = finish_commit(
        state,
        group_key,
        info,
        next.clone(),
        body,
        revocations,
        Some((&mut *guard, rollback_snapshot.as_slice())),
    )
    .await;
    drop(guard);
    if installed {
        for agent in named {
            let _ = ng::prune_treekem_cache_member(
                state,
                group_key,
                &hex::encode(agent),
                "owner_recovery",
            )
            .await;
        }
    }
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
        None => matches!(
            ng::persist_named_group_info(state, group_key, next.clone()).await,
            Ok(ng::AtomicWriteOutcome::Durable)
        ),
    };
    if !persisted {
        replay_log::rewrite_from_memory(state, ext, held, &stable).await;
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
            },
        );
    }
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
    let due: Vec<(String, CommitDelivery)> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner
            .orc
            .deliveries
            .iter_mut()
            .filter(|(_, delivery)| delivery.next_at <= now)
            .map(|(id, delivery)| {
                delivery.next_at = now + ORC_RESEND_INTERVAL;
                (id.clone(), delivery.clone())
            })
            .collect()
    };
    let local = *state.agent.agent_id().as_bytes();
    let capabilities = state.agent.capability_store();
    for (stable, delivery) in due {
        let info = group_by_stable(state, &stable).await.map(|(_, info)| info);
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
    let _spawned = state.spawn_detached(async move {
        let rule = HeadRule::Current(result_head.clone());
        let status = send_guarded(&task_state, &stable, &agent, rule, bytes.as_slice()).await;
        task_state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .finish_commit_attempt(&stable, &result_head, agent.as_bytes(), attempt, status);
    });
}

// ─── Catch-up serving ──────────────────────────────────────────────────────

/// Serve the recovery commit frames this node holds for the group (any of
/// `group_ids`) above `from_revision` to a catch-up requester, oldest
/// first, on the distinct gated carrier only, never inside a legacy
/// catch-up page (§4b(1) "Mixed versions"). Each write uses the guarded
/// admission with [`HeadRule::OnChain`] and the `owner_recovery_v1` gate.
///
/// The author's frames survive a restart ([`replay_log`]).
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
    for (group_id, result_head, bytes) in frames {
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
}

// ─── Receive ───────────────────────────────────────────────────────────────

/// The result of one commit receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveOutcome {
    Applied,
    Duplicate,
    /// Behind the parent, missing revocation evidence, or a local fault:
    /// keep the frame for a retry.
    Retained,
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
                if receive_commit(&task_state, sender, *frame, &payload).await
                    == ReceiveOutcome::Retained
                {
                    let mut inner = task_state.revocation_evictions.inner.lock().await;
                    if inner.orc.stash.len() >= ORC_STASH_CAP {
                        inner.orc.stash.remove(0);
                    }
                    inner.orc.stash.push(StashedFrame {
                        sender,
                        bytes: payload,
                        at: Instant::now(),
                    });
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

async fn retry_stash(state: &Arc<AppState>) {
    let stash = std::mem::take(&mut state.revocation_evictions.inner.lock().await.orc.stash);
    let now = Instant::now();
    let mut keep = Vec::new();
    for frame in stash {
        if now.saturating_duration_since(frame.at) > ORC_RETAIN_TTL {
            continue;
        }
        let Ok(orc::OwnerRecoveryFrameV1::Commit(commit)) = orc::decode_frame(&frame.bytes) else {
            continue;
        };
        if receive_commit(state, frame.sender, *commit, &frame.bytes).await
            == ReceiveOutcome::Retained
        {
            keep.push(frame);
        }
    }
    if !keep.is_empty() {
        let mut inner = state.revocation_evictions.inner.lock().await;
        keep.append(&mut inner.orc.stash);
        let excess = keep.len().saturating_sub(ORC_STASH_CAP);
        keep.drain(..excess);
        inner.orc.stash = keep;
    }
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
        return ReceiveOutcome::Retained;
    }
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
        return if refusal == orc::OwnerRecoveryRefusal::RecoveryNotNeeded {
            // The named revocation records may still be on their way.
            ReceiveOutcome::Retained
        } else {
            ReceiveOutcome::Refused(refusal)
        };
    }
    let commit = body.commit.to_commit();
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
                    if next.secret_epoch < *next_secret_epoch {
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
            tracing::info!(group_id = %ng::LogHexId::group(&group_key), "ADR 0110 S4: owner recovery commit refused by the chained apply: {error}");
            return ReceiveOutcome::Refused(orc::OwnerRecoveryRefusal::RecoveryProofInvalid);
        }
    };
    let removed: Vec<AgentId> = body
        .removed
        .iter()
        .map(|seat| AgentId(seat.agent))
        .collect();
    let installed = match (guard.as_mut(), &body.crypto) {
        (
            Some(guard),
            orc::OwnerRecoveryCryptoV1::TreeKem {
                commits,
                next_epoch,
            },
        ) => {
            let Ok(rollback_snapshot) = guard.to_snapshot_bytes() else {
                return ReceiveOutcome::Retained;
            };
            let processed = commits
                .iter()
                .all(|treekem_commit| guard.process_commit(treekem_commit).is_ok());
            // The cryptographic removal proof: every revoked leaf is gone.
            if !processed
                || guard.epoch() != *next_epoch
                || removed.iter().any(|agent| guard.tracks_member(agent))
            {
                ng::rollback_treekem_group_after_failed_install(
                    state,
                    &group_key,
                    &next,
                    &rollback_snapshot,
                    guard,
                    "owner_recovery_proof_failed",
                );
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
        _ => matches!(
            ng::persist_named_group_info(state, &group_key, next.clone()).await,
            Ok(ng::AtomicWriteOutcome::Durable)
        ),
    };
    drop(guard);
    if !installed {
        // A local storage fault, not a sender defect: keep the frame.
        return ReceiveOutcome::Retained;
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
        if kind == orc::RecoveryCryptoKind::TreeKem {
            let _ = ng::prune_treekem_cache_member(state, &group_key, &agent_hex, "owner_recovery")
                .await;
        }
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
            Arc::new(payload.to_vec()),
            false,
        );
    }
    tracing::info!(
        group_id = %ng::LogHexId::group(&group_key),
        bytes = payload.len(),
        "ADR 0110 S4: owner recovery installed"
    );
    if kind == orc::RecoveryCryptoKind::TreeKem {
        ng::replay_pending_treekem_events(state, &group_key).await;
    }
    state.agent.s4_revocation_intake().request_reconcile();
    ReceiveOutcome::Applied
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
        }
    }

    fn mandate_delivery(mandate_id: &str, promoted: [u8; 32]) -> MandateDelivery {
        MandateDelivery {
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
        // The complete delivery was dropped by that round, so a duplicate
        // completion of the same attempt writes nothing.
        assert!(!orc.deliveries.contains_key("g"));
        assert!(!orc.finish_commit_attempt(
            "g",
            "head-1",
            &survivor,
            attempt,
            RecipientDelivery::Due
        ));

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
        let expected: Vec<String> = (3..=total).map(|revision| format!("h{revision}")).collect();
        assert_eq!(heads, expected);
        assert!(all.iter().all(|(id, _, _)| id == "g"));
        let tail = orc.log.catchup_frames(&["g".into()], total - 1);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].1, format!("h{total}"));
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
                received_at: Instant::now(),
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

    fn advertise(state: &AppState, peer: AgentId, bits: u64, created_at_unix_ms: u64) {
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
        let bytes = state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .deliveries
            .get(&stable)
            .map(|delivery| delivery.bytes.to_vec())
            .expect("the committed frame is held for delivery");
        let Ok(orc::OwnerRecoveryFrameV1::Commit(frame)) = orc::decode_frame(&bytes) else {
            panic!("an X0XORC1 commit frame");
        };
        orc::verify_commit_signatures(&frame).unwrap();
        // The committed frame is held for catch-up serving.
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
        assert_eq!(served[0].2.as_slice(), bytes.as_slice());
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
            let bytes = inner.orc.deliveries[&stable].bytes.to_vec();
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
}
