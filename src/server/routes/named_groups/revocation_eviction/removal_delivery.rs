//! ADR 0110 §3 and §5: the delivery of a seated target's committed
//! removal.
//!
//! The unchanged legacy removal path builds the signed `MemberRemoved`
//! (with its TreeKEM commit or its rotated GSS secret epoch) inside its own
//! transaction, publishes it once and resends it on an in-memory schedule.
//! A crash or a partition in that window loses the event: the TreeKEM
//! commit is not stored anywhere else, and a GSS survivor has no way to
//! pull the rotated secret, so no survivor can catch up from this node
//! later.
//!
//! - **Save** ([`record_committed_removal`]). When S4 runs the removal,
//!   its row saves the exact outgoing event, the result head and the epoch,
//!   and moves to `committed_delivery_pending`. The `.evs` is fsynced
//!   before the first publication.
//! - **Delivery** ([`drive`]). The row stays `committed_delivery_pending`
//!   until every eligible survivor converged on the result: its own
//!   verified catch-up answer names the result head
//!   ([`crypto_exclusion::note_survivor_head`]). A successful write is not
//!   delivery (§3 "survivor convergence, not a transport ACK, proves
//!   delivery"); until the survivor converges, each round asks it for its
//!   head and sends the event again. Each write is guarded egress (§3 L231): ADR 0107's
//!   serving check, the D60 machine and binding check and the head rule
//!   run in the pre-phase and again at the write seam. Resends stop once
//!   the head moves past the result: old crypto material is never sent
//!   after an epoch change.
//! - **Restart** ([`resume_after_load`]). A saved event is classified
//!   against the verified chain like a crypto-only frame. Only an event
//!   whose result is still the head is resent, and only after the group's
//!   head is synced (§2, §3 "re-sync the head before any resend"): the
//!   restart wait, a completed current catch-up round and no unresolved
//!   higher-head evidence. No second rekey runs. For a GSS `MlsEncrypted`
//!   removal or ban, the first resumed round also seals the saved epoch's
//!   secret to each survivor again (`SecureShareDelivered`): the crash may
//!   have lost the legacy shares, and a survivor cannot pull them.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::eviction::{EvictionKey, ObligationStore, Phase, WaitingCause, WaitingState};
use x0x::groups::GroupInfo;

use super::super::NamedGroupMetadataEvent;
use super::crypto_exclusion::{self, HeadRule, RecipientDelivery, RoundUpdate, SavedFrameState};

/// A live delivery waits this long before its first send: the legacy
/// removal path already sent the initial volley.
const REMOVAL_FIRST_SEND_DELAY: Duration = Duration::from_secs(5);
/// A delivery round runs no more often than this per row.
const REMOVAL_RESEND_INTERVAL: Duration = Duration::from_secs(5);

/// The retained delivery of one committed seated-target removal.
#[derive(Debug, Clone)]
pub(super) struct RemovalDelivery {
    event: Arc<NamedGroupMetadataEvent>,
    result_head: String,
    /// The event was saved by an earlier boot: no resend before the
    /// group's head is synced.
    resumed: bool,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
    /// A resumed GSS removal or ban: the rotated secret epoch whose shares
    /// the first round sends again.
    reshare_epoch: Option<u64>,
}

/// The parts of a saved removal event that the restart needs.
#[derive(Debug, Clone)]
pub(super) struct SavedRemoval {
    pub(super) event: NamedGroupMetadataEvent,
    pub(super) result_head: String,
    pub(super) result_epoch: Option<u64>,
}

/// Decode a saved removal event: a `MemberRemoved` or an S4 ban's
/// `MemberBanned` that carries its signed commit. A crypto-only `X0XCE1`
/// frame is not JSON and gives `None`.
pub(super) fn decode_saved_removal(bytes: &[u8]) -> Option<SavedRemoval> {
    let event: NamedGroupMetadataEvent = serde_json::from_slice(bytes).ok()?;
    let (NamedGroupMetadataEvent::MemberRemoved {
        commit: Some(commit),
        treekem_epoch,
        secret_epoch,
        ..
    }
    | NamedGroupMetadataEvent::MemberBanned {
        commit: Some(commit),
        treekem_epoch,
        secret_epoch,
        ..
    }) = &event
    else {
        return None;
    };
    let result_head = commit.state_hash.clone();
    let result_epoch = treekem_epoch.or(*secret_epoch);
    Some(SavedRemoval {
        event,
        result_head,
        result_epoch,
    })
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

fn new_delivery(
    event: NamedGroupMetadataEvent,
    result_head: String,
    recipients: Vec<[u8; 32]>,
    resumed: bool,
    next_at: Instant,
) -> RemovalDelivery {
    RemovalDelivery {
        event: Arc::new(event),
        result_head,
        resumed,
        recipients: recipients
            .into_iter()
            .map(|id| (id, RecipientDelivery::Due))
            .collect(),
        next_at,
        reshare_epoch: None,
    }
}

/// The rotated GSS secret epoch of a saved removal or ban: a
/// `secret_epoch` with no TreeKEM commit. A TreeKEM commit carries its own
/// key material, and a `SignedPublic` group has no secret.
fn gss_secret_epoch(event: &NamedGroupMetadataEvent) -> Option<u64> {
    match event {
        NamedGroupMetadataEvent::MemberRemoved {
            treekem_commit_b64: None,
            secret_epoch,
            ..
        }
        | NamedGroupMetadataEvent::MemberBanned {
            treekem_commit_b64: None,
            secret_epoch,
            ..
        } => *secret_epoch,
        _ => None,
    }
}

/// Seal the group secret of `epoch` to each of `recipients` again, with the
/// existing class-K share delivery (`SecureShareDelivered`, ADR 0107 / D60
/// admission per write). Nothing is sent when the group's secret epoch is
/// not `epoch` any more: old key material is never sent after an epoch
/// change.
fn redeliver_secret_shares(
    state: &Arc<AppState>,
    info: &GroupInfo,
    recipients: &std::collections::BTreeSet<[u8; 32]>,
    epoch: u64,
) {
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
    let actor = hex::encode(state.agent.agent_id().as_bytes());
    for recipient in recipients {
        let recipient_hex = hex::encode(recipient);
        let Some(kem) = info
            .members_v2
            .get(&recipient_hex)
            .and_then(|member| member.kem_public_key_b64.as_deref())
        else {
            continue;
        };
        match super::super::build_secure_share_event(
            info.stable_group_id(),
            &recipient_hex,
            kem,
            &actor,
            &secret,
            epoch,
        ) {
            Ok(share) => {
                super::super::spawn_secure_share_delivery(state, &share);
            }
            Err(_) => tracing::warn!(
                group_id = %super::super::LogHexId::group(info.stable_group_id()),
                recipient = %super::super::LogHexId::agent(&recipient_hex),
                "ADR 0110 S4: cannot seal the rotated secret to a survivor again"
            ),
        }
    }
}

// ─── Save (§5) ─────────────────────────────────────────────────────────────

/// Save the exact outgoing `MemberRemoved` or `MemberBanned` of S4's own
/// removal or ban of `target_hex` from `info` (the committed after-image).
///
/// The caller is `RemovalBarrier::committed`, in the legacy removal or ban
/// route of any plane. It holds the group's
/// membership lock, its roster/crypto transaction is durable, and it has
/// not published the event yet. Only a row that S4 prepared for this
/// removal changes; any other removal returns at once. The `.evs` is
/// fsynced before this returns (§5: "persist ... exact outgoing event
/// before publication").
pub(in crate::server) async fn record_committed_removal(
    state: &AppState,
    info: &GroupInfo,
    target_hex: &str,
    event: &NamedGroupMetadataEvent,
) {
    let Some(target) = agent_bytes(target_hex) else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(event) else {
        return;
    };
    let Some(saved) = decode_saved_removal(&bytes) else {
        return;
    };
    let key = EvictionKey::new(info.stable_group_id().to_string(), target);
    let local = *state.agent.agent_id().as_bytes();
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        let Some(row) = inner.store.get_mut(&key) else {
            return;
        };
        if row.phase != Phase::Prepared {
            return;
        }
        row.phase = Phase::CommittedDeliveryPending;
        row.result_head = Some(saved.result_head.clone());
        row.result_epoch = saved.result_epoch;
        row.outgoing_event = Some(bytes);
        row.waiting = None;
        inner.removals.insert(
            key,
            new_delivery(
                saved.event,
                saved.result_head,
                survivors(info, &local, &target),
                false,
                Instant::now() + REMOVAL_FIRST_SEND_DELAY,
            ),
        );
        inner.dirty = true;
    }
    if !super::persist_obligations(state).await {
        tracing::warn!(
            group_id = %super::super::LogHexId::group(info.stable_group_id()),
            target = %super::super::LogHexId::agent(target_hex),
            "ADR 0110 S4: the saved removal event is not durable yet"
        );
    }
}

// ─── Restart (§3) ──────────────────────────────────────────────────────────

/// What a restart does with one saved removal event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ResumeAction {
    /// The result is the head: resend the saved event after the restart
    /// sync wait, with no second rekey.
    Deliver,
    /// The head moved past the result: discard the delivery; the next pass
    /// completes the row from the chain.
    Discard,
    /// The legacy commit did not land: the row returns to `pending`.
    Abandon,
    /// A competing branch: keep the event as fork evidence and never
    /// publish it.
    Fork,
    /// The relation is unknown yet: `waiting_for_head_sync`.
    WaitForHeadSync,
}

/// Classify a saved removal against `info`'s verified chain (§3).
pub(super) fn classify(
    info: &GroupInfo,
    parent_head: Option<&str>,
    result_head: &str,
) -> ResumeAction {
    let Some(parent_head) = parent_head else {
        // Without the parent the relation cannot be proved; a head equal
        // to the result is still the committed removal.
        return if info.fork_quarantine.is_none() && info.state_hash == result_head {
            ResumeAction::Deliver
        } else {
            ResumeAction::WaitForHeadSync
        };
    };
    match crypto_exclusion::classify_saved_frame(info, parent_head, result_head) {
        SavedFrameState::CurrentHead => ResumeAction::Deliver,
        SavedFrameState::Superseded => ResumeAction::Discard,
        SavedFrameState::Abandoned => ResumeAction::Abandon,
        SavedFrameState::Fork => ResumeAction::Fork,
        SavedFrameState::Unknown => ResumeAction::WaitForHeadSync,
    }
}

/// §3 restart: reconcile every open row that holds a saved removal event
/// against the loaded, verified chain.
pub(super) fn resume_after_load(
    groups: &[(String, GroupInfo)],
    local: &[u8; 32],
    store: &mut ObligationStore,
    removals: &mut HashMap<EvictionKey, RemovalDelivery>,
    ce_state: &mut crypto_exclusion::CeState,
) {
    let saved: Vec<(EvictionKey, SavedRemoval)> = store
        .rows()
        .filter(|row| row.phase.is_open())
        .filter_map(|row| {
            let saved = decode_saved_removal(row.outgoing_event.as_deref()?)?;
            Some((row.key(), saved))
        })
        .collect();
    for (key, saved) in saved {
        let Some(info) = groups
            .iter()
            .map(|(_, info)| info)
            .find(|info| info.stable_group_id() == key.stable_group_id)
        else {
            continue;
        };
        let Some(row) = store.get_mut(&key) else {
            continue;
        };
        match classify(info, row.parent_head.as_deref(), &saved.result_head) {
            ResumeAction::Deliver => {
                row.phase = Phase::CommittedDeliveryPending;
                row.result_head = Some(saved.result_head.clone());
                let reshare_epoch = gss_secret_epoch(&saved.event);
                let mut delivery = new_delivery(
                    saved.event,
                    saved.result_head,
                    survivors(info, local, &key.target),
                    true,
                    Instant::now(),
                );
                delivery.reshare_epoch = reshare_epoch;
                removals.insert(key.clone(), delivery);
            }
            ResumeAction::Discard => {
                row.phase = Phase::CommittedDeliveryPending;
                row.result_head = Some(saved.result_head);
                row.outgoing_event = None;
            }
            ResumeAction::Abandon => {
                row.phase = Phase::Pending;
                row.parent_head = None;
                row.result_head = None;
                row.result_epoch = None;
                row.outgoing_event = None;
            }
            ResumeAction::Fork => {
                ce_state.fork.insert(key.clone());
                tracing::warn!(
                    group_id = %super::super::LogHexId::group(&key.stable_group_id),
                    target = %super::super::LogHexId::agent(&hex::encode(key.target)),
                    "ADR 0110 S4: a saved removal meets a competing branch; waiting for fork resolution"
                );
            }
            ResumeAction::WaitForHeadSync => {
                row.waiting = Some(WaitingState::cause(WaitingCause::WaitingForHeadSync));
            }
        }
    }
}

// ─── Delivery ──────────────────────────────────────────────────────────────

/// One delivery round for every due saved removal: per recipient,
/// re-check the roster and the agent, machine and binding revocations,
/// then send the saved event on the direct carrier.
pub(super) async fn drive(state: &Arc<AppState>) {
    let runtime = &state.revocation_evictions;
    let now = Instant::now();
    let candidates: Vec<(EvictionKey, bool)> = runtime
        .inner
        .lock()
        .await
        .removals
        .iter()
        .filter(|(_, delivery)| delivery.next_at <= now)
        .map(|(key, delivery)| (key.clone(), delivery.resumed))
        .collect();
    // §3 "re-sync the head before any resend": a saved event waits for the
    // group's real head sync, not only the restart wait.
    let synced = crypto_exclusion::resumed_groups_head_synced(state, &candidates).await;
    let due: Vec<(EvictionKey, RemovalDelivery)> = {
        let mut inner = runtime.inner.lock().await;
        candidates
            .into_iter()
            .filter_map(|(key, _)| {
                let delivery = inner.removals.get_mut(&key)?;
                if !crypto_exclusion::resend_due(
                    delivery.next_at,
                    delivery.resumed,
                    &synced,
                    &key,
                    now,
                ) {
                    return None;
                }
                delivery.next_at = now + REMOVAL_RESEND_INTERVAL;
                Some((key, delivery.clone()))
            })
            .collect()
    };
    if due.is_empty() {
        return;
    }
    let local = *state.agent.agent_id().as_bytes();
    for (key, delivery) in due {
        let info = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == key.stable_group_id)
                .cloned()
        };
        let Some(info) = info.filter(|info| !info.withdrawn) else {
            runtime.inner.lock().await.removals.remove(&key);
            continue;
        };
        if info.fork_quarantine.is_some() {
            let mut inner = runtime.inner.lock().await;
            inner.removals.remove(&key);
            inner.ce.fork.insert(key.clone());
            continue;
        }
        if info.state_hash != delivery.result_head {
            // The head moved past the removal: never resend old crypto
            // material after an epoch change.
            let mut inner = runtime.inner.lock().await;
            inner.removals.remove(&key);
            inner.dirty = true;
            continue;
        }
        let active: std::collections::BTreeSet<[u8; 32]> =
            survivors(&info, &local, &key.target).into_iter().collect();
        let mut updates: Vec<RoundUpdate> = Vec::new();
        let mut head_asks: Vec<x0x::identity::AgentId> = Vec::new();
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
            let agent = x0x::identity::AgentId(*recipient);
            // §3: a written event is not a delivered one. Ask the survivor
            // for its head and send the event again, admitted afresh,
            // until it converges.
            if *status == RecipientDelivery::Sent {
                head_asks.push(agent);
            }
            if !crypto_exclusion::write_allowed(state, &agent).await {
                continue;
            }
            updates.push(RoundUpdate {
                recipient: *recipient,
                observed,
                next: Some(RecipientDelivery::InFlight(crypto_exclusion::next_attempt())),
            });
        }
        // Install every status, `InFlight` included, BEFORE any send task
        // starts: a fast completion can then never be overwritten.
        let (started, reshare_epoch) = {
            let mut inner = runtime.inner.lock().await;
            let Some(stored) = inner.removals.get_mut(&key) else {
                continue;
            };
            let started = crypto_exclusion::apply_round(&mut stored.recipients, updates);
            let reshare_epoch = stored.reshare_epoch.take();
            if crypto_exclusion::all_converged(&stored.recipients) {
                inner.removals.remove(&key);
                inner.dirty = true;
            }
            (started, reshare_epoch)
        };
        crypto_exclusion::ask_heads(state, &key.stable_group_id, head_asks);
        if let Some(epoch) = reshare_epoch {
            // The head is synced and still the result: the survivors get
            // the saved epoch's secret again, once per resume.
            redeliver_secret_shares(state, &info, &active, epoch);
        }
        for (recipient, attempt) in started {
            spawn_send(
                state,
                key.clone(),
                recipient,
                attempt,
                delivery.result_head.clone(),
                Arc::clone(&delivery.event),
            );
        }
    }
}

/// §3 survivor convergence ([`crypto_exclusion::note_survivor_head`]):
/// `sender` reported `reported` as its head, so it converged in each
/// removal delivery of `stable_group_id` whose result is that head.
pub(super) fn note_survivor_head(
    removals: &mut HashMap<EvictionKey, RemovalDelivery>,
    stable_group_id: &str,
    sender: &[u8; 32],
    reported: &str,
) {
    for (key, delivery) in removals.iter_mut() {
        if key.stable_group_id == stable_group_id {
            crypto_exclusion::note_converged(
                &mut delivery.recipients,
                &delivery.result_head,
                sender,
                reported,
            );
        }
    }
}

/// The guarded-egress admission of one saved-removal write to `recipient`
/// (§3 L231): [`crypto_exclusion::guarded_removal_admission`] with
/// [`HeadRule::Current`]. The pre-phase runs under the group's membership
/// lock (ADR 0107 serving check, D60, head rule, no capability gate), and
/// the synchronous seam check runs at once after it, immediately before the
/// caller hands the bytes to the ACK'd send.
///
/// Residual (FOR ENGINEER): ant-quic exposes no receive-ACK send with a
/// stream-seam admission, so the seam check runs before the ACK'd send's
/// own resolution and stream open, not inside it, and that send's internal
/// duplicate-safe retry writes again without a fresh check.
async fn removal_write_admitted(
    state: &Arc<AppState>,
    stable_group_id: &str,
    recipient: &x0x::identity::AgentId,
    result_head: &str,
) -> Result<(), String> {
    let admission = crypto_exclusion::guarded_removal_admission(
        state,
        stable_group_id,
        recipient,
        HeadRule::Current(result_head.to_string()),
    );
    let Some(seam) = admission().await else {
        return Err(x0x::dm::PINNED_ADMISSION_REFUSED.to_string());
    };
    if !seam() {
        return Err(x0x::dm::PINNED_ADMISSION_REFUSED.to_string());
    }
    Ok(())
}

/// ADR 0110 §3 (#1357): whether one chunk of a staged S4 removal blob may
/// be served to `recipient` now: the same guarded admission as the event
/// write. The control-blob fetch handler calls it before each chunk send.
pub(in crate::server) async fn removal_blob_serve_admitted(
    state: &Arc<AppState>,
    guard: &super::super::control_blob::ServeGuard,
    recipient: &x0x::identity::AgentId,
) -> Result<(), String> {
    removal_write_admitted(state, &guard.stable_group_id, recipient, &guard.result_head).await
}

/// Send the saved removal event to `recipient`, guarded (§3 L231) and
/// acknowledged.
///
/// [`removal_write_admitted`] runs first; a refusal is a withhold and
/// sends nothing. The send is then the legacy removal send, unchanged:
/// the same bytes and the same ACK'd direct delivery
/// (`named_group_direct_delivery_config`, with the #1217 cold wait for an
/// owner's removal notice), so `Ok` still means the survivor's daemon
/// acknowledged receipt, and a legacy survivor decodes the event. An event
/// above `MAX_PAYLOAD_BYTES` goes by control-blob reference as before; the
/// blob is staged with a [`ServeGuard`](super::super::control_blob::ServeGuard),
/// so each chunk serve passes the same admission.
async fn send_removal(
    state: &Arc<AppState>,
    stable_group_id: &str,
    recipient: &x0x::identity::AgentId,
    result_head: &str,
    event: &NamedGroupMetadataEvent,
) -> Result<(), String> {
    use super::super::control_blob;
    let payload = serde_json::to_vec(event).map_err(|e| e.to_string())?;
    removal_write_admitted(state, stable_group_id, recipient, result_head).await?;
    // The #1217 opt-in, exactly as the legacy send decides it.
    let cold_removal = matches!(event,
        NamedGroupMetadataEvent::MemberRemoved { actor, agent_id, .. }
            if actor == &hex::encode(state.agent.agent_id().as_bytes()) && actor != agent_id);
    if payload.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return control_blob::send_reference_guarded(
            &state.control_blobs,
            &state.agent,
            recipient,
            control_blob::ControlBlobKind::NamedGroupEvent,
            super::super::named_group_metadata_event_group_id(event),
            None,
            payload,
            cold_removal,
            Some(control_blob::ServeGuard {
                stable_group_id: stable_group_id.to_string(),
                result_head: result_head.to_string(),
            }),
        )
        .await;
    }
    let config = super::super::named_group_direct_delivery_config();
    let sent = if cold_removal {
        state
            .agent
            .send_direct_with_config_cold_wait(
                recipient,
                payload,
                config,
                x0x::dm::PINNED_RESOLUTION_WAIT,
            )
            .await
    } else {
        state
            .agent
            .send_direct_with_config(recipient, payload, config)
            .await
    };
    sent.map(|_| ()).map_err(|e| e.to_string())
}

fn spawn_send(
    state: &Arc<AppState>,
    key: EvictionKey,
    recipient: [u8; 32],
    attempt: u64,
    result_head: String,
    event: Arc<NamedGroupMetadataEvent>,
) {
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let agent = x0x::identity::AgentId(recipient);
        let sent = send_removal(
            &task_state,
            &key.stable_group_id,
            &agent,
            &result_head,
            &event,
        )
        .await;
        let status = match sent {
            Ok(()) => RecipientDelivery::Sent,
            Err(error) => {
                // An admission refusal is a withhold: the next round
                // re-evaluates the recipient from the current state.
                tracing::debug!(%error, "ADR 0110 S4: saved removal send refused or failed; retrying");
                RecipientDelivery::Due
            }
        };
        let mut inner = task_state.revocation_evictions.inner.lock().await;
        if let Some(delivery) = inner.removals.get_mut(&key) {
            crypto_exclusion::finish_attempt(&mut delivery.recipients, &recipient, attempt, status);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as Map;
    use x0x::groups::state_commit::{GroupStateCommit, RetainedCommit};
    use x0x::groups::GroupRole;

    fn commit(prev: &str, hash: &str) -> GroupStateCommit {
        GroupStateCommit {
            group_id: "g".to_string(),
            revision: 4,
            prev_state_hash: Some(prev.to_string()),
            roster_root: String::new(),
            policy_hash: String::new(),
            public_meta_hash: String::new(),
            security_binding: None,
            state_hash: hash.to_string(),
            withdrawn: false,
            committed_by: String::new(),
            committed_at: 0,
            signer_public_key: String::new(),
            signature: String::new(),
        }
    }

    fn info_with_log(head: &str, log: &[(&str, &str)]) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            x0x::identity::AgentId([1; 32]),
            "ab".repeat(16),
        );
        info.state_hash = head.to_string();
        for (prev, hash) in log {
            info.commit_log.push(RetainedCommit {
                commit: commit(prev, hash),
                roster: Map::new(),
                meta: None,
            });
        }
        info
    }

    fn removal_bytes(prev: &str, hash: &str) -> Vec<u8> {
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: "g".to_string(),
            revision: 4,
            actor: "aa".repeat(32),
            agent_id: "bb".repeat(32),
            treekem_commit_b64: Some("Y29tbWl0".to_string()),
            treekem_epoch: Some(3),
            secret_epoch: None,
            commit: Some(commit(prev, hash)),
        };
        serde_json::to_vec(&event).expect("encode")
    }

    #[test]
    fn saved_removal_decodes_its_result_head_and_epoch() {
        let saved = decode_saved_removal(&removal_bytes("p", "r")).expect("decoded");
        assert_eq!(saved.result_head, "r");
        assert_eq!(saved.result_epoch, Some(3));
        assert!(decode_saved_removal(b"X0XCE1\0frame").is_none());
    }

    /// #1508 review P1 #4: an S4 ban saves its `MemberBanned` as the
    /// removal event of its row, so restart can classify and deliver it.
    #[test]
    fn a_saved_ban_decodes_like_a_removal() {
        let event = NamedGroupMetadataEvent::MemberBanned {
            group_id: "g".to_string(),
            revision: 4,
            actor: "aa".repeat(32),
            agent_id: "bb".repeat(32),
            secret_epoch: None,
            treekem_commit_b64: Some("Y29tbWl0".to_string()),
            treekem_epoch: Some(3),
            commit: Some(commit("p", "r")),
        };
        let bytes = serde_json::to_vec(&event).unwrap_or_default();
        let saved = decode_saved_removal(&bytes).expect("a saved ban decodes");
        assert_eq!(saved.result_head, "r");
        assert_eq!(saved.result_epoch, Some(3));
    }

    /// The `s4_restart_intake_prepare` crash: the legacy commit landed and
    /// was persisted, its publication was lost, and the restarted node's
    /// head is the removal's result. The saved event is delivered again,
    /// with no second rekey.
    #[test]
    fn committed_removal_on_the_current_head_is_delivered_again() {
        let info = info_with_log("r", &[("p", "r")]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Deliver);
        assert_eq!(classify(&info, None, "r"), ResumeAction::Deliver);
    }

    #[test]
    fn committed_removal_behind_a_later_head_is_discarded() {
        let info = info_with_log("later", &[("p", "r"), ("r", "later")]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Discard);
    }

    #[test]
    fn removal_on_an_unchanged_parent_is_abandoned() {
        let info = info_with_log("p", &[]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Abandon);
    }

    #[test]
    fn removal_beside_a_competing_child_is_a_fork() {
        let info = info_with_log("other", &[("p", "other")]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Fork);
    }

    #[test]
    fn removal_with_an_unrelated_head_waits_for_head_sync() {
        let info = info_with_log("x", &[]);
        assert_eq!(
            classify(&info, Some("p"), "r"),
            ResumeAction::WaitForHeadSync
        );
        assert_eq!(classify(&info, None, "r"), ResumeAction::WaitForHeadSync);
    }

    #[test]
    fn resume_restores_the_delivery_to_each_survivor() {
        // The creator in `info_with_log` is this node.
        let local = [1; 32];
        let target = [0xbb; 32];
        let survivor = [0xcc; 32];
        let mut info = info_with_log("r", &[("p", "r")]);
        for id in [local, target, survivor] {
            info.add_member(hex::encode(id), GroupRole::Member, None, None);
        }
        info.remove_member(&hex::encode(target), Some(hex::encode(local)));
        let key = EvictionKey::new(info.stable_group_id().to_string(), target);
        let mut store = ObligationStore::new();
        store.intake(
            &key,
            x0x::groups::eviction::EvictionTrigger::AgentRevocation {
                record_hash: [7; 32],
                record_bytes: vec![7],
            },
            None,
            0,
            [0; 16],
        );
        let row = store.get_mut(&key).expect("row");
        row.phase = Phase::CommittedDeliveryPending;
        row.parent_head = Some("p".to_string());
        row.outgoing_event = Some(removal_bytes("p", "r"));
        let mut removals = HashMap::new();
        let mut ce_state = crypto_exclusion::CeState::default();
        let groups = vec![("g".to_string(), info)];
        resume_after_load(&groups, &local, &mut store, &mut removals, &mut ce_state);
        let delivery = removals.get(&key).expect("delivery resumed");
        assert!(delivery.resumed);
        assert_eq!(delivery.result_head, "r");
        assert_eq!(
            delivery.recipients.keys().copied().collect::<Vec<_>>(),
            vec![survivor]
        );
        assert_eq!(
            store.get(&key).expect("row").phase,
            Phase::CommittedDeliveryPending
        );
    }
}

#[cfg(test)]
mod resend_gate_tests {
    use super::*;
    use std::collections::BTreeSet;

    /// #1357 review (Codex P1): a delivery an earlier boot saved is due only
    /// when its own group is head-synced; a live delivery needs only its
    /// resend time.
    #[test]
    fn a_resumed_delivery_needs_its_group_head_synced() {
        let now = Instant::now();
        let key = EvictionKey::new("g".to_string(), [1; 32]);
        let none = BTreeSet::new();
        let other: BTreeSet<String> = ["h".to_string()].into();
        let synced: BTreeSet<String> = ["g".to_string()].into();
        assert!(crypto_exclusion::resend_due(now, false, &none, &key, now));
        assert!(!crypto_exclusion::resend_due(now, true, &none, &key, now));
        assert!(!crypto_exclusion::resend_due(now, true, &other, &key, now));
        assert!(crypto_exclusion::resend_due(now, true, &synced, &key, now));
        let later = now + Duration::from_secs(1);
        assert!(!crypto_exclusion::resend_due(
            later, true, &synced, &key, now
        ));
        assert!(!crypto_exclusion::resend_due(
            later, false, &synced, &key, now
        ));
    }
}

#[cfg(test)]
mod daemon_tests {
    use super::super::super as ng;
    use super::super::{HeadRound, S4Runtime};
    use super::*;
    use anyhow::{Context, Result};
    use x0x::groups::eviction::S4Timing;
    use x0x::identity::AgentId;

    /// A test state whose restart sync wait has already elapsed, so only
    /// the per-group head sync can hold a resend.
    async fn state_past_restart_wait() -> Result<(Arc<AppState>, tempfile::TempDir)> {
        let (mut state, dir) = ng::tests::secure_endpoint_test_state().await?;
        Arc::get_mut(&mut state)
            .context("the fresh test state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        Ok((state, dir))
    }

    /// One group with the local admin and `survivor` as Active members.
    async fn insert_group(state: &AppState, group_id: &str, survivor: &AgentId) -> GroupInfo {
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

    fn removal_event(group_id: &str, target: &[u8; 32]) -> NamedGroupMetadataEvent {
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.to_string(),
            revision: 2,
            actor: String::new(),
            agent_id: hex::encode(target),
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            commit: None,
        }
    }

    /// #1357 review (Codex P1 "elapsed time treated as head
    /// synchronization"): a saved removal that an earlier boot left is not
    /// resent while the group has unresolved higher-head evidence, even
    /// though the restart wait has elapsed. Once the evidence resolves, the
    /// same round resends it.
    #[tokio::test]
    async fn resumed_removal_waits_for_unresolved_higher_head_evidence() -> Result<()> {
        let (state, _dir) = state_past_restart_wait().await?;
        let survivor = AgentId([0x51; 32]);
        let target = [0x52; 32];
        let group_id = "d4".repeat(16);
        let info = insert_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        let key = EvictionKey::new(stable.clone(), target);
        let scheduled = Instant::now();
        {
            let mut inner = state.revocation_evictions.inner.lock().await;
            // The head round for the current head has run its course.
            inner
                .head_rounds
                .insert(stable.clone(), HeadRound::new(&info.state_hash, scheduled));
            inner.removals.insert(
                key.clone(),
                new_delivery(
                    removal_event(&group_id, &target),
                    info.state_hash.clone(),
                    vec![*survivor.as_bytes()],
                    true,
                    scheduled,
                ),
            );
        }
        // Higher-head evidence: epoch-ahead traffic the catch-up still chases.
        state.treekem_epoch_ahead_targets.lock().await.insert(
            group_id.clone(),
            ng::EpochAheadTarget {
                epoch: info.secret_epoch.saturating_add(1),
                observations: 0,
            },
        );

        drive(&state).await;
        {
            let inner = state.revocation_evictions.inner.lock().await;
            let delivery = inner.removals.get(&key).context("delivery kept")?;
            assert_eq!(
                delivery.next_at, scheduled,
                "no resend round while higher-head evidence is unresolved"
            );
            assert_eq!(
                delivery.recipients.get(survivor.as_bytes()),
                Some(&RecipientDelivery::Due),
                "nothing was sent to the survivor"
            );
        }

        // The evidence resolves: the head is synced and the resend runs.
        state.treekem_epoch_ahead_targets.lock().await.clear();
        drive(&state).await;
        let inner = state.revocation_evictions.inner.lock().await;
        let delivery = inner.removals.get(&key).context("delivery kept")?;
        assert!(
            delivery.next_at > scheduled,
            "the synced group's resend round ran"
        );
        assert_ne!(
            delivery.recipients.get(survivor.as_bytes()),
            Some(&RecipientDelivery::Due),
            "the survivor's send started"
        );
        Ok(())
    }

    async fn admit(
        state: &Arc<AppState>,
        stable: &str,
        recipient: &AgentId,
        rule: &HeadRule,
    ) -> Option<x0x::dm::SeamAdmission> {
        crypto_exclusion::guarded_removal_admission(state, stable, recipient, rule.clone())().await
    }

    /// #1357 review: the saved removal goes through guarded egress. A
    /// legacy survivor with no capability bit is admitted (it must still get
    /// the `MemberRemoved` it decodes). A survivor that becomes removed,
    /// banned, quarantined, sees the head move, or whose machine is revoked
    /// is refused at the write seam after a passing pre-phase, and by a
    /// fresh pre-phase.
    #[tokio::test]
    async fn removal_delivery_refuses_an_ineligible_recipient() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let survivor = AgentId([0x61; 32]);
        let survivor_hex = hex::encode(survivor.as_bytes());
        let group_id = "d5".repeat(16);
        let info = insert_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        let rule = HeadRule::Current(info.state_hash.clone());
        // A legacy advert: a verified machine binding and a known registry
        // with none of the S4 bits. `v1_gossip_ready` advertises this
        // build's `CapabilityRegistry::current()`, which sets them, so the
        // registry is replaced (#1357 CI 972ede0).
        let machine = x0x::identity::MachineKeypair::generate()?;
        let mut legacy = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        legacy.application_registry = x0x::dm::CapabilityRegistry {
            version: x0x::dm::CapabilityRegistry::current().version,
            bits: 0,
        };
        assert!(
            state.agent.capability_store().insert(
                survivor,
                machine.machine_id(),
                legacy,
                x0x::dm_capability::now_unix_ms(),
            ),
            "verified legacy advert"
        );
        assert_eq!(
            state.agent.capability_store().verified_registry_supports(
                &survivor,
                x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1
            ),
            Some(false),
            "the survivor is legacy"
        );

        let seam = admit(&state, &stable, &survivor, &rule).await;
        assert!(
            seam.is_some_and(|seam| seam()),
            "an eligible legacy survivor is admitted"
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
            let seam = admit(&state, &stable, &survivor, &rule)
                .await
                .with_context(|| format!("{label}: the pre-phase must admit first"))?;
            {
                let mut groups = state.named_groups.write().await;
                let stored = groups.get_mut(&group_id).context("group")?;
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

        // D60: the survivor's machine is revoked after the pre-phase.
        let seam = admit(&state, &stable, &survivor, &rule)
            .await
            .context("machine: the pre-phase must admit first")?;
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Machine(machine.machine_id()),
            machine.public_key(),
            machine.secret_key(),
            x0x::groups::owner_cert::restore_clock_now(),
            Some("s4 removal delivery test".to_string()),
        )?;
        state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)?;
        assert!(!seam(), "machine revoked: the seam must refuse the write");
        assert!(
            admit(&state, &stable, &survivor, &rule).await.is_none(),
            "machine revoked: a fresh pre-phase must refuse"
        );
        Ok(())
    }

    /// #1357 review: the ACK'd saved-removal send and the serve of a chunk
    /// of its blob both pass the guarded admission first. For a banned
    /// survivor both are refused before anything is sent.
    #[tokio::test]
    async fn saved_removal_send_and_blob_serve_refuse_an_ineligible_recipient() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let survivor = AgentId([0x71; 32]);
        let survivor_hex = hex::encode(survivor.as_bytes());
        let target = [0x72; 32];
        let group_id = "d6".repeat(16);
        let info = insert_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        let guard = super::super::super::control_blob::ServeGuard {
            stable_group_id: stable.clone(),
            result_head: info.state_hash.clone(),
        };
        assert_eq!(
            removal_blob_serve_admitted(&state, &guard, &survivor).await,
            Ok(()),
            "an eligible survivor's chunk is served"
        );
        state
            .named_groups
            .write()
            .await
            .get_mut(&group_id)
            .context("group")?
            .ban_member(&survivor_hex, None);
        assert_eq!(
            removal_blob_serve_admitted(&state, &guard, &survivor).await,
            Err(x0x::dm::PINNED_ADMISSION_REFUSED.to_string()),
            "a banned survivor's chunk is withheld"
        );
        let sent = send_removal(
            &state,
            &stable,
            &survivor,
            &info.state_hash,
            &removal_event(&group_id, &target),
        )
        .await;
        assert_eq!(
            sent,
            Err(x0x::dm::PINNED_ADMISSION_REFUSED.to_string()),
            "the send is refused at admission, before any write"
        );
        Ok(())
    }
}
