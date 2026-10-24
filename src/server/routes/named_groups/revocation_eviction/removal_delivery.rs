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
/// The bound of one saved-removal exchange (the guarded egress point caps
/// it further).
const REMOVAL_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
/// The kind of a saved-removal event write at the guarded egress point.
const REMOVAL_EVENT_EGRESS: &str = "s4_removal";
/// The kind of the bounded reference write of an oversized saved removal.
const REMOVAL_REFERENCE_EGRESS: &str = "s4_removal_reference";

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
    /// A GSS removal or ban: the rotated secret epoch whose share each
    /// resend round seals again to every survivor it writes to, until that
    /// survivor converges (#1573). A survivor holds the removal head until
    /// its share installs, so a lost share is sent again.
    gss_epoch: Option<u64>,
    /// The next round seals the share too. A live delivery's first round
    /// does not: the route published the shares with the event.
    share_due: bool,
}

#[cfg(test)]
impl RemovalDelivery {
    /// The rotated secret epoch whose shares the first round sends again.
    pub(super) fn reshare_epoch_for_test(&self) -> Option<u64> {
        self.gss_epoch.filter(|_| self.share_due)
    }
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
    let gss_epoch = gss_secret_epoch(&event);
    RemovalDelivery {
        event: Arc::new(event),
        result_head,
        resumed,
        recipients: recipients
            .into_iter()
            .map(|id| (id, RecipientDelivery::Due))
            .collect(),
        next_at,
        gss_epoch,
        share_due: resumed,
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
///
/// `reshare` is set when the route stopped before its own publication (the
/// roster is live but not directory-durable): the first delivery round then
/// also seals a GSS removal's rotated secret to each survivor, as after a
/// restart (#1508 review P1).
pub(in crate::server) async fn record_committed_removal(
    state: &AppState,
    info: &GroupInfo,
    target_hex: &str,
    event: &NamedGroupMetadataEvent,
    reshare: bool,
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
        let mut delivery = new_delivery(
            saved.event,
            saved.result_head,
            survivors(info, &local, &target),
            false,
            Instant::now() + REMOVAL_FIRST_SEND_DELAY,
        );
        delivery.share_due = reshare;
        inner.removals.insert(key, delivery);
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
    /// An epoch change followed the result: discard the delivery; the next
    /// pass completes the row from the chain.
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
///
/// A later commit with no epoch change (a rename) leaves the removal on
/// the chain at the current epoch: the saved event is delivered again,
/// because after a restart it is the only source of a survivor's
/// transition (#1508 rc12). Only a later epoch change discards it.
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
        SavedFrameState::Superseded if delivery_retained(info, result_head) => {
            ResumeAction::Deliver
        }
        SavedFrameState::Superseded => ResumeAction::Discard,
        SavedFrameState::Abandoned => ResumeAction::Abandon,
        SavedFrameState::Fork => ResumeAction::Fork,
        SavedFrameState::Unknown => ResumeAction::WaitForHeadSync,
    }
}

/// §3: the one rule that keeps a saved removal's delivery and admits its
/// writes. The removal stays on the verified chain at the current epoch
/// ([`HeadRule::OnChainAtEpoch`]).
fn delivery_rule(result_head: &str) -> HeadRule {
    HeadRule::OnChainAtEpoch(result_head.to_string())
}

fn delivery_retained(info: &GroupInfo, result_head: &str) -> bool {
    crypto_exclusion::head_rule_admits(info, &delivery_rule(result_head))
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
                let delivery = new_delivery(
                    saved.event,
                    saved.result_head,
                    survivors(info, local, &key.target),
                    true,
                    Instant::now(),
                );
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
        if !delivery_retained(&info, &delivery.result_head) {
            // The removal left the chain, or an epoch change followed it:
            // never resend old crypto material. A later epoch-less commit
            // keeps the delivery (#1508 rc12).
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
            let reshare_epoch = stored.gss_epoch.filter(|_| stored.share_due);
            // #1573: every later round seals the share again.
            stored.share_due = true;
            if crypto_exclusion::all_converged(&stored.recipients) {
                inner.removals.remove(&key);
                inner.dirty = true;
            }
            (started, reshare_epoch)
        };
        crypto_exclusion::ask_heads(state, &key.stable_group_id, head_asks);
        if let Some(epoch) = reshare_epoch {
            // The removal is still on the chain at its epoch: each survivor
            // written to this round gets the epoch's secret again (#1573).
            let written: std::collections::BTreeSet<[u8; 32]> =
                started.iter().map(|(recipient, _)| *recipient).collect();
            redeliver_secret_shares(state, &info, &written, epoch);
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
/// `sender` holds each head in `installed`, so it converged in each
/// removal delivery of `stable_group_id` whose result is one of them.
pub(super) fn note_survivor_head(
    removals: &mut HashMap<EvictionKey, RemovalDelivery>,
    stable_group_id: &str,
    sender: &[u8; 32],
    installed: &std::collections::BTreeSet<String>,
) {
    for (key, delivery) in removals.iter_mut() {
        if key.stable_group_id == stable_group_id {
            crypto_exclusion::note_converged(
                &mut delivery.recipients,
                &delivery.result_head,
                sender,
                installed,
            );
        }
    }
}

/// The guarded admission of one serve to `recipient` (§3 L231):
/// [`crypto_exclusion::guarded_removal_admission`] with
/// [`delivery_rule`]. The pre-phase runs under the group's membership
/// lock (ADR 0107 serving check, D60, head rule, no capability gate), and
/// the synchronous seam check runs at once after it.
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
        delivery_rule(result_head),
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

/// Send the saved removal event to `recipient` in one guarded exchange
/// (§3 L231, #1508 r7 F2).
///
/// Every physical write goes through the one guarded egress point
/// ([`super::super::send_join_artifact`]): x0x's pinned single-exchange
/// send. Its pre-phase runs [`crypto_exclusion::guarded_removal_admission`]
/// under the group's membership lock after route resolution, and its seam
/// check runs again immediately before `write_all`. It never uses the
/// gossip inbox, never waits for an ACK-v2 receipt (whose internal retry
/// writes again without a fresh check) and never retries: "each new
/// exchange re-admits". The S4 round owns every resend, and a write is
/// not delivery; the survivor's convergence is
/// ([`crypto_exclusion::note_survivor_head`]). The bounded resolution of
/// that send waits for a cold survivor's verified binding, as the #1217
/// cold wait did.
///
/// The bytes are the legacy removal event, unchanged, on the direct
/// carrier that every member decodes. An event above `MAX_PAYLOAD_BYTES`
/// goes by control-blob reference: the blob is staged with a
/// [`ServeGuard`](super::super::control_blob::ServeGuard), so each chunk
/// serve passes the same admission, and the reference is one guarded
/// exchange too.
async fn send_removal(
    state: &Arc<AppState>,
    stable_group_id: &str,
    recipient: &x0x::identity::AgentId,
    result_head: &str,
    event: &NamedGroupMetadataEvent,
) -> Result<(), String> {
    use super::super::control_blob;
    let payload = serde_json::to_vec(event).map_err(|e| e.to_string())?;
    let admission = crypto_exclusion::guarded_removal_admission(
        state,
        stable_group_id,
        recipient,
        delivery_rule(result_head),
    );
    let deadline = std::time::Instant::now() + REMOVAL_EXCHANGE_TIMEOUT;
    if payload.len() <= x0x::dm::MAX_PAYLOAD_BYTES {
        let sent = super::super::send_join_artifact(
            state,
            recipient,
            &payload,
            stable_group_id,
            REMOVAL_EVENT_EGRESS,
            admission,
            deadline,
        )
        .await;
        return plain_refusal(sent);
    }
    // Stage nothing for a recipient that is not eligible now.
    removal_write_admitted(state, stable_group_id, recipient, result_head).await?;
    let reference = control_blob::stage_reference_entry(
        &state.control_blobs,
        &state.agent,
        recipient,
        control_blob::ControlBlobKind::NamedGroupEvent,
        super::super::named_group_metadata_event_group_id(event),
        None,
        payload,
        None,
        Some(control_blob::ServeGuard {
            stable_group_id: stable_group_id.to_string(),
            result_head: result_head.to_string(),
        }),
    )
    .map_err(str::to_string)?;
    let message =
        control_blob::encode_message(&control_blob::ControlBlobMessage::Reference { reference })?;
    let sent = super::super::send_join_artifact(
        state,
        recipient,
        &message,
        stable_group_id,
        REMOVAL_REFERENCE_EGRESS,
        admission,
        deadline,
    )
    .await;
    plain_refusal(sent)
}

/// An admission refusal at either phase of the guarded exchange is
/// reported as [`x0x::dm::PINNED_ADMISSION_REFUSED`] itself, as
/// [`removal_write_admitted`] reports it: a withhold, not a transport
/// failure.
fn plain_refusal(sent: Result<(), String>) -> Result<(), String> {
    sent.map_err(|error| {
        if error.contains(x0x::dm::PINNED_ADMISSION_REFUSED) {
            x0x::dm::PINNED_ADMISSION_REFUSED.to_string()
        } else {
            error
        }
    })
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
            // The in-process stand-in reports an admitted exchange with its
            // marker error (test builds only), as for the class-K shares.
            #[cfg(test)]
            Err(error) if error.contains(x0x::dm::PINNED_STANDIN_ADMITTED) => {
                RecipientDelivery::Sent
            }
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

    pub(super) fn commit(prev: &str, hash: &str) -> GroupStateCommit {
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

    /// `info` with each retained commit bound to its entry of `bindings`
    /// and the head bound to `head_binding` (the epoch each commits to).
    fn bound(mut info: GroupInfo, head_binding: &str, bindings: &[&str]) -> GroupInfo {
        for (retained, binding) in info.commit_log.iter_mut().zip(bindings) {
            retained.commit.security_binding = Some((*binding).to_string());
        }
        info.security_binding = Some(head_binding.to_string());
        info
    }

    /// A later commit changed the epoch: the removal's crypto material is
    /// old, so the saved event is never sent again.
    #[test]
    fn committed_removal_behind_a_later_epoch_is_discarded() {
        let info = bound(
            info_with_log("later", &[("p", "r"), ("r", "later")]),
            "treekem:epoch=4",
            &["treekem:epoch=3", "treekem:epoch=4"],
        );
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Discard);
    }

    /// Codex P1 (#1508 rc12, ADR 0110 §3): a later roster commit with no
    /// epoch change (a rename) moved the head past the removal. The
    /// removal is still on the chain at the current epoch, and after a
    /// restart the catch-up log is empty, so the saved event is the only
    /// source of a survivor's transition: it is delivered again. Before
    /// the fix it was discarded.
    #[test]
    fn a_removal_behind_an_epochless_later_commit_is_delivered_again() {
        let info = bound(
            info_with_log("renamed", &[("p", "r"), ("r", "renamed")]),
            "treekem:epoch=3",
            &["treekem:epoch=3", "treekem:epoch=3"],
        );
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Deliver);
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
        resume_restores_the_delivery(info_with_log("r", &[("p", "r")]));
    }

    /// Codex P1 (#1508 rc12): the restart after a later epoch-less commit
    /// (a rename) restores the saved removal's delivery; the restart after
    /// an epoch change drops the saved event and keeps the row open for
    /// the chain to complete.
    #[test]
    fn resume_after_a_later_commit_keeps_the_delivery_only_at_the_same_epoch() {
        let log = [("p", "r"), ("r", "renamed")];
        resume_restores_the_delivery(bound(
            info_with_log("renamed", &log),
            "treekem:epoch=3",
            &["treekem:epoch=3", "treekem:epoch=3"],
        ));
        let (removals, store, key) = resume_one(bound(
            info_with_log("renamed", &log),
            "treekem:epoch=4",
            &["treekem:epoch=3", "treekem:epoch=4"],
        ));
        assert!(removals.is_empty(), "no delivery after an epoch change");
        let row = store.get(&key).expect("row");
        assert_eq!(row.phase, Phase::CommittedDeliveryPending);
        assert!(row.outgoing_event.is_none(), "the old event is dropped");
    }

    fn resume_restores_the_delivery(info: GroupInfo) {
        let survivor = [0xcc; 32];
        let (removals, store, key) = resume_one(info);
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

    /// Restart over `info` with one open row whose saved removal of
    /// `0xbb` went from head `p` to `r`.
    fn resume_one(
        mut info: GroupInfo,
    ) -> (
        HashMap<EvictionKey, RemovalDelivery>,
        ObligationStore,
        EvictionKey,
    ) {
        // The creator in `info_with_log` is this node.
        let local = [1; 32];
        let target = [0xbb; 32];
        let survivor = [0xcc; 32];
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
        (removals, store, key)
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

    /// Codex P1 (#1508 rc12, ADR 0110 §3): a live removal delivery whose
    /// result a later epoch-less roster commit (a rename) moved behind the
    /// head keeps running, and its write is admitted: the removal is still
    /// on the chain at the current epoch. After an epoch change the
    /// delivery stops and no write is admitted. Before the fix the rename
    /// ended the delivery, so a survivor that missed the removal lost its
    /// transition.
    #[tokio::test]
    async fn a_removal_delivery_survives_a_later_commit_only_at_the_same_epoch() -> Result<()> {
        let (state, _dir) = state_past_restart_wait().await?;
        let survivor = AgentId([0x53; 32]);
        let target = [0x54; 32];
        let group_id = "d6".repeat(16);
        let mut info = insert_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        let key = EvictionKey::new(stable.clone(), target);
        // The removal's result is the current head at epoch binding "e3";
        // then a rename commits on top with the same binding.
        let result_head = info.state_hash.clone();
        info.security_binding = Some("treekem:epoch=3".to_string());
        let mut removal = super::tests::commit("p", &result_head);
        removal.security_binding = info.security_binding.clone();
        let mut rename = super::tests::commit(&result_head, "renamed");
        rename.security_binding = info.security_binding.clone();
        for commit in [removal, rename] {
            info.commit_log
                .push(x0x::groups::state_commit::RetainedCommit {
                    commit,
                    roster: std::collections::BTreeMap::new(),
                    meta: None,
                });
        }
        info.state_hash = "renamed".to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        let scheduled = Instant::now();
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .removals
            .insert(
                key.clone(),
                new_delivery(
                    removal_event(&group_id, &target),
                    result_head.clone(),
                    vec![*survivor.as_bytes()],
                    false,
                    scheduled,
                ),
            );

        drive(&state).await;
        {
            let inner = state.revocation_evictions.inner.lock().await;
            let delivery = inner
                .removals
                .get(&key)
                .context("an epoch-less later commit keeps the delivery")?;
            assert_ne!(
                delivery.recipients.get(survivor.as_bytes()),
                Some(&RecipientDelivery::Due),
                "the survivor's send started"
            );
        }
        let rule = HeadRule::OnChainAtEpoch(result_head.clone());
        assert!(
            admit(&state, &stable, &survivor, &rule)
                .await
                .is_some_and(|seam| seam()),
            "the saved removal's write is admitted after the rename"
        );

        // An epoch change: the delivery stops and nothing is admitted.
        info.security_binding = Some("treekem:epoch=4".to_string());
        info.state_hash = "rekeyed".to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
        assert!(
            admit(&state, &stable, &survivor, &rule).await.is_none(),
            "no write after an epoch change"
        );
        if let Some(delivery) = state
            .revocation_evictions
            .inner
            .lock()
            .await
            .removals
            .get_mut(&key)
        {
            delivery.next_at = Instant::now();
            delivery
                .recipients
                .insert(*survivor.as_bytes(), RecipientDelivery::Due);
        }
        drive(&state).await;
        assert!(
            !state
                .revocation_evictions
                .inner
                .lock()
                .await
                .removals
                .contains_key(&key),
            "an epoch change ends the delivery"
        );
        Ok(())
    }

    /// The shares `state` scheduled to `recipient_hex`.
    fn shares_to(state: &AppState, recipient_hex: &str) -> usize {
        state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
            .map(|scheduled| {
                scheduled
                    .iter()
                    .filter(|(_, recipient, _)| recipient == recipient_hex)
                    .count()
            })
            .unwrap_or_default()
    }

    /// #1573 (#1508 rc12), committer side: a GSS removal's delivery seals
    /// the survivor's share again on every resend round until that
    /// survivor converges. A live delivery's first round sends none (the
    /// route published it with the event); a resumed one sends it at once.
    /// Before the fix a live delivery never sent the share again and a
    /// resumed one sent it once, so a lost share was never replaced.
    #[tokio::test]
    async fn a_gss_removal_reseals_the_share_each_round_until_convergence() -> Result<()> {
        use base64::Engine as _;
        for resumed in [false, true] {
            let (state, _dir) = state_past_restart_wait().await?;
            let survivor = AgentId([0x55; 32]);
            let survivor_hex = hex::encode(survivor.as_bytes());
            let target = [0x56; 32];
            let group_id = "d7".repeat(16);
            let mut info = insert_group(&state, &group_id, &survivor).await;
            let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
            let member = info
                .members_v2
                .get_mut(&survivor_hex)
                .context("survivor seat")?;
            member.kem_public_key_b64 =
                Some(base64::engine::general_purpose::STANDARD.encode(&kem.public_bytes));
            info.secret_epoch = 5;
            info.shared_secret = Some(vec![5; 32]);
            state
                .named_groups
                .write()
                .await
                .insert(group_id.clone(), info.clone());
            let stable = info.stable_group_id().to_string();
            let key = EvictionKey::new(stable.clone(), target);
            let mut event = removal_event(&group_id, &target);
            if let NamedGroupMetadataEvent::MemberRemoved { secret_epoch, .. } = &mut event {
                *secret_epoch = Some(5);
            }
            {
                let mut inner = state.revocation_evictions.inner.lock().await;
                inner.head_rounds.insert(
                    stable.clone(),
                    HeadRound::new(&info.state_hash, Instant::now()),
                );
                inner.removals.insert(
                    key.clone(),
                    new_delivery(
                        event,
                        info.state_hash.clone(),
                        vec![*survivor.as_bytes()],
                        resumed,
                        Instant::now(),
                    ),
                );
            }
            // One resend round: the survivor's write is not converged.
            let round = || async {
                if let Some(delivery) = state
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .removals
                    .get_mut(&key)
                {
                    delivery.next_at = Instant::now();
                    delivery
                        .recipients
                        .insert(*survivor.as_bytes(), RecipientDelivery::Sent);
                }
                drive(&state).await;
            };
            let first = usize::from(resumed);
            round().await;
            assert_eq!(shares_to(&state, &survivor_hex), first, "resumed={resumed}");
            round().await;
            assert_eq!(
                shares_to(&state, &survivor_hex),
                first + 1,
                "resumed={resumed}"
            );
            round().await;
            assert_eq!(
                shares_to(&state, &survivor_hex),
                first + 2,
                "resumed={resumed}"
            );
            // The survivor converges: the delivery ends and no share follows.
            {
                let mut inner = state.revocation_evictions.inner.lock().await;
                let installed: std::collections::BTreeSet<String> =
                    [info.state_hash.clone()].into_iter().collect();
                note_survivor_head(
                    &mut inner.removals,
                    &stable,
                    survivor.as_bytes(),
                    &installed,
                );
                if let Some(delivery) = inner.removals.get_mut(&key) {
                    delivery.next_at = Instant::now();
                }
            }
            drive(&state).await;
            assert!(
                !state
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .removals
                    .contains_key(&key),
                "convergence ends the delivery"
            );
            round().await;
            assert_eq!(
                shares_to(&state, &survivor_hex),
                first + 2,
                "resumed={resumed}"
            );
        }
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

    /// #1357 review: the saved-removal send and the serve of a chunk
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
    /// #1508 r7 F2 (Codex P1), ADR 0110 §3: every physical write of a
    /// saved removal is admitted immediately before it, under the
    /// membership lock: "each new exchange re-admits", with no hidden
    /// transport resend. The real send function goes through the one
    /// guarded single-exchange egress point. An eligible survivor's write
    /// is admitted at the write. A write held after it was scheduled, with
    /// the survivor banned before the bytes leave, is refused at that
    /// write: an admission taken before route resolution and an ACK'd
    /// transport with its own retries does not stand for it.
    #[tokio::test]
    async fn each_saved_removal_write_is_admitted_at_the_write() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let survivor = AgentId([0x81; 32]);
        let survivor_hex = hex::encode(survivor.as_bytes());
        let target = [0x82; 32];
        let group_id = "d7".repeat(16);
        let info = insert_group(&state, &group_id, &survivor).await;
        let stable = info.stable_group_id().to_string();
        let event = removal_event(&group_id, &target);

        let sent = send_removal(&state, &stable, &survivor, &info.state_hash, &event).await;
        assert!(
            sent.as_ref()
                .is_err_and(|reason| reason.contains(x0x::dm::PINNED_STANDIN_ADMITTED)),
            "an eligible survivor's write is admitted at the guarded single exchange: {sent:?}"
        );

        // The next write is held after it was scheduled; the survivor is
        // banned before its bytes leave.
        let armed = ng::join_egress_test_barrier::arm(&survivor_hex, "s4_removal");
        let task = {
            let state = Arc::clone(&state);
            let stable = stable.clone();
            let head = info.state_hash.clone();
            let event = event.clone();
            tokio::spawn(
                async move { send_removal(&state, &stable, &survivor, &head, &event).await },
            )
        };
        for _ in 0..200 {
            if armed.gate.reached() || task.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let held = armed.gate.reached();
        state
            .named_groups
            .write()
            .await
            .get_mut(&group_id)
            .context("group")?
            .ban_member(&survivor_hex, None);
        drop(armed);
        let sent = task.await?;
        assert!(held, "the write goes through the guarded egress point");
        assert_eq!(
            sent,
            Err(x0x::dm::PINNED_ADMISSION_REFUSED.to_string()),
            "the write after the ban is refused at that write"
        );
        Ok(())
    }
}
