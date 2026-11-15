//! Issue #1840 (ask 4): the typed outcome of a refused join request.
//!
//! Authority side ([`send_join_request_refusal`]): after validation refused
//! a requester's `JoinRequestCreated` offer and the admission journal was
//! released durably, the authority sends one small typed DM
//! ([`crate::groups::join_outcome::JoinRequestOutcome`]) back to the agent
//! that offered the envelope. The send is best effort and bounded:
//!
//! - only to the authenticated DM sender of the offer, which is also the
//!   signer of the envelope, so the authority cannot be pointed at a third
//!   party, and the reply is smaller than the offer;
//! - only when that agent's current verified capability advert sets
//!   `join_request_outcome_v1` (an older requester would show the payload
//!   as an ordinary DM);
//! - at most once per envelope digest in [`OUTCOME_RESEND_MIN_MS`], with a
//!   memory of recent digests that is capped per requester and in total.
//!   At a cap, no outcome is sent and the requester keeps its old
//!   behaviour (it offers again on its schedule).
//!
//! The outcome goes out as a plain (v1) DM with no application ACK. If the
//! requester cannot store it, the authority is not told; the requester's
//! next offer of that envelope gets a new outcome after the interval.
//!
//! Requester side ([`handle_join_request_outcome_typed_payload`]): the
//! outcome is accepted only when all of these hold, else it is ignored:
//!
//! 1. the DM envelope verified its sender;
//! 2. this daemon holds an offer obligation for `(group_id, request_id)`
//!    that it filed itself;
//! 3. the sender is the authority that obligation was offered to;
//! 4. `envelope_digest` is the digest of the offered envelope;
//! 5. the local request is still pending.
//!
//! An accepted outcome is stored on the obligation
//! (`RequesterOfferObligation::refusal`). The offer worker then stops
//! offering that envelope, and `GET /groups/:id` shows the refusal in
//! `own_join_request`. The local roster is not changed.

use std::sync::Arc;

use crate::dm_inbox::{DmTypedPayload, DmTypedPayloadCompletion, DmTypedPayloadCompletionResult};
use crate::groups::join_outcome::{JoinHeadError, JoinRequestOutcome, JoinRequestRefusalReason};
use crate::groups::state_commit::RetainedCommit;

use super::join_sequence::JoinTurn;

use super::requester_offer::{
    find_requester_offer, mark_requester_offer_refused, offer_still_live, RequesterOfferRefusal,
};
use super::{named_group_direct_delivery_config, now_millis_u64};
use crate::identity::AgentId;
use crate::server::state::AppState;

/// One outcome per refused envelope digest in this interval. The
/// requester's offer schedule starts at 0, 1, 2, 4 … seconds, so this stops
/// an outcome per early re-offer and still repeats a lost one.
pub(in crate::server) const OUTCOME_RESEND_MIN_MS: u64 = 30_000;
/// Cap on remembered digests, in total.
pub(in crate::server) const OUTCOME_SEND_MEMORY_CAP: usize = 256;
/// Cap on remembered digests per requester: one agent with many
/// self-signed envelopes gets this many outcomes per interval and cannot
/// fill the total memory for other requesters.
pub(in crate::server) const OUTCOME_SEND_PER_REQUESTER_CAP: usize = 8;

/// Authority side: send the refusal of one offered envelope to its
/// requester, subject to the capability gate and the per-digest limit.
/// The send runs in a detached task.
///
/// Issue #1840 routes 1–3 (A08 amendment of 15 Nov 2026), for a `stale`
/// refusal of a requester that advertises `join_request_head_v1`:
/// - the requester holds the group's turn (`turn`, from the join queue):
///   the outcome carries the authority's current head
///   ([`current_join_head`]), so the requester can sign the same request
///   again over it. A head that does not fit the bound is left off;
/// - the requester waits behind another turn: no outcome. It keeps its
///   offer and offers again on its schedule; an offer after the queue
///   moves can give it the turn. A refusal now would stop its offers;
/// - the requester is not queued (the queue is full): the outcome without
///   a head, as for every other requester.
pub(in crate::server) async fn send_join_request_refusal(
    state: &Arc<AppState>,
    group_id: &str,
    request_id: &str,
    requester: AgentId,
    envelope_digest: [u8; 32],
    reason: JoinRequestRefusalReason,
    turn: Option<&JoinTurn>,
) {
    let capabilities = state.agent.capability_store();
    let supports = |bit| capabilities.verified_registry_supports(&requester, bit) == Some(true);
    if !supports(crate::dm::CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1) {
        return;
    }
    let mut head = None;
    if reason == JoinRequestRefusalReason::Stale
        && supports(crate::dm::CapabilityRegistry::JOIN_REQUEST_HEAD_V1)
    {
        let requester_hex = hex::encode(requester.as_bytes());
        let holds_turn = turn.is_some_and(|t| {
            t.request.requester_agent_id == requester_hex && t.request.request_id == request_id
        });
        if holds_turn {
            head = current_join_head(state, group_id).await;
        } else if state
            .join_sequencer
            .lock()
            .await
            .position(group_id, &requester_hex)
            .is_some()
        {
            return;
        }
    }
    let mut outcome = JoinRequestOutcome {
        group_id: group_id.to_string(),
        request_id: request_id.to_string(),
        envelope_digest: hex::encode(envelope_digest),
        reason,
        head,
    };
    let payload = match outcome.encode() {
        Ok(payload) => payload,
        Err(_) if outcome.head.is_some() => {
            outcome.head = None;
            let Ok(payload) = outcome.encode() else {
                return;
            };
            payload
        }
        Err(_) => return,
    };
    let now_ms = now_millis_u64();
    {
        let mut sent = state
            .join_request_outcome_sends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sent.retain(|_, (at, _)| now_ms.saturating_sub(*at) < OUTCOME_RESEND_MIN_MS);
        if sent.contains_key(&envelope_digest)
            || sent.len() >= OUTCOME_SEND_MEMORY_CAP
            || sent.values().filter(|(_, to)| *to == requester).count()
                >= OUTCOME_SEND_PER_REQUESTER_CAP
        {
            return;
        }
        sent.insert(envelope_digest, (now_ms, requester));
    }
    #[cfg(test)]
    test_seam::record(state, requester, payload.clone());
    let agent = Arc::clone(&state.agent);
    let group = group_id.to_string();
    state.spawn_detached(async move {
        let mut config = named_group_direct_delivery_config();
        config.require_gossip = true;
        config.max_retries = 0;
        if let Err(error) = agent
            .send_direct_with_config(&requester, payload, config)
            .await
        {
            tracing::debug!(
                group_id = %crate::logging::LogHexId::group(&group),
                %error,
                "#1840: join-request outcome was not delivered (best effort)"
            );
        }
    });
}

/// The authority's current head on `group_key`, as a join-request outcome
/// carries it: the newest retained link when it is the head (its
/// `state_hash` is the record's and it carries its metadata), with the
/// certificate bytes stripped from the roster. `None` when there is no
/// such link.
pub(in crate::server) async fn current_join_head(
    state: &AppState,
    group_key: &str,
) -> Option<RetainedCommit> {
    let groups = state.named_groups.read().await;
    let info = groups.get(group_key)?;
    let mut head = info
        .commit_log
        .last()
        .filter(|link| link.commit.state_hash == info.state_hash && link.meta.is_some())?
        .clone();
    for snap in head.roster.values_mut() {
        snap.certificate = None;
    }
    Some(head)
}

/// Requester side: apply one join-request outcome DM. Every path resolves
/// the durable-route completion; an ignored outcome is `Duplicate` (the
/// sender has nothing to retry).
pub(in crate::server) async fn handle_join_request_outcome_typed_payload(
    state: &AppState,
    typed: &DmTypedPayload,
) -> DmTypedPayloadCompletionResult {
    const IGNORED: DmTypedPayloadCompletionResult = Ok(DmTypedPayloadCompletion::Duplicate);
    if !typed.verified {
        return IGNORED;
    }
    let Some(outcome) = JoinRequestOutcome::decode(&typed.payload) else {
        return IGNORED;
    };
    let sender_hex = hex::encode(typed.sender.as_bytes());
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let accept = |o: &super::RequesterOfferObligation| {
        o.refusal.is_none()
            && o.requester_agent_id == local_hex
            && o.authority_agent_id == sender_hex
            && hex::encode(o.digest) == outcome.envelope_digest
    };
    let Some(obligation) =
        find_requester_offer(state, &outcome.group_id, &outcome.request_id).await
    else {
        return IGNORED;
    };
    if !accept(&obligation) || !offer_still_live(state, &obligation).await {
        tracing::debug!(
            sender = %crate::logging::LogHexId::agent(&sender_hex),
            "#1840: join-request outcome does not match a pending offer of this daemon; ignored"
        );
        return IGNORED;
    }
    // #1840 routes 1–3: the authority's head lets this daemon sign the same
    // request again over the authority's state. Only a head that fails a
    // check, or a seal that fails, falls through to the refusal.
    let head = match outcome.head.as_ref() {
        Some(_) if obligation.reseal_count >= super::requester_offer::JOIN_REQUEST_RESEAL_CAP => {
            tracing::warn!(
                group_id = %crate::logging::LogHexId::group(&outcome.group_id),
                request_id = %outcome.request_id,
                reseals = obligation.reseal_count,
                "#1840: the join request was signed again too many times; recording the refusal"
            );
            None
        }
        other => other,
    };
    if let Some(head) = head {
        match reseal_join_request_over_head(state, &obligation, head).await {
            Ok(()) => {
                tracing::info!(
                    group_id = %crate::logging::LogHexId::group(&outcome.group_id),
                    request_id = %outcome.request_id,
                    head_revision = head.commit.revision,
                    "#1840: signed the join request again over the authority's head"
                );
                return Ok(DmTypedPayloadCompletion::Inserted);
            }
            // A head that is not ahead of this copy is a late or duplicate
            // outcome: this daemon already holds a newer state. Nothing to
            // record; the offer stays live.
            Err(ResealError::Head(JoinHeadError::NotAhead)) => return IGNORED,
            // A local failure is not the authority's verdict. The offer
            // stays live: its next offer is refused again and brings the
            // head again, so a temporary failure does not end the join.
            Err(ResealError::Local(error)) => {
                tracing::warn!(
                    group_id = %crate::logging::LogHexId::group(&outcome.group_id),
                    request_id = %outcome.request_id,
                    %error,
                    "#1840: could not sign the join request again over the head; the offer stays live"
                );
                return IGNORED;
            }
            // Only a head that fails a check becomes the stale refusal.
            Err(ResealError::Head(error)) => {
                tracing::warn!(
                    group_id = %crate::logging::LogHexId::group(&outcome.group_id),
                    request_id = %outcome.request_id,
                    %error,
                    "#1840: the authority's head failed a check; recording the refusal"
                );
            }
        }
    }
    let refusal = RequesterOfferRefusal {
        reason: outcome.reason.as_str().to_string(),
        retryable: outcome.reason.is_retryable(),
        refused_at_ms: now_millis_u64(),
    };
    match mark_requester_offer_refused(
        state,
        &outcome.group_id,
        &outcome.request_id,
        refusal,
        accept,
    )
    .await
    {
        Ok(true) => {
            tracing::warn!(
                group_id = %crate::logging::LogHexId::group(&outcome.group_id),
                request_id = %outcome.request_id,
                reason = outcome.reason.as_str(),
                retryable = outcome.reason.is_retryable(),
                "#1840: the authority refused this join request; the envelope is not offered again"
            );
            Ok(DmTypedPayloadCompletion::Inserted)
        }
        Ok(false) => IGNORED,
        Err(error) => Err(error),
    }
}

/// Why a re-seal over a head did not happen.
#[derive(Debug)]
enum ResealError {
    /// The head failed a check: the authority's state is not usable.
    Head(JoinHeadError),
    /// A local condition (the group or the request is gone, the seal or a
    /// write failed). Not the authority's verdict, so never a refusal.
    Local(String),
}

/// Requester side (#1840 routes 1–3, A08 amendment of 15 Nov 2026): install
/// the authority's checked head on this daemon's copy of the group
/// ([`crate::groups::join_outcome::adopt_join_head`]) and sign the SAME
/// pending request again over it: same request id, message, KEM key and
/// TreeKEM KeyPackage, a new commit at the head's next revision. The new
/// envelope is published on the metadata topic as `create_join_request`
/// does, and replaces the offered one in the offer obligation, so the offer
/// worker offers it now. Nothing changes when a check fails.
///
/// The link is sealed with the plain requester seal
/// ([`crate::groups::GroupInfo::seal_commit`]), not the member seal path:
/// a request link changes no roster row, and the requester does not hold
/// the members' certificates (the head carries digests only), so it neither
/// can nor needs to verify or evict them. `adopt_join_head` admits only a
/// request-access group, which the plain seal accepts.
async fn reseal_join_request_over_head(
    state: &AppState,
    obligation: &super::RequesterOfferObligation,
    head: &RetainedCommit,
) -> Result<(), ResealError> {
    use base64::Engine as _;
    let local = |e: &str| ResealError::Local(e.to_string());
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let key = {
        let groups = state.named_groups.read().await;
        groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == obligation.group_id)
            .map(|(key, _)| key.clone())
            .ok_or_else(|| local("the group is not held"))?
    };
    let membership_lock = super::group_membership_lock(state, &key).await;
    let membership_guard = membership_lock.lock().await;
    let now_ms = now_millis_u64();
    let current = state
        .named_groups
        .read()
        .await
        .get(&key)
        .cloned()
        .ok_or_else(|| local("the group is not held"))?;
    let request = current
        .join_requests
        .get(&obligation.request_id)
        .filter(|r| r.is_pending() && r.requester_agent_id == local_hex)
        .cloned()
        .ok_or_else(|| local("the request is no longer pending"))?;
    let mut next = crate::groups::join_outcome::adopt_join_head(&current, head, &local_hex)
        .map_err(ResealError::Head)?;
    next.join_requests
        .insert(request.request_id.clone(), request.clone());
    let commit = next
        .seal_commit(state.agent.identity().agent_keypair(), now_ms)
        .map_err(|e| ResealError::Local(format!("seal failed: {e}")))?;
    let metadata_topic = next.metadata_topic.clone();
    if !matches!(
        super::persist_named_group_info(state, &key, next).await,
        Ok(crate::server::AtomicWriteOutcome::Durable)
    ) {
        return Err(local("the new seal is not directory-durable"));
    }
    drop(membership_guard);
    let event = super::NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: obligation.group_id.clone(),
        request_id: request.request_id.clone(),
        requester_agent_id: request.requester_agent_id.clone(),
        message: request.message.clone(),
        ts: request.created_at,
        requester_kem_public_key_b64: Some(
            base64::engine::general_purpose::STANDARD.encode(&state.agent_kem_keypair.public_bytes),
        ),
        treekem_key_package_b64: request.treekem_key_package_b64.clone(),
        commit: Some(commit),
    };
    // No envelope (the publish failed): the stored offer stays. Its next
    // offer is refused again and brings the head again.
    let envelope =
        super::publish_named_group_metadata_event_with_envelope(state, &metadata_topic, &event)
            .await
            .ok_or_else(|| local("the new seal was not published"))?;
    super::requester_offer::replace_requester_offer_envelope(
        state,
        &obligation.group_id,
        &obligation.request_id,
        obligation.digest,
        envelope.to_vec(),
        now_ms,
    )
    .await
    .map_err(ResealError::Local)?;
    Ok(())
}

/// `own_join_request` of `GET /groups/:id`: this daemon's own pending
/// request on the group, with the authority's refusal when one was
/// received. `Null` when this daemon has no pending request there.
pub(in crate::server) async fn own_join_request_json(
    state: &AppState,
    info: &crate::groups::GroupInfo,
) -> serde_json::Value {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let Some(request) = info
        .join_requests
        .values()
        .find(|r| r.requester_agent_id == local_hex && r.is_pending())
    else {
        return serde_json::Value::Null;
    };
    let refusal = find_requester_offer(state, info.stable_group_id(), &request.request_id)
        .await
        .and_then(|o| o.refusal);
    match refusal {
        Some(refusal) => serde_json::json!({
            "request_id": request.request_id,
            "status": "refused",
            "created_at": request.created_at,
            "refusal": {
                "reason": refusal.reason,
                "retryable": refusal.retryable,
                "refused_at": refusal.refused_at_ms,
            },
        }),
        None => serde_json::json!({
            "request_id": request.request_id,
            "status": "pending",
            "created_at": request.created_at,
        }),
    }
}

/// Test-only record of the outcomes this process handed to the send task.
#[cfg(test)]
pub(in crate::server) mod test_seam {
    use super::{AgentId, AppState};
    use std::sync::Mutex;

    type Sent = (String, AgentId, Vec<u8>);
    static SENT: Mutex<Vec<Sent>> = Mutex::new(Vec::new());

    pub(super) fn record(state: &AppState, to: AgentId, payload: Vec<u8>) {
        let from = hex::encode(state.agent.agent_id().as_bytes());
        SENT.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((from, to, payload));
    }

    /// The outcomes the authority `state` sent, oldest first.
    pub(in crate::server) fn sent_by(state: &AppState) -> Vec<(AgentId, Vec<u8>)> {
        let from = hex::encode(state.agent.agent_id().as_bytes());
        SENT.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(sender, _, _)| *sender == from)
            .map(|(_, to, payload)| (*to, payload.clone()))
            .collect()
    }
}
