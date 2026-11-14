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
use crate::groups::join_outcome::{JoinRequestOutcome, JoinRequestRefusalReason};

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
/// Never blocks: the send runs in a detached task.
pub(in crate::server) fn send_join_request_refusal(
    state: &Arc<AppState>,
    group_id: &str,
    request_id: &str,
    requester: AgentId,
    envelope_digest: [u8; 32],
    reason: JoinRequestRefusalReason,
) {
    let bit = crate::dm::CapabilityRegistry::JOIN_REQUEST_OUTCOME_V1;
    if state
        .agent
        .capability_store()
        .verified_registry_supports(&requester, bit)
        != Some(true)
    {
        return;
    }
    let outcome = JoinRequestOutcome {
        group_id: group_id.to_string(),
        request_id: request_id.to_string(),
        envelope_digest: hex::encode(envelope_digest),
        reason,
    };
    let Ok(payload) = outcome.encode() else {
        return;
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
