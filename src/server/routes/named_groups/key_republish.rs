//! #1663: the send and the ingest of `MemberKeyRepublishV1` (`X0XKR1`),
//! the signed republication of a member's KEM key on its own
//! already-Active seat (David's ruling, 28 Oct 2026 02:25 GMT).
//!
//! A GSS survivor of an encrypted group whose seat carries no KEM key can
//! not receive the re-sealed share of a rotated secret (#1578): every
//! author skips the seal. The republication keys the seat again without a
//! leave and re-join, so the next delivery round seals the share, the
//! keyless hold ends, and the survivor's catch-up answers carry
//! `responder_state_hash` again.
//!
//! - The sender is the seat's own member: [`republish_own_key`] signs the
//!   daemon's live ML-KEM-768 public key (the key the node can actually
//!   open shares under) with the agent ML-DSA-65 key, seats it on its own
//!   row, and sends the frame to each other Active member whose verified
//!   advert sets `key_republish_v1` (bit 12).
//! - The receiver verifies the frame and seats the key on the actor's
//!   row ([`receive`]); replays, stale keys, and unsigned or wrong-signer
//!   frames are refused with the typed reasons
//!   ([`x0x::groups::key_republish::MemberKeyRepublishRefusal`]).
//! - The republication of the LOCAL seat ends this node's keyless
//!   exclusion holds ([`gss_share_hold::release_keyless_on_republish`]):
//!   the node holds no secret while keyless, so the no-secret refusal
//!   covers its sends until the re-sealed share installs.
//!
//! Two triggers send it: the keyless install itself (a member that just
//! learned it can not take a share) and the startup pass
//! [`republish_outstanding_keyless_seats`] (a node that booted into the
//! keyless state).

use crate::dm::CapabilityRegistry;
use crate::groups::key_republish as kr;
use crate::identity::AgentId;
use base64::Engine as _;

use crate as x0x;
use crate::server::routes::named_groups as ng;
use crate::server::routes::named_groups::gss_share_hold;
use crate::server::state::AppState;

/// The built republication of this node's own seat: the encoded frame, the
/// recipients (every other Active member), and the sequence it seats.
pub(super) struct OwnRepublish {
    pub(super) payload: Vec<u8>,
    pub(super) recipients: Vec<[u8; 32]>,
    pub(super) kem_public_key_b64: String,
    pub(super) key_sequence: u64,
}

/// What the ingest of one frame did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum RepublishOutcome {
    /// The key seated on the actor's row.
    Installed,
    /// The group is unknown here; nothing to seat.
    NotApplicable,
    /// The frame is sound but a local fault kept it from persisting.
    LocalFailure,
    /// Refused with the typed reason.
    Refused(kr::MemberKeyRepublishRefusal),
}

/// Build, sign and seat this node's own republication on its own Active
/// seat of `group_key`, then send the frame to every other Active member
/// whose current verified advert sets `key_republish_v1` (the ADR 0110 S4
/// hand-off send rule). The published key is the daemon's live ML-KEM-768
/// keypair — the key this node can open sealed shares under. Returns
/// whether a republication was built and seated.
pub(super) async fn republish_own_key(state: &std::sync::Arc<AppState>, group_key: &str) -> bool {
    let Some(own) = build_own_republish(state, group_key).await else {
        return false;
    };
    if !seat_own_republish(state, group_key, &own).await {
        return false;
    }
    let local = *state.agent.agent_id().as_bytes();
    let capabilities = state.agent.capability_store();
    for recipient in own.recipients {
        if recipient == local {
            continue;
        }
        let agent = AgentId(recipient);
        match capabilities.verified_registry_supports(&agent, CapabilityRegistry::KEY_REPUBLISH_V1)
        {
            Some(true) => {
                let send_state = std::sync::Arc::clone(state);
                let bytes = own.payload.clone();
                let _spawned = state.spawn_detached(async move {
                    if let Err(error) = send_state.agent.send_direct(&agent, bytes).await {
                        tracing::debug!(%error, "#1663: key republish send failed");
                    }
                });
            }
            Some(false) => {
                tracing::debug!(
                    recipient = %hex::encode(recipient),
                    "#1663: key republish skipped — the recipient's advert lacks key_republish_v1"
                );
            }
            None => {}
        }
    }
    true
}

/// Read the saved group, build and sign this node's own republication
/// frame, and collect the recipients. Read-only: nothing is seated and
/// nothing is sent.
pub(super) async fn build_own_republish(
    state: &std::sync::Arc<AppState>,
    group_key: &str,
) -> Option<OwnRepublish> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let info = groups.get(group_key)?;
    if !x0x::groups::crypto_exclusion::is_gss_encrypted(info) || info.withdrawn {
        return None;
    }
    // The republication seats an already-Active row only. A seat that
    // still carries a key republishes too: a peer's view can lack the key
    // (the key is local data), and the re-seat heals that divergence.
    let member = info.members_v2.get(&local_hex)?;
    if member.state != x0x::groups::member::GroupMemberState::Active
        || info.join_seat_key_marker_only(&local_hex)
    {
        return None;
    }
    let key_sequence = member.kem_key_sequence.unwrap_or(0) + 1;
    let kem_public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(&state.agent_kem_keypair.public_bytes);
    let body = kr::MemberKeyRepublishBodyV1 {
        stable_group_id: info.stable_group_id().to_string(),
        actor: *state.agent.agent_id().as_bytes(),
        agent_public_key_b64: base64::engine::general_purpose::STANDARD.encode(
            state
                .agent
                .identity()
                .agent_keypair()
                .public_key()
                .as_bytes(),
        ),
        kem_public_key_b64: kem_public_key_b64.clone(),
        key_sequence,
    };
    let frame = kr::sign(body, state.agent.identity().agent_keypair()).ok()?;
    let payload = kr::encode_frame(&frame).ok()?;
    if payload.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return None;
    }
    let recipients = info
        .active_members()
        .filter_map(|member| {
            ng::parse_agent_id_hex(&member.agent_id)
                .ok()
                .map(|agent| *agent.as_bytes())
        })
        .collect();
    drop(groups);
    Some(OwnRepublish {
        payload,
        recipients,
        kem_public_key_b64,
        key_sequence,
    })
}

/// Seat the built republication on this node's own row and end the keyless
/// holds it keys. The sender installs its own republication locally, as a
/// receiver of it would, so the seat and the frame agree.
async fn seat_own_republish(
    state: &std::sync::Arc<AppState>,
    group_key: &str,
    own: &OwnRepublish,
) -> bool {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let next = {
        let mut groups = state.named_groups.write().await;
        let Some(next) = groups.get_mut(group_key) else {
            return false;
        };
        if !next.install_republished_kem_key(&local_hex, &own.kem_public_key_b64, own.key_sequence)
        {
            return false;
        }
        next.clone()
    };
    if !matches!(
        ng::persist_named_group_info(state, group_key, next.clone()).await,
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
    ) {
        tracing::warn!("#1663: own key republication did not persist");
        return false;
    }
    gss_share_hold::release_keyless_on_republish(state, group_key, &next).await;
    tracing::info!(
        group_id = %group_key,
        key_sequence = own.key_sequence,
        "#1663: own KEM key republished on the seat"
    );
    true
}

/// Verify and seat one frame (the direct carrier's receipt path). The
/// caller checked the transport; the frame must still pass
/// [`kr::verify_signatures`] and [`kr::validate_against_seat`] against the
/// saved group state under the group's membership lock.
pub(in crate::server) async fn receive(
    state: &std::sync::Arc<AppState>,
    sender: AgentId,
    payload: &[u8],
) -> RepublishOutcome {
    use kr::MemberKeyRepublishRefusal as Refusal;
    let frame = match kr::decode_frame(payload) {
        Ok(frame) => frame,
        Err(refusal) => return RepublishOutcome::Refused(refusal),
    };
    if let Err(refusal) = kr::verify_signatures(&frame) {
        tracing::debug!(reason = refusal.as_str(), "#1663: key republish refused");
        return RepublishOutcome::Refused(refusal);
    }
    let body = frame.body;
    {
        // A revoked signer or sender fails closed, as every S4 frame does.
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        if set.is_agent_revoked(&AgentId(body.actor)) || set.is_agent_revoked(&sender) {
            return RepublishOutcome::Refused(Refusal::ActorIneligible);
        }
    }
    let Some(group_key) = ng::resolve_named_group_storage_key(state, &body.stable_group_id).await
    else {
        return RepublishOutcome::NotApplicable;
    };
    let membership_lock = ng::group_membership_lock(state, &group_key).await;
    let membership_guard = membership_lock.lock().await;
    let actor_hex = hex::encode(body.actor);
    let next = {
        let mut groups = state.named_groups.write().await;
        let Some(next) = groups.get_mut(&group_key) else {
            return RepublishOutcome::NotApplicable;
        };
        // The frame is self-authenticating (the actor signed it); a
        // relaying sender must still be an Active member of the group.
        let sender_hex = hex::encode(sender.as_bytes());
        if sender.as_bytes() != &body.actor && !next.has_active_member(&sender_hex) {
            return RepublishOutcome::Refused(Refusal::ActorIneligible);
        }
        match kr::validate_against_seat(&body, next) {
            Err(refusal) => return RepublishOutcome::Refused(refusal),
            Ok(()) => {
                if !next.install_republished_kem_key(
                    &actor_hex,
                    &body.kem_public_key_b64,
                    body.key_sequence,
                ) {
                    return RepublishOutcome::Refused(Refusal::StaleKey);
                }
                next.clone()
            }
        }
    };
    drop(membership_guard);
    if !matches!(
        ng::persist_named_group_info(state, &group_key, next.clone()).await,
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
    ) {
        // A local storage fault, not a sender defect.
        return RepublishOutcome::LocalFailure;
    }
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    // The republication of the LOCAL seat ends the keyless holds: the
    // withholding reason is gone (this node holds no secret to seal
    // anything under while it waits for the share).
    if body.actor == *state.agent.agent_id().as_bytes() {
        gss_share_hold::release_keyless_on_republish(state, &group_key, &next).await;
    }
    tracing::info!(
        group_id = %group_key,
        actor = %actor_hex,
        key_sequence = body.key_sequence,
        own_seat = body.actor == *state.agent.agent_id().as_bytes(),
        "#1663: republished KEM key seated"
    );
    RepublishOutcome::Installed
}

/// The direct carrier's receipt of one `X0XKR1` frame; verified off the
/// listener loop, as every typed frame is.
pub(in crate::server) fn spawn_receipt(
    state: &std::sync::Arc<AppState>,
    sender: AgentId,
    verified: bool,
    payload: Vec<u8>,
) {
    if !verified {
        return;
    }
    let task_state = std::sync::Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let _ = receive(&task_state, sender, &payload).await;
    });
}

/// Startup pass (#1663): every encrypted GSS group whose own seat is
/// Active and keyless republishes the key. The keyless-install hook covers
/// the live discovery; this pass covers a node that booted into the state
/// (including the pre-#1578 joiner shape whose own view never seated a
/// key).
pub(in crate::server) async fn republish_outstanding_keyless_seats(
    state: &std::sync::Arc<AppState>,
) {
    // Tests that pin the #1578 keyless state machine suppress the
    // automatic republish (`key_republish_suppressed`); production runs it.
    #[cfg(test)]
    if state
        .named_group_test_recorders
        .key_republish_suppressed
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    let keys: Vec<String> = {
        let groups = state.named_groups.read().await;
        groups
            .iter()
            .filter(|(_, info)| {
                !info.withdrawn
                    && x0x::groups::crypto_exclusion::is_gss_encrypted(info)
                    && super::revocation_eviction::crypto_exclusion::own_seat_cannot_take_a_share(
                        state, info,
                    )
            })
            .map(|(key, _)| key.clone())
            .collect()
    };
    for group_key in keys {
        republish_own_key(state, &group_key).await;
    }
}
