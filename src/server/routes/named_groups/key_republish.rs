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
//! keyless state, or into the keyed-but-shareless state the
//! republication leaves until the share seals).
//!
//! A send the carrier does not accept is not done (#1663 review P2): a
//! recipient whose verified advert was missing or expired, or whose send
//! failed, stays owed in [`PendingKeyRepublish`], and the sweep
//! [`sweep_pending_key_republishes`] retries it after the advert arrives
//! or the failure passes. The startup pass rebuilds the debt after a
//! restart, because the seat stays selected until its share seals.

use crate::dm::CapabilityRegistry;
use crate::groups::key_republish as kr;
use crate::identity::AgentId;
use base64::Engine as _;

use crate as x0x;
use crate::server::routes::named_groups as ng;
use crate::server::routes::named_groups::gss_share_hold;
use crate::server::state::AppState;

/// How often the pending-republish sweep retries an owed frame (#1663
/// review P2): the cadence of one S4 delivery round.
const KEY_REPUBLISH_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// The built republication of this node's own seat: the encoded frame, the
/// recipients (every other Active member), and the sequence it seats.
pub(super) struct OwnRepublish {
    pub(super) payload: Vec<u8>,
    pub(super) stable_group_id: String,
    pub(super) recipients: Vec<[u8; 32]>,
    pub(super) kem_public_key_b64: String,
    pub(super) key_sequence: u64,
}

/// One group's republication frames still owed to recipients (#1663
/// review P2): each `owed` recipient had no current verified advert when
/// the republication ran, or its send failed. The sweep re-sends the frame
/// until the carrier accepts it, or an advert that lacks
/// `key_republish_v1` rules the peer out, or the group ends. Memory-only
/// by design: the startup pass keeps selecting the group until its share
/// seals, so a restart rebuilds the debt.
pub(in crate::server) struct PendingKeyRepublish {
    payload: std::sync::Arc<Vec<u8>>,
    owed: std::collections::BTreeSet<[u8; 32]>,
    next_at: std::time::Instant,
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
/// keypair — the key this node can open sealed shares under. A recipient
/// whose advert is missing or expired, or whose send fails, stays owed
/// and is retried by the sweep (#1663 review P2). Returns whether a
/// republication was built and seated.
pub(super) async fn republish_own_key(state: &std::sync::Arc<AppState>, group_key: &str) -> bool {
    let Some(own) = build_own_republish(state, group_key).await else {
        return false;
    };
    if !seat_own_republish(state, group_key, &own).await {
        return false;
    }
    let local = *state.agent.agent_id().as_bytes();
    let capabilities = state.agent.capability_store();
    let mut owed: Vec<[u8; 32]> = Vec::new();
    let mut capable: Vec<[u8; 32]> = Vec::new();
    let mut refreshes: Vec<AgentId> = Vec::new();
    for recipient in own.recipients {
        if recipient == local {
            continue;
        }
        let agent = AgentId(recipient);
        match capabilities.verified_registry_supports(&agent, CapabilityRegistry::KEY_REPUBLISH_V1)
        {
            Some(true) => {
                owed.push(recipient);
                capable.push(recipient);
            }
            Some(false) => {
                tracing::debug!(
                    recipient = %hex::encode(recipient),
                    "#1663: key republish skipped — the recipient's advert lacks key_republish_v1"
                );
            }
            // No current verified advert: the frame stays owed, and a
            // refresh asks the peer for one (#1663 review P2).
            None => {
                owed.push(recipient);
                refreshes.push(agent);
            }
        }
    }
    record_pending_republish(state, &own.stable_group_id, own.payload.clone(), &owed);
    // A capable recipient gets the frame at once; the send stays owed
    // until the carrier accepts it.
    let payload = std::sync::Arc::new(own.payload.clone());
    for recipient in capable {
        spawn_republish_send(
            state,
            &own.stable_group_id,
            AgentId(recipient),
            std::sync::Arc::clone(&payload),
        );
    }
    for agent in refreshes {
        let task_state = std::sync::Arc::clone(state);
        let _spawned = state.spawn_detached(async move {
            task_state
                .agent
                .refresh_application_capability(agent, CapabilityRegistry::KEY_REPUBLISH_V1)
                .await;
        });
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
    let stable_group_id = info.stable_group_id().to_string();
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
        stable_group_id,
        recipients,
        kem_public_key_b64,
        key_sequence,
    })
}

/// Seat the built republication on this node's own row and end the keyless
/// holds it keys. The sender installs its own republication locally, as a
/// receiver of it would, so the seat and the frame agree. The membership
/// guard spans the mutation and the durable persist (the house M→P lock
/// order), so no interleaved removal or newer-sequence write can be
/// overwritten by this write's clone (#1663 review P1).
async fn seat_own_republish(
    state: &std::sync::Arc<AppState>,
    group_key: &str,
    own: &OwnRepublish,
) -> bool {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let membership_lock = ng::group_membership_lock(state, group_key).await;
    let _membership_guard = membership_lock.lock().await;
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
    let _membership_guard = membership_lock.lock().await;
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
    // The membership guard spans the mutation and the durable persist (the
    // house M→P lock order): a removal or a newer-sequence republication
    // that interleaves here serializes on the same guard, so this write's
    // clone can not overwrite it (#1663 review P1).
    if !matches!(
        ng::persist_named_group_info(state, &group_key, next.clone()).await,
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
    ) {
        // A local storage fault, not a sender defect.
        return RepublishOutcome::LocalFailure;
    }
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    // The seated key may key a survivor this node's delivery rounds could
    // not seal to: the next round must seal the current secret to that
    // seat whatever a restored head already reported, so the delivery can
    // not complete shareless (#1663 review P1).
    super::revocation_eviction::crypto_exclusion::owe_gss_shares_after_republish(
        state,
        &body.stable_group_id,
    )
    .await;
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

/// Startup pass (#1663): every encrypted GSS group whose own Active seat
/// is keyless republishes the key. The keyless-install hook covers
/// the live discovery; this pass covers a node that booted into the state
/// (including the pre-#1578 joiner shape whose own view never seated a
/// key). A seat that already carries its republished key but whose share
/// never sealed stays selected too (#1663 review P2): the sends can all
/// have failed before the restart, and the author can not seal the share
/// until the frame reaches it — the pass re-sends until the secret
/// installs.
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
                    && (super::revocation_eviction::crypto_exclusion::own_seat_cannot_take_a_share(
                        state, info,
                    ) || own_seat_awaits_its_share(state, info))
            })
            .map(|(key, _)| key.clone())
            .collect()
    };
    for group_key in keys {
        republish_own_key(state, &group_key).await;
    }
}

/// #1663 review P2: the own Active seat carries a key but this node still
/// holds no secret of the group — the state right after its own
/// republication, while the share is owed. The republication is not done
/// until the share seals, so the startup pass keeps the group.
fn own_seat_awaits_its_share(state: &AppState, info: &x0x::groups::GroupInfo) -> bool {
    let own_hex = hex::encode(state.agent.agent_id().as_bytes());
    info.shared_secret.is_none()
        && info
            .active_members()
            .any(|member| member.agent_id == own_hex)
}

fn pending_lock(
    state: &AppState,
) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, PendingKeyRepublish>> {
    state
        .key_republish_pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record the frames `owed` still need (#1663 review P2) and arm the
/// sweep. A newer republication of the same group replaces the frame; the
/// receiver's sequence check refuses an older one anyway.
fn record_pending_republish(
    state: &std::sync::Arc<AppState>,
    stable_group_id: &str,
    payload: Vec<u8>,
    owed: &[[u8; 32]],
) {
    if owed.is_empty() {
        return;
    }
    {
        let mut pending = pending_lock(state);
        let entry = pending
            .entry(stable_group_id.to_string())
            .or_insert_with(|| PendingKeyRepublish {
                payload: std::sync::Arc::new(payload.clone()),
                owed: std::collections::BTreeSet::new(),
                next_at: std::time::Instant::now() + KEY_REPUBLISH_RETRY_INTERVAL,
            });
        if entry.payload.as_slice() != payload.as_slice() {
            entry.payload = std::sync::Arc::new(payload);
        }
        entry.owed.extend(owed.iter().copied());
    }
    arm_pending_sweep(state);
}

/// Send one owed frame to `agent`. A send the carrier accepts clears the
/// recipient's debt; a failed one leaves it for the next sweep (#1663
/// review P2). The receiver's sequence check refuses a repeat of a frame
/// it already seated, so a duplicate send is refused, not replayed.
fn spawn_republish_send(
    state: &std::sync::Arc<AppState>,
    stable_group_id: &str,
    agent: AgentId,
    payload: std::sync::Arc<Vec<u8>>,
) {
    #[cfg(test)]
    state
        .named_group_test_recorders
        .key_republish_sends
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(*agent.as_bytes());
    let task_state = std::sync::Arc::clone(state);
    let stable = stable_group_id.to_string();
    let _spawned = state.spawn_detached(async move {
        if let Err(error) = task_state
            .agent
            .send_direct(&agent, (*payload).clone())
            .await
        {
            tracing::debug!(%error, "#1663: key republish send failed; the sweep retries it");
            return;
        }
        drop_pending_recipient(&task_state, &stable, agent.as_bytes());
    });
}

/// Remove one recipient's debt; the group's entry goes when the last debt
/// clears.
fn drop_pending_recipient(state: &AppState, stable_group_id: &str, recipient: &[u8; 32]) {
    let mut pending = pending_lock(state);
    let dropped = pending
        .get_mut(stable_group_id)
        .is_some_and(|entry| entry.owed.remove(recipient));
    if dropped
        && pending
            .get(stable_group_id)
            .is_some_and(|entry| entry.owed.is_empty())
    {
        pending.remove(stable_group_id);
    }
}

/// Arm the one sweep task this state runs while any frame is pending. The
/// flag keeps a second record from arming a second task; the task clears
/// it when nothing is owed, after a last look for a record that raced it.
fn arm_pending_sweep(state: &std::sync::Arc<AppState>) {
    if state
        .key_republish_sweep_armed
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    let task_state = std::sync::Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        loop {
            tokio::time::sleep(KEY_REPUBLISH_RETRY_INTERVAL).await;
            if sweep_pending_key_republishes(&task_state).await {
                continue;
            }
            task_state
                .key_republish_sweep_armed
                .store(false, std::sync::atomic::Ordering::SeqCst);
            if pending_lock(&task_state).is_empty() {
                break;
            }
        }
    });
}

/// One sweep's snapshot of a group's debt: the frame and the recipients
/// it is still owed to.
struct DueRepublish {
    stable_group_id: String,
    payload: std::sync::Arc<Vec<u8>>,
    owed: Vec<[u8; 32]>,
}

/// One sweep of the pending republications (#1663 review P2): each owed
/// recipient is re-checked against its current verified advert — a
/// recipient that now sets `key_republish_v1` gets the frame, an advert
/// that rules it out clears the debt (an intentionally unsupported peer
/// is not owed a retry), and a still-unknown one gets a refresh request.
/// The debt ends with the group too: a withdrawn group or a left seat
/// owes nothing. Returns whether anything is still owed.
pub(in crate::server) async fn sweep_pending_key_republishes(
    state: &std::sync::Arc<AppState>,
) -> bool {
    let now = std::time::Instant::now();
    let due: Vec<DueRepublish> = {
        let mut pending = pending_lock(state);
        let mut due = Vec::new();
        for (stable, entry) in pending.iter_mut() {
            if entry.next_at > now {
                continue;
            }
            entry.next_at = now + KEY_REPUBLISH_RETRY_INTERVAL;
            due.push(DueRepublish {
                stable_group_id: stable.clone(),
                payload: std::sync::Arc::clone(&entry.payload),
                owed: entry.owed.iter().copied().collect(),
            });
        }
        due
    };
    if !due.is_empty() {
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let capabilities = state.agent.capability_store();
        let mut refreshes: Vec<AgentId> = Vec::new();
        for due in due {
            let group_key = ng::resolve_named_group_storage_key(state, &due.stable_group_id).await;
            let live = match group_key {
                Some(group_key) => {
                    let groups = state.named_groups.read().await;
                    groups.get(&group_key).is_some_and(|info| {
                        !info.withdrawn
                            && x0x::groups::crypto_exclusion::is_gss_encrypted(info)
                            && info.members_v2.get(&local_hex).is_some_and(|seat| {
                                seat.state == x0x::groups::member::GroupMemberState::Active
                            })
                    })
                }
                None => false,
            };
            if !live {
                pending_lock(state).remove(&due.stable_group_id);
                continue;
            }
            for recipient in due.owed {
                match capabilities.verified_registry_supports(
                    &AgentId(recipient),
                    CapabilityRegistry::KEY_REPUBLISH_V1,
                ) {
                    Some(true) => {
                        spawn_republish_send(
                            state,
                            &due.stable_group_id,
                            AgentId(recipient),
                            std::sync::Arc::clone(&due.payload),
                        );
                    }
                    Some(false) => {
                        drop_pending_recipient(state, &due.stable_group_id, &recipient);
                    }
                    None => refreshes.push(AgentId(recipient)),
                }
            }
        }
        for agent in refreshes {
            let task_state = std::sync::Arc::clone(state);
            let _spawned = state.spawn_detached(async move {
                task_state
                    .agent
                    .refresh_application_capability(agent, CapabilityRegistry::KEY_REPUBLISH_V1)
                    .await;
            });
        }
    }
    !pending_lock(state).is_empty()
}

/// #1663 review P2 test seam: the recipients (hex) one group's pending
/// republication still owes.
#[cfg(test)]
pub(in crate::server) fn pending_republish_owed(
    state: &AppState,
    stable_group_id: &str,
) -> Vec<String> {
    pending_lock(state)
        .get(stable_group_id)
        .map(|entry| entry.owed.iter().map(hex::encode).collect())
        .unwrap_or_default()
}

/// #1663 review P2 test seam: mark every pending frame due now, so a test
/// drives the sweep without the retry interval's clock.
#[cfg(test)]
pub(in crate::server) fn pending_republish_due_now(state: &AppState) {
    let now = std::time::Instant::now();
    for entry in pending_lock(state).values_mut() {
        entry.next_at = now;
    }
}
