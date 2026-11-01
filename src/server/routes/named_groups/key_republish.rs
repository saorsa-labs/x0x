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
//! The wire has no ack, so one accepted send does not end the debt: it
//! ends after a fixed number of accepted sends on a backed-off schedule
//! (#1663 review round 5, Claude, 30 Oct).

use crate::dm::CapabilityRegistry;
use crate::groups::key_republish as kr;
use crate::identity::AgentId;
use base64::Engine as _;

use crate as x0x;
use crate::server::routes::named_groups as ng;
use crate::server::routes::named_groups::gss_share_hold;
use crate::server::state::AppState;

/// How often the pending-republish sweep retries an owed frame (#1663
/// review P2): the cadence of one S4 delivery round. It is also the first
/// backoff step of each group's debt.
const KEY_REPUBLISH_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// #1663 review round 5 (Claude, 30 Oct): the ceiling of the per-group
/// backoff. The interval doubles after each sweep of the group (5, 10,
/// 20, 40, 80 s) and then stays at this value.
const KEY_REPUBLISH_MAX_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(80);

/// #1663 review round 5 (Claude, 30 Oct): the number of carrier-accepted
/// sends that end one recipient's debt. The wire has no ack, and a
/// receiver can refuse a frame it gets too early (its roster is behind:
/// `ActorIneligible`; a local storage fault: `LocalFailure`). So one
/// accepted send does not prove the key seated. The first send and five
/// backed-off sweeps cover about 2.5 min. A repeat of a seated frame is
/// harmless: the receiver refuses it as `StaleKey`.
const KEY_REPUBLISH_ACCEPTED_SENDS: u8 = 6;

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
/// review P2): each `owed` recipient maps to the number of sends of the
/// current `payload` that the carrier accepted. The sweep re-sends the
/// frame until [`KEY_REPUBLISH_ACCEPTED_SENDS`] sends are accepted, or an
/// advert that lacks `key_republish_v1` rules the peer out, or the peer
/// stops being an Active, unrevoked member, or the group ends (#1663
/// review round 5, Claude, 30 Oct). Memory-only by design: the startup
/// pass keeps selecting the group until its share seals, so a restart
/// rebuilds the debt.
pub(in crate::server) struct PendingKeyRepublish {
    payload: std::sync::Arc<Vec<u8>>,
    owed: std::collections::BTreeMap<[u8; 32], u8>,
    /// The wait after the next sweep of this group; it doubles after each
    /// sweep, up to [`KEY_REPUBLISH_MAX_RETRY_INTERVAL`].
    interval: std::time::Duration,
    next_at: std::time::Instant,
}

/// The per-state pending-republish map, keyed by stable group id.
type PendingMap = std::collections::BTreeMap<String, PendingKeyRepublish>;

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
    // #1663 review round 4 (Claude N1, 30 Oct): the counter is local data
    // and can sit at its ceiling; a checked add keeps a republish from
    // wrapping to a sequence every receiver refuses.
    let key_sequence = member.kem_key_sequence.unwrap_or(0).checked_add(1)?;
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
        let Some(current) = groups.get_mut(group_key) else {
            return false;
        };
        // #1663 review P2 (Codex controller, 30 Oct): stage the seat on a
        // clone and let the persister install it. A mutation of the live
        // entry precedes the persister's rollback snapshot, so a failed
        // save would restore the already-advanced sequence and refuse the
        // identical frame's retry as `StaleKey`.
        let mut staged = current.clone();
        if !staged.install_republished_kem_key(
            &local_hex,
            &own.kem_public_key_b64,
            own.key_sequence,
        ) {
            return false;
        }
        staged
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
        let Some(current) = groups.get_mut(&group_key) else {
            return RepublishOutcome::NotApplicable;
        };
        // The frame is self-authenticating (the actor signed it); a
        // relaying sender must still be an Active member of the group.
        let sender_hex = hex::encode(sender.as_bytes());
        if sender.as_bytes() != &body.actor && !current.has_active_member(&sender_hex) {
            return RepublishOutcome::Refused(Refusal::ActorIneligible);
        }
        // #1663 review P2 (Codex controller, 30 Oct): as the own-seat
        // path — validate and stage on a clone, so a pre-replacement
        // save failure restores the seat this frame found and the
        // identical frame's retry is not refused `StaleKey`.
        let mut staged = match kr::validate_against_seat(&body, current) {
            Err(refusal) => return RepublishOutcome::Refused(refusal),
            Ok(()) => current.clone(),
        };
        if !staged.install_republished_kem_key(
            &actor_hex,
            &body.kem_public_key_b64,
            body.key_sequence,
        ) {
            return RepublishOutcome::Refused(Refusal::StaleKey);
        }
        staged
    };
    // #1663 review round 4 (Codex controller P1, 30 Oct): arm the share
    // obligation BEFORE the durable write. The persister installs the
    // keyed seat inside that write, and the head/round observers read the
    // roster without the membership guard — a restored head answered in
    // the gap between the install and a later arm would converge the
    // now-keyged seat and remove the row this debt holds open. Arming
    // first makes key visibility and the obligation move together; the
    // failed save rolls the arm back with the seat below.
    let armed = super::revocation_eviction::crypto_exclusion::owe_gss_shares_after_republish(
        state,
        &body.stable_group_id,
        &body.actor,
        &body.kem_public_key_b64,
    )
    .await;
    // The membership guard spans the staging and the durable persist (the
    // house M→P lock order): a removal or a newer-sequence republication
    // that interleaves here serializes on the same guard, so this write's
    // clone can not overwrite it (#1663 review P1).
    if !matches!(
        ng::persist_named_group_info(state, &group_key, next.clone()).await,
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable)
    ) {
        // A local storage fault, not a sender defect: the seat stays as
        // the frame found it, and so does the obligation.
        super::revocation_eviction::crypto_exclusion::retract_gss_shares_after_republish(
            state, armed,
        )
        .await;
        return RepublishOutcome::LocalFailure;
    }
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    // The seated key may key a survivor this node's delivery rounds could
    // not seal to: the next round must seal the current secret to that
    // seat whatever a restored head already reported, so the delivery can
    // not complete shareless (#1663 review P1). The armed debt — held
    // against the republisher's convergence until the carrier accepts a
    // share sealed under the same key — is that obligation; the batch
    // re-arm rides with it (#1663 review P1, Codex controller, 30 Oct).
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

fn pending_lock(state: &AppState) -> std::sync::MutexGuard<'_, PendingMap> {
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
    record_into(
        &mut pending_lock(state),
        stable_group_id,
        payload,
        owed,
        std::time::Instant::now(),
    );
    arm_pending_sweep(state);
}

/// The map step of [`record_pending_republish`]. #1663 review round 5
/// (Claude, 30 Oct): a different `payload` (a newer sequence) replaces the
/// frame, sets every recipient's accepted-send count to zero, and starts
/// the backoff again — the sends of the old frame do not seat the new key.
/// The same `payload` only adds the recipients that are not owed yet.
fn record_into(
    pending: &mut PendingMap,
    stable_group_id: &str,
    payload: Vec<u8>,
    owed: &[[u8; 32]],
    now: std::time::Instant,
) {
    let entry = pending
        .entry(stable_group_id.to_string())
        .or_insert_with(|| PendingKeyRepublish {
            payload: std::sync::Arc::new(payload.clone()),
            owed: std::collections::BTreeMap::new(),
            interval: KEY_REPUBLISH_RETRY_INTERVAL,
            next_at: now + KEY_REPUBLISH_RETRY_INTERVAL,
        });
    if entry.payload.as_slice() != payload.as_slice() {
        entry.payload = std::sync::Arc::new(payload);
        entry.owed.values_mut().for_each(|accepted| *accepted = 0);
        entry.interval = KEY_REPUBLISH_RETRY_INTERVAL;
        entry.next_at = now + KEY_REPUBLISH_RETRY_INTERVAL;
    }
    for recipient in owed {
        entry.owed.entry(*recipient).or_insert(0);
    }
}

/// #1663 review round 5 (Claude, 30 Oct): count one carrier-accepted send
/// of `payload` to `recipient`. The debt ends at
/// [`KEY_REPUBLISH_ACCEPTED_SENDS`]; the group's entry goes when the last
/// debt ends. A send of a frame that a newer one replaced does not count.
fn note_accepted_into(
    pending: &mut PendingMap,
    stable_group_id: &str,
    recipient: &[u8; 32],
    payload: &[u8],
) {
    let Some(entry) = pending.get_mut(stable_group_id) else {
        return;
    };
    if entry.payload.as_slice() != payload {
        return;
    }
    let Some(accepted) = entry.owed.get_mut(recipient) else {
        return;
    };
    *accepted = accepted.saturating_add(1);
    if *accepted >= KEY_REPUBLISH_ACCEPTED_SENDS {
        entry.owed.remove(recipient);
        if entry.owed.is_empty() {
            pending.remove(stable_group_id);
        }
    }
}

/// The due step of one sweep: snapshot each group whose retry time came,
/// and back off its next retry (#1663 review round 5, Claude, 30 Oct). The
/// interval doubles after each sweep of the group, up to
/// [`KEY_REPUBLISH_MAX_RETRY_INTERVAL`].
fn take_due(pending: &mut PendingMap, now: std::time::Instant) -> Vec<DueRepublish> {
    let mut due = Vec::new();
    for (stable, entry) in pending.iter_mut() {
        if entry.next_at > now {
            continue;
        }
        entry.interval = entry
            .interval
            .saturating_mul(2)
            .min(KEY_REPUBLISH_MAX_RETRY_INTERVAL);
        entry.next_at = now + entry.interval;
        due.push(DueRepublish {
            stable_group_id: stable.clone(),
            payload: std::sync::Arc::clone(&entry.payload),
            owed: entry.owed.keys().copied().collect(),
        });
    }
    due
}

/// Send one owed frame to `agent`. A send the carrier accepts counts
/// toward the recipient's bound (#1663 review round 5, Claude, 30 Oct); a
/// failed one does not count, and the next sweep retries it (#1663 review
/// P2). The receiver's sequence check refuses a repeat of a frame it
/// already seated, so a duplicate send is refused, not replayed.
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
        note_accepted_into(
            &mut pending_lock(&task_state),
            &stable,
            agent.as_bytes(),
            payload.as_slice(),
        );
    });
}

/// Remove one recipient's debt; the group's entry goes when the last debt
/// clears.
fn drop_pending_recipient(state: &AppState, stable_group_id: &str, recipient: &[u8; 32]) {
    let mut pending = pending_lock(state);
    let dropped = pending
        .get_mut(stable_group_id)
        .is_some_and(|entry| entry.owed.remove(recipient).is_some());
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
            // #1663 review round 5 (Claude, 30 Oct): a record raced the
            // clear. Take the flag again before this task continues; if a
            // concurrent arm took it first, that arm's task owns the
            // sweep, and this one stops (one task per state).
            if task_state
                .key_republish_sweep_armed
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
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
/// owes nothing. A recipient that is no longer an Active member (Removed,
/// Banned or absent), or whose agent id is revoked, is owed nothing too
/// (#1663 review round 5, Claude, 30 Oct). Returns whether anything is
/// still owed.
pub(in crate::server) async fn sweep_pending_key_republishes(
    state: &std::sync::Arc<AppState>,
) -> bool {
    let due = take_due(&mut pending_lock(state), std::time::Instant::now());
    if !due.is_empty() {
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let capabilities = state.agent.capability_store();
        let mut refreshes: Vec<AgentId> = Vec::new();
        for due in due {
            let group_key = ng::resolve_named_group_storage_key(state, &due.stable_group_id).await;
            // `None`: the group is not live here. `Some`: the owed
            // recipients that are no longer Active members.
            let departed: Option<Vec<[u8; 32]>> = match group_key {
                Some(group_key) => {
                    let groups = state.named_groups.read().await;
                    groups
                        .get(&group_key)
                        .filter(|info| {
                            !info.withdrawn
                                && x0x::groups::crypto_exclusion::is_gss_encrypted(info)
                                && info.members_v2.get(&local_hex).is_some_and(|seat| {
                                    seat.state == x0x::groups::member::GroupMemberState::Active
                                })
                        })
                        .map(|info| {
                            due.owed
                                .iter()
                                .filter(|recipient| {
                                    !info.has_active_member(&hex::encode(recipient))
                                })
                                .copied()
                                .collect()
                        })
                }
                None => None,
            };
            let Some(departed) = departed else {
                pending_lock(state).remove(&due.stable_group_id);
                continue;
            };
            // A revoked recipient fails closed, as `receive` does for a
            // revoked actor or sender.
            let revoked: Vec<[u8; 32]> = {
                let revocation_set = state.agent.revocation_set();
                let set = revocation_set.read().await;
                due.owed
                    .iter()
                    .filter(|recipient| set.is_agent_revoked(&AgentId(**recipient)))
                    .copied()
                    .collect()
            };
            for recipient in departed.iter().chain(revoked.iter()) {
                drop_pending_recipient(state, &due.stable_group_id, recipient);
            }
            for recipient in due.owed {
                if departed.contains(&recipient) || revoked.contains(&recipient) {
                    continue;
                }
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
        .map(|entry| entry.owed.keys().map(hex::encode).collect())
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

#[cfg(test)]
mod tests {
    //! #1663 review round 5 (Claude, 30 Oct): the bounded retry, the
    //! sweep's recipient checks, and the refusals of [`receive`].
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const R1: [u8; 32] = [0x11; 32];
    const R2: [u8; 32] = [0x22; 32];

    fn owed_of(pending: &PendingMap, stable: &str) -> Vec<[u8; 32]> {
        pending
            .get(stable)
            .map(|entry| entry.owed.keys().copied().collect())
            .unwrap_or_default()
    }

    /// One carrier-accepted send does not end the debt; the bound does.
    /// A failed send is not counted (it never reaches `note_accepted_into`).
    #[test]
    fn key_republish_accepted_sends_end_the_debt_at_the_bound() {
        let mut pending = PendingMap::new();
        let payload = vec![1u8, 2, 3];
        record_into(
            &mut pending,
            "g",
            payload.clone(),
            &[R1, R2],
            Instant::now(),
        );
        for _ in 1..KEY_REPUBLISH_ACCEPTED_SENDS {
            note_accepted_into(&mut pending, "g", &R1, &payload);
        }
        assert_eq!(
            owed_of(&pending, "g"),
            vec![R1, R2],
            "one send short of the bound: still owed"
        );
        note_accepted_into(&mut pending, "g", &R1, &payload);
        assert_eq!(owed_of(&pending, "g"), vec![R2], "the bound ends the debt");
        for _ in 0..KEY_REPUBLISH_ACCEPTED_SENDS {
            note_accepted_into(&mut pending, "g", &R2, &payload);
        }
        assert!(pending.is_empty(), "the last debt removes the group entry");
    }

    /// A newer frame resets every count and the backoff, and a late
    /// accept of the replaced frame does not count toward the new one.
    #[test]
    fn key_republish_newer_payload_resets_counts_and_backoff() {
        let mut pending = PendingMap::new();
        let old = vec![1u8];
        let new = vec![2u8];
        let t0 = Instant::now();
        record_into(&mut pending, "g", old.clone(), &[R1], t0);
        for _ in 1..KEY_REPUBLISH_ACCEPTED_SENDS {
            note_accepted_into(&mut pending, "g", &R1, &old);
        }
        let swept = t0 + KEY_REPUBLISH_RETRY_INTERVAL;
        assert_eq!(take_due(&mut pending, swept).len(), 1);
        let t1 = swept + Duration::from_secs(1);
        record_into(&mut pending, "g", new.clone(), &[R2], t1);
        let entry = pending.get("g");
        assert!(
            entry.is_some_and(|entry| entry.interval == KEY_REPUBLISH_RETRY_INTERVAL
                && entry.next_at == t1 + KEY_REPUBLISH_RETRY_INTERVAL
                && entry.payload.as_slice() == new.as_slice()
                && entry.owed.values().all(|accepted| *accepted == 0))
        );
        assert_eq!(owed_of(&pending, "g"), vec![R1, R2]);
        // The replaced frame's late accept does not count.
        note_accepted_into(&mut pending, "g", &R1, &old);
        for _ in 1..KEY_REPUBLISH_ACCEPTED_SENDS {
            note_accepted_into(&mut pending, "g", &R1, &new);
        }
        assert_eq!(
            owed_of(&pending, "g"),
            vec![R1, R2],
            "the old frame's sends did not carry over"
        );
        note_accepted_into(&mut pending, "g", &R1, &new);
        assert_eq!(owed_of(&pending, "g"), vec![R2]);
        // The same frame recorded again keeps the counts.
        note_accepted_into(&mut pending, "g", &R2, &new);
        record_into(&mut pending, "g", new.clone(), &[R1, R2], t1);
        assert!(pending.get("g").is_some_and(
            |entry| entry.owed.get(&R1) == Some(&0) && entry.owed.get(&R2) == Some(&1)
        ));
    }

    /// The sweep interval of a group doubles after each sweep, up to the
    /// cap; a group not yet due is not swept.
    #[test]
    fn key_republish_sweep_backoff_doubles_to_the_cap() {
        let mut pending = PendingMap::new();
        let mut now = Instant::now();
        record_into(&mut pending, "g", vec![1], &[R1], now);
        assert!(take_due(&mut pending, now).is_empty(), "not due at once");
        let mut waits = Vec::new();
        let mut wait = KEY_REPUBLISH_RETRY_INTERVAL;
        for _ in 0..6 {
            now += wait;
            assert_eq!(take_due(&mut pending, now).len(), 1);
            let next_at = pending.get("g").map(|entry| entry.next_at);
            assert_eq!(
                take_due(&mut pending, now + Duration::from_millis(1)).len(),
                0
            );
            wait = next_at.map_or(Duration::ZERO, |at| at - now);
            waits.push(wait.as_secs());
        }
        assert_eq!(waits, vec![10, 20, 40, 80, 80, 80]);
    }

    /// A GSS `MlsEncrypted` group owned by `state`, with each of
    /// `members` as an Active Member. Returns the storage key and the
    /// stable id.
    async fn gss_group(state: &Arc<AppState>, members: &[AgentId]) -> (String, String) {
        let admin = state.agent.agent_id();
        let admin_hex = hex::encode(admin.as_bytes());
        let group_id = "d5".repeat(16);
        let mut info =
            x0x::groups::GroupInfo::new("kr".into(), String::new(), admin, group_id.clone());
        for member in members {
            info.add_member(
                hex::encode(member.as_bytes()),
                x0x::groups::GroupRole::Member,
                Some(admin_hex.clone()),
                None,
            );
        }
        info.recompute_state_hash();
        assert!(x0x::groups::crypto_exclusion::is_gss_encrypted(&info));
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
        (group_id, stable)
    }

    async fn edit_group(
        state: &AppState,
        group_key: &str,
        edit: impl FnOnce(&mut x0x::groups::GroupInfo),
    ) {
        if let Some(info) = state.named_groups.write().await.get_mut(group_key) {
            edit(info);
        }
    }

    async fn revoke(state: &AppState, kp: &x0x::identity::AgentKeypair) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(kp.agent_id()),
            kp.public_key(),
            kp.secret_key(),
            now,
            None,
        )?;
        let revocation_set = state.agent.revocation_set();
        let inserted = revocation_set
            .write()
            .await
            .verify_and_insert(record, None)?;
        assert!(inserted, "the self-revocation is new");
        assert!(revocation_set.read().await.is_agent_revoked(&kp.agent_id()));
        Ok(())
    }

    /// A signed `X0XKR1` frame by `actor` that seats `state`'s KEM key.
    fn frame(
        state: &AppState,
        actor: &x0x::identity::AgentKeypair,
        stable: &str,
        key_sequence: u64,
    ) -> Result<Vec<u8>> {
        let b64 = &base64::engine::general_purpose::STANDARD;
        let body = kr::MemberKeyRepublishBodyV1 {
            stable_group_id: stable.to_string(),
            actor: *actor.agent_id().as_bytes(),
            agent_public_key_b64: b64.encode(actor.public_key().as_bytes()),
            kem_public_key_b64: b64.encode(&state.agent_kem_keypair.public_bytes),
            key_sequence,
        };
        let signed = kr::sign(body, actor).map_err(|refusal| anyhow::anyhow!(refusal.as_str()))?;
        Ok(kr::encode_frame(&signed)?)
    }

    const INELIGIBLE: RepublishOutcome =
        RepublishOutcome::Refused(kr::MemberKeyRepublishRefusal::ActorIneligible);

    /// The sweep drops the debt of a recipient that is Removed, Banned,
    /// absent or revoked; an Active, unrevoked recipient stays owed.
    #[tokio::test]
    async fn key_republish_sweep_drops_a_departed_or_revoked_recipient() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let revoked_kp = x0x::identity::AgentKeypair::generate()?;
        let removed = AgentId([0x31; 32]);
        let banned = AgentId([0x32; 32]);
        let active = AgentId([0x33; 32]);
        let absent = AgentId([0x34; 32]);
        let revoked = revoked_kp.agent_id();
        let (group_key, stable) = gss_group(&state, &[removed, banned, active, revoked]).await;
        record_pending_republish(
            &state,
            &stable,
            vec![7, 7, 7],
            &[
                *removed.as_bytes(),
                *banned.as_bytes(),
                *active.as_bytes(),
                *absent.as_bytes(),
                *revoked.as_bytes(),
            ],
        );
        assert_eq!(pending_republish_owed(&state, &stable).len(), 5);
        edit_group(&state, &group_key, |info| {
            info.remove_member(&hex::encode(removed.as_bytes()), None);
            info.ban_member(&hex::encode(banned.as_bytes()), None);
        })
        .await;
        revoke(&state, &revoked_kp).await?;
        pending_republish_due_now(&state);
        assert!(sweep_pending_key_republishes(&state).await);
        assert_eq!(
            pending_republish_owed(&state, &stable),
            vec![hex::encode(active.as_bytes())],
            "only the Active, unrevoked recipient stays owed"
        );
        Ok(())
    }

    /// (a) A relay from a sender that is not an Active member is refused,
    /// though the actor's own seat is sound: the same frame from an
    /// Active relaying member seats the key.
    #[tokio::test]
    async fn key_republish_receive_refuses_a_relay_from_a_non_member() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let actor = x0x::identity::AgentKeypair::generate()?;
        let relay = AgentId([0x42; 32]);
        let (_, stable) = gss_group(&state, &[actor.agent_id(), relay]).await;
        let payload = frame(&state, &actor, &stable, 1)?;
        let outsider = AgentId([0x41; 32]);
        assert_eq!(receive(&state, outsider, &payload).await, INELIGIBLE);
        assert_eq!(
            receive(&state, relay, &payload).await,
            RepublishOutcome::Installed,
            "the control: an Active member's relay of the same frame seats it"
        );
        Ok(())
    }

    /// (b) A revoked sender, and a revoked actor, are refused.
    #[tokio::test]
    async fn key_republish_receive_refuses_a_revoked_actor_or_sender() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let actor = x0x::identity::AgentKeypair::generate()?;
        let relay = x0x::identity::AgentKeypair::generate()?;
        let (_, stable) = gss_group(&state, &[actor.agent_id(), relay.agent_id()]).await;
        let payload = frame(&state, &actor, &stable, 1)?;
        revoke(&state, &relay).await?;
        assert_eq!(
            receive(&state, relay.agent_id(), &payload).await,
            INELIGIBLE,
            "a revoked relaying member"
        );
        revoke(&state, &actor).await?;
        assert_eq!(
            receive(&state, actor.agent_id(), &payload).await,
            INELIGIBLE,
            "a revoked actor sending its own frame"
        );
        Ok(())
    }

    /// (c) A frame for a group this node does not hold is not applicable.
    #[tokio::test]
    async fn key_republish_receive_of_an_unknown_group_is_not_applicable() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let actor = x0x::identity::AgentKeypair::generate()?;
        let payload = frame(&state, &actor, &"e7".repeat(32), 1)?;
        assert_eq!(
            receive(&state, actor.agent_id(), &payload).await,
            RepublishOutcome::NotApplicable
        );
        Ok(())
    }

    /// (d) A Banned seat is not Active: `validate_against_seat` refuses
    /// the actor, and nothing seats.
    #[tokio::test]
    async fn key_republish_receive_refuses_a_banned_seat() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let actor = x0x::identity::AgentKeypair::generate()?;
        let actor_hex = hex::encode(actor.agent_id().as_bytes());
        let (group_key, stable) = gss_group(&state, &[actor.agent_id()]).await;
        edit_group(&state, &group_key, |info| info.ban_member(&actor_hex, None)).await;
        let payload = frame(&state, &actor, &stable, 1)?;
        assert_eq!(
            receive(&state, actor.agent_id(), &payload).await,
            INELIGIBLE
        );
        assert!(state
            .named_groups
            .read()
            .await
            .get(&group_key)
            .and_then(|info| info.members_v2.get(&actor_hex))
            .is_some_and(|seat| seat.kem_key_sequence.is_none()));
        Ok(())
    }
}
