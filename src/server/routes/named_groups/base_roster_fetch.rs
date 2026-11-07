//! #646 (D13/W4): content-addressed base-roster fetch for v5 invites.
//!
//! A v5 invite names its base roster by CONTENT ADDRESS (the roster root)
//! instead of carrying the projection inline. Before installing any local
//! state, the joiner asks the INVITER for the projection
//! ([`super::JoinResultMessage::BaseRosterFetch`]) and admits the answer
//! ([`super::JoinResultMessage::BaseRoster`]) only when it re-derives the
//! invite's SIGNED root — the payload is self-certifying, so neither the
//! serving peer nor the transport needs any further trust. Proof of invite
//! possession rides as the BLAKE3 of the raw invite secret: the inviter
//! serves only while a live issued-invite record hashes to it, so the
//! roster never leaks to peers without the invite. This builds on the
//! fetch-by-hash direction D34(3) assigned to the liveness contract
//! (ADR 0088 / archived ADR 0111): a bounded inline carrier, and
//! past it a hash reference fetched from a holder.

use super::*;

/// How long one join waits for the inviter to serve the projection. The
/// join route returns a typed retryable 503 past it; the caller re-joins.
pub(in crate::server) const BASE_ROSTER_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on parked [`BaseRosterSlot::Ready`] entries. Entries are
/// content-verified before parking (a mismatching payload is dropped), so
/// the cache can hold only rosters that match their own key; the bound
/// keeps a burst of unsolicited-but-valid replies from growing the map.
const READY_SLOT_CAP: usize = 16;

/// The digest-only projection map a fetch moves.
pub(in crate::server) type BaseRosterProjection =
    BTreeMap<String, x0x::groups::state_commit::RosterMemberSnapshot>;

/// One slot per `(stable group, roster root)`: a join waiting for the
/// projection, or a verified projection that arrived first.
pub(in crate::server) enum BaseRosterSlot {
    /// A join is parked on this key.
    Waiter(tokio::sync::oneshot::Sender<BaseRosterProjection>),
    /// A verified projection arrived with no waiter (a duplicate reply, a
    /// reply racing the retry, or a test pre-seeding the exchange).
    Ready(BaseRosterProjection),
}

/// The slot key: the stable group id and the content address together.
fn slot_key(stable_group_id: &str, roster_root: &str) -> String {
    format!("{stable_group_id}|{roster_root}")
}

/// Joiner side: admit one `BaseRoster` reply. The payload is admitted only
/// when it re-derives `roster_root` over its own bytes (content
/// addressing), with certificate bytes stripped first — the projection a
/// v4 link would have carried is digest-only, and the root ignores the
/// bytes either way. A verified payload wakes the parked join, or parks as
/// [`BaseRosterSlot::Ready`] under [`READY_SLOT_CAP`].
pub(in crate::server) fn deliver_base_roster(
    state: &Arc<AppState>,
    group_id: &str,
    roster_root: &str,
    roster: &BaseRosterProjection,
) {
    if roster.len() > x0x::groups::invite::MAX_FETCHED_BASE_ROSTER_ENTRIES {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            entries = roster.len(),
            "dropped base-roster reply past the fetch entry cap"
        );
        return;
    }
    let digest_only: BaseRosterProjection = roster
        .iter()
        .map(|(id, snap)| {
            let mut snap = snap.clone();
            snap.certificate = None;
            (id.clone(), snap)
        })
        .collect();
    if x0x::groups::state_commit::roster_root_of_projection(&digest_only) != roster_root {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster reply that does not re-derive its own root"
        );
        return;
    }
    let key = slot_key(group_id, roster_root);
    let mut slots = state
        .base_roster_fetch_slots
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match slots.remove(&key) {
        Some(BaseRosterSlot::Waiter(waiter)) => {
            // A dropped receiver (the join timed out) is harmless.
            let _ = waiter.send(digest_only);
        }
        other => {
            // Keep an existing Ready copy (identical by content address),
            // or park this one while the cache has room.
            let occupied = matches!(other, Some(BaseRosterSlot::Ready(_)));
            if let Some(existing) = other {
                slots.insert(key, existing);
            } else if slots.len() < READY_SLOT_CAP {
                slots.insert(key, BaseRosterSlot::Ready(digest_only));
            }
            if !occupied {
                tracing::debug!(
                    group_id = %LogHexId::group(group_id),
                    "parked a verified base-roster reply with no waiter"
                );
            }
        }
    }
}

/// Joiner side: obtain the projection `signed_root` names — from a parked
/// verified copy when one exists, else by one `BaseRosterFetch` round trip
/// to the inviter bounded by `timeout`.
///
/// # Errors
///
/// A static reason when the inviter could not be asked or did not answer
/// in time; the join route maps it to a retryable typed 503.
pub(in crate::server) async fn obtain_base_roster(
    state: &Arc<AppState>,
    inviter: AgentId,
    stable_group_id: &str,
    signed_root: &str,
    secret_hash_hex: &str,
    timeout: Duration,
) -> Result<BaseRosterProjection, &'static str> {
    let key = slot_key(stable_group_id, signed_root);
    let receiver = {
        let mut slots = state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match slots.remove(&key) {
            Some(BaseRosterSlot::Ready(roster)) => return Ok(roster),
            // A stale waiter from an abandoned join is replaced below.
            Some(BaseRosterSlot::Waiter(_)) | None => {}
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        slots.insert(key.clone(), BaseRosterSlot::Waiter(sender));
        receiver
    };
    let remove_slot = || {
        let mut slots = state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Only this join's waiter is removed; a Ready parked meanwhile
        // stays for the retry.
        if matches!(slots.get(&key), Some(BaseRosterSlot::Waiter(_))) {
            slots.remove(&key);
        }
    };
    let request = JoinResultMessage::BaseRosterFetch {
        group_id: stable_group_id.to_string(),
        member_agent_id: hex::encode(state.agent.agent_id().as_bytes()),
        roster_root: signed_root.to_string(),
        secret_hash: secret_hash_hex.to_string(),
    };
    let payload = match serde_json::to_vec(&request) {
        Ok(payload) => payload,
        Err(_) => {
            remove_slot();
            return Err("request serialization failed");
        }
    };
    if let Err(e) = state
        .agent
        .send_direct_with_config(&inviter, payload, direct_message_send_config())
        .await
    {
        // #1776: a fresh joiner may hold no DM binding for the inviter
        // yet — ask the mesh for its advert so a retry can ride the
        // gossip-inbox leg.
        if !state.agent.holds_gossip_usable_dm_binding(&inviter) {
            let agent = Arc::clone(&state.agent);
            tokio::spawn(async move {
                agent.refresh_dm_capability_binding(inviter).await;
            });
        }
        tracing::debug!("base-roster fetch send failed: {e}");
        remove_slot();
        return Err("inviter unreachable");
    }
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(roster)) => {
            // Defense in depth: the delivery already verified the payload
            // against this key's root; re-derive once more against the
            // SIGNED root before anything seeds from it.
            if x0x::groups::state_commit::roster_root_of_projection(&roster) != signed_root {
                remove_slot();
                return Err("served roster does not re-derive the signed root");
            }
            Ok(roster)
        }
        Ok(Err(_)) | Err(_) => {
            remove_slot();
            Err("no answer from the inviter within the fetch window")
        }
    }
}

/// Inviter side, the pure half of the serve: authorize by invite
/// possession (a LIVE issued-invite record — unconsumed, unexpired —
/// whose raw 32-byte secret BLAKE3-hashes to `secret_hash`), then locate
/// the projection the CONTENT ADDRESS names: the live roster when its
/// root matches, else the retained commit whose signed `roster_root`
/// matches (so an invite minted a few commits ago is still serveable).
/// Always digest-only, and only within the fetch entry cap.
pub(in crate::server) fn locate_served_base_roster(
    info: &x0x::groups::GroupInfo,
    roster_root: &str,
    secret_hash: &str,
    now_secs: u64,
) -> Option<BaseRosterProjection> {
    let authorized = info.issued_invites.iter().any(|(secret, record)| {
        if record.consumed_by.is_some()
            || (record.expires_at_secs != 0 && record.expires_at_secs <= now_secs)
        {
            return false;
        }
        hex::decode(secret).is_ok_and(|raw| {
            raw.len() == 32 && hex::encode(blake3::hash(&raw).as_bytes()) == secret_hash
        })
    });
    if !authorized {
        return None;
    }
    let live = x0x::groups::state_commit::roster_projection_digest_only(&info.members_v2);
    let roster = if x0x::groups::state_commit::roster_root_of_projection(&live) == roster_root {
        Some(live)
    } else {
        info.commit_log
            .iter()
            .rev()
            .find(|entry| entry.commit.roster_root == roster_root && entry.roster_root_consistent())
            .map(|entry| {
                entry
                    .roster
                    .iter()
                    .map(|(id, snap)| {
                        let mut snap = snap.clone();
                        snap.certificate = None;
                        (id.clone(), snap)
                    })
                    .collect::<BaseRosterProjection>()
            })
    };
    roster.filter(|roster| roster.len() <= x0x::groups::invite::MAX_FETCHED_BASE_ROSTER_ENTRIES)
}

/// Inviter side: answer one authorized `BaseRosterFetch`.
///
/// Authorization is possession of the invite: a LIVE issued-invite record
/// (unconsumed, unexpired) whose raw 32-byte secret hashes (BLAKE3) to
/// `secret_hash`. The served projection is located by CONTENT ADDRESS —
/// the live roster when its root matches, else the retained commit whose
/// signed `roster_root` matches (so an invite minted a few commits ago is
/// still serveable) — always digest-only, and only within the fetch entry
/// cap. Anything else is silently dropped; the joiner retries.
pub(in crate::server) async fn serve_base_roster_fetch(
    state: &Arc<AppState>,
    requester: &AgentId,
    group_id: &str,
    roster_root: &str,
    secret_hash: &str,
) {
    let info = {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, group_id).map(|(_, info)| info.clone())
    };
    let Some(info) = info else {
        tracing::debug!(group_id = %LogHexId::group(group_id), "base-roster fetch for an unknown group; dropped");
        return;
    };
    let now_secs = now_millis_u64() / 1_000;
    let Some(roster) = locate_served_base_roster(&info, roster_root, secret_hash, now_secs) else {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            requester = %LogHexId::agent(&hex::encode(requester.as_bytes())),
            "base-roster fetch refused: no live matching invite, no held root, or over the entry cap"
        );
        return;
    };
    let reply = JoinResultMessage::BaseRoster {
        group_id: info.stable_group_id().to_string(),
        roster_root: roster_root.to_string(),
        roster,
    };
    let Ok(payload) = serde_json::to_vec(&reply) else {
        return;
    };
    if let Err(e) = state
        .agent
        .send_direct_with_config(requester, payload, direct_message_send_config())
        .await
    {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "base-roster reply send failed: {e}"
        );
    }
}
