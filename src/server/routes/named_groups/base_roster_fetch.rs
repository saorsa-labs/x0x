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

/// How long a parked reply stays before it is dropped. A parked projection
/// cannot go STALE (it is content-addressed), so the TTL only bounds cache
/// occupancy: unsolicited-but-valid replies for keys no join will ever ask
/// for age out instead of pinning [`READY_SLOT_CAP`] slots forever.
const READY_SLOT_TTL: Duration = Duration::from_secs(60);

/// Distinguishes each parked join's sender inside a shared
/// [`BaseRosterSlot::Waiter`], so a timed-out join removes only its own.
static NEXT_WAITER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The digest-only projection map a fetch moves.
pub(in crate::server) type BaseRosterProjection =
    BTreeMap<String, x0x::groups::state_commit::RosterMemberSnapshot>;

/// One slot per `(stable group, roster root)`: the joins waiting for the
/// projection, or a verified projection that arrived first.
pub(in crate::server) enum BaseRosterSlot {
    /// Joins parked on this key. Concurrent joins on the same key SHARE
    /// the slot — each parks its own `(waiter id, sender)` pair, and one
    /// reply wakes them all.
    Waiter(Vec<(u64, tokio::sync::oneshot::Sender<BaseRosterProjection>)>),
    /// A verified projection arrived with no waiter (a duplicate reply, a
    /// reply racing the retry, or a test pre-seeding the exchange), with
    /// the instant it parked for [`READY_SLOT_TTL`] eviction.
    Ready(BaseRosterProjection, std::time::Instant),
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
        Some(BaseRosterSlot::Waiter(waiters)) => {
            // Every join parked on this key gets the projection. A dropped
            // receiver (that join timed out) is harmless.
            for (_, waiter) in waiters {
                let _ = waiter.send(digest_only.clone());
            }
        }
        Some(existing @ BaseRosterSlot::Ready(..)) => {
            // Keep the existing copy (identical by content address) and
            // its original parking instant — a resent reply must not keep
            // refreshing its own slot past the TTL.
            slots.insert(key, existing);
        }
        None => {
            // Self-cleaning park: expired entries go first, and at cap the
            // OLDEST parked reply is evicted, so unsolicited-but-valid
            // replies cannot pin the cache forever.
            slots.retain(|_, slot| {
                !matches!(slot, BaseRosterSlot::Ready(_, parked)
                    if parked.elapsed() >= READY_SLOT_TTL)
            });
            let ready_count = slots
                .values()
                .filter(|slot| matches!(slot, BaseRosterSlot::Ready(..)))
                .count();
            if ready_count >= READY_SLOT_CAP {
                let oldest = slots
                    .iter()
                    .filter_map(|(key, slot)| match slot {
                        BaseRosterSlot::Ready(_, parked) => Some((key.clone(), *parked)),
                        BaseRosterSlot::Waiter(_) => None,
                    })
                    .min_by_key(|(_, parked)| *parked)
                    .map(|(key, _)| key);
                if let Some(oldest) = oldest {
                    slots.remove(&oldest);
                }
            }
            slots.insert(
                key,
                BaseRosterSlot::Ready(digest_only, std::time::Instant::now()),
            );
            tracing::debug!(
                group_id = %LogHexId::group(group_id),
                "parked a verified base-roster reply with no waiter"
            );
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
    let waiter_id = NEXT_WAITER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    {
        let mut slots = state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match slots.remove(&key) {
            // A parked projection cannot go stale (content-addressed), so
            // any Ready copy answers regardless of its age.
            Some(BaseRosterSlot::Ready(roster, _)) => return Ok(roster),
            // A concurrent join (or an abandoned one whose sender is now
            // closed) already waits on this key: SHARE the slot instead of
            // replacing its sender, which would fail that join with a 503.
            Some(BaseRosterSlot::Waiter(mut waiters)) => {
                waiters.push((waiter_id, sender));
                slots.insert(key.clone(), BaseRosterSlot::Waiter(waiters));
            }
            None => {
                slots.insert(
                    key.clone(),
                    BaseRosterSlot::Waiter(vec![(waiter_id, sender)]),
                );
            }
        }
    }
    let remove_slot = || {
        let mut slots = state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Only THIS join's waiter is removed; concurrent joins' waiters
        // and a Ready parked meanwhile stay for them and for the retry.
        if let Some(BaseRosterSlot::Waiter(waiters)) = slots.get_mut(&key) {
            waiters.retain(|(id, _)| *id != waiter_id);
            if waiters.is_empty() {
                slots.remove(&key);
            }
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
