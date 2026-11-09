//! #646 (D13/W4): content-addressed base-roster fetch for v5 invites.
//!
//! A v5 invite names its base roster by CONTENT ADDRESS (the roster root)
//! instead of carrying the projection inline. Before installing any local
//! state, the joiner asks the INVITER for the projection
//! ([`super::JoinResultMessage::BaseRosterFetch`]) and admits the answer
//! ([`super::JoinResultMessage::BaseRoster`]) only when it comes VERIFIED
//! from the expected inviter, answers a WAITING join, and re-derives the
//! invite's SIGNED root. Proof of invite possession rides as the BLAKE3 of
//! the raw invite secret: the inviter serves only while a live
//! issued-invite record hashes to it, so the roster never leaks to peers
//! without the invite. This builds on the fetch-by-hash direction D34(3)
//! assigned to the liveness contract (ADR 0088 / archived ADR 0111): a
//! bounded inline carrier, and past it a hash reference fetched from a
//! holder.
//!
//! Review r3 (blocker 1): the roster root (`roster_root_from_entries`)
//! commits to id, role, state and certificate digest — NOT to
//! `treekem_key_package_hash`. A fetched projection's key-package anchors
//! are therefore unauthenticated, so they are STRIPPED on receipt (and on
//! serve), a reply is accepted only from the join's own inviter, and
//! nothing is cached for a reply no join asked for.

use super::*;

/// How long one join waits for the inviter to serve the projection. The
/// join route returns a typed retryable 503 past it; the caller re-joins.
pub(in crate::server) const BASE_ROSTER_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Distinguishes each parked join's sender inside a shared waiter list,
/// so a timed-out or cancelled join removes only its own.
static NEXT_WAITER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The digest-only projection map a fetch moves.
pub(in crate::server) type BaseRosterProjection =
    BTreeMap<String, x0x::groups::state_commit::RosterMemberSnapshot>;

/// One join parked on a `(stable group, roster root)` key, bound to the
/// inviter its invite names: a reply wakes it only when that inviter sent
/// it. Concurrent joins on one key each park their own waiter.
pub(in crate::server) struct BaseRosterWaiter {
    id: u64,
    inviter: AgentId,
    sender: tokio::sync::oneshot::Sender<BaseRosterProjection>,
}

impl BaseRosterWaiter {
    /// Test seam: a parked waiter expecting `inviter`.
    #[cfg(test)]
    pub(in crate::server) fn for_test(
        inviter: AgentId,
        sender: tokio::sync::oneshot::Sender<BaseRosterProjection>,
    ) -> Self {
        Self {
            id: NEXT_WAITER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            inviter,
            sender,
        }
    }
}

/// The slot key: the stable group id and the content address together.
fn slot_key(stable_group_id: &str, roster_root: &str) -> String {
    format!("{stable_group_id}|{roster_root}")
}

/// Review r3 (blocker 1): a fetched projection is certificate-free AND
/// anchor-free. The roster root does not commit `treekem_key_package_hash`
/// (`roster_root_from_entries` hashes id, role, state and certificate
/// digest only), so a served anchor is whatever the sender chose — the
/// authority's signed commits carry the real anchors later.
fn sanitize_fetched(roster: &BaseRosterProjection) -> BaseRosterProjection {
    roster
        .iter()
        .map(|(id, snap)| {
            let mut snap = snap.clone();
            snap.certificate = None;
            snap.treekem_key_package_hash = None;
            (id.clone(), snap)
        })
        .collect()
}

#[cfg(test)]
static TEST_PRESEEDED_PROJECTIONS: std::sync::LazyLock<
    StdMutex<HashMap<String, BaseRosterProjection>>,
> = std::sync::LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Test seam (consumed on use): satisfy one `obtain_base_roster` call
/// without any network, standing in for the inviter's serve so the real
/// join route runs socket-free. The projection still has to re-derive the
/// SIGNED root inside `obtain_base_roster`, exactly like a served reply.
#[cfg(test)]
pub(in crate::server) fn preseed_fetched_projection_for_test(
    stable_group_id: &str,
    roster_root: &str,
    roster: BaseRosterProjection,
) {
    TEST_PRESEEDED_PROJECTIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(slot_key(stable_group_id, roster_root), roster);
}

/// Joiner side: admit one `BaseRoster` reply from `sender`. The payload is
/// admitted only when a join is WAITING on this key with `sender` as its
/// expected inviter, and only when it re-derives `roster_root` over its
/// own sanitized bytes (content addressing; certificates and key-package
/// anchors stripped first — see [`sanitize_fetched`]). A reply no waiting
/// join asked for is dropped: nothing is cached.
pub(in crate::server) fn deliver_base_roster(
    state: &Arc<AppState>,
    sender: &AgentId,
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
    // r4 item 8: the root encoding joins entries without a length prefix,
    // so entry keys and states are validated structurally — ids are
    // strict 64 lowercase hex, and a base projection carries only Active
    // and Banned seats (what the inline v4 carrier holds).
    let well_formed = roster.iter().all(|(id, snap)| {
        id.len() == 64
            && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            && matches!(
                snap.state,
                x0x::groups::GroupMemberState::Active | x0x::groups::GroupMemberState::Banned
            )
    });
    if !well_formed {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster reply with malformed entry keys or states"
        );
        return;
    }
    let sanitized = sanitize_fetched(roster);
    if x0x::groups::state_commit::roster_root_of_projection(&sanitized) != roster_root {
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
    let Some(waiters) = slots.remove(&key) else {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster reply no join is waiting for"
        );
        return;
    };
    // Wake ONLY the joins whose invite names this sender as the inviter;
    // a join waiting on another inviter keeps waiting. A dropped receiver
    // (that join timed out) is harmless.
    let mut woken = false;
    let mut kept = Vec::with_capacity(waiters.len());
    for waiter in waiters {
        if waiter.inviter == *sender {
            woken = true;
            let _ = waiter.sender.send(sanitized.clone());
        } else {
            kept.push(waiter);
        }
    }
    if !kept.is_empty() {
        slots.insert(key, kept);
    }
    if !woken {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster reply from a peer no waiting join named as its inviter"
        );
    }
}

/// Removes one join's own waiter on every exit from
/// [`obtain_base_roster`], including cancellation (the HTTP client
/// disconnecting drops the join future). A waiter already consumed by a
/// delivery is simply not found.
struct WaiterGuard<'a> {
    state: &'a Arc<AppState>,
    key: &'a str,
    id: u64,
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        let mut slots = self
            .state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(waiters) = slots.get_mut(self.key) {
            waiters.retain(|waiter| waiter.id != self.id);
            if waiters.is_empty() {
                slots.remove(self.key);
            }
        }
    }
}

/// Joiner side: obtain the projection `signed_root` names by one
/// `BaseRosterFetch` round trip to the inviter bounded by `timeout`. The
/// answer is accepted only from `inviter` (delivery matches the sender
/// against this join's waiter) and only when it re-derives `signed_root`.
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
    #[cfg(test)]
    {
        let preseeded = TEST_PRESEEDED_PROJECTIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        if let Some(roster) = preseeded {
            let sanitized = sanitize_fetched(&roster);
            if x0x::groups::state_commit::roster_root_of_projection(&sanitized) == signed_root {
                return Ok(sanitized);
            }
            return Err("served roster does not re-derive the signed root");
        }
    }
    let waiter_id = NEXT_WAITER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    {
        let mut slots = state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slots
            .entry(key.clone())
            .or_default()
            .push(BaseRosterWaiter {
                id: waiter_id,
                inviter,
                sender,
            });
    }
    // Review r3 item 8: the guard removes THIS join's waiter on every
    // exit — error, timeout, and cancellation alike — and never another
    // join's. A waiter a delivery already consumed is simply not found.
    let _guard = WaiterGuard {
        state,
        key: &key,
        id: waiter_id,
    };
    let request = JoinResultMessage::BaseRosterFetch {
        group_id: stable_group_id.to_string(),
        member_agent_id: hex::encode(state.agent.agent_id().as_bytes()),
        roster_root: signed_root.to_string(),
        secret_hash: secret_hash_hex.to_string(),
    };
    let Ok(payload) = serde_json::to_vec(&request) else {
        return Err("request serialization failed");
    };
    // r4 item 6: ONE timeout bounds the whole exchange — the send's own
    // internal retries included — so a v5 join never waits past the fetch
    // window before its typed retryable 503.
    let exchange = async {
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
            // The reply can have raced the send failure in on another leg
            // (an earlier attempt's answer); a delivered projection was
            // already verified against this key's root.
            return match receiver.try_recv() {
                Ok(roster)
                    if x0x::groups::state_commit::roster_root_of_projection(&roster)
                        == signed_root =>
                {
                    Ok(roster)
                }
                _ => Err("inviter unreachable"),
            };
        }
        match receiver.await {
            Ok(roster) => {
                // Defense in depth: the delivery already verified the
                // payload against this key's root; re-derive once more
                // against the SIGNED root before anything seeds from it.
                if x0x::groups::state_commit::roster_root_of_projection(&roster) != signed_root {
                    return Err("served roster does not re-derive the signed root");
                }
                Ok(roster)
            }
            Err(_) => Err("no answer from the inviter within the fetch window"),
        }
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => Err("no answer from the inviter within the fetch window"),
    }
}

/// Inviter side, the pure half of the serve. r4 blocker 1 (D95, archived
/// ADR 0111; A08:71 — "a pre-member gets no other kind and no other
/// root"):
/// - the requester must not sit Banned or Removed on the live roster;
/// - possession of a LIVE issued-invite record (unconsumed, unexpired)
///   whose raw 32-byte secret BLAKE3-hashes to `secret_hash`, compared in
///   constant time through [`blake3::Hash`] equality (r4 item 4);
/// - an ADDRESSED invite is served only to its `intended_joiner`;
/// - ONLY the root that invite signed at mint
///   (`IssuedInviteRecord::base_roster_root`) is served — the live roster
///   when its root still matches, else the retained commit with that
///   signed root (an invite minted a few commits ago stays serveable); a
///   v4 record binds no root and serves nothing.
///
/// The served projection is certificate-free and anchor-free (see
/// [`sanitize_fetched`]), and only within the fetch entry cap.
pub(in crate::server) fn locate_served_base_roster(
    info: &x0x::groups::GroupInfo,
    requester_hex: &str,
    roster_root: &str,
    secret_hash: &str,
    now_secs: u64,
) -> Option<BaseRosterProjection> {
    if info.members_v2.get(requester_hex).is_some_and(|seat| {
        matches!(
            seat.state,
            x0x::groups::GroupMemberState::Banned | x0x::groups::GroupMemberState::Removed
        )
    }) {
        return None;
    }
    let requested: [u8; 32] = hex::decode(secret_hash).ok()?.try_into().ok()?;
    let requested = blake3::Hash::from(requested);
    let record = info.issued_invites.iter().find_map(|(secret, record)| {
        if record.consumed_by.is_some()
            || (record.expires_at_secs != 0 && record.expires_at_secs <= now_secs)
        {
            return None;
        }
        let raw = hex::decode(secret).ok()?;
        // blake3::Hash equality is constant-time.
        (raw.len() == 32 && blake3::hash(&raw) == requested).then_some(record)
    })?;
    if record
        .intended_joiner
        .as_deref()
        .is_some_and(|intended| !intended.eq_ignore_ascii_case(requester_hex))
    {
        return None;
    }
    if record.base_roster_root.as_deref() != Some(roster_root) {
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
            .map(|entry| entry.roster.clone())
    };
    roster
        .map(|roster| sanitize_fetched(&roster))
        .filter(|roster| roster.len() <= x0x::groups::invite::MAX_FETCHED_BASE_ROSTER_ENTRIES)
}

/// Inviter side: send one located, sanitized projection back to the
/// requester. Authorization and location already ran in the dispatch arm
/// UNDER the groups read lock and BEFORE the admission ticket (r4 item 5:
/// an unauthorized request never takes a ticket; r3 item 6: it never
/// clones the group record either).
pub(in crate::server) async fn send_base_roster_reply(
    state: &Arc<AppState>,
    requester: &AgentId,
    stable_group_id: String,
    roster_root: String,
    roster: BaseRosterProjection,
) {
    let reply = JoinResultMessage::BaseRoster {
        group_id: stable_group_id,
        roster_root,
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
        tracing::debug!("base-roster reply send failed: {e}");
    }
}
