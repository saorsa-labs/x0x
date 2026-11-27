//! #646 (D13/W4): content-addressed base-roster fetch for v6 invites.
//!
//! A v6 invite names its base roster by CONTENT ADDRESS (the roster root)
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

/// What a waiting join is woken with.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::server) enum BaseRosterFetchReply {
    /// The inviter served a verified projection.
    Served(BaseRosterProjection),
    /// r5 item 6: the inviter answered that this invite's signed root is
    /// in neither its live roster nor its retained commit log any more —
    /// TERMINAL, no retry can serve it.
    Unavailable,
}

/// How [`obtain_base_roster`] fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum ObtainBaseRosterError {
    /// The inviter could not be asked or did not answer in time; the join
    /// route maps it to the retryable typed 503.
    Retryable(&'static str),
    /// r5 item 6: the inviter answered that the invite's signed root is
    /// pruned — the join route maps it to a TERMINAL typed refusal.
    Pruned,
}

/// One join parked on a `(stable group, roster root)` key, bound to the
/// inviter its invite names: a reply wakes it only when that inviter sent
/// it. Concurrent joins on one key each park their own waiter.
pub(in crate::server) struct BaseRosterWaiter {
    id: u64,
    inviter: AgentId,
    sender: tokio::sync::oneshot::Sender<BaseRosterFetchReply>,
}

impl BaseRosterWaiter {
    /// Test seam: a parked waiter expecting `inviter`.
    #[cfg(test)]
    pub(in crate::server) fn for_test(
        inviter: AgentId,
        sender: tokio::sync::oneshot::Sender<BaseRosterFetchReply>,
    ) -> Self {
        Self {
            id: NEXT_WAITER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            inviter,
            sender,
        }
    }
}

/// Wake every waiter on `key` whose expected inviter is `sender` with
/// `reply`; the others keep waiting. Returns whether any join was woken.
fn wake_matching_waiters(
    state: &Arc<AppState>,
    sender: &AgentId,
    key: &str,
    reply: &BaseRosterFetchReply,
) -> bool {
    let mut slots = state
        .base_roster_fetch_slots
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(waiters) = slots.remove(key) else {
        return false;
    };
    let mut woken = false;
    let mut kept = Vec::with_capacity(waiters.len());
    for waiter in waiters {
        if waiter.inviter == *sender {
            woken = true;
            // A dropped receiver (that join timed out) is harmless.
            let _ = waiter.sender.send(reply.clone());
        } else {
            kept.push(waiter);
        }
    }
    if !kept.is_empty() {
        slots.insert(key.to_string(), kept);
    }
    woken
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

#[cfg(test)]
static TEST_PRESEEDED_PRUNED: std::sync::LazyLock<StdMutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| StdMutex::new(std::collections::HashSet::new()));

/// Test seam (consumed on use): make one `obtain_base_roster` call answer
/// [`ObtainBaseRosterError::Pruned`], standing in for the inviter's
/// `BaseRosterUnavailable` answer.
#[cfg(test)]
pub(in crate::server) fn preseed_pruned_answer_for_test(stable_group_id: &str, roster_root: &str) {
    TEST_PRESEEDED_PRUNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(slot_key(stable_group_id, roster_root));
}

/// Test tripwire: true while a preseeded projection for this key is still
/// UNCONSUMED — a join that fetched would have eaten it, so this proves a
/// fetch-skip path never asked.
#[cfg(test)]
pub(in crate::server) fn preseeded_projection_untouched_for_test(
    stable_group_id: &str,
    roster_root: &str,
) -> bool {
    TEST_PRESEEDED_PROJECTIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains_key(&slot_key(stable_group_id, roster_root))
}

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

/// Bounded chunk reassembly buffer for a multi-chunk v6 base-roster reply
/// (>128 Active+Banned entries). Created only when a waiter for
/// `(stable_group_id|roster_root, sender)` is already parked, and cleared when
/// assembly completes or the waiter drops.
pub(in crate::server) struct BaseRosterChunkAssembly {
    total_chunks: u16,
    received_chunks: std::collections::BTreeSet<u16>,
    entries: BaseRosterProjection,
}

fn validate_projection_entries(roster: &BaseRosterProjection) -> bool {
    let is_hex64 =
        |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    roster.iter().all(|(id, snap)| {
        is_hex64(id)
            && snap.certificate_digest.as_deref().is_none_or(is_hex64)
            && snap.role != x0x::groups::GroupRole::Unknown
            && matches!(
                snap.state,
                x0x::groups::GroupMemberState::Active | x0x::groups::GroupMemberState::Banned
            )
    })
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
    if !validate_projection_entries(roster) {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster reply with malformed entry keys, digests, roles or states"
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
    // Wake ONLY the joins whose invite names this sender as the inviter;
    // a join waiting on another inviter keeps waiting.
    let key = slot_key(group_id, roster_root);
    if !wake_matching_waiters(
        state,
        sender,
        &key,
        &BaseRosterFetchReply::Served(sanitized),
    ) {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster reply no waiting join asked this sender for"
        );
    }
}

/// Joiner side: admit one chunk of a multi-chunk `BaseRosterChunk` reply from
/// `sender`. Chunks are buffered ONLY while a join is waiting on
/// `(group_id|roster_root, sender)`, bounded to `MAX_BASE_ROSTER_CHUNKS`
/// chunks of `MAX_FETCHED_BASE_ROSTER_ENTRIES` entries each, and wake waiters
/// only once every chunk has arrived and the reassembled sanitized projection
/// re-derives `roster_root`.
pub(in crate::server) fn deliver_base_roster_chunk(
    state: &Arc<AppState>,
    sender: &AgentId,
    group_id: &str,
    roster_root: &str,
    chunk_index: u16,
    total_chunks: u16,
    entries: &BaseRosterProjection,
) {
    if total_chunks == 0
        || total_chunks > x0x::groups::invite::MAX_BASE_ROSTER_CHUNKS
        || chunk_index >= total_chunks
        || entries.len() > x0x::groups::invite::MAX_FETCHED_BASE_ROSTER_ENTRIES
    {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            chunk_index,
            total_chunks,
            entries = entries.len(),
            "dropped out-of-bounds base-roster chunk"
        );
        return;
    }
    if !validate_projection_entries(entries) {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster chunk with malformed entries"
        );
        return;
    }
    let key = slot_key(group_id, roster_root);
    let sanitized_chunk = sanitize_fetched(entries);
    // Lock order matches `WaiterGuard::drop`: `base_roster_fetch_slots` then
    // `base_roster_chunk_buffers`, preventing an orphaned assembly when a
    // waiter drops concurrently with chunk arrival.
    let completed = {
        let slots = state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let waiting = slots
            .get(&key)
            .is_some_and(|list| list.iter().any(|w| &w.inviter == sender));
        if !waiting {
            tracing::debug!(
                group_id = %LogHexId::group(group_id),
                "dropped base-roster chunk no waiting join asked this sender for"
            );
            return;
        }
        let mut buffers = state
            .base_roster_chunk_buffers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let buf_key = (key.clone(), *sender);
        let assembly = buffers
            .entry(buf_key.clone())
            .or_insert_with(|| BaseRosterChunkAssembly {
                total_chunks,
                received_chunks: std::collections::BTreeSet::new(),
                entries: BaseRosterProjection::new(),
            });
        if assembly.total_chunks != total_chunks {
            buffers.remove(&buf_key);
            tracing::debug!(
                group_id = %LogHexId::group(group_id),
                "dropped conflicting total_chunks in base-roster chunk assembly"
            );
            return;
        }
        if assembly.received_chunks.insert(chunk_index) {
            for (k, v) in sanitized_chunk {
                if assembly.entries.len() >= x0x::groups::invite::MAX_CHUNKED_BASE_ROSTER_ENTRIES {
                    buffers.remove(&buf_key);
                    return;
                }
                assembly.entries.insert(k, v);
            }
        }
        if assembly.received_chunks.len() == usize::from(assembly.total_chunks) {
            buffers.remove(&buf_key).map(|a| a.entries)
        } else {
            None
        }
    };
    let Some(assembled) = completed else {
        return;
    };
    if x0x::groups::state_commit::roster_root_of_projection(&assembled) != roster_root {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped reassembled base-roster that does not re-derive its own root"
        );
        return;
    }
    if !wake_matching_waiters(
        state,
        sender,
        &key,
        &BaseRosterFetchReply::Served(assembled),
    ) {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped completed base-roster chunks after waiter disappeared"
        );
    }
}

/// Joiner side: admit one `BaseRosterUnavailable` answer from `sender` —
/// terminal for every join waiting on this key with `sender` as its
/// expected inviter (r5 item 6). Like a served reply, it is honoured only
/// for a waiting join and never cached.
pub(in crate::server) fn deliver_base_roster_unavailable(
    state: &Arc<AppState>,
    sender: &AgentId,
    group_id: &str,
    roster_root: &str,
) {
    let key = slot_key(group_id, roster_root);
    if !wake_matching_waiters(state, sender, &key, &BaseRosterFetchReply::Unavailable) {
        tracing::debug!(
            group_id = %LogHexId::group(group_id),
            "dropped base-roster-unavailable answer no waiting join asked this sender for"
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
    inviter: AgentId,
    id: u64,
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        let mut still_has_inviter = false;
        let mut slots = self
            .state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(waiters) = slots.get_mut(self.key) {
            waiters.retain(|waiter| waiter.id != self.id);
            still_has_inviter = waiters.iter().any(|w| w.inviter == self.inviter);
            if waiters.is_empty() {
                slots.remove(self.key);
            }
        }
        // Hold `base_roster_fetch_slots` while clearing `base_roster_chunk_buffers`
        // (same lock order as registration and delivery) so a concurrent re-parked
        // waiter cannot have its fresh chunk buffer removed.
        if !still_has_inviter {
            self.state
                .base_roster_chunk_buffers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&(self.key.to_string(), self.inviter));
        }
        drop(slots);
    }
}

/// Joiner side: obtain the projection `signed_root` names by one
/// `BaseRosterFetch` round trip to the inviter bounded by `timeout`. The
/// answer is accepted only from `inviter` (delivery matches the sender
/// against this join's waiter) and only when it re-derives `signed_root`.
///
/// # Errors
///
/// [`ObtainBaseRosterError::Retryable`] when the inviter could not be
/// asked or did not answer in time (the join route maps it to the
/// retryable typed 503); [`ObtainBaseRosterError::Pruned`] when the
/// inviter answered that the root is gone (terminal).
pub(in crate::server) async fn obtain_base_roster(
    state: &Arc<AppState>,
    inviter: AgentId,
    stable_group_id: &str,
    signed_root: &str,
    secret_hash_hex: &str,
    timeout: Duration,
) -> Result<BaseRosterProjection, ObtainBaseRosterError> {
    use ObtainBaseRosterError::Retryable;
    let key = slot_key(stable_group_id, signed_root);
    #[cfg(test)]
    {
        if TEST_PRESEEDED_PRUNED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key)
        {
            return Err(ObtainBaseRosterError::Pruned);
        }
        let preseeded = TEST_PRESEEDED_PROJECTIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        if let Some(roster) = preseeded {
            let sanitized = sanitize_fetched(&roster);
            if x0x::groups::state_commit::roster_root_of_projection(&sanitized) == signed_root {
                return Ok(sanitized);
            }
            return Err(Retryable(
                "served roster does not re-derive the signed root",
            ));
        }
    }
    let waiter_id = NEXT_WAITER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    {
        let mut slots = state
            .base_roster_fetch_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let first_for_inviter = !slots
            .get(&key)
            .is_some_and(|list| list.iter().any(|w| w.inviter == inviter));
        if first_for_inviter {
            let mut buffers = state
                .base_roster_chunk_buffers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            buffers.remove(&(key.clone(), inviter));
        }
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
        inviter,
        id: waiter_id,
    };
    let request = JoinResultMessage::BaseRosterFetch {
        group_id: stable_group_id.to_string(),
        member_agent_id: hex::encode(state.agent.agent_id().as_bytes()),
        roster_root: signed_root.to_string(),
        secret_hash: secret_hash_hex.to_string(),
        accepts_chunks: true,
    };
    let Ok(payload) = serde_json::to_vec(&request) else {
        return Err(Retryable("request serialization failed"));
    };
    // Defense in depth: the delivery already verified a served payload
    // against this key's root; re-derive once more against the SIGNED
    // root before anything seeds from it.
    let admit = |reply: BaseRosterFetchReply| match reply {
        BaseRosterFetchReply::Served(roster) => {
            if x0x::groups::state_commit::roster_root_of_projection(&roster) != signed_root {
                return Err(Retryable(
                    "served roster does not re-derive the signed root",
                ));
            }
            Ok(roster)
        }
        BaseRosterFetchReply::Unavailable => Err(ObtainBaseRosterError::Pruned),
    };
    // r4 item 6: ONE timeout bounds the whole exchange — the send's own
    // internal retries included — so a v6 join never waits past the fetch
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
            // (an earlier attempt's answer).
            return match receiver.try_recv() {
                Ok(reply) => admit(reply),
                Err(_) => Err(Retryable("inviter unreachable")),
            };
        }
        match receiver.await {
            Ok(reply) => admit(reply),
            Err(_) => Err(Retryable(
                "no answer from the inviter within the fetch window",
            )),
        }
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => Err(Retryable(
            "no answer from the inviter within the fetch window",
        )),
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
///
/// The decision distinguishes the SILENT refusal (nothing proves the
/// requester may ask) from the TERMINAL answer (the invite is live and
/// authorized, but its root is unserveable — pruned from the commit log,
/// or over the fetch entry cap — so no retry can succeed; r5 item 6).
pub(in crate::server) enum BaseRosterServeDecision {
    /// No live matching invite, wrong addressee, or a Banned/Removed
    /// requester: dropped silently, the joiner just retries blind.
    Refuse,
    /// Authorized, but the bound root cannot be served any more: answer
    /// `BaseRosterUnavailable`, which the joiner maps to a terminal
    /// refusal.
    Unavailable,
    /// Authorized and located: serve this projection.
    Serve(BaseRosterProjection),
}

#[cfg(test)]
impl BaseRosterServeDecision {
    /// Test helper: the silent refusal.
    pub(in crate::server) fn is_refused(&self) -> bool {
        matches!(self, BaseRosterServeDecision::Refuse)
    }

    /// Test helper: the terminal answer.
    pub(in crate::server) fn is_unavailable(&self) -> bool {
        matches!(self, BaseRosterServeDecision::Unavailable)
    }

    /// Test helper: the served projection, when one was located.
    pub(in crate::server) fn served(self) -> Option<BaseRosterProjection> {
        match self {
            BaseRosterServeDecision::Serve(roster) => Some(roster),
            BaseRosterServeDecision::Refuse | BaseRosterServeDecision::Unavailable => None,
        }
    }
}

pub(in crate::server) fn locate_served_base_roster(
    info: &x0x::groups::GroupInfo,
    requester_hex: &str,
    roster_root: &str,
    secret_hash: &str,
    now_secs: u64,
) -> BaseRosterServeDecision {
    use BaseRosterServeDecision::{Refuse, Serve, Unavailable};
    if info.members_v2.get(requester_hex).is_some_and(|seat| {
        matches!(
            seat.state,
            x0x::groups::GroupMemberState::Banned | x0x::groups::GroupMemberState::Removed
        )
    }) {
        return Refuse;
    }
    let requested: [u8; 32] = match hex::decode(secret_hash)
        .ok()
        .and_then(|raw| raw.try_into().ok())
    {
        Some(bytes) => bytes,
        None => return Refuse,
    };
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
    });
    let Some(record) = record else {
        return Refuse;
    };
    if record
        .intended_joiner
        .as_deref()
        .is_some_and(|intended| !intended.eq_ignore_ascii_case(requester_hex))
    {
        return Refuse;
    }
    if record.base_roster_root.as_deref() != Some(roster_root) {
        return Refuse;
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
    match roster {
        Some(roster) => {
            let sanitized = sanitize_fetched(&roster);
            if sanitized.len() <= x0x::groups::invite::MAX_CHUNKED_BASE_ROSTER_ENTRIES {
                Serve(sanitized)
            } else {
                Unavailable
            }
        }
        None => Unavailable,
    }
}

/// Inviter side: send one located, sanitized projection back to the
/// requester. Projections up to [`MAX_FETCHED_BASE_ROSTER_ENTRIES`] travel as
/// one backward-compatible `BaseRoster` DM; larger projections (up to
/// [`MAX_CHUNKED_BASE_ROSTER_ENTRIES`]) travel as sequential `BaseRosterChunk`
/// DMs when `accepts_chunks` is true, or `BaseRosterUnavailable` for legacy
/// joiners that do not advertise chunk support.
pub(in crate::server) async fn send_base_roster_reply(
    state: &Arc<AppState>,
    requester: &AgentId,
    stable_group_id: String,
    roster_root: String,
    roster: BaseRosterProjection,
    accepts_chunks: bool,
) {
    if roster.len() <= x0x::groups::invite::MAX_FETCHED_BASE_ROSTER_ENTRIES {
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
        return;
    }
    if !accepts_chunks {
        send_base_roster_unavailable(state, requester, stable_group_id, roster_root).await;
        return;
    }
    let chunk_size = x0x::groups::invite::MAX_FETCHED_BASE_ROSTER_ENTRIES;
    let items: Vec<(String, x0x::groups::state_commit::RosterMemberSnapshot)> =
        roster.into_iter().collect();
    let total_chunks = items.len().div_ceil(chunk_size);
    let Ok(total_chunks_u16) = u16::try_from(total_chunks) else {
        send_base_roster_unavailable(state, requester, stable_group_id, roster_root).await;
        return;
    };
    if total_chunks_u16 > x0x::groups::invite::MAX_BASE_ROSTER_CHUNKS {
        send_base_roster_unavailable(state, requester, stable_group_id, roster_root).await;
        return;
    }
    for (idx, chunk) in items.chunks(chunk_size).enumerate() {
        let Ok(chunk_index) = u16::try_from(idx) else {
            break;
        };
        let entries: BaseRosterProjection = chunk.iter().cloned().collect();
        let reply = JoinResultMessage::BaseRosterChunk {
            group_id: stable_group_id.clone(),
            roster_root: roster_root.clone(),
            chunk_index,
            total_chunks: total_chunks_u16,
            entries,
        };
        let Ok(payload) = serde_json::to_vec(&reply) else {
            return;
        };
        if let Err(e) = state
            .agent
            .send_direct_with_config(requester, payload, direct_message_send_config())
            .await
        {
            tracing::debug!(chunk_index, "base-roster chunk send failed: {e}");
            return;
        }
    }
}

/// Inviter side (r5 item 6): tell an AUTHORIZED requester its invite's
/// root is unserveable, so its join can refuse terminally instead of
/// retrying forever.
pub(in crate::server) async fn send_base_roster_unavailable(
    state: &Arc<AppState>,
    requester: &AgentId,
    stable_group_id: String,
    roster_root: String,
) {
    let reply = JoinResultMessage::BaseRosterUnavailable {
        group_id: stable_group_id,
        roster_root,
    };
    let Ok(payload) = serde_json::to_vec(&reply) else {
        return;
    };
    if let Err(e) = state
        .agent
        .send_direct_with_config(requester, payload, direct_message_send_config())
        .await
    {
        tracing::debug!("base-roster-unavailable send failed: {e}");
    }
}

#[cfg(test)]
mod waiter_guard_tests {
    use super::*;

    #[tokio::test]
    async fn waiter_guard_drop_preserves_buffer_while_sibling_waiter_lives() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate()?)
                .with_peer_cache_disabled()
                .with_contact_store_path(dir.path().join("contacts.json"))
                .build()
                .await?,
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            dir.path(),
            agent,
        )
        .await?;
        let inviter = AgentId([42u8; 32]);
        let key = "group-race|root-race".to_string();
        let id1 = NEXT_WAITER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id2 = NEXT_WAITER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx1, _rx1) = tokio::sync::oneshot::channel();
        let (tx2, _rx2) = tokio::sync::oneshot::channel();
        {
            let mut slots = state.base_roster_fetch_slots.lock().expect("slots lock");
            let entry = slots.entry(key.clone()).or_default();
            entry.push(BaseRosterWaiter {
                id: id1,
                inviter,
                sender: tx1,
            });
            entry.push(BaseRosterWaiter {
                id: id2,
                inviter,
                sender: tx2,
            });
            state
                .base_roster_chunk_buffers
                .lock()
                .expect("buf lock")
                .insert(
                    (key.clone(), inviter),
                    BaseRosterChunkAssembly {
                        total_chunks: 2,
                        received_chunks: std::collections::BTreeSet::from([0u16]),
                        entries: BaseRosterProjection::new(),
                    },
                );
        }

        let guard1 = WaiterGuard {
            state: &state,
            key: &key,
            inviter,
            id: id1,
        };
        let guard2 = WaiterGuard {
            state: &state,
            key: &key,
            inviter,
            id: id2,
        };
        drop(guard1);
        assert!(
            state
                .base_roster_chunk_buffers
                .lock()
                .expect("buf lock")
                .contains_key(&(key.clone(), inviter)),
            "dropping first waiter must keep chunk buffer while second waiter is parked"
        );
        drop(guard2);
        assert!(
            !state
                .base_roster_chunk_buffers
                .lock()
                .expect("buf lock")
                .contains_key(&(key.clone(), inviter)),
            "dropping last waiter must clear chunk buffer atomically under slots lock"
        );
        Ok(())
    }
}
