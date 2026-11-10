//! Issue #1840: the order in which waiting join requesters get their turn.
//!
//! A join request is a chain link that the requester signs. A requester is
//! not a member, so it can seal over a head that is partial (an imported
//! card gives an owner-only roster) or already used (another requester
//! sealed over the same head first). The authority's validator refuses such
//! a commit and it can never apply; the requester must sign again over the
//! current head.
//!
//! This module fixes the ORDER of those requesters. The authority (the group
//! creator, the only node that admits request offers) keeps a bounded queue.
//! Order is the order of arrival of the first refused offer. One requester
//! per group holds the turn; it is the one to be told the head
//! ([`ChainHead`]) so that it can seal again.
//!
//! The queue is a hint and never authority. It applies nothing, signs
//! nothing and writes nothing durable. The ADR 0028 single-slot admission
//! journal is unchanged: every request still goes through it, one at a
//! time. Losing the queue (a restart) loses no request, because the
//! requester's durable offer obligation offers the request again and the
//! queue is rebuilt in the order of those re-offers.

use super::{AppState, NamedGroupMetadataEvent, CAUSAL_APPROVAL_RETENTION_MS};
use crate::groups::state_commit::ChainHead;

/// Waiting requesters per group. A full queue takes no new entry.
pub(in crate::server) const JOIN_SEQUENCE_PER_GROUP_CAP: usize = 16;
/// Waiting requesters on this daemon, over all groups.
pub(in crate::server) const JOIN_SEQUENCE_PER_DAEMON_CAP: usize = 256;
/// An entry is dropped this long after its first arrival.
pub(in crate::server) const JOIN_SEQUENCE_ENTRY_TTL_MS: u64 = CAUSAL_APPROVAL_RETENTION_MS;
/// How long one requester holds the turn before the next one gets it.
pub(in crate::server) const JOIN_SEQUENCE_TURN_MS: u64 = 30_000;
/// A requester that misses more turns than this is dropped.
pub(in crate::server) const JOIN_SEQUENCE_MAX_MISSED_TURNS: u8 = 2;

/// One requester that waits for its turn on one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct WaitingRequest {
    pub(in crate::server) group_id: String,
    pub(in crate::server) request_id: String,
    pub(in crate::server) requester_agent_id: String,
    /// Position key: lower is earlier. Unique on this daemon.
    pub(in crate::server) seq: u64,
    pub(in crate::server) first_seen_ms: u64,
    turn_started_ms: Option<u64>,
    missed_turns: u8,
}

/// The result of [`JoinSequencer::enqueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum Enqueued {
    /// A new entry at the back of the group's queue.
    Queued,
    /// The requester already waits on this group. It keeps its position.
    AlreadyQueued,
    /// A cap is reached. Nothing was stored.
    Full,
}

/// The bounded, in-memory queue of waiting join requesters.
#[derive(Debug, Default)]
pub(in crate::server) struct JoinSequencer {
    next_seq: u64,
    waiting: Vec<WaitingRequest>,
}

impl JoinSequencer {
    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    /// Record a refused request. One entry per (group, requester): a later
    /// request id from the same requester takes over the entry and keeps
    /// its position, so a requester can not get a second slot or a better
    /// place by asking again.
    pub(in crate::server) fn enqueue(
        &mut self,
        group_id: &str,
        request_id: &str,
        requester_agent_id: &str,
        now_ms: u64,
    ) -> Enqueued {
        self.waiting
            .retain(|w| now_ms < w.first_seen_ms.saturating_add(JOIN_SEQUENCE_ENTRY_TTL_MS));
        if let Some(entry) = self
            .waiting
            .iter_mut()
            .find(|w| w.group_id == group_id && w.requester_agent_id == requester_agent_id)
        {
            entry.request_id = request_id.to_string();
            return Enqueued::AlreadyQueued;
        }
        let in_group = self
            .waiting
            .iter()
            .filter(|w| w.group_id == group_id)
            .count();
        if self.waiting.len() >= JOIN_SEQUENCE_PER_DAEMON_CAP
            || in_group >= JOIN_SEQUENCE_PER_GROUP_CAP
        {
            return Enqueued::Full;
        }
        let seq = self.take_seq();
        self.waiting.push(WaitingRequest {
            group_id: group_id.to_string(),
            request_id: request_id.to_string(),
            requester_agent_id: requester_agent_id.to_string(),
            seq,
            first_seen_ms: now_ms,
            turn_started_ms: None,
            missed_turns: 0,
        });
        Enqueued::Queued
    }

    /// The requester whose turn it is on `group_id`: the entry with the
    /// lowest `seq`. Entries that are expired, or for which `resolved` is
    /// true (the request applied, or it can no longer be admitted), are
    /// dropped first. A holder that kept the turn for
    /// [`JOIN_SEQUENCE_TURN_MS`] without being resolved goes to the back,
    /// and is dropped after [`JOIN_SEQUENCE_MAX_MISSED_TURNS`] misses, so
    /// one requester can not hold the head of the line.
    pub(in crate::server) fn turn(
        &mut self,
        group_id: &str,
        now_ms: u64,
        mut resolved: impl FnMut(&WaitingRequest) -> bool,
    ) -> Option<WaitingRequest> {
        self.waiting.retain(|w| {
            w.group_id != group_id
                || (now_ms < w.first_seen_ms.saturating_add(JOIN_SEQUENCE_ENTRY_TTL_MS)
                    && !resolved(w))
        });
        loop {
            let index = self
                .waiting
                .iter()
                .enumerate()
                .filter(|(_, w)| w.group_id == group_id)
                .min_by_key(|(_, w)| w.seq)
                .map(|(index, _)| index)?;
            let next_seq = self.next_seq;
            let holder = self.waiting.get_mut(index)?;
            match holder.turn_started_ms {
                None => {
                    holder.turn_started_ms = Some(now_ms);
                    return Some(holder.clone());
                }
                Some(start) if now_ms < start.saturating_add(JOIN_SEQUENCE_TURN_MS) => {
                    return Some(holder.clone());
                }
                Some(_) if holder.missed_turns >= JOIN_SEQUENCE_MAX_MISSED_TURNS => {
                    self.waiting.remove(index);
                }
                Some(_) => {
                    holder.missed_turns += 1;
                    holder.turn_started_ms = None;
                    holder.seq = next_seq;
                    self.next_seq = next_seq.saturating_add(1);
                }
            }
        }
    }

    /// 1-based place of `requester_agent_id` in the group's queue.
    pub(in crate::server) fn position(
        &self,
        group_id: &str,
        requester_agent_id: &str,
    ) -> Option<usize> {
        let own = self
            .waiting
            .iter()
            .find(|w| w.group_id == group_id && w.requester_agent_id == requester_agent_id)?;
        let ahead = self
            .waiting
            .iter()
            .filter(|w| w.group_id == group_id && w.seq < own.seq)
            .count();
        Some(ahead + 1)
    }

    /// Number of waiting entries on this daemon.
    pub(in crate::server) fn len(&self) -> usize {
        self.waiting.len()
    }
}

/// Whether a refused request from `requester_agent_id` can still be admitted
/// once it is sealed over the right head. False for every terminal refusal
/// (policy, member, banned, a pending request, a used request id): those do
/// not wait for a turn.
fn request_waits_for_a_turn(
    info: &crate::groups::GroupInfo,
    requester_agent_id: &str,
    request_id: &str,
) -> bool {
    !info.withdrawn
        && info.policy.admission == crate::groups::GroupAdmission::RequestAccess
        && !info.has_active_member(requester_agent_id)
        && !info.is_banned(requester_agent_id)
        && !info.join_requests.contains_key(request_id)
        && !info
            .join_requests
            .values()
            .any(|r| r.requester_agent_id == requester_agent_id && r.is_pending())
}

/// The requester whose turn it is, with the head it must seal over.
#[derive(Debug, Clone)]
pub(in crate::server) struct JoinTurn {
    pub(in crate::server) request: WaitingRequest,
    pub(in crate::server) head: ChainHead,
}

/// The current turn on `group_key`, or `None` when nobody waits.
pub(in crate::server) async fn next_turn(
    state: &AppState,
    group_key: &str,
    now_ms: u64,
) -> Option<JoinTurn> {
    let groups = state.named_groups.read().await;
    let info = groups.get(group_key)?;
    let mut sequencer = state.join_sequencer.lock().await;
    let request = sequencer.turn(group_key, now_ms, |w| {
        !request_waits_for_a_turn(info, &w.requester_agent_id, &w.request_id)
    })?;
    Some(JoinTurn {
        request,
        head: info.chain_head(),
    })
}

/// The authority's listener refused `event` by validation, with no roster
/// write (#1842). If the only thing wrong is the head the requester sealed
/// over, the requester joins the queue. Nothing durable changes here.
pub(in crate::server) async fn note_refused_request(
    state: &AppState,
    group_key: &str,
    event: &NamedGroupMetadataEvent,
    now_ms: u64,
) {
    let NamedGroupMetadataEvent::JoinRequestCreated {
        request_id,
        requester_agent_id,
        commit: Some(_),
        ..
    } = event
    else {
        return;
    };
    let waits = state
        .named_groups
        .read()
        .await
        .get(group_key)
        .is_some_and(|info| request_waits_for_a_turn(info, requester_agent_id, request_id));
    if !waits {
        return;
    }
    let (enqueued, position, waiting) = {
        let mut sequencer = state.join_sequencer.lock().await;
        let enqueued = sequencer.enqueue(group_key, request_id, requester_agent_id, now_ms);
        (
            enqueued,
            sequencer.position(group_key, requester_agent_id),
            sequencer.len(),
        )
    };
    let turn = next_turn(state, group_key, now_ms).await;
    tracing::info!(
        group_id = %group_key,
        request_id = %request_id,
        requester = %requester_agent_id,
        outcome = "waiting",
        ?enqueued,
        ?position,
        waiting,
        turn_holder = turn.as_ref().map(|t| t.request.requester_agent_id.as_str()),
        head_revision = turn.as_ref().map(|t| t.head.revision),
        "issue 1840: join request sealed over a partial or used head; requester waits for its turn"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enqueue(s: &mut JoinSequencer, group: &str, who: &str, now_ms: u64) -> Enqueued {
        s.enqueue(group, &format!("req-{who}"), who, now_ms)
    }

    fn holder(s: &mut JoinSequencer, group: &str, now_ms: u64) -> Option<String> {
        s.turn(group, now_ms, |_| false)
            .map(|w| w.requester_agent_id)
    }

    #[test]
    fn issue1840_order_is_arrival_order_and_one_slot_per_requester() {
        let mut s = JoinSequencer::default();
        for who in ["c", "a", "b"] {
            assert_eq!(enqueue(&mut s, "g", who, 1), Enqueued::Queued);
        }
        // Asking again, with a new request id, keeps the place and the slot.
        assert_eq!(s.enqueue("g", "req-a-2", "a", 2), Enqueued::AlreadyQueued);
        assert_eq!(s.len(), 3);
        assert_eq!(s.position("g", "c"), Some(1));
        assert_eq!(s.position("g", "a"), Some(2));
        assert_eq!(s.position("g", "b"), Some(3));
        let mut order = Vec::new();
        loop {
            let next = s.turn("g", 3, |w| order.contains(&w.requester_agent_id));
            let Some(w) = next else { break };
            order.push(w.requester_agent_id);
        }
        assert_eq!(order, ["c", "a", "b"]);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn issue1840_caps_are_enforced_and_a_full_queue_stores_nothing() {
        let mut s = JoinSequencer::default();
        for i in 0..JOIN_SEQUENCE_PER_GROUP_CAP {
            assert_eq!(enqueue(&mut s, "g", &format!("r{i}"), 1), Enqueued::Queued);
        }
        assert_eq!(enqueue(&mut s, "g", "late", 1), Enqueued::Full);
        assert_eq!(s.position("g", "late"), None);
        // Another group is not blocked by a full group.
        assert_eq!(enqueue(&mut s, "h", "late", 1), Enqueued::Queued);
        let mut s = JoinSequencer::default();
        for i in 0..JOIN_SEQUENCE_PER_DAEMON_CAP {
            let group = format!("g{}", i / JOIN_SEQUENCE_PER_GROUP_CAP);
            assert_eq!(
                enqueue(&mut s, &group, &format!("r{i}"), 1),
                Enqueued::Queued
            );
        }
        assert_eq!(enqueue(&mut s, "new-group", "late", 1), Enqueued::Full);
        assert_eq!(s.len(), JOIN_SEQUENCE_PER_DAEMON_CAP);
    }

    #[test]
    fn issue1840_missed_turn_goes_to_the_back_then_is_dropped() {
        let mut s = JoinSequencer::default();
        for who in ["a", "b"] {
            enqueue(&mut s, "g", who, 0);
        }
        assert_eq!(holder(&mut s, "g", 0).as_deref(), Some("a"));
        assert_eq!(
            holder(&mut s, "g", JOIN_SEQUENCE_TURN_MS - 1).as_deref(),
            Some("a")
        );
        // "a" did not apply in its turn: "b" is not blocked behind it.
        let mut now = JOIN_SEQUENCE_TURN_MS;
        assert_eq!(holder(&mut s, "g", now).as_deref(), Some("b"));
        assert_eq!(s.position("g", "a"), Some(2));
        // Nobody ever applies: every entry is dropped after its misses.
        let mut turns = 0;
        while holder(&mut s, "g", now).is_some() {
            now += JOIN_SEQUENCE_TURN_MS;
            turns += 1;
            assert!(turns < 16, "the queue must drain");
        }
        assert_eq!(s.len(), 0);
        assert!(
            now < JOIN_SEQUENCE_ENTRY_TTL_MS,
            "misses drain before the TTL"
        );
    }

    #[test]
    fn issue1840_entries_expire_without_any_turn() {
        let mut s = JoinSequencer::default();
        enqueue(&mut s, "g", "a", 10);
        enqueue(&mut s, "h", "b", 10);
        assert_eq!(holder(&mut s, "g", 10 + JOIN_SEQUENCE_ENTRY_TTL_MS), None);
        // The other group's expired entry goes on the next enqueue.
        enqueue(&mut s, "k", "c", 10 + JOIN_SEQUENCE_ENTRY_TTL_MS);
        assert_eq!(s.len(), 1);
    }
}
