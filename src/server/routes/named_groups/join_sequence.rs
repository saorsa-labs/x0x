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
//! per group holds the turn; it is the one to be told the head so that it
//! can seal again. This slice does not tell it: the daemon only records and
//! logs the order. There is no timer; the queue moves when a refused offer
//! arrives.
//!
//! The queue is a hint and never authority. It applies nothing, signs
//! nothing and writes nothing durable. The ADR 0028 single-slot admission
//! journal is unchanged: every request still goes through it, one at a
//! time. Losing the queue (a restart) loses no request, because the
//! requester's durable offer obligation offers the request again and the
//! queue is rebuilt in the order of those re-offers.

use super::{
    apply_stateful_event_to_group, AppState, NamedGroupMetadataEvent, CAUSAL_APPROVAL_RETENTION_MS,
};
use crate::groups::state_commit::{ActionKind, ApplyError, GroupStateCommit};

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
/// A request with a longer id is not queued (the id is stored per entry).
pub(in crate::server) const JOIN_SEQUENCE_REQUEST_ID_MAX_BYTES: usize = 128;

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

    /// Drop the entries of `group_id` that are expired or `resolved` (the
    /// request applied, or it can no longer be admitted). An expired entry
    /// of another group goes on the next [`Self::enqueue`].
    fn prune(
        &mut self,
        group_id: &str,
        now_ms: u64,
        mut resolved: impl FnMut(&WaitingRequest) -> bool,
    ) {
        self.waiting.retain(|w| {
            w.group_id != group_id
                || (now_ms < w.first_seen_ms.saturating_add(JOIN_SEQUENCE_ENTRY_TTL_MS)
                    && !resolved(w))
        });
    }

    /// Record a refused request. One entry per (group, requester): a later
    /// request id from the same requester takes over the entry. It keeps
    /// the position (`seq`) and the first-arrival time, so asking again
    /// gives no second slot, no better place and no longer stay. The turn
    /// state starts again, because the new request was never offered a
    /// turn. The caller prunes resolved entries first, so an entry whose
    /// request was applied is never taken over.
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
            if entry.request_id != request_id {
                entry.request_id = request_id.to_string();
                entry.turn_started_ms = None;
                entry.missed_turns = 0;
            }
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
    /// lowest `seq`, after [`Self::prune`]. A holder that kept the turn for
    /// [`JOIN_SEQUENCE_TURN_MS`] without being resolved goes to the back,
    /// and is dropped after [`JOIN_SEQUENCE_MAX_MISSED_TURNS`] misses, so
    /// one requester can not hold the head of the line. Time passes only
    /// when this is called; there is no timer.
    pub(in crate::server) fn turn(
        &mut self,
        group_id: &str,
        now_ms: u64,
        resolved: impl FnMut(&WaitingRequest) -> bool,
    ) -> Option<WaitingRequest> {
        self.prune(group_id, now_ms, resolved);
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

/// Whether `requester_agent_id` can still be admitted on `info` with a
/// request `request_id`. False for every terminal state (policy, member,
/// banned, a pending request, a used request id).
fn request_is_admissible(
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

/// Whether the validator refuses `commit` on `info` ONLY because of the
/// head it was sealed over: a used revision, an old previous hash, or hash
/// inputs that are not the authority's. This runs the same read-only
/// validation as the apply (a pending request is not in the state hash, so
/// no mutation is needed). A bad signature, a wrong group id, an
/// unauthorized signer and every other refusal are not this class.
fn refused_for_its_head(info: &crate::groups::GroupInfo, commit: &GroupStateCommit) -> bool {
    matches!(
        apply_stateful_event_to_group(info, commit, ActionKind::NonMemberRequest, |_| {}),
        Err(ApplyError::StaleRevision { .. }
            | ApplyError::PrevHashMismatch { .. }
            | ApplyError::StateHashMismatch { .. })
    )
}

/// The requester whose turn it is, with the revision of the head it must
/// seal over.
#[derive(Debug, Clone)]
pub(in crate::server) struct JoinTurn {
    pub(in crate::server) request: WaitingRequest,
    pub(in crate::server) head_revision: u64,
}

/// The current turn on `group_key`, read under the caller's locks.
pub(in crate::server) fn turn_on(
    sequencer: &mut JoinSequencer,
    info: &crate::groups::GroupInfo,
    group_key: &str,
    now_ms: u64,
) -> Option<JoinTurn> {
    let request = sequencer.turn(group_key, now_ms, |w| {
        !request_is_admissible(info, &w.requester_agent_id, &w.request_id)
    })?;
    Some(JoinTurn {
        request,
        head_revision: info.state_revision,
    })
}

/// The authority's listener refused `event` by validation, with no roster
/// write (#1842). The requester joins the queue only when the request is
/// still admissible and the commit was refused for its head
/// ([`refused_for_its_head`]). Nothing durable changes here. Returns the
/// current turn on the group, if any.
pub(in crate::server) async fn note_refused_request(
    state: &AppState,
    group_key: &str,
    event: &NamedGroupMetadataEvent,
    now_ms: u64,
) -> Option<JoinTurn> {
    let NamedGroupMetadataEvent::JoinRequestCreated {
        request_id,
        requester_agent_id,
        commit: Some(commit),
        ..
    } = event
    else {
        return None;
    };
    let groups = state.named_groups.read().await;
    let info = groups.get(group_key)?;
    let mut sequencer = state.join_sequencer.lock().await;
    // Resolved entries go first, so an applied request's entry is dropped
    // and never taken over by a later request of the same requester.
    sequencer.prune(group_key, now_ms, |w| {
        !request_is_admissible(info, &w.requester_agent_id, &w.request_id)
    });
    let waits = request_id.len() <= JOIN_SEQUENCE_REQUEST_ID_MAX_BYTES
        && request_is_admissible(info, requester_agent_id, request_id)
        && refused_for_its_head(info, commit);
    let enqueued =
        waits.then(|| sequencer.enqueue(group_key, request_id, requester_agent_id, now_ms));
    let position = sequencer.position(group_key, requester_agent_id);
    let turn = turn_on(&mut sequencer, info, group_key, now_ms);
    if enqueued.is_some() {
        tracing::info!(
            group_id = %group_key,
            requester = %requester_agent_id,
            outcome = "waiting",
            ?enqueued,
            ?position,
            waiting = sequencer.len(),
            turn_holder = turn.as_ref().map(|t| t.request.requester_agent_id.as_str()),
            head_revision = turn.as_ref().map(|t| t.head_revision),
            "issue 1840: join request refused for the head it was sealed over; requester waits for its turn"
        );
    }
    turn
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
    fn issue1840_new_request_id_keeps_place_and_restarts_the_turn() {
        let mut s = JoinSequencer::default();
        for who in ["a", "b"] {
            enqueue(&mut s, "g", who, 0);
        }
        assert_eq!(holder(&mut s, "g", 0).as_deref(), Some("a"));
        // "a" asks again just before its turn runs out. It keeps the place,
        // and the new request gets a full turn with no miss counted.
        let late = JOIN_SEQUENCE_TURN_MS - 1;
        assert_eq!(
            s.enqueue("g", "req-a-2", "a", late),
            Enqueued::AlreadyQueued
        );
        assert_eq!(s.position("g", "a"), Some(1));
        let turn = s.turn("g", JOIN_SEQUENCE_TURN_MS + 1, |_| false);
        assert_eq!(
            turn.as_ref().map(|w| w.request_id.as_str()),
            Some("req-a-2")
        );
        assert_eq!(turn.map(|w| w.missed_turns), Some(0));
        // The same request id again changes nothing.
        assert_eq!(
            s.enqueue("g", "req-a-2", "a", late),
            Enqueued::AlreadyQueued
        );
        assert_eq!(
            holder(&mut s, "g", 2 * JOIN_SEQUENCE_TURN_MS + 1).as_deref(),
            Some("b"),
            "the turn of the new request also runs out"
        );
    }

    #[test]
    fn issue1840_resolved_entry_is_dropped_and_not_reused() {
        let mut s = JoinSequencer::default();
        for who in ["a", "b"] {
            enqueue(&mut s, "g", who, 0);
        }
        s.prune("g", 1, |w| w.requester_agent_id == "a");
        assert_eq!(s.position("g", "a"), None);
        // "a" asks again later: a new entry at the back, with a new clock.
        assert_eq!(s.enqueue("g", "req-a-2", "a", 5), Enqueued::Queued);
        assert_eq!(s.position("g", "b"), Some(1));
        assert_eq!(s.position("g", "a"), Some(2));
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
