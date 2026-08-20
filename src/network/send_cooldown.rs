//! Destructive cooldown for gossip per-peer sends (#368 / PR A).
//!
//! Heap profile of a bare daemon on a NAT-exposed LAN (issue #368): a peer
//! whose path stalls (NAT traversal half-open, path validation failing, slow
//! consumer) stops draining its QUIC streams, while saorsa-gossip keeps
//! fanning messages at it. Every per-message uni-stream send that times out
//! is dropped mid-`SendStream::write` by saorsa-gossip's outer timeout,
//! pinning the unsent buffer on the sender and the partial assembler state on
//! the receiver — linear growth per stalled peer per message.
//!
//! The x0x transport now owns the per-send timeout (below saorsa-gossip's
//! adaptive floor so it always fires first) and escalates consecutive
//! timeouts to a connection close by peer-id. Closing resets every stream in
//! both directions and releases all pinned buffers on both ends; the normal
//! reconnect-eligible redial path recovers the peer if it comes back.
//!
//! Explicit per-stream `reset()` of the timed-out stream (ant-quic #244:
//! drop = finish/truncate, not reset) needs an ant-quic API for a
//! peer-addressable uni stream handle; that lands as the ant-quic follow-up.
//! Until then the escalation close performs the reset for the whole
//! connection, bounding the pinned residue to at most one stream per peer
//! between the first timeout and the close.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// x0x-side timeout for one gossip per-peer send.
///
/// MUST stay strictly below saorsa-gossip's adaptive timeout floor
/// (`saorsa_gossip_pubsub::timing::PER_PEER_TIMEOUT_FLOOR`, 1500 ms): the
/// transport timeout has to fire before saorsa-gossip's outer
/// `tokio::time::timeout` drops the in-flight send future mid-`write`, or the
/// abandoned stream is pinned again (the exact leak this module exists to
/// bound). The unit test `gossip_send_timeout_stays_below_sg_floor` pins the
/// relationship.
///
/// A peer that cannot complete a send within this budget twice in a row (with
/// no intervening success) is treated as stalled and disconnected — gossip is
/// epidemic and loss-tolerant, so trading a reconnect for an unbounded send
/// buffer is the correct side of the trade.
pub(crate) const GOSSIP_SEND_TIMEOUT: Duration = Duration::from_millis(1_200);

/// Consecutive send timeouts (with no intervening successful send to the same
/// peer) before the connection is closed.
///
/// 2 keeps the pinned-stream residue bounded to a single stream per stalled
/// peer (first timeout throttles, second closes), while an isolated slow send
/// followed by any success resets the streak.
pub(crate) const COOLDOWN_CLOSE_CONSECUTIVE_TIMEOUTS: u32 = 2;

/// Per-peer consecutive-timeout streaks plus the two proof counters for the
/// #368 soak (`GET /diagnostics/gossip` → `send_cooldown`).
#[derive(Debug, Default)]
pub(crate) struct SendCooldownTracker {
    streaks: Mutex<HashMap<[u8; 32], u32>>,
    sends_timed_out: AtomicU64,
    conns_closed_by_cooldown: AtomicU64,
}

impl SendCooldownTracker {
    /// Record a successful send: the peer's streak resets, so an isolated
    /// timeout never escalates on its own.
    pub(crate) fn note_success(&self, peer: [u8; 32]) {
        match self.streaks.lock() {
            Ok(mut guard) => {
                guard.remove(&peer);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&peer);
            }
        }
    }

    /// Record a timed-out send. Returns `true` when the escalation threshold
    /// ([`COOLDOWN_CLOSE_CONSECUTIVE_TIMEOUTS`]) is met and the caller should
    /// close the connection to this peer.
    pub(crate) fn note_timeout(&self, peer: [u8; 32]) -> bool {
        self.sends_timed_out.fetch_add(1, Ordering::Relaxed);
        let streak = match self.streaks.lock() {
            Ok(mut guard) => {
                let entry = guard.entry(peer).or_insert(0);
                *entry += 1;
                *entry
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                let entry = guard.entry(peer).or_insert(0);
                *entry += 1;
                *entry
            }
        };
        streak >= COOLDOWN_CLOSE_CONSECUTIVE_TIMEOUTS
    }

    /// Record that the escalation close happened: bumps the proof counter and
    /// clears the streak so the redialled connection starts clean.
    pub(crate) fn note_closed(&self, peer: [u8; 32]) {
        self.conns_closed_by_cooldown
            .fetch_add(1, Ordering::Relaxed);
        match self.streaks.lock() {
            Ok(mut guard) => {
                guard.remove(&peer);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&peer);
            }
        }
    }

    /// Proof counters for `GET /diagnostics/gossip`.
    #[must_use]
    pub(crate) fn snapshot(&self) -> SendCooldownSnapshot {
        SendCooldownSnapshot {
            streams_reset_on_timeout: self.sends_timed_out.load(Ordering::Relaxed),
            conns_closed_by_cooldown: self.conns_closed_by_cooldown.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of the cooldown proof counters (issue #368).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SendCooldownSnapshot {
    /// Per-peer gossip sends abandoned on transport timeout. The stream's
    /// pinned residue is freed by the escalation close (explicit per-stream
    /// reset lands with the ant-quic #244 follow-up).
    pub streams_reset_on_timeout: u64,
    /// Connections closed by the destructive cooldown escalation.
    pub conns_closed_by_cooldown: u64,
}

/// Outcome of one gossip per-peer send under the transport timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    /// Completed within the transport budget.
    Sent,
    /// Abandoned at [`GOSSIP_SEND_TIMEOUT`]; the escalation policy (not the
    /// caller) owns what happens next.
    TimedOut,
}

impl SendCooldownTracker {
    /// Current consecutive-timeout streak for `peer` (test/diagnostics aid).
    #[cfg(test)]
    pub(crate) fn streak(&self, peer: [u8; 32]) -> u32 {
        match self.streaks.lock() {
            Ok(guard) => guard.get(&peer).copied().unwrap_or(0),
            Err(poisoned) => poisoned.into_inner().get(&peer).copied().unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Why: the transport timeout MUST fire before saorsa-gossip's adaptive
    /// floor, or the outer timeout drops the in-flight send mid-write and
    /// pins the abandoned stream again — the leak this module bounds.
    #[test]
    fn gossip_send_timeout_stays_below_sg_floor() {
        assert!(
            GOSSIP_SEND_TIMEOUT < saorsa_gossip_pubsub::timing::PER_PEER_TIMEOUT_FLOOR,
            "GOSSIP_SEND_TIMEOUT ({GOSSIP_SEND_TIMEOUT:?}) must stay below sg's \
             PER_PEER_TIMEOUT_FLOOR \
             ({:?})",
            saorsa_gossip_pubsub::timing::PER_PEER_TIMEOUT_FLOOR
        );
    }

    /// Why (#368): the escalation state machine — first timeout throttles
    /// only, the second consecutive timeout closes, and any intervening
    /// success resets the streak so isolated slow sends never escalate.
    #[test]
    fn cooldown_state_machine_first_throttles_second_closes_success_resets() {
        let tracker = SendCooldownTracker::default();
        let peer = [0x11; 32];

        assert!(!tracker.note_timeout(peer), "first timeout must not close");
        assert_eq!(tracker.streak(peer), 1);

        assert!(
            tracker.note_timeout(peer),
            "second consecutive timeout must close"
        );
        assert_eq!(tracker.streak(peer), 2);

        tracker.note_closed(peer);
        assert_eq!(tracker.streak(peer), 0, "close clears the streak");
        assert_eq!(tracker.snapshot().conns_closed_by_cooldown, 1);
        assert_eq!(tracker.snapshot().streams_reset_on_timeout, 2);

        // After the close, a fresh timeout on the redialled conn starts a new
        // streak instead of instantly closing again.
        assert!(!tracker.note_timeout(peer));
    }

    #[test]
    fn cooldown_success_resets_streak_between_timeouts() {
        let tracker = SendCooldownTracker::default();
        let peer = [0x22; 32];

        assert!(!tracker.note_timeout(peer));
        tracker.note_success(peer);
        assert_eq!(tracker.streak(peer), 0);
        // This is a FIRST timeout again — no close.
        assert!(!tracker.note_timeout(peer));
        assert_eq!(
            tracker.snapshot().conns_closed_by_cooldown,
            0,
            "isolated timeouts separated by successes never escalate"
        );
    }

    /// Why: streaks are per-peer — one stalled peer must not cause the close
    /// of another peer's healthy connection.
    #[test]
    fn cooldown_streaks_are_per_peer() {
        let tracker = SendCooldownTracker::default();
        let stalled = [0x33; 32];
        let healthy = [0x44; 32];

        assert!(!tracker.note_timeout(stalled));
        assert!(!tracker.note_timeout(healthy));
        assert!(
            tracker.note_timeout(stalled),
            "only the stalled peer's streak escalates"
        );
    }
}
