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
//! connection, bounding the pinned residue to one stream per peer per
//! escalation window.

use std::time::Instant;

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
/// A peer that cannot complete a send within this budget repeatedly (see
/// [`N_CONSECUTIVE_TIMEOUTS_TO_CLOSE`]) is treated as stalled and
/// disconnected — gossip is epidemic and loss-tolerant, so trading a
/// reconnect for an unbounded send buffer is the correct side of the trade.
pub(crate) const GOSSIP_SEND_TIMEOUT: Duration = Duration::from_millis(1_200);

/// Consecutive send timeouts (with no intervening successful send to the same
/// peer) before the connection is closed.
///
/// 5 balances two failure modes (#368 vs the v0.36.2 lesson): closing too
/// eagerly (e.g. 2 consecutive 1.2 s timeouts ≈ 2.4 s of stall) churns
/// redials/hole-punches on healthy WAN peers that genuinely experience
/// multi-second 100%-loss windows, while waiting too long re-pins the
/// unbounded send buffers this escalation exists to free. Five consecutive
/// misses with no success in between is a stalled peer, not a lossy-but-alive
/// one; any successful send resets the streak.
pub(crate) const N_CONSECUTIVE_TIMEOUTS_TO_CLOSE: u32 = 5;

/// Minimum wall time between cooldown closes of the same peer (#368): a
/// flapping peer must not loop close → redial → close, which would trade the
/// buffer leak for a connection-churn storm.
pub(crate) const COOLDOWN_CLOSE_RATE_LIMIT: Duration = Duration::from_secs(60);

/// Per-peer consecutive-timeout streaks, close rate-limit bookkeeping, and
/// the two proof counters for the #368 soak (`GET /diagnostics/gossip` →
/// `send_cooldown`).
#[derive(Debug, Default)]
pub(crate) struct SendCooldownTracker {
    streaks: Mutex<HashMap<[u8; 32], u32>>,
    last_close_at: Mutex<HashMap<[u8; 32], Instant>>,
    /// Wall-time window for [`Self::note_timeout`]'s close rate limit.
    /// Production uses [`COOLDOWN_CLOSE_RATE_LIMIT`]; tests inject a short
    /// window so the limit is exercisable deterministically.
    close_rate_limit: Option<Duration>,
    sends_timed_out: AtomicU64,
    conns_closed_by_cooldown: AtomicU64,
}

impl SendCooldownTracker {
    /// Tracker with the production close rate limit.
    pub(crate) fn new() -> Self {
        Self {
            close_rate_limit: Some(COOLDOWN_CLOSE_RATE_LIMIT),
            ..Self::default()
        }
    }

    /// Test constructor with an explicit close rate-limit window.
    #[cfg(test)]
    pub(crate) fn with_close_rate_limit(close_rate_limit: Duration) -> Self {
        Self {
            close_rate_limit: Some(close_rate_limit),
            ..Self::default()
        }
    }

    fn lock_map<T, R>(
        lock: &Mutex<HashMap<[u8; 32], T>>,
        with: impl FnOnce(&mut HashMap<[u8; 32], T>) -> R,
    ) -> R {
        match lock.lock() {
            Ok(mut guard) => with(&mut guard),
            Err(poisoned) => with(&mut poisoned.into_inner()),
        }
    }

    /// Record a successful send: the peer's streak resets, so isolated
    /// timeouts never escalate on their own.
    pub(crate) fn note_success(&self, peer: [u8; 32]) {
        Self::lock_map(&self.streaks, |m| {
            m.remove(&peer);
        });
    }

    /// Record a timed-out send. Returns `true` when the escalation threshold
    /// ([`N_CONSECUTIVE_TIMEOUTS_TO_CLOSE`]) is met AND the per-peer close
    /// rate limit ([`COOLDOWN_CLOSE_RATE_LIMIT`]) allows another close — the
    /// caller should then close the connection to this peer.
    pub(crate) fn note_timeout(&self, peer: [u8; 32]) -> bool {
        self.sends_timed_out.fetch_add(1, Ordering::Relaxed);
        let streak = Self::lock_map(&self.streaks, |m| {
            let entry = m.entry(peer).or_insert(0);
            *entry += 1;
            *entry
        });
        if streak < N_CONSECUTIVE_TIMEOUTS_TO_CLOSE {
            return false;
        }
        // Rate limit: within the window of a previous close, keep the streak
        // accumulating but do not close again — a flapping peer must not
        // loop close → redial → close.
        Self::lock_map(&self.last_close_at, |m| {
            m.get(&peer)
                .is_none_or(|at| at.elapsed() >= self.close_rate_limit.unwrap_or_default())
        })
    }

    /// Record that the escalation close happened: bumps the proof counter,
    /// arms the per-peer rate limit, and clears the streak so the redialled
    /// connection starts clean.
    pub(crate) fn note_closed(&self, peer: [u8; 32]) {
        self.conns_closed_by_cooldown
            .fetch_add(1, Ordering::Relaxed);
        Self::lock_map(&self.streaks, |m| {
            m.remove(&peer);
        });
        Self::lock_map(&self.last_close_at, |m| {
            m.insert(peer, Instant::now());
        });
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

    /// Why (#368 + v0.36.2): the escalation state machine — the first
    /// N-1 consecutive timeouts throttle only, the Nth closes, and any
    /// intervening success resets the streak so a lossy-but-alive WAN peer
    /// (multi-second 100%-loss windows are real) never escalates.
    #[test]
    fn cooldown_state_machine_closes_on_nth_consecutive_timeout() {
        let tracker = SendCooldownTracker::default();
        let peer = [0x11; 32];

        for i in 1..N_CONSECUTIVE_TIMEOUTS_TO_CLOSE {
            assert!(
                !tracker.note_timeout(peer),
                "timeout #{i} below the threshold must not close"
            );
            assert_eq!(tracker.streak(peer), i);
        }

        assert!(
            tracker.note_timeout(peer),
            "timeout #{N_CONSECUTIVE_TIMEOUTS_TO_CLOSE} must close"
        );

        tracker.note_closed(peer);
        assert_eq!(tracker.streak(peer), 0, "close clears the streak");
        assert_eq!(tracker.snapshot().conns_closed_by_cooldown, 1);
        assert_eq!(
            tracker.snapshot().streams_reset_on_timeout,
            u64::from(N_CONSECUTIVE_TIMEOUTS_TO_CLOSE)
        );

        // After the close, fresh timeouts on the redialled conn start a new
        // streak instead of instantly closing again.
        assert!(!tracker.note_timeout(peer));
    }

    /// Why (#368): a flapping peer must not loop close → redial → close —
    /// within the rate-limit window the tracker refuses a second close even
    /// at threshold, and allows it again once the window elapses.
    #[test]
    fn cooldown_close_is_rate_limited_per_peer() {
        let window = Duration::from_millis(80);
        let tracker = SendCooldownTracker::with_close_rate_limit(window);
        let peer = [0x55; 32];

        for _ in 0..N_CONSECUTIVE_TIMEOUTS_TO_CLOSE - 1 {
            assert!(!tracker.note_timeout(peer));
        }
        assert!(tracker.note_timeout(peer), "first close is allowed");
        tracker.note_closed(peer);

        // Streak rebuilds past the threshold while the window is fresh, but
        // every close request is refused.
        for i in 0..=N_CONSECUTIVE_TIMEOUTS_TO_CLOSE {
            assert!(
                !tracker.note_timeout(peer),
                "close #{i} within the rate-limit window must be refused"
            );
        }

        std::thread::sleep(window + Duration::from_millis(30));
        assert!(
            tracker.note_timeout(peer),
            "close is allowed again once the window elapses"
        );
        assert_eq!(tracker.snapshot().conns_closed_by_cooldown, 1);
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

        for _ in 0..N_CONSECUTIVE_TIMEOUTS_TO_CLOSE - 1 {
            assert!(!tracker.note_timeout(stalled));
            assert!(!tracker.note_timeout(healthy), "healthy peer never closes");
        }
        // stalled reaches the threshold and closes; healthy sits at N-1
        // untouched — the streaks are independent.
        assert!(
            tracker.note_timeout(stalled),
            "only the stalled peer's streak escalates"
        );
        assert_eq!(tracker.streak(healthy), N_CONSECUTIVE_TIMEOUTS_TO_CLOSE - 1);
    }
}
