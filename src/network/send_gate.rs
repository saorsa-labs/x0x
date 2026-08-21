//! Per-peer in-flight send cap for gossip sends (#368, design v2).
//!
//! v1 ("destructive cooldown") falsified by soak: a fixed 1.2 s transport
//! timeout undercuts saorsa-gossip's ADAPTIVE per-peer timeout (floor
//! 1.5 s, grows under load), so most timeouts on a NAT'd node are false
//! stalls — and closing connections on them trades pinned stream buffers
//! for redial/handshake/NAT-traversal churn that allocates MORE than the
//! teardown frees (ant-quic #210 class; early slope ~4 GB/h vs ~1.3 GB/h
//! baseline; see issue #368).
//!
//! v2 keeps the mechanism (bound the outbound memory a stalled peer can
//! pin) and changes the remedy: STOP OPENING new streams to a saturated
//! peer instead of tearing the peer down.
//!
//! - Each peer gets a semaphore of [`MAX_INFLIGHT_SENDS_PER_PEER`] permits.
//!   A send acquires with `try_acquire`; when none is free (the peer already
//!   has K stalled/slow sends) the transport returns an error immediately
//!   WITHOUT opening a stream. saorsa-gossip sees the error and applies its
//!   own cooldown/backoff. No connection churn.
//! - No fixed transport timeout: the send future runs under saorsa-gossip's
//!   adaptive outer timeout again. The permit lives inside the future, so
//!   whether the send completes or sg's timeout drops the future mid-write,
//!   the slot is released — in-flight (and therefore stream-opening) memory
//!   per peer is bounded to K messages.
//! - A connection close exists ONLY for a genuinely dead peer: one whose
//!   permits have been continuously exhausted for
//!   [`DEAD_PEER_SATURATION_WINDOW`] (no send completed while saturated),
//!   rate-limited to one close per peer per [`DEAD_PEER_CLOSE_RATE_LIMIT`].
//!   This must be rare — the soak gate asserts < 5 closes/hour.
//!
//! Inbound `Assembler` pinning (the receive half of the profile) is not
//! addressable from x0x; that is ant-quic #255.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Maximum concurrently in-flight uni-stream sends to one peer (#368 v2).
///
/// Bounds the outbound stream memory a single stalled peer can pin to
/// K × message-size, while leaving healthy peers (sends complete in well
/// under a second) effectively unlimited — they never hold K at once.
pub(crate) const MAX_INFLIGHT_SENDS_PER_PEER: usize = 8;

/// A peer whose permits have been continuously exhausted for this long with
/// no completed send is dead for routing purposes and its connection is
/// closed (by peer-id). Shorter windows fire on healthy-but-slow WAN paths;
/// the v1 soak showed false positives are worse than the leak they patch.
pub(crate) const DEAD_PEER_SATURATION_WINDOW: Duration = Duration::from_secs(60);

/// Minimum wall time between dead-peer closes of the same peer: a flapping
/// peer must not loop close → redial → close.
pub(crate) const DEAD_PEER_CLOSE_RATE_LIMIT: Duration = Duration::from_secs(5 * 60);

/// Per-peer in-flight send gates plus the v2 proof counters
/// (`GET /diagnostics/gossip` → `send_gate`).
#[derive(Debug, Default)]
pub(crate) struct PeerSendGate {
    inflight: Mutex<HashMap<[u8; 32], Arc<Semaphore>>>,
    /// When each peer's permits last went from available to exhausted;
    /// continuous saturation past `saturation_window` marks a dead peer.
    saturated_since: Mutex<HashMap<[u8; 32], Instant>>,
    last_close_at: Mutex<HashMap<[u8; 32], Instant>>,
    saturation_window: Option<Duration>,
    close_rate_limit: Option<Duration>,
    sends_rejected_saturated: AtomicU64,
    conns_closed_dead_peer: AtomicU64,
}

impl PeerSendGate {
    /// Gate with the production windows.
    pub(crate) fn new() -> Self {
        Self {
            saturation_window: Some(DEAD_PEER_SATURATION_WINDOW),
            close_rate_limit: Some(DEAD_PEER_CLOSE_RATE_LIMIT),
            ..Self::default()
        }
    }

    /// Test constructor with explicit windows so the dead-peer logic is
    /// exercisable without minute-long sleeps.
    #[cfg(test)]
    pub(crate) fn with_windows(saturation_window: Duration, close_rate_limit: Duration) -> Self {
        Self {
            saturation_window: Some(saturation_window),
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

    /// Acquire an in-flight send slot for `peer`.
    ///
    /// `Ok(permit)` — the send may open a stream; the slot is released when
    /// the permit drops (send completed, or saorsa-gossip's adaptive timeout
    /// dropped the future). `Err(())` — the peer is saturated: the caller
    /// MUST return an error without opening a stream.
    pub(crate) fn acquire(&self, peer: [u8; 32]) -> Result<OwnedSemaphorePermit, ()> {
        let semaphore = Self::lock_map(&self.inflight, |m| {
            m.entry(peer)
                .or_insert_with(|| Arc::new(Semaphore::new(MAX_INFLIGHT_SENDS_PER_PEER)))
                .clone()
        });
        match semaphore.try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(_) => {
                self.sends_rejected_saturated
                    .fetch_add(1, Ordering::Relaxed);
                Self::lock_map(&self.saturated_since, |m| {
                    m.entry(peer).or_insert_with(Instant::now);
                });
                Err(())
            }
        }
    }

    /// Record a completed send: ends the peer's continuous-saturation
    /// streak (a peer that completes anything is alive).
    pub(crate) fn note_completed(&self, peer: [u8; 32]) {
        Self::lock_map(&self.saturated_since, |m| {
            m.remove(&peer);
        });
    }

    /// True when the peer has been continuously saturated past the
    /// dead-peer window AND the per-peer close rate limit allows another
    /// close — the caller should close the connection (by peer-id).
    pub(crate) fn should_close_dead_peer(&self, peer: [u8; 32]) -> bool {
        let saturated_long_enough = Self::lock_map(&self.saturated_since, |m| {
            m.get(&peer)
                .is_some_and(|since| since.elapsed() >= self.saturation_window.unwrap_or_default())
        });
        if !saturated_long_enough {
            return false;
        }
        Self::lock_map(&self.last_close_at, |m| {
            m.get(&peer)
                .is_none_or(|at| at.elapsed() >= self.close_rate_limit.unwrap_or_default())
        })
    }

    /// Record the dead-peer close: bumps the proof counter, arms the rate
    /// limit, and clears the saturation streak.
    pub(crate) fn note_closed(&self, peer: [u8; 32]) {
        self.conns_closed_dead_peer.fetch_add(1, Ordering::Relaxed);
        Self::lock_map(&self.saturated_since, |m| {
            m.remove(&peer);
        });
        Self::lock_map(&self.last_close_at, |m| {
            m.insert(peer, Instant::now());
        });
    }

    /// Proof counters for `GET /diagnostics/gossip`.
    #[must_use]
    pub(crate) fn snapshot(&self) -> SendGateSnapshot {
        SendGateSnapshot {
            sends_rejected_saturated: self.sends_rejected_saturated.load(Ordering::Relaxed),
            peers_saturated_now: u64::try_from(Self::lock_map(&self.saturated_since, |m| m.len()))
                .unwrap_or(u64::MAX),
            conns_closed_dead_peer: self.conns_closed_dead_peer.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of the send-gate proof counters (issue #368 v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SendGateSnapshot {
    /// Sends rejected because the peer already held the maximum in-flight
    /// permits — each would have opened (and pinned) another stream.
    pub sends_rejected_saturated: u64,
    /// Peers currently in a saturated streak (all permits held).
    pub peers_saturated_now: u64,
    /// Connections closed by the dead-peer escalation (must stay rare:
    /// the soak gate asserts < 5/hour).
    pub conns_closed_dead_peer: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Why (#368 v2): the cap bounds the streams a stalled peer can pin —
    /// the K+1th concurrent send is rejected without opening a stream, and
    /// a released slot (send completed OR future dropped by sg's timeout)
    /// immediately admits the next send.
    #[test]
    fn gate_rejects_beyond_cap_and_readmits_on_release() {
        let gate = PeerSendGate::new();
        let peer = [0x11; 32];

        let mut permits = Vec::new();
        for _ in 0..MAX_INFLIGHT_SENDS_PER_PEER {
            permits.push(gate.acquire(peer).expect("first K sends are admitted"));
        }
        assert!(
            gate.acquire(peer).is_err(),
            "K+1th concurrent send rejected"
        );
        assert_eq!(gate.snapshot().sends_rejected_saturated, 1);

        // Drop one permit — exactly as sg's adaptive timeout dropping the
        // in-flight future would — and the slot readmits.
        drop(permits.pop());
        assert!(
            gate.acquire(peer).is_ok(),
            "released slot (future drop) readmits the next send"
        );
        assert_eq!(gate.snapshot().peers_saturated_now, 1, "still saturated");
    }

    /// Why (#368 v2): a completed send ends the saturation streak — a peer
    /// that finishes anything is alive, not dead.
    #[test]
    fn completed_send_ends_saturation() {
        let gate = PeerSendGate::with_windows(Duration::from_millis(50), Duration::from_secs(300));
        let peer = [0x22; 32];

        let _permits: Vec<_> = (0..MAX_INFLIGHT_SENDS_PER_PEER)
            .map(|_| gate.acquire(peer).expect("admitted"))
            .collect();
        assert!(gate.acquire(peer).is_err());
        assert_eq!(gate.snapshot().peers_saturated_now, 1);

        gate.note_completed(peer);
        assert_eq!(gate.snapshot().peers_saturated_now, 0);
        std::thread::sleep(Duration::from_millis(70));
        assert!(
            !gate.should_close_dead_peer(peer),
            "a peer that completed a send is never dead-peer closed"
        );
    }

    /// Why (#368 v2 / v1 lesson): the dead-peer close fires ONLY after the
    /// continuous-saturation window, at most once per rate-limit window —
    /// no close→redial→close churn.
    #[test]
    fn dead_peer_close_waits_for_window_and_is_rate_limited() {
        let gate =
            PeerSendGate::with_windows(Duration::from_millis(60), Duration::from_millis(120));
        let peer = [0x33; 32];

        let first_permits: Vec<_> = (0..MAX_INFLIGHT_SENDS_PER_PEER)
            .map(|_| gate.acquire(peer).expect("admitted"))
            .collect();
        assert!(gate.acquire(peer).is_err(), "saturated");

        assert!(
            !gate.should_close_dead_peer(peer),
            "saturation younger than the window must not close"
        );
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            gate.should_close_dead_peer(peer),
            "continuous saturation past the window closes"
        );

        // The close decision reads the saturation streak, not the live
        // permits — release them, then record the close.
        drop(first_permits);
        gate.note_closed(peer);
        // Release the first saturation's permits, then immediately
        // re-saturate (streak restarts).
        {
            let _permits: Vec<_> = (0..MAX_INFLIGHT_SENDS_PER_PEER)
                .map(|_| gate.acquire(peer).expect("readmitted after close"))
                .collect();
            assert!(gate.acquire(peer).is_err());
        }
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            !gate.should_close_dead_peer(peer),
            "close rate limit refuses a second close inside the window"
        );
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            gate.should_close_dead_peer(peer),
            "close allowed again once the rate-limit window elapses"
        );
        assert_eq!(gate.snapshot().conns_closed_dead_peer, 1);
    }

    /// Why: gates are per-peer — one peer's saturation must not reject
    /// another peer's sends.
    #[test]
    fn gates_are_per_peer() {
        let gate = PeerSendGate::new();
        let stalled = [0x44; 32];
        let healthy = [0x55; 32];

        let _permits: Vec<_> = (0..MAX_INFLIGHT_SENDS_PER_PEER)
            .map(|_| gate.acquire(stalled).expect("admitted"))
            .collect();
        assert!(gate.acquire(stalled).is_err());
        assert!(
            gate.acquire(healthy).is_ok(),
            "healthy peer's sends are unaffected"
        );
    }
}
