//! Connection-churn observation for the #368 gate-2 measurement.
//!
//! Gate 1 established two separable defects: pathological replacement churn
//! (~40 s connection lifetimes against a stable peer set) and ~5.5 MB of
//! residue per replaced connection. Gate 2 asks WHO drives the churn —
//! x0x-initiated redials of already-connected peers vs inbound replacements
//! — and whether replaced generations are ever fully closed.
//!
//! Pure observation, zero behaviour change: a task in `NetworkNode`
//! subscribes to ant-quic's event streams and counts. The proxy-level
//! `Endpoint::open_connections()` (which includes draining/retained
//! generations) is NOT reachable from x0x — `P2pEndpoint`'s low-level
//! endpoint handle is private in ant-quic 0.27.41 — so the residue signal
//! here is the lifecycle delta: `generations_replaced` vs
//! `generations_closed`. If closed ≈ replaced, generations do not linger
//! and the residue lives elsewhere; if closed ≪ replaced, replaced
//! generations retain state (the ant-quic #210/#255 class).

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ant_quic::{P2pEvent, PeerLifecycleEvent, Side};

/// Churn counters derived from ant-quic's event streams (#368 gate 2).
#[derive(Debug, Default)]
pub(crate) struct ChurnCounters {
    connects_outbound: AtomicU64,
    connects_inbound: AtomicU64,
    /// Connect events (either side) for a peer the event view still showed
    /// connected — the replacement/redial signal.
    connects_while_connected: AtomicU64,
    /// Outbound (Client-side) connects for a peer the event view still
    /// showed connected — x0x redialing an already-connected peer.
    outbound_redials_of_connected: AtomicU64,
    disconnects: AtomicU64,
    generations_established: AtomicU64,
    /// A newer generation replaced the previously active one — THE churn
    /// event.
    generations_replaced: AtomicU64,
    /// A generation fully closed from the endpoint's view. The gap
    /// `replaced − closed` is the lingering-generation residue signal.
    generations_closed: AtomicU64,
    reader_exited: AtomicU64,
    /// Broadcast lag batches dropped (undercounting caveat; expected 0 at
    /// the observed churn rates).
    event_lag_batches: AtomicU64,
    /// Event-view set of currently-connected peer ids.
    connected_view: Mutex<HashSet<ant_quic::PeerId>>,
    /// ADR-0035 metering: peers that successfully dialed US inbound
    /// (Server-side connects), with the most recent time each did.
    /// Distinct-dialer counts over a window are the local ground truth for
    /// future `verified_inbound` promotion — a node's OWN dial evidence,
    /// never a peer's self-asserted count. Bounded (see
    /// `MAX_TRACKED_INBOUND_DIALERS`).
    inbound_dialers: Mutex<HashMap<ant_quic::PeerId, Instant>>,
    /// #774 diagnostic-only (test builds): first observed disconnect and
    /// generation-close reason per peer, captured only while armed by the
    /// delivery fixture. Bounded to `MAX_CLOSE_REASON_PEERS` entries;
    /// first-per-peer wins, later reasons for the same peer are ignored.
    #[cfg(test)]
    close_reason_capture: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    close_reason_seq: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    first_disconnect_reasons: Mutex<HashMap<ant_quic::PeerId, CloseReasonSample>>,
    #[cfg(test)]
    first_closed_reasons: Mutex<HashMap<ant_quic::PeerId, ClosedReasonSample>>,
    #[cfg(test)]
    close_reason_base: Mutex<Option<Instant>>,
}

/// #774 diagnostic-only: first `P2pEvent::PeerDisconnected` reason per peer.
#[cfg(test)]
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct CloseReasonSample {
    pub seq: u64,
    /// Elapsed from the shared arm base; null when the base was not yet
    /// recorded for this capture (never a fabricated value).
    pub at_ms: Option<u128>,
    pub reason: String,
}

/// #774 diagnostic-only: first `PeerLifecycleEvent::Closed` reason per peer.
#[cfg(test)]
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ClosedReasonSample {
    pub seq: u64,
    pub at_ms: Option<u128>,
    pub generation: u64,
    pub reason: String,
}

/// #774 diagnostic-only bound on the close-reason tables.
#[cfg(test)]
const MAX_CLOSE_REASON_PEERS: usize = 32;
/// #774 diagnostic-only bound on retained text from transport errors.
#[cfg(test)]
const MAX_CLOSE_REASON_CHARS: usize = 120;

/// Window over which a distinct inbound dialer counts as "recent" for the
/// ADR-0035 reachability metering. Matches the promotion design's sustained
/// window unit (hours, not the 60s gossip windows).
pub(crate) const INBOUND_DIALER_WINDOW: Duration = Duration::from_secs(3600);

/// Bound on the inbound-dialer table; window-expired entries are evicted on
/// insert once the cap is reached.
const MAX_TRACKED_INBOUND_DIALERS: usize = 4096;

impl ChurnCounters {
    fn observe_p2p(&self, event: &P2pEvent) {
        match event {
            P2pEvent::PeerConnected { peer_id, side, .. } => {
                let already = match self.connected_view.lock() {
                    Ok(mut set) => !set.insert(*peer_id),
                    Err(poisoned) => !poisoned.into_inner().insert(*peer_id),
                };
                if already {
                    self.connects_while_connected
                        .fetch_add(1, Ordering::Relaxed);
                }
                match side {
                    Side::Client => {
                        self.connects_outbound.fetch_add(1, Ordering::Relaxed);
                        if already {
                            self.outbound_redials_of_connected
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Side::Server => {
                        self.connects_inbound.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut dialers) = self.inbound_dialers.lock() {
                            if dialers.len() >= MAX_TRACKED_INBOUND_DIALERS {
                                let cutoff = Instant::now() - INBOUND_DIALER_WINDOW;
                                dialers.retain(|_, t| *t >= cutoff);
                            }
                            dialers.insert(*peer_id, Instant::now());
                        }
                    }
                }
            }
            P2pEvent::PeerDisconnected { peer_id, .. } => {
                self.disconnects.fetch_add(1, Ordering::Relaxed);
                #[cfg(test)]
                if let P2pEvent::PeerDisconnected { reason, .. } = event {
                    self.note_disconnect_reason(peer_id, reason);
                }
                if let Ok(mut set) = self.connected_view.lock() {
                    set.remove(peer_id);
                }
            }
            _ => {}
        }
    }

    fn observe_lifecycle(&self, _peer: &ant_quic::PeerId, event: &PeerLifecycleEvent) {
        match event {
            PeerLifecycleEvent::Established { .. } => {
                self.generations_established.fetch_add(1, Ordering::Relaxed);
            }
            PeerLifecycleEvent::Replaced { .. } => {
                self.generations_replaced.fetch_add(1, Ordering::Relaxed);
            }
            PeerLifecycleEvent::Closed { .. } => {
                self.generations_closed.fetch_add(1, Ordering::Relaxed);
                #[cfg(test)]
                if let PeerLifecycleEvent::Closed { generation, reason } = event {
                    self.note_closed_reason(_peer, *generation, reason);
                }
            }
            PeerLifecycleEvent::ReaderExited { .. } => {
                self.reader_exited.fetch_add(1, Ordering::Relaxed);
            }
            PeerLifecycleEvent::Closing { .. } => {}
        }
    }

    /// #774 diagnostic-only (test builds): arm first-per-peer close-reason
    /// capture against the same monotonic base instant as the edge trace,
    /// so the first closure can be correlated with edge send timestamps.
    /// Records nothing until armed; entries are bounded and never include
    /// payload or key material — only the ant-quic reason enums.
    #[cfg(test)]
    pub(crate) fn arm_close_reason_capture(&self, base: Instant) {
        if let Ok(mut guard) = self.close_reason_base.lock() {
            *guard = Some(base);
            self.close_reason_capture.store(true, Ordering::Release);
        }
    }

    /// #774 diagnostic-only (test builds): bounded snapshot of the first
    /// disconnect and generation-close reasons per peer, with elapsed
    /// offsets from the shared arm base.
    #[cfg(test)]
    pub(crate) fn close_reason_snapshot(&self) -> serde_json::Value {
        let first_disconnect = match self.first_disconnect_reasons.lock() {
            Ok(map) => map
                .iter()
                .map(|(peer, sample)| {
                    (
                        hex::encode(peer.0),
                        serde_json::to_value(sample).unwrap_or(serde_json::Value::Null),
                    )
                })
                .collect::<serde_json::Map<_, _>>(),
            Err(_) => serde_json::Map::new(),
        };
        let first_closed = match self.first_closed_reasons.lock() {
            Ok(map) => map
                .iter()
                .map(|(peer, sample)| {
                    (
                        hex::encode(peer.0),
                        serde_json::to_value(sample).unwrap_or(serde_json::Value::Null),
                    )
                })
                .collect::<serde_json::Map<_, _>>(),
            Err(_) => serde_json::Map::new(),
        };
        serde_json::json!({
            "first_disconnect_reason": first_disconnect,
            "first_generation_closed_reason": first_closed,
        })
    }

    #[cfg(test)]
    fn note_disconnect_reason(
        &self,
        peer_id: &ant_quic::PeerId,
        reason: &ant_quic::DisconnectReason,
    ) {
        if !self.close_reason_capture.load(Ordering::Acquire) {
            return;
        }
        let seq = self.close_reason_seq.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.first_disconnect_reasons.lock() {
            if map.len() >= MAX_CLOSE_REASON_PEERS && !map.contains_key(peer_id) {
                return;
            }
            map.entry(*peer_id).or_insert(CloseReasonSample {
                seq,
                at_ms: self.elapsed_since_base(),
                reason: format!("{reason:?}")
                    .chars()
                    .take(MAX_CLOSE_REASON_CHARS)
                    .collect(),
            });
        }
    }
    #[cfg(test)]
    fn note_closed_reason(
        &self,
        peer_id: &ant_quic::PeerId,
        generation: u64,
        reason: &ant_quic::ConnectionCloseReason,
    ) {
        if !self.close_reason_capture.load(Ordering::Acquire) {
            return;
        }
        let seq = self.close_reason_seq.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.first_closed_reasons.lock() {
            if map.len() >= MAX_CLOSE_REASON_PEERS && !map.contains_key(peer_id) {
                return;
            }
            map.entry(*peer_id).or_insert(ClosedReasonSample {
                seq,
                at_ms: self.elapsed_since_base(),
                generation,
                reason: format!("{reason:?}"),
            });
        }
    }

    /// #774 diagnostic-only: elapsed from the shared arm base, or `None`
    /// when no base was recorded — never a fabricated timestamp.
    #[cfg(test)]
    fn elapsed_since_base(&self) -> Option<u128> {
        self.close_reason_base
            .lock()
            .ok()
            .and_then(|base| base.map(|base| base.elapsed().as_millis()))
    }

    fn note_lag(&self) {
        self.event_lag_batches.fetch_add(1, Ordering::Relaxed);
    }

    /// Spawn the observer task over both event streams. The task exits when
    /// either stream closes (endpoint shutdown); broadcast lag is counted,
    /// never fatal.
    pub(crate) fn spawn_observer(self: Arc<Self>, node: &ant_quic::Node) {
        // P2pEvent (not Node::subscribe's NodeEvent) is required: only the
        // endpoint-level event carries `side`, the dial-direction signal.
        let mut p2p_rx = node.inner_endpoint().subscribe();
        let mut lifecycle_rx = node.subscribe_all_peer_events();
        let counters = Arc::clone(&self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe = p2p_rx.recv() => match maybe {
                        Ok(event) => counters.observe_p2p(&event),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            counters.note_lag();
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                    maybe = lifecycle_rx.recv() => match maybe {
                        Ok((peer, event)) => counters.observe_lifecycle(&peer, &event),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            counters.note_lag();
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        });
    }

    /// Snapshot for `GET /diagnostics/transport` → `churn`.
    #[must_use]
    pub(crate) fn snapshot(&self) -> ChurnSnapshot {
        ChurnSnapshot {
            connects_outbound: self.connects_outbound.load(Ordering::Relaxed),
            connects_inbound: self.connects_inbound.load(Ordering::Relaxed),
            connects_while_connected: self.connects_while_connected.load(Ordering::Relaxed),
            outbound_redials_of_connected: self
                .outbound_redials_of_connected
                .load(Ordering::Relaxed),
            disconnects: self.disconnects.load(Ordering::Relaxed),
            generations_established: self.generations_established.load(Ordering::Relaxed),
            generations_replaced: self.generations_replaced.load(Ordering::Relaxed),
            generations_closed: self.generations_closed.load(Ordering::Relaxed),
            reader_exited: self.reader_exited.load(Ordering::Relaxed),
            event_lag_batches: self.event_lag_batches.load(Ordering::Relaxed),
            distinct_inbound_dialers_1h: self.distinct_inbound_dialers(INBOUND_DIALER_WINDOW),
        }
    }

    /// Distinct peers that completed an inbound handshake within `window`.
    /// ADR-0035 metering: local dial evidence for reachability promotion.
    pub(crate) fn distinct_inbound_dialers(&self, window: Duration) -> u64 {
        let cutoff = match Instant::now().checked_sub(window) {
            Some(c) => c,
            None => return 0,
        };
        match self.inbound_dialers.lock() {
            Ok(dialers) => dialers.values().filter(|t| **t >= cutoff).count() as u64,
            Err(_) => 0,
        }
    }
}

/// Serialized churn snapshot (issue #368 gate 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ChurnSnapshot {
    /// Completed handshakes we initiated (Client side).
    pub connects_outbound: u64,
    /// Completed inbound handshakes (Server side).
    pub connects_inbound: u64,
    /// ADR-0035: distinct peers that completed an inbound handshake in the
    /// last hour — the node's OWN evidence that it is publicly dialable
    /// (promotion requires this to be sustained; a peer's self-asserted
    /// count is never trusted in its place).
    pub distinct_inbound_dialers_1h: u64,
    /// Handshakes for a peer still shown connected by the event view.
    pub connects_while_connected: u64,
    /// Outbound handshakes for a peer still shown connected — x0x redials
    /// of connected peers (the auto-connect-churn hypothesis).
    pub outbound_redials_of_connected: u64,
    pub disconnects: u64,
    pub generations_established: u64,
    /// New generations that replaced a live one — THE churn event.
    pub generations_replaced: u64,
    /// Generations fully closed; `replaced − closed` ≫ 0 means replaced
    /// generations linger with their state.
    pub generations_closed: u64,
    pub reader_exited: u64,
    pub event_lag_batches: u64,
}

#[cfg(test)]
mod issue774_tests {
    use super::*;

    fn peer(byte: u8) -> ant_quic::PeerId {
        ant_quic::PeerId([byte; 32])
    }

    /// #774 diagnostic-only capture: socket-free synthetic-event control.
    /// Proves opt-in arming, first-per-peer retention, the peer bound, and
    /// the JSON snapshot shape. No Node, endpoint, or socket is created.
    #[test]
    fn close_reason_capture_is_opt_in_bounded_and_first_per_peer() {
        let counters = ChurnCounters::default();

        // Unarmed: events are counted but no reasons are retained.
        counters.observe_p2p(&P2pEvent::PeerDisconnected {
            peer_id: peer(1),
            reason: ant_quic::DisconnectReason::Timeout,
        });
        assert!(
            counters
                .first_disconnect_reasons
                .lock()
                .expect("disconnect map")
                .is_empty(),
            "capture must record nothing before arming"
        );

        let base = Instant::now();
        counters.arm_close_reason_capture(base);
        counters.observe_p2p(&P2pEvent::PeerDisconnected {
            peer_id: peer(1),
            reason: ant_quic::DisconnectReason::Timeout,
        });
        counters.observe_p2p(&P2pEvent::PeerDisconnected {
            peer_id: peer(1),
            reason: ant_quic::DisconnectReason::ConnectionLost,
        });
        let disconnects = counters
            .first_disconnect_reasons
            .lock()
            .expect("disconnect map");
        assert_eq!(disconnects.len(), 1, "first-per-peer retention");
        assert_eq!(
            disconnects[&peer(1)].reason,
            "Timeout",
            "later reasons for the same peer must not replace the first"
        );
        assert_eq!(counters.disconnects.load(Ordering::Relaxed), 3);
        drop(disconnects);

        // Endpoint ProtocolError carries arbitrary text; never retain it unbounded.
        counters.observe_p2p(&P2pEvent::PeerDisconnected {
            peer_id: peer(2),
            reason: ant_quic::DisconnectReason::ProtocolError("E".repeat(400)),
        });
        let reasons = counters
            .first_disconnect_reasons
            .lock()
            .expect("disconnect map");
        assert_eq!(
            reasons[&peer(2)].reason.chars().count(),
            MAX_CLOSE_REASON_CHARS,
            "transport error text must be bounded"
        );
        drop(reasons);

        counters.observe_lifecycle(
            &peer(1),
            &PeerLifecycleEvent::Closed {
                generation: 7,
                reason: ant_quic::ConnectionCloseReason::Superseded,
            },
        );
        let closes = counters.first_closed_reasons.lock().expect("closed map");
        assert_eq!(closes.len(), 1, "first close per peer retained");
        assert_eq!(closes[&peer(1)].generation, 7);
        assert!(
            closes[&peer(1)].at_ms.is_some(),
            "at_ms must be a real elapsed offset from the shared arm base"
        );
        assert_eq!(closes[&peer(1)].reason, "Superseded");
        drop(closes);

        // Bound: distinct peers beyond MAX_CLOSE_REASON_PEERS are ignored.
        for byte in 0..u8::try_from(MAX_CLOSE_REASON_PEERS + 8).expect("bound fits u8") {
            counters.observe_lifecycle(
                &peer(byte),
                &PeerLifecycleEvent::Closed {
                    generation: 1,
                    reason: ant_quic::ConnectionCloseReason::LifecycleCleanup,
                },
            );
        }
        let bounded = counters
            .first_closed_reasons
            .lock()
            .expect("closed map")
            .len();
        assert!(
            bounded <= MAX_CLOSE_REASON_PEERS,
            "close-reason table must stay bounded, got {bounded}"
        );

        let snapshot = counters.close_reason_snapshot();
        assert!(
            snapshot["first_disconnect_reason"][hex::encode(peer(1).0)]["reason"]
                .as_str()
                .is_some(),
            "snapshot must serialize per-peer first disconnect reason"
        );
        assert!(
            snapshot["first_generation_closed_reason"][hex::encode(peer(1).0)]["generation"]
                .as_u64()
                .is_some(),
            "snapshot must serialize per-peer first closed reason"
        );
    }
}
