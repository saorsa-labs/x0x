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

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
}

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
                    }
                }
            }
            P2pEvent::PeerDisconnected { peer_id, .. } => {
                self.disconnects.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut set) = self.connected_view.lock() {
                    set.remove(peer_id);
                }
            }
            _ => {}
        }
    }

    fn observe_lifecycle(&self, event: &PeerLifecycleEvent) {
        match event {
            PeerLifecycleEvent::Established { .. } => {
                self.generations_established.fetch_add(1, Ordering::Relaxed);
            }
            PeerLifecycleEvent::Replaced { .. } => {
                self.generations_replaced.fetch_add(1, Ordering::Relaxed);
            }
            PeerLifecycleEvent::Closed { .. } => {
                self.generations_closed.fetch_add(1, Ordering::Relaxed);
            }
            PeerLifecycleEvent::ReaderExited { .. } => {
                self.reader_exited.fetch_add(1, Ordering::Relaxed);
            }
            PeerLifecycleEvent::Closing { .. } => {}
        }
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
                        Ok((_peer, event)) => counters.observe_lifecycle(&event),
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
