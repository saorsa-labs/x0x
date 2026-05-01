//! Direct agent-to-agent messaging.
//!
//! This module provides point-to-point communication between agents,
//! bypassing the gossip layer for private, efficient, reliable delivery.
//!
//! ## Overview
//!
//! While gossip pub/sub is great for broadcast and eventually-consistent
//! data sharing, many use cases require direct communication:
//!
//! - Private messages between two agents
//! - Request/response patterns
//! - Large file transfers
//! - Real-time coordination
//!
//! ## Wire Format
//!
//! Direct messages use stream type byte `0x10` to distinguish from gossip:
//!
//! ```text
//! [0x10][sender_agent_id: 32 bytes][payload: N bytes]
//! ```
//!
//! The sender's AgentId is included in the message so the receiver can
//! identify who sent it, even if multiple agents share a machine.
//!
//! ## Security Model
//!
//! **Sender identity verification.** Each [`DirectMessage`] carries a `verified`
//! field that indicates whether the claimed `sender` AgentId was cross-referenced
//! against the identity discovery cache (which contains signed identity
//! announcements). When `verified` is `true`, the AgentId→MachineId binding
//! was confirmed. When `false`, the AgentId is self-asserted only.
//!
//! The underlying QUIC connection is always authenticated by the sender's
//! [`MachineId`](crate::identity::MachineId) via ML-DSA-65 signatures.
//!
//! **Trust annotations.** Each message also carries a `trust_decision` field
//! from [`TrustEvaluator`](crate::trust::TrustEvaluator), reflecting the
//! full trust evaluation including contact store trust level and machine
//! pinning. Messages are never dropped — applications inspect these fields
//! to decide how to handle each message.
//!
//! ## Example
//!
//! ```rust,ignore
//! use x0x::{Agent, DirectMessage};
//!
//! // Agent A sends to Agent B
//! let outcome = agent_a.connect_to_agent(&agent_b_id).await?;
//! agent_a.send_direct(&agent_b_id, b"hello".to_vec()).await?;
//!
//! // Agent B receives
//! let msg = agent_b.recv_direct().await?;
//! assert_eq!(msg.sender, agent_a.agent_id());
//! assert_eq!(msg.payload, b"hello");
//! ```

use crate::dm::DmPath;
use crate::error::{NetworkError, NetworkResult};
use crate::identity::{AgentId, MachineId};
use crate::trust::TrustDecision;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};

/// Stream type byte for direct messages (distinct from gossip: 0, 1, 2).
pub const DIRECT_MESSAGE_STREAM_TYPE: u8 = 0x10;

/// Maximum payload size for direct messages (16 MB).
pub const MAX_DIRECT_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Per-subscriber direct-message buffer depth.
///
/// Each `subscribe_direct()` caller gets an independent queue of this size so
/// one slow SSE/WebSocket/file-transfer consumer cannot force drops for every
/// other consumer.
const DIRECT_SUBSCRIBER_BUFFER: usize = 8192;

/// A direct message received from another agent.
///
/// # Security Note
///
/// The `sender` field is **self-asserted** by the sender and not cryptographically
/// verified. However, `machine_id` is authenticated via the QUIC connection's
/// ML-DSA-65 handshake, so you can trust which machine sent this message.
///
/// The claimed `sender` AgentId is only as trustworthy as the machine that sent it.
/// For sensitive operations, verify the AgentId→MachineId binding against a
/// trusted source (e.g., a signed identity announcement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMessage {
    /// The AgentId claimed by the sender.
    ///
    /// **Warning:** This is self-asserted and not cryptographically verified.
    /// Use `machine_id` for authenticated sender identity, or check the
    /// `verified` field which cross-references the identity discovery cache.
    pub sender: AgentId,
    /// The MachineId the message was sent from (authenticated via QUIC).
    ///
    /// This is derived from the QUIC connection's peer identity and is
    /// cryptographically verified via ML-DSA-65 signatures.
    pub machine_id: MachineId,
    /// The message payload.
    pub payload: Vec<u8>,
    /// Unix timestamp (milliseconds) when the message was received.
    pub received_at: u64,
    /// Whether the sender's AgentId was verified against the identity
    /// discovery cache.
    ///
    /// `true` if the cache contains an entry mapping this `sender` AgentId
    /// to this `machine_id`. `false` if the AgentId could not be verified
    /// (self-asserted only — the sender may still be legitimate but hasn't
    /// been seen via a signed identity announcement yet).
    pub verified: bool,
    /// Trust decision from [`TrustEvaluator`](crate::trust::TrustEvaluator)
    /// for the `(sender, machine_id)` pair.
    ///
    /// `None` if the trust system was unavailable at receive time.
    /// When present, reflects the full trust evaluation including contact
    /// store trust level and machine pinning.
    pub trust_decision: Option<TrustDecision>,
}

impl DirectMessage {
    /// Create a new `DirectMessage` with default verification fields.
    ///
    /// `verified` defaults to `false` and `trust_decision` to `None`.
    /// Use [`new_verified`](Self::new_verified) to set these fields.
    #[must_use]
    pub fn new(sender: AgentId, machine_id: MachineId, payload: Vec<u8>) -> Self {
        Self::new_verified(sender, machine_id, payload, false, None)
    }

    /// Create a new `DirectMessage` with explicit verification fields.
    #[must_use]
    pub fn new_verified(
        sender: AgentId,
        machine_id: MachineId,
        payload: Vec<u8>,
        verified: bool,
        trust_decision: Option<TrustDecision>,
    ) -> Self {
        let received_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            sender,
            machine_id,
            payload,
            received_at,
            verified,
            trust_decision,
        }
    }

    /// Returns the payload as a UTF-8 string if valid.
    #[must_use]
    pub fn payload_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.payload).ok()
    }
}

fn now_unix_ms_lossy() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn dm_path_label(path: DmPath) -> &'static str {
    match path {
        DmPath::GossipInbox => "gossip_inbox",
        DmPath::RawQuic => "raw_quic",
        DmPath::RawQuicAcked => "raw_quic_acked",
    }
}

/// Compute a stable, short content digest for `dm.trace` correlation.
///
/// Returns the first 16 hex characters (64 bits) of a BLAKE3 hash of the
/// supplied bytes. Used to correlate sender-side and receiver-side
/// `dm.trace` lines for a single message regardless of whether it travelled
/// the raw-QUIC or gossip-inbox path. The full payload is always available
/// to both ends — the gossip path decrypts before fan-out — so the same
/// input produces the same digest on both sides.
#[must_use]
pub fn dm_payload_digest_hex(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    let hex = hex::encode(hash.as_bytes());
    hex[..16].to_string()
}

/// Receiver for direct messages.
///
/// Each receiver owns an independent bounded mpsc queue. Cloning a receiver
/// creates a fresh subscription rather than sharing cursor state, preserving
/// the old broadcast-style "every subscriber sees every future message"
/// semantics without tokio broadcast's global lag/drop behaviour.
#[derive(Debug)]
pub struct DirectMessageReceiver {
    id: Option<u64>,
    rx: mpsc::Receiver<DirectMessage>,
    subscribers: Arc<Mutex<HashMap<u64, mpsc::Sender<DirectMessage>>>>,
    next_subscriber_id: Arc<AtomicU64>,
    capacity: usize,
}

impl DirectMessageReceiver {
    /// Create and register a new receiver in the shared subscriber registry.
    pub(crate) fn new(
        subscribers: Arc<Mutex<HashMap<u64, mpsc::Sender<DirectMessage>>>>,
        next_subscriber_id: Arc<AtomicU64>,
        capacity: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        let id = next_subscriber_id.fetch_add(1, Ordering::Relaxed);
        let registered = match subscribers.lock() {
            Ok(mut guard) => {
                guard.insert(id, tx);
                Some(id)
            }
            Err(e) => {
                tracing::error!("direct subscriber registry poisoned: {e}");
                None
            }
        };

        Self {
            id: registered,
            rx,
            subscribers,
            next_subscriber_id,
            capacity,
        }
    }

    /// Receive the next direct message.
    ///
    /// Returns `None` if this subscriber was dropped because it fell behind,
    /// the daemon is shutting down, or the channel closed.
    pub async fn recv(&mut self) -> Option<DirectMessage> {
        self.rx.recv().await
    }

    /// Try to receive a message without blocking.
    ///
    /// Returns `None` if no message is available or channel is closed.
    pub fn try_recv(&mut self) -> Option<DirectMessage> {
        self.rx.try_recv().ok()
    }
}

impl Clone for DirectMessageReceiver {
    fn clone(&self) -> Self {
        Self::new(
            Arc::clone(&self.subscribers),
            Arc::clone(&self.next_subscriber_id),
            self.capacity,
        )
    }
}

impl Drop for DirectMessageReceiver {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        match self.subscribers.lock() {
            Ok(mut guard) => {
                guard.remove(&id);
            }
            Err(e) => tracing::error!("direct subscriber registry poisoned on drop: {e}"),
        }
    }
}

#[derive(Debug, Default)]
struct DirectDiagnosticsCounters {
    outgoing_send_total: AtomicU64,
    outgoing_send_succeeded: AtomicU64,
    outgoing_send_failed: AtomicU64,
    outgoing_path_raw_quic: AtomicU64,
    outgoing_path_gossip_inbox: AtomicU64,
    incoming_envelopes_total: AtomicU64,
    incoming_decode_failed: AtomicU64,
    incoming_signature_failed: AtomicU64,
    incoming_trust_rejected: AtomicU64,
    incoming_delivered_to_subscribe: AtomicU64,
    subscriber_channel_lagged: AtomicU64,
    subscriber_channel_closed: AtomicU64,
}

#[derive(Debug, Clone, Default)]
struct DirectPeerDiagnosticsState {
    avg_rtt_ms: Option<u32>,
    last_send_at_ms: Option<u64>,
    last_recv_at_ms: Option<u64>,
    send_succeeded: u64,
    send_failed: u64,
    recv_count: u64,
    preferred_path: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
struct DirectLifecycleState {
    generation: Option<u64>,
    blocked_reason: Option<String>,
}

/// Global direct-message diagnostics exposed by `/diagnostics/dm`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DmDiagnosticsStats {
    pub outgoing_send_total: u64,
    pub outgoing_send_succeeded: u64,
    pub outgoing_send_failed: u64,
    pub outgoing_path_raw_quic: u64,
    pub outgoing_path_gossip_inbox: u64,
    pub incoming_envelopes_total: u64,
    pub incoming_decode_failed: u64,
    pub incoming_signature_failed: u64,
    pub incoming_trust_rejected: u64,
    pub incoming_delivered_to_subscribe: u64,
    pub subscriber_channel_lagged: u64,
    pub subscriber_channel_closed: u64,
}

/// Per-peer direct-message diagnostics exposed by `/diagnostics/dm`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DmPeerDiagnostics {
    pub avg_rtt_ms: Option<u32>,
    pub last_send_ms_ago: Option<u64>,
    pub last_recv_ms_ago: Option<u64>,
    pub send_succeeded: u64,
    pub send_failed: u64,
    pub recv_count: u64,
    pub preferred_path: String,
}

/// Snapshot of the direct-message diagnostics surface.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DmDiagnosticsSnapshot {
    pub stats: DmDiagnosticsStats,
    pub per_peer: BTreeMap<String, DmPeerDiagnostics>,
    pub subscriber_count: usize,
    pub subscriber_capacity: usize,
}

/// Tracks connections and mappings for direct messaging.
///
/// This maintains the MachineId → AgentId reverse lookup needed to
/// identify message senders, since ant-quic only knows about MachineIds.
#[derive(Debug)]
pub struct DirectMessaging {
    /// Reverse mapping: MachineId → AgentId.
    /// Built from discovered agents.
    machine_to_agent: Arc<RwLock<HashMap<MachineId, AgentId>>>,

    /// Currently connected agents (AgentId → MachineId).
    connected_agents: Arc<RwLock<HashMap<AgentId, MachineId>>>,

    /// Per-subscriber queues for received direct messages.
    subscribers: Arc<Mutex<HashMap<u64, mpsc::Sender<DirectMessage>>>>,

    /// Monotonic id source for subscriber queues.
    next_subscriber_id: Arc<AtomicU64>,

    /// Queue capacity assigned to each subscriber.
    subscriber_capacity: usize,

    /// Global direct-message diagnostics counters.
    diagnostics: Arc<DirectDiagnosticsCounters>,

    /// Per-peer direct-message diagnostics state.
    peer_diagnostics: Arc<Mutex<HashMap<AgentId, DirectPeerDiagnosticsState>>>,

    /// Hot peer lifecycle table keyed by MachineId.
    lifecycle: Arc<Mutex<HashMap<MachineId, DirectLifecycleState>>>,

    /// Internal sender for the receiver task.
    internal_tx: mpsc::Sender<DirectMessage>,

    /// Internal receiver (owned by the processing task).
    internal_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<DirectMessage>>>,
}

impl DirectMessaging {
    /// Create a new DirectMessaging instance.
    #[must_use]
    pub fn new() -> Self {
        // Each subscribe_direct() caller now gets an independent queue. This
        // preserves fan-out semantics without tokio::sync::broadcast's
        // behaviour of making a lagging receiver skip old messages. If a
        // subscriber fills its own queue we drop that subscriber explicitly and
        // count it in diagnostics instead of silently dropping messages for it.
        let (internal_tx, internal_rx) = mpsc::channel(DIRECT_SUBSCRIBER_BUFFER);

        Self {
            machine_to_agent: Arc::new(RwLock::new(HashMap::new())),
            connected_agents: Arc::new(RwLock::new(HashMap::new())),
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            next_subscriber_id: Arc::new(AtomicU64::new(1)),
            subscriber_capacity: DIRECT_SUBSCRIBER_BUFFER,
            diagnostics: Arc::new(DirectDiagnosticsCounters::default()),
            peer_diagnostics: Arc::new(Mutex::new(HashMap::new())),
            lifecycle: Arc::new(Mutex::new(HashMap::new())),
            internal_tx,
            internal_rx: Arc::new(tokio::sync::Mutex::new(internal_rx)),
        }
    }

    /// Register a mapping from MachineId to AgentId.
    ///
    /// Called when an agent is discovered or connected.
    pub async fn register_agent(&self, agent_id: AgentId, machine_id: MachineId) {
        let mut map = self.machine_to_agent.write().await;
        map.insert(machine_id, agent_id);
        tracing::debug!(
            "Registered agent mapping: {:?} -> {:?}",
            machine_id,
            agent_id
        );
    }

    /// Look up AgentId from MachineId.
    pub async fn lookup_agent(&self, machine_id: &MachineId) -> Option<AgentId> {
        let map = self.machine_to_agent.read().await;
        map.get(machine_id).copied()
    }

    /// Mark an agent as connected.
    pub async fn mark_connected(&self, agent_id: AgentId, machine_id: MachineId) {
        // Ensure we have the mapping
        self.register_agent(agent_id, machine_id).await;

        let mut connected = self.connected_agents.write().await;
        connected.insert(agent_id, machine_id);
        self.record_lifecycle_established(machine_id, None);
        tracing::info!("Agent connected: {:?}", agent_id);
    }

    /// Mark an agent as disconnected.
    pub async fn mark_disconnected(&self, agent_id: &AgentId) {
        let mut connected = self.connected_agents.write().await;
        connected.remove(agent_id);
        // NetworkEvent::PeerDisconnected carries no ant-quic lifecycle
        // generation. A delayed disconnect for a superseded old connection can
        // therefore arrive after a newer Established/Replaced event. Do not
        // write a lifecycle block here; generation-bearing Closed events are
        // the authoritative source for the send fast-fail table.
        tracing::info!("Agent disconnected: {:?}", agent_id);
    }

    /// Record an established lifecycle generation for a machine.
    pub fn record_lifecycle_established(&self, machine_id: MachineId, generation: Option<u64>) {
        self.update_lifecycle(machine_id, |state| {
            if let Some(generation) = generation {
                state.generation = Some(generation);
            }
            state.blocked_reason = None;
        });
    }

    /// Record that a newer generation replaced the old one.
    pub fn record_lifecycle_replaced(&self, machine_id: MachineId, new_generation: u64) {
        self.update_lifecycle(machine_id, |state| {
            state.generation = Some(new_generation);
            state.blocked_reason = None;
        });
    }

    /// Record a closing/closed lifecycle state for a machine.
    pub fn record_lifecycle_blocked(
        &self,
        machine_id: MachineId,
        generation: Option<u64>,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        self.update_lifecycle(machine_id, |state| {
            if let Some(generation) = generation {
                match state.generation {
                    Some(current) if current != generation => return,
                    Some(_) => {}
                    None => state.generation = Some(generation),
                }
            }
            state.blocked_reason = Some(reason);
        });
    }

    /// Returns the current lifecycle block reason for a machine, if any.
    #[must_use]
    pub fn lifecycle_block_reason(&self, machine_id: &MachineId) -> Option<String> {
        match self.lifecycle.lock() {
            Ok(guard) => guard
                .get(machine_id)
                .and_then(|state| state.blocked_reason.clone()),
            Err(e) => {
                tracing::error!("direct lifecycle registry poisoned: {e}");
                None
            }
        }
    }

    /// Check if an agent is currently connected.
    pub async fn is_connected(&self, agent_id: &AgentId) -> bool {
        let connected = self.connected_agents.read().await;
        connected.contains_key(agent_id)
    }

    /// Get the MachineId for a connected agent.
    pub async fn get_machine_id(&self, agent_id: &AgentId) -> Option<MachineId> {
        let connected = self.connected_agents.read().await;
        connected.get(agent_id).copied()
    }

    /// Get all currently connected agents.
    pub async fn connected_agents(&self) -> Vec<AgentId> {
        let connected = self.connected_agents.read().await;
        connected.keys().copied().collect()
    }

    /// Get a receiver for direct messages.
    pub fn subscribe(&self) -> DirectMessageReceiver {
        DirectMessageReceiver::new(
            Arc::clone(&self.subscribers),
            Arc::clone(&self.next_subscriber_id),
            self.subscriber_capacity,
        )
    }

    /// Current number of live direct-message subscribers.
    ///
    /// Used by diagnostics to distinguish "message dispatched to N SSE/WS
    /// consumers" from "no one is listening".
    pub fn subscriber_count(&self) -> usize {
        match self.subscribers.lock() {
            Ok(guard) => guard.len(),
            Err(e) => {
                tracing::error!("direct subscriber registry poisoned: {e}");
                0
            }
        }
    }

    /// Record that a logical outgoing DM was accepted for sending.
    pub(crate) fn record_outgoing_started(&self, agent_id: AgentId, avg_rtt_ms: Option<u32>) {
        self.diagnostics
            .outgoing_send_total
            .fetch_add(1, Ordering::Relaxed);
        let now_ms = now_unix_ms_lossy();
        self.with_peer_diagnostics(agent_id, |peer| {
            peer.last_send_at_ms = Some(now_ms);
            if let Some(rtt) = avg_rtt_ms.filter(|rtt| *rtt > 0) {
                peer.avg_rtt_ms = Some(rtt);
            }
        });
    }

    /// Record a successful logical outgoing DM.
    pub(crate) fn record_outgoing_succeeded(&self, agent_id: AgentId, path: DmPath) {
        self.diagnostics
            .outgoing_send_succeeded
            .fetch_add(1, Ordering::Relaxed);
        match path {
            DmPath::RawQuic | DmPath::RawQuicAcked => {
                self.diagnostics
                    .outgoing_path_raw_quic
                    .fetch_add(1, Ordering::Relaxed);
            }
            DmPath::GossipInbox => {
                self.diagnostics
                    .outgoing_path_gossip_inbox
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        let path_label = dm_path_label(path);
        self.with_peer_diagnostics(agent_id, |peer| {
            peer.send_succeeded = peer.send_succeeded.saturating_add(1);
            peer.preferred_path = Some(path_label);
        });
    }

    /// Record a failed logical outgoing DM.
    pub(crate) fn record_outgoing_failed(&self, agent_id: AgentId) {
        self.diagnostics
            .outgoing_send_failed
            .fetch_add(1, Ordering::Relaxed);
        self.with_peer_diagnostics(agent_id, |peer| {
            peer.send_failed = peer.send_failed.saturating_add(1);
        });
    }

    /// Record a DM inbox decode failure.
    pub(crate) fn record_incoming_decode_failed(&self) {
        self.diagnostics
            .incoming_decode_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a DM inbox signature failure.
    pub(crate) fn record_incoming_signature_failed(&self) {
        self.diagnostics
            .incoming_signature_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a DM trust-policy rejection.
    pub(crate) fn record_incoming_trust_rejected(&self, agent_id: AgentId) {
        self.diagnostics
            .incoming_trust_rejected
            .fetch_add(1, Ordering::Relaxed);
        self.with_peer_diagnostics(agent_id, |_| {});
    }

    /// Snapshot direct-message diagnostics for API surfaces.
    #[must_use]
    pub fn diagnostics_snapshot(&self) -> DmDiagnosticsSnapshot {
        let stats = DmDiagnosticsStats {
            outgoing_send_total: self.diagnostics.outgoing_send_total.load(Ordering::Relaxed),
            outgoing_send_succeeded: self
                .diagnostics
                .outgoing_send_succeeded
                .load(Ordering::Relaxed),
            outgoing_send_failed: self
                .diagnostics
                .outgoing_send_failed
                .load(Ordering::Relaxed),
            outgoing_path_raw_quic: self
                .diagnostics
                .outgoing_path_raw_quic
                .load(Ordering::Relaxed),
            outgoing_path_gossip_inbox: self
                .diagnostics
                .outgoing_path_gossip_inbox
                .load(Ordering::Relaxed),
            incoming_envelopes_total: self
                .diagnostics
                .incoming_envelopes_total
                .load(Ordering::Relaxed),
            incoming_decode_failed: self
                .diagnostics
                .incoming_decode_failed
                .load(Ordering::Relaxed),
            incoming_signature_failed: self
                .diagnostics
                .incoming_signature_failed
                .load(Ordering::Relaxed),
            incoming_trust_rejected: self
                .diagnostics
                .incoming_trust_rejected
                .load(Ordering::Relaxed),
            incoming_delivered_to_subscribe: self
                .diagnostics
                .incoming_delivered_to_subscribe
                .load(Ordering::Relaxed),
            subscriber_channel_lagged: self
                .diagnostics
                .subscriber_channel_lagged
                .load(Ordering::Relaxed),
            subscriber_channel_closed: self
                .diagnostics
                .subscriber_channel_closed
                .load(Ordering::Relaxed),
        };

        let now_ms = now_unix_ms_lossy();
        let per_peer = match self.peer_diagnostics.lock() {
            Ok(guard) => guard
                .iter()
                .map(|(agent_id, peer)| {
                    (
                        hex::encode(agent_id.as_bytes()),
                        DmPeerDiagnostics {
                            avg_rtt_ms: peer.avg_rtt_ms,
                            last_send_ms_ago: peer
                                .last_send_at_ms
                                .map(|ts| now_ms.saturating_sub(ts)),
                            last_recv_ms_ago: peer
                                .last_recv_at_ms
                                .map(|ts| now_ms.saturating_sub(ts)),
                            send_succeeded: peer.send_succeeded,
                            send_failed: peer.send_failed,
                            recv_count: peer.recv_count,
                            preferred_path: peer.preferred_path.unwrap_or("unknown").to_string(),
                        },
                    )
                })
                .collect(),
            Err(e) => {
                tracing::error!("direct peer diagnostics registry poisoned: {e}");
                BTreeMap::new()
            }
        };

        DmDiagnosticsSnapshot {
            stats,
            per_peer,
            subscriber_count: self.subscriber_count(),
            subscriber_capacity: self.subscriber_capacity,
        }
    }

    /// Process an incoming direct message from the network.
    ///
    /// Called by the network layer when a direct message is received.
    /// The `verified` and `trust_decision` fields are populated by the
    /// caller based on the identity discovery cache and contact store.
    ///
    /// Returns the number of subscribers that successfully received the
    /// message. Subscribers whose queues were full or closed are removed
    /// from the registry and counted in [`DmDiagnosticsStats`] but do not
    /// contribute to the returned count.
    pub async fn handle_incoming(
        &self,
        machine_id: MachineId,
        sender_agent_id: AgentId,
        payload: Vec<u8>,
        verified: bool,
        trust_decision: Option<TrustDecision>,
    ) -> u64 {
        self.diagnostics
            .incoming_envelopes_total
            .fetch_add(1, Ordering::Relaxed);
        let now_ms = now_unix_ms_lossy();
        self.with_peer_diagnostics(sender_agent_id, |peer| {
            peer.last_recv_at_ms = Some(now_ms);
            peer.recv_count = peer.recv_count.saturating_add(1);
        });

        let msg = DirectMessage::new_verified(
            sender_agent_id,
            machine_id,
            payload,
            verified,
            trust_decision,
        );

        let subscribers = self.subscriber_snapshot();
        let mut delivered = 0_u64;
        let mut remove_ids = Vec::new();
        for (id, tx) in subscribers {
            match tx.try_send(msg.clone()) {
                Ok(()) => {
                    delivered = delivered.saturating_add(1);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.diagnostics
                        .subscriber_channel_lagged
                        .fetch_add(1, Ordering::Relaxed);
                    remove_ids.push(id);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.diagnostics
                        .subscriber_channel_closed
                        .fetch_add(1, Ordering::Relaxed);
                    remove_ids.push(id);
                }
            }
        }
        if delivered > 0 {
            self.diagnostics
                .incoming_delivered_to_subscribe
                .fetch_add(1, Ordering::Relaxed);
        }
        if !remove_ids.is_empty() {
            self.remove_subscribers(&remove_ids);
        }

        // Also enqueue on the internal pull-API channel (consumed by
        // `recv_direct()`). This is a best-effort, non-blocking enqueue: the
        // mpsc receiver is typically idle in long-running daemons that only
        // use `subscribe_direct()` for SSE/WS fan-out. If we awaited a
        // bounded `send` here, a cold `internal_rx` would back-pressure this
        // task, which in turn stalls `start_direct_listener` →
        // `NetworkNode::spawn_receiver` → `Node::recv` and causes ant-quic
        // reader tasks to queue up on their forward channel. The per-subscriber
        // queues above are the authoritative delivery surface for daemons; the
        // internal channel is a convenience for library users that keep calling
        // `recv_direct()`.
        if self.internal_tx.try_send(msg).is_err() {
            tracing::trace!("direct internal_tx full or closed, skipping pull-API copy");
        }

        delivered
    }

    fn update_lifecycle(
        &self,
        machine_id: MachineId,
        update: impl FnOnce(&mut DirectLifecycleState),
    ) {
        match self.lifecycle.lock() {
            Ok(mut guard) => {
                let state = guard.entry(machine_id).or_default();
                update(state);
            }
            Err(e) => tracing::error!("direct lifecycle registry poisoned: {e}"),
        }
    }

    fn with_peer_diagnostics(
        &self,
        agent_id: AgentId,
        update: impl FnOnce(&mut DirectPeerDiagnosticsState),
    ) {
        match self.peer_diagnostics.lock() {
            Ok(mut guard) => {
                let peer = guard.entry(agent_id).or_default();
                update(peer);
            }
            Err(e) => tracing::error!("direct peer diagnostics registry poisoned: {e}"),
        }
    }

    fn subscriber_snapshot(&self) -> Vec<(u64, mpsc::Sender<DirectMessage>)> {
        match self.subscribers.lock() {
            Ok(guard) => guard.iter().map(|(id, tx)| (*id, tx.clone())).collect(),
            Err(e) => {
                tracing::error!("direct subscriber registry poisoned: {e}");
                Vec::new()
            }
        }
    }

    fn remove_subscribers(&self, ids: &[u64]) {
        match self.subscribers.lock() {
            Ok(mut guard) => {
                for id in ids {
                    guard.remove(id);
                }
            }
            Err(e) => tracing::error!("direct subscriber registry poisoned: {e}"),
        }
    }

    /// Receive the next direct message (blocking).
    pub async fn recv(&self) -> Option<DirectMessage> {
        let mut rx = self.internal_rx.lock().await;
        rx.recv().await
    }

    /// Encode a direct message for transmission.
    ///
    /// Format: `[0x10][sender_agent_id: 32 bytes][payload]`
    pub fn encode_message(sender_agent_id: &AgentId, payload: &[u8]) -> NetworkResult<Vec<u8>> {
        if payload.len() > MAX_DIRECT_PAYLOAD_SIZE {
            return Err(NetworkError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_DIRECT_PAYLOAD_SIZE,
            });
        }

        let mut buf = Vec::with_capacity(1 + 32 + payload.len());
        buf.push(DIRECT_MESSAGE_STREAM_TYPE);
        buf.extend_from_slice(&sender_agent_id.0);
        buf.extend_from_slice(payload);
        Ok(buf)
    }

    /// Decode a direct message from the wire.
    ///
    /// Returns (sender_agent_id, payload) on success.
    pub fn decode_message(data: &[u8]) -> NetworkResult<(AgentId, Vec<u8>)> {
        // Minimum size: 1 (type) + 32 (agent_id) = 33 bytes
        if data.len() < 33 {
            return Err(NetworkError::InvalidMessage(
                "Direct message too short".to_string(),
            ));
        }

        if data[0] != DIRECT_MESSAGE_STREAM_TYPE {
            return Err(NetworkError::InvalidMessage(format!(
                "Invalid stream type byte: expected {}, got {}",
                DIRECT_MESSAGE_STREAM_TYPE, data[0]
            )));
        }

        let mut agent_id_bytes = [0u8; 32];
        agent_id_bytes.copy_from_slice(&data[1..33]);
        let sender = AgentId(agent_id_bytes);

        let payload = data[33..].to_vec();

        Ok((sender, payload))
    }
}

impl Default for DirectMessaging {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_payload_digest_is_stable_and_short() {
        let payload = b"hello world".to_vec();
        let digest = dm_payload_digest_hex(&payload);
        assert_eq!(digest.len(), 16);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(dm_payload_digest_hex(&payload), digest);

        let other = dm_payload_digest_hex(b"different");
        assert_ne!(other, digest);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let agent_id = AgentId([42u8; 32]);
        let payload = b"hello world".to_vec();

        let encoded = DirectMessaging::encode_message(&agent_id, &payload).unwrap();

        assert_eq!(encoded[0], DIRECT_MESSAGE_STREAM_TYPE);
        assert_eq!(encoded.len(), 1 + 32 + payload.len());

        let (decoded_agent, decoded_payload) = DirectMessaging::decode_message(&encoded).unwrap();

        assert_eq!(decoded_agent, agent_id);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_decode_too_short() {
        let short_data = vec![DIRECT_MESSAGE_STREAM_TYPE; 10];
        let result = DirectMessaging::decode_message(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_wrong_type() {
        let mut data = vec![0x00; 50]; // Wrong type byte
        data[0] = 0x01;
        let result = DirectMessaging::decode_message(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_payload_too_large() {
        let agent_id = AgentId([1u8; 32]);
        let payload = vec![0u8; MAX_DIRECT_PAYLOAD_SIZE + 1];
        let result = DirectMessaging::encode_message(&agent_id, &payload);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_register_and_lookup() {
        let dm = DirectMessaging::new();
        let agent_id = AgentId([1u8; 32]);
        let machine_id = MachineId([2u8; 32]);

        dm.register_agent(agent_id, machine_id).await;

        let lookup = dm.lookup_agent(&machine_id).await;
        assert_eq!(lookup, Some(agent_id));
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        let dm = DirectMessaging::new();
        let agent_id = AgentId([1u8; 32]);
        let machine_id = MachineId([2u8; 32]);

        assert!(!dm.is_connected(&agent_id).await);

        dm.mark_connected(agent_id, machine_id).await;
        assert!(dm.is_connected(&agent_id).await);
        assert_eq!(dm.get_machine_id(&agent_id).await, Some(machine_id));

        let connected = dm.connected_agents().await;
        assert_eq!(connected, vec![agent_id]);

        dm.mark_disconnected(&agent_id).await;
        assert!(!dm.is_connected(&agent_id).await);
    }

    #[tokio::test]
    async fn test_message_subscription() {
        let dm = DirectMessaging::new();
        let mut rx = dm.subscribe();

        let sender = AgentId([1u8; 32]);
        let machine_id = MachineId([2u8; 32]);
        let payload = b"test message".to_vec();

        dm.handle_incoming(machine_id, sender, payload.clone(), true, None)
            .await;

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.sender, sender);
        assert_eq!(msg.machine_id, machine_id);
        assert_eq!(msg.payload, payload);
        assert!(msg.verified);
        assert!(msg.trust_decision.is_none());

        let snap = dm.diagnostics_snapshot();
        assert_eq!(snap.stats.incoming_envelopes_total, 1);
        assert_eq!(snap.stats.incoming_delivered_to_subscribe, 1);
        assert_eq!(snap.stats.subscriber_channel_lagged, 0);
    }

    #[tokio::test]
    async fn test_message_subscription_clone_gets_independent_queue() {
        let dm = DirectMessaging::new();
        let mut rx1 = dm.subscribe();
        let mut rx2 = rx1.clone();

        let sender = AgentId([3u8; 32]);
        let machine_id = MachineId([4u8; 32]);
        let payload = b"fanout".to_vec();

        dm.handle_incoming(machine_id, sender, payload.clone(), true, None)
            .await;

        assert_eq!(rx1.recv().await.unwrap().payload, payload);
        assert_eq!(rx2.recv().await.unwrap().payload, payload);
        assert_eq!(dm.subscriber_count(), 2);
    }

    #[tokio::test]
    async fn test_lagging_subscriber_is_dropped_not_global_broadcast_lag() {
        let dm = DirectMessaging::new();
        let _lagging_rx = dm.subscribe();
        let sender = AgentId([5u8; 32]);
        let machine_id = MachineId([6u8; 32]);

        for idx in 0..=DIRECT_SUBSCRIBER_BUFFER {
            dm.handle_incoming(machine_id, sender, idx.to_be_bytes().to_vec(), true, None)
                .await;
        }

        let snap = dm.diagnostics_snapshot();
        assert_eq!(snap.stats.subscriber_channel_lagged, 1);
        assert_eq!(snap.subscriber_count, 0);
    }

    #[test]
    fn test_lifecycle_blocks_only_current_generation() {
        let dm = DirectMessaging::new();
        let machine_id = MachineId([7u8; 32]);

        dm.record_lifecycle_established(machine_id, Some(1));
        assert!(dm.lifecycle_block_reason(&machine_id).is_none());

        dm.record_lifecycle_replaced(machine_id, 2);
        dm.record_lifecycle_blocked(machine_id, Some(1), "closed: superseded");
        assert!(dm.lifecycle_block_reason(&machine_id).is_none());

        dm.record_lifecycle_blocked(machine_id, Some(2), "closed: timed out");
        assert_eq!(
            dm.lifecycle_block_reason(&machine_id).as_deref(),
            Some("closed: timed out")
        );

        dm.record_lifecycle_established(machine_id, Some(3));
        assert!(dm.lifecycle_block_reason(&machine_id).is_none());
    }

    #[test]
    fn test_direct_message_payload_str() {
        let msg = DirectMessage::new(AgentId([1u8; 32]), MachineId([2u8; 32]), b"hello".to_vec());
        assert_eq!(msg.payload_str(), Some("hello"));

        let binary_msg =
            DirectMessage::new(AgentId([1u8; 32]), MachineId([2u8; 32]), vec![0xff, 0xfe]);
        assert!(binary_msg.payload_str().is_none());
    }
}
