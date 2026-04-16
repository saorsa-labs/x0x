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

use crate::error::{NetworkError, NetworkResult};
use crate::identity::{AgentId, MachineId};
use crate::trust::TrustDecision;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, RwLock};

/// Stream type byte for direct messages (distinct from gossip: 0, 1, 2).
pub const DIRECT_MESSAGE_STREAM_TYPE: u8 = 0x10;

/// Maximum payload size for direct messages (16 MB).
pub const MAX_DIRECT_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

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

/// Receiver for direct messages.
///
/// This is a wrapper around a broadcast receiver that provides a cleaner API.
/// Multiple receivers can be created to process messages in parallel.
#[derive(Debug)]
pub struct DirectMessageReceiver {
    rx: broadcast::Receiver<DirectMessage>,
}

impl DirectMessageReceiver {
    /// Create a new receiver from a broadcast receiver.
    pub(crate) fn new(rx: broadcast::Receiver<DirectMessage>) -> Self {
        Self { rx }
    }

    /// Receive the next direct message.
    ///
    /// Returns `None` if the channel is closed.
    pub async fn recv(&mut self) -> Option<DirectMessage> {
        loop {
            match self.rx.recv().await {
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Direct message receiver lagged, skipped {} messages", n);
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
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
        Self {
            rx: self.rx.resubscribe(),
        }
    }
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

    /// Channel for broadcasting received direct messages.
    message_tx: broadcast::Sender<DirectMessage>,

    /// Internal sender for the receiver task.
    internal_tx: mpsc::Sender<DirectMessage>,

    /// Internal receiver (owned by the processing task).
    internal_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<DirectMessage>>>,
}

impl DirectMessaging {
    /// Create a new DirectMessaging instance.
    #[must_use]
    pub fn new() -> Self {
        let (message_tx, _) = broadcast::channel(256);
        let (internal_tx, internal_rx) = mpsc::channel(256);

        Self {
            machine_to_agent: Arc::new(RwLock::new(HashMap::new())),
            connected_agents: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
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
        tracing::info!("Agent connected: {:?}", agent_id);
    }

    /// Mark an agent as disconnected.
    pub async fn mark_disconnected(&self, agent_id: &AgentId) {
        let mut connected = self.connected_agents.write().await;
        connected.remove(agent_id);
        tracing::info!("Agent disconnected: {:?}", agent_id);
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
        DirectMessageReceiver::new(self.message_tx.subscribe())
    }

    /// Current number of live broadcast subscribers.
    ///
    /// Used by diagnostics to distinguish "message dispatched to N SSE/WS
    /// consumers" from "message silently dropped because no one is listening".
    pub fn subscriber_count(&self) -> usize {
        self.message_tx.receiver_count()
    }

    /// Process an incoming direct message from the network.
    ///
    /// Called by the network layer when a direct message is received.
    /// The `verified` and `trust_decision` fields are populated by the
    /// caller based on the identity discovery cache and contact store.
    pub async fn handle_incoming(
        &self,
        machine_id: MachineId,
        sender_agent_id: AgentId,
        payload: Vec<u8>,
        verified: bool,
        trust_decision: Option<TrustDecision>,
    ) {
        let msg = DirectMessage::new_verified(
            sender_agent_id,
            machine_id,
            payload,
            verified,
            trust_decision,
        );

        // Broadcast to all subscribers
        if self.message_tx.receiver_count() > 0 {
            let _ = self.message_tx.send(msg.clone());
        }

        // Also enqueue on the internal pull-API channel (consumed by
        // `recv_direct()`). This is a best-effort, non-blocking enqueue: the
        // mpsc receiver is typically idle in long-running daemons that only
        // use `subscribe_direct()` on the broadcast channel. If we awaited a
        // bounded `send` here, a cold `internal_rx` would back-pressure this
        // task, which in turn stalls `start_direct_listener` →
        // `NetworkNode::spawn_receiver` → `Node::recv` and causes ant-quic
        // reader tasks to queue up on their forward channel. The broadcast
        // channel above is the authoritative delivery surface for daemons;
        // the internal channel is a convenience for library users that keep
        // calling `recv_direct()`.
        if self.internal_tx.try_send(msg).is_err() {
            tracing::trace!("direct internal_tx full or closed, skipping pull-API copy");
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
