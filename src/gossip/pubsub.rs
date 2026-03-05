//! x0x Pub/Sub with PlumTree dissemination and ML-DSA-65 signed messages.
//!
//! This module implements topic-based pub/sub for x0x with:
//! - PlumTree dissemination via `saorsa-gossip-pubsub`
//! - x0x payload-level message authentication (V2 signed format)
//!
//! Two wire formats coexist during the transition period:
//! - **V1** (legacy): `[topic_len: u16_be | topic | payload]` — unsigned
//! - **V2** (signed): `[0x02 | agent_id | pubkey | signature | topic | payload]`

use crate::contacts::{ContactStore, TrustLevel};
use crate::error::{NetworkError, NetworkResult};
use crate::identity::AgentId;
use crate::network::NetworkNode;
use bytes::Bytes;
use saorsa_gossip_pubsub::{PlumtreePubSub, PubSub};
use saorsa_gossip_types::{PeerId, TopicId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Domain separation prefix for signed message payloads.
const MSG_V2_PREFIX: &[u8] = b"x0x-msg-v2";

/// Version byte for signed messages.
const VERSION_V2: u8 = 0x02;

/// Signing context for message authentication.
///
/// Holds the agent identity and key material needed to sign outgoing
/// pub/sub messages. Created from an [`crate::identity::AgentKeypair`]
/// and shared via `Arc` across the pub/sub manager.
pub struct SigningContext {
    /// The agent's 32-byte identifier.
    pub agent_id: AgentId,
    /// The agent's ML-DSA-65 public key bytes (for embedding in messages).
    pub public_key_bytes: Vec<u8>,
    /// The agent's ML-DSA-65 secret key bytes (for signing).
    secret_key_bytes: Vec<u8>,
}

impl std::fmt::Debug for SigningContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningContext")
            .field("agent_id", &self.agent_id)
            .field("public_key_bytes_len", &self.public_key_bytes.len())
            .field("secret_key", &"<REDACTED>")
            .finish()
    }
}

impl SigningContext {
    /// Create a signing context from an agent keypair.
    pub fn from_keypair(kp: &crate::identity::AgentKeypair) -> Self {
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        Self {
            agent_id: kp.agent_id(),
            public_key_bytes: pub_bytes,
            secret_key_bytes: sec_bytes,
        }
    }

    /// Sign a message using the agent's ML-DSA-65 secret key.
    pub fn sign(&self, message: &[u8]) -> NetworkResult<Vec<u8>> {
        let secret_key =
            ant_quic::MlDsaSecretKey::from_bytes(&self.secret_key_bytes).map_err(|e| {
                NetworkError::SerializationError(format!("invalid secret key: {:?}", e))
            })?;
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret_key, message)
                .map_err(|e| {
                    NetworkError::SerializationError(format!("signing failed: {:?}", e))
                })?;
        Ok(signature.as_bytes().to_vec())
    }
}

/// Message published to the pub/sub system.
///
/// Messages may be signed (v2) or unsigned (v1 legacy). The `sender` and
/// `verified` fields indicate the authentication state.
#[derive(Debug, Clone)]
pub struct PubSubMessage {
    /// The topic this message was published on.
    pub topic: String,
    /// The message payload.
    pub payload: Bytes,
    /// Sender's AgentId (`None` for unsigned legacy v1 messages).
    pub sender: Option<AgentId>,
    /// Sender's ML-DSA-65 public key bytes (included in v2 messages).
    pub sender_public_key: Option<Vec<u8>>,
    /// Whether the ML-DSA-65 signature was verified.
    pub verified: bool,
    /// Trust level from the local contact store (populated during incoming handling).
    pub trust_level: Option<TrustLevel>,
}

/// Subscription to a topic.
///
/// Receives messages published to its topic through a channel receiver.
/// The subscription is canceled when dropped, automatically decrementing
/// topic subscriber counts in the PubSubManager.
pub struct Subscription {
    /// The topic this subscription is for.
    topic: String,
    /// Channel receiver for messages on this topic.
    receiver: mpsc::Receiver<PubSubMessage>,
    /// Reference to per-topic subscriber counts for cleanup on drop.
    topic_ref_counts: Arc<RwLock<HashMap<String, usize>>>,
}

impl Subscription {
    /// Get the topic for this subscription.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Receive the next message on this subscription.
    ///
    /// # Returns
    ///
    /// The next message, or `None` if the subscription has been canceled.
    pub async fn recv(&mut self) -> Option<PubSubMessage> {
        self.receiver.recv().await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let topic = self.topic.clone();
        let topic_ref_counts = self.topic_ref_counts.clone();

        // Spawn a task to decrement the refcount for this topic.
        // This avoids blocking on synchronous locks in drop.
        tokio::spawn(async move {
            let mut counts = topic_ref_counts.write().await;
            if let Some(count) = counts.get_mut(&topic) {
                if *count > 1 {
                    *count -= 1;
                } else {
                    counts.remove(&topic);
                }
            }
        });
    }
}

/// Pub/Sub manager using PlumTree dissemination with x0x payload signing.
///
/// # Architecture
///
/// ```text
/// Publisher → PubSubManager.publish()
///     ├─> Sign with ML-DSA-65 (if signing context present)
///     └─> Publish encoded payload via PlumTree (saorsa-gossip-pubsub)
///
/// Peer message → PubSubManager.handle_incoming()
///     └─> Dispatch to PlumTree handler (EAGER/IHAVE/IWANT/AntiEntropy)
///
/// Local subscription delivery path:
///     PlumTree topic receiver → decode x0x payload (v1/v2) → trust filter → subscriber channel
/// ```
pub struct PubSubManager {
    /// Network node used by PlumTree transport and topic peer initialization.
    network: Arc<NetworkNode>,
    /// PlumTree pub/sub engine from saorsa-gossip-pubsub.
    plumtree: Arc<PlumtreePubSub<NetworkNode>>,
    /// Local topic subscription ref-counts (for stats and cleanup).
    topic_ref_counts: Arc<RwLock<HashMap<String, usize>>>,
    /// Signing context for authenticating published messages.
    signing: Option<Arc<SigningContext>>,
    /// Contact store for trust-based message filtering.
    /// Set via `set_contacts()` after construction.
    contacts: std::sync::OnceLock<Arc<tokio::sync::RwLock<ContactStore>>>,
}

impl std::fmt::Debug for PubSubManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubSubManager")
            .field("network", &self.network)
            .field("topic_count", &"<dynamic>")
            .field("signing_enabled", &self.signing.is_some())
            .finish_non_exhaustive()
    }
}

impl PubSubManager {
    /// Create a new pub/sub manager.
    ///
    /// # Arguments
    ///
    /// * `network` - The network node (implements GossipTransport)
    /// * `signing` - Optional signing context for message authentication.
    ///   When `None`, messages are published unsigned (v1 format).
    ///
    /// # Returns
    ///
    /// A new `PubSubManager` instance
    pub fn new(
        network: Arc<NetworkNode>,
        signing: Option<Arc<SigningContext>>,
    ) -> NetworkResult<Self> {
        let peer_id = saorsa_gossip_transport::GossipTransport::local_peer_id(network.as_ref());
        let plumtree_signing_key =
            saorsa_gossip_identity::MlDsaKeyPair::generate().map_err(|e| {
                NetworkError::NodeCreation(format!("failed to create PlumTree signing key: {e}"))
            })?;

        let plumtree = Arc::new(PlumtreePubSub::new(
            peer_id,
            Arc::clone(&network),
            plumtree_signing_key,
        ));

        Ok(Self {
            network,
            plumtree,
            topic_ref_counts: Arc::new(RwLock::new(HashMap::new())),
            signing,
            contacts: std::sync::OnceLock::new(),
        })
    }

    /// Attach a contact store for trust-based message filtering.
    ///
    /// When set, incoming messages from `Blocked` senders are silently
    /// dropped (and NOT re-broadcast). Messages from other senders are
    /// annotated with their trust level.
    ///
    /// Call this once after construction, before handling messages.
    /// Calling more than once is a no-op (first caller wins).
    pub fn set_contacts(&self, store: Arc<tokio::sync::RwLock<ContactStore>>) {
        let _ = self.contacts.set(store);
    }

    /// Subscribe to a topic.
    ///
    /// Creates a new subscription to receive messages published to the
    /// given topic. The subscription is canceled when the returned
    /// `Subscription` is dropped.
    pub async fn subscribe(&self, topic: String) -> Subscription {
        let topic_id = TopicId::from_entity(topic.as_bytes());
        self.initialize_topic_peers(topic_id).await;

        let mut plumtree_rx = self.plumtree.subscribe(topic_id);
        // Plumtree registers subscribers on a spawned task; yield once so
        // immediate local publishes in the same task see this subscriber.
        tokio::task::yield_now().await;
        let (tx, rx) = mpsc::channel(100);
        let contacts = self.contacts.get().cloned();

        {
            let mut counts = self.topic_ref_counts.write().await;
            *counts.entry(topic.clone()).or_insert(0) += 1;
        }

        tokio::spawn(async move {
            while let Some((_peer, encoded_payload)) = plumtree_rx.recv().await {
                let Some(message) = decode_for_delivery(encoded_payload, contacts.as_ref()).await
                else {
                    continue;
                };
                if tx.send(message).await.is_err() {
                    break;
                }
            }
        });

        Subscription {
            topic,
            receiver: rx,
            topic_ref_counts: self.topic_ref_counts.clone(),
        }
    }

    /// Publish a message to a topic.
    ///
    /// When a signing context is present, the message is signed with
    /// ML-DSA-65 and encoded in v2 format. Otherwise, v1 (unsigned).
    ///
    /// # Errors
    ///
    /// Returns an error if encoding or signing fails.
    pub async fn publish(&self, topic: String, payload: Bytes) -> NetworkResult<()> {
        let encoded = if let Some(ref ctx) = self.signing {
            let signing_payload =
                build_signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
            let signature = ctx.sign(&signing_payload)?;
            encode_v2(
                &ctx.agent_id,
                &ctx.public_key_bytes,
                &signature,
                &topic,
                &payload,
            )?
        } else {
            encode_v1(&topic, &payload)?
        };

        let topic_id = TopicId::from_entity(topic.as_bytes());
        self.initialize_topic_peers(topic_id).await;

        self.plumtree
            .publish(topic_id, encoded)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("PlumTree publish failed: {e}")))
    }

    /// Handle an incoming message from a peer.
    ///
    /// This delegates to the PlumTree implementation for protocol-level
    /// processing (EAGER/IHAVE/IWANT/AntiEntropy).
    pub async fn handle_incoming(&self, peer: PeerId, data: Bytes) {
        if let Err(e) = self.plumtree.handle_message(peer, data).await {
            tracing::warn!("Failed to handle PlumTree pubsub message from {peer}: {e}");
        }
    }

    /// Get the number of active subscriptions (topics with at least one subscriber).
    pub async fn subscription_count(&self) -> usize {
        self.topic_ref_counts.read().await.len()
    }

    /// Unsubscribe from a topic, removing all subscriptions.
    pub async fn unsubscribe(&self, topic: &str) {
        self.topic_ref_counts.write().await.remove(topic);
        let topic_id = TopicId::from_entity(topic.as_bytes());
        if let Err(e) = self.plumtree.unsubscribe(topic_id).await {
            tracing::debug!("PlumTree unsubscribe failed for topic '{topic}': {e}");
        }
    }

    /// Initialize PlumTree peers for a topic from currently connected peers.
    async fn initialize_topic_peers(&self, topic: TopicId) {
        let peers: Vec<PeerId> = self
            .network
            .connected_peers()
            .await
            .into_iter()
            .map(|peer| PeerId::new(peer.0))
            .collect();
        self.plumtree.initialize_topic_peers(topic, peers).await;
    }
}

/// Decode and filter a delivered payload before exposing it to x0x subscribers.
async fn decode_for_delivery(
    encoded_payload: Bytes,
    contacts: Option<&Arc<tokio::sync::RwLock<ContactStore>>>,
) -> Option<PubSubMessage> {
    let mut message = match decode_auto(encoded_payload) {
        Ok(msg) => msg,
        Err(e) => {
            tracing::warn!("Failed to decode x0x payload from PlumTree message: {}", e);
            return None;
        }
    };

    // Drop signed messages with failed verification.
    if message.sender.is_some() && !message.verified {
        tracing::warn!(
            "Dropping pubsub payload with invalid signature from sender {:?}",
            message.sender
        );
        return None;
    }

    if let (Some(store), Some(sender)) = (contacts, message.sender) {
        let trust = store.read().await.trust_level(&sender);
        if trust == TrustLevel::Blocked {
            tracing::debug!("Dropping delivered payload from blocked sender {}", sender);
            return None;
        }
        message.trust_level = Some(trust);
    }

    Some(message)
}

// ---------------------------------------------------------------------------
// Wire format: V1 (legacy, unsigned)
// ---------------------------------------------------------------------------

/// Encode a v1 (unsigned) pub/sub message.
///
/// Format: `[topic_len: u16_be | topic_bytes | payload]`
fn encode_v1(topic: &str, payload: &Bytes) -> NetworkResult<Bytes> {
    let topic_bytes = topic.as_bytes();
    let topic_len = u16::try_from(topic_bytes.len())
        .map_err(|_| NetworkError::SerializationError("Topic too long".to_string()))?;

    let mut buf = Vec::with_capacity(2 + topic_bytes.len() + payload.len());
    buf.extend_from_slice(&topic_len.to_be_bytes());
    buf.extend_from_slice(topic_bytes);
    buf.extend_from_slice(payload);

    Ok(Bytes::from(buf))
}

/// Decode a v1 (unsigned) pub/sub message.
fn decode_v1(data: &[u8]) -> NetworkResult<PubSubMessage> {
    if data.len() < 2 {
        return Err(NetworkError::SerializationError(
            "Message too short".to_string(),
        ));
    }

    let topic_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + topic_len {
        return Err(NetworkError::SerializationError(
            "Invalid topic length".to_string(),
        ));
    }

    let topic = String::from_utf8(data[2..2 + topic_len].to_vec())
        .map_err(|e| NetworkError::SerializationError(format!("Invalid UTF-8: {}", e)))?;

    let payload = Bytes::copy_from_slice(&data[2 + topic_len..]);

    Ok(PubSubMessage {
        topic,
        payload,
        sender: None,
        sender_public_key: None,
        verified: false,
        trust_level: None,
    })
}

// ---------------------------------------------------------------------------
// Wire format: V2 (signed)
// ---------------------------------------------------------------------------

/// Encode a v2 (signed) pub/sub message.
///
/// Format:
/// ```text
/// [version: 0x02]
/// [sender_agent_id: 32 bytes]
/// [pubkey_len: u16_be] [sender_public_key: pubkey_len bytes]
/// [sig_len: u16_be]    [signature: sig_len bytes]
/// [topic_len: u16_be]  [topic_bytes: topic_len bytes]
/// [payload: remaining bytes]
/// ```
fn encode_v2(
    agent_id: &AgentId,
    public_key: &[u8],
    signature: &[u8],
    topic: &str,
    payload: &Bytes,
) -> NetworkResult<Bytes> {
    let topic_bytes = topic.as_bytes();
    let topic_len = u16::try_from(topic_bytes.len())
        .map_err(|_| NetworkError::SerializationError("Topic too long".to_string()))?;
    let pk_len = u16::try_from(public_key.len())
        .map_err(|_| NetworkError::SerializationError("Public key too long".to_string()))?;
    let sig_len = u16::try_from(signature.len())
        .map_err(|_| NetworkError::SerializationError("Signature too long".to_string()))?;

    let total =
        1 + 32 + 2 + public_key.len() + 2 + signature.len() + 2 + topic_bytes.len() + payload.len();
    let mut buf = Vec::with_capacity(total);

    buf.push(VERSION_V2);
    buf.extend_from_slice(agent_id.as_bytes());
    buf.extend_from_slice(&pk_len.to_be_bytes());
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&sig_len.to_be_bytes());
    buf.extend_from_slice(signature);
    buf.extend_from_slice(&topic_len.to_be_bytes());
    buf.extend_from_slice(topic_bytes);
    buf.extend_from_slice(payload);

    Ok(Bytes::from(buf))
}

/// Decode a v2 (signed) message, verifying the ML-DSA-65 signature.
fn decode_v2(data: &[u8]) -> NetworkResult<PubSubMessage> {
    // Minimum: 1 (version) + 32 (agent_id) + 2 (pk_len) + 2 (sig_len) + 2 (topic_len)
    if data.len() < 39 {
        return Err(NetworkError::SerializationError(
            "V2 message too short".to_string(),
        ));
    }

    let mut pos = 1; // skip version byte

    // Agent ID (32 bytes)
    let mut agent_id_bytes = [0u8; 32];
    agent_id_bytes.copy_from_slice(&data[pos..pos + 32]);
    let agent_id = AgentId(agent_id_bytes);
    pos += 32;

    // Public key
    if data.len() < pos + 2 {
        return Err(NetworkError::SerializationError(
            "Truncated pubkey length".to_string(),
        ));
    }
    let pk_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + pk_len {
        return Err(NetworkError::SerializationError(
            "Truncated public key".to_string(),
        ));
    }
    let public_key_bytes = data[pos..pos + pk_len].to_vec();
    pos += pk_len;

    // Signature
    if data.len() < pos + 2 {
        return Err(NetworkError::SerializationError(
            "Truncated signature length".to_string(),
        ));
    }
    let sig_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + sig_len {
        return Err(NetworkError::SerializationError(
            "Truncated signature".to_string(),
        ));
    }
    let signature_bytes = &data[pos..pos + sig_len];
    pos += sig_len;

    // Topic
    if data.len() < pos + 2 {
        return Err(NetworkError::SerializationError(
            "Truncated topic length".to_string(),
        ));
    }
    let topic_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + topic_len {
        return Err(NetworkError::SerializationError(
            "Truncated topic".to_string(),
        ));
    }
    let topic = String::from_utf8(data[pos..pos + topic_len].to_vec())
        .map_err(|e| NetworkError::SerializationError(format!("Invalid UTF-8: {}", e)))?;
    pos += topic_len;

    // Payload (remaining bytes)
    let payload = Bytes::copy_from_slice(&data[pos..]);

    // Verify: reconstruct the public key and check the signature
    let verified = verify_signature(
        &public_key_bytes,
        &agent_id_bytes,
        topic.as_bytes(),
        &payload,
        signature_bytes,
    );

    if !verified {
        tracing::warn!(
            "ML-DSA-65 signature verification failed for sender {}",
            agent_id
        );
    }

    Ok(PubSubMessage {
        topic,
        payload,
        sender: Some(agent_id),
        sender_public_key: Some(public_key_bytes),
        verified,
        trust_level: None,
    })
}

/// Auto-detect and decode a pub/sub message (v1 or v2).
///
/// The first byte distinguishes the format:
/// - `0x02` → v2 (signed)
/// - Anything else → v1 (legacy unsigned, where byte is high byte of topic_len)
fn decode_auto(data: Bytes) -> NetworkResult<PubSubMessage> {
    if data.is_empty() {
        return Err(NetworkError::SerializationError(
            "Empty message".to_string(),
        ));
    }

    if data[0] == VERSION_V2 {
        decode_v2(&data)
    } else {
        decode_v1(&data)
    }
}

/// Build the signing payload with domain separation.
///
/// `b"x0x-msg-v2" || sender_agent_id(32) || topic_bytes || payload`
fn build_signing_payload(agent_id: &[u8; 32], topic: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MSG_V2_PREFIX.len() + 32 + topic.len() + payload.len());
    buf.extend_from_slice(MSG_V2_PREFIX);
    buf.extend_from_slice(agent_id);
    buf.extend_from_slice(topic);
    buf.extend_from_slice(payload);
    buf
}

/// Verify an ML-DSA-65 signature against the reconstructed signing payload.
fn verify_signature(
    public_key_bytes: &[u8],
    agent_id: &[u8; 32],
    topic: &[u8],
    payload: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let public_key = match ant_quic::MlDsaPublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Verify that the agent_id matches the public key
    let derived_id = crate::identity::AgentId::from_public_key(&public_key);
    if derived_id.0 != *agent_id {
        tracing::warn!("Agent ID mismatch: embedded ID does not match public key");
        return false;
    }

    let signature =
        match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(signature_bytes) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

    let signing_payload = build_signing_payload(agent_id, topic, payload);

    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
        &public_key,
        &signing_payload,
        &signature,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;
    use crate::network::NetworkConfig;

    /// Helper to create a test network node.
    async fn test_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(NetworkConfig::default())
                .await
                .expect("Failed to create test node"),
        )
    }

    // -----------------------------------------------------------------------
    // V1 wire format tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_v1_encode_decode_roundtrip() {
        let topic = "test-topic";
        let payload = Bytes::from(&b"hello world"[..]);

        let encoded = encode_v1(topic, &payload).expect("Encoding failed");
        let msg = decode_v1(&encoded).expect("Decoding failed");

        assert_eq!(msg.topic, topic);
        assert_eq!(msg.payload, payload);
        assert!(msg.sender.is_none());
        assert!(!msg.verified);
    }

    #[test]
    fn test_v1_empty_topic() {
        let encoded = encode_v1("", &Bytes::from("data")).expect("Encoding failed");
        let msg = decode_v1(&encoded).expect("Decoding failed");
        assert_eq!(msg.topic, "");
        assert_eq!(msg.payload, Bytes::from("data"));
    }

    #[test]
    fn test_v1_empty_payload() {
        let encoded = encode_v1("topic", &Bytes::new()).expect("Encoding failed");
        let msg = decode_v1(&encoded).expect("Decoding failed");
        assert_eq!(msg.topic, "topic");
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_v1_unicode_topic() {
        let topic = "тема/главная/система";
        let payload = Bytes::from(&b"data"[..]);
        let encoded = encode_v1(topic, &payload).expect("Encoding failed");
        let msg = decode_v1(&encoded).expect("Decoding failed");
        assert_eq!(msg.topic, topic);
    }

    #[test]
    fn test_v1_too_long_topic() {
        let topic = "a".repeat(70000);
        assert!(encode_v1(&topic, &Bytes::from("data")).is_err());
    }

    #[test]
    fn test_v1_too_short() {
        assert!(decode_v1(&[0x12]).is_err());
    }

    #[test]
    fn test_v1_invalid_utf8() {
        let data = vec![0, 3, 0xFF, 0xFF, 0xFF];
        assert!(decode_v1(&data).is_err());
    }

    // -----------------------------------------------------------------------
    // V2 wire format tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_v2_encode_decode_roundtrip() {
        let kp = AgentKeypair::generate().expect("keygen");
        let ctx = SigningContext::from_keypair(&kp);

        let topic = "chat";
        let payload = Bytes::from("hello signed world");
        let signing_payload =
            build_signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let signature = ctx.sign(&signing_payload).expect("sign");

        let encoded = encode_v2(
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            topic,
            &payload,
        )
        .expect("encode");

        let msg = decode_v2(&encoded).expect("decode");
        assert_eq!(msg.topic, topic);
        assert_eq!(msg.payload, payload);
        assert_eq!(msg.sender, Some(ctx.agent_id));
        assert!(msg.verified);
    }

    #[test]
    fn test_v2_tampered_payload_fails_verification() {
        let kp = AgentKeypair::generate().expect("keygen");
        let ctx = SigningContext::from_keypair(&kp);

        let topic = "chat";
        let payload = Bytes::from("original");
        let signing_payload =
            build_signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let signature = ctx.sign(&signing_payload).expect("sign");

        // Encode with the WRONG payload (tampered)
        let tampered_payload = Bytes::from("TAMPERED");
        let encoded = encode_v2(
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            topic,
            &tampered_payload,
        )
        .expect("encode");

        let msg = decode_v2(&encoded).expect("decode");
        assert!(!msg.verified); // Signature should NOT verify
    }

    #[test]
    fn test_v2_wrong_sender_fails() {
        let kp1 = AgentKeypair::generate().expect("keygen1");
        let kp2 = AgentKeypair::generate().expect("keygen2");
        let ctx1 = SigningContext::from_keypair(&kp1);

        let topic = "chat";
        let payload = Bytes::from("hello");
        let signing_payload =
            build_signing_payload(ctx1.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let signature = ctx1.sign(&signing_payload).expect("sign");

        // Encode with kp2's identity but kp1's signature
        let ctx2 = SigningContext::from_keypair(&kp2);
        let encoded = encode_v2(
            &ctx2.agent_id,
            &ctx2.public_key_bytes,
            &signature,
            topic,
            &payload,
        )
        .expect("encode");

        let msg = decode_v2(&encoded).expect("decode");
        assert!(!msg.verified); // Wrong key for signature
    }

    #[test]
    fn test_v2_empty_payload() {
        let kp = AgentKeypair::generate().expect("keygen");
        let ctx = SigningContext::from_keypair(&kp);

        let topic = "ping";
        let payload = Bytes::new();
        let signing_payload =
            build_signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let signature = ctx.sign(&signing_payload).expect("sign");

        let encoded = encode_v2(
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            topic,
            &payload,
        )
        .expect("encode");

        let msg = decode_v2(&encoded).expect("decode");
        assert!(msg.verified);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_v2_truncated_data() {
        // Just version byte + a few bytes — should fail
        assert!(decode_v2(&[VERSION_V2, 0, 0, 0]).is_err());
    }

    // -----------------------------------------------------------------------
    // Auto-detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auto_detect_v1() {
        let encoded = encode_v1("topic", &Bytes::from("data")).expect("encode");
        let msg = decode_auto(encoded).expect("decode");
        assert_eq!(msg.topic, "topic");
        assert!(msg.sender.is_none());
        assert!(!msg.verified);
    }

    #[test]
    fn test_auto_detect_v2() {
        let kp = AgentKeypair::generate().expect("keygen");
        let ctx = SigningContext::from_keypair(&kp);
        let topic = "test";
        let payload = Bytes::from("signed");
        let signing_payload =
            build_signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let signature = ctx.sign(&signing_payload).expect("sign");
        let encoded = encode_v2(
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            topic,
            &payload,
        )
        .expect("encode");

        let msg = decode_auto(encoded).expect("decode");
        assert_eq!(msg.topic, topic);
        assert!(msg.sender.is_some());
        assert!(msg.verified);
    }

    #[test]
    fn test_auto_detect_empty() {
        assert!(decode_auto(Bytes::new()).is_err());
    }

    // -----------------------------------------------------------------------
    // Signing payload tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_signing_payload_deterministic() {
        let agent_id = [42u8; 32];
        let p1 = build_signing_payload(&agent_id, b"topic", b"payload");
        let p2 = build_signing_payload(&agent_id, b"topic", b"payload");
        assert_eq!(p1, p2);

        // Different topic → different payload
        let p3 = build_signing_payload(&agent_id, b"other", b"payload");
        assert_ne!(p1, p3);
    }

    // -----------------------------------------------------------------------
    // PubSubManager tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_pubsub_creation() {
        let node = test_node().await;
        let _manager = PubSubManager::new(node, None).expect("manager");
    }

    #[tokio::test]
    async fn test_subscribe_to_topic() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let sub = manager.subscribe("test-topic".to_string()).await;
        assert_eq!(sub.topic(), "test-topic");
    }

    #[tokio::test]
    async fn test_publish_local_delivery_unsigned() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let mut sub = manager.subscribe("chat".to_string()).await;

        manager
            .publish("chat".to_string(), Bytes::from("hello"))
            .await
            .expect("Publish failed");

        let msg = sub.recv().await.expect("Failed to receive message");
        assert_eq!(msg.topic, "chat");
        assert_eq!(msg.payload, Bytes::from("hello"));
        assert!(msg.sender.is_none());
        assert!(!msg.verified);
    }

    #[tokio::test]
    async fn test_publish_local_delivery_signed() {
        let node = test_node().await;
        let kp = AgentKeypair::generate().expect("keygen");
        let ctx = Arc::new(SigningContext::from_keypair(&kp));
        let manager = PubSubManager::new(node, Some(ctx.clone())).expect("manager");

        let mut sub = manager.subscribe("chat".to_string()).await;

        manager
            .publish("chat".to_string(), Bytes::from("signed hello"))
            .await
            .expect("Publish failed");

        let msg = sub.recv().await.expect("Failed to receive");
        assert_eq!(msg.topic, "chat");
        assert_eq!(msg.payload, Bytes::from("signed hello"));
        assert_eq!(msg.sender, Some(kp.agent_id()));
        assert!(msg.verified);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let mut sub1 = manager.subscribe("news".to_string()).await;
        let mut sub2 = manager.subscribe("news".to_string()).await;

        manager
            .publish("news".to_string(), Bytes::from("breaking"))
            .await
            .expect("Publish failed");

        let msg1 = sub1.recv().await.expect("sub1 failed");
        let msg2 = sub2.recv().await.expect("sub2 failed");
        assert_eq!(msg1.payload, Bytes::from("breaking"));
        assert_eq!(msg2.payload, Bytes::from("breaking"));
    }

    #[tokio::test]
    async fn test_publish_no_subscribers() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        assert!(manager
            .publish("empty".to_string(), Bytes::from("nothing"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_unsubscribe() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let mut sub = manager.subscribe("temp".to_string()).await;

        manager
            .publish("temp".to_string(), Bytes::from("msg1"))
            .await
            .expect("Publish");
        assert!(sub.recv().await.is_some());

        manager.unsubscribe("temp").await;
        manager
            .publish("temp".to_string(), Bytes::from("msg2"))
            .await
            .expect("Publish");
        assert!(sub.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_subscription_count() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");

        assert_eq!(manager.subscription_count().await, 0);
        let _sub_t1 = manager.subscribe("t1".to_string()).await;
        assert_eq!(manager.subscription_count().await, 1);
        let _sub_t2 = manager.subscribe("t2".to_string()).await;
        assert_eq!(manager.subscription_count().await, 2);
        let _sub_t1_b = manager.subscribe("t1".to_string()).await; // same topic
        assert_eq!(manager.subscription_count().await, 2);
        manager.unsubscribe("t1").await;
        assert_eq!(manager.subscription_count().await, 1);
    }

    #[tokio::test]
    async fn test_handle_incoming_invalid() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let _sub = manager.subscribe("test".to_string()).await;

        let peer = PeerId::new([1; 32]);
        // Should not panic on invalid data
        manager
            .handle_incoming(peer, Bytes::from(&[0x12][..]))
            .await;
    }
}
