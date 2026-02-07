//! x0x Pub/Sub with epidemic broadcast.
//!
//! This module implements minimal topic-based pub/sub for x0x, enabling
//! agents to publish and subscribe to messages by topic. Messages are
//! broadcast to all connected peers using epidemic dissemination.

use crate::error::NetworkResult;
use crate::network::NetworkNode;
use bytes::Bytes;
use futures::future;
use saorsa_gossip_transport::{GossipStreamType, GossipTransport};
use saorsa_gossip_types::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Message published to the pub/sub system.
#[derive(Debug, Clone, PartialEq)]
pub struct PubSubMessage {
    /// The topic this message was published on.
    pub topic: String,
    /// The message payload.
    pub payload: Bytes,
}

/// Subscription to a topic.
///
/// A subscription receives messages published to its topic through
/// a channel receiver. The subscription can be canceled by dropping
/// the receiver.
///
/// When dropped, the subscription automatically cleans up dead senders
/// from the PubSubManager's subscription list, preventing memory leaks
/// and performance degradation from accumulating disconnected channels.
pub struct Subscription {
    /// The topic this subscription is for.
    topic: String,
    /// Channel receiver for messages on this topic.
    receiver: mpsc::Receiver<PubSubMessage>,
    /// Reference to subscriptions map for cleanup on drop.
    subscriptions: Arc<RwLock<HashMap<String, Vec<mpsc::Sender<PubSubMessage>>>>>,
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
        let subscriptions = self.subscriptions.clone();

        // Spawn a task to clean up dead senders from this topic
        // This avoids blocking on synchronous locks in drop
        tokio::spawn(async move {
            // Do cleanup on the topic's senders
            let mut subs_map = subscriptions.write().await;
            if let Some(senders) = subs_map.get_mut(&topic) {
                // Remove all disconnected senders (where is_closed() returns true)
                senders.retain(|sender| !sender.is_closed());

                // If no senders remain, remove the topic entirely
                if senders.is_empty() {
                    drop(subs_map);
                    subscriptions.write().await.remove(&topic);
                }
            }
        });
    }
}

/// Pub/Sub manager using epidemic broadcast.
///
/// This implements simple topic-based pub/sub with local subscriber
/// tracking and epidemic broadcast to all connected peers.
///
/// # Architecture
///
/// ```text
/// Publisher → PubSubManager.publish()
///     ├─> Deliver to local subscribers
///     └─> Broadcast to all connected peers via GossipTransport
///
/// Peer message → PubSubManager.handle_incoming()
///     ├─> Deliver to local subscribers
///     └─> Re-broadcast to other peers (epidemic)
/// ```
///
/// Note: Message deduplication will be added in Task 5.
#[derive(Debug)]
pub struct PubSubManager {
    /// Network node for sending/receiving messages.
    network: Arc<NetworkNode>,
    /// Local subscriptions: topic -> list of senders.
    subscriptions: Arc<RwLock<HashMap<String, Vec<mpsc::Sender<PubSubMessage>>>>>,
}

impl PubSubManager {
    /// Create a new pub/sub manager.
    ///
    /// # Arguments
    ///
    /// * `network` - The network node (implements GossipTransport)
    ///
    /// # Returns
    ///
    /// A new `PubSubManager` instance
    pub fn new(network: Arc<NetworkNode>) -> Self {
        Self {
            network,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to a topic.
    ///
    /// Creates a new subscription to receive messages published to the
    /// given topic. The subscription is canceled when the returned
    /// `Subscription` is dropped.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic to subscribe to
    ///
    /// # Returns
    ///
    /// A new `Subscription` for receiving messages on this topic
    pub async fn subscribe(&self, topic: String) -> Subscription {
        let (tx, rx) = mpsc::channel(100);

        self.subscriptions
            .write()
            .await
            .entry(topic.clone())
            .or_default()
            .push(tx);

        Subscription {
            topic,
            receiver: rx,
            subscriptions: self.subscriptions.clone(),
        }
    }

    /// Publish a message to a topic.
    ///
    /// Publishes a message to all local subscribers and broadcasts it
    /// to all connected peers via epidemic broadcast.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic to publish to
    /// * `payload` - The message payload
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Peer communication fails
    /// - Message encoding fails
    pub async fn publish(&self, topic: String, payload: Bytes) -> NetworkResult<()> {
        // 1. Deliver to local subscribers
        if let Some(subs) = self.subscriptions.read().await.get(&topic) {
            let message = PubSubMessage {
                topic: topic.clone(),
                payload: payload.clone(),
            };

            for tx in subs {
                // Ignore errors: subscriber may have dropped the receiver
                let _ = tx.send(message.clone()).await;
            }
        }

        // 2. Broadcast to all connected peers via GossipTransport (in parallel)
        let encoded = encode_pubsub_message(&topic, &payload)?;

        // Get connected peers and broadcast to each
        let connected_peers = {
            let ant_peers = self.network.connected_peers().await;
            // Convert ant-quic PeerIds to saorsa-gossip PeerIds
            ant_peers
                .into_iter()
                .map(|p| {
                    // Convert ant-quic PeerId (32 bytes) to saorsa-gossip PeerId
                    PeerId::new(p.0)
                })
                .collect::<Vec<_>>()
        };

        // Parallelize peer sends using join_all
        let send_futures: Vec<_> = connected_peers
            .into_iter()
            .map(|peer| {
                let network = self.network.clone();
                let encoded = encoded.clone();
                async move {
                    // Ignore errors: individual peer failures shouldn't fail entire publish
                    let _ = network
                        .send_to_peer(peer, GossipStreamType::PubSub, encoded)
                        .await;
                }
            })
            .collect();

        future::join_all(send_futures).await;

        Ok(())
    }

    /// Handle an incoming message from a peer.
    ///
    /// Called when a message is received from the network. Decodes the
    /// message, delivers it to local subscribers, and re-broadcasts to
    /// other peers (epidemic dissemination).
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer that sent this message (for logging/debugging)
    /// * `data` - The encoded message data
    pub async fn handle_incoming(&self, peer: PeerId, data: Bytes) {
        // Decode the message
        let (topic, payload) = match decode_pubsub_message(data) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!(
                    "Failed to decode pubsub message from peer {:?}: {}",
                    peer,
                    e
                );
                return;
            }
        };

        // Deliver to local subscribers
        if let Some(subs) = self.subscriptions.read().await.get(&topic) {
            let message = PubSubMessage {
                topic: topic.clone(),
                payload: payload.clone(),
            };

            for tx in subs {
                // Ignore errors: subscriber may have dropped the receiver
                let _ = tx.send(message.clone()).await;
            }
        }

        // Re-broadcast to other peers (epidemic broadcast)
        // TODO: Task 5 - Add seen-message tracking to prevent loops
        let encoded = match encode_pubsub_message(&topic, &payload) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("Failed to encode pubsub message for rebroadcast: {}", e);
                return;
            }
        };

        // Get connected peers and re-broadcast (excluding sender if possible)
        let connected_peers = {
            let ant_peers = self.network.connected_peers().await;
            ant_peers
                .into_iter()
                .map(|p| PeerId::new(p.0))
                .collect::<Vec<_>>()
        };

        // Parallelize re-broadcasts using join_all
        let rebroadcast_futures: Vec<_> = connected_peers
            .into_iter()
            .filter(|other_peer| other_peer != &peer) // Exclude sender
            .map(|other_peer| {
                let network = self.network.clone();
                let encoded = encoded.clone();
                async move {
                    let _ = network
                        .send_to_peer(other_peer, GossipStreamType::PubSub, encoded)
                        .await;
                }
            })
            .collect();

        future::join_all(rebroadcast_futures).await;
    }

    /// Get the number of active subscriptions.
    ///
    /// # Returns
    ///
    /// The number of topics with at least one subscriber
    pub async fn subscription_count(&self) -> usize {
        self.subscriptions.read().await.len()
    }

    /// Unsubscribe from a topic.
    ///
    /// Removes all subscriptions for the given topic. This is typically
    /// called automatically when a `Subscription` is dropped, but can
    /// be used to manually cancel all subscriptions to a topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic to unsubscribe from
    pub async fn unsubscribe(&self, topic: &str) {
        self.subscriptions.write().await.remove(topic);
    }
}

/// Encode a pub/sub message for network transmission.
///
/// Format: `[topic_len: u16_be | topic_bytes | payload]`
///
/// # Arguments
///
/// * `topic` - The topic string
/// * `payload` - The message payload
///
/// # Returns
///
/// Encoded message bytes
///
/// # Errors
///
/// Returns an error if:
/// - Topic is too long (> 65535 bytes)
/// - Encoding fails
fn encode_pubsub_message(topic: &str, payload: &Bytes) -> NetworkResult<Bytes> {
    let topic_bytes = topic.as_bytes();
    let topic_len = u16::try_from(topic_bytes.len()).map_err(|_| {
        crate::error::NetworkError::SerializationError("Topic too long".to_string())
    })?;

    let mut buf = Vec::with_capacity(2 + topic_bytes.len() + payload.len());
    buf.extend_from_slice(&topic_len.to_be_bytes());
    buf.extend_from_slice(topic_bytes);
    buf.extend_from_slice(payload);

    Ok(Bytes::from(buf))
}

/// Decode a pub/sub message from network transmission.
///
/// # Arguments
///
/// * `data` - The encoded message bytes
///
/// # Returns
///
/// Tuple of (topic, payload)
///
/// # Errors
///
/// Returns an error if:
/// - Data is too short (< 2 bytes)
/// - Topic length is invalid
/// - UTF-8 decoding fails
fn decode_pubsub_message(data: Bytes) -> NetworkResult<(String, Bytes)> {
    if data.len() < 2 {
        return Err(crate::error::NetworkError::SerializationError(
            "Message too short".to_string(),
        ));
    }

    let topic_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + topic_len {
        return Err(crate::error::NetworkError::SerializationError(
            "Invalid topic length".to_string(),
        ));
    }

    let topic_bytes = &data[2..2 + topic_len];
    let topic = String::from_utf8(topic_bytes.to_vec()).map_err(|e| {
        crate::error::NetworkError::SerializationError(format!("Invalid UTF-8: {}", e))
    })?;

    let payload = data.slice(2 + topic_len..);

    Ok((topic, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkConfig;

    /// Helper to create a test network node
    async fn test_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(NetworkConfig::default())
                .await
                .expect("Failed to create test node"),
        )
    }

    #[test]
    fn test_message_encoding_decoding() {
        let topic = "test-topic";
        let payload = Bytes::from(&b"hello world"[..]);

        let encoded = encode_pubsub_message(topic, &payload).expect("Encoding failed");
        let (decoded_topic, decoded_payload) =
            decode_pubsub_message(encoded).expect("Decoding failed");

        assert_eq!(decoded_topic, topic);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_message_encoding_empty_topic() {
        let topic = "";
        let payload = Bytes::from(&b"data"[..]);

        let encoded = encode_pubsub_message(topic, &payload).expect("Encoding failed");
        let (decoded_topic, decoded_payload) =
            decode_pubsub_message(encoded).expect("Decoding failed");

        assert_eq!(decoded_topic, topic);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_message_encoding_empty_payload() {
        let topic = "test-topic";
        let payload = Bytes::new();

        let encoded = encode_pubsub_message(topic, &payload).expect("Encoding failed");
        let (decoded_topic, decoded_payload) =
            decode_pubsub_message(encoded).expect("Decoding failed");

        assert_eq!(decoded_topic, topic);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_message_encoding_unicode_topic() {
        let topic = "тема/главная/система";
        let payload = Bytes::from(&b"data"[..]);

        let encoded = encode_pubsub_message(topic, &payload).expect("Encoding failed");
        let (decoded_topic, decoded_payload) =
            decode_pubsub_message(encoded).expect("Decoding failed");

        assert_eq!(decoded_topic, topic);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_message_encoding_too_long_topic() {
        let topic = "a".repeat(70000); // > u16::MAX
        let payload = Bytes::from(&b"data"[..]);

        let result = encode_pubsub_message(&topic, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_decoding_too_short() {
        let data = Bytes::from(&[0x12, 0x34][..]); // Only 2 bytes (topic length)

        let result = decode_pubsub_message(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_decoding_invalid_utf8() {
        let mut data = vec![0u8; 5];
        data[0] = 0; // topic_len = 0
        data[1] = 3; // topic_len = 3
        data[2] = 0xFF;
        data[3] = 0xFF;
        data[4] = 0xFF; // Invalid UTF-8

        let result = decode_pubsub_message(Bytes::from(data));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pubsub_creation() {
        let node = test_node().await;
        let _manager = PubSubManager::new(node);
    }

    #[tokio::test]
    async fn test_subscribe_to_topic() {
        let node = test_node().await;
        let manager = PubSubManager::new(node);

        let sub = manager.subscribe("test-topic".to_string()).await;
        assert_eq!(sub.topic(), "test-topic");
    }

    #[tokio::test]
    async fn test_publish_local_delivery() {
        let node = test_node().await;
        let manager = PubSubManager::new(node.clone());

        // Subscribe to topic
        let mut sub = manager.subscribe("chat".to_string()).await;

        // Publish message
        manager
            .publish("chat".to_string(), Bytes::from("hello"))
            .await
            .expect("Publish failed");

        // Receive message
        let msg = sub.recv().await.expect("Failed to receive message");

        assert_eq!(msg.topic, "chat");
        assert_eq!(msg.payload, Bytes::from("hello"));
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let node = test_node().await;
        let manager = PubSubManager::new(node.clone());

        // Multiple subscribers to same topic
        let mut sub1 = manager.subscribe("news".to_string()).await;
        let mut sub2 = manager.subscribe("news".to_string()).await;
        let mut sub3 = manager.subscribe("news".to_string()).await;

        // Publish message
        manager
            .publish("news".to_string(), Bytes::from("breaking news"))
            .await
            .expect("Publish failed");

        // All subscribers should receive
        let msg1 = sub1.recv().await.expect("sub1 failed");
        let msg2 = sub2.recv().await.expect("sub2 failed");
        let msg3 = sub3.recv().await.expect("sub3 failed");

        assert_eq!(msg1.payload, Bytes::from("breaking news"));
        assert_eq!(msg2.payload, Bytes::from("breaking news"));
        assert_eq!(msg3.payload, Bytes::from("breaking news"));
    }

    #[tokio::test]
    async fn test_publish_no_subscribers() {
        let node = test_node().await;
        let manager = PubSubManager::new(node);

        // Publish without any subscribers - should not fail
        let result = manager
            .publish("empty-topic".to_string(), Bytes::from("no one listening"))
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unsubscribe() {
        let node = test_node().await;
        let manager = PubSubManager::new(node);

        // Subscribe
        let mut sub = manager.subscribe("temp".to_string()).await;

        // Publish - should receive
        manager
            .publish("temp".to_string(), Bytes::from("message 1"))
            .await
            .expect("Publish failed");

        assert!(sub.recv().await.is_some());

        // Unsubscribe
        manager.unsubscribe("temp").await;

        // Publish again - should not receive (channel closed)
        manager
            .publish("temp".to_string(), Bytes::from("message 2"))
            .await
            .expect("Publish failed");

        assert!(sub.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_subscription_count() {
        let node = test_node().await;
        let manager = PubSubManager::new(node.clone());

        assert_eq!(manager.subscription_count().await, 0);

        manager.subscribe("topic1".to_string()).await;
        assert_eq!(manager.subscription_count().await, 1);

        manager.subscribe("topic2".to_string()).await;
        assert_eq!(manager.subscription_count().await, 2);

        manager.subscribe("topic1".to_string()).await; // Same topic
        assert_eq!(manager.subscription_count().await, 2); // Still 2 topics

        manager.unsubscribe("topic1").await;
        assert_eq!(manager.subscription_count().await, 1);
    }

    #[tokio::test]
    async fn test_handle_incoming_delivers_to_subscribers() {
        let node = test_node().await;
        let manager = PubSubManager::new(node.clone());

        // Subscribe
        let mut sub = manager.subscribe("remote".to_string()).await;

        // Simulate incoming message from peer
        let peer = PeerId::new([1; 32]);
        let encoded = encode_pubsub_message("remote", &Bytes::from("incoming message"))
            .expect("Encoding failed");

        manager.handle_incoming(peer, encoded).await;

        // Should receive
        let msg = sub.recv().await.expect("Failed to receive");
        assert_eq!(msg.topic, "remote");
        assert_eq!(msg.payload, Bytes::from("incoming message"));
    }

    #[tokio::test]
    async fn test_handle_incoming_invalid_message() {
        let node = test_node().await;
        let manager = PubSubManager::new(node);

        // Subscribe
        let _sub = manager.subscribe("test".to_string()).await;

        // Send invalid message (too short)
        let peer = PeerId::new([1; 32]);
        let invalid_data = Bytes::from(&[0x12][..]);

        // Should not panic
        manager.handle_incoming(peer, invalid_data).await;
    }
}
