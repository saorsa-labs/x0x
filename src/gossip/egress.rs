//! Observe-only Leaf egress accounting and the PubSub transport seam.
use super::config::GossipConfig;
use crate::network::NetworkNode;
use bytes::Bytes;
use saorsa_gossip_transport::{GossipStreamType, GossipTransport};
use saorsa_gossip_types::{MessageHeader, MessageKind, PeerId, TopicId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// sg spawns bounded sends, so task-local context cannot label cached replies.
// Match exact in-flight IWANT (peer, topic, message) requests. PlumTree
// verifies every inbound IWANT signature in `handle_message` before acting
// on it, so this tracking does NOT re-verify (#656): a forged frame's
// the counters are diagnostics-only.
type RepairKey = (PeerId, TopicId, [u8; 32]);
type RepairRequests = Arc<Mutex<HashMap<RepairKey, usize>>>;

pub(super) struct RepairScope {
    requests: RepairRequests,
    keys: Vec<RepairKey>,
}
impl Drop for RepairScope {
    fn drop(&mut self) {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in &self.keys {
            if let Some(count) = requests.get_mut(key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    requests.remove(key);
                }
            }
        }
    }
}

pub(super) struct PubSubTransport {
    pub network: Arc<NetworkNode>,
    /// Eager sends matching an in-flight IWANT (peer, topic, message) — a
    /// diagnostics-only subset of eager counters. Signature verification is
    /// PlumTree's job on the inbound IWANT; the tracking keys are
    /// unverified frame fields (#656), so a forged IWANT cannot inflate
    /// these beyond the repair sends its own (rejected) frame would have
    /// drawn.
    pub repair_msgs: AtomicU64,
    /// Byte total accompanying [`Self::repair_msgs`].
    pub repair_bytes: AtomicU64,
    repair_requests: RepairRequests,
    pub repair_tracking_overflow: AtomicU64,
    #[cfg(test)]
    pub recorder: std::sync::Mutex<Option<Recorder>>,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct Recorder {
    pub peers: Vec<PeerId>,
    pub sends: Vec<(PeerId, Bytes)>,
}

impl PubSubTransport {
    pub fn new(network: Arc<NetworkNode>) -> Self {
        Self {
            network,
            repair_msgs: AtomicU64::new(0),
            repair_bytes: AtomicU64::new(0),
            repair_requests: Arc::new(Mutex::new(HashMap::new())),
            repair_tracking_overflow: AtomicU64::new(0),
            #[cfg(test)]
            recorder: std::sync::Mutex::new(None),
        }
    }
    /// Track the message IDs an inbound IWANT frame requests, keyed by
    /// (peer, topic, message). Returns the scope whose `Drop` retires the
    /// entries, so classification covers exactly the repair sends PlumTree
    /// issues while handling this frame.
    ///
    /// Deliberately does NOT verify the frame's ML-DSA signature (#656):
    /// `plumtree.handle_message` verifies the same bytes immediately after
    /// this call and ignores unauthenticated IWANTs, so a redundant verify
    /// here cost one ML-DSA-65 verification per inbound IWANT (~106/s on
    /// the profiled fleet) purely to gate a diagnostics counter. The cheap
    /// structural gates stay: exact `GossipMessage` decode, `IWant` kind,
    /// v2 header, payload-hash binding, and decodable id list.
    pub fn track_iwant(&self, peer: PeerId, data: &[u8]) -> Option<RepairScope> {
        let message: saorsa_gossip_pubsub::GossipMessage = postcard::from_bytes(data).ok()?;
        if message.header.kind != MessageKind::IWant {
            return None;
        }
        let payload = message.payload.as_ref()?;
        if message.header.version != 2
            || message.header.payload_hash != Some(*blake3::hash(payload).as_bytes())
        {
            return None;
        }
        let ids: Vec<[u8; 32]> = postcard::from_bytes(payload).ok()?;
        let mut scope = RepairScope {
            requests: Arc::clone(&self.repair_requests),
            keys: Vec::new(),
        };
        let mut requests = self
            .repair_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in ids {
            let key = (peer, message.header.topic, id);
            if requests.len() >= 4096 || scope.keys.len() >= 4096 {
                self.repair_tracking_overflow
                    .fetch_add(1, Ordering::Relaxed);
                break;
            }
            *requests.entry(key).or_default() += 1;
            scope.keys.push(key);
        }
        Some(scope)
    }
}

#[async_trait::async_trait]
impl GossipTransport for PubSubTransport {
    async fn dial(&self, peer: PeerId, addr: SocketAddr) -> anyhow::Result<()> {
        self.network.dial(peer, addr).await
    }
    async fn dial_bootstrap(&self, addr: SocketAddr) -> anyhow::Result<PeerId> {
        self.network.dial_bootstrap(addr).await
    }
    async fn listen(&self, bind: SocketAddr) -> anyhow::Result<()> {
        self.network.listen(bind).await
    }
    async fn close(&self) -> anyhow::Result<()> {
        self.network.close().await
    }
    async fn receive_message(&self) -> anyhow::Result<(PeerId, GossipStreamType, Bytes)> {
        self.network.receive_message().await
    }
    fn local_peer_id(&self) -> PeerId {
        self.network.local_peer_id()
    }
    async fn connected_peer_ids(&self) -> Vec<PeerId> {
        #[cfg(test)]
        if let Some(recorder) = self.recorder.lock().expect("recorder").as_ref() {
            return recorder.peers.clone();
        }
        self.network.connected_peer_ids().await
    }
    async fn send_to_peer(
        &self,
        peer: PeerId,
        stream: GossipStreamType,
        data: Bytes,
    ) -> anyhow::Result<()> {
        if postcard::take_from_bytes::<MessageHeader>(&data).is_ok_and(|(header, _)| {
            header.kind == MessageKind::Eager
                && self
                    .repair_requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains_key(&(peer, header.topic, header.msg_id))
        }) {
            self.repair_msgs.fetch_add(1, Ordering::Relaxed);
            self.repair_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        #[cfg(test)]
        if let Some(recorder) = self.recorder.lock().expect("recorder").as_mut() {
            recorder.sends.push((peer, data));
            return Ok(());
        }
        self.network.send_to_peer(peer, stream, data).await
    }
}

#[derive(Default)]
pub(super) struct EgressMeter {
    previous: HashMap<String, u64>,
    samples: VecDeque<(Instant, u64)>,
    pub rate: f64,
    pub soft_exceeded: u64,
    pub hard_exceeded: u64,
    pub sampled_at: Option<Instant>,
}

impl EgressMeter {
    /// Runtime samples once per second. Counters count exceeded samples, not
    /// API reads or packets. Warm-up treats the preceding unused window as idle.
    pub fn sample(
        &mut self,
        now: Instant,
        rows: &serde_json::Value,
        subscribed: &HashSet<String>,
        config: &GossipConfig,
    ) {
        let mut delta = 0u64;
        if let Some(rows) = rows.as_object() {
            for (topic, kinds) in rows {
                let bytes = kinds
                    .as_object()
                    .map(|kinds| {
                        kinds.values().fold(0u64, |sum, kind| {
                            sum.saturating_add(kind["bytes"].as_u64().unwrap_or(0))
                        })
                    })
                    .unwrap_or(0);
                let old = self.previous.insert(topic.clone(), bytes).unwrap_or(0);
                if subscribed.contains(topic) {
                    delta = delta.saturating_add(bytes.saturating_sub(old));
                }
            }
        }
        self.samples.push_back((now, delta));
        while self
            .samples
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= Duration::from_secs(60))
        {
            self.samples.pop_front();
        }
        self.rate = self
            .samples
            .iter()
            .map(|(_, bytes)| *bytes as f64)
            .sum::<f64>()
            / 60.0;
        self.sampled_at = Some(now);
        if !config.resolved_participation().forwards_passthrough() {
            if config.leaf_egress_soft_bytes_per_sec > 0
                && self.rate > config.leaf_egress_soft_bytes_per_sec as f64
            {
                self.soft_exceeded = self.soft_exceeded.saturating_add(1);
            }
            if config.leaf_egress_hard_bytes_per_sec > 0
                && self.rate > config.leaf_egress_hard_bytes_per_sec as f64
            {
                self.hard_exceeded = self.hard_exceeded.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn slice1_rate_window_exceed_counts_are_observe_only_and_expire() {
        let config = GossipConfig {
            leaf_egress_soft_bytes_per_sec: 1,
            leaf_egress_hard_bytes_per_sec: 2,
            ..Default::default()
        };
        let mut meter = EgressMeter::default();
        let now = Instant::now();
        let subscribed = HashSet::from(["bus".to_string()]);
        let rows = json!({"bus": {"eager": {"bytes": 600}, "iwant": {"bytes": 60}}, "other": {"eager": {"bytes": 60_000}}});
        meter.sample(now, &rows, &subscribed, &config);
        assert_eq!(meter.rate, 11.0);
        assert_eq!((meter.soft_exceeded, meter.hard_exceeded), (1, 1));
        meter.sample(now + Duration::from_secs(1), &rows, &subscribed, &config);
        assert_eq!(
            meter.rate, 11.0,
            "cumulative counters must not be counted twice"
        );
        assert_eq!((meter.soft_exceeded, meter.hard_exceeded), (2, 2));
        meter.sample(now + Duration::from_secs(60), &rows, &subscribed, &config);
        assert_eq!(meter.rate, 0.0, "the 60s window must expire idle traffic");
        let disabled = GossipConfig {
            leaf_egress_soft_bytes_per_sec: 0,
            leaf_egress_hard_bytes_per_sec: 0,
            ..Default::default()
        };
        meter.sample(
            now + Duration::from_secs(61),
            &json!({"bus":{"eager":{"bytes":60000}}}),
            &subscribed,
            &disabled,
        );
        assert_eq!((meter.soft_exceeded, meter.hard_exceeded), (2, 2));
        let full = GossipConfig {
            relay: true,
            ..config
        };
        meter.sample(now + Duration::from_secs(62), &rows, &subscribed, &full);
        assert_eq!((meter.soft_exceeded, meter.hard_exceeded), (2, 2));
    }

    mod track_iwant {
        use super::super::*;
        use crate::network::{NetworkConfig, NetworkNode};
        use bytes::Bytes;
        use saorsa_gossip_types::TopicId;
        use std::sync::Arc;

        /// Explicit test-only network config (#417/#337): loopback bind, no
        /// seeds, discovery/port-mapping off.
        fn test_network_config() -> NetworkConfig {
            NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..NetworkConfig::default()
            }
        }

        async fn make_transport() -> PubSubTransport {
            let node = Arc::new(
                NetworkNode::new(test_network_config(), None, None)
                    .await
                    .expect("network node"),
            );
            PubSubTransport::new(node)
        }

        /// A structurally valid v2 IWANT frame: exact decode, IWant kind,
        /// payload-hash binding, decodable id list — optionally signed.
        fn iwant_frame(topic: TopicId, ids: &[[u8; 32]], sign: bool) -> Vec<u8> {
            let payload = postcard::to_stdvec(&ids.to_vec()).expect("encode ids");
            let mut header = MessageHeader {
                version: 2,
                topic,
                msg_id: [7; 32],
                kind: MessageKind::IWant,
                hop: 0,
                ttl: 10,
                payload_hash: Some(*blake3::hash(&payload).as_bytes()),
            };
            header.seal_payload_hash(Some(&payload));
            let signature = if sign {
                let kp = saorsa_gossip_identity::MlDsaKeyPair::generate().expect("keypair");
                let header_bytes = postcard::to_stdvec(&header).expect("encode header");
                kp.sign(&header_bytes).expect("sign")
            } else {
                Vec::new()
            };
            let message = saorsa_gossip_pubsub::GossipMessage {
                header,
                payload: Some(Bytes::from(payload)),
                signature,
                public_key: Vec::new(),
            };
            postcard::to_stdvec(&message).expect("encode frame")
        }

        /// #656: the counter path must not pay an ML-DSA verify per inbound
        /// IWANT. PlumTree verifies the frame itself in `handle_message`;
        /// here, a malformed (empty) signature must change NOTHING about
        /// tracking — both frames are tracked identically. Under the old
        /// verify-gated tracking the unsigned frame returned `None`.
        #[tokio::test]
        async fn malformed_signature_does_not_change_the_counter_path() {
            let transport = make_transport().await;
            let peer = PeerId::new([1; 32]);
            let topic = TopicId::from_entity(b"iwant-verify-topic");
            let ids = [[0xAA; 32]];
            let signed = iwant_frame(topic, &ids, true);
            let unsigned = iwant_frame(topic, &ids, false);
            assert_ne!(signed, unsigned);

            let signed_scope = transport
                .track_iwant(peer, &signed)
                .expect("validly signed IWANT is tracked");
            assert_eq!(signed_scope.keys.len(), 1);
            let unsigned_scope = transport
                .track_iwant(peer, &unsigned)
                .expect("an unauthenticated IWANT is tracked too — the verify is PlumTree's job");
            assert_eq!(
                unsigned_scope.keys, signed_scope.keys,
                "signature validity must not alter the tracked keys"
            );
        }

        /// The classification itself still works end to end: while an
        /// IWANT's scope is live, an Eager send matching its
        /// (peer, topic, message) key is metered into the repair counters.
        #[tokio::test]
        async fn tracked_iwant_classifies_the_matching_repair_eager_send() {
            let transport = make_transport().await;
            // Keep sends off the real socket; the metering happens before
            // the recorder early-return.
            *transport
                .recorder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Recorder::default());
            let peer = PeerId::new([2; 32]);
            let topic = TopicId::from_entity(b"iwant-repair-topic");
            let wanted = [0xBB; 32];
            let frame = iwant_frame(topic, &[wanted], false);
            let _scope = transport.track_iwant(peer, &frame).expect("tracked");

            let repair = saorsa_gossip_pubsub::GossipMessage {
                header: MessageHeader {
                    version: 2,
                    topic,
                    msg_id: wanted,
                    kind: MessageKind::Eager,
                    hop: 0,
                    ttl: 10,
                    payload_hash: None,
                },
                payload: Some(Bytes::from_static(b"repair payload")),
                signature: Vec::new(),
                public_key: Vec::new(),
            };
            let bytes = postcard::to_stdvec(&repair).expect("encode repair");
            transport
                .send_to_peer(peer, GossipStreamType::PubSub, Bytes::from(bytes.clone()))
                .await
                .expect("recorder send");

            assert_eq!(transport.repair_msgs.load(Ordering::Relaxed), 1);
            assert_eq!(
                transport.repair_bytes.load(Ordering::Relaxed),
                bytes.len() as u64
            );
        }
    }
}
