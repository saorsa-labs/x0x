//! x0x Pub/Sub with PlumTree dissemination and ML-DSA-65 signed messages.
//!
//! This module implements topic-based pub/sub for x0x with:
//! - PlumTree dissemination via `saorsa-gossip-pubsub`
//! - x0x payload-level message authentication (V2 and topic-bound V3)
//!
//! Three wire formats coexist during the transition period:
//! - **V1** (legacy): `[topic_len: u16_be | topic | payload]` — unsigned
//! - **V3** (Signed KV pairing): same fields as V2, with signed topic length
//! - **V2** (signed): `[0x02 | agent_id | pubkey | signature | topic | payload]`

use super::egress::{EgressMeter, PubSubTransport};
use super::participation::{
    classify_outbound_relay_json, leaf_refuses_unsubscribed_passthrough, ParticipationMode,
    ParticipationSnapshot, RELAY_BYTES_SEMANTICS,
};
use super::GossipConfig;
use crate::contacts::{ContactStore, TrustLevel};
use crate::error::{NetworkError, NetworkResult};
use crate::identity::AgentId;
use crate::network::NetworkNode;
use bytes::Bytes;
use saorsa_gossip_pubsub::{PlumtreePubSub, PubSub, SignaturePolicy};
use saorsa_gossip_transport::GossipTransport;
use saorsa_gossip_types::{
    MessageHeader, MessageKind, PeerHealthOracle, PeerId, TopicId, TopicPriority,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

/// Rate-limit window for `fan_out == 0` warnings (issue #296).
///
/// Matches the X0X-0073 cooling floor so a send storm produces one warn
/// per group per cooldown, not one warn per message.
pub(crate) const ZERO_FANOUT_WARN_WINDOW: Duration = Duration::from_secs(30);

/// Drop-detection counters for the pub/sub pipeline.
///
/// Every stage of the publish → transport → receive → decode → deliver flow
/// increments exactly one counter so that deltas surface where messages are
/// lost. Exposed via `GET /diagnostics/gossip`.
#[derive(Debug, Default)]
pub struct PubSubStats {
    /// Successful `publish()` calls (encoded + handed to PlumTree).
    pub publish_total: AtomicU64,
    /// `publish()` that failed at encoding/signing or PlumTree handoff.
    pub publish_failed: AtomicU64,
    /// Messages received from PlumTree (pre-decode, per topic).
    pub incoming_total: AtomicU64,
    /// Messages that decoded successfully + passed trust filter.
    pub incoming_decoded: AtomicU64,
    /// Messages that failed decode (malformed, unsupported version) OR were
    /// dropped by trust filter (blocked sender).
    pub incoming_decode_failed: AtomicU64,
    /// Messages successfully handed to a local subscriber channel.
    pub delivered_to_subscriber: AtomicU64,
    /// Subscriber channel was full and got dropped to isolate the dispatcher
    /// from a slow local consumer (for example a stuck SSE client path).
    pub slow_subscriber_dropped: AtomicU64,
    /// Subscriber channel closed or was dropped after slow-consumer isolation —
    /// message not delivered, but accounted for so decode→delivery deltas stay
    /// meaningful.
    pub subscriber_channel_closed: AtomicU64,
    /// Local publishes that fanned out to zero eager peers (`fan_out == 0`).
    /// Exposed as `gossip_publish_zero_fanout` at `GET /diagnostics/gossip`.
    pub publish_zero_fanout: AtomicU64,
}

/// Snapshot of [`PubSubStats`] for JSON serialization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PubSubStatsSnapshot {
    pub publish_total: u64,
    pub publish_failed: u64,
    pub incoming_total: u64,
    pub incoming_decoded: u64,
    pub incoming_decode_failed: u64,
    pub delivered_to_subscriber: u64,
    pub slow_subscriber_dropped: u64,
    pub subscriber_channel_closed: u64,
    /// Local publishes whose eager-peer fan-out was zero.
    pub publish_zero_fanout: u64,
    /// `incoming_total - incoming_decoded - incoming_decode_failed` — messages
    /// that entered the pipeline but did not reach a decision yet (usually 0,
    /// non-zero means a worker panicked or the decode task is blocked).
    pub in_flight_decode: i64,
    /// `incoming_decoded - delivered_to_subscriber - subscriber_channel_closed`
    /// — messages decoded but never handed off (drop signal).
    pub decode_to_delivery_drops: i64,
}

impl PubSubStats {
    /// Take an atomic snapshot of every counter.
    pub fn snapshot(&self) -> PubSubStatsSnapshot {
        let publish_total = self.publish_total.load(Ordering::Relaxed);
        let publish_failed = self.publish_failed.load(Ordering::Relaxed);
        let incoming_total = self.incoming_total.load(Ordering::Relaxed);
        let incoming_decoded = self.incoming_decoded.load(Ordering::Relaxed);
        let incoming_decode_failed = self.incoming_decode_failed.load(Ordering::Relaxed);
        let delivered_to_subscriber = self.delivered_to_subscriber.load(Ordering::Relaxed);
        let slow_subscriber_dropped = self.slow_subscriber_dropped.load(Ordering::Relaxed);
        let subscriber_channel_closed = self.subscriber_channel_closed.load(Ordering::Relaxed);
        let publish_zero_fanout = self.publish_zero_fanout.load(Ordering::Relaxed);
        let in_flight_decode =
            incoming_total as i64 - incoming_decoded as i64 - incoming_decode_failed as i64;
        let decode_to_delivery_drops = incoming_decoded as i64
            - delivered_to_subscriber as i64
            - subscriber_channel_closed as i64;
        PubSubStatsSnapshot {
            publish_total,
            publish_failed,
            incoming_total,
            incoming_decoded,
            incoming_decode_failed,
            delivered_to_subscriber,
            slow_subscriber_dropped,
            subscriber_channel_closed,
            publish_zero_fanout,
            in_flight_decode,
            decode_to_delivery_drops,
        }
    }
}

/// Decide whether a zero-fanout publish should emit `tracing::warn!`.
///
/// Always increments `publish_zero_fanout` when `fan_out == 0`. Skips the
/// warn when `peer_count == 0` (solo / first-node is expected). Otherwise
/// rate-limits to once per `(group_id, window)`.
#[must_use]
pub(crate) fn observe_zero_fanout_publish(
    stats: &PubSubStats,
    last_warn_by_group: &mut HashMap<String, Instant>,
    group_id: &str,
    fan_out: u32,
    peer_count: usize,
    now: Instant,
    window: Duration,
) -> bool {
    if fan_out != 0 {
        return false;
    }
    stats.publish_zero_fanout.fetch_add(1, Ordering::Relaxed);
    if peer_count == 0 {
        return false;
    }
    should_emit_zero_fanout_warn(last_warn_by_group, group_id, now, window)
}

/// True when this group has not warned inside `window`.
#[must_use]
pub(crate) fn should_emit_zero_fanout_warn(
    last_warn_by_group: &mut HashMap<String, Instant>,
    group_id: &str,
    now: Instant,
    window: Duration,
) -> bool {
    if let Some(prev) = last_warn_by_group.get(group_id) {
        if now.duration_since(*prev) < window {
            return false;
        }
    }
    last_warn_by_group.insert(group_id.to_string(), now);
    true
}

/// Domain separation prefix for signed message payloads.
const MSG_V2_PREFIX: &[u8] = b"x0x-msg-v2";

/// Version byte for signed messages.
const VERSION_V2: u8 = 0x02;

/// Reserved exclusively for the topic-bound signed inner envelope (ADR-0063).
const VERSION_V3: u8 = 0x03;

/// Domain and bounds of gossip #48's Signed KV inner verifier (ADR-0063).
const MSG_V3_PREFIX: &[u8] = b"x0x-msg-v3";
const MAX_V3_ENVELOPE_BYTES: usize = 1024 * 1024;
const ML_DSA_65_PUBKEY_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SignedVersion {
    V2,
    V3,
}

impl SignedVersion {
    fn byte(self) -> u8 {
        match self {
            Self::V2 => VERSION_V2,
            Self::V3 => VERSION_V3,
        }
    }

    fn signing_payload(
        self,
        author: &[u8; 32],
        topic: &[u8],
        payload: &[u8],
    ) -> NetworkResult<Vec<u8>> {
        match self {
            Self::V2 => Ok(build_signing_payload(author, topic, payload)),
            Self::V3 => {
                let len = u16::try_from(topic.len())
                    .map_err(|_| NetworkError::SerializationError("Topic too long".to_string()))?;
                let mut signed =
                    Vec::with_capacity(MSG_V3_PREFIX.len() + 32 + 2 + topic.len() + payload.len());
                signed.extend_from_slice(MSG_V3_PREFIX);
                signed.extend_from_slice(author);
                signed.extend_from_slice(&len.to_be_bytes());
                signed.extend_from_slice(topic);
                signed.extend_from_slice(payload);
                Ok(signed)
            }
        }
    }
}

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
/// Messages may be signed (v2 or v3) or unsigned (v1 legacy). The `sender` and
/// `verified` fields indicate the authentication state.
#[derive(Debug, Clone)]
pub struct PubSubMessage {
    /// The topic this message was published on.
    pub topic: String,
    /// The message payload.
    pub payload: Bytes,
    /// Sender's AgentId (`None` for unsigned legacy v1 messages).
    pub sender: Option<AgentId>,
    /// Sender's ML-DSA-65 public key bytes (included in signed messages).
    pub sender_public_key: Option<Vec<u8>>,
    /// Whether the ML-DSA-65 signature was verified.
    pub verified: bool,
    /// Trust level from the local contact store (populated during incoming handling).
    pub trust_level: Option<TrustLevel>,
    /// The raw V2 or V3 wire envelope bytes for signed messages (`None` for v1).
    ///
    /// ADR 0028: an authority relays the requester-authored predecessor
    /// envelope unchanged to active witnesses. The relay is a courier, not an
    /// author — these bytes carry the requester's ML-DSA-65 signature and
    /// must be forwarded verbatim, never reconstructed from decoded fields.
    pub raw_envelope: Option<Bytes>,
}

/// Subscription to a topic.
///
/// Receives messages published to its topic through a channel receiver.
/// The subscription is canceled when dropped, automatically decrementing
/// topic subscriber counts in the PubSubManager.
pub struct Subscription {
    /// The topic this subscription is for.
    topic: String,
    /// Transport id recorded at subscribe time (DM inboxes use a
    /// domain-separated id, not `TopicId::from_entity(name)`).
    topic_id: Option<TopicId>,
    /// Channel receiver for messages on this topic.
    receiver: mpsc::Receiver<PubSubMessage>,
    /// Reference to per-topic subscriber counts for cleanup on drop.
    topic_ref_counts: Arc<RwLock<HashMap<String, usize>>>,
    /// Name → transport id, dropped with the last local subscriber.
    topic_id_by_name: Arc<std::sync::RwLock<HashMap<String, TopicId>>>,
    /// Live subscribed transport ids used by the Leaf C0 refuse gate.
    subscribed_topic_ids: Arc<std::sync::RwLock<HashSet<TopicId>>>,
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
        let topic_id = self.topic_id;
        let topic_ref_counts = self.topic_ref_counts.clone();
        let topic_id_by_name = self.topic_id_by_name.clone();
        let subscribed_topic_ids = self.subscribed_topic_ids.clone();

        // Spawn a task to decrement the refcount for this topic.
        // This avoids blocking on synchronous locks in drop.
        tokio::spawn(async move {
            let mut counts = topic_ref_counts.write().await;
            if let Some(count) = counts.get_mut(&topic) {
                if *count > 1 {
                    *count -= 1;
                } else {
                    counts.remove(&topic);
                    topic_id_by_name
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&topic);
                    if let Some(topic_id) = topic_id {
                        subscribed_topic_ids
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .remove(&topic_id);
                    }
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
    plumtree: Arc<PlumtreePubSub<PubSubTransport>>,
    transport: Arc<PubSubTransport>,
    egress_config: GossipConfig,
    egress_meter: Mutex<EgressMeter>,
    eager_ceiling_initialized: tokio::sync::OnceCell<()>,
    /// Local topic subscription ref-counts (for stats and cleanup).
    topic_ref_counts: Arc<RwLock<HashMap<String, usize>>>,
    /// Signing context for authenticating published messages.
    signing: Option<Arc<SigningContext>>,
    /// Contact store for trust-based message filtering.
    /// Set via `set_contacts()` after construction.
    contacts: std::sync::OnceLock<Arc<tokio::sync::RwLock<ContactStore>>>,
    /// Authoritative gossiped revocation set (issue #130 / #191). Runtime-
    /// injected via `set_revocation_set()` after construction (mirrors
    /// `contacts`). Delivery consults this BEFORE the operator-local
    /// ContactStore so a gossiped issuer/agent revocation closes the path
    /// even before the eviction loop sets `trust = Blocked`.
    revocation_set: std::sync::OnceLock<Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>>,
    /// Drop-detection counters exposed at `GET /diagnostics/gossip`.
    stats: Arc<PubSubStats>,
    /// Subscriber channels for `local:` topics (issue #89). These topics
    /// are same-daemon IPC: delivered only to local subscribers, never
    /// handed to PlumTree, never gossipped to remote peers.
    local_topics: Arc<RwLock<HashMap<String, Vec<mpsc::Sender<PubSubMessage>>>>>,
    /// Long-lived membership holds so Direct-connect pre-subscribe of a
    /// peer inbox (#380 C4) stays on the subscribed-topic path. The owned
    /// task drains the receiver so a quiet hold cannot fill the channel
    /// and drop the PlumTree registration.
    membership_holds: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
    /// Issue #380: Leaf skips pass-through eager-set refresh.
    participation: ParticipationMode,
    /// Why this process selected Leaf or Full (diagnostics / startup log).
    participation_reason: String,
    /// Times the Full pass-through loop actually ran.
    passthrough_refresh_runs: AtomicU64,
    /// Name → actual PlumTree topic id (DM inboxes are not `from_entity(name)`).
    topic_id_by_name: Arc<std::sync::RwLock<HashMap<String, TopicId>>>,
    /// Live subscribed transport ids for the Leaf C0 refuse gate.
    subscribed_topic_ids: Arc<std::sync::RwLock<HashSet<TopicId>>>,
    /// Inbound unsubscribed pass-through frames this Leaf refused.
    unsubscribed_refused_frames: AtomicU64,
    unsubscribed_refused_bytes: AtomicU64,
    unsubscribed_refused_graft_equiv: AtomicU64,
    /// Last `fan_out == 0` warn per group, used to rate-limit issue #296.
    zero_fanout_warns: Mutex<HashMap<String, Instant>>,
    /// Test-only: topic ids last passed to `set_topic_peers`.
    #[cfg(test)]
    refreshed_topic_ids: std::sync::Mutex<Vec<TopicId>>,
    /// Test-only: inject PlumTree-known topics without a live mesh.
    #[cfg(test)]
    known_topic_override: std::sync::Mutex<Option<Vec<TopicId>>>,
    /// Test-only: report this fan-out after a successful publish so HTTP
    /// tests can simulate an empty eager set without disabling cooling.
    #[cfg(test)]
    fanout_report_override: Mutex<Option<u32>>,
}

/// Outcome of a PlumTree (or local-topic) publish.
struct PublishFanoutOutcome {
    /// Eager-peer publish count at `publish_local`. `0` is the black-hole.
    fan_out: u32,
    /// Signed envelope bytes when signing is enabled.
    envelope: Option<Bytes>,
}

/// Topic-name prefix marking a topic as local-only (issue #89).
///
/// Topics starting with this prefix are delivered exclusively to
/// subscribers on the same daemon — they never enter the PlumTree EAGER
/// set, IHAVE digests, or any other remote relay path. Because such
/// topics are never registered with PlumTree, an inbound gossip frame
/// referencing one has no subscription to deliver into and is dropped.
pub const LOCAL_TOPIC_PREFIX: &str = "local:";

/// True when `topic` is a same-daemon-only topic (issue #89).
#[must_use]
pub fn is_local_topic(topic: &str) -> bool {
    topic.starts_with(LOCAL_TOPIC_PREFIX)
}

/// Peek the PlumTree header of a serialized `GossipMessage` without verifying
/// the signature. Used by the Leaf C0 refuse gate so unsubscribed frames
/// never reach `handle_message`.
fn peek_pubsub_header(frame: &[u8]) -> Option<MessageHeader> {
    postcard::take_from_bytes::<MessageHeader>(frame)
        .ok()
        .map(|(header, _rest)| header)
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
        Self::new_with_oracle(network, signing, None)
    }

    /// Same as [`Self::new_with_oracle`] with an explicit participation mode.
    pub fn new_with_participation(
        network: Arc<NetworkNode>,
        signing: Option<Arc<SigningContext>>,
        oracle: Option<Arc<dyn PeerHealthOracle>>,
        participation: ParticipationMode,
        participation_reason: impl Into<String>,
    ) -> NetworkResult<Self> {
        let mut manager = Self::new_with_oracle(network, signing, oracle)?;
        manager.participation = participation;
        manager.participation_reason = participation_reason.into();
        Ok(manager)
    }

    /// Construct a [`PubSubManager`] with an explicit SWIM peer-health
    /// oracle. X0X-0073b cooling-decision branches (Suspect grace, Dead
    /// escalation) and X0X-0074 admission Suspect/Dead drops require the
    /// oracle to be wired — without it, the snapshot stays empty and
    /// those branches never engage in production.
    ///
    /// Use `new_with_oracle(network, signing, Some(membership.swim_arc()))`
    /// from the runtime to thread the existing HyParView SWIM detector
    /// into pub-sub. Use [`Self::new`] only when running pub-sub in
    /// isolation (tests, single-binary tools).
    pub fn new_with_oracle(
        network: Arc<NetworkNode>,
        signing: Option<Arc<SigningContext>>,
        oracle: Option<Arc<dyn PeerHealthOracle>>,
    ) -> NetworkResult<Self> {
        let peer_id = saorsa_gossip_transport::GossipTransport::local_peer_id(network.as_ref());
        let plumtree_signing_key =
            saorsa_gossip_identity::MlDsaKeyPair::generate().map_err(|e| {
                NetworkError::NodeCreation(format!("failed to create PlumTree signing key: {e}"))
            })?;

        let transport = Arc::new(PubSubTransport::new(Arc::clone(&network)));
        let mut plumtree_inner =
            PlumtreePubSub::new(peer_id, Arc::clone(&transport), plumtree_signing_key);
        // ADR-014 modern-only: reject outer v1 (header-only-signed) frames.
        plumtree_inner.set_signature_policy(SignaturePolicy::RejectV1);
        if plumtree_inner.signature_policy() != SignaturePolicy::RejectV1 {
            return Err(NetworkError::NodeCreation(
                "mandatory outer signature policy RejectV1 could not be installed".to_string(),
            ));
        }
        let plumtree_inner = match oracle {
            Some(oracle) => plumtree_inner.with_health_oracle(oracle),
            None => plumtree_inner,
        };
        let plumtree = Arc::new(plumtree_inner);
        register_x0x_topic_priorities(plumtree.admission().registry());
        crate::storm_control::register_announce_validators(plumtree.as_ref());

        Ok(Self {
            network,
            plumtree,
            transport,
            egress_config: GossipConfig::default(),
            egress_meter: Mutex::new(EgressMeter::default()),
            eager_ceiling_initialized: tokio::sync::OnceCell::new(),
            topic_ref_counts: Arc::new(RwLock::new(HashMap::new())),
            signing,
            contacts: std::sync::OnceLock::new(),
            revocation_set: std::sync::OnceLock::new(),
            stats: Arc::new(PubSubStats::default()),
            local_topics: Arc::new(RwLock::new(HashMap::new())),
            membership_holds: Arc::new(RwLock::new(HashMap::new())),
            participation: ParticipationMode::Leaf,
            participation_reason: "default_leaf".to_string(),
            passthrough_refresh_runs: AtomicU64::new(0),
            topic_id_by_name: Arc::new(std::sync::RwLock::new(HashMap::new())),
            subscribed_topic_ids: Arc::new(std::sync::RwLock::new(HashSet::new())),
            unsubscribed_refused_frames: AtomicU64::new(0),
            unsubscribed_refused_bytes: AtomicU64::new(0),
            unsubscribed_refused_graft_equiv: AtomicU64::new(0),
            #[cfg(test)]
            refreshed_topic_ids: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            known_topic_override: std::sync::Mutex::new(None),
            zero_fanout_warns: Mutex::new(HashMap::new()),
            #[cfg(test)]
            fanout_report_override: Mutex::new(None),
        })
    }

    /// Apply the validated, observe-only budget before starting the runtime.
    pub(crate) async fn configure_egress(&mut self, config: &GossipConfig) {
        self.egress_config = config.clone();
        self.egress_config.participation = self.participation;
        if let Some(warning) = self.egress_config.normalize_egress_budget() {
            tracing::warn!("{warning}");
        }
        self.ensure_eager_ceiling().await;
    }

    /// Configure before any topic creation or inbound handling, including
    /// standalone managers made with the synchronous public constructors.
    async fn ensure_eager_ceiling(&self) {
        self.eager_ceiling_initialized
            .get_or_init(|| async {
                let degree = if self.participation.forwards_passthrough() {
                    0
                } else {
                    self.egress_config.leaf_max_eager_degree
                };
                self.plumtree.set_eager_degree_ceiling(degree).await;
            })
            .await;
    }

    /// Sample independently of HTTP reads, once per runtime peer-refresh tick.
    pub(crate) fn sample_egress(&self) {
        let stages = serde_json::to_value(self.plumtree.stage_stats()).unwrap_or_default();
        let mut config = self.egress_config.clone();
        config.participation = self.participation;
        self.egress_meter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sample(
                Instant::now(),
                &stages["outbound_by_topic"],
                &self.subscribed_topic_keys(),
                &config,
            );
    }

    /// Named subscription/outbound diagnostics. Names use stored IDs, including
    /// raw DM inbox IDs; unknown or no-longer-subscribed rows stay unknown-hex.
    pub fn egress_diagnostics(&self) -> serde_json::Value {
        let names = self
            .topic_id_by_name
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut subscribed = names
            .iter()
            .map(|(name, id)| (name.clone(), id.to_string()))
            .collect::<Vec<_>>();
        subscribed.sort();
        let topics = subscribed
            .iter()
            .map(|(name, id)| serde_json::json!({"name": name, "topic_id_hex8": id}))
            .collect::<Vec<_>>();
        let stages = serde_json::to_value(self.plumtree.stage_stats()).unwrap_or_default();
        let rows = stages["outbound_by_topic"]
            .as_object()
            .map(|rows| {
                rows.iter()
                    .map(|(id, counters)| {
                        let matching = subscribed
                            .iter()
                            .filter(|(_, topic)| topic == id)
                            .map(|(name, _)| name.clone())
                            .collect::<Vec<_>>();
                        serde_json::json!({
                            "topic_id_hex8": id,
                            "name": matching.first().map(String::as_str).unwrap_or("unknown-hex"),
                            "names": matching,
                            "outbound": counters,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let meter = self
            .egress_meter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        serde_json::json!({
            "subscribed_topics": topics,
            "outbound_by_topic_named": rows,
            "egress_budget": {
                "leaf_max_eager_degree": self.egress_config.leaf_max_eager_degree,
                "leaf_egress_soft_bytes_per_sec": self.egress_config.leaf_egress_soft_bytes_per_sec,
                "leaf_egress_hard_bytes_per_sec": self.egress_config.leaf_egress_hard_bytes_per_sec,
                "applies_to_leaf": !self.participation.forwards_passthrough(),
                "sustained_cap_status": "experimental: pinned sg draft #51 ceiling; publication and full acceptance pending",
                "byte_policy": "observe_only",
                "window_secs": 60,
                "sample_age_secs": meter.sampled_at.map(|at| at.elapsed().as_secs_f64()),
                "subscribed_outbound_bytes_per_sec_60s": meter.rate,
                "egress_budget_soft_exceeded": meter.soft_exceeded,
                "egress_budget_hard_exceeded": meter.hard_exceeded,
                "exceed_count_unit": "runtime samples above threshold (nominally 1s)",
                "rate_semantics": "1s sampled subscribed-topic send-attempt bytes, all kinds including repair; 60s denominator including warm-up",
                "per_topic_meter_limit": "sg may omit topics beyond its bounded meter; rate is observed bytes, not a hard bound",
                "repair": {
                    "tracking_overflow": self.transport.repair_tracking_overflow.load(Ordering::Relaxed),
                    "iwant_matched_eager_attempt_msgs": self.transport.repair_msgs.load(Ordering::Relaxed),
                    "iwant_matched_eager_attempt_bytes": self.transport.repair_bytes.load(Ordering::Relaxed),
                    "semantics": "subset of eager counters matching authenticated v2 in-flight IWANT peer/topic/message IDs; includes coincident same-message forwards, not confirmed delivery; anti_entropy stays separate"
                }
            }
        })
    }

    /// Outer saorsa-gossip signature policy for `GET /diagnostics/gossip`.
    ///
    /// Explicit string mapping (not `Debug`) so operators and harnesses can
    /// assert the modern-only RejectV1 boundary without parsing Rust enums.
    #[must_use]
    pub fn outer_signature_policy(&self) -> &'static str {
        match self.plumtree.signature_policy() {
            SignaturePolicy::RejectV1 => "reject_v1",
            SignaturePolicy::AcceptV1 => "accept_v1",
        }
    }

    /// Cumulative outer v1 (header-only-signed) receipts since startup.
    ///
    /// Counts rejected frames under RejectV1 as well — evidence of contact
    /// with the sunset boundary, not acceptance.
    #[must_use]
    pub fn outer_v1_receipts(&self) -> u64 {
        self.plumtree.v1_receipt_count()
    }

    /// Snapshot of Leaf vs Full participation for `GET /diagnostics/gossip`.
    #[must_use]
    pub fn participation_snapshot(&self) -> ParticipationSnapshot {
        let runs = self.passthrough_refresh_runs.load(Ordering::Relaxed);
        let metering = self.relay_metering();
        ParticipationSnapshot {
            mode: self.participation,
            reason: self.participation_reason.clone(),
            passthrough_refresh_runs: runs,
            passthrough_refresh_ran: runs > 0,
            unsubscribed_refused_frames: self.unsubscribed_refused_frames.load(Ordering::Relaxed),
            unsubscribed_refused_bytes: self.unsubscribed_refused_bytes.load(Ordering::Relaxed),
            unsubscribed_refused_graft_equiv: self
                .unsubscribed_refused_graft_equiv
                .load(Ordering::Relaxed),
            relay_bytes: metering.relay_bytes,
            relay_msgs: metering.relay_msgs,
            epidemic_forward_bytes: metering.epidemic_forward_bytes,
            epidemic_forward_msgs: metering.epidemic_forward_msgs,
            relay_bytes_semantics: RELAY_BYTES_SEMANTICS,
        }
    }

    fn subscribed_topic_keys(&self) -> HashSet<String> {
        self.subscribed_topic_ids
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn relay_metering(&self) -> super::participation::RelayMetering {
        let stages = serde_json::to_value(self.plumtree.stage_stats()).unwrap_or_default();
        classify_outbound_relay_json(
            stages
                .get("outbound_by_topic")
                .unwrap_or(&serde_json::Value::Null),
            &self.subscribed_topic_keys(),
        )
    }

    /// Snapshot of drop-detection counters for the gossip pipeline.
    ///
    /// Surfaced at `GET /diagnostics/gossip` — deltas between stages are the
    /// drop signal the test harness uses to prove 100 % delivery under load.
    pub fn stats(&self) -> PubSubStatsSnapshot {
        self.stats.snapshot()
    }

    /// Record a `fan_out == 0` publish and return whether to `warn!`.
    ///
    /// Increments [`PubSubStats::publish_zero_fanout`]. Skips the warn when
    /// `peer_count == 0` (solo / first-node). Otherwise rate-limits to once
    /// per group per 30s cooldown window.
    #[must_use]
    pub fn observe_zero_fanout(&self, group_id: &str, fan_out: u32, peer_count: usize) -> bool {
        let mut last = self
            .zero_fanout_warns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observe_zero_fanout_publish(
            &self.stats,
            &mut last,
            group_id,
            fan_out,
            peer_count,
            Instant::now(),
            ZERO_FANOUT_WARN_WINDOW,
        )
    }

    /// Test hook: report `fan_out` instead of the PlumTree eager-peer count.
    #[cfg(test)]
    pub fn set_fanout_report_override(&self, fan_out: Option<u32>) {
        *self
            .fanout_report_override
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = fan_out;
    }

    #[cfg(test)]
    fn apply_fanout_override(&self, fan_out: u32) -> u32 {
        self.fanout_report_override
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .unwrap_or(fan_out)
    }

    /// Snapshot of low-level PlumTree PubSub stage timings.
    ///
    /// Surfaced at `GET /diagnostics/gossip` so soak runs can identify which
    /// phase of inbound PubSub handling owns dispatcher wall-clock time.
    pub fn stage_stats(&self) -> saorsa_gossip_pubsub::PubSubStageStatsSnapshot {
        self.plumtree.stage_stats()
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
    /// Attach the authoritative gossiped revocation set (issue #191).
    ///
    /// When set, payloads delivered via the subscribe path whose sender is in
    /// the revocation set are dropped before reaching subscribers — closing
    /// the window between a gossiped revocation arriving and the eviction
    /// loop setting `trust = Blocked`. Call once after construction; a second
    /// call is a no-op (first caller wins), matching `set_contacts`.
    pub fn set_revocation_set(
        &self,
        set: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    ) {
        let _ = self.revocation_set.set(set);
    }

    /// Subscribe to a topic.
    ///
    /// Creates a new subscription to receive messages published to the
    /// given topic. The subscription is canceled when the returned
    /// `Subscription` is dropped.
    pub async fn subscribe(&self, topic: String) -> Subscription {
        let topic_id = TopicId::from_entity(topic.as_bytes());
        self.subscribe_topic_id(topic, topic_id).await
    }

    /// Subscribe to a topic with an explicit transport `TopicId`.
    ///
    /// Most callers use [`Self::subscribe`], which derives the transport id
    /// from the topic string. DM inbox topics are specified as raw
    /// domain-separated `TopicId`s, while still carrying a stable string topic
    /// name inside the signed x0x payload.
    pub async fn subscribe_topic_id(&self, topic: String, topic_id: TopicId) -> Subscription {
        // `local:` topics never touch PlumTree — same-daemon delivery only
        // (issue #89).
        if is_local_topic(&topic) {
            let (tx, rx) = mpsc::channel(10_000);
            self.local_topics
                .write()
                .await
                .entry(topic.clone())
                .or_default()
                .push(tx);
            {
                let mut counts = self.topic_ref_counts.write().await;
                *counts.entry(topic.clone()).or_insert(0) += 1;
            }
            return Subscription {
                topic,
                topic_id: None,
                receiver: rx,
                topic_ref_counts: Arc::clone(&self.topic_ref_counts),
                topic_id_by_name: Arc::clone(&self.topic_id_by_name),
                subscribed_topic_ids: Arc::clone(&self.subscribed_topic_ids),
            };
        }

        self.register_dynamic_topic_priority(&topic, topic_id);
        self.initialize_topic_peers(topic_id).await;

        let mut plumtree_rx = self.plumtree.subscribe(topic_id);
        // Plumtree registers subscribers on a spawned task; yield once so
        // immediate local publishes in the same task see this subscriber.
        tokio::task::yield_now().await;
        let (tx, rx) = mpsc::channel(10_000);
        let contacts = self.contacts.get().cloned();
        let revocation_set = self.revocation_set.get().cloned();

        {
            let mut counts = self.topic_ref_counts.write().await;
            *counts.entry(topic.clone()).or_insert(0) += 1;
        }
        self.topic_id_by_name
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(topic.clone(), topic_id);
        self.subscribed_topic_ids
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(topic_id);
        // ADR-0034 / #397 (Leaf C0): a Leaf node REFUSES inbound frames —
        // including anti-entropy — for unsubscribed topics, so a topic that
        // was unsubscribed for a while has no passively-repaired state to
        // rejoin. Trigger an explicit anti-entropy round on (re)subscribe so
        // catch-up is a property of the subscribe path itself, not a hope
        // that background repair happens to run. Best-effort: failure only
        // delays convergence to the next periodic round.
        {
            let plumtree = Arc::clone(&self.plumtree);
            tokio::spawn(async move {
                if let Err(e) = plumtree.trigger_anti_entropy(topic_id).await {
                    tracing::debug!("subscribe-time anti-entropy trigger failed: {e}");
                }
            });
        }

        let sub_topic = topic.clone();
        let stats = Arc::clone(&self.stats);
        tokio::spawn(async move {
            loop {
                let received = tokio::select! {
                    // The subscriber dropping its receiver must end this
                    // forwarding task PROMPTLY, even on a forever-quiet
                    // topic — parking on recv() alone only notices the
                    // closed downstream when the next message arrives, so
                    // every discarded subscription would pin a task and its
                    // PlumTree registration indefinitely (issue #238
                    // round-5 review: registration rollbacks on unique
                    // topics leaked these unboundedly). Both arms are
                    // cancel-safe.
                    () = tx.closed() => {
                        stats
                            .subscriber_channel_closed
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            topic = %sub_topic,
                            "[4/6 pubsub] subscriber receiver dropped — ending forwarding task"
                        );
                        return;
                    }
                    received = plumtree_rx.recv() => received,
                };
                let Some((_peer, encoded_payload)) = received else {
                    return;
                };
                stats.incoming_total.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    topic = %sub_topic,
                    payload_len = encoded_payload.len(),
                    "[4/6 pubsub] received from PlumTree, decoding"
                );
                let Some(message) = decode_for_delivery(
                    encoded_payload,
                    contacts.as_ref(),
                    revocation_set.as_ref(),
                )
                .await
                else {
                    stats.incoming_decode_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        topic = %sub_topic,
                        "[4/6 pubsub] decode_for_delivery returned None, skipping"
                    );
                    continue;
                };
                stats.incoming_decoded.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    topic = %sub_topic,
                    msg_topic = %message.topic,
                    "[4/6 pubsub] decoded, forwarding to subscriber channel"
                );
                match tx.try_send(message) {
                    Ok(()) => {
                        stats
                            .delivered_to_subscriber
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        stats
                            .slow_subscriber_dropped
                            .fetch_add(1, Ordering::Relaxed);
                        stats
                            .subscriber_channel_closed
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            topic = %sub_topic,
                            "[4/6 pubsub] subscriber channel full — dropping slow subscriber"
                        );
                        break;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        stats
                            .subscriber_channel_closed
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::info!(topic = %sub_topic, "[4/6 pubsub] subscriber channel closed");
                        break;
                    }
                }
            }
        });

        Subscription {
            topic,
            topic_id: Some(topic_id),
            receiver: rx,
            topic_ref_counts: self.topic_ref_counts.clone(),
            topic_id_by_name: Arc::clone(&self.topic_id_by_name),
            subscribed_topic_ids: Arc::clone(&self.subscribed_topic_ids),
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
        self.publish_with_fanout(topic, payload).await.map(|_| ())
    }

    /// Publish to a topic and return the eager-peer fan-out count.
    ///
    /// `0` means PlumTree handed the message to no remote eager peers
    /// (solo node, or every eligible peer cooled/excluded). Local ledger
    /// writes are a separate fact — this count is delivery opportunity.
    pub async fn publish_with_fanout(&self, topic: String, payload: Bytes) -> NetworkResult<u32> {
        let topic_id = TopicId::from_entity(topic.as_bytes());
        Ok(self
            .publish_topic_id_with_fanout_and_envelope(topic, topic_id, payload, SignedVersion::V2)
            .await?
            .fan_out)
    }

    /// Publish to a topic and return the signed V2 envelope bytes when
    /// signing is enabled.
    ///
    /// ADR 0028: the authority relays the requester-authored predecessor
    /// envelope unchanged to active witnesses. The caller needs the exact V2
    /// wire bytes (including the requester's ML-DSA-65 signature) to offer to
    /// the authority for relay. Returns `None` for v1 (unsigned) publishes.
    pub async fn publish_and_get_envelope(
        &self,
        topic: String,
        payload: Bytes,
    ) -> NetworkResult<Option<Bytes>> {
        let topic_id = TopicId::from_entity(topic.as_bytes());
        self.publish_topic_id_with_envelope(topic, topic_id, payload)
            .await
    }

    /// Publish to a topic with an explicit transport `TopicId`.
    ///
    /// The signed x0x payload still embeds `topic`; only the underlying
    /// PlumTree topic id is supplied by the caller.
    pub async fn publish_topic_id(
        &self,
        topic: String,
        topic_id: TopicId,
        payload: Bytes,
    ) -> NetworkResult<()> {
        self.publish_topic_id_with_envelope(topic, topic_id, payload)
            .await
            .map(|_| ())
    }

    /// Publish to a topic with an explicit transport `TopicId`, returning the
    /// signed V2 envelope bytes when signing is enabled.
    ///
    /// The signed x0x payload still embeds `topic`; only the underlying
    /// PlumTree topic id is supplied by the caller.
    pub async fn publish_topic_id_with_envelope(
        &self,
        topic: String,
        topic_id: TopicId,
        payload: Bytes,
    ) -> NetworkResult<Option<Bytes>> {
        self.publish_topic_id_with_fanout_and_envelope(topic, topic_id, payload, SignedVersion::V2)
            .await
            .map(|outcome| outcome.envelope)
    }

    /// Publish a topic-bound V3 inner envelope for the Signed KV pairing.
    ///
    /// This requires an author signing context and a network topic. It never
    /// falls back to V2 or unsigned local delivery. It does not register a
    /// compatibility topic, issue a grant, or enable legacy transport. Callers
    /// must separately establish the Signed policy and audited receive/apply
    /// path before adoption (ADR-0063). Existing publishers remain on V2.
    pub async fn publish_signed_kv_v3(
        &self,
        topic: String,
        payload: Bytes,
    ) -> NetworkResult<Bytes> {
        if self.signing.is_none() || is_local_topic(&topic) {
            return Err(NetworkError::SerializationError(
                "Signed KV V3 requires signing and a network topic".to_string(),
            ));
        }
        let topic_id = TopicId::from_entity(topic.as_bytes());
        self.publish_topic_id_with_fanout_and_envelope(topic, topic_id, payload, SignedVersion::V3)
            .await?
            .envelope
            .ok_or_else(|| NetworkError::SerializationError("Missing V3 envelope".to_string()))
    }

    /// Publish and return both the signed envelope (when signing) and the
    /// eager-peer fan-out count from PlumTree `publish_local`.
    async fn publish_topic_id_with_fanout_and_envelope(
        &self,
        topic: String,
        topic_id: TopicId,
        payload: Bytes,
        version: SignedVersion,
    ) -> NetworkResult<PublishFanoutOutcome> {
        // `local:` topics fan out to same-daemon subscribers only — the
        // payload never reaches PlumTree or any remote peer (issue #89).
        if is_local_topic(&topic) {
            self.publish_local(topic, payload).await?;
            return Ok(PublishFanoutOutcome {
                fan_out: 0,
                envelope: None,
            });
        }

        let (encoded, envelope_bytes) = if let Some(ref ctx) = self.signing {
            let result = version
                .signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload)
                .and_then(|signing_payload| ctx.sign(&signing_payload))
                .and_then(|signature| {
                    encode_signed(
                        version,
                        &ctx.agent_id,
                        &ctx.public_key_bytes,
                        &signature,
                        &topic,
                        &payload,
                    )
                });
            match result {
                Ok(encoded) => {
                    let envelope = Bytes::clone(&encoded);
                    (encoded, Some(envelope))
                }
                Err(err) => {
                    self.stats.publish_failed.fetch_add(1, Ordering::Relaxed);
                    return Err(err);
                }
            }
        } else {
            let encoded = encode_v1(&topic, &payload)?;
            (encoded, None)
        };

        self.register_dynamic_topic_priority(&topic, topic_id);
        self.initialize_topic_peers(topic_id).await;

        match self.plumtree.publish_with_fanout(topic_id, encoded).await {
            Ok(counts) => {
                self.stats.publish_total.fetch_add(1, Ordering::Relaxed);
                let attempted = counts.map(|c| c.attempted).unwrap_or(0);
                let fan_out = u32::try_from(attempted).unwrap_or(u32::MAX);
                #[cfg(test)]
                let fan_out = self.apply_fanout_override(fan_out);
                Ok(PublishFanoutOutcome {
                    fan_out,
                    envelope: envelope_bytes,
                })
            }
            Err(e) => {
                self.stats.publish_failed.fetch_add(1, Ordering::Relaxed);
                Err(NetworkError::ConnectionFailed(format!(
                    "PlumTree publish failed: {e}"
                )))
            }
        }
    }

    /// Fan out a `local:` publish to same-daemon subscribers only.
    ///
    /// The payload never reaches PlumTree or any remote peer (issue #89). The
    /// `Full` vs `Closed` arms encode the slow-subscriber-drop behaviour:
    /// `Full` keeps the subscriber (the message is dropped, not the queue),
    /// `Closed` evicts it.
    async fn publish_local(&self, topic: String, payload: Bytes) -> NetworkResult<()> {
        let message = PubSubMessage {
            topic: topic.clone(),
            payload,
            sender: self.signing.as_ref().map(|ctx| ctx.agent_id),
            sender_public_key: self
                .signing
                .as_ref()
                .map(|ctx| ctx.public_key_bytes.clone()),
            // Local publishes come from a bearer-token-authenticated
            // API caller on this daemon — trusted by construction.
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        let mut topics = self.local_topics.write().await;
        if let Some(senders) = topics.get_mut(&topic) {
            senders.retain(|tx| match tx.try_send(message.clone()) {
                Ok(()) => {
                    self.stats
                        .delivered_to_subscriber
                        .fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stats
                        .slow_subscriber_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            });
        }
        self.stats.publish_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Handle an incoming message from a peer.
    ///
    /// Leaf (#380 C0): refuse GRAFT-equivalent / eager / IHAVE / IWANT /
    /// anti-entropy frames for topics this node does not subscribe to, so
    /// PlumTree never creates pass-through state or eager-forwards them.
    /// Full nodes keep today's `handle_message` behaviour.
    pub async fn handle_incoming(&self, peer: PeerId, data: Bytes) {
        self.ensure_eager_ceiling().await;
        if self.refuse_leaf_unsubscribed_passthrough(&data) {
            return;
        }
        let _repair_scope =
            if peek_pubsub_header(&data).is_some_and(|header| header.kind == MessageKind::IWant) {
                self.transport.track_iwant(peer, &data)
            } else {
                None
            };
        if let Err(e) = self.plumtree.handle_message(peer, data).await {
            tracing::warn!(
                "Failed to handle PlumTree pubsub message from {}: {e}",
                crate::logging::LogPeerId::from(peer)
            );
        }
    }

    fn refuse_leaf_unsubscribed_passthrough(&self, data: &[u8]) -> bool {
        let Some(header) = peek_pubsub_header(data) else {
            return false;
        };
        let subscribed = self
            .subscribed_topic_ids
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&header.topic);
        if !leaf_refuses_unsubscribed_passthrough(self.participation, subscribed, header.kind) {
            return false;
        }
        self.unsubscribed_refused_frames
            .fetch_add(1, Ordering::Relaxed);
        self.unsubscribed_refused_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        if matches!(
            header.kind,
            MessageKind::Eager | MessageKind::IHave | MessageKind::IWant
        ) {
            self.unsubscribed_refused_graft_equiv
                .fetch_add(1, Ordering::Relaxed);
        }
        tracing::debug!(
            topic = %header.topic,
            kind = ?header.kind,
            bytes = data.len(),
            "Leaf refused unsubscribed PlumTree pass-through frame (#380 C0)"
        );
        true
    }

    /// Get the number of active subscriptions (topics with at least one subscriber).
    pub async fn subscription_count(&self) -> usize {
        self.topic_ref_counts.read().await.len()
    }

    /// Unsubscribe from a topic, removing all subscriptions.
    pub async fn unsubscribe(&self, topic: &str) {
        self.topic_ref_counts.write().await.remove(topic);
        if is_local_topic(topic) {
            self.local_topics.write().await.remove(topic);
            return;
        }
        let stored_id = self
            .topic_id_by_name
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(topic);
        let topic_id = stored_id.unwrap_or_else(|| TopicId::from_entity(topic.as_bytes()));
        self.subscribed_topic_ids
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&topic_id);
        if let Err(e) = self.plumtree.unsubscribe(topic_id).await {
            tracing::debug!("PlumTree unsubscribe failed for topic '{topic}': {e}");
        }
    }

    /// Re-initialize PlumTree peers for all locally subscribed topics.
    ///
    /// This ensures that newly connected peers are added to the eager set
    /// for existing topics. Without this, a peer that connects after a topic
    /// is subscribed would never receive messages on that topic from this node.
    pub async fn refresh_topic_peers(&self) {
        // Issue #206: plane-gated peer view — only plane-cleared peers may
        // enter PlumTree eager sets.
        let peers: Vec<PeerId> = self.transport.connected_peer_ids().await;

        // Refresh locally subscribed topics.
        let subscribed: Vec<String> = self.topic_ref_counts.read().await.keys().cloned().collect();
        if !peers.is_empty() && !subscribed.is_empty() {
            tracing::debug!(
                "[4/6 pubsub] refresh_topic_peers: {} connected peers, {} subscribed topics",
                peers.len(),
                subscribed.len()
            );
        }
        let subscribed_ids: HashSet<TopicId> = self
            .subscribed_topic_ids
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for topic_id in &subscribed_ids {
            self.apply_topic_peers(*topic_id, peers.clone()).await;
        }

        // Full (bootstrap / relay / `--relay`): also refresh pass-through
        // topics (known to PlumTree but without local subscribers) so this
        // node forwards. Leaf (ordinary desktop): skip — unsubscribed topics
        // must not expand eager sets here (issue #380).
        if !self.participation.forwards_passthrough() {
            return;
        }
        self.passthrough_refresh_runs
            .fetch_add(1, Ordering::Relaxed);

        let all_plumtree_topics = self.known_plumtree_topics().await;
        for topic_id in all_plumtree_topics {
            if !subscribed_ids.contains(&topic_id) {
                self.apply_topic_peers(topic_id, peers.clone()).await;
            }
        }
    }

    async fn apply_topic_peers(&self, topic_id: TopicId, peers: Vec<PeerId>) {
        self.ensure_eager_ceiling().await;
        #[cfg(test)]
        self.refreshed_topic_ids
            .lock()
            .expect("refresh log")
            .push(topic_id);
        let peers = self.ordered_topic_peers(peers).await;
        self.plumtree.set_topic_peers(topic_id, peers).await;
    }

    async fn known_plumtree_topics(&self) -> Vec<TopicId> {
        #[cfg(test)]
        {
            if let Some(topics) = self
                .known_topic_override
                .lock()
                .expect("topic override")
                .clone()
            {
                return topics;
            }
        }
        self.plumtree.all_topic_ids().await
    }

    #[cfg(test)]
    fn take_refreshed_topic_ids(&self) -> Vec<TopicId> {
        std::mem::take(&mut *self.refreshed_topic_ids.lock().expect("refresh log"))
    }

    #[cfg(test)]
    fn set_known_plumtree_topics_for_test(&self, topics: Vec<TopicId>) {
        *self.known_topic_override.lock().expect("topic override") = Some(topics);
    }

    /// X0X-0074: classify a dynamic topic name and register it with the
    /// admission control registry. Idempotent — re-registering with the
    /// same priority is a no-op; re-registering with a different priority
    /// overwrites (the runtime should never do that for production
    /// topics, but the registry handles it gracefully).
    ///
    /// Called on subscribe + publish entry points. The static x0x topic
    /// set is seeded at construction; this path covers sharded topics
    /// (`x0x.identity.shard.v2.<u16>`), DM-inbox topics (per-recipient
    /// hashes), release manifests, and any custom application topic.
    fn register_dynamic_topic_priority(&self, topic_name: &str, topic_id: TopicId) {
        let priority = classify_x0x_topic(topic_name);
        self.plumtree
            .admission()
            .registry()
            .register(topic_id, priority);
    }

    /// Initialize PlumTree peers for a topic from currently connected peers.
    async fn initialize_topic_peers(&self, topic: TopicId) {
        self.ensure_eager_ceiling().await;
        // Issue #206: plane-gated peer view (see refresh_topic_peers).
        let peers: Vec<PeerId> = self.transport.connected_peer_ids().await;
        let peers = self.ordered_topic_peers(peers).await;
        self.plumtree.initialize_topic_peers(topic, peers).await;
    }

    /// Refresh PlumTree eager-set peers for one topic id via the
    /// subscribed-topic path (`initialize_topic_peers` + `set_topic_peers`).
    ///
    /// Leaf-safe: does not walk unsubscribed pass-through topics and does
    /// not change [`Self::refresh_topic_peers`]. Used to pre-warm reverse
    /// ACK topics so the first durable send is not the join event (#380 C2).
    pub(crate) async fn refresh_subscribed_topic_id(&self, topic: &str, topic_id: TopicId) {
        self.register_dynamic_topic_priority(topic, topic_id);
        self.initialize_topic_peers(topic_id).await;
        let peers: Vec<PeerId> = self.transport.connected_peer_ids().await;
        self.apply_topic_peers(topic_id, peers).await;
    }

    /// C5b: prefer one connected Full/bootstrap peer at the front of the
    /// eager set for the given topics (durable ACK inbox + bus only).
    ///
    /// Does not walk unsubscribed pass-through topics and does not re-enable
    /// GRAFT piggyback on topics the node is not subscribed to (C0).
    pub async fn prefer_one_full_bootstrap_eager(&self, topic_ids: &[TopicId]) {
        if topic_ids.is_empty() {
            return;
        }
        let plane: Vec<[u8; 32]> = self
            .transport
            .connected_peer_ids()
            .await
            .into_iter()
            .map(|peer| *peer.as_bytes())
            .collect();
        self.apply_preferred_eager_peer(plane, topic_ids).await;
    }

    /// Pre-subscribe a topic id (C4) so the first later `publish_topic_id`
    /// is not the PlumTree join. Idempotent. Leaf-safe: uses
    /// [`Self::subscribe_topic_id`] (subscribed path) and does not walk
    /// pass-through topics.
    ///
    /// #396 race fix: the original check-then-insert ran the refcount READ,
    /// the subscribe, and the holds INSERT under separate lock acquisitions.
    /// Two concurrent warmers (outbound `maybe_warm_reverse_ack_topics` on
    /// Direct connect vs inbound `PeerConnected`) could both observe "no
    /// refcount", both `subscribe_topic_id`, and both spawn a permanent
    /// drain hold — a leaked duplicate subscription plus a duplicate drain
    /// task per topic, forever. The refcount write inside
    /// `subscribe_topic_id` is the linearization point: we take the holds
    /// WRITE lock FIRST and re-check the refcount while holding it, so
    /// exactly one warmer ever creates a hold per topic; the loser sees the
    /// winner's refcount and only refreshes. (The write guard is held
    /// across `subscribe_topic_id`'s awaits — acceptable because warmers
    /// target three topics, the map is tiny, and readers
    /// (`shutdown`/drop-abort) tolerate brief writer hold.)
    pub(crate) async fn ensure_subscribed_topic_id(&self, topic: &str, topic_id: TopicId) {
        // Serialize hold creation per manager: the guard is released on
        // return, and the double-check below makes duplicate concurrent
        // calls converge to one hold.
        let mut holds = self.membership_holds.write().await;
        if self.topic_ref_counts.read().await.contains_key(topic) {
            drop(holds);
            self.refresh_subscribed_topic_id(topic, topic_id).await;
            return;
        }
        // Re-check under the same guard ordering used by the fast path:
        // another warmer may have inserted between our lock acquisition
        // and here is impossible (we hold the write lock), but the
        // refcount read above may have raced the winner's subscribe —
        // the definitive check is the holds map itself.
        if holds.contains_key(topic) {
            drop(holds);
            self.refresh_subscribed_topic_id(topic, topic_id).await;
            return;
        }
        let mut sub = self.subscribe_topic_id(topic.to_string(), topic_id).await;
        let hold = tokio::spawn(async move { while sub.recv().await.is_some() {} });
        holds.insert(topic.to_string(), hold);
        drop(holds);
        self.refresh_subscribed_topic_id(topic, topic_id).await;
    }

    /// Topic ids currently known to PlumTree. Test helper for proving a
    /// warm joined the real inbox ids, not name-derived pass-through ids.
    #[cfg(test)]
    pub(crate) async fn plumtree_topic_ids(&self) -> Vec<TopicId> {
        self.plumtree.all_topic_ids().await
    }

    /// Whether `topic` currently has a local subscriber (C4 pre-join).
    #[cfg(test)]
    pub(crate) async fn is_topic_subscribed(&self, topic: &str) -> bool {
        self.topic_ref_counts.read().await.contains_key(topic)
    }

    /// Number of live membership-hold drain tasks (C4). Test helper for the
    /// #396 concurrent-warmer race: exactly one hold may exist per topic.
    #[cfg(test)]
    pub(crate) async fn membership_hold_count(&self) -> usize {
        self.membership_holds.read().await.len()
    }

    /// C5b continuation: pick the preferred eager peer and apply it to the
    /// ACK topics only (called by [`Self::prefer_one_full_bootstrap_eager`]).
    async fn apply_preferred_eager_peer(&self, plane: Vec<[u8; 32]>, topic_ids: &[TopicId]) {
        let peers = plane.into_iter().map(PeerId::new).collect::<Vec<_>>();
        for topic_id in topic_ids {
            self.apply_topic_peers(*topic_id, peers.clone()).await;
        }
    }

    /// One policy for every initializer/overwrite. Keep the full transport plane
    /// as the source on each refresh so disconnected selected peers are replaced.
    async fn ordered_topic_peers(&self, peers: Vec<PeerId>) -> Vec<PeerId> {
        let mut coordinators = Vec::new();
        let mut relays = Vec::new();
        if let Some(cache) = self.network.bootstrap_cache() {
            // Fetch all candidates before tie-breaking. Truncating a HashMap-
            // derived candidate list to six first would make the choice flap.
            coordinators = cache
                .select_coordinators(usize::MAX)
                .await
                .into_iter()
                .filter(|peer| peer.capabilities.supports_coordination)
                .map(|peer| peer.peer_id.0)
                .collect();
            relays = cache
                .select_relay_peers(usize::MAX)
                .await
                .into_iter()
                .filter(|peer| peer.capabilities.supports_relay)
                .map(|peer| peer.peer_id.0)
                .collect();
        }
        ordered_leaf_peers(
            peers,
            &coordinators,
            &relays,
            &self.network.config().pinned_bootstrap_peers,
            if self.participation.forwards_passthrough() {
                0
            } else {
                self.egress_config.leaf_max_eager_degree
            },
        )
    }
}

fn ordered_leaf_peers(
    mut peers: Vec<PeerId>,
    coordinators: &[[u8; 32]],
    relays: &[[u8; 32]],
    pinned: &HashSet<[u8; 32]>,
    degree: usize,
) -> Vec<PeerId> {
    peers.sort_by_key(|peer| *peer.as_bytes());
    peers.dedup();
    let plane = peers
        .iter()
        .map(|peer| *peer.as_bytes())
        .collect::<Vec<_>>();
    if let Some(preferred) =
        select_one_full_bootstrap_eager_peer(&plane, coordinators, relays, pinned)
    {
        peers.retain(|peer| peer.as_bytes() != &preferred);
        peers.insert(0, PeerId::new(preferred));
    }
    if degree != 0 {
        peers.truncate(degree);
    }
    peers
}

/// Pick at most one connected Full/bootstrap peer for ACK-topic eager.
///
/// Order: coordinators, then relays, then pinned bootstrap IDs. Returns
/// `None` when the plane has no such peer; the Leaf policy then uses the
/// sorted eligible plane without a preferred slot. Ties use the full PeerId.
pub(crate) fn select_one_full_bootstrap_eager_peer(
    plane: &[[u8; 32]],
    coordinators: &[[u8; 32]],
    relays: &[[u8; 32]],
    pinned: &std::collections::HashSet<[u8; 32]>,
) -> Option<[u8; 32]> {
    let connected: std::collections::HashSet<[u8; 32]> = plane.iter().copied().collect();
    coordinators
        .iter()
        .filter(|id| connected.contains(*id))
        .min()
        .copied()
        .or_else(|| {
            relays
                .iter()
                .filter(|id| connected.contains(*id))
                .min()
                .copied()
        })
        .or_else(|| plane.iter().copied().filter(|id| pinned.contains(id)).min())
}

/// Decode and filter a delivered payload before exposing it to x0x subscribers.
///
/// Revocation is checked against the authoritative gossiped `RevocationSet`
/// (issue #191) before the operator-local `ContactStore`, so a gossiped
/// issuer/agent revocation closes delivery even before the eviction loop sets
/// `trust = Blocked`.
async fn decode_for_delivery(
    encoded_payload: Bytes,
    contacts: Option<&Arc<RwLock<ContactStore>>>,
    revocation_set: Option<&Arc<RwLock<crate::revocation::RevocationSet>>>,
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
    // Authoritative gossiped revocation set (issue #191). Checked before the
    // ContactStore below, which is operator-local only — without this a
    // gossiped revocation reaches delivery only once the eviction loop has
    // set trust = Blocked (a race reopens it).
    if let (Some(rev_set), Some(sender)) = (revocation_set, message.sender) {
        if rev_set.read().await.is_agent_revoked(&sender) {
            tracing::debug!(
                "Dropping delivered payload from revoked sender {} (RevocationSet)",
                sender
            );
            return None;
        }
    }

    if let (Some(store), Some(sender)) = (contacts, message.sender) {
        let guard = store.read().await;
        // Check revocation first — revoked keys are permanently rejected.
        if guard.is_revoked(&sender) {
            tracing::debug!("Dropping delivered payload from revoked sender {}", sender);
            return None;
        }
        let trust = guard.trust_level(&sender);
        drop(guard);
        if trust == TrustLevel::Blocked {
            tracing::debug!("Dropping delivered payload from blocked sender {}", sender);
            return None;
        }
        message.trust_level = Some(trust);
    }

    Some(message)
}

// ---------------------------------------------------------------------------
// X0X-0074 — topic priority classification
// ---------------------------------------------------------------------------

/// Topic-name fragments that classify production x0x topics into admission
/// priority bands. Topics not matching any prefix here default to
/// `TopicPriority::Normal` via the registry.
///
/// Matching is `starts_with` against the topic name string (the value
/// applications pass to `PubSubManager::publish` / `subscribe`, before
/// `TopicId::from_entity` hashes it). x0x's production topic set mixes
/// two naming conventions:
///   - **Slash-separated** (path style): `x0x/dm/v1/bus`, `x0x/release`,
///     `x0x/caps/v1`. Used for DM bus, release manifests, capability
///     adverts.
///   - **Dot-separated**: `x0x.identity.shard.v2.<u16>`, `x0x.discovery.groups`,
///     etc. Used for identity/machine/user anti-entropy + discovery
///     shards.
///
/// Both shapes are listed below so the classifier matches what x0x
/// actually publishes. A previous version of this classifier had only
/// the dot-style prefixes, which caused DM bus and release manifests to
/// silently fall through to Normal in production (reviewer P1.2,
/// 2026-05-12).
const CRITICAL_TOPIC_PREFIXES: &[&str] = &[
    "x0x/dm/v1/", // DM bus + DM inbox (slash style — x0x/dm/v1/bus, x0x/dm/v1/inbox/...)
    "x0x.dm.",    // Reserved for any future dot-style DM topics
    "x0x.identity.announce.v2", // Identity announce — control-plane
    "x0x.test.discover.v1", // Test orchestrator discover (X0X-0076 harness)
    "x0x.test.control.v1", // Test orchestrator control commands
    // ADR 0030 strict-send capability refresh. These share the `x0x/caps/v1`
    // prefix with the Bulk steady advert topic, so they rely on Critical being
    // matched first: a strict send has a three-second convergence window and
    // cannot wait behind Bulk cooling.
    "x0x/caps/v1/request/targeted-v2",
    "x0x/caps/v1/response/targeted-v2",
];

const BULK_TOPIC_PREFIXES: &[&str] = &[
    "x0x.identity.shard.v2.",  // Identity anti-entropy shards
    "x0x.machine.shard.v2.",   // Machine anti-entropy shards
    "x0x.user.shard.v2.",      // User anti-entropy shards
    "x0x.machine.announce.v2", // Machine announce — bulk
    "x0x.user.announce.v2",    // User announce — bulk
    "x0x.discovery.groups",    // Global group discovery anti-entropy
    "x0x.directory.",          // Group directory tag/name/id shards (src/groups/discovery.rs)
    "x0x.rendezvous.shard",    // Rendezvous shard discovery
    "x0x/release",             // Release manifests (slash style — x0x/release)
    "x0x.release.",            // Reserved for any future dot-style release topics
    "x0x/caps/v1",             // Mesh-wide DM capability advert (5-min republish)
    "x0x/caps/v2/digest",      // #448 digest extension — same advert cadence, Bulk (r2)
    "x0x.group.cards",         // Group card anti-entropy
    "x0x.group.share.v2",      // Group share anti-entropy
];

/// Returns the X0X-0074 admission priority for an x0x topic name.
///
/// Matching is prefix-based against the priority lists above. Critical is
/// checked before Bulk so e.g. `x0x.test.discover.v1` lands on Critical
/// even though `x0x.test.` is a substring of other bulk topics. Anything
/// unmatched (presence, named-group fanout, public messages, custom app
/// topics) falls through to `TopicPriority::Normal`.
#[must_use]
pub fn classify_x0x_topic(topic_name: &str) -> TopicPriority {
    if CRITICAL_TOPIC_PREFIXES
        .iter()
        .any(|prefix| topic_name.starts_with(prefix))
    {
        return TopicPriority::Critical;
    }
    if BULK_TOPIC_PREFIXES
        .iter()
        .any(|prefix| topic_name.starts_with(prefix))
    {
        return TopicPriority::Bulk;
    }
    TopicPriority::Normal
}

/// Seed the topic-priority registry with x0x's production topic set.
///
/// Called once during `PubSubManager::new` so the admission gate has
/// correct priorities before any traffic flows. Application-side topics
/// (custom user topics, named-group fanout) are not pre-registered and
/// default to Normal admission — which is the safe default for traffic
/// the substrate doesn't have context on.
fn register_x0x_topic_priorities(
    registry: &saorsa_gossip_pubsub::admission::TopicPriorityRegistry,
) {
    use saorsa_gossip_types::TopicId;

    // Critical — DM bus + control plane + test orchestrator
    registry.register(
        TopicId::from_entity("x0x/dm/v1/bus".as_bytes()),
        TopicPriority::Critical,
    );
    registry.register(
        TopicId::from_entity("x0x.identity.announce.v2".as_bytes()),
        TopicPriority::Critical,
    );
    registry.register(
        TopicId::from_entity("x0x.test.discover.v1".as_bytes()),
        TopicPriority::Critical,
    );
    registry.register(
        TopicId::from_entity("x0x.test.control.v1".as_bytes()),
        TopicPriority::Critical,
    );
    registry.register(
        TopicId::from_entity("x0x/caps/v1/request/targeted-v2".as_bytes()),
        TopicPriority::Critical,
    );
    registry.register(
        TopicId::from_entity("x0x/caps/v1/response/targeted-v2".as_bytes()),
        TopicPriority::Critical,
    );
    // Per-recipient DM inbox topics (`x0x/dm/v1/inbox/<hash>`) are
    // dynamic — they're registered through `register_dynamic_topic_priority`
    // when the runtime subscribes to its own inbox. The prefix
    // `x0x/dm/v1/` in CRITICAL_TOPIC_PREFIXES catches them.

    // Bulk — fleet-wide anti-entropy + manifests + capability adverts
    registry.register(
        TopicId::from_entity("x0x.machine.announce.v2".as_bytes()),
        TopicPriority::Bulk,
    );
    registry.register(
        TopicId::from_entity("x0x.user.announce.v2".as_bytes()),
        TopicPriority::Bulk,
    );
    registry.register(
        TopicId::from_entity("x0x.discovery.groups".as_bytes()),
        TopicPriority::Bulk,
    );
    registry.register(
        TopicId::from_entity("x0x/release".as_bytes()),
        TopicPriority::Bulk,
    );
    registry.register(
        TopicId::from_entity("x0x/caps/v1".as_bytes()),
        TopicPriority::Bulk,
    );
    // Identity/Machine/User shards (`x0x.identity.shard.v2.<u16>`,
    // `x0x.machine.shard.v2.<u16>`, `x0x.user.shard.v2.<u16>`) + rendezvous
    // shards are dynamic per-shard topic names — they fall through
    // `register_dynamic_topic_priority` on first publish/subscribe.
    // Normal is the default for anything unregistered.
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

    if topic_len.to_be_bytes()[0] >= VERSION_V2 {
        return Err(NetworkError::SerializationError(
            "Unsigned topic length uses a reserved signed version byte".to_string(),
        ));
    }
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
        raw_envelope: None,
    })
}

// ---------------------------------------------------------------------------
// Wire formats: V2 and V3 (signed)
// ---------------------------------------------------------------------------

/// Encode a signed pub/sub message with an explicit version.
///
/// Format:
/// ```text
/// [version: 0x02 (V2) or 0x03 (V3)]
/// [sender_agent_id: 32 bytes]
/// [pubkey_len: u16_be] [sender_public_key: pubkey_len bytes]
/// [sig_len: u16_be]    [signature: sig_len bytes]
/// [topic_len: u16_be]  [topic_bytes: topic_len bytes]
/// [payload: remaining bytes]
/// ```
fn encode_signed(
    version: SignedVersion,
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
    if version == SignedVersion::V3 {
        validate_v3_bounds(total, public_key.len(), signature.len())?;
    }
    let mut buf = Vec::with_capacity(total);

    buf.push(version.byte());
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

/// Read a `u16_be` length-prefixed field at `*pos`, advancing the cursor past
/// both the prefix and the field.
///
/// Returns a borrowed slice of the field bytes. `what` names the field so the
/// per-field error diagnostics (`"Truncated <what> length"` / `"Truncated
/// <what>"`) match the original hand-written checks. Performs the two bounds
/// checks the v2 decoder relies on: that the length prefix is present, and
/// that the buffer holds the full claimed field.
fn take_lp<'a>(data: &'a [u8], pos: &mut usize, what: &str) -> NetworkResult<&'a [u8]> {
    if data.len() < *pos + 2 {
        return Err(NetworkError::SerializationError(format!(
            "Truncated {what} length"
        )));
    }
    let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    if data.len() < *pos + len {
        return Err(NetworkError::SerializationError(format!(
            "Truncated {what}"
        )));
    }
    let field = &data[*pos..*pos + len];
    *pos += len;
    Ok(field)
}

/// Decode a v2 (signed) message, verifying the ML-DSA-65 signature.
pub(crate) fn decode_v2(data: &[u8]) -> NetworkResult<PubSubMessage> {
    decode_signed(data, SignedVersion::V2)
}

/// Decode and authenticate the V3 inner envelope required by Signed KV compatibility.
///
/// Rejects V2, unsupported versions, and invalid signatures. Successful signature
/// verification is not store authorization: callers still enforce the concrete
/// topic, author roster, Signed ownership and state-request rules (ADR-0063).
pub fn decode_signed_kv_v3(data: &[u8]) -> NetworkResult<PubSubMessage> {
    if data.len() > MAX_V3_ENVELOPE_BYTES {
        return Err(NetworkError::SerializationError(
            "V3 envelope exceeds 1 MiB".to_string(),
        ));
    }
    let message = decode_signed(data, SignedVersion::V3)?;
    if !message.verified {
        return Err(NetworkError::SerializationError(
            "Invalid V3 signature".to_string(),
        ));
    }
    Ok(message)
}

fn validate_v3_bounds(total: usize, key_len: usize, sig_len: usize) -> NetworkResult<()> {
    if total > MAX_V3_ENVELOPE_BYTES {
        return Err(NetworkError::SerializationError(
            "V3 envelope exceeds 1 MiB".to_string(),
        ));
    }
    if key_len != ML_DSA_65_PUBKEY_LEN || sig_len != ML_DSA_65_SIG_LEN {
        return Err(NetworkError::SerializationError(
            "Invalid V3 ML-DSA-65 key or signature length".to_string(),
        ));
    }
    Ok(())
}

fn decode_signed(data: &[u8], version: SignedVersion) -> NetworkResult<PubSubMessage> {
    if data.first() != Some(&version.byte()) {
        return Err(NetworkError::SerializationError(
            "Unexpected signed message version".to_string(),
        ));
    }
    // Minimum: 1 (version) + 32 (agent_id) + 2 (pk_len) + 2 (sig_len) + 2 (topic_len)
    if data.len() < 39 {
        return Err(NetworkError::SerializationError(
            "Signed message too short".to_string(),
        ));
    }

    let mut pos = 1; // skip version byte

    // Agent ID (32 bytes)
    let mut agent_id_bytes = [0u8; 32];
    agent_id_bytes.copy_from_slice(&data[pos..pos + 32]);
    let agent_id = AgentId(agent_id_bytes);
    pos += 32;

    let public_key_bytes = take_lp(data, &mut pos, "public key").map_err(|e| match e {
        NetworkError::SerializationError(msg) if msg == "Truncated public key length" => {
            NetworkError::SerializationError("Truncated pubkey length".to_string())
        }
        other => other,
    })?;
    let public_key_bytes = public_key_bytes.to_vec();

    let signature_bytes = take_lp(data, &mut pos, "signature")?;
    if version == SignedVersion::V3 {
        validate_v3_bounds(data.len(), public_key_bytes.len(), signature_bytes.len())?;
    }

    let topic_bytes = take_lp(data, &mut pos, "topic")?;
    let topic = String::from_utf8(topic_bytes.to_vec())
        .map_err(|e| NetworkError::SerializationError(format!("Invalid UTF-8: {}", e)))?;

    // Payload (remaining bytes)
    let payload = Bytes::copy_from_slice(&data[pos..]);

    // Verify: reconstruct the public key and check the signature
    let verified = verify_signature(
        version,
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
        raw_envelope: Some(Bytes::copy_from_slice(data)),
    })
}

/// Auto-detect and decode a pub/sub message (v1, v2 or v3).
///
/// The first byte distinguishes the format:
/// - `0x02` → v2 (signed)
/// - `0x03` → v3 (topic-bound signed; never retried as V2 or V1)
/// - `0x00` or `0x01` → v1 (unsigned, where byte is high byte of topic_len)
/// - Higher bytes → unsupported version error
///
/// V1 has no version byte. Its encoder limits topics to 511 UTF-8 bytes;
/// Signed KV compatibility callers must use [`decode_signed_kv_v3`] directly.
pub fn decode_auto(data: Bytes) -> NetworkResult<PubSubMessage> {
    if data.is_empty() {
        return Err(NetworkError::SerializationError(
            "Empty message".to_string(),
        ));
    }

    match data[0] {
        VERSION_V2 => decode_v2(&data),
        VERSION_V3 => decode_signed_kv_v3(&data),
        0 | 1 => decode_v1(&data),
        version => Err(NetworkError::SerializationError(format!(
            "Unsupported x0x envelope version 0x{version:02x}"
        ))),
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
    version: SignedVersion,
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

    let Ok(signing_payload) = version.signing_payload(agent_id, topic, payload) else {
        return false;
    };

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

    fn encode_v2(
        agent_id: &AgentId,
        public_key: &[u8],
        signature: &[u8],
        topic: &str,
        payload: &Bytes,
    ) -> NetworkResult<Bytes> {
        encode_signed(
            SignedVersion::V2,
            agent_id,
            public_key,
            signature,
            topic,
            payload,
        )
    }

    #[test]
    fn classify_x0x_topic_routes_dm_bus_to_critical() {
        // Why: x0x's DM bus is the canonical Critical class — never drop
        // on admission load. The production topic uses slash-style
        // naming (`x0x/dm/v1/bus`), and a previous classifier with only
        // `x0x.dm.` dot-style prefix silently routed DM to Normal in
        // production (reviewer P1.2, 2026-05-12).
        assert_eq!(
            classify_x0x_topic("x0x/dm/v1/bus"),
            TopicPriority::Critical,
            "DM_BUS_TOPIC string from src/dm_inbox.rs must classify as Critical"
        );
    }

    #[test]
    fn classify_x0x_topic_routes_dm_inbox_hash_to_critical() {
        // Why: per-recipient DM inbox topics use the slash-prefix
        // `x0x/dm/v1/inbox/<hash>`. The classifier prefix `x0x/dm/v1/`
        // catches both the bus and per-recipient inbox topics.
        assert_eq!(
            classify_x0x_topic("x0x/dm/v1/inbox/abc123"),
            TopicPriority::Critical
        );
    }

    #[test]
    fn classify_x0x_topic_routes_identity_announce_to_critical() {
        assert_eq!(
            classify_x0x_topic("x0x.identity.announce.v2"),
            TopicPriority::Critical
        );
    }

    #[test]
    fn classify_x0x_topic_routes_test_orchestrator_to_critical() {
        // Why: split-soak (X0X-0076) needs reliable test-orchestrator
        // control delivery even under PubSub-pressure variant B.
        assert_eq!(
            classify_x0x_topic("x0x.test.discover.v1"),
            TopicPriority::Critical
        );
        assert_eq!(
            classify_x0x_topic("x0x.test.control.v1"),
            TopicPriority::Critical
        );
    }

    #[test]
    fn classify_x0x_topic_routes_directory_shards_to_bulk() {
        // Why: group directory shard topics (tag/name/id) are
        // anti-entropy discovery traffic published from x0xd. They use
        // `x0x.directory.{kind}.{shard}` naming (see
        // src/groups/discovery.rs `DIRECTORY_TOPIC_PREFIX`). A previous
        // classifier omitted them so they defaulted to Normal admission
        // (reviewer P2.1, 2026-05-13).
        assert_eq!(
            classify_x0x_topic("x0x.directory.tag.42"),
            TopicPriority::Bulk
        );
        assert_eq!(
            classify_x0x_topic("x0x.directory.name.0"),
            TopicPriority::Bulk
        );
        assert_eq!(
            classify_x0x_topic("x0x.directory.id.65535"),
            TopicPriority::Bulk
        );
    }

    #[test]
    fn classify_x0x_topic_routes_anti_entropy_to_bulk() {
        // Why: identity / machine / user shards + discovery anti-entropy
        // + release manifests + capability adverts + group cards are the
        // pressure-generating topics the Hunt 12f forecast identified.
        // Production uses both dot- and slash-separated topic names —
        // both must classify correctly.
        assert_eq!(
            classify_x0x_topic("x0x.identity.shard.v2.0042"),
            TopicPriority::Bulk
        );
        assert_eq!(
            classify_x0x_topic("x0x.machine.shard.v2.0123"),
            TopicPriority::Bulk
        );
        assert_eq!(
            classify_x0x_topic("x0x.user.shard.v2.0099"),
            TopicPriority::Bulk
        );
        assert_eq!(
            classify_x0x_topic("x0x.discovery.groups"),
            TopicPriority::Bulk
        );
        // Production RELEASE_TOPIC from src/upgrade/manifest.rs is
        // `x0x/release` (slash-style). A previous classifier with only
        // the dot-style `x0x.release.` prefix silently routed release
        // manifests to Normal (reviewer P1.2, 2026-05-12).
        assert_eq!(
            classify_x0x_topic("x0x/release"),
            TopicPriority::Bulk,
            "RELEASE_TOPIC string from src/upgrade/manifest.rs must classify as Bulk"
        );
        // DM capability advert — mesh-wide republish every 5 min.
        // Production constant `DM_CAPABILITY_TOPIC = x0x/caps/v1`
        // (src/dm_capability.rs).
        assert_eq!(
            classify_x0x_topic("x0x/caps/v1"),
            TopicPriority::Bulk,
            "DM_CAPABILITY_TOPIC string from src/dm_capability.rs must classify as Bulk"
        );
        // #448 r2: the signed digest extension is published on the same
        // fleet-wide cadence as the advert. Production constant
        // `DM_CAPABILITY_DIGEST_TOPIC = x0x/caps/v2/digest`
        // (src/dm_capability.rs); it must not default to Normal admission.
        assert_eq!(
            classify_x0x_topic("x0x/caps/v2/digest"),
            TopicPriority::Bulk,
            "DM_CAPABILITY_DIGEST_TOPIC string from src/dm_capability.rs must classify as Bulk"
        );
        assert_eq!(
            classify_x0x_topic("x0x.group.cards.v1"),
            TopicPriority::Bulk
        );
    }

    /// ADR 0030: the targeted refresh topics share the `x0x/caps/v1` prefix
    /// with the Bulk steady advert topic, so they only land on Critical
    /// because Critical is matched first. A reordering of the two prefix lists
    /// would silently cool a strict send's three-second convergence window
    /// behind Bulk admission — this pins the ordering.
    #[test]
    fn targeted_capability_refresh_topics_outrank_the_bulk_advert_topic() {
        assert_eq!(
            classify_x0x_topic(crate::dm_capability::DM_CAPABILITY_TARGETED_REQUEST_TOPIC),
            TopicPriority::Critical
        );
        assert_eq!(
            classify_x0x_topic(crate::dm_capability::DM_CAPABILITY_TARGETED_RESPONSE_TOPIC),
            TopicPriority::Critical
        );
        assert_eq!(
            classify_x0x_topic(crate::dm_capability::DM_CAPABILITY_TOPIC),
            TopicPriority::Bulk,
            "the steady advert topic must stay Bulk"
        );

        // The seeded registry must agree with the dynamic classifier, or the
        // priority depends on whether the topic was pre-registered.
        let registry = saorsa_gossip_pubsub::admission::TopicPriorityRegistry::default();
        register_x0x_topic_priorities(&registry);
        assert_eq!(
            registry.priority_for(&TopicId::from_entity(
                crate::dm_capability::DM_CAPABILITY_TARGETED_REQUEST_TOPIC.as_bytes()
            )),
            TopicPriority::Critical
        );
        assert_eq!(
            registry.priority_for(&TopicId::from_entity(
                crate::dm_capability::DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.as_bytes()
            )),
            TopicPriority::Critical
        );
    }

    #[test]
    fn classify_x0x_topic_defaults_unknown_topics_to_normal() {
        // Why: presence, named-group fanout, public messages, and any
        // custom application topic land here. Normal admission only
        // drops Dead peers — safe default.
        assert_eq!(
            classify_x0x_topic("x0x.presence.global"),
            TopicPriority::Normal
        );
        assert_eq!(
            classify_x0x_topic("x0x.groups.public.v1"),
            TopicPriority::Normal
        );
        assert_eq!(
            classify_x0x_topic("my.custom.app.topic"),
            TopicPriority::Normal
        );
    }

    /// Helper to create a test network node.
    async fn test_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(
                NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
                    bootstrap_nodes: Vec::new(),
                    mdns_enabled: false,
                    port_mapping_enabled: false,
                    ..NetworkConfig::default()
                },
                None,
                None,
            )
            .await
            .expect("Failed to create test node"),
        )
    }

    async fn slice1_manager(degree: usize, full: bool) -> PubSubManager {
        let mut network_config = NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..Default::default()
        };
        network_config.pinned_bootstrap_peers.insert([8; 32]);
        let node = Arc::new(NetworkNode::new(network_config, None, None).await.unwrap());
        let mut manager = PubSubManager::new_with_participation(
            node,
            None,
            None,
            if full {
                ParticipationMode::Full
            } else {
                ParticipationMode::Leaf
            },
            "slice1_test",
        )
        .unwrap();
        manager
            .configure_egress(&GossipConfig {
                leaf_max_eager_degree: degree,
                leaf_egress_soft_bytes_per_sec: 1,
                leaf_egress_hard_bytes_per_sec: 2,
                ..Default::default()
            })
            .await;
        *manager.transport.recorder.lock().unwrap() = Some(super::super::egress::Recorder {
            peers: (1..=8).rev().map(|id| PeerId::new([id; 32])).collect(),
            sends: Vec::new(),
        });
        manager
    }

    fn recorded_eager(
        manager: &PubSubManager,
    ) -> Vec<(PeerId, saorsa_gossip_pubsub::GossipMessage)> {
        let sends = std::mem::take(
            &mut manager
                .transport
                .recorder
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .sends,
        );
        sends
            .into_iter()
            .filter_map(|(peer, bytes)| {
                let message: saorsa_gossip_pubsub::GossipMessage =
                    postcard::from_bytes(&bytes).unwrap();
                (message.header.kind == MessageKind::Eager).then_some((peer, message))
            })
            .collect()
    }

    /// Cumulative EAGER send attempts claimed by sg (stage_stats). Claims are
    /// recorded synchronously before detached forward tasks are spawned, so a
    /// delta taken after `handle_incoming` / publish returns is the settle
    /// target for the test recorder — not a guessed minimum.
    fn eager_outbound_attempt_msgs(manager: &PubSubManager) -> u64 {
        manager
            .stage_stats()
            .outbound_by_kind
            .get("eager")
            .map(|meter| meter.msgs)
            .unwrap_or(0)
    }

    /// Count Eager frames for `msg_id` in the recorder without draining.
    fn count_eager_for_msg(manager: &PubSubManager, msg_id: [u8; 32]) -> usize {
        manager
            .transport
            .recorder
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .sends
            .iter()
            .filter(|(_, bytes)| {
                peek_pubsub_header(bytes)
                    .is_some_and(|h| h.kind == MessageKind::Eager && h.msg_id == msg_id)
            })
            .count()
    }

    /// Peek Eager (peer, message) pairs for `msg_id` without draining.
    fn peek_eager_for_msg(
        manager: &PubSubManager,
        msg_id: [u8; 32],
    ) -> Vec<(PeerId, saorsa_gossip_pubsub::GossipMessage)> {
        manager
            .transport
            .recorder
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .sends
            .iter()
            .filter_map(|(peer, bytes)| {
                let message: saorsa_gossip_pubsub::GossipMessage =
                    postcard::from_bytes(bytes).ok()?;
                (message.header.kind == MessageKind::Eager && message.header.msg_id == msg_id)
                    .then_some((*peer, message))
            })
            .collect()
    }

    /// Wait with a declared deadline until every metered EAGER attempt for
    /// `msg_id` has hit the test recorder (complete per-message recipient set).
    /// `attempted == 0` settles immediately as the legitimate empty forward set
    /// (e.g. D=1 inbound from the sole selected peer).
    async fn await_eager_settled_for_msg(
        manager: &PubSubManager,
        msg_id: [u8; 32],
        attempted: usize,
    ) -> Vec<(PeerId, saorsa_gossip_pubsub::GossipMessage)> {
        if attempted == 0 {
            return peek_eager_for_msg(manager, msg_id);
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if count_eager_for_msg(manager, msg_id) >= attempted {
                    return peek_eager_for_msg(manager, msg_id);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "eager fanout for msg did not settle before deadline (wanted {attempted} recorded sends)"
            )
        })
    }

    /// Like [`await_eager_settled_for_msg`], but discovers the sole new msg_id
    /// after a drained recorder (local publish path).
    async fn await_eager_settled_attempts(
        manager: &PubSubManager,
        attempted: usize,
    ) -> Vec<(PeerId, saorsa_gossip_pubsub::GossipMessage)> {
        if attempted == 0 {
            return Vec::new();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let msg_id = manager
                    .transport
                    .recorder
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .sends
                    .iter()
                    .find_map(|(_, bytes)| {
                        peek_pubsub_header(bytes).and_then(|h| {
                            (h.kind == MessageKind::Eager).then_some(h.msg_id)
                        })
                    });
                if let Some(msg_id) = msg_id {
                    if count_eager_for_msg(manager, msg_id) >= attempted {
                        return peek_eager_for_msg(manager, msg_id);
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "eager publish fanout did not settle before deadline (wanted {attempted} recorded sends)"
            )
        })
    }

    fn slice1_signed_frame(
        kind: MessageKind,
        topic: TopicId,
        payload: Bytes,
        id: [u8; 32],
    ) -> Bytes {
        let key = saorsa_gossip_identity::MlDsaKeyPair::generate().unwrap();
        let mut header = MessageHeader::new(topic, kind, 10);
        header.msg_id = id;
        header.seal_payload_hash(Some(&payload));
        let signature = key.sign(&postcard::to_stdvec(&header).unwrap()).unwrap();
        postcard::to_stdvec(&saorsa_gossip_pubsub::GossipMessage {
            header,
            payload: Some(payload),
            signature,
            public_key: key.public_key().to_vec(),
        })
        .unwrap()
        .into()
    }

    #[tokio::test]
    async fn slice1_four_writers_record_actual_eager_recipients_and_delivery() {
        for (degree, full) in [(1, false), (2, false), (12, false), (0, false), (2, true)] {
            let manager = slice1_manager(degree, full).await;
            let name = "x0x/dm/v1/inbox/slice1";
            let topic = TopicId::new([42; 32]);
            let mut sub = manager.subscribe_topic_id(name.into(), topic).await;
            let expected = if full || degree == 0 || degree == 12 {
                6
            } else {
                degree
            };
            for writer in 0..4 {
                // Permute HashMap-like plane ordering before each actual writer.
                manager
                    .transport
                    .recorder
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .peers
                    .rotate_left(1);
                match writer {
                    0 => manager.initialize_topic_peers(topic).await,
                    1 => {
                        manager.refresh_topic_peers().await;
                        manager.refresh_topic_peers().await;
                    }
                    2 => manager.refresh_subscribed_topic_id(name, topic).await,
                    _ => manager.prefer_one_full_bootstrap_eager(&[topic]).await,
                }
                recorded_eager(&manager);
                let publish_before = eager_outbound_attempt_msgs(&manager);
                manager
                    .publish_topic_id(name.into(), topic, Bytes::from(format!("local-{writer}")))
                    .await
                    .unwrap();
                let publish_attempted =
                    (eager_outbound_attempt_msgs(&manager) - publish_before) as usize;
                let sends = await_eager_settled_attempts(&manager, publish_attempted).await;
                assert_eq!(
                    sends.len(),
                    expected,
                    "writer {writer}, D={degree}, full={full}"
                );
                assert_eq!(
                    publish_attempted, expected,
                    "metered publish attempts must match the selected ceiling"
                );
                if expected <= 2 {
                    let actual = sends
                        .iter()
                        .map(|(peer, _)| *peer.as_bytes())
                        .collect::<HashSet<_>>();
                    let wanted = if degree == 1 {
                        HashSet::from([[8; 32]])
                    } else {
                        HashSet::from([[8; 32], [1; 32]])
                    };
                    assert_eq!(
                        actual, wanted,
                        "all writers preserve preferred + deterministic remainder"
                    );
                }
                recorded_eager(&manager);
                let local = tokio::time::timeout(Duration::from_secs(2), sub.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(local.payload, Bytes::from(format!("local-{writer}")));
                // A selected inbound sender cannot expand stock sg; unlisted
                // inbound expansion is the separate, explicitly held sg gate.
                let inbound_from = PeerId::new([8; 32]);
                let inbound_msg_id = [50 + writer; 32];
                let payload = encode_v1(name, &Bytes::from(format!("remote-{writer}"))).unwrap();
                let frame = slice1_signed_frame(MessageKind::Eager, topic, payload, inbound_msg_id);
                let inbound_before = eager_outbound_attempt_msgs(&manager);
                manager.handle_incoming(inbound_from, frame).await;
                let inbound_attempted =
                    (eager_outbound_attempt_msgs(&manager) - inbound_before) as usize;
                let sends =
                    await_eager_settled_for_msg(&manager, inbound_msg_id, inbound_attempted).await;
                assert_eq!(
                    sends.len(),
                    inbound_attempted,
                    "settled recipient set must include every metered attempt"
                );
                assert!(
                    sends.iter().all(|(peer, _)| *peer != inbound_from),
                    "forward set must exclude the inbound sender"
                );
                if expected == 1 {
                    // Sole selected peer is the sender: legitimate zero-recipient forward.
                    assert_eq!(
                        inbound_attempted, 0,
                        "D=1 inbound from sole selected peer must claim zero forwards"
                    );
                    assert!(
                        sends.is_empty(),
                        "D=1 inbound from sole selected peer must record zero recipients"
                    );
                } else {
                    assert!(
                        inbound_attempted >= 1,
                        "live eligible recipients must yield positive forward attempts"
                    );
                    assert!(
                        inbound_attempted <= expected,
                        "inbound fanout must obey the selected ceiling"
                    );
                }
                recorded_eager(&manager);
                let received = tokio::time::timeout(Duration::from_secs(2), sub.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(received.payload, Bytes::from(format!("remote-{writer}")));
            }
            assert_eq!(
                manager.egress_diagnostics()["subscribed_topics"][0]["topic_id_hex8"],
                topic.to_string(),
                "named diagnostics must retain the raw DM transport ID"
            );
            let topics = manager.plumtree_topic_ids().await;
            assert!(
                !topics.contains(&TopicId::from_entity(name.as_bytes())),
                "periodic refresh must use the stored raw DM ID"
            );
        }
    }

    #[tokio::test]
    async fn slice1_named_meters_repair_and_thresholds_do_not_shed() {
        let manager = slice1_manager(2, false).await;
        let name = "x0x/dm/v1/bus";
        let topic = TopicId::from_entity(name.as_bytes());
        let mut sub = manager.subscribe(name.into()).await;
        let cached_before = eager_outbound_attempt_msgs(&manager);
        manager
            .publish(name.into(), Bytes::from("cached"))
            .await
            .unwrap();
        let cached_attempted = (eager_outbound_attempt_msgs(&manager) - cached_before) as usize;
        let initial = await_eager_settled_attempts(&manager, cached_attempted).await;
        let id = initial[0].1.header.msg_id;
        recorded_eager(&manager);
        let request = slice1_signed_frame(
            MessageKind::IWant,
            topic,
            postcard::to_stdvec(&vec![id]).unwrap().into(),
            [0; 32],
        );
        // Real cached IWANT handler + spawned send task + outbound recorder.
        let repair_before = eager_outbound_attempt_msgs(&manager);
        manager.handle_incoming(PeerId::new([7; 32]), request).await;
        let repair_attempted = (eager_outbound_attempt_msgs(&manager) - repair_before) as usize;
        let repaired = await_eager_settled_for_msg(&manager, id, repair_attempted).await;
        assert_eq!(repaired.len(), 1);
        assert_eq!(repaired[0].0, PeerId::new([7; 32]));
        assert_eq!(repaired[0].1.header.msg_id, id);
        recorded_eager(&manager);
        manager.sample_egress();
        let before = manager.egress_diagnostics();
        assert_eq!(before["subscribed_topics"][0]["name"], name);
        assert_eq!(
            before["subscribed_topics"][0]["topic_id_hex8"],
            "a746d680e31732d1"
        );
        assert_eq!(before["outbound_by_topic_named"][0]["name"], name);
        assert_eq!(
            before["egress_budget"]["repair"]["iwant_matched_eager_attempt_msgs"],
            1
        );
        assert!(
            before["egress_budget"]["egress_budget_hard_exceeded"]
                .as_u64()
                .unwrap()
                > 0
        );
        let before_refresh_pub = eager_outbound_attempt_msgs(&manager);
        manager
            .publish(name.into(), Bytes::from("after-iwant-before-refresh"))
            .await
            .unwrap();
        let before_refresh_attempted =
            (eager_outbound_attempt_msgs(&manager) - before_refresh_pub) as usize;
        let before_refresh_sends =
            await_eager_settled_attempts(&manager, before_refresh_attempted).await;
        assert!(
            before_refresh_sends.len() <= 2,
            "repair promotion must preserve the ceiling before refresh"
        );
        assert!(
            !before_refresh_sends.is_empty(),
            "publish with live selected peers must record positive eager delivery"
        );
        recorded_eager(&manager);
        manager.refresh_topic_peers().await;
        let after_hard_before = eager_outbound_attempt_msgs(&manager);
        manager
            .publish(name.into(), Bytes::from("after-hard-exceed"))
            .await
            .unwrap();
        let after_hard_attempted =
            (eager_outbound_attempt_msgs(&manager) - after_hard_before) as usize;
        let after_hard_sends = await_eager_settled_attempts(&manager, after_hard_attempted).await;
        assert_eq!(
            after_hard_sends.len(),
            2,
            "byte thresholds never shed sends"
        );
        recorded_eager(&manager);
        let first = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.payload, Bytes::from("cached"));
        assert_eq!(second.payload, Bytes::from("after-iwant-before-refresh"));
        let third = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(third.payload, Bytes::from("after-hard-exceed"));
        assert_eq!(
            manager.egress_diagnostics()["egress_budget"]["egress_budget_hard_exceeded"],
            before["egress_budget"]["egress_budget_hard_exceeded"],
            "HTTP reads must not increment counters"
        );
    }

    #[tokio::test]
    async fn slice1_replacement_after_selected_peer_failure() {
        let manager = slice1_manager(2, false).await;
        let name = "slice1-failover";
        let mut sub = manager.subscribe(name.into()).await;
        for (removed, expected) in [
            (vec![8], HashSet::from([[1; 32], [2; 32]])),
            (vec![1, 2], HashSet::from([[3; 32], [4; 32]])),
        ] {
            manager
                .transport
                .recorder
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .peers
                .retain(|peer| !removed.contains(&peer.as_bytes()[0]));
            manager.refresh_topic_peers().await;
            recorded_eager(&manager);
            let payload = Bytes::from(format!("after-removing-{removed:?}"));
            let pub_before = eager_outbound_attempt_msgs(&manager);
            manager.publish(name.into(), payload.clone()).await.unwrap();
            let pub_attempted = (eager_outbound_attempt_msgs(&manager) - pub_before) as usize;
            let sends = await_eager_settled_attempts(&manager, pub_attempted).await;
            assert_eq!(
                sends
                    .iter()
                    .map(|(peer, _)| *peer.as_bytes())
                    .collect::<HashSet<_>>(),
                expected
            );
            recorded_eager(&manager);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), sub.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .payload,
                payload
            );
        }
    }

    #[tokio::test]
    async fn slice1_pinned_sg_caps_unlisted_inbound_and_interleaved_publish() {
        let manager = slice1_manager(2, false).await;
        let name = "slice1-sg-hold";
        let topic = TopicId::from_entity(name.as_bytes());
        let mut sub = manager.subscribe(name.into()).await;
        for peer in [3, 4, 5] {
            let inbound_from = PeerId::new([peer; 32]);
            let inbound_msg_id = [peer; 32];
            let frame = slice1_signed_frame(
                MessageKind::Eager,
                topic,
                encode_v1(name, &Bytes::from(vec![peer])).unwrap(),
                inbound_msg_id,
            );
            let inbound_before = eager_outbound_attempt_msgs(&manager);
            manager.handle_incoming(inbound_from, frame).await;
            let inbound_attempted =
                (eager_outbound_attempt_msgs(&manager) - inbound_before) as usize;
            let sends =
                await_eager_settled_for_msg(&manager, inbound_msg_id, inbound_attempted).await;
            assert_eq!(sends.len(), inbound_attempted);
            assert!(
                sends.iter().all(|(peer_id, _)| *peer_id != inbound_from),
                "forward set must exclude the unlisted inbound sender"
            );
            assert!(
                inbound_attempted >= 1,
                "unlisted inbound with live selected peers must forward positively"
            );
            assert!(
                inbound_attempted <= 2,
                "inbound handler must cap before forwarding"
            );
            recorded_eager(&manager);
            assert!(tokio::time::timeout(Duration::from_secs(2), sub.recv())
                .await
                .unwrap()
                .is_some());
            let requester = PeerId::new([peer + 3; 32]);
            let request = slice1_signed_frame(
                MessageKind::IWant,
                topic,
                postcard::to_stdvec(&vec![[peer; 32]]).unwrap().into(),
                [0; 32],
            );
            let repair_before = eager_outbound_attempt_msgs(&manager);
            manager.handle_incoming(requester, request).await;
            let repair_attempted = (eager_outbound_attempt_msgs(&manager) - repair_before) as usize;
            let repair =
                await_eager_settled_for_msg(&manager, inbound_msg_id, repair_attempted).await;
            assert_eq!(
                repair.len(),
                1,
                "cached IWANT reply remains available outside selected peers"
            );
            assert_eq!(repair[0].0, requester);
            recorded_eager(&manager);
            let interleave_before = eager_outbound_attempt_msgs(&manager);
            manager
                .publish(name.into(), Bytes::from(vec![peer, 9]))
                .await
                .unwrap();
            let interleave_attempted =
                (eager_outbound_attempt_msgs(&manager) - interleave_before) as usize;
            let interleave = await_eager_settled_attempts(&manager, interleave_attempted).await;
            assert!(
                !interleave.is_empty(),
                "interleaved publish after repair promotion must attempt delivery"
            );
            assert!(
                interleave.len() <= 2,
                "interleaved publish after repair promotion"
            );
            recorded_eager(&manager);
            assert!(tokio::time::timeout(Duration::from_secs(2), sub.recv())
                .await
                .unwrap()
                .is_some());
        }
        recorded_eager(&manager);
        let final_before = eager_outbound_attempt_msgs(&manager);
        manager
            .publish(name.into(), Bytes::from("between-refreshes"))
            .await
            .unwrap();
        let final_attempted = (eager_outbound_attempt_msgs(&manager) - final_before) as usize;
        let final_sends = await_eager_settled_attempts(&manager, final_attempted).await;
        let actual = final_sends.len();
        assert!(
            !final_sends.is_empty(),
            "between-refreshes publish must attempt positive eager delivery"
        );
        assert!(
            actual <= 2,
            "pinned sg must preserve D between x0x refreshes"
        );
        recorded_eager(&manager);
        eprintln!("Pinned sg #51: D=2, unlisted inbound + interleaved publish, final eager fanout={actual}");
    }

    #[tokio::test]
    async fn slice1_pinned_sg_concurrent_publishers_after_maintenance_timers() {
        let manager = slice1_manager(2, false).await;
        // The measured DM bus is Critical and queues concurrent sends. Normal
        // topics intentionally shed when their single sg send slot is occupied.
        let name = "x0x/dm/v1/bus";
        let topic = TopicId::from_entity(name.as_bytes());
        let mut sub = manager.subscribe(name.into()).await;
        // Exercise two actual maintenance periods (including startup jitter).
        // Keep sg's std::time deadlines and Tokio timers on the same clock.
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_secs(31)).await;
        }
        let frames = (3..=6)
            .map(|peer| {
                (
                    PeerId::new([peer; 32]),
                    slice1_signed_frame(
                        MessageKind::Eager,
                        topic,
                        encode_v1(name, &Bytes::from(vec![peer])).unwrap(),
                        [peer; 32],
                    ),
                )
            })
            .collect::<Vec<_>>();
        recorded_eager(&manager);
        tokio::join!(
            async {
                for (peer, frame) in frames {
                    manager.handle_incoming(peer, frame).await;
                }
            },
            async {
                for id in 10..14 {
                    manager
                        .publish(name.into(), Bytes::from(vec![id]))
                        .await
                        .unwrap();
                }
            }
        );
        // Inbound EAGER fanout uses detached tasks: handler completion alone
        // is not transport evidence. Await all expected recording sends.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let eager_count = manager
                    .transport
                    .recorder
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .sends
                    .iter()
                    .filter(|(_, bytes)| {
                        peek_pubsub_header(bytes).is_some_and(|h| h.kind == MessageKind::Eager)
                    })
                    .count();
                if eager_count >= 16 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("eight messages must reach both selected peers");
        let mut sends_per_message = HashMap::new();
        for (_, message) in recorded_eager(&manager) {
            *sends_per_message.entry(message.header.msg_id).or_insert(0) += 1;
        }
        assert_eq!(sends_per_message.len(), 8);
        assert_eq!(manager.stage_stats().outbound_budget_exhausted, 0);
        assert!(
            sends_per_message.values().all(|count| *count <= 2),
            "each concurrent unsolicited forwarding event obeys D"
        );
        for _ in 0..8 {
            assert!(tokio::time::timeout(Duration::from_secs(2), sub.recv())
                .await
                .unwrap()
                .is_some());
        }
    }

    #[tokio::test]
    async fn slice1_ihave_iwant_recovers_missed_message_after_selected_failure() {
        let owner = slice1_manager(2, false).await;
        let receiver = slice1_manager(2, false).await;
        let name = "slice1-recovery";
        let topic = TopicId::from_entity(name.as_bytes());
        let _owner_sub = owner.subscribe(name.into()).await;
        let mut receiver_sub = receiver.subscribe(name.into()).await;
        let first_before = eager_outbound_attempt_msgs(&owner);
        owner
            .publish(name.into(), Bytes::from("deliberately-missed"))
            .await
            .unwrap();
        let first_attempted = (eager_outbound_attempt_msgs(&owner) - first_before) as usize;
        let first = await_eager_settled_attempts(&owner, first_attempted).await;
        let id = first[0].1.header.msg_id;
        recorded_eager(&owner);
        // Lose both selected carriers; no initial EAGER reaches the receiver.
        owner
            .transport
            .recorder
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .peers
            .retain(|peer| ![1, 8].contains(&peer.as_bytes()[0]));
        owner.refresh_topic_peers().await;
        let ihave = slice1_signed_frame(
            MessageKind::IHave,
            topic,
            postcard::to_stdvec(&vec![id]).unwrap().into(),
            [0; 32],
        );
        receiver.handle_incoming(PeerId::new([3; 32]), ihave).await;
        let sends = std::mem::take(
            &mut receiver
                .transport
                .recorder
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .sends,
        );
        let request = sends
            .into_iter()
            .find(|(peer, bytes)| {
                *peer == PeerId::new([3; 32])
                    && peek_pubsub_header(bytes).is_some_and(|h| h.kind == MessageKind::IWant)
            })
            .expect("real IHAVE handler emits IWANT")
            .1;
        let repair_before = eager_outbound_attempt_msgs(&owner);
        owner.handle_incoming(PeerId::new([4; 32]), request).await;
        let repair_attempted = (eager_outbound_attempt_msgs(&owner) - repair_before) as usize;
        let repair = await_eager_settled_for_msg(&owner, id, repair_attempted).await;
        assert_eq!(repair.len(), 1);
        assert_eq!(repair[0].0, PeerId::new([4; 32]));
        recorded_eager(&owner);
        receiver
            .handle_incoming(
                PeerId::new([3; 32]),
                postcard::to_stdvec(&repair[0].1).unwrap().into(),
            )
            .await;
        let recovered = tokio::time::timeout(Duration::from_secs(2), receiver_sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.payload, Bytes::from("deliberately-missed"));
        let after_before = eager_outbound_attempt_msgs(&owner);
        owner
            .publish(name.into(), Bytes::from("after-recovery"))
            .await
            .unwrap();
        let after_attempted = (eager_outbound_attempt_msgs(&owner) - after_before) as usize;
        let after_sends = await_eager_settled_attempts(&owner, after_attempted).await;
        assert!(after_sends.len() <= 2);
        assert!(!after_sends.is_empty());
    }

    #[test]
    fn slice1_deterministic_full_width_ties_duplicates_and_replacements() {
        let mut peers = (1..=8).map(|id| PeerId::new([id; 32])).collect::<Vec<_>>();
        peers.push(PeerId::new([1; 32]));
        for _ in 0..peers.len() {
            peers.rotate_left(1);
            let selected = ordered_leaf_peers(
                peers.clone(),
                &[[8; 32], [7; 32]],
                &[[6; 32]],
                &HashSet::new(),
                2,
            );
            assert_eq!(selected, vec![PeerId::new([7; 32]), PeerId::new([1; 32])]);
        }
        let mut a = [1; 32];
        a[31] = 2;
        let mut b = a;
        b[31] = 3;
        assert_eq!(
            ordered_leaf_peers(
                vec![PeerId::new(b), PeerId::new(a)],
                &[],
                &[],
                &HashSet::new(),
                1
            ),
            vec![PeerId::new(a)]
        );
        peers.retain(|peer| ![1, 7].contains(&peer.as_bytes()[0]));
        assert_eq!(
            ordered_leaf_peers(peers, &[[7; 32], [8; 32]], &[], &HashSet::new(), 2),
            vec![PeerId::new([8; 32]), PeerId::new([2; 32])]
        );
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

    /// Issue #191 gap 3: pubsub delivery must consult the authoritative
    /// gossiped `RevocationSet`, not just the operator-local ContactStore.
    /// Pre-fix `decode_for_delivery` never checked `RevocationSet`, so a
    /// gossiped revocation reached delivery only once the eviction loop had
    /// set `trust = Blocked` — a race (revocation received, eviction not yet
    /// run) or a later `set_trust` off Blocked reopened delivery from the
    /// revoked sender. Here a verified v2 payload from a RevocationSet-
    /// revoked sender is dropped; a non-revoked sender is delivered.
    #[tokio::test]
    async fn decode_for_delivery_drops_revoked_sender_via_revocation_set() {
        // Build a RevocationSet holding a self-revoked agent (the sender).
        let kp = AgentKeypair::generate().expect("keygen");
        let ctx = SigningContext::from_keypair(&kp);
        let revoked_agent = ctx.agent_id;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(revoked_agent),
            kp.public_key(),
            kp.secret_key(),
            now,
            None,
        )
        .expect("sign revocation");
        let mut set = crate::revocation::RevocationSet::new();
        set.verify_and_insert(record, None)
            .expect("self-revocation verifies without a cert");
        let rev_set = std::sync::Arc::new(tokio::sync::RwLock::new(set));

        let topic = "chat";
        let payload = Bytes::from("hello");
        // A verified v2 payload signed by the (now-revoked) sender.
        let signing_payload =
            build_signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let signature = ctx.sign(&signing_payload).expect("sign message");
        let encoded = encode_v2(
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            topic,
            &payload,
        )
        .expect("encode");

        // contacts = None isolates the RevocationSet check. The payload's
        // signature verifies, but the sender is revoked → dropped.
        assert!(
            decode_for_delivery(encoded.clone(), None, Some(&rev_set))
                .await
                .is_none(),
            "payload from a RevocationSet-revoked sender must be dropped"
        );

        // A non-revoked sender (different agent) is delivered.
        let other = AgentKeypair::generate().expect("keygen2");
        let other_ctx = SigningContext::from_keypair(&other);
        let sp2 = build_signing_payload(other_ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let sig2 = other_ctx.sign(&sp2).expect("sign2");
        let encoded2 = encode_v2(
            &other_ctx.agent_id,
            &other_ctx.public_key_bytes,
            &sig2,
            topic,
            &payload,
        )
        .expect("encode2");
        assert!(
            decode_for_delivery(encoded2, None, Some(&rev_set))
                .await
                .is_some(),
            "payload from a non-revoked sender must be delivered"
        );
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
    // V2 decode bounds-check tests (pin the `take_lp` extraction in finding #2)
    // -----------------------------------------------------------------------

    /// Produce a known-good encoded v2 buffer for slicing in the bounds tests.
    fn valid_v2_buffer() -> Bytes {
        let kp = AgentKeypair::generate().expect("keygen");
        let ctx = SigningContext::from_keypair(&kp);
        let topic = "bounds-check";
        let payload = Bytes::from("payload bytes");
        let signing_payload =
            build_signing_payload(ctx.agent_id.as_bytes(), topic.as_bytes(), &payload);
        let signature = ctx.sign(&signing_payload).expect("sign");
        encode_v2(
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            topic,
            &payload,
        )
        .expect("encode")
    }

    #[test]
    fn test_v2_full_buffer_decodes_and_verifies() {
        // Baseline: the unmodified buffer round-trips and verifies. This pins
        // the happy path so the bounds tests below isolate truncation.
        let buf = valid_v2_buffer();
        let msg = decode_v2(&buf).expect("decode");
        assert_eq!(msg.topic, "bounds-check");
        assert_eq!(msg.payload, Bytes::from("payload bytes"));
        assert!(msg.verified);
    }

    /// Byte offset where the trailing payload (the "remaining bytes" field)
    /// begins in a v2 buffer. Truncations before this offset hit a length-
    /// prefix bounds check; truncations at/after it just shorten the payload
    /// and remain valid.
    fn v2_payload_start(buf: &[u8]) -> usize {
        let pk_len = u16::from_be_bytes([buf[33], buf[34]]) as usize;
        let sig_len_pos = 35 + pk_len;
        let sig_len = u16::from_be_bytes([buf[sig_len_pos], buf[sig_len_pos + 1]]) as usize;
        let topic_len_pos = sig_len_pos + 2 + sig_len;
        let topic_len = u16::from_be_bytes([buf[topic_len_pos], buf[topic_len_pos + 1]]) as usize;
        topic_len_pos + 2 + topic_len
    }

    #[test]
    fn test_v2_truncated_in_header_region_is_err() {
        // Truncating anywhere inside the framed header (version → end of topic)
        // must be rejected, never panic. This walks every length-prefix bounds
        // check in decode_v2.
        let buf = valid_v2_buffer();
        let payload_start = v2_payload_start(&buf);
        for cut in 1..payload_start {
            assert!(
                decode_v2(&buf[..cut]).is_err(),
                "truncating to {cut} of {} bytes (payload_start={payload_start}) must be an error",
                buf.len()
            );
        }
    }

    #[test]
    fn test_v2_truncation_into_payload_region_still_decodes() {
        // The payload is the trailing "remaining bytes" field with no length
        // prefix, so cutting into it yields a shorter (still valid) payload.
        // This pins the boundary that test_v2_truncated_in_header_region_is_err
        // stops at.
        let buf = valid_v2_buffer();
        let payload_start = v2_payload_start(&buf);
        for cut in payload_start..=buf.len() {
            assert!(
                decode_v2(&buf[..cut]).is_ok(),
                "truncating to {cut} (>= payload_start {payload_start}) must still decode"
            );
        }
    }

    #[test]
    fn test_v2_oversized_pubkey_len_is_err() {
        // Overwrite the pubkey length prefix (bytes 33..35) with 0xFFFF so the
        // claimed field overruns the buffer — must be a clean error.
        let mut buf = valid_v2_buffer().to_vec();
        buf[33] = 0xFF;
        buf[34] = 0xFF;
        assert!(decode_v2(&buf).is_err());
    }

    #[test]
    fn test_v2_oversized_sig_len_is_err() {
        // The signature length prefix sits right after the public key. Decode
        // the real pubkey length to locate it, then poison it.
        let mut buf = valid_v2_buffer().to_vec();
        let pk_len = u16::from_be_bytes([buf[33], buf[34]]) as usize;
        let sig_len_pos = 35 + pk_len;
        buf[sig_len_pos] = 0xFF;
        buf[sig_len_pos + 1] = 0xFF;
        assert!(decode_v2(&buf).is_err());
    }

    #[test]
    fn test_v2_oversized_topic_len_is_err() {
        // The topic length prefix sits after pubkey and signature.
        let mut buf = valid_v2_buffer().to_vec();
        let pk_len = u16::from_be_bytes([buf[33], buf[34]]) as usize;
        let sig_len_pos = 35 + pk_len;
        let sig_len = u16::from_be_bytes([buf[sig_len_pos], buf[sig_len_pos + 1]]) as usize;
        let topic_len_pos = sig_len_pos + 2 + sig_len;
        buf[topic_len_pos] = 0xFF;
        buf[topic_len_pos + 1] = 0xFF;
        assert!(decode_v2(&buf).is_err());
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

    // ADR-0063: fixtures independently construct the exact gossip #48 preimage.
    fn v3_fixture(ctx: &SigningContext, topic: &str, payload: &[u8]) -> Bytes {
        let mut preimage = b"x0x-msg-v3".to_vec();
        preimage.extend_from_slice(ctx.agent_id.as_bytes());
        preimage.extend_from_slice(
            &u16::try_from(topic.len())
                .expect("topic fits")
                .to_be_bytes(),
        );
        preimage.extend_from_slice(topic.as_bytes());
        preimage.extend_from_slice(payload);
        let signature = ctx.sign(&preimage).expect("fixture sign");
        encode_signed(
            SignedVersion::V3,
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            topic,
            &Bytes::copy_from_slice(payload),
        )
        .expect("fixture encode")
    }

    fn topic_length_offset(envelope: &[u8]) -> usize {
        let mut pos = 33;
        take_lp(envelope, &mut pos, "public key").expect("key");
        take_lp(envelope, &mut pos, "signature").expect("signature");
        pos
    }

    #[tokio::test]
    async fn v3_rejects_topic_boundary_rewrites() {
        let ctx = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen"));
        for (short, suffix) in [("T", "/state-sync"), ("é", "/other")] {
            let long = format!("{short}{suffix}");
            for (topic, payload, rewritten_topic) in [
                (short, format!("{suffix}body"), long.as_str()),
                (long.as_str(), "body".to_string(), short),
            ] {
                let original = v3_fixture(&ctx, topic, payload.as_bytes());
                let valid = decode_signed_kv_v3(&original).expect("honest original");
                assert!(valid.verified);
                assert_eq!(valid.payload.as_ref(), payload.as_bytes());
                let offset = topic_length_offset(&original);
                let mut rewritten = original.to_vec();
                rewritten[offset..offset + 2].copy_from_slice(
                    &u16::try_from(rewritten_topic.len())
                        .expect("length")
                        .to_be_bytes(),
                );
                // Topic+payload concatenation is unchanged: only the boundary moved.
                assert!(decode_signed_kv_v3(&rewritten)
                    .expect_err("rewrite rejected")
                    .to_string()
                    .contains("Invalid V3 signature"));
                assert!(decode_for_delivery(Bytes::from(rewritten), None, None)
                    .await
                    .is_none());
            }
        }
    }

    #[test]
    fn v3_strict_version_dispatch_and_relabeling() {
        let ctx = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen"));
        let payload = Bytes::from_static(b"body");
        let signature = ctx
            .sign(&build_signing_payload(
                ctx.agent_id.as_bytes(),
                b"T",
                &payload,
            ))
            .expect("v2 sign");
        let v2 = encode_v2(
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &signature,
            "T",
            &payload,
        )
        .expect("v2 encode");
        assert!(
            decode_auto(v2.clone())
                .expect("stock v2 remains v2")
                .verified
        );
        assert!(decode_signed_kv_v3(&v2).is_err());
        let mut relabeled = v2.to_vec();
        relabeled[0] = VERSION_V3;
        assert!(decode_auto(Bytes::from(relabeled)).is_err());
        let v3 = v3_fixture(&ctx, "T", &payload);
        assert!(decode_auto(v3.clone()).expect("v3 dispatch").verified);
        assert!(decode_v2(&v3).is_err());
        for version in [0, 1, 2, 4, 255] {
            let mut wrong = v3.to_vec();
            wrong[0] = version;
            assert!(decode_signed_kv_v3(&wrong).is_err());
            if version == VERSION_V2 {
                assert!(
                    !decode_auto(Bytes::from(wrong))
                        .expect("v2 dispatch uses v2 domain")
                        .verified
                );
            }
        }
        for end in 0..=topic_length_offset(&v3) + 2 {
            assert!(decode_signed_kv_v3(&v3[..end]).is_err(), "truncation {end}");
        }
        let mut tampered = v3.to_vec();
        tampered[1] ^= 1;
        assert!(decode_signed_kv_v3(&tampered).is_err());
        let mut appended = v3.to_vec();
        appended.push(0);
        assert!(decode_signed_kv_v3(&appended).is_err());
    }

    #[test]
    fn v3_signing_preimage_matches_gossip_contract() {
        let author = [42; 32];
        let signed = SignedVersion::V3
            .signing_payload(&author, "é".as_bytes(), b"/state-sync")
            .expect("signing payload");
        let mut expected = b"x0x-msg-v3".to_vec();
        expected.extend_from_slice(&author);
        expected.extend_from_slice(&[0, 2]); // UTF-8 byte length, not character count
        expected.extend_from_slice("é/state-sync".as_bytes());
        assert_eq!(signed, expected);
        assert!(SignedVersion::V3
            .signing_payload(&author, &vec![b'x'; 65536], b"")
            .is_err());
        for len in [512, 767, 768, 1023, 1024, 65535] {
            assert!(encode_v1(&"x".repeat(len), &Bytes::new()).is_err());
        }
        for len in [0, 255, 256, 511] {
            assert!(decode_auto(
                encode_v1(&"x".repeat(len), &Bytes::new()).expect("unreserved v1 length")
            )
            .is_ok());
        }
        // V2 signs identical concatenations; V3 authenticates the split itself.
        assert_eq!(
            build_signing_payload(&author, b"T", b"/state-syncbody"),
            build_signing_payload(&author, b"T/state-sync", b"body")
        );
        assert_ne!(
            SignedVersion::V3
                .signing_payload(&author, b"T", b"/state-syncbody")
                .unwrap(),
            SignedVersion::V3
                .signing_payload(&author, b"T/state-sync", b"body")
                .unwrap()
        );
    }

    #[test]
    fn signed_and_unknown_versions_never_fall_through_to_unsigned() {
        // Valid UTF-8 deliberately removes the accidental protection of random
        // key bytes failing V1's topic parsing. Stock decode_v1 accepts these.
        for version in VERSION_V2..=u8::MAX {
            let mut bytes = vec![b'x'; 2 + (usize::from(version) << 8)];
            bytes[0] = version;
            bytes[1] = 0;
            assert!(decode_v1(&bytes).is_ok());
            assert!(decode_auto(Bytes::from(bytes)).is_err());
        }
    }

    #[test]
    fn v3_enforces_gossip_shape_and_size_bounds() {
        let ctx = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen"));
        // Construct malformed frames through V2 so V3's encoder cannot mask a
        // missing check in its decoder. No cryptographic verification is needed.
        for (key_len, sig_len) in [(1951, 3309), (1953, 3309), (1952, 3308), (1952, 3310)] {
            let key = vec![0; key_len];
            let signature = vec![0; sig_len];
            assert!(encode_signed(
                SignedVersion::V3,
                &ctx.agent_id,
                &key,
                &signature,
                "T",
                &Bytes::new()
            )
            .is_err());
            let mut malformed = encode_v2(&ctx.agent_id, &key, &signature, "T", &Bytes::new())
                .unwrap()
                .to_vec();
            malformed[0] = VERSION_V3;
            assert!(decode_signed_kv_v3(&malformed)
                .unwrap_err()
                .to_string()
                .contains("length"));
        }
        let header_len = 39 + ctx.public_key_bytes.len() + ML_DSA_65_SIG_LEN + 1;
        let payload = vec![0; MAX_V3_ENVELOPE_BYTES - header_len];
        let at_limit = v3_fixture(&ctx, "T", &payload);
        assert_eq!(at_limit.len(), MAX_V3_ENVELOPE_BYTES);
        assert!(decode_signed_kv_v3(&at_limit).unwrap().verified);
        let mut oversized = at_limit.to_vec();
        oversized.push(0);
        assert!(decode_signed_kv_v3(&oversized)
            .unwrap_err()
            .to_string()
            .contains("exceeds 1 MiB"));
        assert!(encode_signed(
            SignedVersion::V3,
            &ctx.agent_id,
            &ctx.public_key_bytes,
            &vec![0; ML_DSA_65_SIG_LEN],
            "T",
            &Bytes::from(vec![0; payload.len() + 1])
        )
        .is_err());
    }

    #[tokio::test]
    async fn v3_publisher_requires_signing_and_emits_verifiable_envelope() {
        let node = test_node().await;
        let unsigned = PubSubManager::new(Arc::clone(&node), None).expect("manager");
        assert!(unsigned
            .publish_signed_kv_v3("T".to_string(), Bytes::new())
            .await
            .is_err());
        let ctx = Arc::new(SigningContext::from_keypair(
            &AgentKeypair::generate().expect("keygen"),
        ));
        let manager = PubSubManager::new(node, Some(Arc::clone(&ctx))).expect("manager");
        // Preparation must not implicitly migrate even a Signed KV topic name.
        for topic in ["ordinary", "T", "T/state-sync"] {
            let envelope = manager
                .publish_and_get_envelope(topic.to_string(), Bytes::from_static(b"body"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(envelope[0], VERSION_V2);
            assert!(decode_v2(&envelope).unwrap().verified);
        }
        assert!(manager
            .publish_signed_kv_v3("local:T".to_string(), Bytes::new())
            .await
            .is_err());
        for topic in ["T", "T/state-sync"] {
            let envelope = manager
                .publish_signed_kv_v3(topic.to_string(), Bytes::from_static(b"body"))
                .await
                .expect("v3 publish");
            assert_eq!(envelope[0], VERSION_V3);
            let msg = decode_signed_kv_v3(&envelope).expect("paired receiver");
            assert_eq!(msg.topic, topic);
            assert_eq!(msg.sender, Some(ctx.agent_id));
            assert_eq!(msg.raw_envelope, Some(envelope.clone()));
            // Independently verify the production signer with gossip's crypto API.
            let mut pos = 33;
            let key = take_lp(&envelope, &mut pos, "key").expect("key");
            assert_eq!(PeerId::from_pubkey(key).as_bytes(), ctx.agent_id.as_bytes());
            let signature = take_lp(&envelope, &mut pos, "signature").expect("signature");
            let mut expected = b"x0x-msg-v3".to_vec();
            expected.extend_from_slice(ctx.agent_id.as_bytes());
            expected.extend_from_slice(&u16::try_from(topic.len()).expect("length").to_be_bytes());
            expected.extend_from_slice(topic.as_bytes());
            expected.extend_from_slice(b"body");
            assert!(
                saorsa_gossip_identity::MlDsaKeyPair::verify(key, &expected, signature)
                    .expect("gossip verify")
            );
        }
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

    /// WHY (issue #238 round-5 review): dropping a `Subscription` must end
    /// its forwarding task PROMPTLY — on a forever-QUIET topic, with no
    /// message ever arriving to surface the closed downstream channel.
    /// Before the fix the task parked on `plumtree_rx.recv()` indefinitely,
    /// so every discarded subscription (e.g. a daemon registration
    /// rollback on a unique topic) pinned a ghost task and its PlumTree
    /// registration until process exit. The `subscriber_channel_closed`
    /// counter is the task's exit breadcrumb — it must tick WITHOUT any
    /// publish.
    #[tokio::test]
    async fn dropping_subscription_ends_forwarding_task_on_quiet_topic() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let before = manager.stats().subscriber_channel_closed;

        let sub = manager
            .subscribe("quiet-topic-238-teardown".to_string())
            .await;
        drop(sub);

        // No publish ever happens on the topic; the forwarding task must
        // still notice the dropped receiver via tx.closed() and exit.
        let mut ended = false;
        for _ in 0..200 {
            if manager.stats().subscriber_channel_closed > before {
                ended = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            ended,
            "forwarding task must exit promptly when its subscriber is \
             dropped on a quiet topic (ghost-task leak)"
        );
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
    async fn leaf_refresh_topic_peers_skips_unsubscribed_passthrough_topics() {
        // Why (#380): a desktop Leaf must not call set_topic_peers for
        // topics it does not subscribe to — that is the pass-through loop
        // that saturates residential uplinks.
        let node = test_node().await;
        let manager = PubSubManager::new_with_participation(
            node,
            None,
            None,
            ParticipationMode::Leaf,
            "default_leaf",
        )
        .expect("manager");
        let subscribed = "x0x/dm/v1/inbox/self";
        let passthrough = "x0x.groups.public.v1";
        let _sub = manager.subscribe(subscribed.to_string()).await;
        manager.set_known_plumtree_topics_for_test(vec![
            TopicId::from_entity(subscribed.as_bytes()),
            TopicId::from_entity(passthrough.as_bytes()),
        ]);

        manager.refresh_topic_peers().await;

        let refreshed = manager.take_refreshed_topic_ids();
        let passthrough_id = TopicId::from_entity(passthrough.as_bytes());
        assert!(
            !refreshed.contains(&passthrough_id),
            "Leaf must not call set_topic_peers for unsubscribed topic ids"
        );
        assert!(
            refreshed.contains(&TopicId::from_entity(subscribed.as_bytes())),
            "Leaf still refreshes topics it actually subscribes to"
        );
        let snap = manager.participation_snapshot();
        assert_eq!(snap.mode, ParticipationMode::Leaf);
        assert!(!snap.passthrough_refresh_ran);
        assert_eq!(snap.passthrough_refresh_runs, 0);
    }

    #[tokio::test]
    async fn full_refresh_topic_peers_still_feeds_passthrough_topics() {
        // Why (#380): backbone Full keeps today's relay loop so unsubscribed
        // PlumTree topics still get a plane peer list.
        let node = test_node().await;
        let manager = PubSubManager::new_with_participation(
            node,
            None,
            None,
            ParticipationMode::Full,
            "operator_relay",
        )
        .expect("manager");
        let subscribed = "x0x/caps/v1";
        let passthrough = "x0x.groups.public.v1";
        let _sub = manager.subscribe(subscribed.to_string()).await;
        manager.set_known_plumtree_topics_for_test(vec![
            TopicId::from_entity(subscribed.as_bytes()),
            TopicId::from_entity(passthrough.as_bytes()),
        ]);

        manager.refresh_topic_peers().await;

        let refreshed = manager.take_refreshed_topic_ids();
        assert!(
            refreshed.contains(&TopicId::from_entity(subscribed.as_bytes())),
            "Full still refreshes subscribed topics"
        );
        assert!(
            refreshed.contains(&TopicId::from_entity(passthrough.as_bytes())),
            "Full must still call set_topic_peers for pass-through topic ids"
        );
        let snap = manager.participation_snapshot();
        assert_eq!(snap.mode, ParticipationMode::Full);
        assert!(snap.passthrough_refresh_ran);
        assert_eq!(snap.passthrough_refresh_runs, 1);
    }

    fn passthrough_frame(kind: MessageKind, topic: TopicId) -> Bytes {
        let msg = saorsa_gossip_pubsub::GossipMessage {
            header: MessageHeader {
                version: 1,
                topic,
                msg_id: [0u8; 32],
                kind,
                hop: 0,
                ttl: 10,
                payload_hash: None,
            },
            payload: None,
            signature: Vec::new(),
            public_key: Vec::new(),
        };
        postcard::to_stdvec(&msg)
            .expect("passthrough frame serializes")
            .into()
    }

    #[tokio::test]
    async fn leaf_refuses_graft_and_eager_for_unsubscribed_topic_ids() {
        // Why (#380 C0): inbound EAGER/IHAVE/IWANT create pass-through
        // PlumTree state and local GRAFT even when refresh is skipped.
        let node = test_node().await;
        let manager = PubSubManager::new_with_participation(
            node,
            None,
            None,
            ParticipationMode::Leaf,
            "default_leaf",
        )
        .expect("manager");
        let subscribed = "x0x/caps/v1";
        let passthrough = "x0x.groups.public.v1";
        let _sub = manager.subscribe(subscribed.to_string()).await;
        let peer = PeerId::new([7; 32]);
        let passthrough_id = TopicId::from_entity(passthrough.as_bytes());

        for kind in [MessageKind::Eager, MessageKind::IHave, MessageKind::IWant] {
            manager
                .handle_incoming(peer, passthrough_frame(kind, passthrough_id))
                .await;
        }

        let snap = manager.participation_snapshot();
        assert_eq!(snap.unsubscribed_refused_frames, 3);
        assert_eq!(snap.unsubscribed_refused_graft_equiv, 3);
        assert!(
            snap.unsubscribed_refused_bytes > 0,
            "refused frames must count inbound bytes"
        );
        let known = manager.plumtree.all_topic_ids().await;
        assert!(
            !known.contains(&passthrough_id),
            "Leaf must not let unsubscribed GRAFT/eager reach PlumTree"
        );
        assert_eq!(
            snap.relay_bytes_semantics, RELAY_BYTES_SEMANTICS,
            "relay_bytes means non-subscribed forward"
        );
    }

    #[tokio::test]
    async fn leaf_still_accepts_subscribed_topic_passthrough_frames() {
        let node = test_node().await;
        let manager = PubSubManager::new_with_participation(
            node,
            None,
            None,
            ParticipationMode::Leaf,
            "default_leaf",
        )
        .expect("manager");
        let subscribed = "x0x/dm/v1/inbox/self";
        let mut sub = manager.subscribe(subscribed.to_string()).await;
        let peer = PeerId::new([3; 32]);
        let subscribed_id = TopicId::from_entity(subscribed.as_bytes());

        manager
            .handle_incoming(peer, passthrough_frame(MessageKind::Eager, subscribed_id))
            .await;

        let snap = manager.participation_snapshot();
        assert_eq!(
            snap.unsubscribed_refused_frames, 0,
            "subscribed topics must still reach PlumTree on Leaf"
        );
        manager
            .publish(subscribed.to_string(), Bytes::from("still-works"))
            .await
            .expect("leaf subscribed publish");
        let msg = sub.recv().await.expect("leaf subscribed delivery");
        assert_eq!(msg.payload, Bytes::from("still-works"));
    }

    #[tokio::test]
    async fn full_still_accepts_unsubscribed_passthrough_frames() {
        let node = test_node().await;
        let manager = PubSubManager::new_with_participation(
            node,
            None,
            None,
            ParticipationMode::Full,
            "operator_relay",
        )
        .expect("manager");
        let passthrough = "x0x.groups.public.v1";
        let peer = PeerId::new([9; 32]);
        let passthrough_id = TopicId::from_entity(passthrough.as_bytes());

        manager
            .handle_incoming(peer, passthrough_frame(MessageKind::Eager, passthrough_id))
            .await;

        let snap = manager.participation_snapshot();
        assert_eq!(
            snap.unsubscribed_refused_frames, 0,
            "Full must keep today's unsubscribed pass-through"
        );
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

    // -----------------------------------------------------------------------
    // Replay protection tests (protection is in saorsa-gossip PlumTree layer)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_multiple_subscribers_not_starved_by_replay_cache() {
        // Regression test: a shared replay cache at the subscriber level
        // would cause only 1 of N subscribers to receive each message.
        // With replay detection in PlumTree (before fan-out), all
        // subscribers must receive every legitimate message.
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let mut sub1 = manager.subscribe("multi".to_string()).await;
        let mut sub2 = manager.subscribe("multi".to_string()).await;
        let mut sub3 = manager.subscribe("multi".to_string()).await;

        manager
            .publish("multi".to_string(), Bytes::from("msg-a"))
            .await
            .expect("publish a");

        let m1 = sub1.recv().await.expect("sub1");
        let m2 = sub2.recv().await.expect("sub2");
        let m3 = sub3.recv().await.expect("sub3");
        assert_eq!(m1.payload, Bytes::from("msg-a"));
        assert_eq!(m2.payload, Bytes::from("msg-a"));
        assert_eq!(m3.payload, Bytes::from("msg-a"));
    }

    #[tokio::test]
    async fn test_local_duplicate_publishes_are_delivered() {
        // Local publishes are trusted — the replay cache only gates
        // network-incoming messages (handle_eager). An agent that
        // intentionally publishes the same content twice should see
        // both deliveries locally.
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let mut sub = manager.subscribe("dedup".to_string()).await;

        manager
            .publish("dedup".to_string(), Bytes::from("hello"))
            .await
            .expect("publish 1");
        manager
            .publish("dedup".to_string(), Bytes::from("hello"))
            .await
            .expect("publish 2 (same content, intentional)");

        let msg1 = sub.recv().await.expect("should receive first message");
        assert_eq!(msg1.payload, Bytes::from("hello"));

        let msg2 = sub.recv().await.expect("should receive second message");
        assert_eq!(
            msg2.payload,
            Bytes::from("hello"),
            "Local duplicate publishes should both be delivered"
        );
    }

    #[tokio::test]
    #[ignore = "stress: publishes 100k messages to prove slow-subscriber isolation"]
    async fn test_slow_subscriber_isolated_at_100k_messages() {
        use tokio::time::{timeout, Duration};

        const MESSAGES: usize = 100_000;
        let node = test_node().await;
        let manager = Arc::new(PubSubManager::new(node, None).expect("manager"));
        let _slow = manager.subscribe("slow-consumer".to_string()).await;
        let mut fast = manager.subscribe("slow-consumer".to_string()).await;

        let fast_task = tokio::spawn(async move {
            let mut received = 0usize;
            while received < MESSAGES {
                let Some(_msg) = fast.recv().await else {
                    break;
                };
                received += 1;
            }
            received
        });

        for i in 0..MESSAGES {
            manager
                .publish("slow-consumer".to_string(), Bytes::from(format!("msg-{i}")))
                .await
                .expect("publish");
            if i % 256 == 0 {
                tokio::task::yield_now().await;
            }
        }

        let fast_received = timeout(Duration::from_secs(30), fast_task)
            .await
            .expect("fast subscriber timed out")
            .expect("fast task join failed");
        let stats = manager.stats();

        if let Ok(path) = std::env::var("X0X_SLOW_CONSUMER_PROOF") {
            let body = serde_json::json!({
                "messages": MESSAGES,
                "publish_total": stats.publish_total,
                "delivered_to_subscriber": stats.delivered_to_subscriber,
                "slow_subscriber_dropped": stats.slow_subscriber_dropped,
                "subscriber_channel_closed": stats.subscriber_channel_closed,
                "decode_to_delivery_drops": stats.decode_to_delivery_drops,
                "fast_received": fast_received,
            });
            std::fs::write(path, serde_json::to_vec_pretty(&body).expect("proof json"))
                .expect("write proof json");
        }

        assert_eq!(
            stats.publish_total, MESSAGES as u64,
            "publisher must reach full publish_total without stalling"
        );
        assert!(
            stats.slow_subscriber_dropped >= 1,
            "slow subscriber should be dropped once its 10k buffer fills"
        );
        assert!(
            stats.subscriber_channel_closed >= 1,
            "slow subscriber drop should be accounted as closed for delivery deltas"
        );
        assert_eq!(
            fast_received, MESSAGES,
            "fast subscriber must still receive all {} messages",
            MESSAGES
        );
    }

    // ── PubSubStats ────────────────────────────────────────────────────

    #[test]
    fn pubsub_stats_default_is_zero() {
        let stats = PubSubStats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.publish_total, 0);
        assert_eq!(snap.publish_failed, 0);
        assert_eq!(snap.incoming_total, 0);
        assert_eq!(snap.incoming_decoded, 0);
        assert_eq!(snap.incoming_decode_failed, 0);
        assert_eq!(snap.delivered_to_subscriber, 0);
        assert_eq!(snap.slow_subscriber_dropped, 0);
        assert_eq!(snap.subscriber_channel_closed, 0);
        assert_eq!(snap.publish_zero_fanout, 0);
    }

    /// Why (#296): `fan_out == 0` with no connected peers is the solo /
    /// first-node case — count it, but do not warn.
    #[test]
    fn zero_fanout_solo_increments_counter_without_warn() {
        let stats = PubSubStats::default();
        let mut last = HashMap::new();
        let now = Instant::now();
        let warn = observe_zero_fanout_publish(
            &stats,
            &mut last,
            "group-a",
            0,
            0,
            now,
            ZERO_FANOUT_WARN_WINDOW,
        );
        assert!(!warn, "peer_count == 0 must skip the warn");
        assert_eq!(stats.snapshot().publish_zero_fanout, 1);
    }

    /// Why (#296): peers exist but eager fan-out is empty (all cooled) —
    /// that is the black-hole. Count + warn once per group/window.
    #[test]
    fn zero_fanout_with_peers_warns_once_per_window() {
        let stats = PubSubStats::default();
        let mut last = HashMap::new();
        let now = Instant::now();
        let first = observe_zero_fanout_publish(
            &stats,
            &mut last,
            "group-a",
            0,
            1,
            now,
            ZERO_FANOUT_WARN_WINDOW,
        );
        let second = observe_zero_fanout_publish(
            &stats,
            &mut last,
            "group-a",
            0,
            1,
            now + Duration::from_secs(1),
            ZERO_FANOUT_WARN_WINDOW,
        );
        let other = observe_zero_fanout_publish(
            &stats,
            &mut last,
            "group-b",
            0,
            2,
            now,
            ZERO_FANOUT_WARN_WINDOW,
        );
        assert!(first, "first zero-fanout with peers must warn");
        assert!(!second, "same group inside the window must not warn again");
        assert!(other, "a different group has its own warn window");
        assert_eq!(stats.snapshot().publish_zero_fanout, 3);
    }

    /// Why (#296): healthy fan-out must not increment the black-hole counter.
    #[test]
    fn healthy_fanout_leaves_zero_fanout_counter_unchanged() {
        let stats = PubSubStats::default();
        let mut last = HashMap::new();
        let warn = observe_zero_fanout_publish(
            &stats,
            &mut last,
            "group-a",
            1,
            1,
            Instant::now(),
            ZERO_FANOUT_WARN_WINDOW,
        );
        assert!(!warn);
        assert_eq!(stats.snapshot().publish_zero_fanout, 0);
    }

    #[tokio::test]
    async fn publish_with_fanout_is_zero_when_eager_set_is_empty() {
        let node = test_node().await;
        let manager = PubSubManager::new(node, None).expect("manager");
        let fan_out = manager
            .publish_with_fanout("empty-eager".to_string(), Bytes::from("nobody"))
            .await
            .expect("publish");
        assert_eq!(fan_out, 0, "solo node has no eager peers");
    }

    #[test]
    fn pubsub_stats_tracks_publish_via_fetch_add() {
        let stats = PubSubStats::default();
        stats
            .publish_total
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        stats
            .publish_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.publish_total, 2);
        assert_eq!(snap.publish_failed, 1);
    }

    #[test]
    fn pubsub_stats_tracks_incoming_via_fetch_add() {
        let stats = PubSubStats::default();
        stats
            .incoming_total
            .fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        stats
            .incoming_decoded
            .fetch_add(4, std::sync::atomic::Ordering::Relaxed);
        stats
            .incoming_decode_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.incoming_total, 5);
        assert_eq!(snap.incoming_decoded, 4);
        assert_eq!(snap.incoming_decode_failed, 1);
    }

    #[test]
    fn pubsub_stats_tracks_delivery_via_fetch_add() {
        let stats = PubSubStats::default();
        stats
            .delivered_to_subscriber
            .fetch_add(10, std::sync::atomic::Ordering::Relaxed);
        stats
            .slow_subscriber_dropped
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        stats
            .subscriber_channel_closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.delivered_to_subscriber, 10);
        assert_eq!(snap.slow_subscriber_dropped, 2);
        assert_eq!(snap.subscriber_channel_closed, 1);
    }

    #[test]
    fn pubsub_stats_computes_in_flight_decode() {
        let stats = PubSubStats::default();
        stats
            .incoming_total
            .fetch_add(10, std::sync::atomic::Ordering::Relaxed);
        stats
            .incoming_decoded
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        stats
            .incoming_decode_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.in_flight_decode, 2);
    }

    #[test]
    fn pubsub_stats_computes_decode_to_delivery_drops() {
        let stats = PubSubStats::default();
        stats
            .incoming_decoded
            .fetch_add(10, std::sync::atomic::Ordering::Relaxed);
        stats
            .delivered_to_subscriber
            .fetch_add(6, std::sync::atomic::Ordering::Relaxed);
        stats
            .subscriber_channel_closed
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.decode_to_delivery_drops, 2);
    }

    #[test]
    fn c5b_prefers_one_connected_coordinator_over_relays() {
        let plane = [[1; 32], [2; 32], [3; 32]];
        let coordinators = [[9; 32], [2; 32]];
        let relays = [[1; 32]];
        let pinned = std::collections::HashSet::new();
        assert_eq!(
            select_one_full_bootstrap_eager_peer(&plane, &coordinators, &relays, &pinned),
            Some([2; 32]),
            "C5b must prefer one Full/bootstrap coordinator already on the plane"
        );
    }

    #[test]
    fn c5b_skips_eager_prefer_when_no_full_bootstrap_is_connected() {
        let plane = [[1; 32], [2; 32]];
        let coordinators = [[9; 32]];
        let relays = [[8; 32]];
        let pinned = std::collections::HashSet::new();
        assert_eq!(
            select_one_full_bootstrap_eager_peer(&plane, &coordinators, &relays, &pinned),
            None,
            "no Full/bootstrap on the plane must leave topic membership unchanged"
        );
    }
}
