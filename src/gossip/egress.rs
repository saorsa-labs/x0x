use super::config::GossipConfig;
use crate::network::NetworkNode;
use bytes::Bytes;
use saorsa_gossip_pubsub::OutboundTopicMeterSnapshot;
use saorsa_gossip_transport::{AuthenticatedSession, GossipStreamType, GossipTransport};
use saorsa_gossip_types::{MessageHeader, MessageKind, PeerId, TopicId};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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
    pub repair_msgs: AtomicU64,
    pub repair_bytes: AtomicU64,
    repair_requests: RepairRequests,
    pub repair_tracking_overflow: AtomicU64,
    #[cfg(test)]
    pub recorder: std::sync::Mutex<Option<Recorder>>,
    #[cfg(test)]
    session_override: Mutex<Option<AuthenticatedSession>>,
    #[cfg(test)]
    pub remote_send_pause: Mutex<RemoteSendPause>,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct Recorder {
    pub peers: Vec<PeerId>,
    pub sends: Vec<(PeerId, Bytes)>,
}

#[cfg(test)]
type RemoteSendPause = Option<(
    TopicId,
    Arc<tokio::sync::Barrier>,
    Arc<tokio::sync::Barrier>,
)>;

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
            #[cfg(test)]
            session_override: Mutex::new(None),
            #[cfg(test)]
            remote_send_pause: Mutex::new(None),
        }
    }

    #[cfg(test)]
    async fn wait_remote_send_pause(&self, data: &[u8]) {
        let gates = {
            let mut pause = self
                .remote_send_pause
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let matches = pause.as_ref().is_some_and(|(topic, _, _)| {
                postcard::take_from_bytes::<MessageHeader>(data).is_ok_and(|(header, _)| {
                    header.topic == *topic && header.kind == MessageKind::Eager
                })
            });
            if matches {
                pause.take().map(|(_, entered, release)| (entered, release))
            } else {
                None
            }
        };
        if let Some((entered, release)) = gates {
            entered.wait().await;
            release.wait().await;
        }
    }

    #[cfg(test)]
    pub(super) fn set_session_override(&self, session: Option<AuthenticatedSession>) {
        *self
            .session_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = session;
    }

    /// Does not verify the frame's ML-DSA signature (#656):
    /// `plumtree.handle_message` verifies the same bytes right after this call
    /// and ignores unauthenticated IWANTs, so a forged IWANT cannot inflate
    /// counters beyond what its own rejected frame would draw. The structural
    /// gates remain: exact `GossipMessage` decode, `IWant` kind, v2 header,
    /// payload-hash binding, and decodable id list.
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
        #[cfg(test)]
        self.wait_remote_send_pause(&data).await;
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

    fn authenticated_session(&self, peer: PeerId) -> Option<AuthenticatedSession> {
        #[cfg(test)]
        if let Some(session) = *self
            .session_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            if session.peer == peer {
                return Some(session);
            }
        }
        self.network.authenticated_session(peer)
    }

    async fn send_to_peer_guarded(
        &self,
        peer: PeerId,
        stream: GossipStreamType,
        admit: saorsa_gossip_transport::SessionAdmission,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(recorder) = self.recorder.lock().expect("recorder").as_mut() {
            let bytes = admit(self.network.authenticated_session(peer).unwrap_or(
                AuthenticatedSession {
                    peer,
                    generation: 0,
                },
            ))
            .map_err(|e| anyhow::anyhow!("test admit refused: {e}"))?;
            recorder.sends.push((peer, bytes));
            return Ok(());
        }
        self.network.send_to_peer_guarded(peer, stream, admit).await
    }

    async fn receive_message_with_session(
        &self,
    ) -> anyhow::Result<(
        PeerId,
        GossipStreamType,
        Bytes,
        Option<AuthenticatedSession>,
    )> {
        self.network.receive_message_with_session().await
    }
}

/// How long the Leaf hard egress budget must stay exceeded, sample after
/// sample, before `/status` and `x0x status` warn about it (#1964).
pub const SUSTAINED_EGRESS_EXCEED_SECS: u64 = 60;

/// Largest gap between two samples that still continues an over-budget
/// run. A longer gap (a stalled 1 s tick) restarts the run, so a stall is
/// never counted as time over the budget.
const MAX_SAMPLE_GAP_SECS: u64 = 5;

/// Rate window of [`EgressMeter`], in seconds.
const EGRESS_WINDOW_SECS: u64 = 60;

/// Topics named in [`EgressBudgetWarning::top_topics`].
const WARNING_TOP_TOPICS: usize = 3;

/// The wire kinds the meter counts, in [`KindBytes`] index order.
const KIND_LABELS: [&str; 4] = ["eager", "ihave", "iwant", "anti_entropy"];

/// Per-kind byte counts, indexed like [`KIND_LABELS`].
type KindBytes = [u64; 4];

/// One subscribed topic's share of the 60 s egress window.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EgressTopicUsage {
    /// Subscribed topic name, or `unknown-hex` when no name is stored.
    pub name: String,
    /// Display form of the topic ID (first 8 bytes, hex).
    pub topic_id_hex8: String,
    /// x0x admission class of the name: `critical`, `normal`, `bulk`, or
    /// `unknown` for an unnamed topic.
    pub priority: String,
    /// Average bytes per second over the window, all kinds.
    pub bytes_per_sec: f64,
    /// Average bytes per second over the window, per wire kind.
    pub by_kind: BTreeMap<String, f64>,
}

/// Present while the Leaf hard egress budget has been exceeded on every
/// sample for at least [`SUSTAINED_EGRESS_EXCEED_SECS`] (#1964).
///
/// It is observation only. Nothing is capped because of it. Under the
/// default `byte_policy = "observe_only"` saorsa-gossip defers nothing.
/// Under `"shed_normal"` it can defer only forwarded (not locally
/// originated) traffic on Normal/Bulk topics: EAGER relays, IHAVE/IWANT,
/// anti-entropy digests and serves of other nodes' messages. Local
/// publishes and serves of them, Critical topics, own-inbox delivery and
/// targeted sends are never held back by this budget.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EgressBudgetWarning {
    /// Seconds from the first to the latest sample of the current
    /// over-budget run. A gap of more than 5 s between samples restarts
    /// the run, so a stalled sampler does not extend it.
    pub exceeded_for_secs: u64,
    /// [`SUSTAINED_EGRESS_EXCEED_SECS`].
    pub threshold_secs: u64,
    /// Subscribed-topic egress, 60 s average, bytes per second.
    pub rate_bytes_per_sec_60s: f64,
    /// Configured `leaf_egress_hard_bytes_per_sec`.
    pub hard_bytes_per_sec: u64,
    /// Effective byte policy (`observe_only` or `shed_normal`).
    pub byte_policy: String,
    /// The heaviest subscribed topics in the window, largest first.
    pub top_topics: Vec<EgressTopicUsage>,
    /// Bytes per second per wire kind over the window, all subscribed topics.
    pub by_kind: BTreeMap<String, f64>,
    /// The one-line warning that `/status` also puts in `warnings`.
    pub message: String,
}

#[derive(Default)]
pub(super) struct EgressMeter {
    previous: HashMap<String, KindBytes>,
    samples: VecDeque<(Instant, u64)>,
    /// Per-topic, per-kind deltas of subscribed topics that moved bytes,
    /// with the same 60 s expiry as `samples`.
    topic_samples: VecDeque<(Instant, Vec<(String, KindBytes)>)>,
    /// First sample of the current unbroken run above the hard budget.
    hard_exceeded_since: Option<Instant>,
    pub rate: f64,
    pub soft_exceeded: u64,
    pub hard_exceeded: u64,
    pub sampled_at: Option<Instant>,
}

impl EgressMeter {
    pub fn sample(
        &mut self,
        now: Instant,
        rows: &BTreeMap<String, OutboundTopicMeterSnapshot>,
        subscribed: &HashSet<String>,
        config: &GossipConfig,
    ) {
        let mut delta = 0u64;
        let mut topic_deltas = Vec::new();
        for (topic, kinds) in rows {
            let bytes: KindBytes = [
                kinds.eager.bytes,
                kinds.ihave.bytes,
                kinds.iwant.bytes,
                kinds.anti_entropy.bytes,
            ];
            let old = self
                .previous
                .insert(topic.clone(), bytes)
                .unwrap_or_default();
            if subscribed.contains(topic) {
                let mut kind_delta = KindBytes::default();
                for (slot, (new, old)) in kind_delta.iter_mut().zip(bytes.iter().zip(old.iter())) {
                    *slot = new.saturating_sub(*old);
                }
                let topic_delta = kind_delta
                    .iter()
                    .fold(0u64, |sum, b| sum.saturating_add(*b));
                delta = delta.saturating_add(topic_delta);
                if topic_delta > 0 {
                    topic_deltas.push((topic.clone(), kind_delta));
                }
            }
        }
        let window = Duration::from_secs(EGRESS_WINDOW_SECS);
        self.samples.push_back((now, delta));
        while self
            .samples
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= window)
        {
            self.samples.pop_front();
        }
        self.topic_samples.push_back((now, topic_deltas));
        while self
            .topic_samples
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= window)
        {
            self.topic_samples.pop_front();
        }
        self.rate = self
            .samples
            .iter()
            .map(|(_, bytes)| *bytes as f64)
            .sum::<f64>()
            / EGRESS_WINDOW_SECS as f64;
        let stalled = self.sampled_at.is_some_and(|last| {
            now.saturating_duration_since(last) > Duration::from_secs(MAX_SAMPLE_GAP_SECS)
        });
        self.sampled_at = Some(now);
        let mut hard_over = false;
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
                hard_over = true;
            }
        }
        if hard_over && stalled {
            self.hard_exceeded_since = Some(now);
        } else if hard_over {
            self.hard_exceeded_since.get_or_insert(now);
        } else {
            self.hard_exceeded_since = None;
        }
    }

    /// How long the hard budget has been exceeded on every sample, once
    /// that run has lasted [`SUSTAINED_EGRESS_EXCEED_SECS`]; `None` before
    /// that and as soon as one sample is back under the budget.
    ///
    /// The run ends at the last sample, not at the time of the query, and a
    /// gap of more than `MAX_SAMPLE_GAP_SECS` between samples restarts it:
    /// a stalled 1 s tick, before or inside a run, is never counted as time
    /// over the budget. If the tick stops for good the last result stays.
    pub fn sustained_hard_exceed(&self) -> Option<Duration> {
        let since = self.hard_exceeded_since?;
        let last = self.sampled_at?;
        let run = last.saturating_duration_since(since);
        (run >= Duration::from_secs(SUSTAINED_EGRESS_EXCEED_SECS)).then_some(run)
    }

    /// The sustained-exceed warning, or `None` while the run is shorter
    /// than [`SUSTAINED_EGRESS_EXCEED_SECS`] or there is no run.
    ///
    /// `names` maps a topic ID display string to its subscribed name.
    pub fn warning(
        &self,
        hard_bytes_per_sec: u64,
        byte_policy: &str,
        names: &HashMap<String, String>,
    ) -> Option<EgressBudgetWarning> {
        let run = self.sustained_hard_exceed()?;
        let window = EGRESS_WINDOW_SECS as f64;
        let mut per_topic: BTreeMap<&str, KindBytes> = BTreeMap::new();
        for (_, rows) in &self.topic_samples {
            for (topic, kinds) in rows {
                let sum = per_topic.entry(topic.as_str()).or_default();
                for (slot, add) in sum.iter_mut().zip(kinds.iter()) {
                    *slot = slot.saturating_add(*add);
                }
            }
        }
        let mut totals = KindBytes::default();
        for kinds in per_topic.values() {
            for (slot, add) in totals.iter_mut().zip(kinds.iter()) {
                *slot = slot.saturating_add(*add);
            }
        }
        let by_kind_of = |kinds: &KindBytes| {
            KIND_LABELS
                .iter()
                .zip(kinds.iter())
                .map(|(label, bytes)| ((*label).to_string(), *bytes as f64 / window))
                .collect::<BTreeMap<_, _>>()
        };
        let mut ranked = per_topic.into_iter().collect::<Vec<_>>();
        ranked.sort_by(|(a_id, a), (b_id, b)| {
            let a_sum = a.iter().fold(0u64, |s, x| s.saturating_add(*x));
            let b_sum = b.iter().fold(0u64, |s, x| s.saturating_add(*x));
            b_sum.cmp(&a_sum).then_with(|| a_id.cmp(b_id))
        });
        let top_topics = ranked
            .into_iter()
            .take(WARNING_TOP_TOPICS)
            .map(|(id, kinds)| {
                let name = names.get(id).cloned();
                let priority = name
                    .as_deref()
                    .map(|name| {
                        match super::pubsub::classify_x0x_topic(name) {
                            saorsa_gossip_types::TopicPriority::Critical => "critical",
                            saorsa_gossip_types::TopicPriority::Normal => "normal",
                            saorsa_gossip_types::TopicPriority::Bulk => "bulk",
                        }
                        .to_string()
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                EgressTopicUsage {
                    name: name.unwrap_or_else(|| "unknown-hex".to_string()),
                    topic_id_hex8: id.to_string(),
                    priority,
                    bytes_per_sec: kinds.iter().fold(0u64, |s, x| s.saturating_add(*x)) as f64
                        / window,
                    by_kind: by_kind_of(&kinds),
                }
            })
            .collect::<Vec<_>>();
        let tops = top_topics
            .iter()
            .map(|topic| {
                let kind = topic
                    .by_kind
                    .iter()
                    .max_by(|a, b| a.1.total_cmp(b.1))
                    .map(|(kind, _)| kind.as_str())
                    .unwrap_or("eager");
                format!(
                    "{} ({}, mostly {kind}) {}",
                    topic.name,
                    topic.priority,
                    human_bits_per_sec(topic.bytes_per_sec)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let policy_effect = policy_effect(byte_policy);
        let message = format!(
            "gossip egress has exceeded the Leaf hard budget for {} s: {} (60 s average of \
             subscribed topics) against {}; top topics: {}. {policy_effect} (#1964)",
            run.as_secs(),
            human_bits_per_sec(self.rate),
            human_bits_per_sec(hard_bytes_per_sec as f64),
            if tops.is_empty() { "none" } else { &tops },
        );
        Some(EgressBudgetWarning {
            exceeded_for_secs: run.as_secs(),
            threshold_secs: SUSTAINED_EGRESS_EXCEED_SECS,
            rate_bytes_per_sec_60s: self.rate,
            hard_bytes_per_sec,
            byte_policy: byte_policy.to_string(),
            top_topics,
            by_kind: by_kind_of(&totals),
            message,
        })
    }
}

/// What the effective byte policy does about an exceeded budget.
fn policy_effect(byte_policy: &str) -> String {
    if byte_policy == super::config::LeafBytePolicy::ShedNormal.as_str() {
        format!(
            "byte_policy \"{byte_policy}\" can defer only forwarded (not locally \
             originated) traffic on Normal/Bulk topics: EAGER relays, IHAVE/IWANT, \
             anti-entropy digests and serves of other nodes' messages; local publishes and \
             serves of them, Critical topics, own-inbox delivery and targeted sends are never \
             held back, so that part is not capped"
        )
    } else {
        format!(
            "byte_policy \"{byte_policy}\" measures only and defers nothing, so none of this \
             traffic is capped; \"shed_normal\" could defer only forwarded (not locally \
             originated) traffic on Normal/Bulk topics, never local publishes or serves of \
             them, Critical topics, own-inbox delivery or targeted sends"
        )
    }
}

/// Bytes per second as a short bits-per-second string (`2.1 Mbps`).
fn human_bits_per_sec(bytes_per_sec: f64) -> String {
    let bits = (bytes_per_sec * 8.0).max(0.0);
    if bits >= 1_000_000.0 {
        format!("{:.1} Mbps", bits / 1_000_000.0)
    } else if bits >= 1_000.0 {
        format!("{:.1} kbps", bits / 1_000.0)
    } else {
        format!("{} bps", bits as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saorsa_gossip_pubsub::OutboundKindMeterSnapshot;

    fn topic_meter(
        eager: u64,
        ihave: u64,
        iwant: u64,
        anti_entropy: u64,
    ) -> OutboundTopicMeterSnapshot {
        let kind = |label, bytes| OutboundKindMeterSnapshot {
            label,
            msgs: 0,
            bytes,
        };
        OutboundTopicMeterSnapshot {
            eager: kind("eager", eager),
            ihave: kind("ihave", ihave),
            iwant: kind("iwant", iwant),
            anti_entropy: kind("anti_entropy", anti_entropy),
        }
    }

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
        let rows = BTreeMap::from([
            ("bus".to_string(), topic_meter(600, 0, 60, 0)),
            ("other".to_string(), topic_meter(60_000, 0, 0, 0)),
        ]);
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
            &BTreeMap::from([("bus".to_string(), topic_meter(60_000, 0, 0, 0))]),
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

    #[test]
    fn previously_unsubscribed_topic_counts_only_new_bytes_after_subscription() {
        let mut meter = EgressMeter::default();
        let config = GossipConfig::default();
        let now = Instant::now();
        let initial = BTreeMap::from([("bus".to_string(), topic_meter(100, 20, 3, 7))]);
        meter.sample(now, &initial, &HashSet::new(), &config);
        assert_eq!(meter.rate, 0.0);

        let subscribed = HashSet::from(["bus".to_string()]);
        meter.sample(now + Duration::from_secs(1), &initial, &subscribed, &config);
        assert_eq!(
            meter.rate, 0.0,
            "earlier unsubscribed traffic is the baseline"
        );

        let later = BTreeMap::from([("bus".to_string(), topic_meter(105, 22, 4, 8))]);
        meter.sample(now + Duration::from_secs(2), &later, &subscribed, &config);
        assert_eq!(meter.rate, 9.0 / 60.0, "all four new wire-kind bytes count");
    }

    fn sustained_config() -> GossipConfig {
        GossipConfig {
            leaf_egress_soft_bytes_per_sec: 1,
            leaf_egress_hard_bytes_per_sec: 50,
            ..Default::default()
        }
    }

    /// Feeds `per_sec` eager bytes on `bus` as one sample per second over
    /// `secs` (offsets from `start`), advancing the cumulative `total`.
    fn feed(
        meter: &mut EgressMeter,
        start: Instant,
        secs: std::ops::Range<u64>,
        total: &mut u64,
        per_sec: u64,
        config: &GossipConfig,
    ) {
        let subscribed = HashSet::from(["bus".to_string()]);
        for sec in secs {
            *total += per_sec;
            let rows = BTreeMap::from([("bus".to_string(), topic_meter(*total, 0, 0, 0))]);
            meter.sample(start + Duration::from_secs(sec), &rows, &subscribed, config);
        }
    }

    /// WHY (#1964): a warning must mean "over the hard budget on every
    /// sample for 60 s", not one burst; it must appear at 60 s, not before.
    #[test]
    fn sustained_exceed_enters_after_60s_and_not_before() {
        let config = sustained_config();
        let mut meter = EgressMeter::default();
        let start = Instant::now();
        let mut total = 0;
        let names = HashMap::from([("bus".to_string(), "x0x.identity.announce.v2".to_string())]);
        // 60 s window: 6_000 B/s once warm; the first sample alone is
        // already 6_000 / 60 = 100 B/s, over the 50 B/s hard budget.
        feed(&mut meter, start, 0..60, &mut total, 6_000, &config);
        assert!(
            meter.sustained_hard_exceed().is_none(),
            "59 s is not sustained"
        );
        assert!(meter.warning(50, "observe_only", &names).is_none());

        feed(&mut meter, start, 60..61, &mut total, 6_000, &config);
        assert_eq!(
            meter.sustained_hard_exceed(),
            Some(Duration::from_secs(SUSTAINED_EGRESS_EXCEED_SECS))
        );
        let warning = meter
            .warning(50, "shed_normal", &names)
            .expect("60 s over budget warns");
        assert_eq!(warning.exceeded_for_secs, 60);
        assert_eq!(warning.threshold_secs, SUSTAINED_EGRESS_EXCEED_SECS);
        assert_eq!(warning.top_topics.len(), 1);
        let top = &warning.top_topics[0];
        assert_eq!(top.name, "x0x.identity.announce.v2");
        assert_eq!(top.priority, "critical");
        assert_eq!(top.by_kind["eager"], 6_000.0);
        assert_eq!(warning.by_kind["eager"], 6_000.0);
        assert!(warning
            .message
            .contains("x0x.identity.announce.v2 (critical, mostly eager)"));
        assert!(warning.message.contains(
            "\"shed_normal\" can defer only forwarded (not locally originated) traffic on \
             Normal/Bulk topics: EAGER relays, IHAVE/IWANT, anti-entropy digests and serves of \
             other nodes' messages; local publishes and serves of them, Critical topics, \
             own-inbox delivery and targeted sends are never held back"
        ));
        assert!(
            !warning
                .message
                .contains("IWANT/anti-entropy serves are never"),
            "sg can defer forwarded IWANT/anti-entropy traffic under shed_normal"
        );
    }

    /// WHY (#1964 review): under the default `observe_only` nothing is
    /// deferred at all, so the warning must not claim that it defers
    /// forwarded traffic.
    #[test]
    fn sustained_exceed_message_matches_observe_only() {
        let config = sustained_config();
        let mut meter = EgressMeter::default();
        let start = Instant::now();
        let mut total = 0;
        feed(&mut meter, start, 0..61, &mut total, 6_000, &config);
        let warning = meter
            .warning(50, "observe_only", &HashMap::new())
            .expect("60 s over budget warns");
        assert!(warning.message.contains(
            "\"observe_only\" measures only and defers nothing, so none of this traffic is \
             capped; \"shed_normal\" could defer only forwarded (not locally originated) \
             traffic on Normal/Bulk topics, never local publishes or serves of them, Critical \
             topics, own-inbox delivery or targeted sends"
        ));
        assert!(!warning.message.contains("\"observe_only\" can defer"));
        assert_eq!(warning.top_topics[0].name, "unknown-hex");
        assert_eq!(warning.top_topics[0].priority, "unknown");
    }

    /// WHY (#1964 review): the run ends at the last sample. If the 1 s
    /// tick stalls after one over-budget sample, a later status read must
    /// not count the stall as time over the budget.
    #[test]
    fn stalled_sampling_does_not_extend_the_run() {
        let config = sustained_config();
        let mut meter = EgressMeter::default();
        let start = Instant::now();
        let mut total = 0;
        feed(&mut meter, start, 0..1, &mut total, 6_000, &config);
        assert_eq!(meter.hard_exceeded, 1, "the one sample is over budget");
        // No further samples: a read at +61 s (any read time) must not warn.
        assert!(meter.sustained_hard_exceed().is_none());
        assert!(meter.warning(50, "shed_normal", &HashMap::new()).is_none());
    }

    /// WHY (#1964 review): a stall between two over-budget samples must
    /// not count either; the run restarts after a gap longer than
    /// `MAX_SAMPLE_GAP_SECS` and needs a full 60 s of samples again.
    #[test]
    fn a_stall_inside_a_run_restarts_it() {
        let config = sustained_config();
        let mut meter = EgressMeter::default();
        let start = Instant::now();
        let mut total = 0;
        feed(&mut meter, start, 0..1, &mut total, 6_000, &config);
        // 300 s with no sample, then over budget again.
        feed(&mut meter, start, 300..360, &mut total, 6_000, &config);
        assert_eq!(meter.hard_exceeded, 61, "every sample was over budget");
        assert!(
            meter.sustained_hard_exceed().is_none(),
            "59 s since the restart, not 359 s"
        );
        feed(&mut meter, start, 360..361, &mut total, 6_000, &config);
        assert_eq!(
            meter.sustained_hard_exceed(),
            Some(Duration::from_secs(SUSTAINED_EGRESS_EXCEED_SECS))
        );
        // A gap of exactly MAX_SAMPLE_GAP_SECS still continues the run.
        feed(
            &mut meter,
            start,
            (361 + MAX_SAMPLE_GAP_SECS - 1)..(361 + MAX_SAMPLE_GAP_SECS),
            &mut total,
            6_000,
            &config,
        );
        assert_eq!(
            meter.sustained_hard_exceed(),
            Some(Duration::from_secs(60 + MAX_SAMPLE_GAP_SECS))
        );
    }

    /// WHY (#1964): one sample back under the budget ends the run, so the
    /// warning clears when the rate drops and the next run starts at zero.
    #[test]
    fn sustained_exceed_clears_on_recovery_and_restarts_the_run() {
        let config = sustained_config();
        let mut meter = EgressMeter::default();
        let start = Instant::now();
        let mut total = 0;
        feed(&mut meter, start, 0..90, &mut total, 6_000, &config);
        assert!(meter.sustained_hard_exceed().is_some());
        // Idle traffic: the 60 s average is back under 50 B/s once the
        // last 6_000 B sample (t = 89 s) has left the window at t = 149 s.
        feed(&mut meter, start, 90..150, &mut total, 0, &config);
        assert!(meter.rate <= 50.0, "rate {} must be back under", meter.rate);
        assert!(meter.sustained_hard_exceed().is_none());
        assert!(meter.warning(50, "observe_only", &HashMap::new()).is_none());
        // A fresh burst must wait a full 60 s again.
        feed(&mut meter, start, 150..170, &mut total, 60_000, &config);
        assert!(meter.sustained_hard_exceed().is_none());
    }

    /// WHY: Full nodes and a zero hard budget have no Leaf budget to exceed.
    #[test]
    fn sustained_exceed_never_starts_without_a_leaf_hard_budget() {
        let start = Instant::now();
        for config in [
            GossipConfig {
                leaf_egress_hard_bytes_per_sec: 0,
                leaf_egress_soft_bytes_per_sec: 0,
                ..Default::default()
            },
            GossipConfig {
                relay: true,
                ..sustained_config()
            },
        ] {
            let mut meter = EgressMeter::default();
            let mut total = 0;
            feed(&mut meter, start, 0..120, &mut total, 60_000, &config);
            assert!(meter.sustained_hard_exceed().is_none());
        }
    }

    mod track_iwant {
        use super::super::*;
        use crate::network::{NetworkConfig, NetworkNode};
        use bytes::Bytes;
        use saorsa_gossip_types::TopicId;
        use std::sync::Arc;

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

        #[tokio::test]
        async fn tracked_iwant_classifies_the_matching_repair_eager_send() {
            let transport = make_transport().await;
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
