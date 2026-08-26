//! Runtime service that consumes this agent's inbox topic, runs the
//! signature-first pipeline from `docs/design/dm-over-gossip.md`, and
//! bridges decrypted payloads into [`crate::direct::DirectMessaging`].

use crate::contacts::ContactStore;
use crate::direct::DirectMessaging;
use crate::dm::{
    decrypt_payload, dm_inbox_topic, now_unix_ms, validate_timestamp_window, DmAckOutcome, DmBody,
    DmEnvelope, DmOriginAttestation, DmPayload, EnvelopeBuilder, InFlightAcks, RecentDeliveryCache,
    DM_PROTOCOL_DURABLE_ACK, DM_PROTOCOL_V1, DM_PROTOCOL_VERSION, MAX_ENVELOPE_BYTES,
};
use crate::error::{NetworkError, NetworkResult};
use crate::gossip::{PubSubManager, PubSubMessage, SigningContext, Subscription};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::identity::{AgentId, MachineId, MachineKeypair};
use crate::network::NetworkNode;
use crate::revocation::RevocationSet;
use crate::trust::{TrustContext, TrustDecision, TrustEvaluator};
use async_trait::async_trait;
use bytes::Bytes;
use saorsa_gossip_types::TopicId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::{JoinHandle, JoinSet};

const ACK_ENVELOPE_LIFETIME_MS: u64 = 60_000;
/// The pinned pubsub Critical-priority contract permits ten seconds waiting
/// at its FIFO gate plus ten seconds for the send itself. Keep each durable
/// ACK route alive for that complete healthy-congestion budget plus slack.
const DURABLE_ACK_ROUTE_TIMEOUT: Duration = Duration::from_secs(22);
/// ACK envelopes are small, but the queue is bounded so a disconnected mesh
/// cannot turn sender retries into unbounded retained work.
const DURABLE_ACK_QUEUE_CAPACITY: usize = 256;
/// Bound the number of ACK jobs simultaneously holding pubsub fan-out work.
const DURABLE_ACK_MAX_CONCURRENT: usize = 32;

/// Outcome of the C5 live Direct/typed ACK hedge.
///
/// Direct send-ok is never a sender receipt. The waiter completes only when
/// the same v2 envelope arrives and matches `acks_request_id`. Missing Direct
/// is fail-open so the inbox + compatibility-bus gossip hedges still count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectAckHedgeOutcome {
    Sent,
    SkippedNoDirect,
    Failed,
}

/// Send the already-committed v2 ACK envelope on a live Direct/typed path.
///
/// Implementations must not treat a successful send as waiter completion and
/// must not fail the durable ACK when no Direct connection exists.
#[async_trait]
pub(crate) trait DirectAckHedge: Send + Sync {
    async fn hedge(&self, recipient: AgentId, encoded: Bytes) -> DirectAckHedgeOutcome;
}

/// Production C5 hedge: send the same v2 ACK envelope on live Direct/typed.
pub(crate) struct LiveDirectAckHedge {
    pub network: Arc<NetworkNode>,
    pub dm: Arc<DirectMessaging>,
    pub sender_agent_id: AgentId,
}

#[async_trait]
impl DirectAckHedge for LiveDirectAckHedge {
    async fn hedge(&self, recipient: AgentId, encoded: Bytes) -> DirectAckHedgeOutcome {
        let Some(machine) = self.dm.get_machine_id(&recipient).await else {
            return DirectAckHedgeOutcome::SkippedNoDirect;
        };
        let peer = ant_quic::PeerId(machine.0);
        if !self.network.is_connected(&peer).await {
            return DirectAckHedgeOutcome::SkippedNoDirect;
        }
        match self
            .network
            .send_direct(&peer, self.sender_agent_id.as_bytes(), encoded.as_ref())
            .await
        {
            Ok(()) => DirectAckHedgeOutcome::Sent,
            Err(_) => DirectAckHedgeOutcome::Failed,
        }
    }
}

/// How long the durable path waits for a typed-route handler to report
/// completion before withholding the ACK (ADR 0030 §7).
///
/// Deliberately shorter than the sender's per-attempt budget
/// (`DM_TIMEOUT_MAX_MS`, 30 s): waiting longer than the sender will wait can
/// only pin this receiver on an ACK nobody is still listening for. The
/// campaign draft instead waited out the envelope's remaining lifetime — up
/// to 120 s — inline on the serial inbox loop, which would stall every later
/// DM and ACK behind one slow handler. The budget is a receiver-side
/// liveness bound, not a correctness one: timing out withholds the ACK, and
/// the sender retries.
const DURABLE_TYPED_COMPLETION_TIMEOUT: Duration = Duration::from_secs(20);

const AUTHENTICATED_MACHINE_BINDING_CAPACITY: usize = 65_536;

#[derive(Debug, Clone, Copy)]
struct AuthenticatedMachineBinding {
    machine_id: MachineId,
    announced_at: u64,
    last_used: (std::time::Instant, u64),
}

/// Bounded LRU cache of authenticated agent→machine bindings.
///
/// Bindings survive reachability-cache eviction and are refreshed by accepted
/// identity announcements and inbound DMs. At the generous capacity ceiling,
/// the least-recently-used binding is evicted and every eviction is logged;
/// subsequent DMs from that agent degrade to the observable claim fallback.
#[derive(Debug)]
pub struct AuthenticatedMachineBindingCache {
    entries: std::collections::HashMap<AgentId, AuthenticatedMachineBinding>,
    capacity: usize,
    recency: std::collections::BTreeSet<(std::time::Instant, u64, [u8; 32])>,
    clock: u64,
}

impl Default for AuthenticatedMachineBindingCache {
    fn default() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            recency: std::collections::BTreeSet::new(),
            capacity: AUTHENTICATED_MACHINE_BINDING_CAPACITY,
            clock: 0,
        }
    }
}

impl AuthenticatedMachineBindingCache {
    #[cfg(test)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            recency: std::collections::BTreeSet::new(),
            capacity: capacity.max(1),
            clock: 0,
        }
    }

    fn next_tick(&mut self) -> (std::time::Instant, u64) {
        self.clock = self.clock.wrapping_add(1);
        (std::time::Instant::now(), self.clock)
    }

    fn record(&mut self, agent_id: AgentId, machine_id: MachineId, announced_at: u64) {
        let tick = self.next_tick();
        if let Some(mut existing) = self.entries.get(&agent_id).copied() {
            self.recency
                .remove(&(existing.last_used.0, existing.last_used.1, agent_id.0));
            existing.last_used = tick;
            if announced_at >= existing.announced_at {
                existing.machine_id = machine_id;
                existing.announced_at = announced_at;
            }
            self.entries.insert(agent_id, existing);
            self.recency.insert((tick.0, tick.1, agent_id.0));
            return;
        }

        if self.entries.len() >= self.capacity {
            let oldest = self.recency.first().copied();
            if let Some(oldest_key) = oldest {
                self.recency.remove(&oldest_key);
                let evicted_agent = AgentId(oldest_key.2);
                if let Some(evicted_binding) = self.entries.remove(&evicted_agent) {
                    tracing::warn!(
                        agent = %hex::encode(evicted_agent.as_bytes()),
                        machine = %hex::encode(evicted_binding.machine_id.as_bytes()),
                        capacity = self.capacity,
                        "authenticated machine binding evicted; future DMs degrade to claimed-machine fallback"
                    );
                }
            }
        }

        self.entries.insert(
            agent_id,
            AuthenticatedMachineBinding {
                machine_id,
                announced_at,
                last_used: tick,
            },
        );
        self.recency.insert((tick.0, tick.1, agent_id.0));
    }

    fn resolve(&mut self, agent_id: &AgentId) -> Option<MachineId> {
        let tick = self.next_tick();
        let mut binding = self.entries.get(agent_id).copied()?;
        self.recency
            .remove(&(binding.last_used.0, binding.last_used.1, agent_id.0));
        binding.last_used = tick;
        self.entries.insert(*agent_id, binding);
        self.recency.insert((tick.0, tick.1, agent_id.0));
        Some(binding.machine_id)
    }
}

/// Shared retained cache of authenticated agent→machine bindings.
pub type AuthenticatedMachineBindings = Arc<RwLock<AuthenticatedMachineBindingCache>>;

/// Retain the freshest accepted, authenticated agent→machine announcement.
///
/// This security binding intentionally outlives discovery/reachability cache
/// eviction. A later authenticated announcement can still move a portable
/// agent, while a replayed older announcement cannot roll the binding back.
pub(crate) async fn record_authenticated_machine_binding(
    bindings: &AuthenticatedMachineBindings,
    agent_id: AgentId,
    machine_id: MachineId,
    announced_at: u64,
) {
    bindings
        .write()
        .await
        .record(agent_id, machine_id, announced_at);
}

#[cfg(test)]
pub(crate) async fn authenticated_machine_binding_for_testing(
    bindings: &AuthenticatedMachineBindings,
    agent_id: &AgentId,
) -> Option<MachineId> {
    bindings.write().await.resolve(agent_id)
}

#[derive(Clone, Default)]
pub struct DmInboxConfig {
    /// If true, trust-policy rejections do NOT emit an ACK.
    pub silent_reject: bool,
    /// Prefix-routed payloads that should bypass generic DirectMessaging fan-out.
    pub typed_payload_routes: Vec<DmTypedPayloadRoute>,
}

impl std::fmt::Debug for DmInboxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmInboxConfig")
            .field("silent_reject", &self.silent_reject)
            .field("typed_payload_routes", &self.typed_payload_routes.len())
            .finish()
    }
}

impl DmInboxConfig {
    /// Add a typed-payload route. Matching payloads are delivered to `sender`
    /// and are not emitted to generic `/direct/events` consumers.
    ///
    /// Routes registered this way cannot satisfy a durable (v2) receipt — see
    /// [`Self::with_durable_typed_payload_route`].
    #[must_use]
    pub fn with_typed_payload_route(
        mut self,
        prefix: impl Into<Vec<u8>>,
        sender: mpsc::Sender<DmTypedPayload>,
    ) -> Self {
        self.typed_payload_routes.push(DmTypedPayloadRoute {
            prefix: prefix.into(),
            sender,
            durable_completion: false,
        });
        self
    }

    /// Add a typed-payload route whose handler reports durable completion
    /// (ADR 0030 §7).
    ///
    /// Opting in is a promise: the handler must resolve the payload's
    /// [`DmTypedPayload::completion`] channel once the payload is durably
    /// recorded in *its own* store, and only then. The inbox emits a v2 ACK
    /// solely on that signal, so a route that resolves optimistically converts
    /// a durable receipt into a lie. Routes that do not opt in never receive a
    /// v2 ACK — that withholding is stated policy, not an oversight.
    #[must_use]
    pub fn with_durable_typed_payload_route(
        mut self,
        prefix: impl Into<Vec<u8>>,
        sender: mpsc::Sender<DmTypedPayload>,
    ) -> Self {
        self.typed_payload_routes.push(DmTypedPayloadRoute {
            prefix: prefix.into(),
            sender,
            durable_completion: true,
        });
        self
    }
}

/// Prefix route for decrypted DM payloads.
#[derive(Clone)]
pub struct DmTypedPayloadRoute {
    pub prefix: Vec<u8>,
    pub sender: mpsc::Sender<DmTypedPayload>,
    /// Whether this route's handler resolves [`DmTypedPayload::completion`],
    /// and may therefore back a durable v2 ACK (ADR 0030 §7).
    pub durable_completion: bool,
}

/// What a typed-route handler reports once it has durably recorded a payload.
///
/// Mirrors the history store's own vocabulary deliberately: these are the two
/// outcomes that prove exactly one durable record exists for the request, and
/// they are the only two that let the inbox emit a v2 ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmTypedPayloadCompletion {
    /// Newly recorded in the handler's durable store.
    Inserted,
    /// Already present — an idempotent replay of the same logical request.
    Duplicate,
}

/// Outcome a handler sends back on [`DmTypedPayload::completion`]. `Err`
/// carries a reason for the trace; it withholds the ACK exactly like a
/// dropped channel does.
pub type DmTypedPayloadCompletionResult = Result<DmTypedPayloadCompletion, String>;

/// A decrypted, verified DM payload routed before generic direct-message fan-out.
///
/// Deliberately NOT `Clone`: `completion` holds a `oneshot::Sender`, which has
/// no meaningful copy — two clones could not both answer the receiver, and
/// cloning would silently drop one caller's receipt.
#[derive(Debug)]
pub struct DmTypedPayload {
    pub sender: AgentId,
    pub machine_id: MachineId,
    pub payload: Vec<u8>,
    pub verified: bool,
    pub trust_decision: Option<TrustDecision>,
    pub received_at_unix_ms: u64,
    /// Logical request id of the envelope that carried this payload, so a
    /// handler can dedupe on `(sender, request_id)` across restart.
    pub request_id: [u8; 16],
    /// Present only for a durable (v2) payload on a route that opted in.
    /// Resolving it with `Inserted`/`Duplicate` is what releases the v2 ACK;
    /// dropping it withholds the ACK, which is the safe default on any
    /// handler path that returns early.
    pub completion: Option<oneshot::Sender<DmTypedPayloadCompletionResult>>,
}

pub struct DmInboxService {
    handles: Vec<JoinHandle<()>>,
    topic: String,
    pipeline: InboxPipeline,
}

/// One durable (v2) ACK envelope awaiting publication on both routes.
struct AckPublishJob {
    recipient: AgentId,
    acked_request_id: [u8; 16],
    protocol_version: u16,
    encoded: Bytes,
}

#[derive(Clone)]
struct AckPublisherHandle {
    sender: mpsc::Sender<AckPublishJob>,
}

impl AckPublisherHandle {
    /// Hand a job to the worker without ever blocking the inbox loop. A full
    /// queue is reported, never awaited: the receiver has already committed
    /// and the sender will time out, which is the documented safe failure —
    /// whereas blocking here would stall every later DM behind one wedged ACK.
    fn try_publish(&self, job: AckPublishJob) -> NetworkResult<()> {
        self.sender.try_send(job).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => NetworkError::RemoteReceiveBackpressured(
                "durable ACK publisher queue is full".to_string(),
            ),
            mpsc::error::TrySendError::Closed(_) => {
                NetworkError::ChannelClosed("durable ACK publisher stopped".to_string())
            }
        })
    }
}

/// Legacy shared DM transport topic. New sends use per-recipient inbox
/// topics; this listener remains so rolling upgrades can still receive
/// envelopes from older daemons.
pub const DM_BUS_TOPIC: &str = "x0x/dm/v1/bus";
const DM_INBOX_TOPIC_NAME_PREFIX: &str = "x0x/dm/v1/inbox/";

/// Topic ids that may receive one Full/bootstrap eager prefer (C5b).
///
/// C0 stays: this list is inbox + compatibility bus only. Unsubscribed
/// pass-through / GRAFT piggyback is not re-enabled here.
pub(crate) fn ack_publish_eager_topics(recipient: &AgentId) -> [TopicId; 2] {
    [
        dm_inbox_topic(recipient),
        TopicId::from_entity(DM_BUS_TOPIC.as_bytes()),
    ]
}

impl DmInboxService {
    /// Human-readable name for the agent's raw derived DM inbox topic.
    #[must_use]
    pub fn inbox_topic_name(agent_id: &AgentId) -> String {
        format!(
            "{DM_INBOX_TOPIC_NAME_PREFIX}{}",
            hex::encode(dm_inbox_topic(agent_id).to_bytes())
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        machine_keypair: Arc<MachineKeypair>,
        kem_keypair: Arc<AgentKemKeypair>,
        dm: Arc<DirectMessaging>,
        contacts: Arc<RwLock<ContactStore>>,
        inflight: Arc<InFlightAcks>,
        cache: Arc<RecentDeliveryCache>,
        config: DmInboxConfig,
        revocation_set: Arc<RwLock<RevocationSet>>,
        authenticated_machine_bindings: AuthenticatedMachineBindings,
        history: Option<crate::history::HistoryHandle>,
    ) -> NetworkResult<Self> {
        Self::spawn_with_hedge(
            pubsub,
            signing,
            self_agent_id,
            self_machine_id,
            machine_keypair,
            kem_keypair,
            dm,
            contacts,
            inflight,
            cache,
            config,
            revocation_set,
            authenticated_machine_bindings,
            history,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn spawn_with_hedge(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        machine_keypair: Arc<MachineKeypair>,
        kem_keypair: Arc<AgentKemKeypair>,
        dm: Arc<DirectMessaging>,
        contacts: Arc<RwLock<ContactStore>>,
        inflight: Arc<InFlightAcks>,
        cache: Arc<RecentDeliveryCache>,
        config: DmInboxConfig,
        revocation_set: Arc<RwLock<RevocationSet>>,
        authenticated_machine_bindings: AuthenticatedMachineBindings,
        history: Option<crate::history::HistoryHandle>,
        direct_hedge: Option<Arc<dyn DirectAckHedge>>,
    ) -> NetworkResult<Self> {
        let topic = Self::inbox_topic_name(&self_agent_id);
        let subscription = pubsub
            .subscribe_topic_id(topic.clone(), dm_inbox_topic(&self_agent_id))
            .await;
        let legacy_subscription = pubsub.subscribe(DM_BUS_TOPIC.to_string()).await;
        let (ack_publisher, ack_worker) =
            spawn_durable_ack_publisher(Arc::clone(&pubsub), Arc::clone(&dm), direct_hedge);

        let pipeline = InboxPipeline {
            pubsub: Arc::clone(&pubsub),
            signing,
            self_agent_id,
            self_machine_id,
            machine_keypair,
            kem_keypair,
            dm,
            contacts,
            inflight,
            cache,
            silent_reject: config.silent_reject,
            typed_payload_routes: config.typed_payload_routes,
            revocation_set,
            authenticated_machine_bindings,
            history,
            ack_publisher,
        };

        let primary_handle =
            spawn_subscription_loop(topic.clone(), false, subscription, pipeline.clone());
        let legacy_handle = spawn_subscription_loop(
            DM_BUS_TOPIC.to_string(),
            true,
            legacy_subscription,
            pipeline.clone(),
        );

        Ok(Self {
            // Aborting the worker drops its JoinSet, which aborts all owned
            // route publications. A graceful channel close drains them.
            handles: vec![primary_handle, legacy_handle, ack_worker],
            topic,
            pipeline,
        })
    }

    /// Ingest a Direct/typed payload if it is the same v2 ACK envelope.
    ///
    /// Returns `true` when the bytes decoded as an ACK (whether or not a
    /// waiter was still registered). Direct send-ok is not a receipt; this
    /// is the request_id path the sender waiter actually completes on.
    pub async fn try_ingest_direct_ack(
        &self,
        sender: AgentId,
        sender_public_key: Vec<u8>,
        payload: Bytes,
    ) -> bool {
        self.pipeline
            .ingest_direct_ack_envelope(sender, sender_public_key, payload)
            .await
    }

    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub fn abort(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

impl Drop for DmInboxService {
    fn drop(&mut self) {
        self.abort();
    }
}

fn spawn_subscription_loop(
    topic_for_task: String,
    ack_legacy_bus: bool,
    mut subscription: Subscription,
    pipeline: InboxPipeline,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(topic = %topic_for_task, "DM inbox service subscribed");
        while let Some(message) = subscription.recv().await {
            pipeline.handle_incoming(message, ack_legacy_bus).await;
        }
        tracing::debug!(topic = %topic_for_task, "DM inbox subscription closed");
    })
}

fn spawn_durable_ack_publisher(
    pubsub: Arc<PubSubManager>,
    dm: Arc<DirectMessaging>,
    direct_hedge: Option<Arc<dyn DirectAckHedge>>,
) -> (AckPublisherHandle, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel(DURABLE_ACK_QUEUE_CAPACITY);
    let worker = spawn_ack_publish_worker(receiver, move |job| {
        let pubsub = Arc::clone(&pubsub);
        let dm = Arc::clone(&dm);
        let direct_hedge = direct_hedge.clone();
        async move {
            publish_durable_ack_job(pubsub, dm, direct_hedge, job).await;
        }
    });
    (AckPublisherHandle { sender }, worker)
}

/// Generic over the publish closure so the worker's queue and concurrency
/// behaviour can be tested without a live pubsub mesh.
fn spawn_ack_publish_worker<Publish, PublishFuture>(
    mut receiver: mpsc::Receiver<AckPublishJob>,
    publish: Publish,
) -> JoinHandle<()>
where
    Publish: Fn(AckPublishJob) -> PublishFuture + Send + Sync + 'static,
    PublishFuture: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let publish = Arc::new(publish);
        let mut in_flight = JoinSet::new();

        loop {
            if in_flight.len() >= DURABLE_ACK_MAX_CONCURRENT {
                if let Some(result) = in_flight.join_next().await {
                    log_ack_publish_join_result(result);
                }
                continue;
            }

            tokio::select! {
                biased;
                Some(result) = in_flight.join_next(), if !in_flight.is_empty() => {
                    log_ack_publish_join_result(result);
                }
                job = receiver.recv() => {
                    let Some(job) = job else {
                        break;
                    };
                    let publish = Arc::clone(&publish);
                    in_flight.spawn(async move {
                        publish(job).await;
                    });
                }
            }
        }

        // Graceful closure drains accepted jobs. DmInboxService::abort aborts
        // this owner task; dropping JoinSet then aborts every child promptly.
        while let Some(result) = in_flight.join_next().await {
            log_ack_publish_join_result(result);
        }
    })
}

fn log_ack_publish_join_result(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        tracing::warn!(
            target: "dm.trace",
            stage = "ack_publish_worker_failed",
            %error,
            "durable ACK publisher task failed"
        );
    }
}

async fn publish_durable_ack_job(
    pubsub: Arc<PubSubManager>,
    dm: Arc<DirectMessaging>,
    direct_hedge: Option<Arc<dyn DirectAckHedge>>,
    job: AckPublishJob,
) {
    // C5b: prefer one Full/bootstrap eager on inbox+bus only. Does not
    // re-enable unsubscribed pass-through / GRAFT piggyback (C0).
    pubsub
        .prefer_one_full_bootstrap_eager(&ack_publish_eager_topics(&job.recipient))
        .await;

    let topic = DmInboxService::inbox_topic_name(&job.recipient);
    let topic_id = dm_inbox_topic(&job.recipient);
    let encoded_primary = Bytes::clone(&job.encoded);
    let encoded_legacy = Bytes::clone(&job.encoded);
    let primary_pubsub = Arc::clone(&pubsub);
    let legacy_pubsub = Arc::clone(&pubsub);
    // Owned clones so each route can be spawned independently. First-success
    // must detach the sibling, not cancel it — otherwise a healthy second
    // publish is dropped before it delivers.
    let primary = async move {
        primary_pubsub
            .publish_topic_id(topic, topic_id, encoded_primary)
            .await
    };
    // The durable path always hedges onto the compatibility bus, even when the
    // payload did not arrive there. A v2 sender has already been promised a
    // committed row; a second route costs one small publish and removes a
    // whole class of "committed but never acked" outcomes.
    let legacy = async move {
        legacy_pubsub
            .publish(DM_BUS_TOPIC.to_string(), encoded_legacy)
            .await
    };
    // C5: same v2 ACK envelope on live Direct/typed as a third hedge.
    // Detached from gossip: missing Direct is fail-open, and Direct send-ok
    // is not a sender receipt. Do not abort sibling gossip routes.
    // `direct_hedge_was_sent` distinguishes Sent from SkippedNoDirect for
    // the (c) outcome counters.
    let direct_hedge_was_sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let direct = {
        let sent_flag = Arc::clone(&direct_hedge_was_sent);
        let hedge = direct_hedge.clone();
        let recipient = job.recipient;
        let encoded = Bytes::clone(&job.encoded);
        async move {
            let Some(hedge) = hedge else {
                return Ok(());
            };
            match hedge.hedge(recipient, encoded).await {
                DirectAckHedgeOutcome::Sent => {
                    sent_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                }
                DirectAckHedgeOutcome::SkippedNoDirect => Ok(()),
                DirectAckHedgeOutcome::Failed => Err(NetworkError::ConnectionFailed(
                    "direct ACK hedge failed".to_string(),
                )),
            }
        }
    };
    let publish_started = Instant::now();
    let (gossip, direct_outcome) = tokio::join!(
        publish_durable_ack_routes(DURABLE_ACK_ROUTE_TIMEOUT, primary, legacy),
        publish_ack_route_with_timeout("direct-typed", DURABLE_ACK_ROUTE_TIMEOUT, direct),
    );
    dm.record_ack_publish_ms(crate::dm::millis_since(publish_started));
    // #380 leaf-reverse-ACK fix (c): count gossip and Direct hedge outcomes
    // SEPARATELY so /diagnostics/dm distinguishes "gossip routes dead,
    // Direct saved it" from "all dead". The old code incremented the same
    // ack_publish_route_failed counter for gossip failure AND direct
    // failure, and warned "ACK never left" even when Direct had Sent —
    // the 3/3 fleet reading was ambiguous.
    let direct_sent = matches!(direct_outcome, Ok(()))
        && direct_hedge_was_sent.load(std::sync::atomic::Ordering::Relaxed);
    match (gossip, direct_outcome) {
        (Ok(()), _) => {
            dm.record_ack_gossip_route_succeeded();
            if direct_sent {
                dm.record_ack_direct_hedge(crate::direct::AckDirectHedgeOutcomeRecord::Sent);
            }
        }
        (Err(error), Ok(())) => {
            // Gossip failed but the Direct hedge fired — the ACK still had a
            // route. Count the gossip failure for visibility; Direct carries
            // the receipt.
            dm.record_ack_gossip_route_failed();
            if direct_sent {
                dm.record_ack_direct_hedge(
                    crate::direct::AckDirectHedgeOutcomeRecord::SavedFailure,
                );
            } else {
                dm.record_ack_direct_hedge(
                    crate::direct::AckDirectHedgeOutcomeRecord::SkippedOrNoDirect,
                );
            }
            tracing::warn!(
                target: "dm.trace",
                stage = "ack_gossip_routes_failed_direct_hedge",
                acked_request_id = %hex::encode(job.acked_request_id),
                recipient = %hex::encode(job.recipient.as_bytes()),
                direct_sent,
                %error,
                "gossip ACK routes failed; Direct hedge state recorded separately"
            );
        }
        (Err(error), Err(direct_error)) => {
            // All routes dead — the ACK genuinely never left.
            dm.record_ack_gossip_route_failed();
            dm.record_ack_direct_hedge(crate::direct::AckDirectHedgeOutcomeRecord::Failed);
            tracing::warn!(
                target: "dm.trace",
                stage = "ack_publish_all_routes_failed",
                acked_request_id = %hex::encode(job.acked_request_id),
                recipient = %hex::encode(job.recipient.as_bytes()),
                protocol_version = job.protocol_version,
                gossip_error = %error,
                direct_error = %direct_error,
                "both gossip routes AND the Direct hedge failed; ACK never left this recipient"
            );
        }
    }
}

/// Choose Direct/typed hedge outcome without treating send-ok as a receipt.
#[cfg(test)]
pub(crate) fn direct_ack_hedge_outcome(
    connected: bool,
    send_ok: Option<bool>,
) -> DirectAckHedgeOutcome {
    match (connected, send_ok) {
        (false, _) => DirectAckHedgeOutcome::SkippedNoDirect,
        (true, Some(true)) => DirectAckHedgeOutcome::Sent,
        (true, _) => DirectAckHedgeOutcome::Failed,
    }
}

/// Pre-warm PlumTree membership for the reverse-ACK topics used by a
/// durable send to `peer`.
///
/// Joins (1) this agent's inbox (where ACKs land), (2) the peer's inbox,
/// and (3) the compatibility bus. C2 refreshes those topic ids on the
/// subscribed path. C4 also pre-subscribes the peer inbox so the first
/// durable POST is not a cold `publish_topic_id` join. Does not walk
/// pass-through topics (Leaf-safe; C0/#395 hygiene).
pub(crate) async fn warm_reverse_ack_topics(
    pubsub: &PubSubManager,
    self_agent: &AgentId,
    peer: &AgentId,
) {
    if !should_warm_reverse_ack(true, self_agent, peer) {
        return;
    }
    pubsub
        .ensure_subscribed_topic_id(
            &DmInboxService::inbox_topic_name(self_agent),
            dm_inbox_topic(self_agent),
        )
        .await;
    // C4: peer inbox must be subscribed, not merely initialized, before
    // the first durable publish_topic_id.
    pubsub
        .ensure_subscribed_topic_id(
            &DmInboxService::inbox_topic_name(peer),
            dm_inbox_topic(peer),
        )
        .await;
    pubsub
        .ensure_subscribed_topic_id(
            DM_BUS_TOPIC,
            saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes()),
        )
        .await;
}

/// Reverse-ACK pre-warm is for a Trusted *other* peer. Self and untrusted
/// peers must not join extra inbox topics on connect.
pub(crate) fn should_warm_reverse_ack(trusted: bool, self_agent: &AgentId, peer: &AgentId) -> bool {
    trusted && self_agent != peer
}

async fn publish_durable_ack_routes<Primary, Legacy>(
    route_timeout: Duration,
    primary: Primary,
    legacy: Legacy,
) -> NetworkResult<()>
where
    Primary: std::future::Future<Output = NetworkResult<()>>,
    Legacy: std::future::Future<Output = NetworkResult<()>>,
{
    // #396 rework: C1 (first-success hedge) was removed — the joint review
    // decided the post-commit Direct/typed hedge (C5, PR #408) supersedes
    // it. This restores main's join!-both semantics unchanged: a targeted
    // inbox publish can deliver remotely yet remain pending under
    // per-topic fan-out backpressure, so both routes are polled with their
    // own deadlines and BOTH must succeed (a wedged sibling fails at its
    // deadline instead of pinning this serial inbox loop). The residual
    // 504 `budget_stage=ack_wait_ms` pressure is addressed by C2/C4
    // pre-warm (below) plus the C5 direct hedge in #408.
    let (primary, legacy) = tokio::join!(
        publish_ack_route_with_timeout("targeted", route_timeout, primary),
        publish_ack_route_with_timeout("legacy-bus", route_timeout, legacy),
    );
    primary.and(legacy)
}

async fn publish_ack_route_with_timeout<Route>(
    route: &'static str,
    route_timeout: Duration,
    publish: Route,
) -> NetworkResult<()>
where
    Route: std::future::Future<Output = NetworkResult<()>>,
{
    match tokio::time::timeout(route_timeout, publish).await {
        Ok(result) => result,
        Err(_) => Err(NetworkError::BroadcastError(format!(
            "ACK {route} publish timed out after {route_timeout:?}"
        ))),
    }
}

#[derive(Clone)]
struct InboxPipeline {
    pubsub: Arc<PubSubManager>,
    signing: Arc<SigningContext>,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    /// This machine's keypair — signs the #213 origin attestation embedded
    /// in outbound ACK envelopes, so ACK receivers authenticate the
    /// acking machine exactly like payload-DM receivers do.
    machine_keypair: Arc<MachineKeypair>,
    kem_keypair: Arc<AgentKemKeypair>,
    dm: Arc<DirectMessaging>,
    contacts: Arc<RwLock<ContactStore>>,
    inflight: Arc<InFlightAcks>,
    cache: Arc<RecentDeliveryCache>,
    silent_reject: bool,
    typed_payload_routes: Vec<DmTypedPayloadRoute>,
    /// Shared revocation set for enforcement point 3.
    revocation_set: Arc<RwLock<RevocationSet>>,
    /// Authenticated origin-machine bindings retained across discovery eviction.
    authenticated_machine_bindings: AuthenticatedMachineBindings,
    /// ADR-0023 history handle. Recording is `try_send`-only — this loop
    /// must never block (see the typed-route comment below).
    history: Option<crate::history::HistoryHandle>,
    /// Bounded background publisher for durable (v2) ACK envelopes.
    ack_publisher: AckPublisherHandle,
}

impl InboxPipeline {
    /// Ingest a Direct/typed payload only when it is an ACK envelope.
    ///
    /// Reuses the gossip ACK path so the waiter still keys on
    /// `acks_request_id`. Returns `true` iff the payload decoded as an ACK
    /// (callers must not fan it out as a user DM).
    async fn ingest_direct_ack_envelope(
        &self,
        sender: AgentId,
        sender_public_key: Vec<u8>,
        payload: Bytes,
    ) -> bool {
        let Ok(envelope) = DmEnvelope::from_wire_bytes(&payload) else {
            return false;
        };
        if !matches!(envelope.body, DmBody::Ack(_)) {
            return false;
        }
        if envelope.sender_agent_id != *sender.as_bytes() {
            return false;
        }
        let message = PubSubMessage {
            topic: String::from("direct-typed-ack-hedge"),
            payload,
            sender: Some(sender),
            sender_public_key: Some(sender_public_key),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        self.handle_incoming(message, false).await;
        true
    }
}

/// Re-ACK semantics for a logical request that already completed.
///
/// ADR 0030 §2: a request completed under weaker semantics is answered
/// `AckSemanticsUnavailable`, never re-ACKed as durable — otherwise a v2
/// sender racing a v1 delivery of the same request would be handed a durable
/// receipt nobody made.
fn cached_ack_for_protocol(
    cached: &crate::dm::CachedOutcome,
    requested_protocol: u16,
) -> DmAckOutcome {
    if cached.protocol_version >= requested_protocol {
        cached.outcome.clone()
    } else {
        DmAckOutcome::AckSemanticsUnavailable {
            reason: format!(
                "logical request already completed under v{} semantics",
                cached.protocol_version
            ),
        }
    }
}

/// Whether `handle_incoming`'s fast replay re-ACK must stand aside and let the
/// durable path decide.
///
/// True only for a v2 payload envelope replaying a completion that carries a
/// durable binding — the one case where the correct answer depends on bytes
/// this stage has not decrypted yet. Everything else (v1 replays, ACK
/// envelopes, completions with no binding) keeps the cheap path, so the cost
/// of a signature verification and a decrypt is paid only where it buys the
/// ADR 0030 §1 conflict check.
fn cached_completion_needs_binding_check(
    cached: Option<&crate::dm::CachedOutcome>,
    envelope: &DmEnvelope,
) -> bool {
    matches!(envelope.body, DmBody::Payload(_))
        && envelope.protocol_version >= DM_PROTOCOL_DURABLE_ACK
        && cached.is_some_and(|cached| cached.durable_binding.is_some())
}

/// A commit outcome that proves exactly one durable row exists for this
/// record. `Inserted` is the first commit; `Duplicate` is the idempotent
/// replay of an identical record (ADR 0030 validation: "exactly one durable
/// history row (`Duplicate` re-ACK)"). Anything else means the row we
/// promised is not the row that is there, so the ACK must be withheld.
fn exact_durable_history_outcome(outcome: crate::history::InsertOutcome) -> bool {
    matches!(
        outcome,
        crate::history::InsertOutcome::Inserted | crate::history::InsertOutcome::Duplicate
    )
}

/// Build the ADR-0023 history row for a verified inbound DM.
///
/// `Ok(None)` means the payload classifies `Ephemeral` — protocol plumbing
/// whose durable effect lives in its own store, never in DM history.
///
/// Schema v4 (`ingress_sender_agent`, `logical_request_id`) is populated here:
/// together they key the ADR 0030 §1 durable-history lookup, which is what
/// lets a receiver recognise a logical request it has already committed.
fn inbound_dm_history_record(
    envelope: &DmEnvelope,
    application_payload: &[u8],
    sender_machine_id: MachineId,
    sender_pubkey: &[u8],
) -> Result<Option<crate::history::HistoryRecord>, String> {
    let crate::history::classify::DmPayloadClass::Durable(content_type) =
        crate::history::classify::classify_dm_payload(application_payload)
    else {
        return Ok(None);
    };
    let artifact = envelope.to_wire_bytes().map_err(|e| e.to_string())?;
    Ok(Some(crate::history::HistoryRecord {
        msg_id: crate::history::HistoryRecord::compute_msg_id(Some(&artifact), application_payload),
        scope: crate::history::Scope::Dm(hex::encode(envelope.sender_agent_id)),
        author_agent: Some(hex::encode(envelope.sender_agent_id)),
        author_machine: Some(hex::encode(sender_machine_id.as_bytes())),
        author_pubkey: Some(sender_pubkey.to_vec()),
        sent_at_ms: i64::try_from(envelope.created_at_unix_ms).unwrap_or(i64::MAX),
        seen_at_ms: i64::try_from(now_unix_ms()).unwrap_or(i64::MAX),
        direction: crate::history::Direction::Inbound,
        content_type: content_type.to_string(),
        payload: application_payload.to_vec(),
        signed_artifact: Some(artifact),
        signature: Some(envelope.signature.clone()),
        // Mirrors `DM_SIGN_DOMAIN` in `dm.rs`.
        sig_context: Some("x0x-dm-v1".to_string()),
        provenance: crate::history::Provenance::VerifiedEnvelope,
        replace_key: None,
        thread_root: None,
        thread_parent: None,
        ingress_sender_agent: Some(hex::encode(envelope.sender_agent_id)),
        logical_request_id: Some(envelope.request_id),
    }))
}

/// What the receiver durable path decided for one v2 envelope.
///
/// Returned rather than inferred from side effects so the commit-before-ACK
/// ordering is directly assertable: "no ACK when the commit fails" is the
/// central promise of ADR 0030 §1 and must not be tested by proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableAckDecision {
    /// An ACK was emitted with these semantics. `accepted` distinguishes a
    /// delivery receipt from a refusal; a refusal never claims durability.
    Acked {
        protocol_version: u16,
        accepted: bool,
    },
    /// No ACK was emitted — the sender times out. The stage names why.
    Withheld(&'static str),
}

/// Result of the ADR 0030 §1 durable-history lookup for one logical request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableLogicalRequestLookup {
    /// No durable row for this `(sender, request_id)` yet.
    Missing,
    /// A durable row exists and binds exactly the bytes now being accepted.
    Exact,
    /// A durable row exists under this logical request but binds different
    /// bytes — the sender reused a request id for different content.
    Conflict,
}

/// Durable-history lookup keyed on the schema v4 columns this path writes.
///
/// Runs on `spawn_blocking`: `Store` is synchronous SQLite and this is called
/// from the inbox task.
async fn durable_history_logical_request(
    history: &crate::history::HistoryHandle,
    sender: AgentId,
    request_id: [u8; 16],
    accepted_payload: Vec<u8>,
) -> crate::error::HistoryResult<DurableLogicalRequestLookup> {
    let store = Arc::clone(history.store());
    let ingress = hex::encode(sender.as_bytes());
    tokio::task::spawn_blocking(move || {
        let rows = store.find_by_logical_request(&ingress, request_id)?;
        if rows.is_empty() {
            return Ok(DurableLogicalRequestLookup::Missing);
        }
        if rows
            .iter()
            .any(|row| row.record.payload != accepted_payload)
        {
            return Ok(DurableLogicalRequestLookup::Conflict);
        }
        Ok(DurableLogicalRequestLookup::Exact)
    })
    .await
    .map_err(|error| {
        crate::error::HistoryError::Database(format!("logical request lookup task failed: {error}"))
    })?
}

impl InboxPipeline {
    async fn handle_incoming(&self, msg: PubSubMessage, ack_legacy_bus: bool) {
        let (pubsub_sender, sender_pubkey) = match (msg.sender, msg.sender_public_key.as_deref()) {
            (Some(s), Some(pk)) if msg.verified => (s, pk.to_vec()),
            _ => {
                // Real unverified-drop site (issue #296): count here before
                // discarding so the server-layer typed-payload handler never
                // sees these messages and does not need its own copy of this
                // check.
                self.dm.record_incoming_signature_failed();
                tracing::debug!(
                    target: "dm.trace",
                    stage = "inbound_unverified_drop",
                    "dropped unverified pubsub message before envelope decode"
                );
                return;
            }
        };

        if msg.payload.len() > MAX_ENVELOPE_BYTES {
            self.dm.record_incoming_decode_failed();
            return;
        }

        let envelope = match DmEnvelope::from_wire_bytes(&msg.payload) {
            Ok(e) => e,
            Err(_) => {
                self.dm.record_incoming_decode_failed();
                return;
            }
        };

        // ADR 0030 §2 receiver ceiling: an envelope above what this build
        // understands is dropped WITHOUT an ACK, so the sender times out
        // rather than being handed a receipt for semantics we cannot honour.
        if envelope.protocol_version > DM_PROTOCOL_VERSION {
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_protocol_above_ceiling_dropped",
                sender = %hex::encode(envelope.sender_agent_id),
                protocol_version = envelope.protocol_version,
                ceiling = DM_PROTOCOL_VERSION,
                "DM dropped without ACK: envelope protocol version exceeds local ceiling"
            );
            return;
        }

        let now = now_unix_ms();
        if validate_timestamp_window(
            envelope.created_at_unix_ms,
            envelope.expires_at_unix_ms,
            now,
        )
        .is_err()
        {
            return;
        }

        if envelope.recipient_agent_id != *self.self_agent_id.as_bytes() {
            return;
        }

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_envelope_received",
            request_id = %hex::encode(envelope.request_id),
            sender = %hex::encode(envelope.sender_agent_id),
            bytes = msg.payload.len(),
        );

        let dedupe = envelope.dedupe_key();
        // A v2 envelope replaying a logical request that already completed
        // durably must have its bytes compared against the committed binding
        // before anything is re-ACKed — otherwise a caller that reused a
        // `logical_id` for *different* content is told `Accepted` for bytes
        // nobody stored. That comparison needs the plaintext, which this fast
        // path does not have, so the durable path owns the whole replay
        // decision for these envelopes (it re-ACKs from the same cache entry
        // at step 2 without re-dispatching).
        let needs_durable_binding_check =
            cached_completion_needs_binding_check(self.cache.lookup(&dedupe).as_ref(), &envelope);
        if let Some(cached) = self
            .cache
            .lookup(&dedupe)
            .filter(|_| !needs_durable_binding_check)
        {
            if matches!(envelope.body, DmBody::Payload(_)) {
                // ADR 0030 §2: re-ACK under the semantics the completion was
                // actually made with. A v1 completion answers a v2 request
                // with a refusal, never with a durable-looking receipt.
                let outcome = cached_ack_for_protocol(&cached, envelope.protocol_version);
                // Accepted re-ACKs carry the semantics actually honoured;
                // refusals carry the requested version so they reach the
                // sender's exact-protocol waiter instead of timing out.
                let ack_protocol = if matches!(outcome, DmAckOutcome::Accepted) {
                    cached
                        .protocol_version
                        .min(envelope.protocol_version)
                        .max(DM_PROTOCOL_V1)
                } else {
                    envelope.protocol_version
                };
                let _ = self
                    .publish_ack_for_protocol(
                        AgentId(envelope.sender_agent_id),
                        envelope.request_id,
                        outcome,
                        ack_protocol,
                        ack_legacy_bus,
                    )
                    .await;
            }
            return;
        }

        if !verify_envelope_signature(&envelope, &sender_pubkey) {
            self.dm.record_incoming_signature_failed();
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_signature_failed",
                request_id = %hex::encode(envelope.request_id),
                sender = %hex::encode(envelope.sender_agent_id),
            );
            return;
        }

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_signature_verified",
            request_id = %hex::encode(envelope.request_id),
            sender = %hex::encode(envelope.sender_agent_id),
        );

        if envelope.sender_agent_id != *pubsub_sender.as_bytes() {
            self.dm.record_incoming_signature_failed();
            tracing::debug!(
                target: "dm.trace",
                stage = "inbound_sender_id_mismatch",
                "dropped DM: envelope sender_agent_id does not match gossip-layer sender"
            );
            return;
        }

        // Enforcement point 3 — authenticated-origin revocation gate.
        //
        // Issue #213: prefer the fresh per-DM origin-machine attestation —
        // a machine-key signature covering this envelope, verifiable with
        // ZERO prior cache state. When present and valid it supersedes (and
        // refreshes) the retained binding; when present but invalid the DM
        // is a hard drop (never fall back — a bad attestation is an attack
        // signal, not a legacy peer). Only when the attestation is ABSENT
        // (pre-#213 peer) do we degrade to the #184 retained-binding check,
        // where the envelope machine claim is sender-controlled: prefer the
        // retained machine from an accepted, verified identity announcement;
        // the claim is only a best-effort fallback for agents with no
        // authenticated binding. See docs/adr/0021-dm-origin-machine-attestation.md.
        let sender_agent_id = AgentId(envelope.sender_agent_id);
        let claimed_machine_id = MachineId(envelope.sender_machine_id);
        let sender_machine_id = match envelope.verify_origin_attestation() {
            Ok(Some(attested_machine)) => {
                tracing::info!(
                    target: "dm.trace",
                    stage = "inbound_origin_attested",
                    sender = %hex::encode(envelope.sender_agent_id),
                    machine = %hex::encode(attested_machine.as_bytes()),
                    "DM origin machine authenticated by fresh machine-key attestation"
                );
                // Refresh the retained binding so later UNATTESTED DMs from
                // this agent are checked against the freshest authenticated
                // machine — this is what lets a portable move A→B displace a
                // stale binding. Convert ms→s: announcement-sourced bindings
                // are seconds-granularity and the cache orders by timestamp.
                record_authenticated_machine_binding(
                    &self.authenticated_machine_bindings,
                    sender_agent_id,
                    attested_machine,
                    envelope.created_at_unix_ms / 1000,
                )
                .await;
                attested_machine
            }
            Err(rejection) => {
                self.dm.record_incoming_trust_rejected(sender_agent_id);
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_origin_attestation_invalid",
                    sender = %hex::encode(envelope.sender_agent_id),
                    claimed_machine = %hex::encode(claimed_machine_id.as_bytes()),
                    rejection = %rejection,
                    "DM dropped: origin-machine attestation invalid"
                );
                return;
            }
            Ok(None) => {
                let authenticated_machine_id = self
                    .authenticated_machine_bindings
                    .write()
                    .await
                    .resolve(&sender_agent_id);
                match authenticated_machine_id {
                    Some(authenticated) if authenticated != claimed_machine_id => {
                        self.dm.record_incoming_trust_rejected(sender_agent_id);
                        tracing::warn!(
                            target: "dm.trace",
                            stage = "inbound_origin_machine_mismatch",
                            sender = %hex::encode(envelope.sender_agent_id),
                            claimed_machine = %hex::encode(claimed_machine_id.as_bytes()),
                            authenticated_machine = %hex::encode(authenticated.as_bytes()),
                            "DM dropped: envelope machine does not match authenticated origin"
                        );
                        return;
                    }
                    Some(authenticated) => authenticated,
                    None => {
                        tracing::info!(
                            target: "dm.trace",
                            stage = "inbound_origin_machine_claim_fallback",
                            sender = %hex::encode(envelope.sender_agent_id),
                            claimed_machine = %hex::encode(claimed_machine_id.as_bytes()),
                            "DM origin has no attestation and no authenticated binding; checking sender claim only"
                        );
                        claimed_machine_id
                    }
                }
            }
        };

        {
            let revoked = self.revocation_set.read().await;
            if drop_if_sender_revoked(&self.dm, &revoked, &sender_agent_id, &sender_machine_id) {
                tracing::info!(
                    target: "dm.trace",
                    stage = "inbound_revoked_sender_dropped",
                    sender = %hex::encode(envelope.sender_agent_id),
                    machine = %hex::encode(sender_machine_id.as_bytes()),
                    "DM dropped: sender is revoked"
                );
                return;
            }
        }

        match envelope.body.clone() {
            DmBody::Ack(ack) => {
                // The ACK's own `protocol_version` names the receipt semantics
                // the recipient is claiming; the waiter accepts it only if
                // that matches what the send negotiated (ADR 0030 §2).
                let resolved = self.inflight.resolve_for_protocol(
                    &ack.acks_request_id,
                    envelope.protocol_version,
                    sender_agent_id,
                    sender_machine_id,
                    ack.outcome,
                );
                tracing::debug!(
                    acked = %hex::encode(ack.acks_request_id),
                    protocol_version = envelope.protocol_version,
                    resolved,
                    "DM ACK received"
                );
            }
            DmBody::Payload(payload) => {
                self.handle_payload(
                    envelope,
                    payload,
                    sender_machine_id,
                    sender_pubkey,
                    ack_legacy_bus,
                )
                .await;
            }
        }
    }

    async fn handle_payload(
        &self,
        envelope: DmEnvelope,
        payload: DmPayload,
        sender_machine_id: MachineId,
        sender_pubkey: Vec<u8>,
        ack_legacy_bus: bool,
    ) {
        let sender_agent_id = AgentId(envelope.sender_agent_id);
        let decision = {
            let store = self.contacts.read().await;
            TrustEvaluator::new(&store).evaluate(&TrustContext {
                agent_id: &sender_agent_id,
                machine_id: &sender_machine_id,
            })
        };

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_trust_evaluated",
            request_id = %hex::encode(envelope.request_id),
            sender = %hex::encode(sender_agent_id.as_bytes()),
            decision = %decision,
        );

        match decision {
            TrustDecision::RejectBlocked | TrustDecision::RejectMachineMismatch => {
                self.dm.record_incoming_trust_rejected(sender_agent_id);
                let outcome = DmAckOutcome::RejectedByPolicy {
                    reason: decision.to_string(),
                };
                self.cache.insert_for_protocol(
                    envelope.dedupe_key(),
                    outcome.clone(),
                    envelope.protocol_version,
                );
                if !self.silent_reject {
                    // A refusal makes no durability claim, so it is stamped
                    // with the requested version rather than downgraded to v1:
                    // a strict v2 sender must learn it was rejected instead of
                    // waiting out its ACK budget on a receipt it would ignore
                    // (ADR 0030 drivers — no black hole, bounded latency).
                    let _ = self
                        .publish_ack_for_protocol(
                            sender_agent_id,
                            envelope.request_id,
                            outcome,
                            envelope.protocol_version,
                            ack_legacy_bus,
                        )
                        .await;
                }
                return;
            }
            _ => {}
        }

        let aad = envelope.aead_aad();
        let plaintext = match decrypt_payload(&self.kem_keypair, &payload, &aad) {
            Ok(p) => p,
            Err(_) => {
                self.dm.record_incoming_decode_failed();
                return;
            }
        };
        if plaintext.request_id != envelope.request_id {
            self.dm.record_incoming_decode_failed();
            return;
        }

        // ADR 0030 §1/§2: a v2 envelope is answered by the durable path or not
        // at all. There is no silent v1 downgrade of a v2 request — if durable
        // history is unavailable the ACK is withheld and the sender times out,
        // which can only happen against a peer that believed a false v2
        // capability advert (this daemon advertises v2 iff history is on).
        if envelope.protocol_version >= DM_PROTOCOL_DURABLE_ACK {
            // #380 leaf-reverse-ACK fix (a): a signature-verified durable
            // envelope just arrived — this is the authoritative moment the
            // receiver owes a reverse route. On a Leaf receiver, the
            // sender's inbox topic is not in the subscribed set (C2/C4
            // pre-warm only fires on connect events with a resolvable
            // agent_id and a trusted contact — neither is guaranteed on a
            // fresh daemon or a first-ever message). Without a subscription
            // the targeted-inbox ACK publish finds zero peers and fails;
            // the compat bus has the same zero-peer problem in Leaf mode.
            // Subscribe the SENDER's inbox topic right now so the ACK that
            // follows has a gossip route. No trust gate and no
            // commit-success gate: the sender just delivered a
            // signature-verified envelope addressed to us — we owe them the
            // receipt, and the route must exist even if the commit below
            // withholds (the sender will retry).
            {
                let sender_agent = AgentId(envelope.sender_agent_id);
                crate::dm_inbox::warm_reverse_ack_topics(
                    self.pubsub.as_ref(),
                    &self.self_agent_id,
                    &sender_agent,
                )
                .await;
            }

            // #380 leaf-reverse-ACK fix (b): register the sender's
            // agent→machine mapping from the verified envelope itself. The
            // C5 Direct hedge's `get_machine_id` lookup was SkippedNoDirect
            // whenever the connected_agents map lacked the entry — which
            // happens on inbound connections where the PeerConnected
            // handler could not resolve the agent_id from the machine_id
            // (fresh cache, no DM history yet). The envelope carries both
            // identities and just passed signature verification; this is
            // the strongest binding evidence we will get.
            {
                let sender_agent = AgentId(envelope.sender_agent_id);
                let sender_machine = MachineId(envelope.sender_machine_id);
                self.dm.mark_connected(sender_agent, sender_machine).await;
            }

            let _decision = self
                .handle_payload_durable(
                    envelope,
                    plaintext.payload,
                    decision,
                    sender_machine_id,
                    sender_pubkey,
                    ack_legacy_bus,
                )
                .await;
            return;
        }

        // Atomic dedupe claim BEFORE delivery. The same envelope can arrive
        // twice — once on the primary per-recipient inbox and once on the
        // legacy bus (during a rolling upgrade), driven by two independent
        // subscription loops. The earlier `cache.lookup` in `handle_incoming`
        // is not sufficient: both tasks can miss it before either delivers.
        // Claiming the dedupe slot here (insert returns `true` only for the
        // task that inserted it) ensures exactly one task delivers to the
        // application; the loser re-ACKs the accepted outcome and returns.
        // The claim happens only after a successful decrypt, so a decrypt
        // failure above still leaves the slot unclaimed for a genuine retry.
        if !self
            .cache
            .insert(envelope.dedupe_key(), DmAckOutcome::Accepted)
        {
            let _ = self
                .publish_ack(
                    sender_agent_id,
                    envelope.request_id,
                    DmAckOutcome::Accepted,
                    ack_legacy_bus,
                )
                .await;
            return;
        }

        let is_typed_payload = self
            .route_typed_payload(
                sender_agent_id,
                sender_machine_id,
                envelope.request_id,
                plaintext.payload.clone(),
                Some(decision),
            )
            .await;

        if !is_typed_payload {
            // ADR-0023 §4: record durable DM communication after every
            // signature/trust/revocation gate has passed. Non-blocking
            // (`HistoryHandle::record` is try_send); plumbing payload
            // families classify Ephemeral and are skipped.
            if self.history.is_some() {
                match inbound_dm_history_record(
                    &envelope,
                    &plaintext.payload,
                    sender_machine_id,
                    &sender_pubkey,
                ) {
                    Ok(Some(record)) => {
                        if let Some(history) = self.history.as_ref() {
                            history.record(record);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            "history: DM envelope wire encode failed, row skipped: {e}"
                        );
                    }
                }
            }
            self.dm
                .handle_incoming(
                    sender_machine_id,
                    sender_agent_id,
                    plaintext.payload,
                    true,
                    Some(decision),
                    // Gossip-inbox deliveries carry no point-to-point
                    // transport observation (issue #120).
                    None,
                )
                .await;

            tracing::info!(
                target: "dm.trace",
                stage = "inbound_broadcast_published",
                request_id = %hex::encode(envelope.request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
            );
        }

        let _ = self
            .publish_ack(
                sender_agent_id,
                envelope.request_id,
                DmAckOutcome::Accepted,
                ack_legacy_bus,
            )
            .await;
    }

    /// Receiver durable path for a v2 envelope (ADR 0030 §1).
    ///
    /// Ordering is normative and implemented in exactly this order:
    /// per-logical-request lock → replay-cache binding check →
    /// durable-history lookup → dispatch → `record_committed` awaited → ACK.
    ///
    /// Every failure below withholds the ACK. A withheld ACK costs the sender
    /// a timeout; a premature ACK costs it a lost message it was told had
    /// arrived, which is the defect this protocol exists to remove. No branch
    /// here may fall back to a v1 ACK: that would answer a durable request
    /// with a weaker receipt the sender cannot distinguish (ADR 0030 §2).
    async fn handle_payload_durable(
        &self,
        envelope: DmEnvelope,
        application_payload: Vec<u8>,
        decision: TrustDecision,
        sender_machine_id: MachineId,
        sender_pubkey: Vec<u8>,
        ack_legacy_bus: bool,
    ) -> DurableAckDecision {
        let sender_agent_id = AgentId(envelope.sender_agent_id);
        let request_id = envelope.request_id;
        let dedupe = envelope.dedupe_key();

        let Some(history) = self.history.clone() else {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_history_unavailable",
                request_id = %hex::encode(request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
                "v2 DM withheld: durable history is not enabled on this daemon"
            );
            return DurableAckDecision::Withheld("history_unavailable");
        };

        // ADR 0030 §7 — typed-route obligation, now discharged by the handler.
        //
        // Typed-prefix families classify `Ephemeral`: their durable effect
        // lives in their own store, not in DM history, so a DM-history commit
        // could never honestly back their receipt. Slice 2 therefore withheld
        // every v2 ACK on a typed route. Slice 3 replaces that blanket refusal
        // with a completion signal — the handler tells us when the payload is
        // durably recorded on ITS surface, and that signal, not a history row,
        // is what releases the ACK.
        //
        // Routes opt in via `with_durable_typed_payload_route`. A route that
        // has not opted in still gets no v2 ACK: this daemon will not certify
        // durability for a handler that has not promised it. That withholding
        // is stated policy (see the PR/design doc), not an oversight.
        let typed_route_durable = self
            .typed_payload_routes
            .iter()
            .find(|route| application_payload.starts_with(&route.prefix))
            .map(|route| route.durable_completion);
        if typed_route_durable == Some(false) {
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_durable_typed_route_not_opted_in",
                request_id = %hex::encode(request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
                "v2 DM matched a typed route that does not report durable completion; ACK withheld by policy (ADR 0030 §7)"
            );
            return DurableAckDecision::Withheld("typed_route_not_durable");
        }
        let is_durable_typed_route = typed_route_durable == Some(true);

        // 1. Per-logical-request lock. Serializes the primary inbox and the
        //    legacy-bus copy of the same envelope so neither can observe a
        //    provisional success from the other.
        let Some(lock) = self.cache.delivery_lock(dedupe) else {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_lock_unavailable",
                request_id = %hex::encode(request_id),
                "v2 DM withheld: no durable delivery lock slot available"
            );
            return DurableAckDecision::Withheld("lock_unavailable");
        };
        let _guard = lock.lock().await;

        // 2. Replay-cache binding check. A completion already exists ⇒ re-ACK
        //    it under its own semantics, never re-dispatch.
        let binding = crate::dm::DmDurableBindingDigest::accepted(
            envelope.protocol_version,
            &application_payload,
        );
        if let Some(cached) = self.cache.lookup(&dedupe) {
            let outcome = match cached.durable_binding {
                Some(stored) if stored == binding => {
                    cached_ack_for_protocol(&cached, envelope.protocol_version)
                }
                // ADR 0030 slice 4: the id is bound to other bytes, which is a
                // caller-side idempotency-key reuse, not a peer-capability
                // gap. It answered `AckSemanticsUnavailable` until the typed
                // error existed (#329 review).
                Some(_) => DmAckOutcome::IdempotencyConflict {
                    reason: "logical request already completed with different content".to_string(),
                },
                None => cached_ack_for_protocol(&cached, envelope.protocol_version),
            };
            let accepted_replay = matches!(outcome, DmAckOutcome::Accepted);
            // An accepted re-ACK is stamped with the semantics actually
            // honoured (never above what this request asked for). A refusal
            // makes no durability claim and is stamped with the requested
            // version instead, so it reaches the sender's exact-protocol
            // waiter and is answered rather than waited out.
            let ack_protocol = if accepted_replay {
                cached
                    .protocol_version
                    .min(envelope.protocol_version)
                    .max(DM_PROTOCOL_V1)
            } else {
                envelope.protocol_version
            };
            let _ = self
                .publish_ack_for_protocol(
                    sender_agent_id,
                    request_id,
                    outcome,
                    ack_protocol,
                    ack_legacy_bus,
                )
                .await;
            return DurableAckDecision::Acked {
                protocol_version: ack_protocol,
                accepted: accepted_replay,
            };
        }

        // 3a. Durable typed route: the handler's own store is the durable
        //     surface, so steps 3–5 are replaced by dispatch-and-await. The
        //     handler reports `Inserted | Duplicate` only once the payload is
        //     recorded, which is the same "exactly one durable record" proof
        //     `record_committed` gives the generic path.
        if is_durable_typed_route {
            let decision = self
                .dispatch_durable_typed_route(
                    sender_agent_id,
                    sender_machine_id,
                    request_id,
                    application_payload,
                    Some(decision),
                )
                .await;
            let completion = match decision {
                Ok(completion) => completion,
                Err(stage) => return DurableAckDecision::Withheld(stage),
            };
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_durable_typed_completed",
                request_id = %hex::encode(request_id),
                ?completion,
            );
            if let Err(error) = self.cache.complete_durable(
                dedupe,
                DmAckOutcome::Accepted,
                envelope.protocol_version,
                binding,
            ) {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_replay_publish_failed",
                    request_id = %hex::encode(request_id),
                    ?error,
                    "v2 ACK withheld: durable typed completion could not be made replay-safe"
                );
                return DurableAckDecision::Withheld("replay_publish_failed");
            }
            let _ = self
                .publish_ack_for_protocol(
                    sender_agent_id,
                    request_id,
                    DmAckOutcome::Accepted,
                    envelope.protocol_version,
                    ack_legacy_bus,
                )
                .await;
            return DurableAckDecision::Acked {
                protocol_version: envelope.protocol_version,
                accepted: true,
            };
        }

        // 3. Durable-history lookup. Survives restart, where the in-memory
        //    replay cache above does not.
        let Ok(Some(record)) = inbound_dm_history_record(
            &envelope,
            &application_payload,
            sender_machine_id,
            &sender_pubkey,
        ) else {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_record_unbuildable",
                request_id = %hex::encode(request_id),
                "v2 DM withheld: payload has no durable history representation"
            );
            return DurableAckDecision::Withheld("no_durable_representation");
        };
        match durable_history_logical_request(
            &history,
            sender_agent_id,
            request_id,
            application_payload.clone(),
        )
        .await
        {
            Ok(DurableLogicalRequestLookup::Missing | DurableLogicalRequestLookup::Exact) => {}
            Ok(DurableLogicalRequestLookup::Conflict) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_logical_request_conflict",
                    request_id = %hex::encode(request_id),
                    sender = %hex::encode(sender_agent_id.as_bytes()),
                    "v2 DM rejected: logical request already committed with different content"
                );
                let _ = self
                    .publish_ack_for_protocol(
                        sender_agent_id,
                        request_id,
                        DmAckOutcome::IdempotencyConflict {
                            reason: "logical request already committed with different content"
                                .to_string(),
                        },
                        envelope.protocol_version,
                        ack_legacy_bus,
                    )
                    .await;
                return DurableAckDecision::Acked {
                    protocol_version: envelope.protocol_version,
                    accepted: false,
                };
            }
            Err(error) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_history_lookup_failed",
                    request_id = %hex::encode(request_id),
                    %error,
                    "v2 DM withheld: durable history lookup failed"
                );
                return DurableAckDecision::Withheld("history_lookup_failed");
            }
        }

        // 4. Dispatch.
        self.dm
            .handle_incoming(
                sender_machine_id,
                sender_agent_id,
                application_payload.clone(),
                true,
                Some(decision),
                // Gossip-inbox deliveries carry no point-to-point transport
                // observation (issue #120).
                None,
            )
            .await;

        // 5. Commit awaited. This is the step the v2 receipt is actually
        //    about: the ACK below may not exist unless this returned.
        match history.record_committed(record).await {
            Ok(outcome) if exact_durable_history_outcome(outcome) => {}
            Ok(outcome) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_commit_inexact",
                    request_id = %hex::encode(request_id),
                    ?outcome,
                    "v2 ACK withheld: history commit did not yield exactly one durable row"
                );
                return DurableAckDecision::Withheld("commit_inexact");
            }
            Err(error) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_commit_failed",
                    request_id = %hex::encode(request_id),
                    %error,
                    "v2 ACK withheld: durable history commit failed"
                );
                return DurableAckDecision::Withheld("commit_failed");
            }
        }

        // Publish the completion into the replay cache before acknowledging,
        // so a concurrent copy of this envelope can never be dispatched twice
        // by a peer that has already been told the request completed.
        if let Err(error) = self.cache.complete_durable(
            dedupe,
            DmAckOutcome::Accepted,
            envelope.protocol_version,
            binding,
        ) {
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_replay_publish_failed",
                request_id = %hex::encode(request_id),
                ?error,
                "v2 ACK withheld: durable completion could not be made replay-safe"
            );
            return DurableAckDecision::Withheld("replay_publish_failed");
        }

        // 6. ACK, stamped with the semantics actually honoured.
        let _ = self
            .publish_ack_for_protocol(
                sender_agent_id,
                request_id,
                DmAckOutcome::Accepted,
                envelope.protocol_version,
                ack_legacy_bus,
            )
            .await;

        tracing::info!(
            target: "dm.trace",
            stage = "inbound_durable_ack_published",
            request_id = %hex::encode(request_id),
            sender = %hex::encode(sender_agent_id.as_bytes()),
            protocol_version = envelope.protocol_version,
        );

        DurableAckDecision::Acked {
            protocol_version: envelope.protocol_version,
            accepted: true,
        }
    }

    /// Hand a durable (v2) payload to its typed route and wait for the
    /// handler's completion signal (ADR 0030 §7).
    ///
    /// `Err(stage)` names the reason the ACK must be withheld. Every failure
    /// mode lands there deliberately, because each one means the durable
    /// receipt would be unbacked:
    ///
    /// - the channel is full or closed — the handler never saw the payload;
    /// - the handler dropped the completion sender — including by returning
    ///   early on its own error path, so "forgot to answer" fails safe;
    /// - the handler reported an error;
    /// - the handler did not answer inside the budget.
    ///
    /// Only `Inserted | Duplicate` returns `Ok`.
    async fn dispatch_durable_typed_route(
        &self,
        sender_agent_id: AgentId,
        sender_machine_id: MachineId,
        request_id: [u8; 16],
        payload: Vec<u8>,
        trust_decision: Option<TrustDecision>,
    ) -> Result<DmTypedPayloadCompletion, &'static str> {
        let Some(route) = self
            .typed_payload_routes
            .iter()
            .find(|route| payload.starts_with(&route.prefix))
        else {
            return Err("typed_route_vanished");
        };
        let (completion_tx, completion_rx) = oneshot::channel();
        let typed = DmTypedPayload {
            sender: sender_agent_id,
            machine_id: sender_machine_id,
            payload,
            verified: true,
            trust_decision,
            received_at_unix_ms: now_unix_ms(),
            request_id,
            completion: Some(completion_tx),
        };
        // Still `try_send`, still non-blocking: this runs inline on the serial
        // inbox loop, so a full channel must not stall unrelated DMs. The
        // difference from the v1 path is what a drop means — there it was a
        // tolerable loss of a redundant fallback, here it withholds the ACK
        // and the sender retries.
        if let Err(error) = route.sender.try_send(typed) {
            self.dm.record_incoming_typed_route_dropped();
            tracing::warn!(
                target: "dm.trace",
                stage = "inbound_durable_typed_route_unavailable",
                request_id = %hex::encode(request_id),
                sender = %crate::logging::LogAgentId::from(&sender_agent_id),
                "v2 ACK withheld: typed route could not accept the payload ({error})"
            );
            return Err("typed_route_unavailable");
        }

        match tokio::time::timeout(DURABLE_TYPED_COMPLETION_TIMEOUT, completion_rx).await {
            Ok(Ok(Ok(completion))) => Ok(completion),
            Ok(Ok(Err(reason))) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_handler_failed",
                    request_id = %hex::encode(request_id),
                    %reason,
                    "v2 ACK withheld: typed-route handler reported failure"
                );
                Err("typed_handler_failed")
            }
            Ok(Err(_)) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_completion_dropped",
                    request_id = %hex::encode(request_id),
                    "v2 ACK withheld: typed-route handler dropped the completion channel"
                );
                Err("typed_completion_dropped")
            }
            Err(_) => {
                tracing::warn!(
                    target: "dm.trace",
                    stage = "inbound_durable_typed_completion_timeout",
                    request_id = %hex::encode(request_id),
                    timeout_secs = DURABLE_TYPED_COMPLETION_TIMEOUT.as_secs(),
                    "v2 ACK withheld: typed-route handler did not report completion in budget"
                );
                Err("typed_completion_timeout")
            }
        }
    }

    async fn route_typed_payload(
        &self,
        sender_agent_id: AgentId,
        sender_machine_id: MachineId,
        request_id: [u8; 16],
        payload: Vec<u8>,
        trust_decision: Option<TrustDecision>,
    ) -> bool {
        let Some(route) = self
            .typed_payload_routes
            .iter()
            .find(|route| payload.starts_with(&route.prefix))
        else {
            return false;
        };
        let typed = DmTypedPayload {
            sender: sender_agent_id,
            machine_id: sender_machine_id,
            payload,
            verified: true,
            trust_decision,
            received_at_unix_ms: now_unix_ms(),
            request_id,
            // v1 payloads make no durability promise, so there is nothing for
            // a handler to report; the ACK is level-2 enqueue either way.
            completion: None,
        };
        // Best-effort, NON-BLOCKING hand-off. These typed routes (the
        // group-public-message and KvStore-delta gossip-DM fallbacks) are
        // redundant delivery paths — primary fan-out is per-group/store pubsub.
        // We must not `send().await`: this runs inline in the single DM-inbox
        // subscription loop that also publishes ACKs, so a slow or
        // lock-contended route consumer filling the bounded channel would block
        // ACK delivery for unrelated senders (surfacing as 504s now that
        // `require_gossip_ack` defaults true). Drop on a full channel and count
        // it rather than stalling the pipeline.
        match route.sender.try_send(typed) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dm.record_incoming_typed_route_dropped();
                tracing::warn!(
                    sender = %crate::logging::LogAgentId::from(&sender_agent_id),
                    "typed DM payload route channel full; dropping redundant fallback payload"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    sender = %crate::logging::LogAgentId::from(&sender_agent_id),
                    "typed DM payload route receiver is closed; dropping payload"
                );
            }
        }
        true
    }

    /// Emit a v1 ACK: verified and locally enqueued (receipt level 2).
    async fn publish_ack(
        &self,
        to: AgentId,
        acks_request_id: [u8; 16],
        outcome: DmAckOutcome,
        ack_legacy_bus: bool,
    ) -> NetworkResult<()> {
        self.publish_ack_for_protocol(to, acks_request_id, outcome, DM_PROTOCOL_V1, ack_legacy_bus)
            .await
    }

    /// Emit an ACK stamped with the semantics this receiver actually honoured.
    ///
    /// ADR 0030: `protocol_version` names the receipt the recipient is
    /// claiming, and the sender's waiter matches it exactly. Callers must pass
    /// [`DM_PROTOCOL_DURABLE_ACK`] only from the durable path, after
    /// `record_committed` has returned — never as an optimistic stamp.
    async fn publish_ack_for_protocol(
        &self,
        to: AgentId,
        acks_request_id: [u8; 16],
        outcome: DmAckOutcome,
        protocol_version: u16,
        ack_legacy_bus: bool,
    ) -> NetworkResult<()> {
        let body = EnvelopeBuilder::build_ack_body(acks_request_id, outcome);
        let created = now_unix_ms();
        let expires = created + ACK_ENVELOPE_LIFETIME_MS;
        let mut ack_rid = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut ack_rid);

        let mut envelope = DmEnvelope {
            // ADR 0030: an ACK is stamped with the semantics this receiver
            // actually honoured, not with the local ceiling. Only the durable
            // path passes v2, and only once the history commit has returned;
            // everything else stays v1 so a v2 waiter times out rather than
            // being handed a receipt no one made.
            protocol_version,
            request_id: ack_rid,
            sender_agent_id: *self.self_agent_id.as_bytes(),
            sender_machine_id: *self.self_machine_id.as_bytes(),
            recipient_agent_id: *to.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: expires,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        let signed = envelope
            .signed_bytes()
            .map_err(|e| NetworkError::SerializationError(format!("ack sign-bytes: {e}")))?;
        envelope.signature = self.signing.sign(&signed)?;
        // #213: attest the acking machine too — a fake `Accepted` ACK from
        // a revoked machine would otherwise forge a delivery receipt.
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            self.machine_keypair.public_key().as_bytes().to_vec(),
        );
        attestation.sign(&self.machine_keypair).map_err(|e| {
            NetworkError::SerializationError(format!("ack origin attestation: {e}"))
        })?;
        envelope.origin_attestation = Some(attestation);
        let encoded = envelope
            .to_wire_bytes()
            .map_err(|e| NetworkError::SerializationError(format!("ack encode: {e}")))?;
        let result = if protocol_version >= DM_PROTOCOL_DURABLE_ACK {
            // Durable v2 owns both publications in the bounded background
            // worker. The inbox loop can immediately process a subsequent DM
            // while the target and compatibility-bus routes retain their full
            // healthy-congestion budgets. Ordering is unaffected: the history
            // commit is already awaited before we get here, so this only makes
            // the *publication* asynchronous, never the promise behind it.
            self.ack_publisher.try_publish(AckPublishJob {
                recipient: to,
                acked_request_id: acks_request_id,
                protocol_version,
                encoded: Bytes::from(encoded),
            })
        } else {
            // Preserve v1 exactly: target first, and only publish back on the
            // compatibility bus when this payload itself arrived there. No
            // new deadline or background ownership changes legacy behavior.
            let topic = DmInboxService::inbox_topic_name(&to);
            let primary = self
                .pubsub
                .publish_topic_id(topic, dm_inbox_topic(&to), Bytes::from(encoded.clone()))
                .await;
            let legacy = if ack_legacy_bus {
                self.pubsub
                    .publish(DM_BUS_TOPIC.to_string(), Bytes::from(encoded))
                    .await
            } else {
                Ok(())
            };
            primary.and(legacy)
        };
        if let Err(error) = &result {
            self.dm.record_ack_publish_route_failed();
            tracing::warn!(
                target: "dm.trace",
                stage = "ack_publish_route_failed",
                acked_request_id = %hex::encode(acks_request_id),
                recipient = %hex::encode(to.as_bytes()),
                protocol_version,
                %error,
                "ACK publication could not be scheduled or completed"
            );
        }
        result
    }
}

/// Enforcement point 3 decision (issue #130): if `sender` is revoked, record
/// the `incoming_dropped_revoked` counter and return `true` (the caller must
/// drop the DM). Returns `false` for a non-revoked sender without touching the
/// counter.
///
/// Pure revocation-gate predicate for the gossip DM path (EP3).
///
/// Drops (and counts) a DM whose sender agent OR originating machine is in
/// the local revocation set — matching the raw-QUIC direct path
/// (`direct::inbound_peer_revoked`) and EP1/EP2, so both DM paths are
/// fail-closed on a machine revocation even when the agent-id is clean
/// (issue #184). Extracted as a pure function of
/// `(DirectMessaging, RevocationSet, AgentId, MachineId)` so the gate can be
/// unit-tested without a live inbox pipeline, and so a future refactor of
/// `handle_incoming` cannot silently drop the counter side-effect.
fn drop_if_sender_revoked(
    dm: &DirectMessaging,
    revoked: &RevocationSet,
    sender: &AgentId,
    machine: &MachineId,
) -> bool {
    if revoked.is_agent_revoked(sender) || revoked.is_machine_revoked(machine) {
        dm.record_incoming_dropped_revoked();
        true
    } else {
        false
    }
}

pub fn verify_envelope_signature(envelope: &DmEnvelope, public_key_bytes: &[u8]) -> bool {
    let signed = match envelope.signed_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let public_key = match ant_quic::MlDsaPublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let derived = AgentId::from_public_key(&public_key);
    if derived.0 != envelope.sender_agent_id {
        return false;
    }
    let signature = match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
        &envelope.signature,
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &signed, &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::TrustLevel;
    use crate::dm::MAX_ENVELOPE_BYTES;
    use crate::identity::{AgentKeypair, MachineKeypair};
    use crate::network::{NetworkConfig, NetworkNode};
    use std::time::Duration;

    fn test_keypair() -> AgentKeypair {
        AgentKeypair::generate().expect("keygen")
    }

    fn make_unsigned_envelope(sender_kp: &AgentKeypair, recipient_id: &[u8; 32]) -> DmEnvelope {
        let now = now_unix_ms();
        DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: [1u8; 16],
            sender_agent_id: *sender_kp.agent_id().as_bytes(),
            sender_machine_id: [2u8; 32],
            recipient_agent_id: *recipient_id,
            created_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            body: DmBody::Ack(crate::dm::DmAckBody {
                acks_request_id: [3u8; 16],
                outcome: crate::dm::DmAckOutcome::Accepted,
            }),
            signature: Vec::new(),
            origin_attestation: None,
        }
    }

    fn sign_envelope(envelope: &mut DmEnvelope, sender_kp: &AgentKeypair) {
        let signed = envelope.signed_bytes().expect("signed_bytes");
        let sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            sender_kp.secret_key(),
            &signed,
        )
        .expect("sign");
        envelope.signature = sig.as_bytes().to_vec();
    }

    struct InboxHarness {
        /// Keeps the durable-ACK worker alive for the harness's lifetime.
        /// Dropping it closes the queue and every v2 ACK would fail to
        /// schedule, which would look like a protocol bug in every test.
        _ack_worker: JoinHandle<()>,
        pipeline: InboxPipeline,
        recipient_agent_id: AgentId,
        recipient_kem: Arc<AgentKemKeypair>,
        receiver: crate::direct::DirectMessageReceiver,
        _tempdir: tempfile::TempDir,
    }

    async fn make_inbox_harness(
        sender: &AgentKeypair,
        authenticated_machine: Option<MachineId>,
        revoked_machine: Option<&MachineKeypair>,
    ) -> InboxHarness {
        make_inbox_harness_with_hedge(sender, authenticated_machine, revoked_machine, None).await
    }

    async fn make_inbox_harness_with_hedge(
        sender: &AgentKeypair,
        authenticated_machine: Option<MachineId>,
        revoked_machine: Option<&MachineKeypair>,
        direct_hedge: Option<Arc<dyn DirectAckHedge>>,
    ) -> InboxHarness {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut contacts = ContactStore::new(tempdir.path().join("contacts.json"));
        contacts.set_trust(&sender.agent_id(), TrustLevel::Trusted);

        let recipient = AgentKeypair::generate().expect("recipient keygen");
        let recipient_agent_id = recipient.agent_id();
        let recipient_machine_id = MachineId([0xCC; 32]);
        let recipient_kem = Arc::new(AgentKemKeypair::generate().expect("recipient KEM"));
        let dm = Arc::new(DirectMessaging::new());
        let receiver = dm.subscribe();
        let node = Arc::new(
            NetworkNode::new(NetworkConfig::default(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let authenticated_machine_bindings =
            Arc::new(RwLock::new(AuthenticatedMachineBindingCache::default()));
        if let Some(machine_id) = authenticated_machine {
            record_authenticated_machine_binding(
                &authenticated_machine_bindings,
                sender.agent_id(),
                machine_id,
                100,
            )
            .await;
        }

        let mut revocation_set = RevocationSet::new();
        if let Some(machine) = revoked_machine {
            let record = crate::revocation::RevocationRecord::sign(
                crate::revocation::RevokedSubject::Machine(machine.machine_id()),
                machine.public_key(),
                machine.secret_key(),
                now_unix_ms() / 1000,
                Some("compromised machine".to_string()),
            )
            .expect("sign machine revocation");
            revocation_set
                .verify_and_insert(record, None)
                .expect("insert machine revocation");
        }

        let (ack_publisher, ack_worker) =
            spawn_durable_ack_publisher(Arc::clone(&pubsub), Arc::clone(&dm), direct_hedge);
        let pipeline = InboxPipeline {
            pubsub,
            signing: Arc::new(SigningContext::from_keypair(&recipient)),
            self_agent_id: recipient_agent_id,
            self_machine_id: recipient_machine_id,
            machine_keypair: Arc::new(
                MachineKeypair::generate().expect("recipient machine keygen"),
            ),
            kem_keypair: Arc::clone(&recipient_kem),
            dm,
            contacts: Arc::new(RwLock::new(contacts)),
            inflight: Arc::new(InFlightAcks::new()),
            cache: Arc::new(RecentDeliveryCache::with_defaults()),
            silent_reject: true,
            typed_payload_routes: Vec::new(),
            revocation_set: Arc::new(RwLock::new(revocation_set)),
            authenticated_machine_bindings,
            history: None,
            ack_publisher,
        };

        InboxHarness {
            _ack_worker: ack_worker,
            pipeline,
            recipient_agent_id,
            recipient_kem,
            receiver,
            _tempdir: tempdir,
        }
    }

    /// Build a signed-but-unattested payload envelope, simulating a
    /// pre-#213 (legacy) sender: agent signature only, no origin attestation.
    /// The trust/origin/revocation regression suite below is about the gates
    /// that run before any protocol version matters, so it builds v1
    /// envelopes: these tests predate DM v2 and only became v2 incidentally
    /// when slice 1 raised `DM_PROTOCOL_VERSION` to the durable-ACK ceiling.
    /// The durable path has its own envelopes via `durable_payload_message`.
    fn craft_unsigned_payload_envelope(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
    ) -> DmEnvelope {
        craft_unsigned_payload_envelope_versioned(
            harness,
            sender,
            claimed_machine,
            request_byte,
            DM_PROTOCOL_V1,
            b"security regression payload".to_vec(),
        )
    }

    fn craft_unsigned_payload_envelope_versioned(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
        protocol_version: u16,
        application_payload: Vec<u8>,
    ) -> DmEnvelope {
        let created_at = now_unix_ms();
        let body = EnvelopeBuilder::build_payload_body(
            &[request_byte; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created_at,
            application_payload,
            None,
            &harness.recipient_kem.public_bytes,
        )
        .expect("build payload body");
        DmEnvelope {
            protocol_version,
            request_id: [request_byte; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *claimed_machine.as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created_at,
            expires_at_unix_ms: created_at + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        }
    }

    fn sign_envelope_with_agent(envelope: &mut DmEnvelope, sender: &AgentKeypair) {
        let signed = envelope.signed_bytes().expect("signed_bytes");
        let sig =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(sender.secret_key(), &signed)
                .expect("agent sign");
        envelope.signature = sig.as_bytes().to_vec();
    }

    fn wrap_in_pubsub(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        envelope: &DmEnvelope,
    ) -> PubSubMessage {
        PubSubMessage {
            topic: DmInboxService::inbox_topic_name(&harness.recipient_agent_id),
            payload: Bytes::from(envelope.to_wire_bytes().expect("encode envelope")),
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: Some(TrustLevel::Trusted),
            raw_envelope: None,
        }
    }

    /// Legacy (pre-#213) sender: signed envelope, NO origin attestation.
    fn payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
    ) -> PubSubMessage {
        let mut envelope =
            craft_unsigned_payload_envelope(harness, sender, claimed_machine, request_byte);
        sign_envelope_with_agent(&mut envelope, sender);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    /// #213 sender: signed envelope WITH a valid origin attestation from
    /// `machine` (which therefore owns `sender_machine_id`).
    fn attested_payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: &MachineKeypair,
        request_byte: u8,
    ) -> PubSubMessage {
        let mut envelope =
            craft_unsigned_payload_envelope(harness, sender, machine.machine_id(), request_byte);
        sign_envelope_with_agent(&mut envelope, sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(machine).expect("machine attest");
        envelope.origin_attestation = Some(attestation);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    // ── ADR 0030 §1 receiver durable path ─────────────────────────────

    /// Start a real history service in the harness tempdir and attach its
    /// handle to the pipeline. The service is returned so a test can shut the
    /// writer down mid-flight to force a commit failure.
    fn attach_history(harness: &mut InboxHarness) -> crate::history::HistoryService {
        let config = crate::history::HistoryConfig {
            db_path: Some(harness._tempdir.path().join("history.db")),
            ..crate::history::HistoryConfig::daemon_default()
        };
        let service = crate::history::HistoryService::start(&config, harness._tempdir.path())
            .expect("history service");
        harness.pipeline.history = Some(service.handle());
        service
    }

    /// A signed v2 (durable) payload envelope carrying `application_payload`.
    fn durable_payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
        application_payload: &[u8],
    ) -> PubSubMessage {
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            harness,
            sender,
            claimed_machine,
            request_byte,
            DM_PROTOCOL_DURABLE_ACK,
            application_payload.to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, sender);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    fn committed_rows(
        history: &crate::history::HistoryHandle,
        sender: &AgentKeypair,
        request_byte: u8,
    ) -> Vec<crate::history::StoredRecord> {
        history
            .store()
            .find_by_logical_request(
                &hex::encode(sender.agent_id().as_bytes()),
                [request_byte; 16],
            )
            .expect("logical request lookup")
    }

    /// ADR 0030 §1: the ACK exists only because the commit succeeded. With the
    /// writer stopped the commit cannot succeed, so no ACK may be emitted —
    /// and crucially it must NOT degrade to a v1 ACK, which would hand the
    /// sender a weaker receipt it cannot tell apart from the durable one.
    #[tokio::test]
    async fn durable_ack_is_withheld_when_history_commit_fails() {
        let sender = test_keypair();
        let machine = MachineId([0xD1; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        // Stop the writer thread; the retained handle now fails every commit.
        service.shutdown().await;

        let message = durable_payload_message(&harness, &sender, machine, 0x51, b"durable hello");
        harness.pipeline.handle_incoming(message, false).await;

        assert!(
            committed_rows(&history, &sender, 0x51).is_empty(),
            "a failed commit must leave no durable row"
        );
        assert!(
            harness
                .pipeline
                .cache
                .lookup(&crate::dm::DedupeKey::new(
                    *sender.agent_id().as_bytes(),
                    [0x51; 16]
                ))
                .is_none(),
            "a withheld ACK must not publish a completion into the replay cache"
        );
    }

    /// The same ordering asserted directly on the durable path's decision, so
    /// "no ACK" is a checked outcome rather than an absence inferred from
    /// side effects.
    #[tokio::test]
    async fn durable_path_reports_withheld_ack_on_commit_failure() {
        let sender = test_keypair();
        let machine = MachineId([0xD2; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let service = attach_history(&mut harness);
        service.shutdown().await;

        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x52,
            DM_PROTOCOL_DURABLE_ACK,
            b"durable hello".to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);

        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                b"durable hello".to_vec(),
                TrustDecision::Accept,
                machine,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;

        assert_eq!(decision, DurableAckDecision::Withheld("commit_failed"));
    }

    /// Happy path: commit lands first, then a v2-stamped ACK, and the schema
    /// v4 columns are populated — they are what makes the restart-spanning
    /// lookup in step 3 possible at all.
    #[tokio::test]
    async fn durable_path_commits_before_acking_and_stamps_v2() {
        let sender = test_keypair();
        let machine = MachineId([0xD3; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x53,
            DM_PROTOCOL_DURABLE_ACK,
            b"durable hello".to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);

        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                b"durable hello".to_vec(),
                TrustDecision::Accept,
                machine,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;

        assert_eq!(
            decision,
            DurableAckDecision::Acked {
                protocol_version: DM_PROTOCOL_DURABLE_ACK,
                accepted: true,
            }
        );

        let rows = committed_rows(&history, &sender, 0x53);
        assert_eq!(rows.len(), 1, "exactly one durable row per logical request");
        assert_eq!(rows[0].record.payload, b"durable hello".to_vec());
        assert_eq!(
            rows[0].record.ingress_sender_agent.as_deref(),
            Some(hex::encode(sender.agent_id().as_bytes()).as_str()),
            "schema v4 ingress_sender_agent must be written"
        );
        assert_eq!(
            rows[0].record.logical_request_id,
            Some([0x53; 16]),
            "schema v4 logical_request_id must be written"
        );
    }

    /// ADR 0030 §1 step 2: a replayed logical request is re-ACKed from the
    /// binding, never dispatched or committed a second time.
    #[tokio::test]
    async fn durable_replay_rebinds_instead_of_committing_twice() {
        let sender = test_keypair();
        let machine = MachineId([0xD4; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        for _ in 0..2 {
            let message =
                durable_payload_message(&harness, &sender, machine, 0x54, b"durable hello");
            harness.pipeline.handle_incoming(message, false).await;
        }

        let rows = committed_rows(&history, &sender, 0x54);
        assert_eq!(
            rows.len(),
            1,
            "a replayed logical request must not commit a second durable row"
        );
    }

    /// ADR 0030 §1 step 2: the binding is over the accepted bytes, so the
    /// same request id carrying different content is refused rather than
    /// re-ACKed as the original delivery.
    #[tokio::test]
    async fn durable_replay_with_different_bytes_is_refused() {
        let sender = test_keypair();
        let machine = MachineId([0xD5; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);

        let first = durable_payload_message(&harness, &sender, machine, 0x55, b"original bytes");
        harness.pipeline.handle_incoming(first, false).await;

        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x55,
            DM_PROTOCOL_DURABLE_ACK,
            b"different bytes".to_vec(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);
        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                b"different bytes".to_vec(),
                TrustDecision::Accept,
                machine,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;

        assert_eq!(
            decision,
            DurableAckDecision::Acked {
                protocol_version: DM_PROTOCOL_DURABLE_ACK,
                accepted: false,
            },
            "a rebound logical request must be refused, not accepted"
        );
    }

    /// Subscribe to the topic ACKs for `sender` land on, so a test can assert
    /// the outcome the receiver actually put on the wire. `DurableAckDecision`
    /// records only *that* a refusal was ACKed; which refusal it was is the
    /// whole product contract, and it is only observable here.
    async fn watch_acks_to(harness: &InboxHarness, sender: &AgentKeypair) -> Subscription {
        harness
            .pipeline
            .pubsub
            .subscribe_topic_id(
                DmInboxService::inbox_topic_name(&sender.agent_id()),
                dm_inbox_topic(&sender.agent_id()),
            )
            .await
    }

    async fn next_ack_outcome(subscription: &mut Subscription) -> DmAckOutcome {
        let message = tokio::time::timeout(Duration::from_secs(5), subscription.recv())
            .await
            .expect("an ACK must be published within the timeout")
            .expect("ACK subscription closed before an ACK arrived");
        let envelope =
            DmEnvelope::from_wire_bytes(&message.payload).expect("ACK envelope should decode");
        match envelope.body {
            DmBody::Ack(ack) => ack.outcome,
            other => panic!("expected an ACK envelope, got {other:?}"),
        }
    }

    /// ADR 0030 slice 4 rebind. Both binding-conflict sites answered
    /// `AckSemanticsUnavailable` until `IdempotencyConflict` existed, which
    /// told a product "the peer needs upgrading" when the truth was "your
    /// client reused an idempotency key for different bytes". The two errors
    /// prescribe opposite repairs — retry-later versus never-retry-these-bytes
    /// — so conflating them is a user-visible defect, not a naming quibble.
    #[tokio::test]
    async fn a_rebound_logical_request_is_answered_idempotency_conflict() {
        let sender = test_keypair();
        let machine = MachineId([0xD6; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let mut acks = watch_acks_to(&harness, &sender).await;

        let first = durable_payload_message(&harness, &sender, machine, 0x56, b"original bytes");
        harness.pipeline.handle_incoming(first, false).await;
        assert_eq!(
            next_ack_outcome(&mut acks).await,
            DmAckOutcome::Accepted,
            "the first delivery is a normal durable acceptance"
        );

        // Replay-cache binding check: the id is still hot in memory.
        let rebound = durable_payload_message(&harness, &sender, machine, 0x56, b"different bytes");
        harness.pipeline.handle_incoming(rebound, false).await;
        let hot = next_ack_outcome(&mut acks).await;
        assert!(
            matches!(hot, DmAckOutcome::IdempotencyConflict { .. }),
            "a hot rebind must be an idempotency conflict, not a capability gap: {hot:?}"
        );

        // Restart: the replay cache is memory-only (ADR 0030 §1), so the same
        // rebind must now be caught by the durable-history lookup instead —
        // the site that has to reach the same verdict for the guarantee to
        // survive a crash.
        harness.pipeline.cache = Arc::new(RecentDeliveryCache::with_defaults());
        let after_restart =
            durable_payload_message(&harness, &sender, machine, 0x56, b"different bytes");
        harness.pipeline.handle_incoming(after_restart, false).await;
        assert!(
            matches!(
                next_ack_outcome(&mut acks).await,
                DmAckOutcome::IdempotencyConflict { .. }
            ),
            "the durable-history conflict path must agree with the replay-cache path"
        );
    }

    /// ADR 0030 §2 mixed version: a 0.37 peer's v1 envelope keeps exactly its
    /// old behaviour on a durable-capable receiver — delivered, and ACKed with
    /// v1 semantics. Enabling durable history must not silently upgrade the
    /// receipt an old sender is handed.
    #[tokio::test]
    async fn v1_envelope_receives_v1_ack_even_with_durable_history_enabled() {
        let sender = test_keypair();
        let machine = MachineId([0xD6; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);

        let message = payload_message(&harness, &sender, machine, 0x56);
        harness.pipeline.handle_incoming(message, false).await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("v1 delivery timeout")
            .expect("v1 delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());

        let cached = harness
            .pipeline
            .cache
            .lookup(&crate::dm::DedupeKey::new(
                *sender.agent_id().as_bytes(),
                [0x56; 16],
            ))
            .expect("v1 completion is cached");
        assert_eq!(
            cached.protocol_version, DM_PROTOCOL_V1,
            "a v1 envelope must complete under v1 semantics"
        );
        assert!(
            cached.durable_binding.is_none(),
            "the v1 path must not publish a durable binding"
        );
    }

    /// ADR 0030 §2: a v2 request is never silently downgraded. Without a
    /// history handle there is nothing to commit to, so the ACK is withheld
    /// rather than answered at v1.
    #[tokio::test]
    async fn v2_envelope_without_history_is_never_downgraded_to_v1() {
        let sender = test_keypair();
        let machine = MachineId([0xD7; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        assert!(harness.pipeline.history.is_none());

        let message = durable_payload_message(&harness, &sender, machine, 0x57, b"durable hello");
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .cache
                .lookup(&crate::dm::DedupeKey::new(
                    *sender.agent_id().as_bytes(),
                    [0x57; 16]
                ))
                .is_none(),
            "a withheld v2 request must leave no completion behind"
        );
    }

    /// Drive one v2 typed payload through the durable path with `route`
    /// installed, returning the decision. `respond` receives the payload the
    /// handler would see and decides what (if anything) to report back.
    async fn durable_typed_decision<F>(
        request_byte: u8,
        durable_completion: bool,
        respond: F,
    ) -> DurableAckDecision
    where
        F: FnOnce(DmTypedPayload) + Send + 'static,
    {
        let sender = test_keypair();
        let machine = MachineId([0xD8; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let (tx, mut rx) = mpsc::channel::<DmTypedPayload>(8);
        harness.pipeline.typed_payload_routes = vec![DmTypedPayloadRoute {
            durable_completion,
            prefix: b"X0X-KV-DELTA-V1\n".to_vec(),
            sender: tx,
        }];
        let handler = tokio::spawn(async move {
            if let Some(typed) = rx.recv().await {
                respond(typed);
            }
        });

        let mut payload = b"X0X-KV-DELTA-V1\n".to_vec();
        payload.extend_from_slice(b"{\"k\":1}");
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            request_byte,
            DM_PROTOCOL_DURABLE_ACK,
            payload.clone(),
        );
        sign_envelope_with_agent(&mut envelope, &sender);

        let decision = harness
            .pipeline
            .handle_payload_durable(
                envelope,
                payload,
                TrustDecision::Accept,
                machine,
                sender.public_key().as_bytes().to_vec(),
                false,
            )
            .await;
        handler.abort();
        decision
    }

    /// ADR 0030 §7 obligation upgrade — this is the slice-2 lock, deliberately
    /// changed. Slice 2 withheld every v2 ACK on a typed route; slice 3 lets a
    /// handler earn one by reporting that the payload is durably recorded on
    /// its own surface. `Inserted` and `Duplicate` are the only signals that
    /// release the ACK, mirroring the history store's proof that exactly one
    /// durable record exists.
    #[tokio::test]
    async fn durable_typed_route_acks_on_handler_completion() {
        for completion in [
            DmTypedPayloadCompletion::Inserted,
            DmTypedPayloadCompletion::Duplicate,
        ] {
            let decision = durable_typed_decision(0x58, true, move |typed| {
                assert_eq!(
                    typed.request_id, [0x58; 16],
                    "handler must receive the logical request id it dedupes on"
                );
                if let Some(tx) = typed.completion {
                    let _ = tx.send(Ok(completion));
                }
            })
            .await;
            assert_eq!(
                decision,
                DurableAckDecision::Acked {
                    protocol_version: DM_PROTOCOL_DURABLE_ACK,
                    accepted: true,
                },
                "{completion:?} must release the durable ACK"
            );
        }
    }

    /// A route that has not opted in still gets no v2 ACK. This daemon will
    /// not certify durability for a handler that never promised it — stated
    /// policy, which is why it has its own distinct stage.
    #[tokio::test]
    async fn durable_typed_route_without_opt_in_is_withheld_by_policy() {
        let decision = durable_typed_decision(0x59, false, |_typed| {}).await;
        assert_eq!(
            decision,
            DurableAckDecision::Withheld("typed_route_not_durable")
        );
    }

    /// Every way a handler can fail to confirm withholds the ACK. Each of
    /// these would otherwise hand the sender a durable receipt for a payload
    /// that was never durably recorded.
    #[tokio::test]
    async fn durable_typed_route_withholds_on_every_non_completion() {
        // Handler reports failure.
        assert_eq!(
            durable_typed_decision(0x5A, true, |typed| {
                if let Some(tx) = typed.completion {
                    let _ = tx.send(Err("store write failed".to_string()));
                }
            })
            .await,
            DurableAckDecision::Withheld("typed_handler_failed")
        );

        // Handler drops the completion sender — the "forgot to answer" case,
        // including any early return on the handler's own error path.
        assert_eq!(
            durable_typed_decision(0x5B, true, |typed| {
                drop(typed.completion);
            })
            .await,
            DurableAckDecision::Withheld("typed_completion_dropped")
        );
    }

    #[test]
    fn cached_v1_completion_refuses_a_v2_request() {
        let cached = crate::dm::CachedOutcome {
            outcome: DmAckOutcome::Accepted,
            protocol_version: DM_PROTOCOL_V1,
            durable_binding: None,
            first_seen: std::time::Instant::now(),
        };
        // ADR 0030 §2 names this outcome explicitly. It must NOT be
        // `RejectedByPolicy`: nothing about the trust relationship failed,
        // and the sender maps that variant to `RecipientRejected`, which
        // would tell a product UI "peer blocked you" instead of "you cannot
        // have a durable receipt for this request".
        assert!(matches!(
            cached_ack_for_protocol(&cached, DM_PROTOCOL_DURABLE_ACK),
            DmAckOutcome::AckSemanticsUnavailable { .. }
        ));
        assert!(matches!(
            cached_ack_for_protocol(&cached, DM_PROTOCOL_V1),
            DmAckOutcome::Accepted
        ));
    }

    /// Wire safety for the appended `AckSemanticsUnavailable` variant: a
    /// v1-only 0.37 peer can never be sent it, because it asks for at most v1
    /// and any cached completion is at least v1. If this ever regresses, an
    /// 0.37 receiver would fail to postcard-decode the ACK and the send would
    /// degrade to a timeout.
    #[test]
    fn a_v1_request_is_never_answered_with_the_new_ack_variant() {
        for cached_version in [DM_PROTOCOL_V1, DM_PROTOCOL_DURABLE_ACK] {
            for outcome in [
                DmAckOutcome::Accepted,
                DmAckOutcome::RejectedByPolicy {
                    reason: "blocked".to_string(),
                },
            ] {
                let cached = crate::dm::CachedOutcome {
                    outcome,
                    protocol_version: cached_version,
                    durable_binding: None,
                    first_seen: std::time::Instant::now(),
                };
                assert!(
                    !matches!(
                        cached_ack_for_protocol(&cached, DM_PROTOCOL_V1),
                        DmAckOutcome::AckSemanticsUnavailable { .. }
                    ),
                    "a v1 request must never be answered with a variant 0.37 cannot decode"
                );
            }
        }
    }

    /// ADR 0030 ACK liveness: the durable publisher must never make the inbox
    /// loop wait. A saturated queue is reported to the caller rather than
    /// awaited — the receiver has already committed, so the sender timing out
    /// is the documented safe failure, whereas blocking here would stall every
    /// later DM behind one wedged ACK route.
    #[tokio::test]
    async fn a_saturated_ack_queue_is_reported_rather_than_awaited() {
        let (sender, mut receiver) = mpsc::channel(DURABLE_ACK_QUEUE_CAPACITY);
        let handle = AckPublisherHandle { sender };
        let job = || AckPublishJob {
            recipient: AgentId([7; 32]),
            acked_request_id: [1; 16],
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            encoded: Bytes::from_static(b"ack"),
        };

        for _ in 0..DURABLE_ACK_QUEUE_CAPACITY {
            handle
                .try_publish(job())
                .expect("queue accepts up to its capacity");
        }
        assert!(
            matches!(
                handle.try_publish(job()),
                Err(NetworkError::RemoteReceiveBackpressured(_))
            ),
            "the job past capacity must be refused, not block the inbox loop"
        );

        receiver.close();
        while receiver.try_recv().is_ok() {}
        assert!(
            matches!(
                handle.try_publish(job()),
                Err(NetworkError::ChannelClosed(_))
            ),
            "a stopped worker must surface as an error, never a silent drop"
        );
    }

    /// Both routes failing is still an error; the caller records
    /// `ack_publish_route_failed` so gates can tell ACK never left.
    #[tokio::test]
    async fn both_failed_ack_routes_are_an_error() {
        let primary = async { Err(NetworkError::BroadcastError("targeted".into())) };
        let legacy = async { Err(NetworkError::BroadcastError("legacy-bus".into())) };
        let result = publish_durable_ack_routes(DURABLE_ACK_ROUTE_TIMEOUT, primary, legacy).await;
        assert!(
            matches!(result, Err(NetworkError::BroadcastError(_))),
            "both-fail must remain Err + ack_publish_route_failed at the caller: {result:?}"
        );
    }

    #[test]
    fn reverse_ack_prewarm_is_only_for_a_trusted_other_peer() {
        let self_id = AgentId([1; 32]);
        let peer = AgentId([2; 32]);
        assert!(
            should_warm_reverse_ack(true, &self_id, &peer),
            "a Trusted other peer is the Direct-connect pre-warm case"
        );
        assert!(
            !should_warm_reverse_ack(false, &self_id, &peer),
            "untrusted peers must not join extra inbox topics on connect"
        );
        assert!(
            !should_warm_reverse_ack(true, &self_id, &self_id),
            "self-connect must not pre-warm"
        );
    }

    /// Invariant: first durable send to a Direct-connected peer must not be
    /// the event that joins self inbox, peer inbox, or the compatibility bus.
    /// Warm uses the real inbox `TopicId`s (Leaf-safe subscribed path), not
    /// the name-derived ids `refresh_topic_peers` would invent.
    #[tokio::test]
    async fn reverse_ack_prewarm_joins_inbox_and_bus_before_any_publish() {
        let node = Arc::new(
            NetworkNode::new(NetworkConfig::default(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub = PubSubManager::new(node, None).expect("pubsub");
        let self_id = AgentId([0xA1; 32]);
        let peer = AgentId([0xB2; 32]);
        let self_inbox = dm_inbox_topic(&self_id);
        let peer_inbox = dm_inbox_topic(&peer);
        let bus = saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes());
        let name_derived = saorsa_gossip_types::TopicId::from_entity(
            DmInboxService::inbox_topic_name(&self_id).as_bytes(),
        );
        assert_ne!(
            self_inbox, name_derived,
            "inbox TopicId is domain-separated; a name-derived id is the pass-through trap"
        );

        let before = pubsub.plumtree_topic_ids().await;
        assert!(
            !before.contains(&self_inbox)
                && !before.contains(&peer_inbox)
                && !before.contains(&bus),
            "pre-warm must be what joins these topics, not PubSubManager construction"
        );

        warm_reverse_ack_topics(&pubsub, &self_id, &peer).await;

        let warmed = pubsub.plumtree_topic_ids().await;
        assert!(
            warmed.contains(&self_inbox),
            "self inbox (where ACKs land) must be joined before first durable POST: {warmed:?}"
        );
        assert!(
            warmed.contains(&peer_inbox),
            "peer inbox must be joined before first durable POST: {warmed:?}"
        );
        assert!(
            warmed.contains(&bus),
            "compatibility bus must be joined before first durable POST: {warmed:?}"
        );
        assert!(
            !warmed.contains(&name_derived),
            "must not create a name-derived pass-through topic id (Leaf hygiene)"
        );

        pubsub
            .publish_topic_id(
                DmInboxService::inbox_topic_name(&peer),
                peer_inbox,
                Bytes::from_static(b"not-the-join"),
            )
            .await
            .expect("publish after pre-warm");
        let after_publish = pubsub.plumtree_topic_ids().await;
        assert!(
            after_publish.contains(&peer_inbox),
            "publish must reuse the pre-warmed peer inbox membership"
        );
    }

    /// #396 race regression: concurrent warmers (outbound Direct connect vs
    /// inbound PeerConnected) must converge to exactly ONE membership hold
    /// per topic. The original check-then-insert read the refcount, then
    /// subscribed, then inserted the hold under three separate lock
    /// acquisitions — both warmers observed "not subscribed", both spawned
    /// permanent drain holds, leaking a duplicate subscription per topic
    /// forever. The fix linearizes creation under the holds write guard.
    #[tokio::test]
    async fn concurrent_reverse_ack_warmers_create_a_single_membership_hold() {
        let node = Arc::new(
            NetworkNode::new(NetworkConfig::default(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub = Arc::new(PubSubManager::new(node, None).expect("pubsub"));
        let peer = AgentId([0xC4; 32]);
        let peer_inbox_topic_id = dm_inbox_topic(&peer);
        let peer_inbox_name = DmInboxService::inbox_topic_name(&peer);

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut warmers = Vec::new();
        for _ in 0..2 {
            let pubsub = Arc::clone(&pubsub);
            let barrier = Arc::clone(&barrier);
            let name = peer_inbox_name.clone();
            warmers.push(tokio::spawn(async move {
                barrier.wait().await;
                pubsub
                    .ensure_subscribed_topic_id(&name, peer_inbox_topic_id)
                    .await;
            }));
        }
        for warmer in warmers {
            warmer.await.expect("concurrent warmers must not panic");
        }

        let holds = pubsub.membership_hold_count().await;
        assert_eq!(
            holds, 1,
            "two concurrent warmers for one topic must create exactly one hold, got {holds}"
        );
        assert!(
            pubsub.is_topic_subscribed(&peer_inbox_name).await,
            "the winning warmer's subscription must be live"
        );
    }

    /// C4: Direct-connect pre-warm must pre-subscribe the peer inbox so the
    /// first durable POST is not the cold `publish_topic_id` that joins it.
    #[tokio::test]
    async fn reverse_ack_prewarm_presubscribes_peer_inbox_before_first_publish() {
        let node = Arc::new(
            NetworkNode::new(NetworkConfig::default(), None, None)
                .await
                .expect("network node"),
        );
        let pubsub = PubSubManager::new(node, None).expect("pubsub");
        let self_id = AgentId([0xC3; 32]);
        let peer = AgentId([0xD4; 32]);
        let peer_name = DmInboxService::inbox_topic_name(&peer);
        let peer_inbox = dm_inbox_topic(&peer);

        assert!(
            !pubsub.is_topic_subscribed(&peer_name).await,
            "peer inbox must be unsubscribed before Direct-connect pre-warm"
        );

        warm_reverse_ack_topics(&pubsub, &self_id, &peer).await;

        assert!(
            pubsub.is_topic_subscribed(&peer_name).await,
            "C4: peer inbox must be subscribed before the first durable POST"
        );
        assert!(
            pubsub.plumtree_topic_ids().await.contains(&peer_inbox),
            "C4 pre-subscribe must join the real inbox TopicId, not wait for publish"
        );

        let subscribed_before_publish = pubsub.subscription_count().await;
        pubsub
            .publish_topic_id(
                peer_name.clone(),
                peer_inbox,
                Bytes::from_static(b"first-durable-must-not-join"),
            )
            .await
            .expect("publish after C4 pre-subscribe");
        assert_eq!(
            pubsub.subscription_count().await,
            subscribed_before_publish,
            "first publish_topic_id must not be the subscribe/join event"
        );
        assert!(
            pubsub.is_topic_subscribed(&peer_name).await,
            "peer inbox membership hold must survive the first durable publish"
        );
    }

    /// The v1 publish path must be untouched by the hedging work: a v1 ACK
    /// still goes to the targeted topic only, and reaches the compatibility
    /// bus only when the payload itself arrived there. Hedging every v1 ACK
    /// onto the shared bus would add gossip traffic for every 0.37 peer in the
    /// mesh, which is not what this change is for.
    #[tokio::test]
    async fn a_v1_ack_is_not_hedged_onto_the_compatibility_bus() {
        let sender = test_keypair();
        let machine = MachineId([0xD8; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let mut bus = harness
            .pipeline
            .pubsub
            .subscribe(DM_BUS_TOPIC.to_string())
            .await;

        harness
            .pipeline
            .publish_ack_for_protocol(
                sender.agent_id(),
                [0x59; 16],
                DmAckOutcome::Accepted,
                DM_PROTOCOL_V1,
                false,
            )
            .await
            .expect("v1 ACK publishes");

        assert!(
            tokio::time::timeout(Duration::from_millis(300), bus.recv())
                .await
                .is_err(),
            "a v1 ACK with ack_legacy_bus=false must not reach the shared bus"
        );
    }

    /// The other half of the hedge contract: a durable v2 ACK reaches the
    /// compatibility bus even when the payload itself never arrived there
    /// (`ack_legacy_bus = false`). The bus route is what rescues a sender
    /// whose targeted-topic delivery is wedged — the "committed but never
    /// acked" 504 — so if v2 ever stops hedging onto the bus, the failure
    /// this worker exists to remove comes back silently.
    #[tokio::test]
    async fn a_v2_ack_is_always_hedged_onto_the_compatibility_bus() {
        let sender = test_keypair();
        let machine = MachineId([0xD9; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let mut bus = harness
            .pipeline
            .pubsub
            .subscribe(DM_BUS_TOPIC.to_string())
            .await;

        harness
            .pipeline
            .publish_ack_for_protocol(
                sender.agent_id(),
                [0x60; 16],
                DmAckOutcome::Accepted,
                DM_PROTOCOL_DURABLE_ACK,
                false,
            )
            .await
            .expect("v2 ACK schedules in the background publisher");

        let message = tokio::time::timeout(Duration::from_secs(5), bus.recv())
            .await
            .expect("a v2 ACK must reach the shared bus even with ack_legacy_bus=false")
            .expect("bus subscription stays open");
        let envelope = DmEnvelope::from_wire_bytes(&message.payload)
            .expect("bus payload decodes as a DM envelope");
        assert_eq!(envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
        assert_eq!(envelope.recipient_agent_id, *sender.agent_id().as_bytes());
    }

    struct RecordingDirectHedge {
        tx: mpsc::UnboundedSender<(AgentId, Bytes)>,
        outcome: DirectAckHedgeOutcome,
    }

    #[async_trait]
    impl DirectAckHedge for RecordingDirectHedge {
        async fn hedge(&self, recipient: AgentId, encoded: Bytes) -> DirectAckHedgeOutcome {
            let _ = self.tx.send((recipient, encoded));
            self.outcome
        }
    }

    /// C5: after history commit the same v2 ACK envelope is handed to a live
    /// Direct/typed hedge. This is not prefer_raw_quic on the durable SEND
    /// path — the payload remains the gossip_inbox ACK envelope.
    #[tokio::test]
    async fn durable_ack_is_hedged_on_direct_typed_after_history_commit() {
        let sender = test_keypair();
        let machine = MachineId([0xC5; 32]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let hedge = Arc::new(RecordingDirectHedge {
            tx,
            outcome: DirectAckHedgeOutcome::Sent,
        });
        let mut harness =
            make_inbox_harness_with_hedge(&sender, Some(machine), None, Some(hedge)).await;
        let _service = attach_history(&mut harness);
        let history = harness.pipeline.history.clone().expect("history handle");

        let message = durable_payload_message(&harness, &sender, machine, 0xC5, b"c5 hedge");
        harness.pipeline.handle_incoming(message, false).await;

        let rows = committed_rows(&history, &sender, 0xC5);
        assert_eq!(
            rows.len(),
            1,
            "Direct hedge must run only after the durable row exists"
        );

        let (recipient, encoded) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("C5 Direct hedge must fire after commit")
            .expect("hedge channel stays open");
        assert_eq!(recipient, sender.agent_id());
        let envelope =
            DmEnvelope::from_wire_bytes(&encoded).expect("Direct hedge carries the ACK envelope");
        assert_eq!(envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
        match envelope.body {
            DmBody::Ack(ack) => assert_eq!(ack.acks_request_id, [0xC5; 16]),
            other => panic!("Direct hedge must carry the ACK envelope, got {other:?}"),
        }
    }

    /// C5 fail-open: missing Direct must not fail the ACK. Gossip hedges
    /// still publish the same envelope.
    #[tokio::test]
    async fn durable_ack_fail_opens_when_direct_is_missing() {
        let sender = test_keypair();
        let machine = MachineId([0xC6; 32]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let hedge = Arc::new(RecordingDirectHedge {
            tx,
            outcome: DirectAckHedgeOutcome::SkippedNoDirect,
        });
        let mut harness =
            make_inbox_harness_with_hedge(&sender, Some(machine), None, Some(hedge)).await;
        let _service = attach_history(&mut harness);
        let mut bus = harness
            .pipeline
            .pubsub
            .subscribe(DM_BUS_TOPIC.to_string())
            .await;

        harness
            .pipeline
            .publish_ack_for_protocol(
                sender.agent_id(),
                [0xC6; 16],
                DmAckOutcome::Accepted,
                DM_PROTOCOL_DURABLE_ACK,
                false,
            )
            .await
            .expect("missing Direct must not fail the ACK schedule");

        let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("fail-open hedge is still invoked")
            .expect("hedge channel stays open");
        let message = tokio::time::timeout(Duration::from_secs(5), bus.recv())
            .await
            .expect("gossip compatibility-bus hedge must still deliver")
            .expect("bus subscription stays open");
        let envelope = DmEnvelope::from_wire_bytes(&message.payload).expect("bus ACK decodes");
        assert_eq!(envelope.protocol_version, DM_PROTOCOL_DURABLE_ACK);
    }

    /// C5: the sender waiter completes on the envelope request_id only.
    /// Direct send-ok is not a receipt.
    #[tokio::test]
    async fn waiter_completes_on_envelope_request_id_not_direct_send_ok() {
        let inflight = InFlightAcks::new();
        let request_id = [0xC7; 16];
        let ack_sender = AgentId([0x11; 32]);
        let ack_machine = MachineId([0x22; 32]);
        let mut rx = inflight.register_for_protocol(
            request_id,
            DM_PROTOCOL_DURABLE_ACK,
            ack_sender,
            Some(ack_machine),
        );

        assert_eq!(
            direct_ack_hedge_outcome(true, Some(true)),
            DirectAckHedgeOutcome::Sent,
            "a live Direct send-ok is only a hedge, not a receipt"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut rx)
                .await
                .is_err(),
            "Direct send-ok must not complete the waiter"
        );

        assert!(
            inflight.resolve_for_protocol(
                &request_id,
                DM_PROTOCOL_DURABLE_ACK,
                ack_sender,
                ack_machine,
                DmAckOutcome::Accepted,
            ),
            "the waiter is keyed on the ACK envelope request_id"
        );
        assert_eq!(
            rx.await.expect("oneshot"),
            DmAckOutcome::Accepted,
            "only the matching request_id envelope completes the waiter"
        );
    }

    /// #380 leaf-reverse-ACK: the failing fleet case, end-to-end at the
    /// PubSubManager level. A Leaf receiver with ZERO prior subscription
    /// state (no C2/C4 connect-event warm) receives a durable DM. The fix
    /// pre-subscribes the sender's inbox topic ON RECEIPT (the authoritative
    /// moment), so the ACK publish that follows has a gossip route. Also
    /// verifies the agent→machine registration for the C5 Direct hedge.
    #[tokio::test]
    async fn leaf_receiver_of_durable_dm_pre_subscribes_sender_inbox_on_receipt() {
        let sender = test_keypair();
        let machine_kp = MachineKeypair::generate().expect("machine");
        let machine = machine_kp.machine_id();
        let harness = make_inbox_harness(&sender, Some(machine), None).await;

        // Zero prior subscription state: prove the sender's inbox topic is
        // NOT in PlumTree before the DM arrives (the leaf fleet condition).
        let sender_inbox_topic_id = dm_inbox_topic(&sender.agent_id());
        let sender_inbox_name = DmInboxService::inbox_topic_name(&sender.agent_id());
        let before = harness.pipeline.pubsub.plumtree_topic_ids().await;
        assert!(
            !before.contains(&sender_inbox_topic_id),
            "precondition: sender inbox topic NOT subscribed (the leaf zero-state case)"
        );

        // Build a real durable v2 envelope using the production builder.
        let request_id = [0xE1; 16];
        let created = now_unix_ms();
        let envelope = EnvelopeBuilder::build_payload_envelope_with_version(
            DM_PROTOCOL_DURABLE_ACK,
            request_id,
            &sender.agent_id(),
            &machine,
            &machine_kp,
            &harness.recipient_agent_id,
            &harness.recipient_kem.public_bytes,
            created,
            created + ACK_ENVELOPE_LIFETIME_MS,
            b"leaf-reverse-ack-proof".to_vec(),
            |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(sender.secret_key(), bytes)
                    .map(|sig| sig.as_bytes().to_vec())
                    .map_err(|e| e.to_string())
            },
        )
        .expect("build durable envelope");
        let encoded = Bytes::from(envelope.to_wire_bytes().expect("encode"));

        let msg = PubSubMessage {
            topic: sender_inbox_name.clone(),
            payload: encoded,
            sender: Some(sender.agent_id()),
            sender_public_key: Some(sender.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        harness.pipeline.handle_incoming(msg, false).await;

        // The fix: the sender's inbox topic is now subscribed (the receipt
        // is the trigger), so the ACK publish has peers.
        let after = harness.pipeline.pubsub.plumtree_topic_ids().await;
        assert!(
            after.contains(&sender_inbox_topic_id),
            "receipt of a durable DM must pre-subscribe the sender's inbox for the reverse ACK: {after:?}"
        );
        assert!(
            harness
                .pipeline
                .pubsub
                .is_topic_subscribed(&sender_inbox_name)
                .await,
            "the subscription must be live (membership hold), not a one-shot refresh"
        );

        // The agent→machine mapping is registered from the envelope (fix b),
        // so the C5 Direct hedge can look up the sender.
        assert_eq!(
            harness.pipeline.dm.get_machine_id(&sender.agent_id()).await,
            Some(machine),
            "the verified envelope must register the sender's agent→machine binding for the C5 Direct hedge"
        );
    }

    /// C5 receive path: ingesting the same ACK envelope via Direct/typed
    /// completes the waiter. Fan-out as a user DM must not happen.
    #[tokio::test]
    async fn direct_typed_ack_envelope_completes_waiter_on_request_id() {
        let sender = test_keypair();
        let machine_kp = MachineKeypair::generate().expect("machine");
        let machine = machine_kp.machine_id();
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let request_id = [0xC8; 16];
        let waiter = harness.pipeline.inflight.register_for_protocol(
            request_id,
            DM_PROTOCOL_DURABLE_ACK,
            sender.agent_id(),
            Some(machine),
        );

        let created = now_unix_ms();
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            request_id: [0xC8; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: created + ACK_ENVELOPE_LIFETIME_MS,
            body: EnvelopeBuilder::build_ack_body(request_id, DmAckOutcome::Accepted),
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope(&mut envelope, &sender);
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            machine_kp.public_key().as_bytes().to_vec(),
        );
        attestation.sign(&machine_kp).expect("attest ACK");
        envelope.origin_attestation = Some(attestation);
        let encoded = Bytes::from(envelope.to_wire_bytes().expect("encode ACK"));

        assert!(
            harness
                .pipeline
                .ingest_direct_ack_envelope(
                    sender.agent_id(),
                    sender.public_key().as_bytes().to_vec(),
                    encoded,
                )
                .await,
            "the Direct/typed payload is the ACK envelope"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("waiter must complete from the Direct-ingested envelope")
                .expect("oneshot"),
            DmAckOutcome::Accepted
        );
        assert_no_delivery(&mut harness.receiver).await;
    }

    #[test]
    fn ack_publish_eager_topics_are_inbox_and_bus_only() {
        let recipient = AgentId([0xC5; 32]);
        let topics = ack_publish_eager_topics(&recipient);
        assert_eq!(topics[0], dm_inbox_topic(&recipient));
        assert_eq!(topics[1], TopicId::from_entity(DM_BUS_TOPIC.as_bytes()));
        assert_eq!(
            topics.len(),
            2,
            "C5b must not prefer eager on any topic except inbox+bus"
        );
    }

    #[test]
    fn missing_direct_is_skipped_not_failed() {
        assert_eq!(
            direct_ack_hedge_outcome(false, None),
            DirectAckHedgeOutcome::SkippedNoDirect
        );
        assert_eq!(
            direct_ack_hedge_outcome(false, Some(true)),
            DirectAckHedgeOutcome::SkippedNoDirect
        );
    }

    /// The two pre-existing variants must keep their postcard discriminants,
    /// or every 0.37 peer stops decoding our ACKs.
    #[test]
    fn appending_the_new_ack_variant_preserves_legacy_discriminants() {
        let accepted = postcard::to_stdvec(&DmAckOutcome::Accepted).expect("encode accepted");
        assert_eq!(accepted.first(), Some(&0u8), "Accepted must stay variant 0");
        let rejected = postcard::to_stdvec(&DmAckOutcome::RejectedByPolicy {
            reason: String::new(),
        })
        .expect("encode rejected");
        assert_eq!(
            rejected.first(),
            Some(&1u8),
            "RejectedByPolicy must stay variant 1"
        );
        let unavailable = postcard::to_stdvec(&DmAckOutcome::AckSemanticsUnavailable {
            reason: String::new(),
        })
        .expect("encode unavailable");
        assert_eq!(
            unavailable.first(),
            Some(&2u8),
            "AckSemanticsUnavailable must keep the index slice 1 assigned it"
        );
        let conflict = postcard::to_stdvec(&DmAckOutcome::IdempotencyConflict {
            reason: String::new(),
        })
        .expect("encode conflict");
        assert_eq!(
            conflict.first(),
            Some(&3u8),
            "IdempotencyConflict must be appended last"
        );
    }

    async fn assert_no_delivery(receiver: &mut crate::direct::DirectMessageReceiver) {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), receiver.recv())
                .await
                .is_err(),
            "inbox unexpectedly delivered a rejected message"
        );
    }

    // ── Signature verification ────────────────────────────────────────

    #[test]
    fn verify_envelope_signature_accepts_valid_signature() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        assert!(verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_empty_signature() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let envelope = make_unsigned_envelope(&sender_kp, &recipient_id);

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_wrong_key() {
        let sender_kp = test_keypair();
        let wrong_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Verify with a different public key — must fail because the
        // derived AgentId won't match sender_agent_id in the envelope.
        assert!(!verify_envelope_signature(
            &envelope,
            wrong_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_tampered_body() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Tamper with the body after signing
        envelope.body = DmBody::Ack(crate::dm::DmAckBody {
            acks_request_id: [99u8; 16],
            outcome: crate::dm::DmAckOutcome::Accepted,
        });

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_tampered_timestamp() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Tamper with timestamp after signing
        envelope.created_at_unix_ms = 0;

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    #[test]
    fn verify_envelope_signature_rejects_garbage_public_key() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        let garbage_key = [0xFFu8; 3200]; // ML-DSA-65 public keys are 807 bytes
        assert!(!verify_envelope_signature(&envelope, &garbage_key));
    }

    #[test]
    fn verify_envelope_signature_rejects_empty_public_key() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        assert!(!verify_envelope_signature(&envelope, &[]));
    }

    #[test]
    fn verify_envelope_signature_rejects_tampered_sender_id() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        // Tamper with sender_agent_id after signing
        envelope.sender_agent_id = [0xFFu8; 32];

        assert!(!verify_envelope_signature(
            &envelope,
            sender_kp.public_key().as_bytes()
        ));
    }

    // ── Enforcement point 3: revocation gate ──────────────────────────

    /// A DM from a revoked sender MUST be dropped and counted in
    /// `incoming_dropped_revoked` (issue #130, EP3). The revocation is applied
    /// via the real `verify_and_insert` receive path with a valid
    /// self-revocation, and the assertion reads the real production counter —
    /// so this fails if the drop or the counter side-effect regresses.
    #[test]
    fn revoked_sender_dm_is_dropped_and_counted() {
        let dm = DirectMessaging::new();
        // A machine that is NOT revoked — isolates the drop to the agent revocation.
        let clean_machine = MachineId([0xAB; 32]);

        // A foreign sender self-revokes its own agent-id (valid authority).
        let sender_kp = test_keypair();
        let sender = sender_kp.agent_id();
        let now = now_unix_ms() / 1000;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(sender),
            sender_kp.public_key(),
            sender_kp.secret_key(),
            now,
            Some("compromised".to_string()),
        )
        .expect("sign self-revocation");
        let mut set = RevocationSet::new();
        set.verify_and_insert(record, None)
            .expect("self-revocation verifies and inserts");

        // A revoked sender's DM is dropped and increments the counter.
        let before = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert!(
            drop_if_sender_revoked(&dm, &set, &sender, &clean_machine),
            "a DM from a revoked sender must be dropped"
        );
        let after = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert_eq!(
            after,
            before + 1,
            "dropping a revoked DM must increment incoming_dropped_revoked"
        );

        // A non-revoked sender is NOT dropped and does NOT move the counter —
        // proving the gate is precise, not a blanket drop.
        let other = test_keypair().agent_id();
        assert!(
            !drop_if_sender_revoked(&dm, &set, &other, &clean_machine),
            "a DM from a non-revoked sender must pass the gate"
        );
        assert_eq!(
            dm.diagnostics_snapshot().stats.incoming_dropped_revoked,
            after,
            "a passing DM must not touch incoming_dropped_revoked"
        );
    }

    #[tokio::test]
    async fn trusted_sender_cannot_bypass_revoked_authenticated_machine_with_clean_claim() {
        let sender = test_keypair();
        let revoked_machine = MachineKeypair::generate().expect("revoked machine keygen");
        let clean_claim = MachineId([0xB2; 32]);
        let mut harness = make_inbox_harness(
            &sender,
            Some(revoked_machine.machine_id()),
            Some(&revoked_machine),
        )
        .await;

        let message = payload_message(&harness, &sender, clean_claim, 0x11);
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1,
            "authenticated-machine mismatch must be an observable policy rejection"
        );
    }

    #[tokio::test]
    async fn trusted_sender_matching_clean_authenticated_machine_is_delivered() {
        let sender = test_keypair();
        let clean_machine = MachineId([0xC3; 32]);
        let mut harness = make_inbox_harness(&sender, Some(clean_machine), None).await;

        let message = payload_message(&harness, &sender, clean_machine, 0x22);
        harness.pipeline.handle_incoming(message, false).await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());
        assert_eq!(delivered.machine_id, clean_machine);
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
    }

    #[tokio::test]
    async fn unknown_binding_fallback_checks_claimed_machine_revocation() {
        let sender = test_keypair();
        let revoked_machine = MachineKeypair::generate().expect("revoked machine keygen");
        let mut harness = make_inbox_harness(&sender, None, Some(&revoked_machine)).await;

        let message = payload_message(&harness, &sender, revoked_machine.machine_id(), 0x33);
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1
        );
    }

    #[tokio::test]
    async fn unknown_binding_fallback_allows_clean_claimed_machine() {
        let sender = test_keypair();
        let clean_claim = MachineId([0xD4; 32]);
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let message = payload_message(&harness, &sender, clean_claim, 0x44);
        harness.pipeline.handle_incoming(message, false).await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(delivered.machine_id, clean_claim);
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
    }

    // ── Issue #213: origin-machine attestation acceptance tests ─────────────

    /// #213 SPOOF: an attacker holding the agent key (but NOT machine B's
    /// key) claims unrevoked machine B in the envelope. The attestation they
    /// can produce (signed by their own machine A's key) fails the
    /// key↔machine-id hash binding — hard drop, even with NO retained
    /// binding and B unrevoked. This is the core #213 acceptance criterion:
    /// a revoked origin cannot hide behind an unrevoked claim.
    #[tokio::test]
    async fn spoof_agent_key_holder_claiming_unrevoked_machine_is_rejected() {
        let sender = test_keypair();
        let attacker_machine = MachineKeypair::generate().expect("attacker machine keygen");
        let unrevoked_b = MachineId([0xB9; 32]);
        // No retained binding, no revocations: ONLY the attestation gate can
        // catch this (the #184 fallback alone would accept the claim).
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let mut envelope = craft_unsigned_payload_envelope(&harness, &sender, unrevoked_b, 0x51);
        sign_envelope_with_agent(&mut envelope, &sender);
        // Attacker attaches the best attestation they can mint: their OWN
        // machine key over fields claiming machine B.
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            attacker_machine.public_key().as_bytes().to_vec(),
        );
        attestation
            .sign(&attacker_machine)
            .expect("attacker attest");
        envelope.origin_attestation = Some(attestation);
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(crate::dm::OriginAttestationError::KeyBindingMismatch)
        );

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1,
            "an invalid attestation must be an observable hard rejection"
        );
    }

    /// #213 SPOOF (variant): a forged/garbage attestation signature is a
    /// hard drop, never a fallback to the claimed machine.
    #[tokio::test]
    async fn spoof_forged_attestation_signature_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let mut envelope =
            craft_unsigned_payload_envelope(&harness, &sender, machine.machine_id(), 0x52);
        sign_envelope_with_agent(&mut envelope, &sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        // Garbage signature of the right length class: parses or not, it
        // must never verify.
        attestation.signature = vec![0xAB; 3309];
        envelope.origin_attestation = Some(attestation);

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1
        );
    }

    /// #213 TRANSITION-WINDOW RESIDUAL — pinned, documented behavior (ADR
    /// 0021 "Downgrade / mixed-version"). An attacker holding the agent key
    /// STRIPS the attestation entirely: the envelope degrades to the legacy
    /// claim path, and on a cold receiver with no retained binding the
    /// claim of unrevoked machine B is accepted even though the true origin
    /// A is revoked. Under the transition policy (accept-with-binding-
    /// fallback for unattested DMs) this DM IS delivered — the exact
    /// residual #213 narrows to unattested senders only.
    ///
    /// This test intentionally asserts the residual EXISTS: when the
    /// `DmCapabilities` attestation hard-require follow-up lands, delivery
    /// stops and this test must be flipped to `assert_no_delivery` — it
    /// fails-positive the day the residual actually closes.
    #[tokio::test]
    async fn strip_downgrade_residual_delivered_under_transition_policy() {
        let sender = test_keypair();
        let true_origin_a = MachineKeypair::generate().expect("origin machine keygen");
        let unrevoked_b = MachineId([0xB8; 32]);
        // Cold receiver: NO retained binding. True origin A IS revoked.
        let mut harness = make_inbox_harness(&sender, None, Some(&true_origin_a)).await;

        // Stripped envelope: agent-signed, no attestation, claims B.
        let stripped = payload_message(&harness, &sender, unrevoked_b, 0x53);
        harness.pipeline.handle_incoming(stripped, false).await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect(
                "transition policy accepts unattested DMs on the claim path — \
                 flip this to assert_no_delivery when the hard-require lands",
            )
            .expect("delivery stream closed");
        assert_eq!(
            delivered.machine_id, unrevoked_b,
            "strip residual: the unattested claim of B is accepted (ADR 0021 residual)"
        );
    }

    /// #213 REPLAY: an attestation captured from DM-1 (request R1) is
    /// re-presented inside DM-2 (request R2) — the attacker re-signs the
    /// envelope with the (stolen) agent key but cannot mint a fresh machine
    /// attestation. The request-id field match fails → hard drop.
    #[tokio::test]
    async fn replay_captured_attestation_with_new_request_id_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        // Capture: a valid attested DM (request 0x61).
        let first = attested_payload_message(&harness, &sender, &machine, 0x61);
        let first_envelope =
            DmEnvelope::from_wire_bytes(&first.payload).expect("decode first envelope");
        let captured = first_envelope
            .origin_attestation
            .clone()
            .expect("first envelope attested");

        // Replay: same agent, NEW request id, envelope re-signed by the
        // agent key — but the captured attestation still names request 0x61.
        let mut envelope =
            craft_unsigned_payload_envelope(&harness, &sender, machine.machine_id(), 0x62);
        sign_envelope_with_agent(&mut envelope, &sender);
        envelope.origin_attestation = Some(captured);
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(crate::dm::OriginAttestationError::EnvelopeMismatch)
        );

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_trust_rejected,
            1
        );
    }

    /// #213 REPLAY (variant): an attestation re-presented past its expiry
    /// window is dropped — the envelope timestamp window covers the
    /// attestation because the fields must match exactly.
    #[tokio::test]
    async fn replay_expired_attestation_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        // Build an honestly-signed envelope + attestation whose window
        // already closed (created 10 min ago, 60 s lifetime).
        let created = now_unix_ms().saturating_sub(600_000);
        let body = EnvelopeBuilder::build_payload_body(
            &[0x63; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created,
            b"stale replay".to_vec(),
            None,
            &harness.recipient_kem.public_bytes,
        )
        .expect("build payload body");
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: [0x63; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: created + 60_000,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, &sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(&machine).expect("machine attest");
        envelope.origin_attestation = Some(attestation);
        // The attestation itself verifies — only the expiry window rejects.
        assert!(envelope.verify_origin_attestation().is_ok());

        let message = wrap_in_pubsub(&harness, &sender, &envelope);
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
    }

    /// #213 REVOCATION: the origin machine is revoked mid-flight — the
    /// envelope + attestation are both honestly signed by machine A, but A
    /// enters the receiver's revocation set before the DM arrives. EP3 drops
    /// on the ATTESTED machine id (not the claim).
    #[tokio::test]
    async fn revocation_of_origin_machine_mid_flight_is_rejected() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        // Harness revocation set already holds machine A's self-revocation.
        let mut harness = make_inbox_harness(&sender, None, Some(&machine)).await;

        let message = attested_payload_message(&harness, &sender, &machine, 0x64);
        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "a validly-attested DM from a revoked origin machine must hit EP3"
        );
    }

    /// #213 OFFLINE RECEIVER: a completely cold receiver — no retained
    /// binding, no discovery cache, nothing — authenticates the DM's origin
    /// machine purely from envelope-carried material and delivers.
    #[tokio::test]
    async fn offline_cold_receiver_authenticates_origin_with_zero_cache_state() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("machine keygen");
        let mut harness = make_inbox_harness(&sender, None, None).await;

        let message = attested_payload_message(&harness, &sender, &machine, 0x65);
        harness.pipeline.handle_incoming(message, false).await;

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(delivered.sender, sender.agent_id());
        assert_eq!(
            delivered.machine_id,
            machine.machine_id(),
            "delivery must carry the ATTESTED machine, not just the claim"
        );
        assert_eq!(delivered.trust_decision, Some(TrustDecision::Accept));
    }

    /// #213 A→B MOVE: the agent legitimately moves from machine A to
    /// machine B. The retained binding still says A, but B's fresh
    /// attestation supersedes it — the DM is delivered with machine B and
    /// the binding refreshes. A later A-attested DM (stale origin, A now
    /// revoked) is rejected. Revoking A does NOT block the valid move.
    #[tokio::test]
    async fn portable_move_fresh_b_attestation_accepted_stale_revoked_a_rejected() {
        let sender = test_keypair();
        let machine_a = MachineKeypair::generate().expect("machine A keygen");
        let machine_b = MachineKeypair::generate().expect("machine B keygen");
        // Retained binding says A (stale announcement); A is then revoked
        // (compromised) — the move to B must still authenticate.
        let mut harness =
            make_inbox_harness(&sender, Some(machine_a.machine_id()), Some(&machine_a)).await;

        // 1. Fresh B attestation: accepted even though the binding says A.
        let message = attested_payload_message(&harness, &sender, &machine_b, 0x66);
        harness.pipeline.handle_incoming(message, false).await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("delivery timeout")
            .expect("delivery stream closed");
        assert_eq!(
            delivered.machine_id,
            machine_b.machine_id(),
            "a valid fresh attestation from B supersedes the stale A binding"
        );

        // 2. The retained binding refreshes to B (seconds-granularity
        //    ordering: the fresh attestation outranks the old announcement).
        assert_eq!(
            authenticated_machine_binding_for_testing(
                &harness.pipeline.authenticated_machine_bindings,
                &sender.agent_id(),
            )
            .await,
            Some(machine_b.machine_id()),
            "the attested move must refresh the retained binding to B"
        );

        // 3. Stale A attestation: A is revoked → EP3 rejects.
        let stale = attested_payload_message(&harness, &sender, &machine_a, 0x67);
        harness.pipeline.handle_incoming(stale, false).await;
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .incoming_dropped_revoked,
            1,
            "a stale attestation from revoked machine A must hit EP3"
        );
        assert_no_delivery(&mut harness.receiver).await;
    }

    #[tokio::test]
    async fn authenticated_binding_allows_portable_move_and_rejects_stale_replay() {
        let sender = test_keypair().agent_id();
        let machine_a = MachineId([0xA5; 32]);
        let machine_b = MachineId([0xB6; 32]);
        let bindings = Arc::new(RwLock::new(AuthenticatedMachineBindingCache::default()));

        record_authenticated_machine_binding(&bindings, sender, machine_a, 100).await;
        record_authenticated_machine_binding(&bindings, sender, machine_b, 200).await;
        record_authenticated_machine_binding(&bindings, sender, machine_a, 150).await;

        let binding = bindings.write().await.resolve(&sender).expect("binding");
        assert_eq!(binding, machine_b);
    }

    #[test]
    fn authenticated_binding_cache_evicts_least_recently_used_at_capacity() {
        let mut bindings = AuthenticatedMachineBindingCache::with_capacity(2);
        let agent_a = AgentId([0xA1; 32]);
        let agent_b = AgentId([0xB2; 32]);
        let agent_c = AgentId([0xC3; 32]);

        bindings.record(agent_a, MachineId([0x01; 32]), 1);
        bindings.record(agent_b, MachineId([0x02; 32]), 2);
        assert!(bindings.resolve(&agent_a).is_some());
        bindings.record(agent_c, MachineId([0x03; 32]), 3);

        assert!(bindings.resolve(&agent_a).is_some());
        assert!(bindings.resolve(&agent_b).is_none());
        assert!(bindings.resolve(&agent_c).is_some());
    }

    /// A DM whose originating MACHINE is revoked (but whose agent-id is clean)
    /// MUST be dropped and counted — issue #184, bringing EP3 to machine-id
    /// parity with the raw-QUIC direct path (`direct::inbound_peer_revoked`)
    /// and EP1/EP2. The revocation is applied via the real `verify_and_insert`
    /// receive path with a valid machine self-revocation, so this fails if the
    /// machine-revocation half of the EP3 gate regresses.
    #[test]
    fn machine_revoked_sender_dm_is_dropped_and_counted() {
        let dm = DirectMessaging::new();

        // A foreign machine self-revokes its own machine-id (valid authority).
        let machine_kp = MachineKeypair::generate().expect("machine keygen");
        let revoked_machine = machine_kp.machine_id();
        let now = now_unix_ms() / 1000;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(revoked_machine),
            machine_kp.public_key(),
            machine_kp.secret_key(),
            now,
            Some("compromised hardware".to_string()),
        )
        .expect("sign machine self-revocation");
        let mut set = RevocationSet::new();
        set.verify_and_insert(record, None)
            .expect("machine self-revocation verifies and inserts");

        // A clean (non-revoked) agent on the revoked machine is still dropped —
        // the machine revocation is decisive, not the agent revocation.
        let clean_agent = test_keypair().agent_id();
        let before = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert!(
            drop_if_sender_revoked(&dm, &set, &clean_agent, &revoked_machine),
            "a DM from a machine-revoked (agent-clean) sender must be dropped (#184)"
        );
        let after = dm.diagnostics_snapshot().stats.incoming_dropped_revoked;
        assert_eq!(
            after,
            before + 1,
            "dropping a machine-revoked DM must increment incoming_dropped_revoked"
        );
    }

    // ── Envelope size limits ──────────────────────────────────────────

    #[test]
    fn envelope_from_wire_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        let result = DmEnvelope::from_wire_bytes(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn envelope_from_wire_bytes_rejects_garbage() {
        let garbage = vec![0xFF, 0xFE, 0xFD];
        let result = DmEnvelope::from_wire_bytes(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn envelope_from_wire_bytes_rejects_empty() {
        let result = DmEnvelope::from_wire_bytes(&[]);
        assert!(result.is_err());
    }

    // ── Wire round-trip ───────────────────────────────────────────────

    #[test]
    fn envelope_wire_roundtrip() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        sign_envelope(&mut envelope, &sender_kp);

        let wire = envelope.to_wire_bytes().expect("to_wire_bytes");
        let decoded = DmEnvelope::from_wire_bytes(&wire).expect("from_wire_bytes");
        assert_eq!(decoded.sender_agent_id, envelope.sender_agent_id);
        assert_eq!(decoded.recipient_agent_id, envelope.recipient_agent_id);
        assert_eq!(decoded.request_id, envelope.request_id);
        assert_eq!(decoded.protocol_version, envelope.protocol_version);
    }

    // ── Dedupe key uniqueness ─────────────────────────────────────────

    #[test]
    fn dedupe_key_differs_for_different_request_ids() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let e1 = make_unsigned_envelope(&sender_kp, &recipient_id);
        let mut e2 = make_unsigned_envelope(&sender_kp, &recipient_id);
        e2.request_id = [99u8; 16];

        assert_ne!(e1.dedupe_key(), e2.dedupe_key());
    }

    #[test]
    fn dedupe_key_same_for_same_request_id() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let e1 = make_unsigned_envelope(&sender_kp, &recipient_id);
        let e2 = make_unsigned_envelope(&sender_kp, &recipient_id);

        assert_eq!(e1.dedupe_key(), e2.dedupe_key());
    }

    #[test]
    fn dedupe_key_differs_for_different_senders() {
        let sender1 = test_keypair();
        let sender2 = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let e1 = make_unsigned_envelope(&sender1, &recipient_id);
        let e2 = make_unsigned_envelope(&sender2, &recipient_id);

        assert_ne!(e1.dedupe_key(), e2.dedupe_key());
    }

    // ── Protocol version enforcement ──────────────────────────────────

    #[test]
    fn envelope_future_version_detected() {
        let sender_kp = test_keypair();
        let recipient_id: [u8; 32] = [4u8; 32];
        let mut envelope = make_unsigned_envelope(&sender_kp, &recipient_id);
        envelope.protocol_version = DM_PROTOCOL_VERSION + 10;

        assert!(envelope.protocol_version > DM_PROTOCOL_VERSION);
    }

    // ── Inbox topic name consistency ──────────────────────────────────

    #[test]
    fn inbox_topic_is_agent_specific_and_matches_raw_topic_id() {
        let id1: [u8; 32] = [1u8; 32];
        let id2: [u8; 32] = [2u8; 32];
        let agent1 = AgentId(id1);
        let agent2 = AgentId(id2);

        let topic1 = DmInboxService::inbox_topic_name(&agent1);
        let topic2 = DmInboxService::inbox_topic_name(&agent2);

        assert_ne!(topic1, topic2);
        assert!(topic1.starts_with(DM_INBOX_TOPIC_NAME_PREFIX));
        assert_eq!(
            topic1,
            format!(
                "{DM_INBOX_TOPIC_NAME_PREFIX}{}",
                hex::encode(dm_inbox_topic(&agent1).to_bytes())
            )
        );
    }

    // ── Typed payload route matching ──────────────────────────────────

    #[test]
    fn typed_payload_route_matches_prefix() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<DmTypedPayload>(1);
        let route = DmTypedPayloadRoute {
            durable_completion: false,
            prefix: b"x0x-exec-v1\0".to_vec(),
            sender: tx,
        };
        let payload = b"x0x-exec-v1\0some-command".to_vec();
        assert!(payload.starts_with(&route.prefix));
    }

    #[test]
    fn typed_payload_route_no_match_for_different_prefix() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<DmTypedPayload>(1);
        let route = DmTypedPayloadRoute {
            durable_completion: false,
            prefix: b"x0x-exec-v1\0".to_vec(),
            sender: tx,
        };
        let payload = b"x0x-other-stuff".to_vec();
        assert!(!payload.starts_with(&route.prefix));
    }

    // ── DmInboxConfig ─────────────────────────────────────────────────

    #[test]
    fn dm_inbox_config_default_has_empty_routes() {
        let config = DmInboxConfig::default();
        assert!(!config.silent_reject, "silent_reject defaults to false");
        assert!(config.typed_payload_routes.is_empty());
    }

    #[test]
    fn dm_inbox_config_with_route_adds_entry() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let config = DmInboxConfig::default().with_typed_payload_route(b"x0x-exec-v1\x00", tx);
        assert_eq!(config.typed_payload_routes.len(), 1);
        assert_eq!(config.typed_payload_routes[0].prefix, b"x0x-exec-v1\x00");
    }

    #[test]
    fn dm_inbox_config_with_multiple_routes() {
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let config = DmInboxConfig::default()
            .with_typed_payload_route(b"prefix-a\x00", tx1)
            .with_typed_payload_route(b"prefix-b\x00", tx2);
        assert_eq!(config.typed_payload_routes.len(), 2);
    }

    #[test]
    fn dm_inbox_config_debug_does_not_panic() {
        let config = DmInboxConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("silent_reject"));
        assert!(debug.contains("typed_payload_routes"));
    }

    // ── Unverified drop path instrumentation (issue #296) ─────────────

    /// The REAL drop site for unverified pubsub messages is dm_inbox.rs, NOT
    /// server/mod.rs. The typed-payload handler in server/mod.rs only fires
    /// after the inbox pipeline has already verified and dispatched the message
    /// — typed.verified is hardcoded to true there, so any !typed.verified
    /// check in server/mod.rs is unreachable dead code. This test is the
    /// revert-guard: if the counter call is removed from handle_incoming the
    /// test fails even though the dead server-layer check is still in place.
    #[tokio::test]
    async fn unverified_pubsub_message_increments_signature_failed_counter() {
        let sender = test_keypair();
        let harness = make_inbox_harness(&sender, None, None).await;
        let dm = Arc::clone(&harness.pipeline.dm);

        let msg = PubSubMessage {
            topic: "test-inbox-topic".to_string(),
            payload: bytes::Bytes::new(),
            sender: None,
            sender_public_key: None,
            verified: false,
            trust_level: None,
            raw_envelope: None,
        };

        let before = dm.diagnostics_snapshot().stats.incoming_signature_failed;
        harness.pipeline.handle_incoming(msg, false).await;
        let after = dm.diagnostics_snapshot().stats.incoming_signature_failed;

        assert_eq!(
            after - before,
            1,
            "unverified PubSubMessage must increment incoming_signature_failed \
             at the real drop site in dm_inbox (issue #296)"
        );
    }
}
