//! Runtime service that consumes this agent's inbox topic, runs the
//! signature-first pipeline from `docs/design/dm-over-gossip.md`, and
//! bridges decrypted payloads into [`crate::direct::DirectMessaging`].

use crate::contacts::ContactStore;
use crate::direct::DirectMessaging;
use crate::dm::{
    decrypt_payload, dm_inbox_topic, now_unix_ms, validate_timestamp_window, DmAckOutcome, DmBody,
    DmEnvelope, DmOriginAttestation, DmPayload, EnvelopeBuilder, InFlightAcks, RecentDeliveryCache,
    DM_PROTOCOL_DURABLE_ACK, DM_PROTOCOL_VERSION, MAX_ENVELOPE_BYTES,
};
use crate::error::{NetworkError, NetworkResult};
use crate::gossip::{PubSubManager, PubSubMessage, SigningContext, Subscription};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::identity::{AgentId, MachineId, MachineKeypair};
use crate::revocation::RevocationSet;
use crate::trust::{TrustContext, TrustDecision, TrustEvaluator};
use bytes::Bytes;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

const ACK_ENVELOPE_LIFETIME_MS: u64 = 60_000;
/// Upper bound for one ACK publication route. PubSub's per-peer fan-out is
/// itself bounded at four seconds; the extra second lets normal completion
/// accounting settle without allowing one wedged route to pin the serial DM
/// inbox loop indefinitely.
const ACK_PUBLISH_ROUTE_TIMEOUT: Duration = Duration::from_secs(5);

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
    #[must_use]
    pub fn with_typed_payload_route(
        mut self,
        prefix: impl Into<Vec<u8>>,
        sender: mpsc::Sender<DmTypedPayload>,
    ) -> Self {
        self.typed_payload_routes.push(DmTypedPayloadRoute {
            prefix: prefix.into(),
            sender,
        });
        self
    }
}

/// Prefix route for decrypted DM payloads.
#[derive(Clone)]
pub struct DmTypedPayloadRoute {
    pub prefix: Vec<u8>,
    pub sender: mpsc::Sender<DmTypedPayload>,
}

/// A decrypted, verified DM payload routed before generic direct-message fan-out.
#[derive(Debug, Clone)]
pub struct DmTypedPayload {
    pub sender: AgentId,
    pub machine_id: MachineId,
    pub payload: Vec<u8>,
    pub verified: bool,
    pub trust_decision: Option<TrustDecision>,
    pub received_at_unix_ms: u64,
}

pub struct DmInboxService {
    handles: Vec<JoinHandle<()>>,
    topic: String,
}

/// Legacy shared DM transport topic. New sends use per-recipient inbox
/// topics; this listener remains so rolling upgrades can still receive
/// envelopes from older daemons.
pub const DM_BUS_TOPIC: &str = "x0x/dm/v1/bus";
const DM_INBOX_TOPIC_NAME_PREFIX: &str = "x0x/dm/v1/inbox/";

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
        let topic = Self::inbox_topic_name(&self_agent_id);
        let subscription = pubsub
            .subscribe_topic_id(topic.clone(), dm_inbox_topic(&self_agent_id))
            .await;
        let legacy_subscription = pubsub.subscribe(DM_BUS_TOPIC.to_string()).await;

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
        };

        let primary_handle =
            spawn_subscription_loop(topic.clone(), false, subscription, pipeline.clone());
        let legacy_handle = spawn_subscription_loop(
            DM_BUS_TOPIC.to_string(),
            true,
            legacy_subscription,
            pipeline,
        );

        Ok(Self {
            handles: vec![primary_handle, legacy_handle],
            topic,
        })
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
}

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

fn exact_durable_history_outcome(outcome: crate::history::InsertOutcome) -> bool {
    matches!(
        outcome,
        crate::history::InsertOutcome::Inserted | crate::history::InsertOutcome::Duplicate
    )
}

fn ack_requires_legacy_bus_hedge(protocol_version: u16, received_on_legacy_bus: bool) -> bool {
    received_on_legacy_bus || protocol_version >= DM_PROTOCOL_DURABLE_ACK
}

async fn publish_ack_routes<Primary, Legacy>(
    hedge_on_legacy_bus: bool,
    route_timeout: Duration,
    primary: Primary,
    legacy: Legacy,
) -> NetworkResult<()>
where
    Primary: std::future::Future<Output = NetworkResult<()>>,
    Legacy: std::future::Future<Output = NetworkResult<()>>,
{
    if !hedge_on_legacy_bus {
        return publish_ack_route_with_timeout("targeted", route_timeout, primary).await;
    }

    // A targeted inbox publish can deliver remotely yet remain pending under
    // per-topic fan-out backpressure. Poll the compatibility-bus hedge at the
    // same time so a durable recipient does not commit and dispatch the DM
    // while the sender exhausts its complete ACK budget waiting on the reverse
    // targeted topic. Each independently-polled route has an explicit
    // deadline: the successful hedge can reach the sender immediately, while
    // a wedged sibling is cancelled at the deadline instead of pinning this
    // serial inbox loop and blocking later DMs/ACKs forever.
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

        if envelope.protocol_version > DM_PROTOCOL_VERSION {
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
        if let Some(cached) = self.cache.lookup(&dedupe) {
            if matches!(envelope.body, DmBody::Payload(_)) {
                if cached.protocol_version >= envelope.protocol_version {
                    let _ = self
                        .publish_ack(
                            AgentId(envelope.sender_agent_id),
                            envelope.request_id,
                            cached_ack_for_protocol(&cached, envelope.protocol_version),
                            envelope.protocol_version,
                            ack_legacy_bus,
                        )
                        .await;
                    return;
                }
                // A v1 completion cannot satisfy a v2 receipt. Continue
                // through signature, attestation, and decrypt verification;
                // the serialized branch below returns an explicit semantics
                // error without dispatching the logical request again.
            } else {
                return;
            }
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
                if envelope.protocol_version >= DM_PROTOCOL_DURABLE_ACK {
                    self.dm.record_incoming_trust_rejected(sender_agent_id);
                    tracing::warn!(
                        target: "dm.trace",
                        stage = "inbound_origin_attestation_required",
                        sender = %hex::encode(envelope.sender_agent_id),
                        "v2 DM dropped: durable ACK semantics require a fresh origin attestation"
                    );
                    return;
                }
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
                let resolved = self.inflight.resolve_for_protocol(
                    &ack.acks_request_id,
                    envelope.protocol_version,
                    sender_agent_id,
                    sender_machine_id,
                    ack.outcome,
                );
                if !resolved {
                    self.dm.record_ack_unresolved();
                    tracing::warn!(
                        target: "dm.trace",
                        stage = "ack_unresolved",
                        acked_request_id = %hex::encode(ack.acks_request_id),
                        ack_sender = %hex::encode(sender_agent_id.as_bytes()),
                        ack_machine = %hex::encode(sender_machine_id.as_bytes()),
                        protocol_version = envelope.protocol_version,
                        "authenticated ACK did not match an active exact waiter; it may be late or binding-mismatched"
                    );
                }
                tracing::debug!(
                    acked = %hex::encode(ack.acks_request_id),
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
        let protocol_version = envelope.protocol_version;
        let durable_ack = protocol_version >= DM_PROTOCOL_DURABLE_ACK;
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
                    protocol_version,
                );
                if !self.silent_reject {
                    let _ = self
                        .publish_ack(
                            sender_agent_id,
                            envelope.request_id,
                            outcome,
                            protocol_version,
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

        // Serialize every protocol generation for one logical request. This
        // prevents simultaneous v1/v2 or primary/legacy copies from each
        // dispatching after observing a cache miss. V2 still avoids inserting
        // a provisional Accepted outcome: a failed owner releases the lock so
        // an exact retry can safely attempt the commit again.
        let Some(lock) = self.cache.delivery_lock(envelope.dedupe_key()) else {
            tracing::warn!(
                request_id = %hex::encode(envelope.request_id),
                "DM delivery claim cache is saturated or unavailable; withholding ACK"
            );
            return;
        };
        let _delivery_guard = lock.lock_owned().await;
        if let Some(cached) = self.cache.lookup(&envelope.dedupe_key()) {
            let _ = self
                .publish_ack(
                    sender_agent_id,
                    envelope.request_id,
                    cached_ack_for_protocol(&cached, protocol_version),
                    protocol_version,
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
        if !durable_ack
            && !self.cache.insert_for_protocol(
                envelope.dedupe_key(),
                DmAckOutcome::Accepted,
                protocol_version,
            )
        {
            let _ = self
                .publish_ack(
                    sender_agent_id,
                    envelope.request_id,
                    DmAckOutcome::Accepted,
                    protocol_version,
                    ack_legacy_bus,
                )
                .await;
            return;
        }

        let matches_typed_route = self
            .typed_payload_routes
            .iter()
            .any(|route| plaintext.payload.starts_with(&route.prefix));
        if durable_ack && matches_typed_route {
            tracing::warn!(
                request_id = %hex::encode(envelope.request_id),
                "v2 durable ACK requested for typed protocol payload; withholding ACK"
            );
            return;
        }

        let is_typed_payload = self
            .route_typed_payload(
                sender_agent_id,
                sender_machine_id,
                plaintext.payload.clone(),
                Some(decision),
            )
            .await;

        if !is_typed_payload {
            let history_record =
                match crate::history::classify::classify_dm_payload(&plaintext.payload) {
                    crate::history::classify::DmPayloadClass::Durable(content_type) => {
                        match envelope.to_wire_bytes() {
                            Ok(artifact) => Some(crate::history::HistoryRecord {
                                msg_id: crate::history::HistoryRecord::compute_msg_id(
                                    Some(&artifact),
                                    &plaintext.payload,
                                ),
                                scope: crate::history::Scope::Dm(hex::encode(
                                    envelope.sender_agent_id,
                                )),
                                author_agent: Some(hex::encode(envelope.sender_agent_id)),
                                author_machine: Some(hex::encode(sender_machine_id.as_bytes())),
                                author_pubkey: Some(sender_pubkey.clone()),
                                sent_at_ms: i64::try_from(envelope.created_at_unix_ms)
                                    .unwrap_or(i64::MAX),
                                seen_at_ms: i64::try_from(now_unix_ms()).unwrap_or(i64::MAX),
                                direction: crate::history::Direction::Inbound,
                                content_type: content_type.to_string(),
                                payload: plaintext.payload.clone(),
                                signed_artifact: Some(artifact),
                                signature: Some(envelope.signature.clone()),
                                // Mirrors `DM_SIGN_DOMAIN` in `dm.rs`.
                                sig_context: Some("x0x-dm-v1".to_string()),
                                provenance: crate::history::Provenance::VerifiedEnvelope,
                                replace_key: None,
                            }),
                            Err(e) => {
                                tracing::debug!(
                                    "history: DM envelope wire encode failed, row skipped: {e}"
                                );
                                None
                            }
                        }
                    }
                    crate::history::classify::DmPayloadClass::Ephemeral => None,
                };

            if durable_ack {
                let (Some(history), Some(record)) = (self.history.as_ref(), history_record) else {
                    tracing::warn!(
                        request_id = %hex::encode(envelope.request_id),
                        "v2 durable ACK unavailable: no durable history record can be committed"
                    );
                    return;
                };
                match history.record_committed(record).await {
                    Ok(outcome) if exact_durable_history_outcome(outcome) => {}
                    Ok(outcome) => {
                        tracing::warn!(
                            request_id = %hex::encode(envelope.request_id),
                            ?outcome,
                            "v2 durable history write did not establish this exact row; withholding ACK and app dispatch"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            request_id = %hex::encode(envelope.request_id),
                            %error,
                            "v2 durable history commit failed; withholding ACK and app dispatch"
                        );
                        return;
                    }
                }
            } else if let (Some(history), Some(record)) = (self.history.as_ref(), history_record) {
                // Legacy v1 keeps the ADR-0023 non-blocking, shed-on-full path.
                history.record(record);
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

        if durable_ack {
            if let Err(error) = self
                .cache
                .complete_durable(envelope.dedupe_key(), DmAckOutcome::Accepted)
            {
                tracing::error!(
                    request_id = %hex::encode(envelope.request_id),
                    ?error,
                    "v2 dispatch completed but replay-safe completion failed; withholding ACK"
                );
                return;
            }
        }

        let _ = self
            .publish_ack(
                sender_agent_id,
                envelope.request_id,
                DmAckOutcome::Accepted,
                protocol_version,
                ack_legacy_bus,
            )
            .await;
    }

    async fn route_typed_payload(
        &self,
        sender_agent_id: AgentId,
        sender_machine_id: MachineId,
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

    async fn publish_ack(
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
        let topic = DmInboxService::inbox_topic_name(&to);
        let primary =
            self.pubsub
                .publish_topic_id(topic, dm_inbox_topic(&to), Bytes::from(encoded.clone()));
        let legacy = self
            .pubsub
            .publish(DM_BUS_TOPIC.to_string(), Bytes::from(encoded));
        let hedged = ack_requires_legacy_bus_hedge(protocol_version, ack_legacy_bus);
        let result = publish_ack_routes(hedged, ACK_PUBLISH_ROUTE_TIMEOUT, primary, legacy).await;
        if let Err(error) = &result {
            self.dm.record_ack_publish_route_failed();
            tracing::warn!(
                target: "dm.trace",
                stage = "ack_publish_route_failed",
                acked_request_id = %hex::encode(acks_request_id),
                recipient = %hex::encode(to.as_bytes()),
                protocol_version,
                hedged,
                %error,
                "one or more required ACK publish routes returned an error; another hedge may still have delivered"
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
    use crate::history::{HistoryConfig, HistoryQuery, HistoryService};
    use crate::identity::{AgentKeypair, MachineKeypair};
    use crate::network::{NetworkConfig, NetworkNode};
    use std::sync::atomic::{AtomicBool, Ordering};

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
        pipeline: InboxPipeline,
        recipient_agent_id: AgentId,
        recipient_kem: Arc<AgentKemKeypair>,
        receiver: crate::direct::DirectMessageReceiver,
        history_service: Option<HistoryService>,
        _tempdir: tempfile::TempDir,
    }

    async fn make_inbox_harness(
        sender: &AgentKeypair,
        authenticated_machine: Option<MachineId>,
        revoked_machine: Option<&MachineKeypair>,
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
        };

        InboxHarness {
            pipeline,
            recipient_agent_id,
            recipient_kem,
            receiver,
            history_service: None,
            _tempdir: tempdir,
        }
    }

    async fn enable_durable_history(harness: &mut InboxHarness) -> crate::history::HistoryHandle {
        let config = HistoryConfig {
            enabled: true,
            ..HistoryConfig::default()
        };
        let service = HistoryService::start(&config, harness._tempdir.path())
            .expect("start durable history service");
        let handle = service.handle();
        harness.pipeline.history = Some(handle.clone());
        harness.history_service = Some(service);
        handle
    }

    /// Build a signed-but-unattested payload envelope, simulating a
    /// pre-#213 (legacy) sender: agent signature only, no origin attestation.
    fn craft_unsigned_payload_envelope(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        claimed_machine: MachineId,
        request_byte: u8,
    ) -> DmEnvelope {
        let created_at = now_unix_ms();
        let body = EnvelopeBuilder::build_payload_body(
            &[request_byte; 16],
            sender.agent_id().as_bytes(),
            harness.recipient_agent_id.as_bytes(),
            created_at,
            b"security regression payload".to_vec(),
            None,
            &harness.recipient_kem.public_bytes,
        )
        .expect("build payload body");
        DmEnvelope {
            protocol_version: crate::dm::DM_PROTOCOL_V1,
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

    fn durable_attested_payload_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: &MachineKeypair,
        request_byte: u8,
    ) -> PubSubMessage {
        let legacy = attested_payload_message(harness, sender, machine, request_byte);
        let mut envelope =
            DmEnvelope::from_wire_bytes(&legacy.payload).expect("decode attested envelope");
        envelope.protocol_version = DM_PROTOCOL_DURABLE_ACK;
        envelope.signature.clear();
        envelope.origin_attestation = None;
        sign_envelope_with_agent(&mut envelope, sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(machine).expect("machine attest v2");
        envelope.origin_attestation = Some(attestation);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    fn durable_attested_ack_message(
        harness: &InboxHarness,
        sender: &AgentKeypair,
        machine: &MachineKeypair,
        acked_request_id: [u8; 16],
        envelope_request_byte: u8,
    ) -> PubSubMessage {
        let created_at = now_unix_ms();
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            request_id: [envelope_request_byte; 16],
            sender_agent_id: *sender.agent_id().as_bytes(),
            sender_machine_id: *machine.machine_id().as_bytes(),
            recipient_agent_id: *harness.recipient_agent_id.as_bytes(),
            created_at_unix_ms: created_at,
            expires_at_unix_ms: created_at + 60_000,
            body: DmBody::Ack(crate::dm::DmAckBody {
                acks_request_id: acked_request_id,
                outcome: DmAckOutcome::Accepted,
            }),
            signature: Vec::new(),
            origin_attestation: None,
        };
        sign_envelope_with_agent(&mut envelope, sender);
        let mut attestation =
            DmOriginAttestation::for_envelope(&envelope, machine.public_key().as_bytes().to_vec());
        attestation.sign(machine).expect("ACK machine attestation");
        envelope.origin_attestation = Some(attestation);
        wrap_in_pubsub(harness, sender, &envelope)
    }

    #[tokio::test]
    async fn durable_v2_requires_history_before_dispatch_and_dedupes() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("sender machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let history = enable_durable_history(&mut harness).await;
        let message = durable_attested_payload_message(&harness, &sender, &machine, 0xA1);
        let duplicate = message.clone();

        harness.pipeline.handle_incoming(message, false).await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("v2 dispatch timeout")
            .expect("v2 delivery stream closed");
        assert_eq!(delivered.payload, b"security regression payload");

        let rows = history
            .store()
            .query(&HistoryQuery::default())
            .expect("query committed history");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record.payload, delivered.payload);

        harness.pipeline.handle_incoming(duplicate, false).await;
        assert_no_delivery(&mut harness.receiver).await;

        if let Some(service) = harness.history_service.take() {
            service.shutdown().await;
        }
    }

    #[tokio::test]
    async fn durable_v2_commit_failure_withholds_completion_and_retry_succeeds() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("sender machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let _closed_handle = enable_durable_history(&mut harness).await;
        let stopped = harness
            .history_service
            .take()
            .expect("history service started");
        stopped.shutdown().await;

        let message = durable_attested_payload_message(&harness, &sender, &machine, 0xA4);
        harness
            .pipeline
            .handle_incoming(message.clone(), false)
            .await;
        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            harness
                .pipeline
                .cache
                .lookup(
                    &DmEnvelope::from_wire_bytes(&message.payload)
                        .expect("envelope")
                        .dedupe_key()
                )
                .is_none(),
            "failed commit must not publish an Accepted completion"
        );

        let retry_db = harness._tempdir.path().join("retry-history.db");
        let retry_config = HistoryConfig {
            enabled: true,
            db_path: Some(retry_db),
            ..HistoryConfig::default()
        };
        let retry_service = HistoryService::start(&retry_config, harness._tempdir.path())
            .expect("restart history writer");
        let retry_history = retry_service.handle();
        harness.pipeline.history = Some(retry_history.clone());
        harness.history_service = Some(retry_service);

        harness.pipeline.handle_incoming(message, false).await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("retry dispatch timeout")
            .expect("retry delivery stream closed");
        assert_eq!(delivered.payload, b"security regression payload");
        assert_eq!(
            retry_history
                .store()
                .query(&HistoryQuery::default())
                .expect("query retry history")
                .len(),
            1
        );

        if let Some(service) = harness.history_service.take() {
            service.shutdown().await;
        }
    }

    #[tokio::test]
    async fn durable_v2_simultaneous_primary_and_legacy_commit_and_dispatch_once() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("sender machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let history = enable_durable_history(&mut harness).await;
        let message = durable_attested_payload_message(&harness, &sender, &machine, 0xA5);

        tokio::join!(
            harness.pipeline.handle_incoming(message.clone(), false),
            harness.pipeline.handle_incoming(message, true)
        );

        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("simultaneous dispatch timeout")
            .expect("delivery stream closed");
        assert_eq!(delivered.payload, b"security regression payload");
        assert_no_delivery(&mut harness.receiver).await;
        assert_eq!(
            history
                .store()
                .query(&HistoryQuery::default())
                .expect("query history")
                .len(),
            1
        );
        assert_eq!(
            history
                .counters()
                .written_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            history
                .counters()
                .dedup_hits
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        if let Some(service) = harness.history_service.take() {
            service.shutdown().await;
        }
    }

    #[tokio::test]
    async fn v1_then_v2_same_logical_request_is_not_redispatched() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("sender machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let v1 = attested_payload_message(&harness, &sender, &machine, 0xA6);
        let mut v2_envelope = DmEnvelope::from_wire_bytes(&v1.payload).expect("decode v1");
        v2_envelope.protocol_version = DM_PROTOCOL_DURABLE_ACK;
        v2_envelope.signature.clear();
        v2_envelope.origin_attestation = None;
        sign_envelope_with_agent(&mut v2_envelope, &sender);
        let mut attestation = DmOriginAttestation::for_envelope(
            &v2_envelope,
            machine.public_key().as_bytes().to_vec(),
        );
        attestation.sign(&machine).expect("v2 attestation");
        v2_envelope.origin_attestation = Some(attestation);
        let v2 = wrap_in_pubsub(&harness, &sender, &v2_envelope);

        harness.pipeline.handle_incoming(v1, false).await;
        let _first = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("v1 dispatch timeout")
            .expect("delivery stream closed");
        harness.pipeline.handle_incoming(v2, false).await;
        assert_no_delivery(&mut harness.receiver).await;

        let cached = harness
            .pipeline
            .cache
            .lookup(&v2_envelope.dedupe_key())
            .expect("v1 completion remains cached");
        assert_eq!(cached.protocol_version, crate::dm::DM_PROTOCOL_V1);
        assert!(matches!(
            cached_ack_for_protocol(&cached, DM_PROTOCOL_DURABLE_ACK),
            DmAckOutcome::AckSemanticsUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn durable_v2_without_history_withholds_dispatch() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("sender machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let message = durable_attested_payload_message(&harness, &sender, &machine, 0xA2);

        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
    }

    #[test]
    fn stale_or_replaced_history_outcome_cannot_complete_durable_delivery() {
        assert!(exact_durable_history_outcome(
            crate::history::InsertOutcome::Inserted
        ));
        assert!(exact_durable_history_outcome(
            crate::history::InsertOutcome::Duplicate
        ));
        assert!(!exact_durable_history_outcome(
            crate::history::InsertOutcome::Replaced
        ));
        assert!(!exact_durable_history_outcome(
            crate::history::InsertOutcome::StaleRejected
        ));
    }

    #[tokio::test]
    async fn durable_v2_poisoned_cache_withholds_before_history_and_dispatch() {
        let sender = test_keypair();
        let machine = MachineKeypair::generate().expect("sender machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let history = enable_durable_history(&mut harness).await;
        harness.pipeline.cache.poison_for_testing();
        let message = durable_attested_payload_message(&harness, &sender, &machine, 0xA7);

        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
        assert!(
            history
                .store()
                .query(&HistoryQuery::default())
                .expect("query history")
                .is_empty(),
            "poisoned replay cache must withhold before durable history commit"
        );
        if let Some(service) = harness.history_service.take() {
            service.shutdown().await;
        }
    }

    #[tokio::test]
    async fn durable_v2_rejects_unattested_machine_claim() {
        let sender = test_keypair();
        let claimed_machine = MachineId([0xA3; 32]);
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let mut envelope =
            craft_unsigned_payload_envelope(&harness, &sender, claimed_machine, 0xA3);
        envelope.protocol_version = DM_PROTOCOL_DURABLE_ACK;
        sign_envelope_with_agent(&mut envelope, &sender);
        let message = wrap_in_pubsub(&harness, &sender, &envelope);

        harness.pipeline.handle_incoming(message, false).await;

        assert_no_delivery(&mut harness.receiver).await;
    }

    #[tokio::test]
    async fn durable_v2_ack_requires_exact_advertised_agent_and_machine() {
        let intended = test_keypair();
        let intended_machine = MachineKeypair::generate().expect("intended machine");
        let third_party = test_keypair();
        let third_party_machine = MachineKeypair::generate().expect("third-party machine");
        let wrong_intended_machine = MachineKeypair::generate().expect("wrong intended machine");
        let harness = make_inbox_harness(&intended, None, None).await;
        let request_id = [0xB1; 16];
        let mut receipt = harness.pipeline.inflight.register_for_protocol(
            request_id,
            DM_PROTOCOL_DURABLE_ACK,
            intended.agent_id(),
            Some(intended_machine.machine_id()),
        );

        let wrong_agent = durable_attested_ack_message(
            &harness,
            &third_party,
            &third_party_machine,
            request_id,
            0xB2,
        );
        harness.pipeline.handle_incoming(wrong_agent, false).await;
        assert!(matches!(
            receipt.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(harness.pipeline.inflight.outstanding(), 1);

        let wrong_machine = durable_attested_ack_message(
            &harness,
            &intended,
            &wrong_intended_machine,
            request_id,
            0xB3,
        );
        harness.pipeline.handle_incoming(wrong_machine, false).await;
        assert!(matches!(
            receipt.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(harness.pipeline.inflight.outstanding(), 1);
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .ack_unresolved,
            2
        );

        let exact =
            durable_attested_ack_message(&harness, &intended, &intended_machine, request_id, 0xB4);
        harness.pipeline.handle_incoming(exact, false).await;
        assert_eq!(
            receipt.await.expect("exact recipient ACK"),
            DmAckOutcome::Accepted
        );
        assert_eq!(harness.pipeline.inflight.outstanding(), 0);
        assert_eq!(
            harness
                .pipeline
                .dm
                .diagnostics_snapshot()
                .stats
                .ack_unresolved,
            2,
            "the exact ACK must resolve without incrementing mismatch diagnostics"
        );
    }

    #[tokio::test]
    async fn durable_ack_bus_hedge_is_bounded_and_does_not_block_followup_dm() {
        assert!(!ack_requires_legacy_bus_hedge(
            crate::dm::DM_PROTOCOL_V1,
            false
        ));
        assert!(ack_requires_legacy_bus_hedge(
            crate::dm::DM_PROTOCOL_V1,
            true
        ));
        assert!(ack_requires_legacy_bus_hedge(
            DM_PROTOCOL_DURABLE_ACK,
            false
        ));

        let sender = test_keypair();
        let sender_machine = MachineKeypair::generate().expect("sender machine");
        let mut harness = make_inbox_harness(&sender, None, None).await;
        let history = enable_durable_history(&mut harness).await;
        let message = durable_attested_payload_message(&harness, &sender, &sender_machine, 0xC1);
        let replay = message.clone();
        let request_id = DmEnvelope::from_wire_bytes(&message.payload)
            .expect("decode production-shaped payload")
            .request_id;

        harness.pipeline.handle_incoming(message, false).await;
        let delivered = tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
            .await
            .expect("initial durable app dispatch timed out")
            .expect("direct-message receiver closed");
        assert_eq!(delivered.payload, b"security regression payload");

        let inflight = Arc::new(InFlightAcks::new());
        let recipient = harness.pipeline.self_agent_id;
        let machine = harness.pipeline.self_machine_id;
        let receipt = inflight.register_for_protocol(
            request_id,
            DM_PROTOCOL_DURABLE_ACK,
            recipient,
            Some(machine),
        );
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let targeted_started = Arc::new(AtomicBool::new(false));
        let targeted_dropped = Arc::new(AtomicBool::new(false));
        let targeted_started_tx = Arc::clone(&targeted_started);
        let targeted_dropped_tx = Arc::clone(&targeted_dropped);
        let legacy_inflight = Arc::clone(&inflight);

        let targeted = async move {
            let _drop_flag = DropFlag(targeted_dropped_tx);
            targeted_started_tx.store(true, Ordering::SeqCst);
            std::future::pending::<NetworkResult<()>>().await
        };
        let legacy = async move {
            assert!(legacy_inflight.resolve_for_protocol(
                &request_id,
                DM_PROTOCOL_DURABLE_ACK,
                recipient,
                machine,
                DmAckOutcome::Accepted,
            ));
            Ok(())
        };
        let publish_result = tokio::time::timeout(Duration::from_secs(1), async move {
            publish_ack_routes(
                ack_requires_legacy_bus_hedge(DM_PROTOCOL_DURABLE_ACK, false),
                Duration::from_millis(50),
                targeted,
                legacy,
            )
            .await
        })
        .await
        .expect("hedged ACK publisher remained head-of-line blocked");
        assert!(
            publish_result.is_err(),
            "the stalled targeted route must report its bounded timeout"
        );
        assert!(
            targeted_started.load(Ordering::SeqCst),
            "targeted ACK publish was not polled concurrently"
        );
        assert!(
            targeted_dropped.load(Ordering::SeqCst),
            "timed-out targeted ACK publish was not cancelled"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receipt)
                .await
                .expect("legacy ACK hedge did not reach the sender waiter")
                .expect("sender waiter was cancelled"),
            DmAckOutcome::Accepted
        );
        assert_eq!(inflight.outstanding(), 0);

        // The sender can retry the same logical envelope before observing the
        // hedge. Stable request_id replay must re-ACK from the completion cache
        // without a second durable row or second application dispatch.
        harness.pipeline.handle_incoming(replay, true).await;
        assert_no_delivery(&mut harness.receiver).await;
        let rows = history
            .store()
            .query(&HistoryQuery::default())
            .expect("query durable replay history");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record.payload, b"security regression payload");
        assert_eq!(
            rows[0].record.provenance,
            crate::history::Provenance::VerifiedEnvelope
        );
        assert!(rows[0].record.signed_artifact.is_some());
        assert!(rows[0].record.signature.is_some());
        assert_eq!(
            history
                .counters()
                .written_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // This is the same serial processing order as the subscription loop:
        // the next distinct envelope cannot enter `handle_incoming` until the
        // previous ACK publication returns. Its delivery proves the bounded
        // cancellation above prevents a stalled route from causing HoL.
        let followup = durable_attested_payload_message(&harness, &sender, &sender_machine, 0xC2);
        tokio::time::timeout(
            Duration::from_secs(2),
            harness.pipeline.handle_incoming(followup, false),
        )
        .await
        .expect("follow-up DM remained head-of-line blocked");
        let followup_delivered =
            tokio::time::timeout(Duration::from_secs(2), harness.receiver.recv())
                .await
                .expect("follow-up durable app dispatch timed out")
                .expect("direct-message receiver closed");
        assert_eq!(followup_delivered.payload, b"security regression payload");
        assert_eq!(
            history
                .store()
                .query(&HistoryQuery::default())
                .expect("query follow-up durable history")
                .len(),
            2,
            "the original logical request and the distinct follow-up each need one row"
        );
        assert_eq!(
            history
                .counters()
                .written_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        if let Some(service) = harness.history_service.take() {
            service.shutdown().await;
        }
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
        let config = DmInboxConfig::default().with_typed_payload_route(b"x0x-exec-v1 ", tx);
        assert_eq!(config.typed_payload_routes.len(), 1);
        assert_eq!(config.typed_payload_routes[0].prefix, b"x0x-exec-v1 ");
    }

    #[test]
    fn dm_inbox_config_with_multiple_routes() {
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<DmTypedPayload>(8);
        let config = DmInboxConfig::default()
            .with_typed_payload_route(b"prefix-a ", tx1)
            .with_typed_payload_route(b"prefix-b ", tx2);
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
