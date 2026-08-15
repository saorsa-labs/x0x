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
use crate::revocation::RevocationSet;
use crate::trust::{TrustContext, TrustDecision, TrustEvaluator};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

const ACK_ENVELOPE_LIFETIME_MS: u64 = 60_000;

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
        if let Some(cached) = self.cache.lookup(&dedupe) {
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

        // ADR 0030 §7 — typed-route obligation (documented, not closed here).
        //
        // Typed-prefix families (group ingest, KV deltas, exec audit, card
        // import, voice signalling) classify `Ephemeral`: their durable effect
        // lives in their own store, not in DM history, so a DM-history commit
        // could not honestly back their receipt. They are also handed off with
        // a non-blocking `try_send` that may drop under backpressure, so a
        // durable ACK here would claim a dispatch that never completed.
        //
        // A v2 envelope on a typed route therefore gets NO ACK in this slice,
        // and the handler carries the restart-spanning dedupe obligation via
        // its own durable surface (the bootstrap outbox handler satisfies it
        // with `Inserted | Duplicate` completion). Slice 3 adds the typed-route
        // completion signal that lets these frames earn a v2 ACK.
        if self
            .typed_payload_routes
            .iter()
            .any(|route| application_payload.starts_with(&route.prefix))
        {
            tracing::info!(
                target: "dm.trace",
                stage = "inbound_durable_typed_route_unacked",
                request_id = %hex::encode(request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
                "v2 DM matched a typed route; ACK withheld pending typed-route completion (ADR 0030 §7)"
            );
            return DurableAckDecision::Withheld("typed_route");
        }

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
                Some(_) => DmAckOutcome::AckSemanticsUnavailable {
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
                        DmAckOutcome::AckSemanticsUnavailable {
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

    /// ADR 0030 §7: typed routes are documented as carrying their own
    /// restart-spanning dedupe obligation, and do not earn a v2 ACK in this
    /// slice. Locking that in so slice 3 has to change this test deliberately.
    #[tokio::test]
    async fn durable_typed_route_withholds_ack_pending_handler_completion() {
        let sender = test_keypair();
        let machine = MachineId([0xD8; 32]);
        let mut harness = make_inbox_harness(&sender, Some(machine), None).await;
        let _service = attach_history(&mut harness);
        let (tx, _rx) = mpsc::channel::<DmTypedPayload>(8);
        harness.pipeline.typed_payload_routes = vec![DmTypedPayloadRoute {
            prefix: b"X0X-KV-DELTA-V1\n".to_vec(),
            sender: tx,
        }];

        let mut payload = b"X0X-KV-DELTA-V1\n".to_vec();
        payload.extend_from_slice(b"{\"k\":1}");
        let mut envelope = craft_unsigned_payload_envelope_versioned(
            &harness,
            &sender,
            machine,
            0x58,
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

        assert_eq!(decision, DurableAckDecision::Withheld("typed_route"));
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
            "AckSemanticsUnavailable must be appended last"
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
