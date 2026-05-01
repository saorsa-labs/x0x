//! Runtime service that consumes this agent's inbox topic, runs the
//! signature-first pipeline from `docs/design/dm-over-gossip.md`, and
//! bridges decrypted payloads into [`crate::direct::DirectMessaging`].

use crate::contacts::ContactStore;
use crate::direct::DirectMessaging;
use crate::dm::{
    decrypt_payload, now_unix_ms, validate_timestamp_window, DmAckOutcome, DmBody, DmEnvelope,
    DmPayload, EnvelopeBuilder, InFlightAcks, RecentDeliveryCache, DM_PROTOCOL_VERSION,
    MAX_ENVELOPE_BYTES,
};
use crate::error::{NetworkError, NetworkResult};
use crate::gossip::{PubSubManager, PubSubMessage, SigningContext};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::identity::{AgentId, MachineId};
use crate::trust::{TrustContext, TrustDecision, TrustEvaluator};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

const ACK_ENVELOPE_LIFETIME_MS: u64 = 60_000;

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
    handle: JoinHandle<()>,
    topic: String,
}

/// Shared DM transport topic. Every gossip-DM-capable agent subscribes
/// here. Recipients filter by `envelope.recipient_agent_id`; non-
/// recipients observe only encrypted metadata/payload and do not process it.
///
/// The shared bus keeps topic membership simple, but application-level
/// re-broadcast is intentionally avoided: `PubSubManager::publish()` signs
/// each hop with the local agent id, while the DM envelope signature is bound
/// to the origin agent id. Re-publishing an origin envelope from a relay would
/// make the outer PubSub sender differ from `envelope.sender_agent_id`, so
/// downstream receivers would reject it and the fleet would only gain load.
pub const DM_BUS_TOPIC: &str = "x0x/dm/v1/bus";

impl DmInboxService {
    /// Topic every DM envelope is published on. Uniform across agents so
    /// all subscribers can relay via epidemic broadcast.
    #[must_use]
    pub fn inbox_topic_name(_agent_id: &AgentId) -> String {
        DM_BUS_TOPIC.to_string()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        kem_keypair: Arc<AgentKemKeypair>,
        dm: Arc<DirectMessaging>,
        contacts: Arc<RwLock<ContactStore>>,
        inflight: Arc<InFlightAcks>,
        cache: Arc<RecentDeliveryCache>,
        config: DmInboxConfig,
    ) -> NetworkResult<Self> {
        let topic = Self::inbox_topic_name(&self_agent_id);
        let mut subscription = pubsub.subscribe(topic.clone()).await;

        let pipeline = InboxPipeline {
            pubsub: Arc::clone(&pubsub),
            signing,
            self_agent_id,
            self_machine_id,
            kem_keypair,
            dm,
            contacts,
            inflight,
            cache,
            silent_reject: config.silent_reject,
            typed_payload_routes: config.typed_payload_routes,
        };

        let topic_for_task = topic.clone();
        let handle = tokio::spawn(async move {
            tracing::info!(topic = %topic_for_task, "DM inbox service subscribed");
            while let Some(message) = subscription.recv().await {
                pipeline.handle_incoming(message).await;
            }
            tracing::debug!(topic = %topic_for_task, "DM inbox subscription closed");
        });

        Ok(Self { handle, topic })
    }

    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for DmInboxService {
    fn drop(&mut self) {
        self.abort();
    }
}

struct InboxPipeline {
    pubsub: Arc<PubSubManager>,
    signing: Arc<SigningContext>,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    kem_keypair: Arc<AgentKemKeypair>,
    dm: Arc<DirectMessaging>,
    contacts: Arc<RwLock<ContactStore>>,
    inflight: Arc<InFlightAcks>,
    cache: Arc<RecentDeliveryCache>,
    silent_reject: bool,
    typed_payload_routes: Vec<DmTypedPayloadRoute>,
}

impl InboxPipeline {
    async fn handle_incoming(&self, msg: PubSubMessage) {
        let (pubsub_sender, sender_pubkey) = match (msg.sender, msg.sender_public_key.as_deref()) {
            (Some(s), Some(pk)) if msg.verified => (s, pk.to_vec()),
            _ => return,
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
                let _ = self
                    .publish_ack(
                        AgentId(envelope.sender_agent_id),
                        envelope.request_id,
                        cached.outcome,
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
            return;
        }

        match envelope.body.clone() {
            DmBody::Ack(ack) => {
                let resolved = self.inflight.resolve(&ack.acks_request_id, ack.outcome);
                tracing::debug!(
                    acked = %hex::encode(ack.acks_request_id),
                    resolved,
                    "DM ACK received"
                );
            }
            DmBody::Payload(payload) => {
                self.handle_payload(envelope, payload).await;
            }
        }
    }

    async fn handle_payload(&self, envelope: DmEnvelope, payload: DmPayload) {
        let sender_agent_id = AgentId(envelope.sender_agent_id);
        let sender_machine_id = MachineId(envelope.sender_machine_id);

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
                self.cache.insert(envelope.dedupe_key(), outcome.clone());
                if !self.silent_reject {
                    let _ = self
                        .publish_ack(sender_agent_id, envelope.request_id, outcome)
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

        let is_typed_payload = self
            .route_typed_payload(
                sender_agent_id,
                sender_machine_id,
                plaintext.payload.clone(),
                Some(decision),
            )
            .await;

        if !is_typed_payload {
            self.dm
                .handle_incoming(
                    sender_machine_id,
                    sender_agent_id,
                    plaintext.payload,
                    true,
                    Some(decision),
                )
                .await;

            tracing::info!(
                target: "dm.trace",
                stage = "inbound_broadcast_published",
                request_id = %hex::encode(envelope.request_id),
                sender = %hex::encode(sender_agent_id.as_bytes()),
            );
        }

        self.cache
            .insert(envelope.dedupe_key(), DmAckOutcome::Accepted);

        let _ = self
            .publish_ack(sender_agent_id, envelope.request_id, DmAckOutcome::Accepted)
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
        if route.sender.send(typed).await.is_err() {
            tracing::warn!(
                sender = %hex::encode(sender_agent_id.as_bytes()),
                "typed DM payload route receiver is closed; dropping payload"
            );
        }
        true
    }

    async fn publish_ack(
        &self,
        to: AgentId,
        acks_request_id: [u8; 16],
        outcome: DmAckOutcome,
    ) -> NetworkResult<()> {
        let body = EnvelopeBuilder::build_ack_body(acks_request_id, outcome);
        let created = now_unix_ms();
        let expires = created + ACK_ENVELOPE_LIFETIME_MS;
        let mut ack_rid = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut ack_rid);

        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: ack_rid,
            sender_agent_id: *self.self_agent_id.as_bytes(),
            sender_machine_id: *self.self_machine_id.as_bytes(),
            recipient_agent_id: *to.as_bytes(),
            created_at_unix_ms: created,
            expires_at_unix_ms: expires,
            body,
            signature: Vec::new(),
        };
        let signed = envelope
            .signed_bytes()
            .map_err(|e| NetworkError::SerializationError(format!("ack sign-bytes: {e}")))?;
        envelope.signature = self.signing.sign(&signed)?;
        let encoded = envelope
            .to_wire_bytes()
            .map_err(|e| NetworkError::SerializationError(format!("ack encode: {e}")))?;
        let topic = DmInboxService::inbox_topic_name(&to);
        self.pubsub.publish(topic, Bytes::from(encoded)).await
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
