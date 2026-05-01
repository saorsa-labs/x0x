//! Sender-side gossip DM path (phase 4 of `docs/design/dm-over-gossip.md`).

use crate::dm::{
    now_unix_ms, DmAckOutcome, DmEnvelope, DmError, DmPath, DmReceipt, DmSendConfig,
    EnvelopeBuilder, InFlightAcks, DM_PROTOCOL_VERSION, MAX_PAYLOAD_BYTES,
};
use crate::dm_inbox::DmInboxService;
use crate::error::IdentityError;
use crate::gossip::{PubSubManager, SigningContext};
use crate::identity::{AgentId, MachineId};

use bytes::Bytes;
use std::sync::Arc;
use std::time::Instant;

pub const DEFAULT_ENVELOPE_LIFETIME_MS: u64 = 120_000;

#[allow(clippy::too_many_arguments)]
pub async fn send_via_gossip(
    pubsub: Arc<PubSubManager>,
    signing: &SigningContext,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    recipient_agent_id: AgentId,
    recipient_kem_public_key: &[u8],
    payload: Vec<u8>,
    config: &DmSendConfig,
    inflight: Arc<InFlightAcks>,
) -> Result<DmReceipt, DmError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(DmError::EnvelopeConstruction(format!(
            "payload exceeds MAX_PAYLOAD_BYTES ({} > {})",
            payload.len(),
            MAX_PAYLOAD_BYTES
        )));
    }
    if recipient_kem_public_key.is_empty() {
        return Err(DmError::RecipientKeyUnavailable(
            "recipient has no published KEM public key".to_string(),
        ));
    }

    let request_id = fresh_request_id();

    let created = now_unix_ms();
    let expires = created.saturating_add(DEFAULT_ENVELOPE_LIFETIME_MS);
    let body = EnvelopeBuilder::build_payload_body(
        &request_id,
        self_agent_id.as_bytes(),
        recipient_agent_id.as_bytes(),
        created,
        payload,
        None,
        recipient_kem_public_key,
    )
    .map_err(map_identity_err)?;
    let mut envelope = DmEnvelope {
        protocol_version: DM_PROTOCOL_VERSION,
        request_id,
        sender_agent_id: *self_agent_id.as_bytes(),
        sender_machine_id: *self_machine_id.as_bytes(),
        recipient_agent_id: *recipient_agent_id.as_bytes(),
        created_at_unix_ms: created,
        expires_at_unix_ms: expires,
        body,
        signature: Vec::new(),
    };
    let signed = envelope.signed_bytes().map_err(map_identity_err)?;
    envelope.signature = signing
        .sign(&signed)
        .map_err(|e| DmError::EnvelopeConstruction(format!("sign: {e}")))?;
    let wire = envelope.to_wire_bytes().map_err(map_identity_err)?;
    let topic = DmInboxService::inbox_topic_name(&recipient_agent_id);

    tracing::info!(
        target: "dm.trace",
        stage = "path_chosen",
        request_id = %hex::encode(request_id),
        recipient = %hex::encode(recipient_agent_id.as_bytes()),
        path = "gossip_inbox",
        timeout_ms = config.timeout_per_attempt.as_millis() as u64,
    );
    tracing::info!(
        target: "dm.trace",
        stage = "wire_encoded",
        request_id = %hex::encode(request_id),
        recipient = %hex::encode(recipient_agent_id.as_bytes()),
        bytes = wire.len(),
    );

    let mut rx = inflight.register(request_id);
    let mut guard = InFlightGuard::new(Arc::clone(&inflight), request_id);

    let start = Instant::now();
    for attempt in 0..=config.max_retries {
        // The per-attempt budget covers both the local PlumTree publish and
        // the remote ACK wait.  Under PubSub back-pressure, `publish()` can be
        // the slow leg; bounding only the ACK wait let HTTP handlers exceed
        // their curl/user-visible deadline without returning a structured
        // `DmError::Timeout`.
        let attempt_result = tokio::time::timeout(config.timeout_per_attempt, async {
            pubsub
                .publish(topic.clone(), Bytes::from(wire.clone()))
                .await
                .map_err(|e| DmError::LocalGossipUnavailable(e.to_string()))?;

            (&mut rx).await.map_err(|_| {
                DmError::PublishFailed("in-flight ACK registry replaced our waiter".to_string())
            })
        })
        .await;

        match attempt_result {
            Ok(Ok(outcome)) => {
                tracing::info!(
                    target: "dm.trace",
                    stage = "outbound_send_returned_ok",
                    request_id = %hex::encode(request_id),
                    recipient = %hex::encode(recipient_agent_id.as_bytes()),
                    attempt,
                );
                guard.mark_resolved();
                return match outcome {
                    DmAckOutcome::Accepted => Ok(DmReceipt {
                        request_id,
                        accepted_at: Instant::now(),
                        retries_used: attempt,
                        path: DmPath::GossipInbox,
                    }),
                    DmAckOutcome::RejectedByPolicy { reason } => {
                        Err(DmError::RecipientRejected { reason })
                    }
                };
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if attempt < config.max_retries {
                    let delay = config.backoff.delay(config.timeout_per_attempt, attempt);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }

    Err(DmError::Timeout {
        retries: config.max_retries,
        elapsed: start.elapsed(),
    })
}

struct InFlightGuard {
    inflight: Arc<InFlightAcks>,
    request_id: [u8; 16],
    resolved: bool,
}

impl InFlightGuard {
    fn new(inflight: Arc<InFlightAcks>, request_id: [u8; 16]) -> Self {
        Self {
            inflight,
            request_id,
            resolved: false,
        }
    }

    fn mark_resolved(&mut self) {
        self.resolved = true;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if !self.resolved {
            self.inflight.cancel(&self.request_id);
        }
    }
}

fn fresh_request_id() -> [u8; 16] {
    use rand::RngCore;
    let mut rid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut rid);
    rid
}

fn map_identity_err(e: IdentityError) -> DmError {
    DmError::EnvelopeConstruction(e.to_string())
}

#[must_use]
pub fn raw_quic_receipt() -> DmReceipt {
    raw_quic_receipt_for_path(DmPath::RawQuic)
}

#[must_use]
pub fn loopback_receipt() -> DmReceipt {
    receipt_for_path(DmPath::Loopback)
}

#[must_use]
pub fn raw_quic_receipt_for_path(path: DmPath) -> DmReceipt {
    receipt_for_path(path)
}

fn receipt_for_path(path: DmPath) -> DmReceipt {
    DmReceipt {
        request_id: fresh_request_id(),
        accepted_at: Instant::now(),
        retries_used: 0,
        path,
    }
}
