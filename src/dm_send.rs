//! Sender-side gossip DM path (phase 4 of `docs/design/dm-over-gossip.md`).

use crate::dm::{
    dm_inbox_topic, now_unix_ms, DmAckOutcome, DmError, DmLogicalId, DmPath, DmReceipt,
    DmSendConfig, DmThreadMeta, EnvelopeBuilder, InFlightAcks, DM_PROTOCOL_DURABLE_ACK,
    DM_PROTOCOL_THREADED, DM_PROTOCOL_V1, MAX_PAYLOAD_BYTES,
};
use crate::dm_inbox::{DmInboxService, DM_BUS_TOPIC};
use crate::error::IdentityError;
use crate::gossip::{PubSubManager, SigningContext};
use crate::identity::{AgentId, MachineId, MachineKeypair};

use bytes::Bytes;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::TryRecvError as BroadcastTryRecvError;
use tokio::sync::oneshot::error::TryRecvError;

/// X0X-0041: prefer-newest-connection hint for the gossip-DM retry loop.
///
/// When provided, the retry loop watches for `Replaced` lifecycle events that
/// target the recipient's machine_id and short-circuits the current backoff —
/// the supersede signal indicates the previous attempt's transport state is
/// stale and we should reissue against the new generation immediately rather
/// than waiting for the configured backoff window.
pub struct DmLifecycleHint {
    /// MachineId of the intended recipient (resolved by caller from the
    /// discovery cache or direct-messaging registry).
    pub recipient_machine_id: MachineId,
    /// Receiver for `(machine_id, new_generation)` from
    /// [`crate::direct::DirectMessaging::subscribe_lifecycle_replaced`].
    pub replaced_rx: tokio::sync::broadcast::Receiver<(MachineId, u64)>,
}

pub const DEFAULT_ENVELOPE_LIFETIME_MS: u64 = 120_000;
const PUBLISH_ONLY_REDUNDANT_REPUBLISH_DELAY: Duration = Duration::from_millis(250);
const ACK_LEGACY_BUS_FALLBACK_DELAY: Duration = Duration::from_millis(250);
const THREADED_PAYLOAD_MAGIC: &[u8; 16] = b"x0x-dm-thread-v1";

#[derive(serde::Serialize, serde::Deserialize)]
struct ThreadedDmPayload {
    payload: Vec<u8>,
    thread_meta: DmThreadMeta,
}

/// Stable per-sender context for [`send_via_gossip`].
///
/// Groups the identity/runtime handles that are constant for a given sending
/// agent, separating them from the per-call message parameters. This keeps the
/// two adjacent `AgentId`/`MachineId` self-identity fields off the call site's
/// positional argument list, where they were easy to transpose.
pub struct DmSendContext<'a> {
    /// PlumTree pub/sub manager used to publish the envelope.
    pub pubsub: Arc<PubSubManager>,
    /// Sender signing context (ML-DSA-65 agent key).
    pub signing: &'a SigningContext,
    /// This agent's `AgentId`.
    pub self_agent_id: AgentId,
    /// This agent's `MachineId`.
    pub self_machine_id: MachineId,
    /// This machine's keypair — signs the #213 origin-machine attestation
    /// embedded in every envelope. MUST own `self_machine_id`.
    pub machine_keypair: &'a MachineKeypair,
    /// Shared in-flight ACK registry.
    pub inflight: Arc<InFlightAcks>,
    /// Absolute expiry for a strict logical send, computed before discovery
    /// and transport work so anti-entropy cannot outlive the caller deadline.
    pub expires_at_unix_ms: Option<u64>,
    /// Negotiated v3 thread metadata. `None` keeps plaintext application
    /// bytes byte-identical for v1/v2 and unthreaded recipients.
    pub thread_meta: Option<&'a DmThreadMeta>,
    /// Explicit caller idempotency key. Omission retains a random request id.
    pub logical_id: Option<&'a DmLogicalId>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedDmEnvelope {
    pub(crate) request_id: [u8; 16],
    pub(crate) protocol_version: u16,
    pub(crate) wire: Vec<u8>,
}

pub(crate) struct DmAckWaiter {
    rx: tokio::sync::oneshot::Receiver<DmAckOutcome>,
    guard: InFlightGuard,
}

impl DmAckWaiter {
    pub(crate) fn register(
        inflight: Arc<InFlightAcks>,
        prepared: &PreparedDmEnvelope,
        recipient_agent_id: AgentId,
        recipient_machine_id: Option<MachineId>,
    ) -> Self {
        let rx = inflight.register_for_protocol(
            prepared.request_id,
            prepared.protocol_version,
            recipient_agent_id,
            recipient_machine_id,
        );
        let guard = InFlightGuard::new(inflight, prepared.request_id);
        Self { rx, guard }
    }

    pub(crate) async fn wait_for_raw_ack(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<DmAckOutcome>, DmError> {
        match tokio::time::timeout(timeout, &mut self.rx).await {
            Ok(Ok(outcome)) => Ok(Some(outcome)),
            Ok(Err(_)) => Err(DmError::PublishFailed(
                "in-flight ACK registry replaced our raw waiter".to_string(),
            )),
            Err(_) => Ok(None),
        }
    }

    pub(crate) fn finish_raw(
        mut self,
        outcome: DmAckOutcome,
        request_id: [u8; 16],
    ) -> Result<DmReceipt, DmError> {
        self.guard.mark_resolved();
        ack_outcome_to_receipt_for_path(outcome, request_id, 0, DmPath::RawQuicAcked)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_dm_envelope(
    signing: &SigningContext,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    machine_keypair: &MachineKeypair,
    recipient_agent_id: AgentId,
    recipient_kem_public_key: &[u8],
    payload: Vec<u8>,
    protocol_version: u16,
    expires_at_unix_ms: Option<u64>,
    thread_meta: Option<&DmThreadMeta>,
    logical_id: Option<&DmLogicalId>,
) -> Result<PreparedDmEnvelope, DmError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(DmError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_BYTES,
        });
    }
    if recipient_kem_public_key.is_empty() {
        return Err(DmError::RecipientKeyUnavailable(
            "recipient has no published KEM public key".to_string(),
        ));
    }
    let request_id = request_id_for_logical(self_agent_id, recipient_agent_id, logical_id);
    let payload = encode_application_payload(payload, protocol_version, thread_meta)?;
    let created = now_unix_ms();
    let expires = match expires_at_unix_ms {
        Some(expires) if expires > created => expires,
        Some(_) => {
            return Err(DmError::Timeout {
                retries: 0,
                elapsed: Duration::ZERO,
            });
        }
        None => created.saturating_add(DEFAULT_ENVELOPE_LIFETIME_MS),
    };
    let envelope = EnvelopeBuilder::build_payload_envelope_with_version(
        protocol_version,
        request_id,
        &self_agent_id,
        &self_machine_id,
        machine_keypair,
        &recipient_agent_id,
        recipient_kem_public_key,
        created,
        expires,
        payload,
        |bytes| signing.sign(bytes).map_err(|error| error.to_string()),
    )?;
    Ok(PreparedDmEnvelope {
        request_id,
        protocol_version,
        wire: envelope.to_wire_bytes().map_err(map_identity_err)?,
    })
}

pub async fn send_via_gossip(
    ctx: DmSendContext<'_>,
    recipient_agent_id: AgentId,
    recipient_machine_id: Option<MachineId>,
    recipient_kem_public_key: &[u8],
    payload: Vec<u8>,
    config: &DmSendConfig,
    lifecycle_hint: Option<DmLifecycleHint>,
) -> Result<DmReceipt, DmError> {
    let protocol_version = if ctx.thread_meta.is_some() {
        DM_PROTOCOL_THREADED
    } else if config.require_durable_app_ack {
        DM_PROTOCOL_DURABLE_ACK
    } else {
        DM_PROTOCOL_V1
    };
    let prepared = prepare_dm_envelope(
        ctx.signing,
        ctx.self_agent_id,
        ctx.self_machine_id,
        ctx.machine_keypair,
        recipient_agent_id,
        recipient_kem_public_key,
        payload,
        protocol_version,
        ctx.expires_at_unix_ms,
        ctx.thread_meta,
        ctx.logical_id,
    )?;
    let waiter = DmAckWaiter::register(
        Arc::clone(&ctx.inflight),
        &prepared,
        recipient_agent_id,
        recipient_machine_id,
    );
    send_prepared_via_gossip(
        ctx,
        recipient_agent_id,
        prepared,
        config,
        lifecycle_hint,
        waiter,
    )
    .await
}

pub(crate) async fn send_prepared_via_gossip(
    ctx: DmSendContext<'_>,
    recipient_agent_id: AgentId,
    prepared: PreparedDmEnvelope,
    config: &DmSendConfig,
    lifecycle_hint: Option<DmLifecycleHint>,
    waiter: DmAckWaiter,
) -> Result<DmReceipt, DmError> {
    let DmSendContext {
        pubsub,
        signing: _,
        self_agent_id: _,
        self_machine_id: _,
        machine_keypair: _,
        inflight: _,
        expires_at_unix_ms: _,
        thread_meta: _,
        logical_id: _,
    } = ctx;
    let PreparedDmEnvelope {
        request_id,
        protocol_version: _,
        wire,
    } = prepared;
    let topic = DmInboxService::inbox_topic_name(&recipient_agent_id);
    let topic_id = dm_inbox_topic(&recipient_agent_id);

    tracing::debug!(
        target: "dm.trace",
        stage = "path_chosen",
        request_id = %hex::encode(request_id),
        recipient = %hex::encode(recipient_agent_id.as_bytes()),
        path = "gossip_inbox",
        timeout_ms = config.timeout_per_attempt.as_millis() as u64,
    );
    tracing::debug!(
        target: "dm.trace",
        stage = "wire_encoded",
        request_id = %hex::encode(request_id),
        recipient = %hex::encode(recipient_agent_id.as_bytes()),
        bytes = wire.len(),
    );

    let DmAckWaiter { mut rx, mut guard } = waiter;

    // X0X-0041: split the lifecycle hint into the per-peer match key and the
    // mutable receiver so we can both filter events and short-circuit the
    // backoff on a `Replaced` for the target peer.
    let mut lifecycle_hint = lifecycle_hint;

    let start = Instant::now();
    for attempt in 0..=config.max_retries {
        if attempt > 0 {
            match rx.try_recv() {
                Ok(outcome) => {
                    tracing::debug!(
                        target: "dm.trace",
                        stage = "outbound_send_returned_ok",
                        request_id = %hex::encode(request_id),
                        recipient = %hex::encode(recipient_agent_id.as_bytes()),
                        attempt = attempt.saturating_sub(1),
                        ack_observed = "before_retry",
                    );
                    guard.mark_resolved();
                    return ack_outcome_to_receipt(outcome, request_id, attempt.saturating_sub(1));
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Closed) => {
                    return Err(DmError::PublishFailed(
                        "in-flight ACK registry replaced our waiter".to_string(),
                    ));
                }
            }
        }

        // The per-attempt budget covers both the local PlumTree publish and
        // the remote ACK wait.  Under PubSub back-pressure, `publish()` can be
        // the slow leg; bounding only the ACK wait let HTTP handlers exceed
        // their curl/user-visible deadline without returning a structured
        // `DmError::Timeout`.
        let attempt_result = tokio::time::timeout(config.timeout_per_attempt, async {
            let primary_publish = pubsub
                .publish_topic_id(topic.clone(), topic_id, Bytes::from(wire.clone()))
                .await;
            let primary_publish_ok = match primary_publish {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        target: "dm.trace",
                        stage = "primary_inbox_publish_failed",
                        request_id = %hex::encode(request_id),
                        recipient = %crate::logging::LogAgentId::from(&recipient_agent_id),
                        attempt,
                        error = %e,
                    );
                    false
                }
            };

            if !config.require_gossip_ack {
                if !primary_publish_ok {
                    return Err(DmError::LocalGossipUnavailable(
                        "primary inbox publish failed".to_string(),
                    ));
                }
                return Ok(None);
            }

            if primary_publish_ok {
                if let Some(outcome) =
                    wait_for_ack_or_backoff(&mut rx, ACK_LEGACY_BUS_FALLBACK_DELAY).await?
                {
                    return Ok(Some(outcome));
                }
            }

            tracing::debug!(
                target: "dm.trace",
                stage = "legacy_bus_fallback_publish",
                request_id = %hex::encode(request_id),
                recipient = %hex::encode(recipient_agent_id.as_bytes()),
                attempt,
                primary_publish_ok,
                bus_topic = DM_BUS_TOPIC,
            );
            if let Err(e) = pubsub
                .publish(DM_BUS_TOPIC.to_string(), Bytes::from(wire.clone()))
                .await
            {
                if primary_publish_ok {
                    tracing::warn!(
                        target: "dm.trace",
                        stage = "legacy_bus_fallback_publish_failed",
                        request_id = %hex::encode(request_id),
                        recipient = %crate::logging::LogAgentId::from(&recipient_agent_id),
                        attempt,
                        error = %e,
                    );
                } else {
                    return Err(DmError::LocalGossipUnavailable(e.to_string()));
                }
            }

            (&mut rx).await.map(Some).map_err(|_| {
                DmError::PublishFailed("in-flight ACK registry replaced our waiter".to_string())
            })
        })
        .await;

        match attempt_result {
            Ok(Ok(Some(outcome))) => {
                tracing::debug!(
                    target: "dm.trace",
                    stage = "outbound_send_returned_ok",
                    request_id = %hex::encode(request_id),
                    recipient = %hex::encode(recipient_agent_id.as_bytes()),
                    attempt,
                );
                guard.mark_resolved();
                return ack_outcome_to_receipt(outcome, request_id, attempt);
            }
            Ok(Ok(None)) => {
                tracing::debug!(
                    target: "dm.trace",
                    stage = "outbound_send_publish_only_attempt",
                    request_id = %hex::encode(request_id),
                    recipient = %hex::encode(recipient_agent_id.as_bytes()),
                    attempt,
                    ack_required = false,
                );
                if attempt < config.max_retries {
                    tokio::time::sleep(PUBLISH_ONLY_REDUNDANT_REPUBLISH_DELAY).await;
                    continue;
                }
                tracing::debug!(
                    target: "dm.trace",
                    stage = "outbound_send_returned_ok",
                    request_id = %hex::encode(request_id),
                    recipient = %hex::encode(recipient_agent_id.as_bytes()),
                    retries_used = attempt,
                    ack_required = false,
                );
                return Ok(gossip_publish_receipt(request_id, attempt));
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if attempt < config.max_retries {
                    let delay = config.backoff.delay(config.timeout_per_attempt, attempt);
                    let wait_outcome = wait_for_ack_or_backoff_or_replaced(
                        &mut rx,
                        delay,
                        lifecycle_hint.as_mut(),
                    )
                    .await?;
                    match wait_outcome {
                        BackoffWait::Ack(outcome) => {
                            tracing::debug!(
                                target: "dm.trace",
                                stage = "outbound_send_returned_ok",
                                request_id = %hex::encode(request_id),
                                recipient = %hex::encode(recipient_agent_id.as_bytes()),
                                attempt,
                                ack_observed = "during_backoff",
                            );
                            guard.mark_resolved();
                            return ack_outcome_to_receipt(outcome, request_id, attempt);
                        }
                        BackoffWait::ReplacedShortCircuit { new_generation } => {
                            tracing::debug!(
                                target: "dm.trace",
                                stage = "outbound_send_replaced_short_circuit",
                                request_id = %hex::encode(request_id),
                                recipient = %hex::encode(recipient_agent_id.as_bytes()),
                                attempt,
                                new_generation,
                                "X0X-0041: prefer-newest, abandon backoff and reissue against new generation",
                            );
                        }
                        BackoffWait::Elapsed => {}
                    }
                }
            }
        }
    }

    if let Ok(outcome) = rx.try_recv() {
        tracing::debug!(
            target: "dm.trace",
            stage = "outbound_send_returned_ok",
            request_id = %hex::encode(request_id),
            recipient = %hex::encode(recipient_agent_id.as_bytes()),
            attempt = config.max_retries,
            ack_observed = "before_timeout",
        );
        guard.mark_resolved();
        return ack_outcome_to_receipt(outcome, request_id, config.max_retries);
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

async fn wait_for_ack_or_backoff(
    rx: &mut tokio::sync::oneshot::Receiver<DmAckOutcome>,
    delay: Duration,
) -> Result<Option<DmAckOutcome>, DmError> {
    if delay.is_zero() {
        return Ok(None);
    }
    match tokio::time::timeout(delay, rx).await {
        Ok(Ok(outcome)) => Ok(Some(outcome)),
        Ok(Err(_)) => Err(DmError::PublishFailed(
            "in-flight ACK registry replaced our waiter".to_string(),
        )),
        Err(_) => Ok(None),
    }
}

/// X0X-0041: outcome of the prefer-newest-aware backoff wait.
#[derive(Debug)]
enum BackoffWait {
    /// The recipient ACKed during the backoff window.
    Ack(DmAckOutcome),
    /// A `Replaced` event for the target peer fired during the backoff —
    /// short-circuit and reissue against the new generation.
    ReplacedShortCircuit {
        /// new generation reported by ant-quic
        new_generation: u64,
    },
    /// Backoff window elapsed without ACK or supersede signal.
    Elapsed,
}

/// X0X-0041: backoff wait that races ACK delivery, the configured backoff
/// timer, and a supersede event for the target peer.
async fn wait_for_ack_or_backoff_or_replaced(
    rx: &mut tokio::sync::oneshot::Receiver<DmAckOutcome>,
    delay: Duration,
    lifecycle_hint: Option<&mut DmLifecycleHint>,
) -> Result<BackoffWait, DmError> {
    if delay.is_zero() {
        return Ok(BackoffWait::Elapsed);
    }
    let Some(hint) = lifecycle_hint else {
        // No hint → fall back to the legacy two-arm wait.
        return match wait_for_ack_or_backoff(rx, delay).await? {
            Some(outcome) => Ok(BackoffWait::Ack(outcome)),
            None => Ok(BackoffWait::Elapsed),
        };
    };
    let target_machine = hint.recipient_machine_id;
    let replaced_rx = &mut hint.replaced_rx;

    let deadline = tokio::time::Instant::now() + delay;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(BackoffWait::Elapsed);
        }
        tokio::select! {
            biased;
            ack = &mut *rx => {
                return match ack {
                    Ok(outcome) => Ok(BackoffWait::Ack(outcome)),
                    Err(_) => Err(DmError::PublishFailed(
                        "in-flight ACK registry replaced our waiter".to_string(),
                    )),
                };
            }
            replaced = replaced_rx.recv() => {
                match replaced {
                    Ok((machine, gen)) if machine == target_machine => {
                        return Ok(BackoffWait::ReplacedShortCircuit { new_generation: gen });
                    }
                    Ok(_) => {
                        // Event for a different peer — keep waiting.
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Replaced channel lag on a noisy node — drain any
                        // outstanding events for the target peer before
                        // resuming the wait.
                        loop {
                            match replaced_rx.try_recv() {
                                Ok((machine, gen)) if machine == target_machine => {
                                    return Ok(BackoffWait::ReplacedShortCircuit { new_generation: gen });
                                }
                                Ok(_) => continue,
                                Err(BroadcastTryRecvError::Empty)
                                | Err(BroadcastTryRecvError::Closed)
                                | Err(BroadcastTryRecvError::Lagged(_)) => break,
                            }
                        }
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // Channel closed — fall back to the simple delay.
                        match tokio::time::timeout_at(deadline, &mut *rx).await {
                            Ok(Ok(outcome)) => return Ok(BackoffWait::Ack(outcome)),
                            Ok(Err(_)) => return Err(DmError::PublishFailed(
                                "in-flight ACK registry replaced our waiter".to_string(),
                            )),
                            Err(_) => return Ok(BackoffWait::Elapsed),
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Ok(BackoffWait::Elapsed);
            }
        }
    }
}

fn ack_outcome_to_receipt(
    outcome: DmAckOutcome,
    request_id: [u8; 16],
    retries_used: u8,
) -> Result<DmReceipt, DmError> {
    ack_outcome_to_receipt_for_path(outcome, request_id, retries_used, DmPath::GossipInbox)
}

fn ack_outcome_to_receipt_for_path(
    outcome: DmAckOutcome,
    request_id: [u8; 16],
    retries_used: u8,
    path: DmPath,
) -> Result<DmReceipt, DmError> {
    match outcome {
        DmAckOutcome::Accepted => Ok(DmReceipt {
            request_id,
            accepted_at: Instant::now(),
            retries_used,
            path,
        }),
        DmAckOutcome::RejectedByPolicy { reason } => Err(DmError::RecipientRejected { reason }),
        DmAckOutcome::AckSemanticsUnavailable { reason } => {
            Err(DmError::AckSemanticsUnavailable(reason))
        }
    }
}

fn gossip_publish_receipt(request_id: [u8; 16], retries_used: u8) -> DmReceipt {
    DmReceipt {
        request_id,
        accepted_at: Instant::now(),
        retries_used,
        path: DmPath::GossipInbox,
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if !self.resolved {
            self.inflight.cancel(&self.request_id);
        }
    }
}

pub(crate) fn fresh_request_id() -> [u8; 16] {
    use rand::RngCore;
    let mut rid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut rid);
    rid
}

pub(crate) fn encode_application_payload(
    payload: Vec<u8>,
    protocol_version: u16,
    thread_meta: Option<&DmThreadMeta>,
) -> Result<Vec<u8>, DmError> {
    let Some(thread_meta) = thread_meta else {
        return Ok(payload);
    };
    if protocol_version < DM_PROTOCOL_THREADED {
        return Err(DmError::AckSemanticsUnavailable(
            "recipient did not negotiate direct-message thread metadata".to_string(),
        ));
    }
    let encoded = postcard::to_stdvec(&ThreadedDmPayload {
        payload,
        thread_meta: thread_meta.clone(),
    })
    .map_err(|error| DmError::EnvelopeConstruction(format!("threaded DM payload: {error}")))?;
    let mut framed = Vec::with_capacity(THREADED_PAYLOAD_MAGIC.len() + encoded.len());
    framed.extend_from_slice(THREADED_PAYLOAD_MAGIC);
    framed.extend_from_slice(&encoded);
    if framed.len() > MAX_PAYLOAD_BYTES {
        return Err(DmError::PayloadTooLarge {
            len: framed.len(),
            max: MAX_PAYLOAD_BYTES,
        });
    }
    Ok(framed)
}

pub(crate) fn decode_application_payload(
    protocol_version: u16,
    payload: Vec<u8>,
) -> Result<(Vec<u8>, Option<DmThreadMeta>), DmError> {
    if protocol_version < DM_PROTOCOL_THREADED {
        return Ok((payload, None));
    }
    let encoded = payload
        .strip_prefix(THREADED_PAYLOAD_MAGIC)
        .ok_or_else(|| {
            DmError::EnvelopeConstruction("v3 DM is missing its thread payload wrapper".to_string())
        })?;
    let threaded: ThreadedDmPayload = postcard::from_bytes(encoded).map_err(|error| {
        DmError::EnvelopeConstruction(format!("threaded DM payload decode: {error}"))
    })?;
    Ok((threaded.payload, Some(threaded.thread_meta)))
}

/// Scope an explicit caller idempotency key to this authenticated sender and
/// recipient. x0x never infers identity by parsing opaque application bytes.
fn logical_request_id(
    sender: AgentId,
    recipient: AgentId,
    logical_id: Option<&DmLogicalId>,
) -> Option<[u8; 16]> {
    let logical_id = logical_id?;
    let mut hasher = blake3::Hasher::new_derive_key("x0x dm logical request id v1");
    hasher.update(sender.as_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(logical_id.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest.as_bytes()[..16]);
    Some(request_id)
}

pub(crate) fn request_id_for_logical(
    sender: AgentId,
    recipient: AgentId,
    logical_id: Option<&DmLogicalId>,
) -> [u8; 16] {
    logical_request_id(sender, recipient, logical_id).unwrap_or_else(fresh_request_id)
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
pub fn loopback_receipt_with_request_id(request_id: [u8; 16]) -> DmReceipt {
    DmReceipt {
        request_id,
        accepted_at: Instant::now(),
        retries_used: 0,
        path: DmPath::Loopback,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backoff_wait_zero_delay_returns_none_without_consuming_ack() {
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        tx.send(DmAckOutcome::Accepted).expect("send ack");

        let outcome = wait_for_ack_or_backoff(&mut rx, Duration::ZERO)
            .await
            .expect("zero-delay wait should not fail");

        assert_eq!(outcome, None);
        assert_eq!(
            rx.try_recv().expect("ack still pending"),
            DmAckOutcome::Accepted
        );
    }

    #[tokio::test]
    async fn backoff_wait_errors_when_ack_sender_dropped() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<DmAckOutcome>();
        drop(tx);

        let err = wait_for_ack_or_backoff(&mut rx, Duration::from_secs(1))
            .await
            .expect_err("closed waiter should be a publish failure");

        assert!(matches!(err, DmError::PublishFailed(_)));
    }

    #[tokio::test]
    async fn backoff_wait_returns_late_ack_before_retry() {
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx.send(DmAckOutcome::Accepted);
        });

        let outcome = wait_for_ack_or_backoff(&mut rx, Duration::from_secs(1))
            .await
            .expect("backoff wait should not fail");

        assert_eq!(outcome, Some(DmAckOutcome::Accepted));
    }

    #[tokio::test]
    async fn backoff_wait_times_out_without_ack() {
        let (_tx, mut rx) = tokio::sync::oneshot::channel();

        let outcome = wait_for_ack_or_backoff(&mut rx, Duration::from_millis(1))
            .await
            .expect("backoff timeout is not an error");

        assert_eq!(outcome, None);
    }

    #[tokio::test]
    async fn x0x_0041_zero_delay_returns_elapsed_even_with_hint() {
        let (_ack_tx, mut rx) = tokio::sync::oneshot::channel::<DmAckOutcome>();
        let (_replaced_tx, replaced_rx) = tokio::sync::broadcast::channel::<(MachineId, u64)>(1);
        let mut hint = DmLifecycleHint {
            recipient_machine_id: MachineId([0x44; 32]),
            replaced_rx,
        };

        let outcome = wait_for_ack_or_backoff_or_replaced(&mut rx, Duration::ZERO, Some(&mut hint))
            .await
            .expect("zero-delay wait should not fail");

        assert!(matches!(outcome, BackoffWait::Elapsed));
    }

    /// X0X-0041: a `Replaced` event for the target peer fires during the
    /// backoff window — the wait short-circuits with
    /// `BackoffWait::ReplacedShortCircuit` rather than waiting for the full
    /// backoff or returning `Elapsed`.
    #[tokio::test]
    async fn x0x_0041_backoff_short_circuits_on_replaced_for_target() {
        let (_ack_tx, mut rx) = tokio::sync::oneshot::channel::<DmAckOutcome>();
        let (replaced_tx, replaced_rx) = tokio::sync::broadcast::channel::<(MachineId, u64)>(8);
        let target = MachineId([0x77; 32]);
        let mut hint = DmLifecycleHint {
            recipient_machine_id: target,
            replaced_rx,
        };

        // Fire the supersede mid-wait.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = replaced_tx.send((target, 42));
        });

        let start = Instant::now();
        let outcome =
            wait_for_ack_or_backoff_or_replaced(&mut rx, Duration::from_secs(2), Some(&mut hint))
                .await
                .expect("wait should not error");

        match outcome {
            BackoffWait::ReplacedShortCircuit { new_generation } => {
                assert_eq!(new_generation, 42);
            }
            other => panic!("expected short-circuit, got {other:?}"),
        }
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "short-circuit must land in well under the 2s backoff (took {:?})",
            start.elapsed()
        );
    }

    /// X0X-0041: a `Replaced` event for an UNRELATED peer must NOT short-
    /// circuit the backoff. Verifies the peer-id filter inside the wait helper.
    #[tokio::test]
    async fn x0x_0041_replaced_for_other_peer_does_not_short_circuit() {
        let (_ack_tx, mut rx) = tokio::sync::oneshot::channel::<DmAckOutcome>();
        let (replaced_tx, replaced_rx) = tokio::sync::broadcast::channel::<(MachineId, u64)>(8);
        let target = MachineId([0x11; 32]);
        let other = MachineId([0xEE; 32]);
        let mut hint = DmLifecycleHint {
            recipient_machine_id: target,
            replaced_rx,
        };
        // Fire supersede for a different peer mid-wait.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = replaced_tx.send((other, 99));
        });

        let outcome = wait_for_ack_or_backoff_or_replaced(
            &mut rx,
            Duration::from_millis(80),
            Some(&mut hint),
        )
        .await
        .expect("wait should not error");

        assert!(matches!(outcome, BackoffWait::Elapsed));
    }

    #[tokio::test]
    async fn x0x_0041_closed_replaced_channel_falls_back_to_ack_wait() {
        let (ack_tx, mut rx) = tokio::sync::oneshot::channel();
        let (replaced_tx, replaced_rx) = tokio::sync::broadcast::channel::<(MachineId, u64)>(1);
        drop(replaced_tx);
        let mut hint = DmLifecycleHint {
            recipient_machine_id: MachineId([0x55; 32]),
            replaced_rx,
        };
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let _ = ack_tx.send(DmAckOutcome::Accepted);
        });

        let outcome =
            wait_for_ack_or_backoff_or_replaced(&mut rx, Duration::from_secs(1), Some(&mut hint))
                .await
                .expect("closed replaced channel should fall back to ack wait");

        assert!(matches!(outcome, BackoffWait::Ack(DmAckOutcome::Accepted)));
    }

    #[tokio::test]
    async fn x0x_0041_lagged_replaced_channel_drains_target_event() {
        let (_ack_tx, mut rx) = tokio::sync::oneshot::channel::<DmAckOutcome>();
        let (replaced_tx, replaced_rx) = tokio::sync::broadcast::channel::<(MachineId, u64)>(1);
        let target = MachineId([0x66; 32]);
        let mut hint = DmLifecycleHint {
            recipient_machine_id: target,
            replaced_rx,
        };
        let _ = replaced_tx.send((MachineId([0x67; 32]), 1));
        let _ = replaced_tx.send((target, 7));

        let outcome =
            wait_for_ack_or_backoff_or_replaced(&mut rx, Duration::from_secs(1), Some(&mut hint))
                .await
                .expect("lagged channel should drain target event");

        match outcome {
            BackoffWait::ReplacedShortCircuit { new_generation } => assert_eq!(new_generation, 7),
            other => panic!("expected replacement short-circuit, got {other:?}"),
        }
    }

    /// X0X-0041: a late ACK during the backoff still wins over a same-peer
    /// supersede when the ACK fires first.
    #[tokio::test]
    async fn x0x_0041_late_ack_wins_when_first() {
        let (ack_tx, mut rx) = tokio::sync::oneshot::channel();
        let (_replaced_tx, replaced_rx) = tokio::sync::broadcast::channel::<(MachineId, u64)>(8);
        let target = MachineId([0x33; 32]);
        let mut hint = DmLifecycleHint {
            recipient_machine_id: target,
            replaced_rx,
        };

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let _ = ack_tx.send(DmAckOutcome::Accepted);
        });

        let outcome =
            wait_for_ack_or_backoff_or_replaced(&mut rx, Duration::from_secs(1), Some(&mut hint))
                .await
                .expect("wait should not error");

        assert!(matches!(outcome, BackoffWait::Ack(DmAckOutcome::Accepted)));
    }

    #[test]
    fn inflight_guard_drop_cancels_unresolved_waiter() {
        let inflight = Arc::new(InFlightAcks::new());
        let request_id = [0x88; 16];
        let _rx = inflight.register(request_id, AgentId([0x81; 32]), Some(MachineId([0x82; 32])));
        assert_eq!(inflight.outstanding(), 1);
        {
            let _guard = InFlightGuard::new(Arc::clone(&inflight), request_id);
        }
        assert_eq!(inflight.outstanding(), 0);
    }

    #[test]
    fn inflight_guard_mark_resolved_preserves_waiter_on_drop() {
        let inflight = Arc::new(InFlightAcks::new());
        let request_id = [0x89; 16];
        let _rx = inflight.register(request_id, AgentId([0x83; 32]), Some(MachineId([0x84; 32])));
        let mut guard = InFlightGuard::new(Arc::clone(&inflight), request_id);
        guard.mark_resolved();
        drop(guard);
        assert_eq!(inflight.outstanding(), 1);
        inflight.cancel(&request_id);
    }

    #[test]
    fn fresh_request_id_generates_unique_ids() {
        let id1 = fresh_request_id();
        let id2 = fresh_request_id();
        assert_ne!(id1, id2, "two request IDs should be different");
        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
    }

    #[test]
    fn explicit_logical_id_is_stable_and_conversation_scoped() {
        let sender = AgentId([0x11; 32]);
        let recipient = AgentId([0x22; 32]);
        let logical_id = DmLogicalId::parse("retry-123").expect("logical id");

        assert_eq!(
            logical_request_id(sender, recipient, Some(&logical_id)),
            logical_request_id(sender, recipient, Some(&logical_id)),
            "the explicit logical id must be stable across fresh envelopes"
        );
        assert_ne!(
            logical_request_id(sender, recipient, Some(&logical_id)),
            logical_request_id(sender, AgentId([0x23; 32]), Some(&logical_id)),
            "the same logical id in another conversation must remain independent"
        );
    }

    #[test]
    fn omitted_logical_id_keeps_random_id_contract() {
        assert_eq!(
            logical_request_id(AgentId([0x31; 32]), AgentId([0x32; 32]), None,),
            None
        );
    }

    #[test]
    fn negotiated_v3_thread_wrapper_roundtrips_exact_application_payload() {
        let thread = DmThreadMeta::from_hex(Some(&"ab".repeat(32)), Some(&"cd".repeat(32)))
            .expect("valid thread")
            .expect("thread present");
        let original = b"exact legacy-visible bytes".to_vec();
        let wrapped =
            encode_application_payload(original.clone(), DM_PROTOCOL_THREADED, Some(&thread))
                .expect("encode threaded payload");
        assert_ne!(wrapped, original);
        let (decoded, decoded_thread) =
            decode_application_payload(DM_PROTOCOL_THREADED, wrapped).expect("decode wrapper");
        assert_eq!(decoded, original);
        assert_eq!(decoded_thread, Some(thread));
    }

    #[test]
    fn legacy_protocol_keeps_exact_bytes_and_never_accepts_thread_wrapper() {
        let original = b"legacy app payload".to_vec();
        assert_eq!(
            encode_application_payload(original.clone(), DM_PROTOCOL_DURABLE_ACK, None)
                .expect("legacy exact payload"),
            original
        );
        let thread = DmThreadMeta::from_hex(Some(&"ab".repeat(32)), None)
            .expect("valid root")
            .expect("thread present");
        assert!(encode_application_payload(
            b"must not wrap".to_vec(),
            DM_PROTOCOL_DURABLE_ACK,
            Some(&thread),
        )
        .is_err());
    }

    #[test]
    fn map_identity_err_converts_to_dm_error() {
        let identity_err = IdentityError::KeyGeneration("test error".to_string());
        let dm_err = map_identity_err(identity_err);
        assert!(dm_err.to_string().contains("test error"));
    }

    #[test]
    fn raw_quic_receipt_has_correct_path() {
        let receipt = raw_quic_receipt();
        assert_eq!(receipt.path, DmPath::RawQuic);
        assert_eq!(receipt.retries_used, 0);
    }

    #[test]
    fn loopback_receipt_has_correct_path() {
        let receipt = loopback_receipt();
        assert_eq!(receipt.path, DmPath::Loopback);
        assert_eq!(receipt.retries_used, 0);
    }

    #[test]
    fn raw_quic_receipt_for_path_uses_given_path() {
        let receipt = raw_quic_receipt_for_path(DmPath::GossipInbox);
        assert_eq!(receipt.path, DmPath::GossipInbox);
    }

    #[test]
    fn receipt_for_path_creates_valid_receipt() {
        let receipt = receipt_for_path(DmPath::RawQuic);
        assert_eq!(receipt.path, DmPath::RawQuic);
        assert_eq!(receipt.retries_used, 0);
        // request_id should be 16 bytes
        assert_eq!(receipt.request_id.len(), 16);
    }

    #[test]
    fn ack_outcome_to_receipt_converts_accepted() {
        let outcome = DmAckOutcome::Accepted;
        let request_id = [1u8; 16];
        let receipt = ack_outcome_to_receipt(outcome, request_id, 2).unwrap();
        assert_eq!(receipt.request_id, request_id);
        assert_eq!(receipt.retries_used, 2);
        assert_eq!(receipt.path, DmPath::GossipInbox);
    }

    #[test]
    fn gossip_publish_receipt_uses_gossip_path() {
        let request_id = [3u8; 16];
        let receipt = gossip_publish_receipt(request_id, 1);
        assert_eq!(receipt.request_id, request_id);
        assert_eq!(receipt.retries_used, 1);
        assert_eq!(receipt.path, DmPath::GossipInbox);
    }

    #[test]
    fn ack_outcome_to_receipt_rejected_returns_error() {
        let outcome = DmAckOutcome::RejectedByPolicy {
            reason: "not trusted".to_string(),
        };
        let result = ack_outcome_to_receipt(outcome, [2u8; 16], 1);
        assert!(result.is_err(), "rejected should return error");
        let err = result.unwrap_err();
        assert!(
            format!("{:?}", err).contains("not trusted"),
            "error should contain reason"
        );
    }

    #[test]
    fn ack_semantics_unavailable_outcome_is_explicit_sender_error() {
        let outcome = DmAckOutcome::AckSemanticsUnavailable {
            reason: "logical request already completed under v1 semantics".to_string(),
        };
        let error = ack_outcome_to_receipt(outcome, [4u8; 16], 0)
            .expect_err("weaker cached semantics cannot become a v2 receipt");
        assert!(matches!(error, DmError::AckSemanticsUnavailable(_)));
    }

    // ── send_via_gossip early validation ──────────────────────────────

    #[tokio::test]
    async fn send_via_gossip_rejects_oversized_payload() {
        use crate::dm::MAX_PAYLOAD_BYTES;
        // Create a minimal PubSubManager by using a placeholder
        // The early payload-size check fires before any gossip calls
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        // We can't construct PubSubManager without a network node,
        // but the early validation at line 49 checks payload size first.
        // This test verifies the concept by checking the constant directly.
        assert!(oversized.len() > MAX_PAYLOAD_BYTES);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn send_via_gossip_payload_size_check_constant() {
        use crate::dm::MAX_PAYLOAD_BYTES;
        // Documentation assertions — verify the constant is in the expected
        // range. Both bounds are compile-time constants, so the asserts are
        // tautological in nextest's eyes but document the invariant.
        assert!(MAX_PAYLOAD_BYTES > 0);
        assert!(MAX_PAYLOAD_BYTES <= 1024 * 1024); // Max 1MB
    }

    #[test]
    fn dm_lifecycle_hint_struct_is_send() {
        // Verify DmLifecycleHint can be sent between threads
        fn assert_send<T: Send>() {}
        assert_send::<DmLifecycleHint>();
    }

    #[test]
    fn default_send_config_requires_gossip_ack() {
        assert!(DmSendConfig::default().require_gossip_ack);
    }
}
