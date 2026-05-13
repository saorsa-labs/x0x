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
    lifecycle_hint: Option<DmLifecycleHint>,
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

    // X0X-0041: split the lifecycle hint into the per-peer match key and the
    // mutable receiver so we can both filter events and short-circuit the
    // backoff on a `Replaced` for the target peer.
    let mut lifecycle_hint = lifecycle_hint;

    let start = Instant::now();
    for attempt in 0..=config.max_retries {
        if attempt > 0 {
            match rx.try_recv() {
                Ok(outcome) => {
                    tracing::info!(
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
                return ack_outcome_to_receipt(outcome, request_id, attempt);
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
                            tracing::info!(
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
                            tracing::info!(
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
        tracing::info!(
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
    match outcome {
        DmAckOutcome::Accepted => Ok(DmReceipt {
            request_id,
            accepted_at: Instant::now(),
            retries_used,
            path: DmPath::GossipInbox,
        }),
        DmAckOutcome::RejectedByPolicy { reason } => Err(DmError::RecipientRejected { reason }),
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fresh_request_id_generates_unique_ids() {
        let id1 = fresh_request_id();
        let id2 = fresh_request_id();
        assert_ne!(id1, id2, "two request IDs should be different");
        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
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
}
