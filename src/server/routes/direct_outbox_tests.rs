#![cfg(test)]
//! #1109 slice S1 unit tests for the durable direct-send outbox worker.
//! Inert: local files and a scripted transport, no network.

use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

const NOW: u64 = 1_800_000_000_000;

fn agent(byte: u8) -> AgentId {
    AgentId([byte; 32])
}

fn request_id_for(logical_id: &str, recipient: AgentId) -> [u8; 16] {
    crate::dm::DmLogicalId::parse(logical_id)
        .expect("valid logical id")
        .request_id(agent(1), recipient)
}

fn obligation(logical_id: &str, recipient: AgentId, deliver_until_ms: u64) -> DirectSendObligation {
    DirectSendObligation {
        recipient: hex::encode(recipient.as_bytes()),
        logical_id: logical_id.to_string(),
        request_id: hex::encode(request_id_for(logical_id, recipient)),
        payload: b"hello".to_vec(),
        deliver_until_ms,
        first_seen_ms: NOW,
        retry_count: 0,
        next_retry_at_ms: NOW,
        last_error: None,
        options: DirectSendOptions::default(),
    }
}

/// A transport that returns scripted results (then `Ok`) and counts calls.
#[derive(Default)]
struct ScriptedTransport {
    results: std::sync::Mutex<VecDeque<Result<(), DmError>>>,
    calls: AtomicUsize,
    configs: std::sync::Mutex<Vec<(DmSendConfig, Duration)>>,
}

impl ScriptedTransport {
    fn with(results: Vec<Result<(), DmError>>) -> Self {
        Self {
            results: std::sync::Mutex::new(results.into()),
            ..Self::default()
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl DirectSendTransport for ScriptedTransport {
    fn send<'a>(
        &'a self,
        _recipient: AgentId,
        _payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), DmError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.configs
            .lock()
            .expect("configs lock")
            .push((config, budget));
        let next = self
            .results
            .lock()
            .expect("results lock")
            .pop_front()
            .unwrap_or(Ok(()));
        Box::pin(async move { next })
    }
}

fn outbox_in(dir: &tempfile::TempDir) -> DirectSendOutbox {
    DirectSendOutbox::new(dir.path().join(DIRECT_SEND_OUTBOX_FILE))
}

fn unknown(_: &[u8; 16]) -> DmReceiptStatus {
    DmReceiptStatus::Unknown
}

async fn status(
    outbox: &DirectSendOutbox,
    recipient: AgentId,
    rid: &[u8; 16],
) -> DirectSendReceipt {
    outbox
        .receipt(&recipient, rid, DmReceiptStatus::Unknown)
        .await
}

/// WHY: a late ACK of an earlier attempt already proves delivery, so the
/// worker must clear the obligation without sending the message again.
#[tokio::test]
async fn issue1109_late_ack_settles_delivered_with_zero_sends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-1", peer);
    assert_eq!(
        outbox
            .enqueue(obligation("order-1", peer, NOW + 60_000))
            .await,
        EnqueueOutcome::Queued
    );
    let transport = ScriptedTransport::default();
    let late = |id: &[u8; 16]| {
        if *id == rid {
            DmReceiptStatus::DeliveredLate
        } else {
            DmReceiptStatus::Unknown
        }
    };
    outbox.step(NOW, &late, &transport).await;
    assert_eq!(transport.calls(), 0, "a late ACK must not cause a resend");
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "delivered");
}

/// WHY: a cold recipient (no v2 advert yet) must be held and retried, not
/// refused, and delivered exactly once when it becomes reachable.
#[tokio::test]
async fn issue1109_cold_recipient_is_held_then_delivered_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-2", peer);
    outbox
        .enqueue(obligation("order-2", peer, NOW + 60_000))
        .await;
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");
    let transport = ScriptedTransport::with(vec![Err(DmError::AckSemanticsUnavailable(
        "no v2 advert".to_string(),
    ))]);

    outbox.step(NOW, &unknown, &transport).await;
    assert_eq!(transport.calls(), 1);
    let held = outbox.snapshot().await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].retry_count, 1);
    assert_eq!(held[0].next_retry_at_ms, NOW + 2_000);
    assert_eq!(
        held[0].last_error.as_deref(),
        Some("recipient_ack_semantics_unavailable")
    );
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");

    // Not due yet: no send.
    outbox.step(NOW + 1_000, &unknown, &transport).await;
    assert_eq!(transport.calls(), 1);

    outbox.step(NOW + 2_000, &unknown, &transport).await;
    assert_eq!(transport.calls(), 2);
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "delivered");
    outbox.step(NOW + 10_000, &unknown, &transport).await;
    assert_eq!(
        transport.calls(),
        2,
        "a delivered obligation is never sent again"
    );

    let configs = transport.configs.lock().expect("configs lock");
    for (config, budget) in configs.iter() {
        assert!(config.require_durable_app_ack);
        assert_eq!(config.logical_request_id, Some(rid));
        assert!(*budget <= Duration::from_secs(10));
    }
}

/// WHY: a deadline that has passed ends the obligation as `expired`
/// without one more send.
#[tokio::test]
async fn issue1109_past_deadline_drops_as_expired_without_a_send() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-3", peer);
    outbox.enqueue(obligation("order-3", peer, NOW + 500)).await;
    let transport = ScriptedTransport::default();
    outbox.step(NOW + 500, &unknown, &transport).await;
    assert_eq!(transport.calls(), 0);
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "expired");
}

/// WHY: the deadline makes an obligation due even when its next retry is
/// later, so `queued` never outlives the deadline by a retry interval.
#[tokio::test]
async fn issue1109_deadline_is_due_before_a_later_retry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let mut late_retry = obligation("order-3b", peer, NOW + 1_000);
    late_retry.next_retry_at_ms = NOW + 60_000;
    outbox.enqueue(late_retry).await;
    let transport = ScriptedTransport::default();
    outbox.step(NOW + 1_000, &unknown, &transport).await;
    assert_eq!(transport.calls(), 0);
    assert!(outbox.snapshot().await.is_empty());
}

/// WHY: the time left caps the attempt budget, so no attempt runs past
/// the caller's deadline.
#[tokio::test]
async fn issue1109_attempt_budget_never_exceeds_the_time_left() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    outbox
        .enqueue(obligation("order-3c", agent(2), NOW + 3_000))
        .await;
    let transport = ScriptedTransport::default();
    outbox.step(NOW, &unknown, &transport).await;
    let configs = transport.configs.lock().expect("configs lock");
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].1, Duration::from_millis(3_000));
    assert_eq!(
        configs[0].0.timeout_per_attempt,
        Duration::from_millis(3_000)
    );
    assert_eq!(configs[0].0.max_retries, 0);
}

/// WHY: an error a retry cannot repair ends the obligation as `failed`
/// with the route's error code, instead of retrying until the deadline.
#[tokio::test]
async fn issue1109_terminal_error_drops_as_failed_with_its_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-4", peer);
    outbox
        .enqueue(obligation("order-4", peer, NOW + 60_000))
        .await;
    let transport = ScriptedTransport::with(vec![Err(DmError::RecipientRejected {
        reason: "blocked".to_string(),
    })]);
    outbox.step(NOW, &unknown, &transport).await;
    assert_eq!(transport.calls(), 1);
    assert!(outbox.snapshot().await.is_empty());
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.error.as_deref(), Some("recipient_rejected"));
}

/// WHY: a retryable error keeps the obligation and walks the 2, 5, 10,
/// 30, 60 s schedule (the last offset repeats).
#[tokio::test]
async fn issue1109_retryable_error_keeps_and_reschedules() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    outbox
        .enqueue(obligation("order-5", peer, NOW + 3_600_000))
        .await;
    let timeouts = (0..7)
        .map(|_| {
            Err(DmError::Timeout {
                retries: 0,
                elapsed: Duration::from_secs(1),
            })
        })
        .collect();
    let transport = ScriptedTransport::with(timeouts);
    let mut now = NOW;
    for expected_offset in [2_000, 5_000, 10_000, 30_000, 60_000, 60_000] {
        outbox.step(now, &unknown, &transport).await;
        let held = outbox.snapshot().await;
        assert_eq!(held.len(), 1, "a retryable error keeps the obligation");
        assert_eq!(held[0].last_error.as_deref(), Some("timeout"));
        assert_eq!(held[0].next_retry_at_ms, now + expected_offset);
        now = held[0].next_retry_at_ms;
    }
    assert_eq!(transport.calls(), 6);
}

/// WHY: an accepted obligation must survive a daemon restart and still
/// read `queued` after the sidecar is loaded again.
#[tokio::test]
async fn issue1109_obligations_survive_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let rid = request_id_for("order-6", peer);
    let written = obligation("order-6", peer, NOW + 60_000);
    {
        let before = outbox_in(&dir);
        assert_eq!(
            before.enqueue(written.clone()).await,
            EnqueueOutcome::Queued
        );
    }
    let after = outbox_in(&dir);
    assert!(after.snapshot().await.is_empty());
    after.load(NOW).await.expect("sidecar loads");
    assert_eq!(after.snapshot().await, vec![written]);
    assert_eq!(status(&after, peer, &rid).await.status, "queued");
}

/// WHY: a repeat of a held send stores nothing new, and the same key with
/// other bytes is a conflict, not a second obligation.
#[tokio::test]
async fn issue1109_enqueue_is_idempotent_and_refuses_other_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let first = obligation("order-7", peer, NOW + 60_000);
    assert_eq!(outbox.enqueue(first.clone()).await, EnqueueOutcome::Queued);
    let mut repeat = first.clone();
    repeat.deliver_until_ms = NOW + 90_000;
    assert_eq!(
        outbox.enqueue(repeat).await,
        EnqueueOutcome::AlreadyQueued {
            deliver_until_ms: NOW + 60_000
        }
    );
    let mut other = first;
    other.payload = b"other".to_vec();
    assert_eq!(outbox.enqueue(other).await, EnqueueOutcome::Conflict);
    assert_eq!(outbox.snapshot().await.len(), 1);
}

/// WHY: a full recipient is refused, so an accepted obligation is never
/// evicted by a newer one.
#[tokio::test]
async fn issue1109_full_recipient_is_refused_not_evicted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    for i in 0..DIRECT_SEND_OUTBOX_CAPS.per_partition {
        let queued = outbox
            .enqueue(obligation(&format!("cap-{i}"), peer, NOW + 60_000))
            .await;
        assert_eq!(queued, EnqueueOutcome::Queued);
    }
    assert_eq!(
        outbox
            .enqueue(obligation("cap-over", peer, NOW + 60_000))
            .await,
        EnqueueOutcome::Full
    );
    assert_eq!(
        outbox.snapshot().await.len(),
        DIRECT_SEND_OUTBOX_CAPS.per_partition
    );
}

/// WHY: the terminal ledger's order queue must stay bounded even when one
/// id is rewritten many times (greptile's finding on #1901).
#[test]
fn issue1109_terminal_ledger_order_queue_stays_bounded() {
    let mut ledger = TerminalLedger::default();
    let now = Instant::now();
    for _ in 0..(RECEIPT_LEDGER_CAP * 2) {
        ledger.record([1; 16], DirectSendTerminal::Expired, now);
    }
    for i in 0..(RECEIPT_LEDGER_CAP + 10) {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        ledger.record(id, DirectSendTerminal::Delivered, now);
    }
    assert!(ledger.order.len() <= RECEIPT_LEDGER_CAP);
    assert!(ledger.entries.len() <= RECEIPT_LEDGER_CAP);
}
