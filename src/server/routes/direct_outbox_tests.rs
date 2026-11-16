#![cfg(test)]
//! #1109 slice S1 unit tests for the durable direct-send outbox worker.
//! Inert: local files and a scripted transport, no network (the
//! real-receiver test drives the in-process durable inbox pipeline).

use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const NOW: u64 = 1_800_000_000_000;

fn at(wall_ms: u64, mono_ms: u64) -> DirectSendNow {
    DirectSendNow { wall_ms, mono_ms }
}

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
        next_retry_at_ms: 0,
        last_error: None,
        options: DirectSendOptions::default(),
    }
}

fn no_record() -> LedgerReceipt {
    LedgerReceipt {
        status: DmReceiptStatus::Unknown,
        digest: None,
    }
}

fn unknown(_: &[u8; 16]) -> LedgerReceipt {
    no_record()
}

fn digest_of(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).into()
}

/// A transport that returns scripted results (then `Ok`) and counts calls.
#[derive(Default)]
struct ScriptedTransport {
    results: std::sync::Mutex<VecDeque<Result<(), DmError>>>,
    calls: AtomicUsize,
    blocked: AtomicBool,
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
    fn recipient_blocked(&self, _recipient: AgentId) -> TransportFuture<'_, bool> {
        let blocked = self.blocked.load(Ordering::SeqCst);
        Box::pin(async move { blocked })
    }

    fn send(
        &self,
        _recipient: AgentId,
        _payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> TransportFuture<'_, Result<(), DmError>> {
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

async fn status(
    outbox: &DirectSendOutbox,
    recipient: AgentId,
    rid: &[u8; 16],
) -> DirectSendReceipt {
    outbox.receipt(&recipient, rid, no_record()).await
}

/// WHY: a late ACK of an earlier attempt for the same bytes already proves
/// delivery, so the worker must clear the obligation without a resend.
#[tokio::test]
async fn issue1109_late_ack_settles_delivered_with_zero_sends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-1", peer);
    assert_eq!(
        outbox
            .enqueue(obligation("order-1", peer, NOW + 60_000), no_record())
            .await,
        EnqueueOutcome::Queued
    );
    let transport = ScriptedTransport::default();
    let late = |id: &[u8; 16]| LedgerReceipt {
        status: if *id == rid {
            DmReceiptStatus::DeliveredLate
        } else {
            DmReceiptStatus::Unknown
        },
        digest: Some(digest_of(b"hello")),
    };
    outbox.step(at(NOW, 0), &late, &transport).await;
    assert_eq!(transport.calls(), 0, "a late ACK must not cause a resend");
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "delivered");
}

/// WHY: a receipt for other bytes under the same logical id proves nothing
/// about these bytes: the worker must not settle them as delivered.
#[tokio::test]
async fn issue1109_receipt_for_other_bytes_does_not_settle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    outbox
        .enqueue(obligation("order-1b", peer, NOW + 60_000), no_record())
        .await;
    let transport = ScriptedTransport::with(vec![Err(DmError::IdempotencyConflict(
        "bound to other bytes".to_string(),
    ))]);
    let other = |_: &[u8; 16]| LedgerReceipt {
        status: DmReceiptStatus::Delivered,
        digest: Some(digest_of(b"other bytes")),
    };
    outbox.step(at(NOW, 0), &other, &transport).await;
    assert_eq!(transport.calls(), 1, "the bytes are sent, not settled");
    let rid = request_id_for("order-1b", peer);
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.error.as_deref(), Some("idempotency_conflict"));
}

/// WHY: queuing other bytes under a key whose earlier bytes were delivered
/// must be refused, not stored and later reported delivered.
#[tokio::test]
async fn issue1109_enqueue_refuses_other_bytes_than_a_delivered_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let delivered_a = LedgerReceipt {
        status: DmReceiptStatus::Delivered,
        digest: Some(digest_of(b"payload A")),
    };
    let mut b = obligation("order-1c", peer, NOW + 60_000);
    b.payload = b"payload B".to_vec();
    assert_eq!(
        outbox.enqueue(b, delivered_a).await,
        EnqueueOutcome::Conflict
    );
    assert!(outbox.snapshot().await.is_empty());

    // The worker's own delivery record binds the bytes the same way.
    let mut a = obligation("order-1c", peer, NOW + 60_000);
    a.payload = b"payload A".to_vec();
    assert_eq!(
        outbox.enqueue(a.clone(), no_record()).await,
        EnqueueOutcome::Queued
    );
    outbox
        .step(at(NOW, 0), &unknown, &ScriptedTransport::default())
        .await;
    let mut b = a.clone();
    b.payload = b"payload B".to_vec();
    assert_eq!(
        outbox.enqueue(b, no_record()).await,
        EnqueueOutcome::Conflict
    );
    // The same bytes again are accepted (the recipient re-ACKs them).
    assert_eq!(outbox.enqueue(a, no_record()).await, EnqueueOutcome::Queued);
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
        .enqueue(obligation("order-2", peer, NOW + 60_000), no_record())
        .await;
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");
    let transport = ScriptedTransport::with(vec![Err(DmError::AckSemanticsUnavailable(
        "no v2 advert".to_string(),
    ))]);

    outbox.step(at(NOW, 100), &unknown, &transport).await;
    assert_eq!(transport.calls(), 1);
    let held = outbox.snapshot().await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].retry_count, 1);
    assert_eq!(held[0].next_retry_at_ms, 100 + 2_000);
    assert_eq!(
        held[0].last_error.as_deref(),
        Some("recipient_ack_semantics_unavailable")
    );
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");

    // Not due yet: no send.
    outbox
        .step(at(NOW + 1_000, 1_100), &unknown, &transport)
        .await;
    assert_eq!(transport.calls(), 1);

    outbox
        .step(at(NOW + 2_000, 2_100), &unknown, &transport)
        .await;
    assert_eq!(transport.calls(), 2);
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "delivered");
    outbox
        .step(at(NOW + 10_000, 10_100), &unknown, &transport)
        .await;
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
    outbox
        .enqueue(obligation("order-3", peer, NOW + 500), no_record())
        .await;
    let transport = ScriptedTransport::default();
    outbox.step(at(NOW + 500, 0), &unknown, &transport).await;
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
    outbox
        .enqueue(obligation("order-3b", peer, NOW + 1_000), no_record())
        .await;
    let transport = ScriptedTransport::with(vec![Err(DmError::PeerLikelyOffline {
        phi: 9.0,
        last_seen_ms_ago: None,
    })]);
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    // The next retry is at mono 2_000; the deadline comes first.
    outbox
        .step(at(NOW + 1_000, 1_000), &unknown, &transport)
        .await;
    assert_eq!(transport.calls(), 1);
    assert!(outbox.snapshot().await.is_empty());
}

/// WHY: the time left caps the attempt budget, so no attempt runs past
/// the caller's deadline.
#[tokio::test]
async fn issue1109_attempt_budget_never_exceeds_the_time_left() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    outbox
        .enqueue(obligation("order-3c", agent(2), NOW + 3_000), no_record())
        .await;
    let transport = ScriptedTransport::default();
    outbox.step(at(NOW, 0), &unknown, &transport).await;
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
        .enqueue(obligation("order-4", peer, NOW + 60_000), no_record())
        .await;
    let transport = ScriptedTransport::with(vec![Err(DmError::RecipientRejected {
        reason: "blocked".to_string(),
    })]);
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 1);
    assert!(outbox.snapshot().await.is_empty());
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.error.as_deref(), Some("recipient_rejected"));
}

/// WHY: a contact blocked after accept must not get the message: the
/// worker checks before each attempt and ends the obligation as failed.
#[tokio::test]
async fn issue1109_blocked_recipient_fails_before_an_attempt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-4b", peer);
    outbox
        .enqueue(obligation("order-4b", peer, NOW + 60_000), no_record())
        .await;
    let transport = ScriptedTransport::default();
    transport.blocked.store(true, Ordering::SeqCst);
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 0, "a blocked contact is never sent to");
    assert!(outbox.snapshot().await.is_empty());
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.error.as_deref(), Some(RECIPIENT_BLOCKED));
}

/// WHY: blocking a contact removes all of its queued sends at once, and
/// leaves other recipients' sends alone.
#[tokio::test]
async fn issue1109_drop_recipient_removes_only_that_contacts_sends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let (blocked, other) = (agent(2), agent(3));
    for id in ["b-1", "b-2"] {
        outbox
            .enqueue(obligation(id, blocked, NOW + 60_000), no_record())
            .await;
    }
    outbox
        .enqueue(obligation("o-1", other, NOW + 60_000), no_record())
        .await;
    assert_eq!(outbox.drop_recipient(&blocked, RECIPIENT_BLOCKED).await, 2);
    let held = outbox.snapshot().await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].recipient, hex::encode(other.as_bytes()));
    let receipt = status(&outbox, blocked, &request_id_for("b-1", blocked)).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.error.as_deref(), Some(RECIPIENT_BLOCKED));
}

/// WHY: a cancel removes the held send and its receipt reads `cancelled`;
/// a second cancel finds nothing.
#[tokio::test]
async fn issue1109_cancel_removes_the_held_send() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-c", peer);
    outbox
        .enqueue(obligation("order-c", peer, NOW + 60_000), no_record())
        .await;
    assert_eq!(outbox.cancel(&peer, &rid).await, CancelOutcome::Cancelled);
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "cancelled");
    assert_eq!(outbox.cancel(&peer, &rid).await, CancelOutcome::NotHeld);
    let transport = ScriptedTransport::default();
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 0);
}

/// WHY: a retryable error keeps the obligation and walks the 2, 5, 10,
/// 30, 60 s schedule (the last offset repeats).
#[tokio::test]
async fn issue1109_retryable_error_keeps_and_reschedules() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    outbox
        .enqueue(obligation("order-5", peer, NOW + 3_600_000), no_record())
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
    let mut mono = 0;
    for expected_offset in [2_000, 5_000, 10_000, 30_000, 60_000, 60_000] {
        outbox
            .step(at(NOW + mono, mono), &unknown, &transport)
            .await;
        let held = outbox.snapshot().await;
        assert_eq!(held.len(), 1, "a retryable error keeps the obligation");
        assert_eq!(held[0].last_error.as_deref(), Some("timeout"));
        assert_eq!(held[0].next_retry_at_ms, mono + expected_offset);
        mono = held[0].next_retry_at_ms;
    }
    assert_eq!(transport.calls(), 6);
}

/// WHY: a backward wall-clock step must not stall retries: the schedule
/// runs on the monotonic clock, the wall clock only decides the deadline.
#[tokio::test]
async fn issue1109_backward_wall_clock_step_does_not_stall_retries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    outbox
        .enqueue(obligation("order-5b", agent(2), NOW + 60_000), no_record())
        .await;
    let transport = ScriptedTransport::with(vec![Err(DmError::PeerLikelyOffline {
        phi: 9.0,
        last_seen_ms_ago: None,
    })]);
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    // The wall clock jumps back an hour; the monotonic clock moves on 2 s.
    outbox
        .step(at(NOW - 3_600_000, 2_000), &unknown, &transport)
        .await;
    assert_eq!(transport.calls(), 2, "the retry ran on schedule");
    assert!(outbox.snapshot().await.is_empty());
}

/// WHY: an accepted obligation must survive a daemon restart, read
/// `queued` after the sidecar is loaded, and be due at once (the old
/// schedule belongs to the previous process's clock).
#[tokio::test]
async fn issue1109_obligations_survive_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let rid = request_id_for("order-6", peer);
    let written = obligation("order-6", peer, NOW + 60_000);
    {
        let before = outbox_in(&dir);
        assert_eq!(
            before.enqueue(written.clone(), no_record()).await,
            EnqueueOutcome::Queued
        );
        let transport = ScriptedTransport::with(vec![Err(DmError::PeerLikelyOffline {
            phi: 9.0,
            last_seen_ms_ago: None,
        })]);
        before.step(at(NOW, 50_000), &unknown, &transport).await;
    }
    let after = outbox_in(&dir);
    assert!(after.snapshot().await.is_empty());
    after.load(NOW).await.expect("sidecar loads");
    let held = after.snapshot().await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].payload, written.payload);
    assert_eq!(held[0].next_retry_at_ms, 0, "due at once after a restart");
    assert_eq!(status(&after, peer, &rid).await.status, "queued");
    let transport = ScriptedTransport::default();
    after.step(at(NOW + 1, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 1);
}

/// WHY: the sidecar holds payloads unsealed, so it must be owner-only.
#[cfg(unix)]
#[tokio::test]
async fn issue1109_sidecar_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    outbox
        .enqueue(obligation("order-6b", agent(2), NOW + 60_000), no_record())
        .await;
    let mode = std::fs::metadata(dir.path().join(DIRECT_SEND_OUTBOX_FILE))
        .expect("sidecar written")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// WHY: a repeat of a held send stores nothing new, and the same key with
/// other bytes is a conflict, not a second obligation.
#[tokio::test]
async fn issue1109_enqueue_is_idempotent_and_refuses_other_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let first = obligation("order-7", peer, NOW + 60_000);
    assert_eq!(
        outbox.enqueue(first.clone(), no_record()).await,
        EnqueueOutcome::Queued
    );
    let mut repeat = first.clone();
    repeat.deliver_until_ms = NOW + 90_000;
    assert_eq!(
        outbox.enqueue(repeat, no_record()).await,
        EnqueueOutcome::AlreadyQueued {
            deliver_until_ms: NOW + 60_000
        }
    );
    let mut other = first;
    other.payload = b"other".to_vec();
    assert_eq!(
        outbox.enqueue(other, no_record()).await,
        EnqueueOutcome::Conflict
    );
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
            .enqueue(
                obligation(&format!("cap-{i}"), peer, NOW + 60_000),
                no_record(),
            )
            .await;
        assert_eq!(queued, EnqueueOutcome::Queued);
    }
    assert_eq!(
        outbox
            .enqueue(obligation("cap-over", peer, NOW + 60_000), no_record())
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
        ledger.record([1; 16], DirectSendTerminal::Expired, [0; 32], now);
    }
    for i in 0..(RECEIPT_LEDGER_CAP + 10) {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        ledger.record(id, DirectSendTerminal::Delivered, [0; 32], now);
    }
    assert!(ledger.order.len() <= RECEIPT_LEDGER_CAP);
    assert!(ledger.entries.len() <= RECEIPT_LEDGER_CAP);
}

/// A transport that hands each attempt to the real durable receiver path
/// and loses the first ACK (the attempt reports a timeout).
struct ReceiverTransport {
    receiver: tokio::sync::Mutex<crate::dm_inbox::tests::DurableReceiverFixture>,
    calls: AtomicUsize,
}

impl DirectSendTransport for ReceiverTransport {
    fn recipient_blocked(&self, _recipient: AgentId) -> TransportFuture<'_, bool> {
        Box::pin(async { false })
    }

    fn send(
        &self,
        _recipient: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> TransportFuture<'_, Result<(), DmError>> {
        Box::pin(async move {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
            let Some(request_id) = config.logical_request_id else {
                return Err(DmError::PublishFailed("no logical id".to_string()));
            };
            let acked = self
                .receiver
                .lock()
                .await
                .deliver(request_id, &payload)
                .await;
            if attempt == 0 || !acked {
                // The receiver committed and ACKed, but the ACK was lost.
                return Err(DmError::Timeout {
                    retries: 0,
                    elapsed: budget,
                });
            }
            Ok(())
        })
    }
}

/// WHY: the retry after a lost ACK must reach the real durable receiver
/// as the same logical request: it is re-ACKed and dispatched only once.
#[tokio::test]
async fn issue1109_retry_after_a_lost_ack_is_delivered_once_at_a_real_receiver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-8", peer);
    outbox
        .enqueue(obligation("order-8", peer, NOW + 60_000), no_record())
        .await;
    let transport = ReceiverTransport {
        receiver: tokio::sync::Mutex::new(
            crate::dm_inbox::tests::DurableReceiverFixture::new().await,
        ),
        calls: AtomicUsize::new(0),
    };
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");
    outbox
        .step(at(NOW + 2_000, 2_000), &unknown, &transport)
        .await;
    assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "delivered");
    let dispatched = transport.receiver.lock().await.drain_dispatched();
    assert_eq!(
        dispatched,
        vec![b"hello".to_vec()],
        "dispatched exactly once"
    );
}
