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
        machine: None,
    }
}

/// The machine every test attempt to a peer is pinned to (#2007).
fn peer_machine() -> MachineId {
    MachineId([0xa2; 32])
}

/// A ledger that names the machine an attempt was pinned to, as the DM
/// receipt ledger does after a durable send gave up (#2007).
fn pinned(_: &[u8; 16]) -> LedgerReceipt {
    LedgerReceipt {
        status: DmReceiptStatus::Pending,
        digest: None,
        machine: Some(peer_machine()),
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
        machine: None,
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
        machine: None,
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
        machine: None,
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
    let now = NOW;
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

/// A transport whose single attempt waits at a gate, so a test can act
/// while the attempt is in flight.
struct GatedTransport {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    result: std::sync::Mutex<Option<Result<(), DmError>>>,
    calls: AtomicUsize,
}

impl GatedTransport {
    fn new(result: Result<(), DmError>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            result: std::sync::Mutex::new(Some(result)),
            calls: AtomicUsize::new(0),
        })
    }
}

impl DirectSendTransport for GatedTransport {
    fn recipient_blocked(&self, _recipient: AgentId) -> TransportFuture<'_, bool> {
        Box::pin(async { false })
    }

    fn send(
        &self,
        _recipient: AgentId,
        _payload: Vec<u8>,
        _config: DmSendConfig,
        _budget: Duration,
    ) -> TransportFuture<'_, Result<(), DmError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            self.release.notified().await;
            self.result
                .lock()
                .expect("result lock")
                .take()
                .unwrap_or(Ok(()))
        })
    }
}

fn spawn_step(
    outbox: &std::sync::Arc<DirectSendOutbox>,
    transport: &std::sync::Arc<GatedTransport>,
    now: DirectSendNow,
) -> tokio::task::JoinHandle<()> {
    let outbox = std::sync::Arc::clone(outbox);
    let transport = std::sync::Arc::clone(transport);
    tokio::spawn(async move { outbox.step(now, &unknown, transport.as_ref()).await })
}

/// WHY: a cancel cannot recall an attempt in flight, so it must say so
/// (409) rather than answer `cancelled`; other bytes under the same key
/// are refused while the attempt runs, and its outcome is then recorded
/// against the bytes it sent.
#[tokio::test]
async fn issue1109_cancel_and_requeue_during_an_attempt_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = std::sync::Arc::new(outbox_in(&dir));
    let peer = agent(2);
    let rid = request_id_for("order-f", peer);
    let a = obligation("order-f", peer, NOW + 60_000);
    outbox.enqueue(a.clone(), no_record()).await;
    let transport = GatedTransport::new(Ok(()));
    let step = spawn_step(&outbox, &transport, at(NOW, 0));
    transport.started.notified().await;

    assert_eq!(outbox.cancel(&peer, &rid).await, CancelOutcome::InFlight);
    let mut b = a.clone();
    b.payload = b"payload B".to_vec();
    assert_eq!(
        outbox.enqueue(b.clone(), no_record()).await,
        EnqueueOutcome::InFlight
    );

    transport.release.notify_one();
    step.await.expect("step task");
    assert!(outbox.snapshot().await.is_empty());
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "delivered");
    assert_eq!(receipt.payload_digest, Some(digest_of(b"hello")));
    // A was delivered under this key: B can never be.
    assert_eq!(
        outbox.enqueue(b, no_record()).await,
        EnqueueOutcome::Conflict
    );
}

/// WHY: blocking a contact during an attempt records that attempt's
/// outcome and never sends again; other bytes cannot then be queued under
/// the same key, so the old attempt never reports them delivered.
#[tokio::test]
async fn issue1109_block_during_an_attempt_records_it_and_never_resends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = std::sync::Arc::new(outbox_in(&dir));
    let peer = agent(2);
    let rid = request_id_for("order-g", peer);
    let a = obligation("order-g", peer, NOW + 60_000);
    outbox.enqueue(a.clone(), no_record()).await;
    let transport = GatedTransport::new(Err(DmError::Timeout {
        retries: 0,
        elapsed: Duration::from_secs(1),
    }));
    let step = spawn_step(&outbox, &transport, at(NOW, 0));
    transport.started.notified().await;

    assert_eq!(outbox.drop_recipient(&peer, RECIPIENT_BLOCKED).await, 1);
    assert_eq!(
        outbox.snapshot().await.len(),
        1,
        "held until the attempt ends"
    );

    transport.release.notify_one();
    step.await.expect("step task");
    assert!(outbox.snapshot().await.is_empty());
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.error.as_deref(), Some(RECIPIENT_BLOCKED));
    outbox
        .step(at(NOW + 5_000, 5_000), &unknown, transport.as_ref())
        .await;
    assert_eq!(
        transport.calls.load(Ordering::SeqCst),
        1,
        "never sent again"
    );

    // A was attempted with an unknown outcome: other bytes are refused.
    let mut b = a;
    b.payload = b"payload B".to_vec();
    assert_eq!(
        outbox.enqueue(b, no_record()).await,
        EnqueueOutcome::Conflict
    );
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.payload_digest, Some(digest_of(b"hello")));
}

/// WHY: #1109 S2 a receipt must answer the same after a restart: every
/// terminal status, its error code and its payload digest come back from
/// the owner-only outcomes sidecar.
#[cfg(unix)]
#[tokio::test]
async fn issue1109_outcomes_survive_restart_with_their_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let wall = now_unix_ms();
    let ids = [
        "out-delivered",
        "out-expired",
        "out-failed",
        "out-cancelled",
    ];
    {
        let before = outbox_in(&dir);
        for id in ids {
            let until = if id == "out-expired" {
                wall + 1
            } else {
                wall + 60_000
            };
            before
                .enqueue(obligation(id, peer, until), no_record())
                .await;
        }
        let cancel_rid = request_id_for("out-cancelled", peer);
        assert_eq!(
            before.cancel(&peer, &cancel_rid).await,
            CancelOutcome::Cancelled
        );
        // One pass: "out-expired" is past its deadline, "out-failed" is
        // rejected, "out-delivered" is delivered.
        let failed_rid = request_id_for("out-failed", peer);
        let transport = FailOne(failed_rid);
        before.step(at(wall + 10, 0), &unknown, &transport).await;
        assert!(before.snapshot().await.is_empty());
    }
    let mode = {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(dir.path().join(DIRECT_SEND_OUTCOMES_FILE))
            .expect("outcomes sidecar written")
            .permissions()
            .mode()
    };
    assert_eq!(mode & 0o777, 0o600);
    let after = outbox_in(&dir);
    after.load(wall).await.expect("sidecars load");
    let expect = [
        ("out-delivered", "delivered", None),
        ("out-expired", "expired", None),
        ("out-failed", "failed", Some("recipient_rejected")),
        ("out-cancelled", "cancelled", None),
    ];
    for (id, want, error) in expect {
        let receipt = status(&after, peer, &request_id_for(id, peer)).await;
        assert_eq!(receipt.status, want, "{id}");
        assert_eq!(receipt.error.as_deref(), error, "{id}");
        assert_eq!(receipt.payload_digest, Some(digest_of(b"hello")), "{id}");
    }
}

/// A transport that rejects one request id and delivers the rest.
struct FailOne([u8; 16]);

impl DirectSendTransport for FailOne {
    fn recipient_blocked(&self, _recipient: AgentId) -> TransportFuture<'_, bool> {
        Box::pin(async { false })
    }

    fn send(
        &self,
        _recipient: AgentId,
        _payload: Vec<u8>,
        config: DmSendConfig,
        _budget: Duration,
    ) -> TransportFuture<'_, Result<(), DmError>> {
        let fail = config.logical_request_id == Some(self.0);
        Box::pin(async move {
            if fail {
                Err(DmError::RecipientRejected {
                    reason: "no".to_string(),
                })
            } else {
                Ok(())
            }
        })
    }
}

/// WHY: #1109 S2 after a restart the ACK waiter and tombstone are gone; a
/// late ACK from the recipient must still settle the held obligation, so
/// the worker does not send it again.
#[tokio::test]
async fn issue1109_late_ack_after_restart_settles_with_zero_sends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let rid = request_id_for("order-r", peer);
    {
        let before = outbox_in(&dir);
        before
            .enqueue(obligation("order-r", peer, NOW + 60_000), no_record())
            .await;
        // One attempt whose ACK is lost; then the daemon restarts.
        before
            .step(
                at(NOW, 0),
                &pinned,
                &ScriptedTransport::with(vec![Err(timeout())]),
            )
            .await;
    }
    let after = outbox_in(&dir);
    after.load(NOW).await.expect("sidecar loads");
    assert!(after.settle_late_ack(&rid, &peer, &peer_machine()).await);
    assert!(after.snapshot().await.is_empty());
    let transport = ScriptedTransport::default();
    after.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 0);
    let receipt = status(&after, peer, &rid).await;
    assert_eq!(receipt.status, "delivered");
    assert_eq!(receipt.payload_digest, Some(digest_of(b"hello")));
}

/// WHY: #1109 S2 only the recipient's ACK proves delivery: a late ACK
/// from another agent (or for another request) changes nothing.
#[tokio::test]
async fn issue1109_late_ack_from_another_agent_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("order-s", peer);
    outbox
        .enqueue(obligation("order-s", peer, NOW + 60_000), no_record())
        .await;
    assert!(
        !outbox
            .settle_late_ack(&rid, &agent(9), &peer_machine())
            .await
    );
    assert!(
        !outbox
            .settle_late_ack(&[0x77; 16], &peer, &peer_machine())
            .await
    );
    assert_eq!(outbox.snapshot().await.len(), 1);
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");
}

/// WHY: #1109 S2 a durable-capable advert from a recipient makes its held
/// sends due now instead of at the next retry time, and only its own.
#[tokio::test]
async fn issue1109_advert_nudge_makes_only_that_recipients_sends_due() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let (cold, other) = (agent(2), agent(3));
    outbox
        .enqueue(obligation("nudge-a", cold, NOW + 600_000), no_record())
        .await;
    outbox
        .enqueue(obligation("nudge-b", other, NOW + 600_000), no_record())
        .await;
    let unavailable = || Err(DmError::AckSemanticsUnavailable("no v2 advert".to_string()));
    let transport = ScriptedTransport::with(vec![unavailable(), unavailable()]);
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 2);

    assert!(outbox.nudge_recipient(&cold, at(NOW + 100, 100)).await);
    assert!(!outbox.nudge_recipient(&agent(9), at(NOW + 100, 100)).await);
    outbox.step(at(NOW + 100, 100), &unknown, &transport).await;
    assert_eq!(
        transport.calls(),
        3,
        "only the nudged recipient was sent to"
    );
    let held = outbox.snapshot().await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].recipient, hex::encode(other.as_bytes()));
    assert_eq!(
        held[0].next_retry_at_ms, 2_000,
        "the other schedule is unchanged"
    );
}

/// WHY: #1109 S2 a bad outcomes sidecar must not stop the daemon: it is
/// moved aside, the outcomes start empty and the outbox keeps working.
#[tokio::test]
async fn issue1109_corrupt_outcomes_sidecar_is_moved_aside() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(DIRECT_SEND_OUTCOMES_FILE);
    std::fs::write(&path, b"{not json").expect("write garbage");
    let outbox = outbox_in(&dir);
    let error = outbox
        .load(42)
        .await
        .expect_err("a corrupt sidecar is reported");
    assert!(error.contains("moved aside"), "{error}");
    assert!(!path.exists());
    assert!(path.with_extension("corrupt-42").exists());
    assert_eq!(
        outbox
            .enqueue(
                obligation("after-corrupt", agent(2), NOW + 60_000),
                no_record()
            )
            .await,
        EnqueueOutcome::Queued
    );
}

fn timeout() -> DmError {
    DmError::Timeout {
        retries: 0,
        elapsed: Duration::from_secs(1),
    }
}

/// One attempt whose ACK is lost (a retryable timeout).
async fn attempt_once(outbox: &DirectSendOutbox, wall: u64, mono: u64) {
    let transport = ScriptedTransport::with(vec![Err(timeout())]);
    outbox.step(at(wall, mono), &pinned, &transport).await;
    assert_eq!(transport.calls(), 1, "one attempt was made");
}

/// WHY: #1109 S2 review — the outcome is written before the obligation is
/// removed; if a crash comes between, the reload removes the obligation
/// and the recorded outcome wins.
#[tokio::test]
async fn issue1109_outcome_written_before_removal_wins_on_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let rid = request_id_for("crash-1", peer);
    {
        let before = outbox_in(&dir);
        before
            .enqueue(obligation("crash-1", peer, NOW + 60_000), no_record())
            .await;
        before
            .record_outcomes_only(vec![(
                rid,
                DirectSendTerminal::Expired,
                digest_of(b"hello"),
            )])
            .await
            .expect("outcome written");
        // Crash: the obligation was not removed.
        assert_eq!(before.snapshot().await.len(), 1);
    }
    let after = outbox_in(&dir);
    after.load(NOW).await.expect("sidecars load");
    assert!(after.snapshot().await.is_empty(), "the outcome wins");
    assert_eq!(status(&after, peer, &rid).await.status, "expired");
    let transport = ScriptedTransport::default();
    after.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 0);
}

/// WHY: #1109 S2 review — when the outcome cannot be written, nothing ends:
/// the send stays held, a cancel answers not-durable, and no attempt is
/// made until the attempt record can be written.
#[tokio::test]
async fn issue1109_failed_outcome_write_keeps_the_send_held() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("nowrite-1", peer);
    outbox
        .enqueue(obligation("nowrite-1", peer, NOW + 60_000), no_record())
        .await;
    // A directory where the outcomes file goes: every write fails.
    let blocker = dir.path().join(DIRECT_SEND_OUTCOMES_FILE);
    std::fs::create_dir(&blocker).expect("blocker dir");
    assert!(matches!(
        outbox.cancel(&peer, &rid).await,
        CancelOutcome::NotDurable(_)
    ));
    assert_eq!(outbox.snapshot().await.len(), 1, "still held");
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");
    let transport = ScriptedTransport::default();
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(
        transport.calls(),
        0,
        "no send without a durable attempt record"
    );
    std::fs::remove_dir(&blocker).expect("remove blocker");
    outbox.step(at(NOW, 1), &unknown, &transport).await;
    assert_eq!(transport.calls(), 1);
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "delivered");
}

/// WHY: #1109 S2 review — a late ACK for the only bytes ever attempted,
/// arriving after the send expired, is recorded truthfully.
#[tokio::test]
async fn issue1109_late_ack_after_expiry_reads_delivered_late() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("late-exp", peer);
    outbox
        .enqueue(obligation("late-exp", peer, NOW + 1_000), no_record())
        .await;
    attempt_once(&outbox, NOW, 0).await;
    outbox
        .step(
            at(NOW + 1_000, 1_000),
            &unknown,
            &ScriptedTransport::default(),
        )
        .await;
    assert_eq!(status(&outbox, peer, &rid).await.status, "expired");
    assert!(outbox.settle_late_ack(&rid, &peer, &peer_machine()).await);
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "delivered_late");
    assert_eq!(receipt.payload_digest, Some(digest_of(b"hello")));
}

/// WHY: #1109 S2 review — a late ACK for the only bytes ever attempted,
/// arriving after a cancel, is recorded truthfully.
#[tokio::test]
async fn issue1109_late_ack_after_cancel_reads_delivered_late() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("late-cancel", peer);
    outbox
        .enqueue(obligation("late-cancel", peer, NOW + 60_000), no_record())
        .await;
    attempt_once(&outbox, NOW, 0).await;
    assert_eq!(outbox.cancel(&peer, &rid).await, CancelOutcome::Cancelled);
    assert!(
        !outbox
            .settle_late_ack(&rid, &agent(9), &peer_machine())
            .await,
        "another agent"
    );
    assert!(outbox.settle_late_ack(&rid, &peer, &peer_machine()).await);
    assert_eq!(status(&outbox, peer, &rid).await.status, "delivered_late");
}

/// WHY: #1109 S2 review — once bytes were attempted under a key, other
/// bytes cannot be queued under it (their delivery is unknowable), and a
/// held send whose bytes were never attempted is not settled by a late
/// ACK.
#[tokio::test]
async fn issue1109_late_ack_never_settles_bytes_that_were_not_attempted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("requeue", peer);
    let a = obligation("requeue", peer, NOW + 60_000);
    outbox.enqueue(a.clone(), no_record()).await;
    attempt_once(&outbox, NOW, 0).await;
    assert_eq!(outbox.cancel(&peer, &rid).await, CancelOutcome::Cancelled);
    let mut b = a;
    b.payload = b"payload B".to_vec();
    assert_eq!(
        outbox.enqueue(b.clone(), no_record()).await,
        EnqueueOutcome::Conflict
    );

    // B held under a key whose only attempt was other bytes (A).
    let other_dir = tempfile::tempdir().expect("tempdir");
    let other = outbox_in(&other_dir);
    assert_eq!(other.enqueue(b, no_record()).await, EnqueueOutcome::Queued);
    other
        .note_attempts(vec![(
            rid,
            hex::encode(peer.as_bytes()),
            digest_of(b"hello"),
            peer_machine(),
        )])
        .await
        .expect("noted");
    assert!(!other.settle_late_ack(&rid, &peer, &peer_machine()).await);
    assert_eq!(other.snapshot().await.len(), 1, "B is still held");
    let receipt = status(&other, peer, &rid).await;
    assert_eq!(receipt.status, "queued");
    assert_eq!(receipt.payload_digest, Some(digest_of(b"payload B")));
}

/// WHY: #1109 S2 review — with two digests attempted under one key, a late
/// ACK cannot say which bytes it proves, so it changes nothing.
#[tokio::test]
async fn issue1109_two_attempted_digests_make_a_late_ack_change_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("two-digests", peer);
    outbox
        .enqueue(obligation("two-digests", peer, NOW + 60_000), no_record())
        .await;
    outbox
        .note_attempts(vec![(
            rid,
            hex::encode(peer.as_bytes()),
            digest_of(b"other"),
            peer_machine(),
        )])
        .await
        .expect("noted");
    attempt_once(&outbox, NOW, 0).await;
    assert!(!outbox.settle_late_ack(&rid, &peer, &peer_machine()).await);
    assert_eq!(outbox.snapshot().await.len(), 1);
    assert_eq!(status(&outbox, peer, &rid).await.status, "queued");
}

/// WHY: #1109 S2 review — wake-ups arriving faster than the tick must not
/// starve the scheduled passes: due sends are still attempted and a
/// past-deadline send still expires.
#[tokio::test(start_paused = true)]
async fn issue1109_wake_up_flood_does_not_starve_the_scheduled_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = std::sync::Arc::new(outbox_in(&dir));
    let peer = agent(2);
    let rid = request_id_for("flood", peer);
    outbox
        .enqueue(obligation("flood", peer, NOW + 6_000), no_record())
        .await;
    let transport = std::sync::Arc::new(ScriptedTransport::with(vec![
        Err(timeout()),
        Err(timeout()),
        Err(timeout()),
    ]));
    let (wake_tx, wake_rx) = tokio::sync::mpsc::channel(64);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let worker = {
        let outbox = std::sync::Arc::clone(&outbox);
        let transport = std::sync::Arc::clone(&transport);
        tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            let clock = move || {
                let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                at(NOW + elapsed, elapsed)
            };
            run_direct_send_worker(
                &outbox,
                &unknown,
                transport.as_ref(),
                &clock,
                wake_rx,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await;
        })
    };
    // A wake-up every 300 ms for 9 s, for a recipient with nothing held.
    for _ in 0..30 {
        wake_tx
            .send(DirectSendWake::Advert(agent(9)))
            .await
            .expect("worker alive");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(transport.calls() >= 2, "retries ran on schedule");
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(status(&outbox, peer, &rid).await.status, "expired");
    let _ = stop_tx.send(());
    worker.await.expect("worker ends");
}

/// WHY: #1983 review MINOR 1 — a flood of adverts from a recipient that
/// HAS held sends must not resend on every advert: one nudge per
/// recipient per [`DIRECT_SEND_NUDGE_MIN_MS`].
#[tokio::test(start_paused = true)]
async fn issue1109_advert_flood_for_a_held_recipient_is_rate_limited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = std::sync::Arc::new(outbox_in(&dir));
    let peer = agent(2);
    outbox
        .enqueue(obligation("advert-flood", peer, NOW + 600_000), no_record())
        .await;
    // Every attempt times out, so the send stays held throughout.
    let transport = std::sync::Arc::new(ScriptedTransport::with(
        (0..200).map(|_| Err(timeout())).collect(),
    ));
    let (wake_tx, wake_rx) = tokio::sync::mpsc::channel(256);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let worker = {
        let outbox = std::sync::Arc::clone(&outbox);
        let transport = std::sync::Arc::clone(&transport);
        tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            let clock = move || {
                let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                at(NOW + elapsed, elapsed)
            };
            run_direct_send_worker(
                &outbox,
                &unknown,
                transport.as_ref(),
                &clock,
                wake_rx,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await;
        })
    };
    // 100 adverts from the held recipient over 10 s (one every 100 ms).
    for _ in 0..100 {
        wake_tx
            .send(DirectSendWake::Advert(peer))
            .await
            .expect("worker alive");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = stop_tx.send(());
    worker.await.expect("worker ends");
    // Without the limit every advert would resend (about 100). With it, at
    // most one nudge per 2 s plus the scheduled passes: well under 20.
    let calls = transport.calls();
    assert!(calls >= 2, "the held send was still tried: {calls}");
    assert!(calls <= 12, "advert flood resent too often: {calls}");
    assert_eq!(outbox.snapshot().await.len(), 1, "still held");
}

/// WHY: #1983 review MINOR 1 — the nudge limit is per recipient: a nudge
/// of one recipient does not hold back another's.
#[tokio::test]
async fn issue1109_nudge_limit_is_per_recipient() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let (a, b) = (agent(2), agent(3));
    for (id, peer) in [("lim-a", a), ("lim-b", b)] {
        outbox
            .enqueue(obligation(id, peer, NOW + 600_000), no_record())
            .await;
    }
    assert!(outbox.nudge_recipient(&a, at(NOW, 100)).await);
    assert!(
        !outbox.nudge_recipient(&a, at(NOW, 1_000)).await,
        "too soon"
    );
    assert!(
        outbox.nudge_recipient(&b, at(NOW, 1_000)).await,
        "other recipient"
    );
    assert!(
        outbox
            .nudge_recipient(&a, at(NOW, 100 + DIRECT_SEND_NUDGE_MIN_MS))
            .await,
        "after the interval"
    );
}

/// WHY: #1983 review MINOR 2 — the attempt memory must not drop a record
/// before its 24 hours: when held sends and attempt records fill it, a new
/// queued send is refused instead.
#[tokio::test]
async fn issue1109_full_attempt_memory_refuses_new_queued_sends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    // Fill the attempt memory up to one below its cap, with recent records.
    let now_ms = now_unix_ms();
    {
        let mut terminal = outbox.terminal();
        for i in 0..(DIRECT_SEND_OUTCOMES_CAP - 1) {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            terminal.note_attempt(id, "aa", [1; 32], now_ms);
        }
    }
    // One held send without an attempt record fills the last place.
    assert_eq!(
        outbox
            .enqueue(obligation("mem-1", peer, NOW + 60_000), no_record())
            .await,
        EnqueueOutcome::Queued
    );
    assert_eq!(
        outbox
            .enqueue(obligation("mem-2", peer, NOW + 60_000), no_record())
            .await,
        EnqueueOutcome::Full,
        "no room for another attempt record"
    );
    assert_eq!(
        outbox
            .enqueue(obligation("mem-1", peer, NOW + 60_000), no_record())
            .await,
        EnqueueOutcome::AlreadyQueued {
            deliver_until_ms: NOW + 60_000
        },
        "a repeat of a held send is still answered"
    );
    assert_eq!(
        outbox.terminal().attempts.len(),
        DIRECT_SEND_OUTCOMES_CAP - 1
    );
}

/// WHY: #1983 review MINOR 3 — when a pass decides `failed` but cannot
/// write it, the next pass must write it again and send nothing: the send
/// was already refused by the recipient's side.
#[tokio::test]
async fn issue1109_unwritten_failed_outcome_is_not_resent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = outbox_in(&dir);
    let peer = agent(2);
    let rid = request_id_for("unwritten-1", peer);
    outbox
        .enqueue(obligation("unwritten-1", peer, NOW + 60_000), no_record())
        .await;
    // The first attempt fails with a terminal error, and the outcomes
    // file becomes unwritable while it runs.
    let blocker = dir.path().join(DIRECT_SEND_OUTCOMES_FILE);
    let transport = BlockDuringSend {
        inner: ScriptedTransport::with(vec![Err(DmError::RecipientRejected {
            reason: "blocked".to_string(),
        })]),
        blocker: blocker.clone(),
    };
    outbox.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.inner.calls(), 1);
    assert_eq!(outbox.snapshot().await.len(), 1, "held: outcome unwritten");
    // Still unwritable: no send.
    outbox.step(at(NOW, 3_000), &unknown, &transport).await;
    assert_eq!(transport.inner.calls(), 1, "no resend");
    std::fs::remove_dir(&blocker).expect("remove blocker");
    outbox.step(at(NOW, 6_000), &unknown, &transport).await;
    assert_eq!(transport.inner.calls(), 1, "no resend once writable");
    assert!(outbox.snapshot().await.is_empty());
    let receipt = status(&outbox, peer, &rid).await;
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.error.as_deref(), Some("recipient_rejected"));
}

/// A scripted transport that makes the outcomes file unwritable (a
/// directory in its place) during the send.
struct BlockDuringSend {
    inner: ScriptedTransport,
    blocker: std::path::PathBuf,
}

impl DirectSendTransport for BlockDuringSend {
    fn recipient_blocked(&self, recipient: AgentId) -> TransportFuture<'_, bool> {
        self.inner.recipient_blocked(recipient)
    }

    fn send(
        &self,
        recipient: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
        budget: Duration,
    ) -> TransportFuture<'_, Result<(), DmError>> {
        let _ = std::fs::remove_file(&self.blocker);
        std::fs::create_dir(&self.blocker).expect("blocker dir");
        self.inner.send(recipient, payload, config, budget)
    }
}

/// WHY: #2007 after a restart only the machine the attempt was pinned to
/// can settle a held send: an orphan ACK from the right agent on another
/// machine changes nothing, and the pinned machine's ACK still settles it.
#[tokio::test]
async fn issue2007_late_ack_from_another_machine_after_restart_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let rid = request_id_for("pin-held", peer);
    {
        let before = outbox_in(&dir);
        before
            .enqueue(obligation("pin-held", peer, NOW + 60_000), no_record())
            .await;
        attempt_once(&before, NOW, 0).await;
    }
    let after = outbox_in(&dir);
    after.load(NOW).await.expect("sidecars load");
    let other_machine = MachineId([0xb3; 32]);
    assert!(
        !after.settle_late_ack(&rid, &peer, &other_machine).await,
        "an ACK from another machine settles nothing"
    );
    assert_eq!(after.snapshot().await.len(), 1, "still held");
    assert_eq!(status(&after, peer, &rid).await.status, "queued");
    assert!(after.settle_late_ack(&rid, &peer, &peer_machine()).await);
    assert!(after.snapshot().await.is_empty());
    assert_eq!(status(&after, peer, &rid).await.status, "delivered");
}

/// WHY: #2007 an ended send becomes `delivered_late` only on an ACK from
/// the machine its attempt was pinned to, also after a restart.
#[tokio::test]
async fn issue2007_delivered_late_needs_the_pinned_machine_after_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let rid = request_id_for("pin-cancel", peer);
    {
        let before = outbox_in(&dir);
        before
            .enqueue(obligation("pin-cancel", peer, NOW + 60_000), no_record())
            .await;
        attempt_once(&before, NOW, 0).await;
        assert_eq!(before.cancel(&peer, &rid).await, CancelOutcome::Cancelled);
    }
    let after = outbox_in(&dir);
    after.load(NOW).await.expect("sidecars load");
    assert!(
        !after
            .settle_late_ack(&rid, &peer, &MachineId([0xb3; 32]))
            .await
    );
    assert_eq!(status(&after, peer, &rid).await.status, "cancelled");
    assert!(after.settle_late_ack(&rid, &peer, &peer_machine()).await);
    assert_eq!(status(&after, peer, &rid).await.status, "delivered_late");
}

/// WHY: #2007 an attempt record with no machine (written before #2007, or
/// whose machine was never known) still loads, but no late ACK can settle
/// it: the held send is sent again instead and the recipient re-ACKs.
#[tokio::test]
async fn issue2007_attempt_record_without_a_machine_loads_and_settles_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = agent(2);
    let rid = request_id_for("pin-legacy", peer);
    {
        let before = outbox_in(&dir);
        before
            .enqueue(obligation("pin-legacy", peer, NOW + 60_000), no_record())
            .await;
        // `unknown` names no machine: the record is what a pre-#2007
        // daemon wrote.
        let transport = ScriptedTransport::with(vec![Err(timeout())]);
        before.step(at(NOW, 0), &unknown, &transport).await;
        assert_eq!(transport.calls(), 1);
    }
    let sidecar = std::fs::read(dir.path().join(DIRECT_SEND_OUTCOMES_FILE)).expect("sidecar");
    let json: serde_json::Value = serde_json::from_slice(&sidecar).expect("json");
    let attempt = &json["attempts"][0];
    assert!(attempt.get("digests").is_some(), "{json}");
    assert!(attempt.get("machines").is_none(), "pre-#2007 shape: {json}");

    let after = outbox_in(&dir);
    after
        .load(NOW)
        .await
        .expect("a record with no machine loads");
    assert!(!after.settle_late_ack(&rid, &peer, &peer_machine()).await);
    assert_eq!(after.snapshot().await.len(), 1, "still held");
    let transport = ScriptedTransport::default();
    after.step(at(NOW, 0), &unknown, &transport).await;
    assert_eq!(transport.calls(), 1, "sent again, not settled by the ACK");
    assert_eq!(status(&after, peer, &rid).await.status, "delivered");
}

/// WHY: #2007 the pinned machines survive the sidecar round trip, and a
/// malformed machine fails the file like any malformed record.
#[test]
fn issue2007_attempt_machines_round_trip_the_sidecar() {
    let rid = [0x5a; 16];
    let recipient = hex::encode([2u8; 32]);
    let mut ledger = TerminalLedger::default();
    ledger.note_attempt(rid, &recipient, [7; 32], NOW);
    ledger.note_machine(&rid, peer_machine());
    let bytes = serde_json::to_vec(&ledger.to_file()).expect("encode");
    let loaded = TerminalLedger::from_bytes(&bytes, NOW).expect("decode");
    assert_eq!(
        loaded.only_attempted(&rid, &recipient, &peer_machine()),
        Some([7; 32])
    );
    assert_eq!(
        loaded.only_attempted(&rid, &recipient, &MachineId([0xb3; 32])),
        None
    );

    let bad = serde_json::json!({
        "version": 1,
        "attempts": [{
            "request_id": hex::encode(rid),
            "recipient": recipient,
            "digests": [hex::encode([7u8; 32])],
            "machines": ["not hex"],
            "last_ms": NOW,
        }],
    });
    let bad = serde_json::to_vec(&bad).expect("encode");
    assert!(TerminalLedger::from_bytes(&bad, NOW).is_err());
}
