#![cfg(test)]
//! #1109 unit tests for the `deliver_until` obligation outbox. Inert:
//! local files and a scripted sender only.

use super::*;
use crate::dm::{DmAckOutcome, DM_PROTOCOL_DURABLE_ACK};
use crate::identity::MachineId;
use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;

const ME: AgentId = AgentId([0x01; 32]);
const PEER: AgentId = AgentId([0x02; 32]);
const T0: u64 = 1_000_000;

/// A sender that answers from a script and records each attempt.
#[derive(Default)]
struct Scripted {
    answers: StdMutex<VecDeque<Result<(), DmError>>>,
    sent: StdMutex<Vec<(AgentId, Vec<u8>, DmSendConfig)>>,
}

impl Scripted {
    fn with(answers: Vec<Result<(), DmError>>) -> Self {
        Self {
            answers: StdMutex::new(answers.into()),
            sent: StdMutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<(AgentId, Vec<u8>, DmSendConfig)> {
        self.sent.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl ObligationSender for Scripted {
    async fn send(
        &self,
        to: AgentId,
        payload: Vec<u8>,
        config: DmSendConfig,
    ) -> Result<(), DmError> {
        if let Ok(mut sent) = self.sent.lock() {
            sent.push((to, payload, config));
        }
        self.answers
            .lock()
            .ok()
            .and_then(|mut a| a.pop_front())
            .unwrap_or(Err(DmError::NoConnectivity("script ended".to_string())))
    }
}

fn no_v2_advert() -> DmError {
    DmError::AckSemanticsUnavailable(
        "recipient has no current v2 durable-ACK capability advert".to_string(),
    )
}

fn obligation(logical: &str, payload: &[u8], deliver_until_ms: u64) -> DmObligation {
    let logical_id = DmLogicalId::parse(logical).expect("valid logical id");
    DmObligation::new(
        ME,
        PEER,
        &logical_id,
        payload.to_vec(),
        deliver_until_ms,
        T0,
    )
}

fn request_id(logical: &str) -> [u8; 16] {
    DmLogicalId::parse(logical)
        .expect("valid logical id")
        .request_id(ME, PEER)
}

/// #1109: a cold recipient (no v2 advert yet) is held, not refused. The
/// #1158 advert signal makes it due at once, and the next pass delivers it
/// with the same logical request id; the receipt then reads `delivered`.
#[tokio::test]
async fn issue1109_cold_recipient_is_held_then_delivered_on_advert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DmObligationStore::new(dir.path());
    let acks = InFlightAcks::new();
    let held = obligation("order-1", b"hello", T0 + 600_000);
    assert_eq!(
        store.admit(held.clone()).await,
        Ok(DmObligationAdmission::Admitted)
    );
    let sender = Scripted::with(vec![Err(no_v2_advert()), Ok(())]);
    let config = DmSendConfig::default();

    let first = store.step(&sender, ME, &config, &acks, T0).await;
    assert_eq!(first.retried, vec!["order-1".to_string()]);
    let kept = store.find(&PEER, "order-1").await.expect("still held");
    assert_eq!(kept.retry_count, 1);
    assert_eq!(
        kept.last_error.as_deref(),
        Some("recipient_ack_semantics_unavailable")
    );
    assert!(kept.next_retry_at_ms > T0 + 1_000, "the retry waits");

    // Not due yet: nothing is sent.
    let idle = store.step(&sender, ME, &config, &acks, T0 + 1_000).await;
    assert_eq!(idle, DmObligationPass::default());

    // The verified advert arrives.
    assert!(store.nudge_for(&PEER, T0 + 1_000).await);
    let second = store.step(&sender, ME, &config, &acks, T0 + 1_000).await;
    assert_eq!(second.delivered, vec!["order-1".to_string()]);
    assert!(store.is_empty().await);
    assert_eq!(
        acks.receipt_status(&request_id("order-1")),
        DmReceiptStatus::Delivered
    );

    let sent = sender.sent();
    assert_eq!(sent.len(), 2, "one send per pass, no extra copy");
    for (to, payload, config) in sent {
        assert_eq!(to, PEER);
        assert_eq!(payload, b"hello");
        assert!(config.require_durable_app_ack);
        assert_eq!(config.logical_request_id, Some(request_id("order-1")));
    }
}

/// #1109: an obligation survives a restart (sidecar reload) and the
/// reloaded store finishes it.
#[tokio::test]
async fn issue1109_restart_mid_obligation_resumes() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = DmObligationStore::new(dir.path());
        store
            .admit(obligation("order-2", b"persist me", T0 + 600_000))
            .await
            .expect("admitted");
        let sender = Scripted::with(vec![Err(DmError::Timeout {
            retries: 1,
            elapsed: std::time::Duration::from_secs(16),
        })]);
        let pass = store
            .step(
                &sender,
                ME,
                &DmSendConfig::default(),
                &InFlightAcks::new(),
                T0,
            )
            .await;
        assert_eq!(pass.retried, vec!["order-2".to_string()]);
    }
    let reloaded = DmObligationStore::new(dir.path());
    reloaded.load(T0).await.expect("sidecar loads");
    let held = reloaded
        .find(&PEER, "order-2")
        .await
        .expect("held after restart");
    assert_eq!(held.retry_count, 1, "the schedule survived the restart");
    assert_eq!(held.payload, b"persist me");

    let acks = InFlightAcks::new();
    let sender = Scripted::with(vec![Ok(())]);
    let pass = reloaded
        .step(
            &sender,
            ME,
            &DmSendConfig::default(),
            &acks,
            held.next_retry_at_ms,
        )
        .await;
    assert_eq!(pass.delivered, vec!["order-2".to_string()]);
    assert!(reloaded.is_empty().await);
    let again = DmObligationStore::new(dir.path());
    again.load(T0).await.expect("sidecar loads");
    assert!(again.is_empty().await, "the delivery was persisted");
}

/// #1109: past the deadline nothing more is sent; the receipt reads
/// `expired`. A matching late v2 ACK still upgrades it to `delivered_late`.
#[tokio::test]
async fn issue1109_deadline_expiry_reads_expired() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DmObligationStore::new(dir.path());
    let acks = InFlightAcks::new();
    store
        .admit(obligation("order-3", b"late", T0 + 10_000))
        .await
        .expect("admitted");
    let sender = Scripted::with(vec![]);
    let pass = store
        .step(&sender, ME, &DmSendConfig::default(), &acks, T0 + 10_000)
        .await;
    assert_eq!(pass.expired, vec!["order-3".to_string()]);
    assert!(sender.sent().is_empty(), "no send after the deadline");
    assert!(store.is_empty().await);
    let rid = request_id("order-3");
    assert_eq!(acks.receipt_status(&rid), DmReceiptStatus::Expired);
    assert!(!acks.resolve_for_protocol(
        &rid,
        DM_PROTOCOL_DURABLE_ACK,
        PEER,
        MachineId([0x09; 32]),
        DmAckOutcome::Accepted,
    ));
    assert_eq!(acks.receipt_status(&rid), DmReceiptStatus::DeliveredLate);
}

/// #1109: a refusal a retry cannot change ends the obligation as `failed`;
/// an ordinary transient error keeps it.
#[tokio::test]
async fn issue1109_final_refusal_reads_failed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DmObligationStore::new(dir.path());
    let acks = InFlightAcks::new();
    store
        .admit(obligation("order-4", b"no", T0 + 600_000))
        .await
        .expect("admitted");
    let sender = Scripted::with(vec![Err(DmError::RecipientRejected {
        reason: "blocked".to_string(),
    })]);
    let pass = store
        .step(&sender, ME, &DmSendConfig::default(), &acks, T0)
        .await;
    assert_eq!(pass.failed, vec!["order-4".to_string()]);
    assert!(store.is_empty().await);
    assert_eq!(
        acks.receipt_status(&request_id("order-4")),
        DmReceiptStatus::Failed
    );
    for transient in [
        no_v2_advert(),
        DmError::RecipientCapabilityPending {
            capability: "dm_v2",
        },
        DmError::RecipientKeyUnavailable("unknown".to_string()),
        DmError::PeerDisconnected {
            reason: "gone".to_string(),
        },
    ] {
        assert_eq!(classify(&Err(transient)), AttemptOutcome::Retry);
    }
}

/// #1109: admission is idempotent for the same bytes, refuses other bytes
/// under the same logical id, and refuses (does not evict) at the cap.
#[tokio::test]
async fn issue1109_admission_is_idempotent_and_capped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DmObligationStore::new(dir.path());
    let first = obligation("order-5", b"same", T0 + 600_000);
    assert_eq!(
        store.admit(first.clone()).await,
        Ok(DmObligationAdmission::Admitted)
    );
    assert_eq!(
        store.admit(first).await,
        Ok(DmObligationAdmission::AlreadyHeld)
    );
    assert_eq!(
        store
            .admit(obligation("order-5", b"other", T0 + 600_000))
            .await,
        Err(DmObligationRefusal::IdempotencyConflict)
    );
    for n in 1..DM_OBLIGATION_CAPS.per_partition {
        store
            .admit(obligation(&format!("fill-{n}"), b"x", T0 + 600_000))
            .await
            .expect("under the cap");
    }
    assert_eq!(store.len().await, DM_OBLIGATION_CAPS.per_partition);
    assert_eq!(
        store
            .admit(obligation("one-too-many", b"x", T0 + 600_000))
            .await,
        Err(DmObligationRefusal::Full)
    );
    assert!(
        store.find(&PEER, "order-5").await.is_some(),
        "the oldest obligation was not evicted"
    );
}

/// #1109: the sidecar is private to the daemon user.
#[cfg(unix)]
#[tokio::test]
async fn issue1109_sidecar_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DmObligationStore::new(dir.path());
    store
        .admit(obligation("order-6", b"private", T0 + 600_000))
        .await
        .expect("admitted");
    let mode = std::fs::metadata(dir.path().join(DM_OBLIGATION_FILE))
        .expect("sidecar written")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
