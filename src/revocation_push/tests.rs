//! #1003 receiver-side unit tests: the push alone revokes (no gossip), a
//! forged or malformed push is refused with nothing inserted, a duplicate
//! costs no second insert, and the rate limit drops the excess.

use super::*;
use crate::identity::UserKeypair;
use crate::revocation::{RevocationRecord, ShareGrantRevocation};

fn owner_trust() -> crate::owner_trust::OwnerTrust {
    let bindings = std::sync::Arc::new(tokio::sync::RwLock::new(
        crate::dm_inbox::AuthenticatedMachineBindingCache::default(),
    ));
    crate::owner_trust::OwnerTrust::new(None, bindings)
}

fn now_unix() -> u64 {
    crate::Agent::unix_timestamp_secs()
}

fn signed_record(owner: &UserKeypair, grant_id: [u8; 32], grant_expiry: u64) -> RevocationRecord {
    RevocationRecord::sign(
        RevokedSubject::ShareGrant(ShareGrantRevocation {
            grant_id,
            owner: owner.user_id(),
            grant_expiry,
        }),
        owner.public_key(),
        owner.secret_key(),
        now_unix(),
        None,
    )
    .expect("sign revocation record")
}

struct Receiver {
    owner_trust: crate::owner_trust::OwnerTrust,
    set: tokio::sync::RwLock<RevocationSet>,
    limiter: tokio::sync::Mutex<PushRateLimiter>,
    // Keeps persists off the real `~/.x0x` (the `None` fallback).
    dir: tempfile::TempDir,
}

impl Receiver {
    fn new() -> Self {
        Self {
            owner_trust: owner_trust(),
            set: tokio::sync::RwLock::new(RevocationSet::new()),
            limiter: tokio::sync::Mutex::new(PushRateLimiter::new()),
            dir: tempfile::TempDir::new().expect("tempdir"),
        }
    }

    async fn handle(&self, sender: AgentId, payload: &[u8]) -> PushOutcome {
        handle_grant_revocation_push(
            &self.owner_trust,
            &self.set,
            Some(self.dir.path()),
            &self.limiter,
            sender,
            payload,
            now_unix(),
        )
        .await
    }
}

/// WHY: the whole point of #1003 — with NO gossip delivery at all, a
/// receiver that gets the direct push stops honouring the grant: the
/// revocation is in its set and every access decision filters through it.
#[tokio::test]
async fn push_alone_revokes_without_gossip() {
    let owner = UserKeypair::generate().expect("owner key");
    let grant_id = [0x42; 32];
    let record = signed_record(&owner, grant_id, now_unix() + 86_400);
    let payload = encode_grant_revocation_push(&record).expect("encode");
    assert!(payload.starts_with(GRANT_REVOCATION_PUSH_PREFIX));
    assert!(payload.len() <= MAX_GRANT_REVOCATION_PUSH_BYTES);

    let receiver = Receiver::new();
    assert!(!receiver
        .set
        .read()
        .await
        .is_share_grant_revoked(&grant_id, &owner.user_id()));
    let outcome = receiver.handle(AgentId([0x01; 32]), &payload).await;
    assert_eq!(outcome, PushOutcome::Ingested { inserted: true });
    assert!(receiver
        .set
        .read()
        .await
        .is_share_grant_revoked(&grant_id, &owner.user_id()));
}

/// WHY: idempotence (ADR 0080 §5) — the dedupe key is the record hash; a
/// second copy of the same record (push after push, standing in for push
/// after gossip) changes nothing and is dropped before any verify.
#[tokio::test]
async fn duplicate_record_is_dropped_before_verify() {
    let owner = UserKeypair::generate().expect("owner key");
    let record = signed_record(&owner, [0x43; 32], now_unix() + 86_400);
    let payload = encode_grant_revocation_push(&record).expect("encode");
    let receiver = Receiver::new();
    let sender = AgentId([0x02; 32]);
    assert_eq!(
        receiver.handle(sender, &payload).await,
        PushOutcome::Ingested { inserted: true }
    );
    assert_eq!(
        receiver.handle(sender, &payload).await,
        PushOutcome::Dropped(PushDrop::Duplicate)
    );
}

/// WHY: a forged push must be refused with no state change (#1003 test
/// list). Tampered bytes still decode as a record, so they reach the
/// shared ingest, whose ONE verify refuses them: `inserted` is false and
/// the set stays empty.
#[tokio::test]
async fn forged_push_is_refused_and_inserts_nothing() {
    let owner = UserKeypair::generate().expect("owner key");
    let mut record = signed_record(&owner, [0x44; 32], now_unix() + 86_400);
    // Tamper after signing: a different grant id under the same signature.
    if let RevokedSubject::ShareGrant(subject) = &mut record.subject {
        subject.grant_id = [0x45; 32];
    }
    let payload = encode_grant_revocation_push(&record).expect("encode");
    let receiver = Receiver::new();
    assert_eq!(
        receiver.handle(AgentId([0x03; 32]), &payload).await,
        PushOutcome::Ingested { inserted: false }
    );
    assert!(receiver.set.read().await.is_empty());
    assert!(!receiver
        .set
        .read()
        .await
        .is_share_grant_revoked(&[0x45; 32], &owner.user_id()));
}

/// WHY: the decode step must refuse every malformed shape (ADR 0080 §4
/// step 1-2): wrong subject, unknown grant (`u64::MAX`), a `Vec` payload,
/// trailing bytes, an oversize payload, and a stale record.
#[tokio::test]
async fn malformed_and_wrong_subject_pushes_are_dropped() {
    let owner = UserKeypair::generate().expect("owner key");
    let receiver = Receiver::new();
    let sender = AgentId([0x04; 32]);

    // A non-ShareGrant subject never encodes as a push...
    let agent_record = RevocationRecord::sign(
        RevokedSubject::Agent(AgentId([0x05; 32])),
        owner.public_key(),
        owner.secret_key(),
        now_unix(),
        None,
    )
    .expect("sign");
    assert!(encode_grant_revocation_push(&agent_record).is_err());
    // ...and is dropped when hand-built.
    let mut hand_built = GRANT_REVOCATION_PUSH_PREFIX.to_vec();
    hand_built.extend_from_slice(&bincode::serialize(&agent_record).expect("encode"));
    assert_eq!(
        receiver.handle(sender, &hand_built).await,
        PushOutcome::Dropped(PushDrop::WrongSubject)
    );

    // An unknown grant (`grant_expiry == u64::MAX`) travels by gossip only.
    let unknown = signed_record(&owner, [0x46; 32], u64::MAX);
    assert!(encode_grant_revocation_push(&unknown).is_err());
    let mut hand_built = GRANT_REVOCATION_PUSH_PREFIX.to_vec();
    hand_built.extend_from_slice(&bincode::serialize(&unknown).expect("encode"));
    assert_eq!(
        receiver.handle(sender, &hand_built).await,
        PushOutcome::Dropped(PushDrop::WrongSubject)
    );

    // A Vec payload (a v3 batch under the push prefix) is malformed.
    let record = signed_record(&owner, [0x47; 32], now_unix() + 86_400);
    let mut vec_payload = GRANT_REVOCATION_PUSH_PREFIX.to_vec();
    vec_payload
        .extend_from_slice(&bincode::serialize(&vec![record.clone()]).expect("encode batch"));
    assert_eq!(
        receiver.handle(sender, &vec_payload).await,
        PushOutcome::Dropped(PushDrop::Malformed)
    );

    // Trailing bytes are refused (every byte must be consumed).
    let mut trailing = encode_grant_revocation_push(&record).expect("encode");
    trailing.push(0);
    assert_eq!(
        receiver.handle(sender, &trailing).await,
        PushOutcome::Dropped(PushDrop::Malformed)
    );

    // An oversize payload is refused by the SIZE bound, not by decode: the
    // record is well-formed (it round-trips through plain bincode) and only
    // its unbounded reason pushes it over MAX_GRANT_REVOCATION_PUSH_BYTES.
    // #1857: `sign` refuses a reason this long, so the record is built by
    // hand, as a peer on an earlier build could send it. The size bound
    // runs before any signature check.
    let oversize_record = RevocationRecord {
        subject: RevokedSubject::ShareGrant(ShareGrantRevocation {
            grant_id: [0x4a; 32],
            owner: owner.user_id(),
            grant_expiry: now_unix() + 86_400,
        }),
        issuer_public_key: owner.public_key().as_bytes().to_vec(),
        revoked_at: now_unix(),
        reason: Some("r".repeat(2 * MAX_GRANT_REVOCATION_PUSH_BYTES)),
        signature: vec![0; 3309],
    };
    let body = bincode::serialize(&oversize_record).expect("encode");
    let round_trip: RevocationRecord = bincode::deserialize(&body).expect("well-formed record");
    assert_eq!(round_trip.record_hash(), oversize_record.record_hash());
    assert!(
        encode_grant_revocation_push(&oversize_record).is_err(),
        "the sender refuses an over-bound record"
    );
    let mut oversize = GRANT_REVOCATION_PUSH_PREFIX.to_vec();
    oversize.extend_from_slice(&body);
    assert!(oversize.len() > MAX_GRANT_REVOCATION_PUSH_BYTES);
    assert_eq!(
        receiver.handle(sender, &oversize).await,
        PushOutcome::Dropped(PushDrop::Malformed)
    );

    // A record past its GC horizon is stale: the grant can no longer be
    // honoured, so the push is dropped without a verify.
    let stale = signed_record(&owner, [0x48; 32], 1);
    let payload = encode_grant_revocation_push(&stale).expect("encode");
    assert_eq!(
        receiver.handle(sender, &payload).await,
        PushOutcome::Dropped(PushDrop::Stale)
    );

    assert!(receiver.set.read().await.is_empty());
}

/// WHY: the handler and the v3 gossip carrier must stay ONE ingest: a
/// record that arrived by push is a no-op when the same record then
/// arrives by gossip, and the gossip carrier still inserts a distinct
/// later record.
#[tokio::test]
async fn pushed_record_is_a_gossip_duplicate() {
    let owner = UserKeypair::generate().expect("owner key");
    let grant_id = [0x49; 32];
    let record = signed_record(&owner, grant_id, now_unix() + 86_400);
    let receiver = Receiver::new();
    let payload = encode_grant_revocation_push(&record).expect("encode");
    assert_eq!(
        receiver.handle(AgentId([0x06; 32]), &payload).await,
        PushOutcome::Ingested { inserted: true }
    );
    // A real v3 gossip batch (the full gossip path, batch decode included)
    // holding the pushed record plus a DISTINCT later record for the same
    // grant (a retried DELETE: a new `revoked_at`, so a new record hash):
    // the pushed record is a duplicate, the later record still inserts.
    let later = RevocationRecord::sign(
        RevokedSubject::ShareGrant(ShareGrantRevocation {
            grant_id,
            owner: owner.user_id(),
            grant_expiry: now_unix() + 86_400,
        }),
        owner.public_key(),
        owner.secret_key(),
        now_unix() + 7,
        None,
    )
    .expect("sign later record");
    assert_ne!(later.record_hash(), record.record_hash());
    let batch = crate::revocation::encode_revocation_batch(&[record.clone(), later.clone()])
        .expect("encode batch");
    let inserted = crate::ingest_share_grant_revocations(
        &receiver.owner_trust,
        &receiver.set,
        Some(receiver.dir.path().to_path_buf()),
        &batch,
    )
    .await;
    assert!(inserted, "the distinct later record inserts through gossip");
    let set = receiver.set.read().await;
    assert!(set.contains_hash(&later.record_hash()));
    assert!(set.contains_hash(&record.record_hash()));
    drop(set);
    // The pushed record alone, re-sent as a batch, is a pure duplicate.
    let dup = crate::revocation::encode_revocation_batch(&[record]).expect("encode batch");
    let inserted = crate::ingest_share_grant_revocations(
        &receiver.owner_trust,
        &receiver.set,
        Some(receiver.dir.path().to_path_buf()),
        &dup,
    )
    .await;
    assert!(!inserted, "a pushed record is a gossip duplicate");
}

/// WHY: ADR 0080 validation case 7 for the PUSH carrier — a pushed
/// revocation inserts in memory at once (6a: in force while a redelivery
/// send of the grant is still in flight) and then parks at the #926 send
/// gate (6b): the handler cannot return until the in-flight pass has
/// finished, so no new send or enqueue of the grant can follow it. The
/// handler is DRIVEN for 250 ms while the send is paused — a single
/// `Pending` poll would pass without 6b, because the persist alone (the
/// in-process write lock plus fs I/O) makes the first poll pend and then
/// completes. With 6b removed, the handler finishes during the pause and
/// the select panics.
#[tokio::test]
async fn pushed_revoke_parks_at_the_outbox_gate_until_the_in_flight_send_ends() {
    use futures::FutureExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0xC1; 32]);
    let shared = AgentId([0xC3; 32]);
    let grant_id = [0x60; 32];
    let now = now_unix();
    let grant = crate::share_grant::ShareGrant::sign(
        &owner,
        grant_id,
        crate::share_grant::Grantee::Agent(grantee),
        vec![shared],
        vec![crate::share_grant::ShareCap::Dm],
        0,
        now + 3_600,
    )
    .expect("sign grant");
    let receiver = Receiver::new();
    let outbox = std::sync::Arc::new(
        crate::share_grant::outbox::GrantRedeliveryOutbox::in_memory(Some(owner.user_id())),
    );
    assert!(outbox
        .enqueue(&grant, grantee, now, &receiver.set)
        .await
        .expect("enqueue"));
    receiver
        .owner_trust
        .install_share_grant_outbox(std::sync::Arc::clone(&outbox));

    // A redelivery pass of the grant with its one send paused in flight:
    // the pass holds the #926 send gate shared until `release` fires.
    let entered = AtomicBool::new(false);
    let release = tokio::sync::Notify::new();
    let due = now + crate::share_grant::outbox::retry_delay_secs(0);
    let step = outbox.step(due, &receiver.set, |_recipient, _payload, _id| async {
        entered.store(true, Ordering::SeqCst);
        release.notified().await;
        Ok(())
    });
    tokio::pin!(step);
    assert!(step.as_mut().now_or_never().is_none());
    assert!(
        entered.load(Ordering::SeqCst),
        "control: the send is in flight"
    );

    let record = signed_record(&owner, grant_id, now + 3_600);
    let payload = encode_grant_revocation_push(&record).expect("encode");
    let push = receiver.handle(AgentId([0x08; 32]), &payload);
    tokio::pin!(push);
    tokio::select! {
        outcome = push.as_mut() => {
            panic!("the push handler returned while a send of the grant was in flight: {outcome:?}")
        }
        () = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
    }
    // 6a: the pushed revocation is already in force in memory during the
    // 6b wait.
    assert!(receiver
        .set
        .read()
        .await
        .is_share_grant_revoked(&grant_id, &owner.user_id()));

    release.notify_one();
    let _ = step.await; // the in-flight send returns (its outcome is not the contract)
    assert_eq!(push.await, PushOutcome::Ingested { inserted: true });

    // From here on nothing of this grant can be queued again.
    assert_eq!(
        outbox
            .enqueue(&grant, AgentId([0xC2; 32]), now, &receiver.set)
            .await,
        Err(crate::share_grant::outbox::OutboxError::Revoked),
        "a revoked grant can no longer be queued"
    );
}

/// WHY: ADR 0080 §4 step 5 — at most 16 pushes per minute from one
/// sender and 256 in total; the excess is dropped, not queued.
#[test]
fn rate_limiter_bounds_per_sender_and_total() {
    let mut limiter = PushRateLimiter::new();
    let now = std::time::Instant::now();
    let sender = AgentId([0x07; 32]);
    for _ in 0..PUSH_RATE_PER_SENDER_PER_MINUTE {
        assert!(limiter.admit(&sender, now));
    }
    assert!(!limiter.admit(&sender, now), "17th push from one sender");
    // Other senders still fit until the total bound.
    let mut admitted = PUSH_RATE_PER_SENDER_PER_MINUTE;
    let mut raw = [0u8; 32];
    'outer: for b in 1..=255u8 {
        raw[0] = b;
        raw[1] = 0xee;
        let other = AgentId(raw);
        for _ in 0..PUSH_RATE_PER_SENDER_PER_MINUTE {
            if admitted >= PUSH_RATE_TOTAL_PER_MINUTE {
                break 'outer;
            }
            assert!(limiter.admit(&other, now));
            admitted += 1;
        }
    }
    raw[0] = 0;
    raw[1] = 0xdd;
    assert!(
        !limiter.admit(&AgentId(raw), now),
        "total bound reached: a fresh sender is still dropped"
    );
    // The window resets after a minute.
    let later = now + std::time::Duration::from_secs(61);
    assert!(limiter.admit(&sender, later));
}

/// WHY: ADR 0080 §3 (D113, positive evidence) — the sender pushes only on a
/// current verified advert that HAS the bit: a capable recipient is
/// scheduled, an advert WITHOUT the bit is `skipped_not_capable` (never
/// sent: an old receiver would show the payload as an ordinary DM), and an
/// unknown recipient is scheduled behind the one-refresh-and-wait gate.
#[tokio::test]
async fn schedule_counts_capable_not_capable_and_unknown() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let owner = UserKeypair::generate().expect("owner key");
    let agent = std::sync::Arc::new(
        crate::Agent::builder()
            .with_identity_dir(dir.path())
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("offline agent"),
    );
    let capable = AgentId([0xA1; 32]);
    let not_capable = AgentId([0xA2; 32]);
    let unknown = AgentId([0xA3; 32]);
    let bit = crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1;
    let now_ms = crate::dm_capability::now_unix_ms();
    let mut with_bit = crate::dm::DmCapabilities::pending();
    with_bit.application_registry = crate::dm::CapabilityRegistry {
        version: 1,
        bits: crate::dm::CapabilityRegistry::current().bits | bit,
    };
    let mut without_bit = crate::dm::DmCapabilities::pending();
    without_bit.application_registry = crate::dm::CapabilityRegistry {
        version: 1,
        bits: crate::dm::CapabilityRegistry::current().bits & !bit,
    };
    assert!(agent.capability_store().insert(
        capable,
        crate::identity::MachineId([0xB1; 32]),
        with_bit,
        now_ms
    ));
    assert!(agent.capability_store().insert(
        not_capable,
        crate::identity::MachineId([0xB2; 32]),
        without_bit,
        now_ms
    ));
    let grant = crate::share_grant::ShareGrant::sign(
        &owner,
        [0x50; 32],
        crate::share_grant::Grantee::Agent(capable),
        vec![not_capable, unknown],
        vec![crate::share_grant::ShareCap::Dm],
        0,
        now_unix() + 86_400,
    )
    .expect("sign grant");
    let record = signed_record(&owner, [0x50; 32], now_unix() + 86_400);
    let report = schedule_share_grant_revocation_push(&agent, &record, &grant).await;
    assert_eq!(report.recipients, 3);
    assert_eq!(
        report.skipped_not_capable, 1,
        "a current verified advert WITHOUT the bit is never pushed to"
    );
    assert_eq!(
        report.scheduled, 2,
        "the capable recipient and the unknown one (behind the refresh gate)"
    );
    assert_eq!(report.skipped_bound, 0);
}

/// WHY: ADR 0080 §3 — at most `MAX_PENDING_PUSHES` pushes pending in
/// memory; one over the bound is skipped (RAII slots return on drop).
/// Runs under nextest's process-per-test model, so the global counter is
/// this test's alone.
#[test]
fn pending_slot_bound_is_enforced() {
    let slots: Vec<PendingSlot> = (0..MAX_PENDING_PUSHES)
        .map(|_| PendingSlot::try_take().expect("slot within the bound"))
        .collect();
    assert!(
        PendingSlot::try_take().is_none(),
        "one push over the bound is refused"
    );
    drop(slots);
    assert!(
        PendingSlot::try_take().is_some(),
        "a released slot is reusable"
    );
}

/// WHY: ADR 0080 §3 retry semantics — ONE successful send publishes
/// exactly once (never republished), and a local error is retried up to
/// `1 + GRANT_REVOCATION_PUSH_SEND_RETRIES` attempts in total, stopping
/// at the first success.
#[tokio::test]
async fn push_send_retries_only_on_local_error() {
    use std::sync::atomic::{AtomicU32, Ordering};

    // One success: exactly one call.
    let calls = AtomicU32::new(0);
    let sent: Result<(), String> = super::send_push_with_local_retries(|_| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    })
    .await;
    assert!(sent.is_ok());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a successful send publishes exactly once"
    );

    // Local errors retry; the first success stops the loop.
    let calls = AtomicU32::new(0);
    let sent: Result<(), String> = super::send_push_with_local_retries(|attempt| {
        calls.fetch_add(1, Ordering::SeqCst);
        async move {
            if attempt < 2 {
                Err("local send error".to_string())
            } else {
                Ok(())
            }
        }
    })
    .await;
    assert!(sent.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // Persistent local errors stop at 1 + retries attempts.
    let calls = AtomicU32::new(0);
    let sent: Result<(), String> = super::send_push_with_local_retries(|_| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Err("local send error".to_string()) }
    })
    .await;
    assert!(sent.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1 + u32::from(GRANT_REVOCATION_PUSH_SEND_RETRIES)
    );
}

/// WHY: wire pinning — the prefix bytes and the payload-capability mapping
/// are frozen once released; the capability bit is positive-evidence
/// gated, so `required_for_payload` must also know the prefix (defence in
/// depth on generic send paths).
#[test]
fn prefix_and_capability_bit_are_pinned() {
    assert_eq!(
        GRANT_REVOCATION_PUSH_PREFIX,
        b"x0x-grant-revocation-push-v1\0"
    );
    assert_eq!(
        crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1,
        1 << 15
    );
    // ADR 0080 §1: the bit is ROUTE-GATED. No route means no bit; a
    // registered push route means the bit.
    assert!(!crate::dm::CapabilityRegistry::current()
        .supports(crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1));
    let no_routes: [&[u8]; 0] = [];
    assert!(!crate::dm::CapabilityRegistry::advertised(no_routes)
        .supports(crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1));
    assert!(
        !crate::dm::CapabilityRegistry::advertised([b"x0x-exec-v1\0".as_slice()])
            .supports(crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1)
    );
    let with_route = crate::dm::CapabilityRegistry::advertised([GRANT_REVOCATION_PUSH_PREFIX]);
    assert!(with_route.supports(crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1));
    assert_eq!(
        with_route.bits & !crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1,
        crate::dm::CapabilityRegistry::current().bits,
        "the route gate adds exactly the one bit"
    );
    let mut payload = GRANT_REVOCATION_PUSH_PREFIX.to_vec();
    payload.push(1);
    assert_eq!(
        crate::dm::CapabilityRegistry::required_for_payload(&payload),
        Some((
            crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1,
            "grant_revocation_push_v1"
        ))
    );
    assert!(crate::dm_inbox::recognized_production_typed_prefix(
        &payload
    ));
}
