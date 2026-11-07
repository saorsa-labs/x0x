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

    // An oversize payload is refused before decode.
    let mut oversize = GRANT_REVOCATION_PUSH_PREFIX.to_vec();
    oversize.resize(MAX_GRANT_REVOCATION_PUSH_BYTES + 1, 0xaa);
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
    let record = signed_record(&owner, [0x49; 32], now_unix() + 86_400);
    let receiver = Receiver::new();
    let payload = encode_grant_revocation_push(&record).expect("encode");
    assert_eq!(
        receiver.handle(AgentId([0x06; 32]), &payload).await,
        PushOutcome::Ingested { inserted: true }
    );
    // The same record through the shared records ingest (the gossip path
    // after batch decode) inserts nothing new.
    let inserted = crate::ingest_share_grant_revocation_records(
        &receiver.owner_trust,
        &receiver.set,
        Some(receiver.dir.path()),
        vec![record],
    )
    .await;
    assert!(!inserted, "a pushed record is a gossip duplicate");
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
        1 << 14
    );
    assert!(crate::dm::CapabilityRegistry::current()
        .supports(crate::dm::CapabilityRegistry::GRANT_REVOCATION_PUSH_V1));
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
