//! ADR 0079 §1 wire and handler tests: the names signature binds the grant
//! digest and the owner key, the envelope decodes strictly within its
//! bounds, and the v2 handler stores the grant idempotently with a v1
//! delivery while names land as defaults or suggestions by the contact
//! gate.

use super::*;
use crate::dm_inbox::{DmTypedPayload, DmTypedPayloadCompletion};
use crate::identity::{AgentId, MachineId, UserKeypair};
use crate::names::NameStore;
use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn grant_for(owner: &UserKeypair, grantee: AgentId) -> ShareGrant {
    ShareGrant::sign(
        owner,
        [0x11; 32],
        Grantee::Agent(grantee),
        vec![AgentId([0x22; 32])],
        vec![ShareCap::Dm],
        0,
        now() + 3600,
    )
    .expect("sign grant")
}

fn names_section() -> GrantNames {
    GrantNames {
        owner_name: Some("Bob Smith".to_string()),
        machines: vec![GrantMachineName {
            machine_id: MachineId([0x33; 32]),
            machine_name: "Studio Mac".to_string(),
        }],
    }
}

/// The local hosting evidence for the test grant's machine.
fn hosts() -> std::collections::BTreeSet<[u8; 32]> {
    std::collections::BTreeSet::from([[0x33; 32]])
}

fn typed(payload: Vec<u8>) -> DmTypedPayload {
    DmTypedPayload {
        sender: AgentId([0x44; 32]),
        machine_id: MachineId([0x55; 32]),
        payload,
        verified: true,
        trust_decision: None,
        received_at_unix_ms: 0,
        request_id: [0x66; 16],
        completion: None,
    }
}

/// WHY: the envelope round-trips, verifies, and refuses trailing or
/// non-canonical bytes and anything over the 48 KiB bound — the strict
/// rules every typed grant route enforces.
#[test]
fn v2_envelope_round_trips_and_decodes_strictly() {
    let owner = UserKeypair::generate().expect("owner key");
    let envelope = ShareGrantV2::sign(
        &owner,
        grant_for(&owner, AgentId([0x44; 32])),
        names_section(),
    )
    .expect("sign names");
    envelope.verify().expect("verify");
    let payload = envelope.to_dm_payload().expect("encode");
    assert!(payload.starts_with(SHARE_GRANT_V2_DM_PREFIX));
    let decoded = ShareGrantV2::from_dm_payload(&payload).expect("decode");
    assert_eq!(decoded, envelope);

    let mut trailing = payload.clone();
    trailing.push(0);
    assert!(matches!(
        ShareGrantV2::from_dm_payload(&trailing),
        Err(ShareGrantError::Malformed(_))
    ));
    let mut oversized = payload.clone();
    oversized.extend_from_slice(&vec![0u8; MAX_SHARE_GRANT_V2_BYTES]);
    assert!(matches!(
        ShareGrantV2::from_dm_payload(&oversized),
        Err(ShareGrantError::Malformed(_))
    ));
    assert!(matches!(
        ShareGrantV2::from_dm_payload(b"x0x-sharegrant-v1\0junk"),
        Err(ShareGrantError::Malformed(_))
    ));
}

/// WHY (ADR 0079 validation): a tampered name fails, and names cannot be
/// moved to another grant — the signature covers the grant digest.
#[test]
fn names_signature_binds_the_grant_and_the_names() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");

    let mut tampered = envelope.clone();
    tampered.names.owner_name = Some("Mallory".to_string());
    assert!(matches!(
        tampered.verify(),
        Err(ShareGrantError::BadSignature(_))
    ));

    // Same owner, different grant: swapped names must fail.
    let other_grant = ShareGrant::sign(
        &owner,
        [0x99; 32],
        Grantee::Agent(grantee),
        vec![AgentId([0x22; 32])],
        vec![ShareCap::Dm],
        0,
        now() + 3600,
    )
    .expect("sign grant");
    let mut swapped = envelope.clone();
    swapped.grant = other_grant;
    assert!(matches!(
        swapped.verify(),
        Err(ShareGrantError::BadSignature(_))
    ));

    // A names section signed by a key that is not the grant owner is
    // refused at signing time.
    let mallory = UserKeypair::generate().expect("other key");
    assert!(matches!(
        ShareGrantV2::sign(&mallory, grant_for(&owner, grantee), names_section()),
        Err(ShareGrantError::Invalid(_))
    ));
}

/// WHY (ADR 0079 validation): the structural bounds hold — an empty
/// section, an oversized name, too many machines, and unsorted machine ids
/// are all invalid.
#[test]
fn names_section_bounds_hold() {
    let empty = GrantNames {
        owner_name: None,
        machines: Vec::new(),
    };
    assert!(empty.validate().is_err());
    let oversized = GrantNames {
        owner_name: Some("x".repeat(MAX_GRANT_NAME_BYTES + 1)),
        machines: Vec::new(),
    };
    assert!(oversized.validate().is_err());
    let untrimmed = GrantNames {
        owner_name: Some(" Bob ".to_string()),
        machines: Vec::new(),
    };
    assert!(untrimmed.validate().is_err());
    let machine = |b: u8| GrantMachineName {
        machine_id: MachineId([b; 32]),
        machine_name: "m".to_string(),
    };
    let too_many = GrantNames {
        owner_name: None,
        machines: (0..=MAX_GRANT_AGENTS).map(|i| machine(i as u8)).collect(),
    };
    assert!(too_many.validate().is_err());
    let unsorted = GrantNames {
        owner_name: None,
        machines: vec![machine(2), machine(1)],
    };
    assert!(unsorted.validate().is_err());
    let duplicate = GrantNames {
        owner_name: None,
        machines: vec![machine(1), machine(1)],
    };
    assert!(duplicate.validate().is_err());
    let sorted = GrantNames {
        owner_name: None,
        machines: vec![machine(1), machine(2)],
    };
    sorted.validate().expect("sorted unique machines are valid");
}

/// WHY (ADR 0079 §2): a trusted owner's v2 delivery stores the grant AND
/// applies the defaults; a v1 copy of the same grant is an idempotent
/// `Duplicate`; and a replay of the v2 bytes is a `Duplicate` that leaves
/// the names unchanged.
#[tokio::test]
async fn v2_delivery_stores_grant_and_applies_defaults_for_a_trusted_owner() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let store = ShareGrantStore::in_memory(grantee, None);
    let names = NameStore::in_memory();
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");
    let payload = envelope.to_dm_payload().expect("encode");

    let outcome = handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        None,
        |_| async { true },
        |_| async { hosts() },
        typed(payload.clone()),
    )
    .await
    .expect("v2 accepted");
    assert_eq!(outcome, DmTypedPayloadCompletion::Inserted);
    assert_eq!(
        names
            .owner("bob-smith")
            .await
            .expect("store usable")
            .map(|b| b.user_id),
        Some(owner.user_id())
    );
    let pin = names
        .get_pin("machine:studio-mac.bob-smith")
        .await
        .expect("store usable")
        .expect("machine pin recorded");
    assert_eq!(pin.id, [0x33; 32]);

    // Replay: Duplicate, nothing rebinds.
    let outcome = handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        None,
        |_| async { true },
        |_| async { hosts() },
        typed(payload),
    )
    .await
    .expect("replay accepted");
    assert_eq!(outcome, DmTypedPayloadCompletion::Duplicate);

    // A v1 delivery of the same grant is the same logical grant.
    let v1 = envelope.grant.to_dm_payload().expect("v1 encode");
    let outcome = crate::share_grant::handle_share_grant_dm(Some(&store), typed(v1))
        .await
        .expect("v1 duplicate accepted");
    assert_eq!(outcome, DmTypedPayloadCompletion::Duplicate);
}

/// WHY (ADR 0079 §2 contact gate): a stranger's v2 delivery stores the
/// grant but only SUGGESTS the names; nothing binds. The local owner's own
/// grant applies no names at all (`me` is reserved).
#[tokio::test]
async fn v2_delivery_from_a_stranger_only_suggests() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let store = ShareGrantStore::in_memory(grantee, None);
    let names = NameStore::in_memory();
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");
    let payload = envelope.to_dm_payload().expect("encode");

    handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        None,
        |_| async { false },
        |_| async { hosts() },
        typed(payload),
    )
    .await
    .expect("v2 accepted");
    assert!(
        names
            .owner("bob-smith")
            .await
            .expect("store usable")
            .is_none(),
        "a stranger's default must not bind"
    );
    let (suggestions, conflicts) = names.pending().await.expect("store usable");
    assert_eq!(suggestions.len(), 1);
    assert!(suggestions.contains_key("bob-smith"));
    assert!(conflicts.is_empty());

    // Accept applies it later.
    let applied = names
        .accept_suggestion("bob-smith", now())
        .await
        .expect("accept");
    assert!(applied.owner_bound, "{applied:?}");
    assert_eq!(applied.machine_pins, ["machine:studio-mac.bob-smith"]);
}

/// WHY (ADR 0079 §2/§3): names from the local owner's own grant are
/// skipped, and a tampered envelope is refused outright — the grant is NOT
/// stored (Malformed refuses the whole envelope, ACK withheld).
#[tokio::test]
async fn own_grants_skip_names_and_a_bad_signature_refuses_the_envelope() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let store = ShareGrantStore::in_memory(grantee, Some(owner.user_id()));
    let names = NameStore::in_memory();
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");

    // Own grant: stored, names skipped.
    handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        Some(owner.user_id()),
        |_| async { true },
        |_| async { hosts() },
        typed(envelope.to_dm_payload().expect("encode")),
    )
    .await
    .expect("own grant accepted");
    let (suggestions, _) = names.pending().await.expect("store usable");
    assert!(
        names
            .owner("bob-smith")
            .await
            .expect("store usable")
            .is_none()
            && suggestions.is_empty(),
        "own grants carry no name defaults"
    );

    // Tampered names: the whole envelope is refused, nothing stored.
    let other_store = ShareGrantStore::in_memory(grantee, None);
    let mut tampered = envelope.clone();
    tampered.names.owner_name = Some("Mallory".to_string());
    let err = handle_share_grant_v2_dm(
        Some(&other_store),
        None,
        &names,
        None,
        |_| async { true },
        |_| async { hosts() },
        typed(tampered.to_dm_payload().expect("encode")),
    )
    .await
    .expect_err("tampered envelope refused");
    assert!(err.contains("signature"), "{err}");
    assert!(
        other_store
            .grants(crate::share_grant::GrantRole::Received)
            .is_empty(),
        "a refused envelope must store nothing"
    );
}

// ─── Sender side (ADR 0079 §1 "Who gets v2") ────────────────────────────────

/// WHY: the persisted attachment must rebuild the EXACT v2 bytes and the
/// same logical request id, so an outbox retry is byte-identical and
/// idempotent (ADR 0079 §1).
#[test]
fn attachment_rebuilds_the_exact_v2_bytes() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");
    let (payload, request_id) = grant_delivery_request_v2(&envelope).expect("encode");
    let rebuilt = ShareGrantV2::from_parts(envelope.grant.clone(), envelope.attachment());
    let (payload2, request_id2) = grant_delivery_request_v2(&rebuilt).expect("re-encode");
    assert_eq!(payload, payload2, "same bytes");
    assert_eq!(request_id, request_id2, "same logical request");
    // And distinct from the v1 request, so a v1 retry never masquerades.
    let (v1_payload, v1_id) =
        crate::share_grant::grant_delivery_request(&envelope.grant).expect("v1");
    assert_ne!(payload, v1_payload);
    assert_ne!(request_id, v1_id);
}

/// WHY (ADR 0079 §1): the grant names only machines that are (a) currently
/// enrolled by THIS owner, (b) carry a synced, valid machine_name, and
/// (c) host a granted agent — sorted by id and unique.
#[test]
fn grant_machine_names_lists_enrolled_named_hosting_machines_only() {
    let owner = UserKeypair::generate().expect("owner key");
    let stranger = UserKeypair::generate().expect("stranger key");
    let now_ms = 1_900_000_000_000u64;
    let hosting_named = MachineId([2; 32]);
    let hosting_unnamed = MachineId([1; 32]);
    let idle_named = MachineId([3; 32]);
    let foreign = MachineId([4; 32]);
    let expired = MachineId([5; 32]);
    let enrollments = vec![
        crate::owner_sync::OwnerEnrollment::sign(hosting_named, &owner, now_ms - 10, None)
            .expect("enroll"),
        crate::owner_sync::OwnerEnrollment::sign(hosting_unnamed, &owner, now_ms - 10, None)
            .expect("enroll"),
        crate::owner_sync::OwnerEnrollment::sign(idle_named, &owner, now_ms - 10, None)
            .expect("enroll"),
        crate::owner_sync::OwnerEnrollment::sign(foreign, &stranger, now_ms - 10, None)
            .expect("enroll"),
        crate::owner_sync::OwnerEnrollment::sign(
            expired,
            &owner,
            now_ms - 10_000_000,
            Some(now_ms - 5_000_000),
        )
        .expect("enroll"),
    ];
    let named = vec![
        (hosting_named, "Studio Mac".to_string()),
        (idle_named, "Idle Box".to_string()),
        (foreign, "Foreign".to_string()),
        (expired, "Old Box".to_string()),
        (MachineId([6; 32]), "Unenrolled".to_string()),
    ];
    let a = |b: u8| AgentId([b; 32]);
    let hosts = vec![
        (a(0x21), hosting_named),
        (a(0x22), hosting_unnamed),
        (a(0x23), foreign),
        (a(0x24), expired),
        (a(0x25), MachineId([6; 32])),
    ];
    let machines = grant_machine_names(&owner.user_id(), &enrollments, &named, &hosts, now_ms);
    assert_eq!(
        machines,
        vec![GrantMachineName {
            machine_id: hosting_named,
            machine_name: "Studio Mac".to_string(),
        }],
        "only the enrolled, named, hosting machine qualifies"
    );
}

/// WHY (ADR 0079 §1): flagged recipients get the v2 payload, everyone else
/// the v1 payload; a FAILED v2 recipient is queued WITH its names and the
/// outbox retry resends the identical v2 bytes.
#[tokio::test]
async fn classified_delivery_sends_v2_to_flagged_recipients_and_retries_same_bytes() {
    use std::sync::Mutex;
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let shared = AgentId([0x22; 32]);
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");
    let grant = envelope.grant.clone();
    let revocations = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
    let outbox =
        crate::share_grant::outbox::GrantRedeliveryOutbox::in_memory(Some(owner.user_id()));
    let sent: Mutex<Vec<(AgentId, Vec<u8>)>> = Mutex::new(Vec::new());
    // The grant's window is anchored on the real clock (`grant_for`), so
    // the queue clock must be too, or the enqueue refuses it as expired.
    let now = now();

    // The grantee (flagged v2) is offline; the shared daemon (v1) ACKs.
    let deliveries = crate::share_grant::deliver_grant_via_classified(
        &grant,
        Some(&envelope),
        &[(grantee, true), (shared, false)],
        Some(&outbox),
        &revocations,
        || now,
        |recipient, payload, _id| {
            sent.lock().expect("lock").push((recipient, payload));
            async move {
                if recipient == grantee {
                    Err("offline".to_string())
                } else {
                    Ok(())
                }
            }
        },
    )
    .await;
    {
        let sent = sent.lock().expect("lock");
        let v2 = sent.iter().find(|(r, _)| *r == grantee).expect("v2 send");
        assert!(v2.1.starts_with(SHARE_GRANT_V2_DM_PREFIX));
        let v1 = sent.iter().find(|(r, _)| *r == shared).expect("v1 send");
        assert!(v1.1.starts_with(crate::share_grant::SHARE_GRANT_DM_PREFIX));
    }
    let grantee_delivery = deliveries
        .iter()
        .find(|d| d.agent == hex::encode(grantee.as_bytes()))
        .expect("grantee row");
    assert_eq!(grantee_delivery.envelope, "v2");
    assert!(!grantee_delivery.delivered);
    assert!(grantee_delivery.queued, "{grantee_delivery:?}");
    let shared_delivery = deliveries
        .iter()
        .find(|d| d.agent == hex::encode(shared.as_bytes()))
        .expect("shared row");
    assert_eq!(shared_delivery.envelope, "v1");
    assert!(shared_delivery.delivered);

    // The outbox retry resends the SAME v2 bytes.
    let first_v2 = sent
        .lock()
        .expect("lock")
        .iter()
        .find(|(r, _)| *r == grantee)
        .expect("v2 send")
        .1
        .clone();
    sent.lock().expect("lock").clear();
    let report = outbox
        .step(now + 60, &revocations, |recipient, payload, _id| {
            sent.lock().expect("lock").push((recipient, payload));
            async move { Ok(()) }
        })
        .await;
    assert_eq!(report.delivered, 1, "{report:?}");
    let resent = sent.lock().expect("lock");
    assert_eq!(resent.len(), 1);
    assert_eq!(resent[0].0, grantee);
    assert_eq!(resent[0].1, first_v2, "retry resends the same v2 bytes");
}

/// WHY (ADR 0079 §1): a recipient flagged v2 without a names envelope is a
/// caller bug — it gets a per-recipient error, nothing is sent to it, and
/// the other recipients still deliver.
#[tokio::test]
async fn a_v2_flag_without_an_envelope_fails_only_that_recipient() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let shared = AgentId([0x22; 32]);
    let grant = grant_for(&owner, grantee);
    let revocations = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
    let deliveries = crate::share_grant::deliver_grant_via_classified(
        &grant,
        None,
        &[(grantee, true), (shared, false)],
        None,
        &revocations,
        || 1_900_000_000,
        |recipient, _payload, _id| async move {
            assert_ne!(recipient, grantee, "nothing must be sent to the v2 flag");
            Ok(())
        },
    )
    .await;
    let grantee_delivery = deliveries
        .iter()
        .find(|d| d.agent == hex::encode(grantee.as_bytes()))
        .expect("grantee row");
    assert!(!grantee_delivery.delivered);
    assert!(grantee_delivery
        .error
        .as_deref()
        .is_some_and(|e| e.contains("without a names envelope")));
    let shared_delivery = deliveries
        .iter()
        .find(|d| d.agent == hex::encode(shared.as_bytes()))
        .expect("shared row");
    assert!(shared_delivery.delivered);
}

/// WHY (#1826 review, MEDIUM 1): a name store that failed to load fails
/// every write until names.json is repaired. If that withheld the ACK, the
/// sender would retry forever. The grant is stored and ACKed; the names are
/// skipped.
#[tokio::test]
async fn unloadable_name_store_acks_the_grant_and_skips_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("names.json");
    std::fs::write(&path, b"{ not json").expect("write corrupt names.json");
    let names = NameStore::load(path).await;
    assert!(
        names.load_error().is_some(),
        "control: the store must not load"
    );

    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let store = ShareGrantStore::in_memory(grantee, None);
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");
    let outcome = handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        None,
        |_| async { true },
        |_| async { hosts() },
        typed(envelope.to_dm_payload().expect("encode")),
    )
    .await
    .expect("grant ACKed although the name store is unusable");
    assert_eq!(outcome, DmTypedPayloadCompletion::Inserted);
    assert_eq!(
        store.grants(crate::share_grant::GrantRole::Received).len(),
        1,
        "the grant is stored"
    );
}

/// WHY (#1826 review, LOW): a name-store WRITE failure withholds the ACK,
/// and the sender's replay of the same bytes is a grant `Duplicate` that
/// applies the names once the store can write again.
#[tokio::test]
async fn name_store_write_failure_then_replay_is_duplicate_with_names_applied() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Load while the parent directory is missing (an empty store), then
    // put a regular file where the parent should be: the write fails for
    // any user, root included.
    let blocker = dir.path().join("blocker");
    let names = NameStore::load(blocker.join("names.json")).await;
    assert!(names.load_error().is_none(), "a missing file loads empty");
    std::fs::write(&blocker, b"not a directory").expect("write blocker");

    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let store = ShareGrantStore::in_memory(grantee, None);
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");
    let payload = envelope.to_dm_payload().expect("encode");

    let err = handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        None,
        |_| async { true },
        |_| async { hosts() },
        typed(payload.clone()),
    )
    .await
    .expect_err("a name-store write failure withholds the ACK");
    assert!(err.contains("not durable"), "{err}");
    assert_eq!(
        store.grants(crate::share_grant::GrantRole::Received).len(),
        1,
        "the grant itself is stored before the names"
    );

    std::fs::remove_file(&blocker).expect("remove blocker");
    std::fs::create_dir(&blocker).expect("create the store directory");
    let outcome = handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        None,
        |_| async { true },
        |_| async { hosts() },
        typed(payload),
    )
    .await
    .expect("replay ACKed");
    assert_eq!(outcome, DmTypedPayloadCompletion::Duplicate);
    assert!(
        names
            .owner("bob-smith")
            .await
            .expect("store usable")
            .is_some(),
        "the replay applies the owner name"
    );
    assert!(
        names
            .get_pin("machine:studio-mac.bob-smith")
            .await
            .expect("store usable")
            .is_some(),
        "the replay applies the machine name"
    );
}

/// WHY (#1826 review, LOW): a revoked grant on the v2 path is refused and
/// not stored, and no names are applied.
#[tokio::test]
async fn revoked_grant_on_the_v2_path_is_refused() {
    use crate::revocation::{
        RevocationRecord, RevocationSet, RevokedSubject, ShareGrantRevocation,
    };
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let store = ShareGrantStore::in_memory(grantee, None);
    let names = NameStore::in_memory();
    let grant = grant_for(&owner, grantee);
    let record = RevocationRecord::sign(
        RevokedSubject::ShareGrant(ShareGrantRevocation {
            grant_id: grant.grant_id,
            owner: owner.user_id(),
            grant_expiry: grant.expiry,
        }),
        owner.public_key(),
        owner.secret_key(),
        now(),
        None,
    )
    .expect("sign revocation");
    let mut set = RevocationSet::new();
    set.verify_and_insert(record, None)
        .expect("insert revocation");
    let revocations = tokio::sync::RwLock::new(set);
    let envelope = ShareGrantV2::sign(&owner, grant, names_section()).expect("sign");

    let err = handle_share_grant_v2_dm(
        Some(&store),
        Some(&revocations),
        &names,
        None,
        |_| async { true },
        |_| async { hosts() },
        typed(envelope.to_dm_payload().expect("encode")),
    )
    .await
    .expect_err("a revoked grant is refused");
    assert!(err.contains("revoked"), "{err}");
    assert!(store
        .grants(crate::share_grant::GrantRole::Received)
        .is_empty());
    let (suggestions, _) = names.pending().await.expect("store usable");
    assert!(
        names
            .owner("bob-smith")
            .await
            .expect("store usable")
            .is_none()
            && suggestions.is_empty(),
        "a revoked grant applies no names"
    );
}

/// WHY (#1826 review, MEDIUM 2): a signed machine-name default is only a
/// claim. Without local hosting evidence for a granted agent, a trusted
/// owner's machine default is held as a suggestion, not pinned, so it can
/// never squat a label on an unrelated machine.
#[tokio::test]
async fn machine_default_without_hosting_evidence_is_only_suggested() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let store = ShareGrantStore::in_memory(grantee, None);
    let names = NameStore::in_memory();
    let envelope =
        ShareGrantV2::sign(&owner, grant_for(&owner, grantee), names_section()).expect("sign");

    handle_share_grant_v2_dm(
        Some(&store),
        None,
        &names,
        None,
        |_| async { true },
        |_| async { std::collections::BTreeSet::new() },
        typed(envelope.to_dm_payload().expect("encode")),
    )
    .await
    .expect("v2 accepted");
    assert!(
        names
            .owner("bob-smith")
            .await
            .expect("store usable")
            .is_some(),
        "the owner name still applies"
    );
    assert!(
        names
            .get_pin("machine:studio-mac.bob-smith")
            .await
            .expect("store usable")
            .is_none(),
        "no pin without hosting evidence"
    );
    let (suggestions, _) = names.pending().await.expect("store usable");
    let held = suggestions
        .get("bob-smith")
        .expect("machine held as a suggestion");
    assert_eq!(
        held.machines,
        vec![(MachineId([0x33; 32]), "Studio Mac".to_string())]
    );

    // The local owner can still confirm it.
    let applied = names
        .accept_suggestion("bob-smith", now())
        .await
        .expect("accept");
    assert_eq!(applied.machine_pins, ["machine:studio-mac.bob-smith"]);
}

/// WHY (#1831 review, LOW 2): a v2 recipient whose payload could not be
/// built is reported and NOT queued. A queued row without its envelope
/// would resend as v1 while the response said v2.
#[tokio::test]
async fn an_unbuilt_v2_payload_is_never_queued() {
    let owner = UserKeypair::generate().expect("owner key");
    let grantee = AgentId([0x44; 32]);
    let grant = grant_for(&owner, grantee);
    let revocations = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
    let outbox =
        crate::share_grant::outbox::GrantRedeliveryOutbox::in_memory(Some(owner.user_id()));
    let now = now();
    let deliveries = crate::share_grant::deliver_grant_via_classified(
        &grant,
        None,
        &[(grantee, true)],
        Some(&outbox),
        &revocations,
        || now,
        |_recipient, _payload, _id| async { Err("must not be called".to_string()) },
    )
    .await;
    assert_eq!(deliveries.len(), 1);
    assert!(!deliveries[0].delivered);
    assert!(!deliveries[0].queued, "{:?}", deliveries[0]);
    assert_eq!(deliveries[0].envelope, "v2");
    assert!(outbox.is_empty(), "nothing queued for an unbuilt payload");
}

/// WHY (#1831 review, LOW 1): this machine's name comes from the profile,
/// not from a synced MachineNames record that may be stale. With no profile
/// name, this machine is not named even when a synced record names it.
#[test]
fn own_machine_name_comes_from_the_profile_not_a_synced_record() {
    let owner = UserKeypair::generate().expect("owner key");
    let now_ms = 1_900_000_000_000u64;
    let own = MachineId([7; 32]);
    let other = MachineId([8; 32]);
    let enrollments = vec![
        crate::owner_sync::OwnerEnrollment::sign(own, &owner, now_ms - 10, None).expect("enroll"),
        crate::owner_sync::OwnerEnrollment::sign(other, &owner, now_ms - 10, None).expect("enroll"),
    ];
    let synced = vec![
        (own, "Old Studio".to_string()),
        (other, "Laptop".to_string()),
    ];
    let hosts = vec![(AgentId([0x22; 32]), own), (AgentId([0x23; 32]), other)];
    let machines = assemble_grant_machine_names(
        &owner.user_id(),
        &enrollments,
        &synced,
        &hosts,
        own,
        Some("New Studio".to_string()),
        now_ms,
    );
    assert_eq!(
        machines,
        vec![
            GrantMachineName {
                machine_id: own,
                machine_name: "New Studio".to_string(),
            },
            GrantMachineName {
                machine_id: other,
                machine_name: "Laptop".to_string(),
            },
        ]
    );
    let machines = assemble_grant_machine_names(
        &owner.user_id(),
        &enrollments,
        &synced,
        &hosts,
        own,
        None,
        now_ms,
    );
    assert_eq!(
        machines,
        vec![GrantMachineName {
            machine_id: other,
            machine_name: "Laptop".to_string(),
        }],
        "a stale synced name is never used for this machine"
    );
}

/// WHY (ADR 0093: one regression test per bit): `share_grant_names_v1` is
/// registry bit 14, this release advertises it, and it is the bit a v2
/// grant payload requires.
#[test]
fn share_grant_names_v1_is_registry_bit_14() {
    use crate::dm::CapabilityRegistry;
    assert_eq!(CapabilityRegistry::SHARE_GRANT_NAMES_V1, 1 << 14);
    assert!(
        CapabilityRegistry::current().supports(CapabilityRegistry::SHARE_GRANT_NAMES_V1),
        "this release advertises the names bit"
    );
    let mut payload = SHARE_GRANT_V2_DM_PREFIX.to_vec();
    payload.extend_from_slice(b"body");
    assert_eq!(
        CapabilityRegistry::required_for_payload(&payload),
        Some((1 << 14, "share_grant_names_v1"))
    );
    assert_ne!(
        CapabilityRegistry::SHARE_GRANT_NAMES_V1,
        CapabilityRegistry::SHARE_GRANT_V1,
        "the v2 envelope has its own bit"
    );
}
