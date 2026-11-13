#![cfg(test)]
//! #1107 Fix 4, PR 1: the `DeviceEnrollment` kind (0x05), its record
//! version rule, and SyncV1 protocol 3 with negotiation down to protocol 2.
//! Minting and applying the records come in PR 2.

use std::sync::Arc;

use super::tests::{clock, cross_enroll_for_tests, machine, names_value, owner_kp};
use super::*;

const OWNER_SEED: u8 = 7;

fn enrolled(machine_id: MachineId, at_ms: u64) -> DeviceEnrollmentState {
    let owner = owner_kp(OWNER_SEED);
    DeviceEnrollmentState::Enrolled {
        enrollment: OwnerEnrollment::sign(machine_id, &owner, at_ms, None).expect("sign"),
    }
}

fn removed(at_ms: u64) -> DeviceEnrollmentState {
    DeviceEnrollmentState::Removed {
        deleted_at_ms: at_ms,
    }
}

fn version(state: &DeviceEnrollmentState) -> u64 {
    device_enrollment_version(state).expect("version fits")
}

/// A signed `DeviceEnrollment` record for `machine_id` at its rule version.
fn device_record(machine_id: MachineId, state: DeviceEnrollmentState) -> VersionedRecord {
    let owner = owner_kp(OWNER_SEED);
    let clock = RecordClock {
        version: version(&state),
        signed_at_ms: 1,
        writer_machine: machine(1).0,
    };
    VersionedRecord::sign(
        SyncKind::DeviceEnrollment,
        &hex::encode(machine_id.0),
        &SyncValue::DeviceEnrollment { state },
        clock,
        &owner,
    )
    .expect("sign")
}

fn names_record(key: &str) -> VersionedRecord {
    VersionedRecord::sign(
        SyncKind::MachineNames,
        key,
        &names_value("n"),
        clock(1, 1, 1),
        &owner_kp(OWNER_SEED),
    )
    .expect("sign")
}

#[test]
fn record_version_is_twice_the_time_plus_one_for_a_removal() {
    let m = machine(9);
    assert_eq!(version(&enrolled(m, 1_000)), 2_000);
    assert_eq!(version(&removed(1_000)), 2_001);
    assert_eq!(version(&enrolled(m, 0)), 0);
    assert_eq!(version(&removed(0)), 1);
}

#[test]
fn removal_wins_at_the_same_millisecond_and_a_re_enrollment_needs_a_newer_time() {
    let m = machine(9);
    // Same millisecond: the removal outranks the enrollment.
    assert!(version(&removed(5_000)) > version(&enrolled(m, 5_000)));
    // A re-enrollment at the removal's millisecond does not undo it.
    assert!(version(&enrolled(m, 5_000)) < version(&removed(5_000)));
    // A re-enrollment one millisecond later does.
    assert!(version(&enrolled(m, 5_001)) > version(&removed(5_000)));
    // A later removal outranks an earlier enrollment, and the reverse.
    assert!(version(&removed(5_001)) > version(&enrolled(m, 5_000)));
    assert!(version(&enrolled(m, 5_002)) > version(&removed(5_001)));
    // The same state minted twice gives the same version.
    assert_eq!(version(&removed(7)), version(&removed(7)));
}

#[test]
fn record_version_refuses_a_time_whose_double_does_not_fit() {
    let max_fit = u64::MAX / 2;
    assert_eq!(device_enrollment_version(&removed(max_fit)), Some(u64::MAX));
    assert_eq!(
        device_enrollment_version(&removed(max_fit + 1)),
        None,
        "2·t overflows"
    );
    assert_eq!(device_enrollment_version(&removed(u64::MAX)), None);
}

#[test]
fn new_kind_and_value_go_last_so_the_old_encodings_do_not_change() {
    let tag = |kind: SyncKind| bincode::serialize(&kind).expect("encode");
    assert_eq!(tag(SyncKind::OwnerProfile), 0u32.to_le_bytes());
    assert_eq!(tag(SyncKind::MachineNames), 1u32.to_le_bytes());
    assert_eq!(tag(SyncKind::HomePointer), 2u32.to_le_bytes());
    assert_eq!(tag(SyncKind::IssuanceJournal), 3u32.to_le_bytes());
    assert_eq!(tag(SyncKind::DeviceEnrollment), 4u32.to_le_bytes());
    assert_eq!(SyncKind::DeviceEnrollment.as_u8(), 0x05);
    assert_eq!(SyncKind::from_u8(0x05), Some(SyncKind::DeviceEnrollment));

    let variant = |value: &SyncValue| bincode::serialize(value).expect("encode")[..4].to_vec();
    assert_eq!(
        variant(&SyncValue::OwnerProfile { human_name: None }),
        0u32.to_le_bytes()
    );
    assert_eq!(variant(&names_value("n")), 1u32.to_le_bytes());
    assert_eq!(
        variant(&SyncValue::IssuanceJournal {
            agent_id: String::new(),
            cert_digest: String::new(),
            issued_at: 0,
            not_after: None,
        }),
        3u32.to_le_bytes()
    );
    assert_eq!(
        variant(&SyncValue::DeviceEnrollment { state: removed(1) }),
        4u32.to_le_bytes()
    );
    // The old bytes of a MachineNames value are exactly the protocol-2 bytes.
    assert_eq!(
        bincode::serialize(&names_value("n")).expect("encode"),
        [
            1u32.to_le_bytes().as_slice(),
            &[1],
            &1u64.to_le_bytes(),
            b"n",
            &[0]
        ]
        .concat()
    );
}

#[test]
fn protocol_negotiation_runs_at_the_lower_version_and_accepts_only_2_or_3() {
    assert_eq!(SYNC_PROTOCOL_VERSION, 3);
    assert_eq!(negotiated_protocol(3, 3), Some(3));
    assert_eq!(negotiated_protocol(3, 2), Some(2));
    assert_eq!(negotiated_protocol(2, 3), Some(2));
    assert_eq!(negotiated_protocol(2, 2), Some(2));
    assert_eq!(negotiated_protocol(3, 1), None);
    assert_eq!(negotiated_protocol(3, 4), None);
    assert!(SyncKind::DeviceEnrollment.carried_at(3));
    assert!(!SyncKind::DeviceEnrollment.carried_at(2));
    for kind in SyncKind::ALL {
        if kind != SyncKind::DeviceEnrollment {
            assert!(kind.carried_at(2), "{kind:?} stays in protocol 2");
        }
    }
}

#[test]
fn a_device_record_must_follow_the_version_rule_and_name_its_key() {
    // Hex digits with letters, so the uppercase key differs.
    let m = MachineId([0xab; 32]);
    device_record(m, enrolled(m, 1_000))
        .verify()
        .expect("well-formed enrollment verifies");
    device_record(m, removed(1_000))
        .verify()
        .expect("well-formed removal verifies");

    let owner = owner_kp(OWNER_SEED);
    let sign = |key: &str, state: DeviceEnrollmentState, version: u64| {
        VersionedRecord::sign(
            SyncKind::DeviceEnrollment,
            key,
            &SyncValue::DeviceEnrollment { state },
            clock(version, 1, 1),
            &owner,
        )
        .expect("sign")
    };
    let key = hex::encode(m.0);
    // Version not from the timestamps (an enrollment claiming a removal's
    // rank).
    assert!(matches!(
        sign(&key, enrolled(m, 1_000), 2_001).verify(),
        Err(SyncError::MalformedFrame(_))
    ));
    // Enrollment of another machine under this key.
    assert!(matches!(
        sign(&key, enrolled(machine(8), 1_000), 2_000).verify(),
        Err(SyncError::MalformedFrame(_))
    ));
    // Key that is not a lowercase machine id hex.
    assert!(matches!(
        sign(&key.to_uppercase(), removed(1), 3).verify(),
        Err(SyncError::MalformedFrame(_))
    ));
    assert!(matches!(
        sign("home", removed(1), 3).verify(),
        Err(SyncError::MalformedFrame(_))
    ));
}

/// Two stores under one owner, cross-enrolled as machines 1 and 2.
async fn pair() -> (tempfile::TempDir, Arc<OwnerSyncStore>, Arc<OwnerSyncStore>) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let a = Arc::new(
        OwnerSyncStore::load(&dir.path().join("a"))
            .await
            .expect("a"),
    );
    let b = Arc::new(
        OwnerSyncStore::load(&dir.path().join("b"))
            .await
            .expect("b"),
    );
    cross_enroll_for_tests(&a, &b, &owner_kp(OWNER_SEED)).await;
    (dir, a, b)
}

/// Run one session between `a` (machine 1) and `b` (machine 2).
async fn session(
    a: &Arc<OwnerSyncStore>,
    b: &Arc<OwnerSyncStore>,
) -> (
    Result<SessionSummary, SyncError>,
    Result<SessionSummary, SyncError>,
) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let (mut a_recv, mut a_send) = tokio::io::split(server);
    let (mut b_recv, mut b_send) = tokio::io::split(client);
    let budget = Duration::from_secs(10);
    let (a_owner, b_owner) = (owner_kp(OWNER_SEED), owner_kp(OWNER_SEED));
    let (m1, m2) = (machine(1), machine(2));
    let a_side = run_sync_session_with_timeout(
        budget,
        &mut a_send,
        &mut a_recv,
        a,
        &a_owner,
        &m1,
        &m2,
        |_| {},
    );
    let b_side = run_sync_session_with_timeout(
        budget,
        &mut b_send,
        &mut b_recv,
        b,
        &b_owner,
        &m2,
        &m1,
        |_| {},
    );
    tokio::join!(a_side, b_side)
}

fn device_keys(records: &[VersionedRecord]) -> usize {
    records
        .iter()
        .filter(|r| r.kind == SyncKind::DeviceEnrollment)
        .count()
}

#[tokio::test]
async fn protocol_3_peers_sync_a_device_enrollment_record() {
    let (_dir, a, b) = pair().await;
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    a.commit_batch(vec![device_record(m, enrolled(m, 1_000))], &owner_id)
        .await
        .expect("store record");

    let (ra, rb) = session(&a, &b).await;
    ra.expect("a completes");
    let rb = rb.expect("b completes");
    assert_eq!(rb.accepted, 1);
    let key = hex::encode(m.0);
    let held = b.stored_value(SyncKind::DeviceEnrollment, &key).await;
    assert!(held.is_some(), "b holds the record; applying it is PR 2");
    assert_eq!(
        held,
        a.stored_value(SyncKind::DeviceEnrollment, &key).await,
        "b holds a's record unchanged"
    );
}

/// A node that speaks only protocol 2 refuses a `Hello` of version 3. The
/// protocol-3 side remembers the version 2 it received, so the next session
/// opens at 2 and completes. Only the four older kinds cross; the device
/// record stays on the protocol-3 side.
#[tokio::test]
async fn a_protocol_2_peer_still_completes_a_session() {
    let (_dir, a, b) = pair().await;
    b.speak_only_protocol_for_testing(2);
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    a.commit_batch(
        vec![
            device_record(m, enrolled(m, 1_000)),
            names_record(&hex::encode(machine(1).0)),
        ],
        &owner_id,
    )
    .await
    .expect("a records");
    b.commit_batch(vec![names_record(&hex::encode(machine(2).0))], &owner_id)
        .await
        .expect("b records");

    // First meeting: a opens at 3; the protocol-2 node refuses it.
    let (ra, rb) = session(&a, &b).await;
    assert!(
        matches!(
            rb,
            Err(SyncError::ProtocolVersion {
                local: 2,
                remote: 3
            })
        ),
        "{rb:?}"
    );
    assert!(ra.is_err(), "the session fails on the first meeting");

    // Next session: a opens at 2 and the session completes both ways.
    let (ra, rb) = session(&a, &b).await;
    let ra = ra.expect("a completes at protocol 2");
    let rb = rb.expect("the protocol-2 peer completes");
    assert_eq!(ra.shipped, 1, "a ships only the names record");
    assert_eq!(rb.accepted, 1);
    assert_eq!(ra.accepted, 1, "a takes b's names record");
    let b_records = b.records_snapshot().await;
    assert_eq!(
        device_keys(&b_records),
        0,
        "kind 0x05 is never sent to a v2 peer"
    );
    assert_eq!(b_records.len(), 2);
    assert_eq!(device_keys(&a.records_snapshot().await), 1);
}

/// After the peer moves to protocol 3, the remembered version 2 lasts one
/// more session: that session runs at 2 and completes, so both sides
/// remember 3, and the next session runs at 3 and carries the device
/// record.
#[tokio::test]
async fn a_peer_that_moves_to_protocol_3_is_met_at_3_from_the_next_session() {
    let (dir, a, b) = pair().await;
    b.speak_only_protocol_for_testing(2);
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    a.commit_batch(vec![device_record(m, enrolled(m, 1_000))], &owner_id)
        .await
        .expect("a record");
    let _ = session(&a, &b).await; // a learns: b speaks 2

    // b "upgrades": a fresh protocol-3 store on the same files.
    drop(b);
    let b = Arc::new(
        OwnerSyncStore::load(&dir.path().join("b"))
            .await
            .expect("reload b"),
    );
    let (ra, rb) = session(&a, &b).await;
    rb.expect("b completes at 2");
    ra.expect("a completes at 2");
    assert_eq!(device_keys(&b.records_snapshot().await), 0);

    let (ra, rb) = session(&a, &b).await;
    ra.expect("a completes at 3");
    assert_eq!(rb.expect("b completes at 3").accepted, 1);
    assert_eq!(device_keys(&b.records_snapshot().await), 1);
}

/// A peer that opens at protocol 2 and then sends a kind 0x05 version entry
/// is refused: a protocol-2 session never carries the new kind.
#[tokio::test]
async fn a_protocol_2_session_refuses_a_device_enrollment_entry() {
    let (_dir, a, _b) = pair().await;
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (mut a_recv, mut a_send) = tokio::io::split(server);
    let (mut p_recv, mut p_send) = tokio::io::split(client);
    let owner = owner_kp(OWNER_SEED);
    let owner_id = owner.user_id().0;

    let peer = tokio::spawn(async move {
        let signer = owner_kp(OWNER_SEED);
        write_frame(
            &mut p_send,
            &SyncFrame::Hello {
                protocol_version: 2,
                machine_id: machine(2).0,
                owner_user_id: owner_id,
                nonce: fresh_nonce(),
            },
        )
        .await?;
        let a_nonce = match read_frame(&mut p_recv).await? {
            SyncFrame::Hello { nonce, .. } => nonce,
            other => return Err(SyncError::MalformedFrame(format!("{other:?}"))),
        };
        let msg = proof_message(&a_nonce, &machine(2).0, &machine(1).0, &owner_id);
        let sig = sign_with_ml_dsa(signer.secret_key(), &msg)
            .map_err(|e| SyncError::ChallengeFailed(format!("{e:?}")))?;
        write_frame(
            &mut p_send,
            &SyncFrame::Proof {
                signature: sig.as_bytes().to_vec(),
            },
        )
        .await?;
        let _ = read_frame(&mut p_recv).await?; // a's proof
        write_frame(
            &mut p_send,
            &SyncFrame::VersionVector {
                kinds: vec![KindVersions {
                    kind: SyncKind::DeviceEnrollment,
                    entries: vec![(hex::encode(machine(9).0), clock(2, 1, 2), [0; 32])],
                }],
            },
        )
        .await?;
        // Keep the pipe open while a refuses.
        while read_frame(&mut p_recv).await.is_ok() {}
        Ok::<(), SyncError>(())
    });

    let err = run_sync_session_with_timeout(
        Duration::from_secs(10),
        &mut a_send,
        &mut a_recv,
        &a,
        &owner,
        &machine(1),
        &machine(2),
        |_| {},
    )
    .await
    .expect_err("kind 0x05 in a protocol-2 session must be refused");
    assert!(matches!(err, SyncError::MalformedFrame(_)), "{err:?}");
    drop((a_send, a_recv));
    let _ = peer.await;
}
