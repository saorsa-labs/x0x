#![cfg(test)]
//! #1107 Fix 4: the `DeviceEnrollment` kind (0x05), its record version
//! rule, SyncV1 protocol 3 with negotiation down to protocol 2 (PR 1), and
//! minting and applying the records (PR 2).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        variant(&SyncValue::HomePointer {
            group_id: String::new(),
            policy: GroupPolicy::default(),
            roster: vec![],
            primary_agent: String::new(),
            provisioned_at_ms: 0,
        }),
        2u32.to_le_bytes()
    );
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
    assert!(held.is_some(), "b holds the record");
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

/// The record shape of a binary built before kind 0x05: the same
/// fields, with kind and value enums that end at `IssuanceJournal`.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub(super) enum OldKind {
    OwnerProfile,
    MachineNames,
    HomePointer,
    IssuanceJournal,
}
#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub(super) enum OldValue {
    OwnerProfile {
        human_name: Option<String>,
    },
    MachineNames {
        display_name: Option<String>,
        machine_name: Option<String>,
    },
    HomePointer {
        group_id: String,
        policy: GroupPolicy,
        roster: Vec<HomeRosterEntry>,
        primary_agent: String,
        provisioned_at_ms: u64,
    },
    IssuanceJournal {
        agent_id: String,
        cert_digest: String,
        issued_at: u64,
        not_after: Option<u64>,
    },
}
#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub(super) struct OldRecord {
    kind: OldKind,
    key: String,
    value: OldValue,
    clock: RecordClock,
    owner_public_key: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(serde::Deserialize)]
pub(super) struct OldPersisted {
    pub(super) records: Vec<OldRecord>,
}

/// After a kind 0x05 record is stored, `records.json` holds only the four
/// older kinds and still decodes with the four-kind decoder of a binary
/// built before 0x05; the record is in `enrollment_records.json`, and a
/// reload sees both files as one register.
#[tokio::test]
async fn records_json_stays_decodable_by_a_four_kind_binary() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let store = OwnerSyncStore::load(dir.path()).await.expect("store");
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    store
        .commit_batch(
            vec![
                device_record(m, enrolled(m, 1_000)),
                names_record(&hex::encode(machine(1).0)),
            ],
            &owner_id,
        )
        .await
        .expect("commit");
    // A later register write that changes only an older kind keeps the
    // device record out of records.json too.
    store
        .commit_batch(vec![names_record(&hex::encode(machine(2).0))], &owner_id)
        .await
        .expect("commit names");
    drop(store);

    let sync_dir = dir.path().join(SYNC_DIR);
    let bytes = std::fs::read(sync_dir.join(RECORDS_FILE)).expect("records.json");
    let old: OldPersisted =
        serde_json::from_slice(&bytes).expect("a four-kind binary decodes records.json");
    assert_eq!(old.records.len(), 2, "both names records, no device record");

    let enrollment: PersistedRecords = serde_json::from_slice(
        &std::fs::read(sync_dir.join(ENROLLMENT_RECORDS_FILE)).expect("enrollment file"),
    )
    .expect("decode");
    assert_eq!(enrollment.records.len(), 1);
    assert_eq!(enrollment.records[0].kind, SyncKind::DeviceEnrollment);

    let reloaded = OwnerSyncStore::load(dir.path()).await.expect("reload");
    let records = reloaded.records_snapshot().await;
    assert_eq!(records.len(), 3, "one register over both files");
    assert_eq!(device_keys(&records), 1);
}

/// Copy `from` into `to` under test control: pass the first `hello_len`
/// bytes once `release_hello` fires (sending `hello_seen` when they have
/// arrived), then send `rest_seen` when the next byte arrives and hold it
/// and everything after it until `release_rest` fires.
async fn gated_relay<R, W>(
    mut from: R,
    mut to: W,
    hello_len: usize,
    hello_seen: tokio::sync::oneshot::Sender<()>,
    release_hello: tokio::sync::oneshot::Receiver<()>,
    rest_seen: tokio::sync::oneshot::Sender<()>,
    release_rest: tokio::sync::oneshot::Receiver<()>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut hello = vec![0u8; hello_len];
    if from.read_exact(&mut hello).await.is_err() {
        return;
    }
    let _ = hello_seen.send(());
    let _ = release_hello.await;
    if to.write_all(&hello).await.is_err() {
        return;
    }
    let mut first = [0u8; 1];
    let got = from.read(&mut first).await.unwrap_or(0);
    let _ = rest_seen.send(());
    let _ = release_rest.await;
    if got == 1 && to.write_all(&first).await.is_ok() {
        let _ = tokio::io::copy(&mut from, &mut to).await;
    }
    let _ = to.shutdown().await;
}

/// Bytes of one `Hello` frame on the wire (length prefix included).
fn hello_frame_len() -> usize {
    4 + bincode::serialize(&SyncFrame::Hello {
        protocol_version: 0,
        machine_id: [0; 32],
        owner_user_id: [0; 32],
        nonce: [0; 32],
    })
    .expect("encode")
    .len()
}

/// The test controls of one direction of a gated session.
struct Gate {
    hello_seen: tokio::sync::oneshot::Receiver<()>,
    release_hello: tokio::sync::oneshot::Sender<()>,
    rest_seen: tokio::sync::oneshot::Receiver<()>,
    release_rest: tokio::sync::oneshot::Sender<()>,
}

/// One side of a session whose inbound bytes pass a [`gated_relay`]: the
/// side runs `run_sync_session` on `store` and returns its gate.
fn gated_side(
    store: &Arc<OwnerSyncStore>,
    local: MachineId,
    peer: MachineId,
) -> (
    Gate,
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
    tokio::task::JoinHandle<Result<SessionSummary, SyncError>>,
) {
    let hello_len = hello_frame_len();
    // `out_far` reads what this side sends; `in_far` feeds what it reads.
    let (out_near, out_far) = tokio::io::duplex(256 * 1024);
    let (in_near, in_far) = tokio::io::duplex(256 * 1024);
    let (hello_seen_tx, hello_seen) = tokio::sync::oneshot::channel();
    let (release_hello, release_hello_rx) = tokio::sync::oneshot::channel();
    let (rest_seen_tx, rest_seen) = tokio::sync::oneshot::channel();
    let (release_rest, release_rest_rx) = tokio::sync::oneshot::channel();
    let (relay_from, relay_to) = tokio::io::duplex(256 * 1024);
    tokio::spawn(gated_relay(
        relay_from,
        in_near,
        hello_len,
        hello_seen_tx,
        release_hello_rx,
        rest_seen_tx,
        release_rest_rx,
    ));
    let store = Arc::clone(store);
    let task = tokio::spawn(async move {
        let (mut recv, _unused) = tokio::io::split(in_far);
        let (_unused2, mut send) = tokio::io::split(out_near);
        run_sync_session_with_timeout(
            Duration::from_secs(30),
            &mut send,
            &mut recv,
            &store,
            &owner_kp(OWNER_SEED),
            &local,
            &peer,
            |_| {},
        )
        .await
    });
    (
        Gate {
            hello_seen,
            release_hello,
            rest_seen,
            release_rest,
        },
        out_far,
        relay_to,
        task,
    )
}

/// Two sessions on one pair run at the same time. Session S opens on both
/// sides at protocol 2 from stale memory, but completes only after session
/// T has moved both sides to 3. A completed session must not lower the
/// remembered version: both sides stay at 3. (On 9d7aad2e2 both sides
/// ended at 2 and stayed there.)
#[tokio::test]
async fn interleaved_sessions_do_not_leave_both_sides_at_protocol_2() {
    let (_dir, a, b) = pair().await;
    let (ma, mb) = (machine(1), machine(2));
    // a met b as a protocol-2 node: a remembers 2, b remembers nothing.
    b.speak_only_protocol_for_testing(2);
    let _ = session(&a, &b).await;
    b.speak_only_protocol_for_testing(0);
    assert_eq!(a.hello_protocol_for(&mb), 2);
    assert_eq!(b.hello_protocol_for(&ma), 3);

    // Wire one gated side to another: what `x` sends goes to `y`'s relay.
    async fn wire(from: tokio::io::DuplexStream, to: tokio::io::DuplexStream) {
        let (mut r, _w) = tokio::io::split(from);
        let (_r2, mut w) = tokio::io::split(to);
        let _ = tokio::io::copy(&mut r, &mut w).await;
        let _ = w.shutdown().await;
    }

    // S, side a: opens at 2. Hold its Hello here, so a has read its
    // memory before T starts.
    let (s_a_gate, mut s_a_out, s_a_in, s_a_task) = gated_side(&a, ma, mb);
    let mut s_a_hello = vec![0u8; hello_frame_len()];
    s_a_out
        .read_exact(&mut s_a_hello)
        .await
        .expect("S hello from a");

    // T, both sides, starts now: a sends 2, b sends 3.
    let (t_a_gate, t_a_out, t_a_in, t_a_task) = gated_side(&a, ma, mb);
    let (t_b_gate, t_b_out, t_b_in, t_b_task) = gated_side(&b, mb, ma);
    tokio::spawn(wire(t_a_out, t_b_in));
    tokio::spawn(wire(t_b_out, t_a_in));
    let _ = t_a_gate.release_hello.send(());
    let _ = t_b_gate.release_hello.send(());
    // Both sides of T have read the other's Hello once each wrote its
    // next frame: a = 3 (received 3), b = 2 (received 2 below its 3).
    let _ = t_a_gate.rest_seen.await;
    let _ = t_b_gate.rest_seen.await;
    assert_eq!(a.hello_protocol_for(&mb), 3);
    assert_eq!(b.hello_protocol_for(&ma), 2);

    // S, side b: opens at 2 from that memory.
    let (s_b_gate, s_b_out, mut s_b_in, s_b_task) = gated_side(&b, mb, ma);
    s_b_in.write_all(&s_a_hello).await.expect("forward S hello");
    tokio::spawn(wire(s_a_out, s_b_in));
    tokio::spawn(wire(s_b_out, s_a_in));
    // Both S Hellos are at the gates, unread: b has read its memory (2).
    let _ = s_a_gate.hello_seen.await;
    let _ = s_b_gate.hello_seen.await;

    // T completes: both sides remember 3.
    let _ = t_a_gate.release_rest.send(());
    let _ = t_b_gate.release_rest.send(());
    t_a_task.await.expect("join").expect("T completes on a");
    t_b_task.await.expect("join").expect("T completes on b");
    assert_eq!(a.hello_protocol_for(&mb), 3);
    assert_eq!(b.hello_protocol_for(&ma), 3);

    // Now S, opened at 2 on both sides, runs and completes.
    let _ = s_a_gate.release_hello.send(());
    let _ = s_b_gate.release_hello.send(());
    let _ = s_a_gate.release_rest.send(());
    let _ = s_b_gate.release_rest.send(());
    s_a_task.await.expect("join").expect("S completes on a");
    s_b_task.await.expect("join").expect("S completes on b");
    let _ = (
        s_a_gate.rest_seen,
        s_b_gate.rest_seen,
        t_a_gate.hello_seen,
        t_b_gate.hello_seen,
    );

    assert_eq!(
        (a.hello_protocol_for(&mb), b.hello_protocol_for(&ma)),
        (3, 3),
        "a completed session at protocol 2 must not lower a remembered 3"
    );
}

// ───────── PR 2: minting and applying ─────────

fn now_ms() -> u64 {
    now_unix_ms()
}

fn signed(machine_id: MachineId, at_ms: u64, expires_at_ms: Option<u64>) -> OwnerEnrollment {
    OwnerEnrollment::sign(machine_id, &owner_kp(OWNER_SEED), at_ms, expires_at_ms).expect("sign")
}

async fn mint(store: &OwnerSyncStore, local: MachineId) -> usize {
    store
        .mint_device_enrollments(&owner_kp(OWNER_SEED), local)
        .await
        .expect("mint")
}

fn device_hashes(records: &[VersionedRecord]) -> Vec<(String, [u8; 32])> {
    records
        .iter()
        .filter(|r| r.kind == SyncKind::DeviceEnrollment)
        .map(|r| (r.key.clone(), r.record_hash()))
        .collect()
}

/// An enrollment made on device a reaches device b through one session.
/// Each device ignores the record about its own machine.
#[tokio::test]
async fn an_enrollment_minted_on_one_device_is_applied_on_the_other() {
    let (_dir, a, b) = pair().await;
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    a.enroll(signed(m, now_ms() - 1_000, None))
        .await
        .expect("a enrolls m");
    assert_eq!(mint(&a, machine(1)).await, 2, "machine 2 and m");
    assert_eq!(mint(&b, machine(2)).await, 1, "machine 1");
    assert!(!b.is_enrolled(&m, &owner_id).await);

    let (ra, rb) = session(&a, &b).await;
    ra.expect("a completes");
    rb.expect("b completes");
    assert!(b.is_enrolled(&m, &owner_id).await, "b applied m");
    let b_devices: Vec<[u8; 32]> = b
        .enrolled_devices()
        .await
        .iter()
        .map(|e| e.machine_id)
        .collect();
    assert!(
        !b_devices.contains(&machine(2).0),
        "b ignores the record about itself"
    );
    let a_devices: Vec<[u8; 32]> = a
        .enrolled_devices()
        .await
        .iter()
        .map(|e| e.machine_id)
        .collect();
    assert!(
        !a_devices.contains(&machine(1).0),
        "a ignores the record about itself"
    );
    // Applying made no new record: the versions come from the timestamps.
    assert_eq!(mint(&a, machine(1)).await, 0);
    assert_eq!(mint(&b, machine(2)).await, 0);
}

/// A removal on device a reaches device b and wins over an enrollment of
/// the same millisecond. A replayed older `Enrolled` record is refused
/// afterwards; a re-enrollment with a newer time admits the machine again.
#[tokio::test]
async fn a_removal_propagates_and_wins_at_equal_time_and_a_replay_is_refused() {
    let (_dir, a, b) = pair().await;
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    let t = now_ms() - 10_000;
    a.enroll(signed(m, t, None)).await.expect("a enrolls m");
    b.enroll(signed(m, t, None)).await.expect("b enrolls m");
    mint(&a, machine(1)).await;
    mint(&b, machine(2)).await;
    let (ra, rb) = session(&a, &b).await;
    ra.expect("a completes");
    rb.expect("b completes");
    assert!(b.is_enrolled(&m, &owner_id).await);

    // a removes m at the enrollment's own millisecond.
    assert!(a.unenroll_at(&m, t).await.expect("a removes m"));
    assert_eq!(mint(&a, machine(1)).await, 1, "the Removed record");
    let (ra, rb) = session(&a, &b).await;
    ra.expect("a completes");
    rb.expect("b completes");
    assert!(
        !b.is_enrolled(&m, &owner_id).await,
        "the removal wins at equal time"
    );
    assert!(!a.is_enrolled(&m, &owner_id).await);
    let key = hex::encode(m.0);
    assert_eq!(
        b.stored_value(SyncKind::DeviceEnrollment, &key).await,
        Some(SyncValue::DeviceEnrollment { state: removed(t) })
    );
    assert_eq!(
        mint(&b, machine(2)).await,
        0,
        "b's own state gives the same version"
    );
    assert_eq!(
        device_hashes(&a.records_snapshot().await),
        device_hashes(&b.records_snapshot().await),
        "both devices hold the same records"
    );

    // A replay of the older Enrolled record: the register keeps Removed,
    // and applying it does not admit m again.
    let replay = device_record(m, enrolled(m, t));
    let outcome = b
        .commit_batch(vec![replay.clone()], &owner_id)
        .await
        .expect("commit");
    assert!(
        outcome.accepted.is_empty(),
        "the older record is superseded"
    );
    b.apply_device_enrollments(&[replay], &owner_id, &machine(2))
        .await;
    assert!(
        !b.is_enrolled(&m, &owner_id).await,
        "the replay does not admit m"
    );

    // A re-enrollment needs a newer time than the removal.
    a.enroll(signed(m, t + 1, None)).await.expect("re-enroll");
    assert_eq!(mint(&a, machine(1)).await, 1);
    let (ra, rb) = session(&a, &b).await;
    ra.expect("a completes");
    rb.expect("b completes");
    assert!(
        b.is_enrolled(&m, &owner_id).await,
        "the newer enrollment admits m"
    );
}

/// A synced enrollment that has expired is stored but not applied, so the
/// machine stays denied.
#[tokio::test]
async fn an_expired_enrollment_stays_denied() {
    let (_dir, a, b) = pair().await;
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    let day = 86_400_000;
    a.enroll(signed(m, now_ms() - 2 * day, Some(now_ms() - day)))
        .await
        .expect("a stores the expired enrollment");
    assert_eq!(mint(&a, machine(1)).await, 2);
    let (ra, rb) = session(&a, &b).await;
    ra.expect("a completes");
    rb.expect("b completes");
    assert!(
        b.stored_value(SyncKind::DeviceEnrollment, &hex::encode(m.0))
            .await
            .is_some(),
        "b stores the record"
    );
    assert!(
        !b.is_enrolled(&m, &owner_id).await,
        "an expired enrollment stays denied"
    );
    assert!(
        !b.enrolled_devices()
            .await
            .iter()
            .any(|e| e.machine_id == m.0),
        "it is not applied"
    );
}

/// At start a device applies every stored kind 0x05 record (a device that
/// ran PR 1 stored them without applying them) and mints records for its
/// local device set. A restart after that mints nothing new.
#[tokio::test]
async fn a_restart_applies_stored_records_and_mints_nothing_new() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let owner = owner_kp(OWNER_SEED);
    let owner_id = owner.user_id();
    let (m, n, p, q) = (machine(9), machine(10), machine(11), machine(12));
    let path = dir.path().join("s");
    {
        let s = OwnerSyncStore::load(&path).await.expect("store");
        s.enroll(signed(n, 1_500, None)).await.expect("enroll n");
        s.enroll(signed(p, 3_000, None)).await.expect("enroll p");
        s.enroll(signed(q, 5_000, None)).await.expect("enroll q");
        // Stored as PR 1 stores them: in the register, not applied.
        s.commit_batch(
            vec![
                device_record(m, enrolled(m, 1_000)),
                device_record(n, removed(2_000)),
                // Older than q's local enrollment: it must not remove q.
                device_record(q, removed(4_000)),
            ],
            &owner_id,
        )
        .await
        .expect("commit");
        assert!(!s.is_enrolled(&m, &owner_id).await);
        assert!(s.is_enrolled(&n, &owner_id).await);
    }
    let s = OwnerSyncStore::load(&path).await.expect("restart");
    let minted = s
        .reconcile_device_enrollments(&owner, machine(1))
        .await
        .expect("reconcile");
    assert!(
        s.is_enrolled(&m, &owner_id).await,
        "the stored Enrolled is applied"
    );
    assert!(
        !s.is_enrolled(&n, &owner_id).await,
        "the stored Removed is applied"
    );
    assert!(s.is_enrolled(&p, &owner_id).await);
    assert!(
        s.is_enrolled(&q, &owner_id).await,
        "an older removal keeps q"
    );
    assert_eq!(
        minted, 2,
        "p had no record; q's enrollment is newer than its record"
    );
    assert_eq!(
        s.stored_value(SyncKind::DeviceEnrollment, &hex::encode(q.0))
            .await,
        Some(SyncValue::DeviceEnrollment {
            state: DeviceEnrollmentState::Enrolled {
                enrollment: signed_like(&s, q).await
            }
        })
    );
    let before = device_hashes(&s.records_snapshot().await);
    assert_eq!(before.len(), 4);
    drop(s);

    let s = OwnerSyncStore::load(&path).await.expect("second restart");
    let minted = s
        .reconcile_device_enrollments(&owner, machine(1))
        .await
        .expect("reconcile");
    assert_eq!(minted, 0, "a restart mints nothing new");
    assert_eq!(device_hashes(&s.records_snapshot().await), before);
}

/// At start, every stored kind 0x05 record is verified again before it is
/// applied. The records are written straight into the enrollment file, so
/// no ingest check runs on them: an expired enrollment, an inner enrollment
/// signed by another key, and an enrollment that names another machine than
/// its key are not admitted. A valid record in the same file is.
#[tokio::test]
async fn a_restart_does_not_admit_an_invalid_stored_record() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let owner = owner_kp(OWNER_SEED);
    let owner_id = owner.user_id();
    let (expired, foreign, wrong, valid) = (machine(9), machine(10), machine(11), machine(12));
    let named = machine(13);
    let day = 86_400_000;
    let at = now_ms() - 2 * day;
    let stranger = OwnerEnrollment::sign(foreign, &owner_kp(99), at, None).expect("sign");
    write_records(
        dir.path(),
        ENROLLMENT_RECORDS_FILE,
        vec![
            device_record(
                expired,
                DeviceEnrollmentState::Enrolled {
                    enrollment: signed(expired, at, Some(now_ms() - day)),
                },
            ),
            device_record(
                foreign,
                DeviceEnrollmentState::Enrolled {
                    enrollment: stranger,
                },
            ),
            // Key `wrong`, inner enrollment for `named`.
            device_record(
                wrong,
                DeviceEnrollmentState::Enrolled {
                    enrollment: signed(named, at, None),
                },
            ),
            device_record(valid, enrolled(valid, at)),
        ],
    );
    let s = OwnerSyncStore::load(dir.path()).await.expect("start");
    assert_eq!(device_hashes(&s.records_snapshot().await).len(), 4);
    s.reconcile_device_enrollments(&owner, machine(1))
        .await
        .expect("reconcile");
    let applied: Vec<[u8; 32]> = s
        .enrolled_devices()
        .await
        .iter()
        .map(|e| e.machine_id)
        .collect();
    assert_eq!(applied, vec![valid.0], "only the valid record is admitted");
    assert!(s.is_enrolled(&valid, &owner_id).await);
    for m in [expired, foreign, wrong, named] {
        assert!(!s.is_enrolled(&m, &owner_id).await);
    }
}

async fn signed_like(store: &OwnerSyncStore, machine_id: MachineId) -> OwnerEnrollment {
    store
        .enrolled_devices()
        .await
        .into_iter()
        .find(|e| e.machine_id == machine_id.0)
        .expect("enrolled")
}

/// A `Hello` of a lower version lowers the remembered version; only a
/// durable commit raises it back to the version this side sent. A session
/// whose commit fails leaves it lowered.
#[tokio::test]
async fn a_failed_commit_does_not_raise_the_remembered_version() {
    let (dir, a, b) = pair().await;
    a.speak_only_protocol_for_testing(2);
    let _ = session(&a, &b).await; // b learns: a speaks 2
    let _ = session(&a, &b).await;
    assert_eq!(b.hello_protocol_for(&machine(1)), 2);

    // a "upgrades" (a fresh store remembers nothing, so it sends 3) and
    // b holds a record a lacks, so a has a batch to commit.
    drop(a);
    let a = Arc::new(
        OwnerSyncStore::load(&dir.path().join("a"))
            .await
            .expect("reload a"),
    );
    b.commit_batch(
        vec![names_record(&hex::encode(machine(2).0))],
        &owner_kp(OWNER_SEED).user_id(),
    )
    .await
    .expect("b record");
    a.fail_next_register_write
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let (ra, rb) = session(&a, &b).await;
    assert!(ra.is_err(), "a's commit fails");
    rb.expect("b completes");
    assert_eq!(
        a.hello_protocol_for(&machine(2)),
        2,
        "b's Hello of 2 lowered it, and no durable commit raised it"
    );

    let (ra, _rb) = session(&a, &b).await;
    ra.expect("a completes");
    assert_eq!(
        a.hello_protocol_for(&machine(2)),
        3,
        "a durable commit raises it"
    );
}

fn write_records(dir: &Path, file: &str, records: Vec<VersionedRecord>) {
    let sync = dir.join(SYNC_DIR);
    std::fs::create_dir_all(&sync).expect("sync dir");
    std::fs::write(
        sync.join(file),
        serde_json::to_vec(&PersistedRecords { records }).expect("encode"),
    )
    .expect("write");
}

/// A key in both files keeps the record that wins, whichever file holds it.
#[tokio::test]
async fn load_keeps_the_winning_record_when_a_key_is_in_both_files() {
    let m = machine(9);
    let older = device_record(m, enrolled(m, 1_000));
    let newer = device_record(m, removed(1_000));
    for (in_records, in_enrollments) in [(&older, &newer), (&newer, &older)] {
        let dir = tempfile::tempdir().expect("tmpdir");
        write_records(dir.path(), RECORDS_FILE, vec![in_records.clone()]);
        write_records(
            dir.path(),
            ENROLLMENT_RECORDS_FILE,
            vec![in_enrollments.clone()],
        );
        let s = OwnerSyncStore::load(dir.path()).await.expect("load");
        assert_eq!(
            s.stored_value(SyncKind::DeviceEnrollment, &hex::encode(m.0))
                .await,
            Some(SyncValue::DeviceEnrollment {
                state: removed(1_000)
            })
        );
    }
}

/// Without the enrollment file a device loads the four older kinds; with a
/// corrupt one it refuses to start, as for every other state file.
#[tokio::test]
async fn a_missing_enrollment_file_loads_and_a_corrupt_one_refuses_to_start() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    {
        let s = OwnerSyncStore::load(dir.path()).await.expect("store");
        s.commit_batch(
            vec![
                names_record(&hex::encode(machine(1).0)),
                device_record(m, enrolled(m, 1_000)),
            ],
            &owner_id,
        )
        .await
        .expect("commit");
    }
    let file = dir.path().join(SYNC_DIR).join(ENROLLMENT_RECORDS_FILE);
    std::fs::remove_file(&file).expect("remove");
    let s = OwnerSyncStore::load(dir.path())
        .await
        .expect("loads without the file");
    let records = s.records_snapshot().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, SyncKind::MachineNames);
    drop(s);

    std::fs::write(&file, b"{not json").expect("corrupt");
    let err = OwnerSyncStore::load(dir.path())
        .await
        .err()
        .expect("a corrupt enrollment file refuses the start");
    assert!(err.to_string().contains(ENROLLMENT_RECORDS_FILE), "{err}");
}

/// A failure after the first of the two register writes leaves a valid
/// register on disk: the kind 0x05 record and the old records of the other
/// kinds. The record not stored comes in again later.
#[tokio::test]
async fn a_failure_between_the_two_writes_keeps_a_valid_register() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let m = machine(9);
    let batch = vec![
        names_record(&hex::encode(machine(1).0)),
        device_record(m, enrolled(m, 1_000)),
    ];
    {
        let s = OwnerSyncStore::load(dir.path()).await.expect("store");
        s.set_fail_after_rename_for_testing(true);
        let err = s
            .commit_batch(batch.clone(), &owner_id)
            .await
            .expect_err("the first write fails after its rename");
        assert!(matches!(err, SyncError::Poisoned(_)), "{err:?}");
    }
    let s = OwnerSyncStore::load(dir.path()).await.expect("reload");
    let records = s.records_snapshot().await;
    assert_eq!(records.len(), 1, "only the first write landed");
    assert_eq!(records[0].kind, SyncKind::DeviceEnrollment);
    for record in &records {
        record
            .verify_owner(&owner_id)
            .expect("each stored record verifies");
    }
    let outcome = s.commit_batch(batch, &owner_id).await.expect("again");
    assert_eq!(outcome.accepted.len(), 1, "the names record comes in again");
    assert_eq!(s.records_snapshot().await.len(), 2);
}

/// A peer at protocol 2 that sends a kind 0x05 record in a records page is
/// refused, and nothing is committed.
#[tokio::test]
async fn a_protocol_2_session_refuses_a_device_enrollment_record_page() {
    let (_dir, a, _b) = pair().await;
    let (client, server) = tokio::io::duplex(256 * 1024);
    let (mut a_recv, mut a_send) = tokio::io::split(server);
    let (mut p_recv, mut p_send) = tokio::io::split(client);
    let owner = owner_kp(OWNER_SEED);
    let owner_id = owner.user_id().0;
    let m = machine(9);
    let record = device_record(m, enrolled(m, 1_000));

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
        write_frame(&mut p_send, &SyncFrame::VersionVector { kinds: vec![] }).await?;
        write_frame(&mut p_send, &SyncFrame::VectorEnd).await?;
        write_frame(
            &mut p_send,
            &SyncFrame::Records {
                records: vec![record],
            },
        )
        .await?;
        write_frame(&mut p_send, &SyncFrame::Done).await?;
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
    .expect_err("a kind 0x05 record in a protocol-2 session must be refused");
    assert!(matches!(err, SyncError::MalformedFrame(_)), "{err:?}");
    assert_eq!(
        device_keys(&a.records_snapshot().await),
        0,
        "nothing committed"
    );
    assert!(!a.is_enrolled(&m, &owner.user_id()).await);
    drop((a_send, a_recv));
    let _ = peer.await;
}

/// The service applies the stored kind 0x05 records when it starts, before
/// any session, and its reconcile pass mints a record for an enrollment
/// made after the start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_service_applies_stored_records_at_start_and_its_pass_mints() {
    super::tests::install_loopback_socket_boundary();
    let dir = tempfile::tempdir().expect("tmpdir");
    let seed = OWNER_SEED;
    let owner_id = owner_kp(seed).user_id();
    let (m, n) = (machine(9), machine(10));
    {
        let s = OwnerSyncStore::load(&dir.path().join("alice"))
            .await
            .expect("store");
        s.commit_batch(vec![device_record(m, enrolled(m, 1_000))], &owner_id)
            .await
            .expect("stored, not applied");
        assert!(!s.is_enrolled(&m, &owner_id).await);
    }
    let (_agent, service) = super::tests::live_owner_device(dir.path(), "alice", [seed; 32]).await;
    let store = service.store();
    assert!(store.is_enrolled(&m, &owner_id).await, "applied at start");

    store
        .enroll(signed(n, now_ms() - 1_000, None))
        .await
        .expect("enroll n");
    let key = hex::encode(n.0);
    assert!(store
        .stored_value(SyncKind::DeviceEnrollment, &key)
        .await
        .is_none());
    service.reconcile_local_state().await.expect("pass");
    assert!(
        store
            .stored_value(SyncKind::DeviceEnrollment, &key)
            .await
            .is_some(),
        "the pass mints the record"
    );
}

/// A kind 0x05 record whose time is more than the enrollment clock skew
/// (`ENROLL_EXPIRY_SKEW_MS`, 300 s) in the future is not stored; the other
/// records of its batch commit. A time within the skew is stored.
#[tokio::test]
async fn a_device_enrollment_record_from_the_future_is_not_stored() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let s = OwnerSyncStore::load(dir.path()).await.expect("store");
    let owner_id = owner_kp(OWNER_SEED).user_id();
    let (m, n, p) = (machine(9), machine(10), machine(11));
    let now = now_ms();
    let outcome = s
        .commit_batch(
            vec![
                device_record(m, enrolled(m, now + ENROLL_EXPIRY_SKEW_MS + 60_000)),
                device_record(n, removed(now + ENROLL_EXPIRY_SKEW_MS + 60_000)),
                device_record(p, removed(now + 60_000)),
                names_record(&hex::encode(machine(1).0)),
            ],
            &owner_id,
        )
        .await
        .expect("commit");
    assert_eq!(outcome.accepted.len(), 2, "p's record and the names record");
    for (machine_id, stored) in [(m, false), (n, false), (p, true)] {
        assert_eq!(
            s.stored_value(SyncKind::DeviceEnrollment, &hex::encode(machine_id.0))
                .await
                .is_some(),
            stored,
            "{machine_id:?}"
        );
    }
}

fn unsigned_names(key: &str) -> VersionedRecord {
    VersionedRecord {
        kind: SyncKind::MachineNames,
        key: key.to_string(),
        value: names_value("n"),
        clock: clock(1, 1, 1),
        owner_public_key: Vec::new(),
        signature: Vec::new(),
    }
}

/// The two register files share one limit of `MAX_STORED_RECORDS`: a new
/// key of either kind is refused at the limit, by a commit and by a mint,
/// and a newer record of a stored key is still accepted.
#[tokio::test]
async fn the_store_limit_counts_both_files() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let owner = owner_kp(OWNER_SEED);
    let owner_id = owner.user_id();
    let m = machine(9);
    // Loaded records are not verified, so unsigned fillers will do.
    let fillers: Vec<VersionedRecord> = (0..MAX_STORED_RECORDS - 2)
        .map(|i| unsigned_names(&format!("filler-{i}")))
        .collect();
    write_records(dir.path(), RECORDS_FILE, fillers);
    write_records(
        dir.path(),
        ENROLLMENT_RECORDS_FILE,
        vec![device_record(m, enrolled(m, 1_000))],
    );
    let s = OwnerSyncStore::load(dir.path()).await.expect("load");
    assert_eq!(s.records_snapshot().await.len(), MAX_STORED_RECORDS - 1);

    // The last free slot takes a kind 0x05 record.
    let n = machine(10);
    let outcome = s
        .commit_batch(vec![device_record(n, enrolled(n, 1_000))], &owner_id)
        .await
        .expect("the last slot");
    assert_eq!(outcome.accepted.len(), 1);

    // At the limit a new key is refused, whatever its kind.
    let p = machine(11);
    for record in [
        device_record(p, enrolled(p, 1_000)),
        names_record(&hex::encode(machine(1).0)),
    ] {
        let err = s
            .commit_batch(vec![record], &owner_id)
            .await
            .expect_err("a new key at the limit");
        assert!(matches!(err, SyncError::StoreLimit(_)), "{err:?}");
    }
    s.enroll(signed(p, 1_000, None)).await.expect("enroll p");
    let err = s
        .mint_device_enrollments(&owner, machine(1))
        .await
        .expect_err("a mint of a new key at the limit");
    assert!(matches!(err, SyncError::StoreLimit(_)), "{err:?}");

    // A newer record of a stored key still replaces it.
    let outcome = s
        .commit_batch(vec![device_record(m, removed(1_000))], &owner_id)
        .await
        .expect("a stored key at the limit");
    assert_eq!(outcome.accepted.len(), 1);
    assert_eq!(s.records_snapshot().await.len(), MAX_STORED_RECORDS);
}
