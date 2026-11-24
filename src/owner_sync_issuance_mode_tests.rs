#![cfg(test)]
//! #2182: the `IssuanceMode` kind (0x06). The hosting mode and label of an
//! owner issuance reach the owner's other devices through owner sync, in a
//! protocol-4 session only, and stay out of every file an older binary
//! reads.

use std::sync::Arc;

use super::tests::{cross_enroll_for_tests, machine, names_value, owner_kp};
use super::*;
use crate::profile::{CertMode, IssuedCertRecord};

const OWNER_SEED: u8 = 7;
const AGENT: &str = "bb";

fn owner_hex() -> String {
    hex::encode(owner_kp(OWNER_SEED).user_id().0)
}

struct Device {
    store: Arc<OwnerSyncStore>,
    journal: PathBuf,
    machine: MachineId,
}

/// Two enrolled devices of one owner, each with its own journal: `a` is
/// machine 1 and `b` is machine 2.
async fn pair() -> (tempfile::TempDir, Device, Device) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let mut devices = Vec::new();
    for (name, id) in [("a", 1), ("b", 2)] {
        let path = dir.path().join(name);
        let store = Arc::new(OwnerSyncStore::load(&path).await.expect("store"));
        let journal = path.join(crate::profile::CERT_JOURNAL_FILE);
        store.set_journal_path(journal.clone());
        devices.push(Device {
            store,
            journal,
            machine: machine(id),
        });
    }
    let b = devices.pop().expect("b");
    let a = devices.pop().expect("a");
    cross_enroll_for_tests(&a.store, &b.store, &owner_kp(OWNER_SEED)).await;
    (dir, a, b)
}

/// A line written by `POST /owner/agents/issue` on this device: it keeps
/// the certificate bytes, so it states its mode.
fn issued(digest: &str, issued_at: u64, mode: CertMode, label: Option<&str>) -> IssuedCertRecord {
    IssuedCertRecord {
        user_id: owner_hex(),
        agent_id: AGENT.to_string(),
        cert_digest: digest.to_string(),
        issued_at,
        not_after: Some(issued_at + 1_000),
        mode,
        label: label.map(str::to_string),
        cert_b64: Some("Y2VydA==".to_string()),
        synced_mode: false,
    }
}

/// A certificate line that states no mode (a live sighting or a synced
/// certificate).
fn bare(digest: &str, issued_at: u64) -> IssuedCertRecord {
    IssuedCertRecord {
        mode: CertMode::Acp,
        label: None,
        cert_b64: None,
        ..issued(digest, issued_at, CertMode::Acp, None)
    }
}

async fn append(device: &Device, line: &IssuedCertRecord) {
    IssuedCertRecord::append(&device.journal, line)
        .await
        .expect("append");
}

/// The reconcile step of the sync service for the journal (kinds 4 and 6).
async fn reconcile(device: &Device) {
    mint_journal_lines(
        &device.store,
        &device.journal,
        &owner_kp(OWNER_SEED),
        device.machine,
    )
    .await;
}

/// One session between `a` (machine 1) and `b` (machine 2).
async fn session(
    a: &Device,
    b: &Device,
) -> (
    Result<SessionSummary, SyncError>,
    Result<SessionSummary, SyncError>,
) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let (mut a_recv, mut a_send) = tokio::io::split(server);
    let (mut b_recv, mut b_send) = tokio::io::split(client);
    let budget = Duration::from_secs(10);
    let (a_owner, b_owner) = (owner_kp(OWNER_SEED), owner_kp(OWNER_SEED));
    let a_side = run_sync_session_with_timeout(
        budget,
        &mut a_send,
        &mut a_recv,
        &a.store,
        &a_owner,
        &a.machine,
        &b.machine,
        |_| {},
    );
    let b_side = run_sync_session_with_timeout(
        budget,
        &mut b_send,
        &mut b_recv,
        &b.store,
        &b_owner,
        &b.machine,
        &a.machine,
        |_| {},
    );
    tokio::join!(a_side, b_side)
}

/// The mode and label the owner roster reads for `AGENT` from the journal:
/// those of the last line, in file order, that states them
/// (`Agent::owner_issued_certificates` applies the same rule).
async fn roster_mode(device: &Device) -> Option<(CertMode, Option<String>)> {
    IssuedCertRecord::load(&device.journal)
        .await
        .into_iter()
        .rev()
        .find(|line| line.user_id == owner_hex() && line.agent_id == AGENT && line.states_mode())
        .map(|line| (line.mode, line.label))
}

/// The certificate the roster shows for `AGENT`: that of its last line.
async fn roster_cert(device: &Device) -> Option<(String, u64)> {
    IssuedCertRecord::load(&device.journal)
        .await
        .into_iter()
        .rev()
        .find(|line| line.user_id == owner_hex() && line.agent_id == AGENT)
        .map(|line| (line.cert_digest, line.issued_at))
}

async fn mode_record(device: &Device) -> Option<VersionedRecord> {
    device
        .store
        .records_snapshot()
        .await
        .into_iter()
        .find(|r| r.kind == SyncKind::IssuanceMode && r.key == AGENT)
}

fn complete(
    result: (
        Result<SessionSummary, SyncError>,
        Result<SessionSummary, SyncError>,
    ),
) {
    result.0.expect("a completes");
    result.1.expect("b completes");
}

/// The case of #2182: device A issues the agent as a rider and later
/// re-issues it as ACP. Device B must follow both changes. Before the fix
/// owner sync carried no mode: B kept no mode for the rider, and after the
/// re-issue it kept `rider`.
#[tokio::test]
async fn a_mode_set_on_device_a_reaches_device_b() {
    let (_dir, a, b) = pair().await;

    append(&a, &issued("d1", 100, CertMode::Rider, Some("helper"))).await;
    reconcile(&a).await;
    complete(session(&a, &b).await);
    assert_eq!(
        roster_mode(&b).await,
        Some((CertMode::Rider, Some("helper".to_string()))),
        "the rider mode and label set on a reach b"
    );
    assert_eq!(roster_cert(&b).await, Some(("d1".to_string(), 100)));

    append(&a, &issued("d2", 200, CertMode::Acp, None)).await;
    reconcile(&a).await;
    complete(session(&a, &b).await);
    assert_eq!(
        roster_mode(&b).await,
        Some((CertMode::Acp, None)),
        "the re-issue as ACP on a reaches b"
    );
    assert_eq!(roster_cert(&b).await, Some(("d2".to_string(), 200)));

    // b's own reconcile publishes nothing new: its mode line states the
    // register's value.
    let before = mode_record(&b).await;
    reconcile(&b).await;
    assert_eq!(
        mode_record(&b).await,
        before,
        "b does not mint over a's record"
    );
    assert_eq!(
        mode_record(&b).await.map(|r| r.clock.writer_machine),
        Some(a.machine.0)
    );
}

/// A mode line repeats the certificate fields of the agent's last line, so
/// it does not roll the roster back to the certificate of the issuance
/// that stated the mode. Here b already holds a later renewal.
#[tokio::test]
async fn a_synced_mode_keeps_the_certificate_the_roster_shows() {
    let (_dir, a, b) = pair().await;
    append(&b, &bare("d3", 300)).await;
    append(&a, &issued("d1", 100, CertMode::Rider, None)).await;
    reconcile(&a).await;
    let record = mode_record(&a).await.expect("a publishes the mode");
    b.store
        .merge_record(record, &owner_kp(OWNER_SEED).user_id())
        .await
        .expect("merge");

    assert_eq!(roster_mode(&b).await, Some((CertMode::Rider, None)));
    assert_eq!(
        roster_cert(&b).await,
        Some(("d3".to_string(), 300)),
        "the roster keeps the later certificate"
    );
    let lines = IssuedCertRecord::load(&b.journal).await;
    assert!(lines.last().is_some_and(|line| line.synced_mode));
    assert_eq!(
        latest_journal_values(lines, &owner_hex())
            .get(AGENT)
            .map(|value| match value {
                SyncValue::IssuanceJournal { cert_digest, .. } => cert_digest.clone(),
                _ => String::new(),
            }),
        Some("d3".to_string()),
        "the certificate b publishes does not change"
    );

    // b's mode line repeats b's certificate, not a's, so its value differs
    // from a's record. b must still publish nothing: it states the same
    // mode and label. Otherwise each device would mint over the other on
    // every pass.
    let before = mode_record(&b).await;
    reconcile(&b).await;
    assert_eq!(
        mode_record(&b).await,
        before,
        "b publishes no record for a mode it only received"
    );
}

/// Run sessions and reconcile passes until neither register changes for
/// two passes.
async fn settle(a: &Device, b: &Device) {
    let mut stable = 0;
    for _ in 0..8 {
        let before = (mode_record(a).await, mode_record(b).await);
        complete(session(a, b).await);
        reconcile(a).await;
        reconcile(b).await;
        let after = (mode_record(a).await, mode_record(b).await);
        stable = if before == after { stable + 1 } else { 0 };
        if stable == 2 {
            return;
        }
    }
    panic!("the register never stopped changing");
}

async fn assert_both(a: &Device, b: &Device, mode: CertMode, label: Option<&str>) {
    let want = Some((mode, label.map(str::to_string)));
    for (device, who) in [(a, "a"), (b, "b")] {
        assert_eq!(roster_mode(device).await, want, "roster of {who}");
        let record = mode_record(device).await.expect("register record");
        let SyncValue::IssuanceMode {
            mode: held_mode,
            label: held_label,
            ..
        } = record.value
        else {
            panic!("not a mode value");
        };
        assert_eq!(Some((held_mode, held_label)), want, "register of {who}");
    }
    assert_eq!(mode_record(a).await, mode_record(b).await);
}

/// Conflict rule, first contact after an upgrade (the #2182 field state):
/// a holds an older rider issuance, b a newer ACP issuance, and neither
/// has published. The record version is the issuance second, so the
/// later issuance wins on both devices whichever device reconciles
/// first.
#[tokio::test]
async fn the_later_issuance_wins_whichever_device_reconciles_first() {
    for a_first in [true, false] {
        let (_dir, a, b) = pair().await;
        append(&a, &issued("da", 100, CertMode::Rider, Some("old"))).await;
        append(&b, &issued("db", 200, CertMode::Acp, None)).await;
        if a_first {
            reconcile(&a).await;
            complete(session(&a, &b).await);
            reconcile(&b).await;
        } else {
            reconcile(&b).await;
            complete(session(&a, &b).await);
            reconcile(&a).await;
        }
        settle(&a, &b).await;
        assert_both(&a, &b, CertMode::Acp, None).await;
        assert_eq!(
            mode_record(&a).await.map(|r| r.clock.version),
            Some(200),
            "a_first = {a_first}"
        );
    }
}

/// Security review probe: b publishes a rider issued at 100; a then issues
/// the agent as ACP at 900, and a session lands before a's reconcile. a
/// must keep its own newer line (not append b's rider over it), publish
/// it at its next reconcile, and win on both devices.
#[tokio::test]
async fn an_unpublished_local_issuance_is_not_overwritten_by_an_older_one() {
    let (_dir, a, b) = pair().await;
    append(&b, &issued("db", 100, CertMode::Rider, None)).await;
    reconcile(&b).await;
    append(&a, &issued("da", 900, CertMode::Acp, None)).await;
    complete(session(&a, &b).await);
    assert_eq!(
        roster_mode(&a).await,
        Some((CertMode::Acp, None)),
        "a keeps its newer local issuance"
    );
    settle(&a, &b).await;
    assert_both(&a, &b, CertMode::Acp, None).await;
}

/// Two statements in the same second: equal versions, so the rest of the
/// Tier-1 rule decides (later signing time, then greater writer machine,
/// then greater record hash). Both devices end on that winner and the
/// register stops changing.
#[tokio::test]
async fn same_second_statements_converge_on_the_tier1_winner() {
    let (_dir, a, b) = pair().await;
    append(&a, &issued("da", 100, CertMode::Rider, Some("from-a"))).await;
    append(&b, &issued("db", 100, CertMode::Acp, Some("from-b"))).await;
    reconcile(&a).await;
    reconcile(&b).await;
    let ra = mode_record(&a).await.expect("a's statement");
    let rb = mode_record(&b).await.expect("b's statement");
    assert_eq!((ra.clock.version, rb.clock.version), (100, 100));
    let winner = if OwnerSyncStore::classify(&ra, &rb) == MergeOutcome::Accepted {
        ra
    } else {
        rb
    };
    settle(&a, &b).await;
    assert_eq!(mode_record(&a).await, Some(winner.clone()));
    assert_eq!(mode_record(&b).await, Some(winner.clone()));
    let SyncValue::IssuanceMode { mode, label, .. } = winner.value else {
        panic!("not a mode value");
    };
    assert_both(&a, &b, mode, label.as_deref()).await;
}

/// Limit: a re-issue whose issuance second is before the published one
/// (a clock behind the other device's) loses. The device that issued it
/// yields: it appends the winner's mode line, so both rosters agree.
#[tokio::test]
async fn a_re_issue_with_an_earlier_second_yields_to_the_later_issuance() {
    let (_dir, a, b) = pair().await;
    append(&b, &issued("db", 900, CertMode::Acp, None)).await;
    reconcile(&b).await;
    complete(session(&a, &b).await);
    append(&a, &issued("da", 500, CertMode::Rider, None)).await;
    settle(&a, &b).await;
    assert_both(&a, &b, CertMode::Acp, None).await;
}

/// A third device that syncs only with b gets a's mode through b, and
/// keeps its own later certificate.
#[tokio::test]
async fn a_third_device_gets_the_mode_through_another_device() {
    let (dir, a, b) = pair().await;
    let path = dir.path().join("c");
    let store = Arc::new(OwnerSyncStore::load(&path).await.expect("store"));
    let journal = path.join(crate::profile::CERT_JOURNAL_FILE);
    store.set_journal_path(journal.clone());
    let c = Device {
        store,
        journal,
        machine: machine(3),
    };
    let owner = owner_kp(OWNER_SEED);
    for (store, peer) in [(&b.store, c.machine), (&c.store, b.machine)] {
        store
            .enroll(OwnerEnrollment::sign(peer, &owner, 1_000, None).expect("sign"))
            .await
            .expect("enroll");
    }
    append(&c, &bare("d3", 300)).await;

    append(&a, &issued("d1", 100, CertMode::Rider, Some("x"))).await;
    reconcile(&a).await;
    complete(session(&a, &b).await);
    complete(session(&b, &c).await);
    assert_eq!(
        roster_mode(&c).await,
        Some((CertMode::Rider, Some("x".to_string())))
    );
    assert_eq!(roster_cert(&c).await, Some(("d3".to_string(), 300)));
    assert_eq!(mode_record(&c).await, mode_record(&a).await);
}

/// A peer that speaks only protocol 3 (a released build) refuses a
/// protocol-4 `Hello`; the next session runs at 3 and completes. Kind 0x06
/// never crosses to it, and the older kinds still do.
#[tokio::test]
async fn a_protocol_3_peer_still_syncs_and_never_receives_kind_0x06() {
    let (_dir, a, b) = pair().await;
    b.store.speak_only_protocol_for_testing(3);
    append(&a, &issued("d1", 100, CertMode::Rider, None)).await;
    reconcile(&a).await;
    let owner_id = owner_kp(OWNER_SEED).user_id();
    a.store
        .commit_batch(
            vec![VersionedRecord::sign(
                SyncKind::MachineNames,
                &hex::encode(machine(1).0),
                &names_value("n"),
                super::tests::clock(1, 1, 1),
                &owner_kp(OWNER_SEED),
            )
            .expect("sign")],
            &owner_id,
        )
        .await
        .expect("names record");

    let (ra, rb) = session(&a, &b).await;
    assert!(
        matches!(
            rb,
            Err(SyncError::ProtocolVersion {
                local: 3,
                remote: 4
            })
        ),
        "{rb:?}"
    );
    assert!(ra.is_err(), "the first meeting fails");

    complete(session(&a, &b).await);
    let held = b.store.records_snapshot().await;
    assert!(
        held.iter().all(|r| r.kind != SyncKind::IssuanceMode),
        "kind 0x06 is never sent to a protocol-3 peer"
    );
    assert!(held.iter().any(|r| r.kind == SyncKind::MachineNames));
    assert!(held.iter().any(|r| r.kind == SyncKind::IssuanceJournal));
    assert_eq!(
        roster_mode(&b).await,
        None,
        "b keeps the behaviour of before"
    );
    assert!(mode_record(&a).await.is_some());
}

/// Kind 0x06 records are kept in their own file: `records.json` and
/// `enrollment_records.json`, which a binary built before kind 0x06 reads
/// at start, never hold one. A reload reads the record back.
#[tokio::test]
async fn mode_records_stay_out_of_the_files_an_older_binary_reads() {
    let (dir, a, _b) = pair().await;
    append(&a, &issued("d1", 100, CertMode::Rider, None)).await;
    reconcile(&a).await;
    let record = mode_record(&a).await.expect("a publishes the mode");
    let sync = dir.path().join("a").join(SYNC_DIR);
    for file in [RECORDS_FILE, ENROLLMENT_RECORDS_FILE] {
        let text = std::fs::read_to_string(sync.join(file)).unwrap_or_default();
        assert!(!text.contains("IssuanceMode"), "{file} holds no kind 0x06");
    }
    let text = std::fs::read_to_string(sync.join(MODE_RECORDS_FILE)).expect("mode file");
    assert!(text.contains("IssuanceMode"));

    drop(a);
    let reloaded = OwnerSyncStore::load(&dir.path().join("a"))
        .await
        .expect("reload");
    assert!(reloaded.records_snapshot().await.contains(&record));
}

/// Old format: a journal line written before #2182 has no `synced_mode`.
/// It reads as `false` and states a mode exactly as before; a line that is
/// not a synced mode line is written without the field, so an older build
/// reads the same bytes it wrote.
#[test]
fn a_journal_line_without_synced_mode_reads_as_before() {
    let legacy = format!(
        r#"{{"user_id":"{}","agent_id":"bb","cert_digest":"d","issued_at":1,"not_after":null}}"#,
        owner_hex()
    );
    let line: IssuedCertRecord = serde_json::from_str(&legacy).expect("legacy line");
    assert!(!line.synced_mode);
    assert!(!line.states_mode(), "a bare legacy line states no mode");
    let written = serde_json::to_string(&line).expect("encode");
    assert!(!written.contains("synced_mode"), "{written}");

    let synced = IssuedCertRecord {
        synced_mode: true,
        ..line
    };
    assert!(synced.states_mode(), "a synced ACP line states its mode");
    let written = serde_json::to_string(&synced).expect("encode");
    assert!(written.contains(r#""synced_mode":true"#), "{written}");
}

/// A record whose key names another agent than its value is refused.
#[test]
fn a_mode_record_must_name_the_agent_of_its_key() {
    let value = SyncValue::IssuanceMode {
        agent_id: "cc".into(),
        cert_digest: "d".into(),
        issued_at: 1,
        not_after: None,
        mode: CertMode::Rider,
        label: None,
    };
    let record = VersionedRecord::sign(
        SyncKind::IssuanceMode,
        AGENT,
        &value,
        super::tests::clock(1, 1, 1),
        &owner_kp(OWNER_SEED),
    )
    .expect("sign");
    assert!(matches!(record.verify(), Err(SyncError::MalformedFrame(_))));

    // The version must be the issuance second of the statement.
    let value = SyncValue::IssuanceMode {
        agent_id: AGENT.into(),
        cert_digest: "d".into(),
        issued_at: 7,
        not_after: None,
        mode: CertMode::Rider,
        label: None,
    };
    let record = VersionedRecord::sign(
        SyncKind::IssuanceMode,
        AGENT,
        &value,
        super::tests::clock(8, 1, 1),
        &owner_kp(OWNER_SEED),
    )
    .expect("sign");
    assert!(matches!(record.verify(), Err(SyncError::MalformedFrame(_))));
}
