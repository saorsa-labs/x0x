#![cfg(test)]

//! #1107 Fix 4: an enrollment learned through owner sync.
//!
//! Owner device A enrolls machine M. A syncs with owner device B, which has
//! never seen M, and then goes offline. B must now hold M as an enrolled
//! owner machine (the `ENROLLED` owner-trust bit) and exec on B must admit
//! a request from M's agent.
//!
//! Red until PR 2 of #1107: PR 1 adds the `DeviceEnrollment` kind and
//! protocol 3, but nothing mints a record from an enrollment or applies
//! one to the device set, so B never learns M.

use super::cold_restart_tests::{build_receiver, new_sender, owner_acl, SeedPolicy, SEED};
use super::protocol::{encode_frame_payload, ExecFrame, ExecRequestId};
use super::service::ExecService;
use crate::dm_inbox::DmTypedPayload;
use crate::identity::{AgentCertificate, MachineId, UserKeypair};
use crate::owner_sync::{run_sync_session_with_timeout, OwnerEnrollment, OwnerSyncStore};
use crate::peer_evidence::{EvidenceConfig, IngestSource, PeerEvidenceStore};
use crate::trust::TrustDecision;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const DEVICE_A: MachineId = MachineId([0xa1; 32]);
const DEVICE_B: MachineId = MachineId([0xb2; 32]);
const BOUND: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "red until PR 2 of #1107: PR 2 mints DeviceEnrollment records (skipping a mint when a record with the same version exists), applies received ones, and at start-up re-verifies and applies every stored kind 0x05 record, because PR 1 stores them without applying them"]
async fn enrollment_made_on_another_owner_device_admits_exec_after_sync() {
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::create_dir_all(dir.path().join("identity")).expect("identity dir");
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let sender = new_sender();
    let m = sender.machine.machine_id();
    let now_ms = crate::dm_capability::now_unix_ms();

    // B's evidence store holds M's agent with an owner-issued certificate,
    // so the only missing fact on B is M's enrollment.
    let seed = PeerEvidenceStore::open(
        &dir.path().join("evidence"),
        EvidenceConfig::default(),
        Arc::new(SeedPolicy),
        now_ms,
    )
    .expect("seed store");
    let mut record =
        crate::peer_evidence::record_for_test(&sender.agent, &sender.machine, now_ms, now_ms);
    let cert = AgentCertificate::issue_with_expiry(&owner, &sender.agent, None).expect("cert");
    record.certificate = Some(cert.to_storage_bytes().expect("cert bytes"));
    seed.ingest(record, IngestSource::Hello, now_ms)
        .expect("seed record");
    seed.flush(now_ms, true).expect("flush");
    drop(seed);

    // A enrolls B and M; B enrolls only A.
    let a = OwnerSyncStore::load(&dir.path().join("a-sync"))
        .await
        .expect("a store");
    for machine in [DEVICE_B, m] {
        a.enroll(OwnerEnrollment::sign(machine, &owner, now_ms - 1_000, None).expect("sign"))
            .await
            .expect("a enrolls");
    }
    let b = OwnerSyncStore::load(&dir.path().join("sync"))
        .await
        .expect("b store");
    b.enroll(OwnerEnrollment::sign(DEVICE_A, &owner, now_ms - 1_000, None).expect("sign"))
        .await
        .expect("b enrolls a");
    assert!(
        !b.is_enrolled(&m, &owner.user_id()).await,
        "B starts without M"
    );

    // One session between A and B, then A goes offline.
    let (client, server) = tokio::io::duplex(256 * 1024);
    let (mut a_recv, mut a_send) = tokio::io::split(server);
    let (mut b_recv, mut b_send) = tokio::io::split(client);
    let b_owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let (ra, rb) = tokio::join!(
        run_sync_session_with_timeout(
            BOUND,
            &mut a_send,
            &mut a_recv,
            &a,
            &owner,
            &DEVICE_A,
            &DEVICE_B,
            |_| {},
        ),
        run_sync_session_with_timeout(
            BOUND,
            &mut b_send,
            &mut b_recv,
            &b,
            &b_owner,
            &DEVICE_B,
            &DEVICE_A,
            |_| {},
        ),
    );
    ra.expect("A completes the session");
    rb.expect("B completes the session");
    drop(a);
    drop(b);

    // B runs on its own files; A is gone.
    let receiver = build_receiver(dir.path()).await;
    let relation = {
        let revoked = receiver.revocation_set();
        let revoked = revoked.read().await;
        receiver.owner_trust().evidence_relation(
            sender.agent.agent_id(),
            m,
            None,
            &revoked,
            crate::dm_capability::now_unix_ms(),
        )
    };
    let (tx, rx) = mpsc::channel(8);
    let service = ExecService::spawn(Arc::clone(&receiver), owner_acl(dir.path()), rx);
    tx.send(DmTypedPayload {
        sender: sender.agent.agent_id(),
        machine_id: m,
        payload: encode_frame_payload(&ExecFrame::Request {
            request_id: ExecRequestId([1; 16]),
            argv: vec!["echo".to_string(), "ok".to_string()],
            stdin: None,
            timeout_ms: 1_000,
            cwd: None,
        })
        .expect("encode"),
        verified: true,
        trust_decision: Some(TrustDecision::Unknown),
        received_at_unix_ms: crate::dm_capability::now_unix_ms(),
        request_id: [1; 16],
        completion: None,
    })
    .await
    .expect("inbound channel open");
    let start = Instant::now();
    let totals = loop {
        let totals = service.diagnostics_snapshot().await.totals;
        if totals.requests_allowed + totals.requests_denied >= 1 || start.elapsed() > BOUND {
            break totals;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    service.shutdown().await;
    receiver.try_shutdown().await.expect("receiver stops");

    assert_eq!(
        relation.map(|r| r & crate::peer_evidence::ENROLLED),
        Some(crate::peer_evidence::ENROLLED),
        "B must hold M as an enrolled owner machine after syncing with A"
    );
    assert_eq!(
        (totals.requests_allowed, totals.requests_denied),
        (1, 0),
        "exec on B must admit M's agent"
    );
}
