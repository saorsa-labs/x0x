#![cfg(test)]

//! #1107 Fix 4: an enrollment learned through owner sync.
//!
//! Owner device A enrolls machine M. A syncs with owner device B, which has
//! never seen M, and then goes offline. B must now hold M as an enrolled
//! owner machine (the `ENROLLED` owner-trust bit) and exec on B must admit
//! a request from M's agent.
//!
//! PR 2 of #1107: A mints `DeviceEnrollment` records for its device set
//! (in a daemon, the reconcile pass that each enroll kicks), and B applies
//! the committed records to its device set. An ADR-0018 revocation of M
//! still overrides the synced enrollment.

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

/// The ENROLLED owner-trust bit B holds for M after the sync, and B's exec
/// totals (allowed, denied) for one request from M's agent. With
/// `revoke_m`, B holds an ADR-0018 revocation of M before the request.
async fn sync_then_exec(revoke_m: bool) -> (Option<u8>, (u64, u64)) {
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

    // The records the daemon's reconcile pass mints for each device set.
    a.mint_device_enrollments(&owner, DEVICE_A)
        .await
        .expect("a mints");
    b.mint_device_enrollments(&owner, DEVICE_B)
        .await
        .expect("b mints");

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
    if revoke_m {
        let now_secs = now_ms / 1_000;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(m),
            sender.machine.public_key(),
            sender.machine.secret_key(),
            now_secs,
            None,
        )
        .expect("sign machine revocation");
        receiver
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)
            .expect("insert machine revocation");
    }
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
    (
        relation.map(|r| r & crate::peer_evidence::ENROLLED),
        (totals.requests_allowed, totals.requests_denied),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrollment_made_on_another_owner_device_admits_exec_after_sync() {
    let (enrolled, totals) = sync_then_exec(false).await;
    assert_eq!(
        enrolled,
        Some(crate::peer_evidence::ENROLLED),
        "B must hold M as an enrolled owner machine after syncing with A"
    );
    assert_eq!(totals, (1, 0), "exec on B must admit M's agent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_synced_enrollment_of_a_revoked_machine_stays_denied() {
    let (enrolled, totals) = sync_then_exec(true).await;
    assert_eq!(
        enrolled,
        Some(crate::peer_evidence::ENROLLED),
        "the enrollment itself is applied"
    );
    assert_eq!(totals.0, 0, "exec on B must not admit a revoked machine");
}
