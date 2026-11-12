#![cfg(test)]

//! #1107: the exec gate after a true restart of the receiving daemon.
//!
//! The receiver holds only durable state: its key files, the owner device
//! store (the sender's machine is enrolled) and the ADR 0089 evidence store
//! (the sender's record carries an owner-issued certificate). The discovery
//! cache and the binding registry are empty, as in a fresh process. The test
//! sends a real `ExecFrame::Request` through `ExecService::spawn`, the same
//! inbound loop the daemon runs, so `inbound_owner_trusted` decides on the
//! real `Agent`. It does not carry the frame over a DM: the DM layer already
//! set `verified` and the contact decision when it handed the payload over.

use super::acl::{AllowedCommand, AllowedToken, ExecAcl, ExecCaps, ExecPolicy, OwnerAllowEntry};
use super::protocol::{encode_frame_payload, DenialReason, ExecFrame, ExecRequestId};
use super::service::ExecService;
use crate::dm_inbox::DmTypedPayload;
use crate::identity::UserKeypair;
use crate::identity::{AgentCertificate, AgentId, AgentKeypair, MachineId, MachineKeypair};
use crate::peer_evidence::{
    EvidenceConfig, EvidencePolicy, IngestSource, PeerEvidenceStore, GROUP,
};
use crate::trust::TrustDecision;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const SEED: [u8; 32] = [0x11; 32];
/// A refusal must come fast; a timeout cannot satisfy a test.
const REFUSAL_BOUND: Duration = Duration::from_secs(10);

/// Admits every record at ingest. The receiver's real policy runs after the
/// restart; this one only writes the files a past session left behind.
struct SeedPolicy;

impl EvidencePolicy for SeedPolicy {
    fn relation(&self, _: AgentId, _: MachineId, _: Option<&AgentCertificate>, _: u64) -> u8 {
        GROUP
    }
    fn revoked(&self, _: AgentId, _: MachineId, _: Option<crate::identity::UserId>) -> bool {
        false
    }
    fn contains_agent(&self, _: AgentId, _: u64) -> bool {
        true
    }
}

struct Sender {
    agent: AgentKeypair,
    machine: MachineKeypair,
}

struct Rig {
    _dir: tempfile::TempDir,
    sender: Sender,
    receiver: Arc<crate::Agent>,
    service: Arc<ExecService>,
    tx: mpsc::Sender<DmTypedPayload>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

async fn build_receiver(dir: &Path) -> Arc<crate::Agent> {
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let agent = crate::Agent::builder()
        .with_machine_key(dir.join("rx-machine.key"))
        .with_agent_key_path(dir.join("rx-agent.key"))
        .with_agent_cert_path(dir.join("rx-agent.cert"))
        .with_user_key(owner)
        .with_contact_store_path(dir.join("rx-contacts.json"))
        .with_peer_cache_disabled()
        .with_network_config(crate::network::NetworkConfig {
            bind_addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            bootstrap_nodes: Vec::new(),
            port_mapping_enabled: false,
            mdns_enabled: false,
            ..crate::network::NetworkConfig::default()
        })
        .build()
        .await
        .expect("receiver");
    let agent = Arc::new(agent);
    let store = Arc::new(
        crate::owner_sync::OwnerSyncStore::load(&dir.join("sync"))
            .await
            .expect("device store"),
    );
    agent.install_owner_device_store(store);
    agent
        .start_peer_evidence(
            dir.join("evidence"),
            EvidenceConfig::default(),
            Arc::new(|_| Some(false)),
        )
        .expect("evidence starts");
    assert!(agent.peer_evidence().wait(0).await, "evidence loads");
    agent
}

fn owner_acl(dir: &Path) -> ExecPolicy {
    ExecPolicy::Enabled(ExecAcl {
        loaded_from: dir.join("exec-acl.toml"),
        loaded_at_unix_ms: 1,
        caps: ExecCaps {
            max_duration_secs: 5,
            default_cwd: Some(std::path::PathBuf::from("/tmp")),
            ..ExecCaps::default()
        },
        audit_log_path: dir.join("exec-audit.jsonl"),
        audit_tasklist_id: None,
        allow: Vec::new(),
        owner_allow: vec![OwnerAllowEntry {
            description: Some("owner echo".to_string()),
            max_duration_secs: None,
            commands: vec![AllowedCommand {
                argv: vec![
                    AllowedToken::Literal("echo".to_string()),
                    AllowedToken::Literal("ok".to_string()),
                ],
            }],
        }],
        grant_allow: Vec::new(),
    })
}

/// Build the receiver's past: enrol the sender's machine and persist an
/// evidence record that carries `cert`. Then run the receiver once, stop it
/// with `try_shutdown`, and start it again on the same files.
async fn rig(cert_not_after: Option<u64>) -> Rig {
    let dir = tempfile::tempdir().expect("tmpdir");
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let sender = Sender {
        agent: AgentKeypair::generate().expect("agent key"),
        machine: MachineKeypair::generate().expect("machine key"),
    };
    let now_ms = crate::dm_capability::now_unix_ms();

    // Durable evidence: the sender's record, certificate included.
    let mut record =
        crate::peer_evidence::record_for_test(&sender.agent, &sender.machine, now_ms, now_ms);
    let cert =
        AgentCertificate::issue_with_expiry(&owner, &sender.agent, cert_not_after).expect("cert");
    record.certificate = Some(cert.to_storage_bytes().expect("cert bytes"));
    let seed_store = PeerEvidenceStore::open(
        &dir.path().join("evidence"),
        EvidenceConfig::default(),
        Arc::new(SeedPolicy),
        now_ms,
    )
    .expect("seed store");
    seed_store
        .ingest(record, IngestSource::Hello, now_ms)
        .expect("seed record");
    seed_store.flush(now_ms, true).expect("flush");
    drop(seed_store);

    // Durable owner state: the sender's machine is enrolled.
    let devices = crate::owner_sync::OwnerSyncStore::load(&dir.path().join("sync"))
        .await
        .expect("device store");
    devices
        .enroll(
            crate::owner_sync::OwnerEnrollment::sign(
                sender.machine.machine_id(),
                &owner,
                now_ms / 1000 - 1000,
                None,
            )
            .expect("enrollment"),
        )
        .await
        .expect("enroll");
    drop(devices);

    // Before: the receiver runs on these files, then stops completely.
    let before = build_receiver(dir.path()).await;
    before.try_shutdown().await.expect("receiver shuts down");
    assert!(
        before
            .network()
            .expect("network")
            .node_status()
            .await
            .is_none(),
        "the old endpoint must be gone before the restart"
    );
    drop(before);

    // THE RESTART: a fresh process-equivalent on the same files.
    let receiver = build_receiver(dir.path()).await;
    assert!(
        receiver
            .discovered_agent_for_testing(&sender.agent.agent_id())
            .await
            .is_none(),
        "the restarted receiver has no discovery entry for the sender"
    );
    let (tx, rx) = mpsc::channel(8);
    let service = ExecService::spawn(Arc::clone(&receiver), owner_acl(dir.path()), rx);
    Rig {
        _dir: dir,
        sender,
        receiver,
        service,
        tx,
    }
}

impl Rig {
    async fn request(&self, id: u8) {
        let frame = ExecFrame::Request {
            request_id: ExecRequestId([id; 16]),
            argv: vec!["echo".to_string(), "ok".to_string()],
            stdin: None,
            timeout_ms: 1_000,
            cwd: None,
        };
        self.tx
            .send(DmTypedPayload {
                sender: self.sender.agent.agent_id(),
                machine_id: self.sender.machine.machine_id(),
                payload: encode_frame_payload(&frame).expect("encode"),
                verified: true,
                trust_decision: Some(TrustDecision::Unknown),
                received_at_unix_ms: crate::dm_capability::now_unix_ms(),
                request_id: [id; 16],
                completion: None,
            })
            .await
            .expect("inbound channel open");
    }

    /// Wait until `total` requests have an outcome; return (allowed, denied
    /// by `trust_rejected`, denied for any other reason) and the elapsed time.
    async fn outcome(&self, total: u64) -> (u64, u64, u64, Duration) {
        let start = Instant::now();
        loop {
            let totals = self.service.diagnostics_snapshot().await.totals;
            if totals.requests_allowed + totals.requests_denied >= total
                || start.elapsed() > REFUSAL_BOUND
            {
                let trust = totals
                    .denial_breakdown
                    .get(DenialReason::TrustRejected.as_str())
                    .copied()
                    .unwrap_or(0);
                return (
                    totals.requests_allowed,
                    trust,
                    totals.requests_denied - trust,
                    start.elapsed(),
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn stop(self) {
        self.service.shutdown().await;
        self.receiver.try_shutdown().await.expect("receiver stops");
    }
}

/// An owner-trusted sender the restarted receiver knows only from the
/// evidence store and the enrollment is admitted to run the listed command.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_from_an_owner_trusted_peer_is_admitted_after_a_cold_restart() {
    let rig = rig(None).await;
    rig.request(1).await;
    let (allowed, trust_denied, other_denied, _) = rig.outcome(1).await;
    let cache_empty = rig
        .receiver
        .discovered_agent_for_testing(&rig.sender.agent.agent_id())
        .await
        .is_none();
    rig.stop().await;
    assert_eq!(
        (allowed, trust_denied, other_denied),
        (1, 0, 0),
        "the request must be admitted by owner trust from evidence"
    );
    assert!(
        cache_empty,
        "admission wrote nothing to the discovery cache"
    );
}

/// A first request is admitted; then the sender's agent is revoked. The next
/// request is refused with `trust_rejected`, fast, not by a timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_is_refused_with_trust_rejected_once_the_known_agent_is_revoked() {
    let rig = rig(None).await;
    rig.request(1).await;
    let control = rig.outcome(1).await;
    let revocation = crate::revocation::RevocationRecord::sign(
        crate::revocation::RevokedSubject::Agent(rig.sender.agent.agent_id()),
        rig.sender.agent.public_key(),
        rig.sender.agent.secret_key(),
        now_secs(),
        None,
    )
    .expect("revocation");
    rig.receiver
        .revocation_set()
        .write()
        .await
        .verify_and_insert(revocation, None)
        .expect("insert revocation");
    rig.request(2).await;
    let after = rig.outcome(2).await;
    rig.stop().await;
    assert_eq!(
        (control.0, control.1, control.2),
        (1, 0, 0),
        "control: admitted before the revocation"
    );
    assert_eq!(
        (after.0, after.1, after.2),
        (1, 1, 0),
        "the revoked sender must be refused with trust_rejected"
    );
    assert!(after.3 < REFUSAL_BOUND, "refusal took {:?}", after.3);
}

/// The sender's certificate is current at the restart, then expires. The
/// next request is refused with `trust_rejected`, fast, not by a timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_is_refused_with_trust_rejected_once_the_certificate_has_expired() {
    // The gate allows `EXPIRY_CLOCK_SKEW_SECS` past `not_after`; the control
    // runs inside it and the second request runs after it.
    let expires = now_secs() + 6 - crate::identity::EXPIRY_CLOCK_SKEW_SECS;
    let rig = rig(Some(expires)).await;
    rig.request(1).await;
    let control = rig.outcome(1).await;
    while now_secs() <= expires + crate::identity::EXPIRY_CLOCK_SKEW_SECS + 1 {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    rig.request(2).await;
    let after = rig.outcome(2).await;
    rig.stop().await;
    assert_eq!(
        (control.0, control.1, control.2),
        (1, 0, 0),
        "control: admitted while the certificate is current"
    );
    assert_eq!(
        (after.0, after.1, after.2),
        (1, 1, 0),
        "the expired certificate must be refused with trust_rejected"
    );
    assert!(after.3 < REFUSAL_BOUND, "refusal took {:?}", after.3);
}
