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

pub(super) const SEED: [u8; 32] = [0x11; 32];
/// A refusal must come fast; a timeout cannot satisfy a test.
const REFUSAL_BOUND: Duration = Duration::from_secs(10);

/// Admits every record at ingest. The receiver's real policy runs after the
/// restart; this one only writes the files a past session left behind.
pub(super) struct SeedPolicy;

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

pub(super) struct Sender {
    pub(super) agent: AgentKeypair,
    pub(super) machine: MachineKeypair,
}

struct Rig {
    _dir: tempfile::TempDir,
    /// `senders[0]` is the sender under test; `senders[1]` is the control:
    /// owner-trusted the same way and never revoked.
    senders: [Sender; 2],
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

pub(super) async fn build_receiver(dir: &Path) -> Arc<crate::Agent> {
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let agent = crate::Agent::builder()
        .with_machine_key(dir.join("rx-machine.key"))
        .with_agent_key_path(dir.join("rx-agent.key"))
        .with_agent_cert_path(dir.join("rx-agent.cert"))
        .with_user_key(owner)
        .with_identity_dir(dir.join("identity"))
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

pub(super) fn owner_acl(dir: &Path) -> ExecPolicy {
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

pub(super) fn new_sender() -> Sender {
    Sender {
        agent: AgentKeypair::generate().expect("agent key"),
        machine: MachineKeypair::generate().expect("machine key"),
    }
}

/// Build the receiver's past: enrol both senders' machines and persist an
/// evidence record for each. Sender 0's certificate expires at
/// `cert_not_after`. With `revoke_first`, sender 0's agent is revoked on the
/// running receiver and persisted through `persist_identity_revocation_stores`
/// before it stops. Then the receiver stops with `try_shutdown` and starts
/// again on the same files.
async fn rig(cert_not_after: Option<u64>, revoke_first: bool) -> Rig {
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::create_dir_all(dir.path().join("identity")).expect("identity dir");
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let senders = [new_sender(), new_sender()];
    let now_ms = crate::dm_capability::now_unix_ms();

    // Durable evidence: each sender's record, certificate included.
    let seed_store = PeerEvidenceStore::open(
        &dir.path().join("evidence"),
        EvidenceConfig::default(),
        Arc::new(SeedPolicy),
        now_ms,
    )
    .expect("seed store");
    for (index, sender) in senders.iter().enumerate() {
        let mut record =
            crate::peer_evidence::record_for_test(&sender.agent, &sender.machine, now_ms, now_ms);
        let not_after = if index == 0 { cert_not_after } else { None };
        let cert =
            AgentCertificate::issue_with_expiry(&owner, &sender.agent, not_after).expect("cert");
        record.certificate = Some(cert.to_storage_bytes().expect("cert bytes"));
        seed_store
            .ingest(record, IngestSource::Hello, now_ms)
            .expect("seed record");
    }
    seed_store.flush(now_ms, true).expect("flush");
    drop(seed_store);

    // Durable owner state: both senders' machines are enrolled.
    let devices = crate::owner_sync::OwnerSyncStore::load(&dir.path().join("sync"))
        .await
        .expect("device store");
    for sender in &senders {
        devices
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(
                    sender.machine.machine_id(),
                    &owner,
                    now_ms - 1_000,
                    None,
                )
                .expect("enrollment"),
            )
            .await
            .expect("enroll");
    }
    drop(devices);

    // Before: the receiver runs on these files, then stops completely.
    let before = build_receiver(dir.path()).await;
    if revoke_first {
        let revocation = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(senders[0].agent.agent_id()),
            senders[0].agent.public_key(),
            senders[0].agent.secret_key(),
            now_secs(),
            None,
        )
        .expect("revocation");
        before
            .revocation_set()
            .write()
            .await
            .verify_and_insert(revocation, None)
            .expect("insert revocation");
        before
            .persist_identity_revocation_stores()
            .await
            .expect("revocation persists");
    }
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
    for sender in &senders {
        assert!(
            receiver
                .discovered_agent_for_testing(&sender.agent.agent_id())
                .await
                .is_none(),
            "the restarted receiver has no discovery entry for a sender"
        );
    }
    let (tx, rx) = mpsc::channel(8);
    let service = ExecService::spawn(Arc::clone(&receiver), owner_acl(dir.path()), rx);
    Rig {
        _dir: dir,
        senders,
        receiver,
        service,
        tx,
    }
}

impl Rig {
    async fn request(&self, who: usize, id: u8) {
        let frame = ExecFrame::Request {
            request_id: ExecRequestId([id; 16]),
            argv: vec!["echo".to_string(), "ok".to_string()],
            stdin: None,
            timeout_ms: 1_000,
            cwd: None,
        };
        self.tx
            .send(DmTypedPayload {
                sender: self.senders[who].agent.agent_id(),
                machine_id: self.senders[who].machine.machine_id(),
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

/// Wait for the audit log to hold the exit record of request `id`, then
/// return its exit code (`None` for a signal exit). The completion counter
/// moves before the audit line is written, so poll the file itself.
async fn exit_code_of(rig: &Rig, id: u8) -> Option<i64> {
    let wanted = ExecRequestId([id; 16]).to_hex();
    let path = rig._dir.path().join("exec-audit.jsonl");
    let start = Instant::now();
    loop {
        let log = std::fs::read_to_string(&path).unwrap_or_default();
        let exit = log
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| event["event"] == "exit" && event["request_id"] == wanted.as_str());
        if let Some(event) = exit {
            return event["code"].as_i64();
        }
        assert!(
            start.elapsed() < REFUSAL_BOUND,
            "no exit record for request {wanted} within {REFUSAL_BOUND:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// An owner-trusted sender the restarted receiver knows only from the
/// evidence store and the enrollment is admitted, and the listed command
/// runs and exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_from_an_owner_trusted_peer_is_admitted_after_a_cold_restart() {
    let rig = rig(None, false).await;
    rig.request(0, 1).await;
    let (allowed, trust_denied, other_denied, _) = rig.outcome(1).await;
    let code = exit_code_of(&rig, 1).await;
    let cache_empty = rig
        .receiver
        .discovered_agent_for_testing(&rig.senders[0].agent.agent_id())
        .await
        .is_none();
    rig.stop().await;
    assert_eq!(
        (allowed, trust_denied, other_denied),
        (1, 0, 0),
        "the request must be admitted by owner trust from evidence"
    );
    assert_eq!(code, Some(0), "the command must run and exit 0");
    assert!(
        cache_empty,
        "admission wrote nothing to the discovery cache"
    );
}

/// A first request is admitted; then the sender's agent is revoked in
/// memory. The next request is refused with `trust_rejected`, fast, not by
/// a timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_is_refused_with_trust_rejected_once_the_known_agent_is_revoked() {
    let rig = rig(None, false).await;
    rig.request(0, 1).await;
    let control = rig.outcome(1).await;
    let revocation = crate::revocation::RevocationRecord::sign(
        crate::revocation::RevokedSubject::Agent(rig.senders[0].agent.agent_id()),
        rig.senders[0].agent.public_key(),
        rig.senders[0].agent.secret_key(),
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
    rig.request(0, 2).await;
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

/// The revocation is persisted before the receiver stops
/// (`persist_identity_revocation_stores`) and must survive the restart:
/// the revoked sender is refused with `trust_rejected`, while a second,
/// unrevoked owner-trusted sender on the same restarted receiver is
/// admitted and its command exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_refuses_an_agent_revoked_before_the_restart() {
    let rig = rig(None, true).await;
    rig.request(1, 1).await;
    let control = rig.outcome(1).await;
    let code = exit_code_of(&rig, 1).await;
    rig.request(0, 2).await;
    let after = rig.outcome(2).await;
    rig.stop().await;
    assert_eq!(
        (control.0, control.1, control.2),
        (1, 0, 0),
        "control: the unrevoked sender is admitted on the restarted receiver"
    );
    assert_eq!(code, Some(0), "the control command must exit 0");
    assert_eq!(
        (after.0, after.1, after.2),
        (1, 1, 0),
        "the sender revoked before the restart must be refused with trust_rejected"
    );
    assert!(after.3 < REFUSAL_BOUND, "refusal took {:?}", after.3);
}

/// The sender's certificate is current at the restart, then expires. The
/// next request is refused with `trust_rejected`, fast, not by a timeout.
///
/// The trust clock is the system clock and the agent offers no injection
/// point, so the window is wide: the control has 20 s after the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_is_refused_with_trust_rejected_once_the_certificate_has_expired() {
    // The gate allows `EXPIRY_CLOCK_SKEW_SECS` past `not_after`.
    let skew = crate::identity::EXPIRY_CLOCK_SKEW_SECS;
    let expires = now_secs() + 20 - skew;
    let rig = rig(Some(expires), false).await;
    rig.request(0, 1).await;
    let control = rig.outcome(1).await;
    assert!(
        now_secs() <= expires + skew,
        "the control ran after the certificate expired; rerun on a quieter machine"
    );
    while now_secs() <= expires + skew + 1 {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    rig.request(0, 2).await;
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
