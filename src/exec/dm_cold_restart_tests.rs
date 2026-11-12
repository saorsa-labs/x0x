#![cfg(test)]

//! #1107: an exec request over the real DM path after a true restart of the
//! receiving daemon.
//!
//! Two real `Agent`s talk over loopback gossip. The sender `S` is owner
//! enrolled on the receiver `R` and known to `R` only from durable state: the
//! owner device store and the ADR 0089 evidence store. `R` stops with
//! `try_shutdown` and starts again on the same files, so its discovery cache
//! and binding registry are empty. `S` then calls `ExecService::run_remote`,
//! the call the `x0x exec` route makes. The request travels as a signed
//! gossip DM into `R`'s DM inbox, through the exec typed route and into the
//! `ExecService` loop; the reply travels back the same way.
//!
//! The senders are owner devices that have consented, so they announce their
//! user identity at join. A V3 announcement names the certificate digest
//! only; the bytes come by a later fetch. The request goes out without
//! waiting for that fetch, so it meets the window in which the receiver's
//! evidence record for the sender is replaced by that announcement. The
//! store keeps the stored certificate across a same-digest announcement
//! (`PeerEvidenceStore::carry_certificate`); without it the request is
//! refused with `trust_rejected` until the fetch completes.

use super::acl::{AllowedCommand, AllowedToken, ExecAcl, ExecCaps, ExecPolicy, OwnerAllowEntry};
use super::protocol::decode_frame_payload;
use super::protocol::ExecRunResult;
use super::service::{ExecRunOptions, ExecService};
use crate::dm_inbox::{DmInboxConfig, DmTypedPayload};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::identity::{AgentCertificate, AgentId, MachineId, UserKeypair};
use crate::peer_evidence::{
    EvidenceConfig, EvidencePolicy, IngestSource, PeerEvidenceStore, GROUP,
};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const SEED: [u8; 32] = [0x11; 32];
/// Stated bound for a request on a cold-restarted receiver, from the call to
/// the result. A timeout inside the exec client is 100 s; this is shorter.
const BOUND: Duration = Duration::from_secs(40);

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

fn loopback_config() -> crate::network::NetworkConfig {
    crate::network::NetworkConfig {
        bind_addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        mdns_enabled: false,
        ..crate::network::NetworkConfig::default()
    }
}

/// A node with its DM inbox (exec route) and exec service running.
struct Node {
    agent: Arc<crate::Agent>,
    service: Arc<ExecService>,
}

async fn start_node(agent: crate::Agent, policy: ExecPolicy, dir: &Path, name: &str) -> Node {
    let agent = Arc::new(agent);
    let (tx, rx) = mpsc::channel::<DmTypedPayload>(64);
    let kem = Arc::new(
        AgentKemKeypair::load_or_generate(&dir.join(format!("{name}-kem.key")))
            .await
            .expect("kem key"),
    );
    let config = DmInboxConfig::default().with_validated_typed_payload_route(
        super::EXEC_DM_PREFIX,
        tx,
        |payload| decode_frame_payload(payload).is_ok(),
    );
    agent.start_dm_inbox(kem, config).await.expect("dm inbox");
    let service = ExecService::spawn(Arc::clone(&agent), policy, rx);
    agent.join_network().await.expect("join network");
    Node { agent, service }
}

fn disabled() -> ExecPolicy {
    ExecPolicy::Disabled {
        path: std::path::PathBuf::from("/nonexistent/exec-acl.toml"),
        reason: "client only".to_string(),
        loaded_at_unix_ms: 1,
    }
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

async fn build_sender(dir: &Path, name: &str) -> crate::Agent {
    crate::Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.join(format!("{name}-agent.key")))
        .with_agent_cert_path(dir.join(format!("{name}-agent.cert")))
        .with_user_key(UserKeypair::from_seed(&SEED).expect("owner key"))
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_peer_cache_disabled()
        .with_network_config(loopback_config())
        .build()
        .await
        .expect("sender")
}

async fn build_receiver(dir: &Path) -> crate::Agent {
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let agent = crate::Agent::builder()
        .with_machine_key(dir.join("rx-machine.key"))
        .with_agent_key_path(dir.join("rx-agent.key"))
        .with_agent_cert_path(dir.join("rx-agent.cert"))
        .with_user_key(owner)
        .with_identity_dir(dir.join("identity"))
        .with_contact_store_path(dir.join("rx-contacts.json"))
        .with_peer_cache_disabled()
        .with_network_config(loopback_config())
        .build()
        .await
        .expect("receiver");
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

struct Rig {
    dir: tempfile::TempDir,
    /// `senders[0]` is under test; `senders[1]` is the unrevoked control.
    senders: [Node; 2],
    receiver: Node,
}

/// Build the receiver's past from the senders' real keys, stop it, start it
/// again, and connect the senders to the new receiver. With `revoke_first`
/// the receiver revokes `senders[0]`'s agent and persists it before the stop.
async fn rig(revoke_first: bool) -> Rig {
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::create_dir_all(dir.path().join("identity")).expect("identity dir");
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let s0 = build_sender(dir.path(), "s0").await;
    let s1 = build_sender(dir.path(), "s1").await;
    let now_ms = crate::dm_capability::now_unix_ms();

    // Durable evidence and owner enrollment, from the senders' real keys.
    let seed_store = PeerEvidenceStore::open(
        &dir.path().join("evidence"),
        EvidenceConfig::default(),
        Arc::new(SeedPolicy),
        now_ms,
    )
    .expect("seed store");
    let devices = crate::owner_sync::OwnerSyncStore::load(&dir.path().join("sync"))
        .await
        .expect("device store");
    for sender in [&s0, &s1] {
        let identity = sender.identity();
        // The certificate the sender really holds, as its past Hello stored it.
        let cert = identity
            .agent_certificate()
            .cloned()
            .expect("the sender holds an owner certificate");
        let record = crate::peer_evidence::record_with_certificate_for_test(
            identity.agent_keypair(),
            identity.machine_keypair(),
            Some(&cert),
            now_ms,
            now_ms,
        );
        seed_store
            .ingest(record, IngestSource::Hello, now_ms)
            .expect("seed record");
        devices
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(
                    identity.machine_id(),
                    &owner,
                    now_ms - 1_000,
                    None,
                )
                .expect("enrollment"),
            )
            .await
            .expect("enroll");
    }
    seed_store.flush(now_ms, true).expect("flush");
    drop(seed_store);
    drop(devices);

    // Before: the receiver runs on these files, then stops completely.
    let before = build_receiver(dir.path()).await;
    if revoke_first {
        let identity = s0.identity();
        let revocation = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(identity.agent_id()),
            identity.agent_keypair().public_key(),
            identity.agent_keypair().secret_key(),
            now_ms / 1000,
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
    let receiver = start_node(
        build_receiver(dir.path()).await,
        owner_acl(dir.path()),
        dir.path(),
        "rx",
    )
    .await;
    // An owner device that has consented (A05, #1107) announces its user
    // identity and certificate at join and in every heartbeat. Without it the
    // startup announce is anonymous and drops the certificate on the peer.
    for sender in [&s0, &s1] {
        sender
            .user_identity_consented
            .store(true, std::sync::atomic::Ordering::Release);
    }
    let senders = [
        start_node(s0, disabled(), dir.path(), "s0").await,
        start_node(s1, disabled(), dir.path(), "s1").await,
    ];
    let rx_addr = receiver
        .agent
        .network()
        .expect("network")
        .bound_addr()
        .await
        .expect("receiver address");
    for sender in &senders {
        // The receiver knows nothing of the sender.
        let id = sender.agent.agent_id();
        assert!(
            receiver
                .agent
                .discovered_agent_for_testing(&id)
                .await
                .is_none(),
            "the restarted receiver has no discovery entry for a sender"
        );
        assert!(
            crate::dm_inbox::authenticated_machine_binding_evidence(
                &receiver.agent.authenticated_machine_bindings(),
                &id,
            )
            .await
            .is_none(),
            "the restarted receiver has no binding for a sender"
        );
        // The sender knows the receiver, as a daemon that has met it does.
        sender
            .agent
            .insert_discovered_agent_for_testing(crate::DiscoveredAgent {
                self_name: None,
                cert_digest: None,
                agent_id: receiver.agent.agent_id(),
                machine_id: receiver.agent.machine_id(),
                user_id: None,
                addresses: vec![rx_addr],
                announced_at: now_ms / 1000,
                last_seen: now_ms / 1000,
                machine_public_key: vec![],
                nat_type: None,
                can_receive_direct: Some(true),
                is_relay: None,
                is_coordinator: None,
                reachable_via: vec![],
                relay_candidates: vec![],
                cert_not_after: None,
                agent_certificate: None,
                agent_public_key: vec![],
            })
            .await;
        sender
            .agent
            .set_contact_trusted_for_testing(receiver.agent.agent_id())
            .await;
        let connected = tokio::time::timeout(
            Duration::from_secs(10),
            sender
                .agent
                .network()
                .expect("network")
                .connect_addr(rx_addr),
        )
        .await
        .expect("connect deadline")
        .expect("connect");
        assert_eq!(connected.0, receiver.agent.machine_id().0);
    }
    // Gossip carries the receiver's DM capabilities to each sender, as it
    // does between daemons that have met. Ask until both senders hold them.
    for node in senders.iter().chain([&receiver]) {
        node.agent
            .gossip_runtime
            .as_ref()
            .expect("gossip")
            .pubsub()
            .refresh_topic_peers()
            .await;
    }
    let start = Instant::now();
    while senders.iter().any(|sender| {
        !sender
            .agent
            .capability_store
            .lookup(&receiver.agent.agent_id())
            .is_some_and(|caps| caps.gossip_inbox && !caps.kem_public_key.is_empty())
    }) {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "a sender never learned the receiver's DM capabilities"
        );
        for sender in &senders {
            let _ = crate::dm_capability_service::publish_targeted_capability_request(
                sender
                    .agent
                    .gossip_runtime
                    .as_ref()
                    .expect("gossip")
                    .pubsub(),
                receiver.agent.agent_id(),
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Rig {
        dir,
        senders,
        receiver,
    }
}

impl Rig {
    /// Run `echo ok` on the receiver from `senders[who]`, through the same
    /// call the `x0x exec` route makes. Waits for the sender to learn the
    /// receiver's DM capabilities first, since gossip carries them.
    async fn run(&self, who: usize) -> (Result<ExecRunResult, String>, Duration) {
        let sender = &self.senders[who];
        let start = Instant::now();
        let outcome = tokio::time::timeout(
            BOUND,
            sender.service.run_remote(
                self.receiver.agent.agent_id(),
                ExecRunOptions {
                    argv: vec!["echo".to_string(), "ok".to_string()],
                    stdin: None,
                    timeout_ms: Some(3_000),
                    cwd: None,
                },
            ),
        )
        .await;
        let result = match outcome {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => Err(format!("client error: {error}")),
            Err(_) => Err(format!("no result within {BOUND:?}")),
        };
        (result, start.elapsed())
    }

    async fn stop(self) {
        for sender in &self.senders {
            sender.service.shutdown().await;
            sender.agent.try_shutdown().await.expect("sender stops");
        }
        self.receiver.service.shutdown().await;
        self.receiver
            .agent
            .try_shutdown()
            .await
            .expect("receiver stops");
    }

    /// The exit code in the receiver's audit log for the request, polled.
    async fn audit_exit(&self, result: &ExecRunResult) -> Option<i64> {
        let wanted = result.request_id.to_hex();
        let path = self.dir.path().join("exec-audit.jsonl");
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
                start.elapsed() < Duration::from_secs(10),
                "no audit exit record for request {wanted}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

/// An owner-enrolled sender, known to the restarted receiver only from the
/// evidence store, gets its command run and the result back over DMs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_over_dm_is_admitted_after_the_receiver_restarts() {
    let rig = rig(false).await;
    // No wait for the certificate fetch: the request goes out at once.
    let (result, elapsed) = rig.run(0).await;
    let diagnostics = rig.receiver.service.diagnostics_snapshot().await.totals;
    let result = result.unwrap_or_else(|why| panic!("no result: {why}; receiver {diagnostics:?}"));
    assert_eq!(
        result.denial_reason, None,
        "the request must be admitted; receiver {diagnostics:?}"
    );
    assert_eq!(result.code, Some(0), "the command must exit 0");
    assert_eq!(String::from_utf8_lossy(&result.stdout), "ok\n");
    let audit = rig.audit_exit(&result).await;
    rig.stop().await;
    assert_eq!(audit, Some(0), "the audit log records exit 0");
    assert!(elapsed < BOUND, "took {elapsed:?}");
}

/// The sender's agent was revoked on the receiver before the restart, and
/// the revocation survived it. The receiver's pub/sub layer refuses every
/// payload signed by a revoked agent (`incoming_sender_refused`) before any
/// DM inbox or exec service sees it, and sends nothing back. So the revoked
/// sender gets no result and no refusal frame; the request never reaches the
/// exec service. An unrevoked owner sender on the same restarted receiver
/// gets its result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_over_dm_from_an_agent_revoked_before_the_restart_is_refused_unseen() {
    /// Long enough for a delivered request to be refused by the exec
    /// service and the refusal to come back (the control takes well under
    /// a second on loopback).
    const SILENCE: Duration = Duration::from_secs(10);
    let rig = rig(true).await;
    let (control, _) = rig.run(1).await;
    let diagnostics = rig.receiver.service.diagnostics_snapshot().await.totals;
    let control =
        control.unwrap_or_else(|why| panic!("control: no result: {why}; receiver {diagnostics:?}"));
    let refused = || {
        rig.receiver
            .agent
            .gossip_runtime
            .as_ref()
            .expect("gossip")
            .pubsub()
            .stats()
            .incoming_sender_refused
    };
    let refused_before = refused();
    let revoked_result = tokio::select! {
        outcome = rig.run(0) => Some(outcome),
        () = tokio::time::sleep(SILENCE) => None,
    };
    let refused_after = refused();
    let after = rig.receiver.service.diagnostics_snapshot().await.totals;
    rig.stop().await;
    assert_eq!(control.denial_reason, None, "control: admitted");
    assert_eq!(control.code, Some(0), "control: unrevoked sender runs");
    assert!(
        revoked_result.is_none(),
        "the revoked sender must get nothing back: {revoked_result:?}"
    );
    assert!(
        refused_after > refused_before,
        "the receiver's pub/sub must refuse the revoked sender's payloads"
    );
    assert_eq!(
        after.requests_received, diagnostics.requests_received,
        "the refused request never reaches the exec service"
    );
}
