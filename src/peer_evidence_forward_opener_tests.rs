#![cfg(test)]

//! #1107: a `ForwardV2` opener that the receiver knows only from ADR 0089
//! evidence. The discovery cache is empty, as after a restart of the
//! receiver or before the opener's identity announce arrives.
//!
//! The rule under test: on a discovery-cache miss the forward gate may take
//! the opener's certificate from a usable evidence record, only when the
//! stream proves the agent key (the signed `ForwardV2` header), the record
//! names the transport machine, and the certificate verifies, is current
//! and is not revoked. Nothing is written to the discovery cache or the
//! binding registry.

use super::tests::{setup, Peer};
use super::*;
use crate::connect::ConnectDenialReason;
use crate::forward::{decide_inbound_attested, AttestationVerifyCtx, ForwardV2Header};
use crate::identity::{AgentCertificate, AgentKeypair, MachineId, UserKeypair};
use crate::revocation::{RevocationRecord, RevocationSet, RevokedSubject};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

const TARGET: &str = "127.0.0.1:22";

struct Fixture {
    _dir: tempfile::TempDir,
    peer: Peer,
    local_machine: MachineId,
    owner_trust: crate::owner_trust::OwnerTrust,
    revocations: Arc<tokio::sync::RwLock<RevocationSet>>,
    bindings: Arc<tokio::sync::RwLock<crate::dm_inbox::AuthenticatedMachineBindingCache>>,
    discovery: Arc<tokio::sync::RwLock<HashMap<AgentId, crate::DiscoveredAgent>>>,
    _runtime: Arc<EvidenceRuntime>,
}

/// The receiver's owner enrolled the peer's machine, and the evidence store
/// holds the peer's record with `cert` (when given). The discovery cache is
/// empty.
async fn fixture(
    owner: &UserKeypair,
    cert: impl FnOnce(&Peer) -> Option<AgentCertificate>,
) -> Fixture {
    let peer = Peer::new();
    let local = Peer::new();
    let now = crate::dm_capability::now_unix_ms();
    let (dir, policy, store) = setup(&peer);
    drop(store);
    let mut record = peer.record(now, now);
    record.certificate = cert(&peer).map(|c| c.to_storage_bytes().expect("cert bytes"));
    let fixture_store =
        PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, now).expect("store");
    // An expired certificate may be refused here already; the gate must
    // deny either way, so the result is not asserted.
    let _ = fixture_store.ingest(record, IngestSource::Hello, now);
    fixture_store.flush(now, true).expect("flush");
    drop(fixture_store);

    let bindings = Arc::new(tokio::sync::RwLock::new(
        crate::dm_inbox::AuthenticatedMachineBindingCache::default(),
    ));
    let owner_trust = crate::owner_trust::OwnerTrust::new(Some(owner.user_id()), bindings.clone());
    let devices = Arc::new(
        crate::owner_sync::OwnerSyncStore::load(dir.path())
            .await
            .expect("device store"),
    );
    devices
        .enroll(
            crate::owner_sync::OwnerEnrollment::sign(peer.m(), owner, now - 1000, None)
                .expect("enrollment"),
        )
        .await
        .expect("enroll");
    owner_trust.install_device_store(devices);
    let revocations = Arc::new(tokio::sync::RwLock::new(RevocationSet::new()));
    let runtime = Arc::new(EvidenceRuntime::default());
    owner_trust.install_evidence(&runtime);
    runtime.start(
        dir.path().to_owned(),
        EvidenceConfig::default(),
        Arc::new(RuntimePolicy::new(
            local.a(),
            owner_trust.clone(),
            revocations.clone(),
        )),
        Arc::default(),
    );
    assert!(runtime.wait(0).await, "the evidence runtime loads");
    Fixture {
        _dir: dir,
        peer,
        local_machine: local.m(),
        owner_trust,
        revocations,
        bindings,
        discovery: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        _runtime: runtime,
    }
}

fn owner_policy() -> crate::connect::ConnectPolicy {
    let text = format!(
        "[connect]\nenabled = true\n[[connect.allow]]\nprincipal = \"owner\"\ntargets = [\"{TARGET}\"]\n"
    );
    crate::connect::parse_connect_policy(std::path::Path::new("/tmp/x"), 0, &text)
        .expect("owner policy")
}

/// A header naming `agent` (with that agent's public key), signed by
/// `signer`, addressed to `recipient`.
fn header(agent: &AgentKeypair, signer: &AgentKeypair, recipient: MachineId) -> ForwardV2Header {
    let target: SocketAddr = TARGET.parse().expect("target");
    let mut header = ForwardV2Header::new(
        target.ip().to_string(),
        target.port(),
        agent.agent_id(),
        agent.public_key().as_bytes().to_vec(),
        recipient,
    );
    header.sign(signer).expect("sign");
    header
}

async fn decide(
    f: &Fixture,
    header: &ForwardV2Header,
    peer_machine: MachineId,
) -> std::result::Result<SocketAddr, ConnectDenialReason> {
    let contacts = Arc::new(tokio::sync::RwLock::new(
        crate::contacts::ContactStore::new(f._dir.path().join("contacts.json")),
    ));
    let ctx = AttestationVerifyCtx::for_test(
        Arc::clone(&f.discovery),
        contacts,
        f.local_machine,
        Arc::clone(&f.revocations),
        f.owner_trust.clone(),
        false,
    );
    decide_inbound_attested(header, &owner_policy(), &peer_machine, &ctx).await
}

async fn assert_registries_empty(f: &Fixture) {
    assert!(
        f.discovery.read().await.is_empty(),
        "the evidence lookup writes nothing to the discovery cache"
    );
    assert!(
        crate::dm_inbox::authenticated_machine_binding(&f.bindings, &f.peer.a())
            .await
            .is_none(),
        "the evidence lookup writes nothing to the binding registry"
    );
}

/// The receiver knows the opener only from evidence: the owner-principal
/// forward is admitted. RED before #1107: `agent_not_in_discovery_cache`.
#[tokio::test]
async fn forward_opener_known_only_from_evidence_is_admitted() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, |p| AgentCertificate::issue(&owner, &p.agent).ok()).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(
        decide(&f, &h, f.peer.m()).await,
        Ok(TARGET.parse().expect("target"))
    );
    assert_registries_empty(&f).await;
}

/// A machine that names the agent and carries its public key, but cannot
/// sign as that agent, is denied. The machine-signed record alone is never
/// enough.
#[tokio::test]
async fn forward_opener_that_cannot_sign_as_the_agent_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, |p| AgentCertificate::issue(&owner, &p.agent).ok()).await;
    let forger = AgentKeypair::generate().expect("forger");
    let h = header(&f.peer.agent, &forger, f.local_machine);
    assert_eq!(
        decide(&f, &h, f.peer.m()).await,
        Err(ConnectDenialReason::AttestationFailed)
    );
    assert_registries_empty(&f).await;
}

/// The record names another machine than the transport peer: denied.
#[tokio::test]
async fn forward_opener_on_another_machine_than_the_record_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, |p| AgentCertificate::issue(&owner, &p.agent).ok()).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    let other = MachineId([0x5a; 32]);
    assert!(decide(&f, &h, other).await.is_err());
    assert_registries_empty(&f).await;
}

/// The fixture really stores a usable record, so the denial tests below
/// fail for their own reason, not for an empty store.
#[tokio::test]
async fn fixture_record_is_usable() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, |p| AgentCertificate::issue(&owner, &p.agent).ok()).await;
    let now = crate::dm_capability::now_unix_ms();
    assert!(f._runtime.usable(f.peer.a(), f.peer.m(), now).is_some());
}

/// A self-revoked agent is denied, though its record is still on disk.
#[tokio::test]
async fn forward_opener_with_a_revoked_agent_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, |p| AgentCertificate::issue(&owner, &p.agent).ok()).await;
    let record = RevocationRecord::sign(
        RevokedSubject::Agent(f.peer.a()),
        f.peer.agent.public_key(),
        f.peer.agent.secret_key(),
        crate::dm_capability::now_unix_ms() / 1000,
        None,
    )
    .expect("revocation");
    f.revocations
        .write()
        .await
        .verify_and_insert(record, None)
        .expect("insert revocation");
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert!(decide(&f, &h, f.peer.m()).await.is_err());
    assert_registries_empty(&f).await;
}

/// An expired certificate gives no owner trust: denied.
#[tokio::test]
async fn forward_opener_with_an_expired_certificate_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    // Past the expiry clock-skew allowance, so the certificate is expired.
    let past =
        crate::dm_capability::now_unix_ms() / 1000 - crate::identity::EXPIRY_CLOCK_SKEW_SECS - 60;
    let f = fixture(&owner, |p| {
        AgentCertificate::issue_with_expiry(&owner, &p.agent, Some(past)).ok()
    })
    .await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert!(decide(&f, &h, f.peer.m()).await.is_err());
    assert_registries_empty(&f).await;
}

/// A certificate from another owner gives no owner trust: denied.
#[tokio::test]
async fn forward_opener_with_a_foreign_certificate_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let stranger = UserKeypair::generate().expect("stranger");
    let f = fixture(&owner, |p| {
        AgentCertificate::issue(&stranger, &p.agent).ok()
    })
    .await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert!(decide(&f, &h, f.peer.m()).await.is_err());
    assert_registries_empty(&f).await;
}
