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
/// The denial for an opener the gate cannot accept from evidence. The
/// store's point-of-use check (`usable`) refuses a revoked or expired
/// record, so the gate finds no opener; a foreign certificate passes that
/// check but gives no owner trust. Both deny as for an unknown agent.
const NO_USABLE_EVIDENCE: ConnectDenialReason = ConnectDenialReason::AttestationFailed;

struct Fixture {
    _dir: tempfile::TempDir,
    peer: Peer,
    local_machine: MachineId,
    /// Another machine the same owner enrolled; it holds no record.
    other_enrolled: MachineId,
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
    fixture_store
        .ingest(record, IngestSource::Hello, now)
        .expect("the record is valid at ingest");
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
    let other_enrolled = Peer::new().m();
    devices
        .enroll(
            crate::owner_sync::OwnerEnrollment::sign(other_enrolled, owner, now - 1000, None)
                .expect("enrollment"),
        )
        .await
        .expect("enroll the other machine");
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
        other_enrolled,
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
    decide_with_policy(f, header, peer_machine, &owner_policy()).await
}

async fn decide_with_policy(
    f: &Fixture,
    header: &ForwardV2Header,
    peer_machine: MachineId,
    policy: &crate::connect::ConnectPolicy,
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
    decide_inbound_attested(header, policy, &peer_machine, &ctx).await
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

fn issued(owner: &UserKeypair) -> impl FnOnce(&Peer) -> Option<AgentCertificate> + '_ {
    move |p: &Peer| AgentCertificate::issue(owner, &p.agent).ok()
}

async fn assert_no_usable_evidence(f: &Fixture) {
    let now = crate::dm_capability::now_unix_ms();
    assert!(
        f._runtime.usable(f.peer.a(), f.peer.m(), now).is_none(),
        "the evidence store refuses the record at point of use"
    );
}

async fn revoke(f: &Fixture, record: RevocationRecord, cert: Option<&AgentCertificate>) {
    f.revocations
        .write()
        .await
        .verify_and_insert(record, cert)
        .expect("insert revocation");
}

fn now_secs() -> u64 {
    crate::dm_capability::now_unix_ms() / 1000
}

/// The receiver knows the opener only from evidence: the owner-principal
/// forward is admitted. RED before #1107: `AttestationFailed` from
/// `agent_not_in_discovery_cache`.
#[tokio::test]
async fn forward_opener_known_only_from_evidence_is_admitted() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(
        decide(&f, &h, f.peer.m()).await,
        Ok(TARGET.parse().expect("target"))
    );
    assert_registries_empty(&f).await;
}

/// The receiver knows the opener only from evidence and the owner gave the
/// opener a current ShareGrant with a Connect port for the target. The ACL
/// has only a `principal = "grant"` entry. The evidence path gives owner
/// trust only, so the grant entry must not match: the forward is denied.
/// RED without the #1107 grant gate in `authorize_attested_opener`: the
/// grant is confirmed from the evidence record and the forward is admitted.
#[tokio::test]
async fn forward_opener_known_only_from_evidence_is_not_admitted_by_a_grant_entry() {
    use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};

    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let target: SocketAddr = TARGET.parse().expect("target");
    let local_agent = AgentKeypair::generate().expect("local agent").agent_id();
    let grants = Arc::new(ShareGrantStore::in_memory(
        local_agent,
        Some(owner.user_id()),
    ));
    let now = now_secs();
    let grant = ShareGrant::sign(
        &owner,
        [0xB7; 32],
        Grantee::Agent(f.peer.a()),
        vec![local_agent],
        vec![ShareCap::Connect {
            ports: vec![target.port()],
        }],
        now - 60,
        now + 3600,
    )
    .expect("sign grant");
    grants.accept(grant, now).await.expect("accept grant");
    f.owner_trust.install_share_grant_store(grants);
    let text = format!(
        "[connect]\nenabled = true\n[[connect.allow]]\nprincipal = \"grant\"\ntargets = [\"{TARGET}\"]\n"
    );
    let grant_policy =
        crate::connect::parse_connect_policy(std::path::Path::new("/tmp/x"), 0, &text)
            .expect("grant policy");

    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(
        decide_with_policy(&f, &h, f.peer.m(), &grant_policy).await,
        Err(ConnectDenialReason::AgentMachineNotInAcl)
    );
    assert_registries_empty(&f).await;
}

/// The fixture really stores a usable record, so the denial tests below
/// fail for their own reason, not for an empty store.
#[tokio::test]
async fn fixture_record_is_usable() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let now = crate::dm_capability::now_unix_ms();
    assert!(f._runtime.usable(f.peer.a(), f.peer.m(), now).is_some());
}

/// A machine that names the agent and carries its public key, but cannot
/// sign as that agent, is denied. The machine-signed record alone is never
/// enough.
#[tokio::test]
async fn forward_opener_that_cannot_sign_as_the_agent_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let forger = AgentKeypair::generate().expect("forger");
    let h = header(&f.peer.agent, &forger, f.local_machine);
    assert_eq!(
        decide(&f, &h, f.peer.m()).await,
        Err(ConnectDenialReason::AttestationFailed)
    );
    assert_registries_empty(&f).await;
}

/// The transport machine is another machine of the same owner, enrolled
/// too, but the record names the agent's own machine: no evidence for this
/// pair, so the opener is unknown.
#[tokio::test]
async fn forward_opener_on_another_enrolled_machine_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(
        decide(&f, &h, f.other_enrolled).await,
        Err(ConnectDenialReason::AttestationFailed)
    );
    assert_registries_empty(&f).await;
}

/// A discovery entry that names a different machine is not overridden by
/// evidence: the cache answers, and the machine does not match.
#[tokio::test]
async fn discovery_entry_on_another_machine_is_not_overridden_by_evidence() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let elsewhere = MachineId([0x5a; 32]);
    let entry = crate::DiscoveredAgent {
        self_name: None,
        agent_id: f.peer.a(),
        machine_id: elsewhere,
        user_id: None,
        addresses: Vec::new(),
        announced_at: 0,
        last_seen: 0,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: f.peer.agent.public_key().as_bytes().to_vec(),
        cert_digest: None,
    };
    f.discovery.write().await.insert(f.peer.a(), entry);
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(
        decide(&f, &h, f.peer.m()).await,
        Err(ConnectDenialReason::AgentNotOnMachine)
    );
    let cache = f.discovery.read().await;
    assert_eq!(cache.len(), 1);
    assert_eq!(
        cache.get(&f.peer.a()).map(|e| e.machine_id),
        Some(elsewhere),
        "the discovery entry is not rewritten from evidence"
    );
}

/// A self-revoked agent is denied, though its record is still on disk.
#[tokio::test]
async fn forward_opener_with_a_revoked_agent_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let record = RevocationRecord::sign(
        RevokedSubject::Agent(f.peer.a()),
        f.peer.agent.public_key(),
        f.peer.agent.secret_key(),
        now_secs(),
        None,
    )
    .expect("revocation");
    revoke(&f, record, None).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(decide(&f, &h, f.peer.m()).await, Err(NO_USABLE_EVIDENCE));
    assert_no_usable_evidence(&f).await;
    assert_registries_empty(&f).await;
}

/// A self-revoked machine is denied on the evidence path.
#[tokio::test]
async fn forward_opener_on_a_revoked_machine_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let record = RevocationRecord::sign(
        RevokedSubject::Machine(f.peer.m()),
        f.peer.machine.public_key(),
        f.peer.machine.secret_key(),
        now_secs(),
        None,
    )
    .expect("revocation");
    revoke(&f, record, None).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(decide(&f, &h, f.peer.m()).await, Err(NO_USABLE_EVIDENCE));
    assert_no_usable_evidence(&f).await;
    assert_registries_empty(&f).await;
}

/// The owner retired the agent's binding to this machine: denied on the
/// evidence path.
#[tokio::test]
async fn forward_opener_with_a_revoked_binding_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let cert = AgentCertificate::issue(&owner, &f.peer.agent).expect("cert");
    let record = RevocationRecord::sign(
        RevokedSubject::AgentMachineBinding(crate::revocation::AgentMachineBinding {
            agent: f.peer.a(),
            machine: f.peer.m(),
            move_epoch: 1,
        }),
        owner.public_key(),
        owner.secret_key(),
        now_secs(),
        None,
    )
    .expect("revocation");
    revoke(&f, record, Some(&cert)).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(decide(&f, &h, f.peer.m()).await, Err(NO_USABLE_EVIDENCE));
    assert_no_usable_evidence(&f).await;
    assert_registries_empty(&f).await;
}

/// The certificate is valid when the record is stored and expires before
/// the forward: the gate denies (the ingest succeeded; see the fixture).
#[tokio::test]
async fn forward_opener_whose_certificate_expired_after_ingest_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    // Expired, with the skew allowance, two seconds from now.
    let not_after = now_secs() + 2 - crate::identity::EXPIRY_CLOCK_SKEW_SECS;
    let f = fixture(&owner, |p| {
        AgentCertificate::issue_with_expiry(&owner, &p.agent, Some(not_after)).ok()
    })
    .await;
    let now = crate::dm_capability::now_unix_ms();
    assert!(
        f._runtime.usable(f.peer.a(), f.peer.m(), now).is_some(),
        "the certificate is still current at ingest"
    );
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(decide(&f, &h, f.peer.m()).await, Err(NO_USABLE_EVIDENCE));
    assert_no_usable_evidence(&f).await;
    assert_registries_empty(&f).await;
}

/// A certificate from another owner gives no owner trust: denied.
#[tokio::test]
async fn forward_opener_with_a_foreign_certificate_is_denied() {
    let owner = UserKeypair::generate().expect("owner");
    let stranger = UserKeypair::generate().expect("stranger");
    let f = fixture(&owner, issued(&stranger)).await;
    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(decide(&f, &h, f.peer.m()).await, Err(NO_USABLE_EVIDENCE));
    // Here the record itself is usable; owner trust refuses the foreign
    // certificate, and an evidence opener is admitted for owner trust only.
    let now = crate::dm_capability::now_unix_ms();
    assert!(f._runtime.usable(f.peer.a(), f.peer.m(), now).is_some());
    assert_registries_empty(&f).await;
}

/// The receiver knows the opener only from evidence, and the ACL has only
/// an exact-pair entry for the opener's agent and machine on the target.
/// Only a `principal = "owner"` entry admits such an opener (A03, A05), so
/// the forward is denied. RED without the owner-entry check in
/// `authorize_attested_opener` (Greptile P1 on #1869): the exact-pair entry
/// matches and the forward is admitted.
#[tokio::test]
async fn forward_opener_known_only_from_evidence_is_not_admitted_by_an_exact_pair_entry() {
    let owner = UserKeypair::generate().expect("owner");
    let f = fixture(&owner, issued(&owner)).await;
    let text = format!(
        "[connect]\nenabled = true\n[[connect.allow]]\nagent_id = \"{}\"\nmachine_id = \"{}\"\ntargets = [\"{TARGET}\"]\n",
        hex::encode(f.peer.a().0),
        hex::encode(f.peer.m().0),
    );
    let pair_policy =
        crate::connect::parse_connect_policy(std::path::Path::new("/tmp/x"), 0, &text)
            .expect("pair policy");

    let h = header(&f.peer.agent, &f.peer.agent, f.local_machine);
    assert_eq!(
        decide_with_policy(&f, &h, f.peer.m(), &pair_policy).await,
        Err(ConnectDenialReason::AgentMachineNotInAcl)
    );
    assert_registries_empty(&f).await;
}
