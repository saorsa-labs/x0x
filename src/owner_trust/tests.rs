//! ADR-0070 slice 1 intent tests. Each negative case would pass (and so
//! fail the assertion) if the owner check it guards were loosened or removed.

use super::*;
use crate::connect::{ConnectAcl, ConnectOwnerEntry, ConnectPolicy};
use crate::contacts::TrustLevel;
use crate::error::NetworkError;
use crate::identity::{AgentKeypair, MachineKeypair, UserKeypair};
use crate::key_move::MoveState;
use crate::owner_sync::OwnerEnrollment;
use crate::revocation::{RevocationRecord, RevokedSubject};

/// How the fixture's machine is enrolled in the local owner device set.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Enrollment {
    /// Current enrollment signed by the local owner.
    Current,
    /// Enrollment signed by the local owner whose expiry is long past.
    Expired,
    /// The machine is not in the device set.
    None,
}

struct Fixture {
    _dir: tempfile::TempDir,
    agent_kp: AgentKeypair,
    agent_id: AgentId,
    machine_id: MachineId,
    contacts: Arc<RwLock<ContactStore>>,
    cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>,
    revocations: Arc<RwLock<RevocationSet>>,
    move_state: Arc<RwLock<MoveState>>,
    connect_policy: Arc<std::sync::RwLock<Arc<ConnectPolicy>>>,
    devices: Arc<OwnerSyncStore>,
    local_owner: UserId,
    trust: OwnerTrust,
}

impl Fixture {
    /// A remote pair seen by an install owned by `local_owner`. The remote
    /// agent's certificate is signed by `cert_signer` (with `cert_not_after`)
    /// and its machine enrolled per `enrollment` (always by `local_owner`).
    async fn new(
        local_owner: &UserKeypair,
        cert_signer: Option<&UserKeypair>,
        cert_not_after: Option<u64>,
        enrollment: Enrollment,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent_kp = AgentKeypair::generate().expect("agent keygen");
        let agent_id = agent_kp.agent_id();
        let machine_id = MachineKeypair::generate()
            .expect("machine keygen")
            .machine_id();
        let cert = cert_signer.map(|signer| {
            AgentCertificate::issue_with_expiry(signer, &agent_kp, cert_not_after)
                .expect("cert issue")
        });

        let devices = OwnerSyncStore::load(dir.path())
            .await
            .expect("device store");
        let now_ms = unix_now_secs().saturating_mul(1000);
        let enrolled = match enrollment {
            Enrollment::Current => Some(
                OwnerEnrollment::sign(machine_id, local_owner, now_ms, None).expect("enroll sign"),
            ),
            Enrollment::Expired => Some(
                OwnerEnrollment::sign(machine_id, local_owner, 1_000, Some(2_000))
                    .expect("enroll sign"),
            ),
            Enrollment::None => None,
        };
        if let Some(enrolled) = enrolled {
            devices.enroll(enrolled).await.expect("enroll");
        }
        let devices = Arc::new(devices);
        // The agent's authenticated binding names its real machine, as an
        // accepted identity announcement would record it (#890).
        let bindings = AuthenticatedMachineBindings::default();
        crate::dm_inbox::record_authenticated_machine_binding(
            &bindings,
            agent_id,
            machine_id,
            unix_now_secs(),
        )
        .await;
        let trust = OwnerTrust::new(Some(local_owner.user_id()), bindings);
        trust.install_device_store(Arc::clone(&devices));

        let mut cache = HashMap::new();
        cache.insert(
            agent_id,
            DiscoveredAgent {
                self_name: None,
                agent_id,
                machine_id,
                user_id: cert_signer.map(UserKeypair::user_id),
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
                cert_not_after: cert.as_ref().and_then(AgentCertificate::not_after),
                agent_certificate: cert,
                agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
                cert_digest: None,
            },
        );
        let contacts = ContactStore::new(dir.path().join("contacts.json"));
        Self {
            _dir: dir,
            agent_kp,
            agent_id,
            machine_id,
            contacts: Arc::new(RwLock::new(contacts)),
            cache: Arc::new(RwLock::new(cache)),
            revocations: Arc::new(RwLock::new(RevocationSet::new())),
            move_state: Arc::new(RwLock::new(MoveState::default())),
            connect_policy: Arc::new(std::sync::RwLock::new(Arc::new(ConnectPolicy::default()))),
            devices,
            local_owner: local_owner.user_id(),
            trust,
        }
    }

    /// Same owner, valid cert, current enrollment: the positive case.
    async fn same_owner() -> (UserKeypair, Self) {
        let owner = UserKeypair::generate().expect("owner keygen");
        let fixture = Self::new(&owner, Some(&owner), None, Enrollment::Current).await;
        (owner, fixture)
    }

    async fn pair(&self) -> PairTrust {
        self.trust
            .evaluate_pair(
                &self.contacts,
                &self.cache,
                &self.revocations,
                &self.agent_id,
                &self.machine_id,
            )
            .await
    }

    /// Replace the owner-trust source with one whose authenticated
    /// bindings are `bindings` (same owner, same device store).
    fn with_bindings(&mut self, bindings: AuthenticatedMachineBindings) {
        self.trust = OwnerTrust::new(Some(self.local_owner), bindings);
        self.trust.install_device_store(Arc::clone(&self.devices));
    }

    /// The real inbound stream gate (accept loop / datagram lane).
    async fn inbound_gate(&self) -> Result<Vec<AgentId>, NetworkError> {
        crate::Agent::gate_peer_machine_inbound(
            &self.cache,
            &self.contacts,
            &self.revocations,
            &self.move_state,
            &self.connect_policy,
            &self.trust,
            &self.machine_id,
        )
        .await
    }

    fn set_connect_policy(&self, owner_entry: bool) {
        let owner_allow = if owner_entry {
            vec![ConnectOwnerEntry {
                description: Some("my machines".to_string()),
                targets: vec!["127.0.0.1:22".parse().expect("loopback literal")],
            }]
        } else {
            Vec::new()
        };
        let policy = ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: std::path::PathBuf::from("/test/connect-acl.toml"),
            loaded_at_unix_ms: 0,
            allow: Vec::new(),
            owner_allow,
        });
        *self
            .connect_policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(policy);
    }
}

// (1) R3: an owner's own certified agent on an enrolled machine passes the
// stream gate with NO contact entry and NO ACL edit.
#[tokio::test]
async fn same_owner_pair_passes_stream_gate_without_contact() {
    let (_owner, f) = Fixture::same_owner().await;
    assert!(f.contacts.read().await.get(&f.agent_id).is_none());

    let pair = f.pair().await;
    assert!(pair.owner_trusted);
    assert_eq!(pair.decision, TrustDecision::Accept);
    assert_eq!(f.inbound_gate().await.expect("gate"), vec![f.agent_id]);
}

// Control for (1): the SAME pair on an install with no owner is Unknown and
// refused, so the pass above is owner trust and nothing else.
#[tokio::test]
async fn ownerless_install_does_not_owner_trust() {
    let (_owner, mut f) = Fixture::same_owner().await;
    f.trust = OwnerTrust::new(None, AuthenticatedMachineBindings::default());
    let pair = f.pair().await;
    assert!(!pair.owner_trusted);
    assert_eq!(pair.decision, TrustDecision::Unknown);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}

// (2) A different owner's agent on a machine WE enrolled is still Unknown
// and refused. Fails if the user-id comparison is dropped.
#[tokio::test]
async fn other_owners_agent_is_denied() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let stranger = UserKeypair::generate().expect("stranger keygen");
    let f = Fixture::new(&owner, Some(&stranger), None, Enrollment::Current).await;
    let pair = f.pair().await;
    assert!(!pair.owner_trusted);
    assert_eq!(pair.decision, TrustDecision::Unknown);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}

// (2) An agent that presents no certificate at all is not owner-trusted,
// even on an enrolled machine.
#[tokio::test]
async fn uncertified_agent_is_denied() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let f = Fixture::new(&owner, None, None, Enrollment::Current).await;
    assert!(!f.pair().await.owner_trusted);
    assert!(f.inbound_gate().await.is_err());
}

// (2) Our owner's certificate for a DIFFERENT agent must not vouch for this
// one. Fails if the cert-subject check is dropped.
#[tokio::test]
async fn owner_certificate_for_another_agent_is_denied() {
    let (owner, f) = Fixture::same_owner().await;
    let other_agent = AgentKeypair::generate().expect("agent keygen");
    let foreign_cert = AgentCertificate::issue(&owner, &other_agent).expect("cert issue");
    if let Some(entry) = f.cache.write().await.get_mut(&f.agent_id) {
        entry.agent_certificate = Some(foreign_cert);
    }
    assert!(!f.pair().await.owner_trusted);
    assert!(f.inbound_gate().await.is_err());
}

// (b) Same owner, but the machine is not enrolled ⇒ refused.
#[tokio::test]
async fn unenrolled_machine_is_denied() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let f = Fixture::new(&owner, Some(&owner), None, Enrollment::None).await;
    assert!(!f.pair().await.owner_trusted);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}

// (3) An expired enrollment no longer vouches for the machine.
#[tokio::test]
async fn expired_enrollment_is_denied() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let f = Fixture::new(&owner, Some(&owner), None, Enrollment::Expired).await;
    assert!(!f.pair().await.owner_trusted);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}

// (3) An expired owner certificate grants no owner trust.
#[tokio::test]
async fn expired_certificate_is_denied() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let f = Fixture::new(&owner, Some(&owner), Some(1), Enrollment::Current).await;
    assert!(!f.pair().await.owner_trusted);
    assert!(f.inbound_gate().await.is_err());
}

// (c) After the agent is revoked (ADR-0018), the previously accepted pair
// is refused.
#[tokio::test]
async fn revoked_agent_loses_owner_trust() {
    let (_owner, f) = Fixture::same_owner().await;
    assert!(f.inbound_gate().await.is_ok(), "precondition: accepted");

    let record = RevocationRecord::sign(
        RevokedSubject::Agent(f.agent_id),
        f.agent_kp.public_key(),
        f.agent_kp.secret_key(),
        unix_now_secs(),
        None,
    )
    .expect("sign revocation");
    f.revocations
        .write()
        .await
        .verify_and_insert(record, None)
        .expect("insert revocation");

    assert!(!f.pair().await.owner_trusted);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerRevoked { .. })
    ));
}

// (4) An explicit Blocked contact beats owner trust.
#[tokio::test]
async fn blocked_contact_beats_owner_trust() {
    let (_owner, f) = Fixture::same_owner().await;
    f.contacts
        .write()
        .await
        .set_trust(&f.agent_id, TrustLevel::Blocked);
    let pair = f.pair().await;
    assert_eq!(pair.decision, TrustDecision::RejectBlocked);
    assert!(!pair.owner_trusted);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}

// (5 / e) PR #896 decision 1: with a connect ACL in force, owner trust alone
// opens nothing — the stream is refused until a `principal = "owner"` entry
// exists.
#[tokio::test]
async fn owner_trust_without_owner_acl_entry_is_denied_by_connect_acl() {
    let (_owner, f) = Fixture::same_owner().await;
    f.set_connect_policy(false);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerNotInConnectAcl { .. })
    ));

    f.set_connect_policy(true);
    assert_eq!(f.inbound_gate().await.expect("gate"), vec![f.agent_id]);
}

// Invariant (Root, #911): an agent with NO valid owner certificate that
// self-announces the machine_id of a CURRENTLY ENROLLED owner machine gets
// nothing — not owner-trusted, refused by the stream gate, and not matched by
// a `principal = "owner"` connect entry. Enrollment vouches for the machine
// only; without the owner cert on the agent it must never confer trust.
// Covers both a foreign-owner agent and an owner-less (uncertified) agent.
#[tokio::test]
async fn uncertified_agent_claiming_enrolled_machine_gets_nothing() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let stranger = UserKeypair::generate().expect("stranger keygen");
    for signer in [Some(&stranger), None] {
        let f = Fixture::new(&owner, signer, None, Enrollment::Current).await;
        // Precondition: the claimed machine really is currently enrolled.
        let devices = f.trust.device_store().expect("device store installed");
        assert!(devices.is_enrolled(&f.machine_id, &owner.user_id()).await);

        assert!(!f.pair().await.owner_trusted);
        assert!(matches!(
            f.inbound_gate().await,
            Err(NetworkError::PeerTrustRejected { .. })
        ));

        // With an owner entry in force (and a Trusted contact so only the ACL
        // can refuse), the owner selector still does not match.
        f.set_connect_policy(true);
        f.contacts
            .write()
            .await
            .set_trust(&f.agent_id, TrustLevel::Trusted);
        assert!(matches!(
            f.inbound_gate().await,
            Err(NetworkError::PeerNotInConnectAcl { .. })
        ));
    }
}

// (5) The owner entry matches owner pairs only: a different owner's agent
// on an enrolled machine is refused even with the entry present.
#[tokio::test]
async fn owner_acl_entry_does_not_match_non_owner_pairs() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let stranger = UserKeypair::generate().expect("stranger keygen");
    let f = Fixture::new(&owner, Some(&stranger), None, Enrollment::Current).await;
    // Give the stranger a Trusted contact so only the ACL can refuse it.
    f.contacts
        .write()
        .await
        .set_trust(&f.agent_id, TrustLevel::Trusted);
    f.set_connect_policy(true);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerNotInConnectAcl { .. })
    ));
}

// ── Pairing comes only from the authenticated binding (#911 fix) ─────────

// (1) The discovery cache's machine_id is mutable (connect_to_agent, raw
// Direct mark_connected). Pointing it at an enrolled machine with NO
// authenticated binding must confer nothing — fail closed, as after LRU
// eviction.
#[tokio::test]
async fn cache_machine_rewrite_without_binding_gets_no_owner_trust() {
    let (_owner, mut f) = Fixture::same_owner().await;
    f.with_bindings(AuthenticatedMachineBindings::default());
    if let Some(entry) = f.cache.write().await.get_mut(&f.agent_id) {
        entry.machine_id = f.machine_id;
    }
    assert!(!f.pair().await.owner_trusted);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}

// (2) The binding names machine A; the transport peer is enrolled machine B
// (the cache has been rewritten to B). No owner trust for (agent, B).
#[tokio::test]
async fn binding_to_other_machine_than_transport_peer_gets_no_owner_trust() {
    let (_owner, mut f) = Fixture::same_owner().await;
    let machine_a = MachineKeypair::generate()
        .expect("machine keygen")
        .machine_id();
    let bindings = AuthenticatedMachineBindings::default();
    crate::dm_inbox::record_authenticated_machine_binding(
        &bindings,
        f.agent_id,
        machine_a,
        unix_now_secs(),
    )
    .await;
    f.with_bindings(bindings);
    // f.machine_id (B) is enrolled and is what the cache says.
    assert!(f.devices.is_enrolled(&f.machine_id, &f.local_owner).await);
    assert!(!f.pair().await.owner_trusted);
    assert!(f.inbound_gate().await.is_err());
}

// (3) Binding == transport peer + valid owner cert + enrolled machine: trust.
// (The positive control for (1), (2) and (4) — same fixture, binding intact.)
#[tokio::test]
async fn binding_matching_transport_peer_with_cert_and_enrollment_is_trusted() {
    let (_owner, f) = Fixture::same_owner().await;
    let pair = f.pair().await;
    assert!(pair.owner_trusted);
    assert_eq!(pair.decision, TrustDecision::Accept);
    assert_eq!(f.inbound_gate().await.expect("gate"), vec![f.agent_id]);
}

// (4) #898 path: an UNVERIFIED raw Direct message calls
// `DirectMessaging::mark_connected(sender, machine)` and the cache may be
// rewritten to that machine. Neither writes the authenticated binding, so an
// agent with no binding gains no owner trust from it.
#[tokio::test]
async fn unverified_raw_direct_mark_connected_cannot_confer_owner_trust() {
    let (_owner, mut f) = Fixture::same_owner().await;
    f.with_bindings(AuthenticatedMachineBindings::default());
    let dm = crate::direct::DirectMessaging::new();
    dm.mark_connected(f.agent_id, f.machine_id).await;
    if let Some(entry) = f.cache.write().await.get_mut(&f.agent_id) {
        entry.machine_id = f.machine_id;
    }
    assert!(!f.pair().await.owner_trusted);
    assert!(matches!(
        f.inbound_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}
