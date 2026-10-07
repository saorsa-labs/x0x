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
            grant_allow: Vec::new(),
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

// ── #1040: enrolled owner-sync admission for a machine with no known agent ──

/// A transport-authenticated machine whose discovery-cache entry is EMPTY
/// (no agent announced on it), seen by an install owned by `local_owner`,
/// enrolled per `enrollment` (signed by `enroller`, normally the owner).
struct UnknownMachine {
    _dir: tempfile::TempDir,
    machine_kp: MachineKeypair,
    machine_id: MachineId,
    contacts: Arc<RwLock<ContactStore>>,
    cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>,
    revocations: Arc<RwLock<RevocationSet>>,
    move_state: Arc<RwLock<MoveState>>,
    connect_policy: Arc<std::sync::RwLock<Arc<ConnectPolicy>>>,
    devices: Arc<OwnerSyncStore>,
    bindings: AuthenticatedMachineBindings,
    trust: OwnerTrust,
}

impl UnknownMachine {
    async fn new(
        local_owner: &UserKeypair,
        enroller: &UserKeypair,
        enrollment: Enrollment,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tmpdir");
        let machine_kp = MachineKeypair::generate().expect("machine keygen");
        let machine_id = machine_kp.machine_id();
        let devices = OwnerSyncStore::load(dir.path())
            .await
            .expect("device store");
        let now_ms = unix_now_secs().saturating_mul(1000);
        let enrolled = match enrollment {
            Enrollment::Current => {
                Some(OwnerEnrollment::sign(machine_id, enroller, now_ms, None).expect("sign"))
            }
            Enrollment::Expired => {
                Some(OwnerEnrollment::sign(machine_id, enroller, 1_000, Some(2_000)).expect("sign"))
            }
            Enrollment::None => None,
        };
        if let Some(enrolled) = enrolled {
            devices.enroll(enrolled).await.expect("enroll");
        }
        let devices = Arc::new(devices);
        let bindings = AuthenticatedMachineBindings::default();
        let trust = OwnerTrust::new(Some(local_owner.user_id()), Arc::clone(&bindings));
        trust.install_device_store(Arc::clone(&devices));
        Self {
            machine_kp,
            machine_id,
            contacts: Arc::new(RwLock::new(ContactStore::new(
                dir.path().join("contacts.json"),
            ))),
            cache: Arc::new(RwLock::new(HashMap::new())),
            revocations: Arc::new(RwLock::new(RevocationSet::new())),
            move_state: Arc::new(RwLock::new(MoveState::default())),
            connect_policy: Arc::new(std::sync::RwLock::new(Arc::new(ConnectPolicy::default()))),
            devices,
            bindings,
            trust,
            _dir: dir,
        }
    }

    async fn enrolled() -> (UserKeypair, Self) {
        let owner = UserKeypair::generate().expect("owner keygen");
        let machine = Self::new(&owner, &owner, Enrollment::Current).await;
        (owner, machine)
    }

    /// The accept loop's pre-prefix branch decision.
    async fn candidate(&self) -> bool {
        crate::Agent::enrolled_owner_sync_candidate(
            &self.cache,
            &self.revocations,
            &self.trust,
            &self.machine_id,
        )
        .await
    }

    /// The accept loop's post-prefix routing for `protocol`.
    async fn route(
        &self,
        protocol: crate::streams::StreamProtocol,
    ) -> crate::EnrolledOwnerSyncRoute<()> {
        crate::Agent::route_enrolled_owner_sync(
            &self.cache,
            &self.revocations,
            &self.trust,
            &self.machine_id,
            protocol,
            || (),
        )
        .await
    }

    /// Whether the post-prefix routing admits `protocol` on enrollment.
    async fn admits(&self, protocol: crate::streams::StreamProtocol) -> bool {
        matches!(
            self.route(protocol).await,
            crate::EnrolledOwnerSyncRoute::Admitted(())
        )
    }

    /// Make an agent KNOWN on this machine (as a delivered announcement
    /// would), returning its id. A class A announcement also records the
    /// authenticated binding (ADR 0115 §1).
    async fn learn_agent(&self) -> AgentId {
        let agent_kp = AgentKeypair::generate().expect("agent keygen");
        let agent_id = agent_kp.agent_id();
        crate::dm_inbox::record_authenticated_machine_binding(
            &self.bindings,
            agent_id,
            self.machine_id,
            unix_now_secs(),
        )
        .await;
        self.cache.write().await.insert(
            agent_id,
            DiscoveredAgent {
                self_name: None,
                agent_id,
                machine_id: self.machine_id,
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
                agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
                cert_digest: None,
            },
        );
        agent_id
    }

    /// Both halves: what an inbound SyncV1 stream actually gets.
    async fn sync_v1_admitted(&self) -> bool {
        self.candidate().await && self.admits(crate::streams::StreamProtocol::SyncV1).await
    }

    /// The shared inbound gate (datagram lane, forwards, and the accept
    /// loop for every machine outside the #1040 branch).
    async fn shared_gate(&self) -> Result<Vec<AgentId>, NetworkError> {
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
}

const NON_SYNC_PROTOCOLS: [crate::streams::StreamProtocol; 4] = [
    crate::streams::StreamProtocol::ForwardV1,
    crate::streams::StreamProtocol::SocksV1,
    crate::streams::StreamProtocol::ForwardV2,
    crate::streams::StreamProtocol::WebRtcV1,
];

// #1040 positive control: the verified enrollment alone admits SyncV1 from
// a machine the discovery cache does not know. Without this the negative
// cases below would pass vacuously.
#[tokio::test]
async fn enrolled_machine_with_no_known_agent_is_admitted_for_sync_v1() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    assert!(m.cache.read().await.is_empty(), "no agent is known");
    assert!(m.sync_v1_admitted().await);
}

// #1040: nothing is widened. An enrolled but otherwise unknown machine's
// forward, SOCKS, and media streams are still denied, and the shared gate
// (datagram lane, forward decisions) still says `deny_not_verified`.
#[tokio::test]
async fn enrolled_machine_with_no_known_agent_gets_no_other_stream_kind() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    assert!(
        m.candidate().await,
        "precondition: the #1040 branch is taken"
    );
    for protocol in NON_SYNC_PROTOCOLS {
        assert!(
            !m.admits(protocol).await,
            "{protocol:?} from an enrolled but unknown machine must stay denied"
        );
    }
    assert!(matches!(
        m.shared_gate().await,
        Err(NetworkError::PeerNotVerified { .. })
    ));
}

// #1040: a transport-authenticated machine that is NOT enrolled is still
// denied its SyncV1 stream.
#[tokio::test]
async fn non_enrolled_machine_sync_v1_is_denied() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let m = UnknownMachine::new(&owner, &owner, Enrollment::None).await;
    assert!(!m.candidate().await);
    assert!(!m.admits(crate::streams::StreamProtocol::SyncV1).await);
    assert!(matches!(
        m.shared_gate().await,
        Err(NetworkError::PeerNotVerified { .. })
    ));
}

// #1040: an enrollment signed by a DIFFERENT owner is not in this device's
// verified set (the signature must chain to the local owner).
#[tokio::test]
async fn foreign_owner_enrollment_is_denied() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let stranger = UserKeypair::generate().expect("stranger keygen");
    let m = UnknownMachine::new(&owner, &stranger, Enrollment::Current).await;
    assert!(!m.sync_v1_admitted().await);
}

// #1040: an expired enrollment is denied.
#[tokio::test]
async fn expired_enrollment_is_denied_for_sync_v1_admission() {
    let owner = UserKeypair::generate().expect("owner keygen");
    let m = UnknownMachine::new(&owner, &owner, Enrollment::Expired).await;
    assert!(!m.candidate().await);
    assert!(!m.admits(crate::streams::StreamProtocol::SyncV1).await);
}

// #1040: a revoked machine (ADR-0018 revocation set) is denied even though
// its enrollment still verifies, and the re-check after the prefix read
// catches a revocation that lands after the pre-prefix check.
#[tokio::test]
async fn revoked_machine_enrollment_is_denied_even_mid_admission() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    assert!(
        m.candidate().await,
        "precondition: admitted before revocation"
    );
    let record = RevocationRecord::sign(
        RevokedSubject::Machine(m.machine_id),
        m.machine_kp.public_key(),
        m.machine_kp.secret_key(),
        unix_now_secs(),
        None,
    )
    .expect("sign machine revocation");
    m.revocations
        .write()
        .await
        .verify_and_insert(record, None)
        .expect("insert machine revocation");
    assert!(
        !m.admits(crate::streams::StreamProtocol::SyncV1).await,
        "the post-prefix re-check must see the revocation"
    );
    assert!(!m.candidate().await);
}

// #1040: a deleted enrollment (`DELETE /sync/devices/:id`) is denied.
#[tokio::test]
async fn deleted_enrollment_is_denied() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    assert!(m.sync_v1_admitted().await, "precondition");
    assert!(m.devices.unenroll(&m.machine_id).await.expect("unenroll"));
    assert!(!m.sync_v1_admitted().await);
}

// #1040: the branch is only for machines with NO known agent. Once any
// agent is known on the machine, the shared agent-level gate decides (so
// revoked/blocked/expired agents are never bypassed by the enrollment).
#[tokio::test]
async fn known_agent_on_enrolled_machine_uses_the_shared_gate() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    m.learn_agent().await;
    assert!(!m.candidate().await);
}

// #1044 review round 1 (P2): the pre-prefix check found no known agent, but
// a BLOCKED agent on the machine becomes known while the prefix is read.
// The post-prefix routing must send the stream to the shared gate (which
// denies it), not admit it on the enrollment alone. Deterministic: the
// agent is learned between the two decisions, with no sleeps. Before the
// fix the post-prefix step re-checked only the enrollment and admitted.
#[tokio::test]
async fn agent_learned_during_prefix_read_goes_through_the_shared_gate() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    assert!(m.candidate().await, "pre-prefix: enrolled, no known agent");
    let agent_id = m.learn_agent().await;
    m.contacts
        .write()
        .await
        .set_trust(&agent_id, TrustLevel::Blocked);
    assert_eq!(
        m.route(crate::streams::StreamProtocol::SyncV1).await,
        crate::EnrolledOwnerSyncRoute::SharedGate,
        "an agent known at admission time must not ride the enrollment-only path"
    );
    assert!(matches!(
        m.shared_gate().await,
        Err(NetworkError::PeerTrustRejected { .. })
    ));
}

// #1044 P2, the ACL arm: the newly known agent is otherwise acceptable
// (a Trusted contact) but not on an Enabled connect ACL. The shared gate's
// ACL still applies, so the stream is denied.
#[tokio::test]
async fn agent_learned_during_prefix_read_is_still_subject_to_the_connect_acl() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    assert!(m.candidate().await, "pre-prefix: enrolled, no known agent");
    let agent_id = m.learn_agent().await;
    m.contacts
        .write()
        .await
        .set_trust(&agent_id, TrustLevel::Trusted);
    assert!(
        m.shared_gate().await.is_ok(),
        "precondition: trusted passes"
    );
    *m.connect_policy
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Arc::new(ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: std::path::PathBuf::from("/test/connect-acl.toml"),
            loaded_at_unix_ms: 0,
            allow: Vec::new(),
            owner_allow: Vec::new(),
            grant_allow: Vec::new(),
        }));
    assert_eq!(
        m.route(crate::streams::StreamProtocol::SyncV1).await,
        crate::EnrolledOwnerSyncRoute::SharedGate
    );
    assert!(matches!(
        m.shared_gate().await,
        Err(NetworkError::PeerNotInConnectAcl { .. })
    ));
}

// #1044 P2: the admission closure runs only on the enrollment-only path,
// and never when an agent is known (the handoff is decided under the same
// discovery-cache guard as the "no known agent" check).
#[tokio::test]
async fn admission_closure_runs_only_while_no_agent_is_known() {
    let (_owner, m) = UnknownMachine::enrolled().await;
    let mut ran = false;
    let route = crate::Agent::route_enrolled_owner_sync(
        &m.cache,
        &m.revocations,
        &m.trust,
        &m.machine_id,
        crate::streams::StreamProtocol::SyncV1,
        || ran = true,
    )
    .await;
    assert_eq!(route, crate::EnrolledOwnerSyncRoute::Admitted(()));
    assert!(ran);
    m.learn_agent().await;
    let mut ran = false;
    let route = crate::Agent::route_enrolled_owner_sync(
        &m.cache,
        &m.revocations,
        &m.trust,
        &m.machine_id,
        crate::streams::StreamProtocol::SyncV1,
        || ran = true,
    )
    .await;
    assert_eq!(route, crate::EnrolledOwnerSyncRoute::SharedGate);
    assert!(!ran, "no enrollment-only handoff once an agent is known");
}

// #1040: an install without the owner device set installed (or without an
// owner) admits nothing on enrollment.
#[tokio::test]
async fn no_device_store_or_no_owner_admits_nothing() {
    let (owner, mut m) = UnknownMachine::enrolled().await;
    m.trust = OwnerTrust::new(
        Some(owner.user_id()),
        AuthenticatedMachineBindings::default(),
    );
    assert!(!m.sync_v1_admitted().await, "no device store installed");
    m.trust = OwnerTrust::new(None, AuthenticatedMachineBindings::default());
    m.trust.install_device_store(Arc::clone(&m.devices));
    assert!(!m.sync_v1_admitted().await, "ownerless install");
}

/// Inert production admission regression: no QUIC node, sockets, or gossip.
#[tokio::test(start_paused = true)]
async fn s3_stream_gate_silent_strangers_cannot_block_known_or_enrolled_sync() {
    use crate::streams::{read_protocol_prefix, StreamProtocol, PREFIX_READ_TIMEOUT};
    use tokio::io::AsyncWriteExt;
    let (_owner, f) = Fixture::same_owner().await;
    let limits = Arc::new(crate::evidence_wire::Limits::default());
    let mut held = Vec::new();
    let mut silent_writers = Vec::new();
    for id in 0..16 {
        let machine = MachineId([id; 32]);
        for _ in 0..2 {
            let admission = crate::Agent::admit_stream_before_prefix(
                &f.cache,
                &f.contacts,
                &f.revocations,
                &f.move_state,
                &f.connect_policy,
                &f.trust,
                &machine,
                &limits,
            )
            .await
            .unwrap();
            assert!(admission.agents.is_none());
            assert!(admission.prefix.is_some());
            let (tx, mut rx) = tokio::io::duplex(1);
            silent_writers.push(tx);
            held.push(tokio::spawn(async move {
                let _admission = admission;
                tokio::time::timeout(PREFIX_READ_TIMEOUT, read_protocol_prefix(&mut rx)).await
            }));
        }
        assert!(crate::Agent::admit_stream_before_prefix(
            &f.cache,
            &f.contacts,
            &f.revocations,
            &f.move_state,
            &f.connect_policy,
            &f.trust,
            &machine,
            &limits,
        )
        .await
        .is_none());
    }
    tokio::task::yield_now().await; // All silent readers are now pending.
    assert!(limits.admit_prefix(MachineId([99; 32])).is_none());
    assert_eq!(
        limits
            .prefix_refused
            .load(std::sync::atomic::Ordering::Relaxed),
        17
    );
    let start = tokio::time::Instant::now();
    // Exercise the same pre-prefix admission as the production accept loop.
    let known = crate::Agent::admit_stream_before_prefix(
        &f.cache,
        &f.contacts,
        &f.revocations,
        &f.move_state,
        &f.connect_policy,
        &f.trust,
        &f.machine_id,
        &limits,
    )
    .await
    .unwrap();
    assert_eq!(known.agents, Some(vec![f.agent_id]));
    assert!(known.prefix.is_none());
    let (mut tx, mut rx) = tokio::io::duplex(1);
    tx.write_u8(StreamProtocol::SyncV1.as_u8()).await.unwrap();
    assert_eq!(
        read_protocol_prefix(&mut rx).await.unwrap(),
        StreamProtocol::SyncV1
    );
    assert_eq!(start.elapsed(), std::time::Duration::ZERO);
    assert!(held.iter().all(|task| !task.is_finished()));
    // The enrolled-only path also bypasses the saturated pool and still
    // admits only owner sync when no agent is known.
    f.cache.write().await.clear();
    let enrolled = crate::Agent::admit_stream_before_prefix(
        &f.cache,
        &f.contacts,
        &f.revocations,
        &f.move_state,
        &f.connect_policy,
        &f.trust,
        &f.machine_id,
        &limits,
    )
    .await
    .unwrap();
    assert!(enrolled.agents.is_none() && enrolled.prefix.is_none());
    let delivered = crate::Agent::route_enrolled_owner_sync(
        &f.cache,
        &f.revocations,
        &f.trust,
        &f.machine_id,
        StreamProtocol::SyncV1,
        || true,
    )
    .await;
    assert!(matches!(
        delivered,
        crate::EnrolledOwnerSyncRoute::Admitted(true)
    ));
    for task in held {
        task.abort();
        let _ = task.await;
    }
    assert!(limits.admit_prefix(MachineId([99; 32])).is_some());
}

#[tokio::test]
async fn s3_stream_gate_known_denial_precedes_prefix_admission() {
    let (_owner, mut f) = Fixture::same_owner().await;
    f.trust = OwnerTrust::new(None, AuthenticatedMachineBindings::default());
    let limits = Arc::new(crate::evidence_wire::Limits::default());
    assert!(crate::Agent::admit_stream_before_prefix(
        &f.cache,
        &f.contacts,
        &f.revocations,
        &f.move_state,
        &f.connect_policy,
        &f.trust,
        &f.machine_id,
        &limits,
    )
    .await
    .is_none());
    assert_eq!(
        limits
            .prefix_refused
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn s3_enrolled_machine_gets_reserved_evidence_capacity_without_discovery() {
    let (_owner, f) = UnknownMachine::enrolled().await;
    let limits = Arc::new(crate::evidence_wire::Limits::default());
    let strangers: Vec<_> = (0..4)
        .map(|id| limits.admit(MachineId([id; 32]), false).unwrap())
        .collect();
    let related =
        crate::evidence_wire::reserved_peer(None, &f.trust, &f.revocations, f.machine_id).await;
    assert!(related);
    assert!(limits.admit(f.machine_id, related).is_some());
    let stranger = MachineId([99; 32]);
    let related =
        crate::evidence_wire::reserved_peer(None, &f.trust, &f.revocations, stranger).await;
    assert!(!related);
    assert!(limits.admit(stranger, related).is_none());
    drop(strangers);
}
