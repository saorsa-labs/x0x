#![cfg(test)]

//! GHSA-rr9m-cvx5-pmv9 (fixed in v0.46.5): regression tests
//! for ADR 0115 (Accepted), identity discovery authority.
//!
//! Root cause under test:
//! - V2 (`X0A2`) and V3 (`X0A3`) identity announcements are signed by a
//!   machine key only (`IdentityAnnouncement::verify`, src/lib.rs:1836;
//!   `IdentityAnnouncementV3::verify`, src/announce_v3.rs:373).
//! - An `AgentCertificate` is a user signature over an agent PUBLIC key. It
//!   carries no consent from that agent
//!   (`AgentCertificate::issue_for_public_key`, src/identity.rs:620).
//! - The identity listener merges every valid announcement into the
//!   discovery cache, and `upsert_discovered_agent` (src/lib.rs:2818) lets
//!   any equal-or-newer one replace the machine, certificate, digest and
//!   user. The pubsub author check (src/lib.rs:1956) only decides whether
//!   the separate authenticated-binding store is written.
//!
//! Each test:
//! - drives the REAL identity listener (`Agent::start_identity_listener`)
//!   with signed outer PlumTree frames, fed through the agent's real
//!   `PubSubManager` (`Agent::handle_gossip_incoming_for_test`);
//! - runs a CONTROL: the genuine path (pubsub envelope author == announced
//!   agent, genuine owner) must work before and after the fix;
//! - then runs the VECTOR and collects every open sub-case. On unfixed main
//!   the last assertion fails with `VECTOR OPEN`. A `HARNESS` or
//!   `CONTROL FAILED` panic is not vector evidence.
//!
//! Inert: one loopback-bound agent per test (127.0.0.1:0, no bootstrap
//! peers, mDNS and port mapping off, a private network id, a temporary
//! identity directory). The tests never join a network. No announcement
//! carries an address, so the listener's auto-connect never dials. Run only
//! through the isolation wrapper (`just test` or
//! `scripts/dev/test-isolated.py`).

use std::sync::Arc;
use std::time::Duration;

use crate::announce_v3;
use crate::gossip::pubsub::test_support::{outer_v2_frame, signed_inner_v2};
use crate::gossip::SigningContext;
use crate::groups::owner_cert::MemberCertStatus;
use crate::identity::{
    AgentCertificate, AgentId, AgentKeypair, MachineId, MachineKeypair, UserKeypair,
};
use crate::key_move::{self, Placement};
use crate::revocation::{AgentMachineBinding, RevocationRecord, RevokedSubject};
use crate::{Agent, IdentityAnnouncement};

/// The longest a harness step may wait for the listener.
const DEADLINE: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);
/// The attacker's timestamp lead. It is inside the listener's future-skew
/// bound (`IDENTITY_ANNOUNCEMENT_CLOCK_SKEW_SECS`, 30 s, src/lib.rs:1903)
/// and it beats every genuine beat (`>=` at src/lib.rs:2818).
const ATTACKER_LEAD_SECS: u64 = 20;
/// The daemon's revocation sweep TTL (`REVOCATION_RECORD_TTL_SECS`,
/// src/lib.rs:4262).
const REVOCATION_RECORD_TTL_SECS: u64 = 90 * 24 * 3600;
const DAY_SECS: u64 = 86_400;

fn now_secs() -> u64 {
    Agent::unix_timestamp_secs()
}

/// One agent with its own key, its real machine and a certificate from its
/// real owner.
struct Subject {
    agent: AgentKeypair,
    machine: MachineKeypair,
    cert: AgentCertificate,
}

impl Subject {
    fn certified_by(owner: &UserKeypair) -> Self {
        let agent = AgentKeypair::generate().expect("subject agent key");
        let cert = AgentCertificate::issue(owner, &agent).expect("genuine owner certificate");
        Self {
            agent,
            machine: MachineKeypair::generate().expect("subject machine key"),
            cert,
        }
    }

    fn new() -> Self {
        Self::certified_by(&UserKeypair::generate().expect("subject owner key"))
    }

    fn id(&self) -> AgentId {
        self.agent.agent_id()
    }

    fn public_key(&self) -> &[u8] {
        self.agent.public_key().as_bytes()
    }

    fn machine_id(&self) -> MachineId {
        self.machine.machine_id()
    }

    fn hex(&self) -> String {
        hex::encode(self.id().as_bytes())
    }
}

/// The attacker: its own publisher agent key, its own machine and its own
/// user key. It holds no secret of any victim; it reads victims' public keys
/// from their public announcements.
struct Attacker {
    agent: AgentKeypair,
    machine: MachineKeypair,
    user: UserKeypair,
}

impl Attacker {
    fn new() -> Self {
        Self {
            agent: AgentKeypair::generate().expect("attacker agent key"),
            machine: MachineKeypair::generate().expect("attacker machine key"),
            user: UserKeypair::generate().expect("attacker user key"),
        }
    }

    fn machine_id(&self) -> MachineId {
        self.machine.machine_id()
    }

    /// A valid certificate for the target's PUBLIC key under the attacker's
    /// user key. The target never consents.
    fn certificate_for(&self, target: &Subject) -> AgentCertificate {
        AgentCertificate::issue_for_public_key(&self.user, target.public_key(), None)
            .expect("attacker-issued certificate")
    }

    /// A valid announcement that names `target`, signed by the attacker's
    /// machine. With `with_cert` it carries the attacker-issued certificate
    /// inline (the V2 one-step plant).
    fn forged_announcement(
        &self,
        target: &Subject,
        announced_at: u64,
        with_cert: bool,
    ) -> IdentityAnnouncement {
        let cert = with_cert.then(|| self.certificate_for(target));
        signed_announcement(
            target.id(),
            target.public_key(),
            &self.machine,
            announced_at,
            cert.as_ref(),
        )
    }

    /// The same forgery as an anonymous `X0A3` beat.
    fn forged_v3_wire(&self, target: &Subject, announced_at: u64) -> Vec<u8> {
        v3_wire(
            &self.forged_announcement(target, announced_at, false),
            &self.machine,
        )
    }
}

/// A machine-signed identity announcement for `agent`. `cert` sets the inline
/// V2 user/certificate pair.
fn signed_announcement(
    agent: AgentId,
    agent_public_key: &[u8],
    machine: &MachineKeypair,
    announced_at: u64,
    cert: Option<&AgentCertificate>,
) -> IdentityAnnouncement {
    let mut announcement =
        crate::signed_identity_announcement_fixture(agent, machine, announced_at);
    announcement.agent_public_key = agent_public_key.to_vec();
    if let Some(cert) = cert {
        announcement.user_id = Some(cert.user_id().expect("certificate user"));
        announcement.agent_certificate = Some(cert.clone());
    }
    announcement.machine_signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        machine.secret_key(),
        &bincode::serialize(&announcement.to_unsigned()).expect("unsigned announcement bytes"),
    )
    .expect("machine signature")
    .as_bytes()
    .to_vec();
    announcement
        .verify()
        .expect("the announcement is valid: machine signature and certificate verify");
    announcement
}

fn v2_wire(announcement: &IdentityAnnouncement) -> Vec<u8> {
    crate::serialize_identity_announcement(announcement).expect("X0A2 wire bytes")
}

fn v3_wire(announcement: &IdentityAnnouncement, machine: &MachineKeypair) -> Vec<u8> {
    let v3 =
        announce_v3::IdentityAnnouncementV3::build_from_v2(announcement, machine.secret_key(), 0)
            .expect("X0A3 build");
    v3.verify()
        .expect("X0A3 verifies: key hashes and machine signature");
    announce_v3::serialize_v3(&v3).expect("X0A3 wire bytes")
}

fn self_revocation(subject: &AgentKeypair, revoked_at: u64) -> RevocationRecord {
    RevocationRecord::sign(
        RevokedSubject::Agent(subject.agent_id()),
        subject.public_key(),
        subject.secret_key(),
        revoked_at,
        Some("ghsa-rr9m test self-revocation".to_string()),
    )
    .expect("self-revocation")
}

fn user_revocation(
    issuer: &UserKeypair,
    subject: RevokedSubject,
    revoked_at: u64,
) -> RevocationRecord {
    RevocationRecord::sign(
        subject,
        issuer.public_key(),
        issuer.secret_key(),
        revoked_at,
        None,
    )
    .expect("user-signed revocation")
}

fn binding(agent: AgentId, machine: MachineId) -> RevokedSubject {
    RevokedSubject::AgentMachineBinding(AgentMachineBinding {
        agent,
        machine,
        move_epoch: 1,
    })
}

/// A coherent ADR-0043 `ActivationBundle` that moves `subject` from `from`
/// to `to` (pinned), retires `(subject, from)` and is signed by `owner`,
/// whose certificate for the subject rides inside.
fn activation_bundle(
    subject: AgentId,
    from: MachineId,
    to: MachineId,
    owner: &UserKeypair,
    cert: &AgentCertificate,
) -> key_move::ChainedRecord {
    let now = now_secs();
    let epoch = 1;
    let authorization = key_move::MoveAuthorization {
        agent_id: subject,
        move_epoch: epoch,
        from_machine: from,
        to_machine: to,
        placement: Placement::Pinned(to),
        issued_at: now,
    };
    let placement_record = key_move::PlacementRecord::sign(
        subject,
        owner.public_key().as_bytes(),
        Placement::Pinned(to),
        epoch,
        now,
        owner.secret_key(),
    )
    .expect("owner-signed placement record");
    let record = key_move::MoveRecord::ActivationBundle {
        authorization,
        retired_bindings: vec![AgentMachineBinding {
            agent: subject,
            machine: from,
            move_epoch: epoch,
        }],
        placement_record,
        agent_certificate: cert.clone(),
    };
    let bundle = key_move::ChainedRecord::sign(
        [0u8; 32],
        record,
        owner.public_key().as_bytes(),
        owner.secret_key(),
    )
    .expect("owner-signed bundle");
    key_move::verify_bundle_coherence_chained(&bundle)
        .expect("the bundle is coherent under the ADR-0043 mesh rule");
    bundle
}

fn assert_vector_closed(test: &str, open: &[String]) {
    assert!(
        open.is_empty(),
        "GHSA-rr9m {test} VECTOR OPEN ({} sub-case(s)); RED is expected on unfixed main and \
         GREEN after ADR 0115 phase 2:\n  - {}",
        open.len(),
        open.join("\n  - ")
    );
}

fn harness_deadline(started: tokio::time::Instant, what: &str) {
    assert!(
        started.elapsed() < DEADLINE,
        "HARNESS (not vector evidence): {what} did not happen within {DEADLINE:?}"
    );
}

/// The receiving node, with its real identity listener running.
struct Victim {
    dir: tempfile::TempDir,
    agent: Arc<Agent>,
}

impl Victim {
    async fn start(label: &str) -> Self {
        let dir = tempfile::tempdir().expect("temporary identity dir");
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_identity_dir(dir.path())
            .with_peer_cache_disabled()
            .with_network_config(crate::network::NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback bind address")),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                network_id: Some(format!("ghsa-rr9m-{label}-{nonce}")),
                ..crate::network::NetworkConfig::default()
            })
            .build()
            .await
            .expect("inert loopback victim");
        let agent = Arc::new(agent);
        agent
            .start_identity_listener()
            .await
            .expect("real identity listener");
        let victim = Self { dir, agent };
        // Prove that the whole frame → PubSub → listener path delivers.
        victim.identity_barrier().await;
        victim
    }

    /// Feed one signed PlumTree EAGER frame into the victim's real
    /// `PubSubManager`. `author` signs the inner V2 envelope; it is the
    /// pubsub `sender` that the listener sees.
    async fn feed(&self, topic: &str, author: &AgentKeypair, payload: Vec<u8>) {
        let inner = signed_inner_v2(
            &SigningContext::from_keypair(author),
            topic,
            &bytes::Bytes::from(payload),
        );
        let msg_id = *blake3::hash(&inner).as_bytes();
        let frame = outer_v2_frame(
            saorsa_gossip_types::TopicId::from_entity(topic),
            inner,
            msg_id,
        );
        self.agent
            .handle_gossip_incoming_for_test(saorsa_gossip_types::PeerId::new([0x5a; 32]), frame)
            .await;
    }

    async fn announce(&self, author: &AgentKeypair, wire: Vec<u8>) {
        self.feed(crate::IDENTITY_ANNOUNCE_TOPIC, author, wire)
            .await;
    }

    /// A genuine `X0A2` announcement: the subject signs the pubsub envelope
    /// and its real machine signs the body.
    async fn announce_genuine(&self, subject: &Subject, announced_at: u64) {
        let announcement = signed_announcement(
            subject.id(),
            subject.public_key(),
            &subject.machine,
            announced_at,
            Some(&subject.cert),
        );
        self.announce(&subject.agent, v2_wire(&announcement)).await;
    }

    /// FIFO barrier on the identity topic: a fresh genuine announcement
    /// reaches the cache only after every earlier frame on the topic was
    /// decided (one forwarding task and one listener loop per subscription).
    async fn identity_barrier(&self) {
        let sentinel = Subject::new();
        let announcement = signed_announcement(
            sentinel.id(),
            sentinel.public_key(),
            &sentinel.machine,
            now_secs(),
            None,
        );
        self.announce(&sentinel.agent, v2_wire(&announcement)).await;
        let started = tokio::time::Instant::now();
        while self.agent.cached_agent(&sentinel.id()).await.is_none() {
            harness_deadline(
                started,
                "the identity sentinel reaching the discovery cache",
            );
            tokio::time::sleep(POLL).await;
        }
    }

    /// CONTROL: the genuine announcement set the machine, the certificate
    /// and the authenticated binding.
    async fn expect_genuine_entry(&self, subject: &Subject, test: &str) {
        let entry = self
            .agent
            .cached_agent(&subject.id())
            .await
            .unwrap_or_else(|| {
                panic!("{test} CONTROL FAILED (not the vector): genuine announce not cached")
            });
        assert_eq!(
            entry.machine_id,
            subject.machine_id(),
            "{test} CONTROL FAILED (not the vector): the genuine announce must set the machine"
        );
        assert_eq!(
            entry.agent_certificate.as_ref(),
            Some(&subject.cert),
            "{test} CONTROL FAILED (not the vector): the genuine announce must set the certificate"
        );
        assert_eq!(
            self.agent
                .authenticated_bound_machine(&subject.id())
                .await
                .map(|bound| bound.machine_id),
            Some(subject.machine_id()),
            "{test} CONTROL FAILED (not the vector): the agent-authenticated announce must \
             record the authenticated binding (src/lib.rs:12141)"
        );
    }

    async fn revoked(&self, agent: &AgentId) -> bool {
        self.agent
            .revocation_set()
            .read()
            .await
            .is_agent_revoked(agent)
    }

    async fn binding_revoked(&self, agent: &AgentId, machine: &MachineId) -> bool {
        self.agent
            .revocation_set()
            .read()
            .await
            .is_binding_revoked(agent, machine)
    }

    /// Feed one revocation batch on `topic`, with a fresh self-revocation
    /// sentinel appended, and wait until the sentinel is applied. The
    /// listener decides a whole batch under one write lock, so every record
    /// in it is decided by then.
    async fn feed_revocations(&self, topic: &str, mut records: Vec<RevocationRecord>) {
        let sentinel = AgentKeypair::generate().expect("sentinel key");
        records.push(self_revocation(&sentinel, now_secs()));
        let courier = AgentKeypair::generate().expect("courier key");
        self.feed(
            topic,
            &courier,
            bincode::serialize(&records).expect("revocation batch"),
        )
        .await;
        let started = tokio::time::Instant::now();
        while !self.revoked(&sentinel.agent_id()).await {
            harness_deadline(started, "the revocation sentinel being applied");
            tokio::time::sleep(POLL).await;
        }
    }

    async fn feed_bundle(&self, bundle: &key_move::ChainedRecord) {
        let courier = AgentKeypair::generate().expect("courier key");
        self.feed(
            crate::MOVE_ACTIVATION_TOPIC,
            &courier,
            bincode::serialize(bundle).expect("bundle wire bytes"),
        )
        .await;
    }

    async fn placement(&self, agent: &AgentId) -> Option<Placement> {
        self.agent
            .move_state
            .read()
            .await
            .placement(agent)
            .map(|record| record.placement)
    }

    /// The raw-QUIC receiver's verdict for a frame that claims `agent` and
    /// arrives from the transport-authenticated `machine`: the same inputs
    /// and decision function as the receiver (src/lib.rs:15909-15918).
    async fn raw_frame_verified(&self, agent: AgentId, machine: MachineId) -> bool {
        let registry = crate::dm_inbox::authenticated_machine_binding_evidence(
            &self.agent.authenticated_machine_bindings,
            &agent,
        )
        .await;
        // The receiver's ADR 0115 §2 shape: the announced store is read
        // before the discovery cache, and the routing entry stands for the
        // sender only when an authority store confirms its machine.
        let announced = self
            .agent
            .announced_machine_bindings
            .read()
            .await
            .peek(&agent);
        let cache = self.agent.identity_discovery_cache.read().await;
        let entry = cache.get(&agent).filter(|entry| {
            crate::identity_authority::confirms(entry.machine_id, announced, registry, || false)
        });
        let (verified, _live, _expiry) = crate::raw_delivery_from_ingress(
            entry,
            registry,
            None,
            agent,
            machine,
            crate::dm_capability::now_unix_ms(),
            crate::network::DirectIngress::Transport,
        );
        verified
    }

    /// The machine the general raw-QUIC send path (`POST /direct/send`, file
    /// chunks) resolves for `agent`, over a scripted connection table.
    async fn raw_target(
        &self,
        agent: AgentId,
        transport: &crate::RawQuicTransport<'_>,
    ) -> Option<MachineId> {
        self.agent
            .resolve_raw_quic_target(
                &agent,
                transport,
                "ghsa-rr9m",
                0,
                std::time::Instant::now(),
                crate::ColdResolution::Off,
            )
            .await
            .ok()
            .map(|target| target.machine_id)
    }

    /// The machine the pinned single-exchange path (join results, Welcome
    /// chunks) selects for `agent`.
    async fn pinned_machine(&self, agent: AgentId) -> Option<MachineId> {
        self.agent
            .pinned_binding_now(&agent)
            .await
            .map(|binding| binding.machine)
    }
}

/// T1 (audit finding 1): a forged announcement plants an attacker-issued
/// certificate for X. A revocation of X signed by the attacker's user key is
/// then accepted, through both carriers.
///
/// Fails on main: the listener caches the forged certificate
/// (src/lib.rs:2871-2881), `collect_subject_certs` (src/lib.rs:2645) hands
/// it to `verify_authority`, and `issuer_is_certifier`
/// (src/revocation.rs:341) holds for the attacker's user key. The v1
/// carrier (src/lib.rs:11467) then evicts X and marks it Blocked; the v2
/// carrier (src/lib.rs:11647) stores a permanent binding tombstone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t1_attacker_certificate_never_authorizes_a_revocation_of_the_victim() {
    let victim = Victim::start("t1").await;
    let attacker = Attacker::new();
    let now = now_secs();

    let control_owner = UserKeypair::generate().expect("control owner key");
    let control_agent = Subject::certified_by(&control_owner);
    let control_binding = Subject::certified_by(&control_owner);
    let warm = Subject::new();
    let warm_binding = Subject::new();
    for subject in [&control_agent, &control_binding, &warm, &warm_binding] {
        victim.announce_genuine(subject, now).await;
    }
    victim.identity_barrier().await;
    for subject in [&control_agent, &control_binding, &warm, &warm_binding] {
        victim.expect_genuine_entry(subject, "T1").await;
    }

    // CONTROL: the genuine owner revokes its agent (v1) and a binding (v2).
    victim
        .feed_revocations(
            crate::REVOCATION_TOPIC,
            vec![user_revocation(
                &control_owner,
                RevokedSubject::Agent(control_agent.id()),
                now,
            )],
        )
        .await;
    victim
        .feed_revocations(
            crate::REVOCATION_V2_TOPIC,
            vec![user_revocation(
                &control_owner,
                binding(control_binding.id(), control_binding.machine_id()),
                now,
            )],
        )
        .await;
    assert!(
        victim.revoked(&control_agent.id()).await,
        "T1 CONTROL FAILED (not the vector): the genuine owner's revocation must be accepted"
    );
    assert!(
        victim
            .binding_revoked(&control_binding.id(), &control_binding.machine_id())
            .await,
        "T1 CONTROL FAILED (not the vector): the genuine owner's binding tombstone must be accepted"
    );

    // VECTOR: forged X0A2 beats (attacker envelope, attacker machine,
    // attacker-issued certificate inline), then attacker-signed revocations.
    let cold = Subject::new();
    let later = now + ATTACKER_LEAD_SECS;
    for target in [&warm, &warm_binding, &cold] {
        victim
            .announce(
                &attacker.agent,
                v2_wire(&attacker.forged_announcement(target, later, true)),
            )
            .await;
    }
    victim.identity_barrier().await;
    victim
        .feed_revocations(
            crate::REVOCATION_TOPIC,
            vec![
                user_revocation(&attacker.user, RevokedSubject::Agent(warm.id()), now),
                user_revocation(&attacker.user, RevokedSubject::Agent(cold.id()), now),
            ],
        )
        .await;
    victim
        .feed_revocations(
            crate::REVOCATION_V2_TOPIC,
            vec![user_revocation(
                &attacker.user,
                binding(warm_binding.id(), warm_binding.machine_id()),
                now,
            )],
        )
        .await;

    let mut open = Vec::new();
    if victim.revoked(&warm.id()).await {
        open.push(
            "warm X (agent-authenticated binding and genuine certificate first): the attacker's \
             Agent(X) revocation was accepted on x0x.revocation.v1"
                .to_string(),
        );
    }
    if victim.revoked(&cold.id()).await {
        open.push(
            "cold X (never announced by X itself): the attacker's Agent(X) revocation was accepted"
                .to_string(),
        );
    }
    if victim
        .binding_revoked(&warm_binding.id(), &warm_binding.machine_id())
        .await
    {
        open.push(
            "warm X: the attacker's permanent binding tombstone for (X, X's real machine) was \
             accepted on x0x.revocation.v2"
                .to_string(),
        );
    }
    assert_vector_closed("T1", &open);
}

/// T2 (audit finding 2): a forged announcement makes raw frames from the
/// attacker's machine count as verified traffic from X.
///
/// Fails on main: the forged beat replaces the cached machine
/// (src/lib.rs:2824-2826). `raw_delivery_binding` lets discovery win
/// unless the authenticated binding is strictly newer (src/lib.rs:4597),
/// then treats `entry.machine_id == transport machine` as verification
/// (src/lib.rs:4610). `Agent::is_agent_machine_verified` reads the same
/// cache field (src/lib.rs:13397).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t2_forged_announce_never_verifies_raw_frames_from_the_attacker_machine() {
    let victim = Victim::start("t2").await;
    let attacker = Attacker::new();
    let now = now_secs();
    let warm = Subject::new();
    victim.announce_genuine(&warm, now).await;
    victim.identity_barrier().await;
    victim.expect_genuine_entry(&warm, "T2").await;

    // CONTROL: frames from X's own machine verify; others do not.
    assert!(
        victim
            .raw_frame_verified(warm.id(), warm.machine_id())
            .await,
        "T2 CONTROL FAILED (not the vector): frames from X's authenticated machine must verify"
    );
    assert!(
        victim
            .agent
            .is_agent_machine_verified(&warm.id(), &warm.machine_id())
            .await,
        "T2 CONTROL FAILED (not the vector): is_agent_machine_verified(X, X's machine)"
    );
    assert!(
        !victim
            .raw_frame_verified(warm.id(), attacker.machine_id())
            .await,
        "T2 CONTROL FAILED (not the vector): before any forgery a foreign machine must not verify"
    );

    // VECTOR: X0A2 for warm X, X0A3 for cold X, both from the attacker.
    let cold = Subject::new();
    let later = now + ATTACKER_LEAD_SECS;
    victim
        .announce(
            &attacker.agent,
            v2_wire(&attacker.forged_announcement(&warm, later, false)),
        )
        .await;
    victim
        .announce(&attacker.agent, attacker.forged_v3_wire(&cold, later))
        .await;
    victim.identity_barrier().await;

    let attacker_machine = attacker.machine_id();
    let mut open = Vec::new();
    if victim.raw_frame_verified(warm.id(), attacker_machine).await {
        open.push(
            "warm X (X0A2 forgery): raw frames from the attacker's machine verify as X".to_string(),
        );
    }
    if victim
        .agent
        .is_agent_machine_verified(&warm.id(), &attacker_machine)
        .await
    {
        open.push(
            "warm X: Agent::is_agent_machine_verified(X, attacker machine) is true".to_string(),
        );
    }
    if !victim
        .raw_frame_verified(warm.id(), warm.machine_id())
        .await
    {
        open.push(
            "warm X: genuine frames from X's own authenticated machine no longer verify"
                .to_string(),
        );
    }
    if victim.raw_frame_verified(cold.id(), attacker_machine).await {
        open.push(
            "cold X (X0A3 forgery, X never announced): raw frames from the attacker's machine \
             verify as X"
                .to_string(),
        );
    }
    if victim
        .agent
        .is_agent_machine_verified(&cold.id(), &attacker_machine)
        .await
    {
        open.push(
            "cold X: Agent::is_agent_machine_verified(X, attacker machine) is true".to_string(),
        );
    }
    assert_vector_closed("T2", &open);
}

/// T3 (audit finding 3): raw-first resolution of X picks the attacker's
/// machine, so DMs and file chunks addressed to X go to the attacker.
///
/// Fails on main: the general resolver takes the cached machine when it is
/// connected (src/lib.rs:9236-9276). The pinned selector prefers the newer
/// announced-binding record (src/lib.rs:290-317), which every verified
/// announcement writes (src/lib.rs:3373-3383). The listener also registers
/// the attacker machine in the DM registry (src/lib.rs:12189-12191).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t3_raw_first_resolution_never_selects_the_attacker_machine() {
    let victim = Victim::start("t3").await;
    let attacker = Attacker::new();
    let now = now_secs();
    let x = Subject::new();
    victim.announce_genuine(&x, now).await;
    victim.identity_barrier().await;
    victim.expect_genuine_entry(&x, "T3").await;
    let attacker_machine = attacker.machine_id();
    // Both machines are connected, so only authority decides.
    let transport = crate::RawQuicTransport::Scripted(Arc::new(
        crate::PinnedTransportScript::connected_only(&[x.machine_id(), attacker_machine], false),
    ));

    // CONTROL: before the forgery both paths resolve X's own machine.
    assert_eq!(
        victim.raw_target(x.id(), &transport).await,
        Some(x.machine_id()),
        "T3 CONTROL FAILED (not the vector): the raw-first resolver must pick X's machine"
    );
    assert_eq!(
        victim.pinned_machine(x.id()).await,
        Some(x.machine_id()),
        "T3 CONTROL FAILED (not the vector): the pinned selector must pick X's machine"
    );

    // VECTOR: an X0A3 beat for X from the attacker's machine.
    victim
        .announce(
            &attacker.agent,
            attacker.forged_v3_wire(&x, now + ATTACKER_LEAD_SECS),
        )
        .await;
    victim.identity_barrier().await;

    let mut open = Vec::new();
    let raw = victim.raw_target(x.id(), &transport).await;
    if raw != Some(x.machine_id()) {
        open.push(format!(
            "raw-first send resolves X to {raw:?}, not X's machine (attacker machine: {})",
            raw == Some(attacker_machine)
        ));
    }
    let pinned = victim.pinned_machine(x.id()).await;
    if pinned != Some(x.machine_id()) {
        open.push(format!(
            "pinned send resolves X to {pinned:?}, not X's machine (attacker machine: {})",
            pinned == Some(attacker_machine)
        ));
    }
    if victim.agent.direct_messaging.get_machine_id(&x.id()).await == Some(attacker_machine) {
        open.push("the DM registry maps X to the attacker's machine".to_string());
    }
    assert_vector_closed("T3", &open);
}

/// T4 (audit finding 1, lifetime): a revocation whose `revoked_at` is far in
/// the future is accepted, and the 90-day sweep never removes it.
///
/// Fails on main: `verify_authority` (src/revocation.rs:284) has no bound on
/// `revoked_at`, and the sweep keeps every record with
/// `revoked_at >= now - ttl` (src/revocation.rs:645).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t4_far_future_revoked_at_is_rejected_and_cannot_outlive_the_ttl() {
    let victim = Victim::start("t4").await;
    let now = now_secs();

    // CONTROL: a current record is accepted, and the sweep expires it.
    let current = AgentKeypair::generate().expect("current subject key");
    victim
        .feed_revocations(
            crate::REVOCATION_TOPIC,
            vec![self_revocation(&current, now)],
        )
        .await;
    assert!(
        victim.revoked(&current.agent_id()).await,
        "T4 CONTROL FAILED (not the vector): a current self-revocation must be accepted"
    );
    let mut swept = victim.agent.revocation_set().read().await.clone();
    swept.expire_records_older_than(
        REVOCATION_RECORD_TTL_SECS,
        now + REVOCATION_RECORD_TTL_SECS + DAY_SECS,
    );
    assert!(
        !swept.is_agent_revoked(&current.agent_id()),
        "T4 CONTROL FAILED (not the vector): the sweep must expire a current record after its TTL"
    );

    // VECTOR
    let day_ahead = AgentKeypair::generate().expect("day-ahead subject key");
    let forever = AgentKeypair::generate().expect("forever subject key");
    victim
        .feed_revocations(
            crate::REVOCATION_TOPIC,
            vec![
                self_revocation(&day_ahead, now + DAY_SECS),
                self_revocation(&forever, u64::MAX),
            ],
        )
        .await;

    let mut open = Vec::new();
    if victim.revoked(&day_ahead.agent_id()).await {
        open.push("revoked_at = now + 1 day was accepted".to_string());
    }
    if victim.revoked(&forever.agent_id()).await {
        let mut swept = victim.agent.revocation_set().read().await.clone();
        swept.expire_records_older_than(
            REVOCATION_RECORD_TTL_SECS,
            now.saturating_add(100 * 365 * DAY_SECS),
        );
        open.push(format!(
            "revoked_at = u64::MAX was accepted; a sweep 100 years later still enforces it: {}",
            swept.is_agent_revoked(&forever.agent_id())
        ));
    }
    assert_vector_closed("T4", &open);
}

/// T5 (audit finding 7): a forged announcement changes X's certificate or
/// digest, so an OwnerCertified verdict for a correctly seated X stops being
/// `Clean`.
///
/// Fails on main: the forged beat replaces the cached certificate or drops it
/// for a new digest (src/lib.rs:2871-2900). `owner_cert_evidence_for`
/// (src/server/routes/named_groups.rs:22974-23021) feeds both into the
/// verdict. A resolved wrong-owner certificate is a definitive failure, and
/// a changed digest stales the embedded certificate
/// (src/groups/mod.rs:1640-1694).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t5_forged_announce_never_changes_an_owner_certified_verdict() {
    let victim = Victim::start("t5").await;
    let daemon_dir = victim.dir.path().join("daemon");
    tokio::fs::create_dir_all(&daemon_dir)
        .await
        .expect("daemon data dir");
    let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
        &daemon_dir,
        Arc::clone(&victim.agent),
    )
    .await
    .expect("daemon test state");
    let attacker = Attacker::new();
    let owner = UserKeypair::generate().expect("group owner key");
    let now = now_secs();
    let by_cert = Subject::certified_by(&owner);
    let by_digest = Subject::certified_by(&owner);

    let mut policy = crate::groups::GroupPolicyPreset::PublicRequestSecure.to_policy();
    policy.admission = crate::groups::GroupAdmission::OwnerCertified(owner.user_id());
    let mut group = crate::groups::GroupInfo::with_policy(
        "ghsa-rr9m-t5".to_string(),
        String::new(),
        victim.agent.agent_id(),
        "ab".repeat(16),
        policy,
    );
    for member in [&by_cert, &by_digest] {
        group.add_member(member.hex(), crate::groups::GroupRole::Member, None, None);
        group
            .set_member_certificate(&member.hex(), member.cert.clone())
            .expect("committed member certificate");
        victim.announce_genuine(member, now).await;
    }
    victim.identity_barrier().await;
    for member in [&by_cert, &by_digest] {
        victim.expect_genuine_entry(member, "T5").await;
    }
    let members = [by_cert.hex(), by_digest.hex()];
    let wanted: Vec<&str> = members.iter().map(String::as_str).collect();

    // CONTROL: both seated members are Clean.
    let evidence =
        crate::server::routes::named_groups::owner_cert_evidence_for(&state, &wanted).await;
    let verdict = group.owner_cert_verdict(&evidence);
    for member in &members {
        assert_eq!(
            verdict.per_member.get(member),
            Some(&MemberCertStatus::Clean),
            "T5 CONTROL FAILED (not the vector): a seated member with its genuine announce \
             must be Clean"
        );
    }

    // VECTOR: an X0A2 beat with an attacker-issued certificate, and an
    // anonymous X0A3 beat, both from the attacker's machine.
    let later = now + ATTACKER_LEAD_SECS;
    victim
        .announce(
            &attacker.agent,
            v2_wire(&attacker.forged_announcement(&by_cert, later, true)),
        )
        .await;
    victim
        .announce(&attacker.agent, attacker.forged_v3_wire(&by_digest, later))
        .await;
    victim.identity_barrier().await;

    let evidence =
        crate::server::routes::named_groups::owner_cert_evidence_for(&state, &wanted).await;
    let verdict = group.owner_cert_verdict(&evidence);
    let mut open = Vec::new();
    for (member, how) in [
        (
            &by_cert,
            "forged X0A2 beat with an attacker-issued certificate",
        ),
        (
            &by_digest,
            "forged anonymous X0A3 beat from the attacker's machine",
        ),
    ] {
        let status = verdict.per_member.get(&member.hex());
        if status != Some(&MemberCertStatus::Clean) {
            open.push(format!(
                "{how}: the member verdict is {status:?}, not Clean; evidence certificate \
                 owner is {:?} (genuine owner: {:?}), evidence digest is {:?}",
                evidence
                    .cert_for(&member.hex())
                    .and_then(|cert| cert.user_id().ok()),
                owner.user_id(),
                evidence.digest_for(&member.hex()).map(hex::encode)
            ));
        }
    }
    assert_vector_closed("T5", &open);
}

/// T6 (new; not in the audit): an ADR-0043 `ActivationBundle` signed by any
/// user who certified X's PUBLIC key passes the mesh rule. Its tombstone
/// retires X's real binding for ever and its placement pins X to the
/// attacker's machine. No forged announcement is needed.
///
/// Fails on main: the mesh coherence check only requires the bundle's
/// embedded certificate to name X and to be issued by the bundle signer
/// (src/key_move.rs:1022-1037). Its tombstones then union in
/// unconditionally (src/key_move.rs:1422), and its placement is cached
/// under the same signer (src/key_move.rs:1427).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t6_attacker_bundle_never_retires_the_victim_binding_or_pins_it() {
    let victim = Victim::start("t6").await;
    let attacker = Attacker::new();
    let now = now_secs();
    let control_owner = UserKeypair::generate().expect("control owner key");
    let control = Subject::certified_by(&control_owner);
    let x = Subject::new();
    victim.announce_genuine(&control, now).await;
    victim.announce_genuine(&x, now).await;
    victim.identity_barrier().await;
    victim.expect_genuine_entry(&control, "T6").await;
    victim.expect_genuine_entry(&x, "T6").await;

    // The VECTOR bundle goes first. The CONTROL bundle follows on the same
    // topic, so its effect is also the FIFO barrier for the vector.
    let attack = activation_bundle(
        x.id(),
        x.machine_id(),
        attacker.machine_id(),
        &attacker.user,
        &attacker.certificate_for(&x),
    );
    let control_target = MachineKeypair::generate()
        .expect("control target machine")
        .machine_id();
    let genuine = activation_bundle(
        control.id(),
        control.machine_id(),
        control_target,
        &control_owner,
        &control.cert,
    );
    victim.feed_bundle(&attack).await;
    victim.feed_bundle(&genuine).await;

    // CONTROL: the genuine owner's bundle retires and re-pins its agent.
    let started = tokio::time::Instant::now();
    while !victim
        .binding_revoked(&control.id(), &control.machine_id())
        .await
    {
        harness_deadline(
            started,
            "T6 CONTROL (not the vector): the genuine owner's bundle being applied",
        );
        tokio::time::sleep(POLL).await;
    }
    assert_eq!(
        victim.placement(&control.id()).await,
        Some(Placement::Pinned(control_target)),
        "T6 CONTROL FAILED (not the vector): the genuine owner's bundle must set its placement"
    );

    // VECTOR
    let mut open = Vec::new();
    if victim.binding_revoked(&x.id(), &x.machine_id()).await {
        open.push(
            "the attacker-signed bundle retired (X, X's real machine) permanently".to_string(),
        );
    }
    if victim.placement(&x.id()).await == Some(Placement::Pinned(attacker.machine_id())) {
        open.push(
            "the attacker-signed bundle pinned X to the attacker's machine, so X's own \
             announcements are now dropped at ingest (key_move::enforce_pairing)"
                .to_string(),
        );
    }
    assert_vector_closed("T6", &open);
}

// ── ADR 0115 Validation: phase-2 tests (review P2-1) ──────────────────────
//
// GREEN after phase 2. Each drives the same real listener, pubsub and
// stores as T1–T6.

/// The process-wide `identity_announce_unauthenticated` counter. Tests run
/// in parallel and only ever add to it, so callers assert an increase.
fn unauthenticated_announces() -> u64 {
    crate::identity_authority::counters_json()["identity_announce_unauthenticated"]
        .as_u64()
        .unwrap_or_default()
}

impl Victim {
    /// A legacy republisher (`courier`) re-publishes `subject`'s body,
    /// signed by `machine`, under its own pubsub envelope: the storm-control
    /// shape of pre-ADR 0115 builds (ADR 0115 §7).
    async fn republish(
        &self,
        courier: &AgentKeypair,
        subject: &Subject,
        machine: &MachineKeypair,
        announced_at: u64,
        cert: Option<&AgentCertificate>,
    ) {
        let body = signed_announcement(
            subject.id(),
            subject.public_key(),
            machine,
            announced_at,
            cert,
        );
        self.announce(courier, v2_wire(&body)).await;
    }

    async fn cached_machine(&self, agent: &AgentId) -> Option<MachineId> {
        self.agent
            .cached_agent(agent)
            .await
            .map(|entry| entry.machine_id)
    }

    async fn cached_cert(&self, agent: &AgentId) -> Option<AgentCertificate> {
        self.agent
            .cached_agent(agent)
            .await
            .and_then(|entry| entry.agent_certificate)
    }

    async fn announced_binding(
        &self,
        agent: &AgentId,
    ) -> Option<crate::dm_inbox::AuthenticatedMachineBinding> {
        self.agent
            .announced_machine_bindings
            .read()
            .await
            .peek(agent)
    }
}

/// ADR 0115 §1 freshness: inside classes A and B an equal `announced_at`
/// replaces, as before; a class C announcement never counts as newer, so an
/// equal-timestamp forgery changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr0115_equal_timestamps_replace_only_within_classes_a_and_b() {
    let victim = Victim::start("eq-ts").await;
    let attacker = Attacker::new();
    let owner = UserKeypair::generate().expect("owner key");
    let x = Subject::certified_by(&owner);
    let t = now_secs() - 100;
    victim.announce_genuine(&x, t).await;
    victim.identity_barrier().await;
    victim.expect_genuine_entry(&x, "equal-timestamps").await;

    // Class C at the same timestamp: the attacker's machine, its own cert.
    let before = unauthenticated_announces();
    victim
        .announce(
            &attacker.agent,
            v2_wire(&attacker.forged_announcement(&x, t, true)),
        )
        .await;
    victim.identity_barrier().await;
    assert_eq!(victim.cached_machine(&x.id()).await, Some(x.machine_id()));
    assert_eq!(victim.cached_cert(&x.id()).await, Some(x.cert.clone()));
    assert!(
        unauthenticated_announces() > before,
        "the equal-timestamp forgery is counted as class C"
    );

    // Class A at the same timestamp replaces (a renewed certificate).
    let renewal_a =
        AgentCertificate::issue_with_expiry(&owner, &x.agent, Some(now_secs() + 86_400))
            .expect("class A renewal");
    let body = signed_announcement(x.id(), x.public_key(), &x.machine, t, Some(&renewal_a));
    victim.announce(&x.agent, v2_wire(&body)).await;
    victim.identity_barrier().await;
    assert_eq!(
        victim.cached_cert(&x.id()).await,
        Some(renewal_a),
        "an equal-timestamp class A beat replaces"
    );

    // Class B at the same timestamp replaces too: a republished body from
    // X's authenticated machine.
    let courier = AgentKeypair::generate().expect("legacy republisher");
    let renewal_b =
        AgentCertificate::issue_with_expiry(&owner, &x.agent, Some(now_secs() + 2 * 86_400))
            .expect("class B renewal");
    victim
        .republish(&courier, &x, &x.machine, t, Some(&renewal_b))
        .await;
    victim.identity_barrier().await;
    assert_eq!(
        victim.cached_cert(&x.id()).await,
        Some(renewal_b),
        "an equal-timestamp class B body replaces"
    );
    assert_eq!(victim.cached_machine(&x.id()).await, Some(x.machine_id()));
}

/// ADR 0115 §1 and §7: a legacy republisher's copy of X's body, signed by
/// X's authenticated machine, is class B. It refreshes the certificate and
/// never moves X: a copy signed by any other machine, including X's machine
/// before X moved, is class C.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr0115_class_b_republished_body_refreshes_but_never_moves_the_pairing() {
    let victim = Victim::start("class-b").await;
    let attacker = Attacker::new();
    let owner = UserKeypair::generate().expect("owner key");
    let x = Subject::certified_by(&owner);
    let courier = AgentKeypair::generate().expect("legacy republisher");
    let t = now_secs() - 100;
    victim.announce_genuine(&x, t).await;
    victim.identity_barrier().await;
    victim.expect_genuine_entry(&x, "class-b").await;

    // Refresh: a newer body from X's own machine, under the courier's
    // envelope, carrying a renewed certificate.
    let renewal = AgentCertificate::issue_with_expiry(&owner, &x.agent, Some(now_secs() + 86_400))
        .expect("renewal");
    victim
        .republish(&courier, &x, &x.machine, t + 5, Some(&renewal))
        .await;
    victim.identity_barrier().await;
    assert_eq!(
        victim.cached_cert(&x.id()).await,
        Some(renewal.clone()),
        "a class B body refreshes the certificate of an authenticated pairing"
    );
    assert_eq!(victim.cached_machine(&x.id()).await, Some(x.machine_id()));

    // The same courier relaying a body signed by another machine: class C.
    let before = unauthenticated_announces();
    victim
        .republish(&courier, &x, &attacker.machine, t + 10, None)
        .await;
    victim.identity_barrier().await;
    assert_eq!(
        victim.cached_machine(&x.id()).await,
        Some(x.machine_id()),
        "a republished body from a machine that is not X's pairing never moves X"
    );
    assert!(unauthenticated_announces() > before);

    // X moves (its own class A beat from M2). A later copy of a body from
    // the OLD machine is class C and never moves X back.
    let m2 = MachineKeypair::generate().expect("X's new machine");
    let moved = signed_announcement(x.id(), x.public_key(), &m2, t + 15, Some(&renewal));
    victim.announce(&x.agent, v2_wire(&moved)).await;
    victim.identity_barrier().await;
    assert_eq!(victim.cached_machine(&x.id()).await, Some(m2.machine_id()));
    victim
        .republish(&courier, &x, &x.machine, t + 20, Some(&renewal))
        .await;
    victim.identity_barrier().await;
    assert_eq!(
        victim.cached_machine(&x.id()).await,
        Some(m2.machine_id()),
        "a republished body from X's previous machine is class C after the move"
    );
    assert_eq!(
        victim
            .agent
            .authenticated_bound_machine(&x.id())
            .await
            .map(|bound| bound.machine_id),
        Some(m2.machine_id())
    );
}

/// ADR 0115 §1: the `find_agent` shard lookup (stage 2) applies the same
/// classes. A forged shard beat is ignored; X's own beat is accepted and
/// records the announced binding with its certificate digest (§3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr0115_find_agent_shard_path_accepts_only_class_a_or_b() {
    let victim = Victim::start("shard").await;
    let attacker = Attacker::new();
    let x = Subject::new();
    let topic = crate::shard_topic_for_agent(&x.id());
    let pubsub = Arc::clone(
        victim
            .agent
            .gossip_runtime
            .as_ref()
            .expect("HARNESS (not vector evidence): the victim has a gossip runtime")
            .pubsub(),
    );
    assert!(
        !pubsub.is_topic_subscribed(&topic).await,
        "HARNESS (not vector evidence): X's shard topic is already subscribed"
    );
    assert!(victim.agent.cached_agent(&x.id()).await.is_none());

    let lookup = {
        let agent = Arc::clone(&victim.agent);
        let id = x.id();
        tokio::spawn(async move { agent.find_agent(id).await })
    };
    let started = tokio::time::Instant::now();
    while !pubsub.is_topic_subscribed(&topic).await {
        harness_deadline(started, "find_agent subscribing to X's shard topic");
        tokio::time::sleep(POLL).await;
    }

    // The forgery goes first; X's own beat follows on the same topic.
    let now = now_secs();
    victim
        .feed(
            &topic,
            &attacker.agent,
            v2_wire(&attacker.forged_announcement(&x, now + ATTACKER_LEAD_SECS, true)),
        )
        .await;
    let genuine = signed_announcement(x.id(), x.public_key(), &x.machine, now, Some(&x.cert));
    victim.feed(&topic, &x.agent, v2_wire(&genuine)).await;

    let found = tokio::time::timeout(DEADLINE, lookup)
        .await
        .expect("HARNESS (not vector evidence): find_agent finished")
        .expect("find_agent task")
        .expect("find_agent result");
    assert!(found.is_some(), "the shard lookup found X");
    assert_eq!(
        victim.cached_machine(&x.id()).await,
        Some(x.machine_id()),
        "the shard lookup must cache X's own machine, never the forger's"
    );
    assert_eq!(victim.cached_cert(&x.id()).await, Some(x.cert.clone()));
    let binding = victim
        .announced_binding(&x.id())
        .await
        .expect("a class A shard beat records the announced binding");
    assert_eq!(binding.machine_id, x.machine_id());
    assert_eq!(
        binding.cert_digest,
        Some(crate::identity_authority::certificate_digest(&x.cert)),
        "the announced binding carries the committed certificate digest (§3 provenance)"
    );
}

/// ADR 0115 §1: a certificate that lands by digest takes the class of the
/// announcement that committed to the digest. Blobs for digests that only
/// class C beats committed to land nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr0115_blob_hydration_follows_the_committing_announcement_class() {
    let victim = Victim::start("blob").await;
    let attacker = Attacker::new();
    let x = Subject::new();
    let cold = Subject::new();
    let now = now_secs();

    // X's own X0A3 beat commits to its certificate digest; the blob is not
    // cached yet, so the entry has the digest and no certificate.
    let genuine = signed_announcement(x.id(), x.public_key(), &x.machine, now, Some(&x.cert));
    victim
        .announce(&x.agent, v3_wire(&genuine, &x.machine))
        .await;
    // Class C X0A3 beats commit to attacker-issued certificates, for warm X
    // (newer) and for a cold agent.
    let forged_warm = attacker.forged_announcement(&x, now + ATTACKER_LEAD_SECS, true);
    victim
        .announce(&attacker.agent, v3_wire(&forged_warm, &attacker.machine))
        .await;
    let forged_cold = attacker.forged_announcement(&cold, now, true);
    victim
        .announce(&attacker.agent, v3_wire(&forged_cold, &attacker.machine))
        .await;
    victim.identity_barrier().await;
    let entry = victim
        .agent
        .cached_agent(&x.id())
        .await
        .expect("CONTROL FAILED (not the vector): X's class A X0A3 beat is cached");
    let x_digest = crate::identity_authority::certificate_digest(&x.cert);
    assert_eq!(entry.cert_digest, Some(x_digest));
    assert_eq!(entry.machine_id, x.machine_id());

    // The blobs land: the attacker's first, then X's.
    let blob = |cert: &AgentCertificate| crate::announce_blob::CachedBlob {
        digest: crate::identity_authority::certificate_digest(cert),
        payload_version: 0,
        user_id: cert.user_id().ok(),
        agent_certificate: Some(cert.clone()),
        fetched_at_unix: now,
    };
    for forged in [&forged_warm, &forged_cold] {
        let cert = forged
            .agent_certificate
            .as_ref()
            .expect("forged announcements carry the attacker certificate");
        victim
            .agent
            .announce_blob_cache
            .insert_verified(blob(cert))
            .await;
    }
    victim
        .agent
        .announce_blob_cache
        .insert_verified(blob(&x.cert))
        .await;
    let started = tokio::time::Instant::now();
    while victim.cached_cert(&x.id()).await.is_none() {
        harness_deadline(started, "X's certificate landing by digest");
        tokio::time::sleep(POLL).await;
    }
    // Every watcher polls once a second; give the class C ones a full
    // period after X's landed.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    assert_eq!(
        victim.cached_cert(&x.id()).await,
        Some(x.cert.clone()),
        "X's certificate is the one its own beat committed to"
    );
    let entry = victim.agent.cached_agent(&x.id()).await.expect("X cached");
    assert_eq!(entry.cert_digest, Some(x_digest));
    assert_eq!(entry.machine_id, x.machine_id());
    assert!(
        victim.agent.cached_agent(&cold.id()).await.is_none(),
        "a blob committed only by a class C beat creates no entry"
    );
    assert!(victim.announced_binding(&cold.id()).await.is_none());
    let binding = victim
        .announced_binding(&x.id())
        .await
        .expect("X's announced binding");
    assert_eq!(binding.cert_digest, Some(x_digest));
    assert_eq!(binding.machine_id, x.machine_id());
}

/// ADR 0115 §7, mixed versions: a v0.46.4 publisher (wire encoders
/// unchanged since v0.46.4: `IdentityAnnouncementV3::build_from_v2`,
/// `serialize_v3`, `serialize_identity_announcement`; envelope signed by
/// the publishing agent) stays class A. A v0.46.4 legacy republisher's copy
/// is class B for an authenticated pairing and class C for a cold agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr0115_mixed_version_v0464_publisher_and_legacy_republisher() {
    let victim = Victim::start("mixed").await;
    let owner = UserKeypair::generate().expect("owner key");
    let x = Subject::certified_by(&owner);
    let cold = Subject::new();
    let courier = AgentKeypair::generate().expect("v0.46.4 republisher");
    let t = now_secs() - 100;

    // The v0.46.4 heartbeat: an anonymous X0A3 beat under X's envelope.
    let beat = signed_announcement(x.id(), x.public_key(), &x.machine, t, None);
    victim.announce(&x.agent, v3_wire(&beat, &x.machine)).await;
    victim.identity_barrier().await;
    assert_eq!(
        victim.cached_machine(&x.id()).await,
        Some(x.machine_id()),
        "a genuine v0.46.4 publisher is class A"
    );
    assert_eq!(
        victim
            .agent
            .authenticated_bound_machine(&x.id())
            .await
            .map(|bound| bound.machine_id),
        Some(x.machine_id()),
        "class A records the authenticated binding"
    );
    assert_eq!(
        victim
            .announced_binding(&x.id())
            .await
            .map(|bound| bound.machine_id),
        Some(x.machine_id())
    );

    // The republisher relays X's later X0A2 body (now certified): class B.
    victim
        .republish(&courier, &x, &x.machine, t + 5, Some(&x.cert))
        .await;
    // And a cold agent's body it heard elsewhere: class C.
    let before = unauthenticated_announces();
    victim
        .republish(&courier, &cold, &cold.machine, t + 5, Some(&cold.cert))
        .await;
    victim.identity_barrier().await;
    assert_eq!(
        victim.cached_cert(&x.id()).await,
        Some(x.cert.clone()),
        "a legacy republished body for an authenticated pairing refreshes it (class B)"
    );
    assert_eq!(victim.cached_machine(&x.id()).await, Some(x.machine_id()));
    assert!(
        victim.agent.cached_agent(&cold.id()).await.is_none(),
        "a legacy republished body for a cold agent is class C"
    );
    assert!(unauthenticated_announces() > before);

    // The cold agent's own beat, when it arrives, is class A.
    victim.announce_genuine(&cold, t + 6).await;
    victim.identity_barrier().await;
    victim.expect_genuine_entry(&cold, "mixed-version").await;
}
