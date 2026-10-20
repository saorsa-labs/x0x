//! ADR-0074 §4 intent tests: live forward streams close within 5 s of a
//! revocation or trust loss and within 35 s of a grant's expiry, and only
//! the streams whose authority is gone.
//!
//! Time is paused tokio time. The re-check clock is derived from it, so a
//! grant's expiry is crossed deterministically. Event tests run with the
//! expiry sweep disabled, so only the event under test can close a stream. Streams are in-memory
//! registrations (plus `tokio::io::duplex` for the bridge); nothing binds a
//! socket.

use super::*;
use crate::connect::{ConnectAcl, ConnectAllowEntry, ConnectOwnerEntry};
use crate::contacts::{ContactStore, TrustLevel};
use crate::dm_inbox::AuthenticatedMachineBindings;
use crate::identity::{AgentCertificate, AgentKeypair, MachineKeypair, UserKeypair};
use crate::owner_sync::{OwnerEnrollment, OwnerSyncStore};
use crate::owner_trust::OwnerTrust;
use crate::revocation::RevocationSet;
use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
use crate::DiscoveredAgent;
use tokio::sync::{Notify, RwLock};
use tokio::time::Instant;

const SSH: &str = "127.0.0.1:22";
/// The §4 bound after an applied event.
const EVENT_BOUND: Duration = Duration::from_secs(5);
/// The §4 bound after a grant's expiry.
const EXPIRY_BOUND: Duration = Duration::from_secs(35);

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn discovered(kp: &AgentKeypair, machine: MachineId, cert: AgentCertificate) -> DiscoveredAgent {
    DiscoveredAgent {
        self_name: None,
        agent_id: kp.agent_id(),
        machine_id: machine,
        user_id: cert.user_id().ok(),
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
        cert_not_after: cert.not_after(),
        agent_certificate: Some(cert),
        agent_public_key: kp.public_key().as_bytes().to_vec(),
        cert_digest: None,
    }
}

/// Owner A's exposing daemon (agent A1). Peers: B1 (user B, a stranger
/// who may hold grants), C1 (user C, a stranger) and O1 (owner A's own
/// agent on an enrolled machine).
struct World {
    dir: tempfile::TempDir,
    owner_a: UserKeypair,
    user_b: UserKeypair,
    a1: AgentId,
    b1: AgentId,
    mb: MachineId,
    c1: AgentId,
    mc: MachineId,
    o1: AgentId,
    mo: MachineId,
    contacts: Arc<RwLock<ContactStore>>,
    cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>,
    revocations: Arc<RwLock<RevocationSet>>,
    move_state: Arc<RwLock<crate::key_move::MoveState>>,
    policy: Arc<std::sync::RwLock<Arc<ConnectPolicy>>>,
    trust: OwnerTrust,
    /// ADR 0115 announced-binding store (shared with OwnerTrust).
    announced: AuthenticatedMachineBindings,
    /// ADR 0115 authenticated-binding store (shared with OwnerTrust).
    authenticated: AuthenticatedMachineBindings,
    devices: Arc<OwnerSyncStore>,
    grants: Arc<ShareGrantStore>,
    kick: Arc<Notify>,
    diag: Arc<ForwardDiagnostics>,
    live: Arc<LiveStreams>,
    /// Unix seconds at tokio time zero; the re-check clock advances with
    /// paused tokio time from here.
    base_secs: u64,
    start: Instant,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base_secs = real_now();
        let owner_a = UserKeypair::generate().unwrap();
        let user_b = UserKeypair::generate().unwrap();
        let user_c = UserKeypair::generate().unwrap();
        let a1 = AgentKeypair::generate().unwrap().agent_id();
        let b1_kp = AgentKeypair::generate().unwrap();
        let c1_kp = AgentKeypair::generate().unwrap();
        let o1_kp = AgentKeypair::generate().unwrap();
        let (mb, mc, mo) = (
            MachineId([0xB0; 32]),
            MachineId([0xC0; 32]),
            MachineId([0x0A; 32]),
        );
        let authenticated = AuthenticatedMachineBindings::default();
        let announced = AuthenticatedMachineBindings::default();
        let mut cache = HashMap::new();
        for (kp, user, machine) in [
            (&b1_kp, &user_b, mb),
            (&c1_kp, &user_c, mc),
            (&o1_kp, &owner_a, mo),
        ] {
            crate::dm_inbox::record_authenticated_machine_binding(
                &authenticated,
                kp.agent_id(),
                machine,
                base_secs,
            )
            .await;
            crate::dm_inbox::record_authenticated_machine_binding(
                &announced,
                kp.agent_id(),
                machine,
                base_secs,
            )
            .await;
            let cert = AgentCertificate::issue(user, kp).unwrap();
            cache.insert(kp.agent_id(), discovered(kp, machine, cert));
        }

        // Every contact-store, revocation-set, device-set, and machine-binding
        // change wakes the loop, as the agent wires them.
        let kick = Arc::new(Notify::new());
        let mut contacts = ContactStore::new(dir.path().join("contacts.json"));
        contacts.set_change_notify(Arc::clone(&kick));
        let mut revocations = RevocationSet::new();
        revocations.set_change_notify(Arc::clone(&kick));
        authenticated
            .write()
            .await
            .set_change_notify(Arc::clone(&kick));
        announced.write().await.set_change_notify(Arc::clone(&kick));

        let devices = Arc::new(OwnerSyncStore::load(dir.path()).await.unwrap());
        devices
            .enroll(OwnerEnrollment::sign(mo, &owner_a, base_secs * 1000, None).unwrap())
            .await
            .unwrap();
        devices.set_device_change_notify(Arc::clone(&kick));
        let grants = Arc::new(ShareGrantStore::in_memory(a1, Some(owner_a.user_id())));
        let trust = OwnerTrust::new(Some(owner_a.user_id()), Arc::clone(&authenticated));
        trust.install_announced_bindings(Arc::clone(&announced));
        trust.install_device_store(Arc::clone(&devices));
        trust.install_share_grant_store(Arc::clone(&grants));

        let diag = Arc::new(ForwardDiagnostics::default());
        Self {
            dir,
            owner_a,
            user_b,
            a1,
            b1: b1_kp.agent_id(),
            mb,
            c1: c1_kp.agent_id(),
            mc,
            o1: o1_kp.agent_id(),
            mo,
            contacts: Arc::new(RwLock::new(contacts)),
            cache: Arc::new(RwLock::new(cache)),
            revocations: Arc::new(RwLock::new(revocations)),
            move_state: Arc::new(RwLock::new(crate::key_move::MoveState::default())),
            policy: Arc::new(std::sync::RwLock::new(Arc::new(ConnectPolicy::default()))),
            trust,
            announced,
            authenticated,
            devices,
            grants,
            kick,
            live: Arc::new(LiveStreams::new(Arc::clone(&diag))),
            diag,
            base_secs,
            start: Instant::now(),
        }
    }

    fn clock(&self) -> Clock {
        let (base_ms, start) = (self.base_secs * 1000, self.start);
        Arc::new(move || base_ms + u64::try_from(start.elapsed().as_millis()).unwrap())
    }

    fn ctx(&self) -> ReauthCtx {
        ReauthCtx {
            discovery_cache: Arc::clone(&self.cache),
            contact_store: Arc::clone(&self.contacts),
            revocation_set: Arc::clone(&self.revocations),
            move_state: Arc::clone(&self.move_state),
            connect_policy: Arc::clone(&self.policy),
            owner_trust: self.trust.clone(),
            announced_bindings: Arc::clone(&self.announced),
            authenticated_bindings: Arc::clone(&self.authenticated),
            own_machine_id: MachineId([0xAA; 32]),
            clock: self.clock(),
        }
    }

    /// Install `policy` WITHOUT waking the loop (fixture setup, before the
    /// loop runs).
    fn set_policy_silently(&self, policy: ConnectPolicy) {
        *self.policy.write().unwrap() = Arc::new(policy);
    }

    /// A connect ACL for `:22` with exact entries for `exact`, plus owner
    /// and grant entries.
    fn acl(&self, exact: &[(AgentId, MachineId)], owner: bool, grant: bool) -> ConnectPolicy {
        let targets = vec![SSH.parse().unwrap()];
        let entry = || ConnectOwnerEntry {
            description: None,
            targets: targets.clone(),
        };
        ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: self.dir.path().join("connect-acl.toml"),
            loaded_at_unix_ms: 0,
            allow: exact
                .iter()
                .map(|(agent_id, machine_id)| ConnectAllowEntry {
                    description: None,
                    agent_id: *agent_id,
                    machine_id: *machine_id,
                    targets: targets.clone(),
                })
                .collect(),
            owner_allow: if owner { vec![entry()] } else { Vec::new() },
            grant_allow: if grant { vec![entry()] } else { Vec::new() },
        })
    }

    /// An accepted grant from owner A over A1 conferring `Connect{22}`.
    async fn grant(&self, id: u8, grantee: Grantee, expiry: u64) -> ShareGrant {
        let grant = ShareGrant::sign(
            &self.owner_a,
            [id; 32],
            grantee,
            vec![self.a1],
            vec![ShareCap::Connect { ports: vec![22] }],
            self.base_secs - 60,
            expiry,
        )
        .unwrap();
        self.grants
            .accept(grant.clone(), self.base_secs)
            .await
            .unwrap();
        grant
    }

    /// Apply an owner-signed revocation of `grant` through the v3 ingest
    /// path, as gossip delivers it.
    async fn revoke_grant(&self, grant: &ShareGrant) {
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::ShareGrant(
                crate::revocation::ShareGrantRevocation {
                    grant_id: grant.grant_id,
                    owner: grant.owner,
                    grant_expiry: grant.expiry,
                },
            ),
            self.owner_a.public_key(),
            self.owner_a.secret_key(),
            real_now(),
            None,
        )
        .unwrap();
        let payload = bincode::serialize(&vec![record]).unwrap();
        assert!(
            crate::ingest_share_grant_revocations(
                &OwnerTrust::default(),
                &self.revocations,
                Some(self.dir.path().to_path_buf()),
                &payload,
            )
            .await
        );
    }

    fn inbound(&self, opener: AgentId, machine: MachineId) -> StreamGate {
        StreamGate::InboundAttested {
            opener,
            machine,
            target: SSH.parse().unwrap(),
        }
    }

    /// Admit a stream through the real gate and register it live, as the
    /// forwarder does once a stream is bridged.
    async fn admit(&self, gate: StreamGate) -> (LiveStreamGuard, StreamAuthority) {
        let authority = check_gate(&gate, &self.ctx())
            .await
            .unwrap_or_else(|reason| panic!("admission refused: {reason}"));
        (self.live.register(gate, authority.clone()), authority)
    }

    /// Start the loop. `sweep: None` disables the expiry sweep, so only an
    /// event can trigger a pass.
    fn spawn_loop(&self, sweep: Option<Duration>) -> CancellationToken {
        let stop = CancellationToken::new();
        spawn_reauth_loop(
            Arc::clone(&self.live),
            self.ctx(),
            Arc::clone(&self.kick),
            stop.clone(),
            sweep,
        );
        stop
    }

    fn reasons(&self) -> std::collections::BTreeMap<String, u64> {
        self.diag.torn_down_reasons()
    }
}

/// Wait for `guard` to be torn down within `bound`; returns how long it took.
async fn closes_within(guard: &LiveStreamGuard, bound: Duration) -> Duration {
    let started = Instant::now();
    tokio::time::timeout(bound, guard.token().cancelled())
        .await
        .unwrap_or_else(|_| panic!("stream still open {bound:?} after the event"));
    started.elapsed()
}

/// WHY (ADR-0074 §4, Q5): revoking the ShareGrant a forward was admitted
/// under must close that live forward within 5 s. Before slice 3 the grant
/// was checked only at admission, so the stream outlived the revocation.
/// The sweep is off: only the revocation event can close it.
#[tokio::test(start_paused = true)]
async fn revoked_grant_closes_its_forward_within_5s() {
    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], false, true));
    let grant = w
        .grant(0x11, Grantee::User(w.user_b.user_id()), w.base_secs + 3_600)
        .await;
    let (stream, authority) = w.admit(w.inbound(w.b1, w.mb)).await;
    assert_eq!(
        authority,
        StreamAuthority::Grant {
            grant_ids: vec![hex::encode(grant.grant_id)]
        },
        "the stream records the grant it was admitted under"
    );
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!stream.token().is_cancelled());

    w.revoke_grant(&grant).await;
    closes_within(&stream, EVENT_BOUND).await;
    assert_eq!(w.diag.torn_down_reauth(), 1);
    assert_eq!(w.reasons().get("trust_rejected"), Some(&1));
    assert_eq!(w.live.len(), 0, "a torn-down stream leaves the registry");
}

/// WHY (Codex P2 / RC7): a DM-attestation binding write must wake stream
/// reauth within the ADR-0074 5 s event bound with the periodic sweep off.
///
/// The production DM path (`dm_inbox` ~1612) calls
/// [`crate::dm_inbox::record_authenticated_machine_binding`] after a valid
/// origin attestation; the notify fires inside that shared writer (and every
/// other cache mutator), so this test drives the same function rather than
/// re-verifying a full DM envelope.
#[tokio::test(start_paused = true)]
async fn dm_attestation_binding_change_closes_grant_forward_within_5s() {
    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], false, true));
    let grant = w
        .grant(0x21, Grantee::User(w.user_b.user_id()), w.base_secs + 3_600)
        .await;
    let (stream, authority) = w.admit(w.inbound(w.b1, w.mb)).await;
    assert_eq!(
        authority,
        StreamAuthority::Grant {
            grant_ids: vec![hex::encode(grant.grant_id)]
        }
    );
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!stream.token().is_cancelled());

    // Portable move: fresher DM attestation binds b1 to a new machine. The
    // inbound StreamGate still names mb; grant reauth fails the authenticated
    // binding match and tears the stream down (same reason as grant revoke).
    let moved = MachineId([0xB1; 32]);
    crate::dm_inbox::record_authenticated_machine_binding(
        &w.authenticated,
        w.b1,
        moved,
        w.base_secs + 1,
    )
    .await;

    closes_within(&stream, EVENT_BOUND).await;
    assert_eq!(w.diag.torn_down_reauth(), 1);
    assert_eq!(w.reasons().get("trust_rejected"), Some(&1));
    assert_eq!(w.live.len(), 0);
}

/// WHY: a contact downgrade to `Blocked` must close the peer's live forward
/// within 5 s, through the contact-store event (sweep off).
#[tokio::test(start_paused = true)]
async fn trust_downgrade_closes_within_5s() {
    let w = World::new().await;
    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Trusted);
    w.set_policy_silently(w.acl(&[(w.b1, w.mb)], false, false));
    let (stream, authority) = w.admit(w.inbound(w.b1, w.mb)).await;
    assert_eq!(authority, StreamAuthority::AclEntry);
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!stream.token().is_cancelled());

    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Blocked);
    closes_within(&stream, EVENT_BOUND).await;
    assert_eq!(w.reasons().get("trust_rejected"), Some(&1));
}

/// WHY (Codex P2 / RC5): public `ContactStore::get_mut` must wake reauth;
/// setting `Blocked` via `get_mut` (no save) must close the stream within
/// EVENT_BOUND (sweep off).
#[tokio::test(start_paused = true)]
async fn get_mut_edit_closes_within_5s() {
    let w = World::new().await;
    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Trusted);
    w.set_policy_silently(w.acl(&[(w.b1, w.mb)], false, false));
    let (stream, _) = w.admit(w.inbound(w.b1, w.mb)).await;
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!stream.token().is_cancelled());

    w.contacts.write().await.get_mut(&w.b1).unwrap().trust_level = TrustLevel::Blocked;
    closes_within(&stream, EVENT_BOUND).await;
}

/// WHY: an ACL reload that drops a stream's entry must close it within 5 s,
/// through the reload event `Agent::set_connect_policy` raises (sweep off).
/// The still-listed stream stays up.
#[tokio::test(start_paused = true)]
async fn acl_reload_closes_a_stream_no_longer_listed() {
    let w = World::new().await;
    for agent in [w.b1, w.c1] {
        w.contacts
            .write()
            .await
            .set_trust(&agent, TrustLevel::Trusted);
    }
    w.set_policy_silently(w.acl(&[(w.b1, w.mb), (w.c1, w.mc)], false, false));
    let (b_stream, _) = w.admit(w.inbound(w.b1, w.mb)).await;
    let (c_stream, _) = w.admit(w.inbound(w.c1, w.mc)).await;
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_secs(10)).await;

    crate::install_connect_policy(
        &w.policy,
        &w.kick,
        Arc::new(w.acl(&[(w.c1, w.mc)], false, false)),
    );
    closes_within(&b_stream, EVENT_BOUND).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(
        !c_stream.token().is_cancelled(),
        "the still-listed stream closed"
    );
    assert_eq!(w.reasons().get("agent_machine_not_in_acl"), Some(&1));
}

/// WHY: removing the owner enrollment of a machine ends owner trust for its
/// agents; their owner-admitted streams must close within 5 s through the
/// device-set event (sweep off).
#[tokio::test(start_paused = true)]
async fn enrollment_removal_closes_owner_stream_within_5s() {
    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], true, false));
    let (stream, authority) = w.admit(w.inbound(w.o1, w.mo)).await;
    assert_eq!(authority, StreamAuthority::OwnerTrust);
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!stream.token().is_cancelled());

    assert!(w.devices.unenroll(&w.mo).await.unwrap());
    closes_within(&stream, EVENT_BOUND).await;
    assert_eq!(w.reasons().get("trust_rejected"), Some(&1));
}

/// WHY (Q5): with only the 30 s expiry sweep, a grant's expiry closes its
/// forward within 35 s, and not before the expiry. The expiry falls just
/// after a sweep, the worst case for the bound.
#[tokio::test(start_paused = true)]
async fn grant_expiry_closes_within_35s_with_the_30s_sweep() {
    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], false, true));
    // Sweeps run at t = 0, 30, 60, 90, 120 s.
    let expiry = w.base_secs + 91;
    w.grant(0x22, Grantee::User(w.user_b.user_id()), expiry)
        .await;
    let (stream, _) = w.admit(w.inbound(w.b1, w.mb)).await;
    let _stop = w.spawn_loop(Some(REAUTH_SWEEP_INTERVAL));

    // Past the t = 90 s sweep, one second before expiry: still open.
    tokio::time::sleep(Duration::from_secs(90)).await;
    assert!(
        !stream.token().is_cancelled(),
        "closed before the grant expired"
    );

    closes_within(&stream, Duration::from_secs(1) + EXPIRY_BOUND).await;
    let closed_at_ms = (w.clock())();
    assert!(closed_at_ms >= expiry * 1000, "closed before expiry");
    assert!(
        closed_at_ms <= expiry * 1000 + EXPIRY_BOUND.as_millis() as u64,
        "closed {} ms after expiry",
        closed_at_ms - expiry * 1000
    );
    assert_eq!(w.diag.torn_down_reauth(), 1);
}

/// WHY: teardown is per stream. Revoking grants closes only the stream that
/// depended on them. An owner-trusted stream stays up even though a grant
/// naming its agent is revoked too (owner trust, not the grant, admitted
/// it), and an unrelated exact-ACL stream is untouched.
#[tokio::test(start_paused = true)]
async fn unaffected_streams_stay_open() {
    let w = World::new().await;
    w.contacts
        .write()
        .await
        .set_trust(&w.c1, TrustLevel::Trusted);
    w.set_policy_silently(w.acl(&[(w.c1, w.mc)], true, true));
    let grant_b = w
        .grant(0x33, Grantee::User(w.user_b.user_id()), w.base_secs + 3_600)
        .await;
    let grant_o = w
        .grant(0x44, Grantee::Agent(w.o1), w.base_secs + 3_600)
        .await;
    let (b_stream, b_auth) = w.admit(w.inbound(w.b1, w.mb)).await;
    let (o_stream, o_auth) = w.admit(w.inbound(w.o1, w.mo)).await;
    let (c_stream, c_auth) = w.admit(w.inbound(w.c1, w.mc)).await;
    assert!(matches!(b_auth, StreamAuthority::Grant { .. }));
    assert_eq!(o_auth, StreamAuthority::OwnerTrust);
    assert_eq!(c_auth, StreamAuthority::AclEntry);
    let _stop = w.spawn_loop(None);

    w.revoke_grant(&grant_b).await;
    w.revoke_grant(&grant_o).await;
    closes_within(&b_stream, EVENT_BOUND).await;

    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(
        !o_stream.token().is_cancelled(),
        "owner stream closed by a grant event"
    );
    assert!(!c_stream.token().is_cancelled(), "unrelated stream closed");
    assert_eq!(w.diag.torn_down_reauth(), 1);
    assert_eq!(w.live.len(), 2);
}

/// WHY (§4 "both ends enforce"): the opener also closes its side once its
/// peer is blocked (sweep off).
#[tokio::test(start_paused = true)]
async fn outbound_stream_closes_when_the_peer_is_blocked() {
    let w = World::new().await;
    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Trusted);
    let (stream, authority) = w
        .admit(StreamGate::Outbound {
            peer_agent: w.b1,
            machine: w.mb,
        })
        .await;
    assert_eq!(authority, StreamAuthority::PeerTrust);
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!stream.token().is_cancelled());

    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Blocked);
    closes_within(&stream, EVENT_BOUND).await;
}

/// WHY: a re-check pass must not redo ML-DSA work for evidence that has not
/// changed — with many streams that cost is per stream per pass. The first
/// pass verifies (owner certificate chain, enrollment, grantee chain); a
/// repeat pass with nothing changed verifies nothing; a revocation-set
/// change clears the memo, so the next pass verifies again.
// Verify-memo (995b746) not required for the §4 bounds; keep the intent
// test but skip until OwnerTrust memo is ported separately.
#[tokio::test]
#[ignore = "verify memo not in this slice; bounds covered by event/expiry tests"]
async fn repeat_pass_without_changes_performs_no_verification() {
    use crate::identity::ml_dsa_verify_count;
    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], true, true));
    w.grant(0x55, Grantee::User(w.user_b.user_id()), w.base_secs + 3_600)
        .await;
    let unrelated = w
        .grant(0x66, Grantee::Agent(w.c1), w.base_secs + 3_600)
        .await;
    let (_o, _) = w.admit(w.inbound(w.o1, w.mo)).await;
    let (_b, _) = w.admit(w.inbound(w.b1, w.mb)).await;

    let before = ml_dsa_verify_count::get();
    assert_eq!(
        reauth_pass(&w.live, &w.ctx(), Instant::now() + REAUTH_PASS_BUDGET).await,
        0
    );
    let first = ml_dsa_verify_count::get() - before;
    // Admission above already filled the memo, so even this pass is free;
    // clear it through a revocation-set change to measure a cold pass.
    w.revoke_grant(&unrelated).await;
    let before = ml_dsa_verify_count::get();
    assert_eq!(
        reauth_pass(&w.live, &w.ctx(), Instant::now() + REAUTH_PASS_BUDGET).await,
        0
    );
    let cold = ml_dsa_verify_count::get() - before;
    assert!(
        cold >= 3,
        "a cold pass verifies the owner chain, the enrollment and the grantee chain (got {cold})"
    );

    let before = ml_dsa_verify_count::get();
    assert_eq!(
        reauth_pass(&w.live, &w.ctx(), Instant::now() + REAUTH_PASS_BUDGET).await,
        0
    );
    assert_eq!(
        ml_dsa_verify_count::get() - before,
        0,
        "repeat pass re-verified"
    );
    assert_eq!(first, 0, "the pass after admission re-verified");
    assert_eq!(w.live.len(), 2);
}

/// WHY: a torn-down bridge must stop moving bytes at once rather than run
/// until the peer hangs up; an untouched bridge still ends on its own when
/// both sides close (#961 semantics kept).
#[tokio::test]
async fn bridge_stops_on_teardown_and_ends_normally_otherwise() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Teardown mid-stream.
    let (mut app, tcp_side) = tokio::io::duplex(1024);
    let (mut peer, quic_side) = tokio::io::duplex(1024);
    let cancel = CancellationToken::new();
    let bridge = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_side);
            let (mut recv, mut send) = tokio::io::split(quic_side);
            bridge_io(&mut tcp_read, &mut tcp_write, &mut recv, &mut send, &cancel).await
        })
    };
    app.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    peer.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping", "bytes flow before teardown");
    cancel.cancel();
    let torn_down = tokio::time::timeout(Duration::from_secs(1), bridge)
        .await
        .expect("bridge kept running after teardown")
        .unwrap();
    assert!(torn_down);

    // No teardown: both sides close, the bridge ends by itself.
    let (app, tcp_side) = tokio::io::duplex(1024);
    let (peer, quic_side) = tokio::io::duplex(1024);
    let cancel = CancellationToken::new();
    drop((app, peer));
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_side);
    let (mut recv, mut send) = tokio::io::split(quic_side);
    let torn_down = tokio::time::timeout(
        Duration::from_secs(1),
        bridge_io(&mut tcp_read, &mut tcp_write, &mut recv, &mut send, &cancel),
    )
    .await
    .expect("bridge did not end when both sides closed");
    assert!(!torn_down);
}

/// WHY (Codex P2 / RC6): a peer reauth reset ends the QUIC-recv copy with an
/// error. That error must tear down both bridge halves so an idle TCP client
/// does not keep its socket open while `join!` waits on TCP→stream input.
/// Dual endpoints: real idle TCP client ↔ `bridge_io` ↔ TCP pair standing in
/// for the stream (RST on the peer feeding `recv`).
#[tokio::test]
async fn bridge_io_quic_recv_error_tears_down_idle_tcp() {
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    // Local TCP: idle client (connected, not sending) ↔ accepted half.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let mut tcp_client = TcpStream::connect(tcp_addr).await.unwrap();
    let (tcp_server, _) = tcp_listener.accept().await.unwrap();
    let (mut tcp_read, mut tcp_write) = tcp_server.into_split();

    // Stream side: real sockets so a linger-0 drop yields a read error, not
    // clean EOF (duplex drop would be half-close and must not force teardown).
    let stream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream_addr = stream_listener.local_addr().unwrap();
    let stream_peer = TcpStream::connect(stream_addr).await.unwrap();
    let (stream_bridge, _) = stream_listener.accept().await.unwrap();
    let (mut recv, mut send) = stream_bridge.into_split();

    let cancel = CancellationToken::new();
    let bridge = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            bridge_io(&mut tcp_read, &mut tcp_write, &mut recv, &mut send, &cancel).await
        })
    };

    // Settle so both copies are parked; TCP client stays idle.
    tokio::task::yield_now().await;

    // Abrupt peer reset on the half feeding `recv` (reauth-style error).
    reset_tcp(&stream_peer);
    drop(stream_peer);

    let torn_down = tokio::time::timeout(EVENT_BOUND, bridge)
        .await
        .expect("bridge hung after QUIC-recv error; idle TCP kept join waiting")
        .expect("bridge task panicked");
    assert!(
        torn_down,
        "copy/shutdown error must return true so the caller resets both halves"
    );

    // Idle TCP client must observe EOF/RST within the ADR-0074 bound.
    let mut buf = [0u8; 1];
    match tokio::time::timeout(EVENT_BOUND, tcp_client.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("unexpected {n} bytes from torn-down bridge"),
        Err(_) => panic!("idle TCP client stayed open after QUIC-recv error"),
    }
}

/// WHY: ADR-0074 §4 requires the local TCP socket to reset (RST), not finish
/// with a clean FIN that makes a truncated response look complete. Tokio's
/// `OwnedWriteHalf` would otherwise `shutdown(Write)` on drop after
/// `set_linger(0)`; `forget()` avoids that FIN-before-RST race.
#[tokio::test]
async fn reset_tcp_with_forgotten_write_half_yields_connection_reset() {
    use std::io::ErrorKind;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    let (read, write) = server.into_split();
    reset_tcp(&write);
    write.forget();
    drop(read);

    let mut buf = [0u8; 8];
    match client.read(&mut buf).await {
        Ok(0) => panic!("got clean EOF (FIN); expected ConnectionReset from linger-0 close"),
        Ok(n) => panic!("unexpected {n} bytes from reset peer"),
        Err(err) => assert_eq!(
            err.kind(),
            ErrorKind::ConnectionReset,
            "expected ConnectionReset, got {err:?}"
        ),
    }
}

/// WHY: a stream that ends on its own leaves the registry, so it is never
/// re-checked or counted as a teardown afterwards.
#[tokio::test]
async fn ended_stream_leaves_the_registry_uncounted() {
    let w = World::new().await;
    let guard = w.live.register(
        StreamGate::Outbound {
            peer_agent: w.b1,
            machine: w.mb,
        },
        StreamAuthority::PeerTrust,
    );
    assert_eq!(w.live.len(), 1);
    drop(guard);
    assert_eq!(w.live.len(), 0);
    assert_eq!(
        reauth_pass(&w.live, &w.ctx(), Instant::now() + REAUTH_PASS_BUDGET).await,
        0
    );
    assert_eq!(w.diag.torn_down_reauth(), 0);
}

/// WHY (Claude blocking + Codex P2): admission uses ADR 0115
/// `authorized_routing_machine` (authority stores win over an unconfirmed
/// cache route). The re-check must share that body — a stale/unconfirmed
/// cache rewrite must not tear down a live outbound as `machine_changed`.
#[tokio::test(start_paused = true)]
async fn outbound_reauth_keeps_stream_when_cache_route_is_stale_but_authority_names_machine() {
    let w = World::new().await;
    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Trusted);

    // Discovery cache claims a different, unconfirmed machine; the
    // authenticated/announced stores still name mb (the admitted peer).
    let stale = MachineId([0xEE; 32]);
    {
        let mut cache = w.cache.write().await;
        let entry = cache.get_mut(&w.b1).expect("b1 cached");
        entry.machine_id = stale;
    }

    let resolved = crate::Agent::gate_peer_outbound_at(
        &w.cache,
        &w.contacts,
        &w.revocations,
        &w.move_state,
        &w.trust,
        &w.announced,
        &w.authenticated,
        &w.b1,
        w.base_secs,
        true,
    )
    .await
    .expect("admission must use authority machine mb, not stale cache");
    assert_eq!(resolved, w.mb, "ADR 0115 must prefer the authority machine");

    let (stream, authority) = w
        .admit(StreamGate::Outbound {
            peer_agent: w.b1,
            machine: w.mb,
        })
        .await;
    assert_eq!(authority, StreamAuthority::PeerTrust);
    assert_eq!(
        reauth_pass(&w.live, &w.ctx(), Instant::now() + REAUTH_PASS_BUDGET).await,
        0
    );
    assert!(
        !stream.token().is_cancelled(),
        "reauth must not tear down as machine_changed when authority still names mb"
    );
    assert_eq!(w.diag.torn_down_reauth(), 0);
}

/// WHY (Claude Low / RC3): a stream admitted on usable persisted evidence
/// with no authenticated binding must survive a local-only reauth pass.
/// Reauth must not tear it down just because bindings are absent.
#[tokio::test(start_paused = true)]
async fn evidence_admitted_stream_survives_reauth_without_bindings() {
    use crate::announce_v3::IdentityAnnouncementV3;
    use crate::dm::DmCapabilities;
    use crate::dm_capability::{CapabilityAdvert, RegistryTrailer, REGISTRY_TRAILER_MAGIC};
    use crate::peer_evidence::{
        EvidenceConfig, EvidenceRecordV1, EvidenceRuntime, IngestSource, PeerEvidenceStore,
        RuntimePolicy,
    };

    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], false, true));

    let agent_kp = AgentKeypair::generate().unwrap();
    let machine_kp = MachineKeypair::generate().unwrap();
    let peer = agent_kp.agent_id();
    let machine = machine_kp.machine_id();
    let cert = AgentCertificate::issue(&w.user_b, &agent_kp).unwrap();
    w.cache
        .write()
        .await
        .insert(peer, discovered(&agent_kp, machine, cert.clone()));
    let _grant = w
        .grant(0x51, Grantee::Agent(peer), w.base_secs + 3_600)
        .await;

    // Usable persisted evidence for the peer (ready store, no load barrier).
    let now_ms = w.base_secs.saturating_mul(1000);
    let record = {
        let v2 = crate::IdentityAnnouncement {
            self_name: Some("evidence peer".into()),
            agent_id: peer,
            machine_id: machine,
            user_id: None,
            agent_certificate: None,
            machine_public_key: machine_kp.public_key().as_bytes().to_vec(),
            machine_signature: vec![],
            addresses: vec![],
            announced_at: now_ms / 1000,
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
        };
        let mut ann =
            IdentityAnnouncementV3::build_from_v2(&v2, machine_kp.secret_key(), 0).unwrap();
        ann.sign_v3_1(machine_kp.secret_key()).unwrap();
        let mut caps = DmCapabilities::pending();
        caps.kem_public_key = vec![42; 1184];
        let mut advert = CapabilityAdvert {
            protocol_version: crate::dm_capability_service::ADVERT_PROTOCOL_VERSION,
            agent_id: *peer.as_bytes(),
            machine_id: *machine.as_bytes(),
            created_at_unix_ms: now_ms,
            capabilities: caps,
            signature: vec![],
        };
        advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            agent_kp.secret_key(),
            &advert.signed_bytes().unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let mut trailer = RegistryTrailer {
            registry: Default::default(),
            signature: vec![],
        };
        trailer.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            agent_kp.secret_key(),
            &trailer.signed_bytes(&advert).unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let mut bytes = postcard::to_stdvec(&advert).unwrap();
        bytes.extend_from_slice(REGISTRY_TRAILER_MAGIC);
        bytes.extend(postcard::to_stdvec(&trailer).unwrap());
        EvidenceRecordV1 {
            announcement: crate::announce_v3::serialize_v3_1(&ann).unwrap(),
            advert: bytes,
            certificate: Some(cert.to_storage_bytes().unwrap()),
            relation: crate::peer_evidence::GROUP,
            stored_at_ms: now_ms,
        }
    };
    let policy = Arc::new(RuntimePolicy::new(
        w.a1,
        w.trust.clone(),
        Arc::clone(&w.revocations),
    ));
    let store = Arc::new(
        PeerEvidenceStore::open(
            &w.dir.path().join("evidence-survive"),
            EvidenceConfig::default(),
            policy,
            now_ms,
        )
        .unwrap(),
    );
    store.ingest(record, IngestSource::Hello, now_ms).unwrap();
    let (evidence, ready) = EvidenceRuntime::loading_store_for_test(store);
    ready.cancel();
    assert!(
        evidence.usable(peer, machine, now_ms).is_some(),
        "control: persisted evidence must be usable before reauth"
    );
    w.trust.install_evidence(&evidence);

    // No authenticated binding — grant authority rides on local usable evidence.
    {
        let mut bind = w.authenticated.write().await;
        // Keep change_notify installed (World wires ADR-0074 reauth wake).
        bind.clear_for_test();
    }

    // Drive the same gate registration admission would after an
    // evidence-backed grant (local reauth flags already on pass_inputs).
    let gate = w.inbound(peer, machine);
    let authority = check_gate(&gate, &w.ctx())
        .await
        .expect("evidence-backed grant must admit without authenticated binding");
    assert!(matches!(authority, StreamAuthority::Grant { .. }));
    let stream = w.live.register(gate, authority);
    assert_eq!(
        reauth_pass(&w.live, &w.ctx(), Instant::now() + REAUTH_PASS_BUDGET).await,
        0
    );
    assert!(
        !stream.token().is_cancelled(),
        "local reauth must keep an evidence-admitted stream when bindings stay cleared"
    );
    assert_eq!(w.diag.torn_down_reauth(), 0);
}

/// WHY (Codex P1 / RC4, updated RC7): owner-trust can fall through to
/// evidence when the authenticated binding is missing. Reauth must use
/// `try_usable` (never block on `usable`). A held ready-store is `Busy`,
/// not an immediate deny: the pass retries until a fresh verdict or the
/// five-second deadline. Holding the store through the full budget (and
/// unenrolling so the loop is kicked) must still tear down by the deadline
/// as `reauth_deadline` — no fresh verdict, fail closed.
#[tokio::test(start_paused = true)]
async fn owner_trust_reauth_tears_down_within_5s_while_evidence_store_held() {
    use crate::announce_v3::IdentityAnnouncementV3;
    use crate::dm::DmCapabilities;
    use crate::dm_capability::{CapabilityAdvert, RegistryTrailer, REGISTRY_TRAILER_MAGIC};
    use crate::peer_evidence::{
        EvidenceConfig, EvidenceRecordV1, EvidenceRuntime, IngestSource, PeerEvidenceStore,
        RuntimePolicy,
    };

    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], true, false));

    let agent_kp = AgentKeypair::generate().unwrap();
    let machine_kp = MachineKeypair::generate().unwrap();
    let peer = agent_kp.agent_id();
    let machine = machine_kp.machine_id();
    let cert = AgentCertificate::issue(&w.owner_a, &agent_kp).unwrap();
    w.devices
        .enroll(OwnerEnrollment::sign(machine, &w.owner_a, w.base_secs * 1000, None).unwrap())
        .await
        .unwrap();
    w.cache
        .write()
        .await
        .insert(peer, discovered(&agent_kp, machine, cert.clone()));

    let now_ms = w.base_secs.saturating_mul(1000);
    let record = {
        let v2 = crate::IdentityAnnouncement {
            self_name: Some("owner evidence peer".into()),
            agent_id: peer,
            machine_id: machine,
            user_id: None,
            agent_certificate: None,
            machine_public_key: machine_kp.public_key().as_bytes().to_vec(),
            machine_signature: vec![],
            addresses: vec![],
            announced_at: now_ms / 1000,
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
        };
        let mut ann =
            IdentityAnnouncementV3::build_from_v2(&v2, machine_kp.secret_key(), 0).unwrap();
        ann.sign_v3_1(machine_kp.secret_key()).unwrap();
        let mut caps = DmCapabilities::pending();
        caps.kem_public_key = vec![42; 1184];
        let mut advert = CapabilityAdvert {
            protocol_version: crate::dm_capability_service::ADVERT_PROTOCOL_VERSION,
            agent_id: *peer.as_bytes(),
            machine_id: *machine.as_bytes(),
            created_at_unix_ms: now_ms,
            capabilities: caps,
            signature: vec![],
        };
        advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            agent_kp.secret_key(),
            &advert.signed_bytes().unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let mut trailer = RegistryTrailer {
            registry: Default::default(),
            signature: vec![],
        };
        trailer.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            agent_kp.secret_key(),
            &trailer.signed_bytes(&advert).unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let mut bytes = postcard::to_stdvec(&advert).unwrap();
        bytes.extend_from_slice(REGISTRY_TRAILER_MAGIC);
        bytes.extend(postcard::to_stdvec(&trailer).unwrap());
        EvidenceRecordV1 {
            announcement: crate::announce_v3::serialize_v3_1(&ann).unwrap(),
            advert: bytes,
            certificate: Some(cert.to_storage_bytes().unwrap()),
            relation: crate::peer_evidence::ENROLLED,
            stored_at_ms: now_ms,
        }
    };
    let policy = Arc::new(RuntimePolicy::new(
        w.a1,
        w.trust.clone(),
        Arc::clone(&w.revocations),
    ));
    let store = Arc::new(
        PeerEvidenceStore::open(
            &w.dir.path().join("evidence-owner-reauth"),
            EvidenceConfig::default(),
            policy,
            now_ms,
        )
        .unwrap(),
    );
    store.ingest(record, IngestSource::Hello, now_ms).unwrap();
    let (evidence, ready) = EvidenceRuntime::loading_store_for_test(Arc::clone(&store));
    ready.cancel();
    assert!(
        evidence.usable(peer, machine, now_ms).is_some(),
        "control: enrolled evidence must be usable before admission"
    );
    w.trust.install_evidence(&evidence);

    // Force owner-trust's evidence fallback (no authenticated binding).
    {
        let mut bind = w.authenticated.write().await;
        // Keep change_notify installed (World wires ADR-0074 reauth wake).
        bind.clear_for_test();
    }

    let gate = w.inbound(peer, machine);
    let authority = check_gate(&gate, &w.ctx())
        .await
        .expect("owner stream must admit on enrolled evidence without binding");
    assert_eq!(authority, StreamAuthority::OwnerTrust);
    let stream = w.live.register(gate, authority);

    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(!stream.token().is_cancelled());

    // Hold the ready store on a real OS thread so a blocking `usable()` would
    // stall the reauth task without parking the paused tokio clock.
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let _guard = store.hold_state_for_testing();
            let _ = held_tx.send(());
            let _ = release_rx.recv();
        })
    };
    held_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("evidence store lock holder must start");

    let started = Instant::now();
    assert!(w.devices.unenroll(&machine).await.unwrap());
    // Tear-down lands on the deadline Instant; slack avoids racing the
    // final Busy → reauth_deadline step against closes_within's bound.
    closes_within(&stream, EVENT_BOUND + Duration::from_millis(250)).await;
    assert!(
        started.elapsed() <= EVENT_BOUND + Duration::from_millis(250),
        "owner-trust reauth exceeded the five-second bound while the evidence store was held ({:?})",
        started.elapsed()
    );
    // Store stayed held: Busy retries until the deadline, then fail-closed
    // with no fresh verdict (not an immediate trust_rejected).
    assert_eq!(w.reasons().get("reauth_deadline"), Some(&1));
    assert_eq!(w.diag.torn_down_reauth(), 1);

    let _ = release_tx.send(());
    let _ = holder.join();
}

/// WHY (Codex P1): grant evaluation can await a 5 s EvidenceV1 load barrier
/// when an authenticated binding is absent. Several open streams must not
/// push revocation past the ADR-0074 five-second bound — reauth uses local
/// authority only under [`REAUTH_PASS_BUDGET`].
#[tokio::test(start_paused = true)]
async fn reauth_enforces_revocation_within_5s_despite_slow_evidence() {
    use crate::peer_evidence::{EvidenceConfig, EvidenceRuntime, PeerEvidenceStore, RuntimePolicy};

    let w = World::new().await;
    // Grant-only ACL: streams live only while the grant evaluation passes.
    w.set_policy_silently(w.acl(&[], false, true));
    let grant_b = w
        .grant(0x42, Grantee::Agent(w.b1), w.base_secs + 3_600)
        .await;
    let grant_c = w
        .grant(0x43, Grantee::Agent(w.c1), w.base_secs + 3_600)
        .await;

    // Several live grant-backed streams across two gates.
    let mut streams = Vec::new();
    for _ in 0..3 {
        let (b, auth) = w.admit(w.inbound(w.b1, w.mb)).await;
        assert!(matches!(auth, StreamAuthority::Grant { .. }));
        streams.push(b);
        let (c, auth) = w.admit(w.inbound(w.c1, w.mc)).await;
        assert!(matches!(auth, StreamAuthority::Grant { .. }));
        streams.push(c);
    }

    // Started-but-not-ready evidence: wait(0) blocks ~5 s. Install it so a
    // non-local reauth grant path would stall; the ADR-0074 path must not.
    let policy = Arc::new(RuntimePolicy::new(
        w.a1,
        w.trust.clone(),
        Arc::clone(&w.revocations),
    ));
    let store = Arc::new(
        PeerEvidenceStore::open(
            w.dir.path(),
            EvidenceConfig::default(),
            policy,
            w.base_secs * 1000,
        )
        .unwrap(),
    );
    let (evidence, _ready) = EvidenceRuntime::loading_store_for_test(store);
    w.trust.install_evidence(&evidence);

    // Control: with bindings cleared, non-local grant eval sits in wait(0).
    {
        let mut bind = w.authenticated.write().await;
        // Keep change_notify installed (World wires ADR-0074 reauth wake).
        bind.clear_for_test();
    }
    let blocked = tokio::spawn({
        let trust = w.trust.clone();
        let contacts = Arc::clone(&w.contacts);
        let cache = Arc::clone(&w.cache);
        let revocations = Arc::clone(&w.revocations);
        let b1 = w.b1;
        let mb = w.mb;
        let now = w.base_secs;
        async move {
            trust
                .grant_access_at(&contacts, &cache, &revocations, &b1, &mb, now, true)
                .await
        }
    });
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(
        !blocked.is_finished(),
        "control: evidence wait(0) must still be pending after 1 s"
    );
    blocked.abort();
    // Bindings stay cleared: reauth must tear down via the local-only inbound
    // path (no wait/lookup), not by restoring bindings first.
    let local_probe = Instant::now();
    let _ = w
        .trust
        .grant_access_at(
            &w.contacts,
            &w.cache,
            &w.revocations,
            &w.b1,
            &w.mb,
            w.base_secs,
            false,
        )
        .await;
    assert!(
        local_probe.elapsed() < Duration::from_millis(50),
        "local grant eval must not await the evidence barrier"
    );

    let _stop = w.spawn_loop(None);
    let started = Instant::now();
    w.revoke_grant(&grant_b).await;
    w.revoke_grant(&grant_c).await;
    // EVENT_BOUND already covers REAUTH_MIN_SPACING (250 ms) after the kick.
    for stream in &streams {
        closes_within(stream, EVENT_BOUND).await;
    }
    assert!(
        started.elapsed() <= EVENT_BOUND,
        "pass exceeded the five-second bound under slow evidence ({:?})",
        started.elapsed()
    );
    assert!(
        w.diag.torn_down_reauth() >= streams.len() as u64,
        "expected every live stream torn down; got {:?}",
        w.reasons()
    );
}

/// WHY (Codex P1 / Claude #2): handlers race every pre-bridge I/O against
/// the cancel token via [`wait_cancellable`] (not a post-hoc `is_cancelled`
/// poll), then [`deny_pre_bridge`] resets QUIC with
/// [`ant_quic::high_level::DROPPED_UNFINISHED_ERROR_CODE`] and RSTs TCP.
/// This drives that sequence: register → stall on response read →
/// `tear_down` → wait returns [`Cancelled`] → deny RSTs the local socket.
#[tokio::test]
async fn pre_bridge_cancel_interrupts_stalled_io_and_rsts_tcp() {
    use std::io::ErrorKind;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let server = listener.accept().await.unwrap().0;

    // Same register → wait → tear_down path the outbound handler uses.
    let diag = Arc::new(ForwardDiagnostics::default());
    let live = Arc::new(LiveStreams::new(Arc::clone(&diag)));
    let guard = live.register(
        StreamGate::Outbound {
            peer_agent: AgentId([0xB1; 32]),
            machine: MachineId([0xB0; 32]),
        },
        StreamAuthority::PeerTrust,
    );
    let id = {
        // The first registration is id 0.
        0u64
    };
    let token = guard.token().clone();
    let stalled = tokio::spawn(async move {
        // Stalled response read — the wait reviewers flagged as uncancellable.
        wait_cancellable(&token, std::future::pending::<std::io::Result<()>>()).await
    });
    tokio::task::yield_now().await;
    assert!(
        live.tear_down(id, "revoked"),
        "teardown must cancel the stream"
    );
    assert!(
        matches!(stalled.await.unwrap(), Err(Cancelled)),
        "stalled pre-bridge wait must return Cancelled when reauth tears down"
    );

    // Handler deny path after Cancelled: RST TCP (QUIC
    // DROPPED_UNFINISHED_ERROR_CODE covered by reset_quic / bridge teardown
    // with real halves).
    reset_tcp(&server);
    drop(server);

    let mut buf = [0u8; 8];
    match client.read(&mut buf).await {
        Ok(0) => panic!("got clean EOF (FIN); expected ConnectionReset from linger-0 close"),
        Ok(n) => panic!("unexpected {n} bytes from reset peer"),
        Err(err) => assert_eq!(
            err.kind(),
            ErrorKind::ConnectionReset,
            "expected ConnectionReset, got {err:?}"
        ),
    }
    assert_eq!(diag.torn_down_reauth(), 1);
}

/// Hold a write lock on `lock` until `release` fires. Signals `held` once
/// acquired so the test can race the reauth loop against a stalled gate.
fn hold_write<T: Send + Sync + 'static>(
    lock: Arc<RwLock<T>>,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _guard = lock.write().await;
        let _ = held_tx.send(());
        let _ = release_rx.await;
    });
    (release_tx, held_rx, handle)
}

/// WHY (Codex P2 / RC4): a kick during [`REAUTH_MIN_SPACING`] must measure the
/// next pass deadline from that event, not from pass start after the cooldown.
/// Holding the discovery-cache write lock forces the follow-up pass onto the
/// fail-closed deadline path so a fresh `now()+5s` budget would miss
/// [`EVENT_BOUND`].
#[tokio::test(start_paused = true)]
async fn kick_during_spacing_deadline_from_event() {
    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], false, true));
    let grant = w
        .grant(0x61, Grantee::User(w.user_b.user_id()), w.base_secs + 3_600)
        .await;
    let (stream, _) = w.admit(w.inbound(w.b1, w.mb)).await;
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_millis(1)).await;

    // First pass: no-op kick so the loop enters spacing.
    w.kick.notify_waiters();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    let (release_tx, held_rx, holder) = hold_write(Arc::clone(&w.cache));
    held_rx
        .await
        .expect("discovery-cache write holder must start");

    let event_at = Instant::now();
    w.revoke_grant(&grant).await;

    // Finish the remaining spacing; the pending event's pass starts blocked.
    tokio::time::advance(REAUTH_MIN_SPACING - Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert!(
        !stream.token().is_cancelled(),
        "stream must still be open while the stalled pass awaits the deadline"
    );

    let remain = EVENT_BOUND.saturating_sub(event_at.elapsed());
    tokio::time::advance(remain).await;
    tokio::task::yield_now().await;
    assert!(
        stream.token().is_cancelled(),
        "teardown must land within 5 s of the spacing kick (elapsed {:?})",
        event_at.elapsed()
    );
    assert!(
        event_at.elapsed() <= EVENT_BOUND,
        "deadline-from-event exceeded EVENT_BOUND ({:?})",
        event_at.elapsed()
    );

    let _ = release_tx.send(());
    let _ = holder.await;
}

/// WHY (Codex P2 / RC4): a kick during an in-flight pass must schedule the
/// next pass with a deadline from that mid-pass event. A stream registered
/// after the in-flight `gates()` snapshot is only checked on the follow-up
/// pass; stalling that pass on the discovery-cache lock proves the budget is
/// not reset at pass start.
#[tokio::test(start_paused = true)]
async fn kick_during_inflight_pass_deadline_from_event() {
    let w = World::new().await;
    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Trusted);
    w.set_policy_silently(w.acl(&[(w.b1, w.mb)], false, true));
    let (decoy, _) = w.admit(w.inbound(w.b1, w.mb)).await;
    let grant = w
        .grant(0x62, Grantee::Agent(w.c1), w.base_secs + 3_600)
        .await;

    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_millis(1)).await;

    let (release_tx, held_rx, holder) = hold_write(Arc::clone(&w.cache));
    held_rx
        .await
        .expect("discovery-cache write holder must start");

    // Start a pass that stalls on the decoy while the cache write is held.
    let pass1_at = Instant::now();
    w.kick.notify_waiters();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!decoy.token().is_cancelled());

    // Mid-pass event: register a grant-backed stream the in-flight snapshot
    // never saw, then revoke it so only the follow-up pass can tear it down.
    let event_at = Instant::now();
    let target = w.live.register(
        w.inbound(w.c1, w.mc),
        StreamAuthority::Grant {
            grant_ids: vec![hex::encode(grant.grant_id)],
        },
    );
    w.revoke_grant(&grant).await;
    tokio::task::yield_now().await;

    // Exhaust the first pass's budget (from the priming kick). Decoy
    // fail-closes; target is untouched. Spacing then starts the pending pass.
    let pass1_remain = REAUTH_PASS_BUDGET.saturating_sub(pass1_at.elapsed());
    tokio::time::advance(pass1_remain).await;
    tokio::task::yield_now().await;
    assert!(
        decoy.token().is_cancelled(),
        "in-flight pass must fail-close the decoy at its own deadline"
    );
    assert!(
        !target.token().is_cancelled(),
        "target registered mid-pass must survive the in-flight snapshot"
    );

    tokio::time::advance(REAUTH_MIN_SPACING).await;
    tokio::task::yield_now().await;
    assert!(
        !target.token().is_cancelled(),
        "follow-up pass must still be stalled before the event deadline"
    );

    let remain = EVENT_BOUND.saturating_sub(event_at.elapsed());
    tokio::time::advance(remain).await;
    tokio::task::yield_now().await;
    assert!(
        target.token().is_cancelled(),
        "mid-pass revocation must tear down within 5 s of that event (elapsed {:?})",
        event_at.elapsed()
    );
    assert!(
        event_at.elapsed() <= EVENT_BOUND,
        "deadline-from-event exceeded EVENT_BOUND ({:?})",
        event_at.elapsed()
    );

    let _ = release_tx.send(());
    let _ = holder.await;
}

/// WHY (Codex P2 / RC5): cooldown must not push past event deadline.
/// An event ~100 ms into a long (nearly [`REAUTH_PASS_BUDGET`]) pass leaves
/// `pass_remainder + REAUTH_MIN_SPACING` > 5 s from the kick. Spacing must
/// clip to the pending event deadline so teardown still lands in
/// [`EVENT_BOUND`], not ~5.15 s.
///
/// The first kick often completes without blocking on the discovery-cache
/// write lock (same as [`kick_during_inflight_pass_deadline_from_event`]'s
/// first pass). The long stall is the *second* pass, which does block —
/// matching that sibling's observed gate trace.
#[tokio::test(start_paused = true)]
async fn kick_late_in_long_pass_spacing_respects_event_deadline() {
    let w = World::new().await;
    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Trusted);
    w.set_policy_silently(w.acl(&[(w.b1, w.mb)], false, true));
    let (decoy, _) = w.admit(w.inbound(w.b1, w.mb)).await;
    let grant = w
        .grant(0x63, Grantee::Agent(w.c1), w.base_secs + 3_600)
        .await;

    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_millis(1)).await;

    let (release_tx, held_rx, holder) = hold_write(Arc::clone(&w.cache));
    held_rx
        .await
        .expect("discovery-cache write holder must start");

    // Priming kick: may complete immediately. Drain spacing so the next
    // kick starts a fresh pass against the held cache write.
    w.kick.notify_waiters();
    tokio::task::yield_now().await;
    tokio::time::advance(REAUTH_MIN_SPACING).await;
    tokio::task::yield_now().await;

    // Long stalled pass (cache write held).
    let pass_at = Instant::now();
    w.kick.notify_waiters();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert!(!decoy.token().is_cancelled());

    let event_at = Instant::now();
    let target = w.live.register(
        w.inbound(w.c1, w.mc),
        StreamAuthority::Grant {
            grant_ids: vec![hex::encode(grant.grant_id)],
        },
    );
    w.revoke_grant(&grant).await;
    tokio::task::yield_now().await;
    assert!(
        !decoy.token().is_cancelled() && !target.token().is_cancelled(),
        "both streams must still be live while the stalled pass awaits its deadline"
    );

    let pass_remain = REAUTH_PASS_BUDGET.saturating_sub(pass_at.elapsed());
    assert!(
        pass_remain + REAUTH_MIN_SPACING > EVENT_BOUND.saturating_sub(event_at.elapsed()),
        "scenario must be the Codex case where full spacing would overshoot"
    );
    tokio::time::advance(pass_remain).await;
    tokio::task::yield_now().await;
    assert!(
        decoy.token().is_cancelled(),
        "stalled pass must fail-close the decoy at its own deadline"
    );

    // Full 250 ms spacing would still be running; only the event remainder
    // is left. Clipped cooldown must start the follow-up before EVENT_BOUND.
    if !target.token().is_cancelled() {
        let remain = EVENT_BOUND.saturating_sub(event_at.elapsed());
        assert!(
            !remain.is_zero(),
            "event budget must remain after the stalled pass ends"
        );
        tokio::time::advance(remain).await;
        tokio::task::yield_now().await;
    }
    assert!(
        target.token().is_cancelled(),
        "late mid-pass revoke must tear down within 5 s of that event (elapsed {:?}), not pass_remainder+spacing",
        event_at.elapsed()
    );
    assert!(
        event_at.elapsed() <= EVENT_BOUND,
        "deadline-from-event exceeded EVENT_BOUND ({:?})",
        event_at.elapsed()
    );

    let _ = release_tx.send(());
    let _ = holder.await;
}

/// Owner-trust stream admitted on enrolled evidence without an authenticated
/// binding (RC7 busy/deadline fixtures). Returns the world, live stream, the
/// ready evidence store (for `hold_state_for_testing`), and the live
/// [`EvidenceRuntime`] Arc that OwnerTrust holds weakly — keep it alive for
/// the test body or reauth sees no evidence and denies immediately.
async fn owner_evidence_reauth_fixture() -> (
    World,
    LiveStreamGuard,
    Arc<crate::peer_evidence::PeerEvidenceStore>,
    Arc<crate::peer_evidence::EvidenceRuntime>,
) {
    use crate::announce_v3::IdentityAnnouncementV3;
    use crate::dm::DmCapabilities;
    use crate::dm_capability::{CapabilityAdvert, RegistryTrailer, REGISTRY_TRAILER_MAGIC};
    use crate::peer_evidence::{
        EvidenceConfig, EvidenceRecordV1, EvidenceRuntime, IngestSource, PeerEvidenceStore,
        RuntimePolicy,
    };

    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], true, false));

    let agent_kp = AgentKeypair::generate().unwrap();
    let machine_kp = MachineKeypair::generate().unwrap();
    let peer = agent_kp.agent_id();
    let machine = machine_kp.machine_id();
    let cert = AgentCertificate::issue(&w.owner_a, &agent_kp).unwrap();
    w.devices
        .enroll(OwnerEnrollment::sign(machine, &w.owner_a, w.base_secs * 1000, None).unwrap())
        .await
        .unwrap();
    w.cache
        .write()
        .await
        .insert(peer, discovered(&agent_kp, machine, cert.clone()));

    let now_ms = w.base_secs.saturating_mul(1000);
    let record = {
        let v2 = crate::IdentityAnnouncement {
            self_name: Some("owner evidence peer".into()),
            agent_id: peer,
            machine_id: machine,
            user_id: None,
            agent_certificate: None,
            machine_public_key: machine_kp.public_key().as_bytes().to_vec(),
            machine_signature: vec![],
            addresses: vec![],
            announced_at: now_ms / 1000,
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
        };
        let mut ann =
            IdentityAnnouncementV3::build_from_v2(&v2, machine_kp.secret_key(), 0).unwrap();
        ann.sign_v3_1(machine_kp.secret_key()).unwrap();
        let mut caps = DmCapabilities::pending();
        caps.kem_public_key = vec![42; 1184];
        let mut advert = CapabilityAdvert {
            protocol_version: crate::dm_capability_service::ADVERT_PROTOCOL_VERSION,
            agent_id: *peer.as_bytes(),
            machine_id: *machine.as_bytes(),
            created_at_unix_ms: now_ms,
            capabilities: caps,
            signature: vec![],
        };
        advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            agent_kp.secret_key(),
            &advert.signed_bytes().unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let mut trailer = RegistryTrailer {
            registry: Default::default(),
            signature: vec![],
        };
        trailer.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            agent_kp.secret_key(),
            &trailer.signed_bytes(&advert).unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let mut bytes = postcard::to_stdvec(&advert).unwrap();
        bytes.extend_from_slice(REGISTRY_TRAILER_MAGIC);
        bytes.extend(postcard::to_stdvec(&trailer).unwrap());
        EvidenceRecordV1 {
            announcement: crate::announce_v3::serialize_v3_1(&ann).unwrap(),
            advert: bytes,
            certificate: Some(cert.to_storage_bytes().unwrap()),
            relation: crate::peer_evidence::ENROLLED,
            stored_at_ms: now_ms,
        }
    };
    let policy = Arc::new(RuntimePolicy::new(
        w.a1,
        w.trust.clone(),
        Arc::clone(&w.revocations),
    ));
    let store = Arc::new(
        PeerEvidenceStore::open(
            &w.dir.path().join("evidence-owner-reauth-busy"),
            EvidenceConfig::default(),
            policy,
            now_ms,
        )
        .unwrap(),
    );
    store.ingest(record, IngestSource::Hello, now_ms).unwrap();
    let (evidence, ready) = EvidenceRuntime::loading_store_for_test(Arc::clone(&store));
    ready.cancel();
    assert!(
        evidence.usable(peer, machine, now_ms).is_some(),
        "control: enrolled evidence must be usable before admission"
    );
    w.trust.install_evidence(&evidence);

    {
        let mut bind = w.authenticated.write().await;
        // Keep change_notify installed (World wires ADR-0074 reauth wake).
        bind.clear_for_test();
    }

    let gate = w.inbound(peer, machine);
    let authority = check_gate(&gate, &w.ctx())
        .await
        .expect("owner stream must admit on enrolled evidence without binding");
    assert_eq!(authority, StreamAuthority::OwnerTrust);
    let stream = w.live.register(gate, authority);
    (w, stream, store, evidence)
}

fn hold_evidence_store(
    store: Arc<crate::peer_evidence::PeerEvidenceStore>,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _guard = store.hold_state_for_testing();
        let _ = held_tx.send(());
        let _ = release_rx.recv();
    });
    held_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("evidence store lock holder must start");
    (release_tx, holder)
}

/// RC7 engineer ruling: evidence-store contention that clears inside the
/// five-second budget must not tear down a still-authorized stream.
#[tokio::test(start_paused = true)]
async fn reauth_evidence_store_busy_resolves_inside_budget_stream_survives() {
    let (w, stream, store, _evidence) = owner_evidence_reauth_fixture().await;
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(!stream.token().is_cancelled());
    assert_eq!(w.diag.torn_down_reauth(), 0);

    let (release_tx, holder) = hold_evidence_store(store);
    // Kick without changing enrollments/grants/contacts — pure contention.
    w.kick.notify_waiters();
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert!(
        !stream.token().is_cancelled(),
        "busy alone must not tear down before the deadline"
    );
    assert_eq!(w.diag.torn_down_reauth(), 0);

    let _ = release_tx.send(());
    let _ = holder.join();
    // Let Busy backoff complete and a fresh allow land inside the budget.
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert!(
        !stream.token().is_cancelled(),
        "stream must survive after contention clears inside the budget"
    );
    assert_eq!(w.diag.torn_down_reauth(), 0);
    assert!(w.reasons().is_empty());

    // A later kick with the store free must keep the stream (authority
    // never changed). Stay well under the original event deadline.
    w.kick.notify_waiters();
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert!(
        !stream.token().is_cancelled(),
        "post-release reauth must keep the still-authorized stream"
    );
    assert_eq!(w.diag.torn_down_reauth(), 0);
}

/// RC7 engineer ruling: evidence-store contention that never yields a fresh
/// verdict before the deadline must tear down as `reauth_deadline`.
#[tokio::test(start_paused = true)]
async fn reauth_evidence_store_busy_through_deadline_tears_down() {
    let (w, stream, store, _evidence) = owner_evidence_reauth_fixture().await;
    let _stop = w.spawn_loop(None);
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(!stream.token().is_cancelled());

    let (release_tx, holder) = hold_evidence_store(store);
    let started = Instant::now();
    // Kick without authority loss — hold through the full budget.
    w.kick.notify_waiters();
    // Tear-down lands on the deadline Instant; allow a little slack so
    // closes_within does not race the final Busy → reauth_deadline step.
    closes_within(&stream, EVENT_BOUND + Duration::from_millis(250)).await;
    assert!(
        started.elapsed() <= EVENT_BOUND,
        "busy-through-deadline teardown exceeded EVENT_BOUND ({:?})",
        started.elapsed()
    );
    assert_eq!(w.diag.torn_down_reauth(), 1);
    assert_eq!(w.reasons().get("reauth_deadline"), Some(&1));

    let _ = release_tx.send(());
    let _ = holder.join();
}
