//! ADR-0074 §4 intent tests: live forward streams close within 5 s of a
//! revocation or trust loss and within 35 s of a grant's expiry, and only
//! the streams whose authority is gone.
//!
//! Time is paused tokio time. The re-check clock is derived from it, so a
//! grant's expiry is crossed deterministically. Streams are in-memory
//! registrations (plus `tokio::io::duplex` for the bridge); nothing binds a
//! socket.

use super::*;
use crate::connect::{ConnectAcl, ConnectAllowEntry, ConnectOwnerEntry};
use crate::contacts::{ContactStore, TrustLevel};
use crate::dm_inbox::AuthenticatedMachineBindings;
use crate::identity::{AgentCertificate, AgentKeypair, UserKeypair};
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
        let bindings = AuthenticatedMachineBindings::default();
        let mut cache = HashMap::new();
        for (kp, user, machine) in [
            (&b1_kp, &user_b, mb),
            (&c1_kp, &user_c, mc),
            (&o1_kp, &owner_a, mo),
        ] {
            crate::dm_inbox::record_authenticated_machine_binding(
                &bindings,
                kp.agent_id(),
                machine,
                base_secs,
            )
            .await;
            let cert = AgentCertificate::issue(user, kp).unwrap();
            cache.insert(kp.agent_id(), discovered(kp, machine, cert));
        }

        // Every contact-store and revocation-set change wakes the loop, as
        // the agent wires them.
        let kick = Arc::new(Notify::new());
        let mut contacts = ContactStore::new(dir.path().join("contacts.json"));
        contacts.set_change_notify(Arc::clone(&kick));
        let mut revocations = RevocationSet::new();
        revocations.set_change_notify(Arc::clone(&kick));

        let devices = OwnerSyncStore::load(dir.path()).await.unwrap();
        devices
            .enroll(OwnerEnrollment::sign(mo, &owner_a, base_secs * 1000, None).unwrap())
            .await
            .unwrap();
        let grants = Arc::new(ShareGrantStore::in_memory(a1, Some(owner_a.user_id())));
        let trust = OwnerTrust::new(Some(owner_a.user_id()), bindings);
        trust.install_device_store(Arc::new(devices));
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
            own_machine_id: MachineId([0xAA; 32]),
            clock: self.clock(),
        }
    }

    /// Install `policy` WITHOUT waking the loop (an unsignalled change: only
    /// the sweep can see it).
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

    fn spawn_loop(&self) -> CancellationToken {
        let stop = CancellationToken::new();
        spawn_reauth_loop(
            Arc::clone(&self.live),
            self.ctx(),
            Arc::clone(&self.kick),
            stop.clone(),
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
    let _stop = w.spawn_loop();

    // Nothing changed: sweeps keep it open.
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!stream.token().is_cancelled());

    w.revoke_grant(&grant).await;
    let took = closes_within(&stream, EVENT_BOUND).await;
    assert!(took < EVENT_BOUND, "closed after {took:?}");
    assert_eq!(w.diag.torn_down_reauth(), 1);
    assert_eq!(w.reasons().get("trust_rejected"), Some(&1));
    assert_eq!(w.live.len(), 0, "a torn-down stream leaves the registry");
}

/// WHY: a contact downgrade to `Blocked` must close the peer's live forward
/// within 5 s, and through the event path (the contact-store change wakes
/// the loop) rather than waiting for a sweep.
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
    let _stop = w.spawn_loop();
    // Half a sweep after the loop's first pass: the next sweep is 1.5 s away.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!stream.token().is_cancelled());

    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Blocked);
    let took = closes_within(&stream, EVENT_BOUND).await;
    assert!(
        took < Duration::from_secs(1),
        "the event path, not the next sweep, closed it (took {took:?})"
    );
    assert_eq!(w.reasons().get("trust_rejected"), Some(&1));
}

/// WHY (Q5): a grant's expiry must close its forward within 35 s — and not
/// before the expiry: the stream is authorized right up to it.
#[tokio::test(start_paused = true)]
async fn grant_expiry_closes_within_35s_and_not_before() {
    let w = World::new().await;
    w.set_policy_silently(w.acl(&[], false, true));
    let expiry = w.base_secs + 100;
    w.grant(0x22, Grantee::User(w.user_b.user_id()), expiry)
        .await;
    let (stream, _) = w.admit(w.inbound(w.b1, w.mb)).await;
    let _stop = w.spawn_loop();

    // One second before expiry, after ~50 sweeps: still open.
    tokio::time::sleep(Duration::from_secs(99)).await;
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
    let _stop = w.spawn_loop();

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

/// WHY: an ACL change that drops a stream's entry must close it within
/// 5 s. The policy is swapped here WITHOUT any event, so this also proves
/// the sweep backstop alone keeps the bound.
#[tokio::test(start_paused = true)]
async fn acl_change_closes_a_stream_no_longer_listed() {
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
    let _stop = w.spawn_loop();
    tokio::time::sleep(Duration::from_secs(5)).await;

    w.set_policy_silently(w.acl(&[(w.c1, w.mc)], false, false));
    let took = closes_within(&b_stream, EVENT_BOUND).await;
    assert!(took <= REAUTH_SWEEP_INTERVAL + REAUTH_MIN_SPACING);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(
        !c_stream.token().is_cancelled(),
        "the still-listed stream closed"
    );
    assert_eq!(w.reasons().get("agent_machine_not_in_acl"), Some(&1));
}

/// WHY (§4 "both ends enforce"): the opener also closes its side once its
/// peer is blocked.
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
    let _stop = w.spawn_loop();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!stream.token().is_cancelled());

    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Blocked);
    closes_within(&stream, EVENT_BOUND).await;
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
    assert_eq!(reauth_pass(&w.live, &w.ctx()).await, 0);
    assert_eq!(w.diag.torn_down_reauth(), 0);
}
