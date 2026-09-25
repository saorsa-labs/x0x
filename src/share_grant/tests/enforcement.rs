//! ADR-0070 §5.3 enforcement matrix for share grants. Each negative case
//! would pass (and so fail its assertion) if the grant check it guards were
//! loosened or removed.

use super::*;
use crate::connect::{
    evaluate_connect_gate_for_principals, ConnectAcl, ConnectOwnerEntry, ConnectPolicy,
};
use crate::contacts::TrustLevel;
use crate::identity::{AgentCertificate, MachineId};
use crate::trust::TrustDecision;
use std::net::SocketAddr;

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn discovered(
    agent_kp: &AgentKeypair,
    machine: MachineId,
    cert: AgentCertificate,
) -> DiscoveredAgent {
    let agent_id = agent_kp.agent_id();
    DiscoveredAgent {
        self_name: None,
        agent_id,
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
        agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
        cert_digest: None,
    }
}

/// Owner A's daemons. User B (agent B1 on machine MB) and user C (agent C1
/// on machine MC) are strangers (no contacts) with authenticated bindings.
struct World {
    dir: tempfile::TempDir,
    owner_a: UserKeypair,
    a1: AgentId,
    a2: AgentId,
    user_b: UserKeypair,
    b1: AgentId,
    mb: MachineId,
    c1: AgentId,
    mc: MachineId,
    contacts: Arc<RwLock<ContactStore>>,
    cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>,
    revocations: Arc<RwLock<RevocationSet>>,
    bindings: AuthenticatedMachineBindings,
    move_state: Arc<RwLock<crate::key_move::MoveState>>,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner_a = UserKeypair::generate().unwrap();
        let user_b = UserKeypair::generate().unwrap();
        let user_c = UserKeypair::generate().unwrap();
        let a1 = AgentKeypair::generate().unwrap().agent_id();
        let a2 = AgentKeypair::generate().unwrap().agent_id();
        let b1_kp = AgentKeypair::generate().unwrap();
        let c1_kp = AgentKeypair::generate().unwrap();
        let (mb, mc) = (MachineId([0xB0; 32]), MachineId([0xC0; 32]));
        let bindings = AuthenticatedMachineBindings::default();
        let mut cache = HashMap::new();
        for (kp, user, machine) in [(&b1_kp, &user_b, mb), (&c1_kp, &user_c, mc)] {
            crate::dm_inbox::record_authenticated_machine_binding(
                &bindings,
                kp.agent_id(),
                machine,
                real_now(),
            )
            .await;
            let cert = AgentCertificate::issue(user, kp).unwrap();
            cache.insert(kp.agent_id(), discovered(kp, machine, cert));
        }
        let contacts = ContactStore::new(dir.path().join("contacts.json"));
        Self {
            dir,
            owner_a,
            a1,
            a2,
            b1: b1_kp.agent_id(),
            user_b,
            mb,
            c1: c1_kp.agent_id(),
            mc,
            contacts: Arc::new(RwLock::new(contacts)),
            cache: Arc::new(RwLock::new(cache)),
            revocations: Arc::new(RwLock::new(RevocationSet::new())),
            bindings,
            move_state: Arc::new(RwLock::new(crate::key_move::MoveState::default())),
        }
    }

    /// A grant from owner A to user B over A1.
    fn grant(&self, caps: Vec<ShareCap>, not_before: u64, expiry: u64) -> ShareGrant {
        ShareGrant::sign(
            &self.owner_a,
            [0x33; 32],
            Grantee::User(self.user_b.user_id()),
            vec![self.a1],
            caps,
            not_before,
            expiry,
        )
        .unwrap()
    }

    /// Owner-trust source of A's daemon hosting `local`, holding `grants`.
    async fn daemon(&self, local: AgentId, grants: &[ShareGrant]) -> OwnerTrust {
        let store = ShareGrantStore::in_memory(local, Some(self.owner_a.user_id()));
        for grant in grants {
            store.accept(grant.clone(), grant.not_before).await.unwrap();
        }
        let trust = OwnerTrust::new(Some(self.owner_a.user_id()), Arc::clone(&self.bindings));
        trust.install_share_grant_store(Arc::new(store));
        trust
    }

    async fn access(
        &self,
        trust: &OwnerTrust,
        agent: &AgentId,
        machine: &MachineId,
    ) -> GrantAccess {
        trust
            .grant_access(
                &self.contacts,
                &self.cache,
                &self.revocations,
                agent,
                machine,
            )
            .await
    }

    /// The real inbound stream gate (accept loop / datagram lane).
    async fn inbound(
        &self,
        trust: &OwnerTrust,
        policy: ConnectPolicy,
        machine: &MachineId,
    ) -> crate::error::NetworkResult<Vec<AgentId>> {
        let policy = Arc::new(std::sync::RwLock::new(Arc::new(policy)));
        crate::Agent::gate_peer_machine_inbound(
            &self.cache,
            &self.contacts,
            &self.revocations,
            &self.move_state,
            &policy,
            trust,
            machine,
        )
        .await
    }
}

fn grant_policy(targets: &[&str]) -> ConnectPolicy {
    ConnectPolicy::Enabled(ConnectAcl {
        loaded_from: std::path::PathBuf::from("/test/connect-acl.toml"),
        loaded_at_unix_ms: 0,
        allow: Vec::new(),
        owner_allow: Vec::new(),
        grant_allow: vec![ConnectOwnerEntry {
            description: Some("sharees".to_string()),
            targets: targets.iter().map(|t| t.parse().unwrap()).collect(),
        }],
    })
}

/// The forwarder's per-target decision, exactly as `forward.rs` derives it.
fn connect(
    access: &GrantAccess,
    policy: &ConnectPolicy,
    agent: &AgentId,
    machine: &MachineId,
    target: &str,
) -> Result<(), crate::connect::ConnectDenialReason> {
    let target: SocketAddr = target.parse().unwrap();
    let port_ok = access.allows_connect_port(target.port());
    evaluate_connect_gate_for_principals(
        true,
        Some(TrustDecision::Unknown.with_owner_trust(port_ok)),
        policy,
        agent,
        machine,
        false,
        port_ok,
        &target,
    )
}

fn dm_connect22() -> Vec<ShareCap> {
    vec![ShareCap::Dm, ShareCap::Connect { ports: vec![22] }]
}

/// ADR-0070 §5.3: owner A grants user B {Dm, Connect{22}} over A1. B's agent
/// DMs A1 and connects to :22 with NO contact entry; B is denied :80 even
/// though a grant entry lists it; user C is denied everything.
#[tokio::test]
async fn grantee_reaches_granted_agent_only_on_granted_caps_and_ports() {
    let w = World::new().await;
    let now = real_now();
    let trust = w
        .daemon(w.a1, &[w.grant(dm_connect22(), now - 60, now + 3_600)])
        .await;
    let policy = grant_policy(&["127.0.0.1:22", "127.0.0.1:80"]);

    let b = w.access(&trust, &w.b1, &w.mb).await;
    assert!(b.dm);
    assert_eq!(
        b.connect_ports.iter().copied().collect::<Vec<_>>(),
        vec![22]
    );
    assert!(!b.exec && !b.group_invite);
    assert!(connect(&b, &policy, &w.b1, &w.mb, "127.0.0.1:22").is_ok());
    assert!(connect(&b, &policy, &w.b1, &w.mb, "127.0.0.1:80").is_err());
    assert_eq!(
        w.inbound(&trust, policy.clone(), &w.mb).await.unwrap(),
        vec![w.b1]
    );
    let dm_gate = ShareGrantDmGate::new(trust.clone(), Arc::clone(&w.cache));
    assert!(
        dm_gate
            .dm_allowed(&w.contacts, &w.revocations, &w.b1, &w.mb)
            .await
    );

    let c = w.access(&trust, &w.c1, &w.mc).await;
    assert!(c.is_empty(), "user C holds no grant");
    assert!(connect(&c, &policy, &w.c1, &w.mc, "127.0.0.1:22").is_err());
    assert!(w.inbound(&trust, policy, &w.mc).await.is_err());
    assert!(
        !dm_gate
            .dm_allowed(&w.contacts, &w.revocations, &w.c1, &w.mc)
            .await
    );
}

/// WHY: a grant for agent A1 must not open agent A2 — the daemon hosting A2
/// (same owner, same grant held) confers nothing.
#[tokio::test]
async fn grant_for_one_agent_does_not_open_another() {
    let w = World::new().await;
    let now = real_now();
    let grant = w.grant(dm_connect22(), now - 60, now + 3_600);
    let a2_daemon = w.daemon(w.a2, &[grant]).await;
    assert!(w.access(&a2_daemon, &w.b1, &w.mb).await.is_empty());
    assert!(w
        .inbound(&a2_daemon, grant_policy(&["127.0.0.1:22"]), &w.mb)
        .await
        .is_err());
}

fn share_grant_revocation(signer: &UserKeypair, grant: &ShareGrant) -> Vec<u8> {
    let record = crate::revocation::RevocationRecord::sign(
        crate::revocation::RevokedSubject::ShareGrant(crate::revocation::ShareGrantRevocation {
            grant_id: grant.grant_id,
            owner: grant.owner,
            grant_expiry: grant.expiry,
        }),
        signer.public_key(),
        signer.secret_key(),
        real_now(),
        None,
    )
    .unwrap();
    bincode::serialize(&vec![record]).unwrap()
}

/// WHY: after revocation the grantee is denied again, at the next
/// evaluation and without a restart, when the record arrives over the v3
/// carrier; and the record is persisted.
#[tokio::test]
async fn v3_revocation_denies_the_grantee_promptly() {
    let w = World::new().await;
    let now = real_now();
    let grant = w.grant(dm_connect22(), now - 60, now + 3_600);
    let trust = w.daemon(w.a1, std::slice::from_ref(&grant)).await;
    let policy = grant_policy(&["127.0.0.1:22"]);
    assert!(w.inbound(&trust, policy.clone(), &w.mb).await.is_ok());

    let payload = share_grant_revocation(&w.owner_a, &grant);
    assert!(
        crate::ingest_share_grant_revocations(
            &w.revocations,
            Some(w.dir.path().to_path_buf()),
            &payload,
        )
        .await
    );
    assert!(w.access(&trust, &w.b1, &w.mb).await.is_empty());
    assert!(w.inbound(&trust, policy, &w.mb).await.is_err());
    assert!(w
        .dir
        .path()
        .join(crate::SHARE_GRANT_REVOCATIONS_FILE)
        .exists());
}

/// WHY: a v3 record signed by the grantee (not the owner) revokes nothing.
#[tokio::test]
async fn grantee_signed_revocation_is_rejected() {
    let w = World::new().await;
    let now = real_now();
    let grant = w.grant(dm_connect22(), now - 60, now + 3_600);
    let trust = w.daemon(w.a1, std::slice::from_ref(&grant)).await;
    let payload = share_grant_revocation(&w.user_b, &grant);
    assert!(
        !crate::ingest_share_grant_revocations(
            &w.revocations,
            Some(w.dir.path().to_path_buf()),
            &payload,
        )
        .await
    );
    assert!(w.access(&trust, &w.b1, &w.mb).await.dm);
}

/// WHY: expired and not-yet-valid grants evaluate as if absent.
#[tokio::test]
async fn expired_and_not_yet_valid_grants_are_ignored() {
    let w = World::new().await;
    let now = real_now();
    let expired = w
        .daemon(w.a1, &[w.grant(dm_connect22(), now - 7_200, now - 60)])
        .await;
    assert!(w.access(&expired, &w.b1, &w.mb).await.is_empty());
    let future = w
        .daemon(w.a1, &[w.grant(dm_connect22(), now + 3_600, now + 7_200)])
        .await;
    assert!(w.access(&future, &w.b1, &w.mb).await.is_empty());
    assert!(w
        .inbound(&future, grant_policy(&["127.0.0.1:22"]), &w.mb)
        .await
        .is_err());
}

/// WHY: explicit local denial wins — a Blocked grantee gets nothing.
#[tokio::test]
async fn blocked_grantee_gets_nothing() {
    let w = World::new().await;
    let now = real_now();
    let trust = w
        .daemon(w.a1, &[w.grant(dm_connect22(), now - 60, now + 3_600)])
        .await;
    w.contacts
        .write()
        .await
        .set_trust(&w.b1, TrustLevel::Blocked);
    assert!(w.access(&trust, &w.b1, &w.mb).await.is_empty());
    assert!(w
        .inbound(&trust, grant_policy(&["127.0.0.1:22"]), &w.mb)
        .await
        .is_err());
}

/// WHY: a grant never opens anything without an explicit rule. With no
/// `principal = "grant"` entry, or with connect disabled entirely (where the
/// identity gate would otherwise be the only boundary), a grant-only peer is
/// refused.
#[tokio::test]
async fn connect_grant_needs_an_explicit_grant_entry() {
    let w = World::new().await;
    let now = real_now();
    let trust = w
        .daemon(w.a1, &[w.grant(dm_connect22(), now - 60, now + 3_600)])
        .await;
    let owner_entry_only = ConnectPolicy::Enabled(ConnectAcl {
        loaded_from: std::path::PathBuf::from("/test/connect-acl.toml"),
        loaded_at_unix_ms: 0,
        allow: Vec::new(),
        owner_allow: vec![ConnectOwnerEntry {
            description: None,
            targets: vec!["127.0.0.1:22".parse().unwrap()],
        }],
        grant_allow: Vec::new(),
    });
    assert!(w
        .inbound(&trust, owner_entry_only.clone(), &w.mb)
        .await
        .is_err());
    let b = w.access(&trust, &w.b1, &w.mb).await;
    assert!(connect(&b, &owner_entry_only, &w.b1, &w.mb, "127.0.0.1:22").is_err());
    assert!(w
        .inbound(&trust, ConnectPolicy::default(), &w.mb)
        .await
        .is_err());
}

/// WHY: Exec is its own capability, and argv stays an exact allowlist.
#[tokio::test]
async fn exec_grant_matches_only_grant_entries_with_exact_argv() {
    let w = World::new().await;
    let now = real_now();
    let toml = "[exec]\nenabled = true\n[[exec.allow]]\nprincipal = \"grant\"\n\
                [[exec.allow.commands]]\nargv = [\"uptime\"]\n";
    let policy =
        crate::exec::acl::parse_exec_policy(std::path::Path::new("/tmp/x"), 0, toml).unwrap();
    let crate::exec::ExecPolicy::Enabled(acl) = policy else {
        unreachable!("the TOML above enables exec");
    };
    let uptime = vec!["uptime".to_string()];
    let rm = vec!["rm".to_string()];

    let dm_only = w
        .daemon(w.a1, &[w.grant(dm_connect22(), now - 60, now + 3_600)])
        .await;
    let access = w.access(&dm_only, &w.b1, &w.mb).await;
    assert!(!access.exec);
    assert!(!acl.has_entry_for_principals(&w.b1, &w.mb, false, access.exec));

    let exec = w
        .daemon(
            w.a1,
            &[w.grant(vec![ShareCap::Exec], now - 60, now + 3_600)],
        )
        .await;
    let access = w.access(&exec, &w.b1, &w.mb).await;
    assert!(access.exec);
    assert!(matches!(
        acl.match_command_for_principals(&w.b1, &w.mb, false, access.exec, &uptime),
        Some(crate::exec::acl::PrincipalMatch::Grant(_))
    ));
    assert!(acl
        .match_command_for_principals(&w.b1, &w.mb, false, access.exec, &rm)
        .is_none());
    let c = w.access(&exec, &w.c1, &w.mc).await;
    assert!(acl
        .match_command_for_principals(&w.c1, &w.mc, false, c.exec, &uptime)
        .is_none());
}

/// ADR-0070 §6: a GroupInvite grant never satisfies Home admission
/// (`GroupAdmission::OwnerCertified`), which requires the joiner's
/// certificate to chain to the Home owner — B's does not, grant or not.
#[tokio::test]
async fn group_invite_grant_does_not_admit_grantee_to_owner_home() {
    let w = World::new().await;
    let now = real_now();
    let trust = w
        .daemon(
            w.a1,
            &[w.grant(vec![ShareCap::GroupInvite], now - 60, now + 3_600)],
        )
        .await;
    assert!(w.access(&trust, &w.b1, &w.mb).await.group_invite);
    let b_cert = w
        .cache
        .read()
        .await
        .get(&w.b1)
        .and_then(|e| e.agent_certificate.clone())
        .unwrap();
    assert!(crate::groups::owner_cert::verify_cert_against_owner(
        &w.owner_a.user_id(),
        &hex::encode(w.b1.as_bytes()),
        &b_cert,
        false,
        now,
    )
    .is_err());
}

/// WHY (decision 1): an expired grant is denied regardless of revocation —
/// which is what makes it safe to garbage-collect the revocation once the
/// grant is dead (`expiry + slack`).
#[tokio::test]
async fn expired_grant_is_denied_after_its_revocation_is_collected() {
    let w = World::new().await;
    let now = real_now();
    let grant = w.grant(dm_connect22(), now - 60, now + 3_600);
    let store = ShareGrantStore::in_memory(w.a1, Some(w.owner_a.user_id()));
    store.accept(grant.clone(), now).await.unwrap();
    let eval = |at: u64| {
        evaluate_grant_access(
            &store,
            &w.bindings,
            &w.cache,
            &w.revocations,
            &w.b1,
            &w.mb,
            at,
        )
    };
    assert!(eval(now).await.dm, "control: live grant");

    let payload = share_grant_revocation(&w.owner_a, &grant);
    assert!(
        crate::ingest_share_grant_revocations(
            &w.revocations,
            Some(w.dir.path().to_path_buf()),
            &payload,
        )
        .await
    );
    assert!(eval(now).await.is_empty(), "revoked while live");

    let horizon = grant.expiry + crate::revocation::SHARE_GRANT_REVOCATION_GC_SLACK_SECS;
    let collected = w
        .revocations
        .write()
        .await
        .expire_records_older_than(90 * 24 * 3600, horizon);
    assert_eq!(collected, 1, "revocation collected at expiry + slack");
    assert!(!w
        .revocations
        .read()
        .await
        .is_share_grant_revoked(&grant.grant_id, &grant.owner));
    assert!(
        eval(horizon).await.is_empty(),
        "the expired grant stays denied without its revocation"
    );
}

/// #898: a raw Direct payload from machine MX that claims an agent is
/// unverified, and must neither rebind the agent nor gain its grant or
/// owner trust.
///
/// The fixture makes owner trust LIVE (not vacuous): OWN is the owner's own
/// agent with a valid owner certificate on enrolled machine M_OWN, and MX is
/// ALSO an enrolled owner machine — so for OWN on MX, the only missing piece
/// is the agent↔machine pairing, which is exactly what the spoof forges.
///
/// Which assertion catches what (hand mutation check; test binaries are not
/// run on the authoring host):
/// - re-allowing `mark_connected` for an unverified claim (the #898 bug)
///   fails the `dm.get_machine_id(..) == Some(real)` assertion below;
/// - additionally dropping slice 1's authenticated-binding pairing rule
///   (pairing via the discovery cache, which the pre-fix `connect_to_agent`
///   rewrote from the DirectMessaging entry) fails the owner-trust and grant
///   assertions for MX.
#[tokio::test]
async fn raw_direct_spoof_gains_neither_grant_nor_owner_trust() {
    let w = World::new().await;
    let now = real_now();
    let trust = w
        .daemon(w.a1, &[w.grant(dm_connect22(), now - 60, now + 3_600)])
        .await;
    let own_kp = AgentKeypair::generate().unwrap();
    let own = own_kp.agent_id();
    let m_own = MachineId([0xD0; 32]);
    let mx = MachineId([0x99; 32]);

    let devices = crate::owner_sync::OwnerSyncStore::load(w.dir.path())
        .await
        .unwrap();
    for machine in [m_own, mx] {
        devices
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(
                    machine,
                    &w.owner_a,
                    now.saturating_mul(1000),
                    None,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }
    trust.install_device_store(Arc::new(devices));
    crate::dm_inbox::record_authenticated_machine_binding(&w.bindings, own, m_own, now).await;
    let own_cert = AgentCertificate::issue(&w.owner_a, &own_kp).unwrap();
    w.cache
        .write()
        .await
        .insert(own, discovered(&own_kp, m_own, own_cert));

    // Positive controls: owner trust and the grant are live on the REAL
    // machines, so the negatives below are not vacuous.
    assert!(
        trust
            .is_owner_trusted(&w.cache, &w.revocations, &own, &m_own)
            .await
    );
    assert!(w.access(&trust, &w.b1, &w.mb).await.dm);

    // The spoof: MX sends raw Direct bytes claiming OWN and B1; the
    // listener computes verified=false for both.
    let dm = crate::direct::DirectMessaging::new();
    for (agent, real) in [(own, m_own), (w.b1, w.mb)] {
        assert!(dm.mark_raw_direct_sender_connected(agent, real, true).await);
        assert!(!dm.mark_raw_direct_sender_connected(agent, mx, false).await);
        // Catches the #898 mutation (unverified claim marks connected).
        assert_eq!(dm.get_machine_id(&agent).await, Some(real));
    }

    // Propagate whatever DirectMessaging now says into the discovery cache,
    // as the pre-fix `connect_to_agent` did — then force MX anyway (worst
    // case: the cache is attacker-steered).
    for agent in [own, w.b1] {
        if let Some(entry) = w.cache.write().await.get_mut(&agent) {
            entry.machine_id = mx;
        }
    }
    assert!(
        !trust
            .is_owner_trusted(&w.cache, &w.revocations, &own, &mx)
            .await,
        "enrolled MX + valid owner cert must not owner-trust OWN without its binding"
    );
    assert!(w.access(&trust, &w.b1, &mx).await.is_empty());
    assert!(w
        .inbound(&trust, grant_policy(&["127.0.0.1:22"]), &mx)
        .await
        .is_err());
    // The real pairing is unaffected by the rewritten cache: owner trust
    // pairs only through the authenticated binding.
    assert!(
        trust
            .is_owner_trusted(&w.cache, &w.revocations, &own, &m_own)
            .await
    );
}
