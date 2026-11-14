//! #1177 exit test (A12): sharing an agent team with another person is one
//! owner-signed `ShareGrant`. Alice (one owner key, two agents a1 and a2)
//! signs one grant to Bob as a whole human (`Grantee::User`), naming both
//! agents, with the `Dm` and `GroupInvite` capabilities. Bob's agent is
//! admitted by both of Alice's agents; Carol's agent, and Bob's agent
//! before the grant, are not. Alice revokes the grant on a1: a1 refuses
//! Bob at once, and a2 refuses Bob once the `x0x.revocation.v3` gossip
//! reaches it.
//!
//! The assertions read `Agent::share_grant_access`, the gate that the DM
//! inbox (ADR-0070 §2, `ShareGrantDmGate::dm_allowed`) and the group-invite
//! path consult. The test is `#[ignore]`; the CI tailnet job runs it with
//! `X0X_REQUIRE_NETWORK_TESTS=1`. A refused UDP bind fails the test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[path = "common/network_gate.rs"]
mod network_gate;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use x0x::identity::UserKeypair;
use x0x::network::NetworkConfig;
use x0x::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
use x0x::DiscoveredAgent;

/// The revoker refuses at once; the bound is share_grant_connect's.
const REVOKER_BOUND: Duration = Duration::from_secs(5);
/// A consenting announce reaches the team agents.
const ADMIT_BOUND: Duration = Duration::from_secs(15);
/// The other team agent learns the revocation over gossip.
const GOSSIP_BOUND: Duration = Duration::from_secs(30);

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

async fn build_agent(dir: &TempDir, name: &str, user: UserKeypair) -> Arc<x0x::Agent> {
    network_gate::init_stream_tracing();
    let built = x0x::Agent::builder()
        // Every store (revocations included) lives in this test's temp dir.
        .with_identity_dir(dir.path().join(name))
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_agent_cert_path(dir.path().join(format!("{name}-agent.cert")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config())
        .with_user_key(user)
        .build()
        .await;
    match built {
        Ok(agent) => Arc::new(agent),
        Err(e) if network_gate::skip_on_refused_network(&e) => {
            panic!("network setup refused; share_grant_team does not skip: {e}");
        }
        Err(e) => panic!("agent build failed: {e}"),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn normalize_loopback(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )
    } else {
        addr
    }
}

/// A discovery entry that carries the agent's owner certificate: a
/// `Grantee::User` grant needs it to name the requester's human.
async fn beacon(agent: &x0x::Agent) -> DiscoveredAgent {
    let addr = normalize_loopback(agent.network().unwrap().bound_addr().await.unwrap());
    let now = now_secs();
    DiscoveredAgent {
        self_name: None,
        // The digest a consenting announce commits to: a later announce
        // with this digest keeps the cached certificate.
        cert_digest: Some(x0x::announce_v3::cert_digest(
            &agent.user_id(),
            &agent.agent_certificate().cloned(),
        )),
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: agent.user_id(),
        addresses: vec![addr],
        announced_at: now,
        last_seen: now,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: agent.agent_certificate().cloned(),
        agent_public_key: Vec::new(),
    }
}

/// Connect `x` to `y` over loopback, and give each the other's discovery
/// entry and verified machine binding. No contact is marked trusted:
/// admission must come from the grant alone.
async fn link(x: &x0x::Agent, y: &x0x::Agent) {
    let xn = x.network().unwrap().clone();
    let yn = y.network().unwrap().clone();
    xn.connect_addr(normalize_loopback(yn.bound_addr().await.unwrap()))
        .await
        .unwrap();
    let (xp, yp) = (
        ant_quic::PeerId(x.machine_id().0),
        ant_quic::PeerId(y.machine_id().0),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if xn.is_connected(&yp).await && yn.is_connected(&xp).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(xn.is_connected(&yp).await, "link up");
    x.insert_discovered_agent_for_testing(beacon(y).await).await;
    y.insert_discovered_agent_for_testing(beacon(x).await).await;
    x.record_authenticated_machine_binding_for_testing(y.agent_id(), y.machine_id())
        .await;
    y.record_authenticated_machine_binding_for_testing(x.agent_id(), x.machine_id())
        .await;
}

/// `(dm, group_invite)` that `holder` grants `requester`.
async fn access(holder: &x0x::Agent, requester: &x0x::Agent) -> (bool, bool) {
    let a = holder
        .share_grant_access(&requester.agent_id(), &requester.machine_id())
        .await;
    (a.dm, a.group_invite)
}

/// Whether `holder` admits `requester` for DMs and group invites within
/// `bound` (the consenting announce must reach it first).
async fn admitted_within(holder: &x0x::Agent, requester: &x0x::Agent, bound: Duration) -> bool {
    let deadline = std::time::Instant::now() + bound;
    loop {
        if access(holder, requester).await == (true, true) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether `holder` refuses `requester` within `bound`.
async fn refused_within(holder: &x0x::Agent, requester: &x0x::Agent, bound: Duration) -> bool {
    refused_by(holder, requester, std::time::Instant::now() + bound).await
}

/// Whether `holder` refuses `requester` at or before `deadline`. A refusal
/// first seen after the deadline is a failure, even if it is seen on the
/// first check (a revoke call that itself ran past the deadline).
async fn refused_by(
    holder: &x0x::Agent,
    requester: &x0x::Agent,
    deadline: std::time::Instant,
) -> bool {
    loop {
        if access(holder, requester).await == (false, false) {
            return std::time::Instant::now() <= deadline;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "four-agent loopback ShareGrant team; binds UDP. Integration tailnet job."]
async fn one_grant_shares_a_two_agent_team_with_a_human_and_revokes() {
    let dir = TempDir::new().unwrap();
    let alice_seed: [u8; 32] = rand::random();
    let alice = UserKeypair::from_seed(&alice_seed).unwrap();
    let a1 = build_agent(&dir, "a1", UserKeypair::from_seed(&alice_seed).unwrap()).await;
    let a2 = build_agent(&dir, "a2", UserKeypair::from_seed(&alice_seed).unwrap()).await;
    let bob = build_agent(&dir, "bob", UserKeypair::generate().unwrap()).await;
    let carol = build_agent(&dir, "carol", UserKeypair::generate().unwrap()).await;
    for agent in [&a1, &a2, &bob, &carol] {
        agent.join_network().await.unwrap();
    }
    // Bob and Carol disclose their human identity, as a person who wants
    // to be reached by user grants does: their announces then carry the
    // owner certificate that a `Grantee::User` grant reads. Without this,
    // a later plain announce replaces the discovery entry and drops it.
    for human in [&bob, &carol] {
        human
            .announce_identity(true, true)
            .await
            .expect("announce with consent");
    }
    link(&a1, &a2).await;
    for holder in [&a1, &a2] {
        link(holder, &bob).await;
        link(holder, &carol).await;
    }
    let bob_user = bob.user_id().expect("bob is a human");
    assert!(
        bob.agent_certificate().is_some(),
        "bob's agent is certified"
    );

    // Before the grant, nobody is admitted.
    let store_for = |agent: &Arc<x0x::Agent>| {
        Arc::new(ShareGrantStore::in_memory(
            agent.agent_id(),
            Some(alice.user_id()),
        ))
    };
    let stores = [store_for(&a1), store_for(&a2)];
    a1.install_share_grant_store(Arc::clone(&stores[0]));
    a2.install_share_grant_store(Arc::clone(&stores[1]));
    for holder in [&a1, &a2] {
        assert_eq!(access(holder, &bob).await, (false, false), "no grant yet");
    }

    // One grant: Alice's two agents, to Bob as a human, Dm + GroupInvite.
    let now = now_secs();
    let grant = ShareGrant::sign(
        &alice,
        rand::random(),
        Grantee::User(bob_user),
        vec![a1.agent_id(), a2.agent_id()],
        vec![ShareCap::Dm, ShareCap::GroupInvite],
        now.saturating_sub(60),
        now + 3_600,
    )
    .expect("sign grant");
    for store in &stores {
        store.accept(grant.clone(), now).await.expect("store grant");
    }
    for holder in [&a1, &a2] {
        let admitted = admitted_within(holder, &bob, ADMIT_BOUND).await;
        let cached_cert = holder
            .discovered_agent_for_testing(&bob.agent_id())
            .await
            .is_some_and(|entry| entry.agent_certificate.is_some());
        assert!(
            admitted,
            "the grant admits Bob's agent for DMs and group invites \
             (Bob's certificate cached: {cached_cert})"
        );
        assert_eq!(
            access(holder, &carol).await,
            (false, false),
            "the grant names Bob, not another human"
        );
    }

    // Alice revokes on a1.
    let armed = std::time::Instant::now();
    a1.revoke_share_grant(grant.grant_id, Some("team share ended".into()))
        .await
        .expect("revoke grant");
    assert!(
        refused_by(&a1, &bob, armed + REVOKER_BOUND).await,
        "the revoking agent refuses Bob within {REVOKER_BOUND:?} of the revoke call \
         (took {:?})",
        armed.elapsed()
    );
    assert!(
        refused_within(&a2, &bob, GOSSIP_BOUND).await,
        "the other team agent refuses Bob once the revocation gossip arrives"
    );
    assert!(
        a2.revocation_set()
            .read()
            .await
            .is_share_grant_revoked(&grant.grant_id, &alice.user_id()),
        "a2 refuses because it holds the revocation"
    );

    for agent in [&a1, &a2, &bob, &carol] {
        agent.shutdown().await;
    }
}
