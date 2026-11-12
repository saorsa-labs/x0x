#![cfg(test)]
//! #1107 real-path owner-sync tests: an enrolled owner machine whose agent
//! the peer already knows, but only anonymously (no user ID, no
//! certificate). This is the state after a restart without consent: the
//! device announces with no user identity, so the peer holds a known agent
//! with no trust. `SyncV1` must still run in both directions on the
//! enrollment and the mutual owner-key proof (A03, amendment of
//! 12 Nov 2026), and must still refuse a revoked agent and an expired
//! cached certificate.
//!
//! The rig is the real stack: two `Agent`s on loopback QUIC, the real
//! `SyncV1` acceptor, the shared stream gate, the enrollment handoff and the
//! owner-key proof. Only the discovery entries are seeded, because
//! gossip announces are not running in this fixture.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::tests::{install_loopback_socket_boundary, live_owner_device};
use super::*;

const SEED: [u8; 32] = [0x07; 32];

struct Device {
    agent: Arc<crate::Agent>,
    sync: Arc<OwnerSyncService>,
}

async fn loopback_addr(agent: &crate::Agent) -> SocketAddr {
    let addr = agent
        .network()
        .expect("network")
        .bound_addr()
        .await
        .expect("bound address");
    if addr.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], addr.port()))
    } else {
        addr
    }
}

async fn remember_peer(agent: &crate::Agent, peer: MachineId, addr: SocketAddr) {
    agent
        .network()
        .and_then(|network| network.bootstrap_cache())
        .expect("bootstrap cache")
        .add_from_connection(ant_quic::PeerId(peer.0), vec![addr], None)
        .await;
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// What `peer` looks like to a device that heard an announce with no user
/// identity: the agent and machine IDs and an address, nothing else.
fn anonymous_card(
    peer: &crate::Agent,
    addr: SocketAddr,
    cert_not_after: Option<u64>,
) -> crate::DiscoveredAgent {
    let now = now_secs();
    crate::DiscoveredAgent {
        self_name: None,
        cert_digest: None,
        agent_id: peer.agent_id(),
        machine_id: peer.machine_id(),
        user_id: None,
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
        cert_not_after,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

async fn enroll(device: &Device, peer: MachineId) {
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    device
        .sync
        .store()
        .enroll(OwnerEnrollment::sign(peer, &owner, 1_000, None).expect("enrollment"))
        .await
        .expect("enroll");
}

async fn mint_name(device: &Device, display: &str) {
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let machine = device.agent.machine_id();
    device
        .sync
        .store()
        .mint(
            SyncKind::MachineNames,
            &hex::encode(machine.0),
            &SyncValue::MachineNames {
                display_name: Some(display.to_string()),
                machine_name: None,
            },
            &owner,
            machine,
        )
        .await
        .expect("mint name");
}

async fn has_name(device: &Device, display: &str) -> bool {
    device
        .sync
        .store()
        .records_snapshot()
        .await
        .iter()
        .any(|record| {
            matches!(
                &record.value,
                SyncValue::MachineNames { display_name: Some(name), .. } if name == display
            )
        })
}

/// Stop a device completely. `Agent::drop` only aborts the heartbeat and the
/// discovery reaper; the tracked stream-accept task keeps the endpoint alive,
/// so a plain drop would run the restarted device beside the old one. This
/// shuts the node down, then asserts the old endpoint is gone: it reports no
/// node status, and the peer holds no connection to its machine.
async fn shut_down_fully(device: Device, peer: &Device, machine: crate::owner_sync::MachineId) {
    let Device { agent, sync } = device;
    drop(sync);
    agent.try_shutdown().await.expect("old device shuts down");
    let network = agent.network().expect("old network");
    assert!(
        network.node_status().await.is_none(),
        "the old endpoint must be gone before the restart"
    );
    let peer_network = peer.agent.network().expect("peer network");
    let old = ant_quic::PeerId(machine.0);
    let mut connected = true;
    for _ in 0..50 {
        connected = peer_network.is_connected(&old).await;
        if !connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !connected,
        "the peer still holds a live connection to the old device"
    );
    drop(agent);
}

/// Alice stays up. Bob is enrolled, restarts cold with no consent (same key
/// files, same sync store, empty caches), and both know the other's agent
/// anonymously. Every cached entry for the other side has no certificate.
async fn rig() -> (tempfile::TempDir, Device, Device) {
    install_loopback_socket_boundary();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (alice_agent, alice_sync) = live_owner_device(dir.path(), "alice", SEED).await;
    let alice = Device {
        agent: alice_agent,
        sync: alice_sync,
    };
    let (bob_agent, bob_sync) = live_owner_device(dir.path(), "bob", SEED).await;
    let bob = Device {
        agent: bob_agent,
        sync: bob_sync,
    };
    enroll(&alice, bob.agent.machine_id()).await;
    enroll(&bob, alice.agent.machine_id()).await;
    // Alice heard Bob's anonymous announce before he went down.
    let old_bob_addr = loopback_addr(&bob.agent).await;
    alice
        .agent
        .insert_discovered_agent_for_testing(anonymous_card(&bob.agent, old_bob_addr, None))
        .await;
    let (bob_agent_id, bob_machine) = (bob.agent.agent_id(), bob.agent.machine_id());

    // THE RESTART: a fresh process-equivalent on the same files.
    shut_down_fully(bob, &alice, bob_machine).await;
    let bob_old = alice
        .agent
        .discovered_agent_for_testing(&bob_agent_id)
        .await
        .expect("alice still knows bob");
    assert!(
        bob_old.agent_certificate.is_none() && bob_old.user_id.is_none(),
        "alice knows bob only anonymously"
    );
    let (bob_agent, bob_sync) = live_owner_device(dir.path(), "bob", SEED).await;
    assert_eq!(
        bob_agent.agent_id(),
        bob_agent_id,
        "same agent after restart"
    );
    assert_eq!(
        bob_agent.machine_id(),
        bob_machine,
        "same machine after restart"
    );
    let bob = Device {
        agent: bob_agent,
        sync: bob_sync,
    };
    assert!(
        bob.sync
            .store()
            .is_enrolled(
                &alice.agent.machine_id(),
                &UserKeypair::from_seed(&SEED).expect("owner").user_id()
            )
            .await,
        "the enrollment survived the restart"
    );

    // Bob's new address; both sides then hold the other's anonymous card.
    let alice_addr = loopback_addr(&alice.agent).await;
    let bob_addr = loopback_addr(&bob.agent).await;
    remember_peer(&alice.agent, bob.agent.machine_id(), bob_addr).await;
    remember_peer(&bob.agent, alice.agent.machine_id(), alice_addr).await;
    alice
        .agent
        .insert_discovered_agent_for_testing(anonymous_card(&bob.agent, bob_addr, None))
        .await;
    bob.agent
        .insert_discovered_agent_for_testing(anonymous_card(&alice.agent, alice_addr, None))
        .await;
    (dir, alice, bob)
}

async fn dial(from: &Device, to: &Device) -> Result<SessionSummary, (&'static str, String)> {
    tokio::time::timeout(
        Duration::from_secs(30),
        from.sync.dial_and_sync(&to.agent.machine_id()),
    )
    .await
    .unwrap_or_else(|_| Err(("timeout", "no answer within 30 s".to_string())))
}

/// A refusal must come fast, so a dial timeout cannot satisfy a test.
const REFUSAL_BOUND: Duration = Duration::from_secs(10);

/// A refused dial as the dialer sees it.
struct Refusal {
    class: &'static str,
    message: String,
    elapsed: Duration,
}

/// Dial `to` from `from`; `None` means the session succeeded.
async fn dial_refusal(from: &Device, to: &Device) -> Option<Refusal> {
    let started = Instant::now();
    let result = dial(from, to).await;
    let elapsed = started.elapsed();
    result.err().map(|(class, message)| Refusal {
        class,
        message,
        elapsed,
    })
}

/// The shared inbound gate decision on `receiver` for `peer`'s machine, as
/// the acceptor runs it. The dialer of an inbound stream sees only a reset,
/// so the tests read the reason here, on the receiver side.
async fn inbound_gate_error(
    receiver: &Device,
    peer: &Device,
) -> Option<crate::error::NetworkError> {
    let agent = &receiver.agent;
    crate::Agent::gate_peer_machine_inbound(
        &agent.identity_discovery_cache,
        &agent.contact_store,
        &agent.revocation_set,
        &agent.move_state,
        &agent.connect_policy,
        &agent.owner_trust,
        &peer.agent.machine_id(),
    )
    .await
    .err()
}

/// Both directions were refused, quickly,
/// and Alice's own outbound gate naming `outbound_prefix`.
fn assert_refused(
    bob_to_alice: Option<Refusal>,
    alice_to_bob: Option<Refusal>,
    outbound_prefix: &str,
) {
    // bob→alice: the stream is reset, so Bob sees no reason; it is still a
    // fast refusal and not the 30 s dial timeout.
    let refused = bob_to_alice.expect("bob→alice must be refused");
    assert!(
        refused.class != "timeout" && refused.elapsed < REFUSAL_BOUND,
        "bob→alice refusal is slow or a timeout: {} after {:?}: {}",
        refused.class,
        refused.elapsed,
        refused.message
    );
    // alice→bob: refused at Alice's own outbound gate, with the reason.
    let refused = alice_to_bob.expect("alice→bob must be refused");
    assert!(
        refused.class == "open_stream"
            && refused.message.starts_with(outbound_prefix)
            && refused.elapsed < REFUSAL_BOUND,
        "alice→bob must be refused with `{outbound_prefix}`, got {} after {:?}: {}",
        refused.class,
        refused.elapsed,
        refused.message
    );
}

async fn shutdown(alice: Device, bob: Device) {
    alice.agent.shutdown().await;
    bob.agent.shutdown().await;
}

/// B restarted with no consent; A still knows B's agent anonymously (and B
/// has heard A's anonymous announce). Each side minted a record. Owner sync
/// completes in both directions within 30 s, and neither cache entry gained
/// a certificate on the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_sync_completes_both_ways_when_the_peers_agent_is_known_only_anonymously() {
    let (_dir, alice, bob) = rig().await;
    mint_name(&alice, "alice-era").await;
    mint_name(&bob, "bob-era").await;

    let started = Instant::now();
    let bob_to_alice = dial(&bob, &alice).await;
    let alice_to_bob = dial(&alice, &bob).await;
    let elapsed = started.elapsed();

    let alice_view = alice
        .agent
        .discovered_agent_for_testing(&bob.agent.agent_id())
        .await
        .expect("alice's entry for bob");
    let bob_view = bob
        .agent
        .discovered_agent_for_testing(&alice.agent.agent_id())
        .await
        .expect("bob's entry for alice");
    let results = (
        bob_to_alice.is_ok(),
        alice_to_bob.is_ok(),
        has_name(&alice, "bob-era").await,
        has_name(&bob, "alice-era").await,
        alice_view.agent_certificate.is_none(),
        bob_view.agent_certificate.is_none(),
    );
    shutdown(alice, bob).await;

    assert!(
        bob_to_alice.is_ok(),
        "bob→alice failed: {:?}",
        bob_to_alice.err()
    );
    assert!(
        alice_to_bob.is_ok(),
        "alice→bob failed: {:?}",
        alice_to_bob.err()
    );
    assert!(elapsed < Duration::from_secs(30), "took {elapsed:?}");
    assert_eq!(
        results,
        (true, true, true, true, true, true),
        "(b→a ok, a→b ok, alice has bob's record, bob has alice's record, \
         alice's entry still anonymous, bob's entry still anonymous)"
    );
}

/// The same rig, but Bob's agent is revoked on Alice after a first working
/// session. The sync that follows is refused in both directions and Bob's
/// newer record never reaches Alice. A revocation is an explicit deny; the
/// enrollment does not waive it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_sync_is_refused_once_the_known_agent_is_revoked() {
    let (_dir, alice, bob) = rig().await;
    mint_name(&bob, "bob-before").await;
    let first = dial(&alice, &bob).await;
    let first_ok = first.is_ok() && has_name(&alice, "bob-before").await;

    let revocation = crate::revocation::RevocationRecord::sign(
        crate::revocation::RevokedSubject::Agent(bob.agent.agent_id()),
        bob.agent.identity().agent_keypair().public_key(),
        bob.agent.identity().agent_keypair().secret_key(),
        now_secs(),
        None,
    )
    .expect("revocation");
    alice
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(revocation, None)
        .expect("insert revocation");
    mint_name(&bob, "bob-after").await;

    let bob_to_alice = dial_refusal(&bob, &alice).await;
    let alice_to_bob = dial_refusal(&alice, &bob).await;
    let alice_gate = inbound_gate_error(&alice, &bob).await;
    let leaked = has_name(&alice, "bob-after").await;
    shutdown(alice, bob).await;

    assert!(
        first_ok,
        "control: sync works before the revocation: {first:?}"
    );
    // Alice's inbound gate names the cause: the agent is revoked.
    assert!(
        matches!(
            alice_gate,
            Some(crate::error::NetworkError::PeerRevoked { .. })
        ),
        "alice's gate must refuse bob as revoked, got {alice_gate:?}"
    );
    assert_refused(bob_to_alice, alice_to_bob, "stream peer revoked");
    assert!(
        !leaked,
        "bob's record must not reach alice after the revocation"
    );
}

/// The same rig, but after a first working session Alice's cached entry for
/// Bob holds a certificate that has expired. The sync is refused in both
/// directions and the newer record does not move. The enrollment does not
/// waive an expired certificate (A03).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_sync_is_refused_when_the_cached_certificate_has_expired() {
    let (_dir, alice, bob) = rig().await;
    mint_name(&bob, "bob-before").await;
    let first = dial(&alice, &bob).await;
    let first_ok = first.is_ok() && has_name(&alice, "bob-before").await;

    // Alice's cache now holds a certificate for Bob, from the owner, that
    // expired an hour ago (a cached entry whose certificate is past its
    // `not_after`; an anonymous entry has no expiry to read).
    let owner = UserKeypair::from_seed(&SEED).expect("owner key");
    let expired = crate::identity::AgentCertificate::issue_with_expiry(
        &owner,
        bob.agent.identity().agent_keypair(),
        Some(now_secs() - 3600),
    )
    .expect("expired certificate");
    let bob_addr = loopback_addr(&bob.agent).await;
    let mut card = anonymous_card(&bob.agent, bob_addr, Some(now_secs() - 3600));
    card.user_id = Some(owner.user_id());
    card.agent_certificate = Some(expired);
    alice.agent.insert_discovered_agent_for_testing(card).await;
    let cached = alice
        .agent
        .discovered_agent_for_testing(&bob.agent.agent_id())
        .await
        .expect("alice's entry for bob");
    let cached_expired = crate::identity::is_expired(cached.cert_not_after, now_secs());
    mint_name(&bob, "bob-after").await;

    let bob_to_alice = dial_refusal(&bob, &alice).await;
    let alice_to_bob = dial_refusal(&alice, &bob).await;
    let alice_gate = inbound_gate_error(&alice, &bob).await;
    let leaked = has_name(&alice, "bob-after").await;
    shutdown(alice, bob).await;

    assert!(first_ok, "control: sync works before the expiry: {first:?}");
    assert!(
        cached_expired,
        "control: alice's cached certificate is expired"
    );
    // Alice's inbound gate names the cause: not verified (expired), which
    // is not the revoked refusal.
    assert!(
        matches!(
            alice_gate,
            Some(crate::error::NetworkError::PeerNotVerified { .. })
        ),
        "alice's gate must refuse bob as not verified (expired), got {alice_gate:?}"
    );
    assert_refused(bob_to_alice, alice_to_bob, "stream peer not verified");
    assert!(
        !leaked,
        "bob's record must not reach alice with an expired certificate"
    );
}
