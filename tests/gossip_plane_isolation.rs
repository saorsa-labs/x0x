//! Issue #206: co-located gossip planes must be isolated.
//!
//! Two daemons on one host (prod + testnet) discovered each other via
//! ant-quic's first-party mDNS auto-connect and exchanged gossip traffic —
//! a revocation minted on the testnet plane persisted into prod revocation
//! sets. The fix exchanges a plane hello on every connection and refuses
//! gossip traffic with mismatched peers (disconnect + tombstone + cache
//! eviction); peers are not gossip-eligible until plane-cleared.
//!
//! These tests run the crossing in-process: a manual `connect_addr` stands
//! in for the mDNS auto-connect (ant-quic skips mDNS on loopback-only
//! endpoints); the transport connection is the same carrier either way.

use std::time::Duration;

use x0x::network::{validate_plane_id, NetworkConfig};
use x0x::Agent;

const TOPIC: &str = "x0x.test.plane-isolation.v1";

async fn build_agent(dir: &std::path::Path, name: &str, network_id: Option<&str>) -> Agent {
    let network_config = NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
        bootstrap_nodes: Vec::new(),
        network_id: network_id.map(str::to_string),
        ..NetworkConfig::default()
    };
    Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.join(format!("{name}-peers")))
        .with_network_config(network_config)
        .build()
        .await
        .unwrap_or_else(|e| panic!("build {name}: {e}"))
}

/// Dial `b` from `a` and wait until both sides register the connection.
async fn connect_pair(a: &Agent, b: &Agent) {
    let b_addr = b.bound_addr().await.expect("b bound addr");
    let a_network = a.network().expect("a network");
    let connected = a_network.connect_addr(b_addr).await.expect("a dials b");
    assert_eq!(connected.0, b.machine_id().0, "a connected to b's identity");

    let b_peer = ant_quic::PeerId(b.machine_id().0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if a_network.is_connected(&b_peer).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("a never registered the connection to b");
}

/// Receive until `want` arrives (skipping the publisher's own local echo,
/// which PlumTree delivers to the publisher's own subscription) or the
/// deadline expires. Returns `true` iff `want` was delivered.
async fn recv_payload(sub: &mut x0x::Subscription, want: &[u8], within: Duration) -> bool {
    tokio::time::timeout(within, async {
        while let Some(msg) = sub.recv().await {
            if msg.payload == want {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

/// Carrier proof, isolation OFF: two open-plane agents on one host exchange
/// gossip over a co-located connection. This is the pre-#206 behaviour the
/// issue reported; it must keep working when no plane is configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_plane_pair_exchanges_gossip() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let alice = build_agent(dir.path(), "alice", None).await;
    let bob = build_agent(dir.path(), "bob", None).await;
    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let mut alice_sub = alice.subscribe(TOPIC).await.expect("alice sub");
    let mut bob_sub = bob.subscribe(TOPIC).await.expect("bob sub");
    connect_pair(&alice, &bob).await;
    // Let the 1s eager-set refresh tick pick up the new peer.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let payload = b"open-plane carrier proof".to_vec();
    bob.publish(TOPIC, payload.clone())
        .await
        .expect("bob publishes");
    assert!(
        recv_payload(&mut alice_sub, &payload, Duration::from_secs(15)).await,
        "alice should receive from bob on the open plane"
    );

    // And the reverse direction, to prove symmetric carrier behaviour.
    let payload2 = b"open-plane reverse".to_vec();
    alice
        .publish(TOPIC, payload2.clone())
        .await
        .expect("alice publishes");
    assert!(
        recv_payload(&mut bob_sub, &payload2, Duration::from_secs(15)).await,
        "bob should receive from alice on the open plane"
    );
}

/// Isolation ON: two co-located agents configured on DIFFERENT planes must
/// not exchange gossip, and the cross-plane connection must be refused
/// (disconnected + tombstoned) once the plane hellos are exchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_plane_pair_does_not_exchange_gossip() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let prod = build_agent(dir.path(), "prod", Some("x0x.test.prod")).await;
    let testnet = build_agent(dir.path(), "testnet", Some("x0x.test.testnet")).await;
    prod.join_network().await.expect("prod joins");
    testnet.join_network().await.expect("testnet joins");

    let mut prod_sub = prod.subscribe(TOPIC).await.expect("prod sub");
    let mut testnet_sub = testnet.subscribe(TOPIC).await.expect("testnet sub");
    connect_pair(&prod, &testnet).await;

    // Publish in both directions across the (initially connected) link.
    // Neither may be delivered to the other side: the plane gate holds
    // frames from non-cleared peers, and the mismatched hellos refuse the
    // connection. (Each side DOES see its own publish echoed locally; the
    // assertions below only look for the foreign payload.)
    testnet
        .publish(TOPIC, b"testnet junk payload".to_vec())
        .await
        .expect("testnet publishes");
    prod.publish(TOPIC, b"prod payload".to_vec())
        .await
        .expect("prod publishes");

    let (prod_saw_testnet, testnet_saw_prod) = tokio::join!(
        recv_payload(
            &mut prod_sub,
            b"testnet junk payload",
            Duration::from_secs(6)
        ),
        recv_payload(&mut testnet_sub, b"prod payload", Duration::from_secs(6)),
    );
    assert!(
        !prod_saw_testnet,
        "prod must not receive testnet's cross-plane publish"
    );
    assert!(
        !testnet_saw_prod,
        "testnet must not receive prod's cross-plane publish"
    );

    // Hard isolation: the mismatched hello must tear the connection down on
    // both sides and keep it down (PolicyRejection tombstone).
    let prod_network = prod.network().expect("prod network");
    let testnet_peer = ant_quic::PeerId(testnet.machine_id().0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut disconnected = false;
    while tokio::time::Instant::now() < deadline {
        if !prod_network.is_connected(&testnet_peer).await {
            disconnected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        disconnected,
        "prod should have disconnected the cross-plane testnet peer"
    );
    // Stay-down check across several eager-set refresh ticks.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !prod_network.is_connected(&testnet_peer).await,
        "cross-plane peer must stay disconnected (tombstoned)"
    );
}

/// Isolation ON, same plane: two agents configured with the SAME plane id
/// must converge exactly as before — plane hellos clear immediately.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_plane_pair_converges() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let one = build_agent(dir.path(), "one", Some("x0x.test.same")).await;
    let two = build_agent(dir.path(), "two", Some("x0x.test.same")).await;
    one.join_network().await.expect("one joins");
    two.join_network().await.expect("two joins");

    let mut one_sub = one.subscribe(TOPIC).await.expect("one sub");
    connect_pair(&one, &two).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let payload = b"same-plane convergence".to_vec();
    two.publish(TOPIC, payload.clone())
        .await
        .expect("two publishes");
    assert!(
        recv_payload(&mut one_sub, &payload, Duration::from_secs(15)).await,
        "same-plane peer should receive"
    );
}

/// Mixed fleet: a plane-gated agent and an open-plane (legacy/embedder)
/// agent must still converge — the gated side admits the hello-less peer
/// after the legacy grace window instead of partitioning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gated_and_open_pair_converges_after_legacy_grace() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let gated = build_agent(dir.path(), "gated", Some("x0x.test.gated")).await;
    let open = build_agent(dir.path(), "open", None).await;
    gated.join_network().await.expect("gated joins");
    open.join_network().await.expect("open joins");

    let mut open_sub = open.subscribe(TOPIC).await.expect("open sub");
    connect_pair(&gated, &open).await;

    // The gated side holds the open peer at the plane gate until the legacy
    // grace (10s) promotes it; publish only after that window plus the 1s
    // eager-set refresh tick.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let payload = b"legacy-grace convergence".to_vec();
    gated
        .publish(TOPIC, payload.clone())
        .await
        .expect("gated publishes");
    assert!(
        recv_payload(&mut open_sub, &payload, Duration::from_secs(15)).await,
        "open peer should receive after legacy grace"
    );
}

#[test]
fn plane_id_validation() {
    assert!(validate_plane_id("x0x.prod").is_ok());
    assert!(validate_plane_id("x0x.testnet-01_eu").is_ok());
    assert!(validate_plane_id("").is_err());
    assert!(validate_plane_id("has space").is_err());
    assert!(validate_plane_id("slash/invalid").is_err());
    assert!(validate_plane_id(&"a".repeat(65)).is_err());
    assert!(validate_plane_id(&"a".repeat(64)).is_ok());
}
