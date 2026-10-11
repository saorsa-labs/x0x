//! Issue #1321: a cached peer on another gossip plane must not become a
//! HyParView JOIN seed.
//!
//! On saorsa-6 (prod plane) the bootstrap cache held two testnet daemons.
//! At start-up `Agent::join_network` dialled them (Phase 0/1) and the dials
//! returned `Ok`. The gossip-plane gate (issue #206) refused them a moment
//! later, when their plane hello arrived, but the JOIN seeds were built from
//! the dial results. `membership().join(seeds)` then dialled each refused
//! address up to ten times with backoff, and the #292 suppression gate
//! refused every dial.
//!
//! These tests drive the same path in-process on loopback: the prod agent's
//! bootstrap cache holds the other agent before `join_network` runs. The
//! oracle is the JOIN's own tracing (target `saorsa_gossip_membership`), the
//! same lines the saorsa-6 journal showed: a seed the JOIN uses always logs
//! `JOIN: Connecting to bootstrap node` with its address.
//!
//! Each nextest test runs in its own process, so the global capture layer
//! sees only that test's agents.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use x0x::network::{NetworkConfig, NetworkEvent};
use x0x::Agent;

/// Upper bound for one `join_network` call. Phase 1 gives each cached dial
/// up to 15 s; the rest of the join on loopback takes well under that.
const JOIN_BOUND: Duration = Duration::from_secs(60);

const JOIN_CONNECTING: &str = "JOIN: Connecting to bootstrap node";
const JOIN_RETRY: &str = "JOIN: Connection failed, will retry";
const JOIN_JOINED: &str = "JOIN: Successfully joined network";

/// One captured saorsa-gossip JOIN event.
#[derive(Debug, Clone)]
struct JoinEvent {
    message: String,
    seed: Option<String>,
}

static JOIN_EVENTS: Mutex<Vec<JoinEvent>> = Mutex::new(Vec::new());
static CAPTURE: OnceLock<()> = OnceLock::new();

#[derive(Default)]
struct JoinVisitor {
    message: String,
    seed: Option<String>,
}

impl Visit for JoinVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = value.to_string(),
            "seed" => self.seed = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "seed" => self.seed = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

struct JoinCapture;

impl<S: tracing::Subscriber> Layer<S> for JoinCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = JoinVisitor::default();
        event.record(&mut visitor);
        if visitor.message.starts_with("JOIN:") {
            JOIN_EVENTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(JoinEvent {
                    message: visitor.message,
                    seed: visitor.seed,
                });
        }
    }
}

/// Install the process-global capture of saorsa-gossip membership events.
/// Only that target is enabled, so other crates' callsites stay disabled.
fn install_join_capture() {
    CAPTURE.get_or_init(|| {
        let only_membership = tracing_subscriber::filter::Targets::new()
            .with_target("saorsa_gossip_membership", tracing::Level::DEBUG);
        let subscriber =
            tracing_subscriber::registry().with(JoinCapture.with_filter(only_membership));
        tracing::subscriber::set_global_default(subscriber)
            .expect("install the JOIN capture subscriber");
    });
}

/// Captured JOIN events whose `seed` field is `addr`.
fn join_events_for(addr: SocketAddr) -> Vec<JoinEvent> {
    let addr = addr.to_string();
    JOIN_EVENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|event| event.seed.as_deref() == Some(addr.as_str()))
        .cloned()
        .collect()
}

fn count(events: &[JoinEvent], message: &str) -> usize {
    events
        .iter()
        .filter(|event| event.message == message)
        .count()
}

async fn build_agent(dir: &std::path::Path, name: &str, network_id: Option<&str>) -> Agent {
    let network_config = NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
        bootstrap_nodes: Vec::new(),
        network_id: network_id.map(str::to_string),
        mdns_enabled: false,
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

/// Build an agent that is already on the network and return it with its
/// transport peer id and bound loopback address.
async fn remote_agent(
    dir: &std::path::Path,
    name: &str,
    network_id: Option<&str>,
) -> (Agent, ant_quic::PeerId, SocketAddr) {
    let agent = build_agent(dir, name, network_id).await;
    agent
        .join_network()
        .await
        .unwrap_or_else(|e| panic!("{name} joins: {e}"));
    let peer = ant_quic::PeerId(agent.machine_id().0);
    let addr = agent
        .bound_addr()
        .await
        .unwrap_or_else(|| panic!("{name} bound addr"));
    (agent, peer, addr)
}

/// Put `peer` at `addr` into `agent`'s bootstrap cache, as a peer learned
/// from an earlier connection (how the testnet daemons sat in saorsa-6's
/// cache).
async fn cache_peer(agent: &Agent, peer: ant_quic::PeerId, addr: SocketAddr) {
    agent
        .network()
        .expect("agent network")
        .bootstrap_cache()
        .expect("agent bootstrap cache")
        .add_from_connection(peer, vec![addr], None)
        .await;
}

/// Peers for which the network emitted `PeerConnected` (an outbound dial
/// that returned `Ok`, or an admitted inbound connection).
fn drain_connected(
    events: &mut tokio::sync::broadcast::Receiver<NetworkEvent>,
) -> HashSet<[u8; 32]> {
    let mut connected = HashSet::new();
    loop {
        match events.try_recv() {
            Ok(NetworkEvent::PeerConnected { peer_id, .. }) => {
                connected.insert(peer_id);
            }
            Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(_) => return connected,
        }
    }
}

/// Run `agent.join_network()` until it returns, until a JOIN event for
/// `watch` is captured, or until [`JOIN_BOUND`]. Returns `Some(result)` when
/// the join returned. The early stop keeps a red run short: the unfixed JOIN
/// spends about 81 s retrying one refused seed.
async fn join_watching(agent: &Agent, watch: SocketAddr) -> Option<x0x::error::Result<()>> {
    let join = agent.join_network();
    tokio::pin!(join);
    let deadline = tokio::time::Instant::now() + JOIN_BOUND;
    loop {
        tokio::select! {
            result = &mut join => return Some(result),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if !join_events_for(watch).is_empty()
                    || tokio::time::Instant::now() >= deadline
                {
                    return None;
                }
            }
        }
    }
}

/// The saorsa-6 shape. A second cached peer is a silent UDP socket, so
/// Phase 1 waits on that dial and the cross-plane refusal lands before the
/// JOIN, as it did in prod (refusal at 21:59:38, JOIN at 21:59:48). The
/// unfixed join then retried the refused seed without success.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1321_cached_cross_plane_peer_is_not_a_join_seed() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_testnet, testnet_peer, testnet_addr) =
        remote_agent(dir.path(), "testnet", Some("x0x.test.testnet")).await;
    let prod = build_agent(dir.path(), "prod", Some("x0x.test.prod")).await;

    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    cache_peer(&prod, testnet_peer, testnet_addr).await;
    cache_peer(&prod, ant_quic::PeerId([0x5a; 32]), silent_addr).await;

    let prod_network = prod.network().expect("prod network");
    let mut prod_events = prod_network.subscribe();
    let joined = join_watching(&prod, testnet_addr).await;

    assert!(
        drain_connected(&mut prod_events).contains(&testnet_peer.0),
        "scenario: the join must dial the cached cross-plane peer successfully \
         (that dial result is what reached the JOIN seeds on saorsa-6)"
    );
    let events = join_events_for(testnet_addr);
    assert_eq!(
        count(&events, JOIN_RETRY),
        0,
        "a refused cross-plane peer must cause no JOIN retries: {events:?}"
    );
    assert!(
        events.is_empty(),
        "cached cross-plane peer {testnet_addr} must not be a JOIN seed: {events:?}"
    );
    assert!(
        matches!(joined, Some(Ok(()))),
        "join_network must finish within {JOIN_BOUND:?}: {joined:?}"
    );
    drop(silent);
}

/// The other ordering: no slow cached dial, so Phase 1 ends as soon as the
/// cross-plane dial returns and the JOIN can start before either plane
/// hello is processed. The peer must still not become a seed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1321_cross_plane_peer_refused_after_phase1_is_not_a_join_seed() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_testnet, testnet_peer, testnet_addr) =
        remote_agent(dir.path(), "testnet", Some("x0x.test.testnet")).await;
    let prod = build_agent(dir.path(), "prod", Some("x0x.test.prod")).await;
    cache_peer(&prod, testnet_peer, testnet_addr).await;

    let prod_network = prod.network().expect("prod network");
    let mut prod_events = prod_network.subscribe();
    let joined = join_watching(&prod, testnet_addr).await;

    assert!(
        drain_connected(&mut prod_events).contains(&testnet_peer.0),
        "scenario: the join must dial the cached cross-plane peer successfully"
    );
    let events = join_events_for(testnet_addr);
    assert!(
        events.is_empty(),
        "cached cross-plane peer {testnet_addr} must not be a JOIN seed: {events:?}"
    );
    assert!(
        matches!(joined, Some(Ok(()))),
        "join_network must finish within {JOIN_BOUND:?}: {joined:?}"
    );
}

/// Parity control (v0.46.6 and v0.47.0 behave the same here): a cached peer
/// on the SAME plane is still a JOIN seed, and the JOIN succeeds on its
/// first dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1321_control_cached_same_plane_peer_is_still_a_join_seed() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_peer_agent, peer, peer_addr) =
        remote_agent(dir.path(), "peer", Some("x0x.test.prod")).await;
    let prod = build_agent(dir.path(), "prod", Some("x0x.test.prod")).await;
    cache_peer(&prod, peer, peer_addr).await;

    let joined = tokio::time::timeout(JOIN_BOUND, prod.join_network()).await;
    assert!(
        matches!(joined, Ok(Ok(()))),
        "join_network must finish within {JOIN_BOUND:?}: {joined:?}"
    );
    let events = join_events_for(peer_addr);
    assert_eq!(
        count(&events, JOIN_CONNECTING),
        1,
        "same-plane cached peer must be dialled once as a JOIN seed: {events:?}"
    );
    assert_eq!(count(&events, JOIN_RETRY), 0, "no JOIN retries: {events:?}");
    assert_eq!(
        count(&events, JOIN_JOINED),
        1,
        "the JOIN must succeed via the same-plane seed: {events:?}"
    );
}

/// Parity control: a cached peer that sends no plane hello (open plane,
/// i.e. pre-#206 code) is admitted by the gate after the 10 s legacy grace
/// and is still a JOIN seed. This guards the bounded wait for plane
/// verdicts: it must not drop legacy peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1321_control_cached_legacy_peer_is_a_join_seed_after_grace() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_legacy, legacy_peer, legacy_addr) = remote_agent(dir.path(), "legacy", None).await;
    let prod = build_agent(dir.path(), "prod", Some("x0x.test.prod")).await;
    cache_peer(&prod, legacy_peer, legacy_addr).await;

    let joined = tokio::time::timeout(JOIN_BOUND, prod.join_network()).await;
    assert!(
        matches!(joined, Ok(Ok(()))),
        "join_network must finish within {JOIN_BOUND:?}: {joined:?}"
    );
    let events = join_events_for(legacy_addr);
    assert_eq!(
        count(&events, JOIN_CONNECTING),
        1,
        "legacy cached peer must be dialled once as a JOIN seed: {events:?}"
    );
    assert_eq!(count(&events, JOIN_RETRY), 0, "no JOIN retries: {events:?}");
    assert_eq!(
        count(&events, JOIN_JOINED),
        1,
        "the JOIN must succeed via the legacy seed: {events:?}"
    );
}

/// Prod-like mix: one cross-plane and one same-plane cached peer. Only the
/// same-plane peer may be a seed. (On unfixed code this case depends on the
/// cache selection order, so it is a green guard, not the red test.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1321_mixed_cache_seeds_only_the_same_plane_peer() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_testnet, testnet_peer, testnet_addr) =
        remote_agent(dir.path(), "testnet", Some("x0x.test.testnet")).await;
    let (_peer_agent, peer, peer_addr) =
        remote_agent(dir.path(), "peer", Some("x0x.test.prod")).await;
    let prod = build_agent(dir.path(), "prod", Some("x0x.test.prod")).await;
    cache_peer(&prod, testnet_peer, testnet_addr).await;
    cache_peer(&prod, peer, peer_addr).await;

    let joined = tokio::time::timeout(JOIN_BOUND, prod.join_network()).await;
    assert!(
        matches!(joined, Ok(Ok(()))),
        "join_network must finish within {JOIN_BOUND:?}: {joined:?}"
    );
    let cross = join_events_for(testnet_addr);
    assert!(
        cross.is_empty(),
        "cached cross-plane peer {testnet_addr} must not be a JOIN seed: {cross:?}"
    );
    let same = join_events_for(peer_addr);
    assert_eq!(
        count(&same, JOIN_JOINED),
        1,
        "the JOIN must succeed via the same-plane seed: {same:?}"
    );
}
