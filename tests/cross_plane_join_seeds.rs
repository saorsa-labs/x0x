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
//!
//! The round-2 tests (Codex review of round 1) order events with [`Gate`]s,
//! not with timing: a gate holds the thread that emits one tracing event,
//! so the code after that event waits until the test opens the gate.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use x0x::network::{NetworkConfig, NetworkEvent, PeerAdmission};
use x0x::Agent;

/// Upper bound for one `join_network` call. Phase 1 gives each cached dial
/// up to 15 s; the rest of the join on loopback takes well under that.
const JOIN_BOUND: Duration = Duration::from_secs(60);

const JOIN_CONNECTING: &str = "JOIN: Connecting to bootstrap node";
const JOIN_RETRY: &str = "JOIN: Connection failed, will retry";
const JOIN_JOINED: &str = "JOIN: Successfully joined network";
/// saorsa-gossip logs this on the peer that receives a JOIN frame, with the
/// joiner's peer id (first 8 bytes, hex) in `new_peer`.
const JOIN_RECEIVED: &str = "HyParView: Received JOIN request";

const PROD_PLANE: &str = "x0x.test.prod";
const TESTNET_PLANE: &str = "x0x.test.testnet";

/// One captured saorsa-gossip JOIN event.
#[derive(Debug, Clone)]
struct JoinEvent {
    message: String,
    seed: Option<String>,
    new_peer: Option<String>,
}

static JOIN_EVENTS: Mutex<Vec<JoinEvent>> = Mutex::new(Vec::new());
static CAPTURE: OnceLock<()> = OnceLock::new();

/// Longest time a gate holds one thread. A safety net only: a test that
/// never opens its gate fails on its own bounds, not by hanging.
const GATE_MAX_HOLD: Duration = Duration::from_secs(90);

/// A test-controlled hold on one tracing event.
///
/// While the gate is armed and closed, a thread that emits an event whose
/// message starts with `prefix` blocks inside the capture layer. The wait
/// runs in `block_in_place`, so the runtime moves the worker's other tasks
/// to another thread. The code after that event cannot run until the test
/// opens the gate.
struct Gate {
    prefix: &'static str,
    state: Mutex<GateState>,
    changed: Condvar,
}

struct GateState {
    armed: bool,
    open: bool,
    held: usize,
}

impl Gate {
    const fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            state: Mutex::new(GateState {
                armed: false,
                open: false,
                held: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Close the gate: from now on, emitters of the event block.
    fn arm(&self) {
        *self.lock() = GateState {
            armed: true,
            open: false,
            held: 0,
        };
    }

    /// Release every held emitter and let later emitters pass.
    fn open(&self) {
        self.lock().open = true;
        self.changed.notify_all();
    }

    /// How many emitters reached the closed gate.
    fn held(&self) -> usize {
        self.lock().held
    }

    /// Called by the capture layer for every event.
    fn pass(&self, message: &str) {
        if !message.starts_with(self.prefix) {
            return;
        }
        {
            let mut state = self.lock();
            if !state.armed || state.open {
                return;
            }
            state.held += 1;
        }
        tokio::task::block_in_place(|| {
            let state = self.lock();
            let _released = self
                .changed
                .wait_timeout_while(state, GATE_MAX_HOLD, |state| state.armed && !state.open);
        });
    }

    /// Wait until `count` emitters reached the closed gate, at most `bound`.
    async fn wait_held(&self, count: usize, bound: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + bound;
        while self.held() < count {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }
}

/// `join_network` logs this after its dial phases, before it reads any
/// JOIN seed admission verdict.
static JOIN_COMPLETE_GATE: Gate = Gate::new("Network join complete");
/// `schedule_reconnect` logs this just before each proactive redial.
static RECONNECT_GATE: Gate = Gate::new("proactive reconnect attempt");
/// `plane_handle_hello` logs this before it writes the #292 tombstone and
/// disconnects a cross-plane peer.
static PLANE_REFUSAL_GATE: Gate =
    Gate::new("gossip-plane mismatch: refusing cross-plane peer (issue #206)");

#[derive(Default)]
struct JoinVisitor {
    message: String,
    seed: Option<String>,
    new_peer: Option<String>,
}

impl Visit for JoinVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = value.to_string(),
            "seed" => self.seed = Some(value.to_string()),
            "new_peer" => self.new_peer = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "seed" => self.seed = Some(format!("{value:?}")),
            "new_peer" => self.new_peer = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

struct JoinCapture;

impl<S: tracing::Subscriber> Layer<S> for JoinCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = JoinVisitor::default();
        event.record(&mut visitor);
        if visitor.message.starts_with("JOIN:") || visitor.message.starts_with(JOIN_RECEIVED) {
            JOIN_EVENTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(JoinEvent {
                    message: visitor.message.clone(),
                    seed: visitor.seed,
                    new_peer: visitor.new_peer,
                });
        }
        JOIN_COMPLETE_GATE.pass(&visitor.message);
        RECONNECT_GATE.pass(&visitor.message);
        PLANE_REFUSAL_GATE.pass(&visitor.message);
    }
}

/// Install the process-global capture of saorsa-gossip membership events
/// and x0x info events (the gate events). Only these targets are enabled,
/// so other crates' callsites stay disabled.
fn install_join_capture() {
    CAPTURE.get_or_init(|| {
        let targets = tracing_subscriber::filter::Targets::new()
            .with_target("saorsa_gossip_membership", tracing::Level::DEBUG)
            .with_target("x0x", tracing::Level::INFO);
        let subscriber = tracing_subscriber::registry().with(JoinCapture.with_filter(targets));
        tracing::subscriber::set_global_default(subscriber)
            .expect("install the JOIN capture subscriber");
    });
}

/// Captured `JOIN_RECEIVED` events whose joiner is `joiner` (a machine id).
fn joins_received_from(joiner: [u8; 32]) -> usize {
    let prefix: String = joiner[..8].iter().map(|b| format!("{b:02x}")).collect();
    JOIN_EVENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|event| {
            event.message == JOIN_RECEIVED && event.new_peer.as_deref() == Some(prefix.as_str())
        })
        .count()
}

/// Wait until `joiner`'s JOIN frame is received by another agent in this
/// process, at most `bound`.
async fn wait_join_received_from(joiner: [u8; 32], bound: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + bound;
    while joins_received_from(joiner) == 0 {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
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
    build_agent_with_bootstrap(dir, name, network_id, Vec::new()).await
}

/// [`build_agent`] with configured bootstrap nodes (loopback addresses of
/// other agents in this test only).
async fn build_agent_with_bootstrap(
    dir: &std::path::Path,
    name: &str,
    network_id: Option<&str>,
    bootstrap_nodes: Vec<SocketAddr>,
) -> Agent {
    let network_config = NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
        bootstrap_nodes,
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

/// Spawn `agent.join_network()` as its own task, so a gate can hold it
/// while the test body keeps running.
fn spawn_join(agent: &Arc<Agent>) -> tokio::task::JoinHandle<x0x::error::Result<()>> {
    let agent = Arc::clone(agent);
    tokio::spawn(async move { agent.join_network().await })
}

/// How long the reconnect gate stays closed after the seed read is
/// released, if the join has not returned before. While the gate is
/// closed, no proactive redial can restore the peer.
const RECONNECT_HOLD: Duration = Duration::from_secs(3);

/// Upper bound for a join that waits for transport recovery: the reconnect
/// hold, one proactive redial, and the JOIN.
const RECOVERY_JOIN_BOUND: Duration = Duration::from_secs(60);

/// Codex round-1 finding 1. The sole same-plane candidate answers the
/// Phase 1 dial. Then it loses its transport connection before the join
/// reads the JOIN seed verdicts, and the proactive reconnect restores it
/// after that read. The JOIN must still reach the peer. (The code before
/// round 1 kept the address, and the JOIN redialled it.)
///
/// Gates fix the event order:
/// 1. `JOIN_COMPLETE_GATE` holds `join_network` after its dials and before
///    its first seed read. The test drops the connection with a
///    transport-reason disconnect (no tombstone) and waits until the agent
///    reports the peer as not connected. Then it opens the gate.
/// 2. `RECONNECT_GATE` holds every proactive redial until the join has
///    returned or [`RECONNECT_HOLD`] has passed. So the peer is not
///    connected when the join reads its verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_transient_loss_before_seed_read_still_joins_after_reconnect() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_peer_agent, peer, peer_addr) = remote_agent(dir.path(), "peer", Some(PROD_PLANE)).await;
    let prod = Arc::new(build_agent(dir.path(), "prod", Some(PROD_PLANE)).await);
    cache_peer(&prod, peer, peer_addr).await;
    let prod_network = Arc::clone(prod.network().expect("prod network"));
    let prod_id = prod.machine_id().0;

    JOIN_COMPLETE_GATE.arm();
    RECONNECT_GATE.arm();
    let join = spawn_join(&prod);

    assert!(
        JOIN_COMPLETE_GATE.wait_held(1, JOIN_BOUND).await,
        "scenario: join_network must reach the end of its dial phases"
    );
    assert!(
        prod_network.is_connected(&peer).await,
        "scenario: Phase 1 must have dialled the cached same-plane peer"
    );
    prod_network
        .disconnect(&peer)
        .await
        .expect("transport-reason disconnect");
    let drop_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while prod_network.is_connected(&peer).await {
        assert!(
            tokio::time::Instant::now() < drop_deadline,
            "scenario: the transport disconnect must land"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        prod_network.peer_admission(&peer).await,
        PeerAdmission::NotConnected,
        "scenario: a transport loss must leave no tombstone"
    );
    JOIN_COMPLETE_GATE.open();

    let hold_deadline = tokio::time::Instant::now() + RECONNECT_HOLD;
    while !join.is_finished() && tokio::time::Instant::now() < hold_deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !prod_network.is_connected(&peer).await,
        "scenario: nothing may reconnect the peer while the reconnect gate is closed"
    );
    RECONNECT_GATE.open();

    let joined = tokio::time::timeout(RECOVERY_JOIN_BOUND, join).await;
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must finish within {RECOVERY_JOIN_BOUND:?}: {joined:?}"
    );
    let events = join_events_for(peer_addr);
    assert_eq!(count(&events, JOIN_RETRY), 0, "no JOIN retries: {events:?}");
    assert_eq!(
        count(&events, JOIN_JOINED),
        1,
        "after its transport recovers, the same-plane peer must get the JOIN; \
         it must not be dropped as a seed after one not-connected read: {events:?}"
    );
    assert!(
        wait_join_received_from(prod_id, Duration::from_secs(10)).await,
        "the peer must receive the JOIN frame (overlay membership, not only a return)"
    );
}

/// Codex round-1 finding 2. Three cached cross-plane peers answer the
/// Phase 1 dials. Their plane verdicts are still open when the join counts
/// its peers, so they fill `min_connected` and the join skips the Phase 2
/// bootstrap fallback. The plane gate refuses all three a moment later. The
/// join must then still fall back to the reachable same-plane bootstrap
/// node.
///
/// Gates fix the event order:
/// 1. `PLANE_REFUSAL_GATE` holds every plane-mismatch refusal, on both
///    sides, before its tombstone and disconnect.
/// 2. `JOIN_COMPLETE_GATE` holds `join_network` after its phase decisions.
///    The test checks that all three peers are connected with an open plane
///    verdict. Then it opens both gates, so the refusals land after the
///    phase decisions.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_late_refused_peers_at_min_connected_keep_bootstrap_fallback() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_boot_agent, _boot, boot_addr) = remote_agent(dir.path(), "boot", Some(PROD_PLANE)).await;
    let mut testnet = Vec::new();
    for name in ["testnet-a", "testnet-b", "testnet-c"] {
        testnet.push(remote_agent(dir.path(), name, Some(TESTNET_PLANE)).await);
    }
    let prod = Arc::new(
        build_agent_with_bootstrap(dir.path(), "prod", Some(PROD_PLANE), vec![boot_addr]).await,
    );
    for (_, peer, addr) in &testnet {
        cache_peer(&prod, *peer, *addr).await;
    }
    let prod_network = Arc::clone(prod.network().expect("prod network"));
    let prod_id = prod.machine_id().0;

    PLANE_REFUSAL_GATE.arm();
    JOIN_COMPLETE_GATE.arm();
    let join = spawn_join(&prod);

    assert!(
        JOIN_COMPLETE_GATE.wait_held(1, JOIN_BOUND).await,
        "scenario: join_network must reach the end of its dial phases"
    );
    for (_, peer, addr) in &testnet {
        assert_eq!(
            prod_network.peer_admission(peer).await,
            PeerAdmission::PlanePending,
            "scenario: cross-plane peer {addr} must be connected, with its plane \
             verdict still open, at the phase decisions"
        );
    }
    assert!(
        join_events_for(boot_addr).is_empty(),
        "scenario: no JOIN before the gates open"
    );
    PLANE_REFUSAL_GATE.open();
    JOIN_COMPLETE_GATE.open();

    let joined = tokio::time::timeout(JOIN_BOUND, join).await;
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must finish within {JOIN_BOUND:?}: {joined:?}"
    );
    for (_, peer, addr) in &testnet {
        let events = join_events_for(*addr);
        assert!(
            events.is_empty(),
            "cross-plane peer {addr} must not be a JOIN seed: {events:?}"
        );
        assert_ne!(
            prod_network.peer_admission(peer).await,
            PeerAdmission::Admitted,
            "scenario: the plane gate must refuse cross-plane peer {addr}"
        );
    }
    let boot_events = join_events_for(boot_addr);
    assert_eq!(
        count(&boot_events, JOIN_JOINED),
        1,
        "late refusals left no admitted peer, so the join must fall back to the \
         same-plane bootstrap node: {boot_events:?}"
    );
    assert!(
        wait_join_received_from(prod_id, Duration::from_secs(10)).await,
        "the bootstrap node must receive the JOIN frame"
    );
}
