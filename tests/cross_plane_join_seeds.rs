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
use x0x::network::{DisconnectReason, NetworkConfig, NetworkEvent, PeerAdmission};
use x0x::Agent;

/// Upper bound for one `join_network` call in a normal topology. Phase 1
/// gives each cached dial up to 15 s; the rest of the join on loopback
/// takes well under that.
const JOIN_BOUND: Duration = Duration::from_secs(60);

/// Upper bound for a join whose only candidates are cross-plane peers.
/// Sometimes the cross-plane peer refuses us first: it closes each of our
/// connections at accept, before its plane hello reaches us. Then we never
/// write a tombstone for it. Such a peer keeps one JOIN retry budget (ten
/// dials) and gets no JOIN. Each dial answers and the connection closes,
/// so the attempts are spaced by saorsa-gossip's loss cooldown (D252: nine
/// cooldowns of 100 ms doubled up to 25.6 s, 51.1 s plus up to 6.379 s of
/// jitter in total; no cooldown follows the tenth dial). This bound covers
/// that case and is used only there.
const REFUSAL_JOIN_BOUND: Duration = Duration::from_secs(150);

const JOIN_CONNECTING: &str = "JOIN: Connecting to bootstrap node";
const JOIN_RETRY: &str = "JOIN: Connection failed, will retry";
const JOIN_JOINED: &str = "JOIN: Successfully joined network";
/// saorsa-gossip logs this on the peer that receives a JOIN frame, with the
/// joiner's peer id (first 8 bytes, hex) in `new_peer`.
const JOIN_RECEIVED: &str = "HyParView: Received JOIN request";

const PROD_PLANE: &str = "x0x.test.prod";
const TESTNET_PLANE: &str = "x0x.test.testnet";

/// One captured JOIN event. `seq` orders all captured events.
#[derive(Debug, Clone)]
struct JoinEvent {
    seq: u64,
    message: String,
    seed: Option<String>,
    new_peer: Option<String>,
}

static JOIN_EVENTS: Mutex<Vec<JoinEvent>> = Mutex::new(Vec::new());

/// Order of all captured events (JOIN events, dial starts, refusals).
static EVENT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One captured plane refusal: who refused (`our_plane`) whom
/// (`peer_id_prefix`, first 4 bytes, hex).
#[derive(Debug, Clone)]
struct Refusal {
    seq: u64,
    our_plane: String,
    peer_id_prefix: String,
}

static REFUSALS: Mutex<Vec<Refusal>> = Mutex::new(Vec::new());
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
/// `join_network` Phase 0 logs this after its cache read, before it starts
/// its dials.
static PHASE0_START_GATE: Gate = Gate::new("Phase 0: Trying");
/// `join_network` Phase 1 logs this after its phase count and its cache
/// read, before it starts its dials.
static PHASE1_START_GATE: Gate = Gate::new("Phase 1: Trying");

/// `NetworkNode::connect_addr_with_origin` logs this (target
/// `x0x::connect`, debug) when an address dial starts, with the address in
/// `addr`. Every `join_network` address dial goes through it.
const DIAL_STARTED: &str = "starting direct dial";

/// Captured [`DIAL_STARTED`] events: `(seq, address)`, in order.
static DIAL_STARTS: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());

/// `NetworkNode::connect_peer_with_addrs` logs an event (target
/// `x0x::connect`, debug, no message) with this `strategy` when a dial by
/// peer id starts. A cached-peer dial goes through it.
const PEER_DIAL_STRATEGY: &str = "peer_with_addrs";

/// Captured [`PEER_DIAL_STRATEGY`] events: `(seq, peer id prefix)`.
static PEER_DIAL_STARTS: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());

/// A spawned address-dial task of `join_network` logs this (debug, target
/// `x0x`) after the parent's token check and before its dial.
static ADDR_DIAL_TASK_GATE: Gate = Gate::new("Connecting to peer: ");
/// A spawned cached-peer dial task of `join_network` logs this (debug,
/// target `x0x`) after the parent's token check and before its dial.
static CACHED_DIAL_TASK_GATE: Gate = Gate::new("Connecting to cached peer: ");

/// `plane_handle_hello` logs this (warn) before it refuses a peer.
const PLANE_REFUSED: &str = "gossip-plane mismatch: refusing cross-plane peer (issue #206)";

#[derive(Default)]
struct JoinVisitor {
    message: String,
    seed: Option<String>,
    new_peer: Option<String>,
    addr: Option<String>,
    our_plane: Option<String>,
    peer_id_prefix: Option<String>,
    strategy: Option<String>,
}

impl Visit for JoinVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = value.to_string(),
            "seed" => self.seed = Some(value.to_string()),
            "new_peer" => self.new_peer = Some(value.to_string()),
            "addr" => self.addr = Some(value.to_string()),
            "our_plane" => self.our_plane = Some(value.to_string()),
            "peer_id_prefix" => self.peer_id_prefix = Some(value.to_string()),
            "strategy" => self.strategy = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "seed" => self.seed = Some(format!("{value:?}")),
            "new_peer" => self.new_peer = Some(format!("{value:?}")),
            "addr" => self.addr = Some(format!("{value:?}")),
            "our_plane" => self.our_plane = Some(format!("{value:?}")),
            "peer_id_prefix" => self.peer_id_prefix = Some(format!("{value:?}")),
            "strategy" => self.strategy = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

struct JoinCapture;

impl<S: tracing::Subscriber> Layer<S> for JoinCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = JoinVisitor::default();
        event.record(&mut visitor);
        let seq = EVENT_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if visitor.message.starts_with("JOIN:") || visitor.message.starts_with(JOIN_RECEIVED) {
            JOIN_EVENTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(JoinEvent {
                    seq,
                    message: visitor.message.clone(),
                    seed: visitor.seed.clone(),
                    new_peer: visitor.new_peer.clone(),
                });
        }
        if visitor.message == DIAL_STARTED {
            if let Some(addr) = visitor.addr.clone() {
                DIAL_STARTS
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push((seq, addr));
            }
        }
        if visitor.strategy.as_deref() == Some(PEER_DIAL_STRATEGY) {
            if let Some(prefix) = visitor.peer_id_prefix.clone() {
                PEER_DIAL_STARTS
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push((seq, prefix));
            }
        }
        if visitor.message == PLANE_REFUSED {
            if let (Some(our_plane), Some(peer_id_prefix)) =
                (visitor.our_plane.clone(), visitor.peer_id_prefix.clone())
            {
                REFUSALS
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(Refusal {
                        seq,
                        our_plane,
                        peer_id_prefix,
                    });
            }
        }
        JOIN_COMPLETE_GATE.pass(&visitor.message);
        RECONNECT_GATE.pass(&visitor.message);
        PLANE_REFUSAL_GATE.pass(&visitor.message);
        PHASE0_START_GATE.pass(&visitor.message);
        PHASE1_START_GATE.pass(&visitor.message);
        ADDR_DIAL_TASK_GATE.pass(&visitor.message);
        CACHED_DIAL_TASK_GATE.pass(&visitor.message);
    }
}

/// How many dials by peer id to `peer` have started.
fn peer_dials_started_to(peer: ant_quic::PeerId) -> usize {
    let prefix: String = peer.0[..4].iter().map(|b| format!("{b:02x}")).collect();
    PEER_DIAL_STARTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|(_, started)| *started == prefix)
        .count()
}

/// How many address dials to `addr` have started.
fn dials_started_to(addr: SocketAddr) -> usize {
    dials_started_to_after(addr, 0)
}

/// How many address dials to `addr` started after event `after`.
fn dials_started_to_after(addr: SocketAddr, after: u64) -> usize {
    dial_seqs_to(addr)
        .iter()
        .filter(|seq| **seq > after)
        .count()
}

/// The `seq` of each address dial to `addr`.
fn dial_seqs_to(addr: SocketAddr) -> Vec<u64> {
    let addr = addr.to_string();
    DIAL_STARTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|(_, started)| *started == addr)
        .map(|(seq, _)| *seq)
        .collect()
}

/// The next event sequence number: every event captured from now on has a
/// larger `seq`.
fn seq_mark() -> u64 {
    EVENT_SEQ.load(std::sync::atomic::Ordering::SeqCst)
}

/// The `seq` of the first refusal of `peer` by an agent on `our_plane`.
fn first_refusal_of(peer: ant_quic::PeerId, our_plane: &str) -> Option<u64> {
    let prefix: String = peer.0[..4].iter().map(|b| format!("{b:02x}")).collect();
    REFUSALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|refusal| refusal.our_plane == our_plane && refusal.peer_id_prefix == prefix)
        .map(|refusal| refusal.seq)
        .min()
}

/// Install the process-global capture of saorsa-gossip membership events,
/// x0x info events (the gate events) and x0x connect debug events (dial
/// starts). Only these targets are enabled, so other crates' callsites stay
/// disabled.
fn install_join_capture() {
    install_capture(tracing::Level::INFO);
}

/// [`install_join_capture`] with every x0x debug event too (the dial-task
/// events). Each nextest test runs in its own process, so only the test
/// that calls this pays for the extra events.
fn install_join_capture_with_x0x_debug() {
    install_capture(tracing::Level::DEBUG);
}

fn install_capture(x0x_level: tracing::Level) {
    CAPTURE.get_or_init(|| {
        let targets = tracing_subscriber::filter::Targets::new()
            .with_target("saorsa_gossip_membership", tracing::Level::DEBUG)
            .with_target("x0x", x0x_level)
            .with_target("x0x::connect", tracing::Level::DEBUG);
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

/// Run `agent.join_network()` until it returns, until a JOIN through
/// `watch` succeeds, or until `bound`. Returns `Some(result)` when the join
/// returned.
async fn join_watching(
    agent: &Agent,
    watch: SocketAddr,
    bound: Duration,
) -> Option<x0x::error::Result<()>> {
    let join = agent.join_network();
    tokio::pin!(join);
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        tokio::select! {
            result = &mut join => return Some(result),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if count(&join_events_for(watch), JOIN_JOINED) > 0
                    || tokio::time::Instant::now() >= deadline
                {
                    return None;
                }
            }
        }
    }
}

/// The JOIN oracle for a cross-plane peer `peer` at `addr` that `joiner`
/// (on `PROD_PLANE`) dialled.
///
/// - No JOIN through it succeeds, and it receives no JOIN frame.
/// - If the joiner refused it (tombstone) before the first JOIN attempt of
///   the join (the saorsa-6 shape of #1321), no JOIN attempt goes to it.
/// - Otherwise the remote refused us first and we never got its hello, so
///   there is no tombstone. Then it gets at most one old JOIN budget: ten
///   attempts.
fn assert_cross_plane_peer_not_joined(peer: ant_quic::PeerId, addr: SocketAddr, joiner: [u8; 32]) {
    let events = join_events_for(addr);
    assert_eq!(
        count(&events, JOIN_JOINED),
        0,
        "no JOIN may succeed through cross-plane peer {addr}: {events:?}"
    );
    assert_eq!(
        joins_received_from(joiner),
        0,
        "cross-plane peer {addr} must receive no JOIN frame"
    );
    let first_attempt = JOIN_EVENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|event| event.message == JOIN_CONNECTING)
        .map(|event| event.seq)
        .min()
        .unwrap_or(u64::MAX);
    match first_refusal_of(peer, PROD_PLANE) {
        Some(refused) if refused < first_attempt => assert!(
            events.is_empty(),
            "cross-plane peer {addr} was refused before the JOIN started: it must \
             get no JOIN attempt and no JOIN retry: {events:?}"
        ),
        _ => assert!(
            count(&events, JOIN_CONNECTING) <= 10,
            "cross-plane peer {addr} that refused us first may get at most one \
             old JOIN budget (ten attempts): {events:?}"
        ),
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
    let joined = join_watching(&prod, testnet_addr, REFUSAL_JOIN_BOUND).await;

    assert!(
        drain_connected(&mut prod_events).contains(&testnet_peer.0),
        "scenario: the join must dial the cached cross-plane peer successfully \
         (that dial result is what reached the JOIN seeds on saorsa-6)"
    );
    assert_cross_plane_peer_not_joined(testnet_peer, testnet_addr, prod.machine_id().0);
    assert!(
        matches!(joined, Some(Ok(()))),
        "join_network must finish within {REFUSAL_JOIN_BOUND:?}: {joined:?}"
    );
    drop(silent);
}

/// The other ordering: no slow cached dial, so Phase 1 ends as soon as the
/// cross-plane dial returns and the JOIN can start before either plane
/// hello is processed. The peer must still not become a seed.
///
/// #1403: the testnet peer refuses prod before prod joins (a
/// `PolicyRejection` tombstone, as after a first contact). So the test
/// takes the long branch on every run: testnet closes each prod connection
/// at accept, prod gets no hello and writes no tombstone, and each JOIN
/// attempt answers and then loses its connection. Before #1403 the legacy
/// grace clock could carry over from an earlier connection generation, and
/// attempt 9 or 10 then joined through the refused peer (about 1 run in 6
/// on this branch).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1321_cross_plane_peer_refused_after_phase1_is_not_a_join_seed() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (testnet, testnet_peer, testnet_addr) =
        remote_agent(dir.path(), "testnet", Some("x0x.test.testnet")).await;
    let prod = build_agent(dir.path(), "prod", Some("x0x.test.prod")).await;
    cache_peer(&prod, testnet_peer, testnet_addr).await;

    // The long branch: testnet already refused prod. Prod is not connected
    // yet, so the transport disconnect can fail; the tombstone is written
    // before it.
    let prod_peer = ant_quic::PeerId(prod.machine_id().0);
    let testnet_network = testnet.network().expect("testnet network");
    let _ = testnet_network
        .disconnect_with_reason(&prod_peer, DisconnectReason::PolicyRejection)
        .await;
    assert!(
        testnet_network.is_reconnect_suppressed(prod_peer.0),
        "scenario: testnet must hold a PolicyRejection tombstone for prod"
    );

    let prod_network = prod.network().expect("prod network");
    let mut prod_events = prod_network.subscribe();
    let joined = join_watching(&prod, testnet_addr, REFUSAL_JOIN_BOUND).await;

    assert!(
        drain_connected(&mut prod_events).contains(&testnet_peer.0),
        "scenario: the join must dial the cached cross-plane peer successfully"
    );
    assert_cross_plane_peer_not_joined(testnet_peer, testnet_addr, prod.machine_id().0);
    assert!(
        matches!(joined, Some(Ok(()))),
        "join_network must finish within {REFUSAL_JOIN_BOUND:?}: {joined:?}"
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
/// released, if the join has not returned before.
const RECONNECT_HOLD: Duration = Duration::from_secs(3);

/// Upper bound for a join that waits for transport recovery: the reconnect
/// hold, one redial, and the JOIN.
const RECOVERY_JOIN_BOUND: Duration = Duration::from_secs(60);

/// Upper bound for the join when the proactive reconnect stays in flight.
/// The round-2 code (8a60712) gave up after a fixed 49.2 s. The old JOIN
/// retried one seed for about 81 s of backoff plus dial time.
const SLOW_RECONNECT_JOIN_BOUND: Duration = Duration::from_secs(150);

/// Upper bound for a join after shutdown began.
const SHUTDOWN_JOIN_BOUND: Duration = Duration::from_secs(5);

/// How long a test waits for all plane refusals to reach the closed
/// refusal gate. Well inside the 10 s plane legacy grace, after which an
/// open verdict reads as admitted.
const REFUSAL_HOLD_BOUND: Duration = Duration::from_secs(5);

/// The transient-loss scenario, held at the seed read.
struct TransientLoss {
    _peer_agent: Agent,
    peer_addr: SocketAddr,
    prod: Arc<Agent>,
    join: tokio::task::JoinHandle<x0x::error::Result<()>>,
    /// Event mark taken just before the seed read was released.
    released: u64,
}

/// The sole same-plane candidate answers the Phase 1 dial. Then it loses
/// its transport connection before the join reads its JOIN seed verdicts.
///
/// Gates fix the event order:
/// 1. `JOIN_COMPLETE_GATE` holds `join_network` after its dials and before
///    its first seed read. The test drops the connection with a
///    transport-reason disconnect (no tombstone) and waits until the agent
///    reports the peer as not connected.
/// 2. `RECONNECT_GATE` holds every proactive redial. The test waits until
///    the proactive reconnect for the lost peer reaches the gate. Only then
///    does it open `JOIN_COMPLETE_GATE`. So the peer is not connected when
///    the join reads its verdict.
///
/// `RECONNECT_GATE` stays closed when this returns.
async fn transient_loss_at_seed_read(dir: &std::path::Path) -> TransientLoss {
    let (peer_agent, peer, peer_addr) = remote_agent(dir, "peer", Some(PROD_PLANE)).await;
    let prod = Arc::new(build_agent(dir, "prod", Some(PROD_PLANE)).await);
    cache_peer(&prod, peer, peer_addr).await;
    let prod_network = Arc::clone(prod.network().expect("prod network"));

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
    assert!(
        RECONNECT_GATE.wait_held(1, Duration::from_secs(10)).await,
        "scenario: the proactive reconnect for the lost peer must reach \
         RECONNECT_GATE before the seed read"
    );
    assert_eq!(
        prod_network.peer_admission(&peer).await,
        PeerAdmission::NotConnected,
        "scenario: a transport loss must leave no tombstone, and the held \
         reconnect must not have restored the peer"
    );
    let released = seq_mark();
    JOIN_COMPLETE_GATE.open();
    TransientLoss {
        _peer_agent: peer_agent,
        peer_addr,
        prod,
        join,
        released,
    }
}

/// The JOIN reached `peer_addr` once, with no retries, and the peer received
/// the JOIN frame from `joiner`.
async fn assert_join_reached(peer_addr: SocketAddr, joiner: [u8; 32], context: &str) {
    let events = join_events_for(peer_addr);
    assert_eq!(count(&events, JOIN_RETRY), 0, "no JOIN retries: {events:?}");
    assert_eq!(
        count(&events, JOIN_JOINED),
        1,
        "{context}: the JOIN must reach the same-plane peer {peer_addr}: {events:?}"
    );
    assert!(
        wait_join_received_from(joiner, Duration::from_secs(10)).await,
        "{context}: the peer must receive the JOIN frame (overlay membership, \
         not only a return)"
    );
}

/// Codex round-1 finding 1. After the transient loss, the proactive
/// reconnect is released within [`RECONNECT_HOLD`]. The JOIN must still
/// reach the peer. (The code before round 1 kept the address, and the JOIN
/// redialled it.)
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_transient_loss_before_seed_read_still_joins_after_reconnect() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let scenario = transient_loss_at_seed_read(dir.path()).await;
    let prod_id = scenario.prod.machine_id().0;

    let hold_deadline = tokio::time::Instant::now() + RECONNECT_HOLD;
    while !scenario.join.is_finished() && tokio::time::Instant::now() < hold_deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    RECONNECT_GATE.open();

    let joined = tokio::time::timeout(RECOVERY_JOIN_BOUND, scenario.join).await;
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must finish within {RECOVERY_JOIN_BOUND:?}: {joined:?}"
    );
    assert_join_reached(
        scenario.peer_addr,
        prod_id,
        "the lost candidate must not be dropped as a seed after one not-connected read",
    )
    .await;
}

/// Codex re-review of 8a60712, finding 1. After the transient loss, the
/// proactive reconnect stays in flight (held at `RECONNECT_GATE`) until the
/// join returns. The round-2 code waited a fixed 49.2 s for it and then
/// skipped the JOIN. The old JOIN retried the seed itself (ten attempts,
/// about 81 s of backoff plus dial time), so a fixed limit shorter than a
/// reconnect in flight must not end the recovery. The JOIN must reach the
/// peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_reconnect_slower_than_a_fixed_recovery_limit_still_joins() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let mut scenario = transient_loss_at_seed_read(dir.path()).await;
    let prod_id = scenario.prod.machine_id().0;

    let joined = tokio::time::timeout(SLOW_RECONNECT_JOIN_BOUND, &mut scenario.join).await;
    RECONNECT_GATE.open();
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must finish within {SLOW_RECONNECT_JOIN_BOUND:?}: {joined:?}"
    );
    assert_join_reached(
        scenario.peer_addr,
        prod_id,
        "a proactive reconnect still in flight must not end the seed recovery",
    )
    .await;
}

/// The late-refusal scenario, held at the phase decisions.
struct LateRefusals {
    _testnet_agents: Vec<Agent>,
    testnet: Vec<(ant_quic::PeerId, SocketAddr)>,
    prod: Arc<Agent>,
    prod_network: Arc<x0x::network::NetworkNode>,
    join: tokio::task::JoinHandle<x0x::error::Result<()>>,
}

/// Three cached cross-plane peers answer the Phase 1 dials. Their plane
/// verdicts are still open when the join counts its peers, so they fill
/// `min_connected` and the join skips Phase 2 (`bootstrap`).
///
/// Gates fix the event order:
/// 1. `PLANE_REFUSAL_GATE` holds every plane-mismatch refusal, before its
///    tombstone and disconnect. The test waits until all four are held:
///    prod's (one receive loop, so one at a time) and one on each testnet
///    peer.
/// 2. `JOIN_COMPLETE_GATE` holds `join_network` after its phase decisions.
///    The test checks that all three peers are connected with an open plane
///    verdict.
///
/// Both gates stay closed when this returns.
async fn late_refusals_at_phase_decisions(
    dir: &std::path::Path,
    bootstrap_nodes: Vec<SocketAddr>,
) -> LateRefusals {
    let mut testnet_agents = Vec::new();
    let mut testnet = Vec::new();
    for name in ["testnet-a", "testnet-b", "testnet-c"] {
        let (agent, peer, addr) = remote_agent(dir, name, Some(TESTNET_PLANE)).await;
        testnet_agents.push(agent);
        testnet.push((peer, addr));
    }
    let prod =
        Arc::new(build_agent_with_bootstrap(dir, "prod", Some(PROD_PLANE), bootstrap_nodes).await);
    for (peer, addr) in &testnet {
        cache_peer(&prod, *peer, *addr).await;
    }
    let prod_network = Arc::clone(prod.network().expect("prod network"));

    PLANE_REFUSAL_GATE.arm();
    JOIN_COMPLETE_GATE.arm();
    let join = spawn_join(&prod);

    assert!(
        JOIN_COMPLETE_GATE.wait_held(1, JOIN_BOUND).await,
        "scenario: join_network must reach the end of its dial phases"
    );
    assert!(
        PLANE_REFUSAL_GATE.wait_held(4, REFUSAL_HOLD_BOUND).await,
        "scenario: the plane refusals on prod and on the three testnet peers \
         must be held at PLANE_REFUSAL_GATE (held: {})",
        PLANE_REFUSAL_GATE.held()
    );
    // Exactly four: prod's single receive loop is held on its first refusal,
    // and each testnet peer is held on its refusal of prod.
    assert_eq!(
        PLANE_REFUSAL_GATE.held(),
        4,
        "scenario: exactly four refusals are held"
    );
    for (peer, addr) in &testnet {
        assert_eq!(
            prod_network.peer_admission(peer).await,
            PeerAdmission::PlanePending,
            "scenario: cross-plane peer {addr} must be connected, with its plane \
             verdict still open, at the phase decisions"
        );
    }
    LateRefusals {
        _testnet_agents: testnet_agents,
        testnet,
        prod,
        prod_network,
        join,
    }
}

/// Codex round-1 finding 2. The refusals land after the phase decisions.
/// The join must then still fall back to the reachable same-plane bootstrap
/// node.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_late_refused_peers_at_min_connected_keep_bootstrap_fallback() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_boot_agent, _boot, boot_addr) = remote_agent(dir.path(), "boot", Some(PROD_PLANE)).await;
    let scenario = late_refusals_at_phase_decisions(dir.path(), vec![boot_addr]).await;
    let prod_id = scenario.prod.machine_id().0;
    assert!(
        join_events_for(boot_addr).is_empty(),
        "scenario: no JOIN before the gates open"
    );
    PLANE_REFUSAL_GATE.open();
    JOIN_COMPLETE_GATE.open();

    let joined = tokio::time::timeout(JOIN_BOUND, scenario.join).await;
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must finish within {JOIN_BOUND:?}: {joined:?}"
    );
    for (peer, addr) in &scenario.testnet {
        let events = join_events_for(*addr);
        assert!(
            events.is_empty(),
            "cross-plane peer {addr} must not be a JOIN seed: {events:?}"
        );
        assert_ne!(
            scenario.prod_network.peer_admission(peer).await,
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

/// No JOIN from `joiner` reached any captured seed or peer.
fn assert_no_join(joiner: [u8; 32], seeds: &[SocketAddr]) {
    for seed in seeds {
        let events = join_events_for(*seed);
        assert!(
            events.is_empty(),
            "after shutdown began, no JOIN may go to {seed}: {events:?}"
        );
    }
    assert_eq!(
        joins_received_from(joiner),
        0,
        "after shutdown began, no peer may receive a JOIN from the joiner"
    );
}

/// Codex re-review of 8a60712, finding 2. Shutdown begins (`begin_shutdown`,
/// which keeps the transport up while the embedder drains its tasks) while
/// `join_network` is held before its seed settlement. The settlement then
/// returns early with no admitted peer. The join must not start the
/// fallback bootstrap phase, and it must not send a JOIN.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_shutdown_before_seed_settlement_starts_no_fallback_or_join() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_boot_agent, boot, boot_addr) = remote_agent(dir.path(), "boot", Some(PROD_PLANE)).await;
    let scenario = late_refusals_at_phase_decisions(dir.path(), vec![boot_addr]).await;
    let prod_id = scenario.prod.machine_id().0;

    scenario.prod.begin_shutdown();
    // The refusals stay held, so the plane verdicts stay open: only the
    // shutdown can end the settlement early.
    JOIN_COMPLETE_GATE.open();
    let joined = tokio::time::timeout(SHUTDOWN_JOIN_BOUND, scenario.join).await;
    PLANE_REFUSAL_GATE.open();

    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must return within {SHUTDOWN_JOIN_BOUND:?} after shutdown began: {joined:?}"
    );
    assert_eq!(
        dials_started_to(boot_addr),
        0,
        "shutdown began before the seed settlement: the join must not start the \
         fallback bootstrap dial"
    );
    assert!(
        !scenario.prod_network.is_connected(&boot).await,
        "the join must not connect to the bootstrap node after shutdown began"
    );
    let mut seeds: Vec<SocketAddr> = scenario.testnet.iter().map(|(_, addr)| *addr).collect();
    seeds.push(boot_addr);
    assert_no_join(prod_id, &seeds);
}

/// Codex re-review of 8a60712, finding 2. The fallback bootstrap phase has
/// started its dial to an address that never answers (a silent UDP socket).
/// Shutdown begins while that dial is in flight. The fallback dial batch
/// and its retry sleeps (10 s and 15 s) must stop on the shutdown token,
/// and the join must not send a JOIN.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_shutdown_stops_an_in_flight_fallback_bootstrap_dial() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    let scenario = late_refusals_at_phase_decisions(dir.path(), vec![silent_addr]).await;
    let prod_id = scenario.prod.machine_id().0;
    assert_eq!(
        dials_started_to(silent_addr),
        0,
        "scenario: the phase decisions must skip the bootstrap phase"
    );
    PLANE_REFUSAL_GATE.open();
    JOIN_COMPLETE_GATE.open();

    let dial_deadline = tokio::time::Instant::now() + JOIN_BOUND;
    while dials_started_to(silent_addr) == 0 {
        assert!(
            tokio::time::Instant::now() < dial_deadline,
            "scenario: after the late refusals, the join must start the fallback \
             bootstrap dial"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    scenario.prod.begin_shutdown();
    let joined = tokio::time::timeout(SHUTDOWN_JOIN_BOUND, scenario.join).await;
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "after shutdown began, the fallback dial batch and its retry sleeps must \
         stop: join_network must return within {SHUTDOWN_JOIN_BOUND:?}: {joined:?}"
    );
    let mut seeds: Vec<SocketAddr> = scenario.testnet.iter().map(|(_, addr)| *addr).collect();
    seeds.push(silent_addr);
    assert_no_join(prod_id, &seeds);
    drop(silent);
}

/// Codex re-review of 15e6192, finding 2. A recovered seed keeps one attempt
/// budget across the recovery and the JOIN. Here the lost peer answers the
/// join's first redial and is admitted at once (its plane was verified
/// before the loss), so the JOIN through it takes one attempt: one address
/// dial. (15e6192 dialled it twice: once in its recovery and once more in
/// the membership JOIN, which has its own ten-attempt budget.) The proactive
/// reconnect stays held until the join returns, so no other path dials.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_recovered_seed_keeps_one_attempt_budget_across_the_join() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let mut scenario = transient_loss_at_seed_read(dir.path()).await;
    let prod_id = scenario.prod.machine_id().0;

    let joined = tokio::time::timeout(SLOW_RECONNECT_JOIN_BOUND, &mut scenario.join).await;
    RECONNECT_GATE.open();
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must finish within {SLOW_RECONNECT_JOIN_BOUND:?}: {joined:?}"
    );
    assert_join_reached(
        scenario.peer_addr,
        prod_id,
        "the recovered seed must get the JOIN",
    )
    .await;
    assert_eq!(
        dials_started_to_after(scenario.peer_addr, scenario.released),
        1,
        "one successful JOIN attempt on a recovered seed is one address dial: \
         the recovery and the JOIN share one attempt budget"
    );
}

/// Upper bound for the join in the admitted-seed fallback control: the
/// fallback bootstrap phase (at most 3 x 15 s dials and 10 s + 15 s sleeps)
/// plus the settles and the JOIN.
const FALLBACK_JOIN_BOUND: Duration = Duration::from_secs(120);

/// Codex re-review of 15e6192, question 3: an admitted seed does not mean
/// an immediate JOIN. Phase 1 answers one same-plane peer and two
/// cross-plane peers whose plane verdicts are still open. The three fill
/// `min_connected`, so the phase decisions skip the bootstrap phase. The two
/// cross-plane peers are refused later. The settled admitted count (1) is
/// below the minimum, so the join first runs the skipped bootstrap phase.
/// Every bootstrap address here is silent, so that phase uses its full
/// schedule: three dials (each up to 15 s) and the 10 s and 15 s retry
/// sleeps. Only then does the JOIN go to the admitted peer. The old code
/// joined that peer at once. This control states the delay explicitly.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_admitted_seed_with_late_refusals_waits_for_the_bootstrap_fallback() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    let (_same_agent, same, same_addr) = remote_agent(dir.path(), "same", Some(PROD_PLANE)).await;
    let mut testnet_agents = Vec::new();
    let mut testnet = Vec::new();
    for name in ["testnet-a", "testnet-b"] {
        let (agent, peer, addr) = remote_agent(dir.path(), name, Some(TESTNET_PLANE)).await;
        testnet_agents.push(agent);
        testnet.push((peer, addr));
    }
    let prod = Arc::new(
        build_agent_with_bootstrap(dir.path(), "prod", Some(PROD_PLANE), vec![silent_addr]).await,
    );
    cache_peer(&prod, same, same_addr).await;
    for (peer, addr) in &testnet {
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
    assert!(
        PLANE_REFUSAL_GATE.wait_held(3, REFUSAL_HOLD_BOUND).await,
        "scenario: the plane refusals on prod and on the two testnet peers \
         must be held at PLANE_REFUSAL_GATE (held: {})",
        PLANE_REFUSAL_GATE.held()
    );
    assert_eq!(
        PLANE_REFUSAL_GATE.held(),
        3,
        "scenario: exactly three refusals are held"
    );
    for (peer, addr) in &testnet {
        assert_eq!(
            prod_network.peer_admission(peer).await,
            PeerAdmission::PlanePending,
            "scenario: cross-plane peer {addr} must be connected, with its plane \
             verdict still open, at the phase decisions"
        );
    }
    assert!(
        matches!(
            prod_network.peer_admission(&same).await,
            PeerAdmission::Admitted | PeerAdmission::PlanePending
        ),
        "scenario: the same-plane peer must be connected at the phase decisions"
    );
    assert_eq!(
        dials_started_to(silent_addr),
        0,
        "scenario: the phase decisions must skip the bootstrap phase"
    );
    let released = tokio::time::Instant::now();
    PLANE_REFUSAL_GATE.open();
    JOIN_COMPLETE_GATE.open();

    let joined = tokio::time::timeout(FALLBACK_JOIN_BOUND, join).await;
    let elapsed = released.elapsed();
    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must finish within {FALLBACK_JOIN_BOUND:?}: {joined:?}"
    );
    let events = join_events_for(same_addr);
    assert_eq!(
        count(&events, JOIN_JOINED),
        1,
        "the JOIN must go to the admitted same-plane peer: {events:?}"
    );
    assert!(
        wait_join_received_from(prod_id, Duration::from_secs(10)).await,
        "the same-plane peer must receive the JOIN frame"
    );
    let joined_seq = events
        .iter()
        .filter(|event| event.message == JOIN_JOINED)
        .map(|event| event.seq)
        .min()
        .unwrap_or(0);
    let silent_dials = dial_seqs_to(silent_addr);
    assert_eq!(
        silent_dials.len(),
        3,
        "the fallback bootstrap phase dials the silent address in all three rounds"
    );
    assert!(
        silent_dials.iter().all(|seq| *seq < joined_seq),
        "the JOIN to the admitted peer waits until the fallback phase has finished"
    );
    // The two retry sleeps (10 s + 15 s) are the floor. Three 15 s dial
    // timeouts and the 12 s settles bound it from above.
    assert!(
        elapsed >= Duration::from_secs(25),
        "fallback delay {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(25 + 3 * 15 + 3 * 12),
        "fallback delay {elapsed:?}"
    );
    for (_, addr) in &testnet {
        assert!(
            join_events_for(*addr).is_empty(),
            "cross-plane peer {addr} must not be a JOIN seed"
        );
    }
    drop(silent);
}

/// Codex re-review of bde6b2c, finding 2. The normal bootstrap phase (not
/// the fallback) has started its dial to an address that never answers (a
/// silent UDP socket). Shutdown begins while that dial is in flight. The
/// dial batch and its retry sleeps (10 s and 15 s) must stop on the shutdown
/// token. At bde6b2c the normal phases had no token, so the join ran the
/// whole schedule (three dials of up to 15 s and both sleeps).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_shutdown_stops_an_in_flight_normal_bootstrap_dial() {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    let prod = Arc::new(
        build_agent_with_bootstrap(dir.path(), "prod", Some(PROD_PLANE), vec![silent_addr]).await,
    );
    let join = spawn_join(&prod);

    let dial_deadline = tokio::time::Instant::now() + JOIN_BOUND;
    while dials_started_to(silent_addr) == 0 {
        assert!(
            tokio::time::Instant::now() < dial_deadline,
            "scenario: the normal bootstrap phase must start its dial"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    prod.begin_shutdown();
    let joined = tokio::time::timeout(SHUTDOWN_JOIN_BOUND, join).await;

    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "after shutdown began, the normal bootstrap dial batch and its retry \
         sleeps must stop: join_network must return within \
         {SHUTDOWN_JOIN_BOUND:?}: {joined:?}"
    );
    assert_eq!(
        dials_started_to(silent_addr),
        1,
        "no retry round may start after shutdown began"
    );
    drop(silent);
}

/// The count/start race of Codex's re-review of bde6b2c, finding 2. The
/// only cached peer is at an address that never answers (a silent UDP
/// socket); Phase 0 and Phase 1 both select it. `gate` holds the join after
/// one phase's cache read, just before that phase starts its dials. Then
/// shutdown begins and the gate opens.
async fn shutdown_at_phase_start(gate: &'static Gate) -> PhaseStartShutdown {
    install_join_capture();
    let dir = tempfile::tempdir().expect("tmpdir");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    let prod = Arc::new(build_agent(dir.path(), "prod", Some(PROD_PLANE)).await);
    cache_peer(&prod, ant_quic::PeerId([0x51; 32]), silent_addr).await;

    gate.arm();
    let join = spawn_join(&prod);
    assert!(
        gate.wait_held(1, JOIN_BOUND).await,
        "scenario: the phase must reach the start of its dials"
    );
    prod.begin_shutdown();
    gate.open();
    let joined = tokio::time::timeout(SHUTDOWN_JOIN_BOUND, join)
        .await
        .ok()
        .map(|joined| joined.expect("join task"));
    PhaseStartShutdown {
        joined,
        silent_addr,
        _silent: silent,
        _prod: prod,
        _dir: dir,
    }
}

/// The result of [`shutdown_at_phase_start`].
struct PhaseStartShutdown {
    /// The join's result; `None` when it did not return within
    /// [`SHUTDOWN_JOIN_BOUND`].
    joined: Option<x0x::error::Result<()>>,
    silent_addr: SocketAddr,
    _silent: std::net::UdpSocket,
    _prod: Arc<Agent>,
    _dir: tempfile::TempDir,
}

/// Codex re-review of bde6b2c, finding 2: Phase 0 checks the token after
/// its cache read. Shutdown begins just before Phase 0 starts its dials.
/// It must start no dial, and the join must return at once. At bde6b2c
/// Phase 0 had no token, so it dialled the silent address and waited up to
/// its 15 s dial timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_shutdown_at_the_start_of_phase0_starts_no_dial() {
    let run = shutdown_at_phase_start(&PHASE0_START_GATE).await;
    assert!(
        matches!(run.joined, Some(Ok(()))),
        "after shutdown began, Phase 0 must start no dial: join_network must \
         return within {SHUTDOWN_JOIN_BOUND:?}: {:?}",
        run.joined
    );
    assert_eq!(
        dials_started_to(run.silent_addr),
        0,
        "Phase 0 started a dial"
    );
}

/// Codex re-review of bde6b2c, finding 2 (a count/start race). Phase 0
/// dials the silent address and fails. Shutdown begins after the Phase 1
/// count and its cache read, just before Phase 1 starts its dials. Phase 1
/// must start no dial, and the join must return at once. (A Phase 1 dial
/// goes by peer id and logs no address dial, so the oracle is the time.)
/// At bde6b2c Phase 1 had no token, so it dialled the cached peer and
/// waited up to its 15 s dial timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_shutdown_between_the_phase1_count_and_its_dials_starts_no_dial() {
    let run = shutdown_at_phase_start(&PHASE1_START_GATE).await;
    assert!(
        matches!(run.joined, Some(Ok(()))),
        "after shutdown began, Phase 1 must start no dial: join_network must \
         return within {SHUTDOWN_JOIN_BOUND:?}: {:?}",
        run.joined
    );
    assert_eq!(
        dials_started_to(run.silent_addr),
        1,
        "scenario: only Phase 0 dialled the silent address"
    );
}

/// Codex re-review of dd36b40, finding 2. A spawned dial task of the
/// bootstrap phase is held at its "Connecting to peer" event: after the
/// parent's token check, before its dial. Shutdown begins, then the task
/// resumes. It must not start its dial (no address dial to the silent
/// address at all). At dd36b40 the task did not get the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_a_dial_task_starts_no_dial_after_shutdown() {
    install_join_capture_with_x0x_debug();
    let dir = tempfile::tempdir().expect("tmpdir");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    let prod = Arc::new(
        build_agent_with_bootstrap(dir.path(), "prod", Some(PROD_PLANE), vec![silent_addr]).await,
    );

    ADDR_DIAL_TASK_GATE.arm();
    let join = spawn_join(&prod);
    assert!(
        ADDR_DIAL_TASK_GATE.wait_held(1, JOIN_BOUND).await,
        "scenario: the bootstrap dial task must reach its start event"
    );
    prod.begin_shutdown();
    ADDR_DIAL_TASK_GATE.open();
    let joined = tokio::time::timeout(SHUTDOWN_JOIN_BOUND, join).await;
    // Give a resumed dial task time to start its dial.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must return within {SHUTDOWN_JOIN_BOUND:?}: {joined:?}"
    );
    assert_eq!(
        dials_started_to(silent_addr),
        0,
        "the dial task started its dial after shutdown began"
    );
    drop(silent);
}

/// Codex re-review of dd36b40, finding 2, the cached-peer helper. Phase 0
/// dials the cached peer's silent address and fails. Then a Phase 1 dial
/// task is held at its "Connecting to cached peer" event. Shutdown begins,
/// then the task resumes. It must not start its dial by peer id. At dd36b40
/// the task did not get the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn issue1321_a_cached_dial_task_starts_no_dial_after_shutdown() {
    install_join_capture_with_x0x_debug();
    let dir = tempfile::tempdir().expect("tmpdir");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    let prod = Arc::new(build_agent(dir.path(), "prod", Some(PROD_PLANE)).await);
    let cached = ant_quic::PeerId([0x51; 32]);
    cache_peer(&prod, cached, silent_addr).await;

    CACHED_DIAL_TASK_GATE.arm();
    let join = spawn_join(&prod);
    assert!(
        CACHED_DIAL_TASK_GATE.wait_held(1, JOIN_BOUND).await,
        "scenario: the Phase 1 dial task must reach its start event"
    );
    assert_eq!(
        peer_dials_started_to(cached),
        0,
        "scenario: no dial by peer id before the held task"
    );
    prod.begin_shutdown();
    CACHED_DIAL_TASK_GATE.open();
    let joined = tokio::time::timeout(SHUTDOWN_JOIN_BOUND, join).await;
    // Give a resumed dial task time to start its dial.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        matches!(joined, Ok(Ok(Ok(())))),
        "join_network must return within {SHUTDOWN_JOIN_BOUND:?}: {joined:?}"
    );
    assert_eq!(
        peer_dials_started_to(cached),
        0,
        "the cached-peer dial task started its dial after shutdown began"
    );
    drop(silent);
}
