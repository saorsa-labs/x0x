//! W3-H (#1164) deterministic simulation fabric. Test builds only.
//!
//! A [`SimFabric`] stands in for the network between several in-process
//! x0x daemons. Each node's [`super::NetworkNode`] runs on a [`SimLink`]
//! (the `Sim` arm of [`super::link::LinkNode`]) instead of an ant-quic
//! endpoint, so everything above the transport — the receive pump, plane
//! hello, session registry, gossip runtime, direct messages and the daemon's
//! listeners — is production code.
//!
//! Contracts (`.planning/team-2026-10-05/w3h-plan.md` §3):
//! - **Ordering (3e).** ant-quic opens one uni stream per send, so it
//!   guarantees no order between messages. The fabric deliberately models a
//!   stronger, documented order: strict FIFO within a lane
//!   `(src, dst, stream-type class)`. Between lane heads due at the same
//!   instant, the choice is a fixed seeded rank per lane, never the global
//!   order in which tasks happened to emit.
//! - **Trace (3d).** Every write is recorded when it is handed to the
//!   transport — immutable payload bytes, virtual write time, lane,
//!   sequence and connection — before any fault rule runs. Its fate
//!   (delivered, or dropped and why, including frames discarded when a
//!   link closes) is a separate event. Publish attempts are recorded before
//!   mesh fan-out, and refused sends (no live link) are recorded too.
//! - **Canonical form (3a).** [`SimFabric::canonical_trace`] renders the
//!   trace grouped per node, pair, lane and destination, in a fixed order,
//!   so the digest compares executions, not just outcomes. A harness can
//!   [`SimFabric::cut`] the trace: [`SimFabric::canonical_trace_until`]
//!   renders the events before the cut (the digested part) and
//!   [`SimFabric::trace_appendix`] the events after it.
//! - The fabric never reads the wall clock; all times are tokio virtual
//!   time since the fabric started.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::Waker;
use std::time::Duration;

use ant_quic::{
    ConnectionCloseReason, EndpointError, NodeError, PeerConnection, PeerId, PeerLifecycleEvent,
    Side, TransportAddr, TraversalMethod,
};
use saorsa_gossip_transport::GossipStreamType;
use tokio::sync::{broadcast, mpsc, oneshot, Notify};
use tokio::time::Instant;

/// A node's transport identity (its machine id / ant-quic peer id).
pub(crate) type Key = [u8; 32];

/// The ordered lane a frame travels on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum LaneClass {
    Direct,
    RelayedDm,
    PlaneHello,
    Membership,
    PubSub,
    Bulk,
    Other(u8),
    /// One direction of an application byte-stream (per-pair ordinal).
    Stream(u32),
}

impl LaneClass {
    fn of(bytes: &[u8]) -> Self {
        match bytes.first().copied() {
            Some(super::DIRECT_MESSAGE_STREAM_TYPE) => Self::Direct,
            Some(super::RELAYED_DM_STREAM_TYPE) => Self::RelayedDm,
            Some(super::PLANE_HELLO_STREAM_TYPE) => Self::PlaneHello,
            Some(byte) => match GossipStreamType::from_byte(byte) {
                Some(GossipStreamType::Membership) => Self::Membership,
                Some(GossipStreamType::PubSub) => Self::PubSub,
                Some(GossipStreamType::Bulk) => Self::Bulk,
                None => Self::Other(byte),
            },
            None => Self::Other(0),
        }
    }

    fn name(self) -> String {
        match self {
            Self::Direct => "direct".into(),
            Self::RelayedDm => "relayed_dm".into(),
            Self::PlaneHello => "plane_hello".into(),
            Self::Membership => "membership".into(),
            Self::PubSub => "pubsub".into(),
            Self::Bulk => "bulk".into(),
            Self::Other(byte) => format!("other_{byte:02x}"),
            Self::Stream(ordinal) => format!("stream{ordinal}"),
        }
    }
}

/// `(src, dst, class)`: frames on one lane are delivered in write order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LaneKey {
    pub(crate) src: Key,
    pub(crate) dst: Key,
    pub(crate) class: LaneClass,
}

/// One write, captured when the bytes were handed to the transport, before
/// any fault rule ran.
#[derive(Clone, Debug)]
pub(crate) struct Write {
    pub(crate) lane: LaneKey,
    /// Position on its lane, from 0.
    pub(crate) seq: u64,
    /// Which connection of this node pair carried it (0 = first).
    pub(crate) pair_ordinal: u64,
    /// Virtual time since the fabric started.
    pub(crate) at: Duration,
    pub(crate) bytes: Arc<[u8]>,
}

/// Why the transport refused a send outright.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefusalReason {
    /// No live link between the pair.
    NoLink,
    /// A pinned send named a connection generation that is no longer the
    /// live one (refused before admission, so no bytes were produced).
    GenerationSuperseded,
    /// A dial to a known node that is offline or partitioned away.
    Unreachable,
    /// A write on a stream that was already reset (or whose reader left).
    StreamReset,
    /// Bytes already in a stream that its reader had not read when the
    /// stream was reset. As with QUIC RESET_STREAM, they are discarded.
    ResetDiscarded,
}

/// A send the transport refused, with the bytes when there were any.
#[derive(Clone, Debug)]
pub(crate) struct Refusal {
    pub(crate) src: Key,
    pub(crate) dst: Key,
    pub(crate) class: Option<LaneClass>,
    pub(crate) at: Duration,
    pub(crate) reason: RefusalReason,
    pub(crate) bytes: Option<Arc<[u8]>>,
}

/// A fault decision for one write, made at send time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    Pass,
    Drop,
    Delay(Duration),
}

/// Why a write was not delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DropReason {
    /// A fault rule (by index) dropped it.
    Rule(usize),
    /// Its connection closed while it was in flight.
    LinkClosed,
    /// The destination was offline at its delivery instant.
    DestinationOffline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fate {
    Delivered { at: Duration },
    Dropped { at: Duration, reason: DropReason },
}

#[derive(Clone, Debug)]
enum NodeEventKind {
    Attached { incarnation: u64 },
    Online(bool),
    Detached,
}

#[derive(Clone, Debug)]
enum TraceEvent {
    Node {
        node: Key,
        at: Duration,
        kind: NodeEventKind,
    },
    Link {
        a: Key,
        b: Key,
        ordinal: u64,
        at: Duration,
        open: bool,
    },
    Write {
        index: usize,
        fault: Fault,
    },
    Fate {
        lane: LaneKey,
        seq: u64,
        fate: Fate,
    },
    /// A send the transport refused (no live link, or a pinned generation
    /// that is no longer current). `index` points into `refused` (bytes
    /// retained); admission refusals have no bytes yet.
    Refused {
        index: usize,
    },
    Publish {
        node: Key,
        at: Duration,
        topic: String,
        digest: [u8; 32],
    },
    Mark {
        at: Duration,
        text: String,
    },
    StreamOpen {
        opener: Key,
        acceptor: Key,
        ordinal: u32,
        at: Duration,
    },
    /// The reader of `lane` (one direction of a stream) read to its FIN.
    StreamFinRead {
        lane: LaneKey,
        at: Duration,
    },
}

/// The connection identity a session token binds to (see
/// `NetworkNode::current_session_for_peer`). Each simulated connection has
/// a fabric-unique generation and its own closed flag.
#[derive(Clone, Debug)]
pub(crate) struct SimConnection {
    generation: u64,
    closed: Arc<AtomicBool>,
}

impl SimConnection {
    pub(crate) fn stable_id(&self) -> usize {
        usize::try_from(self.generation).unwrap_or(usize::MAX)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

type FaultRule = Box<dyn Fn(&Write) -> Fault + Send + Sync>;

struct NodeSlot {
    addr: SocketAddr,
    online: bool,
    incarnation: u64,
    inbound: mpsc::UnboundedSender<(PeerId, u64, Vec<u8>)>,
    accept: mpsc::UnboundedSender<PeerConnection>,
    lifecycle: broadcast::Sender<(PeerId, PeerLifecycleEvent)>,
    streams: mpsc::UnboundedSender<(PeerId, SimSend, SimRecv)>,
}

struct LinkState {
    generation: u64,
    ordinal: u64,
    closed: Arc<AtomicBool>,
}

struct Queued {
    seq: u64,
    due: Instant,
    generation: u64,
    bytes: Arc<[u8]>,
    delivered: Option<oneshot::Sender<()>>,
}

#[derive(Default)]
struct LaneState {
    next_seq: u64,
    last_due: Option<Instant>,
    queue: VecDeque<Queued>,
}

struct FabricState {
    nodes: BTreeMap<Key, NodeSlot>,
    labels: BTreeMap<Key, String>,
    by_addr: BTreeMap<SocketAddr, Key>,
    links: BTreeMap<(Key, Key), LinkState>,
    pair_ordinals: BTreeMap<(Key, Key), u64>,
    stream_ordinals: BTreeMap<(Key, Key), u32>,
    open_streams: Vec<(u64, Arc<StreamPair>)>,
    partitions: BTreeSet<(Key, Key)>,
    rules: Vec<FaultRule>,
    lanes: BTreeMap<LaneKey, LaneState>,
    writes: Vec<Write>,
    refused: Vec<Refusal>,
    trace: Vec<TraceEvent>,
    next_generation: u64,
}

/// The shared in-memory network for one simulated scenario.
pub(crate) struct SimFabric {
    seed: u64,
    start: Instant,
    base_latency: Duration,
    jitter_us: u64,
    state: Mutex<FabricState>,
    wake: Notify,
}

fn pair(a: Key, b: Key) -> (Key, Key) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn stable_hash(parts: &[&[u8]]) -> u64 {
    // `DefaultHasher::new()` is SipHash with fixed zero keys: stable within
    // one toolchain, unlike `RandomState`.
    let mut hasher = std::hash::DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

fn not_connected(peer: &PeerId) -> NodeError {
    NodeError::Connection(format!(
        "sim: no live link to {}",
        hex::encode(&peer.0[..4])
    ))
}

fn micros(at: Duration) -> u128 {
    at.as_micros()
}

impl SimFabric {
    /// A fabric whose every scheduling choice derives from `seed`. Must be
    /// called inside the scenario's (paused, current-thread) runtime.
    pub(crate) fn new(seed: u64) -> Arc<Self> {
        let fabric = Arc::new(Self {
            seed,
            start: Instant::now(),
            base_latency: Duration::from_millis(2),
            jitter_us: 3_000,
            state: Mutex::new(FabricState {
                nodes: BTreeMap::new(),
                labels: BTreeMap::new(),
                by_addr: BTreeMap::new(),
                links: BTreeMap::new(),
                pair_ordinals: BTreeMap::new(),
                stream_ordinals: BTreeMap::new(),
                open_streams: Vec::new(),
                partitions: BTreeSet::new(),
                rules: Vec::new(),
                lanes: BTreeMap::new(),
                writes: Vec::new(),
                refused: Vec::new(),
                trace: Vec::new(),
                next_generation: 1,
            }),
            wake: Notify::new(),
        });
        let pump = Arc::clone(&fabric);
        tokio::spawn(async move { pump.run_pump().await });
        fabric
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FabricState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Virtual time since the fabric started.
    pub(crate) fn now(&self) -> Duration {
        Instant::now().saturating_duration_since(self.start)
    }

    /// Name a node for the canonical trace.
    pub(crate) fn label(&self, node: &PeerId, name: &str) {
        self.lock().labels.insert(node.0, name.to_string());
    }

    /// Add a fault rule. Rules are consulted in insertion order and the
    /// first non-`Pass` decision wins.
    pub(crate) fn add_rule(&self, rule: impl Fn(&Write) -> Fault + Send + Sync + 'static) {
        self.lock().rules.push(Box::new(rule));
    }

    /// Take a node off the network (crash or power-off), or bring it back.
    /// Going offline closes every link; frames in flight are dropped with
    /// [`DropReason::LinkClosed`].
    pub(crate) fn set_online(&self, node: &PeerId, online: bool) {
        let at = self.now();
        let mut state = self.lock();
        if let Some(slot) = state.nodes.get_mut(&node.0) {
            slot.online = online;
        }
        state.trace.push(TraceEvent::Node {
            node: node.0,
            at,
            kind: NodeEventKind::Online(online),
        });
        if !online {
            Self::close_all_locked(&mut state, node.0, ConnectionCloseReason::PeerShutdown, at);
        }
    }

    /// Partition `a` from `b` (closing any live link) or heal it.
    pub(crate) fn set_partitioned(&self, a: &PeerId, b: &PeerId, partitioned: bool) {
        let at = self.now();
        let mut state = self.lock();
        let key = pair(a.0, b.0);
        if partitioned {
            state.partitions.insert(key);
            Self::close_link_locked(&mut state, key, ConnectionCloseReason::LifecycleCleanup, at);
        } else {
            state.partitions.remove(&key);
        }
    }

    /// Record a harness event (barrier, receipt, fault step) in the trace.
    pub(crate) fn mark(&self, text: impl Into<String>) {
        let at = self.now();
        self.lock().trace.push(TraceEvent::Mark {
            at,
            text: text.into(),
        });
    }

    /// [`Self::mark`], returning the mark's trace position. A trace
    /// position orders events that share one virtual instant, which their
    /// timestamps cannot.
    pub(crate) fn mark_indexed(&self, text: impl Into<String>) -> usize {
        let at = self.now();
        let mut state = self.lock();
        state.trace.push(TraceEvent::Mark {
            at,
            text: text.into(),
        });
        state.trace.len().saturating_sub(1)
    }

    /// Writes from `src` to `dst` whose delivery comes after trace position
    /// `after`, in delivery order, each with its delivery's trace position.
    /// A delivery is recorded when the bytes reach the destination's
    /// inbound queue, so it precedes everything the destination does with
    /// them.
    pub(crate) fn delivered_writes_after(
        &self,
        src: &PeerId,
        dst: &PeerId,
        after: usize,
    ) -> Vec<(Write, usize)> {
        let state = self.lock();
        let writes: BTreeMap<(LaneKey, u64), &Write> = state
            .writes
            .iter()
            .filter(|write| write.lane.src == src.0 && write.lane.dst == dst.0)
            .map(|write| ((write.lane, write.seq), write))
            .collect();
        state
            .trace
            .iter()
            .enumerate()
            .skip(after.saturating_add(1))
            .filter_map(|(position, event)| match event {
                TraceEvent::Fate {
                    lane,
                    seq,
                    fate: Fate::Delivered { .. },
                } => writes
                    .get(&(*lane, *seq))
                    .map(|write| ((*write).clone(), position)),
                _ => None,
            })
            .collect()
    }

    /// Raw payload dump for offline analysis and the ADR 0108 privacy
    /// audit: every write (in acceptance order) and every refused send that
    /// carried bytes, each as a UTF-8 header line followed by the raw bytes
    /// and a newline:
    /// `W <src>-><dst> <class> #<seq> w@<us> len=<n>` /
    /// `R <src>-><dst> <class> @<us> <reason> len=<n>`.
    /// Stops (with a `TRUNCATED` line) before exceeding `cap` bytes.
    pub(crate) fn payload_dump(&self, cap: usize) -> Vec<u8> {
        let state = self.lock();
        let mut out = Vec::new();
        let push = |header: String, bytes: &[u8], out: &mut Vec<u8>| -> bool {
            if out.len() + header.len() + bytes.len() + 2 > cap {
                out.extend_from_slice(b"TRUNCATED\n");
                return false;
            }
            out.extend_from_slice(header.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(bytes);
            out.push(b'\n');
            true
        };
        for write in &state.writes {
            let header = format!(
                "W {} #{} w@{}us len={}",
                Self::lane_name(&state, &write.lane),
                write.seq,
                micros(write.at),
                write.bytes.len()
            );
            if !push(header, &write.bytes, &mut out) {
                return out;
            }
        }
        for refusal in &state.refused {
            if let Some(bytes) = &refusal.bytes {
                let header = format!(
                    "R {}->{} {} @{}us {:?} len={}",
                    Self::name(&state, &refusal.src),
                    Self::name(&state, &refusal.dst),
                    refusal.class.map_or("connect".to_string(), LaneClass::name),
                    micros(refusal.at),
                    refusal.reason,
                    bytes.len()
                );
                if !push(header, bytes, &mut out) {
                    return out;
                }
            }
        }
        out
    }

    /// Every write so far, in the order the fabric accepted them.
    pub(crate) fn writes(&self) -> Vec<Write> {
        self.lock().writes.clone()
    }

    fn name(state: &FabricState, node: &Key) -> String {
        state
            .labels
            .get(node)
            .cloned()
            .unwrap_or_else(|| hex::encode(&node[..4]))
    }

    fn lane_name(state: &FabricState, lane: &LaneKey) -> String {
        format!(
            "{}->{} {}",
            Self::name(state, &lane.src),
            Self::name(state, &lane.dst),
            lane.class.name()
        )
    }

    fn note_fin_read(&self, lane: LaneKey) {
        let at = self.now();
        self.lock()
            .trace
            .push(TraceEvent::StreamFinRead { lane, at });
    }

    /// When the reader of `lane` (one direction of a stream) read to its
    /// FIN, if it did.
    pub(crate) fn fin_read_at(&self, lane: &LaneKey) -> Option<Duration> {
        self.lock().trace.iter().find_map(|event| match event {
            TraceEvent::StreamFinRead { lane: read, at } if read == lane => Some(*at),
            _ => None,
        })
    }

    /// Record `text` as a mark and return the trace position just after it,
    /// for [`Self::canonical_trace_until`] and [`Self::trace_appendix`].
    pub(crate) fn cut(&self, text: impl Into<String>) -> usize {
        let at = self.now();
        let mut state = self.lock();
        state.trace.push(TraceEvent::Mark {
            at,
            text: text.into(),
        });
        state.trace.len()
    }

    /// The canonical semantic trace: grouped per node, pair, lane and
    /// destination in a fixed order, so two executions compare equal only
    /// if every node wrote the same bytes on the same lanes at the same
    /// virtual times, with the same fates.
    pub(crate) fn canonical_trace(&self) -> String {
        let state = self.lock();
        self.render(&state, &state.trace, "canonical trace")
    }

    /// The canonical trace of the events recorded before `cut` (from
    /// [`Self::cut`]). A write whose fate is recorded after the cut renders
    /// as `in-flight`.
    pub(crate) fn canonical_trace_until(&self, cut: usize) -> String {
        let state = self.lock();
        let end = cut.min(state.trace.len());
        self.render(&state, &state.trace[..end], "canonical trace")
    }

    /// The events recorded at or after `cut`, rendered like the canonical
    /// trace. A fate whose write precedes the cut is listed under its lane
    /// as `#<seq> (written before the cut) -> <fate>`.
    pub(crate) fn trace_appendix(&self, cut: usize) -> String {
        let state = self.lock();
        let start = cut.min(state.trace.len());
        self.render(&state, &state.trace[start..], "trace appendix")
    }

    fn render(&self, state: &FabricState, events: &[TraceEvent], title: &str) -> String {
        let mut nodes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut links: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut lanes: BTreeMap<String, BTreeMap<u64, String>> = BTreeMap::new();
        let mut fates: BTreeMap<(String, u64), String> = BTreeMap::new();
        let mut deliveries: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut refusals: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut publishes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut marks: Vec<String> = Vec::new();
        for event in events {
            match event {
                TraceEvent::Node { node, at, kind } => {
                    let what = match kind {
                        NodeEventKind::Attached { incarnation } => {
                            format!("attached inc={incarnation}")
                        }
                        NodeEventKind::Online(true) => "online".to_string(),
                        NodeEventKind::Online(false) => "offline".to_string(),
                        NodeEventKind::Detached => "detached".to_string(),
                    };
                    nodes
                        .entry(Self::name(state, node))
                        .or_default()
                        .push(format!("{what}@{}us", micros(*at)));
                }
                TraceEvent::Link {
                    a,
                    b,
                    ordinal,
                    at,
                    open,
                } => {
                    let (na, nb) = (Self::name(state, a), Self::name(state, b));
                    let key = if na <= nb {
                        format!("{na}~{nb}")
                    } else {
                        format!("{nb}~{na}")
                    };
                    links.entry(key).or_default().push(format!(
                        "#{ordinal} {}@{}us",
                        if *open { "open" } else { "close" },
                        micros(*at)
                    ));
                }
                TraceEvent::Write { index, fault } => {
                    if let Some(write) = state.writes.get(*index) {
                        let digest = blake3::hash(&write.bytes).to_hex();
                        lanes
                            .entry(Self::lane_name(state, &write.lane))
                            .or_default()
                            .insert(
                                write.seq,
                                format!(
                                    "#{} conn{} w@{}us len={} b3={} fault={fault:?}",
                                    write.seq,
                                    write.pair_ordinal,
                                    micros(write.at),
                                    write.bytes.len(),
                                    &digest[..16],
                                ),
                            );
                    }
                }
                TraceEvent::Fate { lane, seq, fate } => {
                    let name = Self::lane_name(state, lane);
                    let text = match fate {
                        Fate::Delivered { at } => {
                            deliveries
                                .entry(Self::name(state, &lane.dst))
                                .or_default()
                                .push(format!("{name} #{seq}@{}us", micros(*at)));
                            format!("delivered@{}us", micros(*at))
                        }
                        Fate::Dropped { at, reason } => {
                            format!("dropped@{}us {reason:?}", micros(*at))
                        }
                    };
                    fates.insert((name, *seq), text);
                }
                TraceEvent::Refused { index } => {
                    if let Some(refusal) = state.refused.get(*index) {
                        let class = refusal.class.map_or("connect".to_string(), LaneClass::name);
                        let payload =
                            refusal
                                .bytes
                                .as_ref()
                                .map_or("no-bytes".to_string(), |bytes| {
                                    format!(
                                        "len={} b3={}",
                                        bytes.len(),
                                        &blake3::hash(bytes).to_hex()[..16]
                                    )
                                });
                        refusals
                            .entry(Self::name(state, &refusal.src))
                            .or_default()
                            .push(format!(
                                "->{} {class}@{}us {:?} {payload}",
                                Self::name(state, &refusal.dst),
                                micros(refusal.at),
                                refusal.reason,
                            ));
                    }
                }
                TraceEvent::Publish {
                    node,
                    at,
                    topic,
                    digest,
                } => {
                    publishes
                        .entry(Self::name(state, node))
                        .or_default()
                        .push(format!(
                            "@{}us topic={topic} b3={}",
                            micros(*at),
                            &hex::encode(digest)[..16]
                        ));
                }
                TraceEvent::Mark { at, text } => marks.push(format!("@{}us {text}", micros(*at))),
                TraceEvent::StreamOpen {
                    opener,
                    acceptor,
                    ordinal,
                    at,
                } => {
                    let (na, nb) = (Self::name(state, opener), Self::name(state, acceptor));
                    let key = if na <= nb {
                        format!("{na}~{nb}")
                    } else {
                        format!("{nb}~{na}")
                    };
                    links
                        .entry(key)
                        .or_default()
                        .push(format!("stream{ordinal} {na}->{nb} open@{}us", micros(*at)));
                }
                TraceEvent::StreamFinRead { lane, at } => {
                    let (na, nb) = (Self::name(state, &lane.src), Self::name(state, &lane.dst));
                    let key = if na <= nb {
                        format!("{na}~{nb}")
                    } else {
                        format!("{nb}~{na}")
                    };
                    links.entry(key).or_default().push(format!(
                        "{} {na}->{nb} fin-read@{}us",
                        lane.class.name(),
                        micros(*at)
                    ));
                }
            }
        }
        // Fates of writes outside `events` (an appendix after a cut).
        for (lane, seq) in fates.keys() {
            lanes
                .entry(lane.clone())
                .or_default()
                .entry(*seq)
                .or_insert_with(|| format!("#{seq} (written before the cut)"));
        }
        let mut out = String::new();
        let _ = writeln!(out, "# w3h {title} v1 seed={:#x}", self.seed);
        let section = |out: &mut String, title: &str, map: &BTreeMap<String, Vec<String>>| {
            let _ = writeln!(out, "[{title}]");
            for (key, items) in map {
                let _ = writeln!(out, "{key}");
                for item in items {
                    let _ = writeln!(out, "  {item}");
                }
            }
        };
        section(&mut out, "nodes", &nodes);
        section(&mut out, "links", &links);
        let _ = writeln!(out, "[lanes]");
        for (lane, writes) in &lanes {
            let _ = writeln!(out, "{lane}");
            for (seq, write) in writes {
                let fate = fates
                    .get(&(lane.clone(), *seq))
                    .map_or("in-flight", String::as_str);
                let _ = writeln!(out, "  {write} -> {fate}");
            }
        }
        section(&mut out, "deliveries", &deliveries);
        section(&mut out, "refusals", &refusals);
        section(&mut out, "publishes", &publishes);
        let _ = writeln!(out, "[marks]");
        for mark in &marks {
            let _ = writeln!(out, "  {mark}");
        }
        out
    }

    fn attach(self: &Arc<Self>, peer: PeerId, addr: SocketAddr) -> Arc<SimLink> {
        let at = self.now();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let (streams_tx, streams_rx) = mpsc::unbounded_channel();
        let (lifecycle, _) = broadcast::channel(1024);
        let mut state = self.lock();
        let incarnation = state
            .nodes
            .get(&peer.0)
            .map_or(0, |slot| slot.incarnation.saturating_add(1));
        Self::close_all_locked(&mut state, peer.0, ConnectionCloseReason::Superseded, at);
        state.by_addr.insert(addr, peer.0);
        state.nodes.insert(
            peer.0,
            NodeSlot {
                addr,
                online: true,
                incarnation,
                inbound: inbound_tx,
                accept: accept_tx,
                streams: streams_tx,
                lifecycle: lifecycle.clone(),
            },
        );
        state.trace.push(TraceEvent::Node {
            node: peer.0,
            at,
            kind: NodeEventKind::Attached { incarnation },
        });
        drop(state);
        Arc::new(SimLink {
            fabric: Arc::clone(self),
            me: peer,
            inbound: tokio::sync::Mutex::new(inbound_rx),
            accept: tokio::sync::Mutex::new(accept_rx),
            streams: tokio::sync::Mutex::new(streams_rx),
            lifecycle,
        })
    }

    fn close_all_locked(
        state: &mut FabricState,
        node: Key,
        reason: ConnectionCloseReason,
        at: Duration,
    ) {
        let keys: Vec<(Key, Key)> = state
            .links
            .keys()
            .filter(|(a, b)| *a == node || *b == node)
            .copied()
            .collect();
        for key in keys {
            Self::close_link_locked(state, key, reason, at);
        }
    }

    fn close_link_locked(
        state: &mut FabricState,
        key: (Key, Key),
        reason: ConnectionCloseReason,
        at: Duration,
    ) {
        let Some(link) = state.links.remove(&key) else {
            return;
        };
        link.closed.store(true, Ordering::SeqCst);
        // Every stream of the closed connection fails, as with QUIC: bytes
        // already received stay readable, then reads fail.
        state.open_streams.retain(|(generation, stream)| {
            if *generation == link.generation {
                stream.connection_lost();
                false
            } else {
                true
            }
        });
        state.trace.push(TraceEvent::Link {
            a: key.0,
            b: key.1,
            ordinal: link.ordinal,
            at,
            open: false,
        });
        // Frames of the closed connection are lost, each one recorded.
        let lane_keys: Vec<LaneKey> = state
            .lanes
            .keys()
            .filter(|lane| pair(lane.src, lane.dst) == key)
            .copied()
            .collect();
        for lane in lane_keys {
            let mut lost = Vec::new();
            if let Some(lane_state) = state.lanes.get_mut(&lane) {
                lane_state.queue.retain(|queued| {
                    if queued.generation == link.generation {
                        lost.push(queued.seq);
                        false
                    } else {
                        true
                    }
                });
            }
            for seq in lost {
                state.trace.push(TraceEvent::Fate {
                    lane,
                    seq,
                    fate: Fate::Dropped {
                        at,
                        reason: DropReason::LinkClosed,
                    },
                });
            }
        }
        for (me, other) in [(key.0, key.1), (key.1, key.0)] {
            if let Some(slot) = state.nodes.get(&me) {
                let _ = slot.lifecycle.send((
                    PeerId(other),
                    PeerLifecycleEvent::Closed {
                        generation: link.generation,
                        reason,
                    },
                ));
            }
        }
    }

    fn connect(&self, from: Key, addr: SocketAddr) -> Result<PeerConnection, NodeError> {
        let at = self.now();
        let mut state = self.lock();
        let to = *state
            .by_addr
            .get(&addr)
            .ok_or_else(|| NodeError::Connection(format!("sim: nothing at {addr}")))?;
        let reachable = state.nodes.get(&from).is_some_and(|s| s.online)
            && state.nodes.get(&to).is_some_and(|s| s.online)
            && !state.partitions.contains(&pair(from, to));
        if !reachable || from == to {
            if from != to {
                Self::refuse_locked(
                    &mut state,
                    Refusal {
                        src: from,
                        dst: to,
                        class: None,
                        at,
                        reason: RefusalReason::Unreachable,
                        bytes: None,
                    },
                );
            }
            return Err(NodeError::Connection(format!("sim: {addr} unreachable")));
        }
        let key = pair(from, to);
        if state.links.contains_key(&key) {
            return Ok(Self::peer_connection(&state, to, Side::Client));
        }
        let generation = state.next_generation;
        state.next_generation = state.next_generation.saturating_add(1);
        let ordinal = {
            let next = state.pair_ordinals.entry(key).or_insert(0);
            let ordinal = *next;
            *next = next.saturating_add(1);
            ordinal
        };
        state.links.insert(
            key,
            LinkState {
                generation,
                ordinal,
                closed: Arc::new(AtomicBool::new(false)),
            },
        );
        state.trace.push(TraceEvent::Link {
            a: key.0,
            b: key.1,
            ordinal,
            at,
            open: true,
        });
        for (me, other) in [(from, to), (to, from)] {
            if let Some(slot) = state.nodes.get(&me) {
                let _ = slot.lifecycle.send((
                    PeerId(other),
                    PeerLifecycleEvent::Established { generation },
                ));
            }
        }
        let inbound_side = Self::peer_connection(&state, from, Side::Server);
        if let Some(slot) = state.nodes.get(&to) {
            let _ = slot.accept.send(inbound_side);
        }
        Ok(Self::peer_connection(&state, to, Side::Client))
    }

    fn peer_connection(state: &FabricState, peer: Key, side: Side) -> PeerConnection {
        let addr = state
            .nodes
            .get(&peer)
            .map_or(SocketAddr::from(([0, 0, 0, 0], 0)), |slot| slot.addr);
        let now = Instant::now().into_std();
        PeerConnection {
            peer_id: PeerId(peer),
            remote_addr: TransportAddr::Udp(addr),
            traversal_method: TraversalMethod::Direct,
            side,
            authenticated: true,
            connected_at: now,
            last_activity: now,
        }
    }

    fn enqueue(
        &self,
        from: Key,
        to: Key,
        generation: Option<u64>,
        bytes: &[u8],
        delivered: Option<oneshot::Sender<()>>,
    ) -> Result<(), NodeError> {
        let at = self.now();
        let class = LaneClass::of(bytes);
        let mut state = self.lock();
        let key = pair(from, to);
        let live = state
            .links
            .get(&key)
            .map(|link| (link.generation, link.ordinal));
        let Some((link_generation, ordinal)) =
            live.filter(|(current, _)| generation.is_none_or(|wanted| wanted == *current))
        else {
            let reason = if live.is_some() {
                RefusalReason::GenerationSuperseded
            } else {
                RefusalReason::NoLink
            };
            Self::refuse_locked(
                &mut state,
                Refusal {
                    src: from,
                    dst: to,
                    class: Some(class),
                    at,
                    reason,
                    bytes: Some(Arc::from(bytes)),
                },
            );
            return Err(not_connected(&PeerId(to)));
        };
        let lane = LaneKey {
            src: from,
            dst: to,
            class,
        };
        let seq = {
            let lane_state = state.lanes.entry(lane).or_default();
            let seq = lane_state.next_seq;
            lane_state.next_seq = seq.saturating_add(1);
            seq
        };
        let bytes: Arc<[u8]> = Arc::from(bytes);
        let write = Write {
            lane,
            seq,
            pair_ordinal: ordinal,
            at,
            bytes: Arc::clone(&bytes),
        };
        let mut fault = Fault::Pass;
        let mut rule_index = 0;
        for (index, rule) in state.rules.iter().enumerate() {
            fault = rule(&write);
            if fault != Fault::Pass {
                rule_index = index;
                break;
            }
        }
        let index = state.writes.len();
        state.writes.push(write);
        state.trace.push(TraceEvent::Write { index, fault });
        let class_name = class.name();
        let jitter = Duration::from_micros(
            stable_hash(&[
                &self.seed.to_le_bytes(),
                &from,
                &to,
                class_name.as_bytes(),
                &seq.to_le_bytes(),
            ]) % self.jitter_us.max(1),
        );
        let mut due = Instant::now() + self.base_latency + jitter;
        match fault {
            Fault::Drop => {
                state.trace.push(TraceEvent::Fate {
                    lane,
                    seq,
                    fate: Fate::Dropped {
                        at,
                        reason: DropReason::Rule(rule_index),
                    },
                });
                return Ok(());
            }
            Fault::Delay(extra) => due += extra,
            Fault::Pass => {}
        }
        let lane_state = state.lanes.entry(lane).or_default();
        // Strict FIFO within the lane: never due before its predecessor,
        // and the pump pops lane heads only.
        if let Some(last) = lane_state.last_due {
            if due < last {
                due = last;
            }
        }
        lane_state.last_due = Some(due);
        lane_state.queue.push_back(Queued {
            seq,
            due,
            generation: link_generation,
            bytes,
            delivered,
        });
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    /// Open a bi-directional stream `from` → `to` on their live connection;
    /// the acceptor's halves are queued for its `accept_bi`.
    fn open_stream(self: &Arc<Self>, from: Key, to: Key) -> Result<(SimSend, SimRecv), NodeError> {
        let at = self.now();
        let mut state = self.lock();
        let key = pair(from, to);
        let Some(generation) = state.links.get(&key).map(|link| link.generation) else {
            Self::refuse_locked(
                &mut state,
                Refusal {
                    src: from,
                    dst: to,
                    class: None,
                    at,
                    reason: RefusalReason::NoLink,
                    bytes: None,
                },
            );
            return Err(not_connected(&PeerId(to)));
        };
        let ordinal = {
            let next = state.stream_ordinals.entry(key).or_insert(0);
            let ordinal = *next;
            *next = next.saturating_add(1);
            ordinal
        };
        let stream = Arc::new(StreamPair::default());
        state.open_streams.push((generation, Arc::clone(&stream)));
        state.trace.push(TraceEvent::StreamOpen {
            opener: from,
            acceptor: to,
            ordinal,
            at,
        });
        let half = |writer: Key, reader: Key, dir: usize| {
            (
                SimSend {
                    fabric: Arc::clone(self),
                    stream: Arc::clone(&stream),
                    dir,
                    lane: LaneKey {
                        src: writer,
                        dst: reader,
                        class: LaneClass::Stream(ordinal),
                    },
                    generation,
                },
                SimRecv {
                    fabric: Arc::clone(self),
                    stream: Arc::clone(&stream),
                    dir: 1 - dir,
                    lane: LaneKey {
                        src: reader,
                        dst: writer,
                        class: LaneClass::Stream(ordinal),
                    },
                    fin_traced: false,
                },
            )
        };
        // Direction 0 carries opener → acceptor bytes, direction 1 the reply.
        let (opener_send, opener_recv) = half(from, to, 0);
        let (acceptor_send, acceptor_recv) = half(to, from, 1);
        let delivered = state
            .nodes
            .get(&to)
            .filter(|slot| slot.online)
            .is_some_and(|slot| {
                slot.streams
                    .send((PeerId(from), acceptor_send, acceptor_recv))
                    .is_ok()
            });
        if !delivered {
            let _ = stream.reset_both();
            return Err(not_connected(&PeerId(to)));
        }
        Ok((opener_send, opener_recv))
    }

    /// Record one stream write (bytes kept, as for frames) and decide its
    /// fate: delivered into the stream, or the stream is reset (a `Drop`
    /// rule, or the connection is gone). `Delay` rules are not supported on
    /// streams: the write is recorded as `Pass` and a `stream Delay
    /// unsupported` mark is added, so the trace says the rule did not apply.
    fn stream_write(&self, lane: LaneKey, generation: u64, bytes: &[u8]) -> io::Result<()> {
        let at = self.now();
        let mut state = self.lock();
        let live = state
            .links
            .get(&pair(lane.src, lane.dst))
            .is_some_and(|link| link.generation == generation);
        let seq = {
            let lane_state = state.lanes.entry(lane).or_default();
            let seq = lane_state.next_seq;
            lane_state.next_seq = seq.saturating_add(1);
            seq
        };
        let ordinal = state
            .links
            .get(&pair(lane.src, lane.dst))
            .map_or(0, |link| link.ordinal);
        let write = Write {
            lane,
            seq,
            pair_ordinal: ordinal,
            at,
            bytes: Arc::from(bytes),
        };
        let mut fault = Fault::Pass;
        let mut rule_index = 0;
        for (index, rule) in state.rules.iter().enumerate() {
            let decision = rule(&write);
            if decision != Fault::Pass {
                fault = decision;
                rule_index = index;
                break;
            }
        }
        let delay_unsupported = matches!(fault, Fault::Delay(_));
        if delay_unsupported {
            fault = Fault::Pass;
        }
        let index = state.writes.len();
        state.writes.push(write);
        state.trace.push(TraceEvent::Write { index, fault });
        if delay_unsupported {
            let text = format!(
                "stream Delay unsupported: rule {rule_index} on {} #{seq} applied as Pass",
                Self::lane_name(&state, &lane)
            );
            state.trace.push(TraceEvent::Mark { at, text });
        }
        let fate = if !live {
            Fate::Dropped {
                at,
                reason: DropReason::LinkClosed,
            }
        } else if fault == Fault::Drop {
            Fate::Dropped {
                at,
                reason: DropReason::Rule(rule_index),
            }
        } else {
            Fate::Delivered { at }
        };
        state.trace.push(TraceEvent::Fate { lane, seq, fate });
        match fate {
            Fate::Delivered { .. } => Ok(()),
            Fate::Dropped { .. } => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "sim: stream reset",
            )),
        }
    }

    /// A write attempted on an already-reset stream: refused, bytes kept.
    fn refuse_stream_write(&self, lane: LaneKey, bytes: &[u8]) {
        self.refuse_stream_bytes(lane, RefusalReason::StreamReset, bytes);
    }

    /// Record stream bytes that never reach the reader, with why.
    fn refuse_stream_bytes(&self, lane: LaneKey, reason: RefusalReason, bytes: &[u8]) {
        let at = self.now();
        let mut state = self.lock();
        Self::refuse_locked(
            &mut state,
            Refusal {
                src: lane.src,
                dst: lane.dst,
                class: Some(lane.class),
                at,
                reason,
                bytes: Some(Arc::from(bytes)),
            },
        );
    }

    fn refuse_locked(state: &mut FabricState, refusal: Refusal) {
        let index = state.refused.len();
        state.refused.push(refusal);
        state.trace.push(TraceEvent::Refused { index });
    }

    /// A pinned send refused before admission: its generation is no longer
    /// the pair's live connection, so no bytes were produced.
    fn refuse_admission(&self, from: Key, to: Key) {
        let at = self.now();
        let mut state = self.lock();
        Self::refuse_locked(
            &mut state,
            Refusal {
                src: from,
                dst: to,
                class: None,
                at,
                reason: RefusalReason::GenerationSuperseded,
                bytes: None,
            },
        );
    }

    /// Sends refused from `src` at or after `since` (any destination).
    pub(crate) fn refused_since(&self, src: &PeerId, since: Duration) -> Vec<Refusal> {
        self.lock()
            .refused
            .iter()
            .filter(|refusal| refusal.src == src.0 && refusal.at >= since)
            .cloned()
            .collect()
    }

    /// Writes from `src` (any destination, any lane) delivered at or after
    /// `since`, as `(dst, class, seq)`.
    pub(crate) fn delivered_from_since(
        &self,
        src: &PeerId,
        since: Duration,
    ) -> Vec<(Key, LaneClass, u64)> {
        let state = self.lock();
        let written: BTreeSet<(LaneKey, u64)> = state
            .writes
            .iter()
            .filter(|write| write.lane.src == src.0 && write.at >= since)
            .map(|write| (write.lane, write.seq))
            .collect();
        state
            .trace
            .iter()
            .filter_map(|event| match event {
                TraceEvent::Fate {
                    lane,
                    seq,
                    fate: Fate::Delivered { .. },
                } if written.contains(&(*lane, *seq)) => Some((lane.dst, lane.class, *seq)),
                _ => None,
            })
            .collect()
    }

    fn lane_rank(&self, lane: &LaneKey) -> u64 {
        let class = lane.class.name();
        stable_hash(&[
            &self.seed.to_le_bytes(),
            &lane.src,
            &lane.dst,
            class.as_bytes(),
        ])
    }

    async fn run_pump(self: Arc<Self>) {
        // The pump owns a strong handle: the fabric lives as long as the
        // scenario's runtime, which drops this task at the end of the test.
        loop {
            let next_due = {
                let state = self.lock();
                state
                    .lanes
                    .values()
                    .filter_map(|lane| lane.queue.front().map(|queued| queued.due))
                    .min()
            };
            let notified = self.wake.notified();
            match next_due {
                Some(due) if due <= Instant::now() => self.deliver_due(),
                Some(due) => {
                    tokio::select! {
                        biased;
                        _ = notified => {}
                        _ = tokio::time::sleep_until(due) => {}
                    }
                }
                None => notified.await,
            }
        }
    }

    /// Deliver every lane head that is due, earliest first; between heads
    /// due at the same instant, the lower seeded lane rank goes first.
    fn deliver_due(&self) {
        let now_instant = Instant::now();
        let at = self.now();
        let mut state = self.lock();
        loop {
            let next = state
                .lanes
                .iter()
                .filter_map(|(lane, lane_state)| {
                    lane_state
                        .queue
                        .front()
                        .filter(|queued| queued.due <= now_instant)
                        .map(|queued| (queued.due, self.lane_rank(lane), *lane))
                })
                .min();
            let Some((_, _, lane)) = next else {
                break;
            };
            let Some(queued) = state
                .lanes
                .get_mut(&lane)
                .and_then(|lane_state| lane_state.queue.pop_front())
            else {
                break;
            };
            let live = state
                .links
                .get(&pair(lane.src, lane.dst))
                .is_some_and(|link| link.generation == queued.generation);
            let target = state
                .nodes
                .get(&lane.dst)
                .filter(|slot| slot.online)
                .map(|slot| slot.inbound.clone());
            let fate = match (live, target) {
                (false, _) => Fate::Dropped {
                    at,
                    reason: DropReason::LinkClosed,
                },
                (true, None) => Fate::Dropped {
                    at,
                    reason: DropReason::DestinationOffline,
                },
                (true, Some(inbound)) => {
                    if inbound
                        .send((PeerId(lane.src), queued.generation, queued.bytes.to_vec()))
                        .is_ok()
                    {
                        if let Some(ack) = queued.delivered {
                            let _ = ack.send(());
                        }
                        Fate::Delivered { at }
                    } else {
                        Fate::Dropped {
                            at,
                            reason: DropReason::DestinationOffline,
                        }
                    }
                }
            };
            state.trace.push(TraceEvent::Fate {
                lane,
                seq: queued.seq,
                fate,
            });
        }
    }

    fn note_publish(&self, node: Key, topic: &str, payload: &[u8]) {
        let at = self.now();
        let digest = *blake3::hash(payload).as_bytes();
        self.lock().trace.push(TraceEvent::Publish {
            node,
            at,
            topic: topic.to_string(),
            digest,
        });
    }

    fn detach(&self, node: Key) {
        let at = self.now();
        let mut state = self.lock();
        if let Some(slot) = state.nodes.get_mut(&node) {
            slot.online = false;
        }
        state.trace.push(TraceEvent::Node {
            node,
            at,
            kind: NodeEventKind::Detached,
        });
        Self::close_all_locked(&mut state, node, ConnectionCloseReason::PeerShutdown, at);
    }
}

/// One node's view of the fabric; the `Sim` arm of
/// [`super::link::LinkNode`].
pub(crate) struct SimLink {
    fabric: Arc<SimFabric>,
    me: PeerId,
    inbound: tokio::sync::Mutex<mpsc::UnboundedReceiver<(PeerId, u64, Vec<u8>)>>,
    accept: tokio::sync::Mutex<mpsc::UnboundedReceiver<PeerConnection>>,
    streams: tokio::sync::Mutex<mpsc::UnboundedReceiver<(PeerId, SimSend, SimRecv)>>,
    lifecycle: broadcast::Sender<(PeerId, PeerLifecycleEvent)>,
}

impl std::fmt::Debug for SimLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimLink")
            .field("me", &hex::encode(&self.me.0[..4]))
            .finish_non_exhaustive()
    }
}

impl SimLink {
    pub(crate) fn peer_id(&self) -> PeerId {
        self.me
    }

    pub(crate) async fn connect_addr(&self, addr: SocketAddr) -> Result<PeerConnection, NodeError> {
        // A virtual handshake round trip.
        tokio::time::sleep(self.fabric.base_latency * 2).await;
        self.fabric.connect(self.me.0, addr)
    }

    pub(crate) async fn connect_peer(&self, peer_id: PeerId) -> Result<PeerConnection, NodeError> {
        let addr = self
            .fabric
            .lock()
            .nodes
            .get(&peer_id.0)
            .map(|slot| slot.addr)
            .ok_or_else(|| not_connected(&peer_id))?;
        self.connect_peer_with_addrs(peer_id, vec![addr]).await
    }

    pub(crate) async fn connect_peer_with_addrs(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
    ) -> Result<PeerConnection, NodeError> {
        let mut last = not_connected(&peer_id);
        for addr in addrs {
            match self.connect_addr(addr).await {
                Ok(conn) if conn.peer_id == peer_id => return Ok(conn),
                Ok(_) => last = NodeError::Connection("sim: peer id mismatch".into()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    pub(crate) fn upsert_peer_hints(&self, _peer_id: PeerId, _addrs: Vec<SocketAddr>) {}

    pub(crate) fn connection_health(&self, peer_id: &PeerId) -> ant_quic::ConnectionHealth {
        let generation = self.current_connection_generation(peer_id);
        ant_quic::ConnectionHealth {
            connected: generation.is_some(),
            generation,
            ..ant_quic::ConnectionHealth::default()
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        self.fabric
            .lock()
            .nodes
            .get(&self.me.0)
            .is_some_and(|slot| slot.online)
    }

    pub(crate) fn open_bi(&self, peer_id: &PeerId) -> Result<(SimSend, SimRecv), NodeError> {
        self.fabric.open_stream(self.me.0, peer_id.0)
    }

    pub(crate) async fn accept_bi(&self) -> Result<(PeerId, SimSend, SimRecv), NodeError> {
        self.streams
            .lock()
            .await
            .recv()
            .await
            .ok_or(NodeError::ShuttingDown)
    }

    pub(crate) async fn accept(&self) -> Option<PeerConnection> {
        self.accept.lock().await.recv().await
    }

    pub(crate) fn disconnect(&self, peer_id: &PeerId) -> Result<(), NodeError> {
        let at = self.fabric.now();
        let mut state = self.fabric.lock();
        SimFabric::close_link_locked(
            &mut state,
            pair(self.me.0, peer_id.0),
            ConnectionCloseReason::LifecycleCleanup,
            at,
        );
        Ok(())
    }

    pub(crate) fn connected_peers(&self) -> Vec<PeerConnection> {
        let state = self.fabric.lock();
        state
            .links
            .keys()
            .filter_map(|(a, b)| {
                if *a == self.me.0 {
                    Some(*b)
                } else if *b == self.me.0 {
                    Some(*a)
                } else {
                    None
                }
            })
            .map(|other| SimFabric::peer_connection(&state, other, Side::Client))
            .collect()
    }

    pub(crate) fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.current_connection_generation(peer_id).is_some()
    }

    pub(crate) fn subscribe_all_peer_events(
        &self,
    ) -> broadcast::Receiver<(PeerId, PeerLifecycleEvent)> {
        self.lifecycle.subscribe()
    }

    pub(crate) fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), NodeError> {
        self.fabric.enqueue(self.me.0, peer_id.0, None, data, None)
    }

    pub(crate) fn send_on_generation_with_admission<B, F>(
        &self,
        peer_id: &PeerId,
        generation: u64,
        admit: F,
    ) -> Result<(), NodeError>
    where
        B: AsRef<[u8]> + Send,
        F: FnOnce(u64) -> Result<B, EndpointError> + Send,
    {
        if self.current_connection_generation(peer_id) != Some(generation) {
            self.fabric.refuse_admission(self.me.0, peer_id.0);
            return Err(NodeError::Connection("sim: generation superseded".into()));
        }
        let bytes = admit(generation).map_err(NodeError::Endpoint)?;
        self.fabric
            .enqueue(self.me.0, peer_id.0, Some(generation), bytes.as_ref(), None)
    }

    pub(crate) async fn send_with_receive_ack(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(), NodeError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.fabric
            .enqueue(self.me.0, peer_id.0, None, data, Some(ack_tx))?;
        match tokio::time::timeout(timeout, ack_rx).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(NodeError::Connection("sim: frame lost".into())),
            Err(_) => Err(NodeError::Connection("sim: receive-ack timeout".into())),
        }
    }

    pub(crate) fn probe_peer(&self, peer_id: &PeerId) -> Result<Duration, NodeError> {
        if self.is_connected(peer_id) {
            Ok(self.fabric.base_latency * 2)
        } else {
            Err(not_connected(peer_id))
        }
    }

    pub(crate) async fn recv_with_generation(&self) -> Result<(PeerId, u64, Vec<u8>), NodeError> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(NodeError::ShuttingDown)
    }

    pub(crate) fn current_connection_generation(&self, peer: &PeerId) -> Option<u64> {
        self.fabric
            .lock()
            .links
            .get(&pair(self.me.0, peer.0))
            .map(|link| link.generation)
    }

    pub(crate) fn session_connection(&self, peer: &PeerId) -> Option<SimConnection> {
        self.fabric
            .lock()
            .links
            .get(&pair(self.me.0, peer.0))
            .map(|link| SimConnection {
                generation: link.generation,
                closed: Arc::clone(&link.closed),
            })
    }

    pub(crate) fn note_publish(&self, topic: &str, payload: &[u8]) {
        self.fabric.note_publish(self.me.0, topic, payload);
    }

    pub(crate) fn shutdown(&self) {
        self.fabric.detach(self.me.0);
    }
}

/// One direction of a simulated stream: bytes in order, EOF on finish.
/// As with QUIC (ant-quic `Recv::reset` clears its assembler):
/// - a stream reset (the writer dropped its half unfinished, or a `Drop`
///   fault) discards the bytes the reader has not read, and every later
///   read fails;
/// - a lost connection (the link closed) leaves received bytes readable;
///   once they are read, the reader sees EOF if the writer had finished,
///   otherwise an error.
#[derive(Default)]
struct Pipe {
    buf: VecDeque<u8>,
    finished: bool,
    reset: bool,
    lost: bool,
    reader_gone: bool,
    reader_waker: Option<Waker>,
}

impl Pipe {
    fn wake(&mut self) {
        if let Some(waker) = self.reader_waker.take() {
            waker.wake();
        }
    }
}

/// Both directions of one simulated stream.
#[derive(Default)]
pub(crate) struct StreamPair {
    dirs: [Mutex<Pipe>; 2],
}

impl StreamPair {
    fn pipe(&self, dir: usize) -> std::sync::MutexGuard<'_, Pipe> {
        self.dirs[dir & 1]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reset one direction: unread bytes are discarded and returned.
    fn reset(&self, dir: usize) -> Vec<u8> {
        let mut pipe = self.pipe(dir);
        pipe.reset = true;
        let unread = pipe.buf.drain(..).collect();
        pipe.wake();
        unread
    }

    /// Reset both directions; returns the unread bytes of each.
    fn reset_both(&self) -> [Vec<u8>; 2] {
        [self.reset(0), self.reset(1)]
    }

    /// The connection carrying the stream closed.
    fn connection_lost(&self) {
        for dir in 0..2 {
            let mut pipe = self.pipe(dir);
            pipe.lost = true;
            pipe.wake();
        }
    }
}

/// The write half of a simulated stream (the `Sim` arm of
/// [`super::StreamSend`] in test builds).
pub struct SimSend {
    fabric: Arc<SimFabric>,
    stream: Arc<StreamPair>,
    dir: usize,
    lane: LaneKey,
    generation: u64,
}

impl SimSend {
    /// Gracefully end this direction (EOF for the reader). As with QUIC
    /// (`ClosedStream`, mapped to `NotConnected`), finishing twice fails.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        let mut pipe = self.stream.pipe(self.dir);
        if pipe.reset || pipe.lost {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "sim: stream reset",
            ));
        }
        if pipe.finished {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "sim: stream already finished",
            ));
        }
        pipe.finished = true;
        pipe.wake();
        Ok(())
    }

    /// The lane carrying the other direction of this stream.
    fn reverse_lane(&self) -> LaneKey {
        LaneKey {
            src: self.lane.dst,
            dst: self.lane.src,
            class: self.lane.class,
        }
    }

    /// Record bytes a reset discarded, per direction (index = `dir`).
    fn record_discarded(&self, unread: [Vec<u8>; 2]) {
        for (dir, bytes) in unread.iter().enumerate() {
            if bytes.is_empty() {
                continue;
            }
            let lane = if dir == self.dir {
                self.lane
            } else {
                self.reverse_lane()
            };
            self.fabric
                .refuse_stream_bytes(lane, RefusalReason::ResetDiscarded, bytes);
        }
    }
}

impl tokio::io::AsyncWrite for SimSend {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        {
            let pipe = this.stream.pipe(this.dir);
            if pipe.reset || pipe.lost || pipe.reader_gone {
                drop(pipe);
                this.fabric.refuse_stream_write(this.lane, buf);
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "sim: stream reset",
                )));
            }
            if pipe.finished {
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "sim: write after finish",
                )));
            }
        }
        if let Err(error) = this.fabric.stream_write(this.lane, this.generation, buf) {
            // A `Drop` fault (or a gone connection) resets both directions.
            let unread = this.stream.reset_both();
            this.record_discarded(unread);
            return std::task::Poll::Ready(Err(error));
        }
        let mut pipe = this.stream.pipe(this.dir);
        pipe.buf.extend(buf.iter().copied());
        pipe.wake();
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(self.get_mut().finish())
    }
}

impl Drop for SimSend {
    fn drop(&mut self) {
        // As with ant-quic: dropping an unfinished send half resets this
        // direction, and the reader loses the bytes it had not read yet.
        let unfinished = {
            let pipe = self.stream.pipe(self.dir);
            // After a lost connection there is no peer left to reset.
            !pipe.finished && !pipe.reset && !pipe.lost
        };
        if unfinished {
            let unread = self.stream.reset(self.dir);
            let mut both = [Vec::new(), Vec::new()];
            both[self.dir & 1] = unread;
            self.record_discarded(both);
        }
    }
}

/// The read half of a simulated stream (the `Sim` arm of
/// [`super::StreamRecv`] in test builds). Reading to the writer's FIN is
/// traced once (`fin-read`), so a case can tell that a reply was consumed.
pub struct SimRecv {
    fabric: Arc<SimFabric>,
    stream: Arc<StreamPair>,
    dir: usize,
    /// The lane this half reads (the other side's writes).
    lane: LaneKey,
    fin_traced: bool,
}

impl tokio::io::AsyncRead for SimRecv {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut pipe = this.stream.pipe(this.dir);
        if pipe.reset {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "sim: stream reset",
            )));
        }
        if !pipe.buf.is_empty() {
            let n = buf.remaining().min(pipe.buf.len());
            let chunk: Vec<u8> = pipe.buf.drain(..n).collect();
            buf.put_slice(&chunk);
            return std::task::Poll::Ready(Ok(()));
        }
        if pipe.finished {
            drop(pipe);
            if !this.fin_traced {
                this.fin_traced = true;
                this.fabric.note_fin_read(this.lane);
            }
            return std::task::Poll::Ready(Ok(()));
        }
        if pipe.lost {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "sim: connection lost",
            )));
        }
        pipe.reader_waker = Some(cx.waker().clone());
        std::task::Poll::Pending
    }
}

impl Drop for SimRecv {
    fn drop(&mut self) {
        // As with QUIC STOP_SENDING: the writer's next write fails.
        self.stream.pipe(self.dir).reader_gone = true;
    }
}

type Registry = Mutex<Vec<(String, Weak<SimFabric>)>>;

fn registry() -> &'static Registry {
    static FABRICS: OnceLock<Registry> = OnceLock::new();
    FABRICS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Make `fabric` the network for every node built with
/// `NetworkConfig { network_id: Some(plane), bind_addr: Some(addr), .. }`.
pub(crate) fn register(plane: &str, fabric: &Arc<SimFabric>) {
    let mut fabrics = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fabrics.retain(|(_, weak)| weak.strong_count() > 0);
    fabrics.push((plane.to_string(), Arc::downgrade(fabric)));
}

/// Called by `NetworkNode::new` in test builds: a node whose plane has a
/// registered fabric runs on that fabric instead of binding a socket.
pub(crate) fn claim(config: &super::NetworkConfig, peer: PeerId) -> Option<Arc<SimLink>> {
    let plane = config.network_id.as_deref()?;
    let addr = config.bind_addr?;
    let fabric = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(name, _)| name == plane)
        .and_then(|(_, weak)| weak.upgrade())?;
    Some(fabric.attach(peer, addr))
}

mod fabric_tests {
    //! Fabric-only checks (no daemons); they run in CI with the `w3h`
    //! profile.
    use super::*;

    fn key(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([198, 18, 0, n], 5483))
    }

    const DM: u8 = super::super::DIRECT_MESSAGE_STREAM_TYPE;

    async fn two_links(fabric: &Arc<SimFabric>) -> (Arc<SimLink>, Arc<SimLink>) {
        let a = fabric.attach(key(1), addr(1));
        let b = fabric.attach(key(2), addr(2));
        fabric.label(&key(1), "A");
        fabric.label(&key(2), "B");
        a.connect_addr(addr(2)).await.expect("connect");
        (a, b)
    }

    async fn drain(link: &SimLink, n: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for _ in 0..n {
            let (_, _, bytes) =
                tokio::time::timeout(Duration::from_secs(5), link.recv_with_generation())
                    .await
                    .expect("delivered in time")
                    .expect("link open");
            out.push(bytes);
        }
        out
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_lane_is_fifo_even_with_delay_faults() {
        let fabric = SimFabric::new(0x5eed);
        // Delay every frame with an even marker; the lane must still
        // deliver in write order (no overtaking within a lane).
        fabric.add_rule(|write| {
            if write.bytes.get(1).is_some_and(|b| b % 2 == 0) {
                Fault::Delay(Duration::from_millis(40))
            } else {
                Fault::Pass
            }
        });
        let (a, b) = two_links(&fabric).await;
        for i in 0..32u8 {
            a.send(&key(2), &[DM, i]).expect("send");
        }
        let order: Vec<u8> = drain(&b, 32).await.iter().map(|bytes| bytes[1]).collect();
        assert_eq!(order, (0..32u8).collect::<Vec<_>>());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_cut_splits_the_digested_trace_from_the_appendix() {
        let fabric = SimFabric::new(11);
        let (a, b) = two_links(&fabric).await;
        a.send(&key(2), &[DM, 1]).expect("send before the cut");
        let cut = fabric.cut("teardown begins");
        drain(&b, 1).await;
        a.send(&key(2), &[DM, 2]).expect("send after the cut");
        drain(&b, 1).await;
        fabric.mark("teardown verified");

        let digested = fabric.canonical_trace_until(cut);
        assert!(digested.starts_with("# w3h canonical trace v1"));
        assert!(digested.contains("teardown begins"));
        assert!(!digested.contains("teardown verified"));
        // Written before the cut, delivered after it.
        assert!(digested.contains("#0 conn0") && digested.contains("-> in-flight"));
        assert!(!digested.contains("#1 conn0"));

        let appendix = fabric.trace_appendix(cut);
        assert!(appendix.starts_with("# w3h trace appendix v1"));
        assert!(appendix.contains("#0 (written before the cut) -> delivered@"));
        assert!(appendix.contains("#1 conn0"));
        assert!(appendix.contains("teardown verified"));
        assert!(!appendix.contains("teardown begins"));

        // The uncut trace is unchanged: every write with its final fate.
        let full = fabric.canonical_trace();
        assert!(!full.contains("in-flight") && !full.contains("written before the cut"));
        assert_eq!(fabric.canonical_trace_until(usize::MAX), full);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_link_close_records_every_lost_frame() {
        let fabric = SimFabric::new(7);
        let (a, _b) = two_links(&fabric).await;
        for i in 0..5u8 {
            a.send(&key(2), &[DM, i]).expect("send");
        }
        fabric.set_online(&key(2), false);
        let trace = fabric.canonical_trace();
        assert_eq!(trace.matches("LinkClosed").count(), 5, "{trace}");
        assert!(a.send(&key(2), &[DM, 9]).is_err());
        let trace = fabric.canonical_trace();
        assert!(
            trace.contains("[refusals]\nA\n  ->B direct@") && trace.contains("NoLink len=2 b3="),
            "a refused send is recorded with its payload: {trace}"
        );
        assert_eq!(fabric.refused_since(&key(1), Duration::ZERO).len(), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_drop_rule_is_recorded_with_the_write() {
        let fabric = SimFabric::new(9);
        fabric.add_rule(|write| {
            if write.seq == 1 {
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        let (a, b) = two_links(&fabric).await;
        for i in 0..3u8 {
            a.send(&key(2), &[DM, i]).expect("send");
        }
        assert_eq!(drain(&b, 2).await, vec![vec![DM, 0], vec![DM, 2]]);
        let writes = fabric.writes();
        assert_eq!(writes.len(), 3, "the dropped write is still captured");
        assert_eq!(&*writes[1].bytes, &[DM, 1]);
        assert!(fabric.canonical_trace().contains("dropped@"));
    }

    async fn stream_pair(
        fabric: &Arc<SimFabric>,
    ) -> (
        Arc<SimLink>,
        Arc<SimLink>,
        SimSend,
        SimRecv,
        SimSend,
        SimRecv,
    ) {
        let (a, b) = two_links(fabric).await;
        let (a_send, a_recv) = a.open_bi(&key(2)).expect("open");
        let (peer, b_send, b_recv) = tokio::time::timeout(Duration::from_secs(1), b.accept_bi())
            .await
            .expect("accepted in time")
            .expect("accept");
        assert_eq!(peer, key(1), "the acceptor learns the opener");
        (a, b, a_send, a_recv, b_send, b_recv)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_stream_open_accept_eof_and_reply() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let fabric = SimFabric::new(21);
        let (_a, _b, mut a_send, mut a_recv, mut b_send, mut b_recv) = stream_pair(&fabric).await;
        a_send.write_all(&[0x06, 1, 2, 3]).await.expect("write");
        a_send.finish().expect("finish");
        let mut got = Vec::new();
        b_recv.read_to_end(&mut got).await.expect("read to EOF");
        assert_eq!(got, vec![0x06, 1, 2, 3], "bytes in order, then EOF");
        b_send.write_all(b"reply").await.expect("reply");
        b_send.shutdown().await.expect("shutdown");
        let mut reply = Vec::new();
        a_recv.read_to_end(&mut reply).await.expect("reply EOF");
        assert_eq!(reply, b"reply");
        assert!(
            a_send.write_all(b"x").await.is_err(),
            "no write after finish"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_stream_fails_when_the_link_closes() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let fabric = SimFabric::new(22);
        let (_a, _b, mut a_send, _a_recv, _b_send, mut b_recv) = stream_pair(&fabric).await;
        a_send.write_all(b"before").await.expect("write");
        fabric.set_online(&key(2), false);
        let mut buf = [0u8; 6];
        // As with a lost QUIC connection: bytes already received stay
        // readable; then the failure surfaces.
        b_recv.read_exact(&mut buf).await.expect("delivered bytes");
        assert_eq!(&buf, b"before");
        let mut more = [0u8; 1];
        assert!(
            b_recv.read_exact(&mut more).await.is_err(),
            "reader sees the lost connection"
        );
        assert!(
            a_send.write_all(b"after").await.is_err(),
            "writer sees the reset"
        );
        let trace = fabric.canonical_trace();
        assert!(
            trace.contains("StreamReset len=5"),
            "the post-close write is recorded with its bytes: {trace}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_stream_drop_fault_resets_the_stream() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let fabric = SimFabric::new(23);
        fabric.add_rule(|write| {
            if matches!(write.lane.class, LaneClass::Stream(_))
                && write.bytes.first() == Some(&0xff)
            {
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        let (_a, _b, mut a_send, _a_recv, _b_send, mut b_recv) = stream_pair(&fabric).await;
        a_send.write_all(b"ok").await.expect("first write passes");
        let mut buf = [0u8; 2];
        b_recv
            .read_exact(&mut buf)
            .await
            .expect("read before the reset");
        a_send
            .write_all(b"unread")
            .await
            .expect("second write passes");
        assert!(
            a_send.write_all(&[0xff]).await.is_err(),
            "dropped write resets"
        );
        let mut more = [0u8; 1];
        assert!(
            b_recv.read_exact(&mut more).await.is_err(),
            "the reset discards unread bytes, and the reader sees it"
        );
        let trace = fabric.canonical_trace();
        assert!(trace.contains("Rule(0)"), "{trace}");
        assert!(trace.contains("ResetDiscarded len=6"), "{trace}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_stream_unfinished_drop_discards_unread_reply() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let fabric = SimFabric::new(25);
        let (_a, _b, _a_send, mut a_recv, mut b_send, _b_recv) = stream_pair(&fabric).await;
        // A responder that writes its reply and drops the send half without
        // finishing it: ant-quic resets the stream and the initiator loses
        // the reply it had not read yet.
        b_send.write_all(b"reply").await.expect("reply");
        drop(b_send);
        let mut got = Vec::new();
        assert!(
            a_recv.read_to_end(&mut got).await.is_err(),
            "the reset reaches the reader"
        );
        assert!(got.is_empty(), "unread reply bytes are discarded: {got:?}");
        let trace = fabric.canonical_trace();
        assert!(trace.contains("ResetDiscarded len=5"), "{trace}");
        let reply_lane = LaneKey {
            src: key(2).0,
            dst: key(1).0,
            class: LaneClass::Stream(0),
        };
        assert_eq!(fabric.fin_read_at(&reply_lane), None, "no FIN was read");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_stream_finished_reply_survives_the_drop() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let fabric = SimFabric::new(26);
        let (_a, _b, _a_send, mut a_recv, mut b_send, _b_recv) = stream_pair(&fabric).await;
        // The EvidenceV1 / SyncV1 reply path: write, shutdown (finish), drop.
        b_send.write_all(b"reply").await.expect("reply");
        b_send.shutdown().await.expect("finish");
        assert_eq!(
            b_send.finish().map_err(|error| error.kind()),
            Err(io::ErrorKind::NotConnected),
            "a second finish fails, as with QUIC"
        );
        drop(b_send);
        let mut got = Vec::new();
        a_recv.read_to_end(&mut got).await.expect("reply then EOF");
        assert_eq!(got, b"reply");
        let reply_lane = LaneKey {
            src: key(2).0,
            dst: key(1).0,
            class: LaneClass::Stream(0),
        };
        assert!(
            fabric.fin_read_at(&reply_lane).is_some(),
            "the FIN read is traced"
        );
        assert!(fabric.canonical_trace().contains("stream0 B->A fin-read@"));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_stream_delay_rule_is_marked_unsupported() {
        use tokio::io::AsyncWriteExt as _;
        let fabric = SimFabric::new(27);
        fabric.add_rule(|write| {
            if matches!(write.lane.class, LaneClass::Stream(_)) {
                Fault::Delay(Duration::from_millis(5))
            } else {
                Fault::Pass
            }
        });
        let (_a, _b, mut a_send, _a_recv, _b_send, _b_recv) = stream_pair(&fabric).await;
        a_send.write_all(b"x").await.expect("write");
        let trace = fabric.canonical_trace();
        assert!(
            trace.contains("stream Delay unsupported: rule 0 on A->B stream0 #0 applied as Pass"),
            "{trace}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_stream_writes_are_traced_with_bytes() {
        use tokio::io::AsyncWriteExt as _;
        let fabric = SimFabric::new(24);
        let (_a, _b, mut a_send, _a_recv, mut b_send, _b_recv) = stream_pair(&fabric).await;
        a_send.write_all(&[0x05, 0xaa]).await.expect("write");
        b_send.write_all(&[0xbb]).await.expect("reply");
        let trace = fabric.canonical_trace();
        assert!(trace.contains("stream0 A->B open@"), "{trace}");
        assert!(trace.contains("A->B stream0\n  #0 conn0 w@"), "{trace}");
        assert!(trace.contains("B->A stream0\n  #0 conn0 w@"), "{trace}");
        let dump = fabric.payload_dump(1 << 20);
        assert!(dump.windows(2).any(|w| w == [0x05, 0xaa]));
        assert!(String::from_utf8_lossy(&dump).contains("W A->B stream0 #0"));
        let writes = fabric.writes();
        assert!(writes
            .iter()
            .any(|w| w.lane.class == LaneClass::Stream(0) && *w.bytes == [0xbb]));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_payload_dump_carries_raw_bytes_and_refusals() {
        let fabric = SimFabric::new(13);
        let (a, _b) = two_links(&fabric).await;
        a.send(&key(2), &[DM, 0xab, 0xcd]).expect("send");
        fabric.set_online(&key(2), false);
        assert!(a.send(&key(2), &[DM, 0xef]).is_err());
        let dump = fabric.payload_dump(1 << 20);
        let text = String::from_utf8_lossy(&dump);
        assert!(text.contains("W A->B direct #0 w@"), "{text}");
        assert!(dump.windows(3).any(|w| w == [DM, 0xab, 0xcd]));
        assert!(text.contains("R A->B direct @"), "{text}");
        assert!(dump.windows(2).any(|w| w == [DM, 0xef]));
        let truncated = fabric.payload_dump(8);
        assert_eq!(truncated, b"TRUNCATED\n");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_partition_refuses_connect_until_healed() {
        let fabric = SimFabric::new(11);
        let (a, _b) = two_links(&fabric).await;
        fabric.set_partitioned(&key(1), &key(2), true);
        assert!(!a.is_connected(&key(2)), "partition closes the live link");
        assert!(a.connect_addr(addr(2)).await.is_err());
        fabric.set_partitioned(&key(1), &key(2), false);
        a.connect_addr(addr(2)).await.expect("healed");
        let trace = fabric.canonical_trace();
        assert!(trace.contains("A~B\n  #0 open@"), "{trace}");
        assert!(
            trace.contains("#1 open@"),
            "a second connection ordinal: {trace}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn w3h_fabric_same_seed_same_trace_other_seed_differs() {
        async fn run(seed: u64) -> String {
            let fabric = SimFabric::new(seed);
            let a = fabric.attach(key(1), addr(1));
            let b = fabric.attach(key(2), addr(2));
            let c = fabric.attach(key(3), addr(3));
            a.connect_addr(addr(3)).await.expect("a-c");
            b.connect_addr(addr(3)).await.expect("b-c");
            for i in 0..8u8 {
                a.send(&key(3), &[DM, i]).expect("a");
                b.send(&key(3), &[DM, 100 + i]).expect("b");
            }
            drain(&c, 16).await;
            // Compare executions, not the seed header.
            let trace = fabric.canonical_trace();
            trace
                .split_once('\n')
                .map_or(trace.clone(), |(_, body)| body.to_string())
        }
        let first = run(1).await;
        assert_eq!(first, run(1).await, "same seed, same canonical trace");
        assert_ne!(
            first,
            run(2).await,
            "the seed drives timing and interleaving"
        );
    }
}
