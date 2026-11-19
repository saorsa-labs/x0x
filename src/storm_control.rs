//! Storm control — announce-topic forward suppression (2026-08-27).
//!
//! Live forensics (`.scratch/cadence-measurement.md`) showed 92% of announce
//! traffic coming from a handful of old, never-updating daemons that replay
//! hours of cached announcements with fresh gossip message-ids every ~2
//! seconds, defeating PlumTree dedupe forever. Their traffic transits every
//! relaying node, so the whole network pays for eight broken machines.
//!
//! This module classifies announce payloads BEFORE they are forwarded (via
//! saorsa-gossip's per-topic validation hook, sg ≥ 0.5.75):
//!
//! - **Stale replay** — the payload's *signed* `announced_at` is older than
//!   the freshness TTL (or unreasonably far in the future). Unforgeable
//!   without the author's machine key. → `Verdict::Drop`: neither
//!   delivered nor forwarded.
//! - **Author flood** — more than one announce per author inside the
//!   per-author window. Valid but redundant. → `Verdict::DeliverOnly`:
//!   local subscribers still see it (the app dedupes), but it is not
//!   forwarded, so the flood dies one hop from its source.
//! - **Anything else** — fresh, in-rate, or *undecodable*. →
//!   `Verdict::Forward`. Fail-open on decode: a future announce format
//!   must not be censored by old relays; garbage without a valid gossip
//!   signature already dies in saorsa-gossip's verify stage.
//!
//! `x0x.machine.announce.v3` (#1964) has its own guard, the
//! `MachineAnnounceV3Guard`. A stale or far-future announce is
//! delivered but not forwarded, and in one window a machine gets one
//! forward plus one forward of changed content. See the guard docs.
//!
//! The classifier is pure and deterministic (caller supplies `now`), so the
//! whole policy is unit-testable without a network.

use std::collections::HashMap;
use std::time::Duration;

/// What to do with an inbound announce payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Deliver locally and forward to eager peers (default behavior).
    Forward,
    /// Deliver locally, do NOT forward (valid but rate-limited).
    DeliverOnly,
    /// Neither deliver nor forward (stale replay).
    Drop,
}

/// Maximum accepted announce age before a payload is classified as a stale
/// replay. Matches the discovery-cache freshness horizon: an announcement
/// this old is already rejected by every receiver's cache gate, so
/// forwarding it can only waste bandwidth.
pub const STALE_ANNOUNCE_TTL_SECS: u64 = 900;

/// Maximum tolerated future skew, mirroring the identity-announcement
/// clock-skew policy. Beyond this the timestamp is not credible and the
/// payload is treated as a replay/forgery artifact.
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Per-author minimum spacing between *forwarded* announces. The legitimate
/// cadence is one announce per [`crate::IDENTITY_HEARTBEAT_INTERVAL_SECS`]
/// (600 s); 60 s leaves a wide margin for join-time announces, consent
/// changes, and multi-address refreshes while capping a flooding author at
/// 1/60th of the storm rate.
pub const PER_AUTHOR_FORWARD_WINDOW: Duration = Duration::from_secs(60);

/// Bound on the per-author rate table. At one entry per distinct announcing
/// author this is far above any realistic network size; the cap only guards
/// against an adversary minting authors to grow the map.
const MAX_TRACKED_AUTHORS: usize = 8192;

/// The author identity and signed timestamp extracted from an announce
/// payload, independent of wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceFacts {
    /// 32-byte author id (agent id for identity announces, machine id for
    /// machine announces).
    pub author: [u8; 32],
    /// The signed `announced_at` (unix seconds).
    pub announced_at: u64,
}

/// Extract [`AnnounceFacts`] from an identity-announce payload (legacy,
/// `X0A2`, or `X0A3`). `None` when the payload does not decode — callers
/// MUST fail open on `None`.
pub fn identity_announce_facts(payload: &[u8]) -> Option<AnnounceFacts> {
    // The wire payload in handle_eager is the x0x V2 GOSSIP ENVELOPE
    // (agent-signed wrapper), not the bare announcement — unwrap it first.
    // Bare bytes are still accepted as a fallback so pre-envelope senders
    // and direct unit inputs classify identically.
    if let Ok(msg) = crate::gossip::pubsub::decode_v2(payload) {
        return identity_announce_facts_bare(&msg.payload);
    }
    identity_announce_facts_bare(payload)
}

fn identity_announce_facts_bare(payload: &[u8]) -> Option<AnnounceFacts> {
    if crate::announce_v3::is_v3_payload(payload) {
        let v3 = crate::announce_v3::deserialize_v3(payload).ok()?;
        return Some(AnnounceFacts {
            author: v3.agent_id.0,
            announced_at: v3.announced_at,
        });
    }
    let v2 = crate::deserialize_identity_announcement(payload).ok()?;
    Some(AnnounceFacts {
        author: v2.agent_id.0,
        announced_at: v2.announced_at,
    })
}

/// Extract [`AnnounceFacts`] from a machine-announce payload.
pub fn machine_announce_facts(payload: &[u8]) -> Option<AnnounceFacts> {
    if let Ok(msg) = crate::gossip::pubsub::decode_v2(payload) {
        return machine_announce_facts_bare(&msg.payload);
    }
    machine_announce_facts_bare(payload)
}

fn machine_announce_facts_bare(payload: &[u8]) -> Option<AnnounceFacts> {
    let ann = crate::deserialize_machine_announcement(payload).ok()?;
    Some(AnnounceFacts {
        author: ann.machine_id.0,
        announced_at: ann.announced_at,
    })
}

/// Per-author forward rate limiter. Time is injected (`now` as a monotonic
/// tick in seconds) so the policy is deterministic under test.
#[derive(Debug, Default)]
pub struct AuthorRate {
    last_forward: HashMap<[u8; 32], u64>,
}

impl AuthorRate {
    /// True when a forward is allowed for this author at `now_secs`;
    /// records the forward when allowed.
    pub fn allow(&mut self, author: [u8; 32], now_secs: u64, window: Duration) -> bool {
        if self.last_forward.len() >= MAX_TRACKED_AUTHORS {
            // Evict entries older than the window rather than growing.
            let cutoff = now_secs.saturating_sub(window.as_secs());
            self.last_forward.retain(|_, t| *t >= cutoff);
        }
        match self.last_forward.get(&author) {
            Some(last) if now_secs.saturating_sub(*last) < window.as_secs() => false,
            _ => {
                self.last_forward.insert(author, now_secs);
                true
            }
        }
    }
}

/// Classify one announce payload.
///
/// `facts` comes from [`identity_announce_facts`] /
/// [`machine_announce_facts`]; pass `None` for an undecodable payload to
/// fail open.
pub fn classify_announce(
    facts: Option<AnnounceFacts>,
    rate: &mut AuthorRate,
    now_unix: u64,
) -> Verdict {
    let Some(facts) = facts else {
        // Unknown format: fail open. Future announce versions must traverse
        // old relays; unsigned garbage already died in sg's verify stage.
        return Verdict::Forward;
    };
    let stale = facts.announced_at + STALE_ANNOUNCE_TTL_SECS < now_unix;
    let far_future = facts.announced_at > now_unix + MAX_FUTURE_SKEW_SECS;
    if stale || far_future {
        return Verdict::Drop;
    }
    if rate.allow(facts.author, now_unix, PER_AUTHOR_FORWARD_WINDOW) {
        Verdict::Forward
    } else {
        Verdict::DeliverOnly
    }
}

/// Window for the inner-payload dedupe on broadcast topics: an identical
/// inner payload (envelope stripped) re-published inside this window is a
/// replay — sg's own payload-replay cache cannot catch it because each
/// re-publish carries a fresh envelope signature, making the wire bytes
/// unique every time (the same envelope-blindness that hid the announce
/// storm from the validators until #423).
///
/// One payload is keyed per author (#1867): the empty-set statement (about
/// 250 bytes) has the same bytes for every sender, but a waiting daemon
/// opens its carrier only on the statement of ITS trusted authority. See
/// `broadcast_replay_key`.
pub const INNER_REPLAY_WINDOW: Duration = Duration::from_secs(300);

/// Domain tag for the per-author replay key of the empty-set statement.
const EMPTY_SET_STATEMENT_KEY_TAG: &[u8] = b"x0x-storm-empty-set-statement-v1";

/// Replay-dedupe key for one inner payload on a broadcast topic.
///
/// When `inner` is the empty-set `statement` and the envelope names an
/// author, the key covers the author too, so each author's statement
/// passes once per window (#1867). Every other payload keeps the plain
/// `blake3(inner)` key: identical record sets from many senders still
/// dedupe network-wide.
fn broadcast_replay_key(
    author: Option<[u8; 32]>,
    inner: &[u8],
    statement: Option<&[u8]>,
) -> [u8; 32] {
    match (author, statement) {
        (Some(author), Some(statement)) if inner == statement => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(EMPTY_SET_STATEMENT_KEY_TAG);
            hasher.update(&author);
            hasher.update(inner);
            *hasher.finalize().as_bytes()
        }
        _ => *blake3::hash(inner).as_bytes(),
    }
}

/// Per-author + inner-payload state for a generic broadcast-topic validator.
#[derive(Debug, Default)]
pub struct BroadcastGuard {
    rate: AuthorRate,
    seen_inner: HashMap<[u8; 32], u64>,
}

impl BroadcastGuard {
    /// Classify a wire payload on a broadcast topic with no per-format
    /// timestamp semantics (revocation sets, group cards):
    ///
    /// - identical INNER payload (envelope stripped) seen inside
    ///   `INNER_REPLAY_WINDOW` → `Drop` (pure replay; receivers already
    ///   have it);
    /// - envelope author exceeding the per-author forward window →
    ///   `DeliverOnly`;
    /// - unwrappable payloads (no envelope) → fail open per the same
    ///   contract as the announce validators.
    pub fn classify(
        &mut self,
        author: Option<[u8; 32]>,
        inner_hash: [u8; 32],
        now_unix: u64,
    ) -> Verdict {
        // Bound + expire the inner-seen table.
        if self.seen_inner.len() >= MAX_TRACKED_AUTHORS {
            let cutoff = now_unix.saturating_sub(INNER_REPLAY_WINDOW.as_secs());
            self.seen_inner.retain(|_, t| *t >= cutoff);
        }
        match self.seen_inner.get(&inner_hash) {
            Some(t) if now_unix.saturating_sub(*t) < INNER_REPLAY_WINDOW.as_secs() => {
                return Verdict::Drop;
            }
            _ => {
                self.seen_inner.insert(inner_hash, now_unix);
            }
        }
        let Some(author) = author else {
            return Verdict::Forward; // fail open: no envelope, unknown sender
        };
        if self.rate.allow(author, now_unix, PER_AUTHOR_FORWARD_WINDOW) {
            Verdict::Forward
        } else {
            Verdict::DeliverOnly
        }
    }
}

/// Classify one wire payload of a guarded broadcast topic.
///
/// `topic` is the name of the guarded topic. `statement` is the empty-set
/// statement of the topic, if the topic has one (see
/// `broadcast_replay_key`).
///
/// Only an envelope that its author signed for this topic can change a
/// table (PR #1877 review). Two envelopes get `Drop` and change nothing:
///
/// - The inner signature is wrong. `decode_v2` returns `Ok` for such an
///   envelope, with the `sender` that the bytes claim, and any peer can
///   make these bytes for any author. No subscriber receives an unverified
///   payload (#1114), so `Drop` loses nothing.
/// - The signed topic is not `topic`. The heartbeat sends the same
///   statement bytes on the v2, v3 and v1 topics, so a peer could copy the
///   v2 statement of an authority to the v1 topic. A publisher on a
///   guarded topic always signs the name of that topic.
///
/// If one of these filled the replay or rate entry of the author it names,
/// the genuine statement of a trusted authority would get `Drop` or
/// `DeliverOnly` for the whole window, and a waiting daemon would stay
/// closed. Bytes that are not a V2 envelope still fail open.
fn classify_broadcast_wire(
    guard: &mut BroadcastGuard,
    topic: &str,
    payload: &[u8],
    statement: Option<&[u8]>,
    now_unix: u64,
) -> Verdict {
    let (author, inner_hash) = match crate::gossip::pubsub::decode_v2(payload) {
        Ok(msg) if !msg.verified || msg.topic != topic => return Verdict::Drop,
        Ok(msg) => {
            let author = msg.sender.map(|a| a.0);
            (
                author,
                broadcast_replay_key(author, msg.payload.as_ref(), statement),
            )
        }
        Err(_) => (None, *blake3::hash(payload).as_bytes()),
    };
    guard.classify(author, inner_hash, now_unix)
}

/// Domain tag for the content digest of a V3 machine announce (#1964).
const MACHINE_V3_CONTENT_TAG: &[u8] = b"x0x-storm-machine-announce-v3-content-v1";

/// Hard cap on the machine table of the V3 guard (#1964 review of #2101).
///
/// An entry must live as long as an announce that is not newer than its
/// `last_announced_at` can still be fresh: up to
/// [`STALE_ANNOUNCE_TTL_SECS`] (900 s) after that time. Each machine
/// announces every 600 s, so the live table is about the number of
/// announcing machines. 32,768 entries is about 3-4 MB and covers the
/// 10,000-node planning target with a wide margin. When the table is full
/// after expiry, a new machine's announce is forwarded without an entry
/// (fail open, counted as `table_full`), so a full table never blocks a
/// real announce.
const MAX_TRACKED_V3_MACHINES: usize = 32_768;

/// Forward state of one machine on `x0x.machine.announce.v3` (#1964).
#[derive(Debug, Clone, Copy)]
struct MachineV3Window {
    /// When the forward window of this machine opened (unix seconds).
    opened_at: u64,
    /// Content digest of the last forwarded announce.
    content: [u8; 32],
    /// True when the one content change of this window was forwarded.
    change_used: bool,
    /// Signed `announced_at` of the last forwarded announce. Kept across
    /// windows: only a strictly newer announce can use a forward slot.
    last_announced_at: u64,
}

impl MachineV3Window {
    /// True when the entry can be removed: its window is over, and every
    /// announce that is not newer than the last forwarded one is stale.
    fn expired(&self, now_unix: u64) -> bool {
        let window_over =
            now_unix.saturating_sub(self.opened_at) >= PER_AUTHOR_FORWARD_WINDOW.as_secs();
        let replays_stale = self
            .last_announced_at
            .saturating_add(STALE_ANNOUNCE_TTL_SECS)
            < now_unix;
        window_over && replays_stale
    }
}

/// Per-machine forward state for `x0x.machine.announce.v3` (#1964).
///
/// Every V3 publish has a fresh `announced_at` and fresh signatures, so
/// the bytes never repeat. The guard keys on the signed machine id and on
/// a digest of the decoded content without the timestamp and signatures.
/// Only an announce whose signed `announced_at` is strictly newer than
/// the last forwarded one of the machine can use a forward slot, so a
/// replay of older valid announces cannot open a window or take the
/// change slot. In one [`PER_AUTHOR_FORWARD_WINDOW`] a machine gets one
/// forward, plus one more forward when the content changes (a real
/// address change is not delayed). Every other announce is delivered
/// locally but not forwarded.
#[derive(Debug, Default)]
pub struct MachineAnnounceV3Guard {
    machines: HashMap<[u8; 32], MachineV3Window>,
    /// The second of the last expiry sweep of a full table; the sweep
    /// runs at most once per second.
    last_sweep: Option<u64>,
}

/// What the V3 machine-announce guard decided, for the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachineV3Outcome {
    /// First announce of the window: forwarded.
    Forwarded,
    /// The one content change of the window: forwarded.
    ForwardedContentChange,
    /// Same content, or a second change, inside the window: deliver only.
    RateLimited,
    /// Not newer than the last forwarded announce of the machine (a
    /// replay or an out-of-order copy): deliver only.
    NotNewer,
    /// Signed timestamp too old or too far in the future: deliver only.
    Stale,
    /// Bad inner envelope, wrong signed topic, or bad machine signature
    /// on an announce that would use a forward slot: drop.
    Forged,
    /// Not a decodable V3 announce: forward (fail open).
    Undecodable,
    /// New machine while the table is full: forward (fail open).
    TableFull,
}

impl MachineV3Outcome {
    fn verdict(self) -> Verdict {
        match self {
            Self::Forwarded
            | Self::ForwardedContentChange
            | Self::Undecodable
            | Self::TableFull => Verdict::Forward,
            Self::RateLimited | Self::NotNewer | Self::Stale => Verdict::DeliverOnly,
            Self::Forged => Verdict::Drop,
        }
    }
}

/// Counters of the V3 machine-announce guard (#1964).
#[derive(Debug, Default)]
pub struct MachineAnnounceV3Stats {
    forwarded: std::sync::atomic::AtomicU64,
    forwarded_content_change: std::sync::atomic::AtomicU64,
    deliver_only_rate_limited: std::sync::atomic::AtomicU64,
    deliver_only_not_newer: std::sync::atomic::AtomicU64,
    deliver_only_stale: std::sync::atomic::AtomicU64,
    dropped_forged: std::sync::atomic::AtomicU64,
    forwarded_undecodable: std::sync::atomic::AtomicU64,
    table_full: std::sync::atomic::AtomicU64,
}

/// Snapshot of [`MachineAnnounceV3Stats`], served on
/// `GET /diagnostics/gossip` as `storm_control.machine_announce_v3`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct MachineAnnounceV3StatsSnapshot {
    /// Announces forwarded as the first announce of a machine's window.
    pub forwarded: u64,
    /// Announces forwarded as the one content change of a window.
    pub forwarded_content_change: u64,
    /// Announces delivered locally but not forwarded (rate limit).
    pub deliver_only_rate_limited: u64,
    /// Announces delivered locally but not forwarded because they were not
    /// newer than the last forwarded announce of the machine.
    pub deliver_only_not_newer: u64,
    /// Announces delivered locally but not forwarded (stale or far-future
    /// signed timestamp).
    pub deliver_only_stale: u64,
    /// Announces dropped: bad inner envelope, wrong signed topic, or a bad
    /// machine signature.
    pub dropped_forged: u64,
    /// Payloads that did not decode as a V3 announce and were forwarded
    /// (fail open).
    pub forwarded_undecodable: u64,
    /// Announces of a new machine forwarded without an entry because the
    /// machine table was full (fail open).
    pub table_full: u64,
}

impl MachineAnnounceV3Stats {
    const fn new() -> Self {
        use std::sync::atomic::AtomicU64;
        Self {
            forwarded: AtomicU64::new(0),
            forwarded_content_change: AtomicU64::new(0),
            deliver_only_rate_limited: AtomicU64::new(0),
            deliver_only_not_newer: AtomicU64::new(0),
            deliver_only_stale: AtomicU64::new(0),
            dropped_forged: AtomicU64::new(0),
            forwarded_undecodable: AtomicU64::new(0),
            table_full: AtomicU64::new(0),
        }
    }

    fn record(&self, outcome: MachineV3Outcome) {
        let counter = match outcome {
            MachineV3Outcome::Forwarded => &self.forwarded,
            MachineV3Outcome::ForwardedContentChange => &self.forwarded_content_change,
            MachineV3Outcome::RateLimited => &self.deliver_only_rate_limited,
            MachineV3Outcome::NotNewer => &self.deliver_only_not_newer,
            MachineV3Outcome::Stale => &self.deliver_only_stale,
            MachineV3Outcome::Forged => &self.dropped_forged,
            MachineV3Outcome::Undecodable => &self.forwarded_undecodable,
            MachineV3Outcome::TableFull => &self.table_full,
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Snapshot the counters.
    #[must_use]
    pub fn snapshot(&self) -> MachineAnnounceV3StatsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        MachineAnnounceV3StatsSnapshot {
            forwarded: self.forwarded.load(Relaxed),
            forwarded_content_change: self.forwarded_content_change.load(Relaxed),
            deliver_only_rate_limited: self.deliver_only_rate_limited.load(Relaxed),
            deliver_only_not_newer: self.deliver_only_not_newer.load(Relaxed),
            deliver_only_stale: self.deliver_only_stale.load(Relaxed),
            dropped_forged: self.dropped_forged.load(Relaxed),
            forwarded_undecodable: self.forwarded_undecodable.load(Relaxed),
            table_full: self.table_full.load(Relaxed),
        }
    }
}

static MACHINE_ANNOUNCE_V3_STATS: MachineAnnounceV3Stats = MachineAnnounceV3Stats::new();

/// Process-wide counters of the `x0x.machine.announce.v3` guard (#1964).
#[must_use]
pub fn machine_announce_v3_stats() -> MachineAnnounceV3StatsSnapshot {
    MACHINE_ANNOUNCE_V3_STATS.snapshot()
}

/// Decode a bare V3 machine announce exactly as the receiver does
/// (`bincode::deserialize` in the discovery listener): fixint encoding,
/// trailing bytes accepted. If the guard refused bytes that receivers
/// accept, an appended byte would make a genuine announce "undecodable"
/// and forwarded without limit (review of #2101). The size limit only
/// bounds allocation; gossip frames are far below it.
fn decode_machine_announce_v3(bare: &[u8]) -> Option<crate::MachineAnnouncementV3> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
        .allow_trailing_bytes()
        .deserialize(bare)
        .ok()
}

/// Digest of the signed content of a V3 machine announce without
/// `announced_at` and the signatures: two publishes of the same machine
/// state have the same digest.
fn machine_v3_content_digest(announcement: &crate::MachineAnnouncementV3) -> Option<[u8; 32]> {
    let mut unsigned = announcement.to_unsigned();
    unsigned.base.announced_at = 0;
    let body = bincode::serialize(&unsigned).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(MACHINE_V3_CONTENT_TAG);
    hasher.update(&body);
    Some(*hasher.finalize().as_bytes())
}

/// Classify one wire payload of `x0x.machine.announce.v3` (#1964) and
/// count the outcome in `stats`.
///
/// The inner envelope rules are those of `classify_broadcast_wire`: an
/// unverified envelope, or one signed for another topic, gets `Drop` and
/// changes no state. Bytes that are not a V2 envelope are read as a bare
/// announce, as on the v2 topics.
fn classify_machine_announce_v3_wire(
    guard: &mut MachineAnnounceV3Guard,
    payload: &[u8],
    now_unix: u64,
    stats: &MachineAnnounceV3Stats,
) -> Verdict {
    let outcome = machine_announce_v3_outcome(guard, payload, now_unix);
    stats.record(outcome);
    outcome.verdict()
}

fn machine_announce_v3_outcome(
    guard: &mut MachineAnnounceV3Guard,
    payload: &[u8],
    now_unix: u64,
) -> MachineV3Outcome {
    let decoded = crate::gossip::pubsub::decode_v2(payload);
    let bare: &[u8] = match &decoded {
        Ok(msg) if !msg.verified || msg.topic != crate::MACHINE_ANNOUNCE_V3_TOPIC => {
            return MachineV3Outcome::Forged;
        }
        Ok(msg) => msg.payload.as_ref(),
        Err(_) => payload,
    };
    let Some(announcement) = decode_machine_announce_v3(bare) else {
        return MachineV3Outcome::Undecodable;
    };
    let Some(content) = machine_v3_content_digest(&announcement) else {
        return MachineV3Outcome::Undecodable;
    };
    guard.classify(
        announcement.base.machine_id.0,
        announcement.base.announced_at,
        content,
        now_unix,
        || announcement.verify().is_ok(),
    )
}

/// Which forward slot of the window an announce would use.
enum MachineV3Slot {
    /// A new window opens.
    Open,
    /// The one content change of the current window.
    Change,
}

impl MachineAnnounceV3Guard {
    /// Decide one announce of `machine`. `verify` runs only when the
    /// announce would use a forward slot, so a flood of copies costs no
    /// extra signature checks, and a forgery cannot take the slot.
    fn classify(
        &mut self,
        machine: [u8; 32],
        announced_at: u64,
        content: [u8; 32],
        now_unix: u64,
        verify: impl FnOnce() -> bool,
    ) -> MachineV3Outcome {
        let stale = announced_at.saturating_add(STALE_ANNOUNCE_TTL_SECS) < now_unix;
        let far_future = announced_at > now_unix.saturating_add(MAX_FUTURE_SKEW_SECS);
        if stale || far_future {
            return MachineV3Outcome::Stale;
        }
        let window = PER_AUTHOR_FORWARD_WINDOW.as_secs();
        let slot = match self.machines.get(&machine) {
            // Only a strictly newer announce can use a slot. The entry
            // keeps `last_announced_at` until every not-newer announce is
            // stale, so a replay after the window still fails here.
            Some(w) if announced_at <= w.last_announced_at => {
                return MachineV3Outcome::NotNewer;
            }
            Some(w) if now_unix.saturating_sub(w.opened_at) < window => {
                if w.content == content || w.change_used {
                    return MachineV3Outcome::RateLimited;
                }
                MachineV3Slot::Change
            }
            Some(_) => MachineV3Slot::Open,
            None => {
                if !self.has_room(now_unix) {
                    return MachineV3Outcome::TableFull;
                }
                MachineV3Slot::Open
            }
        };
        if !verify() {
            return MachineV3Outcome::Forged;
        }
        match slot {
            MachineV3Slot::Open => {
                self.machines.insert(
                    machine,
                    MachineV3Window {
                        opened_at: now_unix,
                        content,
                        change_used: false,
                        last_announced_at: announced_at,
                    },
                );
                MachineV3Outcome::Forwarded
            }
            MachineV3Slot::Change => {
                if let Some(w) = self.machines.get_mut(&machine) {
                    w.content = content;
                    w.change_used = true;
                    w.last_announced_at = announced_at;
                }
                MachineV3Outcome::ForwardedContentChange
            }
        }
    }

    /// True when a new machine can get an entry. A full table is swept
    /// for expired entries at most once per second, so a full table of
    /// live machines does not cost a full scan on every message.
    fn has_room(&mut self, now_unix: u64) -> bool {
        if self.machines.len() < MAX_TRACKED_V3_MACHINES {
            return true;
        }
        if self.last_sweep != Some(now_unix) {
            self.last_sweep = Some(now_unix);
            self.machines.retain(|_, w| !w.expired(now_unix));
        }
        self.machines.len() < MAX_TRACKED_V3_MACHINES
    }
}

/// Register announce-topic validators as the BASE (content) layer of the
/// #674 relay fan-out composite.
///
/// Called once at `PubSubManager` construction. Identity announces (legacy /
/// `X0A2` / `X0A3`) and machine announces each get a classifier keyed on the
/// SIGNED author id; both share the stale-TTL policy. Shard topics carry the
/// same payload formats, but shard ids are per-entity and unbounded — the
/// global broadcast topics are where the measured storm lives, so those are
/// the enforcement points.
///
/// The validators are registered on the [`RelayFanout`] handle, NOT directly
/// on sg: sg's `set_topic_validator` replaces any prior validator for a
/// topic, so a direct registration here would be clobbered by the composite
/// (or vice versa). The composite consults this base layer live on every
/// admitted message and never widens a `Drop`/`DeliverOnly` verdict, so
/// storm-control semantics are unchanged; only the fan-out of a verdict
/// storm control lets through can become lazy (#674 C2/C3).
pub(crate) fn register_announce_validators<T>(
    plumtree: &saorsa_gossip_pubsub::PlumtreePubSub<T>,
    fanout: &std::sync::Arc<crate::gossip::relay_fanout::RelayFanout>,
) where
    T: saorsa_gossip_transport::GossipTransport + Send + Sync + 'static,
{
    use saorsa_gossip_pubsub::ValidationAction;
    use saorsa_gossip_types::TopicId;

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    fn to_action(v: Verdict) -> ValidationAction {
        match v {
            Verdict::Forward => ValidationAction::ForwardAndDeliver,
            Verdict::DeliverOnly => ValidationAction::DeliverOnly,
            Verdict::Drop => ValidationAction::Drop,
        }
    }

    let identity_rate = std::sync::Arc::new(std::sync::Mutex::new(AuthorRate::default()));
    let identity_validator: saorsa_gossip_pubsub::TopicValidator = {
        let rate = std::sync::Arc::clone(&identity_rate);
        std::sync::Arc::new(move |_topic, payload| {
            let facts = identity_announce_facts(payload);
            // A poisoned lock means a panic elsewhere; fail open rather than
            // let the validator become a network-wide censor.
            let Ok(mut rate) = rate.lock() else {
                return ValidationAction::ForwardAndDeliver;
            };
            to_action(classify_announce(facts, &mut rate, now_unix()))
        })
    };
    let identity_topic = TopicId::from_entity(crate::IDENTITY_ANNOUNCE_TOPIC.as_bytes());
    fanout.register_base(identity_topic, identity_validator);
    fanout.ensure_registered(plumtree, identity_topic);

    let machine_rate = std::sync::Arc::new(std::sync::Mutex::new(AuthorRate::default()));
    let machine_validator: saorsa_gossip_pubsub::TopicValidator = {
        let rate = std::sync::Arc::clone(&machine_rate);
        std::sync::Arc::new(move |_topic, payload| {
            let facts = machine_announce_facts(payload);
            let Ok(mut rate) = rate.lock() else {
                return ValidationAction::ForwardAndDeliver;
            };
            to_action(classify_announce(facts, &mut rate, now_unix()))
        })
    };
    let machine_topic = TopicId::from_entity(crate::MACHINE_ANNOUNCE_TOPIC.as_bytes());
    fanout.register_base(machine_topic, machine_validator);
    fanout.ensure_registered(plumtree, machine_topic);

    // #1964: machine announce v3 — stale age, one forward per machine per
    // window plus one content change, deliver-only otherwise.
    let machine_v3_guard =
        std::sync::Arc::new(std::sync::Mutex::new(MachineAnnounceV3Guard::default()));
    let machine_v3_validator: saorsa_gossip_pubsub::TopicValidator = {
        let guard = std::sync::Arc::clone(&machine_v3_guard);
        std::sync::Arc::new(move |_topic, payload| {
            let Ok(mut guard) = guard.lock() else {
                return ValidationAction::ForwardAndDeliver;
            };
            to_action(classify_machine_announce_v3_wire(
                &mut guard,
                payload,
                now_unix(),
                &MACHINE_ANNOUNCE_V3_STATS,
            ))
        })
    };
    let machine_v3_topic = TopicId::from_entity(crate::MACHINE_ANNOUNCE_V3_TOPIC.as_bytes());
    fanout.register_base(machine_v3_topic, machine_v3_validator);
    fanout.ensure_registered(plumtree, machine_v3_topic);

    // Broadcast topics with no per-format timestamp semantics get the
    // generic guard: inner-payload replay dedupe + per-author rate limit.
    // The measured storm migrated here the moment the announce topics were
    // guarded (revocation.v1 hit 405 KB/s of identical stale sets).
    // On the revocation topics the empty-set statement is deduped per
    // author (#1867); see `broadcast_replay_key`.
    let empty_set_statement = crate::revocation::encode_empty_set_statement().ok();
    for (topic, statement) in [
        (crate::REVOCATION_TOPIC, empty_set_statement.clone()),
        (crate::REVOCATION_V3_TOPIC, empty_set_statement),
        ("x0x.discovery.groups", None),
    ] {
        let guard = std::sync::Arc::new(std::sync::Mutex::new(BroadcastGuard::default()));
        let validator: saorsa_gossip_pubsub::TopicValidator = {
            let guard = std::sync::Arc::clone(&guard);
            std::sync::Arc::new(move |_topic, payload| {
                let Ok(mut guard) = guard.lock() else {
                    return ValidationAction::ForwardAndDeliver;
                };
                to_action(classify_broadcast_wire(
                    &mut guard,
                    topic,
                    payload,
                    statement.as_deref(),
                    now_unix(),
                ))
            })
        };
        let topic_id = TopicId::from_entity(topic.as_bytes());
        fanout.register_base(topic_id, validator);
        fanout.ensure_registered(plumtree, topic_id);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const NOW: u64 = 1_787_800_000;

    fn facts(author: u8, announced_at: u64) -> Option<AnnounceFacts> {
        Some(AnnounceFacts {
            author: [author; 32],
            announced_at,
        })
    }

    /// The storm signature: a payload whose signed timestamp is hours old
    /// must never be forwarded OR delivered — replays waste every hop they
    /// touch and receivers' cache gates reject them anyway.
    #[test]
    fn stale_replays_are_dropped() {
        let mut rate = AuthorRate::default();
        let hours_old = NOW - 6 * 3600;
        assert_eq!(
            classify_announce(facts(1, hours_old), &mut rate, NOW),
            Verdict::Drop
        );
        // Just past the TTL boundary also drops…
        assert_eq!(
            classify_announce(facts(2, NOW - STALE_ANNOUNCE_TTL_SECS - 1), &mut rate, NOW),
            Verdict::Drop
        );
        // …and exactly at the boundary still forwards.
        assert_eq!(
            classify_announce(facts(3, NOW - STALE_ANNOUNCE_TTL_SECS), &mut rate, NOW),
            Verdict::Forward
        );
    }

    /// A credible-but-flooding author (fresh timestamps every ~2 s, the
    /// other half of the observed storm) gets one forward per window; the
    /// rest deliver locally only, so the flood dies one hop from its source
    /// without hiding a genuinely fresh announce from the local node.
    #[test]
    fn author_floods_are_forward_limited_not_hidden() {
        let mut rate = AuthorRate::default();
        assert_eq!(
            classify_announce(facts(7, NOW), &mut rate, NOW),
            Verdict::Forward
        );
        for dt in [2, 4, 30, 59] {
            assert_eq!(
                classify_announce(facts(7, NOW + dt), &mut rate, NOW + dt),
                Verdict::DeliverOnly,
                "flood at +{dt}s must not be forwarded"
            );
        }
        assert_eq!(
            classify_announce(facts(7, NOW + 60), &mut rate, NOW + 60),
            Verdict::Forward,
            "window expiry restores forwarding"
        );
    }

    /// Different authors never rate-limit each other: the limiter keys on
    /// the SIGNED author id, not the gossip sender, so one flooding node
    /// cannot starve announcements from healthy agents it relays.
    #[test]
    fn rate_limit_is_per_author() {
        let mut rate = AuthorRate::default();
        for a in 0..20u8 {
            assert_eq!(
                classify_announce(facts(a, NOW), &mut rate, NOW),
                Verdict::Forward
            );
        }
    }

    /// Fail-open contract: undecodable payloads (future formats) forward.
    /// If this regresses, shipping V4 announces would be censored by every
    /// deployed relay running this code.
    #[test]
    fn unknown_formats_fail_open() {
        let mut rate = AuthorRate::default();
        assert_eq!(classify_announce(None, &mut rate, NOW), Verdict::Forward);
    }

    /// Far-future timestamps are as suspect as stale ones (mirrors the
    /// identity clock-skew policy): a forged timestamp cannot buy immunity
    /// from the stale check.
    #[test]
    fn far_future_is_dropped() {
        let mut rate = AuthorRate::default();
        assert_eq!(
            classify_announce(facts(9, NOW + MAX_FUTURE_SKEW_SECS + 1), &mut rate, NOW),
            Verdict::Drop
        );
        assert_eq!(
            classify_announce(facts(10, NOW + MAX_FUTURE_SKEW_SECS), &mut rate, NOW),
            Verdict::Forward
        );
    }

    /// Broadcast-guard semantics: identical inner payloads inside the
    /// replay window are DROPPED even from a compliant author (that is the
    /// revocation-storm signature — same 2-record set re-published forever
    /// under fresh envelope signatures), while distinct payloads from a
    /// flooding author fall back to the per-author DeliverOnly limit, and
    /// envelope-less payloads fail open on authorship.
    #[test]
    fn broadcast_guard_drops_inner_replays_and_limits_authors() {
        let mut g = BroadcastGuard::default();
        let author = Some([1u8; 32]);
        let set_hash = [7u8; 32];
        assert_eq!(g.classify(author, set_hash, NOW), Verdict::Forward);
        // Same inner payload 2s later (fresh envelope in reality) — replay.
        assert_eq!(g.classify(author, set_hash, NOW + 2), Verdict::Drop);
        assert_eq!(g.classify(author, set_hash, NOW + 200), Verdict::Drop);
        // Distinct payload, same author, inside the author window — limited.
        assert_eq!(g.classify(author, [8u8; 32], NOW + 3), Verdict::DeliverOnly);
        // Distinct payload from another author — forwards.
        assert_eq!(
            g.classify(Some([2u8; 32]), [9u8; 32], NOW + 4),
            Verdict::Forward
        );
        // No envelope: dedupe still applies, authorship fails open.
        assert_eq!(g.classify(None, [10u8; 32], NOW + 5), Verdict::Forward);
        assert_eq!(g.classify(None, [10u8; 32], NOW + 6), Verdict::Drop);
        // Window expiry readmits the original set (fallback anti-entropy).
        assert_eq!(
            g.classify(author, set_hash, NOW + INNER_REPLAY_WINDOW.as_secs() + 200),
            Verdict::Forward
        );
    }

    fn statement_1867() -> Vec<u8> {
        crate::revocation::encode_empty_set_statement().unwrap()
    }

    /// Two authors send the same statement bytes inside the window: both
    /// pass, because a waiter needs the statement of ITS authority. An
    /// author that published other bytes inside its forward window gets
    /// `DeliverOnly` for its statement (rate limit, not replay).
    #[test]
    fn statement_from_two_authors_both_pass_1867() {
        let statement = statement_1867();
        let mut g = BroadcastGuard::default();
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let key =
            |author: [u8; 32]| broadcast_replay_key(Some(author), &statement, Some(&statement));
        assert_ne!(key(a), key(b));
        assert_eq!(g.classify(Some(a), key(a), NOW), Verdict::Forward);
        assert_eq!(g.classify(Some(b), key(b), NOW + 1), Verdict::Forward);
        // Author c published a record set first, then its statement.
        let other = broadcast_replay_key(Some(c), b"record set", Some(&statement));
        assert_eq!(g.classify(Some(c), other, NOW + 2), Verdict::Forward);
        assert_eq!(g.classify(Some(c), key(c), NOW + 3), Verdict::DeliverOnly);
    }

    /// The same author's statement repeated inside the window is a replay.
    #[test]
    fn statement_repeat_from_one_author_drops_1867() {
        let statement = statement_1867();
        let mut g = BroadcastGuard::default();
        let a = [1u8; 32];
        let key = broadcast_replay_key(Some(a), &statement, Some(&statement));
        assert_eq!(g.classify(Some(a), key, NOW), Verdict::Forward);
        assert_eq!(g.classify(Some(a), key, NOW + 120), Verdict::Drop);
    }

    /// Any other payload keeps the network-wide key: the same bytes from a
    /// second author are still a replay (the storm fix is unchanged).
    #[test]
    fn same_record_set_from_two_authors_drops_1867() {
        let statement = statement_1867();
        let mut g = BroadcastGuard::default();
        let set = b"identical record set".as_slice();
        let ka = broadcast_replay_key(Some([1u8; 32]), set, Some(&statement));
        let kb = broadcast_replay_key(Some([2u8; 32]), set, Some(&statement));
        assert_eq!(ka, *blake3::hash(set).as_bytes());
        assert_eq!(ka, kb);
        assert_eq!(g.classify(Some([1u8; 32]), ka, NOW), Verdict::Forward);
        assert_eq!(g.classify(Some([2u8; 32]), kb, NOW + 1), Verdict::Drop);
        // A topic with no statement (group cards) uses the plain key too.
        let plain = broadcast_replay_key(Some([1u8; 32]), &statement, None);
        assert_eq!(plain, *blake3::hash(&statement).as_bytes());
    }

    /// A statement with no envelope author falls back to the plain key.
    #[test]
    fn statement_without_author_uses_plain_key_1867() {
        let statement = statement_1867();
        let key = broadcast_replay_key(None, &statement, Some(&statement));
        assert_eq!(key, *blake3::hash(&statement).as_bytes());
        let mut g = BroadcastGuard::default();
        assert_eq!(g.classify(None, key, NOW), Verdict::Forward);
        assert_eq!(g.classify(None, key, NOW + 1), Verdict::Drop);
    }

    /// A copy of `genuine` with one signature byte changed: the envelope
    /// still names the same author, but the inner signature is wrong. A
    /// peer that cannot sign for the author can make these bytes.
    fn forged_copy_1877(genuine: &[u8]) -> Vec<u8> {
        let decoded = crate::gossip::pubsub::decode_v2(genuine).unwrap();
        assert!(decoded.verified);
        let key_len = decoded.sender_public_key.unwrap().len();
        // version (1) + agent id (32) + key length (2) + key + sig length (2)
        let first_signature_byte = 1 + 32 + 2 + key_len + 2;
        let mut forged = genuine.to_vec();
        forged[first_signature_byte] ^= 0x01;
        let decoded = crate::gossip::pubsub::decode_v2(&forged).unwrap();
        assert!(!decoded.verified, "the forged envelope decodes unverified");
        forged
    }

    /// PR #1877 review: an envelope whose inner signature is wrong names an
    /// author that did not sign it. It must not fill that author's replay
    /// entry: the author's genuine statement still passes afterwards.
    #[test]
    fn forged_statement_does_not_block_the_genuine_statement_1877() {
        use crate::gossip::pubsub::test_support::{signed_inner_v2, signing_context};
        let statement = statement_1867();
        let authority = signing_context();
        let genuine = signed_inner_v2(
            &authority,
            crate::REVOCATION_TOPIC,
            &bytes::Bytes::from(statement.clone()),
        );
        let forged = forged_copy_1877(&genuine);
        let mut g = BroadcastGuard::default();
        let forged_verdict = classify_broadcast_wire(
            &mut g,
            crate::REVOCATION_TOPIC,
            &forged,
            Some(&statement),
            NOW,
        );
        let tables_empty = g.seen_inner.is_empty() && g.rate.last_forward.is_empty();
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                &genuine,
                Some(&statement),
                NOW + 1
            ),
            Verdict::Forward,
            "the genuine statement passes after the forgery"
        );
        assert!(tables_empty, "no replay or rate entry from a forgery");
        assert_eq!(
            forged_verdict,
            Verdict::Drop,
            "a forged envelope is not forwarded or delivered"
        );
        // The genuine statement is still a replay on its second arrival, and
        // a later forgery does not change that.
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                &genuine,
                Some(&statement),
                NOW + 2
            ),
            Verdict::Drop
        );
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                &forged,
                Some(&statement),
                NOW + 3
            ),
            Verdict::Drop
        );
    }

    /// A forged envelope with other bytes must not use the forward window
    /// of the author it names: the statement of that author would become
    /// `DeliverOnly` and stop at this relay. It must not fill the
    /// network-wide replay key of a record set either.
    #[test]
    fn forged_payload_does_not_rate_limit_or_dedupe_the_named_author_1877() {
        use crate::gossip::pubsub::test_support::{signed_inner_v2, signing_context};
        let statement = statement_1867();
        let authority = signing_context();
        let set = bytes::Bytes::from_static(b"record set");
        let genuine_set = signed_inner_v2(&authority, crate::REVOCATION_TOPIC, &set);
        let forged_set = forged_copy_1877(&genuine_set);
        let mut g = BroadcastGuard::default();
        let forged_verdict = classify_broadcast_wire(
            &mut g,
            crate::REVOCATION_TOPIC,
            &forged_set,
            Some(&statement),
            NOW,
        );
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                &genuine_set,
                Some(&statement),
                NOW + 1
            ),
            Verdict::Forward,
            "the genuine record set is not a replay of the forgery"
        );
        assert_eq!(forged_verdict, Verdict::Drop);
        let mut g = BroadcastGuard::default();
        classify_broadcast_wire(
            &mut g,
            crate::REVOCATION_TOPIC,
            &forged_set,
            Some(&statement),
            NOW,
        );
        let genuine_statement = signed_inner_v2(
            &authority,
            crate::REVOCATION_TOPIC,
            &bytes::Bytes::from(statement.clone()),
        );
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                &genuine_statement,
                Some(&statement),
                NOW + 1
            ),
            Verdict::Forward,
            "the forgery did not use the forward window of the author"
        );
    }

    /// A statement that the authority signed for another topic (the
    /// heartbeat sends the same statement bytes on v2, v3 and v1) is not a
    /// statement on this topic. A peer can copy it here. It must not fill
    /// the replay entry that the genuine statement on this topic uses.
    #[test]
    fn statement_copied_from_another_topic_does_not_block_the_genuine_statement_1877() {
        use crate::gossip::pubsub::test_support::{signed_inner_v2, signing_context};
        let statement = statement_1867();
        let authority = signing_context();
        let inner = bytes::Bytes::from(statement.clone());
        let genuine = signed_inner_v2(&authority, crate::REVOCATION_TOPIC, &inner);
        let mut g = BroadcastGuard::default();
        let mut copied_verdicts = Vec::new();
        for other in [crate::REVOCATION_V2_TOPIC, crate::REVOCATION_V3_TOPIC] {
            let copied = signed_inner_v2(&authority, other, &inner);
            assert!(crate::gossip::pubsub::decode_v2(&copied).unwrap().verified);
            copied_verdicts.push(classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                &copied,
                Some(&statement),
                NOW,
            ));
        }
        let tables_empty = g.seen_inner.is_empty() && g.rate.last_forward.is_empty();
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                &genuine,
                Some(&statement),
                NOW + 1
            ),
            Verdict::Forward,
            "the genuine v1 statement passes after the copies"
        );
        assert!(tables_empty, "no replay or rate entry from a copy");
        assert_eq!(copied_verdicts, [Verdict::Drop, Verdict::Drop]);
    }

    /// The fail-open contract is unchanged: bytes that are not a V2
    /// envelope keep the whole-payload replay key and forward once.
    #[test]
    fn undecodable_broadcast_payload_still_fails_open_1877() {
        let statement = statement_1867();
        let mut g = BroadcastGuard::default();
        let unknown = b"\xF7 future format".as_slice();
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                unknown,
                Some(&statement),
                NOW
            ),
            Verdict::Forward
        );
        assert_eq!(
            classify_broadcast_wire(
                &mut g,
                crate::REVOCATION_TOPIC,
                unknown,
                Some(&statement),
                NOW + 1
            ),
            Verdict::Drop
        );
    }

    /// A signed V3 machine announce for `machine`, wrapped in an inner V2
    /// envelope that `signer` signed for `topic` — the wire shape of
    /// `x0x.machine.announce.v3`.
    fn machine_v3_wire_1964(
        machine: &crate::identity::MachineKeypair,
        signer: &crate::gossip::pubsub::SigningContext,
        topic: &str,
        port: u16,
        announced_at: u64,
    ) -> Vec<u8> {
        use ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa;
        let mut base = crate::MachineAnnouncement {
            machine_id: machine.machine_id(),
            machine_public_key: machine.public_key().as_bytes().to_vec(),
            machine_signature: Vec::new(),
            addresses: vec![std::net::SocketAddr::from(([192, 0, 2, 1], port))],
            announced_at,
            nat_type: None,
            can_receive_direct: Some(true),
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
        };
        let base_body = bincode::serialize(&base.to_unsigned()).unwrap();
        base.machine_signature = sign_with_ml_dsa(machine.secret_key(), &base_body)
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut v3 = crate::MachineAnnouncementV3 {
            base,
            machine_kem_public_key: Vec::new(),
            placement_digests: Vec::new(),
            move_protocol: 1,
            machine_signature_v3: Vec::new(),
        };
        let v3_body = bincode::serialize(&v3.to_unsigned()).unwrap();
        v3.machine_signature_v3 = sign_with_ml_dsa(machine.secret_key(), &v3_body)
            .unwrap()
            .as_bytes()
            .to_vec();
        assert!(v3.verify().is_ok(), "fixture announce verifies");
        let bare = bytes::Bytes::from(bincode::serialize(&v3).unwrap());
        crate::gossip::pubsub::test_support::signed_inner_v2(signer, topic, &bare).to_vec()
    }

    struct V3Fixture1964 {
        machine: crate::identity::MachineKeypair,
        signer: std::sync::Arc<crate::gossip::pubsub::SigningContext>,
    }

    impl V3Fixture1964 {
        fn new() -> Self {
            Self {
                machine: crate::identity::MachineKeypair::generate().unwrap(),
                signer: crate::gossip::pubsub::test_support::signing_context(),
            }
        }

        fn wire(&self, port: u16, announced_at: u64) -> Vec<u8> {
            machine_v3_wire_1964(
                &self.machine,
                &self.signer,
                crate::MACHINE_ANNOUNCE_V3_TOPIC,
                port,
                announced_at,
            )
        }
    }

    fn v3_verdict_1964(
        guard: &mut MachineAnnounceV3Guard,
        stats: &MachineAnnounceV3Stats,
        wire: &[u8],
        now: u64,
    ) -> Verdict {
        classify_machine_announce_v3_wire(guard, wire, now, stats)
    }

    /// A stale V3 announce (or one far in the future) is delivered locally
    /// but not forwarded, and it does not use the machine's forward slot.
    #[test]
    fn v3_stale_announce_is_delivered_not_forwarded_1964() {
        let m = V3Fixture1964::new();
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        let stale = m.wire(5483, NOW - STALE_ANNOUNCE_TTL_SECS - 1);
        let future = m.wire(5483, NOW + MAX_FUTURE_SKEW_SECS + 1);
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &stale, NOW),
            Verdict::DeliverOnly
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &future, NOW),
            Verdict::DeliverOnly
        );
        assert!(g.machines.is_empty(), "stale copies use no forward slot");
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(5483, NOW), NOW),
            Verdict::Forward,
            "a fresh announce after the stale copies forwards"
        );
        let snap = stats.snapshot();
        assert_eq!(snap.deliver_only_stale, 2);
        assert_eq!(snap.forwarded, 1);
    }

    /// A second announce with the same content inside the window is
    /// delivered but not forwarded; window expiry restores forwarding.
    #[test]
    fn v3_second_announce_in_window_is_not_forwarded_1964() {
        let m = V3Fixture1964::new();
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(5483, NOW), NOW),
            Verdict::Forward
        );
        for dt in [1, 30, 59] {
            assert_eq!(
                v3_verdict_1964(&mut g, &stats, &m.wire(5483, NOW + dt), NOW + dt),
                Verdict::DeliverOnly,
                "re-publish at +{dt}s must not be forwarded"
            );
        }
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(5483, NOW + 60), NOW + 60),
            Verdict::Forward,
            "window expiry restores forwarding"
        );
        let snap = stats.snapshot();
        assert_eq!(snap.forwarded, 2);
        assert_eq!(snap.deliver_only_rate_limited, 3);
    }

    /// One content change inside the window forwards (a real address
    /// change is not delayed); a second change in the same window does
    /// not, and neither does a repeat of the changed content.
    #[test]
    fn v3_one_content_change_forwards_second_does_not_1964() {
        let m = V3Fixture1964::new();
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(5483, NOW), NOW),
            Verdict::Forward
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(6000, NOW + 5), NOW + 5),
            Verdict::Forward,
            "the first content change of the window forwards"
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(6000, NOW + 6), NOW + 6),
            Verdict::DeliverOnly,
            "the changed content repeated is rate limited"
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(7000, NOW + 10), NOW + 10),
            Verdict::DeliverOnly,
            "a second change in the window is not forwarded"
        );
        // The change does not extend the window.
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(7000, NOW + 60), NOW + 60),
            Verdict::Forward
        );
        let snap = stats.snapshot();
        assert_eq!(snap.forwarded, 2);
        assert_eq!(snap.forwarded_content_change, 1);
        assert_eq!(snap.deliver_only_rate_limited, 2);
    }

    /// Different machines never rate-limit each other, even when one
    /// relaying agent wraps all of them.
    #[test]
    fn v3_machines_are_independent_1964() {
        let relay_signer = crate::gossip::pubsub::test_support::signing_context();
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        for i in 0..3u64 {
            let machine = crate::identity::MachineKeypair::generate().unwrap();
            let wire = machine_v3_wire_1964(
                &machine,
                &relay_signer,
                crate::MACHINE_ANNOUNCE_V3_TOPIC,
                5483,
                NOW,
            );
            assert_eq!(
                v3_verdict_1964(&mut g, &stats, &wire, NOW + i),
                Verdict::Forward
            );
        }
        assert_eq!(stats.snapshot().forwarded, 3);
    }

    /// An announce whose machine signature is wrong names a machine that
    /// did not sign it (the #1877 trap). It is dropped and does not use
    /// that machine's forward slot. A V3 announce signed for another topic
    /// is dropped too.
    #[test]
    fn v3_forged_announce_does_not_take_the_forward_slot_1964() {
        let m = V3Fixture1964::new();
        let attacker = crate::identity::MachineKeypair::generate().unwrap();
        // The victim's machine id and key, signed with another key.
        let genuine_bare = {
            let decoded = crate::gossip::pubsub::decode_v2(&m.wire(5483, NOW)).unwrap();
            decoded.payload.to_vec()
        };
        let mut forged: crate::MachineAnnouncementV3 = bincode::deserialize(&genuine_bare).unwrap();
        forged.base.addresses = vec![std::net::SocketAddr::from(([198, 51, 100, 9], 1))];
        let body = bincode::serialize(&forged.to_unsigned()).unwrap();
        forged.machine_signature_v3 =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(attacker.secret_key(), &body)
                .unwrap()
                .as_bytes()
                .to_vec();
        assert!(forged.verify().is_err());
        let forged_wire = crate::gossip::pubsub::test_support::signed_inner_v2(
            &m.signer,
            crate::MACHINE_ANNOUNCE_V3_TOPIC,
            &bytes::Bytes::from(bincode::serialize(&forged).unwrap()),
        );
        let other_topic = machine_v3_wire_1964(
            &m.machine,
            &m.signer,
            crate::MACHINE_ANNOUNCE_TOPIC,
            5483,
            NOW,
        );
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &forged_wire, NOW),
            Verdict::Drop
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &other_topic, NOW),
            Verdict::Drop
        );
        assert!(g.machines.is_empty(), "no forward slot from a forgery");
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(5483, NOW + 1), NOW + 1),
            Verdict::Forward,
            "the genuine announce forwards after the forgeries"
        );
        assert_eq!(stats.snapshot().dropped_forged, 2);
    }

    /// Bytes that are not a V3 announce forward (fail open), so a future
    /// format is not censored by this relay.
    #[test]
    fn v3_undecodable_payload_fails_open_1964() {
        let signer = crate::gossip::pubsub::test_support::signing_context();
        let wire = crate::gossip::pubsub::test_support::signed_inner_v2(
            &signer,
            crate::MACHINE_ANNOUNCE_V3_TOPIC,
            &bytes::Bytes::from_static(b"\xF7 future format"),
        );
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        for dt in 0..3 {
            assert_eq!(
                v3_verdict_1964(&mut g, &stats, &wire, NOW + dt),
                Verdict::Forward
            );
        }
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, b"not an envelope", NOW),
            Verdict::Forward
        );
        assert_eq!(stats.snapshot().forwarded_undecodable, 4);
    }

    /// The v2 machine-announce policy is unchanged by #1964: a stale v2
    /// announce is still dropped (not delivered), a re-publish inside the
    /// window is deliver-only with no content-change exception, and a v3
    /// payload on the v2 classifier fails open as before.
    #[test]
    fn v2_machine_policy_unchanged_1964() {
        let mut rate = AuthorRate::default();
        assert_eq!(
            classify_announce(facts(4, NOW - STALE_ANNOUNCE_TTL_SECS - 1), &mut rate, NOW),
            Verdict::Drop
        );
        assert_eq!(
            classify_announce(facts(5, NOW), &mut rate, NOW),
            Verdict::Forward
        );
        assert_eq!(
            classify_announce(facts(5, NOW + 1), &mut rate, NOW + 1),
            Verdict::DeliverOnly
        );
        let m = V3Fixture1964::new();
        assert!(machine_announce_facts(&m.wire(5483, NOW)).is_none());
    }

    /// Review of #2101: a peer holding two older valid announces of a
    /// machine (still inside the 900 s stale window) replays them after
    /// the window of the current announce expired. Neither is newer than
    /// the last forwarded announce, so neither opens a window or takes the
    /// change slot, and the machine's next real announce forwards.
    #[test]
    fn v3_replayed_older_announces_do_not_take_slots_1964() {
        let m = V3Fixture1964::new();
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        let older_a = m.wire(1000, NOW - 200);
        let older_b = m.wire(2000, NOW - 100);
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(3000, NOW), NOW),
            Verdict::Forward
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &older_a, NOW + 61),
            Verdict::DeliverOnly,
            "an older replay does not open a new window"
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &older_b, NOW + 62),
            Verdict::DeliverOnly,
            "an older replay does not take the change slot"
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(4000, NOW + 63), NOW + 63),
            Verdict::Forward,
            "the real current announce forwards"
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(5000, NOW + 64), NOW + 64),
            Verdict::Forward,
            "and its change slot is still free"
        );
    }

    /// Honest out-of-order arrival: an older copy that arrives after a
    /// newer announce is delivered only and does not take the change slot.
    #[test]
    fn v3_older_copy_after_newer_does_not_take_change_slot_1964() {
        let m = V3Fixture1964::new();
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(2000, NOW), NOW),
            Verdict::Forward
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(1000, NOW - 5), NOW + 1),
            Verdict::DeliverOnly,
            "the older copy is not forwarded"
        );
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &m.wire(3000, NOW + 2), NOW + 2),
            Verdict::Forward,
            "a real change after it still uses the free change slot"
        );
    }

    /// Review of #2101: receivers decode with plain `bincode::deserialize`,
    /// which accepts trailing bytes. A genuine announce with a byte
    /// appended must be classified as the same announce, not forwarded as
    /// undecodable and not counted as a content change.
    #[test]
    fn v3_trailing_bytes_do_not_bypass_the_limit_1964() {
        let m = V3Fixture1964::new();
        let with_trailing = |port: u16, at: u64| {
            let wire = m.wire(port, at);
            let mut bare = crate::gossip::pubsub::decode_v2(&wire)
                .unwrap()
                .payload
                .to_vec();
            bare.push(0);
            assert!(bincode::deserialize::<crate::MachineAnnouncementV3>(&bare).is_ok());
            crate::gossip::pubsub::test_support::signed_inner_v2(
                &m.signer,
                crate::MACHINE_ANNOUNCE_V3_TOPIC,
                &bytes::Bytes::from(bare),
            )
            .to_vec()
        };
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        assert_eq!(
            v3_verdict_1964(&mut g, &stats, &with_trailing(5483, NOW), NOW),
            Verdict::Forward
        );
        for dt in [1, 2, 3] {
            assert_eq!(
                v3_verdict_1964(&mut g, &stats, &with_trailing(5483, NOW + dt), NOW + dt),
                Verdict::DeliverOnly,
                "a trailing byte is neither undecodable nor a content change"
            );
        }
        let snap = stats.snapshot();
        assert_eq!(snap.forwarded, 1);
        assert_eq!(snap.forwarded_undecodable, 0);
        assert_eq!(snap.forwarded_content_change, 0);
    }

    fn machine_key_1964(i: usize) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[..8].copy_from_slice(&(i as u64).to_le_bytes());
        a[31] = 0xA5;
        a
    }

    /// Review of #2101: the machine table has a hard cap. With more live
    /// machines than the cap in one window, a new machine is forwarded
    /// without an entry (fail open, `table_full`), the table does not
    /// grow, and the expiry sweep runs at most once per second.
    #[test]
    fn v3_machine_table_has_a_hard_cap_1964() {
        let cap = super::MAX_TRACKED_V3_MACHINES;
        let mut g = MachineAnnounceV3Guard::default();
        let stats = MachineAnnounceV3Stats::default();
        for i in 0..cap {
            let outcome = g.classify(machine_key_1964(i), NOW, [0u8; 32], NOW, || true);
            assert_eq!(outcome, MachineV3Outcome::Forwarded);
        }
        assert_eq!(g.machines.len(), cap);
        for i in cap..cap + 100 {
            let outcome = g.classify(machine_key_1964(i), NOW + 1, [0u8; 32], NOW + 1, || true);
            stats.record(outcome);
            assert_eq!(
                outcome.verdict(),
                Verdict::Forward,
                "a full table fails open"
            );
        }
        assert_eq!(g.machines.len(), cap, "the table does not grow");
        assert_eq!(stats.snapshot().table_full, 100);
        assert_eq!(g.last_sweep, Some(NOW + 1), "one sweep in that second");
        // A known machine is still limited while the table is full.
        assert_eq!(
            g.classify(machine_key_1964(0), NOW + 2, [0u8; 32], NOW + 2, || true),
            MachineV3Outcome::RateLimited
        );
        // Entries are kept until a replay of their last announce is stale
        // (900 s), not only for the 60 s window.
        let after_window = NOW + 120;
        assert_eq!(
            g.classify(
                machine_key_1964(cap + 1),
                after_window,
                [0u8; 32],
                after_window,
                || true
            ),
            MachineV3Outcome::TableFull
        );
        // Once the stale window has passed, the sweep frees entries.
        let later = NOW + STALE_ANNOUNCE_TTL_SECS + 1;
        assert_eq!(
            g.classify(machine_key_1964(cap + 1), later, [0u8; 32], later, || true),
            MachineV3Outcome::Forwarded
        );
        assert!(g.machines.len() <= cap);
    }

    /// An entry outlives the 60 s window: a replay of an older announce
    /// that is still fresh finds the entry and gets `NotNewer`.
    #[test]
    fn v3_entry_outlives_the_window_for_replays_1964() {
        let mut g = MachineAnnounceV3Guard::default();
        let m = [7u8; 32];
        assert_eq!(
            g.classify(m, NOW, [1u8; 32], NOW, || true),
            MachineV3Outcome::Forwarded
        );
        let w = g.machines.get(&m).copied().unwrap();
        assert!(!w.expired(NOW + 61));
        assert!(!w.expired(NOW + STALE_ANNOUNCE_TTL_SECS));
        assert!(w.expired(NOW + STALE_ANNOUNCE_TTL_SECS + 1));
        assert_eq!(
            g.classify(m, NOW - 1, [2u8; 32], NOW + 800, || true),
            MachineV3Outcome::NotNewer
        );
    }

    /// The author table stays bounded under an author-minting adversary.
    #[test]
    fn author_table_is_bounded() {
        let mut rate = AuthorRate::default();
        for i in 0..(super::MAX_TRACKED_AUTHORS + 100) {
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&(i as u64).to_le_bytes());
            // Old entries: all at NOW - 120 (outside window) so eviction fires.
            rate.allow(a, NOW - 120, PER_AUTHOR_FORWARD_WINDOW);
        }
        // Trigger eviction with a fresh insert.
        rate.allow([0xFF; 32], NOW, PER_AUTHOR_FORWARD_WINDOW);
        assert!(rate.last_forward.len() <= super::MAX_TRACKED_AUTHORS);
    }

    /// End-to-end facts extraction: a real V3 payload yields its signed
    /// author + timestamp, and truncated bytes yield None (fail-open path).
    #[test]
    fn facts_extraction_from_real_v3() {
        let agent = crate::identity::AgentKeypair::generate().unwrap();
        let machine = crate::identity::MachineKeypair::generate().unwrap();
        let v2 = crate::IdentityAnnouncement {
            self_name: None,
            agent_id: agent.agent_id(),
            machine_id: machine.machine_id(),
            user_id: None,
            agent_certificate: None,
            machine_public_key: machine.public_key().as_bytes().to_vec(),
            machine_signature: Vec::new(),
            addresses: vec![],
            announced_at: NOW,
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            agent_public_key: agent.public_key().as_bytes().to_vec(),
        };
        let v3 =
            crate::announce_v3::IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0)
                .unwrap();
        let bytes = crate::announce_v3::serialize_v3(&v3).unwrap();
        let f = identity_announce_facts(&bytes).expect("decodes");
        assert_eq!(f.author, agent.agent_id().0);
        assert_eq!(f.announced_at, NOW);
        assert!(identity_announce_facts(&bytes[..10]).is_none());
    }
}

#[cfg(test)]
mod wiring_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    /// End-to-end wiring proof: a STALE identity announce published by one
    /// agent is DROPPED by the receiving agent's registered validator — the
    /// validator counter increments and the payload is never delivered to
    /// subscribers. If this regresses (topic-id mismatch, registration not
    /// running, sg hook moved), storm control silently stops protecting the
    /// network while everything else stays green.
    #[tokio::test]
    async fn stale_announce_is_dropped_by_receiving_validator() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mk = |n: &str| {
            crate::Agent::builder()
                .with_machine_key(dir.path().join(format!("{n}-machine.key")))
                .with_agent_key_path(dir.path().join(format!("{n}-agent.key")))
                .with_contact_store_path(dir.path().join(format!("{n}-contacts.json")))
                .with_peer_cache_dir(dir.path().join(format!("{n}-peers")))
                .with_network_config(crate::network::NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    bootstrap_nodes: Vec::new(),
                    mdns_enabled: false,
                    ..crate::network::NetworkConfig::default()
                })
        };
        let alice = mk("alice").build().await.expect("alice");
        let bob = mk("bob").build().await.expect("bob");

        // Connect transport + gossip (join_network wires the gossip runtime
        // onto the transport; without it publishes go nowhere).
        alice.join_network().await.expect("alice join");
        bob.join_network().await.expect("bob join");
        let alice_net = alice.network().expect("alice net");
        let bob_net = bob.network().expect("bob net");
        let mut bob_addr = bob_net.bound_addr().await.expect("bob bound");
        if bob_addr.ip().is_unspecified() {
            bob_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        }
        alice_net.connect_addr(bob_addr).await.expect("connect");
        let bob_peer = ant_quic::PeerId(bob.machine_id().0);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if alice_net.is_connected(&bob_peer).await {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(alice_net.is_connected(&bob_peer).await, "transport connect");

        // Both subscribe the identity topic so the eager mesh carries it.
        let _sub_a = alice
            .subscribe(crate::IDENTITY_ANNOUNCE_TOPIC)
            .await
            .unwrap();
        let mut sub_b = bob.subscribe(crate::IDENTITY_ANNOUNCE_TOPIC).await.unwrap();
        // Allow PlumTree to exchange subscription announcements (same wait
        // as tests/group_bidirectional_delivery.rs).
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Craft a STALE but well-formed V3 announce (signed 2h ago).
        let stale_at = now_unix_test() - 7200;
        let machine = crate::identity::MachineKeypair::generate().unwrap();
        let agent_kp = crate::identity::AgentKeypair::generate().unwrap();
        let v2 = crate::IdentityAnnouncement {
            self_name: None,
            agent_id: agent_kp.agent_id(),
            machine_id: machine.machine_id(),
            user_id: None,
            agent_certificate: None,
            machine_public_key: machine.public_key().as_bytes().to_vec(),
            machine_signature: Vec::new(),
            addresses: vec![],
            announced_at: stale_at,
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
        };
        let v3 =
            crate::announce_v3::IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0)
                .unwrap();
        let stale_bytes = crate::announce_v3::serialize_v3(&v3).unwrap();

        // Mesh-proving control: an undecodable payload FORWARDS (fail-open),
        // so its delivery proves the A->B eager path works before we assert
        // on the stale drop (otherwise a dead mesh would greenwash the test).
        alice
            .publish(crate::IDENTITY_ANNOUNCE_TOPIC, b"not-an-announce".to_vec())
            .await
            .expect("control publish");
        let control_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match tokio::time::timeout_at(control_deadline, sub_b.recv()).await {
                Ok(Some(m)) if m.payload.as_ref() == b"not-an-announce" => break,
                Ok(Some(_)) => continue,
                _ => panic!("control payload never delivered — mesh not formed"),
            }
        }

        // Alice publishes the stale payload; Bob's handle_eager must DROP it.
        alice
            .publish(crate::IDENTITY_ANNOUNCE_TOPIC, stale_bytes.clone())
            .await
            .expect("publish");

        let bob_pubsub = bob.gossip_runtime.as_ref().expect("bob runtime").pubsub();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
        let mut dropped = 0u64;
        while tokio::time::Instant::now() < deadline {
            dropped = bob_pubsub.stage_stats().validator.dropped;
            if dropped > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        if dropped == 0 {
            // Diagnose: was it delivered instead (validator not registered /
            // topic mismatch) or lost elsewhere?
            let delivered =
                tokio::time::timeout(std::time::Duration::from_secs(2), sub_b.recv()).await;
            panic!(
                "validator counter stayed 0 — wiring broken; stale delivered to subscriber: {:?}",
                delivered.map(|o| o.map(|m| m.payload.len()))
            );
        }
        // And the STALE payload itself must never reach Bob's subscribers.
        // Other traffic on the topic (the agents' own fresh announces) is
        // legitimate and may arrive in this window — only the crafted stale
        // bytes are forbidden.
        let drain_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(400);
        while let Ok(Some(m)) = tokio::time::timeout_at(drain_deadline, sub_b.recv()).await {
            assert_ne!(
                m.payload.as_ref(),
                stale_bytes.as_slice(),
                "stale announce must not be delivered"
            );
        }
    }

    fn now_unix_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
