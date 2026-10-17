//! Relay fan-out policy — #674 C2/C3 (fleet CPU, inbound/relay side).
//!
//! ~99% of a bootstrap's gossip send-path work is *relayed* traffic:
//! inbound messages on topics the node has no local subscriber for, which
//! saorsa-gossip eager-republishes to the full eager set (measured 242
//! sends/s, 4.27 MB/s per node). sg 0.5.79 adds
//! [`ValidationAction::LazyForward`] — withhold the eager re-publish, keep
//! the message cached and IWANT-serveable, and announce the msg_id via
//! IHAVE (to the lazy set AND every peer whose eager send was withheld) —
//! so delivery is preserved at ~1 IHAVE instead of an EAGER per withheld
//! peer, at the cost of one 100 ms flush + RTT of extra latency.
//!
//! This module owns the x0x side of that verdict, as one composite
//! per-topic validator:
//!
//! 0. **Unsigned inner V1 is refused** (#1226) before content or fan-out
//!    decisions. The outer signature proves the forwarding machine, not
//!    an x0x author. Drop also prevents IHAVE, IWANT and anti-entropy serving.
//! 1. **Base (content) validators first** — the storm-control classifiers
//!    (`crate::storm_control`). Their `Drop`/`DeliverOnly` verdicts always
//!    win: fan-out policy must never *widen* suppression, and a
//!    `LazyForward` would reintroduce an IHAVE announce for a message
//!    storm control refused to forward.
//! 2. **C2 — lazy-only for unconsumed topics.** A topic with zero local
//!    subscribers is never delivered locally anyway; the node's only role
//!    is relay, and lazy relay is strictly cheaper on the send path. The
//!    verdict is `LazyForward` unconditionally (the C3 budget does not buy
//!    eager sends back for topics nobody here consumes). Live subscriber
//!    state is read from the same `subscribed_topic_ids` set the Leaf C0
//!    refuse gate uses, so the last unsubscribe / first subscribe flips
//!    the mode without touching sg validator registration.
//! 3. **C3 — per-topic eager budget for consumed topics.** Topics WITH
//!    local subscribers keep today's eager forwarding inside a token
//!    bucket (messages/s); when the budget is exhausted the topic
//!    degrades to `LazyForward` and recovers as the bucket refills. A
//!    budget of 0 disables the gate (always eager), matching the
//!    `leaf_egress_*_bytes_per_sec` "0 disables" convention.
//!
//! Bootstraps keep `Full` participation, so the relay role and ADR-0034
//! hold for signed traffic. Unsigned inner V1 is refused before relaying.

use saorsa_gossip_pubsub::{TopicValidator, ValidationAction};
use saorsa_gossip_types::TopicId;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// One eager-forward token, in nanosecond-scaled units so refill is
/// continuous integer math (no floats on the hot path).
const TOKEN_UNITS_PER_MSG: u128 = 1_000_000_000;

/// Upper bound on the configurable budget. Guards the u128 refill product
/// (`elapsed_ns × rate`) and operator typos; 100k msgs/s per topic is far
/// above any measured fleet rate (busiest observed topic: ~19/s).
pub const MAX_BUDGET_MSGS_PER_SEC: u64 = 100_000;

/// #697: how long a relay topic may stay silent (no inbound frame, no local
/// subscriber) before its per-topic state is evicted. Relay topics arrive
/// via inbound frames alone (`ensure_registered` on the inbound path), and
/// nothing else reclaimed them — measured ~7 topics/hour, linear, no
/// plateau over 6 h on the bootstraps (tag shards alone allow 65,536).
pub(crate) const RELAY_TOPIC_IDLE_SECS: u64 = 3600;

/// #697: how often the eviction sweep runs. Decoupled from the idle
/// horizon so operators can watch `relay_fanout.topics` fall without a
/// per-frame cost; the first interval tick fires immediately, which only
/// ever evicts already-idle topics.
pub(crate) const RELAY_TOPIC_EVICT_POLL_SECS: u64 = 600;

/// Coarse wall-clock seconds for #697 last-use stamps. Hours-scale
/// horizons do not need monotonic precision; coarse granularity keeps the
/// hot-path refresh to one relaxed atomic store under a read lock.
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The validator registry the lifecycle serializes against — sg's
/// per-topic validator map. A crate-internal seam (NOT a public API) so
/// the #697 review's deterministic interleaving regression can observe
/// the actual install/remove operations and the lock they run under;
/// the only production implementation is the blanket impl for
/// [`saorsa_gossip_pubsub::PlumtreePubSub`].
pub(crate) trait ValidatorRegistry {
    fn install_topic_validator(&self, topic: TopicId, validator: TopicValidator);
    fn clear_topic_validator(&self, topic: TopicId);
}

impl<T> ValidatorRegistry for saorsa_gossip_pubsub::PlumtreePubSub<T>
where
    T: saorsa_gossip_transport::GossipTransport + Send + Sync + 'static,
{
    fn install_topic_validator(&self, topic: TopicId, validator: TopicValidator) {
        self.set_topic_validator(topic, validator);
    }

    fn clear_topic_validator(&self, topic: TopicId) {
        saorsa_gossip_pubsub::PlumtreePubSub::clear_topic_validator(self, topic);
    }
}

/// Per-topic eager-forward token bucket (C3). One token = one message the
/// validator may return `ForwardAndDeliver` for; refill is lazy (computed
/// on `try_acquire`), so idle topics cost nothing. Capacity is one second
/// of the configured rate (burst allowance = rate).
#[derive(Debug)]
struct TokenBucket {
    /// Current tokens, in `TOKEN_UNITS_PER_MSG`-scaled units. Starts at
    /// the `u128::MAX` sentinel so the first `try_acquire` clamps down to
    /// a FULL bucket — capacity is rate-dependent and unknown at
    /// construction, and a fresh topic must get its whole burst allowance
    /// ("tokens left ⇒ ForwardAndDeliver" from message #1).
    tokens: u128,
    last_refill: Instant,
}

impl TokenBucket {
    fn full() -> Self {
        Self {
            tokens: u128::MAX,
            last_refill: Instant::now(),
        }
    }

    /// Refill to `now`, then spend one token if available.
    fn try_acquire(&mut self, rate_per_sec: u64, now: Instant) -> bool {
        let capacity = u128::from(rate_per_sec) * TOKEN_UNITS_PER_MSG;
        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos();
        // saturating_add: the fresh-bucket sentinel must not overflow;
        // after the clamp, tokens ≤ capacity ≪ u128::MAX.
        self.tokens = self
            .tokens
            .saturating_add(refill_units(elapsed_ns, rate_per_sec))
            .min(capacity);
        self.last_refill = now;
        if self.tokens >= TOKEN_UNITS_PER_MSG {
            self.tokens -= TOKEN_UNITS_PER_MSG;
            true
        } else {
            false
        }
    }
}

/// `elapsed_ns × rate` capped at u128::MAX (the caller's clamp dominates).
fn refill_units(elapsed_ns: u128, rate_per_sec: u64) -> u128 {
    elapsed_ns.saturating_mul(u128::from(rate_per_sec))
}
/// Shared x0x relay-fanout state: base validators, the set of topics with
/// a composite registered on sg, C3 buckets, and the live subscriber set.
pub(crate) struct RelayFanout {
    /// Content-based validators (storm control) by topic. The composite
    /// consults these live, so registration order and later swaps are
    /// irrelevant — no sg re-registration needed.
    base: RwLock<HashMap<TopicId, TopicValidator>>,
    /// Topics whose composite validator is registered on sg, with a coarse
    /// unix-seconds last-use stamp (#697). Validators live in a separate
    /// sg map from topic state, so they survive sg `unsubscribe` — the set
    /// never went stale, but it also never shrank: entries idle past
    /// [`RELAY_TOPIC_IDLE_SECS`] with no local subscriber are evicted by
    /// [`RelayFanout::evict_idle`].
    registered: RwLock<HashMap<TopicId, AtomicU64>>,
    /// C3 token buckets by topic, created on the first budget decision.
    /// Bounded by the daemon's topic universe, exactly like sg's own
    /// per-topic maps.
    buckets: RwLock<HashMap<TopicId, TokenBucket>>,
    /// Configured eager budget (msgs/s, 0 = gate disabled).
    budget: RwLock<u64>,
    /// Live locally-subscribed transport topic ids — the same Arc the
    /// PubSubManager maintains for the Leaf C0 refuse gate.
    subscribed_topic_ids: Arc<RwLock<HashSet<TopicId>>>,
    /// `ForwardAndDeliver` verdicts returned by composites. sg meters only
    /// non-default verdicts (`validator.lazy_forward` / `dropped` /
    /// `deliver_only`), so the eager side of the split lives here.
    forward_msgs: AtomicU64,
    /// Structurally valid unsigned inner V1 messages refused by this validator.
    unsigned_inner_v1_dropped: AtomicU64,
}

/// Match the unsigned branch of `decode_auto` without allocating or copying
/// the application payload. Signed/unknown prefixes never fall back to V1.
fn is_unsigned_inner_v1(payload: &[u8]) -> bool {
    let [high @ (0 | 1), low, rest @ ..] = payload else {
        return false;
    };
    let topic_len = usize::from(u16::from_be_bytes([*high, *low]));
    rest.get(..topic_len)
        .is_some_and(|topic| std::str::from_utf8(topic).is_ok())
}

fn read_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

fn write_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

impl RelayFanout {
    pub(crate) fn new(subscribed_topic_ids: Arc<RwLock<HashSet<TopicId>>>) -> Arc<Self> {
        Arc::new(Self {
            base: RwLock::new(HashMap::new()),
            registered: RwLock::new(HashMap::new()),
            buckets: RwLock::new(HashMap::new()),
            budget: RwLock::new(super::config::default_relay_fanout_budget()),
            subscribed_topic_ids,
            forward_msgs: AtomicU64::new(0),
            unsigned_inner_v1_dropped: AtomicU64::new(0),
        })
    }

    /// Apply the operator's C3 budget (messages/s; 0 disables the gate).
    /// Existing buckets keep their units but re-capacity on next use, so a
    /// lowered budget takes effect within one second.
    pub(crate) fn set_budget(&self, msgs_per_sec: u64) {
        *write_unpoisoned(&self.budget) = msgs_per_sec.min(MAX_BUDGET_MSGS_PER_SEC);
    }

    /// The effective (clamped) budget for diagnostics — differs from the
    /// raw config value only when an operator set a value above
    /// [`MAX_BUDGET_MSGS_PER_SEC`]; reporting the enforced number keeps
    /// `relay_fanout.budget_msgs_per_sec` honest (Greptile P2, PR #695).
    pub(crate) fn effective_budget(&self) -> u64 {
        *read_unpoisoned(&self.budget)
    }

    /// Register (or replace) a content-based base validator for a topic.
    /// Called at construction for the storm-control topics; the verdict
    /// takes effect on the next inbound message with no sg re-registration.
    pub(crate) fn register_base(&self, topic: TopicId, validator: TopicValidator) {
        write_unpoisoned(&self.base).insert(topic, validator);
    }

    /// Idempotently register this topic's composite validator on the
    /// registry. Cheap on the hot path (one read-lock map lookup); the
    /// write path runs once per topic lifetime. Called from the subscribe
    /// path (topic creation), the inbound path (topics sg learns from
    /// peers without a local subscription — the relay case C2 exists for;
    /// the per-frame call is also the #697 last-use refresh), and
    /// construction for the storm-control topics.
    ///
    /// The registry install runs UNDER the `registered` write lock, so map
    /// membership and the validator's presence on the registry can never
    /// disagree (the #697 review's P1: clearing after an unlock let a
    /// concurrent install land between the map removal and the clear,
    /// leaving a member with no validator forever).
    pub(crate) fn ensure_registered<R: ValidatorRegistry + ?Sized>(
        self: &Arc<Self>,
        registry: &R,
        topic: TopicId,
    ) {
        if self.note_topic_use(&topic) {
            return;
        }
        let mut registered = write_unpoisoned(&self.registered);
        if registered.contains_key(&topic) {
            // Raced another registration; it installed the composite under
            // this same lock. Refresh the stamp it wrote and bail.
            if let Some(last_use) = registered.get(&topic) {
                last_use.store(unix_now_secs(), Ordering::Relaxed);
            }
            return;
        }
        let fanout = Arc::clone(self);
        let validator: TopicValidator =
            Arc::new(move |topic, payload| fanout.verdict(topic, payload));
        registry.install_topic_validator(topic, validator);
        registered.insert(topic, AtomicU64::new(unix_now_secs()));
    }

    /// #697 hot-path last-use refresh: one relaxed atomic store under the
    /// read lock keeps an entry off the eviction path. Returns whether the
    /// topic was already registered (the `ensure_registered` fast path).
    fn note_topic_use(&self, topic: &TopicId) -> bool {
        read_unpoisoned(&self.registered)
            .get(topic)
            .is_some_and(|last_use| {
                last_use.store(unix_now_secs(), Ordering::Relaxed);
                true
            })
    }

    /// #697: evict per-topic relay state for topics that have been silent
    /// for `idle_secs` AND have no local subscriber AND carry no base
    /// (storm-control) validator. The registry removal runs UNDER the
    /// `registered` write lock (same serialization as the install side),
    /// and each evicted topic's C3 bucket is reclaimed. An evicted topic
    /// sighted again on the inbound path simply re-registers through
    /// `ensure_registered` — eviction trades one re-install for the
    /// reclaim. `now_secs` is a parameter (not read from the clock) so the
    /// sweep is deterministic under test.
    fn evict_idle<R: ValidatorRegistry + ?Sized>(
        &self,
        now_secs: u64,
        idle_secs: u64,
        registry: &R,
    ) -> Vec<TopicId> {
        let mut registered = write_unpoisoned(&self.registered);
        let subscribed = read_unpoisoned(&self.subscribed_topic_ids);
        let base = read_unpoisoned(&self.base);
        let mut evicted = Vec::new();
        registered.retain(|topic, last_use| {
            let idle = now_secs.saturating_sub(last_use.load(Ordering::Relaxed));
            let keep = idle < idle_secs || subscribed.contains(topic) || base.contains_key(topic);
            if !keep {
                evicted.push(*topic);
            }
            keep
        });
        drop(base);
        drop(subscribed);
        // Still holding the `registered` write lock: the registry clear
        // must not interleave with a concurrent install (see
        // `ensure_registered`).
        for topic in &evicted {
            registry.clear_topic_validator(*topic);
        }
        drop(registered);
        if !evicted.is_empty() {
            let mut buckets = write_unpoisoned(&self.buckets);
            for topic in &evicted {
                buckets.remove(topic);
            }
        }
        evicted
    }

    /// #697 sweep wired into the manager: evict idle relay topics and drop
    /// their registry composites. Called from a slow interval task (see
    /// the PubSubManager constructor), not the hot path.
    pub(crate) fn evict_idle_topics<R: ValidatorRegistry + ?Sized>(&self, registry: &R) {
        self.evict_idle(unix_now_secs(), RELAY_TOPIC_IDLE_SECS, registry);
    }

    /// #697 test probe: whether the `registered` lifecycle lock is
    /// currently write-held. The deterministic interleaving regression
    /// asserts this from INSIDE its registry's install/remove, proving
    /// the actual sg-side operations can only run under the lifecycle
    /// lock (the review's P1 — the old code cleared after unlocking).
    #[cfg(test)]
    fn registered_write_locked_for_test(&self) -> bool {
        self.registered.try_write().is_err()
    }

    /// Number of topics with a composite validator registered (diagnostics).
    pub(crate) fn registered_topics(&self) -> usize {
        read_unpoisoned(&self.registered).len()
    }

    /// Cumulative `ForwardAndDeliver` verdicts (diagnostics; sg meters only
    /// the non-default verdicts).
    pub(crate) fn forward_msgs(&self) -> u64 {
        self.forward_msgs.load(Ordering::Relaxed)
    }

    /// Refused unsigned inner V1 envelopes since this manager started.
    pub(crate) fn unsigned_inner_v1_dropped(&self) -> u64 {
        self.unsigned_inner_v1_dropped.load(Ordering::Relaxed)
    }

    /// The composite verdict for one admitted inbound message. Ordering is
    /// load-bearing: refuse unsigned V1, then apply content suppression, C2
    /// (unconsumed ⇒ lazy), and C3 (budgeted eager for consumed topics).
    fn verdict(&self, topic: &TopicId, payload: &[u8]) -> ValidationAction {
        // #1226: the machine's valid outer signature cannot authorize an
        // unsigned author payload. SG applies this composite after outer
        // verification, including key-cache replay, and marks Drop entries
        // never-serveable before any delivery, IHAVE or EAGER forwarding.
        if is_unsigned_inner_v1(payload) {
            self.unsigned_inner_v1_dropped
                .fetch_add(1, Ordering::Relaxed);
            return ValidationAction::Drop;
        }
        // 1. Content validators first; never widen Drop/DeliverOnly.
        let base = read_unpoisoned(&self.base).get(topic).cloned();
        if let Some(validator) = base {
            let action = validator(topic, payload);
            if action != ValidationAction::ForwardAndDeliver {
                return action;
            }
        }
        // 2. C2: nothing here consumes the topic — relay it lazily.
        if !read_unpoisoned(&self.subscribed_topic_ids).contains(topic) {
            return ValidationAction::LazyForward;
        }
        // 3. C3: budgeted eager for consumed topics.
        if self.spend_budget_token(topic) {
            self.forward_msgs.fetch_add(1, Ordering::Relaxed);
            ValidationAction::ForwardAndDeliver
        } else {
            ValidationAction::LazyForward
        }
    }

    /// Spend one C3 token for `topic`. A budget of 0 disables the gate
    /// (always eager), mirroring the `leaf_egress_*` "0 disables" config
    /// convention.
    fn spend_budget_token(&self, topic: &TopicId) -> bool {
        let rate = *read_unpoisoned(&self.budget);
        if rate == 0 {
            return true;
        }
        let mut buckets = write_unpoisoned(&self.buckets);
        let now = Instant::now();
        buckets
            .entry(*topic)
            .or_insert_with(TokenBucket::full)
            .try_acquire(rate, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::PoisonError;

    fn subscriber_set() -> Arc<RwLock<HashSet<TopicId>>> {
        Arc::new(RwLock::new(HashSet::new()))
    }

    /// Registry stub for state-level tests: no sg instance needed.
    struct NoopRegistry;
    impl ValidatorRegistry for NoopRegistry {
        fn install_topic_validator(&self, _topic: TopicId, _validator: TopicValidator) {}
        fn clear_topic_validator(&self, _topic: TopicId) {}
    }

    /// Records the actual install/remove operations and asserts — from
    /// inside the operation — that the fanout's lifecycle lock is
    /// write-held at that moment. With the pre-P1 code (clear after
    /// unlock) the eviction-side assert fires; this is the deterministic
    /// interleaving regression: no scheduler dependence, the serialization
    /// itself is pinned.
    struct LockProbingRegistry {
        fanout: Arc<RelayFanout>,
        ops: Mutex<Vec<(&'static str, TopicId)>>,
    }

    impl ValidatorRegistry for LockProbingRegistry {
        fn install_topic_validator(&self, topic: TopicId, _validator: TopicValidator) {
            assert!(
                self.fanout.registered_write_locked_for_test(),
                "install must run under the registered lifecycle lock (P1)"
            );
            self.ops
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(("install", topic));
        }

        fn clear_topic_validator(&self, topic: TopicId) {
            assert!(
                self.fanout.registered_write_locked_for_test(),
                "clear must run under the registered lifecycle lock (P1)"
            );
            self.ops
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(("clear", topic));
        }
    }

    #[test]
    fn issue1226_unsigned_inner_v1_drops_before_base_and_fanout() {
        let subscribed = subscriber_set();
        let fanout = RelayFanout::new(Arc::clone(&subscribed));
        let topic = TopicId::new([26; 32]);
        let base_calls = Arc::new(AtomicU64::new(0));
        let calls = Arc::clone(&base_calls);
        fanout.register_base(
            topic,
            Arc::new(move |_, _| {
                calls.fetch_add(1, Ordering::Relaxed);
                ValidationAction::ForwardAndDeliver
            }),
        );
        for consumed in [false, true] {
            if consumed {
                write_unpoisoned(&subscribed).insert(topic);
            }
            assert_eq!(
                fanout.verdict(&topic, b"\0\x01tdata"),
                ValidationAction::Drop
            );
            assert_eq!(fanout.verdict(&topic, b"\0\0"), ValidationAction::Drop);
        }
        assert_eq!(fanout.unsigned_inner_v1_dropped(), 4);
        assert_eq!(base_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fanout.forward_msgs(), 0);
        assert!(read_unpoisoned(&fanout.buckets).is_empty());
        for signed_prefix in [2, 3] {
            assert_eq!(
                fanout.verdict(&topic, &[signed_prefix, 0]),
                ValidationAction::ForwardAndDeliver
            );
        }
        assert_eq!(fanout.unsigned_inner_v1_dropped(), 4);
    }

    #[test]
    fn issue1226_unsigned_classifier_keeps_version_and_shape_boundaries() {
        assert!(is_unsigned_inner_v1(b"\0\x02\xc3\xa9payload"));
        let mut longest = vec![1, 255];
        longest.extend(vec![b'x'; 511]);
        assert!(is_unsigned_inner_v1(&longest));
        for malformed in [&b""[..], &b"\0"[..], &b"\0\x02t"[..], &b"\0\x01\xff"[..]] {
            assert!(!is_unsigned_inner_v1(malformed));
        }
        for prefix in 2..=255 {
            let mut bytes = vec![prefix, 0];
            bytes.extend(vec![b'x'; usize::from(prefix) * 256]);
            assert!(!is_unsigned_inner_v1(&bytes));
        }
    }

    #[test]
    fn c2_unconsumed_topic_is_always_lazy_even_with_budget() {
        // Why (#674 C2): a relay with zero local subscribers on a topic has
        // no delivery obligation locally; eager re-publish is pure send-path
        // cost (the measured 242 sends/s on bootstraps). The budget must
        // NOT buy eager sends back for topics nobody here consumes.
        let subscribed = subscriber_set();
        let fanout = RelayFanout::new(Arc::clone(&subscribed));
        fanout.set_budget(100);
        let topic = TopicId::new([7; 32]);
        for _ in 0..10 {
            assert_eq!(
                fanout.verdict(&topic, b"payload"),
                ValidationAction::LazyForward
            );
        }
        // First subscribe flips the topic to budgeted eager.
        write_unpoisoned(&subscribed).insert(topic);
        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::ForwardAndDeliver
        );
        // Last unsubscribe flips it back to lazy.
        write_unpoisoned(&subscribed).remove(&topic);
        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::LazyForward
        );
    }

    #[test]
    fn c3_budget_exhausts_then_refills() {
        // Why (#674 C3): a storm on a consumed topic must degrade the
        // relay's forwarding to lazy rather than amplifying it, and must
        // recover as the bucket refills — degradation, not a new floor.
        let subscribed = subscriber_set();
        let fanout = RelayFanout::new(Arc::clone(&subscribed));
        fanout.set_budget(2);
        let topic = TopicId::new([9; 32]);
        write_unpoisoned(&subscribed).insert(topic);
        // Burst (1 s of rate) forwards eagerly, then the immediate next
        // message on the same topic goes lazy.
        assert_eq!(
            fanout.verdict(&topic, b"p1"),
            ValidationAction::ForwardAndDeliver
        );
        assert_eq!(
            fanout.verdict(&topic, b"p2"),
            ValidationAction::ForwardAndDeliver
        );
        assert_eq!(
            fanout.verdict(&topic, b"p3"),
            ValidationAction::LazyForward,
            "burst capacity exhausted — storm degrades to lazy"
        );
        // Refill math, with explicit clocks: 0.4 s refills 0.8 tokens
        // (still lazy), a full second refills one token.
        let mut bucket = TokenBucket::full();
        let t0 = Instant::now();
        assert!(bucket.try_acquire(2, t0), "first token");
        assert!(bucket.try_acquire(2, t0), "second token");
        assert!(
            !bucket.try_acquire(2, t0),
            "burst capacity (1s of rate) exhausted"
        );
        assert!(
            !bucket.try_acquire(2, t0 + std::time::Duration::from_millis(400)),
            "0.4s refills only 0.8 tokens"
        );
        assert!(
            bucket.try_acquire(2, t0 + std::time::Duration::from_millis(600)),
            "1s total refills one full token"
        );
        // Sustained max rate holds indefinitely (refill == spend).
        let mut t = t0 + std::time::Duration::from_secs(10);
        for _ in 0..100 {
            assert!(bucket.try_acquire(2, t), "at-rate acquire must hold");
            t += std::time::Duration::from_millis(500);
        }
    }

    #[test]
    fn c3_zero_budget_disables_the_gate() {
        // Why: 0 must mean "off" like every other gossip budget knob, not
        // "zero tokens" (that would silently lazy-forward every consumed
        // topic and needs an extra escape hatch to undo).
        let subscribed = subscriber_set();
        let fanout = RelayFanout::new(Arc::clone(&subscribed));
        fanout.set_budget(0);
        let topic = TopicId::new([3; 32]);
        write_unpoisoned(&subscribed).insert(topic);
        for _ in 0..1000 {
            assert_eq!(
                fanout.verdict(&topic, b"payload"),
                ValidationAction::ForwardAndDeliver
            );
        }
    }

    #[test]
    fn effective_budget_reports_the_enforced_clamp() {
        // Why (Greptile P2, PR #695): diagnostics must report what is
        // enforced, not what was configured — an operator setting 1M msg/s
        // sees the 100k clamp in `relay_fanout.budget_msgs_per_sec`
        // instead of a number nothing on the wire honours.
        let fanout = RelayFanout::new(subscriber_set());
        assert_eq!(fanout.effective_budget(), 50, "construction default");
        fanout.set_budget(1_000_000);
        assert_eq!(fanout.effective_budget(), MAX_BUDGET_MSGS_PER_SEC);
        fanout.set_budget(0);
        assert_eq!(fanout.effective_budget(), 0);
    }

    #[test]
    fn base_suppression_wins_over_fanout_policy() {
        // Why: storm control classifies by SIGNED content (stale replay /
        // author flood). A LazyForward verdict would announce a refused
        // message via IHAVE — widening suppression is never allowed, in
        // either direction of the budget.
        let subscribed = subscriber_set();
        let fanout = RelayFanout::new(subscribed);
        fanout.set_budget(100);
        let topic = TopicId::new([5; 32]);
        let verdicts = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&verdicts);
        fanout.register_base(
            topic,
            Arc::new(move |_topic, _payload| {
                counter.fetch_add(1, Ordering::Relaxed);
                ValidationAction::Drop
            }),
        );
        assert_eq!(fanout.verdict(&topic, b"payload"), ValidationAction::Drop);
        assert_eq!(verdicts.load(Ordering::Relaxed), 1, "base ran exactly once");

        // A base DeliverOnly also wins over both C2-lazy and C3-eager.
        fanout.register_base(topic, Arc::new(|_t, _p| ValidationAction::DeliverOnly));
        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::DeliverOnly
        );

        // Base Forward falls through to the fan-out policy (C2 lazy here).
        fanout.register_base(
            topic,
            Arc::new(|_t, _p| ValidationAction::ForwardAndDeliver),
        );

        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::LazyForward
        );
    }
    // #697: per-topic relay state (registered composites + C3 buckets) grew
    // monotonically on relays (~7 topics/hour, linear, no plateau across
    // 6 h) because nothing reclaimed entries for topics that stopped being
    // relayed. The sweep evicts only topics that are idle AND unsubscribed
    // AND base-validator-free; anything active, locally consumed, or
    // storm-controlled survives. The sweep's clock is a parameter, so the
    // stamps below are deterministic.
    #[test]
    fn idle_relay_topics_are_evicted_active_subscribed_and_base_survive() {
        let subscribed = subscriber_set();
        let fanout = RelayFanout::new(Arc::clone(&subscribed));

        let idle_unsub = TopicId::new([11; 32]);
        let active_unsub = TopicId::new([12; 32]);
        let idle_sub = TopicId::new([13; 32]);
        let idle_base = TopicId::new([14; 32]);
        let now = 10_000u64;
        let stale = now - 2 * RELAY_TOPIC_IDLE_SECS;
        {
            let mut registered = write_unpoisoned(&fanout.registered);
            for (topic, stamp) in [
                (idle_unsub, stale),
                (active_unsub, now),
                (idle_sub, stale),
                (idle_base, stale),
            ] {
                registered.insert(topic, AtomicU64::new(stamp));
            }
        }
        write_unpoisoned(&subscribed).insert(idle_sub);
        fanout.register_base(
            idle_base,
            Arc::new(|_t, _p| ValidationAction::ForwardAndDeliver),
        );
        {
            let mut buckets = write_unpoisoned(&fanout.buckets);
            buckets.insert(idle_unsub, TokenBucket::full());
            buckets.insert(idle_sub, TokenBucket::full());
        }

        let evicted = fanout.evict_idle(now, RELAY_TOPIC_IDLE_SECS, &NoopRegistry);

        assert_eq!(
            evicted,
            vec![idle_unsub],
            "only the idle+unsubscribed+baseless topic is evicted"
        );
        assert_eq!(
            fanout.registered_topics(),
            3,
            "active, subscribed and base topics survive"
        );
        assert!(
            !read_unpoisoned(&fanout.buckets).contains_key(&idle_unsub),
            "the evicted topic's bucket is reclaimed too"
        );
        assert!(
            read_unpoisoned(&fanout.buckets).contains_key(&idle_sub),
            "a surviving topic keeps its bucket"
        );
    }

    // #697 growth bound: churn through a large relay-topic universe and the
    // state stays reclaimable — one sweep returns the maps to the retained
    // set instead of growing without bound (tag shards alone allow 65,536).
    #[test]
    fn relay_topic_state_is_bounded_under_topic_churn() {
        let fanout = RelayFanout::new(subscriber_set());
        let now = 10_000u64;
        let stale = now - 2 * RELAY_TOPIC_IDLE_SECS;
        {
            let mut registered = write_unpoisoned(&fanout.registered);
            let mut buckets = write_unpoisoned(&fanout.buckets);
            for i in 0..1_000u32 {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&i.to_be_bytes());
                let topic = TopicId::new(bytes);
                registered.insert(topic, AtomicU64::new(stale));
                buckets.insert(topic, TokenBucket::full());
            }
        }
        assert_eq!(fanout.registered_topics(), 1_000);

        let evicted = fanout.evict_idle(now, RELAY_TOPIC_IDLE_SECS, &NoopRegistry);

        assert_eq!(evicted.len(), 1_000);
        assert_eq!(
            fanout.registered_topics(),
            0,
            "nothing survives a fully idle universe"
        );
        assert!(
            read_unpoisoned(&fanout.buckets).is_empty(),
            "every evicted topic's bucket is reclaimed"
        );
    }

    // #697: an inbound frame refreshes the last-use stamp, keeping a live
    // relay topic off the eviction path (the hot-path half of the fix).
    #[test]
    fn inbound_sight_refreshes_last_use_against_eviction() {
        let fanout = RelayFanout::new(subscriber_set());
        let topic = TopicId::new([15; 32]);
        write_unpoisoned(&fanout.registered).insert(topic, AtomicU64::new(0));

        fanout.note_topic_use(&topic);

        let evicted = fanout.evict_idle(unix_now_secs(), RELAY_TOPIC_IDLE_SECS, &NoopRegistry);
        assert!(evicted.is_empty(), "a freshly sighted topic is not idle");
        assert_eq!(fanout.registered_topics(), 1);
    }

    // P1 regression (#697 review): the eviction's registry clear and the
    // registration's install must be serialized against the `registered`
    // map by the SAME write lock — the pre-fix code removed the entry,
    // unlocked, then cleared, so a concurrent install could land between
    // the map removal and the clear, leaving the topic a map member with
    // NO validator on the registry (C2/C3 gone) forever. The probing
    // registry asserts lock-held from inside each actual operation (no
    // scheduler-dependent interleaving), and the op sequence pins the
    // full lifecycle: install → clear → re-install after a re-sight.
    #[test]
    fn install_and_clear_are_serialized_under_the_lifecycle_lock() {
        let fanout = RelayFanout::new(subscriber_set());
        let registry = LockProbingRegistry {
            fanout: Arc::clone(&fanout),
            ops: Mutex::new(Vec::new()),
        };
        let topic = TopicId::new([21; 32]);
        let now = 10_000u64;

        fanout.ensure_registered(&registry, topic);
        assert_eq!(fanout.registered_topics(), 1);

        // Age the topic out; the clear runs under the lifecycle lock.
        write_unpoisoned(&fanout.registered)
            .insert(topic, AtomicU64::new(now - 2 * RELAY_TOPIC_IDLE_SECS));
        let evicted = fanout.evict_idle(now, RELAY_TOPIC_IDLE_SECS, &registry);
        assert_eq!(evicted, vec![topic]);
        assert_eq!(fanout.registered_topics(), 0);

        // A re-sighted topic re-installs coherently — the exact sequence
        // the P1 gap could corrupt is now atomic end-to-end.
        fanout.ensure_registered(&registry, topic);
        assert_eq!(fanout.registered_topics(), 1);

        let ops = registry.ops.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            *ops,
            vec![("install", topic), ("clear", topic), ("install", topic)],
            "exactly one coherent install/clear/install lifecycle"
        );
    }
}
