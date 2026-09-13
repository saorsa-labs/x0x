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
//! hold; this changes *how* relays forward (lazy first), not *whether*.

use saorsa_gossip_pubsub::{TopicValidator, ValidationAction};
use saorsa_gossip_types::TopicId;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Instant;

/// One eager-forward token, in nanosecond-scaled units so refill is
/// continuous integer math (no floats on the hot path).
const TOKEN_UNITS_PER_MSG: u128 = 1_000_000_000;

/// Upper bound on the configurable budget. Guards the u128 refill product
/// (`elapsed_ns × rate`) and operator typos; 100k msgs/s per topic is far
/// above any measured fleet rate (busiest observed topic: ~19/s).
pub const MAX_BUDGET_MSGS_PER_SEC: u64 = 100_000;

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
    /// Topics whose composite validator is registered on sg. Validators
    /// live in a separate sg map from topic state, so they survive sg
    /// `unsubscribe` (topic-state removal) — the set never goes stale.
    registered: RwLock<HashSet<TopicId>>,
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
            registered: RwLock::new(HashSet::new()),
            buckets: RwLock::new(HashMap::new()),
            budget: RwLock::new(super::config::default_relay_fanout_budget()),
            subscribed_topic_ids,
            forward_msgs: AtomicU64::new(0),
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

    /// Idempotently register this topic's composite validator on sg. Cheap
    /// on the hot path (one read-lock set lookup); the write path runs
    /// once per topic lifetime. Called from the subscribe path (topic
    /// creation), the inbound path (topics sg learns from peers without a
    /// local subscription — the relay case C2 exists for), and
    /// construction for the storm-control topics.
    pub(crate) fn ensure_registered<T>(
        self: &Arc<Self>,
        plumtree: &saorsa_gossip_pubsub::PlumtreePubSub<T>,
        topic: TopicId,
    ) where
        T: saorsa_gossip_transport::GossipTransport + Send + Sync + 'static,
    {
        if read_unpoisoned(&self.registered).contains(&topic) {
            return;
        }
        if !write_unpoisoned(&self.registered).insert(topic) {
            return; // raced another registration; it installed the composite
        }
        let fanout = Arc::clone(self);
        let validator: TopicValidator =
            Arc::new(move |topic, payload| fanout.verdict(topic, payload));
        plumtree.set_topic_validator(topic, validator);
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

    /// The composite verdict for one admitted inbound message. Ordering is
    /// load-bearing: content suppression wins, then C2 (unconsumed ⇒ lazy),
    /// then C3 (budgeted eager for consumed topics).
    fn verdict(&self, topic: &TopicId, payload: &[u8]) -> ValidationAction {
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
    use std::sync::atomic::AtomicU64;

    fn subscriber_set() -> Arc<RwLock<HashSet<TopicId>>> {
        Arc::new(RwLock::new(HashSet::new()))
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
}
