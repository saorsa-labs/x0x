use saorsa_gossip_pubsub::{TopicValidator, ValidationAction};
use saorsa_gossip_types::TopicId;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const TOKEN_UNITS_PER_MSG: u128 = 1_000_000_000;

/// Upper bound on the configurable budget; guards against operator typos.
/// 100k/s per topic is far above any measured fleet rate (busiest observed: ~19/s).
pub const MAX_BUDGET_MSGS_PER_SEC: u64 = 100_000;

/// #697: nothing reclaimed idle relay topics — measured ~7/hour, linear, no
/// plateau over 6 h on the bootstraps (tag shards alone allow 65,536).
pub(crate) const RELAY_TOPIC_IDLE_SECS: u64 = 3600;

pub(crate) const RELAY_TOPIC_EVICT_POLL_SECS: u64 = 600;

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

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

#[derive(Debug)]
struct TokenBucket {
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

    fn try_acquire(&mut self, rate_per_sec: u64, now: Instant) -> bool {
        let capacity = u128::from(rate_per_sec) * TOKEN_UNITS_PER_MSG;
        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos();
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

fn refill_units(elapsed_ns: u128, rate_per_sec: u64) -> u128 {
    elapsed_ns.saturating_mul(u128::from(rate_per_sec))
}

pub(crate) struct RelayFanout {
    base: RwLock<HashMap<TopicId, TopicValidator>>,
    /// sg keeps validators in a separate map from topic state, so they
    /// survive sg `unsubscribe`.
    registered: RwLock<HashMap<TopicId, AtomicU64>>,
    buckets: RwLock<HashMap<TopicId, TokenBucket>>,
    budget: RwLock<u64>,
    subscribed_topic_ids: Arc<RwLock<HashSet<TopicId>>>,
    /// `ForwardAndDeliver` verdicts returned by composites. sg meters only
    /// non-default verdicts (`validator.lazy_forward` / `dropped` /
    /// `deliver_only`), so the eager side of the split lives here.
    forward_msgs: AtomicU64,
    unsigned_inner_v1_dropped: AtomicU64,
}

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

    pub(crate) fn set_budget(&self, msgs_per_sec: u64) {
        *write_unpoisoned(&self.budget) = msgs_per_sec.min(MAX_BUDGET_MSGS_PER_SEC);
    }

    pub(crate) fn effective_budget(&self) -> u64 {
        *read_unpoisoned(&self.budget)
    }

    pub(crate) fn register_base(&self, topic: TopicId, validator: TopicValidator) {
        write_unpoisoned(&self.base).insert(topic, validator);
    }

    /// The registry install runs under the `registered` write lock, so map
    /// membership and the validator's presence on the registry cannot disagree.
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

    fn note_topic_use(&self, topic: &TopicId) -> bool {
        read_unpoisoned(&self.registered)
            .get(topic)
            .is_some_and(|last_use| {
                last_use.store(unix_now_secs(), Ordering::Relaxed);
                true
            })
    }

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
        // Still under the `registered` write lock: the registry clear must not
        // interleave with a concurrent install.
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

    pub(crate) fn evict_idle_topics<R: ValidatorRegistry + ?Sized>(&self, registry: &R) {
        self.evict_idle(unix_now_secs(), RELAY_TOPIC_IDLE_SECS, registry);
    }

    #[cfg(test)]
    fn registered_write_locked_for_test(&self) -> bool {
        self.registered.try_write().is_err()
    }

    pub(crate) fn registered_topics(&self) -> usize {
        read_unpoisoned(&self.registered).len()
    }

    pub(crate) fn forward_msgs(&self) -> u64 {
        self.forward_msgs.load(Ordering::Relaxed)
    }

    pub(crate) fn unsigned_inner_v1_dropped(&self) -> u64 {
        self.unsigned_inner_v1_dropped.load(Ordering::Relaxed)
    }

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
        let base = read_unpoisoned(&self.base).get(topic).cloned();
        if let Some(validator) = base {
            let action = validator(topic, payload);
            if action != ValidationAction::ForwardAndDeliver {
                return action;
            }
        }
        if !read_unpoisoned(&self.subscribed_topic_ids).contains(topic) {
            return ValidationAction::LazyForward;
        }
        if self.spend_budget_token(topic) {
            self.forward_msgs.fetch_add(1, Ordering::Relaxed);
            ValidationAction::ForwardAndDeliver
        } else {
            ValidationAction::LazyForward
        }
    }

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

    struct NoopRegistry;
    impl ValidatorRegistry for NoopRegistry {
        fn install_topic_validator(&self, _topic: TopicId, _validator: TopicValidator) {}
        fn clear_topic_validator(&self, _topic: TopicId) {}
    }

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
        write_unpoisoned(&subscribed).insert(topic);
        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::ForwardAndDeliver
        );
        write_unpoisoned(&subscribed).remove(&topic);
        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::LazyForward
        );
    }

    #[test]
    fn c3_budget_exhausts_then_refills() {
        let subscribed = subscriber_set();
        let fanout = RelayFanout::new(Arc::clone(&subscribed));
        fanout.set_budget(2);
        let topic = TopicId::new([9; 32]);
        write_unpoisoned(&subscribed).insert(topic);
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
        let mut t = t0 + std::time::Duration::from_secs(10);
        for _ in 0..100 {
            assert!(bucket.try_acquire(2, t), "at-rate acquire must hold");
            t += std::time::Duration::from_millis(500);
        }
    }

    #[test]
    fn c3_zero_budget_disables_the_gate() {
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
        let fanout = RelayFanout::new(subscriber_set());
        assert_eq!(fanout.effective_budget(), 50, "construction default");
        fanout.set_budget(1_000_000);
        assert_eq!(fanout.effective_budget(), MAX_BUDGET_MSGS_PER_SEC);
        fanout.set_budget(0);
        assert_eq!(fanout.effective_budget(), 0);
    }

    #[test]
    fn base_suppression_wins_over_fanout_policy() {
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

        fanout.register_base(topic, Arc::new(|_t, _p| ValidationAction::DeliverOnly));
        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::DeliverOnly
        );

        fanout.register_base(
            topic,
            Arc::new(|_t, _p| ValidationAction::ForwardAndDeliver),
        );

        assert_eq!(
            fanout.verdict(&topic, b"payload"),
            ValidationAction::LazyForward
        );
    }
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

        write_unpoisoned(&fanout.registered)
            .insert(topic, AtomicU64::new(now - 2 * RELAY_TOPIC_IDLE_SECS));
        let evicted = fanout.evict_idle(now, RELAY_TOPIC_IDLE_SECS, &registry);
        assert_eq!(evicted, vec![topic]);
        assert_eq!(fanout.registered_topics(), 0);

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
