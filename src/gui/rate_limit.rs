//! Per-agent + per-machine hourly rate limit for GUI show (ADR 0083 §5).
//!
//! - Per requesting `AgentId`: token bucket, burst 3, refill 1 per 20 s.
//! - Per target machine: at most 30 accepted shows per hour across all senders.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::identity::AgentId;

/// Burst capacity per requesting agent.
pub const BURST: f64 = 3.0;
/// Seconds between refill tokens after the burst is spent.
pub const REFILL_SECS: u64 = 20;
/// Cap on accepted shows per target machine in any rolling hour.
pub const HOURLY_CAP: usize = 30;
/// Retained agent buckets. A full refill is dropped first. Past this cap
/// the oldest other bucket is dropped.
const AGENT_CAP: usize = 64;
const HOUR: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct AgentBucket {
    tokens: f64,
    last_refill: Instant,
}

/// In-memory show rate limiter for one display machine.
#[derive(Debug, Default)]
pub struct GuiShowRateLimit {
    agents: HashMap<[u8; 32], AgentBucket>,
    hourly: Vec<Instant>,
}

impl GuiShowRateLimit {
    /// Returns `true` when the request may proceed; records the acceptance.
    pub fn try_acquire(&mut self, agent: &AgentId, now: Instant) -> bool {
        self.try_acquire_all(std::slice::from_ref(agent), now)
    }

    /// One show charged to every distinct agent, and once against the hourly cap.
    ///
    /// The first agent is the envelope signer. Later agents are subjects.
    /// The signer bucket is checked before any subject bucket is created.
    /// A refusal spends nothing and inserts nothing. A bucket that has
    /// refilled to a full burst is dropped. Past the retained-entry cap,
    /// the oldest bucket that this request did not just charge is dropped.
    pub fn try_acquire_all(&mut self, agents: &[AgentId], now: Instant) -> bool {
        self.hourly.retain(|t| now.duration_since(*t) < HOUR);
        self.evict_expired(now);
        if self.hourly.len() >= HOURLY_CAP {
            return false;
        }
        let keys = distinct_keys(agents);
        let Some(&signer) = keys.first() else {
            return false;
        };
        if self.available(signer, now) < 1.0 {
            return false;
        }
        if keys[1..].iter().any(|key| self.available(*key, now) < 1.0) {
            return false;
        }
        for key in &keys {
            let bucket = self.agents.entry(*key).or_insert(AgentBucket {
                tokens: BURST,
                last_refill: now,
            });
            refill_bucket(bucket, now);
            bucket.tokens -= 1.0;
        }
        self.hourly.push(now);
        self.evict_over_cap(&keys);
        true
    }

    fn available(&self, key: [u8; 32], now: Instant) -> f64 {
        self.agents
            .get(&key)
            .map(|bucket| tokens_at(bucket, now))
            .unwrap_or(BURST)
    }

    /// Drop a bucket that has refilled to a full burst. Creating it again
    /// is the same state.
    fn evict_expired(&mut self, now: Instant) {
        self.agents
            .retain(|_, bucket| tokens_at(bucket, now) < BURST);
    }

    fn evict_over_cap(&mut self, protect: &[[u8; 32]]) {
        while self.agents.len() > AGENT_CAP {
            let oldest = self
                .agents
                .iter()
                .filter(|(key, _)| !protect.contains(*key))
                .min_by_key(|(_, bucket)| bucket.last_refill)
                .map(|(key, _)| *key);
            let Some(oldest) = oldest else {
                break;
            };
            self.agents.remove(&oldest);
        }
    }
}

fn distinct_keys(agents: &[AgentId]) -> Vec<[u8; 32]> {
    let mut keys = Vec::with_capacity(agents.len());
    for agent in agents {
        let key = *agent.as_bytes();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

fn tokens_at(bucket: &AgentBucket, now: Instant) -> f64 {
    let elapsed = now.saturating_duration_since(bucket.last_refill);
    let refill = elapsed.as_secs_f64() / (REFILL_SECS as f64);
    (bucket.tokens + refill).min(BURST)
}

fn refill_bucket(bucket: &mut AgentBucket, now: Instant) {
    bucket.tokens = tokens_at(bucket, now);
    bucket.last_refill = now;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let id = AgentId([7u8; 32]);
        let mut lim = GuiShowRateLimit::default();
        let t0 = Instant::now();
        assert!(lim.try_acquire(&id, t0));
        assert!(lim.try_acquire(&id, t0));
        assert!(lim.try_acquire(&id, t0));
        assert!(!lim.try_acquire(&id, t0), "fourth inside burst is limited");
        assert!(lim.try_acquire(&id, t0 + Duration::from_secs(REFILL_SECS)));
    }

    /// After the signer burst is spent, a fresh subject must not be stored.
    #[test]
    fn refused_subjects_do_not_grow_the_map_after_the_signer_is_exhausted() {
        let signer = AgentId([1u8; 32]);
        let mut lim = GuiShowRateLimit::default();
        let t0 = Instant::now();
        for n in 0..3u8 {
            let mut subject = [2u8; 32];
            subject[0] = n;
            assert!(
                lim.try_acquire_all(&[signer, AgentId(subject)], t0),
                "show {n} is inside the signer burst"
            );
        }
        let retained = lim.agents.len();
        assert_eq!(retained, 4, "the signer and three subjects are retained");
        for n in 0..64u8 {
            let mut subject = [9u8; 32];
            subject[0] = n;
            assert!(
                !lim.try_acquire_all(&[signer, AgentId(subject)], t0),
                "subject {n} must be refused once the signer burst is spent"
            );
        }
        assert_eq!(
            lim.agents.len(),
            retained,
            "a refused subject must not be inserted"
        );
    }

    /// A bucket that has refilled to a full burst is not retained.
    #[test]
    fn a_refilled_bucket_is_dropped() {
        let mut lim = GuiShowRateLimit::default();
        let t0 = Instant::now();
        let signer = AgentId([1u8; 32]);
        assert!(lim.try_acquire(&signer, t0));
        let later = t0 + Duration::from_secs(REFILL_SECS);
        assert!(lim.try_acquire(&AgentId([2u8; 32]), later));
        assert!(
            !lim.agents.contains_key(signer.as_bytes()),
            "a bucket back at burst is not retained"
        );
        assert_eq!(lim.agents.len(), 1, "only the agent just charged stays");
    }

    /// Past the cap, the oldest bucket that this request did not charge is dropped.
    #[test]
    fn oldest_bucket_is_evicted_past_the_cap() {
        let mut lim = GuiShowRateLimit::default();
        let t0 = Instant::now();
        for n in 0..AGENT_CAP {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&u64::try_from(n).expect("n fits").to_le_bytes());
            lim.agents.insert(
                id,
                AgentBucket {
                    tokens: 0.0,
                    last_refill: t0 + Duration::from_millis(u64::try_from(n).expect("n fits")),
                },
            );
        }
        let fresh = AgentId([0xABu8; 32]);
        assert!(lim.try_acquire(&fresh, t0));
        assert!(
            lim.agents.len() <= AGENT_CAP,
            "retained buckets stay within the cap, got {}",
            lim.agents.len()
        );
        assert!(
            lim.agents.contains_key(fresh.as_bytes()),
            "the agent just charged is kept"
        );
        assert!(
            !lim.agents.contains_key(&[0u8; 32]),
            "the oldest other bucket is dropped"
        );
    }
}
