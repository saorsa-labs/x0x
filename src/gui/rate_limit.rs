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
    /// A rider show names a subject and an envelope signer. Both buckets
    /// must have a token. Rotating the subject does not refill the signer.
    /// A refusal spends nothing.
    pub fn try_acquire_all(&mut self, agents: &[AgentId], now: Instant) -> bool {
        self.hourly.retain(|t| now.duration_since(*t) < HOUR);
        if self.hourly.len() >= HOURLY_CAP {
            return false;
        }
        let mut keys: Vec<[u8; 32]> = agents.iter().map(|agent| *agent.as_bytes()).collect();
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() {
            return false;
        }
        for key in &keys {
            let bucket = self.agents.entry(*key).or_insert(AgentBucket {
                tokens: BURST,
                last_refill: now,
            });
            refill_bucket(bucket, now);
        }
        let denied = keys.iter().any(|key| {
            self.agents
                .get(key)
                .map(|bucket| bucket.tokens < 1.0)
                .unwrap_or(true)
        });
        if denied {
            return false;
        }
        for key in &keys {
            let Some(bucket) = self.agents.get_mut(key) else {
                return false;
            };
            bucket.tokens -= 1.0;
        }
        self.hourly.push(now);
        true
    }
}

fn refill_bucket(bucket: &mut AgentBucket, now: Instant) {
    let elapsed = now.saturating_duration_since(bucket.last_refill);
    let refill = elapsed.as_secs_f64() / (REFILL_SECS as f64);
    bucket.tokens = (bucket.tokens + refill).min(BURST);
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
}
