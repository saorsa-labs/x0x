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
