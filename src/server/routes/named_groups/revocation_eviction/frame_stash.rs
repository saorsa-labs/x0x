//! ADR 0110 §2 (#1508 rc18): the bounded stash of received S4 frames (a
//! certificate rebind, a crypto-only exclusion or an owner recovery) that
//! this node cannot install yet.
//!
//! - **Head evidence.** A frame of a later revision is "known
//!   higher-head evidence" (§2) only when it passed every check this
//!   node can make on its own latest head: both signatures, the signer's
//!   standing (an Active, unrevoked member with the authority the frame
//!   needs) and the certificate or mandate it carries. Only such a frame
//!   holds the head unsynced ([`FrameStash::ahead`]). A frame from a
//!   sender without that standing is kept for a retry, but it holds
//!   nothing, so a forged future frame cannot stop eviction or recovery.
//! - **No expiry for evidence.** A head-evidence frame stays until a
//!   retry resolves it (it installs, this node already holds it, or the
//!   head moved past it and the frame is refused). Time does not end it,
//!   and a retry pass does not hide it: the frames stay in the stash
//!   while the pass runs ([`FrameStash::retry_set`],
//!   [`FrameStash::settle`]). A frame that is not head evidence expires
//!   after [`UNVERIFIED_TTL`].
//! - **Bounds.** One sender keeps at most [`PER_SENDER_PER_GROUP`] frames
//!   per group, and the stash keeps at most `CAP` frames. A frame that is
//!   not head evidence never removes a head-evidence frame; at the cap, a
//!   head-evidence frame removes the oldest frame of the sender that
//!   holds the most.

use std::time::Duration;

use crate::identity::AgentId;
use tokio::time::Instant;

/// A stashed frame that is not head evidence is dropped after this long.
pub(super) const UNVERIFIED_TTL: Duration = Duration::from_secs(600);
/// Frames one sender keeps per group.
pub(super) const PER_SENDER_PER_GROUP: usize = 4;

/// One received frame that waits.
#[derive(Debug, Clone)]
pub(super) struct StashedFrame {
    pub(super) sender: AgentId,
    pub(super) bytes: Vec<u8>,
    pub(super) at: Instant,
    pub(super) stable_group_id: String,
    pub(super) next_revision: u64,
    /// The frame passed every check this node can make on its latest
    /// head, so it is known higher-head evidence (§2).
    pub(super) evidence: bool,
}

impl StashedFrame {
    pub(super) fn new(
        sender: AgentId,
        bytes: Vec<u8>,
        stable_group_id: &str,
        next_revision: u64,
        evidence: bool,
    ) -> Self {
        Self {
            sender,
            bytes,
            at: Instant::now(),
            stable_group_id: stable_group_id.to_string(),
            next_revision,
            evidence,
        }
    }

    fn same(&self, other: &Self) -> bool {
        self.sender == other.sender && self.bytes == other.bytes
    }
}

/// The stash of one S4 frame kind, bounded by `CAP` frames.
#[derive(Debug, Default)]
pub(super) struct FrameStash<const CAP: usize> {
    frames: Vec<StashedFrame>,
}

impl<const CAP: usize> FrameStash<CAP> {
    /// Whether a head-evidence frame of `stable_group_id` commits a
    /// revision above `revision`.
    pub(super) fn ahead(&self, stable_group_id: &str, revision: u64) -> bool {
        self.frames.iter().any(|frame| {
            frame.evidence
                && frame.stable_group_id == stable_group_id
                && frame.next_revision > revision
        })
    }

    /// Keep `frame` under the bounds. Returns whether it is kept.
    pub(super) fn push(&mut self, frame: StashedFrame) -> bool {
        if let Some(kept) = self.frames.iter_mut().find(|kept| kept.same(&frame)) {
            kept.evidence |= frame.evidence;
            kept.at = frame.at;
            return true;
        }
        let own = |kept: &StashedFrame| {
            kept.sender == frame.sender && kept.stable_group_id == frame.stable_group_id
        };
        if self.frames.iter().filter(|kept| own(kept)).count() >= PER_SENDER_PER_GROUP {
            let unverified = self
                .frames
                .iter()
                .position(|kept| own(kept) && !kept.evidence);
            let at = match unverified {
                Some(at) => at,
                None if frame.evidence => match self.frames.iter().position(own) {
                    Some(at) => at,
                    None => return false,
                },
                None => return false,
            };
            self.frames.remove(at);
        }
        if self.frames.len() >= CAP {
            let at = match self.frames.iter().position(|kept| !kept.evidence) {
                Some(at) => at,
                None if frame.evidence => match self.largest_sender_oldest() {
                    Some(at) => at,
                    None => return false,
                },
                None => return false,
            };
            self.frames.remove(at);
        }
        self.frames.push(frame);
        true
    }

    /// The position of the oldest frame of the sender that holds the most
    /// frames.
    fn largest_sender_oldest(&self) -> Option<usize> {
        let count = |sender: &AgentId| {
            self.frames
                .iter()
                .filter(|kept| kept.sender == *sender)
                .count()
        };
        let sender = self
            .frames
            .iter()
            .map(|kept| (count(&kept.sender), kept.sender))
            .max_by_key(|(held, _)| *held)?
            .1;
        self.frames.iter().position(|kept| kept.sender == sender)
    }

    /// Drop the frames that are not head evidence and are older than
    /// [`UNVERIFIED_TTL`], and return a copy of the rest for a retry. The
    /// frames stay in the stash, so they still hold the head while the
    /// retry runs.
    pub(super) fn retry_set(&mut self, now: Instant) -> Vec<StashedFrame> {
        self.frames.retain(|frame| {
            frame.evidence || now.saturating_duration_since(frame.at) <= UNVERIFIED_TTL
        });
        self.frames.clone()
    }

    /// Apply a retry's results: `None` resolved the frame, which goes;
    /// `Some(evidence)` keeps it with its new head-evidence state. Frames
    /// that arrived during the retry are kept as they are.
    pub(super) fn settle(&mut self, results: Vec<(StashedFrame, Option<bool>)>) {
        for (frame, kept) in results {
            let Some(at) = self.frames.iter().position(|held| held.same(&frame)) else {
                continue;
            };
            match kept {
                Some(evidence) => self.frames[at].evidence = evidence,
                None => {
                    self.frames.remove(at);
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.frames.len()
    }

    /// Test builds only: make every frame `by` older.
    #[cfg(test)]
    pub(super) fn age(&mut self, by: Duration) {
        for frame in &mut self.frames {
            frame.at = frame.at.checked_sub(by).unwrap_or(frame.at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(sender: u8, group: &str, revision: u64, evidence: bool, tag: u8) -> StashedFrame {
        StashedFrame::new(
            AgentId([sender; 32]),
            vec![tag, sender, revision as u8],
            group,
            revision,
            evidence,
        )
    }

    /// #1508 rc18 (Codex P1): a frame that is not head evidence holds
    /// nothing, and a flood of them never removes a head-evidence frame.
    #[test]
    fn unverified_frames_hold_nothing_and_never_evict_evidence() {
        let mut stash = FrameStash::<8>::default();
        assert!(stash.push(frame(1, "g", 5, true, 0)));
        for sender in 10..40 {
            let _ = stash.push(frame(sender, "g", 9, false, 0));
        }
        assert!(stash.ahead("g", 4), "the evidence frame stays");
        assert!(!stash.ahead("g", 5));
        assert!(stash.len() <= 8);
        let mut forged = FrameStash::<8>::default();
        assert!(forged.push(frame(2, "g", 9, false, 0)));
        assert!(!forged.ahead("g", 1), "a forged future frame holds nothing");
    }

    /// #1508 rc18 (Codex P1): one sender keeps at most
    /// `PER_SENDER_PER_GROUP` frames per group.
    #[test]
    fn one_sender_is_bounded_per_group() {
        let mut stash = FrameStash::<64>::default();
        for tag in 0..20 {
            let _ = stash.push(frame(1, "g", 9, true, tag));
        }
        assert_eq!(stash.len(), PER_SENDER_PER_GROUP);
        assert!(stash.push(frame(2, "g", 9, true, 0)));
        assert_eq!(stash.len(), PER_SENDER_PER_GROUP + 1);
    }

    /// #1508 rc18 (Codex P1): head evidence has no time limit, and a retry
    /// pass does not hide it. Before the fix the frame stopped holding the
    /// head after ten minutes, and the retry took it out of the stash.
    #[tokio::test]
    async fn evidence_outlives_the_ttl_and_the_retry() {
        let mut stash = FrameStash::<8>::default();
        assert!(stash.push(frame(1, "g", 5, true, 0)));
        assert!(stash.push(frame(2, "g", 5, false, 0)));
        stash.age(UNVERIFIED_TTL + Duration::from_secs(1));
        let retry = stash.retry_set(Instant::now());
        assert_eq!(retry.len(), 1, "only the unverified frame expires");
        assert!(stash.ahead("g", 4), "the retry set stays in the stash");
        let results = retry.into_iter().map(|frame| (frame, Some(true))).collect();
        stash.settle(results);
        assert!(stash.ahead("g", 4));
        let retry = stash.retry_set(Instant::now());
        stash.settle(retry.into_iter().map(|frame| (frame, None)).collect());
        assert!(!stash.ahead("g", 4), "a resolved frame goes");
    }
}
