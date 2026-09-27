//! Bounded, per-sender-fair hold for sealed records whose epoch is ahead of
//! the local group epoch.
//!
//! See `docs/design/gss-future-epoch-hold.md`. The container is pure
//! bookkeeping over opaque ciphertext payloads: it never decrypts, never
//! touches store contents, and takes the clock as an argument so bounds and
//! TTL are testable without sleeping. The receive path decides WHAT may be
//! offered (pre-decrypt checks) and re-runs full verification on release.

use crate::identity::AgentId;
use tokio::time::{Duration, Instant};

/// How long a held record waits for its epoch key before it is discarded.
pub(crate) const HOLD_TTL: Duration = Duration::from_secs(300);
/// Maximum held records from one pub/sub-verified sender.
pub(crate) const MAX_HELD_PER_SENDER: usize = 32;
/// Maximum held payload bytes from one pub/sub-verified sender. Also the
/// largest single record that can be held.
pub(crate) const MAX_HELD_BYTES_PER_SENDER: usize = 1024 * 1024;
/// Maximum held records per store.
pub(crate) const MAX_HELD_PER_STORE: usize = 128;
/// Maximum held payload bytes per store.
pub(crate) const MAX_HELD_BYTES_PER_STORE: usize = 4 * 1024 * 1024;
/// Records more than this many epochs ahead of the local epoch are refused.
pub(crate) const MAX_EPOCH_LOOKAHEAD: u64 = 4;
/// Maintenance cadence while the hold has work (entries or a pending
/// catch-up request).
pub(crate) const HOLD_TICK: Duration = Duration::from_secs(1);
/// Minimum spacing between catch-up state requests for one store.
pub(crate) const CATCHUP_MIN_SPACING: Duration = Duration::from_secs(15);

/// One held ciphertext payload, exactly as received on the main topic.
#[derive(Debug, Clone)]
pub(crate) struct HeldRecord {
    pub(crate) sender: AgentId,
    pub(crate) epoch: u64,
    pub(crate) payload: Vec<u8>,
    seq: u64,
    arrived: Instant,
    digest: [u8; 32],
}

/// Result of offering a payload to the hold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HoldInsert {
    /// The payload is now held.
    pub(crate) held: bool,
    /// An identical payload was already held (gossip redelivery).
    pub(crate) duplicate: bool,
    /// The payload exceeds the per-sender byte bound and was not held.
    pub(crate) oversize: bool,
    /// Entries dropped by TTL during this insert.
    pub(crate) expired: usize,
    /// Entries evicted by the count/byte bounds during this insert.
    pub(crate) evicted: usize,
}

/// Records sealed under an epoch this node does not hold yet.
#[derive(Debug, Default)]
pub(crate) struct FutureEpochHold {
    entries: Vec<HeldRecord>,
    bytes: usize,
    next_seq: u64,
    /// Lowest and highest future epoch observed since the last catch-up
    /// request (held or not). A catch-up is due once the local epoch
    /// reaches the lowest.
    catchup: Option<(u64, u64)>,
    last_catchup: Option<Instant>,
}

impl FutureEpochHold {
    /// Number of held records.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Held payload bytes.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether there is no maintenance work: nothing held and no catch-up
    /// request pending.
    pub(crate) fn is_idle(&self) -> bool {
        self.entries.is_empty() && self.catchup.is_none()
    }

    /// Record that a future epoch was observed from a roster writer, whether
    /// or not its record could be held.
    pub(crate) fn note_future_epoch(&mut self, epoch: u64) {
        self.catchup = Some(match self.catchup {
            Some((low, high)) => (low.min(epoch), high.max(epoch)),
            None => (epoch, epoch),
        });
    }

    /// Drop entries older than [`HOLD_TTL`]; returns how many.
    pub(crate) fn expire(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        let mut freed = 0usize;
        self.entries.retain(|entry| {
            let keep = now.saturating_duration_since(entry.arrived) < HOLD_TTL;
            if !keep {
                freed = freed.saturating_add(entry.payload.len());
            }
            keep
        });
        self.bytes = self.bytes.saturating_sub(freed);
        before - self.entries.len()
    }

    /// Offer a payload that already passed the caller's pre-decrypt checks.
    pub(crate) fn insert(
        &mut self,
        sender: AgentId,
        epoch: u64,
        payload: &[u8],
        now: Instant,
    ) -> HoldInsert {
        let mut outcome = HoldInsert {
            expired: self.expire(now),
            ..HoldInsert::default()
        };
        if payload.len() > MAX_HELD_BYTES_PER_SENDER {
            outcome.oversize = true;
            return outcome;
        }
        let digest = *blake3::hash(payload).as_bytes();
        if self.entries.iter().any(|entry| entry.digest == digest) {
            outcome.duplicate = true;
            return outcome;
        }
        // A sender only ever displaces its own records first.
        loop {
            let (count, bytes) = self.sender_usage(&sender);
            if count < MAX_HELD_PER_SENDER
                && bytes.saturating_add(payload.len()) <= MAX_HELD_BYTES_PER_SENDER
            {
                break;
            }
            if !self.evict_oldest_of(&sender) {
                break;
            }
            outcome.evicted += 1;
        }
        // Store-wide overflow evicts from the heaviest sender.
        while self.entries.len() >= MAX_HELD_PER_STORE
            || self.bytes.saturating_add(payload.len()) > MAX_HELD_BYTES_PER_STORE
        {
            let Some(heaviest) = self.heaviest_sender() else {
                break;
            };
            if !self.evict_oldest_of(&heaviest) {
                break;
            }
            outcome.evicted += 1;
        }
        self.bytes = self.bytes.saturating_add(payload.len());
        self.entries.push(HeldRecord {
            sender,
            epoch,
            payload: payload.to_vec(),
            seq: self.next_seq,
            arrived: now,
            digest,
        });
        self.next_seq = self.next_seq.wrapping_add(1);
        outcome.held = true;
        outcome
    }

    /// Remove and return every entry whose epoch is `<= current_epoch`,
    /// ordered by `(epoch, arrival)`.
    pub(crate) fn take_releasable(&mut self, current_epoch: u64) -> Vec<HeldRecord> {
        let (mut ready, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|entry| entry.epoch <= current_epoch);
        self.entries = keep;
        let freed: usize = ready.iter().map(|entry| entry.payload.len()).sum();
        self.bytes = self.bytes.saturating_sub(freed);
        ready.sort_by_key(|entry| (entry.epoch, entry.seq));
        ready
    }

    /// Whether a catch-up state request should be sent now. True at most
    /// once per [`CATCHUP_MIN_SPACING`]; a due request suppressed by the
    /// spacing stays pending for the next call.
    pub(crate) fn take_catchup_due(&mut self, current_epoch: u64, now: Instant) -> bool {
        let Some((low, high)) = self.catchup else {
            return false;
        };
        if current_epoch < low {
            return false;
        }
        if self
            .last_catchup
            .is_some_and(|last| now.saturating_duration_since(last) < CATCHUP_MIN_SPACING)
        {
            return false;
        }
        self.last_catchup = Some(now);
        self.catchup = (current_epoch < high).then_some((high, high));
        true
    }

    fn sender_usage(&self, sender: &AgentId) -> (usize, usize) {
        self.entries
            .iter()
            .filter(|entry| entry.sender == *sender)
            .fold((0, 0), |(count, bytes), entry| {
                (count + 1, bytes.saturating_add(entry.payload.len()))
            })
    }

    /// The sender holding the most bytes; ties go to more entries, then to
    /// the sender whose oldest entry is oldest.
    fn heaviest_sender(&self) -> Option<AgentId> {
        let mut best: Option<(AgentId, usize, usize, u64)> = None;
        for entry in &self.entries {
            if best.is_some_and(|(sender, ..)| sender == entry.sender) {
                continue;
            }
            let (count, bytes) = self.sender_usage(&entry.sender);
            let oldest = self
                .entries
                .iter()
                .filter(|e| e.sender == entry.sender)
                .map(|e| e.seq)
                .min()
                .unwrap_or(entry.seq);
            let better = match best {
                None => true,
                Some((_, best_bytes, best_count, best_oldest)) => {
                    (bytes, count, std::cmp::Reverse(oldest))
                        > (best_bytes, best_count, std::cmp::Reverse(best_oldest))
                }
            };
            if better {
                best = Some((entry.sender, bytes, count, oldest));
            }
        }
        best.map(|(sender, ..)| sender)
    }

    fn evict_oldest_of(&mut self, sender: &AgentId) -> bool {
        let Some(index) = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.sender == *sender)
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(index, _)| index)
        else {
            return false;
        };
        let removed = self.entries.remove(index);
        self.bytes = self.bytes.saturating_sub(removed.payload.len());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn payload(tag: u32, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len.max(4)];
        bytes[..4].copy_from_slice(&tag.to_le_bytes());
        bytes
    }

    #[test]
    fn future_epoch_hold_expires_after_ttl() {
        let start = Instant::now();
        let mut hold = FutureEpochHold::default();
        assert!(hold.insert(agent(1), 8, &payload(1, 64), start).held);
        assert_eq!(hold.expire(start + HOLD_TTL - Duration::from_millis(1)), 0);
        assert_eq!(hold.len(), 1, "a record inside its TTL stays held");
        assert_eq!(hold.expire(start + HOLD_TTL), 1);
        assert_eq!((hold.len(), hold.bytes()), (0, 0));
        assert!(
            hold.take_releasable(u64::MAX).is_empty(),
            "an expired record is never released, whatever the epoch"
        );
        // Insert also expires first, and reports it.
        assert!(hold.insert(agent(1), 8, &payload(2, 64), start).held);
        let later = hold.insert(agent(2), 8, &payload(3, 64), start + HOLD_TTL);
        assert_eq!((later.held, later.expired), (true, 1));
        assert_eq!(hold.len(), 1);
    }

    #[test]
    fn future_epoch_hold_flood_is_bounded_and_per_sender_fair() {
        let now = Instant::now();
        let mut hold = FutureEpochHold::default();
        let honest = agent(9);
        assert!(hold.insert(honest, 5, &payload(0, 128), now).held);

        // One flooder: capped at its own quota, and only its own records go.
        let flooder = agent(1);
        let mut evicted = 0;
        for tag in 1..=(MAX_HELD_PER_SENDER as u32 * 3) {
            evicted += hold.insert(flooder, 5, &payload(tag, 64), now).evicted;
        }
        assert_eq!(hold.sender_usage(&flooder).0, MAX_HELD_PER_SENDER);
        assert_eq!(evicted, MAX_HELD_PER_SENDER * 2);
        assert_eq!(
            hold.sender_usage(&honest).0,
            1,
            "flooder displaced itself only"
        );
        let kept: Vec<u32> = hold
            .entries
            .iter()
            .filter(|e| e.sender == flooder)
            .map(|e| u32::from_le_bytes([e.payload[0], e.payload[1], e.payload[2], e.payload[3]]))
            .collect();
        assert_eq!(
            kept.first().copied(),
            Some(MAX_HELD_PER_SENDER as u32 * 2 + 1),
            "oldest-first eviction keeps the newest records"
        );

        // Many flooders at full byte quota: store bounds hold, and the
        // honest single small record survives because heavier senders are
        // evicted first.
        let big = MAX_HELD_BYTES_PER_SENDER / 2;
        for sender in 20..40u8 {
            for tag in 0..3u32 {
                hold.insert(
                    agent(sender),
                    5,
                    &payload(1000 * sender as u32 + tag, big),
                    now,
                );
                assert!(hold.len() <= MAX_HELD_PER_STORE);
                assert!(hold.bytes() <= MAX_HELD_BYTES_PER_STORE);
                for s in 20..40u8 {
                    let (_, bytes) = hold.sender_usage(&agent(s));
                    assert!(bytes <= MAX_HELD_BYTES_PER_SENDER);
                }
            }
        }
        assert_eq!(
            hold.sender_usage(&honest).0,
            1,
            "honest record survived flood"
        );

        // Oversize never held; duplicates never double-count.
        let over = hold.insert(agent(2), 5, &vec![7u8; MAX_HELD_BYTES_PER_SENDER + 1], now);
        assert!(over.oversize && !over.held);
        let before = hold.len();
        let dup = hold.insert(honest, 5, &payload(0, 128), now);
        assert!(dup.duplicate && !dup.held);
        assert_eq!(hold.len(), before);
    }

    #[test]
    fn take_releasable_orders_by_epoch_then_arrival_and_keeps_later_epochs() {
        let now = Instant::now();
        let mut hold = FutureEpochHold::default();
        hold.insert(agent(1), 7, &payload(1, 8), now);
        hold.insert(agent(2), 6, &payload(2, 8), now);
        hold.insert(agent(1), 6, &payload(3, 8), now);
        hold.insert(agent(3), 9, &payload(4, 8), now);
        let ready = hold.take_releasable(7);
        let order: Vec<(u64, u8)> = ready.iter().map(|e| (e.epoch, e.payload[0])).collect();
        assert_eq!(order, vec![(6, 2), (6, 3), (7, 1)]);
        assert_eq!(hold.len(), 1);
        assert_eq!(hold.bytes(), 8);
    }

    #[test]
    fn catchup_state_request_fires_once_per_window() {
        let start = Instant::now();
        let mut hold = FutureEpochHold::default();
        assert!(!hold.take_catchup_due(10, start), "nothing observed");
        hold.note_future_epoch(6);
        assert!(!hold.take_catchup_due(5, start), "epoch not installed yet");
        assert!(hold.take_catchup_due(6, start), "first install fires");
        assert!(hold.is_idle());

        // A second advance inside the window is suppressed but stays due.
        hold.note_future_epoch(7);
        let inside = start + CATCHUP_MIN_SPACING - Duration::from_millis(1);
        assert!(!hold.take_catchup_due(7, inside));
        assert!(!hold.is_idle(), "suppressed request stays pending");
        assert!(hold.take_catchup_due(7, start + CATCHUP_MIN_SPACING));
        assert!(!hold.take_catchup_due(7, start + CATCHUP_MIN_SPACING * 3));

        // Observed E+1 and E+2; installing E+1 fires and keeps E+2 pending.
        let t = start + CATCHUP_MIN_SPACING * 4;
        hold.note_future_epoch(9);
        hold.note_future_epoch(8);
        assert!(hold.take_catchup_due(8, t));
        assert!(!hold.take_catchup_due(8, t + CATCHUP_MIN_SPACING));
        assert!(hold.take_catchup_due(9, t + CATCHUP_MIN_SPACING));
        assert!(hold.is_idle());
    }
}
