//! Keep non-connected peers out of gossip send-target sets (x0x#1036).
//!
//! Every x0x gossip send goes through ant-quic's `send`, which needs a live
//! connection: a send to a peer with none fails fast with `Peer not found`.
//! Two send-target sets were not bounded by the transport:
//!
//! - **HyParView active view.** saorsa-gossip adds peers to the active view
//!   from JOIN/FORWARDJOIN random walks — including peers several hops away
//!   that this node never connects to — and nothing prunes the view by
//!   transport connectivity. The view's peers are SWIM-probed (1 s period),
//!   shuffled and forwarded to for as long as they stay in it.
//! - **Presence broadcast set.** x0x seeded presence beacon and FOAF targets
//!   from `active_view() ∪ connected_peers()`, so every stale active-view
//!   entry also received a beacon every interval.
//!
//! On a relay node those stale entries produced thousands of fast-fail sends
//! per hour, each one a `WARN` line in ant-quic (x0x#1036).
//!
//! The fix keeps a short grace (a peer that disconnected between two
//! connected-peer snapshots is fine) but never lets a peer that has been
//! disconnected for [`STALE_SEND_TARGET_AFTER`] stay a target:
//! [`StaleTargetTracker`] prunes it from the HyParView active view and
//! restores it once it is connected again. Presence targets are filtered to
//! connected peers by [`presence_broadcast_targets`]. PlumTree topic planes
//! are already refreshed from the connected plane every second, so lazy/IHAVE
//! and anti-entropy repair reach a reconnecting peer as soon as it is
//! connected again; nothing here touches them.

use saorsa_gossip_membership::Membership;
use saorsa_gossip_types::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// A peer disconnected for at least this long stops being a send target.
pub(crate) const STALE_SEND_TARGET_AFTER: Duration = Duration::from_secs(60);

/// Upper bound on peers tracked as absent or pruned.
const MAX_TRACKED_PEERS: usize = 4096;

/// What one maintenance pass changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct StaleTargetPlan {
    /// Targets disconnected for at least the threshold; remove them.
    pub prune: Vec<PeerId>,
    /// Previously pruned peers that are connected again; restore them.
    pub restore: Vec<PeerId>,
}

/// Tracks how long each send target has been without a connection.
#[derive(Debug)]
pub(crate) struct StaleTargetTracker {
    threshold: Duration,
    /// First time a target was seen without a connection. Kept after the
    /// target is pruned, so a peer re-added by a random walk while still
    /// disconnected is pruned again on the next pass instead of getting a
    /// fresh grace period.
    absent_since: HashMap<PeerId, Instant>,
    /// Peers this tracker pruned, restored when they reconnect.
    pruned: HashSet<PeerId>,
}

impl Default for StaleTargetTracker {
    fn default() -> Self {
        Self::new(STALE_SEND_TARGET_AFTER)
    }
}

impl StaleTargetTracker {
    pub(crate) fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            absent_since: HashMap::new(),
            pruned: HashSet::new(),
        }
    }

    /// Compare the current `targets` with the `connected` snapshot at `now`.
    pub(crate) fn observe(
        &mut self,
        targets: &[PeerId],
        connected: &HashSet<PeerId>,
        now: Instant,
    ) -> StaleTargetPlan {
        let mut plan = StaleTargetPlan::default();

        // Connected peers are never stale; pruned ones come back.
        self.absent_since
            .retain(|peer, _| !connected.contains(peer));
        self.pruned.retain(|peer| {
            if connected.contains(peer) {
                plan.restore.push(*peer);
                false
            } else {
                true
            }
        });

        for peer in targets {
            if connected.contains(peer) {
                continue;
            }
            let since = *self.absent_since.entry(*peer).or_insert(now);
            if now.saturating_duration_since(since) >= self.threshold {
                // RED PROOF: pre-fix behaviour, stale targets are kept.
                tracing::trace!(peer = %peer, "stale target kept (fix reverted)");
            }
        }

        self.bound(targets);
        plan.prune.sort_unstable_by_key(|peer| *peer.as_bytes());
        plan.restore.sort_unstable_by_key(|peer| *peer.as_bytes());
        plan
    }

    fn bound(&mut self, targets: &[PeerId]) {
        if self.absent_since.len() > MAX_TRACKED_PEERS {
            let keep: HashSet<PeerId> = targets.iter().copied().collect();
            let pruned = &self.pruned;
            self.absent_since
                .retain(|peer, _| keep.contains(peer) || pruned.contains(peer));
            if self.absent_since.len() > MAX_TRACKED_PEERS {
                self.absent_since.clear();
            }
        }
        if self.pruned.len() > MAX_TRACKED_PEERS {
            // Losing a pruned mark only skips an explicit restore; PlumTree
            // and presence still target the peer once it is connected.
            self.pruned.clear();
        }
    }
}

/// Run one pass over the HyParView active view: remove targets disconnected
/// for at least the tracker's threshold and restore reconnected ones.
pub(crate) async fn maintain_active_view<M>(
    membership: &M,
    tracker: &mut StaleTargetTracker,
    connected: &HashSet<PeerId>,
    now: Instant,
) -> StaleTargetPlan
where
    M: Membership + ?Sized,
{
    let active = membership.active_view();
    let plan = tracker.observe(&active, connected, now);
    for peer in &plan.prune {
        if let Err(e) = membership.remove_active(*peer).await {
            tracing::debug!(peer = %peer, "x0x#1036: stale active-view prune failed: {e}");
        }
    }
    for peer in &plan.restore {
        if active.contains(peer) {
            continue;
        }
        if let Err(e) = membership.add_active(*peer).await {
            tracing::debug!(peer = %peer, "x0x#1036: active-view restore failed: {e}");
        }
    }
    if !plan.prune.is_empty() || !plan.restore.is_empty() {
        tracing::debug!(
            pruned = plan.prune.len(),
            restored = plan.restore.len(),
            "x0x#1036: HyParView active view reconciled with transport connectivity"
        );
    }
    plan
}

/// Presence beacon/FOAF targets: the HyParView active view and the transport
/// table, restricted to connected peers. A beacon to a peer with no
/// connection can only fail, so active-view entries without one are dropped.
pub(crate) fn presence_broadcast_targets(
    active_view: Vec<PeerId>,
    connected: &[PeerId],
) -> Vec<PeerId> {
    // RED PROOF: pre-fix behaviour, active_view() ∪ connected unfiltered.
    let mut targets: Vec<PeerId> = active_view;
    targets.extend(connected.iter().copied());
    targets.sort_unstable_by_key(|peer| *peer.as_bytes());
    targets.dedup();
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn peer(byte: u8) -> PeerId {
        PeerId::new([byte; 32])
    }

    fn set(peers: &[PeerId]) -> HashSet<PeerId> {
        peers.iter().copied().collect()
    }

    /// Minimal `Membership` whose active view is a plain set.
    #[derive(Default)]
    struct FakeMembership {
        active: Mutex<HashSet<PeerId>>,
    }

    #[async_trait::async_trait]
    impl Membership for FakeMembership {
        async fn join(&self, _seeds: Vec<String>) -> anyhow::Result<()> {
            Ok(())
        }
        fn active_view(&self) -> Vec<PeerId> {
            let mut view: Vec<PeerId> = self.active.lock().expect("lock").iter().copied().collect();
            view.sort_unstable_by_key(|peer| *peer.as_bytes());
            view
        }
        fn passive_view(&self) -> Vec<PeerId> {
            Vec::new()
        }
        async fn add_active(&self, peer: PeerId) -> anyhow::Result<()> {
            self.active.lock().expect("lock").insert(peer);
            Ok(())
        }
        async fn remove_active(&self, peer: PeerId) -> anyhow::Result<()> {
            self.active.lock().expect("lock").remove(&peer);
            Ok(())
        }
        async fn promote(&self, peer: PeerId) -> anyhow::Result<()> {
            self.add_active(peer).await
        }
    }

    #[test]
    fn peer_disconnected_past_threshold_is_pruned_but_not_before() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let targets = [peer(1), peer(2)];
        let connected = set(&[peer(1)]);

        // Disconnected between snapshots: still inside the grace period.
        assert!(tracker.observe(&targets, &connected, t0).prune.is_empty());
        assert!(tracker
            .observe(&targets, &connected, t0 + Duration::from_secs(59))
            .prune
            .is_empty());
        // Missing for the whole threshold: stop targeting it.
        assert_eq!(
            tracker
                .observe(&targets, &connected, t0 + Duration::from_secs(60))
                .prune,
            vec![peer(2)]
        );
    }

    #[test]
    fn reconnect_resets_the_clock_and_restores_a_pruned_peer() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let none = HashSet::new();
        tracker.observe(&[peer(3)], &none, t0);
        assert_eq!(
            tracker
                .observe(&[peer(3)], &none, t0 + Duration::from_secs(61))
                .prune,
            vec![peer(3)]
        );

        let plan = tracker.observe(&[], &set(&[peer(3)]), t0 + Duration::from_secs(70));
        assert_eq!(plan.restore, vec![peer(3)]);
        assert!(plan.prune.is_empty());

        // A later disconnect starts a fresh grace period.
        let t1 = t0 + Duration::from_secs(80);
        assert!(tracker.observe(&[peer(3)], &none, t1).prune.is_empty());
        assert!(tracker
            .observe(&[peer(3)], &none, t1 + Duration::from_secs(30))
            .prune
            .is_empty());
    }

    #[test]
    fn re_added_disconnected_peer_gets_no_fresh_grace() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let none = HashSet::new();
        tracker.observe(&[peer(4)], &none, t0);
        assert_eq!(
            tracker
                .observe(&[peer(4)], &none, t0 + Duration::from_secs(60))
                .prune,
            vec![peer(4)]
        );
        // Pruned, absent from the view for a pass, then re-added by a random
        // walk while still disconnected: pruned again immediately.
        tracker.observe(&[], &none, t0 + Duration::from_secs(75));
        assert_eq!(
            tracker
                .observe(&[peer(4)], &none, t0 + Duration::from_secs(90))
                .prune,
            vec![peer(4)]
        );
    }

    /// x0x#1036 wiring: a peer disconnected longer than the threshold leaves
    /// the HyParView active view (so SWIM, shuffle and presence stop
    /// targeting it) and comes back when it reconnects.
    #[tokio::test]
    async fn active_view_drops_stale_peer_and_restores_it_on_reconnect() {
        let membership = FakeMembership::default();
        for byte in [1, 2] {
            membership.add_active(peer(byte)).await.expect("add");
        }
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let only_1 = set(&[peer(1)]);

        maintain_active_view(&membership, &mut tracker, &only_1, t0).await;
        assert_eq!(membership.active_view(), vec![peer(1), peer(2)]);

        maintain_active_view(
            &membership,
            &mut tracker,
            &only_1,
            t0 + Duration::from_secs(61),
        )
        .await;
        assert_eq!(
            membership.active_view(),
            vec![peer(1)],
            "stale peer must stop being a send target"
        );

        let both = set(&[peer(1), peer(2)]);
        maintain_active_view(
            &membership,
            &mut tracker,
            &both,
            t0 + Duration::from_secs(90),
        )
        .await;
        assert_eq!(
            membership.active_view(),
            vec![peer(1), peer(2)],
            "reconnected peer must be targeted again"
        );
    }

    #[test]
    fn presence_targets_exclude_non_connected_active_view_peers() {
        let targets =
            presence_broadcast_targets(vec![peer(1), peer(2), peer(9)], &[peer(1), peer(3)]);
        assert_eq!(targets, vec![peer(1), peer(3)]);

        // Reconnected: targeted again.
        let targets = presence_broadcast_targets(vec![peer(9)], &[peer(9)]);
        assert_eq!(targets, vec![peer(9)]);
    }
}
