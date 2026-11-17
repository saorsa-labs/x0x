//! Keep non-connected peers out of gossip send-target sets (x0x#1036).
//!
//! saorsa-gossip adds peers to the HyParView active view from
//! JOIN/FORWARDJOIN random walks, including peers this node never connects
//! to, and nothing prunes the view by transport connectivity. ant-quic's
//! `send` to such a peer fails fast with `Peer not found`.

use saorsa_gossip_membership::Membership;
use saorsa_gossip_types::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub(crate) const STALE_SEND_TARGET_AFTER: Duration = Duration::from_secs(60);

const MAX_TRACKED_PEERS: usize = 4096;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct StaleTargetPlan {
    pub prune: Vec<PeerId>,
    pub restore: Vec<PeerId>,
}

#[derive(Debug)]
pub(crate) struct StaleTargetTracker {
    threshold: Duration,
    absent_since: HashMap<PeerId, Instant>,
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

    pub(crate) fn observe(
        &mut self,
        targets: &[PeerId],
        connected: &HashSet<PeerId>,
        now: Instant,
    ) -> StaleTargetPlan {
        let mut plan = StaleTargetPlan::default();

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
                plan.prune.push(*peer);
                self.pruned.insert(*peer);
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
            self.pruned.clear();
        }
    }
}

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

pub(crate) fn presence_broadcast_targets(
    active_view: Vec<PeerId>,
    connected: &[PeerId],
) -> Vec<PeerId> {
    let connected_set: HashSet<PeerId> = connected.iter().copied().collect();
    let mut targets: Vec<PeerId> = active_view
        .into_iter()
        .filter(|peer| connected_set.contains(peer))
        .collect();
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

        assert!(tracker.observe(&targets, &connected, t0).prune.is_empty());
        assert!(tracker
            .observe(&targets, &connected, t0 + Duration::from_secs(59))
            .prune
            .is_empty());
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
        tracker.observe(&[], &none, t0 + Duration::from_secs(75));
        assert_eq!(
            tracker
                .observe(&[peer(4)], &none, t0 + Duration::from_secs(90))
                .prune,
            vec![peer(4)]
        );
    }

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

        let targets = presence_broadcast_targets(vec![peer(9)], &[peer(9)]);
        assert_eq!(targets, vec![peer(9)]);
    }

    #[tokio::test]
    async fn pool_tombstoned_peer_is_pruned_after_threshold() {
        let membership = FakeMembership::default();
        let (kept, evicted) = (peer(10), peer(11));
        for p in [kept, evicted] {
            membership.add_active(p).await.expect("add");
        }
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();

        let both = set(&[kept, evicted]);
        maintain_active_view(&membership, &mut tracker, &both, t0).await;

        let only_kept = set(&[kept]);
        let t_close = t0 + Duration::from_secs(15);
        let plan = maintain_active_view(&membership, &mut tracker, &only_kept, t_close).await;
        assert!(plan.prune.is_empty(), "grace starts at the close");
        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(59),
        )
        .await;
        assert!(plan.prune.is_empty(), "still inside the grace period");

        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(60),
        )
        .await;
        assert_eq!(plan.prune, vec![evicted]);
        assert_eq!(
            membership.active_view(),
            vec![kept],
            "a pool-evicted peer must stop being a send target"
        );

        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(75),
        )
        .await;
        assert!(plan.restore.is_empty(), "no restore while evicted");
        membership.add_active(evicted).await.expect("re-add");
        let plan = maintain_active_view(
            &membership,
            &mut tracker,
            &only_kept,
            t_close + Duration::from_secs(90),
        )
        .await;
        assert_eq!(plan.prune, vec![evicted]);
        assert_eq!(membership.active_view(), vec![kept]);
    }

    #[test]
    fn plane_pending_peer_counts_as_connected() {
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let p = peer(20);
        let none = HashSet::new();
        let plane_pending = set(&[p]);

        tracker.observe(&[p], &none, t0);
        assert_eq!(
            tracker
                .observe(&[p], &none, t0 + Duration::from_secs(60))
                .prune,
            vec![p]
        );

        let plan = tracker.observe(&[], &plane_pending, t0 + Duration::from_secs(70));
        assert_eq!(plan.restore, vec![p], "restored while plane-pending");

        let t1 = t0 + Duration::from_secs(100);
        tracker.observe(&[p], &none, t1);
        tracker.observe(&[p], &plane_pending, t1 + Duration::from_secs(50));
        let refused_at = t1 + Duration::from_secs(55);
        assert!(tracker.observe(&[p], &none, refused_at).prune.is_empty());
        assert!(
            tracker
                .observe(&[p], &none, refused_at + Duration::from_secs(59))
                .prune
                .is_empty(),
            "the plane-pending sighting restarted the absence clock"
        );
        assert_eq!(
            tracker
                .observe(&[p], &none, refused_at + Duration::from_secs(60))
                .prune,
            vec![p]
        );
    }

    #[tokio::test]
    async fn presence_targets_and_pruning_agree() {
        let membership = FakeMembership::default();
        let (up, flapped, long_gone, transport_only) = (peer(30), peer(31), peer(32), peer(33));
        for p in [up, flapped, long_gone] {
            membership.add_active(p).await.expect("add");
        }
        let mut tracker = StaleTargetTracker::new(Duration::from_secs(60));
        let t0 = Instant::now();

        maintain_active_view(&membership, &mut tracker, &set(&[up, flapped]), t0).await;
        maintain_active_view(
            &membership,
            &mut tracker,
            &set(&[up]),
            t0 + Duration::from_secs(30),
        )
        .await;

        let snapshot = vec![up, transport_only];
        let now = t0 + Duration::from_secs(60);
        let view_before = membership.active_view();
        let presence_before = presence_broadcast_targets(view_before.clone(), &snapshot);
        let plan = maintain_active_view(&membership, &mut tracker, &set(&snapshot), now).await;
        let presence_after = presence_broadcast_targets(membership.active_view(), &snapshot);

        assert_eq!(plan.prune, vec![long_gone], "only the 60 s-absent peer");
        for pruned in &plan.prune {
            assert!(
                !presence_before.contains(pruned),
                "a pruned peer must not be a presence target"
            );
        }
        for target in &presence_before {
            assert!(
                !plan.prune.contains(target),
                "a presence target must not be pruned"
            );
        }
        assert_eq!(
            presence_before, presence_after,
            "pruning must not change the presence target set"
        );
        assert_eq!(presence_after, vec![up, transport_only]);
        assert!(
            !presence_after.contains(&flapped),
            "inside its grace a disconnected peer stays in the view but gets no beacon"
        );
    }
}
