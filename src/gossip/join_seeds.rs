//! HyParView JOIN seeds come only from gossip-admitted peers (x0x#1321).
//!
//! [`crate::Agent::join_network`] dials peers in three phases (cached
//! coordinators, cached peers, hard-coded bootstrap nodes) and then joins
//! the HyParView overlay through them. It used to pass every address whose
//! transport dial returned `Ok` to `membership().join(seeds)`.
//!
//! A dial that returned `Ok` is transport truth, not gossip admission. The
//! gossip-plane gate (issue #206) decides a peer's plane only when the
//! peer's plane hello arrives, after the dial has returned. A mismatched
//! hello disconnects the peer with a `PolicyRejection` reconnect-suppression
//! tombstone (issue #292). So a cached peer on another plane passed the
//! dial, was refused a moment later, and still became a JOIN seed.
//! saorsa-gossip's JOIN tries the seeds in order and dials one seed up to
//! ten times with backoff (about 81 s), and the #292 gate refused each of
//! those dials. The work after the JOIN in `join_network` (presence
//! beacons, the first identity announcement) waited that long for each
//! refused seed ahead of the first good one. saorsa-6 showed it at the
//! v0.46.4 and v0.47.0 rollouts.
//!
//! #292 invariant A names the predicate for every gossip-affecting decision:
//! [`NetworkNode::peer_admission`], never transport truth. [`JoinCandidates`]
//! keeps each dial result with the answered peer id, so the join can apply
//! that predicate:
//!
//! - [`JoinCandidates::usable`] is the count for the phase decisions: only
//!   peers that are still connected and not suppressed. A peer refused
//!   before the count does not fill the join's minimum-peer target, and the
//!   bootstrap phase does not dial its address again.
//! - [`JoinCandidates::settle`] with [`SettleGoal::Admitted`] waits while
//!   plane verdicts are open, until enough peers are admitted (bounded by
//!   [`JOIN_SEED_VERDICT_WAIT`]). The join compares the settled admitted
//!   count with its minimum. When peers that filled the minimum on an open
//!   verdict were refused later, the join runs the phases it skipped.
//! - [`JoinCandidates::settle`] with [`SettleGoal::Recover`] is for a join
//!   with no admitted seed yet. A candidate that lost its connection without
//!   a tombstone can come back: the proactive reconnect (`schedule_reconnect`)
//!   redials it. The join waits for that, bounded by
//!   [`JOIN_SEED_RECOVERY_WAIT`], and reads the verdict again. (The code
//!   before #1321 kept the address and let the JOIN redial it.)
//!
//! The seeds are always the admitted candidates only. A JOIN to a peer that
//! is not admitted cannot work anyway: `send_to_peer` holds gossip frames to
//! a peer that is not plane-cleared and drops them for a suppressed peer.
//!
//! None of these steps weakens the plane gate or the #292 dial gates; they
//! only read their verdicts. The join itself makes no extra dial for
//! recovery.

use std::net::SocketAddr;
use std::time::Duration;

use crate::network::{NetworkNode, PeerAdmission, PLANE_HELLO_RETRY_INTERVAL, PLANE_LEGACY_GRACE};

/// Longest time [`SettleGoal::Admitted`] waits for open plane verdicts.
/// After [`PLANE_LEGACY_GRACE`] the plane gate admits a connected peer that
/// never sent a hello (pre-#206 code), so no verdict on a peer connected
/// before the wait starts stays open longer than this; one hello retry
/// interval is margin.
pub(crate) const JOIN_SEED_VERDICT_WAIT: Duration =
    PLANE_LEGACY_GRACE.saturating_add(PLANE_HELLO_RETRY_INTERVAL);

/// Longest time [`SettleGoal::Recover`] waits for a candidate to become
/// admitted.
///
/// A candidate that lost its connection without a tombstone is redialled
/// by the proactive reconnect: one attempt after each delay in
/// `RECONNECT_BACKOFF_DELAYS` (1, 2, 4, 8 and 16 s), each delay with up to
/// +20 % jitter. So the last attempt starts at most 37.2 s after the loss.
/// One [`JOIN_SEED_VERDICT_WAIT`] after that covers the last dial and the
/// plane hello. The wait ends as soon as one candidate is admitted.
pub(crate) const JOIN_SEED_RECOVERY_WAIT: Duration =
    reconnect_backoff_envelope().saturating_add(JOIN_SEED_VERDICT_WAIT);

/// Poll interval while plane verdicts are open.
const JOIN_SEED_VERDICT_POLL: Duration = Duration::from_millis(50);

/// Poll interval while the join waits for transport recovery.
const JOIN_SEED_RECOVERY_POLL: Duration = Duration::from_millis(250);

/// Sum of the proactive reconnect backoff delays at their largest jitter
/// (factor 1.2, see `jittered_backoff_delay`).
const fn reconnect_backoff_envelope() -> Duration {
    let mut total_ms: u64 = 0;
    let mut index = 0;
    while index < crate::RECONNECT_BACKOFF_DELAYS.len() {
        let delay = crate::RECONNECT_BACKOFF_DELAYS[index];
        total_ms = total_ms
            .saturating_add(delay.as_secs().saturating_mul(1000))
            .saturating_add(delay.subsec_millis() as u64);
        index += 1;
    }
    Duration::from_millis(total_ms.saturating_mul(6) / 5)
}

/// What one [`JoinCandidates::settle`] call waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettleGoal {
    /// Wait while plane verdicts are open, until this many distinct peers
    /// are admitted. At most [`JOIN_SEED_VERDICT_WAIT`]. The join uses its
    /// minimum peer count here, for its phase fallback.
    Admitted(usize),
    /// No candidate is admitted yet. Wait while a candidate can still
    /// become admitted (its plane verdict is open, or it lost its
    /// connection without a tombstone), until one is admitted. At most
    /// [`JOIN_SEED_RECOVERY_WAIT`].
    Recover,
}

/// The seeds the JOIN may use, and how many candidates were left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct JoinSeedPlan {
    /// Admitted candidates, in dial order, each address once.
    pub(crate) seeds: Vec<SocketAddr>,
    /// Distinct admitted peers. A peer dialled at two addresses counts once.
    pub(crate) admitted_peers: usize,
    /// Left out: a live reconnect-suppression tombstone (cross-plane
    /// refusal, policy rejection, eviction, revocation).
    pub(crate) suppressed: usize,
    /// Left out: still connected, but the plane verdict was open when the
    /// wait ended.
    pub(crate) plane_unresolved: usize,
    /// Left out: no transport connection when the wait ended.
    pub(crate) not_connected: usize,
}

/// Keep the admitted candidates, in dial order and each address once.
/// `verdicts[i]` is the admission verdict for `candidates[i]`.
pub(crate) fn plan_join_seeds(
    candidates: &[(SocketAddr, ant_quic::PeerId)],
    verdicts: &[PeerAdmission],
) -> JoinSeedPlan {
    let mut plan = JoinSeedPlan::default();
    let mut admitted: Vec<ant_quic::PeerId> = Vec::new();
    for ((addr, peer), verdict) in candidates.iter().zip(verdicts) {
        match verdict {
            PeerAdmission::Admitted => {
                if !plan.seeds.contains(addr) {
                    plan.seeds.push(*addr);
                }
                if !admitted.contains(peer) {
                    admitted.push(*peer);
                }
            }
            PeerAdmission::Suppressed => plan.suppressed += 1,
            PeerAdmission::PlanePending => plan.plane_unresolved += 1,
            PeerAdmission::NotConnected => plan.not_connected += 1,
        }
    }
    plan.admitted_peers = admitted.len();
    plan
}

/// `true` when more waiting cannot improve `plan` for `goal`, or when the
/// wait for `goal` has used its bound.
pub(crate) fn settled(goal: SettleGoal, plan: &JoinSeedPlan, waited: Duration) -> bool {
    match goal {
        SettleGoal::Admitted(target) => {
            plan.admitted_peers >= target
                || plan.plane_unresolved == 0
                || waited >= JOIN_SEED_VERDICT_WAIT
        }
        SettleGoal::Recover => {
            plan.admitted_peers > 0
                || (plan.plane_unresolved == 0 && plan.not_connected == 0)
                || waited >= JOIN_SEED_RECOVERY_WAIT
        }
    }
}

/// Dial results of one `join_network` run, with the answered peer ids.
#[derive(Debug, Default)]
pub(crate) struct JoinCandidates {
    /// Dials that returned `Ok` and are not known to be suppressed.
    connected: Vec<(SocketAddr, ant_quic::PeerId)>,
    /// Addresses whose answered peer was later found suppressed.
    refused: Vec<SocketAddr>,
}

impl JoinCandidates {
    /// Record dials that returned `Ok`, as `(address, answered peer id)`.
    /// A record that is already present is not added again.
    pub(crate) fn extend(
        &mut self,
        dialled: impl IntoIterator<Item = (SocketAddr, ant_quic::PeerId)>,
    ) {
        for record in dialled {
            if !self.connected.contains(&record) {
                self.connected.push(record);
            }
        }
    }

    /// Number of dial records not known to be suppressed (for logs).
    pub(crate) fn len(&self) -> usize {
        self.connected.len()
    }

    /// `true` if `addr` was already dialled in this join, connected or
    /// refused, so a later phase must not dial it again.
    pub(crate) fn contains_addr(&self, addr: &SocketAddr) -> bool {
        self.refused.contains(addr) || self.connected.iter().any(|(known, _)| known == addr)
    }

    /// The count for the join's phase decisions: distinct peers that are
    /// still connected and not suppressed (`Admitted` or `PlanePending`).
    /// It reads the verdicts now and does not wait. Suppressed candidates
    /// move to the refused set.
    pub(crate) async fn usable(&mut self, network: &NetworkNode) -> usize {
        let mut kept = Vec::with_capacity(self.connected.len());
        let mut usable: Vec<ant_quic::PeerId> = Vec::new();
        for (addr, peer) in std::mem::take(&mut self.connected) {
            match network.peer_admission(&peer).await {
                PeerAdmission::Suppressed => self.refused.push(addr),
                PeerAdmission::Admitted | PeerAdmission::PlanePending => {
                    if !usable.contains(&peer) {
                        usable.push(peer);
                    }
                    kept.push((addr, peer));
                }
                PeerAdmission::NotConnected => kept.push((addr, peer)),
            }
        }
        self.connected = kept;
        usable.len()
    }

    /// Read the verdicts until [`settled`] for `goal`, then keep only the
    /// admitted candidates. Returns early when `shutdown` is cancelled.
    pub(crate) async fn settle(
        &self,
        network: &NetworkNode,
        goal: SettleGoal,
        shutdown: &tokio_util::sync::CancellationToken,
    ) -> JoinSeedPlan {
        let poll = match goal {
            SettleGoal::Admitted(_) => JOIN_SEED_VERDICT_POLL,
            SettleGoal::Recover => JOIN_SEED_RECOVERY_POLL,
        };
        let started = tokio::time::Instant::now();
        loop {
            let mut verdicts = Vec::with_capacity(self.connected.len());
            for (_, peer) in &self.connected {
                verdicts.push(network.peer_admission(peer).await);
            }
            let plan = plan_join_seeds(&self.connected, &verdicts);
            if settled(goal, &plan, started.elapsed()) || shutdown.is_cancelled() {
                return plan;
            }
            tokio::select! {
                _ = tokio::time::sleep(poll) => {}
                _ = shutdown.cancelled() => {}
            }
        }
    }

    /// Log the final seed plan when it left candidates out.
    pub(crate) fn log_plan(&self, plan: &JoinSeedPlan) {
        let left_out = plan.suppressed + plan.plane_unresolved + plan.not_connected;
        if left_out > 0 || !self.refused.is_empty() {
            tracing::info!(
                target: "x0x::connect",
                seeds = plan.seeds.len(),
                suppressed = plan.suppressed + self.refused.len(),
                plane_unresolved = plan.plane_unresolved,
                not_connected = plan.not_connected,
                "JOIN seeds: kept only gossip-admitted peers (issue #1321)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn peer(byte: u8) -> ant_quic::PeerId {
        ant_quic::PeerId([byte; 32])
    }

    fn plan(admitted: usize, pending: usize, lost: usize) -> JoinSeedPlan {
        JoinSeedPlan {
            seeds: Vec::new(),
            admitted_peers: admitted,
            suppressed: 0,
            plane_unresolved: pending,
            not_connected: lost,
        }
    }

    #[test]
    fn plan_keeps_only_admitted_candidates_in_dial_order() {
        let candidates = [
            (addr(6483), peer(1)),
            (addr(5483), peer(2)),
            (addr(443), peer(3)),
            (addr(5484), peer(4)),
            (addr(5485), peer(5)),
        ];
        let verdicts = [
            PeerAdmission::Suppressed,
            PeerAdmission::Admitted,
            PeerAdmission::PlanePending,
            PeerAdmission::NotConnected,
            PeerAdmission::Admitted,
        ];
        let plan = plan_join_seeds(&candidates, &verdicts);
        assert_eq!(plan.seeds, vec![addr(5483), addr(5485)]);
        assert_eq!(plan.admitted_peers, 2);
        assert_eq!(plan.suppressed, 1);
        assert_eq!(plan.plane_unresolved, 1);
        assert_eq!(plan.not_connected, 1);
    }

    #[test]
    fn plan_lists_each_admitted_address_once() {
        let candidates = [(addr(5483), peer(2)), (addr(5483), peer(2))];
        let verdicts = [PeerAdmission::Admitted, PeerAdmission::Admitted];
        assert_eq!(
            plan_join_seeds(&candidates, &verdicts).seeds,
            vec![addr(5483)]
        );
    }

    #[test]
    fn plan_counts_a_peer_dialled_at_two_addresses_once() {
        let candidates = [(addr(5483), peer(2)), (addr(443), peer(2))];
        let verdicts = [PeerAdmission::Admitted, PeerAdmission::Admitted];
        let plan = plan_join_seeds(&candidates, &verdicts);
        assert_eq!(plan.seeds, vec![addr(5483), addr(443)]);
        assert_eq!(plan.admitted_peers, 1);
    }

    #[test]
    fn plan_with_only_a_refused_cross_plane_peer_has_no_seed() {
        let plan = plan_join_seeds(&[(addr(6483), peer(1))], &[PeerAdmission::Suppressed]);
        assert!(plan.seeds.is_empty());
        assert_eq!(plan.suppressed, 1);
    }

    /// Codex round-1 finding 2: open verdicts below the target are waited
    /// for, so a later refusal still leads to the phase fallback.
    #[test]
    fn admitted_goal_waits_for_open_verdicts_below_the_target() {
        let zero = Duration::ZERO;
        let goal = SettleGoal::Admitted(3);
        assert!(!settled(goal, &plan(0, 3, 0), zero));
        assert!(!settled(goal, &plan(2, 1, 0), zero));
        // The refusals landed: nothing open, below the target. The join
        // reads this as "fall back".
        assert!(settled(goal, &plan(0, 0, 0), zero));
        assert!(settled(goal, &plan(3, 2, 0), zero));
        // A lost connection does not hold the phase decision.
        assert!(settled(goal, &plan(0, 0, 2), zero));
        assert!(settled(goal, &plan(0, 3, 0), JOIN_SEED_VERDICT_WAIT));
    }

    /// Codex round-1 finding 1: one read that shows the only candidate not
    /// connected does not end the recovery wait.
    #[test]
    fn recover_goal_waits_for_a_lost_unsuppressed_candidate() {
        let zero = Duration::ZERO;
        assert!(!settled(SettleGoal::Recover, &plan(0, 0, 1), zero));
        assert!(!settled(SettleGoal::Recover, &plan(0, 1, 0), zero));
        assert!(settled(SettleGoal::Recover, &plan(1, 0, 1), zero));
        // Only suppressed candidates (or none): nothing can recover.
        assert!(settled(SettleGoal::Recover, &plan(0, 0, 0), zero));
        // Bounded.
        assert!(!settled(
            SettleGoal::Recover,
            &plan(0, 0, 1),
            JOIN_SEED_RECOVERY_WAIT.saturating_sub(Duration::from_millis(1))
        ));
        assert!(settled(
            SettleGoal::Recover,
            &plan(0, 0, 1),
            JOIN_SEED_RECOVERY_WAIT
        ));
    }

    #[test]
    fn verdict_wait_covers_the_plane_legacy_grace() {
        assert!(JOIN_SEED_VERDICT_WAIT > PLANE_LEGACY_GRACE);
    }

    #[test]
    fn recovery_wait_covers_the_proactive_reconnect_schedule() {
        // 1 + 2 + 4 + 8 + 16 s at +20 % jitter.
        assert_eq!(reconnect_backoff_envelope(), Duration::from_millis(37_200));
        assert_eq!(
            JOIN_SEED_RECOVERY_WAIT,
            Duration::from_millis(37_200) + JOIN_SEED_VERDICT_WAIT
        );
    }
}
