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
//! those dials. Everything after the JOIN in `join_network` (presence
//! beacons, the first identity announcement, the capability advert) waited
//! that long for each refused seed ahead of the first good one. saorsa-6
//! showed it at the v0.46.4 and v0.47.0 rollouts.
//!
//! #292 invariant A names the predicate for every gossip-affecting decision:
//! [`NetworkNode::peer_admission`], never transport truth. [`JoinCandidates`]
//! keeps each dial result with the answered peer id, so the join can apply
//! that predicate:
//!
//! - [`JoinCandidates::prune_suppressed`] moves a reconnect-suppressed peer
//!   out of the connected set as soon as its tombstone exists. It then does
//!   not count toward the join's minimum-peer target, and the bootstrap
//!   phase does not dial its address again.
//! - [`JoinCandidates::settle_join_seeds`] waits while plane verdicts are
//!   still open and no candidate is admitted yet, bounded by
//!   [`JOIN_SEED_VERDICT_WAIT`]. It then returns only the admitted
//!   candidates. A JOIN to a peer that is not admitted cannot work anyway:
//!   `send_to_peer` holds gossip frames to a peer that is not plane-cleared
//!   and drops them for a suppressed peer.
//!
//! Neither step weakens the plane gate or the #292 dial gates; both only
//! read their verdicts.

use std::net::SocketAddr;
use std::time::Duration;

use crate::network::{NetworkNode, PeerAdmission, PLANE_HELLO_RETRY_INTERVAL, PLANE_LEGACY_GRACE};

/// Longest time [`JoinCandidates::settle_join_seeds`] waits for open plane
/// verdicts. After [`PLANE_LEGACY_GRACE`] the plane gate admits a connected
/// peer that never sent a hello (pre-#206 code), so no verdict on a peer
/// connected before the wait starts stays open longer than this; one hello
/// retry interval is margin.
pub(crate) const JOIN_SEED_VERDICT_WAIT: Duration =
    PLANE_LEGACY_GRACE.saturating_add(PLANE_HELLO_RETRY_INTERVAL);

/// Poll interval while plane verdicts are open.
const JOIN_SEED_VERDICT_POLL: Duration = Duration::from_millis(50);

/// The seeds the JOIN may use, and how many candidates were left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct JoinSeedPlan {
    /// Admitted candidates, in dial order, each address once.
    pub(crate) seeds: Vec<SocketAddr>,
    /// Left out: a live reconnect-suppression tombstone (cross-plane
    /// refusal, policy rejection, eviction, revocation).
    pub(crate) suppressed: usize,
    /// Left out: still connected, but the plane verdict was open when the
    /// wait ended.
    pub(crate) plane_unresolved: usize,
    /// Left out: no transport connection any more.
    pub(crate) not_connected: usize,
}

/// `true` when more waiting cannot improve the seed choice: a candidate is
/// already admitted (the JOIN needs one good seed), or no plane verdict is
/// still open.
pub(crate) fn verdicts_settled(verdicts: &[PeerAdmission]) -> bool {
    verdicts.contains(&PeerAdmission::Admitted) || !verdicts.contains(&PeerAdmission::PlanePending)
}

/// Keep the admitted candidates, in dial order and each address once.
/// `verdicts[i]` is the admission verdict for `candidates[i]`.
pub(crate) fn plan_join_seeds(
    candidates: &[(SocketAddr, ant_quic::PeerId)],
    verdicts: &[PeerAdmission],
) -> JoinSeedPlan {
    let mut plan = JoinSeedPlan::default();
    for ((addr, _peer), verdict) in candidates.iter().zip(verdicts) {
        match verdict {
            PeerAdmission::Admitted => {
                if !plan.seeds.contains(addr) {
                    plan.seeds.push(*addr);
                }
            }
            PeerAdmission::Suppressed => plan.suppressed += 1,
            PeerAdmission::PlanePending => plan.plane_unresolved += 1,
            PeerAdmission::NotConnected => plan.not_connected += 1,
        }
    }
    plan
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
    pub(crate) fn extend(
        &mut self,
        dialled: impl IntoIterator<Item = (SocketAddr, ant_quic::PeerId)>,
    ) {
        self.connected.extend(dialled);
    }

    /// Number of dialled peers still counted as connected.
    pub(crate) fn len(&self) -> usize {
        self.connected.len()
    }

    /// `true` if `addr` was already dialled in this join, connected or
    /// refused, so a later phase must not dial it again.
    pub(crate) fn contains_addr(&self, addr: &SocketAddr) -> bool {
        self.refused.contains(addr) || self.connected.iter().any(|(known, _)| known == addr)
    }

    /// Move every candidate with a live reconnect-suppression tombstone out
    /// of the connected set. Returns how many moved.
    pub(crate) fn prune_suppressed(&mut self, network: &NetworkNode) -> usize {
        let before = self.connected.len();
        let refused = &mut self.refused;
        self.connected.retain(|(addr, peer)| {
            if network.is_reconnect_suppressed(peer.0) {
                refused.push(*addr);
                false
            } else {
                true
            }
        });
        before - self.connected.len()
    }

    /// Choose the JOIN seeds: wait (at most [`JOIN_SEED_VERDICT_WAIT`])
    /// until a candidate is admitted or no plane verdict is open, then keep
    /// only the admitted candidates.
    pub(crate) async fn settle_join_seeds(&self, network: &NetworkNode) -> JoinSeedPlan {
        let deadline = tokio::time::Instant::now() + JOIN_SEED_VERDICT_WAIT;
        let plan = loop {
            let mut verdicts = Vec::with_capacity(self.connected.len());
            for (_, peer) in &self.connected {
                verdicts.push(network.peer_admission(peer).await);
            }
            if verdicts_settled(&verdicts) || tokio::time::Instant::now() >= deadline {
                break plan_join_seeds(&self.connected, &verdicts);
            }
            tokio::time::sleep(JOIN_SEED_VERDICT_POLL).await;
        };
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
        plan
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
    fn plan_with_only_a_refused_cross_plane_peer_has_no_seed() {
        let plan = plan_join_seeds(&[(addr(6483), peer(1))], &[PeerAdmission::Suppressed]);
        assert!(plan.seeds.is_empty());
        assert_eq!(plan.suppressed, 1);
    }

    #[test]
    fn verdicts_settle_on_first_admitted_or_when_none_is_open() {
        assert!(verdicts_settled(&[]));
        assert!(verdicts_settled(&[
            PeerAdmission::Suppressed,
            PeerAdmission::NotConnected
        ]));
        assert!(verdicts_settled(&[
            PeerAdmission::PlanePending,
            PeerAdmission::Admitted
        ]));
        assert!(!verdicts_settled(&[PeerAdmission::PlanePending]));
        assert!(!verdicts_settled(&[
            PeerAdmission::Suppressed,
            PeerAdmission::PlanePending
        ]));
    }

    #[test]
    fn verdict_wait_covers_the_plane_legacy_grace() {
        assert!(JOIN_SEED_VERDICT_WAIT > PLANE_LEGACY_GRACE);
    }
}
