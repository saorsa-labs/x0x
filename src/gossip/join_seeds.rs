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
//! ten times with backoff, and the #292 gate refused each of those dials.
//! The work after the JOIN in `join_network` (presence beacons, the first
//! identity announcement) waited that long for each refused seed ahead of
//! the first good one. saorsa-6 showed it at the v0.46.4 and v0.47.0
//! rollouts.
//!
//! #292 invariant A names the predicate for every gossip-affecting decision:
//! [`NetworkNode::peer_admission`], never transport truth. [`JoinCandidates`]
//! keeps each dial result with the answered peer id, so the join can apply
//! that predicate:
//!
//! - [`JoinCandidates::usable`] is the count for the phase decisions: only
//!   distinct peers that are still connected and not suppressed. A peer
//!   refused before the count does not fill the join's minimum-peer target,
//!   and the bootstrap phase does not dial its address again.
//! - [`JoinCandidates::settle`] waits while plane verdicts are open, until
//!   enough peers are admitted (at most [`JOIN_SEED_VERDICT_WAIT`], which
//!   covers the plane gate's own legacy grace). The join compares the
//!   settled admitted count with its minimum. When peers that filled the
//!   minimum on an open verdict were refused later, the join runs the
//!   phases it skipped. This wait drops no candidate.
//! - [`JoinCandidates::join_overlay`] is the JOIN. saorsa-gossip drives
//!   each JOIN attempt and owns its retry policy, its frame and its
//!   membership side effects, through its step API
//!   (`HyParViewMembership::join_dial`, `join_send` and `JoinLedger`, added
//!   for this fix; D248). x0x chooses the candidate and decides, between the
//!   dial and the JOIN frame, whether the answered peer may get the frame:
//!   - One `JoinLedger` covers the whole `join_network` call, so each
//!     candidate address has one budget of saorsa-gossip's attempts, kept
//!     when another candidate interrupts it and never renewed.
//!   - The next attempt on an address waits for `JoinLedger::ready_at`:
//!     the later of saorsa-gossip's dial backoff (it grows only after a
//!     failed dial, as in its `join`) and its loss cooldown.
//!   - After a dial that answered, the JOIN frame goes out only when the
//!     peer is `Admitted`. The gate waits for an open plane verdict (at
//!     most [`JOIN_SEED_VERDICT_WAIT`]).
//!   - A peer that answered and then lost its connection before admission
//!     (for example, the remote refused us first) is reported with
//!     `JoinLedger::record_loss`: saorsa-gossip's loss cooldown (100 ms,
//!     doubled after each loss up to 30 s, plus jitter; D252) paces the
//!     next attempt on that address. Another admitted address can go
//!     meanwhile.
//!   - A failed send, or a verdict that stays open for the whole gate
//!     wait, ends the attempt; the next attempt may start at once.
//!   - A suppressed candidate is dropped at once, with no attempt.
//!   - An admitted candidate goes first. Otherwise the candidates are tried
//!     in dial order, one after another, as the old JOIN tried its seeds.
//!
//! `join_network` awaits all of this, as it awaited the old JOIN. There is
//! no new time limit for a candidate and no retry after its budget. The
//! admission reads, the verdict waits, the JOIN dials, the backoffs and the
//! JOIN send stop on the shutdown token; when the token and a result are
//! both ready, cancellation goes first. `join_network` checks the token
//! before each phase and before the JOIN.
//!
//! None of these steps weakens the plane gate or the #292 dial gates; they
//! only read their verdicts.

use std::net::SocketAddr;
use std::time::Duration;

use saorsa_gossip_membership::{HyParViewMembership, JoinDial, JoinLedger, JoinSend};
use saorsa_gossip_transport::GossipTransport;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::network::{NetworkNode, PeerAdmission, PLANE_HELLO_RETRY_INTERVAL, PLANE_LEGACY_GRACE};

/// Longest time [`JoinCandidates::settle`] (and the JOIN gate) waits for an
/// open plane verdict. After [`PLANE_LEGACY_GRACE`] the plane gate admits a
/// connected peer that never sent a hello (pre-#206 code), so no verdict on
/// a peer connected before the wait starts stays open longer than this; one
/// hello retry interval is margin.
pub(crate) const JOIN_SEED_VERDICT_WAIT: Duration =
    PLANE_LEGACY_GRACE.saturating_add(PLANE_HELLO_RETRY_INTERVAL);

/// Poll interval while plane verdicts are open, and during a JOIN backoff.
const JOIN_SEED_VERDICT_POLL: Duration = Duration::from_millis(50);

/// The time left until `at`, or `None` when `at` has passed.
fn remaining(at: Instant) -> Option<Duration> {
    at.checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// The admission verdicts that the seed choice reads.
#[async_trait::async_trait]
pub(crate) trait SeedAdmission: Send + Sync {
    /// The #292 admission verdict for `peer`.
    async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission;
}

#[async_trait::async_trait]
impl SeedAdmission for NetworkNode {
    async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission {
        self.peer_admission(peer).await
    }
}

fn ant_peer(peer: saorsa_gossip_types::PeerId) -> ant_quic::PeerId {
    ant_quic::PeerId(peer.to_bytes())
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

/// `true` when more waiting for plane verdicts cannot raise the admitted
/// count to `target`, or when the wait has used [`JOIN_SEED_VERDICT_WAIT`].
pub(crate) fn settled(plan: &JoinSeedPlan, target: usize, waited: Duration) -> bool {
    plan.admitted_peers >= target || plan.plane_unresolved == 0 || waited >= JOIN_SEED_VERDICT_WAIT
}

/// How [`JoinCandidates::join_overlay`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JoinOutcome {
    /// The JOIN went through this seed.
    Joined(SocketAddr),
    /// No candidate is left: each was dropped or used its budget.
    /// `attempts` is the number of JOIN attempts made.
    NoSeed { attempts: usize },
    /// The active-view update failed. saorsa-gossip's JOIN ends with this
    /// error.
    Failed(String),
    /// Shutdown began.
    Cancelled,
}

/// How one JOIN attempt ended.
enum Attempt {
    /// The attempt was used; choose the next attempt.
    Next,
    /// saorsa-gossip refused an early dial (no attempt used).
    NotReady,
    Joined(SocketAddr),
    Failed(String),
    Cancelled,
}

/// What the JOIN gate decided for an answered peer.
enum Gate {
    /// Admitted: send the JOIN frame.
    Send,
    /// The peer lost its connection before admission: end this attempt
    /// without a frame and start saorsa-gossip's loss cooldown (D252).
    Lost,
    /// The plane verdict stayed open for the whole gate wait: end this
    /// attempt without a frame; the next attempt may start at once.
    Unresolved,
    /// Suppressed: drop the candidate.
    Refused,
    Cancelled,
}

/// One admission read that ends early when shutdown begins. Cancellation
/// goes first when both are ready.
async fn read_admission<A: SeedAdmission + ?Sized>(
    admission: &A,
    peer: &ant_quic::PeerId,
    shutdown: &CancellationToken,
) -> Option<PeerAdmission> {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => None,
        verdict = admission.admission(peer) => Some(verdict),
    }
}

/// Sleep for `wait`, or until shutdown begins. Returns `false` on shutdown.
/// Cancellation goes first when both are ready.
async fn nap(wait: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tokio::time::sleep(wait) => true,
    }
}

/// One candidate: a dial that returned `Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    addr: SocketAddr,
    /// The peer that answered at `addr` last.
    peer: ant_quic::PeerId,
}

/// Dial results of one `join_network` run, with the answered peer ids and
/// the JOIN retry state of each address.
#[derive(Debug, Default)]
pub(crate) struct JoinCandidates {
    /// Dials that returned `Ok` and are not known to be suppressed, one
    /// record per address.
    connected: Vec<Candidate>,
    /// Addresses whose answered peer was later found suppressed.
    refused: Vec<SocketAddr>,
    /// saorsa-gossip's JOIN attempts, dial backoff and loss cooldown per
    /// address, for the whole join.
    ledger: JoinLedger,
}

impl JoinCandidates {
    /// Record dials that returned `Ok`, as `(address, answered peer id)`.
    /// A new answer at a known address replaces the old peer id; the
    /// address keeps its JOIN budget.
    pub(crate) fn extend(
        &mut self,
        dialled: impl IntoIterator<Item = (SocketAddr, ant_quic::PeerId)>,
    ) {
        for (addr, peer) in dialled {
            match self.connected.iter_mut().find(|known| known.addr == addr) {
                Some(record) => record.peer = peer,
                None => self.connected.push(Candidate { addr, peer }),
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
        self.refused.contains(addr) || self.connected.iter().any(|known| known.addr == *addr)
    }

    /// Move `addr` to the refused set.
    fn drop_candidate(&mut self, addr: SocketAddr) {
        self.connected.retain(|known| known.addr != addr);
        self.refused.push(addr);
    }

    /// Read the verdict of every record (only those with JOIN budget left
    /// when `budgeted`). Suppressed records move to the refused set.
    /// Returns the kept records' addresses with their verdicts, in dial
    /// order, or `None` when shutdown began.
    async fn read_verdicts<A: SeedAdmission + ?Sized>(
        &mut self,
        admission: &A,
        budgeted: bool,
        shutdown: &CancellationToken,
    ) -> Option<Vec<(SocketAddr, ant_quic::PeerId, PeerAdmission)>> {
        let mut read = Vec::with_capacity(self.connected.len());
        for candidate in &self.connected {
            if !budgeted || !self.ledger.is_exhausted(candidate.addr) {
                let verdict = read_admission(admission, &candidate.peer, shutdown).await?;
                read.push((candidate.addr, candidate.peer, verdict));
            }
        }
        for (addr, _, verdict) in &read {
            if *verdict == PeerAdmission::Suppressed {
                self.drop_candidate(*addr);
            }
        }
        read.retain(|(_, _, verdict)| *verdict != PeerAdmission::Suppressed);
        Some(read)
    }

    /// The count for the join's phase decisions: distinct peers that are
    /// still connected and not suppressed (`Admitted` or `PlanePending`).
    /// It reads the verdicts now and does not wait. Suppressed candidates
    /// move to the refused set. `None` when shutdown began.
    pub(crate) async fn usable<A: SeedAdmission + ?Sized>(
        &mut self,
        admission: &A,
        shutdown: &CancellationToken,
    ) -> Option<usize> {
        let mut usable: Vec<ant_quic::PeerId> = Vec::new();
        for (_, peer, verdict) in self.read_verdicts(admission, false, shutdown).await? {
            let connected = matches!(
                verdict,
                PeerAdmission::Admitted | PeerAdmission::PlanePending
            );
            if connected && !usable.contains(&peer) {
                usable.push(peer);
            }
        }
        Some(usable.len())
    }

    /// Read the verdicts until [`settled`] for `target`, then keep only the
    /// admitted candidates. When shutdown begins, it returns at once with no
    /// seed.
    pub(crate) async fn settle<A: SeedAdmission + ?Sized>(
        &self,
        admission: &A,
        target: usize,
        shutdown: &CancellationToken,
    ) -> JoinSeedPlan {
        let started = Instant::now();
        let records: Vec<(SocketAddr, ant_quic::PeerId)> = self
            .connected
            .iter()
            .map(|candidate| (candidate.addr, candidate.peer))
            .collect();
        loop {
            let mut verdicts = Vec::with_capacity(records.len());
            for (_, peer) in &records {
                match read_admission(admission, peer, shutdown).await {
                    Some(verdict) => verdicts.push(verdict),
                    None => return JoinSeedPlan::default(),
                }
            }
            let plan = plan_join_seeds(&records, &verdicts);
            if settled(&plan, target, started.elapsed()) {
                return plan;
            }
            if !nap(JOIN_SEED_VERDICT_POLL, shutdown).await {
                return JoinSeedPlan::default();
            }
        }
    }

    /// The JOIN through `membership`, with saorsa-gossip's attempt budget,
    /// dial backoff and loss cooldown per address, and x0x's admission gate
    /// before each JOIN frame (see the module doc).
    pub(crate) async fn join_overlay<T, A>(
        &mut self,
        membership: &HyParViewMembership<T>,
        admission: &A,
        shutdown: &CancellationToken,
    ) -> JoinOutcome
    where
        T: GossipTransport + 'static,
        A: SeedAdmission + ?Sized,
    {
        // The old JOIN tried its seeds one after another: after the last
        // failed attempt on a seed it slept that attempt's backoff before
        // the next seed. `gate` keeps that order for candidates that are
        // not admitted.
        let mut gate = Instant::now();
        let mut attempts = 0;
        loop {
            if shutdown.is_cancelled() {
                return JoinOutcome::Cancelled;
            }
            let Some(live) = self.read_verdicts(admission, true, shutdown).await else {
                return JoinOutcome::Cancelled;
            };
            let pick = live
                .iter()
                .find(|(_, _, verdict)| *verdict == PeerAdmission::Admitted)
                .map(|(addr, _, _)| (*addr, true))
                .or_else(|| live.first().map(|(addr, _, _)| (*addr, false)));
            let Some((addr, admitted)) = pick else {
                // As in the old JOIN, the last failed attempt's backoff
                // ends before the JOIN gives up.
                if let Some(wait) = remaining(gate) {
                    if !nap(wait, shutdown).await {
                        return JoinOutcome::Cancelled;
                    }
                }
                return JoinOutcome::NoSeed { attempts };
            };
            // saorsa-gossip's readiness for this address: the later of its
            // dial backoff and its loss cooldown.
            let own = self.ledger.ready_at(addr);
            let ready_at = if admitted {
                own
            } else {
                Some(own.map_or(gate, |own| own.max(gate)))
            };
            if let Some(wait) = ready_at.and_then(remaining) {
                // Not yet: wait (a little at a time, so that a candidate
                // that becomes admitted can go first).
                if !nap(wait.min(JOIN_SEED_VERDICT_POLL), shutdown).await {
                    return JoinOutcome::Cancelled;
                }
                continue;
            }
            match self
                .attempt(membership, admission, addr, &mut gate, shutdown)
                .await
            {
                Attempt::Next => attempts += 1,
                Attempt::NotReady => {}
                Attempt::Joined(seed) => return JoinOutcome::Joined(seed),
                Attempt::Failed(error) => return JoinOutcome::Failed(error),
                Attempt::Cancelled => return JoinOutcome::Cancelled,
            }
        }
    }

    /// One JOIN attempt on `addr`: saorsa-gossip's dial, x0x's admission
    /// gate, then saorsa-gossip's JOIN send.
    async fn attempt<T, A>(
        &mut self,
        membership: &HyParViewMembership<T>,
        admission: &A,
        addr: SocketAddr,
        gate: &mut Instant,
        shutdown: &CancellationToken,
    ) -> Attempt
    where
        T: GossipTransport + 'static,
        A: SeedAdmission + ?Sized,
    {
        if shutdown.is_cancelled() {
            return Attempt::Cancelled;
        }
        let dialled = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Attempt::Cancelled,
            dialled = membership.join_dial(&mut self.ledger, addr) => dialled,
        };
        let peer = match dialled {
            JoinDial::Answered(peer) => ant_peer(peer),
            JoinDial::Failed { exhausted, .. } => {
                if exhausted {
                    if let Some(at) = self.ledger.ready_at(addr) {
                        *gate = (*gate).max(at);
                    }
                }
                return Attempt::Next;
            }
            JoinDial::NotReady { .. } => return Attempt::NotReady,
            JoinDial::Exhausted => return Attempt::Next,
        };
        self.extend([(addr, peer)]);

        match self.gate(admission, addr, peer, shutdown).await {
            Gate::Send => {}
            Gate::Lost => {
                // D252: saorsa-gossip's loss cooldown paces the next
                // attempt on this address.
                let _ready_at = self.ledger.record_loss(addr);
                return Attempt::Next;
            }
            Gate::Unresolved => return Attempt::Next,
            Gate::Refused => {
                self.drop_candidate(addr);
                return Attempt::Next;
            }
            Gate::Cancelled => return Attempt::Cancelled,
        }

        if shutdown.is_cancelled() {
            return Attempt::Cancelled;
        }
        let sent = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Attempt::Cancelled,
            sent = membership.join_send(addr, saorsa_gossip_types::PeerId::new(peer.0)) => sent,
        };
        match sent {
            Ok(JoinSend::Joined) => Attempt::Joined(addr),
            // saorsa-gossip's JOIN tries again at once after a failed send.
            Ok(JoinSend::SendFailed) => Attempt::Next,
            Err(error) => Attempt::Failed(error.to_string()),
        }
    }

    /// x0x#1321: the JOIN frame goes only to an admitted peer. Wait for an
    /// open plane verdict, at most [`JOIN_SEED_VERDICT_WAIT`].
    async fn gate<A: SeedAdmission + ?Sized>(
        &self,
        admission: &A,
        addr: SocketAddr,
        peer: ant_quic::PeerId,
        shutdown: &CancellationToken,
    ) -> Gate {
        let deadline = Instant::now() + JOIN_SEED_VERDICT_WAIT;
        loop {
            let Some(verdict) = read_admission(admission, &peer, shutdown).await else {
                return Gate::Cancelled;
            };
            match verdict {
                PeerAdmission::Admitted => return Gate::Send,
                PeerAdmission::Suppressed => {
                    tracing::info!(
                        target: "x0x::connect",
                        seed = %addr,
                        "JOIN seed refused by the plane gate; dropped (issue #1321)"
                    );
                    return Gate::Refused;
                }
                PeerAdmission::NotConnected => {
                    tracing::debug!(
                        target: "x0x::connect",
                        seed = %addr,
                        "JOIN seed lost its connection before admission (issue #1321)"
                    );
                    return Gate::Lost;
                }
                PeerAdmission::PlanePending => {
                    let Some(wait) = remaining(deadline) else {
                        tracing::debug!(
                            target: "x0x::connect",
                            seed = %addr,
                            "JOIN seed plane verdict still open (issue #1321)"
                        );
                        return Gate::Unresolved;
                    };
                    if !nap(wait.min(JOIN_SEED_VERDICT_POLL), shutdown).await {
                        return Gate::Cancelled;
                    }
                }
            }
        }
    }

    /// Log the seed plan when it left candidates out.
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
mod tests;
