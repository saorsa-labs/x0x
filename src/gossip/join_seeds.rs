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
//! that predicate. The join keeps the old JOIN retry budget and changes only
//! which peers can be seeds:
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
//! - [`JoinCandidates::join_overlay`] is the JOIN. It is the loop of
//!   saorsa-gossip-membership 0.5.87 `HyParViewMembership::join`
//!   (`src/lib.rs:1630-1716`), run by x0x attempt by attempt, with the
//!   #292 admission check between the dial and the JOIN frame:
//!   - Each candidate address has one budget of [`JOIN_SEED_ATTEMPTS`]
//!     attempts for the whole `join_network` call. One attempt is one
//!     `GossipTransport::dial_bootstrap`, as in the old JOIN. A candidate
//!     that used its budget is never tried again.
//!   - After a failed dial, the next attempt waits the old backoff: 100 ms,
//!     doubled after each attempt, at most 30 s, plus the same jitter.
//!     Each dial is awaited, so the budget counts dial time.
//!   - After a dial that answered, the JOIN frame goes out only once the
//!     peer is `Admitted`. The wait for that verdict uses the attempt's
//!     backoff time. If the verdict is still open after it, the attempt
//!     failed.
//!   - The JOIN frame and the active-view update are the old JOIN's own
//!     steps, built from the pinned public API: `store_peer_addr`, a
//!     postcard `MembershipProtocolMessage::HyParView(Join { sender, ttl:
//!     ACTIVE_RANDOM_WALK_LENGTH })` sent on the membership stream, and
//!     `Membership::add_active`. A failed send retries at once, as before;
//!     a failed `add_active` ends the JOIN with its error, as before.
//!   - A suppressed candidate is dropped at once, with no attempt.
//!   - An admitted candidate goes first. Otherwise the candidates are tried
//!     in dial order, one after another, as the old JOIN tried its seeds.
//!     A candidate that another one interrupted keeps the attempts it used.
//!
//! `join_network` awaits all of this, as it awaited the old JOIN. There is
//! no new time limit for a candidate and no retry after its budget. The
//! verdict waits, the JOIN dials, the backoffs and the JOIN send stop on
//! the shutdown token. `join_network` checks the token before the fallback
//! phases and before the JOIN.
//!
//! None of these steps weakens the plane gate or the #292 dial gates; they
//! only read their verdicts.

use std::net::SocketAddr;
use std::time::Duration;

use saorsa_gossip_membership::{
    HyParViewMembership, HyParViewMessage, Membership, MembershipProtocolMessage,
    ACTIVE_RANDOM_WALK_LENGTH,
};
use saorsa_gossip_transport::{GossipStreamType, GossipTransport};
use saorsa_gossip_types::PeerId as GossipPeerId;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::network::{NetworkNode, PeerAdmission, PLANE_HELLO_RETRY_INTERVAL, PLANE_LEGACY_GRACE};

/// Longest time [`JoinCandidates::settle`] waits for open plane verdicts.
/// After [`PLANE_LEGACY_GRACE`] the plane gate admits a connected peer that
/// never sent a hello (pre-#206 code), so no verdict on a peer connected
/// before the wait starts stays open longer than this; one hello retry
/// interval is margin.
pub(crate) const JOIN_SEED_VERDICT_WAIT: Duration =
    PLANE_LEGACY_GRACE.saturating_add(PLANE_HELLO_RETRY_INTERVAL);

/// Poll interval while plane verdicts are open, and during a JOIN backoff.
const JOIN_SEED_VERDICT_POLL: Duration = Duration::from_millis(50);

/// Attempts per seed address: `MAX_RETRIES` of saorsa-gossip-membership
/// 0.5.87 `HyParViewMembership::join` (`src/lib.rs:1641`).
pub(crate) const JOIN_SEED_ATTEMPTS: usize = 10;

/// First backoff: `INITIAL_DELAY_MS` (`src/lib.rs:1639`).
const JOIN_SEED_INITIAL_BACKOFF_MS: u64 = 100;

/// Largest backoff: `MAX_DELAY_MS` (`src/lib.rs:1640`).
const JOIN_SEED_MAX_BACKOFF_MS: u64 = 30_000;

/// The backoff after attempt `attempt` (0-based), without jitter: 100 ms,
/// doubled after each attempt, at most 30 s (`src/lib.rs:1704`).
pub(crate) fn join_seed_backoff_ms(attempt: usize) -> u64 {
    let mut delay = JOIN_SEED_INITIAL_BACKOFF_MS;
    for _ in 0..attempt {
        delay = delay.saturating_mul(2).min(JOIN_SEED_MAX_BACKOFF_MS);
    }
    delay
}

/// The JOIN's jitter for a backoff of `delay_ms` (`src/lib.rs:1701-1702`):
/// a random value below `delay_ms / 4`, minus `delay_ms / 8`, at least 0.
fn join_seed_jitter_ms(delay_ms: u64) -> u64 {
    rand::random::<u64>()
        .checked_rem(delay_ms / 4)
        .unwrap_or(0)
        .saturating_sub(delay_ms / 8)
}

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

/// The steps of one old JOIN attempt (saorsa-gossip-membership 0.5.87,
/// `src/lib.rs:1664-1691`). [`OverlayJoin`] is the production
/// implementation; unit tests script it.
#[async_trait::async_trait]
pub(crate) trait SeedJoin: SeedAdmission {
    /// The JOIN's dial, `GossipTransport::dial_bootstrap` (through the #292
    /// dial gates). Returns the answered peer, or the error text.
    async fn dial_seed(&self, addr: SocketAddr) -> Result<ant_quic::PeerId, String>;

    /// Store the seed address and send the JOIN frame to the seed.
    async fn send_join(&self, seed: ant_quic::PeerId, addr: SocketAddr) -> Result<(), String>;

    /// Add the seed to the HyParView active view.
    async fn add_active(&self, seed: ant_quic::PeerId) -> Result<(), String>;
}

#[async_trait::async_trait]
impl SeedAdmission for NetworkNode {
    async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission {
        self.peer_admission(peer).await
    }
}

/// The production [`SeedJoin`]: the node's transport and the HyParView
/// membership of its gossip runtime.
pub(crate) struct OverlayJoin<'a> {
    network: &'a NetworkNode,
    membership: &'a HyParViewMembership<NetworkNode>,
}

impl<'a> OverlayJoin<'a> {
    pub(crate) fn new(
        network: &'a NetworkNode,
        membership: &'a HyParViewMembership<NetworkNode>,
    ) -> Self {
        Self {
            network,
            membership,
        }
    }
}

#[async_trait::async_trait]
impl<'a> SeedAdmission for OverlayJoin<'a> {
    async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission {
        self.network.peer_admission(peer).await
    }
}

#[async_trait::async_trait]
impl<'a> SeedJoin for OverlayJoin<'a> {
    async fn dial_seed(&self, addr: SocketAddr) -> Result<ant_quic::PeerId, String> {
        GossipTransport::dial_bootstrap(self.network, addr)
            .await
            .map(|peer| ant_quic::PeerId(peer.to_bytes()))
            .map_err(|e| e.to_string())
    }

    async fn send_join(&self, seed: ant_quic::PeerId, addr: SocketAddr) -> Result<(), String> {
        let seed = GossipPeerId::new(seed.0);
        // `HyParViewMembership::join` stores the address, then sends a JOIN
        // with this sender and TTL through `send_hyparview_message`, which
        // postcard-encodes it and sends it on the membership stream.
        self.membership.store_peer_addr(seed, addr).await;
        let join = MembershipProtocolMessage::HyParView(HyParViewMessage::Join {
            sender: self.membership.local_peer_id(),
            ttl: ACTIVE_RANDOM_WALK_LENGTH,
        });
        let bytes = postcard::to_stdvec(&join).map_err(|e| e.to_string())?;
        GossipTransport::send_to_peer(
            self.network,
            seed,
            GossipStreamType::Membership,
            bytes.into(),
        )
        .await
        .map_err(|e| e.to_string())
    }

    async fn add_active(&self, seed: ant_quic::PeerId) -> Result<(), String> {
        Membership::add_active(self.membership, GossipPeerId::new(seed.0))
            .await
            .map_err(|e| e.to_string())
    }
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
    /// The active-view update failed. The old JOIN returned this error at
    /// once.
    Failed(String),
    /// Shutdown began.
    Cancelled,
}

/// How one JOIN attempt ended.
enum Attempt {
    /// The budget was updated; choose the next attempt.
    Next,
    Joined(SocketAddr),
    Failed(String),
    Cancelled,
}

/// One candidate: a dial that returned `Ok`, and its JOIN budget.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    addr: SocketAddr,
    /// The peer that answered at `addr` last.
    peer: ant_quic::PeerId,
    /// JOIN attempts used, at most [`JOIN_SEED_ATTEMPTS`].
    attempts: usize,
    /// The next JOIN attempt starts no earlier than this (the old backoff).
    next_attempt: Option<Instant>,
}

/// Dial results of one `join_network` run, with the answered peer ids and
/// the JOIN budget of each address.
#[derive(Debug, Default)]
pub(crate) struct JoinCandidates {
    /// Dials that returned `Ok` and are not known to be suppressed, one
    /// record per address.
    connected: Vec<Candidate>,
    /// Addresses whose answered peer was later found suppressed.
    refused: Vec<SocketAddr>,
}

impl JoinCandidates {
    /// Record dials that returned `Ok`, as `(address, answered peer id)`.
    /// A new answer at a known address replaces the old peer id and keeps
    /// the address's JOIN budget.
    pub(crate) fn extend(
        &mut self,
        dialled: impl IntoIterator<Item = (SocketAddr, ant_quic::PeerId)>,
    ) {
        for (addr, peer) in dialled {
            match self.connected.iter_mut().find(|known| known.addr == addr) {
                Some(record) => record.peer = peer,
                None => self.connected.push(Candidate {
                    addr,
                    peer,
                    attempts: 0,
                    next_attempt: None,
                }),
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
    /// order.
    async fn read_verdicts<T: SeedAdmission + ?Sized>(
        &mut self,
        transport: &T,
        budgeted: bool,
    ) -> Vec<(SocketAddr, ant_quic::PeerId, PeerAdmission)> {
        let mut read = Vec::with_capacity(self.connected.len());
        for candidate in &self.connected {
            if !budgeted || candidate.attempts < JOIN_SEED_ATTEMPTS {
                let verdict = transport.admission(&candidate.peer).await;
                read.push((candidate.addr, candidate.peer, verdict));
            }
        }
        for (addr, _, verdict) in &read {
            if *verdict == PeerAdmission::Suppressed {
                self.drop_candidate(*addr);
            }
        }
        read.retain(|(_, _, verdict)| *verdict != PeerAdmission::Suppressed);
        read
    }

    /// The count for the join's phase decisions: distinct peers that are
    /// still connected and not suppressed (`Admitted` or `PlanePending`).
    /// It reads the verdicts now and does not wait. Suppressed candidates
    /// move to the refused set.
    pub(crate) async fn usable<T: SeedAdmission + ?Sized>(&mut self, transport: &T) -> usize {
        let mut usable: Vec<ant_quic::PeerId> = Vec::new();
        for (_, peer, verdict) in self.read_verdicts(transport, false).await {
            let connected = matches!(
                verdict,
                PeerAdmission::Admitted | PeerAdmission::PlanePending
            );
            if connected && !usable.contains(&peer) {
                usable.push(peer);
            }
        }
        usable.len()
    }

    /// Read the verdicts until [`settled`] for `target`, then keep only the
    /// admitted candidates. Returns early when `shutdown` is cancelled.
    pub(crate) async fn settle<T: SeedAdmission + ?Sized>(
        &self,
        transport: &T,
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
                verdicts.push(transport.admission(peer).await);
            }
            let plan = plan_join_seeds(&records, &verdicts);
            if settled(&plan, target, started.elapsed()) || shutdown.is_cancelled() {
                return plan;
            }
            tokio::select! {
                () = tokio::time::sleep(JOIN_SEED_VERDICT_POLL) => {}
                () = shutdown.cancelled() => {}
            }
        }
    }

    /// The JOIN: the old JOIN loop, attempt by attempt, with one budget of
    /// [`JOIN_SEED_ATTEMPTS`] per address (see the module doc).
    pub(crate) async fn join_overlay<T: SeedJoin + ?Sized>(
        &mut self,
        transport: &T,
        shutdown: &CancellationToken,
    ) -> JoinOutcome {
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
            let live = self.read_verdicts(transport, true).await;
            let pick = live
                .iter()
                .find(|(_, _, verdict)| *verdict == PeerAdmission::Admitted)
                .map(|(addr, _, _)| (*addr, true))
                .or_else(|| live.first().map(|(addr, _, _)| (*addr, false)));
            let Some((addr, admitted)) = pick else {
                // As in the old JOIN, the last failed attempt's backoff
                // ends before the JOIN gives up.
                if let Some(wait) = remaining(gate) {
                    tokio::select! {
                        () = tokio::time::sleep(wait) => {}
                        () = shutdown.cancelled() => return JoinOutcome::Cancelled,
                    }
                }
                return JoinOutcome::NoSeed { attempts };
            };
            let own = self
                .connected
                .iter()
                .find(|known| known.addr == addr)
                .and_then(|known| known.next_attempt);
            let ready_at = match (admitted, own) {
                (true, own) => own,
                (false, own) => Some(own.map_or(gate, |own| own.max(gate))),
            };
            if let Some(wait) = ready_at.and_then(remaining) {
                // Not yet: wait (a little at a time, so that a candidate
                // that becomes admitted can go first).
                tokio::select! {
                    () = tokio::time::sleep(wait.min(JOIN_SEED_VERDICT_POLL)) => {}
                    () = shutdown.cancelled() => return JoinOutcome::Cancelled,
                }
                continue;
            }
            attempts += 1;
            match self.attempt(transport, addr, &mut gate, shutdown).await {
                Attempt::Next => {}
                Attempt::Joined(seed) => return JoinOutcome::Joined(seed),
                Attempt::Failed(error) => return JoinOutcome::Failed(error),
                Attempt::Cancelled => return JoinOutcome::Cancelled,
            }
        }
    }

    /// One old JOIN attempt on `addr` (`src/lib.rs:1657-1705`), with the
    /// admission check between the dial and the JOIN frame.
    async fn attempt<T: SeedJoin + ?Sized>(
        &mut self,
        transport: &T,
        addr: SocketAddr,
        gate: &mut Instant,
        shutdown: &CancellationToken,
    ) -> Attempt {
        let Some(attempt) = self
            .connected
            .iter_mut()
            .find(|known| known.addr == addr)
            .map(|known| {
                known.attempts += 1;
                known.attempts - 1
            })
        else {
            return Attempt::Next;
        };
        let delay_ms = join_seed_backoff_ms(attempt);
        let backoff = Duration::from_millis(delay_ms.saturating_add(join_seed_jitter_ms(delay_ms)));
        tracing::debug!(
            target: "x0x::connect",
            seed = %addr,
            attempt = attempt + 1,
            "JOIN: Connecting to bootstrap node"
        );
        let dialled = tokio::select! {
            dialled = transport.dial_seed(addr) => dialled,
            () = shutdown.cancelled() => return Attempt::Cancelled,
        };
        let peer = match dialled {
            Ok(peer) => peer,
            Err(error) => {
                tracing::warn!(
                    target: "x0x::connect",
                    seed = %addr,
                    attempt = attempt + 1,
                    error = %error,
                    delay_ms,
                    "JOIN: Connection failed, will retry"
                );
                self.back_off(addr, Instant::now() + backoff, gate);
                return Attempt::Next;
            }
        };
        tracing::debug!(
            target: "x0x::connect",
            seed = %addr,
            peer_id_prefix = %crate::network::hex_prefix(&peer.0, 4),
            "JOIN: Connected to bootstrap"
        );
        self.extend([(addr, peer)]);

        // x0x#1321: the JOIN frame goes only to an admitted peer. Wait for
        // the verdict, at most this attempt's backoff.
        let deadline = Instant::now() + backoff;
        loop {
            match transport.admission(&peer).await {
                PeerAdmission::Admitted => break,
                PeerAdmission::Suppressed => {
                    tracing::info!(
                        target: "x0x::connect",
                        seed = %addr,
                        "JOIN seed refused by the plane gate; dropped (issue #1321)"
                    );
                    self.drop_candidate(addr);
                    return Attempt::Next;
                }
                PeerAdmission::PlanePending | PeerAdmission::NotConnected => {
                    let Some(wait) = remaining(deadline) else {
                        tracing::debug!(
                            target: "x0x::connect",
                            seed = %addr,
                            attempt = attempt + 1,
                            "JOIN seed not admitted within the attempt (issue #1321)"
                        );
                        self.back_off(addr, deadline, gate);
                        return Attempt::Next;
                    };
                    tokio::select! {
                        () = tokio::time::sleep(wait.min(JOIN_SEED_VERDICT_POLL)) => {}
                        () = shutdown.cancelled() => return Attempt::Cancelled,
                    }
                }
            }
        }

        if shutdown.is_cancelled() {
            return Attempt::Cancelled;
        }
        let sent = tokio::select! {
            sent = transport.send_join(peer, addr) => sent,
            () = shutdown.cancelled() => return Attempt::Cancelled,
        };
        if let Err(error) = sent {
            // The old JOIN tried again at once, without backoff.
            tracing::warn!(
                target: "x0x::connect",
                seed = %addr,
                error = %error,
                "JOIN: Failed to send JOIN message"
            );
            self.back_off(addr, Instant::now(), gate);
            return Attempt::Next;
        }
        match transport.add_active(peer).await {
            Ok(()) => {
                tracing::debug!(
                    target: "x0x::connect",
                    seed = %addr,
                    "JOIN: Successfully joined network"
                );
                Attempt::Joined(addr)
            }
            Err(error) => Attempt::Failed(error),
        }
    }

    /// The next attempt on `addr` starts no earlier than `at`. When `addr`
    /// has used its budget, the next candidate starts no earlier than `at`.
    fn back_off(&mut self, addr: SocketAddr, at: Instant, gate: &mut Instant) {
        if let Some(known) = self.connected.iter_mut().find(|known| known.addr == addr) {
            known.next_attempt = Some(at);
            if known.attempts >= JOIN_SEED_ATTEMPTS {
                *gate = (*gate).max(at);
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
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

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

    /// One scripted seed dial.
    #[derive(Debug, Clone, Copy)]
    enum FakeDial {
        /// The dial takes this long, then fails.
        Fail(Duration),
        /// The dial takes this long, then this peer answers. With a
        /// verdict, the peer's verdict becomes that (a new connection);
        /// without, it stays as it is (the dial reused a connection).
        Answer(Duration, ant_quic::PeerId, Option<PeerAdmission>),
    }

    /// One scripted JOIN send.
    #[derive(Debug, Clone, Copy)]
    enum FakeSend {
        Sent,
        /// The send fails.
        Fail,
        /// The connection is lost at the send: it fails, and the peer
        /// reads as not connected from now on.
        Lost,
        /// The send takes this long, then succeeds.
        Slow(Duration),
    }

    #[derive(Default)]
    struct FakeState {
        verdicts: HashMap<ant_quic::PeerId, PeerAdmission>,
        /// Per address: the dial outcomes in order; the last one repeats.
        dial_plan: HashMap<SocketAddr, Vec<FakeDial>>,
        /// Per peer: the send outcomes in order; the last one repeats.
        send_plan: HashMap<ant_quic::PeerId, Vec<FakeSend>>,
        add_active_error: Option<String>,
        dials: Vec<(SocketAddr, Instant)>,
        sends: Vec<(ant_quic::PeerId, Instant)>,
        active: Vec<ant_quic::PeerId>,
    }

    /// A scripted [`SeedJoin`] for paused-time tests: verdicts, dial and
    /// send outcomes are injected, and every dial and send is recorded.
    #[derive(Default)]
    struct FakeTransport {
        state: Mutex<FakeState>,
    }

    impl FakeTransport {
        fn set(&self, peer: ant_quic::PeerId, verdict: PeerAdmission) {
            self.state.lock().unwrap().verdicts.insert(peer, verdict);
        }

        fn plan_dials(&self, addr: SocketAddr, dials: Vec<FakeDial>) {
            self.state.lock().unwrap().dial_plan.insert(addr, dials);
        }

        fn plan_sends(&self, peer: ant_quic::PeerId, sends: Vec<FakeSend>) {
            self.state.lock().unwrap().send_plan.insert(peer, sends);
        }

        fn dials_to(&self, target: SocketAddr) -> Vec<Instant> {
            let state = self.state.lock().unwrap();
            state
                .dials
                .iter()
                .filter(|(addr, _)| *addr == target)
                .map(|(_, at)| *at)
                .collect()
        }

        fn sends_to(&self, target: ant_quic::PeerId) -> usize {
            let state = self.state.lock().unwrap();
            state
                .sends
                .iter()
                .filter(|(peer, _)| *peer == target)
                .count()
        }

        fn active(&self) -> Vec<ant_quic::PeerId> {
            self.state.lock().unwrap().active.clone()
        }
    }

    fn next<T: Copy>(plan: Option<&Vec<T>>, earlier: usize) -> Option<T> {
        let plan = plan?;
        plan.get(earlier.min(plan.len().saturating_sub(1))).copied()
    }

    #[async_trait::async_trait]
    impl SeedAdmission for FakeTransport {
        async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission {
            let state = self.state.lock().unwrap();
            state
                .verdicts
                .get(peer)
                .copied()
                .unwrap_or(PeerAdmission::NotConnected)
        }
    }

    #[async_trait::async_trait]
    impl SeedJoin for FakeTransport {
        async fn dial_seed(&self, addr: SocketAddr) -> Result<ant_quic::PeerId, String> {
            let outcome = {
                let mut state = self.state.lock().unwrap();
                let earlier = state.dials.iter().filter(|(a, _)| *a == addr).count();
                state.dials.push((addr, Instant::now()));
                next(state.dial_plan.get(&addr), earlier)
            };
            match outcome {
                None => Err("no route".to_string()),
                Some(FakeDial::Fail(took)) => {
                    tokio::time::sleep(took).await;
                    Err("dial failed".to_string())
                }
                Some(FakeDial::Answer(took, answered, verdict)) => {
                    tokio::time::sleep(took).await;
                    if let Some(verdict) = verdict {
                        self.set(answered, verdict);
                    }
                    Ok(answered)
                }
            }
        }

        async fn send_join(&self, seed: ant_quic::PeerId, _addr: SocketAddr) -> Result<(), String> {
            let outcome = {
                let mut state = self.state.lock().unwrap();
                let earlier = state.sends.iter().filter(|(p, _)| *p == seed).count();
                state.sends.push((seed, Instant::now()));
                next(state.send_plan.get(&seed), earlier).unwrap_or(FakeSend::Sent)
            };
            match outcome {
                FakeSend::Sent => Ok(()),
                FakeSend::Fail => Err("send failed".to_string()),
                FakeSend::Lost => {
                    self.set(seed, PeerAdmission::NotConnected);
                    Err("peer not connected".to_string())
                }
                FakeSend::Slow(took) => {
                    tokio::time::sleep(took).await;
                    Ok(())
                }
            }
        }

        async fn add_active(&self, seed: ant_quic::PeerId) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            if let Some(error) = state.add_active_error.clone() {
                return Err(error);
            }
            state.active.push(seed);
            Ok(())
        }
    }

    fn candidates(records: &[(SocketAddr, ant_quic::PeerId)]) -> JoinCandidates {
        let mut candidates = JoinCandidates::default();
        candidates.extend(records.iter().copied());
        candidates
    }

    /// The old JOIN's backoff before jitter for `attempts` failed attempts.
    fn backoff_ms(attempts: usize) -> u64 {
        (0..attempts).map(join_seed_backoff_ms).sum()
    }

    /// The largest jitter the old JOIN adds over `attempts` failed attempts.
    fn max_jitter_ms(attempts: usize) -> u64 {
        (0..attempts)
            .map(|attempt| {
                let delay = join_seed_backoff_ms(attempt);
                (delay / 4).saturating_sub(1).saturating_sub(delay / 8)
            })
            .sum()
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

    #[test]
    fn a_new_answer_at_a_known_address_replaces_the_peer_and_keeps_the_budget() {
        let mut candidates = candidates(&[(addr(5483), peer(1))]);
        candidates.connected[0].attempts = 4;
        candidates.extend([(addr(5483), peer(2)), (addr(443), peer(3))]);
        let records: Vec<(SocketAddr, ant_quic::PeerId, usize)> = candidates
            .connected
            .iter()
            .map(|c| (c.addr, c.peer, c.attempts))
            .collect();
        assert_eq!(
            records,
            vec![(addr(5483), peer(2), 4), (addr(443), peer(3), 0)]
        );
    }

    /// Codex round-1 finding 2: open verdicts below the target are waited
    /// for, so a later refusal still leads to the phase fallback.
    #[test]
    fn settle_waits_for_open_verdicts_below_the_target() {
        let zero = Duration::ZERO;
        assert!(!settled(&plan(0, 3, 0), 3, zero));
        assert!(!settled(&plan(2, 1, 0), 3, zero));
        // The refusals landed: nothing open, below the target. The join
        // reads this as "fall back".
        assert!(settled(&plan(0, 0, 0), 3, zero));
        assert!(settled(&plan(3, 2, 0), 3, zero));
        // A lost connection does not hold the phase decision.
        assert!(settled(&plan(0, 0, 2), 3, zero));
        assert!(settled(&plan(0, 3, 0), 3, JOIN_SEED_VERDICT_WAIT));
    }

    #[test]
    fn verdict_wait_covers_the_plane_legacy_grace() {
        assert!(JOIN_SEED_VERDICT_WAIT > PLANE_LEGACY_GRACE);
    }

    /// The schedule is the one in saorsa-gossip-membership 0.5.87
    /// `HyParViewMembership::join`: 100 ms doubling to at most 30 s, ten
    /// attempts, 81.1 s of backoff before jitter, and at most 10 128 ms of
    /// jitter in total.
    #[test]
    fn backoff_schedule_matches_the_saorsa_gossip_join() {
        let schedule: Vec<u64> = (0..JOIN_SEED_ATTEMPTS).map(join_seed_backoff_ms).collect();
        assert_eq!(
            schedule,
            vec![100, 200, 400, 800, 1600, 3200, 6400, 12_800, 25_600, 30_000]
        );
        assert_eq!(backoff_ms(JOIN_SEED_ATTEMPTS), 81_100);
        assert_eq!(max_jitter_ms(JOIN_SEED_ATTEMPTS), 10_128);
    }

    #[test]
    fn jitter_stays_within_the_saorsa_gossip_bounds() {
        for _ in 0..1000 {
            for delay in [100, 25_600, 30_000] {
                assert!(join_seed_jitter_ms(delay) < delay / 4 - delay / 8);
            }
        }
        assert_eq!(join_seed_jitter_ms(0), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn settle_ends_at_once_on_shutdown() {
        let transport = FakeTransport::default();
        transport.set(peer(1), PeerAdmission::PlanePending);
        let candidates = candidates(&[(addr(1), peer(1))]);
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let started = Instant::now();
        let plan = candidates.settle(&transport, 3, &shutdown).await;
        assert_eq!(plan.plane_unresolved, 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn an_admitted_seed_joins_in_one_attempt() {
        let transport = FakeTransport::default();
        transport.set(peer(1), PeerAdmission::Admitted);
        transport.plan_dials(
            addr(1),
            vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
        );
        let mut candidates = candidates(&[(addr(1), peer(1))]);

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
        assert_eq!(transport.dials_to(addr(1)).len(), 1);
        assert_eq!(transport.sends_to(peer(1)), 1);
        assert_eq!(transport.active(), vec![peer(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn no_candidate_means_no_join_attempt() {
        let transport = FakeTransport::default();
        let mut candidates = JoinCandidates::default();
        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;
        assert_eq!(outcome, JoinOutcome::NoSeed { attempts: 0 });
    }

    /// A suppressed candidate is dropped before any attempt (the #1321 fix:
    /// the old JOIN spent ten refused dials on it).
    #[tokio::test(start_paused = true)]
    async fn a_suppressed_candidate_gets_no_attempt() {
        let transport = FakeTransport::default();
        transport.set(peer(1), PeerAdmission::Suppressed);
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;
        assert_eq!(outcome, JoinOutcome::NoSeed { attempts: 0 });
        assert!(transport.dials_to(addr(1)).is_empty());
        assert!(candidates.refused.contains(&addr(1)));
    }

    /// Codex re-review of 8a60712, finding 1: slow dials. Nine dials take
    /// 5 s each and fail; the tenth answers. There is no time limit: the
    /// JOIN uses all ten attempts, long after the 49.2 s of round 2.
    #[tokio::test(start_paused = true)]
    async fn slow_dials_keep_the_old_attempt_budget() {
        let transport = FakeTransport::default();
        let mut dials = vec![FakeDial::Fail(Duration::from_secs(5)); JOIN_SEED_ATTEMPTS - 1];
        dials.push(FakeDial::Answer(
            Duration::from_secs(5),
            peer(1),
            Some(PeerAdmission::Admitted),
        ));
        transport.plan_dials(addr(1), dials);
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = Instant::now();

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
        let dials = transport.dials_to(addr(1));
        assert_eq!(dials.len(), JOIN_SEED_ATTEMPTS);
        // The tenth dial starts after nine 5 s dials and nine backoffs.
        let tenth = dials[JOIN_SEED_ATTEMPTS - 1].duration_since(started);
        let floor = Duration::from_millis(45_000 + backoff_ms(JOIN_SEED_ATTEMPTS - 1));
        assert!(tenth >= floor, "{tenth:?}");
    }

    /// A candidate that never answers uses exactly the old budget: ten
    /// dials and ten backoffs (81.1 s plus at most 10.128 s of jitter),
    /// then the JOIN gives up.
    #[tokio::test(start_paused = true)]
    async fn the_join_gives_up_after_the_old_budget() {
        let transport = FakeTransport::default();
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = Instant::now();

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert_eq!(
            outcome,
            JoinOutcome::NoSeed {
                attempts: JOIN_SEED_ATTEMPTS
            }
        );
        assert_eq!(transport.dials_to(addr(1)).len(), JOIN_SEED_ATTEMPTS);
        let elapsed = started.elapsed();
        let base = backoff_ms(JOIN_SEED_ATTEMPTS);
        assert!(elapsed >= Duration::from_millis(base), "{elapsed:?}");
        assert!(
            elapsed <= Duration::from_millis(base + max_jitter_ms(JOIN_SEED_ATTEMPTS) + 100),
            "{elapsed:?}"
        );
    }

    /// Codex re-review of 15e6192, finding 1: an exhausted budget is not
    /// renewed. A never answers. B answers and is admitted, but every JOIN
    /// send through it fails. Each address gets one budget in total: ten
    /// attempts.
    #[tokio::test(start_paused = true)]
    async fn an_exhausted_budget_is_not_renewed_after_a_failed_join() {
        let transport = FakeTransport::default();
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        transport.plan_dials(
            addr(2),
            vec![FakeDial::Answer(
                Duration::ZERO,
                peer(2),
                Some(PeerAdmission::Admitted),
            )],
        );
        transport.plan_sends(peer(2), vec![FakeSend::Fail]);
        let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert_eq!(
            outcome,
            JoinOutcome::NoSeed {
                attempts: 2 * JOIN_SEED_ATTEMPTS
            }
        );
        assert_eq!(transport.dials_to(addr(1)).len(), JOIN_SEED_ATTEMPTS);
        assert_eq!(transport.dials_to(addr(2)).len(), JOIN_SEED_ATTEMPTS);
        assert_eq!(transport.sends_to(peer(2)), JOIN_SEED_ATTEMPTS);
    }

    /// The same, when B interrupts A: B becomes admitted by another path
    /// (the proactive reconnect) while A backs off. B gets its attempts;
    /// then A continues with the attempts it has left, not a new budget.
    #[tokio::test(start_paused = true)]
    async fn an_interrupted_budget_continues_where_it_stopped() {
        let transport = Arc::new(FakeTransport::default());
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        transport.plan_dials(
            addr(2),
            vec![FakeDial::Answer(Duration::ZERO, peer(2), None)],
        );
        transport.plan_sends(peer(2), vec![FakeSend::Fail]);
        let reconnect = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                transport.set(peer(2), PeerAdmission::Admitted);
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
        let started = Instant::now();

        let outcome = candidates
            .join_overlay(transport.as_ref(), &CancellationToken::new())
            .await;
        reconnect.await.unwrap();

        assert!(matches!(outcome, JoinOutcome::NoSeed { .. }), "{outcome:?}");
        let first = transport.dials_to(addr(1));
        assert_eq!(first.len(), JOIN_SEED_ATTEMPTS);
        let second = transport.dials_to(addr(2));
        assert_eq!(second.len(), JOIN_SEED_ATTEMPTS);
        // A was interrupted: some of its attempts came before B's, the rest
        // after.
        let interrupted_at = started + Duration::from_secs(2);
        assert!(first.iter().any(|at| *at < interrupted_at));
        assert!(first.iter().any(|at| *at > second[0]));
    }

    /// Codex re-review of 15e6192, finding 2: the recovery and the JOIN
    /// share one budget. Nine dials fail; the tenth answers and the peer is
    /// admitted; then the connection is lost at the JOIN send. There is no
    /// second budget: the JOIN ends after the ten attempts.
    #[tokio::test(start_paused = true)]
    async fn a_seed_lost_at_the_join_handoff_keeps_one_budget() {
        let transport = FakeTransport::default();
        let mut dials = vec![FakeDial::Fail(Duration::ZERO); JOIN_SEED_ATTEMPTS - 1];
        dials.push(FakeDial::Answer(
            Duration::ZERO,
            peer(1),
            Some(PeerAdmission::Admitted),
        ));
        transport.plan_dials(addr(1), dials);
        transport.plan_sends(peer(1), vec![FakeSend::Lost]);
        let mut candidates = candidates(&[(addr(1), peer(1))]);

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert_eq!(
            outcome,
            JoinOutcome::NoSeed {
                attempts: JOIN_SEED_ATTEMPTS
            }
        );
        assert_eq!(transport.dials_to(addr(1)).len(), JOIN_SEED_ATTEMPTS);
        assert_eq!(transport.sends_to(peer(1)), 1);
        assert!(transport.active().is_empty());
    }

    /// The handoff loss earlier: the first dial answers, the send loses the
    /// connection, and the later dials fail. Still ten attempts in total.
    #[tokio::test(start_paused = true)]
    async fn an_early_handoff_loss_keeps_one_budget() {
        let transport = FakeTransport::default();
        transport.plan_dials(
            addr(1),
            vec![
                FakeDial::Answer(Duration::ZERO, peer(1), Some(PeerAdmission::Admitted)),
                FakeDial::Fail(Duration::ZERO),
            ],
        );
        transport.plan_sends(peer(1), vec![FakeSend::Lost]);
        let mut candidates = candidates(&[(addr(1), peer(1))]);

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert!(matches!(outcome, JoinOutcome::NoSeed { .. }), "{outcome:?}");
        assert_eq!(transport.dials_to(addr(1)).len(), JOIN_SEED_ATTEMPTS);
        assert_eq!(transport.sends_to(peer(1)), 1);
    }

    /// As in the old JOIN, a failed send is retried at once, without
    /// backoff, within the same budget.
    #[tokio::test(start_paused = true)]
    async fn a_failed_send_is_retried_at_once() {
        let transport = FakeTransport::default();
        transport.set(peer(1), PeerAdmission::Admitted);
        transport.plan_dials(
            addr(1),
            vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
        );
        transport.plan_sends(peer(1), vec![FakeSend::Fail, FakeSend::Sent]);
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = Instant::now();

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
        assert_eq!(transport.dials_to(addr(1)).len(), 2);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// As in the old JOIN, a failed active-view update ends the JOIN.
    #[tokio::test(start_paused = true)]
    async fn a_failed_add_active_ends_the_join() {
        let transport = FakeTransport::default();
        transport.set(peer(1), PeerAdmission::Admitted);
        transport.plan_dials(
            addr(1),
            vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
        );
        transport.state.lock().unwrap().add_active_error = Some("view".to_string());
        let mut candidates = candidates(&[(addr(1), peer(1))]);

        let outcome = candidates
            .join_overlay(&transport, &CancellationToken::new())
            .await;

        assert_eq!(outcome, JoinOutcome::Failed("view".to_string()));
    }

    /// A candidate is dropped as soon as it is suppressed, and the next one
    /// gets its own budget.
    #[tokio::test(start_paused = true)]
    async fn a_candidate_is_dropped_as_soon_as_it_is_suppressed() {
        let transport = Arc::new(FakeTransport::default());
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        transport.plan_dials(
            addr(2),
            vec![FakeDial::Answer(
                Duration::ZERO,
                peer(2),
                Some(PeerAdmission::Admitted),
            )],
        );
        let refusal = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                transport.set(peer(1), PeerAdmission::Suppressed);
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
        let started = Instant::now();

        let outcome = candidates
            .join_overlay(transport.as_ref(), &CancellationToken::new())
            .await;
        refusal.await.unwrap();

        assert_eq!(outcome, JoinOutcome::Joined(addr(2)));
        let suppressed_at = started + Duration::from_secs(2);
        assert!(transport
            .dials_to(addr(1))
            .iter()
            .all(|at| *at < suppressed_at));
        let second = transport.dials_to(addr(2));
        assert_eq!(second.len(), 1);
        assert!(second[0] <= suppressed_at + JOIN_SEED_VERDICT_POLL);
        assert!(candidates.refused.contains(&addr(1)));
    }

    /// A connected candidate with an open verdict gets the JOIN frame only
    /// when the plane gate admits it (here after the 10 s legacy grace),
    /// within its budget.
    #[tokio::test(start_paused = true)]
    async fn an_open_verdict_gets_the_join_only_when_admitted() {
        let transport = Arc::new(FakeTransport::default());
        transport.set(peer(1), PeerAdmission::PlanePending);
        transport.plan_dials(
            addr(1),
            vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
        );
        let grace = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                tokio::time::sleep(PLANE_LEGACY_GRACE).await;
                transport.set(peer(1), PeerAdmission::Admitted);
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = Instant::now();

        let outcome = candidates
            .join_overlay(transport.as_ref(), &CancellationToken::new())
            .await;
        grace.await.unwrap();

        assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
        assert!(started.elapsed() >= PLANE_LEGACY_GRACE);
        assert!(transport.dials_to(addr(1)).len() <= JOIN_SEED_ATTEMPTS);
        assert_eq!(transport.sends_to(peer(1)), 1);
    }

    /// Another path (the proactive reconnect, an inbound dial) restores a
    /// later candidate while the first one backs off: it goes first.
    #[tokio::test(start_paused = true)]
    async fn a_candidate_that_another_path_reconnected_goes_first() {
        let transport = Arc::new(FakeTransport::default());
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        transport.plan_dials(
            addr(2),
            vec![FakeDial::Answer(Duration::ZERO, peer(2), None)],
        );
        let reconnect = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                transport.set(peer(2), PeerAdmission::Admitted);
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
        let started = Instant::now();

        let outcome = candidates
            .join_overlay(transport.as_ref(), &CancellationToken::new())
            .await;
        reconnect.await.unwrap();

        assert_eq!(outcome, JoinOutcome::Joined(addr(2)));
        assert!(started.elapsed() < Duration::from_secs(3) + JOIN_SEED_VERDICT_POLL * 2);
        assert_eq!(transport.dials_to(addr(2)).len(), 1);
        assert!(transport.dials_to(addr(1)).len() < JOIN_SEED_ATTEMPTS);
    }

    /// Shutdown ends the JOIN during a backoff, with no further dial.
    #[tokio::test(start_paused = true)]
    async fn the_join_stops_on_shutdown_during_a_backoff() {
        let transport = FakeTransport::default();
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        let shutdown = CancellationToken::new();
        let canceller = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                shutdown.cancel();
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = Instant::now();

        let outcome = candidates.join_overlay(&transport, &shutdown).await;
        canceller.await.unwrap();

        assert_eq!(outcome, JoinOutcome::Cancelled);
        assert!(started.elapsed() <= Duration::from_secs(5) + JOIN_SEED_VERDICT_POLL);
        let cancelled_at = started + Duration::from_secs(5);
        assert!(transport
            .dials_to(addr(1))
            .iter()
            .all(|at| *at <= cancelled_at));
    }

    /// Shutdown also ends a JOIN dial in flight.
    #[tokio::test(start_paused = true)]
    async fn the_join_stops_a_dial_in_flight_on_shutdown() {
        let transport = FakeTransport::default();
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::from_secs(60))]);
        let shutdown = CancellationToken::new();
        let canceller = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                shutdown.cancel();
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = Instant::now();

        let outcome = candidates.join_overlay(&transport, &shutdown).await;
        canceller.await.unwrap();

        assert_eq!(outcome, JoinOutcome::Cancelled);
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }

    /// Shutdown also ends a JOIN send in flight; the seed is not added to
    /// the active view.
    #[tokio::test(start_paused = true)]
    async fn the_join_stops_a_send_in_flight_on_shutdown() {
        let transport = FakeTransport::default();
        transport.set(peer(1), PeerAdmission::Admitted);
        transport.plan_dials(
            addr(1),
            vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
        );
        transport.plan_sends(peer(1), vec![FakeSend::Slow(Duration::from_secs(60))]);
        let shutdown = CancellationToken::new();
        let canceller = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                shutdown.cancel();
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = Instant::now();

        let outcome = candidates.join_overlay(&transport, &shutdown).await;
        canceller.await.unwrap();

        assert_eq!(outcome, JoinOutcome::Cancelled);
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert!(transport.active().is_empty());
    }
}
