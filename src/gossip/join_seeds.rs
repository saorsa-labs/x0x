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
//! that predicate. The join keeps the old JOIN recovery behaviour and
//! changes only which peers can be seeds:
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
//! - The JOIN goes first to the admitted candidates. saorsa-gossip's JOIN
//!   retries each of them as before.
//! - If that JOIN does not succeed, [`JoinCandidates::recover_seed`] gives
//!   each other candidate that is not suppressed the retry budget that the
//!   old JOIN gave a seed (saorsa-gossip-membership 0.5.87,
//!   `HyParViewMembership::join`, `src/lib.rs:1639-1705`): up to
//!   [`JOIN_SEED_ATTEMPTS`] attempts, each with the JOIN's own dial
//!   (`GossipTransport::dial_bootstrap`), and after each attempt the JOIN's
//!   backoff (100 ms, doubled after each attempt, at most 30 s, plus the
//!   same jitter). The budget counts attempts, not time: each dial is
//!   awaited, so the recovery cannot end while one of its dials is in
//!   flight. Between attempts the join reads the verdicts again. The first
//!   admitted candidate becomes the seed, whichever path reconnected it. A
//!   candidate is dropped as soon as it is suppressed. The JOIN frame goes
//!   only to an admitted seed. (The old JOIN sent it to any peer whose dial
//!   returned `Ok`.)
//!
//! `join_network` awaits all of this, as it awaited the old JOIN. There is
//! no new time limit for a candidate, and no retry after its budget.
//! The verdict waits, the recovery waits and the recovery dials stop on the
//! shutdown token. `join_network` checks the token before the fallback
//! phases and before each JOIN.
//!
//! None of these steps weakens the plane gate or the #292 dial gates; they
//! only read their verdicts.

use std::net::SocketAddr;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::network::{NetworkNode, PeerAdmission, PLANE_HELLO_RETRY_INTERVAL, PLANE_LEGACY_GRACE};

/// Longest time [`JoinCandidates::settle`] waits for open plane verdicts.
/// After [`PLANE_LEGACY_GRACE`] the plane gate admits a connected peer that
/// never sent a hello (pre-#206 code), so no verdict on a peer connected
/// before the wait starts stays open longer than this; one hello retry
/// interval is margin.
pub(crate) const JOIN_SEED_VERDICT_WAIT: Duration =
    PLANE_LEGACY_GRACE.saturating_add(PLANE_HELLO_RETRY_INTERVAL);

/// Poll interval while plane verdicts are open, and during a recovery
/// backoff.
const JOIN_SEED_VERDICT_POLL: Duration = Duration::from_millis(50);

/// Attempts per seed: `MAX_RETRIES` of saorsa-gossip-membership 0.5.87
/// `HyParViewMembership::join` (`src/lib.rs:1641`).
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

/// The transport operations that the JOIN seed choice uses.
/// [`NetworkNode`] is the production implementation; unit tests script it.
#[async_trait::async_trait]
pub(crate) trait SeedTransport: Send + Sync {
    /// The #292 admission verdict for `peer`.
    async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission;

    /// One seed dial: the dial that saorsa-gossip's JOIN makes
    /// (`GossipTransport::dial_bootstrap`, through the #292 dial gates).
    /// Returns the answered peer, or `None` when the dial failed or was
    /// refused.
    async fn dial_seed(&self, addr: SocketAddr) -> Option<ant_quic::PeerId>;
}

#[async_trait::async_trait]
impl SeedTransport for NetworkNode {
    async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission {
        self.peer_admission(peer).await
    }

    async fn dial_seed(&self, addr: SocketAddr) -> Option<ant_quic::PeerId> {
        match saorsa_gossip_transport::GossipTransport::dial_bootstrap(self, addr).await {
            Ok(peer) => Some(ant_quic::PeerId(peer.to_bytes())),
            Err(e) => {
                tracing::debug!(
                    target: "x0x::connect",
                    %addr,
                    error = %e,
                    "JOIN seed dial failed (issue #1321)"
                );
                None
            }
        }
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

/// What one candidate's retry budget in [`JoinCandidates::recover_seed`]
/// ended with.
enum Recovery {
    /// This candidate address is admitted: the JOIN may use it.
    Seed(SocketAddr),
    /// The candidate was suppressed and is dropped.
    Dropped,
    /// All [`JOIN_SEED_ATTEMPTS`] attempts were used.
    Exhausted,
    /// Shutdown began.
    Cancelled,
}

/// What one verdict read in [`JoinCandidates::recover_seed`] found.
enum Scan {
    /// A candidate in the pool is admitted.
    Seed(SocketAddr),
    /// The current candidate is suppressed (now dropped).
    CurrentDropped,
    /// The current candidate is connected, with its plane verdict open.
    CurrentConnected,
    /// The current candidate has no transport connection.
    CurrentLost,
}

/// Dial results of one `join_network` run, with the answered peer ids.
#[derive(Debug, Default)]
pub(crate) struct JoinCandidates {
    /// Dials that returned `Ok` and are not known to be suppressed, one
    /// record per address (the peer that answered there last).
    connected: Vec<(SocketAddr, ant_quic::PeerId)>,
    /// Addresses whose answered peer was later found suppressed.
    refused: Vec<SocketAddr>,
}

impl JoinCandidates {
    /// Record dials that returned `Ok`, as `(address, answered peer id)`.
    /// A new answer at a known address replaces the old peer id.
    pub(crate) fn extend(
        &mut self,
        dialled: impl IntoIterator<Item = (SocketAddr, ant_quic::PeerId)>,
    ) {
        for (addr, peer) in dialled {
            match self.connected.iter_mut().find(|(known, _)| *known == addr) {
                Some(record) => record.1 = peer,
                None => self.connected.push((addr, peer)),
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

    /// Read the verdict of every record whose address is in `pool` (every
    /// record when `pool` is `None`). Suppressed records move to the
    /// refused set. Returns the kept records with their verdicts.
    async fn read_verdicts<T: SeedTransport + ?Sized>(
        &mut self,
        transport: &T,
        pool: Option<&[SocketAddr]>,
    ) -> Vec<(SocketAddr, ant_quic::PeerId, PeerAdmission)> {
        let mut read = Vec::with_capacity(self.connected.len());
        for (addr, peer) in &self.connected {
            if pool.is_none_or(|pool| pool.contains(addr)) {
                read.push((*addr, *peer, transport.admission(peer).await));
            }
        }
        for (addr, _, verdict) in &read {
            if *verdict == PeerAdmission::Suppressed {
                self.connected.retain(|(known, _)| known != addr);
                self.refused.push(*addr);
            }
        }
        read.retain(|(_, _, verdict)| *verdict != PeerAdmission::Suppressed);
        read
    }

    /// The count for the join's phase decisions: distinct peers that are
    /// still connected and not suppressed (`Admitted` or `PlanePending`).
    /// It reads the verdicts now and does not wait. Suppressed candidates
    /// move to the refused set.
    pub(crate) async fn usable<T: SeedTransport + ?Sized>(&mut self, transport: &T) -> usize {
        let mut usable: Vec<ant_quic::PeerId> = Vec::new();
        for (_, peer, verdict) in self.read_verdicts(transport, None).await {
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
    pub(crate) async fn settle<T: SeedTransport + ?Sized>(
        &self,
        transport: &T,
        target: usize,
        shutdown: &CancellationToken,
    ) -> JoinSeedPlan {
        let started = tokio::time::Instant::now();
        loop {
            let mut verdicts = Vec::with_capacity(self.connected.len());
            for (_, peer) in &self.connected {
                verdicts.push(transport.admission(peer).await);
            }
            let plan = plan_join_seeds(&self.connected, &verdicts);
            if settled(&plan, target, started.elapsed()) || shutdown.is_cancelled() {
                return plan;
            }
            tokio::select! {
                () = tokio::time::sleep(JOIN_SEED_VERDICT_POLL) => {}
                () = shutdown.cancelled() => {}
            }
        }
    }

    /// Find a JOIN seed among the candidates that are not in `tried`, with
    /// the old JOIN's per-seed retry budget (see the module doc).
    ///
    /// The candidates are tried in dial order, one at a time, as the old
    /// JOIN tried its seeds. Returns the first admitted candidate, or
    /// `None` when every candidate was dropped or used its budget, or when
    /// shutdown began.
    pub(crate) async fn recover_seed<T: SeedTransport + ?Sized>(
        &mut self,
        transport: &T,
        tried: &[SocketAddr],
        shutdown: &CancellationToken,
    ) -> Option<SocketAddr> {
        let pool: Vec<SocketAddr> = self
            .connected
            .iter()
            .map(|(addr, _)| *addr)
            .filter(|addr| !tried.contains(addr))
            .collect();
        for addr in &pool {
            if !self.connected.iter().any(|(known, _)| known == addr) {
                // Dropped (suppressed) while an earlier candidate was retried.
                continue;
            }
            match self
                .recover_candidate(transport, *addr, &pool, shutdown)
                .await
            {
                Recovery::Seed(seed) => return Some(seed),
                Recovery::Cancelled => return None,
                Recovery::Dropped | Recovery::Exhausted => {}
            }
        }
        None
    }

    /// One candidate's retry budget: up to [`JOIN_SEED_ATTEMPTS`] attempts,
    /// each a dial when the candidate is not connected, then the JOIN's
    /// backoff while the verdicts are read again.
    async fn recover_candidate<T: SeedTransport + ?Sized>(
        &mut self,
        transport: &T,
        addr: SocketAddr,
        pool: &[SocketAddr],
        shutdown: &CancellationToken,
    ) -> Recovery {
        for attempt in 0..JOIN_SEED_ATTEMPTS {
            if shutdown.is_cancelled() {
                return Recovery::Cancelled;
            }
            match self.scan(transport, addr, pool).await {
                Scan::Seed(seed) => return Recovery::Seed(seed),
                Scan::CurrentDropped => return Recovery::Dropped,
                // Connected with an open verdict: no dial, wait below.
                Scan::CurrentConnected => {}
                Scan::CurrentLost => {
                    let dialled = tokio::select! {
                        dialled = transport.dial_seed(addr) => dialled,
                        () = shutdown.cancelled() => return Recovery::Cancelled,
                    };
                    if let Some(answered) = dialled {
                        self.extend([(addr, answered)]);
                    }
                }
            }
            let delay_ms = join_seed_backoff_ms(attempt);
            let backoff =
                Duration::from_millis(delay_ms.saturating_add(join_seed_jitter_ms(delay_ms)));
            let deadline = tokio::time::Instant::now() + backoff;
            loop {
                match self.scan(transport, addr, pool).await {
                    Scan::Seed(seed) => return Recovery::Seed(seed),
                    Scan::CurrentDropped => return Recovery::Dropped,
                    Scan::CurrentConnected | Scan::CurrentLost => {}
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let nap = deadline.duration_since(now).min(JOIN_SEED_VERDICT_POLL);
                tokio::select! {
                    () = tokio::time::sleep(nap) => {}
                    () = shutdown.cancelled() => return Recovery::Cancelled,
                }
            }
        }
        Recovery::Exhausted
    }

    /// Read the verdicts of the candidates in `pool`; drop the suppressed.
    async fn scan<T: SeedTransport + ?Sized>(
        &mut self,
        transport: &T,
        current: SocketAddr,
        pool: &[SocketAddr],
    ) -> Scan {
        let mut current_state = Scan::CurrentDropped;
        let mut seed = None;
        for (addr, _, verdict) in self.read_verdicts(transport, Some(pool)).await {
            if verdict == PeerAdmission::Admitted && seed.is_none() {
                seed = Some(addr);
            }
            if addr == current {
                current_state = match verdict {
                    PeerAdmission::NotConnected => Scan::CurrentLost,
                    _ => Scan::CurrentConnected,
                };
            }
        }
        match seed {
            Some(seed) => Scan::Seed(seed),
            None => current_state,
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
        /// The dial takes this long, then the peer answers with this
        /// verdict.
        Answer(Duration, ant_quic::PeerId, PeerAdmission),
    }

    #[derive(Default)]
    struct FakeState {
        verdicts: HashMap<ant_quic::PeerId, PeerAdmission>,
        /// Per address: the dial outcomes in order; the last one repeats.
        dial_plan: HashMap<SocketAddr, Vec<FakeDial>>,
        dials: Vec<(SocketAddr, tokio::time::Instant)>,
    }

    /// A scripted [`SeedTransport`] for paused-time tests: verdicts and
    /// dial outcomes are injected, and every dial is recorded.
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

        fn dials_to(&self, target: SocketAddr) -> Vec<tokio::time::Instant> {
            let state = self.state.lock().unwrap();
            state
                .dials
                .iter()
                .filter(|(addr, _)| *addr == target)
                .map(|(_, at)| *at)
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl SeedTransport for FakeTransport {
        async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission {
            let state = self.state.lock().unwrap();
            state
                .verdicts
                .get(peer)
                .copied()
                .unwrap_or(PeerAdmission::NotConnected)
        }

        async fn dial_seed(&self, addr: SocketAddr) -> Option<ant_quic::PeerId> {
            let outcome = {
                let mut state = self.state.lock().unwrap();
                let earlier = state.dials.iter().filter(|(a, _)| *a == addr).count();
                state.dials.push((addr, tokio::time::Instant::now()));
                let plan = state.dial_plan.get(&addr).cloned().unwrap_or_default();
                plan.get(earlier.min(plan.len().saturating_sub(1))).copied()
            };
            match outcome {
                None => None,
                Some(FakeDial::Fail(took)) => {
                    tokio::time::sleep(took).await;
                    None
                }
                Some(FakeDial::Answer(took, answered, verdict)) => {
                    tokio::time::sleep(took).await;
                    self.set(answered, verdict);
                    Some(answered)
                }
            }
        }
    }

    fn candidates(records: &[(SocketAddr, ant_quic::PeerId)]) -> JoinCandidates {
        let mut candidates = JoinCandidates::default();
        candidates.extend(records.iter().copied());
        candidates
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
    fn a_new_answer_at_a_known_address_replaces_the_peer() {
        let mut candidates = candidates(&[(addr(5483), peer(1))]);
        candidates.extend([(addr(5483), peer(2)), (addr(443), peer(3))]);
        assert_eq!(
            candidates.connected,
            vec![(addr(5483), peer(2)), (addr(443), peer(3))]
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
    /// attempts, 81.1 s of backoff before jitter.
    #[test]
    fn backoff_schedule_matches_the_saorsa_gossip_join() {
        let schedule: Vec<u64> = (0..JOIN_SEED_ATTEMPTS).map(join_seed_backoff_ms).collect();
        assert_eq!(
            schedule,
            vec![100, 200, 400, 800, 1600, 3200, 6400, 12_800, 25_600, 30_000]
        );
        assert_eq!(schedule.iter().sum::<u64>(), 81_100);
    }

    #[test]
    fn jitter_stays_within_the_saorsa_gossip_bounds() {
        for _ in 0..1000 {
            for delay in [100, 25_600, 30_000] {
                assert!(join_seed_jitter_ms(delay) <= delay / 8);
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
        let started = tokio::time::Instant::now();
        let plan = candidates.settle(&transport, 3, &shutdown).await;
        assert_eq!(plan.plane_unresolved, 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// Codex re-review of 8a60712, finding 1: slow dials. Nine dials take
    /// 5 s each and fail; the tenth answers. The recovery does not end on a
    /// time limit: it uses all ten attempts, long after the 49.2 s of the
    /// round-2 code.
    #[tokio::test(start_paused = true)]
    async fn recovery_keeps_the_old_attempt_budget_when_dials_are_slow() {
        let transport = FakeTransport::default();
        let slow_fail = FakeDial::Fail(Duration::from_secs(5));
        let mut dials = vec![slow_fail; JOIN_SEED_ATTEMPTS - 1];
        dials.push(FakeDial::Answer(
            Duration::from_secs(5),
            peer(1),
            PeerAdmission::Admitted,
        ));
        transport.plan_dials(addr(1), dials);
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = tokio::time::Instant::now();

        let seed = candidates
            .recover_seed(&transport, &[], &CancellationToken::new())
            .await;

        assert_eq!(seed, Some(addr(1)));
        let dials = transport.dials_to(addr(1));
        assert_eq!(dials.len(), JOIN_SEED_ATTEMPTS);
        // The tenth dial starts after nine 5 s dials and nine backoffs
        // (51.1 s before jitter).
        let tenth = dials[JOIN_SEED_ATTEMPTS - 1].duration_since(started);
        assert!(tenth >= Duration::from_millis(45_000 + 51_100), "{tenth:?}");
        assert!(started.elapsed() > Duration::from_millis(49_200));
    }

    /// A candidate that never comes back uses exactly the old budget: ten
    /// dials and 81.1 s of backoff (plus at most 1/8 jitter), then none.
    #[tokio::test(start_paused = true)]
    async fn recovery_gives_up_after_the_old_budget() {
        let transport = FakeTransport::default();
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        let mut candidates = candidates(&[(addr(1), peer(1))]);
        let started = tokio::time::Instant::now();

        let seed = candidates
            .recover_seed(&transport, &[], &CancellationToken::new())
            .await;

        assert_eq!(seed, None);
        assert_eq!(transport.dials_to(addr(1)).len(), JOIN_SEED_ATTEMPTS);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(81_100), "{elapsed:?}");
        assert!(
            elapsed <= Duration::from_millis(81_100 + 81_100 / 8 + 500),
            "{elapsed:?}"
        );
    }

    /// A candidate is dropped as soon as it is suppressed, and the next one
    /// gets its own budget.
    #[tokio::test(start_paused = true)]
    async fn recovery_drops_a_candidate_as_soon_as_it_is_suppressed() {
        let transport = Arc::new(FakeTransport::default());
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        transport.plan_dials(
            addr(2),
            vec![FakeDial::Answer(
                Duration::ZERO,
                peer(2),
                PeerAdmission::Admitted,
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
        let started = tokio::time::Instant::now();

        let seed = candidates
            .recover_seed(transport.as_ref(), &[], &CancellationToken::new())
            .await;
        refusal.await.unwrap();

        assert_eq!(seed, Some(addr(2)));
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

    /// A connected candidate with an open verdict is not dialled; it
    /// becomes the seed when the plane gate admits it (here after the 10 s
    /// legacy grace).
    #[tokio::test(start_paused = true)]
    async fn recovery_waits_for_an_open_verdict_without_dialling() {
        let transport = Arc::new(FakeTransport::default());
        transport.set(peer(1), PeerAdmission::PlanePending);
        let grace = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                tokio::time::sleep(PLANE_LEGACY_GRACE).await;
                transport.set(peer(1), PeerAdmission::Admitted);
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1))]);

        let seed = candidates
            .recover_seed(transport.as_ref(), &[], &CancellationToken::new())
            .await;
        grace.await.unwrap();

        assert_eq!(seed, Some(addr(1)));
        assert!(transport.dials_to(addr(1)).is_empty());
    }

    /// Another path (the proactive reconnect, an inbound dial) restores a
    /// later candidate while the first one backs off: it becomes the seed
    /// at once.
    #[tokio::test(start_paused = true)]
    async fn recovery_takes_a_candidate_that_another_path_reconnected() {
        let transport = Arc::new(FakeTransport::default());
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        let reconnect = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                transport.set(peer(2), PeerAdmission::Admitted);
            })
        };
        let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
        let started = tokio::time::Instant::now();

        let seed = candidates
            .recover_seed(transport.as_ref(), &[], &CancellationToken::new())
            .await;
        reconnect.await.unwrap();

        assert_eq!(seed, Some(addr(2)));
        assert!(started.elapsed() < Duration::from_secs(3) + JOIN_SEED_VERDICT_POLL * 2);
        assert!(transport.dials_to(addr(2)).is_empty());
    }

    /// Shutdown ends the recovery during a backoff, with no further dial.
    #[tokio::test(start_paused = true)]
    async fn recovery_stops_on_shutdown() {
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
        let started = tokio::time::Instant::now();

        let seed = candidates.recover_seed(&transport, &[], &shutdown).await;
        canceller.await.unwrap();

        assert_eq!(seed, None);
        assert!(started.elapsed() <= Duration::from_secs(5) + JOIN_SEED_VERDICT_POLL);
        let cancelled_at = started + Duration::from_secs(5);
        assert!(transport
            .dials_to(addr(1))
            .iter()
            .all(|at| *at <= cancelled_at));
    }

    /// Shutdown also ends a dial in flight.
    #[tokio::test(start_paused = true)]
    async fn recovery_stops_a_dial_in_flight_on_shutdown() {
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
        let started = tokio::time::Instant::now();

        let seed = candidates.recover_seed(&transport, &[], &shutdown).await;
        canceller.await.unwrap();

        assert_eq!(seed, None);
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }

    /// Codex re-review of 15e6192, finding 1: an exhausted budget is not
    /// renewed. A never answers. B answers and is admitted, but its JOIN
    /// fails, so join_network asks for another seed (the loop below is the
    /// caller's loop). A must still get one budget in total: ten dials.
    #[tokio::test(start_paused = true)]
    async fn an_exhausted_budget_is_not_renewed_after_a_failed_join() {
        let transport = FakeTransport::default();
        transport.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
        transport.plan_dials(
            addr(2),
            vec![FakeDial::Answer(
                Duration::ZERO,
                peer(2),
                PeerAdmission::Admitted,
            )],
        );
        let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
        let shutdown = CancellationToken::new();

        let mut tried = Vec::new();
        while let Some(seed) = candidates.recover_seed(&transport, &tried, &shutdown).await {
            // The JOIN through `seed` fails.
            tried.push(seed);
        }

        assert_eq!(tried, vec![addr(2)]);
        assert_eq!(transport.dials_to(addr(1)).len(), JOIN_SEED_ATTEMPTS);
    }

    /// The candidates the JOIN already tried are not tried again.
    #[tokio::test(start_paused = true)]
    async fn recovery_skips_the_seeds_the_join_already_tried() {
        let transport = FakeTransport::default();
        transport.set(peer(1), PeerAdmission::Admitted);
        let mut candidates = candidates(&[(addr(1), peer(1))]);

        let seed = candidates
            .recover_seed(&transport, &[addr(1)], &CancellationToken::new())
            .await;

        assert_eq!(seed, None);
        assert!(transport.dials_to(addr(1)).is_empty());
    }
}
