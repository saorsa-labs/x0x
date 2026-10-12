//! Unit tests for the JOIN seed choice. They run the real saorsa-gossip
//! `HyParViewMembership` (its step API, ledger, frame and side effects)
//! over a scripted transport that also supplies the admission verdicts.
//! Paused time, no sockets.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use saorsa_gossip_membership::{
    HyParViewMessage, Membership, MembershipConfig, MembershipProtocolMessage, JOIN_MAX_ATTEMPTS,
};
use saorsa_gossip_transport::GossipStreamType;
use saorsa_gossip_types::PeerId as GossipPeerId;

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
    /// The dial takes this long, then this peer answers. With a verdict,
    /// the peer's verdict becomes that (a new connection); without, it stays
    /// as it is (the dial reused a connection).
    Answer(Duration, ant_quic::PeerId, Option<PeerAdmission>),
}

/// One scripted JOIN send.
#[derive(Debug, Clone, Copy)]
enum FakeSend {
    Sent,
    /// The send fails.
    Fail,
    /// The connection is lost at the send: it fails, and the peer reads as
    /// not connected from now on.
    Lost,
    /// The send takes this long, then succeeds.
    Slow(Duration),
}

#[derive(Default)]
struct FakeState {
    verdicts: HashMap<ant_quic::PeerId, PeerAdmission>,
    /// Per address: the dial outcomes in order; the last one repeats.
    dial_plan: HashMap<SocketAddr, Vec<FakeDial>>,
    /// Per peer: the JOIN send outcomes in order; the last one repeats.
    send_plan: HashMap<ant_quic::PeerId, Vec<FakeSend>>,
    dials: Vec<(SocketAddr, Instant)>,
    join_sends: Vec<(ant_quic::PeerId, Instant)>,
    /// Admission reads made so far.
    reads: usize,
    /// After this many reads, each admission read takes this long.
    slow_reads_after: Option<(usize, Duration)>,
}

/// A scripted saorsa-gossip transport that is also the admission source.
/// It records every `dial_bootstrap` and every JOIN send. Other frames
/// (SWIM probes, shuffles from the membership's background tasks) are
/// accepted and not recorded.
#[derive(Default)]
struct Fake {
    state: Mutex<FakeState>,
}

impl Fake {
    fn set(&self, peer: ant_quic::PeerId, verdict: PeerAdmission) {
        self.state.lock().unwrap().verdicts.insert(peer, verdict);
    }

    fn plan_dials(&self, addr: SocketAddr, dials: Vec<FakeDial>) {
        self.state.lock().unwrap().dial_plan.insert(addr, dials);
    }

    fn plan_sends(&self, peer: ant_quic::PeerId, sends: Vec<FakeSend>) {
        self.state.lock().unwrap().send_plan.insert(peer, sends);
    }

    /// After `reads` fast admission reads, each read takes `took`.
    fn slow_reads_after(&self, reads: usize, took: Duration) {
        self.state.lock().unwrap().slow_reads_after = Some((reads, took));
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
            .join_sends
            .iter()
            .filter(|(peer, _)| *peer == target)
            .count()
    }
}

fn next<T: Copy>(plan: Option<&Vec<T>>, earlier: usize) -> Option<T> {
    let plan = plan?;
    plan.get(earlier.min(plan.len().saturating_sub(1))).copied()
}

fn is_join_frame(data: &[u8]) -> bool {
    matches!(
        postcard::from_bytes::<MembershipProtocolMessage>(data),
        Ok(MembershipProtocolMessage::HyParView(
            HyParViewMessage::Join { .. }
        ))
    )
}

#[async_trait::async_trait]
impl SeedAdmission for Fake {
    async fn admission(&self, peer: &ant_quic::PeerId) -> PeerAdmission {
        let slow = {
            let mut state = self.state.lock().unwrap();
            state.reads += 1;
            state
                .slow_reads_after
                .filter(|(fast, _)| state.reads > *fast)
                .map(|(_, took)| took)
        };
        if let Some(took) = slow {
            tokio::time::sleep(took).await;
        }
        let state = self.state.lock().unwrap();
        state
            .verdicts
            .get(peer)
            .copied()
            .unwrap_or(PeerAdmission::NotConnected)
    }
}

#[async_trait::async_trait]
impl GossipTransport for Fake {
    async fn dial(&self, _peer: GossipPeerId, _addr: SocketAddr) -> anyhow::Result<()> {
        Ok(())
    }

    async fn dial_bootstrap(&self, addr: SocketAddr) -> anyhow::Result<GossipPeerId> {
        let outcome = {
            let mut state = self.state.lock().unwrap();
            let earlier = state.dials.iter().filter(|(a, _)| *a == addr).count();
            state.dials.push((addr, Instant::now()));
            next(state.dial_plan.get(&addr), earlier)
        };
        match outcome {
            None => Err(anyhow::anyhow!("no route")),
            Some(FakeDial::Fail(took)) => {
                tokio::time::sleep(took).await;
                Err(anyhow::anyhow!("dial failed"))
            }
            Some(FakeDial::Answer(took, answered, verdict)) => {
                tokio::time::sleep(took).await;
                if let Some(verdict) = verdict {
                    self.set(answered, verdict);
                }
                Ok(GossipPeerId::new(answered.0))
            }
        }
    }

    async fn listen(&self, _bind: SocketAddr) -> anyhow::Result<()> {
        Ok(())
    }

    async fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn send_to_peer(
        &self,
        peer: GossipPeerId,
        _stream_type: GossipStreamType,
        data: Bytes,
    ) -> anyhow::Result<()> {
        if !is_join_frame(&data) {
            return Ok(());
        }
        let seed = ant_quic::PeerId(peer.to_bytes());
        let outcome = {
            let mut state = self.state.lock().unwrap();
            let earlier = state.join_sends.iter().filter(|(p, _)| *p == seed).count();
            state.join_sends.push((seed, Instant::now()));
            next(state.send_plan.get(&seed), earlier).unwrap_or(FakeSend::Sent)
        };
        match outcome {
            FakeSend::Sent => Ok(()),
            FakeSend::Fail => Err(anyhow::anyhow!("send failed")),
            FakeSend::Lost => {
                self.set(seed, PeerAdmission::NotConnected);
                Err(anyhow::anyhow!("peer not connected"))
            }
            FakeSend::Slow(took) => {
                tokio::time::sleep(took).await;
                Ok(())
            }
        }
    }

    async fn receive_message(&self) -> anyhow::Result<(GossipPeerId, GossipStreamType, Bytes)> {
        Err(anyhow::anyhow!("fake transport has no receive queue"))
    }

    fn local_peer_id(&self) -> GossipPeerId {
        GossipPeerId::new([0xEE; 32])
    }
}

fn fake() -> Arc<Fake> {
    Arc::new(Fake::default())
}

fn membership(fake: &Arc<Fake>) -> HyParViewMembership<Fake> {
    HyParViewMembership::new(
        GossipPeerId::new([0xEE; 32]),
        MembershipConfig::default(),
        Arc::clone(fake),
    )
}

fn active(membership: &HyParViewMembership<Fake>) -> Vec<ant_quic::PeerId> {
    membership
        .active_view()
        .into_iter()
        .map(|peer| ant_quic::PeerId(peer.to_bytes()))
        .collect()
}

fn candidates(records: &[(SocketAddr, ant_quic::PeerId)]) -> JoinCandidates {
    let mut candidates = JoinCandidates::default();
    candidates.extend(records.iter().copied());
    candidates
}

async fn join(
    candidates: &mut JoinCandidates,
    fake: &Arc<Fake>,
    membership: &HyParViewMembership<Fake>,
    shutdown: &CancellationToken,
) -> JoinOutcome {
    candidates
        .join_overlay(membership, fake.as_ref(), shutdown)
        .await
}

/// The 0.5.87 JOIN backoff (before jitter) after `attempts` failed dials.
fn backoff_ms(attempts: usize) -> u64 {
    let mut delay = 100_u64;
    let mut total = 0;
    for _ in 0..attempts {
        total += delay;
        delay = (delay * 2).min(30_000);
    }
    total
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
    let records: Vec<(SocketAddr, ant_quic::PeerId)> = candidates
        .connected
        .iter()
        .map(|c| (c.addr, c.peer))
        .collect();
    assert_eq!(records, vec![(addr(5483), peer(2)), (addr(443), peer(3))]);
}

/// Codex round-1 finding 2: open verdicts below the target are waited for,
/// so a later refusal still leads to the phase fallback.
#[test]
fn settle_waits_for_open_verdicts_below_the_target() {
    let zero = Duration::ZERO;
    assert!(!settled(&plan(0, 3, 0), 3, zero));
    assert!(!settled(&plan(2, 1, 0), 3, zero));
    // The refusals landed: nothing open, below the target. The join reads
    // this as "fall back".
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

#[tokio::test(start_paused = true)]
async fn settle_ends_at_once_on_shutdown() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::PlanePending);
    let candidates = candidates(&[(addr(1), peer(1))]);
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let started = Instant::now();
    let plan = candidates.settle(fake.as_ref(), 3, &shutdown).await;
    // A cancelled settlement reports no seed, and reads nothing.
    assert_eq!(plan, JoinSeedPlan::default());
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn an_admitted_seed_joins_in_one_attempt() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::Admitted);
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
    );
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
    assert_eq!(fake.dials_to(addr(1)).len(), 1);
    assert_eq!(fake.sends_to(peer(1)), 1);
    assert_eq!(active(&membership), vec![peer(1)]);
    assert_eq!(
        membership
            .get_peer_addr(&GossipPeerId::new(peer(1).0))
            .await,
        Some(addr(1))
    );
}

#[tokio::test(start_paused = true)]
async fn no_candidate_means_no_join_attempt() {
    let fake = fake();
    let membership = membership(&fake);
    let mut candidates = JoinCandidates::default();
    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(outcome, JoinOutcome::NoSeed { attempts: 0 });
}

/// A suppressed candidate is dropped before any attempt (the #1321 fix: the
/// old JOIN spent ten refused dials on it).
#[tokio::test(start_paused = true)]
async fn a_suppressed_candidate_gets_no_attempt() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::Suppressed);
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(outcome, JoinOutcome::NoSeed { attempts: 0 });
    assert!(fake.dials_to(addr(1)).is_empty());
    assert!(candidates.refused.contains(&addr(1)));
}

/// Slow dials: nine dials take 5 s each and fail; the tenth answers. There
/// is no time limit: the JOIN uses all ten attempts.
#[tokio::test(start_paused = true)]
async fn slow_dials_keep_the_old_attempt_budget() {
    let fake = fake();
    let mut dials = vec![FakeDial::Fail(Duration::from_secs(5)); JOIN_MAX_ATTEMPTS - 1];
    dials.push(FakeDial::Answer(
        Duration::from_secs(5),
        peer(1),
        Some(PeerAdmission::Admitted),
    ));
    fake.plan_dials(addr(1), dials);
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
    let dials = fake.dials_to(addr(1));
    assert_eq!(dials.len(), JOIN_MAX_ATTEMPTS);
    let tenth = dials[JOIN_MAX_ATTEMPTS - 1].duration_since(started);
    let floor = Duration::from_millis(45_000 + backoff_ms(JOIN_MAX_ATTEMPTS - 1));
    assert!(tenth >= floor, "{tenth:?}");
}

/// A candidate that never answers uses exactly the old budget: ten dials
/// and ten backoffs (81.1 s plus at most 10.128 s of jitter).
#[tokio::test(start_paused = true)]
async fn the_join_gives_up_after_the_old_budget() {
    let fake = fake();
    fake.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(
        outcome,
        JoinOutcome::NoSeed {
            attempts: JOIN_MAX_ATTEMPTS
        }
    );
    assert_eq!(fake.dials_to(addr(1)).len(), JOIN_MAX_ATTEMPTS);
    let elapsed = started.elapsed();
    let base = backoff_ms(JOIN_MAX_ATTEMPTS);
    assert!(elapsed >= Duration::from_millis(base), "{elapsed:?}");
    assert!(
        elapsed <= Duration::from_millis(base + 10_128 + 100),
        "{elapsed:?}"
    );
}

/// Codex re-review of bf034a2, finding 1: only a failed dial grows the
/// backoff. A is admitted, answers nine dials, but every JOIN send fails;
/// its tenth dial fails. Before seed B, the JOIN waits the first backoff
/// (100 ms plus at most 12 ms of jitter), as in saorsa-gossip's JOIN, not
/// 30 s.
#[tokio::test(start_paused = true)]
async fn failed_sends_do_not_grow_the_backoff() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::Admitted);
    let mut a = vec![FakeDial::Answer(Duration::ZERO, peer(1), None); JOIN_MAX_ATTEMPTS - 1];
    a.push(FakeDial::Fail(Duration::ZERO));
    fake.plan_dials(addr(1), a);
    fake.plan_sends(peer(1), vec![FakeSend::Fail]);
    fake.plan_dials(
        addr(2),
        vec![FakeDial::Answer(
            Duration::ZERO,
            peer(2),
            Some(PeerAdmission::Admitted),
        )],
    );
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(outcome, JoinOutcome::Joined(addr(2)));
    let first = fake.dials_to(addr(1));
    assert_eq!(first.len(), JOIN_MAX_ATTEMPTS);
    assert_eq!(fake.sends_to(peer(1)), JOIN_MAX_ATTEMPTS - 1);
    let second = fake.dials_to(addr(2));
    assert_eq!(second.len(), 1);
    let waited = second[0].duration_since(first[JOIN_MAX_ATTEMPTS - 1]);
    assert!(
        waited >= Duration::from_millis(100) && waited <= Duration::from_millis(112),
        "{waited:?}"
    );
}

/// An exhausted budget is not renewed. A never answers. B answers and is
/// admitted, but every JOIN send through it fails. Each address gets one
/// budget in total: ten attempts.
#[tokio::test(start_paused = true)]
async fn an_exhausted_budget_is_not_renewed_after_a_failed_join() {
    let fake = fake();
    fake.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
    fake.plan_dials(
        addr(2),
        vec![FakeDial::Answer(
            Duration::ZERO,
            peer(2),
            Some(PeerAdmission::Admitted),
        )],
    );
    fake.plan_sends(peer(2), vec![FakeSend::Fail]);
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(
        outcome,
        JoinOutcome::NoSeed {
            attempts: 2 * JOIN_MAX_ATTEMPTS
        }
    );
    assert_eq!(fake.dials_to(addr(1)).len(), JOIN_MAX_ATTEMPTS);
    assert_eq!(fake.dials_to(addr(2)).len(), JOIN_MAX_ATTEMPTS);
    assert_eq!(fake.sends_to(peer(2)), JOIN_MAX_ATTEMPTS);
}

/// The same, when B interrupts A: B becomes admitted by another path (the
/// proactive reconnect) while A backs off. B gets its attempts; then A
/// continues with the attempts it has left, not a new budget.
#[tokio::test(start_paused = true)]
async fn an_interrupted_budget_continues_where_it_stopped() {
    let fake = fake();
    fake.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
    fake.plan_dials(
        addr(2),
        vec![FakeDial::Answer(Duration::ZERO, peer(2), None)],
    );
    fake.plan_sends(peer(2), vec![FakeSend::Fail]);
    let reconnect = {
        let fake = Arc::clone(&fake);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            fake.set(peer(2), PeerAdmission::Admitted);
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
    let started = Instant::now();

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;
    reconnect.await.unwrap();

    assert!(matches!(outcome, JoinOutcome::NoSeed { .. }), "{outcome:?}");
    let first = fake.dials_to(addr(1));
    assert_eq!(first.len(), JOIN_MAX_ATTEMPTS);
    let second = fake.dials_to(addr(2));
    assert_eq!(second.len(), JOIN_MAX_ATTEMPTS);
    let interrupted_at = started + Duration::from_secs(2);
    assert!(first.iter().any(|at| *at < interrupted_at));
    assert!(first.iter().any(|at| *at > second[0]));
}

/// Codex re-review of 15e6192, finding 2: one budget across the recovery
/// and the JOIN. Nine dials fail; the tenth answers and the peer is
/// admitted; then the connection is lost at the JOIN send. There is no
/// second budget.
#[tokio::test(start_paused = true)]
async fn a_seed_lost_at_the_join_handoff_keeps_one_budget() {
    let fake = fake();
    let mut dials = vec![FakeDial::Fail(Duration::ZERO); JOIN_MAX_ATTEMPTS - 1];
    dials.push(FakeDial::Answer(
        Duration::ZERO,
        peer(1),
        Some(PeerAdmission::Admitted),
    ));
    fake.plan_dials(addr(1), dials);
    fake.plan_sends(peer(1), vec![FakeSend::Lost]);
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(
        outcome,
        JoinOutcome::NoSeed {
            attempts: JOIN_MAX_ATTEMPTS
        }
    );
    assert_eq!(fake.dials_to(addr(1)).len(), JOIN_MAX_ATTEMPTS);
    assert_eq!(fake.sends_to(peer(1)), 1);
    assert!(active(&membership).is_empty());
}

/// The handoff loss earlier: the first dial answers, the send loses the
/// connection, and the later dials fail. Still ten attempts in total.
#[tokio::test(start_paused = true)]
async fn an_early_handoff_loss_keeps_one_budget() {
    let fake = fake();
    fake.plan_dials(
        addr(1),
        vec![
            FakeDial::Answer(Duration::ZERO, peer(1), Some(PeerAdmission::Admitted)),
            FakeDial::Fail(Duration::ZERO),
        ],
    );
    fake.plan_sends(peer(1), vec![FakeSend::Lost]);
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert!(matches!(outcome, JoinOutcome::NoSeed { .. }), "{outcome:?}");
    assert_eq!(fake.dials_to(addr(1)).len(), JOIN_MAX_ATTEMPTS);
    assert_eq!(fake.sends_to(peer(1)), 1);
}

/// As in saorsa-gossip's JOIN, a failed send is retried at once, without
/// backoff, within the same budget.
#[tokio::test(start_paused = true)]
async fn a_failed_send_is_retried_at_once() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::Admitted);
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
    );
    fake.plan_sends(peer(1), vec![FakeSend::Fail, FakeSend::Sent]);
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
    assert_eq!(fake.dials_to(addr(1)).len(), 2);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

/// A candidate is dropped as soon as it is suppressed, and the next one gets
/// its own budget.
#[tokio::test(start_paused = true)]
async fn a_candidate_is_dropped_as_soon_as_it_is_suppressed() {
    let fake = fake();
    fake.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
    fake.plan_dials(
        addr(2),
        vec![FakeDial::Answer(
            Duration::ZERO,
            peer(2),
            Some(PeerAdmission::Admitted),
        )],
    );
    let refusal = {
        let fake = Arc::clone(&fake);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            fake.set(peer(1), PeerAdmission::Suppressed);
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
    let started = Instant::now();

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;
    refusal.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Joined(addr(2)));
    let suppressed_at = started + Duration::from_secs(2);
    assert!(fake.dials_to(addr(1)).iter().all(|at| *at < suppressed_at));
    let second = fake.dials_to(addr(2));
    assert_eq!(second.len(), 1);
    assert!(second[0] <= suppressed_at + JOIN_SEED_VERDICT_POLL);
    assert!(candidates.refused.contains(&addr(1)));
}

/// A connected candidate with an open verdict gets the JOIN frame only when
/// the plane gate admits it (here after the 10 s legacy grace), in one
/// attempt: the gate waits for the verdict.
#[tokio::test(start_paused = true)]
async fn an_open_verdict_gets_the_join_only_when_admitted() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::PlanePending);
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
    );
    let grace = {
        let fake = Arc::clone(&fake);
        tokio::spawn(async move {
            tokio::time::sleep(PLANE_LEGACY_GRACE).await;
            fake.set(peer(1), PeerAdmission::Admitted);
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;
    grace.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Joined(addr(1)));
    assert!(started.elapsed() >= PLANE_LEGACY_GRACE);
    assert_eq!(fake.dials_to(addr(1)).len(), 1);
    assert_eq!(fake.sends_to(peer(1)), 1);
}

/// A gate refusal (suppressed after the dial answered) sends no JOIN frame,
/// stores no address and leaves the active view empty.
#[tokio::test(start_paused = true)]
async fn a_peer_refused_after_the_dial_gets_no_join_frame() {
    let fake = fake();
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(
            Duration::ZERO,
            peer(1),
            Some(PeerAdmission::Suppressed),
        )],
    );
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(outcome, JoinOutcome::NoSeed { attempts: 1 });
    assert_eq!(fake.sends_to(peer(1)), 0);
    assert!(active(&membership).is_empty());
    assert_eq!(
        membership
            .get_peer_addr(&GossipPeerId::new(peer(1).0))
            .await,
        None
    );
    assert!(candidates.refused.contains(&addr(1)));
}

/// Another path (the proactive reconnect, an inbound dial) restores a later
/// candidate while the first one backs off: it goes first.
#[tokio::test(start_paused = true)]
async fn a_candidate_that_another_path_reconnected_goes_first() {
    let fake = fake();
    fake.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
    fake.plan_dials(
        addr(2),
        vec![FakeDial::Answer(Duration::ZERO, peer(2), None)],
    );
    let reconnect = {
        let fake = Arc::clone(&fake);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            fake.set(peer(2), PeerAdmission::Admitted);
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);
    let started = Instant::now();

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;
    reconnect.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Joined(addr(2)));
    assert!(started.elapsed() < Duration::from_secs(3) + JOIN_SEED_VERDICT_POLL * 2);
    assert_eq!(fake.dials_to(addr(2)).len(), 1);
    assert!(fake.dials_to(addr(1)).len() < JOIN_MAX_ATTEMPTS);
}

/// Shutdown ends the JOIN during a backoff, with no further dial.
#[tokio::test(start_paused = true)]
async fn the_join_stops_on_shutdown_during_a_backoff() {
    let fake = fake();
    fake.plan_dials(addr(1), vec![FakeDial::Fail(Duration::ZERO)]);
    let shutdown = CancellationToken::new();
    let canceller = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            shutdown.cancel();
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(&mut candidates, &fake, &membership, &shutdown).await;
    canceller.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Cancelled);
    assert!(started.elapsed() <= Duration::from_secs(5) + JOIN_SEED_VERDICT_POLL);
    let cancelled_at = started + Duration::from_secs(5);
    assert!(fake.dials_to(addr(1)).iter().all(|at| *at <= cancelled_at));
}

/// Shutdown also ends a JOIN dial in flight.
#[tokio::test(start_paused = true)]
async fn the_join_stops_a_dial_in_flight_on_shutdown() {
    let fake = fake();
    fake.plan_dials(addr(1), vec![FakeDial::Fail(Duration::from_secs(60))]);
    let shutdown = CancellationToken::new();
    let canceller = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown.cancel();
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(&mut candidates, &fake, &membership, &shutdown).await;
    canceller.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Cancelled);
    assert_eq!(started.elapsed(), Duration::from_secs(1));
}

/// Shutdown also ends a JOIN send in flight; the seed is not added to the
/// active view.
#[tokio::test(start_paused = true)]
async fn the_join_stops_a_send_in_flight_on_shutdown() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::Admitted);
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
    );
    fake.plan_sends(peer(1), vec![FakeSend::Slow(Duration::from_secs(60))]);
    let shutdown = CancellationToken::new();
    let canceller = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown.cancel();
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(&mut candidates, &fake, &membership, &shutdown).await;
    canceller.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Cancelled);
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert!(active(&membership).is_empty());
}

/// D252: a peer that answers the dial and then closes (it lost its
/// connection before admission; for example the remote refused us first)
/// is redialled only after the loss cooldown: 100 ms, doubled after each
/// loss up to 30 s, plus at most 1/8 jitter. The cooldown does not reset
/// when the peer answers again. The budget stays ten attempts, and no JOIN
/// frame goes out.
#[tokio::test(start_paused = true)]
async fn a_peer_that_answers_and_closes_is_paced_by_the_loss_cooldown() {
    let fake = fake();
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(
            Duration::ZERO,
            peer(1),
            Some(PeerAdmission::NotConnected),
        )],
    );
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(
        outcome,
        JoinOutcome::NoSeed {
            attempts: JOIN_MAX_ATTEMPTS
        }
    );
    assert_eq!(fake.sends_to(peer(1)), 0);
    let dials = fake.dials_to(addr(1));
    assert_eq!(dials.len(), JOIN_MAX_ATTEMPTS);
    let mut cooldown = 100_u64;
    for (i, pair) in dials.windows(2).enumerate() {
        let gap = pair[1].duration_since(pair[0]);
        assert!(
            gap >= Duration::from_millis(cooldown)
                && gap <= Duration::from_millis(cooldown + cooldown / 8),
            "gap {i} is {gap:?}, expected the {cooldown} ms loss cooldown plus at most 1/8 jitter"
        );
        cooldown = (cooldown * 2).min(30_000);
    }
}

/// D252: while a lost address waits for its cooldown, another address that
/// becomes admitted goes first. The lost address is not redialled meanwhile.
#[tokio::test(start_paused = true)]
async fn another_admitted_address_goes_first_while_a_lost_one_waits() {
    let fake = fake();
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(
            Duration::ZERO,
            peer(1),
            Some(PeerAdmission::NotConnected),
        )],
    );
    fake.plan_dials(
        addr(2),
        vec![FakeDial::Answer(Duration::ZERO, peer(2), None)],
    );
    let reconnect = {
        let fake = Arc::clone(&fake);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            fake.set(peer(2), PeerAdmission::Admitted);
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1)), (addr(2), peer(2))]);

    let outcome = join(
        &mut candidates,
        &fake,
        &membership,
        &CancellationToken::new(),
    )
    .await;
    reconnect.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Joined(addr(2)));
    assert_eq!(
        fake.dials_to(addr(1)).len(),
        1,
        "the lost address waits for its cooldown while the admitted one joins"
    );
}

/// Codex re-review of f3e28b3, finding 3: shutdown ends a slow admission
/// read in the candidate scan.
#[tokio::test(start_paused = true)]
async fn the_join_stops_on_shutdown_during_a_slow_admission_read() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::Admitted);
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
    );
    fake.slow_reads_after(0, Duration::from_secs(60));
    let shutdown = CancellationToken::new();
    let canceller = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown.cancel();
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(&mut candidates, &fake, &membership, &shutdown).await;
    canceller.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Cancelled);
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert!(fake.dials_to(addr(1)).is_empty());
}

/// Codex re-review of f3e28b3, finding 3: shutdown ends a slow admission
/// read in the gate after an answered dial, and no JOIN frame goes out.
#[tokio::test(start_paused = true)]
async fn the_join_stops_on_shutdown_during_the_gate_read() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::Admitted);
    fake.plan_dials(
        addr(1),
        vec![FakeDial::Answer(Duration::ZERO, peer(1), None)],
    );
    // The candidate scan reads once; the gate read after the dial is slow.
    fake.slow_reads_after(1, Duration::from_secs(60));
    let shutdown = CancellationToken::new();
    let canceller = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown.cancel();
        })
    };
    let membership = membership(&fake);
    let mut candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let outcome = join(&mut candidates, &fake, &membership, &shutdown).await;
    canceller.await.unwrap();

    assert_eq!(outcome, JoinOutcome::Cancelled);
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(fake.dials_to(addr(1)).len(), 1);
    assert_eq!(fake.sends_to(peer(1)), 0);
}

/// Codex re-review of f3e28b3, finding 3: shutdown ends a slow admission
/// read in the seed settlement.
#[tokio::test(start_paused = true)]
async fn settle_stops_on_shutdown_during_a_slow_admission_read() {
    let fake = fake();
    fake.set(peer(1), PeerAdmission::PlanePending);
    fake.slow_reads_after(0, Duration::from_secs(60));
    let shutdown = CancellationToken::new();
    let canceller = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown.cancel();
        })
    };
    let candidates = candidates(&[(addr(1), peer(1))]);
    let started = Instant::now();

    let _plan = candidates.settle(fake.as_ref(), 3, &shutdown).await;
    canceller.await.unwrap();

    assert_eq!(started.elapsed(), Duration::from_secs(1));
}
