//! HyParView JOIN seeds come only from gossip-admitted peers (x0x#1321).
//!
//! A dial that returned `Ok` is transport truth, not gossip admission: the
//! plane gate decides when the peer's hello arrives, after the dial returned.
//! saorsa-gossip's JOIN tries the seeds in order and dials one seed up to ten
//! times with backoff, so a refused seed delays the work after the JOIN.
//!
//! #292 invariant A: [`crate::network::NetworkNode::peer_admission`] is the
//! predicate for every gossip-affecting decision, never transport truth.

use std::net::SocketAddr;
use std::time::Duration;

use saorsa_gossip_membership::{HyParViewMembership, JoinDial, JoinLedger, JoinSend};
use saorsa_gossip_transport::GossipTransport;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::network::{NetworkNode, PeerAdmission, PLANE_HELLO_RETRY_INTERVAL, PLANE_LEGACY_GRACE};

pub(crate) const JOIN_SEED_VERDICT_WAIT: Duration =
    PLANE_LEGACY_GRACE.saturating_add(PLANE_HELLO_RETRY_INTERVAL);

const JOIN_SEED_VERDICT_POLL: Duration = Duration::from_millis(50);

fn remaining(at: Instant) -> Option<Duration> {
    at.checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

#[async_trait::async_trait]
pub(crate) trait SeedAdmission: Send + Sync {
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct JoinSeedPlan {
    pub(crate) seeds: Vec<SocketAddr>,
    pub(crate) admitted_peers: usize,
    pub(crate) suppressed: usize,
    pub(crate) plane_unresolved: usize,
    pub(crate) not_connected: usize,
}

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

pub(crate) fn settled(plan: &JoinSeedPlan, target: usize, waited: Duration) -> bool {
    plan.admitted_peers >= target || plan.plane_unresolved == 0 || waited >= JOIN_SEED_VERDICT_WAIT
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JoinOutcome {
    Joined(SocketAddr),
    NoSeed { attempts: usize },
    Failed(String),
    Cancelled,
}

enum Attempt {
    Next,
    NotReady,
    Joined(SocketAddr),
    Failed(String),
    Cancelled,
}

enum Gate {
    Send,
    Lost,
    Unresolved,
    Refused,
    Cancelled,
}

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

async fn nap(wait: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tokio::time::sleep(wait) => true,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    addr: SocketAddr,
    peer: ant_quic::PeerId,
}

#[derive(Debug, Default)]
pub(crate) struct JoinCandidates {
    connected: Vec<Candidate>,
    refused: Vec<SocketAddr>,
    ledger: JoinLedger,
}

impl JoinCandidates {
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

    pub(crate) fn len(&self) -> usize {
        self.connected.len()
    }

    pub(crate) fn contains_addr(&self, addr: &SocketAddr) -> bool {
        self.refused.contains(addr) || self.connected.iter().any(|known| known.addr == *addr)
    }

    fn drop_candidate(&mut self, addr: SocketAddr) {
        self.connected.retain(|known| known.addr != addr);
        self.refused.push(addr);
    }

    async fn read_verdicts<A: SeedAdmission + ?Sized>(
        &mut self,
        admission: &A,
        budgeted: bool,
        shutdown: &CancellationToken,
    ) -> Option<Vec<(SocketAddr, ant_quic::PeerId, PeerAdmission)>> {
        if shutdown.is_cancelled() {
            return None;
        }
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
            if shutdown.is_cancelled() {
                return JoinSeedPlan::default();
            }
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
        let mut gate = Instant::now();
        let mut attempts = 0;
        loop {
            if shutdown.is_cancelled() {
                return JoinOutcome::Cancelled;
            }
            let Some(live) = self.read_verdicts(admission, true, shutdown).await else {
                return JoinOutcome::Cancelled;
            };
            let Some((addr, ready_at)) = self.choose(&live, gate) else {
                if let Some(wait) = remaining(gate) {
                    if !nap(wait, shutdown).await {
                        return JoinOutcome::Cancelled;
                    }
                }
                return JoinOutcome::NoSeed { attempts };
            };
            if let Some(wait) = ready_at.and_then(remaining) {
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

    fn choose(
        &self,
        live: &[(SocketAddr, ant_quic::PeerId, PeerAdmission)],
        gate: Instant,
    ) -> Option<(SocketAddr, Option<Instant>)> {
        let admitted = || {
            live.iter()
                .filter(|(_, _, verdict)| *verdict == PeerAdmission::Admitted)
                .map(|(addr, _, _)| (*addr, self.ledger.ready_at(*addr)))
        };
        if let Some((addr, _)) =
            admitted().find(|(_, ready_at)| ready_at.and_then(remaining).is_none())
        {
            return Some((addr, None));
        }
        if let Some(waiting) = admitted().min_by_key(|(_, ready_at)| *ready_at) {
            return Some(waiting);
        }
        live.first().map(|(addr, _, _)| {
            let own = self.ledger.ready_at(*addr);
            (*addr, Some(own.map_or(gate, |own| own.max(gate))))
        })
    }

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
