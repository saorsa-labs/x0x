//! The discovery/evidence portion of an ordinary DM shares one attempt budget.
//! Later raw resolution and transport waits retain their existing budgets.

use crate::{connectivity, dm, identity, peer_evidence, Agent};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::time::Instant;

pub(crate) struct SendEvidence<'a> {
    agent: &'a Agent,
    recipient: identity::AgentId,
    deadline: Instant,
}

impl<'a> SendEvidence<'a> {
    pub(crate) fn new(agent: &'a Agent, recipient: identity::AgentId, budget: Duration) -> Self {
        Self {
            agent,
            recipient,
            deadline: Instant::now() + budget,
        }
    }

    pub(crate) fn failed(&self, stage: &str) -> dm::DmError {
        self.agent
            .direct_messaging
            .record_outgoing_failed(self.recipient);
        dm::DmError::RecipientUndiscovered(format!(
            "direct-send binding source unavailable within the send budget ({stage})"
        ))
    }

    pub(crate) async fn bounded<T>(
        &self,
        stage: &str,
        work: impl Future<Output = T>,
    ) -> Result<T, dm::DmError> {
        if Instant::now() >= self.deadline {
            return Err(self.failed(stage));
        }
        tokio::time::timeout_at(self.deadline, work)
            .await
            .map_err(|_| self.failed(stage))
    }

    pub(crate) async fn wait(&self, bytes: usize) -> Result<(), dm::DmError> {
        if self
            .bounded("evidence load", self.agent.peer_evidence().wait(bytes))
            .await?
        {
            Ok(())
        } else {
            Err(self.failed("evidence load"))
        }
    }

    pub(crate) async fn lookup(&self) -> Result<(), dm::DmError> {
        self.agent
            .peer_evidence()
            .lookup_before(self.recipient, self.deadline)
            .await
            .map_err(|()| self.failed("evidence Lookup"))
    }

    /// Transport has its own existing cap. Retain exactly the unused evidence
    /// budget across it, including the point-of-use check after the dial.
    pub(crate) async fn transport<T>(&mut self, work: impl Future<Output = T>) -> T {
        let started = Instant::now();
        let result = work.await;
        self.deadline += started.elapsed();
        result
    }

    pub(crate) async fn usable_agent(
        &self,
    ) -> Result<Option<Arc<peer_evidence::EvidenceView>>, dm::DmError> {
        self.usable_inner(None, "evidence agent").await
    }

    pub(crate) async fn usable(
        &self,
        machine: identity::MachineId,
    ) -> Result<Option<Arc<peer_evidence::EvidenceView>>, dm::DmError> {
        self.usable_inner(Some(machine), "evidence pairing").await
    }

    async fn usable_inner(
        &self,
        machine: Option<identity::MachineId>,
        stage: &str,
    ) -> Result<Option<Arc<peer_evidence::EvidenceView>>, dm::DmError> {
        self.agent
            .peer_evidence()
            .usable_before(self.recipient, machine, self.deadline)
            .await
            .map_err(|()| self.failed(stage))
    }
}

impl Agent {
    /// Optional transport hint only: its failure never rules out gossip.
    /// Keep the existing three-second dial cap separate from evidence reads.
    pub(crate) async fn dial_evidence_view(
        &self,
        view: &peer_evidence::EvidenceView,
    ) -> Option<connectivity::ConnectOutcome> {
        #[cfg(test)]
        if let Some(dial) = self.peer_evidence().evidence_dial.get() {
            let _ = tokio::time::timeout(Duration::from_secs(3), dial(view.announcement.agent_id))
                .await;
            return Some(connectivity::ConnectOutcome::Unreachable);
        }
        let network = self.network.as_ref()?;
        let peer = ant_quic::PeerId(view.announcement.machine_id.0);
        if network.is_connected(&peer).await {
            return Some(connectivity::ConnectOutcome::AlreadyConnected);
        }
        let addrs = crate::filter_discovery_announcement_addrs(
            view.announcement.addresses.clone(),
            crate::allow_local_discovery_addresses(network.config()),
        );
        Some(
            match tokio::time::timeout(
                Duration::from_secs(3),
                network.connect_peer_with_addrs(peer, addrs),
            )
            .await
            {
                Ok(Ok((addr, connected))) if connected == peer => {
                    connectivity::ConnectOutcome::Direct(addr)
                }
                _ => connectivity::ConnectOutcome::Unreachable,
            },
        )
    }
}
