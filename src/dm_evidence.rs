//! The discovery/evidence portion of an ordinary DM shares one attempt budget.
//! Later raw resolution and transport waits retain their existing budgets.

use crate::{dm, dm_capability, identity, peer_evidence, Agent};
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

    pub(crate) fn usable_agent(
        &self,
    ) -> Result<Option<Arc<peer_evidence::EvidenceView>>, dm::DmError> {
        if Instant::now() >= self.deadline {
            return Err(self.failed("evidence agent"));
        }
        self.agent
            .peer_evidence()
            .try_usable_agent(self.recipient, dm_capability::now_unix_ms())
            .map_err(|()| self.failed("evidence agent busy"))
    }

    pub(crate) fn usable(
        &self,
        machine: identity::MachineId,
    ) -> Result<Option<Arc<peer_evidence::EvidenceView>>, dm::DmError> {
        if Instant::now() >= self.deadline {
            return Err(self.failed("evidence pairing"));
        }
        self.agent
            .peer_evidence()
            .try_usable(self.recipient, machine, dm_capability::now_unix_ms())
            .map_err(|()| self.failed("evidence pairing busy"))
    }
}
