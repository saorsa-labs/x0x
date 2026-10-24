//! The discovery/evidence portion of an ordinary DM shares one attempt budget.
//! Later raw resolution and transport waits retain their existing budgets,
//! and [`ordinary_send_budget`] fixes the ONE absolute deadline across the
//! entire send that they all answer to (#1239).

use crate::{connectivity, dm, identity, peer_evidence, Agent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::time::Instant;

/// Ceiling of the absolute budget. A retry schedule whose summed budgets
/// exceed it already saturates the backoff computation, so Tokio's own
/// inter-attempt timers cannot represent it either; the deadline bounds such
/// a pathological config at the ceiling instead of panicking on an
/// unrepresentable `Instant`.
const MAX_SEND_BUDGET: Duration = Duration::from_secs(24 * 60 * 60);

/// #1239: the one absolute budget of an entire ordinary send. Every stage
/// with a budget of its own is summed, so a send that fits those stages is
/// never cut short, while a wait none of them bounds (a held lock, a stacked
/// slow stage, a stuck fallback) ends at this deadline with the send's typed
/// timeout instead of staying open.
///
/// Stage terms: the discovery/evidence budget ([`SendEvidence`]), one forced
/// targeted capability refresh (ADR 0030 §2), the evidence dial cap
/// ([`Agent::dial_evidence_view`]), the preferred raw-QUIC attempt and the
/// raw-QUIC fallback redial — each counted with one X0X-0053 reissue and its
/// prefer-newest grace — and every gossip attempt with its backoff plus the
/// publish-only inter-attempt republish delay. A cold-wait send adds its
/// opt-in repair wait (#1217).
///
/// Stages that had NO bound before #1239 — the known-recipient redial and
/// last-resort `connect_to_agent`, a fire-and-forget raw write, the relay
/// fallback — get no term: the deadline itself is their first bound, which is
/// the fix. A redial or traversal slower than the send's whole budget fails
/// retryably instead of hanging the caller.
pub(crate) fn ordinary_send_budget(
    config: &dm::DmSendConfig,
    cold_wait: Option<Duration>,
) -> Duration {
    let per_attempt = config.timeout_per_attempt;
    let raw_attempt = config.raw_quic_receive_ack_timeout.unwrap_or(per_attempt);
    let grace = Duration::from_millis(config.prefer_newest_grace_ms);
    let raw_execution = raw_attempt.saturating_mul(2).saturating_add(grace);
    let mut budget = per_attempt;
    budget = budget.saturating_add(crate::CAPABILITY_REFRESH_CONVERGENCE_WAIT);
    budget = budget.saturating_add(EVIDENCE_DIAL_CAP);
    budget = budget.saturating_add(raw_execution);
    for attempt in 0..=config.max_retries {
        budget = budget.saturating_add(per_attempt);
        if attempt > 0 {
            budget = budget
                .saturating_add(config.backoff.delay(per_attempt, attempt - 1))
                .saturating_add(crate::dm_send::PUBLISH_ONLY_REDUNDANT_REPUBLISH_DELAY);
        }
    }
    budget = budget.saturating_add(raw_execution);
    budget
        .saturating_add(cold_wait.unwrap_or(Duration::ZERO))
        .min(MAX_SEND_BUDGET)
}

pub(crate) type SendCapability = (
    Option<dm::DmCapabilities>,
    Option<identity::MachineId>,
    &'static str,
);

/// The dial cap of [`Agent::dial_evidence_view`]: one stage of an ordinary
/// send's absolute budget ([`ordinary_send_budget`]).
const EVIDENCE_DIAL_CAP: Duration = Duration::from_secs(3);

pub(crate) struct SendEvidence<'a> {
    agent: &'a Agent,
    recipient: identity::AgentId,
    deadline: Instant,
    strict: bool,
    unavailable: AtomicBool,
    expiry_counted: AtomicBool,
}

impl<'a> SendEvidence<'a> {
    pub(crate) fn new(
        agent: &'a Agent,
        recipient: identity::AgentId,
        budget: Duration,
        strict: bool,
    ) -> Self {
        Self {
            agent,
            recipient,
            deadline: Instant::now() + budget,
            strict,
            unavailable: AtomicBool::new(false),
            expiry_counted: AtomicBool::new(false),
        }
    }

    fn failed(&self, stage: &str) -> dm::DmError {
        self.agent
            .direct_messaging
            .record_outgoing_failed(self.recipient);
        dm::DmError::RecipientUndiscovered(format!(
            "direct-send binding source unavailable within the send budget ({stage})"
        ))
    }

    /// Evidence is optional for ordinary sends. Count expiry separately from
    /// the final send result, and stop consulting this source after failure.
    fn optional<T: Default>(&self, stage: &str, result: Result<T, ()>) -> Result<T, dm::DmError> {
        match result {
            Ok(value) => Ok(value),
            Err(()) => {
                self.unavailable.store(true, Ordering::Relaxed);
                if Instant::now() >= self.deadline
                    && !self.expiry_counted.swap(true, Ordering::Relaxed)
                {
                    self.agent
                        .peer_evidence()
                        .evidence_barrier_timeout
                        .fetch_add(1, Ordering::Relaxed);
                }
                if self.strict {
                    Err(self.failed(stage))
                } else {
                    Ok(T::default())
                }
            }
        }
    }

    async fn before<T>(&self, work: impl Future<Output = T>) -> Result<T, ()> {
        if self.unavailable.load(Ordering::Relaxed) || Instant::now() >= self.deadline {
            return Err(());
        }
        tokio::time::timeout_at(self.deadline, work)
            .await
            .map_err(|_| ())
    }

    /// Discovery preflight retains its original error and failure accounting.
    pub(crate) async fn discovery<T>(
        &self,
        work: impl Future<Output = T>,
    ) -> Result<T, dm::DmError> {
        Agent::pinned_bounded(self.deadline, "discovery", work).await
    }

    pub(crate) async fn bounded<T>(
        &self,
        stage: &str,
        work: impl Future<Output = T>,
    ) -> Result<Option<T>, dm::DmError> {
        self.optional(stage, self.before(work).await.map(Some))
    }

    pub(crate) async fn wait(&self, bytes: usize) -> Result<(), dm::DmError> {
        match self.before(self.agent.peer_evidence().wait(bytes)).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                // The runtime already counts its own five-second timeout (or
                // queue overflow). Do not charge the same expiry twice.
                self.unavailable.store(true, Ordering::Relaxed);
                if Instant::now() >= self.deadline {
                    self.expiry_counted.store(true, Ordering::Relaxed);
                }
                if self.strict {
                    Err(self.failed("evidence load"))
                } else {
                    Ok(())
                }
            }
            Err(()) => self.optional("evidence load", Err(())),
        }
    }

    pub(crate) async fn lookup(&self) -> Result<(), dm::DmError> {
        let result = self
            .before(
                self.agent
                    .peer_evidence()
                    .lookup_before(self.recipient, None, self.deadline),
            )
            .await;
        self.optional("evidence Lookup", result.and_then(|result| result))
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
        let result = self
            .before(self.agent.peer_evidence().usable_before(
                self.recipient,
                machine,
                self.deadline,
            ))
            .await;
        self.optional(stage, result.and_then(|result| result))
    }

    /// A point-of-use timeout drops evidence authority and uses the same
    /// contact-card fallback as a send that never had evidence. Actual loss
    /// of previously usable authority still fails with the existing error.
    pub(crate) async fn current_capability(
        &self,
        view: Option<Arc<peer_evidence::EvidenceView>>,
    ) -> Result<SendCapability, dm::DmError> {
        match view {
            Some(view) => Ok((
                Some(view.advert.capabilities.clone()),
                Some(view.announcement.machine_id),
                "peer_evidence",
            )),
            None if !self.strict && self.unavailable.load(Ordering::Relaxed) => {
                Ok(self.fallback_capability(None, None).await)
            }
            None => Err(dm::DmError::RecipientUndiscovered(
                "peer evidence no longer usable".into(),
            )),
        }
    }

    /// Validate both the original selection and any late contact-card fallback.
    pub(crate) fn validate_capability(
        &self,
        cap: Option<&dm::DmCapabilities>,
    ) -> Result<(), dm::DmError> {
        if let Some(cap) = cap.filter(|cap| cap.gossip_inbox && !cap.kem_public_key.is_empty()) {
            if let Err(reason) = dm::validate_recipient_kem_key(&cap.kem_public_key) {
                self.agent
                    .direct_messaging
                    .record_outgoing_failed(self.recipient);
                return Err(dm::DmError::RecipientKeyInvalid(reason));
            }
        }
        Ok(())
    }

    pub(crate) async fn fallback_capability(
        &self,
        advert_cap: Option<dm::DmCapabilities>,
        advert_machine: Option<identity::MachineId>,
    ) -> SendCapability {
        if self.strict {
            // An unbound card cannot supply a machine-pinned durable ACK.
            return (
                advert_cap,
                advert_machine,
                "advert_cache_unusable_for_durable_ack",
            );
        }
        let contact_cap = {
            let contacts = self.agent.contact_store.read().await;
            contacts.get(&self.recipient).and_then(|contact| {
                contact
                    .dm_capabilities
                    .as_ref()
                    .filter(|caps| caps.gossip_inbox && !caps.kem_public_key.is_empty())
                    .cloned()
            })
        };
        match contact_cap {
            Some(cap) if advert_cap.is_some() => {
                (Some(cap), None, "contact_card_after_unusable_advert")
            }
            Some(cap) => (Some(cap), None, "contact_card"),
            None if advert_cap.is_some() => (advert_cap, advert_machine, "advert_cache_unusable"),
            None => (None, None, "none"),
        }
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
                EVIDENCE_DIAL_CAP,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #1239: the absolute budget is the sum of the config's spendable
    /// stages, so a send that fits its configured stages is never cut short.
    #[test]
    fn ordinary_send_budget_sums_the_configured_stages() {
        let config = dm::DmSendConfig {
            timeout_per_attempt: Duration::from_secs(2),
            ..Default::default()
        };
        // evidence 2 + refresh 3 + dial 3 + raw (2*2 + 0.25)
        // + gossip 2 + (2 + 2 backoff + 0.25 republish) + raw (2*2 + 0.25)
        assert_eq!(
            ordinary_send_budget(&config, None),
            Duration::from_millis(22_750)
        );
        // A cold-wait send adds its opt-in repair wait (#1217).
        assert_eq!(
            ordinary_send_budget(&config, Some(Duration::from_secs(30))),
            Duration::from_millis(52_750)
        );
        // Retries and backoff extend the budget they already control.
        let strict = dm::DmSendConfig {
            timeout_per_attempt: Duration::from_secs(8),
            max_retries: 0,
            raw_quic_receive_ack_timeout: Some(Duration::from_secs(8)),
            require_durable_app_ack: true,
            ..Default::default()
        };
        // evidence 8 + refresh 3 + dial 3 + raw (2*8 + 0.25) + gossip 8
        // + raw (2*8 + 0.25)
        assert_eq!(
            ordinary_send_budget(&strict, None),
            Duration::from_millis(54_500)
        );
        // Publish-only retries add their inter-attempt republish delay even
        // with zero backoff (review r1: 32 x 250 ms must fit the budget).
        let publish_only = dm::DmSendConfig {
            timeout_per_attempt: Duration::from_millis(10),
            max_retries: 32,
            backoff: dm::BackoffPolicy::Fixed(Duration::ZERO),
            prefer_newest_grace_ms: 0,
            ..Default::default()
        };
        assert!(
            ordinary_send_budget(&publish_only, None) >= Duration::from_secs(8),
            "publish-only republish delays must fit the absolute budget"
        );
    }

    /// #1239 review r1: a pathological retry schedule saturates the backoff
    /// arithmetic; the budget must stay clock-representable instead of
    /// panicking on `Instant + Duration`.
    #[test]
    fn ordinary_send_budget_stays_representable_for_pathological_retries() {
        let config = dm::DmSendConfig {
            timeout_per_attempt: Duration::from_secs(4),
            max_retries: 64,
            ..Default::default()
        };
        let budget = ordinary_send_budget(&config, None);
        assert_eq!(budget, MAX_SEND_BUDGET);
        assert!(tokio::time::Instant::now().checked_add(budget).is_some());
    }
}
