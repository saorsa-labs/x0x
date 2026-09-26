//! Owner trust (ADR-0070 §1, slice 1).
//!
//! A remote `(AgentId, MachineId)` pair is **owner-trusted** when all hold:
//!
//! 1. this install has an owner (`user.key`, ADR-0036) and the ADR-0041
//!    owner device set has been installed ([`crate::Agent::install_owner_device_store`]);
//! 2. the agent's **authenticated** machine binding
//!    ([`crate::dm_inbox::AuthenticatedMachineBindings`], written only from the
//!    agent's own fresh identity announcement or a valid ADR-0021 DM
//!    attestation) names exactly the transport-authenticated peer machine —
//!    no binding (never learned, or LRU-evicted) means not owner-trusted. The
//!    mutable `DiscoveredAgent::machine_id` is never used for the pairing;
//! 3. the `AgentCertificate` cached for the agent (looked up by agent only —
//!    it is self-verifying) verifies, binds exactly this agent, is signed by
//!    the local owner's key and is unexpired;
//! 4. neither the agent, the machine, nor the ADR-0043 binding is in the
//!    local ADR-0018 revocation set;
//! 5. the machine holds a current `OwnerEnrollment` signed by the local owner
//!    ([`OwnerSyncStore::is_enrolled`], which re-verifies the signature and
//!    expiry on every call).
//!
//! Every failure — no owner, no device set, no cached certificate, a bad or
//! foreign or expired certificate, a revocation, a missing or expired
//! enrollment — yields "not owner-trusted", never an error that a caller
//! could mistake for success.
//!
//! Owner trust is an *input* to [`TrustEvaluator`]: it raises `Unknown` /
//! `AcceptWithFlag` to `Accept` and never overrides `Blocked` or a
//! machine-pin mismatch. It does **not** open the connect or exec ACLs by
//! itself; those need an explicit `principal = "owner"` entry (PR #896,
//! decision 1).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::contacts::ContactStore;
use crate::dm_inbox::AuthenticatedMachineBindings;
use crate::identity::{AgentCertificate, AgentId, MachineId, UserId};
use crate::owner_sync::OwnerSyncStore;
use crate::revocation::RevocationSet;
use crate::trust::{TrustContext, TrustDecision, TrustEvaluator};
use crate::DiscoveredAgent;

/// The local owner and the owner device set used to decide owner trust.
///
/// Cheap to clone: the device-set slot is shared, so installing the store
/// once (at daemon startup) is seen by every clone, including the stream
/// accept loop.
#[derive(Clone, Default)]
pub struct OwnerTrust {
    local_owner: Option<UserId>,
    devices: Arc<std::sync::RwLock<Option<Arc<OwnerSyncStore>>>>,
    /// The agent's authenticated agent→machine bindings (#890). The default
    /// is an empty cache, which owner-trusts nothing.
    bindings: AuthenticatedMachineBindings,
    /// ADR-0070 §2 share-grant store (slice 3). Shared slot like `devices`:
    /// until the daemon installs it, no pair holds any grant.
    grants: Arc<std::sync::RwLock<Option<Arc<crate::share_grant::ShareGrantStore>>>>,
}

impl std::fmt::Debug for OwnerTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerTrust")
            .field("local_owner", &self.local_owner)
            .field("device_store_installed", &self.device_store().is_some())
            .finish()
    }
}

/// Result of a pair evaluation: the trust decision (with the owner input
/// applied) and whether the pair was owner-trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairTrust {
    /// The [`TrustEvaluator`] decision with owner trust applied.
    pub decision: TrustDecision,
    /// Whether the pair is owner-trusted. Always `false` when the contact
    /// rules already rejected the pair (`Blocked`, machine-pin mismatch).
    pub owner_trusted: bool,
}

impl OwnerTrust {
    /// Owner trust for an install whose owner is `local_owner` (`None` for
    /// an ownerless install, which never owner-trusts anything), pairing
    /// agents to machines only through `bindings`.
    #[must_use]
    pub fn new(local_owner: Option<UserId>, bindings: AuthenticatedMachineBindings) -> Self {
        Self {
            local_owner,
            devices: Arc::new(std::sync::RwLock::new(None)),
            bindings,
            grants: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Install the ADR-0070 share-grant store. Every clone sees it.
    pub fn install_share_grant_store(&self, store: Arc<crate::share_grant::ShareGrantStore>) {
        let mut slot = self
            .grants
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Some(store);
    }

    /// The installed share-grant store, if any.
    #[must_use]
    pub fn share_grant_store(&self) -> Option<Arc<crate::share_grant::ShareGrantStore>> {
        self.grants
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// ADR-0070 §2: what the held share grants confer on `(agent_id,
    /// machine_id)` for this daemon's agent. Explicit local denials win: a
    /// `Blocked` agent or a machine-pin mismatch gets nothing. Pairing uses
    /// the same authenticated binding as owner trust (module docs, 2); see
    /// [`crate::share_grant::evaluate_grant_access`] for the rest.
    pub async fn grant_access(
        &self,
        contact_store: &RwLock<ContactStore>,
        discovery_cache: &RwLock<HashMap<AgentId, DiscoveredAgent>>,
        revocation_set: &RwLock<RevocationSet>,
        agent_id: &AgentId,
        machine_id: &MachineId,
    ) -> crate::share_grant::GrantAccess {
        let Some(store) = self.share_grant_store() else {
            return crate::share_grant::GrantAccess::default();
        };
        let base = {
            let contacts = contact_store.read().await;
            TrustEvaluator::new(&contacts).evaluate(&TrustContext {
                agent_id,
                machine_id,
            })
        };
        let rejected = |decision: TrustDecision| {
            matches!(
                decision,
                TrustDecision::RejectBlocked | TrustDecision::RejectMachineMismatch
            )
        };
        if rejected(base) {
            return crate::share_grant::GrantAccess::default();
        }
        let access = crate::share_grant::evaluate_grant_access(
            &store,
            &self.bindings,
            discovery_cache,
            revocation_set,
            agent_id,
            machine_id,
            unix_now_secs(),
        )
        .await;
        // Final contact read, as in `evaluate_pair`: a `Blocked` or re-pin
        // that landed while the grant was being evaluated still wins.
        let last = {
            let contacts = contact_store.read().await;
            TrustEvaluator::new(&contacts).evaluate(&TrustContext {
                agent_id,
                machine_id,
            })
        };
        if rejected(last) {
            return crate::share_grant::GrantAccess::default();
        }
        access
    }

    /// The local owner, if this install has one.
    #[must_use]
    pub fn local_owner(&self) -> Option<UserId> {
        self.local_owner
    }

    /// Install the ADR-0041 owner device set. Until this is called no pair
    /// is owner-trusted (enrollment cannot be checked).
    pub fn install_device_store(&self, store: Arc<OwnerSyncStore>) {
        let mut slot = self
            .devices
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Some(store);
    }

    fn device_store(&self) -> Option<Arc<OwnerSyncStore>> {
        self.devices
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether `(agent_id, machine_id)` is owner-trusted (module docs, 1–5).
    ///
    /// `machine_id` must be the transport-authenticated peer machine (the
    /// QUIC peer, or for gossip-DM exec the authenticated origin); it must
    /// equal the agent's authenticated binding.
    ///
    /// Cheap checks run first so a non-owner peer costs a cache lookup and
    /// a hash, never an ML-DSA verification. Each lock is taken in its own
    /// scope; none is held across another lock or the enrollment check.
    pub async fn is_owner_trusted(
        &self,
        discovery_cache: &RwLock<HashMap<AgentId, DiscoveredAgent>>,
        revocation_set: &RwLock<RevocationSet>,
        agent_id: &AgentId,
        machine_id: &MachineId,
    ) -> bool {
        let Some(owner) = self.local_owner else {
            return false;
        };
        let Some(devices) = self.device_store() else {
            return false;
        };
        match crate::dm_inbox::authenticated_machine_binding(&self.bindings, agent_id).await {
            Some(bound) if bound == *machine_id => {}
            _ => return false,
        }
        let cert = {
            let cache = discovery_cache.read().await;
            cache
                .get(agent_id)
                .and_then(|entry| entry.agent_certificate.clone())
        };
        let Some(cert) = cert else {
            return false;
        };
        let revoked = {
            let revoked = revocation_set.read().await;
            revoked.is_agent_revoked(agent_id)
                || revoked.is_machine_revoked(machine_id)
                || revoked.is_binding_revoked(agent_id, machine_id)
        };
        if !certificate_chains_to_owner(&owner, agent_id, &cert, revoked, unix_now_secs()) {
            return false;
        }
        devices.is_enrolled(machine_id, &owner).await
    }

    /// Evaluate trust for a pair with the owner-trust input applied, in the
    /// ADR-0070 §1 order: `Blocked` → machine-pin mismatch → owner trust →
    /// contact rules. (Revocation is checked by the owner-trust test itself
    /// and, independently, by every gate that calls this.)
    ///
    /// Owner trust is computed only when the contact rules did not already
    /// reject the pair. The final decision is taken under a fresh contact
    /// read, so a `Blocked` written while owner trust was being checked
    /// still wins.
    pub async fn evaluate_pair(
        &self,
        contact_store: &RwLock<ContactStore>,
        discovery_cache: &RwLock<HashMap<AgentId, DiscoveredAgent>>,
        revocation_set: &RwLock<RevocationSet>,
        agent_id: &AgentId,
        machine_id: &MachineId,
    ) -> PairTrust {
        let ctx = TrustContext {
            agent_id,
            machine_id,
        };
        let base = {
            let contacts = contact_store.read().await;
            TrustEvaluator::new(&contacts).evaluate(&ctx)
        };
        if matches!(
            base,
            TrustDecision::RejectBlocked | TrustDecision::RejectMachineMismatch
        ) {
            return PairTrust {
                decision: base,
                owner_trusted: false,
            };
        }
        if !self
            .is_owner_trusted(discovery_cache, revocation_set, agent_id, machine_id)
            .await
        {
            return PairTrust {
                decision: base,
                owner_trusted: false,
            };
        }
        let decision = {
            let contacts = contact_store.read().await;
            TrustEvaluator::new(&contacts)
                .with_owner_trust(true)
                .evaluate(&ctx)
        };
        PairTrust {
            decision,
            owner_trusted: !matches!(
                decision,
                TrustDecision::RejectBlocked | TrustDecision::RejectMachineMismatch
            ),
        }
    }
}

/// Whether `cert` is a valid, unexpired certificate for exactly `agent_id`,
/// signed by `owner`, and not revoked. The user-id comparison runs first so
/// a foreign certificate is refused before any signature verification; the
/// full check is the ADR-0038 Home rule
/// ([`crate::groups::owner_cert::verify_cert_against_owner`]).
#[must_use]
pub fn certificate_chains_to_owner(
    owner: &UserId,
    agent_id: &AgentId,
    cert: &AgentCertificate,
    revoked: bool,
    now_unix: u64,
) -> bool {
    match cert.user_id() {
        Ok(cert_user) if cert_user == *owner => {}
        _ => return false,
    }
    crate::groups::owner_cert::verify_cert_against_owner(
        owner,
        &hex::encode(agent_id.as_bytes()),
        cert,
        revoked,
        now_unix,
    )
    .is_ok()
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl crate::Agent {
    /// Install the ADR-0041 owner device set so enrolled machines can be
    /// owner-trusted (ADR-0070 §1). The daemon calls this once the owner
    /// sync service has loaded its store; without it nothing is
    /// owner-trusted.
    pub fn install_owner_device_store(&self, store: Arc<OwnerSyncStore>) {
        self.owner_trust.install_device_store(store);
    }

    /// Whether `(agent_id, machine_id)` is owner-trusted (ADR-0070 §1). See
    /// [`OwnerTrust::is_owner_trusted`].
    pub async fn is_owner_trusted_pair(&self, agent_id: &AgentId, machine_id: &MachineId) -> bool {
        self.owner_trust
            .is_owner_trusted(
                &self.identity_discovery_cache,
                &self.revocation_set,
                agent_id,
                machine_id,
            )
            .await
    }

    /// The owner-trust source shared with gates that run outside `&self`.
    pub(crate) fn owner_trust(&self) -> &OwnerTrust {
        &self.owner_trust
    }
}

#[cfg(test)]
mod tests;
