//! Runtime load barrier and live policy adapters. No derived authority is seeded.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Live group membership predicate. A busy/missing policy fails closed.
pub(crate) type GroupContext = dyn Fn(AgentId, AgentId) -> Option<bool> + Send + Sync;

type GroupPolicy = dyn Fn(AgentId) -> Option<bool> + Send + Sync;

#[cfg(test)]
type LookupResponder = dyn Fn(AgentId) -> futures::future::BoxFuture<'static, ()> + Send + Sync;

/// Reads current relationship and revocation stores at every use, without crypto.
pub struct RuntimePolicy {
    unavailable: AtomicU64,
    local_agent: AgentId,
    pub(crate) owner: crate::owner_trust::OwnerTrust,
    pub(crate) revoked: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    groups: std::sync::RwLock<Option<Arc<GroupPolicy>>>,
}
impl RuntimePolicy {
    pub(crate) fn new(
        local_agent: AgentId,
        owner: crate::owner_trust::OwnerTrust,
        revoked: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    ) -> Self {
        Self {
            unavailable: AtomicU64::new(0),
            local_agent,
            owner,
            revoked,
            groups: Default::default(),
        }
    }
    /// Install a predicate that reads the current active shared-group roster.
    pub fn set_groups(&self, groups: Arc<GroupPolicy>) {
        if let Ok(mut slot) = self.groups.write() {
            *slot = Some(groups);
        }
    }
}
impl EvidencePolicy for RuntimePolicy {
    fn unavailable_epoch(&self) -> u64 {
        self.unavailable.load(Ordering::Relaxed)
    }

    fn relation(
        &self,
        agent: AgentId,
        machine: MachineId,
        cert: Option<&AgentCertificate>,
        now: u64,
    ) -> u8 {
        if agent == self.local_agent {
            return 0;
        }
        let Ok(revoked) = self.revoked.try_read() else {
            self.unavailable.fetch_add(1, Ordering::Relaxed);
            return 0;
        };
        let Some(mut flags) = self
            .owner
            .evidence_relation(agent, machine, cert, &revoked, now)
        else {
            self.unavailable.fetch_add(1, Ordering::Relaxed);
            return 0;
        };
        if let Some(groups) = self.groups.read().ok().and_then(|g| g.clone()) {
            match groups(agent) {
                Some(true) => flags |= GROUP,
                Some(false) => {}
                None => {
                    self.unavailable.fetch_add(1, Ordering::Relaxed);
                    return 0;
                }
            }
        }
        flags
    }
    fn revoked(&self, agent: AgentId, machine: MachineId, _user: Option<UserId>) -> bool {
        let Ok(r) = self.revoked.try_read() else {
            self.unavailable.fetch_add(1, Ordering::Relaxed);
            return true;
        };
        // RevocationSet has no user subject. A certificate's UserId must not
        // be interpreted as an AgentId in the agent revocation namespace.
        r.is_agent_revoked(&agent)
            || r.is_machine_revoked(&machine)
            || r.is_binding_revoked(&agent, &machine)
    }
    fn try_relation(
        &self,
        agent: AgentId,
        machine: MachineId,
        cert: Option<&AgentCertificate>,
        now: u64,
    ) -> Option<u8> {
        if agent == self.local_agent {
            return Some(0);
        }
        let revoked = self.revoked.try_read().ok()?;
        let mut flags = self
            .owner
            .try_evidence_relation(agent, machine, cert, &revoked, now)?;
        let groups = match self.groups.try_read() {
            Ok(slot) => slot.clone(),
            Err(std::sync::TryLockError::Poisoned(_)) => None,
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        if let Some(groups) = groups {
            match groups(agent) {
                Some(true) => flags |= GROUP,
                Some(false) => {}
                None => return None,
            }
        }
        Some(flags)
    }
    fn try_revoked(
        &self,
        agent: AgentId,
        machine: MachineId,
        _user: Option<UserId>,
    ) -> Option<bool> {
        let r = self.revoked.try_read().ok()?;
        Some(
            r.is_agent_revoked(&agent)
                || r.is_machine_revoked(&machine)
                || r.is_binding_revoked(&agent, &machine),
        )
    }
    fn contains_agent(&self, agent: AgentId, now: u64) -> bool {
        // Without a record, only explicit agent grants and active rosters
        // resolve this agent. Enrollment/user-grant resolution needs a record;
        // the store independently protects every watermark that has one.
        self.relation(agent, MachineId([0; 32]), None, now) != 0
    }
}

/// Bounded startup barrier shared by raw frames and sends. Views are ephemeral.
pub struct EvidenceRuntime {
    #[cfg(test)]
    pub(crate) lookup_responder: std::sync::OnceLock<Arc<LookupResponder>>,
    pub(crate) lookup_context: std::sync::OnceLock<std::sync::Weak<crate::evidence_wire::Context>>,
    pub(crate) group_context: std::sync::RwLock<Option<Arc<GroupContext>>>,
    pub(crate) lookup_hints: crate::evidence_wire::lookup::RoutingHints,
    pub(crate) wire_limits: Arc<crate::evidence_wire::Limits>,
    store: std::sync::OnceLock<Arc<PeerEvidenceStore>>,
    ready: tokio_util::sync::CancellationToken,
    started: std::sync::atomic::AtomicBool,
    frames: tokio::sync::Semaphore,
    bytes: tokio::sync::Semaphore,
    /// Number of operations waiting for startup verification.
    pub evidence_load_barrier_waits: AtomicU64,
    /// Operations that exhausted the five-second deadline.
    pub evidence_barrier_timeout: AtomicU64,
    /// Operations refused by the aggregate queue bounds.
    pub evidence_barrier_overflow: AtomicU64,
    /// Lookups skipped because all outstanding Lookup permits were occupied.
    pub evidence_lookup_skipped: AtomicU64,
}
impl Default for EvidenceRuntime {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            lookup_responder: Default::default(),
            lookup_context: Default::default(),
            group_context: Default::default(),
            lookup_hints: Default::default(),
            wire_limits: Arc::new(crate::evidence_wire::Limits::default()),
            store: Default::default(),
            ready: Default::default(),
            started: Default::default(),
            frames: tokio::sync::Semaphore::new(64),
            bytes: tokio::sync::Semaphore::new(1024 * 1024),
            evidence_load_barrier_waits: AtomicU64::new(0),
            evidence_barrier_timeout: AtomicU64::new(0),
            evidence_barrier_overflow: AtomicU64::new(0),
            evidence_lookup_skipped: AtomicU64::new(0),
        }
    }
}
impl EvidenceRuntime {
    /// Install a live shared-roster predicate, including local membership.
    /// Unavailable policy reads fail closed; no membership snapshot is cached.
    pub fn set_group_context(&self, context: Arc<GroupContext>) {
        if let Ok(mut slot) = self.group_context.write() {
            *slot = Some(context);
        }
    }
    /// Pull missing relationship evidence over bounded connected-peer streams.
    /// Callers must re-read their authoritative sources after this await.
    pub(crate) async fn lookup(&self, agent: AgentId, machine: Option<MachineId>) {
        let Some(permit) = self.lookup_permit() else {
            return;
        };
        self.lookup_with_permit(agent, machine, permit).await;
    }

    /// x0x #1207: start a Lookup for `agent` in the background (the permit
    /// is reserved first, as in [`Self::spawn_lookup`]). The caller never
    /// runs the Lookup's load barrier or its responder selection, whose
    /// evidence and policy reads block synchronously, so a bounded wait can
    /// start one. It re-reads its sources afterwards, as after
    /// [`Self::lookup`].
    pub(crate) fn spawn_agent_lookup(self: &Arc<Self>, agent: AgentId) {
        let Some(permit) = self.lookup_permit() else {
            return;
        };
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            if runtime.wait(0).await {
                runtime.lookup_with_permit(agent, None, permit).await;
            }
        });
    }

    /// Test seam (x0x #1207): mark the store started without completing its
    /// load, so every load-barrier wait waits (up to its five-second bound).
    /// Test builds only.
    #[cfg(test)]
    pub(crate) fn hold_load_barrier_for_testing(&self) {
        self.started.store(true, Ordering::Release);
    }

    /// x0x #1207: [`Self::wait`] without waiting: whether the evidence is
    /// loaded (or the store never started) right now.
    pub(crate) fn ready_now(&self) -> bool {
        !self.started.load(Ordering::Acquire) || self.ready.is_cancelled()
    }

    /// Reserve before spawning: raw frames never wait for a Lookup or queue
    /// unbounded tasks behind the shared outstanding-Lookup limit.
    pub(crate) fn spawn_lookup(self: &Arc<Self>, agent: AgentId, machine: MachineId) {
        let Some(permit) = self.lookup_permit() else {
            return;
        };
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            runtime
                .lookup_with_permit(agent, Some(machine), permit)
                .await;
        });
    }

    fn lookup_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let permit = self.wire_limits.try_lookup_permit();
        if permit.is_none() {
            self.evidence_lookup_skipped.fetch_add(1, Ordering::Relaxed);
        }
        permit
    }

    async fn lookup_with_permit(
        &self,
        agent: AgentId,
        machine: Option<MachineId>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        // Only the raw receive path supplies a transport-authenticated machine.
        // Its claimed agent is a routing hint, never evidence authority.
        if let Some(machine) = machine {
            self.lookup_hints.record(agent, machine);
        }
        let now = crate::dm_capability::now_unix_ms();
        let usable = match machine {
            Some(machine) => self.usable(agent, machine, now),
            None => self.usable_agent(agent, now),
        };
        if usable.is_some() {
            return;
        }
        #[cfg(test)]
        if let Some(responder) = self.lookup_responder.get() {
            responder(agent).await;
            return;
        }
        if let Some(context) = self.lookup_context.get().and_then(std::sync::Weak::upgrade) {
            context.lookup(agent, permit).await;
        }
    }
    /// Start exactly one background re-verification; invalid files stay untouched.
    pub(crate) fn start(
        self: &Arc<Self>,
        dir: PathBuf,
        config: EvidenceConfig,
        policy: Arc<dyn EvidencePolicy>,
        wire: Arc<VerifiedWireCapture>,
    ) -> bool {
        if self.started.swap(true, Ordering::AcqRel) {
            return false;
        }
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            match PeerEvidenceStore::open(&dir, config, policy, crate::dm_capability::now_unix_ms())
            {
                Ok(store) => {
                    let store = Arc::new(store);
                    let _ = this.store.set(Arc::clone(&store));
                    let now = crate::dm_capability::now_unix_ms();
                    for agent in wire.agents(now) {
                        if let (Some(view), Some(advert)) =
                            (store.usable_agent(agent, now), wire.get(agent, false, now))
                        {
                            let _ = store.ingest_move_advert(
                                &advert,
                                &view.announcement.agent_public_key,
                                now,
                            );
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "peer evidence load failed closed"),
            }
            this.ready.cancel();
        });
        true
    }
    /// Await load within the frame/byte cap. Cancellation releases both permits.
    pub async fn wait(&self, bytes: usize) -> bool {
        if self.ready.is_cancelled() {
            return true;
        }
        if !self.started.load(Ordering::Acquire) {
            return true;
        }
        let Ok(_frame) = self.frames.try_acquire() else {
            self.evidence_barrier_overflow
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let Ok(bytes) = u32::try_from(bytes) else {
            self.evidence_barrier_overflow
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let Ok(_bytes) = self.bytes.try_acquire_many(bytes) else {
            self.evidence_barrier_overflow
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };
        self.evidence_load_barrier_waits
            .fetch_add(1, Ordering::Relaxed);
        if tokio::time::timeout(std::time::Duration::from_secs(5), self.ready.cancelled())
            .await
            .is_err()
        {
            self.evidence_barrier_timeout
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }
    /// Exact-pair lookup. The result must never be installed in another cache.
    pub fn usable(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
    ) -> Option<Arc<EvidenceView>> {
        if !self.ready.is_cancelled() {
            return None;
        }
        self.store.get()?.usable(agent, machine, now)
    }
    /// [`Self::usable`] without blocking on the store lock or a policy read
    /// (x0x #1207); `Err(())` while a lock is contended.
    pub(crate) fn try_usable(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
    ) -> std::result::Result<Option<Arc<EvidenceView>>, ()> {
        if !self.ready.is_cancelled() {
            return Ok(None);
        }
        match self.store.get() {
            Some(store) => store.try_usable(agent, machine, now),
            None => Ok(None),
        }
    }
    /// Resolve a recipient when its live sources are empty.
    pub fn usable_agent(&self, agent: AgentId, now: u64) -> Option<Arc<EvidenceView>> {
        if !self.ready.is_cancelled() {
            return None;
        }
        self.store.get()?.usable_agent(agent, now)
    }
    /// [`Self::usable_agent`] without blocking on the store lock (x0x #1150
    /// r7b); `Err(())` while the lock is contended.
    pub(crate) fn try_usable_agent(
        &self,
        agent: AgentId,
        now: u64,
    ) -> std::result::Result<Option<Arc<EvidenceView>>, ()> {
        if !self.ready.is_cancelled() {
            return Ok(None);
        }
        match self.store.get() {
            Some(store) => store.try_usable_agent(agent, now),
            None => Ok(None),
        }
    }
    /// Startup, barrier and persistence diagnostics.
    pub fn diagnostics(&self) -> serde_json::Value {
        let mut value = self
            .store
            .get()
            .and_then(|s| s.counters().ok())
            .and_then(|c| serde_json::to_value(c).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        value["evidence_load_complete"] = self.ready.is_cancelled().into();
        value["evidence_load_barrier_waits"] = self
            .evidence_load_barrier_waits
            .load(Ordering::Relaxed)
            .into();
        value["evidence_barrier_timeout"] =
            self.evidence_barrier_timeout.load(Ordering::Relaxed).into();
        value["evidence_barrier_overflow"] = self
            .evidence_barrier_overflow
            .load(Ordering::Relaxed)
            .into();
        value["evidence_lookup_skipped"] =
            self.evidence_lookup_skipped.load(Ordering::Relaxed).into();
        // ADR 0089 S5: the wire counters (hello/lookup/bytes/verifies)
        // ride the same `peer_evidence` diagnostics object.
        let wire = self.wire_limits.counters.json();
        if let Some(object) = wire.as_object() {
            for (key, counter) in object {
                value[key.clone()] = counter.clone();
            }
        }
        value
    }
    pub(crate) fn store(&self) -> Option<Arc<PeerEvidenceStore>> {
        self.store.get().cloned()
    }
    pub(crate) fn observe_advert(&self, wire: &[u8], key: &[u8]) {
        if let Some(store) = self.store() {
            // This synchronous transaction suspends old authority before a move
            // is accepted; disk failure deliberately leaves it suspended.
            let _ = store.ingest_move_advert(wire, key, crate::dm_capability::now_unix_ms());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn s2_load_barrier_hold_release_timeout_and_overflow() {
        use futures::FutureExt;
        let runtime = EvidenceRuntime::default();
        runtime.started.store(true, Ordering::Release);
        let waits: Vec<_> = (0..64).map(|_| runtime.wait(16 * 1024)).collect();
        let mut waits = Box::pin(futures::future::join_all(waits));
        assert!(waits.as_mut().now_or_never().is_none());
        assert!(!runtime.wait(1).await);
        assert_eq!(runtime.evidence_barrier_overflow.load(Ordering::Relaxed), 1);
        runtime.ready.cancel();
        assert!(waits.await.iter().all(|v| *v));
        assert_eq!(runtime.frames.available_permits(), 64);
        assert_eq!(runtime.bytes.available_permits(), 1024 * 1024);

        let runtime = EvidenceRuntime::default();
        runtime.started.store(true, Ordering::Release);
        assert!(!runtime.wait(1024 * 1024 + 1).await);
        let mut wait = Box::pin(runtime.wait(0));
        assert!(wait.as_mut().now_or_never().is_none());
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        assert!(!wait.await);
        assert_eq!(runtime.evidence_barrier_timeout.load(Ordering::Relaxed), 1);
        runtime.ready.cancel();
        assert!(runtime.wait(0).await, "retry after load succeeds");
    }
}
