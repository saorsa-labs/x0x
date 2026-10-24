//! Runtime load barrier and live policy adapters. No derived authority is seeded.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Live group membership predicate. A busy/missing policy fails closed.
pub(crate) type GroupContext = dyn Fn(AgentId, AgentId) -> Option<bool> + Send + Sync;

type GroupPolicy = dyn Fn(AgentId) -> Option<bool> + Send + Sync;

/// One grace for the closed registry, including cancelled/repeated drains.
/// The deadline is absolute and fixed by the first drain call, so no caller
/// can extend it. Five seconds matches the history-writer drain allowance;
/// it is an internal cleanup budget, not a wire, storage or API constant.
/// Unfinished workers stay in custody after the deadline (permits held, not
/// marked complete) and are reported to `Agent::try_shutdown` by count.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Admission and handle custody share one lock. No worker can be spawned
/// between closing the registry and observing that its join set is empty.
#[derive(Default)]
struct EvidenceWorkers {
    closed: bool,
    shutdown_deadline: Option<tokio::time::Instant>,
    tasks: tokio::task::JoinSet<()>,
}

struct AbortWorkerOnDrop(tokio::task::AbortHandle);

impl Drop for AbortWorkerOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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
    #[cfg(test)]
    pub(crate) evidence_dial: std::sync::OnceLock<Arc<LookupResponder>>,
    reads: Arc<tokio::sync::Semaphore>,
    workers: std::sync::Mutex<EvidenceWorkers>,
    stopping: tokio_util::sync::CancellationToken,
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
    /// Load barriers or send evidence budgets that reached their deadline.
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
            #[cfg(test)]
            evidence_dial: Default::default(),
            reads: Arc::new(tokio::sync::Semaphore::new(16)),
            workers: Default::default(),
            stopping: Default::default(),
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
    fn workers(&self) -> std::sync::MutexGuard<'_, EvidenceWorkers> {
        self.workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn spawn_blocking_worker<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> std::result::Result<(tokio::sync::oneshot::Receiver<T>, tokio::task::AbortHandle), ()>
    {
        let mut workers = self.workers();
        if workers.closed {
            return Err(());
        }
        // Join completed tasks on admission so the retained set stays bounded
        // by live work, rather than by the lifetime count of sends.
        while workers.tasks.try_join_next().is_some() {}
        let (send, receive) = tokio::sync::oneshot::channel();
        let abort = workers.tasks.spawn_blocking(move || {
            let _ = send.send(work());
        });
        Ok((receive, abort))
    }

    fn spawn_lookup_worker(&self, work: impl std::future::Future<Output = ()> + Send + 'static) {
        // #1239: a background task still blocks Tokio if its evidence or
        // responder-policy reads take a synchronous lock. Keep the entire
        // Lookup on a tracked blocking worker, as for lookup_before. Both
        // callers reserve a Lookup permit before this call; a running read
        // retains that permit and its join handle through shutdown's grace.
        let executor = tokio::runtime::Handle::current();
        let stopping = self.stopping.clone();
        let _ = self.spawn_blocking_worker(move || {
            executor.block_on(async move {
                tokio::select! {
                    biased;
                    _ = stopping.cancelled() => {},
                    _ = work => {},
                }
            });
        });
    }

    /// Close admission and cancel queued/async work, then join within one grace.
    /// Poll the owned set in place: cancelling this shutdown future never
    /// takes or drops a handle or resets the deadline. Started synchronous
    /// reads cannot be aborted. Return their unfinished count after the grace,
    /// retaining custody so a later Agent shutdown can observe completion.
    pub(crate) async fn shutdown_workers(&self) -> usize {
        let deadline = {
            let mut workers = self.workers();
            workers.closed = true;
            self.reads.close();
            self.stopping.cancel();
            workers.tasks.abort_all();
            *workers
                .shutdown_deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + SHUTDOWN_GRACE)
        };
        let drain = futures::future::poll_fn(|cx| {
            let mut workers = self.workers();
            loop {
                match workers.tasks.poll_join_next(cx) {
                    std::task::Poll::Ready(Some(_)) => continue,
                    std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
        });
        // timeout_at polls the drain first, even past the deadline. Repeated
        // calls can therefore reap finished workers without another grace.
        if tokio::time::timeout_at(deadline, drain).await.is_ok() {
            0
        } else {
            self.workers().tasks.len()
        }
    }

    /// Install a live shared-roster predicate, including local membership.
    /// Unavailable policy reads fail closed; no membership snapshot is cached.
    pub fn set_group_context(&self, context: Arc<GroupContext>) {
        if let Ok(mut slot) = self.group_context.write() {
            *slot = Some(context);
        }
    }
    /// Pull missing relationship evidence over bounded connected-peer streams.
    /// Callers must re-read their authoritative sources after this await.
    /// #1239: this inline variant blocks its caller's Tokio worker on the
    /// synchronous store and policy reads; every production caller now uses
    /// [`Self::lookup_before`]. Test-only, as a stand-in for an awaited sender.
    #[cfg(test)]
    pub(crate) async fn lookup(&self, agent: AgentId, machine: Option<MachineId>) {
        let Some(permit) = self.lookup_permit() else {
            return;
        };
        self.lookup_with_permit(agent, machine, permit, None).await;
    }

    /// #1239: Lookup's store and responder-policy reads are synchronous.
    /// The entire Lookup stays on this worker because responder selection and
    /// exchanges share synchronous policy reads in evidence_wire::lookup.
    /// The awaiting caller keeps driving I/O and timers, including on a
    /// current-thread runtime. The caller's absolute deadline also applies.
    /// Reserve the existing Lookup permit before spawning: even workers that
    /// cannot leave a synchronous read yet stay within the 16-Lookup cap.
    /// `machine` is only the transport-observed routing hint recorded by
    /// [`Self::lookup`]; it is never evidence authority.
    pub(crate) async fn lookup_before(
        self: &Arc<Self>,
        agent: AgentId,
        machine: Option<MachineId>,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), ()> {
        if self.stopping.is_cancelled() || tokio::time::Instant::now() >= deadline {
            return Err(());
        }
        let Some(permit) = self.lookup_permit() else {
            return Ok(());
        };
        let runtime = Arc::clone(self);
        let executor = tokio::runtime::Handle::current();
        let cancelled = tokio_util::sync::CancellationToken::new();
        let _cancel = cancelled.clone().drop_guard();
        let stopping = self.stopping.clone();
        let (result, abort) = self.spawn_blocking_worker(move || {
            executor.block_on(async move {
                tokio::select! {
                    biased;
                    _ = stopping.cancelled() => Err(()),
                    _ = cancelled.cancelled() => Err(()),
                    result = async {
                        if tokio::time::Instant::now() >= deadline {
                            return Err(());
                        }
                        tokio::time::timeout_at(
                            deadline,
                            runtime.lookup_with_permit(agent, machine, permit, Some(deadline)),
                        )
                        .await
                        .map_err(|_| ())?;
                        if tokio::time::Instant::now() >= deadline {
                            return Err(());
                        }
                        Ok(())
                    } => result,
                }
            })
        })?;
        let _abort = AbortWorkerOnDrop(abort);
        // Dropping a queued worker aborts it. A running synchronous read cannot
        // be aborted; its permit stays held until it exits, and the deadline
        // checks below prevent a late read from starting a new exchange.
        // Cancellation also wakes an async worker without needing a timer
        // driver after the caller returns (notably on current-thread runtimes).
        // The caller owns only the result receiver and abort guard; the join
        // handle remains in the registry through deadline/caller cancellation.
        tokio::time::timeout_at(deadline, result)
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?
    }

    /// Wait for a synchronous point-of-use read within the send's budget.
    /// Reserve before spawning, so reads stuck behind a store writer cannot
    /// grow the blocking pool without bound. Cancellation aborts queued work;
    /// a running read keeps its permit until it leaves the synchronous lock.
    pub(crate) async fn usable_before(
        self: &Arc<Self>,
        agent: AgentId,
        machine: Option<MachineId>,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Option<Arc<EvidenceView>>, ()> {
        self.read_before(deadline, move |runtime| {
            let now = crate::dm_capability::now_unix_ms();
            match machine {
                Some(machine) => runtime.usable(agent, machine, now),
                None => runtime.usable_agent(agent, now),
            }
        })
        .await
    }

    /// The ordinary authority check uses the same bounded readers as send
    /// evidence, without changing the store's evidence-use counters.
    pub(crate) async fn confirms_pairing_before(
        self: &Arc<Self>,
        agent: AgentId,
        machine: MachineId,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<bool, ()> {
        self.read_before(deadline, move |runtime| {
            runtime.confirms_pairing(agent, machine, crate::dm_capability::now_unix_ms())
        })
        .await
    }

    /// Admission, the synchronous read and its result share one deadline.
    /// Both read kinds retain the existing 16-reader cap, cancellation guard
    /// and shutdown custody, including when a running read cannot stop yet.
    async fn read_before<T: Send + 'static>(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
        read: impl FnOnce(&Self) -> T + Send + 'static,
    ) -> std::result::Result<T, ()> {
        let work = async {
            let permit = Arc::clone(&self.reads)
                .acquire_owned()
                .await
                .map_err(|_| ())?;
            let runtime = Arc::clone(self);
            let (result, abort) = self.spawn_blocking_worker(move || {
                let _permit = permit;
                if tokio::time::Instant::now() >= deadline {
                    return Err(());
                }
                Ok(read(&runtime))
            })?;
            let _abort = AbortWorkerOnDrop(abort);
            let value = result.await.map_err(|_| ())??;
            if tokio::time::Instant::now() >= deadline {
                return Err(());
            }
            Ok(value)
        };
        tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| ())?
    }

    /// #1239: run one async authority evaluation whose body takes
    /// synchronous std-lock policy reads (the Lookup responder's
    /// `Relations::shared` reads) so it cannot occupy a Tokio worker. The
    /// evaluation runs on a tracked blocking worker; admission, the
    /// evaluation and its result share one absolute `deadline`, and the
    /// deadline plus shutdown cancellation also apply INSIDE the worker, so
    /// an async lock wait cannot pin the worker and its reader permit past
    /// the budget. Readers reserve from the same 16-permit cap as the send
    /// evidence reads, so evaluations queued behind a held lock cannot grow
    /// the blocking pool without bound. Dropping the caller aborts a queued
    /// worker; only a synchronous read already inside a store lock can
    /// outlive the deadline, keeping its permit and join handle through the
    /// shutdown grace, exactly as the evidence readers.
    pub(crate) async fn evaluate_before<T: Send + 'static>(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> std::result::Result<T, ()> {
        let evaluation = async {
            let permit = Arc::clone(&self.reads)
                .acquire_owned()
                .await
                .map_err(|_| ())?;
            let executor = tokio::runtime::Handle::current();
            let stopping = self.stopping.clone();
            let (result, abort) = self.spawn_blocking_worker(move || {
                let _permit = permit;
                if tokio::time::Instant::now() >= deadline {
                    return Err(());
                }
                executor.block_on(async {
                    tokio::select! {
                        biased;
                        _ = stopping.cancelled() => Err(()),
                        _ = tokio::time::sleep_until(deadline) => Err(()),
                        value = work => Ok(value),
                    }
                })
            })?;
            let _abort = AbortWorkerOnDrop(abort);
            let value = result.await.map_err(|_| ())??;
            if tokio::time::Instant::now() >= deadline {
                return Err(());
            }
            Ok(value)
        };
        tokio::time::timeout_at(deadline, evaluation)
            .await
            .map_err(|_| ())?
    }

    /// #1239 test seam: whether every bounded reader permit has returned.
    #[cfg(test)]
    pub(crate) fn readers_idle_for_testing(&self) -> bool {
        self.reads.available_permits() == 16
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
        self.spawn_lookup_worker(async move {
            if runtime.wait(0).await {
                runtime.lookup_with_permit(agent, None, permit, None).await;
            }
        });
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
        self.spawn_lookup_worker(async move {
            runtime
                .lookup_with_permit(agent, Some(machine), permit, None)
                .await;
        });
    }

    fn lookup_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if self.stopping.is_cancelled() {
            return None;
        }
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
        deadline: Option<tokio::time::Instant>,
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
        if self.stopping.is_cancelled()
            || usable.is_some()
            || deadline.is_some_and(|d| tokio::time::Instant::now() >= d)
        {
            return;
        }
        #[cfg(test)]
        if let Some(responder) = self.lookup_responder.get() {
            responder(agent).await;
            return;
        }
        if let Some(context) = self.lookup_context.get().and_then(std::sync::Weak::upgrade) {
            context.lookup(agent, permit, deadline).await;
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
        self.spawn_blocking_worker(move || {
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
        })
        .is_ok()
    }
    /// True after load and captured move adverts have both been applied.
    /// This non-blocking probe does not enter or charge the load barrier.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.is_cancelled()
    }

    #[cfg(test)]
    pub(crate) fn loading_store_for_test(
        store: Arc<PeerEvidenceStore>,
    ) -> (Arc<Self>, tokio_util::sync::CancellationToken) {
        let runtime = Arc::new(Self::default());
        runtime.started.store(true, Ordering::Release);
        assert!(runtime.store.set(store).is_ok());
        let ready = runtime.ready.clone();
        (runtime, ready)
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
    /// ADR 0115 §2: whether a usable record exists for exactly
    /// (agent, machine), without the store's use counters.
    pub(crate) fn confirms_pairing(&self, agent: AgentId, machine: MachineId, now: u64) -> bool {
        self.ready.is_cancelled()
            && self
                .store
                .get()
                .is_some_and(|store| store.confirms_pairing(agent, machine, now))
    }
    /// [`Self::confirms_pairing`] for synchronous seams: `None` while a lock
    /// is contended.
    pub(crate) fn try_confirms_pairing(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
    ) -> Option<bool> {
        if !self.ready.is_cancelled() {
            return Some(false);
        }
        match self.store.get() {
            Some(store) => store.try_confirms_pairing(agent, machine, now),
            None => Some(false),
        }
    }
    /// ADR 0115 §3: the owner certificate of `agent`'s usable
    /// record, if any, without the store's use counters.
    pub(crate) fn usable_certificate(
        &self,
        agent: AgentId,
        now: u64,
    ) -> Option<crate::identity::AgentCertificate> {
        if !self.ready.is_cancelled() {
            return None;
        }
        self.store.get()?.usable_certificate(agent, now)
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

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Deliberately stall the actual load worker.
    async fn started_store_load_has_bounded_shutdown_with_retained_custody() {
        struct NoPeers;
        impl EvidencePolicy for NoPeers {
            fn relation(
                &self,
                _: AgentId,
                _: MachineId,
                _: Option<&AgentCertificate>,
                _: u64,
            ) -> u8 {
                0
            }
            fn revoked(&self, _: AgentId, _: MachineId, _: Option<UserId>) -> bool {
                false
            }
            fn contains_agent(&self, _: AgentId, _: u64) -> bool {
                false
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(EvidenceRuntime::default());
        let wire = Arc::new(VerifiedWireCapture::default());
        // The actual store-load worker publishes its store before consulting
        // captured adverts. Hold that real synchronous read through shutdown.
        let held = wire.inner.lock().unwrap();
        assert!(runtime.start(
            dir.path().to_path_buf(),
            EvidenceConfig::default(),
            Arc::new(NoPeers),
            Arc::clone(&wire),
        ));
        let loaded = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while runtime.store().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        tokio::time::pause();
        let mut shutdown = Box::pin(runtime.shutdown_workers());
        let initially_pending = futures::poll!(&mut shutdown).is_pending();
        tokio::time::advance(std::time::Duration::from_millis(5001)).await;
        let ended = futures::poll!(&mut shutdown).is_ready();
        drop(shutdown);
        let retained = runtime.workers().tasks.len();
        let ready = runtime.is_ready();
        drop(held);
        tokio::time::resume();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                runtime.shutdown_workers().await;
                if runtime.workers().tasks.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(loaded.is_ok(), "store load never entered the held read");
        assert!(initially_pending, "store-load worker was not joined");
        assert!(ended, "store-load worker kept shutdown past its grace");
        assert_eq!(retained, 1, "unfinished load lost its worker handle");
        assert!(!ready, "held load was incorrectly marked ready");
        assert!(runtime.is_ready());
        assert_eq!(Arc::strong_count(&runtime), 1);
    }

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
