//! Relationship-context pull. Routing hints never become evidence authority.
use super::*;
use crate::identity::AgentCertificate;
use std::collections::HashSet;

const LOOKUP_INTERVAL: Duration = Duration::from_secs(30);
const FANOUT: usize = 3;
// A hostile host may accumulate arbitrarily many co-resident identities.
// Bound each indexed source as well as fan-out; excess candidates fail closed.
const MACHINE_BINDING_LIMIT: usize = 16;
const HINT_CAP: usize = 128;

/// Untrusted, process-only raw-frame routing claims. Never read by authority paths.
#[derive(Default)]
pub(crate) struct RoutingHints(Mutex<VecDeque<(AgentId, MachineId, Instant)>>);
impl RoutingHints {
    pub(crate) fn record(&self, agent: AgentId, machine: MachineId) {
        let Ok(mut hints) = self.0.lock() else {
            return;
        };
        let now = Instant::now();
        hints.retain(|(a, m, at)| {
            now.duration_since(*at) < Duration::from_millis(W_MS) && (*a != agent || *m != machine)
        });
        if hints.len() == HINT_CAP {
            hints.pop_front();
        }
        hints.push_back((agent, machine, now));
    }

    fn machines(&self, target: AgentId) -> Vec<MachineId> {
        let Ok(mut hints) = self.0.lock() else {
            return Vec::new();
        };
        let now = Instant::now();
        hints.retain(|(_, _, at)| now.duration_since(*at) < Duration::from_millis(W_MS));
        // Reads refresh LRU order, never the freshness deadline.
        let mut matches = VecDeque::new();
        hints.retain(|(a, m, at)| {
            if *a == target {
                matches.push_back((*a, *m, *at));
                false
            } else {
                true
            }
        });
        let machines = matches.iter().map(|(_, m, _)| *m).collect();
        hints.extend(matches);
        machines
    }
}

#[derive(Serialize)]
pub(super) struct Found {
    announcement: Vec<u8>,
    advert: Vec<u8>,
    certificate: Option<Vec<u8>>,
}
impl From<EvidenceRecordV1> for Found {
    fn from(record: EvidenceRecordV1) -> Self {
        Self {
            announcement: record.announcement,
            advert: record.advert,
            certificate: record.certificate,
        }
    }
}

impl Limits {
    pub(crate) fn try_lookup_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.lookups).try_acquire_owned().ok()
    }

    fn claim_target(&self, target: AgentId) -> bool {
        let now = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state
            .targets
            .retain(|_, at| now.duration_since(*at) < LOOKUP_INTERVAL);
        if state.targets.contains_key(&target) || state.targets.len() >= MACHINE_CAP {
            return false;
        }
        state.targets.insert(target, now);
        true
    }
    #[cfg(test)]
    fn begin_lookup(&self, target: AgentId) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.lookups).try_acquire_owned().ok()?;
        self.claim_target(target).then_some(permit)
    }
}

#[derive(Clone)]
struct Peer {
    agent: AgentId,
    machine: MachineId,
    cert: Option<AgentCertificate>,
}

/// Deduplicate transport identities, prefer X's own host, then cap the fan-out.
fn select(
    target: AgentId,
    peers: impl IntoIterator<Item = (AgentId, MachineId)>,
) -> Vec<MachineId> {
    let mut peers: Vec<_> = peers.into_iter().collect();
    peers.sort_by_key(|(agent, machine)| (*agent != target, machine.0));
    let mut seen = HashSet::new();
    peers
        .into_iter()
        .filter_map(|(_, m)| seen.insert(m).then_some(m))
        .take(FANOUT)
        .collect()
}

struct Relations {
    runtime: Arc<EvidenceRuntime>,
    local: Peer,
    bindings: crate::dm_inbox::AuthenticatedMachineBindings,
    discovery: Arc<tokio::sync::RwLock<HashMap<AgentId, crate::DiscoveredAgent>>>,
    machines: Arc<tokio::sync::RwLock<HashMap<MachineId, crate::DiscoveredMachine>>>,
    #[cfg(test)]
    peer_checks: std::sync::atomic::AtomicUsize,
    owner: crate::owner_trust::OwnerTrust,
    revoked: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
}
impl Relations {
    async fn peer(&self, agent: AgentId) -> Option<Peer> {
        #[cfg(test)]
        self.peer_checks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if agent == self.local.agent {
            return Some(self.local.clone());
        }
        let now = dm_capability::now_unix_ms();
        let binding =
            crate::dm_inbox::authenticated_machine_binding_evidence(&self.bindings, &agent).await;
        // ADR 0115 §2: the authenticated binding names the
        // machine whenever it exists, and a routing entry stands for the
        // peer only when an authority store confirms its machine. The
        // stores are read before the discovery cache (r7g lock order).
        let routing = self
            .discovery
            .read()
            .await
            .get(&agent)
            .map(|d| d.machine_id);
        let routing_confirmed = match routing {
            Some(machine) => {
                binding.is_some_and(|b| b.machine_id == machine)
                    || self.owner.announced_machine(&agent).await == Some(machine)
                    || self.runtime.confirms_pairing(agent, machine, now)
            }
            None => false,
        };
        let cache = self.discovery.read().await;
        let cached = cache
            .get(&agent)
            .filter(|d| routing_confirmed && Some(d.machine_id) == routing);
        let stored = self.runtime.usable_agent(agent, now);
        let machine = if let Some(b) = binding {
            b.machine_id
        } else if let Some(d) = cached {
            d.machine_id
        } else {
            stored.as_ref()?.announcement.machine_id
        };
        if !crate::raw_delivery_with_evidence(
            cached,
            binding,
            Some(&self.runtime),
            agent,
            machine,
            now,
        )
        .0
        {
            return None;
        }
        let cert = cached
            .and_then(|d| d.agent_certificate.clone())
            .or_else(|| stored.and_then(|v| v.certificate.clone()));
        drop(cache);
        let revoked = self.revoked.read().await;
        if revoked.is_agent_revoked(&agent)
            || revoked.is_machine_revoked(&machine)
            || revoked.is_binding_revoked(&agent, &machine)
        {
            return None;
        }
        Some(Peer {
            agent,
            machine,
            cert,
        })
    }

    fn shared(&self, a: &Peer, b: &Peer) -> bool {
        let now = dm_capability::now_unix_ms();
        let Ok(revoked) = self.revoked.try_read() else {
            return false;
        };
        if [a, b].iter().any(|p| {
            revoked.is_agent_revoked(&p.agent)
                || revoked.is_machine_revoked(&p.machine)
                || revoked.is_binding_revoked(&p.agent, &p.machine)
        }) {
            return false;
        }
        if self
            .runtime
            .group_context
            .read()
            .ok()
            .and_then(|g| g.clone())
            .is_some_and(|g| g(a.agent, b.agent) == Some(true))
        {
            return true;
        }
        let enrolled = |p: &Peer| {
            self.owner
                .evidence_relation(p.agent, p.machine, p.cert.as_ref(), &revoked, now)
                .is_some_and(|flags| flags & crate::peer_evidence::ENROLLED != 0)
        };
        (enrolled(a) && enrolled(b))
            || self.owner.share_grant_store().is_some_and(|g| {
                g.evidence_context(
                    a.agent,
                    a.cert.as_ref(),
                    b.agent,
                    b.cert.as_ref(),
                    &revoked,
                    now / 1000,
                )
            })
    }

    async fn machine_agents(&self, machine: MachineId) -> HashSet<AgentId> {
        let mut agents: HashSet<_> = self
            .bindings
            .read()
            .await
            .agents_on_machine(machine, MACHINE_BINDING_LIMIT)
            .into_iter()
            .collect();
        if let Some(entry) = self.machines.read().await.get(&machine) {
            agents.extend(entry.agent_ids.iter().take(MACHINE_BINDING_LIMIT).copied());
        }
        if let Some(store) = self.runtime.store() {
            agents.extend(store.agents_on_machine(machine, MACHINE_BINDING_LIMIT));
        }
        agents
    }

    async fn responders(&self, target: AgentId, connected: &HashSet<MachineId>) -> Vec<MachineId> {
        let target_peer = self.peer(target).await.unwrap_or(Peer {
            agent: target,
            machine: MachineId([0; 32]),
            cert: None,
        });
        if !self.shared(&self.local, &target_peer) {
            return Vec::new();
        }
        let mut eligible = Vec::new();
        for machine in connected {
            for agent in self.machine_agents(*machine).await {
                let Some(peer) = self.peer(agent).await else {
                    continue;
                };
                if peer.machine == *machine
                    && self.shared(&self.local, &peer)
                    && (agent == target || self.shared(&peer, &target_peer))
                {
                    eligible.push((agent, *machine));
                }
            }
        }
        // A claim can route ONLY a query for the claimed agent itself. It
        // neither authorizes an inbound Lookup nor vouches for the reply.
        // Untrusted claims must not displace a connected, verified own host.
        if !eligible.iter().any(|(agent, _)| *agent == target) {
            for machine in self.runtime.lookup_hints.machines(target) {
                if connected.contains(&machine) {
                    let hint = Peer {
                        agent: target,
                        machine,
                        cert: None,
                    };
                    if self.shared(&self.local, &hint) {
                        eligible.push((target, machine));
                    }
                }
            }
        }
        select(target, eligible)
    }

    pub(super) async fn authorized(&self, machine: MachineId, target: AgentId) -> bool {
        let Some(local) = self.peer(self.local.agent).await else {
            return false;
        };
        let target = self.peer(target).await.unwrap_or(Peer {
            agent: target,
            machine: MachineId([0; 32]),
            cert: None,
        });
        for agent in self.machine_agents(machine).await {
            let Some(requester) = self.peer(agent).await else {
                continue;
            };
            if requester.machine == machine
                && self.shared(&local, &requester)
                && self.shared(&requester, &target)
            {
                return true;
            }
        }
        false
    }
}

struct ResetOnDrop {
    limits: Arc<Limits>,
    machine: MachineId,
    complete: bool,
}
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if !self.complete {
            self.limits.reset(self.machine);
        }
    }
}

impl Context {
    fn relations(&self) -> Option<Relations> {
        Some(Relations {
            runtime: Arc::clone(&self.runtime),
            local: Peer {
                agent: self.identity.agent_id(),
                machine: self.identity.machine_id(),
                cert: self.own_cert.read().ok()?.1.clone(),
            },
            bindings: Arc::clone(&self.bindings),
            discovery: Arc::clone(&self.discovery),
            machines: Arc::clone(&self.machines),
            #[cfg(test)]
            peer_checks: Default::default(),
            owner: self.owner.clone(),
            revoked: Arc::clone(&self.revoked),
        })
    }
    pub(super) async fn authorized(&self, machine: MachineId, target: AgentId) -> bool {
        match self.relations() {
            Some(relations) => relations.authorized(machine, target).await,
            None => false,
        }
    }
    pub(super) fn lookup_reply(&self, target: AgentId) -> io::Result<Option<Found>> {
        reply_material(
            target,
            self.identity.agent_id(),
            self.runtime.store().as_deref(),
            dm_capability::now_unix_ms(),
            || self.own(None, true),
        )
    }

    pub(crate) async fn lookup(
        self: Arc<Self>,
        target: AgentId,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let deadline = Instant::now() + DEADLINE;
        let _ = tokio::time::timeout_at(deadline, async {
            let Some(relations) = self.relations() else {
                return;
            };
            let connected: HashSet<_> = self
                .network
                .connected_peers()
                .await
                .into_iter()
                .map(|m| MachineId(m.0))
                .collect();
            let responders = relations.responders(target, &connected).await;
            // ADR 0089 S5 / ADR 0093 bit 2: never spend a Lookup on a
            // machine whose current verified advert lacks
            // `peer_evidence_v1`; unknown adverts still get the try.
            let responders: Vec<_> = responders
                .into_iter()
                .filter(|machine| {
                    self.caps.machine_registry_supports(
                        machine,
                        crate::dm::CapabilityRegistry::PEER_EVIDENCE_V1,
                    ) != Some(false)
                })
                .collect();
            // A pre-seat send or a disconnected peer must not consume the
            // target cooldown: no Lookup has been sent yet (D30 30b).
            if responders.is_empty() || !self.runtime.wire_limits.claim_target(target) {
                return;
            }
            // No task queue: at most three exchanges, each also needing the
            // shared machine stream and aggregate allocation reservations.
            let mut requests = futures::stream::FuturesUnordered::new();
            let permit = Arc::new(permit);
            for machine in responders {
                requests.push(self.pull(machine, target, deadline, Arc::clone(&permit)));
            }
            use futures::StreamExt;
            while let Some(result) = requests.next().await {
                if result.is_ok() {
                    break;
                }
            }
        })
        .await;
    }

    async fn pull(
        &self,
        machine: MachineId,
        target: AgentId,
        deadline: Instant,
        permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    ) -> io::Result<()> {
        let lease = self
            .runtime
            .wire_limits
            // Lookup targets are chosen only from relationship-context
            // peers, so the pull runs in the reserved (non-stranger) pool.
            .admit(machine, true)
            .ok_or_else(|| invalid("lookup stream budget"))?;
        let mut reset = ResetOnDrop {
            limits: Arc::clone(&self.runtime.wire_limits),
            machine,
            complete: false,
        };
        let result = tokio::time::timeout_at(deadline.min(lease.deadline), async {
            let (mut send, mut recv) = self
                .network
                .open_bi(&ant_quic::PeerId(machine.0))
                .await
                .map_err(io::Error::other)?;
            send.write_u8(StreamProtocol::EvidenceV1.as_u8()).await?;
            let body = codec().serialize(&target).map_err(io::Error::other)?;
            write_message(&mut send, &self.runtime.wire_limits, machine, LOOKUP, &body).await?;
            let (kind, body) = read_message(&mut recv, &self.runtime.wire_limits).await?;
            if kind != FOUND {
                return Err(invalid("lookup not found"));
            }
            let record = decode::found(&body)?;
            drop(body);
            let store = self
                .runtime
                .store()
                .ok_or_else(|| invalid("evidence store unavailable"))?;
            let limits = Arc::clone(&self.runtime.wire_limits);
            tokio::task::spawn_blocking(move || {
                // Cancellation cannot release the reservations underneath a
                // still-running verify or durable move write.
                let (_lease, _permit) = (lease, permit);
                ingest_found(
                    &store,
                    &limits,
                    target,
                    record,
                    dm_capability::now_unix_ms(),
                )
            })
            .await
            .map_err(io::Error::other)?
        })
        .await
        .map_err(io::Error::other)?;
        reset.complete = result.is_ok();
        result
    }
}

fn ingest_found(
    store: &crate::peer_evidence::PeerEvidenceStore,
    limits: &Limits,
    target: AgentId,
    record: EvidenceRecordV1,
    now: u64,
) -> io::Result<()> {
    decode::parts(
        &record.announcement,
        &record.advert,
        record.certificate.as_deref(),
    )?;
    if !limits.verify() {
        return Err(invalid("evidence verify budget"));
    }
    let view = Arc::new(record.verify(now, W_MS).map_err(io::Error::other)?);
    if view.announcement.agent_id != target {
        return Err(invalid("lookup target mismatch"));
    }
    let user = view
        .certificate
        .as_ref()
        .and_then(|cert| cert.user_id().ok());
    if announce_v3::cert_digest(&user, &view.certificate) != view.announcement.cert_digest {
        return Err(invalid("certificate digest mismatch"));
    }
    store
        .ingest_verified(record, view, IngestSource::Gossip, now)
        .map_err(io::Error::other)
}

fn reply_material(
    target: AgentId,
    local: AgentId,
    store: Option<&crate::peer_evidence::PeerEvidenceStore>,
    now: u64,
    mint: impl FnOnce() -> io::Result<Hello>,
) -> io::Result<Option<Found>> {
    if target == local {
        return mint().map(|hello| Some(hello.into_record().into()));
    }
    // The persisted map is intentionally not consulted, even within L.
    Ok(store.and_then(|s| s.live(target, now)).map(Found::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{AgentKeypair, Identity, MachineKeypair},
        peer_evidence::{PeerEvidenceStore, RuntimePolicy},
    };

    #[tokio::test]
    async fn s4_relay_ingress_cannot_seed_host_hints_or_spawn_lookup() {
        let runtime = Arc::new(EvidenceRuntime::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = Arc::clone(&entered);
        assert!(runtime
            .lookup_responder
            .set(Arc::new(move |_| {
                let notify = Arc::clone(&notify);
                Box::pin(async move { notify.notify_one() })
            }))
            .is_ok());
        let agent = AgentId([1; 32]);
        let machine = MachineId([2; 32]);
        let now = dm_capability::now_unix_ms();
        let authority = crate::raw_delivery_from_ingress(
            None,
            None,
            Some(&runtime),
            agent,
            machine,
            now,
            crate::network::DirectIngress::Relay,
        );
        assert_eq!(authority, (false, false, None));
        assert_eq!(runtime.wire_limits.lookups.available_permits(), 16);
        tokio::task::yield_now().await;
        assert!(runtime.lookup_hints.machines(agent).is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), entered.notified())
                .await
                .is_err()
        );

        // The same claim on a direct transport still drives S4 recovery;
        // neither lane upgrades the triggering frame's authority.
        assert_eq!(
            crate::raw_delivery_from_ingress(
                None,
                None,
                Some(&runtime),
                agent,
                machine,
                now,
                crate::network::DirectIngress::Transport,
            ),
            authority
        );
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        assert_eq!(runtime.lookup_hints.machines(agent), vec![machine]);
    }

    #[tokio::test]
    async fn s4_raw_lookup_silent_responder_does_not_block_other_peer() {
        // Inert raw receive queue plus the production authority/scheduling and
        // dispatch functions. The Lookup transport is an unanswered duplex,
        // never a NetworkNode, socket, or daemon.
        let runtime = Arc::new(EvidenceRuntime::default());
        let started = Arc::new(tokio::sync::Notify::new());
        let notify = Arc::clone(&started);
        assert!(runtime
            .lookup_responder
            .set(Arc::new(move |_| {
                let notify = Arc::clone(&notify);
                Box::pin(async move {
                    let (_silent_responder, mut recv) = tokio::io::duplex(32);
                    notify.notify_one();
                    let limits = crate::evidence_wire::Limits::default();
                    let _ = read_message(&mut recv, &limits).await;
                })
            }))
            .is_ok());
        let dm = crate::direct::DirectMessaging::new();
        let mut delivered = dm.subscribe();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(AgentId, MachineId)>(2);
        let evidence = Arc::clone(&runtime);
        let listener = tokio::spawn(async move {
            while let Some((sender, machine_id)) = rx.recv().await {
                let (verified, _, _) = crate::raw_delivery_and_schedule_lookup(
                    None,
                    None,
                    Some(&evidence),
                    sender,
                    machine_id,
                    dm_capability::now_unix_ms(),
                );
                let data = b"ordinary raw frame".to_vec();
                crate::dispatch_raw_direct_after_gates(
                    &dm,
                    None,
                    &[],
                    crate::RawDirectDelivery {
                        sender,
                        machine_id,
                        digest: crate::direct::dm_payload_digest_hex(&data),
                        data,
                        verified,
                        trust_decision: None,
                        observed_origin: None,
                    },
                )
                .await;
            }
        });
        let first = (AgentId([1; 32]), MachineId([2; 32]));
        let other = (AgentId([3; 32]), MachineId([4; 32]));
        tx.send(first).await.unwrap();
        tokio::time::timeout(Duration::from_millis(500), started.notified())
            .await
            .unwrap();
        assert_eq!(runtime.wire_limits.lookups.available_permits(), 15);
        tx.send(other).await.unwrap();
        tokio::time::timeout(Duration::from_millis(500), async {
            let frame = delivered.recv().await.unwrap();
            assert_eq!(frame.sender, first.0);
            assert!(!frame.verified);
            let frame = delivered.recv().await.unwrap();
            assert_eq!(frame.sender, other.0);
            assert_eq!(frame.machine_id, other.1);
            assert!(!frame.verified);
        })
        .await
        .expect("another peer must be delivered while Lookup is unanswered");
        drop(tx);
        listener.await.unwrap();
    }

    #[tokio::test]
    async fn s4_raw_lookup_distinct_claim_flood_is_bounded_before_spawn() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let runtime = Arc::new(EvidenceRuntime::default());
        let started = Arc::new(AtomicUsize::new(0));
        let release = tokio_util::sync::CancellationToken::new();
        let count = Arc::clone(&started);
        let done = release.clone();
        assert!(runtime
            .lookup_responder
            .set(Arc::new(move |_| {
                let count = Arc::clone(&count);
                let done = done.clone();
                Box::pin(async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    done.cancelled().await;
                })
            }))
            .is_ok());
        // An ordinary awaited sender already owns one of the SAME permits.
        let sender_runtime = Arc::clone(&runtime);
        let sender = tokio::spawn(async move {
            sender_runtime.lookup(AgentId([255; 32]), None).await;
        });
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::Relaxed), 1);
        for i in 0..128 {
            let authority = crate::raw_delivery_and_schedule_lookup(
                None,
                None,
                Some(&runtime),
                AgentId([i; 32]),
                MachineId([42; 32]),
                dm_capability::now_unix_ms(),
            );
            assert!(!authority.0);
        }
        // No yield in the flood: permits must already be held by queued jobs,
        // not first acquired when those jobs eventually get polled.
        assert_eq!(runtime.wire_limits.lookups.available_permits(), 0);
        assert_eq!(runtime.diagnostics()["evidence_lookup_skipped"], 113);
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::Relaxed), 16);
        release.cancel();
        sender.await.unwrap();
        tokio::time::timeout(Duration::from_millis(500), async {
            while runtime.wire_limits.lookups.available_permits() != 16 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            started.load(Ordering::Relaxed),
            16,
            "skipped jobs must not queue"
        );
    }

    #[tokio::test]
    async fn s4_raw_lookup_only_later_frame_uses_recovered_evidence() {
        let receiver = Node::new().await;
        let peer = Node::new().await;
        receiver.group(&[receiver.a(), peer.a()]);
        let store = receiver.store();
        let wire = codec()
            .serialize(&Found::from(peer.mint().unwrap().into_record()))
            .unwrap();
        let runtime = &receiver.relations.runtime;
        let recovered = Arc::new(tokio::sync::Notify::new());
        let notify = Arc::clone(&recovered);
        assert!(runtime
            .lookup_responder
            .set(Arc::new(move |target| {
                let store = Arc::clone(&store);
                let wire = wire.clone();
                let notify = Arc::clone(&notify);
                Box::pin(async move {
                    ingest_found(
                        &store,
                        &Limits::default(),
                        target,
                        decode::found(&wire).unwrap(),
                        dm_capability::now_unix_ms(),
                    )
                    .unwrap();
                    notify.notify_one();
                })
            }))
            .is_ok());
        let first = crate::raw_delivery_and_schedule_lookup(
            None,
            None,
            Some(runtime),
            peer.a(),
            peer.m(),
            dm_capability::now_unix_ms(),
        );
        tokio::time::timeout(Duration::from_millis(500), recovered.notified())
            .await
            .unwrap();
        assert!(!first.0, "the triggering frame must stay unverified");
        let later = crate::raw_delivery_and_schedule_lookup(
            None,
            None,
            Some(runtime),
            peer.a(),
            peer.m(),
            dm_capability::now_unix_ms(),
        );
        assert!(
            later.0,
            "a later frame uses the stored, reverified evidence"
        );
    }

    struct Node {
        dir: tempfile::TempDir,
        identity: Identity,
        template: crate::IdentityAnnouncement,
        policy: Arc<RuntimePolicy>,
        relations: Relations,
        rosters: Arc<Mutex<Vec<HashSet<AgentId>>>>,
    }
    impl Node {
        async fn new() -> Self {
            // Keys, local files, and policy only: no NetworkNode, sockets, or daemon.
            let dir = tempfile::tempdir().unwrap();
            let identity = Identity::new(
                MachineKeypair::generate().unwrap(),
                AgentKeypair::generate().unwrap(),
            );
            let template = crate::IdentityAnnouncement {
                self_name: None,
                agent_id: identity.agent_id(),
                machine_id: identity.machine_id(),
                user_id: None,
                agent_certificate: None,
                machine_public_key: identity.machine_keypair().public_key().as_bytes().to_vec(),
                machine_signature: vec![],
                agent_public_key: identity.agent_keypair().public_key().as_bytes().to_vec(),
                addresses: vec![],
                announced_at: dm_capability::now_unix_ms() / 1000,
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: vec![],
                relay_candidates: vec![],
            };
            let runtime = Arc::new(EvidenceRuntime::default());
            let revoked = Arc::new(tokio::sync::RwLock::new(
                crate::revocation::RevocationSet::new(),
            ));
            let owner = crate::owner_trust::OwnerTrust::default();
            let local = identity.agent_id();
            let policy = Arc::new(RuntimePolicy::new(
                local,
                owner.clone(),
                Arc::clone(&revoked),
            ));
            let rosters = Arc::new(Mutex::new(Vec::<HashSet<AgentId>>::new()));
            let groups = Arc::clone(&rosters);
            policy.set_groups(Arc::new(move |a| {
                Some(
                    groups
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|g| g.contains(&local) && g.contains(&a)),
                )
            }));
            let groups = Arc::clone(&rosters);
            runtime.set_group_context(Arc::new(move |a, b| {
                Some(
                    groups
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|g| [local, a, b].iter().all(|a| g.contains(a))),
                )
            }));
            runtime.start(
                dir.path().into(),
                Default::default(),
                policy.clone(),
                Arc::default(),
            );
            assert!(runtime.wait(0).await);
            let relations = Relations {
                runtime,
                local: Peer {
                    agent: local,
                    machine: identity.machine_id(),
                    cert: None,
                },
                bindings: Arc::default(),
                discovery: Arc::default(),
                machines: Arc::default(),
                peer_checks: Default::default(),
                owner,
                revoked,
            };
            Self {
                dir,
                identity,
                template,
                policy,
                relations,
                rosters,
            }
        }
        fn a(&self) -> AgentId {
            self.identity.agent_id()
        }
        fn m(&self) -> MachineId {
            self.identity.machine_id()
        }
        fn mint(&self) -> io::Result<Hello> {
            let mut template = self.template.clone();
            template.announced_at = dm_capability::now_unix_ms() / 1000;
            mint_hello(
                &self.identity,
                template,
                &crate::announce_blob::shared_cert_pair(None, None),
                crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]),
                None,
                true,
            )
        }
        async fn know(&self, other: &Self) {
            crate::dm_inbox::record_authenticated_machine_binding(
                &self.relations.bindings,
                other.a(),
                other.m(),
                dm_capability::now_unix_ms() / 1000,
            )
            .await;
        }
        fn group(&self, peers: &[AgentId]) {
            self.rosters
                .lock()
                .unwrap()
                .push(peers.iter().copied().collect());
        }
        fn store(&self) -> Arc<PeerEvidenceStore> {
            self.relations.runtime.store().unwrap()
        }
    }

    #[tokio::test]
    async fn s4_30b_restart_then_new_group_pulls_owners_fresh_own_identity() {
        let joiner = Node::new().await;
        let owner = Node::new().await;
        // Raw receive supplies only a claimed agent plus the authenticated
        // transport machine. No owner binding, discovery, or stored evidence.
        joiner
            .relations
            .runtime
            .lookup(owner.a(), Some(owner.m()))
            .await;
        owner.know(&joiner).await;
        let connected = HashSet::from([owner.m()]);
        assert!(joiner
            .relations
            .responders(owner.a(), &connected)
            .await
            .is_empty());
        assert!(!owner.relations.authorized(joiner.m(), owner.a()).await);
        joiner.group(&[joiner.a(), owner.a()]);
        owner.group(&[joiner.a(), owner.a()]);
        assert!(joiner
            .store()
            .usable_agent(owner.a(), dm_capability::now_unix_ms())
            .is_none());
        assert_eq!(
            joiner.relations.responders(owner.a(), &connected).await,
            vec![owner.m()]
        );
        assert!(owner.relations.authorized(joiner.m(), owner.a()).await);
        let reply = reply_material(
            owner.a(),
            owner.a(),
            Some(&owner.store()),
            dm_capability::now_unix_ms(),
            || owner.mint(),
        )
        .unwrap()
        .unwrap();
        let now = dm_capability::now_unix_ms();
        assert!(joiner
            .relations
            .bindings
            .read()
            .await
            .agents_on_machine(owner.m(), 1)
            .is_empty());
        assert!(joiner.relations.peer(owner.a()).await.is_none());
        assert!(
            !crate::raw_delivery_with_evidence(
                None,
                None,
                Some(&joiner.relations.runtime),
                owner.a(),
                owner.m(),
                now
            )
            .0
        );
        assert!(!joiner.relations.authorized(owner.m(), joiner.a()).await);
        assert!(joiner
            .relations
            .responders(joiner.a(), &connected)
            .await
            .is_empty());
        let mut tampered = owner.mint().unwrap().into_record();
        tampered.advert[100] ^= 1;
        assert!(ingest_found(
            &joiner.store(),
            &Limits::default(),
            owner.a(),
            tampered,
            now
        )
        .is_err());
        assert!(ingest_found(
            &joiner.store(),
            &Limits::default(),
            owner.a(),
            joiner.mint().unwrap().into_record(),
            now
        )
        .is_err());
        assert!(joiner.relations.peer(owner.a()).await.is_none());
        let body = codec().serialize(&reply).unwrap();
        ingest_found(
            &joiner.store(),
            &Limits::default(),
            owner.a(),
            decode::found(&body).unwrap(),
            dm_capability::now_unix_ms(),
        )
        .unwrap();
        let evidence = joiner
            .store()
            .usable_agent(owner.a(), dm_capability::now_unix_ms())
            .unwrap();
        assert!(
            crate::raw_delivery_with_evidence(
                None,
                None,
                Some(&joiner.relations.runtime),
                owner.a(),
                owner.m(),
                now
            )
            .0
        );
        assert_eq!(evidence.announcement.machine_id, owner.m());
        assert_eq!(evidence.advert.capabilities.kem_public_key.len(), 1184);
        // Evidence for the owner still never verifies a different machine.
        let moved = MachineId([18; 32]);
        assert!(joiner
            .store()
            .usable(owner.a(), moved, dm_capability::now_unix_ms())
            .is_none());
        assert!(joiner
            .relations
            .responders(owner.a(), &HashSet::from([moved]))
            .await
            .is_empty());
        // A hint from a different transport may route a self-query, but even
        // the valid reply above cannot verify the owner's claim on that host.
        joiner
            .relations
            .runtime
            .lookup(owner.a(), Some(moved))
            .await;
        assert_eq!(
            joiner
                .relations
                .responders(owner.a(), &HashSet::from([moved]))
                .await,
            vec![moved]
        );
        assert!(
            !crate::raw_delivery_with_evidence(
                None,
                None,
                Some(&joiner.relations.runtime),
                owner.a(),
                moved,
                now
            )
            .0
        );
        assert_eq!(
            joiner
                .relations
                .responders(owner.a(), &HashSet::from([owner.m(), moved]))
                .await,
            vec![owner.m()]
        );
        assert!(joiner
            .relations
            .responders(owner.a(), &HashSet::new())
            .await
            .is_empty());
        // No discovery entries or capability bits are installed by Lookup.
        assert!(joiner.relations.discovery.read().await.is_empty());
        joiner.rosters.lock().unwrap().clear();
        assert!(joiner
            .store()
            .usable_agent(owner.a(), dm_capability::now_unix_ms())
            .is_none());
    }

    #[tokio::test]
    async fn s4_machine_resolution_work_is_independent_of_registry_size() {
        use std::sync::atomic::Ordering;
        let responder = Node::new().await;
        let requester = Node::new().await;
        responder.know(&requester).await;
        responder.group(&[responder.a(), requester.a()]);
        // Fill the registry to its production ceiling with unrelated machines.
        for i in 0u32..65_535 {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            crate::dm_inbox::record_authenticated_machine_binding(
                &responder.relations.bindings,
                AgentId(bytes),
                MachineId(bytes),
                1,
            )
            .await;
        }
        responder.relations.peer_checks.store(0, Ordering::Relaxed);
        assert!(
            responder
                .relations
                .authorized(requester.m(), responder.a())
                .await
        );
        assert_eq!(
            responder.relations.peer_checks.swap(0, Ordering::Relaxed),
            3
        );
        assert!(
            !responder
                .relations
                .authorized(MachineId([255; 32]), responder.a())
                .await
        );
        assert_eq!(
            responder.relations.peer_checks.swap(0, Ordering::Relaxed),
            2
        );
        assert_eq!(
            responder
                .relations
                .responders(requester.a(), &HashSet::from([requester.m()]))
                .await,
            vec![requester.m()]
        );
        assert_eq!(
            responder.relations.peer_checks.swap(0, Ordering::Relaxed),
            2
        );

        // Co-resident Sybils also cannot turn one machine lookup into a scan.
        let crowded = MachineId([254; 32]);
        for i in 0u32..256 {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            crate::dm_inbox::record_authenticated_machine_binding(
                &responder.relations.bindings,
                AgentId(bytes),
                crowded,
                2,
            )
            .await;
        }
        assert!(!responder.relations.authorized(crowded, responder.a()).await);
        assert_eq!(
            responder.relations.peer_checks.load(Ordering::Relaxed),
            2 + MACHINE_BINDING_LIMIT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn s4_raw_hints_are_lru_bounded_and_reads_do_not_extend_ttl() {
        let hints = RoutingHints::default();
        for i in 0..HINT_CAP {
            hints.record(AgentId([i as u8; 32]), MachineId([i as u8; 32]));
        }
        assert_eq!(hints.machines(AgentId([0; 32])), vec![MachineId([0; 32])]);
        hints.record(AgentId([255; 32]), MachineId([255; 32]));
        assert_eq!(hints.0.lock().unwrap().len(), HINT_CAP);
        assert!(hints.machines(AgentId([1; 32])).is_empty());
        assert_eq!(hints.machines(AgentId([0; 32])), vec![MachineId([0; 32])]);
        tokio::time::advance(Duration::from_millis(W_MS - 1)).await;
        assert!(!hints.machines(AgentId([0; 32])).is_empty());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(hints.machines(AgentId([0; 32])).is_empty());
        assert!(hints.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn s4_discovery_machine_index_is_only_a_candidate_source() {
        let responder = Node::new().await;
        let requester = Node::new().await;
        responder.group(&[responder.a(), requester.a()]);
        let mut discovered =
            crate::discovered_agent_fixture(1, dm_capability::now_unix_ms() / 1000, &[], None);
        discovered.agent_id = requester.a();
        discovered.machine_id = requester.m();
        crate::upsert_discovered_machine_from_agent(&responder.relations.machines, &discovered)
            .await;
        responder
            .relations
            .discovery
            .write()
            .await
            .insert(requester.a(), discovered.clone());
        // ADR 0115 §2: a discovery entry alone confirms nothing.
        assert!(
            !responder
                .relations
                .authorized(requester.m(), responder.a())
                .await,
            "an unconfirmed discovery machine must not authorize"
        );
        responder.know(&requester).await;
        assert!(
            responder
                .relations
                .authorized(requester.m(), responder.a())
                .await
        );
        // An obsolete reverse pointer cannot override a move: the agent's
        // authority moves it, and discovery follows.
        crate::dm_inbox::record_authenticated_machine_binding(
            &responder.relations.bindings,
            requester.a(),
            MachineId([99; 32]),
            dm_capability::now_unix_ms() / 1000 + 1,
        )
        .await;
        discovered.machine_id = MachineId([99; 32]);
        responder
            .relations
            .discovery
            .write()
            .await
            .insert(requester.a(), discovered);
        assert!(
            !responder
                .relations
                .authorized(requester.m(), responder.a())
                .await
        );
    }

    #[tokio::test]
    async fn s4_stored_machine_index_survives_restart_and_checks_authority() {
        let responder = Node::new().await;
        let requester = Node::new().await;
        responder.group(&[responder.a(), requester.a()]);
        let now = dm_capability::now_unix_ms();
        responder
            .store()
            .ingest(
                requester.mint().unwrap().into_record(),
                IngestSource::Gossip,
                now,
            )
            .unwrap();
        responder.store().flush(now, true).unwrap();
        assert!(
            responder
                .relations
                .authorized(requester.m(), responder.a())
                .await
        );
        let restarted = PeerEvidenceStore::open(
            responder.dir.path(),
            Default::default(),
            responder.policy.clone(),
            now,
        )
        .unwrap();
        assert_eq!(
            restarted.agents_on_machine(requester.m(), MACHINE_BINDING_LIMIT),
            vec![requester.a()]
        );
        responder.rosters.lock().unwrap().clear();
        assert!(
            !responder
                .relations
                .authorized(requester.m(), responder.a())
                .await
        );
    }

    #[tokio::test]
    async fn s4_age_mismatch_stored_authority_is_not_reply_material() {
        let responder = Node::new().await;
        let target = Node::new().await;
        responder.group(&[responder.a(), target.a()]);
        let now = dm_capability::now_unix_ms();
        let record = target.mint().unwrap().into_record();
        responder
            .store()
            .ingest(record.clone(), IngestSource::Gossip, now)
            .unwrap();
        responder.store().flush(now, true).unwrap();
        let later = now + W_MS + 1001;
        let restarted = PeerEvidenceStore::open(
            responder.dir.path(),
            Default::default(),
            responder.policy.clone(),
            later,
        )
        .unwrap();
        assert!(restarted.usable_agent(target.a(), later).is_some());
        assert!(reply_material(
            target.a(),
            responder.a(),
            Some(&restarted),
            later,
            || panic!("cannot mint another identity")
        )
        .unwrap()
        .is_none());
        // Even the warm process refuses its expired live bytes.
        assert!(reply_material(
            target.a(),
            responder.a(),
            Some(&responder.store()),
            later,
            || panic!("not own")
        )
        .unwrap()
        .is_none());
        let found = reply_material(
            target.a(),
            responder.a(),
            Some(&responder.store()),
            now,
            || panic!("not own"),
        )
        .unwrap()
        .unwrap();
        let cold = Node::new().await;
        cold.group(&[cold.a(), target.a()]);
        ingest_found(
            &cold.store(),
            &Limits::default(),
            target.a(),
            decode::found(&codec().serialize(&found).unwrap()).unwrap(),
            now,
        )
        .unwrap();
        assert!(cold.store().usable_agent(target.a(), now).is_some());
        // Independent component ages: a fresh advert never rescues an old announcement.
        let mut mixed = record.clone();
        let mut announcement = announce_v3::deserialize_v3(&mixed.announcement).unwrap();
        announcement.announced_at = now.saturating_sub(W_MS + 1001) / 1000;
        announcement
            .sign_v3_1(target.identity.machine_keypair().secret_key())
            .unwrap();
        mixed.announcement = announce_v3::serialize_v3_1(&announcement).unwrap();
        assert!(ingest_found(&cold.store(), &Limits::default(), target.a(), mixed, now).is_err());
        assert!(
            ingest_found(&cold.store(), &Limits::default(), target.a(), record, later).is_err()
        );
    }

    #[tokio::test]
    async fn s4_requester_reverifies_tampered_wrong_target_and_stale_replies() {
        let cold = Node::new().await;
        let target = Node::new().await;
        cold.group(&[cold.a(), target.a()]);
        let now = dm_capability::now_unix_ms();
        let record = target.mint().unwrap().into_record();
        for component in 0..2 {
            let mut tampered = record.clone();
            let bytes = if component == 0 {
                &mut tampered.announcement
            } else {
                &mut tampered.advert
            };
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            assert!(
                ingest_found(&cold.store(), &Limits::default(), target.a(), tampered, now).is_err()
            );
            assert!(cold.store().usable_agent(target.a(), now).is_none());
        }
        assert!(ingest_found(
            &cold.store(),
            &Limits::default(),
            cold.a(),
            record.clone(),
            now
        )
        .is_err());
        assert!(ingest_found(
            &cold.store(),
            &Limits::default(),
            target.a(),
            record.clone(),
            now + W_MS + 1001
        )
        .is_err());
        let mut wrong_digest = record.clone();
        let mut announcement = announce_v3::deserialize_v3(&wrong_digest.announcement).unwrap();
        announcement.cert_digest = [17; 32];
        announcement
            .sign_v3_1(target.identity.machine_keypair().secret_key())
            .unwrap();
        wrong_digest.announcement = announce_v3::serialize_v3_1(&announcement).unwrap();
        assert!(ingest_found(
            &cold.store(),
            &Limits::default(),
            target.a(),
            wrong_digest,
            now
        )
        .is_err());
        ingest_found(&cold.store(), &Limits::default(), target.a(), record, now).unwrap();
    }

    #[tokio::test]
    async fn s4_authorization_requires_same_context_and_authenticated_requester() {
        let responder = Node::new().await;
        let requester = Node::new().await;
        let target = Node::new().await;
        responder.group(&[responder.a(), requester.a()]);
        responder.group(&[responder.a(), target.a()]);
        responder.know(&requester).await;
        responder.know(&target).await;
        assert!(
            !responder
                .relations
                .authorized(requester.m(), target.a())
                .await
        );
        responder.group(&[responder.a(), requester.a(), target.a()]);
        assert!(
            responder
                .relations
                .authorized(requester.m(), target.a())
                .await
        );
        assert!(
            !responder
                .relations
                .authorized(MachineId([9; 32]), target.a())
                .await
        );
        responder.rosters.lock().unwrap().clear();
        assert!(
            !responder
                .relations
                .authorized(requester.m(), target.a())
                .await
        );
        assert!(reply_material(
            target.a(),
            responder.a(),
            Some(&responder.store()),
            dm_capability::now_unix_ms(),
            || panic!("not own")
        )
        .unwrap()
        .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn s4_fanout_cooldown_and_outstanding_bounds() {
        let target = AgentId([99; 32]);
        let peers = (0..10)
            .map(|i| (AgentId([i; 32]), MachineId([i / 2; 32])))
            .chain([(target, MachineId([9; 32]))]);
        let selected = select(target, peers);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0], MachineId([9; 32]));
        assert_eq!(selected.iter().collect::<HashSet<_>>().len(), 3);
        let limits = Limits::default();
        let mut outstanding = Vec::new();
        for i in 0..16 {
            outstanding.push(limits.begin_lookup(AgentId([i; 32])).unwrap());
        }
        assert!(limits.begin_lookup(target).is_none());
        drop(outstanding);
        assert!(limits.begin_lookup(AgentId([0; 32])).is_none());
        tokio::time::advance(LOOKUP_INTERVAL).await;
        assert!(limits.begin_lookup(AgentId([0; 32])).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn s4_hostile_requester_not_found_bytes_and_deadline() {
        let limits = Arc::new(Limits::default());
        let machine = MachineId([4; 32]);
        let first = limits.admit(machine, false).unwrap();
        let second = limits.admit(machine, false).unwrap();
        assert!(limits.admit(machine, false).is_none());
        assert!(limits.request(machine, false));
        assert!(!limits.request(machine, false));
        limits.disconnect(machine);
        assert!(!limits.request(machine, false));
        let (mut send, mut recv) = tokio::io::duplex(32);
        write_message(&mut send, &limits, machine, NOT_FOUND, &[])
            .await
            .unwrap();
        assert_eq!(read_message(&mut recv, &limits).await.unwrap().0, NOT_FOUND);
        assert_eq!(
            limits.state.lock().unwrap().machines[&machine].bytes.total,
            5
        );
        assert!(limits.charge(machine, 64 * 1024 - 5));
        assert!(!limits.charge(machine, 1));
        drop((first, second));
        let lease = limits.admit(machine, false).unwrap();
        let (_send, mut recv) = tokio::io::duplex(32);
        assert!(
            tokio::time::timeout_at(lease.deadline, read_message(&mut recv, &limits))
                .await
                .is_err()
        );
        drop(ResetOnDrop {
            limits: Arc::clone(&limits),
            machine,
            complete: false,
        });
        assert_eq!(
            limits.state.lock().unwrap().machines[&machine].bytes.total,
            RESET_CHARGE
        );
        drop(lease);
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
    }
}
