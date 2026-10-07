//! ADR 0089: bounded Hello and relationship-context Lookup evidence.
use crate::{
    announce_v3, dm_capability,
    identity::{AgentId, MachineId},
    peer_evidence::{EvidenceRecordV1, EvidenceRuntime, EvidenceView, IngestSource, W_MS},
    streams::{PeerStream, StreamProtocol},
};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};

mod decode;
pub(crate) mod lookup;

#[cfg(test)]
#[path = "evidence_wire/tests/admission.rs"]
mod admission_tests;

const MESSAGE_CAP: usize = 32 * 1024;
// Reserve the frame, decoded vectors, and signed-part verification copies.
// All requests/replies, including outbound reads, acquire this conservative
// reservation before reading bodies. The wire buffer itself never exceeds
// 32 KiB; the sum of all reservations never exceeds 1 MiB.
const ALLOCATION_RESERVATION: usize = MESSAGE_CAP * 4;
const TOTAL_ALLOCATION_CAP: usize = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);
const HELLO_INTERVAL: Duration = Duration::from_secs(60);
const MACHINE_CAP: usize = 4096;
const RESET_CHARGE: usize = 16;
const HELLO: u8 = 1;
const LOOKUP: u8 = 2;
const CERTIFICATE: u8 = 3;
const NOT_FOUND: u8 = 4;
const ACK: u8 = 5;
const FOUND: u8 = 6;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MESSAGE_CAP as u64)
        .reject_trailing_bytes()
}

/// Signed parts remain verbatim. `have_certificate` refers to the other
/// side's digest, never to an unauthenticated claim of ownership. A certificate
/// continuation is sent only after the reply explicitly reports a cache miss.
#[derive(Debug, Serialize)]
struct Hello {
    announcement: Vec<u8>,
    advert: Vec<u8>,
    certificate: Option<Vec<u8>>,
    have_certificate: Option<[u8; 32]>,
}
impl Hello {
    fn into_record(self) -> EvidenceRecordV1 {
        EvidenceRecordV1 {
            announcement: self.announcement,
            advert: self.advert,
            certificate: self.certificate,
            relation: 0,
            stored_at_ms: 0,
        }
    }
}

#[derive(Default)]
struct Window {
    events: VecDeque<(Instant, usize)>,
    total: usize,
}
impl Window {
    fn prune(&mut self, now: Instant) {
        while self
            .events
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) >= Duration::from_secs(1))
        {
            if let Some((_, n)) = self.events.pop_front() {
                self.total -= n;
            }
        }
    }
    fn add(&mut self, now: Instant, n: usize) {
        // Coalesce same-instant charges so a flood of resets cannot grow a
        // queue without consuming byte credit.
        if let Some((t, value)) = self.events.back_mut() {
            if *t == now {
                *value += n;
                self.total += n;
                return;
            }
        }
        self.events.push_back((now, n));
        self.total += n;
    }
}
#[derive(Default)]
struct MachineBudget {
    open: usize,
    jobs: usize,
    bytes: Window,
    lookup: Option<Instant>,
    hello_in: Option<Instant>,
    hello_out: Option<Instant>,
    attempted: bool,
    hello_generation: Option<u64>,
    touched: Option<Instant>,
    certificate: Option<(AgentId, [u8; 32], Instant)>,
}
impl MachineBudget {
    // Generation IDs are allocated in increasing order, but ant-quic can
    // promote an older superseded connection back to Live. Keep a high-water
    // mark: that promotion fails closed for Hello until a newer generation
    // arrives. A delayed job must not re-arm a previously used connection.
    fn observe_hello_generation(&mut self, generation: u64) -> bool {
        if self.hello_generation.is_some_and(|old| old > generation) {
            return false;
        }
        if self.hello_generation != Some(generation) {
            self.attempted = false;
            self.hello_generation = Some(generation);
        }
        true
    }
}
#[derive(Default)]
struct State {
    machines: HashMap<MachineId, MachineBudget>,
    bytes: Window,
    verifies: Window,
    targets: HashMap<AgentId, Instant>,
}

/// ADR 0089 S5 diagnostics counters for the evidence wire, surfaced via
/// `/diagnostics` (`peer_evidence`). Atomics on `Limits`, which every
/// connection, acceptor and outbound exchange already shares.
#[derive(Default)]
pub(crate) struct WireCounters {
    pub(crate) evidence_hello_sent: std::sync::atomic::AtomicU64,
    pub(crate) evidence_hello_received: std::sync::atomic::AtomicU64,
    pub(crate) evidence_hello_refused: std::sync::atomic::AtomicU64,
    pub(crate) evidence_lookup_sent: std::sync::atomic::AtomicU64,
    pub(crate) evidence_lookup_served: std::sync::atomic::AtomicU64,
    pub(crate) evidence_lookup_refused: std::sync::atomic::AtomicU64,
    pub(crate) evidence_lookup_unauthorized: std::sync::atomic::AtomicU64,
    pub(crate) evidence_bytes_in: std::sync::atomic::AtomicU64,
    pub(crate) evidence_bytes_out: std::sync::atomic::AtomicU64,
    pub(crate) evidence_verifies: std::sync::atomic::AtomicU64,
}

impl WireCounters {
    fn bump(field: &std::sync::atomic::AtomicU64) {
        field.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn add(field: &std::sync::atomic::AtomicU64, bytes: usize) {
        field.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// The `/diagnostics` shape (ADR 0089 §Neutral/Operational).
    pub(crate) fn json(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        serde_json::json!({
            "evidence_hello_sent": self.evidence_hello_sent.load(Relaxed),
            "evidence_hello_received": self.evidence_hello_received.load(Relaxed),
            "evidence_hello_refused": self.evidence_hello_refused.load(Relaxed),
            "evidence_lookup_sent": self.evidence_lookup_sent.load(Relaxed),
            "evidence_lookup_served": self.evidence_lookup_served.load(Relaxed),
            "evidence_lookup_refused": self.evidence_lookup_refused.load(Relaxed),
            "evidence_lookup_unauthorized": self.evidence_lookup_unauthorized.load(Relaxed),
            "evidence_bytes_in": self.evidence_bytes_in.load(Relaxed),
            "evidence_bytes_out": self.evidence_bytes_out.load(Relaxed),
            "evidence_verifies": self.evidence_verifies.load(Relaxed),
        })
    }
}

/// Shared by every connection, acceptor, and outbound exchange on this node.
pub(crate) struct Limits {
    pub(crate) ready_hello: std::sync::atomic::AtomicBool,
    state: Mutex<State>,
    #[cfg(test)]
    hello_open_pause: Mutex<Option<Arc<HelloOpenPause>>>,
    allocations: Arc<tokio::sync::Semaphore>,
    lookups: Arc<tokio::sync::Semaphore>,
    // Strangers may occupy at most half of the aggregate byte reservation.
    stranger_allocations: Arc<tokio::sync::Semaphore>,
    prefix: Mutex<HashMap<MachineId, usize>>,
    pub(crate) prefix_refused: std::sync::atomic::AtomicU64,
    pub(crate) counters: WireCounters,
}
// Per-fixture synchronization at the real open boundary; absent in production.
#[cfg(test)]
#[derive(Default)]
struct HelloOpenPause {
    after_open: bool,
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            ready_hello: Default::default(),
            state: Mutex::new(State::default()),
            #[cfg(test)]
            hello_open_pause: Mutex::new(None),
            lookups: Arc::new(tokio::sync::Semaphore::new(16)),
            allocations: Arc::new(tokio::sync::Semaphore::new(TOTAL_ALLOCATION_CAP)),
            stranger_allocations: Arc::new(tokio::sync::Semaphore::new(TOTAL_ALLOCATION_CAP / 2)),
            prefix: Mutex::new(HashMap::new()),
            prefix_refused: std::sync::atomic::AtomicU64::new(0),
            counters: WireCounters::default(),
        }
    }
}
impl State {
    fn machine(&mut self, machine: MachineId, now: Instant) -> Option<&mut MachineBudget> {
        if !self.machines.contains_key(&machine) && self.machines.len() >= MACHINE_CAP {
            self.machines.retain(|_, m| {
                // Idle markers may be forgotten after the cooldown. Keep
                // leases/jobs and every recent rate entry, including inbound.
                m.open != 0
                    || m.jobs != 0
                    || [m.touched, m.hello_out, m.hello_in]
                        .into_iter()
                        .flatten()
                        .any(|t| now.duration_since(t) < HELLO_INTERVAL)
            });
        }
        if !self.machines.contains_key(&machine) && self.machines.len() >= MACHINE_CAP {
            return None;
        }
        let m = self.machines.entry(machine).or_default();
        m.touched = Some(now);
        Some(m)
    }
}
impl Limits {
    // Pin the budget across work that has not yet acquired a stream lease.
    // The guard also survives awaits and releases on task cancellation.
    fn pin_machine(self: &Arc<Self>, machine: MachineId) -> Option<MachineJob> {
        let mut state = self.state.lock().ok()?;
        state.machine(machine, Instant::now())?.jobs += 1;
        Some(MachineJob {
            limits: Arc::clone(self),
            machine,
        })
    }

    /// Strangers and Unknown relationship peers share this bounded prefix pool.
    /// Entries exist only while a lease is alive, across all connections.
    pub(crate) fn admit_prefix(self: &Arc<Self>, machine: MachineId) -> Option<PrefixLease> {
        let admitted = self.prefix.lock().ok().and_then(|mut slots| {
            if slots.values().sum::<usize>() >= 32 || slots.get(&machine).copied().unwrap_or(0) >= 2
            {
                return None;
            }
            let job = self.pin_machine(machine)?;
            *slots.entry(machine).or_default() += 1;
            Some(PrefixLease {
                limits: Arc::clone(self),
                machine,
                _job: job,
            })
        });
        if admitted.is_none() {
            self.prefix_refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.reset(machine);
            tracing::info!(target: "x0x::streams", ?machine,
                outcome = "deny_pre_identity_capacity", "pre-identity stream refused; resetting");
        }
        admitted
    }

    pub(crate) fn admit(self: &Arc<Self>, machine: MachineId, relationship: bool) -> Option<Lease> {
        let now = Instant::now();
        let stranger_permit = if relationship {
            None
        } else {
            Some(
                Arc::clone(&self.stranger_allocations)
                    .try_acquire_many_owned(ALLOCATION_RESERVATION as u32)
                    .ok()?,
            )
        };
        let permit = Arc::clone(&self.allocations)
            .try_acquire_many_owned(ALLOCATION_RESERVATION as u32)
            .ok()?;
        let mut s = self.state.lock().ok()?;
        let m = s.machine(machine, now)?;
        if m.open >= 2 {
            return None;
        }
        m.open += 1;
        Some(Lease {
            limits: Arc::clone(self),
            machine,
            deadline: now + DEADLINE,
            _permit: permit,
            _stranger_permit: stranger_permit,
        })
    }
    fn charge(&self, machine: MachineId, bytes: usize) -> bool {
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        s.bytes.prune(now);
        if s.bytes.total.saturating_add(bytes) > 256 * 1024 {
            return false;
        }
        let Some(m) = s.machine(machine, now) else {
            return false;
        };
        m.bytes.prune(now);
        if m.bytes.total.saturating_add(bytes) > 64 * 1024 {
            return false;
        }
        m.bytes.add(now, bytes);
        s.bytes.add(now, bytes);
        true
    }
    pub(crate) fn reset(&self, machine: MachineId) {
        let _ = self.charge(machine, RESET_CHARGE);
    }
    fn verify(&self) -> bool {
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        s.verifies.prune(now);
        if s.verifies.total >= 32 {
            return false;
        }
        s.verifies.add(now, 1);
        WireCounters::bump(&self.counters.evidence_verifies);
        true
    }
    fn request(&self, machine: MachineId, hello: bool) -> bool {
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        let Some(m) = s.machine(machine, now) else {
            return false;
        };
        let (last, interval) = if hello {
            (&mut m.hello_in, HELLO_INTERVAL)
        } else {
            (&mut m.lookup, Duration::from_secs(2))
        };
        if last.is_some_and(|t| now.duration_since(t) < interval) {
            return false;
        }
        *last = Some(now);
        true
    }
    /// A cheap, non-blocking scheduler filter. The final atomic decision is
    /// still begin_hello_on_connection, shared with replies.
    fn hello_pending(&self, machine: MachineId) -> bool {
        let Ok(state) = self.state.try_lock() else {
            return false;
        };
        state.machines.get(&machine).is_none_or(|m| {
            !m.attempted
                && m.hello_out
                    .is_none_or(|t| Instant::now().duration_since(t) >= HELLO_INTERVAL)
        })
    }
    // Read-only filter for default-off jobs. The authoritative consume still
    // runs after open, so a replacement or busy read cannot charge an unsent job.
    fn hello_candidate(&self, machine: MachineId, generation: u64) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        state.machines.get(&machine).is_none_or(|m| {
            m.hello_generation
                .is_none_or(|old| old < generation || (old == generation && !m.attempted))
                && m.hello_out
                    .is_none_or(|t| Instant::now().duration_since(t) >= HELLO_INTERVAL)
        })
    }
    #[cfg(test)]
    fn begin_hello(&self, machine: MachineId, related: bool) -> bool {
        self.begin_hello_on_connection(machine, related, None)
    }
    fn begin_hello_on_connection(
        &self,
        machine: MachineId,
        related: bool,
        generation: Option<u64>,
    ) -> bool {
        if !related {
            return false;
        }
        let now = Instant::now();
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        let Some(m) = s.machine(machine, now) else {
            return false;
        };
        // Requests and replies consume the same generation marker under the
        // same lock as the machine rate gate. A remote close need not emit a
        // local PeerDisconnected event. Keep hello_out across replacements.
        if generation.is_some_and(|id| !m.observe_hello_generation(id)) {
            return false;
        }
        if m.attempted
            || m.hello_out
                .is_some_and(|t| now.duration_since(t) < HELLO_INTERVAL)
        {
            return false;
        }
        // Attempted is set before the first byte. A reset or refusal never
        // schedules a retry. Reconnect clears only this connection marker.
        m.attempted = true;
        m.hello_out = Some(now);
        true
    }
    fn hello_connection(&self, machine: MachineId, generation: u64) {
        if let Ok(mut s) = self.state.lock() {
            if let Some(m) = s.machines.get_mut(&machine) {
                // Each readiness pass keeps tracked live markers out of idle eviction.
                m.touched = Some(Instant::now());
                let replaced = m.hello_generation.is_none_or(|old| old < generation);
                if m.observe_hello_generation(generation) && replaced {
                    m.certificate = None;
                }
            }
        }
    }
    fn disconnect(&self, machine: MachineId) {
        if let Ok(mut s) = self.state.lock() {
            if let Some(m) = s.machines.get_mut(&machine) {
                // Events carry no generation. A delayed disconnect must not
                // release the current connection's attempt or machine cooldown.
                // While retained, only a newer generation re-arms the marker;
                // an idle entry can be evicted after its cooldown.
                m.certificate = None;
            }
        }
    }
    fn need_certificate(&self, machine: MachineId, agent: AgentId, digest: [u8; 32]) {
        if let Ok(mut s) = self.state.lock() {
            if let Some(m) = s.machine(machine, Instant::now()) {
                m.certificate = Some((agent, digest, Instant::now() + DEADLINE));
            }
        }
    }
    fn take_certificate(&self, machine: MachineId, agent: AgentId, digest: [u8; 32]) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|mut s| s.machines.get_mut(&machine)?.certificate.take())
            .is_some_and(|(a, d, until)| a == agent && d == digest && Instant::now() < until)
    }
}

struct MachineJob {
    limits: Arc<Limits>,
    machine: MachineId,
}
impl Drop for MachineJob {
    fn drop(&mut self) {
        if let Ok(mut state) = self.limits.state.lock() {
            if let Some(budget) = state.machines.get_mut(&self.machine) {
                budget.jobs = budget.jobs.saturating_sub(1);
            }
        }
    }
}

pub(crate) struct PrefixLease {
    limits: Arc<Limits>,
    machine: MachineId,
    _job: MachineJob,
}
impl Drop for PrefixLease {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.limits.prefix.lock() {
            if let Some(count) = slots.get_mut(&self.machine) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    slots.remove(&self.machine);
                }
            }
        }
    }
}

/// Enrollment or a currently usable evidence record protects allocation
/// capacity. Transport claims and discovery entries alone cannot claim it.
pub(crate) async fn reserved_peer(
    store: Option<&crate::peer_evidence::PeerEvidenceStore>,
    owner: &crate::owner_trust::OwnerTrust,
    revoked: &tokio::sync::RwLock<crate::revocation::RevocationSet>,
    machine: MachineId,
) -> bool {
    if revoked.read().await.is_machine_revoked(&machine) {
        return false;
    }
    owner.is_enrolled_owner_machine(revoked, &machine).await
        || store.is_some_and(|s| s.has_machine(machine, dm_capability::now_unix_ms()))
}

/// Held across queueing, reading, verification and replying; dropping resets
/// release both the machine slot and the aggregate reservation, even on abort.
pub(crate) struct Lease {
    limits: Arc<Limits>,
    machine: MachineId,
    pub(crate) deadline: Instant,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _stranger_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut s) = self.limits.state.lock() {
            if let Some(m) = s.machines.get_mut(&self.machine) {
                m.open = m.open.saturating_sub(1);
            }
        }
    }
}

async fn read_message(
    reader: &mut (impl AsyncRead + Unpin),
    limits: &Limits,
) -> io::Result<(u8, Vec<u8>)> {
    let kind = reader.read_u8().await?;
    let length = reader.read_u32().await? as usize;
    if length > MESSAGE_CAP - 5 {
        return Err(invalid("evidence message cap"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    // Exactly one frame per direction. FIN is covered by the same deadline;
    // a peer cannot append another request or hold the stream indefinitely.
    if reader.read(&mut [0u8; 1]).await? != 0 {
        return Err(invalid("evidence trailing frame"));
    }
    WireCounters::add(&limits.counters.evidence_bytes_in, length + 5);
    Ok((kind, body))
}
async fn write_message(
    writer: &mut (impl AsyncWrite + Unpin),
    limits: &Limits,
    machine: MachineId,
    kind: u8,
    body: &[u8],
) -> io::Result<()> {
    if body.len() > MESSAGE_CAP - 5 || !limits.charge(machine, body.len() + 5) {
        return Err(invalid("evidence reply budget"));
    }
    writer.write_u8(kind).await?;
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(body).await?;
    writer.shutdown().await?;
    let framed = body.len() as u64 + 5;
    WireCounters::add(&limits.counters.evidence_bytes_out, framed as usize);
    match kind {
        // Outbound Hello (connect path or simultaneous reply).
        HELLO => WireCounters::bump(&limits.counters.evidence_hello_sent),
        // Outbound Lookup request.
        LOOKUP => WireCounters::bump(&limits.counters.evidence_lookup_sent),
        // A served Lookup answer. NOT_FOUND is charged the same as FOUND
        // (ADR 0089 §6 responder budgets).
        FOUND | NOT_FOUND => WireCounters::bump(&limits.counters.evidence_lookup_served),
        _ => {}
    }
    Ok(())
}

pub(crate) fn ingest_hello(
    store: Option<&Arc<crate::peer_evidence::PeerEvidenceStore>>,
    capture: &crate::peer_evidence::VerifiedWireCapture,
    limits: &Limits,
    machine: MachineId,
    mut record: EvidenceRecordV1,
    now: u64,
) -> io::Result<Arc<EvidenceView>> {
    decode::parts(
        &record.announcement,
        &record.advert,
        record.certificate.as_deref(),
    )?;
    // Cheap name/cap checks precede any cryptographic work.
    if record.announcement.len() > crate::peer_evidence::ANNOUNCEMENT_CAP {
        return Err(invalid("announcement cap"));
    }
    let ann = announce_v3::deserialize_v3(&record.announcement).map_err(io::Error::other)?;
    if ann.machine_id != machine {
        return Err(invalid("Hello does not name transport machine"));
    }
    if record.certificate.is_none() {
        record.certificate = store
            .cloned()
            .and_then(|s| s.certificate_for(ann.agent_id, machine, ann.cert_digest, now));
    }
    let view = Arc::new(
        record
            .verify_budgeted(now, W_MS, &mut || limits.verify())
            .map_err(io::Error::other)?,
    );
    if let Some(cert) = &view.certificate {
        if announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone())) != ann.cert_digest {
            return Err(invalid("certificate digest mismatch"));
        }
    }
    if let Some(store) = store.cloned() {
        if store.related(ann.agent_id, machine, view.certificate.as_ref(), now) {
            // Reuse the verified view, never pay for an unbudgeted second verify.
            store
                .ingest_verified(record, Arc::clone(&view), IngestSource::Hello, now)
                .map_err(io::Error::other)?;
            return Ok(view);
        }
    }
    // Network-verified, ingest-fresh bytes only; never seed the binding,
    // discovery or capability registries from persisted evidence.
    capture.capture(
        ann.agent_id,
        true,
        &record.announcement,
        ann.announced_at.saturating_mul(1000),
        now,
    );
    capture.capture(
        ann.agent_id,
        false,
        &record.advert,
        view.advert.created_at_unix_ms,
        now,
    );
    Ok(view)
}

fn mint_hello(
    identity: &crate::identity::Identity,
    mut v2: crate::IdentityAnnouncement,
    own_cert: &crate::announce_blob::SharedCertPair,
    caps: crate::dm::DmCapabilities,
    have: Option<[u8; 32]>,
    include_cert: bool,
) -> io::Result<Hello> {
    // The only signer is this process's identity, never a selected peer record.
    if v2.agent_id != identity.agent_id() || v2.machine_id != identity.machine_id() {
        return Err(invalid("Hello must carry our own identity"));
    }
    let pair = own_cert.read().map_err(|_| invalid("certificate lock"))?;
    v2.user_id = pair.0;
    v2.agent_certificate = pair.1.clone();
    drop(pair);
    let v3 = announce_v3::IdentityAnnouncementV3::build_from_v2(
        &v2,
        identity.machine_keypair().secret_key(),
        0,
    )
    .map_err(io::Error::other)?;
    let certificate = if include_cert && have != Some(v3.cert_digest) {
        v2.agent_certificate
            .as_ref()
            .map(|c| c.to_storage_bytes())
            .transpose()
            .map_err(io::Error::other)?
    } else {
        None
    };
    if !crate::dm_capability_service::advert_is_publishable(&caps) {
        return Err(invalid("own capabilities not ready"));
    }
    let signing = crate::gossip::SigningContext::from_keypair(identity.agent_keypair());
    let advert = crate::dm_capability_service::build_signed_advert(
        &signing,
        v2.agent_id,
        v2.machine_id,
        caps,
    )
    .map_err(io::Error::other)?;
    Ok(Hello {
        announcement: announce_v3::serialize_v3(&v3).map_err(io::Error::other)?,
        advert,
        certificate,
        have_certificate: None,
    })
}

/// Live relationship check for the shared gate's evidence-only Unknown mode.
/// Discovery locates the candidate; only ingest_hello verifies/stores its bytes.
pub(crate) async fn unknown_relationship(
    discovery: &tokio::sync::RwLock<HashMap<AgentId, crate::DiscoveredAgent>>,
    owner: &crate::owner_trust::OwnerTrust,
    agent: &AgentId,
    machine: &MachineId,
) -> bool {
    let certificate = discovery
        .read()
        .await
        .get(agent)
        .filter(|entry| entry.machine_id == *machine)
        .map(|entry| entry.agent_certificate.clone());
    let Some(certificate) = certificate else {
        return false;
    };
    owner
        .evidence()
        .and_then(|runtime| runtime.store())
        .is_some_and(|store| {
            store.related(
                *agent,
                *machine,
                certificate.as_ref(),
                dm_capability::now_unix_ms(),
            )
        })
}

pub(crate) struct Context {
    bindings: crate::dm_inbox::AuthenticatedMachineBindings,
    runtime: Arc<EvidenceRuntime>,
    capture: Arc<crate::peer_evidence::VerifiedWireCapture>,
    network: Arc<crate::network::NetworkNode>,
    identity: Arc<crate::identity::Identity>,
    template: crate::IdentityAnnouncement,
    own_cert: crate::announce_blob::SharedCertPair,
    capabilities: Arc<tokio::sync::watch::Sender<crate::dm::DmCapabilities>>,
    /// Current verified adverts, for the ADR 0093 bit-2 Hello/Lookup
    /// gate (S5): a peer whose current verified advert LACKS
    /// `peer_evidence_v1` gets no evidence traffic; unknown still sends.
    caps: Arc<crate::dm_capability::CapabilityStore>,
    discovery: Arc<tokio::sync::RwLock<HashMap<AgentId, crate::DiscoveredAgent>>>,
    machines: Arc<tokio::sync::RwLock<HashMap<MachineId, crate::DiscoveredMachine>>>,
    owner: crate::owner_trust::OwnerTrust,
    revoked: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
}
impl Context {
    async fn related(&self, machine: MachineId) -> bool {
        if self.revoked.read().await.is_machine_revoked(&machine) {
            return false;
        }
        if self
            .owner
            .is_enrolled_owner_machine(&self.revoked, &machine)
            .await
        {
            return true;
        }
        let Some(store) = self.runtime.store() else {
            return false;
        };
        let now = dm_capability::now_unix_ms();
        if store.has_machine(machine, now) {
            return true;
        }
        let cache = self.discovery.read().await;
        // Never wait for a second identity lock, and never clone an entire
        // machine's discovery entries just to decide whether to send Hello.
        let Ok(revoked) = self.revoked.try_read() else {
            return false;
        };
        cache.values().any(|d| {
            d.machine_id == machine
                && now / 1000
                    <= d.announced_at
                        .saturating_add(crate::dm_capability::ADVERT_CACHE_TTL_SECS)
                && !revoked.is_agent_revoked(&d.agent_id)
                && !revoked.is_binding_revoked(&d.agent_id, &machine)
                && !d
                    .agent_certificate
                    .as_ref()
                    .is_some_and(|c| c.is_expired(now / 1000))
                && store.related(d.agent_id, machine, d.agent_certificate.as_ref(), now)
        })
    }
    fn own(&self, have: Option<[u8; 32]>, include_cert: bool) -> io::Result<Hello> {
        self.own_with_pair(have, include_cert, &self.own_cert)
    }
    fn own_ready(&self, have: Option<[u8; 32]>, include_cert: bool) -> io::Result<Hello> {
        let pair = self
            .own_cert
            .try_read()
            .map_err(|_| invalid("certificate busy"))?
            .clone();
        // Minting may take CPU time, but never waits on a shared cert lock.
        self.own_with_pair(have, include_cert, &Arc::new(std::sync::RwLock::new(pair)))
    }
    fn own_with_pair(
        &self,
        have: Option<[u8; 32]>,
        include_cert: bool,
        pair: &crate::announce_blob::SharedCertPair,
    ) -> io::Result<Hello> {
        let mut v2 = self.template.clone();
        v2.announced_at = dm_capability::now_unix_ms() / 1000;
        v2.addresses = self
            .network
            .local_addr()
            .filter(|a| a.port() != 0)
            .map(|addr| {
                crate::filter_discovery_announcement_addrs(
                    crate::bind_dialable_interface_hints(Some(addr), addr.port()),
                    crate::allow_local_discovery_addresses(self.network.config()),
                )
            })
            .unwrap_or_default();
        mint_hello(
            &self.identity,
            v2,
            pair,
            self.capabilities.borrow().clone(),
            have,
            include_cert,
        )
    }

    fn ingest(
        &self,
        machine: MachineId,
        record: EvidenceRecordV1,
    ) -> io::Result<Arc<EvidenceView>> {
        ingest_hello(
            self.runtime.store().as_ref(),
            &self.capture,
            &self.runtime.wire_limits,
            machine,
            record,
            dm_capability::now_unix_ms(),
        )
    }
    async fn accept(self: Arc<Self>, mut stream: PeerStream) {
        let Some(lease) = stream.evidence_lease.take() else {
            return;
        };
        let lease = Arc::new(lease);
        let machine = stream.peer();
        let (mut send, mut recv) = stream.into_split();
        let result = tokio::time::timeout_at(lease.deadline, async {
            let (kind, body) = read_message(&mut recv, &self.runtime.wire_limits).await?;
            if !self.runtime.wait(0).await {
                return Err(invalid("evidence load deadline"));
            }
            match kind {
                LOOKUP => {
                    if !self.runtime.wire_limits.request(machine, false) {
                        WireCounters::bump(
                            &self.runtime.wire_limits.counters.evidence_lookup_refused,
                        );
                        return Err(invalid("lookup rate"));
                    }
                    let target: AgentId = codec().deserialize(&body).map_err(io::Error::other)?;
                    drop(body);
                    let context = Arc::clone(&self);
                    let authorized = context.authorized(machine, target).await;
                    if !authorized {
                        WireCounters::bump(
                            &self
                                .runtime
                                .wire_limits
                                .counters
                                .evidence_lookup_unauthorized,
                        );
                    }
                    let serving_lease = Arc::clone(&lease);
                    let reply = tokio::task::spawn_blocking(move || {
                        let _lease = serving_lease;
                        if authorized {
                            context.lookup_reply(target)
                        } else {
                            Ok(None)
                        }
                    })
                    .await
                    .map_err(io::Error::other)??;
                    // Membership/revocation may have changed while signing.
                    let reply = if reply.is_some() && !self.authorized(machine, target).await {
                        WireCounters::bump(
                            &self
                                .runtime
                                .wire_limits
                                .counters
                                .evidence_lookup_unauthorized,
                        );
                        None
                    } else {
                        reply
                    };
                    let (kind, body) = match reply {
                        Some(reply) => {
                            (FOUND, codec().serialize(&reply).map_err(io::Error::other)?)
                        }
                        None => (NOT_FOUND, Vec::new()),
                    };
                    write_message(&mut send, &self.runtime.wire_limits, machine, kind, &body).await
                }
                HELLO | CERTIFICATE => {
                    if kind == HELLO && !self.runtime.wire_limits.request(machine, true) {
                        WireCounters::bump(
                            &self.runtime.wire_limits.counters.evidence_hello_refused,
                        );
                        return Err(invalid("Hello rate"));
                    }
                    let hello = match decode::hello(&body) {
                        Ok(hello) => hello,
                        Err(e) => {
                            WireCounters::bump(
                                &self.runtime.wire_limits.counters.evidence_hello_refused,
                            );
                            return Err(e);
                        }
                    };
                    drop(body);
                    if kind == CERTIFICATE {
                        let ann = announce_v3::deserialize_v3(&hello.announcement)
                            .map_err(io::Error::other)?;
                        if hello.certificate.is_none()
                            || !self.runtime.wire_limits.take_certificate(
                                machine,
                                ann.agent_id,
                                ann.cert_digest,
                            )
                        {
                            WireCounters::bump(
                                &self.runtime.wire_limits.counters.evidence_hello_refused,
                            );
                            return Err(invalid("unsolicited certificate"));
                        }
                    } else if hello.certificate.is_some() {
                        WireCounters::bump(
                            &self.runtime.wire_limits.counters.evidence_hello_refused,
                        );
                        return Err(invalid("unsolicited certificate"));
                    }
                    let have = hello.have_certificate;
                    let record = hello.into_record();
                    let context = Arc::clone(&self);
                    let verifying_lease = Arc::clone(&lease);
                    let view = tokio::task::spawn_blocking(move || {
                        let _lease = verifying_lease;
                        context.ingest(machine, record)
                    })
                    .await
                    .map_err(io::Error::other)
                    .and_then(|result| result.map_err(io::Error::other))
                    .inspect(|_| {
                        if kind == HELLO {
                            WireCounters::bump(
                                &self.runtime.wire_limits.counters.evidence_hello_received,
                            );
                        }
                    })
                    .inspect_err(|_| {
                        WireCounters::bump(
                            &self.runtime.wire_limits.counters.evidence_hello_refused,
                        );
                    })?;
                    if kind == CERTIFICATE {
                        return write_message(
                            &mut send,
                            &self.runtime.wire_limits,
                            machine,
                            ACK,
                            &[],
                        )
                        .await;
                    }
                    let have_peer = view
                        .certificate
                        .as_ref()
                        .map(|_| view.announcement.cert_digest);
                    if have_peer.is_none()
                        && crate::announce_blob::fetch_warranted(&view.announcement.cert_digest)
                    {
                        self.runtime.wire_limits.need_certificate(
                            machine,
                            view.announcement.agent_id,
                            view.announcement.cert_digest,
                        );
                    }
                    // A simultaneous on-connect request may already have sent
                    // our Hello. Replies and requests share its 60-second gate.
                    if !crate::dm_capability_service::advert_is_publishable(
                        &self.capabilities.borrow(),
                    ) || self
                        .begin_hello_current(machine, self.related(machine).await)
                        .is_none()
                    {
                        let body = codec().serialize(&have_peer).map_err(io::Error::other)?;
                        return write_message(
                            &mut send,
                            &self.runtime.wire_limits,
                            machine,
                            ACK,
                            &body,
                        )
                        .await;
                    }
                    let mut reply = self.own(have, true)?;
                    reply.have_certificate = have_peer;
                    let body = codec().serialize(&reply).map_err(io::Error::other)?;
                    write_message(&mut send, &self.runtime.wire_limits, machine, HELLO, &body).await
                }
                _ => Err(invalid("unexpected evidence request")),
            }
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            self.runtime.wire_limits.reset(machine);
            // Only this stream is dropped. No connection close or retry signal.
            tracing::debug!(?machine, "evidence stream refused/reset");
        }
    }
    fn begin_hello_current(&self, machine: MachineId, related: bool) -> Option<u64> {
        let Ok(Some(generation)) = self
            .network
            .try_connection_generation(&ant_quic::PeerId(machine.0))
        else {
            // Busy or absent is not evidence of a replacement. Do not clear
            // a consumed marker or start an attempt with unknown ownership.
            tracing::debug!(
                %machine,
                outcome = "hello_reply_gate_closed",
                "evidence Hello reply skipped"
            );
            return None;
        };
        if !self
            .runtime
            .wire_limits
            .begin_hello_on_connection(machine, related, Some(generation))
        {
            tracing::debug!(
                %machine,
                outcome = "hello_reply_attempt_unavailable",
                "evidence Hello reply skipped"
            );
            return None;
        }
        Some(generation)
    }

    #[cfg(test)]
    async fn pause_hello_open(&self, after_open: bool) {
        let pause = self
            .runtime
            .wire_limits
            .hello_open_pause
            .lock()
            .unwrap()
            .clone();
        if let Some(pause) = pause.filter(|p| p.after_open == after_open) {
            pause.reached.notify_one();
            pause.resume.notified().await;
        }
    }

    fn same_connection(&self, machine: MachineId, generation: u64) -> bool {
        self.network
            .try_connection_generation(&ant_quic::PeerId(machine.0))
            == Ok(Some(generation))
    }

    async fn exchange(
        &self,
        machine: MachineId,
        kind: u8,
        hello: Hello,
        generation: Option<u64>,
        policy: Option<&ReadyPolicy>,
    ) -> io::Result<(Lease, u8, Vec<u8>)> {
        let reserved = if policy.is_some() {
            let now = dm_capability::now_unix_ms();
            let revoked = self
                .revoked
                .try_read()
                .map_err(|_| invalid("revocation busy"))?;
            if revoked.is_machine_revoked(&machine) {
                return Err(invalid("revoked machine"));
            }
            let enrolled = self
                .owner
                .try_evidence_relation(self.identity.agent_id(), machine, None, &revoked, now)
                .ok_or_else(|| invalid("owner policy busy"))?
                & crate::peer_evidence::ENROLLED
                != 0;
            enrolled
                || self
                    .runtime
                    .store()
                    .and_then(|s| s.try_has_machine(machine, now, READY_AGENT_CAP))
                    .ok_or_else(|| invalid("evidence busy"))?
        } else {
            reserved_peer(
                self.runtime.store().as_deref(),
                &self.owner,
                &self.revoked,
                machine,
            )
            .await
        };
        let lease = self
            .runtime
            .wire_limits
            .admit(machine, reserved)
            .ok_or_else(|| invalid("evidence stream budget"))?;
        let (kind, body) = tokio::time::timeout_at(lease.deadline, async {
            #[cfg(test)]
            if kind == HELLO {
                self.pause_hello_open(false).await;
            }
            if generation.is_some_and(|g| !self.same_connection(machine, g)) {
                tracing::debug!(
                    %machine,
                    outcome = "hello_generation_changed_before_open",
                    "evidence Hello connection check failed"
                );
                return Err(invalid("Hello connection replaced"));
            }
            let (mut send, mut recv) = self
                .network
                .open_bi(&ant_quic::PeerId(machine.0))
                .await
                .map_err(io::Error::other)?;
            #[cfg(test)]
            if kind == HELLO {
                self.pause_hello_open(true).await;
            }
            if let Some(generation) = generation.filter(|_| policy.is_some()) {
                // Open may yield. A busy Hello defers to the next pass. Its
                // certificate continuation has no later pass, so retry busy
                // reads on this empty stream within the same lease deadline.
                loop {
                    let eligible = policy.map_or(Some(true), |p| p.eligible(self, machine));
                    let current = self
                        .network
                        .try_connection_generation(&ant_quic::PeerId(machine.0));
                    if eligible == Some(false)
                        || matches!(current, Ok(value) if value != Some(generation))
                    {
                        tracing::debug!(
                            %machine,
                            outcome = "hello_generation_or_policy_changed_after_open",
                            "evidence Hello connection or policy check failed"
                        );
                        return Err(invalid("Hello no longer eligible"));
                    }
                    if eligible == Some(true) && current == Ok(Some(generation)) {
                        break;
                    }
                    if kind != CERTIFICATE {
                        tracing::debug!(
                            %machine,
                            outcome = "hello_generation_or_policy_unreadable_after_open",
                            "evidence Hello connection or policy check unavailable"
                        );
                        return Err(invalid("Hello no longer eligible"));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            } else if generation.is_some_and(|g| !self.same_connection(machine, g)) {
                // Open may yield across a replacement. Drop the empty stream
                // without consuming the marker or starting the rate window.
                tracing::debug!(
                    %machine,
                    outcome = "hello_generation_changed_after_open",
                    "evidence Hello connection check failed"
                );
                return Err(invalid("Hello connection replaced"));
            }
            if kind == HELLO
                && !self
                    .runtime
                    .wire_limits
                    .begin_hello_on_connection(machine, true, generation)
            {
                return Err(invalid("Hello already attempted"));
            }
            send.write_u8(StreamProtocol::EvidenceV1.as_u8()).await?;
            // Preserve the default-off serialization point and deadline.
            let body = codec().serialize(&hello).map_err(io::Error::other)?;
            drop(hello);
            write_message(&mut send, &self.runtime.wire_limits, machine, kind, &body).await?;
            drop(body);
            read_message(&mut recv, &self.runtime.wire_limits).await
        })
        .await
        .map_err(io::Error::other)??;
        Ok((lease, kind, body))
    }
    async fn connect(
        self: Arc<Self>,
        machine: MachineId,
        mut generation: Option<u64>,
        policy: Option<Arc<ReadyPolicy>>,
    ) {
        if let Some(policy) = &policy {
            // Enabled jobs are admitted only when ready; a changed prerequisite
            // defers to the next pass without holding a slot through a wait.
            if policy.eligible(&self, machine) != Some(true) {
                return;
            }
        } else {
            // Preserve the original capability wait and skip before load.
            let mut caps = self.capabilities.subscribe();
            if !matches!(
                tokio::time::timeout(DEADLINE, async {
                    loop {
                        if crate::dm_capability_service::advert_is_publishable(&caps.borrow()) {
                            return Ok::<(), io::Error>(());
                        }
                        caps.changed().await.map_err(io::Error::other)?;
                    }
                })
                .await,
                Ok(Ok(()))
            ) {
                return;
            }
            if self.caps.machine_registry_supports(
                &machine,
                crate::dm::CapabilityRegistry::PEER_EVIDENCE_V1,
            ) == Some(false)
            {
                return;
            }
            if !self.runtime.wait(0).await {
                return;
            }
            if !self.related(machine).await {
                return;
            }
        }
        let Some(_job) = self.runtime.wire_limits.pin_machine(machine) else {
            tracing::debug!(
                %machine,
                outcome = "hello_machine_budget_unavailable",
                "evidence Hello connect skipped"
            );
            return;
        };
        if policy.is_none() {
            let Ok(Some(current)) = self
                .network
                .try_connection_generation(&ant_quic::PeerId(machine.0))
            else {
                // Unknown ownership cannot authorize an attempt. Leave both
                // the marker and rate timestamp untouched; no default-off retry.
                tracing::debug!(
                    %machine,
                    outcome = "hello_connect_generation_unreadable",
                    "evidence Hello connect skipped"
                );
                return;
            };
            if !self.runtime.wire_limits.hello_candidate(machine, current) {
                tracing::debug!(
                    %machine,
                    outcome = "hello_connect_not_candidate",
                    "evidence Hello connect skipped"
                );
                return;
            }
            generation = Some(current);
        }
        if self
            .send_hello(machine, generation, policy.as_deref())
            .await
            .is_err()
        {
            self.runtime.wire_limits.reset(machine);
        }
    }
    async fn send_hello(
        self: &Arc<Self>,
        machine: MachineId,
        generation: Option<u64>,
        policy: Option<&ReadyPolicy>,
    ) -> io::Result<()> {
        let mut hello = if policy.is_some() {
            self.own_ready(None, false)?
        } else {
            self.own(None, false)?
        };
        // A missing digest only asks the peer to include its certificate. The
        // opt-in path must not block on the optional cache optimization.
        if policy.is_none() {
            hello.have_certificate = self
                .runtime
                .store()
                .and_then(|s| s.machine_certificate_digest(machine, dm_capability::now_unix_ms()));
        }
        let (lease, kind, body) = self
            .exchange(machine, HELLO, hello, generation, policy)
            .await?;
        let have = match kind {
            ACK => codec()
                .deserialize::<Option<[u8; 32]>>(&body)
                .map_err(io::Error::other)?,
            HELLO => {
                let reply = decode::hello(&body)?;
                let have = reply.have_certificate;
                drop(body);
                let context = Arc::clone(self);
                // Keep the reply reservation alive through durable verification.
                tokio::task::spawn_blocking(move || {
                    let _lease = lease;
                    context.ingest(machine, reply.into_record())
                })
                .await
                .map_err(io::Error::other)??;
                return self
                    .send_certificate_if_missing(machine, have, generation, policy)
                    .await;
            }
            _ => return Err(invalid("evidence Hello refused")),
        };
        drop(body);
        drop(lease);
        self.send_certificate_if_missing(machine, have, generation, policy)
            .await
    }
    async fn send_certificate_if_missing(
        &self,
        machine: MachineId,
        have: Option<[u8; 32]>,
        generation: Option<u64>,
        policy: Option<&ReadyPolicy>,
    ) -> io::Result<()> {
        let follow = if policy.is_some() {
            self.own_ready(have, true)?
        } else {
            self.own(have, true)?
        };
        if follow.certificate.is_some() {
            let (_lease, kind, body) = self
                .exchange(machine, CERTIFICATE, follow, generation, policy)
                .await?;
            if kind != ACK || !body.is_empty() {
                return Err(invalid("certificate refused"));
            }
        }
        Ok(())
    }
}

/// Live denial inputs for the opt-in outgoing path. These are borrowed with
/// try-locks only; a busy read is not an authorization or a consumed attempt.
struct ReadyPolicy {
    contacts: Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    placements: Arc<tokio::sync::RwLock<crate::key_move::MoveState>>,
}
impl ReadyPolicy {
    fn eligible(&self, context: &Context, machine: MachineId) -> Option<bool> {
        if !context.runtime.is_ready() {
            return None;
        }
        if !crate::dm_capability_service::advert_is_publishable(&context.capabilities.borrow()) {
            return Some(false);
        }
        if context
            .caps
            .try_machine_registry_supports(
                &machine,
                crate::dm::CapabilityRegistry::PEER_EVIDENCE_V1,
            )
            .ok()?
            == Some(false)
        {
            return Some(false);
        }
        let store = context.runtime.store()?;
        let now = dm_capability::now_unix_ms();
        let cache = context.discovery.try_read().ok()?;
        let revoked = context.revoked.try_read().ok()?;
        let contacts = self.contacts.try_read().ok()?;
        let placements = self.placements.try_read().ok()?;
        if revoked.is_machine_revoked(&machine) {
            return Some(false);
        }
        let trust = crate::trust::TrustEvaluator::new(&contacts);
        let mut agents = store
            .try_agents_on_machine(machine, READY_AGENT_CAP + 1)
            .ok()?;
        agents.extend(
            cache
                .values()
                .filter(|d| d.machine_id == machine)
                .map(|d| d.agent_id)
                .take(READY_AGENT_CAP + 1),
        );
        agents.sort_by_key(|a| a.0);
        agents.dedup();
        if agents.len() > READY_AGENT_CAP {
            // Do not miss a co-resident denial by truncating authority input.
            return Some(false);
        }
        let mut related = context.owner.try_evidence_relation(
            context.identity.agent_id(),
            machine,
            None,
            &revoked,
            now,
        )? & crate::peer_evidence::ENROLLED
            != 0;
        for agent in agents {
            let discovery = cache.get(&agent).filter(|d| d.machine_id == machine);
            if revoked.is_agent_revoked(&agent)
                || matches!(
                    trust.evaluate(&crate::trust::TrustContext {
                        agent_id: &agent,
                        machine_id: &machine,
                    }),
                    crate::trust::TrustDecision::RejectBlocked
                        | crate::trust::TrustDecision::RejectMachineMismatch
                )
                || discovery.is_some_and(|d| {
                    crate::identity::is_expired(d.cert_not_after, now / 1000)
                        || d.agent_certificate
                            .as_ref()
                            .is_some_and(|c| c.is_expired(now / 1000))
                })
            {
                return Some(false);
            }
            // Dead pairings do not become authority; live co-residents can
            // still establish a relationship, as in the shared machine gate.
            if crate::key_move::enforce_pairing(
                &revoked,
                placements.placement_view(),
                &agent,
                &machine,
            )
            .is_some()
            {
                continue;
            }
            if let Some(d) = discovery {
                if now / 1000
                    <= d.announced_at
                        .saturating_add(dm_capability::ADVERT_CACHE_TTL_SECS)
                {
                    related |=
                        store.try_related(agent, machine, d.agent_certificate.as_ref(), now)?;
                }
            }
            related |= store
                .try_usable_agent(agent, now)
                .ok()?
                .is_some_and(|view| view.announcement.machine_id == machine);
        }
        Some(related)
    }
}

const LOOP_JOB_CAP: usize = 64;
const READY_PASS_CAP: usize = 64;
const READY_AGENT_CAP: usize = 64;
const READY_INTERVAL: Duration = Duration::from_secs(1);

struct WireJob {
    machine: MachineId,
    outgoing: bool,
    abort: tokio::task::AbortHandle,
}

/// Both ingress and outgoing work use this single admission point. Aborted
/// jobs keep their slot and machine ownership until JoinSet reports completion.
#[derive(Default)]
struct WireJobs {
    tasks: tokio::task::JoinSet<()>,
    jobs: HashMap<tokio::task::Id, WireJob>,
}
impl WireJobs {
    fn outgoing(&self, machine: MachineId) -> bool {
        self.jobs
            .values()
            .any(|j| j.machine == machine && j.outgoing)
    }
    fn spawn(
        &mut self,
        machine: MachineId,
        outgoing: bool,
        task: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> bool {
        if self.tasks.len() >= LOOP_JOB_CAP || (outgoing && self.outgoing(machine)) {
            return false;
        }
        let abort = self.tasks.spawn(task);
        self.jobs.insert(
            abort.id(),
            WireJob {
                machine,
                outgoing,
                abort,
            },
        );
        true
    }
    fn cancel(&self, machine: MachineId) {
        for job in self
            .jobs
            .values()
            .filter(|j| j.machine == machine && j.outgoing)
        {
            job.abort.abort();
        }
    }
    async fn join(&mut self) -> Option<Result<(), tokio::task::JoinError>> {
        let result = self.tasks.join_next_with_id().await?;
        let id = match &result {
            Ok((id, ())) => *id,
            Err(error) => error.id(),
        };
        self.jobs.remove(&id);
        Some(result.map(|(_, ())| ()))
    }
    async fn shutdown(&mut self) {
        self.tasks.abort_all();
        while !self.tasks.is_empty() {
            let _ = self.join().await;
        }
    }
}

/// Only current connections occupy this queue. Its rotation advances even
/// when a candidate is busy, ineligible, or already owns a job.
struct ReadyConnections {
    order: VecDeque<MachineId>,
    generations: HashMap<MachineId, Option<u64>>,
    cap: usize,
    last_pass: Option<Instant>,
}
impl ReadyConnections {
    fn new(cap: u32) -> Self {
        Self {
            order: VecDeque::new(),
            generations: HashMap::new(),
            cap: if cap == 0 {
                crate::network::DEFAULT_MAX_CONNECTIONS
            } else {
                cap
            } as usize,
            last_pass: None,
        }
    }
    fn insert(&mut self, machine: MachineId) -> bool {
        if self.generations.contains_key(&machine) {
            return true;
        }
        if self.order.len() >= self.cap {
            return false;
        }
        self.order.push_back(machine);
        self.generations.insert(machine, None);
        true
    }
    fn remove(&mut self, machine: MachineId, jobs: &WireJobs, limits: &Limits) {
        self.order.retain(|m| *m != machine);
        self.generations.remove(&machine);
        jobs.cancel(machine);
        // Even a peer rejected by the tracking cap can have an inbound marker.
        limits.disconnect(machine);
    }
    fn generation(&mut self, machine: MachineId, id: u64, jobs: &WireJobs, limits: &Limits) {
        if let Some(previous) = self.generations.get_mut(&machine) {
            if previous.is_some_and(|old| old != id) {
                jobs.cancel(machine);
            }
            // A reply may already have consumed this generation before the
            // readiness pass observes it. Never clear that new marker.
            limits.hello_connection(machine, id);
            *previous = Some(id);
        }
    }
    fn candidates(&mut self, now: Instant) -> Vec<MachineId> {
        if self
            .last_pass
            .is_some_and(|last| now.duration_since(last) < READY_INTERVAL)
        {
            return Vec::new();
        }
        self.last_pass = Some(now);
        let mut result = Vec::with_capacity(READY_PASS_CAP.min(self.order.len()));
        for _ in 0..READY_PASS_CAP.min(self.order.len()) {
            if let Some(machine) = self.order.pop_front() {
                self.order.push_back(machine);
                result.push(machine);
            }
        }
        result
    }
}

impl crate::Agent {
    pub(crate) fn start_evidence_wire(&self) {
        let Some(network) = &self.network else {
            return;
        };
        let Ok(mut acceptor) = self.register_stream_acceptor(StreamProtocol::EvidenceV1) else {
            return;
        };
        let Ok(template) = self.build_announcement(false, false) else {
            return;
        };
        let enabled = self
            .peer_evidence()
            .wire_limits
            .ready_hello
            .load(std::sync::atomic::Ordering::Acquire);
        let policy = enabled.then(|| {
            Arc::new(ReadyPolicy {
                contacts: Arc::clone(&self.contact_store),
                placements: Arc::clone(&self.move_state),
            })
        });
        let context = Arc::new(Context {
            bindings: Arc::clone(&self.authenticated_machine_bindings),
            runtime: Arc::clone(self.peer_evidence()),
            capture: Arc::clone(&self.capability_store.evidence_wire),
            network: Arc::clone(network),
            identity: Arc::clone(&self.identity),
            template,
            own_cert: Arc::clone(&self.own_cert_pair),
            capabilities: Arc::clone(&self.dm_capabilities_tx),
            caps: Arc::clone(&self.capability_store),
            discovery: Arc::clone(&self.identity_discovery_cache),
            machines: Arc::clone(&self.machine_discovery_cache),
            owner: self.owner_trust.clone(),
            revoked: Arc::clone(&self.revocation_set),
        });
        let _ = self
            .peer_evidence()
            .lookup_context
            .set(Arc::downgrade(&context));
        // Subscribe synchronously, before spawning: don't lose early connects.
        let mut events = network.subscribe();
        let token = self.shutdown_token.clone();
        self.spawn_tracked(async move {
            if !enabled {
                // Preserve the original event loop, including duplicate connect
                // jobs, disconnect handling, select fairness and shutdown.
                let mut tasks = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                        stream = acceptor.next() => {
                            let Some(stream) = stream else { break; };
                            tasks.spawn(Arc::clone(&context).accept(stream));
                        }
                        event = events.recv() => match event {
                            Ok(crate::network::NetworkEvent::PeerConnected { peer_id, .. }) if tasks.len() < 64 => {
                                tasks.spawn(Arc::clone(&context).connect(MachineId(peer_id), None, None));
                            }
                            Ok(crate::network::NetworkEvent::PeerDisconnected { peer_id, .. }) => context.runtime.wire_limits.disconnect(MachineId(peer_id)),
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            _ => {},
                        },
                    }
                }
                tasks.abort_all();
                return;
            }
            let mut jobs = WireJobs::default();
            let mut connections = ReadyConnections::new(context.network.config().max_connections);
            let mut tick = tokio::time::interval(READY_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The immediate first tick includes startup connections. Only an
            // authoritative absent generation removes tracking, never a snapshot.
            'wire: loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = jobs.join(), if !jobs.tasks.is_empty() => {},
                    at = tick.tick() => {
                        let peers = tokio::select! {
                            _ = token.cancelled() => break 'wire,
                            peers = context.network.connected_peers() => peers,
                        };
                        for peer in peers {
                            connections.insert(MachineId(peer.0));
                        }
                        for machine in connections.candidates(at) {
                            let generation = match context.network.try_connection_generation(&ant_quic::PeerId(machine.0)) {
                                Ok(Some(generation)) => generation,
                                Ok(None) => {
                                    connections.remove(machine, &jobs, &context.runtime.wire_limits);
                                    continue;
                                }
                                // Busy/unavailable is not a disconnect. Retain
                                // the generation and consumed-attempt marker.
                                Err(()) => continue,
                            };
                            connections.generation(machine, generation, &jobs, &context.runtime.wire_limits);
                            if context.runtime.wire_limits.hello_pending(machine)
                                && !jobs.outgoing(machine)
                                && policy.as_ref().is_some_and(|p| p.eligible(&context, machine) == Some(true))
                            {
                                jobs.spawn(machine, true, Arc::clone(&context).connect(machine, Some(generation), policy.clone()));
                            }
                        }
                    }
                    stream = acceptor.next() => {
                        let Some(stream) = stream else { break; };
                        let machine = stream.peer();
                        if !jobs.spawn(machine, false, Arc::clone(&context).accept(stream)) {
                            context.runtime.wire_limits.reset(machine);
                        }
                    }
                    event = events.recv() => match event {
                        Ok(crate::network::NetworkEvent::PeerConnected { peer_id, .. }) => {
                            connections.insert(MachineId(peer_id));
                        }
                        Ok(crate::network::NetworkEvent::PeerDisconnected { peer_id, .. }) => {
                            let machine = MachineId(peer_id);
                            if !connections.generations.contains_key(&machine) {
                                // Over-cap peers can still have inbound markers.
                                // No tracked generation needs a replacement fence.
                                connections.remove(machine, &jobs, &context.runtime.wire_limits);
                                continue;
                            }
                            // A delayed event can describe an old generation.
                            match context.network.try_connection_generation(&ant_quic::PeerId(peer_id)) {
                                Ok(Some(generation)) => {
                                    if connections.insert(machine) {
                                        connections.generation(machine, generation, &jobs, &context.runtime.wire_limits);
                                    }
                                }
                                Ok(None) => connections.remove(machine, &jobs, &context.runtime.wire_limits),
                                Err(()) => {},
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        _ => {},
                    },
                }
            }
            jobs.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issue1207_shared_job_bound_and_cancelled_slots_are_not_reused() {
        let mut jobs = WireJobs::default();
        let machine = MachineId([1; 32]);
        assert!(jobs.spawn(machine, true, std::future::pending()));
        for _ in 0..10_000 {
            assert!(!jobs.spawn(machine, true, std::future::pending()));
        }
        for i in 1..LOOP_JOB_CAP {
            assert!(jobs.spawn(MachineId([i as u8; 32]), false, std::future::pending()));
        }
        assert_eq!(jobs.tasks.len(), LOOP_JOB_CAP);
        assert!(!jobs.spawn(MachineId([99; 32]), true, std::future::pending()));
        assert!(!jobs.spawn(MachineId([99; 32]), false, std::future::pending()));
        jobs.cancel(machine);
        assert!(jobs.outgoing(machine));
        assert_eq!(jobs.tasks.len(), LOOP_JOB_CAP);
        assert!(!jobs.spawn(machine, true, std::future::pending()));
        let _ = jobs.join().await;
        assert_eq!(jobs.tasks.len(), LOOP_JOB_CAP - 1);
        assert!(
            jobs.jobs
                .values()
                .any(|j| j.machine == machine && !j.outgoing && !j.abort.is_finished()),
            "cancellation must preserve inbound work for this machine"
        );
        jobs.shutdown().await;
        assert!(jobs.tasks.is_empty());
        assert!(jobs.jobs.is_empty());
    }

    #[tokio::test]
    async fn issue1207_round_robin_pass_rate_capacity_and_generation_cancellation() {
        let mut connections = ReadyConnections::new(130);
        let mut jobs = WireJobs::default();
        let limits = Limits::default();
        for i in 0..130 {
            assert!(connections.insert(MachineId([i; 32])));
        }
        assert!(!connections.insert(MachineId([200; 32])));
        assert_eq!(connections.generations.len(), 130);
        let now = Instant::now();
        let first = connections.candidates(now);
        assert_eq!(first.len(), 64);
        for _ in 0..10_000 {
            assert!(connections.candidates(now).is_empty());
        }
        assert!(connections
            .candidates(now + Duration::from_millis(999))
            .is_empty());
        let second = connections.candidates(now + READY_INTERVAL);
        assert_eq!(second.len(), 64);
        assert!(!second.iter().any(|m| first.contains(m)));
        let third = connections.candidates(now + READY_INTERVAL * 100);
        assert_eq!(&third[..2], &[MachineId([128; 32]), MachineId([129; 32])]);
        assert!(connections
            .candidates(now + READY_INTERVAL * 100)
            .is_empty());
        assert_eq!(
            ReadyConnections::new(0).cap,
            crate::network::DEFAULT_MAX_CONNECTIONS as usize
        );

        let machine = first[0];
        connections.generation(machine, 10, &jobs, &limits);
        assert!(jobs.spawn(machine, true, std::future::pending()));
        assert!(limits.begin_hello(machine, true));
        connections.generation(machine, 11, &jobs, &limits);
        assert!(
            jobs.outgoing(machine),
            "cancelled generation still owns its job slot"
        );
        let _ = jobs.join().await;
        assert!(!jobs.outgoing(machine));
        assert!(
            !limits.begin_hello(machine, true),
            "replacement retains per-machine cooldown"
        );
        assert!(jobs.spawn(machine, true, std::future::pending()));
        connections.remove(machine, &jobs, &limits);
        assert!(!connections.generations.contains_key(&machine));
        assert!(!connections.order.contains(&machine));
        let _ = jobs.join().await;
        assert!(jobs.jobs.is_empty());
        let overflow = MachineId([200; 32]);
        assert!(limits.begin_hello(overflow, true));
        assert!(!connections.generations.contains_key(&overflow));
        connections.remove(overflow, &jobs, &limits);
        assert!(
            limits.state.lock().unwrap().machines[&overflow].attempted,
            "generation-blind disconnect must retain an inbound attempt"
        );
    }

    // Real loopback connections; executed only by the isolated Linux CI lane.
    async fn ready_test_agent(path: &std::path::Path) -> crate::Agent {
        std::fs::create_dir_all(path).unwrap();
        crate::Agent::builder()
            .with_identity_dir(path)
            .with_machine_key(path.join("machine.key"))
            .with_agent_key_path(path.join("agent.key"))
            .with_user_key_path(path.join("user.key"))
            .with_agent_cert_path(path.join("agent.cert"))
            .with_contact_store_path(path.join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(crate::network::NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..Default::default()
            })
            .build()
            .await
            .unwrap()
    }

    fn ready_test_context(agent: &crate::Agent) -> Arc<Context> {
        Arc::new(Context {
            bindings: Arc::clone(&agent.authenticated_machine_bindings),
            runtime: Arc::clone(agent.peer_evidence()),
            capture: Arc::clone(&agent.capability_store.evidence_wire),
            network: Arc::clone(agent.network.as_ref().unwrap()),
            identity: Arc::clone(&agent.identity),
            template: agent.build_announcement(false, false).unwrap(),
            own_cert: Arc::clone(&agent.own_cert_pair),
            capabilities: Arc::clone(&agent.dm_capabilities_tx),
            caps: Arc::clone(&agent.capability_store),
            discovery: Arc::clone(&agent.identity_discovery_cache),
            machines: Arc::clone(&agent.machine_discovery_cache),
            owner: agent.owner_trust.clone(),
            revoked: Arc::clone(&agent.revocation_set),
        })
    }

    async fn ready_test_policy(
        a: &crate::Agent,
        b: &crate::Agent,
        path: &std::path::Path,
    ) -> Arc<ReadyPolicy> {
        let context = ready_test_context(a);
        let peer = b.agent_id();
        let runtime_policy = Arc::new(crate::peer_evidence::RuntimePolicy::new(
            a.agent_id(),
            a.owner_trust.clone(),
            Arc::clone(&a.revocation_set),
        ));
        runtime_policy.set_groups(Arc::new(move |agent| Some(agent == peer)));
        assert!(context.runtime.start(
            path.to_path_buf(),
            Default::default(),
            runtime_policy,
            Arc::clone(&context.capture)
        ));
        assert!(context.runtime.wait(0).await);
        for agent in [a, b] {
            agent
                .dm_capabilities_tx
                .send_replace(crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]));
        }
        context
            .ingest(
                b.machine_id(),
                ready_test_context(b)
                    .own(None, false)
                    .unwrap()
                    .into_record(),
            )
            .unwrap();
        let policy = Arc::new(ReadyPolicy {
            contacts: Arc::clone(&a.contact_store),
            placements: Arc::clone(&a.move_state),
        });
        assert_eq!(policy.eligible(&context, b.machine_id()), Some(true));
        policy
    }

    #[tokio::test]
    async fn issue1207_store_set_before_ready_defers_hello_without_charging_barrier() {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir().unwrap();
        let a = ready_test_agent(&dir.path().join("a")).await;
        let b = ready_test_agent(&dir.path().join("b")).await;
        let policy = ready_test_policy(&a, &b, &dir.path().join("evidence")).await;
        let mut context = ready_test_context(&a);
        // Model start's exact store-set/not-ready window with a verified,
        // otherwise eligible stored binding and no discovery-cache fallback.
        let (runtime, ready) =
            EvidenceRuntime::loading_store_for_test(context.runtime.store().unwrap());
        Arc::get_mut(&mut context).unwrap().runtime = runtime;
        assert!(context.discovery.read().await.is_empty());
        let machine = b.machine_id();
        context
            .network
            .connect_addr(b.network().unwrap().bound_addr().await.unwrap())
            .await
            .unwrap();
        let generation = context
            .network
            .try_connection_generation(&ant_quic::PeerId(machine.0))
            .unwrap()
            .unwrap();
        let mut connections = ReadyConnections::new(1);
        assert!(connections.insert(machine));
        let now = Instant::now();
        assert!(context.runtime.store().is_some());
        assert!(!context.runtime.is_ready());
        assert_eq!(policy.eligible(&context, machine), None);
        for candidate in connections.candidates(now) {
            Arc::clone(&context)
                .connect(candidate, Some(generation), Some(Arc::clone(&policy)))
                .await;
        }
        let limits = &context.runtime.wire_limits;
        assert_eq!(
            limits.counters.evidence_hello_sent.load(Ordering::Relaxed),
            0
        );
        assert!(limits.hello_pending(machine));
        assert_eq!(
            context
                .runtime
                .evidence_load_barrier_waits
                .load(Ordering::Relaxed),
            0
        );

        ready.cancel();
        assert_eq!(policy.eligible(&context, machine), Some(true));
        let remote = Arc::clone(b.network.as_ref().unwrap());
        let reader = tokio::spawn(async move {
            let (_, mut send, mut recv) = remote.accept_bi().await.unwrap();
            assert_eq!(
                recv.read_u8().await.unwrap(),
                StreamProtocol::EvidenceV1.as_u8()
            );
            let limits = Arc::new(Limits::default());
            let (kind, body) = read_message(&mut recv, &limits).await.unwrap();
            assert_eq!(kind, HELLO);
            assert!(decode::hello(&body).is_ok());
            write_message(
                &mut send,
                &limits,
                MachineId([7; 32]),
                ACK,
                &codec().serialize(&Option::<[u8; 32]>::None).unwrap(),
            )
            .await
            .unwrap();
        });
        for at in [now + READY_INTERVAL, now + READY_INTERVAL * 2] {
            for candidate in connections.candidates(at) {
                if limits.hello_pending(candidate) {
                    Arc::clone(&context)
                        .connect(candidate, Some(generation), Some(Arc::clone(&policy)))
                        .await;
                }
            }
        }
        tokio::time::timeout(DEADLINE, reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            limits.counters.evidence_hello_sent.load(Ordering::Relaxed),
            1
        );
        assert!(!limits.hello_pending(machine));
        assert_eq!(
            context
                .runtime
                .evidence_load_barrier_waits
                .load(Ordering::Relaxed),
            0
        );
        a.network().unwrap().shutdown().await;
        b.network().unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn issue1207_stored_only_relationship_and_live_nonblocking_rechecks() {
        let dir = tempfile::tempdir().unwrap();
        let a = ready_test_agent(&dir.path().join("a")).await;
        let b = ready_test_agent(&dir.path().join("b")).await;
        let context = ready_test_context(&a);
        let peer_context = ready_test_context(&b);
        let machine = b.machine_id();
        let agent = b.agent_id();
        let roster = Arc::new(tokio::sync::RwLock::new(true));
        let live = Arc::clone(&roster);
        let runtime_policy = Arc::new(crate::peer_evidence::RuntimePolicy::new(
            a.agent_id(),
            a.owner_trust.clone(),
            Arc::clone(&a.revocation_set),
        ));
        runtime_policy.set_groups(Arc::new(move |peer| {
            live.try_read().ok().map(|r| *r && peer == agent)
        }));
        assert!(context.runtime.start(
            dir.path().join("evidence"),
            Default::default(),
            runtime_policy,
            Arc::clone(&context.capture)
        ));
        assert!(context.runtime.wait(0).await);
        for c in [&context, &peer_context] {
            c.capabilities
                .send_replace(crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]));
        }
        context
            .ingest(
                machine,
                peer_context.own(None, false).unwrap().into_record(),
            )
            .unwrap();
        assert!(context.discovery.read().await.is_empty());
        let store = context.runtime.store().unwrap();
        assert!(store.try_agents_on_machine(machine, 0).unwrap().is_empty());
        assert_eq!(
            store.try_agents_on_machine(machine, 1).unwrap(),
            vec![agent]
        );
        let policy = ReadyPolicy {
            contacts: Arc::clone(&a.contact_store),
            placements: Arc::clone(&a.move_state),
        };
        assert_eq!(
            policy.eligible(&context, machine),
            Some(true),
            "stored-only relationship survives absent discovery"
        );
        let guard = roster.write().await;
        assert_eq!(policy.eligible(&context, machine), None);
        assert!(context.runtime.wire_limits.hello_pending(machine));
        drop(guard);
        let contacts = a.contact_store.write().await;
        assert_eq!(policy.eligible(&context, machine), None);
        drop(contacts);
        let placements = a.move_state.write().await;
        assert_eq!(policy.eligible(&context, machine), None);
        drop(placements);
        assert_eq!(policy.eligible(&context, machine), Some(true));
        a.contact_store
            .write()
            .await
            .set_identity_type(&agent, crate::contacts::IdentityType::Pinned);
        assert_eq!(
            policy.eligible(&context, machine),
            Some(false),
            "stored evidence cannot bypass current pinning"
        );
        a.contact_store
            .write()
            .await
            .set_identity_type(&agent, crate::contacts::IdentityType::Anonymous);
        a.contact_store
            .write()
            .await
            .set_trust(&agent, crate::contacts::TrustLevel::Blocked);
        assert_eq!(
            policy.eligible(&context, machine),
            Some(false),
            "stored evidence cannot bypass current Blocked"
        );
        a.contact_store
            .write()
            .await
            .set_trust(&agent, crate::contacts::TrustLevel::Unknown);
        *roster.write().await = false;
        assert_eq!(
            policy.eligible(&context, machine),
            Some(false),
            "stored relationship flags cannot replace the live roster"
        );
        assert!(context.runtime.wire_limits.hello_pending(machine));
        a.network().unwrap().shutdown().await;
        b.network().unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn issue1207_disconnect_cancels_waiting_hello_and_shutdown_drains_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let a = ready_test_agent(&dir.path().join("a")).await;
        let b = ready_test_agent(&dir.path().join("b")).await;
        let context = ready_test_context(&a);
        let policy = ready_test_policy(&a, &b, &dir.path().join("evidence")).await;
        let machine = b.machine_id();
        let peer = ant_quic::PeerId(machine.0);
        context
            .network
            .connect_addr(b.network().unwrap().bound_addr().await.unwrap())
            .await
            .unwrap();
        let generation = context
            .network
            .try_connection_generation(&peer)
            .unwrap()
            .unwrap();
        let mut connections = ReadyConnections::new(1);
        let mut jobs = WireJobs::default();
        connections.insert(machine);
        connections.generation(machine, generation, &jobs, &context.runtime.wire_limits);
        // This eligible job sends a real Hello, then waits for the peer's reply.
        // Its capability is already published, before spawning or joining.
        assert_eq!(policy.eligible(&context, machine), Some(true));
        assert!(jobs.spawn(
            machine,
            true,
            Arc::clone(&context).connect(machine, Some(generation), Some(policy))
        ));
        let (_send, mut recv) = tokio::time::timeout(DEADLINE, async {
            let (_, send, mut recv) = b.network().unwrap().accept_bi().await.unwrap();
            assert_eq!(
                recv.read_u8().await.unwrap(),
                StreamProtocol::EvidenceV1.as_u8()
            );
            let (kind, _) = read_message(&mut recv, &Arc::new(Limits::default()))
                .await
                .unwrap();
            assert_eq!(kind, HELLO);
            (send, recv)
        })
        .await
        .unwrap();
        // Cancellation must win even without the transport reset completing.
        // Removing the abort makes this assertion fail (normal completion or
        // the job's five-second deadline is not accepted as cancellation).
        connections.remove(machine, &jobs, &context.runtime.wire_limits);
        let result = tokio::time::timeout(Duration::from_secs(1), jobs.join())
            .await
            .unwrap()
            .unwrap();
        assert!(result.unwrap_err().is_cancelled());
        assert!(!jobs.outgoing(machine));
        assert!(context.runtime.wire_limits.state.lock().unwrap().machines[&machine].attempted);
        context.network.disconnect(&peer).await.unwrap();
        // Keep the reply stream alive until after the cancellation assertion.
        let _ = &mut recv;
        assert!(jobs.spawn(machine, true, std::future::pending()));
        assert!(jobs.spawn(machine, false, std::future::pending()));
        tokio::time::timeout(Duration::from_secs(1), jobs.shutdown())
            .await
            .unwrap();
        assert!(jobs.jobs.is_empty());
        a.network().unwrap().shutdown().await;
        b.network().unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn issue1207_old_generation_cannot_emit_hello_or_certificate_on_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let a = ready_test_agent(&dir.path().join("a")).await;
        let b = ready_test_agent(&dir.path().join("b")).await;
        let context = ready_test_context(&a);
        let policy = ready_test_policy(&a, &b, &dir.path().join("evidence")).await;
        let machine = b.machine_id();
        let peer = ant_quic::PeerId(machine.0);
        let address = b.network().unwrap().bound_addr().await.unwrap();
        context.network.connect_addr(address).await.unwrap();
        let old = context
            .network
            .try_connection_generation(&peer)
            .unwrap()
            .unwrap();
        assert!(context.same_connection(machine, old));
        context.network.disconnect(&peer).await.unwrap();
        tokio::time::timeout(DEADLINE, async {
            loop {
                if !b
                    .network()
                    .unwrap()
                    .peer_link_conn(&ant_quic::PeerId(a.machine_id().0))
                    .await
                    .is_ok_and(|c| c.inner().close_reason().is_none())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        context.network.connect_addr(address).await.unwrap();
        let replacement = context
            .network
            .try_connection_generation(&peer)
            .unwrap()
            .unwrap();
        assert_ne!(old, replacement);
        assert!(!context.same_connection(machine, old));
        assert!(context.same_connection(machine, replacement));
        context
            .capabilities
            .send_replace(crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]));
        for kind in [HELLO, CERTIFICATE] {
            let hello = context.own(None, false).unwrap();
            assert!(context
                .exchange(machine, kind, hello, Some(old), Some(&policy))
                .await
                .is_err());
        }
        assert!(
            context.runtime.wire_limits.hello_pending(machine),
            "stale generation consumes no replacement attempt"
        );
        assert_eq!(
            context
                .runtime
                .wire_limits
                .counters
                .evidence_hello_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        // Positive control: the same fence permits a real Hello on the live
        // generation. The raw remote verifies the prefix/kind and sends ACK.
        let remote = Arc::clone(b.network.as_ref().unwrap());
        let reader = tokio::spawn(async move {
            let (_, mut send, mut recv) = remote.accept_bi().await.unwrap();
            assert_eq!(
                recv.read_u8().await.unwrap(),
                StreamProtocol::EvidenceV1.as_u8()
            );
            let limits = Arc::new(Limits::default());
            let (kind, body) = read_message(&mut recv, &limits).await.unwrap();
            assert_eq!(kind, HELLO);
            assert!(decode::hello(&body).is_ok());
            write_message(
                &mut send,
                &limits,
                MachineId([7; 32]),
                ACK,
                &codec().serialize(&Option::<[u8; 32]>::None).unwrap(),
            )
            .await
            .unwrap();
        });
        let hello = context.own(None, false).unwrap();
        let (_, kind, _) = context
            .exchange(machine, HELLO, hello, Some(replacement), Some(&policy))
            .await
            .unwrap();
        assert_eq!(kind, ACK);
        reader.await.unwrap();
        assert!(!context.runtime.wire_limits.hello_pending(machine));
        a.network().unwrap().shutdown().await;
        b.network().unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn issue1207_superseded_but_open_connection_cannot_emit() {
        let dir = tempfile::tempdir().unwrap();
        let a = ready_test_agent(&dir.path().join("a")).await;
        let b = ready_test_agent(&dir.path().join("b")).await;
        // Same machine at a second address: dialing from the same initiator
        // replaces the winner but leaves the old connection open to drain.
        std::fs::create_dir_all(dir.path().join("b2")).unwrap();
        std::fs::copy(
            dir.path().join("b/machine.key"),
            dir.path().join("b2/machine.key"),
        )
        .unwrap();
        let b2 = ready_test_agent(&dir.path().join("b2")).await;
        assert_eq!(b.machine_id(), b2.machine_id());
        let context = ready_test_context(&a);
        let policy = ready_test_policy(&a, &b, &dir.path().join("evidence")).await;
        let machine = b.machine_id();
        let peer = ant_quic::PeerId(machine.0);
        context
            .network
            .connect_addr(b.network().unwrap().bound_addr().await.unwrap())
            .await
            .unwrap();
        let old = context
            .network
            .try_connection_generation(&peer)
            .unwrap()
            .unwrap();
        let retained = context.network.peer_link_conn(&peer).await.unwrap();
        context
            .network
            .connect_addr(b2.network().unwrap().bound_addr().await.unwrap())
            .await
            .unwrap();
        let current = context
            .network
            .try_connection_generation(&peer)
            .unwrap()
            .unwrap();
        assert_ne!(old, current, "must actually supersede the old generation");
        assert!(
            retained.inner().close_reason().is_none(),
            "old connection must still be OPEN"
        );
        assert!(!context.same_connection(machine, old));
        assert!(context.same_connection(machine, current));
        for kind in [HELLO, CERTIFICATE] {
            let hello = context.own_ready(None, false).unwrap();
            let error = context
                .exchange(machine, kind, hello, Some(old), Some(&policy))
                .await
                .err()
                .expect("stale generation must refuse");
            assert_eq!(error.to_string(), "Hello connection replaced");
            assert!(retained.inner().close_reason().is_none());
        }
        assert!(context.runtime.wire_limits.hello_pending(machine));
        assert_eq!(
            context
                .runtime
                .wire_limits
                .counters
                .evidence_hello_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        a.network().unwrap().shutdown().await;
        b.network().unwrap().shutdown().await;
        b2.network().unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn s3_hello_mints_only_own_evidence_and_sends_cert_only_on_miss() {
        let dir = tempfile::tempdir().unwrap();
        // No network config: identity-only, no sockets or real-network tasks.
        let agent = crate::Agent::builder()
            .with_identity_dir(dir.path())
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_user_key_path(dir.path().join("user.key"))
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .build()
            .await
            .unwrap();
        let template = agent.build_announcement(false, false).unwrap();
        let owner = crate::identity::UserKeypair::generate().unwrap();
        let cert = crate::identity::AgentCertificate::issue(&owner, agent.identity.agent_keypair())
            .unwrap();
        let pair = crate::announce_blob::shared_cert_pair(Some(owner.user_id()), Some(cert));
        let caps = crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
        let first = mint_hello(
            &agent.identity,
            template.clone(),
            &pair,
            caps.clone(),
            None,
            false,
        )
        .unwrap();
        assert!(first.certificate.is_none());
        let encoded = codec().serialize(&first).unwrap();
        let decoded = decode::hello(&encoded).unwrap();
        assert_eq!(decoded.announcement, first.announcement);
        assert_eq!(decoded.advert, first.advert);
        let mut forged_length = first.announcement.clone();
        // Magic + two fixed ids precede the first nested Vec length. A tiny
        // frame claiming a huge key must fail without reserving that Vec.
        forged_length[68..76].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode::parts(&forged_length, &first.advert, None).is_err());
        let view = first
            .into_record()
            .verify(dm_capability::now_unix_ms(), W_MS)
            .unwrap();
        assert_eq!(view.announcement.agent_id, agent.agent_id());
        assert_eq!(view.announcement.machine_id, agent.machine_id());
        assert_eq!(view.advert.agent_id, agent.agent_id().0);
        let next = mint_hello(
            &agent.identity,
            template.clone(),
            &pair,
            caps.clone(),
            None,
            true,
        )
        .unwrap();
        assert!(next.certificate.is_some());
        let encoded = codec().serialize(&next).unwrap();
        let record = decode::hello(&encoded).unwrap().into_record();
        assert!(ingest_hello(
            None,
            &Default::default(),
            &Limits::default(),
            agent.machine_id(),
            record,
            dm_capability::now_unix_ms()
        )
        .unwrap()
        .certificate
        .is_some());
        assert!(mint_hello(
            &agent.identity,
            template.clone(),
            &pair,
            caps.clone(),
            Some(view.announcement.cert_digest),
            true
        )
        .unwrap()
        .certificate
        .is_none());
        let mut other = template;
        other.agent_id = AgentId([7; 32]);
        assert!(mint_hello(&agent.identity, other, &pair, caps, None, false).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode::hello(&trailing).is_err());
        agent.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn s3_hostile_requester_shares_all_connection_budgets() {
        let limits = Arc::new(Limits::default());
        let m = MachineId([1; 32]);
        let first_connection = limits.admit(m, false).unwrap();
        let second_connection = limits.admit(m, false).unwrap();
        assert!(limits.admit(m, false).is_none());
        drop(first_connection);
        let third_connection = limits.admit(m, false).unwrap();
        assert!(limits.request(m, false));
        assert!(!limits.request(m, false));
        limits.disconnect(m); // reconnect cannot reset the rate or byte windows
        assert!(!limits.request(m, false));
        assert!(limits.charge(m, 64 * 1024));
        assert!(!limits.charge(m, 1));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limits.charge(m, 64 * 1024));
        assert!(!limits.request(m, false));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limits.request(m, false));
        drop((second_connection, third_connection));
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
    }

    #[tokio::test(start_paused = true)]
    async fn s3_global_bytes_verifies_and_allocation_bounds() {
        let limits = Arc::new(Limits::default());
        let mut leases = Vec::new();
        for id in 0..(TOTAL_ALLOCATION_CAP / ALLOCATION_RESERVATION) {
            leases.push(limits.admit(MachineId([id as u8; 32]), true).unwrap());
        }
        assert!(limits.admit(MachineId([99; 32]), true).is_none());
        drop(leases);
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
        for id in 0..4 {
            assert!(limits.charge(MachineId([id; 32]), 64 * 1024));
        }
        assert!(!limits.charge(MachineId([5; 32]), 1));
        for _ in 0..32 {
            assert!(limits.verify());
        }
        assert!(!limits.verify());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limits.verify());
        assert!(limits.charge(MachineId([5; 32]), 64 * 1024));
    }

    #[tokio::test(start_paused = true)]
    async fn s3_strangers_cannot_exhaust_relationship_reservations() {
        let limits = Arc::new(Limits::default());
        let mut strangers = Vec::new();
        // Four identities could previously consume all eight reservations.
        for id in 0..2 {
            for _ in 0..2 {
                strangers.push(limits.admit(MachineId([id; 32]), false).unwrap());
            }
        }
        assert!(limits.admit(MachineId([2; 32]), false).is_none());
        assert!(limits.admit(MachineId([3; 32]), false).is_none());
        let mut related = Vec::new();
        for id in 4..6 {
            for _ in 0..2 {
                related.push(limits.admit(MachineId([id; 32]), true).unwrap());
            }
        }
        assert_eq!(limits.allocations.available_permits(), 0);
        assert!(limits.admit(MachineId([6; 32]), true).is_none());
        drop(related);
        // Releasing protected slots does not let strangers borrow them.
        assert!(limits.admit(MachineId([2; 32]), false).is_none());
        drop(strangers.pop());
        assert!(limits.admit(MachineId([2; 32]), false).is_some());
        drop(strangers);
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
        assert_eq!(
            limits.stranger_allocations.available_permits(),
            TOTAL_ALLOCATION_CAP / 2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn s3_not_found_and_resets_are_charged() {
        let limits = Limits::default();
        let m = MachineId([1; 32]);
        let (mut tx, mut rx) = tokio::io::duplex(32);
        assert!(limits.request(m, false));
        write_message(&mut tx, &limits, m, NOT_FOUND, &[])
            .await
            .unwrap();
        assert_eq!(
            read_message(&mut rx, &limits).await.unwrap(),
            (NOT_FOUND, vec![])
        );
        assert!(limits.charge(m, RESET_CHARGE));
        assert_eq!(
            limits.state.lock().unwrap().machines[&m].bytes.total,
            5 + RESET_CHARGE
        );
        assert_eq!(limits.state.lock().unwrap().bytes.total, 5 + RESET_CHARGE);
        assert!(!limits.request(m, false));
        assert!(limits.charge(m, 64 * 1024 - 5 - RESET_CHARGE));
        assert!(!limits.charge(m, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn s3_old_peer_reset_is_one_attempt_and_non_relationship_gets_no_hello() {
        let limits = Arc::new(Limits::default());
        let m = MachineId([1; 32]);
        assert!(!limits.begin_hello(m, false));
        assert!(limits.state.lock().unwrap().machines.is_empty());
        assert!(limits.begin_hello(m, true));
        let (mut local, mut old_peer) = tokio::io::duplex(32);
        local
            .write_u8(StreamProtocol::EvidenceV1.as_u8())
            .await
            .unwrap();
        let prefix = old_peer.read_u8().await.unwrap();
        // Frozen 0.45 mapping. This is an inert reset simulation, not the
        // released-binary interop gate, which must still run in Linux CI.
        assert!(!(1..=5).contains(&prefix));
        drop(old_peer);
        assert!(read_message(&mut local, &limits).await.is_err());
        for _ in 0..100 {
            assert!(!limits.begin_hello(m, true));
        }
        tokio::time::advance(HELLO_INTERVAL).await;
        assert!(!limits.begin_hello(m, true), "no retry until reconnect");
        limits.disconnect(m);
        assert!(
            !limits.begin_hello(m, true),
            "disconnect alone cannot re-arm"
        );
        assert!(limits.begin_hello_on_connection(m, true, Some(1)));
        limits.disconnect(m);
        assert!(
            !limits.begin_hello_on_connection(m, true, Some(2)),
            "reconnect churn retains cooldown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn s3_slow_body_deadline_includes_queue_delay_and_releases_budget() {
        let limits = Arc::new(Limits::default());
        let lease = limits.admit(MachineId([1; 32]), false).unwrap();
        tokio::time::advance(Duration::from_secs(4)).await; // queued acceptor
        let (_tx, mut rx) = tokio::io::duplex(32);
        let start = Instant::now();
        assert!(tokio::time::timeout_at(lease.deadline, {
            let inner = Limits::default();
            let mut rx = &mut rx;
            async move {
                let _ = read_message(&mut rx, &inner).await;
            }
        })
        .await
        .is_err());
        assert_eq!(Instant::now().duration_since(start), Duration::from_secs(1));
        drop(lease);
        assert_eq!(limits.allocations.available_permits(), TOTAL_ALLOCATION_CAP);
    }

    #[tokio::test(start_paused = true)]
    async fn s3_malformed_or_incomplete_frames_are_bounded() {
        let mut oversized = vec![HELLO];
        oversized.extend_from_slice(&(MESSAGE_CAP as u32).to_be_bytes());
        let limits = Limits::default();
        assert!(read_message(&mut oversized.as_slice(), &limits)
            .await
            .is_err());
        let (mut tx, mut rx) = tokio::io::duplex(32);
        tx.write_all(&[HELLO, 0, 0, 0, 2, 0]).await.unwrap();
        assert!(
            tokio::time::timeout(DEADLINE, read_message(&mut rx, &limits))
                .await
                .is_err()
        );
        let malformed = vec![255; MESSAGE_CAP - 5];
        assert!(decode::hello(&malformed).is_err());
        let mut hostile_length = u64::MAX.to_le_bytes().to_vec();
        hostile_length.extend_from_slice(&[0; 32]);
        assert!(decode::hello(&hostile_length).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn s3_certificate_continuation_is_requested_once_and_expires() {
        let limits = Arc::new(Limits::default());
        let m = MachineId([1; 32]);
        let a = AgentId([2; 32]);
        assert!(!limits.take_certificate(m, a, [3; 32]));
        limits.need_certificate(m, a, [3; 32]);
        assert!(limits.take_certificate(m, a, [3; 32]));
        assert!(!limits.take_certificate(m, a, [3; 32]));
        limits.need_certificate(m, a, [3; 32]);
        assert!(!limits.take_certificate(m, a, [4; 32]));
        limits.need_certificate(m, a, [3; 32]);
        tokio::time::advance(DEADLINE).await;
        assert!(!limits.take_certificate(m, a, [3; 32]));
    }
}
