//! ADR 0089: self-verifying relationship evidence.
//!
//! Runtime consumers consult verified views at each use. Callers supply current
//! relationship/revocation policy; views must never be copied into other caches.
//! All times are Unix milliseconds. Certificate issuance is not a heartbeat:
//! W/L apply to announcement/advert, while certificates have their own expiry.
use crate::{
    announce_v3::{self, IdentityAnnouncementV3},
    dm_capability::CapabilityAdvert,
    identity::{AgentCertificate, AgentId, MachineId, UserId},
};
mod runtime;
pub use runtime::{EvidenceRuntime, RuntimePolicy};

use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Ingest freshness window (15 minutes).
pub const W_MS: u64 = 15 * 60 * 1000;
/// Maximum permitted future skew.
pub const SKEW_MS: u64 = 5 * 60 * 1000;
/// Milliseconds in a day.
pub const DAY_MS: u64 = 86_400_000;
/// Announcement byte ceiling.
pub const ANNOUNCEMENT_CAP: usize = 8 * 1024;
/// Advert byte ceiling, including registry trailer.
pub const ADVERT_CAP: usize = 12 * 1024;
/// Certificate byte ceiling.
pub const CERTIFICATE_CAP: usize = 10 * 1024;
/// Total signed-part ceiling.
pub const RECORD_BYTES_CAP: usize = 30 * 1024;
/// Total file ceiling, including magic and framing.
pub const FILE_CAP: usize = 16 * 1024 * 1024;
/// Maximum records.
pub const RECORD_CAP: usize = 512;
/// Maximum move watermarks.
pub const WATERMARK_CAP: usize = 4096;
/// Frozen V1 body discriminator.
pub const MAGIC: &[u8; 8] = b"X0PEV1\0\0";
/// Enrolled-device relationship flag (highest retention priority).
pub const ENROLLED: u8 = 1;
/// Grant-counterparty relationship flag.
pub const GRANT: u8 = 2;
/// Active shared-group relationship flag.
pub const GROUP: u8 = 4;

/// TOML `[evidence]` settings. Accepted ADR overrides the plan's stale 30 days.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EvidenceConfig {
    /// Stored authority lifetime, inclusive range 1..=7.
    pub max_age_days: u64,
}
impl Default for EvidenceConfig {
    fn default() -> Self {
        Self { max_age_days: 7 }
    }
}
impl EvidenceConfig {
    /// Reject settings outside the Accepted lifetime bound.
    pub fn validate(&self) -> Result<()> {
        if !(1..=7).contains(&self.max_age_days) {
            return Err(EvidenceError::Invalid(
                "[evidence] max_age_days must be 1..=7",
            ));
        }
        Ok(())
    }
}
/// Evidence rejection or persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// Invalid, stale or unauthorized evidence.
    #[error("invalid evidence: {0}")]
    Invalid(&'static str),
    /// Disk operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Positional format error.
    #[error(transparent)]
    Codec(#[from] bincode::Error),
}
type Result<T> = std::result::Result<T, EvidenceError>;

/// Frozen V1 positional shape. Never add/reorder fields: introduce V2 instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecordV1 {
    /// Verbatim X0A3/X0A4 wire body, excluding gossip envelope.
    pub announcement: Vec<u8>,
    /// Verbatim advert body including optional X0CR trailer.
    pub advert: Vec<u8>,
    /// Optional certificate bytes (AgentCertificate storage encoding).
    pub certificate: Option<Vec<u8>>,
    /// Relationship flags; bookkeeping, never an authority source.
    pub relation: u8,
    /// Local bookkeeping, never used for signed freshness.
    pub stored_at_ms: u64,
}
/// Frozen move watermark. Same-machine refreshes never advance it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoveWatermarkV1 {
    /// Signed advert timestamp.
    pub t: u64,
    /// Destination machine.
    pub machine: MachineId,
}
/// Frozen V1 snapshot; map keys are portable agent identities.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFileV1 {
    /// Signed records.
    #[serde(serialize_with = "serialize_sorted_agents")]
    pub records: HashMap<AgentId, EvidenceRecordV1>,
    /// Move protection survives record eviction.
    #[serde(serialize_with = "serialize_sorted_agents")]
    pub watermarks: HashMap<AgentId, MoveWatermarkV1>,
}
// Array keys have the same frozen wire encoding as the AgentId newtype.
fn serialize_sorted_agents<S: serde::Serializer, V: Serialize>(
    map: &HashMap<AgentId, V>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    map.iter()
        .map(|(id, value)| (id.as_bytes(), value))
        .collect::<std::collections::BTreeMap<_, _>>()
        .serialize(serializer)
}

#[cfg(test)]
thread_local! {
    // Thread-local so parallel inert tests cannot perturb a counting assertion.
    static VERIFY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn signature_check<T>(verify: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    VERIFY_CALLS.with(|count| count.set(count.get() + 1));
    verify()
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(FILE_CAP as u64)
        .reject_trailing_bytes()
}
impl EvidenceFileV1 {
    fn bounds(&self) -> Result<()> {
        if self.records.len() > RECORD_CAP || self.watermarks.len() > WATERMARK_CAP {
            return Err(EvidenceError::Invalid("entry cap"));
        }
        for r in self.records.values() {
            r.bounds()?;
        }
        Ok(())
    }
    /// Encode with explicit version, hard bounds and the frozen layout.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bounds()?;
        let size = options().serialized_size(self)?;
        if size > (FILE_CAP - MAGIC.len()) as u64 {
            return Err(EvidenceError::Invalid("file cap"));
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend(options().serialize(self)?);
        Ok(bytes)
    }
    /// Decode exactly; unknown versions and trailing bytes fail closed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FILE_CAP {
            return Err(EvidenceError::Invalid("file cap"));
        }
        let body = bytes
            .strip_prefix(MAGIC)
            .ok_or(EvidenceError::Invalid("unknown magic"))?;
        let file: Self = options().deserialize(body)?;
        file.bounds()?;
        Ok(file)
    }
}
/// Verified material for one point-of-use decision. Registry bits are cleared.
#[derive(Debug, Clone)]
pub struct EvidenceView {
    /// Verified machine-signed identity.
    pub announcement: IdentityAnnouncementV3,
    /// Verified agent-signed key material; persisted registry bits stay unknown.
    pub advert: CapabilityAdvert,
    /// Verified owner certificate, if supplied.
    pub certificate: Option<AgentCertificate>,
}
fn fresh(t: u64, now: u64, age: u64) -> bool {
    t <= now.saturating_add(SKEW_MS) && now.saturating_sub(t) <= age
}
fn announcement_ms(a: &IdentityAnnouncementV3) -> Result<u64> {
    a.announced_at
        .checked_mul(1000)
        .ok_or(EvidenceError::Invalid("timestamp overflow"))
}
fn charge_verify(charge: &mut impl FnMut() -> bool) -> Result<()> {
    if charge() {
        Ok(())
    } else {
        Err(EvidenceError::Invalid("evidence verify budget"))
    }
}
fn verify_advert(
    bytes: &[u8],
    key: &[u8],
    now: u64,
    age: u64,
    charge: &mut impl FnMut() -> bool,
) -> Result<CapabilityAdvert> {
    if bytes.len() > ADVERT_CAP {
        return Err(EvidenceError::Invalid("advert cap"));
    }
    let (mut advert, trailer) = CapabilityAdvert::decode_evidence(bytes)
        .map_err(|_| EvidenceError::Invalid("advert encoding"))?;
    if advert.protocol_version != crate::dm_capability_service::ADVERT_PROTOCOL_VERSION
        || !fresh(advert.created_at_unix_ms, now, age)
    {
        return Err(EvidenceError::Invalid("advert signature or freshness"));
    }
    charge_verify(charge)?;
    if !signature_check(|| crate::dm_capability_service::verify_advert_signature(&advert, key)) {
        return Err(EvidenceError::Invalid("advert signature or freshness"));
    }
    if let Some(trailer) = trailer {
        let bytes = trailer
            .signed_bytes(&advert)
            .map_err(|_| EvidenceError::Invalid("trailer encoding"))?;
        let key = ant_quic::MlDsaPublicKey::from_bytes(key)
            .map_err(|_| EvidenceError::Invalid("agent key"))?;
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&trailer.signature)
                .map_err(|_| EvidenceError::Invalid("trailer signature"))?;
        charge_verify(charge)?;
        signature_check(|| {
            ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&key, &bytes, &signature)
        })
        .map_err(|_| EvidenceError::Invalid("trailer signature"))?;
    }
    advert.capabilities.application_registry = Default::default();
    Ok(advert)
}
impl EvidenceRecordV1 {
    fn bounds(&self) -> Result<()> {
        if self.announcement.len() > ANNOUNCEMENT_CAP
            || self.advert.len() > ADVERT_CAP
            || self
                .certificate
                .as_ref()
                .is_some_and(|c| c.len() > CERTIFICATE_CAP)
        {
            return Err(EvidenceError::Invalid("component byte cap"));
        }
        Ok(())
    }
    /// Verify signed bytes once at load (L) or network ingest (W).
    pub fn verify(&self, now: u64, max_age_ms: u64) -> Result<EvidenceView> {
        self.verify_budgeted(now, max_age_ms, &mut || true)
    }
    /// Charge immediately before each actual signature verification, including
    /// optional advert trailers and certificates, and failed signatures.
    pub(crate) fn verify_budgeted(
        &self,
        now: u64,
        max_age_ms: u64,
        charge: &mut impl FnMut() -> bool,
    ) -> Result<EvidenceView> {
        self.bounds()?;
        let announcement = announce_v3::deserialize_v3(&self.announcement)?;
        charge_verify(charge)?;
        signature_check(|| announcement.verify())
            .map_err(|_| EvidenceError::Invalid("announcement signature"))?;
        if !fresh(announcement_ms(&announcement)?, now, max_age_ms) {
            return Err(EvidenceError::Invalid("announcement freshness"));
        }
        let advert = verify_advert(
            &self.advert,
            &announcement.agent_public_key,
            now,
            max_age_ms,
            charge,
        )?;
        if advert.agent_id != *announcement.agent_id.as_bytes()
            || advert.machine_id != *announcement.machine_id.as_bytes()
        {
            return Err(EvidenceError::Invalid("agent/machine mismatch"));
        }
        let certificate = self
            .certificate
            .as_ref()
            .map(|bytes| {
                let cert = AgentCertificate::from_storage_bytes(bytes)
                    .map_err(|_| EvidenceError::Invalid("certificate encoding"))?;
                // The certificate codec accepts historical layouts. Require canonical
                // exact consumption without ever replacing the original bytes.
                if cert
                    .to_storage_bytes()
                    .map_err(|_| EvidenceError::Invalid("certificate encoding"))?
                    != *bytes
                {
                    return Err(EvidenceError::Invalid("certificate trailing bytes"));
                }
                charge_verify(charge)?;
                signature_check(|| cert.verify())
                    .map_err(|_| EvidenceError::Invalid("certificate signature"))?;
                if cert.agent_id().ok() != Some(announcement.agent_id)
                    || cert.is_expired(now / 1000)
                    || cert.issued_at() > now.saturating_add(SKEW_MS) / 1000
                {
                    return Err(EvidenceError::Invalid("certificate binding or lifetime"));
                }
                Ok(cert)
            })
            .transpose()?;
        Ok(EvidenceView {
            announcement,
            advert,
            certificate,
        })
    }
}
/// Current policy, queried at every use. Implementations must read current
/// state, not the stored relation flags. Point-of-use checks run without the
/// store lock. Mutations may take policy locks while holding the store lock.
/// Methods must not re-enter the evidence store.
pub trait EvidencePolicy: Send + Sync {
    /// Changes when a policy read was unavailable. Maintenance must not turn
    /// transient lock contention into a durable relationship removal.
    fn unavailable_epoch(&self) -> u64 {
        0
    }

    /// Current relationship flags; zero means stranger.
    fn relation(
        &self,
        agent: AgentId,
        machine: MachineId,
        cert: Option<&AgentCertificate>,
        now_ms: u64,
    ) -> u8;
    /// Checks agent, machine and binding revocations. The certificate user is
    /// available to policies with a user revocation subject; RuntimePolicy has none.
    fn revoked(&self, agent: AgentId, machine: MachineId, user: Option<UserId>) -> bool;
    /// [`Self::relation`] for synchronous admission seams (x0x #1150 r7c):
    /// `None` while a policy read would block. Never waits on a lock.
    fn try_relation(
        &self,
        agent: AgentId,
        machine: MachineId,
        cert: Option<&AgentCertificate>,
        now_ms: u64,
    ) -> Option<u8> {
        Some(self.relation(agent, machine, cert, now_ms))
    }
    /// [`Self::revoked`] for synchronous admission seams (x0x #1150 r7c):
    /// `None` while the revocation read would block. Never waits on a lock.
    fn try_revoked(
        &self,
        agent: AgentId,
        machine: MachineId,
        user: Option<UserId>,
    ) -> Option<bool> {
        Some(self.revoked(agent, machine, user))
    }
    /// Used to protect watermarks even when their record is absent.
    fn contains_agent(&self, agent: AgentId, now_ms: u64) -> bool;
}
/// Snapshot inputs from the existing persisted relationship stores. Enrollments
/// must be the current devices.json entries (removed entries are not supplied).
pub struct RelationshipInputs<'a> {
    /// Local agent.
    pub local_agent: AgentId,
    /// Local owner, if enrolled.
    pub local_owner: Option<UserId>,
    /// Current owner-signed device enrollments.
    pub enrollments: &'a [crate::owner_sync::OwnerEnrollment],
    /// Issued and received grants from share-grants.bin.
    pub grants: &'a [crate::share_grant::ShareGrant],
    /// Current named group state.
    pub groups: &'a [crate::groups::GroupInfo],
    /// Revocations used to exclude revoked grants and devices.
    pub revocations: &'a crate::revocation::RevocationSet,
}
/// Compute the relationship set using verified records to resolve machines and
/// user grantees. Active group IDs and direct grantees also work without records.
pub fn relationship_set(
    inputs: &RelationshipInputs<'_>,
    records: &[EvidenceView],
    now: u64,
) -> HashMap<AgentId, u8> {
    use crate::share_grant::Grantee;
    let mut set = HashMap::new();
    let mut add = |a, flag| {
        if a != inputs.local_agent {
            *set.entry(a).or_insert(0) |= flag;
        }
    };
    for group in inputs.groups {
        if group.withdrawn
            || !group
                .members_v2
                .get(&hex::encode(inputs.local_agent.as_bytes()))
                .is_some_and(|m| m.is_active())
        {
            continue;
        }
        for member in group.members_v2.values().filter(|m| m.is_active()) {
            if let Ok(bytes) = hex::decode(&member.agent_id) {
                if let Ok(id) = <[u8; 32]>::try_from(bytes) {
                    add(AgentId(id), GROUP);
                }
            }
        }
    }
    for record in records {
        let a = record.announcement.agent_id;
        let m = record.announcement.machine_id;
        if inputs.local_owner.is_some_and(|owner| {
            inputs.enrollments.iter().any(|e| {
                e.machine_id == *m.as_bytes()
                    && e.is_current_at(now)
                    && e.verify_owner(&owner).is_ok()
            })
        }) && !inputs.revocations.is_machine_revoked(&m)
            && !inputs.revocations.is_agent_revoked(&a)
            && !inputs.revocations.is_binding_revoked(&a, &m)
        {
            add(a, ENROLLED);
        }
    }
    for grant in inputs.grants {
        if !grant.is_active_at(now / 1000)
            || grant.verify().is_err()
            || inputs
                .revocations
                .is_share_grant_revoked(&grant.grant_id, &grant.owner)
        {
            continue;
        }
        if inputs.local_owner == Some(grant.owner) && grant.agents.contains(&inputs.local_agent) {
            match grant.grantee {
                Grantee::Agent(a) => add(a, GRANT),
                Grantee::User(u) => {
                    for r in records {
                        if r.certificate.as_ref().is_some_and(|c| {
                            !c.is_expired(now / 1000) && c.user_id().ok() == Some(u)
                        }) {
                            add(r.announcement.agent_id, GRANT);
                        }
                    }
                }
            }
        }
        let received = match grant.grantee {
            Grantee::Agent(a) => a == inputs.local_agent,
            Grantee::User(u) => Some(u) == inputs.local_owner,
        };
        if received {
            for a in &grant.agents {
                add(*a, GRANT);
            }
        }
    }
    set
}
/// Network source controls material same-machine refresh policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestSource {
    /// Routine gossip or Lookup.
    Gossip,
    /// Ingest-fresh peer Hello always replaces stored bytes.
    Hello,
}
/// Counters owned by the store; diagnostics wiring is a later slice.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EvidenceCounters {
    /// Records successfully re-verified at startup.
    pub evidence_loaded: u64,
    /// Point-of-use authority hits.
    pub evidence_usable_hits: u64,
    /// Point-of-use refusals, grouped by reason.
    pub evidence_usable_misses: HashMap<String, u64>,
    /// Records refused at startup, by reason.
    pub evidence_rejected_on_load: HashMap<String, u64>,
    /// Failed synchronous move writes.
    pub evidence_move_write_failed: u64,
    /// Incoming moves refused at a protected watermark cap.
    pub evidence_watermark_full: u64,
    /// Successful atomic snapshots.
    pub evidence_writes: u64,
    /// Snapshot bytes written.
    pub evidence_bytes_written: u64,
}
#[derive(Clone)]
struct CachedRecord {
    source: IngestSource,
    wire: EvidenceRecordV1,
    view: Arc<EvidenceView>,
}
#[derive(Default)]
struct State {
    file: EvidenceFileV1,
    // Process-only views, populated only after verifying the corresponding wire.
    verified: HashMap<AgentId, Arc<EvidenceView>>,
    by_machine: std::collections::BTreeSet<([u8; 32], [u8; 32])>,
    live: HashMap<AgentId, CachedRecord>,
    suspended: HashSet<AgentId>,
    pending_moves: HashMap<AgentId, MoveWatermarkV1>,
    last_used: HashMap<AgentId, u64>,
    absent_since: HashMap<AgentId, u64>,
    dirty: bool,
    last_write: Option<u64>,
    counters: EvidenceCounters,
}
/// Locked evidence map with coherent atomic snapshots. Explicit `flush` on
/// shutdown is required; Drop deliberately performs no hidden disk writes.
pub struct PeerEvidenceStore {
    path: PathBuf,
    memory_only: bool,
    max_age: u64,
    policy: Arc<dyn EvidencePolicy>,
    state: Mutex<State>,
    // Serializes snapshot mutations and disk writes; readers never acquire it.
    // Always acquire before state, and release state before any disk write.
    mutation: Mutex<()>,
    #[cfg(test)]
    fail_write: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    slow_write: Mutex<Option<Arc<SlowWrite>>>,
}
impl PeerEvidenceStore {
    /// Open and verify an existing snapshot. Unreadable files are preserved for
    /// the entire lifetime of this instance; missing files allow first writes.
    pub fn open(
        data_dir: &Path,
        config: EvidenceConfig,
        policy: Arc<dyn EvidencePolicy>,
        now: u64,
    ) -> Result<Self> {
        config.validate()?;
        let path = data_dir.join("peer-evidence.bin");
        let decoded = (|| -> Result<EvidenceFileV1> {
            let file = File::open(&path)?;
            let mut bytes = Vec::new();
            file.take(FILE_CAP as u64 + 1).read_to_end(&mut bytes)?;
            EvidenceFileV1::decode(&bytes)
        })();
        let (mut file, memory_only) = match decoded {
            Ok(f) => (f, false),
            Err(EvidenceError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                (EvidenceFileV1::default(), false)
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "unreadable evidence file: memory-only until manual recovery");
                (EvidenceFileV1::default(), true)
            }
        };
        let max_age = config.max_age_days * DAY_MS;
        let mut verified = HashMap::new();
        let mut counters = EvidenceCounters::default();
        file.records.retain(|a, r| {
            let view = match r.verify(now, max_age) {
                Ok(view) => view,
                Err(error) => {
                    *counters
                        .evidence_rejected_on_load
                        .entry(error.to_string())
                        .or_default() += 1;
                    return false;
                }
            };
            let epoch = policy.unavailable_epoch();
            let permitted = allowed(&*policy, &view, now);
            if view.announcement.agent_id != *a
                || disqualified(&file.watermarks, *a, &view)
                || (!permitted && policy.unavailable_epoch() == epoch)
            {
                *counters
                    .evidence_rejected_on_load
                    .entry("identity, watermark or policy".into())
                    .or_default() += 1;
                return false;
            }
            counters.evidence_loaded += 1;
            verified.insert(*a, Arc::new(view));
            true
        });
        Ok(Self {
            path,
            memory_only,
            max_age,
            policy,
            state: Mutex::new(State {
                file,
                by_machine: verified
                    .iter()
                    .map(|(a, v)| (v.announcement.machine_id.0, a.0))
                    .collect(),
                verified,
                counters,
                ..State::default()
            }),
            mutation: Mutex::new(()),
            #[cfg(test)]
            slow_write: Mutex::new(None),
            #[cfg(test)]
            fail_write: std::sync::atomic::AtomicU8::new(0),
        })
    }
    /// Whether this instance is prohibited from replacing an unreadable file.
    pub fn is_memory_only(&self) -> bool {
        self.memory_only
    }
    /// Diagnostic counters.
    pub fn counters(&self) -> Result<EvidenceCounters> {
        Ok(self.lock()?.counters.clone())
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| EvidenceError::Invalid("poisoned store lock"))
    }
    fn lock_mutation(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.mutation
            .lock()
            .map_err(|_| EvidenceError::Invalid("poisoned mutation lock"))
    }
    /// Single authority: check current policy, time, certificate expiry, exact
    /// machine and watermark. Signatures were verified at load or ingest.
    pub fn usable(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
    ) -> Option<Arc<EvidenceView>> {
        let result = self.check_usable(agent, machine, now);
        if let Ok(mut state) = self.state.lock() {
            match &result {
                Ok(_) => state.counters.evidence_usable_hits += 1,
                Err(reason) => {
                    *state
                        .counters
                        .evidence_usable_misses
                        .entry((*reason).into())
                        .or_default() += 1
                }
            }
        }
        result.ok()
    }
    fn check_usable(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
    ) -> std::result::Result<Arc<EvidenceView>, &'static str> {
        self.check_usable_with(agent, machine, now, true)
    }
    /// ADR 0115 §2: whether a usable record exists for exactly
    /// (agent, machine). The same check as [`Self::usable`], without its
    /// use counters, for security readers that only need the answer.
    pub(crate) fn confirms_pairing(&self, agent: AgentId, machine: MachineId, now: u64) -> bool {
        self.check_usable(agent, machine, now).is_ok()
    }
    /// [`Self::confirms_pairing`] for synchronous seams: `None` when the
    /// store or its policy is busy.
    pub(crate) fn try_confirms_pairing(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
    ) -> Option<bool> {
        match self.check_usable_with(agent, machine, now, false) {
            Ok(_) => Some(true),
            Err(reason) if reason == STORE_BUSY => None,
            Err(_) => Some(false),
        }
    }
    /// ADR 0115 §3: the owner certificate of `agent`'s usable
    /// record, if it carries one, without the use counters.
    pub(crate) fn usable_certificate(&self, agent: AgentId, now: u64) -> Option<AgentCertificate> {
        let machine = self
            .state
            .lock()
            .ok()?
            .verified
            .get(&agent)?
            .announcement
            .machine_id;
        self.check_usable(agent, machine, now)
            .ok()?
            .certificate
            .clone()
    }
    /// The state lock, taken blocking, or without blocking (`STORE_BUSY`
    /// on contention) for synchronous seams.
    fn state_for_check(
        &self,
        blocking: bool,
    ) -> std::result::Result<std::sync::MutexGuard<'_, State>, &'static str> {
        if blocking {
            return self.state.lock().map_err(|_| "store_lock");
        }
        match self.state.try_lock() {
            Ok(state) => Ok(state),
            Err(std::sync::TryLockError::WouldBlock) => Err(STORE_BUSY),
            Err(std::sync::TryLockError::Poisoned(_)) => Err("store_lock"),
        }
    }
    fn check_usable_with(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
        blocking: bool,
    ) -> std::result::Result<Arc<EvidenceView>, &'static str> {
        let view = {
            let state = self.state_for_check(blocking)?;
            if state.suspended.contains(&agent) {
                return Err("suspended_or_superseded");
            }
            let view = state.verified.get(&agent).ok_or("missing")?;
            if view.announcement.machine_id != machine
                || disqualified(&state.file.watermarks, agent, view)
            {
                return Err("machine_or_watermark");
            }
            Arc::clone(view)
        };
        if !current(&view, now, self.max_age) {
            return Err("age_or_certificate_expiry");
        }
        if blocking {
            if !allowed(&*self.policy, &view, now) {
                return Err("relationship_or_revocation");
            }
        } else {
            match try_allowed(&*self.policy, &view, now) {
                Some(true) => {}
                Some(false) => return Err("relationship_or_revocation"),
                None => return Err(STORE_BUSY),
            }
        }
        {
            let mut state = self.state_for_check(blocking)?;
            // A move/removal may have raced the policy calls. Never return the
            // old authority if it was suspended or replaced in the meantime.
            if state.suspended.contains(&agent)
                || !state
                    .verified
                    .get(&agent)
                    .is_some_and(|v| Arc::ptr_eq(v, &view))
                || disqualified(&state.file.watermarks, agent, &view)
            {
                return Err("suspended_or_superseded");
            }
            state.last_used.insert(agent, now);
        }
        Ok(view)
    }
    pub(crate) fn related(
        &self,
        agent: AgentId,
        machine: MachineId,
        cert: Option<&AgentCertificate>,
        now: u64,
    ) -> bool {
        self.policy.relation(agent, machine, cert, now) != 0
    }
    /// Live relationship without waiting on a policy lock.
    pub(crate) fn try_related(
        &self,
        agent: AgentId,
        machine: MachineId,
        cert: Option<&AgentCertificate>,
        now: u64,
    ) -> Option<bool> {
        self.policy
            .try_relation(agent, machine, cert, now)
            .map(|r| r != 0)
    }

    /// Indexed candidates without blocking. Callers must check usability;
    /// the index itself confers no authority.
    pub(crate) fn try_agents_on_machine(
        &self,
        machine: MachineId,
        limit: usize,
    ) -> std::result::Result<Vec<AgentId>, ()> {
        let state = self.state.try_lock().map_err(|_| ())?;
        Ok(state
            .by_machine
            .range((machine.0, [0; 32])..=(machine.0, [255; 32]))
            .take(limit)
            .map(|(_, a)| AgentId(*a))
            .collect())
    }

    /// A usable relationship on this exact machine, without blocking.
    pub(crate) fn try_has_machine(
        &self,
        machine: MachineId,
        now: u64,
        limit: usize,
    ) -> Option<bool> {
        for agent in self.try_agents_on_machine(machine, limit).ok()? {
            if self
                .try_usable_agent(agent, now)
                .ok()?
                .is_some_and(|view| view.announcement.machine_id == machine)
            {
                return Some(true);
            }
        }
        Some(false)
    }

    /// Resolve an unknown machine, then run the same point-of-use authority check.
    pub fn usable_agent(&self, agent: AgentId, now: u64) -> Option<Arc<EvidenceView>> {
        let machine = self
            .state
            .lock()
            .ok()?
            .verified
            .get(&agent)?
            .announcement
            .machine_id;
        self.usable(agent, machine, now)
    }
    /// [`Self::usable_agent`] without blocking on the store lock, for
    /// synchronous admission seams and bounded waits (x0x #1150 r7b): the
    /// same point-of-use authority check, or `Err(())` while the lock is
    /// contended. Diagnostic counters are not updated.
    pub(crate) fn try_usable_agent(
        &self,
        agent: AgentId,
        now: u64,
    ) -> std::result::Result<Option<Arc<EvidenceView>>, ()> {
        let machine = match self.state.try_lock() {
            Ok(state) => match state.verified.get(&agent) {
                Some(view) => view.announcement.machine_id,
                None => return Ok(None),
            },
            Err(std::sync::TryLockError::WouldBlock) => return Err(()),
            Err(std::sync::TryLockError::Poisoned(_)) => return Ok(None),
        };
        match self.check_usable_with(agent, machine, now, false) {
            Ok(view) => Ok(Some(view)),
            Err(STORE_BUSY) => Err(()),
            Err(_) => Ok(None),
        }
    }
    /// [`Self::usable`] without blocking on the store lock or a policy read
    /// (x0x #1207), for bounded resolution: the same point-of-use authority
    /// check, or `Err(())` while a lock is contended. Diagnostic counters
    /// are not updated.
    pub(crate) fn try_usable(
        &self,
        agent: AgentId,
        machine: MachineId,
        now: u64,
    ) -> std::result::Result<Option<Arc<EvidenceView>>, ()> {
        match self.check_usable_with(agent, machine, now, false) {
            Ok(view) => Ok(Some(view)),
            Err(STORE_BUSY) => Err(()),
            Err(_) => Ok(None),
        }
    }
    /// Indexed candidates only; never substitutes for `usable` checks.
    pub(crate) fn agents_on_machine(&self, machine: MachineId, limit: usize) -> Vec<AgentId> {
        self.state
            .lock()
            .map(|s| {
                s.by_machine
                    .range((machine.0, [0; 32])..=(machine.0, [255; 32]))
                    .take(limit)
                    .map(|(_, a)| AgentId(*a))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Whether a currently usable relationship record names this machine.
    pub(crate) fn has_machine(&self, machine: MachineId, now: u64) -> bool {
        let agents: Vec<_> = self
            .state
            .lock()
            .map(|s| s.verified.keys().copied().collect())
            .unwrap_or_default();
        agents
            .into_iter()
            .any(|agent| self.usable(agent, machine, now).is_some())
    }
    pub(crate) fn machine_certificate_digest(
        &self,
        machine: MachineId,
        now: u64,
    ) -> Option<[u8; 32]> {
        let agents: Vec<_> = self.state.lock().ok()?.verified.keys().copied().collect();
        agents.into_iter().find_map(|agent| {
            let view = self.usable(agent, machine, now)?;
            view.certificate.as_ref()?;
            Some(view.announcement.cert_digest)
        })
    }
    /// Exact stored certificate for a matching announcement digest, if usable.
    pub(crate) fn certificate_for(
        &self,
        agent: AgentId,
        machine: MachineId,
        digest: [u8; 32],
        now: u64,
    ) -> Option<Vec<u8>> {
        let view = self.usable(agent, machine, now)?;
        if view.announcement.cert_digest != digest {
            return None;
        }
        view.certificate.as_ref()?.to_storage_bytes().ok()
    }
    /// Latest ingest-fresh live wire bytes, kept separately from stored bytes.
    pub fn live(&self, agent: AgentId, now: u64) -> Option<EvidenceRecordV1> {
        let record = {
            let state = self.state.lock().ok()?;
            if state.suspended.contains(&agent) {
                return None;
            }
            state.live.get(&agent)?.clone()
        };
        if !current(&record.view, now, W_MS) || !allowed(&*self.policy, &record.view, now) {
            return None;
        }
        let state = self.state.lock().ok()?;
        if state.suspended.contains(&agent)
            || !state
                .live
                .get(&agent)
                .is_some_and(|r| Arc::ptr_eq(&r.view, &record.view))
            || disqualified(&state.file.watermarks, agent, &record.view)
        {
            return None;
        }
        Some(record.wire)
    }
    /// Ingest a complete verified pair. A move returns success only after the
    /// new snapshot and its parent directory have been synced, unless this
    /// instance is memory-only (where the move takes effect immediately).
    pub fn ingest(&self, record: EvidenceRecordV1, source: IngestSource, now: u64) -> Result<()> {
        let view = Arc::new(record.verify(now, W_MS)?);
        self.ingest_verified(record, view, source, now)
    }
    pub(crate) fn ingest_verified(
        &self,
        mut record: EvidenceRecordV1,
        view: Arc<EvidenceView>,
        source: IngestSource,
        now: u64,
    ) -> Result<()> {
        if !allowed(&*self.policy, &view, now) {
            return Err(EvidenceError::Invalid("not a current relationship"));
        }
        let a = view.announcement.agent_id;
        let m = view.announcement.machine_id;
        record.relation = self.policy.relation(a, m, view.certificate.as_ref(), now);
        record.stored_at_ms = now;
        let _mutation = self.lock_mutation()?;
        let mut state = self.lock()?;
        // A gossip pairing can have been queued before a Hello completed.
        // The same wire pair without its fetched certificate must not undo
        // that Hello (or cause another material write).
        if source == IngestSource::Gossip
            && state.live.get(&a).is_some_and(|old| {
                old.source == IngestSource::Hello
                    && old.wire.announcement == record.announcement
                    && old.wire.advert == record.advert
                    && (record.certificate.is_none() || old.wire.certificate == record.certificate)
            })
        {
            return Ok(());
        }
        if disqualified(&state.file.watermarks, a, &view)
            || state
                .pending_moves
                .get(&a)
                .is_some_and(|w| w.machine != m && w.t >= view.advert.created_at_unix_ms)
        {
            return Err(EvidenceError::Invalid("move watermark"));
        }
        let previous = state
            .live
            .get(&a)
            .map(|r| &r.view)
            .or_else(|| state.verified.get(&a));
        if let Some(old) = &previous {
            if view.advert.created_at_unix_ms < old.advert.created_at_unix_ms
                || announcement_ms(&view.announcement)? < announcement_ms(&old.announcement)?
                || (m != old.announcement.machine_id
                    && view.advert.created_at_unix_ms == old.advert.created_at_unix_ms)
            {
                return Err(EvidenceError::Invalid("non-monotonic evidence"));
            }
        }
        let stored = state.verified.get(&a);
        let moving = stored
            .as_ref()
            .is_some_and(|v| v.announcement.machine_id != m)
            || state.suspended.contains(&a);
        let material = moving
            || source == IngestSource::Hello
            || stored.is_none()
            || state
                .file
                .records
                .get(&a)
                .is_some_and(|old| old.certificate != record.certificate)
            || stored.as_ref().is_some_and(|v| {
                now.saturating_sub(v.announcement.announced_at.saturating_mul(1000))
                    > self.max_age / 2
                    || now.saturating_sub(v.advert.created_at_unix_ms) > self.max_age / 2
            });
        if material {
            let mut next = state.file.clone();
            if moving {
                state.suspended.insert(a);
                state.pending_moves.insert(
                    a,
                    MoveWatermarkV1 {
                        t: view.advert.created_at_unix_ms,
                        machine: m,
                    },
                );
                self.set_watermark(
                    &mut state,
                    &mut next,
                    a,
                    MoveWatermarkV1 {
                        t: view.advert.created_at_unix_ms,
                        machine: m,
                    },
                    now,
                )?;
            }
            next.records.insert(a, record.clone());
            let mut verified = state.verified.clone();
            verified.insert(a, Arc::clone(&view));
            self.evict_records(&state, &mut next, &verified, now);
            next.encode()?; // Refuse an over-cap insert before committing state.
            if moving {
                drop(state);
                self.write_move(&next, now)?;
                state = self.lock()?;
                state.suspended.remove(&a);
                state.pending_moves.remove(&a);
            } else {
                state.dirty = true;
            }
            state.file = next;
            state.verified = verified;
            let retained: HashSet<_> = state.file.records.keys().copied().collect();
            state.verified.retain(|id, _| retained.contains(id));
            state.by_machine = state
                .verified
                .iter()
                .map(|(a, v)| (v.announcement.machine_id.0, a.0))
                .collect();
            state.live.retain(|id, _| retained.contains(id));
            state.last_used.retain(|id, _| retained.contains(id));
        }
        if state.file.records.contains_key(&a) {
            state.live.insert(
                a,
                CachedRecord {
                    wire: record,
                    view,
                    source,
                },
            );
            state.last_used.insert(a, now);
        }
        drop(state);
        self.flush_serialized(now, false)
    }
    /// Verified advert-only move: removes old authority and writes the watermark
    /// atomically. The agent key is hash-checked by the advert verifier.
    pub fn ingest_move_advert(&self, bytes: &[u8], agent_key: &[u8], now: u64) -> Result<()> {
        let advert = verify_advert(bytes, agent_key, now, W_MS, &mut || true)?;
        let a = AgentId(advert.agent_id);
        let m = MachineId(advert.machine_id);
        let _mutation = self.lock_mutation()?;
        let mut state = self.lock()?;
        let old = state
            .verified
            .get(&a)
            .ok_or(EvidenceError::Invalid("no stored binding to move"))?;
        if old.announcement.machine_id == m
            || advert.created_at_unix_ms <= old.advert.created_at_unix_ms
            || state
                .file
                .watermarks
                .get(&a)
                .is_some_and(|w| advert.created_at_unix_ms <= w.t)
        {
            return Err(EvidenceError::Invalid("not a newer move"));
        }
        if !self.policy.contains_agent(a, now)
            || self.policy.revoked(
                a,
                m,
                old.certificate.as_ref().and_then(|c| c.user_id().ok()),
            )
        {
            return Err(EvidenceError::Invalid("move policy"));
        }
        if state.pending_moves.get(&a).is_some_and(|w| {
            advert.created_at_unix_ms < w.t || (advert.created_at_unix_ms == w.t && m != w.machine)
        }) {
            return Err(EvidenceError::Invalid("pending newer move"));
        }
        state.suspended.insert(a);
        state.pending_moves.insert(
            a,
            MoveWatermarkV1 {
                t: advert.created_at_unix_ms,
                machine: m,
            },
        );
        let mut next = state.file.clone();
        self.set_watermark(
            &mut state,
            &mut next,
            a,
            MoveWatermarkV1 {
                t: advert.created_at_unix_ms,
                machine: m,
            },
            now,
        )?;
        next.records.remove(&a);
        drop(state);
        self.write_move(&next, now)?;
        let mut state = self.lock()?;
        state.file = next;
        if let Some(view) = state.verified.remove(&a) {
            state
                .by_machine
                .remove(&(view.announcement.machine_id.0, a.0));
        }
        state.live.remove(&a);
        state.suspended.remove(&a);
        state.pending_moves.remove(&a);
        Ok(())
    }
    fn set_watermark(
        &self,
        state: &mut State,
        next: &mut EvidenceFileV1,
        a: AgentId,
        mark: MoveWatermarkV1,
        now: u64,
    ) -> Result<()> {
        if next
            .watermarks
            .get(&a)
            .is_some_and(|w| mark.t < w.t || (mark.t == w.t && mark.machine != w.machine))
        {
            return Err(EvidenceError::Invalid("older watermark"));
        }
        if !next.watermarks.contains_key(&a) && next.watermarks.len() == WATERMARK_CAP {
            for id in next.watermarks.keys() {
                if self.policy.contains_agent(*id, now) {
                    state.absent_since.remove(id);
                } else {
                    state.absent_since.entry(*id).or_insert(now);
                }
            }
            let victim = next
                .watermarks
                .iter()
                .filter(|(id, w)| {
                    !next.records.contains_key(id)
                        && !self.policy.contains_agent(**id, now)
                        && now.saturating_sub(w.t) > self.max_age
                })
                .min_by_key(|(id, _)| {
                    (
                        state.absent_since.get(id).copied().unwrap_or(now),
                        *id.as_bytes(),
                    )
                })
                .map(|(id, _)| *id);
            let Some(victim) = victim else {
                state.counters.evidence_watermark_full += 1;
                return Err(EvidenceError::Invalid("watermark full"));
            };
            next.watermarks.remove(&victim);
            state.absent_since.remove(&victim);
        }
        next.watermarks.insert(a, mark);
        Ok(())
    }
    fn evict_records(
        &self,
        state: &State,
        next: &mut EvidenceFileV1,
        verified: &HashMap<AgentId, Arc<EvidenceView>>,
        now: u64,
    ) {
        while next.records.len() > RECORD_CAP {
            let victim = next
                .records
                .iter()
                .min_by_key(|(id, r)| {
                    let relation = verified
                        .get(id)
                        .filter(|v| current(v, now, self.max_age))
                        .map(|v| {
                            self.policy.relation(
                                **id,
                                v.announcement.machine_id,
                                v.certificate.as_ref(),
                                now,
                            )
                        })
                        .unwrap_or(0);
                    let priority = if relation & ENROLLED != 0 {
                        3
                    } else if relation & GRANT != 0 {
                        2
                    } else if relation & GROUP != 0 {
                        1
                    } else {
                        0
                    };
                    (
                        priority,
                        state.last_used.get(id).copied().unwrap_or(r.stored_at_ms),
                        *id.as_bytes(),
                    )
                })
                .map(|(id, _)| *id);
            if let Some(victim) = victim {
                next.records.remove(&victim);
            } else {
                break;
            }
        }
    }
    /// Reconcile policy changes and expiry, at least every 60 seconds once
    /// integrated. Tracks how long watermark agents have been absent; after a
    /// restart absent agents tie at the first observation (conservative).
    pub fn maintain(&self, now: u64) -> Result<()> {
        let epoch = self.policy.unavailable_epoch();
        let _mutation = self.lock_mutation()?;
        let (file, verified) = {
            let state = self.lock()?;
            (state.file.clone(), state.verified.clone())
        };
        let absent: Vec<_> = file
            .watermarks
            .keys()
            .map(|a| (*a, !self.policy.contains_agent(*a, now)))
            .collect();
        let removed: Vec<_> = verified
            .iter()
            .filter(|(a, v)| {
                !current(v, now, self.max_age)
                    || disqualified(&file.watermarks, **a, v)
                    || !allowed(&*self.policy, v, now)
            })
            .map(|(a, _)| *a)
            .collect();
        if self.policy.unavailable_epoch() != epoch {
            return Ok(());
        }
        let mut state = self.lock()?;
        for (a, absent) in absent {
            if absent {
                state.absent_since.entry(a).or_insert(now);
            } else {
                state.absent_since.remove(&a);
            }
        }
        for a in removed {
            state.file.records.remove(&a);
            if let Some(view) = state.verified.remove(&a) {
                state
                    .by_machine
                    .remove(&(view.announcement.machine_id.0, a.0));
            }
            state.live.remove(&a);
            state.last_used.remove(&a);
            state.dirty = true;
        }
        drop(state);
        self.flush_serialized(now, false)
    }

    /// Remove matching records and live bytes, preserving all watermarks.
    pub fn remove_where(
        &self,
        predicate: impl Fn(AgentId, &EvidenceRecordV1) -> bool,
    ) -> Result<()> {
        let _mutation = self.lock_mutation()?;
        let mut state = self.lock()?;
        let removed: Vec<_> = state
            .file
            .records
            .iter()
            .filter(|(a, r)| predicate(**a, r))
            .map(|(a, _)| *a)
            .collect();
        for a in removed {
            state.file.records.remove(&a);
            if let Some(view) = state.verified.remove(&a) {
                state
                    .by_machine
                    .remove(&(view.announcement.machine_id.0, a.0));
            }
            state.live.remove(&a);
            state.last_used.remove(&a);
            state.dirty = true;
        }
        Ok(())
    }
    /// Flush due material changes, or force a dirty flush on clean shutdown.
    pub fn flush(&self, now: u64, shutdown: bool) -> Result<()> {
        let _mutation = self.lock_mutation()?;
        self.flush_serialized(now, shutdown)
    }
    // Caller holds mutation throughout snapshot, write and commit.
    fn flush_serialized(&self, now: u64, force: bool) -> Result<()> {
        let snapshot = {
            let state = self.lock()?;
            if self.memory_only
                || !state.dirty
                || (!force
                    && state
                        .last_write
                        .is_some_and(|t| now.saturating_sub(t) < 60_000))
            {
                return Ok(());
            }
            state.file.clone()
        };
        self.write(&snapshot)?;
        self.wrote(&mut *self.lock()?, &snapshot, now)
    }
    fn write_move(&self, next: &EvidenceFileV1, now: u64) -> Result<()> {
        // No persisted authority exists to protect in this mode. The caller
        // still applies the record and watermark in one in-memory transaction.
        if self.memory_only {
            return Ok(());
        }
        if let Err(e) = self.write(next) {
            self.lock()?.counters.evidence_move_write_failed += 1;
            return Err(e);
        }
        self.wrote(&mut *self.lock()?, next, now)
    }
    fn wrote(&self, state: &mut State, file: &EvidenceFileV1, now: u64) -> Result<()> {
        state.counters.evidence_writes += 1;
        state.counters.evidence_bytes_written += file.encode()?.len() as u64;
        state.last_write = Some(now);
        state.dirty = false;
        Ok(())
    }
    fn write(&self, file: &EvidenceFileV1) -> Result<()> {
        if self.memory_only {
            return Err(EvidenceError::Invalid(
                "move cannot be durable in memory-only mode",
            ));
        }
        let bytes = file.encode()?;
        let parent = self
            .path
            .parent()
            .ok_or(EvidenceError::Invalid("missing parent"))?;
        fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(".peer-evidence-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(&bytes)?;
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 1 {
                return Err(std::io::Error::other("injected before fsync").into());
            }
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 3 {
                std::process::exit(89);
            }
            #[cfg(test)]
            if let Some(hook) = self.slow_write.lock().unwrap().clone() {
                hook.entered.wait();
                hook.release.wait();
            }
            f.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            File::open(parent)?.sync_all()?;
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 4 {
                std::process::exit(89);
            }
            #[cfg(test)]
            if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) == 2 {
                return Err(std::io::Error::other("injected after directory fsync").into());
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
}
#[cfg(test)]
struct SlowWrite {
    entered: std::sync::Barrier,
    release: std::sync::Barrier,
}
fn current(view: &EvidenceView, now: u64, age: u64) -> bool {
    announcement_ms(&view.announcement).is_ok_and(|t| fresh(t, now, age))
        && fresh(view.advert.created_at_unix_ms, now, age)
        && view.certificate.as_ref().is_none_or(|cert| {
            !cert.is_expired(now / 1000) && cert.issued_at() <= now.saturating_add(SKEW_MS) / 1000
        })
}
fn allowed(policy: &dyn EvidencePolicy, view: &EvidenceView, now: u64) -> bool {
    let a = view.announcement.agent_id;
    let m = view.announcement.machine_id;
    policy.relation(a, m, view.certificate.as_ref(), now) != 0
        && !policy.revoked(
            a,
            m,
            view.certificate.as_ref().and_then(|c| c.user_id().ok()),
        )
}
/// [`allowed`] without ever blocking (x0x #1150 r7c): `None` while a policy
/// read would block.
fn try_allowed(policy: &dyn EvidencePolicy, view: &EvidenceView, now: u64) -> Option<bool> {
    let a = view.announcement.agent_id;
    let m = view.announcement.machine_id;
    if policy.try_relation(a, m, view.certificate.as_ref(), now)? == 0 {
        return Some(false);
    }
    let user = view.certificate.as_ref().and_then(|c| c.user_id().ok());
    Some(!policy.try_revoked(a, m, user)?)
}
fn disqualified(
    watermarks: &HashMap<AgentId, MoveWatermarkV1>,
    a: AgentId,
    view: &EvidenceView,
) -> bool {
    watermarks.get(&a).is_some_and(|w| {
        w.machine != view.announcement.machine_id && w.t > view.advert.created_at_unix_ms
    })
}

/// Process-only gossip attempt cache, including refusals. It grants no authority.
#[derive(Default)]
pub(crate) struct GossipPairing {
    processed: HashMap<AgentId, PairAttempt>,
}
struct PairAttempt {
    fingerprint: [u8; 32],
    unavailable_epoch: u64,
    last_used: u64,
}
impl GossipPairing {
    /// None means this exact input and policy epoch were already attempted.
    pub(crate) fn ingest(
        &mut self,
        store: &PeerEvidenceStore,
        agent: AgentId,
        record: EvidenceRecordV1,
        now: u64,
    ) -> Option<Result<()>> {
        // Hello has already verified and ingested this exact pair. Do not
        // repeat crypto outside its wire verify budget or strip a fetched cert.
        if store.state.lock().is_ok_and(|state| {
            state.live.get(&agent).is_some_and(|live| {
                live.source == IngestSource::Hello
                    && live.wire.announcement == record.announcement
                    && live.wire.advert == record.advert
                    && (record.certificate.is_none() || live.wire.certificate == record.certificate)
            })
        }) {
            return None;
        }
        let mut hash = blake3::Hasher::new();
        hash.update(&record.announcement);
        hash.update(&record.advert);
        if let Some(cert) = &record.certificate {
            hash.update(cert);
        }
        let fingerprint = *hash.finalize().as_bytes();
        let epoch = store.policy.unavailable_epoch();
        if let Some(previous) = self.processed.get_mut(&agent) {
            previous.last_used = now;
            if previous.fingerprint == fingerprint && previous.unavailable_epoch == epoch {
                return None;
            }
        }
        let result = store.ingest(record, IngestSource::Gossip, now);
        if self.processed.len() >= RECORD_CAP && !self.processed.contains_key(&agent) {
            // Same bounded LRU ordering as the evidence store, including ties.
            if let Some(victim) = self
                .processed
                .iter()
                .min_by_key(|(id, attempt)| (attempt.last_used, *id.as_bytes()))
                .map(|(id, _)| *id)
            {
                self.processed.remove(&victim);
            }
        }
        self.processed.insert(
            agent,
            PairAttempt {
                fingerprint,
                // Include unavailability observed by this attempt so a refusal
                // does not itself force another verification on the next tick.
                unavailable_epoch: store.policy.unavailable_epoch(),
                last_used: now,
            },
        );
        Some(result)
    }

    pub(crate) fn retain_fresh(&mut self, capture: &VerifiedWireCapture, now: u64) {
        let Ok(entries) = capture.inner.lock() else {
            return;
        };
        self.processed.retain(|agent, _| {
            [0, 1].into_iter().all(|part| {
                entries
                    .get(&(*agent, part))
                    .is_some_and(|wire| fresh(wire.timestamp, now, W_MS))
            })
        });
    }
}

/// Bounded, process-only verified capture for pairing. Strangers may occupy
/// this TTL cache, never the persistent relationship store.
#[derive(Default)]
pub struct VerifiedWireCapture {
    inner: Mutex<HashMap<(AgentId, u8), CapturedWire>>,
    pub(crate) changed: tokio::sync::Notify,
}
struct CapturedWire {
    bytes: Vec<u8>,
    timestamp: u64,
}
impl VerifiedWireCapture {
    /// Capture only after the existing listener has verified its wire body.
    pub(crate) fn capture(
        &self,
        agent: AgentId,
        announcement: bool,
        bytes: &[u8],
        timestamp: u64,
        now: u64,
    ) {
        if bytes.len()
            > if announcement {
                ANNOUNCEMENT_CAP
            } else {
                ADVERT_CAP
            }
            || !fresh(timestamp, now, W_MS)
        {
            return;
        }
        let Ok(mut entries) = self.inner.lock() else {
            return;
        };
        entries.retain(|_, v| fresh(v.timestamp, now, W_MS));
        let key = (agent, u8::from(announcement));
        if entries.get(&key).is_some_and(|v| v.timestamp >= timestamp) {
            return;
        }
        if entries.len() >= RECORD_CAP * 2 && !entries.contains_key(&key) {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, v)| v.timestamp)
                .map(|(k, _)| *k)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            CapturedWire {
                bytes: bytes.to_vec(),
                timestamp,
            },
        );
        self.changed.notify_one();
    }
    /// Agents with fresh captured material; bounded to the capture cap.
    pub(crate) fn agents(&self, now: u64) -> Vec<AgentId> {
        self.inner
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, v)| fresh(v.timestamp, now, W_MS))
                    .map(|((a, _), _)| *a)
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Return exact captured bytes for future pairing, provided still fresh.
    pub fn get(&self, agent: AgentId, announcement: bool, now: u64) -> Option<Vec<u8>> {
        let entries = self.inner.lock().ok()?;
        let value = entries.get(&(agent, u8::from(announcement)))?;
        fresh(value.timestamp, now, W_MS).then(|| value.bytes.clone())
    }
}

/// The reason a non-blocking point-of-use check could not take the store lock.
const STORE_BUSY: &str = "store_busy";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dm::DmCapabilities,
        dm_capability::{RegistryTrailer, REGISTRY_TRAILER_MAGIC},
        identity::{AgentKeypair, MachineKeypair, UserKeypair},
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    const NOW: u64 = 2_000_000_000_000;
    #[derive(Default)]
    struct Policy {
        peers: Mutex<HashMap<AgentId, u8>>,
        revoked: AtomicBool,
        unavailable: AtomicBool,
        epoch: std::sync::atomic::AtomicU64,
    }
    impl EvidencePolicy for Policy {
        fn unavailable_epoch(&self) -> u64 {
            self.epoch.load(Ordering::Relaxed)
        }
        fn relation(&self, a: AgentId, _: MachineId, _: Option<&AgentCertificate>, _: u64) -> u8 {
            if self.unavailable.load(Ordering::Relaxed) {
                self.epoch.fetch_add(1, Ordering::Relaxed);
                return 0;
            }
            self.peers.lock().unwrap().get(&a).copied().unwrap_or(0)
        }
        fn revoked(&self, _: AgentId, _: MachineId, _: Option<UserId>) -> bool {
            self.revoked.load(Ordering::Relaxed)
        }
        fn contains_agent(&self, a: AgentId, _: u64) -> bool {
            self.peers.lock().unwrap().contains_key(&a)
        }
    }
    struct Peer {
        agent: AgentKeypair,
        machine: MachineKeypair,
    }
    impl Peer {
        fn new() -> Self {
            Self {
                agent: AgentKeypair::generate().unwrap(),
                machine: MachineKeypair::generate().unwrap(),
            }
        }
        fn a(&self) -> AgentId {
            self.agent.agent_id()
        }
        fn m(&self) -> MachineId {
            self.machine.machine_id()
        }
        fn record(&self, ann_time: u64, advert_time: u64) -> EvidenceRecordV1 {
            let v2 = crate::IdentityAnnouncement {
                self_name: Some("wire name".into()),
                agent_id: self.a(),
                machine_id: self.m(),
                user_id: None,
                agent_certificate: None,
                machine_public_key: self.machine.public_key().as_bytes().to_vec(),
                machine_signature: vec![],
                addresses: vec![],
                announced_at: ann_time / 1000,
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: vec![],
                relay_candidates: vec![],
                agent_public_key: self.agent.public_key().as_bytes().to_vec(),
            };
            let mut ann =
                IdentityAnnouncementV3::build_from_v2(&v2, self.machine.secret_key(), 0).unwrap();
            ann.sign_v3_1(self.machine.secret_key()).unwrap();
            let mut caps = DmCapabilities::pending();
            caps.kem_public_key = vec![42; 1184];
            let mut advert = CapabilityAdvert {
                protocol_version: crate::dm_capability_service::ADVERT_PROTOCOL_VERSION,
                agent_id: *self.a().as_bytes(),
                machine_id: *self.m().as_bytes(),
                created_at_unix_ms: advert_time,
                capabilities: caps,
                signature: vec![],
            };
            advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                self.agent.secret_key(),
                &advert.signed_bytes().unwrap(),
            )
            .unwrap()
            .as_bytes()
            .to_vec();
            let mut trailer = RegistryTrailer {
                registry: Default::default(),
                signature: vec![],
            };
            trailer.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                self.agent.secret_key(),
                &trailer.signed_bytes(&advert).unwrap(),
            )
            .unwrap()
            .as_bytes()
            .to_vec();
            let mut bytes = postcard::to_stdvec(&advert).unwrap();
            bytes.extend_from_slice(REGISTRY_TRAILER_MAGIC);
            bytes.extend(postcard::to_stdvec(&trailer).unwrap());
            EvidenceRecordV1 {
                announcement: announce_v3::serialize_v3_1(&ann).unwrap(),
                advert: bytes,
                certificate: None,
                relation: GROUP,
                stored_at_ms: NOW,
            }
        }
    }
    fn setup(peer: &Peer) -> (tempfile::TempDir, Arc<Policy>, PeerEvidenceStore) {
        let dir = tempfile::tempdir().unwrap();
        let p = Arc::new(Policy::default());
        p.peers.lock().unwrap().insert(peer.a(), GROUP);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), p.clone(), NOW).unwrap();
        (dir, p, store)
    }
    /// WHY (x0x #1150 r7c, Codex NEW 3): the non-blocking point-of-use
    /// check is the pinned seam's and the bounded resolution's. Its policy
    /// evaluation (RuntimePolicy, through owner trust into the share-grant
    /// store) must never wait on a held policy lock: while a writer holds
    /// the grant store it reports busy, and it never blocks.
    #[test]
    fn r7c_try_usable_agent_reports_busy_while_the_grant_store_is_held() {
        let p = Peer::new();
        let dir = tempfile::tempdir().unwrap();
        let local = AgentKeypair::generate().unwrap().agent_id();
        let grants = Arc::new(crate::share_grant::ShareGrantStore::in_memory(local, None));
        let owner = crate::owner_trust::OwnerTrust::new(None, Default::default());
        owner.install_share_grant_store(Arc::clone(&grants));
        let revoked = Arc::new(tokio::sync::RwLock::new(
            crate::revocation::RevocationSet::new(),
        ));
        let policy = Arc::new(RuntimePolicy::new(local, owner, revoked));
        policy.set_groups(Arc::new(|_| Some(true)));
        let store = Arc::new(
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW).unwrap(),
        );
        store
            .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
            .unwrap();
        assert!(
            store
                .try_usable_agent(p.a(), NOW)
                .is_ok_and(|view| view.is_some()),
            "control: usable while no policy lock is held"
        );
        let held = grants.hold_state_for_testing();
        let (tx, rx) = std::sync::mpsc::channel();
        let checker = Arc::clone(&store);
        let agent = p.a();
        let worker = std::thread::spawn(move || {
            let _ = tx.send(checker.try_usable_agent(agent, NOW));
        });
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(2));
        drop(held);
        let _ = worker.join();
        assert!(
            matches!(outcome, Ok(Err(()))),
            "the non-blocking check waited on (or ignored) a held policy lock: {outcome:?}"
        );
    }

    #[test]
    fn cached_views_do_zero_verifies_on_use_and_maintenance() {
        let p = Peer::new();
        let (dir, policy, mut store) = setup(&p);
        let mut record = p.record(NOW, NOW);
        record.certificate = Some(
            AgentCertificate::issue_with_expiry(
                &UserKeypair::generate().unwrap(),
                &p.agent,
                Some(NOW / 1000 + 120),
            )
            .unwrap()
            .to_storage_bytes()
            .unwrap(),
        );
        VERIFY_CALLS.set(0);
        store.ingest(record, IngestSource::Hello, NOW).unwrap();
        assert_eq!(
            VERIFY_CALLS.get(),
            4,
            "each signed part verified once on ingest"
        );
        for reopened in [false, true] {
            if reopened {
                VERIFY_CALLS.set(0);
                store = PeerEvidenceStore::open(
                    dir.path(),
                    EvidenceConfig::default(),
                    policy.clone(),
                    NOW,
                )
                .unwrap();
                assert_eq!(
                    VERIFY_CALLS.get(),
                    4,
                    "each signed part verified once on load"
                );
            }
            VERIFY_CALLS.set(0);
            let first = store.usable(p.a(), p.m(), NOW).unwrap();
            assert!(
                Arc::ptr_eq(&first, &store.usable(p.a(), p.m(), NOW).unwrap()),
                "per-frame lookup must clone only the Arc"
            );
            for _ in 0..100 {
                assert!(store.usable(p.a(), p.m(), NOW).is_some());
                assert_eq!(store.live(p.a(), NOW).is_some(), !reopened);
                store.maintain(NOW).unwrap();
            }
            policy.revoked.store(true, Ordering::Relaxed);
            assert!(store.usable(p.a(), p.m(), NOW).is_none());
            policy.revoked.store(false, Ordering::Relaxed);
            assert!(store
                .usable(p.a(), p.m(), NOW + SKEW_MS + 121_000)
                .is_none());
            assert_eq!(
                VERIFY_CALLS.get(),
                0,
                "use and maintenance must never verify"
            );
        }
        store.maintain(NOW + SKEW_MS + 121_000).unwrap();
        assert!(store.lock().unwrap().verified.is_empty());
        assert_eq!(VERIFY_CALLS.get(), 0, "expiry sweep must never verify");
    }

    #[test]
    fn memory_only_moves_apply_without_writes() {
        for advert_only in [false, true] {
            let mut p = Peer::new();
            let (dir, policy, _) = setup(&p);
            let path = dir.path().join("peer-evidence.bin");
            let unreadable = b"unknown version: preserve me";
            fs::write(&path, unreadable).unwrap();
            let store = PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW)
                .unwrap();
            assert!(store.is_memory_only());
            store
                .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
                .unwrap();
            let old = p.m();
            let stale = p.record(NOW, NOW);
            p.machine = MachineKeypair::generate().unwrap();
            let t = NOW + 1000;
            let record = p.record(t, t);
            store.fail_write.store(1, Ordering::Relaxed);
            if advert_only {
                store
                    .ingest_move_advert(&record.advert, p.agent.public_key().as_bytes(), t)
                    .unwrap();
                assert!(store.usable(p.a(), old, t).is_none());
                assert!(!store.lock().unwrap().suspended.contains(&p.a()));
            }
            store.ingest(record, IngestSource::Hello, t).unwrap();
            assert!(store.usable(p.a(), old, t).is_none());
            assert!(store.usable(p.a(), p.m(), t).is_some());
            assert!(store.ingest(stale, IngestSource::Hello, t).is_err());
            assert_eq!(store.lock().unwrap().file.watermarks[&p.a()].machine, p.m());
            store.flush(t, true).unwrap();
            assert_eq!(store.counters().unwrap().evidence_writes, 0);
            assert_eq!(store.counters().unwrap().evidence_move_write_failed, 0);
            assert_eq!(fs::read(path).unwrap(), unreadable);
        }
    }

    #[test]
    fn other_agent_usable_during_slow_move_write() {
        for advert_only in [false, true] {
            let mut p = Peer::new();
            let other = Peer::new();
            let (dir, policy, store) = setup(&p);
            policy.peers.lock().unwrap().insert(other.a(), GROUP);
            store
                .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
                .unwrap();
            store
                .ingest(other.record(NOW, NOW), IngestSource::Hello, NOW)
                .unwrap();
            let store = Arc::new(store);
            let old = p.m();
            p.machine = MachineKeypair::generate().unwrap();
            let t = NOW + 1000;
            let record = p.record(t, t);
            let hook = Arc::new(SlowWrite {
                entered: std::sync::Barrier::new(2),
                release: std::sync::Barrier::new(2),
            });
            *store.slow_write.lock().unwrap() = Some(hook.clone());
            let writer_store = store.clone();
            let key = p.agent.public_key().as_bytes().to_vec();
            let writer = std::thread::spawn(move || {
                if advert_only {
                    writer_store.ingest_move_advert(&record.advert, &key, t)
                } else {
                    writer_store.ingest(record, IngestSource::Hello, t)
                }
            });
            hook.entered.wait();
            let reader_store = store.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let a = p.a();
            let m = p.m();
            let other_a = other.a();
            let other_m = other.m();
            let reader = std::thread::spawn(move || {
                tx.send((
                    reader_store.usable(other_a, other_m, t).is_some(),
                    reader_store.usable(a, old, t).is_none(),
                    reader_store.usable(a, m, t).is_none(),
                ))
                .unwrap();
            });
            let result = rx.recv_timeout(std::time::Duration::from_secs(2));
            // Always unblock the writer before asserting, including on failure.
            hook.release.wait();
            writer.join().unwrap().unwrap();
            reader.join().unwrap();
            assert_eq!(result.unwrap(), (true, true, true));
            assert_eq!(store.usable(a, m, t).is_some(), !advert_only);
            let reopened =
                PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, t).unwrap();
            assert!(reopened.usable(other_a, other_m, t).is_some());
            assert!(reopened.usable(a, old, t).is_none());
            assert_eq!(reopened.usable(a, m, t).is_some(), !advert_only);
        }
    }

    #[test]
    fn use_rechecks_snapshot_after_unlocked_policy() {
        struct PausingPolicy {
            hook: Mutex<Option<Arc<SlowWrite>>>,
        }
        impl EvidencePolicy for PausingPolicy {
            fn relation(
                &self,
                _: AgentId,
                _: MachineId,
                _: Option<&AgentCertificate>,
                _: u64,
            ) -> u8 {
                let hook = self.hook.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook.entered.wait();
                    hook.release.wait();
                }
                GROUP
            }
            fn revoked(&self, _: AgentId, _: MachineId, _: Option<UserId>) -> bool {
                false
            }
            fn contains_agent(&self, _: AgentId, _: u64) -> bool {
                true
            }
        }
        let p = Peer::new();
        let dir = tempfile::tempdir().unwrap();
        let policy = Arc::new(PausingPolicy {
            hook: Mutex::new(None),
        });
        let store = Arc::new(
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap(),
        );
        store
            .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
            .unwrap();
        let hook = Arc::new(SlowWrite {
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        *policy.hook.lock().unwrap() = Some(hook.clone());
        let reader_store = store.clone();
        let a = p.a();
        let m = p.m();
        let reader = std::thread::spawn(move || reader_store.usable(a, m, NOW));
        hook.entered.wait();
        let (tx, rx) = std::sync::mpsc::channel();
        let writer_store = store.clone();
        let writer = std::thread::spawn(move || {
            tx.send(writer_store.remove_where(|id, _| id == a)).unwrap()
        });
        let removed = rx.recv_timeout(std::time::Duration::from_secs(2));
        hook.release.wait();
        writer.join().unwrap();
        let result = reader.join().unwrap();
        removed.unwrap().unwrap();
        assert!(
            result.is_none(),
            "removed snapshot cannot authorize after policy returns"
        );
    }

    #[test]
    fn snapshot_encoding_is_independent_of_map_insertion_order() {
        let p = Peer::new();
        let record = p.record(NOW, NOW);
        let mut forward = EvidenceFileV1::default();
        let mut reverse = EvidenceFileV1::default();
        for i in 0..8 {
            let a = AgentId([i; 32]);
            forward.records.insert(a, record.clone());
            forward.watermarks.insert(
                a,
                MoveWatermarkV1 {
                    t: NOW + u64::from(i),
                    machine: p.m(),
                },
            );
        }
        for i in (0..8).rev() {
            let a = AgentId([i; 32]);
            reverse.records.insert(a, forward.records[&a].clone());
            reverse.watermarks.insert(a, forward.watermarks[&a]);
        }
        let encoded = forward.encode().unwrap();
        assert_eq!(encoded, reverse.encode().unwrap());
        assert_eq!(EvidenceFileV1::decode(&encoded).unwrap(), forward);
    }

    #[test]
    fn freshness_each_component_and_future_skew() {
        let p = Peer::new();
        for (a, b) in [
            (NOW - W_MS - 1000, NOW),
            (NOW, NOW - W_MS - 1),
            (NOW + SKEW_MS + 1000, NOW),
            (NOW, NOW + SKEW_MS + 1),
        ] {
            assert!(p.record(a, b).verify(NOW, W_MS).is_err());
        }
        assert!(p.record(NOW - W_MS, NOW - W_MS).verify(NOW, W_MS).is_ok());
        assert!(p
            .record(NOW + SKEW_MS, NOW + SKEW_MS)
            .verify(NOW, W_MS)
            .is_ok());
    }
    #[test]
    fn stored_freshness_is_per_component_and_configured_lifetime() {
        let p = Peer::new();
        for (a, b) in [(NOW - 7 * DAY_MS - 1000, NOW), (NOW, NOW - 7 * DAY_MS - 1)] {
            assert!(p.record(a, b).verify(NOW, 7 * DAY_MS).is_err());
        }
        let (dir, policy, _) = setup(&p);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig { max_age_days: 1 }, policy, NOW)
                .unwrap();
        store
            .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
            .unwrap();
        assert!(store.usable(p.a(), p.m(), NOW + DAY_MS).is_some());
        assert!(store.usable(p.a(), p.m(), NOW + DAY_MS + 1).is_none());
        let config: EvidenceConfig = toml::from_str("").unwrap();
        assert_eq!(config.max_age_days, 7);
    }
    #[test]
    fn tamper_each_signed_part_and_exact_consumption() {
        let p = Peer::new();
        let r = p.record(NOW, NOW);
        assert!(r.verify(NOW, W_MS).is_ok());
        let mut bad = r.clone();
        let n = bad.announcement.len();
        bad.announcement[n - 2] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        let mut bad = r.clone();
        bad.advert[100] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        let mut bad = r.clone();
        let n = bad.advert.len();
        bad.advert[n - 2] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        for part in [true, false] {
            let mut bad = r.clone();
            if part {
                bad.announcement.push(0);
            } else {
                bad.advert.push(0);
            }
            assert!(bad.verify(NOW, W_MS).is_err());
        }
        let owner = UserKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&owner, &p.agent).unwrap();
        let mut r = r;
        r.certificate = Some(cert.to_storage_bytes().unwrap());
        assert!(r.verify(NOW, W_MS).is_ok());
        let mut bad = r.clone();
        bad.certificate.as_mut().unwrap()[100] ^= 1;
        assert!(bad.verify(NOW, W_MS).is_err());
        let mut bad = r;
        bad.certificate.as_mut().unwrap().push(0);
        assert!(bad.verify(NOW, W_MS).is_err());
    }
    #[test]
    fn mismatched_agent_machine_and_certificate() {
        let p = Peer::new();
        let mut other = Peer::new();
        let mut r = p.record(NOW, NOW);
        r.advert = other.record(NOW, NOW).advert;
        assert!(r.verify(NOW, W_MS).is_err());
        r = p.record(NOW, NOW);
        r.certificate = Some(
            AgentCertificate::issue(&UserKeypair::generate().unwrap(), &other.agent)
                .unwrap()
                .to_storage_bytes()
                .unwrap(),
        );
        assert!(r.verify(NOW, W_MS).is_err());
        other.agent = p.agent;
        let moved = other.record(NOW, NOW);
        r.certificate = None;
        r.advert = moved.advert;
        assert!(r.verify(NOW, W_MS).is_err());
    }
    #[test]
    fn routine_refresh_restart_preserves_stored_authority_and_live_bytes() {
        let p = Peer::new();
        let (dir, policy, store) = setup(&p);
        let initial = p.record(NOW, NOW);
        store
            .ingest(initial.clone(), IngestSource::Gossip, NOW)
            .unwrap();
        for i in 1..=3 {
            let t = NOW + i * 60_000;
            let r = p.record(t, t);
            store.ingest(r.clone(), IngestSource::Gossip, t).unwrap();
            assert_eq!(store.live(p.a(), t).unwrap().advert, r.advert);
        }
        assert!(store.lock().unwrap().file.watermarks.is_empty());
        assert_eq!(
            store.lock().unwrap().file.records[&p.a()].advert,
            initial.advert
        );
        assert_eq!(store.counters().unwrap().evidence_writes, 1);
        drop(store);
        let reopened =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW + 180_000)
                .unwrap();
        assert!(reopened.usable(p.a(), p.m(), NOW + 180_000).is_some());
        assert!(reopened.live(p.a(), NOW + 180_000).is_none());
    }
    #[tokio::test(start_paused = true)]
    async fn s3_verify_budget_charges_each_signature_and_stops_before_crypto() {
        let p = Peer::new();
        let mut record = p.record(NOW, NOW);
        let cert = AgentCertificate::issue(&UserKeypair::generate().unwrap(), &p.agent).unwrap();
        record.certificate = Some(cert.to_storage_bytes().unwrap());
        let mut ann = announce_v3::deserialize_v3(&record.announcement).unwrap();
        ann.cert_digest = announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert));
        ann.sign_v3_1(p.machine.secret_key()).unwrap();
        record.announcement = announce_v3::serialize_v3_1(&ann).unwrap();
        let limits = crate::evidence_wire::Limits::default();
        let capture = VerifiedWireCapture::default();
        let ingest = |record| {
            crate::evidence_wire::ingest_hello(None, &capture, &limits, p.m(), record, NOW)
        };
        VERIFY_CALLS.set(0);
        for _ in 0..8 {
            ingest(record.clone()).unwrap();
        }
        assert_eq!(VERIFY_CALLS.get(), 32, "eight Hellos cost 32 signatures");
        assert!(ingest(record.clone()).is_err());
        assert_eq!(VERIFY_CALLS.get(), 32, "budget rejection runs no crypto");
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        VERIFY_CALLS.set(0);
        // Absent certificates cost three, absent trailers cost two.
        let no_cert = p.record(NOW, NOW);
        ingest(no_cert.clone()).unwrap();
        assert_eq!(VERIFY_CALLS.get(), 3);
        let mut base = no_cert;
        let (advert, _) = CapabilityAdvert::decode_evidence(&base.advert).unwrap();
        base.advert = postcard::to_stdvec(&advert).unwrap();
        ingest(base.clone()).unwrap();
        assert_eq!(VERIFY_CALLS.get(), 5);
        for _ in 0..6 {
            ingest(record.clone()).unwrap();
        }
        assert_eq!(VERIFY_CALLS.get(), 29);
        assert!(ingest(record.clone()).is_err());
        assert_eq!(
            VERIFY_CALLS.get(),
            32,
            "exhaustion stops before certificate verification"
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        VERIFY_CALLS.set(0);
        let mut bad = announce_v3::deserialize_v3(&base.announcement).unwrap();
        bad.machine_signature[0] ^= 1;
        base.announcement = announce_v3::serialize_v3_1(&bad).unwrap();
        for _ in 0..32 {
            assert!(ingest(base.clone()).is_err());
        }
        assert_eq!(
            VERIFY_CALLS.get(),
            32,
            "failed signatures also consume credit"
        );
        assert!(ingest(record).is_err());
        assert_eq!(VERIFY_CALLS.get(), 32);
    }

    #[tokio::test]
    async fn s3_recorded_machine_gets_reserved_capacity_only_while_usable() {
        let p = Peer::new();
        let (_dir, policy, store) = setup(&p);
        let now = crate::dm_capability::now_unix_ms();
        store
            .ingest(p.record(now, now), IngestSource::Hello, now)
            .unwrap();
        let owner = crate::owner_trust::OwnerTrust::new(
            None,
            crate::dm_inbox::AuthenticatedMachineBindings::default(),
        );
        let revoked = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
        let limits = Arc::new(crate::evidence_wire::Limits::default());
        let strangers: Vec<_> = (0..4)
            .map(|id| limits.admit(MachineId([id; 32]), false).unwrap())
            .collect();
        let related =
            crate::evidence_wire::reserved_peer(Some(&store), &owner, &revoked, p.m()).await;
        assert!(related);
        assert!(limits.admit(p.m(), related).is_some());
        policy.peers.lock().unwrap().clear();
        let related =
            crate::evidence_wire::reserved_peer(Some(&store), &owner, &revoked, p.m()).await;
        assert!(!related);
        assert!(limits.admit(p.m(), related).is_none());
        drop(strangers);
    }

    #[test]
    fn s3_hello_ingest_binds_transport_and_refreshes_each_component() {
        let p = Peer::new();
        let policy = Arc::new(Policy::default());
        policy.peers.lock().unwrap().insert(p.a(), GROUP);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap(),
        );
        let capture = VerifiedWireCapture::default();
        let limits = crate::evidence_wire::Limits::default();
        let old = p.record(NOW, NOW);
        store
            .ingest(old.clone(), IngestSource::Gossip, NOW)
            .unwrap();
        let now = NOW + 60_000;
        let fresh = p.record(now, now);
        let ingest = |m, record| {
            crate::evidence_wire::ingest_hello(Some(&store), &capture, &limits, m, record, now)
        };
        assert!(ingest(MachineId([42; 32]), fresh.clone()).is_err());
        assert!(ingest(p.m(), p.record(now - W_MS - 1000, now)).is_err());
        assert!(ingest(p.m(), p.record(now, now - W_MS - 1)).is_err());
        assert!(ingest(p.m(), p.record(now + SKEW_MS + 1000, now)).is_err());
        assert!(ingest(p.m(), p.record(now, now + SKEW_MS + 1)).is_err());
        let view = ingest(p.m(), fresh.clone()).unwrap();
        assert_eq!(view.announcement.machine_id, p.m());
        assert_eq!(
            store.lock().unwrap().file.records[&p.a()].announcement,
            fresh.announcement
        );
        assert_eq!(
            store.lock().unwrap().file.records[&p.a()].advert,
            fresh.advert
        );
        assert!(store.lock().unwrap().file.watermarks.is_empty());
        store.flush(now, true).unwrap();
        let reopened =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), now)
                .unwrap();
        assert_eq!(
            reopened
                .usable(p.a(), p.m(), now)
                .unwrap()
                .advert
                .created_at_unix_ms,
            now
        );
        policy.peers.lock().unwrap().clear();
        assert!(store.usable(p.a(), p.m(), now).is_none());
    }

    #[test]
    fn s3_hello_certificate_digest_and_gossip_pairing_preserve_fresh_cert() {
        let p = Peer::new();
        let (dir, policy, store) = setup(&p);
        let store = Arc::new(store);
        let capture = VerifiedWireCapture::default();
        let limits = crate::evidence_wire::Limits::default();
        let cert = AgentCertificate::issue(&UserKeypair::generate().unwrap(), &p.agent).unwrap();
        let mut record = p.record(NOW, NOW);
        record.certificate = Some(cert.to_storage_bytes().unwrap());
        // A valid but uncommitted certificate is not this Hello's certificate.
        assert!(crate::evidence_wire::ingest_hello(
            Some(&store),
            &capture,
            &limits,
            p.m(),
            record.clone(),
            NOW
        )
        .is_err());
        let mut ann = announce_v3::deserialize_v3(&record.announcement).unwrap();
        ann.cert_digest = announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert));
        ann.sign_v3_1(p.machine.secret_key()).unwrap();
        record.announcement = announce_v3::serialize_v3_1(&ann).unwrap();
        crate::evidence_wire::ingest_hello(
            Some(&store),
            &capture,
            &limits,
            p.m(),
            record.clone(),
            NOW,
        )
        .unwrap();
        let mut no_cert = record.clone();
        no_cert.certificate = None;
        let mut pairing = GossipPairing::default();
        VERIFY_CALLS.set(0);
        assert!(pairing
            .ingest(&store, p.a(), no_cert.clone(), NOW)
            .is_none());
        assert_eq!(
            VERIFY_CALLS.get(),
            0,
            "Hello is not re-verified by background pairing"
        );
        // Also exercise an already-queued gossip mutation racing the Hello.
        store.ingest(no_cert, IngestSource::Gossip, NOW).unwrap();
        assert_eq!(
            store.lock().unwrap().file.records[&p.a()].certificate,
            record.certificate
        );
        store.flush(NOW, true).unwrap();
        let reopened =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW).unwrap();
        assert!(reopened
            .usable(p.a(), p.m(), NOW)
            .unwrap()
            .certificate
            .is_some());
    }

    #[test]
    fn s3_hello_stranger_is_ttl_only() {
        let p = Peer::new();
        let policy = Arc::new(Policy::default());
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW).unwrap(),
        );
        let capture = VerifiedWireCapture::default();
        let limits = crate::evidence_wire::Limits::default();
        let record = p.record(NOW, NOW);
        crate::evidence_wire::ingest_hello(
            Some(&store),
            &capture,
            &limits,
            p.m(),
            record.clone(),
            NOW,
        )
        .unwrap();
        assert!(store.lock().unwrap().file.records.is_empty());
        assert!(store.live(p.a(), NOW).is_none());
        assert_eq!(capture.get(p.a(), true, NOW).unwrap(), record.announcement);
        assert_eq!(capture.get(p.a(), false, NOW).unwrap(), record.advert);
        assert!(capture.get(p.a(), false, NOW + W_MS + 1).is_none());
    }

    #[test]
    fn use_limit_hello_revalidation_and_half_life_refresh() {
        let p = Peer::new();
        let (_, _, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        assert!(store.usable(p.a(), p.m(), NOW + 7 * DAY_MS).is_some());
        assert!(store.usable(p.a(), p.m(), NOW + 7 * DAY_MS + 1).is_none());
        let t = NOW + 4 * DAY_MS;
        store
            .ingest(p.record(t, t), IngestSource::Gossip, t)
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 2);
        let t = t + 60_000;
        store
            .ingest(p.record(t, t), IngestSource::Hello, t)
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 3);
        assert!(store.usable(p.a(), p.m(), t + 7 * DAY_MS).is_some());
        assert!(store.usable(p.a(), p.m(), t + 7 * DAY_MS + 1).is_none());
    }
    #[test]
    fn move_atomic_durable_restart_and_watermark_replay() {
        let mut p = Peer::new();
        let (dir, policy, store) = setup(&p);
        let old = p.m();
        let old_bytes = p.record(NOW, NOW);
        store
            .ingest(old_bytes.clone(), IngestSource::Gossip, NOW)
            .unwrap();
        p.machine = MachineKeypair::generate().unwrap();
        let t = NOW + 1000;
        store
            .ingest(p.record(t, t), IngestSource::Gossip, t)
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 2);
        assert!(store.usable(p.a(), old, t).is_none());
        assert!(store.usable(p.a(), p.m(), t).is_some());
        drop(store);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, t).unwrap();
        assert!(store.usable(p.a(), old, t).is_none());
        assert!(store.usable(p.a(), p.m(), t).is_some());
        assert!(store.ingest(old_bytes, IngestSource::Hello, t).is_err());
        store.remove_where(|_, _| true).unwrap();
        store.flush(t, true).unwrap();
        assert_eq!(store.lock().unwrap().file.watermarks.len(), 1);
    }
    #[test]
    fn crash_checkpoints_before_and_after_fsync_and_failed_move_suspension() {
        for checkpoint in [1, 2] {
            let mut p = Peer::new();
            let (dir, policy, store) = setup(&p);
            let old = p.m();
            store
                .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
                .unwrap();
            p.machine = MachineKeypair::generate().unwrap();
            let t = NOW + 1000;
            let r = p.record(t, t);
            store.fail_write.store(checkpoint, Ordering::Relaxed);
            assert!(store.ingest(r.clone(), IngestSource::Gossip, t).is_err());
            assert!(store.usable(p.a(), old, t).is_none());
            assert!(store.usable(p.a(), p.m(), t).is_none());
            assert_eq!(store.counters().unwrap().evidence_move_write_failed, 1);
            // Drop has no shutdown flush: reopen exactly the crash-visible disk.
            drop(store);
            let reopened =
                PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, t).unwrap();
            assert_eq!(reopened.usable(p.a(), old, t).is_some(), checkpoint == 1);
            assert_eq!(reopened.usable(p.a(), p.m(), t).is_some(), checkpoint == 2);
            reopened.ingest(r, IngestSource::Hello, t).unwrap();
            assert!(reopened.usable(p.a(), old, t).is_none());
        }
    }
    #[test]
    fn failed_move_retry_and_advert_only_move() {
        let mut p = Peer::new();
        let (dir, policy, store) = setup(&p);
        let old = p.m();
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        p.machine = MachineKeypair::generate().unwrap();
        let t = NOW + 1000;
        let r = p.record(t, t);
        store.fail_write.store(1, Ordering::Relaxed);
        assert!(store
            .ingest_move_advert(&r.advert, p.agent.public_key().as_bytes(), t)
            .is_err());
        assert!(store.usable(p.a(), old, t).is_none());
        store.fail_write.store(0, Ordering::Relaxed);
        store
            .ingest_move_advert(&r.advert, p.agent.public_key().as_bytes(), t)
            .unwrap();
        assert!(store.lock().unwrap().file.records.is_empty());
        assert_eq!(store.lock().unwrap().file.watermarks[&p.a()].machine, p.m());
        drop(store);
        let reopened =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, t).unwrap();
        assert!(reopened.usable(p.a(), old, t).is_none());
        reopened.ingest(r, IngestSource::Hello, t).unwrap();
        assert!(reopened.usable(p.a(), p.m(), t).is_some());
    }
    #[test]
    fn watermark_cap_protects_records_relationships_and_young_entries() {
        let p = Peer::new();
        let (_, policy, store) = setup(&p);
        let mut state = store.lock().unwrap();
        for i in 0..WATERMARK_CAP {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            state.file.watermarks.insert(
                AgentId(id),
                MoveWatermarkV1 {
                    t: NOW,
                    machine: p.m(),
                },
            );
        }
        let mut next = state.file.clone();
        let mark = MoveWatermarkV1 {
            t: NOW,
            machine: p.m(),
        };
        assert!(store
            .set_watermark(&mut state, &mut next, p.a(), mark, NOW)
            .is_err());
        assert_eq!(state.counters.evidence_watermark_full, 1);
        let ids: Vec<_> = next.watermarks.keys().copied().take(4).collect();
        for id in &ids {
            next.watermarks.get_mut(id).unwrap().t = NOW - 8 * DAY_MS;
        }
        next.records.insert(ids[0], p.record(NOW, NOW));
        policy.peers.lock().unwrap().insert(ids[1], GROUP);
        state.absent_since.insert(ids[2], NOW - 2000);
        state.absent_since.insert(ids[3], NOW - 1000);
        store
            .set_watermark(&mut state, &mut next, p.a(), mark, NOW)
            .unwrap();
        assert_eq!(next.watermarks.len(), WATERMARK_CAP);
        assert!(next.watermarks.contains_key(&ids[0]));
        assert!(next.watermarks.contains_key(&ids[1]));
        assert!(!next.watermarks.contains_key(&ids[2]));
        assert!(next.watermarks.contains_key(&ids[3]));
    }
    #[test]
    fn cap_refuses_incoming_move_without_dropping_watermarks() {
        let mut p = Peer::new();
        let (_, _, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        {
            let mut state = store.lock().unwrap();
            for i in 0..WATERMARK_CAP {
                let mut id = [0; 32];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                state.file.watermarks.insert(
                    AgentId(id),
                    MoveWatermarkV1 {
                        t: NOW,
                        machine: p.m(),
                    },
                );
            }
        }
        p.machine = MachineKeypair::generate().unwrap();
        assert!(store
            .ingest(
                p.record(NOW + 1000, NOW + 1000),
                IngestSource::Hello,
                NOW + 1000
            )
            .is_err());
        assert_eq!(store.lock().unwrap().file.watermarks.len(), WATERMARK_CAP);
        assert_eq!(store.counters().unwrap().evidence_watermark_full, 1);
    }
    #[test]
    fn unreadable_files_stay_byte_identical_after_ingest_and_flush() {
        for bytes in [
            b"future magic".to_vec(),
            [MAGIC.as_slice(), &[255; 25]].concat(),
            [EvidenceFileV1::default().encode().unwrap(), vec![1]].concat(),
            vec![0; FILE_CAP + 1],
        ] {
            let p = Peer::new();
            let (dir, policy, _) = setup(&p);
            let path = dir.path().join("peer-evidence.bin");
            fs::write(&path, &bytes).unwrap();
            let store = PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW)
                .unwrap();
            assert!(store.is_memory_only());
            store
                .ingest(p.record(NOW, NOW), IngestSource::Hello, NOW)
                .unwrap();
            store.flush(NOW, true).unwrap();
            assert!(store.usable(p.a(), p.m(), NOW).is_some());
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
    #[test]
    fn roundtrip_unknown_magic_trailing_and_tampered_load() {
        let p = Peer::new();
        let mut file = EvidenceFileV1::default();
        file.records.insert(p.a(), p.record(NOW, NOW));
        file.watermarks.insert(
            p.a(),
            MoveWatermarkV1 {
                t: NOW,
                machine: p.m(),
            },
        );
        let bytes = file.encode().unwrap();
        assert_eq!(EvidenceFileV1::decode(&bytes).unwrap(), file);
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(EvidenceFileV1::decode(&bad).is_err());
        let mut bad = bytes;
        bad.push(0);
        assert!(EvidenceFileV1::decode(&bad).is_err());
        let (dir, policy, _) = setup(&p);
        file.records.get_mut(&p.a()).unwrap().advert[100] ^= 1;
        fs::write(dir.path().join("peer-evidence.bin"), file.encode().unwrap()).unwrap();
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW).unwrap();
        assert!(store.usable(p.a(), p.m(), NOW).is_none());
    }
    #[test]
    fn component_30_kib_and_file_16_mib_caps() {
        let max = EvidenceRecordV1 {
            announcement: vec![0; ANNOUNCEMENT_CAP],
            advert: vec![0; ADVERT_CAP],
            certificate: Some(vec![0; CERTIFICATE_CAP]),
            relation: GROUP,
            stored_at_ms: 0,
        };
        assert_eq!(
            max.announcement.len() + max.advert.len() + max.certificate.as_ref().unwrap().len(),
            RECORD_BYTES_CAP
        );
        assert!(max.bounds().is_ok());
        for part in 0..3 {
            let mut r = max.clone();
            match part {
                0 => r.announcement.push(0),
                1 => r.advert.push(0),
                _ => r.certificate.as_mut().unwrap().push(0),
            };
            assert!(r.bounds().is_err());
            assert!(r.verify(NOW, W_MS).is_err());
        }
        let mut file = EvidenceFileV1::default();
        for i in 0..WATERMARK_CAP {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            file.watermarks.insert(
                AgentId(id),
                MoveWatermarkV1 {
                    t: 0,
                    machine: MachineId([0; 32]),
                },
            );
            if i < RECORD_CAP {
                file.records.insert(AgentId(id), max.clone());
            }
        }
        let bytes = file.encode().unwrap();
        assert!(bytes.len() <= FILE_CAP);
        assert_eq!(EvidenceFileV1::decode(&bytes).unwrap(), file);
        file.records.insert(AgentId([255; 32]), max);
        assert!(file.encode().is_err());
        file.records.remove(&AgentId([255; 32]));
        file.watermarks.insert(
            AgentId([255; 32]),
            MoveWatermarkV1 {
                t: 0,
                machine: MachineId([0; 32]),
            },
        );
        assert!(file.encode().is_err());
        assert!(EvidenceFileV1::decode(&vec![0; FILE_CAP + 1]).is_err());
    }
    #[test]
    fn monotonicity_strangers_and_live_policy_after_load() {
        let p = Peer::new();
        let (dir, policy, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        assert!(store
            .ingest(p.record(NOW - 1000, NOW - 1000), IngestSource::Hello, NOW)
            .is_err());
        let stranger = Peer::new();
        assert!(store
            .ingest(stranger.record(NOW, NOW), IngestSource::Gossip, NOW)
            .is_err());
        assert!(store.live(stranger.a(), NOW).is_none());
        drop(store);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap();
        assert!(store.usable(p.a(), p.m(), NOW).is_some());
        assert!(store.usable(p.a(), MachineId([0; 32]), NOW).is_none());
        policy.revoked.store(true, Ordering::Relaxed);
        assert!(store.usable(p.a(), p.m(), NOW).is_none());
        policy.revoked.store(false, Ordering::Relaxed);
        policy.peers.lock().unwrap().clear();
        assert!(store.usable(p.a(), p.m(), NOW).is_none());
    }
    #[test]
    fn config_default_min_max_and_certificate_expiry() {
        assert_eq!(EvidenceConfig::default().max_age_days, 7);
        for days in [0, 8, 30, u64::MAX] {
            assert!(EvidenceConfig { max_age_days: days }.validate().is_err());
        }
        for days in [1, 7] {
            assert!(EvidenceConfig { max_age_days: days }.validate().is_ok());
        }
        let p = Peer::new();
        let (_, _, store) = setup(&p);
        let mut r = p.record(NOW, NOW);
        let cert = AgentCertificate::issue_with_expiry(
            &UserKeypair::generate().unwrap(),
            &p.agent,
            Some(NOW / 1000 + 10),
        )
        .unwrap();
        r.certificate = Some(cert.to_storage_bytes().unwrap());
        store.ingest(r, IngestSource::Hello, NOW).unwrap();
        assert!(store.usable(p.a(), p.m(), NOW).is_some());
        assert!(store.usable(p.a(), p.m(), NOW + SKEW_MS + 11_000).is_none());
    }
    #[test]
    fn material_changes_coalesce_and_clean_shutdown_flushes() {
        let p = Peer::new();
        let (_, _, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        store
            .ingest(
                p.record(NOW + 1000, NOW + 1000),
                IngestSource::Hello,
                NOW + 1000,
            )
            .unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 1);
        store.flush(NOW + 59_999, false).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 1);
        store.flush(NOW + 60_000, false).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 2);
        store.remove_where(|_, _| true).unwrap();
        store.flush(NOW + 60_001, true).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 3);
        store.flush(NOW + 120_000, true).unwrap();
        assert_eq!(store.counters().unwrap().evidence_writes, 3);
    }
    #[test]
    fn capture_preserves_verbatim_wire_and_ttl() {
        let p = Peer::new();
        let r = p.record(NOW, NOW);
        let cache = VerifiedWireCapture::default();
        cache.capture(p.a(), true, &r.announcement, NOW, NOW);
        cache.capture(p.a(), false, &r.advert, NOW, NOW);
        assert_eq!(cache.get(p.a(), true, NOW).unwrap(), r.announcement);
        assert_eq!(cache.get(p.a(), false, NOW).unwrap(), r.advert);
        assert!(cache.get(p.a(), false, NOW + W_MS + 1).is_none());
    }

    #[test]
    fn record_cap_eviction_priority_then_lru_and_watermark_survival() {
        let p = Peer::new();
        let (_, policy, store) = setup(&p);
        let r = p.record(NOW, NOW);
        let mut state = store.lock().unwrap();
        let mut next = EvidenceFileV1::default();
        let mut verified = HashMap::new();
        let view = Arc::new(r.verify(NOW, W_MS).unwrap());
        for i in 0..=RECORD_CAP {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let a = AgentId(id);
            let mut record = r.clone();
            record.stored_at_ms = NOW + i as u64;
            next.records.insert(a, record);
            verified.insert(a, Arc::clone(&view));
            policy.peers.lock().unwrap().insert(a, ENROLLED);
        }
        let a = AgentId([0; 32]);
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&1u64.to_le_bytes());
        let b = AgentId(bytes);
        policy.peers.lock().unwrap().insert(a, GRANT);
        policy.peers.lock().unwrap().insert(b, GROUP);
        next.watermarks.insert(
            b,
            MoveWatermarkV1 {
                t: NOW,
                machine: p.m(),
            },
        );
        store.evict_records(&state, &mut next, &verified, NOW);
        assert_eq!(next.records.len(), RECORD_CAP);
        assert!(!next.records.contains_key(&b));
        assert!(next.records.contains_key(&a));
        assert!(next.watermarks.contains_key(&b));
        next.records.insert(b, r.clone());
        policy.peers.lock().unwrap().insert(b, GRANT);
        state.last_used.insert(a, NOW + 100);
        store.evict_records(&state, &mut next, &verified, NOW);
        assert!(!next.records.contains_key(&b));
        next.records.insert(b, r);
        policy.peers.lock().unwrap().insert(b, ENROLLED);
        store.evict_records(&state, &mut next, &verified, NOW);
        assert!(!next.records.contains_key(&a));
    }
    #[test]
    fn relationship_sources_enrollment_grants_and_active_groups_only() {
        use crate::share_grant::{Grantee, ShareCap, ShareGrant};
        let p = Peer::new();
        let local = Peer::new();
        let owner = UserKeypair::generate().unwrap();
        let revoked = crate::revocation::RevocationSet::new();
        let view = p.record(NOW, NOW).verify(NOW, W_MS).unwrap();
        let enrollment =
            crate::owner_sync::OwnerEnrollment::sign(p.m(), &owner, NOW - 1000, Some(NOW + 1000))
                .unwrap();
        let records = vec![view];
        let enrollments = vec![enrollment];
        let mut inputs = RelationshipInputs {
            local_agent: local.a(),
            local_owner: Some(owner.user_id()),
            enrollments: &enrollments,
            grants: &[],
            groups: &[],
            revocations: &revoked,
        };
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], ENROLLED);
        assert!(relationship_set(&inputs, &records, NOW + SKEW_MS + 1001).is_empty());
        inputs.enrollments = &[];
        assert!(relationship_set(&inputs, &records, NOW).is_empty());
        let grants = vec![ShareGrant::sign(
            &owner,
            [1; 32],
            Grantee::Agent(p.a()),
            vec![local.a()],
            vec![ShareCap::Dm],
            NOW / 1000 - 1,
            NOW / 1000 + 60,
        )
        .unwrap()];
        inputs.grants = &grants;
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], GRANT);
        assert!(relationship_set(&inputs, &records, NOW + 61_000).is_empty());
        let received = vec![ShareGrant::sign(
            &owner,
            [2; 32],
            Grantee::Agent(local.a()),
            vec![p.a()],
            vec![ShareCap::Dm],
            NOW / 1000 - 1,
            NOW / 1000 + 60,
        )
        .unwrap()];
        inputs.grants = &received;
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], GRANT);
        inputs.grants = &[];
        let mut group = crate::groups::GroupInfo::new(
            "evidence".into(),
            String::new(),
            local.a(),
            "evidence-group".into(),
        );
        let mut member = group.members_v2[&hex::encode(local.a().as_bytes())].clone();
        member.agent_id = hex::encode(p.a().as_bytes());
        group.members_v2.insert(member.agent_id.clone(), member);
        let groups = vec![group.clone()];
        inputs.groups = &groups;
        assert_eq!(relationship_set(&inputs, &records, NOW)[&p.a()], GROUP);
        group.withdrawn = true;
        let withdrawn = vec![group];
        inputs.groups = &withdrawn;
        assert!(relationship_set(&inputs, &records, NOW).is_empty());
    }
    #[test]
    fn verified_ingest_captures_advert_verbatim_and_rejects_forgery() {
        let p = Peer::new();
        let now = crate::dm_capability::now_unix_ms();
        let r = p.record(now, now);
        let store = crate::dm_capability::CapabilityStore::new();
        let mut message = crate::gossip::PubSubMessage {
            topic: String::new(),
            payload: r.advert.clone().into(),
            sender: Some(p.a()),
            sender_public_key: Some(p.agent.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        let mut bad = r.advert.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        message.payload = bad.into();
        assert!(
            !crate::dm_capability_service::ingest_verified_capability_advert(
                &store,
                AgentId([0; 32]),
                &message
            )
        );
        assert!(store.evidence_wire.get(p.a(), false, now).is_none());
        message.payload = r.advert.clone().into();
        assert!(
            crate::dm_capability_service::ingest_verified_capability_advert(
                &store,
                AgentId([0; 32]),
                &message
            )
        );
        assert_eq!(
            store.evidence_wire.get(p.a(), false, now).unwrap(),
            r.advert
        );
    }
    #[test]
    #[ignore = "Explicit initial V1 fixture generation; never rewrite a released fixture"]
    fn generate_initial_v1_fixture() {
        let p = Peer::new();
        let mut file = EvidenceFileV1::default();
        file.records.insert(p.a(), p.record(NOW, NOW));
        file.watermarks.insert(
            p.a(),
            MoveWatermarkV1 {
                t: NOW - 1000,
                machine: p.m(),
            },
        );
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/peer_evidence_v1.bin");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output.write_all(&file.encode().unwrap()).unwrap();
    }
    #[test]
    fn v1_encoder_fixture_loads_and_roundtrips() {
        let bytes = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/peer_evidence_v1.bin"),
        )
        .unwrap();
        let file = EvidenceFileV1::decode(&bytes).unwrap();
        assert_eq!(file.records.len(), 1);
        assert_eq!(file.watermarks.len(), 1);
        let (a, r) = file.records.iter().next().unwrap();
        let view = r.verify(NOW, W_MS).unwrap();
        assert_eq!(view.announcement.agent_id, *a);
        assert_eq!(
            EvidenceFileV1::decode(&file.encode().unwrap()).unwrap(),
            file
        );
    }

    #[test]
    #[ignore = "Crash-test subprocess entry point; launched only by durable_move_process_kill"]
    fn crash_process_child() {
        let root = std::env::var("X0X_EVIDENCE_CRASH_DIR").unwrap();
        let checkpoint = std::env::var("X0X_EVIDENCE_CRASH_POINT")
            .unwrap()
            .parse()
            .unwrap();
        let record: EvidenceRecordV1 = options()
            .deserialize(&fs::read(Path::new(&root).join("incoming.bin")).unwrap())
            .unwrap();
        let view = record.verify(NOW + 1000, W_MS).unwrap();
        let policy = Arc::new(Policy::default());
        policy
            .peers
            .lock()
            .unwrap()
            .insert(view.announcement.agent_id, GROUP);
        let store = PeerEvidenceStore::open(
            Path::new(&root),
            EvidenceConfig::default(),
            policy,
            NOW + 1000,
        )
        .unwrap();
        store.fail_write.store(checkpoint, Ordering::Relaxed);
        let _ = store.ingest(record, IngestSource::Hello, NOW + 1000);
        panic!("crash checkpoint did not terminate");
    }
    #[test]
    fn durable_move_process_kill() {
        for checkpoint in [3, 4] {
            let mut p = Peer::new();
            let (dir, policy, store) = setup(&p);
            let old = p.m();
            store
                .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
                .unwrap();
            drop(store);
            p.machine = MachineKeypair::generate().unwrap();
            let record = p.record(NOW + 1000, NOW + 1000);
            fs::write(
                dir.path().join("incoming.bin"),
                options().serialize(&record).unwrap(),
            )
            .unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "peer_evidence::tests::crash_process_child",
                    "--ignored",
                ])
                .env("X0X_EVIDENCE_CRASH_DIR", dir.path())
                .env("X0X_EVIDENCE_CRASH_POINT", checkpoint.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(89));
            let reopened =
                PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, NOW + 1000)
                    .unwrap();
            assert_eq!(
                reopened.usable(p.a(), old, NOW + 1000).is_some(),
                checkpoint == 3
            );
            assert_eq!(
                reopened.usable(p.a(), p.m(), NOW + 1000).is_some(),
                checkpoint == 4
            );
        }
    }
    #[test]
    fn maintenance_removes_expired_relationships_and_keeps_watermarks() {
        let p = Peer::new();
        let (_, policy, store) = setup(&p);
        store
            .ingest(p.record(NOW, NOW), IngestSource::Gossip, NOW)
            .unwrap();
        store.lock().unwrap().file.watermarks.insert(
            p.a(),
            MoveWatermarkV1 {
                t: NOW,
                machine: p.m(),
            },
        );
        policy.peers.lock().unwrap().clear();
        store.maintain(NOW + 60_000).unwrap();
        let state = store.lock().unwrap();
        assert!(state.file.records.is_empty());
        assert!(state.live.is_empty());
        assert_eq!(state.file.watermarks.len(), 1);
        assert_eq!(state.absent_since[&p.a()], NOW + 60_000);
    }

    #[test]
    fn all_revocation_subjects_rechecked_after_load() {
        struct Revoking {
            a: AgentId,
            m: MachineId,
            u: UserId,
            kind: std::sync::atomic::AtomicU8,
        }
        impl EvidencePolicy for Revoking {
            fn relation(
                &self,
                a: AgentId,
                _: MachineId,
                _: Option<&AgentCertificate>,
                _: u64,
            ) -> u8 {
                if a == self.a {
                    GRANT
                } else {
                    0
                }
            }
            fn contains_agent(&self, a: AgentId, _: u64) -> bool {
                a == self.a
            }
            fn revoked(&self, a: AgentId, m: MachineId, u: Option<UserId>) -> bool {
                match self.kind.load(Ordering::Relaxed) {
                    1 => a == self.a,
                    2 => m == self.m,
                    3 => a == self.a && m == self.m,
                    4 => u == Some(self.u),
                    _ => false,
                }
            }
        }
        let p = Peer::new();
        let owner = UserKeypair::generate().unwrap();
        let policy = Arc::new(Revoking {
            a: p.a(),
            m: p.m(),
            u: owner.user_id(),
            kind: std::sync::atomic::AtomicU8::new(0),
        });
        let dir = tempfile::tempdir().unwrap();
        let mut r = p.record(NOW, NOW);
        r.certificate = Some(
            AgentCertificate::issue(&owner, &p.agent)
                .unwrap()
                .to_storage_bytes()
                .unwrap(),
        );
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap();
        store.ingest(r, IngestSource::Hello, NOW).unwrap();
        drop(store);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy.clone(), NOW)
                .unwrap();
        for kind in 1..=4 {
            policy.kind.store(0, Ordering::Relaxed);
            assert!(store.usable(p.a(), p.m(), NOW).is_some());
            policy.kind.store(kind, Ordering::Relaxed);
            assert!(store.usable(p.a(), p.m(), NOW).is_none(), "subject {kind}");
        }
    }
    #[tokio::test]
    async fn s2_loaded_raw_authority_is_live_and_never_seeds_bindings() {
        let mut p = Peer::new();
        let now = crate::dm_capability::now_unix_ms();
        let (dir, policy, store) = setup(&p);
        let mut record = p.record(now, now);
        record.certificate = Some(
            AgentCertificate::issue_with_expiry(
                &UserKeypair::generate().unwrap(),
                &p.agent,
                Some(now / 1000 + 10),
            )
            .unwrap()
            .to_storage_bytes()
            .unwrap(),
        );
        store.ingest(record, IngestSource::Hello, now).unwrap();
        drop(store);
        let runtime = Arc::new(EvidenceRuntime::default());
        runtime.start(
            dir.path().to_owned(),
            EvidenceConfig::default(),
            policy.clone(),
            Arc::default(),
        );
        assert!(runtime.wait(100).await);
        let binding = Arc::new(tokio::sync::RwLock::new(
            crate::dm_inbox::AuthenticatedMachineBindingCache::default(),
        ));
        let verify = |machine, at| {
            crate::raw_delivery_with_evidence(None, None, Some(&runtime), p.a(), machine, at).0
        };
        assert!(
            verify(p.m(), now),
            "#1088: cold discovery uses the loaded record"
        );
        assert!(!verify(MachineId([9; 32]), now));
        assert!(
            !verify(p.m(), now + SKEW_MS + 11_000),
            "expiry checked on the next frame"
        );
        policy.revoked.store(true, Ordering::Relaxed);
        assert!(!verify(p.m(), now));
        policy.revoked.store(false, Ordering::Relaxed);
        policy.peers.lock().unwrap().clear();
        assert!(!verify(p.m(), now));
        policy.peers.lock().unwrap().insert(p.a(), GROUP);
        assert!(verify(p.m(), now));
        let first = runtime.usable_agent(p.a(), now).unwrap();
        assert!(Arc::ptr_eq(
            &first,
            &runtime.usable_agent(p.a(), now).unwrap()
        ));
        assert_eq!(runtime.diagnostics()["evidence_loaded"], 1);
        assert!(
            crate::dm_inbox::authenticated_machine_binding(&binding, &p.a())
                .await
                .is_none()
        );
        let old = p.m();
        p.machine = MachineKeypair::generate().unwrap();
        runtime
            .store()
            .unwrap()
            .ingest(
                p.record(now + 1000, now + 1000),
                IngestSource::Hello,
                now + 1000,
            )
            .unwrap();
        assert!(
            !crate::raw_delivery_with_evidence(None, None, Some(&runtime), p.a(), old, now + 1000)
                .0
        );
        assert!(
            crate::raw_delivery_with_evidence(None, None, Some(&runtime), p.a(), p.m(), now + 1000)
                .0
        );
    }

    #[tokio::test]
    async fn s2_raw_live_supersession_and_expiry_cannot_fall_back_to_evidence_1098() {
        let p = Peer::new();
        let now = crate::dm_capability::now_unix_ms();
        let secs = now / 1000;
        let (dir, policy, store) = setup(&p);
        store
            .ingest(p.record(now, now), IngestSource::Hello, now)
            .unwrap();
        drop(store);
        let runtime = Arc::new(EvidenceRuntime::default());
        runtime.start(
            dir.path().to_owned(),
            EvidenceConfig::default(),
            policy,
            Arc::default(),
        );
        assert!(runtime.wait(0).await);
        let bindings = crate::dm_inbox::AuthenticatedMachineBindings::default();
        crate::dm_inbox::record_authenticated_machine_binding(&bindings, p.a(), p.m(), secs).await;
        let registry =
            crate::dm_inbox::authenticated_machine_binding_evidence(&bindings, &p.a()).await;
        let moved = MachineId([9; 32]);
        let mut cache = crate::discovered_agent_fixture(9, secs + 1, &[], None);
        cache.agent_id = p.a();
        // A newer cached move (including a timestamp tie) beats the old
        // registry. The still-usable stored old binding cannot resurrect it.
        for (announced_at, winner) in [(secs + 1, moved), (secs, moved), (secs - 1, p.m())] {
            cache.announced_at = announced_at;
            for machine in [p.m(), moved] {
                let (verified, live, _) = crate::raw_delivery_with_evidence(
                    Some(&cache),
                    registry,
                    Some(&runtime),
                    p.a(),
                    machine,
                    now,
                );
                assert_eq!((verified, live), (machine == winner, machine == winner));
            }
        }
        // Expired discovery cannot fall back to either cert-less registry
        // evidence or the valid stored record, regardless of which is newer.
        cache.machine_id = p.m();
        cache.cert_not_after = Some(secs - 1000);
        for announced_at in [secs - 1, secs + 1] {
            cache.announced_at = announced_at;
            let (verified, live, expiry) = crate::raw_delivery_with_evidence(
                Some(&cache),
                registry,
                Some(&runtime),
                p.a(),
                p.m(),
                now,
            );
            assert_eq!((verified, live), (false, false));
            assert_eq!(expiry, cache.cert_not_after);
        }
        crate::dm_inbox::record_authenticated_machine_binding_with_expiry(
            &bindings,
            p.a(),
            p.m(),
            secs + 2,
            Some(secs - 1000),
        )
        .await;
        let registry =
            crate::dm_inbox::authenticated_machine_binding_evidence(&bindings, &p.a()).await;
        let (verified, live, expiry) =
            crate::raw_delivery_with_evidence(None, registry, Some(&runtime), p.a(), p.m(), now);
        assert_eq!((verified, live), (false, false));
        assert_eq!(expiry, Some(secs - 1000));
        // With both live sources absent, stored authority verifies this frame
        // without acquiring the authority to seed the reverse-routing cache.
        assert_eq!(
            crate::raw_delivery_with_evidence(None, None, Some(&runtime), p.a(), p.m(), now),
            (true, false, None),
        );
    }

    #[test]
    fn s2_pairing_verifies_each_outcome_once_until_fingerprint_or_epoch_changes() {
        for refusal in [
            Some("agent/machine mismatch"),
            Some("non-monotonic evidence"),
            Some("move watermark"),
            Some("not a current relationship"),
            None,
        ] {
            let mut p = Peer::new();
            let (_dir, policy, store) = setup(&p);
            let mut record = p.record(NOW, NOW);
            let mut changed = p.record(NOW + 1000, NOW + 1000);
            match refusal {
                Some("agent/machine mismatch") => {
                    p.machine = MachineKeypair::generate().unwrap();
                    record.advert = p.record(NOW, NOW).advert;
                    changed.advert = p.record(NOW + 1000, NOW + 1000).advert;
                }
                Some("non-monotonic evidence") => {
                    store
                        .ingest(
                            p.record(NOW + 60_000, NOW + 60_000),
                            IngestSource::Gossip,
                            NOW,
                        )
                        .unwrap();
                }
                Some("move watermark") => {
                    store.lock().unwrap().file.watermarks.insert(
                        p.a(),
                        MoveWatermarkV1 {
                            t: NOW + 60_000,
                            machine: MachineKeypair::generate().unwrap().machine_id(),
                        },
                    );
                }
                Some("not a current relationship") => {
                    policy.unavailable.store(true, Ordering::Relaxed)
                }
                _ => {}
            }
            let mut pairing = GossipPairing::default();
            VERIFY_CALLS.set(0);
            let outcome = pairing.ingest(&store, p.a(), record.clone(), NOW).unwrap();
            match refusal {
                Some(reason) => assert!(
                    matches!(outcome, Err(EvidenceError::Invalid(actual)) if actual == reason)
                ),
                None => assert!(outcome.is_ok()),
            }
            for tick in 1..30 {
                assert!(pairing
                    .ingest(&store, p.a(), record.clone(), NOW + tick * 1000)
                    .is_none());
            }
            assert_eq!(
                VERIFY_CALLS.get(),
                3,
                "one verification of each signed part over 30 ticks: {refusal:?}"
            );

            assert!(pairing
                .ingest(&store, p.a(), changed.clone(), NOW + 30_000)
                .is_some());
            for tick in 31..60 {
                assert!(pairing
                    .ingest(&store, p.a(), changed.clone(), NOW + tick * 1000)
                    .is_none());
            }
            assert_eq!(
                VERIFY_CALLS.get(),
                6,
                "changed fingerprint retries exactly once: {refusal:?}"
            );

            policy.unavailable.store(false, Ordering::Relaxed);
            policy.epoch.fetch_add(1, Ordering::Relaxed);
            let outcome = pairing
                .ingest(&store, p.a(), changed.clone(), NOW + 60_000)
                .unwrap();
            if refusal == Some("not a current relationship") {
                assert!(
                    outcome.is_ok(),
                    "policy recovery accepts the unchanged pair"
                );
            }
            for tick in 61..90 {
                assert!(pairing
                    .ingest(&store, p.a(), changed.clone(), NOW + tick * 1000)
                    .is_none());
            }
            assert_eq!(
                VERIFY_CALLS.get(),
                9,
                "advanced policy epoch retries exactly once: {refusal:?}"
            );
        }
    }

    #[test]
    fn s2_pairing_fingerprint_cache_is_bounded_lru_and_expires_with_capture() {
        let p = Peer::new();
        let (_dir, _, store) = setup(&p);
        let mut pairing = GossipPairing::default();
        let record = EvidenceRecordV1 {
            announcement: vec![],
            advert: vec![],
            certificate: None,
            relation: 0,
            stored_at_ms: NOW,
        };
        let agent = |i: usize| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            AgentId(bytes)
        };
        for i in 0..RECORD_CAP {
            assert!(pairing
                .ingest(&store, agent(i), record.clone(), NOW + i as u64)
                .unwrap()
                .is_err());
        }
        // Cache hits update recency too, so agent 1 is now the LRU victim.
        assert!(pairing
            .ingest(&store, agent(0), record.clone(), NOW + RECORD_CAP as u64)
            .is_none());
        assert!(pairing
            .ingest(
                &store,
                agent(RECORD_CAP),
                record,
                NOW + RECORD_CAP as u64 + 1
            )
            .is_some());
        assert_eq!(pairing.processed.len(), RECORD_CAP);
        assert!(pairing.processed.contains_key(&agent(0)));
        assert!(!pairing.processed.contains_key(&agent(1)));

        let capture = VerifiedWireCapture::default();
        capture.capture(agent(0), true, &[1], NOW, NOW);
        capture.capture(agent(0), false, &[2], NOW, NOW);
        capture.capture(agent(2), true, &[1], NOW, NOW);
        pairing.retain_fresh(&capture, NOW);
        assert_eq!(
            pairing.processed.len(),
            1,
            "only complete fresh pairs remain"
        );
        pairing.retain_fresh(&capture, NOW + W_MS + 1);
        assert!(pairing.processed.is_empty());
    }

    #[tokio::test]
    async fn s2_capture_pairs_verbatim_bytes_when_relationship_appears() {
        let p = Peer::new();
        let now = crate::dm_capability::now_unix_ms();
        let record = p.record(now, now);
        let dir = tempfile::tempdir().unwrap();
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
        let related = Arc::new(AtomicBool::new(false));
        let current = related.clone();
        let peer = p.a();
        agent
            .start_peer_evidence(
                dir.path().to_owned(),
                EvidenceConfig::default(),
                Arc::new(move |a| Some(a == peer && current.load(Ordering::Relaxed))),
            )
            .unwrap();
        assert!(agent.peer_evidence().wait(0).await);
        agent
            .capability_store
            .evidence_wire
            .capture(peer, true, &record.announcement, now, now);
        let message = crate::gossip::PubSubMessage {
            topic: "x0x/caps/v1".into(),
            payload: record.advert.clone().into(),
            sender: Some(peer),
            sender_public_key: Some(p.agent.public_key().as_bytes().to_vec()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        };
        assert!(
            crate::dm_capability_service::ingest_verified_capability_advert(
                &agent.capability_store,
                agent.agent_id(),
                &message
            )
        );
        assert!(agent.peer_evidence().usable_agent(peer, now).is_none());
        related.store(true, Ordering::Relaxed);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while agent.peer_evidence().usable_agent(peer, now).is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let store = agent.peer_evidence().store().unwrap();
        let live = store.live(peer, now).unwrap();
        assert_eq!(live.announcement, record.announcement);
        assert_eq!(live.advert, record.advert);
        related.store(false, Ordering::Relaxed);
        assert!(agent.peer_evidence().usable_agent(peer, now).is_none());
        store.maintain(now + 60_000).unwrap();
        assert!(store.lock().unwrap().file.records.is_empty());
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn s2_cold_send_resolves_kem_and_strict_ack_without_an_announcement() {
        let p = Peer::new();
        let now = crate::dm_capability::now_unix_ms();
        let (dir, _, store) = setup(&p);
        let mut record = p.record(now, now);
        let mut advert = CapabilityAdvert::decode_evidence(&record.advert).unwrap().0;
        advert.capabilities.gossip_inbox = true;
        advert.capabilities.max_protocol_version = crate::dm::DM_PROTOCOL_DURABLE_ACK;
        advert.capabilities.kem_public_key =
            crate::groups::kem_envelope::AgentKemKeypair::generate()
                .unwrap()
                .public_bytes;
        advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            p.agent.secret_key(),
            &advert.signed_bytes().unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        record.advert = postcard::to_stdvec(&advert).unwrap();
        store.ingest(record, IngestSource::Hello, now).unwrap();
        drop(store);
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
        let peer = p.a();
        agent
            .start_peer_evidence(
                dir.path().to_owned(),
                EvidenceConfig::default(),
                Arc::new(move |a| Some(a == peer)),
            )
            .unwrap();
        assert!(agent.peer_evidence().wait(0).await);
        assert!(agent.identity_discovery_cache.read().await.is_empty());
        assert!(agent.capability_store.lookup_binding(&peer).is_none());
        let config = crate::dm::DmSendConfig {
            require_durable_app_ack: true,
            ..Default::default()
        };
        let error = agent
            .send_direct_with_config(&peer, b"cold strict send".to_vec(), config)
            .await
            .unwrap_err();
        // The inert agent has no transport. Getting this far proves the real
        // send resolved and validated the stored KEM and strict ACK binding.
        assert!(
            matches!(error, crate::dm::DmError::LocalGossipUnavailable(_)),
            "{error:?}"
        );
        assert!(agent.identity_discovery_cache.read().await.is_empty());
        assert!(agent.capability_store.lookup_binding(&peer).is_none());
        assert!(crate::dm_inbox::authenticated_machine_binding(
            &agent.authenticated_machine_bindings,
            &peer
        )
        .await
        .is_none());
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn s2_raw_durable_ack_key_after_load_authenticates_and_completes_waiter() {
        use crate::dm::{DmAckOutcome, DmEnvelope, EnvelopeBuilder, DM_PROTOCOL_DURABLE_ACK};
        let p = Peer::new();
        let now = crate::dm_capability::now_unix_ms();
        let (dir, policy, store) = setup(&p);
        store
            .ingest(p.record(now, now), IngestSource::Hello, now)
            .unwrap();
        drop(store);
        let store =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, now).unwrap();
        let view = store.usable(p.a(), p.m(), now).unwrap();
        let mut ack = DmEnvelope {
            protocol_version: DM_PROTOCOL_DURABLE_ACK,
            request_id: [81; 16],
            sender_agent_id: p.a().0,
            sender_machine_id: p.m().0,
            recipient_agent_id: [82; 32],
            created_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            body: EnvelopeBuilder::build_ack_body([80; 16], DmAckOutcome::Accepted),
            signature: Vec::new(),
            origin_attestation: None,
        };
        ack.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            p.agent.secret_key(),
            &ack.signed_bytes().unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let ack = DmEnvelope::from_wire_bytes(&ack.to_wire_bytes().unwrap()).unwrap();
        assert!(crate::dm_inbox::verify_envelope_signature(
            &ack,
            &view.announcement.agent_public_key
        ));
        let inflight = crate::dm::InFlightAcks::new();
        let waiter =
            inflight.register_for_protocol([80; 16], DM_PROTOCOL_DURABLE_ACK, p.a(), Some(p.m()));
        let crate::dm::DmBody::Ack(body) = ack.body else {
            panic!("ACK");
        };
        assert!(inflight.resolve_for_protocol(
            &body.acks_request_id,
            ack.protocol_version,
            p.a(),
            p.m(),
            body.outcome
        ));
        assert_eq!(waiter.await.unwrap(), DmAckOutcome::Accepted);
    }

    #[tokio::test]
    async fn s2_grant_rules_two_four_and_owner_trust_use_loaded_evidence() {
        use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
        let p = Peer::new();
        let local = Peer::new();
        let owner = UserKeypair::generate().unwrap();
        let peer_owner = UserKeypair::generate().unwrap();
        let now = crate::dm_capability::now_unix_ms();
        let (dir, policy, store) = setup(&p);
        let mut record = p.record(now, now);
        record.certificate = Some(
            AgentCertificate::issue(&peer_owner, &p.agent)
                .unwrap()
                .to_storage_bytes()
                .unwrap(),
        );
        store.ingest(record, IngestSource::Hello, now).unwrap();
        drop(store);
        let bindings = Arc::new(tokio::sync::RwLock::new(
            crate::dm_inbox::AuthenticatedMachineBindingCache::default(),
        ));
        let owner_trust =
            crate::owner_trust::OwnerTrust::new(Some(owner.user_id()), bindings.clone());
        let grants = Arc::new(ShareGrantStore::in_memory(local.a(), Some(owner.user_id())));
        grants
            .accept(
                ShareGrant::sign(
                    &owner,
                    [87; 32],
                    Grantee::User(peer_owner.user_id()),
                    vec![local.a()],
                    vec![ShareCap::Dm],
                    now / 1000 - 1,
                    now / 1000 + 60,
                )
                .unwrap(),
                now / 1000,
            )
            .await
            .unwrap();
        owner_trust.install_share_grant_store(grants.clone());
        let revocations = Arc::new(tokio::sync::RwLock::new(
            crate::revocation::RevocationSet::new(),
        ));
        let runtime = Arc::new(EvidenceRuntime::default());
        owner_trust.install_evidence(&runtime);
        let live_policy = Arc::new(RuntimePolicy::new(
            local.a(),
            owner_trust.clone(),
            revocations.clone(),
        ));
        runtime.start(
            dir.path().to_owned(),
            EvidenceConfig::default(),
            live_policy,
            Arc::default(),
        );
        assert!(runtime.wait(0).await);
        let discovery = tokio::sync::RwLock::new(HashMap::new());
        let access = crate::share_grant::evaluate_grant_access_with_evidence(
            &grants,
            &bindings,
            &discovery,
            &revocations,
            &p.a(),
            &p.m(),
            now / 1000,
            Some(&runtime),
        )
        .await;
        assert!(
            access.dm,
            "both binding and user certificate resolve after restart"
        );
        // A busy live policy denies this frame but cannot erase persisted
        // authority during housekeeping; the next frame retries normally.
        let write_guard = revocations.write().await;
        assert!(runtime.usable(p.a(), p.m(), now).is_none());
        runtime.store().unwrap().maintain(now).unwrap();
        drop(write_guard);
        assert!(runtime.usable(p.a(), p.m(), now).is_some());
        let denied = crate::share_grant::evaluate_grant_access_with_evidence(
            &grants,
            &bindings,
            &discovery,
            &revocations,
            &p.a(),
            &MachineId([9; 32]),
            now / 1000,
            Some(&runtime),
        )
        .await;
        assert!(denied.is_empty());
        assert!(
            runtime.usable(p.a(), p.m(), now + 61_000).is_none(),
            "expired grant removes the relationship immediately"
        );
        assert!(discovery.read().await.is_empty());
        assert!(
            crate::dm_inbox::authenticated_machine_binding(&bindings, &p.a())
                .await
                .is_none()
        );

        // Owner trust needs both enrollment and a same-owner certificate.
        let mut record = p.record(now + 1000, now + 1000);
        record.certificate = Some(
            AgentCertificate::issue(&owner, &p.agent)
                .unwrap()
                .to_storage_bytes()
                .unwrap(),
        );
        let fixture =
            PeerEvidenceStore::open(dir.path(), EvidenceConfig::default(), policy, now).unwrap();
        fixture
            .ingest(record, IngestSource::Hello, now + 1000)
            .unwrap();
        fixture.flush(now + 1000, true).unwrap();
        drop(fixture);
        let devices = Arc::new(
            crate::owner_sync::OwnerSyncStore::load(dir.path())
                .await
                .unwrap(),
        );
        devices
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(p.m(), &owner, now - 1000, None).unwrap(),
            )
            .await
            .unwrap();
        owner_trust.install_device_store(devices.clone());
        let runtime = Arc::new(EvidenceRuntime::default());
        owner_trust.install_evidence(&runtime);
        runtime.start(
            dir.path().to_owned(),
            EvidenceConfig::default(),
            Arc::new(RuntimePolicy::new(
                local.a(),
                owner_trust.clone(),
                revocations.clone(),
            )),
            Arc::default(),
        );
        assert!(runtime.wait(0).await);
        assert!(
            owner_trust
                .is_owner_trusted(&discovery, &revocations, &p.a(), &p.m())
                .await
        );
        devices.unenroll(&p.m()).await.unwrap();
        assert!(runtime.usable(p.a(), p.m(), now + 1000).is_none());
        assert!(
            !owner_trust
                .is_owner_trusted(&discovery, &revocations, &p.a(), &p.m())
                .await
        );
    }

    #[test]
    #[ignore = "CPU-only t_v benchmark; run explicitly on Mac and fleet VPS (crypto dependencies optimized in test profile)"]
    fn verify_benchmark_t_v() {
        use ant_quic::crypto::raw_public_keys::pqc::{sign_with_ml_dsa, verify_with_ml_dsa};
        let p = Peer::new();
        let message = vec![42; 4096];
        let signature = sign_with_ml_dsa(p.agent.secret_key(), &message).unwrap();
        for _ in 0..100 {
            verify_with_ml_dsa(p.agent.public_key(), &message, &signature).unwrap();
        }
        let start = std::time::Instant::now();
        let n = 2000;
        for _ in 0..n {
            verify_with_ml_dsa(
                std::hint::black_box(p.agent.public_key()),
                std::hint::black_box(&message),
                std::hint::black_box(&signature),
            )
            .unwrap();
        }
        let ms = start.elapsed().as_secs_f64() * 1000.0 / f64::from(n);
        println!("ADR0089 t_v: target={}-{} debug_assertions={} n={} message_bytes={} mean_ms={:.6} projected_2048_verifies_s={:.6}",std::env::consts::OS,std::env::consts::ARCH,cfg!(debug_assertions),n,message.len(),ms,ms*2048.0/1000.0);
    }
}
